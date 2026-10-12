// Package connections authorises connection attempts and mints the
// per-attempt artifacts: the ticket (for the host), relay tokens (one per
// role), TURN credentials and the attestation nonce (API §7).
package connections

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/core/connrelaycore/token"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/store"
	"github.com/rohansen856/connrelay/services/control/internal/turncred"
)

// Lifetimes.
const (
	TicketTTL     = 60 * time.Second
	RelayTokenTTL = 90 * time.Second
	IdemWindow    = 60 * time.Second
	RatePerMinute = 10
)

// API errors.
var (
	ErrOffline      = &httpx.Error{Status: http.StatusConflict, Code: "agent_offline", Message: "The computer is offline.", Retryable: true}
	ErrNoGrant      = httpx.E(http.StatusForbidden, "access_grant_missing", "This phone is not authorized to open a terminal on this computer.")
	ErrRate         = &httpx.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many connection attempts.", Retryable: true}
	ErrIdemConflict = httpx.E(http.StatusUnprocessableEntity, "idempotency_conflict", "This Idempotency-Key was used for a different request.")
	ErrTransition   = httpx.E(http.StatusConflict, "invalid_transition", "That status change is not allowed.")
	ErrNotLive      = httpx.E(http.StatusConflict, "attempt_not_live", "This connection attempt has ended.")
)

// Hub is the subset of the socket hub used here.
type Hub interface {
	Connected(host uuid.UUID) bool
	RegisterAttempt(id, phone, host uuid.UUID, expires time.Time)
	EndAttempt(id uuid.UUID)
	SendToAgent(ctx context.Context, host uuid.UUID, typ string, body map[string]any) error
	SendToPhone(ctx context.Context, phone uuid.UUID, m any)
}

// ICEServer mirrors the WebRTC ICE server shape.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Service implements the connection endpoints.
type Service struct {
	Store        *store.Store
	Auth         *auth.Service
	Hub          Hub
	Ticket       token.Issuer
	ISS          string
	TURNSecret   []byte
	STUNURLs     []string
	TURNURLs     []string
	RelayURL     string
	SignalingURL string
	Now          func() time.Time

	rmu  sync.Mutex
	rate map[uuid.UUID][]time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// allow applies a sliding one-minute rate limit per phone.
func (s *Service) allow(phone uuid.UUID) bool {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.rate == nil {
		s.rate = map[uuid.UUID][]time.Time{}
	}
	now := s.now()
	var keep []time.Time
	for _, t := range s.rate[phone] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= RatePerMinute {
		s.rate[phone] = keep
		return false
	}
	s.rate[phone] = append(keep, now)
	return true
}

func (s *Service) iceServers(attempt uuid.UUID) []ICEServer {
	var out []ICEServer
	if len(s.STUNURLs) > 0 {
		out = append(out, ICEServer{URLs: s.STUNURLs})
	}
	if len(s.TURNURLs) > 0 && len(s.TURNSecret) > 0 {
		c := turncred.Issue(s.TURNSecret, attempt.String(), s.now(), turncred.DefaultTTL)
		out = append(out, ICEServer{URLs: s.TURNURLs, Username: c.Username, Credential: c.Credential})
	}
	return out
}

type attemptRow struct {
	ID, Phone, Host, Grant uuid.UUID
	Status                 string
	JTI                    uuid.UUID
	TicketExpires          time.Time
	Nonce                  []byte
	Created                time.Time
	Session                *uuid.UUID
	PathType, Failure      *string
	ConnectedAt, EndedAt   *time.Time
}

const attemptCols = `id, phone_device_id, host_device_id, grant_id, status, ticket_jti, ticket_expires_at, attestation_nonce,
	created_at, target_terminal_session_id, path_type, failure_code, connected_at, ended_at`

func scanAttempt(r pgx.Row) (attemptRow, error) {
	var a attemptRow
	err := r.Scan(&a.ID, &a.Phone, &a.Host, &a.Grant, &a.Status, &a.JTI, &a.TicketExpires, &a.Nonce, &a.Created,
		&a.Session, &a.PathType, &a.Failure, &a.ConnectedAt, &a.EndedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, httpx.ErrNotFound
	}
	return a, err
}

type createReq struct {
	Host       uuid.UUID  `json:"host_device_id"`
	Capability string     `json:"capability"`
	Session    *uuid.UUID `json:"target_terminal_session_id"`
}

// artifacts mints the tickets and tokens for an attempt row.
func (s *Service) artifacts(p *auth.Principal, a attemptRow, host store.Device) (map[string]any, string, error) {
	nonce := base64.RawURLEncoding.EncodeToString(a.Nonce)
	iat := a.TicketExpires.Add(-TicketTTL)
	t := token.Ticket{
		Registered: token.Registered{IAT: iat.Unix(), NBF: iat.Unix(), EXP: a.TicketExpires.Unix(), JTI: a.JTI.String()},
		ISS:        s.ISS, AUD: a.Host.String(), SUB: a.Phone.String(), Acct: p.AccountID.String(), Att: a.ID.String(),
		Cap: "terminal", Nonce: nonce, PV: 1,
	}
	if a.Session != nil {
		t.Sess = a.Session.String()
	}
	ticket, err := s.Ticket.Issue(token.TypeTicket, t)
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	relay := func(role string, dev uuid.UUID) (string, error) {
		return s.Ticket.Issue(token.TypeRelay, token.Relay{
			Registered: token.Registered{IAT: now.Unix(), EXP: now.Add(RelayTokenTTL).Unix(), JTI: store.NewID().String()},
			Att:        a.ID.String(), Role: role, Dev: dev.String()})
	}
	clientTok, err := relay(token.RoleClient, a.Phone)
	if err != nil {
		return nil, "", err
	}
	hostTok, err := relay(token.RoleServer, a.Host)
	if err != nil {
		return nil, "", err
	}
	ice := s.iceServers(a.ID)
	resp := map[string]any{
		"connection_attempt_id": a.ID, "status": a.Status, "expires_at": a.TicketExpires.UTC().Format(time.RFC3339),
		"ticket": ticket, "relay": map[string]string{"url": s.RelayURL, "token": clientTok}, "ice_servers": ice,
		"attestation_nonce": nonce, "signaling_url": s.SignalingURL, "fallback": map[string]int{"wss_race_after_ms": 4000},
		"host": map[string]any{"device_id": host.ID, "key_fingerprint": host.KeyFingerprint,
			"public_key_spki": base64.RawURLEncoding.EncodeToString(host.PublicKey)},
	}
	return resp, hostTok, nil
}

func (s *Service) create(ctx context.Context, p *auth.Principal, req createReq, idem, reqID string) (map[string]any, int, error) {
	if req.Capability != "terminal" {
		return nil, 0, httpx.E(http.StatusBadRequest, "capability_not_supported", "Only terminal access is supported.")
	}
	if len(idem) < 16 || len(idem) > 128 {
		return nil, 0, httpx.E(http.StatusBadRequest, "validation_failed", "Idempotency-Key (16-128 characters) is required.")
	}
	host, err := store.GetDevice(ctx, s.Store.Pool, p.AccountID, req.Host)
	if err != nil || host.Kind != "host" {
		return nil, 0, httpx.ErrNotFound
	}
	if host.AdminState != "active" {
		return nil, 0, httpx.E(http.StatusConflict, "device_revoked", "This computer was removed.")
	}

	// Idempotent retry: same key, same request, recent and still authorised.
	if a, err := scanAttempt(s.Store.Pool.QueryRow(ctx, `SELECT `+attemptCols+` FROM connection_attempts
		WHERE phone_device_id = $1 AND idempotency_key = $2`, p.DeviceID, idem)); err == nil {
		if a.Host != req.Host {
			return nil, 0, ErrIdemConflict
		}
		if s.now().Sub(a.Created) < IdemWindow && a.Status == "authorized" && a.Nonce != nil {
			resp, _, err := s.artifacts(p, a, host)
			return resp, http.StatusCreated, err
		}
		return nil, 0, ErrIdemConflict
	} else if !errors.Is(err, httpx.ErrNotFound) {
		return nil, 0, err
	}

	var grantID uuid.UUID
	err = s.Store.Pool.QueryRow(ctx, `SELECT id FROM access_grants WHERE account_id = $1 AND phone_device_id = $2
		AND host_device_id = $3 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())
		AND 'terminal' = ANY(capabilities)`, p.AccountID, p.DeviceID, req.Host).Scan(&grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = store.WriteAudit(ctx, s.Store.Pool, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
			TargetDeviceID: &req.Host, EventType: "connection_attempt", Outcome: "denied", ReasonCode: "access_grant_missing", RequestID: reqID})
		return nil, 0, ErrNoGrant
	}
	if err != nil {
		return nil, 0, err
	}
	if !s.Hub.Connected(req.Host) {
		return nil, 0, ErrOffline
	}
	if !s.allow(p.DeviceID) {
		return nil, 0, ErrRate
	}

	now := s.now()
	nonce := make([]byte, 32)
	if _, err := randRead(nonce); err != nil {
		return nil, 0, err
	}
	nh := sha256.Sum256(nonce)
	a := attemptRow{ID: store.NewID(), Phone: p.DeviceID, Host: req.Host, Grant: grantID, Status: "authorized",
		JTI: store.NewID(), TicketExpires: now.Add(TicketTTL), Nonce: nonce, Created: now}
	_, err = s.Store.Pool.Exec(ctx, `INSERT INTO connection_attempts (id, account_id, phone_device_id, host_device_id, grant_id,
		requested_capability, ticket_jti, ticket_expires_at, attestation_nonce_hash, attestation_nonce, idempotency_key, created_at)
		VALUES ($1,$2,$3,$4,$5,'terminal',$6,$7,$8,$9,$10,$11)`,
		a.ID, p.AccountID, a.Phone, a.Host, a.Grant, a.JTI, a.TicketExpires, nh[:], nonce, idem, now)
	if store.IsUniqueViolation(err) {
		return nil, 0, ErrIdemConflict
	}
	if err != nil {
		return nil, 0, err
	}
	a.Session = req.Session
	resp, hostTok, err := s.artifacts(p, a, host)
	if err != nil {
		return nil, 0, err
	}
	s.Hub.RegisterAttempt(a.ID, a.Phone, a.Host, now.Add(5*time.Minute))
	err = s.Hub.SendToAgent(ctx, a.Host, "attempt.incoming", map[string]any{
		"payload": map[string]any{"attempt_id": a.ID, "phone_device_id": a.Phone, "ticket": resp["ticket"],
			"relay": map[string]string{"url": s.RelayURL, "token": hostTok}, "ice_servers": s.iceServers(a.ID)}})
	if err != nil {
		_ = s.setStatus(ctx, a.ID, "failed", "", "agent_offline")
		s.Hub.EndAttempt(a.ID)
		return nil, 0, ErrOffline
	}
	_ = store.WriteAudit(ctx, s.Store.Pool, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
		TargetDeviceID: &req.Host, EventType: "connection_attempt", Outcome: "success", RequestID: reqID,
		Metadata: map[string]any{"attempt_id": a.ID}})
	return resp, http.StatusCreated, nil
}

var randRead = rand.Read

// ---- status transitions ----

var terminal = map[string]bool{"failed": true, "canceled": true, "expired": true, "revoked": true}

func allowed(from, to string) bool {
	if terminal[from] {
		return false
	}
	connected := map[string]bool{"connected_direct": true, "connected_relay": true, "connected_wss": true}
	switch to {
	case "signaling", "ice_checking", "relay_fallback":
		return !connected[from]
	case "connected_direct", "connected_relay", "connected_wss":
		return !connected[from] || from == to
	case "failed", "canceled":
		return true
	}
	return false
}

var pathForStatus = map[string]string{"connected_direct": "direct", "connected_relay": "turn_udp", "connected_wss": "wss_relay"}

func (s *Service) setStatus(ctx context.Context, id uuid.UUID, to, path, failure string) error {
	return s.Store.InTx(ctx, func(tx pgx.Tx) error {
		a, err := scanAttempt(tx.QueryRow(ctx, `SELECT `+attemptCols+` FROM connection_attempts WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if !allowed(a.Status, to) {
			return ErrTransition
		}
		if path == "" {
			path = pathForStatus[to]
		}
		_, err = tx.Exec(ctx, `UPDATE connection_attempts SET status = $2,
			path_type = COALESCE(NULLIF($3,''), path_type), failure_code = COALESCE(NULLIF($4,''), failure_code),
			connected_at = CASE WHEN $2 LIKE 'connected_%' AND connected_at IS NULL THEN now() ELSE connected_at END,
			ended_at = CASE WHEN $2 IN ('failed','canceled') THEN now() ELSE ended_at END
			WHERE id = $1`, id, to, path, failure)
		return err
	})
}

// AgentStatus applies an attempt.status report from a host's control socket.
func (s *Service) AgentStatus(ctx context.Context, host, id uuid.UUID, status, path, failure string) {
	a, err := scanAttempt(s.Store.Pool.QueryRow(ctx, `SELECT `+attemptCols+` FROM connection_attempts WHERE id = $1`, id))
	if err != nil || a.Host != host {
		return
	}
	if !validPath(path) {
		path = ""
	}
	if status == "ended" {
		// A connected session closed: record when, keep how it connected.
		_, _ = s.Store.Pool.Exec(ctx, `UPDATE connection_attempts SET ended_at = now()
			WHERE id = $1 AND ended_at IS NULL AND status IN ('connected_direct','connected_relay','connected_wss')`, id)
		return
	}
	if s.setStatus(ctx, id, status, path, failure) == nil && terminal[status] {
		s.Hub.EndAttempt(id)
		s.Hub.SendToPhone(ctx, a.Phone, map[string]any{"type": "attempt_status", "attempt_id": id, "status": status, "failure_code": failure})
	}
}

func validPath(p string) bool {
	switch p {
	case "", "direct", "turn_udp", "turn_tcp", "turn_tls", "wss_relay", "unknown":
		return true
	}
	return false
}

// ---- routes ----

// Routes registers the connection endpoints.
func (s *Service) Routes(mux *http.ServeMux) {
	h := func(f httpx.Handler) http.Handler { return s.Auth.RequirePhone(f) }

	mux.Handle("POST /v1/connections", h(func(w http.ResponseWriter, r *http.Request) error {
		var req createReq
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		resp, code, err := s.create(r.Context(), auth.FromContext(r.Context()), req, r.Header.Get("Idempotency-Key"), httpx.RequestID(r.Context()))
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, code, resp)
		return nil
	}))

	load := func(r *http.Request) (attemptRow, error) {
		p := auth.FromContext(r.Context())
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			return attemptRow{}, httpx.ErrNotFound
		}
		return scanAttempt(s.Store.Pool.QueryRow(r.Context(), `SELECT `+attemptCols+` FROM connection_attempts
			WHERE id = $1 AND account_id = $2 AND phone_device_id = $3`, id, p.AccountID, p.DeviceID))
	}
	view := func(a attemptRow) map[string]any {
		return map[string]any{"id": a.ID, "status": a.Status, "path_type": a.PathType, "failure_code": a.Failure,
			"created_at": a.Created, "connected_at": a.ConnectedAt, "ended_at": a.EndedAt}
	}

	mux.Handle("GET /v1/connections/{id}", h(func(w http.ResponseWriter, r *http.Request) error {
		a, err := load(r)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, view(a))
		return nil
	}))

	mux.Handle("PATCH /v1/connections/{id}", h(func(w http.ResponseWriter, r *http.Request) error {
		a, err := load(r)
		if err != nil {
			return err
		}
		var req struct {
			Status      string `json:"status"`
			PathType    string `json:"path_type"`
			FailureCode string `json:"failure_code"`
		}
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		switch req.Status {
		case "connected_direct", "connected_relay", "connected_wss", "failed", "canceled":
		default:
			return ErrTransition
		}
		if !validPath(req.PathType) || len(req.FailureCode) > 96 {
			return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid path_type or failure_code.")
		}
		if a.Status == "canceled" && req.Status == "canceled" {
			httpx.WriteJSON(w, http.StatusOK, view(a)) // idempotent cancel
			return nil
		}
		if err := s.setStatus(r.Context(), a.ID, req.Status, req.PathType, req.FailureCode); err != nil {
			return err
		}
		if terminal[req.Status] {
			s.Hub.EndAttempt(a.ID)
			_ = s.Hub.SendToAgent(r.Context(), a.Host, "attempt.cancel", map[string]any{"attempt_id": a.ID})
		}
		a, err = load(r)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, view(a))
		return nil
	}))

	mux.Handle("POST /v1/connections/{id}/turn-credentials", h(func(w http.ResponseWriter, r *http.Request) error {
		a, err := load(r)
		if err != nil {
			return err
		}
		if terminal[a.Status] {
			return ErrNotLive
		}
		var live bool
		_ = s.Store.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM access_grants WHERE id = $1 AND revoked_at IS NULL
			AND (expires_at IS NULL OR expires_at > now()))`, a.Grant).Scan(&live)
		if !live {
			return ErrNotLive
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ice_servers": s.iceServers(a.ID)})
		return nil
	}))
}
