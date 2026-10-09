// Package hub keeps the live WebSockets: one control socket per host agent
// (/v1/agent/control) and signaling sockets for phones (/v1/signaling). It
// routes signaling only between the phone and host of a live attempt, pushes
// grant leases and revocation notices, and reports agent presence.
package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/nonce"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Timings and limits (proposed values).
const (
	LeaseTTL = 10 * time.Minute
	// AgentSilence: agents heartbeat every 25 s; a socket silent for longer
	// than this is dead (half-open) and is closed so presence goes stale and
	// the agent's reconnect replaces it.
	AgentSilence     = 75 * time.Second
	LeaseRenew       = 3 * time.Minute
	AuthTimeout      = 10 * time.Second
	MaxFrame         = 64 << 10
	AttemptLife      = 5 * time.Minute
	MaxSignalsPerAtt = 100
	MaxCandidatesAtt = 50
	writeTimeout     = 5 * time.Second
	CloseAuthFailed  = websocket.StatusCode(4401)
	CloseRevoked     = websocket.StatusCode(4403)
	CloseSuperseded  = websocket.StatusCode(4400)
	CloseRateLimited = websocket.StatusCode(4429)
	SubProtocol      = "prw.v1"
)

// agentAllowlist is every message type the server may send to an agent.
var agentAllowlist = map[string]bool{
	"auth.challenge": true, "auth.ok": true, "auth.error": true, "heartbeat.ack": true,
	"attempt.incoming": true, "attempt.cancel": true, "grant.lease": true, "revoke_notice": true,
	"jwks.update": true, "pairing.approved": true, "server.notice": true, "signal": true,
}

// Msg is a control/signaling message.
type Msg struct {
	Type      string          `json:"type"`
	AttemptID string          `json:"attempt_id,omitempty"`
	Kind      string          `json:"kind,omitempty"`
	From      string          `json:"from_device_id,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

// Hub holds live sockets.
type Hub struct {
	Store  *store.Store
	Auth   *auth.Service
	Ticket token.Issuer // signs leases
	JWKS   func() any   // {"keys":[...]} for auth.ok
	Log    *slog.Logger
	Nonces *nonce.Store
	// Silence overrides AgentSilence (tests).
	Silence time.Duration
	// OnAttemptStatus is called for agent attempt.status reports.
	OnAttemptStatus func(ctx context.Context, host uuid.UUID, attemptID uuid.UUID, status, path, failure string)

	mu       sync.Mutex
	agents   map[uuid.UUID]*sock
	phones   map[uuid.UUID]map[*sock]bool
	attempts map[uuid.UUID]*attempt
}

type sock struct {
	ws      *websocket.Conn
	device  uuid.UUID
	account uuid.UUID
	wmu     sync.Mutex
	cancel  context.CancelFunc
}

type attempt struct {
	phone, host uuid.UUID
	created     time.Time
	expires     time.Time
	signals     int
	candidates  int
	// pending holds host->phone messages sent before the phone's signaling
	// socket was connected (at most maxPending, delivered on connect).
	pending []any
}

const (
	maxPending  = 32
	pendingLife = 15 * time.Second
)

func (h *Hub) init() {
	if h.agents == nil {
		h.agents = map[uuid.UUID]*sock{}
		h.phones = map[uuid.UUID]map[*sock]bool{}
		h.attempts = map[uuid.UUID]*attempt{}
	}
	if h.Log == nil {
		h.Log = slog.Default()
	}
	if h.Nonces == nil {
		h.Nonces = nonce.New(time.Minute, 10000)
	}
}

func (s *sock) send(ctx context.Context, m any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return s.ws.Write(ctx, websocket.MessageText, b)
}

// Connected reports whether a host has an authenticated control socket.
func (h *Hub) Connected(host uuid.UUID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	return h.agents[host] != nil
}

// SendToAgent delivers an allowlisted message to a host's control socket.
func (h *Hub) SendToAgent(ctx context.Context, host uuid.UUID, typ string, body map[string]any) error {
	if !agentAllowlist[typ] {
		return fmt.Errorf("hub: %q is not allowed to agents", typ)
	}
	h.mu.Lock()
	h.init()
	s := h.agents[host]
	h.mu.Unlock()
	if s == nil {
		return ErrOffline
	}
	m := map[string]any{"type": typ}
	for k, v := range body {
		m[k] = v
	}
	return s.send(ctx, m)
}

// SendToPhone delivers a message to every signaling socket of a phone.
func (h *Hub) SendToPhone(ctx context.Context, phone uuid.UUID, m any) {
	h.mu.Lock()
	h.init()
	var socks []*sock
	for s := range h.phones[phone] {
		socks = append(socks, s)
	}
	h.mu.Unlock()
	for _, s := range socks {
		_ = s.send(ctx, m)
	}
}

// ErrOffline is returned when the target has no live socket.
var ErrOffline = errors.New("hub: offline")

// RegisterAttempt allows signaling between phone and host for attemptID.
func (h *Hub) RegisterAttempt(id, phone, host uuid.UUID, expires time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	now := time.Now()
	for k, a := range h.attempts { // opportunistic cleanup
		if now.After(a.expires) {
			delete(h.attempts, k)
		}
	}
	h.attempts[id] = &attempt{phone: phone, host: host, created: now, expires: expires}
}

// EndAttempt forbids further signaling for an attempt.
func (h *Hub) EndAttempt(id uuid.UUID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.init()
	delete(h.attempts, id)
}

// Disconnect closes a device's sockets with code (used on revocation).
func (h *Hub) Disconnect(dev uuid.UUID, code websocket.StatusCode, reason string) {
	h.mu.Lock()
	h.init()
	var socks []*sock
	if a := h.agents[dev]; a != nil {
		socks = append(socks, a)
	}
	for s := range h.phones[dev] {
		socks = append(socks, s)
	}
	h.mu.Unlock()
	for _, s := range socks {
		_ = s.ws.Close(code, reason)
	}
}

// route forwards a signaling message from one end of an attempt to the other.
func (h *Hub) route(ctx context.Context, from uuid.UUID, fromHost bool, m Msg) error {
	id, err := uuid.Parse(m.AttemptID)
	if err != nil {
		return errBadSignal
	}
	switch m.Kind {
	case "offer", "answer", "ice_candidate", "ice_complete", "tls_fingerprint", "attempt_cancel":
	default:
		return errBadSignal
	}
	h.mu.Lock()
	h.init()
	a := h.attempts[id]
	if a == nil || time.Now().After(a.expires) {
		h.mu.Unlock()
		return errBadSignal
	}
	if (fromHost && a.host != from) || (!fromHost && a.phone != from) {
		h.mu.Unlock()
		return errBadSignal
	}
	a.signals++
	if m.Kind == "ice_candidate" {
		a.candidates++
	}
	if a.signals > MaxSignalsPerAtt || a.candidates > MaxCandidatesAtt {
		h.mu.Unlock()
		return errSignalLimit
	}
	phone, host := a.phone, a.host
	h.mu.Unlock()

	// The sender is derived from the socket; never trust a client value.
	out := Msg{Type: "signal", AttemptID: m.AttemptID, Kind: m.Kind, From: from.String(), Payload: m.Payload}
	if fromHost {
		h.mu.Lock()
		online := len(h.phones[phone]) > 0
		if !online && len(a.pending) < maxPending && time.Since(a.created) < pendingLife {
			a.pending = append(a.pending, out)
		}
		h.mu.Unlock()
		if online {
			h.SendToPhone(ctx, phone, out)
		}
		return nil
	}
	b, _ := json.Marshal(out)
	var body map[string]any
	_ = json.Unmarshal(b, &body)
	delete(body, "type")
	if err := h.SendToAgent(ctx, host, "signal", body); err != nil {
		h.SendToPhone(ctx, phone, map[string]any{"type": "attempt_status", "attempt_id": m.AttemptID, "status": "failed", "failure_code": "agent_offline"})
	}
	return nil
}

var (
	errBadSignal   = errors.New("hub: signal not allowed")
	errSignalLimit = errors.New("hub: signaling limit")
)

func accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	// Browsers must not drive these sockets: reject any Origin header.
	if r.Header.Get("Origin") != "" {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return nil, errors.New("origin")
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{SubProtocol}})
	if err != nil {
		return nil, err
	}
	ws.SetReadLimit(MaxFrame)
	return ws, nil
}

func read(ctx context.Context, ws *websocket.Conn, timeout time.Duration) (Msg, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	typ, b, err := ws.Read(ctx)
	if err != nil {
		return Msg{}, err
	}
	if typ != websocket.MessageText {
		return Msg{}, errBadSignal
	}
	var m Msg
	if err := json.Unmarshal(b, &m); err != nil {
		return Msg{}, errBadSignal
	}
	return m, nil
}

// ---- agents ----

type authResponse struct {
	DeviceID     string `json:"device_id"`
	Sig          string `json:"sig"`
	AgentVersion string `json:"agent_version"`
}

// ServeAgent handles /v1/agent/control.
func (h *Hub) ServeAgent(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.init()
	h.mu.Unlock()
	ws, err := accept(w, r)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n, exp, _ := h.Nonces.Issue()
	s := &sock{ws: ws, cancel: cancel}
	if err := s.send(ctx, map[string]any{"type": "auth.challenge", "nonce": n, "exp": exp.Unix()}); err != nil {
		ws.CloseNow()
		return
	}
	dev, err := h.agentLogin(ctx, ws, n)
	if err != nil {
		_ = s.send(ctx, map[string]any{"type": "auth.error", "code": err.Error()})
		code := CloseAuthFailed
		if err.Error() == "device_revoked" {
			code = CloseRevoked
		}
		_ = ws.Close(code, err.Error())
		return
	}
	s.device, s.account = dev.ID, dev.AccountID

	h.mu.Lock()
	old := h.agents[dev.ID]
	h.agents[dev.ID] = s
	h.mu.Unlock()
	if old != nil {
		_ = old.ws.Close(CloseSuperseded, "superseded by a newer connection")
	}
	defer func() {
		h.mu.Lock()
		if h.agents[dev.ID] == s {
			delete(h.agents, dev.ID)
		}
		h.mu.Unlock()
	}()

	_ = store.TouchDevice(ctx, h.Store.Pool, dev.ID, "")
	if err := s.send(ctx, map[string]any{"type": "auth.ok", "device_id": dev.ID, "account_id": dev.AccountID, "jwks": h.JWKS()}); err != nil {
		return
	}
	if err := h.SendLease(ctx, dev.ID); err != nil {
		h.Log.Warn("lease send failed", "device_id", dev.ID, "err", err)
		return
	}
	go func() {
		t := time.NewTicker(LeaseRenew)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if err := h.SendLease(ctx, dev.ID); err != nil {
					cancel()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	silence := h.Silence
	if silence == 0 {
		silence = AgentSilence
	}
	for {
		m, err := read(ctx, ws, silence)
		if err != nil {
			if ctx.Err() == nil {
				_ = ws.Close(websocket.StatusCode(4408), "no heartbeat")
			}
			return
		}
		switch m.Type {
		case "heartbeat":
			var hb struct {
				AgentVersion string          `json:"agent_version"`
				Capabilities json.RawMessage `json:"capabilities"`
			}
			_ = json.Unmarshal(m.Payload, &hb)
			_ = store.TouchDevice(ctx, h.Store.Pool, dev.ID, hb.AgentVersion)
			if len(hb.Capabilities) > 0 && len(hb.Capabilities) < 4096 && json.Valid(hb.Capabilities) {
				_, _ = h.Store.Pool.Exec(ctx, `UPDATE devices SET capabilities = $2 WHERE id = $1`, dev.ID, hb.Capabilities)
			}
			_ = s.send(ctx, map[string]any{"type": "heartbeat.ack"})
		case "signal":
			if err := h.route(ctx, dev.ID, true, m); errors.Is(err, errSignalLimit) {
				_ = ws.Close(CloseRateLimited, "signaling_limit")
				return
			}
		case "attempt.status":
			var st struct {
				Status      string `json:"status"`
				PathType    string `json:"path_type"`
				FailureCode string `json:"failure_code"`
			}
			_ = json.Unmarshal(m.Payload, &st)
			if id, err := uuid.Parse(m.AttemptID); err == nil && h.OnAttemptStatus != nil {
				h.OnAttemptStatus(ctx, dev.ID, id, st.Status, st.PathType, st.FailureCode)
			}
		default:
			// Unknown agent messages are ignored (forward compatibility).
		}
	}
}

func (h *Hub) agentLogin(ctx context.Context, ws *websocket.Conn, n string) (store.Device, error) {
	m, err := read(ctx, ws, AuthTimeout)
	if err != nil || m.Type != "auth.response" {
		return store.Device{}, errors.New("unauthenticated")
	}
	var ar authResponse
	if json.Unmarshal(m.Payload, &ar) != nil {
		return store.Device{}, errors.New("unauthenticated")
	}
	id, err := uuid.Parse(ar.DeviceID)
	if err != nil {
		return store.Device{}, errors.New("unauthenticated")
	}
	if !h.Nonces.Consume(n) {
		return store.Device{}, errors.New("unauthenticated")
	}
	dev, err := store.GetDeviceByID(ctx, h.Store.Pool, id)
	if err != nil || dev.Kind != "host" {
		return store.Device{}, errors.New("unauthenticated")
	}
	pub, err := attest.ParsePublicKey(dev.PublicKey)
	if err != nil {
		return store.Device{}, errors.New("unauthenticated")
	}
	if err := attest.VerifyPoP(pub, ar.Sig, attest.PoP{Purpose: attest.PurposeAgent, Nonce: n, DeviceID: id.String()}, time.Now()); err != nil {
		return store.Device{}, errors.New("unauthenticated")
	}
	if dev.AdminState == "revoked" {
		return store.Device{}, errors.New("device_revoked")
	}
	_ = store.TouchDevice(ctx, h.Store.Pool, id, ar.AgentVersion)
	return dev, nil
}

// SendLease signs and pushes the current grant lease to a connected host.
func (h *Hub) SendLease(ctx context.Context, host uuid.UUID) error {
	rows, err := h.Store.Pool.Query(ctx, `
		SELECT g.id, g.phone_device_id, d.public_key, g.capabilities, g.expires_at
		FROM access_grants g JOIN devices d ON d.id = g.phone_device_id
		WHERE g.host_device_id = $1 AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > now())
		  AND d.admin_state = 'active'
		  AND EXISTS (SELECT 1 FROM devices hd WHERE hd.id = $1 AND hd.admin_state = 'active')`, host)
	if err != nil {
		return err
	}
	grants := []token.LeaseGrant{}
	for rows.Next() {
		var gid, phone uuid.UUID
		var key []byte
		var caps []string
		var exp *time.Time
		if err := rows.Scan(&gid, &phone, &key, &caps, &exp); err != nil {
			rows.Close()
			return err
		}
		lg := token.LeaseGrant{PhoneDeviceID: phone.String(), PhoneKeySPKI: base64.RawURLEncoding.EncodeToString(key), Caps: caps, GrantID: gid.String()}
		if exp != nil {
			lg.GrantExpiresAt = exp.Unix()
		}
		grants = append(grants, lg)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now()
	lease, err := h.Ticket.Issue(token.TypeLease, token.Lease{
		Registered: token.Registered{IAT: now.Unix(), NBF: now.Unix(), EXP: now.Add(LeaseTTL).Unix(), JTI: store.NewID().String()},
		Host:       host.String(), Grants: grants})
	if err != nil {
		return err
	}
	return h.SendToAgent(ctx, host, "grant.lease", map[string]any{"lease": lease})
}

// ---- phones ----

// ServePhone handles /v1/signaling.
func (h *Hub) ServePhone(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.init()
	h.mu.Unlock()
	ws, err := accept(w, r)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := read(ctx, ws, AuthTimeout)
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err == nil {
		_ = json.Unmarshal(first.Payload, &tok)
	}
	p, perr := h.phoneAuth(ctx, first.Type, tok.AccessToken)
	if err != nil || perr != nil {
		_ = ws.Close(CloseAuthFailed, "unauthenticated")
		return
	}
	s := &sock{ws: ws, device: p.DeviceID, account: p.AccountID, cancel: cancel}
	h.mu.Lock()
	if h.phones[p.DeviceID] == nil {
		h.phones[p.DeviceID] = map[*sock]bool{}
	}
	h.phones[p.DeviceID][s] = true
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.phones[p.DeviceID], s)
		if len(h.phones[p.DeviceID]) == 0 {
			delete(h.phones, p.DeviceID)
		}
		h.mu.Unlock()
	}()
	_ = s.send(ctx, map[string]any{"type": "auth.ok"})
	// Deliver host messages that arrived before this socket existed.
	h.mu.Lock()
	var backlog []any
	for _, a := range h.attempts {
		if a.phone == p.DeviceID {
			backlog = append(backlog, a.pending...)
			a.pending = nil
		}
	}
	h.mu.Unlock()
	for _, m := range backlog {
		_ = s.send(ctx, m)
	}
	for {
		m, err := read(ctx, ws, 0)
		if err != nil {
			return
		}
		if m.Type != "signal" {
			continue
		}
		if err := h.route(ctx, p.DeviceID, false, m); errors.Is(err, errSignalLimit) {
			_ = ws.Close(CloseRateLimited, "signaling_limit")
			return
		}
	}
}

func (h *Hub) phoneAuth(ctx context.Context, typ, access string) (*auth.Principal, error) {
	if typ != "auth" || access == "" {
		return nil, errors.New("unauthenticated")
	}
	var p *auth.Principal
	rec := &probe{}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	h.Auth.RequirePhone(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		p = auth.FromContext(r.Context())
	})).ServeHTTP(rec, req)
	if p == nil {
		return nil, errors.New("unauthenticated")
	}
	return p, nil
}

type probe struct{ h http.Header }

func (p *probe) Header() http.Header {
	if p.h == nil {
		p.h = http.Header{}
	}
	return p.h
}
func (p *probe) Write(b []byte) (int, error) { return len(b), nil }
func (p *probe) WriteHeader(int)             {}
