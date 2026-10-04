// Package pairing enrols host computers (protocol v1 §4, API §5).
//
//	host  POST /v1/pairing/challenges            (self-signed with the host key)
//	host  GET  /v1/pairing/challenges/{id}/wait  (WaitToken, long poll)
//	phone POST /v1/pairing/resolve               (QR ref or typed code)
//	phone POST /v1/pairing/challenges/{id}/approve  (fingerprint must match)
//	host  POST /v1/pairing/challenges/{id}/complete (signature over nonce2)
//
// Only HMACs of the pairing ref, display code and wait token are stored.
package pairing

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Defaults.
const (
	TTL        = 5 * time.Minute
	WaitMax    = 25 * time.Second
	MaxFailed  = 5
	bodyLimit  = 4 << 10
	pollPeriod = 250 * time.Millisecond
)

// API errors.
var (
	ErrExpired     = httpx.E(http.StatusGone, "pairing_expired", "This pairing code expired. Start pairing again on the computer.")
	ErrUsed        = httpx.E(http.StatusConflict, "pairing_used", "This pairing code was already used.")
	ErrRejected    = httpx.E(http.StatusConflict, "pairing_rejected", "Pairing was canceled.")
	ErrLocked      = httpx.E(http.StatusLocked, "pairing_locked", "Too many failed attempts. Start pairing again on the computer.")
	ErrMismatch    = httpx.E(http.StatusConflict, "pairing_fingerprint_mismatch", "The computer's key does not match the QR code.")
	ErrNotApproved = &httpx.Error{Status: http.StatusConflict, Code: "pairing_not_approved", Message: "Not approved yet.", Retryable: true}
	ErrSignature   = httpx.E(http.StatusForbidden, "signature_invalid", "Key verification failed.")
	ErrHostExists  = httpx.E(http.StatusConflict, "device_exists", "This computer is already enrolled.")
)

// JWK is an Ed25519 public key in JWK form (pinned by hosts).
type JWK struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
}

// Service implements pairing.
type Service struct {
	Store     *store.Store
	Auth      *auth.Service
	Pepper    []byte
	APIURL    string // https://api.example.invalid
	ControlWS string // wss://api.example.invalid/v1/agent/control
	JWKS      func() []JWK
	Now       func() time.Time
	// WaitFor caps one long poll (default WaitMax).
	WaitFor time.Duration
	// Approved is notified (best effort) when a challenge is approved, to
	// wake long polls early.
	waiters waiters
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type challenge struct {
	ID              uuid.UUID
	WaitTokenHMAC   []byte
	HostPublicKey   []byte
	HostFingerprint string
	HostName        string
	HostOS          *string
	AgentVersion    string
	ApproveNonce    []byte
	Status          string
	Failed          int
	AccountID       *uuid.UUID
	ApprovedBy      *uuid.UUID
	GrantTo         *uuid.UUID
	ResultingDevice *uuid.UUID
	ExpiresAt       time.Time
}

const challengeCols = `id, wait_token_hmac, host_public_key, host_key_fingerprint, host_name, host_os, agent_version,
	approve_nonce, status, failed_attempts, account_id, approved_by_device_id, grant_to_device_id, resulting_device_id, expires_at`

func scan(r pgx.Row) (challenge, error) {
	var c challenge
	err := r.Scan(&c.ID, &c.WaitTokenHMAC, &c.HostPublicKey, &c.HostFingerprint, &c.HostName, &c.HostOS, &c.AgentVersion,
		&c.ApproveNonce, &c.Status, &c.Failed, &c.AccountID, &c.ApprovedBy, &c.GrantTo, &c.ResultingDevice, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, httpx.ErrNotFound
	}
	return c, err
}

// statusErr maps a non-live challenge to its API error.
func (s *Service) statusErr(c challenge) error {
	switch {
	case c.Status == "consumed":
		return ErrUsed
	case c.Status == "canceled":
		return ErrRejected
	case c.Status == "locked":
		return ErrLocked
	case c.Status == "expired" || !s.now().Before(c.ExpiresAt):
		return ErrExpired
	}
	return nil
}

// ---- host: create ----

type createReq struct {
	SPKI     string `json:"host_public_key_spki"`
	Hostname string `json:"hostname"`
	OS       struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	} `json:"os"`
	AgentVersion string `json:"agent_version"`
	Proto        struct {
		Min int `json:"min"`
		Max int `json:"max"`
	} `json:"proto"`
	PoPSig string `json:"pop_sig"`
}

func (s *Service) create(ctx context.Context, req createReq) (map[string]any, error) {
	spki, err := base64.RawURLEncoding.DecodeString(req.SPKI)
	if err != nil {
		return nil, httpx.E(http.StatusBadRequest, "validation_failed", "Invalid host key.")
	}
	pub, err := attest.ParsePublicKey(spki)
	if err != nil {
		return nil, httpx.E(http.StatusBadRequest, "validation_failed", "Invalid host key.")
	}
	name, ok := auth.CleanDisplayName(req.Hostname)
	if !ok || len(req.AgentVersion) == 0 || len(req.AgentVersion) > 64 || len(req.OS.ID) > 32 || len(req.OS.Version) > 31 {
		return nil, httpx.E(http.StatusBadRequest, "validation_failed", "Invalid host details.")
	}
	if req.Proto.Min > 1 {
		return nil, httpx.E(http.StatusUpgradeRequired, "unsupported_agent_version", "This agent needs a newer server.")
	}
	fp := attest.Fingerprint(spki)
	if err := attest.VerifyPoP(pub, req.PoPSig, attest.PoP{Purpose: attest.PurposePairCreate, SPKIFP: fp}, s.now()); err != nil {
		return nil, ErrSignature
	}
	ref, code, wait := random(16), NewCode(), random(32)
	nonce := randBytes(32)
	id := store.NewID()
	exp := s.now().Add(TTL)
	var osStr *string
	if req.OS.ID != "" {
		v := strings.TrimSpace(req.OS.ID + " " + req.OS.Version)
		osStr = &v
	}
	_, err = s.Store.Pool.Exec(ctx, `INSERT INTO pairing_challenges (id, ref_hmac, code_hmac, wait_token_hmac, host_public_key,
		host_key_fingerprint, host_name, host_platform, host_os, agent_version, server_nonce, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'linux',$8,$9,$10,$11)`,
		id, mac(s.Pepper, "ref", ref), mac(s.Pepper, "code", NormalizeCode(code)), mac(s.Pepper, "wait", wait),
		spki, fp, name, osStr, req.AgentVersion, nonce, exp)
	if err != nil {
		return nil, err
	}
	q := url.Values{"v": {"1"}, "ref": {ref}, "fp": {fp}, "api": {s.APIURL}}
	return map[string]any{
		"challenge_id": id, "pairing_ref": ref, "display_code": code, "expires_at": exp.UTC().Format(time.RFC3339),
		"wait_token": wait, "qr_payload": "prw://pair?" + q.Encode(),
	}, nil
}

// waitAuth loads a challenge authenticated by its wait token.
func (s *Service) waitAuth(ctx context.Context, q store.Q, r *http.Request, lock bool) (challenge, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return challenge{}, httpx.ErrNotFound
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return challenge{}, httpx.ErrUnauthenticated
	}
	sql := `SELECT ` + challengeCols + ` FROM pairing_challenges WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	c, err := scan(q.QueryRow(ctx, sql, id))
	if err != nil {
		return c, err
	}
	if !hmac.Equal(c.WaitTokenHMAC, mac(s.Pepper, "wait", tok)) {
		return c, httpx.ErrUnauthenticated
	}
	return c, nil
}

// ---- host: wait ----

func (s *Service) wait(ctx context.Context, r *http.Request) (map[string]any, error) {
	c, err := s.waitAuth(ctx, s.Store.Pool, r, false)
	if err != nil {
		return nil, err
	}
	limit := s.WaitFor
	if limit == 0 {
		limit = WaitMax
	}
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	wake := s.waiters.get(c.ID)
	defer s.waiters.put(c.ID, wake)
	for {
		c, err = scan(s.Store.Pool.QueryRow(ctx, `SELECT `+challengeCols+` FROM pairing_challenges WHERE id = $1`, c.ID))
		if err != nil {
			return nil, err
		}
		if err := s.statusErr(c); err != nil {
			return nil, err
		}
		if c.Status == "approved" {
			return map[string]any{"status": "approved", "nonce2": base64.RawURLEncoding.EncodeToString(c.ApproveNonce)}, nil
		}
		select {
		case <-wake:
		case <-time.After(pollPeriod * 4):
		case <-deadline.C:
			return map[string]any{"status": "pending"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// ---- phone: resolve, approve, cancel ----

func (s *Service) resolve(ctx context.Context, ref, code string) (map[string]any, error) {
	var where string
	var key []byte
	switch {
	case ref != "" && code == "":
		where, key = "ref_hmac", mac(s.Pepper, "ref", ref)
	case code != "" && ref == "":
		n := NormalizeCode(code)
		if n == "" {
			return nil, httpx.ErrNotFound
		}
		where, key = "code_hmac", mac(s.Pepper, "code", n)
	default:
		return nil, httpx.E(http.StatusBadRequest, "validation_failed", "Send pairing_ref or display_code.")
	}
	c, err := scan(s.Store.Pool.QueryRow(ctx, `SELECT `+challengeCols+` FROM pairing_challenges WHERE `+where+` = $1`, key))
	if err != nil {
		return nil, err
	}
	if err := s.statusErr(c); err != nil {
		return nil, err
	}
	if c.Status != "pending" {
		return nil, ErrUsed
	}
	out := map[string]any{"challenge_id": c.ID, "hostname": c.HostName, "agent_version": c.AgentVersion,
		"host_key_fingerprint": c.HostFingerprint, "expires_at": c.ExpiresAt.UTC().Format(time.RFC3339), "compat": "ok"}
	if c.HostOS != nil {
		out["os"] = *c.HostOS
	}
	return out, nil
}

type approveReq struct {
	Fingerprint string `json:"host_key_fingerprint"`
	DisplayName string `json:"display_name"`
	Grant       bool   `json:"grant_to_this_phone"`
}

func (s *Service) approve(ctx context.Context, p *auth.Principal, id uuid.UUID, req approveReq, reqID string) error {
	var mismatch bool
	err := s.Store.InTx(ctx, func(tx pgx.Tx) error {
		c, err := scan(tx.QueryRow(ctx, `SELECT `+challengeCols+` FROM pairing_challenges WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if err := s.statusErr(c); err != nil {
			return err
		}
		if c.Status != "pending" {
			return ErrUsed
		}
		if !hmac.Equal([]byte(req.Fingerprint), []byte(c.HostFingerprint)) {
			// Count the failure (and lock) in this transaction, then report.
			mismatch = true
			status := "pending"
			if c.Failed+1 >= MaxFailed {
				status = "locked"
			}
			if _, err := tx.Exec(ctx, `UPDATE pairing_challenges SET failed_attempts = failed_attempts + 1, status = $2 WHERE id = $1`, id, status); err != nil {
				return err
			}
			return store.WriteAudit(ctx, tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
				EventType: "pairing_fingerprint_mismatch", Outcome: "denied", RequestID: reqID})
		}
		name := c.HostName
		if req.DisplayName != "" {
			n, ok := auth.CleanDisplayName(req.DisplayName)
			if !ok {
				return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid name.")
			}
			name = n
		}
		var grantTo *uuid.UUID
		if req.Grant {
			grantTo = &p.DeviceID
		}
		nonce2 := randBytes(32)
		if _, err := tx.Exec(ctx, `UPDATE pairing_challenges SET status = 'approved', account_id = $2, approved_by_device_id = $3,
			approved_at = now(), approve_nonce = $4, host_name = $5, grant_to_device_id = $6 WHERE id = $1`,
			id, p.AccountID, p.DeviceID, nonce2, name, grantTo); err != nil {
			return err
		}
		return store.WriteAudit(ctx, tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
			EventType: "pairing_approved", Outcome: "success", RequestID: reqID, Metadata: map[string]any{"grant": req.Grant}})
	})
	if err != nil {
		return err
	}
	if mismatch {
		return ErrMismatch
	}
	s.waiters.wake(id)
	return nil
}

func (s *Service) cancel(ctx context.Context, q store.Q, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `UPDATE pairing_challenges SET status = 'canceled' WHERE id = $1 AND status IN ('pending','approved')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrUsed
	}
	s.waiters.wake(id)
	return nil
}

// ---- host: complete ----

func (s *Service) complete(ctx context.Context, r *http.Request, sig string) (map[string]any, error) {
	var out map[string]any
	err := s.Store.InTx(ctx, func(tx pgx.Tx) error {
		c, err := s.waitAuth(ctx, tx, r, true)
		if err != nil {
			return err
		}
		if err := s.statusErr(c); err != nil {
			return err
		}
		if c.Status != "approved" {
			return ErrNotApproved
		}
		pub, err := attest.ParsePublicKey(c.HostPublicKey)
		if err != nil {
			return err
		}
		if err := attest.VerifyPoP(pub, sig, attest.PoP{Purpose: attest.PurposePairComplete, ChallengeID: c.ID.String(),
			Nonce: base64.RawURLEncoding.EncodeToString(c.ApproveNonce), SPKIFP: c.HostFingerprint}, s.now()); err != nil {
			return ErrSignature
		}
		ver := c.AgentVersion
		dev, err := store.InsertDevice(ctx, tx, store.NewDevice{AccountID: *c.AccountID, Kind: "host", Platform: "linux",
			DisplayName: c.HostName, PublicKey: c.HostPublicKey, KeyFingerprint: c.HostFingerprint, SoftwareVersion: ver})
		if store.IsUniqueViolation(err) {
			return ErrHostExists
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE pairing_challenges SET status = 'consumed', consumed_at = now(), resulting_device_id = $2
			WHERE id = $1`, c.ID, dev.ID); err != nil {
			return err
		}
		granted := false
		if c.GrantTo != nil {
			g, err := store.InsertGrant(ctx, tx, *c.AccountID, *c.GrantTo, dev.ID, []string{"terminal"}, nil, *c.GrantTo)
			if err == nil {
				granted = true
				_ = g
			} else if !errors.Is(err, store.ErrNotFound) { // phone revoked meanwhile: just skip the grant
				return err
			}
		}
		if err := store.WriteAudit(ctx, tx, store.Audit{AccountID: c.AccountID, ActorKind: "host", ActorDeviceID: &dev.ID,
			TargetDeviceID: &dev.ID, EventType: "device_enrolled", Outcome: "success", RequestID: httpx.RequestID(ctx),
			Metadata: map[string]any{"kind": "host", "granted": granted}}); err != nil {
			return err
		}
		out = map[string]any{"device_id": dev.ID, "account_id": *c.AccountID, "jwks": map[string]any{"keys": s.JWKS()},
			"control_ws_url": s.ControlWS}
		return nil
	})
	return out, err
}

// ---- routes ----

// Routes registers the pairing endpoints.
func (s *Service) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/pairing/challenges", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var req createReq
		if err := httpx.Decode(w, r, bodyLimit, &req); err != nil {
			return err
		}
		out, err := s.create(r.Context(), req)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.Handle("GET /v1/pairing/challenges/{id}/wait", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		out, err := s.wait(r.Context(), r)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/pairing/challenges/{id}/complete", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Sig string `json:"sig"`
		}
		if err := httpx.Decode(w, r, bodyLimit, &req); err != nil {
			return err
		}
		out, err := s.complete(r.Context(), r, req.Sig)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.Handle("POST /v1/pairing/resolve", s.Auth.RequirePhone(httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Ref  string `json:"pairing_ref"`
			Code string `json:"display_code"`
		}
		if err := httpx.Decode(w, r, bodyLimit, &req); err != nil {
			return err
		}
		out, err := s.resolve(r.Context(), req.Ref, req.Code)
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, out)
		return nil
	})))
	mux.Handle("POST /v1/pairing/challenges/{id}/approve", s.Auth.RequirePhone(httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			return httpx.ErrNotFound
		}
		var req approveReq
		if err := httpx.Decode(w, r, bodyLimit, &req); err != nil {
			return err
		}
		if err := s.approve(r.Context(), auth.FromContext(r.Context()), id, req, httpx.RequestID(r.Context())); err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "approved"})
		return nil
	})))
	mux.Handle("POST /v1/pairing/challenges/{id}/cancel", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			return httpx.ErrNotFound
		}
		// Either the host (wait token) or a signed-in phone may cancel.
		if _, err := s.waitAuth(r.Context(), s.Store.Pool, r, false); err != nil {
			var phoneOK bool
			s.Auth.RequirePhone(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { phoneOK = true })).ServeHTTP(discard{}, r)
			if !phoneOK {
				return httpx.ErrUnauthenticated
			}
		}
		if err := s.cancel(r.Context(), s.Store.Pool, id); err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "canceled"})
		return nil
	}))
}

// discard is a ResponseWriter that drops output (used to probe phone auth).
type discard struct{}

func (discard) Header() http.Header         { return http.Header{} }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}
