package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Body limits.
const (
	exchangeLimit = 16 << 10
	defaultLimit  = 64 << 10
)

// Principal is the authenticated phone behind a request.
type Principal struct {
	AccountID uuid.UUID
	DeviceID  uuid.UUID
	SessionID uuid.UUID
}

type principalKey struct{}

// FromContext returns the principal set by RequirePhone.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// RequirePhone authenticates the bearer token and re-checks, on every
// request, that the session is live and the device is not revoked, so a
// revocation takes effect immediately rather than when the token expires.
func (s *Service) RequirePhone(next http.Handler) http.Handler {
	return httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		h := r.Header.Get("Authorization")
		raw, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || raw == "" {
			return httpx.ErrUnauthenticated
		}
		a, err := s.Tokens.Verify(raw)
		if err != nil {
			return httpx.ErrUnauthenticated
		}
		acct, err1 := uuid.Parse(a.SUB)
		dev, err2 := uuid.Parse(a.DID)
		sid, err3 := uuid.Parse(a.SID)
		if err1 != nil || err2 != nil || err3 != nil {
			return httpx.ErrUnauthenticated
		}
		ctx := r.Context()
		// Device first, so a revoked phone learns why rather than seeing a
		// generic sign-in error (its sessions are revoked with it).
		d, err := store.GetDevice(ctx, s.Store.Pool, acct, dev)
		if err != nil {
			return httpx.ErrUnauthenticated
		}
		if d.AdminState == "revoked" {
			return ErrDeviceRevoked
		}
		sess, err := store.GetLiveAuthSession(ctx, s.Store.Pool, sid)
		if errors.Is(err, store.ErrNotFound) || (err == nil && (sess.DeviceID != dev || sess.AccountID != acct)) {
			return httpx.ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		p := &Principal{AccountID: acct, DeviceID: dev, SessionID: sid}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, principalKey{}, p)))
		return nil
	})
}

// Routes registers the auth endpoints on mux.
func (s *Service) Routes(mux *http.ServeMux) {
	mux.Handle("POST /v1/auth/challenge", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		n, exp, err := s.Challenge()
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"nonce": n, "expires_at": exp.UTC().Format(time.RFC3339)})
		return nil
	}))
	mux.Handle("POST /v1/auth/exchange", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var req ExchangeRequest
		if err := httpx.Decode(w, r, exchangeLimit, &req); err != nil {
			return err
		}
		res, err := s.Exchange(r.Context(), req, httpx.RequestID(r.Context()), r.UserAgent())
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.Handle("POST /v1/auth/refresh", httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		var req RefreshRequest
		if err := httpx.Decode(w, r, defaultLimit, &req); err != nil {
			return err
		}
		res, err := s.Refresh(r.Context(), req, httpx.RequestID(r.Context()), r.UserAgent())
		if err != nil {
			return err
		}
		httpx.WriteJSON(w, http.StatusOK, res)
		return nil
	}))
	mux.Handle("POST /v1/auth/logout", s.RequirePhone(httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		if err := s.Logout(r.Context(), FromContext(r.Context()), httpx.RequestID(r.Context())); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})))
	mux.Handle("GET /v1/me", s.RequirePhone(httpx.Handler(func(w http.ResponseWriter, r *http.Request) error {
		p := FromContext(r.Context())
		acct, err := store.GetAccount(r.Context(), s.Store.Pool, p.AccountID)
		if err != nil {
			return err
		}
		d, err := store.GetDevice(r.Context(), s.Store.Pool, p.AccountID, p.DeviceID)
		if err != nil {
			return err
		}
		a := Account{ID: acct.ID}
		if acct.DisplayName != nil {
			a.DisplayName = *acct.DisplayName
		}
		if acct.Email != nil {
			a.Email = *acct.Email
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"account": a, "device": map[string]any{
			"id": d.ID, "kind": d.Kind, "platform": d.Platform, "display_name": d.DisplayName, "key_fingerprint": d.KeyFingerprint,
		}})
		return nil
	})))
}
