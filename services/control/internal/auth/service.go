// Package auth implements phone sign-in (Google ID token + device proof of
// possession), refresh-token rotation with reuse detection, logout, and the
// bearer-token middleware.
package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/nonce"
	"github.com/rohansen856/connrelay/services/control/internal/store"
	"github.com/rohansen856/connrelay/services/control/internal/tokens"
	"golang.org/x/text/unicode/norm"
)

// Refresh lifetimes.
const (
	RefreshSliding  = 30 * 24 * time.Hour
	RefreshAbsolute = 90 * 24 * time.Hour
)

// API errors.
var (
	ErrNotAllowed     = httpx.E(http.StatusForbidden, "account_not_allowed", "This Google account is not allowed to use this server.")
	ErrNonce          = httpx.E(http.StatusBadRequest, "nonce_invalid", "The sign-in challenge expired. Try again.")
	ErrPoP            = httpx.E(http.StatusUnauthorized, "unauthenticated", "Device key verification failed.")
	ErrDeviceRevoked  = httpx.E(http.StatusForbidden, "device_revoked", "This device was removed from your account.")
	ErrRefreshReuse   = httpx.E(http.StatusUnauthorized, "refresh_reuse_detected", "Sign in again.")
	ErrUnsupportedApp = httpx.E(http.StatusUpgradeRequired, "unsupported_client_version", "Update the app to continue.")
)

// IDTokenVerifier verifies Google ID tokens (see package google).
type IDTokenVerifier interface {
	Verify(ctx context.Context, raw, nonce string) (*google.Identity, error)
}

// Service is the auth service.
type Service struct {
	Store  *store.Store
	Google IDTokenVerifier
	Nonces *nonce.Store
	Tokens *tokens.Manager
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Result is returned by Exchange and Refresh.
type Result struct {
	AccessToken      string    `json:"access_token"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	DeviceID         uuid.UUID `json:"device_id"`
	Account          *Account  `json:"account,omitempty"`
	Device           *DevInfo  `json:"device,omitempty"`
}

// Account is the public account view.
type Account struct {
	ID          uuid.UUID `json:"id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email,omitempty"`
}

// DevInfo summarises the signed-in device.
type DevInfo struct {
	Kind           string `json:"kind"`
	KeyFingerprint string `json:"key_fingerprint"`
	Created        bool   `json:"created"`
}

// ExchangeRequest is the body of POST /v1/auth/exchange.
type ExchangeRequest struct {
	Provider  string `json:"provider"`
	IDToken   string `json:"id_token"`
	OIDCNonce string `json:"oidc_nonce"`
	Device    struct {
		Platform      string `json:"platform"`
		DisplayName   string `json:"display_name"`
		AppVersion    string `json:"app_version"`
		PublicKeySPKI string `json:"public_key_spki"`
		KeyProtection string `json:"key_protection,omitempty"`
		Proto         struct {
			Min int `json:"min"`
			Max int `json:"max"`
		} `json:"proto"`
	} `json:"device"`
	PoP PoPReq `json:"pop"`
}

// PoPReq is a proof of possession over a server nonce.
type PoPReq struct {
	Nonce string `json:"nonce"`
	Sig   string `json:"sig"`
}

// Challenge issues a single-use nonce.
func (s *Service) Challenge() (string, time.Time, error) {
	n, exp, ok := s.Nonces.Issue()
	if !ok {
		return "", time.Time{}, httpx.E(http.StatusTooManyRequests, "rate_limited", "Try again shortly.")
	}
	return n, exp, nil
}

func validationError(field string) error {
	return &httpx.Error{Status: http.StatusBadRequest, Code: "validation_failed", Message: "Invalid request.",
		Details: map[string]any{"fields": []string{field}}}
}

// CleanDisplayName NFC-normalises a device name and rejects control
// characters and out-of-range lengths.
func CleanDisplayName(s string) (string, bool) {
	s = strings.TrimSpace(norm.NFC.String(s))
	n := utf8.RuneCountInString(s)
	if n < 1 || n > 120 || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

// SubjectHash identifies a denied Google subject in audit without storing it.
func SubjectHash(sub string) string {
	h := sha256.Sum256([]byte("google:" + sub))
	return hex.EncodeToString(h[:8])
}

// Exchange signs a phone in and registers (or matches) its device key.
func (s *Service) Exchange(ctx context.Context, req ExchangeRequest, requestID, userAgent string) (*Result, error) {
	// Validate shape before doing any work.
	if req.Provider != "google" {
		return nil, validationError("provider")
	}
	if req.Device.Platform != "android" && req.Device.Platform != "ios" {
		return nil, validationError("device.platform")
	}
	if req.Device.Proto.Min > 1 || (req.Device.Proto.Max != 0 && req.Device.Proto.Max < 1) {
		return nil, ErrUnsupportedApp
	}
	name, ok := CleanDisplayName(req.Device.DisplayName)
	if !ok {
		return nil, validationError("device.display_name")
	}
	if len(req.Device.AppVersion) > 64 {
		return nil, validationError("device.app_version")
	}
	spki, err := base64.RawURLEncoding.DecodeString(req.Device.PublicKeySPKI)
	if err != nil {
		return nil, validationError("device.public_key_spki")
	}
	pub, err := attest.ParsePublicKey(spki)
	if err != nil {
		return nil, validationError("device.public_key_spki")
	}
	fp := attest.Fingerprint(spki)

	// 1-2. Google token, then the allowlist (before any account row exists).
	id, err := s.Google.Verify(ctx, req.IDToken, req.OIDCNonce)
	if errors.Is(err, google.ErrNotAllowed) {
		_ = store.WriteAudit(ctx, s.Store.Pool, store.Audit{ActorKind: "anonymous", EventType: "login_denied",
			Outcome: "denied", ReasonCode: "account_not_allowed", RequestID: requestID,
			Metadata: map[string]any{"subject_hash": SubjectHash(id.Subject)}})
		return nil, ErrNotAllowed
	}
	if err != nil {
		return nil, httpx.ErrUnauthenticated
	}
	// 3. Single-use server nonce.
	if !s.Nonces.Consume(req.PoP.Nonce) {
		return nil, ErrNonce
	}
	// 4. Proof of possession of the key being registered.
	if err := attest.VerifyPoP(pub, req.PoP.Sig, attest.PoP{Purpose: attest.PurposeAuth, Nonce: req.PoP.Nonce, SPKIFP: fp}, s.now()); err != nil {
		return nil, ErrPoP
	}

	var res *Result
	err = s.Store.InTx(ctx, func(tx pgx.Tx) error {
		var email, display *string
		if id.Email != "" {
			email = &id.Email
		}
		if id.Name != "" {
			display = &id.Name
		}
		acct, err := store.UpsertGoogleAccount(ctx, tx, id.Subject, email, display)
		if err != nil {
			return err
		}
		if acct.Status != "active" {
			return ErrNotAllowed
		}
		dev, err := store.FindLiveDeviceByFingerprint(ctx, tx, acct.ID, fp)
		created := false
		switch {
		case errors.Is(err, store.ErrNotFound):
			dev, err = store.InsertDevice(ctx, tx, store.NewDevice{AccountID: acct.ID, Kind: "phone",
				Platform: req.Device.Platform, DisplayName: name, PublicKey: spki, KeyFingerprint: fp,
				SoftwareVersion: req.Device.AppVersion})
			if err != nil {
				return err
			}
			created = true
		case err != nil:
			return err
		case dev.Kind != "phone":
			return validationError("device.public_key_spki")
		}
		if err := store.TouchDevice(ctx, tx, dev.ID, req.Device.AppVersion); err != nil {
			return err
		}
		now := s.now()
		refresh, hash := tokens.NewRefresh()
		exp := now.Add(RefreshSliding)
		sid, err := store.InsertAuthSession(ctx, tx, acct.ID, dev.ID, store.NewID(), nil, hash, exp, userAgent)
		if err != nil {
			return err
		}
		event := "login"
		if created {
			event = "device_enrolled"
		}
		if err := store.WriteAudit(ctx, tx, store.Audit{AccountID: &acct.ID, ActorKind: "phone", ActorDeviceID: &dev.ID,
			TargetDeviceID: &dev.ID, EventType: event, Outcome: "success", RequestID: requestID,
			Metadata: map[string]any{"platform": req.Device.Platform, "key_protection": req.Device.KeyProtection}}); err != nil {
			return err
		}
		access, aexp, err := s.Tokens.Issue(acct.ID.String(), dev.ID.String(), sid.String())
		if err != nil {
			return err
		}
		ac := &Account{ID: acct.ID}
		if acct.DisplayName != nil {
			ac.DisplayName = *acct.DisplayName
		}
		if acct.Email != nil {
			ac.Email = *acct.Email
		}
		res = &Result{AccessToken: access, AccessExpiresAt: aexp, RefreshToken: refresh, RefreshExpiresAt: exp,
			DeviceID: dev.ID, Account: ac, Device: &DevInfo{Kind: "phone", KeyFingerprint: fp, Created: created}}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// RefreshRequest is the body of POST /v1/auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
	PoP          PoPReq `json:"pop"`
}

// Refresh rotates a refresh token. Presenting an already-rotated token
// revokes the whole family (theft detection).
func (s *Service) Refresh(ctx context.Context, req RefreshRequest, requestID, userAgent string) (*Result, error) {
	if req.RefreshToken == "" {
		return nil, httpx.ErrUnauthenticated
	}
	var res *Result
	var reuse bool
	err := s.Store.InTx(ctx, func(tx pgx.Tx) error {
		sess, err := store.LockAuthSessionByHash(ctx, tx, tokens.HashRefresh(req.RefreshToken))
		if errors.Is(err, store.ErrNotFound) {
			return httpx.ErrUnauthenticated
		}
		if err != nil {
			return err
		}
		if sess.RevokedAt != nil {
			if sess.RevokeReason != nil && *sess.RevokeReason == "rotated" {
				reuse = true
				if err := store.RevokeAuthFamily(ctx, tx, sess.FamilyID, "reuse_detected"); err != nil {
					return err
				}
				return store.WriteAudit(ctx, tx, store.Audit{AccountID: &sess.AccountID, ActorKind: "phone",
					ActorDeviceID: &sess.DeviceID, EventType: "refresh_reuse_detected", Outcome: "denied", RequestID: requestID})
			}
			return httpx.ErrUnauthenticated
		}
		now := s.now()
		if !now.Before(sess.ExpiresAt) {
			return httpx.ErrUnauthenticated
		}
		dev, err := store.GetDevice(ctx, tx, sess.AccountID, sess.DeviceID)
		if err != nil {
			return err
		}
		if dev.AdminState == "revoked" {
			return ErrDeviceRevoked
		}
		// Device-bound: the phone must prove it still holds its key.
		if !s.Nonces.Consume(req.PoP.Nonce) {
			return ErrNonce
		}
		pub, err := attest.ParsePublicKey(dev.PublicKey)
		if err != nil {
			return err
		}
		if err := attest.VerifyPoP(pub, req.PoP.Sig, attest.PoP{Purpose: attest.PurposeRefresh, Nonce: req.PoP.Nonce,
			DeviceID: dev.ID.String()}, now); err != nil {
			return ErrPoP
		}
		if err := store.RevokeAuthSession(ctx, tx, sess.ID, "rotated"); err != nil {
			return err
		}
		exp := now.Add(RefreshSliding)
		if abs := sess.FamilyStarted.Add(RefreshAbsolute); abs.Before(exp) {
			exp = abs
		}
		if !now.Before(exp) {
			return httpx.ErrUnauthenticated
		}
		refresh, hash := tokens.NewRefresh()
		sid, err := store.InsertAuthSession(ctx, tx, sess.AccountID, dev.ID, sess.FamilyID, &sess.ID, hash, exp, userAgent)
		if err != nil {
			return err
		}
		if err := store.TouchDevice(ctx, tx, dev.ID, ""); err != nil {
			return err
		}
		access, aexp, err := s.Tokens.Issue(sess.AccountID.String(), dev.ID.String(), sid.String())
		if err != nil {
			return err
		}
		res = &Result{AccessToken: access, AccessExpiresAt: aexp, RefreshToken: refresh, RefreshExpiresAt: exp, DeviceID: dev.ID}
		return nil
	})
	if reuse && err == nil {
		// The family revocation is committed; now report the failure.
		return nil, ErrRefreshReuse
	}
	return res, err
}

// Logout revokes the caller's token family (this phone only).
func (s *Service) Logout(ctx context.Context, p *Principal, requestID string) error {
	return s.Store.InTx(ctx, func(tx pgx.Tx) error {
		sess, err := store.GetLiveAuthSession(ctx, tx, p.SessionID)
		if err != nil {
			return err
		}
		if err := store.RevokeAuthFamily(ctx, tx, sess.FamilyID, "logout"); err != nil {
			return err
		}
		return store.WriteAudit(ctx, tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
			EventType: "logout", Outcome: "success", RequestID: requestID})
	})
}
