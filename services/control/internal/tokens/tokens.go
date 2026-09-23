// Package tokens issues and verifies phone access tokens (EdDSA JWTs, 10
// minutes) and generates opaque refresh tokens, which are stored only as
// SHA-256 hashes.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/token"
)

// Token type and audience for access tokens.
const (
	TypeAccess = "prw-access+jwt"
	Audience   = "prw-api"
	AccessTTL  = 10 * time.Minute
)

// ErrInvalid is returned for any access-token failure.
var ErrInvalid = errors.New("tokens: invalid access token")

// Access holds access-token claims.
type Access struct {
	token.Registered
	ISS  string `json:"iss"`
	AUD  string `json:"aud"`
	SUB  string `json:"sub"`  // account ID
	DID  string `json:"did"`  // device ID
	Kind string `json:"kind"` // "phone"
	SID  string `json:"sid"`  // auth session ID
}

// Manager issues and verifies access tokens.
type Manager struct {
	Issuer token.Issuer
	Keys   token.KeySet // active + verify-only keys
	ISS    string
	Now    func() time.Time
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Issue signs an access token and returns it with its expiry.
func (m *Manager) Issue(accountID, deviceID, sessionID string) (string, time.Time, error) {
	now := m.now()
	exp := now.Add(AccessTTL)
	s, err := m.Issuer.Issue(TypeAccess, Access{
		Registered: token.Registered{IAT: now.Unix(), NBF: now.Unix(), EXP: exp.Unix(), JTI: randomID()},
		ISS:        m.ISS, AUD: Audience, SUB: accountID, DID: deviceID, Kind: "phone", SID: sessionID,
	})
	return s, exp, err
}

// Verify checks signature, type, time, issuer and audience.
func (m *Manager) Verify(raw string) (*Access, error) {
	var a Access
	if err := m.Keys.Verify(raw, TypeAccess, m.now(), &a); err != nil {
		return nil, ErrInvalid
	}
	if a.AUD != Audience || a.ISS != m.ISS || a.SUB == "" || a.DID == "" || a.SID == "" {
		return nil, ErrInvalid
	}
	return &a, nil
}

// NewRefresh returns a new opaque refresh token and its storage hash.
func NewRefresh() (string, []byte) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	s := base64.RawURLEncoding.EncodeToString(b[:])
	return s, HashRefresh(s)
}

// HashRefresh returns the stored form of a refresh token.
func HashRefresh(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
