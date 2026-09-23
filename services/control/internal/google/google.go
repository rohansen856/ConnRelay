// Package google verifies Google OIDC ID tokens and applies the account
// allowlist. Google is the only identity provider.
package google

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Issuer is Google's OIDC issuer.
const Issuer = "https://accounts.google.com"

// Errors returned by Verify.
var (
	ErrInvalidToken = errors.New("google: invalid id token")
	ErrNotAllowed   = errors.New("google: account not allowed")
)

// Identity is the verified subset of the ID token.
type Identity struct {
	Subject       string // Google "sub"
	Email         string // only when email_verified
	Name          string
	EmailVerified bool
}

// Verifier checks ID tokens.
type Verifier struct {
	v        *oidc.IDTokenVerifier
	audience []string
	allowed  map[string]bool
}

// New verifies against Google's discovery document and JWKS.
func New(ctx context.Context, clientIDs, allowedSubjects []string) (*Verifier, error) {
	p, err := oidc.NewProvider(ctx, Issuer)
	if err != nil {
		return nil, fmt.Errorf("google: discovery: %w", err)
	}
	return newVerifier(p.Verifier(&oidc.Config{SkipClientIDCheck: true}), clientIDs, allowedSubjects)
}

// NewWithKeySet builds a verifier with an explicit key set (tests).
func NewWithKeySet(issuer string, ks oidc.KeySet, clientIDs, allowedSubjects []string, now func() time.Time) (*Verifier, error) {
	return newVerifier(oidc.NewVerifier(issuer, ks, &oidc.Config{SkipClientIDCheck: true, Now: now}), clientIDs, allowedSubjects)
}

func newVerifier(v *oidc.IDTokenVerifier, clientIDs, allowedSubjects []string) (*Verifier, error) {
	if len(clientIDs) == 0 {
		return nil, errors.New("google: no client IDs configured")
	}
	if len(allowedSubjects) == 0 {
		return nil, errors.New("google: empty allowlist (there is no open sign-up)")
	}
	allowed := map[string]bool{}
	for _, s := range allowedSubjects {
		allowed[s] = true
	}
	return &Verifier{v: v, audience: clientIDs, allowed: allowed}, nil
}

// Verify checks signature, issuer, expiry, audience and nonce, then the
// allowlist. It returns ErrNotAllowed (with the identity) for a valid token
// whose subject is not allowlisted, so callers can audit the denial.
func (g *Verifier) Verify(ctx context.Context, raw, nonce string) (*Identity, error) {
	tok, err := g.v.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !slices.ContainsFunc(tok.Audience, func(a string) bool { return slices.Contains(g.audience, a) }) {
		return nil, fmt.Errorf("%w: audience", ErrInvalidToken)
	}
	if nonce == "" || tok.Nonce != nonce {
		return nil, fmt.Errorf("%w: nonce", ErrInvalidToken)
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := tok.Claims(&c); err != nil {
		return nil, fmt.Errorf("%w: claims", ErrInvalidToken)
	}
	id := &Identity{Subject: tok.Subject, Name: c.Name, EmailVerified: c.EmailVerified}
	if c.EmailVerified {
		id.Email = c.Email
	}
	if !g.allowed[tok.Subject] {
		return id, ErrNotAllowed
	}
	return id, nil
}
