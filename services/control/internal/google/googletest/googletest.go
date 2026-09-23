// Package googletest mints Google-style ID tokens signed by a local key for
// tests. TEST ONLY.
package googletest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// Issuer mints tokens and exposes the matching key set.
type Issuer struct {
	key    *rsa.PrivateKey
	signer jose.Signer
	URL    string
}

// New creates an issuer for the given issuer URL.
func New(t testing.TB, url string) *Issuer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	return &Issuer{key: k, signer: s, URL: url}
}

// KeySet returns a key set that trusts this issuer's key.
func (i *Issuer) KeySet() oidc.KeySet {
	return &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&i.key.PublicKey}}
}

// Claims for a token; zero values get sensible defaults.
type Claims struct {
	Sub, Aud, Nonce, Email, Name, Iss string
	EmailVerified                     bool
	IssuedAt, Expiry                  time.Time
}

// Token signs claims.
func (i *Issuer) Token(t testing.TB, c Claims) string {
	t.Helper()
	if c.Iss == "" {
		c.Iss = i.URL
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now()
	}
	if c.Expiry.IsZero() {
		c.Expiry = c.IssuedAt.Add(time.Hour)
	}
	body, _ := json.Marshal(map[string]any{
		"iss": c.Iss, "sub": c.Sub, "aud": c.Aud, "nonce": c.Nonce, "email": c.Email,
		"email_verified": c.EmailVerified, "name": c.Name, "iat": c.IssuedAt.Unix(), "exp": c.Expiry.Unix(),
	})
	sig, err := i.signer.Sign(body)
	if err != nil {
		t.Fatal(err)
	}
	out, err := sig.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}
