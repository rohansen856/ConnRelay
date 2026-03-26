// Package token issues and verifies server-signed EdDSA (Ed25519) compact
// JWS tokens: connection tickets, relay tokens and grant leases.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

// Token types (JWS typ header).
const (
	TypeTicket = "prw-ticket+jwt"
	TypeRelay  = "prw-relay+jwt"
	TypeLease  = "prw-lease+jwt"
)

// ClockSkew tolerated on nbf/exp checks.
const ClockSkew = 30 * time.Second

// ErrInvalid is returned (wrapped) for any verification failure.
var ErrInvalid = errors.New("token: invalid")

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Registered holds the time claims every token carries.
type Registered struct {
	IAT int64  `json:"iat"`
	NBF int64  `json:"nbf,omitempty"`
	EXP int64  `json:"exp"`
	JTI string `json:"jti"`
}

func (r Registered) times() Registered { return r }

// Timed is implemented by claim structs embedding Registered.
type Timed interface{ times() Registered }

// Issuer signs tokens with one Ed25519 key.
type Issuer struct {
	KID string
	Key ed25519.PrivateKey
}

// Issue signs claims as a compact JWS of the given type.
func (is Issuer) Issue(typ string, claims Timed) (string, error) {
	h, err := json.Marshal(header{Alg: "EdDSA", Typ: typ, Kid: is.KID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig := ed25519.Sign(is.Key, []byte(in))
	return in + "." + b64.EncodeToString(sig), nil
}

// KeySet maps key IDs to pinned Ed25519 public keys.
type KeySet map[string]ed25519.PublicKey

// Verify checks signature, type and time window, then decodes into claims.
func (ks KeySet) Verify(tok, typ string, now time.Time, claims Timed) error {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: malformed", ErrInvalid)
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("%w: header encoding", ErrInvalid)
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "EdDSA" || h.Typ != typ {
		return fmt.Errorf("%w: header", ErrInvalid)
	}
	pub, ok := ks[h.Kid]
	if !ok {
		return fmt.Errorf("%w: unknown kid", ErrInvalid)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return fmt.Errorf("%w: signature", ErrInvalid)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: payload encoding", ErrInvalid)
	}
	if err := json.Unmarshal(pb, claims); err != nil {
		return fmt.Errorf("%w: claims", ErrInvalid)
	}
	r := claims.times()
	if r.JTI == "" || r.EXP == 0 {
		return fmt.Errorf("%w: missing jti/exp", ErrInvalid)
	}
	if now.Add(-ClockSkew).Unix() > r.EXP {
		return fmt.Errorf("%w: expired", ErrInvalid)
	}
	if r.NBF != 0 && now.Add(ClockSkew).Unix() < r.NBF {
		return fmt.Errorf("%w: not yet valid", ErrInvalid)
	}
	return nil
}

// Ticket is a connection ticket (protocol v1 §5).
type Ticket struct {
	Registered
	ISS   string `json:"iss"`
	AUD   string `json:"aud"`  // host device ID
	SUB   string `json:"sub"`  // phone device ID
	Acct  string `json:"acct"` // account ID
	Att   string `json:"att"`
	Cap   string `json:"cap"`
	Sess  string `json:"sess,omitempty"`
	Nonce string `json:"nonce"`
	PV    int    `json:"pv"`
}

// Relay roles.
const (
	RoleClient = "client" // phone
	RoleServer = "server" // host
)

// Relay authorises one peer to join one attempt on /v1/relay.
type Relay struct {
	Registered
	Att  string `json:"att"`
	Role string `json:"role"`
	Dev  string `json:"dev"`
}
