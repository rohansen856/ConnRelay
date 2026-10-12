package attest

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"
)

const (
	PurposePeerAttest = "connrelay.peer.attest.v1"
	// MaxSkew is the tolerated clock difference when checking iat/exp.
	MaxSkew = 30 * time.Second
	// MaxLifetime bounds exp - iat.
	MaxLifetime = 120 * time.Second
	// DefaultLifetime is used by NewClaims.
	DefaultLifetime = 60 * time.Second
)

// Transport identifiers carried in the attestation.
const (
	TransportDTLS  = "dtls"
	TransportTLS13 = "tls13"
)

// Claims is the peer identity attestation payload.
type Claims struct {
	Purpose   string `json:"purpose"`
	PV        int    `json:"pv"`
	Attempt   string `json:"att"`
	From      string `json:"from"`
	To        string `json:"to"`
	Role      string `json:"role"`
	Nonce     string `json:"nonce"`
	Transport string `json:"transport"`
	LocalFP   string `json:"local_fp"`
	RemoteFP  string `json:"remote_fp"`
	Cap       string `json:"cap"`
	IAT       int64  `json:"iat"`
	EXP       int64  `json:"exp"`
}

// NewClaims fills purpose, version and timestamps.
func NewClaims(now time.Time, c Claims) Claims {
	c.Purpose = PurposePeerAttest
	c.PV = 1
	c.IAT = now.Unix()
	c.EXP = now.Add(DefaultLifetime).Unix()
	return c
}

// Expect describes what the verifier knows independently of the peer.
type Expect struct {
	PeerKey      *ecdsa.PublicKey // pinned key of the expected peer
	Attempt      string
	Nonce        string
	Self         string // own device ID
	Peer         string // expected peer device ID
	PeerRole     string
	Transport    string
	ObservedPeer string // fingerprint of the peer certificate actually seen
	OwnCert      string // fingerprint of our own certificate
	AllowedCaps  []string
	Now          time.Time
}

// VerifyPeer verifies a peer attestation JWS against exp. Any failure must
// close the transport with peer_identity_mismatch.
func VerifyPeer(jws string, exp Expect) (*Claims, error) {
	payload, err := Verify(exp.PeerKey, jws)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", ErrInvalid, err)
	}
	fail := func(what string) (*Claims, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, what)
	}
	switch {
	case c.Purpose != PurposePeerAttest || c.PV != 1:
		return fail("purpose/version")
	case c.Attempt != exp.Attempt:
		return fail("attempt")
	case c.Nonce != exp.Nonce:
		return fail("nonce")
	case c.From != exp.Peer:
		return fail("from")
	case c.To != exp.Self:
		return fail("to")
	case c.Role != exp.PeerRole:
		return fail("role")
	case c.Transport != exp.Transport:
		return fail("transport")
	case c.LocalFP != exp.ObservedPeer:
		return fail("peer certificate fingerprint")
	case c.RemoteFP != exp.OwnCert:
		return fail("own certificate fingerprint")
	}
	if !contains(exp.AllowedCaps, c.Cap) {
		return fail("capability")
	}
	iat, ex := time.Unix(c.IAT, 0), time.Unix(c.EXP, 0)
	if ex.Sub(iat) > MaxLifetime || ex.Before(iat) {
		return fail("lifetime")
	}
	if exp.Now.Add(MaxSkew).Before(iat) || exp.Now.Add(-MaxSkew).After(ex) {
		return fail("time window")
	}
	return &c, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
