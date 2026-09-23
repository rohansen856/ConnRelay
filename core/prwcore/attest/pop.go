package attest

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"
)

// Proof-of-possession purposes. Each signature is bound to one purpose so a
// signature made for one flow cannot be replayed in another.
const (
	PurposeAuth    = "prw.auth.v1"    // phone sign-in: binds the key being registered
	PurposeRefresh = "prw.refresh.v1" // phone token refresh
	PurposeAgent   = "prw.agent.v1"   // host agent control-socket login
)

// PoPMaxAge bounds how old a proof may be (plus MaxSkew into the future).
const PoPMaxAge = 120 * time.Second

// PoP is a proof-of-possession statement over a server nonce.
type PoP struct {
	Purpose  string `json:"purpose"`
	Nonce    string `json:"nonce"`
	SPKIFP   string `json:"spki_fp,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	IAT      int64  `json:"iat"`
}

// SignPoP signs a proof for purpose over nonce.
func SignPoP(s Signer, p PoP, now time.Time) (string, error) {
	p.IAT = now.Unix()
	return Sign(s, p)
}

// VerifyPoP checks a proof made with pub. want.Purpose and want.Nonce must
// match exactly, as must SPKIFP and DeviceID when set in want.
func VerifyPoP(pub *ecdsa.PublicKey, jws string, want PoP, now time.Time) error {
	payload, err := Verify(pub, jws)
	if err != nil {
		return err
	}
	var got PoP
	if err := json.Unmarshal(payload, &got); err != nil {
		return fmt.Errorf("%w: pop claims", ErrInvalid)
	}
	switch {
	case got.Purpose != want.Purpose:
		return fmt.Errorf("%w: purpose", ErrInvalid)
	case got.Nonce == "" || got.Nonce != want.Nonce:
		return fmt.Errorf("%w: nonce", ErrInvalid)
	case want.SPKIFP != "" && got.SPKIFP != want.SPKIFP:
		return fmt.Errorf("%w: key fingerprint", ErrInvalid)
	case want.DeviceID != "" && got.DeviceID != want.DeviceID:
		return fmt.Errorf("%w: device", ErrInvalid)
	}
	iat := time.Unix(got.IAT, 0)
	if iat.After(now.Add(MaxSkew)) || now.Sub(iat) > PoPMaxAge {
		return fmt.Errorf("%w: proof too old or from the future", ErrInvalid)
	}
	return nil
}
