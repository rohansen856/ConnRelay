package mobile

import (
	"errors"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
)

type goSigner struct{ s *attest.SoftwareSigner }

func (g goSigner) PublicKeySPKI() ([]byte, error)   { return g.s.PublicKeySPKI(), nil }
func (g goSigner) SignDER(d []byte) ([]byte, error) { return g.s.SignDER(d) }

func TestSignPoP(t *testing.T) {
	k, _ := attest.NewSoftwareSigner()
	pub, _ := attest.ParsePublicKey(k.PublicKeySPKI())
	fp := Fingerprint(k.PublicKeySPKI())
	jws, err := SignPoP("prw.auth.v1", "n1", fp, "", goSigner{k})
	if err != nil {
		t.Fatal(err)
	}
	if err := attest.VerifyPoP(pub, jws, attest.PoP{Purpose: attest.PurposeAuth, Nonce: "n1", SPKIFP: fp}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Agent and pairing purposes are not available to the phone app.
	if _, err := SignPoP(attest.PurposeAgent, "n", "", "d", goSigner{k}); err == nil {
		t.Fatal("agent purpose allowed from the phone facade")
	}
	if _, err := SignPoP(attest.PurposeAuth, "n", fp, "", nil); err == nil {
		t.Fatal("nil signer accepted")
	}
}

type badSigner struct{}

func (badSigner) PublicKeySPKI() ([]byte, error) { return nil, errors.New("keystore locked") }
func (badSigner) SignDER([]byte) ([]byte, error) { return nil, errors.New("no") }

func TestSignerErrors(t *testing.T) {
	if _, err := SignPoP(attest.PurposeAuth, "n", "fp", "", badSigner{}); err == nil {
		t.Fatal("keystore error swallowed")
	}
}
