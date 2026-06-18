package probe

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
)

type goSigner struct{ s *attest.SoftwareSigner }

func (g goSigner) PublicKeySPKI() ([]byte, error)    { return g.s.PublicKeySPKI(), nil }
func (g goSigner) SignDER(d []byte) ([]byte, error) { return g.s.SignDER(d) }

type badSigner struct{ goSigner }

func (badSigner) SignDER([]byte) ([]byte, error) { return []byte{1, 2, 3}, nil }

type failingSigner struct{ goSigner }

func (failingSigner) PublicKeySPKI() ([]byte, error) { return nil, errors.New("keystore locked") }

func check(t *testing.T, s Signer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(CheckSigner(s)), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCheckSigner(t *testing.T) {
	sw, _ := attest.NewSoftwareSigner()
	if m := check(t, goSigner{sw}); m["ok"] != true {
		t.Fatalf("good signer: %v", m)
	}
	if m := check(t, badSigner{goSigner{sw}}); m["ok"] == true {
		t.Fatal("garbage signature accepted")
	}
	if m := check(t, failingSigner{goSigner{sw}}); m["ok"] == true {
		t.Fatal("failing keystore reported ok")
	}
}
