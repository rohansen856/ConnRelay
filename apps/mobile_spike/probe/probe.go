// Package probe is the gomobile-bound entry point for the on-device
// transport spike (S1) and hardware-key spike (S6). It runs the phone side of
// a full connection attempt with prwcore inside the app process, signing the
// identity attestation with a key supplied by the platform (Android
// Keystore / iOS Secure Enclave).
//
// Only gomobile-compatible types appear in the exported API.
package probe

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/tests/netlab/labclient"
)

// Signer is implemented on the platform side with a non-exportable key.
type Signer interface {
	// PublicKeySPKI returns the DER SubjectPublicKeyInfo of the P-256 key.
	PublicKeySPKI() ([]byte, error)
	// SignDER signs a SHA-256 digest (already hashed) and returns DER.
	SignDER(digest []byte) ([]byte, error)
}

type platformSigner struct {
	s    Signer
	spki []byte
}

func (p *platformSigner) PublicKeySPKI() []byte { return p.spki }
func (p *platformSigner) SignDER(d []byte) ([]byte, error) {
	return p.s.SignDER(d)
}

// Version describes the embedded Go runtime.
func Version() string { return "prwcore probe; " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH }

// CheckSigner signs a fixed message with the platform key and verifies it in
// Go, returning a JSON report (S6).
func CheckSigner(s Signer) string {
	type report struct {
		OK          bool   `json:"ok"`
		Fingerprint string `json:"spki_sha256,omitempty"`
		SignMS      int64  `json:"sign_ms,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	r := report{}
	err := func() error {
		spki, err := s.PublicKeySPKI()
		if err != nil {
			return err
		}
		pub, err := attest.ParsePublicKey(spki)
		if err != nil {
			return err
		}
		r.Fingerprint = attest.Fingerprint(spki)
		ps := &platformSigner{s: s, spki: spki}
		t0 := time.Now()
		jws, err := attest.Sign(ps, map[string]any{"purpose": "prw.s6.check", "iat": time.Now().Unix()})
		r.SignMS = time.Since(t0).Milliseconds()
		if err != nil {
			return err
		}
		if _, err := attest.Verify(pub, jws); err != nil {
			return err
		}
		// A different digest must not verify against the same signature.
		d := sha256.Sum256([]byte("other"))
		der, err := s.SignDER(d[:])
		if err != nil {
			return err
		}
		if _, err := attest.DERToRaw(der); err != nil {
			return errors.New("platform returned a non-DER signature")
		}
		return nil
	}()
	if err != nil {
		r.Error = err.Error()
	} else {
		r.OK = true
	}
	b, _ := json.Marshal(r)
	return string(b)
}

// Run performs one phone-side attempt and returns the JSON result. mode is
// "auto", "webrtc" or "wss". signer may be nil (software key).
func Run(server, labID, mode string, forceRelay bool, nbytes int, signer Signer) string {
	cfg := labclient.Config{
		Server: server, LabID: labID, Role: "phone", Mode: mode, ForceRelay: forceRelay,
		Bytes: nbytes, HTTPClient: &http.Client{Timeout: 90 * time.Second},
	}
	if signer != nil {
		spki, err := signer.PublicKeySPKI()
		if err != nil {
			b, _ := json.Marshal(labclient.Result{Role: "phone", Error: "signer: " + err.Error()})
			return string(b)
		}
		cfg.Signer = &platformSigner{s: signer, spki: spki}
	}
	b, _ := json.Marshal(labclient.Run(cfg))
	return string(b)
}
