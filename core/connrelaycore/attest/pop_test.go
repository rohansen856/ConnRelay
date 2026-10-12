package attest

import (
	"errors"
	"testing"
	"time"
)

func TestPoP(t *testing.T) {
	s, _ := NewSoftwareSigner()
	pub, _ := ParsePublicKey(s.PublicKeySPKI())
	fp := Fingerprint(s.PublicKeySPKI())
	now := time.Unix(1760313840, 0)
	jws, err := SignPoP(s, PoP{Purpose: PurposeAuth, Nonce: "n1", SPKIFP: fp}, now)
	if err != nil {
		t.Fatal(err)
	}
	want := PoP{Purpose: PurposeAuth, Nonce: "n1", SPKIFP: fp}
	if err := VerifyPoP(pub, jws, want, now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	other, _ := NewSoftwareSigner()
	opub, _ := ParsePublicKey(other.PublicKeySPKI())
	cases := map[string]func() error{
		"other key":         func() error { return VerifyPoP(opub, jws, want, now) },
		"wrong purpose":     func() error { w := want; w.Purpose = PurposeRefresh; return VerifyPoP(pub, jws, w, now) },
		"wrong nonce":       func() error { w := want; w.Nonce = "n2"; return VerifyPoP(pub, jws, w, now) },
		"wrong fingerprint": func() error { w := want; w.SPKIFP = "ff"; return VerifyPoP(pub, jws, w, now) },
		"too old":           func() error { return VerifyPoP(pub, jws, want, now.Add(10*time.Minute)) },
		"from the future":   func() error { return VerifyPoP(pub, jws, want, now.Add(-10*time.Minute)) },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestPoPNonceRequiredExceptPairCreate(t *testing.T) {
	s, _ := NewSoftwareSigner()
	pub, _ := ParsePublicKey(s.PublicKeySPKI())
	now := time.Now()
	jws, _ := SignPoP(s, PoP{Purpose: PurposeRefresh, DeviceID: "d"}, now)
	if err := VerifyPoP(pub, jws, PoP{Purpose: PurposeRefresh, DeviceID: "d"}, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("nonce-free refresh proof accepted")
	}
	jws, _ = SignPoP(s, PoP{Purpose: PurposePairCreate, SPKIFP: "f"}, now)
	if err := VerifyPoP(pub, jws, PoP{Purpose: PurposePairCreate, SPKIFP: "f"}, now); err != nil {
		t.Fatal(err)
	}
	jws, _ = SignPoP(s, PoP{Purpose: PurposePairComplete, Nonce: "n", ChallengeID: "c1"}, now)
	if err := VerifyPoP(pub, jws, PoP{Purpose: PurposePairComplete, Nonce: "n", ChallengeID: "c2"}, now); !errors.Is(err, ErrInvalid) {
		t.Fatal("proof for another challenge accepted")
	}
}
