package attest

import (
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*SoftwareSigner, *ecdsa.PublicKey, Claims, Expect) {
	t.Helper()
	s, err := NewSoftwareSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(s.PublicKeySPKI())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1760313840, 0)
	c := NewClaims(now, Claims{
		Attempt: "att-1", From: "host-1", To: "phone-1", Role: "host", Nonce: "n-1",
		Transport: TransportDTLS, LocalFP: "aa", RemoteFP: "bb", Cap: "terminal",
	})
	e := Expect{
		PeerKey: pub, Attempt: "att-1", Nonce: "n-1", Self: "phone-1", Peer: "host-1",
		PeerRole: "host", Transport: TransportDTLS, ObservedPeer: "aa", OwnCert: "bb",
		AllowedCaps: []string{"terminal"}, Now: now.Add(5 * time.Second),
	}
	return s, pub, c, e
}

func TestAttestationValid(t *testing.T) {
	s, _, c, e := fixture(t)
	jws, err := Sign(s, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyPeer(jws, e)
	if err != nil {
		t.Fatal(err)
	}
	if got.From != "host-1" || got.Cap != "terminal" {
		t.Fatalf("claims %+v", got)
	}
}

func TestPayloadIsCanonical(t *testing.T) {
	s, _, c, _ := fixture(t)
	jws, _ := Sign(s, c)
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[1])
	// JCS sorts keys lexicographically and emits no whitespace.
	want := `{"att":"att-1","cap":"terminal","exp":1760313900,"from":"host-1","iat":1760313840,"local_fp":"aa","nonce":"n-1","purpose":"prw.peer.attest.v1","pv":1,"remote_fp":"bb","role":"host","to":"phone-1","transport":"dtls"}`
	if string(payload) != want {
		t.Fatalf("payload\n got %s\nwant %s", payload, want)
	}
}

func TestAttestationRejects(t *testing.T) {
	s, _, c, base := fixture(t)
	other, _ := NewSoftwareSigner()
	otherPub, _ := ParsePublicKey(other.PublicKeySPKI())
	jws, _ := Sign(s, c)

	cases := map[string]func(e *Expect){
		"wrong key":      func(e *Expect) { e.PeerKey = otherPub },
		"attempt":        func(e *Expect) { e.Attempt = "att-2" },
		"nonce":          func(e *Expect) { e.Nonce = "n-2" },
		"peer id":        func(e *Expect) { e.Peer = "host-2" },
		"self id":        func(e *Expect) { e.Self = "phone-2" },
		"role":           func(e *Expect) { e.PeerRole = "phone" },
		"transport":      func(e *Expect) { e.Transport = TransportTLS13 },
		"mitm peer cert": func(e *Expect) { e.ObservedPeer = "cc" },
		"mitm own cert":  func(e *Expect) { e.OwnCert = "dd" },
		"capability":     func(e *Expect) { e.AllowedCaps = []string{"file_transfer"} },
		"expired":        func(e *Expect) { e.Now = e.Now.Add(10 * time.Minute) },
		"not yet valid":  func(e *Expect) { e.Now = e.Now.Add(-10 * time.Minute) },
	}
	for name, mut := range cases {
		e := base
		mut(&e)
		if _, err := VerifyPeer(jws, e); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
}

func TestTamperedJWS(t *testing.T) {
	s, _, c, e := fixture(t)
	jws, _ := Sign(s, c)
	parts := strings.Split(jws, ".")
	c.Cap = "file_transfer"
	forged, _ := Sign(s, c)
	tampered := parts[0] + "." + strings.Split(forged, ".")[1] + "." + parts[2]
	if _, err := VerifyPeer(tampered, e); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered payload accepted: %v", err)
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "." + parts[2]
	if _, err := VerifyPeer(none, e); !errors.Is(err, ErrInvalid) {
		t.Fatalf("alg none accepted: %v", err)
	}
	if _, err := VerifyPeer("a.b", e); !errors.Is(err, ErrInvalid) {
		t.Fatal("malformed accepted")
	}
}

func TestLifetimeTooLong(t *testing.T) {
	s, _, c, e := fixture(t)
	c.EXP = c.IAT + 3600
	jws, _ := Sign(s, c)
	if _, err := VerifyPeer(jws, e); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long lifetime accepted: %v", err)
	}
}

func TestDERToRaw(t *testing.T) {
	if _, err := DERToRaw([]byte{0x30, 0x00}); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty DER accepted")
	}
	s, _ := NewSoftwareSigner()
	d := make([]byte, 32)
	der, _ := s.SignDER(d)
	raw, err := DERToRaw(der)
	if err != nil || len(raw) != 64 {
		t.Fatalf("raw %d %v", len(raw), err)
	}
}

func TestFingerprint(t *testing.T) {
	if Fingerprint([]byte("abc")) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("sha256 mismatch")
	}
}
