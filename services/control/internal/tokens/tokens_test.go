package tokens

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/token"
)

func manager(t *testing.T, iss string) *Manager {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &Manager{Issuer: token.Issuer{KID: "a1", Key: priv}, Keys: token.KeySet{"a1": pub}, ISS: iss}
}

func TestIssueVerify(t *testing.T) {
	m := manager(t, "https://api.example.invalid")
	s, exp, err := m.Issue("acct", "dev", "sess")
	if err != nil || time.Until(exp) > AccessTTL+time.Second {
		t.Fatal(err, exp)
	}
	a, err := m.Verify(s)
	if err != nil || a.SUB != "acct" || a.DID != "dev" || a.SID != "sess" || a.Kind != "phone" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestRejects(t *testing.T) {
	m := manager(t, "https://api.example.invalid")
	s, _, _ := m.Issue("acct", "dev", "sess")

	other := manager(t, "https://api.example.invalid")
	if _, err := other.Verify(s); !errors.Is(err, ErrInvalid) {
		t.Fatal("token from another key accepted")
	}
	wrongIss := *m
	wrongIss.ISS = "https://evil.invalid"
	if _, err := wrongIss.Verify(s); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong issuer accepted")
	}
	late := *m
	late.Now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := late.Verify(s); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired token accepted")
	}
	// A relay or ticket token signed by the same key must not work as access.
	rt, _ := m.Issuer.Issue(token.TypeRelay, token.Relay{Registered: token.Registered{IAT: time.Now().Unix(), EXP: time.Now().Add(time.Minute).Unix(), JTI: "x"}})
	if _, err := m.Verify(rt); !errors.Is(err, ErrInvalid) {
		t.Fatal("relay token accepted as access token")
	}
}

func TestRefresh(t *testing.T) {
	a, ha := NewRefresh()
	b, _ := NewRefresh()
	if a == b || len(a) < 40 || string(HashRefresh(a)) != string(ha) {
		t.Fatal("refresh tokens not unique or hash mismatch")
	}
}
