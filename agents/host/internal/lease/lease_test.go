package lease

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/token"
)

func issue(t *testing.T, is token.Issuer, host string, now time.Time, phones ...*attest.SoftwareSigner) string {
	var gs []token.LeaseGrant
	for i, p := range phones {
		gs = append(gs, token.LeaseGrant{PhoneDeviceID: string(rune('a' + i)), PhoneKeySPKI: base64.RawURLEncoding.EncodeToString(p.PublicKeySPKI()), Caps: []string{"terminal"}})
	}
	s, err := is.Issue(token.TypeLease, token.Lease{Registered: token.Registered{IAT: now.Unix(), EXP: now.Add(10 * time.Minute).Unix(), JTI: "l"}, Host: host, Grants: gs})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	is := token.Issuer{KID: "k1", Key: priv}
	ks, err := KeySet([]agentcfg.JWK{{KID: "k1", KTY: "OKP", CRV: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1760313840, 0)
	c := New("host-1", ks, func() time.Time { return now })
	if _, err := c.Lookup("a", "terminal"); !errors.Is(err, ErrNoLease) {
		t.Fatal("lookup before any lease")
	}
	p1, _ := attest.NewSoftwareSigner()
	p2, _ := attest.NewSoftwareSigner()
	if _, err := c.Apply(issue(t, is, "host-1", now, p1, p2)); err != nil {
		t.Fatal(err)
	}
	if p, err := c.Lookup("b", "terminal"); err != nil || string(p.SPKI) != string(p2.PublicKeySPKI()) {
		t.Fatal(err)
	}
	if _, err := c.Lookup("b", "file_transfer"); !errors.Is(err, ErrNotGrant) {
		t.Fatal("capability not checked")
	}
	dropped, _ := c.Apply(issue(t, is, "host-1", now, p1))
	if len(dropped) != 1 || dropped[0] != "b" {
		t.Fatalf("dropped %v", dropped)
	}
	if _, err := c.Apply(issue(t, is, "host-2", now, p1)); err == nil {
		t.Fatal("lease for another host accepted")
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.Apply(issue(t, token.Issuer{KID: "k1", Key: otherPriv}, "host-1", now, p1, p2)); err == nil {
		t.Fatal("lease signed by an unpinned key accepted")
	}
	now = now.Add(11 * time.Minute)
	if _, err := c.Lookup("a", "terminal"); !errors.Is(err, ErrNoLease) {
		t.Fatal("expired lease still grants access")
	}
}
