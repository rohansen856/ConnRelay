package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func keys(t *testing.T) (Issuer, KeySet) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Issuer{KID: "k1", Key: priv}, KeySet{"k1": pub}
}

func TestTicketRoundTrip(t *testing.T) {
	is, ks := keys(t)
	now := time.Unix(1760313840, 0)
	in := Ticket{
		Registered: Registered{IAT: now.Unix(), NBF: now.Unix(), EXP: now.Add(60 * time.Second).Unix(), JTI: "j1"},
		AUD:        "host", SUB: "phone", Att: "a1", Cap: "terminal", Nonce: "n", PV: 1,
	}
	tok, err := is.Issue(TypeTicket, in)
	if err != nil {
		t.Fatal(err)
	}
	var out Ticket
	if err := ks.Verify(tok, TypeTicket, now.Add(10*time.Second), &out); err != nil {
		t.Fatal(err)
	}
	if out.AUD != "host" || out.JTI != "j1" || out.Cap != "terminal" {
		t.Fatalf("%+v", out)
	}
}

func TestVerifyRejects(t *testing.T) {
	is, ks := keys(t)
	_, other := keys(t)
	now := time.Unix(1760313840, 0)
	good := Relay{Registered: Registered{IAT: now.Unix(), EXP: now.Add(90 * time.Second).Unix(), JTI: "j"}, Att: "a", Role: RoleClient}
	tok, _ := is.Issue(TypeRelay, good)

	var r Relay
	check := func(name string, err error) {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
	}
	check("wrong type", ks.Verify(tok, TypeTicket, now, &r))
	check("unknown kid", KeySet{"k2": other["k1"]}.Verify(tok, TypeRelay, now, &r))
	check("wrong key", KeySet{"k1": other["k1"]}.Verify(tok, TypeRelay, now, &r))
	check("expired", ks.Verify(tok, TypeRelay, now.Add(10*time.Minute), &r))
	check("malformed", ks.Verify("x.y", TypeRelay, now, &r))

	p := strings.Split(tok, ".")
	check("tampered", ks.Verify(p[0]+"."+p[1]+"x."+p[2], TypeRelay, now, &r))

	future := good
	future.NBF = now.Add(5 * time.Minute).Unix()
	ftok, _ := is.Issue(TypeRelay, future)
	check("not yet valid", ks.Verify(ftok, TypeRelay, now, &r))

	nojti := good
	nojti.JTI = ""
	ntok, _ := is.Issue(TypeRelay, nojti)
	check("no jti", ks.Verify(ntok, TypeRelay, now, &r))
}
