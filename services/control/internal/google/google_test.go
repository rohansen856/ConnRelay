package google_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/google/googletest"
)

func TestVerify(t *testing.T) {
	iss := googletest.New(t, google.Issuer)
	v, err := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{"android-client", "ios-client"}, []string{"owner-sub"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	good := googletest.Claims{Sub: "owner-sub", Aud: "ios-client", Nonce: "n1", Email: "o@example.invalid", EmailVerified: true, Name: "Owner"}
	id, err := v.Verify(context.Background(), iss.Token(t, good), "n1")
	if err != nil || id.Subject != "owner-sub" || id.Email != "o@example.invalid" {
		t.Fatalf("%+v %v", id, err)
	}

	unverified := good
	unverified.EmailVerified = false
	id, err = v.Verify(context.Background(), iss.Token(t, unverified), "n1")
	if err != nil || id.Email != "" {
		t.Fatalf("unverified email kept: %+v %v", id, err)
	}

	other := googletest.New(t, google.Issuer)
	cases := map[string]struct {
		tok, nonce string
		want       error
	}{
		"wrong audience": {iss.Token(t, func() googletest.Claims { c := good; c.Aud = "someone-else"; return c }()), "n1", google.ErrInvalidToken},
		"wrong issuer":   {iss.Token(t, func() googletest.Claims { c := good; c.Iss = "https://evil.invalid"; return c }()), "n1", google.ErrInvalidToken},
		"expired": {iss.Token(t, func() googletest.Claims {
			c := good
			c.IssuedAt = time.Now().Add(-3 * time.Hour)
			c.Expiry = time.Now().Add(-2 * time.Hour)
			return c
		}()), "n1", google.ErrInvalidToken},
		"nonce mismatch":   {iss.Token(t, good), "n2", google.ErrInvalidToken},
		"empty nonce":      {iss.Token(t, func() googletest.Claims { c := good; c.Nonce = ""; return c }()), "", google.ErrInvalidToken},
		"untrusted key":    {other.Token(t, good), "n1", google.ErrInvalidToken},
		"not on allowlist": {iss.Token(t, func() googletest.Claims { c := good; c.Sub = "stranger"; return c }()), "n1", google.ErrNotAllowed},
		"garbage":          {"not-a-jwt", "n1", google.ErrInvalidToken},
	}
	for name, c := range cases {
		if _, err := v.Verify(context.Background(), c.tok, c.nonce); !errors.Is(err, c.want) {
			t.Errorf("%s: want %v, got %v", name, c.want, err)
		}
	}
}

func TestConfigRequired(t *testing.T) {
	iss := googletest.New(t, google.Issuer)
	if _, err := google.NewWithKeySet(google.Issuer, iss.KeySet(), nil, []string{"x"}, time.Now); err == nil {
		t.Fatal("no client IDs accepted")
	}
	if _, err := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{"c"}, nil, time.Now); err == nil {
		t.Fatal("empty allowlist accepted (would be open sign-up)")
	}
}
