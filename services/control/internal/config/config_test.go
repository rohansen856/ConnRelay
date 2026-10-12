package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name string, b []byte, mode os.FileMode) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func validEnv(t *testing.T) map[string]string {
	dir := t.TempDir()
	key := func(name string) string {
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		pemb, _ := EncodeKey(k)
		return write(t, dir, name, pemb, 0o600)
	}
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return map[string]string{
		"CONNRELAY_PUBLIC_BASE_URL":         "https://api.example.invalid",
		"CONNRELAY_DATABASE_URL":            "postgres://x@localhost/connrelay",
		"CONNRELAY_GOOGLE_CLIENT_IDS":       "a.apps.googleusercontent.com, b.apps.googleusercontent.com",
		"CONNRELAY_ALLOWED_SUBJECTS":        "google:1234",
		"CONNRELAY_ACCESS_SIGNING_KEY_FILE": key("access.pem"),
		"CONNRELAY_TICKET_SIGNING_KEY_FILE": key("ticket.pem"),
		"CONNRELAY_PAIRING_HMAC_KEY_FILE":   write(t, dir, "pepper", secret, 0o600),
		"CONNRELAY_TURN_SHARED_SECRET_FILE": write(t, dir, "turn", secret, 0o600),
		"CONNRELAY_TURN_URLS":               "turn:turn.example.invalid:3478?transport=udp,turns:turn.example.invalid:443?transport=tcp",
	}
}

func load(m map[string]string) (*Config, error) { return Load(func(k string) string { return m[k] }) }

func TestValid(t *testing.T) {
	c, err := load(validEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.GoogleClients) != 2 || c.AllowedSubs[0] != "1234" || len(c.TicketKeyIDs) != 1 || c.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("%+v", c)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]func(m map[string]string){
		"empty allowlist":    func(m map[string]string) { m["CONNRELAY_ALLOWED_SUBJECTS"] = "" },
		"bare subject":       func(m map[string]string) { m["CONNRELAY_ALLOWED_SUBJECTS"] = "1234" },
		"http base url":      func(m map[string]string) { m["CONNRELAY_PUBLIC_BASE_URL"] = "http://api.example.invalid" },
		"base url with path": func(m map[string]string) { m["CONNRELAY_PUBLIC_BASE_URL"] = "https://x.invalid/api" },
		"no client ids":      func(m map[string]string) { m["CONNRELAY_GOOGLE_CLIENT_IDS"] = "" },
		"bad turn url":       func(m map[string]string) { m["CONNRELAY_TURN_URLS"] = "http://x" },
		"same keys":          func(m map[string]string) { m["CONNRELAY_TICKET_SIGNING_KEY_FILE"] = m["CONNRELAY_ACCESS_SIGNING_KEY_FILE"] },
		"world-readable secret": func(m map[string]string) {
			_ = os.Chmod(m["CONNRELAY_TURN_SHARED_SECRET_FILE"], 0o644)
		},
		"short pepper": func(m map[string]string) {
			_ = os.WriteFile(m["CONNRELAY_PAIRING_HMAC_KEY_FILE"], []byte("short"), 0o600)
		},
	}
	for name, mut := range cases {
		m := validEnv(t)
		mut(m)
		if _, err := load(m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReportsAllProblems(t *testing.T) {
	_, err := load(map[string]string{})
	if err == nil || strings.Count(err.Error(), "\n") < 5 {
		t.Fatalf("expected many problems at once, got %v", err)
	}
}
