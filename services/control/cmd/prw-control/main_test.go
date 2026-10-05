package main

import (
	"path/filepath"
	"testing"

	"github.com/rohansen856/connrelay/services/control/internal/config"
)

func TestKeygenProducesLoadableConfig(t *testing.T) {
	dir := t.TempDir()
	if err := keygen(dir); err != nil {
		t.Fatal(err)
	}
	if err := keygen(dir); err == nil {
		t.Fatal("keygen overwrote existing keys")
	}
	env := map[string]string{
		"PRW_PUBLIC_BASE_URL":         "https://api.example.invalid",
		"PRW_DATABASE_URL":            "postgres://x@localhost/prw",
		"PRW_GOOGLE_CLIENT_IDS":       "c",
		"PRW_ALLOWED_SUBJECTS":        "google:1",
		"PRW_ACCESS_SIGNING_KEY_FILE": filepath.Join(dir, "access_signing_key.pem"),
		"PRW_TICKET_SIGNING_KEY_FILE": filepath.Join(dir, "ticket_signing_key.pem"),
		"PRW_PAIRING_HMAC_KEY_FILE":   filepath.Join(dir, "pairing_hmac_key"),
		"PRW_TURN_SHARED_SECRET_FILE": filepath.Join(dir, "turn_shared_secret"),
		"PRW_TURN_URLS":               "turn:t.invalid:3478",
	}
	if _, err := config.Load(func(k string) string { return env[k] }); err != nil {
		t.Fatal(err)
	}
}
