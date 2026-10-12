package agentcfg

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "connrelay")
	k1, created, err := LoadOrCreateKey(dir)
	if err != nil || !created {
		t.Fatal(err, created)
	}
	st, _ := os.Stat(filepath.Join(dir, keyFile))
	ds, _ := os.Stat(dir)
	if st.Mode().Perm() != 0o600 || ds.Mode().Perm() != 0o700 {
		t.Fatalf("permissions %v %v", st.Mode(), ds.Mode())
	}
	k2, created, err := LoadOrCreateKey(dir)
	if err != nil || created || string(k1.PublicKeySPKI()) != string(k2.PublicKeySPKI()) {
		t.Fatal("key not reloaded")
	}
	_ = os.Chmod(filepath.Join(dir, keyFile), 0o644)
	if _, _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("world-readable key accepted")
	}
}

func TestState(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("expected not paired")
	}
	s := &State{Server: "https://x.invalid", DeviceID: "d", JWKS: []JWK{{KID: "k", X: "x"}}}
	if err := SaveState(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil || got.DeviceID != "d" {
		t.Fatal(got, err)
	}
	_ = RemoveState(dir)
	if _, err := LoadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state not removed")
	}
}
