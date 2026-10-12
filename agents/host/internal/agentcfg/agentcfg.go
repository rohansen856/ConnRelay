// Package agentcfg stores the host agent's identity key and enrolment state
// under $XDG_CONFIG_HOME/connrelay (default ~/.config/connrelay). The private key never
// leaves this machine; files are created 0600 in a 0700 directory.
package agentcfg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
)

// Files inside the config directory.
const (
	keyFile   = "host_key.pem"
	stateFile = "agent.json"
)

// JWK is a pinned Ed25519 server key.
type JWK struct {
	KID string `json:"kid"`
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
}

// State is the enrolment state written by `connrelay-agent pair`.
type State struct {
	Server    string `json:"server"` // https://api.example.invalid
	ControlWS string `json:"control_ws_url"`
	DeviceID  string `json:"device_id"`
	AccountID string `json:"account_id"`
	JWKS      []JWK  `json:"jwks"`
}

// Dir returns the configuration directory.
func Dir() string {
	if d := os.Getenv("CONNRELAY_AGENT_CONFIG_DIR"); d != "" {
		return d
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "connrelay")
}

// LoadOrCreateKey returns the host identity key, generating it on first use.
func LoadOrCreateKey(dir string) (*attest.SoftwareSigner, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	p := filepath.Join(dir, keyFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, false, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, false, err
		}
		pemb := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(p, pemb, 0o600); err != nil {
			return nil, false, err
		}
		return &attest.SoftwareSigner{Key: k}, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("%s is readable by group or others; run chmod 600 on it", p)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, false, fmt.Errorf("%s: not PEM", p)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, false, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, false, fmt.Errorf("%s: not a P-256 key", p)
	}
	return &attest.SoftwareSigner{Key: ek}, false, nil
}

// LoadState reads the enrolment state; os.ErrNotExist means not paired.
func LoadState(dir string) (*State, error) {
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.DeviceID == "" || s.Server == "" || len(s.JWKS) == 0 {
		return nil, errors.New("agent.json is incomplete; pair again")
	}
	return &s, nil
}

// SaveState writes the enrolment state atomically.
func SaveState(dir string, s *State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, stateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, stateFile))
}

// RemoveState forgets the enrolment (unpair --local); the key is kept.
func RemoveState(dir string) error {
	err := os.Remove(filepath.Join(dir, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
