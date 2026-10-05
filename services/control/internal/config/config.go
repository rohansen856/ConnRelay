// Package config loads and validates the control plane's environment
// configuration. Secrets are read from files, never from variables.
package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is the validated configuration.
type Config struct {
	PublicBaseURL string
	ListenAddr    string
	DatabaseURL   string
	GoogleClients []string
	AllowedSubs   []string // Google "sub" values (the "google:" prefix removed)
	AccessKey     ed25519.PrivateKey
	TicketKey     ed25519.PrivateKey
	TicketKeyIDs  []string // kid of TicketKey first
	PairingPepper []byte
	TURNSecret    []byte
	TURNURLs      []string
	STUNURLs      []string
	RelayMaxBPS   int
	RelayMaxBytes int64
	LogLevel      string
}

// Getenv reads one variable (os.Getenv in production, a map in tests).
type Getenv func(string) string

// Load validates the environment and reads secret files. It reports every
// problem at once.
func Load(env Getenv) (*Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	c := &Config{ListenAddr: or(env("PRW_LISTEN_ADDR"), "127.0.0.1:8080"), LogLevel: or(env("PRW_LOG_LEVEL"), "info"),
		RelayMaxBPS: 2_000_000 / 8, RelayMaxBytes: 2 << 30}

	c.PublicBaseURL = strings.TrimRight(env("PRW_PUBLIC_BASE_URL"), "/")
	if u, err := url.Parse(c.PublicBaseURL); err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		if !(u != nil && u.Scheme == "http" && env("PRW_DEV_ALLOW_HTTP") == "1") {
			bad("PRW_PUBLIC_BASE_URL must be an https URL without a path")
		}
	}

	c.DatabaseURL = env("PRW_DATABASE_URL")
	if f := env("PRW_DATABASE_URL_FILE"); f != "" {
		b, err := readSecret(f, 1)
		if err != nil {
			bad("PRW_DATABASE_URL_FILE: %v", err)
		}
		c.DatabaseURL = strings.TrimSpace(string(b))
	}
	if c.DatabaseURL == "" {
		bad("PRW_DATABASE_URL or PRW_DATABASE_URL_FILE is required")
	}

	c.GoogleClients = list(env("PRW_GOOGLE_CLIENT_IDS"))
	if len(c.GoogleClients) == 0 {
		bad("PRW_GOOGLE_CLIENT_IDS is required")
	}
	for _, s := range list(env("PRW_ALLOWED_SUBJECTS")) {
		sub, ok := strings.CutPrefix(s, "google:")
		if !ok || sub == "" {
			bad("PRW_ALLOWED_SUBJECTS entries must look like google:<sub>, got %q", s)
			continue
		}
		c.AllowedSubs = append(c.AllowedSubs, sub)
	}
	if len(c.AllowedSubs) == 0 {
		bad("PRW_ALLOWED_SUBJECTS is empty: refusing to start (there is no open sign-up)")
	}

	var err error
	if c.AccessKey, err = loadKey(env("PRW_ACCESS_SIGNING_KEY_FILE")); err != nil {
		bad("PRW_ACCESS_SIGNING_KEY_FILE: %v", err)
	}
	if c.TicketKey, err = loadKey(env("PRW_TICKET_SIGNING_KEY_FILE")); err != nil {
		bad("PRW_TICKET_SIGNING_KEY_FILE: %v", err)
	} else {
		c.TicketKeyIDs = []string{KeyID(c.TicketKey.Public().(ed25519.PublicKey))}
	}
	if c.AccessKey != nil && c.TicketKey != nil && c.AccessKey.Equal(c.TicketKey) {
		bad("access and ticket signing keys must differ")
	}
	if c.PairingPepper, err = readSecret(env("PRW_PAIRING_HMAC_KEY_FILE"), 32); err != nil {
		bad("PRW_PAIRING_HMAC_KEY_FILE: %v", err)
	}
	if c.TURNSecret, err = readSecret(env("PRW_TURN_SHARED_SECRET_FILE"), 32); err != nil {
		bad("PRW_TURN_SHARED_SECRET_FILE: %v", err)
	}
	c.TURNURLs = list(env("PRW_TURN_URLS"))
	c.STUNURLs = list(env("PRW_STUN_URLS"))
	for _, u := range append(append([]string{}, c.TURNURLs...), c.STUNURLs...) {
		if !strings.HasPrefix(u, "turn:") && !strings.HasPrefix(u, "turns:") && !strings.HasPrefix(u, "stun:") {
			bad("invalid ICE URL %q", u)
		}
	}
	if len(c.TURNURLs) == 0 {
		bad("PRW_TURN_URLS is required")
	}
	if v := env("PRW_RELAY_MAX_BPS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 8000 {
			bad("PRW_RELAY_MAX_BPS must be bits per second >= 8000")
		} else {
			c.RelayMaxBPS = n / 8
		}
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		bad("PRW_LOG_LEVEL must be debug, info, warn or error")
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func list(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// readSecret reads a secret file that must not be group/world readable.
func readSecret(path string, min int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (chmod 600)", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < min {
		return nil, fmt.Errorf("must hold at least %d bytes", min)
	}
	return b, nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	b, err := readSecret(path, 1)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, errors.New("expected a PKCS#8 PEM private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not Ed25519")
	}
	return ek, nil
}

// KeyID derives a stable key ID from a public key.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// EncodeKey returns a PKCS#8 PEM encoding of k (used by keygen).
func EncodeKey(k ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
