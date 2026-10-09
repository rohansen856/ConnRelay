package server_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/services/control/internal/config"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/google/googletest"
	"github.com/rohansen856/connrelay/services/control/internal/server"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

func TestAssembledServer(t *testing.T) {
	pool := dbtest.New(t)
	_, ak, _ := ed25519.GenerateKey(rand.Reader)
	_, tk, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &config.Config{PublicBaseURL: "https://api.test.invalid", AccessKey: ak, TicketKey: tk,
		TicketKeyIDs: []string{config.KeyID(tk.Public().(ed25519.PublicKey))}, PairingPepper: make([]byte, 32),
		TURNSecret: make([]byte, 32), TURNURLs: []string{"turn:t.invalid:3478"}, RelayMaxBPS: 250000, RelayMaxBytes: 1 << 30}
	iss := googletest.New(t, google.Issuer)
	gv, _ := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{"c"}, []string{"owner"}, time.Now)
	srv := server.New(cfg, pool, gv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	for path, want := range map[string]int{"/health/live": 200, "/health/ready": 200, "/v1/meta/compat": 200, "/v1/me": 401, "/v1/devices": 401} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: %d, want %d", path, resp.StatusCode, want)
		}
		if resp.Header.Get("X-Request-Id") == "" {
			t.Errorf("%s: no request ID", path)
		}
	}
	// Unauthenticated endpoints are rate limited per IP.
	limited := false
	for i := 0; i < 30; i++ {
		resp, err := http.Post(ts.URL+"/v1/auth/challenge", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 429 {
			limited = resp.Header.Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Fatal("challenge endpoint never rate limited")
	}
}

// With debug logging on, requests are logged (status included) and the
// wrapped writer still lets WebSocket upgrades through.
func TestAccessLog(t *testing.T) {
	pool := dbtest.New(t)
	_, ak, _ := ed25519.GenerateKey(rand.Reader)
	_, tk, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &config.Config{PublicBaseURL: "https://api.test.invalid", AccessKey: ak, TicketKey: tk,
		TicketKeyIDs: []string{config.KeyID(tk.Public().(ed25519.PublicKey))}, PairingPepper: make([]byte, 32),
		TURNSecret: make([]byte, 32), TURNURLs: []string{"turn:t.invalid:3478"}, RelayMaxBPS: 250000, RelayMaxBytes: 1 << 30}
	iss := googletest.New(t, google.Issuer)
	gv, _ := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{"c"}, []string{"owner"}, time.Now)
	var buf safeBuffer
	srv := server.New(cfg, pool, gv, slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/devices?cursor=secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http")+"/v1/agent/control",
		&websocket.DialOptions{Subprotocols: []string{"prw.v1"}})
	if err != nil {
		t.Fatalf("websocket upgrade through access log: %v", err)
	}
	ws.CloseNow()

	out := buf.String()
	if !strings.Contains(out, `"path":"/v1/devices","status":401`) {
		t.Errorf("request not logged:\n%s", out)
	}
	if strings.Contains(out, "secret") {
		t.Error("query string leaked into the log")
	}
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *safeBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
