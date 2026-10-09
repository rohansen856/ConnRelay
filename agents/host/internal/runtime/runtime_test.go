package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
)

// TestReconnectsWhenServerGoesSilent: a control socket that stops delivering
// anything (half-open through a NAT remap or proxy) must be abandoned and
// re-dialled, not trusted forever.
func TestReconnectsWhenServerGoesSilent(t *testing.T) {
	var dials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"prw.v1"}})
		if err != nil {
			return
		}
		dials.Add(1)
		ctx := r.Context()
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"type":"auth.challenge","nonce":"n"}`))
		_, _, _ = ws.Read(ctx) // auth.response
		_ = ws.Write(ctx, websocket.MessageText, []byte(`{"type":"auth.ok"}`))
		// Then silence: read (and ignore) heartbeats, never answer.
		for {
			if _, _, err := ws.Read(ctx); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := attest.NewSoftwareSigner()
	a := &Agent{
		State: &agentcfg.State{Server: srv.URL, ControlWS: "ws" + strings.TrimPrefix(srv.URL, "http"), DeviceID: "host-1",
			JWKS: []agentcfg.JWK{{KID: "k", KTY: "OKP", CRV: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub)}}},
		Key: key, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Silence: 300 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	go a.Run(ctx)
	deadline := time.Now().Add(7 * time.Second)
	for dials.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if dials.Load() < 2 {
		t.Fatalf("agent kept a silent control socket (dials=%d)", dials.Load())
	}
}
