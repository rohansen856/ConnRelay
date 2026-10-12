// Package wssrelay implements the client side of the /v1/relay WebSocket
// fallback (protocol v1 §9.2): join an attempt, wait for the peer, then run
// TLS 1.3 end to end through the opaque byte pipe.
package wssrelay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport/innertls"
)

// JoinTimeout bounds the wait for the relay's "joined" message.
const JoinTimeout = 20 * time.Second

// Params describe one relay join.
type Params struct {
	URL       string // wss://api.example.invalid/v1/relay
	AttemptID string
	Token     string // relay token issued for this attempt and role
	Role      string // "client" (phone) or "server" (host)
	// HTTPClient is used for the WebSocket handshake. Set its Transport.Proxy
	// to traverse HTTP CONNECT proxies. Nil uses http.DefaultClient, which
	// honours HTTPS_PROXY from the environment.
	HTTPClient *http.Client
}

// Message is a relay text control message.
type Message struct {
	Type      string `json:"type"`
	AttemptID string `json:"attempt_id,omitempty"`
	Token     string `json:"relay_token,omitempty"`
	Role      string `json:"role,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ErrRejected is returned when the relay refuses the join.
var ErrRejected = errors.New("wssrelay: join rejected")

// Join connects, sends the join message and waits until the peer has joined.
// The returned net.Conn is the opaque byte pipe to the peer.
func Join(ctx context.Context, p Params) (net.Conn, error) {
	ws, _, err := websocket.Dial(ctx, p.URL, &websocket.DialOptions{HTTPClient: p.HTTPClient})
	if err != nil {
		return nil, fmt.Errorf("wssrelay: dial: %w", err)
	}
	ws.SetReadLimit(64 * 1024)
	jctx, cancel := context.WithTimeout(ctx, JoinTimeout)
	defer cancel()
	join, _ := json.Marshal(Message{Type: "join", AttemptID: p.AttemptID, Token: p.Token, Role: p.Role})
	if err := ws.Write(jctx, websocket.MessageText, join); err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("wssrelay: send join: %w", err)
	}
	typ, b, err := ws.Read(jctx)
	if err != nil {
		ws.CloseNow()
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	var m Message
	if typ != websocket.MessageText || json.Unmarshal(b, &m) != nil || m.Type != "joined" {
		ws.CloseNow()
		return nil, fmt.Errorf("%w: unexpected %q", ErrRejected, m.Type)
	}
	// The context passed to NetConn bounds the lifetime of the pipe; the
	// caller controls it through Close.
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary), nil
}

// Connect joins the relay and runs the inner TLS 1.3 handshake. The host is
// the TLS server ("server" role). peerFP is the fingerprint the peer sent in
// its tls_fingerprint signaling message.
func Connect(ctx context.Context, p Params, id *innertls.Identity, peerFP string) (transport.Conn, error) {
	pipe, err := Join(ctx, p)
	if err != nil {
		return nil, err
	}
	var tc net.Conn
	if p.Role == "server" {
		tc, err = innertls.Server(ctx, pipe, id, peerFP)
	} else {
		tc, err = innertls.Client(ctx, pipe, id, peerFP)
	}
	if err != nil {
		pipe.Close()
		return nil, err
	}
	return transport.NewStreamConn(tc, attest.TransportTLS13, transport.PathWSSRelay, id.Fingerprint, peerFP), nil
}
