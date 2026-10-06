// Package client is the phone side of a connection: request an attempt from
// the control plane, signal over /v1/signaling, race WebRTC against the WSS
// relay, and attest the host against the fingerprint pinned at pairing. The
// returned transport is verified and ready for terminal.* messages.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	pionwebrtc "github.com/pion/webrtc/v4"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/connmgr"
	"github.com/rohansen856/connrelay/core/prwcore/peer"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
	"github.com/rohansen856/connrelay/core/prwcore/transport/innertls"
	"github.com/rohansen856/connrelay/core/prwcore/transport/webrtc"
	"github.com/rohansen856/connrelay/core/prwcore/transport/wssrelay"
)

// ErrHostKeyMismatch means the control plane offered a host key that does not
// match the fingerprint pinned at pairing. Never connect in that case.
var ErrHostKeyMismatch = errors.New("host key does not match the paired fingerprint")

// Config describes the signed-in phone.
type Config struct {
	API         string // https://api.example.invalid
	HTTP        *http.Client
	AccessToken string
	DeviceID    string
	Signer      attest.Signer
	// Mode limits the paths: "auto" (default), "webrtc" or "wss".
	Mode       string
	ForceRelay bool
	UDPBlocked bool
	// IncludeLoopback adds loopback ICE candidates (tests).
	IncludeLoopback bool
}

// Target is the host to connect to.
type Target struct {
	HostID   string
	PinnedFP string // SHA-256 fingerprint of the host key, from pairing
}

// Result describes a connected attempt.
type Result struct {
	AttemptID string
	Path      string
	Report    *connmgr.Report
}

// APIError is an error response from the control plane.
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string { return fmt.Sprintf("control plane: %s (%d)", e.Code, e.Status) }

type attemptResp struct {
	AttemptID string `json:"connection_attempt_id"`
	Ticket    string `json:"ticket"`
	Nonce     string `json:"attestation_nonce"`
	Relay     struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"relay"`
	ICE []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"ice_servers"`
	SignalingURL string `json:"signaling_url"`
	Fallback     struct {
		After int `json:"wss_race_after_ms"`
	} `json:"fallback"`
	Host struct {
		DeviceID string `json:"device_id"`
		SPKI     string `json:"public_key_spki"`
	} `json:"host"`
}

func (c *Config) call(ctx context.Context, method, path string, hdr map[string]string, body, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, method, c.API+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return &APIError{Status: resp.StatusCode, Code: e.Error.Code}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func randomKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Connect establishes and verifies a transport to the host.
func Connect(ctx context.Context, cfg Config, t Target) (transport.Conn, *Result, error) {
	if cfg.HTTP == nil {
		cfg.HTTP = http.DefaultClient
	}
	if t.PinnedFP == "" {
		return nil, nil, errors.New("client: host fingerprint from pairing is required")
	}
	// Open signaling first: the host starts signaling as soon as the
	// attempt exists.
	sig, err := dialSignaling(ctx, cfg, signalingURL(cfg.API))
	if err != nil {
		return nil, nil, err
	}
	defer sig.close()
	var a attemptResp
	if err := cfg.call(ctx, "POST", "/v1/connections", map[string]string{"Idempotency-Key": randomKey()},
		map[string]string{"host_device_id": t.HostID, "capability": "terminal"}, &a); err != nil {
		return nil, nil, err
	}
	spki, err := base64.RawURLEncoding.DecodeString(a.Host.SPKI)
	if err != nil || attest.Fingerprint(spki) != t.PinnedFP {
		cfg.report(context.Background(), a.AttemptID, "failed", "", "peer_identity_mismatch")
		return nil, nil, ErrHostKeyMismatch
	}
	hostKey, err := attest.ParsePublicKey(spki)
	if err != nil {
		return nil, nil, ErrHostKeyMismatch
	}

	var ice []pionwebrtc.ICEServer
	for _, s := range a.ICE {
		ice = append(ice, pionwebrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	opts := connmgr.Options{
		UDPBlocked: cfg.UDPBlocked,
		Handshake: func(ctx context.Context, c transport.Conn) error {
			_, err := peer.Handshake(ctx, c, peer.Params{Role: peer.RolePhone, Self: cfg.DeviceID, Peer: t.HostID,
				Attempt: a.AttemptID, Nonce: a.Nonce, Cap: "terminal", Signer: cfg.Signer, PeerKey: hostKey,
				Ticket: a.Ticket, Impl: "prwcore-client"})
			return err
		},
	}
	if a.Fallback.After > 0 {
		opts.FallbackDelay = time.Duration(a.Fallback.After) * time.Millisecond
	}
	if cfg.Mode == "" || cfg.Mode == "auto" || cfg.Mode == "webrtc" {
		opts.ICE = func(ctx context.Context) (transport.Conn, error) {
			p, err := webrtc.NewPeer(webrtc.Config{Offerer: true, ICEServers: ice, ForceRelay: cfg.ForceRelay,
				IncludeLoopback: cfg.IncludeLoopback, OnSignal: func(s webrtc.Signal) { sig.send(a.AttemptID, s.Type, s) }})
			if err != nil {
				return nil, err
			}
			sig.setPeer(p)
			if err := p.Start(); err != nil {
				p.Close()
				return nil, err
			}
			c, err := p.Wait(ctx)
			if err != nil {
				p.Close()
			}
			return c, err
		}
	}
	if cfg.Mode == "" || cfg.Mode == "auto" || cfg.Mode == "wss" {
		opts.WSS = func(ctx context.Context) (transport.Conn, error) {
			id, err := innertls.NewIdentity(a.AttemptID)
			if err != nil {
				return nil, err
			}
			sig.send(a.AttemptID, "tls_fingerprint", map[string]string{"sha256": id.Fingerprint})
			var fp string
			select {
			case fp = <-sig.tlsFP:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return wssrelay.Connect(ctx, wssrelay.Params{URL: a.Relay.URL, AttemptID: a.AttemptID, Token: a.Relay.Token,
				Role: token.RoleClient, HTTPClient: cfg.HTTP}, id, fp)
		}
	}
	conn, rep, err := connmgr.Connect(ctx, opts)
	if err != nil {
		code := "connect_timeout"
		if errors.Is(err, peer.ErrIdentity) {
			code = "peer_identity_mismatch"
		}
		cfg.report(context.Background(), a.AttemptID, "failed", "", code)
		return nil, nil, err
	}
	status := map[string]string{transport.PathDirect: "connected_direct", transport.PathTURN: "connected_relay", transport.PathWSSRelay: "connected_wss"}[rep.Path]
	cfg.report(ctx, a.AttemptID, status, "", "")
	return conn, &Result{AttemptID: a.AttemptID, Path: rep.Path, Report: rep}, nil
}

// signalingURL derives the signaling endpoint from the API base URL.
func signalingURL(api string) string {
	if strings.HasPrefix(api, "http://") {
		return "ws://" + strings.TrimPrefix(api, "http://") + "/v1/signaling"
	}
	return "wss://" + strings.TrimPrefix(api, "https://") + "/v1/signaling"
}

func (c *Config) report(ctx context.Context, attempt, status, path, failure string) {
	body := map[string]string{"status": status}
	if path != "" {
		body["path_type"] = path
	}
	if failure != "" {
		body["failure_code"] = failure
	}
	_ = c.call(ctx, "PATCH", "/v1/connections/"+attempt, nil, body, nil)
}

// ---- signaling ----

type signaling struct {
	ws    *websocket.Conn
	wmu   sync.Mutex
	tlsFP chan string
	mu    sync.Mutex
	peer  *webrtc.Peer
	queue []webrtc.Signal
	done  chan struct{}
}

func dialSignaling(ctx context.Context, cfg Config, url string) (*signaling, error) {
	ws, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{Subprotocols: []string{"prw.v1"}, HTTPClient: cfg.HTTP})
	if err != nil {
		return nil, fmt.Errorf("signaling: %w", err)
	}
	ws.SetReadLimit(64 << 10)
	s := &signaling{ws: ws, tlsFP: make(chan string, 1), done: make(chan struct{})}
	b, _ := json.Marshal(map[string]any{"type": "auth", "payload": map[string]string{"access_token": cfg.AccessToken}})
	if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
		ws.CloseNow()
		return nil, err
	}
	actx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_, msg, err := ws.Read(actx)
	var ok struct {
		Type string `json:"type"`
	}
	if err != nil || json.Unmarshal(msg, &ok) != nil || ok.Type != "auth.ok" {
		ws.CloseNow()
		return nil, errors.New("signaling: authentication failed")
	}
	go s.loop()
	return s, nil
}

func (s *signaling) loop() {
	defer close(s.done)
	for {
		_, b, err := s.ws.Read(context.Background())
		if err != nil {
			return
		}
		var m struct {
			Type    string          `json:"type"`
			Kind    string          `json:"kind"`
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(b, &m) != nil || m.Type != "signal" {
			continue
		}
		switch m.Kind {
		case "tls_fingerprint":
			var p struct {
				SHA256 string `json:"sha256"`
			}
			if json.Unmarshal(m.Payload, &p) == nil {
				select {
				case s.tlsFP <- p.SHA256:
				default:
				}
			}
		case "answer", "ice_candidate", "ice_complete":
			var w webrtc.Signal
			if json.Unmarshal(m.Payload, &w) != nil {
				continue
			}
			w.Type = m.Kind
			s.mu.Lock()
			if s.peer == nil {
				s.queue = append(s.queue, w)
				s.mu.Unlock()
				continue
			}
			p := s.peer
			s.mu.Unlock()
			_ = p.HandleSignal(w)
		}
	}
}

func (s *signaling) setPeer(p *webrtc.Peer) {
	s.mu.Lock()
	s.peer = p
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	for _, w := range q {
		_ = p.HandleSignal(w)
	}
}

func (s *signaling) send(attempt, kind string, payload any) {
	b, _ := json.Marshal(map[string]any{"type": "signal", "attempt_id": attempt, "kind": kind, "payload": payload})
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.ws.Write(ctx, websocket.MessageText, b)
}

func (s *signaling) close() { s.ws.Close(websocket.StatusNormalClosure, "") }
