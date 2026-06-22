package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/frame"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
	"github.com/rohansen856/connrelay/core/prwcore/transport/innertls"
	"github.com/rohansen856/connrelay/core/prwcore/transport/wssrelay"
)

type env struct {
	srv    *httptest.Server
	relay  *Server
	issuer token.Issuer
	url    string
}

func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := New(cfg, token.KeySet{"k1": pub}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	mux.Handle("/v1/relay", r)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{srv: srv, relay: r, issuer: token.Issuer{KID: "k1", Key: priv},
		url: "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/relay"}
}

var jtiN atomic.Int64

func (e *env) tok(t *testing.T, att, role string) string {
	t.Helper()
	now := time.Now()
	s, err := e.issuer.Issue(token.TypeRelay, token.Relay{
		Registered: token.Registered{IAT: now.Unix(), EXP: now.Add(90 * time.Second).Unix(), JTI: "j" + string(rune('A'+jtiN.Add(1)))},
		Att:        att, Role: role, Dev: role + "-dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// connectPair runs both peers through the relay with inner TLS.
func connectPair(t *testing.T, e *env, att string, hc *http.Client, mitm bool) (transport.Conn, transport.Conn, error, error) {
	t.Helper()
	hostID, _ := innertls.NewIdentity(att)
	phoneID, _ := innertls.NewIdentity(att)
	phoneFPSeenByHost := phoneID.Fingerprint
	if mitm {
		other, _ := innertls.NewIdentity(att)
		phoneFPSeenByHost = other.Fingerprint // signaling tampered
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var host transport.Conn
	var herr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		host, herr = wssrelay.Connect(ctx, wssrelay.Params{URL: e.url, AttemptID: att, Token: e.tok(t, att, "server"), Role: "server", HTTPClient: hc}, hostID, phoneFPSeenByHost)
	}()
	phone, perr := wssrelay.Connect(ctx, wssrelay.Params{URL: e.url, AttemptID: att, Token: e.tok(t, att, "client"), Role: "client", HTTPClient: hc}, phoneID, hostID.Fingerprint)
	wg.Wait()
	return host, phone, herr, perr
}

func TestEndToEndFrames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BytesPerSec = 1 << 30
	e := newEnv(t, cfg)
	host, phone, herr, perr := connectPair(t, e, "att-1", nil, false)
	if herr != nil || perr != nil {
		t.Fatalf("host %v phone %v", herr, perr)
	}
	defer host.Close()
	defer phone.Close()

	if host.Path() != transport.PathWSSRelay || host.Transport() != "tls13" {
		t.Fatalf("path %s transport %s", host.Path(), host.Transport())
	}
	if host.LocalCertFP() != phone.RemoteCertFP() || phone.LocalCertFP() != host.RemoteCertFP() {
		t.Fatal("fingerprints do not line up")
	}

	// 4 MiB of output in max-size frames, plus one input frame back.
	payload := bytes.Repeat([]byte("0123456789abcdef"), frame.MaxPayload/16)
	const n = 256
	go func() {
		for i := 0; i < n; i++ {
			_ = host.Send(&frame.Frame{Type: frame.TypeOutput, StreamID: 1, Seq: uint32(i), Payload: payload})
		}
	}()
	for i := 0; i < n; i++ {
		f, err := phone.Recv()
		if err != nil {
			t.Fatalf("recv %d: %v", i, err)
		}
		if f.Seq != uint32(i) || !bytes.Equal(f.Payload, payload) {
			t.Fatalf("frame %d corrupted", i)
		}
	}
	if err := phone.Send(&frame.Frame{Type: frame.TypeInput, StreamID: 1, Payload: []byte("exit\r")}); err != nil {
		t.Fatal(err)
	}
	f, err := host.Recv()
	if err != nil {
		t.Fatalf("input: %v", err)
	}
	if string(f.Payload) != "exit\r" {
		t.Fatalf("input payload %q", f.Payload)
	}
	if e.relay.Stats.Bytes.Load() < n*frame.MaxPayload {
		t.Fatalf("relay counted %d bytes", e.relay.Stats.Bytes.Load())
	}
}

func TestSignalingTamperDetected(t *testing.T) {
	e := newEnv(t, DefaultConfig())
	_, _, herr, perr := connectPair(t, e, "att-mitm", nil, true)
	if herr == nil && perr == nil {
		t.Fatal("handshake succeeded with substituted fingerprint")
	}
}

func TestRejectsBadTokens(t *testing.T) {
	e := newEnv(t, DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := token.Issuer{KID: "k1", Key: foreign}.Issue(token.TypeRelay, token.Relay{
		Registered: token.Registered{IAT: time.Now().Unix(), EXP: time.Now().Add(time.Minute).Unix(), JTI: "x"}, Att: "a", Role: "client"})

	cases := map[string]wssrelay.Params{
		"forged":        {AttemptID: "a", Token: forged, Role: "client"},
		"wrong attempt": {AttemptID: "b", Token: e.tok(t, "a", "client"), Role: "client"},
		"wrong role":    {AttemptID: "a", Token: e.tok(t, "a", "client"), Role: "server"},
		"garbage":       {AttemptID: "a", Token: "not.a.token", Role: "client"},
	}
	for name, p := range cases {
		p.URL = e.url
		if _, err := wssrelay.Join(ctx, p); !errors.Is(err, wssrelay.ErrRejected) {
			t.Errorf("%s: want rejection, got %v", name, err)
		}
	}
}

func TestRejectsReusedToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PeerWait = 300 * time.Millisecond
	e := newEnv(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok := e.tok(t, "a", "client")
	p := wssrelay.Params{URL: e.url, AttemptID: "a", Token: tok, Role: "client"}
	if _, err := wssrelay.Join(ctx, p); !errors.Is(err, wssrelay.ErrRejected) { // times out waiting for peer
		t.Fatalf("first join: %v", err)
	}
	if _, err := wssrelay.Join(ctx, p); !errors.Is(err, wssrelay.ErrRejected) {
		t.Fatalf("reuse accepted: %v", err)
	}
	if e.relay.Stats.Rejects.Load() < 2 {
		t.Fatalf("rejects %d", e.relay.Stats.Rejects.Load())
	}
}

func TestSameRoleTwiceRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PeerWait = 2 * time.Second
	e := newEnv(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go wssrelay.Join(ctx, wssrelay.Params{URL: e.url, AttemptID: "a", Token: e.tok(t, "a", "client"), Role: "client"})
	time.Sleep(100 * time.Millisecond)
	if _, err := wssrelay.Join(ctx, wssrelay.Params{URL: e.url, AttemptID: "a", Token: e.tok(t, "a", "client"), Role: "client"}); !errors.Is(err, wssrelay.ErrRejected) {
		t.Fatalf("second client accepted: %v", err)
	}
}

func TestCloseAttemptEndsSplice(t *testing.T) {
	e := newEnv(t, DefaultConfig())
	host, phone, herr, perr := connectPair(t, e, "att-rev", nil, false)
	if herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	e.relay.CloseAttempt("att-rev")
	done := make(chan error, 1)
	go func() { _, err := phone.Recv(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error after revoke")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("splice not closed")
	}
	host.Close()
}

// connectProxy is a minimal HTTP CONNECT proxy that records what it tunnels.
func connectProxy(t *testing.T) (*url.URL, *atomic.Int64) {
	t.Helper()
	var tunnels atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				tunnels.Add(1)
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u, &tunnels
}

func TestThroughConnectProxy(t *testing.T) {
	e := newEnv(t, DefaultConfig())
	pu, tunnels := connectProxy(t)
	// Force CONNECT even for a plain ws:// target by tunnelling via a dialer.
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := net.Dial("tcp", pu.Host)
			if err != nil {
				return nil, err
			}
			io.WriteString(c, "CONNECT "+addr+" HTTP/1.1\r\nHost: "+addr+"\r\n\r\n")
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != 200 {
				c.Close()
				return nil, errors.New("proxy refused")
			}
			return c, nil
		},
	}}
	host, phone, herr, perr := connectPair(t, e, "att-proxy", hc, false)
	if herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	defer host.Close()
	defer phone.Close()
	_ = phone.Send(&frame.Frame{Type: frame.TypeInput, StreamID: 1, Payload: []byte("hi")})
	if f, err := host.Recv(); err != nil || string(f.Payload) != "hi" {
		t.Fatal(err)
	}
	if tunnels.Load() < 2 {
		t.Fatalf("proxy tunnelled %d connections", tunnels.Load())
	}
}

func TestRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BytesPerSec = 256 * 1024
	cfg.MaxMessage = 32 * 1024 // burst = 128 KiB
	e := newEnv(t, cfg)
	host, phone, herr, perr := connectPair(t, e, "att-rate", nil, false)
	if herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	defer host.Close()
	defer phone.Close()
	payload := make([]byte, frame.MaxPayload)
	const n = 48 // 768 KiB: ~2.5 s at 256 KiB/s after the burst
	start := time.Now()
	go func() {
		for i := 0; i < n; i++ {
			_ = host.Send(&frame.Frame{Type: frame.TypeOutput, StreamID: 1, Payload: payload})
		}
	}()
	for i := 0; i < n; i++ {
		if _, err := phone.Recv(); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d < 2*time.Second {
		t.Fatalf("768 KiB at 256 KiB/s took only %v", d)
	}
}

func TestByteCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BytesPerSec = 1 << 30
	cfg.MaxBytes = 256 * 1024
	e := newEnv(t, cfg)
	host, phone, herr, perr := connectPair(t, e, "att-cap", nil, false)
	if herr != nil || perr != nil {
		t.Fatal(herr, perr)
	}
	defer host.Close()
	go func() {
		payload := make([]byte, frame.MaxPayload)
		for i := 0; i < 64; i++ {
			if host.Send(&frame.Frame{Type: frame.TypeOutput, StreamID: 1, Payload: payload}) != nil {
				return
			}
		}
	}()
	var got int
	for {
		f, err := phone.Recv()
		if err != nil {
			break
		}
		got += len(f.Payload)
	}
	if got >= 64*frame.MaxPayload || got > int(cfg.MaxBytes) {
		t.Fatalf("received %d bytes past a %d byte cap", got, cfg.MaxBytes)
	}
}
