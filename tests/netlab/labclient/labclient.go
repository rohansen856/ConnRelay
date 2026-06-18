// Package labclient runs one side (phone or host) of a full PRW connection
// attempt against prw-labserver: ICE/TURN and WSS-relay paths raced by the
// connection manager, mutual attestation, then an integrity-checked echo of
// terminal bytes. It backs the prw-labpeer CLI and the on-device probe.
package labclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	pionwebrtc "github.com/pion/webrtc/v4"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/connmgr"
	"github.com/rohansen856/connrelay/core/prwcore/control"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
	"github.com/rohansen856/connrelay/core/prwcore/peer"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
	"github.com/rohansen856/connrelay/core/prwcore/transport/innertls"
	"github.com/rohansen856/connrelay/core/prwcore/transport/webrtc"
	"github.com/rohansen856/connrelay/core/prwcore/transport/wssrelay"
)

type bundle struct {
	AttemptID   string `json:"attempt_id"`
	Role        string `json:"role"`
	Nonce       string `json:"attestation_nonce"`
	Ticket      string `json:"ticket"`
	TicketKey   string `json:"ticket_pubkey"`
	RelayURL    string `json:"relay_url"`
	RelayToken  string `json:"relay_token"`
	SignalURL   string `json:"signal_url"`
	PhoneDevice string `json:"phone_device_id"`
	HostDevice  string `json:"host_device_id"`
	ICEServers  []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"ice_servers"`
}

// sigMsg is the lab signaling envelope.
type sigMsg struct {
	Kind   string          `json:"kind"` // pin, webrtc, tls_fp
	SPKI   string          `json:"spki,omitempty"`
	FP     string          `json:"fp,omitempty"`
	Signal *webrtc.Signal  `json:"signal,omitempty"`
	Extra  json.RawMessage `json:"extra,omitempty"`
}

// Result is the outcome of one attempt (printed as one JSON line).
type Result struct {
	Role      string            `json:"role"`
	OK        bool              `json:"ok"`
	Path      string            `json:"path,omitempty"`
	ConnectMS int64             `json:"connect_ms,omitempty"`
	RTTMS     float64           `json:"rtt_ms,omitempty"`
	Bytes     int               `json:"bytes,omitempty"`
	MBps      float64           `json:"mbps,omitempty"`
	Error     string            `json:"error,omitempty"`
	Report    *connmgr.Report   `json:"report,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

func getBundle(server, role string, hc *http.Client) (*bundle, error) {
	server, id, _ := strings.Cut(server, "|")
	q := "?id=" + url.QueryEscape(id)
	var resp *http.Response
	var err error
	if role == "phone" {
		resp, err = hc.Post(server+"/lab/attempt"+q, "application/json", nil)
	} else {
		for {
			resp, err = hc.Get(server + "/lab/next" + q)
			if err != nil || resp.StatusCode != http.StatusNoContent {
				break
			}
			resp.Body.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lab server: %s", resp.Status)
	}
	var b bundle
	return &b, json.NewDecoder(resp.Body).Decode(&b)
}

// signaling multiplexes the lab signal socket.
type signaling struct {
	ws    *websocket.Conn
	wmu   sync.Mutex
	pin   chan string
	tlsFP chan string
	mu    sync.Mutex
	peer  *webrtc.Peer
	queue []webrtc.Signal
}

func dialSignal(ctx context.Context, b *bundle, hc *http.Client) (*signaling, error) {
	u := b.SignalURL + "?attempt=" + url.QueryEscape(b.AttemptID) + "&role=" + b.Role
	ws, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: hc})
	if err != nil {
		return nil, fmt.Errorf("signal dial: %w", err)
	}
	ws.SetReadLimit(64 * 1024)
	s := &signaling{ws: ws, pin: make(chan string, 1), tlsFP: make(chan string, 1)}
	go s.readLoop()
	return s, nil
}

func (s *signaling) send(m sigMsg) {
	b, _ := json.Marshal(m)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.ws.Write(ctx, websocket.MessageText, b)
}

func (s *signaling) readLoop() {
	for {
		_, b, err := s.ws.Read(context.Background())
		if err != nil {
			return
		}
		var m sigMsg
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		switch m.Kind {
		case "pin":
			s.pin <- m.SPKI
		case "tls_fp":
			s.tlsFP <- m.FP
		case "webrtc":
			s.mu.Lock()
			if s.peer == nil {
				s.queue = append(s.queue, *m.Signal)
				s.mu.Unlock()
				continue
			}
			p := s.peer
			s.mu.Unlock()
			_ = p.HandleSignal(*m.Signal)
		}
	}
}

func (s *signaling) attach(p *webrtc.Peer) {
	s.mu.Lock()
	s.peer = p
	q := s.queue
	s.queue = nil
	s.mu.Unlock()
	for _, sg := range q {
		_ = p.HandleSignal(sg)
	}
}

// Config describes one attempt.
type Config struct {
	Server     string // lab server base URL
	LabID      string // pairs one phone run with one host run
	Role       string // phone or host
	Mode       string // auto, webrtc or wss
	ForceRelay bool
	UDPBlocked bool
	Fallback   time.Duration
	Bytes      int
	HTTPClient *http.Client
	// Signer is the device identity key; nil generates a software key.
	Signer attest.Signer
	// Expect fails the run if a different path wins.
	Expect string
}

// Run executes one attempt and returns its result.
func Run(c Config) Result {
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 90 * time.Second}
	}
	if c.Fallback == 0 {
		c.Fallback = connmgr.DefaultFallbackDelay
	}
	if c.LabID == "" {
		c.LabID = "default"
	}
	r := run(c.Server+"|"+c.LabID, c.Role, c.Mode, c.ForceRelay, c.UDPBlocked, c.Fallback, c.Bytes, c.HTTPClient, c.Signer)
	if r.OK && c.Expect != "" && r.Path != c.Expect {
		r.OK = false
		r.Error = fmt.Sprintf("expected path %s, got %s", c.Expect, r.Path)
	}
	return r
}

func run(server, role, mode string, forceRelay, udpBlocked bool, fallback time.Duration, nbytes int, hc *http.Client, signer attest.Signer) Result {
	res := Result{Role: role}
	b, err := getBundle(server, role, hc)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sig, err := dialSignal(ctx, b, hc)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer sig.ws.CloseNow()

	// Lab-only identity exchange; production pins keys at pairing.
	if signer == nil {
		signer, _ = attest.NewSoftwareSigner()
	}
	res.Extra = map[string]string{"device_key_fp": attest.Fingerprint(signer.PublicKeySPKI())[:16]}
	sig.send(sigMsg{Kind: "pin", SPKI: base64.StdEncoding.EncodeToString(signer.PublicKeySPKI())})
	var peerKeyB64 string
	select {
	case peerKeyB64 = <-sig.pin:
	case <-ctx.Done():
		res.Error = "peer never published its key"
		return res
	}
	der, _ := base64.StdEncoding.DecodeString(peerKeyB64)
	peerKey, err := attest.ParsePublicKey(der)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	self, other := b.PhoneDevice, b.HostDevice
	prole := peer.RolePhone
	if role == "host" {
		self, other, prole = b.HostDevice, b.PhoneDevice, peer.RoleHost
	}
	tkPub, _ := base64.StdEncoding.DecodeString(b.TicketKey)
	keys := token.KeySet{"lab-1": ed25519.PublicKey(tkPub)}
	params := peer.Params{
		Role: prole, Self: self, Peer: other, Attempt: b.AttemptID, Nonce: b.Nonce, Cap: "terminal",
		Signer: signer, PeerKey: peerKey, Impl: "prw-labpeer",
	}
	if role == "phone" {
		params.Ticket = b.Ticket
	} else {
		params.CheckTicket = func(tk string) ([]string, error) {
			var t token.Ticket
			if err := keys.Verify(tk, token.TypeTicket, time.Now(), &t); err != nil {
				return nil, err
			}
			if t.AUD != self || t.SUB != other || t.Att != b.AttemptID || t.Nonce != b.Nonce {
				return nil, errors.New("ticket does not match attempt")
			}
			return []string{t.Cap}, nil
		}
	}

	var ice []pionwebrtc.ICEServer
	for _, s := range b.ICEServers {
		ice = append(ice, pionwebrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	opts := connmgr.Options{
		FallbackDelay: fallback,
		UDPBlocked:    udpBlocked,
		Handshake: func(ctx context.Context, c transport.Conn) error {
			_, err := peer.Handshake(ctx, c, params)
			return err
		},
	}
	if mode == "auto" || mode == "webrtc" {
		opts.ICE = func(ctx context.Context) (transport.Conn, error) {
			p, err := webrtc.NewPeer(webrtc.Config{
				Offerer: role == "phone", ICEServers: ice, ForceRelay: forceRelay,
				OnSignal: func(s webrtc.Signal) { sig.send(sigMsg{Kind: "webrtc", Signal: &s}) },
			})
			if err != nil {
				return nil, err
			}
			sig.attach(p)
			if err := p.Start(); err != nil {
				p.Close()
				return nil, err
			}
			return p.Wait(ctx)
		}
	}
	if mode == "auto" || mode == "wss" {
		opts.WSS = func(ctx context.Context) (transport.Conn, error) {
			id, err := innertls.NewIdentity(b.AttemptID)
			if err != nil {
				return nil, err
			}
			sig.send(sigMsg{Kind: "tls_fp", FP: id.Fingerprint})
			var peerFP string
			select {
			case peerFP = <-sig.tlsFP:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			relayRole := token.RoleClient
			if role == "host" {
				relayRole = token.RoleServer
			}
			return wssrelay.Connect(ctx, wssrelay.Params{
				URL: b.RelayURL, AttemptID: b.AttemptID, Token: b.RelayToken, Role: relayRole, HTTPClient: hc,
			}, id, peerFP)
		}
	}
	if role == "host" {
		// The host answers whichever path the phone uses: it offers both at
		// once and commits to the one carrying the phone's path.select.
		opts.UDPBlocked = true
		opts.Controlled = true
	}

	start := time.Now()
	conn, rep, err := connmgr.Connect(ctx, opts)
	res.Report = rep
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() {
		// Bounded close: report the result even if teardown stalls.
		done := make(chan struct{})
		go func() { conn.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			fmt.Fprintln(os.Stderr, "warning: transport close took more than 3s")
		}
	}()
	res.Path = conn.Path()
	res.ConnectMS = time.Since(start).Milliseconds()
	if sp, ok := conn.(interface{ SelectedPair() string }); ok {
		res.Extra["ice_pair"] = sp.SelectedPair()
	}

	if role == "host" {
		err = hostEcho(conn)
	} else {
		res.RTTMS, res.MBps, err = phoneEcho(conn, nbytes)
		res.Bytes = nbytes
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	return res
}

// hostEcho answers pings and echoes INPUT as OUTPUT until CLOSE_STREAM.
func hostEcho(c transport.Conn) error {
	for {
		f, err := c.Recv()
		if err != nil {
			return err
		}
		switch f.Type {
		case frame.TypeControl:
			env, err := control.Decode(f)
			if err != nil {
				return err
			}
			if env.Type == control.TypePing {
				env.Type = control.TypePong
				out, _ := env.Frame()
				if err := c.Send(out); err != nil {
					return err
				}
			}
		case frame.TypeInput:
			if err := c.Send(&frame.Frame{Type: frame.TypeOutput, StreamID: f.StreamID, Seq: f.Seq, Payload: f.Payload}); err != nil {
				return err
			}
		case frame.TypeCloseStream:
			// Acknowledge so the phone knows every byte was echoed, then let
			// the phone close first so queued output is not cut off.
			if err := c.Send(&frame.Frame{Type: frame.TypeCloseStream, StreamID: f.StreamID, Flags: frame.FlagFIN}); err != nil {
				return err
			}
			done := make(chan struct{})
			go func() {
				for {
					if _, err := c.Recv(); err != nil {
						close(done)
						return
					}
				}
			}()
			select {
			case <-done:
			case <-time.After(30 * time.Second):
			}
			return nil
		}
	}
}

// phoneEcho measures RTT with control pings, then checks a bulk echo.
func phoneEcho(c transport.Conn, n int) (float64, float64, error) {
	var total time.Duration
	const pings = 5
	for i := 0; i < pings; i++ {
		env, _ := control.New(control.TypePing, map[string]int64{"t": time.Now().UnixNano()})
		f, _ := env.Frame()
		t0 := time.Now()
		if err := c.Send(f); err != nil {
			return 0, 0, err
		}
		r, err := c.Recv()
		if err != nil {
			return 0, 0, err
		}
		if e, err := control.Decode(r); err != nil || e.Type != control.TypePong {
			return 0, 0, fmt.Errorf("expected pong")
		}
		total += time.Since(t0)
	}
	data := make([]byte, n)
	_, _ = rand.Read(data)
	want := sha256.Sum256(data)
	t0 := time.Now()
	go func() {
		seq := uint32(0)
		for off := 0; off < n; off += frame.MaxPayload {
			end := min(off+frame.MaxPayload, n)
			if err := c.Send(&frame.Frame{Type: frame.TypeInput, StreamID: 1, Seq: seq, Payload: data[off:end]}); err != nil {
				return
			}
			seq++
		}
		_ = c.Send(&frame.Frame{Type: frame.TypeCloseStream, StreamID: 1, Flags: frame.FlagFIN})
	}()
	var got bytes.Buffer
	for {
		f, err := c.Recv()
		if err != nil {
			return 0, 0, fmt.Errorf("echo after %d bytes: %w", got.Len(), err)
		}
		if f.Type == frame.TypeCloseStream {
			break
		}
		got.Write(f.Payload)
	}
	el := time.Since(t0)
	if got.Len() != n || sha256.Sum256(got.Bytes()) != want {
		return 0, 0, fmt.Errorf("echo mismatch: %d of %d bytes", got.Len(), n)
	}
	rtt := float64(total.Microseconds()) / 1000 / pings
	mbps := float64(n) * 2 * 8 / el.Seconds() / 1e6
	return rtt, mbps, nil
}
