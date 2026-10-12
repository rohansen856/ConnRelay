// Package runtime is the long-running host agent: it keeps the control socket
// to the control plane, maintains the grant lease, answers connection
// attempts over WebRTC or the WSS relay, verifies the phone (ticket + lease +
// attestation) and serves terminal sessions on the verified transport.
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	pionwebrtc "github.com/pion/webrtc/v4"
	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/agents/host/internal/lease"
	"github.com/rohansen856/connrelay/agents/host/internal/termserver"
	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
	"github.com/rohansen856/connrelay/core/connrelaycore/connmgr"
	"github.com/rohansen856/connrelay/core/connrelaycore/control"
	"github.com/rohansen856/connrelay/core/connrelaycore/peer"
	"github.com/rohansen856/connrelay/core/connrelaycore/token"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport/innertls"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport/webrtc"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport/wssrelay"
)

// Version is the agent version reported to the control plane.
var Version = "0.1.0"

// Timings.
const (
	Heartbeat = 25 * time.Second
	// SilenceLimit: the server acknowledges every heartbeat, so hearing
	// nothing for this long means the socket is dead even if writes still
	// "succeed" (half-open TCP through a NAT remap or a proxy).
	SilenceLimit  = 3 * Heartbeat
	MaxPeers      = 8
	ConnectWindow = 30 * time.Second
)

// ErrRevoked is returned by Run when the control plane revoked this host.
var ErrRevoked = errors.New("this computer was removed from the account")

// Agent is the runtime.
type Agent struct {
	State *agentcfg.State
	Key   *attest.SoftwareSigner
	Terms *termserver.Server
	Log   *slog.Logger
	HTTP  *http.Client
	// IncludeLoopback exists for tests.
	IncludeLoopback bool
	// Silence overrides SilenceLimit (tests).
	Silence time.Duration

	keys  token.KeySet
	lease *lease.Cache

	wmu sync.Mutex
	ws  *websocket.Conn

	mu       sync.Mutex
	attempts map[string]chan signal // attempt ID -> inbound signals
	peers    map[string]map[transport.Conn]bool
	seenJTI  map[string]time.Time
}

type signal struct {
	Kind    string
	Payload json.RawMessage
}

type msg struct {
	Type      string          `json:"type"`
	AttemptID string          `json:"attempt_id,omitempty"`
	Kind      string          `json:"kind,omitempty"`
	From      string          `json:"from_device_id,omitempty"`
	Nonce     string          `json:"nonce,omitempty"`
	Code      string          `json:"code,omitempty"`
	Lease     string          `json:"lease,omitempty"`
	Scope     string          `json:"scope,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func (a *Agent) silenceLimit() time.Duration {
	if a.Silence > 0 {
		return a.Silence
	}
	return SilenceLimit
}

// Run keeps the agent connected until ctx ends or the host is revoked.
func (a *Agent) Run(ctx context.Context) error {
	if a.Log == nil {
		a.Log = slog.Default()
	}
	ks, err := lease.KeySet(a.State.JWKS)
	if err != nil {
		return err
	}
	a.keys = ks
	a.lease = lease.New(a.State.DeviceID, ks, nil)
	a.attempts = map[string]chan signal{}
	a.peers = map[string]map[transport.Conn]bool{}
	a.seenJTI = map[string]time.Time{}
	go a.watchLease(ctx)

	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		if errors.Is(err, ErrRevoked) {
			a.closeAll("device_revoked")
			return err
		}
		if ctx.Err() != nil {
			break
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		wait := backoff/2 + time.Duration(rand.Int64N(int64(backoff)))
		a.Log.Warn("control connection lost; reconnecting", "err", err, "in", wait.Round(time.Millisecond))
		select {
		case <-time.After(wait):
		case <-ctx.Done():
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	a.closeAll("agent_stopping")
	return ctx.Err()
}

func (a *Agent) send(ctx context.Context, m any) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	a.wmu.Lock()
	defer a.wmu.Unlock()
	if a.ws == nil {
		return errors.New("control socket down")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return a.ws.Write(ctx, websocket.MessageText, b)
}

// session runs one control-socket connection.
func (a *Agent) session(ctx context.Context) error {
	ws, _, err := websocket.Dial(ctx, a.State.ControlWS, &websocket.DialOptions{Subprotocols: []string{"connrelay.v1"}, HTTPClient: a.HTTP})
	if err != nil {
		return err
	}
	ws.SetReadLimit(64 << 10)
	defer ws.CloseNow()
	read := func() (msg, error) {
		rctx, cancel := context.WithTimeout(ctx, a.silenceLimit())
		defer cancel()
		_, b, err := ws.Read(rctx)
		if err != nil && rctx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
			return msg{}, errors.New("control socket silent; reconnecting")
		}
		if err != nil {
			if websocket.CloseStatus(err) == 4403 {
				return msg{}, ErrRevoked
			}
			return msg{}, err
		}
		var m msg
		return m, json.Unmarshal(b, &m)
	}
	ch, err := read()
	if err != nil || ch.Type != "auth.challenge" {
		return fmt.Errorf("expected auth.challenge: %v", err)
	}
	sig, err := attest.SignPoP(a.Key, attest.PoP{Purpose: attest.PurposeAgent, Nonce: ch.Nonce, DeviceID: a.State.DeviceID}, time.Now())
	if err != nil {
		return err
	}
	a.wmu.Lock()
	a.ws = ws
	a.wmu.Unlock()
	defer func() { a.wmu.Lock(); a.ws = nil; a.wmu.Unlock() }()
	if err := a.send(ctx, map[string]any{"type": "auth.response", "payload": map[string]string{
		"device_id": a.State.DeviceID, "sig": sig, "agent_version": Version}}); err != nil {
		return err
	}
	ok, err := read()
	if err != nil {
		return err
	}
	if ok.Type == "auth.error" {
		if ok.Code == "device_revoked" {
			return ErrRevoked
		}
		return fmt.Errorf("authentication failed: %s", ok.Code)
	}
	if ok.Type != "auth.ok" {
		return fmt.Errorf("unexpected %s", ok.Type)
	}
	a.Log.Info("connected to control plane", "device_id", a.State.DeviceID)

	hctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		t := time.NewTicker(Heartbeat)
		defer t.Stop()
		for {
			a.heartbeat(hctx)
			select {
			case <-t.C:
			case <-hctx.Done():
				return
			}
		}
	}()

	for {
		m, err := read()
		if err != nil {
			return err
		}
		switch m.Type {
		case "grant.lease":
			dropped, err := a.lease.Apply(m.Lease)
			if err != nil {
				a.Log.Warn("rejected lease", "err", err)
				continue
			}
			for _, p := range dropped {
				a.closePhone(p, "access_revoked")
			}
		case "revoke_notice":
			a.revokeNotice(m)
		case "attempt.incoming":
			// Register the attempt before reading further: the phone's first
			// signals follow this message on the same ordered socket.
			var hdr struct {
				AttemptID string `json:"attempt_id"`
			}
			if json.Unmarshal(m.Payload, &hdr) != nil || hdr.AttemptID == "" {
				continue
			}
			sigs := make(chan signal, 128)
			a.mu.Lock()
			a.attempts[hdr.AttemptID] = sigs
			a.mu.Unlock()
			go a.handleAttempt(ctx, m.Payload, sigs)
		case "attempt.cancel":
			a.endAttempt(m.AttemptID)
		case "signal":
			a.mu.Lock()
			ch := a.attempts[m.AttemptID]
			a.mu.Unlock()
			if ch != nil {
				select {
				case ch <- signal{Kind: m.Kind, Payload: m.Payload}:
				default: // a misbehaving peer cannot block the control loop
				}
			}
		case "heartbeat.ack", "jwks.update", "server.notice", "pairing.approved":
		default:
			a.Log.Warn("dropped message outside the allowlist", "type", m.Type)
		}
	}
}

func (a *Agent) heartbeat(ctx context.Context) {
	a.mu.Lock()
	n := 0
	for _, ps := range a.peers {
		n += len(ps)
	}
	a.mu.Unlock()
	_ = a.send(ctx, map[string]any{"type": "heartbeat", "payload": map[string]any{
		"agent_version": Version, "capabilities": map[string]any{"tmux": a.Terms != nil, "peers": n}}})
}

func (a *Agent) revokeNotice(m msg) {
	var p struct {
		Phone    string `json:"phone_device_id"`
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(m.Payload, &p)
	switch {
	case p.Phone != "":
		a.lease.Remove(p.Phone)
		a.closePhone(p.Phone, "access_revoked")
	case p.DeviceID != "" && p.DeviceID != a.State.DeviceID:
		a.lease.Remove(p.DeviceID)
		a.closePhone(p.DeviceID, "access_revoked")
	}
}

// watchLease closes every peer once the lease has expired.
func (a *Agent) watchLease(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if !a.lease.Valid() {
				a.closeAll("lease_expired")
			}
		case <-ctx.Done():
			return
		}
	}
}

// ---- peers ----

func (a *Agent) addPeer(phone string, c transport.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, ps := range a.peers {
		n += len(ps)
	}
	if n >= MaxPeers {
		return false
	}
	if a.peers[phone] == nil {
		a.peers[phone] = map[transport.Conn]bool{}
	}
	a.peers[phone][c] = true
	return true
}

func (a *Agent) removePeer(phone string, c transport.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.peers[phone], c)
	if len(a.peers[phone]) == 0 {
		delete(a.peers, phone)
	}
}

// closePhone ends every transport of a phone. Its tmux sessions keep running
// (detached), as the protocol requires.
func (a *Agent) closePhone(phone, reason string) {
	a.mu.Lock()
	var conns []transport.Conn
	for c := range a.peers[phone] {
		conns = append(conns, c)
	}
	a.mu.Unlock()
	for _, c := range conns {
		if env, err := control.New(control.TypeSessionRevoked, map[string]string{"reason": reason}); err == nil {
			if f, err := env.Frame(); err == nil {
				_ = c.Send(f)
			}
		}
		c.Close()
	}
	if len(conns) > 0 {
		a.Log.Info("closed peer connections", "phone_device_id", phone, "reason", reason, "count", len(conns))
	}
}

func (a *Agent) closeAll(reason string) {
	a.mu.Lock()
	var phones []string
	for p := range a.peers {
		phones = append(phones, p)
	}
	a.mu.Unlock()
	for _, p := range phones {
		a.closePhone(p, reason)
	}
}

// ---- attempts ----

type incoming struct {
	AttemptID string `json:"attempt_id"`
	Phone     string `json:"phone_device_id"`
	Ticket    string `json:"ticket"`
	Relay     struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	} `json:"relay"`
	ICE []struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username"`
		Credential string   `json:"credential"`
	} `json:"ice_servers"`
}

func (a *Agent) endAttempt(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.attempts, id)
}

// verifyTicket checks the ticket and claims its jti (single use).
func (a *Agent) verifyTicket(raw string) (*token.Ticket, error) {
	var t token.Ticket
	if err := a.keys.Verify(raw, token.TypeTicket, time.Now(), &t); err != nil {
		return nil, err
	}
	if t.AUD != a.State.DeviceID || t.PV != 1 {
		return nil, errors.New("ticket not for this host")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for j, exp := range a.seenJTI {
		if now.After(exp.Add(token.ClockSkew)) {
			delete(a.seenJTI, j)
		}
	}
	if _, used := a.seenJTI[t.JTI]; used {
		return nil, errors.New("ticket already used")
	}
	a.seenJTI[t.JTI] = time.Unix(t.EXP, 0)
	return &t, nil
}

func (a *Agent) status(ctx context.Context, attempt, status, path, failure string) {
	_ = a.send(ctx, map[string]any{"type": "attempt.status", "attempt_id": attempt,
		"payload": map[string]string{"status": status, "path_type": path, "failure_code": failure}})
}

func (a *Agent) handleAttempt(ctx context.Context, raw json.RawMessage, sigs chan signal) {
	var in incoming
	if err := json.Unmarshal(raw, &in); err != nil {
		return
	}
	defer a.endAttempt(in.AttemptID)
	// Check the ticket now (it was minted for this host), but only consume
	// it when the phone presents it during attestation.
	var t token.Ticket
	if err := a.keys.Verify(in.Ticket, token.TypeTicket, time.Now(), &t); err != nil || t.AUD != a.State.DeviceID || t.SUB != in.Phone || t.Att != in.AttemptID {
		a.status(ctx, in.AttemptID, "failed", "", "ticket_invalid")
		return
	}
	ph, err := a.lease.Lookup(in.Phone, t.Cap)
	if err != nil {
		a.status(ctx, in.AttemptID, "failed", "", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(ctx, ConnectWindow)
	defer cancel()

	sendSig := func(kind string, payload any) {
		_ = a.send(ctx, map[string]any{"type": "signal", "attempt_id": in.AttemptID, "kind": kind, "payload": payload})
	}

	// Fan inbound signals out to the transport that needs them.
	var pmu sync.Mutex
	var rtc *webrtc.Peer
	var pending []webrtc.Signal
	tlsFP := make(chan string, 1)
	go func() {
		for {
			select {
			case s := <-sigs:
				switch s.Kind {
				case "tls_fingerprint":
					var p struct {
						SHA256 string `json:"sha256"`
					}
					if json.Unmarshal(s.Payload, &p) == nil {
						select {
						case tlsFP <- p.SHA256:
						default:
						}
					}
				case "attempt_cancel":
					cancel()
				default:
					var w webrtc.Signal
					if json.Unmarshal(s.Payload, &w) != nil {
						continue
					}
					w.Type = s.Kind
					pmu.Lock()
					if rtc == nil {
						pending = append(pending, w)
					} else {
						_ = rtc.HandleSignal(w)
					}
					pmu.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	var ice []pionwebrtc.ICEServer
	for _, s := range in.ICE {
		ice = append(ice, pionwebrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	opts := connmgr.Options{
		Controlled: true,
		UDPBlocked: true, // offer both paths at once; the phone chooses
		Timeout:    ConnectWindow,
		ICE: func(ctx context.Context) (transport.Conn, error) {
			p, err := webrtc.NewPeer(webrtc.Config{ICEServers: ice, IncludeLoopback: a.IncludeLoopback,
				OnSignal: func(s webrtc.Signal) { sendSig(s.Type, s) }})
			if err != nil {
				return nil, err
			}
			pmu.Lock()
			rtc = p
			for _, s := range pending {
				_ = p.HandleSignal(s)
			}
			pending = nil
			pmu.Unlock()
			c, err := p.Wait(ctx)
			if err != nil {
				p.Close()
			}
			return c, err
		},
		WSS: func(ctx context.Context) (transport.Conn, error) {
			id, err := innertls.NewIdentity(in.AttemptID)
			if err != nil {
				return nil, err
			}
			sendSig("tls_fingerprint", map[string]string{"sha256": id.Fingerprint})
			var fp string
			select {
			case fp = <-tlsFP:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return wssrelay.Connect(ctx, wssrelay.Params{URL: in.Relay.URL, AttemptID: in.AttemptID, Token: in.Relay.Token,
				Role: token.RoleServer, HTTPClient: a.HTTP}, id, fp)
		},
		Handshake: func(ctx context.Context, c transport.Conn) error {
			_, err := peer.Handshake(ctx, c, peer.Params{
				Role: peer.RoleHost, Self: a.State.DeviceID, Peer: in.Phone, Attempt: in.AttemptID, Nonce: t.Nonce,
				Cap: t.Cap, Signer: a.Key, PeerKey: ph.Key, Impl: "connrelay-agent/" + Version,
				CheckTicket: func(presented string) ([]string, error) {
					if presented != in.Ticket {
						return nil, errors.New("ticket mismatch")
					}
					if _, err := a.verifyTicket(presented); err != nil {
						return nil, err
					}
					// Re-check the lease at the moment of use.
					if _, err := a.lease.Lookup(in.Phone, t.Cap); err != nil {
						return nil, err
					}
					return []string{t.Cap}, nil
				},
			})
			return err
		},
	}
	conn, rep, err := connmgr.Connect(ctx, opts)
	if err != nil {
		code := "connect_timeout"
		if errors.Is(err, peer.ErrIdentity) {
			code = "peer_identity_mismatch"
		}
		a.Log.Warn("connection attempt failed", "attempt_id", in.AttemptID, "err", err)
		a.status(context.Background(), in.AttemptID, "failed", "", code)
		return
	}
	status := map[string]string{transport.PathDirect: "connected_direct", transport.PathTURN: "connected_relay", transport.PathWSSRelay: "connected_wss"}[rep.Path]
	pathType := map[string]string{transport.PathDirect: "direct", transport.PathTURN: "turn_udp", transport.PathWSSRelay: "wss_relay"}[rep.Path]
	if !a.addPeer(in.Phone, conn) {
		conn.Close()
		a.status(context.Background(), in.AttemptID, "failed", "", "host_capacity_reached")
		return
	}
	a.status(context.Background(), in.AttemptID, status, pathType, "")
	a.Log.Info("phone connected", "attempt_id", in.AttemptID, "phone_device_id", in.Phone, "path", rep.Path)
	cancel() // the connect window no longer applies
	defer a.removePeer(in.Phone, conn)
	if a.Terms == nil {
		conn.Close()
		return
	}
	_ = a.Terms.Serve(context.Background(), conn)
	conn.Close()
	a.status(context.Background(), in.AttemptID, "ended", pathType, "")
}
