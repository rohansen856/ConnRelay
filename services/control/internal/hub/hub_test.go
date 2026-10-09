package hub_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/services/control/internal/apitest"
	"github.com/rohansen856/connrelay/services/control/internal/connections"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/hub"
	"github.com/rohansen856/connrelay/services/control/internal/inventory"
	"github.com/rohansen856/connrelay/services/control/internal/outbox"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

type env struct {
	*apitest.Env
	hub    *hub.Hub
	conns  *connections.Service
	worker *outbox.Worker
	keys   token.KeySet
}

func setup(t *testing.T) *env {
	e := &env{Env: apitest.New(t)}
	e.keys = token.KeySet{e.TicketKey.KID: e.TicketPub}
	e.hub = &hub.Hub{Store: e.Store, Auth: e.Auth, Ticket: e.TicketKey, JWKS: func() any { return map[string]any{"keys": []any{}} }}
	e.conns = &connections.Service{Store: e.Store, Auth: e.Auth, Hub: e.hub, Ticket: e.TicketKey, ISS: "https://api.test.invalid",
		TURNSecret: []byte("TEST-ONLY"), STUNURLs: []string{"stun:turn.test.invalid:3478"},
		TURNURLs: []string{"turn:turn.test.invalid:3478?transport=udp"}, RelayURL: "wss://api.test.invalid/v1/relay",
		SignalingURL: "wss://api.test.invalid/v1/signaling"}
	e.hub.OnAttemptStatus = e.conns.AgentStatus
	e.worker = &outbox.Worker{Store: e.Store, Hub: e.hub, Interval: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go e.worker.Run(ctx)
	e.Mux.HandleFunc("GET /v1/agent/control", e.hub.ServeAgent)
	e.Mux.HandleFunc("GET /v1/signaling", e.hub.ServePhone)
	e.conns.Routes(e.Mux)
	(&inventory.Service{Store: e.Store, Auth: e.Auth, Live: e.hub, Notify: e.worker}).Routes(e.Mux)
	return e
}

func (e *env) wsURL(path string) string {
	return "ws" + strings.TrimPrefix(e.Server.URL, "http") + path
}

// client is a JSON WebSocket client with a background reader.
type client struct {
	t  *testing.T
	ws *websocket.Conn
	in chan map[string]any
}

func (e *env) dial(path string) *client {
	e.T.Helper()
	ws, _, err := websocket.Dial(context.Background(), e.wsURL(path), &websocket.DialOptions{Subprotocols: []string{hub.SubProtocol}})
	if err != nil {
		e.T.Fatal(err)
	}
	c := &client{t: e.T.(*testing.T), ws: ws, in: make(chan map[string]any, 64)}
	go func() {
		defer close(c.in)
		for {
			_, b, err := ws.Read(context.Background())
			if err != nil {
				return
			}
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			c.in <- m
		}
	}()
	e.T.Cleanup(func() { ws.CloseNow() })
	return c
}

func (c *client) send(m any) {
	b, _ := json.Marshal(m)
	if err := c.ws.Write(context.Background(), websocket.MessageText, b); err != nil {
		c.t.Fatal(err)
	}
}

// expect waits for a message of the given type; returns nil if the socket closed.
func (c *client) expect(typ string) map[string]any {
	c.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-c.in:
			if !ok {
				return nil
			}
			if m["type"] == typ {
				return m
			}
		case <-timeout:
			c.t.Fatalf("timeout waiting for %s", typ)
		}
	}
}

func (c *client) closed() bool {
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-c.in:
			if !ok {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

// agent logs a host in over /v1/agent/control.
func (e *env) agent(h *apitest.Host, signer *attest.SoftwareSigner) *client {
	c := e.dial("/v1/agent/control")
	ch := c.expect("auth.challenge")
	sig, _ := attest.SignPoP(signer, attest.PoP{Purpose: attest.PurposeAgent, Nonce: ch["nonce"].(string), DeviceID: h.ID.String()}, time.Now())
	c.send(map[string]any{"type": "auth.response", "payload": map[string]string{"device_id": h.ID.String(), "sig": sig, "agent_version": "0.1.0"}})
	return c
}

func (e *env) lease(t *testing.T, c *client) token.Lease {
	m := c.expect("grant.lease")
	if m == nil {
		t.Fatal("no lease")
	}
	var l token.Lease
	if err := e.keys.Verify(m["lease"].(string), token.TypeLease, time.Now(), &l); err != nil {
		t.Fatalf("lease signature: %v", err)
	}
	return l
}

func grant(t *testing.T, p *apitest.Phone, h *apitest.Host) map[string]any {
	r := p.Do("POST", "/v1/access-grants", map[string]any{"phone_device_id": p.ID, "host_device_id": h.ID, "capabilities": []string{"terminal"}})
	if r.Status != 201 {
		t.Fatalf("grant: %v", r.Body)
	}
	r.Body["_version"] = r.Version()
	return r.Body
}

var idem = 0

func connect(p *apitest.Phone, h *apitest.Host) apitest.Resp {
	idem++
	return p.Do("POST", "/v1/connections", map[string]any{"host_device_id": h.ID, "capability": "terminal"},
		"Idempotency-Key", fmt.Sprintf("idem-key-%08d-%d", idem, time.Now().UnixNano()))
}

func TestAgentLoginLeaseAndPresence(t *testing.T) {
	e := setup(t)
	p := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")
	grant(t, p, h)

	impostor, _ := attest.NewSoftwareSigner()
	bad := e.agent(h, impostor)
	if !bad.closed() {
		t.Fatal("agent with the wrong key stayed connected")
	}

	a := e.agent(h, h.Key)
	ok := a.expect("auth.ok")
	if ok == nil || ok["device_id"] != h.ID.String() {
		t.Fatalf("auth.ok %v", ok)
	}
	l := e.lease(t, a)
	if len(l.Grants) != 1 || l.Grants[0].PhoneDeviceID != p.ID.String() ||
		l.Grants[0].PhoneKeySPKI != base64.RawURLEncoding.EncodeToString(p.Key.PublicKeySPKI()) {
		t.Fatalf("lease %+v", l)
	}
	a.send(map[string]any{"type": "heartbeat", "payload": map[string]any{"agent_version": "0.1.1", "capabilities": map[string]any{"tmux": true}}})
	a.expect("heartbeat.ack")
	dev := p.Do("GET", "/v1/devices/"+h.ID.String(), nil)
	if dev.Body["presence"] != "online" || dev.Body["software_version"] != "0.1.1" {
		t.Fatalf("presence/version: %v", dev.Body)
	}
}

func TestConnectionAttemptEndToEnd(t *testing.T) {
	e := setup(t)
	p := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")

	if r := connect(p, h); r.Code() != "access_grant_missing" {
		t.Fatalf("no grant: %v", r.Body)
	}
	grant(t, p, h)
	if r := connect(p, h); r.Code() != "agent_offline" {
		t.Fatalf("offline host: %v", r.Body)
	}
	a := e.agent(h, h.Key)
	a.expect("auth.ok")

	r := connect(p, h)
	if r.Status != 201 {
		t.Fatalf("connect: %d %v", r.Status, r.Body)
	}
	att := r.Body["connection_attempt_id"].(string)
	in := a.expect("attempt.incoming")
	pl := in["payload"].(map[string]any)
	if pl["attempt_id"] != att || pl["ticket"] != r.Body["ticket"] {
		t.Fatalf("incoming %v", in)
	}
	// The host can verify the ticket with the pinned key; it is bound to this pair.
	var tk token.Ticket
	if err := e.keys.Verify(pl["ticket"].(string), token.TypeTicket, time.Now(), &tk); err != nil {
		t.Fatal(err)
	}
	if tk.AUD != h.ID.String() || tk.SUB != p.ID.String() || tk.Att != att || tk.Nonce != r.Body["attestation_nonce"] {
		t.Fatalf("ticket claims %+v", tk)
	}
	var rt token.Relay
	if err := e.keys.Verify(r.Body["relay"].(map[string]any)["token"].(string), token.TypeRelay, time.Now(), &rt); err != nil || rt.Role != "client" {
		t.Fatalf("relay token %+v %v", rt, err)
	}
	ice := r.Body["ice_servers"].([]any)
	if len(ice) != 2 || !strings.HasSuffix(ice[1].(map[string]any)["username"].(string), ":"+att) {
		t.Fatalf("ice servers %v", ice)
	}

	// Signaling flows both ways, with the sender stamped by the server.
	ph := e.dial("/v1/signaling")
	ph.send(map[string]any{"type": "auth", "payload": map[string]string{"access_token": p.Access}})
	ph.expect("auth.ok")
	ph.send(map[string]any{"type": "signal", "attempt_id": att, "kind": "offer", "from_device_id": "spoofed", "payload": map[string]string{"sdp": "v=0"}})
	got := a.expect("signal")
	if got["kind"] != "offer" || got["from_device_id"] != p.ID.String() {
		t.Fatalf("host got %v", got)
	}
	a.send(map[string]any{"type": "signal", "attempt_id": att, "kind": "answer", "payload": map[string]string{"sdp": "v=0"}})
	if back := ph.expect("signal"); back["kind"] != "answer" || back["from_device_id"] != h.ID.String() {
		t.Fatalf("phone got %v", back)
	}

	// Status reports move the state machine.
	a.send(map[string]any{"type": "attempt.status", "attempt_id": att, "payload": map[string]string{"status": "connected_direct", "path_type": "direct"}})
	time.Sleep(200 * time.Millisecond)
	if st := p.Do("GET", "/v1/connections/"+att, nil); st.Body["status"] != "connected_direct" || st.Body["path_type"] != "direct" {
		t.Fatalf("status %v", st.Body)
	}
	if st := p.Do("PATCH", "/v1/connections/"+att, map[string]string{"status": "connected_relay"}); st.Code() != "invalid_transition" {
		t.Fatalf("connected -> other connected: %v", st.Body)
	}
	if st := p.Do("PATCH", "/v1/connections/"+att, map[string]string{"status": "canceled"}); st.Status != 200 {
		t.Fatalf("cancel: %v", st.Body)
	}
	a.expect("attempt.cancel")
	if st := p.Do("POST", "/v1/connections/"+att+"/turn-credentials", nil); st.Code() != "attempt_not_live" {
		t.Fatalf("TURN creds after cancel: %v", st.Body)
	}
}

func TestSignalingIsolation(t *testing.T) {
	e := setup(t)
	p := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")
	other := e.AddHost(p.Account, "other")
	grant(t, p, h)
	a := e.agent(h, h.Key)
	a.expect("auth.ok")
	o := e.agent(other, other.Key)
	o.expect("auth.ok")
	att := connect(p, h).Body["connection_attempt_id"].(string)
	a.expect("attempt.incoming")

	// Another host cannot inject signaling into this attempt.
	o.send(map[string]any{"type": "signal", "attempt_id": att, "kind": "answer", "payload": map[string]string{"sdp": "evil"}})
	ph := e.dial("/v1/signaling")
	ph.send(map[string]any{"type": "auth", "payload": map[string]string{"access_token": p.Access}})
	ph.expect("auth.ok")
	select {
	case m := <-ph.in:
		if m["type"] == "signal" {
			t.Fatalf("foreign host's signal delivered: %v", m)
		}
	case <-time.After(300 * time.Millisecond):
	}
	// Unauthenticated signaling sockets are closed.
	anon := e.dial("/v1/signaling")
	anon.send(map[string]any{"type": "auth", "payload": map[string]string{"access_token": "nope"}})
	if !anon.closed() {
		t.Fatal("unauthenticated signaling socket stayed open")
	}
}

func TestIdempotentRetry(t *testing.T) {
	e := setup(t)
	p := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")
	grant(t, p, h)
	a := e.agent(h, h.Key)
	a.expect("auth.ok")
	body := map[string]any{"host_device_id": h.ID, "capability": "terminal"}
	r1 := p.Do("POST", "/v1/connections", body, "Idempotency-Key", "same-key-0123456789")
	r2 := p.Do("POST", "/v1/connections", body, "Idempotency-Key", "same-key-0123456789")
	if r1.Status != 201 || r2.Status != 201 || r1.Body["connection_attempt_id"] != r2.Body["connection_attempt_id"] ||
		r1.Body["attestation_nonce"] != r2.Body["attestation_nonce"] {
		t.Fatalf("retry: %v / %v", r1.Body, r2.Body)
	}
	if r := p.Do("POST", "/v1/connections", body, "Idempotency-Key", "short"); r.Code() != "validation_failed" {
		t.Fatalf("short key: %v", r.Body)
	}
}

func TestRevocationReachesAgent(t *testing.T) {
	e := setup(t)
	p := e.SignIn("owner")
	p2 := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")
	g := grant(t, p, h)
	grant(t, p2, h)
	a := e.agent(h, h.Key)
	a.expect("auth.ok")
	if l := e.lease(t, a); len(l.Grants) != 2 {
		t.Fatalf("initial lease %d grants", len(l.Grants))
	}

	// Revoke one grant: the host gets a fresh lease and a notice.
	r := p.Do("POST", "/v1/access-grants/"+g["id"].(string)+"/revoke", nil, "If-Match", fmt.Sprintf(`"%d"`, g["_version"].(int)))
	if r.Status != 200 {
		t.Fatalf("revoke grant: %v", r.Body)
	}
	if l := e.lease(t, a); len(l.Grants) != 1 || l.Grants[0].PhoneDeviceID != p2.ID.String() {
		t.Fatalf("lease after grant revoke %+v", l)
	}
	a.expect("revoke_notice")
	if r := connect(p, h); r.Code() != "access_grant_missing" {
		t.Fatalf("connect after revoke: %v", r.Body)
	}

	// Revoke the host itself: its control socket is closed and it cannot log in.
	v := p.Do("GET", "/v1/devices/"+h.ID.String(), nil).Version()
	if r := p.Do("POST", "/v1/devices/"+h.ID.String()+"/revoke", map[string]string{"reason": "compromised"}, "If-Match", fmt.Sprintf(`"%d"`, v)); r.Status != 200 {
		t.Fatalf("revoke host: %v", r.Body)
	}
	if !a.closed() {
		t.Fatal("revoked host's control socket stayed open")
	}
	again := e.agent(h, h.Key)
	if m := again.expect("auth.error"); m == nil || m["code"] != "device_revoked" {
		t.Fatalf("revoked host login: %v", m)
	}
}

func TestSilentAgentIsDropped(t *testing.T) {
	e := setup(t)
	e.hub.Silence = 400 * time.Millisecond
	p := e.SignIn("owner")
	h := e.AddHost(p.Account, "box")
	a := e.agent(h, h.Key)
	a.expect("auth.ok")
	if !e.hub.Connected(h.ID) {
		t.Fatal("not connected after login")
	}
	// The agent goes quiet (half-open socket): the server must give up on it.
	if !a.closed() {
		t.Fatal("silent agent socket stayed open")
	}
	for i := 0; e.hub.Connected(h.ID); i++ {
		if i > 100 {
			t.Fatal("silent agent still counted as connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
