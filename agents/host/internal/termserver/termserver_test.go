package termserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/tmux"
	"github.com/rohansen856/connrelay/core/connrelaycore/control"
	"github.com/rohansen856/connrelay/core/connrelaycore/flow"
	"github.com/rohansen856/connrelay/core/connrelaycore/frame"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
)

func newServer(t *testing.T, max int) *Server {
	t.Helper()
	dir, _ := os.MkdirTemp("", "connrelayt")
	ts, err := tmux.New(filepath.Join(dir, "t.sock"))
	if errors.Is(err, tmux.ErrUnavailable) {
		t.Skip("tmux not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.KillServer(); os.RemoveAll(dir) })
	return New(Config{
		Tmux: ts, Shell: []string{"/bin/sh"}, Dir: "/", MaxSessions: max,
		Env: []string{"PATH=/usr/bin:/bin", "PS1=$ ", "HOME=/tmp"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// phone is a minimal test client speaking the control protocol.
type phone struct {
	t    *testing.T
	c    transport.Conn
	ctl  chan *control.Envelope
	mu   sync.Mutex
	out  map[uint16]*bytes.Buffer
	recv map[uint16]*flow.Receiver
	in   map[uint16]*flow.Sender
	done chan struct{}
}

func connect(t *testing.T, s *Server) *phone {
	t.Helper()
	pc, hc := transport.Pipe("p", "h", "h", "p")
	go s.Serve(context.Background(), hc)
	return newPhone(t, pc)
}

// newPhone wraps an established (already verified) transport.
func newPhone(t *testing.T, c transport.Conn) *phone {
	p := &phone{t: t, c: c, ctl: make(chan *control.Envelope, 64), out: map[uint16]*bytes.Buffer{},
		recv: map[uint16]*flow.Receiver{}, in: map[uint16]*flow.Sender{}, done: make(chan struct{})}
	go p.loop()
	return p
}

func (p *phone) loop() {
	defer close(p.done)
	for {
		f, err := p.c.Recv()
		if err != nil {
			return
		}
		switch f.Type {
		case frame.TypeControl:
			env, err := control.Decode(f)
			if err != nil {
				return
			}
			if env.Type == control.TypeTerminalReady {
				// Register stream state before handling anything that
				// follows (the host's input credit comes right after ready).
				p.register(env)
			}
			if env.Type == control.TypeFlowCredit {
				var fc control.FlowCredit
				_ = env.Unmarshal(&fc)
				p.mu.Lock()
				if s := p.in[fc.StreamID]; s != nil {
					_ = s.Grant(fc.Bytes)
				}
				p.mu.Unlock()
				continue
			}
			p.ctl <- env
		case frame.TypeOutput:
			p.mu.Lock()
			p.out[f.StreamID].Write(f.Payload)
			r := p.recv[f.StreamID]
			p.mu.Unlock()
			_ = r.Received(len(f.Payload))
			if g := r.Consumed(len(f.Payload)); g > 0 {
				p.send(control.TypeFlowCredit, control.FlowCredit{StreamID: f.StreamID, Bytes: g})
			}
		}
	}
}

func (p *phone) send(typ string, payload any) string {
	env, _ := control.New(typ, payload)
	f, _ := env.Frame()
	if err := p.c.Send(f); err != nil {
		p.t.Fatalf("send %s: %v", typ, err)
	}
	return env.RequestID
}

func (p *phone) sendWithID(typ, id string, payload any) {
	env, _ := control.New(typ, payload)
	env.RequestID = id
	f, _ := env.Frame()
	_ = p.c.Send(f)
}

func (p *phone) expect(typ string) *control.Envelope {
	p.t.Helper()
	for {
		select {
		case env := <-p.ctl:
			if env.Type == typ {
				return env
			}
			if env.Type == control.TypeTerminalError && typ != control.TypeTerminalError {
				p.t.Fatalf("got terminal.error %s while waiting for %s", env.Payload, typ)
			}
		case <-time.After(10 * time.Second):
			p.t.Fatalf("timeout waiting for %s", typ)
		}
	}
}

type ready struct {
	SessionID string `json:"terminal_session_id"`
	StreamID  uint16 `json:"stream_id"`
	Resumed   bool   `json:"resumed"`
}

// register creates flow state for a stream announced by terminal.ready. It
// runs on the receive loop so later frames for the stream find it.
func (p *phone) register(env *control.Envelope) {
	var r ready
	if json.Unmarshal(env.Payload, &r) != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.out[r.StreamID] = &bytes.Buffer{}
	p.recv[r.StreamID] = flow.NewReceiver(flow.DefaultOutputWindow)
	p.in[r.StreamID] = flow.NewSender(flow.DefaultInputWindow)
}

// stream grants output credit for a ready stream and returns its IDs.
func (p *phone) stream(env *control.Envelope) ready {
	p.t.Helper()
	var r ready
	if err := json.Unmarshal(env.Payload, &r); err != nil {
		p.t.Fatal(err)
	}
	p.mu.Lock()
	initial := p.recv[r.StreamID].Initial()
	p.mu.Unlock()
	p.send(control.TypeFlowCredit, control.FlowCredit{StreamID: r.StreamID, Bytes: initial})
	return r
}

func (p *phone) open(cols, rows int) ready {
	p.send(control.TypeTerminalOpen, map[string]any{"cols": cols, "rows": rows})
	return p.stream(p.expect(control.TypeTerminalReady))
}

func (p *phone) attach(id string) ready {
	p.send(control.TypeTerminalAttach, map[string]any{"terminal_session_id": id, "cols": 100, "rows": 30})
	return p.stream(p.expect(control.TypeTerminalReady))
}

func (p *phone) typeText(sid uint16, s string) {
	p.mu.Lock()
	snd := p.in[sid]
	p.mu.Unlock()
	b := []byte(s)
	for len(b) > 0 {
		n, err := snd.Acquire(context.Background(), len(b))
		if err != nil {
			p.t.Fatal(err)
		}
		if err := p.c.Send(&frame.Frame{Type: frame.TypeInput, StreamID: sid, Payload: b[:n]}); err != nil {
			p.t.Fatal(err)
		}
		b = b[n:]
	}
}

func (p *phone) waitOutput(sid uint16, re *regexp.Regexp) []string {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		m := re.FindStringSubmatch(p.out[sid].String())
		p.mu.Unlock()
		if m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.t.Fatalf("output never matched %s; got %q", re, p.out[sid].String())
	return nil
}

func (p *phone) drop() {
	p.c.Close()
	<-p.done
}

// TestReconnectReattachesSameShell is the Phase 1 "reconnect to an existing
// terminal session" check over the real control protocol: the transport is
// dropped, a new one attaches by session ID, and the same shell (same PID,
// same variables) continues.
func TestReconnectReattachesSameShell(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	r := p.open(100, 30)
	if r.Resumed || r.SessionID == "" {
		t.Fatalf("open: %+v", r)
	}
	p.typeText(r.StreamID, "MARK=kept; echo PID=$$\r")
	pid := p.waitOutput(r.StreamID, regexp.MustCompile(`PID=(\d+)`))[1]
	p.typeText(r.StreamID, "echo BEFORE-DROP-$((40+2))\r")
	p.waitOutput(r.StreamID, regexp.MustCompile(`BEFORE-DROP-42`))
	p.drop() // phone loses the network

	// Process keeps running while nobody is attached.
	time.Sleep(300 * time.Millisecond)
	info, err := s.cfg.Tmux.Get(r.SessionID)
	if err != nil || info.Attached != 0 {
		t.Fatalf("session after drop: %+v %v", info, err)
	}

	q := connect(t, s)
	defer q.drop()
	r2 := q.attach(r.SessionID)
	if !r2.Resumed {
		t.Fatal("attach did not report resumed")
	}
	// tmux redraws the screen on attach: earlier output is visible again.
	q.waitOutput(r2.StreamID, regexp.MustCompile(`BEFORE-DROP-42`))
	q.typeText(r2.StreamID, "echo AGAIN=$$:$MARK\r")
	m := q.waitOutput(r2.StreamID, regexp.MustCompile(`AGAIN=(\d+):(\w+)`))
	if m[1] != pid || m[2] != "kept" {
		t.Fatalf("reattached to a different shell: pid %s vs %s, mark %q", m[1], pid, m[2])
	}
}

func TestResizeReachesShell(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	defer p.drop()
	r := p.open(100, 30)
	p.waitOutput(r.StreamID, regexp.MustCompile(`\$ `))
	p.send(control.TypeTerminalResize, map[string]any{"stream_id": r.StreamID, "cols": 132, "rows": 40})
	time.Sleep(200 * time.Millisecond)
	p.typeText(r.StreamID, "stty size\r")
	p.waitOutput(r.StreamID, regexp.MustCompile(`40 132`))
}

func TestTerminateAndList(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	defer p.drop()
	a := p.open(80, 24)
	b := p.open(80, 24)
	p.send(control.TypeTerminalList, nil)
	var list struct {
		Sessions []struct{ ID, Status string } `json:"sessions"`
	}
	_ = json.Unmarshal(p.expect(control.TypeTerminalListRes).Payload, &list)
	if len(list.Sessions) != 2 {
		t.Fatalf("list: %+v", list)
	}
	// Terminate requires explicit confirmation.
	p.send(control.TypeTerminalTerm, map[string]any{"terminal_session_id": a.SessionID})
	p.expect(control.TypeTerminalError)
	p.send(control.TypeTerminalTerm, map[string]any{"terminal_session_id": a.SessionID, "confirm": true})
	exit := p.expect(control.TypeTerminalExit)
	if exit.TerminalSessionID != a.SessionID {
		t.Fatalf("exit for %s", exit.TerminalSessionID)
	}
	if _, err := s.cfg.Tmux.Get(a.SessionID); !errors.Is(err, tmux.ErrNotFound) {
		t.Fatal("terminated session still exists")
	}
	if _, err := s.cfg.Tmux.Get(b.SessionID); err != nil {
		t.Fatal("other session affected")
	}
}

func TestShellExitReported(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	defer p.drop()
	r := p.open(80, 24)
	p.waitOutput(r.StreamID, regexp.MustCompile(`\$ `))
	p.typeText(r.StreamID, "exit\r")
	exit := p.expect(control.TypeTerminalExit)
	if exit.TerminalSessionID != r.SessionID {
		t.Fatalf("exit for %q", exit.TerminalSessionID)
	}
}

func TestAttachUnknownSession(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	defer p.drop()
	p.send(control.TypeTerminalAttach, map[string]any{"terminal_session_id": "doesnotexist", "cols": 80, "rows": 24})
	env := p.expect(control.TypeTerminalError)
	var e struct{ Code string }
	_ = json.Unmarshal(env.Payload, &e)
	if e.Code != ErrSessionNotFound {
		t.Fatalf("code %q", e.Code)
	}
}

func TestCapacity(t *testing.T) {
	s := newServer(t, 2)
	p := connect(t, s)
	defer p.drop()
	p.open(80, 24)
	p.open(80, 24)
	p.send(control.TypeTerminalOpen, map[string]any{"cols": 80, "rows": 24})
	env := p.expect(control.TypeTerminalError)
	var e struct{ Code string }
	_ = json.Unmarshal(env.Payload, &e)
	if e.Code != ErrCapacity {
		t.Fatalf("code %q", e.Code)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	defer p.drop()
	p.sendWithID(control.TypeTerminalOpen, "req-1", map[string]any{"cols": 80, "rows": 24})
	a := p.stream(p.expect(control.TypeTerminalReady))
	p.sendWithID(control.TypeTerminalOpen, "req-1", map[string]any{"cols": 80, "rows": 24})
	b := p.stream(p.expect(control.TypeTerminalReady))
	if a.SessionID != b.SessionID {
		t.Fatalf("retry created a second session: %s vs %s", a.SessionID, b.SessionID)
	}
	list, _ := s.cfg.Tmux.List()
	if len(list) != 1 {
		t.Fatalf("%d sessions", len(list))
	}
}

func TestInputForUnknownStreamClosesConnection(t *testing.T) {
	s := newServer(t, 20)
	p := connect(t, s)
	_ = p.c.Send(&frame.Frame{Type: frame.TypeInput, StreamID: 9, Payload: []byte("x")})
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		t.Fatal("server kept a connection that sent input for an unknown stream")
	}
}
