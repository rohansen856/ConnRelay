package termstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/ptyproc"
	"github.com/rohansen856/connrelay/agents/host/internal/tmux"
	"github.com/rohansen856/connrelay/core/prwcore/flow"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
)

// phone simulates a slow phone: it consumes frames, sleeps every few frames
// and re-grants credit the way the app does after rendering.
type phone struct {
	frames   chan *frame.Frame
	inflight atomic.Int64
	maxIn    atomic.Int64
}

func newPhone() *phone { return &phone{frames: make(chan *frame.Frame, 4096)} }

func (p *phone) sink(f *frame.Frame) error {
	c := *f
	c.Payload = append([]byte(nil), f.Payload...)
	if v := p.inflight.Add(int64(len(c.Payload))); v > p.maxIn.Load() {
		p.maxIn.Store(v)
	}
	p.frames <- &c
	return nil
}

// consume reads until CLOSE_STREAM (or until stop returns true) and returns
// everything received.
func (p *phone) consume(t *testing.T, s *Stream, slowEvery int, stop func([]byte) bool) []byte {
	t.Helper()
	r := flow.NewReceiver(flow.DefaultOutputWindow)
	if err := s.GrantOutput(r.Initial()); err != nil {
		t.Fatal(err)
	}
	var all bytes.Buffer
	for i := 0; ; i++ {
		select {
		case f := <-p.frames:
			if f.Type == frame.TypeCloseStream {
				return all.Bytes()
			}
			if err := r.Received(len(f.Payload)); err != nil {
				t.Fatalf("host sent beyond credit: %v", err)
			}
			all.Write(f.Payload)
			p.inflight.Add(-int64(len(f.Payload)))
			if slowEvery > 0 && i%slowEvery == 0 {
				time.Sleep(2 * time.Millisecond)
			}
			if g := r.Consumed(len(f.Payload)); g > 0 {
				if err := s.GrantOutput(g); err != nil {
					t.Fatal(err)
				}
			}
			if stop != nil && stop(all.Bytes()) {
				return all.Bytes()
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("stalled after %d bytes", all.Len())
		}
	}
}

func TestNoOutputWithoutCredit(t *testing.T) {
	p, err := ptyproc.Start([]string{"/bin/sh", "-c", "echo hello; sleep 2"}, nil, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)
	ph := newPhone()
	s := New(1, p, ph.sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	select {
	case f := <-ph.frames:
		t.Fatalf("frame sent without credit: %+v", f)
	case <-time.After(300 * time.Millisecond):
	}
	_ = s.GrantOutput(1024)
	select {
	case f := <-ph.frames:
		if !strings.Contains(string(f.Payload), "hello") {
			t.Fatalf("payload %q", f.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no output after credit")
	}
}

// TestRawBurst50MiB sends 50 MiB of random bytes through a raw PTY to a slow
// consumer: every byte must arrive intact and in-flight data must never
// exceed the 256 KiB window.
func TestRawBurst50MiB(t *testing.T) {
	if testing.Short() {
		t.Skip("50 MiB burst")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "burst.bin")
	data := make([]byte, 50<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(data)

	p, err := ptyproc.Start([]string{"/bin/sh", "-c", `stty raw -echo && printf R && exec cat "$1"`, "sh", src}, nil, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)
	ph := newPhone()
	s := New(1, p, ph.sink)
	go s.Run(context.Background())

	start := time.Now()
	got := ph.consume(t, s, 64, nil)
	if len(got) == 0 || got[0] != 'R' {
		t.Fatal("missing start marker")
	}
	got = got[1:]
	if len(got) != len(data) || sha256.Sum256(got) != want {
		t.Fatalf("received %d bytes, want %d (hash match %v)", len(got), len(data), sha256.Sum256(got) == want)
	}
	if m := ph.maxIn.Load(); m > flow.DefaultOutputWindow {
		t.Fatalf("in-flight peaked at %d > window %d", m, flow.DefaultOutputWindow)
	}
	t.Logf("50 MiB in %v, peak in-flight %d KiB", time.Since(start).Round(time.Millisecond), ph.maxIn.Load()/1024)
}

// TestTmuxBurst floods a tmux-backed session with ~14 MiB of output while the
// phone consumes slowly. tmux re-renders rather than forwarding raw bytes, so
// the check is that the final screen state arrives and memory stays bounded.
func TestTmuxBurst(t *testing.T) {
	dir, _ := os.MkdirTemp("", "prwt")
	defer os.RemoveAll(dir)
	srv, err := tmux.New(filepath.Join(dir, "t.sock"))
	if err != nil {
		t.Skip(err)
	}
	defer srv.KillServer()
	if err := srv.NewSession("burst", []string{"/bin/sh"}, "/", 120, 40); err != nil {
		t.Fatal(err)
	}
	p, err := ptyproc.Start(srv.AttachArgv("burst"), tmux.AttachEnv(os.Environ(), "xterm-256color"), "/", 120, 40)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)
	ph := newPhone()
	s := New(1, p, ph.sink)
	go s.Run(context.Background())

	// Queued immediately: the stream must hold it until tmux is ready.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunInput(ctx, nil)
	cmd := []byte("seq 1 2000000; echo BURST-$((20+22))-END\r")
	if int64(len(cmd)) > s.InitialInputCredit() {
		t.Fatal("command larger than input credit")
	}
	if err := s.Input(cmd); err != nil {
		t.Fatal(err)
	}
	got := ph.consume(t, s, 32, func(b []byte) bool { return bytes.Contains(b, []byte("BURST-42-END")) })
	if !bytes.Contains(got, []byte("BURST-42-END")) {
		t.Fatal("final output never arrived")
	}
	if m := ph.maxIn.Load(); m > flow.DefaultOutputWindow {
		t.Fatalf("in-flight peaked at %d", m)
	}
	t.Logf("tmux delivered %d KiB of rendered output for ~14 MiB produced", len(got)/1024)
}

func TestInputOverrunRejected(t *testing.T) {
	s := New(1, nopProc{}, func(*frame.Frame) error { return nil })
	s.InitialInputCredit()
	if err := s.Input(make([]byte, flow.DefaultInputWindow+1)); err != ErrInputOverrun {
		t.Fatalf("got %v", err)
	}
}

func TestInputHeldUntilReadyOrTimeout(t *testing.T) {
	old := ReadyTimeout
	ReadyTimeout = 400 * time.Millisecond
	defer func() { ReadyTimeout = old }()
	var wrote atomic.Bool
	s := New(1, &recProc{wrote: &wrote}, func(*frame.Frame) error { return nil })
	s.InitialInputCredit()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunInput(ctx, nil)
	if err := s.Input([]byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if wrote.Load() {
		t.Fatal("input written before the process produced output")
	}
	time.Sleep(400 * time.Millisecond)
	if !wrote.Load() {
		t.Fatal("input never written after the readiness timeout")
	}
}

func TestInputRegrantsCredit(t *testing.T) {
	var wrote atomic.Bool
	s := New(1, &recProc{wrote: &wrote}, func(*frame.Frame) error { return nil })
	total := s.InitialInputCredit()
	close(s.ready)
	var granted atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunInput(ctx, func(g int64) { granted.Add(g) })
	for sent := int64(0); sent < total; sent += 1024 {
		if err := s.Input(make([]byte, 1024)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for granted.Load() < total/2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if granted.Load() < total/2 {
		t.Fatalf("re-granted only %d of %d", granted.Load(), total)
	}
}

type nopProc struct{}

func (nopProc) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopProc) Write(b []byte) (int, error) { return len(b), nil }
func (nopProc) Resize(int, int) error       { return nil }

type recProc struct{ wrote *atomic.Bool }

func (r *recProc) Read([]byte) (int, error)    { select {} }
func (r *recProc) Write(b []byte) (int, error) { r.wrote.Store(true); return len(b), nil }
func (r *recProc) Resize(int, int) error       { return nil }
