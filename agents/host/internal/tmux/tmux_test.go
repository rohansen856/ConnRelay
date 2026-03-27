package tmux

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/ptyproc"
)

func server(t *testing.T) *Server {
	t.Helper()
	dir, err := os.MkdirTemp("", "prwt")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(dir, "tmux.sock"))
	if errors.Is(err, ErrUnavailable) {
		t.Skip("tmux not installed")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.KillServer(); os.RemoveAll(dir) })
	return s
}

func readUntil(t *testing.T, r io.Reader, re *regexp.Regexp, timeout time.Duration) []string {
	t.Helper()
	var buf bytes.Buffer
	res := make(chan []string, 1)
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			buf.Write(b[:n])
			if m := re.FindStringSubmatch(buf.String()); m != nil {
				res <- m
				return
			}
			if err != nil {
				res <- nil
				return
			}
		}
	}()
	select {
	case m := <-res:
		if m == nil {
			t.Fatalf("stream ended before %s", re)
		}
		return m
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %s", re)
	}
	return nil
}

func attach(t *testing.T, s *Server, id string) *ptyproc.Proc {
	t.Helper()
	p, err := ptyproc.Start(s.AttachArgv(id), AttachEnv(os.Environ(), "xterm-256color"), "/", 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	// Input typed before the client finishes attaching can be consumed by
	// tmux's terminal negotiation; wait for the first redraw of the prompt.
	readUntil(t, p, regexp.MustCompile(`\$ `), 5*time.Second)
	return p
}

func TestVersionCheck(t *testing.T) {
	for v, ok := range map[string]bool{"tmux 3.2a": true, "tmux 3.0": true, "tmux 2.9": false, "tmux 4.1": true, "tmux next-3.6": true} {
		if versionOK(v) != ok {
			t.Errorf("%q: want %v", v, ok)
		}
	}
}

func TestSessionSurvivesDetachAndReattach(t *testing.T) {
	s := server(t)
	id := "s4-reattach"
	if err := s.NewSession(id, []string{"/bin/sh"}, "/", 100, 30); err != nil {
		t.Fatal(err)
	}
	info, err := s.Get(id)
	if err != nil || info.PanePID == 0 {
		t.Fatalf("get: %+v %v", info, err)
	}

	// First attach: record the shell PID and leave state behind.
	a := attach(t, s, id)
	io.WriteString(a, "MARK=persisted; echo PID=$$\r")
	m := readUntil(t, a, regexp.MustCompile(`PID=(\d+)`), 5*time.Second)
	pid1 := m[1]
	// Drop the client abruptly, as a lost phone connection would.
	a.Close(200 * time.Millisecond)

	time.Sleep(200 * time.Millisecond)
	info, err = s.Get(id)
	if err != nil {
		t.Fatalf("session gone after client loss: %v", err)
	}
	if info.Attached != 0 {
		t.Fatalf("attached clients %d after detach", info.Attached)
	}

	// Reattach: same shell, state intact.
	b := attach(t, s, id)
	defer b.Close(200 * time.Millisecond)
	io.WriteString(b, "echo AGAIN=$$:$MARK\r")
	m = readUntil(t, b, regexp.MustCompile(`AGAIN=(\d+):(\w+)`), 5*time.Second)
	if m[1] != pid1 || m[2] != "persisted" {
		t.Fatalf("reattached to a different shell: pid %s vs %s, mark %q", m[1], pid1, m[2])
	}
}

func TestReattachRedrawsScreen(t *testing.T) {
	s := server(t)
	id := "s4-redraw"
	if err := s.NewSession(id, []string{"/bin/sh"}, "/", 100, 30); err != nil {
		t.Fatal(err)
	}
	a := attach(t, s, id)
	io.WriteString(a, "echo VISIBLE-$((6*7))\r")
	readUntil(t, a, regexp.MustCompile(`VISIBLE-42`), 5*time.Second)
	a.Close(200 * time.Millisecond)

	// Output produced while detached must appear on the redrawn screen.
	if _, err := s.run("send-keys", "-t", Name(id), "echo WHILE-AWAY-$((1+1))", "Enter"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	b := attach(t, s, id)
	defer b.Close(200 * time.Millisecond)
	readUntil(t, b, regexp.MustCompile(`WHILE-AWAY-2`), 5*time.Second)
}

func TestListAndKill(t *testing.T) {
	s := server(t)
	if l, err := s.List(); err != nil || len(l) != 0 {
		t.Fatalf("empty server list: %v %v", l, err)
	}
	for _, id := range []string{"a1", "a2"} {
		if err := s.NewSession(id, []string{"/bin/sh"}, "", 80, 24); err != nil {
			t.Fatal(err)
		}
	}
	l, _ := s.List()
	if len(l) != 2 {
		t.Fatalf("list %+v", l)
	}
	if err := s.Kill("a1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a1 still present: %v", err)
	}
	if err := s.Kill("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("kill unknown: %v", err)
	}
}

func TestRejectsUnsafeID(t *testing.T) {
	s := server(t)
	for _, id := range []string{"", "a b", "a;rm", "../x", strings.Repeat("x", 65)} {
		if err := s.NewSession(id, []string{"/bin/sh"}, "", 80, 24); err == nil {
			t.Errorf("accepted id %q", id)
		}
	}
}
