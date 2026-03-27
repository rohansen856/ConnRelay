package ptyproc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// Expect reads from r until want appears or the timeout passes.
func Expect(t *testing.T, r io.Reader, want string, timeout time.Duration) string {
	t.Helper()
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := r.Read(b)
			buf.Write(b[:n])
			if strings.Contains(buf.String(), want) || err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %q; got %q", want, buf.String())
	}
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("stream ended before %q; got %q", want, buf.String())
	}
	return buf.String()
}

func TestEchoResizeExit(t *testing.T) {
	p, err := Start([]string{"/bin/sh"}, []string{"PATH=/usr/bin:/bin", "PS1=$ "}, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)

	io.WriteString(p, "stty size\n")
	Expect(t, p, "24 80", 3*time.Second)

	if err := p.Resize(132, 50); err != nil {
		t.Fatal(err)
	}
	io.WriteString(p, "stty size\n")
	Expect(t, p, "50 132", 3*time.Second)

	io.WriteString(p, "exit 7\n")
	select {
	case <-p.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("shell did not exit")
	}
	if p.ExitCode() != 7 {
		t.Fatalf("exit code %d", p.ExitCode())
	}
}

func TestCtrlCInterrupts(t *testing.T) {
	p, err := Start([]string{"/bin/sh"}, []string{"PATH=/usr/bin:/bin", "PS1=$ "}, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)
	io.WriteString(p, "sleep 30; echo SLEPT\n")
	time.Sleep(300 * time.Millisecond)
	p.Write([]byte{0x03}) // Ctrl-C as raw byte
	io.WriteString(p, "echo AFTER-$((40+2))\n")
	// AFTER-42 can only appear within the timeout if Ctrl-C interrupted the
	// 30 s sleep (the shell runs commands sequentially).
	start := time.Now()
	Expect(t, p, "AFTER-42", 3*time.Second)
	if time.Since(start) > 3*time.Second {
		t.Fatal("sleep was not interrupted")
	}
}

func TestRejectsBadSize(t *testing.T) {
	if _, err := Start([]string{"/bin/true"}, nil, "/", 0, 24); !errors.Is(err, ErrSize) {
		t.Fatalf("got %v", err)
	}
	p, err := Start([]string{"/bin/sh"}, nil, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(time.Second)
	if err := p.Resize(1001, 10); !errors.Is(err, ErrSize) {
		t.Fatalf("got %v", err)
	}
}

func TestCloseEscalates(t *testing.T) {
	// trap '' HUP makes the shell ignore SIGHUP so Close must escalate.
	p, err := Start([]string{"/bin/sh", "-c", "trap '' HUP; sleep 60"}, nil, "/", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	p.Close(300 * time.Millisecond)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("close took %v", d)
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("process still running")
	}
}
