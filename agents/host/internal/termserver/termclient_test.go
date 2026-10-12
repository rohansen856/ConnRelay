package termserver

import (
	"bytes"
	"context"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/connrelaycore/termclient"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
)

type recorder struct {
	mu     sync.Mutex
	out    bytes.Buffer
	events []string
}

func (r *recorder) Output(_ uint16, b []byte) { r.mu.Lock(); r.out.Write(b); r.mu.Unlock() }
func (r *recorder) Event(kind, detail string) {
	r.mu.Lock()
	r.events = append(r.events, kind+":"+detail)
	r.mu.Unlock()
}

func (r *recorder) wait(t *testing.T, re *regexp.Regexp) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		m := re.FindStringSubmatch(r.out.String())
		r.mu.Unlock()
		if m != nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never saw %s", re)
	return nil
}

func (r *recorder) hasEvent(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// TestTermClientAgainstServer exercises the shared phone-side client against
// the real terminal server.
func TestTermClientAgainstServer(t *testing.T) {
	s := newServer(t, 20)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func() (*termclient.Client, *recorder) {
		pc, hc := transport.Pipe("p", "h", "h", "p")
		go s.Serve(context.Background(), hc)
		rec := &recorder{}
		return termclient.New(pc, rec), rec
	}

	c, rec := connect()
	sess, err := c.Open(ctx, 100, 30)
	if err != nil || sess.ID == "" || !sess.Persistent {
		t.Fatalf("open: %+v %v", sess, err)
	}
	rec.wait(t, regexp.MustCompile(`\$ `))
	if err := c.Input(ctx, sess.StreamID, []byte("KEEP=1; echo PID=$$\r")); err != nil {
		t.Fatal(err)
	}
	pid := rec.wait(t, regexp.MustCompile(`PID=(\d+)`))[1]
	_ = c.Resize(sess.StreamID, 120, 40)
	time.Sleep(100 * time.Millisecond)
	_ = c.Input(ctx, sess.StreamID, []byte("stty size\r"))
	rec.wait(t, regexp.MustCompile(`40 120`))

	list, err := c.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != sess.ID {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, err := c.Attach(ctx, "nope", 80, 24); err == nil {
		t.Fatal("attach to unknown session succeeded")
	} else if he, ok := err.(*termclient.HostError); !ok || he.Code != ErrSessionNotFound {
		t.Fatalf("attach unknown: %v", err)
	}
	_ = c.Detach(sess.StreamID)
	c.Close()

	// A new connection attaches to the same shell.
	c2, rec2 := connect()
	s2, err := c2.Attach(ctx, sess.ID, 100, 30)
	if err != nil || !s2.Resumed {
		t.Fatalf("attach: %+v %v", s2, err)
	}
	_ = c2.Input(ctx, s2.StreamID, []byte("echo BACK=$$:$KEEP\r"))
	m := rec2.wait(t, regexp.MustCompile(`BACK=(\d+):(\d)`))
	if m[1] != pid || m[2] != "1" {
		t.Fatalf("different shell after reattach: %v", m)
	}
	if err := c2.Terminate(ctx, sess.ID); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if !rec2.hasEvent("exit:" + sess.ID) {
		t.Fatal("no exit event")
	}
	c2.Close()
	if !rec2.hasEvent("closed") {
		t.Fatal("no closed event")
	}
}
