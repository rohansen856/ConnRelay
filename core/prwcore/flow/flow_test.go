package flow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSenderBlocksWithoutCredit(t *testing.T) {
	s := NewSender(0)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := s.Acquire(ctx, 10); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
}

func TestSenderPartialAcquire(t *testing.T) {
	s := NewSender(0)
	_ = s.Grant(5)
	n, err := s.Acquire(context.Background(), 10)
	if err != nil || n != 5 {
		t.Fatalf("got %d %v", n, err)
	}
	if s.Available() != 0 {
		t.Fatal("credit left")
	}
}

func TestSenderReturn(t *testing.T) {
	s := NewSender(10)
	_ = s.Grant(10)
	n, _ := s.Acquire(context.Background(), 10)
	s.Return(n - 3)
	if s.Available() != 7 {
		t.Fatalf("available %d", s.Available())
	}
}

func TestSenderWakesOnGrant(t *testing.T) {
	s := NewSender(0)
	done := make(chan int)
	go func() {
		n, _ := s.Acquire(context.Background(), 100)
		done <- n
	}()
	time.Sleep(20 * time.Millisecond)
	_ = s.Grant(40)
	select {
	case n := <-done:
		if n != 40 {
			t.Fatalf("got %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("not woken")
	}
}

func TestSenderClose(t *testing.T) {
	s := NewSender(0)
	go func() { time.Sleep(10 * time.Millisecond); s.Close() }()
	if _, err := s.Acquire(context.Background(), 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("got %v", err)
	}
}

func TestSenderOverGrant(t *testing.T) {
	s := NewSender(100)
	if err := s.Grant(100); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(1); !errors.Is(err, ErrOverGrant) {
		t.Fatalf("got %v", err)
	}
}

func TestReceiverRegrantAtHalf(t *testing.T) {
	r := NewReceiver(100)
	if r.Initial() != 100 {
		t.Fatal("initial")
	}
	if err := r.Received(49); err != nil {
		t.Fatal(err)
	}
	if g := r.Consumed(49); g != 0 {
		t.Fatalf("early grant %d", g)
	}
	_ = r.Received(1)
	if g := r.Consumed(1); g != 50 {
		t.Fatalf("grant %d", g)
	}
	// Peer may now have at most 100 outstanding again.
	if err := r.Received(100); err != nil {
		t.Fatal(err)
	}
	if err := r.Received(1); !errors.Is(err, ErrOverGrant) {
		t.Fatalf("want over-grant, got %v", err)
	}
}

// TestEndToEndNoLossBounded pumps 8 MiB through a sender/receiver pair and
// checks that in-flight bytes never exceed the window.
func TestEndToEndNoLossBounded(t *testing.T) {
	const window = 64 * 1024
	const total = 8 << 20
	s := NewSender(window)
	r := NewReceiver(window)
	_ = s.Grant(r.Initial())

	type chunk struct{ n int }
	pipe := make(chan chunk, 1024)
	var inflight, maxInflight int64
	var mu sync.Mutex

	go func() {
		sent := 0
		for sent < total {
			want := 16384
			if total-sent < want {
				want = total - sent
			}
			n, err := s.Acquire(context.Background(), want)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inflight += int64(n)
			if inflight > maxInflight {
				maxInflight = inflight
			}
			mu.Unlock()
			pipe <- chunk{n}
			sent += n
		}
		close(pipe)
	}()

	got := 0
	for c := range pipe {
		if err := r.Received(c.n); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		inflight -= int64(c.n)
		mu.Unlock()
		got += c.n
		if g := r.Consumed(c.n); g > 0 {
			if err := s.Grant(g); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got != total {
		t.Fatalf("got %d want %d", got, total)
	}
	if maxInflight > window {
		t.Fatalf("in-flight %d exceeded window %d", maxInflight, window)
	}
}
