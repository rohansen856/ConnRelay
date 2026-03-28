package connmgr

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

type fakeConn struct {
	transport.Conn
	path   string
	closed *atomic.Int32
}

func (f fakeConn) Path() string { return f.path }
func (f fakeConn) Close() error { f.closed.Add(1); return nil }

func dialer(path string, after time.Duration, err error, closed *atomic.Int32, started *atomic.Int64, t0 time.Time) Dialer {
	return func(ctx context.Context) (transport.Conn, error) {
		if started != nil {
			started.Store(int64(time.Since(t0)))
		}
		select {
		case <-time.After(after):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, err
		}
		return fakeConn{path: path, closed: closed}, nil
	}
}

func TestICEWinsBeforeFallback(t *testing.T) {
	var closed atomic.Int32
	var wssStart atomic.Int64
	t0 := time.Now()
	c, rep, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 50*time.Millisecond, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 10*time.Millisecond, nil, &closed, &wssStart, t0),
		FallbackDelay: 500 * time.Millisecond,
	})
	if err != nil || c.Path() != transport.PathDirect || rep.Path != transport.PathDirect {
		t.Fatalf("got %v %v", c, err)
	}
	if wssStart.Load() != 0 {
		t.Fatal("WSS started although ICE won before the fallback delay")
	}
}

func TestFallbackAfterDelay(t *testing.T) {
	var closed atomic.Int32
	var wssStart atomic.Int64
	t0 := time.Now()
	c, _, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 5*time.Second, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 20*time.Millisecond, nil, &closed, &wssStart, t0),
		FallbackDelay: 200 * time.Millisecond,
	})
	if err != nil || c.Path() != transport.PathWSSRelay {
		t.Fatalf("got %v %v", c, err)
	}
	if d := time.Duration(wssStart.Load()); d < 200*time.Millisecond || d > 400*time.Millisecond {
		t.Fatalf("WSS started at %v", d)
	}
}

func TestUDPBlockedStartsWSSImmediately(t *testing.T) {
	var closed atomic.Int32
	var wssStart atomic.Int64
	t0 := time.Now()
	_, _, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 5*time.Second, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 10*time.Millisecond, nil, &closed, &wssStart, t0),
		FallbackDelay: 2 * time.Second,
		UDPBlocked:    true,
	})
	if err != nil || time.Duration(wssStart.Load()) > 50*time.Millisecond {
		t.Fatalf("err %v, wss start %v", err, time.Duration(wssStart.Load()))
	}
}

func TestICEFailureTriggersFallbackAtOnce(t *testing.T) {
	var closed atomic.Int32
	var wssStart atomic.Int64
	t0 := time.Now()
	c, rep, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 30*time.Millisecond, errors.New("ice failed"), &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 10*time.Millisecond, nil, &closed, &wssStart, t0),
		FallbackDelay: 3 * time.Second,
	})
	if err != nil || c.Path() != transport.PathWSSRelay || len(rep.Attempts) != 2 {
		t.Fatalf("got %v %v %+v", c, err, rep)
	}
	if time.Duration(wssStart.Load()) > 200*time.Millisecond {
		t.Fatal("fallback waited for the delay after ICE failed")
	}
}

func TestHandshakeFailureIsNotAWin(t *testing.T) {
	var closed atomic.Int32
	t0 := time.Now()
	c, _, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 10*time.Millisecond, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 10*time.Millisecond, nil, &closed, nil, t0),
		FallbackDelay: 50 * time.Millisecond,
		Handshake: func(_ context.Context, c transport.Conn) error {
			if c.Path() == transport.PathDirect {
				return errors.New("peer_identity_mismatch")
			}
			return nil
		},
	})
	if err != nil || c.Path() != transport.PathWSSRelay {
		t.Fatalf("got %v %v", c, err)
	}
	if closed.Load() != 1 {
		t.Fatalf("failed-handshake conn closed %d times", closed.Load())
	}
}

func TestTimeout(t *testing.T) {
	var closed atomic.Int32
	t0 := time.Now()
	_, _, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, time.Hour, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, time.Hour, nil, &closed, nil, t0),
		FallbackDelay: 10 * time.Millisecond,
		Timeout:       200 * time.Millisecond,
	})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestLoserClosed(t *testing.T) {
	var closed atomic.Int32
	t0 := time.Now()
	// Both finish nearly together; whichever loses must be closed.
	c, _, err := Connect(context.Background(), Options{
		ICE:           dialer(transport.PathDirect, 30*time.Millisecond, nil, &closed, nil, t0),
		WSS:           dialer(transport.PathWSSRelay, 0, nil, &closed, nil, t0),
		UDPBlocked:    true,
		FallbackDelay: time.Second,
		Handshake: func(ctx context.Context, c transport.Conn) error {
			time.Sleep(60 * time.Millisecond) // both handshakes overlap
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if closed.Load() != 1 {
		t.Fatalf("loser closed %d times (winner %s)", closed.Load(), c.Path())
	}
}
