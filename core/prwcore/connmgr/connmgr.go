// Package connmgr races the data-plane paths for one connection attempt
// (protocol v1 §8): ICE (direct or TURN) starts immediately; the WSS relay
// starts after FallbackDelay, or immediately when the current network is
// known to block UDP. Each path must complete the peer handshake; the first
// to do so wins and the others are closed.
package connmgr

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/control"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// Proposed defaults.
const (
	DefaultFallbackDelay = 4 * time.Second
	DefaultTimeout       = 20 * time.Second
)

// ErrTimeout is returned when no path completes in time (connect_timeout).
var ErrTimeout = errors.New("connect_timeout")

// Dialer establishes one transport (including ICE/relay setup).
type Dialer func(ctx context.Context) (transport.Conn, error)

// Options configure a race.
type Options struct {
	ICE           Dialer // nil if unavailable
	WSS           Dialer // nil if unavailable
	FallbackDelay time.Duration
	Timeout       time.Duration
	// UDPBlocked starts the WSS relay at t=0.
	UDPBlocked bool
	// Handshake runs hello + attestation on a fresh transport.
	Handshake func(ctx context.Context, c transport.Conn) error
	// Controlled is set on the host. The phone (controlling side) chooses
	// the path and announces it with path.select on the winning transport;
	// the controlled side commits to whichever transport carries it. This
	// prevents the two ends from picking different winners when both paths
	// complete at nearly the same time.
	Controlled bool
}

// Attempt records how one path fared.
type Attempt struct {
	Name    string        `json:"name"` // "ice" or "wss"
	Started time.Duration `json:"started_ms"`
	Elapsed time.Duration `json:"elapsed_ms"`
	Err     string        `json:"error,omitempty"`
}

// Report summarises a race for diagnostics.
type Report struct {
	Path     string        `json:"path"` // direct, turn, wss_relay
	Elapsed  time.Duration `json:"elapsed_ms"`
	Attempts []Attempt     `json:"attempts"`
}

type result struct {
	name string
	conn transport.Conn
	err  error
	at   Attempt
}

// Connect runs the race.
func Connect(ctx context.Context, o Options) (transport.Conn, *Report, error) {
	if o.FallbackDelay == 0 {
		o.FallbackDelay = DefaultFallbackDelay
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultTimeout
	}
	if o.ICE == nil && o.WSS == nil {
		return nil, nil, errors.New("connmgr: no paths configured")
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	results := make(chan result, 2)
	launch := func(name string, d Dialer) {
		go func() {
			at := Attempt{Name: name, Started: time.Since(start)}
			c, err := d(ctx)
			if err == nil && o.Handshake != nil {
				err = o.Handshake(ctx, c)
			}
			if err == nil && o.Controlled {
				err = awaitSelect(ctx, c)
			}
			if err != nil && c != nil {
				c.Close()
				c = nil
			}
			at.Elapsed = time.Since(start) - at.Started
			if err != nil {
				at.Err = err.Error()
			}
			results <- result{name, c, err, at}
		}()
	}

	pending := 0
	if o.ICE != nil {
		launch("ice", o.ICE)
		pending++
	}
	wssStarted := false
	startWSS := func() {
		if !wssStarted && o.WSS != nil {
			wssStarted = true
			launch("wss", o.WSS)
			pending++
		}
	}
	if o.UDPBlocked || o.ICE == nil {
		startWSS()
	}
	fallback := time.NewTimer(o.FallbackDelay)
	defer fallback.Stop()

	rep := &Report{}
	var lastErr error
	drain := func(n int) {
		go func() {
			for i := 0; i < n; i++ {
				if r := <-results; r.conn != nil {
					r.conn.Close()
				}
			}
		}()
	}
	for {
		if pending == 0 && (wssStarted || o.WSS == nil) {
			rep.Elapsed = time.Since(start)
			if lastErr == nil {
				lastErr = ErrTimeout
			}
			return nil, rep, lastErr
		}
		select {
		case <-fallback.C:
			startWSS()
		case r := <-results:
			pending--
			rep.Attempts = append(rep.Attempts, r.at)
			if r.err != nil {
				lastErr = r.err
				startWSS() // a failed ICE attempt triggers the fallback at once
				continue
			}
			if !o.Controlled {
				if err := sendSelect(r.conn); err != nil {
					r.conn.Close()
					lastErr = err
					startWSS()
					continue
				}
			}
			cancel() // stop the losing path
			drain(pending)
			rep.Path = r.conn.Path()
			rep.Elapsed = time.Since(start)
			return r.conn, rep, nil
		case <-ctx.Done():
			drain(pending)
			rep.Elapsed = time.Since(start)
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, rep, fmt.Errorf("%w (last error: %v)", ErrTimeout, lastErr)
			}
			return nil, rep, ctx.Err()
		}
	}
}

// sendSelect tells the controlled side which transport won.
func sendSelect(c transport.Conn) error {
	env, err := control.New(control.TypePathSelect, nil)
	if err != nil {
		return err
	}
	f, err := env.Frame()
	if err != nil {
		return err
	}
	return c.Send(f)
}

// awaitSelect waits for path.select as the first message after the handshake.
func awaitSelect(ctx context.Context, c transport.Conn) error {
	got := make(chan error, 1)
	go func() {
		f, err := c.Recv()
		if err != nil {
			got <- err
			return
		}
		env, err := control.Decode(f)
		if err != nil {
			got <- err
			return
		}
		if env.Type != control.TypePathSelect {
			got <- fmt.Errorf("connmgr: expected %s, got %s", control.TypePathSelect, env.Type)
			return
		}
		got <- nil
	}()
	select {
	case err := <-got:
		return err
	case <-ctx.Done():
		c.Close() // unblocks Recv
		return ctx.Err()
	}
}
