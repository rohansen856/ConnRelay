// Package relay implements /v1/relay: it pairs the phone ("client") and host
// ("server") of one connection attempt and copies binary WebSocket messages
// between them without inspecting them. Payloads are end-to-end TLS 1.3
// ciphertext; the relay only counts bytes.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"golang.org/x/time/rate"
)

// Config holds relay limits (proposed defaults in DefaultConfig).
type Config struct {
	PeerWait      time.Duration // wait for the second peer
	IdleTimeout   time.Duration
	MaxMessage    int64
	BytesPerSec   int // per attempt, both directions combined
	MaxBytes      int64
	JoinReadLimit int64
}

// DefaultConfig returns the documented defaults.
func DefaultConfig() Config {
	return Config{
		PeerWait:      15 * time.Second,
		IdleTimeout:   120 * time.Second,
		MaxMessage:    64 * 1024,
		BytesPerSec:   2_000_000 / 8,
		MaxBytes:      2 << 30,
		JoinReadLimit: 4096,
	}
}

// Stats are cumulative counters for metrics.
type Stats struct {
	Joins, Rejects, Splices, Bytes atomic.Int64
}

// Server is the relay endpoint.
type Server struct {
	cfg   Config
	keys  token.KeySet
	now   func() time.Time
	log   *slog.Logger
	Stats Stats

	mu      sync.Mutex
	pending map[string]*waiter // attempt ID -> first peer
	active  map[string]context.CancelFunc
	seen    map[string]time.Time // relay token jti -> expiry
}

type waiter struct {
	role string
	ws   *websocket.Conn
	peer chan *websocket.Conn
}

// New creates a relay that accepts relay tokens signed by keys.
func New(cfg Config, keys token.KeySet, log *slog.Logger) *Server {
	return &Server{
		cfg: cfg, keys: keys, now: time.Now, log: log,
		pending: map[string]*waiter{}, active: map[string]context.CancelFunc{}, seen: map[string]time.Time{},
	}
}

func (s *Server) reject(ws *websocket.Conn, code websocket.StatusCode, reason string) {
	s.Stats.Rejects.Add(1)
	_ = ws.Close(code, reason)
}

// ServeHTTP handles one peer connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(s.cfg.JoinReadLimit)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	typ, b, err := ws.Read(ctx)
	cancel()
	if err != nil || typ != websocket.MessageText {
		s.reject(ws, 4400, "expected join")
		return
	}
	var m struct {
		Type      string `json:"type"`
		AttemptID string `json:"attempt_id"`
		Token     string `json:"relay_token"`
		Role      string `json:"role"`
	}
	if json.Unmarshal(b, &m) != nil || m.Type != "join" {
		s.reject(ws, 4400, "expected join")
		return
	}
	var claims token.Relay
	if err := s.keys.Verify(m.Token, token.TypeRelay, s.now(), &claims); err != nil ||
		claims.Att != m.AttemptID || claims.Role != m.Role ||
		(m.Role != token.RoleClient && m.Role != token.RoleServer) {
		s.reject(ws, 4401, "invalid relay token")
		return
	}
	if !s.claimJTI(claims.JTI, time.Unix(claims.EXP, 0)) {
		s.reject(ws, 4401, "relay token reused")
		return
	}
	s.Stats.Joins.Add(1)
	ws.SetReadLimit(s.cfg.MaxMessage)

	wt, peer := s.match(m.AttemptID, m.Role, ws)
	switch {
	case wt == nil && peer == nil:
		s.reject(ws, 4409, "attempt already joined")
		return
	case wt != nil:
		// First peer: wait for the counterpart, which runs the splice and
		// owns both connections from then on.
		select {
		case <-wt.peer:
		case <-time.After(s.cfg.PeerWait):
			s.mu.Lock()
			stillPending := s.pending[m.AttemptID] == wt
			if stillPending {
				delete(s.pending, m.AttemptID)
			}
			s.mu.Unlock()
			if stillPending {
				s.reject(ws, 4408, "peer did not join")
			}
		}
		return
	}
	s.splice(m.AttemptID, peer, ws)
}

func (s *Server) claimJTI(jti string, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.seen {
		if now.After(e.Add(token.ClockSkew)) {
			delete(s.seen, k)
		}
	}
	if _, ok := s.seen[jti]; ok {
		return false
	}
	s.seen[jti] = exp
	return true
}

// match registers ws as the first peer (returning its waiter) or returns the
// waiting counterpart. Both nil means the attempt is busy or the role is
// already taken.
func (s *Server) match(att, role string, ws *websocket.Conn) (*waiter, *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, busy := s.active[att]; busy {
		return nil, nil
	}
	w, ok := s.pending[att]
	if !ok {
		w = &waiter{role: role, ws: ws, peer: make(chan *websocket.Conn, 1)}
		s.pending[att] = w
		return w, nil
	}
	if w.role == role {
		return nil, nil
	}
	delete(s.pending, att)
	s.active[att] = func() {} // reserved until splice installs its cancel
	w.peer <- ws
	return nil, w.ws
}

func (s *Server) splice(att string, a, b *websocket.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.active[att] = cancel
	s.mu.Unlock()
	s.Stats.Splices.Add(1)
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.active, att)
		s.mu.Unlock()
	}()

	joined := []byte(`{"type":"joined"}`)
	for _, ws := range []*websocket.Conn{a, b} {
		wctx, c := context.WithTimeout(ctx, 5*time.Second)
		err := ws.Write(wctx, websocket.MessageText, joined)
		c()
		if err != nil {
			a.CloseNow()
			b.CloseNow()
			return
		}
	}

	lim := rate.NewLimiter(rate.Limit(s.cfg.BytesPerSec), int(s.cfg.MaxMessage)*4)
	var total atomic.Int64
	errc := make(chan error, 2)
	pump := func(src, dst *websocket.Conn) {
		for {
			rctx, c := context.WithTimeout(ctx, s.cfg.IdleTimeout)
			typ, msg, err := src.Read(rctx)
			c()
			if err != nil {
				errc <- err
				return
			}
			if typ != websocket.MessageBinary {
				errc <- errors.New("text message after join")
				return
			}
			if total.Add(int64(len(msg))) > s.cfg.MaxBytes {
				errc <- errors.New("byte cap reached")
				return
			}
			if err := lim.WaitN(ctx, len(msg)); err != nil {
				errc <- err
				return
			}
			s.Stats.Bytes.Add(int64(len(msg)))
			wctx, c2 := context.WithTimeout(ctx, s.cfg.IdleTimeout)
			err = dst.Write(wctx, websocket.MessageBinary, msg)
			c2()
			if err != nil {
				errc <- err
				return
			}
		}
	}
	go pump(a, b)
	go pump(b, a)
	err := <-errc
	s.log.Info("relay splice ended", "attempt_id", att, "bytes", total.Load(), "reason", reasonOf(err))
	cancel()
	_ = a.Close(websocket.StatusNormalClosure, "")
	_ = b.Close(websocket.StatusNormalClosure, "")
}

func reasonOf(err error) string {
	switch {
	case err == nil:
		return ""
	case websocket.CloseStatus(err) != -1:
		return "peer_closed"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "idle_timeout"
	}
	return err.Error()
}

// CloseAttempt terminates an active splice (used on revocation).
func (s *Server) CloseAttempt(att string) {
	s.mu.Lock()
	cancel := s.active[att]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
