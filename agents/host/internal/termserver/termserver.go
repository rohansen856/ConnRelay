// Package termserver serves terminal sessions to one verified peer over a
// data-plane connection (protocol v1 §11–13). It must only be started after
// the peer handshake (hello + mutual attestation) has succeeded.
//
// Sessions are tmux sessions and outlive the connection: when the transport
// drops, every attach client is closed (detach) and the shells keep running.
// A later connection re-attaches by terminal session ID.
package termserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/ptyproc"
	"github.com/rohansen856/connrelay/agents/host/internal/termstream"
	"github.com/rohansen856/connrelay/agents/host/internal/tmux"
	"github.com/rohansen856/connrelay/core/prwcore/control"
	"github.com/rohansen856/connrelay/core/prwcore/frame"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
)

// Error codes sent in terminal.error.
const (
	ErrSessionNotFound  = "session_not_found"
	ErrCapacity         = "host_capacity_reached"
	ErrBadRequest       = "bad_request"
	ErrPTYUnavailable   = "pty_unavailable"
	ErrTerminateConfirm = "confirm_required"
)

// Config configures the server.
type Config struct {
	Tmux        *tmux.Server
	Shell       []string // argv of the login shell
	Dir         string   // working directory for new sessions
	Env         []string // environment for attach clients
	MaxSessions int
	Log         *slog.Logger
}

// Server holds state shared across connections (idempotent opens).
type Server struct {
	cfg  Config
	mu   sync.Mutex
	open map[string]string // terminal.open request_id -> session id (dedupe)
}

// New returns a server.
func New(cfg Config) *Server {
	if cfg.MaxSessions == 0 {
		cfg.MaxSessions = 20
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Server{cfg: cfg, open: map[string]string{}}
}

type stream struct {
	s       *termstream.Stream
	proc    *ptyproc.Proc
	session string
	cancel  context.CancelFunc
}

type conn struct {
	srv     *Server
	c       transport.Conn
	mu      sync.Mutex
	streams map[uint16]*stream
	nextID  uint16
}

// Serve handles one verified connection until it fails or ctx ends. All
// attach clients are closed on return; sessions keep running.
func (s *Server) Serve(ctx context.Context, c transport.Conn) error {
	cn := &conn{srv: s, c: c, streams: map[uint16]*stream{}, nextID: 1}
	defer cn.detachAll()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-ctx.Done(); c.Close() }()
	for {
		f, err := c.Recv()
		if err != nil {
			return err
		}
		switch f.Type {
		case frame.TypeControl:
			env, err := control.Decode(f)
			if err != nil {
				return err
			}
			if err := cn.handle(ctx, env); err != nil {
				return err
			}
		case frame.TypeInput:
			st := cn.get(f.StreamID)
			if st == nil {
				return frame.ErrProtocol // input for an unknown stream
			}
			if err := st.s.Input(f.Payload); err != nil {
				return err
			}
		case frame.TypeCloseStream:
			cn.detach(f.StreamID)
		default:
			return frame.ErrProtocol
		}
	}
}

func (cn *conn) get(id uint16) *stream {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.streams[id]
}

func (cn *conn) send(typ, sessionID string, payload any) {
	env, err := control.New(typ, payload)
	if err != nil {
		return
	}
	env.TerminalSessionID = sessionID
	f, err := env.Frame()
	if err == nil {
		_ = cn.c.Send(f)
	}
}

func (cn *conn) fail(req *control.Envelope, code string) {
	env, _ := control.New(control.TypeTerminalError, map[string]string{"code": code, "request_id": req.RequestID})
	env.TerminalSessionID = req.TerminalSessionID
	if f, err := env.Frame(); err == nil {
		_ = cn.c.Send(f)
	}
}

type openReq struct {
	Title string `json:"title"`
	Cols  int    `json:"cols"`
	Rows  int    `json:"rows"`
}

type attachReq struct {
	SessionID string `json:"terminal_session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

type streamReq struct {
	StreamID uint16 `json:"stream_id"`
	Cols     int    `json:"cols"`
	Rows     int    `json:"rows"`
}

func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (cn *conn) handle(ctx context.Context, env *control.Envelope) error {
	srv := cn.srv
	switch env.Type {
	case control.TypeTerminalOpen:
		var r openReq
		if env.Unmarshal(&r) != nil || r.Cols < 1 || r.Rows < 1 {
			cn.fail(env, ErrBadRequest)
			return nil
		}
		srv.mu.Lock()
		id, dup := srv.open[env.RequestID]
		srv.mu.Unlock()
		if !dup {
			list, err := srv.cfg.Tmux.List()
			if err != nil {
				cn.fail(env, ErrPTYUnavailable)
				return nil
			}
			if len(list) >= srv.cfg.MaxSessions {
				cn.fail(env, ErrCapacity)
				return nil
			}
			id = newSessionID()
			if err := srv.cfg.Tmux.NewSession(id, srv.cfg.Shell, srv.cfg.Dir, r.Cols, r.Rows); err != nil {
				srv.cfg.Log.Warn("new session failed", "err", err)
				cn.fail(env, ErrPTYUnavailable)
				return nil
			}
			srv.mu.Lock()
			srv.open[env.RequestID] = id
			srv.mu.Unlock()
		}
		cn.attach(ctx, env, id, r.Cols, r.Rows, dup)
	case control.TypeTerminalAttach:
		var r attachReq
		if env.Unmarshal(&r) != nil || r.Cols < 1 || r.Rows < 1 {
			cn.fail(env, ErrBadRequest)
			return nil
		}
		if _, err := srv.cfg.Tmux.Get(r.SessionID); err != nil {
			env.TerminalSessionID = r.SessionID
			cn.fail(env, ErrSessionNotFound)
			return nil
		}
		cn.attach(ctx, env, r.SessionID, r.Cols, r.Rows, true)
	case control.TypeFlowCredit:
		var r control.FlowCredit
		if env.Unmarshal(&r) != nil {
			return frame.ErrProtocol
		}
		if st := cn.get(r.StreamID); st != nil {
			if err := st.s.GrantOutput(r.Bytes); err != nil {
				return err
			}
		}
	case control.TypeTerminalResize:
		var r streamReq
		if env.Unmarshal(&r) != nil {
			return frame.ErrProtocol
		}
		if st := cn.get(r.StreamID); st != nil {
			if err := st.s.Resize(r.Cols, r.Rows); err != nil {
				cn.fail(env, ErrBadRequest)
			}
		}
	case control.TypeTerminalDetach:
		var r streamReq
		if env.Unmarshal(&r) == nil {
			cn.detach(r.StreamID)
		}
	case control.TypeTerminalTerm:
		var r struct {
			SessionID string `json:"terminal_session_id"`
			Confirm   bool   `json:"confirm"`
		}
		if env.Unmarshal(&r) != nil || !r.Confirm {
			cn.fail(env, ErrTerminateConfirm)
			return nil
		}
		if err := srv.cfg.Tmux.Kill(r.SessionID); err != nil {
			env.TerminalSessionID = r.SessionID
			cn.fail(env, ErrSessionNotFound)
			return nil
		}
		cn.send(control.TypeTerminalExit, r.SessionID, map[string]any{"terminal_session_id": r.SessionID, "reason": "terminated"})
	case control.TypeTerminalList:
		list, err := srv.cfg.Tmux.List()
		if err != nil {
			cn.fail(env, ErrPTYUnavailable)
			return nil
		}
		type item struct {
			ID              string `json:"id"`
			Status          string `json:"status"`
			Persistent      bool   `json:"persistent"`
			CreatedAt       string `json:"created_at"`
			AttachedClients int    `json:"attached_clients"`
		}
		out := []item{}
		for _, i := range list {
			st := "detached"
			if i.Attached > 0 {
				st = "attached"
			}
			out = append(out, item{i.ID, st, true, time.Unix(i.Created, 0).UTC().Format(time.RFC3339), i.Attached})
		}
		cn.send(control.TypeTerminalListRes, "", map[string]any{"sessions": out})
	case control.TypePing:
		env.Type = control.TypePong
		if f, err := env.Frame(); err == nil {
			_ = cn.c.Send(f)
		}
	default:
		// Unknown control messages are ignored for forward compatibility.
	}
	return nil
}

func (cn *conn) attach(ctx context.Context, env *control.Envelope, id string, cols, rows int, resumed bool) {
	srv := cn.srv
	proc, err := ptyproc.Start(srv.cfg.Tmux.AttachArgv(id), tmux.AttachEnv(srv.cfg.Env, "xterm-256color"), "/", cols, rows)
	if err != nil {
		cn.fail(env, ErrPTYUnavailable)
		return
	}
	cn.mu.Lock()
	sid := cn.nextID
	cn.nextID++
	sctx, cancel := context.WithCancel(ctx)
	st := &stream{proc: proc, session: id, cancel: cancel}
	st.s = termstream.New(sid, proc, cn.c.Send)
	cn.streams[sid] = st
	cn.mu.Unlock()

	cn.send(control.TypeTerminalReady, id, map[string]any{
		"terminal_session_id": id, "stream_id": sid, "persistent": true, "resumed": resumed, "backend": "tmux",
	})
	cn.send(control.TypeFlowCredit, id, control.FlowCredit{StreamID: sid, Bytes: st.s.InitialInputCredit()})
	go func() {
		_ = st.s.RunInput(sctx, func(g int64) {
			cn.send(control.TypeFlowCredit, id, control.FlowCredit{StreamID: sid, Bytes: g})
		})
	}()
	go func() {
		err := st.s.Run(sctx)
		// The attach client ended. If the session itself is gone the shell
		// exited; otherwise this was a detach.
		if _, gerr := srv.cfg.Tmux.Get(id); errors.Is(gerr, tmux.ErrNotFound) {
			cn.send(control.TypeTerminalExit, id, map[string]any{"terminal_session_id": id, "reason": "exited"})
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			srv.cfg.Log.Debug("stream ended", "stream_id", sid, "err", err)
		}
	}()
}

func (cn *conn) detach(id uint16) {
	cn.mu.Lock()
	st := cn.streams[id]
	delete(cn.streams, id)
	cn.mu.Unlock()
	if st != nil {
		st.cancel()
		st.s.Close()
		st.proc.Close(time.Second) // closes the tmux client only
	}
}

func (cn *conn) detachAll() {
	cn.mu.Lock()
	ids := make([]uint16, 0, len(cn.streams))
	for id := range cn.streams {
		ids = append(ids, id)
	}
	cn.mu.Unlock()
	for _, id := range ids {
		cn.detach(id)
	}
}
