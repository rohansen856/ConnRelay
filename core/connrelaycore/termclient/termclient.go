// Package termclient is the phone side of the terminal protocol (protocol v1
// §11–13) on a verified transport: open or attach sessions, send input under
// the host's input credit, receive output and re-grant output credit as it is
// consumed, resize, detach and terminate.
package termclient

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rohansen856/connrelay/core/connrelaycore/control"
	"github.com/rohansen856/connrelay/core/connrelaycore/flow"
	"github.com/rohansen856/connrelay/core/connrelaycore/frame"
	"github.com/rohansen856/connrelay/core/connrelaycore/transport"
)

// Errors.
var (
	ErrClosed  = errors.New("termclient: connection closed")
	ErrTimeout = errors.New("termclient: no reply from host")
)

// HostError is a terminal.error reply.
type HostError struct{ Code string }

func (e *HostError) Error() string { return "host refused: " + e.Code }

// Handler receives asynchronous output and events. Calls are made from the
// client's receive goroutine, in order; they must not block for long.
type Handler interface {
	// Output delivers terminal bytes for a stream. The slice is owned by the
	// callee. Credit is re-granted when Output returns.
	Output(stream uint16, data []byte)
	// Event reports exit, revocation and transport loss:
	//   "exit" (session id), "revoked" (reason), "closed" (error text).
	Event(kind, detail string)
}

// Session is an open or attached terminal stream.
type Session struct {
	ID         string `json:"terminal_session_id"`
	StreamID   uint16 `json:"stream_id"`
	Persistent bool   `json:"persistent"`
	Resumed    bool   `json:"resumed"`
	Backend    string `json:"backend"`
}

// Info is one entry of terminal.list.
type Info struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	Persistent      bool   `json:"persistent"`
	CreatedAt       string `json:"created_at"`
	AttachedClients int    `json:"attached_clients"`
}

// Client runs the protocol on one transport.
type Client struct {
	c   transport.Conn
	h   Handler
	mu  sync.Mutex
	in  map[uint16]*flow.Sender   // our input credit per stream
	out map[uint16]*flow.Receiver // output credit we grant per stream
	// waiters for request/response by request_id, plus by message type for
	// replies that carry no request_id.
	waiters map[string]chan *control.Envelope
	done    chan struct{}
	err     error
	once    sync.Once
}

// New starts the client's receive loop on c.
func New(c transport.Conn, h Handler) *Client {
	cl := &Client{c: c, h: h, in: map[uint16]*flow.Sender{}, out: map[uint16]*flow.Receiver{},
		waiters: map[string]chan *control.Envelope{}, done: make(chan struct{})}
	go cl.loop()
	return cl
}

// Done is closed when the transport ends.
func (cl *Client) Done() <-chan struct{} { return cl.done }

func (cl *Client) finish(err error) {
	cl.once.Do(func() {
		cl.err = err
		cl.mu.Lock()
		for _, s := range cl.in {
			s.Close()
		}
		cl.mu.Unlock()
		close(cl.done)
		if cl.h != nil {
			msg := ""
			if err != nil {
				msg = err.Error()
			}
			cl.h.Event("closed", msg)
		}
	})
}

func (cl *Client) loop() {
	for {
		f, err := cl.c.Recv()
		if err != nil {
			cl.finish(err)
			return
		}
		switch f.Type {
		case frame.TypeControl:
			env, err := control.Decode(f)
			if err != nil {
				cl.finish(err)
				return
			}
			cl.control(env)
		case frame.TypeOutput:
			cl.mu.Lock()
			r := cl.out[f.StreamID]
			cl.mu.Unlock()
			if r == nil {
				continue // output for a stream we detached from
			}
			if err := r.Received(len(f.Payload)); err != nil {
				cl.finish(err) // host exceeded our credit: protocol violation
				return
			}
			if cl.h != nil {
				cl.h.Output(f.StreamID, f.Payload)
			}
			if g := r.Consumed(len(f.Payload)); g > 0 {
				cl.send(control.TypeFlowCredit, "", control.FlowCredit{StreamID: f.StreamID, Bytes: g})
			}
		case frame.TypeCloseStream:
			cl.dropStream(f.StreamID)
		}
	}
}

func (cl *Client) control(env *control.Envelope) {
	switch env.Type {
	case control.TypeFlowCredit:
		var fc control.FlowCredit
		if env.Unmarshal(&fc) == nil {
			cl.mu.Lock()
			s := cl.in[fc.StreamID]
			cl.mu.Unlock()
			if s != nil {
				_ = s.Grant(fc.Bytes)
			}
		}
		return
	case control.TypeTerminalReady:
		// Create stream state before any following frame is processed: the
		// host's input credit comes right after ready.
		var s Session
		if env.Unmarshal(&s) == nil && s.StreamID != 0 {
			cl.mu.Lock()
			cl.in[s.StreamID] = flow.NewSender(flow.DefaultInputWindow)
			cl.out[s.StreamID] = flow.NewReceiver(flow.DefaultOutputWindow)
			cl.mu.Unlock()
		}
	case control.TypeTerminalExit:
		if cl.h != nil {
			cl.h.Event("exit", env.TerminalSessionID)
		}
	case control.TypeSessionRevoked:
		var r struct {
			Reason string `json:"reason"`
		}
		_ = env.Unmarshal(&r)
		if cl.h != nil {
			cl.h.Event("revoked", r.Reason)
		}
	case control.TypePing:
		env.Type = control.TypePong
		if f, err := env.Frame(); err == nil {
			_ = cl.c.Send(f)
		}
		return
	}
	cl.mu.Lock()
	key := env.Type
	if env.Type == control.TypeTerminalError {
		var e struct {
			RequestID string `json:"request_id"`
		}
		_ = env.Unmarshal(&e)
		key = "err:" + e.RequestID
	}
	w := cl.waiters[key]
	cl.mu.Unlock()
	if w != nil {
		select {
		case w <- env:
		default:
		}
	}
}

func (cl *Client) send(typ, sessionID string, payload any) (string, error) {
	env, err := control.New(typ, payload)
	if err != nil {
		return "", err
	}
	env.TerminalSessionID = sessionID
	f, err := env.Frame()
	if err != nil {
		return "", err
	}
	return env.RequestID, cl.c.Send(f)
}

// request sends a message and waits for a reply of replyType (or an error
// for the same request).
func (cl *Client) request(ctx context.Context, typ string, payload any, replyType string) (*control.Envelope, error) {
	env, err := control.New(typ, payload)
	if err != nil {
		return nil, err
	}
	reply := make(chan *control.Envelope, 1)
	cl.mu.Lock()
	cl.waiters[replyType] = reply
	cl.waiters["err:"+env.RequestID] = reply
	cl.mu.Unlock()
	defer func() {
		cl.mu.Lock()
		delete(cl.waiters, replyType)
		delete(cl.waiters, "err:"+env.RequestID)
		cl.mu.Unlock()
	}()
	f, err := env.Frame()
	if err != nil {
		return nil, err
	}
	if err := cl.c.Send(f); err != nil {
		return nil, err
	}
	select {
	case r := <-reply:
		if r.Type == control.TypeTerminalError {
			var e struct {
				Code string `json:"code"`
			}
			_ = r.Unmarshal(&e)
			return nil, &HostError{Code: e.Code}
		}
		return r, nil
	case <-cl.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ErrTimeout
	}
}

func (cl *Client) ready(ctx context.Context, typ string, payload any) (*Session, error) {
	r, err := cl.request(ctx, typ, payload, control.TypeTerminalReady)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := r.Unmarshal(&s); err != nil {
		return nil, err
	}
	cl.mu.Lock()
	recv := cl.out[s.StreamID]
	cl.mu.Unlock()
	// Grant the initial output window: nothing flows until we do.
	if recv != nil {
		_, _ = cl.send(control.TypeFlowCredit, s.ID, control.FlowCredit{StreamID: s.StreamID, Bytes: recv.Initial()})
	}
	return &s, nil
}

// Open starts a new session.
func (cl *Client) Open(ctx context.Context, cols, rows int) (*Session, error) {
	return cl.ready(ctx, control.TypeTerminalOpen, map[string]any{"cols": cols, "rows": rows})
}

// Attach re-attaches to an existing session.
func (cl *Client) Attach(ctx context.Context, id string, cols, rows int) (*Session, error) {
	return cl.ready(ctx, control.TypeTerminalAttach, map[string]any{"terminal_session_id": id, "cols": cols, "rows": rows})
}

// List returns the host's sessions.
func (cl *Client) List(ctx context.Context) ([]Info, error) {
	r, err := cl.request(ctx, control.TypeTerminalList, nil, control.TypeTerminalListRes)
	if err != nil {
		return nil, err
	}
	var out struct {
		Sessions []Info `json:"sessions"`
	}
	return out.Sessions, r.Unmarshal(&out)
}

// Input sends keystrokes, blocking while the host has granted no credit.
func (cl *Client) Input(ctx context.Context, stream uint16, data []byte) error {
	cl.mu.Lock()
	s := cl.in[stream]
	cl.mu.Unlock()
	if s == nil {
		return errors.New("termclient: unknown stream")
	}
	for len(data) > 0 {
		n, err := s.Acquire(ctx, min(len(data), frame.MaxPayload))
		if err != nil {
			if errors.Is(err, flow.ErrClosed) {
				return ErrClosed
			}
			return err
		}
		if err := cl.c.Send(&frame.Frame{Type: frame.TypeInput, StreamID: stream, Payload: data[:n]}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Resize reports a new terminal size.
func (cl *Client) Resize(stream uint16, cols, rows int) error {
	_, err := cl.send(control.TypeTerminalResize, "", map[string]any{"stream_id": stream, "cols": cols, "rows": rows})
	return err
}

// Detach closes the stream; the session keeps running on the host.
func (cl *Client) Detach(stream uint16) error {
	cl.dropStream(stream)
	_, err := cl.send(control.TypeTerminalDetach, "", map[string]any{"stream_id": stream})
	return err
}

// Terminate ends a session's processes (explicit, confirmed action).
func (cl *Client) Terminate(ctx context.Context, id string) error {
	_, err := cl.request(ctx, control.TypeTerminalTerm, map[string]any{"terminal_session_id": id, "confirm": true}, control.TypeTerminalExit)
	return err
}

func (cl *Client) dropStream(id uint16) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if s := cl.in[id]; s != nil {
		s.Close()
	}
	delete(cl.in, id)
	delete(cl.out, id)
}

// Close ends the transport.
func (cl *Client) Close() error {
	err := cl.c.Close()
	select {
	case <-cl.done:
	case <-time.After(2 * time.Second):
	}
	return err
}
