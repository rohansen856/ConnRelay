// Package tmux manages ConnRelay sessions as tmux sessions on a private socket.
//
// Each ConnRelay terminal session is one tmux session named "connrelay-<id>". A phone
// attaches by running "tmux attach" inside a PTY owned by the agent; tmux
// redraws the full screen on every attach, so reconnects need no replay
// buffer. The tmux server is a separate process: when the agent runs under
// systemd with KillMode=process it survives agent restarts.
package tmux

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// MinVersion is the oldest supported tmux (major, minor).
var MinVersion = [2]int{3, 0}

// ErrUnavailable is returned when tmux is missing or too old.
var ErrUnavailable = errors.New("tmux_unavailable")

// ErrNotFound is returned for an unknown session.
var ErrNotFound = errors.New("session_not_found")

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Server is a tmux server reachable through a private socket.
type Server struct {
	Bin    string // tmux binary
	Socket string // e.g. $XDG_RUNTIME_DIR/connrelay/tmux.sock
}

// New returns a server for socket, checking that tmux is usable.
func New(socket string) (*Server, error) {
	bin, err := exec.LookPath("tmux")
	if err != nil {
		return nil, ErrUnavailable
	}
	out, err := exec.Command(bin, "-V").Output()
	if err != nil {
		return nil, ErrUnavailable
	}
	if !versionOK(string(out)) {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.TrimSpace(string(out)))
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return nil, err
	}
	return &Server{Bin: bin, Socket: socket}, nil
}

func versionOK(v string) bool {
	m := regexp.MustCompile(`(\d+)\.(\d+)`).FindStringSubmatch(v)
	if m == nil {
		return strings.Contains(v, "next-") || strings.Contains(v, "master")
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj > MinVersion[0] || (maj == MinVersion[0] && min >= MinVersion[1])
}

// Name returns the tmux session name for a ConnRelay session ID.
func Name(id string) string { return "connrelay-" + id }

func (s *Server) cmd(args ...string) *exec.Cmd {
	// -f /dev/null: never load the user's tmux.conf into the ConnRelay server, so
	// behaviour is predictable. -S: private socket, not the user's default.
	return exec.Command(s.Bin, append([]string{"-f", "/dev/null", "-S", s.Socket}, args...)...)
}

func (s *Server) run(args ...string) (string, error) {
	var stderr bytes.Buffer
	c := s.cmd(args...)
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("tmux %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// NewSession creates a detached session running argv in dir.
func (s *Server) NewSession(id string, argv []string, dir string, cols, rows int) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("tmux: invalid session id %q", id)
	}
	args := []string{"new-session", "-d", "-s", Name(id), "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows)}
	if dir != "" {
		args = append(args, "-c", dir)
	}
	args = append(args, "--")
	args = append(args, argv...)
	if _, err := s.run(args...); err != nil {
		return err
	}
	for _, opt := range [][]string{
		{"set-option", "-t", Name(id), "status", "off"},
		{"set-option", "-t", Name(id), "history-limit", "50000"},
		{"set-option", "-t", Name(id), "remain-on-exit", "off"},
		{"set-window-option", "-t", Name(id), "window-size", "latest"},
		{"set-window-option", "-t", Name(id), "aggressive-resize", "on"},
	} {
		if _, err := s.run(opt...); err != nil {
			return err
		}
	}
	return nil
}

// Info describes one tmux-backed session.
type Info struct {
	ID       string
	PanePID  int
	Created  int64
	Attached int
}

// List returns ConnRelay sessions on this server.
func (s *Server) List() ([]Info, error) {
	out, err := s.run("list-sessions", "-F", "#{session_name}\t#{pane_pid}\t#{session_created}\t#{session_attached}")
	if err != nil {
		if strings.Contains(err.Error(), "no server running") || strings.Contains(err.Error(), "No such file") ||
			strings.Contains(err.Error(), "error connecting") {
			return nil, nil
		}
		return nil, err
	}
	var res []Info
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) != 4 || !strings.HasPrefix(f[0], "connrelay-") {
			continue
		}
		pid, _ := strconv.Atoi(f[1])
		created, _ := strconv.ParseInt(f[2], 10, 64)
		att, _ := strconv.Atoi(f[3])
		res = append(res, Info{ID: strings.TrimPrefix(f[0], "connrelay-"), PanePID: pid, Created: created, Attached: att})
	}
	return res, nil
}

// Get returns one session.
func (s *Server) Get(id string) (Info, error) {
	all, err := s.List()
	if err != nil {
		return Info{}, err
	}
	for _, i := range all {
		if i.ID == id {
			return i, nil
		}
	}
	return Info{}, ErrNotFound
}

// AttachArgv returns the argv that attaches to a session; the agent runs it
// inside its own PTY. Killing that client only detaches.
func (s *Server) AttachArgv(id string) []string {
	return []string{s.Bin, "-f", "/dev/null", "-S", s.Socket, "attach-session", "-t", Name(id)}
}

// AttachEnv returns base without variables that would make tmux treat the
// attach as nested, with TERM set for the phone's terminal emulator.
func AttachEnv(base []string, term string) []string {
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if strings.HasPrefix(kv, "TMUX=") || strings.HasPrefix(kv, "TMUX_PANE=") || strings.HasPrefix(kv, "TERM=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "TERM="+term)
}

// Kill terminates a session (explicit terminate only).
func (s *Server) Kill(id string) error {
	if _, err := s.Get(id); err != nil {
		return err
	}
	_, err := s.run("kill-session", "-t", Name(id))
	return err
}

// KillServer stops the private tmux server (tests and uninstall only).
func (s *Server) KillServer() { _, _ = s.run("kill-server") }
