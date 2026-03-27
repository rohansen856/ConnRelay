// Package ptyproc starts a process on a pseudo-terminal and exposes it as a
// byte stream with resize support. Processes are started from an argv slice;
// no shell string is ever constructed.
package ptyproc

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
)

// Size limits for resize requests.
const (
	MinDim = 1
	MaxDim = 1000
)

// ErrSize is returned for out-of-range dimensions.
var ErrSize = errors.New("ptyproc: size out of range")

// Proc is a process attached to a PTY.
type Proc struct {
	cmd  *exec.Cmd
	tty  *os.File
	done chan struct{}
	once sync.Once
	err  error
}

// Start runs argv[0] with argv[1:] on a new PTY of the given size.
func Start(argv []string, env []string, dir string, cols, rows int) (*Proc, error) {
	if len(argv) == 0 {
		return nil, errors.New("ptyproc: empty argv")
	}
	if err := checkSize(cols, rows); err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Dir = dir
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	p := &Proc{cmd: cmd, tty: tty, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

func checkSize(cols, rows int) error {
	if cols < MinDim || rows < MinDim || cols > MaxDim || rows > MaxDim {
		return ErrSize
	}
	return nil
}

// Read reads process output.
func (p *Proc) Read(b []byte) (int, error) { return p.tty.Read(b) }

// Write writes input to the process.
func (p *Proc) Write(b []byte) (int, error) { return p.tty.Write(b) }

// Resize applies TIOCSWINSZ.
func (p *Proc) Resize(cols, rows int) error {
	if err := checkSize(cols, rows); err != nil {
		return err
	}
	return pty.Setsize(p.tty, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

// PID returns the process ID.
func (p *Proc) PID() int { return p.cmd.Process.Pid }

// Done is closed when the process exits.
func (p *Proc) Done() <-chan struct{} { return p.done }

// ExitCode returns the exit status after Done, or -1.
func (p *Proc) ExitCode() int {
	select {
	case <-p.done:
		if p.cmd.ProcessState != nil {
			return p.cmd.ProcessState.ExitCode()
		}
	default:
	}
	return -1
}

// Close sends SIGHUP, waits up to grace, then kills, and closes the PTY.
func (p *Proc) Close(grace time.Duration) error {
	p.once.Do(func() {
		_ = p.cmd.Process.Signal(syscall.SIGHUP)
		select {
		case <-p.done:
		case <-time.After(grace):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		_ = p.tty.Close()
	})
	return nil
}
