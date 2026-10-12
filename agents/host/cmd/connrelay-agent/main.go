// Command connrelay-agent is the ConnRelay host agent.
//
//	connrelay-agent pair --server https://api.example.invalid [--name NAME]
//	connrelay-agent run
//	connrelay-agent status
//	connrelay-agent unpair --local
//	connrelay-agent version
//
// It runs as the logged-in user (never root), normally as a systemd --user
// service with KillMode=process so tmux sessions survive agent restarts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rohansen856/connrelay/agents/host/internal/agentcfg"
	"github.com/rohansen856/connrelay/agents/host/internal/pairclient"
	"github.com/rohansen856/connrelay/agents/host/internal/runtime"
	"github.com/rohansen856/connrelay/agents/host/internal/termserver"
	"github.com/rohansen856/connrelay/agents/host/internal/tmux"
	"github.com/rohansen856/connrelay/core/connrelaycore/attest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "pair":
		err = pair(os.Args[2:])
	case "run":
		err = run()
	case "status":
		err = status()
	case "unpair":
		err = unpair(os.Args[2:])
	case "version":
		fmt.Println("connrelay-agent", runtime.Version)
	default:
		usage()
	}
	if errors.Is(err, runtime.ErrRevoked) {
		fmt.Fprintf(os.Stderr, "connrelay-agent: %v; run `connrelay-agent unpair --local` and pair again\n", err)
		os.Exit(3)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "connrelay-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: connrelay-agent pair --server URL [--name NAME] | run | status | unpair --local | version")
	os.Exit(2)
}

// checkServer requires https, except for loopback servers (development).
func checkServer(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || u.Path != "" {
		return "", errors.New("--server must be a URL like https://api.example.invalid")
	}
	if u.Scheme == "https" {
		return u.String(), nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		return u.String(), nil
	}
	return "", errors.New("--server must use https")
}

func pair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	server := fs.String("server", "", "control plane URL")
	name := fs.String("name", "", "name shown on your phone (default: hostname)")
	asJSON := fs.Bool("json", false, "print the challenge as JSON (automation)")
	_ = fs.Parse(args)
	srv, err := checkServer(*server)
	if err != nil {
		return err
	}
	dir := agentcfg.Dir()
	if _, err := agentcfg.LoadState(dir); err == nil {
		return errors.New("already paired; run `connrelay-agent unpair --local` first")
	}
	key, _, err := agentcfg.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	if *name == "" {
		*name, _ = os.Hostname()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c := &pairclient.Client{Server: srv, HTTP: &http.Client{Timeout: 60 * time.Second}, Key: key, Version: runtime.Version}
	ch, err := c.Create(ctx, *name)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.Marshal(map[string]string{"challenge_id": ch.ID, "pairing_ref": ch.Ref, "display_code": ch.Code,
			"fingerprint": ch.Fingerprint, "qr_payload": ch.QRPayload})
		fmt.Println(string(b))
	} else {
		qr, err := pairclient.RenderQR(ch.QRPayload)
		if err == nil {
			fmt.Println(qr)
		}
		fmt.Printf("Scan the code with the app, or enter:  %s\n", ch.Code)
		fmt.Printf("Computer key fingerprint:            %s\n", groupFP(ch.Fingerprint))
		fmt.Printf("Waiting for approval (expires %s)...\n", ch.ExpiresAt)
	}
	nonce2, err := c.Wait(ctx, ch)
	if err != nil {
		return err
	}
	st, err := c.Complete(ctx, ch, nonce2)
	if err != nil {
		return err
	}
	if err := agentcfg.SaveState(dir, st); err != nil {
		return err
	}
	fmt.Printf("Paired as %q (device %s). Start the agent with `connrelay-agent run` or the systemd unit.\n", *name, st.DeviceID)
	return nil
}

func groupFP(fp string) string {
	var parts []string
	for i := 0; i+4 <= len(fp) && i < 32; i += 4 {
		parts = append(parts, strings.ToUpper(fp[i:i+4]))
	}
	return strings.Join(parts, " ")
}

func socketPath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "connrelay", "tmux.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("connrelay-%d", os.Getuid()), "tmux.sock")
}

func run() error {
	if os.Geteuid() == 0 {
		return errors.New("refusing to run as root; run the agent as the user whose shell it should serve")
	}
	dir := agentcfg.Dir()
	st, err := agentcfg.LoadState(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("not paired; run `connrelay-agent pair --server URL` first")
	}
	if err != nil {
		return err
	}
	key, _, err := agentcfg.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	home, _ := os.UserHomeDir()
	if u, err := user.Current(); err == nil && home == "" {
		home = u.HomeDir
	}
	ag := &runtime.Agent{State: st, Key: key, Log: log, HTTP: &http.Client{Timeout: 30 * time.Second}}
	ts, err := tmux.New(socketPath())
	if err != nil {
		log.Warn("tmux unavailable; terminal sessions are disabled", "err", err)
	} else {
		ag.Terms = termserver.New(termserver.Config{Tmux: ts, Shell: []string{shell, "-l"}, Dir: home,
			Env: os.Environ(), Log: log})
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return ag.Run(ctx)
}

func status() error {
	dir := agentcfg.Dir()
	st, err := agentcfg.LoadState(dir)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Println("not paired")
		return nil
	}
	if err != nil {
		return err
	}
	key, _, err := agentcfg.LoadOrCreateKey(dir)
	if err != nil {
		return err
	}
	fmt.Printf("paired\n  server:      %s\n  device:      %s\n  fingerprint: %s\n", st.Server, st.DeviceID,
		groupFP(attest.Fingerprint(key.PublicKeySPKI())))
	return nil
}

func unpair(args []string) error {
	fs := flag.NewFlagSet("unpair", flag.ExitOnError)
	local := fs.Bool("local", false, "forget the enrolment on this machine")
	_ = fs.Parse(args)
	if !*local {
		return errors.New("revoke the computer from the app, then run `connrelay-agent unpair --local`")
	}
	return agentcfg.RemoveState(agentcfg.Dir())
}
