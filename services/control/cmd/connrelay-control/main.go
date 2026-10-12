// Command connrelay-control runs the ConnRelay control plane.
//
//	connrelay-control serve          run the server (default)
//	connrelay-control check-config   validate configuration and exit
//	connrelay-control keygen DIR     write signing keys and secrets for a new install
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rohansen856/connrelay/services/control/internal/config"
	"github.com/rohansen856/connrelay/services/control/internal/db"
	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/server"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "check-config":
		_, err = config.Load(os.Getenv)
		if err == nil {
			fmt.Println("configuration OK")
		}
	case "keygen":
		if len(os.Args) != 3 {
			err = errors.New("usage: connrelay-control keygen DIR")
		} else {
			err = keygen(os.Args[2])
		}
	default:
		err = fmt.Errorf("unknown command %q (serve, check-config, keygen)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "connrelay-control:", err)
		os.Exit(1)
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	level := map[string]slog.Level{"debug": slog.LevelDebug, "info": slog.LevelInfo, "warn": slog.LevelWarn, "error": slog.LevelError}[cfg.LogLevel]
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	gv, err := google.New(ctx, cfg.GoogleClients, cfg.AllowedSubs)
	if err != nil {
		return err
	}
	srv := server.New(cfg, pool, gv, log)
	srv.Start(ctx)
	hs := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("connrelay-control listening", "addr", cfg.ListenAddr, "public_base_url", cfg.PublicBaseURL)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdown)
}

func keygen(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	write := func(name string, b []byte) error {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists; refusing to overwrite", p)
		}
		return os.WriteFile(p, b, 0o600)
	}
	for _, name := range []string{"access_signing_key.pem", "ticket_signing_key.pem"} {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		b, err := config.EncodeKey(k)
		if err != nil {
			return err
		}
		if err := write(name, b); err != nil {
			return err
		}
	}
	for _, name := range []string{"pairing_hmac_key", "turn_shared_secret"} {
		b := make([]byte, 48)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		// coturn reads static-auth-secret as text, so use printable hex.
		if err := write(name, []byte(fmt.Sprintf("%x", b))); err != nil {
			return err
		}
	}
	fmt.Println("wrote keys and secrets to", dir)
	return nil
}
