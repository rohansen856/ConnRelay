// Package server assembles the control plane: REST API, agent control and
// phone signaling sockets, the WSS relay, the outbox worker and health
// endpoints.
package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/config"
	"github.com/rohansen856/connrelay/services/control/internal/connections"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/hub"
	"github.com/rohansen856/connrelay/services/control/internal/inventory"
	"github.com/rohansen856/connrelay/services/control/internal/nonce"
	"github.com/rohansen856/connrelay/services/control/internal/outbox"
	"github.com/rohansen856/connrelay/services/control/internal/pairing"
	"github.com/rohansen856/connrelay/services/control/internal/relay"
	"github.com/rohansen856/connrelay/services/control/internal/store"
	"github.com/rohansen856/connrelay/services/control/internal/tokens"
	"golang.org/x/time/rate"
)

// Server is a running control plane.
type Server struct {
	Handler http.Handler
	Hub     *hub.Hub
	Worker  *outbox.Worker
	pool    *pgxpool.Pool
}

// New wires every component. verifier checks Google ID tokens.
func New(cfg *config.Config, pool *pgxpool.Pool, verifier auth.IDTokenVerifier, log *slog.Logger) *Server {
	st := &store.Store{Pool: pool}
	ticketPub := cfg.TicketKey.Public().(ed25519.PublicKey)
	ticketKID := cfg.TicketKeyIDs[0]
	accessPub := cfg.AccessKey.Public().(ed25519.PublicKey)
	accessKID := config.KeyID(accessPub)
	ticket := token.Issuer{KID: ticketKID, Key: cfg.TicketKey}

	jwk := func() []pairing.JWK {
		return []pairing.JWK{{KID: ticketKID, KTY: "OKP", CRV: "Ed25519", X: base64.RawURLEncoding.EncodeToString(ticketPub), Use: "sig"}}
	}
	// wss for https deployments; ws only for local http (development, tests).
	wsBase := "wss://" + strings.TrimPrefix(cfg.PublicBaseURL, "https://")
	if strings.HasPrefix(cfg.PublicBaseURL, "http://") {
		wsBase = "ws://" + strings.TrimPrefix(cfg.PublicBaseURL, "http://")
	}

	a := &auth.Service{Store: st, Google: verifier, Log: log, Nonces: nonce.New(2*time.Minute, 100000),
		Tokens: &tokens.Manager{Issuer: token.Issuer{KID: accessKID, Key: cfg.AccessKey}, Keys: token.KeySet{accessKID: accessPub}, ISS: cfg.PublicBaseURL}}
	h := &hub.Hub{Store: st, Auth: a, Ticket: ticket, Log: log, JWKS: func() any { return map[string]any{"keys": jwk()} }}
	w := &outbox.Worker{Store: st, Hub: h, Log: log}
	conns := &connections.Service{Store: st, Auth: a, Hub: h, Ticket: ticket, ISS: cfg.PublicBaseURL, TURNSecret: cfg.TURNSecret,
		STUNURLs: cfg.STUNURLs, TURNURLs: cfg.TURNURLs, RelayURL: wsBase + "/v1/relay", SignalingURL: wsBase + "/v1/signaling"}
	h.OnAttemptStatus = conns.AgentStatus

	rcfg := relay.DefaultConfig()
	rcfg.BytesPerSec, rcfg.MaxBytes = cfg.RelayMaxBPS, cfg.RelayMaxBytes
	rel := relay.New(rcfg, token.KeySet{ticketKID: ticketPub}, log)

	mux := http.NewServeMux()
	a.Routes(mux)
	(&inventory.Service{Store: st, Auth: a, Live: h, Notify: w}).Routes(mux)
	(&pairing.Service{Store: st, Auth: a, Pepper: cfg.PairingPepper, APIURL: cfg.PublicBaseURL,
		ControlWS: wsBase + "/v1/agent/control", JWKS: jwk}).Routes(mux)
	conns.Routes(mux)
	mux.HandleFunc("GET /v1/agent/control", h.ServeAgent)
	mux.HandleFunc("GET /v1/signaling", h.ServePhone)
	mux.Handle("GET /v1/relay", rel)
	mux.HandleFunc("GET /v1/meta/compat", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"protocol": map[string]int{"min": 1, "max": 1}, "server": "prw-control"})
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready"))
	})

	limited := ipLimit(mux, map[string]rate.Limit{
		"/v1/auth/challenge":     rate.Every(2 * time.Second),
		"/v1/auth/exchange":      rate.Every(6 * time.Second),
		"/v1/pairing/challenges": rate.Every(2 * time.Minute),
	})
	return &Server{Handler: httpx.WithRequestID(recoverer(limited, log)), Hub: h, Worker: w, pool: pool}
}

// Start runs background workers until ctx ends.
func (s *Server) Start(ctx context.Context) { go s.Worker.Run(ctx) }

func recoverer(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Error("panic", "path", r.URL.Path, "panic", v)
				httpx.WriteError(w, r, httpx.ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ipLimit applies per-IP token buckets to unauthenticated POST endpoints.
// The service runs behind Caddy on loopback, so the client IP is the
// rightmost X-Forwarded-For hop when the peer is a loopback address.
func ipLimit(next http.Handler, limits map[string]rate.Limit) http.Handler {
	var mu sync.Mutex
	buckets := map[string]*rate.Limiter{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lim, ok := limits[r.URL.Path]
		if !ok || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		key := r.URL.Path + "|" + clientIP(r)
		mu.Lock()
		if len(buckets) > 100000 {
			buckets = map[string]*rate.Limiter{} // crude bound; limits reset under flood
		}
		b := buckets[key]
		if b == nil {
			b = rate.NewLimiter(lim, 10)
			buckets[key] = b
		}
		mu.Unlock()
		if !b.Allow() {
			w.Header().Set("Retry-After", "10")
			httpx.WriteError(w, r, &httpx.Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many requests.", Retryable: true})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}
