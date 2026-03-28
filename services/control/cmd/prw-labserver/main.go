// Command prw-labserver is a network-lab stand-in for the control plane. It
// issues connection-attempt bundles (ticket, relay tokens, TURN credentials,
// attestation nonce), relays signaling between the phone and host of an
// attempt, and serves the production /v1/relay splicer over TLS.
//
// It has no accounts, pairing or authorization and must never be exposed
// outside a test network.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/services/control/internal/relay"
	"github.com/rohansen856/connrelay/services/control/internal/turncred"
)

// ICEServer mirrors the WebRTC ICE server shape.
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Bundle is what each side receives for one attempt.
type Bundle struct {
	AttemptID   string      `json:"attempt_id"`
	Role        string      `json:"role"` // phone or host
	Nonce       string      `json:"attestation_nonce"`
	Ticket      string      `json:"ticket"`
	TicketKey   string      `json:"ticket_pubkey"` // base64 Ed25519 (host pins this)
	RelayURL    string      `json:"relay_url"`
	RelayToken  string      `json:"relay_token"`
	SignalURL   string      `json:"signal_url"`
	ICEServers  []ICEServer `json:"ice_servers"`
	PhoneDevice string      `json:"phone_device_id"`
	HostDevice  string      `json:"host_device_id"`
}

type lab struct {
	issuer     token.Issuer
	pub        ed25519.PublicKey
	turnSecret []byte
	turnURLs   []string
	stunURLs   []string
	publicURL  string

	mu         sync.Mutex
	waiting    chan Bundle // host bundles waiting for the host to pick up
	signals    map[string]map[string]*websocket.Conn
	pendingSig map[string][][]byte // messages for a role not yet connected
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (l *lab) newAttempt() (phone, host Bundle) {
	now := time.Now()
	att := "att-" + rnd(8)
	nonce := base64.RawURLEncoding.EncodeToString([]byte(rnd(16)))
	reg := func(ttl time.Duration) token.Registered {
		return token.Registered{IAT: now.Unix(), NBF: now.Unix(), EXP: now.Add(ttl).Unix(), JTI: rnd(16)}
	}
	ticket, _ := l.issuer.Issue(token.TypeTicket, token.Ticket{
		Registered: reg(60 * time.Second), ISS: l.publicURL, AUD: "host-lab", SUB: "phone-lab",
		Acct: "acct-lab", Att: att, Cap: "terminal", Nonce: nonce, PV: 1,
	})
	relayTok := func(role, dev string) string {
		s, _ := l.issuer.Issue(token.TypeRelay, token.Relay{Registered: reg(90 * time.Second), Att: att, Role: role, Dev: dev})
		return s
	}
	cred := turncred.Issue(l.turnSecret, att, now, turncred.DefaultTTL)
	var ice []ICEServer
	if len(l.stunURLs) > 0 {
		ice = append(ice, ICEServer{URLs: l.stunURLs})
	}
	if len(l.turnURLs) > 0 {
		ice = append(ice, ICEServer{URLs: l.turnURLs, Username: cred.Username, Credential: cred.Credential})
	}
	base := Bundle{
		AttemptID: att, Nonce: nonce, Ticket: ticket, TicketKey: base64.StdEncoding.EncodeToString(l.pub),
		RelayURL:   strings.Replace(l.publicURL, "https://", "wss://", 1) + "/v1/relay",
		SignalURL:  strings.Replace(l.publicURL, "https://", "wss://", 1) + "/lab/signal",
		ICEServers: ice, PhoneDevice: "phone-lab", HostDevice: "host-lab",
	}
	phone, host = base, base
	phone.Role, phone.RelayToken = "phone", relayTok(token.RoleClient, "phone-lab")
	host.Role, host.RelayToken = "host", relayTok(token.RoleServer, "host-lab")
	return phone, host
}

// POST /lab/attempt (phone): returns the phone bundle and queues the host's.
func (l *lab) attempt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	phone, host := l.newAttempt()
	select {
	case l.waiting <- host:
	default:
		http.Error(w, "host queue full", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(phone)
}

// GET /lab/next (host): long-polls for the next attempt.
func (l *lab) next(w http.ResponseWriter, r *http.Request) {
	select {
	case b := <-l.waiting:
		json.NewEncoder(w).Encode(b)
	case <-time.After(60 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
	}
}

// /lab/signal?attempt=..&role=phone|host forwards text messages to the other role.
func (l *lab) signal(w http.ResponseWriter, r *http.Request) {
	att, role := r.URL.Query().Get("attempt"), r.URL.Query().Get("role")
	if att == "" || (role != "phone" && role != "host") {
		http.Error(w, "bad params", http.StatusBadRequest)
		return
	}
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(64 * 1024)
	other := "host"
	if role == "host" {
		other = "phone"
	}
	l.mu.Lock()
	if l.signals[att] == nil {
		l.signals[att] = map[string]*websocket.Conn{}
	}
	l.signals[att][role] = ws
	queued := l.pendingSig[att+"/"+role]
	delete(l.pendingSig, att+"/"+role)
	l.mu.Unlock()
	ctx := r.Context()
	for _, m := range queued {
		_ = ws.Write(ctx, websocket.MessageText, m)
	}
	defer func() {
		l.mu.Lock()
		delete(l.signals[att], role)
		if len(l.signals[att]) == 0 {
			delete(l.signals, att)
		}
		l.mu.Unlock()
		ws.CloseNow()
	}()
	for {
		_, msg, err := ws.Read(ctx)
		if err != nil {
			return
		}
		l.mu.Lock()
		peer := l.signals[att][other]
		if peer == nil {
			l.pendingSig[att+"/"+other] = append(l.pendingSig[att+"/"+other], msg)
		}
		l.mu.Unlock()
		if peer != nil {
			wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = peer.Write(wctx, websocket.MessageText, msg)
			cancel()
		}
	}
}

func selfSigned(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "prw-lab"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     hosts,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	addr := flag.String("addr", ":443", "listen address")
	public := flag.String("public-url", "https://api.lab.invalid", "base URL peers use")
	turnURLs := flag.String("turn-urls", "", "comma-separated TURN URLs")
	stunURLs := flag.String("stun-urls", "", "comma-separated STUN URLs")
	plain := flag.Bool("plain", false, "serve plain HTTP (local runs only)")
	certFile := flag.String("tls-cert", "", "PEM certificate (default: generated self-signed)")
	keyFile := flag.String("tls-key", "", "PEM private key")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	secret := os.Getenv("PRW_TURN_SHARED_SECRET")
	if secret == "" {
		log.Error("PRW_TURN_SHARED_SECRET is required")
		os.Exit(2)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	}
	l := &lab{
		issuer: token.Issuer{KID: "lab-1", Key: priv}, pub: pub, turnSecret: []byte(secret),
		turnURLs: split(*turnURLs), stunURLs: split(*stunURLs), publicURL: strings.TrimRight(*public, "/"),
		waiting: make(chan Bundle, 16), signals: map[string]map[string]*websocket.Conn{}, pendingSig: map[string][][]byte{},
	}
	rs := relay.New(relay.DefaultConfig(), token.KeySet{"lab-1": pub}, log)
	mux := http.NewServeMux()
	mux.Handle("/v1/relay", rs)
	mux.HandleFunc("/lab/attempt", l.attempt)
	mux.HandleFunc("/lab/next", l.next)
	mux.HandleFunc("/lab/signal", l.signal)
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/lab/stats", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]int64{
			"relay_joins": rs.Stats.Joins.Load(), "relay_rejects": rs.Stats.Rejects.Load(),
			"relay_splices": rs.Stats.Splices.Load(), "relay_bytes": rs.Stats.Bytes.Load(),
		})
	})
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Info("prw-labserver listening", "addr", *addr, "public_url", l.publicURL, "turn_urls", l.turnURLs)
	var err error
	if *plain {
		err = srv.ListenAndServe()
	} else if *certFile != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		host := strings.TrimPrefix(strings.TrimPrefix(l.publicURL, "https://"), "http://")
		cert, cerr := selfSigned([]string{strings.Split(host, ":")[0]})
		if cerr != nil {
			log.Error("cert", "err", cerr)
			os.Exit(1)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		err = srv.ListenAndServeTLS("", "")
	}
	log.Error("server stopped", "err", err)
	os.Exit(1)
}
