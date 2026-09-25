// Package apitest wires a complete control-plane HTTP server on a fresh test
// database, with simulated phones that sign in through the real endpoints.
// TEST ONLY.
package apitest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/token"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/google/googletest"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/nonce"
	"github.com/rohansen856/connrelay/services/control/internal/store"
	"github.com/rohansen856/connrelay/services/control/internal/tokens"
)

// ClientID is the Google client ID accepted by the test server.
const ClientID = "test-client"

// Allowed lists the Google subjects allowed to sign in.
var Allowed = []string{"owner", "owner2"}

// Env is a running test server.
type Env struct {
	T      testing.TB
	Pool   *pgxpool.Pool
	Store  *store.Store
	Auth   *auth.Service
	Mux    *http.ServeMux
	Server *httptest.Server
	Issuer *googletest.Issuer
	// TicketKey signs tickets, leases and relay tokens.
	TicketKey token.Issuer
	TicketPub ed25519.PublicKey
}

// New starts a server with the auth routes. Callers add their own routes to
// Mux before making requests.
func New(t testing.TB) *Env {
	t.Helper()
	pool := dbtest.New(t)
	iss := googletest.New(t, google.Issuer)
	gv, err := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{ClientID}, Allowed, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apub, apriv, _ := ed25519.GenerateKey(rand.Reader)
	tpub, tpriv, _ := ed25519.GenerateKey(rand.Reader)
	st := &store.Store{Pool: pool}
	a := &auth.Service{Store: st, Google: gv, Nonces: nonce.New(2*time.Minute, 10000),
		Tokens: &tokens.Manager{Issuer: token.Issuer{KID: "a1", Key: apriv}, Keys: token.KeySet{"a1": apub}, ISS: "https://api.test.invalid"}}
	mux := http.NewServeMux()
	a.Routes(mux)
	srv := httptest.NewServer(httpx.WithRequestID(mux))
	t.Cleanup(srv.Close)
	return &Env{T: t, Pool: pool, Store: st, Auth: a, Mux: mux, Server: srv, Issuer: iss,
		TicketKey: token.Issuer{KID: "t1", Key: tpriv}, TicketPub: tpub}
}

// Resp is a decoded JSON response.
type Resp struct {
	Status int
	Header http.Header
	Body   map[string]any
}

// Code returns the error code of an error response.
func (r Resp) Code() string {
	if e, ok := r.Body["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	return ""
}

// Version returns the ETag version.
func (r Resp) Version() int {
	v, _ := strconv.Atoi(string(bytes.Trim([]byte(r.Header.Get("ETag")), `"`)))
	return v
}

// Do performs a JSON request.
func (e *Env) Do(method, path, bearer string, body any, hdr ...string) Resp {
	e.T.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.Server.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.T.Fatal(err)
	}
	defer resp.Body.Close()
	out := Resp{Status: resp.StatusCode, Header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&out.Body)
	return out
}

// Phone is a simulated phone.
type Phone struct {
	E       *Env
	Key     *attest.SoftwareSigner
	Sub     string
	Access  string
	Refresh string
	ID      uuid.UUID
	Account uuid.UUID
}

// SignIn creates a phone with a fresh key and signs it in as sub.
func (e *Env) SignIn(sub string) *Phone {
	e.T.Helper()
	k, _ := attest.NewSoftwareSigner()
	p := &Phone{E: e, Key: k, Sub: sub}
	nr := e.Do("POST", "/v1/auth/challenge", "", nil)
	n := nr.Body["nonce"].(string)
	spki := k.PublicKeySPKI()
	sig, _ := attest.SignPoP(k, attest.PoP{Purpose: attest.PurposeAuth, Nonce: n, SPKIFP: attest.Fingerprint(spki)}, time.Now())
	idt := e.Issuer.Token(e.T, googletest.Claims{Sub: sub, Aud: ClientID, Nonce: "oidc", Name: sub})
	r := e.Do("POST", "/v1/auth/exchange", "", map[string]any{
		"provider": "google", "id_token": idt, "oidc_nonce": "oidc",
		"device": map[string]any{"platform": "android", "display_name": "phone-" + sub, "app_version": "0.1.0",
			"public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "proto": map[string]int{"min": 1, "max": 1}},
		"pop": map[string]string{"nonce": n, "sig": sig},
	})
	if r.Status != 200 {
		e.T.Fatalf("sign in %s: %d %v", sub, r.Status, r.Body)
	}
	p.Access, p.Refresh = r.Body["access_token"].(string), r.Body["refresh_token"].(string)
	p.ID = uuid.MustParse(r.Body["device_id"].(string))
	p.Account = uuid.MustParse(r.Body["account"].(map[string]any)["id"].(string))
	return p
}

// Do performs a request as this phone.
func (p *Phone) Do(method, path string, body any, hdr ...string) Resp {
	p.E.T.Helper()
	return p.E.Do(method, path, p.Access, body, hdr...)
}

// Host is an enrolled host inserted directly (pairing is tested separately).
type Host struct {
	ID  uuid.UUID
	Key *attest.SoftwareSigner
}

// AddHost enrolls a host for the account directly in the database.
func (e *Env) AddHost(account uuid.UUID, name string) *Host {
	e.T.Helper()
	k, _ := attest.NewSoftwareSigner()
	spki := k.PublicKeySPKI()
	d, err := store.InsertDevice(context.Background(), e.Pool, store.NewDevice{AccountID: account, Kind: "host",
		Platform: "linux", DisplayName: name, PublicKey: spki, KeyFingerprint: attest.Fingerprint(spki), SoftwareVersion: "0.1.0"})
	if err != nil {
		e.T.Fatal(err)
	}
	return &Host{ID: d.ID, Key: k}
}
