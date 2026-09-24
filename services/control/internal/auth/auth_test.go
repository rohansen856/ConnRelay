package auth_test

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
	"os"
	"strings"
	"testing"
	"time"

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

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

const clientID = "ios-client"

type env struct {
	t    *testing.T
	srv  *httptest.Server
	pool *pgxpool.Pool
	iss  *googletest.Issuer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := dbtest.New(t)
	iss := googletest.New(t, google.Issuer)
	gv, err := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{clientID}, []string{"owner"}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	svc := &auth.Service{
		Store:  &store.Store{Pool: pool},
		Google: gv,
		Nonces: nonce.New(2*time.Minute, 1000),
		Tokens: &tokens.Manager{Issuer: token.Issuer{KID: "a1", Key: priv}, Keys: token.KeySet{"a1": pub}, ISS: "https://api.test.invalid"},
	}
	mux := http.NewServeMux()
	svc.Routes(mux)
	srv := httptest.NewServer(httpx.WithRequestID(mux))
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, pool: pool, iss: iss}
}

func (e *env) do(method, path, bearer string, body any) (int, map[string]any) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(m map[string]any) string {
	if e, ok := m["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	return ""
}

func (e *env) nonce() string {
	_, m := e.do("POST", "/v1/auth/challenge", "", nil)
	return m["nonce"].(string)
}

// phone is a simulated phone with its own device key.
type phone struct {
	e       *env
	key     *attest.SoftwareSigner
	sub     string
	access  string
	refresh string
	device  string
}

func (e *env) phone(sub string) *phone {
	k, _ := attest.NewSoftwareSigner()
	return &phone{e: e, key: k, sub: sub}
}

func (p *phone) exchangeBody(n string, signer *attest.SoftwareSigner) map[string]any {
	idt := p.e.iss.Token(p.e.t, googletest.Claims{Sub: p.sub, Aud: clientID, Nonce: "oidc-n", Email: "o@example.invalid", EmailVerified: true, Name: "Owner"})
	spki := p.key.PublicKeySPKI()
	sig, _ := attest.SignPoP(signer, attest.PoP{Purpose: attest.PurposeAuth, Nonce: n, SPKIFP: attest.Fingerprint(spki)}, time.Now())
	return map[string]any{
		"provider": "google", "id_token": idt, "oidc_nonce": "oidc-n",
		"device": map[string]any{"platform": "android", "display_name": "Pixel", "app_version": "0.1.0",
			"public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "proto": map[string]int{"min": 1, "max": 1}},
		"pop": map[string]string{"nonce": n, "sig": sig},
	}
}

func (p *phone) signIn() map[string]any {
	p.e.t.Helper()
	code, m := p.e.do("POST", "/v1/auth/exchange", "", p.exchangeBody(p.e.nonce(), p.key))
	if code != 200 {
		p.e.t.Fatalf("exchange: %d %v", code, m)
	}
	p.access, p.refresh, p.device = m["access_token"].(string), m["refresh_token"].(string), m["device_id"].(string)
	return m
}

func (p *phone) refreshBody(refresh string) map[string]any {
	n := p.e.nonce()
	sig, _ := attest.SignPoP(p.key, attest.PoP{Purpose: attest.PurposeRefresh, Nonce: n, DeviceID: p.device}, time.Now())
	return map[string]any{"refresh_token": refresh, "pop": map[string]string{"nonce": n, "sig": sig}}
}

func TestSignInRegistersPhoneWithNoGrants(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	m := p.signIn()
	dev := m["device"].(map[string]any)
	if dev["created"] != true || dev["kind"] != "phone" {
		t.Fatalf("device %v", dev)
	}
	code, me := e.do("GET", "/v1/me", p.access, nil)
	if code != 200 || me["device"].(map[string]any)["id"] != p.device {
		t.Fatalf("me: %d %v", code, me)
	}
	var grants, audits int
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM access_grants`).Scan(&grants)
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type='device_enrolled'`).Scan(&audits)
	if grants != 0 || audits != 1 {
		t.Fatalf("grants %d, enrol audits %d", grants, audits)
	}
}

func TestSameKeyReusesDeviceNewKeyAddsPhone(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	p.signIn()
	first := p.device
	m := p.signIn()
	if p.device != first || m["device"].(map[string]any)["created"] != false {
		t.Fatalf("same key created a new device: %s vs %s", p.device, first)
	}
	q := e.phone("owner")
	q.signIn()
	if q.device == first {
		t.Fatal("second phone shares a device record")
	}
}

func TestNotAllowlistedIsDeniedAndAudited(t *testing.T) {
	e := newEnv(t)
	code, m := e.do("POST", "/v1/auth/exchange", "", e.phone("stranger").exchangeBody(e.nonce(), e.phone("x").key))
	if code != 403 || errCode(m) != "account_not_allowed" {
		t.Fatalf("%d %v", code, m)
	}
	var accounts int
	var meta string
	_ = e.pool.QueryRow(context.Background(), `SELECT count(*) FROM accounts`).Scan(&accounts)
	_ = e.pool.QueryRow(context.Background(), `SELECT metadata::text FROM audit_events WHERE event_type='login_denied'`).Scan(&meta)
	if accounts != 0 {
		t.Fatal("account row written for a denied subject")
	}
	if meta == "" || strings.Contains(meta, "stranger") {
		t.Fatalf("denial audit missing or leaks the subject: %q", meta)
	}
}

func TestNonceAndPossessionChecks(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	n := e.nonce()
	if code, _ := e.do("POST", "/v1/auth/exchange", "", p.exchangeBody(n, p.key)); code != 200 {
		t.Fatal("first use failed")
	}
	if code, m := e.do("POST", "/v1/auth/exchange", "", p.exchangeBody(n, p.key)); errCode(m) != "nonce_invalid" {
		t.Fatalf("nonce replay: %d %v", code, m)
	}
	// Signature made with a different key than the one being registered.
	other, _ := attest.NewSoftwareSigner()
	if code, m := e.do("POST", "/v1/auth/exchange", "", p.exchangeBody(e.nonce(), other)); code != 401 {
		t.Fatalf("forged possession: %d %v", code, m)
	}
	bad := p.exchangeBody(e.nonce(), p.key)
	bad["device"].(map[string]any)["display_name"] = "evil\x1b[2Jname"
	if code, m := e.do("POST", "/v1/auth/exchange", "", bad); errCode(m) != "validation_failed" {
		t.Fatalf("control characters in name: %d %v", code, m)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	p.signIn()
	old := p.refresh
	code, m := e.do("POST", "/v1/auth/refresh", "", p.refreshBody(old))
	if code != 200 {
		t.Fatalf("refresh: %d %v", code, m)
	}
	fresh := m["refresh_token"].(string)
	if fresh == old {
		t.Fatal("refresh token not rotated")
	}
	// A thief replays the old token: the whole family dies.
	if code, m := e.do("POST", "/v1/auth/refresh", "", p.refreshBody(old)); errCode(m) != "refresh_reuse_detected" {
		t.Fatalf("reuse: %d %v", code, m)
	}
	if code, _ := e.do("POST", "/v1/auth/refresh", "", p.refreshBody(fresh)); code != 401 {
		t.Fatal("family survived reuse detection")
	}
	if code, _ := e.do("GET", "/v1/me", m["access_token"].(string), nil); code == 200 {
		t.Fatal("access token of revoked family still works")
	}
}

func TestRefreshIsDeviceBound(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	p.signIn()
	thief := e.phone("owner")
	thief.device = p.device
	if code, _ := e.do("POST", "/v1/auth/refresh", "", thief.refreshBody(p.refresh)); code != 401 {
		t.Fatal("stolen refresh token worked without the device key")
	}
}

func TestLogoutOnlyAffectsThisPhone(t *testing.T) {
	e := newEnv(t)
	a, b := e.phone("owner"), e.phone("owner")
	a.signIn()
	b.signIn()
	if code, _ := e.do("POST", "/v1/auth/logout", a.access, nil); code != 204 {
		t.Fatal("logout failed")
	}
	if code, _ := e.do("GET", "/v1/me", a.access, nil); code != 401 {
		t.Fatal("logged-out phone still authorised")
	}
	if code, _ := e.do("GET", "/v1/me", b.access, nil); code != 200 {
		t.Fatal("logout affected another phone")
	}
}

func TestRevokedDeviceLosesAccessImmediately(t *testing.T) {
	e := newEnv(t)
	p := e.phone("owner")
	p.signIn()
	if _, err := e.pool.Exec(context.Background(), `UPDATE devices SET admin_state='revoked', revoked_at=now(), revoke_reason='lost' WHERE id=$1`, p.device); err != nil {
		t.Fatal(err)
	}
	if code, m := e.do("GET", "/v1/me", p.access, nil); errCode(m) != "device_revoked" {
		t.Fatalf("revoked device with a valid access token: %d %v", code, m)
	}
	if code, m := e.do("POST", "/v1/auth/refresh", "", p.refreshBody(p.refresh)); errCode(m) != "device_revoked" {
		t.Fatalf("revoked device refresh: %d %v", code, m)
	}
}

func TestBearerRequired(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "garbage", "a.b.c"} {
		if code, m := e.do("GET", "/v1/me", tok, nil); code != 401 || errCode(m) != "unauthenticated" {
			t.Fatalf("token %q: %d %v", tok, code, m)
		}
	}
}
