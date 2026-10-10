// Package e2e runs the whole system: the assembled control plane on a real
// PostgreSQL database, the real prw-agent binary (pairing, control socket,
// tmux terminals) and a phone built on prwcore/client. Nothing is mocked
// except Google, whose ID tokens come from a local test issuer.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/core/prwcore/client"
	"github.com/rohansen856/connrelay/core/prwcore/mobile"
	"github.com/rohansen856/connrelay/core/prwcore/termclient"
	"github.com/rohansen856/connrelay/core/prwcore/transport"
	"github.com/rohansen856/connrelay/services/control/internal/config"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/google"
	"github.com/rohansen856/connrelay/services/control/internal/google/googletest"
	"github.com/rohansen856/connrelay/services/control/internal/server"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

type world struct {
	t     *testing.T
	url   string
	iss   *googletest.Issuer
	agent string // path to the built prw-agent
	dir   string
}

func newWorld(t *testing.T) *world {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not installed")
	}
	pool := dbtest.New(t)
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)
	_, ak, _ := ed25519.GenerateKey(rand.Reader)
	_, tk, _ := ed25519.GenerateKey(rand.Reader)
	cfg := &config.Config{PublicBaseURL: ts.URL, AccessKey: ak, TicketKey: tk,
		TicketKeyIDs: []string{config.KeyID(tk.Public().(ed25519.PublicKey))}, PairingPepper: []byte("TEST-ONLY-pepper-0123456789abcdef"),
		TURNSecret: []byte("TEST-ONLY"), TURNURLs: []string{"turn:127.0.0.1:1?transport=udp"}, RelayMaxBPS: 1 << 24, RelayMaxBytes: 1 << 30}
	iss := googletest.New(t, google.Issuer)
	gv, _ := google.NewWithKeySet(google.Issuer, iss.KeySet(), []string{"app"}, []string{"owner"}, time.Now)
	srv := server.New(cfg, pool, gv, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Start(ctx)
	ts.Config.Handler = srv.Handler

	dir := t.TempDir()
	bin := filepath.Join(dir, "prw-agent")
	build := exec.Command("go", "build", "-o", bin, "./agents/host/cmd/prw-agent")
	build.Dir = filepath.Join("..", "..", "..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v\n%s", err, out)
	}
	return &world{t: t, url: ts.URL, iss: iss, agent: bin, dir: dir}
}

// ---- phone ----

type phone struct {
	w       *world
	key     *attest.SoftwareSigner
	access  string
	id      string
	account string
}

func (w *world) call(method, path, bearer string, body any, hdr ...string) (int, map[string]any, http.Header) {
	w.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, w.url+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (w *world) signIn() *phone {
	k, _ := attest.NewSoftwareSigner()
	_, ch, _ := w.call("POST", "/v1/auth/challenge", "", nil)
	n := ch["nonce"].(string)
	spki := k.PublicKeySPKI()
	sig, _ := attest.SignPoP(k, attest.PoP{Purpose: attest.PurposeAuth, Nonce: n, SPKIFP: attest.Fingerprint(spki)}, time.Now())
	code, r, _ := w.call("POST", "/v1/auth/exchange", "", map[string]any{
		"provider": "google", "id_token": w.iss.Token(w.t, googletest.Claims{Sub: "owner", Aud: "app", Nonce: "o"}), "oidc_nonce": "o",
		"device": map[string]any{"platform": "android", "display_name": "test phone", "app_version": "0.1.0",
			"public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "proto": map[string]int{"min": 1, "max": 1}},
		"pop": map[string]string{"nonce": n, "sig": sig}})
	if code != 200 {
		w.t.Fatalf("sign in: %d %v", code, r)
	}
	return &phone{w: w, key: k, access: r["access_token"].(string), id: r["device_id"].(string),
		account: r["account"].(map[string]any)["id"].(string)}
}

func (p *phone) cfg(mode string) client.Config {
	return client.Config{API: p.w.url, HTTP: &http.Client{Timeout: 30 * time.Second}, AccessToken: p.access, DeviceID: p.id,
		Signer: p.key, Mode: mode}
}

// ---- agent process ----

func (w *world) env() []string {
	run := filepath.Join(w.dir, "run")
	_ = os.MkdirAll(run, 0o700)
	return append(os.Environ(), "PRW_AGENT_CONFIG_DIR="+filepath.Join(w.dir, "cfg"), "XDG_RUNTIME_DIR="+run, "SHELL=/bin/sh", "HOME="+w.dir)
}

// pair runs `prw-agent pair`, approves it from the phone after checking the
// QR fingerprint, and returns the host's device ID and pinned fingerprint.
func (w *world) pair(p *phone) (hostID, fp string) {
	w.t.Helper()
	cmd := exec.Command(w.agent, "pair", "--server", w.url, "--name", "e2e-host", "--json")
	cmd.Env = w.env()
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	sc := bufio.NewScanner(stdout)
	if !sc.Scan() {
		w.t.Fatalf("pair produced no output: %s", stderr.String())
	}
	var ch struct {
		ID, Ref, Fingerprint string
	}
	var raw map[string]string
	_ = json.Unmarshal(sc.Bytes(), &raw)
	ch.ID, ch.Ref, ch.Fingerprint = raw["challenge_id"], raw["pairing_ref"], raw["fingerprint"]

	code, res, _ := w.call("POST", "/v1/pairing/resolve", p.access, map[string]string{"pairing_ref": ch.Ref})
	if code != 200 || res["host_key_fingerprint"] != ch.Fingerprint {
		w.t.Fatalf("resolve: %d %v (QR fingerprint %s)", code, res, ch.Fingerprint)
	}
	if code, r, _ := w.call("POST", "/v1/pairing/challenges/"+ch.ID+"/approve", p.access,
		map[string]any{"host_key_fingerprint": ch.Fingerprint, "grant_to_this_phone": true}); code != 200 {
		w.t.Fatalf("approve: %d %v", code, r)
	}
	var rest strings.Builder
	for sc.Scan() {
		rest.WriteString(sc.Text())
	}
	if err := cmd.Wait(); err != nil {
		w.t.Fatalf("pair failed: %v\n%s\n%s", err, rest.String(), stderr.String())
	}
	m := regexp.MustCompile(`device ([0-9a-f-]{36})`).FindStringSubmatch(rest.String())
	if m == nil {
		w.t.Fatalf("no device id in %q", rest.String())
	}
	return m[1], ch.Fingerprint
}

func (w *world) startAgent() *exec.Cmd {
	cmd := exec.Command(w.agent, "run")
	cmd.Env = w.env()
	var logs syncBuf
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = exec.Command("tmux", "-S", filepath.Join(w.dir, "run", "prw", "tmux.sock"), "kill-server").Run()
		if w.t.Failed() {
			w.t.Logf("agent log:\n%s", logs.String())
		}
	})
	return cmd
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func (w *world) waitOnline(p *phone, host string) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, d, _ := w.call("GET", "/v1/devices/"+host, p.access, nil)
		if d["presence"] == "online" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	w.t.Fatal("agent never came online")
}

// ---- terminal (phone side, via prwcore/termclient) ----

type screen struct {
	t      *testing.T
	mu     sync.Mutex
	out    bytes.Buffer
	closed chan struct{}
	once   sync.Once
}

func newScreen(t *testing.T) *screen { return &screen{t: t, closed: make(chan struct{})} }

func (s *screen) Output(_ uint16, b []byte) { s.mu.Lock(); s.out.Write(b); s.mu.Unlock() }
func (s *screen) Event(kind, _ string) {
	if kind == "closed" {
		s.once.Do(func() { close(s.closed) })
	}
}

func (s *screen) waitFor(re *regexp.Regexp) []string {
	s.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		m := re.FindStringSubmatch(s.out.String())
		s.mu.Unlock()
		if m != nil {
			return m
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("output never matched %s", re)
	return nil
}

// ---- the test ----

func TestFullSystem(t *testing.T) {
	start := time.Now()
	w := newWorld(t)
	p := w.signIn()
	host, fp := w.pair(p)
	w.startAgent()
	w.waitOnline(p, host)
	target := client.Target{HostID: host, PinnedFP: fp}

	// 1. A server-substituted host key is refused before any connection.
	if _, _, err := client.Connect(context.Background(), p.cfg("webrtc"), client.Target{HostID: host, PinnedFP: strings.Repeat("0", 64)}); err != client.ErrHostKeyMismatch {
		t.Fatalf("mismatched pin: %v", err)
	}

	// 2. Direct WebRTC: open a tmux shell and run a command.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, res, err := client.Connect(ctx, p.cfg("webrtc"), target)
	if err != nil {
		t.Fatalf("connect (webrtc): %v", err)
	}
	t.Logf("connected: path=%s in %d ms", res.Path, res.Report.ElapsedMS)
	scr := newScreen(t)
	tc := termclient.New(conn, scr)
	sess, err := tc.Open(ctx, 100, 30)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	scr.waitFor(regexp.MustCompile(`\$ `))
	_ = tc.Input(ctx, sess.StreamID, []byte("MARK=e2e; echo PID=$$ RESULT-$((6*7))\r"))
	m := scr.waitFor(regexp.MustCompile(`PID=(\d+) RESULT-42`))
	pid := m[1]
	if _, a, _ := w.call("GET", "/v1/connections/"+res.AttemptID, p.access, nil); a["status"] != "connected_direct" {
		t.Fatalf("attempt status %v", a)
	}
	t.Logf("step 2 done at %v", time.Since(start))
	tc.Close() // the phone loses its connection
	t.Logf("closed at %v", time.Since(start))
	// The host reports the end; the attempt keeps the path it connected on.
	for i := 0; ; i++ {
		_, a, _ := w.call("GET", "/v1/connections/"+res.AttemptID, p.access, nil)
		if a["ended_at"] != nil {
			if a["status"] != "connected_direct" {
				t.Fatalf("ended attempt status %v", a["status"])
			}
			break
		}
		if i > 100 {
			t.Fatalf("attempt never ended: %v", a)
		}
		time.Sleep(100 * time.Millisecond)
	}
	session := sess.ID

	// 3. Reconnect over the WSS relay (inner TLS) and re-attach the same shell.
	conn2, res2, err := client.Connect(ctx, p.cfg("wss"), target)
	if err != nil {
		t.Fatalf("connect (wss): %v", err)
	}
	t.Logf("wss connected at %v (%+v)", time.Since(start), res2.Report)
	if res2.Path != transport.PathWSSRelay {
		t.Fatalf("path %s", res2.Path)
	}
	scr2 := newScreen(t)
	tc2 := termclient.New(conn2, scr2)
	s2, err := tc2.Attach(ctx, session, 100, 30)
	if err != nil || !s2.Resumed {
		t.Fatalf("attach: %+v %v", s2, err)
	}
	_ = tc2.Input(ctx, s2.StreamID, []byte("echo AGAIN=$$:$MARK\r"))
	m = scr2.waitFor(regexp.MustCompile(`AGAIN=(\d+):(\w+)`))
	if m[1] != pid || m[2] != "e2e" {
		t.Fatalf("reattached to a different shell: %v (pid %s)", m, pid)
	}

	t.Logf("step 3 done at %v", time.Since(start))
	// 4. Revoke the grant: the host drops the phone, and new attempts fail.
	_, grants, _ := w.call("GET", "/v1/access-grants?state=active", p.access, nil)
	g := grants["items"].([]any)[0].(map[string]any)
	code, _, _ := w.call("POST", "/v1/access-grants/"+g["id"].(string)+"/revoke", p.access, nil,
		"If-Match", fmt.Sprintf(`"%d"`, int(g["version"].(float64))))
	if code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	t.Logf("revoked at %v", time.Since(start))
	select {
	case <-scr2.closed:
	case <-time.After(30 * time.Second):
		t.Fatal("host did not drop the revoked phone within 30 s")
	}
	t.Logf("host dropped phone at %v", time.Since(start))
	if _, _, err := client.Connect(context.Background(), p.cfg("wss"), target); err == nil {
		t.Fatal("connected after revocation")
	} else if ae, ok := err.(*client.APIError); !ok || ae.Code != "access_grant_missing" {
		t.Fatalf("after revoke: %v", err)
	}
	// The shell itself keeps running (revocation detaches, never kills).
	out, err := exec.Command("tmux", "-S", filepath.Join(w.dir, "run", "prw", "tmux.sock"), "list-sessions").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "prw-"+session) {
		t.Fatalf("session gone after revocation: %v %s", err, out)
	}
}

// ---- the gomobile facade, as the app uses it ----

type goSigner struct{ s *attest.SoftwareSigner }

func (g goSigner) PublicKeySPKI() ([]byte, error)   { return g.s.PublicKeySPKI(), nil }
func (g goSigner) SignDER(d []byte) ([]byte, error) { return g.s.SignDER(d) }

type appEvents struct{ screen *screen }

func (a appEvents) OnOutput(_ int, b []byte)    { a.screen.Output(0, b) }
func (a appEvents) OnEvent(kind, detail string) { a.screen.Event(kind, detail) }

func TestMobileFacade(t *testing.T) {
	w := newWorld(t)
	p := w.signIn()
	host, fp := w.pair(p)
	w.startAgent()
	w.waitOnline(p, host)

	scr := newScreen(t)
	sess, err := mobile.Connect(w.url, p.access, p.id, host, fp, "auto", 30000, goSigner{p.key}, appEvents{scr})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	opened, err := sess.Open(100, 30)
	if err != nil {
		t.Fatal(err)
	}
	var o struct {
		ID     string `json:"terminal_session_id"`
		Stream int    `json:"stream_id"`
	}
	_ = json.Unmarshal([]byte(opened), &o)
	scr.waitFor(regexp.MustCompile(`\$ `))
	if err := sess.Input(o.Stream, []byte("echo FROM-APP-$((40+2))\r")); err != nil {
		t.Fatal(err)
	}
	scr.waitFor(regexp.MustCompile(`FROM-APP-42`))
	list, err := sess.List()
	if err != nil || !strings.Contains(list, o.ID) {
		t.Fatalf("list: %s %v", list, err)
	}
	if _, err := sess.Attach("not-a-session", 80, 24); err == nil || err.Error() != "session_not_found" {
		t.Fatalf("attach unknown: %v", err)
	}
	sess.Close()
	select {
	case <-scr.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("no closed event")
	}
	if _, err := mobile.Connect(w.url, p.access, p.id, host, strings.Repeat("a", 64), "auto", 30000, goSigner{p.key}, appEvents{newScreen(t)}); err == nil || err.Error() != "host_key_mismatch" {
		t.Fatalf("pin mismatch: %v", err)
	}
}
