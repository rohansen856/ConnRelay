package pairing_test

import (
	"encoding/base64"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rohansen856/connrelay/core/prwcore/attest"
	"github.com/rohansen856/connrelay/services/control/internal/apitest"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/inventory"
	"github.com/rohansen856/connrelay/services/control/internal/pairing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

type env struct {
	*apitest.Env
	svc *pairing.Service
	now time.Time
}

func setup(t *testing.T) *env {
	e := &env{Env: apitest.New(t), now: time.Now()}
	e.svc = &pairing.Service{Store: e.Store, Auth: e.Auth, Pepper: []byte("TEST-ONLY-pepper"),
		APIURL: "https://api.test.invalid", ControlWS: "wss://api.test.invalid/v1/agent/control",
		JWKS: func() []pairing.JWK {
			return []pairing.JWK{{KID: "t1", KTY: "OKP", CRV: "Ed25519", X: "x", Use: "sig"}}
		},
		Now: func() time.Time { return e.now }, WaitFor: 300 * time.Millisecond}
	e.svc.Routes(e.Mux)
	(&inventory.Service{Store: e.Store, Auth: e.Auth}).Routes(e.Mux)
	return e
}

// host simulates prw-agent pair.
type host struct {
	e    *env
	key  *attest.SoftwareSigner
	fp   string
	id   string
	ref  string
	code string
	wait string
	qrFP string
}

func (e *env) newHost(name string) *host {
	e.T.Helper()
	k, _ := attest.NewSoftwareSigner()
	spki := k.PublicKeySPKI()
	fp := attest.Fingerprint(spki)
	sig, _ := attest.SignPoP(k, attest.PoP{Purpose: attest.PurposePairCreate, SPKIFP: fp}, e.now)
	r := e.Do("POST", "/v1/pairing/challenges", "", map[string]any{
		"host_public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "hostname": name,
		"os": map[string]string{"id": "ubuntu", "version": "24.04"}, "agent_version": "0.1.0",
		"proto": map[string]int{"min": 1, "max": 1}, "pop_sig": sig})
	if r.Status != 201 {
		e.T.Fatalf("create: %d %v", r.Status, r.Body)
	}
	qr, _ := url.Parse(r.Body["qr_payload"].(string))
	return &host{e: e, key: k, fp: fp, id: r.Body["challenge_id"].(string), ref: r.Body["pairing_ref"].(string),
		code: r.Body["display_code"].(string), wait: r.Body["wait_token"].(string), qrFP: qr.Query().Get("fp")}
}

func (h *host) poll() apitest.Resp {
	return h.e.Do("GET", "/v1/pairing/challenges/"+h.id+"/wait", h.wait, nil)
}

func (h *host) complete(nonce2 string, signer *attest.SoftwareSigner) apitest.Resp {
	sig, _ := attest.SignPoP(signer, attest.PoP{Purpose: attest.PurposePairComplete, ChallengeID: h.id, Nonce: nonce2, SPKIFP: h.fp}, h.e.now)
	return h.e.Do("POST", "/v1/pairing/challenges/"+h.id+"/complete", h.wait, map[string]string{"sig": sig})
}

func TestQRPairingWithGrant(t *testing.T) {
	e := setup(t)
	phone := e.SignIn("owner")
	h := e.newHost("workstation")
	if h.qrFP != h.fp {
		t.Fatal("QR payload does not carry the host fingerprint")
	}
	if r := h.poll(); r.Body["status"] != "pending" {
		t.Fatalf("poll before approval: %v", r.Body)
	}
	if r := h.complete("whatever", h.key); r.Code() != "pairing_not_approved" {
		t.Fatalf("complete before approval: %v", r.Body)
	}
	res := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"pairing_ref": h.ref})
	if res.Status != 200 || res.Body["host_key_fingerprint"] != h.qrFP || res.Body["hostname"] != "workstation" {
		t.Fatalf("resolve: %d %v", res.Status, res.Body)
	}
	if r := phone.Do("POST", "/v1/pairing/challenges/"+h.id+"/approve",
		map[string]any{"host_key_fingerprint": h.qrFP, "grant_to_this_phone": true}); r.Status != 200 {
		t.Fatalf("approve: %d %v", r.Status, r.Body)
	}
	w := h.poll()
	if w.Body["status"] != "approved" {
		t.Fatalf("poll after approval: %v", w.Body)
	}
	done := h.complete(w.Body["nonce2"].(string), h.key)
	if done.Status != 200 || done.Body["control_ws_url"] == nil || done.Body["jwks"] == nil {
		t.Fatalf("complete: %d %v", done.Status, done.Body)
	}
	hostID := done.Body["device_id"].(string)
	dev := phone.Do("GET", "/v1/devices/"+hostID, nil)
	if dev.Status != 200 || dev.Body["kind"] != "host" || dev.Body["my_grant"] == nil {
		t.Fatalf("enrolled host: %d %v", dev.Status, dev.Body)
	}
	// Replays fail.
	if r := h.complete(w.Body["nonce2"].(string), h.key); r.Code() != "pairing_used" {
		t.Fatalf("replayed complete: %v", r.Body)
	}
	if r := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"pairing_ref": h.ref}); r.Code() != "pairing_used" {
		t.Fatalf("resolve after use: %v", r.Body)
	}
}

func TestTypedCodeWithoutGrant(t *testing.T) {
	e := setup(t)
	phone := e.SignIn("owner")
	h := e.newHost("laptop")
	typed := strings.ToLower(strings.ReplaceAll(h.code, "-", " "))
	res := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"display_code": typed})
	if res.Status != 200 {
		t.Fatalf("resolve typed code: %d %v", res.Status, res.Body)
	}
	phone.Do("POST", "/v1/pairing/challenges/"+h.id+"/approve", map[string]any{"host_key_fingerprint": h.fp})
	w := h.poll()
	done := h.complete(w.Body["nonce2"].(string), h.key)
	dev := phone.Do("GET", "/v1/devices/"+done.Body["device_id"].(string), nil)
	if dev.Body["my_grant"] != nil {
		t.Fatal("grant created although not requested")
	}
	if r := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"display_code": "ZZZZ-ZZZZ"}); r.Status != 404 {
		t.Fatalf("unknown code: %d", r.Status)
	}
}

func TestFingerprintMismatchLocks(t *testing.T) {
	e := setup(t)
	phone := e.SignIn("owner")
	h := e.newHost("victim")
	for i := 0; i < pairing.MaxFailed; i++ {
		r := phone.Do("POST", "/v1/pairing/challenges/"+h.id+"/approve", map[string]any{"host_key_fingerprint": "attacker-fp"})
		if r.Code() != "pairing_fingerprint_mismatch" {
			t.Fatalf("attempt %d: %v", i, r.Body)
		}
	}
	if r := phone.Do("POST", "/v1/pairing/challenges/"+h.id+"/approve", map[string]any{"host_key_fingerprint": h.fp}); r.Code() != "pairing_locked" {
		t.Fatalf("after lock: %v", r.Body)
	}
}

func TestCompleteRequiresHostKeyAndWaitToken(t *testing.T) {
	e := setup(t)
	phone := e.SignIn("owner")
	h := e.newHost("box")
	phone.Do("POST", "/v1/pairing/challenges/"+h.id+"/approve", map[string]any{"host_key_fingerprint": h.fp})
	w := h.poll()
	impostor, _ := attest.NewSoftwareSigner()
	if r := h.complete(w.Body["nonce2"].(string), impostor); r.Code() != "signature_invalid" {
		t.Fatalf("impostor key: %v", r.Body)
	}
	if r := h.complete("wrong-nonce", h.key); r.Code() != "signature_invalid" {
		t.Fatalf("wrong nonce2: %v", r.Body)
	}
	saved := h.wait
	h.wait = "stolen?"
	if r := h.complete(w.Body["nonce2"].(string), h.key); r.Status != 401 {
		t.Fatalf("wrong wait token: %d", r.Status)
	}
	h.wait = saved
	if r := h.complete(w.Body["nonce2"].(string), h.key); r.Status != 200 {
		t.Fatalf("legit complete after failures: %d %v", r.Status, r.Body)
	}
}

func TestExpiryAndCancel(t *testing.T) {
	e := setup(t)
	phone := e.SignIn("owner")
	h := e.newHost("old")
	e.now = e.now.Add(pairing.TTL + time.Second)
	if r := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"pairing_ref": h.ref}); r.Code() != "pairing_expired" {
		t.Fatalf("expired resolve: %v", r.Body)
	}
	if r := h.poll(); r.Code() != "pairing_expired" {
		t.Fatalf("expired poll: %v", r.Body)
	}
	e.now = time.Now()
	h2 := e.newHost("canceled")
	if r := e.Do("POST", "/v1/pairing/challenges/"+h2.id+"/cancel", h2.wait, nil); r.Status != 200 {
		t.Fatalf("host cancel: %d %v", r.Status, r.Body)
	}
	if r := phone.Do("POST", "/v1/pairing/resolve", map[string]string{"pairing_ref": h2.ref}); r.Code() != "pairing_rejected" {
		t.Fatalf("resolve canceled: %v", r.Body)
	}
	if r := e.Do("POST", "/v1/pairing/challenges/"+h2.id+"/cancel", "nobody", nil); r.Status != 401 {
		t.Fatalf("anonymous cancel: %d", r.Status)
	}
}

func TestCreateValidation(t *testing.T) {
	e := setup(t)
	k, _ := attest.NewSoftwareSigner()
	other, _ := attest.NewSoftwareSigner()
	spki := k.PublicKeySPKI()
	sig, _ := attest.SignPoP(other, attest.PoP{Purpose: attest.PurposePairCreate, SPKIFP: attest.Fingerprint(spki)}, e.now)
	body := map[string]any{"host_public_key_spki": base64.RawURLEncoding.EncodeToString(spki), "hostname": "x",
		"os": map[string]string{"id": "ubuntu"}, "agent_version": "0.1.0", "proto": map[string]int{"min": 1, "max": 1}, "pop_sig": sig}
	if r := e.Do("POST", "/v1/pairing/challenges", "", body); r.Code() != "signature_invalid" {
		t.Fatalf("key not proven: %v", r.Body)
	}
	good, _ := attest.SignPoP(k, attest.PoP{Purpose: attest.PurposePairCreate, SPKIFP: attest.Fingerprint(spki)}, e.now)
	body["pop_sig"], body["hostname"] = good, "evil\x1b]0;title\x07"
	if r := e.Do("POST", "/v1/pairing/challenges", "", body); r.Code() != "validation_failed" {
		t.Fatalf("control characters in hostname: %v", r.Body)
	}
}
