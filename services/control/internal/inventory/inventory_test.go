package inventory_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/rohansen856/connrelay/services/control/internal/apitest"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/inventory"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

type kicker struct{ n int }

func (k *kicker) Kick() { k.n++ }

func setup(t *testing.T) (*apitest.Env, *kicker) {
	e := apitest.New(t)
	k := &kicker{}
	(&inventory.Service{Store: e.Store, Auth: e.Auth, Notify: k}).Routes(e.Mux)
	return e, k
}

func ifMatch(v int) []string { return []string{"If-Match", fmt.Sprintf(`"%d"`, v)} }

func TestListShowsOnlyOwnAccount(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	b := e.SignIn("owner2")
	e.AddHost(a.Account, "a-host")
	bh := e.AddHost(b.Account, "b-host")

	r := a.Do("GET", "/v1/devices", nil)
	items := r.Body["items"].([]any)
	if r.Status != 200 || len(items) != 2 {
		t.Fatalf("%d %v", r.Status, r.Body)
	}
	for _, it := range items {
		if it.(map[string]any)["display_name"] == "b-host" {
			t.Fatal("another account's host is visible")
		}
	}
	// Anti-enumeration: a foreign device is 404, not 403.
	if r := a.Do("GET", "/v1/devices/"+bh.ID.String(), nil); r.Status != 404 {
		t.Fatalf("foreign device: %d", r.Status)
	}
	if r := a.Do("GET", "/v1/devices?kind=host", nil); len(r.Body["items"].([]any)) != 1 {
		t.Fatal("kind filter")
	}
}

func TestPagination(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	for i := 0; i < 5; i++ {
		e.AddHost(a.Account, fmt.Sprintf("h%d", i))
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 10; page++ {
		path := "/v1/devices?kind=host&limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		r := a.Do("GET", path, nil)
		for _, it := range r.Body["items"].([]any) {
			seen[it.(map[string]any)["id"].(string)] = true
		}
		next, _ := r.Body["next_cursor"].(string)
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 {
		t.Fatalf("paginated %d of 5 hosts", len(seen))
	}
}

func TestRenameUsesOptimisticConcurrency(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	h := e.AddHost(a.Account, "old")
	get := a.Do("GET", "/v1/devices/"+h.ID.String(), nil)
	v := get.Version()
	if r := a.Do("PATCH", "/v1/devices/"+h.ID.String(), map[string]string{"display_name": "new"}); r.Code() != "precondition_required" {
		t.Fatalf("missing If-Match: %v", r.Body)
	}
	r := a.Do("PATCH", "/v1/devices/"+h.ID.String(), map[string]string{"display_name": "new"}, ifMatch(v)...)
	if r.Status != 200 || r.Body["display_name"] != "new" || r.Version() != v+1 {
		t.Fatalf("rename: %d %v", r.Status, r.Body)
	}
	if r := a.Do("PATCH", "/v1/devices/"+h.ID.String(), map[string]string{"display_name": "x"}, ifMatch(v)...); r.Status != 412 {
		t.Fatalf("stale version: %d", r.Status)
	}
}

func TestGrantLifecycle(t *testing.T) {
	e, k := setup(t)
	a := e.SignIn("owner")
	h := e.AddHost(a.Account, "host")
	body := map[string]any{"phone_device_id": a.ID, "host_device_id": h.ID, "capabilities": []string{"terminal"}}

	if r := a.Do("POST", "/v1/access-grants", map[string]any{"phone_device_id": a.ID, "host_device_id": h.ID,
		"capabilities": []string{"terminal", "port_forward"}}); r.Code() != "capability_not_supported" {
		t.Fatalf("extra capability: %v", r.Body)
	}
	r := a.Do("POST", "/v1/access-grants", body)
	if r.Status != 201 {
		t.Fatalf("create: %d %v", r.Status, r.Body)
	}
	gid, v := r.Body["id"].(string), r.Version()
	if r := a.Do("POST", "/v1/access-grants", body); r.Code() != "grant_exists" {
		t.Fatalf("duplicate: %v", r.Body)
	}
	dev := a.Do("GET", "/v1/devices/"+h.ID.String(), nil)
	if dev.Body["my_grant"] == nil {
		t.Fatal("my_grant missing on the host")
	}
	if r := a.Do("POST", "/v1/access-grants/"+gid+"/revoke", nil, ifMatch(v)...); r.Status != 200 || r.Body["revoked_at"] == nil {
		t.Fatalf("revoke: %d %v", r.Status, r.Body)
	}
	if r := a.Do("POST", "/v1/access-grants/"+gid+"/revoke", nil, ifMatch(v+1)...); r.Code() != "grant_revoked" {
		t.Fatalf("re-revoke: %v", r.Body)
	}
	// Re-granting creates a new grant; the old one is never resurrected.
	if r := a.Do("POST", "/v1/access-grants", body); r.Status != 201 || r.Body["id"] == gid {
		t.Fatalf("re-grant: %d %v", r.Status, r.Body)
	}
	var outbox int
	_ = e.Pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox_events`).Scan(&outbox)
	if outbox != 3 || k.n == 0 {
		t.Fatalf("outbox events %d, kicks %d", outbox, k.n)
	}
}

func TestGrantRejectsForeignOrWrongDevices(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	b := e.SignIn("owner2")
	bh := e.AddHost(b.Account, "b-host")
	ah := e.AddHost(a.Account, "a-host")
	for name, body := range map[string]map[string]any{
		"foreign host":  {"phone_device_id": a.ID, "host_device_id": bh.ID, "capabilities": []string{"terminal"}},
		"foreign phone": {"phone_device_id": b.ID, "host_device_id": ah.ID, "capabilities": []string{"terminal"}},
		"swapped kinds": {"phone_device_id": ah.ID, "host_device_id": a.ID, "capabilities": []string{"terminal"}},
	} {
		if r := a.Do("POST", "/v1/access-grants", body); r.Status != 404 {
			t.Errorf("%s: %d %v", name, r.Status, r.Body)
		}
	}
}

func TestRevokeDeviceCascades(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	other := e.SignIn("owner") // second phone of the same account
	h := e.AddHost(a.Account, "host")
	a.Do("POST", "/v1/access-grants", map[string]any{"phone_device_id": other.ID, "host_device_id": h.ID, "capabilities": []string{"terminal"}})

	v := a.Do("GET", "/v1/devices/"+other.ID.String(), nil).Version()
	r := a.Do("POST", "/v1/devices/"+other.ID.String()+"/revoke", map[string]string{"reason": "lost"}, ifMatch(v)...)
	if r.Status != 200 || r.Body["grants_revoked"].(float64) != 1 {
		t.Fatalf("revoke: %d %v", r.Status, r.Body)
	}
	if r := other.Do("GET", "/v1/me", nil); r.Code() != "device_revoked" {
		t.Fatalf("revoked phone still works: %v", r.Body)
	}
	if r := a.Do("GET", "/v1/me", nil); r.Status != 200 {
		t.Fatal("revoking one phone affected another")
	}
}

func TestLastPhoneNeedsConfirmation(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	v := a.Do("GET", "/v1/devices/"+a.ID.String(), nil).Version()
	if r := a.Do("POST", "/v1/devices/"+a.ID.String()+"/revoke", map[string]string{"reason": "user"}, ifMatch(v)...); r.Code() != "last_phone" {
		t.Fatalf("last phone revoked without confirmation: %v", r.Body)
	}
	if r := a.Do("POST", "/v1/devices/"+a.ID.String()+"/revoke?confirm_last_phone=true", map[string]string{"reason": "user"}, ifMatch(v)...); r.Status != 200 {
		t.Fatalf("confirmed revoke: %d %v", r.Status, r.Body)
	}
}

// Revoking a grant ends its live attempts; finished ones keep their outcome.
func TestRevokeGrantEndsLiveAttempts(t *testing.T) {
	e, _ := setup(t)
	a := e.SignIn("owner")
	h := e.AddHost(a.Account, "host")
	r := a.Do("POST", "/v1/access-grants", map[string]any{"phone_device_id": a.ID, "host_device_id": h.ID, "capabilities": []string{"terminal"}})
	gid, v := r.Body["id"].(string), r.Version()
	ctx := context.Background()
	attempt := func(status string, ended bool) string {
		id := store.NewID()
		if _, err := e.Pool.Exec(ctx, `INSERT INTO connection_attempts (id, account_id, phone_device_id, host_device_id, grant_id,
			requested_capability, status, ticket_jti, ticket_expires_at, attestation_nonce_hash, ended_at)
			VALUES ($1,$2,$3,$4,$5,'terminal',$6,$7,now() + interval '1 minute','\x00', CASE WHEN $8 THEN now() END)`,
			id, a.Account, a.ID, h.ID, gid, status, store.NewID(), ended); err != nil {
			t.Fatal(err)
		}
		return id.String()
	}
	pending, live, done := attempt("signaling", false), attempt("connected_direct", false), attempt("connected_wss", true)

	if r := a.Do("POST", "/v1/access-grants/"+gid+"/revoke", nil, ifMatch(v)...); r.Status != 200 {
		t.Fatalf("revoke: %d %v", r.Status, r.Body)
	}
	for id, want := range map[string]string{pending: "revoked", live: "revoked", done: "connected_wss"} {
		var status string
		var ended bool
		_ = e.Pool.QueryRow(ctx, `SELECT status, ended_at IS NOT NULL FROM connection_attempts WHERE id = $1`, id).Scan(&status, &ended)
		if status != want || !ended {
			t.Errorf("attempt %s: status %s ended %v, want %s and ended", id, status, ended, want)
		}
	}
}
