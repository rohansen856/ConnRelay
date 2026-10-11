package outbox_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rohansen856/connrelay/services/control/internal/dbtest"
	"github.com/rohansen856/connrelay/services/control/internal/outbox"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

func TestMain(m *testing.M) {
	code := m.Run()
	dbtest.Cleanup()
	os.Exit(code)
}

// fakeHub fails the first `failures` sends to agents.
type fakeHub struct {
	online   bool
	failures int
	sends    int
}

func (h *fakeHub) Connected(uuid.UUID) bool { return h.online }
func (h *fakeHub) SendLease(context.Context, uuid.UUID) error {
	h.sends++
	if h.failures != 0 {
		h.failures--
		return errors.New("write failed")
	}
	return nil
}
func (h *fakeHub) SendToAgent(ctx context.Context, host uuid.UUID, _ string, _ map[string]any) error {
	return h.SendLease(ctx, host)
}
func (h *fakeHub) SendToPhone(context.Context, uuid.UUID, any)        {}
func (h *fakeHub) Disconnect(uuid.UUID, websocket.StatusCode, string) {}

type row struct {
	attempts  int
	processed bool
	dead      bool
	due       bool
}

func setup(t *testing.T, h *fakeHub) (*outbox.Worker, func() row, func()) {
	pool := dbtest.New(t)
	ctx := context.Background()
	id := store.NewID()
	if _, err := pool.Exec(ctx, `INSERT INTO outbox_events (id, aggregate_type, aggregate_id, event_type, dedupe_key, payload)
		VALUES ($1, 'grant', $2, 'grant_revoked', $3, $4)`, id, store.NewID(), "grant_revoked:"+id.String(),
		`{"host_device_id":"`+store.NewID().String()+`"}`); err != nil {
		t.Fatal(err)
	}
	w := &outbox.Worker{Store: &store.Store{Pool: pool}, Hub: h, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	get := func() row {
		var r row
		if err := pool.QueryRow(ctx, `SELECT attempts, processed_at IS NOT NULL, dead_lettered_at IS NOT NULL, available_at <= now()
			FROM outbox_events WHERE id = $1`, id).Scan(&r.attempts, &r.processed, &r.dead, &r.due); err != nil {
			t.Fatal(err)
		}
		return r
	}
	makeDue := func() { _, _ = pool.Exec(ctx, `UPDATE outbox_events SET available_at = now() WHERE id = $1`, id) }
	return w, get, makeDue
}

func drain(t *testing.T, w *outbox.Worker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Drain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFailedDeliveryIsRetried(t *testing.T) {
	h := &fakeHub{online: true, failures: 1}
	w, get, makeDue := setup(t, h)
	drain(t, w)
	if r := get(); r.processed || r.dead || r.due || r.attempts != 1 {
		t.Fatalf("after a failed send: %+v (want rescheduled)", r)
	}
	drain(t, w) // not due yet: nothing happens
	if r := get(); r.attempts != 1 {
		t.Fatalf("retried before its backoff: %+v", r)
	}
	makeDue()
	drain(t, w)
	if r := get(); !r.processed || r.attempts != 2 {
		t.Fatalf("after a successful retry: %+v", r)
	}
}

func TestPersistentFailureIsDeadLettered(t *testing.T) {
	h := &fakeHub{online: true, failures: -1} // always fails
	w, get, makeDue := setup(t, h)
	for i := 0; i < outbox.MaxAttempts; i++ {
		makeDue()
		drain(t, w)
	}
	if r := get(); !r.dead || r.processed || r.attempts != outbox.MaxAttempts {
		t.Fatalf("after %d failures: %+v", outbox.MaxAttempts, r)
	}
	makeDue()
	drain(t, w)
	if r := get(); r.attempts != outbox.MaxAttempts {
		t.Fatalf("dead-lettered event was retried: %+v", r)
	}
}

func TestOfflineAgentIsNotRetried(t *testing.T) {
	// It gets a fresh lease on reconnect instead.
	h := &fakeHub{online: false, failures: -1}
	w, get, _ := setup(t, h)
	drain(t, w)
	if r := get(); !r.processed || r.attempts != 1 {
		t.Fatalf("offline agent: %+v", r)
	}
}
