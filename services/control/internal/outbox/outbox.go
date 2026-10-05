// Package outbox delivers committed grant and device changes to live agents
// and phones. Rows are written in the same transaction as the change, so a
// crash between commit and delivery only delays the notice; the grant lease
// bounds how long a missed notice can matter.
package outbox

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Hub is the subset of the socket hub the worker needs.
type Hub interface {
	Connected(host uuid.UUID) bool
	SendLease(ctx context.Context, host uuid.UUID) error
	SendToAgent(ctx context.Context, host uuid.UUID, typ string, body map[string]any) error
	SendToPhone(ctx context.Context, phone uuid.UUID, m any)
	Disconnect(dev uuid.UUID, code websocket.StatusCode, reason string)
}

// Worker delivers outbox events.
type Worker struct {
	Store    *store.Store
	Hub      Hub
	Log      *slog.Logger
	Interval time.Duration
	kick     chan struct{}
}

// Kick wakes the worker immediately (after a commit).
func (w *Worker) Kick() {
	if w.kick == nil {
		return
	}
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Run delivers events until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	if w.Interval == 0 {
		w.Interval = 500 * time.Millisecond
	}
	if w.Log == nil {
		w.Log = slog.Default()
	}
	w.kick = make(chan struct{}, 1)
	t := time.NewTicker(w.Interval)
	defer t.Stop()
	for {
		if err := w.Drain(ctx); err != nil && ctx.Err() == nil {
			w.Log.Warn("outbox drain failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-w.kick:
		}
	}
}

type event struct {
	ID      uuid.UUID
	Account *uuid.UUID
	Type    string
	Payload json.RawMessage
}

// Drain processes all pending events once.
func (w *Worker) Drain(ctx context.Context) error {
	for {
		var evs []event
		err := w.Store.InTx(ctx, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id, account_id, event_type, payload FROM outbox_events
				WHERE processed_at IS NULL AND dead_lettered_at IS NULL AND available_at <= now()
				ORDER BY created_at LIMIT 50 FOR UPDATE SKIP LOCKED`)
			if err != nil {
				return err
			}
			for rows.Next() {
				var e event
				if err := rows.Scan(&e.ID, &e.Account, &e.Type, &e.Payload); err != nil {
					rows.Close()
					return err
				}
				evs = append(evs, e)
			}
			rows.Close()
			for _, e := range evs {
				w.deliver(ctx, tx, e)
				if _, err := tx.Exec(ctx, `UPDATE outbox_events SET processed_at = now(), attempts = attempts + 1 WHERE id = $1`, e.ID); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil || len(evs) == 0 {
			return err
		}
	}
}

// deliver pushes one event. Delivery is best effort: an offline agent gets a
// fresh lease (which reflects the change) when it reconnects.
func (w *Worker) deliver(ctx context.Context, q store.Q, e event) {
	var p struct {
		GrantID  *uuid.UUID `json:"grant_id"`
		Host     *uuid.UUID `json:"host_device_id"`
		Phone    *uuid.UUID `json:"phone_device_id"`
		DeviceID *uuid.UUID `json:"device_id"`
		Kind     string     `json:"kind"`
	}
	_ = json.Unmarshal(e.Payload, &p)
	notice := func(scope string) map[string]any {
		return map[string]any{"type": "revoke_notice", "scope": scope, "dedupe_key": e.ID, "payload": e.Payload}
	}
	switch e.Type {
	case "grant_created":
		if p.Host != nil {
			_ = w.Hub.SendLease(ctx, *p.Host)
		}
	case "grant_revoked":
		if p.Host != nil {
			_ = w.Hub.SendLease(ctx, *p.Host)
			_ = w.Hub.SendToAgent(ctx, *p.Host, "revoke_notice", map[string]any{"scope": "grant", "dedupe_key": e.ID, "payload": e.Payload})
		}
		if p.Phone != nil {
			w.Hub.SendToPhone(ctx, *p.Phone, notice("grant"))
		}
	case "device_revoked":
		if p.DeviceID == nil {
			return
		}
		if p.Kind == "host" {
			_ = w.Hub.SendToAgent(ctx, *p.DeviceID, "revoke_notice", map[string]any{"scope": "device", "dedupe_key": e.ID, "payload": e.Payload})
			w.Hub.Disconnect(*p.DeviceID, 4403, "device_revoked")
			return
		}
		// A revoked phone: every host it had access to must drop it now.
		rows, err := q.Query(ctx, `SELECT DISTINCT host_device_id FROM access_grants
			WHERE phone_device_id = $1 AND revoke_reason = 'device_revoked'`, *p.DeviceID)
		if err == nil {
			var hosts []uuid.UUID
			for rows.Next() {
				var h uuid.UUID
				if rows.Scan(&h) == nil {
					hosts = append(hosts, h)
				}
			}
			rows.Close()
			for _, h := range hosts {
				_ = w.Hub.SendLease(ctx, h)
				_ = w.Hub.SendToAgent(ctx, h, "revoke_notice", map[string]any{"scope": "device", "dedupe_key": e.ID, "payload": e.Payload})
			}
		}
		w.Hub.SendToPhone(ctx, *p.DeviceID, notice("device"))
		w.Hub.Disconnect(*p.DeviceID, 4403, "device_revoked")
	}
}
