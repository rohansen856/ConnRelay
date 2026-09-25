// Package inventory serves the device and access-grant APIs.
package inventory

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Presence thresholds (derived, never stored).
const (
	StaleAfter   = 75 * time.Second
	OfflineAfter = 150 * time.Second
)

// Live reports whether a host currently has an authenticated agent socket.
type Live interface {
	Connected(deviceID uuid.UUID) bool
}

// Notifier receives revocation events after commit (best effort; the outbox
// guarantees eventual delivery).
type Notifier interface {
	Kick()
}

// Service implements the handlers.
type Service struct {
	Store  *store.Store
	Auth   *auth.Service
	Live   Live
	Notify Notifier
	Now    func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) kick() {
	if s.Notify != nil {
		s.Notify.Kick()
	}
}

// Presence derives a device's presence.
func (s *Service) Presence(d store.Device) string {
	if d.LastSeenAt == nil {
		return "unknown"
	}
	age := s.now().Sub(*d.LastSeenAt)
	connected := s.Live == nil || s.Live.Connected(d.ID) || d.Kind == "phone"
	switch {
	case age < StaleAfter && connected:
		return "online"
	case age < OfflineAfter:
		return "stale"
	}
	return "offline"
}

type deviceView struct {
	ID              uuid.UUID    `json:"id"`
	Kind            string       `json:"kind"`
	Platform        string       `json:"platform"`
	DisplayName     string       `json:"display_name"`
	KeyFingerprint  string       `json:"key_fingerprint"`
	SoftwareVersion *string      `json:"software_version"`
	AdminState      string       `json:"admin_state"`
	Presence        string       `json:"presence"`
	LastSeenAt      *time.Time   `json:"last_seen_at"`
	EnrolledAt      time.Time    `json:"enrolled_at"`
	RevokedAt       *time.Time   `json:"revoked_at,omitempty"`
	Capabilities    any          `json:"capabilities,omitempty"`
	MyGrant         *store.Grant `json:"my_grant"`
	Version         int          `json:"version"`
}

func (s *Service) view(r store.DeviceRow) deviceView {
	v := deviceView{ID: r.ID, Kind: r.Kind, Platform: r.Platform, DisplayName: r.DisplayName, KeyFingerprint: r.KeyFingerprint,
		SoftwareVersion: r.SoftwareVersion, AdminState: r.AdminState, LastSeenAt: r.LastSeenAt, EnrolledAt: r.EnrolledAt,
		RevokedAt: r.RevokedAt, MyGrant: r.MyGrant, Version: r.Version}
	if len(r.Capabilities) > 0 {
		v.Capabilities = r.Capabilities
	}
	v.Presence = s.Presence(r.Device)
	if r.AdminState == "revoked" {
		v.Presence = "offline"
	}
	return v
}

func parseID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return id, httpx.ErrNotFound
	}
	return id, nil
}

func (s *Service) getDeviceRow(ctx context.Context, p *auth.Principal, id uuid.UUID) (store.DeviceRow, error) {
	rows, err := store.ListDevices(ctx, s.Store.Pool, p.AccountID, p.DeviceID, store.DeviceFilter{After: nil, Limit: 1000})
	if err != nil {
		return store.DeviceRow{}, err
	}
	for _, r := range rows {
		if r.ID == id {
			return r, nil
		}
	}
	return store.DeviceRow{}, httpx.ErrNotFound
}

// Routes registers the inventory endpoints.
func (s *Service) Routes(mux *http.ServeMux) {
	h := func(f httpx.Handler) http.Handler { return s.Auth.RequirePhone(f) }

	mux.Handle("GET /v1/devices", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		q := r.URL.Query()
		f := store.DeviceFilter{Kind: q.Get("kind"), State: q.Get("state"), Prefix: q.Get("q"), Limit: 50}
		if f.Kind != "" && f.Kind != "phone" && f.Kind != "host" || f.State != "" && f.State != "active" && f.State != "revoked" {
			return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid filter.")
		}
		if l := q.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > 100 {
				return httpx.E(http.StatusBadRequest, "validation_failed", "limit must be 1-100.")
			}
			f.Limit = n
		}
		if c := q.Get("cursor"); c != "" {
			id, err := uuid.Parse(c)
			if err != nil {
				return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid cursor.")
			}
			f.After = &id
		}
		want := f.Limit
		f.Limit = want + 1
		rows, err := store.ListDevices(r.Context(), s.Store.Pool, p.AccountID, p.DeviceID, f)
		if err != nil {
			return err
		}
		var next any
		if len(rows) > want {
			rows = rows[:want]
			next = rows[want-1].ID.String()
		}
		items := make([]deviceView, 0, len(rows))
		for _, row := range rows {
			items = append(items, s.view(row))
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
		return nil
	}))

	mux.Handle("GET /v1/devices/{id}", h(func(w http.ResponseWriter, r *http.Request) error {
		id, err := parseID(r)
		if err != nil {
			return err
		}
		row, err := s.getDeviceRow(r.Context(), auth.FromContext(r.Context()), id)
		if err != nil {
			return err
		}
		httpx.SetETag(w, row.Version)
		httpx.WriteJSON(w, http.StatusOK, s.view(row))
		return nil
	}))

	mux.Handle("PATCH /v1/devices/{id}", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		id, err := parseID(r)
		if err != nil {
			return err
		}
		ver, err := httpx.IfMatch(r)
		if err != nil {
			return err
		}
		var req struct {
			DisplayName string `json:"display_name"`
		}
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		name, ok := auth.CleanDisplayName(req.DisplayName)
		if !ok {
			return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid name.")
		}
		_, err = store.RenameDevice(r.Context(), s.Store.Pool, p.AccountID, id, ver, name)
		if errors.Is(err, store.ErrNotFound) {
			return s.versionOrMissing(r.Context(), p, id)
		}
		if err != nil {
			return err
		}
		row, err := s.getDeviceRow(r.Context(), p, id)
		if err != nil {
			return err
		}
		httpx.SetETag(w, row.Version)
		httpx.WriteJSON(w, http.StatusOK, s.view(row))
		return nil
	}))

	mux.Handle("POST /v1/devices/{id}/revoke", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		id, err := parseID(r)
		if err != nil {
			return err
		}
		ver, err := httpx.IfMatch(r)
		if err != nil {
			return err
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		switch req.Reason {
		case "lost", "user", "compromised", "replaced":
		default:
			return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid reason.")
		}
		var res store.RevokeDeviceResult
		err = s.Store.InTx(r.Context(), func(tx pgx.Tx) error {
			d, err := store.GetDevice(r.Context(), tx, p.AccountID, id)
			if err != nil {
				return httpx.ErrNotFound
			}
			if d.Kind == "phone" && d.AdminState != "revoked" && r.URL.Query().Get("confirm_last_phone") != "true" {
				n, err := store.CountActivePhones(r.Context(), tx, p.AccountID)
				if err != nil {
					return err
				}
				if n <= 1 {
					return httpx.E(http.StatusConflict, "last_phone", "This is your last phone. Confirm to revoke it.")
				}
			}
			res, err = store.RevokeDevice(r.Context(), tx, p.AccountID, id, ver, req.Reason, p.DeviceID)
			if errors.Is(err, store.ErrNotFound) {
				if d.AdminState == "revoked" {
					return httpx.E(http.StatusConflict, "device_revoked", "The device is already revoked.")
				}
				return httpx.ErrPrecondition
			}
			if err != nil {
				return err
			}
			if err := store.Outbox(r.Context(), tx, p.AccountID, "device", id, "device_revoked",
				"device_revoked:"+id.String(), map[string]any{"device_id": id, "kind": d.Kind}); err != nil {
				return err
			}
			return store.WriteAudit(r.Context(), tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
				TargetDeviceID: &id, EventType: "device_revoked", Outcome: "success", ReasonCode: req.Reason,
				RequestID: httpx.RequestID(r.Context()), Metadata: map[string]any{"grants_revoked": res.GrantsRevoked}})
		})
		if err != nil {
			return err
		}
		s.kick()
		httpx.SetETag(w, res.Device.Version)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"device": s.view(store.DeviceRow{Device: res.Device}), "grants_revoked": res.GrantsRevoked, "sessions_notified": true})
		return nil
	}))

	s.grantRoutes(mux, h)
}

// versionOrMissing distinguishes a stale version (412) from a missing or
// foreign device (404).
func (s *Service) versionOrMissing(ctx context.Context, p *auth.Principal, id uuid.UUID) error {
	if _, err := store.GetDevice(ctx, s.Store.Pool, p.AccountID, id); err != nil {
		return httpx.ErrNotFound
	}
	return httpx.ErrPrecondition
}
