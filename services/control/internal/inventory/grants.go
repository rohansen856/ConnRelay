package inventory

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rohansen856/connrelay/services/control/internal/auth"
	"github.com/rohansen856/connrelay/services/control/internal/httpx"
	"github.com/rohansen856/connrelay/services/control/internal/store"
)

// Grant API errors.
var (
	ErrGrantExists  = httpx.E(http.StatusConflict, "grant_exists", "This phone already has access to this computer.")
	ErrCapability   = httpx.E(http.StatusBadRequest, "capability_not_supported", "Only terminal access is supported.")
	ErrGrantRevoked = httpx.E(http.StatusConflict, "grant_revoked", "This grant was revoked. Create a new one.")
	errBadExpiry    = httpx.E(http.StatusBadRequest, "validation_failed", "expires_at must be in the future.")
)

func (s *Service) grantRoutes(mux *http.ServeMux, h func(httpx.Handler) http.Handler) {
	mux.Handle("GET /v1/access-grants", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		q := r.URL.Query()
		var f store.GrantFilter
		for key, dst := range map[string]**uuid.UUID{"phone_device_id": &f.Phone, "host_device_id": &f.Host} {
			if v := q.Get(key); v != "" {
				id, err := uuid.Parse(v)
				if err != nil {
					return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid "+key+".")
				}
				*dst = &id
			}
		}
		f.State = q.Get("state")
		if f.State != "" && f.State != "active" && f.State != "revoked" {
			return httpx.E(http.StatusBadRequest, "validation_failed", "Invalid state.")
		}
		gs, err := store.ListGrants(r.Context(), s.Store.Pool, p.AccountID, f)
		if err != nil {
			return err
		}
		if gs == nil {
			gs = []store.Grant{}
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": gs, "next_cursor": nil})
		return nil
	}))

	mux.Handle("POST /v1/access-grants", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		var req struct {
			Phone        uuid.UUID  `json:"phone_device_id"`
			Host         uuid.UUID  `json:"host_device_id"`
			Capabilities []string   `json:"capabilities"`
			ExpiresAt    *time.Time `json:"expires_at"`
		}
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		if len(req.Capabilities) != 1 || req.Capabilities[0] != "terminal" {
			return ErrCapability
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
			return errBadExpiry
		}
		var g store.Grant
		err := s.Store.InTx(r.Context(), func(tx pgx.Tx) error {
			var err error
			g, err = store.InsertGrant(r.Context(), tx, p.AccountID, req.Phone, req.Host, req.Capabilities, req.ExpiresAt, p.DeviceID)
			if store.IsUniqueViolation(err) {
				return ErrGrantExists
			}
			if errors.Is(err, store.ErrNotFound) {
				// One of the devices is missing, revoked, foreign or the wrong kind.
				return httpx.ErrNotFound
			}
			if err != nil {
				return err
			}
			if err := store.Outbox(r.Context(), tx, p.AccountID, "grant", g.ID, "grant_created",
				"grant_created:"+g.ID.String(), map[string]any{"grant_id": g.ID, "host_device_id": g.HostDeviceID}); err != nil {
				return err
			}
			return store.WriteAudit(r.Context(), tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
				TargetDeviceID: &req.Host, EventType: "grant_created", Outcome: "success", RequestID: httpx.RequestID(r.Context()),
				Metadata: map[string]any{"grant_id": g.ID, "phone_device_id": g.PhoneDeviceID}})
		})
		if err != nil {
			return err
		}
		s.kick()
		httpx.SetETag(w, g.Version)
		httpx.WriteJSON(w, http.StatusCreated, g)
		return nil
	}))

	mux.Handle("PATCH /v1/access-grants/{id}", h(func(w http.ResponseWriter, r *http.Request) error {
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
			ExpiresAt *time.Time `json:"expires_at"`
		}
		if err := httpx.Decode(w, r, 4<<10, &req); err != nil {
			return err
		}
		if req.ExpiresAt != nil && !req.ExpiresAt.After(s.now()) {
			return errBadExpiry
		}
		g, err := store.SetGrantExpiry(r.Context(), s.Store.Pool, p.AccountID, id, ver, req.ExpiresAt)
		if errors.Is(err, store.ErrNotFound) {
			return s.grantVersionOrMissing(r, p, id)
		}
		if err != nil {
			return err
		}
		s.kick()
		httpx.SetETag(w, g.Version)
		httpx.WriteJSON(w, http.StatusOK, g)
		return nil
	}))

	mux.Handle("POST /v1/access-grants/{id}/revoke", h(func(w http.ResponseWriter, r *http.Request) error {
		p := auth.FromContext(r.Context())
		id, err := parseID(r)
		if err != nil {
			return err
		}
		ver, err := httpx.IfMatch(r)
		if err != nil {
			return err
		}
		var g store.Grant
		err = s.Store.InTx(r.Context(), func(tx pgx.Tx) error {
			var err error
			g, err = store.RevokeGrant(r.Context(), tx, p.AccountID, id, ver, p.DeviceID)
			if errors.Is(err, store.ErrNotFound) {
				return s.grantVersionOrMissing(r, p, id)
			}
			if err != nil {
				return err
			}
			if err := store.Outbox(r.Context(), tx, p.AccountID, "grant", g.ID, "grant_revoked",
				"grant_revoked:"+g.ID.String(), map[string]any{"grant_id": g.ID, "host_device_id": g.HostDeviceID,
					"phone_device_id": g.PhoneDeviceID}); err != nil {
				return err
			}
			return store.WriteAudit(r.Context(), tx, store.Audit{AccountID: &p.AccountID, ActorKind: "phone", ActorDeviceID: &p.DeviceID,
				TargetDeviceID: &g.HostDeviceID, EventType: "grant_revoked", Outcome: "success", RequestID: httpx.RequestID(r.Context()),
				Metadata: map[string]any{"grant_id": g.ID, "phone_device_id": g.PhoneDeviceID}})
		})
		if err != nil {
			return err
		}
		s.kick()
		httpx.SetETag(w, g.Version)
		httpx.WriteJSON(w, http.StatusOK, g)
		return nil
	}))
}

func (s *Service) grantVersionOrMissing(r *http.Request, p *auth.Principal, id uuid.UUID) error {
	g, err := store.GetGrant(r.Context(), s.Store.Pool, p.AccountID, id)
	if err != nil {
		return httpx.ErrNotFound
	}
	if g.RevokedAt != nil {
		return ErrGrantRevoked
	}
	return httpx.ErrPrecondition
}
