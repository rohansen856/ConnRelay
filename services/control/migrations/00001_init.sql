-- Initial ConnRelay schema. Integrity rules enforced by the database:
--   * every device reference is account-scoped through composite foreign keys
--     on (account_id, id[, kind]), so a row cannot point at another account's
--     device or at a device of the wrong kind;
--   * history is kept: devices are revoked, never cascade-deleted;
--   * secrets are stored only as hashes or HMACs; private keys never.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION set_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at := now(); RETURN NEW; END $$;
-- +goose StatementEnd

CREATE TABLE accounts (
  id                UUID PRIMARY KEY,                       -- app-generated UUIDv7
  identity_provider TEXT NOT NULL CHECK (identity_provider IN ('google')),
  identity_subject  TEXT NOT NULL CHECK (length(identity_subject) BETWEEN 1 AND 255),
  email             TEXT CHECK (length(email) <= 320),       -- only if verified by Google
  display_name      TEXT CHECK (length(display_name) <= 120),
  status            TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','suspended','deletion_pending','deleted')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (identity_provider, identity_subject)
);
CREATE TRIGGER trg_accounts_updated BEFORE UPDATE ON accounts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE devices (
  id               UUID PRIMARY KEY,
  account_id       UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  kind             TEXT NOT NULL CHECK (kind IN ('phone','host')),
  platform         TEXT NOT NULL CHECK (platform IN ('android','ios','linux')),
  display_name     TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 120),
  public_key       BYTEA NOT NULL,                          -- SPKI DER, ECDSA P-256
  public_key_alg   TEXT NOT NULL DEFAULT 'ecdsa-p256' CHECK (public_key_alg IN ('ecdsa-p256')),
  key_fingerprint  TEXT NOT NULL,                           -- hex(sha256(SPKI))
  software_version TEXT CHECK (length(software_version) <= 64),
  protocol_version INT  NOT NULL DEFAULT 1,
  capabilities     JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(capabilities) <= 4096),
  admin_state      TEXT NOT NULL DEFAULT 'active' CHECK (admin_state IN ('pending','active','revoked')),
  last_seen_at     TIMESTAMPTZ,                             -- presence is derived from this + live WSS
  enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at       TIMESTAMPTZ,
  revoke_reason    TEXT CHECK (revoke_reason IN ('user','lost','compromised','replaced','admin')),
  version          INT  NOT NULL DEFAULT 1,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((admin_state = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (account_id, id),
  UNIQUE (account_id, id, kind)
);
CREATE UNIQUE INDEX uq_devices_live_fingerprint ON devices(account_id, key_fingerprint)
  WHERE admin_state <> 'revoked';
CREATE INDEX idx_devices_inventory ON devices(account_id, kind, admin_state);
CREATE INDEX idx_devices_recent    ON devices(account_id, last_seen_at DESC NULLS LAST);
CREATE TRIGGER trg_devices_updated BEFORE UPDATE ON devices
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE device_credentials (
  id              UUID PRIMARY KEY,
  account_id      UUID NOT NULL,
  device_id       UUID NOT NULL,
  key_purpose     TEXT NOT NULL CHECK (key_purpose IN ('identity_signing')),
  alg             TEXT NOT NULL CHECK (alg IN ('ecdsa-p256')),
  public_key      BYTEA NOT NULL,
  key_fingerprint TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','rotating','revoked','expired')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  UNIQUE (device_id, key_fingerprint),
  FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX uq_device_cred_active ON device_credentials(device_id, key_purpose)
  WHERE status = 'active';

CREATE TABLE auth_sessions (                                -- phones only
  id                 UUID PRIMARY KEY,
  account_id         UUID NOT NULL,
  device_id          UUID NOT NULL,
  device_kind        TEXT GENERATED ALWAYS AS ('phone') STORED,
  token_family_id    UUID NOT NULL,
  refresh_token_hash BYTEA NOT NULL UNIQUE,                 -- SHA-256 of 256-bit random token
  rotated_from_id    UUID REFERENCES auth_sessions(id) ON DELETE SET NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at       TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ NOT NULL,
  revoked_at         TIMESTAMPTZ,
  revoke_reason      TEXT CHECK (revoke_reason IN
                       ('logout','rotated','reuse_detected','device_revoked','admin','expired')),
  user_agent_summary TEXT CHECK (length(user_agent_summary) <= 255),
  CHECK (expires_at > created_at),
  FOREIGN KEY (account_id, device_id, device_kind) REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT
);
CREATE INDEX idx_auth_sessions_family ON auth_sessions(token_family_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_auth_sessions_device ON auth_sessions(device_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE pairing_challenges (
  id                    UUID PRIMARY KEY,
  ref_hmac              BYTEA NOT NULL UNIQUE,              -- HMAC-SHA256(pepper, 'ref:'||ref)
  code_hmac             BYTEA NOT NULL UNIQUE,              -- HMAC-SHA256(pepper, 'code:'||normalized code)
  wait_token_hmac       BYTEA NOT NULL UNIQUE,              -- authenticates host wait/complete/cancel
  host_public_key       BYTEA NOT NULL,
  host_key_fingerprint  TEXT NOT NULL,
  host_name             TEXT NOT NULL CHECK (length(host_name) BETWEEN 1 AND 120),
  host_platform         TEXT NOT NULL CHECK (host_platform IN ('linux')),
  host_os               TEXT CHECK (length(host_os) <= 64),
  agent_version         TEXT NOT NULL CHECK (length(agent_version) <= 64),
  server_nonce          BYTEA NOT NULL CHECK (length(server_nonce) = 32),
  approve_nonce         BYTEA CHECK (approve_nonce IS NULL OR length(approve_nonce) = 32),
  status                TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','approved','consumed','expired','canceled','locked')),
  failed_attempts       INT NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 100),
  account_id            UUID REFERENCES accounts(id) ON DELETE RESTRICT,
  approved_by_device_id UUID,
  approved_at           TIMESTAMPTZ,
  consumed_at           TIMESTAMPTZ,
  resulting_device_id   UUID REFERENCES devices(id) ON DELETE RESTRICT,
  requester_ip_hash     BYTEA,
  expires_at            TIMESTAMPTZ NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  CHECK (status NOT IN ('approved','consumed') OR account_id IS NOT NULL),
  FOREIGN KEY (account_id, approved_by_device_id) REFERENCES devices(account_id, id) ON DELETE RESTRICT
);
CREATE INDEX idx_pairing_live_expiry ON pairing_challenges(expires_at) WHERE status IN ('pending','approved');

CREATE TABLE access_grants (
  id                   UUID PRIMARY KEY,
  account_id           UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  phone_device_id      UUID NOT NULL,
  phone_kind           TEXT GENERATED ALWAYS AS ('phone') STORED,
  host_device_id       UUID NOT NULL,
  host_kind            TEXT GENERATED ALWAYS AS ('host') STORED,
  capabilities         TEXT[] NOT NULL DEFAULT ARRAY['terminal'],
  expires_at           TIMESTAMPTZ,                         -- NULL = no expiry
  created_by_device_id UUID,
  revoked_at           TIMESTAMPTZ,
  revoked_by_device_id UUID,
  revoke_reason        TEXT CHECK (length(revoke_reason) <= 64),
  version              INT NOT NULL DEFAULT 1,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (cardinality(capabilities) > 0),
  CHECK (capabilities <@ ARRAY['terminal','file_transfer','port_forward']::TEXT[]),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  FOREIGN KEY (account_id, phone_device_id, phone_kind) REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT,
  FOREIGN KEY (account_id, host_device_id,  host_kind)  REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT,
  FOREIGN KEY (account_id, created_by_device_id) REFERENCES devices(account_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (account_id, revoked_by_device_id) REFERENCES devices(account_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX uq_grant_active_pair ON access_grants(phone_device_id, host_device_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_grants_host_active ON access_grants(host_device_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_grants_account ON access_grants(account_id, created_at DESC);
CREATE TRIGGER trg_grants_updated BEFORE UPDATE ON access_grants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE terminal_sessions (
  id                         UUID PRIMARY KEY,
  account_id                 UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  host_device_id             UUID NOT NULL,
  host_kind                  TEXT GENERATED ALWAYS AS ('host') STORED,
  created_by_phone_device_id UUID,
  phone_kind                 TEXT GENERATED ALWAYS AS ('phone') STORED,
  host_session_handle        TEXT NOT NULL CHECK (length(host_session_handle) <= 128),  -- e.g. connrelay-<uuid>
  client_request_id          UUID NOT NULL,
  backend                    TEXT NOT NULL CHECK (backend IN ('tmux','pty')),
  persistent                 BOOLEAN NOT NULL,
  title                      TEXT NOT NULL DEFAULT 'Terminal' CHECK (length(title) <= 120),
  shell_kind                 TEXT CHECK (length(shell_kind) <= 32),                    -- basename only
  working_directory_label    TEXT CHECK (length(working_directory_label) <= 255),      -- opt-in
  status                     TEXT NOT NULL DEFAULT 'starting' CHECK (status IN
                               ('starting','attached','detached','exited','terminated','failed',
                                'host_rebooted','revoked','unknown')),
  attached_clients           INT NOT NULL DEFAULT 0 CHECK (attached_clients >= 0),
  started_at                 TIMESTAMPTZ,
  last_attached_at           TIMESTAMPTZ,
  ended_at                   TIMESTAMPTZ,
  exit_code                  INT,
  version                    INT NOT NULL DEFAULT 1,
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (host_device_id, host_session_handle),
  UNIQUE (host_device_id, client_request_id),
  FOREIGN KEY (account_id, host_device_id, host_kind) REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT,
  FOREIGN KEY (account_id, created_by_phone_device_id, phone_kind)
    REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT
);
CREATE INDEX idx_tsess_host_status    ON terminal_sessions(host_device_id, status, last_attached_at DESC);
CREATE INDEX idx_tsess_account_recent ON terminal_sessions(account_id, updated_at DESC);
CREATE TRIGGER trg_tsess_updated BEFORE UPDATE ON terminal_sessions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE connection_attempts (
  id                         UUID PRIMARY KEY,
  account_id                 UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  phone_device_id            UUID NOT NULL,
  phone_kind                 TEXT GENERATED ALWAYS AS ('phone') STORED,
  host_device_id             UUID NOT NULL,
  host_kind                  TEXT GENERATED ALWAYS AS ('host') STORED,
  grant_id                   UUID NOT NULL REFERENCES access_grants(id) ON DELETE RESTRICT,
  requested_capability       TEXT NOT NULL CHECK (requested_capability IN ('terminal')),
  target_terminal_session_id UUID REFERENCES terminal_sessions(id) ON DELETE SET NULL,
  status                     TEXT NOT NULL DEFAULT 'authorized' CHECK (status IN
                               ('authorized','signaling','ice_checking','relay_fallback',
                                'connected_direct','connected_relay','connected_wss',
                                'failed','canceled','expired','revoked')),
  ticket_jti                 UUID NOT NULL UNIQUE,          -- signed ticket itself is never stored
  ticket_expires_at          TIMESTAMPTZ NOT NULL,
  attestation_nonce_hash     BYTEA NOT NULL,                -- SHA-256 of the server nonce
  idempotency_key            TEXT CHECK (length(idempotency_key) <= 128),
  path_type                  TEXT CHECK (path_type IN
                               ('direct','turn_udp','turn_tcp','turn_tls','wss_relay','unknown')),
  failure_code               TEXT CHECK (length(failure_code) <= 96),
  created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
  connected_at               TIMESTAMPTZ,
  ended_at                   TIMESTAMPTZ,
  CHECK (ticket_expires_at > created_at),
  UNIQUE (phone_device_id, idempotency_key),
  FOREIGN KEY (account_id, phone_device_id, phone_kind) REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT,
  FOREIGN KEY (account_id, host_device_id,  host_kind)  REFERENCES devices(account_id, id, kind) ON DELETE RESTRICT
);
CREATE INDEX idx_attempts_host_live ON connection_attempts(host_device_id, ticket_expires_at)
  WHERE status IN ('authorized','signaling','ice_checking','relay_fallback');
CREATE INDEX idx_attempts_account_recent ON connection_attempts(account_id, created_at DESC);
CREATE INDEX idx_attempts_live_by_grant  ON connection_attempts(grant_id)
  WHERE status IN ('connected_direct','connected_relay','connected_wss');

CREATE TABLE session_events (
  id                    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id            UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  terminal_session_id   UUID NOT NULL REFERENCES terminal_sessions(id) ON DELETE RESTRICT,
  connection_attempt_id UUID REFERENCES connection_attempts(id) ON DELETE SET NULL,
  actor_device_id       UUID REFERENCES devices(id) ON DELETE RESTRICT,
  event_type            TEXT NOT NULL CHECK (event_type IN
                          ('requested','started','attached','attach_denied','detached','reconnected',
                           'terminated','exited','failed','revoked','host_rebooted')),
  occurred_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata              JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(metadata) <= 2048)
);
CREATE INDEX idx_sevents_session ON session_events(terminal_session_id, occurred_at DESC);
CREATE INDEX idx_sevents_account ON session_events(account_id, occurred_at DESC);

CREATE TABLE audit_events (
  id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  account_id       UUID REFERENCES accounts(id) ON DELETE RESTRICT,   -- NULL for pre-auth events
  actor_kind       TEXT NOT NULL CHECK (actor_kind IN ('user','phone','host','system','anonymous')),
  actor_device_id  UUID REFERENCES devices(id) ON DELETE RESTRICT,
  target_device_id UUID REFERENCES devices(id) ON DELETE RESTRICT,
  event_type       TEXT NOT NULL CHECK (length(event_type) <= 80),
  outcome          TEXT NOT NULL CHECK (outcome IN ('success','denied','failure')),
  reason_code      TEXT CHECK (length(reason_code) <= 100),
  request_id       TEXT CHECK (length(request_id) <= 64),
  attempt_id       UUID,
  occurred_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(metadata) <= 2048)
);
CREATE INDEX idx_audit_account_time ON audit_events(account_id, occurred_at DESC);
CREATE INDEX idx_audit_target_time  ON audit_events(target_device_id, occurred_at DESC);
CREATE INDEX idx_audit_time         ON audit_events(occurred_at);

CREATE TABLE idempotency_keys (
  id                   UUID PRIMARY KEY,
  account_id           UUID NOT NULL REFERENCES accounts(id) ON DELETE RESTRICT,
  device_id            UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  operation            TEXT NOT NULL CHECK (length(operation) <= 100),
  idempotency_key      TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
  request_digest       BYTEA NOT NULL,
  response_status      INT,
  response_resource_id UUID,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at           TIMESTAMPTZ NOT NULL,
  UNIQUE (device_id, operation, idempotency_key),
  CHECK (expires_at > created_at)
);
CREATE INDEX idx_idem_expiry ON idempotency_keys(expires_at);

CREATE TABLE outbox_events (
  id               UUID PRIMARY KEY,
  account_id       UUID REFERENCES accounts(id) ON DELETE RESTRICT,
  aggregate_type   TEXT NOT NULL,
  aggregate_id     UUID NOT NULL,
  event_type       TEXT NOT NULL,
  dedupe_key       TEXT NOT NULL UNIQUE,                    -- e.g. grant_revoked:<id>:<version>
  payload          JSONB NOT NULL CHECK (pg_column_size(payload) <= 4096),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  available_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at     TIMESTAMPTZ,
  dead_lettered_at TIMESTAMPTZ,
  attempts         INT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_error_code  TEXT
);
CREATE INDEX idx_outbox_pending ON outbox_events(available_at)
  WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

CREATE TABLE signing_keys_meta (
  kid        TEXT PRIMARY KEY,
  purpose    TEXT NOT NULL CHECK (purpose IN ('ticket','access_token')),
  alg        TEXT NOT NULL CHECK (alg IN ('EdDSA')),
  public_key BYTEA NOT NULL,                                -- Ed25519 public key only
  not_before TIMESTAMPTZ NOT NULL,
  not_after  TIMESTAMPTZ,
  retired_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE signing_keys_meta, outbox_events, idempotency_keys, audit_events, session_events,
           connection_attempts, terminal_sessions, access_grants, pairing_challenges,
           auth_sessions, device_credentials, devices, accounts;
DROP FUNCTION set_updated_at();
