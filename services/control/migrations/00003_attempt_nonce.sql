-- Keep the per-attempt attestation nonce so an idempotent retry of
-- POST /v1/connections can re-sign the same ticket. The nonce is a one-time
-- challenge bound to this attempt's ticket and transport certificates, not a
-- credential; it is useless after the attempt expires.
-- +goose Up
ALTER TABLE connection_attempts ADD COLUMN attestation_nonce BYTEA
  CHECK (attestation_nonce IS NULL OR length(attestation_nonce) = 32);
ALTER TABLE connection_attempts ADD COLUMN host_relay_jti UUID;

-- +goose Down
ALTER TABLE connection_attempts DROP COLUMN host_relay_jti;
ALTER TABLE connection_attempts DROP COLUMN attestation_nonce;
