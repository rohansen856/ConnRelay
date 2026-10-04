-- Remember, at approval time, which phone should receive a grant once the
-- host completes enrolment ("grant_to_this_phone").
-- +goose Up
ALTER TABLE pairing_challenges ADD COLUMN grant_to_device_id UUID;
ALTER TABLE pairing_challenges ADD CONSTRAINT fk_pairing_grant_to
  FOREIGN KEY (account_id, grant_to_device_id) REFERENCES devices(account_id, id) ON DELETE RESTRICT;

-- +goose Down
ALTER TABLE pairing_challenges DROP CONSTRAINT fk_pairing_grant_to;
ALTER TABLE pairing_challenges DROP COLUMN grant_to_device_id;
