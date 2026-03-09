# Operational Runbooks

**Status:** Draft v1. Rehearse each procedure in staging before the private beta and update it from what you learn.

Conventions:
- Run commands on the instance through **SSM Session Manager** (`aws ssm start-session --target <instance-id>`).
- `prwctl` is shorthand for `docker compose -f /opt/prw/deploy/compose/compose.yaml exec control /prw-control`.
- Hostnames are placeholders (`api.example.invalid`, `turn.example.invalid`).
- **Never** paste tokens, tickets, TURN credentials, pairing codes or terminal content into tickets, chat or logs.

| Runbook | Use when |
|---|---|
| [Deploy](#deploy) | Shipping a control-plane release |
| [Rollback](#rollback) | A release misbehaves |
| [Rotate secrets and keys](#rotate-secrets-and-keys) | Scheduled rotation or suspected exposure |
| [Lost or stolen phone](#lost-or-stolen-phone) | The owner can no longer trust a phone |
| [Compromised host](#compromised-host) | A paired computer may be compromised |
| [Failed connection triage](#failed-connection-triage) | "Could not reach this computer" |
| [Database restore](#database-restore) | Data loss or corruption |
| [Certificate issues](#certificate-issues) | TLS expiry or renewal failure |
| [Relay abuse or bandwidth spike](#relay-abuse-or-bandwidth-spike) | Relay alerts fire |
| [Server loss recovery](#server-loss-recovery) | Instance or AZ is gone |
| [Security incident response](#security-incident-response) | Suspected breach |

---

## Deploy

1. Check out the release tag in `/opt/prw`. Confirm that the image digests in `compose.yaml` match the signed release notes.
2. `sudo systemctl start prw-secrets.service` to refresh secrets from SSM.
3. Run `prw-control check-config` from the **new** image. It must exit 0.
4. Take a pre-migration backup with `/opt/prw/deploy/scripts/backup.sh --tag pre-<version>`. Confirm that the object appears in S3.
5. Run `prw-control migrate up` from the new image, as `prw_owner`.
6. `docker compose up -d control`.
7. Wait for `curl -fsS https://api.example.invalid/health/ready` to return 200. Allow up to 60 s.
8. Run the smoke test `deploy/scripts/smoke.sh`:
   1. `GET /v1/meta/compat` returns the expected versions.
   2. The WSS upgrade on `/v1/agent/control` yields an `auth.challenge` message.
   3. A TURN allocation with throwaway credentials succeeds. Mint them with `prwctl admin turn-test-cred` and test with `turnutils_uclient`.
   4. `openssl s_client -connect turn.example.invalid:443` presents a valid certificate.
9. Record the version, the time and the operator in the deploy log.

**Abort** if step 3, 5 or 7 fails, and follow [Rollback](#rollback).

## Rollback

| Situation | Action |
|---|---|
| Application bug; the migration was additive | Re-pin the previous image digest, `docker compose up -d control`, then re-run the smoke test. |
| A migration broke compatibility, which the expand/contract rule should prevent | Stop `control`. Restore the pre-migration dump ([Database restore](#database-restore)). Deploy the previous image. Replay revocations. |
| coturn upgrade failure | Re-pin the previous coturn digest and recreate the container. Then confirm a TURN allocation and a TURNS handshake on 443. |
| Bad agent release | Withdraw it from the release page and publish an advisory with the previous version's checksum. Users reinstall the previous `.deb`. The server's N/N−1 compatibility keeps older agents working. |
| Bad mobile app release | Ship a hotfix. Raise `min_app_version` on the server **only** for a security issue. |

## Rotate secrets and keys

All server keys support an overlap window. Rotate one secret at a time and verify each before moving on.

| Secret | Procedure | Effect on clients |
|---|---|---|
| Ticket/lease/relay signing key (Ed25519) | 1. Add the new key to SSM as `ticket_signing_key_next`. 2. Deploy, so the JWKS publishes both keys and agents receive `jwks.update`. 3. Wait at least 15 min. 4. Promote the new key to signing and keep the old one for verification for 1 h. 5. Remove the old key. | None if the overlap is respected. Agents verify tickets against their pinned set. |
| Access-token signing key | Same pattern as above. Without an overlap, every phone signs in again. | Phones refresh; worst case, they sign in again |
| TURN shared secret | 1. Put both secrets in coturn's config so it accepts either. 2. Switch `control` to the new secret. 3. After the maximum credential lifetime of 5 min, remove the old one. | None |
| Pairing HMAC pepper | Rotate only while no pairing is in progress. Pending challenges become invalid. | Any in-flight pairing must restart |
| Postgres passwords | `ALTER ROLE … PASSWORD`, update SSM, re-render secrets, then restart `control` and the backup job. | Brief API restart |
| Device keys (phones, hosts) | Never rotated server-side, because they are owned by the client. To rotate, re-pair the device. | — |

Afterwards, run `gitleaks` against the repo and confirm that no secret is present in images (`trivy image`).

## Lost or stolen phone

1. From another signed-in phone, go to **Settings → Devices → \<phone> → Revoke**. If no other phone is available, have the operator run `prwctl admin device revoke <device-id>`.
2. Verify that revocation took effect:
   1. The device shows as `revoked`, and its refresh-token family is revoked.
   2. All of its grants show `revoked_at`.
   3. The `prw_revoke_propagation_seconds` metric shows delivery to online hosts in under 30 s.
3. Running tmux sessions are **detached, not killed**. Review them from a trusted phone and terminate any you don't recognise.
4. Review **Activity** for the phone's connections and session events since it was lost.
5. If the Google account may also be compromised:
   1. Change the Google password and review its security settings.
   2. Sign out every other session.
   3. Look for any newly registered phone in Activity and revoke it.
6. Optionally, re-pair a replacement phone. It starts with **no grants**.

## Compromised host

1. Revoke the host: **Device → Revoke**, or `prwctl admin device revoke <host-id>`. Its control socket closes and no new tickets are issued for it.
2. Treat everything that host's OS user could reach as exposed. That includes repositories, cloud credentials and SSH keys on the machine.
3. Revoke the grants that point to the host. Phones themselves are not compromised just because they connected to a bad host. Their keys never leave the phones.
4. Rebuild or clean the host. Then re-install the agent, which generates a new key, and pair it again. Never restore the old identity key.
5. Review audit events for the host: connections, sessions, and the times they happened.

## Failed connection triage

Start from the `connection_attempt_id` shown on the app's diagnostics screen. Do **not** ask for terminal output or screenshots of terminal content.

1. **Attempt record.** Run `prwctl admin attempt show <id>` and note:
   - the status and failure code;
   - the path attempted (direct, TURN, WSS relay);
   - the timestamps.
2. **Use the failure code:**

   | Code | Likely cause | Next step |
   |---|---|---|
   | `access_grant_missing` / `device_revoked` | Authorization | Check the grants in the app; this is expected behaviour |
   | `agent_offline` | Host not connected | Check the agent with `systemctl --user status prw-agent` and `prw-agent doctor` |
   | `unsupported_version` | Version skew | Upgrade the agent or app |
   | `connect_timeout` | No path succeeded | Continue at step 3 |
   | `peer_identity_mismatch` | Fingerprint or attestation failure | **Treat as a security event.** Escalate to [incident response](#security-incident-response). |
   | `relay_unavailable` | WSS relay at capacity or down | Check `prw_relay_splices` and the relay limits |
   | `lease_expired` | Host could not renew its grant lease | Check the host's connectivity to the control plane |

3. **Signaling.** Check the signaling counters for the attempt: whether the offer, answer and candidates were exchanged, and whether any message was rejected for size or rate.
4. **TURN.** In the coturn logs, find the attempt's TURN username and check for `ALLOCATE` success or failure, a 401 caused by credential expiry or clock skew, or a denied peer IP.
5. **Network class.** If the phone's network blocks UDP, TCP 3478 and 5349, only TURNS on EIP-B:443 or the WSS relay can work. Confirm `T_fallback` triggered the WSS race.
6. **Reproduce** in netlab with the matching scenario (see [testing](../development/testing.md#network-matrix)). Record the result in the tested-network matrix.

## Database restore

1. Stop writes: `docker compose stop control`.
2. Choose the dump: the latest nightly, or the pre-migration dump for a rollback. Download it, then verify that it decrypts and that its checksum matches.
3. Restore: `pg_restore --clean --if-exists -d prw` as `prw_owner`.
4. Run `prw-control migrate status`. If the running image is newer than the dump, run `migrate up`.
5. **Re-apply revocations made after the dump.** A restore must never bring a revoked device or grant back to life.
   1. Collect revocation events newer than the dump time. Sources:
      - audit events still present in any newer dump;
      - control-plane logs (`event=device_revoked|grant_revoked|logout`);
      - the owner's memory of recent revocations.
   2. Replay them: `prwctl admin replay-revocations --since <dump-time> --from <export-file>`.
   3. Review the device and grant list with the owner.
6. If a compromise is suspected, [rotate](#rotate-secrets-and-keys) the access key, the ticket key, the pairing pepper and the TURN secret.
7. Start `control`, then check `/health/ready` and run the smoke test.
8. Record the RPO and RTO you actually achieved.

## Certificate issues

| Symptom | Action |
|---|---|
| `api` certificate expiring | Read the Caddy logs (`docker compose logs caddy`) for ACME errors, and check that port 80 on EIP-A is reachable and DNS points to EIP-A. Caddy retries automatically. |
| `turn` certificate expiring | Run `certbot renew --dry-run`, then `certbot renew`. Confirm the deploy hook copied the files to `/var/lib/prw/coturn-tls/` and restarted coturn. |
| ACME rate-limited after a rebuild | Use the certificate volume from the latest EBS snapshot, or wait out the limit. The WSS relay (on `api`) and TURN (on `turn`) degrade independently. |
| Clients report TLS errors after renewal | Check the chain with `openssl s_client -connect <host>:443 -showcerts`. Check the system clock on the instance. |

## Relay abuse or bandwidth spike

1. Identify the source. Use `prw_relay_bytes_total` by device and attempt, the coturn allocations by username, and the TURN usernames (each maps to a connection attempt).
2. If the source is legitimate heavy use (for example a large log being printed), no action is needed beyond the caps. Consider raising the cost threshold.
3. If it is abuse or a malfunction:
   1. Revoke the offending device's grants or the device itself.
   2. Lower `PRW_RELAY_MAX_BPS`, `user-quota` or `total-quota`, and redeploy.
   3. Rotate the TURN secret if credentials may have leaked.
4. If a DDoS is hitting the coturn ports, temporarily drop the UDP relay range in the security group. Clients fall back to TURNS on 443 or the WSS relay.
5. Record the incident and adjust alert thresholds.

## Server loss recovery

1. Run `terraform apply` in `deploy/terraform/envs/prod`. This creates a replacement instance. The EIPs are retained resources and get re-associated, so DNS and client configuration stay valid.
2. User-data installs Docker and the SSM agent and writes the netplan file. Then `prw-secrets.service` renders secrets from SSM.
3. Restore the database using [Database restore](#database-restore), including the revocation replay.
4. Certificates are re-issued automatically. If ACME rate limits apply, restore the certificate volumes from a snapshot.
5. Run the deploy steps for the current release, then the smoke test.
6. Agents reconnect automatically, because their pinned keys are unchanged unless rotated. Phones refresh their tokens.
7. Target RTO is 4 hours or less. Communicate the outage window. During the outage, existing direct sessions survived only until their 10-minute lease ran out.

## Security incident response

| Phase | Actions |
|---|---|
| **Detect** | Triggers include an alert, a `peer_identity_mismatch` spike, unexpected devices or grants in Activity, a suspicious coturn pattern, or an external report. |
| **Contain** | Restrict ingress if needed, by narrowing the security group to the operator's IP. Revoke the affected devices. Disable pairing with `PRW_PAIRING_ENABLED=false`. |
| **Preserve** | Snapshot the EBS volumes. Export audit events and logs to an isolated bucket **before** making changes. |
| **Eradicate** | Rotate all secrets ([Rotate secrets and keys](#rotate-secrets-and-keys)). Rebuild the instance from pinned images and Terraform. Do not reuse a possibly tampered host. |
| **Recover** | Restore data as required. Re-enable ingress. Have the owner re-pair any device of uncertain integrity. |
| **Learn** | Write a timeline and root cause. Add tests and alerts. Update these runbooks. |

If the control plane itself is suspected compromised, assume the attacker could:
- observe metadata;
- mint tickets;
- enroll a new phone and grant it access.

Phone keys pinned on hosts limit impersonation of *existing* phones. Revoke every grant, rotate every server key, re-pair the hosts, and grant access again deliberately.
