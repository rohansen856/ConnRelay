# API Reference

> **Status:** design, not yet implemented. Values marked *proposed* may change.

The control plane exposes a REST API under `/v1` and three WebSocket endpoints. It handles identity, pairing, grants, connection authorization, signaling and relaying of encrypted bytes. **It never carries terminal plaintext.** Opening and attaching terminals happens peer-to-peer over the authenticated data channel. The wire-level details (signature inputs, ticket claims, frames, timers) are specified in [protocol.md](protocol.md).

Related: [Security model](security.md), [Data model](data-model.md).

---

## 1. Conventions

| Topic | Rule |
|---|---|
| Transport | HTTPS only at `https://api.example.invalid` (Caddy on port 443). JSON bodies with `Content-Type: application/json`. |
| Body limits | 64 KiB by default, 16 KiB for `/v1/auth/exchange`, 4 KiB for `/v1/pairing/*`. Unknown JSON fields are rejected. |
| IDs | UUIDv7 strings. |
| Time | RFC 3339 timestamps in UTC. |
| Correlation | Every response includes `X-Request-Id`. The same value appears in error bodies and audit events. |
| Device signatures | `sig` fields are **ES256 JWS** made with the device's P-256 key, over the JCS-canonical (RFC 8785) JSON of a purpose-tagged object. |
| Server tokens | Access JWTs, tickets, relay tokens and leases are **EdDSA (Ed25519) JWS**. |
| Pagination | Requests take `?limit=1..100` (default 50) and `?cursor=<opaque>`. Responses look like `{"items":[…],"next_cursor":"…"\|null}`. |
| Idempotency | Endpoints marked **Idem** require an `Idempotency-Key` header of 16–128 characters. Repeating the same key with the same body returns the original result. The same key with a different body returns 422 `idempotency_conflict`. Keys expire after 24 h. |
| Concurrency | Versioned resources return an `ETag`. `PATCH` and revoke calls take `If-Match`; a mismatch returns 412 `precondition_failed`. |
| Anti-enumeration | Resources belonging to another account return 404 `not_found`, never 403. |

### Authentication schemes

| Scheme | Used by | Description |
|---|---|---|
| `UserBearer` | Phone | `Authorization: Bearer <access JWT>`. EdDSA-signed, valid 10 minutes. Claims: `sub` (account), `did` (phone device), `sid` (auth session), `kid`, `aud=prw-api`. |
| `WaitToken` | Host during pairing | `Authorization: Bearer <wait_token>`, returned when a pairing challenge is created. |
| `AgentSocket` | Host agent | Challenge/response on `/v1/agent/control` using the host device key. |
| `None` | — | Unauthenticated, rate-limited by IP. |

Tokens never appear in URLs.

### Error envelope

```json
{
  "error": {
    "code": "access_grant_missing",
    "message": "This phone is not authorized to open a terminal on this computer.",
    "retryable": false,
    "request_id": "req_01J...",
    "details": {}
  }
}
```

`details` never contains tokens, codes, SDP or IP addresses. Validation errors list only field names, in `details.fields`.

### Client retry policy

| Situation | Behaviour |
|---|---|
| `retryable: true`, or a 5xx on an idempotent or **Idem** call | Exponential backoff with full jitter: 500 ms base, 30 s cap, at most 5 attempts. |
| 429 | Wait as long as `Retry-After` says. |
| 401 `unauthenticated` | Refresh once, then retry once. |
| Anything else | Do not retry automatically. |

---

## 2. Endpoint catalog

| # | Method and path | Auth | Idem | Purpose |
|---|---|---|---|---|
| 1 | `POST /v1/auth/challenge` | None | – | Get a single-use proof-of-possession nonce, valid 120 s |
| 2 | `POST /v1/auth/exchange` | None (Google ID token in the body) | ✓ | Sign in, and register or match this phone |
| 3 | `POST /v1/auth/refresh` | Refresh token + device signature | – | Rotate tokens |
| 4 | `POST /v1/auth/logout` | UserBearer | – | Revoke this phone's token family |
| 5 | `GET /v1/me` | UserBearer | – | Account and current device |
| 6 | `GET /v1/devices` | UserBearer | – | List devices with derived presence |
| 7 | `GET /v1/devices/{id}` | UserBearer | – | Device detail |
| 8 | `PATCH /v1/devices/{id}` | UserBearer + If-Match | – | Rename a device |
| 9 | `POST /v1/devices/{id}/revoke` | UserBearer + If-Match | – | Revoke a device |
| 10 | `POST /v1/pairing/challenges` | None (host signature) | – | Host creates a pairing challenge |
| 11 | `GET /v1/pairing/challenges/{id}/wait` | WaitToken | – | Host long-polls for approval |
| 12 | `POST /v1/pairing/resolve` | UserBearer | – | Phone looks up a challenge by QR reference or code |
| 13 | `POST /v1/pairing/challenges/{id}/approve` | UserBearer | ✓ | Phone approves after the fingerprint check |
| 14 | `POST /v1/pairing/challenges/{id}/cancel` | UserBearer or WaitToken | – | Abort pairing |
| 15 | `POST /v1/pairing/challenges/{id}/complete` | WaitToken + host signature | – | Host proves key possession and enrolls |
| 16 | `GET /v1/access-grants` | UserBearer | – | List grants |
| 17 | `POST /v1/access-grants` | UserBearer | ✓ | Grant a phone access to a host |
| 18 | `PATCH /v1/access-grants/{id}` | UserBearer + If-Match | – | Change a grant's capabilities or expiry |
| 19 | `POST /v1/access-grants/{id}/revoke` | UserBearer + If-Match | – | Revoke a grant |
| 20 | `POST /v1/connections` | UserBearer | ✓ | Create a connection attempt (returns ticket, ICE config, relay token) |
| 21 | `GET /v1/connections/{id}` | UserBearer | – | Attempt state |
| 22 | `PATCH /v1/connections/{id}` | UserBearer | – | Report status, path or failure, or cancel |
| 23 | `POST /v1/connections/{id}/turn-credentials` | UserBearer | – | Fresh TURN credentials for an ICE restart |
| 24 | `GET /v1/hosts/{id}/terminal-sessions` | UserBearer | – | Session metadata for a host |
| 25 | `GET /v1/terminal-sessions/{id}` | UserBearer | – | Session metadata |
| 26 | `GET /v1/audit-events` | UserBearer | – | Activity feed |
| 27 | `GET /v1/meta/compat` | None | – | Supported versions |
| 28 | `GET /health/live`, `GET /health/ready` | None | – | Health probes |

There is deliberately **no REST endpoint for creating, attaching or terminating a terminal**. Those operations are sent as `terminal.*` messages over the attested peer connection, so the server cannot start or drive a shell.

---

## 3. Authentication

### 3.1 `POST /v1/auth/challenge`

Response `200`:
```json
{"nonce": "b64url-32-bytes", "expires_at": "2026-10-13T10:02:00Z"}
```

The nonce is single-use and expires after 120 s. Rate limit: 30 per IP per minute (*proposed*).

### 3.2 `POST /v1/auth/exchange`

The phone first completes Google sign-in through AppAuth (Authorization Code + PKCE) and obtains an ID token. Then it sends:

```json
{
  "provider": "google",
  "id_token": "<Google OIDC ID token>",
  "oidc_nonce": "<nonce used in the Google auth request>",
  "device": {
    "platform": "android",
    "display_name": "Pixel 9",
    "app_version": "0.1.0",
    "proto": {"min": 1, "max": 1},
    "public_key_spki": "<b64url DER, P-256>",
    "pop": {
      "nonce": "<from /v1/auth/challenge>",
      "sig": "<ES256 JWS over JCS({purpose:'prw.auth.v1',nonce,spki_fp,iat})>"
    }
  }
}
```

Response `200`:
```json
{
  "access_token": "<EdDSA JWT, 10 min>",
  "access_expires_at": "…",
  "refresh_token": "<opaque, 30 d sliding / 90 d absolute>",
  "refresh_expires_at": "…",
  "account": {"id": "…", "display_name": "…"},
  "device_id": "…",
  "device": {"kind": "phone", "key_fingerprint": "…", "created": true}
}
```

**Validation, in order:**
1. ID token: `iss` is Google, `aud` is our client ID, the signature verifies against Google's JWKS, `exp` is valid within 60 s of skew, and `nonce` matches.
2. The Google `sub` is in `PRW_ALLOWED_SUBJECTS`.
3. The proof-of-possession nonce is unused.
4. The SPKI is a P-256 key and the JWS verifies with it.
5. `display_name` is NFC-normalized, contains no control characters, and is 1–120 characters.

A newly enrolled phone needs no further approval. It starts with **no access grants**, and the enrollment is recorded in the audit log.

**Errors:**

| Status | Code |
|---|---|
| 400 | `validation_failed`, `nonce_invalid` |
| 401 | `unauthenticated` (invalid Google token) |
| 403 | `account_not_allowed` |
| 426 | `unsupported_client_version` |

### 3.3 `POST /v1/auth/refresh`

```json
{"refresh_token": "…",
 "pop": {"nonce": "<from /v1/auth/challenge>",
         "sig": "<ES256 JWS over JCS({purpose:'prw.refresh.v1',nonce,device_id,iat})>"}}
```

The response has the same shape as the exchange response, without `account` and `device`.

**Errors:**

| Status | Code |
|---|---|
| 401 | `unauthenticated` |
| 401 | `refresh_reuse_detected` (the whole token family is revoked) |
| 403 | `device_revoked` |

The client must store the new refresh token before it discards the old one.

### 3.4 `POST /v1/auth/logout`

Returns `204`. Revokes this phone's token family only. Other phones stay signed in.

### 3.5 `GET /v1/me`

```json
{"account": {"id": "…", "display_name": "…", "email": "…"},
 "device": {"id": "…", "kind": "phone", "platform": "ios", "display_name": "…", "key_fingerprint": "…"}}
```

---

## 4. Devices

### 4.1 `GET /v1/devices`

Query parameters:
- `kind`: `host` or `phone`.
- `state`: `active` or `revoked`.
- `q`: name prefix.
- `sort`: `last_seen`, `name` or `last_connected`.
- `limit` and `cursor`.

Item:
```json
{
  "id": "…", "kind": "host", "platform": "linux", "display_name": "workstation",
  "key_fingerprint": "ABCD-EFGH-…", "software_version": "0.1.0", "protocol_version": 1,
  "admin_state": "active",
  "presence": "online",
  "last_seen_at": "…",
  "capabilities": {"tmux": true, "tmux_version": "3.4", "pty": true},
  "my_grant": {"id": "…", "capabilities": ["terminal"], "expires_at": null},
  "compat": "ok",
  "version": 3
}
```

`presence` is derived, never stored:

| Value | Condition |
|---|---|
| `online` | An authenticated agent socket is registered and the last heartbeat is under 75 s old |
| `stale` | Last heartbeat 75–150 s old |
| `offline` | Older than that |
| `unknown` | No heartbeat has ever been seen |

`my_grant` is the calling phone's grant on this host, or `null`. `compat` is one of `ok`, `update_recommended` or `unsupported`.

### 4.2 `GET /v1/devices/{id}`

Returns the same item. Responds 404 for unknown devices and for devices in other accounts.

### 4.3 `PATCH /v1/devices/{id}`

Request: `{"display_name": "…"}` with `If-Match: "3"`.

Returns `200` with the updated device. Errors: 400, 404, 412.

### 4.4 `POST /v1/devices/{id}/revoke`

Request: `{"reason": "lost" | "user" | "compromised" | "replaced"}` with `If-Match`.

Response `200`:
```json
{"device": {"…": "…", "admin_state": "revoked"}, "grants_revoked": 3, "sessions_notified": true}
```

- Revoking a device revokes all of its grants and refresh tokens, and marks its live connection attempts as revoked.
- Online peers are notified. Connected peers are closed within 30 s. tmux sessions on hosts are **detached, not killed**.
- Revoking the last active phone requires `?confirm_last_phone=true`. Recovery from that is a fresh Google sign-in, which enrolls a new phone.

---

## 5. Pairing

```mermaid
sequenceDiagram
  participant H as Host agent
  participant C as Control plane
  participant P as Phone
  H->>C: POST /pairing/challenges (host SPKI + signature)
  C-->>H: challenge_id, pairing_ref, display_code, wait_token, qr_payload
  H->>C: GET /pairing/challenges/{id}/wait (long-poll)
  P->>C: POST /pairing/resolve (ref from QR or code)
  C-->>P: hostname, OS, host_key_fingerprint
  P->>P: compare fingerprint with QR
  P->>C: POST /pairing/challenges/{id}/approve
  C-->>H: wait returns {status: approved, nonce2}
  H->>C: POST /pairing/challenges/{id}/complete (signature over nonce2)
  C-->>H: device_id, pinned JWKS, control_ws_url
```

### 5.1 `POST /v1/pairing/challenges` (host)

Rate limit: 5 per IP per 10 minutes.

```json
{"host_public_key_spki": "<b64url>", "hostname": "workstation",
 "os": {"id": "ubuntu", "version": "24.04"}, "agent_version": "0.1.0",
 "proto": {"min": 1, "max": 1},
 "pop_sig": "<ES256 JWS over JCS({purpose:'prw.pair.create.v1',spki_fp,iat})>"}
```

Response `201`:
```json
{"challenge_id": "…",
 "pairing_ref": "<b64url 16 bytes>",
 "display_code": "7KQ2-M9XT",
 "nonce": "<b64url 32 bytes>",
 "expires_at": "…(+5 min)",
 "wait_token": "<b64url 32 bytes>",
 "qr_payload": "prw://pair?v=1&ref=<ref>&fp=<host spki_fp>&api=https://api.example.invalid"}
```

The display code is 8 Crockford base32 characters (40 bits). The server stores only HMACs of the pairing ref, the code and the wait token.

### 5.2 `GET /v1/pairing/challenges/{id}/wait` (host)

The server holds the request for up to 25 s, then returns one of:

| Response | Meaning |
|---|---|
| `200 {"status":"pending"}` | Not approved yet; the host polls again |
| `200 {"status":"approved","nonce2":"…"}` | Approved |
| `410 pairing_expired` | The challenge expired |
| `409 pairing_used` or `pairing_rejected` | The challenge was already used or was canceled |

### 5.3 `POST /v1/pairing/resolve` (phone)

Request: `{"pairing_ref": "…"}` or `{"display_code": "7KQ2M9XT"}`.

Codes are normalized before lookup: case-insensitive, hyphens ignored, and `I`, `L` and `O` mapped to `1`, `1` and `0`.

Response `200`:
```json
{"challenge_id": "…", "hostname": "workstation", "os": {"id": "ubuntu", "version": "24.04"},
 "agent_version": "0.1.0", "host_key_fingerprint": "…", "expires_at": "…", "compat": "ok"}
```

The phone compares `host_key_fingerprint` with the `fp` value from the QR code. A mismatch is a hard failure: the phone cancels the challenge with reason `pairing_fingerprint_mismatch`. When the code was typed in manually, the app shows the fingerprint so the user can compare it with the agent's output.

**Errors:**

| Status | Code |
|---|---|
| 404 | `not_found` (wrong code; each failure counts toward the 5-attempt lock) |
| 410 | `pairing_expired` |
| 409 | `pairing_used` |
| 423 | `pairing_locked` |

Rate limit: 10 per account per 10 minutes.

### 5.4 `POST /v1/pairing/challenges/{id}/approve` (phone)

```json
{"host_key_fingerprint": "…", "display_name": "workstation", "grant_to_this_phone": false}
```

Returns `200 {"status": "approved"}`.

- No grant is created unless `grant_to_this_phone` is `true`.
- A fingerprint that does not match returns 409 `pairing_fingerprint_mismatch` and counts as a failed attempt.

### 5.5 `POST /v1/pairing/challenges/{id}/cancel`

Returns `200 {"status": "canceled"}`. Callable by the phone or by the host (using its wait token).

### 5.6 `POST /v1/pairing/challenges/{id}/complete` (host)

```json
{"sig": "<ES256 JWS over JCS({purpose:'prw.pair.complete.v1',challenge_id,nonce2,spki_fp,iat})>"}
```

Response `200`:
```json
{"device_id": "…", "account_id": "…",
 "jwks": {"keys": [{"kid": "…", "kty": "OKP", "crv": "Ed25519", "x": "…", "use": "sig"}]},
 "control_ws_url": "wss://api.example.invalid/v1/agent/control"}
```

The host pins `jwks` and uses it to verify tickets and leases.

**Errors:**

| Status | Code | Retry? |
|---|---|---|
| 409 | `pairing_not_approved` | Retryable: keep waiting |
| 410 | `pairing_expired` | No |
| 409 | `pairing_used` | No |
| 403 | `signature_invalid` | No |

---

## 6. Access grants

### 6.1 `GET /v1/access-grants`

Filters: `phone_device_id`, `host_device_id`, `state=active|revoked`.

### 6.2 `POST /v1/access-grants`

```json
{"phone_device_id": "…", "host_device_id": "…", "capabilities": ["terminal"], "expires_at": null}
```

Returns `201` with the grant.

- In V1, `capabilities` must be `["terminal"]`. Anything else returns 400 `capability_not_supported`.
- Both devices must be active, belong to the caller's account, and be of the correct kind (one phone, one host).

**Errors:**

| Status | Code |
|---|---|
| 409 | `grant_exists` |
| 404 | `not_found` |

### 6.3 `PATCH /v1/access-grants/{id}`

Request: `{"expires_at": "…"}` with `If-Match`.

Returns `200`. Errors: 404, 412.

### 6.4 `POST /v1/access-grants/{id}/revoke`

Returns `200` with the grant, now including `revoked_at`.

- An outbox event notifies the host and the phone.
- The host closes affected peer connections within the 30 s target. Their tmux sessions keep running.
- A revoked grant is never reactivated. Re-granting creates a new grant.

---

## 7. Connections

### 7.1 `POST /v1/connections` (Idem)

```json
{"host_device_id": "…", "capability": "terminal", "target_terminal_session_id": "…"}
```

`target_terminal_session_id` is optional and signals an intent to attach.

Response `201`:
```json
{
  "connection_attempt_id": "…",
  "status": "authorized",
  "expires_at": "…(+60 s)",
  "ticket": "<EdDSA JWS, typ=prw-ticket+jwt>",
  "relay": {"url": "wss://api.example.invalid/v1/relay", "token": "<relay token, role=client, exp +90 s>"},
  "ice_servers": [
    {"urls": ["stun:turn.example.invalid:3478"]},
    {"urls": ["turn:turn.example.invalid:3478?transport=udp",
              "turn:turn.example.invalid:3478?transport=tcp",
              "turns:turn.example.invalid:443?transport=tcp"],
     "username": "<unix_expiry>:<attempt_id>", "credential": "<b64 HMAC-SHA1>"}
  ],
  "attestation_nonce": "<b64url 32 bytes>",
  "signaling_url": "wss://api.example.invalid/v1/signaling",
  "fallback": {"wss_race_after_ms": 4000},
  "host": {"device_id": "…", "key_fingerprint": "…", "public_key_spki": "…"}
}
```

**Ticket claims:**

| Claim | Value |
|---|---|
| `iss` | Server |
| `aud` | Host device |
| `sub` | Phone device |
| `acct` | Account |
| `att` | Attempt ID |
| `cap` | Capability (`terminal`) |
| `sess` | Target session, optional |
| `nonce` | Attestation nonce |
| `jti` | Unique ticket ID |
| `iat`, `nbf`, `exp` | `exp = iat + 60 s` |
| `pv` | Protocol version |

The host receives `attempt.incoming` on its control socket. It carries the same ticket, a host relay token (`role=server`) and the ICE servers.

**Checks, in order:**

| # | Check | Error |
|---|---|---|
| 1 | Account is valid | — |
| 2 | Phone is active | 403 `device_revoked` |
| 3 | Host is active and online | 409 `agent_offline` |
| 4 | An active, unexpired grant includes `terminal` | 403 `access_grant_missing` |
| 5 | Agent protocol version is acceptable | 426 `unsupported_agent_version` |
| 6 | Rate limit: 10 per minute per phone | 429 `rate_limited` |
| 7 | Host capacity: 20 sessions, 8 peers | 429 `host_capacity_reached` |

A retry with the same `Idempotency-Key` within 60 s returns the same attempt with re-signed tokens. The tokens are re-signed from stored claims; the raw tokens are never stored.

### 7.2 `GET /v1/connections/{id}`

```json
{"id": "…", "status": "connected_direct", "path_type": "direct", "failure_code": null,
 "created_at": "…", "connected_at": "…", "ended_at": null}
```

Never returns tickets or tokens.

### 7.3 `PATCH /v1/connections/{id}`

The phone reports progress with:
```json
{"status": "connected_direct", "path_type": "direct"}
```

or a failure or cancellation:
```json
{"status": "failed", "failure_code": "connect_timeout"}
```

The host reports the same information as `attempt.status` messages on its control socket.

Allowed `status` values are `connected_direct`, `connected_relay`, `connected_wss`, `failed` and `canceled`. Only valid state-machine transitions are accepted, and only from the attempt's own two devices; anything else returns 409 `invalid_transition`. Canceling is idempotent and also closes signaling and the relay for that attempt.

Attempt state machine: `authorized → signaling → ice_checking → (relay_fallback) → connected_direct | connected_relay | connected_wss`, with terminal states `failed`, `canceled`, `expired` and `revoked`.

### 7.4 `POST /v1/connections/{id}/turn-credentials`

Returns fresh TURN credentials (`ice_servers`) for a connected attempt. Used for an ICE restart after a network change. Fails with 409 if the attempt is not live or its grant has been revoked.

---

## 8. Terminal session metadata

The server's copy is metadata the agent reports. The live state comes from `terminal.list` on the peer connection.

### 8.1 `GET /v1/hosts/{id}/terminal-sessions` and `GET /v1/terminal-sessions/{id}`

```json
{"id": "…", "host_device_id": "…", "title": "claude", "backend": "tmux", "persistent": true,
 "status": "detached", "attached_clients": 0, "shell_kind": "zsh", "working_directory_label": null,
 "created_at": "…", "last_attached_at": "…", "ended_at": null, "exit_code": null,
 "metadata_freshness": "live"}
```

`metadata_freshness` is `cached` when the host is offline. The app then shows the session as "Host unavailable".

## 9. Audit events

### 9.1 `GET /v1/audit-events`

Filters: `device_id`, `event_type`, `since`, `until`, `limit`, `cursor`.

Items contain only allowlisted metadata. They never contain terminal content, tokens or codes.

```json
{"id": 1042, "event_type": "grant.revoked", "outcome": "success", "actor_kind": "phone",
 "actor_device_id": "…", "target_device_id": "…", "reason_code": null,
 "request_id": "req_…", "occurred_at": "…"}
```

## 10. Compatibility and health

### 10.1 `GET /v1/meta/compat`

```json
{"server_version": "0.1.0", "protocol": {"min": 1, "max": 1},
 "min_app_version": "0.1.0", "min_agent_version": "0.1.0"}
```

### 10.2 Health checks

| Endpoint | Behaviour |
|---|---|
| `GET /health/live` | Returns `200 {"status":"ok"}` while the process is up. |
| `GET /health/ready` | Returns `200` only when the database is reachable, the schema is at the expected version, the signing keys are loaded and the outbox worker is alive. Otherwise returns `503 {"status":"not_ready","checks":{"db":"fail"}}`. |

The readiness response names failing checks only. It never includes errors or connection strings.

---

## 11. WebSocket endpoints

Rules shared by all WebSocket endpoints:
- Subprotocol `prw.v1`.
- Browser `Origin` headers are rejected.
- Frames are at most 64 KiB.
- The server derives the sender's identity from the authenticated socket and overwrites any `from_device_id` the client sends.

| Endpoint | Client | Authentication | Client → server | Server → client |
|---|---|---|---|---|
| `/v1/agent/control` | Host agent | The server sends `auth.challenge{nonce}`. The agent replies `auth.response{device_id, sig, agent_version, proto}`, where `sig` is an ES256 JWS over `{purpose:'prw.agent.v1',nonce,device_id,iat}`. The server answers `auth.ok`. The socket is re-challenged every 15 min. | `heartbeat` (every 25 s: session count, tmux availability, version, peers); `session.event` (metadata); `attempt.status`; signaling for its own attempts; `revoke_notice.ack` | **Allowlist only:** `auth.*`, `heartbeat.ack`, `attempt.incoming`, `attempt.cancel`, `grant.lease` (signed, 10 min, renewed every 3 min), `revoke_notice`, `jwks.update`, `pairing.approved`, `server.notice`, relayed signaling |
| `/v1/signaling` | Phone | First frame `{"type":"auth","access_token":"…"}` | `offer`, `ice_candidate`, `ice_complete`, `tls_fingerprint`, `attempt_cancel` | `answer`, `ice_candidate`, `ice_complete`, `tls_fingerprint`, `attempt_status`, `revoke_notice` |
| `/v1/relay` | Phone and host | First text frame `{"type":"join","attempt_id":"…","relay_token":"…","role":"client\|server"}`. The relay token is an EdDSA JWS with claims `{att, role, dev, exp: +90 s, jti}`; its `jti` is single-use. | After `{"type":"joined"}`: **opaque binary frames only** (the inner TLS 1.3 stream) | `joined`, then close codes |

The control channel can never carry terminal operations. Any message type outside the allowlist is dropped and audited.

### Message envelope

Every WebSocket text message is one JSON object. Routing fields sit at the top level and the body sits under `payload`:

```json
{"type": "signal", "attempt_id": "…", "kind": "offer", "from_device_id": "…", "payload": {"sdp": "…"}}
{"type": "auth.response", "payload": {"device_id": "…", "sig": "…", "agent_version": "0.1.0"}}
{"type": "attempt.status", "attempt_id": "…", "payload": {"status": "connected_direct", "path_type": "direct"}}
{"type": "grant.lease", "lease": "<EdDSA JWS, typ prw-lease+jwt>"}
```

- **Signaling** uses `type: "signal"` with `kind` set to `offer`, `answer`, `ice_candidate`, `ice_complete`, `tls_fingerprint` or `attempt_cancel`. The server sets `from_device_id` from the socket.
- **Early messages for a phone.** Host messages sent to a phone that has not yet opened its signaling socket are buffered for up to 15 s (32 messages per attempt). Clients should still open `/v1/signaling` *before* `POST /v1/connections`.

### Limits

| Scope | Limit |
|---|---|
| Signaling | 100 messages per attempt, 20 messages/s per socket, 50 ICE candidates per attempt. Exceeding a limit closes the socket with 4429. |
| Relay | The second peer must join within 15 s. Other limits: 120 s idle timeout, 64 KiB per message, 2 Mbit/s and 2 GiB per attempt, 16 concurrent spliced attempts per account, and a global splice cap (beyond it: `relay_unavailable`). |

### Close codes

| Code | Meaning |
|---|---|
| 4400 | Bad request or protocol error |
| 4401 | Authentication failed |
| 4403 | Revoked |
| 4408 | Timeout |
| 4429 | Rate limited |
| 4500 | Internal error |

---

## 12. Error codes

| Code | HTTP / channel | Retryable | Meaning |
|---|---|---|---|
| `unauthenticated` | 401 | After refresh | Token missing, invalid or expired |
| `account_not_allowed` | 403 | No | Google subject is not on the allowlist |
| `nonce_invalid` | 400 | Get a new challenge | Proof-of-possession nonce unknown, already used or expired |
| `refresh_reuse_detected` | 401 | No | Refresh token reused; the family is revoked |
| `device_revoked` | 403 | No | The calling device has been revoked |
| `not_found` | 404 | No | Resource missing, or belongs to another account |
| `validation_failed` | 400 | No | Field names are listed in `details.fields` |
| `capability_not_supported` | 400 | No | Capability not available in V1 |
| `pairing_expired` | 410 | No | |
| `pairing_used` | 409 | No | |
| `pairing_locked` | 423 | No | Too many failed attempts |
| `pairing_fingerprint_mismatch` | 409 | No | |
| `pairing_rejected` | 409 | No | Challenge was canceled |
| `pairing_not_approved` | 409 | Yes | Keep waiting |
| `signature_invalid` | 403 | No | |
| `grant_exists` | 409 | No | |
| `access_grant_missing` | 403 | No | |
| `invalid_transition` | 409 | No | Invalid attempt state change |
| `agent_offline` | 409 | Yes | |
| `attempt_expired`, `attempt_canceled` | 409 | No | |
| `host_capacity_reached` | 429 | Yes | |
| `rate_limited` | 429 | Yes | Honour `Retry-After` |
| `precondition_failed` | 412 | Refetch | Version mismatch |
| `idempotency_conflict` | 422 | No | |
| `unsupported_client_version`, `unsupported_agent_version` | 426 | No | Update required |
| `relay_unavailable` | 503 | Yes | WSS relay at capacity |
| `internal_error` | 500 | Yes | |
| `peer_identity_mismatch` | Peer error | No (start a new attempt) | Attestation failed |
| `ticket_invalid` | Peer error | No (start a new attempt) | Host rejected the ticket |
| `lease_expired` | Peer error | Yes, when the control plane is back | Host's grant lease is stale |
| `connect_timeout` | Client | Yes | No verified path within 20 s |
| `signaling_limit` | WSS 4429 | Yes, with backoff | |
| `protocol_error` | WSS 4400 / peer | No | |
| `unsupported_version` | Peer `hello` | No | No common protocol version |
| `session_not_found`, `pty_unavailable`, `shell_missing`, `tmux_unavailable` | Peer `terminal.error` | No | Host-side terminal errors |

## 13. Versioning and compatibility

| Surface | Mechanism | Policy |
|---|---|---|
| REST | URL prefix `/v1`; fields are only ever added | A breaking change goes to `/v2`. `/v1` stays available for at least one app release cycle. |
| WebSocket and data channel | Integer `protocol_version` in hello messages and in the attestation | The server supports protocol versions N and N−1 for both app and agent. |
| Minimum versions | `/v1/meta/compat` and 426 errors | The app prompts the user to update. The agent logs the problem and `prw-agent doctor` reports it. |
| Contracts | OpenAPI 3.1 (`protocol/openapi.yaml`) and JSON Schemas | CI validates the server against them, and runs golden tests for the Dart client. |
