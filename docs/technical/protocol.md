# Wire Protocol (version 1)

> **Status:** version 1, implemented in `core/prwcore`, `services/control` and `agents/host`. Parts not built yet are marked *planned*. The protocol is not frozen: golden vectors exist for frames (`protocol/vectors/frames.json`) and the rest follow at freeze time. Values marked *proposed* are defaults that may be tuned.

Conventions:
- "MUST", "SHOULD" and "MAY" follow RFC 2119.
- Integers are big-endian.
- JSON timestamps are RFC 3339 UTC. Token timestamps are Unix seconds.
- Hostnames use the placeholders `api.example.invalid` (Elastic IP A) and `turn.example.invalid` (Elastic IP B).

## 1. Cryptographic primitives

The project contains no custom cryptography. Every primitive comes from a maintained standard library or a well-known library.

| Purpose | Algorithm |
|---|---|
| Device identity signatures | ECDSA P-256 / SHA-256, encoded as JWS `ES256` (raw r‖s, 64 bytes) |
| Server-issued access tokens, tickets, leases, relay tokens | Ed25519, encoded as JWS `EdDSA` |
| Data plane on direct and TURN paths | DTLS (WebRTC) |
| Data plane on the WSS relay path | Inner TLS 1.3 with ephemeral P-256 certificates |
| Outer transport for the API and WebSockets | TLS 1.2+ (prefer 1.3), terminated by Caddy |
| Storage of pairing codes and refs | HMAC-SHA-256 with a server-side pepper |
| Storage of refresh tokens | SHA-256 of a 256-bit random token |
| TURN credentials | TURN REST scheme: HMAC-SHA1 over the username |
| Fingerprints | SHA-256 over the DER SubjectPublicKeyInfo (device keys) or over the DER certificate (transport certificates) |

Hardware keystores return DER-encoded ECDSA signatures. Implementations MUST convert these to raw r‖s before placing them in a JWS.

Signed payloads are **JCS-canonical JSON** (RFC 8785). The signature covers the transmitted bytes. Canonicalisation exists only so that golden vectors are reproducible.

## 2. Phone sign-in and device registration

Google OIDC is the only identity provider. The phone gets a server nonce, obtains a Google ID token bound to it through the platform Google Sign-In SDK (initialised with the server's web client ID), then exchanges the ID token for PRW tokens.

**`POST /v1/auth/challenge`** returns `{nonce, exp}`:
- `nonce` is 32 random bytes, base64url-encoded.
- `exp` is 120 seconds after issue.
- Each nonce is single use.

**`POST /v1/auth/exchange`**

```json
{
  "provider": "google",
  "id_token": "<Google ID token>",
  "oidc_nonce": "<nonce used in the auth request>",
  "device": {
    "platform": "android|ios",
    "display_name": "Pixel 9",
    "app_version": "1.0.0",
    "public_key_spki": "<b64url DER SPKI, P-256>",
    "key_protection": "strongbox|tee|secure_enclave|software"
  },
  "pop": {
    "nonce": "<server nonce>",
    "sig": "<ES256 JWS over JCS({purpose:'prw.auth.v1', nonce, spki_fp, iat})>"
  }
}
```

The server performs these checks in order:
1. It validates the ID token: `iss`, `aud` (one of `PRW_GOOGLE_CLIENT_IDS`), signature against cached Google JWKS, `exp` and `nonce`. The email is stored only when `email_verified` is true.
2. It checks that `sub` is listed in `PRW_ALLOWED_SUBJECTS`. If not, it returns `403 account_not_allowed`, audits a hash of the subject, and logs `google:<sub>` so the operator can add it.
3. It confirms the server nonce has not been used.
4. It verifies the proof-of-possession signature with the presented key.

In **one transaction**, the server then:
- upserts the account;
- inserts the phone device and its credential row, or matches the existing non-revoked device with the same key fingerprint;
- creates an auth session;
- writes an audit event.

A new phone needs no other approval. It starts with **no grants**.

The response is `{access_token, access_expires_at, refresh_token, refresh_expires_at, device_id, account, device}`:
- `access_token` is an EdDSA JWT valid for 10 minutes, with `kid` in its header. Its claims are `iss`, `aud` (`prw-api`), `sub` (account ID), `did` (device ID), `kind` (`phone`), `sid` (auth session), `iat`, `exp` and `jti`.
- `refresh_token` is opaque. It has a 30-day sliding lifetime and a 90-day absolute lifetime.

**`POST /v1/auth/refresh`** takes `{refresh_token, pop: {nonce, sig}}`. The signature MUST verify against the device's active key.
- On success the server rotates the token.
- Reusing a token that has already been rotated revokes the whole token family.
- A revoked device receives `403 device_revoked`.

**`POST /v1/auth/logout`** revokes the current phone's refresh-token family only.

## 3. Agent control-channel authentication

The handshake on `wss://api.example.invalid/v1/agent/control` runs as follows. The agent never puts credentials in the URL.

1. Server → agent: `{"type":"auth.challenge","nonce":"…","exp":…}`
2. Agent → server: `{"type":"auth.response","payload":{"device_id":"…","sig":"<ES256 JWS over JCS({purpose:'prw.agent.v1',nonce,device_id,iat})>","agent_version":"…"}}`
3. The server consumes the nonce (single use, 1 min), verifies the signature against the host's key and checks that the host is active.
4. On success, server → agent: `auth.ok {device_id, account_id, jwks}`, then `grant.lease` (§14).
5. On failure, server → agent: `auth.error {code}`, after which the server closes the socket with `4401`, or `4403` for a revoked host. The agent stops for good on `4403`.
6. If the same host logs in again, the older socket is closed with `4400`.

The agent re-authenticates on every reconnect, with exponential backoff from 1 s to 30 s plus jitter. Re-challenging a long-lived socket (every 15 minutes) and pushing key rotations with `jwks.update` are *planned*.

Messages the server may send to the agent form an allowlist: `auth.*`, `heartbeat.ack`, `attempt.incoming`, `attempt.cancel`, `grant.lease`, `revoke_notice`, `signal`, and the reserved `jwks.update`, `pairing.approved` and `server.notice`. The server refuses to send anything else, and the agent drops any other message type and logs the drop.

The agent sends the server:
- `heartbeat` every 25 s, carrying `payload: {agent_version, capabilities: {tmux, peers}}`. The server stores the capabilities on the device and answers `heartbeat.ack`.
- `attempt.status` with `status` `failed`, `connected_direct`, `connected_relay`, `connected_wss`, or `ended` once a connected session closes.
- Its own signaling (`signal`).

**Liveness.** A socket can be half-open after a NAT remap or proxy failure: writes still appear to succeed but nothing arrives. Both sides therefore treat silence as death:
- The server closes an agent socket that has sent nothing for 75 s (three heartbeats) with `4408 no heartbeat`, so presence goes stale promptly.
- The agent abandons a socket on which it has received nothing for 75 s (the server acknowledges every heartbeat) and reconnects.

## 4. Pairing protocol

| Step | Message | Notes |
|---|---|---|
| 1 | Host → `POST /v1/pairing/challenges` `{host_public_key_spki, hostname, os:{id,version}, agent_version, proto, pop_sig}` | Unauthenticated. Rate-limited per IP (1 per 2 min, burst 10). `pop_sig` is an ES256 signature over `{purpose:'prw.pair.create.v1', spki_fp, iat}`. |
| 2 | Server → host `{challenge_id, pairing_ref, display_code, expires_at, wait_token, qr_payload}` | `pairing_ref` is 16 random bytes. `display_code` is 8 Crockford base32 characters (40 bits), shown as `XXXX-XXXX`. The server stores only HMACs of the ref, the normalized code and the wait token. The challenge expires after 5 min. |
| 3 | Host displays a QR code | `qr_payload` is `prw://pair?v=1&ref=<ref>&fp=<spki_fp hex>&api=<server base URL>`. Alongside it, the host prints the code and the grouped key fingerprint. |
| 4 | Host → `GET /v1/pairing/challenges/{id}/wait` | A long poll (up to 25 s per request) authorized by `wait_token`. It returns `pending`, `approved` with `nonce2`, or an expiry, rejection or lock error. |
| 5 | Phone → `POST /v1/pairing/resolve` `{pairing_ref}` or `{display_code}` | Signed in. A wrong ref or code returns 404 and cannot be tied to a challenge. A per-account rate limit is *planned*. |
| 6 | Server → phone `{challenge_id, hostname, os, agent_version, host_key_fingerprint, expires_at, compat}` | |
| 7 | Phone verification | For a scanned QR code, `fp` MUST equal `host_key_fingerprint`; otherwise the phone fails closed. For a typed code, the user confirms the fingerprint by eye. |
| 8 | Phone → `POST /v1/pairing/challenges/{id}/approve` `{host_key_fingerprint, display_name?, grant_to_this_phone}` | The server compares the fingerprint again. A mismatch returns `pairing_fingerprint_mismatch` and counts as a failure; the fifth failure locks the challenge. On success the challenge becomes `approved`, is bound to the account and gets a fresh `nonce2`. |
| 9 | Server → host | The pending `wait` long poll returns `{status: "approved", nonce2}`. (A `pairing.approved` push on the control socket is reserved but unused: an unpaired host has no control socket.) |
| 10 | Host → `POST /v1/pairing/challenges/{id}/complete` `{sig}` | `sig` is an ES256 signature over `{purpose:'prw.pair.complete.v1', challenge_id, nonce:nonce2, spki_fp, iat}`. |
| 11 | Server, in one transaction | Locks the row and verifies the wait token, status, expiry and signature. Creates the host device and its credential, marks the challenge consumed, creates the grant if `grant_to_this_phone` was set, and writes an audit record. |
| 12 | Server → host `{device_id, account_id, jwks, control_ws_url}` | The host **pins** the server verification keys. |

Failures return `pairing_expired`, `pairing_used`, `pairing_rejected` or `pairing_locked`. A newly paired host has no grants unless the approving phone asked for one.

## 5. Connection attempt and ticket

**`POST /v1/connections`** requires a signed-in phone and an `Idempotency-Key` header.

Request: `{host_device_id, capability: "terminal", target_terminal_session_id?}`.

The server checks the account, that both devices are active, that the phone holds an active and unexpired grant with the requested capability, the host's presence, and rate limits. Possible errors: `access_grant_missing`, `device_revoked`, `not_found` (host missing or in another account), `agent_offline`, `rate_limited`, `idempotency_conflict`. An agent-version check (`unsupported_agent_version`) is *planned*. The phone SHOULD open `/v1/signaling` before this call so no early host message is missed; the server also buffers host messages for up to 15 s.

```json
{
  "connection_attempt_id": "<uuidv7>",
  "status": "authorized",
  "expires_at": "<now+60s>",
  "ticket": "<JWS EdDSA>",
  "relay": {"url": "wss://api.example.invalid/v1/relay", "token": "<relay token, role=client>"},
  "ice_servers": [
    {"urls": ["stun:turn.example.invalid:3478"]},
    {"urls": ["turn:turn.example.invalid:3478?transport=udp",
              "turn:turn.example.invalid:3478?transport=tcp",
              "turns:turn.example.invalid:443?transport=tcp"],
     "username": "<expiry>:<attempt_id>", "credential": "<hmac>"}
  ],
  "attestation_nonce": "<32B b64url>",
  "signaling_url": "wss://api.example.invalid/v1/signaling",
  "fallback": {"wss_race_after_ms": 4000},
  "host": {"device_id": "…", "key_fingerprint": "…", "public_key_spki": "…"}
}
```

The phone compares `host.key_fingerprint` with the fingerprint it pinned at pairing and aborts on a mismatch (`host_key_mismatch`) before connecting.

The host receives `attempt.incoming` whose `payload` carries `attempt_id`, `phone_device_id`, the same ticket, a relay token with `role=server`, and its own ICE servers.

**Ticket.** A JWS with `alg=EdDSA` and `typ=prw-ticket+jwt`.

| Claim | Meaning |
|---|---|
| `iss` | Control-plane base URL |
| `aud` | Host device ID |
| `sub` | Phone device ID |
| `acct` | Account ID |
| `att` | Connection attempt ID |
| `cap` | `terminal` |
| `sess` | Target terminal session (optional) |
| `nonce` | Attestation nonce |
| `jti` | 128-bit random identifier, single use |
| `iat`, `nbf`, `exp` | `exp = iat + 60 s` |
| `pv` | Protocol version |

The host accepts the ticket only if all of the following hold:
- the signature verifies under a pinned `kid`;
- `aud` is the host's own ID;
- the current time is within `nbf`/`exp`, allowing ±30 s of clock skew;
- `sub` matches the phone in `attempt.incoming` and `att` matches the attempt;
- the `jti` has not been seen before (the host remembers it until `exp`);
- `sub` holds `cap` in the current grant lease, checked again when the phone presents the ticket during attestation.

Key rotation is *planned*: new signing keys will be announced through `jwks.update` before first use, signed by the current key, and a retired key will stay valid until every ticket it signed has expired.

**Relay token.** A JWS (EdDSA) carrying `{att, role: client|server, dev, exp = iat + 90 s, jti}`. It is valid only on `/v1/relay`.

## 6. Signaling

Phones open `/v1/signaling`. Their first frame is `{"type":"auth","payload":{"access_token":"…"}}`, answered with `auth.ok`. Agents send signaling over their control socket instead.

Every signaling message uses this envelope:

```json
{"type":"signal","attempt_id":"…","kind":"offer","from_device_id":"<set by the server>","payload":{}}
```

| Kind | Payload | Direction |
|---|---|---|
| `offer` | `{sdp}` | phone → host |
| `answer` | `{sdp}` | host → phone |
| `ice_candidate` | `{candidate, sdp_mid, sdp_mline_index}` | both |
| `ice_complete` | `{}` | both |
| `tls_fingerprint` | `{sha256}` (WSS path) | both |
| `attempt_cancel` | `{reason}` | both |
The server also sends two non-signal messages to phones: `{"type":"attempt_status","attempt_id","status","failure_code"}` and `{"type":"revoke_notice","scope","dedupe_key","payload"}`.

The server enforces these rules:
- The sender is derived from the authenticated socket. A client-supplied `from_device_id` is overwritten.
- The sender MUST be the phone or the host of a registered, unexpired attempt; the message goes to the other one.
- Messages for unknown, expired or ended attempts are dropped.
- Host messages for a phone with no open signaling socket are buffered (32 per attempt, for 15 s) and delivered when it connects.

Limits:

| Limit | Value |
|---|---|
| Frame size | 64 KiB |
| Messages per attempt | 100 |
| ICE candidates per attempt | 50 |
| Messages per second, per socket | 20 (*planned*) |

A violation closes the socket with `4429 signaling_limit`. SDP is never logged. Message-ID deduplication is *planned*.

## 7. ICE configuration and TURN credentials

- `username = "<unix_expiry>:<attempt_id>"` with an expiry 600 s in the future.
- `credential = base64(HMAC-SHA1(turn_shared_secret, username))`. This matches coturn's `use-auth-secret` mode.
- To rotate the secret, coturn is configured with both the old and the new `static-auth-secret`. During the overlap, the server issues credentials only with the new one.
- Pion settings (*proposed*):
  - network types udp4, udp6, tcp4 and tcp6;
  - mDNS candidates off on hosts;
  - ICE timeouts of 5 s (disconnected) and 15 s (failed), with a 2 s keepalive.
- Candidates trickle. A diagnostic "Force relay" setting is *planned*.

## 8. Connection manager algorithm

```text
t=0    open /v1/signaling, POST /v1/connections → attempt
       start ICE (offer, trickle)
       if udp_blocked: start WSS relay now
t=4s   if ICE not connected: start WSS relay (if not started)   [fallback.wss_race_after_ms]
each transport on ready → run identity attestation (§10)
first transport to finish attestation (phone side) → winner; phone sends path.select on it, closes the others
host: runs ICE and the WSS relay at once and commits to the transport on which path.select arrives
t=20s  no winner → fail connect_timeout (report: per-path start, elapsed, error)
host: gives up after its own 30 s window and reports attempt.status failed
on commit: host reports attempt.status connected_*; when the session later closes, attempt.status ended
```

The client's `mode` can restrict the race to `webrtc` or `wss` for diagnostics; the default is `auto`. Caching a per-network "UDP blocked" hint on the phone is *planned*; today `udp_blocked` is only set explicitly.

The race reports the path as `direct` (host or server-reflexive pair), `turn` (relay candidate) or `wss_relay`. The host stores it on the attempt as `path_type` `direct`, `turn_udp` or `wss_relay`. The 4 s and 20 s timings are *proposed*.

## 9. Transports

### 9.1 WebRTC DataChannels

The WebRTC transport uses two DataChannels. Both are reliable, ordered and negotiated out of band.

| Channel | ID | Carries |
|---|---|---|
| `prw-ctl` | 0 | CONTROL frames |
| `prw-term` | 1 | Terminal frames (INPUT, OUTPUT, CLOSE_STREAM) |

Each DataChannel message is exactly one frame (§12).

### 9.2 WSS relay with inner TLS 1.3

**Join.**
1. Each peer opens `wss://api.example.invalid/v1/relay` and sends `{"type":"join","attempt_id","relay_token","role":"client|server"}`.
2. The server verifies the relay token: signature, `att`, `role`, `dev`, `exp`, and that the `jti` is unused.
3. Once both roles have joined, the server sends `{"type":"joined"}` to each peer.
4. From then on, **binary messages only**. The server copies each message unchanged to the other socket.

| Relay limit | Value (*proposed*) |
|---|---|
| Wait for second peer | 15 s |
| Idle timeout | 120 s |
| Max message | 64 KiB |
| Rate per attempt | `PRW_RELAY_MAX_BPS`, default 2 Mbit/s |
| Bytes per attempt | 2 GiB |
| Concurrent relayed attempts per account | 16 (*planned*) |

The server MUST NOT inspect or log the payload. It counts bytes only. Join failures close with `4400` (no join), `4401` (bad or reused relay token), `4408` (peer did not join in time) or `4409` (both roles already joined). Closing splices on revocation is *planned*; today the host closes the revoked phone's transport, which ends the splice.

**Inner TLS.**
1. Each peer generates an ephemeral P-256 key and a self-signed certificate (`CN=prw-<attempt>`, valid for 1 h).
2. Each peer sends `tls_fingerprint` (the SHA-256 of its DER certificate) over signaling before the handshake.
3. TLS 1.3 then runs with the host as server and the phone as client. Client certificates are required and the ALPN is `prw/1`. Chain validation is replaced by a callback that compares the peer certificate's fingerprint with the value received over signaling.
4. Identity attestation (§10) then binds that certificate to the peer's long-term device key, so tampering with signaling is still detected.
5. CONTROL and terminal frames are multiplexed by frame type over the TLS byte stream.

## 10. Identity attestation

Once a transport is up, each peer proves that it holds the enrolled device key. The proof is bound to the certificate actually used on this transport.

Both sides send `peer.attest {jws}` as their first CONTROL message after `hello`. The phone also includes the connection ticket. The JWS is ES256 over JCS-canonical JSON:

```json
{
  "purpose": "prw.peer.attest.v1",
  "pv": 1,
  "att": "<attempt_id>",
  "from": "<own device_id>",
  "to": "<peer device_id>",
  "role": "phone|host",
  "nonce": "<attestation_nonce>",
  "transport": "dtls|tls13",
  "local_fp": "<sha256 of own DTLS/TLS certificate>",
  "remote_fp": "<sha256 of peer certificate as observed>",
  "cap": "terminal",
  "iat": 1760313840,
  "exp": 1760313900
}
```

The receiver verifies:
1. The signature, using the **pinned** key of the expected peer. A host uses the phone's key from its grant lease. A phone uses the host key it pinned at pairing.
2. `att` and `nonce` match the current attempt, `to` is itself, and `from` is the expected peer.
3. `local_fp` equals the peer certificate fingerprint actually observed on this transport.
4. `remote_fp` equals its own certificate fingerprint.
5. The time is within `iat ≤ now ≤ exp` (±30 s), and `exp − iat ≤ 120 s`.
6. `cap` is allowed by the ticket.

When verification succeeds, each side sends `peer.identity_verified {}`. Terminal messages flow only after **both** sides have sent it. A side that has not verified within 5 s, or whose check fails, closes the transport with `peer_identity_mismatch` and records a security audit event. That attempt is not retried.

## 11. Control messages

Control messages are JSON carried in CONTROL frames. Each message is at most 16 KiB.

Envelope: `{"v":1,"type":"…","request_id":"<uuidv7>","terminal_session_id"?:…,"payload":{}}`

| Type | Direction | Payload | Notes |
|---|---|---|---|
| `hello` | both, first | `{pv_min, pv_max, impl, features}` | The selected version is `min(max_a, max_b)`, which must be ≥ each side's `pv_min`. Otherwise `unsupported_version` is returned and the transport closes. |
| `peer.attest` | both | `{jws, ticket?}` | §10 |
| `peer.identity_verified` | both | `{}` | Gate for terminal traffic |
| `path.select` | P → H | `{}` | Sent by the phone on the transport it chose. The host commits to the transport that carries it and closes the others. |
| `terminal.list` | P → H | `{}` | Reply: `terminal.list.result {sessions:[{id,title,status,persistent,created_at,last_attached_at,attached_clients}]}` |
| `terminal.open` | P → H | `{title?, cols, rows, profile:"default"}` | `request_id` acts as the idempotency key. The host deduplicates for as long as the agent runs. |
| `terminal.attach` | P → H | `{terminal_session_id, cols, rows}` | |
| `terminal.ready` | H → P | `{terminal_session_id, stream_id, persistent, resumed, backend:"tmux"}` | `backend: "pty"` is reserved for the planned fallback. |
| `terminal.resize` | P → H | `{stream_id, cols, rows}` | `cols` and `rows` range from 1 to 1000. Coalesced to at most 10 per second. |
| `terminal.detach` | P → H | `{stream_id}` | Ends the attach client only |
| `terminal.terminate` | P → H | `{terminal_session_id, confirm:true}` | Kills the tmux session (`kill-session`); without `confirm` the host answers `confirm_required`. A SIGHUP-then-kill grace period is *planned*. |
| `terminal.exit` | H → P | `{terminal_session_id, exit_code?, reason}` | |
| `terminal.error` | H → P | `{code, request_id}` | Codes: `session_not_found`, `host_capacity_reached`, `bad_request`, `pty_unavailable`, `confirm_required` |
| `flow.credit` | both | `{stream_id, bytes}` | §13 |
| `ping` / `pong` | both | `{t}` | Both sides answer `ping` with `pong`. Periodic pings (every 10 s, with RTT in diagnostics) are *planned*; today a lost transport is detected by the transport itself (ICE failure, TLS or WebSocket close). |
| `session.revoked` | H → P | `{reason}` | Sent immediately before the host closes the transport |

## 12. Frame format

Both transports use the same frames. On WebRTC, one frame is one DataChannel message. On the TLS stream, frames are concatenated.

| Offset | Size | Field | Values |
|---|---|---|---|
| 0 | 1 | `ver` | `0x01` |
| 1 | 1 | `type` | `0x01` CONTROL (JSON), `0x02` INPUT (phone → host), `0x03` OUTPUT (host → phone), `0x04` CLOSE_STREAM |
| 2 | 1 | `flags` | bit 0 = `FIN`. All other bits MUST be 0. |
| 3 | 1 | reserved | `0x00` |
| 4 | 2 | `stream_id` | `0` for CONTROL, `≥ 1` for terminal streams |
| 6 | 2 | `len` | Payload length, 0–16384 |
| 8 | 4 | `seq` | Counter per stream and per direction, starting at 0 and wrapping at 2³². Used for diagnostics and gap detection only. |
| 12 | `len` | payload | Raw bytes, or UTF-8 JSON for CONTROL |

The header is 12 bytes, so a frame is at most 16 396 bytes. That is well within the message limits of every WebRTC implementation.

A receiver MUST close with `protocol_error` if any of these occur:
- an unknown `ver` or `type`;
- non-zero reserved bits;
- `len > 16384`;
- a CONTROL message over 16 KiB;
- a terminal frame for an unknown stream.

## 13. Flow control

Credit is counted in payload bytes, per stream and per direction.

- **Initial window.** Every window starts at 0. Right after `terminal.ready`, the receiver grants credit with `flow.credit {bytes: 262144}` (256 KiB).
- **Sending.** A sender MUST NOT send payload bytes beyond the credit it has been granted.
- **Re-granting.** The receiver re-grants credit after consuming half the window. The phone counts bytes rendered by the terminal emulator. The host counts bytes written to the PTY.
- **Host out of credit.** The host stops reading the PTY. Backpressure then reaches the program through the kernel PTY buffer and tmux. **No bytes are dropped**, and host buffering per stream stays bounded: one 16 KiB read buffer plus at most 256 KiB in flight.
- **Phone input.** Phone INPUT credit defaults to 64 KiB. Large pastes are chunked and go through the paste confirmation.
- **WebRTC backstop.** On WebRTC, the sender also keeps the DataChannel buffered amount at or below 1 MiB as a second guard.

## 14. Heartbeats, timeouts and the grant lease

| Item | Value (*proposed*) |
|---|---|
| Agent heartbeat | 25 s |
| Presence | stale after 75 s, offline after 150 s |
| Peer `ping` | every 10 s; 3 misses → transport lost (*planned*) |
| ICE disconnected / failed | 5 s / 15 s |
| Overall connect timeout | 20 s on the phone, 30 s on the host |
| WSS fallback start | 4 s |
| Attestation | 5 s |
| Ticket lifetime | 60 s |
| TURN credential lifetime | 10 min |
| Access token lifetime | 10 min |
| Agent control-socket silence | 75 s → reconnect (agent) / close with `4408` (server) |
| Agent re-challenge | 15 min (*planned*) |
| Grant lease | 10 min, renewed every 3 min |
| App device-list refresh | every 30 s while the list is on screen |
| Detached session idle reaping | none by default (optional `idle_kill_after`) |

**Grant lease.** The server sends the agent `{"type":"grant.lease","lease":"<JWS>"}`. The lease is an EdDSA JWS with `typ=prw-lease+jwt`, signed with the ticket key, whose claims list the phones allowed on this host:

```json
{"host":"<host device id>","iat":…,"nbf":…,"exp":"<iat + 10 min>","jti":"…",
 "grants":[{"phone_device_id":"…","phone_key_spki":"…","caps":["terminal"],"grant_id":"…","grant_expires_at":0}]}
```

The server sends a fresh lease on login, every 3 minutes, and after every grant change. The agent verifies it against its pinned keys and replaces its cache atomically, closing the transports of any phone that dropped out. If the lease expires without renewal, for example because the control plane is unreachable, the agent:
1. refuses `terminal.open` and `terminal.attach` with `lease_expired`;
2. sends `session.revoked {reason:"lease_expired"}` to every connected peer and closes its transport;
3. **leaves tmux sessions running**, detached.

## 15. Revocation

1. **API transaction.** The API revokes the device or grant (a device revocation also revokes its grants and refresh tokens; both mark the affected live attempts `revoked`), writes an audit event, and writes an outbox row (`grant_revoked` or `device_revoked`) with a dedupe key. From this moment, new tickets and refreshes are refused, and the revoked phone's API calls return `device_revoked`.
2. **Delivery.** The outbox worker (woken on commit, polling every 500 ms) sends each affected host a fresh lease and `{"type":"revoke_notice","scope":"grant"|"device","dedupe_key","payload"}`, and sends the phone the same notice. A failed send to a connected agent is retried with backoff (1 s, doubling, capped at 60 s) and dead-lettered after 8 attempts with an error log; an agent that was offline gets a lease reflecting the change when it reconnects. Agent acknowledgements are *planned*.
3. **Agent handling.** The agent removes the phone from its lease cache, sends `session.revoked {reason}` on each of that phone's transports and closes them.
4. **Running sessions.** Affected tmux sessions are **detached, not killed**. The processes keep running, and the owner can reattach from another authorized phone or terminate them explicitly.
5. **Revoked host or phone.** The server closes the revoked device's sockets with `4403` and refuses to re-authenticate a revoked host. The agent then closes every peer, exits and asks the user to run `prw-agent unpair --local` and pair again.
6. **Missed push.** If the notice never reaches the host, the grant lease limits how long revoked access can last.

## 16. Reconnect algorithm

```text
on transport lost (ICE failed | WSS closed | app resumed with stale transport):
  state = RECONNECTING; freeze input; mark output stale
  backoff = 0.5, 1, 2, 4, 8, 15, 15, … s   (jitter and a 120 s stop are planned)
  loop:
    ensure access token (refresh with device proof-of-possession)
    POST /v1/connections {host, cap, target_terminal_session_id}
      403 device_revoked | access_grant_missing → stop, show reason
      409 agent_offline → wait for next backoff step
    run connection manager (§8) → attestation (§10)
    terminal.attach {id, cols, rows}
      terminal.ready (resumed) → ATTACHED; unfreeze; show "Reconnected"
      terminal.error session_not_found | exited → stop, offer new session
on network change (planned): start a new attempt while the old transport is still alive
  (make-before-break) and switch on success
```

Tickets, TURN credentials and relay tokens are never reused across attempts.

## 17. Error codes

| Code | Where | Retryable |
|---|---|---|
| `unauthenticated` | 401 | after refresh |
| `account_not_allowed` | 403, sign-in | no |
| `device_revoked` | 403 (caller) / 409 (target) | no |
| `not_found` | 404 | no |
| `access_grant_missing` | 403 | no |
| `pairing_expired` / `pairing_used` / `pairing_rejected` / `pairing_locked` | 410 / 409 / 409 / 423 | no (new challenge) |
| `pairing_fingerprint_mismatch` | 409 | no (new challenge) |
| `host_key_mismatch` | phone, before connecting | no (re-pair) |
| `attempt_not_live` | 409 | new attempt |
| `idempotency_conflict` | 422 | new key |
| `agent_offline` | 409 | yes |
| `host_capacity_reached` | 429 / peer | later |
| `rate_limited` | 429 + `Retry-After` | yes |
| `unsupported_agent_version` / `unsupported_version` | 426 / peer | no (upgrade) |
| `peer_identity_mismatch` | peer | no |
| `ticket_invalid` | peer | new attempt |
| `lease_expired` | peer | after control plane returns |
| `relay_unavailable` | 503 / peer | yes (*planned*) |
| `connect_timeout` | phone | yes |
| `signaling_limit` | close `4429` | with backoff |
| `protocol_error` | peer | no |
| `session_not_found` | peer | no |
| `pty_unavailable` | peer | maybe |
| `bad_request` / `confirm_required` | peer | no |
| `internal_error` | 500 | yes |

REST errors use this envelope:

```json
{"error":{"code":"access_grant_missing","message":"…","retryable":false,"request_id":"req_…","details":{}}}
```

Error responses MUST NOT include tokens, pairing codes, terminal bytes or TURN secrets.

**WebSocket close codes**

| Code | Meaning |
|---|---|
| 4400 | Bad request; agent socket superseded by a newer login |
| 4401 | Authentication failed |
| 4403 | Revoked |
| 4408 | Timeout (silent agent, or relay peer did not join) |
| 4409 | Relay attempt already joined |
| 4429 | Rate limited |
| 4500 | Internal error (reserved) |

## 18. Versioning and compatibility

- **Protocol version.** The protocol version `pv` is an integer starting at 1, negotiated in `hello`.
- **Supported versions.** The server supports the current and the previous version (N and N−1) for agents and apps. Today only version 1 exists: sign-in rejects an app whose range excludes it (`unsupported_client_version`) and pairing rejects such an agent (`unsupported_agent_version`).
- **Unknown fields.** Receivers MUST ignore unknown JSON fields.
- **Version bumps.** A new frame `type` requires a `pv` bump.
- **REST versioning.** The REST API is versioned in the path (`/v1`). A breaking change introduces `/v2`, and `/v1` stays available for one release cycle.
- **Agent upgrades.** Agents report their version in heartbeats (shown as `software_version`). An app warning for agents older than N−1 is *planned*.

## 19. Size limits

| Item | Limit |
|---|---|
| REST request body | 16 KiB for `/v1/auth/exchange`, 64 KiB for other auth calls, 4 KiB elsewhere |
| Signaling frame | 64 KiB |
| Control JSON on the data plane | 16 KiB |
| Terminal frame payload | 16 384 bytes |
| Relay WebSocket message | 64 KiB |
| In-flight per stream | 256 KiB output, 64 KiB input |
| Sessions per host | 20 (configurable) |
| Concurrent peers per host | 8 (configurable) |
| Session title | 120 characters |
| Phone scrollback | 10 000 lines (configurable) |
| tmux history | 50 000 lines |

## 20. Golden vectors

`protocol/vectors/` holds JSON fixtures. Today it contains `frames.json` (frames of every type, edge lengths and invalid cases), checked by `core/prwcore/frame`. The rest of the list below is *planned* for the protocol freeze; since the phone runs the same Go core, a Dart implementation is no longer needed for the vectors.

- Frames of every type, with lengths 0, 1 and 16384, the FIN flag, and invalid cases.
- Control envelopes, including unknown fields that receivers must ignore.
- JCS canonicalisation of the attestation, auth, pairing and lease payloads.
- ES256 DER-to-raw conversion, plus a fixed-key attestation JWS.
- EdDSA tickets and leases: valid, expired, wrong audience and unknown key ID.
- TURN credential derivation.
- Pairing code normalisation: Crockford confusables and hyphens.
- QR payload parsing and serialisation.

All vectors use test keys marked `TEST ONLY`.
