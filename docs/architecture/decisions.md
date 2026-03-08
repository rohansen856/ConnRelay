# Architecture Decision Records

> **Status:** design. **Accepted** decisions have been confirmed by the product owner. **Proposed** decisions are the current recommendation and may change, for example after the feasibility spikes.

| ADR | Title | Status |
|---|---|---|
| 001 | App-level remote terminal, not a VPN | Accepted |
| 002 | Data plane: WebRTC primary, WSS relay fallback | Accepted (fallback timing proposed) |
| 003 | Shared Go transport core (`prwcore`) on phone and host | Proposed |
| 004 | WSS relay with end-to-end TLS 1.3 and identity attestation | Accepted (need) / Proposed (mechanism) |
| 005 | coturn ≥ 4.18 on a dedicated IP, ephemeral credentials, hardened | Proposed |
| 006 | Single EC2 instance with two Elastic IPs | Accepted |
| 007 | Google OIDC sign-in, subject allowlist, device-bound tokens, P-256 device keys | Accepted (Google only) / Proposed (details) |
| 008 | tmux persistence backend with plain-PTY fallback | Proposed |
| 009 | Signed tickets verified on the host, plus a grant lease | Proposed |
| 010 | Data layer: one `devices` table, composite FKs, soft revoke, goose + sqlc + pgx | Proposed |
| 011 | Metadata-only audit; no terminal content server-side | Accepted |
| 012 | Flutter stack: Riverpod, go_router, xterm.dart | Proposed |

---

## ADR-001: App-level remote terminal, not a VPN

- **Status:** Accepted
- **Context:** The product exists so a phone can reach PC terminals for shells and coding agents. A system VPN would require:
  - Android `VpnService`
  - the iOS Network Extension entitlement
  - routing, DNS and firewall changes on hosts
  - a much larger security surface
- **Decision:** V1 opens an application-level encrypted channel that carries only PRW control and terminal frames. It provides no TUN interface, no subnet routing and no TCP forwarding.
- **Alternatives considered:**
  - WireGuard overlay: deferred to a separate future track.
  - Port forwarding: deferred to a later capability.
- **Consequences:**
  - No VPN permission is needed.
  - Traffic flows only while the app is in the foreground.
  - Grants carry capabilities (`terminal`, later `file_transfer` and `port_forward`) so new capabilities can be added later.

## ADR-002: Data plane: WebRTC primary, WSS relay fallback

- **Status:** Accepted. Race timings are proposed.
- **Context:** The data plane must meet four requirements:
  - Use a direct path where possible.
  - Fall back to a relay where not.
  - Keep data end-to-end confidential.
  - Work on networks that allow only TCP/443, including DPI and HTTP-proxy networks.
- **Decision:**
  - The **primary** path is WebRTC DataChannels with ICE, using host, server-reflexive and relay candidates. TURN runs over UDP, TCP and TLS on 443.
  - The **mandatory fallback** is a WebSocket relay through the control plane on 443, carrying an inner end-to-end TLS 1.3 stream (ADR-004).
  - Both paths implement one `Transport` interface.
  - The WSS transport is built first because it is deterministic and easy to test.

**Comparison**

Rating scale: ●●● good · ●● acceptable · ● poor.

| Criterion | A. WebRTC + ICE + TURN | B. WireGuard overlay | C. Outbound gateway relay (WSS) | D. Hybrid: relay first, P2P later |
|---|---|---|---|---|
| Engineering complexity | ●● ICE/SDP/signaling are substantial but standard | ● Packet VPN, key distribution, per-OS tunnels | ●●● Simple splice; needs an E2E layer | ●● A + C, staged |
| Library maturity | ●●● Pion, libwebrtc | ●●● WireGuard, but custom control plane | ●●● WebSocket, TLS 1.3 | ●●● |
| Flutter / Linux integration | ●● Fine with a shared Go core | ● Native VPN plugins | ●●● | ●● |
| iOS / Android constraints | ●● Foreground only | ● Entitlement and VPN consent | ●●● | ●● |
| Future Windows / macOS | ●●● | ● Driver per OS | ●●● | ●●● |
| NAT / CGNAT | ●● Direct may fail; TURN covers it | ●● Same issue | ●●● Outbound only | ●●● |
| UDP-blocked / DPI | ● TURN/TLS helps; DPI may still block | ● UDP only | ●●● Looks like HTTPS | ●●● |
| Direct connectivity | ●●● | ●●● | ● Never direct | ●● |
| Relay cost | ●● Only when needed | ●● | ● All traffic through EC2 (terminal traffic is small) | ●● |
| Interactive latency | ●●● No TCP head-of-line blocking | ●●● | ●● Extra hop; TCP head-of-line blocking | ●● → ●●● |
| Large transfers | ●● Chunking required | ●●● | ●● | ●● |
| Flow control | ●● SCTP + app credits | ●●● | ●●● TCP + app credits | ●● |
| Reconnection | ●● New attempt + reattach | ●● Roaming built in | ●●● | ●● |
| Cryptographic security | ●●● DTLS + attestation | ●●● Noise IK | ●● Needs inner E2E | ●●● |
| AuthN / AuthZ boundary | ●●● Ticket + attestation | ●● IP ACLs coarse | ●●● | ●●● |
| Observability | ●● ICE stats | ● | ●●● | ●● |
| Maintenance | ●● | ● | ●●● | ●● |
| Path to a full private network | ● | ●●● | ● | ● |
| Dependence on a control server | ●● Needed to connect; P2P survives until lease expiry | ●● | ● Relay is the server | ●● |

**Outcome:** A plus C together cover every requirement. B is deferred, since its cost is mostly VPN integration that V1 does not need.

**Race (proposed):**

1. Start ICE immediately.
2. Start the WSS relay after 4 s without an ICE connection, or immediately if a "UDP blocked" hint is cached for the current network.
3. The first transport to complete attestation wins; close the other.

**Consequences:**

- Two transports to maintain.
- Diagnostics report three path types: `direct`, `turn` and `wss_relay`.
- Relayed bytes count toward EC2 egress.

## ADR-003: Shared Go transport core (`prwcore`)

- **Status:** Proposed. Decided after the mobile feasibility spike.
- **Context:**
  - The Flutter WebRTC plugin has known backpressure caveats: buffered amounts are cached from events, and there is no max-message-size API.
  - The libwebrtc ↔ Pion interop must be proven.
  - The WSS fallback needs TLS 1.3 over an arbitrary byte stream, which Dart's `SecureSocket` cannot wrap directly.
  - Without a shared core, framing and attestation would be written twice.
- **Decision (proposed):** One Go module, `prwcore`, contains:
  - the Pion transport, the relay transport and `crypto/tls`
  - framing, flow control and attestation
  - the connection manager

  The host agent links it directly. The phone links it with **gomobile** through a narrow API: connect, send, receive, close and diagnostics. Device-key signatures are produced by callbacks into the platform keystore, so phone private keys never enter Go memory.
- **Spike pass criteria:**
  - Terminal bytes flow both ways on real Android and iOS devices over direct, TURN-UDP, TURN-TLS:443 and WSS.
  - App size grows by ≤ 25 MB per ABI.
  - Reconnect on resume works.
  - CI builds are reproducible.
  - Keystore signing works on both platforms.
- **Alternatives:**
  - `flutter_webrtc` with Dart framing and fallback (the fallback plan if gomobile fails).
  - Go via FFI.
  - A Rust core (rejected because it adds a third language).
- **Consequences:**
  - A single protocol implementation.
  - CI needs the Android NDK and macOS runners.
  - The app binary is larger.

## ADR-004: WSS relay with end-to-end TLS 1.3 and identity attestation

- **Status:** The need is Accepted; the mechanism is Proposed.
- **Context:** DPI and proxy networks block UDP and often non-HTTPS TLS. A WebSocket to the API hostname on 443 looks like normal web traffic. The gateway terminates the outer TLS, so it must not be able to read the payload.
- **Decision:**
  1. Phone and host each join `wss://api.example.invalid/v1/relay` with an attempt-scoped relay token and a role. The server pairs the two sockets by attempt ID and copies opaque binary messages.
  2. Inside the relayed stream, the two peers run TLS 1.3:
     - The host is the server.
     - Both sides use ephemeral self-signed P-256 certificates and mutual authentication.
     - Each side validates the other by pinning the certificate fingerprint exchanged over signaling.
  3. The same signed identity attestation used on WebRTC then binds the TLS certificate to each peer's long-term device key.
- **Alternatives:**
  - Noise: weaker library maturity across the toolchain.
  - TURN via an HTTP proxy: inconsistent client support. ICE still tries it.
  - Plaintext through a trusted gateway: rejected.
- **Consequences:**
  - The relay sees ciphertext, timing, volume and the device IDs of the attempt.
  - The relay is rate-limited and bandwidth-capped.
  - An EC2 outage drops relayed sessions.

## ADR-005: coturn ≥ 4.18 on a dedicated IP, ephemeral credentials, hardened

- **Status:** Proposed.
- **Context:** coturn is the standard TURN server. 2026 brought several serious coturn CVEs: pre-auth memory disclosure, a mobility-ticket allocation takeover, admin SQL injection, ACL bypasses and DTLS denial of service.
- **Decision:**
  - **Version:** pin coturn ≥ 4.18 by image digest.
  - **Credentials:** use TURN REST credentials (`use-auth-secret`). The username is `<expiry>:<attempt_id>` and the credential is `base64(HMAC-SHA1(secret, username))`, with a lifetime of 10 minutes or less.
  - **Listeners (Elastic IP B):** UDP/TCP 3478, TLS on 443 and 5349, and a narrow UDP relay range.
  - **Disabled:** the CLI, the web admin, mobility, external DB/Redis backends, multicast peers, and TLS 1.0/1.1.
  - **Denied peers:** private, loopback, link-local and CGNAT ranges, the EC2 metadata IP and the VPC range.
  - **Limits and logging:** per-user and total quotas, `max-bps`, and no payload logging.
- **Alternatives:**
  - Pion TURN: held in reserve if coturn security stalls.
  - A custom relay only: unnecessary, because the WSS relay already covers TCP-only networks.
- **Consequences:** coturn needs a patch cadence, an advisory subscription and a TURN-bytes alert.

## ADR-006: Single EC2 instance with two Elastic IPs

- **Status:** Accepted.
- **Context:** In restrictive networks both HTTPS and TURN-over-TLS want TCP 443. Sharing one IP would require L4 SNI routing.
- **Decision:**
  - **Instance:** one EC2 instance (sized by load test) with two private IPs on one ENI.
    - Elastic IP A carries Caddy on 80/443 for the REST API, the agent control socket, signaling and the relay.
    - Elastic IP B carries coturn.
  - **Services:** the control plane and PostgreSQL run in Docker Compose on a private network, with images pinned by digest.
  - **Host:** Ubuntu 24.04 LTS, encrypted EBS, IMDSv2 only, and administration through SSM with no public SSH.
- **Alternatives:**
  - One IP with TURN-TLS on 5349: fails restrictive networks.
  - TURN on a separate VPS: this is the documented scale-out path.
  - Kubernetes or ECS: unjustified.
- **Consequences:**
  - The instance is a single point of failure, accepted for the private deployment.
  - TURN and the API share CPU and network capacity, which is mitigated by caps and alerts.

## ADR-007: Google OIDC sign-in, allowlist, device-bound tokens, P-256 device keys

- **Status:** Accepted: **Google OIDC is the only sign-in provider**. Details are Proposed.
- **Context:**
  - There is a single operator, so open sign-up must be impossible.
  - Bearer tokens alone are insufficient.
  - Hardware keystores (iOS Secure Enclave, Android StrongBox) support P-256 but not Ed25519.
- **Decision:**
  1. **Sign-in.** The phone signs in with Google using AppAuth and PKCE. The server validates the ID token (issuer, audience, signature via JWKS, expiry, nonce, verified email) and accepts only subjects listed in `PRW_ALLOWED_SUBJECTS`.
  2. **Device registration.** The sign-in exchange also registers the phone's device public key, proven by a signature over a server nonce.
     - A new phone needs **no further approval**. It starts with no grants, and the owner then grants it access to specific hosts.
  3. **Tokens.**
     - The access JWT (Ed25519, 10 min) carries the account, device and kind.
     - The refresh token is opaque and 256-bit. It is stored hashed, rotates on every use, and its whole family is revoked on reuse.
     - Every refresh requires a fresh device-key signature.
  4. **Hosts** authenticate to the control socket by challenge–response with their device key.
  5. **Device keys** are ECDSA P-256:
     - **Phone:** Android Keystore (StrongBox or TEE) or iOS Secure Enclave.
     - **Host:** a PKCS#8 file with mode 0600.
  6. **Server signing keys** are Ed25519 with key-ID rotation.
- **Alternatives:**
  - GitHub sign-in: dropped by the product owner.
  - Self-hosted passkeys or TOTP.
  - Ed25519 device keys: these would be software-only on phones.
  - mTLS for the API: deferred.
- **Consequences:**
  - A stolen refresh token is useless without the device key.
  - A compromised Google account lets an attacker enroll a new phone, but that phone has no grants. Every enrollment is audited and visible.

## ADR-008: tmux persistence backend with plain-PTY fallback

- **Status:** Proposed.
- **Context:** Sessions must survive phone disconnects, app death and agent restarts. Prior art such as Eternal Terminal separates session identity from transport identity.
- **Decision:**
  - **When tmux ≥ 3.0 is present:**
    - The agent creates one tmux session per PRW session (`prw-<uuid>`) on a private socket in `$XDG_RUNTIME_DIR/prw/` (directory mode 0700), using an agent-supplied config with `window-size latest` and a 50 000-line history.
    - Streaming uses `tmux attach` inside a PTY the agent owns, so tmux redraws the screen on reattach. A disconnect kills only the attach client.
    - The agent runs as a `systemd --user` service with lingering and `KillMode=process`, and starts the tmux server through `systemd-run --user --scope`, so restarting the agent never kills tmux.
  - **Without tmux:** the agent uses a plain PTY with a bounded ring buffer. The session survives disconnects but not agent restarts, and the agent flags it as non-persistent.
- **Alternatives:**
  - tmux control mode: structured, but needs a parser. Deferred.
  - dtach or abduco: no redraw on reattach.
  - An agent-held PTY only: fails the restart requirement.
- **Consequences:**
  - The user's own `~/.tmux.conf` is not loaded.
  - Sessions end on host reboot; the agent reconciles at startup.
  - Multiple phones can attach to the same session.

## ADR-009: Signed tickets verified on the host, plus a grant lease

- **Status:** Proposed.
- **Context:** Hosts must authorize connections without a synchronous API call, must behave predictably during a control-plane outage, and must honor revocation within 30 s.
- **Decision:**
  - **Connection tickets:** compact JWS (Ed25519) bound to:
    - the host (audience) and the phone (subject)
    - the account and attempt
    - a capability, a nonce and a single-use `jti`
    - an optional target session

    A ticket expires 60 s after issue.
  - **Ticket verification:** the host pins the server's verification keys at pairing and receives rotations over the control socket.
  - **Grant lease:** the host holds a signed list of phones and their capabilities, pushed on connect and on every change.
    - **Lifetime:** 10 min, renewed every 3 min (*proposed*).
    - **On expiry:** new opens and attaches are refused, and existing streams close.
    - **Revocation:** a pushed revocation takes effect immediately.
- **Alternatives:**
  - Opaque tickets with an introspection call: needs the API online at connect time.
  - PASETO: fewer maintained libraries.
- **Consequences:**
  - The ticket signing key is a critical secret, rotated with an overlap window.
  - Clock skew of ±30 s is tolerated.
  - Behavior during an outage is bounded and explicit.

## ADR-010: Data layer

- **Status:** Proposed.
- **Context:** The initial schema draft had four problems:
  - It did not enforce that referenced devices belong to the same account and are the right kind.
  - It mixed administrative state with presence.
  - Cascading deletes erased history.
  - The outbox had no dedupe key.
- **Decision:**
  - Keep one `devices` table with a `kind` column and a `UNIQUE(account_id, id, kind)` constraint.
  - Referencing tables use constant generated kind columns and composite foreign keys, so a grant can only ever point from a phone to a host in the same account.
  - Store `admin_state ∈ {pending, active, revoked}` only. Presence is derived from heartbeats.
  - Revoke rows (soft delete) and use `ON DELETE RESTRICT`.
  - Generate UUIDv7 IDs in the application.
  - Tooling:
    - goose migrations, forward-only in production
    - sqlc on pgx v5 for queries
    - row-level security deferred, as a defence-in-depth option
- **Alternatives:**
  - Separate phone and host tables.
  - Triggers.
  - An ORM.
  - golang-migrate.
- **Consequences:** Integrity is enforced by the database, not only by application code.

## ADR-011: Metadata-only audit; no terminal content server-side

- **Status:** Accepted.
- **Decision:**
  - The server, relays, logs, analytics and crash reports never receive or store terminal input or output, command lines, environment variables or file names.
  - Audit and session events use typed metadata allowlists.
  - Phone scrollback is held in memory only.
- **Consequences:**
  - Debugging relies on lifecycle events, ICE statistics and error codes.
  - Support bundles are redacted.

## ADR-012: Flutter stack

- **Status:** Proposed.
- **Context:** The UI must model six distinct connection and session states. xterm.dart, the only mature Flutter terminal widget, has been inactive since 2025.
- **Decision:**
  - **App framework:** Riverpod (with code generation) for state and go_router with auth guards for routing.
  - **Platform plugins:**
    - `flutter_appauth` for Google sign-in
    - `flutter_secure_storage`
    - `mobile_scanner` for QR codes
  - **Terminal:** xterm.dart, pinned and ready to fork into the repository if fixes are needed (for example, escape-sequence filtering).
  - **Transport:** accessed through a `TransportService` interface backed by `prwcore`, with a fake implementation for widget tests.
- **Alternatives:**
  - Bloc.
  - A custom terminal renderer: too costly.
  - xterm.js in a WebView: rejected for input fidelity and attack surface.
- **Consequences:** The xterm fork may need maintenance. Claude Code and Codex TUIs must be validated early.
