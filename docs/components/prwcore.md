# prwcore: Shared Go Core

> **Status:** Target design. The host agent always uses prwcore. Using it on the phone through gomobile is **proposed**; the decision is made after the transport spike on real Android and iOS devices.
> **Location:** `core/prwcore/`

prwcore is the single implementation of the PRW data-plane protocol. It covers:

- framing and flow control
- peer identity attestation
- transport establishment over WebRTC (Pion) or the WSS relay with inner TLS 1.3
- the connection manager that races those paths

The host agent links it directly. The phone app is intended to link it through gomobile, so both ends run the same code. This removes interop risk between two WebRTC stacks and keeps the protocol in one place.

prwcore contains no custom cryptography. It composes Pion (DTLS/SCTP), Go `crypto/tls`, `crypto/ecdsa` and `go-jose`.

---

## 1. Package layout

```text
core/prwcore/
  frame/         12-byte header codec, size validation
  control/       control message envelope + typed messages, JSON schema validation
  flow/          per-stream credit accounting
  attest/        JCS canonicalisation, ES256 JWS build/verify, DER↔raw signature conversion
  ticketclaims/  ticket and lease claim types + verification helpers (EdDSA)
  transport/
    transport.go       Transport interface (Conn with control + N terminal streams)
    webrtc/            Pion PeerConnection, negotiated DataChannels, ICE config
    wssrelay/          /v1/relay join, binary WS ↔ net.Conn adapter, inner TLS 1.3
  connmgr/       path race, timeouts, UDP-blocked hint cache, winner selection
  mobile/        gomobile-friendly facade (proposed): callbacks, byte slices, no generics
  vectors_test/  golden-vector tests against protocol/vectors/
```

---

## 2. Transports

Both transports give the layers above them the same abstraction: one CONTROL stream plus any number of terminal streams.

| | WebRTC (direct / TURN) | WSS relay |
|---|---|---|
| Library | `github.com/pion/webrtc/v4` | `github.com/coder/websocket` + `crypto/tls` |
| Encryption | DTLS 1.2 (WebRTC) | TLS 1.3 end to end *inside* the outer WSS/TLS |
| Channels | `prw-ctl` (negotiated id 0), `prw-term` (id 1); reliable, ordered | One TLS byte stream; frames concatenated |
| Framing | One frame per DataChannel message | Frames back to back; `len` delimits them |
| NAT traversal | ICE: host, srflx and relay candidates (TURN UDP/TCP and TLS on 443) | None needed; the connection is outbound TCP/443 only |
| Peer certificate | Ephemeral DTLS certificate; fingerprint taken from the SDP | Ephemeral self-signed P-256 certificate; fingerprint exchanged via signaling |

### WebRTC configuration

- `SetNetworkTypes(udp4, udp6, tcp4, tcp6)`.
- mDNS candidates are disabled on hosts.
- ICE timeouts: disconnected 5 s, failed 15 s, keepalive 2 s.
- Candidates are trickled.
- DataChannels are detached (`SettingEngine.DetachDataChannels`) to get plain `io.ReadWriteCloser` semantics.
- `SetBufferedAmountLowThreshold` is a second guard: the buffered amount stays at or below 1 MiB.

### WSS relay with inner TLS 1.3

1. Each peer connects to `wss://api.example.invalid/v1/relay` and sends `{"type":"join", attempt_id, relay_token, role}`. The host joins as `server` and the phone as `client`.
2. Once both have received `{"type":"joined"}`, the WebSocket becomes an opaque byte pipe. prwcore adapts it to a `net.Conn`.
3. Each peer generates an ephemeral P-256 key and a self-signed certificate (CN `prw-<attempt>`, valid for 1 h). Each sends the SHA-256 of its certificate as `tls_fingerprint` over signaling.
4. The peers run TLS 1.3 with these settings:
   - `MinVersion = tls.VersionTLS13`
   - `ClientAuth = RequireAnyClientCert`
   - ALPN `prw/1`
   - a custom `VerifyPeerCertificate` that compares the peer certificate's fingerprint with the signaled value. Chain validation is disabled because the certificates are ephemeral and self-signed.
5. Attestation (§3) then binds the TLS certificates to the enrolled device keys. Even if signaling were tampered with, the relay and the control plane cannot read or alter the terminal stream.

---

## 3. Identity attestation

Every peer connection must pass mutual attestation before any terminal message is accepted.

The attestation is a compact JWS (`ES256`) over a **JCS-canonical (RFC 8785)** JSON payload:

```json
{
  "purpose": "prw.peer.attest.v1", "pv": 1,
  "att": "<attempt_id>", "from": "<own device_id>", "to": "<peer device_id>",
  "role": "phone|host", "nonce": "<server attestation nonce>",
  "transport": "dtls|tls13",
  "local_fp": "<sha256 of own certificate>", "remote_fp": "<sha256 of peer certificate as observed>",
  "cap": "terminal", "iat": 1760313840, "exp": 1760313900
}
```

The exchange:

1. Both peers send `hello`. The protocol version is negotiated as `min(max_a, max_b)`.
2. Both peers send `peer.attest{jws}`. The phone also includes its connection ticket.
3. Each peer verifies the other's attestation:
   - The signature verifies with the **pinned** peer key. The host uses the phone key from its signed grant lease; the phone uses the host key pinned at pairing.
   - `att`, `nonce`, `from` and `to` match.
   - The peer's `local_fp` equals the certificate actually observed on this transport, and its `remote_fp` equals our own certificate.
   - `iat ≤ now ≤ exp` within ±30 s, and `exp − iat ≤ 120 s`.
   - `cap` is allowed by the ticket.
4. Each peer sends `peer.identity_verified`. Terminal traffic is allowed only after **both** peers have sent it.
5. The whole exchange has a 5 s timeout. Any failure closes the connection with `peer_identity_mismatch` and is not retried within the same attempt.

Signing goes through an interface, so hardware-backed keys never leave the device:

```go
type Signer interface {
    PublicKeySPKI() []byte
    SignDER(digest []byte) ([]byte, error) // ECDSA P-256; converted to raw r||s for JWS
}
```

---

## 4. Frame codec

| Offset | Size | Field | Values |
|---|---|---|---|
| 0 | 1 | `ver` | `0x01` |
| 1 | 1 | `type` | `0x01` CONTROL (JSON), `0x02` INPUT (phone→host), `0x03` OUTPUT (host→phone), `0x04` CLOSE_STREAM |
| 2 | 1 | `flags` | bit0 `FIN`; all other bits MUST be 0 |
| 3 | 1 | reserved | `0x00` |
| 4 | 2 | `stream_id` | 0 = CONTROL; ≥ 1 = terminal streams |
| 6 | 2 | `len` | 0..16384 |
| 8 | 4 | `seq` | Per-stream, per-direction counter; used only for diagnostics and gap detection |
| 12 | len | payload | Raw bytes, or UTF-8 JSON for CONTROL (≤ 16 KiB) |

All integers are big-endian. The decoder rejects any of the following with `protocol_error`:

- an unknown `ver` or `type`
- `len` greater than 16384
- non-zero reserved flags
- an oversized CONTROL frame
- a frame for an unknown stream

A maximum frame is 16,396 bytes, which stays well within the message-size limits of both libwebrtc and Pion.

---

## 5. Flow control

- Credit is counted in payload bytes, per stream and per direction. The initial window is **0**.
- **Output (host → phone).** After `terminal.ready`, the phone grants 256 KiB with `flow.credit{stream_id, bytes}`. It re-grants once half the window has been rendered.
- **Input (phone → host).** The host grants 64 KiB and re-grants once those bytes have been written to the PTY.
- A sender with no credit blocks. On the host that means it stops reading the PTY, so backpressure reaches the application and no bytes are ever dropped.
- Buffering per stream is bounded at one 16 KiB read buffer plus the bytes in flight.

---

## 6. Connection manager

```text
t=0    request attempt (done by caller) → start ICE (offer, trickle)
       if hint[network] == UDP_BLOCKED → start WSS relay immediately
t=4s   if ICE not connected → start WSS relay
each transport, when up → hello + attestation
first transport to complete attestation wins; others are closed
t=20s  no winner → fail "connect_timeout" (with ice_state, turn_alloc, wss_state diagnostics)
winner == wss && no srflx/relay candidates gathered → hint[network] = UDP_BLOCKED (24 h)
winner == direct|turn → clear hint
```

- `network` is a salted, install-local hash of the current network's identity. It never leaves the device.
- The path reported to the server is one of `direct` (host or srflx pair), `turn` (relay candidate) or `wss_relay`.
- A reconnect always uses a brand-new attempt, ticket, TURN credentials and relay token.

---

## 7. gomobile binding surface (proposed)

gomobile can only export simple types, so `prwcore/mobile` provides a small facade built from callbacks and byte slices:

```go
// package mobile
type HostCallbacks interface {
    OnEvent(kind string, json []byte)            // pathSelected, connected, peerVerified, closed, stats
    OnTerminalOutput(streamID int32, data []byte)
    OnSignal(json []byte)                         // outbound signaling to send via the app's WSS client
    Sign(digest []byte) ([]byte, error)           // delegated to Keystore / Secure Enclave
}

type Session struct{ /* opaque */ }

func Connect(paramsJSON []byte, cb HostCallbacks) (*Session, error)
func (s *Session) DeliverSignal(json []byte) error
func (s *Session) SendControl(json []byte) ([]byte, error)
func (s *Session) WriteTerminal(streamID int32, data []byte) error // blocks on credit
func (s *Session) Close(reason string)
```

- A thin Kotlin and Swift shim adapts these callbacks to Flutter `MethodChannel` and `EventChannel`.
- The transport spike checks the following before this approach is adopted:
  - APK/IPA size growth (target ≤ 25 MB)
  - cold start time
  - foreground and resume behaviour
  - reproducible CI builds

---

## 8. Golden vectors

`protocol/vectors/` holds JSON fixtures that both the Go and Dart tests consume. CI fails if any implementation disagrees with a fixture.

1. Frames: every `type`, boundary lengths (0, 1, 16384), `FIN`, and invalid cases (`len` 16385, bad `ver`, non-zero flags).
2. CONTROL envelopes for every message type, including unknown fields, which must be ignored.
3. JCS canonicalisation of attestation, auth PoP, pairing and lease payloads.
4. ES256: DER→raw conversion, and a deterministic (RFC 6979) attestation JWS.
5. EdDSA tickets and leases: valid, expired, wrong `aud` and unknown `kid` cases.
6. TURN REST credential derivation.
7. Pairing-code normalisation: Crockford confusables and hyphen stripping.
8. QR payload parse and serialize.

All fixture keys are clearly marked **TEST ONLY**.
