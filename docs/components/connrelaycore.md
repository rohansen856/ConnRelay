# connrelaycore: Shared Go Core

> **Status:** Implemented. Both the host agent and the Android app use connrelaycore; the app links it through gomobile (decided after the on-device transport spike, see [spike results](../development/spike-results.md)). Items marked **(planned)** are not built yet.
> **Location:** `core/connrelaycore/`

connrelaycore is the single implementation of the ConnRelay data-plane protocol. It covers:

- framing and flow control
- peer identity attestation
- transport establishment over WebRTC (Pion) or the WSS relay with inner TLS 1.3
- the connection manager that races those paths

The host agent links it directly. The phone app links it through gomobile, so both ends run the same code. This removes interop risk between two WebRTC stacks and keeps the protocol in one place.

connrelaycore contains no custom cryptography. It composes Pion (DTLS/SCTP), Go `crypto/tls`, `crypto/ecdsa` and `go-jose`.

---

## 1. Package layout

```text
core/connrelaycore/
  frame/        12-byte header codec, size validation
  control/      control message envelope carried in CONTROL frames
  flow/         per-stream credit accounting (output 256 KiB, input 64 KiB windows)
  attest/       JCS canonicalisation, ES256 JWS build/verify, DER↔raw signatures,
                peer attestation and proof-of-possession (connrelay.auth.v1, connrelay.refresh.v1,
                connrelay.agent.v1, connrelay.pair.create.v1, connrelay.pair.complete.v1)
  token/        EdDSA server tokens: tickets, leases, relay and access tokens; key sets
  peer/         hello + mutual attestation handshake, path.select, identity_verified gate
  transport/
    transport.go, streamconn.go, pipe.go   Conn interface (control + N terminal streams)
    webrtc/        Pion PeerConnection, negotiated DataChannels, ICE config
    wssrelay/      /v1/relay join, binary WS ↔ net.Conn adapter
    innertls/      ephemeral P-256 certificates, TLS 1.3 with fingerprint pinning
  connmgr/      path race, timeouts, winner selection
  client/       phone side of a connection: request attempt, signaling, race, verify host pin
  termclient/   terminal protocol client (open, attach, list, input, resize, detach, terminate)
  mobile/       gomobile facade used by the Android app (§7)
```

Golden vectors live in `protocol/vectors/` at the repository root.

---

## 2. Transports

Both transports give the layers above them the same abstraction: one CONTROL stream plus any number of terminal streams.

| | WebRTC (direct / TURN) | WSS relay |
|---|---|---|
| Library | `github.com/pion/webrtc/v4` | `github.com/coder/websocket` + `crypto/tls` |
| Encryption | DTLS 1.2 (WebRTC) | TLS 1.3 end to end *inside* the outer WSS/TLS |
| Channels | `connrelay-ctl` (negotiated id 0), `connrelay-term` (id 1); reliable, ordered | One TLS byte stream; frames concatenated |
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
2. Once both have received `{"type":"joined"}`, the WebSocket becomes an opaque byte pipe. connrelaycore adapts it to a `net.Conn`.
3. Each peer generates an ephemeral P-256 key and a self-signed certificate (CN `connrelay-<attempt>`, valid for 1 h). Each sends the SHA-256 of its certificate as `tls_fingerprint` over signaling.
4. The peers run TLS 1.3 with these settings:
   - `MinVersion = tls.VersionTLS13`
   - `ClientAuth = RequireAnyClientCert`
   - ALPN `connrelay/1`
   - a custom `VerifyPeerCertificate` that compares the peer certificate's fingerprint with the signaled value. Chain validation is disabled because the certificates are ephemeral and self-signed.
5. Attestation (§3) then binds the TLS certificates to the enrolled device keys. Even if signaling were tampered with, the relay and the control plane cannot read or alter the terminal stream.

---

## 3. Identity attestation

Every peer connection must pass mutual attestation before any terminal message is accepted.

The attestation is a compact JWS (`ES256`) over a **JCS-canonical (RFC 8785)** JSON payload:

```json
{
  "purpose": "connrelay.peer.attest.v1", "pv": 1,
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
t=0    request attempt (done by the caller) → start ICE (offer, trickle)
       if UDPBlocked → start the WSS relay immediately as well
t=4s   if no path has won yet → start the WSS relay
each transport, when up → hello + attestation
the phone (controlling side) picks the first transport to finish and announces it with path.select;
the host (controlled side) commits to whichever transport carries path.select; the others are closed
t=20s  no winner → fail "connect_timeout"; the report lists each path's timing and error
```

- The host always runs with `UDPBlocked` set, so it offers both paths at once and lets the phone choose.
- The path reported to the server is one of `direct` (host or srflx pair), `turn` (relay candidate) or `wss_relay`.
- A reconnect always uses a brand-new attempt, ticket, TURN credentials and relay token.
- Caching a per-network "UDP blocked" hint on the phone is **(planned)**.

---

## 7. gomobile binding surface

gomobile can only export simple types, so `connrelaycore/mobile` exposes strings, ints, byte slices and two interfaces. All protocol and crypto encoding stays in Go; the app never re-implements attestation, framing or flow control.

```go
// package mobile (Java: dev.connrelay.core.mobile)
type Signer interface {            // Android Keystore / Secure Enclave
    PublicKeySPKI() ([]byte, error)
    SignDER(digest []byte) ([]byte, error)
}
type Events interface {
    OnOutput(stream int, data []byte)
    OnEvent(kind, detail string)    // "exit" (session id), "revoked" (reason), "closed" (error, "" if clean)
}

func Fingerprint(spki []byte) string
func SignPoP(purpose, nonce, spkiFP, deviceID string, s Signer) (string, error) // connrelay.auth.v1 / connrelay.refresh.v1
func Connect(api, accessToken, deviceID, hostID, pinnedFP, mode string, timeoutMS int, s Signer, ev Events) (*Session, error)

func (s *Session) Path() string      // direct | turn | wss_relay
func (s *Session) AttemptID() string
func (s *Session) Open(cols, rows int) (string, error)            // JSON session description
func (s *Session) Attach(id string, cols, rows int) (string, error)
func (s *Session) List() (string, error)
func (s *Session) Input(stream int, data []byte) error
func (s *Session) Resize(stream, cols, rows int) error
func (s *Session) Detach(stream int) error
func (s *Session) Terminate(id string) error
func (s *Session) Close()
```

- `mode` is `auto`, `webrtc` or `wss`. Blocking calls must run off the UI thread.
- Errors are stable codes (`host_key_mismatch`, `access_grant_missing`, …) that the app maps to UI copy.
- `MainActivity.kt` adapts this to Flutter's `MethodChannel('connrelay/core')` and `EventChannel('connrelay/core/events')`; see [mobile app](mobile-app.md#5-native-bridge).
- `apps/mobile/gocore/build-aar.sh` builds the AAR (`gomobile bind -target=android/arm64,android/amd64 -androidapi 26 -javapkg dev.connrelay.core -ldflags=-checklinkname=0`). An iOS binding is **(planned)**.

---

## 8. Golden vectors

`protocol/vectors/` holds JSON fixtures that implementations must agree with. Today it contains `frames.json`, checked by the Go frame codec tests; because the phone uses the same Go core, there is no separate Dart codec to check. The remaining fixture sets are **(planned)**:

1. Frames (implemented): every `type`, boundary lengths (0, 1, 16384), `FIN`, and invalid cases (`len` 16385, bad `ver`, non-zero flags).
2. CONTROL envelopes for every message type, including unknown fields, which must be ignored.
3. JCS canonicalisation of attestation, auth PoP, pairing and lease payloads.
4. ES256: DER→raw conversion, and a deterministic (RFC 6979) attestation JWS.
5. EdDSA tickets and leases: valid, expired, wrong `aud` and unknown `kid` cases.
6. TURN REST credential derivation.
7. Pairing-code normalisation: Crockford confusables and hyphen stripping.
8. QR payload parse and serialize.

All fixture keys are clearly marked **TEST ONLY**.
