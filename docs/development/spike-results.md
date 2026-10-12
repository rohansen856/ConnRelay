# Phase 1 Feasibility Spike Results

> **Status:** Phase 1 complete for Linux hosts and Android phones. iOS and real-carrier field runs are still open (see [Open items](#open-items-before-gate-a)).
> **Toolchain:** Go 1.27.2 (module minimum 1.26), Flutter 3.41.6, Pion WebRTC v4.2.23, coturn 4.18.0, tmux 3.2a, xterm.dart 4.0.0.

Every result below comes from a test or script in this repository. The commands to reproduce it are listed with each spike.

> **Historical record.** After Gate A the throwaway spike app (`apps/mobile_spike/`, package `dev.connrelay.connrelay_spike`) and its on-device harness (`tests/devicelab/`) were removed; the product app in `apps/mobile/` replaced them. Commands below that need them work only from a checkout of the git history before the commit `chore(mobile): remove the spike app`. The network lab, `make spike-s4` and the S5 capture script are still current.

## Summary

| Spike | Question | Result |
|---|---|---|
| S1 | Can a shared Go core (Pion via gomobile) carry the data plane on the phone? | **Yes, on Android.** Direct, forced-TURN, WSS-relay and auto modes all pass on a real device. **iOS not run.** |
| S2 | Do the TURN paths work, including TURN-TLS on the second IP's port 443? | **Yes.** All 7 S2 network-lab scenarios pass. |
| S3 | Does the WSS relay with inner TLS 1.3 survive HTTPS-only and DPI egress, and resist tampering? | **Yes.** It works through a CONNECT proxy with a hostname allowlist, and a tampered fingerprint is rejected. |
| S4 | Does a tmux session survive detach, reattach and agent restart, and is output bounded and lossless? | **Yes**, provided the agent unit uses `KillMode=process`. |
| S5 | Does xterm.dart render Claude Code and Codex correctly? | **Yes, screen-exact**, but with **2 defects** in 4.0.0. The plan to fork it stands. |
| S6 | Can the phone sign with a hardware-backed P-256 key? | **Yes, on Android** (TEE, non-exportable). **iOS Secure Enclave not run.** |

**D-22, the client transport core, is recommended to adopt the shared Go core.** It is confirmed on Android. iOS must still pass the same device suite before Gate A closes.

---

## S1: Shared Go core on the phone (Android)

**Setup.**
- Device: A059P running Android 16 (API 36), arm64.
- The Flutter app embeds `connrelaycore` through `gomobile bind`. The phone side of each attempt runs in-process and signs its attestation with the Keystore key from S6.
- The host is a Linux laptop on the phone's Wi-Fi hotspot.
- Run (at the time) with `make aar`, then `flutter build apk`, then `LAN_IP=… make devicelab`. These targets were removed with the spike app.

| Mode | Path chosen | Connect time | RTT | 4 MiB echo, integrity-checked |
|---|---|---|---|---|
| Direct ICE | direct | 1.12 s | 2.2 ms | OK, 54 Mbit/s |
| Forced TURN (coturn on the LAN) | turn (`relay/udp → host/udp`) | 2.11 s | 3.7 ms | OK, 60 Mbit/s |
| WSS relay with inner TLS 1.3 | wss_relay | 43 ms | 3.0 ms | OK, 2.06 Mbit/s (relay cap of 2 Mbit/s) |
| Auto (connection manager race) | direct | 139 ms | 2.8 ms | OK |

- **Lifecycle.** A 6 MB transfer over the WSS relay kept running after the app was backgrounded and the screen was switched off. It finished about 40 s later. Longer periods, such as Doze, were not tested.
- **Size.**
  - AAR: 4.8 MB (Go 1.27.2 build).
  - `libgojni.so`: 12.3 MB, stored uncompressed in the APK (the arm64 release APK is 28.6 MB in total).
  - Both are within the proposed budget of 25 MB or less.
  - The probe also contains test-client code, so the production core should be slightly smaller.
- **Not done:**
  - the `flutter_webrtc` ↔ Pion comparison, which became unnecessary once Pion ↔ Pion worked on the device;
  - an iOS build;
  - a field run over a real carrier NAT (that needs the public deployment).

### Field run over the public internet

**Setup.**
- The lab control plane is exposed through a temporary Cloudflare quick tunnel.
- The phone reaches it over its carrier network (5G); the host runs on the laptop.
- Ran with `tests/fieldlab/run.sh`, which drove the spike APK. Both were removed after Gate A and are in the git history.

| Mode | Path | Connect time | RTT | 1 MiB echo |
|---|---|---|---|---|
| WSS relay through Cloudflare's edge | wss_relay | 1.69 s | 261 ms | OK, 2.2 Mbit/s (relay cap) |
| Auto, with public STUN | direct | 516 ms | 3.6 ms | OK |

- **WSS relay over a real CDN edge.** The relay path works through Cloudflare. Its 261 ms RTT covers both legs through the Delhi edge, which is within the proposed relay echo target of under 500 ms.
- **Direct-path caveat.** The laptop is connected to the phone's own hotspot, so the direct pair is LAN-local. A true carrier-to-carrier direct or TURN measurement still needs a host on a different network.
- **Tunnel setup.**
  - A fresh `trycloudflare.com` name can take a minute to resolve on the carrier's DNS, so the script waits for it.
  - A local `~/.cloudflared/config.yml` with ingress rules overrides `--url`, so the script runs the quick tunnel with an empty config.

## S2: TURN paths and the two-address deployment (network lab)

**Setup.**
- Docker topology: two private LANs behind Linux NAT routers.
- The control-plane stand-in listens on `10.99.0.10:443` (standing in for EIP-A).
- coturn 4.18 listens on `10.99.0.20` (standing in for EIP-B), on 3478 UDP/TCP and TLS 443.
- Run with `make netlab`.

| Scenario | Expected | Result |
|---|---|---|
| Phone on the same LAN as the host | direct | PASS (`host → host`, 6 ms connect, about 860 Mbit/s echo) |
| NATed phone to a host with a public address | direct | PASS |
| Two Linux port-restricted NATs | turn | PASS (see the finding below) |
| Two symmetric NATs (`--random-fully`) | turn | PASS |
| Forced relay | turn | PASS |
| Phone with UDP blocked | turn (over TCP or TLS) | PASS |
| Phone allowed **TCP 443 only** | turn via **TURN-TLS on EIP-B:443** | PASS: TURNS on one IP's 443 works alongside HTTPS on the other IP's 443 |

**Finding: Linux NAT and hole punching.** Behind two Linux MASQUERADE NATs, ICE fell back to TURN even though both NATs preserve ports.

1. The first hole-punch packet reaches the remote router before that router's own outbound packet.
2. That packet creates a conntrack entry on the remote router.
3. When the host then sends outbound, the router remaps it to a new port, so simultaneous open fails.

Many home routers behave differently, so the lab only demonstrates that the fallback works. It does not predict direct-connect rates. The field matrix must measure those.

**Finding: TURN connect time.** TURN paths consistently connect in about 2.0–2.1 s, because Pion's ICE agent waits for better candidate pairs before nominating. That is inside the 10 s p95 target. Tuning it is a Phase 5 item.

## S3: WSS relay through HTTPS-only and DPI egress

| Scenario | Result |
|---|---|
| Phone allowed only TCP to an HTTPS CONNECT proxy; squid permits only `CONNECT api.lab.invalid:443` | PASS: `wss_relay` at the 4 s fallback |
| The same, with the cached "UDP blocked" hint | PASS: `wss_relay` connected in 4 ms (WSS starts at t=0) |
| TURN server down and UDP blocked | PASS: `wss_relay` |
| Peer certificate fingerprint swapped in signaling | Rejected by inner TLS and by attestation (unit tests in `services/control/internal/relay`, `core/connrelaycore/peer`) |
| Forged, reused, wrong-attempt or wrong-role relay token; a second peer with the same role | Rejected (relay unit tests) |
| Relay rate cap (2 Mbit/s) and per-attempt byte cap | Enforced (relay unit tests; measured at about 2.06 Mbit/s) |

The relay only copies opaque binary messages. Payloads are TLS 1.3 ciphertext between the phone and host certificates, and those certificates are bound to the enrolled device keys by attestation.

## S4: Terminal persistence and flow control

| Check | Result |
|---|---|
| Agent unit with `KillMode=process`: stop the agent, start a new one | **Session survives with the same shell PID** (`make spike-s4`) |
| Same test with systemd's default `KillMode=control-group` | Session is killed, so `KillMode=process` (or a separate scope) is **required** |
| Drop the transport, reconnect over a **new attested WebRTC connection**, and attach by session ID | Same shell PID and shell variables intact (`agents/host/internal/termserver`, `TestEndToEndOverWebRTC`) |
| 50 MiB of random bytes through a raw PTY to a slow consumer | SHA-256 identical. Peak in-flight data was 255 KiB, within the 256 KiB window. |
| About 14 MiB of output through tmux to a slow consumer | The final screen arrives and in-flight data stays bounded (tmux re-renders rather than forwarding raw bytes) |
| Resize, Ctrl-C, exit codes, terminate with confirmation, list, idempotent open, session cap | Pass (`ptyproc`, `tmux` and `termserver` tests) |

**Findings.**
- **Early input is lost.** tmux discards input that arrives before the attaching client finishes terminal negotiation. The agent holds input until the attach client has produced output, with a 2 s cap.
- **Input blocked the receive loop (fixed).** Writing input inside the connection's receive loop could stall that loop under load. Input is now queued, bounded by the 64 KiB input credit, and written by a goroutine per stream.
- **Stream state must exist before credit arrives.** A client must create stream state as soon as `terminal.ready` arrives, before handling the next frame, because the host's input credit follows immediately. The test client originally got this wrong.

## S5: xterm.dart with coding-agent TUIs

**Method.**
1. `tests/spikes/s5_capture_tui.sh` records a TUI's raw output inside tmux.
2. Midway through, it resizes the window from 100×30 to 80×24.
3. It saves tmux's screen before and after the resize as ground truth.
4. `apps/mobile/test/xterm_tui_test.dart` (originally in the spike app) replays the same bytes into an xterm.dart `Terminal` and compares each cell.

| TUI | Rows mismatched (100×30 / 80×24) |
|---|---|
| Claude Code: folder-trust dialog | 0 / 0 |
| Claude Code: main UI (block-art logo, box drawing, status lines) | 0 / 0 |
| Codex: update dialog | 0 / 0 |
| htop | 0 / 0 |
| less | 0 / 0 |
| Codex: main UI | **Crash, defect 2** |

**Defects in xterm 4.0.0.** Both are reasons to fork, as ADR-012 already plans.
1. **Arrow keys ignore application cursor mode (DECCKM).**
   - `core/input/handler.dart:119` passes `appKeypadMode` where `cursorKeysMode` belongs.
   - Programs such as vim, less and htop that enable `?1h` receive `ESC [ A` instead of `ESC O A`.
   - The fix is one line.
2. **Buffer assertion on Codex's main UI.**
   - `IndexAwareCircularBuffer` asserts `attached` during a line feed inside a scroll region (`Buffer.index → insert`).
   - Release builds skip the assertion, so lines may be corrupted silently.
   - This needs a root-cause fix in the fork, plus a regression test from this fixture.

Key encodings for Esc, Tab, Enter, Backspace and Ctrl chords, and bracketed paste, are correct.

## S6: Hardware-backed device key (Android)

| Property | Result |
|---|---|
| Algorithm | ECDSA P-256 (`secp256r1`) |
| Location | TEE (`KeyInfo.securityLevel`); this device has no StrongBox, and the code tries StrongBox first |
| Exportable | No (`PrivateKey.getEncoded() == null`) |
| Sign latency | 24–25 ms per signature |
| Interop | Keystore DER signature converted to raw r‖s → ES256 JWS → verified by Go `attest.Verify`. Every S1 attestation was signed with this key. |

## Changes made because of the spikes

| Change | Where |
|---|---|
| **`path.select`.** The phone (controlling side) chooses the winning transport and announces it, and the host commits to that transport. Without it, near-simultaneous ICE and WSS completions could leave the two sides on different paths. | `core/connrelaycore/connmgr`, [protocol](../technical/protocol.md) |
| **Go toolchain moved to 1.27.2 (module minimum 1.26).** Go 1.25.5 had reachable standard-library vulnerabilities, and `golang.org/x/mobile` needs 1.26 or later. govulncheck now reports no reachable vulnerabilities. | all `go.mod`, CI |
| **Pion on Android needs `-ldflags=-checklinkname=0`.** `wlynxg/anet` links to a `net` internal. | `apps/mobile/gocore/build-aar.sh` |
| **Bounded transport close.** Tearing down Pion over TURN-TLS can stall for more than 3 s, so the close must not block reporting or reconnect. | `tests/netlab/labclient`; to carry into the app's connection lifecycle |
| **coturn 4.18 deprecates `no-cli`.** | lab configs |
| **App logs on some OEM builds.** Some Android builds drop app INFO logs unless `log.tag` is raised. In-app diagnostics must not depend on logcat. | the former `tests/devicelab/run.sh` |
| **Flow-control fixes:** credit after close (fixed a panic), and non-blocking input. | `core/connrelaycore/flow`, `agents/host/internal/termstream` |

## Open items before Gate A

1. **iOS:**
   - gomobile `xcframework` build;
   - the S1 device suite on an iPhone;
   - a Secure Enclave P-256 signer for S6.

   This needs macOS and Xcode.
2. **Field run on a carrier network:** the WSS relay is verified over the carrier network through Cloudflare. Still open: a host on a different network from the phone, for carrier-NAT direct and TURN rates (this needs the public TURN deployment).
3. **TURN-TLS:443 from the phone.** It is verified in the lab with Linux peers. Re-run it from the device once a public coturn with a real certificate exists.
4. ~~**xterm.dart fork.**~~ Done: xterm 4.0.0 is vendored in `apps/mobile/third_party/xterm` with both defects fixed and guarded by `apps/mobile/test/xterm_fork_test.dart`. The S5 replay test runs when fixtures are recorded locally (they stay gitignored because captures can contain user names and paths).
