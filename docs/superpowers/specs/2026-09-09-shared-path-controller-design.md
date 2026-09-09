# Shared Path Controller and Portable Telemetry Design

**Status:** approved for implementation on 2026-09-09.

**Goal:** Add a reusable transport-path lifecycle to `PeerSession`, generation-safe telemetry for the portable FFmpeg path, real automatic PMTU watchdog coverage, and a pinned musl validation gate without changing the existing lowlat wire protocol or upgrading `webrtc-ice`.

## Scope

This phase addresses four related but independently testable gaps:

1. Prove that the production lowlat delivery watchdog, rather than a test-only marker, triggers PMTU black-hole recovery in a real Linux namespace.
2. Run the lowlat ABI and syscall boundary tests against musl in a pinned Alpine container.
3. Give `PeerSession` and portable FFmpeg one generation-aware telemetry surface.
4. Add a two-phase path controller, direct↔opaque-relay migration, and a truthful ICE/TURN migration boundary.

The phase is intentionally split into commits so the path abstraction can land without behavior changes before migration behavior is enabled.

Native ScreenCaptureKit/IOSurface/VideoToolbox, native Windows capture/decode/present, Android HEVC, virtual displays, and the `webrtc-ice` 0.20 migration are outside this phase.

## Existing boundaries

The current code already separates the two transport families:

- `engine/lowlat/crates/core/src/session.rs` owns the sans-IO reliable rings, packet-level acknowledgements, PMTU packetization, and the lowlat pacer.
- `engine/lowlat/crates/core/src/endpoint.rs` combines connectivity and media state and currently exposes channel-aware PMTU recovery.
- `engine/lowlat/crates/net/src/shell.rs` owns the Linux socket, wake descriptor, event loop, automatic direct-path PMTU setup, and explicit recovery hook.
- `engine/lowlat/crates/client-core/src/lib.rs` owns `PeerSession`, the signaling endpoint, the long-lived `CipherSession`, and either a direct `UdpTransport` or an ICE `Conn`.
- `engine/lowlat/crates/transport/src/lib.rs` owns the async direct UDP socket, OpenStream relay registration, and encrypted datagram I/O.
- `engine/lowlat/crates/media/src/adaptive.rs` owns encoder-independent frame acknowledgement bitrate control.
- `engine/lowlat/crates/ffmpeg-host/src/main.rs` currently parses `FrameAck` in both the reliable-control and raw-control branches and feeds `AdaptiveBitrate` directly.

The portable path does not expose lowlat's cumulative packet ACK window or `SendRing` occupancy. It must not fabricate those metrics merely to make the two paths look identical.

## Architectural invariants

### One cryptographic session

A path generation is a transport epoch, not a cryptographic session epoch.

Migration preserves all of the following:

- one `CipherSession` and one transmit nonce/counter space;
- one receive replay window;
- reliable-control sequence state;
- frame identifiers and end-to-end `FrameAck` state;
- negotiated capabilities;
- pairing/session identity and authorization.

The replacement path receives only the same session's authenticated datagrams. A migration never creates a second cipher and never merges two cipher/replay states.

### Path generations

Each established path has a monotonically increasing `path_generation`. The first active path is generation 1. A successfully committed replacement increments the generation by one; an abandoned preparation does not change the active generation.

Every path-local metric sample carries its generation. A rate sample never subtracts a baseline recorded under another generation. On commit:

- retain the current encoder bitrate initially;
- reset path RTT, loss, delivery-rate and in-flight EWMA state;
- reset PMTU to the replacement path's conservative baseline;
- reset the path-local pacer to that baseline and current target rate;
- suppress bitrate ramp-up until one healthy observation interval completes.

End-to-end frame feedback is not reset. A `FrameAck` for a frame sent before migration remains valid and is processed against the same bounded frame window.

### Two-phase handoff

Migration is a prepare/commit protocol, not an assignment to a new socket:

```text
ACTIVE generation N
        │
        ├─ prepare replacement backend
        ├─ authenticate with the existing CipherSession
        ├─ prove bidirectional peer traffic
        ├─ validate relay lifetime/framing when applicable
        └─ establish replacement PMTU baseline
                 │
                 ▼
        READY generation N+1
                 │
        ├─ commit sends on replacement
        ├─ old path becomes receive-only DRAINING
        ├─ wait for authenticated commit acknowledgement
        └─ retire old path after a bounded grace period
```

Before `READY`, the active path remains untouched and continues carrying application traffic. The replacement may send only bounded, authenticated path-control probes. It must not receive or emit application media before the handoff is committed.

If preparation fails, the active path and its path-local state remain unchanged. If the replacement fails before its commit acknowledgement, the old path may be reactivated during the bounded rollback window. After the acknowledgement or grace deadline, the old path is retired and no longer sends.

The implementation must use a finite rollback/drain deadline derived from the active path's bounded RTT estimate, clamped to explicit minimum and maximum values. There is no indefinite dual-send mode.

### Path state model

The common lifecycle reports these states:

```text
Preparing → Ready → Active → Draining → Retired
             │                  │
             └────── Failed ◄────┘
```

`Preparing`, `Ready`, `Active`, `Draining`, `Failed`, and `Retired` describe lifecycle state only. They do not dictate how a backend obtains a path.

The common path snapshot contains:

```text
path_generation: u64
kind: DirectUdp | OpaqueRelay | Ice
state: PathState
path_age_ms: u64
datagram_size: usize
path_mtu_state: Base | Searching | SearchComplete | Error | Unavailable
```

Peer addresses, bearer tokens, TURN passwords, session keys, and relay tickets are excluded from diagnostic snapshots.

## Backend responsibilities

### Direct UDP and opaque relay

OpenStream owns direct and opaque-relay lifecycle:

- exchange any replacement candidate through the authenticated signaling endpoint;
- bind a replacement socket without disturbing the active socket;
- connect it to the candidate;
- register the role-scoped opaque-relay ticket when the candidate is a relay;
- use the existing cipher to send an exact authenticated path probe;
- require a matching authenticated response over the replacement path;
- derive a relay-aware PMTU ceiling from the actual framing mode;
- commit only after both endpoints have observed bidirectional replacement traffic.

Direct↔opaque-relay and opaque-relay↔direct are separate path-kind transitions in telemetry even when they use the same `UdpTransport` implementation.

### ICE/TURN

ICE remains the authority over ICE candidate nomination, consent freshness, TURN allocation, permissions, channel binding, and ICE restart. OpenStream wraps that lifecycle and does not manually force a selected pair underneath the ICE agent.

An ICE/TURN replacement is `Ready` only after the agent reports a usable connection and the existing OpenStream cipher completes a bidirectional path proof. A TURN allocation alone is not readiness: the replacement must have functioning peer traffic and valid relay framing.

The implementation remains on the repository's current `webrtc-ice` 0.17 line. No dependency upgrade or 0.20 Sans-I/O migration is part of this phase.

If the current API cannot retain the old connection while an ICE restart prepares a replacement, or cannot expose enough lifecycle information to satisfy the two-phase contract, the ICE backend returns a typed unsupported-migration result. The code and tests must report that limitation; they must not claim TURN migration passed by reconnecting a new session or by switching an internal label.

## Path-control messages

Path-control messages are internal, bounded, authenticated control records carried using the existing OpenStream cipher. They are not exposed as application input or clipboard data.

The vocabulary is versioned and capability-gated. A peer that does not advertise path migration continues to use the current single-path behavior and ignores no application data on its behalf.

The minimum messages are:

```text
PATH_PREPARE   generation, path kind, path token/identifier
PATH_READY     generation, exact validated datagram size
PATH_COMMIT    generation
PATH_COMMIT_ACK generation
PATH_ABORT     generation, typed reason
```

Fields are bounded, reserved bits are rejected, and a message for a generation other than the current active or the one explicitly being prepared is ignored or rejected according to its phase. Tokens identify a candidate/path attempt but never contain bearer credentials or keys.

The existing capability exchange gains an optional, default-false migration capability so older clients remain compatible. The default behavior remains unchanged until both peers advertise support and the caller requests a migration.

## Portable telemetry boundary

### Transport-layer sample

`openstream-transport` records local observations for each async path backend:

```text
path_generation: u64
sent_packets: u64
sent_wire_bytes: u64
received_packets: u64
received_wire_bytes: u64
sample_interval_ms: u64
send_rate_mbps: f64
receive_rate_mbps: f64
```

The counters are cumulative within a generation and reset when a new generation becomes active. The sample is local observation only; it is not a claim about network loss or peer delivery.

`UdpTransport` updates the counters around actual socket send/receive operations, including relay registration only in a separately identified setup counter or excluding registration consistently. Registration traffic must not inflate video delivery calculations.

The ICE adapter exposes the same fields from the `Conn` boundary where the dependency makes them observable. Missing backend signals remain explicitly unavailable; they are not inferred as zero loss or zero delay.

### `PeerSession` snapshot

`PeerSession` exposes a bounded `PeerTransportSnapshot` containing:

- the active `ConnectionPath` and `path_generation`;
- path age and active path state;
- current PMTU/pacing values when known;
- the local transport sample;
- end-to-end frame-feedback values supplied by the media adapter.

The existing `SessionStats` remains backward-compatible as the simple local counter view. New generation-aware fields use a separate type or append-only fields rather than changing the meaning of existing counters.

### `PeerTelemetryAdapter`

`openstream-media` owns a transport-agnostic adapter that combines two deliberately distinct inputs:

```text
Path-local:
  PeerTransportSnapshot

End-to-end:
  frame_sent(frame_id, encoded_bytes, timestamp)
  frame_ack(FrameAck, timestamp)
```

It produces:

```text
pending_frames
oldest_frame_age_ms
smoothed_frame_ack_ms
frame_loss_since_tick
path_generation
path_kind
send_rate_mbps / receive_rate_mbps when available
```

The adapter owns calls to `AdaptiveBitrate::frame_sent`, `frame_acknowledged_with_loss`, and `tick`. FFmpeg no longer has two independent `FrameAck` parsing blocks.

The adapter never exposes lowlat-only cumulative ACK-window fields, `SendRing` occupancy, or packet retransmission counts for `PeerSession`. Those remain available only from the lowlat transport snapshot where they are real.

On a generation change, the adapter keeps pending end-to-end frames, resets path-local rate baselines, keeps the current encoder bitrate, and prevents ramp-up for one healthy interval. An old-generation frame acknowledgement is still accepted because frame identity is end-to-end rather than path-local.

## PMTU and pacing transition

PMTU and pacing are one path-runtime transition. A replacement path starts at its conservative floor and does not inherit the old path's learned PMTU. Applying a new path generation must atomically update:

```text
path generation
packetization/datagram limit
pacer datagram size and token state
telemetry sample baseline
```

If any component cannot accept the new size, the replacement is not `Ready` and the active path remains unchanged. A successful downgrade follows the existing lowlat policy: video may be discarded and re-keyframed, while reliable control is retained or the transition fails closed.

For portable `PeerSession`, the path runtime may initially have only the transport-safe datagram floor and bounded sender pacing. It must still reset its path-local state on generation change; a backend that has no PMTU discovery reports `Unavailable` rather than reusing a previous path's value.

## Automatic watchdog fixture

The current explicit `--pmtu-recover` fixture remains as a fast deterministic recovery-mechanics test. A second fixture mode proves the real watchdog:

```text
discover 1472 on a 1500-byte veth
lower both veth interfaces to 1300
continue sending without a recovery marker
wait for Health::Undeliverable
invoke the production recovery decision once
assert 1229 fallback and post-recovery traffic
restore MTU 1500
request a fresh search
assert 1472 is rediscovered
```

The slow watchdog mode uses a longer fixture timeout derived from the actual `DELIVERY_DEADLINE_MS`. It records a single recovery milestone and fails if the watchdog invokes recovery more than once for the same path generation. The test must continue to exchange connectivity/ACK traffic so an idle-session liveness timeout cannot masquerade as the delivery watchdog.

## Alpine/musl validation

GitHub CI keeps the normal job on Ubuntu/glibc and adds a separate job that runs Docker on the Ubuntu-hosted runner:

```text
actions/checkout on ubuntu-latest
        │
        └── docker run --rm pinned-rust-alpine-image
              ├── build-base / musl C toolchain
              ├── lowlat-common tests
              ├── lowlat-core tests
              ├── lowlat-net tests
              ├── C ABI consumer compile
              └── C++ ABI consumer compile
```

The image tag/digest and Rust toolchain are pinned. The container command mounts only the checked-out workspace and uses the repository lockfile. The job avoids `container:` job mode so JavaScript Actions continue to run on the glibc host; only the compilation/test commands execute inside Alpine/musl.

The musl job is a required input to `CI gate`. It specifically protects the libc-dependent syscall casts and C ABI layout checks that were discovered in the Apple Linux environment.

## Migration acceptance

The acceptance harness must exercise one logical session through three committed generations:

```text
generation N     direct UDP active
generation N+1   TURN/relay path active
generation N+2   direct UDP active again
```

For each transition it must verify:

- the original cipher/session remains usable;
- frame identifiers and `FrameAck` processing continue across the switch;
- no application data is sent on a replacement before commit;
- the old path becomes receive-only and is retired within the grace period;
- a failed prepare leaves the active path unchanged;
- PMTU and pacing reset to the new path's baseline and do not reuse samples from the previous generation;
- the relay path uses the correct framing-specific datagram ceiling;
- the direct return starts a new PMTU search and can rediscover its larger direct limit;
- a commit failure exercises bounded rollback or a typed terminal outcome without leaking sockets, tasks, or relay registrations.

The first implementation target is direct↔opaque-relay migration because OpenStream owns that lifecycle. A separate ICE/TURN acceptance test may pass only when the current `webrtc-ice` API can satisfy the same two-phase contract. Otherwise it records the typed unsupported result and leaves external coturn migration as an open release gate.

## Error handling and resource limits

- Every migration attempt has one absolute deadline and bounded candidate/control queues.
- Only one replacement is prepared at a time per `PeerSession`.
- A failed attempt closes its replacement socket/agent and releases relay registration resources.
- Old-path drain and rollback deadlines are finite.
- Generation, token, candidate, and path-control fields are range-checked before allocation or socket work.
- Unknown path-control versions, invalid generations, mismatched probes, and stale commit acknowledgements are ignored or rejected without changing the active path.
- A migration cannot bypass authorization, capability negotiation, replay protection, or normal frame/control size limits.
- Teardown closes the replacement and old path exactly once and leaves no task holding the signaling endpoint.

## Testing requirements

### Unit and integration tests

The implementation must add deterministic tests for:

- generation allocation and reset boundaries;
- prepare failure leaving the active path unchanged;
- exact authenticated replacement probe/ack;
- commit acknowledgement and old-path retirement;
- bounded rollback after replacement failure;
- duplicate, stale, reordered, and wrong-generation path-control messages;
- one cipher/replay domain across old and new paths;
- no application data before commit;
- per-generation counter baselines and no cross-generation rate samples;
- adapter frame ACK behavior across a generation change;
- watchdog recovery occurring once;
- Alpine/musl C and C++ ABI consumers.

### Real Linux tests

Using Apple's `container machine` on macOS, run the existing seven-topology namespace matrix plus the slow watchdog fixture. The fixture must be skipped with a clear reason when the Linux container lacks the required namespace privileges; it must not silently report a pass without running.

### Migration tests

The migration harness must include direct↔opaque-relay↔direct when a self-hosted relay is available. It must separately run the unsupported-ICE migration path and assert the typed result if the dependency boundary cannot provide a safe restart. A reconnect that creates a new cipher/session is not an acceptance pass.

## Documentation and release notes

Update the implementation plan, architecture, build/testing documentation, NAT matrix, and changelog with:

- the path-generation and two-phase handoff contract;
- the distinction between OpenStream-owned opaque relay migration and ICE-owned restart;
- the exact musl CI command/image pin;
- the slow automatic watchdog fixture command and its expected evidence;
- the telemetry categories and unavailable lowlat-only fields;
- any typed ICE migration limitation discovered during implementation.

## Non-goals and explicit deferrals

- No BUD or Parsec wire compatibility.
- No `webrtc-ice` 0.20 upgrade.
- No native macOS or Windows media pipeline in this phase.
- No fabricated packet loss, packet ACK, or retransmission metrics for `PeerSession`.
- No indefinite dual-path sending.
- No silent reconnect presented as migration.
- No external coturn success claim without a real allocation and bidirectional peer-traffic proof.

## References

- [RFC 8445 — Interactive Connectivity Establishment](https://www.rfc-editor.org/rfc/rfc8445.html)
- [RFC 8656 — TURN extensions](https://www.rfc-editor.org/rfc/rfc8656.html)
- [RFC 8899 — Datagram PLPMTUD](https://www.rfc-editor.org/rfc/rfc8899.html)
- [GitHub Actions jobs in containers](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)
