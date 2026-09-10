# Shared Path Controller and Portable Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the generation-aware portable telemetry boundary, a two-phase direct/opaque-relay path controller, real automatic PMTU-watchdog coverage, and a required pinned Alpine/musl CI gate while preserving one OpenStream cryptographic session across every path switch.

**Architecture:** Keep `lowlat-core`/`lowlat-net` and portable `PeerSession` as separate transport implementations. Put the shared path vocabulary and local transport snapshots in `openstream-transport`; put frame-feedback policy in `openstream-media`; put the path lifecycle and migration choreography in `openstream-client-core`. `PeerSession` owns exactly one `CipherSession`; a `PeerPath` owns only a socket/ICE connection and generation-local state. OpenStream owns direct and opaque-relay migration. The ICE backend remains authoritative for ICE restart and returns a typed unsupported result when `webrtc-ice 0.17.2` cannot retain the old `Conn` during replacement preparation.

**Tech Stack:** Rust 1.85 / edition 2024, Tokio, AES-256-GCM OpenStream packets, existing `UdpTransport`, existing self-hosted UDP relay, shell-based Linux namespace fixtures, Apple `container machine` for persistent Linux execution on macOS, GitHub Ubuntu runners with Docker and a pinned `rust:1.85.0-alpine3.21` image, C11/C++17 ABI consumers, and deterministic unit/integration tests. No new cryptography, no BUD compatibility layer, no `webrtc-ice` upgrade, and no new third-party runtime dependency unless an implementation step proves an existing dependency cannot express the required behavior.

**Spec:** [approved shared-path-controller design](../specs/2026-09-09-shared-path-controller-design.md), reviewed at commit `636d4f24bd58aee5dcf7ca557a6a8dc873479226`.

## Global Constraints

- Start from `636d4f24` with a clean tree. Do not rewrite or reset user changes.
- Every task follows RED → GREEN → refactor: add the smallest failing test or executable assertion, run the narrow command and record the failure, implement the smallest change, rerun the same command, then run the task’s broader checks.
- Commit each task independently with the exact commit message specified below. Do not combine unrelated task commits.
- Do not change the existing OpenStream wire packet format, the lowlat wire format, `MAX_DATAGRAM`, the 64-counter replay window, or the default single-path behavior unless a task explicitly names the change.
- One `CipherSession`, one transmit counter space, one receive replay window, one reliable-control logical sequence space, one frame-ID space, one negotiated capability set, and one session identity survive migration. A path generation is a transport epoch only.
- The host is the only generation allocator and migration initiator in v1. Client requests are bounded and deduplicated; a client never allocates a competing generation or sends `PATH_PREPARE`.
- No application packet is sent on a replacement before it is committed. Replacement traffic is limited to bounded authenticated path probes and path-control messages.
- `PATH_COMMIT` is sent on the old active path; the responder commits before sending `PATH_COMMIT_ACK` on the replacement path. A missing ACK never causes silent rollback after responder commit. The host returns typed `CommitUnconfirmed` at the absolute deadline.
- Old-path receive/drain, rollback, candidate queues, retry counts, and migration deadlines are finite. There is no indefinite dual-send mode and no reconnect presented as migration.
- Path-local rate samples carry their generation. No counter baseline or EWMA sample crosses a generation boundary. Local send/receive rate is diagnostic/path pressure, never encoder capacity by itself.
- End-to-end `FrameAck` state and pending frame IDs survive generation changes. Reliable logical control retransmits with a fresh outer cipher counter on the new path.
- A PMTU/pacer change is atomic within a path runtime. A downgrade preserves reliable control, drops only safely discardable video, requests a fresh IDR, and never silently discards reliable application data.
- Relay tickets, bearer tokens, TURN credentials, addresses, keys, and path tokens never enter diagnostic snapshots or ordinary logs. Any secret-bearing helper has a redacted `Debug` implementation.
- Stay on `webrtc-ice = 0.17.2`. Do not perform the upstream 0.20 Sans-I/O migration in this phase.
- Before claiming completion, run the required workspace format/lint/test/build checks, the fuzz-harness compile, `cargo deny`, the C/C++ ABI checks, the real namespace fixtures when Linux privileges exist, and the direct↔opaque-relay↔direct acceptance harness.

The normal local verification commands, run from the repository root unless a command changes directory, are:

```sh
cd engine/lowlat
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo build --workspace --release --locked
cargo deny check
```

---

## Repository File Map

Use these existing boundaries and keep new code at the narrowest owner:

| Area | Files | Planned responsibility |
| --- | --- | --- |
| Automatic watchdog | `engine/lowlat/crates/sim/src/bin/shell-punch.rs`, `engine/lowlat/scripts/netns-fixtures.sh`, `engine/lowlat/crates/sim/tests/netns.rs` | Real `Health::Undeliverable` recovery fixture and one-shot assertion |
| musl gate | `.github/workflows/ci.yml`, new `engine/lowlat/scripts/alpine-musl-ci.sh` | Pinned Alpine/Docker test command and required `CI gate` input |
| Portable transport telemetry | `engine/lowlat/crates/transport/src/lib.rs`, `engine/lowlat/crates/transport/Cargo.toml`, `engine/lowlat/crates/client-core/src/lib.rs` | Socket counters, generation-safe snapshot, path vocabulary |
| Portable frame adapter | `engine/lowlat/crates/media/src/telemetry.rs`, `engine/lowlat/crates/media/src/adaptive.rs`, `engine/lowlat/crates/media/src/lib.rs`, `engine/lowlat/crates/ffmpeg-host/src/main.rs`, `engine/lowlat/crates/media/Cargo.toml` | One `PeerTelemetryAdapter` and one `FrameAck` path |
| Path lifecycle | new `engine/lowlat/crates/client-core/src/path.rs`, `engine/lowlat/crates/client-core/src/lib.rs` | `PeerPath`, generation, state, snapshots, no behavior change first |
| Path-control wire codec | new `engine/lowlat/crates/protocol/src/path_control.rs`, `engine/lowlat/crates/protocol/src/lib.rs` | Bounded versioned `PATH_*` records and exact validation |
| Direct/relay migration | `engine/lowlat/crates/client-core/src/path.rs`, `engine/lowlat/crates/client-core/src/lib.rs`, `engine/lowlat/crates/transport/src/lib.rs` | Replacement preparation, proof, commit, drain, cleanup |
| Relay cleanup | `engine/lowlat/crates/protocol/src/lib.rs`, `engine/lowlat/crates/transport/src/lib.rs`, `engine/lowlat/crates/signal-server/src/main.rs` | Explicit role-scoped relay unregister and idempotent cleanup |
| Acceptance peers | `engine/lowlat/crates/reference-peer/src/main.rs`, new `scripts/path-migration-smoke.sh`, new `scripts/ice-migration-capability.sh` | Three committed generations and typed ICE result |
| Documentation | `docs/BUILD.md`, `docs/NAT_MATRIX.md`, `docs/IMPLEMENTATION_PLAN.md`, `engine/lowlat/docs/changelog.md` | Commands, status, invariants, and release notes |

## Preflight

- [ ] Confirm the baseline before creating implementation commits:

  ```sh
  git rev-parse --verify HEAD
  git status --short
  git show --stat --oneline --decorate --no-renames HEAD
  ```

  Expected baseline is full SHA `636d4f24bd58aee5dcf7ca557a6a8dc873479226`; the only intentional worktree change after this plan is created is this plan file.

- [ ] Run the existing narrow baseline checks before touching production code:

  ```sh
  cd engine/lowlat
  cargo test --locked -p lowlat-sim -p lowlat-net -p openstream-client-core -p openstream-media -p openstream-transport -- --test-threads=1
  bash -n scripts/netns-fixtures.sh
  ```

  Expected result: existing tests pass; namespace tests skip with a reason if the current host lacks Linux namespace privileges.

---

## Task 1: Add the automatic real-watchdog namespace fixture

**Files:** `engine/lowlat/crates/sim/src/bin/shell-punch.rs`, `engine/lowlat/scripts/netns-fixtures.sh`, `engine/lowlat/crates/sim/tests/netns.rs`

**Commit:** `test: add automatic PMTU watchdog namespace fixture`

The existing `--pmtu-recover` marker remains the fast recovery-mechanics fixture. Add a separate `--pmtu-watchdog` mode that never reads a recovery marker and invokes the same production `Shell::recover_path_black_hole(now_ms)` hook only after the endpoint reports `Health::Undeliverable`.

- [ ] RED: add the pure one-shot decision test in the Linux module of `shell-punch.rs` before adding the helper:

  ```rust
  #[test]
  fn watchdog_recovery_requires_undeliverable_and_is_one_shot() {
      assert!(!watchdog_recovery_due(Health::Alive, false));
      assert!(!watchdog_recovery_due(Health::Stalled, false));
      assert!(watchdog_recovery_due(Health::Undeliverable, false));
      assert!(!watchdog_recovery_due(Health::Undeliverable, true));
  }
  ```

  Run:

  ```sh
  cd engine/lowlat
  cargo test --locked -p lowlat-sim watchdog_recovery_requires_undeliverable_and_is_one_shot
  ```

  Expected RED result: compilation fails because `watchdog_recovery_due` and the required `Health` import do not yet exist.

- [ ] GREEN: import `lowlat_core::session::Health`, add `fn watchdog_recovery_due(health: Health, already_recovered: bool) -> bool`, parse the presence-only `--pmtu-watchdog` flag, and add a `watchdog_recovered` boolean. Evaluate `shell.endpoint().health(now_ms)` after each `Shell::turn`; when the helper returns true, call `shell.recover_path_black_hole(now_ms)` exactly once and print/flush:

  ```text
  pmtu-watchdog-recovered old=<old> new=<new> dropped=<count>
  ```

  Reuse the existing `PathMtuRecovery::{Recovered, Blocked, NotConfigured, Unusable}` handling. Include watchdog mode in the post-recovery settle-window selection so the process remains alive long enough to prove new traffic. Keep explicit marker handling unchanged.

- [ ] GREEN: extend `start_mtu_peer` with an optional `watchdog` mode argument and add `topology_mtu_watchdog()` in `netns-fixtures.sh`. The topology must:

  1. Create the existing `llha`/`llhb` veth pair at MTU 1500.
  2. Start both peers with `--stream --pmtu-watchdog`, no `--pmtu-recover` path and no recovery marker.
  3. Wait for both initial `pmtu-ready datagram=1472` milestones.
  4. Lower both veth interfaces to MTU 1300 and continue the stream without touching a recovery file.
  5. Wait using a watchdog-specific wait budget of at least 30 seconds, derived from the current 15-second `DELIVERY_DEADLINE_MS` plus settle time.
  6. Require exactly one `pmtu-watchdog-recovered old=1472 new=1229` line per endpoint.
  7. Require nonzero `sent_after_recovery` and `after_recovery` counts.
  8. Restore both links to MTU 1500, use the existing explicit raise request only for upward-search control, and require `pmtu-ready-again datagram=1472` on both endpoints.

  Add an optional wait-attempt parameter to `wait_for_file` and `wait_for_line` rather than changing the fast fixture’s 12-second behavior. Add `mtu-watchdog` to the explicit topology selector, but do not add it to the default seven-topology `ALL` list so ordinary matrix runs retain their existing duration.

- [ ] GREEN: add a Linux integration test in `crates/sim/tests/netns.rs` that runs the script with the explicit `mtu-watchdog` argument using `PUNCH` and `PEER` from `env!`. It must return a clear `skipped:` result for non-root/non-Linux environments and fail on a real fixture failure.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p lowlat-sim watchdog_recovery
  cargo test --locked -p lowlat-sim --test netns -- --nocapture
  bash -n scripts/netns-fixtures.sh
  CARGO_TARGET_DIR=/tmp/openstream-lowlat-target cargo build --locked --release -p lowlat-sim --bin punch --bin shell-punch
  ```

  On macOS with the prepared Apple Linux machine, run the real fixture from the persistent Linux environment:

  ```sh
  container machine list
  container machine run -n openstream-linux-ci --root -- bash -lc '
    cd /Users/ankitpipalia/Documents/RE/openersec/engine/lowlat
    PUNCH=/tmp/openstream-lowlat-target/release/punch \
    PEER=/tmp/openstream-lowlat-target/release/shell-punch \
    scripts/netns-fixtures.sh mtu-watchdog
  '
  ```

  Expected evidence: `PASS mtu-watchdog`, `netns fixtures: 1 passed, 0 failed`, one recovery line per endpoint, and no marker file was read by the endpoint.

---

## Task 2: Add the pinned Alpine/musl required CI job

**Files:** new `engine/lowlat/scripts/alpine-musl-ci.sh`, `.github/workflows/ci.yml`

**Commit:** `ci: require pinned Alpine musl validation`

Use the Ubuntu-hosted runner for Actions and run only the compilation/test command inside Docker. Pin the amd64 image to:

```text
docker.io/library/rust:1.85.0-alpine3.21@sha256:715f7a1b6b3a538f7b55c0be7db7e5bb0461fe9ea1d0004a481ab0c5d59542ad
```

Do not use a job-level `container: alpine` because JavaScript Actions require the host’s glibc-compatible runtime.

- [ ] RED: add the workflow job skeleton and the executable check before creating the helper:

  ```sh
  cd engine/lowlat
  test -x scripts/alpine-musl-ci.sh
  ```

  Expected RED result: the helper does not exist.

- [ ] GREEN: add `engine/lowlat/scripts/alpine-musl-ci.sh` with `#!/bin/sh` and `set -eu`. The script must:

  1. Install only `build-base` with `apk add --no-cache build-base`.
  2. Assert `rustc -V` reports `1.85.0`.
  3. Set `CARGO_TARGET_DIR=/tmp/openstream-musl-target`.
  4. Run `cargo test --locked -p lowlat-common -p lowlat-core -p lowlat-net -- --test-threads=1`.
  5. Compile `crates/host/tests/c/alone.c` as C11 and C++17 with `-Wall -Wextra -Werror -I include`.
  6. Print `Alpine/musl validation passed` only after all commands succeed.

  The C and C++ output objects must be written under `/tmp`, not into the checked-out tree.

- [ ] GREEN: add an `alpine-musl` job to `.github/workflows/ci.yml` with `runs-on: ubuntu-latest`, `actions/checkout@v7`, the exact image digest above, `--platform=linux/amd64`, a read-write `/workspace` bind mount, `-w /workspace/engine/lowlat`, and the command `/workspace/engine/lowlat/scripts/alpine-musl-ci.sh`. Add `sh -n scripts/alpine-musl-ci.sh` to the existing `check` job.

- [ ] GREEN: add `alpine-musl` to `ci-gate.needs`, export `ALPINE_MUSL: ${{ needs.alpine-musl.result }}`, and include it in the result loop. A skipped, cancelled, or failed musl job must fail the gate.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  sh -n scripts/alpine-musl-ci.sh
  cargo fmt --all -- --check
  ```

  On a machine with Docker, run the exact CI command from the repository root:

  ```sh
  docker run --rm --platform linux/amd64 \
    --mount type=bind,src="$PWD",dst=/workspace \
    -w /workspace/engine/lowlat \
    docker.io/library/rust:1.85.0-alpine3.21@sha256:715f7a1b6b3a538f7b55c0be7db7e5bb0461fe9ea1d0004a481ab0c5d59542ad \
    /workspace/engine/lowlat/scripts/alpine-musl-ci.sh
  ```

  Expected result: the lowlat packages, C consumer, and C++ consumer compile/test under musl and the helper prints its success line. The first GitHub run must be checked by SHA; do not call the repository green until `CI gate` succeeds.

---

## Task 3: Add portable transport telemetry and `PeerTelemetryAdapter`

**Files:** `engine/lowlat/crates/transport/src/lib.rs`, `engine/lowlat/crates/transport/Cargo.toml`, `engine/lowlat/crates/client-core/src/lib.rs`, new `engine/lowlat/crates/media/src/telemetry.rs`, `engine/lowlat/crates/media/src/lib.rs`, `engine/lowlat/crates/media/src/adaptive.rs`, `engine/lowlat/crates/media/Cargo.toml`, `engine/lowlat/crates/ffmpeg-host/src/main.rs`

**Commit:** `feat: unify portable path telemetry and frame feedback`

Keep `SessionStats` unchanged. Add a new path-local DTO to `openstream-transport` so `openstream-media` can consume it without creating a `client-core` ↔ `media` dependency cycle.

- [ ] RED: add tests for the new transport counters, adapter generation behavior, and rate-only isolation before adding the types. The tests must name these contracts:

  - `udp_counters_count_only_completed_socket_io` sends one authenticated datagram through two connected `UdpTransport` values and expects one sent packet/wire-byte increment and one received packet/wire-byte increment; relay registration is not included.
  - `generation_change_preserves_pending_frames_but_resets_path_baseline` records a frame, observes generation 1, observes generation 2, and expects the pending frame and current bitrate to remain while the previous local rate baseline is discarded.
  - `local_rate_samples_do_not_change_adaptive_bitrate` records a healthy frame ACK, applies only local path samples at 1 Mbps and 100 Mbps, ticks the adapter, and expects the bitrate and decision state to remain unchanged.

  Run:

  ```sh
  cd engine/lowlat
  cargo test --locked -p openstream-transport udp_counters_count_only_completed_socket_io
  cargo test --locked -p openstream-media generation_change_preserves_pending_frames_but_resets_path_baseline
  cargo test --locked -p openstream-media local_rate_samples_do_not_change_adaptive_bitrate
  ```

  Expected RED result: the types and tests do not compile yet.

- [ ] GREEN: add these bounded, `Debug`/`Clone`/`Copy`/`Serialize`/`Deserialize`-appropriate types in `openstream-transport`:

  ```rust
  pub const FIRST_PATH_GENERATION: u64 = 1;

  pub type PathGeneration = u64;

  pub enum TransportPathKind {
      DirectUdp,
      OpaqueRelay,
      Ice,
  }

  pub enum PathState {
      Preparing,
      Ready,
      CommitPending,
      Active,
      Draining,
      Retired,
      Failed,
      Closed,
  }

  pub enum PathMtuState {
      Base,
      Searching,
      SearchComplete,
      Error,
      Unavailable,
  }

  pub struct TransportSample {
      pub path_generation: PathGeneration,
      pub sent_packets: u64,
      pub sent_wire_bytes: u64,
      pub received_packets: u64,
      pub received_wire_bytes: u64,
      pub sample_interval_ms: u64,
      pub send_rate_mbps: f64,
      pub receive_rate_mbps: f64,
  }

  pub struct PeerTransportSnapshot {
      pub path: TransportPathKind,
      pub path_generation: PathGeneration,
      pub state: PathState,
      pub path_age_ms: u64,
      pub datagram_size: Option<usize>,
      pub path_mtu_state: PathMtuState,
      pub sample: Option<TransportSample>,
  }
  ```

  Use decimal Mbps (`bits / 1_000_000.0`). The snapshot contains no address, token, key, credential, or relay-ticket field.

- [ ] GREEN: add a private `TransportTelemetry` accumulator to `UdpTransport` with cumulative counters and a generation setter. Count bytes returned by the connected UDP socket after a successful `send`/`recv_from` operation. Refactor the existing encrypted wrappers to use bounded `send_datagram`/`recv_datagram` helpers so migration can later select an ingress path without duplicating socket logic. Keep registration/setup traffic in separate counters or exclude it consistently; exclude it from `TransportSample`.

- [ ] GREEN: add `PeerSession::transport_snapshot(&mut self, now: Instant) -> PeerTransportSnapshot` and `PeerSession::path_generation() -> PathGeneration`. Track a generation-local baseline for direct and ICE paths. ICE exposes only values observable at the `Conn` boundary; unknown PMTU/rate values are `None` or `PathMtuState::Unavailable`, never fabricated zero loss/capacity. Preserve the meaning and serialized shape of `SessionStats`.

- [ ] GREEN: add `openstream-media/src/telemetry.rs` with:

  ```rust
  pub struct PeerTelemetryAdapter { /* bounded frame/path state */ }

  impl PeerTelemetryAdapter {
      pub fn new(adaptive: AdaptiveBitrate, generation: PathGeneration, now_ms: u64) -> Self;
      pub fn observe_path(&mut self, snapshot: &PeerTransportSnapshot, now_ms: u64);
      pub fn frame_sent(&mut self, frame_id: u32, encoded_bytes: usize, now_ms: u64);
      pub fn frame_ack(&mut self, ack: FrameAck, now_ms: u64);
      pub fn accept_frame_ack_payload(&mut self, payload: &[u8], now_ms: u64) -> bool;
      pub fn tick(&mut self, now_ms: u64) -> Option<BitrateDecision>;
      pub fn bitrate_mbps(&self) -> f64;
      pub fn pending_frames(&self) -> usize;
      pub fn snapshot(&self) -> PeerTelemetrySnapshot;
  }
  ```

  The adapter owns every call to `AdaptiveBitrate::frame_sent`, `frame_acknowledged_with_loss`, and `tick`. Bound pending encoded-byte/frame metadata to `MAX_PENDING_FRAMES`; cumulative ACKs remove older entries using the existing sequence semantics. `observe_path` resets only path-local sample baselines on a generation change, retains pending frames, retains the current bitrate, and blocks ramp-up for one `RAMP_INTERVAL_MS` healthy interval. A lower/stale generation is ignored without changing the active snapshot.

- [ ] GREEN: add `AdaptiveBitrate::suppress_ramp_until(now_ms)` or an equivalent private hook used only by the adapter. Do not feed `send_rate_mbps` or `receive_rate_mbps` into any bitrate decision.

- [ ] GREEN: refactor `ffmpeg-host/src/main.rs` to replace the direct `AdaptiveBitrate` variable with `PeerTelemetryAdapter`. Call `frame_sent` after `send_access_unit` succeeds, call `observe_path` from the existing 100 ms control tick, call `tick` once per control tick, and use the adapter’s `BitrateDecision` for the existing bounded FFmpeg restart policy. Replace the two independent `FrameAck::decode`/adaptive branches with one `accept_frame_ack_payload` call after reliable-control delivery and one call for raw control. Preserve the legacy `openstream/frame-ack` marker as a non-metric compatibility payload.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-transport -p openstream-media -p openstream-client-core -p openstream-ffmpeg-host -- --test-threads=1
  cargo clippy --locked -p openstream-transport -p openstream-media -p openstream-client-core -p openstream-ffmpeg-host --all-targets --all-features -- -D warnings
  ```

  Expected result: transport counters are local observations, adapter tests pass, the two FFmpeg ACK branches are gone, and an isolated path-rate change cannot alter the encoder target.

---

## Task 4: Introduce `PeerPath` and generation lifecycle with no migration behavior

**Files:** new `engine/lowlat/crates/client-core/src/path.rs`, `engine/lowlat/crates/client-core/src/lib.rs`

**Commit:** `refactor: introduce generation-scoped PeerPath runtime`

Refactor the existing private `DataPath` into a path runtime without changing establishment, send, receive, keepalive, or `ConnectionPath` behavior. This is deliberately a no-behavior-change commit.

- [ ] RED: add `path.rs` unit tests for `PathRuntime::initial_active`, `PathRuntime::snapshot`, and `GenerationAllocator`. Assert that the initial generation is 1, the initial state is `Active`, a reserved replacement is `Preparing`, and abandoning a reservation leaves the active generation unchanged. Run the new test name before adding the module; it must fail to compile.

- [ ] GREEN: add the private types:

  ```rust
  pub(crate) struct PeerPath {
      backend: PeerPathBackend,
      generation: PathGeneration,
      state: PathState,
      started_at: std::time::Instant,
      datagram_size: Option<usize>,
      path_mtu_state: PathMtuState,
  }

  pub(crate) enum PeerPathBackend {
      Direct { transport: Box<UdpTransport>, candidate: CandidateKind },
      Ice(IcePath),
  }

  pub(crate) struct PathRuntime {
      pub active: PeerPath,
      pub prepared: Option<PeerPath>,
      pub next_generation: PathGeneration,
  }
  ```

  Add methods `active()`, `active_mut()`, `reserve_generation()`, `snapshot(now)`, `mark_ready()`, `mark_commit_pending()`, `activate_prepared()`, `begin_drain()`, `retire_old()`, and `close_all()`. Generation allocation is host-controlled in the next task; this commit only supplies the state container and monotonic allocator.

- [ ] GREEN: replace `PeerSession.transport: DataPath` with `PeerSession.path: PathRuntime`. Initialize all existing establishment return paths as generation 1 / `Active`. Route current `send`, `recv`, `maintain_liveness`, `release_upnp`, `connection_path`, and `probe_path` through the active backend without changing their external signatures or output.

- [ ] GREEN: ensure `PeerSession`’s custom `Debug` output or field layout never prints stored relay tickets when the migration fields arrive in later tasks. Keep `IcePath`’s agent lifetime unchanged.

- [ ] Verify the no-behavior-change contract:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-client-core -p openstream-transport -p openstream-reference-peer -- --test-threads=1
  cargo test --workspace --all-features --locked -- --test-threads=1
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  ```

  Expected result: existing direct, relay, ICE, capability, and reference-peer tests behave exactly as before; no migration method is exposed or invoked yet.

---

## Task 5: Add versioned path-control records and the capability gate

**Files:** new `engine/lowlat/crates/protocol/src/path_control.rs`, `engine/lowlat/crates/protocol/src/lib.rs`, `engine/lowlat/crates/client-core/src/lib.rs`

**Commit:** `feat: add versioned path migration control protocol`

Carry internal path-control records as authenticated `Kind::Control` payloads using the existing cipher. Do not route them through application input, clipboard, or the ordinary reliable-control payload vocabulary.

- [ ] RED: add codec tests before the module exists:

  - round-trip every record and every abort reason;
  - reject version 0/2, unknown record type, reserved bits, zero generation, zero token, truncated fields, oversized payload, invalid path kind, and invalid datagram size;
  - assert every encoded record is at most `MAX_PATH_CONTROL_BYTES = 64`;
  - assert duplicate encodings decode to equal records.

  Run:

  ```sh
  cd engine/lowlat
  cargo test --locked -p openstream-protocol path_control
  ```

  Expected RED result: the module and `PathControl` type are absent.

- [ ] GREEN: add `protocol::path_control` with fixed constants and bounded enums:

  ```rust
  pub const VERSION: u8 = 1;
  pub const MAX_PATH_CONTROL_BYTES: usize = 64;
  pub const PATH_TOKEN_BYTES: usize = 16;

  pub enum PathKind { DirectUdp, OpaqueRelay, Ice }

  pub enum AbortReason {
      Unsupported,
      Timeout,
      CandidateUnavailable,
      ProbeFailed,
      PmtuUnavailable,
      ResourceLimit,
      CommitUnconfirmed,
  }

  pub enum PathControl {
      Request { request_id: u32, kind: PathKind },
      Prepare { generation: u64, kind: PathKind, token: [u8; PATH_TOKEN_BYTES] },
      Probe { generation: u64, token: [u8; PATH_TOKEN_BYTES] },
      ProbeAck { generation: u64, token: [u8; PATH_TOKEN_BYTES] },
      Ready { generation: u64, token: [u8; PATH_TOKEN_BYTES], datagram_size: u16 },
      Commit { generation: u64, token: [u8; PATH_TOKEN_BYTES] },
      CommitAck { generation: u64, token: [u8; PATH_TOKEN_BYTES] },
      Abort { generation: u64, reason: AbortReason },
  }

  impl PathControl {
      pub fn encode(&self) -> Result<Vec<u8>, Error>;
      pub fn decode(bytes: &[u8]) -> Result<Self, Error>;
  }
  ```

  Validate all lengths before slicing, reject generation 0 and all-zero tokens, keep reserved bytes zero, and do not put bearer credentials or addresses in the records. `PATH_COMMIT` includes the token even though its short-form name is commonly described as generation-only; exact token matching is required for idempotence.

- [ ] GREEN: add `#[serde(default)] pub path_migration: bool` to `Capabilities`, include `path_migration` in `NegotiatedCapabilities`, and negotiate it with logical AND. Keep `Capabilities::host_default()` and `client_default()` false. Add a small builder/helper used by migration acceptance peers to opt in explicitly without changing ordinary applications.

- [ ] GREEN: add a capability compatibility test that decodes a pre-field capability JSON document and expects `path_migration == false`, and a negotiation test that expects false when either peer is old/disabled and true only when both explicitly advertise true.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-protocol -p openstream-client-core -- --test-threads=1
  cargo clippy --locked -p openstream-protocol -p openstream-client-core --all-targets --all-features -- -D warnings
  ```

  Expected result: ordinary peers still establish with single-path behavior; path-control records are bounded/authenticated data ready for the lifecycle task, but no migration begins just because a field exists.

---

## Task 6: Implement host-authoritative direct↔opaque-relay prepare/commit migration

**Files:** `engine/lowlat/crates/client-core/src/path.rs`, `engine/lowlat/crates/client-core/src/lib.rs`, `engine/lowlat/crates/transport/src/lib.rs`, `engine/lowlat/crates/protocol/src/path_control.rs`

**Commit:** `feat: implement two-phase direct opaque-relay migration`

This is the first behavior-changing task. Implement direct/opaque-relay only; ICE returns the typed result in Task 8. Do not create a second cipher. Use a new UDP socket for every replacement so the old path can remain receive-only during the handoff.

- [ ] RED: add state-machine tests against a recording in-memory path driver before wiring real sockets. The driver records `(path_slot, kind, channel, payload)` and can drop/reorder selected records. Add tests named:

  - `application_sends_are_blocked_while_commit_is_pending`;
  - `host_commit_uses_old_path_and_client_ack_uses_new_path`;
  - `client_commit_is_durable_before_ack_and_duplicate_commit_repeats_ack`;
  - `wrong_generation_or_token_does_not_change_active_path`;
  - `client_request_does_not_allocate_a_generation`;
  - `duplicate_requests_coalesce_to_one_preparation`.

  Run:

  ```sh
  cd engine/lowlat
  cargo test --locked -p openstream-client-core path_migration
  ```

  Expected RED result: the migration state machine and path-driver test seam are not present.

- [ ] GREEN: add the internal migration types and exact constants in `client-core/src/path.rs`:

  ```rust
  pub enum MigrationTarget { DirectUdp, OpaqueRelay, Ice }

  pub enum MigrationState {
      Idle,
      Preparing,
      Ready,
      CommitPending,
      Active,
      CommitUnconfirmed,
      Failed,
  }

  pub struct MigrationToken([u8; PATH_TOKEN_BYTES]);

  pub struct MigrationReport {
      pub previous_generation: PathGeneration,
      pub active_generation: PathGeneration,
      pub previous_kind: TransportPathKind,
      pub active_kind: TransportPathKind,
  }

  pub enum PathMigrationError {
      CapabilityNotNegotiated,
      MigrationAlreadyPending,
      HostMigrationRequired,
      UnsupportedIceRestart,
      CommitUnconfirmed,
      PathUnavailable,
  }
  ```

  Use `getrandom` for the token; reject an all-zero token. Define finite timing constants: `MIN_DRAIN_GRACE = 250 ms`, `MAX_DRAIN_GRACE = 2 s`, `COMMIT_RETRY = 250 ms`, and `MIGRATION_DEADLINE = 5 s`. Derive the drain deadline from the old path RTT when available and clamp it to the two explicit limits.

- [ ] GREEN: add these `PeerSession` APIs:

  ```rust
  pub async fn migrate_to(&mut self, target: MigrationTarget) -> Result<MigrationReport, Error>;
  pub fn migration_state(&self) -> MigrationState;
  pub fn path_snapshot(&mut self) -> PeerTransportSnapshot;
  ```

  Add `Error::PathMigration(PathMigrationError)` to the existing client-core error type. `migrate_to` must return `Error::PathMigration(PathMigrationError::CapabilityNotNegotiated)` unless both negotiated capabilities explicitly enable migration, `Error::PathMigration(PathMigrationError::MigrationAlreadyPending)` when a second attempt exists, `Error::PathMigration(PathMigrationError::HostMigrationRequired)` when called by a client, and `Error::PathMigration(PathMigrationError::PathUnavailable)` when the requested candidate/ticket is absent.

- [ ] GREEN: retain the initial candidate inventory and role-scoped relay configuration privately in `PeerSession` during establishment. Copy only `session_id`, the local role, validated candidate addresses, relay address, and a redacted-debug relay ticket wrapper. Never print the ticket. For a new direct socket, exchange one bounded authenticated signaling message per endpoint:

  ```json
  {"type":"path_candidate","generation":N,"token":"32-hex-bytes","kind":"direct_udp","ip":"...","port":P}
  ```

  Validate generation/token/kind/address with the existing candidate limits and `valid_peer_candidate`; reject duplicates and unexpected session messages. Opaque relay uses the pairing relay address and role-scoped ticket already issued by the signal server and does not expose those credentials in `PATH_PREPARE`.

- [ ] GREEN: implement replacement opening:

  1. Host reserves `active_generation + 1` and creates one 16-byte token. A client `PATH_REQUEST` is only a desired `MigrationTarget`; the host chooses the candidate and sends the prepare.
  2. Bind a replacement `UdpTransport` without changing the active socket. For direct, connect it to the exchanged candidate. For opaque relay, connect it to the pairing relay and call `register_relay` with the stored role-specific ticket.
  3. Send bounded encrypted `Probe` records on the replacement and answer only matching `Probe` records with `ProbeAck` on the same replacement. Require a matching authenticated response before `Ready`.
  4. Set replacement datagram size to its conservative safe value and `PathMtuState::Unavailable` for portable paths. Do not inherit the old path’s PMTU, pacer tokens, sample baseline, or path age.
  5. Send `PATH_READY` on the old active path. The record includes exact generation/token/datagram size.

- [ ] GREEN: implement the fixed commit choreography:

  1. Host sends/retries `PATH_COMMIT` on the old path and stops all application sends while `CommitPending`.
  2. Client validates exact generation/token, records N+1 as committed before any response, switches application sends to the replacement, marks the old path receive-only, and sends `PATH_COMMIT_ACK` on the replacement.
  3. Host accepts an ACK only when it is authenticated and observed on the replacement ingress slot with the exact pending generation/token. It then marks N+1 active, marks the old path draining, resets path-local telemetry/pacer/PMTU state atomically, and resumes application sends on the replacement.
  4. Duplicate commit on old or prepared-new is idempotent and repeats the ACK on the replacement. Duplicate ACK is harmless. Stale generation/token records are ignored/rejected without changing state.
  5. If the old path fails after `Ready`, retry the same commit on the prepared replacement. If the absolute deadline expires after responder commit may have happened, return typed `CommitUnconfirmed`; never reactivate the old path while claiming N+1 active.
  6. Retain old receive-only for the clamped drain grace, then close it and release its relay registration exactly once.

- [ ] GREEN: add bounded ingress routing. Refactor receive to retain the ingress slot internally, e.g. `ReceivedPacket { packet: Packet, ingress: PathSlot }`, while keeping `PeerSession::recv() -> Result<Packet, Error>` as the application-compatible wrapper. During preparation, application packets from the replacement are rejected/ignored; active-path application traffic remains allowed. During commit pending, both paths can receive control, but application sends are blocked. After activation, only active and bounded-draining ingress are accepted.

- [ ] GREEN: add a private `send_sealed_on(PathSlot, ...)` that seals with the one session cipher and writes only to the selected path. All outer counters therefore remain one monotonic domain even when old/new path sends interleave.

- [ ] Verify direct↔opaque behavior with the deterministic state-machine tests and existing live relay registration tests:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-client-core -p openstream-transport -p openstream-protocol -- --test-threads=1
  cargo clippy --locked -p openstream-client-core -p openstream-transport -p openstream-protocol --all-targets --all-features -- -D warnings
  ```

  Expected result: direct peers with migration disabled behave exactly as before; enabled peers prepare a replacement without application traffic, commit only after exact proof, and expose the correct generation/state snapshot.

---

## Task 7: Add failure, rollback, replay-window, and resource-cleanup coverage

**Files:** `engine/lowlat/crates/client-core/src/path.rs`, new `engine/lowlat/crates/client-core/tests/path_migration.rs`, `engine/lowlat/crates/protocol/src/lib.rs`, `engine/lowlat/crates/transport/src/lib.rs`, `engine/lowlat/crates/signal-server/src/main.rs`

**Commit:** `test: cover migration failure replay and cleanup semantics`

This task makes the distributed and security invariants executable rather than relying on the happy-path migration test.

- [ ] RED: add deterministic tests for each required failure mode before changing the implementation:

  - `prepare_failure_leaves_generation_path_and_bitrate_unchanged`;
  - `path_commit_ack_loss_enters_commit_unconfirmed_without_old_path_resumption`;
  - `rollback_is_allowed_only_before_responder_commit`;
  - `duplicate_commit_and_ack_are_idempotent`;
  - `stale_wrong_generation_and_wrong_token_are_ignored`;
  - `host_authority_serializes_simultaneous_client_requests`;
  - `no_application_data_is_emitted_before_commit`;
  - `old_path_is_receive_only_then_retired_once`;
  - `generation_samples_never_subtract_across_paths`;
  - `failed_replacement_closes_socket_and_releases_relay_registration`.

  Run:

  ```sh
  cd engine/lowlat
  cargo test --locked -p openstream-client-core --test path_migration
  ```

  Expected RED result: the tests expose the unimplemented failure injection/cleanup hooks.

- [ ] GREEN: add a deterministic `MigrationClock`/retry driver in the test module so commit retries, drain deadlines, and the five-second absolute deadline can be advanced without sleeping. Every test must assert the exact state, active generation, active path slot, and number of cleanup calls.

- [ ] GREEN: implement relay unregister as an idempotent role-scoped control record. Extend `protocol::relay` with `UNREGISTER`, `encode_unregister`, `decode_unregister`, `encode_unregister_ack`, and `is_unregister_ack`. Reuse the session ID, role, and relay ticket; the signal server clears the slot only when the source address and owner match. A stale/duplicate unregister returns the same ACK without clearing a newer registration.

- [ ] GREEN: add `UdpTransport::unregister_relay(&self, session_id, role, ticket)` and a `RelayRegistration`/cleanup guard in the path runtime. Ensure failed preparation, old-path retirement, `CommitUnconfirmed`, and `PeerSession` drop invoke cleanup at most once. Do not wait for relay idle reaping as the normal migration cleanup path.

- [ ] GREEN: add the replay-window test to `openstream-protocol` using one sender and one receiver `Session`: seal an old best-effort video packet, seal at least 65 newer control/path records, deliver the newer record first, then deliver the old record and assert `Session::open` returns `AuthenticationFailed`. In the `openstream-client-core` migration test, separately feed a `ReliableControl` logical frame with the same inner sequence through a retransmitted new outer record and assert one logical delivery, not zero and not two.

- [ ] GREEN: add tests for a frame ACK sent before migration and received after migration. It must acknowledge the same pending frame in `PeerTelemetryAdapter`; generation is not part of frame identity.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-protocol -p openstream-transport -p openstream-client-core -- --test-threads=1
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  ```

  Expected result: every failed/duplicate/reordered path-control case has a deterministic terminal or retry state; old best-effort media may be rejected by the existing replay window; reliable logical control is recoverable with fresh outer counters; sockets and relay registrations are closed once.

---

## Task 8: Probe `webrtc-ice 0.17.2` and land the truthful ICE migration boundary

**Files:** `engine/lowlat/crates/client-core/src/lib.rs`, `engine/lowlat/crates/client-core/src/path.rs`, new `engine/lowlat/crates/client-core/tests/ice_migration.rs`

**Commit:** `feat: report ICE migration capability accurately`

The current dependency is deliberately retained. The public 0.17.2 API exposes `Agent::restart`, `get_selected_candidate_pair`, and selected-pair callbacks, but `dial`/`accept` return the agent-owned shared `Conn`; restarting that agent cannot prepare a replacement `Conn` while retaining the old selected connection for the required two-phase handoff. Therefore the expected v1 implementation is a typed unsupported result, not a simulated migration.

- [ ] RED: add `ice_migration_returns_typed_unsupported_without_reconnect` and assert the exact error variant for an established `ConnectionPath::Ice`. The test must also assert that the session generation, cipher identity marker, and active path state remain unchanged.

- [ ] GREEN: use the stable `PathMigrationError` and `Error::PathMigration` declared in Task 6:

  `migrate_to(MigrationTarget::Ice)` must return `Error::PathMigration(PathMigrationError::UnsupportedIceRestart)` before allocating a new agent, closing the active agent, changing generation, or creating a new cipher. An incoming client request for ICE must receive a bounded `PATH_ABORT { reason: Unsupported }` when path-control is otherwise enabled.

- [ ] GREEN: add the exact source/API probe to the test documentation and keep the dependency declaration at `webrtc-ice = "0.17.2"`:

  ```sh
  rg -n "pub async fn restart|pub fn get_selected_candidate_pair|pub async fn dial|pub async fn accept" \
    "$HOME/.cargo/registry/src" -g 'webrtc-ice-0.17.2/src/agent/*.rs'
  cargo tree --locked -p openstream-client-core -i webrtc-ice@0.17.2
  ```

  This is an evidence record for the boundary, not a permission to upgrade the dependency.

- [ ] Verify the task:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo test --locked -p openstream-client-core --test ice_migration -- --test-threads=1
  cargo test --locked -p openstream-client-core -p openstream-reference-peer -- --test-threads=1
  cargo clippy --locked -p openstream-client-core --all-targets --all-features -- -D warnings
  ```

  Expected result: migration failures, duplicate/reordered controls, replay-window behavior, and one-shot resource cleanup are all deterministic; the code never silently drops reliable data or leaks a replacement path.

---

## Task 9: Add the full direct↔opaque-relay↔direct acceptance harness

**Files:** `engine/lowlat/crates/reference-peer/src/main.rs`, new `scripts/path-migration-smoke.sh`, new `scripts/ice-migration-capability.sh`

**Commit:** `test: add three-generation path migration acceptance`

Exercise one logical session through three committed generations using the self-hosted relay. The harness must use one pairing and one process-level session on both peers; it must never establish a second `PeerSession` for a transition.

- [ ] RED: add the script and reference-peer CLI acceptance assertions before implementing their migration calls. The script should fail with a missing migration milestone rather than silently running the existing one-frame smoke.

- [ ] GREEN: extend `openstream-reference-peer` with the exact invocation `openstream-reference-peer --migration host|client`, preserving the existing `openstream-reference-peer host|client` invocation. In migration mode:

  - opt both capability profiles into `path_migration` explicitly;
  - send/receive an initial authenticated frame at generation 1;
  - host calls `migrate_to(MigrationTarget::OpaqueRelay)` and prints `migration committed generation=2 path=opaque_relay` only after the host receives the replacement-path ACK;
  - client continues its normal receive/ACK loop and prints the observed generation/path snapshot;
  - host sends a second frame after generation 2 and waits for its `FrameAck`;
  - host calls `migrate_to(MigrationTarget::DirectUdp)` and prints `migration committed generation=3 path=direct_udp` only after commit ACK;
  - host sends a third frame after generation 3 and waits for its `FrameAck`;
  - both sides print session/generation/path counters but never print keys, tickets, tokens, or addresses.

  Keep the original non-migration reference-peer output and exit behavior unchanged.

- [ ] GREEN: add `scripts/path-migration-smoke.sh` with private temporary logs and cleanup traps. Start the signal server with a loopback opaque relay, for example:

  ```sh
  OPENSTREAM_ALLOW_NO_AUTH=1 \
  OPENSTREAM_SIGNAL_BIND="127.0.0.1:$signal_port" \
  OPENSTREAM_RELAY_BIND="127.0.0.1:$relay_port" \
  OPENSTREAM_RELAY_ENDPOINT="127.0.0.1:$relay_port" \
  target/debug/openstream-signal-server
  ```

  Create one pairing through the existing REST endpoint, start one migration host and one migration client with `OPENSTREAM_PATH_MIGRATION=1`, and wait for both processes. Require all of:

  ```text
  migration committed generation=2 path=opaque_relay
  migration committed generation=3 path=direct_udp
  client acknowledged frame at generation=1
  client acknowledged frame at generation=2
  client acknowledged frame at generation=3
  migration acceptance passed: one cipher session, three committed generations
  ```

  Fail if logs show application data on the replacement before commit, a new session/cipher establishment, a missing old-path retirement, duplicate recovery/cleanup, or any bearer/relay credential.

- [ ] GREEN: add `scripts/ice-migration-capability.sh`. Run a loopback full-ICE session with `OPENSTREAM_ICE=1`, request `MigrationTarget::Ice`, and require `UnsupportedIceRestart`; do not require an external coturn service for this typed-capability test. The script must use the same pairing only for the capability probe and must reject any output indicating a second key exchange or session establishment.

- [ ] Keep the live relay smoke as a documented local acceptance command; only the non-network state-machine tests belong in required CI. The workflow must not claim external coturn/public-NAT success.

- [ ] Verify the task:

  ```sh
  ./scripts/path-migration-smoke.sh
  ./scripts/ice-migration-capability.sh
  ```

  Expected result: one encrypted session survives direct → opaque relay → direct, frames/ACKs remain end-to-end, generation-local samples reset on every switch, relay framing/cleanup is exercised, and ICE migration reports the typed unsupported result without reconnecting.

---

## Task 10: Update documentation, roadmap, changelog, and final gates

**Files:** `docs/BUILD.md`, `docs/NAT_MATRIX.md`, `docs/IMPLEMENTATION_PLAN.md`, `engine/lowlat/docs/changelog.md`, `README.md` only where the public feature/status summary requires a synchronized sentence

**Commit:** `docs: document shared path migration and musl acceptance`

- [ ] RED: use `rg` to identify stale open-work claims and commands before editing:

  ```sh
  rg -n "portable.*telemetry|PeerSession.*adapter|direct.*TURN.*migration|pmtu-watchdog|Alpine|musl|migration|webrtc-ice" \
    docs README.md engine/lowlat/docs .github/workflows/ci.yml
  ```

  Record every stale status line in the task review notes; do not delete a gap that remains outside this phase, such as native macOS/Windows media or external coturn acceptance.

- [ ] GREEN: update `docs/BUILD.md` with exact commands for:

  - `mtu-watchdog` through `container machine run -n openstream-linux-ci --root`;
  - the existing fast `mtu-transition` fixture;
  - the pinned Alpine helper/image digest;
  - `scripts/path-migration-smoke.sh` and typed ICE capability smoke;
  - the distinction between CI-proven tests, local relay acceptance, and external coturn/public-NAT/hardware gates.

- [ ] GREEN: update `docs/NAT_MATRIX.md` with direct↔opaque-relay↔direct as an OpenStream-owned migration acceptance row, retain external coturn as unverified until a real service run is recorded, and document ICE migration as `UnsupportedIceRestart` on `webrtc-ice 0.17.2` rather than as a successful TURN switch.

- [ ] GREEN: update `docs/IMPLEMENTATION_PLAN.md` to mark the portable adapter and direct/opaque migration complete only when Tasks 1–9 have passed, while leaving native ScreenCaptureKit/VideoToolbox, native Windows zero-copy, Android HEVC, virtual devices, and external-network acceptance open.

- [ ] GREEN: add a newest-first `engine/lowlat/docs/changelog.md` entry covering:

  - generation-scoped `PeerTransportSnapshot` and `PeerTelemetryAdapter`;
  - one-cipher/two-phase direct/opaque migration;
  - old-path receive-only drain and relay unregister cleanup;
  - the automatic watchdog namespace fixture;
  - required pinned Alpine/musl ABI gate;
  - the typed ICE migration limitation and explicit non-claims.

- [ ] Run the complete local verification from the repository root:

  ```sh
  cd engine/lowlat
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-features --locked -- --test-threads=1
  cargo check --manifest-path fuzz/Cargo.toml --locked
  cargo build --workspace --release --locked
  cargo deny check
  bash -n scripts/netns-fixtures.sh
  sh -n scripts/alpine-musl-ci.sh
  cd ../..
  bash -n scripts/path-migration-smoke.sh
  bash -n scripts/ice-migration-capability.sh
  ```

- [ ] Run the real Linux checks where privileges exist:

  ```sh
  container machine run -n openstream-linux-ci --root -- bash -lc '
    cd /Users/ankitpipalia/Documents/RE/openersec/engine/lowlat
    PUNCH=/tmp/openstream-lowlat-target/release/punch \
    PEER=/tmp/openstream-lowlat-target/release/shell-punch \
    scripts/netns-fixtures.sh port-restricted full-cone restricted-cone symmetric carrier-grade hairpin mtu-transition mtu-watchdog
  '
  ```

  Require a clear `skipped:` reason when the machine lacks `CAP_NET_ADMIN`/namespace support. A skip is not a pass claim.

- [ ] Push the task commits and inspect the GitHub run for the exact final SHA. Confirm `CI gate`, `alpine-musl`, workspace tests, C/C++ ABI, fuzz compilation, release build, sanitizer/model jobs, target matrices, and stable smoke jobs all succeed before describing the implementation as CI-green.

## Final Acceptance Checklist

- [ ] `PeerSession` has one cipher/replay state across all committed generations.
- [ ] Generation 1 is the initial active path; only a successful host commit creates generation N+1.
- [ ] `PATH_COMMIT` is old-path traffic; `PATH_COMMIT_ACK` is replacement-path traffic; duplicates are idempotent.
- [ ] No replacement application traffic appears before commit.
- [ ] Commit ACK loss yields bounded `CommitPending`/typed `CommitUnconfirmed`, never silent old-path resumption after responder commit.
- [ ] Old path becomes receive-only and is retired once within the finite drain grace.
- [ ] Reliable logical control retransmits with a fresh outer counter; the >64-counter replay test passes.
- [ ] Frame ACKs survive generation changes and local transport rates cannot independently change `AdaptiveBitrate`.
- [ ] PMTU/pacer/sample baselines reset atomically per path generation.
- [ ] Direct↔opaque-relay↔direct uses one logical session and cleans relay/socket resources.
- [ ] ICE/TURN migration is either truly two-phase or reports `UnsupportedIceRestart`; this plan chooses the typed result for 0.17.2.
- [ ] The slow watchdog fixture uses real `Health::Undeliverable` and recovers exactly once.
- [ ] Alpine/musl C/C++ ABI checks are a required `CI gate` input with an immutable image digest.
- [ ] Documentation distinguishes implementation, local acceptance, and unverified hardware/external-network gates.
