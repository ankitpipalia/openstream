# Portable Packet Scheduling and Delivery Telemetry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded portable `PeerSession` packet scheduler and authenticated packet-delivery estimator while preserving OpenStream's single cipher session and independent `FrameAck` encoder feedback.

**Architecture:** The existing dependency-free `openstream-transport-policy` crate gains a fixed-size delivery estimator. `openstream-protocol` gains a fixed transport-meta ACK record on reserved control channel 254. `openstream-client-core` owns the bounded clear-packet scheduler, ACK receive timer/window, socket integration, and generation reset; it remains independent of lowlat I/O and `webrtc-ice` implementation details.

**Tech Stack:** Rust 1.85, edition 2024, existing Tokio UDP/ICE adapters, AES-GCM `CipherSession`, `openstream-transport-policy` (`#![no_std]`), fixed-size estimator storage, `VecDeque` application queues, existing workspace tests and shell smoke tests. No new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-09-10-portable-packet-scheduler-design.md`

## Global Constraints

- Transport ACKs are channel-254 transport-meta records, intercepted before `ReliableControl`; they are non-ack-eliciting, excluded from delivery accounting, never retransmitted through `ReliableControl`, and coalesced outside application queues.
- ACKs carry `ack_delay_us <= 25_000`; bit 0 is `largest_counter`, bit `n` is `largest_counter - n`; future counters are rejected without state mutation, stale generations are ignored, and acknowledgements are irrevocable.
- Every delivery-history slot retains `{generation, outer_counter, bytes, sent_at_ms, traffic_class, ack_eliciting, logical_retransmission}`; ring aliasing cannot acknowledge a replacement entry; unresolved evictions are explicitly stale/lost.
- `ReliableControl::retry()` creates a fresh outer counter and is reported as a logical retry, never as retransmission of the original encrypted datagram.
- Established application `PeerSession::send()` routes video/audio/input/control through the scheduler; immediate send is private and typed for path-control/setup/meta ACK only.
- Queue saturation is class-specific: critical backpressure, oldest-audio drop, oldest-video drop/report, and one coalesced transport ACK.
- Priority is bounded: ACK/meta immediate, critical and audio finite quanta, video consumes the remaining paced budget.
- Pacer input is encrypted wire bytes and a named `wire_rate_mbps`; no encoder bitrate or local send rate is silently treated as capacity.
- Portable pacing starts at the actual current sealed wire ceiling `openstream_protocol::MAX_DATAGRAM = 1200`; the lowlat policy compatibility default `1229` remains unchanged.
- Path generation reset atomically clears portable estimator/RTT/rate/ACK-window/pacer state while preserving one global `CipherSession`, outer counter/replay domain, reliable-control sequence space, frame IDs, and `FrameAck` history.
- No DPLPMTUD, ICE upgrade, native media pipeline, Parsec/BUD compatibility, or packet media retransmission is added in this plan.
- New production code follows TDD: each behavior gets a failing test, the failure is observed, then the minimal implementation is added and re-tested.

---

## File map

| File | Responsibility |
| --- | --- |
| `engine/lowlat/crates/protocol/src/transport_meta.rs` | Fixed-format authenticated transport ACK codec and constants. |
| `engine/lowlat/crates/protocol/src/lib.rs` | Export transport-meta module; expose the sealed-counter accessor needed by telemetry. |
| `engine/lowlat/crates/transport-policy/src/delivery.rs` | `TrafficClass`, fixed delivery-history ring, RTT/delivery accounting, generation reset. |
| `engine/lowlat/crates/transport-policy/src/lib.rs` | Re-export delivery policy types without adding dependencies. |
| `engine/lowlat/crates/client-core/src/scheduler.rs` | Bounded class queues, service quanta, portable wire pacer, queue/flush reports. |
| `engine/lowlat/crates/client-core/src/transport_ack.rs` | Receive-side ACK window, ACK-delay accounting, threshold/timer policy. |
| `engine/lowlat/crates/client-core/src/lib.rs` | PeerSession fields/API, sealing/sending, receive interception, telemetry and generation reset. |
| `engine/lowlat/crates/media/src/telemetry.rs` | Preserve FrameAck controller semantics while exposing optional packet-delivery diagnostics. |
| `engine/lowlat/crates/ffmpeg-host/src/main.rs` | Use queue/flush/timer APIs in the portable streaming host. |
| `engine/lowlat/crates/reference-peer/src/main.rs` | Exercise scheduled sends and transport ACKs in the reference loop. |
| `engine/lowlat/crates/client/src/main.rs` | Use scheduled input/control sends and flush timers. |
| `engine/lowlat/crates/desktop-client/src/main.rs` | Use scheduled input/control/ACK sends and flush timers. |
| `engine/lowlat/crates/client-core/tests/portable_transport.rs` | Cross-session ACK, scheduler, generation, and no-bypass integration tests. |
| `engine/lowlat/crates/client-core/Cargo.toml` | Depend on `openstream-transport-policy`. |
| `engine/lowlat/Cargo.lock` | Record only the local workspace dependency change. |
| `docs/ARCHITECTURE.md` | Describe the portable scheduler/delivery boundary accurately. |
| `docs/IMPLEMENTATION_PLAN.md` | Mark only completed portable scheduler milestones. |
| `engine/lowlat/docs/changelog.md` | Record behavior, compatibility, and test evidence. |

---

### Task 1: Add the authenticated transport-meta ACK record

**Files:**

- Create: `engine/lowlat/crates/protocol/src/transport_meta.rs`
- Modify: `engine/lowlat/crates/protocol/src/lib.rs`
- Test: `engine/lowlat/crates/protocol/src/transport_meta.rs` unit tests and existing protocol tests

**Interfaces:**

- Produces `openstream_protocol::transport_meta::{TransportAck, TransportMetaError, TRANSPORT_META_CHANNEL, MAX_ACK_DELAY_US, ACK_BITMAP_BITS}`.
- `TransportAck` has `{ generation: u64, largest_counter: u64, received_mask: u64, ack_delay_us: u32 }`.
- `TransportAck::encode(self) -> Result<[u8; 32], TransportMetaError>` and `TransportAck::decode(bytes: &[u8]) -> Result<Self, TransportMetaError>` use the exact 32-byte layout in the spec.
- `openstream_protocol::Session::next_tx_counter(&self) -> u64` returns the next outer counter without advancing it.
- `openstream_protocol::Session::seal_with_counter(...) -> Result<(u64, Vec<u8>), Error>` returns the assigned counter and sealed datagram; existing `seal` delegates to the same implementation.

- [ ] **Step 1: Write failing codec and counter-access tests.**

  Add tests for a valid ACK round trip, all-zero/maximum counters, `ack_delay_us` boundary, non-zero reserved bytes, wrong version/type, short/long records, counter-underflow bitmap bits, `next_tx_counter` non-mutation, and `seal_with_counter` returning counter zero then one.

  ```rust
  #[test]
  fn transport_ack_round_trips_exactly() {
      let ack = TransportAck {
          generation: 7,
          largest_counter: 100,
          received_mask: 0b101,
          ack_delay_us: 2_000,
      };
      assert_eq!(TransportAck::decode(&ack.encode().unwrap()).unwrap(), ack);
  }

  #[test]
  fn an_ack_bit_that_underflows_largest_counter_is_rejected() {
      let ack = TransportAck { largest_counter: 1, received_mask: 1 << 2, ..valid_ack() };
      assert_eq!(TransportAck::decode(&ack.encode().unwrap()), Err(TransportMetaError::CounterUnderflow));
  }
  ```

- [ ] **Step 2: Run the focused tests and observe the expected failure.**

  Run from `engine/lowlat`:

  ```bash
  cargo test -p openstream-protocol transport_meta
  cargo test -p openstream-protocol session_seal_with_counter
  ```

  Expected result: compilation fails because the module, codec, and counter accessor do not exist yet.

- [ ] **Step 3: Implement the fixed codec and counter-returning seal path.**

  Add `pub mod transport_meta;`, fixed offsets/constants, a bounded error enum with `Display`, and exact-length validation before every slice. Refactor the existing sealing body into one private function that returns `(counter, datagram)`; `seal` returns only the datagram and `seal_with_counter` exposes the assigned counter. `next_tx_counter` is read-only and never permits a caller to reserve or reuse a counter.

- [ ] **Step 4: Run focused tests and verify green output.**

  ```bash
  cargo test -p openstream-protocol transport_meta -- --test-threads=1
  cargo test -p openstream-protocol session_seal_with_counter -- --test-threads=1
  ```

  Expected result: all new codec/counter tests pass with zero failures.

- [ ] **Step 5: Run protocol regression tests.**

  ```bash
  cargo test -p openstream-protocol --locked -- --test-threads=1
  cargo clippy -p openstream-protocol --all-targets --all-features -- -D warnings
  ```

- [ ] **Step 6: Commit the protocol extension.**

  ```bash
  git add engine/lowlat/crates/protocol/src/transport_meta.rs engine/lowlat/crates/protocol/src/lib.rs
  git commit -m "feat: add authenticated transport ACK record"
  ```

---

### Task 2: Implement the shared fixed-size delivery estimator

**Files:**

- Create: `engine/lowlat/crates/transport-policy/src/delivery.rs`
- Modify: `engine/lowlat/crates/transport-policy/src/lib.rs`
- Test: `engine/lowlat/crates/transport-policy/src/delivery.rs` unit tests

**Interfaces:**

- Produces `TrafficClass::{Critical, Audio, Video}`.
- Produces `SentPacket`, `DeliveryEstimator`, `DeliverySnapshot`, `DeliveryClassSnapshot`, `AckOutcome`, `SendOutcome`, and `DeliveryError`.
- `DeliveryEstimator` uses exactly 256 `Option<SentPacket>` history slots, `STALE_AFTER_MS = 250.0`, and a `10.0 ms` minimum delivery-rate sample interval.
- `acknowledge` rejects future counters without mutation, ignores stale generations, retires a matching slot at most once, subtracts `ack_delay_us / 1000.0` from the largest newly acknowledged RTT sample, and exposes decimal Mbps.

- [ ] **Step 1: Add failing estimator contract tests.**

  Write tests before implementation for:

  - a sent packet becomes in-flight and an exact ACK retires it;
  - ACK delay is subtracted from RTT and first/second samples follow the `7/8 + 1/8` EWMA;
  - unique acknowledged bytes produce decimal Mbps after a 10 ms interval;
  - duplicate ACKs are irrevocable and report zero new bytes;
  - a future largest counter returns `DeliveryError::FutureCounter` and leaves a cloned estimator state identical;
  - an old generation returns `AckOutcome::IgnoredStaleGeneration` and cannot mutate current state;
  - bitmap bits under 64 counter positions are applied mathematically, including >64 reordering where older history is not falsely acknowledged;
  - ring aliasing rejects a young unresolved collision, explicitly evicts a stale entry, and an old ACK cannot retire the replacement entry;
  - `logical_retransmission` increments its separate count and never increments outer retransmissions;
  - aggregate and video snapshots differ when only audio/control are acknowledged;
  - invalid timestamps and zero-generation reset inputs fail closed.

  ```rust
  #[test]
  fn ack_delay_is_removed_from_the_largest_new_rtt_sample() {
      let mut estimator = DeliveryEstimator::new(1);
      estimator.record_sent(sent(1, 41, 1_000.0)).unwrap();
      let outcome = estimator.acknowledge(1, 41, 1, 2_000, 1_022.0).unwrap();
      assert_eq!(outcome.rtt_sample_ms, Some(20.0));
  }
  ```

- [ ] **Step 2: Run the focused tests and observe failure.**

  ```bash
  cargo test -p openstream-transport-policy delivery
  ```

  Expected result: compilation fails because `delivery.rs` and its public types do not exist.

- [ ] **Step 3: Implement the minimal fixed ring and accounting.**

  Add the three traffic classes and copyable sent-entry identity. Use `outer_counter as usize % DELIVERY_HISTORY_CAPACITY` only after comparing the complete stored identity. `can_record` checks the same slot before sealing; `record_sent` reports stale eviction or bounded history-full. `acknowledge` validates generation/future/underflow inputs, scans set bits, never restores retired entries, and updates per-class/aggregate counters. Keep all time arithmetic finite and monotonic. Do not allocate and do not import protocol or Tokio types.

- [ ] **Step 4: Run estimator tests and verify green.**

  ```bash
  cargo test -p openstream-transport-policy delivery -- --test-threads=1
  cargo clippy -p openstream-transport-policy --all-targets --all-features -- -D warnings
  ```

  Expected result: all estimator tests pass with no warnings.

- [ ] **Step 5: Run shared policy regression tests.**

  ```bash
  cargo test -p openstream-transport-policy --locked -- --test-threads=1
  ```

- [ ] **Step 6: Commit the estimator.**

  ```bash
  git add engine/lowlat/crates/transport-policy/src/delivery.rs engine/lowlat/crates/transport-policy/src/lib.rs
  git commit -m "feat: add shared packet delivery estimator"
  ```

---

### Task 3: Add the portable scheduler and queue policy

**Files:**

- Create: `engine/lowlat/crates/client-core/src/scheduler.rs`
- Modify: `engine/lowlat/crates/client-core/Cargo.toml`
- Modify: `engine/lowlat/Cargo.lock`
- Test: `engine/lowlat/crates/client-core/src/scheduler.rs` unit tests

**Interfaces:**

- Produces `OutboundClass::{Critical, Audio, Video}` and `PendingPacket`.
- Produces `QueueOutcome::{Queued, DroppedOldest}` and `SchedulerError::{QueueFull, InvalidPacket, HistoryFull}`.
- `OutboundScheduler::new(now_ms: f64) -> Self` uses 1200-byte sealed wire datagrams and `wire_rate_mbps = 30.0`.
- `queue(kind, channel, flags, payload, logical_retransmission) -> Result<QueueOutcome, SchedulerError>` classifies `Kind::Input` as Critical and rejects payloads that cannot fit before allocating.
- `pop_due(now_ms, next_outer_counter, can_record) -> Result<Option<PendingPacket>, SchedulerError>` applies persistent bounded priority quanta and the video pacer without sealing.
- `next_wake_ms(now_ms) -> Option<f64>`, `pending() -> usize`, `set_wire_rate_mbps(now_ms, rate)`, and `reset_generation(now_ms, generation)` are deterministic.

- [ ] **Step 1: Write failing scheduler tests.**

  Add tests for critical/audio/video classification, exact capacities, critical backpressure, oldest audio/video drop reporting, video pacer refusal, exact refill wait, continuous critical traffic eventually serving video, no queue entry for transport ACK, and the 1200-byte initial pacer size.

  ```rust
  #[test]
  fn continuous_critical_traffic_cannot_starve_video() {
      let mut scheduler = scheduler();
      scheduler.queue(control_packet(), false).unwrap();
      scheduler.queue(video_packet(), false).unwrap();
      let mut video_seen = false;
      for now_ms in (0..100).map(f64::from) {
          scheduler.queue(control_packet(), false).ok();
          if scheduler.pop_due(now_ms, 0, |_| true).unwrap()
              .is_some_and(|packet| packet.class == OutboundClass::Video) {
              video_seen = true;
              break;
          }
      }
      assert!(video_seen);
  }
  ```

- [ ] **Step 2: Run focused tests and observe failure.**

  ```bash
  cargo test -p openstream-client-core scheduler
  ```

  Expected result: compilation fails because the scheduler module and shared-policy dependency do not exist.

- [ ] **Step 3: Implement bounded queues and the service algorithm.**

  Add the workspace dependency. Store clear packet fields in three `VecDeque`s with capacities 256/32/256. Apply class-specific saturation exactly as the spec says. Track persistent critical/audio priority debt; compute each quantum as `max(datagram, min(4 * datagram, 2 ms * wire_rate))`; yield when lower work is due. For video call the shared pacer with the full sealed wire length (`payload.len() + HEADER_LEN + TAG_LEN`) and return its refill wait without consuming credit when not due. Refuse a tracked emission when `can_record` is false.

- [ ] **Step 4: Run scheduler tests and verify green.**

  ```bash
  cargo test -p openstream-client-core scheduler -- --test-threads=1
  cargo clippy -p openstream-client-core --all-targets --all-features -- -D warnings
  ```

- [ ] **Step 5: Run client-core regression tests.**

  ```bash
  cargo test -p openstream-client-core --locked -- --test-threads=1
  ```

- [ ] **Step 6: Commit the scheduler foundation.**

  ```bash
  git add engine/lowlat/crates/client-core/src/scheduler.rs engine/lowlat/crates/client-core/Cargo.toml engine/lowlat/Cargo.lock
  git commit -m "feat: add portable outbound scheduler"
  ```

---

### Task 4: Implement receive-side ACK policy and PeerSession integration

**Files:**

- Create: `engine/lowlat/crates/client-core/src/transport_ack.rs`
- Modify: `engine/lowlat/crates/client-core/src/lib.rs`
- Test: `engine/lowlat/crates/client-core/src/transport_ack.rs` unit tests and `client-core` integration tests

**Interfaces:**

- Produces `TransportAckConfig { packet_threshold: u8, max_delay: Duration, immediate_on_gap: bool }` with default `2`, `2 ms`, `true` and validation against `25_000 us`.
- Produces `TransportAckWindow::observe(counter, received_at)`, `due(now)`, `take(now, generation)`, `reset(generation)`, and `pending()`.
- Adds `PeerSession::queue`, `flush_outbound`, `next_outbound_wake`, `outbound_pending`, `set_wire_pacing_rate`, and `transport_delivery_snapshot`.
- `PeerSession::send` queues application packets and waits only for its own queue item to emit; private typed `send_path_control` and `send_transport_ack` remain immediate.
- `PeerSession::recv_step` intercepts channel 254 before `ReliableControl`, feeds the estimator, and never emits an ACK for channel 254.

- [ ] **Step 1: Write failing ACK-window tests.**

  Cover first packet starts timer, threshold sends, timer sends one packet, gap/out-of-order sends immediately, duplicate receive does not inflate pending count, ACK delay is measured from largest arrival, mask math across the 64-bit boundary, reset clears state, and ACK records are never re-queued.

- [ ] **Step 2: Run focused tests and observe failure.**

  ```bash
  cargo test -p openstream-client-core transport_ack
  ```

  Expected result: compilation fails because `transport_ack.rs` and the integrated fields do not exist.

- [ ] **Step 3: Implement the receive window and policy.**

  Track `{generation, largest_counter, received_mask, largest_received_at, pending_count, pending_since}`. Reject counter underflow in local bitmap construction, clamp only validated elapsed delay to 25 ms, and reset pending state after `take` while retaining the receive mask. Do not use `ReliableControl` or a background task.

- [ ] **Step 4: Add failing PeerSession integration tests before changing send/recv.**

  Add tests that currently demonstrate the missing behavior: a queued video packet does not write until `flush_outbound`, a control packet is served before a paced video packet, transport ACK is intercepted rather than delivered to application, an ACK-of-ACK does not cause a response, and a two-session loopback produces a delivery snapshot with acknowledged video bytes.

  ```rust
  #[tokio::test]
  async fn transport_ack_is_not_returned_as_application_control() {
      let (mut sender, mut receiver) = connected_test_sessions().await;
      sender.queue(Kind::Video, 0, 0, b"frame").unwrap();
      sender.flush_outbound().await.unwrap();
      let packet = receiver.recv().await.unwrap();
      assert_eq!(packet.kind, Kind::Video);
      assert!(matches!(receiver.recv_step().await.unwrap(), None));
  }
  ```

- [ ] **Step 5: Run integration tests and observe failure.**

  ```bash
  cargo test -p openstream-client-core portable_transport
  ```

  Expected result: the new tests fail because current `PeerSession` has no scheduler/ACK state.

- [ ] **Step 6: Implement PeerSession state and application send routing.**

  Add `scheduler`, `delivery`, `transport_ack`, and a monotonic policy-clock origin to every established-session constructor and test fixture. Add the client-core dependency on `openstream-transport-policy`. Refactor `send_sealed_on` to use `Session::seal_with_counter`; the immediate path must remain private. Implement `queue` classification, `flush_outbound` sealing/write/estimator recording, bounded `flush_until`, and exact pacer delay. Map scheduler errors into typed `Error` variants with `Display` text that names the class but never includes payload content.

- [ ] **Step 7: Implement receive interception and ACK emission.**

  In `recv_step`, detect `packet.kind == Kind::Control && packet.channel == TRANSPORT_META_CHANNEL` before path-control/reliable-control handling. Decode and pass ACK fields to the current-generation estimator; return `Ok(None)`. For active-generation ack-eliciting application packets, update `TransportAckWindow`, send a private coalesced ACK when due, and retain existing local stats. Keep draining-ingress packets out of the new generation ACK window.

- [ ] **Step 8: Run the focused integration tests and verify green.**

  ```bash
  cargo test -p openstream-client-core portable_transport -- --test-threads=1
  cargo test -p openstream-client-core --locked -- --test-threads=1
  cargo clippy -p openstream-client-core --all-targets --all-features -- -D warnings
  ```

- [ ] **Step 9: Commit the PeerSession integration.**

  ```bash
  git add engine/lowlat/crates/client-core/src/transport_ack.rs engine/lowlat/crates/client-core/src/lib.rs
  git commit -m "feat: integrate portable packet delivery telemetry"
  ```

---

### Task 5: Add generation-aware telemetry and migration reset behavior

**Files:**

- Modify: `engine/lowlat/crates/client-core/src/lib.rs`
- Modify: `engine/lowlat/crates/client-core/src/path.rs`
- Modify: `engine/lowlat/crates/media/src/telemetry.rs`
- Test: `engine/lowlat/crates/client-core/tests/portable_transport.rs`, existing path-migration tests, and media telemetry tests

**Interfaces:**

- Produces public `PeerDeliverySnapshot`, `DeliveryClassSnapshot`, and `PeerSession::transport_delivery_snapshot(now: Instant)`.
- `PeerTelemetryAdapter::observe_delivery(&PeerDeliverySnapshot)` stores diagnostics only; no packet field changes `AdaptiveBitrate` decisions.
- `PeerSession` exposes `path_generation`-scoped reset behavior while preserving `CipherSession`, reliable-control sequence numbers, and `FrameAck` state.

- [ ] **Step 1: Write failing generation and telemetry tests.**

  Add tests for aggregate versus video-only delivery, no local send-rate fabrication, late generation-N ACK ignored after generation N+1 activation, pacer credit reset on migration, path snapshot baseline reset, cipher counter increasing across reset, reliable-control logical sequence continuity, and `FrameAck` accepted after migration.

- [ ] **Step 2: Run tests and observe failure.**

  ```bash
  cargo test -p openstream-client-core portable_transport
  cargo test -p openstream-media telemetry
  ```

  Expected result: compilation or assertion failures because the delivery snapshot and reset boundary are not present.

- [ ] **Step 3: Implement the public delivery snapshot.**

  Convert shared estimator snapshots into address/credential-free serde structs. Keep `PeerTransportSnapshot` unchanged for local socket counters. Include `path_generation`, sample interval, optional SRTT, aggregate class counters, and video/audio/critical class snapshots. Use `None` for unavailable packet evidence and preserve decimal Mbps.

- [ ] **Step 4: Implement atomic migration reset.**

  In the existing `MigrationAction::Activate` boundary, reset estimator generation, ACK window generation, scheduler pacer credit/priority debt, path sample baseline, and ICE counters in one synchronous section before application sends resume. Do not replace the cipher or logical media/control objects. Ensure old ACKs fail the generation check without changing current state.

- [ ] **Step 5: Add diagnostics-only adapter support.**

  Extend `PeerTelemetryAdapter` with an optional latest packet-delivery snapshot and accessors. Do not call `AdaptiveBitrate::tick` or alter its decision inputs from packet delivery. Add tests proving identical `BitrateDecision` results with and without local delivery snapshots.

- [ ] **Step 6: Run focused tests and verify green.**

  ```bash
  cargo test -p openstream-client-core portable_transport -- --test-threads=1
  cargo test -p openstream-client-core --test path_migration -- --test-threads=1
  cargo test -p openstream-media telemetry -- --test-threads=1
  cargo clippy -p openstream-client-core -p openstream-media --all-targets --all-features -- -D warnings
  ```

- [ ] **Step 7: Commit the generation/telemetry boundary.**

  ```bash
  git add engine/lowlat/crates/client-core/src/lib.rs engine/lowlat/crates/client-core/src/path.rs engine/lowlat/crates/media/src/telemetry.rs engine/lowlat/crates/client-core/tests/portable_transport.rs
  git commit -m "feat: isolate portable delivery telemetry by path generation"
  ```

---

### Task 6: Migrate portable streaming loops to queue/flush APIs

**Files:**

- Modify: `engine/lowlat/crates/ffmpeg-host/src/main.rs`
- Modify: `engine/lowlat/crates/reference-peer/src/main.rs`
- Modify: `engine/lowlat/crates/client/src/main.rs`
- Modify: `engine/lowlat/crates/desktop-client/src/main.rs`
- Test: each affected crate's existing tests plus `client-core/tests/portable_transport.rs`

**Interfaces:**

- All normal media/control/input call sites use `PeerSession::queue` or the compatibility `send` method, which itself routes through the scheduler.
- Event loops call `flush_outbound` and arm `next_outbound_wake` so video pacing cannot block receive-side ACK/control processing.
- `ReliableControl` marks its resend path as `logical_retransmission = true`; it never invokes a raw socket write.

- [ ] **Step 1: Add a repository-wide no-bypass test/check before migration.**

  Add a focused source check in `client-core/tests/portable_transport.rs` or a shell test that scans the portable crates for calls to private/immediate send symbols and asserts only `client-core/src/lib.rs` contains them. Add a behavior test that enqueues a video burst and proves all writes pass through the scheduler's pacing gate.

- [ ] **Step 2: Run the check and observe the expected failure.**

  ```bash
  cargo test -p openstream-client-core portable_transport no_immediate_media_bypass
  ```

  Expected result: the source check reports the current direct `session.send` streaming call sites outside the scheduler integration.

- [ ] **Step 3: Migrate FFmpeg host and reference peer.**

  Replace high-rate video/audio loops with queue calls followed by bounded flushes. Keep frame ACK and adaptive bitrate logic intact; packet delivery snapshots are diagnostic only. Add a Tokio select branch for scheduler flush wakeups, using `session.next_outbound_wake()` rather than a fixed sleep. Ensure queue drops are logged without payload data and are reflected in existing frame recovery behavior.

- [ ] **Step 4: Run FFmpeg/reference focused tests.**

  ```bash
  cargo test -p openstream-ffmpeg-host -- --test-threads=1
  cargo test -p openstream-reference-peer -- --test-threads=1
  ```

- [ ] **Step 5: Migrate client and desktop-client input/control loops.**

  Route input, clipboard, display selection, rumble, keyframe, and teardown through `send`/`ReliableControl` so they inherit bounded priority. Call `flush_outbound` from the existing control timer and wake branch. Never add a parallel unbounded sender task.

- [ ] **Step 6: Run client/desktop focused tests.**

  ```bash
  cargo test -p openstream-client -- --test-threads=1
  cargo test -p openstream-desktop-client -- --test-threads=1
  ```

- [ ] **Step 7: Run the no-bypass check and inspect all portable call sites.**

  ```bash
  rg -n "send_sealed_on|send_datagram|\.send\(Kind::" engine/lowlat/crates/{client,desktop-client,ffmpeg-host,reference-peer}/src
  cargo test -p openstream-client-core portable_transport no_immediate_media_bypass -- --test-threads=1
  ```

  Expected result: only the compatibility `PeerSession::send` API is called by portable consumers; immediate methods are private to client-core and typed meta/path operations.

- [ ] **Step 8: Commit portable loop migration.**

  ```bash
  git add engine/lowlat/crates/ffmpeg-host/src/main.rs engine/lowlat/crates/reference-peer/src/main.rs engine/lowlat/crates/client/src/main.rs engine/lowlat/crates/desktop-client/src/main.rs engine/lowlat/crates/client-core/tests/portable_transport.rs
  git commit -m "refactor: route portable streams through packet scheduler"
  ```

---

### Task 7: Add cross-session acceptance and constrained-feedback tests

**Files:**

- Modify: `engine/lowlat/crates/client-core/tests/portable_transport.rs`
- Modify: `engine/lowlat/crates/client-core/src/lib.rs` only for test-support visibility that does not expose credentials or sockets
- Create: `scripts/portable-transport-smoke.sh`
- Modify: `docs/BUILD.md`

**Interfaces:**

- The test harness creates two authenticated loopback `PeerSession`s with independent directional cipher keys and drives queue/flush/recv without mocks for transport behavior.
- `scripts/portable-transport-smoke.sh` runs the deterministic portable scheduler/ACK suite and reports counts without requiring external coturn or hardware.

- [ ] **Step 1: Add failing acceptance tests.**

  Add real loopback tests for:

  - one video packet acknowledged through the transport-meta path;
  - ACK loss followed by timer/threshold recovery;
  - ACK bitmap truncation and >64 packet reordering;
  - duplicate ACK and ACK-of-ACK suppression;
  - continuous critical traffic still servicing video;
  - critical queue saturation, audio/video drop behavior;
  - late old-generation ACK after direct-to-opaque-relay migration;
  - asymmetric feedback where ACK packets are delayed/dropped but no ACK loop forms;
  - cipher outer counter continuity and `FrameAck` continuity across reset.

- [ ] **Step 2: Run acceptance tests and observe failure.**

  ```bash
  cargo test -p openstream-client-core --test portable_transport -- --test-threads=1
  ```

- [ ] **Step 3: Implement only the missing test harness glue.**

  Reuse existing loopback/session fixtures and relay test helpers. If a test needs to observe a write, inspect public counters or peer-delivered packets; do not add a fake socket or bypass the cipher. Keep all secrets and addresses out of diagnostics. Do not weaken authentication to simplify setup.

- [ ] **Step 4: Run the complete acceptance suite.**

  ```bash
  cargo test -p openstream-client-core --test portable_transport -- --test-threads=1
  bash scripts/portable-transport-smoke.sh
  ```

  Expected result: all listed behavior cases pass; the script explicitly labels the result as loopback/synthetic and does not claim public NAT, coturn, hardware, or native-media acceptance.

- [ ] **Step 5: Commit the acceptance harness.**

  ```bash
  git add engine/lowlat/crates/client-core/tests/portable_transport.rs scripts/portable-transport-smoke.sh docs/BUILD.md
  git commit -m "test: add portable transport scheduler acceptance"
  ```

---

### Task 8: Documentation, changelog, and final repository verification

**Files:**

- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/IMPLEMENTATION_PLAN.md`
- Modify: `engine/lowlat/docs/changelog.md`
- Modify: `docs/BUILD.md` if acceptance commands changed

- [ ] **Step 1: Add failing documentation assertions.**

  Add a documentation check or focused text assertions requiring the architecture docs to state:

  - portable `PeerSession` now has a bounded scheduler and packet delivery estimator;
  - `PeerTransportSnapshot` remains local observation;
  - `PeerDeliverySnapshot` is authenticated ACK evidence;
  - `FrameAck` remains the encoder signal;
  - wire pacing rate is not encoder bitrate;
  - lowlat and portable I/O paths remain separate;
  - this is not Parsec/BUD compatibility.

- [ ] **Step 2: Run the documentation check and observe failure.**

  ```bash
  rg -n "portable.*scheduler|PeerDeliverySnapshot|FrameAck|wire.rate|BUD|lowlat" docs/ARCHITECTURE.md docs/IMPLEMENTATION_PLAN.md engine/lowlat/docs/changelog.md
  ```

  Expected result: at least one required current-state statement is absent or stale before the documentation update.

- [ ] **Step 3: Update architecture, implementation plan, and changelog.**

  Mark only portable scheduler, transport-meta ACK, delivery estimator, generation isolation, and loop migration complete. Keep DPLPMTUD for portable paths, external coturn/public NAT, native zero-copy media, native device integration, product account/UI, and Parsec/BUD compatibility open. Record exact default ACK policy, 1200-byte portable wire ceiling, 30 Mbps wire-rate default, class saturation behavior, and the loopback-only acceptance boundary.

- [ ] **Step 4: Run focused documentation and hygiene checks.**

  ```bash
  git diff --check
  python3 scripts/check-ascii.py
  ```

- [ ] **Step 5: Run the full locked verification matrix.**

  From `engine/lowlat`:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-features --locked -- --test-threads=1
  cargo check --manifest-path fuzz/Cargo.toml --locked
  cargo build --workspace --release --locked
  cargo deny check
  ```

  Run the portable acceptance script and existing relevant smoke checks after the workspace matrix. Every command must exit zero; existing future-incompatibility warnings must be reported rather than silently treated as test failures.

- [ ] **Step 6: Run a secret scan and inspect the final diff.**

  ```bash
  gitleaks git --log-opts='origin/main..HEAD' --redact --no-banner
  git diff --check origin/main...HEAD
  git status --short --branch
  ```

  Confirm no credentials, pairing tokens, payload contents, or peer addresses entered docs, logs, tests, or snapshots.

- [ ] **Step 7: Commit documentation and verification updates.**

  ```bash
  git add docs/ARCHITECTURE.md docs/IMPLEMENTATION_PLAN.md engine/lowlat/docs/changelog.md docs/BUILD.md
  git commit -m "docs: document portable packet telemetry"
  ```

---

## Final review and integration gate

After Task 8, run the whole-branch review package against the merge base
`origin/main` and the branch head. The final reviewer must inspect:

- ACK codec and exact bounds;
- estimator aliasing/future/stale-generation handling;
- scheduler class drops, service quanta, pacer byte units, and no-bypass rule;
- migration reset/cipher continuity;
- loopback and constrained-feedback tests;
- documentation claims and unchanged non-goals.

Do not merge or push to protected `main` until the final review is clean, all
Critical/Important findings are fixed and re-reviewed, and the full locked
verification matrix is fresh. The next deliverable after this plan is still
native zero-copy media work; portable DPLPMTUD and external WAN acceptance are
separate tasks.
