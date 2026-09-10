# Common Transport Policy Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract lowlat pacing and congestion policy into a dependency-free common crate while preserving the existing lowlat behavior and leaving portable transport behavior unchanged.

**Architecture:** `openstream-transport-policy` owns deterministic no-std pacing and packet-congestion state machines. `lowlat-core` re-exports compatibility types and keeps all packet/session orchestration; portable `PeerSession`, sockets, ICE, migration, crypto, and media frame feedback remain outside this phase.

**Tech Stack:** Rust 1.85, edition 2024, `#![no_std]`, existing lowlat unit tests, cargo workspace, no new third-party dependencies.

**Spec:** `docs/superpowers/specs/2026-09-10-transport-policy-unification-design.md`

## Global Constraints

- No wire-format, packet-size, socket, or `PeerSession` behavior changes.
- The new policy crate has no dependencies and uses `#![no_std]`.
- Preserve the lowlat compatibility configuration: minimum datagram 1229 bytes, maximum datagram 2000 bytes, four burst datagrams, and 5.0 ms maximum burst time.
- Rates use decimal Mbps (`1 Mbps = 1_000_000 bits/s`); time inputs are fractional milliseconds.
- Do not fabricate portable packet delivery, ACK, retransmission, or send-ring metrics.
- `AdaptiveBitrate` remains an end-to-end frame-feedback controller and is not merged into packet congestion policy.

---

## File map

| File | Responsibility |
| --- | --- |
| `engine/lowlat/Cargo.toml` | Register the new workspace member and workspace dependency. |
| `engine/lowlat/crates/transport-policy/Cargo.toml` | Declare the standalone no-std policy crate with no dependencies. |
| `engine/lowlat/crates/transport-policy/src/lib.rs` | Implement `PacerConfig`, `Pacer`, `CongestionObservation`, and `Controller` plus focused unit tests. |
| `engine/lowlat/crates/core/Cargo.toml` | Depend on the shared policy crate. |
| `engine/lowlat/crates/core/src/pacer.rs` | Compatibility re-exports and lowlat-specific `MAX_BURST_BYTES` alias. |
| `engine/lowlat/crates/core/src/congestion.rs` | Compatibility re-exports for the lowlat controller and constants. |
| `docs/ARCHITECTURE.md` | State that pure transport policy is shared-ready while lowlat I/O/session orchestration remains separate. |
| `engine/lowlat/docs/changelog.md` | Record the extraction without claiming portable scheduling is implemented. |

---

### Task 1: Extract the bounded pacer

**Files:**

- Create: `engine/lowlat/crates/transport-policy/Cargo.toml`
- Create: `engine/lowlat/crates/transport-policy/src/lib.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Modify: `engine/lowlat/crates/core/Cargo.toml`
- Modify: `engine/lowlat/crates/core/src/pacer.rs`
- Test: `engine/lowlat/crates/transport-policy/src/lib.rs` unit tests and the unchanged lowlat pacer/session tests

**Interfaces:**

- Produces `openstream_transport_policy::{PacerConfig, Pacer, ConfigError}`.
- `PacerConfig::compatibility_default() -> Self` returns `{ min_datagram_bytes: 1229, max_datagram_bytes: 2000, max_burst_datagrams: 4, max_burst_time_ms: 5.0 }`.
- `PacerConfig::validate(self) -> Result<Self, ConfigError>` returns the validated copy or a precise error.
- `Pacer::new(now_ms: f64) -> Self` uses the compatibility default.
- `Pacer::with_config(now_ms: f64, config: PacerConfig) -> Result<Self, ConfigError>` constructs a custom validated pacer.
- Existing `Pacer` methods retain their names and signatures: `rate_mbps`, `enabled`, `datagram_size`, `set_datagram_size`, `burst_capacity_bytes`, `set_rate`, `can_consume`, `try_consume`, and `wait_ms`.

- [ ] **Step 1: Add the new crate and its failing contract tests.**

  Create the workspace member and a `#![no_std]` crate with no dependency
  section. Write tests for the exact contracts before copying the algorithm:

  ```rust
  #[test]
  fn compatibility_config_is_the_lowlat_default() {
      let config = PacerConfig::compatibility_default();
      assert_eq!(config.min_datagram_bytes, 1229);
      assert_eq!(config.max_datagram_bytes, 2000);
      assert_eq!(config.max_burst_datagrams, 4);
      assert_eq!(config.max_burst_time_ms, 5.0);
      assert_eq!(config.validate(), Ok(config));
  }

  #[test]
  fn invalid_configurations_are_rejected() {
      let base = PacerConfig::compatibility_default();
      for config in [
          PacerConfig { min_datagram_bytes: 0, ..base },
          PacerConfig { min_datagram_bytes: 2001, ..base },
          PacerConfig { max_datagram_bytes: 1228, ..base },
          PacerConfig { max_burst_datagrams: 0, ..base },
          PacerConfig { max_burst_time_ms: 0.0, ..base },
          PacerConfig { max_burst_time_ms: f64::NAN, ..base },
          PacerConfig { max_burst_time_ms: f64::INFINITY, ..base },
      ] {
          assert!(config.validate().is_err());
      }
  }

  #[test]
  fn custom_config_controls_size_validation_and_burst_capacity() {
      let config = PacerConfig {
          min_datagram_bytes: 100,
          max_datagram_bytes: 1600,
          max_burst_datagrams: 2,
          max_burst_time_ms: 2.0,
      };
      let mut pacer = Pacer::with_config(0.0, config).unwrap();
      pacer.set_rate(0.0, 100.0);
      assert_eq!(pacer.burst_capacity_bytes(), 3200);
      assert!(!pacer.set_datagram_size(99));
      assert!(pacer.set_datagram_size(1600));
      assert!(!pacer.set_datagram_size(1601));
  }
  ```

  Run from `engine/lowlat`:

  ```bash
  cargo test -p openstream-transport-policy
  ```

  Expected result before implementation: compilation or test failure because
  the new public types do not exist.

- [ ] **Step 2: Implement the configuration and pacing state machine.**

  Move the current algorithm from `core/src/pacer.rs` into the new crate.
  Replace `crate::DEFAULT_DATAGRAM` and `crate::MAX_DATAGRAM` with the
  validated `PacerConfig` values. Keep the current semantics exactly:

  ```rust
  let time_cap = bytes_per_ms * config.max_burst_time_ms;
  let packet_cap = datagram_bytes as f64 * config.max_burst_datagrams as f64;
  let capacity = time_cap.max(datagram_bytes as f64).min(packet_cap);
  ```

  Use a small `ConfigError` enum with `Debug`, `Clone`, `Copy`, `PartialEq`,
  `Eq`, and `Display` implementations. `Pacer::set_datagram_size` must use
  the configured inclusive range and clip existing credit on a decrease.
  Invalid or backward timestamps must return no credit and must not move the
  stored clock backward.

- [ ] **Step 3: Run the new crate tests and the copied behavior tests.**

  Add the current lowlat tests with constants rewritten against the
  compatibility configuration. Verify the following exact cases:

  ```bash
  cargo test -p openstream-transport-policy -- --test-threads=1
  ```

  Expected result: all new configuration, clock, rate, packet-bound, time-
  bound, and datagram-size tests pass.

- [ ] **Step 4: Replace the lowlat implementation with a compatibility module.**

  Change `core/src/pacer.rs` to re-export `Pacer`, `PacerConfig`, the burst
  constants, and the error type from `openstream-transport-policy`. Keep this
  lowlat-only alias so existing code and diagnostics retain their current
  value:

  ```rust
  pub const MAX_BURST_BYTES: usize = crate::DEFAULT_DATAGRAM * MAX_BURST_DATAGRAMS;
  ```

  Add the dependency through `[workspace.dependencies]` and
  `lowlat-core`'s dependency table. Do not modify `Session` or any packet
  code; its existing `Pacer::new` call must compile unchanged.

- [ ] **Step 5: Verify lowlat compatibility.**

  Run:

  ```bash
  cargo test -p lowlat-core -- --test-threads=1
  cargo clippy -p openstream-transport-policy -p lowlat-core --all-targets --all-features -- -D warnings
  ```

  Expected result: the existing lowlat pacing, session, packet, PMTU, and
  endpoint tests pass without source changes to their callers.

- [ ] **Step 6: Commit the independently reviewable extraction.**

  ```bash
  git add engine/lowlat/Cargo.toml engine/lowlat/crates/transport-policy \
    engine/lowlat/crates/core/Cargo.toml engine/lowlat/crates/core/src/pacer.rs
  git commit -m "refactor: extract common transport pacer"
  ```

---

### Task 2: Extract neutral packet congestion policy

**Files:**

- Modify: `engine/lowlat/crates/transport-policy/src/lib.rs`
- Modify: `engine/lowlat/crates/core/src/congestion.rs`
- Modify: `engine/lowlat/crates/core/Cargo.toml` only if Task 1 did not add the dependency
- Test: `engine/lowlat/crates/transport-policy/src/lib.rs` congestion tests and unchanged `lowlat-core` session/send tests

**Interfaces:**

- Produces `openstream_transport_policy::{CongestionObservation, Controller, Level, LEVELS, DEFAULT_LEVEL, WINDOW_FLOOR}`.
- `CongestionObservation::default()` has every optional field set to `None`.
- `Controller::new(level: usize, min_mbps: f64, max_mbps: f64) -> Self`, `set_bounds`, `max_mbps`, `total_decreases`, `rate_mbps`, `is_congested`, and `tick(window, stale, measured_mbps)` preserve the existing signatures and behavior.
- `Controller::tick_observation(&mut self, observation: CongestionObservation) -> Option<f64>` returns `None` without changing state unless `in_flight` and `stale` are both `Some`; when present it delegates to the compatibility algorithm and uses `delivery_rate_mbps.unwrap_or(0.0)` as the measured-rate input.

- [ ] **Step 1: Add neutral observation tests before moving the implementation.**

  Add these tests to the new policy crate:

  ```rust
  #[test]
  fn missing_packet_evidence_does_not_change_controller() {
      let mut controller = Controller::new(DEFAULT_LEVEL, 1.0, 100.0);
      let before = controller.clone();
      assert_eq!(controller.tick_observation(CongestionObservation::default()), None);
      assert_eq!(controller.rate_mbps(), before.rate_mbps());
      assert_eq!(controller.total_decreases(), before.total_decreases());
  }

  #[test]
  fn complete_observation_returns_a_decision() {
      let mut controller = Controller::new(DEFAULT_LEVEL, 1.0, 100.0);
      let result = controller.tick_observation(CongestionObservation {
          in_flight: Some(10),
          stale: Some(0),
          delivery_rate_mbps: Some(5.0),
          srtt_ms: Some(20.0),
      });
      assert_eq!(result, Some(controller.rate_mbps()));
  }
  ```

- [ ] **Step 2: Move the existing controller and add the observation method.**

  Copy the current `Controller`, `Level`, constants, and tests into the
  dependency-free policy crate. Keep the exact increase/decrease periods,
  stale-ratio thresholds, bound behavior, and default-level fallback. Add
  `CongestionObservation` with `Default` and the guarded
  `tick_observation` method described above. Do not feed this type into
  `AdaptiveBitrate` or portable code in this task.

- [ ] **Step 3: Replace `core/src/congestion.rs` with compatibility exports.**

  Re-export the extracted symbols so existing `session.rs` and `send.rs`
  imports continue to compile without edits. Keep the module-level
  documentation explaining that lowlat stale counts come from `SendRing` and
  that no peer feedback message exists.

- [ ] **Step 4: Run focused and full regression tests.**

  ```bash
  cargo test -p openstream-transport-policy -- --test-threads=1
  cargo test -p lowlat-core -- --test-threads=1
  cargo clippy -p openstream-transport-policy -p lowlat-core --all-targets --all-features -- -D warnings
  cargo test --workspace --all-features --locked
  ```

  Expected result: the neutral observation tests prove missing portable
  packet evidence is inert, all existing lowlat tests remain green, and no
  workspace consumer sees a changed public lowlat API.

- [ ] **Step 5: Commit the congestion extraction.**

  ```bash
  git add engine/lowlat/crates/transport-policy/src/lib.rs \
    engine/lowlat/crates/core/src/congestion.rs
  git commit -m "refactor: extract common congestion policy"
  ```

---

### Task 3: Update architecture documentation and phase gate

**Files:**

- Modify: `docs/ARCHITECTURE.md`
- Modify: `docs/IMPLEMENTATION_PLAN.md`
- Modify: `engine/lowlat/docs/changelog.md`

- [ ] **Step 1: Document the actual boundary.**

  State that pure pacing and packet-congestion policy now live in
  `openstream-transport-policy`, while `lowlat-core` still owns lowlat packet
  encoding, retransmission rings, PMTU probes, and session orchestration.
  State explicitly that portable `PeerSession` has not yet gained an
  outbound scheduler or packet delivery estimator.

- [ ] **Step 2: Update the implementation checklist and changelog.**

  Mark only the extraction tasks complete. Keep portable scheduler,
  cross-backend packet telemetry, native media pipelines, and live external
  network acceptance open. Do not claim Parsec/BUD compatibility.

- [ ] **Step 3: Run documentation and repository checks.**

  ```bash
  git diff --check
  cd engine/lowlat
  python3 scripts/check-ascii.py
  cargo fmt --all -- --check
  cargo deny check
  ```

- [ ] **Step 4: Commit the documentation update.**

  ```bash
  git add docs/ARCHITECTURE.md docs/IMPLEMENTATION_PLAN.md engine/lowlat/docs/changelog.md
  git commit -m "docs: record shared transport policy boundary"
  ```

---

## Final verification

After all three tasks, run from `engine/lowlat`:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked -- --test-threads=1
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo build --workspace --release --locked
cargo deny check
```

The branch is ready for review only if every command exits zero, the diff
contains no generated artifacts or credentials, and the public behavior is
still described as a policy extraction rather than portable transport parity.

