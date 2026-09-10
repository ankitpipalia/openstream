# Task 4 implementation report — portable ACK policy and PeerSession integration

## Prior partial-state audit

- The handoff described the Task 4 implementation as uncommitted. At the
  start of this finisher audit, `git status --short --branch` was clean on
  `codex/portable-scheduler`; `HEAD` was already the implementation commit
  `747ddc9077d99822f5639ed76ab28404158a8137` with the requested subject.
- `git diff HEAD^ HEAD` contained only this report and the four Task 4
  implementation/test files listed below. No implementation redesign or
  unrelated change was necessary.
- The prior partial-state failure was a generation mismatch at path
  activation: the active `PeerPath` advanced while the newly added scheduler,
  delivery estimator, and ACK window remained at generation 1. That caused
  the first post-migration application send to return `OutboundHistoryFull`.
  The activation boundary now resets those path-local states while preserving
  the cipher, outer-counter domain, reliable-control sequence space, and frame
  state.

## Changed files

- `engine/lowlat/crates/client-core/src/lib.rs` — scheduler-backed
  `PeerSession` queue/flush APIs, delivery accounting, transport-meta ACK
  interception/emission, private immediate path helpers, and generation reset.
- `engine/lowlat/crates/client-core/src/scheduler.rs` — local queue identity so
  compatibility `send()` waits for its own queued packet.
- `engine/lowlat/crates/client-core/src/transport_ack.rs` — bounded 64-counter
  receive ACK window with threshold, timer, gap, delay, and reset policy.
- `engine/lowlat/crates/client-core/tests/portable_transport.rs` — authenticated
  loopback coverage for queueing, pacing, ACK interception/suppression, delayed
  ACKs, and delivery snapshots.
- `.superpowers/sdd/2026-09-10-portable-packet-scheduler/task-4-report.md` —
  finisher audit, verification outcomes, concerns, and commit identity.

## Root cause and fixes

Warnings-denied Clippy also found one test assertion using redundant pattern
matching; it now uses `.is_none()`.

## Requirement coverage

- Channel 254 transport metadata is decoded before path/reliable control;
  transport ACKs are non-ack-eliciting, excluded from delivery history, sent
  immediately through the private meta path, coalesced by the receive window,
  and never ACKed in return.
- ACK-window tests cover threshold, timer, gap/out-of-order, duplicate
  suppression, largest-counter delay, 64-bit bitmap math, and generation reset.
- Delivery-policy tests cover future-counter rejection and stale-generation
  ignore behavior without estimator mutation, irrevocable ACKs, actual wire
  byte accounting, RTT delay subtraction, and logical-vs-outer retries.
- `PeerSession` exposes `queue`, `flush_outbound`, `next_outbound_wake`,
  `outbound_pending`, `set_wire_pacing_rate`, and
  `transport_delivery_snapshot`. Queueing does not consume cipher counters;
  successful writes record the actual outer counter and returned wire length.
- Immediate writes remain private and are used only by setup/path-control and
  transport-meta ACK code. Critical queue saturation maps to typed
  `OutboundBackpressure`; invalid packet, history, and pacing failures remain
  typed errors.
- Existing path-migration, cipher-continuity, reliable-control, ICE capability,
  and path-migration integration tests remain green.

## Commands and outcomes

All Rust commands below were run from
`engine/lowlat` in the `portable-scheduler` worktree.

1. `cargo test -p openstream-client-core --test portable_transport
   --all-features --locked` — 6 passed, 0 failed.
2. `cargo test -p openstream-client-core --all-features --locked transport_ack`
   — 10 ACK/window tests, 2 matching portable integration tests, and 1
   scheduler test passed; 0 failed.
3. `cargo test -p openstream-client-core --all-features --locked` — first run
   found 60 passed and 1 failed at
   `tests::path_migration_direct_relay_direct_preserves_cipher_and_resets_snapshot`
   with `OutboundHistoryFull` at `lib.rs:3835`.
4. `cargo test -p openstream-client-core --all-features --locked
   path_migration_direct_relay_direct_preserves_cipher_and_resets_snapshot
   -- --nocapture` — after the generation-reset fix, 1 passed, 0 failed.
5. `cargo test -p openstream-client-core --test portable_transport
   --all-features --locked -- --test-threads=1` — 6 passed, 0 failed.
6. `cargo test -p openstream-client-core transport_ack -- --test-threads=1`
   — 10 unit tests, 2 portable integration tests, and 1 scheduler test passed;
   0 failed.
7. `cargo test -p openstream-client-core --all-features --locked
   -- --test-threads=1` — 61 unit tests, 1 ICE integration test, 3
   path-migration integration tests, 6 portable integration tests, 11
   scheduler tests, and doc-test target completion; 0 failed.
8. `cargo test -p openstream-transport-policy delivery -- --test-threads=1`
   — 17 passed, 0 failed.
9. `cargo test -p openstream-protocol transport_meta -- --test-threads=1` — 8
   passed, 0 failed.
10. `cargo fmt --all -- --check` — passed.
11. `cargo clippy -p openstream-client-core --all-targets --all-features
    --locked -- -D warnings` — first run identified the one redundant test
    pattern; rerun after the lint fix passed.
12. `cargo check -p openstream-client-core --all-features --locked` — passed.

## Fresh finisher verification

- `cargo test -p openstream-client-core --all-features --locked --
  --test-threads=1` — 61 unit tests, 1 ICE integration test, 3
  path-migration integration tests, 6 portable integration tests, 11
  scheduler tests, and doc-test target completion; 0 failed.
- `cargo fmt --all -- --check` — exit 0.
- `cargo clippy -p openstream-client-core --all-targets --all-features
  --locked -- -D warnings` — exit 0.
- `cargo test --all-features --locked -- --test-threads=1` — workspace
  regression passed; all listed tests and doc-tests passed, with only
  environment-dependent tests ignored.
- `git diff --check origin/main...HEAD` — passed.

## Concerns

- No known Task 4 functional concerns remain after the fresh locked test,
  format, and warnings-denied Clippy checks.
- Verification is limited to the repository's unit/integration and loopback
  coverage; it is not a WAN, hardware, or full-ICE performance validation.
- The Cargo workspace is rooted at `engine/lowlat`, so the Rust commands above
  were run from that directory. No Task 5 or Task 6 call-site migration was
  performed.

An initial test invocation from the worktree root failed before compilation
because this repository's Cargo workspace is rooted at `engine/lowlat`; no code
was changed by that invocation.

## Scope

No Task 5 or Task 6 call-site migration was performed. The branch was not
rebased and nothing was pushed.

## Commit

The Task 4 implementation commit already present at the start of the finisher
audit is:

`747ddc9077d99822f5639ed76ab28404158a8137` — `feat: integrate portable packet delivery telemetry`

No rebase or push was performed.
