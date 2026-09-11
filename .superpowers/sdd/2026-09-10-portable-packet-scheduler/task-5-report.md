# Task 5 implementation report — generation-aware telemetry and migration reset behavior

## Audit

- `PeerDeliverySnapshot` and `DeliveryClassSnapshot` are public serde
  representations built only from path generation, timing, rates, and packet
  counters. Their conversion from the dependency-free policy snapshot carries
  no socket addresses, credentials, payloads, or local socket metadata.
- Delivery accounting keeps aggregate, video, audio, and critical state
  separate. `Kind::Control` and `Kind::Input` map to critical; the loopback
  test acknowledges one video and one audio packet and verifies aggregate
  totals without falsely populating critical or video-only totals.
- `PeerSession::transport_delivery_snapshot(now)` reports acknowledged
  delivery evidence from the estimator. A locally written packet remains
  unacknowledged and has no fabricated delivery rate.
- `PeerTelemetryAdapter::observe_delivery` stores the latest delivery snapshot
  for diagnostics only. It does not call or feed packet delivery into
  `AdaptiveBitrate`; the with-delivery and without-delivery tests produce
  identical bitrate decisions and bitrate values.
- The existing `MigrationAction::Activate` boundary is synchronous across path
  activation: it clears the path sample baseline and ICE counters, resets the
  scheduler generation/pacer credit/priority debt, resets the delivery
  estimator and receive ACK window, and updates the keepalive baseline before
  the next application send. The `CipherSession` object is retained, so its
  outer counter/replay domain remains continuous. Reliable-control logical
  sequencing and media `FrameAck` history remain outside this reset and are
  preserved. Old ingress ACKs are ignored, and current-generation ACK
  validation rejects stale generation state without mutating the active
  estimator.
- No `path.rs` change was necessary: the activation/reset boundary already
  exists in `client-core/src/lib.rs` from the preceding migration integration
  and was audited against the Task 5 requirements.
- No Task 6 call-site migration, native media pipeline, ICE restart, or
  hardware/WAN validation was performed.

## Files

Implementation commit `72e152db6ef4c530429ac345128df7d332bc0423` changed:

- `engine/lowlat/Cargo.lock`
- `engine/lowlat/crates/client-core/src/lib.rs`
- `engine/lowlat/crates/client-core/tests/portable_transport.rs`
- `engine/lowlat/crates/media/Cargo.toml`
- `engine/lowlat/crates/media/src/telemetry.rs`
- `engine/lowlat/crates/transport-policy/src/delivery.rs`
- `engine/lowlat/crates/transport-policy/src/lib.rs`

## Commands and results

All commands were run from `engine/lowlat` in the `portable-scheduler`
worktree.

1. `cargo test -p openstream-client-core --test portable_transport --all-features --locked -- --test-threads=1` — **10 passed, 0 failed**.
2. `cargo test -p openstream-client-core --test path_migration --all-features --locked -- --test-threads=1` — **3 passed, 0 failed**.
3. `cargo test -p openstream-media telemetry --all-features --locked -- --test-threads=1` — **4 passed, 0 failed**.
4. `cargo test -p openstream-client-core --all-features --locked -- --test-threads=1` — **61 unit, 1 ICE integration, 3 path-migration integration, 10 portable integration, and 11 scheduler tests passed; 0 failed**.
5. `cargo test -p openstream-media --all-features --locked -- --test-threads=1` — **46 passed, 0 failed**.
6. `cargo fmt --all -- --check` — **passed**.
7. `cargo clippy -p openstream-client-core -p openstream-media --all-targets --all-features --locked -- -D warnings` — **passed**.
8. `cargo check --workspace --all-features --locked` — **passed**.
9. `git diff --check` — **passed** before the implementation commit.

## Finisher corrections

- The first fmt check identified only rustfmt wrapping in the new portable
  transport test; `cargo fmt --all` applied the expected formatting.
- The first warnings-denied Clippy run identified only `clippy::float_cmp` in
  that test; the invariance assertion now compares exact `f64::to_bits()`.

## Concerns

- The workspace check reports the existing future-incompatibility warning for
  `block v0.1.6`; it does not fail the locked check.
- Verification is deterministic repository/loopback coverage. It does not
  establish behavior over WAN/NAT, external coturn, hardware capture, or a
  native media pipeline.
- The branch remains unpushed and was not rebased.

## Commit

`72e152db6ef4c530429ac345128df7d332bc0423` — `feat: isolate portable delivery telemetry by path generation`
