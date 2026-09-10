# Task 5 Fix Report

Date: 2026-09-11

Implementation commit: `77c5fcbc373aab0daff98bc1073dbc624b0b334b`

Commit message: `fix: isolate delivery diagnostics by path generation`

## Decision

`PeerTelemetryAdapter::observe_delivery` accepts a delivery snapshot only
when `snapshot.path_generation == adapter.generation`. Stale and future
snapshots are ignored without overwriting the stored snapshot. When path
telemetry advances the adapter to a newer generation, the stored delivery
snapshot is cleared so old delivery evidence cannot be published beside the
new path telemetry. Future evidence is therefore fail-closed until the
adapter advances, after which the caller may submit that snapshot again.

Delivery remains diagnostics-only: the adapter does not pass packet-delivery
data to `AdaptiveBitrate`, and the existing bitrate decision equality test
continues to pass. No unrelated transport behavior or Task 6 code was
modified.

## Changed files

- `engine/lowlat/crates/media/src/telemetry.rs` — added the exact-generation
  delivery guard, cleared delivery state on path-generation advance, and
  documented the fail-closed future-generation policy.
- `engine/lowlat/crates/media/src/lib.rs` — added deterministic stale and
  future delivery-generation regression tests and policy snapshot fixtures.

## Commands and results

- `cargo test -p openstream-media delivery -- --test-threads=1` — PASS, 2
  passed, 0 failed; covers stale and future-generation regressions.
- `cargo test -p openstream-media telemetry -- --test-threads=1` — PASS, 5
  passed, 0 failed.
- `cargo test -p openstream-client-core --test portable_transport -- --test-threads=1`
  — PASS, 10 passed, 0 failed; includes diagnostics-only telemetry and
  identical `AdaptiveBitrate` decision coverage.
- `cargo test -p openstream-client-core --test path_migration -- --test-threads=1`
  — PASS, 3 passed, 0 failed.
- `cargo fmt --all -- --check` — PASS.
- `git diff --check` — PASS.
- `cargo clippy -p openstream-client-core -p openstream-media --all-targets --all-features -- -D warnings`
  — PASS, no warnings.

The initial TDD red run of
`cargo test -p openstream-media delivery -- --test-threads=1` failed both
new tests before the production change, as expected; the same command passed
after the fix.
