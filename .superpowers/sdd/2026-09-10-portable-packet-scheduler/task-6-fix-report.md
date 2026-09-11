# Task 6 fix report — portable scheduler backpressure

Date: 2026-09-11

Implementation commit: `8c5bcfb08ec2e447acfe0139b41cc9946554eb3e`

Commit message: `fix: keep portable scheduler live under backpressure`

## Findings and fix

The review found that delivery-history saturation was being returned as a
fatal error from migrated portable event loops. After the bounded history was
full, a queued packet was retained but the loop could exit before receiving
transport ACKs that would free history.

`PeerSession::flush_outbound_recoverably` now maps only
`Error::OutboundHistoryFull` to `FlushOutcome::Backpressured`. The migrated
loops keep receiving when that outcome occurs by disabling the scheduler wake
until history is freed, then retry the retained queue. Sealing, delivery
accounting, protocol, path, transport, and I/O errors remain fatal and are
returned unchanged. The strict `flush_outbound` and compatibility `send`
semantics remain available for callers that require an emitted packet.

The no-bypass guard now recursively scans `client-core/src` and all four
portable consumer source trees. It checks the private immediate/application
symbols and direct high-rate audio/video sends, while allowing their
implementation only in `client-core/src/lib.rs`. Its Rust-aware compaction
removes line comments, nested block comments, quoted/byte/raw string literals,
and character literals before matching. Dedicated tests cover both actual
call detection and comment/literal false positives.

## Changed files

- `engine/lowlat/crates/client-core/src/lib.rs` — added the typed flush outcome
  and exact history-backpressure mapping.
- `engine/lowlat/crates/client-core/tests/portable_transport.rs` — broadened
  the no-bypass source scan and added scanner regression tests plus the
  receive-path history-backpressure test.
- `engine/lowlat/crates/client/src/main.rs` — made the receive/control loop
  recover from bounded history saturation.
- `engine/lowlat/crates/desktop-client/src/main.rs` — made the desktop network
  loop recover from bounded history saturation.
- `engine/lowlat/crates/ffmpeg-host/src/main.rs` — made the FFmpeg event loop
  recover from bounded history saturation.
- `engine/lowlat/crates/reference-peer/src/main.rs` — made the reference-peer
  send/wait loop recover from bounded history saturation.
- `.superpowers/sdd/2026-09-10-portable-packet-scheduler/task-6-fix-report.md`
  — this report.

## Tests and checks

All commands were run in the `portable-scheduler` worktree.

- `cargo test -p openstream-client-core --test portable_transport -- --test-threads=1`
  — **15 passed, 0 failed**, including
  `history_backpressure_keeps_receive_path_alive`, the strengthened source
  guard, and both scanner false-positive/actual-call tests.
- `cargo test -p openstream-client-core -p openstream-ffmpeg-host -p openstream-reference-peer -p openstream-client -p openstream-desktop-client --all-targets -- --test-threads=1`
  — **129 passed, 0 failed** across the affected package targets: client-core
  unit, ICE, path-migration, portable-transport, and scheduler tests; FFmpeg,
  desktop, reference-peer, and client targets.
- `cargo fmt --all` — passed.
- `cargo fmt --all -- --check` — passed.
- `cargo clippy -p openstream-client-core -p openstream-ffmpeg-host -p openstream-reference-peer -p openstream-client -p openstream-desktop-client --all-targets -- -D warnings`
  — passed with warnings denied. Cargo also emitted the existing
  future-incompatibility note for `block v0.1.6`.
- `git diff --check` and `git diff --cached --check` — passed.

No Task 7 or Task 8 files were changed. No rebase or push was performed.
