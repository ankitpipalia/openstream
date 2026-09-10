# Task 6 implementation report — portable loop migration

## Summary

Portable high-rate video and audio producers now retain clear packets in the
bounded `PeerSession` scheduler. The FFmpeg host, reference peer, headless
client, and desktop client flush application output from their event loops and
arm the scheduler's computed `next_outbound_wake`; no outbound sender task or
fixed pacing sleep was added.

Control, input, display selection, clipboard, rumble, keyframe, frame-ACK, and
teardown paths continue to use the scheduler-backed compatibility `send` or
`ReliableControl`. `ReliableControl::retry` remains the existing
`logical_retransmission = true` path in client-core and never performs a raw
socket write. `FrameAck` and `AdaptiveBitrate` decision flow were preserved;
packet delivery remains diagnostic.

## Changed files

- `engine/lowlat/crates/ffmpeg-host/src/main.rs` — queue video/audio packets,
  report bounded class drops without payload data, and add flush/wake handling.
- `engine/lowlat/crates/reference-peer/src/main.rs` — queue fragmented video
  and drive flush/wake while waiting for `FrameAck`.
- `engine/lowlat/crates/client/src/main.rs` — flush and wake the scheduler in
  the receive/control loop.
- `engine/lowlat/crates/desktop-client/src/main.rs` — flush and wake the
  scheduler around input/control/clipboard/microphone handling.
- `engine/lowlat/crates/client-core/tests/portable_transport.rs` — add a
  recursive source guard for raw/private and direct high-rate sends, plus a
  loopback pacing/no-immediate-write behavior test.
- `.superpowers/sdd/2026-09-10-portable-packet-scheduler/task-6-report.md` —
  this report.

## Commands and outcomes

All commands were run in the `portable-scheduler` worktree.

- Literal brief command
  `cargo test -p openstream-client-core portable_transport no_immediate_media_bypass`
  — Cargo rejected the two positional filters before running tests. The
  equivalent explicit command was used below.
- TDD red:
  `cargo test -p openstream-client-core --test portable_transport no_immediate_media_bypass -- --test-threads=1`
  — 1 behavior test passed and the source guard failed on the four existing
  direct high-rate video/audio call sites.
- TDD green:
  the same command — 2 passed, 0 failed.
- `cargo test -p openstream-ffmpeg-host -- --test-threads=1` — 21 passed,
  0 failed.
- `cargo test -p openstream-reference-peer -- --test-threads=1` — 0 passed,
  0 failed; the crate has no unit tests.
- `cargo test -p openstream-client -- --test-threads=1` — 0 passed, 0 failed;
  the crate has no unit tests.
- `cargo test -p openstream-desktop-client -- --test-threads=1` — 17 passed,
  0 failed.
- `cargo test -p openstream-client-core --test portable_transport -- --test-threads=1`
  — 12 passed, 0 failed.
- `cargo fmt --all -- --check` — passed.
- `cargo clippy -p openstream-client-core -p openstream-ffmpeg-host -p openstream-reference-peer -p openstream-client -p openstream-desktop-client --all-targets -- -D warnings`
  — passed. Cargo emitted the existing future-incompatibility note for
  `block v0.1.6`.
- `cargo test --workspace --all-targets -- --test-threads=1` — passed with
  exit code 0; all executed tests passed and only documented hardware/device
  tests were ignored.
- `rg -n "send_sealed_on|send_datagram|\\.send\\(Kind::" engine/lowlat/crates/{client,desktop-client,ffmpeg-host,reference-peer}/src`
  — no raw/private or direct high-rate matches; remaining compatibility sends
  are control/input only.
- `git diff --check` — passed before the implementation commit.

## Concerns and scope

- The existing reference-peer migration helper retains its pre-existing
  300 ms old-path drain wait. It is migration timing, not scheduler pacing;
  all new scheduler waits use `next_outbound_wake()`.
- The existing `block v0.1.6` future-incompatibility warning remains outside
  Task 6 scope.
- Verification covers deterministic workspace and loopback behavior. It does
  not claim WAN/NAT, external coturn, hardware capture, native media, or
  Task 7/8 acceptance.
- No rebase or push was performed.

## Commit

`fbf9b8f2341f939745cd934c4888e9ba0dd10efa` —
`refactor: route portable streams through packet scheduler`
