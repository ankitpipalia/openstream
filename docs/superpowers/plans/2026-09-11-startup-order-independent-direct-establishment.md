# Startup-Order-Independent Direct Establishment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OpenStream's project-owned direct UDP establishment reliable when either peer starts first or reconnects, without allowing stale signaling records or keys to complete a later attempt.

**Architecture:** The signaling service remains authoritative for a monotonic establishment epoch that is distinct from per-WebSocket socket generations. It publishes readiness only to a complete current host/client pair, and direct establishment uses generation-tagged v2 envelopes separate from the existing ICE messages. The client waits for readiness outside the 15-second candidate/key phase timers, while the existing authenticated OpenStream data format and post-establishment path lifecycle remain unchanged.

**Tech Stack:** Rust 2024, Tokio, axum WebSockets, serde/serde_json, tokio-tungstenite, existing OpenStream X25519/Ed25519 key exchange and UDP transport.

**Spec:** `docs/superpowers/specs/2026-09-11-startup-order-independent-direct-establishment-design.md`

## Global Constraints

- Direct establishment is v2-only: use `direct_candidate`, `direct_candidate_done`, and `direct_key`; do not add an undefined legacy compatibility gate.
- Existing ICE `ice_candidate`, `ice_candidate_done`, and `key` choreography remains unchanged.
- `host_generation` and `client_generation` are socket generations; `establishment_generation` is a separate monotonic direct epoch.
- No direct-establishment record is sent before a server-generated `peer_ready(N)` is accepted.
- `peer_ready` and `peer_reset` publication is fail-closed: readiness is usable only after both current sender queues accept it; partial delivery invalidates the epoch.
- The direct key signature uses the exact binary transcript from the spec: domain string, length-prefixed session ID, big-endian establishment generation, authenticated sender-role byte, and the 32-byte ephemeral key.
- Waiting for the peer is governed by WebSocket/session lifetime; the candidate and key phase timers each remain 15 seconds and start only at their stated transitions.
- Do not log, serialize, or expose bearer tokens, relay tickets, private keys, or raw pairing secrets.
- Preserve local development behavior: unauthenticated management is explicit and loopback-only; secure bearer/identity authentication remains implemented and is the default outside the local lab mode.
- Every task must add deterministic tests for its new state or error path and run the narrowest relevant test command before committing.

---

### Task 1: Add server-authoritative direct establishment epochs

**Files:**
- Modify: `engine/lowlat/crates/signal-server/src/main.rs` (`Session`, WebSocket admission/cleanup, message forwarding, validation helpers, unit tests)
- Test: `engine/lowlat/crates/signal-server/src/main.rs` inline tests

**Interfaces:**
- Preserve the public REST and WebSocket endpoints.
- Add internal session state for `establishment_generation` and the current socket-generation pair/readiness state.
- Add internal helpers for selective direct-message pruning, readiness/reset enqueue, and current-socket validation.

**Steps:**

- [x] RED: add tests proving that a first role receives no `peer_ready`, a complete current pair receives exactly one `peer_ready(1)`, and a role replacement invalidates the old epoch before publishing the next one.
- [x] RED: add tests for fail-closed partial readiness/reset delivery when one bounded sender is closed/full; no unusable generation may be marked ready.
- [x] RED: add tests proving old socket cleanup cannot clear or mutate a replacement sender and that a stale direct message is not forwarded.
- [x] RED: add tests proving only direct-establishment records are pruned from pending queues; ICE and unrelated supported messages remain.
- [x] GREEN: add a checked monotonic establishment-generation field and readiness bookkeeping distinct from socket generations.
- [x] GREEN: publish `peer_ready` directly to both current role senders only when both enqueue operations succeed; compensate/reset or close the affected sockets on partial failure.
- [x] GREEN: on replacement/disconnect, invalidate the old epoch immediately, enqueue `peer_reset` before any replacement readiness, and form the next epoch only from the exact current pair.
- [x] GREEN: reject client-originated `peer_ready`/`peer_reset`; reject direct records without a ready pair; drop stale generations; fail the sender on future generations.
- [x] GREEN: forward only validated generation-matching direct messages and retain generic queue behavior for non-establishment signaling.
- [x] GREEN: add bounded field validation for generation, candidate count/address/kind, direct key hex widths, and reset reason.
- [x] Run: `cargo test -p openstream-signal-server --all-features --locked`.
- [x] Run: `cargo clippy -p openstream-signal-server --all-targets --all-features --locked -- -D warnings`.
- [x] Commit: `feat: add server-authoritative direct establishment epochs`.

**Expected result:** The service has a single authoritative direct epoch per complete current role pair, with fail-closed readiness/reset delivery and no stale direct-message forwarding.

### Task 2: Implement the direct-v2 client handshake

**Files:**
- Modify: `engine/lowlat/crates/client-core/src/lib.rs` (`Endpoint` helpers, direct establishment, key transcript helpers, errors, tests)
- Test: `engine/lowlat/crates/client-core/src/lib.rs` inline tests

**Interfaces:**
- Keep `PeerSession::establish`, `establish_with_stun`, and `establish_configured` signatures stable.
- Add internal readiness/generation parsing and deterministic direct-v2 key encode/verify helpers.
- Keep the ICE path on its existing message vocabulary and deadlines.

**Steps:**

- [x] RED: add tests for waiting past `PHASE_TIMEOUT` before `peer_ready`, accepting the first current readiness, stale reset/readiness handling, future-generation rejection, and direct records before readiness failing closed.
- [x] RED: add transcript tests showing session ID, generation, authenticated role, and ephemeral key all affect the signature; verify role reflection and cross-session replay fail.
- [x] RED: add duplicate candidate/done/key tests and conflicting duplicate-key rejection tests.
- [x] GREEN: wait in a bounded-by-WebSocket/session-lifetime state for `peer_ready(N)` before transmitting direct-v2 candidates.
- [x] GREEN: tag every direct candidate, completion marker, and key with N; start candidate deadline only after readiness and key deadline only after candidate completion.
- [x] GREEN: reset all epoch-local candidates, completion state, key material, and deadlines on `peer_reset`; regenerate ephemeral keys for the next epoch.
- [x] GREEN: replace direct key serialization/signing with the exact binary transcript; derive the sender role from the role-scoped endpoint and verify the opposite role.
- [x] GREEN: keep the ICE establishment implementation accepting only its existing ICE message types and legacy `key` envelope.
- [x] GREEN: preserve the existing candidate validation, deterministic nomination, relay registration, cipher derivation, and post-establishment behavior.
- [x] Run: `cargo test -p openstream-client-core --all-features --locked`.
- [x] Run: `cargo clippy -p openstream-client-core --all-targets --all-features --locked -- -D warnings`.
- [x] Commit: `feat: make direct establishment startup-order independent`.

**Expected result:** A host can remain connected while waiting for a client, and both peers establish only from the current server-published direct epoch; ICE remains behaviorally unchanged.

### Task 3: Add integration races and production acceptance coverage

**Files:**
- Modify: `engine/lowlat/crates/client-core/src/lib.rs` and `engine/lowlat/crates/signal-server/src/main.rs` only where integration seams require it
- Create: `scripts/startup-order-smoke.sh`
- Modify: `docs/IMPLEMENTATION_PLAN.md`, `docs/ARCHITECTURE.md`, `README.md`
- Test: client-core/signal-server integration tests and the shell smoke harness

**Interfaces:**
- The smoke harness must use one pairing/session, one current WebSocket per role at a time, and the existing direct OpenStream binaries/reference peer; it must not silently establish a second application session to mask a failed reconnect.
- The harness must support local unauthenticated loopback signaling only through the explicit existing development flag and never expose that mode on a non-loopback bind.

**Steps:**

- [x] RED: add deterministic tests for socket replacement after `peer_ready` but before candidate completion, after candidate completion but before key completion, and an old socket submitting a correctly signed stale key after N+1 exists.
- [x] RED: add an integration test with host-first startup exceeding the old 15-second candidate deadline, followed by client arrival and successful encrypted UDP data.
- [x] RED: add reconnect tests proving only one reset/recovery occurs and no old generation completes.
- [x] GREEN: implement the minimum test seam needed to exercise those races without weakening production validation.
- [x] GREEN: create the smoke script with explicit cleanup traps, bounded process timeouts, redacted logs, and checks for host-first/direct-v2 establishment plus post-handshake media/control traffic.
- [x] GREEN: update implementation/status docs to mark startup-order direct establishment implemented, preserve the local-auth caveat, and identify external WAN/coturn and native media as separate acceptance gates.
- [x] Run: `bash scripts/startup-order-smoke.sh`.
- [x] Run: `cargo test --workspace --all-features --locked`.
- [x] Run: `cargo fmt --all -- --check`.
- [x] Run: `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`.
- [x] Commit: `test: cover startup-order direct establishment races`.

**Expected result:** Host-first startup and reconnect races are reproducibly covered, the existing local-network MVP path remains usable, and documentation no longer describes the startup protocol as merely proposed.

### Task 4: Validate the Linux NVIDIA host → Apple Silicon macOS client MVP

**Files:**
- Modify: `scripts/linux-host-preflight.sh`, `docs/BUILD.md`, `docs/NAT_MATRIX.md`, `README.md` only for verified commands/results and safe failure guidance
- Test: physical Linux host and macOS client; existing `scripts/linux-host-preflight.sh`, `scripts/create-session.sh`, `openstream-linux-host`, and `openstream-desktop-client`

**Interfaces:**
- Supported first target: Linux x86_64 + NVIDIA, X11/PipeWire capture with FFmpeg `h264_nvenc` fallback, Apple Silicon macOS client using the existing FFmpeg decode and software/wgpu Metal presentation.
- Local unauthenticated signaling must stay loopback/SSH-tunneled or otherwise explicitly constrained; do not weaken the secure mode.
- Do not claim native DRM or macOS VideoToolbox zero-copy unless the actual hardware run proves those paths.

**Steps:**

- [ ] Run Linux preflight and record GPU, capture, encoder, output, input, and audio diagnostics without secrets.
- [ ] Run the host-first smoke using a fresh local pairing, direct LAN UDP, H.264, and a bounded 10-minute or available-duration stream.
- [ ] Run macOS software presentation first, then the existing wgpu Metal presentation smoke/session if software is stable.
- [ ] Capture evidence: exact commit, OS/kernel/driver/FFmpeg versions, negotiated codec/resolution/FPS, direct path, duration, frame acknowledgements, errors, and clean shutdown.
- [ ] If native DRM fails, make the fallback selection/reporting explicit and preserve X11/FFmpeg/NVENC as the supported MVP path; do not silently advertise native DRM success.
- [ ] Update docs only with observed results and remaining gates; redact pairing JSON, tokens, keys, IPs if not needed, and user data.
- [ ] Run: the narrow hardware commands plus a final workspace test/lint/build on the exact commit.
- [ ] Commit: `docs: record Linux NVIDIA to macOS MVP acceptance`.

**Expected result:** The repository contains a reproducible, honest acceptance record for the real Linux-host/macOS-client MVP and clearly separates tested fallback functionality from untested native/advanced backends.

## Completion Checklist

- [ ] Tasks 1–3 implementation/tests pass locally and in PR CI.
- [ ] Direct host-first startup no longer fails merely because the client arrived after 15 seconds.
- [ ] ICE behavior remains unchanged and direct-v2 messages cannot be confused with ICE messages.
- [ ] Secure authentication/identity paths remain implemented; local no-auth mode is explicit and constrained.
- [ ] Linux NVIDIA → macOS Apple Silicon stream is reproduced from documented commands with clean shutdown.
- [ ] No production claim says native DRM, VideoToolbox decode, zero-copy Metal, WAN/TURN, or fancy device integrations are tested unless evidence exists.
- [ ] Remaining production gaps are recorded rather than hidden: durable product accounts/UI, signed packaging/updates, native media, external NAT, virtual devices, and long-run QA.
