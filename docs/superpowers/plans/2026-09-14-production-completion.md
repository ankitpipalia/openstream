# OpenStream production-completion implementation plan

> **Status: RUNTIME AND CONTROL-PLANE FOUNDATION SOURCE-VERIFIED
> (2026-09-14).** Deliberately narrower than "implemented": secure remote
> Connect, native VideoToolbox decode, raw mouse capture, WAN/TURN validation,
> packaging and signing all remain incomplete, and are listed under "Remaining
> implementation gaps" in [`docs/SESSION-HANDOFF.md`](../../SESSION-HANDOFF.md). What has been
> established is that the runtime spine and control plane build, hold together
> and pass every check this machine can run.
>
> The verification campaign has run. Format, Clippy `-D warnings`, the workspace suite
> (1101 passed / 0 failed / 30 ignored), the Tauri suite (46), the frontend
> suite (16) and bundle, the locked release build, fuzz-harness compilation,
> `cargo deny`, loom, and every local acceptance smoke pass. Nine defects were
> found and fixed during that pass; see [`docs/SESSION-HANDOFF.md`](../../SESSION-HANDOFF.md) for
> each one.
>
> The changes remain **uncommitted** on `codex/production-completion`, and
> `main` is unchanged. Physical hardware, WAN/NAT/TURN, package and signing
> evidence has **not** been produced — the rig host is unreachable and no
> signing identity is available — so the release checker still reports
> `NOT READY` with 11 failures, which is the correct result.

> This plan is executed in the isolated `codex/production-completion` worktree.
> Verification commands were deferred until the final phase by explicit
> project-owner instruction; that phase has now been completed for everything
> this machine can run.

## Outcome

Turn the current product contracts and transport foundation into an honest,
usable runtime spine for the supported first production matrix:

* Linux x86-64/NVIDIA host with the tested X11/FFmpeg/NVENC fallback;
* Apple-Silicon macOS client with Metal presentation and a VideoToolbox
  decoder when the native backend is available, plus FFmpeg fallback;
* control-plane-only signaling after direct establishment, with explicit
  epoch isolation for full ICE as well as direct establishment;
* durable local device identity and typed host/session lifecycle integration;
* frame-based host health and safe restart/stop semantics;
* product-shell Connect/Disconnect/Host actions that launch the real session
  runner without sending media through Tauri/React;
* production input safety contracts and native relative-motion plumbing;
* release artifacts and evidence tooling that fail closed rather than claiming
  unperformed hardware/WAN/signing validation.

This branch does not fabricate physical, WAN, notarization, or rollback
evidence. Those remain final verification gates.

## Work sequence

### 1. Runtime and control contracts

Files:

* `desktop/src-tauri/src/runtime.rs`
* `desktop/src-tauri/src/lib.rs`
* `desktop/src/adapters/tauriAdapter.ts`
* `desktop/src/adapters/productAdapter.ts`
* `desktop/src/App.tsx`
* `engine/lowlat/crates/app-core/src/lib.rs`
* new `engine/lowlat/crates/session-supervisor/`

Implement typed, secret-free session descriptors and a Rust-owned
`SessionSupervisor` that starts/stops the native session process using a
protected inherited descriptor/IPC handoff. Add Tauri commands for connect,
disconnect, host-agent operations, diagnostics refresh, settings update and
runtime events. React remains control/state only; encoded frames never cross
the Tauri boundary. Keep the TypeScript fixture adapter for tests and make it
an explicit test adapter, not the production default.

Acceptance tests to add:

* Connect creates one idempotent session request and launches one runner.
* Disconnect cancels and reaps the runner before reporting disconnected.
* Duplicate Connect/Disconnect are safe.
* Runner crash produces a typed reconnectable event without exposing command
  lines or bearer material.
* settings load/save and host-agent status are reachable through the real
  adapter.

### 2. Durable device identity and trust boundary

Files:

* `engine/lowlat/crates/client-core/src/lib.rs`
* new `engine/lowlat/crates/identity-store/`
* `engine/lowlat/crates/settings/src/lib.rs`
* `engine/lowlat/crates/signal-server/src/main.rs`
* `desktop/src-tauri/src/runtime.rs`

Add a platform-neutral identity-store trait with a hardened file backend and
platform hooks for macOS Keychain, Windows Credential Manager/DPAPI and Linux
Secret Service. Production startup must load a stable device identity or
return a typed enrollment-required state; it must not silently generate a new
identity for every process and must not use raw identity environment values
outside an explicit developer override. Add device enrollment/public-key,
trust/revocation and short-lived session credential records to a durable
SQLite-backed control-plane repository while leaving relay/signal state
ephemeral. Keep tokens out of logs, argv, React state and long-lived child
environments.

Acceptance tests to add:

* same device store returns the same identity across restarts;
* insecure permissions/symlinks/ownership fail closed;
* revoked device cannot obtain a session credential;
* session credentials expire and cannot be replayed;
* database restart preserves devices/trust but not active relay state.

### 3. Epoch-safe full ICE establishment

Files:

* `engine/lowlat/crates/signal-server/src/main.rs`
* `engine/lowlat/crates/client-core/src/lib.rs`
* `engine/lowlat/crates/protocol/src/lib.rs`

Add a server-authoritative monotonic establishment generation distinct from
WebSocket socket generations. Publish `ice_peer_ready(N)` only to the exact
current role sockets; invalidate N immediately on membership change. Replace
generic direct/ICE handshake ambiguity with explicit `ice_candidate_v2`,
`ice_candidate_done_v2`, and `ice_key_v2` envelopes carrying session ID,
generation and role. Stale records are discarded, future generations fail
closed, and no candidate/key deadline starts before readiness. Preserve the
existing direct-v2 protocol and ICE credential flow semantics where they are
independent. Bind session/generation/role/domain to the signed transcript.

Acceptance tests to add:

* host-first/client-late and client-first/host-late;
* role replacement after ready, after candidates, and during key exchange;
* stale socket and stale signed key rejection;
* duplicate current-generation records are idempotent;
* ICE remains compatible with existing credential/candidate plumbing and
  signaling queues do not delete unrelated envelopes.

### 4. Host truth and lifecycle

Files:

* `engine/lowlat/crates/host-agent/src/lib.rs`
* `engine/lowlat/crates/host-agent/src/main.rs`
* `engine/lowlat/crates/ffmpeg-host/src/main.rs`
* `engine/lowlat/crates/local-ipc/src/lib.rs`

Extend the child/agent contract with a bounded frame-liveness heartbeat and
configuration revision. `Ready` requires a recent frame or an explicit
capability-only mode; idle capture is distinguishable from a dead pipeline.
Stop/lifetime/restart paths wait for termination and reap before `Stopped` or
replacement. Start carries a revision/hash of the effective host config and
health reports the applied revision. Remove production use of
`OPENSTREAM_NATIVE_DRM_READY`; use the shared probe API and retain only a
clearly named developer assumption override. Keep Linux X11/FFmpeg/NVENC as
the truthful fallback when native DRM does not prove frame flow.

Acceptance tests to add:

* no-frame child never reaches Ready;
* frame heartbeat recovers after a temporary stall;
* stop force-kills and reaps an ignoring child;
* no replacement starts before reap;
* config revision mismatch is surfaced;
* DRM assumed-ready cannot advertise without the explicit developer override.

### 5. Session runner, input safety, and native window seam

Files:

* `engine/lowlat/crates/desktop-client/src/main.rs`
* `engine/lowlat/crates/desktop-client/src/session.rs`
* `engine/lowlat/crates/desktop-client/src/render.rs`
* `engine/lowlat/crates/media/src/input.rs`
* `engine/lowlat/crates/platform/src/policy.rs`
* new `engine/lowlat/crates/session-runner/` if separation is needed

Introduce a winit-owned session window while preserving the working FFmpeg
fallback. Add explicit window/VSync/immersive policies, focus-loss and
disconnect `ReleaseAll`, host watchdog expiry, separate keyboard/mouse grants,
sequenced latest-wins relative pointer motion, reliable key/button/release
events, and reserved release-input escape handling. Do not put media frames
through Tauri. Keep minifb only as a compatibility fallback during migration.

Acceptance tests to add:

* pointer motion coalesces without reordering key/button transitions;
* revoked keyboard/mouse permissions immediately release state;
* focus loss/disconnect/generation change releases all input;
* queue saturation remains bounded and preserves control priority;
* native window mode and VSync policies resolve deterministically.

### 6. macOS native decode/presentation backend

Files:

* new `engine/lowlat/crates/macos-media/`
* `engine/lowlat/crates/desktop-client/Cargo.toml`
* `engine/lowlat/crates/desktop-client/src/main.rs`
* `engine/lowlat/crates/desktop-client/src/render.rs`

Add a `target_os = "macos"` VideoToolbox decoder for Annex-B H.264 first,
then H.265, using `VTDecompressionSession`, callback timestamps/order and
`CVPixelBuffer`/IOSurface. Add a Metal presenter consuming the native surface
through `CVMetalTextureCache`, with explicit fallback to FFmpeg/BGRA/wgpu.
Keep frame ownership and callback teardown safe. Expose the selected decoder,
renderer and pixel format in diagnostics. Do not call this zero-copy unless
the native path actually reaches the surface presenter.

Acceptance tests to add:

* SPS/PPS/VPS format changes recreate the decoder safely;
* out-of-order callbacks are reordered by timestamps;
* callback after teardown is ignored safely;
* unsupported codec/pixel format selects FFmpeg fallback;
* native backend selection is capability-gated.

### 7. Product settings/control-plane wiring

Files:

* `engine/lowlat/crates/settings/src/lib.rs`
* `desktop/src-tauri/src/runtime.rs`
* `desktop/src-tauri/src/lib.rs`
* `desktop/src/App.tsx`
* `desktop/src/adapters/tauriAdapter.ts`

Complete settings descriptors with scope/apply/capability/visibility metadata,
profile layering (Performance/Balanced/Quality/Custom), host/client/network/
input/audio fields, and effective capability clamping. Wire the shell to
persisted settings and typed app-core state. Add truthful diagnostics and
typed warnings. The UI must never decide capabilities or expose pairing JSON,
tokens or private keys.

### 8. Release and evidence implementation

Files:

* `scripts/check-openstream-1-0-release.sh`
* `scripts/wan-acceptance.sh`
* `release/openstream-1.0-gates.tsv`
* new `scripts/build-release-artifacts.sh`
* new `scripts/generate-sbom.sh`
* new `scripts/verify-package-install.sh`
* `.github/workflows/ci.yml`

Add reproducible artifact staging, SHA-256 manifest, SPDX/CycloneDX SBOM
generation, package integrity checks, and explicit placeholders for signing,
notarization, public-WAN/TURN, hardware, upgrade and rollback evidence. CI
must verify source/tooling contracts and never turn an unperformed physical
test into PASS. Actual signing, notarization, WAN, NAT, TURN, package launch,
upgrade, rollback and long-soak evidence remain external final gates.

## Final verification pass

Only after all implementation work is complete:

1. inspect the complete diff and remove stale claims;
2. run format, clippy, workspace tests, Tauri tests, frontend tests/build;
3. run sanitizer/model-check/fuzz compile and release checks;
4. run Linux host preflight and physical Linux-NVIDIA → Apple-Silicon test;
5. run native/fallback decoder, input, audio and reconnect acceptance;
6. run direct/WAN/NAT/TURN/relay matrix where infrastructure is available;
7. run package install/launch/upgrade/rollback and signing checks where keys
   and installers are available;
8. update release evidence only from observed results;
9. report remaining blockers and do not tag unless the release checker says
   `READY`.
