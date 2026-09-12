# OpenStream Local-First Production MVP Implementation Plan

> **Status:** implementation complete locally; production review hardening
> complete; protected PR CI pending as of 2026-09-12.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Productize the tested Linux-host/Apple-Silicon-client path with persistent local-first control, a background host agent, typed diagnostics, and secure-mode compatibility.

**Architecture:** Keep transport/media crates independent. Add dependency-light settings and domain crates above them, expose a bounded Unix-socket IPC protocol, and make a host agent supervise the proven FFmpeg fallback. Trusted LAN mode - no account authentication - is explicit and constrained; encrypted session capabilities and secure bearer-token mode remain intact.

**Tech Stack:** Rust 2024, serde/JSON, Tokio, Unix-domain sockets on Linux/macOS, existing `openstream-client-core`, `openstream-ffmpeg-host`, `openstream-platform`, systemd units, shell acceptance fixtures.

**Spec:** `docs/superpowers/specs/2026-09-12-openstream-local-first-production-mvp-design.md`

## Global Constraints

- Keep the existing OpenStream wire format and `PeerSession` transport boundary unchanged unless a task explicitly requires a compatible extension.
- `OPENSTREAM_ALLOW_NO_AUTH=1` remains loopback-only; Trusted LAN mode - no account authentication - requires `OPENSTREAM_LOCAL_NO_AUTH=1` and one explicit RFC1918/ULA/link-local bind. Private addressing is not an identity or authentication boundary.
- Role-scoped session capabilities and encrypted peer identity remain required even when account/admin authentication is disabled.
- Settings files contain no bearer tokens, pairing JSON, private keys, TURN passwords, relay tickets, clipboard content, audio, or frame data.
- Environment variables are validated developer/headless overrides and are never persisted automatically.
- Every new queue, socket frame, process restart, and IPC request has a finite bound.
- Native DRM failure must select/report the tested X11/FFmpeg/NVENC fallback; no backend is advertised without a capability result.
- Use TDD: add a failing focused test, run it, implement the smallest change, rerun focused tests, then run relevant workspace checks and commit.

---

### Task 1: Add validated versioned application settings

**Files:**
- Create: `engine/lowlat/crates/settings/Cargo.toml`
- Create: `engine/lowlat/crates/settings/src/lib.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Test: `engine/lowlat/crates/settings/src/lib.rs` unit tests
- Modify: `docs/BUILD.md` with the settings path and secret-file rules

**Interfaces:**
- Produces `openstream-settings::AppConfig`, `SettingsError`, `SettingsFile`, `SecretRef`, `load`, `save_atomic`, and `apply_environment_overrides`.
- Consumes only `serde`, `serde_json`, and standard filesystem APIs.

- [x] Step 1: Add failing tests for default config, unknown-field tolerance, schema migration, invalid enum/value rejection, atomic-save permissions, and secret-free serialization.
- [x] Step 2: Run `cargo test -p openstream-settings --locked`; verify the new tests fail because the crate/types do not exist.
- [x] Step 3: Add the crate and workspace member. Define `AppConfig` with separate device/client/host/video/audio/input/network/privacy/advanced sections and explicit schema version `1`.
- [x] Step 4: Implement deterministic migration from schema `0` to `1`, reject newer schemas, validate all bounded numbers/strings, and keep the original file untouched on migration failure.
- [x] Step 5: Implement `save_atomic(path, config)` through a same-directory temporary file, restrictive Unix permissions where available, flush/rename, and no secret fields. Implement environment overrides as a non-persisting transformation.
- [x] Step 6: Run `cargo test -p openstream-settings --locked`, `cargo fmt --manifest-path engine/lowlat/Cargo.toml --all -- --check`, and Clippy for the crate.
- [x] Step 7: Commit `feat: add validated persistent application settings`.

**Expected result:** A host/client can load a versioned, validated configuration without storing credentials or relying on environment variables for ordinary settings.

### Task 2: Add the pure application/domain state model

**Files:**
- Create: `engine/lowlat/crates/app-core/Cargo.toml`
- Create: `engine/lowlat/crates/app-core/src/lib.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Test: `engine/lowlat/crates/app-core/src/lib.rs` unit tests

**Interfaces:**
- Produces `AppState`, `AppCommand`, `AppEvent`, `DeviceSummary`, `ConnectionRequest`, `PermissionSet`, `HostStatus`, `DiagnosticSnapshot`, and typed `AppErrorCode`.
- Consumes `openstream-settings`; it does not perform I/O, REST, WebSocket, FFmpeg, or UI work.

- [x] Step 1: Add failing transition tests for local ready, connect/approval expiry, connect success, reconnect, disconnect, host enable/disable, invalid permission escalation, and typed retryable/fatal errors.
- [x] Step 2: Run `cargo test -p openstream-app-core --locked`; verify the transition API is absent/failing.
- [x] Step 3: Implement the bounded state machine and command/event types with serde-safe data that excludes credentials and user content.
- [x] Step 4: Implement permission intersection so requested grants can only reduce to host policy/capability, never escalate; reject expired or duplicate request IDs.
- [x] Step 5: Run focused tests, Clippy, and a serde round-trip test suite.
- [x] Step 6: Commit `feat: add OpenStream application domain state`.

**Expected result:** UI, agent, and future control-server adapters can share one state model without embedding transport logic in the frontend.

### Task 3: Add explicit Trusted LAN mode - no account authentication

**Files:**
- Modify: `engine/lowlat/crates/signal-server/src/main.rs`
- Modify: `engine/lowlat/crates/signal-server/Cargo.toml` only if a small existing workspace dependency is required
- Test: signal-server unit tests
- Modify: `deploy/README.md`, `README.md`, `docs/BUILD.md`

**Interfaces:**
- Produces `OPENSTREAM_LOCAL_NO_AUTH=1` configuration behavior and a typed/startup error for invalid binds.
- Preserves `OPENSTREAM_ALLOW_NO_AUTH=1` loopback-only behavior and all role-token/session-capability checks.

- [x] Step 1: Add failing tests for private IPv4/IPv6 binds, wildcard/public rejection, missing opt-in rejection, secure-mode rejection, and role capability enforcement in local mode.
- [x] Step 2: Run `cargo test -p openstream-signal-server --locked`; verify the new config field/validation is absent.
- [x] Step 3: Add explicit config parsing and private-address validation. Reject wildcard/public binds and require no admin token before enabling local mode.
- [x] Step 4: Make management authorization bypass apply only to the explicitly scoped local mode; keep WebSocket/relay role bearer checks unchanged.
- [x] Step 5: Add a redacted startup warning and docs with a prominent LAN-trust warning and secure-mode migration path.
- [x] Step 6: Run focused signal tests, startup-order smoke, full workspace tests, and Clippy.
- [x] Step 7: Commit `feat: add explicit private-LAN development mode`.

**Expected result:** Local devices can use the product without account login, but an accidental public/wildcard unauthenticated deployment fails closed.

### Task 4: Add protected Unix IPC framing

**Files:**
- Create: `engine/lowlat/crates/local-ipc/Cargo.toml`
- Create: `engine/lowlat/crates/local-ipc/src/lib.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Test: `engine/lowlat/crates/local-ipc/src/lib.rs` unit tests

**Interfaces:**
- Produces `IpcRequest`, `IpcResponse`, `IpcEvent`, `MAX_FRAME_BYTES`, `encode_frame`, `decode_frame`, and Unix `Endpoint`/listener helpers.
- Messages carry a bounded request ID and contain only app-domain values; secrets are forbidden by type/schema.

- [x] Step 1: Add failing tests for length framing, zero/oversized frames, malformed JSON, request-ID correlation, safe path creation, and socket permission expectations.
- [x] Step 2: Run focused tests and verify failure.
- [x] Step 3: Implement bounded length-prefix framing and serde message types; reject frames above `64 KiB` before allocation.
- [x] Step 4: Implement Unix socket endpoint preparation with private parent/socket permissions and explicit cleanup semantics.
- [x] Step 5: Run tests on macOS/Linux targets, Clippy, and a local endpoint request/response fixture.
- [x] Step 6: Commit `feat: add protected local IPC protocol`.

**Expected result:** A desktop shell can communicate with a background agent through a bounded local-only interface.

### Task 5: Add host-agent lifecycle supervision

**Files:**
- Create: `engine/lowlat/crates/host-agent/Cargo.toml`
- Create: `engine/lowlat/crates/host-agent/src/lib.rs`
- Create: `engine/lowlat/crates/host-agent/src/main.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Modify: `deploy/openstream-ffmpeg-host.service` or add `deploy/openstream-host-agent.service`
- Test: host-agent unit tests and process fixture

**Interfaces:**
- Produces `HostAgent`, `HostAgentCommand`, `HostAgentEvent`, `HostAgentConfig`, `ChildPolicy`, and `HostHealth`.
- Uses `openstream-settings`, `openstream-app-core`, `local-ipc`, and a typed child-command builder; it never concatenates shell commands.

- [x] Step 1: Add failing tests for start/stop idempotence, child exit classification, bounded restart backoff, stop-before-restart, status snapshots, and secret-redacted diagnostics.
- [x] Step 2: Run focused tests and verify failure.
- [x] Step 3: Implement the supervisor around the existing `openstream-ffmpeg-host` executable with validated environment/config projection and bounded child lifetime.
- [x] Step 4: Add `run_preflight` and fallback reporting: native DRM is selected only when preflight says reachable; otherwise X11/PipeWire/FFmpeg is explicit.
- [x] Step 5: Add Unix IPC serving for lifecycle/status commands and graceful SIGTERM handling; keep UI closure independent from child hosting.
- [x] Step 6: Add/update systemd user unit with the agent as `ExecStart`, documented environment-file permissions, restart limits, and no secret command-line arguments.
- [x] Step 7: Run unit tests and a two-process local agent fixture. The systemd syntax check is environment-dependent and was unavailable on macOS; the Linux→macOS fallback check remains the physical acceptance gate.
- [x] Step 8: Commit `feat: add persistent host-agent supervision`.

**Expected result:** Hosting continues when the desktop shell exits, and operator-visible health/fallback state is available through local IPC.

### Task 6: Integrate local-first session launch without raw pairing UX

**Files:**
- Modify: `engine/lowlat/crates/client/src/main.rs` and/or `engine/lowlat/crates/desktop-client/src/main.rs`
- Create: `scripts/openstream-local-session.sh`
- Modify: `docs/BUILD.md`, `README.md`
- Test: client/session-launch tests and shell smoke

**Interfaces:**
- Produces a developer/headless launch path that reads pairing material from a private runtime file or stdin, never from committed config; normal app-core commands receive only opaque session IDs.

- [x] Step 1: Add failing tests for missing/over-permissive pairing-file permissions, no secret echo, bounded session duration, and graceful child shutdown.
- [x] Step 2: Implement a local launch helper and shared pairing-file loader with private temporary state, cleanup traps, and an explicit developer-only JSON override.
- [x] Step 3: Replace normal documentation and smoke examples that paste pairing JSON into environment variables with the helper/config flow while retaining an explicitly marked developer override.
- [x] Step 4: Run startup-order and portable-transport acceptance plus the local FFmpeg fallback smoke; retain the previously recorded Linux NVIDIA -> macOS hardware run as the physical acceptance gate, with all output redacted.
- [x] Step 5: Commit `feat: add local-first session launch flow`.

**Expected result:** The tested host/client path is repeatable without making raw bearer/pairing data part of ordinary user workflow.

### Task 7: Capability-gate advanced device features

**Files:**
- Modify: `engine/lowlat/crates/platform/src/policy.rs`
- Modify: `engine/lowlat/crates/media/src/input.rs`, `engine/lowlat/crates/inject/src/*`, and platform adapters as needed
- Test: platform/media/inject unit tests
- Modify: `docs/FEATURE_MATRIX.md`, `docs/ARCHITECTURE.md`

**Interfaces:**
- Produces a typed `DeviceCapability`/`UnavailableReason` surface for input, clipboard, microphone, gamepad, tablet, virtual display, and virtual USB.
- Existing protocol messages remain backward compatible; unsupported OS adapters return typed results and do not claim readiness.

- [x] Step 1: Add failing tests that distinguish protocol support, host permission, OS API availability, and hardware validation.
- [x] Step 2: Implement capability discovery and strict advertisement from actual adapter availability.
- [x] Step 3: Keep Linux uinput implementation enabled behind explicit policy; add safe no-op/error adapters for unimplemented Windows/macOS virtual devices instead of false success.
- [x] Step 4: Run workspace tests and update the feature matrix with implementation-versus-tested labels.
- [x] Step 5: Commit `feat: make advanced device capabilities truthful`.

**Expected result:** Controller/USB/microphone/tablet/virtual-display features have real implementation seams and honest capability gates, even when hardware tests are deferred.

### Task 8: Diagnostics export, packaging gates, and release acceptance

**Files:**
- Create/modify: `engine/lowlat/crates/diagnostics/*`
- Modify: `.github/workflows/ci.yml`, `deploy/*`, `scripts/*`, `docs/BUILD.md`, `README.md`
- Test: redaction/export tests, artifact smoke, Linux host/macOS client acceptance

**Interfaces:**
- Produces `DiagnosticBundle`, redaction policy, release manifest, and acceptance-report schema.

- [x] Step 1: Add failing redaction tests for tokens, keys, pairing JSON, clipboard, and user paths.
- [x] Step 2: Implement bounded JSON/text export and artifact checks; no raw log or settings file is copied without redaction.
- [x] Step 3: Add CI checks for settings/app-core/local-ipc/agent, C/C++ ABI, cargo-deny, secret scanning, artifact manifest/presence validation, and Linux/macOS fallback documentation.
- [x] Step 4: Run the complete local release gate and retain the recorded physical Linux NVIDIA -> macOS acceptance without claiming native DRM/zero-copy. Package signatures, notarization, checksums/SBOM, package launch, upgrade/rollback, and package-integrity gates remain deferred.
- [x] Step 5: Commit `chore: add production MVP diagnostics and release gates`.

**Expected result:** The release artifact manifest/presence checks identify the operator-facing outputs, and support bundles cannot leak credentials or user content. Full signed-package validation remains a later release gate.

## Self-review checklist

- [x] Scope is decomposed into independently testable settings, domain, auth, IPC, agent, launch, device, and release tasks.
- [x] Trusted LAN mode - no account authentication is explicit, private-address constrained, and does not remove encrypted session capabilities.
- [x] Secure deployment mode remains the default outside explicit local/test binds.
- [x] Native DRM/VideoToolbox/zero-copy and WAN claims remain separate acceptance gates.
- [x] Each task has concrete files, interfaces, tests, commands, and a commit boundary.
- [x] No task allows secrets in persisted settings, IPC, logs, or command-line arguments.
