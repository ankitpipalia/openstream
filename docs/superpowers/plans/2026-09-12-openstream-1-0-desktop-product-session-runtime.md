# OpenStream 1.0 Desktop Product and Session Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver and verify the OpenStream 1.0 Linux-NVIDIA-host to Apple-Silicon-macOS-client product flow, then publish a truthful signed release.

**Architecture:** Keep the existing Rust transport, protocol, host-agent, and FFmpeg/X11/NVENC fallback foundation. Add a Rust session runner for the latency-critical window, a Rust-owned settings/capability contract, a durable control/device layer, and a Tauri 2 + React shell that communicates through app-core/local IPC. Keep hosting independent from the UI process.

**Tech Stack:** Rust 2024 workspace, winit, wgpu/Metal, VideoToolbox FFI, Tokio/Axum/WebSocket/TURN, SQLite/WAL, Tauri 2, React, TypeScript, Vitest, GitHub Actions, Linux systemd/deb packaging, macOS arm64 DMG/signing/notarization.

**Spec:** `docs/superpowers/specs/2026-09-12-openstream-1-0-desktop-product-session-runtime-design.md`

## Global Constraints

- Baseline is `5b0e87807d8e4050b92daca85523e561e01ae4c7`.
- Supported 1.0 host is Linux x86-64 NVIDIA using X11 → FFmpeg → NVENC.
- Supported 1.0 client is Apple-Silicon macOS using VideoToolbox + Metal with FFmpeg fallback.
- Balanced is the default streaming profile; Performance, Quality, and Custom are deterministic policies.
- Native DRM, Windows/macOS hosting, virtual display, USB passthrough, HDR, tablet pressure/tilt, simultaneous multi-monitor windows, chat, and polished mobile clients remain capability-gated and are not 1.0 blockers.
- No session bearer, TURN password, relay ticket, pairing JSON, or private identity key may be persisted in argv, environment, logs, or settings JSON.
- Every production behavior change starts with a failing behavior test and must show the expected failure before implementation.
- Every implementation worker uses `gpt-5.6-luna` with `reasoning_effort=max`, an isolated worktree, and a disjoint write set.
- Every task receives a scoped review before integration; the final tag waits for the complete automated and physical release gates.
- If hardware, WAN, signing, or notarization evidence is unavailable, report the exact gate as unverified and do not describe it as production-ready.

---

### Task 1: Settings schema v2, profiles, and capability descriptors

**Files:**
- Modify: `engine/lowlat/crates/settings/src/lib.rs`
- Modify: `engine/lowlat/crates/settings/Cargo.toml` only if a migration helper is required
- Modify: `engine/lowlat/crates/app-core/src/lib.rs`
- Modify: `engine/lowlat/crates/platform/src/policy.rs`
- Create: `engine/lowlat/crates/settings/src/descriptors.rs`
- Test: unit tests in `settings/src/lib.rs` and `app-core/src/lib.rs`

**Interfaces:**
- Produces `SettingsFile` schema version 2 and an explicit v1-to-v2 migration.
- Produces `StreamProfile::{Performance,Balanced,Quality,Custom}` and a deterministic effective-config resolver.
- Produces `SettingDescriptor { key, scope, apply_mode, capability, visibility }`.
- Produces independent `InputConfig` permissions for keyboard, mouse, gamepad, clipboard, and microphone.

- [ ] **Step 1: Write failing migration and resolver tests**

```rust
#[test]
fn schema_v1_migrates_to_v2_with_balanced_defaults() {
    let loaded = load_json(v1_fixture()).expect("migration");
    assert_eq!(loaded.config.schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(loaded.config.client.profile, StreamProfile::Balanced);
}

#[test]
fn editing_a_low_level_value_selects_custom_without_losing_profile_defaults() {
    let mut config = AppConfig::default();
    config.client.profile = StreamProfile::Balanced;
    config.client.fps = 120;
    assert_eq!(effective_config(&config).profile, StreamProfile::Custom);
}
```

- [ ] **Step 2: Run the focused tests and confirm the missing schema/profile behavior fails**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-settings -p openstream-app-core`

- [ ] **Step 3: Implement the migration, policy resolver, descriptors, and permission fields**

Use serde defaults for fields added in v2, reject newer schema versions, and keep
unknown enum values representable as `Unknown(String)` so old clients fail
truthfully rather than silently selecting a different backend.

- [ ] **Step 4: Run focused tests, workspace tests, and Clippy**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-settings -p openstream-app-core`

Run: `cargo clippy --manifest-path engine/lowlat/Cargo.toml --workspace --all-targets --all-features --locked -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/settings engine/lowlat/crates/app-core engine/lowlat/crates/platform
git commit -m "feat: add OpenStream settings v2 contracts"
```

### Task 2: Native session runner and window contract

**Files:**
- Create: `engine/lowlat/crates/session-runner/Cargo.toml`
- Create: `engine/lowlat/crates/session-runner/src/lib.rs`
- Create: `engine/lowlat/crates/session-runner/src/window.rs`
- Create: `engine/lowlat/crates/session-runner/src/hotkeys.rs`
- Modify: `engine/lowlat/Cargo.toml`
- Modify: `engine/lowlat/crates/desktop-client/src/main.rs` only to delegate session startup
- Test: `session-runner/src/window.rs` and `session-runner/src/hotkeys.rs`

**Interfaces:**
- `SessionRunner::new(SessionDescriptor, EffectiveClientConfig)` owns one session window.
- `WindowMode::{Windowed,Borderless,Fullscreen}` is platform-independent at the contract layer.
- `WindowEvent::{Focused(bool),Resized,CloseRequested,DeviceMotion,Keyboard,MouseButton,Wheel}` feeds the session loop.
- The runner consumes existing `PeerSession` and decoder interfaces without moving account/control-plane code into the session process.

- [ ] **Step 1: Write failing window-mode and hotkey tests**

```rust
#[test]
fn display_mode_parses_only_known_values() {
    assert_eq!(WindowMode::parse("fullscreen"), WindowMode::Fullscreen);
    assert_eq!(WindowMode::parse("unknown"), WindowMode::Windowed);
}

#[test]
fn release_input_hotkey_is_always_reserved() {
    let bindings = HotkeyMap::from_user_bindings(user_bindings_without_release());
    assert!(bindings.contains(HotkeyAction::ReleaseInput));
}
```

- [ ] **Step 2: Run focused tests and verify they fail because the runner contract is absent**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-session-runner`

- [ ] **Step 3: Add the crate and migrate window creation from minifb to winit**

Use native macOS fullscreen/Spaces behavior, borderless mode without fake
fullscreen state, proper resize/scaling, focus events, and a wgpu presenter
adapter. Keep FFmpeg/BGRA presentation as the first compatibility path.

- [ ] **Step 4: Run runner tests and the desktop-client tests**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-session-runner -p openstream-desktop-client`

- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/Cargo.toml engine/lowlat/crates/session-runner engine/lowlat/crates/desktop-client
git commit -m "feat: add native OpenStream session runner"
```

### Task 3: Production keyboard and mouse input

**Files:**
- Modify: `engine/lowlat/crates/client-core/src/lib.rs`
- Modify: `engine/lowlat/crates/protocol/src/lib.rs`
- Modify: `engine/lowlat/crates/host/src/events.rs` for host-side input admission
- Modify: `engine/lowlat/crates/inject/src/lib.rs`
- Modify: `engine/lowlat/crates/session-runner/src/lib.rs`
- Modify: `engine/lowlat/crates/session-runner/src/window.rs`
- Modify: `engine/lowlat/crates/session-runner/src/hotkeys.rs`
- Modify: `engine/lowlat/crates/app-core/src/lib.rs`
- Test: protocol/client-core/host input tests and a deterministic input watchdog test

**Interfaces:**
- `InputPermissions { keyboard, mouse, gamepad, clipboard, microphone }` is enforced by the host adapter.
- `PointerMotion { generation, sequence, dx, dy }` is latest-wins and non-retransmitted.
- Key/button transitions and `ReleaseAll` remain reliable, ordered, and high priority.
- `InputWatchdog` releases all injected state after authenticated liveness expiry.

- [ ] **Step 1: Write failing tests for permission separation, coalescing, and cleanup**

```rust
#[test]
fn revoking_mouse_does_not_revoke_keyboard() {
    let permissions = InputPermissions { keyboard: true, mouse: false, ..InputPermissions::none() };
    let admission = InputAdmission::new(permissions);
    assert!(admission.accepts(InputEvent::KeyDown { usage: 0x04 }));
    assert!(!admission.accepts(InputEvent::PointerMotion { dx: 2, dy: -1 }));
}

#[test]
fn pointer_motion_coalesces_without_reordering_key_transitions() {
    let mut queue = InputQueue::default();
    queue.push(InputEvent::PointerMotion { dx: 3, dy: 1 });
    queue.push(InputEvent::KeyDown { usage: 0x04 });
    queue.push(InputEvent::PointerMotion { dx: 4, dy: 2 });
    assert_eq!(queue.drain(), vec![
        InputEvent::PointerMotion { dx: 7, dy: 3 },
        InputEvent::KeyDown { usage: 0x04 },
    ]);
}

#[test]
fn focus_loss_and_timeout_emit_release_all() {
    let mut watchdog = InputWatchdog::new(Duration::from_secs(2));
    watchdog.observe(InputEvent::KeyDown { usage: 0x04 }, Instant::now());
    assert_eq!(watchdog.on_focus_lost(), vec![InputEvent::ReleaseAll]);
    assert_eq!(watchdog.on_tick(Instant::now() + Duration::from_secs(3)), vec![InputEvent::ReleaseAll]);
}
```

- [ ] **Step 2: Run the focused tests and observe the expected failures**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-protocol -p openstream-client-core -p lowlat-host -p lowlat-inject`

- [ ] **Step 3: Implement raw `winit::event::DeviceEvent::MouseMotion`, transport policy, permissions, watchdog, and release cleanup**

Unlock/show the cursor and stop forwarding after Release Input. Re-grab only
after explicit session focus. Never log actual key values in diagnostics.

- [ ] **Step 4: Run focused and workspace tests; record the physical Mac-to-Linux matrix as pending evidence**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml --workspace --locked -- --test-threads=1`

- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/client-core engine/lowlat/crates/protocol engine/lowlat/crates/host engine/lowlat/crates/inject engine/lowlat/crates/session-runner engine/lowlat/crates/app-core
git commit -m "feat: harden production keyboard and mouse input"
```

### Task 4: macOS VideoToolbox and Metal presentation

**Files:**
- Create: `engine/lowlat/crates/session-runner/src/macos/video_toolbox.rs`
- Create: `engine/lowlat/crates/session-runner/src/macos/metal_presenter.rs`
- Modify: `engine/lowlat/crates/session-runner/src/decoder.rs`
- Modify: `engine/lowlat/crates/platform/src/hwaccel.rs`
- Modify: `engine/lowlat/crates/desktop-client/src/render.rs` only for compatibility routing
- Test: parser/negotiation/fallback tests and macOS target compilation

**Interfaces:**
- `DecoderBackend::{Auto,VideoToolbox,Ffmpeg,Software}` resolves through the capability catalog.
- `VideoToolboxDecoder::decode_annex_b(&[u8]) -> Result<DecodedSurface, DecodeError>` returns a CVPixelBuffer-backed surface on macOS.
- `MetalPresenter::present(DecodedSurface, PresentOptions)` consumes IOSurface/CVMetalTextureCache surfaces without a BGRA CPU copy.

- [ ] **Step 1: Write failing backend-selection and fallback tests**

```rust
#[test]
fn auto_selects_videotoolbox_only_when_capability_is_usable() {
    let capabilities = DecoderCapabilities { videotoolbox: CapabilityState::Ready, ffmpeg: CapabilityState::Ready };
    assert_eq!(resolve_decoder(DecoderMode::Auto, capabilities), DecoderBackend::VideoToolbox);
}

#[test]
fn unavailable_videotoolbox_falls_back_to_ffmpeg() {
    let capabilities = DecoderCapabilities { videotoolbox: CapabilityState::Unavailable("not on Linux"), ffmpeg: CapabilityState::Ready };
    assert_eq!(resolve_decoder(DecoderMode::Auto, capabilities), DecoderBackend::Ffmpeg);
}
```

- [ ] **Step 2: Run tests and confirm the native backend is not yet present**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-session-runner -p openstream-platform`

- [ ] **Step 3: Implement H.264 VideoToolbox, IOSurface/Metal presentation, and explicit FFmpeg fallback**

Keep H.265 behind the same capability gate; do not claim 10-bit or 4:4:4
presentation until P010/10-bit display evidence exists.

- [ ] **Step 4: Run macOS target checks and fallback tests**

Run: `cargo check --manifest-path engine/lowlat/Cargo.toml -p openstream-session-runner --target aarch64-apple-darwin --locked`

- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/session-runner engine/lowlat/crates/platform engine/lowlat/crates/desktop-client
git commit -m "feat: add macOS VideoToolbox session decoding"
```

### Task 5: Durable device and control plane

**Files:**
- Modify: `engine/lowlat/crates/signal-server/src/main.rs`
- Modify: `engine/lowlat/crates/signal-server/src/turn.rs`
- Create: `engine/lowlat/crates/signal-server/src/store.rs`
- Create: `engine/lowlat/crates/signal-server/src/schema.sql`
- Modify: `engine/lowlat/crates/app-core/src/lib.rs`
- Modify: `engine/lowlat/crates/local-ipc/src/lib.rs`
- Test: store, enrollment, approval, credential-expiry, and audit tests

**Interfaces:**
- Repositories cover `users`, `devices`, `device_public_keys`, `device_credentials`,
  `device_memberships`, `trusted_device_policies`, `shares`, `audit_events`,
  `presence`, and `active_sessions`.
- `DeviceService::{enroll,list,trust,revoke}` owns durable identity.
- `SessionCredentialIssuer::issue_ephemeral(request) -> ExpiringSessionCredential` never persists bearer material.
- `ConnectionRequest::{requested,approved,rejected,expired}` is explicit and observable by both peers.

- [ ] **Step 1: Write failing repository and credential-lifetime tests**

```rust
#[test]
fn revoked_device_cannot_issue_a_new_session_credential() {
    let store = TestStore::new();
    let device = store.enroll_device("macbook", public_key(1));
    store.revoke_device(device.id).unwrap();
    assert!(matches!(store.issue_session_credential(device.id), Err(StoreError::DeviceRevoked)));
}

#[test]
fn expired_connection_request_reaches_client_as_rejected_not_timeout() {
    let mut requests = ConnectionRequests::new(Duration::from_secs(5));
    let id = requests.create(device_id(1), Instant::now());
    let events = requests.expire(Instant::now() + Duration::from_secs(6));
    assert_eq!(events, vec![ConnectionEvent::Rejected { request_id: id, reason: RejectReason::Expired }]);
}
```

- [ ] **Step 2: Run the signal-server and app-core tests and confirm missing persistence behavior**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-signal-server -p openstream-app-core -p openstream-local-ipc`

- [ ] **Step 3: Implement SQLite/WAL schema, repository traits, device enrollment, presence, approval, audit, and ephemeral issuance**

Keep the signaling engine transport-compatible with the production MVP and put
database access behind traits so PostgreSQL can be added later.

- [ ] **Step 4: Run focused tests and the local signal smoke script**

Run: `bash scripts/path-migration-smoke.sh`

- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/signal-server engine/lowlat/crates/app-core engine/lowlat/crates/local-ipc
git commit -m "feat: add durable device control plane"
```

### Task 6: Desktop product shell

**Files:**
- Create: `desktop/package.json`
- Create: `desktop/src-tauri/tauri.conf.json`
- Create: `desktop/src-tauri/src/lib.rs`
- Create: `desktop/src-tauri/src/commands.rs`
- Create: `desktop/src/main.tsx`
- Create: `desktop/src/app/App.tsx`
- Create: `desktop/src/app/routes.tsx`
- Create: `desktop/src/styles/tokens.css`
- Create: `desktop/src/styles/base.css`
- Create: `desktop/tests/app.test.tsx`
- Create: `desktop/tests/capability.test.tsx`
- Modify: `engine/lowlat/crates/app-core/src/lib.rs` for stable command/event DTOs

**Interfaces:**
- Rust commands expose app-core state snapshots, settings descriptors, devices,
  host status, diagnostics, and connection requests.
- React pages are `Computers`, `Access`, `Settings`, `Diagnostics`, and `About`.
- React never performs transport, token, pairing-file, or host-process logic.

- [ ] **Step 1: Write failing frontend tests for navigation and capability rendering**

```ts
it('renders unavailable capabilities with their reason', () => {
  render(<CapabilityRow capability={{ state: 'unavailable', reason: 'uinput permission denied' }} />)
  expect(screen.getByText('uinput permission denied')).toBeVisible()
})
```

- [ ] **Step 2: Run the frontend tests and confirm the shell/components are absent**

Run: `cd desktop && npm test -- --run`

- [ ] **Step 3: Implement the Tauri shell and real Rust IPC DTOs**

Use OpenStream branding and original UI components; use Parsec research only
for functional comparison, never proprietary code or visual assets.

- [ ] **Step 4: Run frontend lint/type/test and the Tauri compile check**

Run: `cd desktop && npm run lint && npm run typecheck && npm test -- --run`

- [ ] **Step 5: Commit**

```bash
git add desktop engine/lowlat/crates/app-core
git commit -m "feat: add OpenStream desktop product shell"
```

### Task 7: Connection and approval product flow

**Files:**
- Modify: `desktop/src/app/pages/Computers.tsx`
- Modify: `desktop/src/app/pages/Access.tsx`
- Create: `desktop/src/app/components/ConnectionRequest.tsx`
- Create: `desktop/src/app/components/GuestPermissions.tsx`
- Modify: `desktop/src-tauri/src/commands.rs`
- Modify: `engine/lowlat/crates/app-core/src/lib.rs`
- Test: frontend flow tests and app-core state-transition tests

**Interfaces:**
- `Connect(device_id, profile)` enters `Connecting → Negotiating → Connected`.
- Host approval produces `Approved`, `Rejected`, or `Expired` explicitly.
- Guest permission changes update the active session and emit `ReleaseAll` before revocation.
- Session runner receives a protected descriptor through local IPC.

- [ ] **Step 1: Write failing state-machine and UI flow tests**

```rust
#[test]
fn connect_requires_approval_for_an_untrusted_device() {
    let mut model = AppModel::new(test_services());
    model.dispatch(AppCommand::Connect { device_id: device_id(1), profile: StreamProfile::Balanced }).unwrap();
    assert_eq!(model.state(), AppState::AwaitingApproval { device_id: device_id(1) });
}
```

```ts
it('shows explicit rejection instead of a generic connection timeout', async () => {
  render(<ConnectionRequest request={{ state: 'rejected', reason: 'expired' }} />)
  expect(screen.getByText('Connection request expired')).toBeVisible()
})
```

- [ ] **Step 2: Run focused tests and observe the missing transitions**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-app-core`

Run: `cd desktop && npm test -- --run src/app/components/ConnectionRequest.test.tsx`
- [ ] **Step 3: Implement discovery, connect, approval, live permissions, launch, reconnect, and disconnect**
- [ ] **Step 4: Run frontend and Rust tests**
- [ ] **Step 5: Commit**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-app-core -p openstream-local-ipc`

```bash
git add desktop engine/lowlat/crates/app-core engine/lowlat/crates/local-ipc
git commit -m "feat: add desktop connection approval flow"
```

### Task 8: Settings, host onboarding, and diagnostics UI

**Files:**
- Modify: `desktop/src/app/pages/Settings.tsx`
- Modify: `desktop/src/app/pages/Diagnostics.tsx`
- Create: `desktop/src/app/components/SettingControl.tsx`
- Create: `desktop/src/app/components/CapabilityState.tsx`
- Create: `desktop/src/app/components/HostPreflight.tsx`
- Modify: `desktop/src-tauri/src/commands.rs`
- Modify: `engine/lowlat/crates/diagnostics/src/lib.rs`
- Test: descriptor-driven rendering and redacted-export tests

**Interfaces:**
- Every control is generated from `SettingDescriptor` and displays scope,
  apply mode, capability, and experimental/unavailable reason.
- Host onboarding reports GPU, X11, NVENC, uinput, audio, and network state.
- Diagnostics export remains field-aware redacted JSON and text.

- [ ] **Step 1: Write failing descriptor-rendering and diagnostics tests**

```ts
it('renders the apply mode and experimental state from Rust metadata', () => {
  render(<SettingControl descriptor={{ key: 'native_drm', apply_mode: 'restart_host', visibility: 'experimental', capability: 'unavailable' }} />)
  expect(screen.getByText('Restart host')).toBeVisible()
  expect(screen.getByText('Experimental')).toBeVisible()
})
```

```rust
#[test]
fn diagnostics_export_redacts_new_capability_and_credential_fields() {
    let export = export_redacted(test_diagnostics_with_secret_fields()).unwrap();
    assert!(!export.json.contains("turn-password-sentinel"));
    assert!(!export.text.contains("private-key-sentinel"));
}
```

- [ ] **Step 2: Run them to confirm the UI cannot yet consume descriptors**

Run: `cd desktop && npm test -- --run src/app/components/SettingControl.test.tsx`

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-diagnostics`
- [ ] **Step 3: Implement client/host/network/audio/input/advanced sections and onboarding**
- [ ] **Step 4: Run frontend tests, redaction tests, and local preflight checks**
- [ ] **Step 5: Commit**

```bash
git add desktop engine/lowlat/crates/diagnostics
git commit -m "feat: add descriptor-driven settings and diagnostics"
```

### Task 9: Tray/menu-bar integration and stay-awake

**Files:**
- Modify: `engine/lowlat/crates/tray/src/main.rs`
- Create: `engine/lowlat/crates/host-agent/src/power.rs`
- Modify: `engine/lowlat/crates/host-agent/src/lib.rs`
- Modify: `desktop/src-tauri/src/lib.rs`
- Test: menu-state and power-inhibitor lifecycle tests

**Interfaces:**
- Tray commands distinguish `QuitUi` from `StopHosting`.
- `SleepInhibitor` is RAII and held while hosting or a session is active.
- Menu state exposes hosting readiness, active guest, disconnect, update, and open UI.

- [ ] **Step 1: Write failing lifecycle/menu tests**

```rust
#[test]
fn quitting_ui_does_not_stop_background_hosting() {
    let mut menu = TrayModel::hosting_ready();
    menu.dispatch(TrayCommand::QuitUi);
    assert!(menu.hosting_continues());
    assert!(!menu.ui_visible());
}
```

- [ ] **Step 2: Run them and confirm the tray stub/power behavior fails**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p lowlat-tray -p openstream-host-agent`
- [ ] **Step 3: Implement native platform adapters and host-agent ownership**
- [ ] **Step 4: Run platform-target checks and tray tests**
- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/tray engine/lowlat/crates/host-agent desktop/src-tauri
git commit -m "feat: add hosting tray and stay-awake lifecycle"
```

### Task 10: In-session overlay and warnings

**Files:**
- Create: `engine/lowlat/crates/session-runner/src/overlay.rs`
- Create: `engine/lowlat/crates/session-runner/src/warnings.rs`
- Modify: `engine/lowlat/crates/session-runner/src/lib.rs`
- Modify: `desktop/src-tauri/src/commands.rs` for session actions
- Test: warning-threshold and overlay-model tests

**Interfaces:**
- `OverlaySnapshot` includes resolution/FPS, codec/chroma/bit depth, decoder,
  renderer, capture/encode/decode/present timing, RTT, loss, bitrate, path,
  profile, display, and capabilities.
- Typed warnings include congestion, decode latency, encoder overload,
  software fallback, relay, and missing permissions.

- [ ] **Step 1: Write failing model tests for metrics and warning thresholds**

```rust
#[test]
fn decode_warning_fires_when_frame_budget_is_exceeded() {
    let snapshot = OverlaySnapshot { fps: 60, decode_ms: 21.0, ..OverlaySnapshot::test_default() };
    assert_eq!(warnings_for(snapshot), vec![Warning::HighDecodeLatency]);
}
```

- [ ] **Step 2: Run focused tests and verify missing overlay behavior**

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-session-runner`
- [ ] **Step 3: Implement compact/expanded overlay, actions, and warnings**
- [ ] **Step 4: Run session-runner tests and a local demo smoke**
- [ ] **Step 5: Commit**

```bash
git add engine/lowlat/crates/session-runner desktop/src-tauri
git commit -m "feat: add session overlay and warnings"
```

### Task 11: WAN/TURN acceptance harness

**Files:**
- Create: `scripts/wan-acceptance.sh`
- Create: `scripts/network-fault-matrix.sh`
- Modify: `scripts/full-ice-smoke.sh`
- Modify: `deploy/turnserver.conf.example`
- Create: `docs/acceptance/OPENSTREAM_1_0_HARDWARE_WAN_MATRIX.md`
- Test: shell syntax and local fault fixtures

**Interfaces:**
- The harness records direct, TURN, and relay path selection without logging
  secrets or key input.
- Matrix columns cover IPv4/IPv6, double NAT/CGNAT/symmetric NAT, loss, jitter,
  bandwidth constraints, Wi-Fi/Ethernet change, router restart, and relay.
- The acceptance document has evidence links/checksums and a status per row.

- [ ] **Step 1: Write failing shell checks for required matrix rows**
- [ ] **Step 2: Run shell checks and confirm the matrix is incomplete**
- [ ] **Step 3: Implement the harness and redacted evidence collection**
- [ ] **Step 4: Run `bash -n` and all locally available fixtures**
- [ ] **Step 5: Commit**

```bash
git add scripts/wan-acceptance.sh scripts/network-fault-matrix.sh scripts/full-ice-smoke.sh deploy/turnserver.conf.example docs/acceptance
git commit -m "test: add OpenStream WAN acceptance matrix"
```

### Task 12: Packaging, updater metadata, and 1.0 release

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `release/manifest.schema.json`
- Create: `release/README.md`
- Modify: `scripts/check-release-artifacts.sh`
- Create: `packaging/linux/openstream-host-agent.service`
- Create: `packaging/linux/openstream.desktop`
- Create: `packaging/linux/build-deb.sh`
- Create: `packaging/macos/build-arm64-dmg.sh`
- Create: `packaging/macos/entitlements.plist`
- Create: `packaging/macos/notarize.sh`
- Create: `docs/acceptance/OPENSTREAM_1_0_RELEASE_REPORT.md`
- Modify: `README.md`, `engine/lowlat/docs/changelog.md`, and version manifests

**Interfaces:**
- Release manifest records exact commit, artifact SHA-256, SBOM path, platform,
  signing/notarization status, and every manual gate.
- Release workflow refuses publication when required artifacts or checksums are
  missing, and keeps signing secrets in GitHub protected environments.
- Updater metadata is signed and separates Stable/Beta/Nightly channels; staged
  update/health-check/rollback hooks are explicit even if the first updater
  client is shipped behind a capability gate.

- [ ] **Step 1: Write failing manifest/artifact validation tests**

```bash
test -f release/manifest.schema.json
test -x scripts/check-release-artifacts.sh
scripts/check-release-artifacts.sh release/manifest.json
```

- [ ] **Step 2: Run the checks and confirm missing release artifacts fail**
- [ ] **Step 3: Implement Linux package, arm64 macOS DMG/signing hooks, SBOM/checksum manifest, and release workflow**
- [ ] **Step 4: Run shell syntax, artifact, secret, dependency, and release-build checks**
- [ ] **Step 5: Fill the release report only with observed evidence, obtain hardware/WAN/signing evidence, and create the annotated signed `v1.0.0` tag**

```bash
git add .github/workflows release packaging scripts README.md engine/lowlat/docs/changelog.md docs/acceptance
git commit -m "release: prepare OpenStream 1.0 artifacts"
git tag -a v1.0.0 -m "OpenStream 1.0.0"
```

## Integration order

Tasks 1 and 5 can be developed in parallel after the clean baseline. Tasks 2,
3, and 4 are sequential because they share the session-runner and input
contracts. Tasks 6–10 are sequential after the app-core/control contracts are
stable. Task 11 can run in parallel with Tasks 8–10. Task 12 is last and may
publish only after the final review confirms every mandatory gate has evidence.

Every task must be integrated with a reviewed commit, not by copying an
unreviewed worker directory. The integration owner runs the full available
verification after each merge and records unavailable toolchains or hardware
as explicit blockers.
