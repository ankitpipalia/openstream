# OpenStream Runtime Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the existing Tauri/React product shell to the real Rust app-core and settings runtime while keeping credentials and media outside the UI process.

**Architecture:** Tauri owns a small, secret-free runtime state containing `AppModel` and persisted `AppConfig`. React talks to it through typed `invoke` commands and receives snapshots/events, while the existing native session and host-agent processes remain outside the WebView. The browser fixture remains available only for frontend tests and non-Tauri development.

**Tech Stack:** Rust 2024 workspace, Tauri 2, `openstream-app-core`, `openstream-settings`, `openstream-host-agent`, `openstream-local-ipc`, React, TypeScript, Vitest.

**Spec:** `docs/superpowers/specs/2026-09-12-openstream-1-0-desktop-product-session-runtime-design.md`

## Global Constraints

- Baseline is `9f14be032caa5f23f68b46dcc0be44a7fe998440`.
- The shell may expose state, settings, capabilities, and typed outcomes, but never session bearer material, TURN passwords, relay tickets, pairing JSON, private identity keys, or user input values.
- React must not perform transport, signaling, host-process, FFmpeg, decoder, or media-frame work.
- Settings use the existing schema-v2 validation/migration and `save_atomic`; invalid updates are rejected without replacing the last valid file.
- Host-agent control uses the existing bounded Unix IPC protocol and typed health/errors; the shell never spawns FFmpeg or opens `/dev/uinput`.
- Every production behavior change starts with a failing behavior test and observes the expected failure before implementation.
- Every implementation worker uses `gpt-5.6-luna` with `reasoning_effort=max`, an isolated worktree, and a disjoint write set.
- Physical Linux-NVIDIA → Apple-Silicon testing remains evidence for the existing FFmpeg/NVENC fallback path; it must not be described as VideoToolbox or zero-copy evidence.

---

### Task 1: Rust runtime state and typed Tauri commands

**Files:**
- Create: `desktop/src-tauri/src/runtime.rs`
- Modify: `desktop/src-tauri/src/lib.rs`
- Modify: `desktop/src-tauri/Cargo.toml`
- Test: `desktop/src-tauri/src/runtime.rs` unit tests

**Interfaces:**
- `RuntimeState::from_settings_path(Option<PathBuf>) -> Result<Self, RuntimeError>` loads an existing schema-v2 file or uses `default_config()` when the file is absent.
- `RuntimeSnapshot { app: AppSnapshot, settings: AppConfig, descriptors: Vec<SettingDescriptor> }` is secret-free and serializable.
- `RuntimeCommand` is a safe subset of app-core commands: authentication, connect, approval, tick, negotiation, connection/loss, disconnect, and hosting transitions; it contains no free-form failure text or credentials.
- `RuntimeDispatchResult { snapshot: RuntimeSnapshot, events: Vec<AppEvent> }` is returned after every accepted command.
- Tauri commands are `runtime_snapshot`, `runtime_settings`, `runtime_update_settings`, and `runtime_dispatch`.

- [ ] **Step 1: Write failing runtime-state tests**

```rust
#[test]
fn absent_settings_start_from_safe_defaults() {
    let state = RuntimeState::from_settings_path(Some(temp_path("missing"))).unwrap();
    assert_eq!(state.settings().schema_version, CURRENT_SCHEMA_VERSION);
    assert_eq!(state.settings().client.profile, StreamProfile::Balanced);
}

#[test]
fn valid_settings_update_is_persisted_and_invalid_update_is_atomic() {
    let path = temp_path("settings");
    let mut state = RuntimeState::from_settings_path(Some(path.clone())).unwrap();
    let mut updated = state.settings().clone();
    updated.client.bandwidth_cap_mbps = Some(20.0);
    state.update_settings(updated.clone()).unwrap();
    assert_eq!(load(&path).unwrap().config, updated);

    let mut invalid = updated.clone();
    invalid.video.fps = 0;
    assert!(state.update_settings(invalid).is_err());
    assert_eq!(load(path).unwrap().config, updated);
}

#[test]
fn dispatch_returns_only_secret_free_snapshot_and_events() {
    let mut state = RuntimeState::for_test();
    let result = state.dispatch(RuntimeCommand::BeginAuthentication).unwrap();
    assert!(serde_json::to_string(&result).unwrap().contains("AuthenticationStarted"));
    assert!(!serde_json::to_string(&result).unwrap().contains("pairing"));
}
```

- [ ] **Step 2: Run the focused tests and observe the missing runtime API failure**

Run: `cargo test --manifest-path desktop/src-tauri/Cargo.toml runtime -- --nocapture`

Expected: compilation failure because `runtime.rs`, `RuntimeState`, and the runtime commands do not exist.

- [ ] **Step 3: Implement the minimal runtime state and commands**

Use `app.path().app_config_dir().join("settings.json")` during Tauri setup. Treat a missing settings file as first-run defaults; propagate all other load errors as typed `SettingsUnavailable`. Map `RuntimeCommand` to `AppCommand` without exposing `AppError.message`. Register the four commands and manage one `Mutex<RuntimeState>` for the application lifetime.

- [ ] **Step 4: Run focused tests, workspace tests, and Clippy**

Run: `cargo test --manifest-path desktop/src-tauri/Cargo.toml runtime -- --nocapture`

Run: `cargo test --manifest-path engine/lowlat/Cargo.toml -p openstream-app-core -p openstream-settings`

Run: `cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings`

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri
git commit -m "feat: add typed desktop runtime commands"
```

### Task 2: Tauri-backed React adapter

**Files:**
- Create: `desktop/src/adapters/tauriAdapter.ts`
- Create: `desktop/src/adapters/tauriAdapter.test.ts`
- Modify: `desktop/package-lock.json` to restore a valid lockfile document
- Modify: `desktop/src/adapters/productAdapter.ts`
- Modify: `desktop/src/App.tsx`
- Modify: `desktop/src/pages/ComputersPage.tsx`
- Modify: `desktop/src/model.ts`
- Test: `desktop/src/adapters/tauriAdapter.test.ts` and `desktop/src/App.test.tsx`

**Interfaces:**
- `ProductAdapter` adds `dispatch(command: RuntimeCommand): Promise<ProductSnapshot>` and `updateSettings(config: unknown): Promise<ProductSnapshot>`; fixture-only `setSnapshot` remains available only on the local adapter.
- `createTauriAdapter(invoke: TauriInvoke): ProductAdapter` invokes only typed Rust commands and maps `RuntimeSnapshot` into the existing `ProductSnapshot` rendering model.
- `createDefaultAdapter()` selects the Tauri adapter only when `window.__TAURI_INTERNALS__` exists; otherwise it returns the local fixture adapter.
- `App` refreshes the selected adapter once on mount and renders an explicit unavailable capability if the runtime bridge fails.

- [ ] **Step 1: Write failing adapter and refresh tests**

```ts
it("loads a Rust snapshot through the Tauri adapter", async () => {
  const adapter = createTauriAdapter(async (command) => {
    expect(command).toBe("runtime_snapshot");
    return runtimeSnapshotFixture();
  });
  const snapshot = await adapter.refresh();
  expect(snapshot.connection.state).toBe("idle");
  expect(snapshot.settings[0].items[0].value).toBe("balanced");
});

it("keeps the fixture adapter outside Tauri", async () => {
  const adapter = createDefaultAdapter({ isTauri: false });
  expect((await adapter.refresh()).product.channel).toBe("Desktop shell");
});
```

- [ ] **Step 2: Run the focused frontend tests and observe the missing adapter failure**

Run: `cd desktop && npm test -- --run src/adapters/tauriAdapter.test.ts`

Expected: the test fails because no Tauri adapter or runtime snapshot mapper exists; before installing dependencies, `node -e 'JSON.parse(require("fs").readFileSync("package-lock.json"))'` must also fail on the current corrupted lockfile.

- [ ] **Step 3: Implement the adapter and production App wiring**

Restore `desktop/package-lock.json` to the valid JSON document represented by the committed dependency graph, and add a JSON-parse check to the frontend verification. Use `invoke` from `@tauri-apps/api/core` only inside `tauriAdapter.ts`. Keep Rust command names and JSON field names in one typed mapping. Do not put pairing paths, tokens, or media data in `ProductSnapshot`. Make the Computers refresh action call `adapter.refresh()` and show a typed unavailable state on bridge failure.

- [ ] **Step 4: Run frontend typecheck, tests, and production build**

Run: `cd desktop && npm ci`

Run: `cd desktop && npm test -- --run`

Run: `cd desktop && npm run build`

- [ ] **Step 5: Commit**

```bash
git add desktop/src
git commit -m "feat: connect desktop shell to Tauri runtime"
```

### Task 3: Host-agent health and lifecycle bridge

**Files:**
- Create: `desktop/src-tauri/src/host_agent.rs`
- Modify: `desktop/src-tauri/src/lib.rs`
- Modify: `desktop/src-tauri/Cargo.toml`
- Create: `desktop/src-tauri/src/host_agent_test.rs`
- Test: `desktop/src-tauri/src/host_agent_test.rs`

**Interfaces:**
- `HostAgentClient::health() -> Result<HostHealth, HostAgentBridgeError>`
- `HostAgentClient::start() -> Result<Vec<HostAgentEvent>, HostAgentBridgeError>`
- `HostAgentClient::stop() -> Result<Vec<HostAgentEvent>, HostAgentBridgeError>`
- Tauri commands `host_agent_health`, `host_agent_start`, and `host_agent_stop` return only typed health/events and never child environment or pairing material.
- The client derives the same default Unix endpoint as the host-agent and accepts an explicit endpoint only through Rust test construction, not from the web UI.

- [ ] **Step 1: Write failing IPC client tests**

```rust
#[tokio::test]
async fn health_round_trip_uses_typed_ipc_without_secret_fields() {
    let server = TestAgentServer::spawn(AgentIpcResponse::Health {
        version: HOST_AGENT_PROTOCOL_VERSION,
        request_id: RequestId::new("test-health").unwrap(),
        health: HostHealth {
            state: ChildState::Ready,
            backend: "ffmpeg-fallback".into(),
            pid: Some(42),
            restart_count: 0,
            next_restart_in_ms: None,
            last_exit: None,
            last_error: None,
        },
    }).await;
    let health = HostAgentClient::with_endpoint(server.endpoint()).health().await.unwrap();
    assert_eq!(health.state, ChildState::Ready);
    assert!(!serde_json::to_string(&health).unwrap().contains("pairing"));
}
```

- [ ] **Step 2: Run the focused test and observe the missing client failure**

Run: `cargo test --manifest-path desktop/src-tauri/Cargo.toml host_agent -- --nocapture`

Expected: compilation failure because the client and test server do not exist.

- [ ] **Step 3: Implement bounded request/response IPC**

Use `Endpoint::connect`, `read_frame`, and `write_frame` from `openstream-local-ipc`; enforce `HOST_AGENT_PROTOCOL_VERSION`, generate a bounded non-secret request ID, and return typed errors for connection, version, timeout, and agent failures. Do not log raw frames.

- [ ] **Step 4: Run the focused host-agent tests and platform compile checks**

Run: `cargo test --manifest-path desktop/src-tauri/Cargo.toml host_agent -- --nocapture`

Run: `cargo check --manifest-path desktop/src-tauri/Cargo.toml --locked`

- [ ] **Step 5: Commit**

```bash
git add desktop/src-tauri
git commit -m "feat: bridge desktop shell to host agent"
```

### Task 4: Runtime integration and physical acceptance

**Files:**
- Create: `scripts/runtime-spine-smoke.sh`
- Modify: `docs/BUILD.md`
- Modify: `docs/acceptance/OPENSTREAM_1_0_RELEASE_REPORT.md`
- Test: shell syntax and existing Linux-to-macOS fallback acceptance

**Interfaces:**
- `scripts/runtime-spine-smoke.sh` checks that the source tree contains the runtime command registration, frontend Tauri adapter, and existing fallback binaries; it must not print secrets.
- The acceptance record distinguishes product-shell integration from the already-proven X11/FFmpeg/NVENC → FFmpeg/BGRA/wgpu path.
- No physical result is marked PASS unless observed on the supplied Linux NVIDIA host and current Apple-Silicon Mac.

- [ ] **Step 1: Write failing shell assertions for the runtime boundary**

```bash
test -f desktop/src/adapters/tauriAdapter.ts
rg -q 'runtime_snapshot' desktop/src-tauri/src/lib.rs
rg -q 'createDefaultAdapter' desktop/src/App.tsx
```

- [ ] **Step 2: Run the assertions and record the missing script behavior**

Run: `bash scripts/runtime-spine-smoke.sh`

Expected: failure because the smoke script does not exist.

- [ ] **Step 3: Implement the redacted source/runtime smoke and update evidence wording**

The script uses `set -euo pipefail`, prints only paths/status, and refuses to read or display pairing files. Documentation must state that the existing manual LAN run proves fallback streaming only, not VideoToolbox, zero-copy, raw input, or release readiness.

- [ ] **Step 4: Run shell checks and the real two-machine fallback test**

Run locally: `bash -n scripts/runtime-spine-smoke.sh && bash scripts/runtime-spine-smoke.sh`

Build/run the host on `deck@192.168.1.69` using the private pairing-file workflow and `OPENSTREAM_VIDEO_ENCODER=h264_nvenc`; run the Apple-Silicon client with the same commit and FFmpeg fallback renderer/decoder. Record only redacted status, access-unit count, path, resolution, encoder and duration.

- [ ] **Step 5: Commit**

```bash
git add scripts/runtime-spine-smoke.sh docs/BUILD.md docs/acceptance/OPENSTREAM_1_0_RELEASE_REPORT.md
git commit -m "test: record runtime integration acceptance boundary"
```

## Integration order

Tasks 1 → 2 → 3 are sequential because the frontend and host-agent bridge consume the Tauri runtime boundary. Task 4 follows the code tasks and may only record observed hardware results. The branch must not claim a production `v1.0.0` release or native VideoToolbox/zero-copy evidence.
