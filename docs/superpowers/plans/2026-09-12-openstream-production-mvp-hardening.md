# OpenStream Production MVP Hardening Implementation Plan

> **Status:** Task 6 complete locally; protected PR CI pending as of
> 2026-09-12.

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` and execute one task at a time with a fresh Luna-max worker, focused tests, and an independent review checkpoint before the next task.

**Goal:** Apply the production-MVP review fixes without changing the approved application architecture: prevent diagnostic secret leaks, make host shutdown mean reaped, provide crash-safe settings replacement on Windows, use a real shared Linux native-DRM probe, remove raw pairing JSON from the persistent agent boundary, and make the documentation/status truthful.

**Base:** `fe524a6a1904d6b6ef6d698e4d662a25ce070fd5`

**Architecture:** Keep the existing settings, app-domain, IPC, host-agent, and capability-policy boundaries. Add only narrow interfaces needed for hardening. The host agent must never treat a termination request as proof of process death. Linux readiness must be obtained through the same library-level probe used by the Linux-host preflight. Pairing bearer material crosses the persistent agent boundary only as a protected file path for now.

**Tech Stack:** Rust 2024, Tokio process supervision, serde/JSON diagnostics, platform-specific filesystem/process APIs, existing `lowlat-host::display::Display::capturable` probe, Markdown documentation.

## Global constraints

- Use TDD for every task: add a focused failing regression test, run it and record the failure, implement the smallest safe change, rerun the focused test, then run the relevant workspace checks.
- Preserve the existing OpenStream wire protocol and application state model.
- Never place bearer tokens, pairing JSON, private keys, relay credentials, clipboard contents, or arbitrary user paths into diagnostics or child arguments.
- `Stopped` means the child has been observed exited and reaped. While a child is still alive, expose `Stopping` and do not spawn a replacement.
- Windows settings replacement must not delete the destination before the replacement operation. Unix writes must remain same-directory and may fsync the parent directory after rename for durability.
- `OPENSTREAM_NATIVE_DRM_READY` is not a production probe and must not select a backend. A clearly named developer-only assumption may exist only as an explicit override.
- The persistent host agent may propagate `OPENSTREAM_PAIRING_FILE`; it must never propagate `OPENSTREAM_PAIRING_JSON`.
- Do not add the GUI, native zero-copy media, account persistence, or unrelated product features in this batch.

## Task 1: Make named diagnostic settings field-aware and secret-safe

**Files:**

- Modify: `engine/lowlat/crates/diagnostics/src/lib.rs`
- Test: inline diagnostics tests in the same file

**Implementation:**

1. Add a failing test that calls `DiagnosticBundle::add_setting` for `host_token`, `client_token`, `turn_password`, `relay_ticket`, `identity_private_key`, `authorization`, `clipboard_text`, and `file_path` using unique sentinel values. Export both JSON and text and assert every raw sentinel is absent while the appropriate redaction marker is present.
2. Run `cargo test -p openstream-diagnostics --locked` and record the leak failure.
3. Change `add_setting` to classify the bounded setting name with `field_redaction_class`; use `redact_class` for classified fields and generic `redact_text` only for unclassified values. Keep the bounded label in the output.
4. Run the focused test and the diagnostics crate Clippy check. Inspect the diff for accidental raw-value formatting.
5. Commit: `fix: redact named diagnostic settings by field`.

**Expected result:** Named secret, private-content, and path settings cannot leak through either diagnostics export format.

## Task 2: Make host-agent stop/lifetime termination bounded and reaped

**Files:**

- Modify: `engine/lowlat/crates/host-agent/src/lib.rs`
- Modify: `engine/lowlat/crates/host-agent/src/main.rs`
- Test: host-agent unit tests and Unix IPC shutdown test as needed

**Implementation:**

1. Extend the lifecycle model with `ChildState::Stopping`, a bounded stop deadline, a pending termination reason, and a force-kill-sent marker. Extend `ManagedChild` with a distinct force-kill operation while retaining compatibility for deterministic fakes.
2. Add failing deterministic fake-child tests for prompt graceful exit, child ignoring graceful termination then force-kill/reap, force-kill failure, no second spawn before reap, shutdown during restart backoff, and shutdown while `Starting`. Update existing stop/lifetime tests so `Stopped` is emitted only after `try_wait` returns an exit.
3. Run `cargo test -p openstream-host-agent --locked` and confirm the new lifecycle assertions fail against immediate `Stopped` behavior.
4. Implement the smallest state-machine change: request graceful termination, retain the child in `Stopping`, poll `try_wait`, force-kill after the deadline, retain the child until a later poll confirms/reaps exit, and never spawn while `Stopping`. Apply the same protocol to lifetime expiration before scheduling a restart. Keep errors typed and avoid child output.
5. Make the Tokio adapter use a real platform termination request where available and a separate force-kill path; on Unix, contain the child process group so helpers cannot outlive the agent. Ensure `kill_on_drop` remains a final containment fallback, not the meaning of `Stopped`.
6. Make the Unix agent shutdown path poll/tick until the child reaches `Stopped` or a bounded shutdown deadline, logging typed failure if reaping cannot be confirmed. Do not block the async runtime with an unbounded wait.
7. Run focused tests, Unix IPC integration tests, Clippy, and workspace tests. Commit: `fix: wait for host child reap before stopped`.

**Expected result:** Stop, shutdown, and lifetime rotation have explicit `Stopping` semantics; resources cannot be reused or a replacement spawned before the old process is observed dead and reaped.

## Task 3: Make settings replacement crash-safe on Windows

**Files:**

- Modify: `engine/lowlat/crates/settings/src/lib.rs`
- Modify: `engine/lowlat/Cargo.toml` or the settings manifest only if a targeted Windows API dependency is required
- Test: settings unit tests, plus Windows-only replacement test if API availability permits

**Implementation:**

1. Add a failing/guarded regression test covering replacement of an existing settings file and preserving the old destination when a replacement operation fails. Keep the test portable; add a Windows-only compile/runtime test for the selected replacement primitive.
2. Run `cargo test -p openstream-settings --locked`.
3. Replace the Windows delete-then-rename branch with `ReplaceFileW` or `MoveFileExW` using write-through/replace semantics, converting paths safely to UTF-16 and mapping OS errors into `SettingsError::Io`. Do not broaden unsafe code beyond a small audited FFI wrapper.
4. On Unix, retain atomic same-directory rename and fsync the containing directory after successful replacement where supported.
5. Run settings tests, formatting, Clippy, and a target check covering Windows cfg compilation. Commit: `fix: atomically replace settings on Windows`.

**Expected result:** An existing destination is replaced without an intentional delete window, and the public `save_atomic` contract is accurate on supported platforms.

## Task 4: Use one real shared Linux native-DRM probe

**Files:**

- Modify: `engine/lowlat/crates/host/src/display.rs` or add a small shared probe module in the existing Linux host library
- Modify: `engine/lowlat/crates/host-agent/Cargo.toml` and `src/main.rs` for Linux-only use
- Modify: `engine/lowlat/crates/linux-host/src/main.rs`
- Modify: `engine/lowlat/Cargo.toml` only if a new workspace member is genuinely necessary
- Test: Linux host/host-agent probe-selection tests and non-Linux cfg checks

**Implementation:**

1. Add a failing test around a shared typed probe result/adapter seam proving backend selection cannot be driven by `OPENSTREAM_NATIVE_DRM_READY`.
2. Run focused host/host-agent tests and inspect existing `Display::capturable`; it already opens DRM cards, checks lit outputs, scans the primary plane, reads the framebuffer and requires a plane handle. Reuse that library operation rather than shelling out or parsing CLI JSON.
3. Expose a small shared probe API (for example `lowlat_host::display::native_drm_probe`) returning a bounded typed result derived from `Display::capturable`. Keep Linux implementation behind `cfg(target_os = "linux")` and return unsupported/unreachable on other targets without linking Linux-only code.
4. Make `openstream-linux-host --preflight` use that API for its `native_drm.host_capture_gate` value, while retaining detailed output enumeration. Make `openstream-host-agent` call the same API when building production config. The only override is an explicitly named developer assumption such as `OPENSTREAM_DEVELOPER_ASSUME_NATIVE_DRM=1`, documented as unsafe and never silently enabled.
5. Remove production dependence on `OPENSTREAM_NATIVE_DRM_READY`; add a regression test that setting it alone cannot select `NativeDrm`, while a positive probe can. Ensure Auto falls through to the tested X11/FFmpeg/NVENC path when native DRM is unreachable.
6. Run Linux-focused tests, cross-target checks, preflight in the current environment, Clippy, and workspace tests. Commit: `fix: use shared native drm readiness probe`.

**Expected result:** Product backend selection and CLI preflight consume the same real DRM reachability check, and the known NVIDIA X11 fallback is chosen truthfully when DRM export/import is unavailable.

## Task 5: Remove raw pairing JSON from persistent host-agent propagation

**Files:**

- Modify: `engine/lowlat/crates/host-agent/src/main.rs`
- Modify: `engine/lowlat/crates/host-agent/src/lib.rs` only for a narrowly scoped helper/test seam
- Modify: `README.md`, `docs/BUILD.md`, and any host-agent usage docs that describe the persistent agent boundary
- Test: host-agent configuration projection/launch tests

**Implementation:**

1. Add a failing test or helper-level assertion showing that an environment containing `OPENSTREAM_PAIRING_JSON` does not enter the persistent child environment, while `OPENSTREAM_PAIRING_FILE` is passed as a path only.
2. Run the focused host-agent tests.
3. Remove the raw JSON propagation block. Add only validated absolute `OPENSTREAM_PAIRING_FILE` propagation, preserving secret-free Debug output and existing secure file loader rules. Keep the explicit client/reference developer override separate and clearly documented.
4. Update docs so the production agent accepts a protected pairing file, while raw JSON is labeled a developer-only compatibility escape hatch and is not used by the persistent agent.
5. Run focused tests, secret scan, formatting, Clippy, and workspace tests. Commit: `fix: keep pairing JSON out of persistent agent env`.

**Expected result:** A long-lived host agent never copies bearer JSON into a child environment; only a protected file boundary is supported.

## Task 6: Correct status, security labels, and release-gate wording

**Files:**

- Modify: `docs/superpowers/specs/2026-09-12-openstream-local-first-production-mvp-design.md`
- Modify: `docs/superpowers/plans/2026-09-12-openstream-local-first-production-mvp.md`
- Modify: `README.md`, `docs/BUILD.md`, `engine/lowlat/docs/changelog.md`, and relevant architecture/release docs

**Implementation:**

1. Add/update documentation tests or repository checks where practical before editing claims.
2. Mark the MVP design/plan status as completed locally with review hardening complete/pending protected PR CI, not "implementation in progress," once Tasks 1–5 pass.
3. Label private-LAN no-account mode as "Trusted LAN mode - no account authentication" and retain a prominent warning that RFC1918/private addressing is not an identity boundary.
4. Rename/rephrase the current release check as artifact manifest/presence validation; list signing, checksums/SBOM, package launch, upgrade/rollback, and notarization as later release gates rather than claiming they are implemented.
5. Record the hardening changes, test commands, and known deferred work in the changelog. Keep changed documentation ASCII-clean.
6. Run documentation/repository checks and commit: `docs: finalize production mvp hardening status`.

**Expected result:** Documentation matches the implementation and does not overclaim security, release, or completion guarantees.

## Final verification and handoff

After all task commits are reviewed:

```bash
cargo fmt --all --check
cargo test --workspace --all-features --locked -- --test-threads=1
cargo +stable clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo deny check
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo build --workspace --release --locked
./scripts/check-release-artifacts.sh
./scripts/secret-scan.sh
git diff --check
```

Also run the Linux preflight and the relevant host-agent/settings/diagnostics focused suites. Review the final diff, create a changelog entry, push `codex/production-mvp`, and open a PR against `main` with the exact final SHA. Do not merge the PR automatically; require protected `CI gate` success first.
