# Workstream 1 — Codebase and architecture

This workstream was performed serially by the primary auditor because this
session exposed no worker-agent/Luna Max facility.

## Findings

OpenStream has a coherent split between a no-std/sans-I/O low-latency core, a
portable async session stack, platform adapters, a product domain model, a
host supervisor, and a Tauri shell. The 33-crate workspace is large but its
dependency direction is generally sound. `openstream-transport-policy` owns
deterministic pacing/congestion/delivery policy; `client-core::PeerSession`
owns portable signaling, encryption, scheduling, liveness, and path
migration; `platform` and host crates own OS integration.

Strong areas:

- bounded signaling, reliable-control, media, input, telemetry, and relay
  queues;
- authenticated generation-scoped direct establishment;
- explicit shutdown and drain ownership in `PeerSession`;
- bounded host restart/backoff plus terminate/kill/wait/reap semantics;
- capability truth separates protocol, implementation, runtime, and physical
  evidence;
- FFI surfaces are bounded and copy callback buffers before returning.

Incomplete runtime spine:

- The Tauri shell persists settings and controls host-agent start/stop, but
  `RuntimeCommand::Connect` only dispatches the in-memory `AppModel`. There is
  no device-directory call, credential issuance, `PeerSession` creation, or
  native session-window launch.
- `desktop-client/src/session.rs` is a lifecycle contract, not a window.
- Host restart settings cannot be proved applied because the host agent does
  not consume a settings revision (`desktop/src-tauri/src/runtime.rs:418-440`).
- Host readiness is inferred after a child survives startup grace, not from
  captured/encoded frame liveness (`host-agent/src/lib.rs:1015-1023`).

Cross-platform architecture is plausible, but production implementations are
not symmetrical. Unix-domain IPC makes the current host-agent control path
Unix-only. Windows/macOS host capture remains FFmpeg fallback code; Linux has
the only native host stack. The large unsafe surface is concentrated in
generated/manual VAAPI/NVENC/CUDA/Vulkan/OS FFI modules, which is reasonable
but increases the need for hardware tests that CI cannot supply.

## Assessment

Architecture status: **Partially implemented**. It can support the target
matrix without a redesign, but the product shell, control plane, session
runner, settings-to-agent application, and non-Unix service boundaries must be
completed.
