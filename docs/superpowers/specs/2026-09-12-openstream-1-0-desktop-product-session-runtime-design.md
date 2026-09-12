# OpenStream 1.0 Desktop Product and Session Runtime

**Status:** Approved execution specification for the OpenStream 1.0 release train

**Baseline:** `main` at `5b0e87807d8e4050b92daca85523e561e01ae4c7`

## Goal

Turn the production-MVP engine into one installable OpenStream product whose
Apple-Silicon macOS client can discover and connect to a Linux x86-64 NVIDIA
host, transfer keyboard and mouse input safely, show a native low-latency
session, and keep hosting alive independently of the product shell.

The first release is deliberately narrow. It must be honest about every
capability: unsupported, experimental, unavailable, and physically unverified
are different states and must not be presented as working features.

## 1. OpenStream 1.0 support matrix

The release target is:

- Host: Linux x86-64 with NVIDIA hardware.
- Capture: X11 through the FFmpeg host path.
- Encoding: NVIDIA NVENC H.264 and H.265 where the host probe confirms them.
- Client: Apple-Silicon macOS.
- Presentation: native Metal, with wgpu/software fallback where available.
- Decoding: VideoToolbox for the production macOS path, FFmpeg fallback.
- Input: keyboard, relative mouse motion, mouse buttons, vertical/horizontal
  wheel, and safe release semantics.
- Audio: Opus.
- Connectivity: direct UDP, STUN/ICE, UPnP, TURN/relay fallback.
- Display: one selectable host display per session.
- Hosting: background host agent/service independent from the UI process.
- Control plane: self-hostable signaling/control service with durable device
  identity and trusted-device policy.

The following are not 1.0 blockers and remain capability-gated: native NVIDIA
DRM capture, Windows or macOS hosting, virtual displays, USB passthrough, HDR,
tablet pressure/tilt, simultaneous multi-monitor windows, approved-app policy,
chat, and polished mobile clients.

## 2. Architecture

```text
Control server
  accounts, devices, presence, approval, credentials, signaling, TURN/relay
                    |
Desktop product shell (Tauri 2 + React/TypeScript)
  Computers, Access, Settings, Diagnostics, About, tray/menu-bar integration
                    |
Rust app-core and protected local IPC
          +---------+----------+
          |                    |
  host-agent/service     session runner (Rust + winit)
  capture/encode/input   decoder/renderer/input/overlay/audio
```

The product shell owns account/device/settings/control-plane concerns. The
session runner owns only one remote session and its native window. The host
agent remains the authority for host lifecycle, preflight, capture, encoding,
input injection, stay-awake, guest permissions, and cleanup. The shell never
spawns FFmpeg or opens `/dev/uinput` directly.

Session credentials are passed over protected local IPC or an inherited pipe;
they are never placed in command-line arguments, persistent environment, or
logs. Long-lived device identity and refresh material use the platform secure
credential store. Session bearer material, TURN passwords, and relay tickets
remain ephemeral.

## 3. Product contracts

### Settings schema

`openstream-settings` moves from schema version 1 to version 2 through an
explicit migration. The schema adds:

- Client: profile, window mode, renderer, VSync, decoder, codec, chroma,
  bit-depth preference, immersive mode, overlay, warning display, and client
  bandwidth cap.
- Host: enabled, name, stay-awake, capture, encoder, selected display,
  aggregate bandwidth cap, approval mode, and maximum guests.
- Input: independent keyboard, mouse, gamepad, clipboard, and microphone
  controls.
- Audio: enabled, codec, bitrate, and latency mode.
- Network: client port, host start port, UPnP, ICE/TURN, forced relay, and
  congestion intent.

Profiles are policies, not copied configuration blobs:

```text
platform defaults -> profile -> global overrides -> device overrides
  -> session overrides -> capability clamping -> effective configuration
```

Performance, Balanced, Quality, and Custom resolve deterministically. Balanced
is the default. Editing a low-level field selects Custom without destroying the
selected policy's defaults.

### Setting metadata

Rust owns a descriptor catalog consumed by every frontend:

```rust
SettingDescriptor {
    key,
    scope: Global | Client | Host | Device | Session,
    apply_mode: Live | Reconnect | RestartHost | RestartApplication,
    capability,
    visibility: Normal | Advanced | Experimental,
}
```

The UI cannot claim a capability from a hard-coded JavaScript list. Native DRM
is Experimental until an end-to-end capture/import/conversion/encoder probe is
physically proven. VideoToolbox, Metal, NVENC, uinput, audio, and networking
are reported with the same truthful availability model.

### Input contract

Keyboard transitions, mouse buttons, wheel, and `ReleaseAll` are reliable and
ordered. Relative pointer motion is sequenced, coalesced, latest-wins, and not
retransmitted. Host-side permissions are independent for keyboard and mouse;
revoking a category first injects `ReleaseAll` for that category.

The following events always release local/remote input state:

- session disconnect;
- client focus loss;
- host permission revocation;
- input detachment;
- establishment-generation change;
- host adapter drop;
- authenticated liveness timeout.

macOS immersive keyboard/mouse mode is opt-in and requests Input Monitoring or
Accessibility permission only when enabled. The escape/release-input hotkey
can never be removed while immersive mouse capture is active.

## 4. Release-train slices

Each slice is a separately reviewable branch/worktree and must leave a green,
testable tree. Workers may not edit overlapping files concurrently.

1. **Product contracts and settings v2** — schema migration, profiles,
   descriptors, capabilities, and role-specific network settings.
2. **Native session window** — winit session runner, windowed/borderless/native
   fullscreen behavior, resize/scaling, VSync policy, focus events, and hotkey
   plumbing while preserving the existing decoder and transport.
3. **Production input v2** — raw relative mouse, permission-separated input,
   input transport policy, focus cleanup, detach/regrab, watchdog, and physical
   Mac-to-Linux acceptance tooling.
4. **macOS decode/presentation** — H.264 VideoToolbox plus CVPixelBuffer/
   IOSurface/Metal presentation; H.265 follows only when the same truthful
   capability and fallback tests pass.
5. **Device/control plane** — SQLite/WAL repositories, device enrollment,
   durable public identity, presence, connection requests, trusted policies,
   invitations, audit records, and ephemeral role-scoped session credentials.
6. **Desktop product shell** — Tauri/React surface over real Rust app-core IPC:
   Computers, Access, Settings, Diagnostics, and About. React contains no
   transport or mock-session logic.
7. **Connection and approval flow** — discovery, profile selection, request,
   approval/rejection, live permissions, session launch, reconnect, and
   disconnect.
8. **Settings UI** — client, host, network, audio, input, advanced, and
   capability explanations backed by descriptors.
9. **Tray/menu bar** — open UI, hosting state, guest state, disconnect, stop
   hosting, update, and quit-UI-with-host-agent-running behavior.
10. **Session overlay** — real stream, decode, encode, path, bitrate, loss,
    warnings, display/profile controls, release input, fullscreen, and
    disconnect actions.
11. **WAN acceptance** — external coturn and real-network matrix covering
    direct UDP, relay, NAT variants, IPv4/IPv6, loss/jitter, bandwidth limits,
    and network changes.
12. **Release engineering** — arm64 macOS bundle/DMG, Linux host package,
    checksums/SBOM/manifest, signing/notarization hooks, updater metadata,
    installer/upgrade/rollback smoke tests, and the signed `v1.0.0` tag.

## 5. Worker and integration rules

- Every worker uses only `gpt-5.6-luna` with `reasoning_effort=max`.
- Reconnaissance, implementation, task review, and final review are separate
  worker roles; workers do not self-approve their own broad changes.
- Every implementation task starts with a failing behavior test, observes the
  expected failure, then implements the smallest passing change.
- Each worker receives an isolated worktree and an explicit disjoint write
  set. Integration is sequential at the release branch.
- After each slice: inspect the diff, run the narrow tests, run the workspace
  checks available in the environment, obtain a scoped code review, then
  integrate only the reviewed commit.
- The broad final review must inspect the complete release diff and the
  release-gate evidence before any tag or publication.

## 6. Release gates

Automated gates include formatting, workspace tests, Clippy with warnings
denied, release build, dependency/license policy, fuzz compilation, secret
scan, frontend/type checks, package/artifact manifest checks, and the protected
CI gate.

Manual/physical gates are mandatory for the production `1.0.0` claim:

- Apple-Silicon macOS client ↔ Linux NVIDIA host;
- H.264 and H.265 LAN sessions;
- VideoToolbox and FFmpeg fallback;
- Metal, windowed, borderless, native fullscreen, and VSync modes;
- keyboard, raw mouse, buttons, wheel, detach, focus-loss, held-input
  disconnect, and reconnect cleanup;
- Opus audio, display switching, client-first/host-first startup, restart and
  reconnect;
- direct UDP, external TURN, relay fallback, NAT/network changes, and a
  documented long-running session/soak;
- signed/notarized macOS artifact, Linux package install/upgrade/rollback, and
  checksum/SBOM verification.

If a gate cannot be run with real evidence, its capability remains marked
Unavailable, Experimental, or Unverified and the release must not describe it
as production-ready. Agents may prepare scripts, fixtures, and documentation,
but they cannot manufacture hardware, WAN, signing, or notarization evidence.

## 7. Definition of done

OpenStream 1.0 is ready only when a user can install the artifacts, enroll a
device, enable Linux hosting, see a green host preflight, discover the host on
macOS, choose Performance/Balanced/Quality, connect with approval semantics,
receive a native fullscreen session using the verified decoder/renderer path,
control the host with safe keyboard/raw mouse input, hear Opus audio, inspect
real overlay metrics, disconnect without stuck input, leave hosting alive in
the background, and reconnect both directly and through the validated relay
path.

The public release must include the exact commit, platform matrix, known
limitations, checksums, SBOM, verification report, and explicit evidence for
each manual gate. No Parsec binaries, proprietary code, or visual assets are
shipped or represented as OpenStream functionality.
