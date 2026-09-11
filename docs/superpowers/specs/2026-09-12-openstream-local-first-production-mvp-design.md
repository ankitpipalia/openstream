# OpenStream Local-First Production MVP Design

**Status:** implementation in progress; requirements adopted from the
production-MVP review on 2026-09-12.

## Goal

Make OpenStream a supportable local-network product for the validated target:
Linux x86_64 hosting with X11/PipeWire and FFmpeg hardware-encoder fallback,
and Apple-Silicon macOS as a client, while keeping the secure authenticated
deployment path implemented for later enablement.

This phase productizes the existing streaming core. It does not replace the
OpenStream protocol, merge UI code into the transport, or claim that the
current FFmpeg/BGRA path is native zero-copy media.

## Scope and non-goals

The production-MVP scope is:

- a versioned, persistent, validated application configuration;
- a local-first control mode that is explicit, private-network constrained,
  and separate from secure bearer-token mode;
- a reusable application/domain state model for devices, host lifecycle,
  connection status, permissions, diagnostics, and typed failures;
- a protected local IPC boundary for a future desktop shell and the host agent;
- a host-agent lifecycle that can keep the proven Linux FFmpeg/NVENC fallback
  alive after the desktop UI exits;
- user-facing diagnostics that distinguish native DRM failure from the tested
  X11/FFmpeg/NVENC fallback;
- capability-gated implementations for existing input, clipboard, microphone,
  controller, and virtual-device backends without silently advertising an
  unavailable platform feature;
- reproducible Linux-host/macOS-client acceptance and release checks.

The following are intentionally separate follow-up gates: durable multi-user
accounts and OIDC, public-WAN/coturn acceptance, native ScreenCaptureKit and
VideoToolbox paths, Windows native hosting, OS-specific secure-store backends
where the platform is not available, multi-guest media fan-out, and signed
installer/update publication.

## Security modes

OpenStream has two control-plane modes:

### Secure mode

Secure mode is the default whenever the signal service is reachable beyond a
loopback development bind. `OPENSTREAM_ADMIN_TOKEN` is required for session
management, role bearer capabilities remain required for signaling and relay
operations, and the existing constant-time token checks remain authoritative.
Device identity keys and session capabilities are never written to ordinary
settings or logs.

### Explicit private-LAN mode

For the user's local-network MVP, `OPENSTREAM_LOCAL_NO_AUTH=1` may disable the
*administrator/account authentication flow* only when all of these are true:

- no administrator token is configured;
- the configured signal bind is one explicit private or link-local IP address,
  never a wildcard or public address;
- the bind address is in IPv4 RFC1918 or IPv6 ULA/link-local space;
- the service prints a warning naming the mode and bind address;
- the role-scoped session capabilities and encrypted peer handshake remain in
  force; “no account auth” must not mean unauthenticated media datagrams.

The existing `OPENSTREAM_ALLOW_NO_AUTH=1` loopback-only mode remains available
for tests. It is not widened by this design. Private-LAN mode is opt-in and
must fail closed if the bind is missing, wildcard, public, or malformed.

The normal product UI may hide account screens in private-LAN mode, but the
secure mode, device identity, token revocation, and future account boundary
remain implemented rather than deleted.

## Process architecture

```text
signal server / relay
        │ HTTPS/WSS or explicit private-LAN HTTP/WSS
        │
desktop shell ── protected local IPC ── host agent
        │                                  │
        │                                  ├─ preflight/capabilities
        │                                  ├─ capture selection
        │                                  ├─ FFmpeg fallback host
        │                                  └─ active host sessions
        │
        └──────── session runner / desktop client window
                 current PeerSession + decoder + presenter
```

The UI never owns transport state or spawns FFmpeg directly. The host agent
owns hosting lifecycle and may outlive the shell. A session runner owns one
interactive client stream. Existing `PeerSession`, media, transport policy,
FFmpeg, and Linux host crates remain below this boundary.

## Application settings

Settings are JSON on disk with a schema version independent from application,
protocol, and database versions. The file contains configuration and secret
references only, never bearer tokens, pairing JSON, private identity keys,
TURN passwords, or relay tickets.

```rust
AppConfig {
    schema_version: u32,
    device: DeviceConfig,
    client: ClientConfig,
    host: HostConfig,
    video: VideoConfig,
    audio: AudioConfig,
    input: InputConfig,
    network: NetworkConfig,
    privacy: PrivacyConfig,
    advanced: AdvancedConfig,
}
```

Each setting declares an effective scope and apply mode in code. Invalid
values are rejected with a field-specific error; they are not clamped into a
different user request. Unknown future fields are ignored for forward
compatibility. Older schema versions migrate through explicit, deterministic
steps before use. A failed migration leaves the original file untouched and
returns a recoverable error.

Environment variables remain developer/headless overrides. Overrides are
parsed through the same validators and are never persisted back to the file.

## Domain state and commands

`openstream-app-core` owns a pure state machine and command/event vocabulary:

```text
SignedOut → Authenticating → Ready
Ready → RequestingConnection → WaitingForApproval → Connecting
Connecting → Negotiating → Connected
Connected → Reconnecting → Connected
Connected → Disconnecting → Ready
any state → Failed { typed code, retryability }
```

Local mode starts at `Ready` without an account login but still creates a
session through the existing role-capability flow. Commands include
`enable_hosting`, `disable_hosting`, `connect`, `cancel_connection`,
`disconnect`, `approve_request`, `reject_request`, `update_setting`, and
`run_diagnostics`. Network adapters translate their results into domain
events; the frontend does not call REST or spawn processes itself.

Connection requests carry a device ID, requested permissions, expiry, and a
single-use request ID. The host approval policy is `Auto` in the explicit
local MVP profile and `OwnerOnly`/prompt-capable in secure product mode. A
request expires and is rejected after its bounded deadline. Permissions are
least privilege: view is required, input/clipboard/microphone/controller are
independent grants.

## Local IPC

The first supported IPC transport is a Unix-domain socket on Linux and macOS.
The socket is created with a private filesystem mode, its parent directory is
created with private permissions, frames are length-bounded JSON messages, and
every request has a request ID and bounded response deadline. The protocol
contains no session bearer tokens or private keys; the agent obtains secrets
from the secure control boundary. A future Windows named-pipe adapter must
preserve the same message schema and access-control guarantees.

## Host-agent behavior

The host agent exposes lifecycle and diagnostics, then launches the currently
proven fallback:

```text
Auto capture selection
  native DRM/KMS if preflight proves reachable
  otherwise X11/PipeWire + FFmpeg

Auto encoder selection
  explicit validated NVENC/VAAPI/software profile

agent stop requested
  stop admission → stop child → release devices → report Ready
```

On Linux it can run as a systemd user service and, where the operator grants
the required device/session access, as the existing system service. Closing a
desktop shell must not stop the agent. Child exits are reported as typed
failures and may restart with bounded backoff; repeated failures stop retrying
until the operator intervenes.

## Diagnostics and capability truth

Diagnostics are structured, redacted, and independent from user data:

```text
signal, direct_udp, stun, relay, turn,
capture_backend, encoder, decoder, renderer,
audio, input, virtual_devices,
last_error, path, pmtu, rtt, loss, bitrate
```

Native DRM is reported as unavailable when its preflight cannot reach a
scanout buffer. The known-good X11/FFmpeg/NVENC path is then shown as the
selected fallback, not silently represented as native capture. Exports include
versions, capability reports, redacted logs, settings with secret references
only, and last-session metrics; they exclude tokens, keys, pairing JSON,
clipboard text, audio, and frame content.

## Device and advanced feature contracts

Existing Linux uinput keyboard/pointer/gamepad paths remain enabled only by
explicit host policy. Controller, tablet, clipboard, microphone, virtual
display, and virtual USB backends expose a capability and a typed unavailable
or permission-required result. A feature must not be advertised solely
because a protocol enum exists. Virtual USB and platform-specific virtual
devices are implemented behind isolated adapters and may remain untested on
the current Linux/macOS hardware until the required OS driver/API is present.

## Acceptance criteria

The local MVP is accepted only when:

1. An operator can load validated persistent settings and start/stop hosting
   without hand-editing a pairing JSON in the normal agent path.
2. Explicit private-LAN mode works only on a private explicit bind; secure
   mode still rejects missing authorization on non-loopback deployments.
3. The host agent survives shell exit and reports child/preflight failures.
4. Linux X11/FFmpeg/NVENC host → Apple-Silicon macOS client streams H.264 over
   direct LAN UDP with software and Metal presentation, as recorded in
   `docs/BUILD.md`.
5. Host-first startup, reconnect, session teardown, and permission defaults
   have deterministic tests.
6. No diagnostics or persisted settings contain secrets or user content.
7. All workspace tests, Clippy, fuzz compilation, dependency audit, release
   build, and relevant shell/ABI checks pass on the exact release commit.

This design does not call the project a universal Parsec replacement. It makes
the tested Linux-host/macOS-client path a supportable local product while
preserving a clear path to secure WAN deployment and native media later.
