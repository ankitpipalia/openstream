# OpenStream: where the product actually is

**Updated 2026-09-17.** This is the one file to read first. Everything else in
`docs/` is either a per-topic reference or a historical record; where they
disagree with this file, this file is right and the other one is stale.

The rule this document is written under: a capability is listed as *verified*
only where a physical run produced the evidence, and a build or a unit test is
never written up as a hardware result. Where something is unverified, the
reason is named.

---

## In one line

A working, self-hosted remote-desktop stack with native capture, encode,
decode and presentation on Linux and macOS -- and a release that is
deliberately fail-closed, because the signing, packaging and physical
acceptance evidence a 1.0 requires does not exist yet.

## Release status: NOT READY, and not published

`scripts/check-openstream-1-0-release.sh` reports **NOT READY**. There are no
tags and no GitHub releases, and there should not be.

The source version is `1.0.0` (see `scripts/check-version-consistency.sh`,
which keeps the nine places that say so in agreement). That is a *candidate*
version for packaging, not a claim that 1.0 shipped. Do not describe this as a
released or production-ready 1.0 anywhere -- not in a commit message, not in a
PR, not in a status update -- until the checker returns READY.

What the checker is missing falls into two groups:

| Missing | Why |
|---|---|
| Built artifacts, checksums | Regenerate from one frozen SHA; nothing is staged for the current version |
| Signing and notarization evidence | No code-signing identity is available |
| `physical-linux-nvidia-to-apple-silicon` | Needs the LAN host rig; unreachable at the time of writing |
| `wan-turn` | No public TURN deployment |
| `package-launch-upgrade` | Needs the packages above, then a clean-machine install/upgrade run |

## What is verified on hardware

| Path | Evidence |
|---|---|
| macOS host: ScreenCaptureKit capture -> VideoToolbox encode, no CPU copy | Live session on an M1 Max: 608 access units at 40.4/s, capture->access-unit mean 24.6 ms. `scripts/macos-zero-copy-session.sh` |
| macOS client: VideoToolbox decode -> Metal presentation, no CPU readback | Same rig: 562 frames presented, zero fallbacks. ~2.2 ms/frame less client work than the readback path (release builds; see the warning below) |
| macOS CoreGraphics capture fallback | Same rig with `OPENSTREAM_ZC_HOST_CAPTURE=coregraphics`: 237 frames in 12 s |
| Linux host: DRM/KMS scanout capture, NVENC encode, uinput | Earlier physical runs on the NVIDIA rig |
| Control plane: signup, login, enrolment, presence, approval, signalling | Live service checks |

**Any performance number must come from a `--release` build.** The per-pixel
loops on both sides are roughly ten times slower in a debug build; an earlier
measurement of this tree reported a 28 ms/frame saving that was 2.2 ms when
measured properly. If a number looks surprising, check the profile before
believing it.

## What is not verified, and why

| Gap | Blocker |
|---|---|
| Windows hosting and the LocalSystem/WTS service model | No Windows machine. Builds in CI on both MSVC targets; **nothing has ever run**. There is no Windows physical record in this repository -- the GTX 970 evidence in `docs/BUILD.md` is a Linux SteamOS host streaming to a macOS client, not a Windows run, and has been mistaken for one |
| Android and iOS clients | No devices |
| Linux reboot-to-login-screen acceptance | Needs the physical rig |
| WAN, TURN, NAT matrix | No public TURN deployment |
| Signed/notarized installers | No signing identity |
| macOS login-window capture | Blocked by Apple; not a scheduling problem, see `docs/DEFERRED_FEATURES.md` |

## Two things that are built but not a product

### Pre-login hosting (Linux)

`openstream-host-broker` and `openstream-machine-service` are real and tested,
but they are **an experimental subsystem, not something an installer enables**:

- The machine service still loads a static pairing from environment variables.
  It does not enrol the machine, announce durable presence, receive Secure
  Connect requests, or obtain fresh role credentials.
- Audio and clipboard are explicitly disabled in it.
- **Neither binary is in the Linux tarball or the Debian package**, and neither
  are their systemd units. Only the older per-user host-agent service ships.

### Approval-bound authorisation: implemented, not yet delivered

Do not describe Secure Connect to privileged-broker authorisation as complete.
Where it actually stands:

| Part | State |
|---|---|
| The grant itself -- session, requester, target device, permissions, validity window, nonce; authenticated encoding, constant-time tag comparison | **implemented** |
| The control plane issues one at approval, per-device key pinned at enrolment | **implemented** |
| The broker verifies one before opening any device, and fails closed without it | **implemented** |
| Replay and reconnect semantics | **corrected** -- a grant leases a session, so the holder may restart and reconnect, a concurrent connection is refused, and a nonce cannot move to another session |
| The host carries it from the credential into the pairing file | **implemented** |
| **Delivery from the pairing file to the machine service and on to the broker** | **incomplete** |
| **Provisioning the broker's key without exposing it to the unprivileged service** | **incomplete** |

So the mechanism exists and is tested end to end *in source*, and no real
session has yet run through it. The broker has no authority configured, which
means it refuses every session. That is the intended posture while the last two
rows are open, not a regression -- but it is also why nothing here should be
called finished.

The remaining work is not desktop work. Only `machine-service` depends on
`host-broker`; the desktop drives `host-agent` directly and never speaks to the
privileged broker. Both open rows belong with the machine service's enrolment.

### The deployed backend is behind `main`

`https://signal.ankitpipalia.site/healthz` answers, but `/version` returns
**404** -- and `GET /version` is on `main`. The deployment predates that merge,
so the live service is not running the current contract.

Redeploy a pinned SHA and confirm `/version` returns it **before** collecting
any WAN evidence against that host; otherwise the evidence describes a build
nobody can identify.

## Where the remaining latency is

Client-side work is now small. The host is the constraint, and it is measured
rather than guessed -- `cargo run --release -p openstream-macos-host --example
capture_timing` splits it per stage on the machine it runs on.

On an M1 Max, the old `CGDisplayCreateImage` path cost 14.3 ms a frame against
0.5 ms for the hardware encode it fed. ScreenCaptureKit removed that.

The next one found was not a slow stage but a missing one. VideoToolbox
finishes on its own thread, and the host only collected output as a side effect
of submitting the next frame -- so every finished access unit waited for the
next capture before anyone looked at it. `cargo run --release -p
openstream-macos-host --example encode_queue_depth` measures it: 290 of 291
access units were already finished before the next frame arrived, and the queue
depth between submits averaged 0.02. The encoder was never the thing holding
them.

Waiting for the next frame in 2 ms slices, with the encoder checked between
them, took submit-to-access-unit from a mean of 34.8 ms to 11.1 ms and p95 from
103.3 ms to 12.6 ms at a comparable capture rate. The residual is the encode.

What that exercise also settled, on this machine: Apple's low-latency rate
control is accepted and now in force, `DataRateLimits` caps the burst at 1.111x
the nominal bitrate, and `MaxFrameDelayCount` and the speed-over-quality hint
are both refused -- which costs nothing, because the measurement above says the
encoder's queue was never where the latency was.

The next constraint is the presenter and the swapchain, at 40 fps into a 60 Hz
display.

## Map of the other documents

| File | What it is | Trust |
|---|---|---|
| `docs/FEATURE_MATRIX.md` | Per-capability breakdown with evidence | Current |
| `docs/IMPLEMENTATION_PLAN.md` | Execution plan and gates | Current for the plan; its per-item checkboxes lag |
| `docs/OPENSTREAM_1_0_RELEASE_GATES.md` | What a 1.0 must prove | Current |
| `docs/DEFERRED_FEATURES.md` | Deliberately out of scope, with reasons | Current |
| `docs/ARCHITECTURE.md`, `docs/OPENSTREAM_PROTOCOL.md` | Design references | Current |
| `docs/acceptance/`, `docs/research/`, `docs/FACT_CHECK.md`, `docs/REVERSE_ENGINEERING.md` | Historical records of particular runs and investigations | **Archive.** Dated snapshots; do not act on them without re-checking |
| `handoff.md` (untracked) | Working notes for the session in progress | Working notes only |
