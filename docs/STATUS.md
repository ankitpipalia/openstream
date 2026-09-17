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
  It does not announce durable presence, receive Secure Connect requests, or
  obtain fresh role credentials. (Enrolment itself is now `openstream-enrol`.)
- **Why it could not announce presence, and what changed.** `/v1/presence`
  needs a device-bound token, and the only way to get one was a password
  sign-in -- which a service facing the network must not hold. So a machine
  could be enrolled, trusted, and still unable to say it was online.
  `POST /v1/auth/device` now takes a signature from the identity key the device
  enrolled with and returns one. **The machine service does not call it yet**:
  the endpoint, the transcript and the client library exist and are tested, and
  nothing announces anything until the service is wired to them.
- Audio and clipboard are explicitly disabled in it.
- The three binaries and two systemd units are now **in the tarball and the
  Debian package**, with `scripts/verify-package-install.sh` asserting each one
  so the gap cannot reopen quietly. The units ship **disabled**: without a grant
  key the broker refuses every session by design, so enabling the pair on
  install would leave a privileged service running and a network-facing one
  restart-looping for a feature nobody asked for. `postinst` prints what to do.
- The configuration those units ship with **could not have started either
  service**, and was fixed only after review: five variables were assigned the
  empty string, which a process reads as a value rather than as unset, and the
  uid the broker admits was never set anywhere, so it fell back to admitting
  root and would have refused the unprivileged service it ships with. Settings
  now live in root-owned files under `/etc/openstream` that `postinst` writes
  once with the account ids it has just resolved.
- **Nothing has been installed or started on a real machine.** The units are
  written and packaged; no one has booted them.
- `scripts/test-linux-packaging.sh` is the check that stops this recurring, and
  only half of it has been run. Its static half ran locally and, against the
  units as they were, failed on eight separate counts -- every problem listed
  above. Its functional half, which starts the real broker with the environment
  the package writes and requires that it listens (with a negative control that
  must still fail), is **wired into CI but has never executed**: it needs Linux,
  and this branch has no pull request, so no run has ever reached it. Do not
  quote it as evidence until a run does.
- The broker's `CapabilityBoundingSet` is deliberately left unnarrowed, because
  guessing it wrong yields a service that will not start and no one here can
  currently test it -- the unit says so and says where to start once someone can.

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
| Delivery from the pairing file to the machine service and on to the broker | **implemented** -- the service takes the pairing's grant; `OPENSTREAM_SESSION_APPROVAL` is a development override that cannot displace a real one |
| Provisioning the broker's key without exposing it to the unprivileged service | **implemented** -- written 0600 through a rename; on read the broker requires the file be owned by its own user, be a regular file opened `O_NOFOLLOW`, and sit under directories no one else can write |
| The enrolment call that obtains the key | **implemented** -- `openstream-enrol` posts to `POST /v1/devices` and writes the key straight to the broker's file, so it never crosses a terminal or a log |
| Enrolment that recovers from a local failure after the response | **implemented, and narrower than it sounds** -- the destination is created and checked before the request that mints the key, and if storing it still fails the device is removed again through `DELETE /v1/devices/{device_id}`. That covers every failure the client *sees*. It does not cover the two where it sees nothing: a response lost in transit after the server committed, and the process or machine dying between the server's commit and the local one. In both the device exists, its one key does not, and the next attempt gets a 409 that needs a manual removal -- which `openstream-enrol` now spells out, but cannot perform for a device it does not know was created. Closing those needs an idempotent enrolment keyed by a durable client-generated request id; it is not built |
| A headless machine able to authenticate at all | **implemented** -- `POST /v1/auth/device` takes a signature from the identity key the device enrolled with, over a transcript binding the **account and** the device, a 30-second window and a single-use nonce. Before this, the only device-bound token came from a password sign-in, which a network-facing service must not hold, so an enrolled and trusted machine still could not announce presence. It issues an access token and no refresh token: a device re-proves itself from its key, and minting refresh tokens it discards would have consumed the account's sixteen slots within hours and evicted its owner's sign-ins. **Not yet called by the machine service.** |
| **A machine actually enrolled, and a session run through the chain** | **not done** -- no machine has a grant key, so every broker refuses every session |

So the chain is joined in source from approval to broker, and tested at every
seam -- but **no real session has run through it end to end**, and that is the
only claim this section makes.

What has been exercised against the live control plane: `openstream-enrol`
reaches `POST /v1/devices` over real TLS and is refused with `401 account
authorization required` for an invalid token. That proves the transport, the
route and the authentication boundary. It does not prove enrolment, because no
account token was used, so no device was created, so no grant key exists on any
machine, so every broker still refuses every session. That is the intended
fail-closed posture rather than a regression.

What has been exercised **against a locally run `openstream-signal-server`**,
with the real binaries over real HTTP -- not the live service, and not a
session:

- Registering an account, then enrolling a device: the key file lands 0600 and
  32 bytes, and the key is not printed on success or failure.
- The broker environment file is updated in place: the shipped
  commented-out `OPENSTREAM_BROKER_GRANT_KEY_FILE` and
  `OPENSTREAM_BROKER_DEVICE_ID` lines become real assignments and
  `OPENSTREAM_BROKER_CEILING` is left alone.
- Enrolling the same device id again is refused `409`.
- `DELETE /v1/devices/{device_id}` returns `204`, and re-enrolling then issues a
  **different** key -- so removal really does destroy the old one.
- Pointing the key at an unusable path refuses *before* the request, and the
  device list afterwards confirms no device was created by that attempt.

That is the enrolment half of the chain working for real. It is still not the
chain: the broker is Linux-only, the Linux rig was unreachable, and nothing has
verified an approval or a frame.

**What would finish it:** enrol one machine with a real account token, start the
broker with `OPENSTREAM_BROKER_DEVICE_ID` and `OPENSTREAM_BROKER_GRANT_KEY_FILE`
set, approve a Secure Connect request, and capture a frame. Until that run
exists, nothing here is verified beyond the unit and integration tests.

The remaining work is not desktop work. Only `machine-service` depends on
`host-broker`; the desktop drives `host-agent` directly and never speaks to the
privileged broker.

**On the key file's protection.** Mode bits alone were not the boundary and an
earlier version of this document overstated what was enforced. A file owned by
the *machine service* with mode 0600 is private to the machine service, and the
broker -- being privileged -- can read it perfectly well; the service could then
choose the key its own approvals are checked against. The broker now requires
ownership by its own user, a regular file opened `O_NOFOLLOW`, and a directory
chain no other user can write, because a directory the service can write is one
in which it can replace the file whatever the file's mode says.

### The capability registry is scaffolding, not runtime behaviour

`crates/capability` and its planner are structured and tested, but **nothing in
a shipping path calls them**. The desktop still decides host support from
compile-time OS checks. Before they are wired in, four things in the model are
known to be wrong or unproven, and each would produce a confident answer that is
not true:

- `host_capable()` only finds a capture record and an encoder record for the
  same OS. It does not establish a shared codec, a workable geometry, or that
  the surface one produces is one the other accepts.
- An advertised but unprobed capture backend, and a software encoder, both count
  as usable -- so a machine can be called host-capable without either having
  been demonstrated.
- System-memory capture feeding NVENC is classified `ZeroCopy`, when the
  CPU-to-GPU upload happens inside the backend. The label is simply wrong.
- The 7680x4320@120 limits are nominal format ceilings, not this device's.

So it is a reasonable 1.1 foundation. It does **not** yet deliver automatic
AMD/Intel/NVIDIA selection or multi-GPU choice, and should not be described as
doing so.

### Native multi-monitor is not implemented

Runtime monitor selection works only on Linux X11, and only when this adapter
controls the capture origin. The native Windows and macOS hosts always open with
no display selected, advertise `multi_monitor = false`, and log and ignore any
selection that arrives -- so nothing reports a switch that did not happen, but
nothing performs one either.

Adding it is not a matter of relaxing the gate. The requested display has to be
carried as a **stable** identifier into `NativeConfig` (`display_id` on macOS,
the DXGI output on Windows) and then verified against what the capture source
actually opened: an index into a monitor list is not stable across hotplug, and
a request that silently lands on the wrong screen is worse than one refused.

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
