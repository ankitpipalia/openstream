# OpenStream 1.0 completion program

Baseline: `origin/main` / `.worktrees/production-completion` at `c8bf194` on
2026-09-19. This is a program plan, not a claim that 1.0 is ready.

## 1. Release scope and non-negotiable rules

The evidence-supported 1.0 scope is deliberately narrow:

- Linux x86-64 NVIDIA host, including an unattended machine service after boot.
- Apple Silicon macOS client.
- Self-hosted account, device-trust, presence, Secure Connect and signalling service.
- Direct encrypted UDP through ICE/STUN, with TURN/UDP relay fallback.
- Keyboard, pointer, gamepad, video and audio only where the frozen acceptance matrix proves them.

Windows hosting/client qualification, Android/iOS clients, AMD/Intel host qualification,
multi-distro certification, macOS hosting, TURN/TCP/TLS, runtime ICE restart and native
PipeWire DMA-BUF remain post-1.0 unless separately implemented and physically proven. Do not
describe a compiling target as supported.

Rules for every milestone:

1. Work from a current-main isolated worktree. Never develop from the stale repository-root
   checkout.
2. One focused PR per independently reviewable boundary. Full CI must pass on the exact head.
3. Add a failing regression test before each bug fix and confirm it fails for the intended
   reason. Avoid scheduler wall-clock upper bounds.
4. No secret, private key, bearer token, grant key or password in commands, logs, screenshots,
   evidence, PR text or this plan. Secrets are read from stdin or `0600` files.
5. Never weaken the release checker or mark a gate PASS to make progress appear complete.
6. Physical, WAN and packaging evidence must name the exact source SHA and artifact digest.
7. No FFmpeg in the accepted native host/client media path. If a fallback remains packaged,
   document it separately and do not exercise it in 1.0 acceptance.
8. Before implementing each milestone, write a short design and execution plan under
   `docs/plans/`; this master plan records order and release gates, not line-by-line code.

## 2. Verified starting point

- `main` is `c8bf194`; its composed CI run passed 24/24.
- No PR is open.
- The held packaging branch is `feat/package-prelogin-subsystem` at `a3c0441`, contains
  `c8bf194`, and has never had its `.deb` installed or its units started.
- The public backend health endpoint works, but `/version` returns 404; the deployed binary is
  therefore not the current source.
- The release checker reports NOT READY with nine failures. Only direct-UDP WAN evidence is
  recorded; nine WAN cases are unverified.
- The Linux NVIDIA rig is currently unreachable.
- An Ubuntu 26.04 ARM64 Parallels VM is available and suspended (2 vCPUs, virtio
  network on the shared NAT, Parallels Tools 27 installed).
- `openstream-machine-service` still uses a static pairing and does not perform device auth,
  presence, pending-request approval or session launch.
- The desktop host announces presence once, although server presence expires after 90 seconds.
- The packaging branch contains the corrected systemd units; the copies under `deploy/` are
  stale and must not remain as competing sources of truth.

Resolved by direct inspection on 2026-09-19; these replace the assumptions the
milestones below were written against. Addresses, accounts and key paths are in
`OPERATOR-NOTES.md`, which is ignored: this is a public repository and the
owner's network map is not something a reader needs.

- **The homelab that runs the backend is reachable** on an existing key. It is
  `aarch64` with **musl libc**, systemd as PID 1, 8 cores. An x86-64 or glibc
  artifact cannot run on it.
- **It has a native Rust toolchain and `wget`, but no `curl`.** The backend can
  be built on the box, and no health-check or deployment script may assume
  `curl`.
- **Its systemd unit is not the name the `deploy/` template used**, it runs as
  its own account from a root-owned environment file, and it is bound to
  loopback behind a Cloudflare Tunnel. Locally `/healthz` answers and
  `/version` is 404, matching the public symptom: the binary predates that
  route.
- **The home line is behind carrier-grade NAT.** The router's WAN interface
  holds no public address; the externally observed address does not match, and
  the first hops beyond the router are in private space. A UDP port-forward for
  TURN is therefore impossible on this line, which is also why the ingress is a
  tunnel. M9's conditional resolves to **a VPS is required**.
- **`POST /v1/connect` checks only the target's trust.** Confirmed in
  `connect_request` (`crates/signal-server/src/main.rs`): it reads the
  requester's device id from `connect_principal` and never consults its trust,
  while the target must be `Trusted`. The M3 server change is real work.

## 3. Corrections to the original plan

These decisions are mandatory because the previous draft would have introduced correctness or
security problems:

- Do not make the environment-driven private `local_identity()` the public product API and do
  not reload the identity on every renewal. Add an explicit path-based identity-store API, load
  the key once at process start and hold it for that process lifetime. Rotation is an explicit
  restart operation.
- Do not rely only on a host-side policy check for an untrusted requester. The signal server
  must reject `POST /v1/connect` unless both requester and target are trusted. The machine
  service repeats the check as defense in depth.
- Desktop presence renewal is required 1.0 work, not optional. A host that disappears after
  90 seconds is not a functioning product.
- A spawned session future must own everything it uses. Do not specify `async fn run(&self)` and
  then pass its borrowed future to `tokio::spawn`. Use an owned `Arc` runner/future with a
  compile-time `Send + 'static` assertion, or a dedicated current-thread runtime if the media
  session is intentionally non-`Send`.
- Enrollment must not depend on hidden UID/GID environment variables. Use explicit CLI options
  for non-secret paths and ownership, validate existing-file ownership, and prepare all local
  destinations before making the server request.
- The headless package must not contain the legacy FFmpeg host or declare an FFmpeg dependency.
  It is a distinct package/profile, not the full desktop package with random files omitted by
  an undocumented environment switch.
- TURN on the home server is conditional on a real public router address. If the router is under
  CGNAT, use a public VPS. Cloudflare Tunnel is only for HTTPS/WSS signalling, never public TURN.
- A VM approval-chain run proves control-plane authorization and broker delivery. It does not
  prove capture, encoding or a media session.
- A release candidate cannot be called ready except for signing while the physical
  Linux-NVIDIA-to-Apple-Silicon gate is stale or unavailable. Re-run it against the frozen RC.

## 3b. Progress, 2026-09-19

Branches are open against `main` at `c8bf194`. None is merged; branch
protection requires an approval the sole collaborator cannot give himself.

| Milestone | PR | State |
|---|---|---|
| M5 desktop presence renewal | #97 | CI green |
| M3 server authorization | #98 | CI green |
| M1 headless package | #99 | install job green on x86-64; rerun after a CI fix |
| M3 portable control client | #100 | CI running |
| M2, M4, M6 to M10 | none | not started |

Three faults were found by running things that had never run, all on the
packaging branch, and all of which read correctly:

- `RuntimeDirectoryGroup=`, a systemd directive that does not exist. Found
  before this session.
- The packaging test's socket check killed the broker and then connected to
  its socket, so it could never pass.
- The `Linux packaging configuration` CI step ran `cargo build` from the
  repository root, where there is no `Cargo.toml`. Cargo exited 101 and the
  script never ran.

The common cause is the same one the milestone order is built around: that
step only runs on a pull request, and the branch had none for weeks.

A fourth was found by installing the package: the unenrolled machine service
restart-looped forever, 12 restarts in 35 seconds, reporting `activating`.

The Ubuntu arm64 VM is provisioned: an installed key, a Rust toolchain and
passwordless sudo, with the repository synced into it. Its sizing was raised
for build speed; `OPERATOR-NOTES.md` records the original values and how to
restore them. It has no accepted capture hardware, so it can never prove a
media session.

## 4. Dependency order

| Milestone | Result | Depends on |
|---|---|---|
| M1 | Installable headless Linux package and one source of systemd units | current main |
| M2 | Explicit identity/enrollment contract with crash-safe ownership | M1 |
| M3 | Portable control-plane client plus server authorization hardening | current main; may run beside M1 |
| M4 | Machine-service auth/presence/approval/session state machine | M2, M3 |
| M5 | Desktop presence renewal | current main; independent |
| M6 | SHA-pinned backend deployment | merged server changes |
| M7 | Control-plane-to-broker acceptance on Ubuntu | M1-M6 |
| M8 | Soak diagnostics and deterministic stress evidence | independent |
| M9 | Direct-WAN, TURN/UDP and outage matrix | M6, M7, reachable rig |
| M10 | Frozen RC, package/physical/WAN/signing evidence | all applicable milestones |

## 5. M1 - package the headless Linux service honestly

Start by rebasing `feat/package-prelogin-subsystem` onto current main. Preserve the branch until
its history and diff are backed up.

Required changes:

- Consolidate the authoritative service files under `packaging/linux/`. Remove the stale
  `deploy/openstream-host-broker.service` and `deploy/openstream-machine-service.service`, and
  make deployment documentation link to the packaged copies.
- Replace the implicit headless environment toggle with an explicit build profile such as
  `packaging/linux/build-deb.sh --profile headless --arch <deb-arch>`.
- Produce an unambiguous package such as `openstream-headless-host_<version>_<arch>.deb`.
- The headless package contains only the broker, machine service, enrollment tool, their system
  units and required native runtime files. It contains no desktop shell, signal server, legacy
  host-agent, FFmpeg host, desktop file or `Depends: ffmpeg`.
- Derive Debian architecture from `dpkg --print-architecture` unless an explicit validated
  argument is supplied. Never label an ARM64 package `amd64`.
- Use a real `openstream` system account, `StateDirectory=openstream`, private configuration,
  and a broker runtime directory/socket reachable by the service group. Reject unknown systemd
  directives in tests.

Verification:

1. Resume the Ubuntu ARM64 VM, build the binaries and package inside it, install with `dpkg -i`,
   and run `systemd-analyze verify` on both units.
2. Start the broker and prove a connection to `/run/openstream/broker.sock` as user
   `openstream`. Use a repository-owned socket probe or test binary; do not assume `nc` exists.
3. Confirm the unenrolled machine service fails closed with a clear status, not a crash loop.
4. Enable both units, reboot without logging in and verify the broker is active.
5. Test upgrade, downgrade, remove and purge separately. Configuration and identity survive
   ordinary removal; purge behavior is explicit.
6. Assert no file under `/etc/openstream` or `/var/lib/openstream` is world-readable.
7. Add an x86-64 `linux-deb-install` CI job. It must fail if PID 1 is not systemd rather than
   silently claiming a start test. Keep `systemd-analyze verify` even when the actual start runs.

Do not merge M1 until both the ARM64 VM transcript and exact-head x86-64 CI are green.

## 6. M2 - explicit identity store and crash-safe enrollment

Create a library API in `openstream-client-core` that does not read process-global environment:

```text
DeviceIdentityStore::open(path)
  -> Loaded { key, source }
  -> Created { key, source }
```

The returned key is owned by the caller and remains loaded for the process lifetime. The API
retains the current file-mode, owner, symlink/reparse-point, atomic-publication and keystore
rules. Existing convenience functions may wrap it, but product services pass an explicit path.

Change `openstream-enrol` to accept non-secret options such as:

```text
--identity-store /var/lib/openstream/device-identity.pk8
--machine-env-file /etc/openstream/machine-service.env
--identity-owner openstream
```

The account access token continues to arrive only through stdin. Before the network request,
the command creates and validates the destination directory, identity, broker grant-key path
and environment-file parent. It installs files atomically and verifies the owner/mode even when
the identity already existed.

Close the enrollment response-loss window before calling this 1.0-ready. Write a separate
threat-model/design note first. The protocol must make a retry return the same logical
enrollment without storing or logging a recoverable plaintext grant secret. Prefer a
client-generated grant secret plus a server-stored verifier and durable client request ID; do
not add server-side plaintext escrow merely for idempotency.

Tests cover concurrent creation, existing root-owned files, interruption before publication,
retry after a lost response, no secret in `Debug`, and owner/mode checks on Linux.

## 7. M3 - portable control client and server-side authorization

Add dependency-light endpoint modules to `openstream-client-core` using its existing HTTP
implementation, not desktop `reqwest`:

- presence announce/withdraw;
- pending connect requests, approve and deny;
- device listing/trust representation;
- conversion from a host-role credential to `Pairing`, refusing every other role.

Keep one canonical wire representation for permissions. If separate crate types remain, use
explicit conversions and round-trip tests so identical-looking structs cannot drift.

Server changes:

1. `POST /v1/connect` checks that the authenticated requester device is Trusted before creating
   a request. Existing target trust remains required.
2. After a valid device proof, a Revoked device receives a stable 403 rather than a token that
   is immediately evicted. Unknown-device work remains covered by the decoy verification path.
3. Tests prove requester pending/revoked is rejected, target pending/revoked is rejected, and
   no role ever receives the other role's credential.

## 8. M4 - machine-service control state machine

Implement a state machine with explicit phases:

```text
Boot -> Authenticate -> Online/Waiting -> Approving -> Hosting
  ^          |               |              |          |
  +----------+---------------+--------------+----------+
       bounded retry, revocation, network loss, session exit
```

Required behavior:

- Load the identity once from the configured store.
- Authenticate with the device proof and renew before the access token expires.
- Announce presence every 30 seconds against the 90-second server TTL.
- Poll pending requests at a bounded cadence.
- Deny requesters absent from the same account's trusted device list.
- Intersect requested permissions with `OPENSTREAM_HOST_ALLOW`; default to view-only.
- Approve once, convert only the host credential to a pairing, and send the grant to the broker.
- Continue authentication and presence while hosting, but reject a second session as busy.
- On 401, discard the token and re-authenticate. On 403, back off visibly without hammering the
  server. On revocation, terminate the active session and release all input.
- Withdraw presence on orderly shutdown. Process death relies on server TTL.
- Static pairing remains available only under an explicit developer-only override.

Session execution must have an owned lifetime. Prefer `Arc<dyn SessionRunner>` returning a
boxed `Send + 'static` future and add a compile-time assertion. If the media implementation is
non-`Send`, use a dedicated OS thread/current-thread runtime and test its shutdown; do not hide
the mismatch behind unsafe code.

Integration tests start the real signal-server binary on loopback and cover registration,
enrollment, trust, device auth, repeated presence, request, approval, idempotent response,
broker delivery, busy denial, revocation, server restart, token expiry and cold process restart.
Inject the identity store/owned identity into the loop; tests must not mutate global identity
environment variables.

## 9. M5 - keep desktop hosts present

While hosting is enabled, renew presence on an existing application timer with jitter and stop
on disable/logout. Test across at least three server TTL intervals with a fake clock; do not use
sleep-duration upper bounds. Network failures use bounded backoff and do not disable the host.

This milestone is a 1.0 blocker because one-shot presence currently expires in 90 seconds.

## 10. M6 - deploy the backend from a reproducible artifact

The homelab is confirmed aarch64 musl with a native Rust toolchain, so the target is
`aarch64-unknown-linux-musl` and the build can run on the box itself. Prefer a
release-workflow artifact with checksum and provenance so the deployed bytes are attested;
fall back to a native build from a clean checkout at the frozen SHA with
`OPENSTREAM_BUILD_SHA` set explicitly, and record which path was used.

Deploy atomically while preserving `/etc/openstream/signal.env` and the durable control-state
file. A deployment script takes an artifact path and expected SHA, retains the previous
binary, restarts, and rolls back unless local `/healthz` and public `/version` both match. It
never prints the environment file. Two details the box imposes: the unit is
`openstream-signal.service`, and `curl` is absent, so health checks use `wget` or `python3`.

Reconcile the stale templates in the same change: `deploy/openstream-signal-server.service`
does not match the unit actually running, and leaving both invites deploying the wrong one.

Cloudflare remains the HTTPS/WSS ingress for `signal.ankitpipalia.site`; the origin stays bound
to loopback. Record the deployed SHA in `docs/STATUS.md`.

## 11. M7 - authorization acceptance on Ubuntu

On the Ubuntu VM, use the packaged tools against the deployed backend:

1. Enroll using a token supplied by stdin.
2. Trust the machine from the desktop UI.
3. Start/restart the machine service and verify stable identity plus repeated online presence.
4. Request a connection from a second trusted device.
5. Verify policy intersection, approval and broker grant delivery.
6. Revoke during a session attempt and verify presence stops, broker state drains and no input
   remains held.
7. Re-trust and verify recovery without re-enrollment.

Name this evidence `control-plane-to-broker authorization acceptance`. The VM has no accepted
capture/NVENC hardware, so it is not a completed remote-desktop session.

## 12. M8 - instrument the soak flake without weakening it

Add bounded, secret-free telemetry for ACK scheduled/emitted/force-flushed/consumed,
delivery-history occupancy, `HistoryFull`, stale eviction, queue depth and last-progress age.
Print the snapshot only on test failure.

Run 20-40 repetitions under CPU load locally and through a manually dispatched or opt-in stress
workflow. Do not put a nondeterministic soak loop on every PR, change the 10-second liveness
contract, or use zero-loss UDP as the test oracle.

## 13. M9 - TURN/UDP and WAN acceptance

This comparison has been made and it settles the question: the home line is behind
carrier-grade NAT (see section 2), so no port-forward can expose a relay and the homelab
cannot host TURN. **A VPS with a public static IP is required, and none is available today.**
`wan-turn` is therefore an external blocker: record it as such, keep the coturn configuration
and the acceptance procedure ready to run, and do not let it hold up any other milestone. The
direct-ICE and outage cases below do not need TURN and should proceed without it.

coturn requirements:

- UDP 3478 and a bounded relay range only;
- long-term/shared-secret authentication, explicit realm and secret rotation procedure;
- firewall permits only required ports; management interfaces are not public;
- TURN credentials and usernames are redacted from logs/evidence.

The 1.0 claim is TURN/UDP fallback. Networks that block UDP entirely remain unsupported until
TURN/TCP/TLS is implemented and tested.

Acceptance, with Mac on a phone hotspot and Linux host on the home LAN:

1. Direct ICE for 15 minutes; prove the selected pair is non-relay.
2. Forced relay for 15 minutes; prove the selected pair is relay and coturn byte counters move.
3. Stop signalling with an automatic timed restart already armed. Existing media/input must
   continue; a new session must fail, then recover after restart.
4. Run double-NAT, symmetric-NAT, IPv4/IPv6 where available, loss/jitter, router restart and
   client-network-change cases.
5. Apply impairment only in a namespace or non-management interface. Never risk the SSH/control
   path with an unguarded `tc` command.

Each matrix row records host/client/backend SHAs, package digests, selected ICE pair, packet and
frame counters, duration, result and sanitized logs.

## 14. M10 - freeze and qualify the release candidate

Freeze one SHA only after M1-M9 are merged. Rebuild every artifact from that SHA. Generate and
verify checksums, SBOM, provenance and package contents. Then run this evidence ladder without
skipping stages:

```text
source + CI
-> clean install
-> control-plane/broker acceptance
-> physical Linux NVIDIA -> Apple Silicon LAN session
-> WAN direct session
-> TURN/UDP session
-> signalling outage/recovery
-> upgrade/downgrade/rollback
-> signed/notarized packages
```

The physical Linux-NVIDIA-to-Apple-Silicon run must be repeated with the frozen artifacts; old
hardware evidence cannot qualify a new RC. The release checker remains NOT READY while the rig
is unavailable or signing identities are absent. Do not describe that state as "signing only."

## 15. Required evidence and final decision

Store sanitized evidence under a dated directory in `audit-runs/` and link it from
`docs/STATUS.md`. At minimum include:

- exact branch, HEAD, origin/main, merge base and dirty-state record;
- exact CI run URLs for every merged head and final main;
- package manifests, architecture, install/upgrade/remove transcripts and permissions;
- backend `/version` and artifact attestation verification;
- control-plane/broker integration report;
- physical LAN and WAN/TURN matrices with frame-count liveness;
- release-checker and WAN-checker output;
- signing/notarization/installer launch evidence, or explicit FAIL/UNAVAILABLE.

Only publish OpenStream 1.0 when every mandatory gate for the narrow 1.0 scope is PASS against
the same frozen SHA. Otherwise the decision remains NO-GO or CONDITIONAL GO with the unresolved
conditions named; compiling and green CI alone are never sufficient.

