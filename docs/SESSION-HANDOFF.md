# OpenStream session handoff

**Written 2026-09-17, revised 2026-09-19.** Tracked, deliberately: this lived
as an untracked file at the repository root, where a worktree prune or a
scripted rewrite could destroy it, and one already destroyed an earlier
3,600-line version. `/handoff.md` stays ignored and is not part of a clone;
this file is the only copy, so edit this one.

`docs/STATUS.md` is the authoritative statement of where the product is, and
`docs/plans/OPENSTREAM-1.0-COMPLETION-PLAN.md` is the owner's plan and
supersedes any ordering here. This file says only what a *next session* needs in order to
continue without repeating work.

> **The previous 3,600-line historical work log that lived here is gone, and I
> deleted it by accident** while rewriting this preamble -- a section marker did
> not match and the tail was dropped. The file was never tracked in git, so
> there is no copy to restore. It was obsolete working notes explicitly marked
> "do not act on it", and removing it was the intended outcome of this rewrite;
> losing it rather than retiring it deliberately was not. What it recorded is
> still available in commit messages, PR bodies, and the dated records under
> `docs/acceptance/` and `docs/research/`.

## How to work on this repository

1. **Never push to `main`.** Branch protection now enforces `CI gate`, a
   required review, and applies to administrators. Direct pushes are refused.
   Open a PR, let CI go green, get it reviewed.
2. **Any performance number comes from a `--release` build.** The pixel loops
   are roughly ten times slower in debug; a figure from a debug build describes
   the compiler.
3. **Never write up a build or a unit test as a hardware result.** If a run did
   not happen on real hardware, say which part is unverified and why.
4. **There are three `Cargo.lock` files** -- `engine/lowlat`, `desktop/src-tauri`
   and `engine/lowlat/fuzz`. CI builds all three with `--locked`, so a manifest
   change can break any subset.
5. **Linux-only files are uncompiled on macOS.** To type-check them locally,
   temporarily relax their `cfg(target_os = "linux")` gates and the matching
   target section in `Cargo.toml`, run `cargo check -p <crate>`, then restore.
   Errors about `peercred`, DRM capture or uinput are expected noise; anything
   naming your own types is signal.
6. **Do not `git add -A` from the repository root.** `engine/lowlat/fuzz/corpus`
   accumulates machine-generated inputs that will otherwise land in a commit.
7. **Back up an untracked file before any scripted rewrite of it.** This file
   is tracked now, but `OPERATOR-NOTES.md`, `new-plan.md` and anything under
   `audit-runs/` you have not committed are not, and `git checkout --` restores
   nothing for them. See the note above for what that cost once.

## Where things stand

Read `docs/STATUS.md`. In brief: native capture, encode, decode and presentation
work on macOS and Linux with hardware evidence; Windows, Android and iOS have
never run; the release checker reports NOT READY and should.

## The review round of 2026-09-18

Six findings, five real. What changed:

| Finding | Verdict |
| --- | --- |
| #96 creates and discards refresh tokens | **Real, high.** A host re-authenticating every 7.5 min filled the account's sixteen refresh slots in about two hours and then evicted its owner's sign-ins. Device credentials now have their own type with no refresh token. |
| #96 has ambiguous account selection | **Real, high.** Two accounts can hold a device with the same id *and* the same key -- one machine has one identity key across every account it signs in to. One proof verified against both. The transcript binds the account now and the lookup is direct. |
| #96 is an unbounded unauthenticated lock/CPU path | **Real, high.** It verified Ed25519 under the global store mutex and persisted before releasing it. Now: read the key under the lock, verify outside, re-take it to consume the nonce. On the renewal budget, not the password one. |
| #92 overclaims "cannot strand a machine" | **Real.** The rollback covers every failure the client sees, and neither of the two it cannot: a lost response, and a crash between commits. The row says so. |
| #92 builds device URLs without encoding | **Real.** `/`, `?`, `#`, spaces and `\r\n` are all accepted device ids. Percent-encoded now. |
| #92 has an errno matching bug | **Wrong.** In a pattern `|` is an or-pattern, not bitwise OR. Verified against rustc: `Some(22)` and `Some(102)` match, `Some(118)` does not. Unchanged. |

A second round on #96 found two more, both real:

| Finding | Verdict |
| --- | --- |
| Device access tokens leak in memory indefinitely | **Real, high.** `authorize_access` evicts an expired token only when that same token is presented, and a renewing host abandons its previous one every time. Pruned at issuance now; the test runs 2000 renewals (about a year at the client's cadence) and asserts at most four entries remain. Without the fix: 2001. |
| Unknown devices are refused more cheaply than known ones | **Real.** Both answer 401, but an unknown pair returned before any Ed25519 work -- a timing oracle for "does this account have a device with that id". Unknown pairs are verified against a decoy key now, generated per process so it is certainly a valid curve point. |
| `refresh_after` could schedule renewal after expiry | **Real, non-blocking.** `max(L/2, 30)` renewed a 30-second token at the moment it expired. Floor removed; a zero or missing lifetime is now a malformed response. |

And the packaging blocker, which was the most dangerous because it looked fine:
`RuntimeDirectoryGroup=` **is not a systemd directive**. An unknown key is
logged once and ignored, so the unit read correctly, the packaging check
*required* it, and `/run/openstream` would still have been unreachable by the
service that needs the socket in it. It is `Group=openstream` now, and the check
refuses the non-existent directive by name.

## What is merged

All five pull requests are on `main`, each merged after a full CI run on its
exact rebased head. `main` is `c8bf194`.

| PR | Merge | What it carried |
| --- | --- | --- |
| #93 | `cfd8bf9` | The mailbox close/publish race, the native reconfiguration deadlock, freshness counters corrected to what they measure |
| #95 | `4815a93` | `SCStreamDelegate`, so a stopped capture is distinguishable from a still screen -- plus the fix for a flaky test #93 had introduced |
| #94 | `475300a` | 14 matrix jobs into 9; 29 jobs / 99.9 job-minutes down to 24 / 87.6 |
| #92 | `709452e` | Grant-key boundary, enrolment that cannot lose the one-time key, `DELETE /v1/devices/{id}` that ends the removed device's sessions |
| #96 | `c8bf194` | `POST /v1/auth/device`: a headless machine can get a device-bound token without an account password |

**How they were merged, because it matters.** Branch protection requires one
approving review and applies to administrators, and GitHub refuses to let an
author approve their own pull request -- `ankitpipalia` is the only collaborator
and authored all five, so that requirement could not be satisfied by anyone. On
the owner's explicit instruction the review count was set to 0 for the duration,
with `enforce_admins` and the strict `CI gate` left on throughout, and restored
to 1 immediately afterwards. The restored configuration was diffed field by
field against a snapshot taken before the change and is identical.

`strict: true` means each merge made the remaining branches stale, so every one
was rebased and given a fresh full CI run before going in. No PR was merged on
evidence from a superseded head.

## Open branches, and what each is waiting for

**Written 2026-09-19.** Six pull requests are open against `main` at
`c8bf194`, all green on the `CI gate`. None is merged: branch protection
requires an approving review, and GitHub refuses to let an author approve
their own pull request.

| PR | Branch | What it is |
| --- | --- | --- |
| #97 | `fix/desktop-presence-renewal` | a hosting desktop stops vanishing after 90 s |
| #98 | `fix/connect-requester-trust` | connect checks the asker's trust; a revoked device is refused at the mint |
| #99 | `feat/package-prelogin-subsystem` | the headless `.deb`, installed and started on a real machine |
| #100 | `feat/client-core-control-plane` | presence/connect/devices client in `client-core` |
| #101 | `feat/device-identity-store` | `DeviceIdentityStore::open(path)` |
| #102 | `docs/track-session-handoff` | this file, tracked |

A green gate is not a review. The round of 2026-09-19 asked for changes on
four of the six, and the pattern in the findings is worth keeping: in each
case a test covered one path while a different path behaved differently -- the
release workflow rather than the script it calls, the keystore branch rather
than the file branch, a failed host rather than a disabled one, and a fresh
clone rather than this working copy.

The plan they follow is `docs/plans/OPENSTREAM-1.0-COMPLETION-PLAN.md`, which
is the owner's and supersedes the older ordering in this file. Per-milestone
design notes sit beside it in `docs/plans/`.

`preserve/root-worktree-2026-09-17` is the preserved root checkout.
`docs/archive/deleted-branches-2026-09-17.txt` lists every branch deleted on
2026-09-17 with its SHA and a one-line restore command.

### The packaging branch is no longer held

It was held until a real install had happened. It has now happened, on a
Parallels VM running Ubuntu 26.04 arm64: the package installs, both units
verify, the broker starts, `/run/openstream` comes out `750 root:openstream`,
and the unprivileged `openstream` account opens the broker's socket. Reboot,
upgrade, downgrade, remove and purge all behave. The transcript is in
`audit-runs/2026-09-19-m1-headless-package/`.

**Three things on that branch read correctly and had never once run.**
`RuntimeDirectoryGroup=`, which systemd does not have. The packaging test's
socket check, which killed the broker and then connected to its socket. And the
CI step that runs that test, which invoked `cargo build` from the repository
root where there is no `Cargo.toml`, exited 101, and never reached the script.
All three share one cause: the workflow step only runs on a pull request, and
the branch had none for weeks. A fourth was found only by installing: the
unenrolled machine service restart-looped forever, 12 restarts in 35 seconds.

### The test machines, by what they can prove

Addresses, accounts and key paths are deliberately **not** here. This is a
public repository, and a map of the owner's network is not a capability anyone
needs in order to read the code. They live in `OPERATOR-NOTES.md` at the
repository root, which is ignored; a session without that file should ask for
it rather than rediscover it.

| Machine | Proves | Cannot prove |
| --- | --- | --- |
| **Ubuntu arm64 VM** | packaging, install, systemd unit start, privilege separation, the broker socket, and the control-plane chain once the loop exists | anything about media: it has no accepted capture hardware |
| **Homelab** | that the backend runs and is reachable through a tunnel | nothing about hosting; it is the control plane, not a host |
| **Linux NVIDIA rig** | the one physical host-to-client media path this 1.0 claims | it has been unreachable throughout this work |

Two properties of the homelab constrain how the backend is built and deployed,
and they are worth stating because they are easy to get wrong: it is
**aarch64 with musl**, so an x86-64 or glibc artifact cannot run on it, and it
has **no `curl`**, so a health check or deployment script must not assume one.
Its systemd unit is also not the name the old `deploy/` template used.

**The home line is behind carrier-grade NAT.** The router's WAN interface
holds no public address, which was established by comparing the externally
observed address with the first hops beyond the router, both of which are in
private space. No port forward can expose a relay, so TURN needs a public VPS
and `wan-turn` stays blocked. This is also why the backend's ingress is a
tunnel rather than a forwarded port.

### Device authentication: the pieces exist, the caller does not

`POST /v1/auth/device` (#96, merged) closes the reason machine-level hosting
was not a product path. `/v1/presence` needs a device-bound token, the only way
to get one was a password sign-in, and a service facing the network must not
hold an account password, so an enrolled and *trusted* machine still could not
say it was online and no client could see it.

What is on `main`: the `device_auth_transcript` in `openstream-protocol`, the
endpoint verifying it against the enrolled public key with a 30-second window
and a single-use nonce, and `client-core::device_auth` to produce the proof.

What is in review, and what each unblocks:

- #101 gives the service a key it can sign with, at a path it names, and tells
  a caller whether that key was loaded or just created.
- #100 gives it presence, the pending queue, approve and deny, the account's
  device list, and the host-credential to `Pairing` conversion.
- #98 closes the two gaps on the server side. The loop repeats the requester
  check as defence in depth, but the server is where it has to hold: a host
  that trusted the service to filter would be trusting the wrong end.
- #99 creates the account the service runs as and the state directory its
  identity lives in. Without it there is no path for #101 to open.

**What still does not exist is any caller.** The machine service loads a static
pairing from the environment and announces nothing. That is M4, and it is the
single largest remaining piece of the product. What it has to do:

1. Open the identity once from `DeviceIdentityStore` at the path its unit sets,
   and hold it. `StateDirectory=openstream` is already on the unit, so the path
   is `/var/lib/openstream/device-identity.pk8`.
2. Authenticate, then re-authenticate at `DeviceSession::refresh_after()`,
   before the token expires rather than after it is refused.
3. Heartbeat presence every 30 s against the 90 s server TTL.
4. Poll pending requests, approve only a requester that is Trusted in the
   account's own device list, and grant the requested set intersected with
   `OPENSTREAM_HOST_ALLOW`.
5. Convert the host credential to a `Pairing` and hand its grant to the broker,
   instead of reading a pairing file.
6. On 401 discard the token and prove again; on 403 back off visibly. On
   revocation, end the session and release every held input.

Steps 1 to 3 are what make a machine visible. Steps 4 and 5 are what make it
connectable without a hand-made pairing.

**Enrolment still cannot be run as printed.** `openstream-enrol` requires
`--public-key` and nothing produces its value, and the account id that a proof
needs is printed to stderr and then dropped. It belongs in the machine
service's environment file, which the tool is not told about: it is only given
the broker's. That is the rest of M2 and it belongs on the packaging branch.

## Merging, when there is an approval to merge with

Branch protection requires one approving review, applies to administrators,
and uses strict status checks. `ankitpipalia` is the only collaborator and
GitHub refuses to let an author approve their own pull request, so the review
requirement is not satisfiable by anyone. The procedure used on 2026-09-18, on
the owner's explicit instruction, was to set the review count to 0 for the
duration with `enforce_admins` and the strict `CI gate` left on throughout,
restore it to 1 immediately afterwards, and diff the restored configuration
field by field against a snapshot taken beforehand.

**`strict: true` means every merge stales the remaining branches.** Each one
has to be rebased and given a fresh full CI run on its exact head before it
goes in. No pull request is merged on evidence from a superseded head.

The order the owner set for the five open on 2026-09-19, which puts each
dependency ahead of what needs it, adjusted if GitHub reports a conflict:

```text
#101 -> #100 -> #98 -> #99 -> #97
```

## What to do next, in order

The ordering lives in `new-plan.md` (milestones M1 to M10). In terms of what
is actually blocked on what, right now:

1. **Review and merge the five open pull requests.** Nothing downstream can
   start until the two libraries are on `main`, and merging needs an approval
   the sole collaborator cannot give himself. The procedure used last time is
   recorded under "What is merged" below.
2. **The machine service control loop (M4).** The largest remaining piece and
   the one that makes a headless host real: load the identity once from
   `DeviceIdentityStore`, authenticate, renew before expiry, heartbeat presence
   every 30 s against the 90 s TTL, poll pending requests, approve only a
   requester that is Trusted in the account's own device list, intersect the
   requested set with `OPENSTREAM_HOST_ALLOW`, convert the host credential to a
   `Pairing` and hand the grant to the broker.

   **It needs all four of the library and contract changes, not just the two
   libraries.** #101 for a key it can sign with at a path its unit names, #100
   for presence, the pending queue and the credential conversion, #98 because
   the loop's own trust check is only half the boundary -- the server has to
   refuse an untrusted asker too, or a pending device still reaches the host --
   and #99 because the identity path the loop reads is created by
   `StateDirectory=openstream` in the packaged unit, and the service it runs as
   is created by the package's postinst.

   A spawned session future must own everything it uses; do not hand a borrowed
   future to `tokio::spawn`. If the media session is deliberately not `Send`,
   give it a dedicated thread with its own current-thread runtime and test its
   shutdown, rather than hiding the mismatch.
3. **The rest of M2 on the packaging branch:** `openstream-enrol` taking
   `--identity-store`, `--machine-env-file` and `--identity-owner`, so the
   enrolment line `postinst` prints can actually be run. Today `--public-key`
   is required with nothing that produces its value, and the account id the
   proof needs is printed and then dropped.
4. **Redeploy the backend (M6).** `/version` 404s, so no evidence collected
   against the live service can name the code it ran. Target is
   `aarch64-unknown-linux-musl`; the homelab has a native toolchain, so it can
   be built there from a clean checkout at the frozen SHA. No `curl` on that
   box, and the unit is `openstream-signal.service`.
5. **Then the chain end to end on the VM (M7)**, and only after that the
   hardware-blocked rows: the NVIDIA rig, Windows, Android, iOS, and WAN.

## Three things worth copying

**Read the neighbouring mutator.** `DELETE /v1/devices/{id}` shipped, in its
first version, invalidating the device's tokens and nothing else -- while
`set_device_trust` right next to it tore down the revoked device's live
sessions and carried a comment explaining why. Removal is strictly stronger
than revocation and was doing less. After writing a mutating endpoint, read the
neighbouring one that mutates the same thing and check you do at least as much.

**Run the thing that has never run, before trusting what it says.** Four faults
on the packaging branch were each invisible to every check the repository had,
and three of them were invisible *because the check itself had never executed*:
a systemd directive that does not exist, a socket test that killed the process
before connecting to it, and a CI step that ran `cargo` from a directory with
no workspace. A check that has never failed and never passed is not evidence.
The fourth needed an install: a service that restart-looped forever.

**Restore a teeth-check edit with `cp`, never `git checkout --`.** The latter
restores from the index, so it discards every unstaged change in that file. It
silently destroyed a finished `DeviceIdentityStore` implementation here on
2026-09-19; it had to be rebuilt.

## The soak flake, which is now a gate failure

`history_backpressure_keeps_receive_path_alive` failed the macOS job of run
35236380694 on PR #92: `portable_transport.rs:1354`, "sender receives a
transport ACK: Elapsed(())". Two earlier attempts (#80, #84) did not fix it.

What is known now, which is more than before:

- `LIVENESS_TIMEOUT` is **10 seconds** and the test ran 11.24s before failing.
  That is a hang waiting for an ACK that never arrives, not a slow runner.
- 30 local macOS runs with `--test-threads=1`: zero failures. It is
  load-dependent.
- Stale eviction in `transport-policy/src/delivery.rs` happens only when a new
  packet reuses a history slot -- there is no background timer. So one lost ACK
  leaves `in_flight` above zero permanently and the drain loop waits forever.
  That part still stands, and is the reason the failure is a hang rather than a
  wrong number.

**A receive-buffer overflow was the obvious explanation, and it is wrong.** The
theory was that the test sends 2048 unpaced packets and then makes 2048
`receiver.recv()` calls while the sender is not reading its socket, overflowing
the sender's receive buffer and dropping the ACKs it then waits for. Tested by
patching `request_receive_buffer` in `transport/src/lib.rs` to force a tiny
buffer: at 4096, 16384 and 65536 bytes the test passes in 1.18s every time,
identically. So ACK loss from buffer pressure is not what happens here. The
likely reason the theory fails is that the receiver coalesces ACKs -- see
`TransportAckWindow` and its `next_wake` -- so 2048 packets do not produce
anything like 2048 ACK datagrams to lose.

Also not reproducible by load alone: 40 runs at 8x parallelism on a 10-core M1
Max, zero failures. Whatever this is, it needs either a much slower machine or
an actual instrumented count.

**What to do next**: count the ACKs the receiver emits against the ACKs the
sender consumes, on the failing path, rather than theorising about the socket.
If they match, the bug is in the window's scheduling rather than in delivery.

## Latency: what is known

The host's remaining per-frame cost is the encode itself, around 11 ms at
1920x1080 on an M1 Max. What was removed was a wait: VideoToolbox finishes on
its own thread and the host only collected output when submitting the next
frame, so every finished access unit sat for a whole inter-frame gap. Measured
34.8 ms -> 11.1 ms mean, p95 103.3 ms -> 12.6 ms.

`cargo run --release -p openstream-macos-host --example encode_queue_depth`
re-measures it and reports which optional encoder properties this machine
accepted. On an M1 Max: low-latency rate control yes, `DataRateLimits` yes,
`MaxFrameDelayCount` and the speed-over-quality hint both refused -- which costs
nothing, because the same measurement showed the encoder's queue was never where
the latency was.

The next constraint is the presenter and the swapchain, at 40 fps into a 60 Hz
display.
