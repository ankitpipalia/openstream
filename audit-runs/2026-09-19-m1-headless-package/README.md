# M1 evidence: headless Linux package, installed and started

**Date:** 2026-09-19
**Branch:** `feat/package-prelogin-subsystem`
**Base:** `origin/main` at `c8bf194` (contained in the branch)
**Machine:** Parallels VM "Ubuntu 26.04 ARM64", Ubuntu 26.04 LTS, `aarch64`,
6 vCPU, 7.4 GB, `dpkg --print-architecture` = `arm64`, systemd as PID 1.
**Toolchain:** rustc 1.98.1, cc (Ubuntu 15.2.0-16ubuntu1) 15.2.0.
**Artifact:** `openstream-headless-host_1.0.0_arm64.deb`, built in the VM from
`cargo build --release --locked` of the three headless crates (2m04s).

This is a **control-plane and packaging** result. It proves nothing about
capture, encoding, or a media session: the VM has no accepted capture hardware.

## What was observed

| Check | Result |
|---|---|
| Package metadata | `Package: openstream-headless-host`, `Architecture: arm64`, `Depends: adduser, libc6 (>= 2.34), libgcc-s1 (>= 4.2)`, `Conflicts`/`Replaces: openstream` |
| Contents | the three binaries and two system units only; no shell, signal server, host agent, FFmpeg host or `.desktop` entry |
| Account | `openstream:x:100:106::/nonexistent:/usr/sbin/nologin` |
| Configuration | `/etc/openstream` `700 root:root`; both `.env` files `600 root:root` |
| `systemd-analyze verify` | both units accepted |
| Broker unit | `active` |
| Runtime directory | `/run/openstream` `750 root:openstream` |
| Socket | `/run/openstream/broker.sock` `660 root:openstream` |
| **Privilege split** | `sudo -u openstream` opened the socket: "CONNECTED as openstream" |
| Unenrolled machine service | exits `PairingRequired`, settles in `failed` after 3 attempts |
| Reboot | broker `active` and socket reachable by the service account after reboot |
| Session state at that point | GDM `greeter` session only, no graphical user session; autologin not configured |
| Upgrade 1.0.0 to 1.0.1 | operator's `OPENSTREAM_BROKER_CEILING` preserved, broker stayed active |
| Downgrade 1.0.1 to 1.0.0 | preserved, broker active |
| Remove | units stopped and disabled, binaries and units gone, configuration and state retained, account retained |
| Purge | `/etc/openstream` and `/var/lib/openstream` removed, identity key included; account retained by design |
| World-readable files | none under `/etc/openstream` or `/var/lib/openstream` |

## Two defects this run found

**The machine service restart-looped forever when unenrolled.** Measured at 12
restarts in the first 35 seconds, with `systemctl is-active` reporting
`activating` indefinitely. An operator looking for why the machine never came
online saw a service that appeared to be trying. `StartLimitIntervalSec=60` and
`StartLimitBurst=3` now hold it in `failed`, where the status and journal name
the reason.

**The functional half of `scripts/test-linux-packaging.sh` could never have
passed.** It killed the broker and then connected to its socket, so the connect
always failed; the socket file outlives the process, which is exactly the case
the check was written to catch. It had never run, because the workflow step that
invokes it only runs on a pull request and the branch had none. The kill now
happens after the connection attempt, and the check passes against a live
broker.

## Added after review, 2026-09-19

The review of this branch found three more things, each verified on the same
machine:

- The published **tarball** still omitted the subsystem. The fallback in
  `scripts/build-release-artifacts.sh` had been updated, but the release
  workflow supplies `OPENSTREAM_LINUX_PACKAGE`, so that fallback never runs and
  the tarball is whatever the `linux-package` job staged: four binaries and no
  system units. The job builds and stages all seven now, and inspects what it
  produced rather than what it assembled.
- The package **declared no library dependencies**. `Depends: adduser` was true
  of the maintainer scripts and false of the programs. `dpkg-shlibdeps` now
  supplies them, which took two corrections to get working: it needs a
  `debian/control` in its working directory, and it must be pointed at the
  binaries where they were built, because the control file is written before
  they are staged. It produced nothing, quietly, until both were right.
- The two profiles **own the same paths** with no declared relationship, so
  installing one over the other would have failed on overlapping files rather
  than replacing it. They now declare `Conflicts`/`Replaces`.

A second round found two more in the same area:

- **The desktop shell was never analysed.** `dpkg-shlibdeps` ran over the
  engine binaries only, and the shell is installed separately, so a desktop
  package could omit its GTK and WebKit runtime while its metadata looked
  automatically generated. The headless CI job cannot see this, because it
  never builds the desktop profile. The packaging check now builds a desktop
  package with a system binary standing in for the shell, chosen because it
  links a library the Rust binaries do not, and asserts that library reaches
  the package's `Depends`. Removing the shell from the analysis fails it with
  "omits what only its shell links against: libselinux1".
- **And it was still fail-open after that.** `--ignore-missing-info` was being
  passed, and dropping it turned out not to be enough on its own: a library
  that cannot be located at all, an unresolvable RPATH for instance, is
  reported as a *warning* and `dpkg-shlibdeps` still exits zero having emitted
  dependencies for everything it could map. Measured on the VM: an ELF linked
  to a library no package provides produced `shlibs:Depends=libc6` and exit 0,
  with and without the flag. The non-empty check passed and the package would
  have shipped looking generated while missing a library it needs. The
  warnings are read now, with two routine merged-`/usr` ones allowed and
  everything else treated as unresolved. A fixture linked against a
  deliberately unmapped library is built and the package creation must fail.
- **Dependency analysis was fail-open.** A missing or failing
  `dpkg-shlibdeps` printed a warning and produced the package anyway, which is
  the exact condition the change was meant to prevent, with metadata that now
  looked generated. It is required now: absent tooling, a failed run, or no
  dependencies at all each refuse. A fully static build is the one legitimate
  case for no dependencies and has to say so through
  `OPENSTREAM_ALLOW_NO_SHLIB_DEPS=1`.

## What is still not proven

- Capture, encode or any media path on this machine.
- The machine service doing anything beyond failing closed. It has no device
  identity, no device authentication and no presence until M2 and M4.
- Pre-login *capture* at the greeter. The broker was active with only a greeter
  session present, which is the service's startup case, not the capture case.
- x86-64. That is what the `linux-deb-install` CI job covers per pull request.
