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
| Package metadata | `Package: openstream-headless-host`, `Architecture: arm64`, `Depends: adduser` |
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

## What is still not proven

- Capture, encode or any media path on this machine.
- The machine service doing anything beyond failing closed. It has no device
  identity, no device authentication and no presence until M2 and M4.
- Pre-login *capture* at the greeter. The broker was active with only a greeter
  session present, which is the service's startup case, not the capture case.
- x86-64. That is what the `linux-deb-install` CI job covers per pull request.
