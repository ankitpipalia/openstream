# M1: package the headless Linux host honestly

## Why this comes first

`openstream-host-broker`, `openstream-machine-service` and `openstream-enrol`
have been built and unit-tested for months without ever being in a package.
That is what kept machine-level hosting an experiment rather than something an
installer can turn on, and it is why nothing downstream of it -- device
enrolment on a real machine, presence from an unattended host, a session
through the approval chain -- has ever run outside a developer's shell.

## What was wrong with the package

The one package the repository built was a workstation package that had the
three machine-level binaries added to it. Three faults followed from that.

**It declared `Depends: ffmpeg`.** The accepted native media path does not use
FFmpeg, and a headless host has no reason to pull a large multimedia stack onto
a server for a fallback 1.0 does not exercise.

**It carried the desktop shell**, the signal server, the per-user host agent and
the FFmpeg host, plus a `.desktop` menu entry, onto machines with no graphical
session to run any of them in.

**It labelled every package `amd64`**, hard-coded in the control file. On this
project's own arm64 test machine that produces a package that installs nowhere
and fails in a way that blames the machine rather than the build.

Separately, two copies of each pre-login unit existed, one under `deploy/` and
one under `packaging/linux/`, and they had already drifted: the `deploy/` copies
still used `/usr/local/bin`, defaulted the broker's admitted uid to 0, and made
the runtime directory `0755` with no `Group=`. The copy an operator read was not
the copy the package installed.

## The change

- `build-deb.sh` takes `--profile desktop|headless` and `--arch DEB_ARCH`. The
  profile is an argument, not an environment switch, because which files land
  in a package should not have to be discovered by reading the script that
  built it. `desktop` is the default and behaves as before.
- The headless profile builds `openstream-headless-host_<version>_<arch>.deb`
  containing the three binaries, their two system units, and nothing else. It
  depends on `adduser`, not on `ffmpeg`.
- The architecture comes from `dpkg --print-architecture` unless given
  explicitly, and is validated.
- The `deploy/` copies of the two units are deleted and `deploy/PRELOGIN.md`
  points at the packaged ones, so there is one source of truth.
- `StateDirectory=openstream` on the machine service, mode `0700`. The account
  runs with `--home /nonexistent` and `ProtectHome=true`, so the device
  identity key M2 introduces has nowhere else it could live.

## How it is tested

`scripts/test-linux-packaging.sh` gains a section that builds a headless package
from stub binaries and inspects it with `dpkg-deb`: the three binaries and two
units are present; the shell, signal server, host agent, FFmpeg host and
`.desktop` entry are absent; the control file names
`openstream-headless-host`, declares no ffmpeg dependency, and is labelled with
the architecture it was built for. Stubs rather than real binaries, because what
is under test is the packaging decision and that needs no compiler. It skips
with a message where `dpkg-deb` is absent, which is how it behaves on macOS.

That is a contents test. The install test is a separate exercise on a real
machine, recorded in this milestone's evidence: install, unit start, socket
reachable as the service account, reboot, upgrade, downgrade, remove.

## What this milestone does not prove

Nothing about capture, encoding or a media session. The Ubuntu VM has no
accepted capture hardware. The machine service also still exits without a
static pairing, which is M4's work; until then its unit is expected to fail
closed rather than run.
