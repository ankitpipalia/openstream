# Windows native subsystems, physically re-run

**Date:** 2026-09-19 (UTC 22:07)
**SHA:** `c8bf1949a5ed77cef5ebbe7bc821ceecf179d4a4` (`c8bf194`, `main`)
**Machine:** the LAN rig, booted into Windows 10 Home `10.0.19045`
**GPU:** NVIDIA GeForce GTX 970, driver `32.0.15.8266`, driving `2560x1440`
**Profile:** `--release`
**Transcript:** `win-tests.log`

## How it was run, and why that matters

The test binaries were compiled over SSH, which lands in **session 0**. They were
**executed in session 1**, the interactive desktop session, through a scheduled task
registered with `-LogonType Interactive`. The runner records its own session id, and the
transcript shows `session_id=1`. A capture or input test that runs in session 0 proves
nothing, so this is recorded rather than assumed.

Both gates were forced:

```text
OPENSTREAM_REQUIRE_WINDOWS_HOST_RUNTIME=1
OPENSTREAM_REQUIRE_MF_TEST=1
```

**This matters more than it looks.** With those unset the four runtime tests in
`windows-host/src/runtime_smoke.rs` return immediately and `cargo test` reports them as
**passed**, because they are not `#[ignore]`. No CI workflow sets either variable, so the
`windows-latest` leg has been reporting these green while never executing them. Any Windows
result that does not state the gates were forced is not evidence.

## Result

| Suite | Tests | Result |
|---|---|---|
| `openstream-windows-host` | 24 | all passed, exit 0 |
| `openstream-windows-media` | 15 | all passed, exit 0 |

Observations from the forced runtime tests, quoted from the transcript:

- **Desktop Duplication**: `captured 2560x1440, 14745600 bytes`. That byte count is exactly
  `2560 x 1440 x 4`, so the frame is full-size packed BGRA rather than a stride-padded or
  truncated buffer.
- **`SendInput`**: `zero-delta move injected`.
- **Job Object**: `created with kill-on-close and closed`.
- **WASAPI loopback**: `opened; 0 frames in 500 ms (0 is expected while nothing renders);
  dropped samples 0`.
- **D3D11 hardware decode**: `6 frames, centre B=191 G=64 R=16` -- decoded pixels, not a
  frame count.
- **Hardware encode**: `hardware=true name="NVIDIA H.264 Encoder MFT"`. NVENC through the
  Media Foundation transform, with no vendor SDK.

## A correction to what was expected

Queried over SSH from session 0, this machine reported **zero** monitors via
`WmiMonitorBasicDisplayParams`, and `Win32_VideoController` listed a Parsec Virtual Display
Adapter. That led to an expectation that Desktop Duplication would capture a virtual
display and that the evidence would need a caveat saying so.

From session 1 the same queries report **one** monitor, the GTX 970 with an active mode of
`2560x1440`, and the Parsec adapter with no mode at all. The capture came from the real
adapter at the real resolution. The zero-monitor reading was an artefact of asking from
session 0, which is the same class of mistake as running the tests there.

## What this does and does not establish

It establishes that the native Windows subsystems work on this hardware, in an interactive
session, at this SHA: capture, input injection, audio loopback, process lifecycle, hardware
decode and hardware encode.

It does **not** establish Windows hosting, though not for the reason first written here.

An earlier version of this file said there was no capture-to-encode-to-transport executable.
That is wrong. `openstream-windows-host` and `openstream-windows-media` are indeed
library-only, but their consumer is `openstream-ffmpeg-host`, which is a binary, is built for
both Windows targets in CI, and contains a `#[cfg(windows)]` native pipeline wiring Desktop
Duplication to the Media Foundation H.264 encoder. `OPENSTREAM_CAPTURE_BACKEND=native`
selects it and `OPENSTREAM_MF_HARDWARE_ENCODE=1` opts into the hardware MFT. Reading the
library crates' manifests and stopping there was the mistake.

What is genuinely missing is narrower: **no live Windows session has ever run**, in either
direction; there is no LocalSystem or WTS session broker and so no pre-login hosting; there
is no Windows host artifact in the release workflow, only a test-build client; and neither
Windows nor macOS implements multi-monitor discovery, so both always open the first output.

So the subsystems are proven on this hardware and the host path exists in code. What has not
happened is running it.
