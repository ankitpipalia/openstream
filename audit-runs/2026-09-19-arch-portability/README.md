# Arch Linux ARM portability probe

**Date:** 2026-09-19 (UTC 22:20)
**SHA:** `c8bf1949a5ed77cef5ebbe7bc821ceecf179d4a4` (`c8bf194`, `main`)
**Machine:** Parallels guest, **Arch Linux ARM**, kernel `7.2.6-1-aarch64-ARCH`,
`aarch64`, 4 vCPU, 7.9 GB, systemd 261 as PID 1
**Toolchain:** rustc 1.98.1, the same version as the Ubuntu guest, the Windows
machine and the homelab
**Transcripts:** `preflight.log`, `clippy-and-tests.log`

This is a portability probe, not a packaging target. There is no Arch package and
the `.deb` path does not apply. Its purpose is finding Debian-specific
assumptions, missing runtime libraries and systemd portability defects. It cannot
prove media: the guest has no accepted capture hardware.

## Results

| Check | Result |
|---|---|
| Build of the four Linux crates, `--release --locked` | **clean**, 1m18s, no missing libraries |
| `cargo clippy --workspace --all-targets -- -D warnings` | **clean** |
| `cargo test --workspace` | 12 suites green, **one failure**, see below |
| Preflight honest reporting | **clean**, see below |

No Debian-specific assumption surfaced. The crates built on ARM64 against Arch's
own libraries with nothing patched.

## Honest reporting, which is the point of this guest

The preflight reports absent hardware as absent rather than advertising it:

```text
"preferred_h264_encoder": null      "preferred_h265_encoder": null
"nvenc_h264": false                 "nvidia_smi": false
"native_drm": { "capturable": "nothing_lit", "outputs": [] }
"x11": { "available": false, "error": "no X DISPLAY is set" }
"pipewire": { "available": true, "sources": [] }
"input": { "uinput_present": true, "enabled_by_policy": false }
"ffmpeg": { "available": false, "error": "No such file or directory" }
```

Nothing crashed from any of those absences, which is the behaviour this guest
exists to check. Note that `vaapi_render_node` is present (`/dev/dri/renderD128`,
the virtio GPU) and yet no encoder is claimed: finding a node is not the same as
proving an encoder, and the report keeps them separate.

**The preflight is not read-only.** It compiles, and resolving the local device
identity creates and persists an Ed25519 keypair when none exists. This guest now
has one, and it is the identity it would enrol with.

## The one failure, which is the test rather than the port

`lowlat-host`: `stream::tests::a_finished_picture_does_not_wait_for_the_next_frame`
fails here. It is **not** the defect that test hunts.

That test asserts `encode.p99 < 1000/240 ms`, an absolute wall-clock bound of
4.167 ms. Three runs on an otherwise idle guest:

| Run | p50 | p99 | Bound |
|---|---|---|---|
| 1 | 1.211 ms | 5.434 ms | 4.167 ms |
| 2 | 1.219 ms | 5.038 ms | 4.167 ms |
| 3 | 1.226 ms | 4.232 ms | 4.167 ms |

The bug it targets leaves the median almost unchanged and pushes the tail to a
whole frame interval; the test's own comment records 16.6 ms, which is one frame
at 60 Hz. Here the median is 1.22 ms, exactly the healthy figure that comment
cites, and the tail is 4.2 to 5.4 ms. Run 3 missed by 1.6 per cent.

So the tail is scheduler noise on a 4-core ARM guest, and the assertion cannot
tell that apart from the bug, because at 240 Hz the frame interval is now smaller
than this machine's noise. The margin that made the check meaningful at 60 Hz
disappeared when the harness rate went up; the bound moved from 16.6 ms to
4.167 ms while the noise did not.

This is the same shape as a `thread::sleep` upper bound: it measures the machine,
not the code. It passes on a fast developer machine and fails on anything slower,
so it is a latent CI failure rather than an Arch defect.

A fix should assert the property rather than a wall-clock constant: either drop
the harness rate so an interval sits well clear of scheduler noise, or compare
the tail against the interval with a margin that reflects measurement noise. It
is deliberately **not** fixed here, because changing a carefully reasoned test's
semantics deserves its own review.
