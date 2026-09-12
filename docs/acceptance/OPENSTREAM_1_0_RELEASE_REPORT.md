# OpenStream 1.0 release report

Status: **NOT READY -- evidence not supplied**

This report is the review checklist for a candidate release. It is not a
substitute for the staged evidence consumed by
`scripts/check-openstream-1-0-release.sh`, and it must not be changed to
`PASS` without attached operator evidence.

| gate | status | evidence |
| --- | --- | --- |
| exact source commit and reproducible build | UNVERIFIED | |
| Linux x86-64 NVIDIA host -> Apple-Silicon macOS client | OBSERVED (fallback path only) | `docs/BUILD.md`, 2026-09-13 runtime-integration re-verification |
| VideoToolbox/Metal path with FFmpeg fallback | UNVERIFIED | |
| keyboard, raw mouse, watchdog, and release cleanup | UNVERIFIED | |
| direct UDP | OBSERVED | `docs/BUILD.md`, 2026-09-13 runtime-integration re-verification |
| external TURN/WAN matrix | UNVERIFIED | |
| application relay and path migration | UNVERIFIED | |
| Linux package launch/upgrade/rollback | UNVERIFIED | |
| macOS arm64 signing/notarization/stapling | UNVERIFIED | |
| checksums and SBOM | UNVERIFIED | |

The repository currently contains loopback and application-owned relay smoke
tests plus capability-gated fallback behavior. Those are useful automated
checks, but they do not satisfy the physical hardware, public WAN, or signing
gates above. Do not publish a production `v1.0.0` tag until every mandatory
release-gate result has independently reviewed evidence.

The two `OBSERVED` rows above are deliberately not `PASS`. They record a real
two-machine session over authenticated direct UDP using the X11/FFmpeg/NVENC
fallback capture and encode path. The `physical-linux-nvidia-to-apple-silicon`
release gate asks for the shipped capture/encode path, and on that host the
supported capture backends could not reach real desktop pixels: `x11grab` sees
only the Xwayland root under a Wayland session, the host FFmpeg has no
`pipewire` demuxer, and `kmsgrab` rejects the display's `ABGR2101010`
framebuffer. That gate stays open until native capture is exercised.

Desktop product-shell integration is separate from this media evidence. The
shell's Rust runtime boundary, its host-agent bridge, and the frontend adapter
that consumes them are checked by `scripts/runtime-spine-smoke.sh` and the
`desktop/src-tauri` and `desktop` test suites. Those are source and unit-level
checks; they are not hardware, WAN, VideoToolbox, zero-copy, or packaging
evidence, and passing them does not advance any release gate above.
