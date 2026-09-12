# OpenStream 1.0 release report

Status: **NOT READY — evidence not supplied**

This report is the review checklist for a candidate release. It is not a
substitute for the staged evidence consumed by
`scripts/check-openstream-1-0-release.sh`, and it must not be changed to
`PASS` without attached operator evidence.

| gate | status | evidence |
| --- | --- | --- |
| exact source commit and reproducible build | UNVERIFIED | |
| Linux x86-64 NVIDIA host → Apple-Silicon macOS client | UNVERIFIED | |
| VideoToolbox/Metal path with FFmpeg fallback | UNVERIFIED | |
| keyboard, raw mouse, watchdog, and release cleanup | UNVERIFIED | |
| direct UDP | UNVERIFIED | |
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
