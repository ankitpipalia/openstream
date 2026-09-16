# Verification evidence

All commands were run against `cac3b2fd363da00417a79da682bcc1f0299cdb87`.

| Command/evidence | Result | Meaning |
|---|---|---|
| `cargo test --workspace --locked` in `engine/lowlat` | PASS, exit 0 | Local unit/integration suites pass; hardware-dependent tests remain ignored |
| `cargo test --manifest-path desktop/src-tauri/Cargo.toml --locked` | PASS, 39 tests | Desktop Rust runtime contracts pass |
| `npm test -- --run` in `desktop` | PASS, 16 tests | React adapter and shell tests pass |
| `npm run build` in `desktop` | PASS | TypeScript and Vite production bundle succeed |
| GitHub run `34816872196` | PASS, 27/27 jobs | Post-merge CI on exact `main` SHA |
| `./scripts/check-openstream-1-0-release.sh` | FAIL CLOSED, 11 failures | No staged 1.0 artifacts, checksum, SBOM, signing, physical/WAN/package gate evidence |
| `./scripts/wan-acceptance.sh` | FAIL CLOSED, 10 unverified cases | No accepted WAN/NAT/TURN evidence |

The release checker reported missing Linux and macOS artifacts, SHA-256 data,
SPDX SBOM, signing evidence, physical Linux-NVIDIA-to-Apple-Silicon evidence,
WAN/TURN evidence, and package launch/upgrade/rollback evidence.

The WAN checker reported all required cases unverified: direct UDP, TURN,
application relay, IPv4 double NAT, IPv6, symmetric NAT, loss/jitter,
bandwidth limiting, Wi-Fi/Ethernet roaming, and router restart.

CI is broad source/build evidence, not physical-platform or production evidence.
The mobile CI compiles the Rust bridge; `scripts/mobile-acceptance.sh:1-7`
explicitly excludes device decode, signed installation, background-radio, and
thermal testing.
