# Task 2 report: pinned Alpine/musl required CI job

## Changed files

- `.github/workflows/ci.yml`
  - Added the executable helper check to the `alpine-musl` job.
  - Added `sh -n scripts/alpine-musl-ci.sh` to the existing `check` job.
  - Added the Ubuntu-hosted, pinned amd64 Alpine/musl Docker job.
  - Added `alpine-musl` to `ci-gate.needs`, exported `ALPINE_MUSL`, and included it in the required-result loop.
- `engine/lowlat/scripts/alpine-musl-ci.sh`
  - Added the executable POSIX helper with the pinned Rust assertion, musl tests, C11/C++17 ABI checks, `/tmp` object outputs, and success line.

## RED evidence

The mandated pre-helper check was run before creating the helper:

```text
$ cd engine/lowlat && test -x scripts/alpine-musl-ci.sh
```

Result: exit status `1`, with no output, because the helper did not exist.

## GREEN evidence

After adding the helper, the executable and required verification checks passed:

```text
$ cd engine/lowlat && sh -n scripts/alpine-musl-ci.sh && test -x scripts/alpine-musl-ci.sh && cargo fmt --all -- --check
```

Result: exit status `0`, no output.

The workflow YAML parsed successfully:

```text
$ ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml"); puts "ci.yml YAML parse passed"'
ci.yml YAML parse passed
```

Whitespace validation also passed:

```text
$ git diff --check
```

Result: exit status `0`.

## Verification commands and outputs

- `sh -n engine/lowlat/scripts/alpine-musl-ci.sh`: passed as part of the combined GREEN command above.
- `cargo fmt --all -- --check`: passed as part of the combined GREEN command above.
- Executable bit check: `stat` reported `-rwxr-xr-x engine/lowlat/scripts/alpine-musl-ci.sh`.
- Workflow YAML parse: passed as shown above.
- Exact Docker command from the brief was attempted from the repository root. It could not start because the local Docker daemon socket is unavailable:

```text
failed to connect to the docker API at unix:///Users/ankitpipalia/.docker/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /Users/ankitpipalia/.docker/run/docker.sock: connect: no such file or directory
```

## Self-review findings

- The helper uses `#!/bin/sh` and `set -eu`, installs only `build-base`, asserts Rust `1.85.0`, sets `CARGO_TARGET_DIR=/tmp/openstream-musl-target`, runs the specified locked lowlat tests, and compiles the C11/C++17 consumers with the required warnings and include path.
- Both object files are written under `/tmp`.
- The workflow uses `runs-on: ubuntu-latest`, `actions/checkout@v7`, `--platform linux/amd64`, the exact image digest, a read-write `/workspace` bind mount, `-w /workspace/engine/lowlat`, and the helper command.
- No job-level container was added; existing jobs and gate checks remain intact, with Alpine/musl added as an additional required result.
- No GitHub Actions run was dispatched or checked by SHA locally. The first pushed run must be checked by SHA and the repository must not be called green until `CI gate` succeeds.

## Concerns

The exact musl compilation/test command remains unverified locally because Docker is installed but its daemon is not running. GitHub Actions validation is still required after the commit is pushed.
