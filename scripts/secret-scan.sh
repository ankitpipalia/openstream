#!/usr/bin/env bash
set -euo pipefail

# Scan the committed source tree, rather than the entire Git history or build
# output. Historical protocol documentation contains intentionally
# secret-shaped labels, while this gate is about files that can ship.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if ! command -v gitleaks >/dev/null 2>&1; then
    echo "gitleaks is required for the production secret scan" >&2
    exit 2
fi

if [[ -n "$(git -C "$repo_dir" status --porcelain --untracked-files=all)" ]]; then
    echo "production secret scan requires a clean worktree" >&2
    exit 2
fi

scan_dir="$(mktemp -d "${TMPDIR:-/tmp}/openstream-secret-scan.XXXXXX")"
cleanup() {
    rm -rf "$scan_dir"
}
trap cleanup EXIT
git -C "$repo_dir" archive --format=tar HEAD | tar -xf - -C "$scan_dir"
gitleaks dir "$scan_dir" --redact --no-banner --exit-code 1
printf '%s\n' 'production secret scan passed'
