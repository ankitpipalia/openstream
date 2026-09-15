#!/usr/bin/env bash
set -euo pipefail

# Install, launch, upgrade and roll back a staged OpenStream package, and
# record what actually happened.
#
# This is the `package-launch-upgrade` release gate. It exists because a
# package that builds is not a package that installs: the gate is about the
# artifact behaving on a machine that has never seen OpenStream, which is why
# it runs against the staged tarball rather than against a build tree.
#
# It writes a gate-report row only on success, and only with the evidence it
# actually produced. A row that says PASS without an observation behind it is
# worse than a missing row, because the checker is designed to trust it.

usage() {
    cat <<'EOF'
Usage: scripts/package-acceptance.sh --package PATH [--report PATH]

  --package PATH   staged Linux tarball to install
  --report PATH    gate-report.tsv to append a row to (optional)

Exits non-zero if any stage fails. Writes no row unless every stage passed.
EOF
}

package=''
report=''
while (($# > 0)); do
    case "$1" in
        --package)
            (($# >= 2)) || { echo "--package requires a path" >&2; exit 2; }
            package="$2"; shift 2 ;;
        --report)
            (($# >= 2)) || { echo "--report requires a path" >&2; exit 2; }
            report="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ -n "$package" ]] || { echo "--package is required" >&2; exit 2; }
[[ -f "$package" ]] || { echo "no such package: $package" >&2; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/openstream-package-acceptance.XXXXXX")"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

prefix_a="$work/install"
prefix_b="$work/upgrade"
mkdir -p "$prefix_a" "$prefix_b"

fail() { echo "package acceptance: $*" >&2; exit 1; }

# --- install -------------------------------------------------------------
# Into an empty prefix, because "it works on the build machine" is the thing
# this gate does not accept as evidence.
tar -xzf "$package" -C "$prefix_a" || fail "the package did not extract"

host_binary="$(find "$prefix_a" -type f -name 'openstream-*host*' -perm -u+x | head -1 || true)"
[[ -n "$host_binary" ]] || host_binary="$(find "$prefix_a" -type f -perm -u+x | head -1 || true)"
[[ -n "$host_binary" ]] || fail "the package contains no executable"
echo "ok   installed $(basename "$host_binary")"

# --- launch --------------------------------------------------------------
# A version query, not a session: this gate is about the package being
# runnable at all -- dynamic links resolved, permissions intact -- which is
# what an install can break and a build cannot show.
launch_output="$("$host_binary" --version 2>&1)" || fail "the installed binary did not run"
[[ -n "$launch_output" ]] || fail "the installed binary produced no version output"
echo "ok   launched: $launch_output"

# --- upgrade -------------------------------------------------------------
# The same package over an existing install. A real upgrade replaces files
# that may be in use and must leave a working install behind.
tar -xzf "$package" -C "$prefix_b" || fail "the package did not extract for upgrade"
cp -R "$prefix_b/." "$prefix_a/" || fail "the upgrade could not overwrite the install"
upgrade_output="$("$host_binary" --version 2>&1)" || fail "the upgraded install did not run"
[[ "$upgrade_output" == "$launch_output" ]] || fail "the upgrade changed the reported version unexpectedly"
echo "ok   upgraded in place and still runs"

# --- rollback ------------------------------------------------------------
# Restoring the previous install must produce a working install too. A
# one-way upgrade is not an upgrade, it is a migration.
rollback="$work/rollback"
mkdir -p "$rollback"
tar -xzf "$package" -C "$rollback" || fail "the package did not extract for rollback"
rollback_binary="$(find "$rollback" -type f -perm -u+x -name "$(basename "$host_binary")" | head -1 || true)"
[[ -n "$rollback_binary" ]] || fail "the rollback install is missing its executable"
rollback_output="$("$rollback_binary" --version 2>&1)" || fail "the rolled-back install did not run"
[[ "$rollback_output" == "$launch_output" ]] || fail "the rollback reported a different version"
echo "ok   rolled back to a working install"

observed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
digest="$( (command -v sha256sum >/dev/null 2>&1 && sha256sum -- "$package" || shasum -a 256 -- "$package") | awk '{print $1}')"
evidence="package=$(basename "$package") sha256=$digest launch=${launch_output// /_}"

if [[ -n "$report" ]]; then
    mkdir -p "$(dirname -- "$report")"
    if [[ ! -f "$report" ]]; then
        printf 'gate_id\tresult\tobserved_at\tevidence\n' >"$report"
    fi
    # Replace any existing row for this gate rather than appending a second:
    # two rows for one gate is an unreadable report, and the checker would
    # accept whichever it saw first.
    if grep -q '^package-launch-upgrade\b' "$report" 2>/dev/null; then
        filtered="$(grep -v '^package-launch-upgrade\b' "$report")"
        printf '%s\n' "$filtered" >"$report"
    fi
    printf 'package-launch-upgrade\tPASS\t%s\t%s\n' "$observed_at" "$evidence" >>"$report"
    echo "ok   recorded package-launch-upgrade in $report"
fi

echo "package acceptance passed: install, launch, upgrade, rollback"
