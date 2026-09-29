#!/usr/bin/env bash
set -uo pipefail

# The documentation-only classifier, and the cases it must get right.
#
# CI skips the native build, sanitizer and target matrices when a pull request
# changes nothing but Markdown. That is a decision about whether code gets
# compiled and tested at all, so the rule is an allow-list -- a path is
# documentation only if it matches, and anything unrecognised takes the full
# run -- and it is tested here rather than only in the workflow, where a
# mistake would be found by something not being built.
#
# The expression below must stay identical to the one in .github/workflows/ci.yml.
#
# Run: scripts/check-ci-classifier.sh

classify() {
  if printf '%s\n' "$1" | grep -qvE '^(docs/.+\.md|[^/]+\.md)$'; then echo "full"; else echo "docs-only"; fi
}
fail=0
check() {
  got=$(classify "$1")
  if [ "$got" = "$2" ]; then printf '  ok   %-10s %s\n' "$2" "$(printf '%s' "$1" | tr '\n' ' ')"
  else printf '  BAD  got %-10s want %-10s %s\n' "$got" "$2" "$(printf '%s' "$1" | tr '\n' ' ')"; fail=1; fi
}
check "docs/STATUS.md" docs-only
check "README.md" docs-only
check "$(printf 'docs/STATUS.md\ndocs/FEATURE_MATRIX.md\nREADME.md')" docs-only
check "docs/acceptance/run.md" docs-only
check ".github/workflows/ci.yml" full
check "scripts/build-release-artifacts.sh" full
check "engine/lowlat/Cargo.lock" full
check "packaging/linux/build-deb.sh" full
check "packaging/linux/openstream-host-broker.service" full
check "release/openstream-1.0-gates.tsv" full
check "engine/lowlat/crates/net/README.md" full
check "$(printf 'docs/STATUS.md\nengine/lowlat/src/lib.rs')" full
check "$(printf 'README.md\n.github/workflows/ci.yml')" full
check "docs/notes.txt" full
check ".github/CONTRIBUTING.md" full
check "desktop/package.json" full
if [ "$fail" -ne 0 ]; then
  echo "the documentation-only classifier does not match its expected cases" >&2
  exit 1
fi
echo "classifier ok"
