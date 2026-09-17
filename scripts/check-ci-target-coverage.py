#!/usr/bin/env python3
"""Assert the CI target matrices still cover every target they are meant to.

Consolidating a matrix by OS is a good trade -- it removes runner acquisitions
and cold dependency builds -- but it has one specific failure mode: a target
quietly stops being built, and nothing goes red, because the job that used to
build it no longer exists. Removing a job is invisible; removing a word from a
space-separated list is more invisible still.

So the expected coverage is written down here and checked on every pull request,
docs-only ones included. Adding or dropping a target is then a deliberate edit to
this file rather than something that can happen by accident.

Parsed with a small hand-rolled scanner rather than PyYAML, because CI should not
need a Python package installed to check its own configuration.
"""

from __future__ import annotations

import pathlib
import re
import sys

WORKFLOW = pathlib.Path(".github/workflows/ci.yml")

# What each matrix must build, and with which command. Keep in sync deliberately.
EXPECTED = {
    "openstream-target-matrix": {
        "targets": {
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-linux-android",
            "x86_64-linux-android",
        },
        # Targets that must get the desktop release build (host binaries).
        "host_targets": {
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        },
        # Targets that must get the mobile bridge build.
        "mobile_targets": {
            "aarch64-apple-ios",
            "aarch64-linux-android",
            "x86_64-linux-android",
        },
    },
    "openstream-desktop-target-matrix": {
        "targets": {
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
        },
    },
}


def matrix_entries(text: str, job_id: str) -> list[dict[str, str]]:
    """Every `include:` entry of one job's matrix, as flat key/value pairs.

    Only the fields this check reads are parsed: each is a plain scalar on its
    own line, so a full YAML implementation buys nothing here.
    """
    start = text.index(f"\n  {job_id}:\n")
    # The next job header at the same indent ends this one.
    following = re.search(r"\n  [a-z][a-z0-9-]*:\n", text[start + 1 :])
    block = text[start : start + 1 + following.start()] if following else text[start:]

    entries: list[dict[str, str]] = []
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("- os:"):
            entries.append({"os": stripped.split(":", 1)[1].strip()})
        elif entries and ":" in stripped and not stripped.startswith("#"):
            key, _, value = stripped.partition(":")
            key = key.strip()
            if key in {"label", "target", "targets", "host_targets", "mobile_targets"}:
                entries[-1][key] = value.strip().strip('"').strip("'")
    return entries


def collect(entries: list[dict[str, str]], field: str) -> set[str]:
    found: set[str] = set()
    for entry in entries:
        found.update(entry.get(field, "").split())
    return found


def main() -> int:
    if not WORKFLOW.is_file():
        print(f"{WORKFLOW} not found; run this from the repository root", file=sys.stderr)
        return 2
    text = WORKFLOW.read_text(encoding="utf-8")

    failures: list[str] = []
    for job_id, expected in EXPECTED.items():
        entries = matrix_entries(text, job_id)
        if not entries:
            failures.append(f"{job_id}: no matrix entries found")
            continue
        for field, want in expected.items():
            have = collect(entries, field)
            for missing in sorted(want - have):
                failures.append(f"{job_id}: {field} no longer covers {missing}")
            for extra in sorted(have - want):
                failures.append(
                    f"{job_id}: {field} covers {extra}, which this check does not "
                    f"expect -- add it here if that is deliberate"
                )
        print(f"{job_id}: {len(entries)} jobs covering {len(collect(entries, 'targets'))} targets")

    if failures:
        print(file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nCI target coverage changed. If that is intended, update "
            f"{pathlib.Path(__file__).name} in the same commit.",
            file=sys.stderr,
        )
        return 1
    print("CI target coverage is unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
