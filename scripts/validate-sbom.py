#!/usr/bin/env python3
"""Validate that a release SBOM actually inventories what the release ships.

The point of this check is coverage, and coverage cannot be asserted by the
document about itself. A comment saying "engine workspace dependency graph"
is prose; an SBOM can carry that string and list none of it. So the expected
set of components is derived from the lockfiles the build is pinned to, and
the SBOM has to contain them.

Usage:
    validate-sbom.py --sbom PATH
                     --cargo-lock PATH [--cargo-lock PATH ...]
                     --npm-lock PATH

Exit code is 1 with a reason on stderr if the document is malformed or does
not cover every pinned dependency.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# Some entries in a lockfile are the workspace's own crates, which a source
# SBOM may legitimately name differently or fold into its root package. The
# check is about third-party supply chain, so allow a small shortfall only for
# path/workspace members, and require every registry-sourced dependency.
_CARGO_PACKAGE_BLOCK = re.compile(r"\[\[package\]\](.*?)(?=\n\[\[|\Z)", re.DOTALL)
_CARGO_FIELD = re.compile(r'^\s*(name|version|source)\s*=\s*"([^"]*)"\s*$', re.MULTILINE)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def cargo_dependencies(path: pathlib.Path) -> set[tuple[str, str]]:
    """(name, version) for every registry-sourced crate in a Cargo lockfile.

    Parsed with `tomllib` where available and with a narrow regex otherwise,
    so this runs on a minimal packaging host without extra packages.
    """
    text = path.read_text(encoding="utf-8")
    packages: list[dict[str, str]] = []
    try:
        import tomllib

        packages = tomllib.loads(text).get("package", [])
    except ImportError:
        for block in _CARGO_PACKAGE_BLOCK.findall(text):
            packages.append(dict(_CARGO_FIELD.findall(block)))

    return {
        (package["name"], package["version"])
        for package in packages
        # A crate with no `source` is a workspace member built from this tree,
        # not a fetched dependency.
        if package.get("source") and package.get("name") and package.get("version")
    }


def npm_dependencies(path: pathlib.Path) -> set[tuple[str, str]]:
    """(name, version) for every resolved package in an npm lockfile."""
    lock = json.loads(path.read_text(encoding="utf-8"))
    entries = lock.get("packages")
    if entries is None:
        fail(f"{path} is not lockfileVersion 2 or 3; regenerate it before staging a release")

    resolved: set[tuple[str, str]] = set()
    for key, entry in entries.items():
        if not key:
            # The workspace root itself.
            continue
        name = entry.get("name") or key.split("node_modules/")[-1]
        version = entry.get("version")
        if name and version:
            resolved.add((name, version))
    return resolved


def sbom_components(document: dict) -> set[tuple[str, str]]:
    spdx = document.get("spdxVersion")
    cyclonedx = document.get("bomFormat")

    if cyclonedx:
        components = document.get("components")
        if not isinstance(components, list) or not components:
            fail("CycloneDX SBOM lists no components")
        return {
            (component.get("name"), component.get("version"))
            for component in components
            if component.get("name") and component.get("version")
        }

    if not spdx:
        fail("SBOM declares neither spdxVersion nor bomFormat")

    packages = document.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("SPDX SBOM lists no packages")

    identifiers = [package.get("SPDXID") for package in packages]
    if any(identifier is None for identifier in identifiers):
        fail("SPDX SBOM has a package without an SPDXID")
    if len(set(identifiers)) != len(identifiers):
        fail("SPDX SBOM reuses an SPDXID")

    describes = document.get("documentDescribes") or []
    if not describes:
        fail("SPDX SBOM describes no root package")
    if any(root not in identifiers for root in describes):
        fail("SPDX SBOM describes a package it does not contain")

    if not document.get("documentNamespace"):
        fail("SPDX SBOM has no documentNamespace")

    relationships = document.get("relationships")
    if not isinstance(relationships, list) or not relationships:
        fail("SPDX SBOM records no relationships")
    for relationship in relationships:
        for end in ("spdxElementId", "relatedSpdxElement"):
            element = relationship.get(end)
            if element != "SPDXRef-DOCUMENT" and element not in identifiers:
                fail(f"SPDX relationship names unknown element {element}")

    return {
        (package.get("name"), package.get("versionInfo"))
        for package in packages
        if package.get("name") and package.get("versionInfo")
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", required=True, type=pathlib.Path)
    parser.add_argument("--cargo-lock", action="append", default=[], type=pathlib.Path)
    parser.add_argument("--npm-lock", action="append", default=[], type=pathlib.Path)
    arguments = parser.parse_args()

    try:
        document = json.loads(arguments.sbom.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        fail(f"SBOM is not readable JSON: {error}")
    if not isinstance(document, dict):
        fail("SBOM root is not a JSON object")

    present = sbom_components(document)

    expected: set[tuple[str, str]] = set()
    for lock in arguments.cargo_lock:
        if not lock.is_file():
            fail(f"missing Cargo lockfile for SBOM coverage: {lock}")
        expected |= cargo_dependencies(lock)
    for lock in arguments.npm_lock:
        if not lock.is_file():
            fail(f"missing npm lockfile for SBOM coverage: {lock}")
        expected |= npm_dependencies(lock)

    if not expected:
        fail("no lockfile dependencies were supplied; SBOM coverage cannot be proven")

    missing = sorted(expected - present)
    if missing:
        shown = ", ".join(f"{name} {version}" for name, version in missing[:8])
        more = "" if len(missing) <= 8 else f" (and {len(missing) - 8} more)"
        fail(
            f"SBOM omits {len(missing)} pinned dependenc"
            f"{'y' if len(missing) == 1 else 'ies'}: {shown}{more}"
        )


if __name__ == "__main__":
    main()
