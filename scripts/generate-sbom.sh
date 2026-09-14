#!/usr/bin/env bash
set -euo pipefail

# Generate a source SBOM for a staged OpenStream candidate.
#
# An SBOM says what a build was made from. It does not say the resulting
# package was signed, installed, or tested, and this command deliberately
# produces none of that evidence.
#
# Three dependency graphs go into a shipped OpenStream build and all three are
# covered here, because an SBOM that silently omits one is worse than no SBOM:
# a reader cannot tell the difference between "this component is absent" and
# "this generator never looked".
#
#   1. the engine Cargo workspace   (engine/lowlat)
#   2. the product shell Cargo crate (desktop/src-tauri) -- a separate
#      workspace with its own lockfile, so `cargo metadata` must be run
#      against it separately
#   3. the shell's npm graph        (desktop/package-lock.json)
#
# System components loaded at runtime rather than linked -- FFmpeg, PipeWire,
# libva, NVENC -- are named in THIRD_PARTY.md and are outside a source SBOM by
# construction. That boundary is recorded in the document rather than left
# implicit.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output="${1:-$repo_dir/dist/openstream-1.0.0/sbom/openstream-1.0.0.spdx.json}"
version="${OPENSTREAM_VERSION:-1.0.0}"

command -v cargo >/dev/null 2>&1 || {
    echo "cargo is required to generate the OpenStream SBOM" >&2
    exit 2
}
command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required to render the dependency graphs as SPDX JSON" >&2
    exit 2
}

engine_manifest="$repo_dir/engine/lowlat/Cargo.toml"
shell_manifest="$repo_dir/desktop/src-tauri/Cargo.toml"
npm_lock="$repo_dir/desktop/package-lock.json"

for required in "$engine_manifest" "$shell_manifest" "$npm_lock"; do
    [[ -f "$required" ]] || {
        echo "missing SBOM input: $required" >&2
        exit 2
    }
done

mkdir -p "$(dirname -- "$output")"
work="$(mktemp -d "${TMPDIR:-/tmp}/openstream-sbom.XXXXXX")"
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT

# `--locked` is part of the release contract. A resolver update must be a
# deliberate repository change, never an implicit side effect of packaging.
cargo metadata --manifest-path "$engine_manifest" \
    --locked --format-version 1 >"$work/engine.json"
cargo metadata --manifest-path "$shell_manifest" \
    --locked --format-version 1 >"$work/shell.json"

python3 - "$work" "$npm_lock" "$version" "$work/sbom.json" <<'PY'
import json
import hashlib
import os
import pathlib
import sys

work = pathlib.Path(sys.argv[1])
npm_lock_path = pathlib.Path(sys.argv[2])
version = sys.argv[3]
output_path = pathlib.Path(sys.argv[4])


def spdx_id(prefix: str, name: str, package_version: str, identity: str) -> str:
    def safe(value: str) -> str:
        return "".join(character if character.isalnum() else "-" for character in value)

    # Names and versions are not unique in a Cargo graph: the same crate can be
    # present from a registry and from git, or at several source ids. The
    # identity digest keeps every SPDX id distinct while staying deterministic.
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"SPDXRef-{prefix}-{safe(name)}-{safe(package_version)}-{digest}"


def cargo_packages(metadata_path: pathlib.Path, prefix: str, origin: str):
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    packages = []
    for package in sorted(
        metadata.get("packages", []),
        key=lambda item: (item["name"], item["version"], item["id"]),
    ):
        # `license` is the declared SPDX expression from the crate manifest.
        # Record it when it is there and say NOASSERTION when it is not,
        # rather than asserting a licence nobody declared.
        declared = package.get("license") or "NOASSERTION"
        packages.append(
            {
                "SPDXID": spdx_id(prefix, package["name"], package["version"], package["id"]),
                "name": package["name"],
                "versionInfo": package["version"],
                "downloadLocation": package.get("source") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": declared,
                "copyrightText": "NOASSERTION",
                "comment": f"{origin} dependency graph",
            }
        )
    return packages


def npm_packages(lock_path: pathlib.Path):
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    entries = lock.get("packages")
    if entries is None:
        raise SystemExit(
            "desktop/package-lock.json is not lockfileVersion 2 or 3; "
            "regenerate it before staging a release SBOM"
        )
    packages = []
    for path, entry in sorted(entries.items()):
        if not path:
            # The empty key is the workspace root itself, covered by the
            # document's own root package below.
            continue
        name = entry.get("name") or path.split("node_modules/")[-1]
        package_version = entry.get("version") or "NOASSERTION"
        packages.append(
            {
                "SPDXID": spdx_id("npm", name, package_version, path),
                "name": name,
                "versionInfo": package_version,
                "downloadLocation": entry.get("resolved") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": entry.get("license") or "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "comment": "desktop shell npm dependency graph",
            }
        )
    return packages


engine = cargo_packages(work / "engine.json", "cargo-engine", "engine workspace")
shell = cargo_packages(work / "shell.json", "cargo-shell", "desktop shell crate")
npm = npm_packages(npm_lock_path)

root_id = "SPDXRef-Package-openstream"
root = {
    "SPDXID": root_id,
    "name": "openstream",
    "versionInfo": version,
    "downloadLocation": "NOASSERTION",
    "filesAnalyzed": False,
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "MIT",
    "copyrightText": "NOASSERTION",
    "comment": (
        "Source SBOM covering the engine Cargo workspace, the desktop shell "
        "Cargo crate, and the desktop shell npm graph. Runtime-loaded system "
        "components (FFmpeg, PipeWire, libva, NVENC) are never linked into "
        "this build and are inventoried in THIRD_PARTY.md."
    ),
}

packages = [root, *engine, *shell, *npm]

# Relationships, so a consumer can tell the root from its dependencies rather
# than inferring it from ordering.
relationships = [
    {
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }
]
relationships.extend(
    {
        "spdxElementId": root_id,
        "relationshipType": "DEPENDS_ON",
        "relatedSpdxElement": package["SPDXID"],
    }
    for package in (*engine, *shell, *npm)
)

# A document namespace must be unique per document. Derive it from the content
# so the output stays byte-identical for identical inputs while still differing
# whenever the graph does.
identity = hashlib.sha256(
    json.dumps(packages, sort_keys=True).encode("utf-8")
).hexdigest()

document = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": f"openstream-{version}-source",
    "documentNamespace": f"https://openstream.invalid/spdx/openstream-{version}-{identity}",
    "creationInfo": {
        # Fixed, because a reproducible artifact must not differ run to run.
        "created": "1970-01-01T00:00:00Z",
        "creators": ["Tool: scripts/generate-sbom.sh"],
    },
    "documentDescribes": [root_id],
    "packages": packages,
    "relationships": relationships,
}
output_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if os.environ.get("OPENSTREAM_SBOM_QUIET") != "1":
    print(
        f"engine={len(engine)} shell={len(shell)} npm={len(npm)} total={len(packages)}",
        file=sys.stderr,
    )
PY

mv -f -- "$work/sbom.json" "$output"
chmod 644 "$output"
printf 'generated SPDX source SBOM: %s\n' "$output"
