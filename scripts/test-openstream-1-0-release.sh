#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
checker="$script_dir/check-openstream-1-0-release.sh"

if [[ ! -x "$checker" ]]; then
    echo "release gate checker is not executable: $checker" >&2
    exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_file() {
        sha256sum -- "$1" | awk '{print $1}'
    }
elif command -v shasum >/dev/null 2>&1; then
    hash_file() {
        shasum -a 256 -- "$1" | awk '{print $1}'
    }
else
    echo "the release gate self-test requires sha256sum or shasum" >&2
    exit 1
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/openstream-release-gates.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT

fixture_root="$test_root/fixture"
artifact_root="$fixture_root/artifacts"
manifest="$fixture_root/manifest.tsv"
report="$fixture_root/gate-report.tsv"

build_fixture() {
    rm -rf -- "$fixture_root"
    mkdir -p \
        "$artifact_root/linux-x86_64" \
        "$artifact_root/macos-aarch64" \
        "$artifact_root/checksums" \
        "$artifact_root/sbom" \
        "$artifact_root/signing"

    printf '%s\n' 'linux release payload' \
        >"$artifact_root/linux-x86_64/OpenStream-Linux-x86_64.tar.gz"
    printf '%s\n' 'macOS disk image payload' \
        >"$artifact_root/macos-aarch64/OpenStream-macOS-arm64.dmg"
    printf '%s\n' 'macOS application archive payload' \
        >"$artifact_root/macos-aarch64/OpenStream-macOS-arm64.zip"

    printf '%b\n' \
        'kind\tid\tvalue' \
        'meta\tmanifest_version\t1' \
        'meta\trelease_version\t1.0.0' \
        'meta\tartifact_root\tdist/openstream-1.0.0' \
        'artifact\tlinux-host-package\tlinux-x86_64/OpenStream-Linux-x86_64.tar.gz' \
        'artifact\tmacos-apple-silicon-package\tmacos-aarch64/OpenStream-macOS-arm64.dmg' \
        'artifact\tmacos-apple-silicon-app-archive\tmacos-aarch64/OpenStream-macOS-arm64.zip' \
        'evidence\tchecksums\tchecksums/SHA256SUMS' \
        'evidence\tsbom\tsbom/openstream-1.0.0.spdx.json' \
        'evidence\tsigning\tsigning/openstream-1.0.0-signing.tsv' \
        'gate\tphysical-linux-nvidia-to-apple-silicon\tLinux NVIDIA host to Apple Silicon client' \
        'gate\twan-turn\tWAN with external TURN relay' \
        'gate\tpackage-launch-upgrade\tPackage launch and upgrade' \
        >"$manifest"

    {
        printf '%b\n' 'gate_id\tresult\tobserved_at\tevidence'
        printf '%b\n' 'physical-linux-nvidia-to-apple-silicon\tPASS\t2026-09-12T00:00:00Z\trun=fixture-hardware'
        printf '%b\n' 'wan-turn\tPASS\t2026-09-12T00:00:00Z\trun=fixture-wan-turn'
        printf '%b\n' 'package-launch-upgrade\tPASS\t2026-09-12T00:00:00Z\trun=fixture-package'
    } >"$report"

    {
        printf '%b\n' 'artifact_id\tstatus\tsigner'
        printf '%b\n' 'linux-host-package\tVERIFIED\tfixture-linux-key'
        printf '%b\n' 'macos-apple-silicon-package\tVERIFIED\tfixture-macos-key'
        printf '%b\n' 'macos-apple-silicon-app-archive\tVERIFIED\tfixture-macos-key'
    } >"$artifact_root/signing/openstream-1.0.0-signing.tsv"

    printf '%b\n' \
        '{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"OpenStream 1.0"}' \
        >"$artifact_root/sbom/openstream-1.0.0.spdx.json"

    {
        for relative_path in \
            linux-x86_64/OpenStream-Linux-x86_64.tar.gz \
            macos-aarch64/OpenStream-macOS-arm64.dmg \
            macos-aarch64/OpenStream-macOS-arm64.zip; do
            printf '%s  %s\n' \
                "$(hash_file "$artifact_root/$relative_path")" \
                "$relative_path"
        done
    } >"$artifact_root/checksums/SHA256SUMS"
}

run_checker() {
    "$checker" \
        --manifest "$manifest" \
        --artifact-root "$artifact_root" \
        --report "$report"
}

assert_checker_fails() {
    local name=$1
    shift
    local output="$test_root/$name.log"
    if "$checker" \
        --manifest "$manifest" \
        --artifact-root "$artifact_root" \
        --report "$report" \
        >"$output" 2>&1; then
        echo "expected release gate failure: $name" >&2
        cat "$output" >&2
        exit 1
    fi
    printf 'ok   %s rejects an incomplete release\n' "$name"
}

build_fixture
printf '%s\n' 'test: complete evidence passes'
run_checker >/dev/null

printf '%s\n' 'test: missing artifact fails closed'
rm -- "$artifact_root/macos-aarch64/OpenStream-macOS-arm64.dmg"
assert_checker_fails missing-artifact

build_fixture
printf '%s\n' 'test: checksum tampering fails closed'
printf '%s\n' 'tampered payload' >"$artifact_root/linux-x86_64/OpenStream-Linux-x86_64.tar.gz"
assert_checker_fails checksum-tampering

build_fixture
printf '%s\n' 'test: missing SBOM fails closed'
rm -- "$artifact_root/sbom/openstream-1.0.0.spdx.json"
assert_checker_fails missing-sbom

build_fixture
printf '%s\n' 'test: unverified signing evidence fails closed'
    printf '%b\n' \
        'artifact_id\tstatus\tsigner' \
        'linux-host-package\tVERIFIED\tfixture-linux-key' \
        'macos-apple-silicon-package\tPENDING\tfixture-macos-key' \
        'macos-apple-silicon-app-archive\tVERIFIED\tfixture-macos-key' \
    >"$artifact_root/signing/openstream-1.0.0-signing.tsv"
assert_checker_fails unverified-signing

build_fixture
printf '%s\n' 'test: report without all named mandatory gates fails closed'
{
    printf '%b\n' 'gate_id\tresult\tobserved_at\tevidence'
    printf '%b\n' 'physical-linux-nvidia-to-apple-silicon\tPASS\t2026-09-12T00:00:00Z\trun=fixture-hardware'
    printf '%b\n' 'wan-turn\tPASS\t2026-09-12T00:00:00Z\trun=fixture-wan-turn'
} >"$report"
assert_checker_fails missing-named-gate

printf '%s\n' 'OpenStream 1.0 release gate self-tests passed'
