#!/usr/bin/env bash
set -euo pipefail

# Authoritative, fail-closed evidence check for an OpenStream 1.0 release.
# Hardware and WAN tests are supplied as explicit report evidence; this script
# verifies that the required artifacts and evidence are present and coherent.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
manifest_path="$repo_dir/release/openstream-1.0-gates.tsv"
artifact_root_override=''
report_path=''

usage() {
    cat <<'EOF'
Usage: scripts/check-openstream-1-0-release.sh [options]

Options:
  --manifest PATH       release gate manifest (default: release/openstream-1.0-gates.tsv)
  --artifact-root PATH  staged release root (default: manifest artifact_root)
  --report PATH         physical/package evidence report (default: <artifact-root>/evidence/gate-report.tsv)
  -h, --help            show this help

Manifest paths are relative to the artifact root. Explicit command-line paths
are resolved relative to the current directory unless absolute.
EOF
}

resolve_cli_path() {
    case "$1" in
        /*) printf '%s\n' "$1" ;;
        *) printf '%s/%s\n' "$PWD" "$1" ;;
    esac
}

while (($# > 0)); do
    case "$1" in
        --manifest)
            (($# >= 2)) || { echo "--manifest requires a path" >&2; exit 2; }
            manifest_path="$(resolve_cli_path "$2")"
            shift 2
            ;;
        --artifact-root)
            (($# >= 2)) || { echo "--artifact-root requires a path" >&2; exit 2; }
            artifact_root_override="$(resolve_cli_path "$2")"
            shift 2
            ;;
        --report)
            (($# >= 2)) || { echo "--report requires a path" >&2; exit 2; }
            report_path="$(resolve_cli_path "$2")"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "$manifest_path" ]]; then
    echo "missing release gate manifest: $manifest_path" >&2
    exit 1
fi

errors=0
fail() {
    printf 'FAIL %s\n' "$*" >&2
    errors=$((errors + 1))
}

is_safe_relative_path() {
    local value=$1
    [[ -n "$value" && "$value" != /* ]] || return 1
    case "/$value/" in
        */../*|*/./*|*//*) return 1 ;;
    esac
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *$'\t'* ]]
}

is_placeholder() {
    case "$1" in
        ''|TBD|UNKNOWN|unknown|REPLACE_ME|REPLACE-WITH-EVIDENCE|not-run|NOT_RUN)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

manifest_header='kind'
manifest_header+=$'\t'
manifest_header+='id'
manifest_header+=$'\t'
manifest_header+='value'
manifest_header_seen=0
manifest_line=0
meta_ids=()
meta_values=()
artifact_ids=()
artifact_paths=()
evidence_ids=()
evidence_paths=()
gate_ids=()
gate_titles=()

append_unique() {
    local needle=$1
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 1
    done
    return 0
}

while IFS= read -r line || [[ -n "$line" ]]; do
    manifest_line=$((manifest_line + 1))
    case "$line" in
        ''|'#'*)
            continue
            ;;
    esac

    if ((manifest_header_seen == 0)); then
        if [[ "$line" != "$manifest_header" ]]; then
            fail "manifest line $manifest_line must start with $manifest_header"
        else
            manifest_header_seen=1
        fi
        continue
    fi

    kind=''
    id=''
    value=''
    extra=''
    IFS=$'\t' read -r kind id value extra <<<"$line"
    if [[ -n "$extra" ]]; then
        fail "manifest line $manifest_line has more than three tab-separated fields"
        continue
    fi
    if [[ -z "$kind" || -z "$id" || -z "$value" ]]; then
        fail "manifest line $manifest_line has an empty field"
        continue
    fi

    case "$kind" in
        meta)
            case "$id" in
                manifest_version|release_version|artifact_root) ;;
                *)
                    fail "manifest line $manifest_line has unknown meta id: $id"
                    continue
                    ;;
            esac
            if ! append_unique "$id" "${meta_ids[@]}"; then
                fail "manifest contains duplicate meta id: $id"
                continue
            fi
            meta_ids+=("$id")
            meta_values+=("$value")
            ;;
        artifact)
            if ! is_safe_relative_path "$value"; then
                fail "artifact $id has an unsafe relative path: $value"
                continue
            fi
            if ! append_unique "$id" "${artifact_ids[@]}"; then
                fail "manifest contains duplicate artifact id: $id"
                continue
            fi
            artifact_ids+=("$id")
            artifact_paths+=("$value")
            ;;
        evidence)
            case "$id" in
                checksums|sbom|signing) ;;
                *)
                    fail "manifest line $manifest_line has unknown evidence id: $id"
                    continue
                    ;;
            esac
            if ! is_safe_relative_path "$value"; then
                fail "evidence $id has an unsafe relative path: $value"
                continue
            fi
            if ! append_unique "$id" "${evidence_ids[@]}"; then
                fail "manifest contains duplicate evidence id: $id"
                continue
            fi
            evidence_ids+=("$id")
            evidence_paths+=("$value")
            ;;
        gate)
            if ! append_unique "$id" "${gate_ids[@]}"; then
                fail "manifest contains duplicate gate id: $id"
                continue
            fi
            gate_ids+=("$id")
            gate_titles+=("$value")
            ;;
        *)
            fail "manifest line $manifest_line has unknown kind: $kind"
            ;;
    esac
done <"$manifest_path"

if ((manifest_header_seen == 0)); then
    fail "manifest is missing the kind/id/value header"
fi

meta_value() {
    local wanted=$1
    local i
    for ((i = 0; i < ${#meta_ids[@]}; i++)); do
        if [[ "${meta_ids[$i]}" == "$wanted" ]]; then
            printf '%s\n' "${meta_values[$i]}"
            return 0
        fi
    done
    return 1
}

artifact_path_for() {
    local wanted=$1
    local i
    for ((i = 0; i < ${#artifact_ids[@]}; i++)); do
        if [[ "${artifact_ids[$i]}" == "$wanted" ]]; then
            printf '%s\n' "${artifact_paths[$i]}"
            return 0
        fi
    done
    return 1
}

evidence_path_for() {
    local wanted=$1
    local i
    for ((i = 0; i < ${#evidence_ids[@]}; i++)); do
        if [[ "${evidence_ids[$i]}" == "$wanted" ]]; then
            printf '%s\n' "${evidence_paths[$i]}"
            return 0
        fi
    done
    return 1
}

gate_present() {
    local wanted=$1
    local item
    for item in "${gate_ids[@]}"; do
        [[ "$item" == "$wanted" ]] && return 0
    done
    return 1
}

required_artifact_ids=(
    linux-host-package
    macos-apple-silicon-package
    macos-apple-silicon-app-archive
)
required_evidence_ids=(checksums sbom signing)
required_gate_ids=(
    physical-linux-nvidia-to-apple-silicon
    wan-turn
    package-launch-upgrade
)

manifest_version="$(meta_value manifest_version 2>/dev/null || true)"
release_version="$(meta_value release_version 2>/dev/null || true)"
manifest_artifact_root="$(meta_value artifact_root 2>/dev/null || true)"
if [[ "$manifest_version" != 1 ]]; then
    fail "manifest_version must be 1"
fi
if [[ "$release_version" != 1.0.0 ]]; then
    fail "release_version must be 1.0.0"
fi
if [[ -z "$artifact_root_override" ]]; then
    if ! is_safe_relative_path "$manifest_artifact_root"; then
        fail "manifest artifact_root must be a safe relative path"
        artifact_root="$repo_dir/dist/openstream-1.0.0"
    else
        artifact_root="$repo_dir/$manifest_artifact_root"
    fi
else
    artifact_root="$artifact_root_override"
fi

if [[ ! -d "$artifact_root" ]]; then
    fail "missing artifact root: $artifact_root"
fi

for required_id in "${required_artifact_ids[@]}"; do
    if ! artifact_path_for "$required_id" >/dev/null 2>&1; then
        fail "manifest is missing required artifact id: $required_id"
    fi
done
if ((${#artifact_ids[@]} == 0)); then
    fail "manifest declares no artifacts"
fi

for required_id in "${required_evidence_ids[@]}"; do
    if ! evidence_path_for "$required_id" >/dev/null 2>&1; then
        fail "manifest is missing required evidence id: $required_id"
    fi
done
for required_id in "${required_gate_ids[@]}"; do
    if ! gate_present "$required_id"; then
        fail "manifest is missing required gate id: $required_id"
    fi
done

if [[ -z "$report_path" ]]; then
    report_path="$artifact_root/evidence/gate-report.tsv"
fi

for evidence_id in "${required_evidence_ids[@]}"; do
    evidence_relative=''
    evidence_relative="$(evidence_path_for "$evidence_id" 2>/dev/null || true)"
    if [[ -z "$evidence_relative" ]]; then
        continue
    fi
    evidence_file="$artifact_root/$evidence_relative"
    if [[ ! -s "$evidence_file" ]]; then
        fail "missing or empty $evidence_id evidence: $evidence_file"
    fi
done

checksum_file=''
checksum_relative="$(evidence_path_for checksums 2>/dev/null || true)"
if [[ -n "$checksum_relative" && -s "$artifact_root/$checksum_relative" ]]; then
    checksum_file="$artifact_root/$checksum_relative"
fi

hash_tool=''
if command -v sha256sum >/dev/null 2>&1; then
    hash_tool=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    hash_tool=shasum
else
    fail "no SHA-256 verifier available (need sha256sum or shasum)"
fi

sha256_for() {
    if [[ "$hash_tool" == sha256sum ]]; then
        sha256sum -- "$1" | awk 'NR == 1 { print tolower($1); exit }'
    else
        shasum -a 256 "$1" | awk 'NR == 1 { print tolower($1); exit }'
    fi
}

checksum_for() {
    local wanted=$1
    local file=$2
    awk -v wanted="$wanted" '
        /^[[:space:]]*#/ || NF < 2 { next }
        {
            path = $2
            sub(/^\*/, "", path)
            sub(/^\.\//, "", path)
            if (path == wanted) {
                count++
                digest = tolower($1)
            }
        }
        END {
            if (count != 1) {
                exit 1
            }
            print digest
        }
    ' "$file"
}

if [[ -n "$checksum_file" && -n "$hash_tool" ]]; then
    for ((i = 0; i < ${#artifact_ids[@]}; i++)); do
        artifact_id="${artifact_ids[$i]}"
        artifact_relative="${artifact_paths[$i]}"
        artifact_file="$artifact_root/$artifact_relative"
        if [[ ! -f "$artifact_file" ]]; then
            fail "missing release artifact $artifact_id: $artifact_file"
            continue
        fi
        expected_digest="$(checksum_for "$artifact_relative" "$checksum_file" 2>/dev/null || true)"
        if [[ ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
            fail "checksums evidence has no unique SHA-256 entry for $artifact_relative"
            continue
        fi
        actual_digest="$(sha256_for "$artifact_file")"
        if [[ "$actual_digest" != "$expected_digest" ]]; then
            fail "checksum mismatch for $artifact_relative"
        fi
    done
else
    for artifact_relative in "${artifact_paths[@]}"; do
        if [[ ! -f "$artifact_root/$artifact_relative" ]]; then
            fail "missing release artifact: $artifact_root/$artifact_relative"
        fi
    done
fi

sbom_file=''
sbom_relative="$(evidence_path_for sbom 2>/dev/null || true)"
if [[ -n "$sbom_relative" && -s "$artifact_root/$sbom_relative" ]]; then
    sbom_file="$artifact_root/$sbom_relative"
fi
if [[ -n "$sbom_file" ]] && ! grep -Eq '"(spdxVersion|bomFormat)"[[:space:]]*:' "$sbom_file"; then
    fail "SBOM evidence is not recognizable as SPDX or CycloneDX JSON: $sbom_file"
fi

signing_file=''
signing_relative="$(evidence_path_for signing 2>/dev/null || true)"
if [[ -n "$signing_relative" && -s "$artifact_root/$signing_relative" ]]; then
    signing_file="$artifact_root/$signing_relative"
fi
signing_header='artifact_id'
signing_header+=$'\t'
signing_header+='status'
signing_header+=$'\t'
signing_header+='signer'
signing_header_seen=0
signing_ids=()
signing_statuses=()
signing_signers=()
if [[ -n "$signing_file" ]]; then
    signing_line=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        signing_line=$((signing_line + 1))
        case "$line" in
            ''|'#'*) continue ;;
        esac
        if ((signing_header_seen == 0)); then
            if [[ "$line" != "$signing_header" ]]; then
                fail "signing evidence line $signing_line must start with artifact_id/status/signer"
            else
                signing_header_seen=1
            fi
            continue
        fi
        signing_id=''
        signing_status=''
        signing_signer=''
        signing_extra=''
        IFS=$'\t' read -r signing_id signing_status signing_signer signing_extra <<<"$line"
        if [[ -n "$signing_extra" || -z "$signing_id" || -z "$signing_status" || -z "$signing_signer" ]]; then
            fail "signing evidence line $signing_line is malformed"
            continue
        fi
        if ! append_unique "$signing_id" "${signing_ids[@]}"; then
            fail "signing evidence contains duplicate artifact id: $signing_id"
            continue
        fi
        signing_ids+=("$signing_id")
        signing_statuses+=("$signing_status")
        signing_signers+=("$signing_signer")
    done <"$signing_file"
    if ((signing_header_seen == 0)); then
        fail "signing evidence is missing its artifact_id/status/signer header"
    fi
fi

signing_status_for() {
    local wanted=$1
    local i
    for ((i = 0; i < ${#signing_ids[@]}; i++)); do
        if [[ "${signing_ids[$i]}" == "$wanted" ]]; then
            printf '%s\t%s\n' "${signing_statuses[$i]}" "${signing_signers[$i]}"
            return 0
        fi
    done
    return 1
}

if [[ -n "$signing_file" ]]; then
    for artifact_id in "${artifact_ids[@]}"; do
        signing_record="$(signing_status_for "$artifact_id" 2>/dev/null || true)"
        signing_status="${signing_record%%$'\t'*}"
        signing_signer="${signing_record#*$'\t'}"
        signer_placeholder=0
        if is_placeholder "$signing_signer"; then
            signer_placeholder=1
        fi
        if [[ -z "$signing_record" || "$signing_status" != VERIFIED || -z "$signing_signer" ]] || ((signer_placeholder != 0)); then
            fail "signing evidence is not VERIFIED for artifact: $artifact_id"
        fi
    done
fi

report_header='gate_id'
report_header+=$'\t'
report_header+='result'
report_header+=$'\t'
report_header+='observed_at'
report_header+=$'\t'
report_header+='evidence'
report_header_seen=0
report_ids=()
report_results=()
if [[ ! -s "$report_path" ]]; then
    fail "missing or empty physical/package gate report: $report_path"
else
    report_line=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        report_line=$((report_line + 1))
        case "$line" in
            ''|'#'*) continue ;;
        esac
        if ((report_header_seen == 0)); then
            if [[ "$line" != "$report_header" ]]; then
                fail "gate report line $report_line must start with gate_id/result/observed_at/evidence"
            else
                report_header_seen=1
            fi
            continue
        fi
        report_id=''
        report_result=''
        observed_at=''
        report_evidence=''
        report_extra=''
        IFS=$'\t' read -r report_id report_result observed_at report_evidence report_extra <<<"$line"
        if [[ -n "$report_extra" || -z "$report_id" || -z "$report_result" || -z "$observed_at" || -z "$report_evidence" ]]; then
            fail "gate report line $report_line is malformed"
            continue
        fi
        if ! gate_present "$report_id"; then
            fail "gate report names an id not declared in the manifest: $report_id"
            continue
        fi
        if ! append_unique "$report_id" "${report_ids[@]}"; then
            fail "gate report contains duplicate gate id: $report_id"
            continue
        fi
        if [[ "$report_result" != PASS ]]; then
            fail "gate report result is not PASS for $report_id: $report_result"
        fi
        observed_placeholder=0
        evidence_placeholder=0
        if is_placeholder "$observed_at"; then
            observed_placeholder=1
        fi
        if is_placeholder "$report_evidence"; then
            evidence_placeholder=1
        fi
        if ((observed_placeholder != 0 || evidence_placeholder != 0)); then
            fail "gate report has placeholder evidence for $report_id"
        fi
        report_ids+=("$report_id")
        report_results+=("$report_result")
    done <"$report_path"
    if ((report_header_seen == 0)); then
        fail "gate report is missing its gate_id/result/observed_at/evidence header"
    fi
fi

for required_id in "${required_gate_ids[@]}"; do
    found=0
    for report_id in "${report_ids[@]}"; do
        if [[ "$report_id" == "$required_id" ]]; then
            found=1
            break
        fi
    done
    if ((found == 0)); then
        fail "gate report is missing required named result: $required_id"
    fi
done

if ((errors != 0)); then
    printf 'OpenStream 1.0 release gates: NOT READY (%d failure(s))\n' "$errors" >&2
    exit 1
fi

printf 'OpenStream 1.0 release gates: READY\n'
printf 'verified %d artifact(s), checksums, SBOM, signing evidence, and %d named acceptance gate(s)\n' \
    "${#artifact_ids[@]}" "${#required_gate_ids[@]}"
