#!/usr/bin/env bash
set -euo pipefail

# Check the evidence document for the mandatory OpenStream 1.0 network cases.
# This script never runs a network test by itself and never prints credentials.
# Operators record observed results in the report, then invoke this checker.

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
report="${OPENSTREAM_WAN_REPORT:-$repo_dir/docs/acceptance/OPENSTREAM_1_0_HARDWARE_WAN_MATRIX.md}"

usage() {
    printf '%s\n' \
        "usage: $0 --check [report]" \
        "       $0 --template"
}

required_cases=(
    "direct-udp"
    "turn-relay"
    "application-relay"
    "ipv4-double-nat"
    "ipv6"
    "symmetric-nat"
    "loss-jitter"
    "bandwidth-limit"
    "wifi-ethernet-roam"
    "router-restart"
)

case "${1:---check}" in
    --template)
        cat <<'EOF'
case,status,evidence
direct-udp,UNVERIFIED,
turn-relay,UNVERIFIED,
application-relay,UNVERIFIED,
ipv4-double-nat,UNVERIFIED,
ipv6,UNVERIFIED,
symmetric-nat,UNVERIFIED,
loss-jitter,UNVERIFIED,
bandwidth-limit,UNVERIFIED,
wifi-ethernet-roam,UNVERIFIED,
router-restart,UNVERIFIED,
EOF
        exit 0
        ;;
    --check)
        if [[ $# -ge 2 ]]; then
            report="$2"
        fi
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if [[ ! -f "$report" ]]; then
    printf 'WAN acceptance report is missing: %s\n' "$report" >&2
    exit 1
fi

failed=0
for case_name in "${required_cases[@]}"; do
    if ! grep -Eiq "\\|[[:space:]]*${case_name}[[:space:]]*\\|[[:space:]]*PASS[[:space:]]*\\|" "$report"; then
        printf 'unverified WAN case: %s\n' "$case_name" >&2
        failed=1
    fi
done

if (( failed != 0 )); then
    printf 'WAN acceptance gate failed; all required cases need observed PASS evidence\n' >&2
    exit 1
fi

printf 'WAN acceptance gate passed: %d cases have PASS evidence\n' "${#required_cases[@]}"
