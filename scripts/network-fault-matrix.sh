#!/usr/bin/env bash
set -euo pipefail

# Deterministic matrix helper. It prints the cases an operator must execute;
# it does not require root, change host networking, or capture secret material.

cases=(
    "loss-jitter|5% loss, 30 ms jitter|direct and relay remain authenticated"
    "bandwidth-limit|20 Mbps egress|video remains bounded without queue growth"
    "wifi-ethernet-roam|change active interface|session generation migrates"
    "router-restart|restart the edge router|reconnect is explicit and input releases"
    "symmetric-nat|symmetric NAT on both peers|TURN or application relay selected"
)

case "${1:---list}" in
    --list)
        printf '%-22s | %-28s | %s\n' "case" "fault" "expected evidence"
        for row in "${cases[@]}"; do
            IFS='|' read -r name fault expected <<<"$row"
            printf '%-22s | %-28s | %s\n' "$name" "$fault" "$expected"
        done
        ;;
    --check-report)
        report="${2:-}"
        if [[ -z "$report" || ! -f "$report" ]]; then
            printf 'usage: %s --check-report REPORT\n' "$0" >&2
            exit 2
        fi
        failed=0
        for row in "${cases[@]}"; do
            IFS='|' read -r name _ _ <<<"$row"
            if ! grep -Eiq "\\|[[:space:]]*${name}[[:space:]]*\\|[[:space:]]*PASS[[:space:]]*\\|" "$report"; then
                printf 'unverified fault case: %s\n' "$name" >&2
                failed=1
            fi
        done
        (( failed == 0 )) || exit 1
        printf 'network fault matrix passed\n'
        ;;
    -h|--help)
        printf '%s\n' "usage: $0 --list" "       $0 --check-report REPORT"
        ;;
    *)
        printf '%s\n' "unknown option: $1" >&2
        exit 2
        ;;
esac
