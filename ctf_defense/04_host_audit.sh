#!/usr/bin/env bash
# Fast audit, not a full Lynis/AIDE run — those take minutes you don't have
# right after takeover. First run establishes a SUID/SGID baseline; every
# run after that diffs against it, so new setuid binaries (a classic
# persistence/privesc trick) jump out immediately instead of scrolling past
# in a wall of "normal" system binaries.
set -u
cd "$(dirname "$0")" && source ./config.sh

SUID_BASELINE="$WORKDIR/suid_baseline.txt"
OUT="$WORKDIR/audit_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "=== $(date -u) ==="

    if command -v lynis >/dev/null; then
        echo -e "\n--- lynis quick audit ---"
        lynis audit system --quick --cronjob 2>/dev/null | grep -E '^\s*(Warning|Suggestion)' || echo "(no lynis warnings/suggestions, or lynis output format changed)"
    else
        echo -e "\n--- lynis not installed, skipping (install it pre-competition; can't rely on repo access mid-game) ---"
    fi

    echo -e "\n--- SUID/SGID binaries ---"
    find / -xdev -perm /6000 -type f 2>/dev/null | sort > "$WORKDIR/.suid_current.txt"
    if [ -f "$SUID_BASELINE" ]; then
        new=$(comm -13 "$SUID_BASELINE" "$WORKDIR/.suid_current.txt")
        if [ -n "$new" ]; then
            echo "NEW SUID/SGID BINARIES SINCE BASELINE:"
            echo "$new"
        else
            echo "no new SUID/SGID binaries since baseline"
        fi
    else
        cp "$WORKDIR/.suid_current.txt" "$SUID_BASELINE"
        echo "baseline created ($(wc -l < "$SUID_BASELINE") binaries) - re-run this script later to diff against it"
    fi

    echo -e "\n--- UID 0 accounts (should just be root) ---"
    awk -F: '$3 == 0 {print}' /etc/passwd

    echo -e "\n--- accounts with a valid shell (potential unauthorized logins) ---"
    grep -Ev '/(nologin|false)$' /etc/passwd

    echo -e "\n--- world-writable files outside /tmp (excluding common false positives) ---"
    find / -xdev -type f -perm -0002 2>/dev/null | grep -Ev '^/(tmp|proc|sys|dev)/' | head -100

} | tee "$OUT"

echo
echo "audit written to $OUT"
