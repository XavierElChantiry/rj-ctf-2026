#!/usr/bin/env bash
# Rapid situational-awareness dump: run this FIRST, before touching anything
# else, the moment you get access to a box. Don't run package updates before
# this — an update can silently change/break a service the scoring engine
# checks, and you won't know what "normal" looked like beforehand.
set -u
cd "$(dirname "$0")" && source ./config.sh

OUT="$WORKDIR/baseline_$(date +%Y%m%d_%H%M%S).txt"

{
    echo "=== $(date -u) ==="

    echo -e "\n--- listening sockets ---"
    if command -v ss >/dev/null; then
        ss -tulpn 2>/dev/null
    else
        netstat -tulpn 2>/dev/null
    fi

    echo -e "\n--- listening port -> process detail ---"
    # `ss`/`netstat` already show PIDs when run as root; this cross-checks
    # against /proc so you have the real binary path even if the process
    # later renames its argv0 to hide itself.
    (ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null) | grep -oP '(?<=pid=)\d+' | sort -u | while read -r pid; do
        [ -d "/proc/$pid" ] || continue
        exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "?")
        echo "pid=$pid exe=$exe"
        ps -p "$pid" -o pid,ppid,user,cmd --no-headers 2>/dev/null
    done

    echo -e "\n--- logged in users ---"
    who
    w

    echo -e "\n--- active ssh sessions ---"
    ss -tnp 2>/dev/null | grep ':22 ' || true

    echo -e "\n--- cron jobs ---"
    for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [ -f "$f" ] && { echo "-- $f --"; cat "$f"; }
    done 2>/dev/null

    echo -e "\n--- systemd timers (another persistence spot) ---"
    command -v systemctl >/dev/null && systemctl list-timers --all 2>/dev/null

} | tee "$OUT"

echo
echo "baseline written to $OUT"
