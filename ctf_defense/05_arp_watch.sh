#!/usr/bin/env bash
# Continuous ARP-table watcher: alerts if an IP's MAC changes (someone
# spoofing that IP) or if one MAC claims multiple IPs (a spoofer's own
# interface showing up under several forged addresses). Run this in the
# background/tmux for the whole event on a flat/shared network segment.
set -u
cd "$(dirname "$0")" && source ./config.sh

: "${ARP_INTERVAL:=4}"
LOG="$WORKDIR/arp_watch.log"
declare -A seen_mac  # ip -> mac

echo "watching ARP table every ${ARP_INTERVAL}s (ctrl-c to stop, log: $LOG)"

while true; do
    declare -A mac_to_ips=()
    while read -r ip mac; do
        [ -z "$ip" ] && continue
        prev="${seen_mac[$ip]:-}"
        if [ -n "$prev" ] && [ "$prev" != "$mac" ]; then
            msg="$(date -u) ALERT: $ip changed MAC $prev -> $mac (possible ARP spoofing)"
            echo "$msg" | tee -a "$LOG"
        fi
        seen_mac[$ip]="$mac"
        mac_to_ips[$mac]="${mac_to_ips[$mac]:-} $ip"
    done < <(ip neigh show 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="lladdr") print $1, $(i+1)}' \
              || arp -an 2>/dev/null | awk -F'[()]' '{print $2}' | awk '{print $1, $4}')

    for mac in "${!mac_to_ips[@]}"; do
        ips="${mac_to_ips[$mac]}"
        count=$(echo "$ips" | wc -w)
        if [ "$count" -gt 1 ]; then
            msg="$(date -u) ALERT: MAC $mac claims multiple IPs:$ips"
            echo "$msg" | tee -a "$LOG"
        fi
    done

    sleep "$ARP_INTERVAL"
done
