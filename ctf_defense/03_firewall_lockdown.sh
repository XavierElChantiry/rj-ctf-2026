#!/usr/bin/env bash
# Dual-direction lockdown: default-drop INPUT/FORWARD/OUTPUT, punch holes
# only for real services + the scoring engine. Egress filtering is the part
# that actually stops reverse shells/exfil — most teams only do inbound.
#
# SAFETY: applying this over your own SSH session can lock you out if a port
# you need isn't in the allow-lists. By default this self-reverts after
# TEST_TIMEOUT seconds unless you run `./03_firewall_lockdown.sh confirm`
# first from a session that's still working. Always test this way before
# trusting it — do not disable the timeout on first run.
set -u
cd "$(dirname "$0")" && source ./config.sh

: "${TEST_TIMEOUT:=60}"
SAVE_FILE="$WORKDIR/iptables_before_lockdown.rules"
CONFIRM_FLAG="$WORKDIR/.lockdown_confirmed"
DRY_RUN="${DRY_RUN:-0}"

run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "+ $*"
    else
        "$@"
    fi
}

if [ "${1:-}" = "confirm" ]; then
    touch "$CONFIRM_FLAG"
    echo "lockdown confirmed, auto-revert cancelled"
    exit 0
fi

if [ "${1:-}" = "revert" ]; then
    [ -f "$SAVE_FILE" ] || { echo "no saved rules at $SAVE_FILE"; exit 1; }
    iptables-restore < "$SAVE_FILE"
    echo "reverted to pre-lockdown rules"
    exit 0
fi

rm -f "$CONFIRM_FLAG"
iptables-save > "$SAVE_FILE" 2>/dev/null && echo "saved current rules to $SAVE_FILE"

run iptables -F
run iptables -X

run iptables -A INPUT -i lo -j ACCEPT
run iptables -A OUTPUT -o lo -j ACCEPT
run iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
run iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

for subnet in $SCORING_SUBNETS; do
    run iptables -A INPUT -s "$subnet" -j ACCEPT
    run iptables -A OUTPUT -d "$subnet" -j ACCEPT
done

for port in $INBOUND_ALLOW_PORTS; do
    run iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    run iptables -A INPUT -p udp --dport "$port" -j ACCEPT
done

for port in $OUTBOUND_ALLOW_PORTS; do
    run iptables -A OUTPUT -p tcp --dport "$port" -j ACCEPT
    run iptables -A OUTPUT -p udp --dport "$port" -j ACCEPT
done

run iptables -P INPUT DROP
run iptables -P FORWARD DROP
run iptables -P OUTPUT DROP

echo "lockdown applied (dry_run=$DRY_RUN)."

if [ "$DRY_RUN" = "1" ]; then
    exit 0
fi

echo "auto-reverting in ${TEST_TIMEOUT}s unless you run: $0 confirm"
(
    sleep "$TEST_TIMEOUT"
    if [ ! -f "$CONFIRM_FLAG" ]; then
        iptables-restore < "$SAVE_FILE"
        echo "$(date -u): lockdown NOT confirmed in time, auto-reverted" >> "$WORKDIR/firewall.log"
    fi
) </dev/null >/dev/null 2>&1 &
disown
