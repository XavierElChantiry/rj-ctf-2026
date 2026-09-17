#!/usr/bin/env bash
# Honeypot/decoy listeners on ports the box isn't actually using — pure
# observation, never a defense. A hit tells you someone's scanning and what
# they tried; it does not stop them and it is not proof of who they are.
# Never point this at a port a real/scored service needs — pick from
# 01_baseline.sh's "listening sockets" output what's still free.
#
# IMPORTANT: if you want this port reachable after 03_firewall_lockdown.sh
# runs, add it to INBOUND_ALLOW_PORTS in config.sh FIRST — the lockdown's
# default-drop would otherwise silently kill the decoy along with
# everything else. Order: decide the port -> allow-list it -> lock down.
set -u
cd "$(dirname "$0")" && source ./config.sh

usage() {
    cat <<EOF
usage:
  $0 start --port PORT [--mode http|banner] [--banner ssh|ftp|smtp|telnet|<text>]
  $0 stop --port PORT | $0 stop --all
  $0 status
  $0 logs --port PORT [--lines N]
EOF
    exit 1
}

cmd="${1:-}"; shift || true
port="" mode="http" banner="ssh" lines=50 all=0

while [ $# -gt 0 ]; do
    case "$1" in
        --port) port="$2"; shift 2 ;;
        --mode) mode="$2"; shift 2 ;;
        --banner) banner="$2"; shift 2 ;;
        --lines) lines="$2"; shift 2 ;;
        --all) all=1; shift ;;
        *) usage ;;
    esac
done

mkdir -p "$CAPTURE_DIR"
pidfile() { echo "$WORKDIR/decoy_${1}.pid"; }
logfile() { echo "$CAPTURE_DIR/decoy-${1}.jsonl"; }

case "$cmd" in
    start)
        [ -n "$port" ] || usage
        pf="$(pidfile "$port")"
        if [ -f "$pf" ] && kill -0 "$(cat "$pf")" 2>/dev/null; then
            echo "decoy already running on :$port (pid $(cat "$pf"))"
            exit 1
        fi
        nohup python3 "$(dirname "$0")/decoy_listener.py" \
            --port "$port" --mode "$mode" --banner "$banner" --log "$(logfile "$port")" \
            > "$WORKDIR/decoy_${port}.log" 2>&1 &
        pid=$!
        sleep 0.5
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "decoy failed to start on :$port — check $WORKDIR/decoy_${port}.log (probably: port already in use)"
            exit 1
        fi
        echo "$pid" > "$pf"
        echo "decoy started on :$port (mode=$mode, pid=$pid), logging to $(logfile "$port")"
        ;;
    stop)
        if [ "$all" = "1" ]; then
            shopt -s nullglob
            for pf in "$WORKDIR"/decoy_*.pid; do
                p=$(cat "$pf"); kill "$p" 2>/dev/null && echo "stopped pid $p ($pf)"; rm -f "$pf"
            done
            exit 0
        fi
        [ -n "$port" ] || usage
        pf="$(pidfile "$port")"
        [ -f "$pf" ] || { echo "no decoy tracked for :$port"; exit 1; }
        kill "$(cat "$pf")" 2>/dev/null && echo "stopped decoy on :$port"
        rm -f "$pf"
        ;;
    status)
        shopt -s nullglob
        found=0
        for pf in "$WORKDIR"/decoy_*.pid; do
            found=1
            p=$(basename "$pf" .pid); p="${p#decoy_}"
            if kill -0 "$(cat "$pf")" 2>/dev/null; then
                echo "  :$p  running (pid $(cat "$pf"))  log: $(logfile "$p")"
            else
                echo "  :$p  dead (stale pidfile $pf)"
            fi
        done
        [ "$found" = "0" ] && echo "no decoys running"
        ;;
    logs)
        [ -n "$port" ] || usage
        lf="$(logfile "$port")"
        [ -f "$lf" ] || { echo "no log yet at $lf"; exit 1; }
        tail -n "$lines" "$lf"
        ;;
    *)
        usage
        ;;
esac
