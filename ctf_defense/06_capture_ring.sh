#!/usr/bin/env bash
# Background rolling packet capture on your service ports, so when a
# service gets popped you have the actual exploit traffic to read instead
# of reconstructing it from memory. Ring-buffered so it can run unattended
# all day without filling the disk.
set -u
cd "$(dirname "$0")" && source ./config.sh

: "${CAPTURE_FILE_MB:=50}"   # size per rotated file
: "${CAPTURE_FILE_COUNT:=10}" # number of files kept (ring)
PIDFILE="$WORKDIR/capture.pid"

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "capture already running (pid $(cat "$PIDFILE")), stop it first: kill \$(cat $PIDFILE)"
    exit 1
fi

mkdir -p "$CAPTURE_DIR"

filter=$(printf "port %s or " $CAPTURE_PORTS)
filter="${filter% or }"

nohup tcpdump -i any -nn -s0 \
    -C "$CAPTURE_FILE_MB" -W "$CAPTURE_FILE_COUNT" \
    -w "$CAPTURE_DIR/capture.pcap" \
    "$filter" \
    > "$WORKDIR/capture.log" 2>&1 &

echo $! > "$PIDFILE"
echo "capturing ($filter) -> $CAPTURE_DIR/capture.pcap* (pid $!, ring of $CAPTURE_FILE_COUNT x ${CAPTURE_FILE_MB}MB)"
echo "stop with: kill \$(cat $PIDFILE)"
echo "read a rotated file with: ctf_toolkit's blue/pcap_triage.py, or tcpdump -r <file>"
