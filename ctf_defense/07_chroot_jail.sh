#!/usr/bin/env bash
# Build a minimal chroot around one daemon binary, so if it gets exploited
# the attacker's shellcode lands in an empty jail with no shell and no
# other binaries to pivot with, instead of your real filesystem.
#
# Usage: ./07_chroot_jail.sh /usr/sbin/vsftpd
#
# This only prepares the jail (copies the binary + its shared libs). You
# still start the daemon yourself with:
#   chroot "$JAIL_ROOT" /path/to/daemon [args]
# Deliberately does NOT do that for you — daemon startup flags/config paths
# vary too much to guess safely.
set -u
cd "$(dirname "$0")" && source ./config.sh

BIN="${1:?usage: $0 /path/to/daemon}"
[ -x "$BIN" ] || { echo "not an executable: $BIN"; exit 1; }

mkdir -p "$JAIL_ROOT"/{bin,lib,lib64,etc,dev,var,usr/sbin,usr/bin}

# Deliberately no /bin/sh or /bin/bash copied in: if the daemon gets popped,
# `system()`/shellcode calls fail to exec because there's no shell present.
mkdir -p "$JAIL_ROOT$(dirname "$BIN")"
cp -p "$BIN" "$JAIL_ROOT$BIN"
echo "copied $BIN -> $JAIL_ROOT$BIN"

ldd "$BIN" 2>/dev/null | grep -oP '(?<==> )/\S+|^\s*/\S+' | while read -r lib; do
    [ -f "$lib" ] || continue
    dest="$JAIL_ROOT$lib"
    mkdir -p "$(dirname "$dest")"
    cp -p "$lib" "$dest"
    echo "copied lib $lib"
done

# The dynamic loader itself isn't always caught by the grep above depending
# on ldd's output format on this distro — copy it explicitly if present.
for ld in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux.so.2; do
    [ -f "$ld" ] && { mkdir -p "$JAIL_ROOT$(dirname "$ld")"; cp -p "$ld" "$JAIL_ROOT$ld"; }
done

# Minimal /etc so name/user resolution inside the jail doesn't hang or leak
# your real passwd file.
echo "root:x:0:0:root:/:/bin/false" > "$JAIL_ROOT/etc/passwd"
echo "root:x:0:" > "$JAIL_ROOT/etc/group"

# Some daemons want /dev/null, /dev/zero, /dev/urandom present.
[ -e "$JAIL_ROOT/dev/null" ] || mknod -m 666 "$JAIL_ROOT/dev/null" c 1 3
[ -e "$JAIL_ROOT/dev/zero" ] || mknod -m 666 "$JAIL_ROOT/dev/zero" c 1 5
[ -e "$JAIL_ROOT/dev/urandom" ] || mknod -m 444 "$JAIL_ROOT/dev/urandom" c 1 9

echo
echo "jail ready at $JAIL_ROOT"
echo "start the daemon inside it with:  chroot \"$JAIL_ROOT\" \"$BIN\" [args]"
echo "verify no shell is reachable:     chroot \"$JAIL_ROOT\" /bin/sh   (should fail: No such file or directory)"
