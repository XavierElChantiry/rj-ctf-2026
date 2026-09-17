#!/usr/bin/env bash
# Shared defaults for every script in this directory. Edit these once you
# know your box's real services/ports/scoring-engine IPs, then every script
# picks them up automatically (or override per-invocation with env vars,
# e.g. `INBOUND_ALLOW_PORTS="22 80" ./03_firewall_lockdown.sh`).

: "${WORKDIR:=/root/ctf_defense}"                     # scripts' own state/logs/backups
: "${BACKUP_DIRS:=/etc /var/www /var/named}"          # space-separated, edit to match real services
: "${INBOUND_ALLOW_PORTS:=22 80 443}"                 # ports the scoring engine/legit users hit
: "${OUTBOUND_ALLOW_PORTS:=53 80 443}"                # DNS + whatever your services legitimately call out to
: "${SCORING_SUBNETS:=}"                              # space-separated CIDRs, e.g. "10.0.0.0/24" - leave empty to skip
: "${CAPTURE_PORTS:=22 80 443}"
: "${CAPTURE_DIR:=/var/log/ctf_capture}"
: "${JAIL_ROOT:=/jail}"

mkdir -p "$WORKDIR"
