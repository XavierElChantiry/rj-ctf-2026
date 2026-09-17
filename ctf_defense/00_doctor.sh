#!/usr/bin/env bash
# Capability report: run this the SECOND you get box access, before
# 01_baseline.sh, so the team knows in five seconds what this specific box
# has vs. what it's missing. No package-repo access is assumed once the
# event is live, so "missing" here means "won't have it all day" — plan
# around it now instead of discovering it mid-incident.
set -u
cd "$(dirname "$0")" && source ./config.sh

ok=0
missing=0

check() {
    local name="$1" used_by="$2"
    if command -v "$name" >/dev/null 2>&1; then
        printf "  [x] %-14s used by: %s\n" "$name" "$used_by"
        ok=$((ok + 1))
    else
        printf "  [ ] %-14s used by: %s (missing)\n" "$name" "$used_by"
        missing=$((missing + 1))
    fi
}

echo "=== $(date -u) — capability report for $(hostname) ==="

echo -e "\n--- core (everything below depends on these) ---"
check ss "01_baseline.sh (falls back to netstat)"
check iptables "03_firewall_lockdown.sh"
check python3 "08_decoy.sh, ctf_toolkit/*"

echo -e "\n--- audit / integrity ---"
check lynis "04_host_audit.sh (optional deeper pass)"
check aide "file-integrity monitoring (external, not scripted here)"
check git "02_backup_git.sh"

echo -e "\n--- network monitoring ---"
check tcpdump "06_capture_ring.sh"
check arp-scan "one-shot ARP sweep on arrival (05_arp_watch.sh is the loop)"
check arping "fallback for 05_arp_watch.sh if arp/ip neigh is unavailable"

echo -e "\n--- extra hardening (nice-to-have, not scripted here) ---"
check apparmor_status "AppArmor confinement on top of 07_chroot_jail.sh"
check getenforce "SELinux confinement on top of 07_chroot_jail.sh"

if command -v python3 >/dev/null 2>&1; then
    echo -e "\n--- python3 modules ---"
    if python3 -c "import scapy" >/dev/null 2>&1; then
        echo "  [x] scapy          used by: ctf_toolkit/blue/pcap_triage.py, ctf_ad/defense/sniff_flags.py"
        ok=$((ok + 1))
    else
        echo "  [ ] scapy          used by: ctf_toolkit/blue/pcap_triage.py, ctf_ad/defense/sniff_flags.py (missing — pip install scapy while you still have network)"
        missing=$((missing + 1))
    fi
fi

echo -e "\n=== $ok available, $missing missing ==="
[ "$missing" -eq 0 ] && echo "everything this toolkit uses is present." || echo "missing tools degrade gracefully (scripts skip what they can't use) but install what you can now, before you lose repo access."
