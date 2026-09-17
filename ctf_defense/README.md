# ctf_defense — live host-defense scripts

Implements the 7 scripts suggested in the team's prep notes, for the
box-defense portion of the event (separate from [`ctf_toolkit/`](../ctf_toolkit/README.md)'s
jeopardy-challenge helpers). Bash, no external Python deps, and everything
gracefully skips tools that aren't installed rather than failing — you can't
`apt install` mid-competition, so whatever's on the box when you get access
is what you have.

**Copy this whole directory onto the box** (or `git clone`/`scp` it) the
moment you get access — don't try to type these out live.

## Run order on taking a box

```bash
cd ctf_defense
./00_doctor.sh            # FIRST — what's actually on this box vs. what's missing
./01_baseline.sh          # what's normal before you change anything
./02_backup_git.sh        # snapshot configs/webroot so you can instantly revert tampering
./04_host_audit.sh        # SUID baseline + quick lynis pass + UID-0 check
./06_capture_ring.sh &    # start rolling packet capture in the background
./05_arp_watch.sh &       # start ARP-spoof monitor in the background (flat network only)
```

Then, once you've reviewed `01_baseline.sh`'s output and edited `config.sh`
with your real ports/scoring-engine subnet:

```bash
./03_firewall_lockdown.sh          # applies lockdown, auto-reverts in 60s if you don't confirm
# test that the scoring engine / your own SSH still works, THEN:
./03_firewall_lockdown.sh confirm  # cancel the auto-revert
```

**Never skip the confirm step's safety net on a live box** — if the allow
lists are missing a port the scoring check needs, you want it to
auto-revert in 60 seconds, not lock your own team out for the round.

If a legacy/vulnerable daemon is mandated by the challenge and you can't
just replace it:

```bash
./07_chroot_jail.sh /usr/sbin/vsftpd
chroot /jail /usr/sbin/vsftpd    # start it yourself — flags/config vary too much to script
```

Optional, once the box is locked down and just needs monitoring — a decoy
listener on a port nothing else is using, to see who's scanning and what
they try:

```bash
# add the port to INBOUND_ALLOW_PORTS in config.sh BEFORE locking down, or
# 03_firewall_lockdown.sh's default-drop will silently kill it too
./08_decoy.sh start --port 8080 --mode http                     # fake login page lure
./08_decoy.sh start --port 2222 --mode banner --banner ssh      # fake ssh greeting
./08_decoy.sh status
./08_decoy.sh logs --port 8080
./08_decoy.sh stop --all
```

It's pure observation, never a defense — it doesn't block anything, and a
hit is a source address, not proof of identity. Never point it at a port a
real/scored service needs; `00_doctor.sh`/`01_baseline.sh`'s listening-socket
dump tells you what's actually free. Refuses to start (non-zero exit) if
the port is already bound to something real — verified against a real
double-bind on Linux; a Windows dev box won't reproduce that refusal since
Windows' `SO_REUSEADDR` is more permissive than POSIX, so don't trust that
specific check outside the actual (Linux) competition box.

## config.sh

Every script sources this for shared settings (backup dirs, allow-listed
ports, scoring-engine subnet, capture ports/dir, jail root). Edit it once
per box; override any single value per-run with an env var, e.g.:

```bash
INBOUND_ALLOW_PORTS="22 80 8080" ./03_firewall_lockdown.sh
```

## If something goes wrong

- Locked yourself out with the firewall: it self-reverts within
  `TEST_TIMEOUT` seconds (default 60) unless you ran `confirm`. To force it
  immediately from a working session: `./03_firewall_lockdown.sh revert`.
- Config/webroot got tampered with: `WORKDIR/rollback.sh <dir>` (path
  printed at the end of `02_backup_git.sh`'s output) reverts to the last
  snapshot in seconds.
- Want to see what actually hit you: rotated pcaps are in `CAPTURE_DIR`
  (default `/var/log/ctf_capture`) — read them with
  `ctf_toolkit/blue/pcap_triage.py` back on your own laptop, or `tcpdump -r`.

## Recommended pre-installed tools (from the team's own research)

These aren't scripted here since they're standalone tools, not workflows —
install/verify them on your box image *before* the competition starts,
since you can't rely on package-repo access once it's live:

- **Lynis** — deeper system audit than `04_host_audit.sh`'s quick pass, run when you have a spare minute.
- **AIDE** — file-integrity monitoring if you want more than the git-snapshot approach in `02_backup_git.sh`.
- **ModSecurity** (OWASP CRS) / **Snort** — if the service is HTTP-based and you have time to tune WAF/IDS rules against a specific exploit you've seen in the capture.
- **AppArmor/SELinux** — extra confinement per-service, complementary to the chroot approach in `07_chroot_jail.sh`.
- **arp-scan** — one-shot ARP sweep to complement `05_arp_watch.sh`'s continuous loop.
