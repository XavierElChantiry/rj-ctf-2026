# Raymond James CTF — team toolkit

Prep for the **Raymond James IT Capture the Flag**, in-person at Raymond
James HQ, St. Petersburg FL, **Saturday Oct 3, 2026, 8am–7pm ET**. Built on
the MetaCTF/SkillBit platform. Format: **jeopardy-style challenges** (mixed
red/blue categories, independent, solved in any order) **plus one live
host-defense round** (hand-off box you must harden while scoring checks
keep passing). See [HANDOFF.md](HANDOFF.md) for the full background,
confirmed-vs-assumed format notes, and open unknowns.

Three independent toolkits, one per folder:

| Folder | Round it's for | Status |
|---|---|---|
| [`ctf_toolkit/`](ctf_toolkit/README.md) | Jeopardy challenges | Primary — you'll use this most |
| [`ctf_defense/`](ctf_defense/README.md) | Live host-defense round | Primary — confirmed round |
| [`ctf_ad/`](ctf_ad/README.md) | Classic attack-defend (rotating flags vs. live opponents) | Contingency only — this format is **not believed** to be part of the event; kept in case a live-infra segment turns up |

## Team roles (5 people)

Based on the user's own past-year read ("mostly red team, a little blue
team") plus the confirmed live-defense round:

1. **Coordinator/captain** — owns the scoreboard, decides priorities, talks
   to organizers, tracks time-boxes so nobody tunnel-visions on one
   challenge.
2. **Defense lead** — runs [`ctf_defense/`](ctf_defense/README.md) scripts
   the second the team gets box access, in the order in its README; owns
   the firewall and backup/rollback.
3. **Defense monitor** — babysits `05_arp_watch.sh` / `06_capture_ring.sh`
   output and `04_host_audit.sh` reruns throughout the day; flags anything
   suspicious to whoever's patching. Collapses into one person with the
   Defense lead for the first ~15 minutes (setup is front-loaded), then
   both drift into jeopardy challenges once the box is locked down and
   just needs periodic monitoring.
4. **Red/offense #1** — jeopardy web/crypto categories via
   [`ctf_toolkit/red/`](ctf_toolkit/README.md#red--offensive-categories-web-crypto-pwn-recon).
5. **Red/offense #2** — jeopardy misc/forensics/pwn, using
   [`ctf_toolkit/common/`](ctf_toolkit/README.md#common--shared-across-categories)
   and [`ctf_toolkit/blue/`](ctf_toolkit/README.md#blue--defensiveforensics-categories)
   as needed; floats to whichever category is bottlenecked.

## Scripts by folder

### `ctf_toolkit/` — jeopardy challenge-solving helpers

- **`common/flagscan.py`** — recursively auto-extracts archives from a
  challenge's downloaded files, pulls strings from binaries, regex-scans
  (+ one base64/hex decode pass) for the flag. Run first on any challenge
  with files.
- **`common/decode_chain.py`** — recursively auto-decodes a mystery string
  (base64/base32/hex/binary/URL/ROT13/gzip/zlib), depth-limited.
- **`red/crypto_solve.py`** — Caesar brute force, single-byte XOR brute
  force, known-plaintext XOR crib-dragging, best-effort Vigenère key
  recovery (index-of-coincidence + per-column chi-squared). Ranks
  flag-pattern matches ahead of frequency scoring, since `{`/`_`/`}` aren't
  letters and skew pure frequency analysis on short ciphertext.
- **`red/web_probe.py`** — read-only recon against a challenge's own web
  target: headers, robots.txt, common backup/config/VCS-leak paths,
  non-destructive error-page probes.
- **`blue/pcap_triage.py`** — scapy-based: conversation summary, DNS dump,
  TCP stream reassembly, HTTP Basic-Auth/FTP credential extraction,
  flag-regex scan. Requires `pip install scapy`.
- **`blue/log_triage.py`** — parses access logs / SSH auth logs, surfaces
  brute-force patterns and common exploit signatures (path traversal, SQLi,
  XSS, command injection, Log4Shell), flag-regex scans every line.

Full usage examples and setup: [`ctf_toolkit/README.md`](ctf_toolkit/README.md).

### `ctf_defense/` — live host-defense scripts

Run in this order the moment the box is handed over:

0. **`00_doctor.sh`** — capability report: what's actually installed on
   this specific box (iptables, tcpdump, lynis, scapy, ...) vs. what's
   missing, so the team knows in five seconds what it's working with. Run
   before `01_baseline.sh`.
1. **`01_baseline.sh`** — listening ports → PID → exe path, logged-in
   users, cron/systemd-timer persistence check.
2. **`02_backup_git.sh`** — tar.gz + git-snapshot of configured dirs
   (default `/etc /var/www /var/named`), generates a `rollback.sh` helper
   for instant revert.
3. **`03_firewall_lockdown.sh`** — default-drop INPUT/FORWARD/OUTPUT
   iptables, allow-lists from `config.sh`. Has a 60s auto-revert safety net
   so a missing port in the allow-list can't lock the team out — run
   `./03_firewall_lockdown.sh confirm` from a still-working session to make
   it permanent.
4. **`04_host_audit.sh`** — SUID/SGID baseline + diff on rerun, UID-0
   account check, quick Lynis pass if installed.
5. **`05_arp_watch.sh`** — loops the ARP table, alerts on MAC changes per
   IP or one MAC claiming multiple IPs (spoofing detection). Run in the
   background.
6. **`06_capture_ring.sh`** — ring-buffered `tcpdump` on configured service
   ports; feed rotated pcaps into `ctf_toolkit/blue/pcap_triage.py`. Run in
   the background.
7. **`07_chroot_jail.sh`** — jails a legacy daemon binary + its
   `ldd`-resolved libs, deliberately excludes any shell so exploited
   shellcode can't pivot. Only needed if a legacy/vulnerable daemon is
   mandated by the challenge.
8. **`08_decoy.sh`** (+ `decoy_listener.py`) — optional honeypot/decoy
   listener (fake HTTP login lure, or a fake service banner) on a port
   nothing else is using. Pure observation — logs who probed it and what
   they sent, never blocks anything. Refuses to bind a port that's already
   in real use.

`config.sh` centralizes all the "fill in on the day" values (backup dirs,
allow-listed ports, scoring subnet, capture ports/dir, jail root) — every
script sources it. Full run order, troubleshooting, and recommended
external tools: [`ctf_defense/README.md`](ctf_defense/README.md).

### `ctf_ad/` — attack-defend exploit-runner scaffold (contingency only)

Built before the format got clarified — assumes continuous rounds against
live opponent infrastructure with rotating flags, which is now believed
**not** to be this event's format. Don't lead with this unless something
concrete points back to it.

- **`attack/runner.py`** — pluggable exploit-module runner; auto-discovers
  modules dropped in `attack/exploits/`, fans out across targets each
  round, dedupes flags, logs per-round summaries.
- **`attack/exploits/_template.py`** — copy this to start a new exploit
  module; implement `run()` to return candidate strings, the runner does
  the flag-matching.
- **`attack/submitters.py`** — pluggable flag-submission backends
  (`file` / `http` / `null`).
- **`defense/healthcheck.py`** — hits your own services after every patch
  to confirm the SLA checker still passes.
- **`defense/log_watch.py`** — tails configured logs, flags common exploit
  patterns plus your own flag regex appearing in a request.
- **`defense/sniff_flags.py`** — passively sniffs configured ports for
  flag-shaped strings on the wire (detection only, never blocks). Needs
  scapy + root/Npcap.

Setup and full workflow: [`ctf_ad/README.md`](ctf_ad/README.md).

## Borrowed ideas

After reviewing [ashwnn/ctf-buddy](https://github.com/ashwnn/ctf-buddy) (a
much larger Python framework built for a similar remote-vuln-box workflow),
two of its patterns were worth adapting into this simpler toolkit — kept as
plain bash/stdlib-Python scripts rather than pulling in its full
plan/apply/rollback framework, which is built for an operator managing a
fleet of profiles remotely over SSH and is more machinery than a
single-box, single-day event needs:

- **`ctf_defense/00_doctor.sh`** — a capability report before touching
  anything, mirroring their `ctfctl doctor`.
- **`ctf_defense/08_decoy.sh` / `decoy_listener.py`** — an honeypot/decoy
  listener, mirroring their `ctfctl decoy`/`honeypot` (HTTP lure + banner
  modes, refuses to bind a port already in real use, bounded/capped
  logging so a scan can't fill the disk or forge log lines).
- **`ctf_ad`'s `acknowledged_rules` gate** — their target-declaration +
  policy-acknowledgment requirement before any remote mutation was worth
  a lighter version here: the attack runner now refuses to start unless
  `acknowledged_rules: true` is set and `teams` no longer matches the
  template's placeholder IPs, so a copy-pasted config can't accidentally
  fire exploits at nobody-confirmed-in-scope addresses.

Not adopted: their full remote SSH-administration model (`remote
probe/plan/apply/verify/rollback` against a declared host from an
operator's laptop), the curated knowledge-base corpus (real content to
research and write ourselves, not something to copy), Docker-based
practice fixtures, and release packaging — all built for a heavier,
longer-running operation than one hand-off box for one day.

## Open unknowns

Flag format, flag-submission mechanism, specific vulnerable services, and
the defense-box's real ports/scoring subnet are all unknown until the event
starts — see [HANDOFF.md](HANDOFF.md#unknowns--do-not-assume-answers-ask-the-user)
for exactly what to update and where once that information arrives.
