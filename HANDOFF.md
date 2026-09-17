# Raymond James CTF — handoff context

For a fresh Claude session picking this up cold in a different project. Read
this fully before touching any files — several early assumptions here were
wrong and got corrected mid-conversation; the "confirmed" section below is
what actually held up.

## The event

- **Raymond James IT Capture the Flag**, in-person at Raymond James HQ,
  St. Petersburg FL, **Saturday Oct 3 (2026), 8am–7pm ET**.
- Theme: *"Relentless Pursuit: Innovate. Anticipate. Defend."*
- Student recruiting event — teams of up to 5, aimed at juniors/seniors for
  IT Accelerated Development Program / internship pipeline.
- Built on the **MetaCTF / SkillBit** platform.
- User's own prior-year experience: "mostly red team, a little bit of blue
  team... the fortress-theme competition definitely had some blue team
  exercises, but still mostly offensive."
- 5-person team.

## Format — confirmed vs. assumed (important, read this)

1. **First assumption (wrong-ish): classic attack-defend.** Initial ask was
   "attack defend component," which reads as continuous rounds where teams
   exploit opponents' live hosts and defend their own service uptime, with
   flags rotating each round.
2. **Correction from research:** MetaCTF's own CTF prep guide explicitly
   states they run **jeopardy-style competitions, not attack-defend** —
   independent challenges by category (web/crypto/forensics/pwn/misc), each
   with its own static flag, solved in any order. Raymond James' own event
   blog post similarly describes "multiple challenges" completed through
   the day, not live inter-team infrastructure combat.
3. **Second correction, from a teammate's video (Gemini-summarized, full
   text in `ctf_defense/README.md`'s context and the original chat):** the
   event *also* includes a **live host-defense round** — you get handed
   access to a real Linux box running vulnerable services, and must harden
   it (firewall, backups, audit, intrusion detection) against other teams
   while keeping scoring checks passing. This is a King-of-the-Hill /
   defend-the-box style exercise, distinct from both "classic A/D" and pure
   jeopardy.

**Net conclusion:** treat this as **jeopardy challenges (mixed red/blue
categories) PLUS one live box-defense round.** There is no confirmed
evidence of continuous cross-team exploitation with rotating flags — don't
build more tooling assuming that unless something concrete says otherwise.

## Unknowns — do not assume answers, ask the user

- **Flag format** — not confirmed. Every tool defaults to a generic
  `word{...}` regex (`ctf_toolkit/common/flagscan.py: DEFAULT_PATTERN`).
  Update the pattern the moment the real scoreboard shows a flag.
- **Flag submission mechanism** — unknown at time of writing (API vs. web
  form vs. something else). `ctf_ad/attack/submitters.py` has pluggable
  backends (`file`/`http`/`null`) ready to point at whichever it turns out
  to be, if a live-infra round ever needs it.
- **Specific vulnerable services / challenge content** — unknown until the
  event starts, by design.
- **Scoring-engine subnet, real service ports for the defense box** —
  unknown; `ctf_defense/config.sh` has placeholders to fill in on the day.

## What's built (three independent toolkits, siblings in this directory)

### `ctf_toolkit/` — jeopardy challenge-solving helpers (the one you'll use most)
- `common/flagscan.py` — recursively auto-extracts archives from a
  challenge's downloaded files, pulls strings from binaries, regex-scans
  (+ one base64/hex decode pass) for the flag. Run first on any challenge
  with files.
- `common/decode_chain.py` — recursively auto-decodes a mystery string
  (base64/base32/hex/binary/URL/ROT13/gzip/zlib), depth-limited.
- `red/crypto_solve.py` — Caesar brute force, single-byte XOR brute force,
  known-plaintext XOR crib-dragging, best-effort Vigenère key recovery
  (index-of-coincidence + per-column chi-squared). All rank flag-pattern
  matches ahead of frequency-score ranking — **this was a real bug that got
  fixed**: pure English letter-frequency scoring ranked noise above the
  actual flag on short XOR ciphertext, because `{`/`_`/`}` aren't letters
  and don't get counted. Fixed by surfacing any flag-regex match first,
  regardless of score.
- `red/web_probe.py` — read-only recon against a challenge's own web
  target: headers, robots.txt, common backup/config/VCS-leak paths,
  non-destructive error-page probes.
- `blue/pcap_triage.py` — scapy-based: conversation summary, DNS dump, TCP
  stream reassembly, HTTP Basic-Auth/FTP credential extraction, flag-regex
  scan. Requires `pip install scapy`.
- `blue/log_triage.py` — parses access logs / SSH auth logs, surfaces
  brute-force patterns and common exploit signatures (path traversal, SQLi,
  XSS, command injection, Log4Shell), flag-regex scans every line.
- All tested with synthetic data during the build — see conversation
  history for exact test transcripts if you need to re-verify.

### `ctf_defense/` — live host-defense scripts (for the confirmed defense round)
Built directly from a teammate's prep-video summary (7 named scripts), plus
2 more (`00_doctor.sh`, `08_decoy.sh`) adapted from reviewing
[ashwnn/ctf-buddy](https://github.com/ashwnn/ctf-buddy) — see "Borrowed
ideas" in the root [README.md](README.md#borrowed-ideas) for what was and
wasn't adopted from it. Bash (+ one stdlib-only Python helper for the
decoy listener), no package-repo dependency at runtime.

0. `00_doctor.sh` — capability report (what's actually installed on this
   box vs. missing) for every tool the other scripts use. **Run this
   first**, before `01_baseline.sh`.
1. `01_baseline.sh` — listening ports → PID → exe path, logged-in users,
   cron/systemd-timer persistence check. **Run this first on any box,
   before anything else.**
2. `02_backup_git.sh` — tar.gz + git-snapshot of configured dirs (default
   `/etc /var/www /var/named` — edit `config.sh`), generates a
   `rollback.sh` helper. **Tested end-to-end**: tampered a file, confirmed
   `rollback.sh` restores it via `git reset --hard`.
3. `03_firewall_lockdown.sh` — default-drop INPUT/FORWARD/OUTPUT iptables,
   allow-lists from `config.sh`. **Has a 60s auto-revert safety net** so a
   missing port in the allow-list can't lock the team out — must run
   `./03_firewall_lockdown.sh confirm` from a still-working session to make
   it permanent. Verified via `DRY_RUN=1` (prints commands without
   executing) since the dev machine had no iptables to test against for
   real.
4. `04_host_audit.sh` — SUID/SGID baseline + diff on rerun, UID-0 account
   check, quick Lynis pass if installed.
5. `05_arp_watch.sh` — loops the ARP table, alerts on MAC changes per IP or
   one MAC claiming multiple IPs (spoofing detection).
6. `06_capture_ring.sh` — ring-buffered `tcpdump` on configured service
   ports; feed rotated pcaps into `ctf_toolkit/blue/pcap_triage.py`.
7. `07_chroot_jail.sh` — jails a legacy daemon binary + its `ldd`-resolved
   libs, deliberately excludes any shell so exploited shellcode can't pivot.
8. `08_decoy.sh` (+ `decoy_listener.py`) — optional honeypot/decoy on a
   port nothing else is using (fake HTTP login lure or fake service
   banner). Pure observation, never blocks anything; refuses to bind a
   port already in real use. **Tested end-to-end** (HTTP lure + banner
   modes, JSON-line logging all verified with curl/manual TCP) — the one
   caveat is the bind-refusal test doesn't reproduce on this Windows dev
   box (`SO_REUSEADDR` is more permissive than POSIX there); it's expected
   to hold correctly on the real Linux competition box.

`ctf_defense/config.sh` centralizes all the "fill in on the day" values
(backup dirs, allow-listed ports, scoring subnet, capture ports/dir, jail
root) — every script sources it, override any single value with an env var.

### `ctf_ad/` — attack-defend exploit-runner scaffold (contingency only)
Built *before* the format got clarified — assumes continuous rounds against
live opponent infrastructure with rotating flags, which is now believed
**not** to be this event's format. Kept in case a live-infra segment turns
up that we don't know about yet; don't lead with this unless something
concrete points back to it. Has: pluggable exploit-module runner
(`attack/runner.py`, drop modules in `attack/exploits/`), pluggable flag
submitters (`attack/submitters.py`: file/http/null), and defense-side
traffic sniffing / healthchecks / log watching mirroring `ctf_defense/`'s
concerns but Python-based and round-oriented rather than one-shot. The
runner now also refuses to start unless `config.yaml` has
`attack.acknowledged_rules: true` *and* `teams` no longer matches the
template's placeholder IPs — a safety gate adapted from ctf-buddy's
target-declaration pattern, tested end-to-end (all three states: refused
unacknowledged, refused on placeholder teams, ran normally once both are
real).

## Recommended external tools (from the teammate's prep video)

Install/verify **before** the event — no package-repo access assumed once
it's live:
- **Lynis, AIDE** — deeper audits than `04_host_audit.sh`'s quick pass; run
  when there's a spare minute
- **iptables/UFW** — `03_firewall_lockdown.sh` already implements the
  egress-filtering pattern the SANS guide describes; nothing extra to
  install, just confirm it's present on the box image
- **ModSecurity, Snort** — WAF/IDS rules, worth tuning only if there's time
  *and* an actual exploit attempt has been observed in a capture to write a
  rule against
- **AppArmor / SELinux** — extra hardening on top of `07_chroot_jail.sh`'s
  chroot, if time allows
- **tcpdump, arp-scan** — `06_capture_ring.sh` and `05_arp_watch.sh` are the
  continuous versions of these; `arp-scan` is still good for a one-shot
  sweep on arrival

## Suggested team roles (5 people)

Given the user's own past-year read ("mostly red team, a little blue team")
plus the confirmed live-defense round:

1. **Coordinator/captain** — owns the scoreboard, decides priorities, talks
   to organizers, tracks time-boxes so nobody tunnel-visions on one challenge
2. **Defense lead** — runs `ctf_defense/` scripts the second the team gets
   box access, in the order in its README; owns firewall + backup/rollback
3. **Defense monitor** — babysits `05_arp_watch.sh`/`06_capture_ring.sh`
   output and `04_host_audit.sh` reruns throughout the day; flags anything
   suspicious to whoever's patching
4. **Red/offense #1** — jeopardy web/crypto categories via `ctf_toolkit/red/`
5. **Red/offense #2** — jeopardy misc/forensics/pwn, using
   `ctf_toolkit/common/flagscan.py` and `ctf_toolkit/blue/` as needed,
   floats to whichever category is bottlenecked

Roles 2+3 collapse into one person for the first ~15 minutes (defense setup
is front-loaded), then both drift into jeopardy challenges once the box is
locked down and just needs periodic monitoring.

## State of this directory

- Was originally created inside an unrelated grad-school project directory,
  then moved out to its own top-level folder (`raymond-james-ctf/`) since
  it has nothing to do with that project.
- **Not a git repo yet.** Has a `.gitignore` ready (excludes real
  config/secrets/logs/pcaps) for whenever `git init` happens.
- Nothing has been committed or pushed anywhere.

## Immediate next steps once more info arrives

1. Real flag format → update `DEFAULT_PATTERN` in
   `ctf_toolkit/common/flagscan.py` (other tools import it from there).
2. Flag submission mechanism (if a live-infra round shows up) → configure
   `ctf_ad/config.yaml` (`cp config.example.yaml config.yaml` first).
3. Defense-box specifics (real services/ports/scoring subnet) → edit
   `ctf_defense/config.sh`.
4. If a live-infra attack round turns out to actually exist → promote
   `ctf_ad/` from contingency to primary, and start writing real exploit
   modules in `ctf_ad/attack/exploits/` once services are known.
