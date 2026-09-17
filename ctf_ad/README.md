# ctf_ad — attack/defend CTF toolkit

Generic scaffolding for an attack-defend event (built for the Raymond James
CTF, but not specific to it). Services and vulnerabilities are unknown until
the vulnbox drops, so this ships as a pluggable framework, not exploits.

Also the toolkit for **FAUST CTF 2026** (Sat 2026-09-26, 12:00-21:00 UTC,
[2026.faustctf.net](https://2026.faustctf.net/)) — a real, live
attack-defend event being used to rehearse this format ahead of Raymond
James. FAUST runs on [ctf-gameserver](https://ctf-gameserver.org/), which
works differently from a generic scoreboard: flags are looked up by
per-round **flag ID** rather than scanned off the wire, targets are
**IPv6 addresses derived from team number**, and submission is a raw
**TCP line protocol** on port 666, not HTTP. All three are supported —
see "ctf-gameserver-based events" below. Use
`config.faustctf.example.yaml` instead of the generic example for this one.

## Setup

```bash
pip install -r requirements.txt   # requests, pyyaml already in the main
                                   # project's requirements.txt; scapy is
                                   # only needed for defense/sniff_flags.py

cp ctf_ad/config.example.yaml ctf_ad/config.yaml            # generic flat-IP A/D event
# or, for FAUST CTF 2026 / any ctf-gameserver-based event:
cp ctf_ad/config.faustctf.example.yaml ctf_ad/config.yaml
```

Edit `config.yaml`: flag regex (from the rules PDF/scoreboard), your own IP,
enemy team IPs once published, and the flag-submission backend. `config.yaml`
is gitignored — it will hold real team IPs and possibly an API token.

Set `attack.acknowledged_rules: true` only after you've actually read the
event's rules on allowed targets/scope. The runner refuses to start
otherwise, and also refuses if `teams` still matches this file's placeholder
IPs — both are there so a copy-pasted template can't accidentally start
firing exploits at addresses nobody confirmed are in-scope.

## Attack side

1. As you find a vulnerable service, copy `attack/exploits/_template.py` to
   a new file (e.g. `attack/exploits/web_login_sqli.py`), implement `run()`
   to return raw response text / candidate strings from a target host. You
   don't need to regex-match the flag yourself — the runner does that.
2. Run it:

   ```bash
   python -m ctf_ad.attack.runner --config ctf_ad/config.yaml --once --dry-run   # sanity check
   python -m ctf_ad.attack.runner --config ctf_ad/config.yaml                    # loop for real
   ```

The runner auto-discovers every exploit module, fans out across all targets
concurrently each round, dedupes flags against `seen_flags.json` so nothing
gets resubmitted, and logs a per-round summary (attempts/hits/new/submitted).

Submission backend is config-only:
- `backend: file` — appends new flags to `captured_flags.txt` for manual
  paste into the scoreboard (use this if it's a web form, or until the API
  is announced).
- `backend: http` — posts to a real scoreboard API (`attack.submission.http`).
- `backend: tcp` — speaks ctf-gameserver's plaintext line protocol
  (`attack.submission.tcp`: host/port, default port 666). This is what
  FAUST CTF and similar events use — see below.
- `backend: null` — dry run, just logs.

## ctf-gameserver-based events (FAUST CTF and similar)

Some attack-defend events (built on [ctf-gameserver](https://ctf-gameserver.org/),
FAUST CTF among them) don't let you just scan traffic for a flag — the
checker stores one **flag ID** per (service, team, round), published in a
`teams.json`-style JSON document, and your exploit has to use the service's
own functionality to fetch the flag *that ID* points at.

To use this mode instead of a flat `teams:` IP list:

```yaml
own_team_number: 7                        # excludes yourself automatically
team_numbers: [3, 4, 5, ...]              # fill in once teams are assigned
target_template: "fd66:666:{team}::2"     # FAUST's scheme; adjust per event

attack:
  flag_ids:
    url: "https://2026.faustctf.net/competition/teams.json"
    refresh_seconds: 30                   # re-fetched at the start of every round
  submission:
    backend: tcp
    tcp:
      host: submission.faustctf.net
      port: 666
```

Exploit modules opt in by accepting the new `flag_ids` parameter:

```python
def run(target: str, timeout: float = 5.0, flag_ids: list[str] | None = None) -> list[str]:
    if flag_ids:
        return [requests.get(f"http://{target}:8080/flag/{fid}", timeout=timeout).text
                for fid in flag_ids]
    ...  # fall back to a plain scan if flag_ids is empty (no flag-ID config, or none issued yet)
```

Older modules that only take `(target, timeout)` still work — the runner
detects the `TypeError` and calls them the old way, just without flag IDs.

`ctf_ad/attack/flagids.py`'s `FlagIdCache` does the fetching (refreshed once
per round, degrades to the last known-good set on a network blip rather than
crashing the round) and `ctf_ad/common/targets.py`'s `expand_targets()` does
the team-number → address expansion. Neither is FAUST-specific by name —
any event using the same `teams.json` shape and address-templating pattern
can reuse them by pointing the config at its own URL/template.

The `tcp` submitter (`ctf_ad/attack/submitters.py: TcpLineSubmitter`) is
written from the [protocol spec](https://ctf-gameserver.org/submission/) and
unit-tested against a local mock server (banner-skip, OK/DUP/INV/ERR
handling, connection reuse and reconnect) — but **not yet exercised against
a real gameserver**, since submission hosts are only reachable from inside
the competition VPN. Sanity-check it against the real welcome banner the
first chance you get once VPN access exists.

## Defense side

- `defense/healthcheck.py` — hits your own services after every patch to
  confirm you didn't break the SLA checker. Run `--once` right after a
  deploy (non-zero exit if anything's down), and loop it in the background
  otherwise.
- `defense/log_watch.py` — tails configured log files, flags common exploit
  patterns (path traversal, SQLi, XSS, command injection) plus your own
  flag regex appearing in a request (possible exfil/probe).
- `defense/sniff_flags.py` — passively sniffs configured ports for
  flag-shaped strings on the wire, so you can see which service is getting
  hit hardest and prioritize patching it. Detection only, never blocks
  anything. Needs scapy + root/Npcap.

## Notes

- Everything here is read-only against other teams except the exploits you
  write yourselves — this toolkit doesn't do anything destructive or
  automated beyond the competition's own attack surface.
- Keep exploits defensive about failure: refused connections, timeouts, and
  patched services are the norm mid-event, not the exception. A crashing
  exploit module must never take down the whole round (the runner already
  catches per-job exceptions, but keep exploit code itself resilient too).
