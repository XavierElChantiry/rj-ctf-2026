# ctf_ad — attack/defend CTF toolkit

Generic scaffolding for an attack-defend event (built for the Raymond James
CTF, but not specific to it). Services and vulnerabilities are unknown until
the vulnbox drops, so this ships as a pluggable framework, not exploits.

## Setup

```bash
pip install -r requirements.txt   # requests, pyyaml already in the main
                                   # project's requirements.txt; scapy is
                                   # only needed for defense/sniff_flags.py
cp ctf_ad/config.example.yaml ctf_ad/config.yaml
```

Edit `config.yaml`: flag regex (from the rules PDF/scoreboard), your own IP,
enemy team IPs once published, and the flag-submission backend. `config.yaml`
is gitignored — it will hold real team IPs and possibly an API token.

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
- `backend: null` — dry run, just logs.

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
