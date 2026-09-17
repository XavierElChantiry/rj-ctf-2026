# ctf_toolkit — jeopardy-style CTF helpers (Raymond James CTF)

Built after checking MetaCTF/SkillBit's own docs: they describe their
platform as running **jeopardy-style** competitions (independent challenges
by category, each with its own flag), not classic live attack-defend
infrastructure. Raymond James' event on this platform mixes red-team
(offensive) and blue-team (defensive/forensics) categories rather than
continuous rounds against opponent hosts. If it turns out the event *does*
include a live infra round, see [`../ctf_ad/`](../ctf_ad/README.md) instead
— that toolkit is built for exactly that.

Flag format wasn't confirmed (`MetaCTF{}`, `SkillBit{}`, `RJ{}`, or a custom
prefix are all plausible) — every tool here defaults to a generic
`word{...}` pattern (`common/flagscan.py: DEFAULT_PATTERN`) and accepts
`--pattern` to override once you see the real format on the scoreboard.

## Setup

```bash
pip install -r requirements.txt   # requests, pyyaml from the main project;
                                   # scapy only needed for pcap_triage.py
```

## common/ — shared across categories

- **`flagscan.py`** — point at a downloaded challenge folder; it recursively
  auto-extracts zip/tar archives, pulls printable strings out of binaries,
  and regex-scans everything (plus one base64/hex decode pass) for the flag
  format. Run this first on *any* challenge that gives you files — cheap and
  often just finds it.

  ```bash
  python -m ctf_toolkit.common.flagscan ./challenge_files
  ```

- **`decode_chain.py`** — given one mystery string, recursively tries
  base64/base32/hex/binary/URL/ROT13/gzip/zlib and prints every readable
  result, flagging anything that matches the flag pattern.

  ```bash
  python -m ctf_toolkit.common.decode_chain 'TWV0YUNURns...'
  ```

## red/ — offensive categories (web, crypto, pwn recon)

- **`crypto_solve.py`** — Caesar/ROT brute force, single-byte XOR brute
  force, known-plaintext XOR (crib dragging — e.g. crib the flag's own
  prefix), and best-effort Vigenere key recovery (index-of-coincidence +
  per-column chi-squared). All rank flag-pattern matches first, since letter-
  frequency scoring alone is unreliable on short ciphertext.

  ```bash
  python -m ctf_toolkit.red.crypto_solve caesar 'Wkh...'
  python -m ctf_toolkit.red.crypto_solve xor-brute <hex>
  python -m ctf_toolkit.red.crypto_solve xor-crib <hex> --known 'MetaCTF{'
  python -m ctf_toolkit.red.crypto_solve vigenere '<ciphertext>' --max-key-len 12
  ```

- **`web_probe.py`** — read-only recon against a web challenge's own URL:
  response headers, robots.txt, common backup/config/VCS-leak paths
  (`.git/HEAD`, `.env`, `backup.sql`, ...), and a few non-destructive
  error-page probes to spot verbose stack traces. Only ever point this at a
  challenge target you've been given, never anything else.

  ```bash
  python -m ctf_toolkit.red.web_probe http://challenge.host:8080
  ```

For binary exploitation, MetaCTF's own prep guide recommends Ghidra +
pwntools — no custom template here since a good one needs the actual binary
in hand; ask me once you have one and I'll help write the exploit directly.

## blue/ — defensive/forensics categories

- **`pcap_triage.py`** — load a pcap, list conversations by bytes
  transferred, dump DNS queries, reassemble TCP streams well enough to pull
  out HTTP Basic-Auth/form credentials and FTP creds, and flag-regex scan
  every stream.

  ```bash
  python -m ctf_toolkit.blue.pcap_triage capture.pcap
  python -m ctf_toolkit.blue.pcap_triage capture.pcap --streams   # dump full stream text
  ```

- **`log_triage.py`** — parse a web access log or SSH auth log, surface top
  talkers, status-code distribution, brute-force patterns, and common
  exploit-attempt signatures (path traversal, SQLi, XSS, command injection,
  Log4Shell), plus flag-regex scan every line.

  ```bash
  python -m ctf_toolkit.blue.log_triage access.log
  python -m ctf_toolkit.blue.log_triage auth.log --format auth
  ```

## Notes

- Everything here is read-only reconnaissance/analysis against your own
  challenge files or a target you've been explicitly given — nothing
  automates exploitation or touches infrastructure outside the challenge.
- All flag-matching defaults to a generic pattern; pass `--pattern` the
  moment you see the real flag format to cut down on false positives.
