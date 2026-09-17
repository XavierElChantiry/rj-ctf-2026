"""Triage a log file for a blue-team/incident-response challenge: parse
common web access-log and SSH auth-log formats, surface brute-force
patterns, exploit-attempt signatures, and top talkers, plus flag-regex scan
every line (challenge flags sometimes hide directly in a log entry).

Usage:
    python -m ctf_toolkit.blue.log_triage access.log
    python -m ctf_toolkit.blue.log_triage auth.log --format auth
"""
from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path

from ctf_toolkit.common.flagscan import DEFAULT_PATTERN

ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\S+)'
)

SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ATTACK_PATTERNS = {
    "path_traversal": re.compile(r"\.\./"),
    "sqli": re.compile(r"(?i)union\s+select|or\s+1=1|'--"),
    "xss": re.compile(r"(?i)<script"),
    "command_injection": re.compile(r";\s*(cat|wget|curl|nc|bash|sh)\s"),
    "log4shell": re.compile(r"\$\{jndi:"),
}


def triage_access_log(lines: list[str], flag_pattern: re.Pattern) -> None:
    ip_counts: Counter = Counter()
    status_counts: Counter = Counter()
    attack_hits: defaultdict = defaultdict(list)
    flag_hits: list[str] = []

    for line in lines:
        m = ACCESS_LOG_RE.search(line)
        if m:
            ip_counts[m.group("ip")] += 1
            status_counts[m.group("status")] += 1
        for name, pat in ATTACK_PATTERNS.items():
            if pat.search(line):
                attack_hits[name].append(line.strip())
        flags = flag_pattern.findall(line)
        if flags:
            flag_hits.extend(flags)

    print("top source IPs:")
    for ip, count in ip_counts.most_common(10):
        print(f"  {ip}: {count} requests")

    print("\nstatus code distribution:")
    for status, count in status_counts.most_common():
        print(f"  {status}: {count}")

    if attack_hits:
        print("\nsuspicious request patterns:")
        for name, hits in attack_hits.items():
            print(f"  {name}: {len(hits)} hit(s), e.g. {hits[0][:200]}")

    if flag_hits:
        print(f"\nFLAG MATCHES in log lines: {sorted(set(flag_hits))}")


def triage_auth_log(lines: list[str], flag_pattern: re.Pattern) -> None:
    fails: defaultdict = defaultdict(int)
    flag_hits: list[str] = []

    for line in lines:
        m = SSH_FAILED_RE.search(line)
        if m:
            fails[m.group("ip")] += 1
        flags = flag_pattern.findall(line)
        if flags:
            flag_hits.extend(flags)

    print("failed SSH logins by source IP (possible brute force):")
    for ip, count in sorted(fails.items(), key=lambda kv: -kv[1]):
        marker = "  <-- likely brute force" if count > 10 else ""
        print(f"  {ip}: {count} failure(s){marker}")

    if flag_hits:
        print(f"\nFLAG MATCHES in log lines: {sorted(set(flag_hits))}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("log_path")
    ap.add_argument("--format", choices=["access", "auth"], default="access")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex")
    args = ap.parse_args()

    lines = Path(args.log_path).read_text(errors="replace").splitlines()
    pattern = re.compile(args.pattern)

    if args.format == "access":
        triage_access_log(lines, pattern)
    else:
        triage_auth_log(lines, pattern)


if __name__ == "__main__":
    main()
