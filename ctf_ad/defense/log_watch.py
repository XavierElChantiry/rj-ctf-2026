"""Tail service logs and alert on suspicious request patterns.

Cheap, dependency-free intrusion-detection-lite: catches common exploit
attempts (path traversal, SQLi, XSS) hitting your services, plus anything
matching your own flag regex leaking through request params (a sign either
of an attacker probing with a stolen flag, or a bug leaking flags into logs).

Usage:
    python -m ctf_ad.defense.log_watch --config ctf_ad/config.yaml
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("ctf_ad.defense.logwatch")

DEFAULT_PATTERNS = [
    r"\.\./",              # path traversal
    r"UNION\s+SELECT",     # sqli
    r"<script",            # xss
    r";\s*(cat|wget|curl|nc|bash|sh)\s",  # command injection
    r"\bexec\s*\(",
]


def tail(path: Path):
    """Yield new lines appended to `path`, like `tail -f`."""
    with path.open("r", errors="ignore") as f:
        f.seek(0, 2)  # start at end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def watch_file(path: Path, patterns: list[re.Pattern]) -> None:
    log.info("watching %s", path)
    for line in tail(path):
        for pat in patterns:
            if pat.search(line):
                log.warning("[%s] matched /%s/: %s", path.name, pat.pattern, line[:300])
                break


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ctf_ad/config.yaml")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    dcfg = cfg["defense"]
    lcfg = dcfg["log_watch"]

    logging.basicConfig(
        level=getattr(logging, dcfg["logging"].get("level", "INFO")),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(dcfg["logging"]["path"]),
            logging.StreamHandler(),
        ],
    )

    pattern_strs = DEFAULT_PATTERNS + lcfg.get("extra_patterns", []) + [cfg["flag_regex"]]
    patterns = [re.compile(p, re.IGNORECASE) for p in pattern_strs]

    paths = [Path(p) for p in lcfg.get("paths", [])]
    missing = [p for p in paths if not p.exists()]
    for p in missing:
        log.error("log path does not exist, skipping: %s", p)
    paths = [p for p in paths if p.exists()]
    if not paths:
        log.error("no valid log paths configured under defense.log_watch.paths")
        return

    if len(paths) == 1:
        watch_file(paths[0], patterns)
        return

    # multiple files: one thread per file
    import threading

    threads = [
        threading.Thread(target=watch_file, args=(p, patterns), daemon=True) for p in paths
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
