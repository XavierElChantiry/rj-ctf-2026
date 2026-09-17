"""Self-check runner: verify your own services are still up/behaving after
you patch them.

Most A/D scoring docks SLA points for a service that's down or answering
wrong, independent of whether it got exploited — so run this right after
every patch deploy, and on a timer throughout the event, rather than
trusting "it compiled" that the checker bot will still be happy.

Usage:
    python -m ctf_ad.defense.healthcheck --config ctf_ad/config.yaml           # loop forever
    python -m ctf_ad.defense.healthcheck --config ctf_ad/config.yaml --once    # single pass, exit 1 on any failure
"""
from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from pathlib import Path
from typing import Any

import requests
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

log = logging.getLogger("ctf_ad.defense.health")


def check_http(check: dict[str, Any], timeout: float) -> tuple[bool, str]:
    try:
        resp = requests.get(check["url"], timeout=timeout)
    except requests.RequestException as exc:
        return False, f"request failed: {exc}"
    expect = check.get("expect_status", 200)
    if resp.status_code != expect:
        return False, f"status {resp.status_code}, expected {expect}"
    expect_text = check.get("expect_text")
    if expect_text and expect_text not in resp.text:
        return False, f"missing expected text {expect_text!r}"
    return True, "ok"


def check_tcp(check: dict[str, Any], timeout: float) -> tuple[bool, str]:
    try:
        with socket.create_connection((check["host"], check["port"]), timeout=timeout):
            return True, "ok"
    except OSError as exc:
        return False, f"connect failed: {exc}"


CHECKERS = {"http": check_http, "tcp": check_tcp}


def run_checks(checks: list[dict[str, Any]], timeout: float) -> bool:
    all_ok = True
    for check in checks:
        checker = CHECKERS.get(check["type"])
        if checker is None:
            log.error("unknown check type %r for %s", check["type"], check.get("name"))
            all_ok = False
            continue
        ok, detail = checker(check, timeout)
        (log.info if ok else log.error)("[%s] %s: %s", check.get("name", "?"), "OK" if ok else "FAIL", detail)
        all_ok = all_ok and ok
    return all_ok


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ctf_ad/config.yaml")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    dcfg = cfg["defense"]
    hcfg = dcfg["healthcheck"]

    logging.basicConfig(
        level=getattr(logging, dcfg["logging"].get("level", "INFO")),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(dcfg["logging"]["path"]),
            logging.StreamHandler(),
        ],
    )

    timeout = hcfg.get("timeout_seconds", 5)
    interval = hcfg.get("interval_seconds", 30)

    while True:
        ok = run_checks(hcfg["checks"], timeout)
        if args.once:
            sys.exit(0 if ok else 1)
        time.sleep(interval)


if __name__ == "__main__":
    main()
