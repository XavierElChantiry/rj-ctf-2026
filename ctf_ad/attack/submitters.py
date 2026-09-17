"""Pluggable flag-submission backends.

Swap backends purely via config.yaml `attack.submission.backend` — nothing
in the runner needs to change once the real scoreboard API is announced.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger("ctf_ad.submit")


class Submitter:
    def submit(self, flag: str) -> bool:
        """Return True if the flag was accepted (or at least not rejected)."""
        raise NotImplementedError


class NullSubmitter(Submitter):
    """Dry-run backend: just logs. Use while the scoreboard endpoint is TBD."""

    def submit(self, flag: str) -> bool:
        log.info("DRY RUN would submit flag: %s", flag)
        return True


class FileSubmitter(Submitter):
    """Appends captured flags to a file for manual copy/paste into a web form."""

    def __init__(self, path: str | Path):
        self._path = Path(path)

    def submit(self, flag: str) -> bool:
        with self._path.open("a") as f:
            f.write(flag + "\n")
        return True


class HttpSubmitter(Submitter):
    """Generic HTTP flag submitter for a scoreboard REST API.

    Configured entirely from config.yaml — url/method/field name/headers —
    so pointing this at the real endpoint on game day is a config edit, not
    a code change. Retries transient failures with backoff; treats HTTP 4xx
    (bad/duplicate/expired flag) as a final non-retryable rejection.
    """

    def __init__(self, cfg: dict[str, Any]):
        self._url = cfg["url"]
        self._method = cfg.get("method", "POST").upper()
        self._flag_field = cfg.get("flag_field", "flag")
        self._headers = cfg.get("headers", {})
        self._timeout = cfg.get("timeout_seconds", 5)
        self._max_retries = cfg.get("max_retries", 3)

    def submit(self, flag: str) -> bool:
        payload = {self._flag_field: flag}
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = requests.request(
                    self._method,
                    self._url,
                    json=payload,
                    headers=self._headers,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                log.warning("submit attempt %d failed for %s: %s", attempt, flag, exc)
                time.sleep(min(2**attempt, 10))
                continue

            if resp.status_code < 300:
                log.info("flag accepted: %s", flag)
                return True
            if 400 <= resp.status_code < 500:
                log.info(
                    "flag rejected (%d): %s -- %s", resp.status_code, flag, resp.text[:200]
                )
                return False
            log.warning(
                "submit attempt %d got %d for %s, retrying", attempt, resp.status_code, flag
            )
            time.sleep(min(2**attempt, 10))
        return False


def build_submitter(cfg: dict[str, Any]) -> Submitter:
    backend = cfg.get("backend", "null")
    if backend == "http":
        return HttpSubmitter(cfg["http"])
    if backend == "file":
        return FileSubmitter(cfg["file"]["path"])
    return NullSubmitter()
