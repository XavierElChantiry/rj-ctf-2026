"""Pluggable flag-submission backends.

Swap backends purely via config.yaml `attack.submission.backend` — nothing
in the runner needs to change once the real scoreboard API is announced.
"""
from __future__ import annotations

import logging
import socket
import threading
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


class TcpLineSubmitter(Submitter):
    """Plaintext line-protocol submitter used by ctf-gameserver-based events
    (FAUST CTF and other ructf/saarctf-family attack-defense CTFs).

    Protocol (https://ctf-gameserver.org/submission/): connect, skip the
    server's welcome banner if any (terminated by a blank line), then for
    each flag send `<flag>\\n` and read one reply line back, formatted
    `<flag> <CODE> [message]`. CODEs: OK (accepted), DUP (already submitted
    by us), OWN (our own flag), OLD (expired), INV (bad format) — all
    terminal, not errors to retry. ERR means the server had a problem and
    may close the connection; that one gets one reconnect-and-retry.

    Reuses one connection across submissions in a round (the protocol
    explicitly allows pipelining), reconnecting lazily on any socket error.

    NOTE: written from the protocol spec, not yet exercised against a real
    gameserver (submission hosts are only reachable from inside the
    competition network/VPN) — sanity-check the banner-skip against the
    real welcome banner the first chance you get once VPN access exists.
    """

    def __init__(self, cfg: dict[str, Any]):
        self._host = cfg["host"]
        self._port = cfg.get("port", 666)
        self._timeout = cfg.get("timeout_seconds", 10)
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._buf = b""

    def _readline(self) -> bytes:
        while b"\n" not in self._buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("submission server closed the connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    def _connect(self) -> None:
        self._sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        self._sock.settimeout(self._timeout)
        self._buf = b""
        # Skip an optional banner, terminated by a blank line. If the server
        # sends flag replies immediately instead (no banner), this would eat
        # the first one — but a bare submit right after connect is unusual
        # enough for this protocol family that banner-skipping first is the
        # safer default; flip if the real server proves otherwise.
        try:
            while self._readline().strip():
                pass
        except (ConnectionError, socket.timeout):
            pass

    def submit(self, flag: str) -> bool:
        with self._lock:
            for attempt in (1, 2):
                try:
                    if self._sock is None:
                        self._connect()
                    self._sock.sendall(flag.encode() + b"\n")
                    reply = self._readline().decode(errors="replace").strip()
                except (OSError, ConnectionError) as exc:
                    log.warning("submission connection dropped (attempt %d): %s", attempt, exc)
                    self._sock = None
                    continue

                parts = reply.split(None, 2)
                code = parts[1] if len(parts) >= 2 else ""
                if code == "OK":
                    log.info("flag accepted: %s", flag)
                    return True
                if code == "ERR":
                    log.warning("submission server error for %s: %s -- retrying", flag, reply)
                    self._sock = None
                    continue
                # DUP/OWN/OLD/INV: terminal rejections, not worth retrying.
                log.info("flag rejected (%s): %s", code or reply, flag)
                return False
        return False


def build_submitter(cfg: dict[str, Any]) -> Submitter:
    backend = cfg.get("backend", "null")
    if backend == "http":
        return HttpSubmitter(cfg["http"])
    if backend == "file":
        return FileSubmitter(cfg["file"]["path"])
    if backend == "tcp":
        return TcpLineSubmitter(cfg["tcp"])
    return NullSubmitter()
