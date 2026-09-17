"""Flag-ID cache for ctf-gameserver-based attack-defense events (FAUST CTF
and other events built on https://github.com/fausecteam/ctf-gameserver).

In these events a flag isn't just a string sitting in cleartext traffic —
the checker stores one *flag ID* per (service, team, round) that names
which stored flag to retrieve (like a username/row ID). Your exploit has
to look up the current ID(s) for its target team+service, then use the
service's own functionality to fetch the flag that ID points at. IDs are
published each round in a JSON document the gameserver serves publicly:

    {"teams": [123, 456], "flag_ids": {"service1": {"123": ["abc", "def"]}}}

See https://ctf-gameserver.org/round-progress/ and the event's own docs
(for FAUST CTF: https://2026.faustctf.net/competition/teams.json) for the
authoritative format — this cache is a thin, defensive fetch-and-index
wrapper around it, not a spec implementation.
"""
from __future__ import annotations

import logging
import threading
import time

import requests

log = logging.getLogger("ctf_ad.flagids")


class FlagIdCache:
    """Polls a teams.json-style URL and indexes flag IDs by (service, team).

    Never raises on a failed refresh — a transient network blip or the
    gameserver being slow mid-round must not crash the attack loop; it just
    keeps serving the last known-good set until the next successful refresh.
    """

    def __init__(self, url: str, refresh_seconds: float = 60.0, timeout: float = 10.0):
        self._url = url
        self._refresh_seconds = refresh_seconds
        self._timeout = timeout
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, list[str]]] = {}
        self._last_refresh = 0.0
        self._last_error: str | None = None

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and (time.monotonic() - self._last_refresh) < self._refresh_seconds:
                return
        try:
            resp = requests.get(self._url, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json().get("flag_ids", {})
        except (requests.RequestException, ValueError) as exc:
            with self._lock:
                self._last_error = str(exc)
            log.warning("flag-id refresh failed (%s), keeping last known set", exc)
            return
        with self._lock:
            self._data = data
            self._last_refresh = time.monotonic()
            self._last_error = None

    def get(self, service: str, team: str) -> list[str]:
        """Current flag IDs for `service` owned by `team`, or [] if unknown."""
        with self._lock:
            return list(self._data.get(service, {}).get(str(team), []))

    def is_stale(self) -> bool:
        with self._lock:
            return self._last_refresh == 0.0
