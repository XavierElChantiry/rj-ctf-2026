"""Flag extraction + dedupe helpers shared by attack and defense tooling."""
from __future__ import annotations

import json
import re
import threading
from pathlib import Path


def compile_flag_regex(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def extract_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Return unique flag matches from `text`, preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for m in pattern.findall(text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


class FlagStore:
    """Thread-safe, JSON-file-backed set of flags already captured/submitted.

    Persisting to disk means a crashed/restarted runner won't re-submit flags
    it already turned in, and won't waste round time re-processing them.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        if self._path.exists():
            try:
                self._seen = set(json.loads(self._path.read_text()))
            except (json.JSONDecodeError, OSError):
                self._seen = set()

    def is_new(self, flag: str) -> bool:
        with self._lock:
            return flag not in self._seen

    def mark_seen(self, flag: str) -> None:
        with self._lock:
            if flag in self._seen:
                return
            self._seen.add(flag)
            self._path.write_text(json.dumps(sorted(self._seen)))
