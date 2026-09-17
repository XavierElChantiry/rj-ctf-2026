"""Recursively hunt a challenge's downloaded files for a flag.

Jeopardy CTF flags are often sitting in plain sight after one layer of
transformation (a file inside a zip, a base64 blob in a text file, a string
buried in a binary). This walks a directory (or single file), auto-expands
common archives, extracts printable strings from binaries, and regex-scans
everything — including a base64/hex decode pass — for the flag format.

Usage:
    python -m ctf_toolkit.common.flagscan ./challenge_files
    python -m ctf_toolkit.common.flagscan ./challenge_files --pattern 'RJ\\{.*?\\}'
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Generic default: catches MetaCTF{...}, SkillBit{...}, flag{...}, RJ{...},
# or any other `word{...}` house style without knowing the exact prefix.
DEFAULT_PATTERN = r"[A-Za-z0-9_]{2,20}\{[^\{\}\s]{3,200}\}"

STRINGS_MIN_LEN = 5
_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % STRINGS_MIN_LEN)


def extract_strings(data: bytes) -> list[str]:
    return [m.decode("ascii") for m in _PRINTABLE.findall(data)]


def try_base64_blobs(text: str) -> list[str]:
    """Find base64-looking substrings and decode them, in case the flag is
    one layer of base64 away from being visible."""
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            out.append(decoded.decode("utf-8"))
        except UnicodeDecodeError:
            out.append(decoded.decode("latin1"))
    return out


def try_hex_blobs(text: str) -> list[str]:
    out = []
    for m in re.finditer(r"(?:[0-9a-fA-F]{2}){8,}", text):
        candidate = m.group(0)
        try:
            decoded = bytes.fromhex(candidate)
        except ValueError:
            continue
        try:
            out.append(decoded.decode("utf-8"))
        except UnicodeDecodeError:
            out.append(decoded.decode("latin1"))
    return out


def scan_text(text: str, pattern: re.Pattern) -> set[str]:
    hits = set(pattern.findall(text))
    for derived in try_base64_blobs(text) + try_hex_blobs(text):
        hits |= set(pattern.findall(derived))
    return hits


def iter_expanded_files(root: Path, work_dir: Path):
    """Yield every file under root, expanding zip/tar archives into work_dir
    (recursively, one level of nesting is usually enough for CTF challenges)."""
    for path in root.rglob("*") if root.is_dir() else [root]:
        if not path.is_file():
            continue
        yield path
        try:
            if zipfile.is_zipfile(path):
                dest = work_dir / (path.name + "_extracted")
                dest.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(path) as zf:
                    zf.extractall(dest)
                yield from iter_expanded_files(dest, work_dir)
            elif tarfile.is_tarfile(path):
                dest = work_dir / (path.name + "_extracted")
                dest.mkdir(parents=True, exist_ok=True)
                with tarfile.open(path) as tf:
                    tf.extractall(dest)
                yield from iter_expanded_files(dest, work_dir)
        except (zipfile.BadZipFile, tarfile.TarError, OSError):
            pass


def scan_path(root: Path, pattern: re.Pattern) -> dict[str, set[str]]:
    results: dict[str, set[str]] = {}
    with tempfile.TemporaryDirectory(prefix="flagscan_") as tmp:
        for path in iter_expanded_files(root, Path(tmp)):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            text = "\n".join(extract_strings(data))
            hits = scan_text(text, pattern)
            if hits:
                results[str(path)] = hits
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="file or directory to scan")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex")
    args = ap.parse_args()

    pattern = re.compile(args.pattern)
    results = scan_path(Path(args.path), pattern)

    if not results:
        print("no flag-shaped strings found")
        return
    for path, flags in results.items():
        for flag in flags:
            print(f"{path}: {flag}")


if __name__ == "__main__":
    main()
