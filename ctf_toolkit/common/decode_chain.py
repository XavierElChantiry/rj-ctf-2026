"""Auto-decode a mystery string through common CTF encodings and show every
readable result, so you don't have to guess "is this base64 or hex or...".

Tries, on the original string and then recursively on each successful
decode (depth-limited): base64, base32, hex, binary (0/1), URL-decoding,
ROT13, gzip/zlib. Prints anything that comes out printable, flagging
anything that also matches a flag pattern.

Usage:
    python -m ctf_toolkit.common.decode_chain 'TWV0YUNURns...'
    echo 'some string' | python -m ctf_toolkit.common.decode_chain -
"""
from __future__ import annotations

import argparse
import base64
import codecs
import re
import sys
import zlib

from ctf_toolkit.common.flagscan import DEFAULT_PATTERN

MAX_DEPTH = 4


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    return printable / len(s)


def _try(name: str, fn, data: str) -> str | None:
    try:
        out = fn(data)
    except Exception:
        return None
    if isinstance(out, bytes):
        try:
            out = out.decode("utf-8")
        except UnicodeDecodeError:
            out = out.decode("latin1")
    if out and out != data and _printable_ratio(out) > 0.85:
        return out
    return None


def _decode_binary(s: str) -> bytes:
    bits = re.sub(r"\s", "", s)
    if not bits or any(c not in "01" for c in bits) or len(bits) % 8:
        raise ValueError("not clean 8-bit-aligned binary")
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def _decode_url(s: str) -> str:
    from urllib.parse import unquote

    return unquote(s)


DECODERS = {
    "base64": lambda s: base64.b64decode(s.strip() + "=" * (-len(s.strip()) % 4)),
    "base32": lambda s: base64.b32decode(s.strip().upper() + "=" * (-len(s.strip()) % 8)),
    "hex": lambda s: bytes.fromhex(re.sub(r"\s|0x", "", s)),
    "binary": _decode_binary,
    "url": _decode_url,
    "rot13": lambda s: codecs.encode(s, "rot_13"),
    "gzip": lambda s: zlib.decompress(bytes.fromhex(s), zlib.MAX_WBITS | 16),
    "zlib": lambda s: zlib.decompress(bytes.fromhex(s)),
}


def decode_all(data: str, pattern: re.Pattern, depth: int = 0, seen: set[str] | None = None) -> None:
    if seen is None:
        seen = set()
    if depth > MAX_DEPTH or data in seen:
        return
    seen.add(data)

    for name, fn in DECODERS.items():
        result = _try(name, fn, data)
        if result is None:
            continue
        flags = pattern.findall(result)
        marker = f"  <-- FLAG: {flags}" if flags else ""
        print(f"[depth {depth}] {name}: {result!r}{marker}")
        decode_all(result, pattern, depth + 1, seen)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("data", help="string to decode, or '-' to read stdin")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex to highlight")
    args = ap.parse_args()

    data = sys.stdin.read().strip() if args.data == "-" else args.data
    pattern = re.compile(args.pattern)

    direct = pattern.findall(data)
    if direct:
        print(f"input already contains a flag match: {direct}")

    decode_all(data, pattern)


if __name__ == "__main__":
    main()
