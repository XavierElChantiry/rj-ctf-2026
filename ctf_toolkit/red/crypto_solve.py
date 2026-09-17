"""Classical-cipher helpers for crypto challenges: Caesar/ROT brute force,
single-byte and known-plaintext XOR, and Vigenere key recovery.

Usage:
    python -m ctf_toolkit.red.crypto_solve caesar 'Wkh IODJ lv khuh'
    python -m ctf_toolkit.red.crypto_solve xor-brute <hexciphertext>
    python -m ctf_toolkit.red.crypto_solve xor-crib <hexciphertext> --known 'MetaCTF{'
    python -m ctf_toolkit.red.crypto_solve vigenere <ciphertext> --max-key-len 20
"""
from __future__ import annotations

import argparse
import re
import string
from collections import Counter

from ctf_toolkit.common.flagscan import DEFAULT_PATTERN

# Standard English letter frequencies (%), used to score decode candidates.
ENGLISH_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2, "g": 2.0,
    "h": 6.1, "i": 7.0, "j": 0.2, "k": 0.8, "l": 4.0, "m": 2.4, "n": 6.7,
    "o": 7.5, "p": 1.9, "q": 0.1, "r": 6.0, "s": 6.3, "t": 9.1, "u": 2.8,
    "v": 1.0, "w": 2.4, "x": 0.2, "y": 2.0, "z": 0.1,
}


def chi_squared_english(text: str) -> float:
    """Lower = more English-like."""
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return float("inf")
    counts = Counter(letters)
    n = len(letters)
    score = 0.0
    for letter, expected_pct in ENGLISH_FREQ.items():
        expected = expected_pct / 100 * n
        observed = counts.get(letter, 0)
        score += (observed - expected) ** 2 / expected
    return score


def caesar_shift(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.isupper():
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower():
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


def caesar_bruteforce(ciphertext: str) -> list[tuple[int, str, float]]:
    """Return all 26 shifts, best guess (lowest chi^2) first."""
    results = [(s, caesar_shift(ciphertext, s)) for s in range(26)]
    scored = [(s, text, chi_squared_english(text)) for s, text in results]
    return sorted(scored, key=lambda t: t[2])


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_single_byte_bruteforce(data: bytes) -> list[tuple[int, bytes, float]]:
    results = []
    for key in range(256):
        out = xor_bytes(data, bytes([key]))
        try:
            text = out.decode("ascii")
        except UnicodeDecodeError:
            continue
        results.append((key, out, chi_squared_english(text)))
    return sorted(results, key=lambda t: t[2])


def xor_crib(data: bytes, known_plaintext: bytes) -> bytes:
    """Derive the repeating-XOR key assuming `known_plaintext` is a prefix of
    the plaintext (e.g. the flag format itself, like 'MetaCTF{')."""
    return xor_bytes(data[: len(known_plaintext)], known_plaintext)


def index_of_coincidence(text: str) -> float:
    letters = [c.lower() for c in text if c.isalpha()]
    n = len(letters)
    if n < 2:
        return 0.0
    counts = Counter(letters)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def guess_vigenere_key_length(ciphertext: str, max_key_len: int) -> list[tuple[int, float]]:
    """Score candidate key lengths by average index of coincidence of their
    columns — English text columns have IC near ~0.067; random ~0.038."""
    letters = [c for c in ciphertext if c.isalpha()]
    scores = []
    for klen in range(1, max_key_len + 1):
        columns = ["".join(letters[i::klen]) for i in range(klen)]
        avg_ic = sum(index_of_coincidence(col) for col in columns) / klen
        scores.append((klen, avg_ic))
    return sorted(scores, key=lambda t: abs(t[1] - 0.067))


def vigenere_crack(ciphertext: str, max_key_len: int = 20) -> tuple[str, str]:
    """Best-effort Vigenere break: guess key length via index of coincidence,
    then break each column as a Caesar shift. Works well on longer English
    ciphertext; short/non-English text may need `caesar_bruteforce` per
    column manually instead."""
    best_klen = guess_vigenere_key_length(ciphertext, max_key_len)[0][0]
    letters = [c for c in ciphertext if c.isalpha()]
    columns = ["".join(letters[i::best_klen]) for i in range(best_klen)]

    key_chars = []
    for col in columns:
        best_shift = min(range(26), key=lambda s: chi_squared_english(caesar_shift(col, s)))
        # a column shifted by `s` to decode means the key letter is `-s` from 'a'
        key_chars.append(chr((26 - best_shift) % 26 + 97))
    key = "".join(key_chars)

    decoded = []
    ki = 0
    for c in ciphertext:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 97
            decoded.append(caesar_shift(c, -shift))
            ki += 1
        else:
            decoded.append(c)
    return key, "".join(decoded)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex to highlight")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("caesar")
    p.add_argument("ciphertext")
    p.add_argument("--top", type=int, default=5)

    p = sub.add_parser("xor-brute")
    p.add_argument("hex_ciphertext")
    p.add_argument("--top", type=int, default=5)

    p = sub.add_parser("xor-crib")
    p.add_argument("hex_ciphertext")
    p.add_argument("--known", required=True, help="known plaintext prefix, e.g. 'MetaCTF{'")

    p = sub.add_parser("vigenere")
    p.add_argument("ciphertext")
    p.add_argument("--max-key-len", type=int, default=20)

    args = ap.parse_args()
    pattern = re.compile(args.pattern)

    if args.cmd == "caesar":
        for shift, text, score in caesar_bruteforce(args.ciphertext)[: args.top]:
            marker = "  <-- FLAG" if pattern.search(text) else ""
            print(f"shift={shift:2d} score={score:8.1f}: {text}{marker}")

    elif args.cmd == "xor-brute":
        data = bytes.fromhex(args.hex_ciphertext)
        results = xor_single_byte_bruteforce(data)
        # Letter-frequency scoring is unreliable on short ciphertext (a flag's
        # `{`, `}`, `_` aren't counted at all) — a direct flag-pattern match
        # is a far stronger signal, so surface those first regardless of score.
        flagged = [r for r in results if pattern.search(r[1].decode("ascii", errors="replace"))]
        rest = [r for r in results if r not in flagged]
        for key, out, score in (flagged + rest)[: args.top]:
            text = out.decode("ascii", errors="replace")
            marker = "  <-- FLAG" if pattern.search(text) else ""
            print(f"key=0x{key:02x} score={score:8.1f}: {text}{marker}")

    elif args.cmd == "xor-crib":
        data = bytes.fromhex(args.hex_ciphertext)
        key = xor_crib(data, args.known.encode())
        print(f"derived key bytes: {key!r} (hex: {key.hex()})")
        print("if this key repeats cleanly, XOR the whole ciphertext with it")

    elif args.cmd == "vigenere":
        key, plaintext = vigenere_crack(args.ciphertext, args.max_key_len)
        marker = "  <-- FLAG" if pattern.search(plaintext) else ""
        print(f"guessed key: {key}")
        print(f"decoded: {plaintext}{marker}")


if __name__ == "__main__":
    main()
