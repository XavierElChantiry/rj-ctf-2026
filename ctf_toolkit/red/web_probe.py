"""Quick read-only recon pass against a web challenge target: headers,
robots.txt, common backup/config/VCS leaks, and verbose-error probing.

This only sends GET requests to paths you'd check by hand anyway — it does
not exploit anything. Point it at a challenge's own URL, not at anything you
don't have authorization to test.

Usage:
    python -m ctf_toolkit.red.web_probe http://challenge.host:8080
"""
from __future__ import annotations

import argparse

import requests

COMMON_PATHS = [
    "robots.txt",
    "sitemap.xml",
    ".git/HEAD",
    ".env",
    ".htaccess",
    "backup.zip",
    "backup.sql",
    "config.php.bak",
    "web.config",
    "server-status",
    "admin/",
    "login",
    "api/",
    "swagger.json",
    "swagger-ui.html",
    ".well-known/security.txt",
]

# Sent as a query value to see if the app leaks a stack trace / DB error —
# purely observational, no attempt to actually inject or exfiltrate data.
ERROR_PROBES = ["'", '"', "1' OR '1'='1", "{{7*7}}", "../../../../etc/passwd"]


def check_headers(base_url: str, timeout: float) -> None:
    resp = requests.get(base_url, timeout=timeout)
    print(f"GET {base_url} -> {resp.status_code}")
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "Via", "Content-Security-Policy"):
        if header in resp.headers:
            print(f"  {header}: {resp.headers[header]}")


def check_common_paths(base_url: str, timeout: float) -> None:
    print("\ncommon paths:")
    for path in COMMON_PATHS:
        url = base_url.rstrip("/") + "/" + path
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException as exc:
            print(f"  {path}: error ({exc})")
            continue
        if resp.status_code < 400:
            print(f"  {path}: {resp.status_code} (len={len(resp.content)})")


def check_error_probes(base_url: str, timeout: float) -> None:
    print("\nerror-page probes (?q=<probe>):")
    for probe in ERROR_PROBES:
        try:
            resp = requests.get(base_url, params={"q": probe}, timeout=timeout)
        except requests.RequestException as exc:
            print(f"  {probe!r}: error ({exc})")
            continue
        leaky_markers = ("Traceback", "stack trace", "SQL syntax", "ORA-", "Warning:", "Exception")
        hit = [m for m in leaky_markers if m.lower() in resp.text.lower()]
        if hit:
            print(f"  {probe!r}: possible leak, matched {hit} (status {resp.status_code})")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url")
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()

    check_headers(args.url, args.timeout)
    check_common_paths(args.url, args.timeout)
    check_error_probes(args.url, args.timeout)


if __name__ == "__main__":
    main()
