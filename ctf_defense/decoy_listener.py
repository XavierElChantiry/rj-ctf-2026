#!/usr/bin/env python3
"""Decoy/honeypot listener for the box-defense round. stdlib only.

Two modes, run one port at a time (start another instance for another port):

  http    a fake login page on a fixed set of commonly-probed paths (200 +
          `X-Decoy: rj-ctf` header), 404 on everything else. Never reflects
          request input, so it can't be turned into a vector against anyone.
  banner  sends one fixed line on connect (ssh/ftp/smtp/telnet presets, or
          custom text), reads up to 512 bytes of whatever the client sends,
          logs it, and closes. Doesn't speak the real protocol past that.

Every event is one JSON line appended to --log. Refuses to start if the
port is already bound to something real — a honeypot squatting on a scored
service's port is worse than no honeypot at all.

Not a defense. It only observes; it never blocks anything. Don't treat a
hit as attribution — it's a source address, nothing more.
"""
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MAX_LOG_BYTES = 4 * 1024 * 1024  # stop appending past this, don't let a scan fill the disk
MAX_FIELD_LEN = 200
RECV_CAP = 512
SOCK_TIMEOUT = 10

DECOY_PATHS = {"/admin", "/.env", "/wp-login.php", "/phpmyadmin", "/login", "/.git/HEAD"}

BANNERS = {
    "ssh": "SSH-2.0-OpenSSH_8.9\r\n",
    "ftp": "220 (vsFTPd 3.0.5)\r\n",
    "smtp": "220 mail.local ESMTP Postfix\r\n",
    "telnet": "Welcome to Ubuntu 22.04 LTS\r\nlogin: ",
}

FAKE_LOGIN_PAGE = (
    "<!doctype html><html><head><title>Sign in</title></head>"
    "<body><h2>Sign in</h2><form method=post>"
    "<input name=username placeholder=Username><br>"
    "<input name=password type=password placeholder=Password><br>"
    "<button>Sign in</button></form></body></html>"
)

_log_lock = threading.Lock()
_log_path: Path | None = None
_log_capped = False


def _trunc(s: str, n: int = MAX_FIELD_LEN) -> str:
    return s if len(s) <= n else s[:n] + "...(truncated)"


def log_event(**fields) -> None:
    global _log_capped
    fields.setdefault("at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    fields["decoy"] = True
    line = json.dumps({k: (_trunc(v) if isinstance(v, str) else v) for k, v in fields.items()})
    with _log_lock:
        if _log_capped:
            return
        try:
            if _log_path.exists() and _log_path.stat().st_size >= MAX_LOG_BYTES:
                _log_capped = True
                print(f"[decoy] log cap ({MAX_LOG_BYTES} bytes) reached, no longer logging new hits", file=sys.stderr)
                return
            with open(_log_path, "a") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"[decoy] failed to write log: {e}", file=sys.stderr)
    print(line)


class LureHandler(BaseHTTPRequestHandler):
    timeout = SOCK_TIMEOUT
    server_version = "Apache/2.4.41"  # blend in, don't advertise itself

    def version_string(self) -> str:
        # BaseHTTPRequestHandler appends sys_version (e.g. "Python/3.x") by
        # default, which would out this as a Python decoy on the first probe.
        return self.server_version

    def _respond(self, code: int) -> None:
        body = FAKE_LOGIN_PAGE.encode() if code == 200 else b"Not Found"
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Decoy", "rj-ctf")
        self.end_headers()
        self.wfile.write(body)

    def _handle(self) -> None:
        path = self.path.split("?", 1)[0]
        hit = path in DECOY_PATHS
        log_event(
            event="decoy-http",
            method=self.command,
            path=path,
            status=200 if hit else 404,
            client=self.client_address[0],
            user_agent=self.headers.get("User-Agent", ""),
        )
        self._respond(200 if hit else 404)

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle

    def log_message(self, fmt, *args) -> None:  # silence default stderr access log
        pass


def run_http(port: int) -> None:
    httpd = HTTPServer(("0.0.0.0", port), LureHandler)  # binding here is the "port free?" test
    print(f"[decoy] http lure listening on :{port} (paths: {', '.join(sorted(DECOY_PATHS))})")
    httpd.serve_forever()


def run_banner(port: int, banner: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))  # raises OSError (address in use) if something real is already there
    srv.listen(8)
    print(f"[decoy] banner listener on :{port}")

    sem = threading.Semaphore(8)  # bound concurrent connections, never let a scan exhaust threads

    def handle(conn: socket.socket, addr: tuple) -> None:
        try:
            conn.settimeout(SOCK_TIMEOUT)
            conn.sendall(banner.encode(errors="replace"))
            try:
                data = conn.recv(RECV_CAP)
            except socket.timeout:
                data = b""
            log_event(
                event="decoy-banner",
                client=addr[0],
                preview=data.decode(errors="replace"),
            )
        except OSError:
            pass
        finally:
            conn.close()
            sem.release()

    while True:
        conn, addr = srv.accept()
        if not sem.acquire(blocking=False):
            conn.close()  # already at the concurrency cap, drop it rather than queue forever
            continue
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--mode", choices=["http", "banner"], required=True)
    ap.add_argument("--banner", default="ssh", help="preset (ssh/ftp/smtp/telnet) or literal text for --mode banner")
    ap.add_argument("--log", required=True, help="path to append JSON-lines events to")
    args = ap.parse_args()

    global _log_path
    _log_path = Path(args.log)
    _log_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if args.mode == "http":
            run_http(args.port)
        else:
            run_banner(args.port, BANNERS.get(args.banner, args.banner))
    except OSError as e:
        print(f"[decoy] refusing to start: port {args.port} unavailable ({e})", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
