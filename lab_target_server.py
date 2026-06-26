#!/usr/bin/env python3
"""
lab_target_server.py

Safe local test server for a red-team / cyber-RAG agent.

Features:
- HTTP test target on port 8080
- Fake service banners on high ports:
    2222  -> fake SSH banner
    33060 -> fake MySQL banner
    6380  -> fake Redis banner
- Realistic but harmless endpoints:
    /
    /health
    /robots.txt
    /admin
    /login
    /api/v1/status
    /api/v1/users
    /api/v1/vulns
    /backup/config.bak
    /debug/env
    /echo?value=test
    /slow
    /large

Run:
    python lab_target_server.py

Then test:
    http://127.0.0.1:8080
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import signal
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


LOG_FILE = Path("lab_server_access.log")
STOP_EVENT = threading.Event()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ],
)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_bytes(data: dict, status: str = "ok") -> bytes:
    data.setdefault("status", status)
    data.setdefault("timestamp_utc", now_iso())
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


class LabHTTPHandler(BaseHTTPRequestHandler):
    server_version = "MedFlow-LabHTTP/0.9"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        logging.info(
            "%s - %s %s",
            self.client_address[0],
            self.command,
            fmt % args,
        )

    def _send(
        self,
        status_code: int,
        body: bytes,
        content_type: str = "text/plain; charset=utf-8",
        extra_headers: dict | None = None,
    ) -> None:
        self.send_response(status_code)

        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Lab-Target", "true")
        self.send_header("X-Application", "MedFlow Training Portal")
        self.send_header("X-Mock-Environment", "lab")

        # Intentionally not setting some common hardening headers, so scanners
        # can report simulated weaknesses:
        # - Strict-Transport-Security
        # - Content-Security-Policy
        # - X-Frame-Options

        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)

        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status_code: int, data: dict) -> None:
        self._send(
            status_code,
            json_bytes(data),
            content_type="application/json; charset=utf-8",
        )

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return ""
        raw = self.rfile.read(min(length, 1_000_000))
        return raw.decode("utf-8", errors="replace")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self.index()

        elif path == "/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "service": "medflow-lab-target",
                    "healthy": True,
                    "purpose": "safe local agent testing",
                },
            )

        elif path == "/robots.txt":
            body = """User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /debug
Allow: /
"""
            self._send(HTTPStatus.OK, body.encode(), "text/plain; charset=utf-8")

        elif path == "/admin":
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {
                    "message": "Admin area exists but access is denied.",
                    "simulated_finding": "interesting_admin_path",
                },
            )

        elif path == "/login":
            self.login_page()

        elif path == "/api/v1/status":
            self._send_json(
                HTTPStatus.OK,
                {
                    "application": "MedFlow Training Portal",
                    "environment": "lab",
                    "version": "0.9.0",
                    "components": {
                        "web": "MedFlow-LabHTTP/0.9",
                        "database": "MockDB 1.2.3",
                        "cache": "MockRedis 2.8",
                    },
                    "simulated_findings": [
                        "outdated_component_banner",
                        "missing_security_headers",
                        "verbose_version_disclosure",
                    ],
                },
            )

        elif path == "/api/v1/users":
            self._send_json(
                HTTPStatus.OK,
                {
                    "note": "Synthetic test data only.",
                    "users": [
                        {
                            "id": 1,
                            "username": "alice.lab",
                            "role": "doctor",
                            "synthetic": True,
                        },
                        {
                            "id": 2,
                            "username": "bob.lab",
                            "role": "analyst",
                            "synthetic": True,
                        },
                        {
                            "id": 3,
                            "username": "admin.lab",
                            "role": "administrator",
                            "synthetic": True,
                        },
                    ],
                    "simulated_finding": "excessive_data_exposure",
                },
            )

        elif path == "/api/v1/vulns":
            self._send_json(
                HTTPStatus.OK,
                {
                    "warning": "These are simulated findings for scanner evaluation.",
                    "simulated_vulnerabilities": [
                        {
                            "id": "LAB-001",
                            "name": "Missing security headers",
                            "severity": "low",
                            "real_exploit": False,
                        },
                        {
                            "id": "LAB-002",
                            "name": "Verbose server banner",
                            "severity": "low",
                            "real_exploit": False,
                        },
                        {
                            "id": "LAB-003",
                            "name": "Exposed mock backup file",
                            "severity": "medium",
                            "real_exploit": False,
                        },
                        {
                            "id": "LAB-004",
                            "name": "Synthetic outdated component",
                            "severity": "medium",
                            "real_exploit": False,
                        },
                    ],
                },
            )

        elif path == "/backup/config.bak":
            body = """# Mock backup file for lab testing only.
# No real credentials are present.

APP_NAME=MedFlow Training Portal
ENVIRONMENT=lab
DB_HOST=mockdb.local
DB_USER=demo_user
DB_PASSWORD=not_a_real_password
API_KEY=not_a_real_api_key
JWT_SECRET=not_a_real_secret

# Simulated finding:
# Exposed backup/configuration file.
"""
            self._send(
                HTTPStatus.OK,
                body.encode(),
                "text/plain; charset=utf-8",
                extra_headers={"X-Simulated-Finding": "exposed_backup_file"},
            )

        elif path == "/debug/env":
            self._send_json(
                HTTPStatus.OK,
                {
                    "warning": "Mock debug endpoint. No real environment variables.",
                    "env": {
                        "APP_ENV": "lab",
                        "DEBUG": "true",
                        "SECRET_KEY": "not_a_real_secret",
                        "DATABASE_URL": "mock://demo_user:not_a_real_password@mockdb.local/medflow",
                    },
                    "simulated_finding": "debug_endpoint_exposure",
                },
            )

        elif path == "/echo":
            value = query.get("value", [""])[0]
            escaped_value = html.escape(value)

            body = f"""<!doctype html>
<html>
<head><title>Echo</title></head>
<body>
<h1>Echo endpoint</h1>
<p>Reflected value, safely HTML-escaped:</p>
<pre>{escaped_value}</pre>
<p>Simulated finding: reflected input surface.</p>
</body>
</html>
"""
            self._send(HTTPStatus.OK, body.encode(), "text/html; charset=utf-8")

        elif path == "/slow":
            time.sleep(2)
            self._send_json(
                HTTPStatus.OK,
                {
                    "message": "Delayed response completed.",
                    "delay_seconds": 2,
                    "simulated_use": "timeout and retry testing",
                },
            )

        elif path == "/large":
            repeated = "\n".join(
                f"Line {i}: synthetic application documentation for retrieval testing."
                for i in range(1, 501)
            )
            self._send(HTTPStatus.OK, repeated.encode(), "text/plain; charset=utf-8")

        else:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {
                    "message": "Not found",
                    "path": path,
                },
            )

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_body()

        if path == "/login":
            params = parse_qs(body)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            logging.info(
                "Lab login attempt username=%r password_length=%d",
                username,
                len(password),
            )

            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                {
                    "message": "Authentication failed. This is a lab endpoint.",
                    "username_received": html.escape(username),
                    "password_received": False,
                    "simulated_finding": "login_surface_detected",
                },
            )

        elif path == "/api/v1/submit":
            self._send_json(
                HTTPStatus.OK,
                {
                    "message": "Submission received by lab server.",
                    "body_length": len(body),
                    "body_preview_escaped": html.escape(body[:200]),
                },
            )

        else:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {
                    "message": "POST endpoint not found",
                    "path": path,
                },
            )

    def index(self) -> None:
        body = """<!doctype html>
<html>
<head>
  <title>MedFlow Lab Target</title>
</head>
<body>
  <h1>MedFlow Lab Target</h1>
  <p>This is a safe local target for testing a cybersecurity agent.</p>

  <h2>Useful paths</h2>
  <ul>
    <li><a href="/health">/health</a></li>
    <li><a href="/robots.txt">/robots.txt</a></li>
    <li><a href="/login">/login</a></li>
    <li><a href="/admin">/admin</a></li>
    <li><a href="/api/v1/status">/api/v1/status</a></li>
    <li><a href="/api/v1/users">/api/v1/users</a></li>
    <li><a href="/api/v1/vulns">/api/v1/vulns</a></li>
    <li><a href="/backup/config.bak">/backup/config.bak</a></li>
    <li><a href="/debug/env">/debug/env</a></li>
    <li><a href="/echo?value=test">/echo?value=test</a></li>
    <li><a href="/slow">/slow</a></li>
    <li><a href="/large">/large</a></li>
  </ul>

  <h2>Simulated findings</h2>
  <ul>
    <li>Missing security headers</li>
    <li>Verbose server banner</li>
    <li>Interesting admin path</li>
    <li>Mock exposed backup file</li>
    <li>Mock debug endpoint</li>
    <li>Fake outdated components</li>
  </ul>

  <p>No real vulnerabilities are implemented.</p>
</body>
</html>
"""
        self._send(HTTPStatus.OK, body.encode(), "text/html; charset=utf-8")

    def login_page(self) -> None:
        body = """<!doctype html>
<html>
<head>
  <title>MedFlow Login</title>
</head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/login">
    <label>Username</label>
    <input name="username" value="">
    <br>
    <label>Password</label>
    <input name="password" type="password" value="">
    <br>
    <button type="submit">Login</button>
  </form>
  <p>Lab endpoint. Authentication always fails.</p>
</body>
</html>
"""
        self._send(HTTPStatus.OK, body.encode(), "text/html; charset=utf-8")


class BannerServer(threading.Thread):
    def __init__(self, host: str, port: int, banner: str, name: str) -> None:
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.banner = banner
        self.name = name
        self.sock: socket.socket | None = None

    def run(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(20)
            self.sock.settimeout(1.0)

            logging.info("%s banner service listening on %s:%s", self.name, self.host, self.port)

            while not STOP_EVENT.is_set():
                try:
                    conn, addr = self.sock.accept()
                except socket.timeout:
                    continue

                with conn:
                    logging.info("%s banner connection from %s:%s", self.name, addr[0], addr[1])
                    conn.sendall(self.banner.encode("utf-8", errors="replace"))
                    time.sleep(0.1)

        except OSError as exc:
            logging.error("%s banner service failed on port %s: %s", self.name, self.port, exc)

        finally:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass


def start_http(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), LabHTTPHandler)
    server.timeout = 1.0

    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.5},
        daemon=True,
    )
    thread.start()

    logging.info("HTTP lab target listening on http://%s:%s", host, port)
    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe local lab target server.")

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host. Use 127.0.0.1 for local only, or 0.0.0.0 for LAN testing.",
    )

    parser.add_argument(
        "--http-port",
        type=int,
        default=8080,
        help="HTTP port.",
    )

    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Disable fake TCP banner services.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    def handle_stop(signum, frame):
        logging.info("Shutdown requested.")
        STOP_EVENT.set()

    signal.signal(signal.SIGINT, handle_stop)
    signal.signal(signal.SIGTERM, handle_stop)

    http_server = start_http(args.host, args.http_port)

    banner_servers: list[BannerServer] = []

    if not args.no_banners:
        banner_servers = [
            BannerServer(
                args.host,
                2222,
                "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8\r\n",
                "fake-ssh",
            ),
            BannerServer(
                args.host,
                33060,
                "5.7.31-log MockMySQL Community Server - lab only\r\n",
                "fake-mysql",
            ),
            BannerServer(
                args.host,
                6380,
                "-NOAUTH Authentication required. MockRedis lab banner only\r\n",
                "fake-redis",
            ),
        ]

        for server in banner_servers:
            server.start()

    print()
    print("============================================")
    print(" Safe Lab Target Server Running")
    print("============================================")
    print(f"HTTP:    http://{args.host}:{args.http_port}")
    print(f"Health:  http://{args.host}:{args.http_port}/health")
    print(f"Vulns:   http://{args.host}:{args.http_port}/api/v1/vulns")
    print()
    print("Fake banner ports:")
    if args.no_banners:
        print("  disabled")
    else:
        print("  2222   fake SSH")
        print("  33060  fake MySQL")
        print("  6380   fake Redis")
    print()
    print("Press Ctrl+C to stop.")
    print("Log file:", LOG_FILE.resolve())
    print("============================================")
    print()

    try:
        while not STOP_EVENT.is_set():
            time.sleep(0.5)

    finally:
        STOP_EVENT.set()
        logging.info("Stopping HTTP server.")
        http_server.shutdown()
        http_server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())