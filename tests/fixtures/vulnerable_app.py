"""Deliberately vulnerable HTTP fixture used by tests and demos.

This server is *intentionally* insecure. It exists only to give the engine a
deterministic, offline target with a known finding set. Never expose it.
"""

from __future__ import annotations

import base64
import contextlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _b64url(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# alg=none and no exp: both are deliberate findings.
_DEMO_JWT = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': 'demo', 'role': 'admin'})}."

_INDEX_HTML = """<!doctype html><html><head><title>Fixture App</title></head><body>
<h1>Fixture App</h1>
<a href="/admin">Admin</a>
<a href="/login">Login</a>
<a href="/api/v1/users?page=1">Users API</a>
<a href="/static/app.css">Styles</a>
<a href="https://external.example.test/away">External</a>
<form method="GET" action="/search"><input name="q"><input name="lang"></form>
</body></html>"""


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        return

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: bytes = b"", *, headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Fixture/1.0 (deliberately vulnerable)")
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _cors(self) -> list[tuple[str, str]]:
        origin = self.headers.get("Origin", "")
        if origin:
            return [
                ("Access-Control-Allow-Origin", origin),
                ("Access-Control-Allow-Credentials", "true"),
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                ("Access-Control-Allow-Headers", "authorization, content-type"),
            ]
        return []

    def _base_headers(self) -> list[tuple[str, str]]:
        return [
            ("Set-Cookie", "session=demo-session-value; Path=/"),
            ("Set-Cookie", f"token={_DEMO_JWT}; Path=/; SameSite=Lax"),
            ("X-Powered-By", "FixtureLite/0.1"),
        ]

    def _dispatch(self) -> None:
        path = self.path.split("?")[0]
        lowered = path.lower()

        if lowered in ("/", "/index.html"):
            self._send(200, _INDEX_HTML.encode(), headers=[*self._base_headers(), *self._cors()])
            return
        if lowered == "/admin":
            self._send(403, b"forbidden", headers=self._cors())
            return
        if lowered == "/login":
            self._send(
                200,
                b"<html><title>Login</title><form action='/login' method='POST'><input name='user'><input name='pass'></form></html>",
                headers=self._cors(),
            )
            return
        if lowered.startswith("/api/v1/users"):
            self._send(
                200,
                b'{"users": [{"id": 1, "email": "a@example.test"}]}',
                headers=[("Content-Type", "application/json"), *self._cors()],
            )
            return
        if lowered == "/static/app.css":
            self._send(200, b"body{margin:0}", headers=[("Content-Type", "text/css")])
            return
        if lowered == "/search":
            self._send(200, b"<html><title>Search</title>results</html>", headers=self._cors())
            return
        if lowered == "/robots.txt":
            self._send(200, b"User-agent: *\nDisallow: /admin\nDisallow: /internal/debug\nDisallow: /backup\n")
            return
        if lowered.startswith("/.git"):
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n\tremote = https://git.example.test/app.git\n")
            return
        if lowered == "/.env":
            self._send(200, b"SECRET_KEY=fixture-secret\nDATABASE_URL=postgresql://user:pass@db/app\n")
            return
        if "%2e%2e" in lowered or "..%2f" in lowered:
            self._send(200, b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return
        if lowered == "/graphql":
            self._send(
                200,
                b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                headers=[("Content-Type", "application/json"), *self._cors()],
            )
            return
        if lowered == "/openapi.json":
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Fixture API", "version": "1.0"},
                "paths": {
                    "/api/v1/users": {"get": {}},
                    "/api/v1/users/{id}": {"get": {}, "delete": {}},
                    "/api/v1/orders": {"post": {}},
                },
            }
            self._send(200, json.dumps(spec).encode(), headers=[("Content-Type", "application/json")])
            return
        if lowered == "/.well-known/security.txt":
            self._send(404, b"not found")
            return

        # Deliberately verbose 404 page.
        self._send(
            404,
            b"<html><body>Traceback (most recent call last):\n"
            b'  File "app.py", line 42, in handler\n'
            b"sqlstate[42S02]: base table or view not found\n</body></html>",
            headers=self._base_headers(),
        )

    def do_GET(self) -> None:
        self._dispatch()

    def do_HEAD(self) -> None:
        self._dispatch()

    def do_OPTIONS(self) -> None:
        allow = "GET, POST, OPTIONS, TRACE, DELETE"
        headers = [*self._cors(), ("Allow", allow), ("Content-Length", "0")]
        self.send_response(200)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()

    def do_TRACE(self) -> None:
        echo = f"TRACE {self.path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in self.headers.items())
        self._send(200, echo.encode())

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        if self.path.split("?")[0].lower() == "/graphql" and b"__schema" in body:
            self._send(
                200,
                b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
                headers=[("Content-Type", "application/json"), *self._cors()],
            )
            return
        self._send(404, b"not found", headers=self._cors())


@contextlib.contextmanager
def running_fixture(host: str = "127.0.0.1") -> Iterator[str]:
    """Start the fixture on an ephemeral port and yield its base URL."""

    server = ThreadingHTTPServer((host, 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the deliberately vulnerable fixture")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), FixtureHandler)
    print(f"fixture listening on http://127.0.0.1:{args.port} (intentionally vulnerable)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
