"""Loopback-only fixture for the documented login/token/cookie flow."""

import argparse
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading


class DemoServer(ThreadingHTTPServer):
    def __init__(self, port=8765):
        super().__init__(("127.0.0.1", port), DemoHandler)
        self.sessions = {}
        self.session_lock = threading.Lock()


class DemoHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, data, cookie=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie is not None:
            self.send_header("Set-Cookie", f"demo_session={cookie}; HttpOnly; SameSite=Lax; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = -1
        if not 0 <= size <= 4096:
            self.close_connection = True
            return self.reply(400, {"message": "INVALID_BODY"})
        try:
            data = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            return self.reply(400, {"message": "INVALID_BODY"})
        if self.path != "/login":
            return self.reply(404, {"message": "NOT_FOUND"})
        if not isinstance(data, dict) or data.get("login") != "demo" or data.get("password") != "demo-password":
            return self.reply(403, {"message": "INVALID_PASSWORD"})
        token = secrets.token_urlsafe(24)
        session = secrets.token_urlsafe(18)
        with self.server.session_lock:
            self.server.sessions[session] = token
        self.reply(200, {"message": "SIGNED_IN", "data": {"opaque": token}}, session)

    def do_GET(self):
        if self.path != "/profile":
            return self.reply(404, {"message": "NOT_FOUND"})
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            return self.reply(403, {"message": "INVALID_SESSION"})
        session = cookie.get("demo_session")
        with self.server.session_lock:
            expected = self.server.sessions.get(session.value if session else "")
        if expected is None or self.headers.get("Authorization") != f"Bearer {expected}":
            return self.reply(403, {"message": "INVALID_SESSION"})
        self.reply(200, {"message": "PROFILE_READY", "plan": "demo", "opaque_echo": expected})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    with DemoServer(args.port) as server:
        print(f"FORGE demo listening at http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
