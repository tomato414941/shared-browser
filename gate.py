#!/usr/bin/env python3
"""Turn a short-lived link into a viewer session: GET /go/<token> logs in to neko and hands the cookie over."""
import fcntl
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LINKS = Path(os.environ.get("GATE_LINKS", "/home/neko/profile/links.json"))
NEKO = os.environ.get("GATE_NEKO", "http://127.0.0.1:8081")
PASSWORD = os.environ["GATE_PASSWORD"]


def take(token):
    """Return the link for token and mark it used, or None. The file is shared with the host, so lock it."""
    if not LINKS.exists():
        return None
    with open(LINKS, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            links = json.load(f)
        except ValueError:
            links = []
        now = time.time()
        links = [l for l in links if l["expires"] > now]
        found = next((l for l in links if l["token"] == token and not l.get("used")), None)
        if found:
            found["used"] = now
        f.seek(0), f.truncate(), json.dump(links, f)
        return found


class Gate(BaseHTTPRequestHandler):
    def do_GET(self):
        token = self.path.split("?", 1)[0].removeprefix("/go/").strip("/")
        link = take(token) if token and "/" not in token else None
        if not link:
            self.send_response(404), self.send_header("content-type", "text/plain; charset=utf-8"), self.end_headers()
            self.wfile.write("This link is no longer valid.\n".encode())
            return
        body = json.dumps({"username": link.get("as") or "viewer", "password": PASSWORD}).encode()
        req = urllib.request.Request(NEKO + "/api/login", data=body, headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as res:
            cookies = res.headers.get_all("set-cookie") or []
        self.send_response(302)
        for cookie in cookies:
            self.send_header("set-cookie", cookie)
        self.send_header("location", "/"), self.send_header("cache-control", "no-store"), self.end_headers()

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8082), Gate).serve_forever()
