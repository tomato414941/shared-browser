#!/usr/bin/env python3
"""Turn a short-lived link into a viewer session.

GET /go/<token> only shows a button, so link previews in chat apps do not use the link up.
POST /go/<token> uses the link, logs in to neko, and hands the session cookie to the browser that pressed the button.
A browser that already has a session goes straight to the viewer, whatever the state of the link.

/cdp/... passes the Chrome DevTools Protocol through to the browser for a principal whose key allows "cdp",
and /mcp passes Model Context Protocol requests to the bundled MCP server for one whose key allows "mcp".
Keys travel in the Authorization header, so they stay out of URLs and logs.

Revoking a principal takes effect at once: its open connections are closed and its viewer sessions ended.
"""
import fcntl
import hashlib
import http.client
import html
import json
import os
import re
import socket
import threading
import time
from contextlib import contextmanager
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LINKS = Path(os.environ.get("GATE_LINKS", "/home/neko/profile/links.json"))
NEKO = os.environ.get("GATE_NEKO", "http://127.0.0.1:8081")
PASSWORD = os.environ["GATE_PASSWORD"]
GRANTS = Path(os.environ.get("GATE_GRANTS", "/home/neko/profile/grants.json"))
CDP = os.environ.get("GATE_CDP", "127.0.0.1:9222")
BASE = os.environ.get("GATE_BASE", "").rstrip("/")   # the URL people and agents use to reach this browser
MCP = os.environ.get("GATE_MCP", "localhost:8083")    # the bundled MCP server only answers to this Host
ADMIN_PASSWORD = os.environ.get("GATE_ADMIN_PASSWORD", "")

# Open connections through the gate, so a revocation can close them: id -> (key digest, ability, sockets).
ACTIVE = {}
ACTIVE_LOCK = threading.Lock()


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<meta name="referrer" content="no-referrer"><title>Browser</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font:17px system-ui,sans-serif;background:#f3f4f6;color:#111827}}
button{{font:inherit;padding:14px 32px;border:0;border-radius:10px;background:#374151;color:#fff}}p{{color:#4b5563}}
@media (prefers-color-scheme:dark){{body{{background:#111827;color:#f3f4f6}}p{{color:#9ca3af}}button{{background:#e5e7eb;color:#111827}}}}</style>
</head><body>{body}</body></html>"""
OPEN = '<form method="post" action="{action}"><button type="submit">Open the browser</button></form>'
GONE = "<p>This link is no longer valid.</p>"
NOT_READY = "<p>The browser is not ready. Try the link again in a moment.</p>"


@contextmanager
def links():
    """The links, locked, without expired ones. The file is shared with the host, so lock it."""
    if not LINKS.exists():
        yield []
        return
    with open(LINKS, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            items = json.load(f)
        except ValueError:
            items = []
        now = time.time()
        items = [l for l in items if l["expires"] > now]
        yield items
        f.seek(0), f.truncate(), json.dump(items, f)


def usable(token):
    with links() as items:
        return any(l["token"] == token and not l.get("used") for l in items)


def take(token):
    """Return the link for token and mark it used, or None if it is unknown, expired, or used."""
    with links() as items:
        found = next((l for l in items if l["token"] == token and not l.get("used")), None)
        if found:
            found["used"] = time.time()
        return found


def principal(name):
    """The principal's grant, or None if unknown or revoked."""
    try:
        grants = json.loads(GRANTS.read_text())
    except (OSError, ValueError):
        return None
    grant = grants.get(name)
    return grant if grant and not grant.get("revoked") else None


def digest(key):
    return hashlib.sha256(key.encode()).hexdigest()


def holder(key_digest):
    """(name, grant) for an unexpired key of an unrevoked principal, or (None, None)."""
    try:
        grants = json.loads(GRANTS.read_text())
    except (OSError, ValueError):
        return None, None
    now = time.time()
    for name, grant in grants.items():
        if grant.get("revoked"):
            continue
        for k in grant.get("keys", []):
            if k["hash"] == key_digest and (not k.get("expires") or k["expires"] > now):
                return name, grant
    return None, None


def allowed(key_digest, ability):
    return ability in (holder(key_digest)[1] or {}).get("can", [])


def neko(method, path, cookie=None, body=None):
    """Call neko's API. Returns (parsed body, session cookie it set). neko hands out sessions only as cookies here."""
    headers = {"content-type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(NEKO + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as res:
        text = res.read()
        set_cookie = next((c.split(";", 1)[0] for c in res.headers.get_all("set-cookie") or []), None)
        return (json.loads(text) if text.strip() else None), set_cookie


_last_grants = None


def enforce():
    """Close connections whose key no longer allows them, and end viewer sessions of principals who may not view."""
    with ACTIVE_LOCK:
        stale = [(i, socks) for i, (d, ability, socks) in ACTIVE.items() if not allowed(d, ability)]
    for _, socks in stale:
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    global _last_grants
    try:
        stamp = GRANTS.stat().st_mtime_ns
        grants = json.loads(GRANTS.read_text())
    except (OSError, ValueError):
        return
    if stamp == _last_grants or not ADMIN_PASSWORD:
        return
    _last_grants = stamp
    barred = {name for name, g in grants.items() if g.get("revoked") or "view" not in g.get("can", [])}
    if not barred:
        return
    try:
        _, cookie = neko("POST", "/api/login", body={"username": "gate", "password": ADMIN_PASSWORD})
        if not cookie:
            raise ValueError("neko set no session cookie")
        try:
            sessions, _ = neko("GET", "/api/sessions", cookie)
            for session in sessions or []:
                if session.get("profile", {}).get("name") in barred:
                    neko("DELETE", f"/api/sessions/{session['id']}", cookie)
        finally:
            neko("POST", "/api/logout", cookie)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"could not end viewer sessions: {error!r}", flush=True)
        _last_grants = None   # try again on the next pass


def watch():
    while True:
        enforce()
        time.sleep(2)


def release(token):
    """Make a taken link usable again, for when logging in failed after taking it."""
    with links() as items:
        for l in items:
            if l["token"] == token:
                l.pop("used", None)


class Gate(BaseHTTPRequestHandler):
    def has_session(self):
        cookie = self.headers.get("Cookie")
        if not cookie:
            return False
        req = urllib.request.Request(NEKO + "/api/whoami", headers={"Cookie": cookie})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                return res.status == 200
        except (urllib.error.URLError, TimeoutError):
            return False

    def token(self):
        token = self.path.split("?", 1)[0].removeprefix("/go/").strip("/")
        return token if token and "/" not in token else None

    def page(self, status, body, head_only=False):
        data = PAGE.format(body=body).encode()
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def redirect(self, cookies=(), status=302):
        self.send_response(status)
        for cookie in cookies:
            self.send_header("set-cookie", cookie)
        self.send_header("location", "/")
        self.send_header("cache-control", "no-store")
        self.end_headers()

    def door_for_path(self):
        path = self.path.split("?", 1)[0]
        if path == "/cdp" or path.startswith("/cdp/"):
            return "cdp"
        if path == "/mcp" or path.startswith("/mcp/"):
            return "mcp"
        return None

    def do_GET(self):
        if self.door_for_path():
            self.door(self.door_for_path())
        else:
            self.show()

    def do_PUT(self):
        if self.door_for_path():
            self.door(self.door_for_path())
        else:
            self.page(405, GONE)

    def do_DELETE(self):
        if self.door_for_path():
            self.door(self.door_for_path())
        else:
            self.page(405, GONE)

    # --- CDP ---

    def outside(self):
        """Where this request came in from, as the ws(s) base agents should use."""
        base = BASE or f"{self.headers.get('X-Forwarded-Proto') or 'http'}://{self.headers.get('Host', '')}"
        return re.sub(r"^http", "ws", base) + "/cdp"

    def refuse(self, status, message):
        data = (message + "\n").encode()
        self.send_response(status)
        if status == 401:
            self.send_header("www-authenticate", 'Bearer realm="shared-browser"')
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def door(self, ability):
        auth = self.headers.get("Authorization", "")
        key_digest = digest(auth[7:]) if auth.startswith("Bearer ") else None
        name, grant = holder(key_digest) if key_digest else (None, None)
        if not grant:
            self.refuse(401, "A key is required.")
            return
        if ability not in grant.get("can", []):
            self.refuse(403, f"{name} may not use {ability}.")
            return
        if ability == "mcp":
            self.tunnel(MCP, self.path, key_digest, ability, close=True)
            return
        path = self.path[len("/cdp"):] or "/"
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.tunnel(CDP, path, key_digest, ability)
        else:
            self.relay(path)

    def relay(self, path):
        """Pass an HTTP request (/json/...) to Chrome and point the addresses it returns back through here."""
        host, port = CDP.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            conn.request(self.command, path, headers={"Host": CDP})
            res = conn.getresponse()
            body = res.read().decode("utf-8", "replace")
        except OSError:
            self.refuse(503, "The browser is not ready.")
            return
        body = body.replace(f"ws://{CDP}", self.outside()).replace(f"ws={CDP}", "ws=" + self.outside().split("://", 1)[1])
        data = body.encode()
        self.send_response(res.status)
        self.send_header("content-type", res.getheader("content-type", "application/json"))
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def tunnel(self, target, path, key_digest, ability, close=False):
        """Pass the request on to target and copy bytes both ways until either side closes.

        With close, the upstream is asked to end the connection after one response, so a second request can never
        ride on a connection that was checked only once.
        """
        host, port = target.split(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.refuse(503, "The browser is not ready.")
            return
        upstream.settimeout(None)
        skip = {"host", "authorization"} | ({"connection", "keep-alive"} if close else set())
        lines = [f"{self.command} {path} HTTP/1.1", f"Host: {target}"]
        lines += [f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in skip]
        if close:
            lines.append("Connection: close")
        upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        self.close_connection = True
        tunnel_id = id(upstream)
        with ACTIVE_LOCK:
            ACTIVE[tunnel_id] = (key_digest, ability, (upstream, self.connection))

        def pump(read, write):
            try:
                while data := read(65536):
                    write(data)
            except OSError:
                pass
            finally:
                for sock in (upstream, self.connection):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        try:
            back = threading.Thread(target=pump, args=(upstream.recv, self.connection.sendall), daemon=True)
            back.start()
            pump(self.rfile.read1, upstream.sendall)
            back.join()
        finally:
            with ACTIVE_LOCK:
                ACTIVE.pop(tunnel_id, None)
            upstream.close()

    def do_HEAD(self):
        self.show(head_only=True)

    def show(self, head_only=False):
        if self.has_session():
            self.redirect()
            return
        token = self.token()
        if token and usable(token):
            self.page(200, OPEN.format(action=html.escape(self.path.split("?", 1)[0])), head_only)
        else:
            self.page(404, GONE, head_only)

    def do_POST(self):
        if self.door_for_path():
            self.door(self.door_for_path())
            return
        if self.has_session():
            self.redirect(status=303)
            return
        token = self.token()
        link = take(token) if token else None
        who = (link or {}).get("as") or "viewer"
        if not link or "view" not in (principal(who) or {}).get("can", []):
            self.page(404, GONE)
            return
        body = json.dumps({"username": who, "password": PASSWORD}).encode()
        req = urllib.request.Request(NEKO + "/api/login", data=body, headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as res:
                cookies = res.headers.get_all("set-cookie") or []
        except (urllib.error.URLError, TimeoutError):
            release(token)
            self.page(503, NOT_READY)
            return
        self.redirect(cookies, status=303)

if __name__ == "__main__":
    threading.Thread(target=watch, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8082), Gate).serve_forever()
