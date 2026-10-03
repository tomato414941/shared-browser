#!/usr/bin/env python3
"""The one way in to a shared browser. Whoever comes, a person or an AI, is a principal with granted abilities.

People:
  GET  /go/<token>   shows a button, so link previews in chat apps do not use the link up.
  POST /go/<token>   uses the link and starts a viewer session for its principal, kept as a cookie.
  Everything the viewer loads is checked against that session (nginx asks /_auth). The screen's WebSocket
  passes through here, so it can be closed the moment the principal is revoked.

Agents:
  /cdp/...           the Chrome DevTools Protocol, for a principal whose key allows "cdp".
  /mcp               Model Context Protocol requests to the bundled MCP server, for one whose key allows "mcp".
  Keys travel in the Authorization header, so they stay out of URLs and logs.

Revoking a principal takes effect at once: its open connections are closed and its sessions stop working.
The screen server behind this gate has no authentication of its own and is reachable only through it.
"""
import fcntl
import hashlib
import http.client
import http.cookies
import html
import json
import os
import re
import secrets
import socket
import threading
import time
import urllib.parse
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STATE = Path(os.environ.get("GATE_STATE", "/home/neko/profile"))
LINKS = Path(os.environ.get("GATE_LINKS", STATE / "links.json"))
GRANTS = Path(os.environ.get("GATE_GRANTS", STATE / "grants.json"))
SESSIONS = Path(os.environ.get("GATE_SESSIONS", STATE / "sessions.json"))
SCREEN = os.environ.get("GATE_SCREEN", "127.0.0.1:8081")   # the screen server (neko), with no authentication
CDP = os.environ.get("GATE_CDP", "127.0.0.1:9222")
MCP = os.environ.get("GATE_MCP", "localhost:8083")          # the bundled MCP server only answers to this Host
BASE = os.environ.get("GATE_BASE", "").rstrip("/")          # the URL people and agents use to reach this browser
COOKIE = "shared_browser_" + re.sub(r"[^A-Za-z0-9_]", "_", os.environ.get("GATE_NAME", "browser"))
SESSION_SECONDS = float(os.environ.get("GATE_SESSION_HOURS", "720")) * 3600

# Open connections through the gate, so a revocation can close them: id -> (still allowed?, sockets).
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
NEED_LINK = "<p>Open this browser with a link.</p>"


def digest(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def read(path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


@contextmanager
def locked(path, default):
    """The JSON in path, locked for update. The files are shared with the host, so lock them."""
    path.touch(mode=0o600, exist_ok=True)
    with open(path, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            data = json.load(f)
        except ValueError:
            data = default
        box = [data]
        yield box
        f.seek(0), f.truncate(), json.dump(box[0], f)


# --- principals ---

def principal(name):
    """The principal's grant, or None if unknown or revoked."""
    grant = read(GRANTS, {}).get(name)
    return grant if grant and not grant.get("revoked") else None


def may(name, ability):
    return ability in (principal(name) or {}).get("can", [])


def key_holder(key_digest):
    """The name of the principal holding this unexpired key, or None."""
    now = time.time()
    for name, grant in read(GRANTS, {}).items():
        if grant.get("revoked"):
            continue
        for k in grant.get("keys", []):
            if k["hash"] == key_digest and (not k.get("expires") or k["expires"] > now):
                return name
    return None


# --- links ---

def link_usable(token):
    return any(l["token"] == token and not l.get("used") and l["expires"] > time.time() for l in read(LINKS, []))


def take_link(token):
    """Mark the link used and return it, or None if it is unknown, expired, or used."""
    with locked(LINKS, []) as box:
        now = time.time()
        box[0] = [l for l in box[0] if l["expires"] > now]
        found = next((l for l in box[0] if l["token"] == token and not l.get("used")), None)
        if found:
            found["used"] = now
        return found


# --- viewer sessions ---

def start_session(name):
    token = secrets.token_urlsafe(32)
    with locked(SESSIONS, {}) as box:
        now = time.time()
        box[0] = {d: s for d, s in box[0].items() if s["expires"] > now}
        box[0][digest(token)] = {"as": name, "expires": now + SESSION_SECONDS}
    return token


def session_holder(session_digest):
    """The name of the principal this session belongs to, if it is unexpired and the principal may still view."""
    session = read(SESSIONS, {}).get(session_digest)
    if not session or session["expires"] <= time.time() or not may(session["as"], "view"):
        return None
    return session["as"]


# --- revocation ---

def enforce():
    """Close every open connection whose principal may no longer hold it."""
    with ACTIVE_LOCK:
        stale = [socks for still_allowed, socks in ACTIVE.values() if not still_allowed()]
    for socks in stale:
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def watch():
    while True:
        enforce()
        time.sleep(2)


class Gate(BaseHTTPRequestHandler):
    # --- who is asking ---

    def viewer(self):
        """(principal name, session digest) for a valid viewer session cookie, or (None, None)."""
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None, None
        if COOKIE not in jar:
            return None, None
        session_digest = digest(jar[COOKIE].value)
        return session_holder(session_digest), session_digest

    def key(self):
        """(principal name, key digest) for a valid key in the Authorization header, or (None, None)."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None, None
        key_digest = digest(auth[7:])
        return key_holder(key_digest), key_digest

    def https(self):
        return BASE.startswith("https://") or self.headers.get("X-Forwarded-Proto") == "https"

    def same_origin(self):
        """A WebSocket must come from a page of this browser, not from some other site the person has open."""
        origin = urllib.parse.urlsplit(self.headers.get("Origin", "")).netloc
        return bool(origin) and origin in (self.headers.get("Host"), urllib.parse.urlsplit(BASE).netloc)

    # --- replies ---

    def page(self, status, body, head_only=False):
        data = PAGE.format(body=body).encode()
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def redirect(self, status=302, cookie=None):
        self.send_response(status)
        if cookie:
            self.send_header("set-cookie", cookie)
        self.send_header("location", "/")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", "0")
        self.end_headers()

    def plain(self, status, message, headers=()):
        data = (message + "\n").encode() if message else b""
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def reply_json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- routing ---

    def route(self):
        path = self.path.split("?", 1)[0]
        if path == "/cdp" or path.startswith("/cdp/"):
            return self.agent_door("cdp")
        if path == "/mcp" or path.startswith("/mcp/"):
            return self.agent_door("mcp")
        if path.startswith("/go/"):
            return self.use_link() if self.command == "POST" else self.show_link()
        if self.command in ("GET", "HEAD"):
            if path == "/_auth":
                return self.plain(204 if self.viewer()[0] else 401, "")
            if path == "/whoami":
                name = self.viewer()[0]
                return self.reply_json({"name": name}) if name else self.plain(401, "A link is needed.")
            if self.headers.get("Upgrade", "").lower() == "websocket":
                return self.screen_socket()
        self.page(401, NEED_LINK, head_only=self.command == "HEAD")

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = route

    # --- people ---

    def link_token(self):
        token = self.path.split("?", 1)[0].removeprefix("/go/").strip("/")
        return token if token and "/" not in token else None

    def show_link(self):
        head_only = self.command == "HEAD"
        if self.viewer()[0]:
            self.redirect()
        elif self.link_token() and link_usable(self.link_token()):
            self.page(200, OPEN.format(action=html.escape(self.path.split("?", 1)[0])), head_only)
        else:
            self.page(404, GONE, head_only)

    def use_link(self):
        if self.viewer()[0]:
            self.redirect(303)
            return
        link = take_link(self.link_token()) if self.link_token() else None
        who = (link or {}).get("as") or "viewer"
        if not link or not may(who, "view"):
            self.page(404, GONE)
            return
        cookie = f"{COOKIE}={start_session(who)}; Path=/; Max-Age={int(SESSION_SECONDS)}; HttpOnly; SameSite=Lax"
        self.redirect(303, cookie + ("; Secure" if self.https() else ""))

    def screen_socket(self):
        """The viewer's live connection to the screen, under the principal's own name."""
        name, session_digest = self.viewer()
        if not name:
            self.plain(401, "A link is needed.")
            return
        if not self.same_origin():
            self.plain(403, "This connection must come from the browser's own page.")
            return
        path = self.path.split("?", 1)[0] + "?" + urllib.parse.urlencode({"username": name, "password": "-"})
        self.tunnel(SCREEN, path, lambda: session_holder(session_digest) == name)

    # --- agents ---

    def agent_door(self, ability):
        name, key_digest = self.key()
        if not name:
            self.plain(401, "A key is required.", [("www-authenticate", 'Bearer realm="shared-browser"')])
            return
        if not may(name, ability):
            self.plain(403, f"{name} may not use {ability}.")
            return
        still_allowed = lambda: key_holder(key_digest) == name and may(name, ability)
        if ability == "mcp":
            self.tunnel(MCP, self.path, still_allowed, close=True)
            return
        path = self.path[len("/cdp"):] or "/"
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.tunnel(CDP, path, still_allowed)
        else:
            self.relay_cdp(path)

    def outside(self):
        """Where this request came in from, as the ws(s) base agents should use."""
        base = BASE or f"{'https' if self.https() else 'http'}://{self.headers.get('Host', '')}"
        return re.sub(r"^http", "ws", base) + "/cdp"

    def relay_cdp(self, path):
        """Pass an HTTP request (/json/...) to Chrome and point the addresses it returns back through here."""
        host, port = CDP.split(":")
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        try:
            conn.request(self.command, path, headers={"Host": CDP})
            res = conn.getresponse()
            body = res.read().decode("utf-8", "replace")
        except OSError:
            self.plain(503, "The browser is not ready.")
            return
        body = body.replace(f"ws://{CDP}", self.outside()).replace(f"ws={CDP}", "ws=" + self.outside().split("://", 1)[1])
        data = body.encode()
        self.send_response(res.status)
        self.send_header("content-type", res.getheader("content-type", "application/json"))
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- carrying a connection ---

    def tunnel(self, target, path, still_allowed, close=False):
        """Pass the request on to target and copy bytes both ways until either side closes or it is revoked.

        The principal's key or session cookie is not passed on. With close, the upstream is asked to end the
        connection after one response, so a second request can never ride on a connection that was checked once.
        """
        host, port = target.split(":")
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            self.plain(503, "The browser is not ready.")
            return
        upstream.settimeout(None)
        skip = {"host", "authorization", "cookie"} | ({"connection", "keep-alive"} if close else set())
        lines = [f"{self.command} {path} HTTP/1.1", f"Host: {target}"]
        lines += [f"{k}: {v}" for k, v in self.headers.items() if k.lower() not in skip]
        if close:
            lines.append("Connection: close")
        upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        self.close_connection = True
        tunnel_id = id(upstream)
        with ACTIVE_LOCK:
            ACTIVE[tunnel_id] = (still_allowed, (upstream, self.connection))

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


if __name__ == "__main__":
    threading.Thread(target=watch, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8082), Gate).serve_forever()
