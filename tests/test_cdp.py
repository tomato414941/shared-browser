import hashlib
import importlib.util
import json
import socket
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gate", Path(__file__).parents[1] / "gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FakeChrome(BaseHTTPRequestHandler):
    """Answers like Chrome's DevTools endpoint: /json/version over HTTP, and an echoing WebSocket."""
    seen = []
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        FakeChrome.seen.append((self.path, self.headers.get("Host"), self.headers.get("Authorization")))
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.end_headers()
            self.wfile.flush()
            while data := self.connection.recv(1024):
                self.connection.sendall(data)
            return
        port = self.server.server_port
        body = json.dumps({"Browser": "Chrome/1", "webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/browser/abc"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class FakeMcp(BaseHTTPRequestHandler):
    """Answers like the bundled MCP server: only to its own Host, streaming the reply as server-sent events."""
    seen = []
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeMcp.seen.append((self.path, self.headers.get("Host"), self.headers.get("Authorization"),
                             self.headers.get("Connection"), body))
        if self.headers.get("Host") != self.server.expected_host:
            self.send_response(403)
            self.send_header("content-length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for part in (b"event: message\n", b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'):
            self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")

    def log_message(self, *_):
        pass


def serve(test, handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    return server


class CdpTests(unittest.TestCase):
    def setUp(self):
        FakeChrome.seen = []
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.grants = Path(tmp.name) / "grants.json"
        digest = lambda k: hashlib.sha256(k.encode()).hexdigest()
        self.grants.write_text(json.dumps({
            "claude": {"can": ["cdp"], "keys": [{"hash": digest("good-key"), "expires": None}]},
            "tomato": {"can": ["view"], "keys": [{"hash": digest("view-key"), "expires": None}]},
            "old": {"can": ["cdp"], "keys": [{"hash": digest("old-key"), "expires": 1}]},
            "helper": {"can": ["mcp"], "keys": [{"hash": digest("mcp-key"), "expires": None}]},
        }))
        FakeMcp.seen = []
        mcp = serve(self, FakeMcp)
        mcp.expected_host = f"localhost:{mcp.server_port}"
        chrome = serve(self, FakeChrome)
        self.chrome = f"127.0.0.1:{chrome.server_port}"
        settings = patch.multiple(gate, GRANTS=self.grants, CDP=self.chrome, BASE="https://browser.example",
                                  MCP=mcp.expected_host)
        settings.start()
        self.addCleanup(settings.stop)
        self.gate = serve(self, gate.Gate)

    def get(self, path, key=None):
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        req = urllib.request.Request(f"http://127.0.0.1:{self.gate.server_port}{path}", headers=headers)
        return urllib.request.urlopen(req)

    def status(self, path, key=None):
        try:
            with self.get(path, key) as res:
                return res.status
        except urllib.error.HTTPError as error:
            return error.code

    def test_a_key_with_cdp_reaches_the_browser_through_the_public_address(self):
        with self.get("/cdp/json/version", "good-key") as res:
            info = json.load(res)
        self.assertEqual(info["webSocketDebuggerUrl"], "wss://browser.example/cdp/devtools/browser/abc")
        self.assertEqual(FakeChrome.seen[-1], ("/json/version", self.chrome, None))

    def test_the_browser_refuses_without_a_valid_key(self):
        self.assertEqual(self.status("/cdp/json/version"), 401)
        self.assertEqual(self.status("/cdp/json/version", "wrong"), 401)
        self.assertEqual(self.status("/cdp/json/version", "old-key"), 401)

    def test_a_principal_without_cdp_is_refused(self):
        self.assertEqual(self.status("/cdp/json/version", "view-key"), 403)

    def test_a_revoked_principal_is_refused(self):
        grants = json.loads(self.grants.read_text())
        grants["claude"]["revoked"] = True
        self.grants.write_text(json.dumps(grants))
        self.assertEqual(self.status("/cdp/json/version", "good-key"), 401)

    def revoke(self, name):
        grants = json.loads(self.grants.read_text())
        grants[name]["revoked"] = True
        grants[name]["keys"] = []
        self.grants.write_text(json.dumps(grants))

    def open_websocket(self, key="good-key"):
        sock = socket.create_connection(("127.0.0.1", self.gate.server_port), timeout=5)
        sock.sendall(b"GET /cdp/devtools/browser/abc HTTP/1.1\r\nHost: browser.example\r\n"
                     b"Upgrade: websocket\r\nConnection: Upgrade\r\nAuthorization: Bearer " + key.encode() + b"\r\n\r\n")
        reply = b""
        while b"\r\n\r\n" not in reply:
            reply += sock.recv(1024)
        return sock, reply

    def test_mcp_requests_reach_the_bundled_server_as_its_own_host_without_the_key(self):
        body = b'{"jsonrpc":"2.0","id":1,"method":"initialize"}'
        req = urllib.request.Request(f"http://127.0.0.1:{self.gate.server_port}/mcp", data=body, method="POST",
                                     headers={"Authorization": "Bearer mcp-key", "content-type": "application/json"})
        with urllib.request.urlopen(req) as res:
            self.assertEqual(res.headers["content-type"], "text/event-stream")
            self.assertIn(b'"result"', res.read())
        path, host, auth, connection, sent = FakeMcp.seen[-1]
        self.assertEqual((path, host, auth, connection, sent), ("/mcp", self.gate_mcp_host(), None, "close", body))

    def gate_mcp_host(self):
        return gate.MCP

    def test_mcp_needs_the_mcp_ability(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.gate.server_port}/mcp", data=b"{}", method="POST",
                                     headers={"Authorization": "Bearer good-key"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(req)
        self.assertEqual(error.exception.code, 403)
        self.assertEqual(FakeMcp.seen, [])

    def test_revoking_closes_open_connections_at_once(self):
        sock, reply = self.open_websocket()
        self.assertTrue(reply.startswith(b"HTTP/1.1 101"))
        self.revoke("claude")
        gate.enforce()
        sock.settimeout(5)
        rest = b""
        try:
            while chunk := sock.recv(1024):
                rest += chunk
        except OSError:
            pass
        self.assertEqual(rest, b"")
        sock.close()

    def test_other_principals_stay_connected_when_one_is_revoked(self):
        sock, _ = self.open_websocket()
        self.revoke("helper")
        gate.enforce()
        sock.sendall(b"still")
        sock.settimeout(5)
        self.assertEqual(sock.recv(1024), b"still")
        sock.close()

    def test_websocket_is_carried_both_ways_without_the_key(self):
        with socket.create_connection(("127.0.0.1", self.gate.server_port), timeout=5) as sock:
            sock.sendall(b"GET /cdp/devtools/browser/abc HTTP/1.1\r\nHost: browser.example\r\n"
                         b"Upgrade: websocket\r\nConnection: Upgrade\r\nAuthorization: Bearer good-key\r\n\r\n")
            reply = b""
            while b"\r\n\r\n" not in reply:
                reply += sock.recv(1024)
            self.assertTrue(reply.startswith(b"HTTP/1.1 101"))
            sock.sendall(b"frame")
            echoed = reply.split(b"\r\n\r\n", 1)[1]
            while len(echoed) < 5:
                echoed += sock.recv(1024)
            self.assertEqual(echoed, b"frame")
        self.assertEqual(FakeChrome.seen[-1], ("/devtools/browser/abc", self.chrome, None))


if __name__ == "__main__":
    unittest.main()
