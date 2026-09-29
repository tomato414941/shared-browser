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

with patch.dict("os.environ", {"GATE_PASSWORD": "test-password"}):
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
        }))
        chrome = serve(self, FakeChrome)
        self.chrome = f"127.0.0.1:{chrome.server_port}"
        settings = patch.multiple(gate, GRANTS=self.grants, CDP=self.chrome, BASE="https://browser.example")
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
