import http.cookiejar
import importlib.util
import json
import tempfile
import threading
import time
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


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.links = Path(self.tmp.name) / "links.json"
        self.logins = 0
        self.neko_ready = True
        test = self

        class Backend(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/whoami" and self.headers.get("Cookie") == "shared_browser_test=active":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"profile":{"name":"viewer"}}')
                else:
                    self.send_error(401)

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if not test.neko_ready:
                    self.send_error(502)
                    return
                if self.path != "/api/login" or data.get("password") != "test-password":
                    self.send_error(401)
                    return
                test.logins += 1
                self.send_response(200)
                self.send_header("Set-Cookie", "shared_browser_test=active; Path=/; HttpOnly")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *_):
                pass

        self.backend = self.serve(Backend)

        class ViewerGate(gate.Gate):
            def do_GET(self):
                if self.path == "/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"viewer")
                else:
                    super().do_GET()

        self.server = self.serve(ViewerGate)
        self.root = f"http://127.0.0.1:{self.server.server_port}"
        self.grants = Path(self.tmp.name) / "grants.json"
        self.grants.write_text(json.dumps({"viewer": {"can": ["view"], "keys": []}}))
        self.settings = patch.multiple(
            gate, LINKS=self.links, GRANTS=self.grants, NEKO=f"http://127.0.0.1:{self.backend.server_port}"
        )
        self.settings.start()
        self.addCleanup(self.settings.stop)
        self.addCleanup(self.tmp.cleanup)
        self.cookies = http.cookiejar.CookieJar()
        self.browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookies))

    def serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def link(self, expires=None):
        self.links.write_text(json.dumps([{
            "token": "one-time-token", "expires": expires or time.time() + 60, "as": "viewer"
        }]))
        return self.root + "/go/one-time-token"

    def press(self, url):
        return self.browser.open(urllib.request.Request(url, data=b"", method="POST"))

    def test_opening_a_link_shows_a_button_that_posts_back(self):
        with self.browser.open(self.link()) as response:
            page = response.read().decode()
        self.assertIn('method="post"', page)
        self.assertIn('action="/go/one-time-token"', page)
        self.assertEqual(self.logins, 0)

    def test_link_previews_leave_the_link_usable(self):
        url = self.link()
        self.browser.open(urllib.request.Request(url, method="HEAD")).close()
        self.browser.open(url).close()
        with self.press(url) as response:
            self.assertEqual(response.geturl(), self.root + "/")
        self.assertEqual(self.logins, 1)

    def test_pressing_the_button_creates_a_viewer_session(self):
        with self.press(self.link()) as response:
            self.assertEqual(response.geturl(), self.root + "/")
            self.assertEqual(response.read(), b"viewer")
        self.assertEqual(self.logins, 1)
        self.assertEqual([c.name for c in self.cookies], ["shared_browser_test"])

    def test_a_link_logs_in_only_once(self):
        url = self.link()
        self.press(url).close()
        self.cookies.clear()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.press(url)
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(self.logins, 1)

    def test_link_stays_usable_when_the_browser_is_not_ready(self):
        url = self.link()
        self.neko_ready = False
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.press(url)
        self.assertEqual(error.exception.code, 503)
        self.neko_ready = True
        with self.press(url) as response:
            self.assertEqual(response.geturl(), self.root + "/")
        self.assertEqual(self.logins, 1)

    def test_authenticated_viewer_reopens_a_used_link(self):
        url = self.link()
        self.press(url).close()
        for _ in range(2):
            with self.browser.open(url) as response:
                self.assertEqual(response.geturl(), self.root + "/")
                self.assertEqual(response.read(), b"viewer")
        self.assertEqual(self.logins, 1)

    def test_authenticated_viewer_reopens_an_expired_link(self):
        url = self.link()
        self.press(url).close()
        self.link(expires=time.time() - 1)
        with self.browser.open(url) as response:
            self.assertEqual(response.geturl(), self.root + "/")
        self.assertEqual(self.logins, 1)

    def test_link_of_a_revoked_principal_does_not_log_in(self):
        url = self.link()
        self.grants.write_text(json.dumps({"viewer": {"can": ["view"], "keys": [], "revoked": True}}))
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.press(url)
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(self.logins, 0)

    def test_signed_out_viewer_needs_a_fresh_link(self):
        url = self.link()
        self.press(url).close()
        self.cookies.clear()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.browser.open(url)
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(error.exception.headers["Cache-Control"], "no-store")
        self.assertEqual(self.logins, 1)

    def test_expired_session_needs_a_fresh_link(self):
        req = urllib.request.Request(self.link(time.time() - 1), headers={"Cookie": "shared_browser_test=expired"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.browser.open(req)
        self.assertEqual(error.exception.code, 404)
        self.assertEqual(self.logins, 0)


if __name__ == "__main__":
    unittest.main()
