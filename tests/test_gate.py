import http.client
import importlib.util
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gate", Path(__file__).parents[1] / "gate.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

COOKIE = gate.COOKIE


class FakeScreen(BaseHTTPRequestHandler):
    """Stands in for the screen: answers like it does and remembers what it was asked."""
    seen = []
    peers = []

    def do_GET(self):
        self.reply(FakeScreen.peers if self.path == "/peers" else {})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        FakeScreen.seen.append((self.path, body, self.headers.get("Cookie")))
        self.reply({"id": "peer-1", "sdp": "v=0 offer", "iceServers": []} if self.path == "/offer" else {})

    def reply(self, body):
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class GateTests(unittest.TestCase):
    def setUp(self):
        FakeScreen.seen, FakeScreen.peers = [], []
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.links = Path(tmp.name) / "links.json"
        self.grants = Path(tmp.name) / "grants.json"
        self.grants.write_text(json.dumps({"tomato": {"can": ["view"], "keys": []}}))
        screen = self.serve(FakeScreen)
        settings = patch.multiple(gate, LINKS=self.links, GRANTS=self.grants, SESSIONS=Path(tmp.name) / "sessions.json",
                                  SCREEN=f"127.0.0.1:{screen.server_port}", BASE="")
        settings.start()
        self.addCleanup(settings.stop)
        gate.Gate.log_message = lambda *_: None
        self.port = self.serve(gate.Gate).server_port
        self.host = f"127.0.0.1:{self.port}"

    def serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def link(self, expires=None, who="tomato"):
        self.links.write_text(json.dumps([{"token": "one-time-token", "expires": expires or time.time() + 60, "as": who}]))
        return "/go/one-time-token"

    def request(self, method, path, cookie=None, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body, headers={**({"Cookie": cookie} if cookie else {}), **(headers or {})})
        res = conn.getresponse()
        reply = res.read().decode()
        conn.close()
        return res.status, {k.lower(): v for k, v in res.getheaders()}, reply

    def press(self, path, headers=None):
        """Press the link's button; returns the status and the session cookie it set, as a Cookie header value."""
        status, headers, _ = self.request("POST", path, headers=headers)
        return status, headers.get("set-cookie", "").split(";", 1)[0] or None, headers

    def revoke(self, name):
        grants = json.loads(self.grants.read_text())
        grants[name]["revoked"] = True
        self.grants.write_text(json.dumps(grants))

    def screen(self, path, cookie, body=None, origin=None):
        """What the viewer page sends to the screen through the gate."""
        headers = {"Origin": origin or f"http://{self.host}", "Content-Type": "application/json"}
        status, _, reply = self.request("POST", path, cookie, headers, json.dumps(body or {}))
        return status, reply

    # --- links ---

    def test_opening_a_link_shows_a_button_that_posts_back(self):
        status, _, page = self.request("GET", self.link())
        self.assertEqual(status, 200)
        self.assertIn('method="post"', page)
        self.assertIn('action="/go/one-time-token"', page)

    def test_link_previews_leave_the_link_usable(self):
        path = self.link()
        self.request("HEAD", path)
        self.request("GET", path)
        self.assertEqual(self.press(path)[0], 303)

    def test_pressing_the_button_starts_a_session_for_the_links_principal(self):
        status, cookie, headers = self.press(self.link())
        self.assertEqual((status, headers["location"]), (303, "/"))
        self.assertTrue(cookie.startswith(COOKIE + "="))
        self.assertEqual(json.loads(self.request("GET", "/whoami", cookie)[2]), {"name": "tomato"})

    def test_a_link_logs_in_only_once(self):
        path = self.link()
        self.press(path)
        status, cookie, _ = self.press(path)
        self.assertEqual((status, cookie), (404, None))

    def test_an_expired_link_is_refused(self):
        path = self.link(expires=time.time() - 1)
        self.assertEqual(self.request("GET", path)[0], 404)
        self.assertEqual(self.press(path)[0], 404)

    def test_a_session_holder_reopening_a_used_link_goes_to_the_viewer(self):
        path = self.link()
        _, cookie, _ = self.press(path)
        status, headers, _ = self.request("GET", path, cookie)
        self.assertEqual((status, headers["location"]), (302, "/"))

    def test_link_of_a_revoked_principal_does_not_log_in(self):
        path = self.link()
        self.revoke("tomato")
        self.assertEqual(self.press(path)[:2], (404, None))

    def test_link_of_a_principal_who_may_not_view_does_not_log_in(self):
        self.grants.write_text(json.dumps({"claude": {"can": ["cdp"], "keys": []}}))
        self.assertEqual(self.press(self.link(who="claude"))[:2], (404, None))

    # --- sessions ---

    def test_without_a_session_the_viewer_asks_for_a_link(self):
        self.assertEqual(self.request("GET", "/whoami")[0], 401)
        for path in ("/", "/anything"):
            status, _, page = self.request("GET", path)
            self.assertEqual(status, 401)
            self.assertIn("Open this browser with a link.", page)

    def test_the_viewer_is_a_page_showing_the_screen(self):
        _, cookie, _ = self.press(self.link())
        status, headers, page = self.request("GET", "/", cookie)
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("text/html"))
        self.assertIn("<title>Browser</title>", page)
        self.assertIn('<video id="screen"', page)

    def test_a_made_up_cookie_is_not_a_session(self):
        self.assertEqual(self.request("GET", "/whoami", f"{COOKIE}=guess")[0], 401)

    def test_revoking_a_principal_ends_its_sessions(self):
        _, cookie, _ = self.press(self.link())
        self.revoke("tomato")
        self.assertEqual(self.request("GET", "/whoami", cookie)[0], 401)

    def test_the_session_cookie_is_secure_only_behind_https(self):
        _, _, plain = self.press(self.link())
        self.assertNotIn("Secure", plain["set-cookie"])
        _, _, behind_https = self.press(self.link(), headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", behind_https["set-cookie"])
        self.assertIn("HttpOnly", behind_https["set-cookie"])

    # --- the screen ---

    def test_the_screen_is_reached_under_the_sessions_own_principal(self):
        _, cookie, _ = self.press(self.link())
        status, reply = self.screen("/screen", cookie, {"as": "someone-else"})
        self.assertEqual((status, json.loads(reply)["id"]), (200, "peer-1"))
        path, body, passed_cookie = FakeScreen.seen[-1]
        self.assertEqual((path, body["as"]), ("/offer", "tomato"))
        self.assertTrue(body["session"])
        self.assertIsNone(passed_cookie)

    def test_the_viewers_answer_reaches_the_screen_under_the_same_principal(self):
        _, cookie, _ = self.press(self.link())
        self.screen("/screen/answer", cookie, {"id": "peer-1", "sdp": "v=0 answer", "as": "someone-else"})
        self.assertEqual(FakeScreen.seen[-1][:2], ("/answer", {"id": "peer-1", "as": "tomato", "sdp": "v=0 answer"}))

    def test_the_viewer_can_hang_up(self):
        _, cookie, _ = self.press(self.link())
        self.screen("/screen/close", cookie, {"id": "peer-1"})
        self.assertEqual(FakeScreen.seen[-1][:2], ("/close", {"id": "peer-1", "as": "tomato"}))

    def test_the_screen_refuses_without_a_session(self):
        self.assertEqual(self.screen("/screen", f"{COOKIE}=guess")[0], 401)
        self.assertEqual(FakeScreen.seen, [])

    def test_the_screen_refuses_a_request_started_by_another_site(self):
        _, cookie, _ = self.press(self.link())
        self.assertEqual(self.screen("/screen", cookie, origin="https://elsewhere.example")[0], 403)
        self.assertEqual(FakeScreen.seen, [])

    def test_revoking_closes_the_screen_connection_at_once(self):
        _, cookie, _ = self.press(self.link())
        self.screen("/screen", cookie)
        session = FakeScreen.seen[-1][1]["session"]
        FakeScreen.peers = [{"id": "peer-1", "as": "tomato", "session": session}]
        gate.enforce()
        self.assertNotIn("/close", [path for path, _, _ in FakeScreen.seen])
        self.revoke("tomato")
        gate.enforce()
        self.assertEqual(FakeScreen.seen[-1][:2], ("/close", {"id": "peer-1"}))


if __name__ == "__main__":
    unittest.main()
