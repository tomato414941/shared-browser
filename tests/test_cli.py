import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

CLI = Path(__file__).parents[1] / "shared-browser"


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        shutil.copy(CLI, self.root / "shared-browser")
        self.profile = self.root / "profile"
        self.run_cli("new", "b", f"SB_PROFILE_DIR={self.profile}", "SB_VIEWER_URL=https://browser.example")

    def run_cli(self, *args, ok=True):
        res = subprocess.run([str(self.root / "shared-browser"), *args], capture_output=True, text=True)
        if ok:
            self.assertEqual(res.returncode, 0, res.stderr)
        return res

    def grants(self):
        return json.loads((self.profile / "grants.json").read_text())

    def test_granting_cdp_prints_a_key_once_and_keeps_only_its_hash(self):
        out = json.loads(self.run_cli("grant", "b", "--as", "claude", "--can", "cdp").stdout)
        self.assertTrue(out["key"].startswith("sb_"))
        stored = self.grants()["claude"]
        self.assertEqual(stored["can"], ["cdp"])
        self.assertEqual(stored["keys"][0]["hash"], hashlib.sha256(out["key"].encode()).hexdigest())
        self.assertNotIn(out["key"], (self.profile / "grants.json").read_text())
        self.assertEqual((self.profile / "grants.json").stat().st_mode & 0o777, 0o600)

    def test_granting_only_view_issues_no_key(self):
        out = json.loads(self.run_cli("grant", "b", "--as", "tomato", "--can", "view").stdout)
        self.assertNotIn("key", out)

    def test_revoking_drops_the_keys(self):
        self.run_cli("grant", "b", "--as", "claude", "--can", "cdp")
        self.run_cli("revoke", "b", "--as", "claude")
        self.assertEqual(self.grants()["claude"]["keys"], [])
        self.assertTrue(self.grants()["claude"]["revoked"])

    def test_a_link_registers_its_principal_as_a_viewer(self):
        link = self.run_cli("link", "b", "--as", "tomato").stdout.strip()
        self.assertTrue(link.startswith("https://browser.example/go/"))
        self.assertEqual(self.grants()["tomato"]["can"], ["view"])

    def test_no_link_for_a_revoked_principal(self):
        self.run_cli("grant", "b", "--as", "tomato", "--can", "view")
        self.run_cli("revoke", "b", "--as", "tomato")
        self.assertNotEqual(self.run_cli("link", "b", "--as", "tomato", ok=False).returncode, 0)

    def test_endpoint_gives_the_cdp_address_under_the_viewer(self):
        out = json.loads(self.run_cli("endpoint", "b").stdout)
        self.assertEqual(out["cdp_url"], "https://browser.example/cdp")

    def config(self, name):
        return dict(line.split("=", 1) for line in self.run_cli("config", name).stdout.splitlines())

    def test_a_new_instance_assumes_no_network_and_discovers_addresses_through_stun(self):
        self.run_cli("new", "c", f"SB_PROFILE_DIR={self.root / 'c'}")
        env = (self.root / "instances" / "c.env").read_text()
        self.assertIn("SB_PUBLIC_IP=\n", env)
        self.assertIn("SB_WEBRTC_BIND=0.0.0.0", env)
        conf = self.config("c")
        self.assertEqual(conf["SB_ICE_LITE"], "0")
        self.assertIn("stun:", conf["SB_ICE_SERVERS"])

    def test_a_known_public_address_turns_on_ice_lite(self):
        self.run_cli("new", "d", f"SB_PROFILE_DIR={self.root / 'd'}", "SB_PUBLIC_IP=203.0.113.5")
        conf = self.config("d")
        self.assertEqual((conf["SB_ICE_LITE"], conf["SB_ICE_SERVERS"]), ("1", "[]"))

    def test_cookies_are_secure_only_behind_https(self):
        self.assertEqual(self.config("b")["SB_COOKIE_SECURE"], "true")
        self.run_cli("new", "e", f"SB_PROFILE_DIR={self.root / 'e'}")
        self.assertEqual(self.config("e")["SB_COOKIE_SECURE"], "false")
        self.run_cli("new", "f", f"SB_PROFILE_DIR={self.root / 'f'}", "SB_COOKIE_SECURE=true")
        self.assertEqual(self.config("f")["SB_COOKIE_SECURE"], "true")

    def test_endpoint_says_what_to_reach_and_whether_a_front_is_set(self):
        out = json.loads(self.run_cli("endpoint", "b").stdout)
        self.assertTrue(out["viewer_url_is_set"])
        self.assertTrue(out["viewer_local_url"].startswith("http://127.0.0.1:"))
        self.assertEqual(out["webrtc_bind"], "0.0.0.0")
        self.assertIsNone(out["public_ip"])

    def test_unknown_abilities_are_refused(self):
        self.assertNotEqual(self.run_cli("grant", "b", "--as", "x", "--can", "root", ok=False).returncode, 0)


if __name__ == "__main__":
    unittest.main()
