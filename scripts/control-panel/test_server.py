import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
os.environ.pop("CONTROL_PANEL_ALLOW_SHELL", None)
import server  # noqa: E402

GOOD = {"Host": "127.0.0.1:8787", "X-Panel-Token": server.PANEL_TOKEN}
JSON = {"Content-Type": "application/json"}


class PanelAuth(unittest.TestCase):
    def setUp(self):
        self.c = server.app.test_client()

    def test_no_token(self):
        self.assertEqual(self.c.get("/api/ping", headers={"Host": "127.0.0.1:8787"}).status_code, 403)

    def test_wrong_token(self):
        h = dict(GOOD, **{"X-Panel-Token": "x" * 64})
        self.assertEqual(self.c.get("/api/ping", headers=h).status_code, 403)

    def test_good(self):
        self.assertEqual(self.c.get("/api/ping", headers=GOOD).status_code, 200)
        self.assertEqual(self.c.get("/api/ping", headers=dict(GOOD, Host="localhost:8787")).status_code, 200)

    def test_bad_host(self):
        self.assertEqual(self.c.get("/api/ping", headers=dict(GOOD, Host="evil.example:8787")).status_code, 403)

    def test_evil_origin(self):
        self.assertEqual(self.c.get("/api/ping", headers=dict(GOOD, Origin="http://evil.example")).status_code, 403)

    def test_cross_site_fetch(self):
        self.assertEqual(self.c.get("/api/ping", headers=dict(GOOD, **{"Sec-Fetch-Site": "cross-site"})).status_code, 403)

    def test_text_plain_post(self):
        r = self.c.post("/api/exec", data='{"cmd":"models"}', headers=dict(GOOD, **{"Content-Type": "text/plain"}))
        self.assertIn(r.status_code, (403, 415))

    def test_shell_escape_off(self):
        r = self.c.post("/api/exec", json={"cmd": "!id"}, headers=GOOD)
        self.assertEqual(r.status_code, 403)

    def test_bad_chars_rejected(self):
        r = self.c.post("/api/exec", json={"cmd": "models; id"}, headers=GOOD)
        self.assertEqual(r.status_code, 400)

    def test_non_dict_body(self):
        r = self.c.post("/api/exec", data="[1]", headers=dict(GOOD, **JSON))
        self.assertEqual(r.get_json()["err"], "empty command")


class PanelPage(unittest.TestCase):
    def setUp(self):
        self.c = server.app.test_client()

    def test_same_origin_gets_token(self):
        r = self.c.get("/", headers={"Host": "127.0.0.1:8787", "Sec-Fetch-Site": "none"})
        self.assertIn(b'<meta name="panel-token"', r.data)
        self.assertIn(server.PANEL_TOKEN.encode(), r.data)

    def test_cross_site_no_token(self):
        r = self.c.get("/", headers={"Host": "127.0.0.1:8787", "Sec-Fetch-Site": "cross-site"})
        self.assertNotIn(server.PANEL_TOKEN.encode(), r.data)
        self.assertNotIn(b'<meta name="panel-token"', r.data)

    def test_bad_origin_or_host_no_token(self):
        for h in ({"Host": "127.0.0.1:8787", "Origin": "http://evil.example"}, {"Host": "evil.example"}):
            self.assertNotIn(server.PANEL_TOKEN.encode(), self.c.get("/", headers=h).data)


if __name__ == "__main__":
    unittest.main()
