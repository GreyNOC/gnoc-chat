import io, json, os, re, sys, tempfile, unittest, urllib.error
from unittest import mock
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_oast as O


class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def cfgfile(text):
    f = tempfile.NamedTemporaryFile("w", suffix=".env", delete=False)
    f.write(text); f.close()
    return f.name


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ws, self.env, self.dis = O.WS, O.OOB_ENV, O._site_disabled
        O.WS = self.tmp
        O._site_disabled = False
        O.OOB_ENV = cfgfile("GNOC_OOB_SECRET=s3cretvalue\nGNOC_OOB_BASE=https://x.test/\n")
        self.p1 = mock.patch.object(O, "start", return_value=("dom.oast.test", "ok"))
        self.p1.start()

    def tearDown(self):
        self.p1.stop()
        O.WS, O.OOB_ENV, O._site_disabled = self.ws, self.env, self.dis

    def test_token_and_url(self):
        t = O._mint_token()
        self.assertRegex(t, r"^g[A-Za-z0-9]{24}$")
        pr = O.new_probe("p")
        self.assertEqual(pr["dns_host"], f"{pr['tag']}.dom.oast.test")
        tok = O._state("p")["tags"][pr["tag"]]["site_token"]
        self.assertEqual(pr["http_url"], f"https://x.test/oob/{tok}/{pr['tag']}")
        self.assertNotIn("s3cretvalue", json.dumps(pr))

    def test_hit_mapping_and_poll(self):
        pr = O.new_probe("p")
        body = {"hits": [{"at": "2026-10-24T01:02:03Z", "method": "GET", "path": "/oob/x/y", "ip": "9.9.9.9",
                          "headers": {"user-agent": "curl"}, "body": ""}]}
        seen = {}
        def fake(req, timeout=0):
            seen["auth"] = req.headers.get("Authorization"); seen["to"] = timeout; seen["url"] = req.full_url
            return Resp(json.dumps(body).encode())
        with mock.patch("urllib.request.urlopen", fake):
            out = O.poll("p", pr["tag"])
        self.assertEqual(seen["to"], 10)
        self.assertTrue(seen["url"].startswith("https://x.test/api/oob/g"))
        self.assertEqual(seen["auth"], "Bearer s3cretvalue")
        self.assertIn("1 callback(s) HTTP", out)
        self.assertIn("[site]", out)
        self.assertIn("from 9.9.9.9", out)
        rows = O._site_hits("p", O._state("p")["tags"][pr["tag"]]["site_token"]) if False else None

    def test_row_shape(self):
        h = {"hits": [{"at": "t", "method": "POST", "path": "/p", "ip": "1.1.1.1", "headers": {"host": "h"}, "body": "b"}]}
        with mock.patch("urllib.request.urlopen", lambda r, timeout=0: Resp(json.dumps(h).encode())):
            rows = O._site_hits("p", "gabcdefghij")
        r = rows[0]
        self.assertEqual((r["source"], r["protocol"], r["remote-address"], r["timestamp"]), ("site", "http", "1.1.1.1", "t"))
        self.assertTrue(r["raw-request"].startswith("POST /p"))

    def test_401_disables_once(self):
        calls = []
        def fake(req, timeout=0):
            calls.append(1)
            raise urllib.error.HTTPError(req.full_url, 401, "no", {}, None)
        with mock.patch("urllib.request.urlopen", fake):
            self.assertEqual(O._site_hits("p", "gabcdefghij"), [])
            self.assertEqual(O._site_hits("p", "gabcdefghij"), [])
        self.assertEqual(len(calls), 1)
        self.assertTrue(O._site_disabled)
        self.assertIn("401", open(os.path.join(O._dir("p"), "client.log")).read())
        self.assertNotIn("s3cretvalue", open(os.path.join(O._dir("p"), "client.log")).read())

    def test_network_error_returns_empty(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")):
            self.assertEqual(O._site_hits("p", "gabcdefghij"), [])

    def test_unconfigured_unchanged(self):
        O.OOB_ENV = "/nonexistent/gnoc-oob.env"
        pr = O.new_probe("p")
        self.assertIsNone(pr["http_url"])
        self.assertTrue(pr["dns_host"])
        self.assertNotIn("site_token", O._state("p")["tags"][pr["tag"]])
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            out = O.poll("p", pr["tag"])
        self.assertIn("no callback yet", out)
        O.OOB_ENV = cfgfile("GNOC_OOB_BASE=https://x.test\n")  # no secret
        self.assertIsNone(O._site_cfg())

    def test_selftest_unconfigured(self):
        O.OOB_ENV = "/nonexistent"
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            self.assertEqual(O._selftest(), 0)
        self.assertIn("site backend not configured", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
