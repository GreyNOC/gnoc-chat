#!/usr/bin/env python3
"""A scope-gated session must not follow a redirect out of scope (offline, loopback only).

Before 2026-11-04, curl_cffi followed the 302 by default and lib_egress checked only the FIRST url:
server B (not in SCOPE.txt) was hit and its body came back to the caller as if it were server A's
answer. That is an out-of-scope request and a corrupted capture in one move. The session now returns
the 30x, and an opt-in follow re-gates EVERY hop before it is fetched.
"""
import http.server
import os
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from lib_egress import make_session, OutOfScope  # noqa: E402

try:   # curl_cffi is in requirements.txt; a checkout that skipped the install should skip these, not crash on them
    import curl_cffi  # noqa: F401
    HAVE_CURL_CFFI = True
except ImportError:
    HAVE_CURL_CFFI = False

HITS = []


class _A(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", f"http://127.0.0.2:{PORT_B}/landed")
        self.end_headers()

    def log_message(self, *a):
        pass


class _B(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OFF-SCOPE-BODY")

    def log_message(self, *a):
        pass


A = http.server.HTTPServer(("127.0.0.1", 0), _A)
B = http.server.HTTPServer(("127.0.0.2", 0), _B)
PORT_A, PORT_B = A.server_address[1], B.server_address[1]
for _srv in (A, B):
    threading.Thread(target=_srv.serve_forever, daemon=True).start()


def _scope(lines):
    fd, path = tempfile.mkstemp(suffix="SCOPE.txt")
    os.write(fd, ("\n".join(lines) + "\n").encode())
    os.close(fd)
    return path


@unittest.skipUnless(HAVE_CURL_CFFI, "curl_cffi is not installed (pip install -r requirements.txt)")
class Redirect(unittest.TestCase):
    def setUp(self):
        HITS.clear()

    def test_default_returns_the_30x_and_never_touches_the_off_scope_host(self):
        scope = _scope(["127.0.0.1"])
        try:
            r = make_session(scope).get(f"http://127.0.0.1:{PORT_A}/start")
        finally:
            os.unlink(scope)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(HITS, [], "the session followed the Location out of scope")

    def test_opt_in_follow_refuses_an_off_scope_hop_before_it_is_fetched(self):
        scope = _scope(["127.0.0.1"])
        try:
            with self.assertRaises(OutOfScope):
                make_session(scope, follow=True).get(f"http://127.0.0.1:{PORT_A}/start")
        finally:
            os.unlink(scope)
        self.assertEqual(HITS, [], "the refused hop was still fetched")

    def test_opt_in_follow_follows_an_in_scope_hop(self):
        scope = _scope(["127.0.0.1", "127.0.0.2"])
        try:
            r = make_session(scope, follow=True).get(f"http://127.0.0.1:{PORT_A}/start")
        finally:
            os.unlink(scope)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(HITS, ["/landed"])
        self.assertIn("OFF-SCOPE-BODY", r.text)

    def test_a_per_call_allow_redirects_is_still_gated(self):
        scope = _scope(["127.0.0.1"])
        try:
            with self.assertRaises(OutOfScope):
                make_session(scope).get(f"http://127.0.0.1:{PORT_A}/start", allow_redirects=True)
        finally:
            os.unlink(scope)
        self.assertEqual(HITS, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
