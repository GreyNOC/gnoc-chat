"""lane_egress_audit: a denied TOOLCHAIN host (the worker CLI phoning its own registry through the lane proxy) is
contained, not a violation; a denied unknown host still fails; a dns-fail never fails."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lane_egress_audit as A  # noqa: E402


def _egress(td, rows):
    p = os.path.join(td, "egress.jsonl")
    with open(p, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    return p


class Audit(unittest.TestCase):
    def test_denied_toolchain_host_is_not_a_violation(self):
        with tempfile.TemporaryDirectory() as td:
            e = _egress(td, [{"host": "models.opencode.ai", "port": 443, "allowed": False, "reason": "not-in-scope"},
                             {"host": "api.example.com", "port": 443, "allowed": True, "reason": "ok"}])
            denied, bypassed = A.audit(e)
        self.assertEqual(denied, [])
        self.assertEqual(bypassed, [])

    def test_denied_unknown_host_still_fails(self):
        with tempfile.TemporaryDirectory() as td:
            e = _egress(td, [{"host": "evil.example.net", "port": 443, "allowed": False, "reason": "not-in-scope"}])
            denied, _ = A.audit(e)
        self.assertEqual(denied, ["evil.example.net:443 (not-in-scope)"])

    def test_dns_fail_never_fails(self):
        with tempfile.TemporaryDirectory() as td:
            e = _egress(td, [{"host": "x.example.com", "port": 443, "allowed": False, "reason": "dns-fail"}])
            self.assertEqual(A.audit(e)[0], [])

    def test_toolchain_matcher(self):
        self.assertTrue(A.toolchain("models.opencode.ai"))
        self.assertTrue(A.toolchain("hf.co"))
        self.assertFalse(A.toolchain("opencode.ai.example.com"))
        self.assertFalse(A.toolchain(""))


if __name__ == "__main__":
    unittest.main()
