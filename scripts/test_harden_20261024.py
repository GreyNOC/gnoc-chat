"""Tests for paid_budget, llm_endpoints health/failover, lane_egress_audit (stdlib unittest, no network, temp dirs)."""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import paid_budget  # noqa: E402
import llm_endpoints  # noqa: E402
import lane_egress_audit as lea  # noqa: E402


class PaidBudget(unittest.TestCase):
    def test_cap_month_rollover_and_single_daily_notice(self):
        with tempfile.TemporaryDirectory() as r, mock.patch.dict(os.environ, {"PAID_RUNS_MONTHLY_CAP": "2"}):
            d = datetime(2026, 10, 24, 9)
            self.assertEqual(paid_budget.reserve(r, "a", d)[0:2], (True, 1))
            self.assertEqual(paid_budget.reserve(r, "b", d)[0:2], (True, 2))
            self.assertFalse(paid_budget.reserve(r, "c", d)[0])
            self.assertFalse(paid_budget.reserve(r, "d", d)[0])
            ib = open(os.path.join(r, ".claude/state/orch/INBOX.md")).read()
            self.assertEqual(ib.count("PAID-BUDGET"), 1)
            st = json.load(open(os.path.join(r, ".claude/state/orch/paid-budget.json")))
            self.assertEqual((st["month"], st["runs"], st["cap"]), ("2026-10", 2, 2))
            self.assertFalse(paid_budget.reserve(r, "e", datetime(2026, 10, 25))[0])
            self.assertEqual(open(os.path.join(r, ".claude/state/orch/INBOX.md")).read().count("PAID-BUDGET"), 2)
            self.assertEqual(paid_budget.reserve(r, "f", datetime(2026, 11, 1))[0:2], (True, 1))

    def test_default_cap(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PAID_RUNS_MONTHLY_CAP", None)
            self.assertEqual(paid_budget.cap_from_env(), 120)

    def test_wallclock_cap_kills_and_notes(self):
        with tempfile.TemporaryDirectory() as r:
            rc = paid_budget.run_capped(["sleep", "30"], 0.5, "unit", r)
            self.assertEqual(rc, 124)
            self.assertIn("PAID-CAPPED", open(os.path.join(r, ".claude/state/orch/INBOX.md")).read())


class Health(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = mock.patch.object(llm_endpoints, "HEALTH_FILE", os.path.join(self.d, "h.json"))
        self.p.start()
        # a three-machine setup: the operator's machine.json sets the desktop and the phone, a fresh install
        # has neither, and an unset host is never probed (it is not part of the setup)
        self.h = mock.patch.dict(llm_endpoints.HOSTS, {"desktop": "desktop.invalid:11434",
                                                       "phone": "phone.invalid:11434"})
        self.h.start()

    def tearDown(self):
        self.h.stop()
        self.p.stop()

    def test_three_failures_trip_with_backoff(self):
        t = 1000.0
        self.assertFalse(llm_endpoints.record("desktop", False, t))
        self.assertFalse(llm_endpoints.record("desktop", False, t))
        self.assertTrue(llm_endpoints.record("desktop", False, t))
        self.assertTrue(llm_endpoints.is_down("desktop", t + 599))
        self.assertFalse(llm_endpoints.is_down("desktop", t + 601))
        for _ in range(3):
            llm_endpoints.record("desktop", False, t + 700)
        self.assertTrue(llm_endpoints.is_down("desktop", t + 700 + 1100))   # second trip = 20 min
        for _ in range(9):
            llm_endpoints.record("desktop", False, t + 5000)
        h = json.load(open(llm_endpoints.HEALTH_FILE))["desktop"]
        self.assertLessEqual(h["down_until"] - (t + 5000), 3600)
        llm_endpoints.record("desktop", True, t + 9000)
        self.assertFalse(llm_endpoints.is_down("desktop", t + 9000))

    def test_up_benches_a_black_hole_instead_of_waiting_on_it(self):
        """A dead reverse tunnel ACCEPTS the connection and never answers, so up()'s patient 2 s + 6 s ladder
        burned 4.1 s per call and `gnoc chat` sat silent for 8 s before its first line (2026-10-26). up() now
        feeds the trip ledger and, once the host is benched, spends ONE 0.6 s sniff - which still lets it come
        back by itself."""
        waited = []

        def black_hole(url, timeout=None):
            waited.append(timeout)
            raise TimeoutError("accepted, never answered")

        L = llm_endpoints
        L._health.clear()
        with mock.patch.object(L.urllib.request, "urlopen", side_effect=black_hole):
            for _ in range(3):                      # three probes trip the bench
                L._health.clear()
                self.assertFalse(L.up("desktop"))
            self.assertTrue(L.is_down("desktop"))
            self.assertEqual(waited, [2, 6, 2, 6, 2, 6])
            waited.clear()
            L._health.clear()
            self.assertFalse(L.up("desktop"))
            self.assertEqual(waited, [0.6])         # benched: one sniff, not the ladder

        answered = mock.MagicMock()
        answered.__enter__ = lambda s: mock.Mock(status=200)
        answered.__exit__ = lambda *a: False
        L._health.clear()
        with mock.patch.object(L.urllib.request, "urlopen", return_value=answered):
            self.assertTrue(L.up("desktop"))        # the sniff is how a benched host recovers
        self.assertFalse(L.is_down("desktop"))      # and a success clears the bench

    def test_up_on_an_unknown_host_key_still_never_raises(self):
        llm_endpoints._health.clear()
        self.assertFalse(llm_endpoints.up("nosuchhost"))

    def test_pick_order_and_skip_down(self):
        up = {"desktop": False, "local": True, "phone": True}
        with mock.patch.object(llm_endpoints, "probe", side_effect=lambda h, timeout=2: up[h]), \
                mock.patch.object(llm_endpoints, "sniff", side_effect=lambda h, timeout=0.6: up[h]):
            self.assertEqual(llm_endpoints.pick(), "local")
            up["desktop"] = True
            self.assertEqual(llm_endpoints.pick(), "desktop")
            for _ in range(3):
                llm_endpoints.record("desktop", False)
            up["desktop"] = False
            self.assertEqual(llm_endpoints.pick(), "local")      # benched and silent: skipped
            up["desktop"] = True
            self.assertEqual(llm_endpoints.pick(), "desktop")    # benched but answering again: one quick probe, back
            for _ in range(3):
                llm_endpoints.record("desktop", False)
            up["desktop"] = False
            up["local"] = False
            self.assertEqual(llm_endpoints.pick(), "phone")
            up["phone"] = False
            self.assertIsNone(llm_endpoints.pick())

    def test_failover_healthy_desktop_is_plain_resolve(self):
        roles = {"brain": "bigmodel-abliterated@desktop"}
        with mock.patch.object(llm_endpoints, "roles", return_value=roles), \
                mock.patch.object(llm_endpoints, "pick", return_value="desktop"), \
                mock.patch.object(llm_endpoints, "resolve", return_value=("u", "m", "desktop")) as rs:
            self.assertEqual(llm_endpoints.failover("brain"), ("u", "m", "desktop"))
            rs.assert_called_once()

    def test_failover_to_laptop_and_non_desktop_role(self):
        roles = {"brain": "bigmodel-abliterated@desktop"}
        with mock.patch.object(llm_endpoints, "roles", return_value=roles), \
                mock.patch.object(llm_endpoints, "pick", return_value="local"), \
                mock.patch.object(llm_endpoints, "stock", return_value=False):
            url, model, host = llm_endpoints.failover("brain")
            self.assertEqual((host, model), ("local", llm_endpoints.DEFAULT))
            self.assertIn(llm_endpoints.HOSTS["local"], url)
        with mock.patch.object(llm_endpoints, "roles", return_value={"brain": "x"}), \
                mock.patch.object(llm_endpoints, "resolve", return_value=("u", "x", "local")):
            self.assertEqual(llm_endpoints.failover("brain")[2], "local")


class LaneAudit(unittest.TestCase):
    def _w(self, d, name, lines):
        p = os.path.join(d, name)
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        return p

    def test_clean_denied_and_bypass(self):
        with tempfile.TemporaryDirectory() as r:
            ok = self._w(r, "ok.jsonl", [json.dumps({"host": "a.in.example", "port": 443, "allowed": True}),
                                         json.dumps({"host": "x", "port": 1, "allowed": False, "reason": "dns-fail"})])
            cmds = self._w(r, "commands.txt", ["t1 T1 GET https://a.in.example/x -> 200 10"])
            self.assertEqual(lea.main(["p", ok, "--commands", cmds, "--fired", "1", "--root", r]), 0)
            self.assertFalse(lea.paused(r, "p"))
            bad = self._w(r, "bad.jsonl", [json.dumps({"host": "evil.example", "port": 443, "allowed": False,
                                                         "reason": "not-in-scope"})])
            self.assertEqual(lea.main(["p", bad, "--root", r]), 1)
            self.assertTrue(lea.paused(r, "p"))
            self.assertEqual(lea.main(["--paused", "p", "--root", r]), 0)
            self.assertIn("lane egress audit FAIL", open(os.path.join(r, ".claude/state/hunt-loop/SCOPE-INCIDENTS.md")).read())
            self.assertIn("SCOPE", open(os.path.join(r, ".claude/state/orch/INBOX.md")).read())
            self.assertEqual(lea.main(["--paused", "other", "--root", r]), 1)
        with tempfile.TemporaryDirectory() as r:
            e = self._w(r, "e.jsonl", [json.dumps({"host": "a.in.example", "allowed": True})])
            cmds = self._w(r, "c.txt", ["t GET https://b.out.example/ -> 200 1"])
            self.assertEqual(lea.main(["q", e, "--commands", cmds, "--fired", "1", "--root", r]), 1)


if __name__ == "__main__":
    unittest.main()
