"""Regression tests for the 2026-11-27 "get a CVSS 10" exchange against their own site.

What went wrong, from the saved session (.claude/state/orch/agent/sessions/20261127-015950-*.json):
  - the goal's hint said "(/stop off, then /goal resume)"; no /stop existed, so "/stop OFF" was an unknown command;
  - the drill said "NOTE: the loud burst was NOT run" as its LAST line and the lead answered "the loud burst was run
    this time - rate limits tested", three times;
  - the limits skip line said "re-run with confirm=true", so every "continue" re-sent confirm=true;
  - site_status said "posture 100/100, every posture check passes" beside a drill that had just failed edge HSTS,
    and the lead squared the two with "the edge must have been updated";
  - three identical drills in a row were each announced as news;
  - a refused fan-out brief ("...or call {bad} yourself.") reached the lead as BOT FINDINGS, with "say which bot
    found what", and the lead credited a bot that never ran.
"""
import ast
import glob
import os
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ["GNOC_REDTEAM_LAST"] = os.path.join(tempfile.mkdtemp(prefix="gnoc-rtlast-"), "last.json")
import gnoc_redteam as R  # noqa: E402
import gnoc_site  # noqa: E402
import gnoc_agent as G  # noqa: E402


def _legacy_commands():
    src = open(os.path.join(HERE, "gnoc"), encoding="utf-8").read()
    return set(re.findall(r'"([a-z]+)":', src.split("legacy = {", 1)[1].split("}", 1)[0]))


class HintedCommandsExist(unittest.TestCase):
    def test_stop_is_a_command(self):
        self.assertIn("stop", _legacy_commands())

    def test_every_slash_command_a_hint_names_exists(self):
        from gnoc_core.commands import builtin_command_names
        known = builtin_command_names(_legacy_commands())
        missing = {}
        for f in glob.glob(os.path.join(HERE, "gnoc_core", "*.py")) + glob.glob(os.path.join(HERE, "gnoc_tools", "*.py")):
            for n in ast.walk(ast.parse(open(f, encoding="utf-8").read())):
                if isinstance(n, ast.Constant) and isinstance(n.value, str):
                    # "(/goal resume)" and "· /goal pause parks it": the two shapes the status hints use
                    for a, b in re.findall(r"\(/([a-z][a-z0-9-]+)(?=[ ,)])|·\s+/([a-z][a-z0-9-]+)(?=[ ,)])", n.value):
                        name = a or b
                        if name not in known:
                            missing.setdefault(name, os.path.basename(f))
        self.assertEqual(missing, {}, "a hint tells them to type a command that does not exist")


class LoudBurstRefusalIsUnmissable(unittest.TestCase):
    def test_the_refusal_is_the_first_thing_the_lead_reads(self):
        ctx = types.SimpleNamespace(program=None, s={"_turn_text": "continue"})
        with mock.patch.object(R, "summary", side_effect=lambda c, confirm, area=None: "DRILL rt-x ran\nNOT RUN: x"):
            out = G.TOOLS["site_redteam"][0](ctx, confirm=True)
        self.assertTrue(out.startswith("RATE LIMITS WERE NOT TESTED THIS TURN"), out[:120])
        self.assertIn("loud burst was NOT run", out)

    def test_the_skip_line_does_not_invite_a_confirm_loop(self):
        f = R.check_limits("http://127.0.0.1:6969", "ua", "h", confirm=False)[0]
        self.assertEqual(f["status"], "skipped")
        self.assertNotIn("re-run with confirm=true", f["evidence"])
        self.assertIn("their own words", f["evidence"])


class RepeatDrill(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="gnoc-rtlast-"), "last.json")
        p = mock.patch.dict(os.environ, {"GNOC_REDTEAM_LAST": self.path})
        p.start()
        self.addCleanup(p.stop)

    def _summary(self, rid, findings):
        with mock.patch.object(R, "run", return_value=(f"DRILL {rid} ran against your-site.example", findings)):
            return R.summary()

    def test_an_identical_second_drill_says_it_is_not_news(self):
        f = [R._finding("edge.hsts", "HSTS as the browser sees it", "medium", "FAIL", "max-age=0", "Turn HSTS on"),
             R._finding("headers.csp", "CSP", "info", "pass", "ok")]
        first = self._summary("rt-aaaaaa", f)
        self.assertNotIn("SAME RESULT", first)
        second = self._summary("rt-bbbbbb", [dict(x, evidence=x["evidence"] + " (222 ms)") for x in f])
        self.assertIn("SAME RESULT as drill rt-aaaaaa", second)
        self.assertIn("change on their side", second)

    def test_a_changed_result_is_news(self):
        self._summary("rt-aaaaaa", [R._finding("edge.hsts", "HSTS", "medium", "FAIL", "max-age=0")])
        out = self._summary("rt-bbbbbb", [R._finding("edge.hsts", "HSTS", "info", "pass", "max-age=31536000")])
        self.assertNotIn("SAME RESULT", out)

    def test_the_drill_is_remembered_with_its_failures(self):
        self._summary("rt-cccccc", [R._finding("edge.hsts", "HSTS", "medium", "FAIL", "max-age=0", "Turn HSTS on")])
        rec = gnoc_site.last_drill()
        self.assertEqual(rec["rid"], "rt-cccccc")
        self.assertEqual(rec["failed"], [{"title": "HSTS", "severity": "medium", "fix": "Turn HSTS on"}])


class StatusShowsTheDrill(unittest.TestCase):
    DATA = {"reached": True, "ok": True, "host": "your-site.example", "health": {"ok": True},
            "server": {"mode": "operational", "version": "1.5.0", "build": "b", "uptime_s": 100},
            "security": {"score": 100, "grade": "hardened", "checks_passing": 9, "failing": 0, "warnings": 0,
                         "watch_enabled": True, "active_bans": 0, "watchlist": 0, "probes": {}, "checks_bad": []},
            "users": {}, "database": {"kind": "x"}, "traffic": {}}

    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(prefix="gnoc-rtlast-"), "last.json")
        p = mock.patch.dict(os.environ, {"GNOC_REDTEAM_LAST": self.path})
        p.start()
        self.addCleanup(p.stop)

    def test_a_failed_drill_sits_beside_a_perfect_score(self):
        import time
        gnoc_site.save_drill({"rid": "rt-e2f489", "ts": time.time() - 120, "key": "", "sig": [],
                              "failed": [{"title": "HSTS as the browser sees it", "severity": "medium",
                                          "fix": "Turn HSTS on at Cloudflare"}]})
        with mock.patch.object(gnoc_site, "read", return_value=self.DATA):
            out = gnoc_site.summary("security")
        self.assertIn("posture 100/100", out)
        self.assertIn("every ORIGIN posture check passes", out)
        self.assertIn("LAST DRILL rt-e2f489 (2 min ago) FAILED 1: [medium] HSTS as the browser sees it", out)
        self.assertIn("does not include these", out)

    def test_no_drill_no_line(self):
        with mock.patch.object(gnoc_site, "read", return_value=self.DATA):
            out = gnoc_site.summary("security")
        self.assertNotIn("LAST DRILL", out)


class RefusedFanOutIsNotFindings(unittest.TestCase):
    def test_the_refusal_names_the_tool_instead_of_a_placeholder(self):
        ctx = types.SimpleNamespace(program=None, s={})
        out = G.t_fan_out(ctx, ["run site_redteam against the site and report every failed check"])
        self.assertTrue(out.startswith("refused:"), out[:80])
        self.assertNotIn("{bad}", out)
        self.assertIn("call site_redteam yourself", out)

    def test_every_refusal_shape_is_recognised(self):
        from gnoc_core.agent import _FANOUT_REFUSAL
        for s in ("refused: the brief names site_redteam", "not run: an action in this turn is waiting",
                  "bad arguments: delegate needs task="):
            self.assertTrue(_FANOUT_REFUSAL.match(s), s)
        self.assertFalse(_FANOUT_REFUSAL.match("bot 1 (read_file): found the route in server.js"))

    def test_the_ultra_path_drops_a_refusal_before_the_lead_sees_it(self):
        src = open(os.path.join(HERE, "gnoc_core", "agent.py"), encoding="utf-8").read()
        i = src.index("_FANOUT_REFUSAL.match(findings)")
        j = src.index('"BOT FINDINGS (parallel worker bots ran these sub-tasks', i)
        self.assertLess(i, j)


if __name__ == "__main__":
    unittest.main()
