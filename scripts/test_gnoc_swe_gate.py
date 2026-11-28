"""The SWE side of the 2026-10-26 tune: the done gate and the per-turn pinned tool sets.

Receipt. Two defects, one cause - the model was the only witness to its own verification.
  * gnoc_modes' swe directive says at step 4 "a change you did not run is a claim, not a change", and nothing
    checked it; the same day a hunt draft reached the user as "capability gate satisfied" with every gate row
    self-reported and nothing behind it.
  * HUNT_CORE pinned race / liveness / pay_check against the 16k fallback's tool-fitting, with a comment
    recording that losing them silently was measured. Nothing pinned repo_map, run_tests or code_review, which
    the swe directive requires at steps 1, 4 and 5, so a coding turn on the fallback could lose exactly the
    tools that tell a change from a claim.

No network, no model, temp dirs only.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_modes  # noqa: E402


def t(name, arg="", ok=True, out=""):
    return {"ev": "tool", "phase": "end", "name": name, "arg": arg, "ok": ok, "out": out}


PASS = "collected 12 items ... 12 passed in 1.20s"
FAIL = "E   AssertionError: assert 3 == 4\n1 failed, 11 passed"


class DoneGate(unittest.TestCase):
    def test_a_turn_that_changed_nothing_is_fine(self):
        self.assertEqual(gnoc_modes.done_gate([t("read_file", "a.py"), t("grep", "foo")]), (True, ""))

    def test_edit_with_no_run_at_all_is_refused(self):
        ok, why = gnoc_modes.done_gate([t("edit_file", "scripts/auth.py"), t("read_file", "scripts/auth.py")])
        self.assertFalse(ok)
        self.assertIn("nothing ran", why)
        self.assertIn("scripts/auth.py", why)

    def test_edit_then_tests_passes(self):
        ok, why = gnoc_modes.done_gate([t("edit_file", "scripts/auth.py"), t("run_tests", "", out=PASS)])
        self.assertTrue(ok, why)

    def test_a_run_BEFORE_the_last_edit_does_not_count(self):
        """The commonest real shape: run the suite, see it pass, then 'just one more small fix'."""
        rows = [t("edit_file", "a.py"), t("run_tests", "", out=PASS), t("edit_file", "a.py")]
        ok, why = gnoc_modes.done_gate(rows)
        self.assertFalse(ok)
        self.assertIn("came AFTER the last run", why)

    def test_a_failing_run_is_refused(self):
        ok, why = gnoc_modes.done_gate([t("edit_file", "a.py"), t("run_tests", "", out=FAIL)])
        self.assertFalse(ok)
        self.assertIn("real failure", why)

    def test_bash_counts_only_when_it_actually_runs_something(self):
        self.assertFalse(gnoc_modes.done_gate([t("edit_file", "a.py"), t("bash", "cat a.py")])[0])
        self.assertFalse(gnoc_modes.done_gate([t("edit_file", "a.py"), t("bash", "grep -n foo a.py")])[0])
        self.assertTrue(gnoc_modes.done_gate([t("edit_file", "a.py"), t("bash", "pytest -q tests/", out=PASS)])[0])

    def test_a_failed_tool_call_is_not_a_run(self):
        ok, _ = gnoc_modes.done_gate([t("edit_file", "a.py"), t("run_tests", "", ok=False, out="")])
        self.assertFalse(ok)

    def test_a_web_file_needs_the_page_loaded_not_just_the_suite(self):
        rows = [t("edit_file", "web/settings.tsx"), t("run_tests", "", out=PASS)]
        ok, why = gnoc_modes.done_gate(rows)
        self.assertFalse(ok)
        self.assertIn("load the page", why)
        rows.append(t("browser", "http://127.0.0.1:3000/settings"))
        self.assertTrue(gnoc_modes.done_gate(rows)[0])

    def test_a_python_change_does_not_demand_a_browser(self):
        self.assertTrue(gnoc_modes.done_gate([t("edit_file", "scripts/x.py"), t("run_tests", "", out=PASS)])[0])

    def test_turn_rows_starts_at_the_last_turn_start(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "activity.jsonl")
            with open(p, "w") as f:
                f.write('{"ev":"tool","phase":"end","name":"edit_file","arg":"old.py","ok":true,"pid":7}\n')
                f.write('{"ev":"turn","phase":"start","pid":7}\n')
                f.write('{"ev":"tool","phase":"end","name":"read_file","arg":"new.py","ok":true,"pid":7}\n')
                f.write('not json at all\n')
            rows = gnoc_modes.turn_rows(p, pid=7)
            self.assertEqual([r.get("name") for r in rows], ["read_file"])
            self.assertEqual(gnoc_modes.turn_rows(os.path.join(d, "nope.jsonl")), [])

    def test_turn_rows_ignores_another_session(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.jsonl")
            with open(p, "w") as f:
                f.write('{"ev":"turn","phase":"start","pid":7}\n')
                f.write('{"ev":"tool","phase":"end","name":"edit_file","ok":true,"pid":9}\n')
                f.write('{"ev":"tool","phase":"end","name":"read_file","ok":true,"pid":7}\n')
            self.assertEqual([r.get("name") for r in gnoc_modes.turn_rows(p, pid=7)], ["read_file"])


class TurnCore(unittest.TestCase):
    """The pinned set follows gnoc_modes.detect, so the tools that survive fitting and the directive the model
    is reading always come from one decision."""

    def setUp(self):
        import gnoc_agent
        self.A = gnoc_agent

    def test_a_hunt_turn_keeps_hunt_core(self):
        self.assertEqual(self.A._turn_core("probe the API for an IDOR", hunting=True), self.A.HUNT_CORE)

    def test_a_coding_turn_keeps_the_tools_that_prove_a_change(self):
        core = self.A._turn_core("refactor the auth module and fix the failing unit tests")
        self.assertEqual(core, self.A.SWE_CORE)
        for must in ("run_tests", "code_review", "repo_map", "apply_patch"):
            self.assertIn(must, core)

    def test_a_web_app_turn_also_keeps_the_tools_that_see_the_page(self):
        core = self.A._turn_core("fix the layout of the settings page, the button does not render")
        self.assertEqual(core, self.A.WEB_CORE)
        for must in ("browser", "http_request", "run_tests"):
            self.assertIn(must, core)

    def test_a_review_turn_counts_as_coding(self):
        self.assertIn("code_review", self.A._turn_core("review this diff for bugs"))

    def test_an_ordinary_question_pins_nothing_extra(self):
        self.assertEqual(self.A._turn_core("what time is it"), ())

    def test_fit_tools_never_drops_a_pinned_coding_tool(self):
        """The whole point: on the 16k fallback the registry does not fit, and these must survive anyway."""
        tools = [{"type": "function", "function": {"name": n, "description": "x" * 400,
                                                   "parameters": {"type": "object", "properties": {}}}}
                 for n in sorted(self.A.TOOLS)]
        kept, dropped = self.A.fit_tools(tools, 1200, "refactor the auth module and run the tests",
                                         core=self.A.SWE_CORE)
        names = {(t.get("function") or {}).get("name") for t in kept}
        for must in self.A.SWE_CORE:
            self.assertIn(must, names, f"{must} was dropped; dropped={sorted(dropped)[:8]}")


if __name__ == "__main__":
    unittest.main()


class SweLedger(unittest.TestCase):
    """The coding half of the learning loop. The hunt loop learns because every lane writes a row code can
    read back; a coding turn wrote nothing, so the bot re-derived this repo's own shape every session."""

    def rows(self):
        return [t("edit_file", "scripts/auth.py"), t("run_tests", "", out=PASS)]

    def test_a_turn_that_changed_nothing_writes_no_row(self):
        self.assertIsNone(gnoc_modes.swe_outcome([t("read_file", "a.py")]))

    def test_the_row_is_what_the_tools_did(self):
        r = gnoc_modes.swe_outcome(self.rows(), "fix the login bug", sid="S1")
        self.assertEqual(r["changed"], ["scripts/auth.py"])
        self.assertEqual(r["runs"][0]["verdict"], "clean")
        self.assertTrue(r["verified"])
        self.assertEqual(r["task"], "fix the login bug")

    def test_an_unverified_turn_is_recorded_as_unverified_with_the_reason(self):
        r = gnoc_modes.swe_outcome([t("edit_file", "a.py")], "x")
        self.assertFalse(r["verified"])
        self.assertIn("nothing ran", r["why"])

    def test_a_failure_is_kept_verbatim_enough_to_recognise_again(self):
        r = gnoc_modes.swe_outcome([t("edit_file", "a.py"), t("run_tests", "", out=FAIL)], "x")
        self.assertIn("AssertionError", r["first_failure"])

    def test_history_recalls_the_runner_this_repo_actually_uses(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "swe.jsonl")
            gnoc_modes.swe_record(gnoc_modes.swe_outcome(
                [t("edit_file", "scripts/auth.py"), t("bash", "python3 -m pytest scripts/ -q", out=PASS)], "x"), p)
            gnoc_modes.swe_record(gnoc_modes.swe_outcome(
                [t("edit_file", "scripts/auth.py"), t("run_tests", "", out=FAIL)], "y"), p)
            runner, past = gnoc_modes.swe_history(["scripts/auth.py"], p)
            self.assertIn("pytest", runner)
            self.assertTrue(past)
            self.assertIn("AssertionError", past[-1]["first_failure"])

    def test_history_on_a_missing_ledger_is_empty_not_an_error(self):
        self.assertEqual(gnoc_modes.swe_history(["a.py"], "/nonexistent/x.jsonl"), ("", []))

    def test_record_never_raises_on_an_unwritable_path(self):
        self.assertFalse(gnoc_modes.swe_record({"a": 1}, "/proc/nope/x.jsonl"))
        self.assertFalse(gnoc_modes.swe_record(None))


class LocalApp(unittest.TestCase):
    def test_local_app_returns_a_url_only_for_a_listening_port(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            self.assertEqual(gnoc_modes.local_app(ports=(port,)), f"http://127.0.0.1:{port}/")
        finally:
            srv.close()
        self.assertEqual(gnoc_modes.local_app(ports=(port,)), "")

    def test_local_app_is_cheap_when_nothing_listens(self):
        import time
        t0 = time.time()
        gnoc_modes.local_app(ports=(1, 2, 3, 4), timeout=0.05)
        self.assertLess(time.time() - t0, 2.0)
