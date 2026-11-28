#!/usr/bin/env python3
"""Regression tests for the long-horizon task state: the standing goal, the plan document, and the slash
commands that drive them.

    python3 -m unittest scripts/test_gnoc_longhorizon.py -v

Everything runs in a temporary workspace: no live goal, plan, task ledger, model or network is touched.
"""
import contextlib
import importlib
import io
import os
import shutil
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


class LongHorizonTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-longhorizon-test-")
        self._old_env = {k: os.environ.get(k) for k in ("GNOC_WORKSPACE", "GNOC_WS")}
        os.environ["GNOC_WORKSPACE"] = self.tmp
        os.environ["GNOC_WS"] = self.tmp
        os.makedirs(os.path.join(self.tmp, "targets"), exist_ok=True)
        import gnoc_goal
        import gnoc_plan
        self.goal = importlib.reload(gnoc_goal)
        self.plan = importlib.reload(gnoc_plan)
        self.goal.PATH = os.path.join(self.tmp, "goal.json")
        self.goal.RECEIPT_BASE = self.tmp
        self.plan.PLAN_DIR = os.path.join(self.tmp, "plans")

    def tearDown(self):
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        # reload() rebinds module globals (WS, PATH, PLAN_DIR) to this test's temp workspace; put them back,
        # or every test file that runs after this one works against a deleted directory
        for name in ("gnoc_goal", "gnoc_plan", "gnoc_agent"):
            if name in sys.modules:
                importlib.reload(sys.modules[name])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def proof(self, name="proof.txt", body="tests: 12 passed\n"):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(body)
        return p


class GoalTests(LongHorizonTestCase):
    def test_parsed_constraint_is_a_completion_gate(self):
        d, err = self.goal.set_goal("achieve zero click ato on gatewayco", owner="s1",
                                    acceptance=["all tests pass"])
        self.assertIsNone(err)
        self.assertEqual(d["crown"], "ato")
        self.assertIn("zero-click", d["constraints"])
        texts = [a["text"] for a in d["acceptance"]]
        self.assertTrue(any(t.startswith("constraint zero-click:") for t in texts),
                        "a parsed constraint must seed an acceptance criterion")

        p = self.proof()
        refused = self.goal.done(p, owner="s1")
        self.assertIn("refused", refused)
        self.assertIn("constraint zero-click", refused)

        self.assertIn("criterion met", self.goal.accept("all tests pass", "met", p, owner="s1"))
        self.assertIn("criterion met", self.goal.accept("zero-click", "met", p, owner="s1"))
        self.assertIn("ACHIEVED", self.goal.done(p, owner="s1"))

    def test_accepting_an_open_criterion_again_closes_it_or_says_how(self):
        """/goal drives 2026-11-21: accept status=open was sent six times on a criterion that was already open,
        three of them with a receipt; "criterion open" came back each time and the goal could never close."""
        self.goal.set_goal("every test passes", owner="s1")
        self.assertIn("criterion added (open)", self.goal.accept("slugify test passes", "open", owner="s1"))
        msg = self.goal.accept("slugify test passes", "open", owner="s1")
        self.assertIn("nothing changed", msg)
        self.assertIn("status='met'", msg)
        p = os.path.join(self.tmp, "test.log")
        with open(p, "w") as fh:
            fh.write("1 passed\n")
        self.assertIn("refused", self.goal.accept("slugify test passes", "open", os.path.join(self.tmp, "nope.log"),
                                                  owner="s1"))
        msg = self.goal.accept("slugify test passes", "open", p, owner="s1")
        self.assertIn("criterion met", msg)
        self.assertEqual(self.goal.load()["acceptance"][0]["status"], "met")
        # a MET criterion can still be re-opened on purpose
        self.assertIn("criterion open", self.goal.accept("slugify test passes", "open", owner="s1"))

    def test_empty_note_is_refused(self):
        self.goal.set_goal("ship the production release", owner="s1")
        msg = self.goal.note("", owner="s1")
        self.assertIn("refused", msg)
        self.assertFalse(self.goal.load().get("log"))

    def test_note_artifact_must_exist(self):
        self.goal.set_goal("ship the production release", owner="s1")
        msg = self.goal.note("captured it", artifact="nope/missing.txt", owner="s1")
        self.assertIn("does not exist", msg)
        p = self.proof()
        self.assertIn("recorded", self.goal.note("captured it", artifact=p, owner="s1"))

    def test_milestone_prefix_does_not_close_a_longer_milestone(self):
        self.goal.set_goal("achieve ato", owner="s1",
                           milestones=["prove ssrf", "prove ssrf to internal admin"])
        p = self.proof()
        self.assertIn("milestone done", self.goal.milestone("prove ssrf to internal admin", "done", p,
                                                            owner="s1"))
        d = self.goal.load()
        self.assertEqual(d["milestones"][0]["status"], "open")
        self.assertEqual(d["milestones"][1]["status"], "done")
        self.assertIn("milestone done", self.goal.milestone("prove ssrf", "done", p, owner="s1"))
        self.assertEqual(self.goal.load()["milestones"][0]["status"], "done")

    def test_ambiguous_acceptance_is_refused(self):
        self.goal.set_goal("ship it", owner="s1", acceptance=["all tests pass", "unit tests pass"])
        p = self.proof()
        msg = self.goal.accept("tests pass", "met", p, owner="s1")
        self.assertIn("ambiguous", msg)
        self.assertTrue(all(a["status"] == "open" for a in self.goal.load()["acceptance"]))

    def test_a_single_generic_word_does_not_resolve_a_long_criterion(self):
        self.goal.set_goal("ship it", owner="s1", acceptance=["no public API change"])
        p = self.proof()
        msg = self.goal.accept("change", "met", p, owner="s1")
        self.assertIn("criterion added", msg)
        self.assertEqual(self.goal.load()["acceptance"][0]["status"], "open")

    def test_owner_isolation_and_pause_resume(self):
        self.goal.set_goal("a private objective", owner="alice", acceptance=["done"])
        self.assertIn("another conversation", self.goal.note("x", owner="bob"))
        self.assertIn("paused", self.goal.pause(owner="alice"))
        self.assertIn("PAUSED", self.goal.block(owner="alice"))
        self.assertIn("paused", self.goal.note("x", owner="alice"))
        self.assertIn("paused", self.goal.done(self.proof(), owner="alice"))
        self.assertIn("resumed", self.goal.resume(owner="alice"))
        self.assertIn("recorded", self.goal.note("x", owner="alice"))

    def test_status_shows_constraints_without_a_crown(self):
        self.goal.set_goal("ship the production release", owner="s1")
        text = self.goal.status_text()
        self.assertIn("constraints: production", text)
        self.assertNotIn("crown:", text)

    def test_achieved_fingerprint_is_not_reported_as_cleared(self):
        self.goal.set_goal("a small objective", owner="s1", acceptance=["proof"])
        p = self.proof()
        self.goal.accept("proof", "met", p, owner="s1")
        self.goal.done(p, owner="s1")
        fp = self.goal.fingerprint(owner="s1")
        self.assertIn("achieved", fp)
        self.assertEqual(self.goal.one_line(owner="s1"), "")
        self.assertIn("last goal was ACHIEVED", self.goal.block(owner="s1"))


class PlanTests(LongHorizonTestCase):
    def _plan(self, statuses=("pending", "pending")):
        p = {"goal": "make it work", "steps": [
            {"action": "read the code", "verify": "grep finds callers", "why": "know the seam"},
            {"action": "patch the code", "verify": "the suite passes", "why": "fix it"}]}
        p = self.plan.normalize(p)
        for step, status in zip(p["steps"], statuses):
            step["status"] = status
        self.plan.save("s1", p)
        return p

    def test_roundtrip_keeps_evidence_and_task_link(self):
        p = self._plan()
        p["steps"][0].update(evidence="grep: 3 callers", task_id="T7", status="done")
        self.plan.save("s1", p)
        got = self.plan.load("s1")
        self.assertEqual(got["steps"][0]["evidence"], "grep: 3 callers")
        self.assertEqual(got["steps"][0]["task_id"], "T7")
        self.assertEqual(self.plan.progress(got), (1, 2))

    def test_all_skipped_is_resolved_but_not_done(self):
        self._plan(("skipped", "skipped"))
        got = self.plan.load("s1")
        self.assertTrue(self.plan.all_resolved(got))
        self.assertEqual(self.plan.progress(got), (0, 2))
        self.assertIsNone(self.plan.next_step(got)[1])
        self.assertTrue(self.plan.one_line(got).startswith("✓ 0/2"))

    def test_doing_step_wins_the_next_slot(self):
        p = self._plan(("pending", "doing"))
        self.plan.save("s1", p)
        i, step = self.plan.next_step(self.plan.load("s1"))
        self.assertEqual(i, 2)
        self.assertEqual(step["action"], "patch the code")


class CommandTests(LongHorizonTestCase):
    def setUp(self):
        super().setUp()
        import gnoc_agent
        self.agent = importlib.reload(gnoc_agent)
        self.agent.WS = self.tmp
        self.agent.TASKS = os.path.join(self.tmp, "tasks.jsonl")
        self.agent.gnoc_goal = self.goal
        self.agent.gnoc_plan = self.plan
        self.ctx = self.agent.Ctx({"sid": "s1", "program": None})
        self.fake = types.SimpleNamespace(s={"sid": "s1", "program": None},
                                         ctx=types.SimpleNamespace(program=None), save=lambda: None)

    def run_quiet(self, fn, *a, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            value = fn(*a, **kw)
        return value, out.getvalue()

    def test_goal_tool_accepts_milestones_and_pauses(self):
        msg = self.agent.t_goal(self.ctx, "set", text="a goal with milestones",
                                acceptance="tests pass", milestones="step one; step two")
        self.assertIn("goal [active]", msg)
        self.assertIn("milestones: 0/2", msg)
        self.assertIn("paused", self.agent.t_goal(self.ctx, "pause"))
        self.assertIn("resumed", self.agent.t_goal(self.ctx, "resume"))

    def test_show_extra_does_not_become_a_goal(self):
        _, out = self.run_quiet(self.agent.goal_cmd, self.fake, "show extra")
        self.assertIn("no goal set", out)
        self.assertFalse(self.goal.load())

    def test_goal_command_closes_with_receipts(self):
        p = self.proof()
        self.run_quiet(self.agent.goal_cmd, self.fake,
                       'ship the production release --no-start --accept "all tests pass"')
        self.assertEqual(self.goal.load()["status"], "active")
        self.run_quiet(self.agent.goal_cmd, self.fake, "milestone first step --open")
        self.run_quiet(self.agent.goal_cmd, self.fake, f"milestone first step --receipt {p}")
        self.run_quiet(self.agent.goal_cmd, self.fake, f'accept "all tests pass" --receipt {p}')
        self.run_quiet(self.agent.goal_cmd, self.fake, f'accept "constraint production" --receipt {p}')
        _, out = self.run_quiet(self.agent.goal_cmd, self.fake, f"done {p}")
        self.assertIn("ACHIEVED", out)

    def test_plan_done_requires_evidence_and_closes_its_ledger_rows(self):
        msg, out = self.run_quiet(self.agent.t_plan, self.ctx, "set", goal="ship the plan",
                                  steps=[{"action": "read the code", "verify": "grep finds callers"},
                                         {"action": "patch the code", "verify": "the suite passes"}])
        self.assertIn("plan set", msg)
        self.assertIn("PLAN", out)
        msg, _ = self.run_quiet(self.agent.t_plan, self.ctx, "update", index=1, status="done")
        self.assertIn("needs evidence", msg)
        msg, _ = self.run_quiet(self.agent.t_plan, self.ctx, "update", index=1, status="done",
                                evidence="grep: 3 callers")
        self.assertIn("-> done", msg)
        msg, _ = self.run_quiet(self.agent.t_plan, self.ctx, "update", index=2, status="done",
                                evidence="pytest: 12 passed")
        self.assertIn("-> done", msg)
        self.assertEqual(self.agent.t_tasks(self.ctx, "list"), "no open tasks")
        self.assertTrue(self.plan.all_resolved(self.plan.load("s1")))

    def test_replacing_a_plan_closes_its_old_ledger_rows(self):
        self.run_quiet(self.agent.t_plan, self.ctx, "set", goal="old plan",
                       steps=[{"action": "old step", "verify": "old proof"}])
        self.run_quiet(self.agent.t_plan, self.ctx, "set", goal="new plan",
                       steps=[{"action": "new step", "verify": "new proof"}])
        tasks = self.agent.t_tasks(self.ctx, "list")
        self.assertIn("plan: new step", tasks)
        self.assertNotIn("plan: old step", tasks)

    def test_tasks_command_lists_and_closes_a_task(self):
        _, out = self.run_quiet(self.agent.handle_slash, self.fake, "/tasks add write the docs", None)
        self.assertIn("T1 [open] write the docs", out)
        _, out = self.run_quiet(self.agent.handle_slash, self.fake, "/tasks done T1", None)
        self.assertIn("T1 [done] write the docs", out)

    def test_split_flags_keeps_quoted_values_and_unknown_words(self):
        parsed, err = self.agent._split_flags('fix the --weird bug --turns 3 --accept "a; b"',
                                              value=("--turns", "--accept"), boolean=("--force",))
        self.assertIsNone(err)
        words, vals, flags = parsed
        self.assertEqual(words, ["fix", "the", "--weird", "bug"])
        self.assertEqual(vals["--turns"], ["3"])
        self.assertEqual(vals["--accept"], ["a; b"])
        self.assertFalse(flags)


class GoalDriverTests(LongHorizonTestCase):
    """A goal keeps working until it is achieved (the user 2026-11-18: "when I set a goal it should not stop
    until that goal is complete"). Before: /goal ran ONE turn, then waited for "continue" every step."""

    def setUp(self):
        super().setUp()
        import gnoc_agent
        self.agent = importlib.reload(gnoc_agent)
        self.agent.WS = self.tmp
        self.agent.gnoc_goal = self.goal
        self.agent.gnoc_plan = self.plan
        self.agent.time = types.SimpleNamespace(sleep=lambda s: None, time=__import__("time").time,
                                                strftime=__import__("time").strftime)
        self.typed = False
        self.agent.TYPED = types.SimpleNamespace(pending=lambda: self.typed)
        self.goal.set_goal("make the whole test suite pass", owner="s1")
        self.prompts = []
        self.script = []          # per turn: (answer, tools, effect) ; effect(fake) may change the goal
        self.fake = types.SimpleNamespace(s={"sid": "s1", "program": None}, interrupted=False,
                                          ctx=types.SimpleNamespace(program=None), save=lambda: None,
                                          turn=self._turn, hunt=lambda prog, goal: self.prompts.append(("HUNT", prog)))

    def _turn(self, prompt):
        self.prompts.append(prompt)
        ans, tools, effect = self.script.pop(0) if self.script else ("working on it", 1, None)
        self.fake.s["_turn_tools_last"] = tools
        if effect:
            effect(self.fake)
        return ans

    def _achieve(self, fake):
        d = self.goal.load()
        d["status"] = "achieved"
        self.goal._saved(d, "")

    def drive(self, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            n = self.agent.drive_goal(self.fake, **kw)
        return n, out.getvalue()

    def test_it_keeps_going_until_the_goal_is_achieved(self):
        self.script = [("step 1", 2, None), ("step 2", 3, None), ("step 3", 1, None), ("closed it", 1, self._achieve)]
        n, out = self.drive(first_prompt="START")
        self.assertEqual(n, 4)
        self.assertEqual(self.prompts[0], "START")
        self.assertIn("Continue the standing goal", self.prompts[1])
        self.assertIn("goal achieved", out)

    def test_needs_hands_back_and_his_answer_resumes_it(self):
        self.script = [("NEEDS: the staging password", 1, None)]
        n, out = self.drive()
        self.assertEqual(n, 1)
        self.assertIn("waiting on you", out)
        self.script = [("done", 1, self._achieve)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.agent.goal_after_turn(self.fake, "the password is in the vault")
        self.assertEqual(self.goal.load()["status"], "achieved")

    def test_ctrl_c_holds_it_until_he_says_continue(self):
        def interrupt(fake):
            fake.interrupted = True
        self.script = [("partial", 1, interrupt)]
        self.drive()
        self.assertTrue(self.fake.s.get("_goal_hold"))
        self.fake.interrupted = False
        before = len(self.prompts)
        self.assertEqual(self.agent.goal_after_turn(self.fake, "what does this file do?"), 0)
        self.assertEqual(len(self.prompts), before, "a held goal does not restart on an unrelated message")
        self.script = [("done", 1, self._achieve)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertGreater(self.agent.goal_after_turn(self.fake, "continue"), 0)
        self.assertNotIn("_goal_hold", self.fake.s)

    def test_typing_interjects_without_holding(self):
        def type_something(fake):
            self.typed = True
        self.script = [("step", 1, type_something)]
        n, _ = self.drive()
        self.assertEqual(n, 1)
        self.assertNotIn("_goal_hold", self.fake.s)

    def test_a_stall_is_nudged_then_handed_back(self):
        self.script = [("thinking about it", 0, None)] * 20
        n, out = self.drive()
        self.assertEqual(n, self.agent.GOAL_STALL_MAX)
        self.assertIn("not called a tool or moved the goal", self.prompts[2])
        self.assertIn("handing back", out)

    def test_progress_without_tools_is_not_a_stall(self):
        def note(fake):
            self.goal.note("found the failing fixture", owner="s1")
        self.script = [("noted", 0, note)] * 8 + [("done", 0, self._achieve)]
        n, _ = self.drive()
        self.assertEqual(n, 9)

    def test_empty_answers_back_off_then_hand_back(self):
        self.script = [("", 0, None)] * 5
        n, out = self.drive()
        self.assertEqual(n, self.agent.GOAL_EMPTY_MAX)
        self.assertIn("no answer", out)

    def test_claiming_done_without_closing_it_is_challenged(self):
        self.script = [("The goal is achieved.", 1, None), ("ok closing", 1, self._achieve)]
        self.drive()
        self.assertIn("still OPEN", self.prompts[1])

    def test_a_budget_is_optional(self):
        os.environ["GNOC_GOAL_TURNS"] = "3"
        try:
            n, out = self.drive()
        finally:
            os.environ.pop("GNOC_GOAL_TURNS", None)
        self.assertEqual(n, 3)
        self.assertIn("budget reached", out)

    def test_a_program_goal_runs_the_continuous_hunt(self):
        d = self.goal.load()
        d["program"] = "acme"
        self.goal._saved(d, "")
        self.drive()
        self.assertEqual(self.prompts, [("HUNT", "acme")])

    def test_paused_or_foreign_goals_are_left_alone(self):
        self.goal.pause(owner="s1")
        self.assertEqual(self.drive()[0], 0)
        self.goal.resume(owner="s1")
        self.fake.s["sid"] = "someone-else"
        self.assertEqual(self.drive()[0], 0)


if __name__ == "__main__":
    unittest.main()
