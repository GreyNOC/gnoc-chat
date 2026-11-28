#!/usr/bin/env python3
"""Phase 4: concurrent subagents. delegate(tasks=[...]) through ONE bounded pool, read-only children with their own
budgets and a structured summary, children that can never approve / spawn / schedule / widen scope, Ctrl-C that
cancels every child (the claude CLI workers too), and a claude_worker that is optional and detected.

Fake model calls only (G.llm_chat is replaced), temp dirs only, no network.

    python3 -m pytest -q scripts/test_gnoc_phase4_subagents.py
"""
import _thread
import json
import os
import shutil
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_monitor  # noqa: E402
import gnoc_subagents as SA  # noqa: E402


def _final(result="read it", evidence=("a.py:1",), files=("a.py",), questions=()):
    return {"role": "assistant", "content": "Done.\n```json\n" + json.dumps(
        {"result": result, "evidence": list(evidence), "files": list(files),
         "open_questions": list(questions)}) + "\n```"}


def _call(name, **args):
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


def _rows(out):
    """Every child's JSON summary from delegate's rendered output, in order."""
    dec, rows, i = json.JSONDecoder(), [], 0
    while True:
        i = out.find("== child ", i)
        if i < 0:
            return rows
        j = out.index("{", i)
        row, end = dec.raw_decode(out, j)
        rows.append(row)
        i = end


def _wait_for(pred, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


class Base(unittest.TestCase):
    """A temp repo as the active root, a temp GNOC_HOME, a fresh pool of 3, and a fake model."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p4-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        with open(os.path.join(self.repo, "a.py"), "w") as f:
            f.write("x = 1\n")
        self.saved = (G._ACTIVE_ROOT[0], G.SKIP_PERMS[0], G.AGENT_DIR)
        G._ACTIVE_ROOT[0] = self.repo
        G.SKIP_PERMS[0] = False
        G.AGENT_DIR = os.path.join(self.tmp, "agent")
        self.patches = [
            mock.patch.dict(os.environ, {"GNOC_HOME": os.path.join(self.tmp, "home")}),
            mock.patch.object(G, "resolve", lambda role, quiet=False: ("fake-model", "local")),
            mock.patch.object(G, "say", lambda *a, **k: None),
            mock.patch.object(gnoc_monitor, "DIR", os.path.join(self.tmp, "subagents")),
            mock.patch.object(SA, "POOL", SA.ChildPool(cap=lambda: 3)),
        ]
        for p in self.patches:
            p.start()
        for k in ("GNOC_DELEGATE_CAP", "GNOC_CHILD_TOKENS", "GNOC_CHILD_SECONDS"):
            os.environ.pop(k, None)
        G.INTERRUPT.clear()
        self.ctx = G.Ctx({"sid": "p4-test"})
        self.lock = threading.Lock()
        self.running, self.started, self.seen = 0, [], {}
        self.go = threading.Event()

    def tearDown(self):
        self.go.set()
        G.INTERRUPT.set()          # any straggler fake stops at once
        time.sleep(0.05)
        G.INTERRUPT.clear()
        for p in reversed(self.patches):
            p.stop()
        G._ACTIVE_ROOT[0], G.SKIP_PERMS[0], G.AGENT_DIR = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _task_of(msgs):
        return str(msgs[1].get("content") or "") if len(msgs) > 1 else ""

    def blocking_llm(self, model, host, msgs, *a, **k):
        """A child that blocks on self.go like a long model stream: it bails on Ctrl-C or a cancelled parent the
        way the real stream loops do (INTERRUPT / _cancelled), and it records how many run at once."""
        task = self._task_of(msgs)
        if any(m.get("role") == "assistant" for m in msgs):
            return _final(result="finished " + task.split()[0])
        with self.lock:
            self.running += 1
            self.started.append(task.split()[0])
        try:
            while not self.go.is_set():
                if G.INTERRUPT.is_set() or G._cancelled():
                    return {"role": "assistant", "content": ""}
                time.sleep(0.01)
            return _call("read_file", path="a.py")
        finally:
            with self.lock:
                self.running -= 1


class FanOutUnderTheCap(Base):
    def test_three_tasks_run_at_once_and_each_returns_a_structured_summary(self):
        both = threading.Event()

        def llm(model, host, msgs, *a, **k):
            if not any(m.get("role") == "assistant" for m in msgs):
                with self.lock:
                    self.running += 1
                    if self.running == 3:
                        both.set()
                both.wait(10)   # all three must be inside the model call at the same moment
                with self.lock:
                    self.running -= 1
            return _final(result="looked at " + self._task_of(msgs).split()[0])

        with mock.patch.object(G, "llm_chat", llm):
            out = G.t_delegate(self.ctx, tasks=["alpha read a.py and report x",
                                                "bravo read a.py and report x",
                                                "charlie read a.py and report x"])
        self.assertTrue(both.is_set(), "the three children never ran concurrently")
        self.assertEqual(SA.POOL.peak, 3)
        self.assertEqual(out.count("== child "), 3, out)
        rows = _rows(out)
        for name, row in zip(("alpha", "bravo", "charlie"), rows):
            self.assertEqual(set(row), {"result", "evidence", "files", "open_questions", "needs_approval", "tokens",
                                        "status"})
            self.assertEqual(row["status"], "done")
            self.assertEqual(row["result"], f"looked at {name}")
            self.assertEqual(row["evidence"], ["a.py:1"])
            self.assertEqual(row["needs_approval"], [])
            self.assertGreater(row["tokens"], 0)
        self.assertEqual(SA.POOL.active, 0)


class TheFourthTaskQueues(Base):
    def test_a_fourth_task_waits_for_a_slot_then_runs(self):
        box = {}
        with mock.patch.object(G, "llm_chat", self.blocking_llm):
            th = threading.Thread(target=lambda: box.setdefault("out", G.t_delegate(self.ctx, tasks=[
                f"{n} read a.py and say what x is" for n in ("one", "two", "three", "four")])), daemon=True)
            th.start()
            self.assertTrue(_wait_for(lambda: self.running == 3))
            time.sleep(0.3)     # time for a fourth to start, if the pool let it
            self.assertEqual(self.running, 3)
            self.assertEqual(len(self.started), 3)
            self.assertEqual(SA.POOL.active, 3)
            self.assertEqual(SA.POOL.waiting, 1, "the fourth task is queued, not lost and not running")
            self.go.set()
            th.join(15)
        self.assertFalse(th.is_alive())
        self.assertEqual(sorted(self.started), ["four", "one", "three", "two"])
        self.assertEqual(SA.POOL.peak, 3)
        self.assertEqual(box["out"].count('"status": "done"'), 4, box["out"])

    def test_two_delegate_calls_in_one_step_share_one_cap(self):
        """run_tools runs approved calls four at a time; the pool is process-wide, so two delegate calls of two
        tasks each still run at most three children at once."""
        calls = [{"function": {"name": "delegate", "arguments": {"tasks": [
            f"{n} read a.py and say what x is" for n in names]}}} for names in (("p", "q"), ("r", "s"))]
        box = {}
        with mock.patch.object(G, "llm_chat", self.blocking_llm):
            th = threading.Thread(target=lambda: box.setdefault(
                "res", G.run_tools(calls, self.ctx, interactive=False, prefix="      ")), daemon=True)
            th.start()
            self.assertTrue(_wait_for(lambda: self.running == 3))
            time.sleep(0.3)
            self.assertEqual(self.running, 3)
            self.assertEqual(SA.POOL.waiting, 1)
            self.go.set()
            th.join(20)
        self.assertEqual(SA.POOL.peak, 3)
        self.assertEqual(len(box["res"]), 2)
        self.assertEqual(sum(r["content"].count('"status": "done"') for r in box["res"]), 4)

    def test_the_cap_comes_from_the_setting(self):
        with mock.patch.dict(os.environ, {"GNOC_DELEGATE_CAP": "2"}):
            self.assertEqual(SA.delegate_cap(), 2)
            with mock.patch.object(SA, "POOL", SA.ChildPool()), mock.patch.object(G, "llm_chat", self.blocking_llm):
                th = threading.Thread(target=lambda: G.t_delegate(self.ctx, tasks=[
                    f"{n} read a.py and say what x is" for n in ("one", "two", "three")]), daemon=True)
                th.start()
                self.assertTrue(_wait_for(lambda: self.running == 2))
                time.sleep(0.2)
                self.assertEqual(self.running, 2)
                self.assertEqual(SA.POOL.waiting, 1)
                self.go.set()
                th.join(15)


class Settings(Base):
    def _write(self, obj, where=None):
        d = where or os.environ["GNOC_HOME"]
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "settings.json"), "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj))

    def test_default_is_three(self):
        self.assertEqual(SA.delegate_cap(), 3)

    def test_the_home_settings_file_sets_it_and_env_wins(self):
        self._write({"delegate": {"cap": 5, "child_tokens": 9000}})
        self.assertEqual(SA.delegate_cap(), 5)
        self.assertEqual(SA.child_token_budget(), 9000)
        with mock.patch.dict(os.environ, {"GNOC_DELEGATE_CAP": "1"}):
            self.assertEqual(SA.delegate_cap(), 1)

    def test_junk_and_out_of_range_values_never_widen_it(self):
        self._write("{not json")
        self.assertEqual(SA.delegate_cap(), 3)
        self._write({"delegate": {"cap": "lots"}})
        self.assertEqual(SA.delegate_cap(), 3)
        self._write({"delegate": {"cap": 500}})
        self.assertEqual(SA.delegate_cap(), SA.MAX_CAP)
        self._write({"delegate": {"cap": 0}})
        self.assertEqual(SA.delegate_cap(), 1)

    def test_a_repo_cannot_set_its_own_pool(self):
        self._write({"delegate": {"cap": 8}}, where=os.path.join(self.repo, ".gnoc"))
        self.assertEqual(SA.delegate_cap(), 3)

    def test_a_task_may_lower_its_budget_but_never_raise_it(self):
        self.assertEqual(SA.clamp_budget(None, 1000, 10), 1000)
        self.assertEqual(SA.clamp_budget(500, 1000, 10), 500)
        self.assertEqual(SA.clamp_budget(10 ** 9, 1000, 10), 1000)
        self.assertEqual(SA.clamp_budget(1, 1000, 10), 10)
        self.assertEqual(SA.clamp_budget("x", 1000, 10), 1000)


class CtrlCCancelsEveryChild(Base):
    def test_ctrl_c_stops_the_running_children_and_the_queued_one_never_starts(self):
        def press_ctrl_c():
            if _wait_for(lambda: self.running == 3):
                time.sleep(0.1)
                _thread.interrupt_main()

        with mock.patch.object(G, "llm_chat", self.blocking_llm):
            threading.Thread(target=press_ctrl_c, daemon=True).start()
            with self.assertRaises(KeyboardInterrupt):
                G.t_delegate(self.ctx, tasks=[f"{n} read a.py and say what x is"
                                              for n in ("one", "two", "three", "four")])
            self.assertTrue(G.INTERRUPT.is_set())
            self.assertTrue(_wait_for(lambda: self.running == 0, 5), "a child kept running after Ctrl-C")
            self.assertTrue(_wait_for(lambda: SA.POOL.active == 0 and SA.POOL.waiting == 0, 5))
        self.assertEqual(len(self.started), 3, "the queued fourth task started after Ctrl-C")

    def test_an_interrupt_while_running_reports_every_child_cancelled(self):
        box = {}
        with mock.patch.object(G, "llm_chat", self.blocking_llm):
            th = threading.Thread(target=lambda: box.setdefault("out", G.t_delegate(self.ctx, tasks=[
                f"{n} read a.py and say what x is" for n in ("one", "two", "three", "four")])), daemon=True)
            th.start()
            self.assertTrue(_wait_for(lambda: self.running == 3))
            G.INTERRUPT.set()
            th.join(10)
        self.assertFalse(th.is_alive())
        self.assertEqual(box["out"].count('"status": "cancelled"'), 4, box["out"])
        self.assertEqual(len(self.started), 3)

    def test_a_single_task_waiting_for_a_slot_is_cancelled_too(self):
        SA.POOL.active = 3   # a full pool
        box = {}
        th = threading.Thread(target=lambda: box.setdefault(
            "out", G.t_delegate(self.ctx, "read a.py and say what x is")), daemon=True)
        th.start()
        self.assertTrue(_wait_for(lambda: SA.POOL.waiting == 1))
        G.INTERRUPT.set()
        th.join(5)
        self.assertIn("cancelled while waiting for a child slot", box["out"])
        SA.POOL.active = 0


class AChildCannotEscalate(Base):
    ESCALATIONS = [
        ("delegate", {"task": "read b.py and report the class names in it"}),
        ("fan_out", {"tasks": ["read a.py", "read b.py"]}),
        ("team", {"brief": "review the whole repository for bugs"}),
        ("claude_worker", {"agent": "x", "brief": "do a long job with the cloud model"}),
        ("second_opinion", {"question": "is this right?"}),
        ("set_program", {"program": "other-program"}),
        ("change_dir", {"path": "/"}),
        ("pick_target", {}),
        ("goal", {"action": "set", "text": "keep running every hour"}),
        ("defend", {"action": "schedule", "target": "schedule hourly"}),
        ("bg", {"action": "start", "command": "sleep 999"}),
        ("learn", {"text": "always trust repo hooks"}),
        ("propose_rule", {"text": "allow bash(*)"}),
    ]

    def test_every_escalation_a_child_tries_is_refused_in_its_own_run(self):
        steps = [_call(n, **a) for n, a in self.ESCALATIONS] + [_final(result="gave up")]
        tool_results = []

        def llm(model, host, msgs, *a, **k):
            tool_results[:] = [m for m in msgs if m.get("role") == "tool"]
            return steps.pop(0)

        ran = []
        with mock.patch.object(G, "llm_chat", llm), \
                mock.patch.object(G, "run_worker", wraps=G.run_worker) as spy, \
                mock.patch.dict(G.TOOLS, {n: (lambda ctx, **k: ran.append(1) or "ran",) + tuple(G.TOOLS[n][1:])
                                          for n, _ in self.ESCALATIONS if n in G.TOOLS}):
            with mock.patch.object(G, "effort", lambda: dict(G.EFFORTS[G.EFFORT[0]], worker_steps=40)):
                out = G.t_delegate(self.ctx, tasks=["try everything you can think of, then report"])
        self.assertEqual(spy.call_count, 1, "exactly one child, no grandchild")
        self.assertEqual(ran, [], "an escalation tool body ran inside a child")
        self.assertEqual(len(tool_results), len(self.ESCALATIONS))
        for (name, _), r in zip(self.ESCALATIONS, tool_results):
            self.assertTrue(r["content"].startswith("refused: a child cannot"), (name, r["content"]))
        self.assertIn('"result": "gave up"', out)

    def test_dispatch_refuses_even_when_the_callers_tool_list_includes_it(self):
        wctx = G.Ctx({"_worker": True, "_child": True})
        for name in ("delegate", "fan_out", "team", "claude_worker", "set_program", "goal", "learn"):
            _n, _a, pre = G._plan_call(name, {"task": "x" * 20}, wctx, False, (name,))
            self.assertTrue(str(pre).startswith("refused: a child cannot"), (name, pre))

    def test_the_lead_is_not_affected(self):
        self.assertIsNone(SA.child_refusal("read_file"))
        _n, _a, pre = G._plan_call("read_file", {"path": "a.py"}, self.ctx, False, None)
        self.assertIsNone(pre)

    def test_a_direct_call_from_a_child_context_is_refused(self):
        out = G.t_delegate(G.Ctx({"_worker": True}), tasks=["read a.py and tell me what x is"])
        self.assertTrue(out.startswith("refused: a child cannot start another child"), out)


class WhatNeedsApprovalGoesBackToTheLead(Base):
    def _run(self, lead_auto=False):
        steps = [_call("http_request", url="https://example.invalid/api/delete", method="POST"),
                 _final(result="could not post")]
        if lead_auto:
            self.ctx.s["auto"] = True
        with mock.patch.object(G, "llm_chat", lambda m, h, msgs, *a, **k: steps.pop(0)):
            return G.t_delegate(self.ctx, tasks=["post to the api and report what it says"])

    def test_a_held_call_is_returned_as_a_request_not_dropped(self):
        out = self._run()
        row = _rows(out)[0]
        self.assertEqual(row["needs_approval"], ["needs approval: http_request POST https://example.invalid/api/delete"])
        self.assertIn("HELD FOR APPROVAL", out)
        self.assertIn("- child 1: needs approval: http_request POST", out)

    def test_the_leads_auto_is_not_inherited(self):
        out = self._run(lead_auto=True)
        self.assertIn("needs approval: http_request POST", out)

    def test_the_single_task_form_hands_the_request_up_too(self):
        steps = [_call("http_request", url="https://example.invalid/x", method="PUT"),
                 {"role": "assistant", "content": "digest: nothing ran"}]
        with mock.patch.object(G, "llm_chat", lambda m, h, msgs, *a, **k: steps.pop(0)):
            out = G.t_delegate(self.ctx, "put to the api and report what it says")
        self.assertTrue(out.startswith("digest: nothing ran"), out)
        self.assertIn("- needs approval: http_request PUT https://example.invalid/x", out)


class BudgetsAndAccounting(Base):
    def test_the_token_budget_stops_the_child_from_real_usage_and_the_turn_is_charged(self):
        calls = {"n": 0}

        def llm(model, host, msgs, *a, **k):
            calls["n"] += 1
            gnoc_monitor.record(model, host, 3000, 1000, 0.1)   # what the real stream loop books per call
            return _call("read_file", path="a.py") if k.get("tools") else _final(result="partial")

        gnoc_monitor.reset_turn()
        with mock.patch.object(G, "llm_chat", llm):
            out = G.t_delegate(self.ctx, tasks=[{"task": "read a.py over and over and report", "tokens": 5000}])
        row = _rows(out)[0]
        self.assertEqual(row["status"], "token_limit")
        self.assertEqual(calls["n"], 3, "two steps to pass the budget, then the one closing digest call")
        self.assertEqual(row["tokens"], 12000)
        self.assertEqual(gnoc_monitor._turn["in"] + gnoc_monitor._turn["out"], 12000)
        self.assertEqual(row["result"], "partial")

    def test_a_call_with_no_usage_is_estimated_and_charged_without_counting_twice(self):
        gnoc_monitor.reset_turn()
        with mock.patch.object(G, "llm_chat", lambda m, h, msgs, *a, **k: _final(result="ok")):
            out = G.t_delegate(self.ctx, tasks=["read a.py and say what x is"])
        row = _rows(out)[0]
        self.assertGreater(row["tokens"], 0)
        self.assertEqual(gnoc_monitor._turn["in"] + gnoc_monitor._turn["out"], row["tokens"])
        self.assertEqual(gnoc_monitor._turn["calls"], 0)
        self.assertIn(f"{row['tokens']} tokens charged to this turn", out)

    def test_children_tallies_are_their_own(self):
        a, b = {"tokens": 0}, {"tokens": 0}

        def child(sink, n):
            with gnoc_monitor.tally(sink):
                gnoc_monitor.record("m", "h", n, 0, 0)

        ts = [threading.Thread(target=child, args=(a, 100)), threading.Thread(target=child, args=(b, 7))]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual((a["tokens"], b["tokens"]), (100, 7))

    def test_the_wall_is_the_childs_own(self):
        seen = {}

        def fake_worker(ctx, task, **kw):
            seen.update(kw)
            return _final()["content"]

        with mock.patch.object(G, "run_worker", fake_worker):
            G.t_delegate(self.ctx, tasks=[{"task": "read a.py and say what x is", "seconds": 45}])
        self.assertEqual(seen["wall"], 45)
        self.assertEqual(seen["extra"]["_child_budget"], SA.DEFAULT_CHILD_TOKENS)


class ReadOnlyByDefault(Base):
    def test_a_childs_default_toolset_writes_nothing(self):
        seen = {}

        def fake_worker(ctx, task, **kw):
            seen.update(kw)
            return "fine"

        with mock.patch.object(G, "run_worker", fake_worker):
            G.t_delegate(self.ctx, tasks=["read a.py and say what x is"])
        names = set(seen["tool_names"])
        self.assertTrue(names)
        self.assertFalse(names & SA.FILE_WRITE_TOOLS)
        self.assertFalse({n for n in names if SA.child_refusal(n)})
        self.assertFalse(names & {"node", "asset", "identities", "oracle_commit", "release_phase", "race", "sweep"})
        self.assertNotIn("_root_override", seen["extra"])

    def test_write_access_only_for_an_isolated_child_inside_its_worktree(self):
        if not shutil.which("git"):
            self.skipTest("git is not installed")
        import gnoc_worktree
        import subprocess
        env = gnoc_worktree.git_env()
        for args in (["init", "-q", "-b", "main"], ["config", "user.email", "t@example.invalid"],
                     ["config", "user.name", "t"], ["config", "commit.gpgsign", "false"], ["add", "-A"],
                     ["commit", "-qm", "init"]):
            subprocess.run(["git", "-C", self.repo, *args], capture_output=True, env=env)
        seen = {}

        def fake_worker(ctx, task, **kw):
            wctx = G.Ctx(dict(ctx.s, _worker=True, **kw["extra"]))
            seen["tools"] = kw["tool_names"]
            seen["edit"] = G._exec("edit_file", {"path": "a.py", "old": "x = 1", "new": "x = 2"}, wctx)
            seen["escape"] = G._exec("write_file", {"path": os.path.join(self.tmp, "out.txt"), "content": "n"}, wctx)
            return 'done {"result": "set x to 2", "evidence": ["a.py"], "files": ["a.py"], "open_questions": []}'

        with mock.patch.object(G, "run_worker", fake_worker):
            out = G.t_delegate(self.ctx, tasks=[{"task": "set x to 2 in a.py and run its tests", "isolated": True}])
        self.assertIn("edit_file", seen["tools"])
        self.assertIn("edited", seen["edit"])
        self.assertIn("refused", seen["escape"])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "out.txt")))
        with open(os.path.join(self.repo, "a.py")) as f:
            self.assertEqual(f.read(), "x = 1\n")      # the lead's checkout is untouched
        row = _rows(out)[0]
        self.assertEqual(row["files"], ["a.py"])
        self.assertTrue(any(e.startswith("patch (NOT applied): ") for e in row["evidence"]), row)

    def test_an_isolated_task_needs_the_leads_approval(self):
        rule = G.TOOLS["delegate"][2]
        self.assertFalse(rule({"tasks": ["read a.py"]}))
        self.assertTrue(rule({"tasks": ["read a.py", {"task": "edit b.py", "isolated": True}]}))
        self.assertTrue(rule({"task": "edit a.py", "isolated": True}))


class BackwardCompatibleAndValidated(Base):
    def test_single_task_returns_the_workers_digest_unchanged(self):
        with mock.patch.object(G, "run_worker", lambda ctx, task, **k: "worker digest"):
            self.assertEqual(G.t_delegate(self.ctx, "read inventory/store.py and list its public methods"),
                             "worker digest")

    def test_one_bad_task_refuses_the_call_before_any_child_starts(self):
        ran = []
        with mock.patch.object(G, "run_worker", lambda ctx, task, **k: ran.append(task) or "x"):
            out = G.t_delegate(self.ctx, tasks=["read a.py and say what x is", "short"])
            self.assertTrue(out.startswith("bad arguments: task 2:"), out)
            out = G.t_delegate(self.ctx, tasks=["read a.py and say what x is", "read <path> and report it back"])
            self.assertIn("placeholder", out)
        self.assertEqual(ran, [])

    def test_no_task_at_all(self):
        self.assertTrue(G.t_delegate(self.ctx).startswith("bad arguments: delegate needs task="))
        self.assertTrue(G.t_delegate(self.ctx, tasks="{\"not\": \"a list\"}").startswith("bad arguments: tasks"))

    def test_tasks_as_a_json_string_from_a_small_model(self):
        seen = []
        with mock.patch.object(G, "run_worker", lambda ctx, task, **k: seen.append(task) or "ok"):
            G.t_delegate(self.ctx, tasks=json.dumps(["read a.py and say what x is", "read a.py and say what y is"]))
        self.assertEqual(len(seen), 2)

    def test_tasks_through_the_tool_wrapper_are_accepted(self):
        with mock.patch.object(G, "run_worker", lambda ctx, task, **k: "ok"):
            out = G._exec("delegate", {"tasks": ["read a.py and say what x is"]}, self.ctx)
        self.assertIn("== child 1", out)


class ParseSummary(unittest.TestCase):
    def test_fenced(self):
        s = SA.parse_summary('text\n```json\n{"result": "r", "evidence": "e", "files": ["f"]}\n```\nbye')
        self.assertEqual(s, {"result": "r", "evidence": ["e"], "files": ["f"], "open_questions": []})

    def test_bare_with_prose_around_and_a_trailing_comma(self):
        s = SA.parse_summary('I did it. {"result": "ok {braces} in text", "open_questions": ["q"],} thanks')
        self.assertEqual(s["result"], "ok {braces} in text")
        self.assertEqual(s["open_questions"], ["q"])

    def test_the_last_object_wins_over_quoted_data(self):
        s = SA.parse_summary('the api said {"result": "theirs"}\n\n{"result": "mine", "files": []}')
        self.assertEqual(s["result"], "mine")

    def test_no_json_falls_back_to_the_text(self):
        s = SA.parse_summary("just prose, no summary")
        self.assertEqual(s["result"], "just prose, no summary")
        self.assertEqual(s["evidence"], [])

    def test_malformed_input_never_raises(self):
        for junk in (None, "", "{", "{{{}", '{"result": ', 123, "```json\n{bad}\n```"):
            self.assertIn("result", SA.parse_summary(junk))

    def test_status_comes_from_how_the_worker_ended(self):
        self.assertEqual(SA.status_of("worker failed: boom"), "failed")
        self.assertEqual(SA.status_of("worker hit its time limit; its digest:\nx"), "time_limit")
        self.assertEqual(SA.status_of("worker hit its token limit; its digest:\nx"), "token_limit")
        self.assertEqual(SA.status_of(None), "cancelled")
        self.assertEqual(SA.status_of("all good"), "done")


FAKE_CLAUDE = """#!/bin/sh
echo $$ > "{pidfile}"
exec sleep 60
"""


class ClaudeWorkerIsOptionalAndStopsOnCtrlC(Base):
    def setUp(self):
        super().setUp()
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        self.pidfile = os.path.join(self.tmp, "claude.pid")

    def _path_without_claude(self):
        keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
                if d and not os.path.exists(os.path.join(d, "claude"))]
        return os.pathsep.join([self.bin] + keep)

    def test_without_the_cli_it_says_how_to_install_and_is_not_offered(self):
        with mock.patch.dict(os.environ, {"PATH": self._path_without_claude()}):
            self.assertIsNone(shutil.which("claude"))
            out = G.t_claude_worker(self.ctx, "recon-scout", "map the repo and report the entry points")
            self.assertEqual(out, SA.CLAUDE_MISSING)
            self.assertIn("npm install -g @anthropic-ai/claude-code", out)
            self.assertTrue(G.offline())
            offered = {t["function"]["name"] for t in G.turn_tools(False, False, code=True) or []}
            self.assertNotIn("claude_worker", offered)

    def test_its_approval_rule_is_still_always(self):
        self.assertEqual(G.TOOLS["claude_worker"][2], "always")

    def _start_fake_worker(self):
        path = os.path.join(self.bin, "claude")
        with open(path, "w") as f:
            f.write(FAKE_CLAUDE.format(pidfile=self.pidfile))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        jobs = os.path.join(self.tmp, "jobs")
        with mock.patch.dict(os.environ, {"PATH": self._path_without_claude()}), \
                mock.patch.object(G, "offline", lambda: False), mock.patch.object(G, "WS", self.tmp), \
                mock.patch.object(G, "JOBS_DIR", jobs), mock.patch.object(G, "_bind_lane", lambda pid, label: False):
            out = G.t_claude_worker(self.ctx, "recon-scout", "map the repo and report the entry points")
        self.assertIn("started claude worker", out)
        self.assertTrue(_wait_for(lambda: os.path.exists(self.pidfile) and open(self.pidfile).read().strip()))
        return int(open(self.pidfile).read().strip())

    @staticmethod
    def _alive(pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        try:
            with open(f"/proc/{pid}/stat") as f:
                return f.read().split()[2] != "Z"
        except OSError:
            return True

    def test_ctrl_c_in_a_turn_kills_the_claude_workers_process_group(self):
        if os.name != "posix" or not shutil.which("timeout"):
            self.skipTest("needs POSIX process groups and coreutils timeout")
        pid = self._start_fake_worker()
        self.assertTrue(self._alive(pid))
        self.assertTrue(SA.claude_workers())

        def llm(*a, **k):
            raise KeyboardInterrupt

        agent = G.Agent(interactive=False)
        agent.s["self_review"] = False
        agent.s["learn"] = False
        with mock.patch.object(G, "llm_chat", llm):
            agent.turn("read a.py and tell me what x is")
        self.assertTrue(agent.interrupted)
        self.assertTrue(_wait_for(lambda: not self._alive(pid), 5), "the claude worker survived Ctrl-C")
        self.assertEqual(SA.claude_workers(), [])

    def test_kill_with_nothing_started_is_a_no_op(self):
        self.assertEqual(SA.kill_claude_workers(), [])

    def tearDown(self):
        try:
            pid = int(open(self.pidfile).read().strip())
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (OSError, ValueError):
            pass
        SA.kill_claude_workers(grace=0)
        super().tearDown()


if __name__ == "__main__":
    unittest.main()
