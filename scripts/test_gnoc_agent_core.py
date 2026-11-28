#!/usr/bin/env python3
"""Regression tests for the agent core: the turn wrapper, slash dispatch and tool dispatch.

These tests deliberately do not call a model, the network or a real tool.  They exercise
the seams that the refactors must keep stable:

  * Agent.turn() success and failure bookkeeping
  * handle_slash() routing for help/exit/unknown/goal/plan/effort/mode
  * _plan_call()/run_tools() refusal and parallel dispatch
  * gnoc_agent.WS/AGENT_DIR/TASKS rebinding stays in sync with gnoc_core.state

    python3 -m unittest scripts/test_gnoc_agent_core.py -v
"""
import contextlib
import importlib
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))


class AgentCoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-agent-core-test-")
        self._old_env = {k: os.environ.get(k) for k in ("GNOC_WORKSPACE", "GNOC_WS")}
        os.environ["GNOC_WORKSPACE"] = self.tmp
        os.environ["GNOC_WS"] = self.tmp
        import gnoc_agent
        self.G = importlib.reload(gnoc_agent)
        self.G.INTERRUPT.clear()

    def tearDown(self):
        self.G.INTERRUPT.clear()
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        for name in ("gnoc_agent",):
            if name in sys.modules:
                importlib.reload(sys.modules[name])
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_agent(self):
        agent = self.G.Agent.__new__(self.G.Agent)
        agent.s = {"sid": "test-sid", "history": []}
        agent.ctx = self.G.Ctx(agent.s)
        agent.interactive = False
        agent.interrupted = False
        agent.save = lambda: None
        return agent

    # ------------------------------------------------------------------ turn
    def test_turn_returns_answer_and_records_both_phases(self):
        agent = self.fake_agent()
        seen, alerts = [], []
        agent._turn = lambda text, deep=False: "hello back"
        agent._done_gate = lambda text: None
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.G, "_activity", seen.append))
            stack.enter_context(mock.patch.object(self.G, "_turn_done_alert",
                                                  lambda secs, answer: alerts.append(answer)))
            stack.enter_context(mock.patch.object(self.G, "say", lambda *a, **k: None))
            answer = agent.turn("hello")
        self.assertEqual(answer, "hello back")
        self.assertEqual(alerts, ["hello back"])
        self.assertEqual([r.get("phase") for r in seen], ["start", "end"])
        self.assertTrue(seen[-1].get("ok"))
        self.assertEqual(agent.s["_turn_user"], "hello")

    def test_turn_failure_is_contained_and_saved(self):
        agent = self.fake_agent()
        saved, out, logged = [], [], []

        def explode(text, deep=False):
            raise ValueError("boom")

        agent._turn = explode
        agent.save = lambda: saved.append(True)

        def log_error(e):
            logged.append(str(e))
            return "trace.txt"

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.G, "_activity", lambda row: None))
            stack.enter_context(mock.patch.object(self.G, "SPIN", types.SimpleNamespace(stop=lambda: None)))
            stack.enter_context(mock.patch.object(self.G, "TYPED", types.SimpleNamespace(stop=lambda: "")))
            stack.enter_context(mock.patch.object(self.G, "_log_error", log_error))
            stack.enter_context(mock.patch.object(self.G, "say", lambda text: out.append(str(text))))
            answer = agent.turn("hello")
        self.assertEqual(answer, "")
        self.assertEqual(saved, [True])
        self.assertEqual(logged, ["boom"])
        self.assertTrue(self.G.INTERRUPT.is_set())
        self.assertTrue(any("turn failed" in row for row in out))
        self.assertTrue(agent.interrupted is False or agent.interrupted is True)  # unchanged either way

    def test_polite_closing_after_a_read_is_not_a_stalled_plan(self):
        closing = ("The file could not be found. The closest files are hello.txt and notes/t23.txt. "
                   "Let me know if you need help with the existing files!")
        self.assertFalse(self.G.needs_plan_push(closing, used_tools=True))
        plan = "I'll edit the file and then run the tests to verify the change."
        self.assertTrue(self.G.needs_plan_push(plan, used_tools=True))
        howto = "You can run pytest to see the failure, then fix it."
        self.assertTrue(self.G.needs_plan_push(howto, used_tools=False))

    def test_showing_a_code_block_is_not_an_order_to_run_it(self):
        self.assertTrue(self.G.wants_advice("Show a fenced bash code block that prints hello."))
        self.assertTrue(self.G.wants_advice("Please show a table of three colors."))
        self.assertFalse(self.G.wants_advice("Show me the error and then fix it."))
        self.assertFalse(self.G.wants_advice("Show me the error, then fix it."))
        self.assertFalse(self.G.wants_advice("List the files and then run the tests."))

    # ------------------------------------------------------------ slash dispatch
    def test_slash_help_exit_unknown_goal_and_plan(self):
        agent = self.fake_agent()
        out, goal_calls = [], []
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.G, "say", lambda text: out.append(str(text))))
            stack.enter_context(mock.patch.object(self.G, "help_text", lambda: "HELP TEXT"))
            stack.enter_context(mock.patch.object(self.G, "goal_cmd",
                                                  lambda a, rest: goal_calls.append((a, rest))))
            self.assertIsNone(self.G.handle_slash(agent, "/help", {}))
            self.assertTrue(any("HELP TEXT" in row for row in out))

            out.clear()
            self.assertIsNone(self.G.handle_slash(agent, "/goal show", {}))
            self.assertEqual(goal_calls, [(agent, "show")])

            out.clear()
            with mock.patch.object(self.G.gnoc_plan, "load", return_value=None):
                self.assertIsNone(self.G.handle_slash(agent, "/plan show", {}))
            self.assertTrue(any("no plan yet" in row for row in out))

            out.clear()
            self.assertIsNone(self.G.handle_slash(agent, "/not-a-command", {}))
            self.assertTrue(any("unknown command" in row for row in out))

            out.clear()
            self.assertEqual(self.G.handle_slash(agent, "/exit", {}), "exit")
            self.assertTrue(any("leaving the chat" in row for row in out))

    def test_slash_effort_and_mode_update_session(self):
        agent = self.fake_agent()
        saved = []
        agent.save = lambda: saved.append(True)
        old_effort = self.G.EFFORT[0]
        try:
            with mock.patch.object(self.G, "say", lambda text: None):
                self.G.handle_slash(agent, "/effort high", {})
            self.assertEqual(self.G.EFFORT[0], "high")
            self.assertEqual(agent.s["effort"], "high")
            self.assertTrue(saved)
            with mock.patch.object(self.G, "say", lambda text: None):
                self.G.handle_slash(agent, "/mode auto", {})
            self.assertEqual(agent.s["mode"], "auto")
        finally:
            self.G.EFFORT[0] = old_effort
            self.G.STEPS_OVERRIDE[0] = None

    # ------------------------------------------------------------- tool dispatch
    def test_plan_call_refuses_unknown_malformed_and_missing_arguments(self):
        ctx = self.G.Ctx({"sid": "test-sid"})
        name, _args, pre = self.G._plan_call("definitely_not_a_tool", {}, ctx, False, None)
        self.assertEqual(name, "definitely_not_a_tool")
        self.assertIn("unknown or unavailable tool", pre)

        _name, _args, pre = self.G._plan_call(
            "read_file", {self.G.MALFORMED_ARGS: "{"}, ctx, False, None)
        self.assertIn("not valid JSON", pre)

        _name, _args, pre = self.G._plan_call("read_file", {}, ctx, False, None)
        self.assertIn("read_file needs path", pre)

    def test_run_tools_dispatches_parallel_calls_and_returns_one_message_each(self):
        ctx = self.G.Ctx({"sid": "test-sid"})
        original = self.G.TOOLS
        tools = dict(original)
        schema = self.G._fn("_test_echo", "echo a value", {"value": {"type": "string"}})
        tools["_test_echo"] = (lambda ctx, value="": f"echo:{value}", schema, None)
        self.G.TOOLS = tools
        try:
            seen = []
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(self.G, "show_result",
                                                      lambda *a, **k: None))
                stack.enter_context(mock.patch.object(self.G, "say", lambda *a, **k: None))
                stack.enter_context(mock.patch.object(self.G, "_activity", seen.append))
                stack.enter_context(mock.patch.object(self.G.SPIN, "start", lambda *a, **k: None))
                stack.enter_context(mock.patch.object(self.G.SPIN, "stop", lambda *a, **k: None))
                calls = [{"function": {"name": "_test_echo", "arguments": {"value": "one"}}},
                         {"function": {"name": "_test_echo", "arguments": '{"value": "two"}'}}]
                msgs = self.G.run_tools(calls, ctx, interactive=False)
            self.assertEqual(len(msgs), 2)
            self.assertEqual([m["role"] for m in msgs], ["tool", "tool"])
            self.assertEqual([m["tool_name"] for m in msgs], ["_test_echo", "_test_echo"])
            self.assertEqual([m["content"] for m in msgs], ["echo:one", "echo:two"])
            self.assertTrue(any(r.get("ev") == "tool" and r.get("phase") == "end" for r in seen))
        finally:
            self.G.TOOLS = original

    # ----------------------------------------------------------------- state
    def test_workspace_rebindings_stay_in_sync_with_state(self):
        other = os.path.join(self.tmp, "other-ws")
        self.G.WS = other
        self.assertEqual(self.G.STATE.ws, other)
        self.assertEqual(self.G.WS, other)

        agent_dir = os.path.join(self.tmp, "custom-agent")
        self.G.AGENT_DIR = agent_dir
        self.assertEqual(self.G.STATE.agent_dir, agent_dir)
        self.assertTrue(self.G.session_file().startswith(agent_dir + os.sep))

        tasks = os.path.join(self.tmp, "custom-tasks.jsonl")
        self.G.TASKS = tasks
        self.assertEqual(self.G.STATE.tasks, tasks)

        self.G.SKIP_PERMS[0] = True
        self.assertTrue(self.G.STATE.skip_perms[0])
        self.G.SKIP_PERMS[0] = False


class SplitSeams20261118(AgentCoreTestCase):
    """The core/tools split must never fail at call time: a missing facade name, a bind() whose targets
    drift from its names, or a facade patch that the moved code cannot see would all pass import and
    lint, then break (or silently stop testing) in the middle of a live turn."""

    PKGS = ("gnoc_core", "gnoc_tools")

    def _bind_calls(self):
        import ast
        import glob
        for pkg in self.PKGS:
            for f in sorted(glob.glob(os.path.join(ROOT, "scripts", pkg, "*.py"))):
                tree = ast.parse(open(f, encoding="utf-8").read())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                            and getattr(node.value.func, "id", None) == "bind":
                        yield f, node

    def test_every_bound_name_exists_on_the_facade(self):
        missing = []
        n = 0
        for f, node in self._bind_calls():
            for a in node.value.args:
                n += 1
                if not hasattr(self.G, a.value):
                    missing.append(f"{os.path.basename(f)}:{node.lineno} {a.value}")
        self.assertGreater(n, 100)
        self.assertEqual(missing, [], "bind() names the facade no longer defines (an 'unused' import "
                                      "removed from gnoc_agent.py?)")

    def test_bind_targets_match_their_names(self):
        import ast
        bad = []
        for f, node in self._bind_calls():
            names = [a.value for a in node.value.args]
            tgt = node.targets[0]
            got = [e.id for e in tgt.elts] if isinstance(tgt, ast.Tuple) else None
            if got != names:
                bad.append(f"{os.path.basename(f)}:{node.lineno}")
        self.assertEqual(bad, [])

    def test_a_facade_patch_reaches_the_core_module_that_calls_it(self):
        import gnoc_core.session as S
        saved = self.G._origin
        self.G._origin = lambda: "cc:patched-origin"
        try:
            self.assertEqual(S._origin(), "cc:patched-origin")
            self.assertIn("session-cc-patched-origin", self.G.session_file())
        finally:
            self.G._origin = saved
        self.assertIs(S._origin, saved)
        with mock.patch.object(self.G, "_origin", lambda: ""):
            self.assertEqual(self.G.session_file(), self.G.legacy_session())
        self.assertIs(S._origin, saved)

    def test_a_patch_never_put_back_is_undone_by_the_next_reload(self):
        import gnoc_core.session as S
        real = S._origin
        self.G._origin = lambda: "cc:leaked"          # a test that forgets to restore
        self.assertEqual(S._origin(), "cc:leaked")
        self.G = importlib.reload(self.G)
        self.assertIs(S._origin, real)
        self.assertIs(self.G._origin, real)

    def test_a_facade_only_name_is_not_pushed_into_core(self):
        import gnoc_core.session as S
        with mock.patch.object(self.G, "offline", lambda: True):
            self.assertNotIn("offline", vars(S))


class TitlesAreGreyNOCsWords20261118(AgentCoreTestCase):
    """/sessions listed chats as "You laid out a plan but have not carried it out" and "(no message)":
    the user's first message had been wrapped in a BOT EVENTS / interrupt preamble, so the title fell
    through to the next user-role message, which was gnoc's own nudge."""

    def test_bot_events_preamble_is_peeled(self):
        h = [{"role": "user", "content": "BOT EVENTS since my last message:\n[inbox] a\n[inbox] b\n\n"
                                         "how is the defensive posture"},
             {"role": "user", "content": "You laid out a plan but have not carried it out: nothing"}]
        self.assertEqual(self.G._title_of(h), "how is the defensive posture")

    def test_interrupt_stub_and_preamble(self):
        h = [{"role": "user", "content": "[an earlier request here was interrupted and dropped by the user]"},
             {"role": "user", "content": "BOT EVENTS since my last message:\n[x]\n\n[I interrupted my previous "
                                         "request on purpose: drop it.]\n\nwhere is the report?"}]
        self.assertEqual(self.G._title_of(h), "where is the report?")

    def test_only_nudges_left_after_compaction(self):
        h = [{"role": "user", "content": self.G.NOTES_TAG + " ..."},
             {"role": "user", "content": "The WORKER model on the other GPU worked the same request"},
             {"role": "user", "content": "You carried out part of this but your own answer still names work"},
             {"role": "user", "content": "check gatewayco again"}]
        self.assertEqual(self.G._title_of(h), "check gatewayco again")

    def test_a_preamble_with_nothing_after_it_is_not_a_title(self):
        self.assertEqual(self.G._title_of([{"role": "user", "content": "BOT EVENTS since my last message:\n[x]"}]),
                         "(no message)")

    def test_a_stale_stored_title_is_worked_out_again(self):
        d = {"title": "You laid out a plan but have not carried it out: n",
             "history": [{"role": "user", "content": "defend"}]}
        self.assertEqual(self.G._stored_title(d), "defend")
        self.assertEqual(self.G._stored_title({"title": "hello", "history": []}), "hello")


class RunAsScriptIsOneModule20261118(unittest.TestCase):
    """`gnoc_agent.py --job-health` (the worker wrapper) runs the facade as __main__. bind() looks the facade
    up as sys.modules["gnoc_agent"]: without the alias it imported a second copy whose import re-ran
    STATE.reset() under the running one."""

    def test_job_health_as_main_imports_the_facade_once(self):
        import subprocess
        tmp = tempfile.mkdtemp(prefix="gnoc-main-probe-")
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "job.out")
        with open(out, "w") as fh:
            fh.write("partial worker output")
        probe = (
            "import sys\n"
            "import gnoc_core.state as st\n"
            "n = []\n"
            "orig = st.RuntimeState.reset\n"
            "st.RuntimeState.reset = lambda self, *a, **k: (n.append(1), orig(self, *a, **k))[1]\n"
            "sys.argv = ['gnoc_agent.py', '--job-health', %r]\n"
            "exec(compile(open('gnoc_agent.py').read(), 'gnoc_agent.py', 'exec'), sys.modules['__main__'].__dict__)\n"
            "print('RESETS', len(n), sys.modules.get('gnoc_agent') is sys.modules['__main__'])\n" % out)
        scripts = os.path.join(ROOT, "scripts")
        r = subprocess.run([sys.executable, "-c", probe], cwd=scripts, capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, PYTHONPATH=scripts, GNOC_WORKSPACE=tmp, GNOC_WS=tmp))
        self.assertIn("RESETS 1 True", r.stdout, r.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
