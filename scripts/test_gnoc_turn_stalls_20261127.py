"""Regression tests for the second 2026-11-27 paste: a simple request ended with nothing run.

  - "ok can you buffer the red team and assist and see if you can get into our DB's" opened with "ok" and matched
    no work word, so it ran as small talk with NO tools; the lead wrote site_redteam as text four times and the turn
    ended with nothing done;
  - "can we hunt your-site.example and set a goal to get a cvss 10": goal set was refused as "their call" though the user
    had just asked for it, and set_program/pivot treated their own site as a HackerOne program;
  - "hello" showed "Let me analyze the conversation context: ..." above the answer with /thoughts off.
"""
import os
import sys
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
from gnoc_core import llmwire  # noqa: E402


class RequestsAfterAnOpenerAreWork(unittest.TestCase):
    def test_the_message_that_stalled_gets_tools(self):
        t = "ok can you buffer the red team and assist and see if you can get into our DB's"
        self.assertFalse(G.is_conversation(t))
        self.assertFalse(G.is_small_talk(t))

    def test_other_requests_after_an_opener(self):
        for t in ("ok could you check our database", "thanks, please red team the site again",
                  "cool let's see if the db is reachable", "hey can you pentest the login"):
            self.assertFalse(G.is_conversation(t), t)

    def test_real_small_talk_stays_small_talk(self):
        for t in ("hello!", "ok", "thanks", "how are you today?", "good morning", "cool, thanks"):
            self.assertTrue(G.is_small_talk(t), t)


class GoalHisWords(unittest.TestCase):
    def _ctx(self, text):
        return types.SimpleNamespace(program=None, s={"_turn_text": text})

    def test_his_ask_replaces_the_standing_goal(self):
        cur = {"status": "active", "text": "get a CVSS 10"}
        with mock.patch.object(G.gnoc_goal, "load", return_value=cur), \
             mock.patch.object(G.gnoc_goal, "set_goal", return_value=({"text": "x"}, None)) as sg, \
             mock.patch.object(G.gnoc_goal, "status_text", return_value="goal: x"), \
             mock.patch.object(G, "_seed_goal", return_value=""), \
             mock.patch.object(G, "warn_goal_excluded", return_value=None):
            out = G.TOOLS["goal"][0](self._ctx("can we hunt it and set a goal to get a cvss 10"), action="set",
                                     text="Find a CVSS 10")
        self.assertNotIn("refused", out)
        sg.assert_called_once()

    def test_without_his_ask_the_standing_goal_is_kept(self):
        cur = {"status": "active", "text": "get a CVSS 10"}
        with mock.patch.object(G.gnoc_goal, "load", return_value=cur), \
             mock.patch.object(G.gnoc_goal, "set_goal", side_effect=AssertionError("replaced without their ask")):
            out = G.TOOLS["goal"][0](self._ctx("continue"), action="set", text="Something else")
        self.assertIn("refused", out)


class OwnSiteIsNotAProgram(unittest.TestCase):
    def setUp(self):
        import gnoc_site
        p = mock.patch.object(gnoc_site, "_env", return_value={"PUBLIC_URL": "https://your-site.example"})
        p.start()
        self.addCleanup(p.stop)

    def test_set_program_points_at_the_site_tools(self):
        ctx = types.SimpleNamespace(program=None, s={})
        out = G.TOOLS["set_program"][0](ctx, program="your-site.example")
        self.assertIn("OWN site", out)
        self.assertIn("site_redteam", out)
        self.assertNotIn("gnoc pivot", out)
        self.assertIsNone(ctx.s.get("program"))

    def test_a_real_program_is_untouched(self):
        from gnoc_tools.hunt import _own_site_note
        self.assertIsNone(_own_site_note("program-19"))
        self.assertIsNone(_own_site_note("example.com"))


class UntaggedAnalysisPreamble(unittest.TestCase):
    PASTE = ("Let me analyze the conversation context:\n\n"
             "1. System Identity: GNOC is the user's local assistant and coding agent, running on their own computer\n"
             "2. Current Date: 2026-11-27 (UTC)\n"
             "3. Constraints:\n   • Reply in one or two short, friendly sentences\n   • Call no tools\n\n"
             "The user is greeting me casually, so I should respond in a friendly, conversational manner.\n\n"
             "Let me craft a response that:\n• Acknowledges the greeting warmly\n• Sounds natural\n\n\n"
             "Hello! I'm GNOC, your local assistant. What would you like to tackle first?")

    def test_the_whole_preamble_is_split_off(self):
        reasoning, answer = llmwire.split_untagged_reasoning(self.PASTE)
        self.assertTrue(answer.startswith("Hello! I'm GNOC"), answer[:60])
        self.assertIn("Let me analyze", reasoning)

    def test_the_live_gate_holds_it_back(self):
        g = llmwire.PreambleGate()
        shown = "".join(g.feed(self.PASTE[i:i + 7]) for i in range(0, len(self.PASTE), 7)) + g.finish()
        self.assertTrue(shown.lstrip().startswith("Hello! I'm GNOC"), shown[:80])

    def test_an_answer_about_his_files_is_not_reasoning(self):
        text = "Let me analyze the log file you sent:\n\nIt shows three 500s at 02:14."
        self.assertEqual(llmwire.split_untagged_reasoning(text)[0], "")


class WrittenCallToAnUnofferedTool(unittest.TestCase):
    """The turn loop: a call written as text to a tool the turn did not offer loads that tool once, instead of
    three nudges that cannot work."""

    def setUp(self):
        import shutil
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="gnoc-stall-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        saved = {n: getattr(G, n) for n in ("AGENT_DIR", "SESSIONS_DIR", "resolve", "llm_chat", "run_tools", "say",
                                            "turn_tools")}
        self.addCleanup(lambda: [setattr(G, n, v) for n, v in saved.items()])
        G.AGENT_DIR, G.SESSIONS_DIR = self.tmp, os.path.join(self.tmp, "sessions")
        self.said = []
        G.say = lambda *a, **k: self.said.append(" ".join(str(x) for x in a))
        G.resolve = lambda role, quiet=False: ("m", "local")
        touch = G.gnoc_hf.touch
        G.gnoc_hf.touch = lambda *a, **k: None
        self.addCleanup(setattr, G.gnoc_hf, "touch", touch)

    def test_the_missing_tool_is_loaded_and_the_call_runs(self):
        offered, ran = [], []
        no_site = [G.TOOLS[n][1] for n in ("read_file", "list_dir")]
        G.turn_tools = lambda *a, **k: list(no_site)

        def scripted(model, host, msgs, *a, **k):
            names = [(t.get("function") or {}).get("name") for t in (k.get("tools") or [])]
            offered.append(names)
            if len(offered) == 1:
                return {"role": "assistant", "content": '<tool_call>\n{"name": "site_redteam", "arguments": '
                                                         '{"checks": "headers store"}}\n</tool_call>'}
            if "site_redteam" in names and not ran:
                return {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "site_redteam", "arguments": {"checks": "headers store"}}}]}
            return {"role": "assistant", "content": "The drill ran: 1 medium (edge HSTS)."}
        G.llm_chat = scripted

        def run(calls_, ctx, interactive, **k):
            ran.extend((c.get("function") or {}).get("name") for c in calls_)
            return [{"role": "tool", "tool_name": "site_redteam", "content": "DRILL rt-1 ran"} for _ in calls_]
        G.run_tools = run
        a = G.Agent(interactive=False)
        a.s["learn"] = False
        a.turn("red team the site and check the store encryption")
        self.assertNotIn("site_redteam", offered[0])
        self.assertIn("site_redteam", offered[1], "the written call's tool must be offered on the next step")
        self.assertEqual(ran, ["site_redteam"])
        self.assertTrue(any("was not loaded this turn" in s for s in self.said))


if __name__ == "__main__":
    unittest.main()
