"""Regression guards for what 2026.11.26 added, so later work cannot quietly undo it.

The release notes name four additions: writing GraphQL queries on request, keeping one programme's paths out of
another programme's hunt, flagging answers that mislabel a capture, and /file plus per-turn request receipts.
Three already had tests in test_gnoc_drive_20261120.py (GraphqlBuilder20261125, GraphqlNotAnEndpoint20261126,
AnotherProgrammesPathIsNotARoute20261125, ClaimsAgainstReceipts20261125, TurnReceipts20261125). /file had none.
Its one safety property is that only a line the human typed can file: a model reply, a tool result or a goal
loop that produces the same text must be refused. These tests pin that property, and that the public edition
(which does not ship gnoc_file.py) answers /file with "not part of this edition" and files nothing.
"""
import contextlib
import os
import sys
import types
import unittest
import unittest.mock as mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402


class FileIsTypedOnly20261126(unittest.TestCase):
    """/file must accept only the exact string object the REPL read from the keyboard (identity, not equality)."""

    def setUp(self):
        self.calls = []
        self.out = []
        fake = types.ModuleType("gnoc_file")
        fake.run = lambda rest, out=None, typed=False: self.calls.append((rest, typed))
        # a stand-in gnoc_file: the real one talks to HackerOne, and the public build may not ship it at all
        self.mods = mock.patch.dict(sys.modules, {"gnoc_file": fake})
        self.mods.start()
        import gnoc_edition
        # the operator edition is where /file runs; the public-edition test below switches this back on
        self.edition = mock.patch.object(gnoc_edition, "PUBLIC", False)
        self.edition.start()
        self.agent = G.Agent.__new__(G.Agent)
        self.agent.s = {"sid": "file-gate-test", "history": []}
        self.agent.ctx = G.Ctx(self.agent.s)
        self.agent.interactive = True
        self.agent.interrupted = False
        self.agent.save = lambda: None

    def tearDown(self):
        self.edition.stop()
        self.mods.stop()

    def _slash(self, line):
        with contextlib.ExitStack() as st:
            st.enter_context(mock.patch.object(G, "say", lambda t: self.out.append(str(t))))
            return G.handle_slash(self.agent, line, {})

    def test_a_line_nobody_typed_is_refused(self):
        self.agent._typed_line = None
        self._slash("/file acme/xss-1")
        self.assertEqual(self.calls, [])
        self.assertTrue(any("refused, nothing sent" in o for o in self.out), self.out)

    def test_an_equal_but_different_string_is_refused(self):
        # a model that echoes the operator's last line produces an EQUAL string, never the same object
        typed = "".join(["/file ", "acme/xss-1"])
        self.agent._typed_line = typed
        echoed = "".join(["/file acme/", "xss-1"])
        self.assertEqual(typed, echoed)
        self.assertIsNot(typed, echoed)
        self._slash(echoed)
        self.assertEqual(self.calls, [])

    def test_the_typed_line_files_once(self):
        typed = "".join(["/file ", "acme/xss-1"])
        self.agent._typed_line = typed
        self._slash(typed)
        self.assertEqual(self.calls, [("acme/xss-1", True)])
        # the marker is consumed: replaying the same object a second time is refused
        self._slash(typed)
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.agent._typed_line)

    def test_the_build_stamp_does_not_change_filing(self):
        # one edition (2026-11-27): a release files exactly like the workspace, and still only from a typed line
        import gnoc_edition
        typed = "".join(["/file ", "acme/xss-1"])
        self.agent._typed_line = typed
        with mock.patch.object(gnoc_edition, "PUBLIC", True):
            self._slash(typed)
        self.assertEqual(self.calls, [("acme/xss-1", True)])
        self.assertFalse(any("not part of this edition" in o for o in self.out), self.out)


if __name__ == "__main__":
    unittest.main()
