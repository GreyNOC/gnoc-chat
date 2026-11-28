"""Tests for the lesson-book admission gate (stdlib unittest, no network, no writes)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_learn as L  # noqa: E402


class HarnessTrivia(unittest.TestCase):
    """The reflection writes a lesson whenever a tool call is uneventful. The 2026-10-25 soak put four
    into the live book in one night - "The host 'bb-hunt-system' (via read_file) correctly identifies
    'hunt-index.py' as a real file" - and one of them was FALSE: it claimed read_file reports no such
    file for a path that exists, when the path had never existed."""

    def test_narrating_our_own_tooling_is_refused(self):
        for text in ("The host 'bb-hunt-system' (via read_file) correctly identifies 'hunt-index.py'",
                     "The host 'bb-hunt-system' (via git log) successfully aggregates a 'workspace' path",
                     "The host 'bb-hunt-system' reports 'no such file' for scripts/x.py"):
            ok, why = L.worth_keeping(text, why="seen twice in this turn", kind="fact")
            self.assertFalse(ok, text)
            self.assertIn("our own tooling", why)

    def test_a_lesson_about_what_a_tool_requires_is_kept(self):
        """The useful tool lesson says what it REQUIRES or how it FAILS, so the gate matches the
        narration shape and not the word "tool"."""
        ok, why = L.worth_keeping(
            "The tool 'race' requires an explicit n parameter; it pairs a burst with a serial control",
            why="race refused to run without n on 2026-10-25", kind="rule")
        self.assertTrue(ok, why)

    def test_a_target_lesson_is_untouched(self):
        ok, why = L.worth_keeping(
            "connect.initech.com is tagged no-bounty, so a 7.0 there is fix-only",
            why="GATES.md line 16 of the nomailbox draft", kind="fact")
        self.assertTrue(ok, why)


if __name__ == "__main__":
    unittest.main()
