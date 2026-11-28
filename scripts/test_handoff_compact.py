"""scripts/learn/handoff-compact.py - it edits an auto-loaded operational doc, so it gets tests.

Receipt (2026-10-27): the auto-loaded instruction set has a 150k budget and past it the files are
SILENTLY truncated, so which rules are in force becomes unknowable. HANDOFF-CURRENT is the only one of
the five that grows every session - each lane appends a dated entry to section 2 - and it broke the
budget three times inside one session even while being hand-trimmed. These pin the two properties that
make the automation safe to run unattended: it moves VERBATIM (nothing is ever lost) and it refuses to
touch entries it was told to keep.
"""
import importlib.util
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("handoff_compact",
                                               os.path.join(HERE, "learn", "handoff-compact.py"))
HC = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(HC)

CUR_TEMPLATE = """# HANDOFF - CURRENT STATE ONLY

## 1. COUNTER
nothing

## 2. LOOP STATE
{entries}

## 3. DO NOT FILE
nothing
"""


def _entries(n):
    return "\n".join(f"**2026-10-{10 + i:02d} entry {i} with some body text that must survive verbatim.**"
                     for i in range(n))


class HandoffCompact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-hc-")
        self.cur = os.path.join(self.tmp, "HANDOFF-CURRENT.md")
        self.arch = os.path.join(self.tmp, "CLAUDE-HANDOFF-CRITICAL-10-07.md")
        with open(self.arch, "w") as f:
            f.write("# archive\n\n## 2026-10-01 COMPACTION 7 - earlier\n")
        self.saved = (HC.WS, HC.CUR, HC.AUTOLOADED)
        HC.WS, HC.CUR = self.tmp, self.cur
        HC.AUTOLOADED = ["HANDOFF-CURRENT.md"]

    def tearDown(self):
        HC.WS, HC.CUR, HC.AUTOLOADED = self.saved

    def _write(self, n):
        with open(self.cur, "w") as f:
            f.write(CUR_TEMPLATE.format(entries=_entries(n)))

    def _run(self, *argv):
        old = sys.argv
        try:
            sys.argv = ["handoff-compact.py", *argv]
            HC.main()
        finally:
            sys.argv = old

    def test_it_moves_the_oldest_verbatim_and_loses_nothing(self):
        self._write(8)
        original = [l for l in open(self.cur).read().splitlines() if l.startswith("**")]
        self._run("--apply", "--keep", "3", "--budget", "1")
        cur, arch = open(self.cur).read(), open(self.arch).read()
        for line in original:
            self.assertTrue(line in cur or line in arch, f"LOST: {line[:60]}")
        self.assertEqual(len([l for l in cur.splitlines() if l.startswith("**")]), 3)
        self.assertIn("COMPACTION 8", arch)      # 7 existed, so the next one is 8

    def test_it_leaves_a_pointer_to_where_they_went(self):
        self._write(6)
        self._run("--apply", "--keep", "2", "--budget", "1")
        cur = open(self.cur).read()
        self.assertIn("MOVED VERBATIM", cur)
        self.assertIn("CLAUDE-HANDOFF-CRITICAL-10-07.md", cur)
        self.assertIn("COMPACTION 8", cur)

    def test_under_budget_is_a_no_op(self):
        self._write(4)
        before = open(self.cur).read()
        self._run("--apply", "--keep", "5", "--budget", "10000000")
        self.assertEqual(before, open(self.cur).read())

    def test_it_refuses_to_cut_below_the_keep_count_even_when_over_budget(self):
        """The overage may be in ANOTHER file; eating the last live entries would not fix it and would
        throw away the only state a fresh session reads."""
        self._write(3)
        before = open(self.cur).read()
        self._run("--apply", "--keep", "5", "--budget", "1")
        self.assertEqual(before, open(self.cur).read())

    def test_it_is_idempotent(self):
        self._write(8)
        self._run("--apply", "--keep", "3", "--budget", "1")
        once = open(self.cur).read()
        self._run("--apply", "--keep", "3", "--budget", "1")
        self.assertEqual(once, open(self.cur).read())

    def test_a_dry_run_changes_nothing(self):
        self._write(8)
        before = open(self.cur).read()
        self._run("--keep", "3", "--budget", "1")
        self.assertEqual(before, open(self.cur).read())


if __name__ == "__main__":
    unittest.main()
