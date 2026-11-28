"""Tests for the soak driver: the flag detector, the output-dir refusal and the run report."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOAK = os.path.join(HERE, "learn", "soak.py")


def load():
    """Exec soak.py without running main(), so importing it needs no argv and writes nothing."""
    src = open(SOAK, encoding="utf-8").read().replace("\nmain()", "\npass")
    ns = {"__name__": "soak_under_test", "__file__": SOAK}   # a release names the workspace from __file__
    exec(compile(src, SOAK, "exec"), ns)
    return ns


class FlagDetector(unittest.TestCase):
    """Batch 8 run 12 asked the agent to read soak.py and suggest another defect class. It answered
    correctly, reproduced this file's own flag table, and was flagged model-down and toolcall-parse
    because "`model-down` | Cannot start or failed twice" matches the dead-model pattern."""

    def setUp(self):
        ns = load()
        self.BAD, self.first = ns["BAD"], ns["first_real_hit"]

    def flags(self, text):
        return sorted(tag for rx, tag in self.BAD if self.first(rx, text))

    def test_the_model_quoting_the_flag_table_is_not_a_flag(self):
        row = ("| `model-down` | Cannot start or failed twice | | "
               "| `toolcall-parse` | Tool call could not be parsed |")
        self.assertEqual(self.flags(row), [])

    def test_a_flag_name_in_backticks_mid_sentence_is_not_a_flag(self):
        self.assertEqual(self.flags("the flag `could not be parsed` is the toolcall-parse one"), [])

    def test_real_harness_output_still_flags(self):
        self.assertEqual(self.flags("  the model cannot start: ollama returned 500"), ["model-down"])
        self.assertEqual(self.flags("  tool call could not be parsed: unexpected token"), ["toolcall-parse"])
        self.assertEqual(self.flags("  bad arguments: learn needs text"), ["bad-args"])
        self.assertEqual(self.flags("Traceback (most recent call last):"), ["traceback"])

    def test_a_real_failure_is_still_caught_when_the_answer_also_quotes_the_table(self):
        row = "| `model-down` | Cannot start or failed twice |"
        self.assertEqual(self.flags(row + "\n  the model cannot start: ollama 500"), ["model-down"])


class RunReport(unittest.TestCase):
    """Fourteen batches of rows were only readable one jsonl at a time, so the trend that matters -
    flags falling while the findings got worse - had to be re-derived by hand each time."""

    def test_the_report_tables_every_batch_in_a_directory(self):
        import json
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "bX.jsonl"), "w") as fh:
                fh.write(json.dumps({"prompt": "a", "rc": 0, "secs": 10.0, "flags": ["bad-args"]}) + "\n")
                fh.write(json.dumps({"prompt": "b", "rc": 0, "secs": 20.0, "flags": []}) + "\n")
            with open(os.path.join(d, "bY.jsonl"), "w") as fh:
                fh.write(json.dumps({"prompt": "c", "rc": 0, "secs": 5.0, "flags": [], "turn": 1}) + "\n")
            r = subprocess.run([sys.executable, SOAK, "--report"], cwd=d, env=dict(os.environ, SOAK_OUT=d),
                               capture_output=True, text=True, timeout=120)
        out = r.stdout
        self.assertIn("bX", out)
        self.assertIn("bY", out)
        self.assertIn("bad-argsx1", out)
        self.assertIn("yes", out)                       # bY is chained
        self.assertRegex(out, r"TOTAL\s+3\s+1")
        # it must say out loud what a flag cannot see, so the table is not read as coverage
        self.assertIn("cannot see a wrong answer", out)

    def test_the_report_writes_nothing_and_survives_an_empty_directory(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, SOAK, "--report"], cwd=d, env=dict(os.environ, SOAK_OUT=d),
                               capture_output=True, text=True, timeout=120)
            self.assertIn("no batch rows", r.stdout)
            self.assertEqual(os.listdir(d), [])


class OutputDirectory(unittest.TestCase):
    def test_rows_are_refused_into_the_tracked_tree(self):
        src = open(SOAK, encoding="utf-8").read()
        self.assertIn("refusing to write rows into the tracked tree", src)
        self.assertIn("SOAK_OUT", src)


if __name__ == "__main__":
    unittest.main()
