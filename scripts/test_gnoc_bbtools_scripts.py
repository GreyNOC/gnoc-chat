#!/usr/bin/env python3
"""The bbtools self-tests, inside the suite.

scripts/bbtools/test_*.py are script-style: their checks run under main() (or at import) and report by exit code,
so pytest collecting them directly ran nothing, and suite.sh only globs scripts/test_*.py. Before 2026-11-19 they
ran only when someone remembered to: the scope proxy (the Host-header and CONNECT gate) had no test in the suite.
Each one runs here as its own process from the workspace root, the way it is meant to be run, and must exit 0.

    python3 -m pytest -q scripts/test_gnoc_bbtools_scripts.py
"""
import glob
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.dirname(HERE)
SCRIPTS = sorted(glob.glob(os.path.join(HERE, "bbtools", "test_*.py")))


class BbtoolsSelfTests(unittest.TestCase):
    def test_there_are_self_tests_to_run(self):
        self.assertGreaterEqual(len(SCRIPTS), 4, SCRIPTS)

    def test_every_bbtools_self_test_passes(self):
        for path in SCRIPTS:
            with self.subTest(script=os.path.basename(path)):
                r = subprocess.run([sys.executable, path], cwd=WS, capture_output=True, text=True, timeout=300,
                                   stdin=subprocess.DEVNULL)
                self.assertEqual(r.returncode, 0, f"{os.path.basename(path)} failed:\n{(r.stdout + r.stderr)[-3000:]}")


if __name__ == "__main__":
    unittest.main()
