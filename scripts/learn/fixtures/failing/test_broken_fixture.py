"""Deliberately failing fixture for the soak's error-recovery batch. NOT part of the real suite:
it lives under fixtures/ so `pytest test_*.py` in scripts/ never collects it. One test passes and
one fails, so a run of it produces a real, honest failure the agent has to report."""
import unittest


class BrokenFixture(unittest.TestCase):
    def test_this_one_passes(self):
        self.assertEqual(2 + 2, 4)

    def test_this_one_fails_on_purpose(self):
        self.assertEqual(sum([1, 2, 3]), 7, "deliberate: the soak needs a real failure to report")
