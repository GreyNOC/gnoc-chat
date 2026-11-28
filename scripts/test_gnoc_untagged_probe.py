"""An untagged probe is still a probe (QAQC 2026-11-03).

`http_request`'s `hypothesis` argument is optional. `gnoc_hunt.log_probe` returned early whenever it
was absent, and `gnoc_agent._econ_budget` returns early on the same condition, so an untagged probe
reached the wire and landed in NO hypothesis and NO budget. The empirical floor reads
`counted_probes(h)`, so a probe that is attached to no hypothesis is invisible to it - a hole straight
through the floor, available to anything that simply omits the tag.

Found on program-63 by the gnoc chat auditing its own control probe: capture `210947717597-get.json`
carried `"hyp": null` and appeared in no hypothesis's evidence list. Its first report of this was that
the probe had been MIS-attributed to H5; checking the ledger refuted that (H5 kept its own 18 h5-*
captures), and the real defect turned out to be unattribution, which is worse.

Untagged probes are now counted at PROGRAM level. Deliberately not a refusal: recon, policy reads and
dedup checks legitimately carry no hypothesis, and hard-failing them mid-hunt would break more than it
fixes. These tests pin both halves - the counter moves, and a TAGGED probe is unaffected.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_hunt as H  # noqa: E402


class UntaggedProbesAreCountedNotDropped(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-untagged-")
        self.saved = (H.path, H.WS)
        H.WS = self.tmp
        H.path = lambda program: os.path.join(self.tmp, "targets", program, "hunts", "gnoc", "ledger.json")
        os.makedirs(os.path.join(self.tmp, "targets", "alpha", "hunts", "gnoc"), exist_ok=True)
        with open(os.path.join(self.tmp, "targets", "alpha", "SCOPE.txt"), "w") as f:
            f.write("www.alpha-t.com\n")

    def tearDown(self):
        H.path, H.WS = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _hyp(self):
        """The ledger refuses a violation that names no concrete request, which is correct, so the
        fixture writes a real one."""
        out = H.hypothesis("alpha", "add", title="order read by a stranger", crown="ato",
                           assumption="the handler resolves the owner from the session",
                           violation="GET /api/v1/orders/<B's id> as A",
                           prediction="200 carrying B's address", kill_byte="403 naming both subjects")
        self.assertNotIn("refused", str(out), out)
        return H.load("alpha")["hypotheses"][0]["id"]

    def test_an_untagged_probe_increments_the_program_counter(self):
        self.assertEqual(H.untagged_probes("alpha"), 0)
        H.log_probe("alpha", None, "raw/one.json")
        H.log_probe("alpha", "", "raw/two.json")
        self.assertEqual(H.untagged_probes("alpha"), 2,
                         "an untagged probe used to vanish from every budget and the floor")

    def test_the_untagged_artifacts_are_kept_so_the_probe_is_findable(self):
        H.log_probe("alpha", None, "raw/one.json")
        self.assertIn("raw/one.json", H.load("alpha").get("untagged_artifacts") or [])

    def test_an_untagged_probe_does_not_touch_any_hypothesis(self):
        hid = self._hyp()
        H.log_probe("alpha", None, "raw/one.json")
        h = H._find_hyp(H.load("alpha")["hypotheses"], hid)
        self.assertEqual(h["probes"], 0, "it must not be guessed onto a hypothesis either")
        self.assertEqual(h["evidence"], [])

    def test_a_tagged_probe_still_counts_against_its_hypothesis(self):
        hid = self._hyp()
        H.log_probe("alpha", hid, "raw/tagged.json")
        h = H._find_hyp(H.load("alpha")["hypotheses"], hid)
        self.assertEqual(h["probes"], 1)
        self.assertIn("raw/tagged.json", h["evidence"])
        self.assertEqual(H.untagged_probes("alpha"), 0, "a tagged probe is not also counted as untagged")

    def test_an_empty_program_is_still_a_no_op(self):
        """program=None raises inside the @_serialized decorator, which locks on path(program) before
        the body runs. That is pre-existing and unrelated to this fix, so it is not asserted here."""
        H.log_probe("", None, "raw/x.json")
        self.assertEqual(H.untagged_probes("alpha"), 0)

    def test_the_counter_survives_a_reload_and_does_not_disturb_hypotheses(self):
        hid = self._hyp()
        H.log_probe("alpha", None, "raw/one.json")
        H.log_probe("alpha", hid, "raw/tagged.json")
        H.log_probe("alpha", None, "raw/three.json")
        d = H.load("alpha")
        self.assertEqual(d.get("untagged_probes"), 2)
        self.assertEqual(H._find_hyp(d["hypotheses"], hid)["probes"], 1)


if __name__ == "__main__":
    unittest.main()
