"""The catastrophe-provenance note on hunt_model show (stdlib unittest, no network, no writes)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_hunt as H  # noqa: E402

FILED = ["Remote impersonation using another holder's PID without their device",
         "Forgery of arbitrary identities, a PID accepted for a fabricated identity",
         "Mass leakage of identity data",
         "Systemic compromise of signing authority at scale"]
DRIFTED = ["ATO (account takeover via PID forgery - reachable unauth)",
           "cross-tenant access via EAA replay",
           "mass-PII leakage via unauthenticated access",
           "admin twin impersonation"]


class CatastropheProvenance(unittest.TestCase):
    """hunt_model's store is free text an agent TYPED with action=add; it is not derived from
    TARGET-MODEL.md. On 2026-10-25 program-32' stored list carried program-101 vocabulary ("admin twin")
    that leaked in from a hunt running at the time, and asked for the catastrophes "in the program's
    own words" the agent quoted the store and called it the program's words. SPINE 2 wants the
    vendor's own words."""

    def setUp(self):
        # targets/ never ships: a fresh install gets a program-32 TARGET-MODEL.md whose catastrophe section has
        # the same shape as the real one (numbered items, a wrapped continuation, a trailing prose paragraph)
        if os.path.isfile(os.path.join(H.WS, "targets", "program-32", "TARGET-MODEL.md")):
            return
        import shutil
        import tempfile
        from unittest import mock
        ws = tempfile.mkdtemp(prefix="gnoc-provenance-")
        self.addCleanup(shutil.rmtree, ws, True)
        os.makedirs(os.path.join(ws, "targets", "program-32"))
        with open(os.path.join(ws, "targets", "program-32", "TARGET-MODEL.md"), "w") as fh:
            fh.write("# TARGET-MODEL\n\n## CATASTROPHE LIST (the program defines the top tier; use their words)\n"
                     "1. Remote impersonation - using another holder's PID without their device or participation.\n"
                     "2. Forgery of arbitrary identities - a PID accepted for a fabricated identity.\n"
                     "3. Mass leakage of identity data.\n"
                     "4. Systemic compromise of signing authority - arbitrary valid PIDs, attestations,\n"
                     "   certificates or status information at scale.\n"
                     "Plus the explicitly solicited: replay and binding failures in proof-of-possession artifacts.\n"
                     "\n## Next section\n")
        p = mock.patch.object(H, "WS", ws)
        p.start()
        self.addCleanup(p.stop)

    def test_a_drifted_store_is_called_out(self):
        note = H._catastrophe_provenance("program-32", DRIFTED)
        self.assertIn("TYPED into this store", note)
        self.assertIn("TARGET-MODEL.md", note)

    def test_a_store_that_tracks_the_file_is_left_alone(self):
        """A note that cries wolf on a correct model teaches agents to skip it. The first version of
        this check swept up wrapped continuation lines and a trailing "Plus the explicitly solicited"
        sentence, inflating the denominator so even a faithful list was flagged."""
        self.assertEqual(H._catastrophe_provenance("program-32", FILED), "")

    def test_it_is_silent_without_a_file_or_a_list(self):
        self.assertEqual(H._catastrophe_provenance("gatewayco", DRIFTED), "")          # no catastrophe section
        self.assertEqual(H._catastrophe_provenance("no-such-program", DRIFTED), "")
        self.assertEqual(H._catastrophe_provenance("program-32", []), "")

    def test_it_finds_the_section_under_either_heading_spelling(self):
        """program-32 writes "CATASTROPHE LIST"; program-64 writes "## 7. What would be catastrophic
        here" and wraps its items in bold ("**1. Memory corruption ..."). Matching only the first
        spelling skipped program-64 in silence - the crying-wolf failure in reverse, and it hid a
        contaminated store on a program with $300k ceilings."""
        stored = (H.load("program-64")["model"] or {}).get("catastrophes") or []
        if stored:            # the live store; skip rather than fail if it is ever cleaned up
            self.assertIn("TYPED into this store", H._catastrophe_provenance("program-64", stored))

    def test_the_note_never_overwrites_the_stored_model(self):
        before = H.load("program-32")["model"].get("catastrophes")
        H._catastrophe_provenance("program-32", DRIFTED)
        self.assertEqual(H.load("program-32")["model"].get("catastrophes"), before)


if __name__ == "__main__":
    unittest.main()
