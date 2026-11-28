"""The catastrophe store is a GATE, not a note (2026-10-25).

`hunt_model` is free text an agent types with action=add. Nothing checked it against
targets/<program>/TARGET-MODEL.md, and SPINE 2 tells every hunt to reason FROM it. Both programs
with a comparable section on disk were contaminated: program-64's slot held GATEWAYCO's model (0-click ATO
via bearer revocation, unauth dispatcher past the IdP gate, client-side PKCE injection) while its own
file lists OSS parser memory corruption to RCE at $300k and cross-user Meta AI session access at
$130k; program-32' held program-101's "admin twin" vocabulary.

A NOTE was tried first and measurably failed: handed the drifted list with the note attached, the
lead reasoned from it anyway, never opened the file, and fired real requests at facebook.com chasing
Gatewayco's attack surface on Meta's estate. So the drifted store is now WITHHELD and the file's list is
shown in its place, and a drifted write is refused.
"""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_hunt as H  # noqa: E402

FILED = """# Target model

## 7. What would be catastrophic here

**1. Memory corruption to code execution in an OSS parser on a victim device. $300k.
**2. Cross-user read or modification of another principal's agentic session. $130k.
**3. Cross-tenant read and write of a Mapillary organization.
"""


class Gate(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="gnoc-hm-")
        self.addCleanup(shutil.rmtree, self.ws, True)
        self.saved = H.WS
        H.WS = self.ws
        self.addCleanup(setattr, H, "WS", self.saved)
        os.makedirs(os.path.join(self.ws, "targets", "p"), exist_ok=True)
        with open(os.path.join(self.ws, "targets", "p", "TARGET-MODEL.md"), "w") as fh:
            fh.write(FILED)

    def _store(self, items):
        d = H.load("p")
        d["model"]["catastrophes"] = list(items)
        d["model"]["actors"] = ["A1: anonymous"]
        H.save("p", d)

    # ---- detection -------------------------------------------------------
    def test_the_file_is_parsed(self):
        filed = H.filed_catastrophes("p")
        self.assertEqual(len(filed), 3)
        self.assertIn("Memory corruption", filed[0])

    def test_another_programs_model_is_drift(self):
        self._store(["C1: 0-click ATO via a bearer that outlives its revocation",
                     "C2: unauth dispatcher reach that bypasses the IdP gate"])
        self.assertTrue(H.catastrophes_drifted("p", H.load("p")["model"]["catastrophes"]))

    def test_a_store_that_tracks_the_file_is_not_drift(self):
        self._store(H.filed_catastrophes("p"))
        self.assertFalse(H.catastrophes_drifted("p", H.load("p")["model"]["catastrophes"]))

    def test_no_file_means_no_gate(self):
        os.remove(os.path.join(self.ws, "targets", "p", "TARGET-MODEL.md"))
        self._store(["C1: anything at all"])
        self.assertFalse(H.catastrophes_drifted("p", ["C1: anything at all"]),
                         "nothing to compare against is not evidence of contamination")

    # ---- the READ gate ---------------------------------------------------
    def test_a_drifted_store_is_withheld_and_the_file_is_shown(self):
        self._store(["C1: 0-click ATO via a bearer that outlives its revocation"])
        out = H.model("p", "show")
        self.assertIn("Memory corruption", out, "the file's list is what a hunt reasons from")
        self.assertNotIn("outlives its revocation", out, "the drifted store must not be handed over")
        self.assertIn("WITHHELD", out)
        self.assertIn("TARGET-MODEL.md", out)
        self.assertIn("hunt_model(action=stored)", out)

    def test_the_store_is_not_destroyed_by_the_gate(self):
        self._store(["C1: 0-click ATO via a bearer that outlives its revocation"])
        H.model("p", "show")
        self.assertEqual(H.load("p")["model"]["catastrophes"],
                         ["C1: 0-click ATO via a bearer that outlives its revocation"])

    def test_action_stored_is_the_escape_hatch_and_labels_what_it_prints(self):
        self._store(["C1: 0-click ATO via a bearer that outlives its revocation"])
        out = H.model("p", "stored")
        self.assertIn("outlives its revocation", out)
        self.assertIn("NOT the program's wording", out)

    def test_a_clean_model_is_shown_unchanged_with_no_gate_text(self):
        self._store(H.filed_catastrophes("p"))
        out = H.model("p", "show")
        self.assertIn("Memory corruption", out)
        self.assertNotIn("WITHHELD", out)
        self.assertNotIn("NOTE on CATASTROPHES", out)

    # ---- the WRITE gate --------------------------------------------------
    def test_contamination_is_caught_ONE_ITEM_AT_A_TIME(self):
        """A two-thirds test on the merged store lets junk in one item at a time, which is exactly
        how a store drifts. Each item is checked against the file on its own."""
        self._store(H.filed_catastrophes("p"))
        out = H.model("p", "add", catastrophes="C9: 0-click ATO via a bearer that outlives revocation")
        self.assertIn("DROPPED 1 catastrophe(s)", out)
        self.assertIn("appear nowhere in", out)
        self.assertIn("Memory corruption", out, "the file's items are offered to copy")
        self.assertNotIn("outlives revocation", H.load("p")["model"]["catastrophes"])

    def test_the_rest_of_the_call_still_saves(self):
        # partial accept: a bad catastrophe must not throw away the actors typed beside it
        self._store(H.filed_catastrophes("p"))
        H.model("p", "add", actors="A7: a partner integrator",
                catastrophes="C9: 0-click ATO via a bearer that outlives revocation")
        self.assertIn("A7: a partner integrator", H.load("p")["model"]["actors"])

    def test_set_with_the_files_items_is_how_a_bad_store_is_corrected(self):
        self._store(["C1: 0-click ATO via a bearer that outlives its revocation"])
        H.model("p", "set", catastrophes=H.filed_catastrophes("p"))
        stored = H.load("p")["model"]["catastrophes"]
        self.assertFalse(H.catastrophes_drifted("p", stored))
        self.assertNotIn("C1: 0-click ATO via a bearer that outlives its revocation", stored)
        self.assertNotIn("WITHHELD", H.model("p", "show"))

    def test_a_program_with_no_file_can_still_record_catastrophes(self):
        os.remove(os.path.join(self.ws, "targets", "p", "TARGET-MODEL.md"))
        H.model("p", "add", catastrophes="C1: whatever this program's crown is")
        self.assertIn("C1: whatever this program's crown is", H.load("p")["model"]["catastrophes"])


if __name__ == "__main__":
    unittest.main()
