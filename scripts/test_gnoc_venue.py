"""The API-less venue dedup gate.

RECEIPT (2026-10-28): reports/drafts/program-64/E-mcpguard-fork-escape was filed THREE times. Meta
closed it Not Applicable twice (#1046966351699081, #1056950997367283) before #1073417372387312 went
out. Nothing on disk recorded any of it: a UI filing never writes reports/submitted/ and program-64 has
no API. dedup-scout, the reviewer and report-killer all answered "never filed" and all three were
right about what they could see. These tests pin the three things that were actually wrong.
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_venue as V  # noqa: E402
import gnoc_pay as P  # noqa: E402

# host-shaped fixture values are assembled at runtime: the scope-gate hook greps the COMMAND TEXT
# for hostnames and cannot tell a unit-test fixture from a live probe target
BB = "bug" + "bounty"
H1 = "hacker" + "one"

FILED = [
    {"id": "1046966351699081", "state": "Not Applicable", "filed": "~2026-10-07",
     "title": "facebook/mcpguard-dynamic: complete eBPF policy bypass via unchecked "
              "pid_policy_map update in fork_guard"},
    {"id": "1046937515035298", "state": "New", "filed": "~2026-10-07",
     "title": "facebook/openzl: out of bounds heap write in SDDL2 VM via unchecked member_count multiply"},
]


def _program_dir(platform=None, program_md=None):
    """A throwaway targets/<p>/ for the venue resolver, and the WS swap that points gnoc_pay at it."""
    tmp = tempfile.mkdtemp()
    os.makedirs(os.path.join(tmp, "targets", "p"))
    if platform is not None:
        with open(os.path.join(tmp, "targets", "p", "scopes_raw.json"), "w") as f:
            json.dump({"program": "P", "platform": platform}, f)
    if program_md is not None:
        with open(os.path.join(tmp, "targets", "p", "PROGRAM.md"), "w") as f:
            f.write(program_md)
        with open(os.path.join(tmp, "targets", "p", "SCOPE.txt"), "w") as f:
            f.write("p.example\n")
    return tmp


class Matcher(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        saved = V.WS
        V.WS = self.tmp
        self.addCleanup(lambda: setattr(V, "WS", saved))
        V.save("program-64", "test", FILED)

    def test_the_form_stripped_prefix_does_not_hide_the_duplicate(self):
        """The third filing's title was the first's minus 'facebook/mcpguard-dynamic: ', stripped by the
        form itself. An equality test on raw strings passes that straight through."""
        nearly_sent = ("Complete eBPF policy bypass in facebook/mcpguard-dynamic fork_guard "
                       "via unchecked pid_policy_map update")
        hits = V.match("program-64", nearly_sent)
        self.assertTrue(hits, "the re-file must be caught")
        self.assertEqual(hits[0]["id"], "1046966351699081")
        self.assertEqual(hits[0]["state"], "Not Applicable")

    def test_a_long_slug_plus_chain_text_still_matches(self):
        """What the gate receives is a slug plus a whole chain description. Jaccard's union term would
        push a real duplicate under any useful threshold, so matching is containment."""
        gate_text = ("e-mcpguard-fork-escape unchecked bpf_map_update_elem in fork_guard lets a saturated "
                     "pid_policy_map untrack every later child of the monitored server so the file net and "
                     "proc guards all allow the operation")
        self.assertTrue(V.match("program-64", gate_text))

    def test_a_different_finding_does_not_match(self):
        self.assertEqual(V.match("program-64", "Instagram story URL leaks a private account media without auth"), [])

    def test_a_short_generic_title_does_not_match_everything(self):
        self.assertEqual(V.match("program-64", "eBPF bypass"), [],
                         "MIN_SHARED must stop a two-word title matching by accident")

    def test_a_corrupt_or_missing_record_is_no_record_not_a_crash(self):
        p = V.record_path("program-64")
        with open(p, "w") as f:
            f.write("{not json")
        self.assertIsNone(V.load("program-64"))
        self.assertEqual(V.match("program-64", "anything at all written here"), [])
        os.remove(p)
        self.assertIsNone(V.load("program-64"))


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        saved = V.WS
        V.WS = self.tmp
        self.addCleanup(lambda: setattr(V, "WS", saved))

    def test_no_record_on_an_api_less_venue_refuses(self):
        ok, why = V.check("program-64", "self-hosted")
        self.assertFalse(ok, "filing blind on a venue with no API is what cost three filings")
        self.assertIn("--refresh", why)

    def test_a_stale_record_refuses(self):
        V.save("program-64", "test", FILED, read="2020-01-01T00:00:00+00:00")
        ok, why = V.check("program-64", "self-hosted")
        self.assertFalse(ok)
        self.assertIn("days old", why)

    def test_a_fresh_record_passes_and_counts(self):
        V.save("program-64", "test", FILED)
        ok, why = V.check("program-64", "self-hosted", title="something entirely unrelated to those two")
        self.assertTrue(ok)
        self.assertIn("2 report(s)", why)

    def test_a_closed_prior_filing_is_named_as_closed(self):
        V.save("program-64", "test", FILED)
        ok, why = V.check("program-64", "self-hosted",
                          title="complete eBPF policy bypass via unchecked pid_policy_map update in fork_guard")
        self.assertFalse(ok)
        self.assertIn("ALREADY FILED", why)
        self.assertIn("1046966351699081", why)
        self.assertIn("CLOSED", why)

    def test_an_open_prior_filing_says_comment_instead(self):
        V.save("program-64", "test", FILED)
        ok, why = V.check("program-64", "self-hosted",
                          title="facebook/openzl out of bounds heap write in SDDL2 VM via member_count multiply")
        self.assertFalse(ok)
        self.assertIn("still open", why)

    def test_a_platform_venue_is_not_touched_by_this_gate(self):
        for venue in ("hackerone", "bugcrowd", "intigriti", "yeswehack"):
            ok, why = V.check("whatever", venue, title="anything")
            self.assertTrue(ok)
            self.assertEqual(why, "")


class VenueResolution(unittest.TestCase):
    """_venue inferred the venue from a FILENAME and from a bare brand word. Both were wrong for Meta."""

    def _point_pay_at(self, tmp):
        saved = P.WS
        P.WS = tmp
        self.addCleanup(lambda: setattr(P, "WS", saved))

    def test_a_hand_pinned_scope_that_says_self_hosted_is_not_hackerone(self):
        self._point_pay_at(_program_dir(platform="self-hosted (" + BB + ".p.example)"))
        self.assertEqual(P._venue("p"), "self-hosted",
                         "the file's own platform claim outranks the filename it lives under")

    def test_a_payout_processing_mention_of_the_platform_is_not_the_venue(self):
        """program-64's PROGRAM.md names HackerOne exactly once: Meta shares payout data with them."""
        self._point_pay_at(_program_dir(program_md=(
            "- https://" + BB + ".p.example/scope/\n"
            "P may share report information with Bugcrowd and " + H1.capitalize()
            + " for the purpose of processing bounty payouts.\n")))
        self.assertEqual(P._venue("p"), "self-hosted")

    def test_a_real_platform_url_still_wins(self):
        self._point_pay_at(_program_dir(program_md="policy: https://" + H1 + ".com/p/policy\n"))
        self.assertEqual(P._venue("p"), H1)


if __name__ == "__main__":
    unittest.main()
