"""Venue inference for the filing gate (offline, no network).

Regression for 2026-11-04: a scopes_raw.json with NO "platform" key was read as proof of HackerOne,
because h1-scope.sh writes that filename. bugcrowd-scope.sh writes the same filename and omits the key,
so program-97 and program-13 (both Bugcrowd engagements, both named in line 1 of their own SCOPE.txt)
were routed through the HackerOne signal gate. That gate: (a) asks hackerone.com/graphql about a team
that does not exist there, and (b) replaces gnoc_venue.check, which is the ONLY dedupe a venue with no
API has. The fixture here is the real program-97 header shape, including its later "HackerOne" contrast.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_pay as P  # noqa: E402


class Venue(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-venue-")
        self.saved = P.WS
        P.WS = self.tmp

    def tearDown(self):
        P.WS = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def prog(self, name, scope_head, program_head, raw=None):
        d = os.path.join(self.tmp, "targets", name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "SCOPE.txt"), "w") as f:
            f.write(scope_head + "\nWILDCARD *." + name + ".example\n")
        with open(os.path.join(d, "PROGRAM.md"), "w") as f:
            f.write(program_head + "\n")
        if raw is not None:
            with open(os.path.join(d, "scopes_raw.json"), "w") as f:
                json.dump(raw, f)
        return name

    # ---- the two live shapes that were wrong ------------------------------------------------
    def test_bugcrowd_dump_without_platform_is_not_hackerone(self):
        """program-97's real header: Bugcrowd first, HackerOne only in a contrast sentence later."""
        p = self.prog(
            "program-97",
            "# program-97 - auto-pulled from the Bugcrowd public engagement brief (zero auth)\n"
            "# Brief page:  https://bugcrowd.com/engagements/program-97",
            "# Bankco Managed Bug Bounty Engagement (Bugcrowd)\n"
            "Bugcrowd mandates no platform-wide identification header (unlike HackerOne's `X-HackerOne:`).",
            raw={"scopes": [{"asset_identifier": "app.example.com",
                             "eligible_for_bounty": True, "eligible_for_submission": True}]},
        )
        self.assertEqual(P._venue(p), "bugcrowd")

    def test_hackerone_dump_without_platform_still_hackerone(self):
        p = self.prog(
            "h1prog",
            "# h1prog - auto-pulled from HackerOne API (eligible_for_submission=true only)",
            "# h1prog - program rules (auto-pulled from H1 API)",
            raw={"scopes": [{"asset_identifier": "www.h1prog.example",
                             "eligible_for_bounty": True, "eligible_for_submission": True}]},
        )
        self.assertEqual(P._venue(p), "hackerone")

    # ---- the evidence that must keep working ------------------------------------------------
    def test_platform_key_still_wins(self):
        p = self.prog("bc", "# bc - pulled brief", "# bc engagement", raw={"platform": "bugcrowd", "scopes": []})
        self.assertEqual(P._venue(p), "bugcrowd")

    def test_self_hosted_platform_is_positive(self):
        p = self.prog("meta", "# meta", "# meta", raw={"platform": "self-hosted (bugbounty.meta.com)",
                                                       "scopes": []})
        self.assertEqual(P._venue(p), "self-hosted")

    def test_no_raw_text_evidence_is_read(self):
        p = self.prog("bc2", "# bc2 - https://bugcrowd.com/engagements/bc2", "# bc2 engagement")
        self.assertEqual(P._venue(p), "bugcrowd")

    def test_earliest_mention_wins_not_a_fixed_order(self):
        """A HackerOne-first header on a HackerOne program must not be flipped by a later Bugcrowd word."""
        p = self.prog("mix", "# mix - auto-pulled from HackerOne API", "# mix ... with Bugcrowd and HackerOne")
        self.assertEqual(P._venue(p), "hackerone")

    def test_no_evidence_and_no_raw_is_unknown(self):
        p = self.prog("mystery", "# mystery", "# mystery")
        self.assertEqual(P._venue(p), "unknown")

    def test_a_bugcrowd_program_never_enters_the_h1_team_gate(self):
        """h1_team() must refuse before any GraphQL call for a program that is not on HackerOne."""
        p = self.prog(
            "bc3",
            "# bc3 - auto-pulled from the Bugcrowd public engagement brief",
            "# bc3 Managed Bug Bounty Engagement (Bugcrowd)",
            raw={"scopes": []},
        )
        self.assertIsNone(P.h1_team(p))


if __name__ == "__main__":
    unittest.main(verbosity=2)
