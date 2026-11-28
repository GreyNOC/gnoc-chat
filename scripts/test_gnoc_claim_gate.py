"""The claim gate (gnoc_gates.claim_checks), 2026-10-26.

Receipt: the user was handed `program-0/gnoc-agent-20261025-h2-seam-race-5-2-2` as a "Critical ATO 9.1,
capability gate satisfied, dedup stamp present" and asked for it to be readied for submission. Its whole
PoC was GET -> 405 / POST -> 200 {"accepted_count":0,"rejected_count":0} on a public telemetry route, one
of seven copies of one generator artifact, five of which claimed cross-user-read off the same Next.js SPA
shell served as BOTH the control and the evidence. Every row of GATE-local-format.md was ticked, because
each row asks "is there a value here" and none asked "does this value name a byte the control lacks".

These tests pin the four checks that cannot be ticked by a hollow draft. Each fixture is the real shape,
trimmed. No network, temp dirs only.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_gates  # noqa: E402

CLEAN_STAMPS = ("Gate: report-killer PASS 2026-10-26\n"
                "Dedup: public-checked 2026-10-26 none\n")

GOOD_POC = """## PoC
**Step 1: negative control, the same request with no session cookie**

```bash
curl -sS -i https://api.example.com/v1/orders/9931 -H 'X-HackerOne-Researcher: greynoc'
```

```http
HTTP 403

{"error":"forbidden"}
```

**Step 2: the same request carrying account A's session reads account B's order**

```bash
curl -sS -i https://api.example.com/v1/orders/9931 -H 'Cookie: sid=A-SESSION'
```

```http
HTTP 200

{"order_id":9931,"owner":"victim@example.com","card_last4":"4242"}
```

## Impact
Account A reads account B's order, including the owner email, as the captured response shows.
"""


def draft(tmp, body, name="a-finding", program="prog"):
    d = os.path.join(tmp, program, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "report.md"), "w") as f:
        f.write(body)
    return d


def failures(d):
    return {name for ok, name, _ in gnoc_gates.claim_checks(d) if not ok}


class ClaimGate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_a_real_looking_draft_passes_all_four(self):
        d = draft(self.tmp, CLEAN_STAMPS + "\n# Cross-user order read\n\n" + GOOD_POC)
        self.assertEqual(failures(d), set())

    def test_a_stamp_that_says_it_never_ran_blocks(self):
        body = ("Gate: report-killer NOT-YET-RUN 2026-10-26\n"
                "Dedup: NOT-YET-RUN 2026-10-26 (scripts/learn/public-dedup.sh prog host <class> --result none)\n"
                "\n# Cross-user order read\n\n" + GOOD_POC)
        d = draft(self.tmp, body)
        self.assertIn("report-killer and public dedup have actually run", failures(d))

    def test_an_unrun_channel_with_a_stated_reason_is_excused(self):
        """The house writes the reason in brackets right after the marker. A usage hint after a DATE is not a
        reason - that is how the program-0 draft's 'NOT-YET-RUN 2026-10-26 (scripts/...)' read."""
        body = ("Gate: report-killer PASS 2026-10-26\n"
                "Dedup: public-checked 2026-10-26 | hacktivity:none | GHSA/CVE:NOT-YET-RUN (hosted service, no "
                "packaged component, no advisory sweep applies)\n"
                "\n# Cross-user order read\n\n" + GOOD_POC)
        d = draft(self.tmp, body)
        self.assertNotIn("report-killer and public dedup have actually run", failures(d))

    def test_a_405_control_on_the_edges_own_url_blocks(self):
        """The program-0 draft, verbatim in shape: the control varies the HTTP METHOD, so what it measured is
        the route's method table, not an authentication boundary (T-31)."""
        body = CLEAN_STAMPS + """
# ATO via event-logging-seam

## PoC
**Step 1: negative control for unauth -> ato**

```bash
curl -sS -i --path-as-is -X GET https://api.example.com/api/event_logging/v2/batch
```

```http
HTTP 405

{"type":"error","error":{"message":"Method Not Allowed"}}
```

**Step 2: event-logging-seam  (unauth -> ato)**

```bash
curl -sS -i --path-as-is -X POST https://api.example.com/api/event_logging/v2/batch
```

```http
HTTP 200

{"accepted_count":0,"rejected_count":0}
```
"""
        d = draft(self.tmp, body)
        f = failures(d)
        self.assertIn("the negative control is not a method-table answer", f)
        self.assertNotIn("control and terminal are not the same response body", f)

    def test_the_same_spa_shell_as_both_arms_blocks(self):
        """Five of the seven copies: the control and the edge differ only by a "concurrent":true field the
        prober invented, and both return the identical Next.js shell (T-60)."""
        shell = "<!DOCTYPE html><html data-build-id=\"0a82b0f\"><head>" + "<link rel=stylesheet href=/a.css>" * 40
        body = CLEAN_STAMPS + f"""
# Cross-user read via concurrent flag

## PoC
**Step 1: negative control**

```bash
curl -sS -i -X POST https://console.example.com/oauth/vault/callback --data-raw '{{"concurrent":false}}'
```

```http
HTTP 200
content-type: text/html

{shell}
```

**Step 2: concurrent read-write**

```bash
curl -sS -i -X POST https://console.example.com/oauth/vault/callback --data-raw '{{"concurrent":true}}'
```

```http
HTTP 200
content-type: text/html

{shell}x
```
"""
        d = draft(self.tmp, body)
        self.assertIn("control and terminal are not the same response body", failures(d))

    def test_a_sibling_copy_already_killed_blocks_the_whole_family(self):
        base = draft(self.tmp, CLEAN_STAMPS + "\n# A finding\n\n" + GOOD_POC, name="seam-race")
        with open(os.path.join(base, "GATE-harness.md"), "w") as f:
            f.write("KILL - the control measured the method table\n")
        copy = draft(self.tmp, CLEAN_STAMPS + "\n# A finding\n\n" + GOOD_POC, name="seam-race-5-2-2")
        self.assertIn("no sibling copy of this slug was already killed", failures(copy))
        # and the killed one does not report ITSELF as the killed sibling
        self.assertNotIn("no sibling copy of this slug was already killed", failures(base))

    def test_an_unrelated_sibling_does_not_block(self):
        other = draft(self.tmp, CLEAN_STAMPS + "\n# Another\n\n" + GOOD_POC, name="oauth-state-reuse")
        with open(os.path.join(other, "GATE-harness.md"), "w") as f:
            f.write("KILL - by design\n")
        mine = draft(self.tmp, CLEAN_STAMPS + "\n# A finding\n\n" + GOOD_POC, name="seam-race-2")
        self.assertEqual(failures(mine), set())

    def test_a_single_step_poc_is_not_judged_on_its_control(self):
        """A one-step PoC has no control pair to compare; those two checks must not fire on it (the stamp and
        sibling checks still do)."""
        body = CLEAN_STAMPS + """
# One step

## PoC
```bash
curl -sS -i https://api.example.com/v1/x
```

```http
HTTP 200

{"ok":true}
```
"""
        d = draft(self.tmp, body)
        f = failures(d)
        self.assertNotIn("the negative control is not a method-table answer", f)
        self.assertNotIn("control and terminal are not the same response body", f)


if __name__ == "__main__":
    unittest.main()


class DraftState(unittest.TestCase):
    """A listing must carry the verdict next to the name.

    Receipt (2026-10-26): asked which program was being hunted and what the newest draft was, the agent
    answered with `gnoc-agent-20261025-h2-seam-race-5-2-2` - a draft carrying GATE-harness-20261026.md
    KILL - and described it as live work, because the only tool it had was a plain directory listing and
    a plain listing sorts by mtime and says nothing else.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-draftstate-")

    def _draft(self, name, files):
        d = os.path.join(self.tmp, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "report.md"), "w") as f:
            f.write("# t")
        for fn, body in files.items():
            with open(os.path.join(d, fn), "w") as f:
                f.write(body)
        return d

    def test_a_killed_draft_reads_as_killed(self):
        d = self._draft("killed", {"GATE-harness-20261026.md": "KILL: control and terminal are one body"})
        self.assertEqual(gnoc_gates.draft_state(d), "KILL")

    def test_a_kill_wins_over_a_sibling_pass(self):
        d = self._draft("mixed", {"GATE-local-format.md": "PASS: fine",
                                  "GATE-harness.md": "KILL: the dedup stamp never ran"})
        self.assertEqual(gnoc_gates.draft_state(d), "KILL")

    def test_held_and_gated_and_fresh(self):
        self.assertEqual(gnoc_gates.draft_state(self._draft("held", {"HELD-REASON.md": "**Unlock: 2nd acct"})), "HELD")
        self.assertEqual(gnoc_gates.draft_state(self._draft("ok", {"GATE-local-format.md": "PASS: ok"})), "gated")
        self.assertEqual(gnoc_gates.draft_state(self._draft("fresh", {})), "")

    def test_a_missing_directory_is_not_an_error(self):
        self.assertEqual(gnoc_gates.draft_state(os.path.join(self.tmp, "nope")), "")

    def test_the_listing_tags_a_killed_draft_and_leaves_other_dirs_alone(self):
        import gnoc_agent
        base = os.path.join(self.tmp, "reports", "drafts", "demo")
        os.makedirs(base, exist_ok=True)
        with open(os.path.join(self._draft(os.path.join("reports", "drafts", "demo", "killed-slug"),
                                           {"GATE-h.md": "KILL: hollow"}), "report.md")) as f:
            f.read()
        saved = (gnoc_agent.WS, gnoc_agent._ACTIVE_ROOT[0])
        try:
            gnoc_agent.WS, gnoc_agent._ACTIVE_ROOT[0] = self.tmp, self.tmp
            out = gnoc_agent.t_list_dir(gnoc_agent.Ctx({"program": "demo"}), base)
        finally:
            gnoc_agent.WS, gnoc_agent._ACTIVE_ROOT[0] = saved
        self.assertIn("KILL - gate-killed", out)
        self.assertNotIn("KILL", gnoc_agent._draft_tag(os.path.join(self.tmp, "scripts"), "whatever"))
