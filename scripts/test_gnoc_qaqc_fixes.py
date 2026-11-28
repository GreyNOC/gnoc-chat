#!/usr/bin/env python3
"""Regression pins for the three defects the 2026-10-31 QAQC pass found in gnoc chat.

All three are the SAME failure mode - a refusal that reads like a result - which every other QAQC stage is
blind to because parse / lint / import / registry never call a tool. They were found only once the functional
battery covered the tools that had no case, so the last test here pins that coverage itself.

    python3 scripts/test_gnoc_qaqc_fixes.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
WS = os.path.dirname(HERE)

import gnoc_probe as P          # noqa: E402
import gnoc_oracle as O         # noqa: E402
import gnoc_agent as G          # noqa: E402

PROG = "qaqc-test-program"
OOS = "qaqc-out-of-scope.invalid"


def _fp(status=200, ln=10):
    return {"status": status, "len": ln, "ctype": "text/html", "hash": "aa", "keys": [], "location": ""}


class UnfiredIsNotANegative(unittest.TestCase):
    """gnoc_probe.summarize counted a variant that never reached the wire as a sent variant, so a wholly
    blocked sweep (scope gate, rate limit, DNS failure) was headed 'N variants, 0 anomalies'."""

    def test_all_variants_blocked_says_nothing_was_sent(self):
        def boom(label, m, u, h, b):
            raise PermissionError("OUT_OF_SCOPE " + u)
        table, n, rows = P.sweep("https://example.test/?q={{X}}", cap=2, send=boom)
        head = table.splitlines()[0]
        self.assertIn("NOTHING WAS SENT", head)
        self.assertIn("UNFIRED", head)
        self.assertNotIn("0 anomalies", head)
        self.assertEqual(n, 0)

    def test_partial_block_reports_the_unfired_count(self):
        seen = {"n": 0}

        def half(label, m, u, h, b):
            seen["n"] += 1
            if seen["n"] > 1:
                raise RuntimeError("429 rate limited")
            return _fp(), "raw/1"
        table, _n, _rows = P.sweep("https://example.test/?q={{X}}", cap=2, send=half)
        head = table.splitlines()[0]
        self.assertIn("1 variants sent", head)
        self.assertIn("UNFIRED", head)
        self.assertIn("not negatives", head)

    def test_a_fully_sent_sweep_keeps_the_shape_the_oracle_greps(self):
        def good(label, m, u, h, b):
            return _fp(), "raw/1"
        table, _n, _rows = P.sweep("https://example.test/?q={{X}}", cap=2, send=good)
        head = table.splitlines()[0]
        self.assertIn("variants sent", head)
        self.assertNotIn("UNFIRED", head)
        # gnoc_oracle.lane_anomalous() greps '<n> anomalies' out of tool text: that wording must survive
        self.assertFalse(O._ANOM.search(head), "a clean sweep must not read as an anomaly")
        self.assertTrue(O._ANOM.search(head.replace("0 anomalies", "2 anomalies")),
                        "the anomaly wording the oracle greps was changed")


class SweepGatesTheSeamUpFront(unittest.TestCase):
    """t_sweep had no up-front scope gate: an out-of-scope seam produced a full table of per-row
    PermissionErrors instead of one refusal, and only the per-variant sender stopped the traffic."""

    def test_out_of_scope_sweep_is_one_refusal(self):
        prog = next((p for p in sorted(os.listdir(os.path.join(WS, "targets")))
                     if os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt"))), None)
        if not prog:
            self.skipTest("no program with a SCOPE.txt on disk")
        out = str(G.t_sweep(G.Ctx({"program": prog}), f"https://{OOS}/?q={{{{X}}}}", cap=3))
        self.assertIn("OUT_OF_SCOPE", out)
        self.assertNotIn("anomal", out, "the sweep built a variant table for an out-of-scope host")
        self.assertEqual(len(out.splitlines()), 1, "an out-of-scope sweep must answer in one line")


class UnknownOracleIsARefusal(unittest.TestCase):
    """t_oracle_verify reported an unknown or already-adjudicated oracle_id as 'verdict failed', which reads
    as 'the terminal was adjudicated and did not hold'. A typo or a stale id silently killed the lane."""

    def setUp(self):
        self.ctx = G.Ctx({"program": PROG})

    def test_unknown_id_refuses_and_denies_a_verdict(self):
        out = str(O.t_oracle_verify(self.ctx, "no-such-oracle-qaqc", "{}"))
        self.assertTrue(out.startswith("refused:"), out[:120])
        self.assertIn("nothing was adjudicated", out)
        self.assertNotIn("verdict failed", out)

    def test_verify_itself_still_returns_failed_for_an_unknown_id(self):
        # the pure-code contract is unchanged on purpose; only the TOOL's wording moved
        v, why = O.verify(PROG, "no-such-oracle-qaqc", [])
        self.assertEqual(v, "failed")
        self.assertIn("no oracle", why)


class TheBatteryLeavesNoOutgoingDraft(unittest.TestCase):
    """Every functional run queued a real outgoing email draft. By 2026-10-31 all 38 drafts in the user's
    approval outbox were battery litter, so a real draft awaiting /send was lost among test rows."""

    def test_comms_isolated_keeps_the_real_outbox_untouched(self):
        import gnoc_comms as C
        real = C.OUTBOX
        with C.isolated() as tmp:
            self.assertNotEqual(C.OUTBOX, real)
            C.draft("email", "body", "x@example.com", "subj")
            self.assertTrue(os.listdir(tmp), "the draft did not land in the throwaway outbox")
        self.assertEqual(C.OUTBOX, real, "isolated() did not restore the real outbox")

    def test_the_draft_case_runs_isolated(self):
        import gnoc_comms as C
        before = set(os.listdir(C.OUTBOX)) if os.path.isdir(C.OUTBOX) else set()
        import gnoc_qaqc_func as F
        rows, _missing = F.run(only="draft_outgoing", with_models=False, verbose=False)
        self.assertTrue(rows)
        after = set(os.listdir(C.OUTBOX)) if os.path.isdir(C.OUTBOX) else set()
        self.assertEqual(before, after, "the battery wrote into the real approval outbox")


class EveryToolHasAFunctionalCase(unittest.TestCase):
    """The three defects above all sat in tools with no functional case. An uncovered tool is an untested
    tool, so the coverage itself is pinned: a new tool must arrive with a case or this fails."""

    def test_no_tool_is_left_without_a_case(self):
        import gnoc_qaqc_func as F
        self.assertEqual(F.run.__module__, "gnoc_qaqc_func")
        cases = F._cases(G, "/tmp", "qaqc")
        covered = {c[0] for c in cases}
        model_backed = {"delegate", "fan_out", "second_opinion", "claude_worker", "hypothesize", "browser",
                        "generate_image", "burp_panels"}
        # mcp__<server>__<tool> are the OPERATOR's configured MCP servers, registered at runtime (an earlier test
        # file's fake server lands here too): no fixed case can exist for them, and gnoc_qaqc_func.run skips them
        missing = sorted({n for n in G.TOOLS if not n.startswith("mcp__")} - covered - model_backed)
        self.assertEqual(missing, [], f"tools with no functional case: {missing}")

    def test_with_models_does_not_crash_the_battery(self):
        # `set(...) - covered - ({} if with_models else {...})` subtracted a DICT: --with-models raised
        # TypeError before a single tool ran
        import gnoc_qaqc_func as F
        rows, missing = F.run(only="decode", with_models=True, verbose=False)
        self.assertTrue(rows)
        self.assertNotIn("decode", missing)


class ProgramEgressIsPerProgram(unittest.TestCase):
    """A program whose host the default route cannot reach (SNI hijack / geo wall) declares its own route in
    .egress beside SCOPE.txt. 2026-11-03: app.example.com was unreachable from http_request entirely, so every probe
    had to bypass the ledger tool; the route now lives with the program and only that program gets it."""

    def _prog(self, td, name, egress=None):
        d = os.path.join(td, name)
        os.makedirs(d, exist_ok=True)
        sf = os.path.join(d, "SCOPE.txt")
        with open(sf, "w") as f:
            f.write("target.example\n")
        if egress is not None:
            with open(os.path.join(d, ".egress"), "w") as f:
                f.write(egress + "\n")
        return sf

    def test_a_program_route_is_resolved_and_others_stay_direct(self):
        import tempfile
        sys.path.insert(0, os.path.join(HERE, "bbtools"))
        from lib_egress import egress_for_scope
        with tempfile.TemporaryDirectory() as td:
            mine = self._prog(td, "mine", "socks5h://127.0.0.1:9050")
            other = self._prog(td, "other")
            self.assertEqual(egress_for_scope(mine), "socks5h://127.0.0.1:9050")
            self.assertIsNone(egress_for_scope(other), "a program without .egress must not be proxied")
            self.assertIsNone(egress_for_scope(None), "no scope file must never raise")

    def test_a_junk_or_absent_route_changes_nothing(self):
        import tempfile
        sys.path.insert(0, os.path.join(HERE, "bbtools"))
        from lib_egress import egress_for_scope
        with tempfile.TemporaryDirectory() as td:
            comments = self._prog(td, "comments", "# a note only")
            self.assertIsNone(egress_for_scope(comments))
            notaurl = self._prog(td, "notaurl", "127.0.0.1:9050")
            self.assertIsNone(egress_for_scope(notaurl), "a non-URL line is ignored, not used as a proxy")


if __name__ == "__main__":
    unittest.main(verbosity=1)
