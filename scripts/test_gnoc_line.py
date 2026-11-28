#!/usr/bin/env python3
"""Tests for gnoc_line (the nine-station production line). Stdlib unittest, temp dirs, no network, no model calls.

    python3 -W error::ResourceWarning scripts/test_gnoc_line.py [-v]
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_economy as E  # noqa: E402
import gnoc_hunt as H  # noqa: E402
import gnoc_line as L  # noqa: E402
import gnoc_oracle as O  # noqa: E402
import gnoc_pay as P  # noqa: E402

PROG = "zz-linetest"
L_ATTRS = ("WS", "TARGETS", "LINE_JSON", "LESSONS", "MANUAL_INDEX", "DNR_DIR", "DNR_GLOBAL", "OUTCOMES",
           "PUBLIC_DEDUP", "INBOX")
SEED = {"seeds": [{"id": "S1", "host": "api.example.test", "class": "business-logic", "endpoint": "/v1/redeem",
                   "kill_byte": '"credited":2'}],
        "dedup": {"stamp": "hq none; public-dedup none 2026-10-23"},
        "promises": [{"claim": "a code redeems once", "url": "https://docs.example.test/codes"}]}
MODEL = {"boundaries": [{"name": "redeem", "asset": "credit balance", "excludes": "a second redeem of one code"}],
         "catastrophic": ["money minted from one code"]}


def _slurp(p):
    with open(p) as f:
        return f.read()


def _hyp(wid="h1", **over):
    h = {"id": wid, "statement": "one code redeems twice under a burst", "class": "business-logic",
         "assumption": "the redeem handler checks then sets in two calls",
         "violation": "POST /redeem code=X, 20 concurrent", "prediction": "two 200s with credited:2",
         "killByte": '"credited":2', "boundary": "redeem"}
    h.update(over)
    return h


class Line(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-line-")
        self.saved_l = {k: getattr(L, k) for k in L_ATTRS}
        self.saved = [(H, "WS", H.WS), (O, "ORACLE_DIR", O.ORACLE_DIR), (O, "SEAL", O.SEAL), (O, "LEDGER", O.LEDGER),
                      (P, "filing_gate", P.filing_gate), (P, "payability", P.payability),
                      (E, "on_event", E.on_event), (E, "budget", E.budget), (E, "dupe_odds", E.dupe_odds),
                      (E, "bounties", E.bounties), (E, "filing_market", E.filing_market)]
        t = self.tmp
        L.WS = H.WS = t
        L.TARGETS = os.path.join(t, "targets")
        L.LINE_JSON = os.path.join(t, "economy", "line.json")
        L.LESSONS = os.path.join(t, "LESSONS.md")
        L.MANUAL_INDEX = os.path.join(t, "MANUAL-INDEX.md")
        L.DNR_DIR = os.path.join(t, "dnr")
        L.DNR_GLOBAL = os.path.join(t, "dnr-global.txt")
        L.OUTCOMES = os.path.join(t, "outcomes.jsonl")
        L.PUBLIC_DEDUP = os.path.join(t, "public-dedup.jsonl")
        L.INBOX = os.path.join(t, "INBOX.md")
        O.ORACLE_DIR = os.path.join(t, "oracles")
        O.SEAL = os.path.join(O.ORACLE_DIR, ".seal")
        O.LEDGER = os.path.join(t, "precision.json")
        with open(O.LEDGER, "w") as f:
            json.dump({"by_class": {"Race Condition": {"n": 4, "positive": 3}}}, f)
        with open(L.MANUAL_INDEX, "w") as f:
            f.write("| **T-39** | **Sequential-dead is not concurrent-dead.** burst | 01 |\n"
                    "| **T-247** | **A limit debited on SUCCESS** business-logic spend cap | 03 |\n"
                    "| **T-60** | **The SPA soft-200.** | 01 |\n")
        os.makedirs(os.path.join(L.TARGETS, PROG), exist_ok=True)
        self.events = []
        E.on_event = lambda kind, **kw: self.events.append((kind, kw)) or None
        E.budget = lambda program, hyp_id: 20
        E.dupe_odds = lambda cls="", program="": (0.5, 0)
        E.bounties = lambda R=None: {}
        E.filing_market = lambda *a, **k: "opened"
        P.filing_gate = lambda program, offline=False: (True, "open, bounties on, no signal gate")
        P.payability = lambda program, host: ("pays", f"{host} sits on a bounty row", {})

    def tearDown(self):
        for k, v in self.saved_l.items():
            setattr(L, k, v)
        for mod, k, v in self.saved:
            setattr(mod, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers
    def wo(self, **over):
        w = {"crown": "money", "class": "business-logic", "asset": "api.example.test", "budget_rc": 120,
             "oracle_class": "race-single-use", "seed_hint": "redeem burst"}
        w.update(over)
        return w

    def to_market(self):
        r = L.open(PROG, self.wo())
        self.assertTrue(r["ok"], r)
        wid = r["wo_id"]
        self.assertTrue(L.advance(PROG, wid, 1, SEED)["ok"])
        self.assertTrue(L.advance(PROG, wid, 2, MODEL)["ok"])
        m = L.market(PROG, wid, [_hyp()])
        self.assertTrue(m["ok"], m)
        return wid, m["hyps"][0]

    def set_floor(self, hid, probes, bursts):
        def fn(d):
            for h in d["hypotheses"]:
                if h["id"] == hid:
                    h["probes"], h["bursts"], h["burst"] = probes, bursts, bursts > 0
        H.modify(PROG, fn)

    # ---- station 0
    def test_open_refused_when_pay_gate_fails(self):
        P.filing_gate = lambda program, offline=False: (False, "HELD ON SIGNAL (T-254): target 1.0, ours -1.0")
        r = L.open(PROG, self.wo())
        self.assertFalse(r["ok"])
        self.assertIn("pay gate", r["check"])
        self.assertIn("HELD ON SIGNAL", r["check"])
        self.assertFalse(os.path.isdir(os.path.join(L.TARGETS, PROG, "line")) and
                         [f for f in os.listdir(os.path.join(L.TARGETS, PROG, "line")) if f.startswith("WO-")])

    def test_open_refused_when_scope_row_does_not_pay(self):
        P.payability = lambda program, host: ("no-bounty", "VDP row", {})
        r = L.open(PROG, self.wo())
        self.assertFalse(r["ok"])
        self.assertIn("scope row does not pay", r["check"])

    def test_open_refuses_trap_class_without_new_root_cause(self):
        with open(L.LESSONS, "w") as f:
            f.write("- TRAP, these are our WORST converters and the ones we hunt most: Insecure Direct Object "
                    "Reference (IDOR) 6% (1/16, 69% dupes); unlabelled 8% (1/12); Information Disclosure 12% (3/26)\n")
        self.assertEqual(L.trap_list(), ("Insecure Direct Object Reference (IDOR)", "Information Disclosure"))
        r = L.open(PROG, self.wo(**{"class": "idor", "oracle_class": "cross-user-read"}))
        self.assertFalse(r["ok"])
        self.assertIn("TRAP", r["check"])
        r = L.open(PROG, self.wo(**{"class": "idor", "oracle_class": "cross-user-read",
                                    "new_root_cause": "merge resolver takes a client-supplied destination id"}))
        self.assertTrue(r["ok"], r)

    def test_trap_fallback(self):
        self.assertIn("Improper Restriction of Authentication Attempts", L.trap_list())
        self.assertTrue(L.trap_match("exposure"))
        self.assertFalse(L.trap_match("business-logic"))

    # ---- station 1
    def test_intel_refused_without_kill_byte(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        sp = json.loads(json.dumps(SEED))
        sp["seeds"][0]["kill_byte"] = ""
        r = L.advance(PROG, wid, 1, sp)
        self.assertFalse(r["ok"])
        self.assertIn("kill byte", r["check"])
        sp = json.loads(json.dumps(SEED))
        sp["dedup"] = {}
        self.assertIn("dedup stamp", L.advance(PROG, wid, 1, sp)["check"])

    def test_intel_drops_do_not_rehunt_seed(self):
        os.makedirs(L.DNR_DIR)
        with open(os.path.join(L.DNR_DIR, f"{PROG}.txt"), "w") as f:
            f.write(f"{PROG}|api.example.test|business-logic redeem race|RECEIPT-DEAD|2026-10-22|x\n")
        wid = L.open(PROG, self.wo())["wo_id"]
        r = L.advance(PROG, wid, 1, SEED)
        self.assertFalse(r["ok"])
        self.assertIn("do-not-rehunt", r["check"])

    def test_no_skipping_stations(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        r = L.advance(PROG, wid, 2, MODEL)
        self.assertFalse(r["ok"])
        self.assertIn("cannot be skipped", r["check"])
        r = L.advance(PROG, wid, 4, {"hyp_id": "H1"})
        self.assertFalse(r["ok"])
        self.assertIn("MARKET has not passed", r["check"])

    def test_model_refused_without_excluded_actor(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        L.advance(PROG, wid, 1, SEED)
        r = L.advance(PROG, wid, 2, {"boundaries": [{"name": "b1", "asset": "x"}], "catastrophic": ["y"]})
        self.assertFalse(r["ok"])
        self.assertIn("excluded actor", r["check"])

    # ---- station 3
    def test_market_refused_without_oracle_commit(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        L.advance(PROG, wid, 1, SEED)
        L.advance(PROG, wid, 2, MODEL)
        H.hypothesis(PROG, "add", title="t", crown="money", assumption="a", violation="POST /api/v1/pay amount=1", prediction="p",
                     kill_byte="k")
        r = L.advance(PROG, wid, 3, {"hyps": [{"hid": "H1", "oracle_id": "o-deadbeef"}]})
        self.assertFalse(r["ok"])
        self.assertIn("no oracle COMMITTED", r["check"])

    def test_market_rejects_missing_avp(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        L.advance(PROG, wid, 1, SEED)
        L.advance(PROG, wid, 2, MODEL)
        r = L.market(PROG, wid, [_hyp(assumption="")])
        self.assertFalse(r["ok"])
        self.assertIn("ASSUMPTION", r["rejected"][0]["why"])
        r = L.market(PROG, wid, [_hyp("h2")])
        self.assertTrue(r["ok"], r)
        self.assertRegex(r["hyps"][0]["preimage"], r"^gnoc-[0-9a-f]{32}$")
        stored = _slurp(L.wo_path(PROG, wid)) + _slurp(r["artifact"])
        self.assertNotIn(r["hyps"][0]["preimage"], stored)

    # ---- station 4
    def test_probe_floor(self):
        wid, h = self.to_market()
        hid = h["hid"]
        self.set_floor(hid, 7, 1)
        r = L.advance(PROG, wid, 4, {"hyp_id": hid, "advisory": "DEAD"})
        self.assertFalse(r["ok"])
        self.assertIn("7 probes < 8", r["check"])
        self.set_floor(hid, 8, 0)
        r = L.advance(PROG, wid, 4, {"hyp_id": hid, "advisory": "DEAD"})
        self.assertFalse(r["ok"])
        self.assertIn("no burst", r["check"])
        self.set_floor(hid, 8, 1)
        r = L.advance(PROG, wid, 4, {"hyp_id": hid, "advisory": "DEAD"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["verdict"], "DEAD")

    def test_probe_finder_candidate_is_not_trusted(self):
        wid, h = self.to_market()
        self.set_floor(h["hid"], 9, 1)
        r = L.advance(PROG, wid, 4, {"hyp_id": h["hid"], "advisory": "CANDIDATE"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["verdict"], "LEAD")
        r = L.advance(PROG, wid, 5, {"hyp_id": h["hid"], "capability": "money", "evidence": "x"})
        self.assertFalse(r["ok"])
        self.assertIn("only an oracle PASS escalates", r["check"])

    def to_candidate(self):
        wid, h = self.to_market()
        O._append(PROG, {"ts": L._now(), "id": h["oracle_id"], "event": "verdict", "status": "passed", "why": "t"})
        r = L.advance(PROG, wid, 4, {"hyp_id": h["hid"], "advisory": "DEAD"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["verdict"], "CANDIDATE")
        return wid, h

    def test_probe_candidate_on_oracle_pass(self):
        self.to_candidate()

    def test_probe_refuses_floorless_dead_outcome_row(self):
        wid, h = self.to_market()
        self.set_floor(h["hid"], 8, 1)
        with open(L.OUTCOMES, "w") as f:
            f.write(json.dumps({"target": PROG, "hypothesis": h["hid"], "verdict": "DEAD", "floor": "not-met"}) + "\n")
        r = L.advance(PROG, wid, 4, {"hyp_id": h["hid"]})
        self.assertFalse(r["ok"])
        self.assertIn("outcome row", r["check"])

    def test_log_and_burst_feed_the_floor_from_files_only(self):
        wid, h = self.to_market()
        hid = h["hid"]
        cdir = os.path.join(L.TARGETS, PROG, "caps")
        os.makedirs(cdir)
        caps = []
        for i in range(8):
            c = os.path.join(cdir, f"c{i}.json")
            with open(c, "w") as f:
                f.write(f'{{"i":{i}}}')
            caps.append(c)
        r = L.log_capture(PROG, hid, caps[:7] + [caps[0], os.path.join(self.tmp, "outside.json")])
        self.assertEqual(r["logged"], 7)
        self.assertEqual(len(r["refused"]), 2)
        self.assertIn("7 probes < 8", L.advance(PROG, wid, 4, {"hyp_id": hid})["check"])
        L.log_capture(PROG, hid, [caps[7]])
        self.assertFalse(L.log_burst(PROG, hid, caps[0], [caps[1]])["ok"])          # one arm is not a burst
        self.assertFalse(L.log_burst(PROG, hid, "missing.json", caps[1:3])["ok"])  # no serial control
        r = L.log_burst(PROG, hid, caps[0], caps[1:3])
        self.assertTrue(r["ok"], r)
        self.assertFalse(L.log_burst(PROG, hid, caps[0], caps[1:3])["ok"])         # same burst twice
        r = L.advance(PROG, wid, 4, {"hyp_id": hid, "advisory": "LEAD"})
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["verdict"], "LEAD")

    # ---- station 5
    def test_escalate_needs_named_capability(self):
        wid, h = self.to_candidate()
        r = L.advance(PROG, wid, 5, {"hyp_id": h["hid"], "capability": "none"})
        self.assertFalse(r["ok"])
        self.assertIn("no NEW capability named", r["check"])
        r = L.advance(PROG, wid, 5, {"hyp_id": h["hid"], "capability": "leaked-internal-hostname", "evidence": "e"})
        self.assertFalse(r["ok"])
        self.assertIn("standalone primitive", r["check"])
        ev = os.path.join(self.tmp, "cap.json")
        with open(ev, "w") as f:
            f.write('{"credited":2}')
        r = L.advance(PROG, wid, 5, {"hyp_id": h["hid"], "capability": "money", "evidence": ev,
                                     "must_contain": '"credited":2'})
        self.assertTrue(r["ok"], r)

    # ---- status, brief, events, summary
    def test_status_brief_and_events(self):
        wid, h = self.to_market()
        s = L.status(PROG)
        self.assertIn(f"WO-{wid} at 3 MARKET", s)
        self.assertIn(h["hid"], s)
        b = L.brief(PROG, wid, "claude-opus")
        for want in ("MANAGER 1:1:", "WORK ORDER:", "SEED PACK:", h["oracle_id"], '"credited":2', "FLOOR: >= 8",
                     "RELEASE PHASE: GA", "BUDGET: 120 RC", "T-39", "T-247", "NEXT STATION for"):
            self.assertIn(want, b)
        self.assertNotIn("T-60:", b)
        kinds = [k for k, _ in self.events]
        self.assertGreaterEqual(kinds.count("line-advance"), 4)   # open + 1 + 2 + 3
        st = [kw.get("station") for k, kw in self.events if k == "line-advance"]
        self.assertEqual(st[:4], [0, 1, 2, 3])
        summary = json.loads(_slurp(L.LINE_JSON))
        self.assertEqual(summary["programs"][PROG][0]["id"], wid)

    def test_refusal_also_emits_event(self):
        P.filing_gate = lambda program, offline=False: (False, "closed")
        L.open(PROG, self.wo())
        self.assertEqual(self.events[-1][0], "line-advance")
        self.assertFalse(self.events[-1][1]["ok"])

    def test_cli_advance_with_urlencoded_data(self):
        wid = L.open(PROG, self.wo())["wo_id"]
        enc = urllib.parse.quote(json.dumps(SEED), safe="")
        self.assertNotIn("'", enc)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = L.main(["advance", PROG, wid, "INTEL", "--data", enc])
            rc2 = L.main(["advance", PROG, wid, "MODEL", "--data", urllib.parse.quote('{"boundaries":[]}')])
        self.assertEqual(rc, 0)
        self.assertEqual(rc2, 3)
        self.assertEqual(L.load_wo(PROG, wid)["station"], 1)
        self.assertIn("MODEL refused: target model has no trust boundaries", out.getvalue())


if __name__ == "__main__":
    unittest.main()
