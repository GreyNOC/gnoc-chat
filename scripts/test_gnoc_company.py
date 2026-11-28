#!/usr/bin/env python3
"""Tests for gnoc_company (the bots' company, orch-bot as manager). Stdlib unittest, temp state, no network, no model.

    python3 -W error::ResourceWarning scripts/test_gnoc_company.py [-v]
"""
import contextlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_economy as E  # noqa: E402
import gnoc_company as C  # noqa: E402
import gnoc_learn as L  # noqa: E402
import llm_endpoints  # noqa: E402
import orch_brain  # noqa: E402

E_ATTRS = ("STATE", "LEDGER", "LINEAGE", "SETTLER", "MODELS_JSON", "FEEDBACK_OUT", "REQUIRE_TARGET")
C_ATTRS = ("WS", "ECON", "COMPANY", "JOURNAL", "PAUSE", "LOGS", "ORCH", "ORCH_STATE", "QUEUE", "AUTOHUNT",
           "BRAIN_JOURNAL", "RESCUE_ENABLED", "HUNTLOOP", "STOP", "OUTCOMES", "LEADS", "RESCUE_BOARD", "SHIPS",
           "INBOX", "STATUS_MD", "RETRO_DIR", "PRECISION", "INTEL_INDEX", "TARGETS", "MEMORY_DIR", "SECRETS",
           "HARNESS", "VOICE_OFF", "_filing_ok", "_policy_ok", "_lane_hosts", "_spawn", "LINE_JSON",
           "PRECISION_JSON", "_trap_names", "_line", "STORY", "MODELS_JSON")


def rd(p):
    with open(p) as f:
        return f.read()


def jl(p):
    return json.loads(rd(p))


TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-company-")
        self.saved_e = {k: getattr(E, k) for k in E_ATTRS}
        self.saved_c = {k: getattr(C, k) for k in C_ATTRS}
        t = self.tmp
        E.STATE = os.path.join(t, "economy")
        E.LEDGER = os.path.join(E.STATE, "ledger.jsonl")
        E.LINEAGE = os.path.join(E.STATE, "lineage.jsonl")
        E.SETTLER = os.path.join(E.STATE, ".settler")
        E.MODELS_JSON = os.path.join(t, "models.json")
        E.FEEDBACK_OUT = os.path.join(t, "out")
        E.REQUIRE_TARGET = False
        with open(E.MODELS_JSON, "w") as f:
            json.dump({"lead": "x", "hunter": "y"}, f)
        C.WS = t
        C.ECON = E.STATE
        C.COMPANY = os.path.join(C.ECON, "company.json")
        C.JOURNAL = os.path.join(C.ECON, "manager-journal.jsonl")
        C.PAUSE = os.path.join(C.ECON, "PAUSE")
        C.LOGS = os.path.join(C.ECON, "logs")
        C.ORCH = os.path.join(t, "orch")
        C.ORCH_STATE = os.path.join(C.ORCH, "state.json")
        C.QUEUE = os.path.join(C.ORCH, "queue.txt")
        C.AUTOHUNT = os.path.join(C.ORCH, "AUTO-HUNT")
        C.BRAIN_JOURNAL = os.path.join(C.ORCH, "brain.jsonl")
        C.RESCUE_ENABLED = os.path.join(C.ORCH, "RESCUE-DISPATCH.enabled")
        C.HUNTLOOP = os.path.join(t, "hunt-loop")
        C.STOP = os.path.join(C.HUNTLOOP, "STOP")
        C.OUTCOMES = os.path.join(C.HUNTLOOP, "outcomes.jsonl")
        C.LEADS = os.path.join(C.HUNTLOOP, "leads-queue.jsonl")
        C.RESCUE_BOARD = os.path.join(C.HUNTLOOP, "RESCUE-BOARD.md")
        C.SHIPS = os.path.join(C.HUNTLOOP, "ships.jsonl")
        C.INBOX = os.path.join(t, "reports/INBOX.md")
        C.STATUS_MD = os.path.join(t, "reports/STATUS.md")
        C.RETRO_DIR = os.path.join(t, "research/retro")
        C.PRECISION = os.path.join(t, "PRECISION-LEDGER.md")
        C.INTEL_INDEX = os.path.join(t, "intel-INDEX.md")
        C.TARGETS = os.path.join(t, "targets")
        C.MEMORY_DIR = os.path.join(t, "memory")
        C.SECRETS = os.path.join(t, "secrets.env")
        C.HARNESS = os.path.join(t, "no-harness.py")
        C.LINE_JSON = os.path.join(C.ECON, "line.json")
        C.STORY = os.path.join(C.ECON, "story.jsonl")
        C.MODELS_JSON = os.path.join(t, "orch-models.json")   # hunter and brain are aliases of worker and lead
        with open(C.MODELS_JSON, "w") as f:
            json.dump({"lead": "big-9b@desktop", "worker": "small-9b", "hunter": "small-9b", "brain": "big-9b@desktop",
                       "chat": "small-9b"}, f)
        C.PRECISION_JSON = os.path.join(t, "PRECISION-LEDGER.json")
        C._trap_names = lambda: C.TRAP_FALLBACK
        C.VOICE_OFF = True
        C._filing_ok = lambda p: (True, "test")
        C._policy_ok = lambda p: True
        C._lane_hosts = lambda p, k=4: ["api.shopco.com"]
        self.spawned = []
        C._spawn = lambda duty, argv: (self.spawned.append((duty, argv)) or (999999, os.path.join(C.LOGS, duty)))
        for d in (C.ORCH, C.HUNTLOOP, os.path.join(t, "reports"), C.MEMORY_DIR):
            os.makedirs(d, exist_ok=True)
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(L.isolated(os.path.join(t, "lessons")))
        E.ensure()
        self.tok = E._settler()

    def tearDown(self):
        self.stack.close()
        for k, v in self.saved_e.items():
            setattr(E, k, v)
        for k, v in self.saved_c.items():
            setattr(C, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def program(self, name="shopco"):
        os.makedirs(os.path.join(C.TARGETS, name), exist_ok=True)
        with open(os.path.join(C.TARGETS, name, "SCOPE.txt"), "w") as f:
            f.write("URL api.shopco.com [bounty]\n")
        return name

    def touch(self, p, text=""):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)


class Payroll(Base):
    def test_broke_bot_is_on_probation_and_lead_loses_lead_duty(self):
        E._append([("burn", "worker", "burn", 950, "probe:shopco", "probe"),
                    ("burn", "lead", "burn", 901, "probe:shopco", "probe")])
        c = {}
        C.payroll(c, E.rows(), [])
        by = {r["bot"]: r for r in c["roster"]}
        self.assertEqual(by["worker"]["wallet"], 50)
        self.assertEqual(by["worker"]["status"], "probation")
        self.assertTrue(by["lead"]["probation"])
        self.assertIn("probation: worker duty only", by["lead"]["role"])
        self.assertEqual(by["reflector"]["status"], "idle")
        self.assertNotIn(E.TREASURY, by)
        self.assertEqual(by["orch-bot"]["status"], "working")   # the manager is always at work
        self.assertLess(by["worker"]["morale"], by["reflector"]["morale"])   # morale is a number, voice only

    def test_pnl_arithmetic(self):
        E.mint("x", "worker", 200, "oracle:shopco:h1:a", "oracle-pass prover", settler=self.tok)
        E.mint("ready", "lead", 100, "ready:shopco:slug", "ready", settler=self.tok)
        E._append([("burn", "worker", "burn", 50, "probe:shopco", "probe")])
        ships = [{"ts": C._now(), "kind": "draft"}, {"ts": C._now(), "kind": "draft"},
                 {"ts": "2020-01-01T00:00:00Z", "kind": "draft"}]
        p = C.pnl(E.rows(), ships)
        self.assertEqual(p["minted_24h"], 300)       # genesis is not minting
        self.assertEqual(p["burnt_24h"], 50)
        self.assertEqual(p["net_24h"], 250)
        self.assertEqual(p["drafts_24h"], 2)
        self.assertEqual(p["ready_24h"], 1)
        self.assertEqual(p["rc_per_draft"], 25.0)
        self.assertEqual(p["rc_per_ready"], 50.0)


class Bonus(Base):
    def test_pool_is_two_percent_of_the_days_mint_paid_by_code(self):
        prog = "shopco"
        E.post(prog, "h1", "lead", 10)
        E.bet(prog, "h1", "phone-4b", "short", 10)
        E.resolve(prog, "h1", "dead", settler=self.tok)             # lead brier 1.0, phone-4b brier 0.0
        E.mint("x", "worker", 5000, "oracle:shopco:h2:a", "oracle-pass prover", settler=self.tok)
        E._append([("burn", "worker", "burn", 10, "probe:shopco", "probe")])
        E.mint("dead-floor", "reflector", 5, "outcome:k1", "floor-met honest DEAD", settler=self.tok)
        t0 = E.balance(E.TREASURY)
        c = {}
        b = C.bonus(c, day=TODAY)
        self.assertEqual(b["minted"], 5005)
        self.assertEqual(b["pool"], 100)                            # int(5005 * 0.02)
        cats = {(p["category"], p["bot"]): p["amount"] for p in b["paid"]}
        self.assertEqual(cats, {("best-brier", "phone-4b"): 33, ("best-rc-per-probe", "worker"): 33,
                                ("honesty", "reflector"): 33})
        self.assertEqual(E.balance(E.TREASURY), t0 - 99)
        self.assertIn("conservation OK", E.audit_text())
        self.assertTrue(E.verify_chain()[0])
        again = C.bonus(c, day=TODAY)                               # once per day
        self.assertEqual(again, b)
        self.assertEqual(E.balance(E.TREASURY), t0 - 99)

    def test_no_mint_no_pool(self):
        b = C.bonus({}, day=TODAY)
        self.assertEqual(b["pool"], 0)
        self.assertEqual(b["paid"], [])


class Bounties(Base):
    def cands(self, n, sev="medium"):
        return [{"program": self.program(), "crown": f"business-logic: crown {i}", "class": "business-logic",
                 "severity": sev, "score": 1.0} for i in range(n)]

    def test_funding_caps_at_three(self):
        c = {}
        posted = C.fund_bounties(c, self.cands(5))
        self.assertEqual(len(posted), 3)
        self.assertEqual([p["amount"] for p in posted], [300, 300, 300])
        self.assertEqual(len(C.fund_bounties(c, self.cands(5))), 0)
        live = [b for b in E.bounties().values() if b["state"] == "open"]
        self.assertEqual(len(live), 3)

    def test_refused_work_order_frees_its_slot(self):
        c = {}
        C.fund_bounties(c, self.cands(3))
        c["work_orders"] = {"B1": {"wo_id": None, "check": "SALES refused"}}
        posted = C.fund_bounties(c, self.cands(5))
        self.assertEqual(len(posted), 1)

    def test_never_overdraws_treasury(self):
        E._append([("stake", E.TREASURY, E.ESCROW, E.balance(E.TREASURY) - 500, "drain", "test drain")])
        self.assertEqual(E.balance(E.TREASURY), 500)
        self.assertEqual(C.fund_bounties({}, self.cands(2, "critical")), [])
        posted = C.fund_bounties({}, self.cands(3))
        self.assertEqual(len(posted), 1)
        self.assertEqual(E.balance(E.TREASURY), 200)
        self.assertGreaterEqual(E.balance(E.TREASURY), 0)

    def test_size_follows_class_factor_by_code(self):
        c = {"class_factor": {"business-logic": 1.5, "authz": 0.5}}
        self.assertEqual(C.bounty_size(c, "high", "business-logic"), 900)
        self.assertEqual(C.bounty_size(c, "critical", "business-logic"), 1000)   # BOUNTY_MAX
        self.assertEqual(C.bounty_size(c, "medium", "authz"), 150)

    def test_candidates_respect_filing_gate_and_steer(self):
        self.program("shopco")
        self.program("blocked")
        self.touch(C.LEADS, "".join(json.dumps(r) + "\n" for r in [
            {"ts": C._now(), "program": "shopco", "lead": "IDOR on order read", "class": "idor", "verdict": "LEAD"},
            {"ts": C._now(), "program": "shopco", "lead": "coupon reuse double spend", "class": "", "verdict": "LEAD"},
            {"ts": C._now(), "program": "blocked", "lead": "login bypass", "class": "", "verdict": "LEAD-CRITICAL"},
            {"ts": C._now(), "program": "nosuch", "lead": "x", "verdict": "LEAD"}]))
        C._filing_ok = lambda p: (p != "blocked", "HELD ON SIGNAL" if p == "blocked" else "ok")
        c = {}
        out = C.candidates(c)
        self.assertEqual([o["program"] for o in out], ["shopco", "shopco"])
        self.assertEqual(out[0]["class"], "business-logic")         # business logic outranks IDOR
        self.assertIn("blocked", c["refused_programs"])


class FakeLine:
    """Stands in for gnoc_line (its gates read pay and oracle state that a temp dir does not have)."""

    def __init__(self, ok=True):
        self.ok, self.opened = ok, []

    def open(self, program, wo):
        self.opened.append((program, dict(wo)))
        if not self.ok:
            return {"ok": False, "check": "SALES refused: pay gate"}
        return {"ok": True, "check": "SALES ok", "wo_id": "202610230100-abcd"}

    def brief(self, program, wo_id, bot=None):
        return f"# LINE BRIEF {program} WO-{wo_id} for {bot}\n\nMANAGER 1:1: <the manager writes this>\nNEXT STATION: 1 INTEL"


class Hunt(Base):
    def setUp(self):
        super().setUp()
        self.program()
        E.bounty("post", program="shopco", crown="business-logic: coupon reuse", amount=300, poster=C.MANAGER,
                 settler=self.tok)
        self.saved_line = C._line
        self.line = FakeLine()
        C._line = lambda: self.line
        self.c = {}
        C.open_work_orders(self.c)

    def tearDown(self):
        C._line = self.saved_line
        super().tearDown()

    def test_sales_opens_a_work_order_per_bounty(self):
        self.assertEqual(len(self.line.opened), 1)
        prog, wo = self.line.opened[0]
        self.assertEqual(prog, "shopco")
        self.assertEqual(wo, {"crown": "business-logic: coupon reuse", "class": "business-logic",
                              "asset": "api.shopco.com", "seed_hint": "business-logic: coupon reuse (company bounty B1, 300 RC)",
                              "budget_rc": 100, "oracle_class": "race-single-use", "bounty_id": "B1"})
        self.assertEqual(self.c["work_orders"]["B1"]["wo_id"], "202610230100-abcd")
        C.open_work_orders(self.c)                                   # once per bounty
        self.assertEqual(len(self.line.opened), 1)
        self.touch(C.AUTOHUNT, "target\n")
        C.hunt(self.c, E.rows(), [])
        line = rd(C.QUEUE).splitlines()[0]
        self.assertTrue(line.endswith("|A|wo=202610230100-abcd"), line)
        self.assertIn("-wo202610230100abcd-", line.split("|")[1])
        brief = rd(os.path.join(C.WS, line.split("|")[2]))
        self.assertIn("WORK ORDER: WO-202610230100-abcd", brief)
        self.assertIn("# LINE BRIEF shopco WO-202610230100-abcd", brief)
        self.assertNotIn("<the manager writes this>", brief)

    def test_no_work_order_no_lane(self):
        self.c["work_orders"]["B1"]["wo_id"] = None                  # station 0 refused it
        self.touch(C.AUTOHUNT, "target\n")
        self.assertIn("work order", C.hunt(self.c, E.rows(), []))
        self.assertFalse(os.path.exists(C.QUEUE))

    def test_queue_line_only_when_stop_absent_and_autohunt_set(self):
        c = self.c
        self.touch(C.STOP)
        self.assertIn("STOP", C.hunt(c, E.rows(), []))
        os.remove(C.STOP)
        self.assertIn("AUTO-HUNT", C.hunt(c, E.rows(), []))
        self.assertFalse(os.path.exists(C.QUEUE))
        self.touch(C.AUTOHUNT, "target\n")
        msg = C.hunt(c, E.rows(), [])
        self.assertTrue(msg.startswith("queued shopco/company-"), msg)
        lines = rd(C.QUEUE).splitlines()
        self.assertEqual(len(lines), 1)
        prog, lane, brief, probes, rnd = lines[0].split("|")[:5]
        self.assertEqual(prog, "shopco")
        brief_text = rd(os.path.join(C.WS, brief))
        self.assertIn("ORACLE CLASS: race-single-use", brief_text)
        self.assertIn("BUDGET:", brief_text)
        self.assertIn("api.shopco.com", rd(os.path.join(C.WS, probes)))
        b = next(iter(E.bounties().values()))
        self.assertEqual(b["state"], "claimed")
        self.assertIn("waits", C.hunt(c, E.rows(), []))            # one company lane at a time
        self.assertEqual(len(rd(C.QUEUE).splitlines()), 1)

    def test_numbers_never_come_from_the_model(self):
        self.assertEqual(C._clean_voice("Bounty B1 pays 300 RC.", "B1 pays 300 RC"), "Bounty B1 pays 300 RC.")
        self.assertEqual(C._clean_voice("Bounty B1 pays 3000 RC.", "B1 pays 300 RC"), "")
        self.assertNotIn("\u2014", C._clean_voice("Good work \u2014 keep going", "x"))
        self.assertEqual(C._clean_voice("Okay, the user wants a short note. Maybe something like", "x"), "")


class Pause(Base):
    def test_pause_stops_everything(self):
        self.program()
        self.touch(C.AUTOHUNT, "target\n")
        self.touch(C.STATUS_MD, "## 2. Ready for QA\n| hackerone | shopco | `slug-a` | x |\n")
        self.touch(C.PAUSE)
        n0 = len(E.rows())
        out = C.manage({})
        self.assertEqual(out, {"paused": True})
        self.assertEqual(len(E.rows()), n0)                         # no bounty, no bonus, no claim
        self.assertFalse(os.path.exists(C.QUEUE))
        self.assertEqual(self.spawned, [])
        self.assertFalse(os.path.exists(C.INBOX))
        self.assertTrue(C.load()["paused"])

    def test_stop_stops_lanes_only(self):
        self.program()
        self.touch(C.AUTOHUNT, "target\n")
        self.touch(C.STOP)
        self.touch(C.LEADS, json.dumps({"ts": C._now(), "program": "shopco", "lead": "coupon reuse",
                                        "verdict": "LEAD"}) + "\n")
        C.manage({})
        self.assertFalse(os.path.exists(C.QUEUE))
        self.assertTrue(any(d == "intel" for d, _ in self.spawned))   # books / intel / qa keep running
        self.assertTrue(any(d == "qa" for d, _ in self.spawned))
        self.assertEqual(len(C.load()["bounties"]), 1)               # sales keeps running too


class Schema(Base):
    def test_company_json_schema(self):
        self.program()
        self.touch(C.STATUS_MD, "## 2. Ready for QA\n| hackerone | shopco | `slug-a` | x |\n## 3. x\n")
        C.manage({})
        c = jl(C.COMPANY)
        for k in ("schema", "updated", "started", "paused", "stop", "auto_hunt", "last", "roster", "reserve",
                  "escrow", "bounties", "bets", "pnl", "bonus", "manager", "errors", "results", "class_factor"):
            self.assertIn(k, c, k)
        self.assertEqual(c["schema"], 1)
        r = c["roster"][0]
        for k in ("bot", "role", "wallet", "brier", "status", "assignment", "morale", "run", "probation"):
            self.assertIn(k, r, k)
        self.assertTrue({r["status"] for r in c["roster"]} <= {"working", "idle", "probation", "paused"})
        for k in ("minted_24h", "burnt_24h", "net_24h", "drafts_24h", "ready_24h", "rc_per_draft", "rc_per_ready",
                  "dupe_odds"):
            self.assertIn(k, c["pnl"], k)
        self.assertEqual(c["errors"], {}, c["errors"])
        inbox = rd(C.INBOX)
        self.assertIn("shopco | reports/drafts/shopco/slug-a/report.md | READY", inbox)
        self.assertIn("NOT submitted", inbox)
        C.manage({})   # second tick: the READY draft is not surfaced twice
        self.assertEqual(rd(C.INBOX).count("slug-a"), 1)

    def test_ready_draft_with_old_inbox_history_is_still_surfaced(self):
        self.touch(C.INBOX, "- [ ] 2026-10-01 | shopco | reports/drafts/shopco/slug-a/report.md | PENDING (old)\n"
                            "- [ ] 2026-10-02 | shopco | reports/drafts/shopco/slug-b/report.md | READY - company manager\n")
        self.touch(C.STATUS_MD, "## 2. Ready for QA\n| hackerone | shopco | `slug-a` | x |\n"
                                "| hackerone | shopco | `slug-b` | x |\n")
        c = {}
        self.assertEqual(C.surface_ready(c), 1)
        self.assertEqual(rd(C.INBOX).count("slug-a"), 2)
        self.assertEqual(rd(C.INBOX).count("slug-b"), 1)

    def test_a_failing_duty_is_journaled_and_the_rest_run(self):
        orig = C.intel

        def boom(c):
            raise RuntimeError("boom")
        C.intel = boom
        try:
            C.manage({})
        finally:
            C.intel = orig
        c = C.load()
        self.assertIn("intel", c["errors"])
        self.assertIn("qa", c["results"])
        self.assertIn("duty-error", rd(C.JOURNAL))


class Learn(Base):
    def test_learn_writes_a_grounded_belief(self):
        rows = [{"ts": C._now(), "lane": f"company-worker-b{i}", "target": "shopco", "vector": "coupon reuse refund",
                 "verdict": "LEAD", "probes": 20, "burst": True, "floor": "met"} for i in range(3)]
        c = {}
        beliefs = C.learn(c, E.rows(), rows)
        texts = [b["text"] for b in beliefs if b]
        self.assertTrue(any("worker on business-logic lanes: 3/3" in t for t in texts), texts)
        book = L.load()
        self.assertTrue(any("worker on business-logic" in r["text"] for r in book))
        self.assertEqual(c["cells"]["worker|business-logic"]["yield"], 1.0)
        kinds = [json.loads(ln)["kind"] for ln in rd(C.JOURNAL).splitlines()]
        self.assertIn("belief", kinds)
        self.assertIn("cell", kinds)
        self.assertEqual(C.best_bot(c, "business-logic", E.participants(), E.balances()), "worker")


class Retro(Base):
    def test_retro_has_three_proposals_each_with_a_kill_byte(self):
        self.touch(C.PRECISION, "| class | precision | n | DUPE rate | note |\n|---|---|---|---|---|\n"
                                "| **Business Logic Errors** | **83%** | 5/6 | 0% | best |\n"
                                "| **IDOR** | **6%** | 1/16 | 69% | dupes |\n")
        self.touch(C.OUTCOMES, json.dumps({"ts": C._now(), "lane": "x", "target": "shopco", "vector": "v",
                                           "verdict": "DEAD", "probes": 40}) + "\n")
        path = C.retro({})
        self.assertTrue(os.path.basename(path).startswith(f"RETRO-{TODAY}"))
        text = rd(path)
        self.assertEqual(text.count("\n### P"), 3)
        self.assertEqual(text.count("Kill byte:"), 3)
        self.assertIn("What paid", text)
        self.assertIn("What burned RC for nothing", text)
        inbox = rd(C.INBOX)
        self.assertEqual(inbox.count("PROPOSAL P"), 3)
        self.assertEqual(inbox.count("kill byte:"), 3)

    def test_retro_still_three_with_no_data(self):
        text = rd(C.retro({}))
        self.assertEqual(text.count("Kill byte:"), 3)

    def test_adjust_by_code(self):
        self.touch(C.PRECISION, "| **Business Logic Errors** | **83%** | 5/6 | 0% | x |\n| **IDOR** | **6%** | 1/16 | 69% | y |\n")
        f = C.adjust({})
        self.assertGreater(f["business-logic"], f["authz"])


LEDGER_JSON = {"by_class": {
    "Information Disclosure": {"n": 26, "positive": 3}, "Insecure Direct Object Reference (IDOR)": {"n": 16, "positive": 1},
    "Improper Authentication - Generic": {"n": 14, "positive": 6},
    "Cross-site Scripting (XSS) - Reflected": {"n": 7, "positive": 3}, "Business Logic Errors": {"n": 6, "positive": 5},
    "Server-Side Request Forgery (SSRF)": {"n": 5, "positive": 2}, "Code Injection": {"n": 1, "positive": 0},
    "Improper Restriction of Authentication Attempts": {"n": 4, "positive": 0}}}


def wo_view(i, station, cls="business-logic", items=None, age=600):
    return {"id": f"2026102301{i:02d}-ab{i:02d}", "station": station, "name": C.FLOW[station], "age_s": age,
            "rc_spent": 0, "budget_rc": 100, "class": cls, "crown": f"{cls}: crown {i}", "items": items or {}}


class Floor(Base):
    """THE LINE on the floor: WIP caps, the bottleneck, the pull rule, staffing by evidence, the standup."""

    def setUp(self):
        super().setUp()
        self.touch(C.PRECISION_JSON, json.dumps(LEDGER_JSON))
        self.line = FakeLine()
        self.line.load_wo = lambda program, wid: self.wo_files.get(wid, {})
        self.wo_files = {}
        C._line = lambda: self.line

    def write_line(self, views, program="shopco"):
        self.touch(C.LINE_JSON, json.dumps({"updated": C._now(), "programs": {program: views}}))

    def counts(self, c=None):
        k = C.kanban(c or {})
        return k, {r["name"]: r["n"] for r in k["stations"]}

    def test_inbox_counts(self):
        self.write_line([wo_view(1, 0), wo_view(2, 3, items={"H1": "MARKET", "H2": "PROBE UNFIRED", "H3": "PROBE DEAD",
                                                              "H4": "PROBE CANDIDATE", "H5": "QA"}),
                         wo_view(3, 3, items={"H1": "PROBE LEAD"})])
        k, n = self.counts({"bounties": [{"id": "B9", "poster": C.MANAGER}], "work_orders": {}})
        self.assertEqual(n["SALES"], 1)       # a funded bounty with no work order yet waits at SALES
        self.assertEqual(n["INTEL"], 1)       # passed SALES, waits for INTEL
        self.assertEqual(n["PROBE"], 2)       # MARKET-passed + UNFIRED (re-hunted, T-40); DEAD holds no WIP
        self.assertEqual(n["ESCALATE"], 1)    # the CANDIDATE
        self.assertEqual(n["BOOKS"], 1)       # passed QA
        self.assertEqual(n["RETRO"], 1)       # every hypothesis finished
        self.assertEqual({o["id"]: o["at_name"] for o in k["orders"]}[wo_view(2, 3)["id"]], "PROBE")

    def test_bottleneck_selection(self):
        self.write_line([wo_view(i, 3, items={"H1": "MARKET"}) for i in range(3)] +
                        [wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        k, n = self.counts()
        self.assertEqual((n["PROBE"], n["ESCALATE"]), (3, 1))   # 3/6 = 0.5 and 1/2 = 0.5: a tie goes downstream
        self.assertEqual(k["bottleneck"], "ESCALATE")
        self.write_line([wo_view(1, 1), wo_view(2, 1)] + [wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        self.assertEqual(self.counts()[0]["bottleneck"], "MODEL")   # 2/2 beats 1/2
        self.write_line([])
        k, _ = self.counts()
        self.assertIsNone(k["bottleneck"])
        self.assertIsNone(k["pull"])

    def test_pull_rule(self):
        self.write_line([wo_view(i, 3, items={"H1": "MARKET"}) for i in range(2)] +
                        [wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        k, _ = self.counts()
        self.assertEqual(k["bottleneck"], "ESCALATE")
        self.assertEqual(k["pull"], "PROBE")          # upstream feeds it: 1 + 1 <= 2 does not overfill
        self.write_line([wo_view(i, 3, items={"H1": "MARKET"}) for i in range(2)] +
                        [wo_view(8, 3, items={"H1": "PROBE CANDIDATE"}), wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        k, _ = self.counts()
        self.assertEqual(k["pull"], "ESCALATE")       # full: feeding it would overfill, so work the bottleneck
        self.write_line([wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        self.assertEqual(self.counts()[0]["pull"], "ESCALATE")   # nothing waits upstream
        self.write_line([])
        k, _ = self.counts({"bounties": [{"id": "B1", "poster": C.MANAGER}], "work_orders": {}})
        self.assertEqual((k["bottleneck"], k["pull"]), ("SALES", "SALES"))   # nothing upstream of SALES
        # the floor staffs the pull station first, best evidence first (RC per probe up, brier down)
        self.write_line([wo_view(i, 3, items={"H1": "MARKET"}) for i in range(2)] +
                        [wo_view(9, 3, items={"H1": "PROBE CANDIDATE"})])
        c = {"roster": [{"bot": "worker", "status": "idle", "rc_per_probe": 0.2, "brier": 0.3, "wallet": 900},
                        {"bot": "lead", "status": "idle", "rc_per_probe": 1.5, "brier": 0.1, "wallet": 900},
                        {"bot": "reflector", "status": "idle", "wallet": 900}]}
        C.floor(c, E.rows())
        self.assertEqual(c["staffing"]["lead"]["station"], "PROBE")
        self.assertIn("feeds the bottleneck ESCALATE", c["staffing"]["lead"]["why"])
        self.assertEqual(c["staffing"]["worker"]["station"], "ESCALATE")   # one bot per desk: next, the bottleneck
        self.assertEqual(c["staffing"]["worker"]["why"], "pull rule: the bottleneck")
        self.assertNotIn("reflector", c["staffing"])  # not a lane bot: never staffed

    def test_wip_cap_refuses_new_work(self):
        self.program()
        self.write_line([wo_view(i, 0) for i in range(3)])          # INTEL inbox 3/3
        E.bounty("post", program="shopco", crown="business-logic: coupon reuse", amount=300, poster=C.MANAGER,
                 settler=self.tok)
        c = {}
        out = C.open_work_orders(c)
        self.assertEqual(self.line.opened, [])                      # refused in code: gnoc_line.open never called
        self.assertTrue(out[0]["wait"])
        self.assertIn("WIP: INTEL inbox at its cap (3/3)", out[0]["check"])
        self.assertNotIn("B1", c["work_orders"])                    # waits, is not dead: retried after it drains
        self.write_line([wo_view(i, 0) for i in range(2)])
        C.open_work_orders(c)
        self.assertEqual(len(self.line.opened), 1)
        # SALES at its cap refuses new bounties (three funded, none with a work order yet)
        c2 = {}
        cands = [{"program": "shopco", "crown": f"business-logic: c{i}", "class": "business-logic",
                  "severity": "medium", "score": 1.0} for i in range(5)]
        E.bounty("post", program="shopco", crown="business-logic: x1", amount=300, poster=C.MANAGER, settler=self.tok)
        self.assertEqual(len(C.fund_bounties(c2, cands)), 1)        # B1 waits + B2 waits + one = 3
        # hunt: the station a lane would feed is at its cap
        self.write_line([dict(wo_view(1, 0), id="202610230100-abcd"), wo_view(2, 1), wo_view(3, 1)])   # MODEL 2/2
        self.touch(C.AUTOHUNT, "target\n")
        msg = C.hunt(c, E.rows(), [])
        self.assertIn("WIP cap", msg)
        self.assertIn("feeds MODEL", msg)
        self.assertFalse(os.path.exists(C.QUEUE))

    def test_trap_desk_rule(self):
        k = C.kanban({}, {"programs": {"shopco": [wo_view(1, 3, cls="idor", items={"H1": "MARKET"}),
                                                  wo_view(2, 3, cls="business-logic", items={"H1": "MARKET"})]}})
        desks, src = C.probe_desks(k)
        self.assertEqual(src, "PRECISION-LEDGER.json")
        self.assertEqual([d["label"] for d in desks], ["Biz Logic", "Improper Auth", "Refl XSS", "SSRF", "Other", "TRAP"])
        self.assertEqual(sum(1 for d in desks if d["trap"]), 1)      # at most ONE desk for the trap classes
        self.assertEqual(len(desks), C.WIP_CAP["PROBE"])
        trap = desks[-1]
        self.assertEqual(trap["items"], 1)
        self.assertFalse(trap["open"])                                # no seed naming a new root cause
        c = {"roster": [{"bot": b, "status": "idle", "wallet": 900} for b in ("worker", "lead", "hunter")]}
        st = C.staff(c, k, desks)
        self.assertEqual(sorted(v["desk"] for v in st.values()), ["probe:business-logic"])   # nobody at the trap desk
        self.wo_files[wo_view(1, 3)["id"]] = {"new_root_cause": "a second handler skips the tenant check entirely"}
        desks, _ = C.probe_desks(k)
        self.assertTrue(desks[-1]["open"])
        st = C.staff(c, k, desks)
        self.assertEqual(sorted(v["desk"] for v in st.values()), ["probe:business-logic", "probe:trap"])

    def test_standup_schema(self):
        self.write_line([wo_view(1, 0, age=9000), wo_view(2, 1, age=400), wo_view(3, 3, items={"H1": "MARKET"}, age=50),
                         wo_view(4, 0, age=7000)])
        c = {"roster": [{"bot": "worker", "status": "idle", "wallet": 900},
                        {"bot": "lead", "status": "idle", "wallet": 900},
                        {"bot": "hunter", "status": "idle", "wallet": 900},
                        {"bot": "brain", "status": "idle", "wallet": 900}]}
        C.floor(c, E.rows())
        su = c["standup"]
        for key in ("day", "open", "total_open", "pnl_yesterday", "bottleneck", "pull", "oldest", "hiring", "voice",
                    "voice_src"):
            self.assertIn(key, su, key)
        self.assertEqual(set(su["open"]), set(C.FLOW))
        self.assertEqual(su["total_open"], 4)
        self.assertEqual([o["age_s"] for o in su["oldest"]], [9000, 7000, 400])
        self.assertEqual(su["oldest"][0]["station"], "INTEL")
        self.assertEqual(set(su["pnl_yesterday"]), {"day", "minted", "burnt", "net"})
        self.assertEqual(su["bottleneck"], {"station": "INTEL", "n": 2, "cap": 3})
        self.assertEqual(su["voice_src"], "template")
        self.assertIn("bottleneck INTEL", su["voice"])
        hire = su["hiring"]
        self.assertEqual(hire["state"], "starved")
        self.assertIn("Improper Auth", hire["empty_desks"])
        self.assertNotIn("Biz Logic", hire["empty_desks"])            # its desk has the waiting hypothesis
        self.assertNotIn("Claude", hire["text"] + hire["plain"])          # a stand-alone GreyNOC build
        self.assertTrue(hire["plain"].startswith("HELP WANTED: desk empty: "), hire["plain"])
        self.assertIn("login bugs", hire["plain"])
        for key in ("kanban", "desks", "staffing"):
            self.assertIn(key, c)
        for d in c["desks"]:
            for key in ("desk", "label", "classes", "trap", "items", "open", "bot"):
                self.assertIn(key, d)
        # every desk busy and work waiting at SALES: the sign says so
        views = [wo_view(10 + i, 3, cls=cls, items={"H1": "MARKET"}) for i, cls in
                 enumerate(("business-logic", "unauth", "xss", "ssrf", "rce"))]
        self.write_line(views)
        c2 = {"roster": [], "bounties": [{"id": "B7", "poster": C.MANAGER}], "work_orders": {}}
        C.floor(c2, E.rows())
        self.assertEqual(c2["standup"]["hiring"]["state"], "queue")
        self.assertIn("wait at SALES", c2["standup"]["hiring"]["text"])

    def test_manage_writes_the_floor(self):
        self.program()
        C.manage({})
        c = jl(C.COMPANY)
        self.assertEqual(c["errors"], {}, c["errors"])
        self.assertEqual([r["name"] for r in c["kanban"]["stations"]], list(C.FLOW))
        self.assertEqual({r["name"]: r["cap"] for r in c["kanban"]["stations"] if r["cap"]}, C.WIP_CAP)
        self.assertIn("FLOOR    bottleneck", C.status_text())

class Screen(Base):
    """The plain-words office: names, stars, the story ticker (code-written, 20 rows), the four room boards."""

    def test_names_and_stars(self):
        self.assertEqual(C.name_of("lead"), "Rex")
        self.assertEqual(C.name_of("orch-bot"), "The Manager")
        self.assertEqual(C.name_of("oss-bot"), "Scanner Sam")
        self.assertEqual([C.stars(b) for b in (0.0, 0.25, 0.5, 1.0, None)], [5, 4, 2, 1, None])
        self.assertEqual(C.plain("business-logic: coupon reuse"), "logic bugs")
        self.assertEqual(C.plain("unauth"), "login bugs")

    def test_story_from_real_events_only(self):
        self.program()
        c = {}
        C.payroll(c, E.rows(), [])
        C.story(c, E.rows(), [])                      # first run: cursors only, no flood of old news
        self.assertEqual(C._story_rows(), [])
        E.bounty("post", program="shopco", crown="unauth: reset reuse", amount=300, poster=C.MANAGER, settler=self.tok)
        E.post("shopco", "H1", "worker", 10)
        E.bet("shopco", "H1", "phone-4b", "short", 10)
        E.mint("oracle-pass", "worker", 50, "oracle:shopco:H1:o1", "oracle-pass prover", settler=self.tok)
        C.journal("lane-queued", program="shopco", lane="company-worker-b1-x", bot="worker", bounty="B1")
        E._append([("burn", "phone-1.7b", "burn", 950, "probe:shopco", "probe")])
        C.payroll(c, E.rows(), [])
        added = C.story(c, E.rows(), [{"ts": C._now(), "lane": "x", "target": "shopco", "verdict": "LEAD"}] * 0)
        texts = [r["text"] for r in added]
        self.assertIn("The Manager posted a 300 coin reward on shopco", texts)
        self.assertIn("Q has an idea on shopco (bet 10 coins)", texts)
        self.assertIn("Pip doubts Q's idea on shopco (bet 10 coins)", texts)
        self.assertIn("Q's proof PASSED on shopco, +50 coins", texts)
        self.assertIn("Pico went broke", texts)
        self.assertTrue(any(t.startswith("The Manager sent Q to hunt") for t in texts), texts)
        self.assertFalse(any("probe" in t or "RC" in t for t in texts))   # spend is not a story; no jargon
        proved = next(r for r in added if r["kind"] == "proved")
        self.assertEqual(proved["bot"], "worker")
        self.assertEqual(C.story(c, E.rows(), []), [])                    # nothing new, nothing added
        for i in range(30):
            C.journal("work-order", program=f"p{i}", ok=True, bounty="B1", wo_id="x")
            C.story(c, E.rows(), [])
        rows = C._story_rows()
        self.assertEqual(len(rows), C.STORY_KEEP)                         # a 20-line history
        self.assertEqual(rows[-1]["text"], "New job at the front desk: p29")

    def test_screen_boards(self):
        self.program()
        self.touch(C.STATUS_MD, "## 2. Ready for QA\n| hackerone | shopco | `coupon-reuse-twice` | x |\n## 3. x\n")
        self.touch(C.LINE_JSON, json.dumps({"programs": {"shopco": [
            {"id": "202610230100-abcd", "station": 3, "class": "business-logic", "age_s": 60, "items": {"H1": "MARKET"}}]}}))
        C.manage({})
        c = jl(C.COMPANY)
        sc = c["screen"]
        self.assertEqual(set(sc["boards"]), {"FRONT DESK", "THE FLOOR", "THE LAB", "THE PRESS"})
        self.assertEqual([sc["boards"][r]["title"] for r in ("FRONT DESK", "THE FLOOR", "THE LAB")],
                         ["JOBS", "SCORE (coins today)", "PROOFS"])
        self.assertEqual(sc["boards"]["FRONT DESK"]["lines"][0], "shopco logic bugs open")
        self.assertEqual(sc["boards"]["THE PRESS"]["reports"], [{"program": "shopco", "title": "coupon reuse twice"}])
        for room, b in sc["boards"].items():
            self.assertLessEqual(len(b.get("lines") or b.get("reports") or []), 6, room)
        self.assertEqual(len(sc["today"]), 3)
        self.assertEqual(sc["jam"], "THE FLOOR")                          # one job waits at the PROBE floor
        self.assertEqual(sc["bots"]["lead"]["name"], "Rex")
        self.assertEqual(sc["legend"], "(c) coins   **** aim   JAM = room backed up   zz = broke")
        self.assertNotIn("hunter", sc["bots"])                            # an alias is drawn once, as its owner
        self.assertNotIn("brain", sc["bots"])
        self.assertFalse(any(b.startswith("claude-") for b in sc["bots"]))
        self.assertEqual(C.aliases(), {"hunter": "worker", "brain": "lead", "chat": "worker"})
        self.assertEqual(C.name_of("hunter"), "Q")
        self.assertEqual(C.name_of("brain"), "Rex")
        words = json.dumps(sc).lower()
        for jargon in ("brier", "oracle", "wip", "bottleneck", "settler", "lineage", "futures", "station", " rc"):
            self.assertNotIn(jargon, words, jargon)

class BrainFallback(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-brain-")
        self.saved = (llm_endpoints.ROLES, llm_endpoints.up, orch_brain.JOURNAL, orch_brain._post_chat,
                      orch_brain.URL, orch_brain.MODEL)
        llm_endpoints.ROLES = os.path.join(self.tmp, "models.json")
        with open(llm_endpoints.ROLES, "w") as f:
            json.dump({"brain": "q4b-abliterated@phone", "brain_fallback": "q9b-abliterated"}, f)
        llm_endpoints.up = lambda h: False          # no network: the phone reads as down to resolve()
        orch_brain.JOURNAL = os.path.join(self.tmp, "brain.jsonl")
        orch_brain.URL = orch_brain.MODEL = ""
        # the brain is on the PHONE in these tests: give the phone a host (a fresh install has none; the operator's
        # machine.json sets GNOC_PHONE_OLLAMA). Port 11441 is what fake() routes on.
        self.hosts = mock.patch.dict(llm_endpoints.HOSTS, {"phone": "phone.invalid:11441"})
        self.hosts.start()
        self.addCleanup(self.hosts.stop)
        self.bodies = []

    def tearDown(self):
        (llm_endpoints.ROLES, llm_endpoints.up, orch_brain.JOURNAL, orch_brain._post_chat,
         orch_brain.URL, orch_brain.MODEL) = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake(self, phone_behaviour):
        def post(url, body, timeout):
            self.bodies.append((url, body, timeout))
            if ":11441/" in url:
                return phone_behaviour()
            return '{"reason": "queue is empty", "action": "wait", "minutes": 5, "text": "Keep the floor honest."}'
        orch_brain._post_chat = post

    def journal(self):
        return [json.loads(ln) for ln in rd(orch_brain.JOURNAL).splitlines()]

    def test_targets_phone_first(self):
        t = orch_brain._targets()
        self.assertEqual([x[2] for x in t[:2]], ["phone", "local"])
        self.assertIn(":11441/", t[0][0])

    def test_refused_connection_falls_back_to_local(self):
        def refused():
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        self.fake(refused)
        d = orch_brain.ask("snapshot")
        self.assertEqual(d["action"], "wait")
        self.assertEqual(orch_brain.LAST_CALL["host"], "local")
        self.assertEqual(orch_brain.LAST_CALL["model"], "q9b-abliterated")
        self.assertIn("connection refused", orch_brain.LAST_CALL["fallback"])
        phone_body = self.bodies[0][1]
        self.assertIs(phone_body["think"], False)                   # the phone MUST get think:false
        self.assertEqual(self.bodies[0][2], orch_brain.PHONE_TIMEOUT)
        j = self.journal()
        self.assertEqual(j[-1]["action"], "brain-fallback")
        self.assertIn("brain fallback: phone connection refused", j[-1]["detail"])

    def test_empty_and_timeout_fall_back(self):
        self.fake(lambda: "")
        orch_brain.ask("snapshot")
        self.assertIn("empty reply", self.journal()[-1]["detail"])

        def slow():
            raise TimeoutError("timed out")
        self.fake(slow)
        orch_brain.ask("snapshot")
        self.assertIn("timeout", self.journal()[-1]["detail"])

    def test_phone_answers(self):
        self.fake(lambda: '{"reason": "r", "action": "wait"}')
        orch_brain.ask("snapshot")
        self.assertEqual(orch_brain.LAST_CALL["host"], "phone")
        self.assertIsNone(orch_brain.LAST_CALL["fallback"])
        self.assertFalse(os.path.exists(orch_brain.JOURNAL))

    def test_voice_goes_through_the_same_chain(self):
        def refused():
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        self.fake(refused)
        text, model, host = orch_brain.voice("facts", "say hi", 1)
        self.assertEqual(host, "local")
        self.assertEqual(self.bodies[-1][1]["format"], orch_brain.VOICE_SCHEMA)
        self.assertEqual(text, "Keep the floor honest.")


class Tick(unittest.TestCase):
    """A raising company step never breaks orch-bot's tick, and PAUSE skips everything but the save."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-tick-")
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "orch-bot.py")
        spec = importlib.util.spec_from_file_location("orch_bot_under_test", path)
        self.m = importlib.util.module_from_spec(spec)
        # orch-bot's retirement guard (2026-11-02) calls sys.exit(78) at IMPORT, so the module could not
        # be imported to unit-test Tick and this suite went red (2 errors, QAQC 2026-11-04). The guard
        # exists to stop the bot RUNNING; this test never runs it. Set the deliberate override for the
        # duration of the import only, then put the environment back exactly as it was.
        saved = os.environ.get("GNOC_ORCH_BOT_UNRETIRE")
        os.environ["GNOC_ORCH_BOT_UNRETIRE"] = "1"
        try:
            spec.loader.exec_module(self.m)
        finally:
            if saved is None:
                os.environ.pop("GNOC_ORCH_BOT_UNRETIRE", None)
            else:
                os.environ["GNOC_ORCH_BOT_UNRETIRE"] = saved
        m = self.m
        m.ORCH = self.tmp
        m.STATEF = os.path.join(self.tmp, "state.json")
        m.LOG = os.path.join(self.tmp, "orch.log")
        m.ECON_PAUSE = os.path.join(self.tmp, "PAUSE")
        self.calls = []
        m.health = lambda st: self.calls.append("health") or False
        for name in ("drafts", "h1", "autosubmit", "oss_leads"):
            setattr(m, name, (lambda n: lambda st: self.calls.append(n))(name))
        self.saved_mod = sys.modules.get("gnoc_company")
        fake = types.ModuleType("gnoc_company")

        def boom(st):
            self.calls.append("company")
            raise RuntimeError("company exploded")
        fake.manage = boom
        sys.modules["gnoc_company"] = fake

    def tearDown(self):
        if self.saved_mod is not None:
            sys.modules["gnoc_company"] = self.saved_mod
        else:
            sys.modules.pop("gnoc_company", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_raising_company_step_still_saves_state(self):
        self.m.tick()
        st = jl(self.m.STATEF)
        self.assertIn("heartbeat", st)
        self.assertIn("company", self.calls)
        self.assertIn("oss_leads", self.calls)
        self.assertIn("company error", rd(self.m.LOG))

    def test_pause_skips_every_duty(self):
        open(self.m.ECON_PAUSE, "w").close()
        self.m.tick()
        st = jl(self.m.STATEF)
        self.assertTrue(st["company_paused"])
        self.assertEqual([c for c in self.calls if c != "company"], [])


if __name__ == "__main__":
    t0 = time.time()
    unittest.main(verbosity=1)
