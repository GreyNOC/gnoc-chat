#!/usr/bin/env python3
"""Tests for gnoc_economy (the proof market). Stdlib unittest, temp state dirs, no network, no model calls.

    python3 -W error::ResourceWarning scripts/test_gnoc_economy.py [-v]

The REGRESSION section folds in every forgery from the 2026-10-22 adversarial review (rv_attack econ_atk.py /
hook_atk.py, cases 3c-3m and 4e): each must now be refused.
"""
import contextvars
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_economy as E  # noqa: E402
import gnoc_hunt as GH  # noqa: E402
import gnoc_oracle as O  # noqa: E402

ATTRS = ("STATE", "LEDGER", "LINEAGE", "SETTLER", "CHAINKEY", "MODELS_JSON", "FEEDBACK_OUT", "WS", "REQUIRE_TARGET")


class Econ(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-econ-")
        self.saved = {k: getattr(E, k) for k in ATTRS}
        self.saved_o = (O.WS, O.ORACLE_DIR, O.SEAL, dict(O._SECRET_CACHE))
        self.saved_h = GH.WS
        E.WS = self.tmp
        E.STATE = os.path.join(self.tmp, "economy")
        E.LEDGER = os.path.join(E.STATE, "ledger.jsonl")
        E.LINEAGE = os.path.join(E.STATE, "lineage.jsonl")
        E.SETTLER = os.path.join(E.STATE, ".settler")
        E.CHAINKEY = None
        E.MODELS_JSON = os.path.join(self.tmp, "models.json")
        E.FEEDBACK_OUT = os.path.join(self.tmp, "out")
        E.REQUIRE_TARGET = False
        E._ROW_CACHE.clear()
        O.WS = self.tmp
        O.ORACLE_DIR = os.path.join(self.tmp, "oracles")
        O.SEAL = os.path.join(O.ORACLE_DIR, ".seal")
        O._SECRET_CACHE.clear()
        GH.WS = self.tmp
        with open(E.MODELS_JSON, "w") as f:
            json.dump({"lead": "x", "hunter": "y", "chat": "z"}, f)
        E.ensure()
        self.tok = E._settler()

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(E, k, v)
        O.WS, O.ORACLE_DIR, O.SEAL = self.saved_o[:3]
        O._SECRET_CACHE.clear()
        O._SECRET_CACHE.update(self.saved_o[3])
        GH.WS = self.saved_h
        E._ROW_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers: non-AI state the economy re-reads
    def hyp(self, hid, probes=0, bursts=0, status="probing", program="p"):
        d = GH.load(program)
        d.setdefault("hypotheses", [])
        d["hypotheses"] = [h for h in d["hypotheses"] if h.get("id") != hid]
        d["hypotheses"].append({"id": hid, "title": hid, "status": status, "probes": probes, "bursts": bursts,
                                "burst": bursts > 0, "evidence": []})
        GH.save(program, d)

    def oracle_pass(self, hid, kind="cross-user-read", program="p", status="passed"):
        """A commit plus a verdict row written through gnoc_oracle's own signed append (what verify writes)."""
        oid = "o-" + hashlib.sha256(f"{hid}{kind}{time.time()}".encode()).hexdigest()[:8]
        O._append(program, {"ts": O._now(), "id": oid, "program": program, "hyp_id": hid, "kind": kind,
                            "sha256": "0" * 64, "status": "open"})
        O._append(program, {"ts": O._now(), "id": oid, "event": "verdict", "cls": kind, "status": status, "why": "t"})
        return oid

    # ---- genesis, key and chain
    def test_genesis_balances_and_key_mode(self):
        b = E.balances()
        for n in E.ROSTER + ("hunter", "chat"):
            self.assertEqual(b[n], 1000, n)
        self.assertEqual(b["treasury"], 100000)
        self.assertEqual(oct(os.stat(E._key_path()).st_mode & 0o777), "0o600")
        ok, n, _ = E.verify_chain()
        self.assertTrue(ok)
        self.assertEqual(n, len(E.ROSTER) + 3)
        self.assertTrue(all("sig" in r for r in E.rows()))

    def test_chain_tamper_detected_and_reads_refuse(self):
        E.debit_probe("p", "worker")
        with open(E.LEDGER, "rb") as f:
            data = bytearray(f.read())
        i = data.index(b'"amount":1000')
        data[i + 9] = ord("2")   # 1000 -> 2000 on one genesis row: a single edited byte
        with open(E.LEDGER, "wb") as f:
            f.write(bytes(data))
        ok, _, why = E.verify_chain()
        self.assertFalse(ok, why)
        self.assertIn("BROKEN", E.status_text())
        with self.assertRaises(E.EconomyBroken):
            E.balances()

    def test_conservation_audit(self):
        E.on_event("hyp-add", program="p", hyp_id="H1", bot="lead")
        E.debit_probe("p", "worker", 3)
        self.assertIn("conservation OK", E.audit_text())

    # ---- REGRESSION 3k/3l: a hand-appended row is rejected, not credited
    def _hand_append(self, row):
        with open(E.LEDGER, "rb") as f:
            last = f.read().splitlines()[-1]
        row = dict({"ts": "2026-10-23T00:00:00Z", "seq": json.loads(last)["seq"] + 1,
                    "prev": hashlib.sha256(last).hexdigest()}, **row)
        with open(E.LEDGER, "ab") as f:
            f.write(json.dumps(row, separators=(",", ":")).encode() + b"\n")

    def test_regression_3k_forged_chained_row_without_sig(self):
        self._hand_append({"kind": "mint", "from": "mint", "to": "phone-1.7b", "amount": 50000, "ref": "forged",
                           "memo": "forged"})
        ok, _, why = E.verify_chain()
        self.assertFalse(ok)
        self.assertIn("no HMAC sig", why)
        with self.assertRaises(E.EconomyBroken):
            E.balance("phone-1.7b")
        self.assertIn("BROKEN", E.audit_text())
        out = E.on_event("probe", program="p", hyp_id="H1", lane="worker")
        self.assertIn("disabled", out)
        with open(os.path.join(E.STATE, "econ.log")) as f:
            self.assertIn("DISABLED", f.read())

    def test_regression_3k_forged_sig_with_a_guessed_key(self):
        import hmac
        row = {"kind": "mint", "from": "mint", "to": "phone-4b", "amount": 7777, "ref": "", "memo": ""}
        with open(E.LEDGER, "rb") as f:
            last = f.read().splitlines()[-1]
        row.update(ts="2026-10-23T00:00:00Z", seq=json.loads(last)["seq"] + 1, prev=hashlib.sha256(last).hexdigest())
        row["sig"] = E._sig(row, b"0" * 64)
        with open(E.LEDGER, "ab") as f:
            f.write(json.dumps(row, separators=(",", ":")).encode() + b"\n")
        self.assertIsNotNone(hmac)
        self.assertIn("bad HMAC sig", E.verify_chain()[2])
        with self.assertRaises(E.EconomyBroken):
            E.balances()

    def test_regression_3l_unchained_row(self):
        with open(E.LEDGER, "ab") as f:
            f.write(json.dumps({"seq": 0, "prev": "x", "kind": "mint", "from": "mint", "to": "phone-4b",
                                "amount": 7777, "ref": "", "memo": ""}).encode() + b"\n")
        self.assertFalse(E.verify_chain()[0])
        with self.assertRaises(E.EconomyBroken):
            E.balance("phone-4b")

    def test_missing_key_under_a_ledger_is_broken_not_a_fresh_key(self):
        os.remove(E._key_path())
        E._KEY_CACHE.clear()
        E._ROW_CACHE.clear()
        self.assertFalse(E.verify_chain()[0])
        with self.assertRaises(E.EconomyBroken):
            E.rows()
        self.assertFalse(os.path.exists(E._key_path()))

    def test_regression_3m_planted_settler_file_is_ignored(self):
        with open(E.SETTLER, "w") as f:
            f.write("known")
        with self.assertRaises(PermissionError):
            E.mint("x", "worker", 1, "r2", settler="known")

    def test_migrate_resigns_unsigned_genesis_once(self):
        # build a pre-HMAC ledger: genesis rows chained by sha256 only
        os.remove(E.LEDGER)
        os.remove(E._key_path())
        E._KEY_CACHE.clear()
        E._ROW_CACHE.clear()
        prev, lines = E.ZERO, []
        for i, (kind, frm, to, amt, ref, memo) in enumerate(E._genesis_rows()):
            r = {"ts": "2026-10-22T20:44:00Z", "seq": i, "prev": prev, "kind": kind, "from": frm, "to": to,
                 "amount": amt, "ref": ref, "memo": memo}
            line = json.dumps(r, separators=(",", ":")).encode()
            lines.append(line)
            prev = hashlib.sha256(line).hexdigest()
        with open(E.LEDGER, "wb") as f:
            f.write(b"\n".join(lines) + b"\n")
        self.assertFalse(E.verify_chain()[0])
        out = E.migrate()
        self.assertIn("chain OK", out)
        self.assertTrue(os.path.exists(E.LEDGER + ".pre-hmac"))
        self.assertTrue(E.verify_chain()[0])
        self.assertEqual(E.balance("treasury"), 100000)
        self.assertIn("already signed", E.migrate())

    def test_migrate_refuses_a_non_genesis_unsigned_row(self):
        os.remove(E._key_path())
        E._KEY_CACHE.clear()
        with open(E.LEDGER, "wb") as f:
            line = json.dumps({"ts": "t", "seq": 0, "prev": E.ZERO, "kind": "mint", "from": "mint", "to": "lead",
                               "amount": 5, "ref": "", "memo": ""}, separators=(",", ":")).encode()
            f.write(line + b"\n")
        self.assertIn("REFUSED", E.migrate())

    # ---- minting only through adjudicated, re-read events
    def test_mint_needs_settler(self):
        with self.assertRaises(PermissionError):
            E.mint("x", "worker", 50, "r")
        with self.assertRaises(PermissionError):
            E.mint("x", "worker", 50, "r", settler="guess")
        with self.assertRaises(PermissionError):
            E.resolve("p", "H1", "proven")

    def test_regression_3c_oracle_pass_with_no_signed_verdict_mints_nothing(self):
        before = E.balance("worker")
        E.on_event("oracle-pass", program="p", hyp_id="H1", lane="worker", ref="fake-1")
        E.on_event("oracle-pass", program="p", hyp_id="H1", lane="worker", ref="fake-2")
        self.assertEqual(E.balance("worker"), before)
        # a hand-appended UNSIGNED verdict row on a real commit is not a pass either
        self.hyp("H1")
        oid = self.oracle_pass("H1", status="failed")
        with open(O._path("p"), "a") as f:
            f.write(json.dumps({"id": oid, "event": "verdict", "status": "passed", "why": "x"}) + "\n")
        E.on_event("oracle-pass", program="p", ref=oid, lane="worker")
        self.assertEqual(E.balance("worker"), before)

    def test_signed_oracle_pass_pays_author_resolves_proven_once(self):
        self.hyp("H1")
        E.on_event("hyp-add", program="p", hyp_id="H1", bot="lead")
        E.on_event("probe", program="p", hyp_id="H1", bot="phone-4b")   # prober lineage + 30 bond
        oid = self.oracle_pass("H1")
        E.on_event("oracle-pass", program="p", hyp_id="IGNORED", lane="worker", ref=oid)
        self.assertEqual(E.balance("lead"), 1000 + 25)
        self.assertEqual(E.balance("phone-4b"), 1050)   # bond refunded, +50 prover
        self.assertEqual(E.market("mkt:p:H1")["closed"], "proven")
        E.on_event("oracle-pass", program="p", lane="worker", ref=oid)   # once per oracle id
        self.assertEqual(E.balance("phone-4b"), 1050)

    def test_regression_3d_self_typed_floor_dead_mints_nothing(self):
        b0 = E.balance("worker")
        for i in range(5):
            E.on_event("outcome", row={"target": "p", "verdict": "DEAD", "floor": "met", "probes": 8, "burst": True,
                                       "lane": "worker", "notes": str(i)})
        self.assertEqual(E.balance("worker"), b0)
        self.hyp("H5", probes=9, bursts=0)   # recomputed: no burst in gnoc_hunt state
        E.on_event("outcome", row={"target": "p", "hypothesis": "H5", "verdict": "DEAD", "floor": "met",
                                   "probes": 99, "burst": True, "lane": "worker"})
        self.assertEqual(E.balance("worker"), b0)

    def test_floor_met_dead_recomputed_mints_5_once_per_hypothesis(self):
        self.hyp("H6", probes=9, bursts=1)
        E.on_event("burst", program="p", hyp_id="H6", bot="worker", n=2)   # the signed burst row (race hook)
        b0 = E.balance("worker")
        for i in range(3):
            E.on_event("outcome", row={"target": "p", "hypothesis": "H6", "verdict": "DEAD", "lane": "worker",
                                       "probes": 1, "burst": False, "floor": "not-met", "notes": str(i)})
        self.assertEqual(E.balance("worker"), b0 + 5)

    def test_floorless_dead_refused_slashes_20(self):
        row = {"verdict": "DEAD", "target": "p", "lane": "worker", "probes": 2, "floor": "not-met", "ts": "t2"}
        E.on_event("outcome", row=row, refused=True)
        self.assertEqual(E.balance("worker"), 980)

    def test_regression_3e_candidate_resolves_lead_never_proven(self):
        E.post("p", "H9", "lead", 10)
        E.bet("p", "H9", "worker", "short", 100)
        E.on_event("outcome", row={"target": "p", "hypothesis": "H9", "verdict": "MEDIUM-CANDIDATE", "probes": 1,
                                   "lane": "lead"})
        self.assertEqual(E.market("mkt:p:H9")["closed"], "unfired")   # 0 probes in gnoc_hunt: refunds only
        self.assertEqual(E.balance("lead"), 1000)
        E.post("p", "H10", "lead", 10)
        self.hyp("H10", probes=3)
        E.on_event("outcome", row={"target": "p", "hypothesis": "H10", "verdict": "CRITICAL-CANDIDATE",
                                   "lane": "lead"})
        self.assertEqual(E.market("mkt:p:H10")["closed"], "lead")

    def test_regression_3f_typed_ready_ship_row_mints_nothing(self):
        b0 = sum(E.balances().get(k, 0) for k in ("lead", "worker"))
        E.on_event("ship", row={"program": "p", "kind": "draft", "status": "READY",
                                "path": "reports/drafts/p/slug1/report.md"})
        self.assertEqual(sum(E.balances().get(k, 0) for k in ("lead", "worker")), b0)
        self.assertIn("PermissionError", E.on_event("ready", program="p", slug="slug1"))
        self.assertEqual(sum(E.balances().get(k, 0) for k in ("lead", "worker")), b0)

    def test_ready_hook_mints_once_and_refuses_held(self):
        d = os.path.join(self.tmp, "reports", "drafts", "p", "s1")
        os.makedirs(d)
        E._lin_append({"program": "p", "slug": "s1", "writer": "lead", "author": "worker"})
        self.assertIn("no draft", E.ready_hook("p", "s1"))
        open(os.path.join(d, "report.md"), "w").close()
        self.assertIn("minted ready", E.ready_hook("p", "s1"))
        self.assertEqual((E.balance("lead"), E.balance("worker")), (1010, 1030))
        E.ready_hook("p", "s1")
        self.assertEqual(E.balance("lead"), 1010)
        d2 = os.path.join(self.tmp, "reports", "drafts", "p", "s2")
        os.makedirs(d2)
        open(os.path.join(d2, "report.md"), "w").close()
        open(os.path.join(d2, "HELD-REASON.md"), "w").close()
        self.assertIn("HELD", E.ready_hook("p", "s2"))

    def test_hand_written_lineage_row_is_ignored(self):
        with open(E.LINEAGE, "a") as f:
            f.write(json.dumps({"program": "p", "hyp_id": "H1", "prober": "phone-1.7b"}) + "\n")
        self.assertNotIn("prober", E.lineage("p", "H1"))

    def test_unknown_bot_cannot_bet_or_be_minted(self):
        E.on_event("hyp-add", program="p", hyp_id="H1", bot="lead")
        self.assertIn("unknown bot", E.bet("p", "H1", "evil-bot", "long", 5))
        E._lin_append({"program": "p", "slug": "s", "author": "evil-bot", "writer": "lead"})
        E.on_event("ready", program="p", slug="s", settler=self.tok)
        self.assertNotIn("evil-bot", E.balances())

    # ---- REGRESSION 3g/3h: bounties
    def test_regression_3g_chat_bounty_is_poster_funded_and_settles_only_on_the_claimers_pass(self):
        self.assertIn("not a wallet", E.bounty("post", program="p", crown="cross-user-read", amount=1000,
                                               poster="orchestrator"))
        self.assertIn("posted", E.bounty("post", program="p", crown="cross-user-read", amount=100, poster="lead"))
        self.assertEqual(E.balance("lead"), 900)
        self.assertIn("cannot claim", E.bounty("claim", id="B1", bot="lead"))
        self.assertIn("claimed", E.bounty("claim", id="B1", bot="worker"))
        with self.assertRaises(PermissionError):
            E.bounty("settle", id="B1", oracle_id="x")
        # unrelated pass: other crown
        self.hyp("Hrce")
        E._lin_append({"program": "p", "hyp_id": "Hrce", "prober": "worker"})
        o1 = self.oracle_pass("Hrce", kind="rce")
        E.on_event("oracle-pass", program="p", ref=o1)
        self.assertEqual(E.bounties()["bty:B1"]["state"], "claimed")
        # right crown, but the prober is not the claimer
        self.hyp("Hx")
        E._lin_append({"program": "p", "hyp_id": "Hx", "prober": "phone-4b"})
        o2 = self.oracle_pass("Hx")
        self.assertIn("not the claimer", E.bounty("settle", id="B1", settler=self.tok, oracle_id=o2))
        # the claimer's own pass on the bounty crown settles it, once
        self.hyp("Hw")
        E._lin_append({"program": "p", "hyp_id": "Hw", "prober": "worker"})
        o3 = self.oracle_pass("Hw")
        w0 = E.balance("worker")
        E.on_event("oracle-pass", program="p", ref=o3)
        self.assertEqual(E.bounties()["bty:B1"]["state"], "settled")
        self.assertEqual(E.balance("worker"), w0 + 50 + 100 + 30)
        self.assertIn("refused", E.bounty("settle", id="B1", settler=self.tok, oracle_id=o3))
        self.assertIn("refused", E.bounty("claim", id="B1", bot="phone-4b"))   # 3h

    def test_treasury_funded_bounty_needs_settler(self):
        self.assertIn("not a wallet", E.bounty("post", program="p", crown="rce", amount=10, poster="greynoc"))
        t0 = E.balance("treasury")
        self.assertIn("from treasury", E.bounty("post", program="p", crown="rce", amount=10, poster="greynoc",
                                                settler=self.tok))
        self.assertEqual(E.balance("treasury"), t0 - 10)

    def test_bounty_expiry_and_abandon(self):
        E.bounty("post", program="p", crown="rce", amount=200, poster="lead")
        E.bounty("claim", id="B1", bot="worker")
        E.sweep_expired(now=time.time() + E.BOUNTY_ABANDON + 5)   # no probe by the claimer for 2h
        b = E.bounties()["bty:B1"]
        self.assertEqual((b["state"], b["claimant"]), ("open", None))
        self.assertEqual(E.balance("worker"), 970)
        E.sweep_expired(now=time.time() + E.BOUNTY_TTL + 5)
        self.assertEqual(E.bounties()["bty:B1"]["state"], "expired")
        self.assertEqual(E.balance("lead"), 1000)   # escrow back to the poster's wallet

    def test_active_claimer_keeps_the_bond(self):
        E.bounty("post", program="p", crown="rce", amount=50, poster="lead")
        E.bounty("claim", id="B1", bot="worker")
        E.debit_probe("p", "worker")
        E.sweep_expired(now=time.time() + 60)
        self.assertEqual(E.bounties()["bty:B1"]["state"], "claimed")

    # ---- REGRESSION 4e: a held lock never blocks a hook
    def test_regression_4e_hook_returns_within_lock_timeout(self):
        holder = subprocess.Popen([sys.executable, "-c", "import fcntl,sys,time; f=open(sys.argv[1],'a'); "
                                   "fcntl.flock(f, fcntl.LOCK_EX); print('held', flush=True); time.sleep(6)",
                                   E.LEDGER], stdout=subprocess.PIPE, text=True)
        try:
            holder.stdout.readline()
            t0 = time.time()
            out = E.on_event("burst", program="p", hyp_id="H1", n=1, bot="worker")
            took = time.time() - t0
            self.assertLess(took, E.LOCK_TIMEOUT + 1.5)
            self.assertIn("skipped", out)
        finally:
            holder.kill()
            holder.wait()
            holder.stdout.close()
        with open(os.path.join(E.STATE, "econ.log")) as f:
            self.assertIn("flock held elsewhere", f.read())

    def test_on_event_never_raises(self):
        os.chmod(E.STATE, 0o500)
        try:
            out = E.on_event("probe", program="p", hyp_id="H9", lane="worker")
        finally:
            os.chmod(E.STATE, 0o700)
        self.assertTrue(out is None or isinstance(out, str))
        self.assertIn("unknown event", E.on_event("nope"))

    # ---- owed: budget, bots, llm
    def test_budget_refusal(self):
        E.on_event("hyp-add", program="p", hyp_id="H4", bot="lead")
        self.assertEqual(E.budget("p", "H4"), 20)
        self.hyp("H4", probes=19)
        self.assertIsNone(E.budget_refusal("p", "H4"))
        self.hyp("H4", probes=20)
        self.assertIn("budget exhausted for H4: bet more or pivot", E.budget_refusal("p", "H4"))
        E.bet("p", "H4", "worker", "long", 30)
        self.assertIsNone(E.budget_refusal("p", "H4"))
        self.assertTrue(issubclass(E.BudgetExhausted, PermissionError))

    def test_a_broke_bot_gets_a_treasury_stipend_and_a_missing_market_self_heals(self):
        E.on_event("hyp-add", program="p", hyp_id="H4", bot="lead")
        self.assertEqual(E.budget("p", "H4"), 20)
        # drain the lead to 0 the way the LLM burns did on 2026-10-23
        E._append([("burn", "lead", "burn", E.balance("lead"), "llm", "drain")])
        self.assertEqual(E.balance("lead"), 0)
        self.hyp("H5", probes=0)                                             # a hypothesis whose post was refused
        self.assertEqual(E.market(E._mref("p", "H5"))["stakes"], [])
        out = E.bet("p", "H5", "lead", "long", 10)                           # self-heal: stipend + post as author
        self.assertTrue(out.startswith("posted"), out)
        self.assertEqual(E.balance("lead"), E.STIPEND - 10)
        self.assertEqual(E.market(E._mref("p", "H5"))["long"], 10)
        self.assertIn("no such hypothesis", E.bet("p", "H9", "lead", "long", 10))
        self.hyp("H4", probes=20)
        self.assertIn("econ_bet program=p id=H4 side=long stake=10", E.budget_refusal("p", "H4"))
        # the stipend is capped per day; past the cap a 0-RC bot is told the truth
        E._append([("burn", "lead", "burn", E.balance("lead"), "llm", "drain")])
        for _ in range(E.STIPEND_PER_DAY):
            E._append([("refund", E.TREASURY, "lead", E.STIPEND, f"stipend:lead:{E._now()[:10]}", "stipend")])
            E._append([("burn", "lead", "burn", E.STIPEND, "llm", "drain")])
        self.assertIsNone(E.stipend("lead"))
        self.assertIn("holds 0 RC", E.budget_refusal("p", "H4"))
        self.assertIn("pivot to the next open hypothesis", E.budget_refusal("p", "H4"))

    def test_budget_bounds(self):
        E.on_event("hyp-add", program="p", hyp_id="H4", bot="lead")
        E.bet("p", "H4", "worker", "long", 500)
        self.assertEqual(E.budget("p", "H4"), 200)

    def test_bot_for_model_and_acting_as_crosses_copied_context(self):
        self.assertEqual(E.bot_for_model("claude-opus-4", "claude"), "worker")  # standalone build: cloud names book as worker
        self.assertEqual(E.bot_for_model("hf.co/x/Qwen3-1.7B-abliterated", "phone"), "phone-1.7b")
        self.assertEqual(E.bot_for_model("hf.co/x/Qwen3-4B-abliterated", "phone"), "phone-4b")
        self.assertEqual(E.bot_for_model("huihui-qwen3.5-9b", "desktop"), "lead")
        self.assertEqual(E.bot_for_model("huihui-qwen3.5-9b", "local"), "worker")
        got = []
        with E.acting_as("phone-4b"):
            ctx = contextvars.copy_context()
        t = threading.Thread(target=lambda: got.append(ctx.run(E.current_bot)))
        t.start()
        t.join()
        self.assertEqual(got, ["phone-4b"])
        self.assertEqual(E.current_bot(), os.environ.get("GNOC_ECON_BOT") or "worker")

    def test_llm_rates(self):
        self.assertEqual(E.llm_rate("qwen3-1.7b-abliterated"), 1)
        self.assertEqual(E.llm_rate("Huihui-Qwen3.5-9B"), 2)
        self.assertEqual(E.llm_rate("claude-opus"), 30)  # a rate tier for a model name, not a roster bot
        E.debit_llm("lead", "Huihui-Qwen3.5-9B", 25000)
        self.assertEqual(E.balance("lead"), 994)
        self.assertIsNone(E.debit_llm("nobody", "x", 5000))

    # ---- line-advance (gnoc_line)
    def test_line_advance_logs_lineage_and_charges_nothing(self):
        b0 = E.balances()
        out = E.on_event("line-advance", program="p", wo="WO-1", station=2, ok=True, bot="phone-4b",
                         artifact="targets/p/line/TM-WO-1.md")
        self.assertEqual(out, "line-advance: logged")
        self.assertEqual(E.balances(), b0)
        rows = E._lin_rows()
        self.assertTrue(any(r.get("wo") == "WO-1" and r.get("station") == 2 and r.get("bot") == "phone-4b"
                            for r in rows))
        self.assertIn("unknown event", E.on_event("line-nope", program="p"))

    def test_line_advance_probe_station_mints_5_only_at_a_recomputed_floor(self):
        wo_dir = os.path.join(self.tmp, "targets", "p", "line")
        os.makedirs(wo_dir)
        import gnoc_line
        saved = gnoc_line.load_wo
        gnoc_line.load_wo = lambda program, wo_id: {"id": wo_id, "history": [
            {"station": 4, "ok": True, "hyp_id": "H7"}]}
        try:
            self.hyp("H7", probes=3, bursts=0)
            b0 = E.balance("worker")
            out = E.on_event("line-advance", program="p", wo="WO-2", station=4, ok=True, bot="worker")
            self.assertIn("no mint", out)
            self.assertEqual(E.balance("worker"), b0)
            self.hyp("H7", probes=9, bursts=1)
            E.on_event("burst", program="p", hyp_id="H7", bot="worker", n=1)
            b0 = E.balance("worker")
            self.assertIn("minted 5", E.on_event("line-advance", program="p", wo="WO-2", station=4, ok=True,
                                                 bot="worker"))
            E.on_event("line-advance", program="p", wo="WO-2", station=4, ok=True, bot="worker")
            E.on_event("line-advance", program="p", wo="WO-3", station=4, ok=True, bot="worker")   # same hyp
            self.assertEqual(E.balance("worker"), b0 + 5)
        finally:
            gnoc_line.load_wo = saved

    # ---- the market
    def test_market_long_wins_pro_rata_with_house(self):
        E.on_event("hyp-add", program="p", hyp_id="H1", bot="lead")     # long 10
        E.bet("p", "H1", "worker", "long", 30)
        E.bet("p", "H1", "phone-1.7b", "short", 50)
        self.assertEqual(E.budget("p", "H1"), 80)
        t0 = E.balance("treasury")
        E.resolve("p", "H1", "lead", settler=self.tok)
        self.assertEqual(E.balance("lead"), 1000 + 12)
        self.assertEqual(E.balance("worker"), 1000 + 36)
        self.assertEqual(E.balance("phone-1.7b"), 950)
        self.assertEqual(E.balance("treasury"), t0 + 2)
        self.assertEqual(E.balance("escrow"), 0)
        self.assertIn("closed", E.bet("p", "H1", "worker", "long", 1))

    def test_market_short_wins_on_dead(self):
        E.on_event("hyp-add", program="p", hyp_id="H2", bot="lead")
        E.bet("p", "H2", "phone-4b", "short", 100)
        E.resolve("p", "H2", "dead", settler=self.tok)
        self.assertEqual(E.balance("phone-4b"), 1000 + 9)
        self.assertEqual(E.balance("lead"), 990)

    def test_unfired_refunds(self):
        E.on_event("hyp-add", program="p", hyp_id="H3", bot="lead")
        E.bet("p", "H3", "worker", "short", 40)
        E.resolve("p", "H3", "unfired", settler=self.tok)
        self.assertEqual(E.balance("lead"), 1000)
        self.assertEqual(E.balance("worker"), 1000)
        self.assertEqual(E.market("mkt:p:H3")["closed"], "unfired")

    # ---- bonds
    def test_bond_refund_on_recomputed_floor(self):
        E.on_event("probe", program="p", hyp_id="H5", lane="worker")
        self.assertEqual(E.balance("worker"), 970)
        E.on_event("burst", program="p", hyp_id="H5", bot="worker", n=4, probes=12)   # typed 12: not trusted
        self.assertEqual(E.balance("worker"), 970 - 4)
        self.hyp("H5", probes=12, bursts=1)
        E.on_event("burst", program="p", hyp_id="H5", bot="worker", n=1)
        self.assertEqual(E.balance("worker"), 970 - 4 - 1 + 30)

    def test_bond_forfeit_on_abandoned_lane(self):
        E.on_event("probe", program="p", hyp_id="H6", lane="worker")
        t0 = E.balance("treasury")
        E.on_event("outcome", row={"verdict": "LEAD", "target": "p", "hypothesis": "H6", "lane": "worker",
                                   "probes": 3, "burst": False, "floor": "not-met"})
        self.assertEqual(E.balance("worker"), 970)
        self.assertEqual(E.balance("treasury"), t0 + 30)

    # ---- triage (settler only)
    def _lin(self, rid):
        E._lin_append({"program": "p", "hyp_id": "H7", "author": "lead", "prober": "worker"})
        E._lin_append({"program": "p", "hyp_id": "H7", "verifier": "phone-4b", "slug": "s7"})
        E.link_report("p", rid, slug="s7", writer="reflector")

    def test_triage_needs_settler(self):
        self._lin("110")
        self.assertIn("PermissionError", E.on_event("triage", program="p", report_id="110", state="resolved"))
        self.assertEqual(E.balance("lead"), 1000)

    def test_triage_payout_split(self):
        self._lin("111")
        E.on_event("triage", program="p", report_id="111", state="resolved", settler=self.tok)
        b = E.balances()
        self.assertEqual((b["lead"], b["worker"], b["phone-4b"], b["reflector"]), (1300, 1400, 1200, 1100))
        E.on_event("triage", program="p", report_id="111", state="resolved", settler=self.tok)
        self.assertEqual(E.balance("lead"), 1300)

    def test_triage_penalties(self):
        self._lin("222")
        E.on_event("triage", program="p", report_id="222", state="duplicate", settler=self.tok)
        self.assertEqual(E.balance("reflector"), 800)
        E._lin_append({"program": "p", "hyp_id": "H8", "slug": "s8"})
        E.link_report("p", "333", slug="s8", writer="brain")
        E.on_event("triage", program="p", report_id="333", state="not-applicable", settler=self.tok)
        self.assertEqual(E.balance("brain"), 500)

    def test_settle_triage_reads_pull_and_skips_unlinked(self):
        d = os.path.join(E.FEEDBACK_OUT, "2026-10-22")
        os.makedirs(d)
        rep = [{"id": "444", "attributes": {"state": "triaged"},
                "relationships": {"program": {"data": {"attributes": {"handle": "p"}}}}},
               {"id": "555", "attributes": {"state": "duplicate"},
                "relationships": {"program": {"data": {"attributes": {"handle": "p"}}}}}]
        with open(os.path.join(d, "reports_list_raw.json"), "w") as f:
            json.dump(rep, f)
        self._lin("444")
        self.assertIn("1 settled", E.settle_triage())
        self.assertEqual(E.balance("reflector"), 1100)
        self.assertIn("refused", E.settle_triage(self.tmp))   # a pull outside FEEDBACK_OUT

    # ---- calibration and routing
    def test_brier(self):
        for i, (side, res) in enumerate([("long", "proven"), ("long", "dead"), ("short", "dead"), ("short", "lead")]):
            E.on_event("hyp-add", program="b", hyp_id=f"H{i}", bot="lead")
            E.bet("b", f"H{i}", "phone-4b", side, 10)
            E.resolve("b", f"H{i}", res, settler=self.tok)
        self.assertEqual(E.brier("phone-4b"), 0.5)
        self.assertEqual(E.brier("lead"), 0.5)
        self.assertIsNone(E.brier("oss-bot"))

    def test_routing_weights_sum_to_one_and_exclude_broke(self):
        E.slash("reflector", 950, "t", "test", settler=self.tok)
        self.assertTrue(E.broke("reflector"))
        w = E.routing_weights()
        self.assertAlmostEqual(sum(w.values()), 1.0, places=9)
        self.assertNotIn("reflector", w)
        self.assertNotIn("treasury", w)
        E.slash("lead", 950, "t2", "test", settler=self.tok)
        self.assertNotEqual(E.route_role("lead"), "lead")
        self.assertEqual(E.route_role("worker"), "worker")

    def test_filing_market_and_dupe_odds(self):
        self._lin("666")
        E.filing_market("open", "p", "666", bot="lead", cls="idor")
        E.filing_market("bet", "p", "666", bot="phone-4b", side="duplicate", stake=20)
        E.filing_market("bet", "p", "666", bot="worker", side="resolved", stake=20)
        with self.assertRaises(PermissionError):
            E.filing_market("resolve", "p", "666", outcome="resolved")
        E.on_event("triage", program="p", report_id="666", state="duplicate", settler=self.tok)
        self.assertEqual(E.balance("worker"), 980)
        self.assertGreater(E.balance("phone-4b"), 1000)
        self.assertEqual(E.dupe_odds("idor"), (round(2 / 3, 3), 1))

    def test_fixture_programs_never_booked(self):
        E.REQUIRE_TARGET = True
        n = len(E.rows())
        self.assertIsNone(E.on_event("probe", program="zz-unit-expert", hyp_id="H1", lane="worker"))
        self.assertIsNone(E.debit_probe("no-such-program-xyz", "worker"))
        self.assertEqual(len(E.rows()), n)


if __name__ == "__main__":
    unittest.main()
