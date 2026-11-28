#!/usr/bin/env python3
"""Tests for gnoc_oracle (hash-committed terminal, sealed captures, validators, release phases, alloy, respawn,
escalation) and gnoc_probe.sweep. Stdlib unittest, temp dirs only, no network, no model calls.

    python3 -W error::ResourceWarning scripts/test_gnoc_oracle.py [-v]
"""
import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_hunt as H  # noqa: E402
import gnoc_oracle as O  # noqa: E402
import gnoc_probe as P  # noqa: E402

import gnoc_secrets as GS  # noqa: E402

PROG = "_oracletest"
AH = {"Authorization": "Bearer aaa"}
BH = {"Authorization": "Bearer bbb"}


def _now():
    return datetime.now(timezone.utc).isoformat()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-oracle-")
        self._saved = [(O, k, getattr(O, k)) for k in ("WS", "ORACLE_DIR", "SEAL", "LEDGER", "SENDER")]
        self._saved.append((H, "WS", H.WS))
        O.WS = self.tmp
        O.ORACLE_DIR = os.path.join(self.tmp, "oracles")
        O.SEAL = os.path.join(O.ORACLE_DIR, ".seal")
        H.WS = self.tmp
        O._SECRET_CACHE.clear()
        self.idents = {"A": {"headers": dict(AH)}, "B": {"headers": dict(BH)}, "A2": {"headers": dict(AH)}}
        self._p = mock.patch.object(O, "_identities", lambda program: self.idents)
        self._p.start()
        H.save(PROG, {"hypotheses": [{"id": f"H{i}", "title": f"hyp {i}", "status": "probing"} for i in range(1, 10)],
                      "edges": []})
        self.econ = []
        stub = types.ModuleType("gnoc_economy")
        stub.on_event = lambda kind, **kw: self.econ.append((kind, kw))
        self._mods = mock.patch.dict(sys.modules, {"gnoc_economy": stub})
        self._mods.start()
        self.n = 0

    def tearDown(self):
        self._mods.stop()
        self._p.stop()
        for mod, k, v in self._saved:
            setattr(mod, k, v)
        O._SECRET_CACHE.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cap(self, body="", req_url="https://t.example/api/me", headers=None, req_body=None, status=200,
            resp_headers=None, sealed=True, method="GET", ts=True, **extra):
        self.n += 1
        d = os.path.join(self.tmp, "targets", PROG, "hunts", "gnoc-agent-test", "raw")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, f"{self.n:03d}.json")
        row = {"request": {"method": method, "url": req_url, "headers": headers or {}, "body": req_body},
               "response": {"status": status, "headers": resp_headers or {"Content-Type": "application/json"},
                            "body": body, "via": "direct"}}
        if ts:
            row["ts"] = _now()
        row.update(extra)
        with open(p, "w") as f:
            json.dump(row, f)
        if sealed:
            self.assertTrue(O.seal(p))
        return os.path.relpath(p, self.tmp)

    def xur(self, hyp="H1"):
        return O.commit(PROG, hyp, "cross-user-read", planted_as="B", must_read_as="A")


class CommitVerify(Base):
    def test_commit_plant_verify_pass_and_preimage_never_stored(self):
        oid, pre = self.xur()
        self.assertRegex(pre, r"^gnoc-[0-9a-f]{32}$")
        with open(O._path(PROG)) as f:
            self.assertNotIn(pre, f.read())
        c = self.cap(body=json.dumps({"bio": pre}), headers=AH)
        v, why = O.verify(PROG, oid, [c])
        self.assertEqual(v, "passed", why)
        self.assertEqual(O.oracles(PROG)[oid]["status"], "passed")
        self.assertEqual(self.econ[0][0], "oracle-pass")
        self.assertEqual(self.econ[0][1]["ref"], oid)
        for root, _, files in os.walk(O.ORACLE_DIR):
            for fn in files:
                if fn != ".seal":
                    with open(os.path.join(root, fn)) as f:
                        self.assertNotIn(pre, f.read())

    def test_reflection_in_request_fails(self):
        oid, pre = self.xur()
        c = self.cap(body=f"echo {pre}", req_url=f"https://t.example/s?q={pre}", headers=AH)
        v, why = O.verify(PROG, oid, [c])
        self.assertEqual(v, "failed")
        self.assertRegex(why, "reflection|not by the planter")
        self.assertEqual(self.econ, [])

    def test_url_encoded_reflection_fails(self):
        oid, pre = self.xur()
        enc = "".join("%{:02x}".format(ord(ch)) for ch in pre)
        c = self.cap(body=pre, req_url=f"https://t.example/run?cmd=echo%20{enc}", headers=AH)
        self.assertEqual(O.verify(PROG, oid, [c])[0], "failed")

    def test_wrong_identity_fails(self):
        oid, pre = self.xur()
        c = self.cap(body=pre, headers=BH)
        v, why = O.verify(PROG, oid, [c])
        self.assertEqual(v, "failed")
        self.assertIn("read as B", why)

    def test_unsealed_capture_refused(self):
        oid, pre = self.xur()
        c = self.cap(body=pre, sealed=False, headers=AH)
        v, why = O.verify(PROG, oid, [c])
        self.assertEqual(v, "failed")
        self.assertIn("unsealed capture", why)

    def test_tampered_capture_refused(self):
        oid, pre = self.xur()
        c = self.cap(body="nothing here", headers=AH)
        p = os.path.join(self.tmp, c)
        with open(p) as f:
            s = f.read()
        with open(p, "w") as f:
            f.write(s.replace("nothing here", pre))
        v, why = O.verify(PROG, oid, [c])
        self.assertEqual(v, "failed")
        self.assertIn("hand-written capture", why)

    def test_wrong_hash_and_outside_workspace(self):
        oid, _ = self.xur()
        c = self.cap(body="gnoc-" + "0" * 32, headers=AH)
        self.assertEqual(O.verify(PROG, oid, [c])[0], "failed")
        oid, _ = self.xur()
        self.assertIn("inside the workspace", O.verify(PROG, oid, ["/etc/passwd"])[1])
        self.assertEqual(O.verify(PROG, "o-nope", [c])[0], "failed")

    def test_seal_secret_is_0600_and_no_tool_returns_it(self):
        oid, pre = self.xur()
        c = self.cap(body=pre, headers=AH)
        mode = stat.S_IMODE(os.stat(O.SEAL).st_mode)
        self.assertEqual(mode, 0o600)
        with open(O.SEAL) as f:
            secret = f.read().strip()
        ctx = types.SimpleNamespace(program=PROG, s={})
        outs = [O.t_oracle_commit(ctx, "H2", "auth-bypass", planted_as="B", must_read_as="none",
                                  planted_url="https://t.example/notes/1"),
                O.t_oracle_verify(ctx, oid, [c]), O.t_oracle_status(ctx), O.t_release_phase(ctx, "rce")]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            O.main(["status", PROG])
        outs.append(buf.getvalue())
        self.assertIn(oid, outs[-1])
        for o in outs:
            self.assertNotIn(secret, str(o))

    def test_unknown_kind_and_bad_program(self):
        with self.assertRaises(ValueError):
            O.commit(PROG, "H1", "telepathy")
        with self.assertRaises(ValueError):
            O.commit("../etc", "H1", "rce")


class Attacks(Base):
    """Every fake PASS from the 2026-10-23 adversarial review (/tmp/rv_attack/oracle_atk.py), now refused."""

    def assertFake(self, oid, caps, why_part=None):
        v, why = O.verify(PROG, oid, caps)
        self.assertEqual(v, "failed", why)
        if why_part == "reflection":   # the plant scan (reader sent the canary) may fire first; both are refusals
            self.assertRegex(why, "reflection|not by the planter")
        elif why_part:
            self.assertIn(why_part, why)
        return why

    def test_1e_1f_1g_1h_reflection_variants(self):
        oid, pre = self.xur()
        self.assertFake(oid, [self.cap(body=pre, headers=AH, req_url="https://t.example/echo", method="POST",
                                       req_body='{"m":"%s"}' % ("\\u0067" + pre[1:]))], "reflection")
        oid, pre = self.xur()
        self.assertFake(oid, [self.cap(body=pre, headers=AH, req_url="https://t.example/e?m=" + pre.upper())],
                        "reflection")
        import urllib.parse as U
        oid, pre2 = self.xur()
        tri = U.quote(U.quote(U.quote(pre2, safe=""), safe=""), safe="")
        self.assertFake(oid, [self.cap(body=pre2, headers=AH, req_url="https://t.example/e?m=" + tri)], "reflection")
        oid, pre = self.xur()
        self.assertFake(oid, [self.cap(body=pre, headers=AH, req_url=f"https://t.example/e?a=gnoc-&b={pre[5:]}")],
                        "reflection")
        oid, pre = self.xur()   # a 12-char piece alone is enough
        self.assertFake(oid, [self.cap(body=pre, headers=AH, req_url=f"https://t.example/e?a={pre[10:22]}")],
                        "reflection")

    def test_1i_1j_identity_rules_at_commit(self):
        with self.assertRaises(ValueError):   # planter == reader
            O.commit(PROG, "H2", "cross-user-read", planted_as="A", must_read_as="A")
        with self.assertRaises(ValueError):   # must_read_as missing
            O.commit(PROG, "H3", "cross-user-read")
        with self.assertRaises(ValueError):   # unknown label
            O.commit(PROG, "H3", "cross-user-read", planted_as="B", must_read_as="Mallory")
        with self.assertRaises(ValueError):   # same credentials under two names
            O.commit(PROG, "H3", "cross-user-read", planted_as="A2", must_read_as="A")
        with self.assertRaises(ValueError):   # planted_as missing
            O.commit(PROG, "H3", "cross-user-read", must_read_as="A")

    def test_1i_planter_sends_canary_as_reader_is_refused(self):
        oid, pre = self.xur()
        self.cap(body="ok", headers=AH, req_url="https://t.example/me", method="POST", req_body={"bio": pre})
        why = self.assertFake(oid, [self.cap(body={"bio": pre}, headers=AH, req_url="https://t.example/me")])
        self.assertIn("not by the planter B", why)

    def test_1k_auth_bypass_needs_private_plant_and_control(self):
        with self.assertRaises(ValueError):
            O.commit(PROG, "H4", "auth-bypass", must_read_as="none")
        with self.assertRaises(ValueError):
            O.commit(PROG, "H4", "auth-bypass", planted_as="B", must_read_as="none")
        pu = "https://t.example/notes/9"
        oid, pre = O.commit(PROG, "H4", "auth-bypass", planted_as="B", must_read_as="none", planted_url=pu)
        plant = self.cap(body="ok", headers=BH, req_url="https://t.example/comments", method="POST",
                         req_body={"c": pre})
        read = self.cap(body="comment: " + pre, req_url="https://t.example/comments")
        self.assertFake(oid, [plant, read], "outside planted_url")
        # positive: private plant, refused control, bypass read
        oid, pre = O.commit(PROG, "H5", "auth-bypass", planted_as="B", must_read_as="none", planted_url=pu)
        plant = self.cap(body="ok", headers=BH, req_url=pu, method="PUT", req_body={"note": pre})
        ctl = self.cap(body="denied", status=401, req_url=pu)
        read = self.cap(body={"note": pre}, req_url=pu + "/..;/9", headers={"X-Original-URL": "/notes/9"})
        v, why = O.verify(PROG, oid, [plant, ctl, read])
        self.assertEqual(v, "passed", why)
        # the same plant ALSO posted publicly: refused by the plant scan
        oid, pre = O.commit(PROG, "H6", "auth-bypass", planted_as="B", must_read_as="none", planted_url=pu)
        plant = self.cap(body="ok", headers=BH, req_url=pu, method="PUT", req_body={"note": pre})
        self.cap(body="ok", headers=BH, req_url="https://t.example/comments", method="POST", req_body={"c": pre})
        ctl = self.cap(body="denied", status=401, req_url=pu)
        read = self.cap(body="comment " + pre, req_url="https://t.example/comments")
        self.assertFake(oid, [plant, ctl, read], "outside planted_url")

    def test_1l_1t_rce_needs_both_tokens_from_output(self):
        with self.assertRaises(ValueError):
            O.commit(PROG, "H5", "rce")
        c = O.commit(PROG, "H5", "rce", must_read_as="A")
        oid, pre = c
        self.assertRegex(c.echo, r"^gnoc-[0-9a-f]{32}$")
        self.assertFake(oid, [self.cap(body=pre, headers=AH, req_url="https://t.example/profile")], "echo")
        c = O.commit(PROG, "H6", "rce", must_read_as="A")
        self.cap(body="ok", headers=AH, req_url="https://t.example/profile", method="POST",
                 req_body={"bio": c[1] + " " + c.echo})
        self.assertFake(c[0], [self.cap(body=f"{c[1]}\n{c.echo}", headers=AH, req_url="https://t.example/profile")],
                        "SENT to the target")
        c = O.commit(PROG, "H7", "rce", must_read_as="A")
        cmd = f"printf '{O._octal(c[1])}'; printf '{O._octal(c.echo)}'"
        good = self.cap(body=f"{c[1]}{c.echo}", headers=AH, req_url="https://t.example/run", method="POST",
                        req_body={"cmd": cmd})
        v, why = O.verify(PROG, c[0], [good])
        self.assertEqual(v, "passed", why)
        c = O.commit(PROG, "H8", "rce", must_read_as="A")
        self.assertFake(c[0], [self.cap(body=f"{c[1]}{c.echo}", headers=AH, ts=False)], "no ts")

    def test_1m_hyp_must_exist(self):
        with self.assertRaises(ValueError):
            O.commit(PROG, "H99", "cross-user-read", planted_as="B", must_read_as="A")
        with self.assertRaises(ValueError):
            O.commit(PROG, "work the notes idor", "cross-user-read", planted_as="B", must_read_as="A")

    def test_1n_draft_hold_keyed_by_oracle_id(self):
        oid, pre = self.xur()
        self.assertEqual(O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])[0], "passed")
        self.assertTrue(any(r.startswith("ORACLE") for r in O.draft_hold(PROG, "cross-user-read")))
        self.assertTrue(any(r.startswith("ORACLE") for r in O.draft_hold(PROG, "cross-user-read", "o-00000000")))
        open_oid, _ = self.xur("H2")
        self.assertIn("is open", " ".join(O.draft_hold(PROG, "cross-user-read", open_oid)))
        self.assertFalse(any(r.startswith("ORACLE") for r in O.draft_hold(PROG, "cross-user-read", oid)))
        self.assertIn("not one of", " ".join(O.draft_hold(PROG, "rce", oid)))
        self.assertEqual(O.pick_oracle(PROG, "cross-user-read", f"evidence o-00000000 then {oid}"), oid)

    def test_1o_one_verdict_per_commit(self):
        oid, pre = self.xur()
        self.assertEqual(O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])[0], "passed")
        self.econ.clear()
        v, why = O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])
        self.assertEqual(v, "failed")
        self.assertIn("one verdict per commit", why)
        self.assertEqual(self.econ, [])
        oid, pre = self.xur()
        self.assertEqual(O.verify(PROG, oid, [self.cap(body="no", headers=AH)])[0], "failed")
        self.assertIn("one verdict", O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])[1])

    def test_1p_1q_open_redirect(self):
        with self.assertRaises(ValueError):
            O.commit(PROG, "H6", "open-redirect")
        for target in ("www.t.example", "sso.t.example", "t.example"):
            oid, _ = O.commit(PROG, "H6", "open-redirect", attacker_host=target)
            self.assertFake(oid, [self.cap(req_url=f"https://t.example/go?u=https://{target}/", status=302,
                                           resp_headers={"Location": f"https://{target}/a"})], "own domain")
        oid, _ = O.commit(PROG, "H6", "open-redirect", attacker_host="evil-owned.example")
        self.assertFake(oid, [self.cap(req_url="https://t.example/login", status=302,
                                       resp_headers={"Location": "https://evil-owned.example/a"})], "not in the request")
        oid, _ = O.commit(PROG, "H6", "open-redirect", attacker_host="evil-owned.example")
        v, why = O.verify(PROG, oid, [self.cap(req_url="https://t.example/go?u=%2F%5Cevil-owned.example", status=302,
                                               resp_headers={"Location": "/\\evil-owned.example/p"})])
        self.assertEqual(v, "passed", why)

    def test_1r_1s_1w_arms_bound_to_one_endpoint(self):
        oid, _ = O.commit(PROG, "H7", "sqli-boolean")
        ps = [self.cap(req_url=f"https://t.example/a?x=1=1&n={i}", body="A" * 500) for i in range(3)]
        ps += [self.cap(req_url=f"https://t.example/other?x=1=2&n={i}", body="B" * 5000) for i in range(3)]
        self.assertFake(oid, ps, "SAME method + path")
        oid, pre = O.commit(PROG, "H8", "cache-poisoning", planted_as="A", must_read_as="none")
        p1 = self.cap(req_url="https://t.example/profile/edit", headers=AH, method="POST", req_body="bio=" + pre)
        p2 = self.cap(req_url="https://t.example/u/a", body="bio " + pre)
        self.assertFake(oid, [p1, p2], "SAME method + path")
        oid, _ = O.commit(PROG, "H9", "race-single-use")
        rs = [self.cap(req_url="https://t.example/redeem", headers=AH, arm="concurrent", method="POST")
              for _ in range(2)]
        rs += [self.cap(req_url="https://t.example/unrelated", headers=AH, arm="serial")]
        self.assertFake(oid, rs, "SAME method + path")

    def test_6_sqli_time_from_captures_elapsed(self):
        oid, _ = O.commit(PROG, "H7", "sqli-time")
        u = "https://t.example/i?id=1"
        caps = [self.cap(req_url=u + "%27%20AND%20SLEEP(5)--", elapsed=5.2) for _ in range(5)]
        caps += [self.cap(req_url=u, elapsed=0.2) for _ in range(5)]
        v, why = O.verify(PROG, oid, caps)
        self.assertEqual(v, "passed", why)
        oid, _ = O.commit(PROG, "H7", "sqli-time")
        caps = [self.cap(req_url=u + "%27%20AND%20SLEEP(5)--", elapsed=5.2) for _ in range(5)]
        caps += [self.cap(req_url="https://t.example/other", elapsed=0.2) for _ in range(5)]
        self.assertFake(oid, caps, "SAME method + path")

    def test_2_forged_state_rows_are_ignored(self):
        oid, pre = self.xur()
        with open(O._path(PROG), "a") as f:
            f.write(json.dumps({"ts": _now(), "id": oid, "event": "verdict", "status": "passed"}) + "\n")
            f.write(json.dumps({"ts": _now(), "id": "o-deadbeef", "program": PROG, "hyp_id": "H1",
                                "kind": "rce", "sha256": "0" * 64, "status": "passed"}) + "\n")
        self.assertEqual(O.oracles(PROG)[oid]["status"], "open")
        self.assertNotIn("o-deadbeef", O.oracles(PROG))
        self.assertEqual(O.passed(PROG), [])
        self.assertTrue(all(r[3] == "open" for r in O.status(PROG)))

    def test_2_state_dirs_are_write_refused(self):
        import gnoc_agent as G
        for rel in (".claude/state/hunt-loop/oracles/x.jsonl", ".claude/state/economy/ledger.jsonl"):
            self.assertIsNotNone(G._write_refusal(os.path.join(G.WS, rel), "x"), rel)

    def test_3_seal_and_settler_are_secret(self):
        import gnoc_agent as G
        for f in GS.STATE_SECRET_FILES:
            self.assertTrue(GS.shell_reads_secret(f"cat {f}"), f)
            self.assertTrue(GS.is_secret_path(f), f)
            self.assertTrue(G._is_secret(f), f)
        self.assertTrue(GS.shell_reads_secret("cd .claude/state/hunt-loop/oracles && cat .seal"))
        self.assertTrue(GS.shell_reads_secret("cat .claude/state/hunt-loop/oracles/.s*"))
        self.assertFalse(GS.shell_reads_secret("cat .claude/state/hunt-loop/oracles/gatewayco.jsonl"))
        seal, settler = os.path.join(self.tmp, "seal"), os.path.join(self.tmp, "settler")
        for p, v in ((seal, "a1" * 32), (settler, "b2" * 32)):
            with open(p, "w") as f:
                f.write(v)
        with mock.patch.object(GS, "STATE_SECRET_FILES", (seal, settler)):
            GS._cache["sig"] = None
            out = GS.redact(f"tool said {'a1' * 32} and {'b2' * 32}")
            self.assertNotIn("a1" * 32, out)
            self.assertNotIn("b2" * 32, out)
            self.assertTrue(GS.find("x " + "b2" * 32))
        GS._cache["sig"] = None
        ctx = types.SimpleNamespace(program=PROG, s={})
        oid, _ = self.xur()
        with open(O.SEAL) as f:
            key = f.read().strip()
        self.assertNotIn(key, GS.redact(f"leak {key}"))
        self.assertIn("refused", G.t_read_file(G.Ctx({}), GS.STATE_SECRET_FILES[0]).lower()
                      if os.path.exists(GS.STATE_SECRET_FILES[0]) else "refused")
        self.assertNotIn(key, O.t_oracle_status(ctx))


class Refire(Base):
    def send_stub(self, body_fn):
        sent = []

        def send(program, method, url, headers, body):
            sent.append((method, url))
            return self.cap(body=body_fn(url), req_url=url, headers=headers, method=method)
        O.SENDER = send
        return sent

    def forged(self, pre, url="https://t.example/notes/1"):
        return self.cap(body={"note": pre}, headers=AH, req_url=url, sealed=False)

    def test_forged_capture_whose_live_resend_lacks_preimage_fails(self):
        oid, pre = self.xur()
        sent = self.send_stub(lambda u: {"note": "nothing"})
        v, why = O.refire(PROG, oid, [self.forged(pre)])
        self.assertEqual(v, "failed", why)
        self.assertEqual(len(sent), 1)
        self.assertIn("fresh sealed capture", why)

    def test_live_resend_containing_preimage_passes_and_writes_liveness(self):
        oid, pre = self.xur()
        self.send_stub(lambda u: {"note": pre})
        draft = os.path.join(self.tmp, "reports", "drafts", PROG, "x")
        os.makedirs(draft)
        v, why = O.refire(PROG, oid, [self.forged(pre)], draft=draft)
        self.assertEqual(v, "passed", why)
        lv = [f for f in os.listdir(os.path.join(draft, "evidence")) if f.startswith("liveness-")]
        self.assertEqual(len(lv), 1)
        with open(os.path.join(draft, "evidence", lv[0])) as f:
            row = json.load(f)
        self.assertTrue(row["live"])
        self.assertEqual(row["oracle"], oid)

    def test_original_unsealed_alone_still_fails(self):
        oid, pre = self.xur()
        v, why = O.verify(PROG, oid, [self.forged(pre)])
        self.assertEqual(v, "failed")
        self.assertIn("unsealed capture", why)

    def test_chat_refire_is_read_only(self):
        oid, pre = self.xur()
        sent = self.send_stub(lambda u: {"note": pre})
        p = self.cap(body="", headers=AH, req_url="https://t.example/notes/1", method="DELETE", sealed=False)
        out = O.t_oracle_verify(types.SimpleNamespace(program=PROG, s={}), oid, [p], refire=True)
        self.assertIn("failed", out)
        self.assertEqual(sent, [])


class Validators(Base):
    def row(self, kind, **kw):
        oid, pre = O.commit(PROG, "H9", kind, **kw)
        return O.oracles(PROG)[oid], pre

    def test_canary_classes_positive_and_negative(self):
        for kind, v in O.VALIDATORS.items():
            if v["check"] is not O._check_canary or kind in ("auth-bypass", "rce"):
                continue
            kw = {"planted_as": "B", "must_read_as": "A"} if kind in O.IDENTITY_KINDS else {"must_read_as": "A"}
            row, pre = self.row(kind, **kw)
            good = {"request": {"url": "https://t.example/x", "headers": AH}, "response": {"status": 200, "body": pre}}
            bad = {"request": {"url": "https://t.example/x", "headers": AH}, "response": {"status": 200, "body": "no"}}
            self.assertTrue(O.adjudicate(kind, row, [dict(good, identity="A")])[0], kind)
            self.assertFalse(O.adjudicate(kind, row, [dict(bad, identity="A")])[0], kind)

    def test_reflection_normalisation_in_the_check_itself(self):
        import urllib.parse as U
        row, pre = self.row("cross-user-read", planted_as="B", must_read_as="A")
        tri = U.quote(U.quote(U.quote(pre, safe=""), safe=""), safe="")
        reqs = [{"url": "https://t.example/e", "body": '{"m":"%s"}' % ("\\u0067" + pre[1:])},
                {"url": "https://t.example/e?m=" + pre.upper()}, {"url": "https://t.example/e?m=" + tri},
                {"url": f"https://t.example/e?a=gnoc-&b={pre[5:]}"}, {"url": f"https://t.example/e?a={pre[3:15]}"},
                {"url": "https://t.example/e", "body": f"x={pre[:8]}&y={pre[8:20]}"}]
        for q in reqs:
            cap = {"identity": "A", "request": dict(q, headers=AH), "response": {"status": 200, "body": pre}}
            ok, why, _ = O._check_canary(row, [cap])
            self.assertFalse(ok, q)
            self.assertIn("reflection", why, q)

    def test_open_redirect(self):
        row, _ = self.row("open-redirect", attacker_host="evil-owned.example")
        good = {"request": {"url": "https://t.example/go?u=//evil-owned.example"},
                "response": {"status": 302, "headers": {"Location": "/\\evil-owned.example/p"}}}
        bad = {"request": {"url": "https://t.example/go?u=x"},
               "response": {"status": 302, "headers": {"Location": "https://t.example/home"}}}
        self.assertTrue(O.adjudicate("open-redirect", row, [good])[0])
        self.assertFalse(O.adjudicate("open-redirect", row, [bad])[0])

    def test_race_single_use(self):
        row, _ = self.row("race-single-use")
        mk = lambda arm, st: {"arm": arm, "request": {"url": "https://t.example/r"},  # noqa: E731
                              "response": {"status": st, "body": ""}}
        good = [mk("concurrent", 200), mk("concurrent", 200), mk("concurrent", 409),
                mk("serial", 200), mk("serial", 409), mk("serial", 409)]
        bad = [mk("concurrent", 200), mk("concurrent", 409), mk("serial", 200), mk("serial", 409)]
        self.assertTrue(O.adjudicate("race-single-use", row, good)[0])
        self.assertFalse(O.adjudicate("race-single-use", row, bad)[0])

    def test_sqli_time(self):
        row, _ = self.row("sqli-time")
        self.assertTrue(O.adjudicate("sqli-time", row, [], {"timed": [5.1, 5.2, 5.0, 5.3, 5.1],
                                                            "control": [0.2, 0.3, 0.2, 0.1, 0.2]})[0])
        self.assertFalse(O.adjudicate("sqli-time", row, [], {"timed": [1.1, 1.2, 1.0, 1.3, 1.1],
                                                             "control": [0.2, 0.3, 0.2, 0.1, 0.2]})[0])
        self.assertFalse(O.adjudicate("sqli-time", row, [], {"timed": [9, 9, 9], "control": [0, 0, 0]})[0])

    def test_sqli_boolean(self):
        row, _ = self.row("sqli-boolean")
        mk = lambda q, st, body: {"request": {"url": "https://t.example/i?id=1" + q}, "response": {  # noqa: E731
            "status": st, "body": body}}
        t = [mk("' AND '1'='1", 200, "x" * 500)] * 3
        f = [mk("' AND '1'='2", 200, "x" * 20)] * 3
        same = [mk("' AND '1'='2", 200, "x" * 500)] * 3
        self.assertTrue(O.adjudicate("sqli-boolean", row, t + f)[0])
        self.assertFalse(O.adjudicate("sqli-boolean", row, t + same)[0])
        self.assertFalse(O.adjudicate("sqli-boolean", row, t[:2] + f)[0])

    def test_cache_poisoning(self):
        row, pre = self.row("cache-poisoning", planted_as="A", must_read_as="B")
        poison = {"identity": "A", "request": {"url": "https://t.example/?x=1", "headers": {"X-Forwarded-Host": pre}},
                  "response": {"status": 200, "body": pre}}
        victim = {"identity": "B", "request": {"url": "https://t.example/?x=1", "headers": {}},
                  "response": {"status": 200, "body": f"<script src=//{pre}/a.js>"}}
        self_only = dict(victim, identity="A")
        self.assertTrue(O.adjudicate("cache-poisoning", row, [poison, victim])[0])
        self.assertFalse(O.adjudicate("cache-poisoning", row, [poison, self_only])[0])
        self.assertFalse(O.adjudicate("cache-poisoning", row, [poison])[0])

    def test_agent_tier_returns_none(self):
        for kind in ("xss-dom", "info-disclosure"):
            row, _ = self.row(kind)
            ok, why = O.adjudicate(kind, row, [])
            self.assertIsNone(ok)
            self.assertTrue(why.startswith("agent-validated: "))
        self.assertEqual(self.econ, [])


class Release(Base):
    def ledger(self, rows):
        p = os.path.join(self.tmp, "PRECISION-LEDGER.json")
        with open(p, "w") as f:
            json.dump({"by_class": rows, "by_program": {PROG: {"n": 4, "positive": 1}}}, f)
        O.LEDGER = p

    def test_thresholds(self):
        self.ledger({"Open Redirect": {"n": 5, "positive": 3}, "Server-Side Request Forgery (SSRF)": {"n": 5, "positive": 2},
                     "SQL Injection": {"n": 10, "positive": 2}, "Race Condition": {"n": 2, "positive": 2},
                     "Code Injection": {"n": 4, "positive": 2}})
        self.assertEqual(O.release_phase("open-redirect"), "GA")         # 60%
        self.assertEqual(O.release_phase("rce"), "GA")                   # exactly 50%
        self.assertEqual(O.release_phase("ssrf-internal"), "preview")    # 40%
        self.assertEqual(O.release_phase("sqli-time"), "private")        # 20%
        self.assertEqual(O.release_phase("race-single-use"), "private")  # n < 3
        self.assertEqual(O.release_phase("cache-poisoning"), "private")  # unmeasured
        self.assertIn("program", O.release_detail("rce", PROG)["why"])
        self.assertIn("GA:", O.banner(PROG))

    def test_draft_hold(self):
        self.ledger({"Insecure Direct Object Reference (IDOR)": {"n": 10, "positive": 1}})
        hold = O.draft_hold(PROG, "cross-user-read")
        self.assertTrue(any(r.startswith("ORACLE") for r in hold))
        self.assertTrue(any("private" in r for r in hold))
        oid, pre = self.xur()
        O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])
        self.assertEqual(O.draft_hold(PROG, "cross-user-read", oid), [])
        self.assertEqual(O.draft_hold(PROG, "money"), [])


class AlloyRespawnEscalate(Base):
    def test_alloy(self):
        a, b = ("w", "h1"), ("l", "h2")
        with mock.patch.dict(os.environ, {"GNOC_ALLOY": ""}):
            self.assertEqual(O.alloy_slot(0, "plain task", [a, b]), (a, False))
            self.assertEqual([O.alloy_slot(i, "[hard] x", [a, b])[0] for i in range(4)], [a, b, a, b])
            self.assertEqual(O.alloy_slot(1, "[hard] x", [a, a]), (a, False))
            self.assertTrue(O.alloy_slot(21, "plain", [a, b])[1])
            self.assertFalse(O.alloy_slot(21, "plain", [a, b], anomalous=True)[1])
            # half the budget, not a fixed 20: a 12-step lane alloys from step 6
            self.assertFalse(O.alloy_slot(5, "plain", [a, b], steps=12)[1])
            self.assertTrue(O.alloy_slot(6, "plain", [a, b], steps=12)[1])
            ph = ("q4b", "phone")
            self.assertEqual([O.alloy_slot(i, "[hard]", [a, b, ph, None])[0] for i in range(3)], [a, b, ph])
        with mock.patch.dict(os.environ, {"GNOC_ALLOY": "1"}):
            self.assertTrue(O.alloy_slot(1, "plain", [a, b])[1])
        with mock.patch.dict(os.environ, {"GNOC_ALLOY": "0"}):
            self.assertFalse(O.alloy_slot(1, "[hard]", [a, b])[1])

    def test_phone_slot_is_a_quick_tcp_check(self):
        import llm_endpoints
        with mock.patch.dict(llm_endpoints.HOSTS, {"phone": "127.0.0.1:1"}):
            self.assertIsNone(O.phone_slot(timeout=0.2))

    def test_respawn_from_disk(self):
        H.save(PROG, {"hypotheses": [{"id": "H3", "title": "B notes readable by A", "status": "probing", "probes": 9,
                                      "assumption": "notes are owner keyed", "evidence": ["targets/x/raw/1.json"]}],
                      "edges": []})
        O.commit(PROG, "H3", "cross-user-read", planted_as="B", must_read_as="A")
        msgs = [{"role": "tool", "content": "24 variants, 0 anomalies"}]
        tail = O.respawn_tail(PROG, "w-1", "work H3 please", msgs, "tried ids 1-3")
        self.assertIn("RESPAWN BRIEF", tail)
        self.assertIn("B notes readable by A", tail)
        self.assertIn("cross-user-read open", tail)
        self.assertIn("tried ids 1-3", tail)
        msgs.append({"role": "tool", "content": "24 variants, 2 anomalies"})
        self.assertEqual(O.respawn_tail(PROG, "w-1", "H3", msgs, ""), "")

    def test_escalate(self):
        brief, role = O.escalate_brief(PROG, "A reads B notes", 0)
        self.assertIsNone(role)
        self.assertIn("only on an oracle PASS", brief)
        oid, pre = self.xur()
        O.verify(PROG, oid, [self.cap(body=pre, headers=AH)])
        self.assertIsNone(O.escalate_brief(PROG, "x", 3)[1])
        brief, role = O.escalate_brief(PROG, "A reads B notes", 2, finder="worker")
        self.assertEqual(role, "lead")
        self.assertIn("self-owned delete", brief)
        self.assertEqual(O.escalate_brief(PROG, "x", 1, finder="lead")[1], "worker")


class Sweep(unittest.TestCase):
    def test_variant_count_and_filling(self):
        sent = []

        def send(label, m, u, h, b):
            sent.append((label, m, u, h, b))
            return {"status": 404 if "gnoc" in u else 200, "headers": {}, "body": "ok" if "%2e" in u else "x"}, f"raw/{len(sent)}"
        table, n, rows = P.sweep("https://t.example/api/{{X}}/users", "GET", payload_set="encodings", cap=5, send=send)
        self.assertEqual(len(sent), 7)  # baseline + control + 5
        self.assertEqual(sent[0][0], "baseline")
        self.assertEqual(sent[0][2], "https://t.example/api//users")
        self.assertTrue(sent[1][2].startswith("https://t.example/api/gnoc"))
        self.assertEqual(sent[2][2], "https://t.example/api/%2e/users")
        self.assertFalse(any("{{" in s[2] for s in sent))
        self.assertIn("7 variants", table)

    def test_slots_headers_body_and_cap(self):
        v = P.sweep_variants("https://t.example/x", "POST", slots={"H": "header-hosts", "B": ["1", "2"]},
                             headers={"Host": "{{H}}"}, body='{"id": {{B}}}', cap=999)
        self.assertLessEqual(len(v), P.SWEEP_CAP + 2)
        self.assertEqual(v[0][3]["Host"], "t.example")       # neutral header-hosts = the url host
        self.assertIn("localhost", {x[3]["Host"] for x in v})
        self.assertIn('{"id": 2}', {x[4] for x in v})
        with self.assertRaises(ValueError):
            P.sweep_variants("https://t.example/x")
        with self.assertRaises(ValueError):
            P.sweep_variants("https://t.example/{{X}}", payload_set="nope")

    def test_sender_error_is_a_row(self):
        def send(*a):
            raise PermissionError("OUT_OF_SCOPE")
        table, n, rows = P.sweep("https://t.example/{{X}}", send=send, cap=2)
        self.assertEqual(len(rows), 4)
        self.assertIn("ERROR", table)


if __name__ == "__main__":
    unittest.main()
