"""Tranche 1 of the 0sec-labs/0 alignment (stdlib unittest, temp dirs, no network, no real `claude`).

Spec: .claude/state/hunt-loop/SPEC-0security-alignment-20261109.md. One class per item:
  T10 claude_worker / ship-gates lanes die with the chat     T11 near-duplicate loop rails + bash turn cap
  T12 grep around= byte windows                               T13 worker job health, single retry, UNFIRED row
  T14 lead share cap (off by default)                         T15 finding.json validator + Bugcrowd P3 floor
  T16 evidence manifest refusals                              T17 child-process env sanitizer
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as A  # noqa: E402
import gnoc_finding as F  # noqa: E402
import gnoc_line as L  # noqa: E402
import gnoc_secrets as SEC  # noqa: E402
import gnoc_session as S  # noqa: E402

PROG = "zz-0sec-align"


class _Mon:
    """MON stand-in: the real monitor registry is live state of the running chat."""

    def start(self, *a, **k):
        return "x"

    def __getattr__(self, name):
        return lambda *a, **k: None


def _j(path):
    with open(path) as fh:
        return json.load(fh)


def _reap(pid, secs=3.0):
    """True once pid is gone. The test process is the worker's parent, so a killed worker is a zombie until
    waited on; reap it, then check /proc."""
    end = time.time() + secs
    while time.time() < end:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        if not os.path.exists(f"/proc/{pid}"):
            return True
        time.sleep(0.1)
    return False


class T10WorkerLaneBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-t10-")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        fake = os.path.join(self.bin, "claude")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nsleep 60\n")
        os.chmod(fake, 0o755)
        self.saved = dict(sessions=S.SESSIONS, mine=S._MINE[0], closing=S._CLOSING[0], arm=S._arm,
                          jobs=A.JOBS_DIR, mon=A.MON, offline=A.offline, path=os.environ.get("PATH", ""))
        S.SESSIONS = os.path.join(self.tmp, "sessions")
        S._MINE[0], S._CLOSING[0] = None, False
        S._arm = lambda: None             # no atexit / signal handlers inside the test runner
        A.JOBS_DIR = os.path.join(self.tmp, "jobs")
        A.MON = _Mon()
        A.offline = lambda: False
        os.environ["PATH"] = self.bin + os.pathsep + self.saved["path"]
        self.pids = []

    def tearDown(self):
        for pid in self.pids:
            try:
                os.killpg(pid, 9)
            except OSError:
                pass
            _reap(pid, 1)
        S.close_session()
        S.SESSIONS, S._MINE[0], S._CLOSING[0], S._arm = (self.saved["sessions"], self.saved["mine"],
                                                         self.saved["closing"], self.saved["arm"])
        A.JOBS_DIR, A.MON, A.offline = self.saved["jobs"], self.saved["mon"], self.saved["offline"]
        os.environ["PATH"] = self.saved["path"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pid_of(self, out):
        import re
        m = re.search(r"pid (\d+)", out)
        self.assertTrue(m, out)
        pid = int(m.group(1))
        self.pids.append(pid)
        return pid

    def test_worker_is_registered_and_dies_with_the_chat(self):
        path = S.open_session(sid="t10", program=PROG)
        out = A.t_claude_worker(A.Ctx({"program": PROG}), "recon-scout", "map the fixture host and report back the routes")
        pid = self._pid_of(out)
        rec = _j(path)
        self.assertIn(pid, [la["pid"] for la in rec.get("lanes") or []], rec)
        self.assertIn("stops when this chat closes", out)
        meta = [f for f in os.listdir(A.JOBS_DIR) if f.endswith(".meta")]
        self.assertTrue(_j(os.path.join(A.JOBS_DIR, meta[0])).get("lane_registered"))
        S.close_session()
        self.assertTrue(_reap(pid), "the worker outlived the chat")

    def test_no_session_keeps_todays_behaviour_and_says_so(self):
        out = A.t_claude_worker(A.Ctx({"program": PROG}), "recon-scout", "map the fixture host and report back the routes")
        self._pid_of(out)
        self.assertIn("not bound to a chat session", out)
        meta = [f for f in os.listdir(A.JOBS_DIR) if f.endswith(".meta")]
        self.assertIs(_j(os.path.join(A.JOBS_DIR, meta[0])).get("lane_registered"), False)


class T11LoopRails(unittest.TestCase):
    def setUp(self):
        self.ctx = A.Ctx({})
        self.env = mock.patch.dict(os.environ, {"GNOC_BASH_TURN_CAP": "", "GNOC_NEAR_REPEAT": ""})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    @staticmethod
    def heredoc(a, b):
        return {"command": f"python3 - <<'EOF'\nb = open('bundle.js').read()\ni = b.find('hasIntercom')\n"
                           f"print(b[i-{a}:i+{b}])\nEOF"}

    def test_digit_shifted_heredocs_are_refused_at_four_and_switched_off_at_six(self):
        out = [A._repeat_note(self.ctx, "bash", self.heredoc(100 * k, 37 * k + 1)) for k in range(1, 7)]
        self.assertEqual(out[:3], [None, None, None], out)
        self.assertTrue(out[3].startswith("refused: this is the 4th near-identical bash call"), out[3])
        self.assertIn("around=2000", out[3])
        self.assertNotIn("switched off", out[4])
        self.assertIn("switched off", out[5])
        self.assertIn("bash", self.ctx.s.get("_turn_off"))
        self.assertLessEqual(out[3].count("\n"), 2)

    def test_a_different_command_runs_in_the_next_turn(self):
        for k in range(1, 7):
            A._repeat_note(self.ctx, "bash", self.heredoc(k, k))
        A._reset_turn_rails(self.ctx.s)
        self.assertIsNone(A._repeat_note(self.ctx, "bash", {"command": "git status --short"}))
        self.assertNotIn("bash", self.ctx.s.get("_turn_off") or [])

    def test_probe_tools_are_never_digit_normalised(self):
        got = [A._repeat_note(self.ctx, "http_request", {"url": f"https://app.zz.test/orders/{i}", "hypothesis": "H1"})
               for i in range(1, 13)]
        self.assertEqual(got, [None] * 12)

    def test_bash_turn_cap(self):
        os.environ["GNOC_BASH_TURN_CAP"] = "5"
        words = ["status", "log", "diff", "branch", "remote", "stash"]
        out = [A._repeat_note(self.ctx, "bash", {"command": f"git {w}"}) for w in words]
        self.assertEqual(out[:5], [None] * 5)
        self.assertTrue(out[5].startswith("refused: 5 bash calls this turn reached the cap (5)"), out[5])
        self.assertIn("grep", out[5])
        self.assertIn("bash", self.ctx.s["_turn_off"])
        A._reset_turn_rails(self.ctx.s)
        self.assertIsNone(A._repeat_note(self.ctx, "bash", {"command": "git tag"}))

    def test_bash_cap_zero_disables_it(self):
        os.environ["GNOC_BASH_TURN_CAP"] = "0"
        out = [A._repeat_note(self.ctx, "bash", {"command": f"echo {w}"}) for w in "abcdefghijklmnop"]
        self.assertEqual(out, [None] * 16)

    def test_abab_gives_exactly_one_advisory(self):
        a = lambda: {"path": "scripts/x.py", "offset": 1}   # noqa: E731
        b = lambda: {"pattern": "def main", "path": "scripts"}   # noqa: E731
        notes = []
        for name, args in (("read_file", a()), ("grep", b()), ("read_file", a()), ("grep", b()),
                           ("read_file", a()), ("grep", b())):
            self.assertIsNone(A._repeat_note(self.ctx, name, args))
            notes.append(A._take_osc_note(args))
        self.assertEqual(sum(1 for n in notes if n), 1, notes)
        self.assertIn("alternating between two calls", notes[3])

    def test_numbered_files_are_distinct_but_paging_one_file_is_a_repeat(self):
        files = [A._repeat_note(self.ctx, "read_file", {"path": f"targets/x/cap{i}.txt", "limit": 100})
                 for i in range(6)]
        self.assertEqual(files, [None] * 6)
        pages = [A._repeat_note(self.ctx, "read_file", {"path": "bundle.js", "offset": 250 * k + 1})
                 for k in range(4)]
        self.assertEqual(pages[:3], [None] * 3)
        self.assertTrue(pages[3].startswith("refused: this is the 4th near-identical read_file"), pages[3])

    def test_near_switch_off(self):
        os.environ["GNOC_NEAR_REPEAT"] = "0"
        out = [A._repeat_note(self.ctx, "bash", self.heredoc(k, k)) for k in range(1, 7)]
        self.assertEqual(out, [None] * 6)


class T12GrepWindows(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="gnoc-t12-"))
        self.saved = A._ACTIVE_ROOT[0]
        A._ACTIVE_ROOT[0] = self.tmp
        blob = bytearray(b"a" * 200_000)
        blob[150_000:150_011] = b"hasIntercom"
        with open(os.path.join(self.tmp, "bundle.js"), "wb") as f:
            f.write(bytes(blob))
        with open(os.path.join(self.tmp, "notes.txt"), "w") as f:
            f.write("alpha\nbeta marker\ngamma\n")
        with open(os.path.join(self.tmp, ".env"), "w") as f:
            f.write("FAKE_TOKEN=fixture-value-not-real-123456\n")
        self.ctx = A.Ctx({})

    def tearDown(self):
        A._ACTIVE_ROOT[0] = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_one_call_windows_a_single_200kb_line(self):
        out = A.t_grep(self.ctx, "hasIntercom", path="bundle.js", around=300)
        self.assertIn("@150000:", out)
        self.assertIn("hasIntercom", out)
        self.assertLess(len(out), 2000)

    def test_around_zero_is_the_line_grep(self):
        plain = A.t_grep(self.ctx, "marker", path="notes.txt")
        self.assertEqual(plain, A.t_grep(self.ctx, "marker", path="notes.txt", around=0))
        self.assertIn("2:beta marker", plain)

    def test_a_secrets_file_is_refused_before_any_read(self):
        out = A.t_grep(self.ctx, "TOKEN", path=".env", around=100)
        self.assertTrue(out.startswith("refused"), out)
        self.assertNotIn("fixture-value", out)

    def test_around_over_a_folder_is_the_ordinary_search(self):
        # it was refused ("around= reads byte windows in ONE file"): gpt-oss sends around= with every grep and
        # was refused five times in one turn (BB drive 2026-11-21). Over a folder there is only one thing to do.
        self.assertNotIn("bad arguments", A.t_grep(self.ctx, "x", path=".", around=50))


class T13WorkerHealth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-t13-")
        self.saved = A.JOBS_DIR
        A.JOBS_DIR = self.tmp

    def tearDown(self):
        A.JOBS_DIR = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name, text, age=0):
        p = os.path.join(self.tmp, name)
        with open(p, "w") as f:
            f.write(text)
        if age:
            t = time.time() - age
            os.utime(p, (t, t))
        return p

    def test_labels(self):
        self.assertEqual(A._job_health(self.out("a.out", "Error: No messages returned from query\n[gnoc-exit 0]\n")),
                         "FAILED-ERROR")
        self.assertEqual(A._job_health(self.out("b.out", "")), "FAILED-EMPTY")
        self.assertEqual(A._job_health(self.out("c.out", "I'm sorry, but I can't help with probing that host. "
                                                         "It may violate our Usage Policy.\n")), "REFUSED")
        digest = "VERDICT: LEAD\nPROBE COUNT: 14 (burst n=10 + serial control)\n" + ("evidence line\n" * 220)
        self.assertEqual(A._job_health(self.out("d.out", digest)), "DONE")
        self.assertEqual(A._job_health(self.out("e.out", "working...\n", age=600), {"pid": os.getpid()}), "STALLED")
        self.assertEqual(A._job_health(self.out("f.out", "partial\n[gnoc-exit 124]\n")), "TIMEOUT")
        self.assertEqual(A._job_health(self.out("g.out", "VERDICT: DEAD\n")), "DONE")   # short real digest

    def test_the_retry_is_judged_on_its_own_output(self):
        txt = ("Error: No messages returned from query\n[gnoc-exit 0]\n[gnoc-retry 1] first attempt was FAILED-ERROR\n"
               "VERDICT: LEAD\nPROBE COUNT: 9\n[gnoc-exit 0]\n")
        self.assertEqual(A._job_health(self.out("r.out", txt)), "DONE")

    def test_wrapper_has_exactly_one_retry_after_thirty_seconds(self):
        sh = A._worker_script(["claude", "-p", "first"], ["claude", "-p", "second"], "/x/j.out")
        self.assertEqual(sh.count("sleep 30"), 1)
        self.assertEqual(sh.count("[gnoc-retry 1]"), 1)
        self.assertEqual(sh.count("claude -p"), 2)
        self.assertIn("--job-health /x/j.out", sh)
        self.assertIn("FAILED-EMPTY|FAILED-ERROR|REFUSED)", sh)

    def test_failed_job_writes_one_unfired_row_and_no_digest(self):
        outf = self.out("20261109-000000-recon-scout.out", "Error: No messages returned from query\n[gnoc-exit 0]\n")
        with open(outf + ".meta", "w") as f:
            json.dump({"pid": 0, "agent": "recon-scout", "model": "sonnet", "program": PROG, "health": 1,
                       "ts": A._now().isoformat()}, f)
        rows = []
        with mock.patch.object(A, "_append_outcome", lambda row: rows.append(row) or "recorded"):
            first = A.t_jobs(A.Ctx({}))
            A.t_jobs(A.Ctx({}))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "UNFIRED")
        self.assertEqual(rows[0]["probes"], 0)
        self.assertIn("FAILED-ERROR", rows[0]["notes"])
        self.assertIn("FAILED-ERROR", first)
        self.assertIn("no digest: do not summarise this as a worker result", first)

    def test_a_legacy_job_without_the_wrapper_records_nothing(self):
        outf = self.out("20261101-000000-recon-scout.out", "Error: No messages returned from query\n")
        with open(outf + ".meta", "w") as f:
            json.dump({"pid": 0, "agent": "recon-scout", "program": PROG}, f)
        rows = []
        with mock.patch.object(A, "_append_outcome", lambda row: rows.append(row) or "recorded"):
            out = A.t_jobs(A.Ctx({}))
        self.assertEqual(rows, [])
        self.assertIn("FAILED-ERROR", out)


class T14LeadShareCap(unittest.TestCase):
    def setUp(self):
        import gnoc_economy
        self.E = gnoc_economy
        self.budget = mock.patch.object(gnoc_economy, "budget", lambda p, h: 20)
        self.budget.start()
        self.env = mock.patch.dict(os.environ, {"GNOC_LEAD_SHARE_CAP": "0.4"})
        self.env.start()

    def tearDown(self):
        self.budget.stop()
        self.env.stop()

    def fire(self, ctx, hyp="H2", thin=False):
        note, ref = A._lead_probe_gate(ctx, PROG, hyp, 1, thin)
        if ref is None:
            A._lead_probe_note(ctx, PROG, hyp)
        return ref

    def test_eight_pass_ninth_refused_thin_once(self):
        ctx = A.Ctx({"_turn_user": "go"})
        refs = [self.fire(ctx) for _ in range(9)]
        self.assertEqual(refs[:8], [None] * 8)
        self.assertTrue(refs[8].startswith("refused: you have fired 8 of H2's 20-probe budget"), refs[8])
        self.assertIn("probe_briefs(hypothesis='H2')", refs[8])
        self.assertLessEqual(refs[8].count("\n"), 2)
        self.assertIsNone(self.fire(ctx, thin=True))
        self.assertIn("already spent", self.fire(ctx, thin=True))

    def test_worker_is_never_refused(self):
        ctx = A.Ctx({"_turn_user": "go", "_worker": True})
        self.assertEqual([self.fire(ctx) for _ in range(30)], [None] * 30)

    def test_offline_names_delegate(self):
        ctx = A.Ctx({"_turn_user": "go"})
        with mock.patch.object(A, "offline", lambda: True):
            ref = [self.fire(ctx) for _ in range(9)][-1]
        self.assertIn("delegate(", ref)

    def test_default_is_off_and_f5_advisory_still_speaks(self):
        os.environ["GNOC_LEAD_SHARE_CAP"] = ""
        ctx = A.Ctx({"_turn_user": "go"})
        self.assertEqual([self.fire(ctx) for _ in range(30)], [None] * 30)
        self.assertIn("dispatch probe_briefs()/claude_worker", A._lead_probe_note(ctx, PROG, "H2"))

    def test_http_request_refuses_before_any_send(self):
        ctx = A.Ctx({"_turn_user": "go", "program": PROG})
        ctx.s["_lead_probes"] = {f"go|{PROG}|H2": 8}

        def boom(*a, **k):
            raise AssertionError("_send was reached")
        H = A.gnoc_hunt
        with mock.patch.object(A, "_program_gate", lambda p, u: ({}, None)), \
                mock.patch.object(A, "_with_identity", lambda p, h, i, u: dict(h or {})), \
                mock.patch.object(A, "_ghost_gate", lambda *a: None), \
                mock.patch.object(A, "_identity_premise_refusal", lambda *a: ""), \
                mock.patch.object(A, "_ghost_strict", lambda *a: None), \
                mock.patch.object(H, "canonical_hyp_id", lambda p, h: h), \
                mock.patch.object(H, "closed_hypothesis", lambda p, h: None), \
                mock.patch.object(H, "verdict_owed", lambda p, h: None), \
                mock.patch.object(A, "_send", boom):
            out = A.t_http_request(ctx, "https://app.zz.test/orders/1", hypothesis="H2")
        self.assertTrue(out.startswith("refused: you have fired 8"), out)


def _png(path, salt):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(F.PNG_MAGIC + b"\x00\x00\x00\rIHDR" + salt.encode())


class _Draft(unittest.TestCase):
    """A fixture draft under a throwaway WS: reports/drafts/<prog>/<slug> plus targets/<prog>/."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="gnoc-t15-"))
        self.saved_ws = F.WS
        F.WS = self.tmp
        self.d = os.path.join(self.tmp, "reports", "drafts", PROG, "idor-orders")
        os.makedirs(os.path.join(self.d, "evidence"))
        os.makedirs(os.path.join(self.tmp, "targets", PROG))
        with open(os.path.join(self.d, "evidence", "cap.json"), "w") as f:
            json.dump({"request": {"method": "GET", "url": "https://app.zz.test/api/orders/1002"},
                       "response": {"status": 200, "body": '{"email":"b@zz.test"}'}}, f)
        with open(os.path.join(self.d, "evidence", "liveness-20261109.json"), "w") as f:
            f.write('{"ok": true}\n')
        _png(os.path.join(self.d, "panels", "burp-req-cap.png"), "req")
        _png(os.path.join(self.d, "panels", "burp-resp-cap.png"), "resp")

    def tearDown(self):
        F.WS = self.saved_ws
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rec(self, **kw):
        r = {"schema": 1, "id": f"{PROG}/idor-orders", "program": PROG, "venue": "hackerone", "asset": "app.zz.test",
             "title": "IDOR on orders", "cwe": "CWE-639",
             "cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "score": 6.5},
             "vrt": {}, "status": "ready", "workflow": "human_review",
             "chain": [{"edge": "E1", "capture": "evidence/cap.json", "sealed": False,
                        "must_contain": '"email":"b@zz.test"', "role": "sink-leg"}],
             "poc_steps": [{"id": "s1", "kind": "exploit", "action": {"type": "http", "method": "GET",
                                                                      "url": "https://app.zz.test/api/orders/1002"},
                            "capture": "evidence/cap.json", "expect": {"type": "http-status", "status": 200}}],
             "claims": [{"stance": "observation", "statement": "B's order read as A",
                         "locator": 'evidence/cap.json#"email":"b@zz.test"', "source": "code:test",
                         "load_bearing": True, "edge": "E1"}],
             "layers": [], "publishability": {"decision": "needs_verify", "reason": "", "refs": []},
             "decorrelation": {"finder_family": "ollama", "refuter_family": "anthropic", "cross_family": True}}
        r.update(kw)
        return r

    @staticmethod
    def leaf(prio):
        return next(v["id"] for v in F._vrt_index().values() if v["leaf"] and v["priority"] == prio)


class T15FindingRecord(_Draft):
    def test_a_valid_record_passes(self):
        F.write(self.d, self.rec())
        self.assertEqual(F.validate(self.d), [])

    def test_cwe_shape(self):
        self.assertTrue(any("CWE-<number>" in e for e in F.validate(self.d, self.rec(cwe="CWE-ABC"))))

    def test_vector_and_score_must_agree(self):
        bad = self.rec(cvss={"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "score": 9.8})
        self.assertTrue(any("computes to 6.5" in e for e in F.validate(self.d, bad)), F.validate(self.d, bad))

    def test_a_symlinked_capture_pointing_outside_fails(self):
        os.symlink("/etc/hostname", os.path.join(self.d, "evidence", "link.json"))
        r = self.rec()
        r["poc_steps"][0]["capture"] = "evidence/link.json"
        self.assertTrue(any("outside the draft dir" in e for e in F.validate(self.d, r)))

    def test_ready_needs_the_needle_on_disk(self):
        r = self.rec()
        r["claims"][0]["locator"] = 'evidence/cap.json#"email":"nobody@zz.test"'
        self.assertTrue(any("T-268" in e for e in F.validate(self.d, r)))

    def test_ready_refuses_a_load_bearing_assumption(self):
        r = self.rec()
        r["claims"].append({"stance": "assumption", "statement": "the id is guessable", "load_bearing": True})
        self.assertTrue(any("assumption" in e for e in F.validate(self.d, r)))

    def test_layers_are_append_only(self):
        F.write(self.d, self.rec())
        F.append_layer(self.d, "killer", "pass", "PASS", by="opus")
        r = F.load(self.d)
        self.assertEqual(r["layers"][0]["family"], "anthropic")
        r["layers"][0]["verdict"] = "reject"
        self.assertTrue(any("append-only" in e for e in F.validate(self.d, r)))
        with self.assertRaises(ValueError):
            F.write(self.d, r)

    def test_bugcrowd_floor(self):
        p3, p4 = self.leaf(3), self.leaf(4)
        ok = self.rec(venue="bugcrowd", vrt={"id": p3, "priority": 3})
        self.assertEqual(F.validate(self.d, ok), [])
        low = F.validate(self.d, self.rec(venue="bugcrowd", vrt={"id": p4, "priority": 4}))
        self.assertTrue(any("below the Bugcrowd P3 floor" in e for e in low), low)
        none = F.validate(self.d, self.rec(venue="bugcrowd", vrt={}))
        self.assertTrue(any("no VRT id" in e for e in none), none)
        varies = next(v["id"] for v in F._vrt_index().values() if v["leaf"] and v["priority"] is None)
        nul = F.validate(self.d, self.rec(venue="bugcrowd", vrt={"id": varies, "priority": None}))
        self.assertTrue(any("the user decides" in e for e in nul), nul)

    def test_backfill_reports_without_raising(self):
        with open(os.path.join(self.d, "report.md"), "w") as f:
            f.write("CVSS: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium\nAsset: app.zz.test\n"
                    "CWE: CWE-639 Authorization Bypass\n\n# IDOR on orders\n\n## Summary\nx\n")
        with mock.patch.object(F, "_venue", lambda p: "hackerone"):
            rec, wrote = F.backfill(self.d)
        self.assertTrue(wrote)
        self.assertEqual(rec["cwe"], "CWE-639")
        self.assertEqual(rec["cvss"]["recomputed"], 6.5)
        self.assertEqual(rec["status"], "draft")
        self.assertIsInstance(F.validate(self.d), list)
        self.assertFalse(F.backfill(self.d)[1])   # never overwrites


class T15GateQa(_Draft):
    """gnoc_line.gate_qa with its unrelated legs stubbed: the finding gate in each mode."""

    def setUp(self):
        super().setUp()
        with open(os.path.join(self.d, "report.md"), "w") as f:
            f.write("CVSS: x\nGate: report-killer PASS\nDedup: public-checked\n\n# t\n\n## Summary\nshort.\n\n"
                    "## PoC\nsteps\n\n## Impact\nshort.\n")
        self.art = os.path.join(self.tmp, "qa.json")
        with open(self.art, "w") as f:
            json.dump({"hyp_id": "H1", "draft_path": os.path.join(self.d, "report.md"), "dedup": {"matchRisk": 0},
                       "repro": "REPRODUCES"}, f)
        self.wo = {"hyps": {"H1": {"station": 5}}}
        import gnoc_economy as E
        import gnoc_hunt as H
        import gnoc_oracle as O
        import gnoc_pay as P
        self.patches = [mock.patch.object(H, "check_evidence", lambda *a: (True, "")),
                        mock.patch.object(E, "dupe_odds", lambda *a: (0.0, 0)),
                        mock.patch.object(O, "release_phase", lambda *a: "public"),
                        mock.patch.object(P, "filing_gate", lambda *a: (True, "ok")),
                        mock.patch.dict(os.environ, {"GNOC_FINDING_GATE": ""})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        super().tearDown()

    def qa(self, mode):
        os.environ["GNOC_FINDING_GATE"] = mode
        return L.gate_qa(PROG, self.wo, self.art)

    def test_clean_fixture_passes_in_every_mode(self):
        F.write(self.d, self.rec())
        F.manifest(self.d)
        for mode in ("", "advisory", "enforce", "off"):
            ok, why, _ = self.qa(mode)
            self.assertTrue(ok, f"{mode}: {why}")
            self.assertNotIn("finding advisory", why)

    def test_bugcrowd_p4_refused_in_enforce_and_advised_by_default(self):
        F.write(self.d, self.rec(venue="bugcrowd", vrt={"id": self.leaf(4), "priority": 4}))
        F.manifest(self.d)
        ok, why, _ = self.qa("enforce")
        self.assertFalse(ok)
        self.assertIn("below the Bugcrowd P3 floor", why)
        ok, why, _ = self.qa("")
        self.assertTrue(ok, why)
        self.assertIn("finding advisory (1)", why)

    def test_off_restores_the_png_count_path(self):
        os.unlink(os.path.join(self.d, "panels", "burp-resp-cap.png"))
        ok, why, _ = self.qa("off")
        self.assertFalse(ok)
        self.assertIn("1 PNG(s)", why)


class T15BuildHoldsBugcrowdBelowP3(unittest.TestCase):
    """gnoc_report.build on a proven chain (the ExpertLayer fixture shape in test_gnoc_agent.py)."""

    def setUp(self):
        import gnoc_hunt
        self.H = gnoc_hunt
        self.prog = "zz-unit-0sec-build"
        self.pdir = os.path.join(gnoc_hunt.WS, "targets", self.prog)
        os.makedirs(os.path.join(self.pdir, "hunts", "raw"), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.pdir, ignore_errors=True)
        shutil.rmtree(os.path.join(self.H.WS, "reports", "drafts", self.prog), ignore_errors=True)

    def _cap(self, name, status, body):
        p = os.path.join(self.pdir, "hunts", "raw", name)
        with open(p, "w") as f:
            json.dump({"ts": "t", "request": {"method": "GET", "url": "https://api.example.com/api/orders/1002",
                                              "headers": {}, "body": ""},
                       "response": {"status": status, "headers": {"content-type": "application/json"}, "body": body}}, f)
        return os.path.relpath(p, self.H.WS)

    def test_p4_leaf_writes_the_draft_and_holds_it(self):
        import gnoc_report
        ev = self._cap("pos.json", 200, '{"id":1002,"email":"b@api.example.com"}')
        ctl = self._cap("neg.json", 401, '{"error":"unauthorized"}')
        self.H.edge(self.prog, "add", "own-account", "cross-user-read", "H1: GET /api/orders/{id} IDOR", "proven",
                    evidence=ev, must_contain='"email":"b@api.example.com"')
        cid = self.H.chains(self.prog, 1)[0][1][0]["id"]
        self.H.edge(self.prog, "update", id=cid, control=ctl)
        p4 = _Draft.leaf(4)
        with mock.patch.object(F, "_venue", lambda p: "bugcrowd"):
            rel, msg = gnoc_report.build(self.prog, llm=None, slug="unit", vrt=p4, finder="qwen3:8b")
        self.assertTrue(rel, msg)
        d = os.path.join(self.H.WS, rel)
        self.assertTrue(os.path.isfile(os.path.join(d, "report.md")))
        with open(os.path.join(d, "HELD-REASON.md")) as fh:
            held = fh.read()
        self.assertIn("BUGCROWD P3 FLOOR", held)
        self.assertIn("**Unlock:", held)
        self.assertIn("vrt.py --search", held)
        rec = F.load(d)
        self.assertEqual((rec["status"], rec["venue"], rec["vrt"]["priority"]), ("held", "bugcrowd", 4))
        self.assertEqual(rec["decorrelation"]["finder_family"], "ollama")
        self.assertEqual([x["layer"] for x in rec["layers"]], ["build", "format"])
        self.assertTrue(os.path.isfile(os.path.join(d, "evidence", "MANIFEST.json")))
        self.assertTrue(any(c["stance"] == "observation" for c in rec["claims"]))
        self.assertNotIn("Cookie", json.dumps(rec))


class T16Manifest(_Draft):
    def clean(self):
        F.manifest(self.d)
        return F.manifest_check(self.d)

    def test_clean_fixture_passes(self):
        self.assertEqual(self.clean(), [])
        m = F.load_manifest(self.d)["files"]
        self.assertEqual(m["panels/burp-req-cap.png"]["pairs_with"], "panels/burp-resp-cap.png")
        self.assertEqual(m["evidence/liveness-20261109.json"]["role"], "liveness")

    def test_a_file_changed_after_the_manifest(self):
        F.manifest(self.d)
        with open(os.path.join(self.d, "evidence", "cap.json"), "a") as f:
            f.write(" ")
        self.assertTrue(any("changed after the manifest: evidence/cap.json (changed)" in e
                            for e in F.manifest_check(self.d)))

    def test_byte_identical_panels(self):
        shutil.copyfile(os.path.join(self.d, "panels", "burp-req-cap.png"),
                        os.path.join(self.d, "panels", "burp-resp-cap.png"))
        self.assertTrue(any("byte-identical" in e for e in self.clean()))

    def test_a_png_without_the_signature(self):
        with open(os.path.join(self.d, "panels", "burp-req-x.png"), "w") as f:
            f.write("not an image")
        self.assertTrue(any("no PNG signature" in e for e in self.clean()))

    def test_no_request_response_pair(self):
        os.unlink(os.path.join(self.d, "panels", "burp-resp-cap.png"))
        self.assertTrue(any("no request+response Burp panel pair" in e for e in self.clean()))

    def test_liveness_outside_evidence(self):
        with open(os.path.join(self.d, "liveness-20261108.json"), "w") as f:
            f.write("{}")
        self.assertTrue(any("liveness receipt outside evidence/" in e for e in self.clean()))

    def test_zero_byte_file(self):
        open(os.path.join(self.d, "evidence", "empty.body"), "w").close()
        self.assertTrue(any("T-41" in e for e in self.clean()))

    def test_an_empty_body_beside_its_headers_is_a_real_302(self):
        with open(os.path.join(self.d, "evidence", "redirect.hdr"), "w") as f:
            f.write("HTTP/1.1 302 Found\nlocation: /login\n")
        open(os.path.join(self.d, "evidence", "redirect.body"), "w").close()
        self.assertEqual(self.clean(), [])

    def test_submit_title_hash(self):
        with open(os.path.join(self.d, "SUBMIT-TITLE.txt"), "w") as f:
            f.write("# Session fixation via vault URL\n")
        self.assertTrue(any("SUBMIT-TITLE.txt starts with '# '" in e for e in self.clean()))

    def test_no_manifest_says_how_to_build_it(self):
        self.assertTrue(any("gnoc_finding.py manifest" in e for e in F.manifest_check(self.d)))


class T17ChildEnv(unittest.TestCase):
    ENV = {"DEEPSEEK_API_KEY": "sk-fixture-not-real", "FOO_TOKEN": "fixture-token", "GNOC_CHILD_ENV": ""}

    def test_child_env_drops_credential_names(self):
        with mock.patch.dict(os.environ, self.ENV):
            env = SEC.child_env({"HUNT_TARGET": PROG})
            self.assertNotIn("DEEPSEEK_API_KEY", env)
            self.assertNotIn("FOO_TOKEN", env)
            self.assertIn("PATH", env)
            self.assertIn("HOME", env)
            self.assertEqual(env["HUNT_TARGET"], PROG)
            self.assertIn("FOO_TOKEN", SEC.child_env(allow=("FOO_TOKEN",)))
        with mock.patch.dict(os.environ, dict(self.ENV, GNOC_SESSION_KEY="tty:/dev/pts/3")):
            self.assertIn("GNOC_SESSION_KEY", SEC.child_env())   # a chat identity, not a credential

    def test_a_real_bash_child_does_not_see_them(self):
        with mock.patch.dict(os.environ, self.ENV):
            # named lookups, not a dump: dumping the whole environment is itself refused (QAQC 2026-11-19 r2)
            out = A.t_bash(A.Ctx({}), "python3 -c \"import os; print([k for k in ('PATH', 'DEEPSEEK_API_KEY', "
                                      "'FOO_TOKEN') if os.environ.get(k)])\"")
        self.assertTrue(out.startswith("exit 0"), out[:200])
        self.assertIn("PATH", out)
        self.assertNotIn("DEEPSEEK_API_KEY", out)
        self.assertNotIn("FOO_TOKEN", out)

    def test_passthrough_restores_the_old_behaviour(self):
        with mock.patch.dict(os.environ, dict(self.ENV, GNOC_CHILD_ENV="passthrough")):
            env = SEC.child_env()
        self.assertIn("DEEPSEEK_API_KEY", env)
        self.assertIn("FOO_TOKEN", env)

    def test_claude_children_keep_only_the_anthropic_key(self):
        with mock.patch.dict(os.environ, dict(self.ENV, ANTHROPIC_API_KEY="fixture-anthropic")):
            env = SEC.child_env(allow=A._claude_auth_allow())
        self.assertIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("DEEPSEEK_API_KEY", env)


if __name__ == "__main__":
    unittest.main()
