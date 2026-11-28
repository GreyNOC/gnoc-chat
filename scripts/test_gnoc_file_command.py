"""/file: the human-only filing command in gnoc chat (the user 2026-11-25, "yes build /file").

Every HackerOne call here is a FAKE. No test in this file may reach api.hackerone.com: _make_h1 is replaced by
FakeH1, the team/signal reads and the self-dedup pull are stubbed, and the ships ledger is a list.
"""
import base64
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_file as F  # noqa: E402
import gnoc_agent as G  # noqa: E402

HANDLE, TOKEN = "fakehandle", "tok_FAKE_0123456789abcdefSECRET"
PROG, SLUG = "acme", "invoice-read"

REPORT = """CVSS: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N 7.5 High
Asset: api.acme.test
CWE: CWE-862 Missing Authorization
Dedup: public-checked 2026-11-25 (none)
Gate: report-killer PASS 2026-11-25
# Unauthenticated read of another account's invoices on api.acme.test

## Summary
The invoices endpoint returns account B's invoice list to a request with no session.

## PoC
```
curl -s https://api.acme.test/v1/invoices/42
```
```
HTTP/1.1 200 OK

{"owner":"b","total":10}
```

## Impact
I read account B's invoices with no credentials.

## Attachments
repro.sh, capture.log and two Burp panels.
"""

FORM = """Title: Unauthenticated read of another account's invoices on api.acme.test
Asset: api.acme.test
CWE: CWE-862 Missing Authorization
CVSS: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N 7.5 High
Venue: acme

# Generated from the draft header.
"""


class FakeResp:
    def __init__(self, status, body=None, text=None):
        self.status_code, self._body = status, body
        self.text = text if text is not None else ("" if body is None else __import__("json").dumps(body))

    def json(self):
        return self._body or {}


class FakeSession:
    def __init__(self, post_resp, get_resp):
        self.posts, self.gets = [], []
        self.post_resp, self.get_resp = post_resp, get_resp

    def post(self, url, json=None, headers=None, timeout=None):
        self.posts.append((url, json))
        return self.post_resp

    def get(self, url, timeout=None):
        self.gets.append(url)
        return self.get_resp


class FakeH1:
    def __init__(self, post_resp=None, get_resp=None):
        self.s = FakeSession(post_resp or FakeResp(201, {"data": {"id": "3141592"}}), get_resp)

    def get_all(self, url):
        if url.endswith("/structured_scopes"):
            return [{"id": "77", "attributes": {"asset_identifier": "api.acme.test", "asset_type": "URL",
                                                "eligible_for_submission": True, "eligible_for_bounty": True}}]
        if url.endswith("/weaknesses"):
            return [{"id": "55", "attributes": {"external_id": "cwe-862", "name": "Missing Authorization"}}]
        raise AssertionError(url)


def filed_report(title, rating="high", weakness="55", scope="77", attachments=()):
    return FakeResp(200, {"data": {"id": "3141592", "attributes": {"title": title}, "relationships": {
        "severity": {"data": {"attributes": {"rating": rating}}},
        "weakness": {"data": {"id": weakness, "attributes": {"external_id": "cwe-862"}}},
        "structured_scope": {"data": {"id": scope}},
        "attachments": {"data": [{"attributes": {"file_name": n}} for n in attachments]}}}})


class FileCommandBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.saved = {k: getattr(F, k) for k in ("WS", "DRAFTS", "SUBMITTED", "TARGETS", "SECRETS", "_venue",
                                                 "_team", "_signal_gate", "_make_h1", "_dedup", "_ledger_append",
                                                 "_SLEEP")}
        F.WS = self.tmp
        F.DRAFTS = os.path.join(self.tmp, "reports", "drafts")
        F.SUBMITTED = os.path.join(self.tmp, "reports", "submitted")
        F.TARGETS = os.path.join(self.tmp, "targets")
        F.SECRETS = os.path.join(self.tmp, "secrets.env")
        with open(F.SECRETS, "w") as fh:
            fh.write(f"HACKERONE_HANDLE={HANDLE}\nHACKERONE_API_TOKEN={TOKEN}\n"
                     f"PARTNER_HANDLE=partnerfake\nPARTNER_API_TOKEN=tok_PARTNER_fake_0000000000\n")
        self.d = os.path.join(F.DRAFTS, PROG, SLUG)
        os.makedirs(os.path.join(self.d, "evidence"))
        os.makedirs(os.path.join(F.TARGETS, PROG))
        self.write("report.md", REPORT)
        self.write("FORM.md", FORM)
        self.write("GATES.md", "Gate: report-killer PASS 2026-11-25\nBurp panels: captured, 2 PNG\n")
        self.write("repro.sh", "#!/bin/sh\ncurl -s https://api.acme.test/v1/invoices/42\n")
        self.write("capture.log", "HTTP/1.1 200 OK\n")
        for n in ("evidence/panel-req.png", "evidence/panel-resp.png"):
            with open(os.path.join(self.d, n), "wb") as fh:
                fh.write(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
        with open(os.path.join(F.TARGETS, PROG, "PROGRAM.md"), "w") as fh:
            fh.write("# acme\nVenue: HackerOne\nReport anything with impact.\n")
        self.h1 = FakeH1(get_resp=filed_report("Unauthenticated read of another account's invoices on api.acme.test",
                                               attachments=()))
        self.ledger = []
        self.team = {}
        self.signal = (True, "open, bounties on, no signal gate")
        F._venue = lambda program: "hackerone"
        F._team = lambda program: self.team
        F._signal_gate = lambda program: self.signal
        F._make_h1 = lambda handle, token: self.h1
        F._dedup = lambda *a: (True, ["SELFDUP CLEAR"])
        F._ledger_append = lambda row: self.ledger.append(row) or (True, "")
        F._SLEEP = lambda s: None

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(F, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name, text):
        with open(os.path.join(self.d, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_file(self, rest=f"{PROG}/{SLUG}", answer=None, typed=True):
        lines, asked = [], []

        def confirm(prompt):
            asked.append(prompt)
            return answer

        rv = F.run(rest, out=lines.append, typed=typed, confirm=confirm)
        return rv, "\n".join(str(x) for x in lines), asked


class Gates(FileCommandBase):
    def test_held_draft_is_refused_before_any_post(self):
        self.write("HELD-REASON.md", "**Unlock: one more probe\n")
        rv, out, asked = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("HELD", out)
        self.assertEqual((self.h1.s.posts, asked), ([], []))

    def test_not_yet_run_gate_is_refused(self):
        self.write("GATES.md", "Gate: report-killer NOT-YET-RUN 2026-11-25\n")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("NOT-YET-RUN", out)
        self.assertEqual(self.h1.s.posts, [])

    def test_an_unrun_stamp_in_the_report_is_refused(self):
        self.write("report.md", REPORT.replace("Gate: report-killer PASS", "Gate: report-killer NOT-YET-RUN"))
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("never ran", out)

    def test_pending_panels_needs_the_typed_override(self):
        self.write("GATES.md", "## Burp panels: PENDING-PANELS - filing blocker\n")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("--allow-missing-panels", out)
        rv, out, _ = self.run_file(f"{PROG}/{SLUG} --allow-missing-panels --dry-run")
        self.assertEqual(rv, "DRY-RUN", out)

    def test_signal_gated_program_is_refused(self):
        self.signal = (False, "HELD ON SIGNAL (T-254): acme enforces target signal 1.0")
        rv, out, asked = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("T-254", out)
        self.assertEqual((self.h1.s.posts, asked), ([], []))

    def test_required_custom_fields_program_is_refused_file_by_hand(self):
        with open(os.path.join(F.TARGETS, PROG, "PROGRAM.md"), "a") as fh:
            fh.write("* **Affected Version(s):** required for open source findings\n")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("File by hand", out)
        self.assertEqual(self.h1.s.posts, [])

    def test_team_submission_requirements_flag_is_refused(self):
        self.team = {"submission_requirements": True}
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("File by hand", out)

    def test_an_optional_bypass_reference_field_does_not_block(self):
        with open(os.path.join(F.TARGETS, PROG, "PROGRAM.md"), "a") as fh:
            fh.write("If you find a bypass, please fill out the Custom Field `Bypass Reference`.\n")
        rv, out, _ = self.run_file(f"{PROG}/{SLUG} --dry-run")
        self.assertEqual(rv, "DRY-RUN", out)

    def test_filing_channel_refuses_our_account_and_takes_a_named_token(self):
        with open(os.path.join(F.TARGETS, PROG, "FILING-CHANNEL.md"), "w") as fh:
            fh.write("acme is a collab with partner; the user files.\n")
        self.signal = (False, "HELD ON SIGNAL (T-254)")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("FILING-CHANNEL.md", out)
        rv, out, _ = self.run_file(f"{PROG}/{SLUG} --token-env PARTNER_API_TOKEN --dry-run")
        self.assertEqual(rv, "DRY-RUN", out)
        self.assertIn("as partnerfake (PARTNER_API_TOKEN)", out)
        self.assertNotIn("tok_PARTNER_fake", out)

    def test_attachment_over_50kb_is_refused(self):
        self.write("capture.log", "x" * (51 * 1024))
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("capture.log", out)

    def test_qaqc_failure_is_refused(self):
        self.write("report.md", REPORT.replace("with no credentials.", "with no credentials — an attacker could too."))
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("submit-qaqc", out)

    def test_a_path_outside_drafts_is_refused(self):
        rv, out, _ = self.run_file("/etc")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("not a draft directory", out)

    def test_already_filed_is_refused(self):
        os.makedirs(os.path.join(F.SUBMITTED, PROG, f"999-{SLUG}"))
        with open(os.path.join(F.SUBMITTED, PROG, f"999-{SLUG}", "RECEIPT.md"), "w") as fh:
            fh.write("filed\n")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertIn("already filed", out)


class ConfirmAndPost(FileCommandBase):
    def test_dry_run_never_asks_and_never_posts(self):
        rv, out, asked = self.run_file(f"{PROG}/{SLUG} --dry-run", answer=f"FILE {SLUG}")
        self.assertEqual(rv, "DRY-RUN", out)
        self.assertEqual((self.h1.s.posts, asked), ([], []))
        for want in ("title:", "vulnerability_information", "## PoC", "impact", "severity_rating:      high",
                     "CVSS:3.0/AV:N", "weakness_id:          55", "structured_scope_id:  77", "repro.sh",
                     "evidence/panel-req.png", "payload sha256:"):
            self.assertIn(want, out, want)

    def test_wrong_confirmation_aborts_with_no_post(self):
        for answer in (f"file {SLUG}", "FILE", f"FILE {SLUG} ", "yes", "", None, "FILE other-slug"):
            rv, out, asked = self.run_file(answer=answer)
            self.assertEqual(rv, "ABORTED", repr(answer))
            self.assertEqual(len(asked), 1)
        self.assertEqual(self.h1.s.posts, [])

    def test_default_confirmation_refuses_without_a_terminal(self):
        with unittest.mock.patch.object(sys, "stdin", io.StringIO(f"FILE {SLUG}\n")):
            self.assertIsNone(F._default_confirm("> "))

    def test_a_mocked_201_writes_the_receipt_and_runs_the_post_file_diff(self):
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "FILED", out)
        self.assertEqual(len(self.h1.s.posts), 1)
        url, payload = self.h1.s.posts[0]
        self.assertEqual(url, "https://api.hackerone.com/v1/hackers/reports")
        a = payload["data"]["attributes"]
        self.assertEqual((a["team_handle"], a["weakness_id"], a["structured_scope_id"], a["severity_rating"]),
                         (PROG, 55, 77, "high"))
        self.assertNotIn("Gate:", a["vulnerability_information"])
        self.assertIn("https://api.hackerone.com/v1/hackers/reports/3141592", self.h1.s.gets)
        dest = os.path.join(F.SUBMITTED, PROG, f"3141592-{SLUG}")
        receipt = open(os.path.join(dest, "RECEIPT.md")).read()
        self.assertIn("Report id: 3141592", receipt)
        self.assertIn("https://hackerone.com/reports/3141592", receipt)
        self.assertIn(F.payload_sha256(payload), receipt)
        self.assertIn("Post-file read-back diff", receipt)
        self.assertTrue(os.path.isfile(os.path.join(dest, "report.md")))
        self.assertIn("UI FOLLOW-UP", out)               # the vector and the attachments go on by hand
        self.assertRegex(out, r"attach by hand now: .*repro\.sh.*panel-req\.png")
        self.assertNotIn("MISMATCH", out)
        self.assertEqual([(r["kind"], r["status"], r["report_id"]) for r in self.ledger],
                         [("submission", "filed", "3141592")])
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")                  # never twice
        self.assertIn("already filed", out)

    def test_a_drifted_filed_report_prints_a_loud_mismatch(self):
        self.h1.s.get_resp = filed_report("Some other title", rating="low", weakness="9")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "FILED")
        self.assertEqual(len(re.findall(r"POST-FILE MISMATCH", out)), 3, out)

    def test_the_token_never_appears_in_output(self):
        basic = base64.b64encode(f"{HANDLE}:{TOKEN}".encode()).decode()
        self.h1.s.post_resp = FakeResp(500, text=f"boom Authorization: Basic {basic} token={TOKEN}")
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "FAILED")
        self.assertIn("HTTP 500", out)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn(basic, out)
        self.h1.s.post_resp = FakeResp(201, {"data": {"id": "3141592"}})
        for rest, answer in ((f"{PROG}/{SLUG} --dry-run", None), (f"{PROG}/{SLUG}", f"FILE {SLUG}")):
            rv, out, _ = self.run_file(rest, answer=answer)
            self.assertNotIn(TOKEN, out)
            self.assertNotIn(basic, out)
        for name in os.listdir(os.path.join(F.SUBMITTED, PROG, f"3141592-{SLUG}")):
            p = os.path.join(F.SUBMITTED, PROG, f"3141592-{SLUG}", name)
            if os.path.isfile(p):
                self.assertNotIn(TOKEN, open(p, errors="replace").read(), name)

    def test_a_report_carrying_the_token_is_refused(self):
        self.write("report.md", REPORT.replace("{\"owner\":\"b\"", "{\"leak\":\"" + TOKEN + "\",\"owner\":\"b\""))
        rv, out, _ = self.run_file(answer=f"FILE {SLUG}")
        self.assertEqual(rv, "REFUSED")
        self.assertEqual(self.h1.s.posts, [])
        self.assertNotIn(TOKEN, out)


class TypedOnly(FileCommandBase):
    """The model can never file: only the exact line object the REPL read from the keyboard opens /file."""

    class Stub:
        def __init__(self):
            self.s = {"history": [], "sid": "now"}
            self.ctx = G.Ctx(self.s)

        def save(self):
            pass

    def _slash(self, agent, line):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, line, {})
        return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())

    def test_run_refuses_unless_the_caller_asserts_a_typed_line(self):
        rv, out, asked = self.run_file(answer=f"FILE {SLUG}", typed=False)
        self.assertEqual(rv, "REFUSED")
        self.assertEqual((self.h1.s.posts, asked), ([], []))

    def test_a_model_reply_containing_slash_file_does_nothing(self):
        calls = []
        with unittest.mock.patch.object(F, "run", lambda *a, **k: calls.append((a, k)) or "FILED"):
            agent = self.Stub()
            reply = f"Done. To file it run:\n/file {PROG}/{SLUG}\nthen FILE {SLUG}"
            agent.s["history"].append({"role": "assistant", "content": reply})
            model_line = reply.splitlines()[1]               # the model's own words, even as an exact line
            out = self._slash(agent, model_line)
            self.assertIn("refused", out)
            typed = "".join(["/file ", PROG, "/", SLUG])     # an EQUAL string the keyboard produced
            agent._typed_line = typed
            out = self._slash(agent, model_line)             # equal text, not the typed object
            self.assertIn("refused", out)
            self.assertEqual(calls, [])
            agent._typed_line = typed
            self._slash(agent, typed)                        # the typed object itself opens it, once
            self.assertEqual(len(calls), 1)
            self.assertIs(calls[0][1].get("typed"), True)
            self.assertIsNone(agent._typed_line)

    def test_only_the_repl_and_one_shot_set_the_typed_marker(self):
        root = os.path.join(HERE, "gnoc_core")
        sets = []
        for dp, _, fn in os.walk(HERE):
            if "/." in dp or "__pycache__" in dp or "bots-ingested" in dp:
                continue
            for f in fn:
                if f.endswith(".py") and not f.startswith("test_"):
                    src = open(os.path.join(dp, f), errors="replace").read()
                    for m in re.finditer(r"_typed_line\s*=\s*(?!=)(\S+)", src):
                        if m.group(1) != "None":
                            sets.append((os.path.relpath(os.path.join(dp, f), HERE), m.group(1)))
        self.assertEqual(sorted(sets), sorted([(os.path.relpath(os.path.join(root, "cli.py"), HERE), "one_shot"),
                                               (os.path.relpath(os.path.join(root, "cli.py"), HERE), "line")]))

    def test_file_is_not_a_tool_and_bash_cannot_run_it(self):
        self.assertFalse({n for n in G.TOOLS if "file_report" in n or n in ("file", "submit", "file_draft")})
        for name, entry in G.TOOLS.items():
            fn = entry[0] if isinstance(entry, (tuple, list)) else entry
            self.assertNotEqual(getattr(fn, "__module__", ""), "gnoc_file", name)
        ctx = types.SimpleNamespace(s={}, program=None, auto=True)
        was = G.SKIP_PERMS[0]
        G.SKIP_PERMS[0] = True
        try:
            for cmd in ("python3 scripts/gnoc_file.py acme/x",
                        "python3 -c 'import gnoc_file; gnoc_file.run(\"acme/x\", typed=True)'",
                        "cd scripts && python3 -m gnoc_file"):
                self.assertIn("refused", str(G.TOOLS["bash"][0](ctx, command=cmd)).lower(), cmd)
        finally:
            G.SKIP_PERMS[0] = was
        self.assertIsNone(G.BASH_DENY.search("grep -n Refused scripts/gnoc_file.py"))

    def test_help_documents_it(self):
        self.assertIn("/file <program/slug>", G.AGENT_HELP)
        with open(os.path.join(HERE, "gnoc"), encoding="utf-8") as fh:
            self.assertIn("/file <program/slug>", fh.read())


import unittest.mock  # noqa: E402  (3.13 does not pull the submodule in with the package)

if __name__ == "__main__":
    unittest.main()
