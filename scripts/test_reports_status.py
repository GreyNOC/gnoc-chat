"""Tests for the reports.sh STATUS.md generator (stdlib unittest, no network, temp workspace)."""
import os
import re
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPORTS_SH = os.path.join(HERE, "reports.sh")


def build_status(ws):
    """Run `reports.sh status` against a fixture workspace and return the generated STATUS.md."""
    env = dict(os.environ, WS=ws)
    subprocess.run(["bash", REPORTS_SH, "status"], env=env, cwd=ws,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
    with open(os.path.join(ws, "reports", "STATUS.md")) as fh:
        return fh.read()


def section(doc, heading):
    m = re.search(r"^## %s.*?(?=^## |\Z)" % re.escape(heading), doc, re.S | re.M)
    return m.group(0) if m else ""


class PendingOnFiledReport(unittest.TestCase):
    """Section 2b describes follow-ups to reports that are ALREADY filed.

    A row that names only a program, a path and a date reads as an unfiled finding: the chat
    agent summarised the tiffany reopen request as a critical "filed but not yet submitted to
    the program". Each row must state the filed report and what kind of document is waiting.
    """

    def setUp(self):
        self.ws = tempfile.mkdtemp()
        d = os.path.join(self.ws, "reports", "submitted", "acme-bbp", "ato-thing-20260930",
                         "triage-reply-20261001")
        os.makedirs(d)
        with open(os.path.join(d, "REOPEN-REQUEST.md"), "w") as fh:
            fh.write("reopen please\n")
        self.doc = build_status(self.ws)
        self.sec = section(self.doc, "2b.")

    def test_the_section_exists_for_a_reopen_request_under_submitted(self):
        self.assertTrue(self.sec, "section 2b missing:\n" + self.doc)

    def test_the_row_names_the_filed_report_and_the_document_kind(self):
        row = [l for l in self.sec.splitlines() if "ato-thing-20260930" in l and l.startswith("|")]
        self.assertEqual(len(row), 1, self.sec)
        row = row[0]
        self.assertIn("`ato-thing-20260930`", row)
        self.assertIn("reopen request", row)
        self.assertIn("acme-bbp", row)

    def test_the_heading_and_preamble_say_the_report_is_already_filed(self):
        self.assertIn("ALREADY-FILED", self.sec)
        self.assertIn("Nothing here is an unfiled finding.", self.sec)

    def test_a_reply_is_labelled_as_a_reply_not_a_reopen(self):
        d = os.path.join(self.ws, "reports", "submitted", "acme-bbp", "other-20261002")
        os.makedirs(d)
        with open(os.path.join(d, "REPLY-triager.md"), "w") as fh:
            fh.write("hi\n")
        sec = section(build_status(self.ws), "2b.")
        row = [l for l in sec.splitlines() if "other-20261002" in l and l.startswith("|")][0]
        self.assertIn("reply to the triager", row)
        self.assertNotIn("reopen request", row)


if __name__ == "__main__":
    unittest.main()


class DraftCountPerProgram(unittest.TestCase):
    """Asked "how many drafts do we have for gatewayco", the agent read section 4, found one gatewayco row and
    answered "1 draft". Gatewayco has three; the other two sit in section 5 under Held (2026-10-25). Every
    section is a SLICE, and nothing said so, so counting one of them gave a wrong total."""

    def setUp(self):
        import glob
        import shutil
        import subprocess
        ws = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if not glob.glob(os.path.join(ws, "reports", "drafts", "*", "*", "report.md")):
            # A fresh install has no drafts, and an empty count is printed as "None.", so there is nothing to
            # count: count a fixture's instead (one program with a held draft, one handle with an underscore).
            ws = tempfile.mkdtemp(prefix="gnoc-drafts-")
            self.addCleanup(shutil.rmtree, ws, True)
            for prog, slug, held in (("acme-bbp", "idor-a", False), ("acme-bbp", "idor-b", True),
                                     ("beta_vdp", "xss-c", False)):
                d = os.path.join(ws, "reports", "drafts", prog, slug)
                os.makedirs(d)
                with open(os.path.join(d, "report.md"), "w") as fh:
                    fh.write("CVSS: 6.5\nAsset: app.example.test\nCWE: CWE-639\n\n# a draft\n")
                if held:
                    with open(os.path.join(d, "HELD-REASON.md"), "w") as fh:
                        fh.write("**Unlock:** a second account\n")
        # WS: this checkout's own workspace (reports.sh otherwise falls back to its install default)
        subprocess.run(["bash", REPORTS_SH, "status"],
                       capture_output=True, text=True, timeout=180, cwd=ws, env=dict(os.environ, WS=ws))
        self.text = open(os.path.join(ws, "reports/STATUS.md")).read()
        self.ws = ws

    def test_the_totals_block_exists_and_warns_that_sections_are_slices(self):
        self.assertIn("## 3b. Draft count per program", self.text)
        self.assertIn("EVERY live draft, whatever section it appears in", self.text)
        self.assertIn("Counting the", self.text)
        self.assertIn("gives a wrong total", self.text)

    def test_the_slice_headings_say_they_are_slices(self):
        self.assertIn("not staged (a SLICE of 3b, not the total)", self.text)
        self.assertIn("one named unlock (a SLICE of 3b, not the total)", self.text)

    def test_the_count_matches_what_is_on_disk(self):
        import glob
        import re as _re
        block = self.text.split("## 3b.")[1].split("## 4.")[0]
        for row in _re.findall(r"^\| ([a-z0-9_-]+) \| (\d+) \|", block, _re.M):
            prog, n = row[0], int(row[1])
            on_disk = len([d for d in glob.glob(os.path.join(self.ws, "reports/drafts", prog, "*"))
                           if os.path.isfile(os.path.join(d, "report.md"))])
            self.assertEqual(n, on_disk, f"{prog}: table says {n}, disk has {on_disk}")

    def test_the_table_has_its_header(self):
        block = self.text.split("## 3b.")[1].split("## 4.")[0]
        self.assertIn("| Program | Live drafts | States |", block)
        self.assertLess(block.index("| Program | Live drafts | States |"), block.index("|---|---|---|"))


class UnderscoreProgramHandles(unittest.TestCase):
    """`<venue>_<program>_<slug>` was split on the first underscore, with a comment asserting that no
    program handle contains one. program-19, program-32, program-60, program-50 and program-65 all
    do. program-19/autorelease-... was read as program "massive", slug "public_autorelease-...",
    the dedup check then missed the real row, and a PHANTOM held draft appeared for a program with
    nothing on disk (2026-10-25)."""

    def setUp(self):
        import subprocess
        self.ws = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        subprocess.run(["bash", os.path.join(self.ws, "scripts/reports.sh"), "status"],
                       capture_output=True, text=True, timeout=180, cwd=self.ws, env=dict(os.environ, WS=self.ws))
        self.rows = [ln.split("\t") for ln in
                     open(os.path.join(self.ws, ".claude/state/hunt-loop/pipeline.tsv")).read().splitlines()
                     if "\t" in ln]

    def test_no_row_names_a_program_directory_that_does_not_exist(self):
        for r in self.rows:
            if len(r) < 4 or r[0] in ("ARCHIVE", "SUBMITTED", "CLOSED", "ORPHAN"):
                continue
            prog = r[2]
            self.assertTrue(os.path.isdir(os.path.join(self.ws, "reports/drafts", prog))
                            or os.path.isdir(os.path.join(self.ws, "reports/leads", prog))
                            or os.path.isdir(os.path.join(self.ws, "targets", prog)),
                            f"row names program {prog!r}, which has no directory: {r[:4]}")

    def test_the_split_is_not_on_the_first_underscore(self):
        src = open(os.path.join(self.ws, "scripts/reports.sh")).read()
        self.assertIn("longest match first", src)
        self.assertNotIn("no program handle here contains an underscore", src)

    def test_an_underscore_program_keeps_its_whole_handle(self):
        named = {r[2] for r in self.rows if len(r) > 2}
        self.assertNotIn("massive", named, "program-19 must not be truncated to massive")
