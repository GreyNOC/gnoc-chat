#!/usr/bin/env python3
"""Tests for collaborator engagements (scripts/gnoc_collab.py + its gnoc chat wiring).

    python3 scripts/test_gnoc_collab.py [-v]

The contract under test: the partner's INITIAL HANDOFF document is the scope. Finding it must not
mistake the workspace's own HANDOFF-CURRENT.md for a partner handoff, parsing must keep explicit
out-of-scope hosts out, the generated profile must satisfy the existing scope/policy gate without a
bug-bounty program, and opening chat in the project must not enter the hunt stance.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_collab as C  # noqa: E402
import gnoc_agent as G  # noqa: E402
import gnoc_ws as W  # noqa: E402

HANDOFF = """# Acme private engagement - initial handoff

## Objective
Test the private staging plane for our partner.

## Scope
In scope: api.acme.test, *.acme.test, https://portal.acme.test/login
- app.acme.test
Out of scope: admin.acme.test, legacy.acme.test

## Rules of engagement
2 requests per second. Authorization for this engagement is the signed SOW in paperwork/.
No bulk enumeration. Do not test real customer data.

## Accounts
Use the accounts we mint.
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="gnoc-collab-ws-")
        self.project = tempfile.mkdtemp(prefix="partner-acme-")
        os.makedirs(os.path.join(self.ws, "targets"))
        self.saved = (G.WS, list(G._ACTIVE_ROOT), C.WS)
        G.WS = self.ws
        C.WS = self.ws

    def tearDown(self):
        G.WS, root, C.WS = self.saved
        G._ACTIVE_ROOT[:] = root
        shutil.rmtree(self.ws, ignore_errors=True)
        shutil.rmtree(self.project, ignore_errors=True)

    def handoff(self, text=HANDOFF, name="HANDOFF.md"):
        path = os.path.join(self.project, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


class Discovery(Base):
    def test_finds_the_partner_handoff(self):
        path = self.handoff()
        self.assertEqual(C.find_handoff(self.project), path)

    def test_workspace_handoff_series_is_not_a_partner_handoff(self):
        self.handoff(HANDOFF, name="HANDOFF-CURRENT.md")
        self.handoff(HANDOFF, name="CLAUDE-HANDOFF-CRITICAL-10-12.md")
        self.assertIsNone(C.find_handoff(self.project))

    def test_a_plain_scope_document_is_not_an_authorization(self):
        self.handoff("This document describes the scope of the library's parser.", name="SCOPE.md")
        self.assertIsNone(C.find_handoff(self.project))

    def test_readme_alone_is_not_an_engagement(self):
        self.handoff("# A normal project\n\nIn scope: this repo does one thing.", name="README.md")
        self.assertIsNone(C.find_handoff(self.project))

    def test_paperwork_beside_the_handoff_is_listed(self):
        primary = self.handoff()
        os.makedirs(os.path.join(self.project, "paperwork"))
        with open(os.path.join(self.project, "paperwork", "SOW.md"), "w") as fh:
            fh.write("Statement of Work\n")
        found = C.find_paperwork(self.project, primary)
        self.assertEqual([os.path.basename(p) for p in found], ["SOW.md"])

    def test_an_unreadable_handoff_is_reported_not_silently_ignored(self):
        path = os.path.join(self.project, "HANDOFF.md")
        with open(path, "w") as fh:
            fh.write("        ")   # a scan/empty file: a strong name but no text layer
        self.assertEqual(C.find_handoff(self.project), path)
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.assertFalse(got["ok"])
        self.assertIn("no text could be read", got["reason"])
        ctx = G.Ctx({"sid": "test-sid"})
        failed = C.attach(ctx, self.project, self.ws, explicit=True)
        self.assertFalse(failed["ok"])
        self.assertNotIn("program", ctx.s)

    def test_docx_text_is_read_from_its_xml(self):
        path = os.path.join(self.project, "HANDOFF.docx")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("word/document.xml",
                       "<w:document><w:body><w:p><w:r><w:t>In scope: api.acme.test</w:t></w:r></w:p>"
                       "</w:body></w:document>")
        self.assertIn("api.acme.test", C.doc_text(path))

    @unittest.skipUnless(shutil.which("pdftotext") and shutil.which("ps2pdf"),
                         "pdftotext and ps2pdf are needed to build a real PDF here")
    def test_a_pdf_handoff_is_read_and_parsed(self):
        ps = os.path.join(self.project, "handoff.ps")
        with open(ps, "w") as fh:
            fh.write("%!PS-Adobe-3.0\n/Helvetica findfont 12 scalefont setfont\n"
                     "72 720 moveto (Acme partner handoff) show\n"
                     "72 700 moveto (In scope: api.acme.test, *.acme.test) show\n"
                     "72 680 moveto (Out of scope: admin.acme.test) show\n"
                     "72 660 moveto (Authorization: signed statement of work) show\nshowpage\n")
        pdf = os.path.join(self.project, "HANDOFF.pdf")
        r = subprocess.run(["ps2pdf", ps, pdf], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        os.unlink(ps)
        self.assertEqual(C.find_handoff(self.project), pdf)
        parsed = C.parse_scope(C.doc_text(pdf))
        self.assertIn("api.acme.test", parsed["in"])
        self.assertIn("admin.acme.test", parsed["out"])


class ScopeParsing(unittest.TestCase):
    def test_inline_scope_and_exclusions(self):
        parsed = C.parse_scope(HANDOFF)
        self.assertIn("api.acme.test", parsed["in"])
        self.assertIn("*.acme.test", parsed["in"])
        self.assertIn("portal.acme.test", parsed["in"])
        self.assertIn("app.acme.test", parsed["in"])
        self.assertIn("admin.acme.test", parsed["out"])
        self.assertIn("legacy.acme.test", parsed["out"])

    def test_tables_with_a_scope_column(self):
        text = ("| Asset | Type | In scope |\n"
                "|---|---|---|\n"
                "| api.acme.test | API | Yes |\n"
                "| admin.acme.test | Web | No |\n")
        parsed = C.parse_scope(text)
        self.assertIn("api.acme.test", parsed["in"])
        self.assertIn("admin.acme.test", parsed["out"])
        self.assertNotIn("admin.acme.test", parsed["in"])

    def test_out_of_scope_beats_a_wildcard(self):
        parsed = C.parse_scope("## Scope\n*.acme.test\nout of scope: admin.acme.test\n")
        self.assertNotIn("admin.acme.test", parsed["in"])
        self.assertIn("admin.acme.test", parsed["out"])

    def test_a_bare_domain_in_prose_is_not_authorization(self):
        parsed = C.parse_scope("We sometimes look at api.acme.test in conversation.\n")
        self.assertEqual(parsed["in"], [])

    def test_emails_files_and_placeholders_are_not_hosts(self):
        parsed = C.parse_scope("Contact alice@acme.test; see report.md and example.com.\n")
        self.assertNotIn("acme.test", parsed["in"])
        self.assertNotIn("report.md", parsed["in"])
        self.assertNotIn("example.com", parsed["in"])


class ImportProfile(Base):
    def test_import_writes_a_usable_profile(self):
        self.handoff()
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.assertTrue(got["ok"], got)
        self.assertTrue(got["program"].startswith("collab-"), got["program"])
        pdir = os.path.join(self.ws, "targets", got["program"])
        for name in ("SCOPE.txt", "NOSCOPE.txt", "PROGRAM.md", "COLLAB.json"):
            self.assertTrue(os.path.isfile(os.path.join(pdir, name)), name)
        with open(os.path.join(pdir, "COLLAB.json"), encoding="utf-8") as fh:
            meta = json.load(fh)
        self.assertEqual(meta["kind"], "collaborator")
        self.assertEqual(meta["project"], self.project)
        self.assertIn("api.acme.test", meta["hosts"])
        self.assertIn("admin.acme.test", meta["out"])
        with open(os.path.join(pdir, "PROGRAM.md"), encoding="utf-8") as fh:
            program = fh.read()
        self.assertIn("not a public bug-bounty program", program)
        self.assertIn("Authorization for this engagement", program)
        with open(os.path.join(pdir, "SCOPE.txt"), encoding="utf-8") as fh:
            scope_rows = fh.read()
        self.assertIn("api.acme.test", scope_rows)
        self.assertNotIn("admin.acme.test", scope_rows)   # exclusions live in NOSCOPE, never in the allowlist
        with open(os.path.join(pdir, "NOSCOPE.txt"), encoding="utf-8") as fh:
            self.assertIn("admin.acme.test", fh.read())

    def test_second_import_is_idempotent(self):
        self.handoff()
        first = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        second = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.assertTrue(second["unchanged"])
        self.assertEqual(first["program"], second["program"])

    def test_a_specific_handoff_file_can_be_imported_directly(self):
        path = self.handoff()
        got = C.import_handoff("", ws=self.ws, handoff_path=path, consent="explicit")
        self.assertTrue(got["ok"], got)
        self.assertEqual(got["handoff"], path)
        self.assertEqual(got["project"], self.project)
        ctx = G.Ctx({"sid": "test-sid"})
        attached = C.attach(ctx, "", self.ws, handoff_path=path, explicit=True)
        self.assertTrue(attached and attached["ok"], attached)
        self.assertEqual(ctx.s["collab"]["handoff"], path)

    def test_a_changed_handoff_refreshes_the_scope(self):
        self.handoff()
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.handoff(HANDOFF.replace("## Scope\n", "## Scope\nnew.acme.test\n"))
        fresh = C.refresh(got["program"], ws=self.ws)
        self.assertTrue(fresh["ok"], fresh)
        self.assertIn("new.acme.test", fresh["hosts"])
        self.assertFalse(fresh["unchanged"])

    def test_never_overwrites_an_ordinary_program_folder(self):
        self.handoff()
        name = "collab-" + os.path.basename(self.project).lower().replace("_", "-")
        ordinary = os.path.join(self.ws, "targets", name)
        os.makedirs(ordinary)
        with open(os.path.join(ordinary, "SCOPE.txt"), "w") as fh:
            fh.write("real-program.example\n")
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.assertTrue(got["ok"], got)
        self.assertNotEqual(got["program"], name)
        with open(os.path.join(ordinary, "SCOPE.txt")) as fh:
            self.assertEqual(fh.read(), "real-program.example\n")

    def test_no_scope_section_is_reported_not_invented(self):
        self.handoff("This engagement is authorized by the signed agreement.\n")
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        self.assertTrue(got["ok"], got)
        self.assertFalse(got["scope_ok"])
        self.assertEqual(got["hosts"], [])
        self.assertIn("NONE PARSED", C.summary(got["program"], self.ws))


class Gate(Base):
    def test_the_generated_profile_opens_the_existing_gate(self):
        self.handoff()
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        pol, err = G._program_gate(got["program"], "https://api.acme.test/")
        self.assertIsNone(err)
        self.assertTrue((pol or {}).get("network_ok"))
        pol, err = G._program_gate(got["program"], "https://deep.api.acme.test/")
        self.assertIsNone(err)
        _, err = G._program_gate(got["program"], "https://admin.acme.test/")
        self.assertIn("OUT_OF_SCOPE", err)
        self.assertIn("noscope", err)
        _, err = G._program_gate(got["program"], "https://evil.test/")
        self.assertIn("OUT_OF_SCOPE", err)

    def test_a_document_with_no_parsed_host_authorizes_nothing(self):
        self.handoff("This engagement is authorized by the signed agreement.\n")
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        _, err = G._program_gate(got["program"], "https://api.acme.test/")
        self.assertIn("OUT_OF_SCOPE", err)


class ChatWiring(Base):
    def test_attach_sets_the_program_but_not_the_hunt_stance(self):
        self.handoff()
        ctx = G.Ctx({"sid": "test-sid"})
        got = C.attach(ctx, self.project, self.ws, explicit=True)
        self.assertTrue(got and got["ok"], got)
        self.assertEqual(ctx.program, got["program"])
        self.assertNotIn("stance", ctx.s)
        self.assertEqual(ctx.s["program_src"]["program"], got["program"])
        self.assertIn("collaborator handoff", ctx.s["program_src"]["how"])

    def test_launch_dir_names_the_handoff(self):
        self.handoff()
        root, prog, why = G.launch_dir(self.project)
        self.assertEqual(root, self.project)
        self.assertIsNone(prog)
        self.assertIn("collaborator handoff", why)

    def test_collab_prompt_block_says_no_bug_bounty_program_is_needed(self):
        self.handoff()
        ctx = G.Ctx({"sid": "test-sid"})
        C.attach(ctx, self.project, self.ws, explicit=True)
        G._ACTIVE_ROOT[0] = self.project
        block = G._collab_block(ctx)
        self.assertIn("HANDOFF.md", block)
        self.assertIn("api.acme.test", block)
        self.assertIn("Do NOT ask for a bug-bounty program", block)
        self.assertIn("admin.acme.test", block)

    def test_set_program_keeps_the_project_as_the_working_directory(self):
        self.handoff()
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        ctx = G.Ctx({"sid": "test-sid"})
        G._ACTIVE_ROOT[0] = self.ws
        out = G.t_set_program(ctx, got["program"])
        self.assertIn("collaborator engagement", out)
        self.assertEqual(ctx.program, got["program"])
        self.assertEqual(os.path.realpath(G.root()), os.path.realpath(self.project))

    def test_rank_targets_does_not_offer_a_collaboration_as_a_bounty_pick(self):
        self.handoff()
        got = C.import_handoff(self.project, ws=self.ws, consent="explicit")
        real = os.path.join(self.ws, "targets", "real-program")
        os.makedirs(real)
        with open(os.path.join(real, "SCOPE.txt"), "w") as fh:
            fh.write("real-program.example\n")
        names = [r["program"] for r in G.rank_targets()]
        self.assertNotIn(got["program"], names)
        self.assertIn("real-program", names)

    def test_docx_paperwork_reads_as_text_and_as_an_attachment(self):
        self.handoff()
        os.makedirs(os.path.join(self.project, "paperwork"))
        docx = os.path.join(self.project, "paperwork", "SOW.docx")
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("word/document.xml",
                       "<w:document><w:body><w:p><w:r><w:t>Statement of Work</w:t></w:r></w:p>"
                       "<w:p><w:r><w:t>In scope: api.acme.test</w:t></w:r></w:p></w:body></w:document>")
        G._ACTIVE_ROOT[0] = self.project
        ctx = G.Ctx({})
        out = G.t_read_file(ctx, "paperwork/SOW.docx")
        self.assertIn("Statement of Work", out)
        self.assertIn("DOCX document text extracted", out)
        attached = G.expand_mentions("@paperwork/SOW.docx")
        self.assertIn("Statement of Work", attached)
        self.assertIn("document text extracted", attached)

    def test_workspace_setup_treats_the_handoff_as_instructions(self):
        self.handoff()
        self.assertFalse(W.first_open(self.project))
        self.assertEqual(W.instruction_file(self.project), "HANDOFF.md")
        written = W.init_workspace(self.project)
        self.assertTrue(any("kept HANDOFF.md" in line for line in written), written)
        self.assertFalse(os.path.exists(os.path.join(self.project, "GNOC.md")))

    def test_a_handoff_in_a_subdirectory_keeps_its_relative_path(self):
        os.makedirs(os.path.join(self.project, "docs"))
        self.handoff(name=os.path.join("docs", "HANDOFF.md"))
        self.assertEqual(W.instruction_file(self.project), os.path.join("docs", "HANDOFF.md"))
        # the handoff rides the prompt only once the engagement was approved (QAQC 2026-11-19)
        with mock.patch.object(C, "WS", self.ws):
            self.assertNotEqual(G._repo_instructions(self.project)[0], os.path.join("docs", "HANDOFF.md"))
            C.import_handoff(self.project, ws=self.ws, consent="explicit")
            self.assertEqual(G._repo_instructions(self.project)[0], os.path.join("docs", "HANDOFF.md"))


class SlashCollab(Base):
    class _Agent:
        def __init__(self, ctx):
            self.ctx = ctx
            self.s = ctx.s

        def save(self):
            pass

    def _slash(self, agent, line):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, line, {})
        return buf.getvalue()

    def test_import_a_file_and_show_it(self):
        path = self.handoff()
        ctx = G.Ctx({"sid": "slash-sid"})
        agent = self._Agent(ctx)
        out = self._slash(agent, f"/collab import {path}")
        self.assertIn("collaborator engagement ->", out)
        self.assertEqual(ctx.s["collab"]["handoff"], path)
        status = self._slash(agent, "/collab")
        self.assertIn("HANDOFF.md", status)
        self.assertIn("api.acme.test", status)
        self.assertIn("the handoff is the authorization", status)

    def test_status_with_no_engagement_says_how_to_import(self):
        ctx = G.Ctx({"sid": "slash-sid"})
        out = self._slash(self._Agent(ctx), "/collab")
        self.assertIn("no collaborator engagement here", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
