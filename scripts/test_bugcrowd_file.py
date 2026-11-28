"""Unit tests for the pure parts of scripts/bugcrowd-file.py. No network, no CDP.

The FORM.md fixture copies the SHAPE of a real Bugcrowd draft (program-28 vault fixation):
free-text lines, a 'Target group:' line that must NOT be read as the target, an 'Asset:' line
that is, a VRT line with a trailing '(P3)', and a CVSS line telling the filer to leave it empty.
"""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("bugcrowd_file", HERE / "bugcrowd-file.py")
BF = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(BF)

FORM_FIXTURE = """# Bugcrowd submission form - exampleprog (NOT FILED; the user approval required)

Engagement: exampleprog
Target group: Staging @ example.jp

Title: Vault accepts access_token from the URL
Asset: vault-staging.example.com
CWE: CWE-384 Session Fixation
VRT: broken_authentication_and_session_management.session_fixation.remote_attack_vector (P3)
CVSS: LEAVE THIS FIELD EMPTY. Do not type a number in. The honest CVSS 3.1 here is only 3.5 Low.

Description: paste SUBMIT-BODY.txt verbatim.
Attachments: upload every file in upload-bundle/, NOT MANIFEST.md.
"""

TAXONOMY = {"metadata": {"release_date": "fixture"}, "content": [
    {"id": "broken_authentication_and_session_management", "name": "Broken Authentication and Session Management",
     "type": "category", "children": [
         {"id": "authentication_bypass", "name": "Authentication Bypass", "type": "subcategory", "priority": 1},
         {"id": "session_fixation", "name": "Session Fixation", "type": "subcategory", "children": [
             {"id": "remote_attack_vector", "name": "Remote Attack Vector", "type": "variant", "priority": 3},
             {"id": "local_attack_vector", "name": "Local Attack Vector", "type": "variant", "priority": 5}]}]},
    {"id": "sensitive_data_exposure", "name": "Sensitive Data Exposure", "type": "category", "children": [
        {"id": "disclosure_of_secrets", "name": "Disclosure of Secrets", "type": "subcategory", "children": [
            {"id": "for_publicly_accessible_asset", "name": "For Publicly Accessible Asset",
             "type": "variant", "priority": 1},
            {"id": "pii_leakage_exposure", "name": "PII Leakage/Exposure", "type": "variant", "priority": None}]}]},
]}


class FormParser(unittest.TestCase):
    def test_fixture_shape(self):
        f = BF.parse_form(FORM_FIXTURE)
        self.assertEqual(f["engagement"], "exampleprog")
        self.assertEqual(f["target"], "vault-staging.example.com")   # not the Target group line
        self.assertEqual(f["vrt_id"],
                         "broken_authentication_and_session_management.session_fixation.remote_attack_vector")
        self.assertEqual(f["cvss_mode"], "empty")
        self.assertIsNone(f["cvss_vector"])
        self.assertIsNone(f["terms"])

    def test_target_line_wins_over_asset(self):
        f = BF.parse_form("Asset: a.example.com\nTarget: Example API (a.example.com)\n")
        self.assertEqual(f["target"], "Example API (a.example.com)")

    def test_cvss_vector_both_spellings(self):
        v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        self.assertEqual(BF.parse_form("CVSS: " + v + "\n")["cvss_vector"], v)
        f = BF.parse_form(v + "\n")
        self.assertEqual((f["cvss_mode"], f["cvss_vector"]), ("vector", v))

    def test_cvss_absent_is_none(self):
        self.assertIsNone(BF.parse_form("Engagement: x\n")["cvss_mode"])

    def test_terms(self):
        self.assertIs(BF.parse_form("Terms: accept\n")["terms"], True)
        self.assertIs(BF.parse_form("Terms and conditions: check the box\n")["terms"], True)
        self.assertIs(BF.parse_form("Terms: do not accept\n")["terms"], False)

    def test_markdown_bold_keys_and_backticks(self):
        f = BF.parse_form("**Engagement:** `prog-1`\n**VRT:** `a.b.c`\n")
        self.assertEqual((f["engagement"], f["vrt_id"]), ("prog-1", "a.b.c"))


class VrtResolver(unittest.TestCase):
    def test_variant_path(self):
        v = BF.resolve_vrt_path(TAXONOMY,
                                "broken_authentication_and_session_management.session_fixation.remote_attack_vector")
        self.assertEqual(v["path"], ["Broken Authentication and Session Management", "Session Fixation",
                                     "Remote Attack Vector"])
        self.assertEqual(v["badge"],
                         "Broken Authentication and Session Management > Session Fixation > Remote Attack Vector")
        self.assertEqual(v["priority"], 3)

    def test_two_level_leaf(self):
        v = BF.resolve_vrt_path(TAXONOMY, "broken_authentication_and_session_management.authentication_bypass")
        self.assertEqual(len(v["path"]), 2)
        self.assertEqual(v["priority"], 1)

    def test_parent_refused(self):
        with self.assertRaises(ValueError):
            BF.resolve_vrt_path(TAXONOMY, "sensitive_data_exposure.disclosure_of_secrets")

    def test_unknown_refused(self):
        with self.assertRaises(ValueError):
            BF.resolve_vrt_path(TAXONOMY, "sensitive_data_exposure.nope.x")

    def test_bare_list_taxonomy(self):
        v = BF.resolve_vrt_path(TAXONOMY["content"],
                                "sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset")
        self.assertEqual(v["path"][-1], "For Publicly Accessible Asset")

    def test_floor(self):
        self.assertTrue(all(BF.vrt_floor_ok(p) for p in (1, 2, 3)))
        self.assertFalse(any(BF.vrt_floor_ok(p) for p in (4, 5, None)))

    def test_apply_vrt_refuses_p5_and_varies(self):
        for leaf in ("broken_authentication_and_session_management.session_fixation.local_attack_vector",
                     "sensitive_data_exposure.disclosure_of_secrets.pii_leakage_exposure"):
            with self.assertRaises(BF.Needs):
                BF.apply_vrt({"vrt_id": leaf}, TAXONOMY, "fixture")

    def test_real_taxonomy_has_fixture_leaf(self):
        with open(BF.LOCAL_VRT) as fh:
            v = BF.resolve_vrt_path(json.load(fh),
                                    "broken_authentication_and_session_management.session_fixation.remote_attack_vector")
        self.assertEqual(v["priority"], 3)


class Attachments(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def put(self, name, data):
        (self.d / name).write_bytes(data)

    def test_excludes_manifest_and_sorts(self):
        self.put("MANIFEST.md", b"m")
        self.put("b.png", b"bb")
        self.put("a.zip", b"aa")
        names = [a["name"] for a in BF.build_attachments(self.d)]
        self.assertEqual(names, ["a.zip", "b.png"])

    def test_duplicate_md5_refused(self):
        self.put("one.png", b"same")
        self.put("two.png", b"same")
        with self.assertRaisesRegex(ValueError, "duplicate md5"):
            BF.build_attachments(self.d)

    def test_oversize_refused(self):
        self.put("big.bin", b"x" * 11)
        with self.assertRaisesRegex(ValueError, "over 10 bytes"):
            BF.build_attachments(self.d, max_bytes=10)

    def test_default_cap_is_50mb(self):
        self.assertEqual(BF.MAX_BYTES, 50 * 1024 * 1024)

    def test_subdir_dotfile_empty_missing_refused(self):
        (self.d / "sub").mkdir()
        with self.assertRaises(ValueError):
            BF.build_attachments(self.d)
        (self.d / "sub").rmdir()
        self.put(".hidden", b"h")
        with self.assertRaises(ValueError):
            BF.build_attachments(self.d)
        os.remove(self.d / ".hidden")
        self.put("empty.png", b"")
        with self.assertRaises(ValueError):
            BF.build_attachments(self.d)
        with self.assertRaises(ValueError):
            BF.build_attachments(self.d / "nope")

    def test_manifest_only_is_zero_attachments(self):
        self.put("MANIFEST.md", b"m")
        self.assertEqual(BF.build_attachments(self.d), [])


class TitleConfirm(unittest.TestCase):
    def test_confirm_byte_for_byte(self):
        raw = "Vault accepts access_token from the URL\n".encode()
        self.assertTrue(BF.confirm_matches("Vault accepts access_token from the URL", raw))
        self.assertFalse(BF.confirm_matches("Vault accepts access_token from the URL ", raw))
        self.assertFalse(BF.confirm_matches("vault accepts access_token from the URL", raw))
        self.assertFalse(BF.confirm_matches(None, raw))
        self.assertTrue(BF.confirm_matches("T", b"T"))

    def test_title_guards(self):
        self.assertEqual(BF.title_from_file(b"Hello\n"), "Hello")
        for bad in (b"# Hello\n", b"a\nb\n", b"\n", b" Hello\n"):
            with self.assertRaises(ValueError):
                BF.title_from_file(bad)


class PageHelpers(unittest.TestCase):
    U = "11111111-2222-3333-4444-555555555555"

    def test_classify(self):
        self.assertEqual(BF.classify_page("https://bugcrowd.com/x", "t", "", True), "form")
        self.assertEqual(BF.classify_page("https://identity.bugcrowd.com/login", "", "", False), "login")
        self.assertEqual(BF.classify_page("https://bugcrowd.com/user/sign_in", "", "", False), "login")
        self.assertEqual(BF.classify_page("https://bugcrowd.com/e", "403 Forbidden", "", False), "forbidden")
        self.assertEqual(BF.classify_page("https://bugcrowd.com/e", "Oops", "server error", False), "other")

    def test_urls(self):
        self.assertTrue(BF.form_url_ok("https://bugcrowd.com/engagements/p/submissions/new", "p"))
        self.assertTrue(BF.form_url_ok("https://bugcrowd.com/engagements/p/submissions/%s/edit" % self.U, "p"))
        self.assertFalse(BF.form_url_ok("https://bugcrowd.com/engagements/q/submissions/new", "p"))
        self.assertEqual(BF.edit_uuid("https://bugcrowd.com/engagements/p/submissions/%s/edit" % self.U), self.U)
        self.assertIsNone(BF.extract_submission("https://bugcrowd.com/engagements/p/submissions/%s/edit" % self.U))
        s = BF.extract_submission("https://bugcrowd.com/submissions/%s" % self.U)
        self.assertEqual(s["id"], self.U)
        self.assertIsNone(BF.extract_submission("https://bugcrowd.com/dashboard"))


def _expected(atts=("a.png", "b.zip"), cvss_mode="empty", terms=True):
    return {"engagement": "p", "title": "T", "target": "host.example.com",
            "vrt_badge": "A > B > C", "vrt_id": "a.b.c", "desc_sha256": "ab" * 32, "desc_len": 10,
            "attachments": [{"name": n} for n in atts], "cvss_mode": cvss_mode,
            "cvss_vector": "CVSS:3.1/AV:N" if cvss_mode == "vector" else None, "terms": terms}


def _observed(**kw):
    o = {"url": "https://bugcrowd.com/engagements/p/submissions/11111111-2222-3333-4444-555555555555/edit",
         "title": "T", "target": "host.example.com", "vrt_label": "A > B > C", "vrt_id": "a.b.c",
         "desc_sha256": "ab" * 32, "desc_len": 10, "attachments": ["b.zip", "a.png"],
         "attachment_extras": ["a.png", "b.zip"], "cvss_values": ["", ""], "terms": True, "turnstile_len": 709}
    o.update(kw)
    return o


class VerificationDiff(unittest.TestCase):
    def fails(self, exp, obs, phase="prepare"):
        return [r["field"] for r in BF.blocking_failures(BF.verification_diff(exp, obs, phase))]

    def test_clean(self):
        self.assertEqual(self.fails(_expected(), _observed(), "submit"), [])

    def test_each_field_mismatch(self):
        cases = {"title": {"title": "T2"}, "target": {"target": "other"}, "vrt_label": {"vrt_label": "P1"},
                 "vrt_id": {"vrt_id": "x.y.z"}, "desc_sha256": {"desc_sha256": "00" * 32},
                 "desc_len": {"desc_len": 11}, "url": {"url": "https://bugcrowd.com/engagements/zz/submissions/new"},
                 "cvss": {"cvss_values": ["3.5"]}}
        for field, mut in cases.items():
            self.assertIn(field, self.fails(_expected(), _observed(**mut)), field)

    def test_vrt_needs_both_label_and_id(self):
        # the hidden id alone is the silent-no-op failure mode; label alone is the P1-badge trap
        self.assertEqual(self.fails(_expected(), _observed(vrt_label=None)), ["vrt_label"])
        self.assertEqual(self.fails(_expected(), _observed(vrt_id="")), ["vrt_id"])

    def test_attachments_missing_and_extra(self):
        f = self.fails(_expected(), _observed(attachments=["a.png"]))
        self.assertIn("attachments", f)
        self.assertIn("attachment_count", f)
        f = self.fails(_expected(), _observed(attachment_extras=["a.png", "b.zip", "stale.png"]))
        self.assertEqual(f, ["attachment_extras"])

    def test_turnstile_blocks_submit_only(self):
        self.assertEqual(self.fails(_expected(), _observed(turnstile_len=0), "prepare"), [])
        self.assertEqual(self.fails(_expected(), _observed(turnstile_len=0), "submit"), ["turnstile"])

    def test_terms(self):
        self.assertEqual(self.fails(_expected(terms=True), _observed(terms=False)), ["terms"])
        self.assertEqual(self.fails(_expected(terms=None), _observed(terms=False), "prepare"), [])
        self.assertEqual(self.fails(_expected(terms=None), _observed(terms=False), "submit"), ["terms"])

    def test_cvss_vector_mode(self):
        exp = _expected(cvss_mode="vector")
        self.assertEqual(self.fails(exp, _observed(cvss_values=["CVSS:3.1/AV:N/AC:L"])), [])
        self.assertEqual(self.fails(exp, _observed(cvss_values=[""])), ["cvss"])

    def test_format_has_no_em_dash(self):
        txt = BF.format_rows(BF.verification_diff(_expected(), _observed(title="x")))
        self.assertNotIn(chr(0x2014), txt)
        self.assertIn("FAIL", txt)


class Ledger(unittest.TestCase):
    def test_ship_row_passes_live_validator(self):
        spec = importlib.util.spec_from_file_location("hunt_state", HERE / "hunt-state.py")
        hs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hs)
        tmp = Path(tempfile.mkdtemp())
        try:
            smd = tmp / "SUBMITTED.md"
            smd.write_text("x")
            row = BF.ship_row("prog", "slug", smd, {"id": "u", "url": "https://bugcrowd.com/submissions/u"},
                              "prog", "2026-11-09T00:00:00Z")
            self.assertEqual(hs.validate_ship(row), [])
            self.assertEqual((row["kind"], row["status"]), ("submission", "submitted"))
        finally:
            shutil.rmtree(tmp)


class CliRefusesBeforeCdp(unittest.TestCase):
    """The CLI must refuse on disk-only checks without ever touching CDP (port 1 is never used)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.d = self.root / "prog" / "slug"
        (self.d / "upload-bundle").mkdir(parents=True)
        (self.d / "SUBMIT-TITLE.txt").write_bytes(b"Exact title\n")
        (self.d / "SUBMIT-BODY.txt").write_bytes(b"## Summary\nbody\n")
        (self.d / "FORM.md").write_text(FORM_FIXTURE)
        (self.d / "upload-bundle" / "a.png").write_bytes(b"png")
        os.environ["BUGCROWD_FILE_DRAFTS"] = str(self.root)

    def tearDown(self):
        os.environ.pop("BUGCROWD_FILE_DRAFTS", None)
        shutil.rmtree(self.root)

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = BF.main(list(argv))
        return rc, buf.getvalue()

    def test_submit_wrong_confirm(self):
        rc, out = self.run_cli("submit", "prog/slug", "--confirm", "Exact title ", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("byte for byte", out)

    def test_submit_without_prepare(self):
        rc, out = self.run_cli("submit", "prog/slug", "--confirm", "Exact title", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("run prepare first", out)

    def test_submit_requires_confirm_flag(self):
        with self.assertRaises(SystemExit):
            with redirect_stdout(io.StringIO()), unittest.mock.patch("sys.stderr", io.StringIO()):
                BF.main(["submit", "prog/slug"])

    def test_submit_after_attempt_never_retries(self):
        (self.d / BF.STATE_NAME).write_text(json.dumps({"target_id": "t", "submit_attempted": "2026",
                                                        "submit_result": "FAILED-SILENT"}))
        rc, out = self.run_cli("submit", "prog/slug", "--confirm", "Exact title", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("never retried", out)

    def test_prepare_refuses_sub_p3_leaf_before_cdp(self):
        (self.d / "FORM.md").write_text(FORM_FIXTURE.replace("remote_attack_vector", "local_attack_vector"))
        rc, out = self.run_cli("prepare", "prog/slug", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("P3", out)
        self.assertNotIn("CDP", out)

    def test_prepare_refuses_duplicate_attachment(self):
        (self.d / "upload-bundle" / "b.png").write_bytes(b"png")
        rc, out = self.run_cli("prepare", "prog/slug", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("duplicate md5", out)

    def test_prepare_refuses_engagement_disagreement(self):
        rc, out = self.run_cli("prepare", "prog/slug", "--engagement", "other", "--cdp-port", "1")
        self.assertEqual(rc, 4)
        self.assertIn("disagrees", out)

    def test_bad_draft_spec(self):
        rc, out = self.run_cli("prepare", "../etc", "--cdp-port", "1")
        self.assertEqual(rc, 4)

    def test_load_expected_digest(self):
        exp = BF.load_expected(self.d)
        self.assertEqual(exp["desc_sha256"], hashlib.sha256(b"## Summary\nbody\n").hexdigest())
        self.assertEqual(exp["desc_len"], len("## Summary\nbody\n"))
        self.assertEqual(exp["title"], "Exact title")
        self.assertEqual(exp["engagement"], "exampleprog")


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main(verbosity=1)
