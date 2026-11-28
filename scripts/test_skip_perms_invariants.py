"""The limits the code says survive `gnoc chat -s-p`, tested as code rather than trusted as a comment.

gnoc_agent's SKIP_PERMS definition states: "The hard limits are code, not prompts, and stay on: scope
gate, BASH_DENY, WRITE_DENY, the secret guard, no submit tool." On 2026-10-25 one of those five was
false - BASH_DENY knew the `gnoc submit` spelling and the raw API URL but not the scripts that
actually POST, so `python3 scripts/h1-submit-report.py --send <dir>` walked through a limit documented
as absolute. The other four held. This file exists so the next one that goes false fails a test.

Every case here must be REFUSED, so nothing is ever written, read or sent by running them.
"""
import os
import re
import shutil
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402


class SkipPermsInvariants(unittest.TestCase):
    def setUp(self):
        self._was = G.SKIP_PERMS[0]
        self._root = list(G._ACTIVE_ROOT)
        G.SKIP_PERMS[0] = True                      # the -s-p case: no approval prompts at all
        # these cases assert about THE repo's protected paths, so name it: another test's temp root
        # must never make "reports/submitted" relative to a checkout the case did not mean
        G._ACTIVE_ROOT[0] = G.WS
        self.ctx = types.SimpleNamespace(s={}, program=None, auto=True)

    def tearDown(self):
        G.SKIP_PERMS[0] = self._was
        G._ACTIVE_ROOT[:] = self._root

    def test_a_write_outside_the_repo_is_refused(self):
        for path in ("/etc/passwd", "~/.ssh/authorized_keys", "~/.bashrc",
                     "~/.claude/settings.json", "~/.config/gnoc/secrets.env",
                     "../../../tmp/soak-escape-probe.txt"):
            out = str(G.TOOLS["write_file"][0](self.ctx, path=path, content="must never land"))
            self.assertIn("refused", out.lower(), path)
        self.assertFalse(os.path.exists("/tmp/soak-escape-probe.txt"))

    def test_a_write_to_a_protected_path_inside_the_repo_is_refused(self):
        for path in ("reports/submitted/x/report.md", ".claude/hooks/evil.sh",
                     ".claude/settings.json", ".git/config"):
            out = str(G.TOOLS["write_file"][0](self.ctx, path=path, content="must never land"))
            self.assertIn("refused", out.lower(), path)

    def test_protected_names_stay_protected_in_another_checkout(self):
        # --repo / a collaborator project moves the active root. The protected names are repo-relative,
        # so they must be refused there too; before the fix the check computed rel only against WS and
        # a session whose root was a temp dir WROTE reports/submitted/x/report.md (suite, 2026-11-17).
        other = tempfile.mkdtemp(prefix="gnoc-other-root-")
        saved = list(G._ACTIVE_ROOT)
        try:
            G._ACTIVE_ROOT[0] = other
            for path in ("reports/submitted/x/report.md", ".claude/hooks/evil.sh",
                         ".claude/settings.json", ".git/config"):
                out = str(G.TOOLS["write_file"][0](self.ctx, path=path, content="must never land"))
                self.assertIn("refused", out.lower(), path)
                self.assertFalse(os.path.exists(os.path.join(other, path)), path)
        finally:
            G._ACTIVE_ROOT[:] = saved
            shutil.rmtree(other, ignore_errors=True)

    def test_bash_refuses_to_read_the_credential_store(self):
        out = str(G.TOOLS["bash"][0](self.ctx, command="cat ~/.config/gnoc/secrets.env"))
        self.assertIn("refused", out.lower())
        # and nothing that looks like a real value came back
        sec = os.path.expanduser("~/.config/gnoc/secrets.env")
        if os.path.exists(sec):
            for ln in open(sec, encoding="utf-8", errors="replace"):
                m = re.match(r'\s*\w+\s*=\s*["\']?([^"\'\s#]{12,})', ln)
                if m:
                    self.assertNotIn(m.group(1), out)

    def test_read_file_cannot_reach_outside_the_repo(self):
        out = str(G.TOOLS["read_file"][0](self.ctx, path="~/.config/gnoc/secrets.env"))
        self.assertIn("no such file in the active repo", out)

    def test_an_out_of_scope_host_is_refused_before_a_request_is_sent(self):
        """.invalid is reserved and unresolvable, and 169.254/16 is link-local: if the gate ever fails
        open, these still reach nobody."""
        # an intaken program to be out of scope OF (a fresh install has none, and "no SCOPE.txt" is a different
        # refusal from the one under test)
        ws = os.path.realpath(tempfile.mkdtemp(prefix="gnoc-sp-ws-"))
        self.addCleanup(shutil.rmtree, ws, True)
        os.makedirs(os.path.join(ws, "targets", "gatewayco"))
        with open(os.path.join(ws, "targets", "gatewayco", "SCOPE.txt"), "w") as fh:
            fh.write("# scope\n=api.gateway.test\n")
        saved = G.WS
        G.WS = ws
        self.addCleanup(setattr, G, "WS", saved)
        ctx = types.SimpleNamespace(s={}, program="gatewayco", auto=True)
        for url, why in (("https://totally-not-in-scope.invalid/", "not-in-scope"),
                         ("http://169.254.169.254/latest/meta-data/", "internal-ip"),
                         ("https://evil.example.invalid/x", "not-in-scope")):
            out = str(G.TOOLS["http_request"][0](ctx, url=url, program="gatewayco"))
            self.assertIn("OUT_OF_SCOPE", out, url)
            self.assertIn(why, out, url)

    def test_no_tool_in_the_registry_can_file_a_report(self):
        names = set(G.TOOLS)
        self.assertFalse({"submit", "file_report", "send_report", "h1_submit"} & names)
        for a in ("submit", "submit --send", "ship", "chat"):
            self.assertEqual(G._gnoc_class(a)[0], "deny", a)

    def test_bash_cannot_run_the_scripts_that_file_a_report(self):
        """The one that was false on 2026-10-25.

        Asserted at RUNTIME, through the tool, not by matching BASH_DENY. A pattern that matches
        proves nothing about whether the tool consults it, and this test asserted only the pattern
        until the agent reviewing this very file said the limits were checked by pattern alone. It
        was wrong about the others - those already drive the real tools - and right about this one."""
        for cmd in ("python3 scripts/h1-submit-report.py --send reports/drafts/x",
                    "./scripts/h1-comment.py 123 'thanks'",
                    "python3 scripts/vdp-autosubmit.py --scan --dry"):
            out = str(G.TOOLS["bash"][0](self.ctx, command=cmd))
            self.assertIn("refused", out.lower(), cmd)
            self.assertTrue(G.BASH_DENY.search(cmd), f"pattern missed: {cmd}")

    def test_the_filing_deny_does_not_catch_its_read_only_neighbours(self):
        """A deny that swallows the QAQC checker would push the next filing round to skip its gates."""
        for cmd in ("python3 scripts/submit-qaqc.py reports/drafts/x",
                    "grep -rn submit scripts/reports.sh"):
            self.assertIsNone(G.BASH_DENY.search(cmd), f"wrongly denied: {cmd}")


if __name__ == "__main__":
    unittest.main()
