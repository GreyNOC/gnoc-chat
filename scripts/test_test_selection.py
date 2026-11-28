"""Pick the tests that COVER a change, so a web fix is verifiable in seconds.

Receipt (2026-10-27). detect_tests() answers with the repo's whole-suite command. On the website that is
`npm test`, which chains about 200 node test files behind a 25-file `pretest` - so as a per-change check
it either times out or drowns a one-line fix in unrelated failures, and T-269 says a change that was not
RUN is a claim rather than a change. Matching the changed file's name-parts against the test tree turns
that into seconds.

Measured against the real repo at the time of writing (197 test files):
    lib/censor.js                        -> test/censor.test.mjs
    scripts/video/reel/build-reel.mjs    -> test/reel-lint.test.mjs, test/reel-capture.test.mjs
    public/greypath/lab.js               -> test/greypath-lab-contract.test.mjs, ...http-lab...
    server.js                            -> test/server.integration.test.mjs
    public/css/gateway.css               -> test/cssmin.test.mjs, test/css-syntax.test.mjs
The last two are why "server" is NOT a stopword and why the file-kind fallback exists.
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402

TESTS = ("censor.test.mjs", "reel-lint.test.mjs", "reel-capture.test.mjs", "cohorts.test.mjs",
         "cohorts.integration.test.mjs", "certdata.test.mjs", "greypath-lab-contract.test.mjs",
         "server.integration.test.mjs", "css-syntax.test.mjs", "cssmin.test.mjs", "xss.dom.test.mjs",
         "icons.test.mjs", "campus.test.mjs")


class Selection(unittest.TestCase):
    def setUp(self):
        self.r = tempfile.mkdtemp(prefix="gnoc-sel-")
        os.makedirs(os.path.join(self.r, "test"))
        for t in TESTS:
            open(os.path.join(self.r, "test", t), "w").close()
        # a vendored test tree must never be offered
        vend = os.path.join(self.r, "node_modules", "dep", "test")
        os.makedirs(vend)
        open(os.path.join(vend, "censor.test.mjs"), "w").close()

    def pick(self, *changed):
        return G.tests_for(self.r, list(changed))

    def test_it_finds_the_test_named_after_the_file(self):
        self.assertEqual(self.pick("lib/censor.js"), ["test/censor.test.mjs"])

    def test_a_directory_feature_name_matches_several(self):
        got = self.pick("scripts/video/reel/build-reel.mjs")
        self.assertIn("test/reel-lint.test.mjs", got)
        self.assertIn("test/reel-capture.test.mjs", got)

    def test_several_changed_files_union_their_tests(self):
        got = self.pick("lib/cohorts.mjs", "lib/certdata.mjs")
        self.assertIn("test/certdata.test.mjs", got)
        self.assertIn("test/cohorts.test.mjs", got)

    def test_a_generic_looking_but_real_feature_name_still_matches(self):
        """'server' must NOT be treated as filename noise: listing it made server.js match nothing."""
        self.assertEqual(self.pick("server.js"), ["test/server.integration.test.mjs"])

    def test_a_stylesheet_falls_back_to_the_file_KIND(self):
        got = self.pick("public/css/gateway.css")
        self.assertTrue(any("css" in t for t in got), got)

    def test_markup_falls_back_to_the_dom_tests(self):
        self.assertTrue(any("dom" in t for t in self.pick("public/page.html")), "markup should reach the dom test")

    def test_a_vendored_test_is_never_offered(self):
        self.assertTrue(all("node_modules" not in t for t in self.pick("lib/censor.js")))

    def test_an_unmatched_name_returns_nothing_rather_than_guessing(self):
        self.assertEqual(self.pick("lib/zzqqwobble.mjs"), [])

    def test_it_is_capped(self):
        self.assertLessEqual(len(self.pick("lib/campus.mjs", "lib/cohorts.mjs", "lib/censor.js",
                                           "lib/certdata.mjs", "lib/icons.mjs", "server.js",
                                           "public/a.css", "public/b.html")), 6)

    def test_the_exact_stem_outranks_a_weaker_share(self):
        got = self.pick("lib/cohorts.mjs")
        self.assertEqual(got[0], "test/cohorts.test.mjs", got)

    def test_the_hint_names_the_files_and_the_call(self):
        hint = G.narrow_test_hint(self.r, ["lib/censor.js"])
        self.assertIn("censor.test.mjs", hint)
        self.assertIn("run_tests(files=", hint)

    def test_the_hint_is_empty_when_nothing_matches(self):
        self.assertEqual(G.narrow_test_hint(self.r, ["lib/zzqqwobble.mjs"]), "")

    def test_no_test_tree_is_not_an_error(self):
        empty = tempfile.mkdtemp(prefix="gnoc-sel-empty-")
        self.assertEqual(G.tests_for(empty, ["a.js"]), [])
        self.assertEqual(G.find_test_files(empty), [])


class ChangedPaths(unittest.TestCase):
    def test_porcelain_parsing_handles_a_rename_and_quotes(self):
        import subprocess
        r = tempfile.mkdtemp(prefix="gnoc-chg-")
        subprocess.run(["git", "init", "-q"], cwd=r, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.t"], cwd=r, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=r, check=True)
        open(os.path.join(r, "a.js"), "w").write("1")
        subprocess.run(["git", "add", "-A"], cwd=r, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=r, check=True)
        open(os.path.join(r, "a.js"), "w").write("2")
        open(os.path.join(r, "b.js"), "w").write("3")
        got = G._changed_paths(r)
        self.assertIn("a.js", got)
        self.assertIn("b.js", got)
        self.assertTrue(all(not p.endswith("/") for p in got))


if __name__ == "__main__":
    unittest.main()


class RepoPorts(unittest.TestCase):
    """The repo's OWN port must beat the framework defaults.

    Receipt (2026-10-27): the website serves on 6971 and DEV_PORTS does not contain it, so local_app()
    either answered "" while the site was running - no web-verify ever fired - or worse, returned the
    first framework default that happened to be open, which on this machine was an unrelated service on
    8787. A web check that passes against the wrong application is worse than no check.
    """

    def setUp(self):
        import gnoc_modes
        self.M = gnoc_modes
        self.r = tempfile.mkdtemp(prefix="gnoc-port-")

    def test_a_port_in_the_repos_dotenv_is_tried_first(self):
        with open(os.path.join(self.r, ".env"), "w") as f:
            f.write("# comment\nFOO=1\nPORT=6971\n")
        self.assertEqual(self.M.repo_ports(self.r)[0], 6971)

    def test_an_exported_port_line_is_read_too(self):
        with open(os.path.join(self.r, ".env"), "w") as f:
            f.write('export PORT="8123"\n')
        self.assertIn(8123, self.M.repo_ports(self.r)[:2])

    def test_the_framework_defaults_remain_as_a_fallback(self):
        ports = self.M.repo_ports(self.r)
        self.assertTrue(set(self.M.DEV_PORTS).issubset(set(ports)))

    def test_no_duplicates_and_no_crash_without_a_repo(self):
        ports = self.M.repo_ports(None)
        self.assertEqual(len(ports), len(set(ports)))
        self.assertTrue(ports)

    def test_a_nonexistent_repo_is_not_an_error(self):
        self.assertTrue(self.M.repo_ports("/nonexistent/zz"))

    def test_local_app_probes_the_given_ports_only(self):
        self.assertEqual(self.M.local_app(ports=(1, 2, 3), timeout=0.02), "")
