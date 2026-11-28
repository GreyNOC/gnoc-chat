#!/usr/bin/env python3
"""Public and local repo intake for gnoc chat, and the repo map on an untrusted clone.

The defects this file pins (all found 2026-11-27 on a public clone):

- `/repo` and `gnoc chat --repo` accepted only a directory that already existed, so a public repository
  could not be opened from the chat at all.
- repo_map opened a symlink's TARGET: a clone containing `innocent.py -> ~/.ssh/id_rsa` had the target's line
  count and definition names printed into the model's window.
- one generated `.py` file (`x = 1+1+...`) raises RecursionError out of ast.parse, and that escaped repo_map.
- find_symbol answered "not found" when its own search TIMED OUT, because a timed-out search has no hits.
- repo_map kept walking every directory after its file cap, so a large public repo still cost a full walk.

Stdlib unittest, temp dirs, no network (`git clone` reads a local `file://` repo).
"""
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_code  # noqa: E402
import gnoc_repo as R  # noqa: E402
from gnoc_core import cli as C  # noqa: E402
from gnoc_core.state import STATE  # noqa: E402

HAVE_GIT = bool(shutil.which("git"))


def _git(repo, *args, env=None):
    base = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    base.update(env or {})
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False, env=base)


class TempCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-repo-test-")
        self.cache = os.path.join(self.tmp, "cache")
        self.env = mock.patch.dict(os.environ, {"GNOC_REPOS": self.cache})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text, base=None):
        p = os.path.join(base or self.tmp, rel)
        os.makedirs(os.path.dirname(p) or base or self.tmp, exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def git_repo(self, name="work", files=None):
        if not HAVE_GIT:
            self.skipTest("git is not installed")
        repo = os.path.join(self.tmp, name)
        os.makedirs(repo)
        self.assertEqual(_git(repo, "init", "-q", "-b", "main").returncode, 0)
        for rel, text in (files or {"a.py": "def hello():\n    pass\n"}).items():
            self.write(rel, text, base=repo)
        self.assertEqual(_git(repo, "add", "-A").returncode, 0)
        self.assertEqual(_git(repo, "commit", "-qm", "init").returncode, 0)
        return repo


# ---------------------------------------------------------------------------------------------- parse
class TestParse(TempCase):
    def test_a_local_path_is_not_a_remote(self):
        for spec in ("/tmp/x", "~/code/x", "./x", "../x", "C:/x/y", "\\\\server\\share"):
            self.assertIsNone(R.parse_remote(spec), spec)
            self.assertFalse(R.looks_remote(spec), spec)

    def test_github_shapes(self):
        for spec in ("https://github.com/acme/widget", "https://github.com/acme/widget.git",
                     "https://github.com/acme/widget/"):
            got = R.parse_remote(spec)
            self.assertEqual((got.host, got.owner, got.name, got.branch), ("github.com", "acme", "widget", ""), spec)
            self.assertTrue(got.network)
        self.assertEqual(R.parse_remote("acme/widget").url, "https://github.com/acme/widget.git")
        self.assertEqual(R.parse_remote("acme/widget#dev").branch, "dev")
        scp = R.parse_remote("git@github.com:acme/widget.git")
        self.assertEqual((scp.kind, scp.owner, scp.name), ("scp", "acme", "widget"))
        self.assertEqual(R.parse_remote("ssh://git@github.com/acme/widget.git").name, "widget")

    def test_a_browser_tree_url_names_the_repo_and_the_branch(self):
        got = R.parse_remote("https://github.com/acme/widget/tree/main")
        self.assertEqual((got.url, got.branch), ("https://github.com/acme/widget", "main"))
        got = R.parse_remote("https://github.com/acme/widget/tree/feature/src/file.py")
        self.assertEqual((got.owner, got.name, got.branch), ("acme", "widget", "feature"))
        # a fragment cannot override a branch the path already names
        self.assertEqual(R.parse_remote("https://github.com/acme/widget/tree/main#nope").branch, "main")

    def test_a_fragment_is_the_branch_when_the_path_names_none(self):
        self.assertEqual(R.parse_remote("https://github.com/acme/widget#dev").branch, "dev")

    def test_gitlab_and_bitbucket_browser_urls_strip_their_marker(self):
        got = R.parse_remote("https://gitlab.com/group/sub/repo/-/tree/main")
        self.assertEqual((got.url, got.owner, got.name, got.branch),
                         ("https://gitlab.com/group/sub/repo", "group-sub", "repo", "main"))
        got = R.parse_remote("https://bitbucket.org/acme/widget/src/main/file.py")
        self.assertEqual((got.url, got.branch), ("https://bitbucket.org/acme/widget", "main"))
        # a repository actually named src is not a Bitbucket marker
        self.assertEqual(R.parse_remote("https://github.com/acme/src").name, "src")

    def test_a_bad_spec_is_explained(self):
        with self.assertRaises(R.RepoError):
            R.parse_remote("https://github.com/acme")
        with self.assertRaises(R.RepoError):
            R.parse_remote("https://user:token@github.com/acme/widget")
        with self.assertRaises(R.RepoError):
            R.parse_remote("ssh://git:token@github.com/acme/widget.git")
        self.assertTrue(R.looks_remote("https://github.com/acme"))   # a malformed remote is not a local path

    def test_a_file_url_is_local_and_does_not_need_the_network(self):
        got = R.parse_remote("file:///tmp/acme/widget")
        self.assertEqual((got.kind, got.host, got.owner, got.name), ("file", "local", "tmp-acme", "widget"))
        self.assertFalse(got.network)

    def test_the_same_repo_by_https_and_scp_compares_equal(self):
        self.assertEqual(R._norm_url("git@github.com:acme/widget.git"),
                         R._norm_url("https://github.com/acme/widget"))

    def test_a_credential_never_reaches_a_message(self):
        for url in ("https://user:token@github.com/acme/widget",
                    "https://user:token@github.com:bad/acme/widget"):
            self.assertNotIn("token", R._safe_url(url))

    def test_a_name_cannot_climb_out_of_the_cache(self):
        for spec in ("https://github.com/../widget", "https://github.com/acme/.."):
            with self.assertRaises(R.RepoError):
                R.parse_remote(spec)
        # a relative path with .. is a LOCAL path, never a GitHub owner/repo; it opens or says no such folder
        self.assertIsNone(R.parse_remote("acme/../../etc"))

    def test_dest_is_under_the_cache(self):
        dest = R._dest(R.parse_remote("https://github.com/acme/widget"))
        self.assertTrue(dest.startswith(os.path.realpath(self.cache) + os.sep), dest)
        self.assertTrue(dest.endswith(os.path.join("github.com", "acme", "widget")), dest)


# ---------------------------------------------------------------------------------------------- clone
class TestClone(TempCase):
    def test_a_local_remote_is_cloned_once_and_reused(self):
        work = self.git_repo()
        url = "file://" + work
        path, note = R.obtain(url)
        self.assertTrue(os.path.isfile(os.path.join(path, "a.py")))
        self.assertIn("cloned", note)
        self.assertIn("git main @", R.summary(path))
        self.assertIn("clean", R.summary(path))
        path2, note2 = R.obtain(url)
        self.assertEqual(path, path2)
        self.assertEqual(note2, "already cloned")

    def test_a_dirty_checkout_says_how_many_files_changed(self):
        work = self.git_repo()
        path, _ = R.obtain("file://" + work)
        self.write("new.txt", "x", base=path)
        self.assertIn("1 changed file", R.summary(path))

    def test_an_existing_directory_without_git_is_never_deleted(self):
        work = self.git_repo()
        dest = R._dest(R.parse_remote("file://" + work))
        os.makedirs(dest)
        marker = self.write("keep.txt", "do not delete", base=dest)
        with self.assertRaises(R.RepoError):
            R.obtain("file://" + work)
        self.assertTrue(os.path.isfile(marker))
        self.assertIn("not a git checkout", R.summary(dest))

    def test_a_different_origin_is_refused(self):
        work = self.git_repo()
        path, _ = R.obtain("file://" + work)
        self.assertEqual(_git(path, "remote", "set-url", "origin", "https://github.com/other/repo.git").returncode, 0)
        with self.assertRaises(R.RepoError) as ctx:
            R.obtain("file://" + work)
        self.assertIn("another repo", str(ctx.exception))

    def test_a_failed_clone_leaves_no_temp_directory(self):
        with self.assertRaises(R.RepoError):
            R.obtain("file://" + os.path.join(self.tmp, "missing"))
        left = []
        for dp, _dns, fns in os.walk(self.cache):
            left += [os.path.join(dp, f) for f in fns if ".tmp-" in f or ".tmp-" in dp]
        self.assertFalse([p for p in left if ".tmp-" in p], left)
        self.assertFalse(os.path.exists(os.path.join(self.cache, "local", "tmp")))

    def test_a_local_folder_opens_without_cloning(self):
        work = self.git_repo()
        path, note = R.obtain(work)
        self.assertEqual(path, os.path.realpath(work))
        self.assertEqual(note, "")
        with self.assertRaises(R.RepoError):
            R.obtain(os.path.join(self.tmp, "nope"))


# ---------------------------------------------------------------------------------------------- set_repo
class FakeAgent:
    def __init__(self):
        self.s = {"repo": None, "history": [1, 2], "collab": {}}
        self.ctx = types.SimpleNamespace(program=None)
        self.saves = 0

    def save(self):
        self.saves += 1


class TestSetRepo(TempCase):
    def setUp(self):
        super().setUp()
        self.saved = (G.say, G.repo_is_live, G.attach_collab, G._repo_instructions, G.gnoc_goal,
                      G._ACTIVE_ROOT[0], STATE.offline[0], G.PLAIN[0])
        self.out = []
        G.say = self.out.append
        G.repo_is_live = lambda _p: False
        G.attach_collab = lambda _a, _p: False
        G._repo_instructions = lambda _p, cap=9000: ("README.md", "demo")
        G.gnoc_goal = types.SimpleNamespace(scope_to=lambda _p: None)
        G.PLAIN[0] = False
        STATE.offline[0] = False
        self.addCleanup(self._restore)

    def _restore(self):
        (G.say, G.repo_is_live, G.attach_collab, G._repo_instructions, G.gnoc_goal,
         G._ACTIVE_ROOT[0], STATE.offline[0], G.PLAIN[0]) = self.saved

    def test_a_public_url_is_cloned_and_becomes_the_root(self):
        work = self.git_repo()
        agent = FakeAgent()
        self.assertTrue(C.set_repo(agent, "file://" + work))
        self.assertEqual(agent.s["repo"], G._ACTIVE_ROOT[0])
        self.assertTrue(agent.s["repo"].startswith(os.path.realpath(self.cache) + os.sep))
        self.assertEqual(agent.s["history"], [])
        self.assertGreaterEqual(agent.saves, 1)
        banner = "\n".join(self.out)
        self.assertIn("git main @", banner)
        self.assertIn("instructions: README.md", banner)

    def test_a_local_folder_still_opens(self):
        work = self.git_repo()
        agent = FakeAgent()
        self.assertTrue(C.set_repo(agent, work))
        self.assertEqual(G._ACTIVE_ROOT[0], os.path.realpath(work))

    def test_offline_refuses_a_network_clone_before_any_work(self):
        STATE.offline[0] = True
        agent = FakeAgent()
        self.assertFalse(C.set_repo(agent, "https://github.com/acme/widget"))
        self.assertEqual(agent.s["repo"], None)
        self.assertIn("offline mode", "\n".join(self.out))
        self.assertFalse(os.path.exists(self.cache))

    def test_a_credential_url_is_refused(self):
        agent = FakeAgent()
        self.assertFalse(C.set_repo(agent, "https://user:token@github.com/acme/widget"))
        self.assertIn("username/password", "\n".join(self.out))

    def test_a_relative_folder_is_tried_inside_the_open_repo(self):
        work = self.git_repo()
        sub = os.path.join(work, "src", "pkg")
        os.makedirs(sub)
        G._ACTIVE_ROOT[0] = os.path.realpath(work)
        here = os.getcwd()
        self.addCleanup(os.chdir, here)
        os.chdir(self.tmp)                 # the shell is NOT in the active repo (launched from home)
        agent = FakeAgent()
        self.assertTrue(C.set_repo(agent, "src/pkg"))
        self.assertEqual(G._ACTIVE_ROOT[0], os.path.realpath(sub))

    def test_a_missing_folder_says_so(self):
        agent = FakeAgent()
        self.assertFalse(C.set_repo(agent, os.path.join(self.tmp, "missing")))
        self.assertIn("no such directory", "\n".join(self.out))

    def test_help_names_the_new_shapes(self):
        self.assertIn("/repo <path|url|owner/repo|off>", C.AGENT_HELP)
        with open(os.path.join(HERE, "gnoc"), encoding="utf-8") as fh:
            launcher = fh.read()
        self.assertIn("--repo <path|url|owner/repo|website>", launcher)
        with open(os.path.join(HERE, "gnoc_core", "commands.py"), encoding="utf-8") as fh:
            commands = fh.read()
        self.assertIn("/repo <path|url|owner/repo>", commands)   # the bare /repo status line
        self.assertNotIn("repo", C.OPERATOR_COMMANDS)   # /repo is in the public edition


# ---------------------------------------------------------------------------------------------- repo map
class TestRepoMapSafety(TempCase):
    def test_a_symlink_out_of_the_repo_is_never_read(self):
        repo = os.path.join(self.tmp, "repo")
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(repo)
        os.makedirs(outside)
        self.write("creds.py", "def aws_secret_key_prod():\n    return 'AKIA-TOPSECRET'\n", base=outside)
        self.write("app.js", "function hiddenAdminToken() { return 'x'; }\n", base=outside)
        os.symlink(os.path.join(outside, "creds.py"), os.path.join(repo, "innocent.py"))
        os.symlink(os.path.join(outside, "app.js"), os.path.join(repo, "bundle.js"))
        out = gnoc_code.repo_map(repo)
        self.assertNotIn("aws_secret_key_prod", out)
        self.assertNotIn("hiddenAdminToken", out)
        self.assertIn("skipped 2 symlink(s)", out)

    def test_an_ast_recursion_failure_does_not_escape(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(repo)
        self.write("deep.py", "x = " + "+".join(["1"] * 50_000) + "\n", base=repo)
        self.write("ok.py", "def fine():\n    pass\n", base=repo)
        out = gnoc_code.repo_map(repo)
        self.assertIn("deep.py (1 lines)", out)
        self.assertIn("def fine", out)

    def test_the_walk_stops_at_the_cap(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(repo, "a"))
        os.makedirs(os.path.join(repo, "zzz"))
        for i in range(20):
            self.write(f"a/f{i:02}.py", "x = 1\n", base=repo)
        self.write("zzz/sentinel.py", "def sentinel():\n    pass\n", base=repo)
        out = gnoc_code.repo_map(repo, max_files=5)
        self.assertIn("stopped at the 5-file cap", out)
        self.assertNotIn("sentinel", out)

    def test_a_sub_outside_the_repo_is_never_mapped(self):
        repo = os.path.join(self.tmp, "repo")
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(repo)
        os.makedirs(outside)
        self.write("secret.py", "def hidden():\n    pass\n", base=outside)
        out = gnoc_code.repo_map(repo, sub=outside)
        self.assertNotIn("hidden", out)
        self.assertIn("subfolder of", out)

    def test_a_timeout_is_not_reported_as_not_found(self):
        repo = os.path.join(self.tmp, "repo")
        os.makedirs(repo)
        with mock.patch.object(gnoc_code, "_rg", return_value=["__TIMEOUT__"]):
            out = gnoc_code.find_symbol(repo, "missing_name")
        self.assertIn("TIMED OUT", out)
        self.assertIn("NOT evidence", out)
        self.assertNotIn("not found", out.lower())


if __name__ == "__main__":
    unittest.main()
