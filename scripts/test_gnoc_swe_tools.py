#!/usr/bin/env python3
"""Tests for the software-engineering tool surface added 2026-11-19: honest truncation in read_file / grep,
edit_file's replace_all / edits / notebook cells and the stale-file guard, git's new actions and their approval
rules, run_tests name= / files=['failed'] / per-language runners, typecheck, bg (background processes),
find_symbol's precise mode (jedi and a stand-in language server), the operator's hooks and slash commands,
native MCP tools, and the isolated builder's git worktree.

Stdlib unittest, temp dirs only, no model, no network.

    python3 -m pytest -q scripts/test_gnoc_swe_tools.py
"""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_bg  # noqa: E402
import gnoc_code  # noqa: E402
import gnoc_hooks  # noqa: E402
import gnoc_lsp  # noqa: E402
import gnoc_mcp  # noqa: E402
import gnoc_typecheck  # noqa: E402
import gnoc_worktree  # noqa: E402
from gnoc_core import testing as T  # noqa: E402

HAVE_GIT = bool(shutil.which("git"))
HAVE_PYTEST = importlib.util.find_spec("pytest") is not None


def _git(repo, *args):
    # never inherit GIT_DIR / GIT_INDEX_FILE: run from a pre-commit hook, `git -C <tmp>` otherwise commits into
    # the repository being committed (it moved the workspace's main branch once, 2026-11-19)
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False,
                          env=gnoc_worktree.git_env())


class RepoCase(unittest.TestCase):
    """A temp repo as the active root, agent state in a temp dir, hooks/commands in a temp GNOC_HOME."""

    git = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-swe-")
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.saved = (G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0])
        G.AGENT_DIR = os.path.join(self.tmp, "agent")
        G._ACTIVE_ROOT[0] = self.repo
        G.SKIP_PERMS[0] = False
        self.env = mock.patch.dict(os.environ, {"GNOC_HOME": self.home, "GNOC_BG_DIR": os.path.join(self.tmp, "bg"),
                                                "GNOC_WORKTREE_DIR": os.path.join(self.tmp, "wt")})
        self.env.start()
        for k in gnoc_worktree.GIT_LOCATION_VARS:   # a git hook's variables must not reach any git call here
            os.environ.pop(k, None)
        self.ctx = G.Ctx({"sid": "swe-test"})
        if self.git:
            if not HAVE_GIT:
                self.skipTest("git is not installed")
            _git(self.repo, "init", "-q", "-b", "main")
            _git(self.repo, "config", "user.email", "t@example.invalid")
            _git(self.repo, "config", "user.name", "t")
            _git(self.repo, "config", "commit.gpgsign", "false")
            self.write("a.py", "x = 1\n")
            _git(self.repo, "add", "-A")
            _git(self.repo, "commit", "-q", "-m", "first")

    def tearDown(self):
        gnoc_bg.stop_all()
        gnoc_bg._PROCS.clear()
        self.env.stop()
        G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0] = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text):
        p = os.path.join(self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p

    def read(self, rel):
        with open(os.path.join(self.repo, rel)) as f:
            return f.read()

    def ex(self, name, args):
        return G._exec(name, args, self.ctx)


# ---------------------------------------------------------------------------------------------- read / grep
class TestHonestTruncation(RepoCase):
    def test_long_line_is_marked_and_explained(self):
        self.write("min.js", "a\n" + "b" * 1000 + "\n")
        out = self.ex("read_file", {"path": "min.js"})
        self.assertIn("...[+600 chars]", out)
        self.assertIn("line(s) 2 are longer than 400", out)

    def test_short_lines_carry_no_marker(self):
        self.write("s.py", "x = 1\n")
        self.assertNotIn("chars]", self.ex("read_file", {"path": "s.py"}))

    def test_grep_reports_the_per_file_cap(self):
        self.write("sub/many.py", "".join(f"hit{i}\n" for i in range(30)))
        out = self.ex("grep", {"pattern": "hit", "path": "."})
        self.assertIn("stopped at 20 matches", out)
        one = self.ex("grep", {"pattern": "hit", "path": "sub/many.py"})
        self.assertNotIn("stopped at", one)
        self.assertEqual(one.count("hit"), 30)
        self.write("big.txt", "".join(f"m{i}\n" for i in range(250)))
        self.assertIn("stopped at 200 matches", self.ex("grep", {"pattern": "m", "path": "big.txt"}))

    def test_grep_marks_long_lines(self):
        self.write("w.txt", "needle" + "z" * 500 + "\n")
        out = self.ex("grep", {"pattern": "needle", "path": "."})
        self.assertIn("...[+", out)
        self.assertIn("long line(s) shown cut", out)

    def test_grep_options(self):
        self.write("c.py", "Alpha\nbeta\nGAMMA\n")
        self.assertIn("Alpha", self.ex("grep", {"pattern": "alpha", "path": ".", "ignore_case": True}))
        self.assertIn("(no matches", self.ex("grep", {"pattern": "alpha", "path": "."}))
        files = self.ex("grep", {"pattern": "beta", "path": ".", "files_only": True})
        self.assertEqual(files.strip(), "c.py")
        ctx = self.ex("grep", {"pattern": "beta", "path": ".", "context": 1})
        self.assertIn("Alpha", ctx)
        self.assertIn("GAMMA", ctx)


# ---------------------------------------------------------------------------------------------- edit_file
class TestEditModes(RepoCase):
    def test_replace_all(self):
        self.write("r.py", "foo(1)\nfoo(2)\nbar(foo)\n")
        refused = self.ex("edit_file", {"path": "r.py", "old": "foo", "new": "baz"})
        self.assertIn("replace_all=true", refused)
        out = self.ex("edit_file", {"path": "r.py", "old": "foo", "new": "baz", "replace_all": True})
        self.assertIn("3 occurrences", out)
        self.assertEqual(self.read("r.py"), "baz(1)\nbaz(2)\nbar(baz)\n")

    def test_edits_apply_in_order(self):
        self.write("m.py", "a = 1\nb = 2\n")
        out = self.ex("edit_file", {"path": "m.py", "edits": [{"old": "a = 1", "new": "a = 10"},
                                                              {"old": "b = 2", "new": "b = 20"}]})
        self.assertIn("2 edits", out)
        self.assertEqual(self.read("m.py"), "a = 10\nb = 20\n")

    def test_edits_are_all_or_nothing(self):
        self.write("m.py", "a = 1\nb = 2\n")
        out = self.ex("edit_file", {"path": "m.py", "edits": [{"old": "a = 1", "new": "a = 10"},
                                                              {"old": "missing", "new": "x"}]})
        self.assertIn("edit 2 of 2", out)
        self.assertIn("nothing was changed", out)
        self.assertEqual(self.read("m.py"), "a = 1\nb = 2\n")

    def test_edits_can_be_undone(self):
        self.write("u.py", "a = 1\n")
        self.ex("edit_file", {"path": "u.py", "edits": [{"old": "a = 1", "new": "a = 2"}]})
        G.undo(self.ctx, 1)
        self.assertEqual(self.read("u.py"), "a = 1\n")

    def test_preview_covers_edits_and_replace_all(self):
        self.write("p.py", "k\nk\n")
        rows = G._preview("edit_file", {"path": "p.py", "old": "k", "new": "j", "replace_all": True})
        self.assertTrue(rows)
        rows = G._preview("edit_file", {"path": "p.py", "edits": [{"old": "k\nk", "new": "z"}]})
        self.assertTrue(rows)


class TestStaleGuard(RepoCase):
    def test_line_edit_refused_after_an_outside_change(self):
        self.write("s.py", "one\ntwo\nthree\n")
        self.ex("read_file", {"path": "s.py"})
        time.sleep(0.01)
        self.write("s.py", "zero\none\ntwo\nthree\n")   # someone inserted a line above
        out = self.ex("edit_file", {"path": "s.py", "start_line": 2, "end_line": 2, "new": "TWO"})
        self.assertIn("changed on disk since you last read", out)
        self.assertEqual(self.read("s.py"), "zero\none\ntwo\nthree\n")
        self.ex("read_file", {"path": "s.py"})
        out = self.ex("edit_file", {"path": "s.py", "start_line": 3, "end_line": 3, "new": "TWO"})
        self.assertIn("edited", out)
        self.assertEqual(self.read("s.py"), "zero\none\nTWO\nthree\n")

    def test_own_edits_do_not_trip_the_guard(self):
        self.write("s.py", "one\ntwo\n")
        self.ex("read_file", {"path": "s.py"})
        self.ex("edit_file", {"path": "s.py", "old": "one", "new": "uno"})
        out = self.ex("edit_file", {"path": "s.py", "start_line": 2, "end_line": 2, "new": "dos"})
        self.assertIn("edited", out)

    def test_exact_text_edit_still_works_after_an_outside_change(self):
        self.write("s.py", "one\ntwo\n")
        self.ex("read_file", {"path": "s.py"})
        time.sleep(0.01)
        self.write("s.py", "one\ntwo\nthree\n")
        self.assertIn("edited", self.ex("edit_file", {"path": "s.py", "old": "two", "new": "2"}))

    def test_a_resumed_session_does_not_see_everything_as_stale(self):
        self.write("j.py", "a\nb\n")
        self.ex("read_file", {"path": "j.py"})
        self.ctx.s["_seen_files"] = json.loads(json.dumps(self.ctx.s["_seen_files"]))   # saved and reloaded
        self.assertIn("edited", self.ex("edit_file", {"path": "j.py", "start_line": 1, "end_line": 1, "new": "A"}))

    def test_whole_file_write_refused_over_an_outside_change(self):
        self.write("w.py", "a\n")
        self.ex("read_file", {"path": "w.py"})
        time.sleep(0.01)
        self.write("w.py", "a\nb\n")
        out = self.ex("write_file", {"path": "w.py", "content": "c\n"})
        self.assertIn("changed on disk", out)
        self.assertEqual(self.read("w.py"), "a\nb\n")


class TestNotebook(RepoCase):
    NB = {"cells": [{"cell_type": "markdown", "metadata": {}, "source": ["# Title\n"]},
                    {"cell_type": "code", "metadata": {}, "execution_count": 1, "source": ["print(1)\n", "x = 2"],
                     "outputs": [{"output_type": "stream", "name": "stdout", "text": ["1\n"]}]}],
          "metadata": {"kernelspec": {"language": "python"}}, "nbformat": 4, "nbformat_minor": 5}

    def setUp(self):
        super().setUp()
        self.write("n.ipynb", json.dumps(self.NB, indent=1))

    def test_reads_as_cells(self):
        out = self.ex("read_file", {"path": "n.ipynb"})
        self.assertIn("--- cell 0 [markdown] ---", out)
        self.assertIn("--- cell 1 [code, run 1] ---", out)
        self.assertIn("print(1)\nx = 2", out)
        self.assertIn(">>> output", out)

    def test_replace_insert_delete(self):
        self.assertIn("replaced cell 1", self.ex("edit_file", {"path": "n.ipynb", "cell": 1, "new": "y = 3\nz = 4"}))
        nb = json.loads(self.read("n.ipynb"))
        self.assertEqual(nb["cells"][1]["source"], ["y = 3\n", "z = 4"])
        self.assertEqual(nb["cells"][1]["outputs"], [])
        self.ex("edit_file", {"path": "n.ipynb", "cell": 2, "cell_action": "insert", "new": "## end",
                              "cell_type": "markdown"})
        self.assertEqual(json.loads(self.read("n.ipynb"))["cells"][2]["cell_type"], "markdown")
        self.ex("edit_file", {"path": "n.ipynb", "cell": 0, "cell_action": "delete"})
        self.assertEqual(len(json.loads(self.read("n.ipynb"))["cells"]), 2)

    def test_bad_cell_refused(self):
        self.assertIn("does not exist", self.ex("edit_file", {"path": "n.ipynb", "cell": 9, "new": "x"}))


class TestImageRead(RepoCase):
    @unittest.skipUnless(importlib.util.find_spec("PIL"), "pillow is not installed")
    def test_no_vision_model_says_so(self):
        from PIL import Image
        Image.new("RGB", (8, 8)).save(os.path.join(self.repo, "shot.png"))
        with mock.patch.object(G, "_vision_model", lambda: None):
            out = self.ex("read_file", {"path": "shot.png"})
        self.assertIn("No vision model is installed", out)

    def test_an_undecodable_image_gets_the_plain_answer(self):
        p = self.write("bad.png", "")
        with open(p, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n" + b"\0" * 32)
        with mock.patch("gnoc_vision.describe", side_effect=AssertionError("must not be asked")):
            out = self.ex("read_file", {"path": "bad.png"})
        if importlib.util.find_spec("PIL"):
            self.assertIn("binary PNG image", out)

    @unittest.skipUnless(importlib.util.find_spec("PIL"), "pillow is not installed")
    def test_vision_model_description_is_relayed(self):
        from PIL import Image
        p = os.path.join(self.repo, "shot.png")
        Image.new("RGB", (8, 8), (200, 30, 30)).save(p)
        with mock.patch("gnoc_vision.describe", return_value=("fake-vl", "a login form with a red error")):
            out = self.ex("read_file", {"path": "shot.png", "question": "any errors?"})
        self.assertIn("a login form with a red error", out)
        self.assertIn("fake-vl", out)


# ---------------------------------------------------------------------------------------------- git
class TestGit(RepoCase):
    git = True

    def test_blame_branch_switch_stash_restore(self):
        blame = self.ex("git", {"action": "blame", "paths": ["a.py"], "lines": "1,1"})
        self.assertIn("x = 1", blame)
        self.assertIn("created branch feat", self.ex("git", {"action": "branch", "ref": "feat"}))
        self.assertIn("feat", self.ex("git", {"action": "branch"}))
        self.write("a.py", "x = 2\n")
        self.assertIn("uncommitted changes", self.ex("git", {"action": "switch", "ref": "feat"}))
        self.ex("git", {"action": "stash", "op": "push", "message": "wip"})
        self.assertEqual(self.read("a.py"), "x = 1\n")
        self.assertIn("wip", self.ex("git", {"action": "stash", "op": "list"}))
        self.assertIn("feat", self.ex("git", {"action": "switch", "ref": "feat"}))
        self.ex("git", {"action": "stash", "op": "pop"})
        self.assertEqual(self.read("a.py"), "x = 2\n")
        self.assertIn("restored", self.ex("git", {"action": "restore", "paths": ["a.py"]}))
        self.assertEqual(self.read("a.py"), "x = 1\n")

    def test_option_shaped_refs_refused(self):
        self.assertIn("refused", self.ex("git", {"action": "show", "ref": "--output=/tmp/x"}))
        self.assertIn("refused", self.ex("git", {"action": "branch", "ref": "-D main"}))

    def test_push_to_a_remote_never_forces(self):
        bare = os.path.join(self.tmp, "remote.git")
        subprocess.run(["git", "init", "-q", "--bare", bare], check=True)
        _git(self.repo, "remote", "add", "origin", bare)
        self.assertIn("refused", self.ex("git", {"action": "push"}))   # on main without ref=main
        out = self.ex("git", {"action": "push", "ref": "main"})
        self.assertNotIn("refused", out)
        self.assertEqual(_git(bare, "rev-parse", "main").returncode, 0)

    def test_approval_rules(self):
        auto = G.Ctx({"auto": True})
        for a in ({"action": "status"}, {"action": "blame", "paths": ["a.py"]}, {"action": "branch"},
                  {"action": "stash", "op": "list"}, {"action": "pr", "op": "view"}):
            self.assertTrue(G._git_reads(a), a)
            self.assertFalse(G._approval_required("git", a, self.ctx), a)
        for a in ({"action": "branch", "ref": "x"}, {"action": "switch", "ref": "x"}, {"action": "restore"},
                  {"action": "stash", "op": "pop"}):
            self.assertFalse(G._git_reads(a), a)
            self.assertTrue(G._approval_required("git", a, self.ctx), a)
            self.assertFalse(G._approval_required("git", a, auto), a)
        for a in ({"action": "commit"}, {"action": "push"}, {"action": "pr", "op": "create"}):
            self.assertTrue(G._approval_required("git", a, auto), a)   # every time, /auto or not


# ---------------------------------------------------------------------------------------------- tests / types
class TestRunTests(RepoCase):
    def test_argv_per_language(self):
        r = self.repo
        self.assertEqual(T.test_argv(r, os.path.join(r, "x_test.go"), name="TestX")[0],
                         ["go", "test", "./.", "-run", "TestX"])
        self.assertEqual(T.test_argv(r, os.path.join(r, "tests", "api.rs"), name="t")[0],
                         ["cargo", "test", "--test", "api", "t"])
        self.assertEqual(T.test_argv(r, os.path.join(r, "a.test.mjs"))[0], ["node", os.path.join(r, "a.test.mjs")])
        self.assertIn("--test-name-pattern=add", T.test_argv(r, os.path.join(r, "a.test.mjs"), name="add")[0])
        self.write("package.json", json.dumps({"devDependencies": {"vitest": "1"}}))
        self.assertEqual(T.test_argv(r, os.path.join(r, "a.test.ts"), name="adds")[0],
                         ["npx", "--no-install", "vitest", "run", "a.test.ts", "-t", "adds"])
        self.assertEqual(T.suite_with_name("python3 -m pytest -q", "foo")[0], "python3 -m pytest -q -k 'foo'")
        self.assertEqual(T.suite_with_name("go test ./...", "TestA")[0], "go test ./... -run 'TestA'")
        self.assertIn("ignored", T.suite_with_name("make test", "x")[1])

    @unittest.skipUnless(HAVE_PYTEST, "pytest is not installed")
    def test_name_filter_and_rerun_failed(self):
        self.write("test_m.py", "def test_good():\n    assert True\n\ndef test_bad():\n    assert False\n")
        out = self.ex("run_tests", {"files": ["test_m.py"], "name": "good"})
        self.assertIn("1/1 test command passed", out)
        out = self.ex("run_tests", {"files": ["test_m.py"]})
        self.assertIn("FAIL", out)
        self.write("test_m.py", "def test_good():\n    assert True\n\ndef test_bad():\n    assert True\n")
        out = self.ex("run_tests", {"files": ["failed"]})
        self.assertIn("1/1 test command passed", out)
        self.assertIn("nothing failed", self.ex("run_tests", {"files": ["failed"]}))

    @unittest.skipUnless(HAVE_PYTEST, "pytest is not installed")
    def test_a_name_that_matches_nothing_fails(self):
        self.write("test_n.py", "def test_one():\n    assert True\n")
        out = self.ex("run_tests", {"files": ["test_n.py"], "name": "nosuchtest"})
        self.assertIn("no test matched", out)
        self.assertIn("0/1", out)


class TestTypecheck(RepoCase):
    def fake_bin(self, name, script):
        b = os.path.join(self.tmp, "bin")
        os.makedirs(b, exist_ok=True)
        p = os.path.join(b, name)
        with open(p, "w") as f:
            f.write("#!/bin/sh\n" + script)
        os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
        return b

    def test_nothing_to_check(self):
        self.write("README.md", "hi\n")
        out = self.ex("typecheck", {})
        self.assertTrue("nothing to type-check" in out or "no type checker" in out, out)

    def test_runs_mypy_and_reports_errors(self):
        self.write("pyproject.toml", "[tool.mypy]\n")
        self.write("m.py", "x: int = 'a'\n")
        b = self.fake_bin("mypy", "echo \"m.py:1: error: Incompatible types\"; exit 1\n")
        with mock.patch.dict(os.environ, {"PATH": b + os.pathsep + os.environ.get("PATH", "")}):
            out = self.ex("typecheck", {"files": ["m.py"]})
        self.assertIn("ERRORS (1) mypy", out)
        self.assertIn("Incompatible types", out)

    def test_own_script_wins(self):
        self.write("package.json", json.dumps({"scripts": {"typecheck": "tsc -p ."}}))
        self.assertEqual(gnoc_typecheck.plan(self.repo)[0][0], "npm run -s typecheck")


# ---------------------------------------------------------------------------------------------- bg
class TestBackground(RepoCase):
    def test_start_output_stop(self):
        out = self.ex("bg", {"action": "start", "name": "srv", "command": "echo ready; sleep 30", "wait": 2})
        self.assertIn("started srv", out)
        self.assertIn("ready", out)
        self.assertIn("running", self.ex("bg", {"action": "list"}))
        self.assertIn("already running", self.ex("bg", {"action": "start", "name": "srv", "command": "true"}))
        self.assertIn("stopped srv", self.ex("bg", {"action": "stop", "name": "srv"}))
        self.assertNotIn("running,", self.ex("bg", {"action": "list"}))

    def test_send_to_stdin_and_new_output_only(self):
        self.ex("bg", {"action": "start", "name": "cat", "command": "cat", "wait": 0})
        self.ex("bg", {"action": "send", "name": "cat", "text": "hello there"})
        out = self.ex("bg", {"action": "output", "name": "cat", "wait": 2})
        self.assertIn("hello there", out)
        self.assertIn("(no new output)", self.ex("bg", {"action": "output", "name": "cat"}))

    def test_tty_mode(self):
        self.ex("bg", {"action": "start", "name": "t", "command": "test -t 0 && echo IS_A_TTY; sleep 5",
                       "tty": True, "wait": 2})
        self.assertIn("IS_A_TTY", self.ex("bg", {"action": "log", "name": "t"}))

    def test_bash_gates_apply(self):
        out = self.ex("bg", {"action": "start", "name": "x", "command": "shutdown -h now"})
        self.assertIn("deny list", out)
        self.assertNotIn("x", gnoc_bg._PROCS)

    def test_approval(self):
        self.assertTrue(G._approval_required("bg", {"action": "start", "command": "npm run dev"}, self.ctx))
        self.assertFalse(G._approval_required("bg", {"action": "output", "name": "x"}, self.ctx))
        self.assertTrue(G._bg_reads({"action": "list"}))


# ---------------------------------------------------------------------------------------------- navigation
class TestNavigation(RepoCase):
    def test_methods_and_more_languages(self):
        self.write("c.ts", "export class Agent {\n  async turn(x: string) {\n    this.turn(x);\n  }\n}\n")
        self.write("B.java", "public class Bee {\n  public int run(int x) {\n    return run(x);\n  }\n}\n")
        self.write("a.rs", "pub struct Foo {}\nimpl Foo {\n  pub fn bar(&self) {}\n}\n")
        out = gnoc_code.find_symbol(self.repo, "Agent.turn")
        self.assertIn("DEFINED (1)", out)
        self.assertIn("c.ts:2", out)
        self.assertIn("B.java:2", gnoc_code.find_symbol(self.repo, "run").split("USED")[0])
        m = gnoc_code.repo_map(self.repo)
        self.assertIn("class Bee", m)
        self.assertIn("fn bar", m)

    @unittest.skipUnless(importlib.util.find_spec("jedi"), "jedi is not installed")
    def test_jedi_definition_and_references(self):
        self.write("lib.py", "def helper(x):\n    return x\n")
        self.write("use.py", "from lib import helper\n\nhelper(1)\nhelper(2)\n")
        out = self.ex("find_symbol", {"name": "helper", "path": "use.py", "line": 3})
        self.assertIn("DEFINITION via jedi", out)
        self.assertIn("lib.py:1", out)
        out = self.ex("find_symbol", {"name": "helper", "path": "use.py", "line": 3, "action": "references"})
        self.assertIn("REFERENCES via jedi", out)
        self.assertIn("use.py:4", out)

    def test_name_not_on_line_falls_back_and_says_so(self):
        self.write("q.py", "a = 1\n")
        out = self.ex("find_symbol", {"name": "nothere", "path": "q.py", "line": 1})
        self.assertIn("no precise answer", out)

    def test_lsp_client_against_a_stand_in_server(self):
        server = os.path.join(self.tmp, "fake_lsp.py")
        with open(server, "w") as f:
            f.write(textwrap.dedent('''
                import json, sys
                def read():
                    h = {}
                    while True:
                        ln = sys.stdin.buffer.readline()
                        if not ln: sys.exit(0)
                        ln = ln.decode().strip()
                        if not ln: break
                        k, _, v = ln.partition(":"); h[k.lower()] = v.strip()
                    return json.loads(sys.stdin.buffer.read(int(h["content-length"])))
                def send(o):
                    b = json.dumps(o).encode()
                    sys.stdout.buffer.write(b"Content-Length: %d\\r\\n\\r\\n" % len(b) + b); sys.stdout.buffer.flush()
                while True:
                    m = read()
                    if "id" not in m: continue
                    if m["method"] == "textDocument/definition":
                        uri = m["params"]["textDocument"]["uri"]
                        send({"jsonrpc": "2.0", "id": m["id"], "result": [{"uri": uri, "range": {
                            "start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 3}}}]})
                    else:
                        send({"jsonrpc": "2.0", "id": m["id"], "result": {}})
            '''))
        p = self.write("main.go", "func foo() {}\nfoo()\n")
        who, rows = gnoc_lsp._lsp(self.repo, p, 2, 0, "definition", argv=[sys.executable, server])
        self.assertEqual(rows, [(p, 1)])


# ---------------------------------------------------------------------------------------------- hooks
class TestHooks(RepoCase):
    def user_hooks(self, d):
        with open(os.path.join(self.home, "hooks.json"), "w") as f:
            json.dump(d, f)

    def test_pre_hook_blocks_and_post_hook_reports(self):
        self.write("migrations/1.sql", "x\n")
        self.write("app.py", "a = 1\n")
        self.user_hooks({"pre_tool": [{"tools": "edit_file|write_file", "files": "migrations/*",
                                       "command": "echo 'generated: never hand-edit' >&2; exit 2"}],
                         "post_tool": [{"tools": "edit_file", "files": "*.py",
                                        "command": "echo checked $GNOC_FILES"}]})
        out = self.ex("edit_file", {"path": "migrations/1.sql", "old": "x", "new": "y"})
        self.assertIn("BLOCKED by your user pre_tool hook", out)
        self.assertIn("never hand-edit", out)
        self.assertEqual(self.read("migrations/1.sql"), "x\n")
        out = self.ex("edit_file", {"path": "app.py", "old": "a = 1", "new": "a = 2"})
        self.assertIn("checked app.py", out)

    def test_post_hook_that_rewrites_keeps_the_stale_guard_quiet(self):
        self.write("f.py", "a = 1\nb = 2\n")
        self.user_hooks({"post_tool": [{"tools": "edit_file", "command": "sed -i 's/  */ /g' $GNOC_FILES; echo fmt"}]})
        self.ex("read_file", {"path": "f.py"})
        self.ex("edit_file", {"path": "f.py", "old": "a = 1", "new": "a  =  1"})
        out = self.ex("edit_file", {"path": "f.py", "start_line": 2, "end_line": 2, "new": "b = 3"})
        self.assertIn("edited", out)

    def test_repo_hooks_need_trust_and_lapse_on_change(self):
        self.write("x.py", "a\n")
        self.write(".gnoc/hooks.json", json.dumps({"pre_tool": [{"tools": "edit_file", "command": "exit 2"}]}))
        self.assertEqual(gnoc_hooks.repo_state(self.repo), "untrusted")
        self.assertIn("edited", self.ex("edit_file", {"path": "x.py", "old": "a", "new": "b"}))
        gnoc_hooks.trust(self.repo)
        self.assertIn("BLOCKED", self.ex("edit_file", {"path": "x.py", "old": "b", "new": "c"}))
        self.write(".gnoc/hooks.json", json.dumps({"pre_tool": [{"tools": "edit_file", "command": "exit 2 "}]}))
        self.assertEqual(gnoc_hooks.repo_state(self.repo), "changed")
        self.assertIn("edited", self.ex("edit_file", {"path": "x.py", "old": "b", "new": "c"}))

    def test_refused_call_runs_no_post_hook(self):
        self.user_hooks({"post_tool": [{"tools": ".*", "command": "echo SHOULD_NOT_RUN"}]})
        self.assertNotIn("SHOULD_NOT_RUN", self.ex("read_file", {"path": "/etc/passwd"}))

    def test_custom_commands(self):
        os.makedirs(os.path.join(self.home, "commands"))
        with open(os.path.join(self.home, "commands", "fixpr.md"), "w") as f:
            f.write("description: fix a PR\nFix pull request $ARGUMENTS and run the tests.\n")
        self.write(".gnoc/commands/fixpr.md", "---\ndescription: repo version\n---\nRepo fix for $ARGUMENTS\n")
        cmds = gnoc_hooks.commands(self.repo)
        self.assertEqual(cmds["fixpr"][1], "repo version")
        self.assertEqual(gnoc_hooks.expand(self.repo, "fixpr", "42"), "Repo fix for 42")
        self.assertIsNone(gnoc_hooks.expand(self.repo, "nope", ""))


# ---------------------------------------------------------------------------------------------- MCP
FAKE_MCP = r'''
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    meth, rid = m["method"], m["id"]
    if meth == "initialize":
        res = {"protocolVersion": "2024-11-05", "capabilities": {}, "serverInfo": {"name": "fake"}}
    elif meth == "tools/list":
        res = {"tools": [{"name": "echo", "description": "echo text back",
                          "inputSchema": {"$schema": "x", "type": "object", "properties": {"text": {"type": "string"}},
                                          "required": ["text"]}}]}
    elif meth == "tools/call":
        res = {"content": [{"type": "text", "text": "ECHO " + m["params"]["arguments"].get("text", "")}]}
    elif meth == "resources/list":
        res = {"resources": [{"uri": "mem://a", "name": "a"}]}
    elif meth == "resources/read":
        res = {"contents": [{"uri": "mem://a", "text": "resource body"}]}
    else:
        res = {}
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
'''


class TestNativeMcp(RepoCase):
    def setUp(self):
        super().setUp()
        self.ws = os.path.join(self.tmp, "ws")
        os.makedirs(self.ws)
        srv = os.path.join(self.tmp, "fake_mcp.py")
        with open(srv, "w") as f:
            f.write(FAKE_MCP)
        gnoc_mcp.add_server("fake", {"transport": "stdio", "command": sys.executable, "args": [srv]}, ws=self.ws)
        self.saved_ws = G.WS
        G.WS = self.ws

    def tearDown(self):
        G.WS = self.saved_ws
        G.register_mcp_tools()
        super().tearDown()

    def test_tools_become_native_and_callable(self):
        n = G.register_mcp_tools(refresh=True)
        self.assertEqual(n, 1)
        name = "mcp__fake__echo"
        self.assertIn(name, G.TOOLS)
        schema = G.TOOLS[name][1]["function"]["parameters"]
        self.assertNotIn("$schema", schema)
        self.assertEqual(schema["required"], ["text"])
        self.assertIn(name, G.CODE_TOOLS)
        self.assertIn("ECHO hi", G._exec(name, {"text": "hi"}, self.ctx))
        self.assertTrue(hasattr(G.TOOLS[name][0], "__wrapped__"))
        self.assertGreater(len(G.TOOLS[name][1]["function"]["description"]), 20)
        self.assertTrue(G._approval_required(name, {"text": "hi"}, self.ctx))

    def test_cache_drops_a_server_whose_config_changed(self):
        G.register_mcp_tools(refresh=True)
        conf = gnoc_mcp.servers(self.ws)["fake"]
        gnoc_mcp.add_server("fake", dict(conf, args=conf["args"] + ["--changed"]), ws=self.ws)
        self.assertEqual(G.register_mcp_tools(), 0)
        self.assertNotIn("mcp__fake__echo", G.TOOLS)

    def test_resources(self):
        self.assertIn("mem://a", G.t_mcp(self.ctx, "resources", server="fake"))
        self.assertIn("resource body", G.t_mcp(self.ctx, "read", server="fake", uri="mem://a"))


# ---------------------------------------------------------------------------------------------- builder
class TestIsolatedBuilder(RepoCase):
    git = True

    def test_worktree_starts_from_uncommitted_state(self):
        self.write("a.py", "x = 2\n")        # uncommitted
        wt, base = gnoc_worktree.create(self.repo)
        try:
            with open(os.path.join(wt, "a.py")) as f:
                self.assertEqual(f.read(), "x = 2\n")
            with open(os.path.join(wt, "new.py"), "w") as f:
                f.write("y = 1\n")
            patch = gnoc_worktree.diff(wt, base)
            self.assertIn("+++ b/new.py", patch)
            self.assertNotIn("a.py", patch)
        finally:
            gnoc_worktree.remove(wt)
        self.assertFalse(os.path.exists(wt))
        self.assertNotIn("gnoc/build-", _git(self.repo, "branch").stdout)

    def test_builder_writes_only_in_its_worktree_and_returns_a_patch(self):
        seen = {}

        def fake_worker(ctx, task, **kw):
            wctx = G.Ctx(dict(ctx.s, **kw["extra"]))
            seen["edit"] = G._exec("edit_file", {"path": "a.py", "old": "x = 1", "new": "x = 99"}, wctx)
            seen["escape"] = G._exec("write_file", {"path": os.path.join(self.tmp, "outside.txt"),
                                                    "content": "no"}, wctx)
            self.assertFalse(G._approval_required("edit_file", {"path": "a.py"}, wctx))
            return "changed a.py"

        with mock.patch.object(G, "run_worker", fake_worker):
            out = G.t_delegate(self.ctx, "set x to 99 in a.py and run its tests", isolated=True)
        self.assertIn("edited", seen["edit"])
        self.assertIn("refused", seen["escape"])
        self.assertEqual(self.read("a.py"), "x = 1\n")          # the lead's checkout is untouched
        pf = out.split("Patch: ", 1)[1].split(" (", 1)[0]
        self.assertTrue(os.path.isfile(pf))
        res = self.ex("apply_patch", {"patch_file": pf})
        self.assertIn("applied", res)
        self.assertEqual(self.read("a.py"), "x = 99\n")

    def test_patch_file_must_be_a_builder_patch_or_in_the_repo(self):
        p = os.path.join(self.tmp, "elsewhere.patch")
        with open(p, "w") as f:
            f.write("--- a/a.py\n+++ b/a.py\n")
        self.assertIn("refused", self.ex("apply_patch", {"patch_file": p}))

    def test_an_inherited_git_dir_cannot_redirect_harness_git(self):
        decoy = os.path.join(self.tmp, "decoy")
        os.makedirs(decoy)
        _git(decoy, "init", "-q", "-b", "main")
        before = sorted(os.listdir(os.path.join(decoy, ".git")))
        with mock.patch.dict(os.environ, {"GIT_DIR": os.path.join(decoy, ".git"),
                                          "GIT_INDEX_FILE": os.path.join(decoy, ".git", "index")}):
            self.write("a.py", "x = 5\n")
            wt, base = gnoc_worktree.create(self.repo)
            gnoc_worktree.remove(wt)
            self.assertIn("a.py", self.ex("git", {"action": "status"}))
        self.assertEqual(_git(decoy, "branch", "--list").stdout.strip(), "")
        self.assertNotIn("index", set(os.listdir(os.path.join(decoy, ".git"))) - set(before))

    def test_root_override_is_per_thread(self):
        import threading
        got = {}
        with G.root_scope(os.path.join(self.tmp, "elsewhere")):
            t = threading.Thread(target=lambda: got.setdefault("other", G.root()))
            t.start()
            t.join()
            got["here"] = G.root()
        self.assertEqual(got["other"], self.repo)
        self.assertTrue(got["here"].endswith("elsewhere"))
        self.assertEqual(G.root(), self.repo)


class TestRegistry(unittest.TestCase):
    def test_new_tools_registered_and_in_the_code_set(self):
        for n in ("bg", "typecheck"):
            self.assertIn(n, G.TOOLS)
            self.assertIn(n, G.CODE_TOOLS)
        self.assertIn("find_file", G.CODE_TOOLS)
        self.assertIn("typecheck", G.SWE_CORE)
        self.assertIn("bg", G.WEB_CORE)
        props = G.TOOLS["edit_file"][1]["function"]["parameters"]["properties"]
        for k in ("replace_all", "edits", "cell"):
            self.assertIn(k, props)
        self.assertEqual(set(G.TOOLS["git"][1]["function"]["parameters"]["properties"]["action"]["enum"]),
                         set(G.GIT_ACTIONS))


if __name__ == "__main__":
    unittest.main()
