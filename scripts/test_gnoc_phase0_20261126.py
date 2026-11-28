"""Phase 0 (2026-11-26): defects the baseline diagnosis found that the existing suite only caught on some machines.

The node run_tests check passed on Node 22 and failed on Node 20, because the two versions report a name filter
that matches nothing differently. These tests feed both shapes to run_tests directly, so they hold whatever node
(if any) the machine has.
"""
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock as mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402

NODE20_NO_MATCH = ("TAP version 13\n# Subtest: adds\nok 1 - adds # SKIP test name does not match pattern\n"
                   "1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 0\n")
NODE22_NO_MATCH = "TAP version 13\n1..0\n# tests 0\n# suites 0\n# pass 0\n# fail 0\n# skipped 0\n"
NODE_MATCH_PASS = ("TAP version 13\n# Subtest: adds\nok 1 - adds\n1..1\n# tests 1\n# suites 0\n# pass 1\n"
                   "# fail 0\n# skipped 0\n")


class NodeNameFilterThatMatchedNothing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p0-")
        self.saved = G._ACTIVE_ROOT[0]
        G._ACTIVE_ROOT[0] = self.tmp
        self.ctx = G.Ctx({"sid": "p0-node"})
        os.makedirs(os.path.join(self.tmp, "test"))
        with open(os.path.join(self.tmp, "test", "a.test.js"), "w") as fh:
            fh.write('const { test } = require("node:test");\ntest("adds", () => {});\n')

    def tearDown(self):
        G._ACTIVE_ROOT[0] = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, tap, name):
        done = mock.Mock(returncode=0, stdout=tap, stderr="")
        with mock.patch.object(G, "_run_group", return_value=done):
            return str(G._exec("run_tests", {"files": ["test/a.test.js"], "name": name}, self.ctx))

    def test_node20_skip_shape_is_not_a_pass(self):
        out = self._run(NODE20_NO_MATCH, "zzz-nothing")
        self.assertTrue(out.startswith("0/1"), out[:200])
        self.assertIn("no test matched name='zzz-nothing'", out)

    def test_node22_empty_shape_is_still_not_a_pass(self):
        out = self._run(NODE22_NO_MATCH, "zzz-nothing")
        self.assertTrue(out.startswith("0/1"), out[:200])

    def test_a_name_that_matched_and_passed_is_a_pass(self):
        # negative control: the new check must not turn a real filtered pass into "no test matched"
        out = self._run(NODE_MATCH_PASS, "adds")
        self.assertTrue(out.startswith("1/1"), out[:200])
        self.assertNotIn("no test matched", out)


class TurnReadsOnlyNamesItBinds(unittest.TestCase):
    """Agent._turn binds `re` as `_re` (it has no module-level `import re`). One branch, a refused record_outcome in
    hunt mode, called bare `re.search` and would raise NameError mid-turn; it shipped in 2026.11.25.1 and
    2026.11.26. The check: _turn never reads a bare `re` it did not bind."""

    def test_no_bare_re_in_turn(self):
        import ast
        import inspect
        import textwrap
        from gnoc_core import agent as A
        tree = ast.parse(textwrap.dedent(inspect.getsource(A.Agent._turn)))
        bound = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        bound |= {a.asname or a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                  for a in n.names}
        module_has_re = hasattr(A, "re")
        reads = [n.lineno for n in ast.walk(tree)
                 if isinstance(n, ast.Name) and n.id == "re" and isinstance(n.ctx, ast.Load)]
        if "re" not in bound and not module_has_re:
            self.assertEqual(reads, [], "Agent._turn reads `re` without binding it (use _re)")


if __name__ == "__main__":
    unittest.main()
