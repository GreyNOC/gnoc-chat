"""One edition (the user 2026-11-27: "make the two editions the same").

The workspace copy and every release run the same code paths. What differs between machines is a setting in
.claude/state/orch/machine.json (scripts/gnoc_edition.py), never a branch on the build stamp gnoc_edition.PUBLIC.
"""
import ast
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_edition  # noqa: E402
import llm_endpoints  # noqa: E402

# the release builder flips the stamp and checks it; nothing else may read it
STAMP_READERS_OK = {"gnoc_release.py", "gnoc_edition.py"}


def _code_files():
    for dp, dns, fns in os.walk(HERE):
        dns[:] = [d for d in dns if d not in ("__pycache__", "fixtures", "node_modules", ".git")]
        for fn in fns:
            if fn.endswith(".py") or (fn == "gnoc" and dp == HERE):
                if fn.startswith("test_") or fn in STAMP_READERS_OK:
                    continue
                yield os.path.join(dp, fn)


class NothingBranchesOnTheStamp(unittest.TestCase):
    def test_no_code_reads_gnoc_edition_public(self):
        hits = []
        for p in _code_files():
            try:
                with open(p, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read(), p)
            except (SyntaxError, UnicodeDecodeError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr == "PUBLIC" and \
                        isinstance(node.value, ast.Name) and node.value.id == "gnoc_edition":
                    hits.append(f"{os.path.relpath(p, HERE)}:{node.lineno}")
                if isinstance(node, ast.ImportFrom) and node.module == "gnoc_edition" and \
                        any(a.name == "PUBLIC" for a in node.names):
                    hits.append(f"{os.path.relpath(p, HERE)}:{node.lineno}")
        self.assertEqual(hits, [], "a feature branches on the build stamp; make it a machine.json setting instead")


class MachineSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "machine.json")

    def write(self, d):
        with open(self.path, "w") as fh:
            json.dump(d, fh)

    def test_only_gnoc_variables_load(self):
        self.write({"env": {"GNOC_TEST_X": "1", "PATH": "/evil", "LD_PRELOAD": "x.so"}})
        self.assertEqual(gnoc_edition.machine_env(self.path), {"GNOC_TEST_X": "1"})

    def test_a_set_variable_wins_over_the_file(self):
        self.write({"env": {"GNOC_TEST_Y": "file"}})
        with mock.patch.dict(os.environ, {"GNOC_TEST_Y": "env"}):
            gnoc_edition.apply(self.path)
            self.assertEqual(os.environ["GNOC_TEST_Y"], "env")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GNOC_TEST_Y", None)
            gnoc_edition.apply(self.path)
            self.assertEqual(os.environ["GNOC_TEST_Y"], "file")

    def test_a_missing_or_broken_file_is_no_settings(self):
        self.assertEqual(gnoc_edition.machine_env(os.path.join(self.tmp, "absent.json")), {})
        with open(self.path, "w") as fh:
            fh.write("{not json")
        self.assertEqual(gnoc_edition.machine_env(self.path), {})
        self.write(["a", "list"])
        self.assertEqual(gnoc_edition.machine_env(self.path), {})


class SettingsReplaceTheEditionSplit(unittest.TestCase):
    def test_any_model_may_fill_any_role(self):
        # 2026-11-27: the uncensored-only rule is gone; the old setting no longer turns it back on
        for v in ("", "0", "1"):
            with mock.patch.dict(os.environ, {"GNOC_ALLOW_STOCK": v}):
                self.assertTrue(llm_endpoints.allow_stock())

    def test_one_computer_has_no_laptop_label(self):
        with mock.patch.dict(llm_endpoints.HOSTS, {"desktop": ""}), \
                mock.patch.dict(os.environ, {"GNOC_LOCAL_NAME": "laptop", "GNOC_DESKTOP_NAME": "desktop"}):
            self.assertEqual(llm_endpoints.host_label("local"), "this computer")

    def test_named_machines_keep_their_names(self):
        with mock.patch.dict(llm_endpoints.HOSTS, {"desktop": "127.0.0.1:1"}), \
                mock.patch.dict(os.environ, {"GNOC_LOCAL_NAME": "laptop", "GNOC_DESKTOP_NAME": "desktop"}):
            self.assertEqual(llm_endpoints.host_label("local"), "laptop")
            self.assertEqual(llm_endpoints.host_label("desktop"), "desktop")
            self.assertEqual(llm_endpoints.host_label("split"), "desktop+laptop")
        with mock.patch.dict(llm_endpoints.HOSTS, {"desktop": "127.0.0.1:1"}), \
                mock.patch.dict(os.environ, {"GNOC_LOCAL_NAME": "", "GNOC_DESKTOP_NAME": ""}):
            self.assertEqual(llm_endpoints.host_label("desktop"), "the other computer")
            self.assertEqual(llm_endpoints.host_label("split"), "both computers")

    def test_comfy_is_a_setting(self):
        import gnoc_image
        with mock.patch.dict(os.environ, {"GNOC_COMFY_URL": ""}):
            self.assertFalse(gnoc_image.comfy_configured())
        with mock.patch.dict(os.environ, {"GNOC_COMFY_URL": "http://127.0.0.1:1"}):
            self.assertTrue(gnoc_image.comfy_configured())


if __name__ == "__main__":
    unittest.main()
