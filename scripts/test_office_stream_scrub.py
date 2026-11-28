"""Tests for the hashed secret scrubber in office-stream.py: the module must redact known secrets (whole or as an
8-character fragment) without ever holding a plaintext copy.

    python3 scripts/test_office_stream_scrub.py
"""
import importlib.util
import os
import sys
import types
import tempfile
import unittest

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECRET = "Zq7Lm2Xp9RwK4vTb"  # fake, generated for this test only


def load():
    spec = importlib.util.spec_from_file_location("office_stream_under_test", os.path.join(WS, "scripts/office-stream.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def contains(obj, needle, seen, depth=0):
    """True if needle appears in obj (str/bytes/containers/object attrs/closures), searched recursively."""
    if id(obj) in seen or depth > 8 or isinstance(obj, types.ModuleType):  # not sys/os: they reach this test file
        return False
    seen.add(id(obj))
    if isinstance(obj, str):
        return needle in obj
    if isinstance(obj, (bytes, bytearray)):
        return needle.encode() in bytes(obj)
    if isinstance(obj, dict):
        return any(contains(k, needle, seen, depth + 1) or contains(v, needle, seen, depth + 1) for k, v in obj.items())
    if isinstance(obj, (list, tuple, set, frozenset)):
        return any(contains(v, needle, seen, depth + 1) for v in obj)
    if callable(obj) and getattr(obj, "__closure__", None):
        return any(contains(c.cell_contents, needle, seen, depth + 1) for c in obj.__closure__ if _filled(c))
    if hasattr(obj, "__dict__") and not isinstance(obj, type) and type(obj).__module__ != "builtins":
        return contains(vars(obj), needle, seen, depth + 1)
    return False


def _filled(c):
    try:
        c.cell_contents
        return True
    except ValueError:
        return False


class ScrubTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load()
        cls.tmp = tempfile.TemporaryDirectory()
        with open(os.path.join(cls.tmp.name, "fake.env"), "w") as f:
            f.write(f"FAKE_API_TOKEN={SECRET}\n")
        S = cls.mod.SECRETS
        S.globs = [os.path.join(cls.tmp.name, "*.env")]
        S.ws = cls.tmp.name  # no targets/ here, so no ACCOUNTS.md
        S.fresh(force=True)
        cls.mod._ROW_CACHE.clear()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scrub(self, t):
        idx = set(self.mod.scrub_row(list(t)))
        return "".join("▒" if i in idx and c != " " else c for i, c in enumerate(t))

    def test_full_secret_redacted(self):
        out = self.scrub(f"the key is {SECRET} ok")
        self.assertNotIn(SECRET[:8], out)
        self.assertEqual(out.count("▒"), len(SECRET))

    def test_fragment_redacted(self):
        frag = SECRET[3:11]
        out = self.scrub(f"clipped ..{frag}.. here")
        self.assertNotIn(frag, out)
        self.assertEqual(out.count("▒"), 8)

    def test_unrelated_untouched(self):
        line = "the quick brown fox jumps over lazy dogs"
        self.assertEqual(self.scrub(line), line)

    def test_no_plaintext_held(self):
        for needle in (SECRET, SECRET[:8], SECRET[3:11], SECRET[-8:]):
            self.assertFalse(contains(vars(self.mod), needle, set()), needle[:2] + "...")
        self.assertTrue(self.mod.SECRETS.grams)
        self.assertTrue(all(isinstance(g, bytes) and len(g) == 16 for g in self.mod.SECRETS.grams))


if __name__ == "__main__":
    unittest.main()
