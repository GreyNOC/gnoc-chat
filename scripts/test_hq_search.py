#!/usr/bin/env python3
"""Tests for `scripts/hq search` (hq + hq_search.py).

Run:  python3 scripts/test_hq_search.py
Guards three measured regressions (2026-10-22):
  1. free text joined with `paste -sd' OR '` became "a" "b"O"c"R"d" (AND + stray terms o/r) and made one
     call take 27 s; free text must be an OR of quoted tokens.
  2. FTS5 snippet() is quadratic in per-doc hits; search must stay bounded on huge minified blobs.
  3. a read must never rebuild or write the index (the reindex is `hq reindex` / the oss-bot daemon only).
"""
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HQ = os.path.join(HERE, "hq")
LIVE_DB = os.path.join(HERE, "..", ".hunt-index", "hunts.db")
sys.path.insert(0, HERE)
import hq_search  # noqa: E402

DDL = """
CREATE TABLE docs(id INTEGER PRIMARY KEY, sha TEXT UNIQUE, path TEXT, target TEXT, kind TEXT,
  role TEXT, ext TEXT, mtime REAL, size INTEGER, ncopies INTEGER DEFAULT 1, body TEXT);
CREATE TABLE sources(sha TEXT, path TEXT, root TEXT, mtime REAL);
CREATE TABLE hosts(doc_id INTEGER, host TEXT);
CREATE TABLE urls (doc_id INTEGER, url TEXT);
CREATE TABLE requests(doc_id INTEGER, target TEXT, method TEXT, host TEXT, url TEXT, status INTEGER);
CREATE VIRTUAL TABLE fts USING fts5(body, content='docs', content_rowid='id');
"""
REF_SQL = ("SELECT d.target,d.kind,d.path,snippet(fts,0,'[',']','...',12) FROM fts JOIN docs d "
           "ON d.id=fts.rowid WHERE fts MATCH ? ORDER BY rank LIMIT 40")

DOCS = [
    ("alphaonly", "prog-a", "note", "/t/a.md", "the alpha gateway handles login for the gatewayco admin"),
    ("betaonly", "prog-b", "note", "/t/b.md", "beta release notes; nothing about the first word"),
    ("letters", "prog-c", "note", "/t/c.md", "o r o r o r single letters only here"),
    ("both", "prog-d", "report", "/t/d.md", "alpha and beta together with zero click ato"),
    ("quote", "prog-e", "note", "/t/e.md", "it's an apostrophe test with alpha inside"),
    # a huge, dense doc: snippet() on it is the quadratic case (12k hits)
    ("blob", "prog-f", "capture", "/t/f.js", "var x=1;function f(){return var;}\n" * 6000),
]


def build_fixture(path):
    con = sqlite3.connect(path)
    con.executescript(DDL)
    for i, (sha, target, kind, p, body) in enumerate(DOCS, 1):
        con.execute("INSERT INTO docs(id,sha,path,target,kind,role,body) VALUES(?,?,?,?,?,'intel',?)",
                    (i, sha, p, target, kind, body))
    con.execute("INSERT INTO fts(fts) VALUES('rebuild')")
    con.commit()
    con.close()


def hq(db, *words, timeout=60):
    return subprocess.run([HQ, "search", *words], capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, HUNT_DB=db), stdin=subprocess.DEVNULL)


class FixtureSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "hunts.db")
        build_fixture(cls.db)
        os.chmod(cls.db, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)   # read-only: any write would fail
        os.chmod(cls.tmp.name, stat.S_IRUSR | stat.S_IXUSR)             # and no journal/-wal can be created

    @classmethod
    def tearDownClass(cls):
        os.chmod(cls.tmp.name, stat.S_IRWXU)
        cls.tmp.cleanup()

    def test_read_does_not_write_or_rebuild(self):
        st0 = os.stat(self.db)
        listing0 = sorted(os.listdir(self.tmp.name))
        r = hq(self.db, "alpha", "beta")
        self.assertEqual(r.returncode, 0, r.stderr)
        st1 = os.stat(self.db)
        self.assertEqual((st0.st_mtime_ns, st0.st_size), (st1.st_mtime_ns, st1.st_size))
        self.assertEqual(listing0, sorted(os.listdir(self.tmp.name)))

    def test_search_branch_never_calls_the_indexer(self):
        with open(HQ) as fh:
            src = fh.read()
        branch = src[src.index("  search)"):src.index("  host)")]
        self.assertNotIn("hunt-index.py", branch)
        self.assertNotIn("reindex", branch)

    def test_free_text_is_an_or_of_tokens(self):
        out = hq(self.db, "alpha", "beta", "gamma").stdout
        for p in ("/t/a.md", "/t/b.md", "/t/d.md"):     # OR: a doc with only one of the words still matches
            self.assertIn(p, out)
        self.assertNotIn("/t/c.md", out)                # no stray single-letter terms (the paste bug)

    def test_battery_query_shape_does_not_crash(self):
        r = hq(self.db, "gatewayco", "/", "focus:", "zero", "click", "ato")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/t/d.md", r.stdout)

    def test_apostrophe_is_safe(self):
        r = hq(self.db, "it's", "apostrophe")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("/t/e.md", r.stdout)

    def test_rows_and_snippets_match_reference_for_cheap_docs(self):
        con = sqlite3.connect("file:%s?mode=ro" % self.db, uri=True)
        for expr in ('"alpha" OR "beta"', '"zero" OR "click" OR "ato"', 'alpha AND beta', '"gatewayco"'):
            ref = con.execute(REF_SQL, (expr,)).fetchall()
            self.assertEqual(ref, hq_search.search(self.db, expr), expr)
        con.close()

    def test_heavy_doc_is_bounded_and_keeps_rank(self):
        expr = '"function" OR "return" OR "var"'
        t = time.time()
        rows = hq_search.search(self.db, expr)
        self.assertLess(time.time() - t, 2.0)
        self.assertEqual([r[2] for r in rows], ["/t/f.js"])
        self.assertIn("[var]", rows[0][3])             # the linear excerpt keeps the snippet shape

    def test_empty_result_prints_nothing(self):
        r = hq(self.db, "zzzznotaword")
        self.assertEqual((r.returncode, r.stdout), (0, ""))


@unittest.skipUnless(os.path.exists(LIVE_DB), "no live hunt index")
class LiveIndexBounded(unittest.TestCase):
    """Bounded time on the real 1.6 GB index. Read-only: asserts the db file is untouched."""

    def _timed(self, *words, limit):
        st0 = os.stat(LIVE_DB)
        t = time.time()
        r = hq(LIVE_DB, *words, timeout=60)
        dt = time.time() - t
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(dt, limit, "%s took %.2fs" % (words, dt))
        st1 = os.stat(LIVE_DB)
        self.assertEqual((st0.st_mtime_ns, st0.st_size), (st1.st_mtime_ns, st1.st_size))
        return r.stdout

    def test_battery_query_under_budget(self):       # was 26.6 s; budget widened for the grown live index
        out = self._timed("gatewayco", "/", "focus:", "zero", "click", "ato", limit=4.0)
        self.assertIn("gatewayco", out.lower())

    def test_pathological_common_terms_bounded(self):  # was 21-42 s (quadratic snippet on minified blobs)
        self._timed("function", "return", "var", limit=5.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
