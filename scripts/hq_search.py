#!/usr/bin/env python3
"""hq search backend: FTS5 match + bounded snippet, rendered by the sqlite3 CLI's -box mode.

Called by `scripts/hq search` as:  hq_search.py <db> <fts5-match-expression>
Read-only: opens the db with mode=ro and never rebuilds or writes the index.

Why this exists (measured 2026-10-22): FTS5 snippet() is QUADRATIC in the number of phrase hits inside
one document (it scores a window at every hit by rescanning every hit). A 7 MB minified blob with 55k
hits of a common term costs 35 s for ONE snippet; the top-40 page could take 40 s+. Doc selection and
order (bm25 rank, LIMIT 40) are unchanged. snippet() is still used, byte-identical, for every document
whose estimated cost is cheap; only a document that would blow the budget gets a linear excerpt of
the same shape ('...' + ~12 tokens around the first hit, terms in [ ]).
"""
import os
import re
import sqlite3
import subprocess
import sys

LIMIT = 40
SNIP_TOKENS = 12
PER_DOC_MAX_HITS = 4000          # 4000^2 * ~1.6e-8 s = ~0.25 s for the worst admitted doc (measured)
ALWAYS_SNIPPET_HITS = 400        # 400^2 * 1.6e-8 = ~2.5 ms: a cheap doc always gets the real snippet()
TOTAL_COST_BUDGET = 3.5e7        # sum(hits^2) over the page, ~0.55 s of snippet() in total
_OPS = {"AND", "OR", "NOT", "NEAR"}
_TOK = re.compile(r"[^\W_]+", re.UNICODE)    # unicode61: letters/digits are token chars, '_' separates

SQL_TOP = ("SELECT d.id, d.target, d.kind, d.path FROM fts JOIN docs d ON d.id=fts.rowid "
           "WHERE fts MATCH ? ORDER BY rank LIMIT %d" % LIMIT)
# HQ_TARGET=<handle> keeps only that programme's rows plus untargeted workspace docs (gnoc hunt_search sets it
# while a programme is active: the initech replay 2026-11-25 ported a stayco hotel route onto www.initech.com)
SQL_TOP_T = ("SELECT d.id, d.target, d.kind, d.path FROM fts JOIN docs d ON d.id=fts.rowid "
             "WHERE fts MATCH ? AND (d.target=? OR d.target='' OR d.target IS NULL) ORDER BY rank LIMIT %d" % LIMIT)
SQL_SNIP = ("SELECT snippet(fts,0,'[',']','...',%d) FROM fts WHERE fts MATCH ? AND rowid=?" % SNIP_TOKENS)


def match_terms(expr):
    """The lowercase tokens an FTS5 expression can hit (operators, column filters and '*' dropped)."""
    out = []
    for t in _TOK.findall(expr):
        if t in _OPS:            # FTS5 operators are case-sensitive uppercase
            continue
        t = t.lower()
        if t not in out:
            out.append(t)
    return out


def _term_re(terms, prefix=False):
    """Matcher for the query terms with a TRAILING token boundary only. Dropping the leading boundary
    keeps the count an upper bound (it may count 'xkong', never misses 'gatewayco') and lets re use its
    literal-prefix scan: 0.04 s on a 6 MB blob versus 0.28 s with a lookbehind (measured).
    prefix=True (the query uses term*) drops the trailing boundary too."""
    tail = "" if prefix else "(?![^\\W_])"
    alt = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    return re.compile(r"(?:%s)%s" % (alt, tail))


def est_hits(body_lower, terms, rx):
    """Upper bound of the phrase-hit count snippet() iterates over. str.count first (memchr speed);
    only a doc that is not obviously cheap pays for the boundary-aware regex."""
    c = sum(body_lower.count(t) for t in terms)
    if c <= ALWAYS_SNIPPET_HITS or c > 25 * PER_DOC_MAX_HITS:   # obviously cheap / obviously over budget
        return c
    return len(rx.findall(body_lower))


def linear_excerpt(body, body_lower, rx, terms):
    """Same shape as snippet(fts,0,'[',']','...',12): ~12 tokens around the first hit, terms in [ ].
    Tokenizes only a local window, so it is O(position of first hit), not O(doc)."""
    alt = "|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True))
    m = re.search(r"(?<![^\W_])(?:%s)" % alt, body_lower) or rx.search(body_lower)   # whole-token hit first
    at = m.start() if m else 0
    lo_b = max(0, at - 200)
    win = list(_TOK.finditer(body, lo_b, min(len(body), at + 4000)))
    if not win:
        return ""
    first = next((i for i, t in enumerate(win) if t.start() >= at), 0)
    if lo_b > 0 and first == 0:
        first = 1                       # the window may start mid-token; never use a partial first token
    lo = max(1 if lo_b > 0 else 0, first - 2)
    hi = min(len(win), lo + SNIP_TOKENS)
    tset = set(terms)
    parts, pos = [], win[lo].start()
    for t in win[lo:hi]:
        parts.append(body[pos:t.start()])
        w = t.group(0)
        parts.append("[%s]" % w if w.lower() in tset else w)
        pos = t.end()
    at_start = lo_b == 0 and lo == 0
    at_end = win[hi - 1].end() >= len(body) or not _TOK.search(body, win[hi - 1].end())
    return ("" if at_start else "...") + "".join(parts) + ("" if at_end else "...")


def search(db_path, expr):
    con = sqlite3.connect("file:%s?mode=ro" % db_path, uri=True)
    try:
        tgt = os.environ.get("HQ_TARGET", "").strip()
        top = con.execute(SQL_TOP_T, (expr, tgt)).fetchall() if tgt else con.execute(SQL_TOP, (expr,)).fetchall()
        terms = match_terms(expr)
        rx = _term_re(terms, prefix="*" in expr) if terms else None
        rows, spent = [], 0.0
        for doc_id, target, kind, path in top:
            body = con.execute("SELECT body FROM docs WHERE id=?", (doc_id,)).fetchone()[0] or ""
            low = body.lower()
            h = est_hits(low, terms, rx) if rx else 0
            cost = float(h) * h
            if h <= ALWAYS_SNIPPET_HITS or (h <= PER_DOC_MAX_HITS and spent + cost <= TOTAL_COST_BUDGET):
                spent += cost
                hit = con.execute(SQL_SNIP, (expr, doc_id)).fetchone()[0]
            else:
                hit = linear_excerpt(body, low, rx, terms) if rx else ""
            rows.append((target, kind, path, hit))
        return rows
    finally:
        con.close()


def _q(v):
    return "NULL" if v is None else "'" + str(v).replace("'", "''") + "'"


def render_sql(rows):
    """A SELECT that reproduces the rows with the original column names, for `sqlite3 -box`."""
    if not rows:
        return ""
    vals = ",".join("(%d,%s)" % (i, ",".join(_q(v) for v in r)) for i, r in enumerate(rows))
    return ("SELECT column2 AS target, column3 AS kind, column4 AS path, column5 AS hit "
            "FROM (VALUES %s) ORDER BY column1;" % vals)


def main(argv):
    if len(argv) != 3:
        print("usage: hq_search.py <db> <fts5 expression>", file=sys.stderr)
        return 2
    try:
        rows = search(argv[1], argv[2])
    except sqlite3.Error as e:          # same surface as the sqlite3 CLI: message on stderr, exit 1
        print("Parse error: %s" % e, file=sys.stderr)
        return 1
    sql = render_sql(rows)
    if not sql:                         # the CLI prints nothing for an empty result
        return 0
    return subprocess.run(["sqlite3", "-box", ":memory:"], input=sql, text=True).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
