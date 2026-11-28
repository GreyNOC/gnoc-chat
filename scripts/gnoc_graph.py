#!/usr/bin/env python3
"""gnoc_graph.py - the ARTEX-style dual graph for the gnoc harness.

Two graphs, one SQLite file:

  ASSET GRAPH (global, shared by every program)
      root_domain -> subdomain -> endpoint/service, plus ip/app/repo/email.
      Deduplicated by (kind, normalised identifier). A program is associated with the
      assets it has in scope, so the same host can be seen from several programs.

  EXPLORATION GRAPH (one per program, the active engagement)
      goal / intent / fact / finding / hint / digest nodes, linked by
      spawns / derived_from / yields / proves / covers / depends_on.
      Nodes are ANCHORED to assets: this is what makes coverage computable
      (an in-scope asset is covered when a fact/finding node is anchored to it).

Also persisted here:
  todos       a durable planning scratchpad with atomic worker claims and expiring leases
  traces      every recorded tool/probe step, searchable across workers
  evidence    deduplicated observations promoted from a trace (or entered by hand)
  findings    the evidence-backed lifecycle: candidate -> triaged -> confirmed -> reported
  coverage    in-scope vs touched vs fact/finding-covered assets

This is additive: the existing hunt ledger (`targets/<p>/hunts/gnoc/ledger.json`)
still owns hypotheses, edges and chains. The graph is the shared state layer the
harness was missing, not a replacement for the gates.

CLI: python3 scripts/gnoc_graph.py overview|assets|coverage|nodes|todos|traces|traffic|evidence|findings|approvals [program]
     python3 scripts/gnoc_graph.py snapshot <program> [label] / snapshots <program> / diff <program> [since]
     python3 scripts/gnoc_graph.py path <program> <from> <to> / lineage <program> <node>
     python3 scripts/gnoc_graph.py export <program> [--out PATH] [--open]     the cockpit page
     python3 scripts/gnoc_graph.py draft <program> <finding_id> [--out DIR] [--cvss ...] [--cwe ...]
                                                                             a REPORT-FORMAT draft
"""
from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import html as _html
import ipaddress
import json
import os
import re
import shlex
import shutil
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now

WS = os.path.abspath(os.environ.get("GNOC_WS") or
                     os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(WS, ".claude/state/graph/gnoc_graph.db")

PROGRAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,80}$")
ASSET_KINDS = ("root_domain", "domain", "subdomain", "ip", "service", "endpoint", "url", "app", "repo",
               "email", "other")
NODE_KINDS = ("begin", "goal", "intent", "fact", "finding", "hint", "digest", "note")
NODE_STATES = {
    "intent": ("open", "running", "paused", "done", "blocked", "exhausted", "stopped", "deleted"),
    "goal": ("open", "met", "abandoned"),
    "fact": ("confirmed", "dismissed", "origin"),
    "finding": ("confirmed", "dismissed"),
    "hint": ("active", "consumed"),
    "digest": ("active", "superseded"),
    "begin": ("open",),
    "note": ("open",),
}
RELS = ("spawns", "derived_from", "yields", "proves", "covers", "depends_on", "blocks")
TODO_STATES = ("pending", "in_progress", "completed", "blocked")
EVIDENCE_KINDS = ("probe", "artifact", "note")
FINDING_STATES = ("candidate", "triaged", "confirmed", "reported", "closed", "rejected")
APPROVAL_STATES = ("pending", "approved", "denied", "expired")
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
DEFAULT_STATE = {"begin": "open", "goal": "open", "intent": "open", "fact": "confirmed",
                 "finding": "confirmed", "hint": "active", "digest": "active", "note": "open"}
DEFAULT_REL = {"intent": "spawns", "fact": "yields", "finding": "proves", "hint": "derived_from"}

PUBLIC_SUFFIX = {"app.example.com", "com.au", "com.co", "com.mx", "co.jp", "co.nz", "com.br", "co.in",
                 "com.sg", "com.hk", "co.za", "com.tr", "gov.uk", "org.uk", "net.au", "org.au",
                 "co.kr", "com.cn", "co.id", "com.ph", "com.my", "co.th", "com.tw", "ne.jp", "or.jp"}
_OOS = re.compile(r"^(?:out.?of.?scope|oos\b|exclud|ineligib|not\s+in\s+scope|do\s+not\s+test|forbidden)",
                  re.I)
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", re.I)

_LOCK = threading.RLock()


# ------------------------------------------------------------------ storage
_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    parent_id   INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    attrs       TEXT NOT NULL DEFAULT '{}',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(kind, identifier)
);
CREATE INDEX IF NOT EXISTS idx_assets_ident ON assets(identifier);
CREATE INDEX IF NOT EXISTS idx_assets_kind  ON assets(kind);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_id);

CREATE TABLE IF NOT EXISTS asset_programs (
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    program     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (asset_id, program)
);
CREATE INDEX IF NOT EXISTS idx_asset_programs_prog ON asset_programs(program);

CREATE TABLE IF NOT EXISTS asset_links (
    src_id      INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    dst_id      INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rel         TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (src_id, dst_id, rel)
);

CREATE TABLE IF NOT EXISTS asset_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program     TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    taken_at    TEXT NOT NULL,
    assets      INTEGER NOT NULL DEFAULT 0,
    payload     TEXT NOT NULL,
    sha256      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_snapshots_prog ON asset_snapshots(program, taken_at DESC);

CREATE TABLE IF NOT EXISTS explorations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    program     TEXT NOT NULL UNIQUE,
    goal        TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open',
    round_no    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    title           TEXT NOT NULL,
    body            TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL,
    confidence      TEXT,
    priority        INTEGER NOT NULL DEFAULT 0,
    owner           TEXT,
    attrs           TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    completed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_nodes_exp  ON nodes(exploration_id, kind, state);
CREATE INDEX IF NOT EXISTS idx_nodes_time ON nodes(created_at DESC);

CREATE TABLE IF NOT EXISTS edges (
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    src_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst_id          INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rel             TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (exploration_id, src_id, rel, dst_id),
    CHECK (src_id <> dst_id)
);
CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id, rel);
CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id, rel);

CREATE TABLE IF NOT EXISTS anchors (
    node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (node_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_anchors_asset ON anchors(asset_id);

CREATE TABLE IF NOT EXISTS todos (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    content         TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    depends_on      TEXT NOT NULL DEFAULT '[]',
    claimed_by      TEXT NOT NULL DEFAULT '',
    lease_until     TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT NOT NULL DEFAULT '',
    completed_at    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_todos_exp ON todos(exploration_id, state);

CREATE TABLE IF NOT EXISTS traces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    node_id         INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    worker          TEXT NOT NULL DEFAULT 'lead',
    tool            TEXT NOT NULL,
    args            TEXT NOT NULL DEFAULT '',
    result          TEXT NOT NULL DEFAULT '',
    ok              INTEGER,
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_traces_exp  ON traces(exploration_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_traces_node ON traces(node_id);

CREATE TABLE IF NOT EXISTS trace_assets (
    trace_id    INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (trace_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_trace_assets_asset ON trace_assets(asset_id);

CREATE TABLE IF NOT EXISTS traffic (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id    INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    host              TEXT NOT NULL DEFAULT '',
    method            TEXT NOT NULL DEFAULT '',
    url               TEXT NOT NULL DEFAULT '',
    status            INTEGER,
    request_headers   TEXT NOT NULL DEFAULT '',
    request_body      TEXT NOT NULL DEFAULT '',
    response_headers  TEXT NOT NULL DEFAULT '',
    response_body     TEXT NOT NULL DEFAULT '',
    raw_path          TEXT NOT NULL DEFAULT '',
    trace_id          INTEGER,
    sha256            TEXT NOT NULL,
    seen_count        INTEGER NOT NULL DEFAULT 1,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    UNIQUE(exploration_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_traffic_exp  ON traffic(exploration_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(exploration_id, host);

CREATE TABLE IF NOT EXISTS evidence (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    asset_id        INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    trace_id        INTEGER REFERENCES traces(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL DEFAULT 'probe',
    label           TEXT NOT NULL DEFAULT '',
    method          TEXT NOT NULL DEFAULT '',
    url             TEXT NOT NULL DEFAULT '',
    status          INTEGER,
    request         TEXT NOT NULL DEFAULT '',
    response        TEXT NOT NULL DEFAULT '',
    detail          TEXT NOT NULL DEFAULT '',
    raw_path        TEXT NOT NULL DEFAULT '',
    raw_sha256      TEXT NOT NULL DEFAULT '',
    sha256          TEXT NOT NULL,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    UNIQUE(exploration_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_evidence_exp   ON evidence(exploration_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    body            TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'candidate',
    severity        TEXT NOT NULL DEFAULT '',
    confidence      TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_exp ON findings(exploration_id, state);

CREATE TABLE IF NOT EXISTS finding_assets (
    finding_id  INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    asset_id    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_assets_asset ON finding_assets(asset_id);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id   INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_ev ON finding_evidence(evidence_id);

CREATE TABLE IF NOT EXISTS finding_artifacts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL DEFAULT 'report-draft',
    path            TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    bytes           INTEGER NOT NULL DEFAULT 0,
    files           TEXT NOT NULL DEFAULT '[]',
    note            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    UNIQUE(finding_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_finding_artifacts_finding ON finding_artifacts(finding_id, created_at DESC);

CREATE TABLE IF NOT EXISTS finding_retests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER NOT NULL REFERENCES explorations(id) ON DELETE CASCADE,
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    due_at          TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    note            TEXT NOT NULL DEFAULT '',
    outcome         TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_retests_due ON finding_retests(exploration_id, state, due_at);

CREATE TABLE IF NOT EXISTS approval_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    program         TEXT NOT NULL,
    action          TEXT NOT NULL,
    pattern         TEXT NOT NULL,
    uses_left       INTEGER NOT NULL DEFAULT 1,
    expires_at      TEXT NOT NULL,
    note            TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approval_rules_prog ON approval_rules(program, action);

CREATE TABLE IF NOT EXISTS approvals (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    exploration_id  INTEGER REFERENCES explorations(id) ON DELETE SET NULL,
    program         TEXT NOT NULL,
    action          TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    summary         TEXT NOT NULL DEFAULT '',
    payload         TEXT NOT NULL DEFAULT '',
    risk            TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT 'pending',
    requested_by    TEXT NOT NULL DEFAULT 'lead',
    decided_by      TEXT NOT NULL DEFAULT '',
    reason          TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL,
    decided_at      TEXT,
    expires_at      TEXT NOT NULL,
    used_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_program ON approvals(program, state);
CREATE INDEX IF NOT EXISTS idx_approvals_fp ON approvals(fingerprint, state);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""




def _check_program(program: str) -> str:
    program = str(program or "").strip()
    if not PROGRAM_RE.fullmatch(program):
        raise ValueError(f"invalid program handle: {program!r}")
    return program


def _check(value, allowed, what):
    value = str(value or "").strip().lower()
    if value not in allowed:
        raise ValueError(f"{what} must be one of: {', '.join(allowed)} (got {value!r})")
    return value


def _dump(obj) -> str:
    return json.dumps(obj if obj is not None else {}, sort_keys=True, default=str)


def _load(text, default=None):
    try:
        value = json.loads(text or "null")
    except ValueError:
        return default if default is not None else {}
    return value if value is not None else (default if default is not None else {})


def _migrate(conn) -> None:
    """Add columns introduced after a database was created. CREATE TABLE IF NOT EXISTS does not
    alter an existing table, so a live graph must be upgraded in place."""
    additions = {
        "evidence": (("raw_path", "TEXT NOT NULL DEFAULT ''"),
                     ("raw_sha256", "TEXT NOT NULL DEFAULT ''")),
        "todos": (("claimed_by", "TEXT NOT NULL DEFAULT ''"),
                  ("lease_until", "TEXT"),
                  ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                  ("last_error", "TEXT NOT NULL DEFAULT ''"),
                  ("completed_at", "TEXT")),
    }
    for table, columns in additions.items():
        have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, decl in columns:
            if name not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_todos_lease ON todos(exploration_id, lease_until)")


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = os.path.abspath(db_path or DB_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _LOCK:
        conn = sqlite3.connect(path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA)
        _migrate(conn)
        conn.commit()
        return conn


def _rows(conn, sql, args=()):
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _row(conn, sql, args=()):
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None


# ------------------------------------------------------------------ assets
def _host(identifier: str) -> str:
    s = str(identifier or "").strip()
    if "://" in s:
        try:
            return (urlsplit(s).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    s = s.lstrip("*.").split("/", 1)[0]
    return s.lower().rstrip(".")


def _is_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value) is not None
    except ValueError:
        return False


def _registrable(host: str) -> str:
    h = (host or "").lstrip("*.").lower().rstrip(".")
    parts = [p for p in h.split(".") if p]
    if len(parts) <= 2:
        return h
    if ".".join(parts[-2:]) in PUBLIC_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _kind_for_host(host: str) -> str:
    h = (host or "").lstrip("*.").lower().rstrip(".")
    if _is_ip(h):
        return "ip"
    if not h:
        return "other"
    return "root_domain" if h == _registrable(h) else "subdomain"


def _normalise(kind: str, identifier: str) -> str:
    s = str(identifier or "").strip()
    if not s:
        raise ValueError("identifier is empty")
    if kind in ("endpoint", "url", "service"):
        if "://" not in s:
            s = "https://" + s
        try:
            u = urlsplit(s)
        except ValueError as e:
            raise ValueError(f"invalid URL: {identifier!r} ({e})") from e
        if not u.hostname:
            raise ValueError(f"invalid URL (no host): {identifier!r}")
        try:
            port = u.port
        except ValueError as e:
            raise ValueError(f"invalid URL port: {identifier!r} ({e})") from e
        path = u.path or "/"
        query = ("?" + u.query) if u.query else ""
        return f"{u.scheme.lower()}://{u.hostname.lower()}{':' + str(port) if port else ''}{path}{query}"
    if kind == "ip":
        try:
            return ipaddress.ip_address(s).compressed
        except ValueError as e:
            raise ValueError(f"invalid IP: {identifier!r}") from e
    if kind in ("root_domain", "subdomain", "domain"):
        h = s.lstrip("=").lstrip("*.").lower().rstrip(".")
        if not h or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", h):
            raise ValueError(f"invalid host: {identifier!r}")
        return ("*." + h) if s.startswith("*.") and kind == "domain" else h
    return s.lower() if kind in ("app", "repo", "email") else s


def _ensure_exploration_conn(conn, program: str, goal: str = "") -> dict:
    program = _check_program(program)
    row = _row(conn, "SELECT * FROM explorations WHERE program=?", (program,))
    now = _now()
    if not row:
        conn.execute("INSERT INTO explorations(program, goal, status, round_no, created_at, updated_at) "
                     "VALUES(?,?, 'open', 0, ?, ?)", (program, goal or "", now, now))
        row = _row(conn, "SELECT * FROM explorations WHERE program=?", (program,))
    elif goal and not row.get("goal"):
        conn.execute("UPDATE explorations SET goal=?, updated_at=? WHERE id=?", (goal, now, row["id"]))
        row["goal"] = goal
    return row


def _exploration_or_empty(conn, program: str) -> dict:
    """Read-only lookup: no exploration row means an empty graph, NOT a row created by looking."""
    program = _check_program(program)
    row = _row(conn, "SELECT * FROM explorations WHERE program=?", (program,))
    return row or {"id": 0, "program": program, "goal": "", "status": "open", "round_no": 0,
                   "created_at": "", "updated_at": ""}


def ensure_exploration(program: str, goal: str = "", db_path: str | None = None) -> dict:
    with _closed(connect(db_path)) as conn:
        with conn:
            return _ensure_exploration_conn(conn, program, goal)


@contextlib.contextmanager
def _closed(conn):
    try:
        yield conn
    finally:
        conn.close()


def _asset_row(conn, asset_id: int) -> dict | None:
    return _row(conn, "SELECT * FROM assets WHERE id=?", (int(asset_id),))


def _auto_parent(conn, kind: str, identifier: str, program: str) -> int | None:
    """The parent asset in the hierarchy. The parent is created GLOBALLY, not associated with the
    program: association means "this row is in scope", and an auto-created apex is not a scope row.
    Otherwise coverage would count parent domains the operator never listed."""
    if kind in ("subdomain", "domain"):
        apex = _registrable(identifier.lstrip("*."))
        if apex and apex != identifier.lstrip("*."):
            return upsert_asset("root_domain", apex, None, conn=conn)["id"]
    if kind in ("endpoint", "url", "service"):
        h = _host(identifier)
        if h:
            return upsert_asset(_kind_for_host(h), h, None, conn=conn)["id"]
    return None


def upsert_asset(kind: str, identifier: str, program: str | None = None, parent=None,
                 attrs: dict | None = None, conn: sqlite3.Connection | None = None,
                 db_path: str | None = None) -> dict:
    """Insert or refresh one asset. Deduplicated by (kind, normalised identifier)."""
    kind = _check(kind, ASSET_KINDS, "asset kind")
    ident = _normalise(kind, identifier)
    prog = _check_program(program) if program else None
    own = conn is None
    conn = conn or connect(db_path)
    try:
        with conn:
            now = _now()
            row = _row(conn, "SELECT * FROM assets WHERE kind=? AND identifier=?", (kind, ident))
            parent_id = None
            if isinstance(parent, int) or (isinstance(parent, str) and str(parent).isdigit()):
                parent_id = int(parent)
                if not _asset_row(conn, parent_id):
                    parent_id = None
            elif isinstance(parent, str) and parent.strip():
                ph = _host(parent)
                if not ph:
                    raise ValueError(f"invalid parent asset: {parent!r}")
                parent_id = upsert_asset(_kind_for_host(ph), ph, prog, conn=conn)["id"]
            if row:
                merged = _load(row.get("attrs"), {})
                if isinstance(attrs, dict):
                    merged.update(attrs)
                conn.execute("UPDATE assets SET last_seen=?, attrs=?, parent_id=COALESCE(parent_id, ?) "
                             "WHERE id=?", (now, _dump(merged), parent_id, row["id"]))
                asset_id = row["id"]
            else:
                if parent_id is None:
                    parent_id = _auto_parent(conn, kind, ident, prog) if prog else None
                cur = conn.execute("INSERT INTO assets(kind, identifier, parent_id, attrs, first_seen, last_seen) "
                                   "VALUES(?,?,?,?,?,?)",
                                   (kind, ident, parent_id, _dump(attrs or {}), now, now))
                asset_id = cur.lastrowid
            if prog:
                conn.execute("INSERT INTO asset_programs(asset_id, program, first_seen, last_seen) "
                             "VALUES(?,?,?,?) ON CONFLICT(asset_id, program) DO UPDATE SET last_seen=excluded.last_seen",
                             (asset_id, prog, now, now))
            return _asset_row(conn, asset_id)
    finally:
        if own:
            conn.close()


def asset_detail(asset_id: int, db_path: str | None = None) -> dict | None:
    with _closed(connect(db_path)) as conn:
        row = _asset_row(conn, asset_id)
        if not row:
            return None
        row["programs"] = [r["program"] for r in conn.execute(
            "SELECT program FROM asset_programs WHERE asset_id=? ORDER BY program", (int(asset_id),))]
        row["parent"] = _asset_row(conn, row["parent_id"]) if row.get("parent_id") else None
        row["children"] = _rows(conn, "SELECT id, kind, identifier FROM assets WHERE parent_id=? "
                                      "ORDER BY kind, identifier", (int(asset_id),))
        row["nodes"] = _rows(conn, "SELECT n.id, n.kind, n.state, n.title FROM anchors a "
                                   "JOIN nodes n ON n.id=a.node_id WHERE a.asset_id=? "
                                   "ORDER BY n.created_at DESC", (int(asset_id),))
        row["touches"] = conn.execute("SELECT COUNT(*) FROM trace_assets WHERE asset_id=?",
                                      (int(asset_id),)).fetchone()[0]
        row["attrs"] = _load(row.get("attrs"), {})
        return row


def list_assets(program: str | None = None, kind: str | None = None, query: str = "",
                limit: int = 100, db_path: str | None = None) -> list[dict]:
    limit = max(1, min(int(limit or 100), 500))
    sql = ("SELECT a.* FROM assets a "
           + ("JOIN asset_programs ap ON ap.asset_id=a.id " if program else "")
           + "WHERE 1=1")
    args = []
    if program:
        sql += " AND ap.program=?"
        args.append(_check_program(program))
    if kind:
        sql += " AND a.kind=?"
        args.append(_check(kind, ASSET_KINDS, "asset kind"))
    if query:
        sql += " AND a.identifier LIKE ?"
        args.append(f"%{query.lower()}%")
    sql += " ORDER BY a.last_seen DESC, a.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        out = _rows(conn, sql, tuple(args))
    for r in out:
        r["attrs"] = _load(r.get("attrs"), {})
    return out


def link_assets(src_id: int, dst_id: int, rel: str = "related", db_path: str | None = None) -> str:
    rel = str(rel or "related").strip().lower()
    if not re.fullmatch(r"[a-z_]{2,24}", rel):
        raise ValueError("invalid asset link relation")
    with _closed(connect(db_path)) as conn:
        with conn:
            if not _asset_row(conn, src_id) or not _asset_row(conn, dst_id):
                raise ValueError("both asset ids must exist")
            if int(src_id) == int(dst_id):
                raise ValueError("an asset cannot link to itself")
            conn.execute("INSERT OR IGNORE INTO asset_links(src_id, dst_id, rel, created_at) VALUES(?,?,?,?)",
                         (int(src_id), int(dst_id), rel, _now()))
    return f"linked asset #{int(src_id)} -{rel}-> #{int(dst_id)}"


# ------------------------------------------------------------------ scope import
def _scope_token(raw: str) -> str:
    line = re.sub(r"\s*#.*$", "", raw).strip()
    if not line:
        return ""
    toks = re.split(r"\s+", line)
    if len(toks) > 1 and re.fullmatch(r"[A-Z][A-Z0-9_]*", toks[0]):
        tok = toks[1]           # platform table row: "WILDCARD *.foo.com  [tags]"
    else:
        tok = toks[0]
    tok = tok.lstrip("=").strip("`'\"<>()[],;")
    return tok


def import_scope(program: str, scopes: str | None = None, db_path: str | None = None) -> dict:
    """Ingest a program's in-scope rows as assets. Idempotent; OOS rows are skipped."""
    program = _check_program(program)
    path = scopes or os.path.join(WS, "targets", program, "SCOPE.txt")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return {"ok": False, "reason": f"no SCOPE.txt at {path}", "counts": {}}
    counts = {}
    with _closed(connect(db_path)) as conn:
        with conn:
            for raw in lines:
                line = raw.strip()
                if not line:
                    continue
                bare = re.sub(r"^#+\s*", "", line)
                bare = re.sub(r"^[-=\s]+", "", bare)
                if _OOS.match(bare) and not _HOST.search(bare):
                    break
                if line.startswith("#"):
                    continue
                tok = _scope_token(line)
                if not tok:
                    continue
                host = _host(tok)
                if not host and "://" not in tok:
                    continue
                if "://" in tok:
                    kind = "url"
                elif _is_ip(tok):
                    kind = "ip"
                elif tok.startswith("*."):
                    kind = "domain"
                elif "." in host:
                    kind = _kind_for_host(host)
                else:
                    continue
                try:
                    upsert_asset(kind, tok, program, attrs={"source": "SCOPE.txt"}, conn=conn)
                except ValueError:
                    continue
                counts[kind] = counts.get(kind, 0) + 1
    return {"ok": True, "program": program, "counts": counts, "total": sum(counts.values())}


# ------------------------------------------------------------------ snapshots / attack-surface diff
# ARTEX keeps an asset history so an operator can see the surface MOVE (a new subdomain appears, an old
# endpoint stops answering). The graph is a current-state store, so history is explicit: take a snapshot
# (one JSON row, hash-committed) and diff today's in-scope set against it.
def _in_scope_assets(conn, program: str) -> list[dict]:
    """Every in-scope asset with its coverage state. Read-only."""
    exp = _exploration_or_empty(conn, program)
    rows = _rows(conn, "SELECT a.id, a.kind, a.identifier, a.last_seen FROM assets a "
                       "JOIN asset_programs ap ON ap.asset_id=a.id WHERE ap.program=? "
                       "ORDER BY a.kind, a.identifier", (program,))
    covered = {r[0] for r in conn.execute(
        "SELECT DISTINCT x.asset_id FROM anchors x JOIN nodes n ON n.id=x.node_id "
        "WHERE n.exploration_id=? AND n.kind IN ('fact','finding')", (exp["id"],))}
    covered |= {r[0] for r in conn.execute(
        "SELECT DISTINCT fa.asset_id FROM finding_assets fa JOIN findings f ON f.id=fa.finding_id "
        "WHERE f.exploration_id=? AND f.state IN ('confirmed','reported','closed')", (exp["id"],))}
    touched = {r[0] for r in conn.execute(
        "SELECT DISTINCT ta.asset_id FROM trace_assets ta JOIN traces t ON t.id=ta.trace_id "
        "WHERE t.exploration_id=?", (exp["id"],))}
    for r in rows:
        r["coverage"] = ("covered" if r["id"] in covered
                         else "touched" if r["id"] in touched else "untested")
    return rows


def take_snapshot(program: str, label: str = "", db_path: str | None = None) -> dict:
    """Record the in-scope asset set (identifier, kind, coverage state) as one immutable row."""
    program = _check_program(program)
    label = " ".join(str(label or "").split())[:120]
    with _closed(connect(db_path)) as conn:
        rows = _in_scope_assets(conn, program)
        payload = json.dumps({"program": program, "assets": rows}, sort_keys=True, default=str)
        now = _now()
        with conn:
            cur = conn.execute("INSERT INTO asset_snapshots(program, label, taken_at, assets, payload, sha256) "
                               "VALUES(?,?,?,?,?,?)",
                               (program, label, now, len(rows), payload,
                                hashlib.sha256(payload.encode()).hexdigest()))
            snap = _row(conn, "SELECT * FROM asset_snapshots WHERE id=?", (cur.lastrowid,))
    snap["payload"] = json.loads(snap["payload"])
    return snap


def snapshots_text(program: str, db_path: str | None = None) -> str:
    rows = _snapshot_list(program, db_path=db_path)
    if not rows:
        return f"no snapshots in {program} (gnoc graph snapshot)"
    lines = [f"ASSET SNAPSHOTS - {program}"]
    for r in rows:
        lines.append(f"  #{r['id']:<4} {r['taken_at'][:16]}  {r['assets']} assets  "
                     f"{r['label'] or '-'}  sha {r['sha256'][:12]}")
    return "\n".join(lines)


def _snapshot_list(program: str, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, "SELECT id, program, label, taken_at, assets, sha256 FROM asset_snapshots "
                           "WHERE program=? ORDER BY id DESC LIMIT 100", (program,))


def _snapshot_row(conn, program: str, ref) -> dict | None:
    """Find a snapshot by id, ISO timestamp prefix, or label."""
    ref = str(ref or "").strip()
    if not ref:
        return None
    if ref.isdigit():
        return _row(conn, "SELECT * FROM asset_snapshots WHERE program=? AND id=?",
                    (program, int(ref)))
    return _row(conn, "SELECT * FROM asset_snapshots WHERE program=? AND (taken_at LIKE ? OR label=?) "
                      "ORDER BY id DESC LIMIT 1", (program, ref + "%", ref))


def asset_diff(program: str, since=None, db_path: str | None = None) -> dict:
    """Compare the CURRENT in-scope asset set against a snapshot (default: the newest one).
    Returns added / removed / changed-coverage assets and the coverage delta."""
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        if since in (None, "", 0):
            base = _row(conn, "SELECT * FROM asset_snapshots WHERE program=? ORDER BY id DESC LIMIT 1",
                        (program,))
        else:
            base = _snapshot_row(conn, program, since)
        if not base:
            raise ValueError("no snapshot to diff against: run `gnoc graph snapshot` first"
                             if not since else f"no snapshot {since!r} in {program}")
        before = {a["identifier"]: a for a in json.loads(base["payload"]).get("assets", [])}
        after_rows = _in_scope_assets(conn, program)
    after = {a["identifier"]: a for a in after_rows}
    added = [after[k] for k in sorted(after) if k not in before]
    removed = [before[k] for k in sorted(before) if k not in after]
    changed = [after[k] for k in sorted(after)
               if k in before and before[k].get("coverage") != after[k].get("coverage")]
    def counts(rows):
        out = {"covered": 0, "touched": 0, "untested": 0}
        for r in rows:
            out[r.get("coverage", "untested")] = out.get(r.get("coverage", "untested"), 0) + 1
        return out
    return {"program": program, "base": {k: base[k] for k in ("id", "label", "taken_at", "assets", "sha256")},
            "current_assets": len(after_rows),
            "added": added, "removed": removed, "changed": changed,
            "coverage_before": counts(before.values()), "coverage_after": counts(after.values())}


def diff_text(program: str, since=None, db_path: str | None = None) -> str:
    d = asset_diff(program, since=since, db_path=db_path)
    b = d["base"]
    lines = [f"ATTACK-SURFACE DIFF - {program}",
             f"  base: snapshot #{b['id']} {b['taken_at'][:16]} ({b['assets']} assets)"
             f"  -> now ({d['current_assets']} assets)",
             f"  added {len(d['added'])}  removed {len(d['removed'])}  coverage-changed {len(d['changed'])}",
             "  coverage: " + ", ".join(f"{k}={v}" for k, v in sorted(d["coverage_before"].items()))
             + "  ->  " + ", ".join(f"{k}={v}" for k, v in sorted(d["coverage_after"].items()))]
    for a in d["added"][:40]:
        lines.append(f"  + {a['kind']} {a['identifier']}")
    for a in d["removed"][:40]:
        lines.append(f"  - {a['kind']} {a['identifier']}")
    for a in d["changed"][:40]:
        lines.append(f"  ~ {a['kind']} {a['identifier']}  now {a['coverage']}")
    if not (d["added"] or d["removed"] or d["changed"]):
        lines.append("  the in-scope surface has not moved")
    return "\n".join(lines)


# ------------------------------------------------------------------ exploration
def add_node(program: str, kind: str, title: str, body: str = "", state: str | None = None,
             priority: int = 0, owner: str = "lead", attrs: dict | None = None,
             asset_ids=None, parent_ids=None, rel: str | None = None,
             db_path: str | None = None) -> dict:
    program = _check_program(program)
    kind = _check(kind, NODE_KINDS, "node kind")
    state = _check(state or DEFAULT_STATE[kind], NODE_STATES[kind], f"{kind} state")
    title = " ".join(str(title or "").split())[:300]
    if not title:
        raise ValueError("node title is empty")
    body = str(body or "")[:20000]
    assets = []
    for a in (asset_ids or []):
        try:
            assets.append(int(a))
        except (TypeError, ValueError):
            continue
    parents = []
    for p in (parent_ids or []):
        try:
            parents.append(int(p))
        except (TypeError, ValueError):
            continue
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            now = _now()
            cur = conn.execute("INSERT INTO nodes(exploration_id, kind, title, body, state, priority, owner, "
                               "attrs, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                               (exp["id"], kind, title, body, state, int(priority or 0), owner,
                                _dump(attrs or {}), now, now))
            node_id = cur.lastrowid
            for aid in assets:
                if _asset_row(conn, aid):
                    conn.execute("INSERT OR IGNORE INTO anchors(node_id, asset_id, created_at) VALUES(?,?,?)",
                                 (node_id, aid, now))
            if not parents:
                # small helpful default: a fact/finding hangs off the newest intent; an intent off the newest goal
                want = "intent" if kind in ("fact", "finding") else "goal" if kind == "intent" else None
                if want:
                    p = _row(conn, "SELECT id FROM nodes WHERE exploration_id=? AND kind=? "
                                   "ORDER BY id DESC LIMIT 1", (exp["id"], want))
                    if p:
                        parents = [p["id"]]
            link_rel = _check(rel or DEFAULT_REL.get(kind, "derived_from"), RELS, "edge relation")
            for pid in parents:
                if pid != node_id and _row(conn, "SELECT id FROM nodes WHERE id=? AND exploration_id=?",
                                           (pid, exp["id"])):
                    conn.execute("INSERT OR IGNORE INTO edges(exploration_id, src_id, dst_id, rel, created_at) "
                                 "VALUES(?,?,?,?,?)", (exp["id"], pid, node_id, link_rel, now))
            return node_detail(program, node_id, db_path=db_path, _conn=conn)
    # unreachable


def node_detail(program: str, node_id: int, db_path: str | None = None,
                _conn: sqlite3.Connection | None = None) -> dict | None:
    program = _check_program(program)
    own = _conn is None
    conn = _conn or connect(db_path)
    try:
        exp = _exploration_or_empty(conn, program)
        node = _row(conn, "SELECT * FROM nodes WHERE id=? AND exploration_id=?", (int(node_id), exp["id"]))
        if not node:
            return None
        node["attrs"] = _load(node.get("attrs"), {})
        node["anchors"] = [dict(r) for r in conn.execute(
            "SELECT a.id, a.kind, a.identifier FROM anchors x JOIN assets a ON a.id=x.asset_id "
            "WHERE x.node_id=? ORDER BY a.kind, a.identifier", (int(node_id),)).fetchall()]
        node["parents"] = [dict(r) for r in conn.execute(
            "SELECT n.id, n.kind, n.state, n.title, e.rel FROM edges e JOIN nodes n ON n.id=e.src_id "
            "WHERE e.dst_id=? ORDER BY e.created_at", (int(node_id),)).fetchall()]
        node["children"] = [dict(r) for r in conn.execute(
            "SELECT n.id, n.kind, n.state, n.title, e.rel FROM edges e JOIN nodes n ON n.id=e.dst_id "
            "WHERE e.src_id=? ORDER BY e.created_at", (int(node_id),)).fetchall()]
        node["traces"] = conn.execute("SELECT COUNT(*) FROM traces WHERE node_id=?", (int(node_id),)).fetchone()[0]
        return node
    finally:
        if own:
            conn.close()


def node_search(program: str, kind: str | None = None, state: str | None = None,
                query: str = "", limit: int = 100, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    limit = max(1, min(int(limit or 100), 500))
    sql = ("SELECT n.*, (SELECT COUNT(*) FROM anchors a WHERE a.node_id=n.id) AS n_assets "
           "FROM nodes n JOIN explorations e ON e.id=n.exploration_id WHERE e.program=?")
    args = [program]
    if kind:
        sql += " AND n.kind=?"
        args.append(_check(kind, NODE_KINDS, "node kind"))
    if state:
        sql += " AND n.state=?"
        args.append(str(state).strip().lower())
    if query:
        sql += " AND (n.title LIKE ? OR n.body LIKE ?)"
        args += [f"%{query}%", f"%{query}%"]
    sql += " ORDER BY n.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        rows = _rows(conn, sql, tuple(args))
    for r in rows:
        r["attrs"] = _load(r.get("attrs"), {})
    return rows


def update_node(program: str, node_id: int, state: str | None = None, body: str | None = None,
                title: str | None = None, priority: int | None = None, attrs: dict | None = None,
                db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            node = _row(conn, "SELECT * FROM nodes WHERE id=? AND exploration_id=?", (int(node_id), exp["id"]))
            if not node:
                raise ValueError(f"no node #{node_id} in {program}")
            new_state = node["state"]
            if state:
                new_state = _check(state, NODE_STATES[node["kind"]], f"{node['kind']} state")
            merged = _load(node.get("attrs"), {})
            if isinstance(attrs, dict):
                merged.update(attrs)
            done = _now() if new_state != node["state"] and new_state in (
                "done", "met", "confirmed", "completed", "consumed", "stopped", "exhausted") else node.get("completed_at")
            conn.execute("UPDATE nodes SET state=?, body=?, title=?, priority=?, attrs=?, updated_at=?, "
                         "completed_at=? WHERE id=?",
                         (new_state, str(body if body is not None else node["body"])[:20000],
                          " ".join(str(title if title is not None else node["title"]).split())[:300],
                          int(priority if priority is not None else node["priority"]),
                          _dump(merged), _now(), done, int(node_id)))
            return node_detail(program, node_id, db_path=db_path, _conn=conn)


def link_nodes(program: str, src_id: int, dst_id: int, rel: str = "derived_from",
               db_path: str | None = None) -> str:
    program = _check_program(program)
    rel = _check(rel, RELS, "edge relation")
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            for nid in (int(src_id), int(dst_id)):
                if not _row(conn, "SELECT id FROM nodes WHERE id=? AND exploration_id=?", (nid, exp["id"])):
                    raise ValueError(f"no node #{nid} in {program}")
            if int(src_id) == int(dst_id):
                raise ValueError("a node cannot link to itself")
            conn.execute("INSERT OR IGNORE INTO edges(exploration_id, src_id, dst_id, rel, created_at) "
                         "VALUES(?,?,?,?,?)", (exp["id"], int(src_id), int(dst_id), rel, _now()))
    return f"linked node #{int(src_id)} -{rel}-> #{int(dst_id)}"


# ------------------------------------------------------------------ path / lineage
def _edges_of(conn, exploration_id: int) -> list[dict]:
    return _rows(conn, "SELECT src_id, dst_id, rel FROM edges WHERE exploration_id=? ORDER BY created_at",
                 (int(exploration_id),))


def node_path(program: str, src_id: int, dst_id: int, max_depth: int = 12,
              db_path: str | None = None) -> dict:
    """Shortest chain between two exploration nodes, following edges in EITHER direction (a finding's
    'how did we get here' normally walks backwards). Breadth-first, bounded, deterministic."""
    program = _check_program(program)
    src_id, dst_id = int(src_id), int(dst_id)
    max_depth = max(1, min(int(max_depth or 12), 50))
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        nodes = {r["id"]: r for r in _rows(conn, "SELECT id, kind, state, title FROM nodes "
                                                 "WHERE exploration_id=?", (exp["id"],))}
        for nid in (src_id, dst_id):
            if nid not in nodes:
                raise ValueError(f"no node #{nid} in {program}")
        if src_id == dst_id:
            return {"program": program, "found": True, "depth": 0, "path": [nodes[src_id]],
                    "edges": []}
        adj: dict[int, list[tuple]] = {}
        for e in _edges_of(conn, exp["id"]):
            adj.setdefault(e["src_id"], []).append((e["dst_id"], e["rel"], "forward"))
            adj.setdefault(e["dst_id"], []).append((e["src_id"], e["rel"], "reverse"))
        prev: dict[int, tuple] = {src_id: (None, None, None)}
        frontier, depth = [src_id], 0
        while frontier and depth < max_depth and dst_id not in prev:
            depth += 1
            nxt = []
            for cur in frontier:
                for other, rel, direction in adj.get(cur, []):
                    if other in prev:
                        continue
                    prev[other] = (cur, rel, direction)
                    nxt.append(other)
                    if other == dst_id:
                        break
                if dst_id in prev:
                    break
            frontier = nxt
        if dst_id not in prev:
            return {"program": program, "found": False, "depth": None, "path": [], "edges": [],
                    "searched": len(prev)}
    chain, edges_back, at = [dst_id], [], dst_id
    while prev[at][0] is not None:
        before, rel, direction = prev[at]
        edges_back.append({"from": before, "to": at, "rel": rel, "direction": direction})
        chain.append(before)
        at = before
    chain.reverse()
    edges_back.reverse()
    return {"program": program, "found": True, "depth": len(edges_back),
            "path": [nodes[n] for n in chain], "edges": edges_back}


def path_text(program: str, src_id: int, dst_id: int, db_path: str | None = None) -> str:
    r = node_path(program, src_id, dst_id, db_path=db_path)
    if not r["found"]:
        return (f"no path from #{src_id} to #{dst_id} in {program} within the depth bound "
                f"({r.get('searched', 0)} nodes reachable)")
    lines = [f"PATH - {program}: #{src_id} -> #{dst_id} ({r['depth']} step(s))"]
    first = r["path"][0]
    lines.append(f"  start #{first['id']} {first['kind']}[{first['state']}] {_short(first['title'], 70)}")
    for e, nxt in zip(r["edges"], r["path"][1:]):
        arrow = f"-{e['rel']}->" if e["direction"] == "forward" else f"<-{e['rel']}-"
        lines.append(f"  {arrow} #{nxt['id']} {nxt['kind']}[{nxt['state']}] {_short(nxt['title'], 70)}")
    return "\n".join(lines)


def node_lineage(program: str, node_id: int, max_depth: int = 12, db_path: str | None = None) -> dict:
    """Everything that led to a node: its ancestors through derived_from/spawns/yields/proves edges,
    nearest first, with the asset each ancestor is anchored to."""
    program = _check_program(program)
    node_id = int(node_id)
    max_depth = max(1, min(int(max_depth or 12), 50))
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        node = _row(conn, "SELECT id, kind, state, title FROM nodes WHERE id=? AND exploration_id=?",
                    (node_id, exp["id"]))
        if not node:
            raise ValueError(f"no node #{node_id} in {program}")
        adj: dict[int, list[dict]] = {}
        for e in _edges_of(conn, exp["id"]):
            adj.setdefault(e["dst_id"], []).append({"id": e["src_id"], "rel": e["rel"]})
        names = {r["id"]: r for r in _rows(conn, "SELECT id, kind, state, title FROM nodes "
                                                  "WHERE exploration_id=?", (exp["id"],))}
        anchors: dict[int, list[str]] = {}
        for r in conn.execute("SELECT x.node_id, a.identifier FROM anchors x JOIN assets a "
                              "ON a.id=x.asset_id JOIN nodes n ON n.id=x.node_id "
                              "WHERE n.exploration_id=?", (exp["id"],)):
            anchors.setdefault(r[0], []).append(r[1])
    seen = {node_id}
    seen_edges = set()
    frontier, depth, rows = [node_id], 0, []
    while frontier and depth < max_depth:
        depth += 1
        nxt = []
        for cur in frontier:
            for parent in adj.get(cur, []):
                pid = parent["id"]
                key = (pid, cur, parent["rel"])
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                row = dict(names.get(pid) or {"id": pid, "kind": "?", "state": "?", "title": "?"})
                row.update({"child": cur, "rel": parent["rel"], "depth": depth,
                            "assets": anchors.get(pid, [])})
                rows.append(row)
                if pid not in seen:
                    seen.add(pid)
                    nxt.append(pid)
        frontier = nxt
    return {"program": program, "node": node, "ancestors": rows}


def lineage_text(program: str, node_id: int, db_path: str | None = None) -> str:
    r = node_lineage(program, node_id, db_path=db_path)
    n = r["node"]
    lines = [f"LINEAGE - {program}: #{n['id']} {n['kind']}[{n['state']}] {_short(n['title'], 80)}"]
    if not r["ancestors"]:
        lines.append("  no parents: this is a root of the exploration graph")
        return "\n".join(lines)
    for row in sorted(r["ancestors"], key=lambda x: (x["depth"], x["id"])):
        assets = f"  assets={','.join(row['assets'][:3])}" if row["assets"] else ""
        lines.append(f"  {'  ' * (row['depth'] - 1)}<-{row['rel']}- #{row['id']} {row['kind']}"
                     f"[{row['state']}] {_short(row['title'], 70)}{assets}")
    return "\n".join(lines)


# ------------------------------------------------------------------ todos
def _lease_until(lease_secs=600) -> str:
    try:
        seconds = max(30, min(int(lease_secs or 600), 86400))
    except (TypeError, ValueError):
        seconds = 600
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(timespec="seconds")


def _lease_live(row: dict) -> bool:
    until = str(row.get("lease_until") or "")
    return bool(until and until > _now())


def todo_add(program: str, content: str, depends_on=None, db_path: str | None = None) -> dict:
    program = _check_program(program)
    text = " ".join(str(content or "").split())[:500]
    if not text:
        raise ValueError("todo content is empty")
    deps = []
    for d in (depends_on or []):
        try:
            deps.append(int(d))
        except (TypeError, ValueError):
            continue
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            now = _now()
            cur = conn.execute("INSERT INTO todos(exploration_id, content, state, depends_on, created_at, updated_at) "
                               "VALUES(?,?, 'pending', ?, ?, ?)", (exp["id"], text, _dump(deps), now, now))
            out = _row(conn, "SELECT * FROM todos WHERE id=?", (cur.lastrowid,))
            out["depends_on"] = _load(out.get("depends_on"), [])
            return out


def todo_list(program: str, state: str | None = None, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    sql = ("SELECT t.* FROM todos t JOIN explorations e ON e.id=t.exploration_id WHERE e.program=?")
    args = [program]
    if state:
        sql += " AND t.state=?"
        args.append(_check(state, TODO_STATES, "todo state"))
    sql += " ORDER BY t.id"
    with _closed(connect(db_path)) as conn:
        rows = _rows(conn, sql, tuple(args))
    for r in rows:
        r["depends_on"] = _load(r.get("depends_on"), [])
        r["lease_live"] = _lease_live(r)
    return rows


def todo_update(program: str, todo_id: int, state: str | None = None, content: str | None = None,
                db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT * FROM todos WHERE id=? AND exploration_id=?", (int(todo_id), exp["id"]))
            if not row:
                raise ValueError(f"no todo #{todo_id} in {program}")
            new_state = _check(state, TODO_STATES, "todo state") if state else row["state"]
            text = " ".join(str(content if content is not None else row["content"]).split())[:500]
            now = _now()
            claimed = "" if new_state in ("pending", "blocked", "completed") else row["claimed_by"]
            lease = None if new_state in ("pending", "blocked", "completed") else row["lease_until"]
            completed = now if new_state == "completed" else (None if new_state == "pending"
                                                                 else row["completed_at"])
            conn.execute("UPDATE todos SET state=?, content=?, claimed_by=?, lease_until=?, completed_at=?, "
                         "updated_at=? WHERE id=?", (new_state, text, claimed, lease, completed, now, int(todo_id)))
            out = _row(conn, "SELECT * FROM todos WHERE id=?", (int(todo_id),))
            out["depends_on"] = _load(out.get("depends_on"), [])
            return out


def _todo_ready(rows: list[dict]) -> dict | None:
    done = {r["id"] for r in rows if r["state"] == "completed"}
    for row in rows:
        if row["state"] == "in_progress":
            if _lease_live(row):
                continue
        elif row["state"] != "pending":
            continue
        if all(d in done for d in row.get("depends_on") or []):
            return row
    return None


def todo_next(program: str, db_path: str | None = None) -> dict | None:
    return _todo_ready(todo_list(program, db_path=db_path))


def todo_claim(program: str, todo_id=None, worker: str = "worker", lease_secs=600,
               db_path: str | None = None) -> dict:
    """Atomically claim a ready todo for a worker. A live lease held by another worker is refused;
    an expired lease is reclaimable. This is the planner/worker handoff the old todo_next lacked."""
    program = _check_program(program)
    worker = " ".join(str(worker or "worker").split())[:40] or "worker"
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        exp = _ensure_exploration_conn(conn, program)
        rows = _rows(conn, "SELECT * FROM todos WHERE exploration_id=? ORDER BY id", (exp["id"],))
        for r in rows:
            r["depends_on"] = _load(r.get("depends_on"), [])
        if todo_id not in (None, "", 0):
            row = next((r for r in rows if r["id"] == int(todo_id)), None)
            if not row:
                raise ValueError(f"no todo #{todo_id} in {program}")
            if row["state"] == "completed":
                raise ValueError(f"todo #{row['id']} is already completed")
            if row["state"] == "blocked":
                raise ValueError(f"todo #{row['id']} is blocked; release it to pending first")
            if row["state"] == "in_progress" and _lease_live(row) and row["claimed_by"] != worker:
                raise ValueError(f"todo #{row['id']} is claimed by {row['claimed_by']} until {row['lease_until']}")
            done = {r["id"] for r in rows if r["state"] == "completed"}
            missing = [d for d in row["depends_on"] if d not in done]
            if missing:
                raise ValueError(f"todo #{row['id']} is blocked by "
                                 + ", ".join(f"#{d}" for d in missing if d not in done))
        else:
            row = _todo_ready(rows)
            if not row:
                raise ValueError("no ready todo (all completed, blocked, or leased)")
        now = _now()
        conn.execute("UPDATE todos SET state='in_progress', claimed_by=?, lease_until=?, "
                     "attempts=attempts+1, last_error='', updated_at=? WHERE id=?",
                     (worker, _lease_until(lease_secs), now, row["id"]))
        out = _row(conn, "SELECT * FROM todos WHERE id=?", (row["id"],))
        out["depends_on"] = _load(out.get("depends_on"), [])
        out["lease_live"] = _lease_live(out)
        conn.commit()
        return out
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def todo_heartbeat(program: str, todo_id: int, worker: str = "worker", lease_secs=600,
                   db_path: str | None = None) -> dict:
    program = _check_program(program)
    worker = " ".join(str(worker or "worker").split())[:40] or "worker"
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT * FROM todos WHERE id=? AND exploration_id=?", (int(todo_id), exp["id"]))
            if not row:
                raise ValueError(f"no todo #{todo_id} in {program}")
            if row["state"] != "in_progress" or row["claimed_by"] != worker:
                raise ValueError(f"todo #{todo_id} is not leased to {worker}")
            conn.execute("UPDATE todos SET lease_until=?, updated_at=? WHERE id=?",
                         (_lease_until(lease_secs), _now(), int(todo_id)))
            out = _row(conn, "SELECT * FROM todos WHERE id=?", (int(todo_id),))
            out["depends_on"] = _load(out.get("depends_on"), [])
            return out


def todo_release(program: str, todo_id: int, worker: str = "worker", state: str = "pending",
                 error: str = "", db_path: str | None = None) -> dict:
    program = _check_program(program)
    worker = " ".join(str(worker or "worker").split())[:40] or "worker"
    state = _check(state or "pending", ("pending", "blocked"), "release state")
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT * FROM todos WHERE id=? AND exploration_id=?", (int(todo_id), exp["id"]))
            if not row:
                raise ValueError(f"no todo #{todo_id} in {program}")
            if row["state"] == "completed":
                raise ValueError(f"todo #{todo_id} is already completed")
            if row["claimed_by"] and row["claimed_by"] != worker:
                raise ValueError(f"todo #{todo_id} is claimed by {row['claimed_by']}, not {worker}")
            conn.execute("UPDATE todos SET state=?, claimed_by='', lease_until=NULL, last_error=?, "
                         "completed_at=NULL, updated_at=? WHERE id=?",
                         (state, str(error or "")[:500], _now(), int(todo_id)))
            out = _row(conn, "SELECT * FROM todos WHERE id=?", (int(todo_id),))
            out["depends_on"] = _load(out.get("depends_on"), [])
            return out
    return None


# ------------------------------------------------------------------ traces
def trace_add(program: str, tool: str, args: str = "", result: str = "", node_id: int | None = None,
              worker: str = "lead", ok: bool | None = None, asset_ids=None,
              db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            if node_id and not _row(conn, "SELECT id FROM nodes WHERE id=? AND exploration_id=?",
                                    (int(node_id), exp["id"])):
                node_id = None
            cur = conn.execute("INSERT INTO traces(exploration_id, node_id, worker, tool, args, result, ok, "
                               "created_at) VALUES(?,?,?,?,?,?,?,?)",
                               (exp["id"], int(node_id) if node_id else None, str(worker or "lead")[:40],
                                str(tool or "?")[:60], str(args or "")[:8000], str(result or "")[:16000],
                                None if ok is None else (1 if ok else 0), _now()))
            tid = cur.lastrowid
            for a in (asset_ids or []):
                try:
                    aid = int(a)
                except (TypeError, ValueError):
                    continue
                if _asset_row(conn, aid):
                    conn.execute("INSERT OR IGNORE INTO trace_assets(trace_id, asset_id) VALUES(?,?)", (tid, aid))
            return _row(conn, "SELECT * FROM traces WHERE id=?", (tid,))


def trace_search(program: str, query: str = "", limit: int = 50, node_id: int | None = None,
                 exclude_node: int | None = None, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    limit = max(1, min(int(limit or 50), 200))
    sql = ("SELECT t.* FROM traces t JOIN explorations e ON e.id=t.exploration_id WHERE e.program=?")
    args = [program]
    if node_id:
        sql += " AND t.node_id=?"
        args.append(int(node_id))
    if exclude_node:
        sql += " AND (t.node_id IS NULL OR t.node_id<>?)"
        args.append(int(exclude_node))
    if query:
        sql += " AND (t.tool LIKE ? OR t.args LIKE ? OR t.result LIKE ?)"
        args += [f"%{query}%"] * 3
    sql += " ORDER BY t.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        rows = _rows(conn, sql, tuple(args))
    for r in rows:
        r["args"] = r["args"][:500]
        r["result"] = r["result"][:500]
    return rows


def trace_get(program: str, ids, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    want = []
    for i in (ids or []):
        try:
            want.append(int(i))
        except (TypeError, ValueError):
            continue
    if not want:
        return []
    marks = ",".join("?" for _ in want)
    with _closed(connect(db_path)) as conn:
        rows = _rows(conn, f"SELECT t.* FROM traces t JOIN explorations e ON e.id=t.exploration_id "
                           f"WHERE e.program=? AND t.id IN ({marks}) ORDER BY t.id", tuple([program] + want))
    return rows


def record_probe(program: str, url: str, method: str = "GET", status=None, raw: str = "",
                 hypothesis: str = "", worker: str = "lead", db_path: str | None = None) -> dict:
    """Auto-write one probe into the asset graph + exploration traces. Never raises on graph failure."""
    program = _check_program(program)
    host = _host(url)
    assets = []
    try:
        if host:
            assets.append(upsert_asset(_kind_for_host(host), host, program, db_path=db_path)["id"])
        if url:
            assets.append(upsert_asset("endpoint", url, program, attrs={"last_method": method},
                                       db_path=db_path)["id"])
    except ValueError:
        pass
    node_id = None
    key = ""
    m = re.search(r"\bH\d+\b", str(hypothesis or ""), re.I)
    if m:
        key = m.group(0).upper()
        with _closed(connect(db_path)) as conn:
            exp = _ensure_exploration_conn(conn, program)
            conn.commit()
            row = _row(conn, "SELECT id FROM nodes WHERE exploration_id=? AND kind='intent' "
                             "AND json_extract(attrs, '$.hypothesis')=? ORDER BY id DESC LIMIT 1",
                       (exp["id"], key))
        if row:
            node_id = row["id"]
        else:
            label = str(hypothesis).strip()[:240]
            title = label if re.match(rf"^{re.escape(key)}\b", label, re.I) else f"{key}: {label}"
            node = add_node(program, "intent", title,
                            body="auto-created from a probe", state="running",
                            attrs={"hypothesis": key}, asset_ids=assets, db_path=db_path)
            node_id = node["id"]
    result = f"HTTP {status} len={len(str(raw))} raw={raw}" if status is not None else f"raw={raw}"
    trace = trace_add(program, "http_request", f"{method.upper()} {url}", result,
                      node_id=node_id, worker=worker, ok=(str(status).startswith(("2", "3")) if status else None),
                      asset_ids=assets, db_path=db_path)
    traffic_id = None
    try:   # the traffic store must never break a probe
        traffic_id = traffic_add(program, method, url, status=status, raw_path=str(raw or ""),
                                 trace_id=trace["id"], db_path=db_path)["id"]
    except Exception:  # noqa: BLE001
        traffic_id = None
    return {"assets": assets, "node_id": node_id, "trace_id": trace["id"], "hypothesis": key,
            "traffic_id": traffic_id}


# ------------------------------------------------------------------ traffic
# ARTEX's traffic page: every exchange the harness makes, stored with its headers and bodies, searchable
# by host/method/status, so a later reader sees the bytes without re-running the probe. record_probe()
# feeds it automatically; the raw capture stays the source of truth on disk.
def _capture_parts(raw_path: str) -> dict:
    """Headers/bodies/status from a gnoc raw capture ({"request": {...}, "response": {...}})."""
    parts = {"request_headers": "", "request_body": "", "response_headers": "", "response_body": "",
             "status": None, "method": "", "url": ""}
    path = str(raw_path or "")
    if not path:
        return parts
    real = os.path.realpath(path if os.path.isabs(path) else os.path.join(WS, path))
    ws_real = os.path.realpath(WS)
    if real != ws_real and not real.startswith(ws_real + os.sep):
        return parts
    try:
        with open(real, "rb") as fh:
            capture = json.loads(fh.read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return parts
    req = capture.get("request") if isinstance(capture.get("request"), dict) else {}
    resp = capture.get("response") if isinstance(capture.get("response"), dict) else {}

    def headers(obj):
        h = obj.get("headers") if isinstance(obj, dict) else None
        if isinstance(h, dict):
            return "\n".join(f"{k}: {v}" for k, v in h.items())
        return str(h or "")

    def body(obj):
        b = obj.get("body") if isinstance(obj, dict) else None
        return b if isinstance(b, str) else ("" if b is None else json.dumps(b, default=str))

    parts.update({"request_headers": headers(req)[:8000], "request_body": body(req)[:16000],
                  "response_headers": headers(resp)[:8000], "response_body": body(resp)[:16000],
                  "method": str(req.get("method") or "").upper(),
                  "url": str(req.get("url") or ""), "status": resp.get("status")})
    return parts


def traffic_add(program: str, method: str = "", url: str = "", status=None,
                request_headers: str = "", request_body: str = "", response_headers: str = "",
                response_body: str = "", raw_path: str = "", trace_id=None,
                db_path: str | None = None) -> dict:
    """Store one HTTP exchange. The same exchange seen twice increments seen_count instead of
    creating a second row. Missing pieces are filled from the raw capture when it is readable."""
    program = _check_program(program)
    parts = _capture_parts(raw_path)
    method = str(method or "").upper()[:16] or parts["method"]
    url = str(url or "")[:4000] or parts["url"]
    if status in (None, ""):
        status = parts["status"]
    try:
        status = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status = None
    fields = {"request_headers": str(request_headers or parts["request_headers"])[:8000],
              "request_body": str(request_body or parts["request_body"])[:16000],
              "response_headers": str(response_headers or parts["response_headers"])[:8000],
              "response_body": str(response_body or parts["response_body"])[:16000]}
    host = _host(url)
    digest = hashlib.sha256(json.dumps(
        {"method": method, "url": url, "status": status, **fields},
        sort_keys=True, ensure_ascii=True).encode()).hexdigest()
    now = _now()
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            conn.execute(
                "INSERT INTO traffic(exploration_id, host, method, url, status, request_headers, "
                "request_body, response_headers, response_body, raw_path, trace_id, sha256, seen_count, "
                "first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?) "
                "ON CONFLICT(exploration_id, sha256) DO UPDATE SET "
                "seen_count=traffic.seen_count+1, last_seen=excluded.last_seen, "
                "raw_path=COALESCE(NULLIF(traffic.raw_path, ''), excluded.raw_path), "
                "trace_id=COALESCE(traffic.trace_id, excluded.trace_id)",
                (exp["id"], host, method, url, status, fields["request_headers"], fields["request_body"],
                 fields["response_headers"], fields["response_body"], str(raw_path or "")[:500],
                 int(trace_id) if trace_id not in (None, "", 0) else None, digest, now, now))
            return _row(conn, "SELECT * FROM traffic WHERE exploration_id=? AND sha256=?",
                        (exp["id"], digest))


def traffic_search(program: str, query: str = "", host: str = "", method: str = "", status=None,
                   limit: int = 50, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    limit = max(1, min(int(limit or 50), 500))
    sql = ("SELECT t.* FROM traffic t JOIN explorations e ON e.id=t.exploration_id "
           "WHERE e.program=?")
    args = [program]
    if query:
        sql += " AND (t.url LIKE ? OR t.request_body LIKE ? OR t.response_body LIKE ?)"
        args += [f"%{query}%"] * 3
    if host:
        sql += " AND t.host LIKE ?"
        args.append(f"%{host}%")
    if method:
        sql += " AND t.method=?"
        args.append(str(method).upper())
    if status not in (None, ""):
        try:
            sql += " AND t.status=?"
            args.append(int(status))
        except (TypeError, ValueError):
            pass
    sql += " ORDER BY t.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, sql, tuple(args))


def traffic_hosts(program: str, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, "SELECT t.host, COUNT(*) n, SUM(t.seen_count) hits, "
                           "SUM(CASE WHEN t.status BETWEEN 200 AND 299 THEN 1 ELSE 0 END) ok, "
                           "SUM(CASE WHEN t.status >= 400 THEN 1 ELSE 0 END) bad, "
                           "MAX(t.last_seen) last_seen FROM traffic t JOIN explorations e "
                           "ON e.id=t.exploration_id WHERE e.program=? GROUP BY t.host "
                           "ORDER BY n DESC, t.host", (program,))


def traffic_get(program: str, ids, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    ids = _int_list(ids if isinstance(ids, (list, tuple, set)) else [ids])
    if not ids:
        return []
    marks = ",".join("?" for _ in ids)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, f"SELECT t.* FROM traffic t JOIN explorations e ON e.id=t.exploration_id "
                           f"WHERE e.program=? AND t.id IN ({marks}) ORDER BY t.id", [program, *ids])


def traffic_purge(program: str, host: str = "", db_path: str | None = None) -> int:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            if host:
                cur = conn.execute("DELETE FROM traffic WHERE exploration_id=? AND host LIKE ?",
                                   (exp["id"], f"%{host}%"))
            else:
                cur = conn.execute("DELETE FROM traffic WHERE exploration_id=?", (exp["id"],))
            return cur.rowcount or 0


def traffic_text(program: str, query: str = "", host: str = "", method: str = "", status=None,
                 limit: int = 50, db_path: str | None = None) -> str:
    rows = traffic_search(program, query=query, host=host, method=method, status=status,
                          limit=limit, db_path=db_path)
    if not rows:
        return f"no traffic in {program}" + (f" matching {query!r}" if query else "")
    lines = [f"TRAFFIC - {program} ({len(rows)} shown)"]
    for r in rows:
        code = r["status"] if r["status"] is not None else "???"
        lines.append(f"  #{r['id']:<5} {r['method']:<6} {code}  {_short(r['url'], 78)}  "
                     f"req={len(r['request_body'])}b resp={len(r['response_body'])}b hits={r['seen_count']}")
    return "\n".join(lines)


def traffic_hosts_text(program: str, db_path: str | None = None) -> str:
    rows = traffic_hosts(program, db_path=db_path)
    if not rows:
        return f"no traffic hosts in {program}"
    lines = [f"TRAFFIC HOSTS - {program}"]
    for r in rows:
        lines.append(f"  {r['n']:>4} exchanges ({r['hits']} hits)  {r['host'] or '(no host)'}  "
                     f"2xx={r['ok']} 4xx+={r['bad']}  last {str(r['last_seen'])[:16]}")
    return "\n".join(lines)


def traffic_detail_text(program: str, traffic_id: int, db_path: str | None = None) -> str:
    rows = traffic_get(program, [traffic_id], db_path=db_path)
    if not rows:
        return f"no traffic #{traffic_id} in {program}"
    r = rows[0]
    lines = [f"TRAFFIC #{r['id']}  {r['method']} {r['url']}",
             f"  host {r['host'] or '-'}  status {r['status'] if r['status'] is not None else '???'}"
             f"  hits {r['seen_count']}  first {r['first_seen'][:16]}  last {r['last_seen'][:16]}"]
    if r.get("raw_path"):
        lines.append(f"  raw {r['raw_path']}")
    lines += ["", "REQUEST", r["request_headers"] or "(no headers captured)"]
    if r.get("request_body"):
        lines += ["", r["request_body"]]
    lines += ["", f"RESPONSE {r['status'] if r['status'] is not None else ''}".rstrip(),
              r["response_headers"] or "(no headers captured)"]
    if r.get("response_body"):
        lines += ["", r["response_body"]]
    return "\n".join(lines)


# ------------------------------------------------------------------ evidence / findings
def _int_list(values) -> list[int]:
    out = []
    for v in (values or []):
        try:
            out.append(int(v))
        except (TypeError, ValueError):
            continue
    return out


def _json_excerpt(value, limit: int) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
    return text[:limit]


def _evidence_row(conn, exploration_id: int, evidence_id: int) -> dict | None:
    row = _row(conn, "SELECT * FROM evidence WHERE id=? AND exploration_id=?",
               (int(evidence_id), int(exploration_id)))
    if row:
        row["asset"] = _asset_row(conn, row["asset_id"]) if row.get("asset_id") else None
        row["trace"] = _row(conn, "SELECT id, worker, tool, ok, created_at FROM traces WHERE id=?",
                            (row["trace_id"],)) if row.get("trace_id") else None
    return row


def evidence_add(program: str, trace_id=None, asset_id=None, kind: str = "probe", label: str = "",
                 method: str = "", url: str = "", status=None, request: str = "", response: str = "",
                 detail: str = "", db_path: str | None = None) -> dict:
    """Promote a trace (or a manual observation) into deduplicated evidence. The sha256 covers the
    method/url/status/excerpts, so the same observation seen twice increments seen_count instead of
    creating a second evidence row."""
    program = _check_program(program)
    kind = _check(kind or "probe", EVIDENCE_KINDS, "evidence kind")
    method = str(method or "").upper()[:16]
    url = str(url or "")[:4000]
    request = str(request or "")[:8000]
    response = str(response or "")[:16000]
    detail = str(detail or "")[:8000]
    label = " ".join(str(label or "").split())[:240]
    try:
        status = int(status) if status not in (None, "") else None
    except (TypeError, ValueError):
        status = None
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            trace = None
            if trace_id not in (None, "", 0):
                try:
                    tid = int(trace_id)
                except (TypeError, ValueError):
                    raise ValueError(f"invalid trace id: {trace_id!r}")
                trace = _row(conn, "SELECT * FROM traces WHERE id=? AND exploration_id=?", (tid, exp["id"]))
                if not trace:
                    raise ValueError(f"no trace #{tid} in {program}")
                if not url:
                    bits = str(trace.get("args") or "").split(None, 1)
                    if len(bits) == 2:
                        method = method or bits[0].upper()
                        url = bits[1]
                if not response:
                    response = str(trace.get("result") or "")
                if status is None:
                    m = re.search(r"HTTP\s+(\d{3})", str(trace.get("result") or ""))
                    if m:
                        status = int(m.group(1))
                if not label:
                    label = str(trace.get("tool") or "")
                if asset_id in (None, ""):
                    a = _row(conn, "SELECT ta.asset_id FROM trace_assets ta JOIN assets a ON a.id=ta.asset_id "
                                   "WHERE ta.trace_id=? ORDER BY CASE a.kind WHEN 'endpoint' THEN 0 "
                                   "WHEN 'url' THEN 1 WHEN 'service' THEN 2 WHEN 'subdomain' THEN 3 ELSE 4 END, "
                                   "a.id LIMIT 1", (tid,))
                    if a:
                        asset_id = a["asset_id"]
            asset_id = int(asset_id) if asset_id not in (None, "", 0) else None
            if asset_id is not None and not _asset_row(conn, asset_id):
                raise ValueError(f"no asset #{asset_id}")
            raw_path = ""
            if trace:
                m = re.search(r"(?:^|\s)raw=([^\s]+)", str(trace.get("result") or ""))
                if m:
                    raw_path = m.group(1).strip(".,;")
            raw_sha = ""
            if raw_path:
                ws_real = os.path.realpath(WS)
                for cand in (raw_path, os.path.join(WS, raw_path)):
                    real = os.path.realpath(cand)
                    if real != ws_real and not real.startswith(ws_real + os.sep):
                        continue
                    if not os.path.isfile(real):
                        continue
                    try:
                        with open(real, "rb") as fh:
                            raw_bytes = fh.read()
                        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
                        try:
                            capture = json.loads(raw_bytes.decode("utf-8", "replace"))
                        except ValueError:
                            capture = {}
                        req = capture.get("request") if isinstance(capture.get("request"), dict) else {}
                        resp = capture.get("response") if isinstance(capture.get("response"), dict) else {}
                        method = method or str(req.get("method") or "").upper()
                        url = url or str(req.get("url") or "")
                        if status is None and resp.get("status") is not None:
                            try:
                                status = int(resp["status"])
                            except (TypeError, ValueError):
                                pass
                        if req:
                            request = _json_excerpt({"headers": req.get("headers"), "body": req.get("body")}, 8000)
                        if resp:
                            response = _json_excerpt({"status": resp.get("status"), "headers": resp.get("headers"),
                                                      "body": resp.get("body")}, 16000)
                    except OSError:
                        continue
                    break
            sha = hashlib.sha256(json.dumps(
                {"asset_id": asset_id, "kind": kind, "method": method, "url": url, "status": status,
                 "request": request, "response": response, "detail": detail, "raw_sha256": raw_sha},
                sort_keys=True, ensure_ascii=True).encode()).hexdigest()
            now = _now()
            conn.execute(
                "INSERT INTO evidence(exploration_id, asset_id, trace_id, kind, label, method, url, status, "
                "request, response, detail, raw_path, raw_sha256, sha256, seen_count, first_seen, last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?) "
                "ON CONFLICT(exploration_id, sha256) DO UPDATE SET "
                "seen_count=evidence.seen_count+1, last_seen=excluded.last_seen, "
                "trace_id=COALESCE(evidence.trace_id, excluded.trace_id), "
                "asset_id=COALESCE(evidence.asset_id, excluded.asset_id), "
                "raw_path=COALESCE(NULLIF(evidence.raw_path, ''), excluded.raw_path), "
                "raw_sha256=COALESCE(NULLIF(evidence.raw_sha256, ''), excluded.raw_sha256)",
                (exp["id"], asset_id, int(trace_id) if trace else None, kind, label, method, url, status,
                 request, response, detail, raw_path, raw_sha, sha, now, now))
            row = _row(conn, "SELECT * FROM evidence WHERE exploration_id=? AND sha256=?", (exp["id"], sha))
            return _evidence_row(conn, exp["id"], row["id"])


def evidence_search(program: str, query: str = "", asset_id=None, kind: str = "",
                    limit: int = 50, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    limit = max(1, min(int(limit or 50), 200))
    sql = ("SELECT e.* FROM evidence e JOIN explorations x ON x.id=e.exploration_id WHERE x.program=?")
    args = [program]
    if kind:
        sql += " AND e.kind=?"
        args.append(_check(kind, EVIDENCE_KINDS, "evidence kind"))
    if asset_id not in (None, ""):
        sql += " AND e.asset_id=?"
        args.append(int(asset_id))
    if query:
        sql += " AND (e.label LIKE ? OR e.url LIKE ? OR e.request LIKE ? OR e.response LIKE ? OR e.detail LIKE ?)"
        args += [f"%{query}%"] * 5
    sql += " ORDER BY e.last_seen DESC, e.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, sql, tuple(args))


def evidence_get(program: str, ids, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    want = _int_list(ids)
    if not want:
        return []
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        out = []
        for i in want:
            row = _evidence_row(conn, exp["id"], i)
            if row:
                out.append(row)
        return out


def _finding_shape(conn, exploration_id: int, finding_id: int) -> dict | None:
    row = _row(conn, "SELECT * FROM findings WHERE id=? AND exploration_id=?",
               (int(finding_id), int(exploration_id)))
    if not row:
        return None
    row["assets"] = _rows(conn, "SELECT a.id, a.kind, a.identifier FROM finding_assets fa "
                                "JOIN assets a ON a.id=fa.asset_id WHERE fa.finding_id=? "
                                "ORDER BY a.kind, a.identifier", (int(finding_id),))
    row["evidence"] = _rows(conn, "SELECT e.id, e.kind, e.label, e.method, e.url, e.status, e.sha256, "
                                  "e.seen_count, e.last_seen FROM finding_evidence fe "
                                  "JOIN evidence e ON e.id=fe.evidence_id WHERE fe.finding_id=? "
                                  "ORDER BY e.id", (int(finding_id),))
    row["asset_count"] = len(row["assets"])
    row["evidence_count"] = len(row["evidence"])
    row["artifacts"] = _rows(conn, "SELECT id, kind, path, sha256, bytes, created_at FROM finding_artifacts "
                                   "WHERE finding_id=? ORDER BY id DESC LIMIT 5", (int(finding_id),))
    row["artifact_count"] = conn.execute("SELECT COUNT(*) FROM finding_artifacts WHERE finding_id=?",
                                         (int(finding_id),)).fetchone()[0]
    row["retests"] = _rows(conn, "SELECT id, due_at, state, outcome FROM finding_retests "
                                 "WHERE finding_id=? ORDER BY id DESC LIMIT 5", (int(finding_id),))
    row["retest_count"] = conn.execute("SELECT COUNT(*) FROM finding_retests WHERE finding_id=? "
                                       "AND state='pending'", (int(finding_id),)).fetchone()[0]
    return row


def _finding_gate(conn, row: dict) -> None:
    state = row["state"]
    if state in ("triaged", "confirmed", "reported") and not (row["severity"] and row["confidence"]):
        raise ValueError("a triaged finding needs severity and confidence")
    if state in ("confirmed", "reported"):
        if not conn.execute("SELECT 1 FROM finding_evidence WHERE finding_id=? LIMIT 1",
                            (row["id"],)).fetchone():
            raise ValueError("a confirmed finding needs at least one evidence record "
                             "(node action=evidence_add, then finding_update evidence_ids=[...])")
        if not conn.execute("SELECT 1 FROM finding_assets WHERE finding_id=? LIMIT 1",
                            (row["id"],)).fetchone():
            raise ValueError("a confirmed finding needs at least one asset anchor")
        if not str(row["body"] or "").strip():
            raise ValueError("a confirmed finding needs a body: impact and reproduction")


def finding_add(program: str, title: str, body: str = "", severity: str = "", confidence: str = "",
                asset_ids=None, evidence_ids=None, state: str = "candidate",
                db_path: str | None = None) -> dict:
    program = _check_program(program)
    title = " ".join(str(title or "").split())[:300]
    if not title:
        raise ValueError("finding title is empty")
    state = _check(state or "candidate", FINDING_STATES, "finding state")
    if state == "reported":
        raise ValueError("confirm the finding before reporting it")
    severity = _check(severity, SEVERITIES, "severity") if severity else ""
    confidence = _check(confidence, CONFIDENCES, "confidence") if confidence else ""
    body = str(body or "")[:20000]
    assets = _int_list(asset_ids)
    evidence = _int_list(evidence_ids)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            ev_rows = []
            for eid in evidence:
                e = _row(conn, "SELECT id, asset_id FROM evidence WHERE id=? AND exploration_id=?",
                         (eid, exp["id"]))
                if not e:
                    raise ValueError(f"no evidence #{eid} in {program}")
                ev_rows.append(e)
            if not assets:
                assets = [e["asset_id"] for e in ev_rows if e.get("asset_id")]
            for aid in assets:
                if not _asset_row(conn, aid):
                    raise ValueError(f"no asset #{aid}")
            now = _now()
            cur = conn.execute("INSERT INTO findings(exploration_id, title, body, state, severity, confidence, "
                               "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                               (exp["id"], title, body, state, severity, confidence, now, now))
            fid = cur.lastrowid
            for aid in dict.fromkeys(assets):
                conn.execute("INSERT OR IGNORE INTO finding_assets(finding_id, asset_id) VALUES(?,?)", (fid, aid))
            for eid in dict.fromkeys(evidence):
                conn.execute("INSERT OR IGNORE INTO finding_evidence(finding_id, evidence_id) VALUES(?,?)",
                             (fid, eid))
            row = _finding_shape(conn, exp["id"], fid)
            _finding_gate(conn, row)
            return row


def finding_update(program: str, finding_id: int, state: str | None = None, severity: str | None = None,
                   confidence: str | None = None, title: str | None = None, body: str | None = None,
                   asset_ids=None, evidence_ids=None, db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT * FROM findings WHERE id=? AND exploration_id=?",
                       (int(finding_id), exp["id"]))
            if not row:
                raise ValueError(f"no finding #{finding_id} in {program}")
            old_state = row["state"]
            new_state = _check(state, FINDING_STATES, "finding state") if state else old_state
            if new_state == "reported" and old_state not in ("confirmed", "reported"):
                raise ValueError("confirm the finding before reporting it")
            new_severity = _check(severity, SEVERITIES, "severity") if severity not in (None, "") else row["severity"]
            new_confidence = (_check(confidence, CONFIDENCES, "confidence")
                              if confidence not in (None, "") else row["confidence"])
            new_title = " ".join(str(title).split())[:300] if title else row["title"]
            new_body = str(body)[:20000] if body is not None else row["body"]
            if asset_ids is not None:
                conn.execute("DELETE FROM finding_assets WHERE finding_id=?", (int(finding_id),))
                for aid in dict.fromkeys(_int_list(asset_ids)):
                    if not _asset_row(conn, aid):
                        raise ValueError(f"no asset #{aid}")
                    conn.execute("INSERT OR IGNORE INTO finding_assets(finding_id, asset_id) VALUES(?,?)",
                                 (int(finding_id), aid))
            if evidence_ids is not None:
                conn.execute("DELETE FROM finding_evidence WHERE finding_id=?", (int(finding_id),))
                for eid in dict.fromkeys(_int_list(evidence_ids)):
                    if not _row(conn, "SELECT id FROM evidence WHERE id=? AND exploration_id=?",
                                (eid, exp["id"])):
                        raise ValueError(f"no evidence #{eid} in {program}")
                    conn.execute("INSERT OR IGNORE INTO finding_evidence(finding_id, evidence_id) VALUES(?,?)",
                                 (int(finding_id), eid))
            conn.execute("UPDATE findings SET state=?, severity=?, confidence=?, title=?, body=?, updated_at=? "
                         "WHERE id=?", (new_state, new_severity, new_confidence, new_title, new_body, _now(),
                                        int(finding_id)))
            updated = _finding_shape(conn, exp["id"], finding_id)
            _finding_gate(conn, updated)
            return updated


def finding_get(program: str, finding_id: int, db_path: str | None = None) -> dict | None:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        return _finding_shape(conn, exp["id"], int(finding_id))


def finding_search(program: str, state: str = "", query: str = "", limit: int = 50,
                   db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    limit = max(1, min(int(limit or 50), 200))
    sql = ("SELECT f.*, (SELECT COUNT(*) FROM finding_evidence fe WHERE fe.finding_id=f.id) AS evidence_count, "
           "(SELECT COUNT(*) FROM finding_assets fa WHERE fa.finding_id=f.id) AS asset_count, "
           "(SELECT COUNT(*) FROM finding_artifacts ar WHERE ar.finding_id=f.id) AS artifact_count, "
           "(SELECT COUNT(*) FROM finding_retests r WHERE r.finding_id=f.id AND r.state='pending') "
           "AS pending_retests "
           "FROM findings f JOIN explorations x ON x.id=f.exploration_id WHERE x.program=?")
    args = [program]
    if state:
        sql += " AND f.state=?"
        args.append(_check(state, FINDING_STATES, "finding state"))
    if query:
        sql += " AND (f.title LIKE ? OR f.body LIKE ?)"
        args += [f"%{query}%"] * 2
    sql += " ORDER BY f.updated_at DESC, f.id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, sql, tuple(args))


def findings_text(program: str, state: str = "", query: str = "", limit: int = 50,
                  db_path: str | None = None) -> str:
    rows = finding_search(program, state=state, query=query, limit=limit, db_path=db_path)
    if not rows:
        return f"no findings in {program}" + (f" in state {state}" if state else "")
    lines = [f"FINDINGS - {program} ({len(rows)} shown)"]
    for r in rows:
        sev = r["severity"] or "-"
        conf = r["confidence"] or "-"
        drafts = f" draft={r['artifact_count']}" if r.get("artifact_count") else ""
        drafts += f" retest={r['pending_retests']}" if r.get("pending_retests") else ""
        lines.append(f"  #{r['id']:<4} [{r['state']}] {sev}/{conf} ev={r['evidence_count']} "
                     f"assets={r['asset_count']}{drafts}  {_short(r['title'], 100)}")
    return "\n".join(lines)


# ------------------------------------------------------------------ finding artifacts
# reports/REPORT-FORMAT.md is the contract: three header lines, one title, exactly three sections,
# the PoC built from captured bytes, no markdown in the title, ASCII only. Code assembles the PoC
# from the evidence the finding cites; the judgment prose (Summary / Impact / CVSS / CWE) is read
# from labelled lines in the finding body. NOTHING here files, submits or announces anything.
_LABEL_LINE = re.compile(r"^\s*([A-Za-z][A-Za-z ]{1,20})\s*:\s*(.*)$")
_TITLE_JUNK = re.compile(r"[#`*|]")
_CVSS_VECTOR = re.compile(r"^CVSS:3\.[01]/[A-Za-z0-9:/.\-]+$")
_ASCII_MAP = {"\u2014": "-", "\u2013": "-", "\u00b7": "-", "\u00d7": "x", "\u2018": "'",
              "\u2019": "'", "\u201c": '"', "\u201d": '"', "\u2026": "...", "\u00a0": " "}
_HTTP_KEEP = ("content-type", "location", "set-cookie", "www-authenticate",
              "access-control-allow-origin", "access-control-allow-credentials", "x-powered-by", "server")


def _ascii(text) -> str:
    s = str(text or "")
    for bad, good in _ASCII_MAP.items():
        s = s.replace(bad, good)
    return s.encode("ascii", "ignore").decode("ascii")


def _body_field(body: str, name: str) -> str:
    """A labelled block in the finding body: 'Summary: ...' / 'Impact: ...' / 'CVSS: ...' / 'CWE: ...'.
    The value runs to the next blank line or the next label."""
    lines = str(body or "").splitlines()
    for i, ln in enumerate(lines):
        m = _LABEL_LINE.match(ln)
        if not m or m.group(1).strip().lower() != name.lower():
            continue
        parts = [m.group(2).strip()]
        for nxt in lines[i + 1:]:
            if not nxt.strip() or _LABEL_LINE.match(nxt):
                break
            parts.append(nxt.strip())
        return " ".join(" ".join(parts).split())
    return ""


def _report_title(title: str) -> str:
    t = _ascii(_TITLE_JUNK.sub("", str(title or "")))
    t = " ".join(t.split())[:120].strip(" -:;,")
    return t or "Untitled finding"


def _report_asset(row: dict) -> str:
    assets = row.get("assets") or []
    return assets[0]["identifier"] if assets else "TODO in-scope asset"


def _report_cvss(row: dict) -> tuple[str, str]:
    raw = _ascii(_body_field(row.get("body") or "", "cvss")).strip()
    if raw and _CVSS_VECTOR.match(raw.split("=")[0].strip()):
        return f"CVSS: {raw}", "finding body"
    return ("CVSS: TODO unscored - add 'CVSS: <vector> = <score> <Severity>' to the finding body",
            "todo")


def _report_cwe(row: dict) -> tuple[str, str]:
    raw = _ascii(_body_field(row.get("body") or "", "cwe")).strip()
    if raw:
        if re.match(r"^\d{2,4}\b", raw):
            raw = "CWE-" + raw
        return f"CWE: {raw}", "finding body"
    return "CWE: TODO CWE-NNN Name", "todo"


def _capture_json(text) -> dict:
    try:
        value = json.loads(text or "null")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def _curl_of(method, url, req: dict) -> str:
    parts = ["curl", "-sS", "-i", "--path-as-is", "-X", str(method or "GET").upper(),
             shlex.quote(str(url or "TODO"))]
    headers = req.get("headers") if isinstance(req.get("headers"), dict) else {}
    for key, val in list(headers.items())[:20]:
        parts += ["-H", shlex.quote(f"{key}: {val}")]
    body = req.get("body")
    if body not in (None, ""):
        parts += ["--data-raw", shlex.quote(body if isinstance(body, str) else json.dumps(body, default=str))]
    return " ".join(parts)


def _http_block(status, resp: dict, fallback: str = "", limit: int = 1200) -> str:
    if not resp:
        text = _ascii(fallback).strip()
        if not text:
            return "TODO captured response"
        return text[:limit] + ("\n[...]" if len(text) > limit else "")
    lines = [f"HTTP {status if status is not None else resp.get('status', '???')}"]
    headers = resp.get("headers") if isinstance(resp.get("headers"), dict) else {}
    for key, val in headers.items():
        if str(key).lower() in _HTTP_KEEP:
            lines.append(f"{key}: {val}")
    body = resp.get("body")
    if body not in (None, ""):
        text = _ascii(body if isinstance(body, str) else json.dumps(body, default=str))
        lines += ["", text[:limit] + ("\n[...]" if len(text) > limit else "")]
    return "\n".join(lines)


def _poc_markdown(evidence: list[dict]) -> tuple[str, list[str]]:
    warnings, blocks = [], []
    for n, ev in enumerate(evidence, 1):
        req = _capture_json(ev.get("request"))
        resp = _capture_json(ev.get("response"))
        label = _ascii(ev.get("label") or f"{ev.get('method') or 'GET'} {ev.get('url') or ''}").strip()
        blocks.append(f"{n}. {label}\n\n```bash\n{_curl_of(ev.get('method'), ev.get('url'), req)}\n```\n\n"
                      f"```http\n{_http_block(ev.get('status'), resp, ev.get('response') or '')}\n```")
        if not req.get("headers") and req.get("body") in (None, ""):
            warnings.append(f"evidence #{ev['id']}: no captured request headers/body; the command is "
                            "reconstructed from method and URL")
    if not blocks:
        blocks.append("1. TODO\n\n```bash\n# TODO the decisive request\n```\n\n"
                      "```http\n# TODO its captured response\n```")
        warnings.append("the finding cites no evidence; the PoC is a placeholder")
    return "\n\n".join(blocks), warnings


def report_markdown(row: dict, evidence: list[dict], cvss: str = "",
                    cwe: str = "") -> tuple[str, list[str], dict]:
    """The REPORT-FORMAT body plus the warnings this generator can see (it does not judge)."""
    if cvss:
        # REPORT-FORMAT: 'CVSS: <vector> = <score> <Severity>', and a vector itself starts 'CVSS:3.1/'
        cvss_line, cvss_src = f"CVSS: {cvss.strip()}", "operator"
    else:
        cvss_line, cvss_src = _report_cvss(row)
    if cwe:
        value = cwe.strip()
        value = value[4:].strip() if value.upper().startswith("CWE:") else value
        cwe_line, cwe_src = f"CWE: {value}", "operator"
    else:
        cwe_line, cwe_src = _report_cwe(row)
    summary = _ascii(_body_field(row.get("body") or "", "summary")).strip()
    impact = _ascii(_body_field(row.get("body") or "", "impact")).strip()
    warnings = []
    if not summary:
        summary = "TODO one sentence, 35 words max: what it is, on what asset, what an attacker gains."
        warnings.append("no 'Summary:' line in the finding body")
    elif len(summary.split()) > 35:
        warnings.append(f"Summary is {len(summary.split())} words; REPORT-FORMAT caps it at 35")
    if not impact:
        impact = "TODO one sentence, 35 words max: the new capability and whose data or money it reaches."
        warnings.append("no 'Impact:' line in the finding body")
    elif len(impact.split()) > 35:
        warnings.append(f"Impact is {len(impact.split())} words; REPORT-FORMAT caps it at 35")
    poc, poc_warnings = _poc_markdown(evidence)
    warnings += poc_warnings
    text = "\n".join([cvss_line, f"Asset: {_ascii(_report_asset(row))}", cwe_line, "",
                      f"# {_report_title(row['title'])}", "", "## Summary", summary, "",
                      "## PoC", poc, "", "## Impact", impact, ""])
    return text, warnings, {"cvss": cvss_src, "cwe": cwe_src}


def _slug(text: str, limit: int = 48) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", _ascii(text).lower()).strip("-")
    return (s[:limit].rstrip("-") or "finding")


def _artifact_dir(base: str, report_text: str) -> tuple[str, int, bool]:
    """Never overwrite a human-edited draft: reuse only a byte-identical report.md, else -v2, -v3..."""
    for n in range(1, 21):
        d = base if n == 1 else f"{base}-v{n}"
        if not os.path.isdir(d):
            return d, n, False
        p = os.path.join(d, "report.md")
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    if fh.read() == report_text:
                        return d, n, True
            except OSError:
                pass
    return f"{base}-v21", 21, False


def _copy_plan(evidence: list[dict]) -> tuple[list[dict], list[str]]:
    """The raw captures the draft will carry, each verified against the sha256 recorded when the
    evidence was promoted. A capture that changed on disk is NOT copied."""
    plan, warnings = [], []
    ws_real = os.path.realpath(WS)
    for ev in evidence:
        raw = str(ev.get("raw_path") or "")
        if not raw:
            continue
        real = os.path.realpath(raw if os.path.isabs(raw) else os.path.join(WS, raw))
        if real != ws_real and not real.startswith(ws_real + os.sep):
            warnings.append(f"evidence #{ev['id']}: raw capture {raw} is outside the workspace; not copied")
            continue
        if not os.path.isfile(real):
            warnings.append(f"evidence #{ev['id']}: raw capture {raw} is gone; not copied")
            continue
        with open(real, "rb") as fh:
            blob = fh.read()
        digest = hashlib.sha256(blob).hexdigest()
        if ev.get("raw_sha256") and digest != ev["raw_sha256"]:
            warnings.append(f"evidence #{ev['id']}: raw capture changed on disk (recorded "
                            f"{str(ev['raw_sha256'])[:12]}, now {digest[:12]}); not copied")
            continue
        ext = os.path.splitext(real)[1] or ".json"
        plan.append({"evidence_id": ev["id"], "src": real, "name": f"evidence-{ev['id']}{ext}",
                     "sha256": digest, "bytes": len(blob)})
    return plan, warnings


def _gates_markdown(program: str, row: dict, report_sha: str, now: str, srcs: dict,
                    plan: list[dict], warnings: list[str]) -> str:
    lines = ["# DRAFT - NOT FILED", "",
             "Generated by scripts/gnoc_graph.py from a confirmed finding in the dual graph.",
             "Nothing here is filed, submitted or announced: the user reviews the draft in chat and",
             "files it themselves (CLAUDE.md hard rules, 2026-10-21).", "",
             f"- program: {program}",
             f"- finding: #{row['id']} [{row['state']}] {row['severity'] or '-'}/{row['confidence'] or '-'} "
             f"{_ascii(row['title'])}",
             f"- report sha256: {report_sha}",
             f"- generated: {now}",
             f"- header values from: CVSS={srcs['cvss']}, CWE={srcs['cwe']}", "",
             "## Assets"]
    lines += [f"- #{a['id']} {a['kind']} {a['identifier']}" for a in (row.get("assets") or [])] or ["- none"]
    lines += ["", "## Evidence"]
    for ev in (row.get("evidence") or []):
        lines.append(f"- #{ev['id']} {ev['kind'] or ''} {ev['method'] or ''} {ev['url'] or ''}"
                     f" -> {ev['status'] if ev.get('status') is not None else '?'}"
                     f"  sha256 {str(ev.get('sha256') or '')[:16]}")
    copied = [p for p in plan if p.get("path")]
    lines += ["", "## Captures copied"]
    lines += [f"- {p['path']}  sha256 {p['sha256']}" for p in copied] or ["- none"]
    lines += ["", "## Warnings"]
    lines += [f"- {w}" for w in warnings] or ["- none"]
    lines += ["", "## Not checked by this generator",
              "duplicate search, VRT priority, the programme's policy and rate, scope re-verification,",
              "and every submission gate in gnoc_gates. A clean draft is not a cleared draft.", ""]
    return "\n".join(lines)


def _house_checks(draft: str) -> dict:
    """Make the generated draft a first-class draft for scripts/gnoc_finding.py: backfill its
    finding.json and run the house validator (CWE/CVSS shape, locator containment, the Bugcrowd P3
    floor). Never writes a finding state, never fixes a value, never raises into the caller."""
    out = {"finding_json": False, "checked": False, "errors": [], "record_id": ""}
    try:
        import gnoc_finding
    except Exception as e:  # noqa: BLE001
        out["errors"] = [f"gnoc_finding unavailable: {type(e).__name__}: {e}"]
        return out
    try:
        rec, written = gnoc_finding.backfill(draft)
        out["finding_json"] = bool(written)
        out["record_id"] = str((rec or {}).get("id") or "")
        out["errors"] = list(gnoc_finding.validate(draft) or [])
        out["checked"] = True
    except Exception as e:  # noqa: BLE001
        out["errors"] = [f"house validator crashed: {type(e).__name__}: {e}"]
    return out


def _house_checks_markdown(house: dict) -> str:
    lines = ["", "## House checks (gnoc_finding)",
             f"- finding.json: {'written' if house.get('finding_json') else 'already present'}"
             + (f" ({house['record_id']})" if house.get("record_id") else ""),
             f"- validator: {'ran' if house.get('checked') else 'did not run'}"]
    for e in house.get("errors") or []:
        lines.append(f"- ERROR: {e}")
    if house.get("checked") and not house.get("errors"):
        lines.append("- no validator errors (not an approval: dedup, VRT priority and scope still apply)")
    return "\n".join(lines) + "\n"


def finding_artifact(program: str, finding_id: int, out_dir: str | None = None, cvss: str = "",
                     cwe: str = "", db_path: str | None = None) -> dict:
    """Assemble a REPORT-FORMAT report draft for one CONFIRMED finding: report.md, GATES.md and the
    raw captures the evidence cites. Versioned, never overwriting an edited draft; records the
    artifact on the finding. It changes no finding state and files nothing."""
    program = _check_program(program)
    now = _now()
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        row = _finding_shape(conn, exp["id"], int(finding_id))
        if not row:
            raise ValueError(f"no finding #{finding_id} in {program}")
        if row["state"] not in ("confirmed", "reported", "closed"):
            raise ValueError(f"finding #{finding_id} is {row['state']}: confirm it before writing a draft")
        evidence = _rows(conn, "SELECT e.* FROM evidence e JOIN finding_evidence fe ON fe.evidence_id=e.id "
                               "WHERE fe.finding_id=? ORDER BY e.id", (int(finding_id),))
    report, warnings, srcs = report_markdown(row, evidence, cvss=cvss, cwe=cwe)
    base = (os.path.abspath(out_dir) if out_dir else
            os.path.join(WS, "reports", "drafts", program, f"f{int(finding_id)}-{_slug(row['title'])}"))
    target, version, reused = _artifact_dir(base, report)
    plan, copy_warnings = _copy_plan(evidence)
    warnings += copy_warnings
    report_sha = hashlib.sha256(report.encode("utf-8")).hexdigest()
    files = [{"path": "report.md", "sha256": report_sha, "bytes": len(report.encode("utf-8"))}]
    if not reused:
        os.makedirs(target, exist_ok=True)
        with open(os.path.join(target, "report.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
        if plan:
            evdir = os.path.join(target, "evidence")
            os.makedirs(evdir, exist_ok=True)
            for item in plan:
                shutil.copyfile(item["src"], os.path.join(evdir, item["name"]))
                item["path"] = f"evidence/{item['name']}"
                files.append({"path": item["path"], "sha256": item["sha256"], "bytes": item["bytes"]})
        house = _house_checks(target)
        gates = (_gates_markdown(program, row, report_sha, now, srcs, plan, warnings)
                 + _house_checks_markdown(house))
        with open(os.path.join(target, "GATES.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(gates)
        files.append({"path": "GATES.md", "sha256": hashlib.sha256(gates.encode("utf-8")).hexdigest(),
                      "bytes": len(gates.encode("utf-8"))})
    else:
        # byte-identical report: fill in any capture a previous run could not copy, never overwrite
        for item in plan:
            dest = os.path.join(target, "evidence", item["name"])
            if os.path.isfile(dest):
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copyfile(item["src"], dest)
            warnings.append(f"copied missing capture {item['name']} into the existing draft")
        if not os.path.isfile(os.path.join(target, "GATES.md")):
            warnings.append("the existing draft has no GATES.md (delete the folder, or edit the body, "
                            "to render a new version)")
        house = _house_checks(target)   # make sure its finding.json exists too; report the rules again
    rel = target
    ws_abs = os.path.abspath(WS)
    if os.path.abspath(target).startswith(ws_abs + os.sep):
        rel = os.path.relpath(target, ws_abs)
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            conn.execute("INSERT OR IGNORE INTO finding_artifacts(exploration_id, finding_id, kind, path, sha256, "
                         "bytes, files, note, created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                         (exp["id"], int(finding_id), "report-draft", rel, report_sha,
                          len(report.encode("utf-8")), json.dumps(files, sort_keys=True),
                          "; ".join(warnings)[:1000], now))
            artifact = _row(conn, "SELECT * FROM finding_artifacts WHERE finding_id=? AND sha256=?",
                            (int(finding_id), report_sha))
    return {"ok": True, "artifact_id": artifact["id"] if artifact else 0, "finding": int(finding_id),
            "program": program, "path": target, "report_path": os.path.join(target, "report.md"),
            "gates_path": os.path.join(target, "GATES.md"), "sha256": report_sha,
            "bytes": len(report.encode("utf-8")), "version": version, "reused": reused,
            "files": files, "warnings": warnings,
            "house": house, "house_errors": house.get("errors") or []}


def artifact_text(result: dict) -> str:
    lines = [f"DRAFT #{result['artifact_id']} - finding #{result['finding']} ({result['program']})",
             f"  {result['report_path']}"]
    if result.get("reused"):
        lines.append("  (identical draft already on disk; nothing was rewritten)")
    if result.get("version", 1) > 1:
        lines.append(f"  version {result['version']}: an earlier edited draft was left untouched")
    lines.append(f"  {result['bytes']} bytes, sha256 {result['sha256'][:16]}")
    house = result.get("house") or {}
    errors = result.get("house_errors") or []
    if house.get("checked"):
        lines.append("  house validator: " + (f"{len(errors)} error(s)" if errors else "no errors"))
        for e in errors[:6]:
            lines.append(f"    - {e}")
        if len(errors) > 6:
            lines.append(f"    ... {len(errors) - 6} more in GATES.md")
    else:
        lines.append("  house validator: did not run" + (f" ({errors[0]})" if errors else ""))
    for w in result.get("warnings") or []:
        lines.append(f"  WARNING: {w}")
    lines.append("  NOT FILED - the user reviews it in chat and files it themselves")
    return "\n".join(lines)


# ------------------------------------------------------------------ finding retests
RETEST_STATES = ("pending", "reproduces", "fixed", "cancelled")


def retest_add(program: str, finding_id: int, due_in_days: int = 14, note: str = "",
               db_path: str | None = None) -> dict:
    """Schedule a re-test of a finding (ARTEX's retests): does it still reproduce after the fix window?"""
    program = _check_program(program)
    try:
        days = max(0, min(int(due_in_days if due_in_days is not None else 14), 365))
    except (TypeError, ValueError):
        days = 14
    note = " ".join(str(note or "").split())[:500]
    now = _now()
    due = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT id, state FROM findings WHERE id=? AND exploration_id=?",
                       (int(finding_id), exp["id"]))
            if not row:
                raise ValueError(f"no finding #{finding_id} in {program}")
            if row["state"] not in ("confirmed", "reported", "closed"):
                raise ValueError(f"finding #{finding_id} is {row['state']}: only a confirmed finding gets a retest")
            cur = conn.execute("INSERT INTO finding_retests(exploration_id, finding_id, due_at, state, note, "
                               "created_at, updated_at) VALUES(?,?,?,'pending',?,?,?)",
                               (exp["id"], int(finding_id), due, note, now, now))
            return _row(conn, "SELECT * FROM finding_retests WHERE id=?", (cur.lastrowid,))


def retest_update(program: str, retest_id: int, state: str, note: str = "",
                  db_path: str | None = None) -> dict:
    program = _check_program(program)
    state = _check(state, RETEST_STATES[1:], "retest state")
    note = " ".join(str(note or "").split())[:500]
    now = _now()
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            row = _row(conn, "SELECT * FROM finding_retests WHERE id=? AND exploration_id=?",
                       (int(retest_id), exp["id"]))
            if not row:
                raise ValueError(f"no retest #{retest_id} in {program}")
            conn.execute("UPDATE finding_retests SET state=?, outcome=?, updated_at=? WHERE id=?",
                         (state, note, now, int(retest_id)))
            return _row(conn, "SELECT * FROM finding_retests WHERE id=?", (int(retest_id),))


def retests(program: str, finding_id=None, active_only: bool = False,
            db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        sql = ("SELECT r.*, f.title, f.state AS finding_state FROM finding_retests r "
               "JOIN findings f ON f.id=r.finding_id WHERE r.exploration_id=?")
        args: list = [exp["id"]]
        if finding_id not in (None, "", 0):
            sql += " AND r.finding_id=?"
            args.append(int(finding_id))
        if active_only:
            sql += " AND r.state='pending'"
        sql += " ORDER BY r.due_at, r.id"
        return _rows(conn, sql, tuple(args))


def retests_text(program: str, active_only: bool = True, db_path: str | None = None) -> str:
    rows = retests(program, active_only=active_only, db_path=db_path)
    if not rows:
        return f"no {'active ' if active_only else ''}retests in {program}"
    now = _now()
    lines = [f"RETESTS - {program}" + (" (pending)" if active_only else "")]
    for r in rows:
        late = "  OVERDUE" if r["state"] == "pending" and str(r["due_at"]) <= now else ""
        lines.append(f"  #{r['id']:<4} finding #{r['finding_id']} [{r['state']}] due {r['due_at'][:16]}"
                     f"{late}  {_short(r['title'], 60)}")
        if r.get("outcome"):
            lines.append(f"        outcome: {_short(r['outcome'], 120)}")
    return "\n".join(lines)


def evidence_text(program: str, query: str = "", limit: int = 40, db_path: str | None = None) -> str:
    rows = evidence_search(program, query=query, limit=limit, db_path=db_path)
    if not rows:
        return f"no evidence in {program}" + (f" matching {query!r}" if query else "")
    lines = [f"EVIDENCE - {program} ({len(rows)} shown)"]
    for r in rows:
        status = f" -> {r['status']}" if r.get("status") is not None else ""
        lines.append(f"  #{r['id']:<4} {r['kind']} {r['method']} {_short(r['url'], 70)}{status} "
                     f"seen={r['seen_count']} {_short(r['label'], 50)}")
    return "\n".join(lines)


# ------------------------------------------------------------------ approval rules
# ARTEX's intercept rules: an operator can pre-authorise one exact, bounded action instead of answering
# the same prompt again. A rule names the tool, globs the JSON arguments, carries a use budget and an
# expiry. The agent checks these only AFTER the always-ask gates (ship, commit, scan, desktop control,
# a tainted turn), so a rule can never turn a hard prompt into a silent run.
def rule_add(program: str, action: str, pattern: str, uses: int = 1, ttl_secs: int = 3600,
             note: str = "", db_path: str | None = None) -> dict:
    program = _check_program(program)
    action = str(action or "").strip()[:80]
    pattern = str(pattern or "").strip()[:400]
    if not action or not pattern:
        raise ValueError("a rule needs an action and an args pattern")
    try:
        uses = max(1, min(int(uses if uses is not None else 1), 1000))
    except (TypeError, ValueError):
        uses = 1
    note = " ".join(str(note or "").split())[:300]
    now = _now()
    with _closed(connect(db_path)) as conn:
        with conn:
            cur = conn.execute("INSERT INTO approval_rules(program, action, pattern, uses_left, expires_at, "
                               "note, created_at) VALUES(?,?,?,?,?,?,?)",
                               (program, action, pattern, uses, _lease_until(ttl_secs), note, now))
            return _row(conn, "SELECT * FROM approval_rules WHERE id=?", (cur.lastrowid,))


def rule_list(program: str, db_path: str | None = None) -> list[dict]:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, "SELECT * FROM approval_rules WHERE program=? AND expires_at > ? "
                           "ORDER BY id DESC", (program, _now()))


def rule_remove(program: str, rule_id: int, db_path: str | None = None) -> bool:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        with conn:
            cur = conn.execute("DELETE FROM approval_rules WHERE id=? AND program=?",
                               (int(rule_id), program))
            return bool(cur.rowcount)


def rule_consume(program: str, action: str, args: dict, db_path: str | None = None) -> dict | None:
    """The first live rule matching this exact action and args glob, consumed by one use."""
    program = _check_program(program)
    payload = json.dumps(args or {}, sort_keys=True, default=str)
    now = _now()
    with _closed(connect(db_path)) as conn:
        with conn:
            rows = _rows(conn, "SELECT * FROM approval_rules WHERE program=? AND action=? "
                               "AND uses_left > 0 AND expires_at > ? ORDER BY id",
                         (program, str(action or "")[:80], now))
            for row in rows:
                if not fnmatch.fnmatchcase(payload, row["pattern"]):
                    continue
                cur = conn.execute("UPDATE approval_rules SET uses_left=uses_left-1 "
                                   "WHERE id=? AND uses_left > 0", (row["id"],))
                if cur.rowcount:
                    return _row(conn, "SELECT * FROM approval_rules WHERE id=?", (row["id"],))
    return None


def rules_text(program: str, db_path: str | None = None) -> str:
    rows = rule_list(program, db_path=db_path)
    if not rows:
        return f"no approval rules in {program}"
    lines = [f"APPROVAL RULES - {program}"]
    for r in rows:
        lines.append(f"  #{r['id']:<4} {r['action']}: {r['pattern'][:80]}  uses_left={r['uses_left']} "
                     f"expires={r['expires_at']}" + (f"  {r['note']}" if r.get("note") else ""))
    return "\n".join(lines)


# ------------------------------------------------------------------ approvals
_SECRET_LIKE = re.compile(
    r"(?i)(gh[pousr]_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9]{10,}|AKIA[0-9A-Z]{12,}|"
    r"xox[abpr]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}|"
    r"Bearer\s+[A-Za-z0-9._\-]{12,}|"
    r"(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|token|secret|password)"
    r"\s*[:=]\s*[^\s,;'\"]{8,})")


def _redact(text) -> str:
    s = str(text)
    try:
        import gnoc_secrets
        s = gnoc_secrets.redact(s)
    except Exception:  # noqa: BLE001 - approvals must work without the optional redactor
        pass
    return _SECRET_LIKE.sub("[REDACTED]", s)


def _approval_summary(action: str, args: dict) -> str:
    detail = (args.get("url") or args.get("command") or args.get("path") or args.get("args")
              or args.get("brief") or args.get("body") or "")
    if not detail:
        detail = json.dumps(args, default=str, sort_keys=True) if args else "(default action)"
    return _redact(f"{action}: {str(detail)[:300]}")[:500]


def approval_fingerprint(action: str, args: dict) -> str:
    return hashlib.sha256(json.dumps({"action": str(action), "args": args or {}},
                                     sort_keys=True, default=str).encode()).hexdigest()


def _approval_row(conn, approval_id: int) -> dict | None:
    return _row(conn, "SELECT * FROM approvals WHERE id=?", (int(approval_id),))


def approval_request(program: str, action: str, args: dict, summary: str = "", risk: str = "",
                     requested_by: str = "lead", ttl_secs=3600, db_path: str | None = None) -> dict:
    """Queue one operator decision for a concrete tool call. Pending and approved-unused requests
    for the same fingerprint are reused; the caller must retry the exact call after approval."""
    program = _check_program(program or "global")
    action = str(action or "?")[:80]
    fingerprint = approval_fingerprint(action, args)
    payload = _redact(json.dumps(args or {}, default=str, sort_keys=True))[:8000]
    summary = _redact(summary)[:500] if summary else _approval_summary(action, args)
    risk = _redact(risk)[:500]
    requested_by = " ".join(str(requested_by or "lead").split())[:60] or "lead"
    with _closed(connect(db_path)) as conn:
        with conn:
            exp = _ensure_exploration_conn(conn, program)
            now = _now()
            row = _row(conn, "SELECT * FROM approvals WHERE program=? AND fingerprint=? AND state IN "
                             "('pending','approved') AND used_at IS NULL AND expires_at > ? "
                             "ORDER BY id DESC LIMIT 1", (program, fingerprint, now))
            if row:
                return row
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=3600)).isoformat(timespec="seconds")
            denied = _row(conn, "SELECT * FROM approvals WHERE program=? AND fingerprint=? AND state='denied' "
                                "AND decided_at >= ? ORDER BY id DESC LIMIT 1", (program, fingerprint, cutoff))
            if denied:
                return denied
            cur = conn.execute("INSERT INTO approvals(exploration_id, program, action, fingerprint, summary, "
                               "payload, risk, state, requested_by, created_at, expires_at) "
                               "VALUES(?,?,?,?,?,?,?, 'pending', ?, ?, ?)",
                               (exp["id"], program, action, fingerprint, summary, payload, risk,
                                requested_by, now, _lease_until(ttl_secs)))
            return _approval_row(conn, cur.lastrowid)


def approval_check(program: str, action: str, args: dict, consume: bool = False,
                   db_path: str | None = None) -> dict | None:
    """The approved, unused, unexpired request for this exact call, or None. consume marks it used
    with a compare-and-set so two tool calls cannot spend the same approval twice."""
    program = _check_program(program or "global")
    fingerprint = approval_fingerprint(action, args)
    now = _now()
    with _closed(connect(db_path)) as conn:
        with conn:
            row = _row(conn, "SELECT * FROM approvals WHERE program=? AND fingerprint=? AND state='approved' "
                             "AND used_at IS NULL AND expires_at > ? ORDER BY id DESC LIMIT 1",
                       (program, fingerprint, now))
            if not row and consume:
                return None
            if row and consume:
                cur = conn.execute("UPDATE approvals SET used_at=? WHERE id=? AND used_at IS NULL",
                                   (now, row["id"]))
                if not cur.rowcount:
                    return None
                row["used_at"] = now
            return row


def approval_status(program: str, action: str, args: dict, db_path: str | None = None) -> dict | None:
    program = _check_program(program or "global")
    fingerprint = approval_fingerprint(action, args)
    with _closed(connect(db_path)) as conn:
        return _row(conn, "SELECT * FROM approvals WHERE program=? AND fingerprint=? ORDER BY id DESC LIMIT 1",
                    (program, fingerprint))


def approval_get(approval_id: int, program: str | None = None, db_path: str | None = None) -> dict | None:
    with _closed(connect(db_path)) as conn:
        if program:
            return _row(conn, "SELECT * FROM approvals WHERE id=? AND program=?",
                        (int(approval_id), _check_program(program)))
        return _approval_row(conn, approval_id)


def approval_list(program: str | None = None, state: str = "pending", limit: int = 100,
                  db_path: str | None = None) -> list[dict]:
    limit = max(1, min(int(limit or 100), 500))
    state = "" if str(state or "").lower() in ("all", "*") else state
    sql = "SELECT * FROM approvals WHERE 1=1"
    args = []
    if program:
        sql += " AND program=?"
        args.append(_check_program(program))
    if state == "used":
        sql += " AND used_at IS NOT NULL"
    elif state:
        sql += " AND state=?"
        args.append(_check(state, APPROVAL_STATES, "approval state"))
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _closed(connect(db_path)) as conn:
        return _rows(conn, sql, tuple(args))


def approval_decide(approval_id: int, approve: bool = True, program: str | None = None,
                    decided_by: str = "operator", reason: str = "", ttl_secs=900,
                    db_path: str | None = None) -> dict:
    """Operator decision. Approval is single-use and valid for ttl_secs; denial is final."""
    with _closed(connect(db_path)) as conn:
        with conn:
            if program:
                row = _row(conn, "SELECT * FROM approvals WHERE id=? AND program=?",
                           (int(approval_id), _check_program(program)))
            else:
                row = _approval_row(conn, approval_id)
            if not row:
                raise ValueError(f"no approval #{approval_id}")
            if row["state"] != "pending":
                return row
            now = _now()
            if str(row["expires_at"] or "") <= now:
                conn.execute("UPDATE approvals SET state='expired', decided_at=?, reason=? WHERE id=?",
                             (now, "request expired before a decision", int(approval_id)))
                row["state"] = "expired"
                row["decided_at"] = now
                row["reason"] = "request expired before a decision"
                return row
            state = "approved" if approve else "denied"
            expires = _lease_until(ttl_secs) if approve else row["expires_at"]
            conn.execute("UPDATE approvals SET state=?, decided_by=?, reason=?, decided_at=?, expires_at=? "
                         "WHERE id=?", (state, " ".join(str(decided_by or "operator").split())[:60] or "operator",
                                        str(reason or "")[:500], now, expires, int(approval_id)))
            return _approval_row(conn, approval_id)


def approvals_text(program: str | None = None, state: str = "pending", db_path: str | None = None) -> str:
    rows = approval_list(program=program, state=state, db_path=db_path)
    scope = f" - {program}" if program else ""
    if not rows:
        return f"no approvals{scope}" + (f" in state {state}" if state else "")
    lines = [f"APPROVALS{scope} ({len(rows)} shown)"]
    for r in rows:
        used = " used" if r.get("used_at") else ""
        lines.append(f"  #{r['id']:<4} [{r['state']}{used}] {r['action']}: {_short(r['summary'], 110)}")
        lines.append(f"        program={r['program']} by={r['requested_by']} expires={r['expires_at']}"
                     + (f" risk={_short(r['risk'], 60)}" if r.get("risk") else ""))
    return "\n".join(lines)


# ------------------------------------------------------------------ coverage / overview
def coverage(program: str, db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        in_scope = _rows(conn, "SELECT a.id, a.kind, a.identifier FROM assets a "
                               "JOIN asset_programs ap ON ap.asset_id=a.id WHERE ap.program=?", (program,))
        covered_ids = {r["asset_id"] for r in conn.execute(
            "SELECT DISTINCT x.asset_id FROM anchors x JOIN nodes n ON n.id=x.node_id "
            "WHERE n.exploration_id=? AND n.kind IN ('fact','finding')", (exp["id"],)).fetchall()}
        covered_ids |= {r["asset_id"] for r in conn.execute(
            "SELECT DISTINCT fa.asset_id FROM finding_assets fa JOIN findings f ON f.id=fa.finding_id "
            "WHERE f.exploration_id=? AND f.state IN ('confirmed','reported','closed')", (exp["id"],)).fetchall()}
        touched_ids = {r["asset_id"] for r in conn.execute(
            "SELECT DISTINCT ta.asset_id FROM trace_assets ta JOIN traces t ON t.id=ta.trace_id "
            "WHERE t.exploration_id=?", (exp["id"],)).fetchall()}
        findings = {r["state"]: r["n"] for r in conn.execute(
            "SELECT state, COUNT(*) n FROM findings WHERE exploration_id=? GROUP BY state",
            (exp["id"],)).fetchall()}
        evidence_count = conn.execute("SELECT COUNT(*) FROM evidence WHERE exploration_id=?",
                                      (exp["id"],)).fetchone()[0]
    by_kind = {}
    for a in in_scope:
        by_kind.setdefault(a["kind"], 0)
        by_kind[a["kind"]] += 1
    covered = [a for a in in_scope if a["id"] in covered_ids]
    touched = [a for a in in_scope if a["id"] in touched_ids]
    untested = [a for a in in_scope if a["id"] not in touched_ids and a["id"] not in covered_ids]
    return {"program": program, "in_scope": len(in_scope), "covered": len(covered),
            "touched": len(touched), "untested": len(untested), "by_kind": by_kind,
            "findings": findings, "evidence": evidence_count,
            "covered_assets": covered, "touched_assets": touched, "untested_assets": untested}


def untested_assets(program: str, limit: int = 100, db_path: str | None = None) -> list[dict]:
    return coverage(program, db_path=db_path)["untested_assets"][:max(1, min(int(limit or 100), 500))]


def overview(program: str, db_path: str | None = None) -> dict:
    program = _check_program(program)
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        node_counts = {r["kind"]: r["n"] for r in conn.execute(
            "SELECT kind, COUNT(*) n FROM nodes WHERE exploration_id=? GROUP BY kind", (exp["id"],))}
        state_counts = {f"{r['kind']}/{r['state']}": r["n"] for r in conn.execute(
            "SELECT kind, state, COUNT(*) n FROM nodes WHERE exploration_id=? GROUP BY kind, state",
            (exp["id"],))}
        open_intents = conn.execute("SELECT COUNT(*) FROM nodes WHERE exploration_id=? AND kind='intent' "
                                    "AND state IN ('open','running','paused','blocked')", (exp["id"],)).fetchone()[0]
        todos = conn.execute("SELECT COUNT(*) FROM todos WHERE exploration_id=? AND state IN "
                             "('pending','in_progress')", (exp["id"],)).fetchone()[0]
        claimed = conn.execute("SELECT COUNT(*) FROM todos WHERE exploration_id=? AND state='in_progress' "
                               "AND lease_until > ?", (exp["id"], _now())).fetchone()[0]
        traces = conn.execute("SELECT COUNT(*) FROM traces WHERE exploration_id=?", (exp["id"],)).fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings WHERE exploration_id=? AND state NOT IN "
                                "('closed','rejected')", (exp["id"],)).fetchone()[0]
        evidence = conn.execute("SELECT COUNT(*) FROM evidence WHERE exploration_id=?", (exp["id"],)).fetchone()[0]
        approvals = conn.execute("SELECT COUNT(*) FROM approvals WHERE program=? AND state='pending' "
                                 "AND expires_at > ?", (program, _now())).fetchone()[0]
        recent_nodes = _rows(conn, "SELECT id, kind, state, title FROM nodes WHERE exploration_id=? "
                                   "ORDER BY id DESC LIMIT 8", (exp["id"],))
        recent_traces = _rows(conn, "SELECT id, tool, worker, result FROM traces WHERE exploration_id=? "
                                    "ORDER BY id DESC LIMIT 5", (exp["id"],))
    cov = coverage(program, db_path=db_path)
    return {"program": program, "exploration": exp, "nodes": node_counts, "states": state_counts,
            "open_intents": open_intents, "open_todos": todos, "claimed_todos": claimed, "traces": traces,
            "findings": findings, "evidence": evidence, "approvals": approvals,
            "recent_nodes": recent_nodes, "recent_traces": recent_traces, "coverage": cov}


def all_programs(db_path: str | None = None) -> list[str]:
    with _closed(connect(db_path)) as conn:
        rows = conn.execute("SELECT program FROM explorations UNION SELECT program FROM asset_programs "
                            "ORDER BY program").fetchall()
    return [r[0] for r in rows]


# ------------------------------------------------------------------ text views
def program_stats(program: str, db_path: str | None = None) -> dict:
    """One dashboard's worth of numbers for a program: assets, coverage, nodes, findings, evidence,
    traffic, retests, rules and snapshots."""
    program = _check_program(program)
    now = _now()
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        eid = exp["id"]
        assets = _in_scope_assets(conn, program)
        nodes = {r[0]: r[1] for r in conn.execute(
            "SELECT kind, COUNT(*) FROM nodes WHERE exploration_id=? GROUP BY kind", (eid,))}
        intents = conn.execute("SELECT COUNT(*) FROM nodes WHERE exploration_id=? AND kind='intent' "
                               "AND state IN ('open','running','paused','blocked')", (eid,)).fetchone()[0]
        findings = {r[0]: r[1] for r in conn.execute(
            "SELECT state, COUNT(*) FROM findings WHERE exploration_id=? GROUP BY state", (eid,))}
        evidence = conn.execute("SELECT COUNT(*) FROM evidence WHERE exploration_id=?", (eid,)).fetchone()[0]
        traffic = conn.execute("SELECT COUNT(*) FROM traffic WHERE exploration_id=?", (eid,)).fetchone()[0]
        hosts = conn.execute("SELECT COUNT(DISTINCT host) FROM traffic WHERE exploration_id=?",
                             (eid,)).fetchone()[0]
        retests = conn.execute("SELECT COUNT(*) FROM finding_retests WHERE exploration_id=? "
                               "AND state='pending'", (eid,)).fetchone()[0]
        overdue = conn.execute("SELECT COUNT(*) FROM finding_retests WHERE exploration_id=? "
                               "AND state='pending' AND due_at <= ?", (eid, now)).fetchone()[0]
        drafts = conn.execute("SELECT COUNT(*) FROM finding_artifacts WHERE exploration_id=?",
                              (eid,)).fetchone()[0]
        traces = conn.execute("SELECT COUNT(*) FROM traces WHERE exploration_id=?", (eid,)).fetchone()[0]
        todos = {r[0]: r[1] for r in conn.execute(
            "SELECT state, COUNT(*) FROM todos WHERE exploration_id=? GROUP BY state", (eid,))}
    rules = len(rule_list(program, db_path=db_path))
    snaps = len(_snapshot_list(program, db_path=db_path))
    cov = {"covered": sum(1 for a in assets if a["coverage"] == "covered"),
           "touched": sum(1 for a in assets if a["coverage"] == "touched"),
           "untested": sum(1 for a in assets if a["coverage"] == "untested")}
    return {"program": program, "assets": len(assets), "coverage": cov, "nodes": nodes,
            "open_intents": intents, "findings": findings, "evidence": evidence, "traffic": traffic,
            "traffic_hosts": hosts, "retests_pending": retests, "retests_overdue": overdue,
            "drafts": drafts, "traces": traces, "todos": todos, "rules": rules, "snapshots": snaps,
            "generated_at": now}


def stats_text(program: str, db_path: str | None = None) -> str:
    st = program_stats(program, db_path=db_path)
    lines = [f"PROGRAM STATS - {program}",
             f"  assets {st['assets']}: covered {st['coverage']['covered']} / "
             f"touched {st['coverage']['touched']} / untested {st['coverage']['untested']}",
             "  nodes: " + (", ".join(f"{k}={v}" for k, v in sorted(st["nodes"].items())) or "none")
             + f"   open intents {st['open_intents']}",
             "  findings: " + (", ".join(f"{k}={v}" for k, v in sorted(st["findings"].items())) or "none")
             + f"   evidence {st['evidence']}   drafts {st['drafts']}",
             f"  traffic {st['traffic']} across {st['traffic_hosts']} host(s)   traces {st['traces']}",
             f"  retests pending {st['retests_pending']}" +
             (f" ({st['retests_overdue']} overdue)" if st["retests_overdue"] else "")
             + f"   approval rules {st['rules']}   snapshots {st['snapshots']}",
             "  todos: " + (", ".join(f"{k}={v}" for k, v in sorted(st["todos"].items())) or "none")]
    return "\n".join(lines)


def _short(text, n=100):
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[:n - 1] + "…"


def assets_filter_text(program: str | None, kind: str = "", coverage_state: str = "",
                       query: str = "", limit: int = 200, db_path: str | None = None) -> str:
    """The asset list with ARTEX-style filters: kind, coverage state (covered/touched/untested), text."""
    rows = list_assets(program, kind=(kind or None), query=query, limit=limit, db_path=db_path)
    if coverage_state and program:
        cov = coverage(program, db_path=db_path)
        allowed = {a["id"] for a in cov.get(f"{coverage_state}_assets", [])}
        rows = [r for r in rows if r["id"] in allowed]
    if not rows:
        return "no assets match" + (f" in {program}" if program else "")
    lines = [f"ASSETS ({len(rows)} shown" + (f" for {program}" if program else "")
             + (f", kind={kind}" if kind else "")
             + (f", coverage={coverage_state}" if coverage_state else "") + ")"]
    lines += [f"  #{r['id']:<5} {r['kind']:<10} {r['identifier']}" for r in rows]
    return "\n".join(lines)


def assets_text(program: str | None = None, kind: str | None = None, query: str = "", limit: int = 60,
                db_path: str | None = None) -> str:
    rows = list_assets(program, kind=kind, query=query, limit=limit, db_path=db_path)
    if not rows:
        return "no assets" + (f" for {program}" if program else "")
    lines = [f"ASSETS ({len(rows)} shown" + (f" for {program}" if program else "")
             + (f", kind={kind}" if kind else "") + ")"]
    for r in rows:
        parent = f" parent=#{r['parent_id']}" if r.get("parent_id") else ""
        lines.append(f"  #{r['id']:<5} {r['kind']:<12} {r['identifier']}{parent}  seen {r['last_seen'][:16]}")
    return "\n".join(lines)


def asset_text(asset_id: int, db_path: str | None = None) -> str:
    a = asset_detail(asset_id, db_path=db_path)
    if not a:
        return f"no asset #{asset_id}"
    lines = [f"ASSET #{a['id']} {a['kind']} {a['identifier']}",
             f"  programs: {', '.join(a['programs']) or '-'}",
             f"  first seen {a['first_seen']}  last seen {a['last_seen']}",
             f"  touches: {a['touches']}  nodes anchored: {len(a['nodes'])}"]
    if a.get("parent"):
        lines.append(f"  parent: #{a['parent']['id']} {a['parent']['kind']} {a['parent']['identifier']}")
    if a["children"]:
        lines.append("  children: " + ", ".join(f"#{c['id']} {c['identifier']}" for c in a["children"][:12]))
    if a["nodes"]:
        lines.append("  nodes: " + "; ".join(f"#{n['id']} {n['kind']} {_short(n['title'], 60)}"
                                             for n in a["nodes"][:12]))
    return "\n".join(lines)


def nodes_text(program: str, kind: str | None = None, state: str | None = None, query: str = "",
               limit: int = 60, db_path: str | None = None) -> str:
    rows = node_search(program, kind=kind, state=state, query=query, limit=limit, db_path=db_path)
    if not rows:
        return f"no nodes in {program}" + (f" matching {kind or ''} {state or ''} {query!r}" if any(
            [kind, state, query]) else "")
    lines = [f"EXPLORATION NODES - {program} ({len(rows)} shown)"]
    for r in rows:
        lines.append(f"  #{r['id']:<5} {r['kind']:<8} [{r['state']}] {_short(r['title'], 90)}"
                     f"  assets={r.get('n_assets', 0)}")
    return "\n".join(lines)


def node_text(program: str, node_id: int, db_path: str | None = None) -> str:
    n = node_detail(program, node_id, db_path=db_path)
    if not n:
        return f"no node #{node_id} in {program}"
    lines = [f"NODE #{n['id']} {n['kind']} [{n['state']}] {n['title']}",
             f"  owner {n.get('owner') or '-'}  confidence {n.get('confidence') or '-'}  "
             f"priority {n.get('priority')}  traces {n.get('traces', 0)}"]
    if n.get("body"):
        lines.append("  body: " + _short(n["body"], 400))
    if n["anchors"]:
        lines.append("  anchors: " + ", ".join(f"#{a['id']} {a['identifier']}" for a in n["anchors"][:12]))
    if n["parents"]:
        lines.append("  parents: " + ", ".join(f"#{p['id']} {p['rel']} {_short(p['title'], 50)}"
                                                for p in n["parents"][:8]))
    if n["children"]:
        lines.append("  children: " + ", ".join(f"#{p['id']} {p['rel']} {_short(p['title'], 50)}"
                                                 for p in n["children"][:8]))
    return "\n".join(lines)


def coverage_text(program: str, db_path: str | None = None) -> str:
    c = coverage(program, db_path=db_path)
    lines = [f"ASSET COVERAGE - {program}",
             f"  in scope {c['in_scope']}  covered (facts/findings) {c['covered']}  "
             f"touched (probe) {c['touched']}  untested {c['untested']}",
             "  by kind: " + (", ".join(f"{k}={v}" for k, v in sorted(c["by_kind"].items())) or "-"),
             "  findings: " + (", ".join(f"{k}={v}" for k, v in sorted(c["findings"].items())) or "-")
             + f"  evidence: {c['evidence']}"]
    if c["untested_assets"]:
        lines.append("  untested sample: " + ", ".join(a["identifier"] for a in c["untested_assets"][:15]))
    return "\n".join(lines)


def todos_text(program: str, db_path: str | None = None) -> str:
    rows = todo_list(program, db_path=db_path)
    if not rows:
        return f"no todos in {program}"
    mark = {"pending": "[ ]", "in_progress": "[>]", "completed": "[x]", "blocked": "[!]"}
    lines = [f"PLANNING TODOS - {program}"]
    for r in rows:
        deps = f"  deps={r['depends_on']}" if r["depends_on"] else ""
        lease = ""
        if r["state"] == "in_progress" and r.get("claimed_by"):
            lease = (f"  worker={r['claimed_by']} lease={'live' if r.get('lease_live') else 'EXPIRED'}"
                     f" until={r.get('lease_until') or '-'} tries={r.get('attempts') or 0}")
        elif r.get("last_error"):
            lease = f"  error={_short(r['last_error'], 80)}"
        lines.append(f"  {mark.get(r['state'], '[ ]')} #{r['id']} {_short(r['content'], 100)}{deps}{lease}")
    return "\n".join(lines)


def traces_text(program: str, query: str = "", limit: int = 40, db_path: str | None = None) -> str:
    rows = trace_search(program, query=query, limit=limit, db_path=db_path)
    if not rows:
        return f"no traces in {program}"
    lines = [f"TRACES - {program} ({len(rows)} shown)"]
    for r in rows:
        lines.append(f"  #{r['id']:<5} {r['created_at'][:16]} {r['worker']}/{r['tool']}: "
                     f"{_short(r['args'], 70)} -> {_short(r['result'], 70)}")
    return "\n".join(lines)


def overview_text(program: str, db_path: str | None = None) -> str:
    o = overview(program, db_path=db_path)
    c = o["coverage"]
    lines = [f"DUAL GRAPH - {program}",
             f"  assets: {c['in_scope']} in scope / {c['covered']} covered / {c['touched']} touched / "
             f"{c['untested']} untested",
             "  exploration: " + (", ".join(f"{k}={v}" for k, v in sorted(o["nodes"].items())) or "empty"),
             f"  open intents: {o['open_intents']}  open todos: {o['open_todos']} "
             f"(claimed {o['claimed_todos']})  traces: {o['traces']}",
             f"  open findings: {o['findings']}  evidence: {o['evidence']}  pending approvals: {o['approvals']}"]
    if o["recent_nodes"]:
        lines.append("  recent nodes: " + "; ".join(
            f"#{n['id']} {n['kind']}[{n['state']}] {_short(n['title'], 45)}" for n in o["recent_nodes"]))
    if o["recent_traces"]:
        lines.append("  recent traces: " + "; ".join(
            f"#{t['id']} {t['tool']} {_short(t['result'], 45)}" for t in o["recent_traces"]))
    return "\n".join(lines)


# ------------------------------------------------------------------ cockpit export
def graph_export_data(program: str, db_path: str | None = None, node_limit: int = 800,
                      asset_limit: int = 2000, trace_limit: int = 12,
                      approval_limit: int = 40) -> dict:
    """Everything the cockpit view draws, as plain JSON: the exploration graph (nodes, edges,
    anchors), the in-scope assets with their coverage state, findings, todos, approvals and the
    most recent traces. Nothing here mutates graph state (connect() still ensures the schema)."""
    program = _check_program(program)
    node_limit = max(1, min(int(node_limit or 800), 5000))
    asset_limit = max(1, min(int(asset_limit or 2000), 10000))
    trace_limit = max(0, min(int(trace_limit if trace_limit is not None else 12), 500))
    now = _now()
    with _closed(connect(db_path)) as conn:
        exp = _exploration_or_empty(conn, program)
        eid = exp["id"]
        total_nodes = conn.execute("SELECT COUNT(*) FROM nodes WHERE exploration_id=?",
                                   (eid,)).fetchone()[0]
        nodes = _rows(conn, "SELECT id, kind, state, title, body, confidence, priority, owner, "
                            "created_at FROM nodes WHERE exploration_id=? ORDER BY id LIMIT ?",
                      (eid, node_limit))
        for n in nodes:
            n["body"] = _short(n.get("body") or "", 1500)
            n["anchors"] = []
        edges = _rows(conn, "SELECT src_id, dst_id, rel FROM edges WHERE exploration_id=? "
                            "ORDER BY created_at", (eid,))
        anchors = _rows(conn, "SELECT x.node_id, a.kind, a.identifier FROM anchors x "
                              "JOIN assets a ON a.id=x.asset_id JOIN nodes n ON n.id=x.node_id "
                              "WHERE n.exploration_id=?", (eid,))
        by_node = {n["id"]: n for n in nodes}
        for a in anchors:
            if a["node_id"] in by_node:
                by_node[a["node_id"]]["anchors"].append(f"{a['kind']} {a['identifier']}")
        total_assets = conn.execute("SELECT COUNT(*) FROM asset_programs WHERE program=?",
                                    (program,)).fetchone()[0]
        assets = _rows(conn, "SELECT a.id, a.kind, a.identifier, a.parent_id, a.last_seen "
                             "FROM assets a JOIN asset_programs ap ON ap.asset_id=a.id "
                             "WHERE ap.program=? ORDER BY a.kind, a.identifier LIMIT ?",
                       (program, asset_limit))
        in_scope_ids = [r[0] for r in conn.execute(
            "SELECT asset_id FROM asset_programs WHERE program=?", (program,))]
        by_kind = {r[0]: r[1] for r in conn.execute(
            "SELECT a.kind, COUNT(*) FROM assets a JOIN asset_programs ap ON ap.asset_id=a.id "
            "WHERE ap.program=? GROUP BY a.kind", (program,))}
        covered_ids = {r[0] for r in conn.execute(
            "SELECT DISTINCT x.asset_id FROM anchors x JOIN nodes n ON n.id=x.node_id "
            "WHERE n.exploration_id=? AND n.kind IN ('fact','finding')", (eid,))}
        covered_ids |= {r[0] for r in conn.execute(
            "SELECT DISTINCT fa.asset_id FROM finding_assets fa JOIN findings f ON f.id=fa.finding_id "
            "WHERE f.exploration_id=? AND f.state IN ('confirmed','reported','closed')", (eid,))}
        touched_ids = {r[0] for r in conn.execute(
            "SELECT DISTINCT ta.asset_id FROM trace_assets ta JOIN traces t ON t.id=ta.trace_id "
            "WHERE t.exploration_id=?", (eid,))}
        # same semantics as coverage(): "touched" counts every asset a trace reached, including ones
        # a fact already covers; "touched_only" is what the coverage bar needs to stay additive.
        covered_ids_in_scope = [aid for aid in in_scope_ids if aid in covered_ids]
        touched_ids_in_scope = [aid for aid in in_scope_ids if aid in touched_ids]
        counts_by_coverage = {
            "covered": len(covered_ids_in_scope),
            "touched": len(touched_ids_in_scope),
            "touched_only": len([aid for aid in touched_ids_in_scope
                                 if aid not in covered_ids]),
            "untested": len([aid for aid in in_scope_ids
                             if aid not in covered_ids and aid not in touched_ids]),
        }
        for a in assets:
            a["coverage"] = ("covered" if a["id"] in covered_ids
                             else "touched" if a["id"] in touched_ids else "untested")
        findings = _rows(conn, "SELECT id, title, state, severity, confidence, updated_at, "
                               "(SELECT COUNT(*) FROM finding_artifacts ar WHERE ar.finding_id=findings.id) "
                               "AS drafts FROM findings WHERE exploration_id=? ORDER BY id DESC LIMIT 200",
                         (eid,))
        finding_assets = {}
        for r in conn.execute("SELECT fa.finding_id, a.identifier FROM finding_assets fa "
                              "JOIN assets a ON a.id=fa.asset_id JOIN findings f ON f.id=fa.finding_id "
                              "WHERE f.exploration_id=?", (eid,)):
            finding_assets.setdefault(r[0], []).append(r[1])
        finding_evidence = {r[0]: r[1] for r in conn.execute(
            "SELECT fe.finding_id, COUNT(*) FROM finding_evidence fe "
            "JOIN findings f ON f.id=fe.finding_id WHERE f.exploration_id=? "
            "GROUP BY fe.finding_id", (eid,))}
        for f in findings:
            f["assets"] = finding_assets.get(f["id"], [])
            f["evidence"] = finding_evidence.get(f["id"], 0)
        todos = _rows(conn, "SELECT id, content, state, depends_on, claimed_by, lease_until, "
                            "attempts, last_error FROM todos WHERE exploration_id=? ORDER BY id",
                      (eid,))
        for t in todos:
            t["depends_on"] = _load(t.get("depends_on"), [])
            t["lease_live"] = bool(t.get("lease_until") and t["state"] == "in_progress"
                                   and t["lease_until"] > now)
        pending = _rows(conn, "SELECT id, action, summary, state, requested_by, created_at, "
                              "expires_at, used_at, reason FROM approvals WHERE program=? "
                              "AND state IN ('pending','approved') AND used_at IS NULL "
                              "AND expires_at > ? ORDER BY id DESC LIMIT ?",
                        (program, now, max(1, int(approval_limit or 40))))
        decided = _rows(conn, "SELECT id, action, summary, state, requested_by, created_at, "
                              "expires_at, used_at, reason FROM approvals WHERE program=? "
                              "AND state IN ('denied','expired') ORDER BY id DESC LIMIT ?",
                        (program, max(1, int(approval_limit or 40) // 2)))
        approvals = pending + decided
        total_traces = conn.execute("SELECT COUNT(*) FROM traces WHERE exploration_id=?",
                                    (eid,)).fetchone()[0]
        traces = _rows(conn, "SELECT id, worker, tool, args, result, ok, created_at FROM traces "
                             "WHERE exploration_id=? ORDER BY id DESC LIMIT ?",
                       (eid, trace_limit))
        for t in traces:
            t["args"] = _short(t.get("args") or "", 300)
            t["result"] = _short(t.get("result") or "", 300)
        traffic = _rows(conn, "SELECT id, host, method, url, status, seen_count, "
                              "length(request_body) AS req_bytes, length(response_body) AS resp_bytes, "
                              "last_seen FROM traffic WHERE exploration_id=? ORDER BY id DESC LIMIT 200",
                        (eid,))
        traffic_hosts = _rows(conn, "SELECT host, COUNT(*) n, SUM(seen_count) hits FROM traffic "
                                    "WHERE exploration_id=? GROUP BY host ORDER BY n DESC", (eid,))
        total_traffic = conn.execute("SELECT COUNT(*) FROM traffic WHERE exploration_id=?",
                                     (eid,)).fetchone()[0]
    return {
        "program": program,
        "generated_at": now,
        "goal": exp.get("goal") or "",
        "status": exp.get("status") or "open",
        "nodes": nodes,
        "edges": edges,
        "assets": assets,
        "findings": findings,
        "todos": todos,
        "approvals": approvals,
        "traces": traces,
        "traffic": traffic,
        "traffic_hosts": traffic_hosts,
        "coverage": {"in_scope": len(in_scope_ids), "by_kind": by_kind,
                     "covered": counts_by_coverage["covered"],
                     "touched": counts_by_coverage["touched"],
                     "touched_only": counts_by_coverage["touched_only"],
                     "untested": counts_by_coverage["untested"]},
        "counts": {"nodes": total_nodes, "edges": len(edges), "assets": total_assets,
                   "traces": total_traces, "findings": len(findings), "traffic": total_traffic,
                   "pending_approvals": sum(1 for a in pending if a["state"] == "pending"),
                   "open_todos": sum(1 for t in todos if t["state"] in ("pending", "in_progress"))},
        "truncated": {"nodes": total_nodes > len(nodes), "assets": total_assets > len(assets)},
    }


def _json_for_script(obj) -> str:
    """JSON safe inside a <script> block: no '<!--', no '</script>' and no raw line separators."""
    text = json.dumps(obj, ensure_ascii=False, default=str, separators=(",", ":"))
    return (text.replace("</", "<\\/").replace("<!--", "<\\u0021--")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def export_html(program: str, out_path: str | None = None, db_path: str | None = None,
                open_in_browser: bool = False, data: dict | None = None) -> dict:
    """Write the self-contained cockpit page for one program. No network, no CDN, no assets:
    the whole view is one HTML file with the graph embedded as JSON."""
    program = _check_program(program)
    data = data or graph_export_data(program, db_path=db_path)
    path = os.path.abspath(out_path or os.path.join(WS, ".claude/state/graph",
                                                    f"cockpit-{program}.html"))
    if os.path.isdir(path):   # --out <dir> means "put the page in there", not "write over the dir"
        path = os.path.join(path, f"cockpit-{program}.html")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    title = f"GNOC DUAL GRAPH - {program}"
    page = (_COCKPIT_HTML.replace("__TITLE__", _html.escape(title))
            .replace("__PROGRAM__", _html.escape(program))
            .replace("__DATA__", _json_for_script(data)))
    # one temp file per writer: two chats exporting the same program must not clobber each other
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(page)
    os.replace(tmp, path)
    if open_in_browser:
        with contextlib.suppress(Exception):
            import webbrowser
            webbrowser.open("file://" + path)
    return {"ok": True, "path": path, "bytes": len(page.encode("utf-8")),
            "nodes": len(data["nodes"]), "edges": len(data["edges"]),
            "assets": data["counts"]["assets"], "findings": len(data["findings"]),
            "pending_approvals": data["counts"]["pending_approvals"]}


_COCKPIT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
  :root {
    --bg: #070a0f; --panel: #0c1118; --line: #17212c; --ink: #c6d3e2; --dim: #6b7d90;
    --green: #35d07f; --cyan: #4cc2ff; --amber: #f0c24b; --red: #ff5d5d; --violet: #c07cff;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body { margin: 0; background: var(--bg); color: var(--ink);
         font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow: hidden; }
  header { display: flex; align-items: center; gap: 18px; padding: 9px 14px;
           border-bottom: 1px solid var(--line); background: var(--panel); }
  header h1 { font-size: 13px; margin: 0; letter-spacing: .08em; text-transform: uppercase; }
  header h1 b { color: var(--green); }
  .stat { color: var(--dim); white-space: nowrap; }
  .stat b { color: var(--ink); font-weight: 600; }
  .cover { flex: 1; min-width: 120px; max-width: 320px; height: 8px; background: #101820;
           border: 1px solid var(--line); border-radius: 5px; overflow: hidden; display: flex; }
  .cover i { display: block; height: 100%; }
  .cover .c { background: var(--green); }
  .cover .t { background: var(--amber); }
  .shell { display: grid; grid-template-columns: 232px minmax(260px, 1fr) 292px;
           grid-template-rows: minmax(180px, 1fr) 196px; height: calc(100vh - 44px); }
  #left { grid-column: 1; grid-row: 1; border-right: 1px solid var(--line); overflow: auto;
          padding: 9px 10px; background: var(--panel); }
  #stage { grid-column: 2; grid-row: 1; position: relative; min-width: 0; }
  canvas { display: block; width: 100%; height: 100%; cursor: grab; }
  canvas.drag { cursor: grabbing; }
  #detail { grid-column: 3; grid-row: 1; border-left: 1px solid var(--line); overflow: auto;
            padding: 9px 12px; background: var(--panel); }
  #dock { grid-column: 1 / -1; grid-row: 2; border-top: 1px solid var(--line);
          background: var(--panel); overflow: auto; }
  .sec { margin-bottom: 14px; }
  .sec h2 { font-size: 10.5px; letter-spacing: .12em; text-transform: uppercase; color: var(--dim);
            margin: 0 0 6px; font-weight: 600; }
  input[type=search] { width: 100%; background: #0a0f15; color: var(--ink); border: 1px solid var(--line);
                       border-radius: 4px; padding: 4px 6px; font: inherit; }
  label.kind { display: flex; align-items: center; gap: 6px; padding: 1px 0; color: var(--dim); }
  label.kind input { accent-color: #2b8a5b; }
  .swatch { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  #nodelist { list-style: none; margin: 0; padding: 0; }
  #nodelist li { padding: 2px 4px; border-radius: 3px; cursor: pointer; white-space: nowrap;
                 overflow: hidden; text-overflow: ellipsis; color: var(--dim); }
  #nodelist li:hover { background: #121b25; color: var(--ink); }
  #nodelist li.on { background: #16242f; color: var(--ink); }
  #nodelist .id { color: #45586b; }
  #detail h3 { margin: 0 0 6px; font-size: 13px; line-height: 1.35; }
  #detail .kv { color: var(--dim); }
  #detail .kv b { color: var(--ink); font-weight: 600; }
  #detail .body { margin-top: 8px; white-space: pre-wrap; color: #a9bacb; }
  .pill { display: inline-block; padding: 0 6px; border-radius: 8px; font-size: 10.5px;
          border: 1px solid var(--line); color: var(--dim); }
  .pill.covered { border-color: #1f5c3d; color: var(--green); }
  .pill.touched { border-color: #5c4d1f; color: var(--amber); }
  .pill.untested { border-color: #2a3644; color: var(--dim); }
  .pill.pending { border-color: #5c4d1f; color: var(--amber); }
  .pill.approved { border-color: #1f5c3d; color: var(--green); }
  .pill.denied, .pill.expired { border-color: #5c2020; color: var(--red); }
  #tabs { display: flex; gap: 2px; padding: 4px 8px 0; border-bottom: 1px solid var(--line);
          position: sticky; top: 0; background: var(--panel); z-index: 2; }
  #tabs button { background: none; border: 1px solid transparent; border-bottom: none; color: var(--dim);
                 font: inherit; padding: 4px 9px; cursor: pointer; border-radius: 4px 4px 0 0; }
  #tabs button.on { color: var(--ink); border-color: var(--line); background: #101820; }
  #tabs .n { color: #45586b; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 3px 9px; border-bottom: 1px solid #101820; vertical-align: top; }
  th { color: var(--dim); font-size: 10.5px; letter-spacing: .08em; text-transform: uppercase;
       position: sticky; top: 27px; background: var(--panel); }
  td { color: #a9bacb; }
  td.mono { color: var(--ink); }
  .empty { padding: 14px; color: var(--dim); }
  #tip { position: fixed; pointer-events: none; background: #0e1620; border: 1px solid #223243;
         border-radius: 4px; padding: 4px 7px; max-width: 380px; color: var(--ink); display: none;
         z-index: 9; box-shadow: 0 6px 18px #0009; }
  #hint { position: absolute; left: 10px; bottom: 8px; color: #45586b; pointer-events: none; }
</style>
</head>
<body>
<header>
  <h1>GNOC dual graph &middot; <b>__PROGRAM__</b></h1>
  <span class="stat" id="st-nodes"></span>
  <span class="stat" id="st-assets"></span>
  <span class="stat" id="st-find"></span>
  <span class="stat" id="st-appr"></span>
  <span class="cover" id="st-cover" title="coverage: covered / touched / untested"></span>
  <span class="stat" id="st-when"></span>
</header>
<div class="shell">
  <aside id="left">
    <div class="sec">
      <h2>search</h2>
      <input type="search" id="q" placeholder="title, kind, state, asset">
    </div>
    <div class="sec">
      <h2>kinds</h2>
      <div id="kinds"></div>
    </div>
    <div class="sec">
      <h2>nodes <span id="n-count"></span></h2>
      <ul id="nodelist"></ul>
    </div>
  </aside>
  <main id="stage">
    <canvas id="cv"></canvas>
    <div id="tip"></div>
    <div id="hint">drag &middot; wheel to zoom &middot; click a node</div>
  </main>
  <aside id="detail"><div class="empty">select a node</div></aside>
  <section id="dock">
    <div id="tabs"></div>
    <div id="tabbody"></div>
  </section>
</div>
<script id="graph-data" type="application/json">__DATA__</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("graph-data").textContent);
  var KIND_COLOR = {begin: "#7c8794", goal: "#f0c24b", intent: "#4cc2ff", fact: "#35d07f",
                    finding: "#ff5d5d", hint: "#c07cff", digest: "#8fa3b8", note: "#9aa7b4"};
  var RADIUS = {goal: 9, finding: 8.5, intent: 7.5, fact: 6.5, digest: 6, hint: 5.5,
                begin: 5, note: 5};
  var nodes = DATA.nodes.map(function (n) {
    return {id: n.id, kind: n.kind, state: n.state, title: n.title, body: n.body || "",
            confidence: n.confidence, priority: n.priority, owner: n.owner,
            anchors: n.anchors || [], x: 0, y: 0, vx: 0, vy: 0};
  });
  var byId = {};
  nodes.forEach(function (n) { byId[n.id] = n; });
  var edges = (DATA.edges || []).filter(function (e) { return byId[e.src_id] && byId[e.dst_id]; });
  var adj = {};
  edges.forEach(function (e) {
    (adj[e.src_id] = adj[e.src_id] || {})[e.dst_id] = 1;
    (adj[e.dst_id] = adj[e.dst_id] || {})[e.src_id] = 1;
  });
  var kindsSeen = [];
  nodes.forEach(function (n) { if (kindsSeen.indexOf(n.kind) < 0) { kindsSeen.push(n.kind); } });
  kindsSeen.sort();
  var active = {};
  kindsSeen.forEach(function (k) { active[k] = true; });

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = String(text); }
    return e;
  }
  function fmt(n) { return (n === null || n === undefined) ? "-" : String(n); }

  // ---- header stats -------------------------------------------------------
  var cov = DATA.coverage || {in_scope: 0, covered: 0, touched: 0, touched_only: 0, untested: 0};
  document.getElementById("st-nodes").innerHTML = "nodes <b>" + DATA.counts.nodes + "</b>";
  document.getElementById("st-assets").innerHTML = "assets <b>" + cov.in_scope + "</b>";
  document.getElementById("st-find").innerHTML = "findings <b>" + DATA.findings.length + "</b>";
  document.getElementById("st-appr").innerHTML = "approvals <b>" + DATA.counts.pending_approvals + "</b>";
  document.getElementById("st-when").textContent = "as of " + (DATA.generated_at || "").replace("T", " ").replace("+00:00", "Z");
  var bar = document.getElementById("st-cover");
  var total = Math.max(1, cov.in_scope);
  [[cov.covered, "c"], [cov.touched_only, "t"]].forEach(function (pair) {
    var seg = el("i", pair[1]);
    seg.style.width = (100 * (pair[0] || 0) / total).toFixed(2) + "%";
    bar.appendChild(seg);
  });
  bar.title = cov.covered + " covered / " + cov.touched + " touched / " + cov.untested + " untested";

  // ---- filters ------------------------------------------------------------
  var kindsBox = document.getElementById("kinds");
  kindsSeen.forEach(function (k) {
    var lab = el("label", "kind");
    var cb = el("input");
    cb.type = "checkbox"; cb.checked = true;
    cb.addEventListener("change", function () { active[k] = cb.checked; reheat(); draw(); renderList(); });
    var dot = el("span", "swatch");
    dot.style.background = KIND_COLOR[k] || "#8899aa";
    lab.appendChild(cb); lab.appendChild(dot);
    lab.appendChild(el("span", null, k + " (" + nodes.filter(function (n) { return n.kind === k; }).length + ")"));
    kindsBox.appendChild(lab);
  });
  var query = "";
  document.getElementById("q").addEventListener("input", function (ev) {
    query = ev.target.value.trim().toLowerCase();
    draw(); renderList();
  });
  function matches(n) {
    if (!active[n.kind]) { return false; }
    if (!query) { return true; }
    var hay = (n.title + " " + n.kind + " " + n.state + " " + n.anchors.join(" ")).toLowerCase();
    return hay.indexOf(query) >= 0;
  }

  // ---- left node list -----------------------------------------------------
  var list = document.getElementById("nodelist");
  var nCount = document.getElementById("n-count");
  function renderList() {
    var shown = nodes.filter(matches).slice().sort(function (a, b) { return b.id - a.id; });
    nCount.textContent = "(" + shown.length + "/" + nodes.length + ")";
    list.textContent = "";
    shown.slice(0, 250).forEach(function (n) {
      var li = el("li", n.id === selected ? "on" : "");
      var dot = el("span", "swatch");
      dot.style.background = KIND_COLOR[n.kind] || "#8899aa";
      dot.style.marginRight = "5px";
      li.appendChild(dot);
      li.appendChild(el("span", "id", "#" + n.id + " "));
      li.appendChild(el("span", null, n.title));
      li.title = "#" + n.id + " " + n.kind + " [" + n.state + "] " + n.title;
      li.addEventListener("click", function () { select(n.id, true); });
      list.appendChild(li);
    });
  }

  // ---- force layout -------------------------------------------------------
  var W = 0, H = 0, k = 1, tx = 0, ty = 0, alpha = 1;
  var cv = document.getElementById("cv");
  var ctx = cv.getContext("2d");
  var dpr = window.devicePixelRatio || 1;
  function resize() {
    var box = cv.parentElement.getBoundingClientRect();
    W = Math.max(50, box.width); H = Math.max(50, box.height);
    cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    draw();
  }
  window.addEventListener("resize", resize);
  var golden = Math.PI * (3 - Math.sqrt(5));
  nodes.forEach(function (n, i) {
    var r = 26 * Math.sqrt(i + 1), a = i * golden;
    n.x = Math.cos(a) * r; n.y = Math.sin(a) * r;
  });
  function reheat() { alpha = 1; }
  function step() {
    var i, j, a, b, dx, dy, d2, f, ax, ay, e, dist;
    for (i = 0; i < nodes.length; i++) { nodes[i].fx = 0; nodes[i].fy = 0; }
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      for (j = i + 1; j < nodes.length; j++) {
        b = nodes[j];
        dx = b.x - a.x; dy = b.y - a.y;
        d2 = dx * dx + dy * dy;
        if (d2 > 250000 || d2 === 0) { continue; }
        if (d2 < 1) { d2 = 1; dx = ((i - j) % 3) + 0.5; dy = ((j - i) % 3) + 0.5; }
        f = 1100 / d2;
        ax = dx * f; ay = dy * f;
        a.fx -= ax; a.fy -= ay; b.fx += ax; b.fy += ay;
      }
    }
    for (i = 0; i < edges.length; i++) {
      e = edges[i]; a = byId[e.src_id]; b = byId[e.dst_id];
      dx = b.x - a.x; dy = b.y - a.y;
      dist = Math.sqrt(dx * dx + dy * dy) || 1;
      f = (dist - 78) * 0.012;
      ax = dx / dist * f; ay = dy / dist * f;
      a.fx += ax; a.fy += ay; b.fx -= ax; b.fy -= ay;
    }
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      a.fx -= a.x * 0.0022; a.fy -= a.y * 0.0022;
      if (a === dragNode) { a.vx = 0; a.vy = 0; continue; }
      a.vx = (a.vx + a.fx) * 0.82;
      a.vy = (a.vy + a.fy) * 0.82;
      var sp = Math.sqrt(a.vx * a.vx + a.vy * a.vy);
      if (sp > 14) { a.vx = a.vx / sp * 14; a.vy = a.vy / sp * 14; }
      a.x += a.vx; a.y += a.vy;
    }
    alpha *= 0.985;
  }

  // ---- drawing ------------------------------------------------------------
  var selected = 0, hovered = 0;
  function toWorld(px, py) { return {x: (px - tx) / k, y: (py - ty) / k}; }
  function draw() {
    if (!W || !H) { return; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);
    if (!nodes.length) {
      ctx.fillStyle = "#45586b";
      ctx.font = "13px ui-monospace, monospace";
      ctx.textAlign = "center";
      ctx.fillText("no exploration nodes yet - intents, facts and findings appear here", W / 2, H / 2);
      ctx.textAlign = "start";
      return;
    }
    ctx.save();
    ctx.translate(tx, ty); ctx.scale(k, k);
    var i, a, b, e;
    for (i = 0; i < edges.length; i++) {
      e = edges[i]; a = byId[e.src_id]; b = byId[e.dst_id];
      var hot = (selected && (e.src_id === selected || e.dst_id === selected)) ||
                (hovered && (e.src_id === hovered || e.dst_id === hovered));
      ctx.strokeStyle = hot ? "rgba(120,200,255,0.55)" : "rgba(110,150,190,0.16)";
      ctx.lineWidth = (hot ? 1.4 : 0.8) / k;
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }
    for (i = 0; i < nodes.length; i++) {
      a = nodes[i];
      var on = matches(a);
      ctx.globalAlpha = on ? 1 : 0.15;
      var r = RADIUS[a.kind] || 5.5;
      if (a.id === selected) {
        ctx.beginPath(); ctx.arc(a.x, a.y, r + 5, 0, 6.2832);
        ctx.strokeStyle = "#8fd8ff"; ctx.lineWidth = 1.5 / k; ctx.stroke();
      }
      ctx.beginPath(); ctx.arc(a.x, a.y, r, 0, 6.2832);
      ctx.fillStyle = KIND_COLOR[a.kind] || "#8899aa";
      ctx.fill();
      if (a.kind === "finding" || a.kind === "goal") {
        ctx.strokeStyle = "#0a0f14"; ctx.lineWidth = 1.5 / k; ctx.stroke();
      }
      var label = a.kind === "intent" || a.kind === "goal" || a.kind === "finding" ||
                  a.id === selected || a.id === hovered;
      if (label && k > 0.45) {
        ctx.globalAlpha = on ? 0.92 : 0.1;
        ctx.fillStyle = "#b9c9d9";
        ctx.font = (11 / k) + "px ui-monospace, monospace";
        ctx.fillText(trim(a.title, 34), a.x + r + 4 / k, a.y + 3 / k);
      }
      ctx.globalAlpha = 1;
    }
    ctx.restore();
  }
  function trim(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "\u2026" : s; }
  var fitted = false;
  function fitView(padPx) {
    if (!nodes.length) { k = 1; tx = W / 2; ty = H / 2; draw(); return; }
    var minX = 1e9, maxX = -1e9, minY = 1e9, maxY = -1e9;
    nodes.forEach(function (n) {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    });
    var pad = padPx || 80;
    var bw = Math.max(1, maxX - minX), bh = Math.max(1, maxY - minY);
    k = Math.min(2.2, Math.max(0.12, Math.min((W - pad * 2) / bw, (H - pad * 2) / bh)));
    tx = W / 2 - (minX + maxX) / 2 * k;
    ty = H / 2 - (minY + maxY) / 2 * k;
    draw();
  }
  function tick() {
    if (alpha > 0.02) {
      step(); draw();
      if (!fitted && alpha < 0.18) { fitted = true; fitView(); }
    }
    requestAnimationFrame(tick);
  }

  // ---- hover / select / drag ---------------------------------------------
  var dragNode = null, panning = false, last = null, moved = 0;
  var tip = document.getElementById("tip");
  function hit(px, py) {
    var w = toWorld(px, py), best = 0, bestD = 1e9;
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      if (!matches(n)) { continue; }
      var dx = n.x - w.x, dy = n.y - w.y, d = Math.sqrt(dx * dx + dy * dy);
      if (d < (RADIUS[n.kind] || 5.5) + 5 / k && d < bestD) { bestD = d; best = n.id; }
    }
    return best;
  }
  function localPos(ev) {
    var r = cv.getBoundingClientRect();
    return {x: ev.clientX - r.left, y: ev.clientY - r.top};
  }
  cv.addEventListener("mousemove", function (ev) {
    var p = localPos(ev);
    if (dragNode) {
      var w = toWorld(p.x, p.y);
      dragNode.x = w.x; dragNode.y = w.y;
      moved += 1; reheat(); draw(); return;
    }
    if (panning && last) {
      tx += p.x - last.x; ty += p.y - last.y; last = p; draw(); return;
    }
    var id = hit(p.x, p.y);
    if (id !== hovered) { hovered = id; draw(); }
    if (id) {
      var n = byId[id];
      tip.style.display = "block";
      tip.style.left = Math.min(window.innerWidth - 300, ev.clientX + 14) + "px";
      tip.style.top = (ev.clientY + 14) + "px";
      tip.textContent = "#" + n.id + " " + n.kind + " [" + n.state + "] " + n.title +
                        (n.anchors.length ? "\n" + n.anchors.join("  ") : "");
      tip.style.whiteSpace = "pre-wrap";
    } else { tip.style.display = "none"; }
  });
  cv.addEventListener("mousedown", function (ev) {
    var p = localPos(ev), id = hit(p.x, p.y);
    moved = 0;
    if (id) { dragNode = byId[id]; } else { panning = true; last = p; cv.className = "drag"; }
  });
  window.addEventListener("mouseup", function (ev) {
    if (dragNode && moved < 4) { select(dragNode.id, false); }
    dragNode = null; panning = false; last = null; cv.className = "";
  });
  cv.addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var p = localPos(ev), w = toWorld(p.x, p.y);
    var nk = Math.min(3.2, Math.max(0.22, k * (ev.deltaY < 0 ? 1.12 : 0.89)));
    tx = p.x - w.x * nk; ty = p.y - w.y * nk; k = nk; draw();
  }, {passive: false});

  function center(id) {
    var n = byId[id]; if (!n) { return; }
    tx = W / 2 - n.x * k; ty = H / 2 - n.y * k; draw();
  }
  function select(id, jump) {
    selected = id;
    if (jump) { center(id); }
    renderDetail();
    renderList();
    draw();
  }

  function renderDetail() {
    var box = document.getElementById("detail");
    box.textContent = "";
    var n = byId[selected];
    if (!n) { box.appendChild(el("div", "empty", "select a node")); return; }
    box.appendChild(el("div", "kv", "#" + n.id + "  " + n.kind));
    box.appendChild(el("h3", null, n.title));
    var kv = el("div", "kv");
    kv.appendChild(el("span", null, "state "));
    kv.appendChild(el("b", null, n.state));
    kv.appendChild(el("span", null, "  priority "));
    kv.appendChild(el("b", null, fmt(n.priority)));
    if (n.owner) { kv.appendChild(el("span", null, "  owner ")); kv.appendChild(el("b", null, n.owner)); }
    box.appendChild(kv);
    if (n.body) { box.appendChild(el("div", "body", n.body)); }
    if (n.anchors.length) {
      var a = el("div", "kv"); a.style.marginTop = "8px";
      a.appendChild(el("div", null, "anchors"));
      n.anchors.forEach(function (x) { a.appendChild(el("div", "mono", "  " + x)); });
      box.appendChild(a);
    }
  }

  // ---- dock tables --------------------------------------------------------
  var TABS = [
    {id: "assets", label: "assets", rows: function () { return DATA.assets || []; }},
    {id: "findings", label: "findings", rows: function () { return DATA.findings || []; }},
    {id: "todos", label: "todos", rows: function () { return DATA.todos || []; }},
    {id: "approvals", label: "approvals", rows: function () { return DATA.approvals || []; }},
    {id: "traces", label: "traces", rows: function () { return DATA.traces || []; }},
    {id: "traffic", label: "traffic", rows: function () { return DATA.traffic || []; }}
  ];
  var activeTab = "assets";
  var tabs = document.getElementById("tabs"), tabbody = document.getElementById("tabbody");
  function renderTabs() {
    tabs.textContent = "";
    TABS.forEach(function (t) {
      var b = el("button", t.id === activeTab ? "on" : "", t.label + " ");
      b.appendChild(el("span", "n", "(" + t.rows().length + ")"));
      b.addEventListener("click", function () { activeTab = t.id; renderTabs(); renderTab(); });
      tabs.appendChild(b);
    });
  }
  function cell(row, text, cls) {
    var td = el("td", cls || "", text === undefined || text === null ? "-" : text);
    row.appendChild(td);
  }
  function renderTab() {
    tabbody.textContent = "";
    var rows = TABS.filter(function (t) { return t.id === activeTab; })[0].rows();
    if (!rows.length) { tabbody.appendChild(el("div", "empty", "nothing here yet")); return; }
    var table = el("table"), thead = el("thead"), hr = el("tr");
    var cols = {
      assets: ["id", "kind", "identifier", "coverage", "last seen"],
      findings: ["id", "state", "sev", "confidence", "title", "assets", "evidence", "drafts"],
      todos: ["id", "state", "content", "worker", "attempts"],
      approvals: ["id", "state", "action", "summary", "expires"],
      traces: ["id", "when", "worker/tool", "result"],
      traffic: ["id", "method", "status", "url", "host", "req/resp bytes", "hits"]
    }[activeTab];
    cols.forEach(function (c) { hr.appendChild(el("th", null, c)); });
    thead.appendChild(hr); table.appendChild(thead);
    var tb = el("tbody");
    rows.slice(0, 400).forEach(function (r) {
      var tr = el("tr");
      if (activeTab === "assets") {
        cell(tr, "#" + r.id, "mono"); cell(tr, r.kind); cell(tr, r.identifier, "mono");
        var td = el("td");
        var p = el("span", "pill " + r.coverage, r.coverage);
        td.appendChild(p); tr.appendChild(td);
        cell(tr, (r.last_seen || "").slice(0, 16));
      } else if (activeTab === "findings") {
        cell(tr, "#" + r.id, "mono");
        var st = el("td"); st.appendChild(el("span", "pill " + (r.state === "confirmed" || r.state === "reported" ? "approved" : "pending"), r.state)); tr.appendChild(st);
        cell(tr, r.severity || "-"); cell(tr, r.confidence || "-");
        cell(tr, r.title); cell(tr, (r.assets || []).join(", ") || "-"); cell(tr, r.evidence);
        cell(tr, r.drafts ? r.drafts : "-");
      } else if (activeTab === "todos") {
        cell(tr, "#" + r.id, "mono"); cell(tr, r.state, "mono"); cell(tr, r.content);
        cell(tr, r.claimed_by || "-"); cell(tr, r.attempts);
      } else if (activeTab === "approvals") {
        cell(tr, "#" + r.id, "mono");
        var st2 = el("td"); st2.appendChild(el("span", "pill " + r.state, r.state)); tr.appendChild(st2);
        cell(tr, r.action, "mono"); cell(tr, r.summary, "mono");
        cell(tr, (r.expires_at || "").slice(0, 16));
      } else if (activeTab === "traces") {
        cell(tr, "#" + r.id, "mono"); cell(tr, (r.created_at || "").slice(0, 16));
        cell(tr, r.worker + " / " + r.tool, "mono"); cell(tr, r.result);
      } else {
        cell(tr, "#" + r.id, "mono"); cell(tr, r.method, "mono");
        var st3 = el("td");
        var cls = r.status >= 400 ? "denied" : (r.status >= 200 && r.status < 300 ? "approved" : "pending");
        st3.appendChild(el("span", "pill " + cls, r.status === null || r.status === undefined ? "???" : r.status));
        tr.appendChild(st3);
        cell(tr, r.url, "mono"); cell(tr, r.host || "-");
        cell(tr, (r.req_bytes || 0) + " / " + (r.resp_bytes || 0) + " b");
        cell(tr, r.seen_count);
      }
      tb.appendChild(tr);
    });
    table.appendChild(tb); tabbody.appendChild(table);
  }

  // ---- boot ---------------------------------------------------------------
  resize();
  fitView();
  renderList(); renderTabs(); renderTab();
  requestAnimationFrame(tick);
  cv.addEventListener("dblclick", function () { fitView(); });
  if (!nodes.length) {
    document.getElementById("detail").textContent = "";
    document.getElementById("detail").appendChild(
      el("div", "empty", "no exploration nodes yet: the agent writes intents, facts and findings here."));
  }
  window.__gnocGraph = {data: DATA, select: select, fit: fitView};
})();
</script>
</body>
</html>
"""


# ------------------------------------------------------------------ CLI
def _main(argv: list[str]) -> int:
    action = (argv[0] if argv else "overview").lower()
    rest = argv[1:]
    program = rest[0] if rest else ""
    if action in ("programs", "list"):
        rows = all_programs()
        print("\n".join(rows) if rows else "no graph data")
        return 0
    if action in ("overview", "status"):
        if not program:
            rows = all_programs()
            if not rows:
                print("no graph data")
                return 0
            program = rows[0]
        print(overview_text(program))
        return 0
    if action in ("assets", "asset"):
        if rest and rest[0].isdigit():
            print(asset_text(int(rest[0])))
            return 0
        kind, wanted, words = "", "", []
        for w in rest[1:]:
            if w.startswith("kind="):
                kind = w.split("=", 1)[1]
            elif w.startswith("coverage="):
                wanted = w.split("=", 1)[1].lower()
            else:
                words.append(w)
        query = " ".join(words)
        if not (kind or wanted):
            print(assets_text(program or None, query=query))
            return 0
        try:
            print(assets_filter_text(program or None, kind=kind, coverage_state=wanted, query=query))
        except Exception as e:  # noqa: BLE001
            print(f"assets failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action in ("coverage", "untested"):
        if not program:
            print("usage: gnoc graph coverage <program>")
            return 2
        print(coverage_text(program))
        return 0
    if action in ("stats", "dashboard", "stat"):
        if not program:
            print("usage: gnoc graph stats <program>")
            return 2
        print(stats_text(program))
        return 0
    if action in ("snapshot", "snap"):
        if not program or program.startswith("-"):
            print("usage: gnoc graph snapshot <program> [label]")
            return 2
        try:
            snap = take_snapshot(program, label=" ".join(rest[1:]))
        except Exception as e:  # noqa: BLE001
            print(f"snapshot failed: {type(e).__name__}: {e}")
            return 1
        print(f"snapshot #{snap['id']} {snap['taken_at']} - {snap['assets']} assets  "
              f"sha256 {snap['sha256'][:16]}")
        return 0
    if action in ("snapshots",):
        if not program:
            print("usage: gnoc graph snapshots <program>")
            return 2
        print(snapshots_text(program))
        return 0
    if action in ("diff", "surface-diff"):
        if not program:
            print("usage: gnoc graph diff <program> [snapshot-id|timestamp|label]")
            return 2
        try:
            print(diff_text(program, since=(rest[1] if len(rest) > 1 else None)))
        except Exception as e:  # noqa: BLE001
            print(f"diff failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action in ("path",):
        if not program or len(rest) < 3 or not str(rest[1]).isdigit() or not str(rest[2]).isdigit():
            print("usage: gnoc graph path <program> <from_node> <to_node>")
            return 2
        try:
            print(path_text(program, int(rest[1]), int(rest[2])))
        except Exception as e:  # noqa: BLE001
            print(f"path failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action in ("lineage", "ancestors"):
        if not program or len(rest) < 2 or not str(rest[1]).isdigit():
            print("usage: gnoc graph lineage <program> <node_id>")
            return 2
        try:
            print(lineage_text(program, int(rest[1])))
        except Exception as e:  # noqa: BLE001
            print(f"lineage failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action in ("nodes", "node"):
        if not program:
            print("usage: gnoc graph nodes <program> [kind] [state] [query]")
            return 2
        if len(rest) > 1 and rest[1].isdigit():
            print(node_text(program, int(rest[1])))
            return 0
        kind = rest[1] if len(rest) > 1 else None
        print(nodes_text(program, kind=kind, query=" ".join(rest[2:])))
        return 0
    if action in ("todos", "todo"):
        if not program:
            print("usage: gnoc graph todos <program>")
            return 2
        print(todos_text(program))
        return 0
    if action in ("traces", "trace"):
        if not program:
            print("usage: gnoc graph traces <program> [query]")
            return 2
        print(traces_text(program, query=" ".join(rest[1:])))
        return 0
    if action in ("evidence", "ev"):
        if not program:
            print("usage: gnoc graph evidence <program> [query]")
            return 2
        if len(rest) > 1 and rest[1].isdigit():
            rows = evidence_get(program, [int(rest[1])])
            print(json.dumps(rows[0], indent=2) if rows else f"no evidence #{rest[1]} in {program}")
            return 0 if rows else 1
        print(evidence_text(program, query=" ".join(rest[1:])))
        return 0
    if action in ("traffic", "http"):
        if not program or program.startswith("-"):
            print("usage: gnoc graph traffic <program> [hosts | show <id> | purge [host] | [search] QUERY] "
                  "[--host H] [--method M] [--status N]")
            return 2
        sub = (rest[1].lower() if len(rest) > 1 else "")
        try:
            if sub in ("hosts", "host"):
                print(traffic_hosts_text(program))
                return 0
            if sub in ("show", "detail", "get"):
                if len(rest) < 3 or not str(rest[2]).isdigit():
                    print("usage: gnoc graph traffic <program> show <id>")
                    return 2
                print(traffic_detail_text(program, int(rest[2])))
                return 0
            if sub in ("purge", "clear", "delete"):
                host = rest[2] if len(rest) > 2 else ""
                n = traffic_purge(program, host=host)
                print(f"purged {n} traffic row(s)" + (f" for host {host}" if host else ""))
                return 0
            host = method = ""
            status = None
            query = ""
            words = rest[1:]
            i = 0
            while i < len(words):
                w = words[i]
                if w == "--host" and i + 1 < len(words):
                    host = words[i + 1]
                    i += 1
                elif w == "--method" and i + 1 < len(words):
                    method = words[i + 1]
                    i += 1
                elif w == "--status" and i + 1 < len(words):
                    status = words[i + 1]
                    i += 1
                elif w in ("search", "find"):
                    pass
                else:
                    query = (query + " " + w).strip()
                i += 1
            print(traffic_text(program, query=query, host=host, method=method, status=status))
        except Exception as e:  # noqa: BLE001
            print(f"traffic failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action in ("findings", "finding"):
        if not program:
            print("usage: gnoc graph findings <program> [state]")
            return 2
        if len(rest) > 1 and rest[1].isdigit():
            row = finding_get(program, int(rest[1]))
            print(json.dumps(row, indent=2) if row else f"no finding #{rest[1]} in {program}")
            return 0 if row else 1
        print(findings_text(program, state=rest[1] if len(rest) > 1 else ""))
        return 0
    if action in ("draft", "artifact"):
        if not program or program.startswith("-") or len(rest) < 2 or not str(rest[1]).isdigit():
            print("usage: gnoc graph draft <program> <finding_id> [--out DIR] "
                  "[--cvss '<vector> = <score> <Severity>'] [--cwe 'CWE-NNN Name']")
            return 2
        out_dir, cvss, cwe = "", "", ""
        words = rest[2:]
        i = 0
        while i < len(words):
            w = words[i]
            if w in ("--out", "--output") and i + 1 < len(words):
                out_dir = words[i + 1]
                i += 1
            elif w == "--cvss" and i + 1 < len(words):
                cvss = words[i + 1]
                i += 1
            elif w == "--cwe" and i + 1 < len(words):
                cwe = words[i + 1]
                i += 1
            else:
                print(f"draft: ignoring unrecognised argument {w!r}")
            i += 1
        try:
            got = finding_artifact(program, int(rest[1]), out_dir=(out_dir or None), cvss=cvss, cwe=cwe)
        except Exception as e:  # noqa: BLE001 - the CLI reports, never tracebacks
            print(f"draft failed: {type(e).__name__}: {e}")
            return 1
        print(artifact_text(got))
        return 0
    if action in ("retest", "retests", "retest-done"):
        if not program or program.startswith("-"):
            print("usage: gnoc graph retest <program> <finding_id> [--in DAYS] [--note TEXT]\n"
                  "       gnoc graph retests <program> [--all]\n"
                  "       gnoc graph retest-done <program> <retest_id> reproduces|fixed|cancelled [note]")
            return 2
        try:
            if action == "retests":
                print(retests_text(program, active_only=("--all" not in rest)))
                return 0
            if action == "retest-done":
                if len(rest) < 3 or not str(rest[1]).isdigit():
                    print("usage: gnoc graph retest-done <program> <retest_id> reproduces|fixed|cancelled [note]")
                    return 2
                row = retest_update(program, int(rest[1]), rest[2], note=" ".join(rest[3:]))
                print(f"retest #{row['id']} -> {row['state']}  due {row['due_at'][:16]}"
                      + (f"  {row['outcome']}" if row.get("outcome") else ""))
                return 0
            if not rest or not str(rest[1]).isdigit():
                print("usage: gnoc graph retest <program> <finding_id> [--in DAYS] [--note TEXT]")
                return 2
            days, note = 14, ""
            words = rest[2:]
            i = 0
            while i < len(words):
                if words[i] == "--in" and i + 1 < len(words):
                    days = words[i + 1]
                    i += 1
                elif words[i] == "--note" and i + 1 < len(words):
                    note = words[i + 1]
                    i += 1
                elif not str(words[i]).startswith("--") and not note:
                    note = " ".join(words[i:])
                    break
                i += 1
            row = retest_add(program, int(rest[1]), due_in_days=days, note=note)
            print(f"retest #{row['id']} scheduled for finding #{row['finding_id']} "
                  f"on {row['due_at'][:16]} (state {row['state']})")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"retest failed: {type(e).__name__}: {e}")
            return 1
    if action in ("rules", "rule"):
        if not program or program.startswith("-"):
            print("usage: gnoc graph rules <program> [list | add <action> <pattern> [--uses N] [--ttl SECS] "
                  "[--note TEXT] | rm <id>]")
            return 2
        try:
            sub = (rest[1].lower() if len(rest) > 1 else "list")
            if sub in ("list", "ls"):
                print(rules_text(program))
                return 0
            if sub in ("rm", "remove", "delete"):
                if len(rest) < 3 or not str(rest[2]).isdigit():
                    print("usage: gnoc graph rules <program> rm <id>")
                    return 2
                ok = rule_remove(program, int(rest[2]))
                print(f"removed approval rule #{rest[2]}" if ok else f"no rule #{rest[2]} in {program}")
                return 0 if ok else 1
            if sub in ("add", "allow"):
                if len(rest) < 4:
                    print("usage: gnoc graph rules <program> add <action> <pattern> [--uses N] [--ttl SECS] "
                          "[--note TEXT]")
                    return 2
                uses, ttl, note = 1, 3600, ""
                words = rest[4:]
                i = 0
                while i < len(words):
                    if words[i] == "--uses" and i + 1 < len(words):
                        uses = words[i + 1]
                        i += 1
                    elif words[i] == "--ttl" and i + 1 < len(words):
                        ttl = words[i + 1]
                        i += 1
                    elif words[i] == "--note" and i + 1 < len(words):
                        note = words[i + 1]
                        i += 1
                    i += 1
                row = rule_add(program, rest[2], rest[3], uses=uses, ttl_secs=ttl, note=note)
                print(f"rule #{row['id']} allows {row['action']} while the args match {row['pattern']!r} "
                      f"({row['uses_left']} use(s), until {row['expires_at']})")
                return 0
            print(f"unknown rules action: {sub} (list|add|rm)")
            return 2
        except Exception as e:  # noqa: BLE001
            print(f"rules failed: {type(e).__name__}: {e}")
            return 1
    if action in ("approvals", "approval"):
        state = rest[1] if len(rest) > 1 else "pending"
        print(approvals_text(program or None, state=state))
        return 0
    if action in ("export", "web", "html", "cockpit"):
        if not program or program.startswith("-"):
            print("usage: gnoc graph export <program> [--out PATH] [--open]")
            return 2
        out_path, open_it = None, False
        words = rest[1:]
        i = 0
        while i < len(words):
            w = words[i]
            if w in ("--open", "-o"):
                open_it = True
            elif w in ("--out", "--output") and i + 1 < len(words):
                out_path = words[i + 1]
                i += 1
            elif w == "--no-open":
                open_it = False
            else:
                print(f"export: ignoring unrecognised argument {w!r}")
            i += 1
        try:
            got = export_html(program, out_path=out_path, open_in_browser=open_it)
        except Exception as e:  # noqa: BLE001 - the CLI reports, never tracebacks
            print(f"export failed: {type(e).__name__}: {e}")
            return 1
        print(f"cockpit written: {got['path']}")
        print(f"  {got['nodes']} nodes, {got['edges']} edges, {got['assets']} assets, "
              f"{got['findings']} findings, {got['pending_approvals']} pending approvals "
              f"({got['bytes']} bytes, self-contained)")
        if not open_it:
            print("  open it with: xdg-open " + got["path"])
        return 0
    print(__doc__.strip().splitlines()[-1])
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
