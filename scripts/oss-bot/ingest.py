#!/usr/bin/env python3
"""ingest - normalise oss-bot tool output into forced-LEAD records (mirror of shannon-ingest.py).

    ingest.py <program> <run_dir> [--tier N]

HARD INVARIANTS (selfcheck proves each):
  * every record's verdict is the module constant LEAD. make_record() takes no verdict argument and
    never copies one from tool output; emit() asserts it and asserts the exact key set. There is no
    code path that writes any other verdict. The bot never calls hunt-state.py append-outcome/ship.
  * every write goes through guard(): it must resolve under targets/<p>/recon/oss-bot/ or
    .claude/state/oss-bot/, or equal the orch INBOX or the SCOPE-INCIDENTS log. Anything else raises
    (F7: never reports/).
  * secret values never leave the chmod-600 .raw: evidence = first4...last2 sha256:<12hex>, and every
    secret value found in the run is scrubbed from every other emitted field.
  * post-run AUDIT (net 3): every host in a network tool's output must have an allowed egress row in that
    run, else SCOPE-INCIDENTS + global PAUSE + INBOX HEALTH and the run's leads are dropped.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import sqlite3
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from bbtools import lib_scope  # noqa: E402

WS_ROOT = lib_scope.WS_ROOT
LEAD = "LEAD"
NET_JOBS = ("probe", "nuclei-fast", "nuclei-cve", "crawl")
RECORD_KEYS = ("ts", "program", "tool", "rule", "severity", "host", "url", "method", "status", "evidence",
               "client", "run", "fp", "verdict", "score", "dedup", "suppressed", "occurrences")
SEV = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.5}
SECRET_CLASS = re.compile(r"aws|gcp|service.?account|private.?key|github|slack", re.I)
SECRET_TOOLS = ("gitleaks", "trufflehog")
# Secret hits in these paths of a cloned/vendored tree are test vectors, fixtures and docs, not leaks: on 2026-10-21
# 967 of 1001 vandelay gitleaks leads sat in tests/data/hpke-vectors and parser fixtures. Our own capture dirs
# (hunts/*/raw, evidence/) never match, so a secret seen in a TARGET's response is never path-suppressed.
_VENDORED = re.compile(r"(^|/)(node_modules|vendor|third_party|bower_components|\.venv|venv|site-packages)/", re.I)
_TESTDIR = re.compile(r"(^|/)(tests?|testdata|test-data|test_data|__tests__|__mocks__|spec|specs|fixtures?|vectors?|"
                      r"mocks?|examples?|samples?|e2e|integration_tests?|testutils?|testing)(/|$)", re.I)
_TESTFILE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.[a-z0-9]+|[^/]*\.(test|spec)\.[a-z0-9]+|conftest\.py|"
                       r"[^/]*(example|sample|dummy|fake|mock)[^/]*)$", re.I)
_DOCFILE = re.compile(r"(^|/)(docs?/[^ ]*|[^/]*\.(md|rst|adoc)|readme[^/]*|changelog[^/]*)$", re.I)


_LOCKFILE = re.compile(r"(^|/)(cargo\.lock|uv\.lock|poetry\.lock|pipfile\.lock|package-lock\.json|yarn\.lock|"
                       r"pnpm-lock\.yaml|go\.sum|composer\.lock|gemfile\.lock|[^/]*\.lock)$", re.I)
# compiler / VCS output only: NOT dist/, out/, .next/ or .map, where a downloaded TARGET bundle or source map lives
_BUILD = re.compile(r"(^|/)(\.git|build|target|cmakefiles|__pycache__)/|\.(o|obj|a|so|dylib|pyc|class|promisor|pack|idx)$",
                    re.I)
# <host>-<probe>.<ext>: the host ends at its TLD (a non-greedy match cut 'app.example.com' to 'app')
_CAPTURE = re.compile(r"/hunts/[^/]+/raw/((?:[a-z0-9-]+\.)+[a-z]{2,})-[^/]*$", re.I)


def capture_context(path):
    """For a hit inside one of OUR captures (hunts/<lane>/raw/<host>-<probe>.*): 'own-account' when the captured host
    is our own tenant (a 'greynoc' name, so the secret is ours), 'third-party-capture' when it is a third-party host
    (lib_scope.THIRD_PARTY, e.g. github.com pages a sweep fetched), else None (a target response: always reviewed)."""
    m = _CAPTURE.search(str(path or "").split(":")[0])
    if not m:
        return None
    host = m.group(1).lower()
    if re.search(r"greynoc|grey-noc", host):  # our own tenants and owned test deployments
        return "own-account"
    if lib_scope.THIRD_PARTY.search(host):
        return "third-party-capture"
    return None


def path_context(path):
    """'vendored' | 'test-path' | 'doc-path' | 'lockfile' | 'build-artifact' | 'own-account' | 'third-party-capture'
    | None for a secret hit's file path (url column of a secrets lead)."""
    p = str(path or "").split(":")[0]
    if not p:
        return None
    if "/hunts/" in p or "/evidence/" in p:
        return capture_context(p)
    if _VENDORED.search(p):
        return "vendored"
    if _TESTDIR.search(p) or _TESTFILE.search(p):
        return "test-path"
    if _DOCFILE.search(p):
        return "doc-path"
    if _LOCKFILE.search(p):
        return "lockfile"
    if _BUILD.search(p):
        return "build-artifact"
    return None
SEEDS_HEADER = ("Scanner LEADS only. Not findings. Scanner silence is not a negative (T-40, T-153). Verify "
                "each by hand: scope, policy, dedup, crafted probe with controls, terminal capture.")
CHECKLIST = [
    "- [ ] Pin the exact deployed/source version and confirm the feature is active.",
    "- [ ] Confirm the host/path is in scope and the program permits automation for this environment.",
    "- [ ] Run local and public dedup before the first live reproduction request.",
    "- [ ] Read the full source-to-sink path; do not inherit the scanner's interpretation.",
    "- [ ] Reproduce with one-variable negative and positive controls using the house client.",
    "- [ ] Capture raw request/response bytes or an owned-account state delta.",
    "- [ ] Name the new attacker capability and push it to a terminal; otherwise keep `LEAD`.",
    "- [ ] Have an independent validator run the shipped reproduction artifact.",
]
SCHEMA = """
CREATE TABLE IF NOT EXISTS programs(program TEXT PRIMARY KEY, tier INTEGER, status TEXT, rps REAL, header TEXT,
  evidence TEXT, refreshed REAL);
CREATE TABLE IF NOT EXISTS jobs(program TEXT, job TEXT, next_due REAL, last_start REAL, last_end REAL, last_rc INTEGER,
  fails INTEGER DEFAULT 0, cursor INTEGER DEFAULT 0, pid INTEGER, run_dir TEXT, PRIMARY KEY(program, job));
CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, program TEXT, job TEXT, started REAL, ended REAL, rc INTEGER,
  hosts_in INTEGER, hosts_refused INTEGER, leads_new INTEGER, audit TEXT, run_dir TEXT);
CREATE TABLE IF NOT EXISTS hosts(program TEXT, host TEXT, first_seen REAL, last_seen REAL, live INTEGER,
  PRIMARY KEY(program, host));
CREATE TABLE IF NOT EXISTS leads(fp TEXT PRIMARY KEY, program TEXT, tool TEXT, rule TEXT, severity TEXT, host TEXT,
  url TEXT, first_seen REAL, last_seen REAL, score REAL, suppressed TEXT,
  state TEXT NOT NULL DEFAULT 'LEAD' CHECK(state IN ('LEAD','FP','DUPE','HUMAN-VERIFIED-ELSEWHERE')), mark_note TEXT);
"""


class PathGuardError(Exception):
    pass


def _now():
    return time.time()


def _iso(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t if t is not None else _now()))


def is_valid_program_name(program):
    """A schedulable program name - excludes sandbox/workbench dirs (leading underscore etc) up
    front, not just at the path-guard layer, so the daemon never offers them a job in the first
    place (a program that fails this can still reach _check_program as a second, independent gate)."""
    return bool(program) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", program)) and ".." not in program


def _check_program(program):
    if not is_valid_program_name(program):
        raise PathGuardError(f"bad program name {program!r}")


def out_dir(program, root=WS_ROOT):
    _check_program(program)
    return os.path.join(root, "targets", program, "recon", "oss-bot")


def state_dir(root=WS_ROOT):
    return os.path.join(root, ".claude", "state", "oss-bot")


def guard(path, program, root=WS_ROOT):
    """Raise unless `path` resolves inside an allowed oss-bot write location. Returns the real path."""
    _check_program(program)
    rp = os.path.realpath(path)
    rroot = os.path.realpath(root)
    if rp == os.path.join(rroot, "reports") or rp.startswith(os.path.join(rroot, "reports") + os.sep):
        raise PathGuardError(f"write under reports/ refused: {path}")
    dirs = [os.path.realpath(out_dir(program, root)), os.path.realpath(state_dir(root))]
    exact = {os.path.realpath(os.path.join(root, ".claude/state/orch/INBOX.md")),
             os.path.realpath(os.path.join(root, ".claude/state/hunt-loop/SCOPE-INCIDENTS.md"))}
    if rp in exact or any(rp == d or rp.startswith(d + os.sep) for d in dirs):
        return rp
    raise PathGuardError(f"write outside oss-bot locations refused: {path}")


def gmkdir(path, program, root=WS_ROOT):
    os.makedirs(guard(path, program, root), exist_ok=True)


def gwrite(path, text, program, root=WS_ROOT, mode=None):
    rp = guard(path, program, root)
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    tmp = guard(rp + ".tmp", program, root)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode:
        os.chmod(tmp, mode)
    os.replace(tmp, rp)


def gappend(path, text, program, root=WS_ROOT):
    """One os.write() per call on an O_APPEND fd (INBOX lines never interleave)."""
    rp = guard(path, program, root)
    os.makedirs(os.path.dirname(rp), exist_ok=True)
    fd = os.open(rp, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)


def db_connect(root=WS_ROOT):
    d = state_dir(root)
    os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(os.path.join(d, "bot.db"), timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    return con


# ------------------------------------------------------------------ records
def _sev(s):
    s = str(s or "").lower()
    return s if s in SEV else "info"


def redact(value):
    v = str(value)
    h = hashlib.sha256(v.encode()).hexdigest()[:12]
    return (f"{v[:4]}...{v[-2:]} sha256:{h}" if len(v) > 8 else f"**** sha256:{h}")


def make_record(program, tool, ver, run_rel, rule, severity, host, url, status, evidence, fp, via):
    """The ONLY record constructor. No verdict parameter exists; tool fields can never set one."""
    return {"ts": _iso(), "program": program, "tool": tool, "rule": str(rule or "")[:200],
            "severity": _sev(severity), "host": str(host or "").lower(), "url": str(url or "")[:500],
            "method": "GET", "status": status if isinstance(status, int) else None,
            "evidence": str(evidence or "")[:300], "client": f"oss-bot/{tool}@{ver} via {via}",
            "run": run_rel, "fp": fp, "verdict": LEAD, "score": 0.0,
            "dedup": {"hq_docs": 0, "dnr": False, "submitted": False}, "suppressed": None,
            "occurrences": 1}


def emit(rec):
    assert rec.get("verdict") == LEAD and rec["verdict"] is LEAD, f"verdict invariant broken: {rec.get('verdict')!r}"
    assert tuple(rec.keys()) == RECORD_KEYS, f"record key set drifted: {tuple(rec.keys())}"
    return json.dumps(rec, sort_keys=False) + "\n"


def _jsonl(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    try:
                        yield json.loads(ln)
                    except json.JSONDecodeError:
                        continue
    except OSError:
        return


def _sha1(*parts):
    return hashlib.sha1("\x1f".join(str(p) for p in parts).encode()).hexdigest()


# ------------------------------------------------------------------ parsers (no verdicts anywhere)
def parse_nuclei(path):
    for o in _jsonl(path):
        info = o.get("info") or {}
        url = o.get("matched-at") or o.get("url") or o.get("host") or ""
        ev = " ".join(x for x in [o.get("matcher-name") or "", ",".join(map(str, o.get("extracted-results") or []))] if x)
        tags = info.get("tags") or []
        tags = tags if isinstance(tags, list) else str(tags).split(",")
        yield {"rule": o.get("template-id") or "", "severity": info.get("severity"),
               "host": lib_scope.extract_host(url), "url": url, "status": None, "evidence": ev,
               "tags": [t.strip().lower() for t in tags]}


def parse_httpx(path):
    for o in _jsonl(path):
        if o.get("failed") is True:
            continue
        url = o.get("url") or ""
        yield {"url": url, "host": lib_scope.extract_host(url).lower(), "status": o.get("status_code"),
               "title": o.get("title") or "", "tech": o.get("tech") or []}


def parse_katana(path):
    for o in _jsonl(path):
        if o.get("error") and not o.get("response"):
            continue   # a failed request (e.g. the proxy denied it) is not output and names no reached host
        req = o.get("request") or {}
        url = req.get("endpoint") or o.get("endpoint") or o.get("url") or ""
        if url:
            yield {"url": url, "host": lib_scope.extract_host(url).lower(),
                   "status": (o.get("response") or {}).get("status_code")}


def parse_subfinder(path):
    for o in _jsonl(path):
        if o.get("host"):
            yield str(o["host"]).lower().rstrip(".")


def parse_gau(path):
    for o in _jsonl(path):
        if o.get("url"):
            yield o["url"]


def parse_gitleaks(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return
    for o in data if isinstance(data, list) else []:
        yield {"detector": o.get("RuleID") or "gitleaks", "value": o.get("Secret") or o.get("Match") or "",
               "file": o.get("File") or "", "line": o.get("StartLine")}


def parse_trufflehog(path):
    for o in _jsonl(path):
        if "DetectorName" not in o:
            continue
        fsm = ((o.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
        yield {"detector": o.get("DetectorName") or "trufflehog", "value": o.get("Raw") or "",
               "file": fsm.get("file") or "", "line": fsm.get("line")}


def parse_semgrep(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return
    sm = {"ERROR": "medium", "WARNING": "low", "INFO": "info"}
    for o in (data or {}).get("results") or []:
        ex = o.get("extra") or {}
        yield {"rule": o.get("check_id") or "", "severity": sm.get(str(ex.get("severity")).upper(), "info"),
               "file": o.get("path") or "", "line": (o.get("start") or {}).get("line"),
               "evidence": f"{ex.get('message') or ''} | {' '.join(str(ex.get('lines') or '').split())}"}


# ------------------------------------------------------------------ dedup / suppression
def _read_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]
    except OSError:
        return []


class Dedup:
    def __init__(self, program, root):
        self.program, self.root = program, root
        self.dnr = [ln.lower() for f in (f".claude/state/do-not-rehunt/{program}.txt",
                                         ".claude/state/hunt-loop/do-not-rehunt.txt")
                    for ln in _read_lines(os.path.join(root, f))]
        self.fp_rules = {ln.strip().split()[0] for ln in _read_lines(os.path.join(state_dir(root), "fp-templates.txt"))}
        self.benign_val, self.benign_det = [], []
        for ln in _read_lines(os.path.join(HERE, "secret-benign.txt")):
            ln = ln.strip()
            (self.benign_det if ln.startswith("detector:") else self.benign_val).append(
                re.compile(ln[len("detector:"):] if ln.startswith("detector:") else ln, re.I))
        self.submitted = []
        for f in glob.glob(os.path.join(root, "reports", "submitted", program, "**", "*"), recursive=True):
            if os.path.isfile(f) and os.path.splitext(f)[1] in (".md", ".txt", ".json") and os.path.getsize(f) < 2_000_000:
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        self.submitted.append(fh.read().lower())
                except OSError:
                    pass
        self._hq, self._hq_cache = None, {}
        hq = os.path.join(root, ".hunt-index", "hunts.db")
        if os.path.isfile(hq):
            try:
                self._hq = sqlite3.connect(f"file:{hq}?mode=ro", uri=True, timeout=5)
            except sqlite3.Error:
                self._hq = None

    def hq_docs(self, host):
        if not host or self._hq is None:
            return 0
        if host not in self._hq_cache:
            try:
                self._hq_cache[host] = self._hq.execute(
                    "SELECT count(*) FROM hosts h JOIN docs d ON d.id=h.doc_id WHERE h.host=? AND d.kind IN "
                    "('verdict','status','report','outcome')", (host,)).fetchone()[0]
            except sqlite3.Error:
                self._hq_cache[host] = 0
        return self._hq_cache[host]

    def in_dnr(self, host):
        if not host:
            return False
        pat = re.compile(r"(^|[^a-z0-9.-])" + re.escape(host) + r"([^a-z0-9-]|$)")
        return any(pat.search(ln) for ln in self.dnr)

    def in_submitted(self, host, rule):
        return bool(host and rule) and any(host in t and rule.lower() in t for t in self.submitted)

    def benign(self, detector, value):
        return any(p.search(detector or "") for p in self.benign_det) or any(p.search(value or "") for p in self.benign_val)


def score(rec, tags, fresh, value=""):
    cls = 1.0
    rule = rec["rule"].lower()
    if "takeover" in tags or "takeover" in rule:
        cls = 1.5
    elif rec["tool"] in ("gitleaks", "trufflehog") and (SECRET_CLASS.search(rule) or
                                                        ("stripe" in rule and str(value).startswith("sk_live"))):
        cls = 1.5
    elif "exposure" in tags:
        cls = 1.2
    s = SEV[rec["severity"]] * cls * (1.5 if fresh else 1.0)
    if rec["dedup"]["hq_docs"] > 0:
        s *= 0.2
    return round(s, 3)


# ------------------------------------------------------------------ ingest
def _load_meta(run_dir):
    try:
        with open(os.path.join(run_dir, "meta.json"), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def audit(run_dir, job):
    """-> (ok, n_output_hosts, offending_hosts). Network jobs only; enum/secrets touch no target."""
    if job not in NET_JOBS:
        return True, 0, []
    allowed = set()
    for f in glob.glob(os.path.join(run_dir, "egress*.jsonl")):
        allowed |= {str(r.get("host") or "").lower() for r in _jsonl(f) if r.get("allowed") is True}
    seen = set()
    for f in glob.glob(os.path.join(run_dir, "nuclei*.raw")):
        seen |= {r["host"] for r in parse_nuclei(f) if r["host"]}
    for f in glob.glob(os.path.join(run_dir, "httpx*.raw")):
        seen |= {r["host"] for r in parse_httpx(f) if r["host"]}
    for f in glob.glob(os.path.join(run_dir, "katana*.raw")):
        seen |= {r["host"] for r in parse_katana(f) if r["host"]}
    bad = sorted(h for h in seen if h not in allowed)
    return not bad, len(seen), bad


def _inbox(root, program, line):
    gappend(os.path.join(root, ".claude/state/orch/INBOX.md"), line.rstrip("\n") + "\n", program, root)


def ingest(program, run_dir, root=WS_ROOT, tier=2, cfg=None):
    cfg = cfg or json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))
    run_dir = os.path.realpath(run_dir)
    meta = _load_meta(run_dir)
    job = meta.get("job") or os.path.basename(run_dir).split("-20")[0]
    vers = meta.get("versions") or {}
    od = out_dir(program, root)
    gmkdir(od, program, root)
    run_rel = os.path.relpath(run_dir, root)
    con = db_connect(root)
    now = _now()
    res = {"job": job, "leads_new": 0, "leads_seen": 0, "new_hosts": [], "audit": "", "backoff": False}

    ok, n_hosts, bad = audit(run_dir, job)
    if not ok:
        res["audit"] = f"AUDIT FAIL {len(bad)} hosts with no allowed egress row: {','.join(bad[:10])}"
        gappend(os.path.join(root, ".claude/state/hunt-loop/SCOPE-INCIDENTS.md"),
                f"\n## {_iso()} oss-bot proxy-bypass audit FAIL ({program}/{job})\n- run: `{run_rel}`\n"
                f"- hosts in tool output with no allowed egress row: {', '.join(bad)}\n"
                f"- action: global PAUSE written, run leads dropped\n", program, root)
        # harmony 2.5: literal "INCIDENT " prefix = a scope-incident latch, cleared only by `bot.py resume --ack-incident`
        gwrite(os.path.join(state_dir(root), "PAUSE"), f"INCIDENT {_iso()} audit fail {program}/{job} {run_rel}\n",
               program, root)
        _inbox(root, program, f"- [{_iso()}] **HEALTH** oss-bot PAUSED: audit fail {program}/{job}, "
                              f"{len(bad)} hosts bypassed the scope proxy. .claude/state/hunt-loop/SCOPE-INCIDENTS.md")
        render_status(program, root, con, extra=res["audit"])
        con.close()
        return res
    res["audit"] = f"AUDIT OK {n_hosts} hosts"

    dd = Dedup(program, root)
    recs, secret_vals, tagmap = [], set(), {}

    def host_fresh(h):
        if not h:
            return False
        r = con.execute("SELECT first_seen FROM hosts WHERE program=? AND host=?", (program, h)).fetchone()
        return r is None or now - r[0] < 7 * 86400

    # hosts (httpx) -> hosts.jsonl + bot.db hosts, NOT leads
    hrows, statuses = {}, []
    for f in sorted(glob.glob(os.path.join(run_dir, "httpx*.raw"))):
        for r in parse_httpx(f):
            if not r["host"] or not lib_scope.program_allows(r["host"], program, root)[0]:
                continue
            statuses.append(r["status"])
            hrows[r["url"]] = r
            prev = con.execute("SELECT 1 FROM hosts WHERE program=? AND host=?", (program, r["host"])).fetchone()
            if prev is None:
                res["new_hosts"].append(r["host"])
                con.execute("INSERT INTO hosts VALUES(?,?,?,?,1)", (program, r["host"], now, now))
            else:
                con.execute("UPDATE hosts SET last_seen=?, live=1 WHERE program=? AND host=?", (now, program, r["host"]))
    if hrows:
        hp = os.path.join(od, "hosts.jsonl")
        cur = {o.get("url"): o for o in _jsonl(hp)}
        for u, r in hrows.items():
            fs = (cur.get(u) or {}).get("first_seen") or _iso(now)
            cur[u] = {"url": u, "status": r["status"], "title": r["title"][:200], "tech": r["tech"], "first_seen": fs}
        gwrite(hp, "".join(json.dumps(v) + "\n" for v in cur.values()), program, root)

    # urls (gau, katana) -> urls.jsonl
    urls = []
    for f in sorted(glob.glob(os.path.join(run_dir, "gau*.raw"))):
        urls += [(u, "gau") for u in parse_gau(f)]
    for f in sorted(glob.glob(os.path.join(run_dir, "katana*.raw"))):
        urls += [(r["url"], "katana") for r in parse_katana(f)]
    if urls:
        up = os.path.join(od, "urls.jsonl")
        cur = {o.get("url"): o for o in _jsonl(up)}
        for u, src in urls:
            if len(cur) >= 20000:
                break
            if u not in cur and lib_scope.program_allows(u, program, root)[0]:
                cur[u] = {"url": u, "source": src}
        gwrite(up, "".join(json.dumps(v) + "\n" for v in cur.values()), program, root)
    # subfinder -> enum candidate hosts (filtered) for the next probe
    subs = set()
    for f in sorted(glob.glob(os.path.join(run_dir, "subfinder*.raw"))):
        subs |= {h for h in parse_subfinder(f) if lib_scope.program_allows(h, program, root)[0]}
    if subs:
        gwrite(os.path.join(run_dir, "enum-hosts.txt"), "".join(h + "\n" for h in sorted(subs)), program, root)

    # leads: nuclei
    for f in sorted(glob.glob(os.path.join(run_dir, "nuclei*.raw"))):
        for r in parse_nuclei(f):
            rec = make_record(program, "nuclei", vers.get("nuclei", "?"), run_rel, r["rule"], r["severity"],
                              r["host"], r["url"], None, r["evidence"], _sha1("nuclei", r["rule"], r["url"]),
                              "scope-proxy")
            recs.append((rec, r["tags"], ""))
    # leads: secrets (one lead per detector+value, occurrences counted)
    agg = {}
    for tool, parser in (("gitleaks", parse_gitleaks), ("trufflehog", parse_trufflehog)):
        for f in sorted(glob.glob(os.path.join(run_dir, f"{tool}*.raw"))):
            for s in parser(f):
                if not s["value"]:
                    continue
                secret_vals.add(s["value"])
                fp = hashlib.sha256((s["detector"] + "\x1f" + s["value"]).encode()).hexdigest()
                if fp in agg:
                    agg[fp][0]["occurrences"] += 1
                    continue
                where = os.path.relpath(s["file"], root) if os.path.isabs(s["file"]) else s["file"]
                rec = make_record(program, tool, vers.get(tool, "?"), run_rel, s["detector"], "medium", "",
                                  where, None, f"{redact(s['value'])} at {where}:{s['line']}", fp, "local")
                agg[fp] = (rec, [], s["value"])
    recs += list(agg.values())
    for f in sorted(glob.glob(os.path.join(run_dir, "semgrep*.raw"))):
        for r in parse_semgrep(f):
            where = os.path.relpath(r["file"], root) if os.path.isabs(r["file"]) else r["file"]
            rec = make_record(program, "semgrep", vers.get("semgrep", "?"), run_rel, r["rule"], r["severity"], "",
                              where, None, f"{where}:{r['line']} {r['evidence']}", _sha1("semgrep", r["rule"], where,
                                                                                        r["line"]), "local")
            recs.append((rec, [], ""))

    # scrub every secret value from every field, then dedup, score, emit
    lines, new_recs = [], []
    for rec, tags, value in recs:
        for v in secret_vals:
            if len(v) >= 6:
                for k in ("evidence", "url", "rule"):
                    if v in rec[k]:
                        rec[k] = rec[k].replace(v, redact(v))
        h = rec["host"]
        rec["dedup"] = {"hq_docs": dd.hq_docs(h), "dnr": dd.in_dnr(h), "submitted": dd.in_submitted(h, rec["rule"])}
        sup = None
        if rec["dedup"]["dnr"]:
            sup = "dnr"
        elif rec["dedup"]["submitted"]:
            sup = "submitted"
        elif rec["rule"] in dd.fp_rules:
            sup = "fp-template"
        elif rec["tool"] in ("gitleaks", "trufflehog") and dd.benign(rec["rule"], value):
            sup = "benign-secret"
        elif rec["tool"] in SECRET_TOOLS and path_context(rec["url"]):
            sup = path_context(rec["url"])
        rec["suppressed"] = sup
        rec["score"] = 0.0 if sup else score(rec, tags, host_fresh(h), value)
        prev = con.execute("SELECT fp FROM leads WHERE fp=?", (rec["fp"],)).fetchone()
        if prev:
            con.execute("UPDATE leads SET last_seen=? WHERE fp=?", (now, rec["fp"]))
            res["leads_seen"] += 1
            continue
        lines.append(emit(rec))
        new_recs.append(rec)
        con.execute("INSERT INTO leads(fp,program,tool,rule,severity,host,url,first_seen,last_seen,score,suppressed)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?)", (rec["fp"], program, rec["tool"], rec["rule"], rec["severity"],
                                                       rec["host"], rec["url"], now, now, rec["score"], sup))
    if lines:
        gappend(os.path.join(od, "leads.jsonl"), "".join(lines), program, root)
    res["leads_new"] = len(lines)

    # WAF back-off (the bot shares the hunters' egress IP)
    wb = cfg["waf_backoff"]
    st = [s for s in statuses if isinstance(s, int)]
    if len(st) >= wb["min_rows"]:
        ratio = sum(1 for s in st if s in (403, 429, 503)) / len(st)
        if ratio >= wb["ratio"]:
            res["backoff"] = True
            due = now + wb["hours"] * 3600
            for j in NET_JOBS:
                con.execute("INSERT INTO jobs(program,job,next_due) VALUES(?,?,?) ON CONFLICT(program,job) "
                            "DO UPDATE SET next_due=excluded.next_due", (program, j, due))
            _inbox(root, program, f"- [{_iso()}] **OSS-BACKOFF** {program} (WAF ratio {ratio:.2f}) network jobs "
                                  f"deferred {wb['hours']}h")
    con.commit()

    # INBOX seeds (rate-limited per program per day)
    ib = cfg["inbox"]
    want = [r for r in new_recs if not r["suppressed"] and
            (r["score"] >= ib["min_score"] or (tier == 0 and r["score"] >= ib["p0_min_score"]))]
    if want:
        qp = os.path.join(state_dir(root), "inbox-quota.json")
        try:
            quota = json.load(open(qp, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            quota = {}
        key = f"{program}|{time.strftime('%Y-%m-%d', time.gmtime())}"
        used = quota.get(key, 0)
        room = max(0, ib["per_program_per_day"] - used)
        for r in sorted(want, key=lambda x: -x["score"])[:room]:
            _inbox(root, program, f"- [{_iso()}] **OSS-SEED** {program}: {r['rule']} on {r['host'] or r['url']} "
                                  f"({r['severity']}, score {r['score']}) LEAD-only. targets/{program}/recon/oss-bot/SEEDS.md")
        if len(want) > room:
            _inbox(root, program, f"- [{_iso()}] **OSS-SEED** {program}: +{len(want) - room} more seeds over the daily "
                                  f"cap, LEAD-only. targets/{program}/recon/oss-bot/SEEDS.md")
        quota[key] = used + min(room, len(want))
        gwrite(qp, json.dumps(quota), program, root)

    render_seeds(program, root, con)
    render_status(program, root, con, extra=res["audit"])
    con.close()
    return res


def render_seeds(program, root, con):
    rows = con.execute("SELECT fp,tool,rule,severity,host,url,score,first_seen FROM leads WHERE program=? AND "
                       "state='LEAD' AND (suppressed IS NULL OR suppressed='') AND score>0 ORDER BY score DESC, "
                       "first_seen DESC LIMIT 15", (program,)).fetchall()
    out = [f"# oss-bot SEEDS - {program}", "", SEEDS_HEADER, "", f"Rendered {_iso()}. Verdict of every row: `LEAD`.", ""]
    if not rows:
        out.append("No open seeds.")
    for i, (fp, tool, rule, sev, host, url, sc, fs) in enumerate(rows, 1):
        out += [f"## {i}. {rule} on {host or url} ({sev}, score {sc})", "",
                f"- tool: {tool}; url: `{url}`; first seen {_iso(fs)}; fp `{fp[:16]}`",
                f"- mark: `scripts/oss-bot/bot.py mark {fp[:16]} fp|dupe|verified-elsewhere \"<why>\"`", "",
                "Manual gate checklist:", ""] + CHECKLIST + [""]
    gwrite(os.path.join(out_dir(program, root), "SEEDS.md"), "\n".join(out) + "\n", program, root)


def render_status(program, root, con, extra=""):
    out = [f"# oss-bot STATUS - {program}", "", f"Rendered {_iso()}. All output is LEAD-only.", ""]
    if extra:
        out += [f"Latest ingest: {extra}", ""]
    out += ["| job | last start | rc | hosts in | refused | leads new | audit | next due |", "|---|---|---|---|---|---|---|---|"]
    for job, in con.execute("SELECT DISTINCT job FROM runs WHERE program=? ORDER BY job", (program,)).fetchall():
        r = con.execute("SELECT started,rc,hosts_in,hosts_refused,leads_new,audit FROM runs WHERE program=? AND job=? "
                        "ORDER BY id DESC LIMIT 1", (program, job)).fetchone()
        nd = con.execute("SELECT next_due FROM jobs WHERE program=? AND job=?", (program, job)).fetchone()
        out.append(f"| {job} | {_iso(r[0]) if r[0] else '-'} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5] or '-'} | "
                   f"{_iso(nd[0]) if nd and nd[0] else '-'} |")
    n = con.execute("SELECT count(*), sum(CASE WHEN suppressed IS NULL THEN 1 ELSE 0 END) FROM leads WHERE program=?",
                    (program,)).fetchone()
    out += ["", f"Leads total {n[0]}, open {n[1] or 0}."]
    gwrite(os.path.join(out_dir(program, root), "STATUS.md"), "\n".join(out) + "\n", program, root)


# ------------------------------------------------------------------ selfcheck
def selfcheck(fixtures=os.path.join(HERE, "fixtures")):
    import shutil
    import tempfile
    root = tempfile.mkdtemp(prefix="oss-ingest-selfcheck-")
    try:
        pd = os.path.join(root, "targets", "px")
        os.makedirs(pd)
        with open(os.path.join(pd, "SCOPE.txt"), "w") as fh:
            fh.write("*.inscope.example\n")
        os.makedirs(os.path.join(root, ".claude/state/orch"))
        os.makedirs(os.path.join(root, ".claude/state/hunt-loop"))
        os.makedirs(os.path.join(root, "reports/drafts"))
        cfg = json.load(open(os.path.join(HERE, "config.json"), encoding="utf-8"))

        # 1. path guard
        for bad in ("reports/drafts/px/x/report.md", "reports/x.md", "targets/px/SCOPE.txt", "targets/px/recon/x.jsonl",
                    "targets/px/recon/oss-bot/../../../../reports/drafts/a.md", ".claude/state/hunt-loop/outcomes.jsonl",
                    "/tmp/x"):
            p = bad if bad.startswith("/") else os.path.join(root, bad)
            try:
                gwrite(p, "x", "px", root)
            except PathGuardError:
                continue
            raise AssertionError(f"path guard let a write through: {bad}")
        os.makedirs(state_dir(root), exist_ok=True)
        os.symlink(os.path.join(root, "reports"), os.path.join(state_dir(root), "evil"))
        try:
            gwrite(os.path.join(state_dir(root), "evil", "r.md"), "x", "px", root)
            raise AssertionError("path guard followed a symlink into reports/")
        except PathGuardError:
            pass
        for bad_prog in ("../reports", "px/../../reports", ""):
            try:
                guard(os.path.join(root, "x"), bad_prog, root)
                raise AssertionError(f"bad program accepted {bad_prog!r}")
            except PathGuardError:
                pass
        assert not os.listdir(os.path.join(root, "reports/drafts")), "something was written under reports/"

        # 2. forced LEAD: emit() refuses any other verdict or an extra/missing key
        r = make_record("px", "nuclei", "v", "run", "x", "critical", "a.inscope.example", "u", None, "e", "fp", "p")
        assert r["verdict"] == LEAD
        for tamper in ({"verdict": "CRITICAL-CANDIDATE"}, {"verdict": "lead"}, {"verdict": "".join(["LE", "AD"]) + " "}):
            t = dict(r, **tamper)
            try:
                emit(t)
                raise AssertionError(f"emit accepted {tamper}")
            except AssertionError as e:
                if "emit accepted" in str(e):
                    raise
        try:
            emit(dict(r, extra=1))
            raise AssertionError("emit accepted an extra key")
        except AssertionError as e:
            if "accepted an extra" in str(e):
                raise

        # 3. full ingest over the fixtures in a fake probe run + nuclei run + secrets run
        def mkrun(name, job, files, egress_hosts):
            d = os.path.join(out_dir("px", root), "runs", name)
            os.makedirs(d)
            json.dump({"job": job, "versions": {"nuclei": "vT"}}, open(os.path.join(d, "meta.json"), "w"))
            for src in files:
                shutil.copy(os.path.join(fixtures, src), os.path.join(d, src))
            with open(os.path.join(d, "egress.jsonl"), "w") as fh:
                for h in egress_hosts:
                    fh.write(json.dumps({"host": h, "allowed": True}) + "\n")
                fh.write(json.dumps({"host": "oos.example", "allowed": False}) + "\n")
            return d
        d1 = mkrun("probe-1", "probe", ["httpx.raw"], ["a.inscope.example", "b.inscope.example"])
        r1 = ingest("px", d1, root, cfg=cfg)
        assert r1["audit"] == "AUDIT OK 2 hosts", r1
        assert sorted(r1["new_hosts"]) == ["a.inscope.example", "b.inscope.example"], r1
        d2 = mkrun("nuclei-fast-1", "nuclei-fast", ["nuclei.raw"], ["a.inscope.example", "b.inscope.example"])
        r2 = ingest("px", d2, root, cfg=cfg, tier=0)
        assert r2["audit"].startswith("AUDIT OK") and r2["leads_new"] == 3, r2
        d3 = mkrun("secrets-1", "secrets", ["gitleaks-0.raw", "trufflehog.raw", "semgrep.raw"], [])
        r3 = ingest("px", d3, root, cfg=cfg)
        leads_txt = open(os.path.join(out_dir("px", root), "leads.jsonl")).read()
        leads = [json.loads(x) for x in leads_txt.splitlines()]
        assert {x["verdict"] for x in leads} == {LEAD}, "a non-LEAD verdict reached leads.jsonl"
        crit = [x for x in leads if x["severity"] == "critical"]
        assert crit and all(x["verdict"] == LEAD for x in crit), "critical fixture not forced to LEAD"
        assert not any("CRITICAL-CANDIDATE" in json.dumps(x.get("verdict")) for x in leads)
        # redaction: no raw secret value appears anywhere in leads.jsonl
        vals = [s["value"] for s in parse_gitleaks(os.path.join(d3, "gitleaks-0.raw"))] + \
               [s["value"] for s in parse_trufflehog(os.path.join(d3, "trufflehog.raw"))]
        assert vals and all(v not in leads_txt for v in vals), "a secret value leaked into leads.jsonl"
        aws = [x for x in leads if x["tool"] in ("gitleaks", "trufflehog") and "aws" in x["rule"].lower()]
        assert aws and aws[0]["occurrences"] == 2, [x["occurrences"] for x in aws]
        benign = [x for x in leads if x["suppressed"] == "benign-secret"]
        assert benign, "benign Google AIza / Stripe pk_ key not suppressed"
        # dedup: re-ingest of the same run emits nothing new
        r4 = ingest("px", d2, root, cfg=cfg)
        assert r4["leads_new"] == 0 and r4["leads_seen"] == 3, r4
        # 4. audit: a host in tool output with no allowed egress row -> PAUSE + incident + leads dropped
        d5 = mkrun("nuclei-fast-2", "nuclei-fast", ["nuclei.raw"], ["a.inscope.example"])
        n_before = len(open(os.path.join(out_dir("px", root), "leads.jsonl")).read().splitlines())
        r5 = ingest("px", d5, root, cfg=cfg)
        assert r5["audit"].startswith("AUDIT FAIL") and "b.inscope.example" in r5["audit"], r5
        assert open(os.path.join(state_dir(root), "PAUSE")).read().startswith("INCIDENT ")
        assert "proxy-bypass audit FAIL" in open(os.path.join(root, ".claude/state/hunt-loop/SCOPE-INCIDENTS.md")).read()
        assert "**HEALTH**" in open(os.path.join(root, ".claude/state/orch/INBOX.md")).read()
        assert len(open(os.path.join(out_dir("px", root), "leads.jsonl")).read().splitlines()) == n_before
        assert "AUDIT FAIL" in open(os.path.join(out_dir("px", root), "STATUS.md")).read()
        assert SEEDS_HEADER in open(os.path.join(out_dir("px", root), "SEEDS.md")).read()
        assert not os.listdir(os.path.join(root, "reports/drafts"))
        print(f"ingest selfcheck: PASS (path guard 7+symlink+program-name, forced-LEAD tamper x4, "
              f"{len(leads)} fixture leads all LEAD incl. critical, redaction of {len(vals)} secrets, dedup, audit-fail PAUSE)")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--selfcheck":
        selfcheck()
    elif len(a) >= 2:
        tier = int(a[a.index("--tier") + 1]) if "--tier" in a else 2
        print(json.dumps(ingest(a[0], a[1], tier=tier)))
    else:
        print(__doc__)
        sys.exit(2)
