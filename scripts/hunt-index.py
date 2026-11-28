#!/usr/bin/env python3
"""Hunt index: one queryable SQLite brain over ALL hunt data, live + HDD backups.

Indexes every text-bearing file (notes, verdicts, reports, captures, HAR,
logs, probe scripts, json) across the live workspace and every HDD backup.
Blacklist model: index everything that is not a known binary. Content-hash
dedup collapses the overlapping backup snapshots so one unique note appears
ONCE, while a `sources` table keeps every physical copy for provenance.

Skips (never a query target): decompiled-app bytecode (smali/java/kotlin app
trees) unless --include-decompiled, and true binaries (images/objects/archives).
Both skips are COUNTED and printed - no silent cap.

Query with the `hq` wrapper or raw:  sqlite3 <db> "SELECT ..."

    python3 hunt-index.py                    # live + all detected HDD backups
    python3 hunt-index.py --root DIR ...      # explicit roots only
    python3 hunt-index.py --include-decompiled  # also index smali/java app trees
    python3 hunt-index.py --selfcheck

ponytail: full rebuild each run (drops tables). Dedup keeps the db small even
with N snapshots; add mtime-incremental only if a run exceeds a few minutes.
"""
import os, re, sys, sqlite3, time, argparse, hashlib, glob, json

LIVE = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_DEFAULT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".hunt-index/hunts.db")
# HDD roots holding bug-bounty history. Globbed; missing ones are skipped.
HDD_GLOBS = [
    "/mnt/backup/workspace_backup_*",
    "/mnt/backup/backup-desktop-*/the workspace",
    "/mnt/backup/archive/workspace_old_*",
    "/mnt/backup/archive/BUG-BOUNTY_*",
    "/mnt/backup/backups/bug_bounty",
    "/mnt/backup/backups/security-research",
    "/mnt/backup/bb-backups",
]

BINARY_EXT = {
    ".png",".jpg",".jpeg",".gif",".webp",".ico",".bmp",".tif",".tiff",
    ".o",".so",".a",".rlib",".rmeta",".pyc",".pyo",".class",".dex",".jar",
    ".zip",".gz",".tar",".xz",".bz2",".7z",".rar",".zst",".lz4",
    ".pdf",".woff",".woff2",".ttf",".eot",".otf",
    ".mp4",".mov",".webm",".mkv",".avi",".mp3",".wav",".ogg",".flac",
    ".bin",".dll",".exe",".dylib",".node",".wasm",".apk",".ipa",".aab",
    ".db",".sqlite",".sqlite3",".idx",".pack",".keystore",".jks",".p12",
    ".ds_store",".pyd",".obj",".lib",".pdb",".nib",".car",
}
# Dirs pruned wholesale. VCS/build/junk always; app-decompile only when not --include-decompiled.
PRUNE_ALWAYS = {"node_modules",".git",".hunt-index","__pycache__",".gradle",
                ".venv","venv",".mypy_cache",".pytest_cache",".next",".cache",
                "System Volume Information","$RECYCLE.BIN"}
PRUNE_APP = {"smali","smali_classes2","smali_classes3","smali_classes4",
             "smali_classes5","smali_assets","res","META-INF","kotlin",
             "original","unknown","build","r"}
# THE AGENT'S OWN EXHAUST IS NOT HUNT DATA (T-271). The chat agent writes its conversation transcripts to
# .claude/state/orch/agent/sessions/ and its raw tool output to .claude/state/orch/agent/out/. Indexing
# those makes the agent its own source: measured 2026-10-28, `hunt_search("acme-corp S3 bucket")` returned
# the agent's OWN earlier run of that same search, as a "note" row, instead of the honest
# "no results: there is no targets/acme-corp". A model that reads its own transcript back as prior work
# will confirm whatever it said last time, which is the exact loop the withhold guard exists to stop.
# Matched on a path SUFFIX, not a bare directory name, because "sessions" and "out" are ordinary names
# that appear inside real target trees and must keep being indexed there.
# The WHOLE agent state tree, not an enumerated list of its subfolders. Enumerating them missed
# `subagents/`, whose reflection logs served the model's own invented "acme-corp-bucket" back to it as an
# indexed hit - the exact hallucination the withhold guard exists to refuse. Everything the agent writes
# about its own work belongs here, so prune the root and nothing under it can leak back in.
PRUNE_PATH_SUFFIXES = (
    os.path.join(".claude", "state", "orch", "agent"),
)


def _is_agent_exhaust(dirpath: str) -> bool:
    """True when this directory is the chat agent's own transcript or tool-output store."""
    norm = os.path.normpath(dirpath)
    return any(norm.endswith(sfx) or (sfx + os.sep) in (norm + os.sep) for sfx in PRUNE_PATH_SUFFIXES)


MAX_BYTES = 15 * 1024 * 1024
# Cloned/decompiled source: discoverable (hosts/URLs extracted) but NOT
# full-text-indexed by default - it is third-party code, not our hunt exhaust.
# --full-code flips this on for literal-everything grep.
CODE_EXT = {".sol",".go",".rs",".js",".ts",".tsx",".jsx",".java",".kt",".c",
    ".h",".cpp",".cc",".hpp",".cs",".rb",".php",".swift",".m",".mm",".scala",
    ".vy",".move",".cairo",".proto",".gradle",".map",".d",".lock",".min.js",
    ".smali",".kts",".pyx",".pyi",".s",".asm",".dart",".ll",".ir"}
# Hunt intelligence we DO index (whitelist). Everything else is incidental.
INTEL_EXT = {".md",".txt",".jsonl",".ndjson",".har",".log",".csv"}
JSON_OK_SEG = ("/hunts/","/evidence/","/recon/","/poc/","/reports/","/state/")
JSON_MAX = 512 * 1024     # index .json only if small (skip giant recon dumps)
EXTRACT_CAP = 500         # max hosts / URLs pulled per doc (mega-dumps blow the table)

def wanted(ext, path, size):
    if ext in INTEL_EXT:
        return True
    if ext == ".json" and size < JSON_MAX and \
       any(seg in path.replace(os.sep, "/") for seg in JSON_OK_SEG):
        return True
    return False
REQ_CAP = 5000  # max request records parsed per capture file

URL_RE  = re.compile(r"https?://[^\s\"'<>)\]}\\]+")
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
FILE_TLD = {"md","txt","py","js","ts","tsx","jsx","json","jsonl","sh","go","rs",
    "html","htm","png","jpg","jpeg","webp","gif","css","xml","yml","yaml","log",
    "csv","map","lock","cfg","ini","toml","env","bak","pdf","zip","gz","har",
    "pcap","smali","java","class","kt","c","h","o","so","rlib","rmeta","pyc","sol"}

def kind_of(path):
    b = os.path.basename(path).lower(); p = path.lower()
    if "/reports/" in p:                                   return "report"
    if b.startswith("scope"):                              return "scope"
    if "verdict" in b:                                     return "verdict"
    if "target-model" in b:                                return "model"
    if b.startswith(("status","state")):                  return "status"
    if b.endswith(".har"):                                 return "http"
    if any(k in b for k in ("poc","repro","exploit")):     return "poc"
    if "outcome-ledger" in b or "outcomes.jsonl" in b or "cycle-log" in b:
        return "outcome"
    if b.endswith(".jsonl") or "captur" in b:              return "capture"
    if b.endswith((".py",".js",".sh",".ts")):             return "script"
    if b.endswith(".log"):                                 return "log"
    return "note"

def target_of(rel):
    parts = rel.split(os.sep)
    if len(parts) > 1 and parts[0] == "targets":                        return parts[1]
    if len(parts) > 2 and parts[0] == "reports" and parts[1] in ("drafts","submitted"):
        return parts[2]
    return ""

def role_of(path, kind):
    if os.path.splitext(path)[1].lower() in CODE_EXT:            return "code"
    if kind in ("capture", "http", "log", "outcome"):           return "http"
    return "intel"

def parse_requests(body, kind):
    """Best-effort HTTP request/response records from HAR or jsonl captures.
    Yields (method, url, status). Silent on anything that is not a record."""
    b = body.lstrip()
    # HAR: one json object with log.entries[]
    if b.startswith("{") and '"entries"' in body:
        try:
            for e in json.loads(body)["log"]["entries"][:REQ_CAP]:
                req = e.get("request", {}); res = e.get("response", {})
                yield (req.get("method"), req.get("url"), res.get("status"))
            return
        except (ValueError, KeyError, TypeError):
            pass
    # jsonl / concatenated json: one record per line
    for line in body.splitlines()[:REQ_CAP]:
        line = line.strip()
        if not (line.startswith("{") and ('"url"' in line or '"uri"' in line
                or '"request"' in line or '"method"' in line)):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        req = o.get("request") if isinstance(o.get("request"), dict) else o
        url = req.get("url") or req.get("uri") or req.get("URL") or o.get("url")
        method = req.get("method") or o.get("method")
        res = o.get("response") if isinstance(o.get("response"), dict) else o
        status = (res.get("status") or res.get("status_code")
                  or res.get("statusCode") or o.get("status"))
        if url or method:
            yield (method, url, status)

def is_binary(path, sniff):
    if os.path.splitext(path)[1].lower() in BINARY_EXT:
        return True
    return b"\x00" in sniff  # null byte in head = binary

def extract(body):
    urls, hosts = set(), set()
    for m in URL_RE.finditer(body):
        u = m.group(0).rstrip(".,);'\"")
        urls.add(u[:500])
        h = re.sub(r"^https?://","",u).split("/")[0].split(":")[0].split("@")[-1]
        if h: hosts.add(h.lower())
    for m in HOST_RE.finditer(body):
        h = m.group(0).lower()
        if h.rsplit(".",1)[-1] not in FILE_TLD: hosts.add(h)
    return urls, hosts

DDL = """
DROP TABLE IF EXISTS docs; DROP TABLE IF EXISTS sources; DROP TABLE IF EXISTS requests;
DROP TABLE IF EXISTS hosts; DROP TABLE IF EXISTS urls; DROP TABLE IF EXISTS fts;
CREATE TABLE docs(
  id INTEGER PRIMARY KEY, sha TEXT UNIQUE, path TEXT, target TEXT, kind TEXT,
  role TEXT, ext TEXT, mtime REAL, size INTEGER, ncopies INTEGER DEFAULT 1, body TEXT);
CREATE TABLE sources(sha TEXT, path TEXT, root TEXT, mtime REAL);
CREATE TABLE hosts(doc_id INTEGER, host TEXT);
CREATE TABLE urls (doc_id INTEGER, url TEXT);
CREATE TABLE requests(doc_id INTEGER, target TEXT, method TEXT, host TEXT, url TEXT, status INTEGER);
CREATE VIRTUAL TABLE fts USING fts5(body, content='docs', content_rowid='id');
"""
INDEXES = """
CREATE INDEX i_docs_target ON docs(target);
CREATE INDEX i_docs_kind   ON docs(kind);
CREATE INDEX i_docs_role   ON docs(role);
CREATE INDEX i_src_sha     ON sources(sha);
CREATE INDEX i_hosts_host  ON hosts(host);
CREATE INDEX i_hosts_doc   ON hosts(doc_id);
CREATE INDEX i_urls_doc    ON urls(doc_id);
CREATE INDEX i_req_host    ON requests(host);
CREATE INDEX i_req_status  ON requests(status);
CREATE INDEX i_req_target  ON requests(target);
"""

def build(roots, db, include_decompiled=False, full_code=False, lean=False):
    prune = PRUNE_ALWAYS if include_decompiled else (PRUNE_ALWAYS | PRUNE_APP)
    os.makedirs(os.path.dirname(db), exist_ok=True)
    # Build beside the live index and swap it in at the end (2026-10-22): DROP TABLE on the live file left every
    # `hq search` / gnoc hunt_search during a multi-minute rebuild reading empty tables, i.e. a dedup check said
    # "never tested" for ground that was. Readers keep the old file until they reopen; no WAL is used here.
    final, db = db, db + ".building"
    for stale in (db, db + "-journal"):
        if os.path.exists(stale):
            os.unlink(stale)
    con = sqlite3.connect(db); con.executescript(DDL); cur = con.cursor()
    t0 = time.time()
    seen = {}                       # sha -> doc_id
    uniq = dups = skip_bin = pruned_app = nreq = skip_code = skip_other = 0
    roles = {"intel": 0, "http": 0, "code": 0}
    per_root = {}
    for root in roots:
        root = os.path.abspath(root)
        if not os.path.isdir(root): continue
        rc = 0
        for dp, dirnames, filenames in os.walk(root):
            if not include_decompiled:
                pruned_app += sum(1 for d in dirnames if d in PRUNE_APP)
            dirnames[:] = [d for d in dirnames if d not in prune]
            if _is_agent_exhaust(dp):     # T-271: never index what the agent itself wrote
                dirnames[:] = []
                continue
            for fn in filenames:
                path = os.path.join(dp, fn)
                ext = os.path.splitext(fn)[1].lower()
                # Cloned/decompiled source (.java/.smali/.sol/.js/...) is not hunt
                # data - skip before reading. --full-code overrides.
                if not full_code and ext in CODE_EXT:
                    skip_code += 1; continue
                try:
                    st = os.stat(path)
                    if st.st_size > MAX_BYTES or st.st_size == 0: continue
                    if not (full_code or wanted(ext, path, st.st_size)):
                        skip_other += 1; continue
                    with open(path, "rb") as f:
                        head = f.read(8192)
                    if is_binary(path, head): skip_bin += 1; continue
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        body = f.read()
                except OSError:
                    continue
                sha = hashlib.sha1(body.encode("utf-8","ignore")).hexdigest()
                cur.execute("INSERT INTO sources VALUES(?,?,?,?)", (sha, path, root, st.st_mtime))
                if sha in seen:
                    dups += 1
                    cur.execute("UPDATE docs SET ncopies=ncopies+1 WHERE id=?", (seen[sha],))
                    continue
                rel = os.path.relpath(path, root)
                target = target_of(rel); kind = kind_of(path)
                role = role_of(path, kind); roles[role] += 1
                fts_body = None if (role == "code" and not full_code) else body
                cur.execute(
                    "INSERT INTO docs(sha,path,target,kind,role,ext,mtime,size,body)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (sha, path, target, kind, role,
                     os.path.splitext(path)[1].lower(), st.st_mtime, st.st_size, fts_body))
                did = cur.lastrowid; seen[sha] = did; uniq += 1; rc += 1
                if fts_body is not None:
                    cur.execute("INSERT INTO fts(rowid, body) VALUES(?,?)", (did, fts_body))
                urls, hosts = extract(body)          # cap per doc: mega-dumps blow the table
                cur.executemany("INSERT INTO hosts VALUES(?,?)", ((did,h) for h in list(hosts)[:EXTRACT_CAP]))
                cur.executemany("INSERT INTO urls  VALUES(?,?)", ((did,u) for u in list(urls)[:EXTRACT_CAP]))
                if role == "http":                   # the request/response map
                    for method, url, status in parse_requests(body, kind):
                        h = (re.sub(r"^https?://","",url).split("/")[0].split("@")[-1]
                             if url else None)
                        try: status = int(status)
                        except (TypeError, ValueError): status = None
                        cur.execute("INSERT INTO requests VALUES(?,?,?,?,?,?)",
                                    (did, target, method, h, url, status)); nreq += 1
                if uniq % 4000 == 0:
                    con.commit(); print(f"  {uniq} unique docs...", file=sys.stderr)
        per_root[root] = rc
    con.executescript(INDEXES); con.commit()
    nh = con.execute("SELECT count(DISTINCT host) FROM hosts").fetchone()[0]
    nu = con.execute("SELECT count(DISTINCT url) FROM urls").fetchone()[0]
    con.close()
    os.replace(db, final)
    db = final
    dt = time.time() - t0
    print(f"\nindexed {uniq} UNIQUE docs ({dups} dedup'd copies) in {dt:.1f}s -> {db}")
    print(f"  roles: intel={roles['intel']} (full-text)  http={roles['http']} (full-text)  "
          f"code={roles['code']} ({'full-text' if full_code else 'hosts/URLs only'})")
    print(f"  {nh} distinct hosts | {nu} distinct URLs | {nreq} request/response records")
    print(f"  skipped {skip_bin} binaries, {skip_code} code/decompiled, "
          f"{skip_other} non-intel files; pruned ~{pruned_app} decompiled-app dirs")
    if not full_code:
        print("  (code bodies not full-text; run --full-code to grep inside cloned source)")
    if not include_decompiled:
        print("  (smali/java app trees pruned; run --include-decompiled to add them)")
    for r, c in per_root.items():
        print(f"  +{c:>6} new from {r}")

def selfcheck():
    import tempfile, shutil
    d = tempfile.mkdtemp()
    try:
        for snap in ("live", "backup"):                     # same md content, 2 roots
            sd = os.path.join(d, snap, "targets", "acme", "hunts")
            os.makedirs(sd)
            with open(os.path.join(sd, "VERDICT.md"), "w") as f:
                f.write("IDOR dead on https://api.acme.com/v1/users . see foo.md too.")
        # a code file (full-text off by default) + a capture (request records)
        with open(os.path.join(d,"live","targets","acme","hunts","probe.sol"), "w") as f:
            f.write("// calls https://code.acme.com/x")
        with open(os.path.join(d,"live","targets","acme","hunts","cap.jsonl"), "w") as f:
            f.write('{"method":"POST","url":"https://api.acme.com/login","status":401}\n'
                    '{"request":{"method":"GET","url":"https://api.acme.com/me"},"response":{"status":200}}\n')
        db = os.path.join(d, "t.db")
        build([os.path.join(d,"live"), os.path.join(d,"backup")], db)
        con = sqlite3.connect(db)
        assert con.execute("SELECT count(*) FROM docs WHERE kind='verdict'").fetchone()[0] == 1, "dedup failed"
        assert con.execute("SELECT ncopies FROM docs WHERE kind='verdict'").fetchone()[0] == 2, "ncopies wrong"
        assert con.execute("SELECT count(*) FROM sources").fetchone()[0] == 3, "provenance lost"
        assert con.execute("SELECT count(*) FROM hosts WHERE host='api.acme.com'").fetchone()[0] >= 1
        assert con.execute("SELECT count(*) FROM hosts WHERE host='foo.md'").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM fts WHERE fts MATCH 'idor'").fetchone()[0] == 1
        # code file: discoverable + host extracted, but NOT full-text
        # code files (.sol) are SKIPPED by default (not hunt data)
        assert con.execute("SELECT count(*) FROM docs WHERE ext='.sol'").fetchone()[0] == 0, "code should be skipped"
        assert con.execute("SELECT count(*) FROM hosts WHERE host='code.acme.com'").fetchone()[0] == 0, "code host should be absent"
        # request/response map
        r = con.execute("SELECT count(*) FROM requests").fetchone()[0]
        assert r == 2, f"requests parse wrong: {r}"
        assert con.execute("SELECT status FROM requests WHERE url LIKE '%/login'").fetchone()[0] == 401
        con.close(); print("selfcheck OK (dedup + provenance + role-tier + requests + fts)")
    finally:
        shutil.rmtree(d)

def default_roots(backups=False):
    roots = [LIVE]
    if backups:                       # HDD snapshots are heavy (18G+); opt-in only
        for g in HDD_GLOBS:
            roots += sorted(glob.glob(g))
    seen, out = set(), []
    for r in roots:
        rp = os.path.abspath(r)
        if rp not in seen and os.path.isdir(rp):
            seen.add(rp); out.append(rp)
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", action="append", default=[])
    ap.add_argument("--db", default=DB_DEFAULT)
    ap.add_argument("--include-decompiled", action="store_true")
    ap.add_argument("--full-code", action="store_true")
    ap.add_argument("--lean", action="store_true", help="(legacy) no-op; code is skipped by default")
    ap.add_argument("--backups", action="store_true",
                    help="also index HDD backup snapshots (heavy, 18G+); default is live workspace only")
    ap.add_argument("--selfcheck", action="store_true")
    a = ap.parse_args()
    if a.selfcheck:
        selfcheck()
    else:
        roots = a.root or default_roots(a.backups)
        print("roots:", *roots, sep="\n  ")
        build(roots, a.db, a.include_decompiled, a.full_code, a.lean)
