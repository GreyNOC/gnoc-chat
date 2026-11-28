#!/usr/bin/env python3
"""pipeline-sweep.py - no open finding sits untouched (SPEC-pipeline-sweep-20261021.md).

Walks every open item (HELD draft, KILL/KILL-PENDING draft, leads-queue row, reports/leads LEAD or
CANDIDATE file, rescuable archive entry), keeps a per-item escalation-ladder ledger in
.claude/state/hunt-loop/rescue-ledger.json, surfaces NEEDS / PROMOTE / EXHAUSTED-FILABLE / STALE
lines to the orch INBOX, and (only when .claude/state/orch/RESCUE-DISPATCH.enabled exists) sends ONE
opus class-hunter per run at the highest-EV untried move. An item goes quiet only at FILED or
DEAD-CONFIRMED. It never writes, gates or files a report.

    pipeline-sweep.py [sweep] [--dry-run]
    pipeline-sweep.py list [program|all]
    pipeline-sweep.py show <id>
    pipeline-sweep.py kill <id> "<the user quote>"
    pipeline-sweep.py reopen <id>
    pipeline-sweep.py chain-pack <program>
    pipeline-sweep.py selfcheck

Root override: PIPELINE_SWEEP_ROOT (selfcheck fixtures only). Stdlib + scripts/bbtools/lib_policy.
--dry-run classifies and prints; it writes NO INBOX line, NO DEAD-CONFIRMED.md, NO outcome row and
starts NO child. It does refresh the ledger/board snapshot under .claude/state (never under reports/).
"""
from __future__ import annotations

import fcntl
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

REAL_ROOT = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(REAL_ROOT, "scripts", "bbtools"))
sys.path.insert(0, os.path.join(REAL_ROOT, "scripts"))
try:
    import lib_policy  # type: ignore
except Exception:  # pragma: no cover
    try:
        from bbtools import lib_policy  # type: ignore
    except Exception:
        lib_policy = None

# --- classifier regexes, copied verbatim from scripts/learn/rescue.sh (one classifier) -----------
DEADMARK = r'KILLED|HELD|NOT[- ]SUBMIT|DO-NOT-SUBMIT|KILL-PENDING|DEAD-with|report-killer.*KILL'
RESCUABLE = (r'primitive|no terminal|capability[- ]empty|capability empty|needs? (a )?(2nd|second|third|another) '
             r'(account|session|token)|one[- ](probe|receipt)[- ]away|\bHELD\b|KILL-PENDING|timid|reachability leg|'
             r'source leg|SOURCE (leg )?missing|inference|not captured|un-?escalat|missing (the )?(write|read|burst|'
             r'terminal)|concurrent burst|sink proven')
PERMADEAD = (r'by[- ]design|duplicate|out of scope|\bOOS\b|informative[- ]confirmed|policy[- ]exclud|not (a )?'
             r'(trust|access[- ]control) boundary|risk[- ]accepted|working as intended|intended behaviou?r|'
             r'known issue|already (reported|tracked)')
DEADMARK_RE = re.compile(DEADMARK, re.I)
RESCUABLE_RE = re.compile(RESCUABLE, re.I)
PERMADEAD_RE = re.compile(PERMADEAD, re.I)

MOVES = {1: "same-defect-higher-asset", 2: "what-it-unlocks", 3: "paired-write", 4: "partner-bug",
         5: "missing-context"}
TERMINAL = {"FILED", "DEAD-CONFIRMED"}
SEV_RANK = {None: 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CROWN_RE = re.compile(r'\bATO\b|account takeover|\bRCE\b|remote code|cross-tenant|cross-user|money|payment|'
                      r'mass PII|auth(entication)? bypass|credential|privesc|privilege', re.I)
HUNTER_MAP = [
    (r'ssrf|forward[- ]proxy|open proxy', "ssrf-hunter"),
    (r'idor|bola|CWE-639', "idor-hunter"),
    (r'oauth|\boidc\b|pkce|redirect_uri|\bstate[- ](param|parameter|validation|binding|jwt)|unsigned state|open[- ]redirect|callback[- ](allowlist|url)', "oauth-hunter"),
    (r'saml|jwt', "saml-jwt-hunter"),
    (r'xss', "xss-hunter"),
    (r'race|toctou|concurren', "race-hunter"),
    (r'firewall|\bwaf\b|path[- ](traversal|normali|bypass|confusion)|dot-segment|normali[sz]|encod|x-?forwarded|trusted[- ]ips|ip[- ]allowlist', "waf-egress-hunter"),
    (r'disclos|exposure|credential|bucket|\bs3\b', "exposure-hunter"),
    (r'unauth|middleware|missing auth', "unauth-access-hunter"),
    (r'takeover|cname', "takeover-hunter"),
    (r'evm|onchain|solidity|consensus', "onchain-hunter"),
]
FALLBACK_HUNTER = "variant-agent"
H1_LIVE = {"new", "triaged", "resolved", "pending-program-review", "needs-more-info"}
H1_DEAD = {"duplicate", "not-applicable", "informative", "spam"}


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class Paths:
    def __init__(self, root: str):
        self.root = root
        hl = os.path.join(root, ".claude/state/hunt-loop")
        self.hl = hl
        self.ledger = os.path.join(hl, "rescue-ledger.json")
        self.lock = os.path.join(hl, "rescue-ledger.lock")
        self.board = os.path.join(hl, "RESCUE-BOARD.md")
        self.stop = os.path.join(hl, "STOP")
        self.noyield = os.path.join(hl, "no-yield.txt")
        self.deny = os.path.join(hl, "rescue-deny.txt")
        self.leadsq = os.path.join(hl, "leads-queue.jsonl")
        self.outcomes = os.path.join(hl, "outcomes.jsonl")
        self.handoff = os.path.join(root, "HANDOFF-CURRENT.md")
        self.myreports = os.path.join(root, ".claude/state/h1-self/my-reports.json")
        self.orch = os.path.join(root, ".claude/state/orch")
        self.inbox = os.path.join(self.orch, "INBOX.md")
        self.enable = os.path.join(self.orch, "RESCUE-DISPATCH.enabled")
        self.chain_enable = os.path.join(self.orch, "CHAIN-DISPATCH.enabled")
        self.memory = os.environ.get("PIPELINE_SWEEP_MEMORY", os.path.expanduser(
            "~/.claude/projects/-home-you-gnoc-workspace/memory"))
        self.outdir = os.path.join(root, ".claude/state/opencode")
        self.hunt_state = os.path.join(root, "scripts/hunt-state.py")
        self.secrets = os.environ.get("PIPELINE_SWEEP_SECRETS",
                                      os.path.expanduser("~/.config/gnoc/secrets.env"))

    def rel(self, p: str) -> str:
        return os.path.relpath(p, self.root)

    def abs(self, p: str) -> str:
        return p if os.path.isabs(p) else os.path.join(self.root, p)


def read(path: str, n: int = 20000) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(n)
    except OSError:
        return ""


def mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def dir_mtime(home: str) -> float:
    """Newest mtime of a regular file directly inside home (non-recursive)."""
    best = 0.0
    try:
        for e in os.scandir(home):
            if e.is_file():
                best = max(best, e.stat().st_mtime)
    except OSError:
        pass
    return best


# ---------------------------------------------------------------- discovery
def discover(P: Paths) -> dict:
    items: dict = {}

    def add(iid, **kw):
        if iid in items:
            return
        items[iid] = dict(id=iid, **kw)

    # drafts: HELD-REASON.md, or KILLPASS*/REVIEW* whose last VERDICT is KILL / KILL-PENDING
    # D103 (2026-10-26): a slug family (<fam>, <fam>-2, <fam>-5-2, ... with the base <fam> present) is ONE rescue
    # item, the newest copy by report.md mtime. build_report used to mint a new -N directory on every rerun of a
    # killed chain (program-0: six copies of h2-seam-race, six ACTIVE ladder-audit items, six Opus dispatches).
    draft_dirs = [d.rstrip("/") for d in sorted(glob.glob(os.path.join(P.root, "reports/drafts/*/*/")))]
    present = set((d.split(os.sep)[-2], d.split(os.sep)[-1]) for d in draft_dirs)
    newest = {}
    for d in draft_dirs:
        prog, slug = d.split(os.sep)[-2], d.split(os.sep)[-1]
        fam = re.sub(r"(-\d+)+$", "", slug)
        if fam != slug and (prog, fam) in present:
            rp = os.path.join(d, "report.md")
            m = mtime(rp) if os.path.isfile(rp) else mtime(d)
            cur = newest.get((prog, fam))
            if cur is None or m > cur[0]:
                newest[(prog, fam)] = (m, slug)
    for d in draft_dirs:
        prog, slug = d.split(os.sep)[-2], d.split(os.sep)[-1]
        fam = re.sub(r"(-\d+)+$", "", slug)
        if (prog, fam) in newest:
            if fam == slug:
                base_rp = os.path.join(d, "report.md")
                base_m = mtime(base_rp) if os.path.isfile(base_rp) else mtime(d)
                if base_m <= newest[(prog, fam)][0]:
                    continue   # an older base than its newest copy: the copy carries the item
            elif newest[(prog, fam)][1] != slug:
                continue       # an older -N copy
        held = os.path.join(d, "HELD-REASON.md")
        kill = None
        for f in sorted(glob.glob(os.path.join(d, "KILLPASS*.txt")) + glob.glob(os.path.join(d, "REVIEW*.txt"))):
            v = re.findall(r"VERDICT:\s*(KILL-PENDING|KILL|PASS)", read(f, 400000))
            if v and v[-1] in ("KILL", "KILL-PENDING"):
                kill = os.path.basename(f)
        # gnoc_report writes its gate verdicts as GATE-<agent>.md whose first line is the verdict (KILL / PASS / ...)
        for f in sorted(glob.glob(os.path.join(d, "GATE-*.md")), key=os.path.getmtime):
            first = read(f, 2000).strip().splitlines()[:1]
            if first and first[0].strip().upper().startswith("KILL"):
                kill = os.path.basename(f)
        if os.path.isfile(held) or kill:
            text = read(held) if os.path.isfile(held) else ""
            add(f"draft:{prog}/{slug}", program=prog, home=P.rel(d), kind="draft",
                source="HELD-REASON.md" if os.path.isfile(held) else kill,
                text=text, killfile=kill, report=read(os.path.join(d, "report.md"), 4000))

    # leads-queue.jsonl rows
    for ln in read(P.leadsq, 5_000_000).splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            row = json.loads(ln)
        except ValueError:
            continue
        prog = row.get("program", "?")
        lead = row.get("lead", "")
        h = hashlib.sha1(lead.encode()).hexdigest()[:8]
        art = row.get("artifact", "")
        home = os.path.dirname(art) if art else f"targets/{prog}"
        add(f"leadq:{prog}/{h}", program=prog, home=home, kind="leadq", source="leads-queue.jsonl",
            text=json.dumps(row), verdict=row.get("verdict", ""), cls=row.get("class", ""), lead=lead)

    # reports/leads/<prog>/(LEAD|CANDIDATE)-*.md
    for f in sorted(glob.glob(os.path.join(P.root, "reports/leads/*/LEAD-*.md")) +
                    glob.glob(os.path.join(P.root, "reports/leads/*/CANDIDATE-*.md"))):
        prog = f.split(os.sep)[-2]
        add(f"leadmd:{prog}/{os.path.basename(f)}", program=prog, home=P.rel(os.path.dirname(f)),
            kind="leadmd", source=os.path.basename(f), text=read(f))

    # archive: rescuable only; otherwise recorded once as DEAD-CONFIRMED(triager)
    for f in sorted(glob.glob(os.path.join(P.root, "reports/archive/*/*/WHY-ARCHIVED.md"))):
        d = os.path.dirname(f)
        prog, slug = d.split(os.sep)[-2], d.split(os.sep)[-1]
        body = read(f, 8000)
        rescuable = bool(RESCUABLE_RE.search(body)) and not PERMADEAD_RE.search(body)
        add(f"archive:{prog}/{slug}", program=prog, home=P.rel(d), kind="archive", source="WHY-ARCHIVED.md",
            text=body, archive_rescuable=rescuable)

    # chain items (SPEC-chain-mapper-20261021): reports/leads/<prog>/chains/<slug>/CHAIN.md
    for f in sorted(glob.glob(os.path.join(P.root, "reports/leads/*/chains/*/CHAIN.md"))):
        d = os.path.dirname(f)
        prog, slug = d.split(os.sep)[-3], d.split(os.sep)[-1]
        body = read(f, 200000)
        cls, members = parse_chain_header(body)
        add(f"chain:{prog}/{slug}", program=prog, home=P.rel(d), kind="chain", source="CHAIN.md",
            text=body, cls=cls, members=members, edges=len(re.findall(r"^\|\s*[1-5]\s*\|", body, re.M)))
    return items


def parse_chain_header(body: str) -> tuple:
    """(Class line text, [member ids]) from a CHAIN.md. Text after a '<-' marker is ignored."""
    cls, members = "", []
    m = re.search(r"^Class:\s*(.+)$", body, re.M)
    if m:
        cls = m.group(1).split("<-")[0].strip()
    m = re.search(r"^Members:\s*(.+)$", body, re.M)
    if m:
        for part in m.group(1).split("<-")[0].split(","):
            tok = part.strip().split()
            if tok:
                members.append(tok[0])
    return cls, members


# ---------------------------------------------------------------- deny set
def deny_set(P: Paths, programs) -> tuple[dict, list, list]:
    """Returns (program_deny{prog: quote}, path_deny[(prefix, quote)], id_deny[(id, quote)])."""
    prog_deny: dict = {}
    path_deny: list = []
    id_deny: list = []
    for ln in read(P.noyield, 2_000_000).splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        tok = s.split()[0]
        prog_deny.setdefault(tok, f"no-yield.txt: {s[:160]}")
    ho = read(P.handoff, 2_000_000)
    m = re.search(r"^## 3\.(.*?)^## 4\.", ho, re.S | re.M)
    if m:
        sec = m.group(1)
        for line in sec.splitlines():
            for p in re.findall(r"(?:reports|targets)/[A-Za-z0-9_.\-/]+", line):
                parts = p.rstrip("/.").split("/")
                if parts[0] == "reports" and len(parts) >= 4:
                    pref = "/".join(parts[:4])
                elif parts[0] == "targets" and len(parts) >= 4 and parts[2] == "hunts":
                    pref = "/".join(parts[:4])
                else:
                    continue
                path_deny.append((pref, "HANDOFF-CURRENT section 3: " + line.strip()[:220]))
    for ln in read(P.deny, 2_000_000).splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        tok = s.split()[0]
        q = f"rescue-deny.txt: {s[:200]}"
        if ":" in tok and not tok.startswith(("reports/", "targets/")):
            id_deny.append((tok, q))
        else:
            path_deny.append((tok.rstrip("/"), q))
    return prog_deny, path_deny, id_deny


def path_hit(home: str, pref: str) -> bool:
    home = home.rstrip("/")
    return home == pref or home.startswith(pref + "/") or pref.startswith(home + "/")


# ---------------------------------------------------------------- severity / class
def severity_of(it: dict) -> tuple:
    blob = (it.get("report", "") + "\n" + it.get("text", ""))
    sev = None
    m = re.search(r"CVSS[^\n]{0,120}?\b(\d{1,2}\.\d)\b", blob)
    if m:
        sc = float(m.group(1))
        sev = "Critical" if sc >= 9 else "High" if sc >= 7 else "Medium" if sc >= 4 else "Low" if sc > 0 else None
    if sev is None:
        m = re.search(r"(?:Severity|CVSS)[^\n]{0,60}?\b(Critical|High|Medium|Low)\b", blob, re.I)
        if m:
            sev = m.group(1).capitalize()
    if sev is None and it.get("kind") == "leadq":
        v = it.get("verdict", "")
        sev = {"CRITICAL-CANDIDATE": "Critical", "MEDIUM-CANDIDATE": "Medium"}.get(v)
    vec = re.search(r"CVSS:[34]\.[01]/[A-Z:/]+", blob)
    if vec:
        cia = bool(re.search(r"/V?[CIA]:[LH]\b", vec.group(0)))
    else:
        cia = SEV_RANK[sev] >= 2  # no vector: a scored Medium+ claims an impact
    return sev, cia


def class_text(it: dict) -> str:
    cwe = re.search(r"^CWE:[^\n]*", it.get("report", ""), re.M)
    return " ".join([it.get("cls", ""), cwe.group(0) if cwe else "", it.get("text", "")[:6000]])


def key_text(it: dict) -> str:
    """The item's own label: class, CWE line, id slug, report title, lead sentence. Matched before prose."""
    rep = it.get("report", "")
    cwe = re.search(r"^CWE:[^\n]*", rep, re.M)
    title = re.search(r"^# [^\n]*", rep, re.M) or re.search(r"^# [^\n]*", it.get("text", ""), re.M)
    return " ".join([it.get("cls", ""), cwe.group(0) if cwe else "", it["id"].replace("-", " "),
                     title.group(0) if title else "", it.get("lead", "")])


def hunter_for(it: dict) -> str:
    if it.get("kind") == "chain" and it.get("cls"):  # a chain routes on its Class: line
        for rx, h in HUNTER_MAP:
            if re.search(rx, it["cls"], re.I):
                return h
    # pass 1 on the item's label, pass 2 on the full prose (2026-10-21 fix 5: prose words swallowed classes)
    for t in (key_text(it), class_text(it)):
        for rx, h in HUNTER_MAP:
            if re.search(rx, t, re.I):
                return h
    return FALLBACK_HUNTER


# ---------------------------------------------------------------- ladder
def item_tag(iid: str) -> str:
    """Per-item suffix for homes that several items can share (leads-queue lane dirs, reports/leads/<p>/)."""
    kind, rest = iid.split(":", 1)
    tail = rest.split("/", 1)[1] if "/" in rest else rest
    if kind == "leadmd":
        tail = re.sub(r"\.md$", "", tail)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", tail)[:120]


def ladder_name(iid: str) -> str:
    return "RESCUE-LADDER.md" if iid.split(":", 1)[0] in ("draft", "archive", "chain") else f"RESCUE-LADDER-{item_tag(iid)}.md"


def promote_name(iid: str) -> str:
    return "PROMOTE-CANDIDATE.md" if iid.split(":", 1)[0] in ("draft", "archive", "chain") else f"PROMOTE-CANDIDATE-{item_tag(iid)}.md"


def parse_ladder(P: Paths, home_abs: str, fname: str = "RESCUE-LADDER.md", n_moves: int = 5) -> dict | None:
    f = os.path.join(home_abs, fname)
    if not os.path.isfile(f):
        return None
    moves = {k: ({"status": "UNTRIED", "artifact": "-", "probes": 0, "burst": False, "note": "", "raw": ""}
                 if k <= n_moves else
                 {"status": "NA", "artifact": "-", "probes": 0, "burst": False, "note": "beyond chain length",
                  "raw": ""})
             for k in MOVES}
    recheck = None
    for ln in read(f, 200000).splitlines():
        s = ln.strip()
        rm = re.match(r"Re-check:\s*(\d{4}-\d{2}-\d{2})", s)
        if rm:
            recheck = rm.group(1)
            continue
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 6:
            continue
        mm = re.match(r"([1-5])\b", cells[0])
        if not mm:
            continue
        k = int(mm.group(1))
        status = cells[1].upper()
        art, probes_s, burst_s, note = cells[2], cells[3], cells[4], "|".join(cells[5:])
        try:
            probes = int(re.sub(r"[^0-9]", "", probes_s) or "0")
        except ValueError:
            probes = 0
        burst = burst_s.lower() in ("yes", "y", "true")
        eff = status
        if status == "TRIED-NEG":
            exists = art not in ("", "-") and (os.path.exists(P.abs(art)) or os.path.exists(os.path.join(home_abs, art)))
            if not (exists and probes >= 8 and burst):
                eff = "UNTRIED"  # SPINE 4 EMPIRICAL FLOOR / SPINE 7: no self-certified death
        elif status == "NA":
            if len(note.strip()) < 20:
                eff = "UNTRIED"
        elif status not in ("TRIED-POS", "NEEDS", "UNTRIED"):
            eff = "UNTRIED"
        moves[k] = {"status": eff, "declared": status, "artifact": art, "probes": probes, "burst": burst,
                    "note": note.strip()[:200]}
    return {"moves": moves, "recheck": recheck}


def move_label(row: dict, k) -> str:
    return f"edge-{k}" if row.get("kind") == "chain" else MOVES[int(k)]


def next_move(row: dict) -> str:
    mv = row.get("moves") or {}
    if row.get("kind") == "chain":  # walk the edges in order; the first non-TRIED-POS edge is the move
        if not mv:
            return "1 edge-1"
        for k in range(1, int(row.get("edges") or 1) + 1):
            v = mv.get(str(k)) or {}
            st = v.get("status")
            if st == "TRIED-POS":
                continue
            if st == "UNTRIED":
                return f"{k} {move_label(row, k)}"
            if st == "NEEDS":
                return f"{k} {move_label(row, k)} (NEEDS: {v.get('note', '')[:60]})"
            return "-"
        return "-"
    if not mv:
        return f"ladder-audit (no {row.get('ladder_file', 'RESCUE-LADDER.md')})"
    for k in sorted(mv, key=int):
        if mv[k]["status"] == "UNTRIED":
            return f"{k} {move_label(row, k)}"
    for k in sorted(mv, key=int):
        if mv[k]["status"] == "NEEDS":
            return f"{k} {move_label(row, k)} (NEEDS: {mv[k]['note'][:60]})"
    return "-"


# ---------------------------------------------------------------- ledger io
def load_ledger(P: Paths) -> dict:
    try:
        with open(P.ledger, encoding="utf-8") as fh:
            d = json.load(fh)
            if isinstance(d, dict):
                d.setdefault("_meta", {})
                return d
    except (OSError, ValueError):
        pass
    return {"_meta": {}}


def atomic_write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


import paid_budget  # noqa: E402  scripts/paid_budget.py: monthly ceiling + wall-clock cap


def _capped_cmd(P, cmd, mins, label):
    """Wrap a detached `claude -p` so a wall-clock cap kills it and writes a PAID-CAPPED INBOX line."""
    return [sys.executable, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "paid_budget.py"),
            "run", "--timeout", str(mins * 60), "--label", label, "--root", P.root, "--"] + cmd


def inbox_line(P: Paths, kind: str, msg: str) -> None:
    """Same format as orch-bot inbox(); one O_APPEND write (< 4KB) so it never interleaves."""
    os.makedirs(P.orch, exist_ok=True)
    new = not os.path.isfile(P.inbox)
    line = ""
    if new:
        line += "# ORCH INBOX - items the bot cannot decide (newest last). Clear a line when handled.\n\n"
    line += f"- [{iso(now_dt())}] **{kind}** {msg}\n"
    fd = os.open(P.inbox, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o664)
    try:
        os.write(fd, line.encode("utf-8")[:4000])
    finally:
        os.close(fd)


def pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


# ---------------------------------------------------------------- classification
def classify(P: Paths, items: dict, ledger: dict, now: datetime) -> None:
    progs = {it["program"] for it in items.values()}
    prog_deny, path_deny, id_deny = deny_set(P, progs)
    myrep = {}
    try:
        for r in json.load(open(P.myreports)).get("reports", []):
            myrep[str(r.get("id"))] = r
    except (OSError, ValueError, AttributeError):
        pass
    submitted = {}
    for f in glob.glob(os.path.join(P.root, "reports/submitted/*/*/SUBMITTED.md")):
        submitted[os.path.basename(os.path.dirname(f))] = P.rel(f)
    policy_cache: dict = {}
    sec_mtime = max(mtime(P.secrets), 0.0)

    for iid, it in items.items():
        row = ledger.get(iid) or {}
        row.update(id=iid, program=it["program"], home=it["home"], kind=it["kind"])
        row.setdefault("attempts", 0)
        row.setdefault("last_surfaced", {})
        row.setdefault("unfired", {})
        row.setdefault("dispatch", {})
        sev, cia = severity_of(it)
        if it["kind"] == "chain":  # a chain's severity is captured only by its PROMOTE, never parsed from prose
            sev, cia = None, False
        row["severity_captured"] = sev
        row["cia"] = cia
        row["class"] = (it.get("cls") or "").strip() or None
        row["hunter"] = hunter_for(it)
        row["crown"] = bool(CROWN_RE.search(class_text(it)))
        home_abs = P.abs(it["home"])
        dm = dir_mtime(home_abs)
        d_ts = parse_iso((row.get("dispatch") or {}).get("ts"))
        lt = max([x for x in (dm, d_ts.timestamp() if d_ts else 0.0) if x] or [0.0])
        row["last_touched"] = iso(datetime.fromtimestamp(lt, timezone.utc)) if lt else None
        prev_state = row.get("state")
        state, why = None, None

        # (FILED / triager) reconcile against my-reports.json + submitted/
        slug = iid.split("/", 1)[1] if "/" in iid else iid
        if it["kind"] in ("draft", "archive") and slug in submitted:
            state, why = "FILED", f"submitted: {submitted[slug]}"
        # chains are skipped: a CHAIN.md citing a member's H1 id must not mark the chain itself FILED
        if state is None and myrep and it["kind"] != "chain":
            hb = it.get("text", "") + "\n" + it.get("report", "")
            for f in (glob.glob(os.path.join(home_abs, "*.md")) + glob.glob(os.path.join(home_abs, "*.txt")))[:40]:
                hb += read(f, 60000)
            for rid in sorted(set(re.findall(r"\b(\d{7})\b", hb))):
                r = myrep.get(rid)
                if not r or r.get("program") not in (it["program"], it["program"].replace("_", "-")):
                    continue
                st = r.get("state", "")
                if st in H1_LIVE:
                    state, why = "FILED", f"H1 #{rid} state {st}"
                    break
                if st in H1_DEAD:
                    state, why = "DEAD-CONFIRMED", f"triager: H1 #{rid} state {st}"
        # operator deny
        if state is None:
            q = prog_deny.get(it["program"])
            if q is None:
                for i2, qq in id_deny:
                    if i2 == iid:
                        q = qq
                        break
            if q is None:
                mpath = it["home"] + ("/" + it["source"] if it["kind"] == "leadmd" else "")
                for pref, qq in path_deny:
                    if path_hit(mpath, pref):
                        q = qq
                        break
            if q is not None:
                state, why = "DEAD-CONFIRMED", f"operator: {q}"
        # triager / structural text
        if state is None:
            # Structured sources only: WHY-ARCHIVED.md here, H1 state above. HELD-REASON.md prose is the
            # operator's risk reasoning, never a verdict, so PERMADEAD is NOT applied to it (2026-10-21 fix).
            if it["kind"] == "archive" and not it.get("archive_rescuable"):
                state, why = "DEAD-CONFIRMED", "triager: WHY-ARCHIVED.md not rescuable (PERMADEAD or no depth signal)"
        # automation ban (non-terminal)
        if state is None and lib_policy is not None:
            pol = policy_cache.get(it["program"])
            if pol is None:
                try:
                    pol = lib_policy.policy(it["program"], root=P.root)
                except Exception as e:  # noqa
                    pol = {"status": "ERR", "evidence": str(e)}
                policy_cache[it["program"]] = pol
            if pol.get("status") == "BANNED":
                state, why = "SKIPPED-POLICY", f"lib_policy BANNED: {pol.get('evidence', '')[:200]}"
        # ladder
        row["ladder_file"] = ladder_name(iid)
        row["promote_file"] = promote_name(iid)
        if it["kind"] == "chain":
            n_edges = max(1, int(it.get("edges") or 0))
            row["edges"] = n_edges
            row["members"] = list(it.get("members") or [])
            lad = parse_ladder(P, home_abs, row["ladder_file"], n_moves=n_edges) if state is None else None
        else:
            lad = parse_ladder(P, home_abs, row["ladder_file"]) if state is None else None
        if state is None and it["kind"] == "chain":
            # chain walk: edges in order, stop at the first edge that is not TRIED-POS. An intermediate
            # TRIED-POS is progress, never PROMOTE. `reopened` is ignored (a refuted chain is not filable).
            if os.path.isfile(os.path.join(home_abs, row["promote_file"])):
                state, why = "PROMOTE", f"{row['promote_file']} present"
            elif lad is None:
                row["moves"] = {}
                state, why = "ACTIVE", f"no {row['ladder_file']}: first dispatch writes the edge ladder"
            else:
                row["moves"] = {str(k): v for k, v in lad["moves"].items()}
                for k in range(1, n_edges + 1):
                    st = lad["moves"][k]["status"]
                    if st == "TRIED-POS":
                        continue
                    if st == "UNTRIED":
                        state, why = "ACTIVE", f"untried edge {k}"
                    elif st == "NEEDS":
                        lt_dt = parse_iso(row.get("last_touched"))
                        fp = max(sec_mtime, mtime(os.path.join(P.root, "targets", it["program"], "ACCOUNTS.md")))
                        if prev_state == "NEEDS" and lt_dt and fp > lt_dt.timestamp():
                            state, why = "ACTIVE", "unlock fingerprint changed (ACCOUNTS.md / secrets.env newer)"
                        else:
                            state, why = "NEEDS", f"chain edge {k} needs a the user-only unlock"
                    else:  # validated TRIED-NEG or NA
                        state, why = "DEAD-CONFIRMED", f"exhausted: chain edge {k} refuted"
                    break
                else:
                    state, why = "PROMOTE", "every chain edge TRIED-POS"
        if state is None:
            if os.path.isfile(os.path.join(home_abs, row["promote_file"])):
                state, why = "PROMOTE", f"{row['promote_file']} present"
            elif lad is None:
                row["moves"] = {}
                state, why = "ACTIVE", f"no {row['ladder_file']}: first dispatch writes the ladder"
            else:
                row["moves"] = {str(k): v for k, v in lad["moves"].items()}
                sts = [v["status"] for v in lad["moves"].values()]
                rc = lad.get("recheck")
                if "TRIED-POS" in sts:
                    state, why = "PROMOTE", "ladder has a TRIED-POS row"
                elif rc and rc > now.strftime("%Y-%m-%d"):
                    state, why = "DATED", f"Re-check: {rc}"
                elif "UNTRIED" in sts:
                    state, why = "ACTIVE", f"untried move {next_move(row)}"
                elif "NEEDS" in sts:
                    lt_dt = parse_iso(row.get("last_touched"))
                    fp = max(sec_mtime, mtime(os.path.join(P.root, "targets", it["program"], "ACCOUNTS.md")))
                    if prev_state == "NEEDS" and lt_dt and fp > lt_dt.timestamp():
                        state, why = "ACTIVE", "unlock fingerprint changed (ACCOUNTS.md / secrets.env newer)"
                    else:
                        state, why = "NEEDS", "every untried move needs a the user-only unlock"
                else:  # all TRIED-NEG / NA, validated
                    if row.get("reopened") or (SEV_RANK.get(sev, 0) >= 2 and cia):
                        state, why = "EXHAUSTED-FILABLE", (f"ladder exhausted, captured {sev} with CIA impact"
                                                           if not row.get("reopened") else
                                                           "ladder exhausted, reopened by the user")
                    else:
                        state, why = "DEAD-CONFIRMED", f"exhausted: ladder exhausted, captured severity {sev or 'none'}" + ("" if cia else ", no CIA impact")
        row["state"] = state
        row["dead_reason"] = why if state == "DEAD-CONFIRMED" else None
        row["state_reason"] = why
        row["next_move"] = next_move(row) if state in ("ACTIVE", "NEEDS") else "-"
        ledger[iid] = row
    # items that vanished from disk stay in the ledger, flagged
    for iid, row in ledger.items():
        if iid != "_meta" and iid not in items:
            row["gone_from_disk"] = True
    chain_reverse_index(ledger, items)


def chain_reverse_index(ledger: dict, items: dict) -> None:
    """`chains` on member rows (computed, never maintained); `members_missing` and the oldest member
    `members_last_touched` on chain rows (the latter feeds score())."""
    for iid, row in ledger.items():
        if iid != "_meta":
            row.pop("chains", None)
    for cid, row in ledger.items():
        if cid == "_meta" or row.get("kind") != "chain" or cid not in items:
            continue
        missing, oldest = [], None
        for m in row.get("members") or []:
            mr = ledger.get(m) if m != "_meta" else None
            if not mr:
                missing.append(m)
                continue
            mr.setdefault("chains", [])
            if cid not in mr["chains"]:
                mr["chains"].append(cid)
            lt = mr.get("last_touched")
            if lt and (oldest is None or lt < oldest):
                oldest = lt
        if missing:
            row["members_missing"] = missing
        else:
            row.pop("members_missing", None)
        row["members_last_touched"] = oldest


def dead_kind(row) -> str:
    r = row.get("dead_reason") or ""
    return r.split(":", 1)[0] if r else ""


def state_label(row) -> str:
    s = row.get("state", "?")
    return f"{s}({dead_kind(row)})" if s == "DEAD-CONFIRMED" else s


# ---------------------------------------------------------------- reap + surface + dispatch
def reap(P: Paths, ledger: dict, dry: bool, out: list) -> None:
    for iid, row in ledger.items():
        if iid == "_meta":
            continue
        d = row.get("dispatch") or {}
        if not d.get("pid") or d.get("reaped"):
            continue
        if pid_alive(d["pid"]):
            continue
        lane = f"rescue-{iid}"
        found = False
        for ln in read(P.outcomes, 50_000_000).splitlines()[-5000:]:
            try:
                o = json.loads(ln)
            except ValueError:
                continue
            if o.get("lane") == lane and (o.get("ts") or "") >= d.get("ts", ""):
                found = True
        move = d.get("move", "?")
        if not found:
            out.append(f"reap {iid}: worker exited without recording -> UNFIRED fallback")
            if not dry:
                o = {"ts": iso(now_dt()), "lane": lane, "target": row["program"], "vector": f"rescue move {move}",
                     "verdict": "UNFIRED", "capability": "none", "probes": 0, "burst": False, "minutes": 0,
                     "floor": "not-met", "artifact": "none", "notes": "rescue worker exited without recording"}
                subprocess.run([sys.executable, P.hunt_state, "append-outcome"], input=json.dumps(o), text=True,
                               cwd=P.root, capture_output=True, timeout=60)
                uf = row.setdefault("unfired", {})
                uf[move] = uf.get(move, 0) + 1
                if uf[move] >= 3 and not row["last_surfaced"].get("RESCUE-STUCK-" + move):
                    inbox_line(P, "RESCUE-STUCK", f"{iid} move {move} went UNFIRED {uf[move]}x; item stays open. "
                                                  f"Home {row['home']}")
                    row["last_surfaced"]["RESCUE-STUCK-" + move] = iso(now_dt())
        if not dry:
            d["reaped"] = iso(now_dt())
    # chain-mapper map passes (SPEC-chain-mapper-20261021 C1 reap)
    for prog, ent in (ledger.get("_meta", {}).get("chain_map") or {}).items():
        if not ent.get("pid") or ent.get("reaped") or pid_alive(ent["pid"]):
            continue
        lane = f"rescue-chainmap:{prog}"
        found = False
        for ln in read(P.outcomes, 50_000_000).splitlines()[-5000:]:
            try:
                o = json.loads(ln)
            except ValueError:
                continue
            if o.get("lane") == lane and (o.get("ts") or "") >= ent.get("ts", ""):
                found = True
        if found:
            pass  # an orchestrator or the mapper itself already recorded this pass
        else:
            # chain-mapper is reasoning-only (no Bash), so the sweep records the pass on its behalf
            # from what the mapper actually wrote to disk (artifact over digest). Fallback only when
            # CHAINMAP.md was not (re)written during this pass.
            res = chainmap_result(P, prog, ent)
            if res:
                out.append(f"reap chainmap:{prog}: map pass done ({res['pairs']} pairs, {res['opened']} chains) "
                           f"-> outcome recorded by sweep")
                if not dry:
                    o = {"ts": iso(now_dt()), "lane": lane, "target": prog,
                         "vector": f"chain-map {res['pairs']} pairs, {res['opened']} chains",
                         "verdict": "UNFIRED", "capability": "none", "probes": 0, "burst": False,
                         "minutes": res["minutes"], "floor": "not-met", "artifact": res["artifact"],
                         "notes": res["notes"]}
                    ok, err = append_outcome(P, o)
                    if not ok:
                        out.append(f"reap chainmap:{prog}: outcome append FAILED: {err}")
            else:
                out.append(f"reap chainmap:{prog}: chain-mapper exited without recording -> UNFIRED fallback")
                if not dry:
                    o = {"ts": iso(now_dt()), "lane": lane, "target": prog, "vector": "chain-map",
                         "verdict": "UNFIRED", "capability": "none", "probes": 0, "burst": False, "minutes": 0,
                         "floor": "not-met", "artifact": "none",
                         "notes": "chain-mapper exited without writing CHAINMAP.md this pass"}
                    append_outcome(P, o)
        if not dry:
            ent["reaped"] = iso(now_dt())


def append_outcome(P: Paths, o: dict) -> tuple:
    """HARNESS 3a: append one outcome through scripts/hunt-state.py (validated, locked). -> (ok, err)."""
    try:
        r = subprocess.run([sys.executable, P.hunt_state, "append-outcome"], input=json.dumps(o), text=True,
                           cwd=P.root, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return False, str(e)[:200]
    return r.returncode == 0, (r.stderr or r.stdout or "").strip()[-200:]


def _md_section_rows(body: str, heading: str) -> list:
    """Data rows (not header, not separator) of the first markdown table under '## <heading>'."""
    rows, on, seen_hdr = [], False, False
    for ln in body.splitlines():
        if ln.startswith("## "):
            if on:
                break
            on = ln[3:].strip().lower().startswith(heading.lower())
            continue
        if not on or not ln.lstrip().startswith("|"):
            continue
        if re.match(r"^\s*\|[\s:|-]+\|\s*$", ln):
            continue
        if not seen_hdr:
            seen_hdr = True
            continue
        rows.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return rows


def chainmap_result(P: Paths, prog: str, ent: dict) -> dict | None:
    """What a finished chain-mapper pass produced, read from disk. None = CHAINMAP.md not written this pass."""
    t0 = parse_iso(ent.get("ts"))
    cdir = os.path.join(P.root, "reports/leads", prog, "chains")
    cm = os.path.join(cdir, "CHAINMAP.md")
    if not t0 or not os.path.isfile(cm) or mtime(cm) < t0.timestamp():
        return None
    body = read(cm, 5_000_000)
    nodes = _md_section_rows(body, "Nodes")
    pairs = _md_section_rows(body, "Pairs")
    queued = _md_section_rows(body, "Queued")
    acc = sum(1 for r in pairs if len(r) > 3 and r[3].upper().startswith("ACCEPT"))
    opened = sorted(os.path.basename(os.path.dirname(f)) for f in glob.glob(os.path.join(cdir, "*", "CHAIN.md"))
                    if mtime(f) >= t0.timestamp())
    outf = P.abs(ent.get("out") or "")
    end = max(mtime(cm), mtime(outf) if os.path.isfile(outf) else 0.0)
    minutes = max(0, round((end - t0.timestamp()) / 60))
    reason = ""
    if not opened and os.path.isfile(outf):
        m = re.search(r"no_chain_reason[`*\s]*:\s*(.+)", read(outf, 200_000))
        reason = m.group(1).strip().strip("`*")[:160] if m else ""
    notes = (f"reasoning pass, no probes; recorded by pipeline-sweep from CHAINMAP.md: {len(nodes)} nodes, "
             f"{len(pairs)} pairs ({acc} accepted), {len(opened)} opened"
             + (f" [{', '.join(opened)}]" if opened else "") + f", {len(queued)} queued"
             + (f"; no_chain_reason: {reason}" if reason else ""))
    return {"nodes": len(nodes), "pairs": len(pairs), "accepted": acc, "opened": len(opened), "slugs": opened,
            "queued": len(queued), "minutes": minutes, "artifact": P.rel(cm), "notes": notes}


def write_dead_file(P: Paths, row: dict) -> bool:
    home_abs = P.abs(row["home"])
    if not os.path.isdir(home_abs):
        return False
    f = os.path.join(home_abs, "DEAD-CONFIRMED.md")
    body = read(f, 2_000_000)
    if f"## {row['id']}" in body:
        return False
    lines = []
    if not body:
        lines.append("# DEAD-CONFIRMED (pipeline-sweep)\n\nReopen with `scripts/learn/pipeline-sweep.py reopen <id>`.\n")
    lines.append(f"\n## {row['id']}\n\n- date: {iso(now_dt())}\n- reason: {row.get('dead_reason')}\n")
    mv = row.get("moves") or {}
    if mv:
        lines.append("\n| move | status | artifact | probes | burst | note |\n|---|---|---|---|---|---|\n")
        for k in sorted(mv, key=int):
            v = mv[k]
            lines.append(f"| {k} {move_label(row, k)} | {v['status']} | {v['artifact']} | {v['probes']} | "
                         f"{'yes' if v['burst'] else 'no'} | {v['note']} |\n")
    with open(f, "a", encoding="utf-8") as fh:
        fh.write("".join(lines))
    return True


def surface(P: Paths, ledger: dict, now: datetime, dry: bool, out: list) -> None:
    def due(row, key, hours):
        last = parse_iso(row["last_surfaced"].get(key))
        return last is None or now - last >= timedelta(hours=hours)

    def emit(row, key, kind, msg):
        out.append(f"INBOX {kind}: {msg}")
        if not dry:
            inbox_line(P, kind, msg)
            row["last_surfaced"][key] = iso(now)

    stale: list = []
    for iid, row in sorted((k, v) for k, v in ledger.items() if k != "_meta"):
        if row.get("gone_from_disk"):
            continue
        s = row.get("state")
        if s == "NEEDS" and due(row, "NEEDS", 72):
            emit(row, "NEEDS", "RESCUE-NEEDS", f"{iid}: {row['next_move']} (home {row['home']})")
        elif s in ("EXHAUSTED-FILABLE", "PROMOTE") and due(row, "PROMOTE", 72):
            emit(row, "PROMOTE", "RESCUE-PROMOTE",
                 f"{iid} [{s}]: orchestrator runs the SPINE 5 ship order, then asks the user to approve. "
                 f"Never auto-file. Home {row['home']}")
        elif s == "SKIPPED-POLICY" and not row["last_surfaced"].get("SKIPPED-POLICY"):
            emit(row, "SKIPPED-POLICY", "RESCUE-SKIPPED-POLICY", f"{iid}: {row['state_reason']}")
        elif s == "DEAD-CONFIRMED":
            # a refuted chain is not a GreyNOC decision: DEAD-CONFIRMED.md only, no INBOX line
            if dead_kind(row) == "exhausted" and row.get("kind") != "chain" and not row["last_surfaced"].get("DEAD"):
                emit(row, "DEAD", "RESCUE-DEAD",
                     f"{iid} exhausted; filing a Low anyway is your call: `pipeline-sweep.py reopen {iid}`")
            if dry:
                out.append(f"would write DEAD-CONFIRMED.md section for {iid} in {row['home']}")
            elif write_dead_file(P, row):
                out.append(f"wrote DEAD-CONFIRMED.md section for {iid}")
        if s not in TERMINAL:
            lt = parse_iso(row.get("last_touched"))
            if lt and now - lt > timedelta(days=7):
                stale.append(row)
    # ONE digest line per sweep run; per-item detail lives in RESCUE-BOARD.md (2026-10-21 fix 4)
    if stale:
        by: dict = {}
        for row in stale:
            by[row.get("hunter", "?")] = by.get(row.get("hunter", "?"), 0) + 1
        brk = ", ".join(f"{n} {h.replace('-hunter', '').replace('-agent', '')}"
                        for h, n in sorted(by.items(), key=lambda x: (-x[1], x[0])))
        msg = (f"{len(stale)} open items untouched >7d ({brk}). Per-item list: "
               f".claude/state/hunt-loop/RESCUE-BOARD.md")
        out.append(f"INBOX RESCUE-STALE: {msg}")
        if not dry:
            inbox_line(P, "RESCUE-STALE", msg)


# 2026-10-21: RCE/no-click-ATO capability-uplift priority (GreyNOC). A cluster of oauth/saml/rce
# leads sat stale 9-16 days at 0 attempts while a 2/day cap fed other classes first (no class
# weighting existed). This boost is deliberately the same weight as the severity bump so it moves
# these classes forward without letting them permanently starve everything else.
PRIORITY_HUNTERS = {"oauth-hunter", "saml-jwt-hunter", "rce-hunter"}


def score(row: dict, now: datetime) -> float:
    if row.get("kind") == "chain":  # max days-untouched over its members, else a fresh chain never wins
        lt = parse_iso(row.get("members_last_touched"))
    else:
        lt = parse_iso(row.get("last_touched"))
    days = (now - lt).days if lt else 14
    return 3 * int(bool(row.get("crown"))) + 2 * int(SEV_RANK.get(row.get("severity_captured"), 0) >= 2) \
        + 2 * int(row.get("hunter") in PRIORITY_HUNTERS) \
        + min(days, 14) - row.get("attempts", 0)


def program_busy(P: Paths, prog: str, now: datetime) -> str | None:
    cands = glob.glob(os.path.join(P.hl, "LOCK*")) + glob.glob(os.path.join(P.hl, "fleet/claims/*"))
    for f in cands:
        if now.timestamp() - mtime(f) > 7200:
            continue
        if read(f, 400).strip().split()[:1] == [prog] or os.path.basename(f) == prog or prog in read(f, 400).split():
            return P.rel(f)
    return None


def build_prompt_chain(row: dict) -> str:
    home, iid, prog = row["home"], row["id"], row["program"]
    traps = set(["T-39", "T-40", "T-142", "T-149", "T-192", "T-215", "T-241", "T-246"])
    root = os.environ.get("PIPELINE_SWEEP_ROOT", REAL_ROOT)
    traps |= set(re.findall(r"\bT-\d{2,3}[a-z]?\b", read(os.path.join(root, home, "CHAIN.md"), 200000)))
    return (f"CHAIN EXPERIMENT of {iid} ({home}). Read Manual/HARNESS.md first and follow it fully, including "
            f"section 3 recording with lane id rescue-{iid}. Read {home}/CHAIN.md and every member's home it lists. "
            f"PRE-FLIGHT: re-fire each member's source leg (its own kill byte); if one no longer fires, mark every "
            f"remaining edge NA with note 'member <id> no longer fires: <artifact>' and stop. Then fire the edges "
            f"IN ORDER; edge k's precondition is edge k-1's captured output, never a hand-injected value (SPINE 4 "
            f"REACHABILITY). Write each edge's row in {home}/RESCUE-LADDER.md in the table format of "
            f"scripts/learn/SPEC-pipeline-sweep-20261021.md with 'edge' as the move name. Grind each edge to the "
            f"floor (8+ crafted probes, a burst on any single-use path, both controls) before TRIED-NEG. Stop at the "
            f"first refuted edge. If the last edge captures the terminal, write {home}/PROMOTE-CANDIDATE.md "
            f"(compound capability, member ids, artifact paths) and stop. If an edge refutation is a reusable SHAPE "
            f"(it would refute this edge type on any target), write a killrule-chain-<from-tag>-to-<to-tag>-<date>.md "
            f"memory note per HARNESS 3b; on success a winpattern-chain-... note. Do not edit any member's files or "
            f"ladder, do NOT write report.md, do NOT file, submit or comment. Scope-gate every host against "
            f"targets/{prog}/SCOPE.txt. Brief traps: {','.join(sorted(traps))}.")


def build_prompt(row: dict) -> str:
    if row.get("kind") == "chain":
        return build_prompt_chain(row)
    home, iid, prog = row["home"], row["id"], row["program"]
    lf, pf = row.get("ladder_file") or ladder_name(iid), row.get("promote_file") or promote_name(iid)
    traps = set(["T-39", "T-40", "T-142", "T-149"])
    home_text = ""
    for n in ("HELD-REASON.md",):
        home_text += read(os.path.join(REAL_ROOT, home, n), 40000)
    traps |= set(re.findall(r"\bT-\d{2,3}[a-z]?\b", home_text))
    return (f"RESCUE of {iid} ({home}). Read Manual/HARNESS.md first and follow it fully, including section 3 "
            f"recording with lane id rescue-{iid}. Read {home}/HELD-REASON.md (or the LEAD file / KILLPASS) and "
            f"{home}/{lf} if present. Step 1: write or refresh {home}/{lf} (this item's own ladder file) in the exact "
            f"table format of scripts/learn/SPEC-pipeline-sweep-20261021.md, marking moves already receipted in "
            f"the existing files (cite the artifact path). Step 2: take the FIRST UNTRIED move that is "
            f"self-provisionable (SPINE 4 order; provision accounts yourself per CLAUDE.md; a the user-only "
            f"unlock is status NEEDS with an 'Unlock:' note). Grind it to the floor (8+ crafted live probes, "
            f"30+ min, a burst on any single-use path) and record TRIED-NEG or TRIED-POS with the artifact path. "
            f"Scope-gate every host against targets/{prog}/SCOPE.txt. If you capture a terminal, write "
            f"{home}/{pf} (capability, artifact paths, the response bytes' path) and stop. Do NOT "
            f"write or edit report.md, do NOT remove HELD-REASON.md, do NOT file, submit or comment on any "
            f"platform. Brief traps: {','.join(sorted(traps))}. Before move 4 (partner-bug), read "
            f"reports/leads/{prog}/chains/CHAINMAP.md if it exists; if a chain lists this item, cite the chain id "
            f"in the move-4 note instead of re-searching for the same partner.")


# ---------------------------------------------------------------- chain items (SPEC-chain-mapper-20261021)
OPEN_EXCLUDE = {"FILED", "DEAD-CONFIRMED", "SKIPPED-POLICY"}
EXCERPT_HEAD_RE = re.compile(r"(?i)why (it|this) (is still a lead|caps|is not)|what caps|capability gate|"
                             r"what is not proven|not (a finding|shippable|fileable)|unlock")


def is_open(row: dict) -> bool:
    return row.get("state") not in OPEN_EXCLUDE and not row.get("gone_from_disk")


def primary_source(P: Paths, row: dict) -> str | None:
    """Absolute path of the item's primary source file (the chain-mapper's src_sha key), or None."""
    home = P.abs(row.get("home") or "")
    kind, iid = row.get("kind"), row.get("id", "")
    if kind == "chain":
        c = [os.path.join(home, "CHAIN.md")]
    elif kind == "draft":
        c = [os.path.join(home, "HELD-REASON.md")] + sorted(glob.glob(os.path.join(home, "KILLPASS*.txt")) +
                                                           glob.glob(os.path.join(home, "REVIEW*.txt")))
    elif kind == "leadmd":
        c = [os.path.join(home, iid.split("/", 1)[1] if "/" in iid else "")]
    elif kind == "archive":
        c = [os.path.join(home, "WHY-ARCHIVED.md")]
    elif kind == "leadq":
        c = [os.path.join(home, "STATUS.md")]
    else:
        c = []
    for f in c:
        if os.path.isfile(f):
            return f
    return None


def source_mtime(P: Paths, row: dict) -> float:
    f = primary_source(P, row)
    return mtime(f) if f else dir_mtime(P.abs(row.get("home") or ""))


def chain_rows(ledger: dict, prog: str) -> list:
    return [v for k, v in ledger.items() if k != "_meta" and v.get("program") == prog and v.get("kind") == "chain"]


def chain_due(P: Paths, ledger: dict, prog: str, now: datetime) -> bool:
    members = [v for k, v in ledger.items() if k != "_meta" and v.get("program") == prog
               and v.get("kind") != "chain" and is_open(v)]
    if len(members) < 2:
        return False
    cm = os.path.join(P.root, "reports/leads", prog, "chains", "CHAINMAP.md")
    if os.path.isfile(cm):
        cmt = mtime(cm)
        if not any(source_mtime(P, v) > cmt for v in members):
            return False
    if sum(1 for v in chain_rows(ledger, prog) if v.get("state") not in TERMINAL and not v.get("gone_from_disk")) >= 3:
        return False
    last = parse_iso(((ledger.get("_meta", {}).get("chain_map") or {}).get(prog) or {}).get("ts"))
    if last and now - last < timedelta(hours=24):
        return False
    return True


def chain_map_pick(P: Paths, ledger: dict, now: datetime) -> str | None:
    """First chain-due, not-busy program by summed member score; None unless CHAIN-DISPATCH.enabled."""
    if not os.path.isfile(P.chain_enable):
        return None
    tot: dict = {}
    for k, v in ledger.items():
        if k != "_meta" and v.get("kind") != "chain" and is_open(v):
            tot[v["program"]] = tot.get(v["program"], 0) + score(v, now)
    for prog in sorted(tot, key=lambda p: (-tot[p], p)):
        if chain_due(P, ledger, prog, now) and not program_busy(P, prog, now):
            return prog
    return None


def rescue_candidates(P: Paths, ledger: dict, now: datetime) -> list:
    act = [v for k, v in ledger.items() if k != "_meta" and v.get("state") == "ACTIVE" and not v.get("gone_from_disk")]
    if not os.path.isfile(P.chain_enable):
        act = [v for v in act if v.get("kind") != "chain"]
    act.sort(key=lambda v: (-score(v, now), v["id"]))
    return act


def _excerpt(report: str, src: str) -> str:
    parts = []
    m = re.search(r"^#{1,6}\s*Summary\s*$(.*?)(?=^#{1,6}\s|\Z)", report, re.M | re.S | re.I)
    if m and m.group(1).strip():
        parts.append(m.group(1).strip())
    for doc in (src, report):
        for hm in re.finditer(r"^(#{1,6})\s*(.+?)\s*$(.*?)(?=^#{1,6}\s|\Z)", doc, re.M | re.S):
            if EXCERPT_HEAD_RE.search(hm.group(2)) and hm.group(3).strip():
                parts.append(f"{hm.group(2)}: {hm.group(3).strip()}")
    return "\n\n".join(parts)[:1500]


def write_pack(P: Paths, ledger: dict, prog: str, items: dict | None = None) -> str:
    """Write reports/leads/<prog>/chains/PACK.json (the chain-mapper input). Read-only over all else."""
    if items is None:
        items = discover(P)
    rows = []
    for k, v in sorted(ledger.items()):
        if k == "_meta" or v.get("program") != prog or v.get("kind") == "chain" or not is_open(v):
            continue
        src = primary_source(P, v)
        raw = b""
        if src:
            try:
                with open(src, "rb") as fh:
                    raw = fh.read()
            except OSError:
                pass
        it = items.get(k) or {}
        report = read(os.path.join(P.abs(v["home"]), "report.md"), 60000) if v.get("kind") == "draft" else ""
        src_text = raw.decode("utf-8", "replace") if raw else it.get("text", "")
        title = re.search(r"^# [^\n]*", report, re.M) or re.search(r"^# [^\n]*", src_text, re.M)
        rows.append({"id": k, "kind": v.get("kind"), "state": v.get("state"), "class": v.get("class"),
                     "severity_captured": v.get("severity_captured"), "crown": v.get("crown"),
                     "next_move": v.get("next_move"), "home": v.get("home"),
                     "source_path": P.rel(src) if src else "leads-queue.jsonl",
                     "src_sha": hashlib.sha1(raw).hexdigest() if raw else None,
                     "title": (title.group(0)[2:].strip() if title else (it.get("lead") or ""))[:200],
                     "excerpt": _excerpt(report, src_text) or (it.get("lead") or "")[:1500]})
    chains = [{"id": v["id"], "state": v.get("state"), "members": v.get("members") or [],
               "next_move": v.get("next_move")} for v in sorted(chain_rows(ledger, prog), key=lambda r: r["id"])]
    notes = sorted(os.path.basename(f) for f in glob.glob(os.path.join(P.memory, "killrule-chain-*")) +
                   glob.glob(os.path.join(P.memory, "winpattern-chain-*")))
    pack = {"program": prog, "generated": iso(now_dt()), "items": rows, "existing_chains": chains,
            "memory_chain_notes": notes}
    path = os.path.join(P.root, "reports/leads", prog, "chains", "PACK.json")
    atomic_write(path, json.dumps(pack, indent=1, sort_keys=True))
    return path


def dispatch(P: Paths, ledger: dict, now: datetime, dry: bool, out: list) -> None:
    meta = ledger["_meta"]
    if not os.path.isfile(P.enable):
        out.append("dispatch: OFF (RESCUE-DISPATCH.enabled absent)")
        return
    if os.path.isfile(P.stop):
        out.append("dispatch: STOP present, nothing sent")
        return
    if dry:
        out.append("dispatch: dry-run, nothing sent")
        return
    r = subprocess.run(["pgrep", "-f", "RESCUE_ITEM="], capture_output=True, text=True)
    live = [x for x in r.stdout.split() if x.strip() and int(x) != os.getpid()]
    if live or any(pid_alive((v.get("dispatch") or {}).get("pid")) for k, v in ledger.items() if k != "_meta") \
            or any(pid_alive((e or {}).get("pid")) for e in (meta.get("chain_map") or {}).values()):
        out.append("dispatch: a rescue child is alive, nothing sent")
        return
    # chain-mapper map pass: own daily cap and own log, so it never eats a rescue slot (gated, off by default)
    if os.path.isfile(P.chain_enable):
        mcap = int(os.environ.get("CHAIN_MAP_DAILY_CAP", "1"))
        mtoday = now.strftime("%Y-%m-%d")
        if len([t for t in meta.get("chainmap_log", []) if t.startswith(mtoday)]) >= mcap:
            out.append(f"chain map: daily cap {mcap} reached")
        else:
            prog = chain_map_pick(P, ledger, now)
            if prog:
                pack = write_pack(P, ledger, prog)
                ts = iso(now)
                os.makedirs(P.outdir, exist_ok=True)
                outf = os.path.join(P.outdir, f"chainmap-{prog}-{ts}.out")
                prompt = (f"CHAIN MAP of {prog}. Read-only, do not probe. Read Manual/HARNESS.md sections 1 and 3, "
                          f"then reports/leads/{prog}/chains/PACK.json and follow your agent file. Write only under "
                          f"reports/leads/{prog}/chains/.")
                cmd = ["claude", "-p", prompt, "--agent", "chain-mapper", "--model", "opus",
                       "--permission-mode", "bypassPermissions", "--output-format", "text", "--max-turns", "40"]
                okb, _runs, bcap = paid_budget.reserve(P.root, f"chain map {prog}")
                if not okb:
                    out.append(f"dispatch: monthly paid-run cap {bcap} reached, chain map skipped")
                    return
                cmd = _capped_cmd(P, cmd, 30, f"chain map {prog}")
                env = dict(os.environ, HUNT_TARGET=prog, RESCUE_ITEM=f"chainmap:{prog}")
                with open(outf, "w") as fh:
                    p = subprocess.Popen(cmd, cwd=P.root, stdin=subprocess.DEVNULL, stdout=fh,
                                         stderr=subprocess.STDOUT, env=env, start_new_session=True)
                meta.setdefault("chain_map", {})[prog] = {"pid": p.pid, "ts": ts, "out": P.rel(outf)}
                meta.setdefault("chainmap_log", []).append(ts)
                out.append(f"dispatch: chain map {prog} -> chain-mapper (opus) pid {p.pid}, pack {P.rel(pack)}")
                return
    cap = int(os.environ.get("RESCUE_DAILY_CAP", "2"))
    today = now.strftime("%Y-%m-%d")
    log = [t for t in meta.get("dispatch_log", []) if t.startswith(today)]
    if len(log) >= cap:
        out.append(f"dispatch: daily cap {cap} reached")
        return
    act = rescue_candidates(P, ledger, now)
    for row in act:
        busy = program_busy(P, row["program"], now)
        if busy:
            key = "BUSY"
            last = parse_iso(row["last_surfaced"].get(key))
            if last is None or now - last >= timedelta(hours=24):
                inbox_line(P, "RESCUE-LIVE-SESSION", f"{row['id']} is next but {busy} holds {row['program']}; "
                                                     f"the live session should take move {row['next_move']}")
                row["last_surfaced"][key] = iso(now)
            continue
        ts = iso(now)
        os.makedirs(P.outdir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", row["id"])
        outf = os.path.join(P.outdir, f"rescue-{safe}-{ts}.out")
        cmd = ["claude", "-p", build_prompt(row), "--agent", row["hunter"], "--model", "opus",
               "--permission-mode", "bypassPermissions", "--output-format", "text", "--max-turns", "60"]
        okb, _runs, bcap = paid_budget.reserve(P.root, f"rescue {row['id']}")
        if not okb:
            out.append(f"dispatch: monthly paid-run cap {bcap} reached, rescue skipped")
            return
        cmd = _capped_cmd(P, cmd, 45, f"rescue {row['id']}")
        env = dict(os.environ, HUNT_TARGET=row["program"], RESCUE_ITEM=row["id"])
        with open(outf, "w") as fh:
            p = subprocess.Popen(cmd, cwd=P.root, stdin=subprocess.DEVNULL, stdout=fh, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        if row.get("kind") == "chain":
            k0 = row["next_move"].split()[0]
            mv = move_label(row, k0) if k0.isdigit() else "edge-1"
        else:
            mv = row["next_move"].split()[0] if row.get("moves") else "ladder-audit"
        row["dispatch"] = {"pid": p.pid, "ts": ts, "lane": f"rescue-{row['id']}", "move": mv,
                           "hunter": row["hunter"], "out": P.rel(outf)}
        row["attempts"] = row.get("attempts", 0) + 1
        meta.setdefault("dispatch_log", []).append(ts)
        out.append(f"dispatch: {row['id']} -> {row['hunter']} (opus) pid {p.pid}, out {P.rel(outf)}")
        return
    out.append("dispatch: no eligible ACTIVE item")


def board(ledger: dict, now: datetime) -> str:
    rows = [v for k, v in ledger.items() if k != "_meta" and not v.get("gone_from_disk")]
    counts: dict = {}
    for v in rows:
        counts[state_label(v)] = counts.get(state_label(v), 0) + 1
    L = [f"# RESCUE BOARD (pipeline-sweep) {iso(now)}", "",
         f"Items: {len(rows)}. Only FILED and DEAD-CONFIRMED are quiet.", "", "| state | count |", "|---|---|"]
    L += [f"| {k} | {counts[k]} |" for k in sorted(counts)]
    ch = [v for v in rows if v.get("kind") == "chain"]
    L += ["", f"Chain items: {sum(1 for v in ch if v.get('state') not in TERMINAL and v.get('state') != 'PROMOTE')} "
              f"open, {sum(1 for v in ch if v.get('state') == 'DEAD-CONFIRMED')} refuted, "
              f"{sum(1 for v in ch if v.get('state') == 'PROMOTE')} promoted"]
    L += ["", "## Open items", "", "| id | state | next move | days untouched |", "|---|---|---|---|"]
    for v in sorted(rows, key=lambda r: (r.get("state", ""), r["id"])):
        if v.get("state") in TERMINAL:
            continue
        lt = parse_iso(v.get("last_touched"))
        days = (now - lt).days if lt else "?"
        L.append(f"| {v['id']} | {state_label(v)} | {v.get('next_move', '-')} | {days} |")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- commands
def cmd_sweep(P: Paths, dry: bool) -> int:
    os.makedirs(P.hl, exist_ok=True)
    lk = open(P.lock, "a")
    try:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("busy")
        return 0
    now = now_dt()
    ledger = load_ledger(P)
    out: list = []
    items = discover(P)
    reap(P, ledger, dry, out)
    classify(P, items, ledger, now)
    if os.path.isfile(P.stop):
        out.append("STOP present: classify + surface only")
    surface(P, ledger, now, dry, out)
    dispatch(P, ledger, now, dry, out)
    ledger["_meta"].update(last_sweep=iso(now), last_sweep_dry=dry, items=len(items))
    b = board(ledger, now)
    atomic_write(P.ledger, json.dumps(ledger, indent=1, sort_keys=True))
    atomic_write(P.board, b)
    fcntl.flock(lk, fcntl.LOCK_UN)
    lk.close()
    print(("DRY-RUN " if dry else "") + f"sweep {iso(now)}: {len(items)} items")
    for o in out:
        print("  " + o)
    print(b.split("## Open items")[0].rstrip())
    return 0


def cmd_list(P: Paths, prog: str) -> int:
    led = load_ledger(P)
    rows = [v for k, v in led.items() if k != "_meta" and not v.get("gone_from_disk")]
    if prog and prog != "all":
        rows = [v for v in rows if v["program"] == prog]
    print(f"=== OPEN FINDINGS ({prog or 'all'}) - pipeline-sweep ledger, last sweep "
          f"{led['_meta'].get('last_sweep', 'never')} ===")
    counts: dict = {}
    for v in sorted(rows, key=lambda r: (r.get("state", ""), r["id"])):
        counts[state_label(v)] = counts.get(state_label(v), 0) + 1
        if v.get("state") in TERMINAL:
            continue
        print(f"- [{v['program']}] {v['id']}  {state_label(v)}  next: {v.get('next_move', '-')}")
    print("=== " + ", ".join(f"{k}={counts[k]}" for k in sorted(counts)) + f" (total {len(rows)}) ===")
    return 0


def cmd_show(P: Paths, iid: str) -> int:
    led = load_ledger(P)
    row = led.get(iid)
    if not row:
        print(f"no such id: {iid}")
        return 1
    print(f"{iid}: {state_label(row)}")
    print(json.dumps(row, indent=1, sort_keys=True))
    return 0


def cmd_kill(P: Paths, iid: str, quote: str) -> int:
    if not quote.strip():
        print("kill needs the user's quote")
        return 2
    os.makedirs(os.path.dirname(P.deny), exist_ok=True)
    with open(P.deny, "a", encoding="utf-8") as fh:
        fh.write(f"{iid}  # {iso(now_dt())} the user: \"{quote.strip()}\"\n")
    print(f"denied {iid}; next sweep marks it DEAD-CONFIRMED(operator)")
    return 0


def cmd_reopen(P: Paths, iid: str) -> int:
    lines = read(P.deny, 5_000_000).splitlines(keepends=True)
    kept = [ln for ln in lines if not (ln.strip() and ln.split()[0] == iid)]
    if len(kept) != len(lines):
        atomic_write(P.deny, "".join(kept))
        print(f"removed {iid} from rescue-deny.txt")
    led = load_ledger(P)
    row = led.get(iid)
    if not row:
        print(f"no such id in ledger: {iid} (deny entry handled if any)")
        return 0
    lk = open(P.lock, "a")
    fcntl.flock(lk, fcntl.LOCK_EX)
    led = load_ledger(P)
    row = led[iid]
    row["reopened"] = iso(now_dt())
    row["last_surfaced"].pop("DEAD", None)
    atomic_write(P.ledger, json.dumps(led, indent=1, sort_keys=True))
    fcntl.flock(lk, fcntl.LOCK_UN)
    reason = row.get("dead_reason") or ""
    print(f"reopened {iid} (was {state_label(row)}). An exhausted item now surfaces as EXHAUSTED-FILABLE.")
    if reason.startswith("operator:") and "rescue-deny.txt" not in reason:
        print(f"NOTE: the deny source is outside this tool ({reason[:120]}); edit that file to fully reopen.")
    return 0


def cmd_chain_pack(P: Paths, prog: str) -> int:
    led = load_ledger(P)
    print(write_pack(P, led, prog))
    return 0


# ---------------------------------------------------------------- selfcheck
def selfcheck() -> int:
    tmp = tempfile.mkdtemp(prefix="pipeline-sweep-fx-")
    R = tmp
    fails = []

    def w(rel, text):
        p = os.path.join(R, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(text)
        return p

    LAD_HDR = "| move | status | artifact | probes | burst | note |\n|---|---|---|---|---|---|\n"
    art = "targets/fx/hunts/l/raw/m1"
    os.makedirs(os.path.join(R, art), exist_ok=True)
    neg = lambda k: f"| {k} {MOVES[k]} | TRIED-NEG | {art} | 12 | yes | grinded |\n"
    na = lambda k: f"| {k} {MOVES[k]} | NA | - | 0 | no | nothing is keyed on the disclosed value at all |\n"
    exhausted = LAD_HDR + neg(1) + na(2) + neg(3) + neg(4) + neg(5)
    HELD = "Unlock: push the missing terminal leg (source leg).\n"
    # fixtures
    w(".claude/state/hunt-loop/no-yield.txt", "nbafx  # receipt-dead\n")
    w("HANDOFF-CURRENT.md", "## 3. DO NOT FILE\n- x -> `reports/drafts/fx/sec3/evidence/live/`\n## 4. BEST\n")
    w(".claude/state/hunt-loop/rescue-deny.txt", "# deny\n")
    w(".claude/state/h1-self/my-reports.json", json.dumps({"reports": [
        {"id": "4100001", "state": "new", "program": "fx"}, {"id": "4100002", "state": "duplicate", "program": "fx"}]}))
    w("reports/drafts/fx/active-noladder/HELD-REASON.md", HELD)
    w("reports/drafts/fx/active-noladder/report.md", "CVSS: 6.5 Medium CVSS:3.1/AV:N/C:H/I:N/A:N\nCWE: CWE-639\n")
    w("reports/drafts/nbafx/noyield/HELD-REASON.md", HELD)
    w("reports/drafts/fx/sec3/HELD-REASON.md", HELD)
    w("reports/drafts/fx/lowprobe/HELD-REASON.md", HELD)
    w("reports/drafts/fx/lowprobe/RESCUE-LADDER.md",
      LAD_HDR + f"| 1 {MOVES[1]} | TRIED-NEG | {art} | 5 | yes | too few |\n" + na(2) + neg(3) + neg(4) + neg(5))
    w("reports/drafts/fx/exlow/HELD-REASON.md", HELD)
    w("reports/drafts/fx/exlow/report.md", "CVSS: 3.1 Low\n")
    w("reports/drafts/fx/exlow/RESCUE-LADDER.md", exhausted)
    w("reports/drafts/fx/exmed/HELD-REASON.md", HELD)
    w("reports/drafts/fx/exmed/report.md", "CVSS: 5.3 Medium CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N\n")
    w("reports/drafts/fx/exmed/RESCUE-LADDER.md", exhausted)
    w("reports/drafts/fx/needs/HELD-REASON.md", HELD)
    w("reports/drafts/fx/needs/RESCUE-LADDER.md", LAD_HDR + neg(1) + na(2) + neg(3) + neg(4) +
      f"| 5 {MOVES[5]} | NEEDS | - | 0 | no | Unlock: owned GitHub account |\n")
    w("reports/drafts/fx/dated/HELD-REASON.md", HELD)
    w("reports/drafts/fx/dated/RESCUE-LADDER.md", LAD_HDR + neg(1) + "Re-check: 2999-01-01\n")
    w("reports/drafts/fx/promote/HELD-REASON.md", HELD)
    w("reports/drafts/fx/promote/PROMOTE-CANDIDATE.md", "terminal\n")
    w("reports/drafts/fx/filed/HELD-REASON.md", HELD + "Filed as " "#4100001\n")
    w("reports/drafts/fx/triagerdead/HELD-REASON.md", HELD + "see #4100002\n")
    w("reports/drafts/fx/killdraft/KILLPASS-1.txt", "rounds...\nVERDICT: KILL-PENDING\n")
    w("reports/drafts/fx/passdraft/KILLPASS-1.txt", "VERDICT: PASS\n")
    # D103 fixtures: a killed chain with two -N copies; only the newest copy is an item, the digits-only slug is not folded
    w("reports/drafts/fx/copyfam/KILLPASS-1.txt", "VERDICT: KILL\n")
    w("reports/drafts/fx/copyfam/report.md", "a\n")
    w("reports/drafts/fx/copyfam-2/KILLPASS-1.txt", "VERDICT: KILL\n")
    w("reports/drafts/fx/copyfam-2/report.md", "b\n")
    w("reports/drafts/fx/copyfam-5-2/KILLPASS-1.txt", "VERDICT: KILL\n")
    w("reports/drafts/fx/copyfam-5-2/report.md", "c\n")
    w("reports/drafts/fx/cve-2026-1234/KILLPASS-1.txt", "VERDICT: KILL\n")
    w("reports/drafts/fx/cve-2026-1234/report.md", "d\n")
    _t = __import__("time").time()
    os.utime(os.path.join(R, "reports/drafts/fx/copyfam/report.md"), (_t - 300, _t - 300))
    os.utime(os.path.join(R, "reports/drafts/fx/copyfam-5-2/report.md"), (_t - 200, _t - 200))
    os.utime(os.path.join(R, "reports/drafts/fx/copyfam-2/report.md"), (_t - 100, _t - 100))
    w("reports/drafts/fx/byd/HELD-REASON.md", "closed as by design by the triager\n")
    w("reports/submitted/" "fx/subd/SUBMITTED.md", "x\n")
    w("reports/drafts/fx/subd/HELD-REASON.md", HELD)
    w("reports/drafts/banfx/banned/HELD-REASON.md", HELD)
    w("targets/banfx/PROGRAM.md", "Rules\nAutomated scanning is prohibited on this program.\n")
    w("reports/archive/fx/arch-perm/WHY-ARCHIVED.md", "duplicate of an earlier report\n")
    w("reports/archive/fx/arch-resc/WHY-ARCHIVED.md", "primitive only, no terminal captured\n")
    w("reports/leads/fx/LEAD-one.md", "lead\n")
    # FIX 3 fixtures: a shared reports/leads/<p>/ folder; a bare RESCUE-LADDER.md there must be IGNORED
    w("reports/leads/fx/LEAD-two.md", "lead two\n")
    w("reports/leads/fx/RESCUE-LADDER.md", LAD_HDR + f"| 1 {MOVES[1]} | NEEDS | - | 0 | no | Unlock: x |\n")
    w("reports/leads/fx/RESCUE-LADDER-LEAD-two.md", exhausted)
    # FIX 5 fixture: the label says IDOR, the prose says oauth state / path; label must win
    w("reports/drafts/fx/hunterchk/HELD-REASON.md", "the oauth state of the path was odd\n")
    w("reports/drafts/fx/hunterchk/report.md", "CVSS: 6.5\nCWE: CWE-639\n# Cross-user order read\n")
    w("reports/leads/fx/notalead.md", "x\n")
    w("targets/fx/hunts/q/STATUS.md", "s\n")
    w(".claude/state/hunt-loop/leads-queue.jsonl",
      json.dumps({"program": "fx", "lead": "row one", "verdict": "LEAD", "class": "ssrf",
                  "artifact": "targets/fx/hunts/q/STATUS.md"}) + "\n" +
      json.dumps({"program": "fx", "lead": "row one", "verdict": "LEAD", "artifact": "targets/fx/hunts/q/STATUS.md"}) + "\n" +
      json.dumps({"program": "fx", "lead": "row two", "verdict": "LEAD", "artifact": "targets/fx/hunts/q/STATUS.md"}) + "\n")
    h2 = hashlib.sha1(b"row two").hexdigest()[:8]
    w(f"targets/fx/hunts/q/RESCUE-LADDER-{h2}.md", LAD_HDR + neg(1) + na(2) + neg(3) + neg(4) +
      f"| 5 {MOVES[5]} | NEEDS | - | 0 | no | Unlock: +886 phone |\n")
    # FIX 4: age three homes to 10 days so the stale digest fires
    old = __import__("time").time() - 10 * 86400
    for rel in ("reports/drafts/fx/killdraft", "reports/drafts/fx/hunterchk", "reports/drafts/fx/byd"):
        for e in os.scandir(os.path.join(R, rel)):
            os.utime(e.path, (old, old))
    # CHAIN fixtures (SPEC-chain-mapper-20261021 V1 a-j)
    def chain_md(members, cls, n):
        rows = "".join(f"| {k} | a | b | victim-click | as | vi | kill byte {k} | neg {k} |\n" for k in range(1, n + 1))
        return (f"# CHAIN: fixture\nMembers: {', '.join(members)}\nClass: {cls}\nTerminal: ATO (crown, attacktree goal G1)\n"
                f"EV: T 5 x P 0.33 x R 1.0 = 1.65\n\n| edge | from | to | satisfies | ASSUMPTION | VIOLATION | "
                f"PREDICTION (kill byte) | negative control |\n|---|---|---|---|---|---|---|---|\n{rows}\n"
                f"Rejected-as-T-246: no\nStill-a-bug (T-216): yes\n")
    pos = lambda k: f"| {k} edge | TRIED-POS | {art} | 9 | yes | edge fired, captured |\n"
    two = ["leadmd:fx/LEAD-one.md", "draft:fx/killdraft"]
    CH = "reports/leads/fx/chains"
    w(f"{CH}/ca/CHAIN.md", chain_md(two, "oauth", 2))
    w(f"{CH}/cb/CHAIN.md", chain_md(two, "ssrf", 2))
    w(f"{CH}/cb/RESCUE-LADDER.md", LAD_HDR + pos(1) + "| 2 edge | UNTRIED | - | 0 | no | |\n")
    w(f"{CH}/cc/CHAIN.md", chain_md(two, "ssrf", 2))
    w(f"{CH}/cc/RESCUE-LADDER.md", LAD_HDR + f"| 1 edge | TRIED-NEG | {art} | 9 | yes | refuted at floor |\n")
    w(f"{CH}/cd/CHAIN.md", chain_md(two, "ssrf", 2))
    w(f"{CH}/cd/RESCUE-LADDER.md", LAD_HDR + f"| 1 edge | TRIED-NEG | {art} | 3 | yes | too few |\n")
    w(f"{CH}/ce/CHAIN.md", chain_md(two, "ssrf", 2))
    w(f"{CH}/ce/RESCUE-LADDER.md", LAD_HDR + pos(1) + pos(2))
    w(f"{CH}/cf/CHAIN.md", chain_md(["leadmd:fx/LEAD-one.md", "leadmd:fx/nope.md"], "ssrf", 1))
    w("reports/leads/fy/LEAD-a.md", "# lead a\n## Why it caps\nneeds victim-click\n")
    w("reports/leads/fy/LEAD-b.md", "# lead b\n")
    w("memory/killrule-chain-header-control-to-victim-click-2026-10-21.md", "x\n")
    # the dispatch switch is ON in the fixture: dry-run must still start nothing
    w(".claude/state/orch/RESCUE-DISPATCH.enabled", "on\n")
    os.makedirs(os.path.join(R, ".claude/state/opencode"), exist_ok=True)

    before = subprocess.run(["pgrep", "-fc", "RESCUE_ITEM="], capture_output=True, text=True).stdout.strip()
    env = dict(os.environ, PIPELINE_SWEEP_ROOT=R, PIPELINE_SWEEP_SECRETS=os.path.join(R, "nosecrets"),
               PIPELINE_SWEEP_MEMORY=os.path.join(R, "memory"))
    os.environ["PIPELINE_SWEEP_MEMORY"] = os.path.join(R, "memory")  # in-process Paths(R) below
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "sweep", "--dry-run"], env=env,
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        fails.append(f"dry-run rc={r.returncode}: {r.stderr[-600:]}")
    P = Paths(R)
    led = load_ledger(P)
    expect = {
        "draft:fx/active-noladder": "ACTIVE",
        "draft:nbafx/noyield": "DEAD-CONFIRMED(operator)",
        "draft:fx/sec3": "DEAD-CONFIRMED(operator)",
        "draft:fx/lowprobe": "ACTIVE",
        "draft:fx/exlow": "DEAD-CONFIRMED(exhausted)",
        "draft:fx/exmed": "EXHAUSTED-FILABLE",
        "draft:fx/needs": "NEEDS",
        "draft:fx/dated": "DATED",
        "draft:fx/promote": "PROMOTE",
        "draft:fx/filed": "FILED",
        "draft:fx/triagerdead": "DEAD-CONFIRMED(triager)",
        "draft:fx/killdraft": "ACTIVE",
        "draft:fx/copyfam-2": "ACTIVE",            # D103: the newest copy carries the family
        "draft:fx/copyfam": "MISSING",             # D103: older base folded
        "draft:fx/copyfam-5-2": "MISSING",         # D103: older copy folded
        "draft:fx/cve-2026-1234": "ACTIVE",        # D103: digits in a slug are not a copy
        "draft:fx/byd": "ACTIVE",  # HELD prose is never a verdict (fix 2)
        "leadmd:fx/LEAD-two.md": "DEAD-CONFIRMED(exhausted)",
        "draft:fx/hunterchk": "ACTIVE",
        "draft:fx/subd": "FILED",
        "draft:banfx/banned": "SKIPPED-POLICY" if lib_policy is not None else "ACTIVE",
        "archive:fx/arch-perm": "DEAD-CONFIRMED(triager)",
        "archive:fx/arch-resc": "ACTIVE",
        "leadmd:fx/LEAD-one.md": "ACTIVE",
        "chain:fx/ca": "ACTIVE",                     # (a) no ladder
        "chain:fx/cb": "ACTIVE",                     # (b) edge1 POS, edge2 UNTRIED: progress, not PROMOTE
        "chain:fx/cc": "DEAD-CONFIRMED(exhausted)",  # (c) validated TRIED-NEG on edge 1
        "chain:fx/cd": "ACTIVE",                     # (d) 3 probes: floor holds
        "chain:fx/ce": "PROMOTE",                    # (e) every edge TRIED-POS
    }
    for iid, want in expect.items():
        got = state_label(led[iid]) if iid in led else "MISSING"
        print(f"  {'PASS' if got == want else 'FAIL'} {iid}: want {want} got {got}")
        if got != want:
            fails.append(iid)
    lq = sorted(k for k in led if k.startswith("leadq:"))
    h1 = hashlib.sha1(b"row one").hexdigest()[:8]
    a, b = led.get(f"leadq:fx/{h1}", {}), led.get(f"leadq:fx/{h2}", {})
    ok = (len(lq) == 2 and a.get("state") == "ACTIVE" and a.get("hunter") == "ssrf-hunter"
          and b.get("state") == "NEEDS" and a.get("ladder_file") != b.get("ladder_file"))
    print(f"  {'PASS' if ok else 'FAIL'} leadq: dup row deduped, 2 items in one lane dir with own ladders "
          f"({a.get('ladder_file')}={a.get('state')}, {b.get('ladder_file')}={b.get('state')})")
    ok or fails.append("leadq")
    ok = led["leadmd:fx/LEAD-one.md"]["ladder_file"] == "RESCUE-LADDER-LEAD-one.md"
    print(f"  {'PASS' if ok else 'FAIL'} shared reports/leads folder: bare RESCUE-LADDER.md ignored, per-item files used")
    ok or fails.append("sharedladder")
    ok = led["draft:fx/hunterchk"]["hunter"] == "idor-hunter"
    print(f"  {'PASS' if ok else 'FAIL'} hunter map: label (CWE-639) beats prose (oauth state/path) -> {led['draft:fx/hunterchk']['hunter']}")
    ok or fails.append("huntermap")
    for bad in ("draft:fx/passdraft", "leadmd:fx/notalead.md"):
        ok = bad not in led
        print(f"  {'PASS' if ok else 'FAIL'} not discovered: {bad}")
        ok or fails.append(bad)
    # ---- chain checks on the first dry-run ledger
    ca, cb, cc, cd = led.get("chain:fx/ca", {}), led.get("chain:fx/cb", {}), led.get("chain:fx/cc", {}), led.get("chain:fx/cd", {})
    ok = ca.get("next_move") == "1 edge-1" and ca.get("hunter") == "oauth-hunter" and ca.get("ladder_file") == "RESCUE-LADDER.md"
    print(f"  {'PASS' if ok else 'FAIL'} (a) chain no ladder -> next {ca.get('next_move')}, Class routes {ca.get('hunter')}")
    ok or fails.append("chain-a")
    ok = cb.get("next_move") == "2 edge-2"
    print(f"  {'PASS' if ok else 'FAIL'} (b) intermediate TRIED-POS -> next {cb.get('next_move')}")
    ok or fails.append("chain-b")
    ok = cc.get("dead_reason") == "exhausted: chain edge 1 refuted"
    print(f"  {'PASS' if ok else 'FAIL'} (c) dead_reason {cc.get('dead_reason')!r}")
    ok or fails.append("chain-c")
    ok = (cd.get("moves") or {}).get("1", {}).get("status") == "UNTRIED"
    print(f"  {'PASS' if ok else 'FAIL'} (d) edge TRIED-NEG with 3 probes reads UNTRIED")
    ok or fails.append("chain-d")
    mv = cb.get("moves") or {}
    ok = all(mv.get(str(k), {}).get("status") == "NA" and mv[str(k)].get("note") == "beyond chain length" for k in (3, 4, 5))
    print(f"  {'PASS' if ok else 'FAIL'} (f) rows 3-5 beyond a 2-edge chain -> NA, not UNTRIED")
    ok or fails.append("chain-f")
    one = led.get("leadmd:fx/LEAD-one.md", {})
    ok = ("chain:fx/ca" in (one.get("chains") or []) and "chain:fx/ca" in (led.get("draft:fx/killdraft", {}).get("chains") or [])
          and led.get("chain:fx/cf", {}).get("members_missing") == ["leadmd:fx/nope.md"]
          and "chains" not in led.get("draft:fx/exmed", {}) and ca.get("members") == two)
    print(f"  {'PASS' if ok else 'FAIL'} (g) reverse index: LEAD-one chains={one.get('chains')}, cf missing={led.get('chain:fx/cf', {}).get('members_missing')}")
    ok or fails.append("chain-g")
    nw = now_dt()
    kd = parse_iso(led["draft:fx/killdraft"]["last_touched"])
    want = 3 * int(bool(ca.get("crown"))) + 2 * int(SEV_RANK.get(ca.get("severity_captured"), 0) >= 2) \
        + 2 * int(ca.get("hunter") in PRIORITY_HUNTERS) + min((nw - kd).days, 14) - ca.get("attempts", 0)
    ok = ca.get("members_last_touched") == led["draft:fx/killdraft"]["last_touched"] and score(ca, nw) == want \
        and (nw - kd).days >= 9
    print(f"  {'PASS' if ok else 'FAIL'} (h) chain score uses oldest member ({ca.get('members_last_touched')}): {score(ca, nw)} == {want}")
    ok or fails.append("chain-h")
    Pf = Paths(R)
    no_chain = not any(v.get("kind") == "chain" for v in rescue_candidates(Pf, led, nw)) and chain_map_pick(Pf, led, nw) is None
    w(".claude/state/orch/CHAIN-DISPATCH.enabled", "on\n")
    armed_c = any(v.get("kind") == "chain" for v in rescue_candidates(Pf, led, nw))
    armed_p = chain_map_pick(Pf, led, nw)
    os.remove(os.path.join(R, ".claude/state/orch/CHAIN-DISPATCH.enabled"))
    ok = no_chain and armed_c and armed_p == "fy"
    print(f"  {'PASS' if ok else 'FAIL'} (i) switch absent: no chain candidate, no map pick; armed: chain candidate={armed_c}, pick={armed_p}")
    ok or fails.append("chain-i")
    j1 = chain_due(Pf, led, "fy", nw)
    j_fx = chain_due(Pf, led, "fx", nw)  # fx already holds 3+ open chain items
    cmf = w("reports/leads/fy/chains/CHAINMAP.md", "# CHAINMAP fy\n")
    fut = __import__("time").time() + 3600
    os.utime(cmf, (fut, fut))
    j2 = chain_due(Pf, led, "fy", nw)
    os.remove(cmf)
    led["_meta"]["chain_map"] = {"fy": {"pid": 0, "ts": iso(nw), "out": "x"}}
    j3 = chain_due(Pf, led, "fy", nw)
    led["_meta"].pop("chain_map")
    ok = j1 and not j2 and not j3 and not j_fx
    print(f"  {'PASS' if ok else 'FAIL'} (j) chain_due fy no CHAINMAP={j1}, CHAINMAP newer={j2}, map <24h={j3}, fx 3+ open chains={j_fx}")
    ok or fails.append("chain-j")
    os.environ["PIPELINE_SWEEP_ROOT"] = R
    pc = build_prompt(ca)
    os.environ.pop("PIPELINE_SWEEP_ROOT", None)
    pg = build_prompt(led["draft:fx/active-noladder"])
    ok = (pc.startswith("CHAIN EXPERIMENT of chain:fx/ca") and "rescue-chain:fx/ca" in pc and "T-246" in pc
          and "T-216" in pc and "chains/CHAINMAP.md" in pg and pg.startswith("RESCUE of"))
    print(f"  {'PASS' if ok else 'FAIL'} chain prompt branch + generic move-4 CHAINMAP pointer")
    ok or fails.append("chain-prompt")
    r2 = subprocess.run([sys.executable, os.path.abspath(__file__), "chain-pack", "fy"], env=env,
                        capture_output=True, text=True, timeout=60)
    try:
        pk = json.load(open(os.path.join(R, "reports/leads/fy/chains/PACK.json")))
    except (OSError, ValueError):
        pk = {}
    its = {i["id"]: i for i in pk.get("items", [])}
    ok = (r2.returncode == 0 and set(its) == {"leadmd:fy/LEAD-a.md", "leadmd:fy/LEAD-b.md"}
          and all(i.get("src_sha") for i in its.values()) and "victim-click" in its["leadmd:fy/LEAD-a.md"]["excerpt"]
          and pk.get("memory_chain_notes") == ["killrule-chain-header-control-to-victim-click-2026-10-21.md"])
    print(f"  {'PASS' if ok else 'FAIL'} chain-pack fy: {len(its)} items, src_sha + excerpt + memory notes")
    ok or fails.append("chain-pack:" + r2.stdout[-300:] + r2.stderr[-300:])
    shutil.rmtree(os.path.join(R, "reports/leads/fy/chains"), ignore_errors=True)
    ok = led["draft:fx/lowprobe"]["moves"]["1"]["status"] == "UNTRIED"
    print(f"  {'PASS' if ok else 'FAIL'} TRIED-NEG with probes 5 reads as UNTRIED")
    ok or fails.append("probes5")
    ok = not any((v.get("dispatch") or {}).get("pid") for k, v in led.items() if k != "_meta")
    after = subprocess.run(["pgrep", "-fc", "RESCUE_ITEM="], capture_output=True, text=True).stdout.strip()
    ok = ok and before == after and not glob.glob(os.path.join(R, ".claude/state/opencode/rescue-*"))
    print(f"  {'PASS' if ok else 'FAIL'} dry-run with dispatch switch ON started no claude child (pgrep {before}->{after})")
    ok or fails.append("nochild")
    ok = not os.path.exists(os.path.join(R, ".claude/state/orch/INBOX.md")) and \
        not glob.glob(os.path.join(R, "reports/**/DEAD-CONFIRMED.md"), recursive=True)
    print(f"  {'PASS' if ok else 'FAIL'} dry-run wrote no INBOX line and no DEAD-CONFIRMED.md")
    ok or fails.append("drywrites")
    # live sweep in the fixture with the dispatch switch OFF: surfaces + writes, still no child
    os.remove(os.path.join(R, ".claude/state/orch/RESCUE-DISPATCH.enabled"))
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "sweep"], env=env, capture_output=True,
                       text=True, timeout=120)
    inbox = read(os.path.join(R, ".claude/state/orch/INBOX.md"))
    ok = (r.returncode == 0 and "**RESCUE-PROMOTE** draft:fx/exmed" in inbox and "**RESCUE-NEEDS** draft:fx/needs" in inbox
          and "**RESCUE-DEAD** draft:fx/exlow" in inbox
          and "## draft:fx/exlow" in read(os.path.join(R, "reports/drafts/fx/exlow/DEAD-CONFIRMED.md"))
          and "dispatch: OFF" in r.stdout and inbox.count("**RESCUE-STALE**") == 1
          and "3 open items untouched" in inbox)
    print(f"  {'PASS' if ok else 'FAIL'} live fixture sweep (switch OFF): INBOX lines + DEAD-CONFIRMED.md, ONE stale digest, no dispatch")
    ok or fails.append("live:" + r.stdout[-400:] + r.stderr[-400:])
    dcc = read(os.path.join(R, "reports/leads/fx/chains/cc/DEAD-CONFIRMED.md"))
    ok = ("## chain:fx/cc" in dcc and "| 1 edge-1 |" in dcc and "**RESCUE-DEAD** chain:" not in inbox
          and "**RESCUE-PROMOTE** chain:fx/ce" in inbox and not os.path.exists(os.path.join(R, ".claude/state/opencode/chainmap-fy")))
    ok = ok and not glob.glob(os.path.join(R, ".claude/state/opencode/chainmap-*"))
    print(f"  {'PASS' if ok else 'FAIL'} (c/e live) refuted chain: DEAD-CONFIRMED.md, NO RESCUE-DEAD line; promoted chain: RESCUE-PROMOTE; no map pass")
    ok or fails.append("chain-live")
    ok = "Chain items: " in read(os.path.join(R, ".claude/state/hunt-loop/RESCUE-BOARD.md"))
    print(f"  {'PASS' if ok else 'FAIL'} board carries the chain count line")
    ok or fails.append("chain-board")
    n1 = inbox.count("\n- [")
    subprocess.run([sys.executable, os.path.abspath(__file__), "sweep"], env=env, capture_output=True, text=True)
    n2 = read(os.path.join(R, ".claude/state/orch/INBOX.md")).count("\n- [")
    ok = n2 == n1 + 1  # only the per-run stale digest repeats; every per-item line is deduped
    print(f"  {'PASS' if ok else 'FAIL'} second sweep adds only the stale digest ({n1} -> {n2} inbox lines)")
    ok or fails.append("dedup")
    # kill / reopen
    subprocess.run([sys.executable, os.path.abspath(__file__), "kill", "draft:fx/killdraft", "drop it"], env=env,
                   capture_output=True, text=True)
    subprocess.run([sys.executable, os.path.abspath(__file__), "sweep", "--dry-run"], env=env, capture_output=True)
    k1 = state_label(load_ledger(P)["draft:fx/killdraft"])
    subprocess.run([sys.executable, os.path.abspath(__file__), "reopen", "draft:fx/killdraft"], env=env,
                   capture_output=True, text=True)
    subprocess.run([sys.executable, os.path.abspath(__file__), "reopen", "draft:fx/exlow"], env=env,
                   capture_output=True, text=True)
    subprocess.run([sys.executable, os.path.abspath(__file__), "sweep", "--dry-run"], env=env, capture_output=True)
    led = load_ledger(P)
    k2, e2 = state_label(led["draft:fx/killdraft"]), state_label(led["draft:fx/exlow"])
    ok = k1 == "DEAD-CONFIRMED(operator)" and k2 == "ACTIVE" and e2 == "EXHAUSTED-FILABLE"
    print(f"  {'PASS' if ok else 'FAIL'} kill -> {k1}; reopen -> {k2}; reopened exhausted Low -> {e2}")
    ok or fails.append("killreopen")
    # chain-map reap: the sweep records a finished map pass itself (chain-mapper has no Bash)
    os.makedirs(os.path.join(R, "scripts"), exist_ok=True)
    shutil.copy(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hunt-state.py"),
                os.path.join(R, "scripts/hunt-state.py"))
    dp = subprocess.Popen(["true"])
    dp.wait()
    t_old = iso(now_dt() - timedelta(minutes=12))
    w("reports/leads/fy/chains/CHAINMAP.md",
      "# CHAINMAP fy   pass x   pack y\n## Nodes\n| id | state | src_sha | grants | needs | cap_quote (path) |\n"
      "|---|---|---|---|---|---|\n| leadmd:fy/LEAD-a.md | LEAD | a | g | victim-click | q |\n"
      "| leadmd:fy/LEAD-b.md | LEAD | b | victim-click | x | q |\n## Pairs considered\n"
      "| from | to | via tag/value | verdict ACCEPT/REJECT | reason |\n|---|---|---|---|---|\n"
      "| b | a | victim-click | ACCEPT | r |\n| a | b | x | REJECT | r |\n## Chain register\n"
      "| slug | opened | state (from ledger) | EV | members | outcome artifact |\n|---|---|---|---|---|---|\n"
      "| b--a | now | ACTIVE | 1.0 | a, b | - |\n## Queued (ranked, not opened this pass)\n"
      "| rank | one-line chain | EV | why not opened (cap / NEEDS edge / lower EV) |\n|---|---|---|---|\n")
    w("reports/leads/fy/chains/b--a/CHAIN.md", "# CHAIN: x\nMembers: leadmd:fy/LEAD-a.md, leadmd:fy/LEAD-b.md\n")
    w("reports/leads/fw/chains/CHAINMAP.md", "# CHAINMAP fw\n## Nodes\n| id |\n|---|\n| n1 |\n| n2 |\n"
      "## Pairs considered\n| from | to | via | verdict | reason |\n|---|---|---|---|---|\n| n1 | n2 | t | REJECT | r |\n")
    w(".claude/state/opencode/chainmap-fw.out", "- `no_chain_reason`: n1->n2 rejected, header-control cannot become victim-click\n")
    oc_before = read(os.path.join(R, ".claude/state/hunt-loop/outcomes.jsonl"), 50_000_000).count("\n")
    lr = {"_meta": {"chain_map": {
        "fy": {"pid": dp.pid, "ts": t_old, "out": "none"},
        "fw": {"pid": dp.pid, "ts": t_old, "out": ".claude/state/opencode/chainmap-fw.out"},
        "fz": {"pid": dp.pid, "ts": t_old, "out": "none"}}}}
    rout = []
    reap(Paths(R), lr, False, rout)
    new = [json.loads(x) for x in read(os.path.join(R, ".claude/state/hunt-loop/outcomes.jsonl"),
                                       50_000_000).splitlines()[oc_before:] if x.strip()]
    by = {o["lane"]: o for o in new}
    oy, ow, oz = by.get("rescue-chainmap:fy", {}), by.get("rescue-chainmap:fw", {}), by.get("rescue-chainmap:fz", {})
    ok = (len(new) == 3 and oy.get("vector") == "chain-map 2 pairs, 1 chains" and oy.get("verdict") == "UNFIRED"
          and oy.get("artifact") == "reports/leads/fy/chains/CHAINMAP.md" and "[b--a]" in oy.get("notes", "")
          and "1 accepted" in oy.get("notes", "") and oy.get("minutes", -1) >= 11
          and ow.get("vector") == "chain-map 1 pairs, 0 chains" and "header-control cannot" in ow.get("notes", "")
          and oz.get("vector") == "chain-map" and "without writing CHAINMAP.md" in oz.get("notes", "")
          and all(e.get("reaped") for e in lr["_meta"]["chain_map"].values())
          and not any("FAILED" in x for x in rout))
    print(f"  {'PASS' if ok else 'FAIL'} chain-map reap: finished pass recorded by sweep from CHAINMAP.md "
          f"({oy.get('vector')}); no_chain_reason carried; missing CHAINMAP -> fallback")
    ok or fails.append("chainmap-reap:" + json.dumps(new)[:600] + str(rout))
    # second reap is a no-op (reaped), and an already-recorded pass is not double-recorded
    n_before = len(new)
    reap(Paths(R), lr, False, [])
    lr2 = {"_meta": {"chain_map": {"fy": {"pid": dp.pid, "ts": t_old, "out": "none"}}}}
    reap(Paths(R), lr2, False, [])
    n_after = read(os.path.join(R, ".claude/state/hunt-loop/outcomes.jsonl"), 50_000_000).count("\n") - oc_before
    ok = n_after == n_before
    print(f"  {'PASS' if ok else 'FAIL'} chain-map reap is idempotent and never double-records ({n_before} -> {n_after})")
    ok or fails.append("chainmap-reap-idem")
    shutil.rmtree(tmp, ignore_errors=True)
    print("SELFCHECK " + ("PASS" if not fails else f"FAIL {fails}"))
    return 0 if not fails else 1


def main(argv) -> int:
    root = os.environ.get("PIPELINE_SWEEP_ROOT", REAL_ROOT)
    P = Paths(root)
    args = argv[1:]
    cmd = args[0] if args and not args[0].startswith("-") else "sweep"
    rest = args[1:] if args and not args[0].startswith("-") else args
    if cmd == "sweep":
        return cmd_sweep(P, "--dry-run" in rest)
    if cmd == "list":
        return cmd_list(P, rest[0] if rest else "all")
    if cmd == "show" and rest:
        return cmd_show(P, rest[0])
    if cmd == "kill" and len(rest) >= 2:
        return cmd_kill(P, rest[0], rest[1])
    if cmd == "reopen" and rest:
        return cmd_reopen(P, rest[0])
    if cmd == "chain-pack" and rest:
        return cmd_chain_pack(P, rest[0])
    if cmd == "selfcheck":
        return selfcheck()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
