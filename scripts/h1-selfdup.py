#!/usr/bin/env python3
"""h1-selfdup.py - are WE about to file something we already filed? (Manual T-244, as code)

  h1-selfdup.py <draft-dir|report.md> [--program h] [--refresh]   check one draft
  h1-selfdup.py --mine [program] [--refresh]                      list our own H1 reports
  h1-selfdup.py --sync                                            refresh the cache only

Read-only against the HackerOne Hacker API (GET /v1/hackers/me/reports and
/v1/hackers/reports/<id>), HTTP Basic with HACKERONE_HANDLE / HACKERONE_API_TOKEN from
~/.config/gnoc/secrets.env. The token is never printed.

A draft is compared with every report we filed on the SAME program, plus the local
reports/submitted/ records:
  - shared endpoint path (2+ segments, ids normalised)          strong
  - title word overlap (Jaccard >= 0.5)                          strong
  - same asset AND same CWE                                      medium
Verdict: CLEAR (exit 0), POSSIBLE (exit 2), DUPLICATE (exit 1), UNVERIFIED (exit 3, the API
could not be read: fail closed). POSSIBLE/DUPLICATE are cleared only by a SELF-DUP-OK.txt in the
draft dir naming each matched report id with a one-line reason (the user's call, never an agent's).
The result is written to <draft>/SELFDUP-auto.txt.
"""
import json
import os
import re
import sys
import time

import requests

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
API = "https://api.hackerone.com/v1/hackers"
STATE = os.path.join(WS, ".claude/state/h1-self")
LIST_CACHE = os.path.join(STATE, "my-reports.json")
DETAIL_DIR = os.path.join(STATE, "details")
LIST_TTL = 20 * 60
STOP = set("a an the of in on to via for and or with by is are from at as be into its it this that".split())


def creds():
    env = {}
    for ln in open(SECRETS, encoding="utf-8"):
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            env[k.replace("export ", "").strip()] = v.strip().strip("'\"")
    h, t = env.get("HACKERONE_HANDLE"), env.get("HACKERONE_API_TOKEN")
    if not h or not t:
        raise RuntimeError("HACKERONE_HANDLE / HACKERONE_API_TOKEN missing in secrets.env")
    return h, t


def session():
    s = requests.Session()
    s.auth = creds()
    s.headers["Accept"] = "application/json"
    return s


def get_all(s, url):
    out, url = [], url + ("&" if "?" in url else "?") + "page%5Bsize%5D=100"
    while url:
        r = s.get(url, timeout=30)
        if r.status_code != 200:
            raise RuntimeError(f"GET {url.split('?')[0]} -> HTTP {r.status_code}")
        d = r.json()
        out += d.get("data", [])
        url = (d.get("links") or {}).get("next")
    return out


def dig(obj, key):
    """First value of `key` anywhere inside a JSON:API blob."""
    if isinstance(obj, dict):
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
        for v in obj.values():
            r = dig(v, key)
            if r not in (None, ""):
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = dig(v, key)
            if r not in (None, ""):
                return r
    return None


def flatten(item):
    a = item.get("attributes", {})
    rel = item.get("relationships", {})
    return {
        "id": str(item.get("id")),
        "title": a.get("title") or "",
        "state": a.get("state") or a.get("substate") or "",
        "created_at": a.get("created_at") or "",
        "program": (dig(rel.get("program", {}), "handle") or "").lower(),
        "asset": dig(rel.get("structured_scope", {}), "asset_identifier") or "",
        "cwe": (dig(rel.get("weakness", {}), "external_id") or "").lower(),
        "weakness": dig(rel.get("weakness", {}), "name") or "",
    }


def my_reports(refresh=False):
    os.makedirs(STATE, exist_ok=True)
    try:
        cache = json.load(open(LIST_CACHE))
    except (OSError, ValueError):
        cache = {}
    if not refresh and cache and time.time() - cache.get("fetched_at", 0) < LIST_TTL:
        return cache["reports"], cache["fetched_at"]
    raw = get_all(session(), f"{API}/me/reports")
    reports = [flatten(x) for x in raw]
    with open(LIST_CACHE, "w") as f:
        json.dump({"fetched_at": time.time(), "reports": reports}, f)
    os.chmod(LIST_CACHE, 0o600)
    return reports, time.time()


def detail(s, rid, state):
    """Report body, cached; open reports are re-read after an hour, closed ones are kept."""
    os.makedirs(DETAIL_DIR, exist_ok=True)
    p = os.path.join(DETAIL_DIR, f"{rid}.json")
    closed = state in ("resolved", "duplicate", "informative", "not-applicable", "spam")
    if os.path.isfile(p) and (closed or time.time() - os.path.getmtime(p) < 3600):
        return json.load(open(p))
    r = s.get(f"{API}/reports/{rid}", timeout=30)
    if r.status_code != 200:
        return {}
    a = r.json().get("data", {}).get("attributes", {})
    d = {"vuln": a.get("vulnerability_information") or "", "impact": a.get("impact") or ""}
    with open(p, "w") as f:
        json.dump(d, f)
    os.chmod(p, 0o600)
    return d


# ---------- similarity ----------

ID_RE = re.compile(r"^(?:\d+|[0-9a-f]{8,}|[0-9a-f-]{32,36}|[A-Za-z0-9_-]{20,})$")
HOST_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.I)
PATH_RE = re.compile(r"(?<![\w.])(/[A-Za-z0-9_.~%:@!$&'()*+,;=-]+(?:/[A-Za-z0-9_.~%:@!$&'()*+,;=-]+)+)")


def paths(text):
    out = set()
    for m in PATH_RE.findall(text or ""):
        m = m.split("?")[0].rstrip("/.,);'\"`")
        segs = [("{id}" if ID_RE.match(x) else x.lower()) for x in m.split("/") if x]
        segs = [x for x in segs if x not in ("http:", "https:")]
        if len(segs) >= 2 and not all(x == "{id}" for x in segs):
            out.add("/" + "/".join(segs))
    return out


def hosts(text):
    return {h.lower() for h in HOST_RE.findall(text or "") if "." in h and not h.lower().endswith((".png", ".md", ".sh", ".log", ".txt", ".json"))}


def words(t):
    return {w for w in re.findall(r"[a-z0-9]+", (t or "").lower()) if w not in STOP and len(w) > 2}


def jaccard(a, b):
    return len(a & b) / len(a | b) if a and b else 0.0


def parse_draft(path):
    rep = path if path.endswith(".md") else os.path.join(path, "report.md")
    text = open(rep, encoding="utf-8").read()
    title = next((l[2:].strip() for l in text.splitlines() if l.startswith("# ")), "")
    hdr = {}
    for l in text.splitlines()[:12]:
        m = re.match(r"^(CVSS|Asset|CWE):\s*(.+)$", l)
        if m:
            hdr[m.group(1)] = m.group(2)
    cwe = re.search(r"CWE-(\d+)", hdr.get("CWE", ""))
    return {"file": rep, "dir": os.path.dirname(rep), "title": title, "text": text,
            "asset": hdr.get("Asset", "").split()[0] if hdr.get("Asset") else "",
            "cwe": f"cwe-{cwe.group(1)}" if cwe else ""}


def infer_program(d):
    rel = os.path.relpath(d, WS).split(os.sep)
    if rel[:2] == ["reports", "drafts"] and len(rel) > 2:
        return rel[2]
    if rel[0] == "targets" and len(rel) > 1:
        return rel[1]
    return None


def local_submitted(program):
    out = []
    root = os.path.join(WS, "reports/submitted", program)
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f in ("report.md", "SUBMITTED.md"):
                t = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
                rid = re.search(r"(?:report id|reports/)\s*#?(\d{6,})", t)
                title = next((l[2:].strip() for l in t.splitlines() if l.startswith("# ")), os.path.basename(dp))
                out.append({"id": rid.group(1) if rid else f"local:{os.path.relpath(dp, WS)}",
                            "title": title, "state": "local-submitted", "text": t})
    return out


def local_archived(program):
    """Reports we WITHDREW or archived before filing. These are invisible to every other dedup we run:
    the H1 API never saw them, reports/submitted/ does not hold them, and the public sweep cannot find an
    unfiled report. On 2026-10-28 a program-62 captcha draft reached a CLEAN submit-qaqc and a SELFDUP CLEAR
    while reports/archive/program-62/unauth-captcha-free-mail-send/ already held our own written kill for the
    same mechanism on the same host. An archived report is a decision we already paid for; surface it."""
    out = []
    for base in ("reports/archive", ".claude/worktrees/hunt-storage-system/reports/archive"):
        root = os.path.join(WS, base, program)
        if not os.path.isdir(root):
            continue
        for dp, _dn, fn in os.walk(root):
            for f in fn:
                if f in ("report.md", "WHY-ARCHIVED.md"):
                    t = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
                    title = next((l[2:].strip() for l in t.splitlines() if l.startswith("# ")),
                                 os.path.basename(dp))
                    out.append({"id": f"archived:{os.path.relpath(dp, WS)}", "title": title,
                                "state": "local-archived", "text": t})
    return out


def check(target, program=None, refresh=False):
    d = parse_draft(target)
    program = (program or infer_program(d["dir"]) or "").lower()
    if not program:
        raise SystemExit("cannot infer the program; pass --program <handle>")
    lines, hits = [], []
    try:
        reports, fetched = my_reports(refresh)
        s = session()
        mine = [r for r in reports if r["program"] == program]
        for r in mine:
            r["text"] = r["title"] + "\n" + detail(s, r["id"], r["state"]).get("vuln", "")
        src = f"H1 API, {len(reports)} of our reports ({len(mine)} on {program}), fetched {int(time.time() - fetched)}s ago"
    except Exception as e:  # fail closed: an unreadable API is not a clear
        verdict = "UNVERIFIED"
        lines = [f"SELFDUP {verdict}  {program}  {d['title'][:90]}", f"  H1 API unreadable: {e}",
                 "  fail-closed: re-run when the API answers (gnoc dupcheck <dir> --refresh)"]
        write(d, lines)
        return verdict, lines
    pool = mine + local_submitted(program) + local_archived(program)
    dpaths, dwords, dhosts = paths(d["text"]), words(d["title"]), hosts(d["text"])
    for r in pool:
        shared = sorted(dpaths & paths(r.get("text", "")))
        tj = jaccard(dwords, words(r["title"]))
        same_asset = bool(d["asset"]) and (d["asset"].lower() == (r.get("asset") or "").lower()
                                           or d["asset"].lower().lstrip("*.") in hosts(r.get("text", "")))
        same_cwe = bool(d["cwe"]) and d["cwe"] == r.get("cwe")
        strong = bool(shared) or tj >= 0.5
        medium = same_asset and same_cwe
        if strong or medium or (tj >= 0.3 and dhosts & hosts(r.get("text", ""))):
            hits.append({"id": r["id"], "title": r["title"], "state": r["state"], "level": "strong" if strong else "medium",
                         "why": "; ".join(x for x in [f"shared paths {shared[:3]}" if shared else "",
                                                      f"title overlap {tj:.2f}" if tj >= 0.3 else "",
                                                      "same asset + CWE" if medium else ""] if x)})
    merged = {}
    for h in hits:  # one row per report id, keep the strongest reason
        cur = merged.get(h["id"])
        if not cur or (h["level"] == "strong" and cur["level"] != "strong"):
            merged[h["id"]] = h
        elif h["why"] and h["why"] not in cur["why"]:
            cur["why"] += "; " + h["why"]
    hits = list(merged.values())
    ok_ids = set()
    okf = os.path.join(d["dir"], "SELF-DUP-OK.txt")
    if os.path.isfile(okf):
        ok_ids = set(re.findall(r"\b(\d{6,}|local:\S+)\b", open(okf).read()))
    open_hits = [h for h in hits if h["id"] not in ok_ids]
    verdict = ("DUPLICATE" if any(h["level"] == "strong" for h in open_hits) else
               "POSSIBLE" if open_hits else "CLEAR")
    lines = [f"SELFDUP {verdict}  {program}  {d['title'][:90]}", f"  source: {src} + reports/submitted/{program}/ + reports/archive/{program}/"]
    for h in hits:
        tag = "acknowledged" if h["id"] in ok_ids else h["level"]
        url = f"https://hackerone.com/reports/{h['id']}" if h["id"].isdigit() else h["id"]
        lines.append(f"  [{tag}] #{h['id']} {h['state']}: {h['title'][:80]}  ({h['why']})  {url}")
    if open_hits:
        lines.append("  to clear: the user writes SELF-DUP-OK.txt in the draft dir naming each id + a one-line reason")
    # ALWAYS surface our own archived decisions on this programme, even on a CLEAR. The title matcher compares
    # titles and endpoints, so it misses a sibling that shares a ROOT CAUSE under a different name: on 2026-10-28
    # this returned CLEAR for a captcha draft while reports/archive/program-62/ already held our written kill for
    # the same client-chosen-site-key mechanism on the same host. An archived report is a decision we already paid
    # for, and nothing else in the chain can see it (the H1 API never saw it, it was withdrawn before filing).
    arch = {r["id"]: r["title"] for r in local_archived(program)}
    if arch:
        lines.append(f"  NOTE  {len(arch)} archived/withdrawn report(s) exist for {program}. These are invisible to "
                     "the H1 API and to the public sweep. READ their WHY-ARCHIVED.md before filing:")
        for rid, title in sorted(arch.items()):
            lines.append(f"    - {rid}: {title[:88]}")
    write(d, lines)
    return verdict, lines


def write(d, lines):
    with open(os.path.join(d["dir"], "SELFDUP-auto.txt"), "w") as f:
        f.write(f"# {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n" + "\n".join(lines) + "\n")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    refresh = "--refresh" in argv
    argv = [a for a in argv if a != "--refresh"]
    if argv[0] == "--sync":
        reps, _ = my_reports(True)
        print(f"synced {len(reps)} of our reports")
        return 0
    if argv[0] == "--mine":
        reps, fetched = my_reports(refresh)
        prog = argv[1].lower() if len(argv) > 1 else None
        rows = [r for r in reps if not prog or r["program"] == prog]
        for r in sorted(rows, key=lambda r: r["created_at"], reverse=True):
            print(f"  #{r['id']:<9} {r['created_at'][:10]} {r['state'][:14]:<14} {r['program'][:16]:<16} {r['title'][:70]}")
        print(f"  {len(rows)} report(s), list fetched {int(time.time() - fetched)}s ago")
        return 0
    prog = argv[argv.index("--program") + 1] if "--program" in argv else None
    verdict, lines = check(argv[0], prog, refresh)
    print("\n".join(lines))
    return {"CLEAR": 0, "DUPLICATE": 1, "POSSIBLE": 2, "UNVERIFIED": 3}[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
