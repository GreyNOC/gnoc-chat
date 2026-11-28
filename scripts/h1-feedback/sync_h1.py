#!/usr/bin/env python3
"""Live H1 feedback sync. Pulls every report of the researcher's HackerOne queue plus
each report's triager activities, classifies the close-reason into failure buckets, and
writes a dated snapshot + a stable triager_analysis.latest.json / TRIAGER-PATTERN.latest.md
that the learning consolidator reads. Token + handle come from the environment
(H1_TOKEN / H1_USER), exported by sync.sh from ~/.config/gnoc/secrets.env - never
hardcoded, never echoed. Run by filename (scope-gate greps command text for URLs)."""
import base64, json, time, urllib.request, urllib.error, os, sys, re, datetime
from collections import Counter

USER = os.environ.get("H1_USER") or "researcher"
TOKEN = (os.environ.get("H1_TOKEN") or "").strip()
# Token only needed to FETCH. RECLASSIFY=1 reuses cached details and needs no token.
AUTH = base64.b64encode(f"{USER}:{TOKEN}".encode()).decode() if TOKEN else ""
BASE = os.path.dirname(os.path.abspath(__file__))
DAY = datetime.date.today().isoformat()
OUT = f"{BASE}/out/{DAY}"
DET = f"{OUT}/details"
os.makedirs(DET, exist_ok=True)


def get(url):
    hdrs = {"Accept": "application/json"}
    if AUTH:
        hdrs["Authorization"] = "Basic " + AUTH
    req = urllib.request.Request(url, headers=hdrs)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            with e:  # the error response is a live socket: close it, or every failed call leaks one
                if e.code == 429:
                    time.sleep(5 * (attempt + 1)); continue
                print(f"HTTP {e.code} {url}: {e.read()[:200]}", file=sys.stderr); raise
        except Exception as e:
            print(f"err {e} {url}", file=sys.stderr); time.sleep(3)
    raise SystemExit("too many retries")


def fetch_list():
    url = "https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=100"
    out = []
    while url:
        d = get(url)
        out.extend(d.get("data", []))
        url = (d.get("links") or {}).get("next")
        print(f"  list {len(out)}", file=sys.stderr); time.sleep(0.4)
    return out


CLOSE_TYPES = {
    "activity-bug-informative", "activity-bug-not-applicable", "activity-bug-duplicate",
    "activity-bug-spam", "activity-not-eligible-for-bounty", "activity-bug-needs-more-info",
    "activity-bug-triaged", "activity-bug-resolved",
}
PAT = {
    "no-impact": re.compile(r"no (practical )?(security )?impact|lack of impact|without impact|no practical impact|does not demonstrate a practical|functioning correctly|do(es)? not demonstrate a (direct )?(security )?(vulnerab|impact)|not (a |directly )?(exploitable|security (vulnerab|risk))|theoretical|informational|best practice|hardening|defense.in.depth", re.I),
    "no-capability": re.compile(r"no.*(sensitive|access|capabilit|escalat)|does not (grant|allow|lead|cause any direct)|cannot access|no cross|own account|self.?xss|no PII|non.?sensitive|cannot be considered sensitive|not.{0,12}sensitive|reachable.*(by design|pre-auth)|must be reachable|conflates|accessible through the standard", re.I),
    "not-a-boundary": re.compile(r"not.{0,20}(access control|trust) boundary|intended behaviou?r|by design|working as intended|expected behaviou?r", re.I),
    "unproven-chain": re.compile(r"unable to (reproduce|replicate|confirm)|could not reproduce|not able to verify|no (clear )?(poc|proof)|speculativ|hypothetical|need.*(more|clearer).*(steps|poc|evidence)|complete exploitation chain|without a complete|reach internal|social engineering", re.I),
    "high-entropy-unreachable": re.compile(r"high.?entropy|without a systematic way|brute.?forc", re.I),
    "out-of-scope": re.compile(r"out of scope|not in scope|asset.*not.*scope|not (a )?part of|does not exist in the codebase|file.*does not exist", re.I),
    "known-accepted": re.compile(r"known issue|already (aware|reported|tracked)|accept(ed|able) risk|risk.accepted|previously reported|another researcher", re.I),
}


def close_msg(detail):
    acts = (((detail.get("data") or {}).get("relationships") or {}).get("activities", {}) or {}).get("data", []) or []
    cm, pub = "", []
    for a in acts:
        at = a.get("type", "")
        attr = a.get("attributes") or {}
        msg = (attr.get("message") or "").strip()
        internal = attr.get("internal")
        if at in CLOSE_TYPES and not internal and msg:
            cm = msg
        if at == "activity-comment" and not internal and msg:
            pub.append(msg)
    return cm or (pub[-1] if pub else "")


_cached = f"{OUT}/reports_list_raw.json"
if os.environ.get("RECLASSIFY") == "1" and os.path.exists(_cached):
    reports = json.load(open(_cached))
    print(f"RECLASSIFY: reusing {len(reports)} cached reports (no fetch)")
else:
    reports = fetch_list()
    json.dump(reports, open(_cached, "w"), indent=1)
print(f"TOTAL {len(reports)}; states {dict(Counter(r['attributes'].get('state','?') for r in reports))}")

rows = []
for r in reports:
    rid = r["id"]
    _df = f"{DET}/{rid}.json"
    if os.path.exists(_df):
        try:
            detail = json.load(open(_df))
        except Exception:
            continue
    else:
        try:
            detail = get(f"https://api.hackerone.com/v1/hackers/reports/{rid}")
        except Exception:
            continue
        json.dump(detail, open(_df, "w"))
    a = r.get("attributes") or {}
    prog = (((r.get("relationships") or {}).get("program") or {}).get("data") or {}).get("attributes", {}).get("handle", "?")
    cm = close_msg(detail)
    tags = [k for k, rx in PAT.items() if rx.search(cm)]
    rows.append({
        "id": rid, "program": prog, "state": a.get("state", "?"),
        "title": (a.get("title") or "")[:70],
        "tags": ",".join(tags) or ("(no-comment)" if not cm else "(unclassified)"),
        "close_msg": cm[:1000],
    })
    time.sleep(0.3)

rows.sort(key=lambda x: (x["state"], x["program"]))
json.dump(rows, open(f"{OUT}/triager_analysis.json", "w"), indent=1)
json.dump(rows, open(f"{BASE}/triager_analysis.latest.json", "w"), indent=1)

NEG = {"informative", "not-applicable", "duplicate", "spam"}
neg = [r for r in rows if r["state"] in NEG]
tc = Counter()
for r in neg:
    for t in r["tags"].split(","):
        if t:
            tc[t] += 1
prog_neg = Counter(r["program"] for r in neg)

md = [f"# TRIAGER-PATTERN {DAY}", ""]
md.append(f"- reports: {len(rows)}; negative-closed: {len(neg)} ({100*len(neg)//max(len(rows),1)}%)")
md.append("- states: " + ", ".join(f"{k}={v}" for k, v in Counter(r['state'] for r in rows).most_common()))
md.append("")
md.append("## kill-tag histogram (negative-closed)")
for t, ntag in tc.most_common():
    md.append(f"- {ntag:3d}  {t}")
md.append("")
md.append("## worst programs (negative count)")
for p, ntag in prog_neg.most_common(12):
    md.append(f"- {ntag:3d}  {p}")
md.append("")
domtag = tc.most_common(1)[0][0] if tc else ""
md.append(f"## sample close quotes (dominant tag: {domtag})")
for r in [x for x in neg if domtag and domtag in x["tags"] and x["close_msg"]][:8]:
    md.append(f"- [{r['program']}] {r['close_msg'][:180]}")
open(f"{OUT}/TRIAGER-PATTERN.md", "w").write("\n".join(md) + "\n")
open(f"{BASE}/TRIAGER-PATTERN.latest.md", "w").write("\n".join(md) + "\n")
print(f"wrote {OUT}/TRIAGER-PATTERN.md; dominant kill tag: {domtag}")
