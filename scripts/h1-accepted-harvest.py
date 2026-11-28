#!/usr/bin/env python3
"""Harvest H1 disclosed reports with activity (triage) messages for the last N days.

Two token-free channels:
  1. GraphQL CompleteHacktivityReportIndex  -> the report list
  2. /reports/<id>.json                     -> full body, state, substate, weakness, scope
  3. GraphQL report(id:) activities          -> the triage replies, with actor + timestamps

Writes one JSON file per report plus an index.jsonl. Idempotent: skips files already on disk.
"""
import json, os, sys, time, concurrent.futures as cf
from curl_cffi import requests

OUT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research/h1-accepted-365")
RAW = os.path.join(OUT, "reports")
os.makedirs(RAW, exist_ok=True)
GQL = "https://hackerone.com/graphql"
IMP = "chrome124"

SEARCH_Q = """query H($q: String!, $from: Int, $size: Int, $sort: SortInput) {
  search(index: CompleteHacktivityReportIndex, query_string: $q, from: $from, size: $size, sort: $sort) {
    total_count
    nodes { ... on HacktivityDocument {
      severity_rating submitted_at latest_disclosable_activity_at
      report { title url } } } } }"""

# derived from introspection at runtime: every ActivityUnion member carrying a message
def _msg_types():
    cache = os.path.join(OUT, "_acttypes.json")
    if os.path.exists(cache):
        return json.load(open(cache))
    d = requests.post(GQL, json={"query": '{ __type(name: "ActivityUnion") { possibleTypes { name fields { name } } } }'},
                      impersonate=IMP, timeout=60).json()
    out = [t["name"] for t in d["data"]["__type"]["possibleTypes"]
           if "message" in {f["name"] for f in (t["fields"] or [])}]
    json.dump(out, open(cache, "w"))
    return out

MSG_TYPES = _msg_types()
FRAGS = "\n".join(
  f'... on {t} {{ created_at internal message actor {{ __typename ... on User {{ username }} ... on Team {{ handle }} }} }}'
  for t in MSG_TYPES)
ACT_Q = """query R($id: Int!) { report(id: $id) { id title substate
  activities(first: 100) { edges { node { __typename %s } } } } }""" % FRAGS


def gql(sess, query, variables, tries=4):
    for i in range(tries):
        try:
            r = sess.post(GQL, json={"query": query, "variables": variables},
                          impersonate=IMP, timeout=60)
            if r.status_code == 200:
                d = r.json()
                if "errors" in d and "data" not in d:
                    raise RuntimeError(json.dumps(d["errors"])[:300])
                return d
            if r.status_code in (429, 502, 503):
                time.sleep(3 * (i + 1)); continue
            raise RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            if i == tries - 1:
                raise
            time.sleep(2 * (i + 1))
    return None


def harvest_index(days=365):
    import datetime
    since = (datetime.date.today() - datetime.timedelta(days=days)).isoformat()
    q = f"disclosed:true AND latest_disclosable_activity_at:[{since} TO *]"
    sess = requests.Session()
    rows, frm = [], 0
    while True:
        d = gql(sess, SEARCH_Q, {"q": q, "from": frm, "size": 100,
                                 "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"}})
        s = d["data"]["search"]
        nodes = [n for n in s["nodes"] if n.get("report")]
        if not nodes:
            break
        rows += nodes
        print(f"  index {len(rows)}/{s['total_count']}", file=sys.stderr)
        frm += 100
        if frm >= min(s["total_count"], 10000):
            break
        time.sleep(0.4)
    with open(os.path.join(OUT, "index.jsonl"), "w") as f:
        for r_ in rows:
            f.write(json.dumps(r_) + "\n")
    return rows


def fetch_one(row):
    url = row["report"]["url"]
    rid = url.rstrip("/").split("/")[-1]
    path = os.path.join(RAW, f"{rid}.json")
    if os.path.exists(path) and os.path.getsize(path) > 500:
        try:
            old = json.load(open(path))
            bad = any(a.get("__typename") == "_HARVEST_ERROR" for a in (old.get("activities") or []))
        except Exception:
            bad = True
        if not bad:
            return rid, "cached"
        sess = requests.Session()
        try:
            d = gql(sess, ACT_Q, {"id": int(rid)})
            rep = (d.get("data") or {}).get("report") or {}
            old["activities"] = [e["node"] for e in ((rep.get("activities") or {}).get("edges") or [])]
            json.dump(old, open(path, "w"))
            return rid, "repaired"
        except Exception as e:
            return rid, f"repairfail-{str(e)[:50]}"
    sess = requests.Session()
    try:
        r = sess.get(f"https://hackerone.com/reports/{rid}.json", impersonate=IMP, timeout=60)
        if r.status_code != 200:
            return rid, f"body-{r.status_code}"
        body = r.json()
        acts = []
        try:
            d = gql(sess, ACT_Q, {"id": int(rid)})
            rep = (d.get("data") or {}).get("report") or {}
            acts = [e["node"] for e in ((rep.get("activities") or {}).get("edges") or [])]
        except Exception as e:
            acts = [{"__typename": "_HARVEST_ERROR", "message": str(e)[:200]}]
        out = {"id": rid, "hacktivity": row, "report": body, "activities": acts}
        with open(path, "w") as f:
            json.dump(out, f)
        return rid, "ok"
    except Exception as e:
        return rid, f"err-{str(e)[:60]}"


if __name__ == "__main__":
    days = int(sys.argv[1]) if len(sys.argv) > 1 else 365
    idx_path = os.path.join(OUT, "index.jsonl")
    if os.path.exists(idx_path) and "--refresh" not in sys.argv:
        rows = [json.loads(l) for l in open(idx_path)]
        print(f"index cached: {len(rows)}", file=sys.stderr)
    else:
        rows = harvest_index(days)
    stats = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for i, (rid, st) in enumerate(ex.map(fetch_one, rows), 1):
            k = st.split("-")[0]
            stats[k] = stats.get(k, 0) + 1
            if i % 50 == 0:
                print(f"  {i}/{len(rows)} {stats}", file=sys.stderr)
    print(json.dumps(stats))
