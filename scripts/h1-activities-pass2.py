#!/usr/bin/env python3
"""Pass 2: for index rows whose /reports/<id>.json is 404 (limited disclosure),
harvest the metadata + ACTIVITY STREAM via GraphQL. Titles and triage replies are
public even when the body is withheld."""
import json, os, glob, sys, time, concurrent.futures as cf
from curl_cffi import requests

ROOT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research/h1-accepted-365")
RAW = os.path.join(ROOT, "reports")
P2 = os.path.join(ROOT, "reports_limited")
os.makedirs(P2, exist_ok=True)
GQL = "https://hackerone.com/graphql"
IMP = "chrome124"
TYPES = json.load(open(os.path.join(ROOT, "_acttypes.json")))
FR = "\n".join(
    f'... on {t} {{ created_at internal message actor {{ __typename ... on User {{ username }} ... on Team {{ handle }} }} }}'
    for t in TYPES)
Q = """query R($id: Int!) { report(id: $id) { id title substate disclosed_at created_at
  severity { rating } weakness { name } team { handle } cve_ids
  structured_scope { asset_identifier asset_type }
  activities(first: 100) { edges { node { __typename %s } } } } }""" % FR


def one(row):
    rid = row["report"]["url"].rstrip("/").split("/")[-1]
    path = os.path.join(P2, f"{rid}.json")
    if os.path.exists(path) and os.path.getsize(path) > 200:
        return "cached"
    sess = requests.Session()
    for i in range(4):
        try:
            r = sess.post(GQL, json={"query": Q, "variables": {"id": int(rid)}},
                          impersonate=IMP, timeout=60)
            if r.status_code != 200:
                time.sleep(2 * (i + 1)); continue
            d = r.json()
            rep = (d.get("data") or {}).get("report")
            if rep is None:
                return "null"
            acts = [e["node"] for e in ((rep.get("activities") or {}).get("edges") or [])]
            rep.pop("activities", None)
            json.dump({"id": rid, "hacktivity": row, "meta": rep, "activities": acts},
                      open(path, "w"))
            return "ok"
        except Exception:
            time.sleep(2 * (i + 1))
    return "fail"


if __name__ == "__main__":
    rows = [json.loads(l) for l in open(os.path.join(ROOT, "index.jsonl"))]
    have = {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(RAW, "*.json"))}
    todo = [r for r in rows if r["report"]["url"].rstrip("/").split("/")[-1] not in have]
    print(f"pass2 targets: {len(todo)}", file=sys.stderr)
    st = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for i, s in enumerate(ex.map(one, todo), 1):
            st[s] = st.get(s, 0) + 1
            if i % 100 == 0:
                print(f"  {i}/{len(todo)} {st}", file=sys.stderr)
    print(json.dumps(st))
