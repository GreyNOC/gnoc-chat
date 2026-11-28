#!/usr/bin/env python3
"""h1-dedup-list.py - READ-ONLY public hacktivity dedup list for one HackerOne program.

Uses the token-free GraphQL search index (see memory reference-h1-hacktivity-via-tokenfree-graphql).
Never submits, never mutates. Always positive-controls against a program with known disclosures.

Usage: python3 -I scripts/h1-dedup-list.py <handle> [--query '"open redirect"'] [--size 100]
Writes JSON to targets/<handle>/recon/dedup-<date>.json and prints a summary.
"""
import argparse
import datetime
import json
import os
import sys
import urllib.request

URL = "https://hackerone.com/graphql"
QUERY = (
    "query H($q: String!, $from: Int, $size: Int, $sort: SortInput) { "
    "search(index: CompleteHacktivityReportIndex, query_string: $q, from: $from, "
    "size: $size, sort: $sort) { total_count nodes { ... on HacktivityDocument { "
    "severity_rating submitted_at report { title url } } } } }"
)
CONTROL_HANDLE = "shopify"  # known to carry titled disclosures (memory: 100 nodes, 2 titled)


def fetch(team_handle, extra, size):
    q = f"team_handle:{team_handle}"
    if extra:
        q = f"{q} AND {extra}"
    body = {
        "operationName": "H",
        "variables": {
            "q": q,
            "from": 0,
            "size": size,
            "sort": {"field": "latest_disclosable_activity_at", "direction": "DESC"},
        },
        "query": QUERY,
    }
    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) research-dedup",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode())


def summarize(label, payload):
    search = (payload.get("data") or {}).get("search") or {}
    nodes = search.get("nodes") or []
    titled = [n for n in nodes if (n.get("report") or {}).get("title")]
    return {
        "label": label,
        "total_count": search.get("total_count"),
        "nodes": len(nodes),
        "titled": len(titled),
        "titles": [
            {
                "title": n["report"]["title"],
                "url": n["report"].get("url"),
                "severity": n.get("severity_rating"),
                "submitted_at": n.get("submitted_at"),
            }
            for n in titled
        ],
        "errors": payload.get("errors"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("handle")
    ap.add_argument("--query", default="", help="extra Lucene clause, e.g. '\"open redirect\"'")
    ap.add_argument("--size", type=int, default=100)
    a = ap.parse_args()

    target = summarize(a.handle, fetch(a.handle, a.query, a.size))
    control = summarize(CONTROL_HANDLE, fetch(CONTROL_HANDLE, "", 100))
    report = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "positive_control": control,
        "target": target,
        "note": "total_count counts hacktivity ENTRIES; undisclosed reports have null titles. "
                "Zero titled nodes is NOT absence. Record power, never read a zero as clear.",
    }
    out_dir = os.path.join("targets", a.handle, "recon")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.date.today().isoformat()
    out = os.path.join(out_dir, f"dedup-{stamp}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"control {CONTROL_HANDLE}: total={control['total_count']} titled={control['titled']}/{control['nodes']}")
    print(f"target  {a.handle}: total={target['total_count']} titled={target['titled']}/{target['nodes']}")
    if target["errors"]:
        print("ERRORS:", json.dumps(target["errors"])[:400])
    for t in target["titles"][:50]:
        print(f"  [{t['severity']}] {t['submitted_at']} {t['title'][:110]}  {t['url']}")
    print(f"wrote {out}")
    if control["titled"] == 0:
        print("POSITIVE CONTROL FAILED: the index returned no titled nodes. Do NOT record clear.", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
