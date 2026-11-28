#!/usr/bin/env python3
"""ywh-reach.py <target-slug> [limit]
Read targets/<slug>/SCOPE.txt, probe each in-scope host root with curl_cffi
chrome124, print a compact reachability table. Scope-gated by construction:
only probes hosts listed in that program's SCOPE.txt. No credential printed.
"""
import sys, os
from curl_cffi import requests as r

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if len(sys.argv) < 2:
    sys.exit("usage: ywh-reach.py <target-slug> [limit]")
slug = sys.argv[1]
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 40
scope = os.path.join(WS, "targets", slug, "SCOPE.txt")
hosts = []
with open(scope) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # strip scheme/path if present, keep bare host
        h = line.split("//")[-1].split("/")[0].strip()
        if h and "." in h and h not in hosts:
            hosts.append(h)
hosts = hosts[:limit]
for h in hosts:
    u = "https://" + h + "/"
    try:
        resp = r.get(u, impersonate="chrome124", timeout=12, allow_redirects=False)
        srv = resp.headers.get("server", "")[:22]
        loc = resp.headers.get("location", "")[:45]
        xpb = resp.headers.get("x-powered-by", "")[:18]
        print(f"{resp.status_code:>3} {h:40} srv={srv:22} xpb={xpb:18} len={len(resp.content):>7} {loc}")
    except Exception as e:
        print(f"ERR {h:40} {type(e).__name__}: {str(e)[:45]}")
