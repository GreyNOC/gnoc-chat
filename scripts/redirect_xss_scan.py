#!/usr/bin/env python3
"""Redirect-param XSS / open-redirect scanner.
Usage: redirect_xss_scan.py <host_file> [max]
Detects per host: redirect param that (a) server-302s to attacker URL (open redirect),
or (b) reflects raw into a client-side location.assign/href / <meta refresh> (DOM js: XSS).
Flags candidates; confirm js:-URI execution separately with xss_confirm.py.
"""
import sys, re, json, concurrent.futures as cf
from curl_cffi import requests as cr

PARAMS = ["next","redirect","redirect_uri","redirect_url","return","returnUrl","return_url",
          "url","u","r","goto","dest","destination","continue","callback","target","to","link","forward"]
# benign canary host for open-redirect; js: canary for DOM-sink reflection
CANARY_HOST = "ex" + "ample.org/zqRDR"
EXT = "https://" + CANARY_HOST
JSP = "javascript:zqJSx//"
META_RE = re.compile(r'http-equiv=["\']?refresh["\']?[^>]*url=([^"\'>\s]+)', re.I)
LOC_RE  = re.compile(r'location\.(?:href|assign|replace)\s*=\s*["\']?([^"\';\)]*zq[A-Za-z]+)', re.I)

def probe(host):
    host = host.strip()
    if not host or host.startswith("#") or "*" in host or "/" in host:
        return None
    s = cr.Session(impersonate="chrome124", timeout=12)
    base = "https://" + host + "/"
    found = []
    for p in PARAMS:
        for val, kind in ((EXT, "open_redirect"), (JSP, "js_dom")):
            try:
                r = s.get(base, params={p: val}, allow_redirects=False)
            except Exception:
                continue
            loc = r.headers.get("location", "")
            b = r.text if r.status_code == 200 else ""
            if loc and ("zqRDR" in loc or loc.strip().lower().startswith("javascript:")):
                found.append({"param": p, "kind": "server_redirect", "status": r.status_code, "loc": loc[:80]})
            if b:
                m = META_RE.search(b)
                if m and ("zqRDR" in m.group(1) or m.group(1).lower().startswith("javascript:")):
                    found.append({"param": p, "kind": "meta_refresh", "val": m.group(1)[:80]})
                lm = LOC_RE.search(b)
                if lm and "zq" in lm.group(1):
                    found.append({"param": p, "kind": "client_location", "val": lm.group(1)[:90]})
                if "javascript:zqJSx" in b:
                    found.append({"param": p, "kind": "raw_js_uri_reflected"})
    if found:
        seen = set(); dd = []
        for f in found:
            k = (f["param"], f["kind"])
            if k in seen:
                continue
            seen.add(k); dd.append(f)
        return {"host": host, "hits": dd}
    return None

def main():
    hf = sys.argv[1]; mx = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    hosts = [l.strip().split("|")[0] for l in open(hf) if l.strip() and not l.startswith("#") and "*" not in l]
    hosts = hosts[:mx]
    print(f"redirect-scan {len(hosts)} hosts...", file=sys.stderr)
    res = []
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(probe, hosts):
            if r:
                res.append(r); print(json.dumps(r, ensure_ascii=False))
    print(f"\n==== hosts with redirect hits: {len(res)} ====")
    json.dump(res, open(hf.rsplit('/', 1)[0] + "/redirect_xss_results.json", "w"), indent=1)

if __name__ == "__main__":
    main()
