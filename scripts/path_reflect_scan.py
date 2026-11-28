#!/usr/bin/env python3
"""404 / error-page path-reflection XSS scanner.
GET /<marker-with-breakout-chars> and check if the path reflects RAW (unencoded < > ")
into the error/404 body in an HTML context. Classic easy reflected XSS.
Usage: path_reflect_scan.py <host_file> [max]
"""
import sys, re, json, concurrent.futures as cf
from curl_cffi import requests as cr
from urllib.parse import quote

# marker placed in path segment + a query; keep chars that survive URL path
PATHMARK = "zqA'zqB\"zqC<zqD>zqE"
def probe(host):
    host=host.strip()
    if not host or host.startswith("#") or "*" in host or "/" in host: return None
    s=cr.Session(impersonate="chrome124", timeout=12)
    tries=[
        "/"+quote(PATHMARK, safe="'\"<>"),
        "/"+quote(PATHMARK, safe="'\"<>")+".html",
        "/search/"+quote(PATHMARK, safe="'\"<>"),
        "/"+quote(PATHMARK, safe="")+"/",
    ]
    best=None
    for path in tries:
        try:
            r=s.get("https://"+host+path, allow_redirects=False)
        except Exception:
            continue
        b=r.text
        if "zqA" not in b and "zqC" not in b: continue
        raw_lt = "zqC<zqD" in b
        raw_gt = "zqD>zqE" in b
        raw_quot = 'zqB"zqC' in b
        i=b.find("zqC<") if raw_lt else (b.find("zqA") if "zqA" in b else b.find("zqC"))
        pre=b[:i]
        in_script = pre.rfind("<script")>pre.rfind("</script")
        jsonblob=bool(re.search(r'(queryParams|"state"|__NEXT_DATA__|__NUXT__|window\.__)', pre[-200:]))
        score=(3 if (raw_lt and raw_gt and not in_script) else 0)+(2 if (raw_quot and in_script) else 0)
        snip=b[max(0,i-50):i+80]
        cand={"host":host,"path":path[:40],"status":r.status_code,"raw_lt":raw_lt,"raw_gt":raw_gt,"raw_quot":raw_quot,
              "in_script":in_script,"jsonblob":jsonblob,"score":score,"snip":snip}
        if best is None or score>best["score"]: best=cand
        if score>=2: break
    return best

def main():
    if len(sys.argv)<2: sys.exit("usage: path_reflect_scan.py <host_file> [max]")
    hf=sys.argv[1]; mx=int(sys.argv[2]) if len(sys.argv)>2 else 300
    hosts=[l.strip().split("|")[0] for l in open(hf) if l.strip() and not l.startswith("#") and "*" not in l][:mx]
    print(f"path-reflect {len(hosts)} hosts...",file=sys.stderr)
    res=[]
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(probe,hosts):
            if r: res.append(r)
    res.sort(key=lambda x:-x["score"])
    cands=[r for r in res if r["score"]>=2]
    raws=[r for r in res if r["raw_lt"]]
    print(f"\n==== reflecting:{len(res)} CANDIDATES:{len(cands)} raw_lt:{len(raws)} ====")
    for r in res:
        if r["score"]>=1 or r["raw_lt"]:
            print(json.dumps(r,ensure_ascii=False)[:300])
    json.dump(res,open(hf.rsplit('/',1)[0]+"/path_reflect_results.json","w"),indent=1)

if __name__=="__main__": main()
