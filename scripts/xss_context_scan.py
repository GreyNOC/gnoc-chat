#!/usr/bin/env python3
"""Context-aware reflected-XSS scanner.
Usage: xss_context_scan.py <scope_file> [max_hosts]
Flags ONLY hosts where breakout chars survive RAW in an EXECUTABLE context
(HTML text/attr with raw < > , or <script> with raw " < ) - not JSON-escaped blobs.
"""
import sys, re, json, concurrent.futures as cf
from curl_cffi import requests as cr

MARK = "zqA'zqB\"zqC<zqD>zqE/zqF`zqG=zqH"
PARAMS = ["q","s","search","query","keyword","text","term","name","msg","error","redirect","lang","title","SearchText"]

def classify(body, idx):
    # context just before the marker occurrence
    pre = body[:idx]
    last_script_open = pre.rfind("<script")
    last_script_close = pre.rfind("</script")
    in_script = last_script_open > last_script_close
    # nearest unclosed tag attribute?
    last_lt = pre.rfind("<"); last_gt = pre.rfind(">")
    in_tag = last_lt > last_gt
    # is the JSON-blob pattern (queryParams / state / __NEXT / __NUXT / window.__) nearby
    win = pre[-200:]
    jsonblob = bool(re.search(r'(queryParams|"state"|__NEXT_DATA__|__NUXT__|window\.__|"router")', win))
    return {"in_script":in_script,"in_tag":in_tag,"jsonblob":jsonblob}

def probe(host):
    host=host.strip()
    if not host or host.startswith("#") or "*" in host or "/" in host: return None
    url="https://"+host+"/"
    s=cr.Session(impersonate="chrome124", timeout=15)
    best=None
    for p in PARAMS:
        try:
            r=s.get(url, params={p:MARK}, allow_redirects=True)
        except Exception:
            continue
        b=r.text
        i=b.find("zqA")
        if i<0: continue
        # which chars raw?
        raw_apos = "zqA'zqB" in b
        raw_quot = 'zqB"zqC' in b
        raw_lt   = "zqC<zqD" in b
        raw_gt   = "zqD>zqE" in b
        ctx=classify(b,i)
        # executable? need to OPEN a tag (raw <) in non-script context, OR break a script string (raw ")
        html_tag_inject = raw_lt and raw_gt and not ctx["in_script"]
        script_break    = raw_quot and ctx["in_script"]
        score = (3 if html_tag_inject else 0) + (2 if script_break else 0) + \
                (1 if (raw_lt and not ctx["jsonblob"]) else 0)
        snippet=b[max(0,i-60):i+90]
        cand={"host":host,"param":p,"status":r.status_code,
              "raw":{"apos":raw_apos,"quot":raw_quot,"lt":raw_lt,"gt":raw_gt},
              "ctx":ctx,"html_tag_inject":html_tag_inject,"script_break":script_break,
              "score":score,"snippet":snippet, "url":r.url}
        if best is None or score>best["score"]:
            best=cand
        if html_tag_inject:  # strongest, stop early
            break
    return best

def main():
    scope=sys.argv[1]; maxh=int(sys.argv[2]) if len(sys.argv)>2 else 200
    hosts=[l.strip() for l in open(scope) if l.strip() and not l.startswith("#")
           and "*" not in l and "/" not in l]
    hosts=hosts[:maxh]
    print(f"scanning {len(hosts)} hosts...", file=sys.stderr)
    results=[]
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for r in ex.map(probe, hosts):
            if r: results.append(r)
    results.sort(key=lambda x:-x["score"])
    cands=[r for r in results if r["score"]>=2]
    print(f"\n==== reflecting hosts: {len(results)} | CANDIDATES(score>=2): {len(cands)} ====")
    for r in results:
        flag = "<<< CANDIDATE" if r["score"]>=2 else ""
        print(f"[{r['score']}] {r['host']:32s} p={r['param']:8s} raw_lt={r['raw']['lt']} raw_quot={r['raw']['quot']} script={r['ctx']['in_script']} jsonblob={r['ctx']['jsonblob']} tag_inject={r['html_tag_inject']} {flag}")
        if r["score"]>=2:
            print("     snip:", repr(r["snippet"]))
    out=scope.rsplit("/",1)[0]+"/xss_context_results.json"
    json.dump(results, open(out,"w"), indent=1)
    print("[saved]", out)

if __name__=="__main__": main()
