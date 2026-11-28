#!/usr/bin/env python3
"""
Multi-host RAW reflected-XSS sweep (anti-hallucination).
For each host: probe common params + path/404 with a canary carrying < > " ' ` ( ) ;
Classify the reflection context and report EXACTLY which dangerous chars survive RAW
(unencoded, not entity/url/unicode/backslash-escaped). Only RAW < or RAW " in an
HTML/attribute/script context is an easy-XSS signal.

SCOPE GATE: pass --scope <SCOPE.txt>; every host is grepped against it before probing.

Usage:
  python3 xss_raw_reflect_sweep.py --scope targets/PROG/SCOPE.txt --hosts h1,h2,...  [--out dir]
  python3 xss_raw_reflect_sweep.py --scope targets/PROG/SCOPE.txt --all   (sweeps every host in scope, capped)
"""
import sys, os, json, argparse, concurrent.futures, re
try:
    from curl_cffi import requests as creq
    HAVE_CFFI = True
except Exception:
    import requests as creq
    HAVE_CFFI = False

CANARY = "zqxCAN8341"
# distinct markers so we can locate each char's fate
MARK = CANARY + 'a<b>c"d\'e`f(g)h;i'
PARAMS = ["q","s","search","query","keyword","k","term","redirect","redirect_uri","url","return","returnUrl","next","r","name","msg","message","error","err","lang","l","ref","utm_source","callback","jsonp","id","page","title","text","comment"]

def in_scope(host, scope_hosts):
    h = host.lower().strip()
    if h in scope_hosts: return True
    # allow wildcard entries *.x
    for s in scope_hosts:
        if s.startswith("*.") and (h == s[2:] or h.endswith("." + s[2:])): return True
    return False

def fetch(url):
    kw = dict(timeout=15, verify=False, allow_redirects=True)
    if HAVE_CFFI: kw["impersonate"] = "chrome124"
    else: kw["headers"] = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36"}
    return creq.get(url, **kw)

def classify(body, idx):
    """Look backwards from idx for the nearest unclosed < (tag open) or quote to guess context."""
    pre = body[max(0,idx-120):idx]
    # in script?
    last_script_open = pre.rfind("<script")
    last_script_close = pre.rfind("</script")
    if last_script_open > last_script_close: return "INSIDE_SCRIPT"
    # in tag attribute? unmatched < after last >
    lt = pre.rfind("<"); gt = pre.rfind(">")
    if lt > gt:
        # which quote
        seg = pre[lt:]
        dq = seg.rfind('"'); sq = seg.rfind("'")
        if dq>sq and dq!=-1: return "ATTR_DQ"
        if sq!=-1: return "ATTR_SQ"
        return "ATTR_UNQ"
    return "HTML_TEXT"

def survive(body, idx):
    """Return which of the injected chars appear RAW right after the canary letters."""
    seg = body[idx: idx+60]
    return {
        "lt_raw": "a<b" in seg or ("<b>c" in seg),
        "gt_raw": "b>c" in seg,
        "dq_raw": 'c"d' in seg,
        "sq_raw": "d'e" in seg,
        "bt_raw": "e`f" in seg,
        "paren_raw": "f(g)" in seg,
        "after": seg[:50],
    }

def probe_host(host, scope_hosts):
    if not in_scope(host, scope_hosts):
        return {"host":host, "scope":"OOS", "skipped":True}
    out = {"host":host, "hits":[], "errors":[]}
    targets = []
    for scheme in ("https",):
        for p in PARAMS:
            targets.append((p, f"{scheme}://{host}/?{p}=" + MARK))
            targets.append((p, f"{scheme}://{host}/search?{p}=" + MARK))
        targets.append(("__path__", f"{scheme}://{host}/" + MARK + "abc"))
    for pname, url in targets:
        try:
            r = fetch(url)
            ct = r.headers.get("content-type","")
            body = r.text
            if CANARY not in body: continue
            # locate every occurrence
            for m in re.finditer(re.escape(CANARY), body):
                idx = m.start()
                ctx = classify(body, idx)
                surv = survive(body, idx)
                dangerous = surv["lt_raw"] or (surv["dq_raw"] and ctx.startswith("ATTR")) or (surv["dq_raw"] and ctx=="INSIDE_SCRIPT")
                if surv["lt_raw"] or surv["dq_raw"] or surv["sq_raw"]:
                    out["hits"].append({
                        "param":pname,"url":url,"status":r.status_code,"ctype":ct,
                        "context":ctx,"survive":{k:v for k,v in surv.items() if k!="after"},
                        "EASY_XSS": bool(dangerous),
                        "sample": body[max(0,idx-40):idx+60].replace("\n"," ")
                    })
                    break  # one hit per url enough
        except Exception as e:
            out["errors"].append(f"{url[:60]}: {str(e)[:80]}")
    out["any_easy"] = any(h.get("EASY_XSS") for h in out["hits"])
    out["any_reflect"] = bool(out["hits"])
    return out

def main():
    import urllib3; urllib3.disable_warnings()
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--hosts", default="")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--cap", type=int, default=40)
    ap.add_argument("--out", default="")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()
    scope_hosts = set()
    for line in open(args.scope):
        line=line.strip()
        if line and not line.startswith("#"): scope_hosts.add(line.lower())
    if args.hosts:
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    elif args.all:
        hosts = [h for h in scope_hosts if not h.startswith("*.")][:args.cap]
    else:
        print("need --hosts or --all"); sys.exit(1)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(probe_host, h, scope_hosts): h for h in hosts}
        for f in concurrent.futures.as_completed(futs):
            try: results.append(f.result())
            except Exception as e: results.append({"host":futs[f],"error":str(e)[:100]})
    easy = [r for r in results if r.get("any_easy")]
    refl = [r for r in results if r.get("any_reflect") and not r.get("any_easy")]
    print(f"\n==== SWEEP DONE: {len(hosts)} hosts | EASY-XSS candidates: {len(easy)} | reflect-only(encoded): {len(refl)} ====")
    for r in easy:
        print(f"\n[EASY] {r['host']}")
        for h in r["hits"]:
            if h.get("EASY_XSS"): print(f"   param={h['param']} ctx={h['context']} survive={h['survive']} | {h['sample'][:90]}")
    if not easy:
        print("(no raw < or raw-quote-in-sink found; reflect-only hosts:", ", ".join(r['host'] for r in refl[:20]), ")")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out,"sweep_results.json"),"w") as f: json.dump(results,f,indent=1)
        print("[saved]", os.path.join(args.out,"sweep_results.json"))

if __name__ == "__main__":
    main()
