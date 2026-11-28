#!/usr/bin/env python3
"""bbp-lookup.py - does a company have a bug bounty / VDP program?

Matches a company name or domain against locally cached program lists
(arkadiyt/bounty-targets-data for HackerOne, Bugcrowd, Intigriti, YesWeHack
+ disclose.io diodb for VDPs), and optionally probes /.well-known/security.txt.

Usage:  bbp-lookup.py "Google" google.com  [--security-txt]
        bbp-lookup.py --file companies.txt --json out.json
Refresh: bbp-lookup.py --refresh
"""
import json, os, re, sys, argparse, subprocess, time
D = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bbp-data")
SRC = {
 "hackerone_data.json":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
 "bugcrowd_data.json":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
 "intigriti_data.json":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
 "yeswehack_data.json":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
 "diodb-program-list.json":"https://raw.githubusercontent.com/disclose/diodb/master/program-list.json",
 "domains.txt":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
 "wildcards.txt":"https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt",
}
def refresh():
    os.makedirs(D, exist_ok=True)
    for f,u in SRC.items():
        p=subprocess.run(["curl","-sS","--max-time","120","-o",os.path.join(D,f),u])
        print(("ok  " if p.returncode==0 else "FAIL"), f)

def norm(s):
    s=(s or "").lower().strip()
    # strip program boilerplate first, then corporate suffixes
    s=re.sub(r"\b(bug ?bounty|bounty ?program|vulnerability disclosure( program)?|responsible disclosure|vdp|vrp|security program|public program|pentest|program)\b"," ",s)
    s=re.sub(r"\b(inc|llc|ltd|limited|corp|corporation|co|gmbh|sa|plc|group|holdings|technologies|technology|labs|software|systems|solutions|international|the)\b","",s)
    return re.sub(r"[^a-z0-9]","",s)

def load():
    def j(f):
        p=os.path.join(D,f)
        if not os.path.exists(p): return None
        try: return json.load(open(p))
        except Exception: return None
    progs=[]
    h=j("hackerone_data.json") or []
    for p in (h if isinstance(h,list) else h.get("programs",[])):
        a=p.get("attributes",p)
        progs.append({"platform":"HackerOne","name":a.get("name"),"handle":a.get("handle"),
          "url":"https://hackerone.com/"+(a.get("handle") or ""),
          "bounty":bool(a.get("offers_bounties")),"state":a.get("submission_state"),
          "targets":[t.get("asset_identifier") for t in (p.get("targets",{}).get("in_scope") or []) if isinstance(t,dict)]})
    b=j("bugcrowd_data.json") or []
    for p in b:
        progs.append({"platform":"Bugcrowd","name":p.get("name"),"handle":p.get("code"),
          "url":p.get("url"),"bounty":bool(p.get("max_payout")),"state":None,
          "targets":[t.get("name") for t in (p.get("targets",{}).get("in_scope") or []) if isinstance(t,dict)]})
    i=j("intigriti_data.json") or []
    for p in i:
        progs.append({"platform":"Intigriti","name":p.get("name"),"handle":p.get("handle") or p.get("id"),
          "url":p.get("url"),"bounty":bool(p.get("max_bounty",{}).get("value") if isinstance(p.get("max_bounty"),dict) else p.get("max_bounty")),
          "state":p.get("status"),
          "targets":[t.get("endpoint") for t in (p.get("targets",{}).get("in_scope") or []) if isinstance(t,dict)]})
    y=j("yeswehack_data.json") or []
    for p in y:
        progs.append({"platform":"YesWeHack","name":p.get("title") or p.get("name"),"handle":p.get("slug"),
          "url":p.get("url"),"bounty":bool(p.get("bounty")),"state":None,
          "targets":[t.get("target") for t in (p.get("targets",{}).get("in_scope") or []) if isinstance(t,dict)]})
    dd=j("diodb-program-list.json") or []
    byurl={}
    for p in (dd if isinstance(dd,list) else []):
        key=p.get("policy_url") or p.get("program_name")
        nm=p.get("program_name") or ""
        prev=byurl.get(key)
        # one entry per policy; prefer an org-style name (no dot) over a bare domain
        if prev is None or ("." in (prev.get("name") or "") and "." not in nm):
            byurl[key]={"platform":"disclose.io(VDP)","name":nm,
              "handle":p.get("policy_url"),"url":p.get("policy_url"),
              "bounty":str(p.get("offers_bounty","")).lower() in ("true","yes"),
              "state":None,"targets":[d for d in [p.get("program_name")] if d and "." in d]}
        elif nm and "." in nm:
            byurl[key]["targets"].append(nm)
    progs.extend(byurl.values())
    for p in progs:
        p["_n"]=norm(p["name"]); p["_t"]=[ (t or "").lower() for t in (p["targets"] or []) if t ]
    return progs

PLAT_RANK = {"HackerOne":0,"Bugcrowd":1,"Intigriti":2,"YesWeHack":3,"disclose.io(VDP)":4}

def _host(t):
    """normalise an in-scope asset string to a bare hostname, or '' if not a host"""
    t=(t or "").strip().lower()
    t=re.sub(r"^[a-z]+://","",t)
    t=t.split("/")[0].split("?")[0].split(":")[0]
    t=t.lstrip("*.")
    return t if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", t or "") else ""

def match(progs, company, domain=None):
    """Returns (owner_programs, asset_mentions).
    owner_programs = the company appears to OWN the program (name match).
    asset_mentions = the domain is listed in SOMEONE ELSE'S scope (informational only)."""
    cn=norm(company); looks_domain="." in company
    dl=(domain or "").lower().lstrip("*.") if domain else None
    owners=[]; mentions=[]
    for p in progs:
        pn=p["_n"]; oscore=0; why=[]
        if pn:
            if pn==cn: oscore=100; why.append("exact program-name match")
            elif not looks_domain and len(cn)>=5 and len(pn)>=5 and (cn in pn or pn in cn):
                # tight: the shorter name must cover most of the longer one
                if min(len(cn),len(pn))/max(len(cn),len(pn)) >= 0.7:
                    oscore=80; why.append("close program-name match")
        ahit=None
        if dl:
            for t in p["_t"]:
                h=_host(t)
                if h and (h==dl or h.endswith("."+dl)): ahit=h; break
        if oscore:
            if ahit: why.append("owns in-scope asset "+ahit); oscore=max(oscore,95)
            owners.append(dict(p, score=oscore, why="; ".join(why), matched_on=company))
        elif ahit:
            mentions.append(dict(p, score=50, why="third-party program lists "+ahit, matched_on=company))
    def clean(L):
        L=[{k:v for k,v in h.items() if not k.startswith("_")} for h in L]
        seen=set(); out=[]
        for h in sorted(L, key=lambda h:(-h["score"], PLAT_RANK.get(h["platform"],9), not h["bounty"])):
            k=(h["platform"],h["url"])
            if k in seen: continue
            seen.add(k); out.append(h)
        return out
    return clean(owners), clean(mentions)

def sectxt(domain):
    for u in (f"https://{domain}/.well-known/security.txt", f"https://{domain}/security.txt"):
        p=subprocess.run(["curl","-sSL","--max-time","20","-o","-","-w","\n%{http_code}",u],
                         capture_output=True, text=True)
        if p.returncode==0:
            *body, code = p.stdout.split("\n")
            if code.strip()=="200" and any(k in "\n".join(body).lower() for k in ("contact:","policy:")):
                return {"url":u,"found":True,"excerpt":"\n".join(body)[:500]}
    return {"found":False}

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("items", nargs="*", help="company names and/or domains")
    ap.add_argument("--file"); ap.add_argument("--json"); ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--security-txt", action="store_true")
    a=ap.parse_args()
    if a.refresh: refresh(); sys.exit(0)
    items=a.items[:]
    if a.file: items+=[l.strip() for l in open(a.file) if l.strip() and not l.startswith("#")]
    progs=load()
    print(f"# loaded {len(progs)} programs from {D}", file=sys.stderr)
    out={}
    for it in items:
        name, dom = (it.split("|")+[None])[:2] if "|" in it else (it, it if "." in it else None)
        owners, mentions = match(progs, name, dom)
        rec={"query":it,"company":name,"domain":dom,"owner_programs":owners,"asset_mentions":mentions[:5]}
        if dom and not owners: rec["security_txt"]=sectxt(dom)
        out[it]=rec
        tag = "OWNS PROGRAM" if owners else "NO PROGRAM"
        print(f"\n== {name}  ->  {tag}  ({len(owners)} owner / {len(mentions)} asset-mention)")
        for x in owners[:5]:
            print(f"   [{x['score']:3d}] {x['platform']:18s} {str(x['name'])[:40]:40s} bounty={str(x['bounty']):5s} {x['url']}")
            print(f"         why: {x['why']}")
        st=rec.get("security_txt")
        if st and st.get("found"): print(f"   security.txt FOUND: {st['url']}")
        elif st: print(f"   security.txt: none")
        if not owners and mentions:
            print(f"   (note: {len(mentions)} unrelated program(s) list this domain as an asset - not a disclosure route)")
    if a.json:
        json.dump(out, open(a.json,"w"), indent=1); print(f"\nwrote {a.json}", file=sys.stderr)
