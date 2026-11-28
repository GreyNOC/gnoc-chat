#!/usr/bin/env /usr/bin/python3
"""takeover_fleet.py - multi-programme dangling-record hunt, DNS only, zero credentials.

WHY THIS EXISTS. Subdomain takeover is the one defect class whose terminal (claim the resource,
serve a benign proof from the in-scope hostname) needs NO account. That matters because every other
capability we reached on Bugcrowd this session sat behind an account, and Bugcrowd programmes
mandate an @bugcrowdninja.com address to create one.

THE DISCRIMINANT, which killed 19 of 19 candidates on program-74 and 9 of 9 on another (T-277): a
takeover needs a dangling record whose TARGET SITS IN A ZONE WHOSE NAME A STRANGER CAN CHOOSE.
    NOT claimable: AWS ELB (`*.elb.amazonaws.com`), API Gateway (`d-*.execute-api...`), Imperva
      (`*.impervadns.net`), Akamai/Fastly/Cloudflare edges - the label carries a provider-assigned
      random suffix. Also anything inside the programme's OWN zone.
    CLAIMABLE: S3 buckets, GitHub Pages, Heroku, Netlify, Azure App Service, Shopify, Zendesk,
      Surge, Pantheon, Webflow, Statuspage and friends - the label IS the account/app name, so if
      it is free, anyone can register it.
So this script classifies by that question and reports ONLY the claimable shape.

Usage:  takeover_fleet.py <program> [<program> ...]
Reads each programme's in-scope wildcard rows from targets/<p>/SCOPE.txt (stopping at the OOS
divider), enumerates names passively from certificate transparency, resolves them, and writes
targets/<p>/recon/takeover-fleet/{names.txt,dns.tsv,CLAIMABLE.tsv}.

DNS and CT only. ZERO HTTP is sent to any programme asset, so no programme's scanner or rate rule
is engaged. Nothing is ever claimed: a claim registers a resource in a third party under our name,
which is the operator's decision, so a hit is reported for approval.
"""
import json
import os
import re
import subprocess
import sys
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

WS = os.environ.get("GNOC_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
RESOLVER = os.environ.get("RESOLVER", "1.1.1.1")

# Zones where the label is the customer's chosen account/app/bucket name, i.e. registrable by a
# stranger if free. Sourced from the long-standing can-i-take-over-xyz fingerprint set.
CLAIMABLE_ZONES = [
    "s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com/s3",
    "github.io", "herokuapp.com", "herokudns.com", "herokussl.com",
    "netlify.app", "netlify.com", "azurewebsites.net", "cloudapp.azure.com",
    "cloudapp.net", "trafficmanager.net", "blob.core.windows.net", "azureedge.net",
    "myshopify.com", "zendesk.com", "desk.com", "freshdesk.com", "helpscoutdocs.com",
    "statuspage.io", "surge.sh", "bitbucket.io", "pantheonsite.io", "wpengine.com",
    "ghost.io", "readme.io", "webflow.io", "tilda.ws", "launchrock.com",
    "canny.io", "gitbook.io", "notion.site", "framer.app", "bubble.io",
    "cargocollective.com", "strikingly.com", "unbounce.com", "instapage.com",
    "pardot.com", "createsend.com", "acquia-sites.com", "uberflip.com",
    "aftership.com", "aha.io", "bigcartel.com", "helpjuice.com", "helprace.com",
    "kajabi.com", "mashery.com", "proposify.biz", "simplebooklet.com",
    "smugmug.com", "wishpond.com", "wufoo.com", "short.io", "hatenablog.com",
    "hubspot.net", "hs-sites.com", "teamwork.com", "tave.com", "fly.dev",
    "render.com", "onrender.com", "pages.dev", "workers.dev", "firebaseapp.com",
    "web.app", "appspot.com", "elasticbeanstalk.com",
]
# Provider-assigned random labels and our own zones: a dangling record here is NOT takeable.
UNCHOOSABLE = [
    "elb.amazonaws.com", "execute-api.", "impervadns.net", "akamaiedge.net",
    "akamai.net", "edgekey.net", "edgesuite.net", "fastly.net", "fastlylb.net",
    "cdn.cloudflare.net", "awsglobalaccelerator.com", "nlb.", "alb.",
    # CloudFront distribution labels (d*.cloudfront.net) are AWS-assigned randoms, exactly like
    # ELB - a stranger cannot choose one. Takeover there needs an unclaimed ALTERNATE DOMAIN NAME
    # on a distribution, a different mechanism that AWS now gates on domain-ownership checks.
    # Listing it as claimable (as the first version of this file did) inflates the candidate set.
    "cloudfront.net",
]

_lock = threading.Lock()


def scope_wildcards(prog):
    """In-scope wildcard apexes from SCOPE.txt, stopping at the OOS divider."""
    p = os.path.join(WS, "targets", prog, "SCOPE.txt")
    apexes, exact = set(), set()
    if not os.path.exists(p):
        return apexes, exact
    for ln in open(p):
        s = ln.strip()
        if s.startswith("# === OUT OF SCOPE"):
            break
        if not s or s.startswith("#"):
            continue
        host = s.split("#")[0].strip().lower()
        if not host:
            continue
        if host.startswith("*."):
            apexes.add(host[2:])
        else:
            exact.add(host)
    return apexes, exact


def ct_names(apex, timeout=60):
    """Passive CT enumeration. No request reaches the programme's own infrastructure."""
    out = set()
    url = "https://crt.sh/?q=%25." + apex + "&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            data = json.loads(fh.read().decode("utf-8", "replace"))
        for row in data:
            for nm in str(row.get("name_value", "")).split("\n"):
                nm = nm.strip().lower().lstrip("*.").rstrip(".")
                if nm.endswith(apex) and re.match(r"^[a-z0-9._-]+$", nm):
                    out.add(nm)
    except Exception as exc:
        print("    ct error for %s: %s" % (apex, type(exc).__name__))
    return out


def dig(args, timeout=10):
    try:
        p = subprocess.run(["dig", "+time=3", "+tries=1", "@" + RESOLVER] + args,
                           capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except Exception:
        return ""


def answer(name, rrtype):
    out = dig(["+noall", "+answer", name, rrtype])
    recs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3].upper() == rrtype.upper():
            recs.append(parts[4].lower().rstrip("."))
    return recs


def rcode(name, rrtype="A"):
    m = re.search(r"status: ([A-Z]+)", dig(["+noall", "+comment", name, rrtype]))
    return m.group(1) if m else "TIMEOUT"


def zone_kind(target, own_apexes):
    t = (target or "").lower()
    if not t:
        return "none"
    if any(t.endswith(a) or ("." + a) in t for a in own_apexes):
        return "self"
    if any(u in t for u in UNCHOOSABLE):
        return "unchoosable"
    if any(z in t for z in CLAIMABLE_ZONES):
        return "claimable"
    return "other"


def probe(args):
    name, own_apexes = args
    chain = answer(name, "CNAME")
    addrs = answer(name, "A") or answer(name, "AAAA")
    target = chain[-1] if chain else ""
    tgt_rcode = rcode(target) if target else "-"
    kind = zone_kind(target, own_apexes)
    shape = "live"
    if chain and tgt_rcode == "NXDOMAIN":
        shape = {"claimable": "CLAIMABLE-DANGLING", "self": "SELF-DANGLING",
                 "unchoosable": "UNCHOOSABLE-DANGLING"}.get(kind, "OTHER-DANGLING")
    elif chain and kind == "claimable":
        shape = "CLAIMABLE-ZONE-LIVE"
    elif not addrs and not chain:
        shape = "no-record"
    return {"name": name, "shape": shape, "zone_kind": kind,
            "cname": ">".join(chain) or "-", "target_rcode": tgt_rcode,
            "addrs": ",".join(addrs) or "-"}


COLS = ["name", "shape", "zone_kind", "cname", "target_rcode", "addrs"]


def run_program(prog):
    apexes, exact = scope_wildcards(prog)
    print("\n=== %s === wildcard apexes: %s" % (prog, ", ".join(sorted(apexes)) or "(none)"))
    if not apexes:
        print("    no in-scope wildcard rows - skipping (exact-only scope has no enumeration surface)")
        return []
    out_dir = os.path.join(WS, "targets", prog, "recon", "takeover-fleet")
    os.makedirs(out_dir, exist_ok=True)

    names = set()
    for a in sorted(apexes):
        got = ct_names(a)
        print("    ct %-28s %d names" % (a, len(got)))
        names |= got
    names = sorted(names - exact)
    with open(os.path.join(out_dir, "names.txt"), "w") as fh:
        fh.write("\n".join(names) + "\n")
    print("    unique names to resolve: %d" % len(names))
    if not names:
        return []

    tsv = os.path.join(out_dir, "dns.tsv")
    claim = os.path.join(out_dir, "CLAIMABLE.tsv")
    for p in (tsv, claim):
        with open(p, "w") as fh:
            fh.write("\t".join(COLS) + "\n")

    hits, done = [], [0]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for row in pool.map(probe, [(n, apexes) for n in names]):
            line = "\t".join(str(row[c]) for c in COLS)
            with _lock:
                with open(tsv, "a") as fh:
                    fh.write(line + "\n")
                if row["shape"] in ("CLAIMABLE-DANGLING", "CLAIMABLE-ZONE-LIVE"):
                    with open(claim, "a") as fh:
                        fh.write(line + "\n")
                    hits.append(row)
                    print("    %s  %s -> %s (%s)" % (
                        row["shape"], row["name"], row["cname"], row["target_rcode"]))
                done[0] += 1
                if done[0] % 500 == 0:
                    print("      ... %d/%d" % (done[0], len(names)))

    import collections
    shapes = collections.Counter(l.split("\t")[1] for l in open(tsv).readlines()[1:])
    print("    shapes: " + ", ".join("%s=%d" % kv for kv in shapes.most_common()))
    return [dict(h, program=prog) for h in hits]


def main():
    progs = sys.argv[1:]
    if not progs:
        sys.exit(__doc__)
    all_hits = []
    for p in progs:
        try:
            all_hits += run_program(p)
        except Exception as exc:
            print("    %s FAILED: %s: %s" % (p, type(exc).__name__, str(exc)[:90]))

    print("\n\n======== CLAIMABLE SHAPES ACROSS %d PROGRAMME(S) ========" % len(progs))
    if not all_hits:
        print("  none. Every dangling record points at a provider-assigned label or the")
        print("  programme's own zone, which is not takeable (T-277).")
    for h in all_hits:
        print("  %-16s %-14s %-48s -> %s (%s)" % (
            h["program"], h["shape"], h["name"], h["cname"], h["target_rcode"]))
    print("\n  NOTHING WAS CLAIMED. A CLAIMABLE-DANGLING row is a candidate, and claiming it")
    print("  registers a resource in a third party under our name - the operator's call.")
    print("  A CLAIMABLE-ZONE-LIVE row needs ONE HTTP probe for the provider's unclaimed marker.")


if __name__ == "__main__":
    main()
