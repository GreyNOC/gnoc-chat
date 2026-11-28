#!/usr/bin/env /usr/bin/python3
"""takeover_markers.py - one HTTP probe per SHARED-INGRESS candidate, looking for the provider's
unclaimed-resource marker.

WHY THESE AND ONLY THESE. The fleet DNS sweep found zero CLAIMABLE-DANGLING rows: no in-scope name
points at a non-resolving label in a zone a stranger can register. What it did find is
CLAIMABLE-ZONE-LIVE rows, and for a SHARED INGRESS that is the interesting state, because
resolution tells you nothing: `cname.createsend.com`, `*.sites.hubspot.net`, `*.zendesk.com` and
Cloudflare Pages all answer DNS for every customer, and whether a given HOSTNAME is claimed lives
in the provider's account-side domain mapping. Only the HTTP response can say (T-33: pick the
instrument that varies).

Rows whose target label is an AWS/Cloudflare-assigned random (`d*.cloudfront.net`) are excluded -
a stranger cannot choose one, so the row is not a takeover regardless of what HTTP says. That
correction is in takeover_fleet.py, where the first version wrongly listed cloudfront as claimable.

WHAT A HIT LOOKS LIKE: the provider's own not-configured page, which is byte-distinct from a served
site. Each candidate carries its provider's documented marker set below.

NOTHING IS EVER CLAIMED HERE. program-93's brief is explicit that "Subdomain takeover reports require a
working proof-of-concept demonstrating actual impact; dangling DNS records alone are not
sufficient", which is also our own standard - the terminal is claim-and-serve. But claiming
registers a resource in a third party under our name, so a marker hit is reported for the operator's
approval and the claim is a separate, deliberate step.

GET only, redirects not followed, no identification header (none of these programmes mandates one,
and an unrequested header is itself a WAF trigger - T-302). One request per host.

Usage: takeover_markers.py <program>   (run once per programme so the scope gate resolves correctly)
"""
import hashlib
import json
import os
import sys
import time

from curl_cffi import requests

WS = os.environ.get("GNOC_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

# host -> (programme, provider, [markers that indicate UNCLAIMED])
CANDIDATES = {
    # host: (program, provider, [fingerprint strings the dangling provider serves])
    "promo.example.com": ("exampleprogram", "github-pages", [
        "There isn't a GitHub Pages site here."]),
}


def probe(host, out_dir):
    url = "https://" + host + "/"
    try:
        r = requests.get(url, impersonate="chrome124", allow_redirects=False, timeout=25)
    except Exception as exc:
        return {"host": host, "fired": False,
                "error": type(exc).__name__ + ": " + str(exc)[:110]}
    body = r.content or b""
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, host)
    with open(base + ".hdr", "w") as fh:
        fh.write("HTTP " + str(r.status_code) + "\r\n"
                 + "\r\n".join(k + ": " + v for k, v in r.headers.items()) + "\r\n")
    with open(base + ".body", "wb") as fh:
        fh.write(body)
    return {"host": host, "fired": True, "status": r.status_code, "len": len(body),
            "md5": hashlib.md5(body).hexdigest(), "server": r.headers.get("server", ""),
            "ctype": r.headers.get("content-type", ""),
            "location": r.headers.get("location", ""), "file": base,
            "body_head": body[:260].decode("utf-8", "replace").replace("\n", " ")}


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    prog = sys.argv[1]
    mine = {h: v for h, v in CANDIDATES.items() if v[0] == prog}
    if not mine:
        sys.exit("no candidates for programme " + prog)
    out_dir = os.path.join(WS, "targets", prog, "recon", "takeover-fleet", "http")
    rows, hits = [], []
    print("programme %s - %d shared-ingress candidate(s), one GET each, no header\n" % (prog, len(mine)))
    for host, (_, provider, markers) in sorted(mine.items()):
        r = probe(host, out_dir)
        r["provider"] = provider
        rows.append(r)
        if not r.get("fired"):
            print("  %-34s UNFIRED  %s" % (host, r["error"]))
            continue
        raw = open(r["file"] + ".body", "rb").read()
        found = [m for m in markers if m.lower().encode() in raw.lower()]
        r["markers"] = found
        strong = [m for m in found if m not in ("404", "HubSpot", "createsend")]
        if strong:
            hits.append(r)
        print("  %-34s %-4s len=%-8s %-18s %s" % (
            host, r["status"], r["len"], provider,
            ("UNCLAIMED MARKER: " + ", ".join(strong)) if strong
            else ("weak/none: " + ", ".join(found) if found else "no marker - serving content")))
        print("        %s" % r["body_head"][:170])
        time.sleep(1.0)

    with open(os.path.join(out_dir, "markers.json"), "w") as fh:
        json.dump(rows, fh, indent=2)
    print("\n=== READING ===")
    if hits:
        print("  %d candidate(s) show a provider UNCLAIMED marker:" % len(hits))
        for h in hits:
            print("    %-34s %s  %s" % (h["host"], h["provider"], ", ".join(h["markers"])))
        print("  NOT CLAIMED. The terminal is claim-and-serve and that registers a resource in a")
        print("  third party under our name, so it goes to the operator for approval first.")
    else:
        print("  No candidate shows an unclaimed marker: every one is serving real content or a")
        print("  generic error. No takeover here. DEAD.")
    print("\nrows -> " + os.path.join(out_dir, "markers.json"))


if __name__ == "__main__":
    main()
