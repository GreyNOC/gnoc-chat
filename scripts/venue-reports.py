#!/usr/bin/env python3
"""Read OUR OWN filed-report list from a venue that has no API, and cache it for the filing gate.

    scripts/venue-reports.py program-64 --refresh     read it from the authed browser
    scripts/venue-reports.py program-64               show what is cached
    scripts/venue-reports.py program-64 --match "<title>"   would this title be a duplicate of ours?

A self-hosted venue publishes no hacktivity feed and offers no API, so `reports/submitted/` and a
public dedup sweep are both blind to what we have already sent it. The authenticated report list is
the only authoritative channel. Receipt (2026-10-28): program-64 E-mcpguard-fork-escape was filed
three times, closed Not Applicable twice, with nothing on disk recording any of it.

Needs the user's Chrome on CDP: scripts/cdp-chrome.sh
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_venue  # noqa: E402

# per-venue reader: the page that lists OUR reports, and how to pull the rows out of it
READERS = {
    "program-64": {
        "url": "https://bugbounty.meta.com/profile/1403358712849745/",
        "tab": "payouts and reports",
        "source": "bugbounty.meta.com profile, Payouts and Reports tab (authed)",
    },
}


def read_live(program):
    cfg = READERS.get(program)
    if not cfg:
        sys.exit(f"no venue reader for {program!r}. Known: {', '.join(sorted(READERS))}. "
                 f"Add one, or write reports/submitted/{program}/venue-reports.json by hand.")
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
    from bbtools.lib_browser import attach_cdp
    import time
    browser, ctx = attach_cdp()
    page = ctx.new_page()
    page.goto(cfg["url"], wait_until="load", timeout=70000)
    time.sleep(7)
    page.evaluate("""(want) => { const a=[...document.querySelectorAll('a,button,[role=tab],[role=button]')]
        .find(e => (e.innerText||'').toLowerCase().includes(want)); if (a) a.click(); }""", cfg["tab"])
    time.sleep(8)
    for _ in range(6):
        page.mouse.wheel(0, 2500)
        time.sleep(1.0)
    txt = page.evaluate("() => (document.body.innerText||'').replace(/[ \\t]+/g,' ')")
    page.close()
    rows = []
    for t, rid, state, _bounty, age in re.findall(
            r"([^\n]{20,180})\n#(\d{10,})\s*\n\s*\n?([^\n]*)\n\s*\n?([^\n]*)\n\s*([^\n]*)", txt):
        rows.append({"id": rid, "title": t.strip(), "state": state.strip(), "filed": age.strip()})
    if not rows:
        sys.exit("read the page but parsed ZERO report rows: the layout changed. Do NOT treat this as "
                 "'we have filed nothing' - fix the parser or write the JSON by hand.")
    return cfg["source"], rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("program")
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--match", metavar="TITLE")
    a = ap.parse_args()
    if a.refresh:
        source, rows = read_live(a.program)
        p = gnoc_venue.save(a.program, source, rows)
        print(f"wrote {p}: {len(rows)} report(s)")
    d = gnoc_venue.load(a.program)
    if not d:
        sys.exit(f"no venue record for {a.program}: run with --refresh")
    age = gnoc_venue.age_days(a.program)
    print(f"{a.program}: {len(d['reports'])} filed report(s), list "
          f"{'%.1f' % age if age is not None else '?'} days old, source {d.get('source')}")
    for r in d["reports"]:
        print(f"  #{r.get('id')}  {str(r.get('state')):16} {str(r.get('filed')):16} {str(r.get('title'))[:86]}")
    if a.match:
        hits = gnoc_venue.match(a.program, a.match)
        print(f"\nmatch for {a.match[:70]!r}: {'DUPLICATE OF OUR OWN' if hits else 'no overlap'}")
        for h in hits:
            print(f"  overlap {h['overlap']}  #{h['id']}  {h['state']}  {str(h['title'])[:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
