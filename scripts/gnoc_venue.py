"""Venue-side filing record for venues that have NO API and NO public feed.

WHY THIS EXISTS (receipt, 2026-10-28). `reports/drafts/program-64/E-mcpguard-fork-escape` was filed
THREE times. Meta closed it Not Applicable twice (#1046966351699081, #1056950997367283) before the
third filing (#1073417372387312) went out. Nothing on disk recorded any of it: a UI filing never
writes `reports/submitted/`, program-64 has no API, and the draft's own dedup stamp read
"self-hosted program, no public hacktivity feed" - which the pipeline treated as THERE IS NO
CHANNEL TO CHECK rather than THE CHANNEL IS OUR OWN LOGGED-IN REPORT LIST. dedup-scout, the
reviewer and report-killer all checked `reports/submitted/`, `reports/archive/` and the public
record, and all three correctly answered "never filed" from what they could see.

So: for a venue with no API, our own filed-report list is read from the authed UI by
`scripts/venue-reports.py`, cached here as JSON, and `gnoc_pay.filing_gate` refuses a filing
decision that cannot see it. The gate refuses on a FACT - "we do not know what we have already
filed on this venue" - not on a model's opinion.
"""
import json
import os
import re
import datetime

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_AGE_DAYS = 14          # a filing decision may not rest on a venue list older than this

# Venues whose own report list is reachable ONLY through the authenticated UI.
# hackerone / bugcrowd / intigriti / yeswehack expose our reports through an API, so they are absent.
NO_API_VENUES = {"meta", "self-hosted", "huntr"}


def record_path(program):
    return os.path.join(WS, "reports", "submitted", program, "venue-reports.json")


def load(program):
    """The cached venue record, or None. Never raises on a malformed file: a corrupt cache is no cache."""
    try:
        with open(record_path(program)) as f:
            d = json.load(f)
        return d if isinstance(d, dict) and isinstance(d.get("reports"), list) else None
    except Exception:  # noqa: BLE001 - missing, unreadable or malformed all mean "no record"
        return None


def save(program, source, reports, read=None):
    """Write the record. `reports` rows carry id, title, state and filed."""
    p = record_path(program)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    doc = {"program": program, "source": source,
           "read": read or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
           "reports": reports}
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    os.replace(tmp, p)
    return p


def age_days(program):
    d = load(program)
    if not d or not d.get("read"):
        return None
    try:
        t = datetime.datetime.fromisoformat(d["read"])
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
        return (datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() / 86400.0
    except Exception:  # noqa: BLE001
        return None


def _norm(s):
    """Compare titles on their content words, so a prefix the form silently strips cannot hide a dupe.

    The third filing's title was the second's with `facebook/mcpguard-dynamic: ` removed by the form
    itself, so an equality test on the raw strings would have passed it through.
    """
    s = re.sub(r"[^a-z0-9 ]+", " ", (s or "").lower())
    stop = {"a", "an", "the", "via", "in", "on", "of", "and", "to", "by", "for", "with", "complete",
            "all", "any", "every", "its", "lets", "that", "this", "from", "into", "out"}
    out = set()
    for w in s.split():
        if len(w) <= 2 or w in stop:
            continue
        if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]          # guards/guard, hooks/hook: a plural must not hide a duplicate
        out.add(w)
    return out


MIN_SHARED = 5          # below this, a short title overlaps by accident


def match(program, title, threshold=0.55):
    """Rows already filed on this venue whose title overlaps `title`.

    CONTAINMENT over the shorter side, not Jaccard: the candidate text handed in at gate time is a slug
    plus a whole chain description, far longer than a filed title, and Jaccard's union term would push a
    real duplicate under any useful threshold. MIN_SHARED stops a short title matching everything.

    The threshold is CALIBRATED, not guessed: 0.55 is what the real re-file needs (7 of 12 content words
    shared between the chain text and the filed title = 0.58), and the measured negatives sit far below
    it - the openzl finding shares ONE word with the mcpguard chain text, and an unrelated Instagram
    finding shares none. Re-run scripts/test_gnoc_venue.py if you touch it.
    """
    d = load(program)
    if not d or not title:
        return []
    want = _norm(title)
    if not want:
        return []
    out = []
    for r in d["reports"]:
        got = _norm(r.get("title"))
        if not got:
            continue
        shared = want & got
        score = len(shared) / float(min(len(want), len(got)))
        if score >= threshold and len(shared) >= MIN_SHARED:
            out.append(dict(r, overlap=round(score, 2), shared=len(shared)))
    return sorted(out, key=lambda r: -r["overlap"])


def check(program, venue, title=None):
    """(ok, why) for a filing decision on an API-less venue.

    False when the venue list is missing or stale (we cannot know what we already filed), and False
    when `title` matches something already filed - loudest when that filing was already CLOSED.
    """
    if venue not in NO_API_VENUES:
        return True, ""
    d = load(program)
    if not d:
        return False, (f"venue {venue} has no API, and there is no record of what we have already filed on it. "
                       f"Run: scripts/venue-reports.py {program} --refresh (reads our own report list from the "
                       "authed browser). Filing blind here already cost three filings of one finding on program-64")
    age = age_days(program)
    if age is not None and age > MAX_AGE_DAYS:
        return False, (f"the venue report list for {program} is {age:.0f} days old (max {MAX_AGE_DAYS}): "
                       f"run scripts/venue-reports.py {program} --refresh before spending a filing")
    hits = match(program, title) if title else []
    if hits:
        h = hits[0]
        closed = (h.get("state") or "").lower() not in ("new", "triaged", "needs more info", "")
        return False, (f"ALREADY FILED on {venue} as #{h.get('id')} ({h.get('state')}, {h.get('filed')}), "
                       f"title overlap {h.get('overlap')}: {str(h.get('title'))[:90]!r}"
                       + (". That report is CLOSED - re-filing the same evidence is a duplicate of our own work"
                          if closed else ". That report is still open: comment on it instead of filing again"))
    n = len(d["reports"])
    return True, (f"venue {venue}: {n} report(s) of ours on record (list {age:.0f} d old)" if age is not None
                  else f"venue {venue}: {n} report(s) of ours on record")
