"""gnoc_pay.py - can this finding PAY, and can we even FILE it? Answered from disk before a draft is spent.

Why this module exists (the 2026-10-19 filability inventory, reports/DRAFT-FILABILITY-20261019.md): of ~50 drafts
ever written, 8 were against assets that cannot pay (no-bounty rows, descoped assets, repos not in scope, a program
whose reward table is not visible), the one filed hunt report closed DUPLICATE in four minutes, and the account's
HackerOne signal fell to -1.0, which makes a granular-signal program refuse report creation on EVERY channel
(Manual T-254). A draft on an asset that cannot pay, or on a program that cannot take the report, costs the slot,
the evidence run and the operator's review, and a bad filing costs future filings. So the questions below are asked
ONCE, mechanically, from what is already on disk, before gnoc_report.build spends anything - and they are advisory
everywhere else (hunt_brief, set_program, the target picker), because a VDP finding is still a finding.

Sources, in order of trust:
  targets/<program>/scopes_raw.json   the structured scope pull from the platform API: per asset
                                       eligible_for_bounty / eligible_for_submission / max_severity (52 programs)
  targets/<program>/SCOPE.txt          the hand-annotated scope: `[bounty; max=high]`, `[no-bounty; ...]`,
                                       `[verify-only ...]`, and commented rows carrying `DESCOPED` /
                                       `submission=False` (the desktop-client rows that cost a staged package)
  hackerone.com/graphql (token-free)   the team's filing flags: offers_bounties, submission_state, the
                                       granular signal requirement and its target (T-254). Cached 6 h.
  scripts/h1-feedback/out/<day>/       our own closed record, for our signal (T-254 weights). Offline.
Nothing here needs a credential, and nothing here writes anywhere but its own cache file.
"""
import json
import os
import re

import gnoc_venue
import time
import urllib.parse
import urllib.request

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _read_n as _read

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEAM_CACHE = os.path.join(WS, ".claude/state/hunt-loop/h1-team-cache.json")
TEAM_TTL = 6 * 3600
GRAPHQL = "https://hackerone.com/graphql"
FEEDBACK_OUT = os.path.join(WS, "scripts/h1-feedback/out")
# T-254: how HackerOne scores a closed report into the researcher's signal
SIGNAL_WEIGHT = {"resolved": 7.0, "informative": 0.0, "duplicate": 0.0, "not-applicable": -5.0, "spam": -10.0}
VERDICT_WORD = {"pays": "PAYS", "no-bounty": "NO BOUNTY", "not-submittable": "NOT SUBMITTABLE",
                "descoped": "DESCOPED", "verify-only": "VERIFY-ONLY", "not-in-scope": "NOT IN SCOPE",
                "no-scope": "NO SCOPE FILE", "unknown": "UNKNOWN"}
_SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}




def _ok_program(program):
    return isinstance(program, str) and bool(re.fullmatch(r"[\w][\w.-]*", program)) and ".." not in program


def _host(s):
    s = (s or "").strip().lower()
    if "://" in s:
        return (urllib.parse.urlsplit(s).hostname or "").rstrip(".")
    return s.split("/")[0].rstrip(".")


# ---------------------------------------------------------------- scope rows, with their money tags

def _rows_from_raw(program):
    """Rows from the platform pull: the truth when it exists. Every row carries the three flags verbatim."""
    try:
        d = json.loads(_read(os.path.join(WS, "targets", program, "scopes_raw.json")) or "null")
    except ValueError:
        return None
    if not isinstance(d, dict) or not isinstance(d.get("scopes"), list):
        return None
    out = []
    for r in d["scopes"]:
        if not isinstance(r, dict):
            continue
        ident = str(r.get("asset_identifier") or "").strip()
        if not ident:
            continue
        out.append({"type": str(r.get("asset_type") or "").upper(), "asset": ident, "host": _host(ident),
                    "bounty": r.get("eligible_for_bounty"), "submit": r.get("eligible_for_submission"),
                    "max": str(r.get("max_severity") or "").lower() or None, "descoped": False,
                    "verify_only": False, "src": "api", "pinned": d.get("pinned")})
    return out


_TAG = re.compile(r"\[([^\]]*)\]")
_OOS = re.compile(r"^(out.?of.?scope|oos([^a-z0-9]|$)|exclud|ineligib|not\s+in\s+scope|do\s+not\s+test|forbidden)", re.I)
_HOST_IN_LINE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}", re.I)


def _rows_from_scope_txt(program):
    """Rows from the annotated SCOPE.txt: the same divider rule as bbtools.lib_scope.parse_scope (everything after
    a genuine OUT-OF-SCOPE divider is ignored), PLUS the commented-out rows that carry a DESCOPED / submission=False
    note, which the host gate rightly ignores but a draft must not: that is the row a package was built against."""
    text = _read(os.path.join(WS, "targets", program, "SCOPE.txt"))
    if not text:
        return None
    out, after_divider = [], False
    # Bugcrowd (scripts/bugcrowd-scope.sh) writes no inline [bounty] tag; it writes one group header per
    # target group, "# --- group 'X' -- rewards: P1 $a-$b, ..." (cash) or "-- rewards: none", and tags a
    # cashless host "NO-BOUNTY" inline. Carry the group's cash state onto its rows (2026-11-04: station 0
    # refused program-97, a paying engagement, as 'unknown' because of this gap).
    group_pays = None
    for raw in text.splitlines():
        is_comment = bool(re.match(r"^\s*#", raw))
        line = re.sub(r"^[-=\s]+", "", re.sub(r"^\s*#+\s*", "", raw))
        if _OOS.match(line) and not _HOST_IN_LINE.search(line):
            after_divider = True
        if not raw.strip():
            continue
        gm = re.match(r"^group '.*' -- rewards: (.*)$", line) if is_comment else None
        if gm:
            group_pays = bool(re.search(r"P[1-5] \$", gm.group(1)))
            continue
        body = line if is_comment else raw
        m = _TAG.search(body)
        tag = (m.group(1) if m else "").lower()
        descoped = is_comment and ("descoped" in tag or "submission=false" in tag)
        if is_comment and not descoped:
            continue
        if after_divider and not descoped:
            continue
        cleaned = re.sub(r"\s*#.*$", "", body if not is_comment else body.split("[")[0]).strip()
        if m and not is_comment:
            cleaned = body[:m.start()].strip()
        toks = re.split(r"\s+", cleaned)
        if not toks or not toks[0]:
            continue
        atype, ident = ("", toks[0])
        if len(toks) > 1 and re.fullmatch(r"[A-Z][A-Z0-9_]*", toks[0]):
            atype, ident = toks[0], " ".join(toks[1:]).strip()
        if not ident:
            continue
        bounty = True if "no-bounty" not in tag and tag.startswith("bounty") else (False if "no-bounty" in tag else None)
        if bounty is None and group_pays is not None and not is_comment:
            bounty = False if re.search(r"#.*\bNO-BOUNTY\b", raw) else group_pays
        mx = re.search(r"max=([a-z]+)", tag)
        out.append({"type": atype, "asset": ident, "host": _host(ident), "bounty": bounty,
                    "submit": False if descoped else (None if "verify-only" in tag else True),
                    "max": mx.group(1) if mx else None, "descoped": descoped,
                    "verify_only": "verify-only" in tag, "src": "scope.txt", "pinned": None})
    return out


def scope_rows(program):
    """Every scope row with its money tags, API pull first, annotated SCOPE.txt as the fallback; [] when neither."""
    if not _ok_program(program):
        return []
    rows = _rows_from_raw(program)
    txt = _rows_from_scope_txt(program) or []
    if rows is None:
        return txt
    # a DESCOPED row only exists in the annotated file (the API pull was taken with eligible_for_submission=true)
    have = {r["asset"].lower() for r in rows}
    return rows + [r for r in txt if r["descoped"] and r["asset"].lower() not in have]


def _matches(row, host):
    """The host gate's own rule: exact, subdomain of a non-public suffix, wildcard-suffix; never a bare TLD."""
    h = (host or "").lower().rstrip(".")
    e = (row.get("host") or "").lower()
    if not h or not e:
        return 0
    wild = e.startswith("*")
    ne = re.sub(r"^\*\.?", "", e)
    if not ne or "." not in ne:
        return 0
    if h == ne:
        return 3 if not wild else 2
    if row.get("type") in ("WILDCARD", "") or wild:
        if h.endswith("." + ne):
            return 1
    return 0


def row_for(program, host_or_url):
    """The most specific scope row that names this host: an exact row beats a wildcard, a longer wildcard apex beats
    a shorter one. None when nothing matches."""
    host = _host(host_or_url)
    if not host:
        return None
    best, best_key = None, None
    for r in scope_rows(program):
        m = _matches(r, host)
        if not m:
            continue
        key = (m, len(r.get("host") or ""), not r.get("descoped"))
        if best is None or key > best_key:
            best, best_key = r, key
    return best


def payability(program, host_or_url):
    """(verdict, why, row) for one host: pays | no-bounty | not-submittable | descoped | verify-only |
    not-in-scope | no-scope | unknown. The verdict is about MONEY and FILING, never about whether probing is allowed
    (that is lib_scope.program_allows, and a no-bounty row is still in scope to test)."""
    if not _ok_program(program):
        return "no-scope", f"{program!r} is not a program handle", None
    rows = scope_rows(program)
    if not rows:
        return "no-scope", f"no targets/{program}/SCOPE.txt or scopes_raw.json", None
    r = row_for(program, host_or_url)
    host = _host(host_or_url) or str(host_or_url)
    if r is None:
        return "not-in-scope", f"{host} matches no scope row of {program}", None
    label = f"{r['type']} {r['asset']}".strip() + f" ({r['src']})"
    if r.get("descoped"):
        return "descoped", f"{host} sits on {label}, DESCOPED by the program: a report closes Not Applicable", r
    if r.get("submit") is False:
        return "not-submittable", f"{host} sits on {label}, eligible_for_submission=false", r
    if r.get("verify_only"):
        return "verify-only", f"{host} sits on {label}, a verify-only row, never a separate finding", r
    if r.get("bounty") is False:
        return "no-bounty", f"{host} sits on {label}, eligible_for_bounty=false: a VDP filing, no payout", r
    if r.get("bounty") is None:
        return "unknown", f"{host} sits on {label} with no bounty tag: check the program's reward table", r
    return "pays", f"{host} sits on {label}, bounty, max {r.get('max') or '?'}", r


def program_pays(program):
    """(any_bounty_row: bool|None, bounty_rows, no_bounty_rows, descoped_rows)."""
    rows = scope_rows(program)
    if not rows:
        return None, 0, 0, 0
    b = sum(1 for r in rows if r["bounty"] is True and not r["descoped"])
    nb = sum(1 for r in rows if r["bounty"] is False)
    ds = sum(1 for r in rows if r["descoped"] or r["submit"] is False)
    return (b > 0) if (b or nb) else None, b, nb, ds


def severity_cap(row, severity):
    """None when the row's max_severity allows this severity, else the one-line reason it will be downgraded."""
    if not row or not row.get("max") or not severity:
        return None
    want, cap = _SEV_RANK.get(str(severity).lower()), _SEV_RANK.get(str(row["max"]).lower())
    if want is None or cap is None or want <= cap:
        return None
    return (f"the scope row {row['asset']} caps severity at {row['max']}: a {severity} claim is paid at {row['max']} "
            "at best (the row's max_severity), so price the report at the cap, never above it")


# ---------------------------------------------------------------- the filing gate (T-254)

_PLATFORM_DOMAINS = ("hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com",
                     "immunefi.com", "hackenproof.com")


# Venue names as programmes write them. Used to find WHICH venue a header passage names, not to rank them.
_VENUE_ALIASES = {
    "hackerone": ("hackerone", "hacker one", "h1 api"),
    "bugcrowd": ("bugcrowd", "bug crowd"),
    "intigriti": ("intigriti",),
    "yeswehack": ("yeswehack", "yes we hack"),
    "immunefi": ("immunefi",),
    "hackenproof": ("hackenproof",),
}


def _venue_from_text(text):
    """The venue that appears EARLIEST in a header passage, else None.

    A fixed hackerone-first scan returns the wrong answer for a Bugcrowd brief, whose first line says
    Bugcrowd and whose prose names HackerOne later in the same breath (program-97: "Bugcrowd mandates no
    platform-wide identification header (unlike HackerOne's `X-HackerOne:`)" - the sentence is a contrast,
    not a venue). The header of an intake file names its own source first, so position is the evidence.
    """
    t = (text or "").lower()
    best = None
    for canon, aliases in _VENUE_ALIASES.items():
        for a in aliases:
            i = t.find(a)
            if i >= 0 and (best is None or i < best[0]):
                best = (i, canon)
    return best[1] if best else None


def _venue(program):
    """hackerone | bugcrowd | intigriti | yeswehack | immunefi | self-hosted | unknown, from intake's files.

    SELF-HOSTED IS TESTED FIRST AND POSITIVELY (2026-10-28). The brand scan below is a bare substring
    match, and program-64's PROGRAM.md names HackerOne exactly once - line 167, "Meta may share report
    information ... with Bugcrowd and HackerOne for the purpose of processing bounty payouts". That
    sentence made every program-64 filing decision run through the HackerOne signal gate, which answered
    "team flags unknown, file with care" instead of "this venue has no API, read your own report list".
    Receipt: one finding filed three times, closed Not Applicable twice first.

    A scopes_raw.json WITH NO "platform" KEY IS NOT PROOF OF HACKERONE (2026-11-04). That path is where
    h1-scope.sh drops its API dump, but bugcrowd-scope.sh writes the same filename with no platform key,
    and this function used to return "hackerone" for it. Measured on the live tree: program-97 and
    program-13 (both Bugcrowd engagements) were routed through the HackerOne signal gate, which
    skips gnoc_venue.check - the only dedupe a venue with no API has. A missing key now falls through to
    the file header, which says "auto-pulled from the Bugcrowd public engagement brief" in line 1.
    """
    raw = os.path.join(WS, "targets", program, "scopes_raw.json")
    raw_ok = os.path.isfile(raw)
    plat = ""
    if raw_ok:
        # That path is where h1-scope.sh drops its API dump, but a HAND-PINNED scope lives there too and
        # says what it is: program-64's carries "platform": "self-hosted (bugbounty.meta.com)". Inferring
        # the venue from the FILENAME is what routed Meta filings into the HackerOne signal gate.
        try:
            d = json.loads(_read(raw) or "null")
            if isinstance(d, dict):
                plat = str(d.get("platform") or "").lower()
        except Exception:  # noqa: BLE001 - unreadable dump: fall through to the header text
            plat = ""
        if "self-hosted" in plat:
            return "self-hosted"
        for canon, aliases in _VENUE_ALIASES.items():
            if any(a in plat for a in aliases):
                return canon
    head = (_read(os.path.join(WS, "targets", program, "SCOPE.txt"), 600) + " "
            + _read(os.path.join(WS, "targets", program, "PROGRAM.md"), 3000)).lower()
    if not any(d in head for d in _PLATFORM_DOMAINS):
        # the programme names its OWN intake host and no platform host: it runs its own venue
        if re.search(r"https?://[a-z0-9.-]*bugbounty[a-z0-9.-]*\.", head) or "/whitehat" in head:
            return "self-hosted"
    named = _venue_from_text(head)
    if named:
        return named
    if raw_ok:
        return "hackerone"      # legacy dump with no header evidence: the old assumption, last resort
    return "unknown"


def _load_cache():
    try:
        d = json.loads(_read(TEAM_CACHE) or "{}")
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _save_cache(d):
    os.makedirs(os.path.dirname(TEAM_CACHE), exist_ok=True)
    tmp = f"{TEAM_CACHE}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, TEAM_CACHE)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


_TEAM_QUERY = ("query($h:String!){team(handle:$h){handle state submission_state offers_bounties "
               "granular_signal_requirements_enabled submission_requirements_enabled i_must_verify_identity_to_submit "
               "signal_requirements_setting{target_signal}}}")


def _fetch_team(handle, timeout=20):
    body = json.dumps({"query": _TEAM_QUERY, "variables": {"h": handle}}).encode()
    req = urllib.request.Request(GRAPHQL, data=body, headers={"content-type": "application/json",
                                                              "accept": "application/json",
                                                              "user-agent": "greynoc-harness/1 (+T-254 team flags)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.load(r)
    team = ((d.get("data") or {}).get("team")) if isinstance(d, dict) else None
    if not isinstance(team, dict):
        return None
    sr = team.get("signal_requirements_setting") or {}
    return {"handle": team.get("handle"), "state": team.get("state"), "submission_state": team.get("submission_state"),
            "offers_bounties": team.get("offers_bounties"),
            "granular_signal": team.get("granular_signal_requirements_enabled"),
            "submission_requirements": team.get("submission_requirements_enabled"),
            "identity_required": team.get("i_must_verify_identity_to_submit"),
            "target_signal": sr.get("target_signal"), "ts": time.time()}


def h1_team(program, refresh=False, offline=False):
    """The team's filing flags, from the 6 h cache or a token-free GraphQL read. None when unknown (not an H1
    program, offline, or the platform did not answer); never raises."""
    if not _ok_program(program):
        return None
    # _venue() reads targets/<program>/, so a programme we have NOT intaken resolves to "unknown".
    # Refusing those made this unusable for TARGET SELECTION, the one job that must answer before
    # intake (2026-10-27: a sweep of 504 un-intaken programmes returned a false zero because of this,
    # while intaken programmes answered fine - a textbook silent population bug). An UNKNOWN venue now
    # falls through to the token-free GraphQL read; a venue we have intaken and know is NOT HackerOne
    # is still refused, which is what the guard was actually for.
    if _venue(program) not in ("hackerone", "unknown"):
        return None
    cache = _load_cache()
    row = cache.get(program)
    if row and not refresh and time.time() - float(row.get("ts") or 0) < TEAM_TTL:
        return row
    if offline:
        return row
    try:
        fresh = _fetch_team(program)
    except Exception:  # noqa: BLE001 - the platform being unreachable is a cache hit or an honest None
        fresh = None
    if fresh:
        cache[program] = fresh
        _save_cache(cache)
        return fresh
    return row


SIGNAL_INFO = {"age_days": None, "day": None}   # the pull own_signal last read, for the staleness note


def own_signal():
    """(signal, scored_rows, states) from the newest h1-feedback pull on disk, with T-254's weights; signal is None
    when no pull exists. The number HackerOne compares against a program's target is THIS, not our opinion.
    SIGNAL_INFO says how old the pull is: a filing decision on a stale pull is T-244's own mistake."""
    SIGNAL_INFO.update(age_days=None, day=None)
    try:
        days = sorted(d for d in os.listdir(FEEDBACK_OUT) if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d))
    except OSError:
        return None, 0, {}
    rows = []
    for day in reversed(days):
        try:
            d = json.loads(_read(os.path.join(FEEDBACK_OUT, day, "reports_list_raw.json")) or "null")
        except ValueError:
            continue
        rows = d if isinstance(d, list) else (d.get("data") if isinstance(d, dict) else None) or []
        if rows:
            try:
                age = (time.time() - time.mktime(time.strptime(day, "%Y-%m-%d"))) / 86400.0
            except ValueError:
                age = None
            SIGNAL_INFO.update(age_days=round(age, 1) if age is not None else None, day=day)
            break
    states = {}
    for r in rows:
        a = (r.get("attributes") if isinstance(r, dict) else None) or (r if isinstance(r, dict) else {})
        st = str(a.get("state") or "").lower()
        if st:
            states[st] = states.get(st, 0) + 1
    scored = [(st, n) for st, n in states.items() if st in SIGNAL_WEIGHT]
    total = sum(n for _, n in scored)
    if not total:
        return None, 0, states
    return round(sum(SIGNAL_WEIGHT[st] * n for st, n in scored) / total, 2), total, states


def recovery(target):
    """How many RESOLVED closures lift our signal to `target` from where it stands, assuming nothing else closes.
    None when unknown. This is the number the whole account is working towards, so it is stated as a number."""
    sig, n, _ = own_signal()
    if sig is None or target is None:
        return None
    total = sig * n
    k = 0
    while (total + 7.0 * k) / (n + k) < float(target) and k < 50:
        k += 1
    return k


def name_match(program, text):
    """Descoped / no-bounty rows whose asset NAME appears in free text (a slug, a title, a crown line). For the
    assets that have no host at all - 'Desktop Client', a repo - which the host gate cannot see and which
    is exactly where a package was built against a descoped row."""
    t = re.sub(r"[^a-z0-9]+", " ", (text or "").lower())
    hits = []
    for r in scope_rows(program):
        if not (r.get("descoped") or r.get("submit") is False or r.get("bounty") is False):
            continue
        words = [w for w in re.sub(r"[^a-z0-9]+", " ", r["asset"].lower()).split() if len(w) >= 4]
        if words and all(f" {w} " in f" {t} " for w in words):
            hits.append(r)
    return hits


def filing_gate(program, offline=False, title=None):
    """(ok, why): can THIS account file a report on THIS program today? False for a closed program and for a
    granular-signal program whose target our closed record does not meet (T-254: the API answers a bare 403 and the
    web form the same wall). ok with a caveat for a VDP (offers_bounties=false). Unknown venues and unreachable
    platforms are ok-with-a-note: this gate refuses on facts, never on missing data.

    `title` is the candidate report's title. On an API-less venue it is checked against our own filed-report
    list (gnoc_venue), because a venue with no API cannot be deduped any other way."""
    if not _ok_program(program):
        return False, f"{program!r} is not a program handle"
    venue = _venue(program)
    if venue != "hackerone":
        # An API-less venue has no feed and no API, so the ONLY record of what we already filed there is
        # our own logged-in report list. Refusing without it is refusing on a fact (2026-10-28 receipt:
        # one program-64 finding filed three times, closed Not Applicable twice first).
        vok, vwhy = gnoc_venue.check(program, venue, title=title)
        if not vok:
            return False, vwhy
        return True, (f"venue {venue}: no signal gate known for it; check the platform's own filing rules"
                      + (f"; {vwhy}" if vwhy else ""))
    team = h1_team(program, offline=offline)
    if not team:
        return True, "HackerOne team flags unknown (no cache and no answer): file with care, T-254 not checked"
    notes = []
    if team.get("submission_state") not in (None, "open"):
        return False, f"{program} submission_state is {team.get('submission_state')!r}: it takes no reports"
    if team.get("offers_bounties") is False:
        notes.append("offers_bounties=false: a VDP, no payout")
    if team.get("identity_required"):
        notes.append("identity verification required to submit")
    if team.get("granular_signal"):
        target = team.get("target_signal")
        sig, n, states = own_signal()
        stale = SIGNAL_INFO.get("age_days")
        stale_note = (f" (pull {SIGNAL_INFO.get('day')}, {stale:.0f} d old: run scripts/h1-feedback/sync.sh)"
                      if stale is not None and stale > 3 else "")
        pending = states.get("new", 0) + states.get("triaged", 0) + states.get("needs-more-info", 0)
        if sig is None:
            notes.append(f"granular signal gate ON (target {target}); our signal is unknown - run "
                         "scripts/h1-feedback/sync.sh before spending a filing")
        elif target is not None and sig < float(target):
            k = recovery(target)
            return False, (f"HELD ON SIGNAL (T-254): {program} enforces target signal {target} on every channel and "
                           f"our closed record scores {sig} over {n} reports{stale_note}. The platform refuses report "
                           "creation; evidence cannot fix this. "
                           + (f"{k} resolved closure(s) elsewhere would clear it" if k else "")
                           + (f"; {pending} of ours still open" if pending else "")
                           + ". Hunt a program that takes our reports, or park the finding")
        else:
            notes.append(f"granular signal gate ON, target {target}, ours {sig} ({n} scored): clears{stale_note}")
    return True, "; ".join(notes) or "open, bounties on, no signal gate"


# ---------------------------------------------------------------- the one-paragraph answer

def summary(program, offline=False):
    """What set_program / hunt_brief print: the money shape of the scope and whether we can file at all."""
    if not _ok_program(program):
        return ""
    any_b, b, nb, ds = program_pays(program)
    rows = scope_rows(program)
    if not rows:
        return f"PAYABILITY: no scope rows on disk for {program}."
    src = "platform API pull" if any(r["src"] == "api" for r in rows) else "annotated SCOPE.txt"
    line = (f"PAYABILITY ({src}): {b} bounty row(s), {nb} no-bounty, {ds} descoped/not-submittable. "
            + ("Aim at the bounty rows; a no-bounty host still counts for a VDP filing but never pays."
               if any_b else ("NO ROW PAYS: findings here are VDP filings, not income." if any_b is False
                              else "no bounty tags on file: verify the reward table before drafting.")))
    ok, why = filing_gate(program, offline=offline)
    line += "\nFILING: " + ("ok - " if ok else "BLOCKED - ") + why
    if ds:
        bad = [r["asset"] for r in rows if r["descoped"] or r["submit"] is False][:6]
        line += "\nNEVER DRAFT AGAINST: " + ", ".join(bad) + (" ..." if ds > 6 else "")
    return line


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:] or ["globex"]:
        print(f"== {p}")
        print(summary(p))
        for h in sys.argv[2:3]:
            print(payability(p, h))
