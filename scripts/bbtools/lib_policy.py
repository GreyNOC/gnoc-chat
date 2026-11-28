#!/usr/bin/env python3
"""lib_policy - T-156 (automation ban) + per-program rate + identification header, as code, in ONE place.

    from bbtools import lib_policy
    p = lib_policy.policy("program-60")
    if not p["network_ok"]:
        sys.exit(f"REFUSED: {p['status']} {p['evidence']}")

policy(program) -> {"status": "BANNED"|"ALLOWED"|"NO-POLICY", "evidence": "<PROGRAM.md:line text>",
                    "rps_stated": float|None, "rps": float, "header": ["X-HackerOne", "<handle>"] | None,
                    "network_ok": bool, "override": "<line>"|None}

Rules (fail closed):
  - no PROGRAM.md -> NO-POLICY, network_ok False (T-156 cannot be checked).
  - any ban phrase on any PROGRAM.md line -> BANNED; the first matching line is the evidence.
  - Immunefi venue (named in the first 4000 chars) -> network_ok False (fork-PoC venue, no web sweeping).
  - override file .claude/state/oss-bot/policy-overrides.txt: "<program> ban <why>" or
    "<program> allow <the user quote + date>"; ban always wins over allow; allow lines are the user's call only.
  - rps = min(3.0, 0.5 * stated) when PROGRAM.md states a rate, else 3.0; floor 0.5.

CLI: --selfcheck (offline regex fixtures, incl. the three 2026-10-21 F1 misses), --all (TSV table:
program, status, rps, header, evidence), or a program name. Stdlib only.
"""
from __future__ import annotations
import os
import re
import sys

WS_ROOT = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OVERRIDES = os.path.join(WS_ROOT, ".claude/state/oss-bot/policy-overrides.txt")
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")

BAN_RES = [re.compile(r, re.I) for r in (
    # the two auto-hunt.py alternatives, verbatim
    r"(automated (scanning|tools?|testing)|scanners?)[^.\n]{0,40}(prohibited|not (allowed|permitted)|forbidden|banned)",
    r"(do not|don't|must not)[^.\n]{0,20}(use )?(automated|scanners?)",
    # 2026-10-21 additions (F1: program-91, program-56, umbrella were missed)
    r"\bno automated (scann|scanner|tool|test)",
    r"automated scanners?,?\s*(tools?,?\s*)?(and the like\s*)?(is|are)\s*(strictly\s*)?(disallowed|prohibited|forbidden|not (allowed|permitted))",
    r"(scanners?|automated (tools?|scanning))[^.\n]{0,60}(disallowed|will (result|lead) in|disqualif|suspen)",
    # 2026-10-21 harmony 2.1: the two AI-agent alternatives from auto-target.BAN_RE, verbatim (program-87:116).
    # auto-target's `bots?` alternatives are deliberately NOT ported: their false-ban rate is unmeasured.
)]
# An AI-AGENT ban is categorically different from a SCANNER ban and must stay a HARD block: the programme
# is refusing US, not a tool we chose. These two alternatives used to sit in BAN_RES with the scanner
# patterns, so both produced the same total network block (2026-10-21 harmony 2.1, from auto-target.BAN_RE,
# program-87:116).
AGENT_BAN_RES = [re.compile(r, re.I) for r in (
    r"(prohibit|forbid|ban|not allow)[^.\n]{0,40}(ai agents?|llms?|large language|generative ai|third-party (llm|ai))",
    r"(ai agents?|llms?|generative ai)[^.\n]{0,40}(prohibited|not (allowed|permitted)|forbidden|banned)",
    # QAQC 2026-11-19: "Do not use AI agents", "AI tools may not be used", "The use of artificial intelligence is
    # prohibited", "No AI agents.", "Autonomous agents are not permitted" all passed. Measured on every PROGRAM.md
    # at the time: no program changed state (no new false bans).
    r"\b(do not|don't|must not|may not|cannot|can't|shall not|are not allowed to|is not allowed to)\s+(use\s+)?"
    r"(any\s+)?(ai|a\.i\.|artificial intelligence|llms?|autonomous|ai[- ](powered|driven|based|assisted))\b",
    r"\b(ai|artificial intelligence|autonomous|llm|ai[- ](powered|driven|based|assisted))[- ]?(agents?|tools?|testing|"
    r"bots?|hackers?|scanners?)[^.\n]{0,40}\b(may not|must not|cannot|can't|are not|is not|aren't|isn't)\s+(be\s+)?"
    r"(used|allowed|permitted|accepted)",
    r"\buse of (ai|artificial intelligence|llms?|autonomous)[^.\n]{0,40}(prohibited|not (allowed|permitted)|forbidden|"
    r"banned|disallowed)",
    r"\bno (ai|llm|autonomous|ai[- ]powered)[- ]?(agents?|tools?|testing|bots?|hacking)\b",
)]
RPS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(?:requests?|reqs?|rps)?\s*(?:/|per)\s*(second|sec|s|minute|min)\b", re.I)
# A DIRECTIVE, NOT A MENTION (2026-11-04, program-74). The alternation used to list only the VENUE names, so
# it matched program-74 PROGRAM.md:47 "Bugcrowd mandates no platform-wide identification header (unlike
# HackerOne's `X-HackerOne:`)" - a sentence saying the header must NOT be sent - and missed the real
# directive on the next line, "X-Bug-Bounty: BugCrowd-<username>", because "Bug-Bounty" names no venue.
# The harness then sent an unrequested X-HackerOne and NOT the header their penalty-stacking clause prices
# at up to 50% of the bounty. Two fixes: "Bug-?Bounty" joins the alternation, and the match must be
# followed by something that looks like a VALUE (so `X-HackerOne:` in prose with a backtick after it does
# not qualify), then a negated mention is dropped in header_directive().
HDR_RE = re.compile(r"\b(X-(?:[A-Za-z0-9-]*-)?(?:HackerOne|Bugcrowd|Bug-?Bounty|Intigriti|YesWeHack|YWH|Researcher)"
                    r"[A-Za-z0-9-]*)\s*:", re.I)
# The same directive written as prose, with no colon: program-98 PROGRAM.md:61 "Every request must include the
# X-Bugcrowd header with Bugcrowd username for e.g: Bugcrowd-<Username>". HDR_RE alone missed it, so the
# harness sent program-98 NO identification header while its brief says EVERY request must carry one (2026-11-06).
HDR_WORD_RE = re.compile(r"\b(X-(?:[A-Za-z0-9-]*-)?(?:HackerOne|Bugcrowd|Bug-?Bounty|Intigriti|YesWeHack|YWH|"
                         r"Researcher)[A-Za-z0-9-]*)`?\s+header\b", re.I)
# "no X-Bug-Bounty header", "unlike HackerOne's X-HackerOne", "do not send X-...": a mention that forbids
# or contrasts the header. Checked within the 60 chars BEFORE a match, since English leads with the
# negation ("Bugcrowd mandates no ... header (unlike HackerOne's `X-HackerOne:`)").
# LEADING WORD BOUNDARY MATTERS: "never" must not match inside "whenever" (measured: program-60's REAL
# directive "include your HackerOne username ... whenever feasible using a custom header: X-HackerOne:"
# was dropped as a negation until the \b went in front).
_HDR_NEG_RE = re.compile(r"\b(no|not|unlike|cannot|can't|isn't|aren't|without|do not|don't|never|"
                         r"no longer|instead of|rather than|in contrast)", re.I)
# MANY PROGRAMMES CARRY THEIR IDENTIFICATION IN THE USER-AGENT, NOT IN A HEADER, and HDR_RE is blind to
# those. program-72:45 "add the following User-Agent header ... User-agent: hackerone -. Requests that will
# not contain this ... might get blocked by our tools/SOC team"; program-62:27 'Append the string
# "bugbounty" to your user agent'; program-55 wants `vendorresearcher_<handle>`. Missing the literal is
# not cosmetic: the programme says it will BLOCK you, and the agent then reads its own 403s as a hard
# target. Captured 2026-10-28: a /hunt program-72 run sent X-HackerOne (never asked for) and NOT the UA
# literal, and every one of its 20+ probes came back 403 len=716.
QUOTES = "\"'\u201c\u201d\u2018\u2019`"
# Two shapes, in priority order, and the COLON form must win: program-72's line carries BOTH a prose
# mention ("add the following User-Agent header ... - ") and the real directive ("User-agent: hackerone"),
# and a dash-tolerant pattern captured the words "User-agent" instead of the literal.
UA_COLON_RE = re.compile(r"user[-\s]?agent\s*[:=]\s*[" + QUOTES + r"]?([A-Za-z0-9_][A-Za-z0-9_.<>-]{2,40})", re.I)
UA_APPEND_RE = re.compile(
    r"(?:append|add|include|suffix)[^.\n]{0,40}?[" + QUOTES + r"]([A-Za-z0-9_][A-Za-z0-9_.<>-]{2,40})["
    + QUOTES + r"][^.\n]{0,60}?user[-\s]?agent", re.I)
UA_STOPWORDS = {"header", "headers", "string", "your", "the", "any", "all", "when", "using", "please",
                "requests", "request", "name", "value", "following", "tools", "scripts", "agent",
                "user-agent", "useragent", "user", "agents"}


def _ua_ok(tok):
    tok = (tok or "").strip().strip(".,;:-" + QUOTES)
    if not tok or tok.lower() in UA_STOPWORDS or tok.lower().startswith("x-"):
        return None
    if re.fullmatch(r"user[-\s]?agent", tok, re.I):
        return None
    return tok


def ua_literal(text: str):
    """The literal a programme wants carried in the User-Agent, else None.

    Returns the TOKEN only; the caller splices it into a real browser UA. A bare literal as the whole
    UA is usually wrong: program-72's own JS bootstrap breaks on a UA of exactly "hackerone", so the house
    rule is a real Chrome UA ENDING in the literal.
    """
    for ln in (text or "").splitlines():
        low = ln.lower()
        if "user" not in low and "agent" not in low:
            continue
        for rx in (UA_COLON_RE, UA_APPEND_RE):     # colon form first: it is the actual directive
            for m in rx.finditer(ln):
                tok = _ua_ok(m.group(1))
                if tok:
                    return tok
    return None
IMMUNEFI_RE = re.compile(r"immunefi", re.I)
# a bare "immunefi" hit inside a negation window ("no X/Y/Immunefi intermediary", "not on Immunefi",
# "unlike Immunefi") is a program DISTINGUISHING itself from Immunefi, not an Immunefi program -
# 2026-10-21, caught on program-92: PROGRAM.md's own "no HackerOne/.../Immunefi intermediary" line
# false-positived the venue gate and silently refused every automated lane for a self-hosted program.
IMMUNEFI_NEG_RE = re.compile(r"\b(no|not|non-?|without|unlike|rather than|isn.?t|aren.?t)\b[^.]{0,60}$", re.I)
H1_SCOPE_RE = re.compile(r"hackerone", re.I)


def handle() -> str:
    """HACKERONE_HANDLE from secrets.env (moved from auto-hunt.py), else the environment, else "". Reads only that
    key; never echoes others. There is NO built-in fallback: it used to be the operator's own handle, so every
    other install would have identified its probes as someone else (2026-11-19)."""
    try:
        with open(SECRETS, encoding="utf-8") as fh:
            for ln in fh:
                if ln.strip().startswith(("HACKERONE_HANDLE", "export HACKERONE_HANDLE")):
                    return ln.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass
    return (os.environ.get("HACKERONE_HANDLE") or os.environ.get("GNOC_H1_HANDLE") or "").strip()


def ban_line(text: str):
    """(lineno, line) of the first line carrying a SCANNER/automated-tooling ban phrase, else None."""
    for i, ln in enumerate(text.splitlines(), 1):
        if any(rx.search(ln) for rx in BAN_RES):
            return i, ln.strip()
    return None


def agent_ban_line(text: str):
    """(lineno, line) of the first line that forbids AI AGENTS or LLMs from testing, else None.
    This is the only ban that stops us touching the target at all: it refuses the researcher, not a tool."""
    for i, ln in enumerate(text.splitlines(), 1):
        if any(rx.search(ln) for rx in AGENT_BAN_RES):
            return i, ln.strip()
    return None


def stated_rps(text: str):
    vals = []
    for m in RPS_RE.finditer(text):
        n = float(m.group(1))
        unit = m.group(2).lower()
        vals.append(n / 60.0 if unit.startswith("min") else n)
    vals = [v for v in vals if v > 0]
    return min(vals) if vals else None


def _overrides(program: str, path: str = OVERRIDES):
    ban = allow = None
    try:
        with open(path, encoding="utf-8") as fh:
            for ln in fh:
                s = ln.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split(None, 2)
                if len(parts) >= 2 and parts[0] == program:
                    if parts[1] == "ban" and ban is None:
                        ban = s
                    elif parts[1] == "allow" and allow is None:
                        allow = s
    except OSError:
        pass
    return ban, allow


def evaluate(program: str, text, scope_head: str = "", overrides=(None, None), hdl: str | None = None) -> dict:
    """Pure decision on already-read inputs (text None = PROGRAM.md missing)."""
    hdl = hdl or handle()
    ban_ov, allow_ov = overrides
    out = {"status": "ALLOWED", "evidence": "", "rps_stated": None, "rps": 3.0, "header": None,
           "network_ok": False, "scanners_ok": True, "ua_literal": None, "override": None}
    if text is None:
        out.update(status="NO-POLICY", evidence=f"targets/{program}/PROGRAM.md missing")
    else:
        # ORDER MATTERS: an AI-agent ban outranks a scanner ban, because only the first one refuses US.
        ahit = agent_ban_line(text)
        if ahit:
            out.update(status="AGENT-BANNED", scanners_ok=False,
                       evidence=f"targets/{program}/PROGRAM.md:{ahit[0]} {ahit[1]}")
        else:
            hit = ban_line(text)
            if hit:
                # 2026-10-28: this used to be status BANNED with network_ok False, which stopped the agent
                # sending a SINGLE crafted GET to a programme whose policy only bans Nessus and Acunetix.
                # Measured: 10 of 132 intaken programmes were fully unreachable that way, and 9 of the 10
                # ban scanners rather than us - including two outright misreads, one program's "do not REPORT
                # using automated scanner output" (a reporting rule) and another program's "keep automated testing
                # to the minimum needed to demonstrate" (permission WITH a limit, inverted into a ban).
                # Worse, the two gates contradicted each other: _scan_gate refuses the scanners with the
                # message "Hunt it by hand (probe_matrix / crafted http_request) instead", and _program_gate
                # then refused exactly that. A scanner ban constrains the TOOL and the RATE, not the leg.
                out.update(status="SCANNERS-BANNED", scanners_ok=False,
                           evidence=f"targets/{program}/PROGRAM.md:{hit[0]} {hit[1]}")
        rs = stated_rps(text)
        out["rps_stated"] = rs
        out["rps"] = round(max(0.5, min(3.0, 0.5 * rs)) if rs else 3.0, 3)
        hname = header_directive(text)
        if hname:
            # THE VALUE SHAPE IS PART OF THE DIRECTIVE. X-Bug-Bounty takes "<Venue>-<username>"
            # ("X-Bug-Bounty: BugCrowd-<username>", program-74 PROGRAM.md:48); X-HackerOne takes the bare
            # handle. A bare handle in X-Bug-Bounty loses the attribution their clause prices.
            val = hdl
            if hname.lower().startswith("x-bug") and hdl and not re.match(r"(bugcrowd|hackerone|intigriti|"
                                                                        r"yeswehack)", hdl, re.I):
                # mirror the brief's own spelling of the prefix when it gives one ("Bugcrowd-<Username>")
                ex = re.search(r"\b(Bug-?Crowd)-<", text, re.I)
                val = (ex.group(1) if ex else "BugCrowd") + "-" + hdl
            # no handle set: no identification header at all, never someone else's or an empty one
            out["header"] = [hname, val] if hdl else None
            if not hdl:
                out["needs_handle"] = hname
    out["ua_literal"] = ua_literal(text) if text else None
    # THE BLANKET FALLBACK IS GONE (T-294, 2026-10-28). It used to read "this SCOPE.txt came from the
    # HackerOne API" as "this programme wants an X-HackerOne header", which added an identification header
    # to 81 of 132 intaken programmes while only 21 policies name one. Our own killrule says an
    # unrequested X-HackerOne-Handle 403'd 25+ program-95 hosts and CORS-broke program-0's SPA, and HARNESS.md
    # says plainly: IF THE PROGRAMME'S POLICY ASKS FOR NO HEADER, SEND NO HEADER. An unrequested header is
    # an unusual request attribute that a WAF fingerprints, and the agent then reads the block as a dead
    # estate. Only a header the POLICY names is sent now.
    if ban_ov:  # an operator ban always wins, and it is the hard kind
        out.update(status="AGENT-BANNED", scanners_ok=False, override=ban_ov,
                   evidence=out["evidence"] or f"override: {ban_ov}")
    elif allow_ov and out["status"] in ("SCANNERS-BANNED", "AGENT-BANNED"):
        # allow flips only a REGEX ban; never a missing PROGRAM.md
        out.update(status="ALLOWED", scanners_ok=True, override=allow_ov)
    immunefi = False
    if text is not None:
        head4k = text[:4000]
        m = IMMUNEFI_RE.search(head4k)
        immunefi = bool(m) and not IMMUNEFI_NEG_RE.search(head4k[:m.start()])
    if immunefi and not out["evidence"]:
        out["evidence"] = "Immunefi venue: no web sweeping"
    out["network_ok"] = out["status"] in ("ALLOWED", "SCANNERS-BANNED") and not immunefi
    if immunefi:
        out["scanners_ok"] = False
    return out



# ---------- EXCLUDED FUNCTIONALITY ----------
# The scope gate checks HOSTS. Nothing checked what the programme put OUT OF SCOPE by FUNCTION, so an agent
# could spend a whole budget on a surface the programme will not read. Measured 2026-10-28: a /hunt program-72
# session fired ~40 probes at /ro/user/register while program-72's PROGRAM.md line 10 reads
# "***All our LOGIN services are out of scope for the moment." The brief printed that line and nothing acted
# on it. This is a WARNING, never a block: "LOGIN services" may or may not cover registration, and that
# judgement is the hunter's. It just has to be made deliberately instead of by accident.
_EXCL_MARKERS = re.compile(r"out[- ]of[- ]scope|not in scope|excluded|will not be (accepted|rewarded)|"
                           r"do not (report|test|target)|no bount(y|ies) (for|on)", re.I)
# generic words that would match almost any hypothesis and so carry no signal
_EXCL_STOP = {
    "the", "and", "for", "are", "our", "all", "any", "not", "out", "scope", "this", "that", "with", "from",
    "you", "your", "will", "please", "issues", "issue", "vulnerability", "vulnerabilities", "report",
    "reports", "reporting", "considered", "following", "moment", "review", "policy", "page", "attack",
    "attacks", "security", "impact", "bug", "bugs", "service", "services", "functionality", "unless",
    "without", "being", "able", "which", "their", "them", "when", "have", "has", "can", "may", "should",
    "accepted", "rewarded", "excluded", "testing", "test", "tests", "use", "using", "user", "users",
}


def exclusion_lines(text: str):
    """Policy lines that put something OUT OF SCOPE, as (lineno, line)."""
    out = []
    for i, ln in enumerate((text or "").splitlines(), 1):
        t = ln.strip()
        if len(t) > 12 and _EXCL_MARKERS.search(t):
            out.append((i, t))
    return out


# A policy says "LOGIN services"; a hypothesis says "/ro/user/register". Same family, zero shared tokens,
# so a bare intersection misses it - measured on program-72, where the agent went back to the registration
# route one turn after being told login was out of scope. Expanding the POLICY side (not the hypothesis
# side) keeps this conservative: the families below only widen what the programme itself named.
_EXCL_SYNONYMS = {
    "login": {"signin", "sign-in", "signup", "sign-up", "register", "registration", "authentication",
              "authenticate", "logout", "password", "credential", "credentials", "session", "otp", "mfa",
              "2fa", "captcha"},
    "social": {"friend", "friends", "follow", "follower", "share", "sharing", "comment", "feed", "profile"},
    "registration": {"register", "signup", "sign-up", "login"},
    "authentication": {"login", "signin", "signup", "register", "password", "otp", "mfa", "2fa"},
    "bruteforce": {"brute", "brute-force", "rate", "ratelimit", "rate-limit", "enumeration"},
    "spam": {"mail", "email", "sms", "flood", "bomb"},
    "dos": {"denial", "flood", "exhaustion", "resource"},
}


def _terms(t):
    # NO "/" in the class: with it, "/ro/user/register" became the single token "ro/user/register" and never
    # matched the policy's "login" family. A URL path has to split into its segments to be comparable to prose.
    return {w for w in re.findall(r"[a-z][a-z0-9_-]{3,}", (t or "").lower()) if w not in _EXCL_STOP}


def _expand(terms):
    """The policy's own terms plus the families they name. Never expands the hypothesis side."""
    out = set(terms)
    for w in terms:
        out |= _EXCL_SYNONYMS.get(w, set())
    return out


def excluded_match(program: str, text: str, root: str = WS_ROOT, limit: int = 3):
    """[(lineno, line, [shared terms])] for exclusion lines this text appears to touch.

    Deliberately conservative: it needs a shared DISTINCTIVE term, and generic security words are stopped,
    so an ordinary hypothesis does not trip it. The caller warns and quotes the line; it never blocks.
    """
    d = os.path.join(root, "targets", program)
    parts = []
    for name in ("PROGRAM.md", "policy.md"):
        try:
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read())
        except OSError:
            pass
    if not parts:
        return []
    want = _terms(text)
    if not want:
        return []
    hits = []
    for lineno, ln in exclusion_lines("\n".join(parts)):
        shared = sorted(want & _expand(_terms(ln)))
        if shared:
            hits.append((lineno, ln[:180], shared))
    hits.sort(key=lambda h: -len(h[2]))
    return hits[:limit]

def header_directive(text: str) -> str | None:
    """The identification HEADER NAME a policy actually asks us to send, or None.

    Skips a mention that forbids or contrasts the header, so a policy that says "we do NOT want
    X-HackerOne" yields None instead of a header. The negation is looked for in the SAME clause only
    (back to the previous newline or sentence end): a "no" three sentences earlier must not veto a
    real directive, and a directive on its own line after "custom header:" is never negated.
    Returns the name as written.
    """
    if not text:
        return None
    for m in sorted(list(HDR_RE.finditer(text)) + list(HDR_WORD_RE.finditer(text)), key=lambda x: x.start()):
        clause = text[max(0, m.start() - 90):m.start()]
        cut = max(clause.rfind("\n"), clause.rfind(". "), clause.rfind("; "))
        if cut >= 0:
            clause = clause[cut + 1:]
        if _HDR_NEG_RE.search(clause):
            continue
        # A colon with NO VALUE, closed at once by a backtick, quote or bracket ("see the `X-HackerOne:`
        # docs page"), names the header without asking for it. HDR_RE's comment always promised this; the
        # check was never written, so selfcheck failed on it. A colon at END OF LINE still counts: the
        # value may sit on the next line ("using a custom header: X-HackerOne:" then the handle).
        if m.re is HDR_RE and _HDR_NOVALUE_RE.match(text, m.end()):
            continue
        return m.group(1)
    return None


_HDR_NOVALUE_RE = re.compile(r"[ \t]*[`'\"’”)\]]")


def policy(program: str, root: str = WS_ROOT) -> dict:
    d = os.path.join(root, "targets", program)
    # READ BOTH FILENAMES. HARNESS.md says it plainly: "Some programmes have no PROGRAM.md, only
    # policy.md - check both." The loader only ever opened PROGRAM.md, so 35 intaken programmes that
    # carry a real policy.md were scored NO-POLICY and had network_ok False, i.e. the agent could not
    # send them a single request AND could not see their rate limits or identification carrier. program-62
    # is one of them, and its policy.md:27 is the line that mandates the "bugbounty" User-Agent literal.
    # Concatenated rather than first-wins, so a ban or a carrier in EITHER file is honoured.
    parts = []
    for name in ("PROGRAM.md", "policy.md"):
        try:
            with open(os.path.join(d, name), encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read())
        except OSError:
            pass
    text = "\n".join(parts) if parts else None
    try:
        with open(os.path.join(d, "SCOPE.txt"), encoding="utf-8", errors="replace") as fh:
            head = fh.read(2000)
    except OSError:
        head = ""
    return evaluate(program, text, head, _overrides(program))


def selfcheck() -> None:
    ban = [
        "Use of automated scanners, tools, and the like is strictly disallowed",          # program-91:109
        "No automated scanners (e.g., Nuclei) or bulk discovery scans.",                    # program-56:79
        "No Automated Scanning: do not run automated scanners against our assets.",        # umbrella:138
        "Automated scanning is prohibited.",
        "Do not use automated tools against production.",
        "Use of scanners will result in a permanent ban.",
    ]
    # An AI-agent ban is the ONLY kind that stops us touching the target: it refuses the researcher.
    agent_ban = [
        "We prohibit any AI agents from searching for vulnerabilities",                     # program-87:116
        "LLMs are not permitted to test this scope.",
        "Generative AI is forbidden for vulnerability discovery.",
    ]
    ok = [
        "If using automated scanning tools, include your HackerOne username in requests",  # program-60
        "Avoid excessive automated scanning; keep requests to 10 per second or lower.",    # program-65
        "Do not perform denial of service attacks.",
        "Reports written with the help of AI must be verified by the researcher",
    ]
    for s in ban:
        assert ban_line(s), f"ban phrase missed: {s}"
        assert not agent_ban_line(s), f"scanner ban misread as an AGENT ban: {s}"
    for s in agent_ban:
        assert agent_ban_line(s), f"agent ban phrase missed: {s}"
    for s in ok:
        assert not ban_line(s), f"false ban: {s}"
        assert not agent_ban_line(s), f"false agent ban: {s}"
    assert stated_rps("no more than 2 requests per second") == 2.0
    assert stated_rps("within 5 requests per second (300 requests per minute)") == 5.0
    assert stated_rps("limit 60 req/min") == 1.0
    assert stated_rps("no rate stated") is None
    e = lambda t, **k: evaluate("px", t, hdl="h", **k)
    assert e("2 requests per second")["rps"] == 1.0
    assert e("3 requests per second")["rps"] == 1.5
    assert e("10 per second")["rps"] == 3.0
    assert e("1 request per minute")["rps"] == 0.5                  # floor
    assert e("nothing")["rps"] == 3.0 and e("nothing")["network_ok"]
    assert e(None)["status"] == "NO-POLICY" and not e(None)["network_ok"]
    assert e("x\nNo automated scanners here.")["evidence"] == "targets/px/PROGRAM.md:2 No automated scanners here."
    # 2026-10-28 THE SPLIT. A scanner ban constrains the TOOL, not the leg: the agent may still send a
    # single crafted request, which is what _scan_gate's own refusal text tells it to do. Only an
    # AI-agent ban closes the network. Before this, 10 of 132 intaken programmes were fully unreachable
    # and 9 of them banned scanners rather than us.
    sc = e("x\nDo not use Scanners such as Nessus, acunetix, etc.")                    # program-72:9
    assert sc["status"] == "SCANNERS-BANNED", sc["status"]
    assert sc["network_ok"] is True, "a scanner ban must NOT close the network leg"
    assert sc["scanners_ok"] is False, "a scanner ban must still block the scanners"
    ab = e("x\nWe prohibit any AI agents from searching for vulnerabilities")          # program-87:116
    assert ab["status"] == "AGENT-BANNED", ab["status"]
    assert ab["network_ok"] is False, "an AI-agent ban MUST close the network leg"
    assert ab["scanners_ok"] is False
    # an agent ban outranks a scanner ban when a policy carries both
    both = e("No automated scanners.\nWe prohibit any AI agents from testing.")
    assert both["status"] == "AGENT-BANNED" and not both["network_ok"]
    assert e("nothing")["scanners_ok"] is True
    assert e("send X-HackerOne: your_username")["header"] == ["X-HackerOne", "h"]
    # 2026-11-04 program-74: a DIRECTIVE, NOT A MENTION. PROGRAM.md:47 says Bugcrowd mandates no
    # platform-wide header and names X-HackerOne only to CONTRAST it; :48 is the real directive,
    # "X-Bug-Bounty: BugCrowd-<username>". Before the fix the harness sent an unrequested X-HackerOne
    # and not the mandated header (worth up to 50% of the bounty under their penalty stacking).
    _tm = ("- Bugcrowd mandates no platform-wide identification header (unlike HackerOne's `X-HackerOne:`).\n"
           "- The brief text mentions a header/User-Agent requirement - READ THESE BEFORE PROBING:\n"
           "    - X-Bug-Bounty: BugCrowd-<username>\n")
    assert e(_tm)["header"] == ["X-Bug-Bounty", "BugCrowd-h"], e(_tm)["header"]
    # the value shape: X-Bug-Bounty takes <Venue>-<handle>, not the bare handle. The prefix mirrors the
    # brief's own spelling when it gives one (evaluate(), "Bugcrowd-<Username>" on program-98); with no spelled
    # prefix it defaults to BugCrowd-. This line used to expect BugCrowd- for a brief spelling "Bugcrowd-",
    # which predates the mirror rule and contradicted the program-98 assertion below.
    assert e("send X-Bug-Bounty: Bugcrowd-<username>")["header"][1] == "Bugcrowd-h"
    assert e("send X-Bug-Bounty: <username>")["header"][1] == "BugCrowd-h"
    # program-98 PROGRAM.md:61: the directive in prose, no colon, value prefix spelled "Bugcrowd-"
    _rp = e("- Every request must include the X-Bugcrowd header with Bugcrowd username for e.g: Bugcrowd-<Username>'")
    assert _rp["header"] == ["X-Bugcrowd", "Bugcrowd-h"], _rp["header"]
    assert e("We do not want an X-Bugcrowd header on requests.")["header"] is None
    # a negation-only mention yields NO header (the T-294 rule: unrequested headers are a WAF fingerprint)
    assert e("send no X-HackerOne: header on any request")["header"] is None
    assert e("Unlike Bugcrowd's X-Bug-Bounty: we do not need it")["header"] is None
    # prose that names a header with no value after the colon is a mention, not a directive
    assert e("see the `X-HackerOne:` docs page")["header"] is None
    # 2026-10-28 T-294: a SCOPE.txt pulled from the HackerOne API is NOT a request for an identification
    # header. This used to add one to 81 of 132 intaken programmes while only 21 policies name one, and an
    # unrequested header is a WAF fingerprint that has already faked a dead estate for us twice.
    assert e("plain", scope_head="# auto-pulled from HackerOne API")["header"] is None
    # the USER-AGENT carrier, which HDR_RE is blind to and which several programmes use instead
    assert ua_literal("Please add the following User-Agent header when you are using any automated tools "
                      "or scripts - User-agent: hackerone -. Requests that will not contain") == "hackerone"
    assert ua_literal('* **Append the string \u201cbugbounty\u201d to your user agent for all traffic**') == "bugbounty"
    assert ua_literal("no mention here") is None
    assert ua_literal("set your User-Agent header appropriately") is None   # prose, not a literal
    assert e("User-agent: hackerone")["ua_literal"] == "hackerone"
    assert e("plain")["header"] is None
    assert not e("This is an Immunefi program.")["network_ok"]
    # 2026-10-21 program-92 false positive: self-hosted program distinguishing itself FROM Immunefi
    assert e("No HackerOne/Bugcrowd/Intigriti/YesWeHack/Immunefi intermediary.")["network_ok"]
    assert e("Unlike Immunefi, this program pays in BTC directly.")["network_ok"]
    b = "Automated scanning is prohibited."
    assert e(b, overrides=(None, "px allow quote 2026-10-21"))["status"] == "ALLOWED"
    assert e(b, overrides=("px ban x", "px allow y"))["status"] == "AGENT-BANNED"   # operator ban wins, hard
    assert not e(b, overrides=("px ban x", "px allow y"))["network_ok"]
    assert e("fine", overrides=("px ban x", None))["status"] == "AGENT-BANNED"
    assert e(None, overrides=(None, "px allow y"))["status"] == "NO-POLICY"         # allow never lifts NO-POLICY
    print("lib_policy selfcheck: PASS")


def table(root: str = WS_ROOT) -> None:
    tdir = os.path.join(root, "targets")
    for p in sorted(os.listdir(tdir)):
        if not os.path.isdir(os.path.join(tdir, p)):
            continue
        r = policy(p, root)
        hdr = f"{r['header'][0]}: {r['header'][1]}" if r["header"] else "-"
        print(f"{p}\t{r['status']}\t{r['rps']}\t{hdr}\t{r['evidence'] or '-'}")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "--selfcheck":
        selfcheck()
    elif a[0] == "--all":
        table()
    else:
        import json
        print(json.dumps(policy(a[0]), indent=1))
