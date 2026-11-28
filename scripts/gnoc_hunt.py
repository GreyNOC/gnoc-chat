"""gnoc_hunt.py - the hunt harness behind `gnoc chat`: a per-program ledger, a capability graph, a chain search
ranked by prestige, evidence checks in code, and the phase director that tells the model what to do next.

Why it exists: a local 20B lead forgets what it tested once history is compacted, probes primitives in
isolation, and stops at a mechanism. This keeps the hunt's state on disk and turns SPINE 4 (ESCALATE + CHAIN)
and the proof-integrity rules into code the model cannot talk its way past.

On disk, one file per program (survives restarts, readable by any agent):
    targets/<program>/hunts/gnoc/ledger.json
        hypotheses  [{id, title, crown, assumption, violation, prediction, kill_byte, status, probes, burst,
                      evidence[], notes, ts}]
        edges       [{id, frm, to, via, status, evidence, must_contain, requires[], ts}]

Capability graph:
    nodes are capabilities: the starting points "unauth" (anonymous internet attacker) and "own-account" (an
    account the attacker self-provisions), CROWN nodes (rce, ato, cross-tenant, money, mass-pii, admin,
    auth-bypass, cross-user-write, cross-user-read, secret), and free-form intermediate capabilities
    ("leaked-internal-hostname", "csrf-token-of-victim", "ssrf-to-169.254"). An edge says: holding FRM, the
    primitive VIA gives you TO. A chain is a path from a starting point to a crown.
Prestige score of a chain = crown weight x product of edge confidence (proven 1.0, lead 0.6, hypothesized 0.3)
    x 0.7 if any edge needs victim interaction x 0.85 if it starts from own-account, minus length drag.
Code-enforced gates:
    - an edge is PROVEN only if its evidence file exists under the workspace, is non-empty, and (when given)
      contains must_contain; otherwise it is stored as a lead and the model is told why
    - a hypothesis can be marked dead only after 8 probes (the empirical floor), else it is recorded UNFIRED
    - a chain reaches SHIP only when every edge on it is proven
"""
import contextlib
import fcntl
import json
import urllib.parse
import os
import re
import threading
import time
from datetime import datetime, timezone

import gnoc_doctrine as DOC  # the expert knowledge layer: vocabulary, chain table, kill shapes, doctrine

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now, _read_n as _read

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
START = ("unauth", "own-account")
CROWNS = {"rce": 10, "ato": 9, "cross-tenant": 9, "money": 9, "mass-pii": 8, "admin": 8, "auth-bypass": 8,
          "cross-user-write": 7, "cross-user-read": 6, "secret": 6}
CROWN_ALIASES = {"account-takeover": "ato", "takeover": "ato", "remote-code-execution": "rce", "code-exec": "rce",
                 "money-movement": "money", "payment": "money", "pii": "mass-pii", "idor-write": "cross-user-write",
                 "idor-read": "cross-user-read", "privesc": "admin", "credential": "secret", "token": "secret",
                 "anonymous": "unauth", "unauthenticated": "unauth", "attacker-account": "own-account"}
CONF = {"proven": 1.0, "lead": 0.6, "hypothesized": 0.3}
STATUSES = ("open", "probing", "lead", "candidate", "dead", "unfired")
FLOOR = 8
# A victim ACTION. "zero-click" / "no-click" is the absence of one (the 2026-11-22 ATO objective), so the bare
# word click is matched only when it is not negated: scoring a zero-click chain at 0.7 and giving it CVSS UI:R
# made the harness prefer a one-click chain and overclaim user interaction on the one it was asked to find.
INTERACTION = re.compile(r"victim|(?<!zero[- ])(?<!no[- ])click|visit|user-interaction|ui:r|social", re.I)




def node(name):
    n = re.sub(r"[^a-z0-9.:/_-]+", "-", (name or "").strip().lower()).strip("-")
    n = CROWN_ALIASES.get(n, n)
    if n in CROWNS or n in START:
        return n
    # intermediate capabilities use the fixed precondition vocabulary so two lanes' edges actually pair
    return DOC.canon(n)


def path(program):
    return os.path.join(WS, "targets", program, "hunts", "gnoc", "ledger.json")


_LOCK = threading.RLock()
_HELD = threading.local()  # per-thread flock depth, see locked()


@contextlib.contextmanager
def locked(program):
    """One writer at a time per ledger, across threads (RLock) and processes (flock on a sidecar). Four bots
    saving at once with one shared .tmp name once counted 45 of 160 probes and left the ledger EMPTY three
    runs out of three, because a torn read loaded as {} and the next save wrote that back."""
    p = path(program)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with _LOCK:
        # RE-ENTRANT for the flock too (2026-10-23): the RLock lets one thread nest locked(), but a nested call
        # opened a SECOND descriptor on the sidecar and flock() blocked against our own first one (flock locks the
        # open file description, not the process): log_probe -> modify deadlocked the moment the writers were
        # serialized. Only the outermost entry per thread takes and releases the file lock.
        depth = getattr(_HELD, "depth", 0)
        if depth:
            _HELD.depth = depth + 1
            try:
                yield
            finally:
                _HELD.depth -= 1
            return
        with open(p + ".lock", "a") as lf:
            try:
                fcntl.flock(lf, fcntl.LOCK_EX)
                _HELD.depth = 1
                yield
            finally:
                _HELD.depth = 0
                fcntl.flock(lf, fcntl.LOCK_UN)


def load(program):
    d = None
    for attempt in range(5):  # a torn read (another process mid-replace) is retried, never taken as "empty"
        try:
            with open(path(program)) as f:
                d = json.load(f)
            break
        except OSError:
            d = {}
            break
        except ValueError:
            time.sleep(0.05 * (attempt + 1))
    if not isinstance(d, dict):
        d = {}
    d.setdefault("hypotheses", [])
    d.setdefault("edges", [])
    d.setdefault("imported", False)
    d.setdefault("model", {})
    _heal(d)
    return d


def _heal(d):
    """Self-heal on every load (fix 51, 2026-10-23): a second chat process on OLD code kept writing twin edges
    ("H2-edge" x5) and edges for hypotheses that no longer exist ("H5-edge") into the program-101 ledger between two of
    our purges. Whatever any writer puts on disk, a reader sees one edge per id (the strongest status, else the
    newest) and no edge whose H# hypothesis is absent. Hypothesis ids are deduped the same way (first wins)."""
    rank = {"hypothesized": 0, "lead": 1, "proven": 2}
    seen, hyps = set(), []
    for h in d.get("hypotheses") or []:
        k = str(h.get("id", "")).upper()
        if k and k in seen:
            continue
        seen.add(k)
        hyps.append(h)
    d["hypotheses"] = hyps
    ids = {str(h.get("id", "")).upper() for h in hyps}
    best = {}
    order = []
    for e in d.get("edges") or []:
        hyp = _edge_hyp({"id": e.get("id", "")})   # by ID only: a via that merely mentions "H1:" is not an orphan
        if hyp and hyp not in ids:
            continue
        k = str(e.get("id", "")).upper()
        if k not in best:
            best[k] = e
            order.append(k)
        else:
            prev = best[k]
            if (rank.get(e.get("status"), 0), e.get("ts", "")) >= (rank.get(prev.get("status"), 0), prev.get("ts", "")):
                best[k] = e
    d["edges"] = [best[k] for k in order]


def save(program, d):
    p = path(program)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = f"{p}.{os.getpid()}.{threading.get_ident()}.tmp"  # one tmp per writer, never a shared name
    with _LOCK:
        with open(tmp, "w") as f:
            json.dump(d, f, indent=1)
        os.replace(tmp, p)


def modify(program, fn):
    """Atomic read-modify-write: fn(ledger_dict) -> value, under the lock. Use this for any update that must
    not lose a concurrent writer's change (probe counts, burst marks, status flips)."""
    with locked(program):
        d = load(program)
        out = fn(d)
        save(program, d)
        return out


_EDGE_TITLE = re.compile(r"^\s*(h\d+-edge(-\d+)?|e\d+)\s*[:.-]", re.I)
_MOVE_TITLE = re.compile(r"^\s*(h\d+\s*[:.-]\s*)?(\(?\d\)?\s*[:.-]?\s*)?(the paired write|the partner bug|the missing "
                         r"context|what the disclosed thing unlocks|same defect,? higher.value asset|admin twin upgrade)",
                         re.I)

# ---------------------------------------------------------------- hypothesis quality gates (2026-10-25)
# Measured on the three richest ledgers (program-101 84 probes, program-32 60, program-0 54): the lead spent 40 probes on
# program-101 against app.example.com/api/v1/admin/twin, a route it invented, whose every answer was 403 len=35; two of its
# hypotheses PREDICTED that 403 ("HTTP 403 ... error_code:40003 confirming the LEAD"); program-0's one PROVEN edge
# unauth -> cross-user-read had kill byte '"ownerId":"<own-id>"', i.e. the identity reading its own profile; three
# program-101 titles started with another hypothesis id ("H5: ...", "H2-escalate: ..."); and one violation with no path at
# all ("malformed token accepted") was accepted. Each of those is now refused at add time with the fix named.
VERDICT_AT = 2 * FLOOR   # still "probing" past twice the floor = a verdict is owed, not another variant
WALL_SHARE = 0.75        # one refusal shape on this share of a route's probes, and never a 2xx = no surface (T-49)
WALL_MIN = 4             # probes on a route before it can be called a wall
WALL_HARD = 3 * WALL_MIN  # D57: never a 2xx/3xx on this many probes is a wall whatever the refusal mix (403 on GET
#                           and 405 on POST are two shapes of one absent surface: api.program-0.example/api/account, 36
#                           probes across H18, H26, H33, top share 0.56, drive cycle 21 2026-10-26 08:10Z)
SURFACE_TURNS = 2        # directive turns a walled hypothesis gets to produce a positive control
PROOF_ATTEMPTS = 3       # proof offers an edge gets per capture before it must cite a new raw file
VERDICT_TURNS = 2        # directive turns a verdict-owed hypothesis gets before it is parked UNFIRED
_HOP_TITLE = re.compile(r"^\s*h\d+(-[a-z]+)*(-\d+)?\s*[:.-]", re.I)      # "H5: ...", "H2-escalate: ..."
_METHOD = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
_BLOCKER_WORD = re.compile(r"(?i)\b(NEEDS|blocked|refus\w*|wall\w*|out of scope|scope-gate|safety|unfireable|no route|"
                           r"credential|phone|captcha)\b")   # D59: what a zero-probe park must name
_PATH_TOKEN = re.compile(r"(?:^|[\s\"'=(\[`])(/[a-z0-9_.{}~%:-]{2,}(?:/[a-z0-9_.{}~%:*-]*)*)", re.I)
# F3 2026-11-09: "GET /?locale=ja" is a typeable request, but _PATH_TOKEN wants 2+ characters after the slash, so a
# root-path request was refused as "no concrete request" (program-28, 11 refusals in one turn). The root path
# counts when a METHOD precedes it (optionally with scheme+host) or a name=value query follows it.
_ROOT_REQUEST = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(?:https?://[^\s/?#]+)?/(?:\?\S*)?(?=[\s,;)\]`'\"]|$)"
                           r"|(?:^|[\s\"'=(\[`])(?:https?://[^\s/?#]+)?/\?[A-Za-z_][\w.\[\]-]*=\S", re.I)
# D93 (cycle 25, 10:51Z): H44 was admitted on "Drifted sibling endpoint returns private body (positive control)
# while enforcing sibling returns 403" because the bare word "body" matched. concrete_input() now wants the input
# word followed by a NAME (a dash, underscore, dot, digit or capital inside it: X-Session, dest_id, sessionId), or
# the input written as name=value. _INPUT_WORD is kept for the other callers.
_INPUT_WORD = re.compile(r"\b(header|cookie|field|param(eter)?|body|query|json key)\b|\b[a-z_][a-z0-9_]*=\S", re.I)
_INPUT_NAME = re.compile(r"\b(header|cookie|field|param(?:eter)?|query|json key|body key)\s+[`'\"]?([A-Za-z_][\w.-]*)", re.I)
_NAME_INPUT = re.compile(r"([A-Za-z_][\w.-]*)\s+(header|cookie|field|param(?:eter)?|query)\b", re.I)   # "the X-Session header"
_ASSIGN = re.compile(r"\b[a-z_][a-z0-9_]*=\S", re.I)
_NOT_A_NAME = {"or", "and", "the", "is", "to", "of", "that", "with", "in", "on", "a", "an"}
# SOURCE lane (2026-11-02): a repository asset has no route to mine, so its violation names the SINK and the crafted
# VALUE instead of "GET /path?param=". Location = file.go:LINE (any language's ext:line) or a Go tree path; input =
# the value with a quote/semicolon/../ separator or a name=value. Both are required, so "the health checker is
# insecure" still fails.
_SOURCE_LOC = re.compile(r"\b[\w./-]+\.(?:go|py|php|js|ts|sh|c|cc|cpp|h|rs|java|rb|yaml|json|tmpl|tpl):\d{1,5}\b"
                         r"|\b(?:pkg|cmd|internal|upup|hack|tools|staging|lib|apps|src)/[\w./-]+\.\w{1,6}\b")
_SOURCE_INPUT = re.compile(r"[\"'`;|&$]|\.\./|%s|\$\{|\b[a-z_][a-z0-9_]*=\S", re.I)


def _source_violation(v):
    """True when a pathless violation still names a SINK location and a crafted value (the SOURCE lane)."""
    return bool(v and _SOURCE_LOC.search(v) and _SOURCE_INPUT.search(v))
_OWN_DATA = re.compile(r"(\b(own|owner'?s|my|self|same (session|account|user))\b[^.]{0,60}\b(id|email|pii|profile|data|"
                       r"fields?|record|object)\b)|<own-", re.I)
_OTHER_PARTY = re.compile(r"\b(victim|other|second|another|foreign|different|cross|stranger|b'?s|account b|tenant b|"
                          r"user b|identity b|(as|by|from|for) b)\b", re.I)
_CROSSING = {"cross-user-read", "cross-user-write", "cross-tenant", "ato", "mass-pii", "admin", "auth-bypass"}


_HEADER_TOKEN = re.compile(r"\b(X-[A-Za-z0-9-]{2,}|Authorization|Cookie|Origin|Referer|Host)\b")


def violation_inputs(violation):
    """The input NAMES a violation says it sends: header tokens (X-Partner-Token), word+name pairs (field dest_id),
    name+word pairs (the X-Session header) and name=value lefts. Lower-cased, de-duplicated, generic words dropped."""
    v = str(violation or "")
    names = set()
    for m in _HEADER_TOKEN.finditer(v):
        names.add(m.group(1).lower())
    for m in _INPUT_NAME.finditer(v):
        names.add(m.group(2).lower())
    for m in _NAME_INPUT.finditer(v):
        names.add(m.group(1).lower())
    for m in re.finditer(r"\b([a-z_][a-z0-9_]*)=\S", v, re.I):
        names.add(m.group(1).lower())
    drop = _NOT_A_NAME | {"method", "path", "header", "headers", "field", "param", "parameter", "cookie", "query",
                          "body", "json", "key", "value", "id", "get", "post", "put", "patch", "delete", "http",
                          "https", "as", "with", "via", "and", "from", "same"}
    return {n for n in names if n not in drop and len(n) >= 3}


def capture_sends(ev_path, names):
    """(present, missing): which of the violation's input names the capture's REQUEST actually carries (header keys and
    values, url, body). D96: H47's lead capture sent nothing but the identification header."""
    names = {str(n).lower() for n in (names or []) if n}
    if not names:
        return [], []
    try:
        with open(os.path.join(WS, str(ev_path))) as f:
            j = json.load(f)
    except (OSError, ValueError, TypeError):
        return [], sorted(names)
    req = j.get("request") or {}
    hay = " ".join([str(req.get("url") or ""), str(req.get("body") or "")] +
                   [f"{k} {v}" for k, v in (req.get("headers") or {}).items()]).lower()
    present = sorted(n for n in names if n in hay)
    missing = sorted(n for n in names if n not in hay)
    return present, missing


_PRECISION_LEDGER = os.path.join(WS, "research/technique/PRECISION-LEDGER.json")
# The trap classes, keyed by the words a hypothesis actually uses. Our own adjudicated record says we
# hunt our WORST converters hardest: IDOR 6% positive over 16 reports with 69% dupes, Information
# Disclosure 12% over 26, auth-attempt-throttling 0% over 4 - while Business Logic sits at 83% (5/6)
# and is barely hunted. That table lived only in a prose blob that is itself subject to the auto-load
# truncation, so it never reached the moment of choice. A number in a prompt is a suggestion; a number
# returned by the tool that accepts the hypothesis is a decision point.
_TRAP_WORDS = (
    (("idor", "bola", "object reference", "object-level", "enumerat"),
     "Insecure Direct Object Reference (IDOR)"),
    (("information disclosure", "info disclosure", "infoleak", "info leak", "disclos"),
     "Information Disclosure"),
    (("rate limit", "rate-limit", "brute force", "brute-force", "otp attempt", "login attempt"),
     "Improper Restriction of Authentication Attempts"),
)


def class_precision_note(*texts):
    """A one-line warning when a hypothesis reads like one of our measured trap classes, or ''.

    Never refuses - the class is INFERRED from wording and a guess must not block real work. It states
    our own adjudicated numbers and names the better-converting neighbour, at the moment the hypothesis
    is written rather than in a doc nobody re-reads."""
    blob = " ".join(str(t or "") for t in texts).lower()
    try:
        with open(_PRECISION_LEDGER) as fh:
            by_class = (json.load(fh) or {}).get("by_class") or {}
    except (OSError, ValueError):
        return ""
    for words, key in _TRAP_WORDS:
        if not any(w in blob for w in words):
            continue
        row = by_class.get(key)
        if not isinstance(row, dict) or not row.get("n"):
            continue
        return (f"\nCLASS WARNING: this reads like '{key}', our {row.get('precision_pct')}% converter "
                f"({row.get('positive')}/{row.get('n')} accepted, {row.get('dupe_pct')}% duplicates). "
                "It is one of the classes we hunt most and win least. Our best converters are Business "
                "Logic 83%, Improper Authentication 43%, Reflected XSS 43%, SSRF 40%. Keep this "
                "hypothesis if the CAPABILITY is genuinely new, but aim the terminal at one of those, or "
                "escalate this one (same defect on a higher-value asset, the paired write, the partner "
                "bug) rather than filing the read. Check first: "
                f"scripts/bbtools/prt.py precision --class '{key}' --program <handle>")
    return ""


def concrete_input(violation):
    """A violation is probeable when it names a PATH (the request's url) and the crafted input: a method, a
    name=value, or an input word (header, cookie, field, param, query, json key) next to a NAME that looks like one
    (a dash, underscore, dot, digit or capital inside it). D93: 'returns private body' is prose, not an input.
    D101: a method with no path ('POST body with state pointing to a different session') is not a request either;
    the wall and ghost-route gates read the path from here, so a pathless violation slips past both.

    SOURCE lane (2026-11-02): a program whose assets are REPOSITORIES is probed by building the code and running the
    extracted function, so its violation names a file:line and a crafted value, never a url. Without this a proven exec
    (node-problem-detector health checker, test PASS + marker files) could not be logged at all: the gate demanded a
    route from known-paths for a bug that has no route. A pathless violation is still refused unless it names a SINK
    LOCATION and the crafted input (_source_violation)."""
    v = str(violation or "")
    if _source_violation(v):
        # A source hypothesis names its sink by file:line, and its payload necessarily contains slashes
        # (/bin/sh -c, ../../etc/passwd), which the HTTP path regex would otherwise read as a route.
        return True
    if not _PATH_TOKEN.search(v) and not _ROOT_REQUEST.search(v):   # F3: "GET /?locale=ja" is a request
        return False
    if _METHOD.search(v) or _ASSIGN.search(v):
        return True
    for name in [m.group(2) for m in _INPUT_NAME.finditer(v)] + [m.group(1) for m in _NAME_INPUT.finditer(v)]:
        if name.lower() not in _NOT_A_NAME and re.search(r"[-_.0-9]|[A-Z]", name):
            return True
    return False


def prediction_is_refusal(prediction, kill_byte=""):
    """(bad, why): a prediction that names a 4xx or an error marker and no granting status predicts the CONTROL
    holding; firing it confirms nothing (program-101 H5/H6, 40 probes). The kill byte must not be an error code either."""
    p, k = str(prediction or ""), str(kill_byte or "")
    grants = re.search(r"\b[23]\d\d\b", p)
    refuses = re.search(r"\b4\d\d\b", p) or _ERROR_MARKER.search(p)
    if refuses and not grants:
        return True, ("the prediction describes a refusal (a 4xx or an error marker), which is the control holding, "
                      "not the capability. Predict the bytes that CONFIRM it (the private body, the changed state, the "
                      "2xx the excluded actor must never get), byte-distinct from the refusal")
    if k and _ERROR_MARKER.search(k) and len(k) < 60 and not re.search(r"\b[23]\d\d\b", k):
        return True, (f"kill_byte={k!r} is an error marker; the kill byte is the byte that PROVES the capability, "
                      "never the code that refuses it")
    return False, ""


def prediction_is_self_read(prediction, kill_byte, crown):
    """(bad, why): a crossing is proved by the OTHER identity's bytes in the response (T-43). program-0 E1 was
    'proven' as unauth -> cross-user-read on '"ownerId":"<own-id>"': the probing account reading its own profile."""
    if node(crown) not in _CROSSING:
        return False, ""
    t = f"{prediction or ''} {kill_byte or ''}"
    if _OWN_DATA.search(t) and not _OTHER_PARTY.search(t):
        return True, ("the prediction confirms on the probing identity's OWN data; getting your own record back is "
                      "the normal case, not a crossing (T-43). Predict the OTHER identity's bytes (victim B's id, email "
                      "or object) inside A's response, and take the kill byte from B")
    return False, ""


def _route_shape(artifact):
    """('host/path', 'status:len') of a raw capture, or (None, None) when it is not one."""
    try:
        p = artifact if os.path.isabs(artifact) else os.path.join(WS, artifact)
        with open(p) as f:
            j = json.load(f)
        url = str((j.get("request") or {}).get("url") or "")
        resp = j.get("response") or {}
    except (OSError, ValueError, AttributeError, TypeError):
        return None, None
    if not url:
        return None, None
    route = route_key(url)   # D57: the sender looks walls up by route_key; the logger used its own key, so
    #                            //api/account and /api/./account were three routes of 5 probes, not one of 36
    body = resp.get("body")
    blen = len(body) if isinstance(body, str) else len(json.dumps(body)) if body is not None else 0
    return route[:200], f"{resp.get('status')}:{blen}"


def _granted(shape):
    st = str(shape).split(":", 1)[0]
    return st.isdigit() and int(st) < 400


def shape_bucket(shape):
    """The wall bucket of a 'status:len' shape: a refusal body of SHELL_MIN bytes or more is the host's HTML error
    shell, whose length drifts by a few hundred bytes per response (a CSP nonce, T-230), so every probe used to be a
    new shape and the wall never formed. Drive cycle 18 (2026-10-26 04:56Z): H19 and H24 poured 14 probes into
    console /admin-settings/billing, 404 len=81697..82228 each time, share of the top shape 1/7."""
    st, _, ln = str(shape).partition(":")
    if ln.isdigit() and int(ln) >= SHELL_MIN and st.isdigit() and int(st) >= 400:
        return f"{st}:shell"
    return str(shape)


def bucketed(shapes):
    """{bucket: probes} for a route's recorded shapes."""
    out = {}
    for s, n in (shapes or {}).items():
        b = shape_bucket(s)
        out[b] = out.get(b, 0) + int(n or 0)
    return out


def walled_routes(h):
    """[(route, shape, probes)] for the routes under this hypothesis that answered ONE refusal shape on
    >= WALL_SHARE of >= WALL_MIN probes and never once a 2xx/3xx. T-49: that is absence of surface (or a WAF
    answering for a path that does not exist), not a tested negative, and T-32 says a negative needs a positive
    control first. program-101 H6: app.example.com/api/v1/admin/twin, 14 probes, 403 len=35 every time."""
    out = []
    for route, raw in (h.get("routes") or {}).items():
        shapes = bucketed(raw)
        total = sum(shapes.values())
        if total < WALL_MIN or any(_granted(s) for s in shapes):
            continue
        top, n = max(shapes.items(), key=lambda kv: kv[1])
        if n / total >= WALL_SHARE or total >= WALL_HARD:
            out.append((route, top, total))
    return out


def route_key(url):
    """The per-route key log_probe keeps: host/path without scheme, query, fragment or trailing slash."""
    k = re.sub(r"^https?://", "", str(url or "")).split("?", 1)[0].split("#", 1)[0]
    k = re.sub(r"/\./", "/", re.sub(r"/{2,}", "/", k))   # //x and /./x are path-shape variants of /x (cycle 5)
    return (k.rstrip("/") or "/")[:200]


class RouteWalled(PermissionError):
    """Raised by the sender BEFORE the wire when the route is a wall across the whole program (see program_walls)."""


def program_walls(program):
    """{route: (shape, probes)} for routes that are a wall ACROSS every hypothesis of the program: the same WALL rule
    as walled_routes, applied to the merged per-route shapes. walled_routes is per hypothesis, and the lead learned
    to dodge it by renaming: drive cycle 1 on program-0 (2026-10-25 23:34Z) fired api.program-0.example/oauth/vault/callback
    under H3, H3-positive-control, E1-...-negative-control and E1-... in turn, 404 len=117 every time, 20+ probes."""
    merged = {}
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001 - no ledger, no walls
        return {}
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            m = merged.setdefault(route_key(route), {})   # D57: fold the keys older ledgers logged unnormalised
            for s, n in bucketed(shapes).items():
                m[s] = m.get(s, 0) + int(n or 0)
    out = {}
    for route, shapes in merged.items():
        total = sum(shapes.values())
        if total < WALL_MIN or any(_granted(s) for s in shapes):
            continue
        top, n = max(shapes.items(), key=lambda kv: kv[1])
        if n / total >= WALL_SHARE or total >= WALL_HARD:
            out[route] = (top, total)
    return out



HOST_WALL_MIN_PATHS = 3
CATCHALL_PATHS = 3      # one shape on this many distinct paths = a catch-all
CATCHALL_SHARE = 0.6    # share of a prefix's paths covered by catch-alls before it is called absent        # distinct paths under one prefix before its uniform shape means anything


def host_walls(program):
    """{host: (shape, distinct_paths)} for hosts that answer the SAME shape on every DISTINCT path tried.

    program_walls is per ROUTE, and a model dodges it for free by changing the path: each new path is a new
    route key, so a host serving one catch-all page can absorb an unlimited number of probes while every
    single refusal looks like "this endpoint is protected". Measured 2026-10-28 on program-72: /api/v1/register
    and /api/v1/login on app.example.com both returned `403 len=716` from `server: AmazonS3` - the SPA's bucket
    answering for a path it does not have. The APIs live on the api.* subdomains entirely. The agent read
    the catch-all as an auth wall and kept inventing paths on the wrong host.

    A host-level verdict is the one that tells it the useful thing: change the HOST, not the method.
    """
    per = {}
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001
        return {}
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            rk = route_key(route)
            if "/" not in rk:
                continue
            host, path = rk.split("/", 1)
            # Group by host AND the first two path segments. A whole HOST is rarely a wall - app.example.com
            # serves its SPA with 200s - but a PREFIX on it can be completely absent: every /api/v1/* path
            # there answered 403 len=716 from server: AmazonS3, the bucket's catch-all, because the real
            # APIs live on the api.* subdomains. Prefix is the granularity that actually names the mistake.
            segs = [x for x in path.split("/") if x][:2]
            key = host + ("/" + "/".join(segs) if segs else "")
            bucket = per.setdefault(key, {})
            for sh, n in bucketed(shapes).items():
                bucket.setdefault(sh, set()).add("/" + path)
    out = {}
    for key, shapes in per.items():
        paths = set()
        for p in shapes.values():
            paths |= p
        if len(paths) < HOST_WALL_MIN_PATHS:
            continue
        # A CATCH-ALL IS NOT A GRANT, even when it is a 200. Excluding any prefix that ever returned 2xx
        # was wrong here: app.example.com/api/v1 answers `403 len=716` (S3's bucket catch-all) on five distinct
        # paths AND ~6.9 KB 200s that are the SPA's index.html - the soft-200 of T-60. Both are the same
        # thing wearing different statuses: one response for every path, i.e. the prefix does not exist.
        # So classify by REPETITION, not by status: a shape seen on CATCHALL_PATHS or more distinct paths
        # is a catch-all whatever its code, and a prefix mostly covered by catch-alls is absent surface.
        catchall = {sh: p for sh, p in shapes.items() if len(p) >= CATCHALL_PATHS}
        if not catchall:
            continue
        covered = set()
        for p in catchall.values():
            covered |= p
        if len(covered) / len(paths) < CATCHALL_SHARE:
            continue
        top, top_paths = max(catchall.items(), key=lambda kv: len(kv[1]))
        out[key] = (top, len(covered))
    return out

_ID_SEG = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,}|[{<:].*)$", re.I)
_HARVEST = {}             # program -> (signature, frozenset(paths)); in-process cache, keyed on the raw dirs' mtimes
HARVEST_MAX_FILES = 40000  # a sanity cap on files read per harvest; the signature is still exact
HARVEST_JSON_MAX = 2_000_000


def norm_path(path):
    """A url path with ids folded: numeric, uuid and long-hex segments (and {x} <x> :x placeholders) become {id}, so a
    captured /v8/api/accounts/1234567/transactions.json and a violation's /v8/api/accounts/{id}/transactions.json
    are the same route."""
    p = urllib.parse.urlsplit(str(path or "")).path if "://" in str(path or "") else str(path or "").split("?", 1)[0]
    p = p.split("#", 1)[0]
    segs = [("{id}" if _ID_SEG.match(x) else x) for x in p.split("/") if x]
    return ("/" + "/".join(segs)) if segs else "/"


def _raw_dirs(program):
    """Every directory at or under targets/<program>/hunts/*/raw (captures nest: raw/flows/...)."""
    base = os.path.join(WS, "targets", program, "hunts")
    out = []
    try:
        lanes = sorted(os.listdir(base))
    except OSError:
        return out
    for lane in lanes:
        top = os.path.join(base, lane, "raw")
        if not os.path.isdir(top):
            continue
        for d, subs, _ in os.walk(top):
            subs.sort()
            out.append(d)
    return out


def _status_of(text):
    """The HTTP status in the first line of a .hdr / .resp capture ('302', 'HTTP/1.1 200 OK'), else None."""
    first = (text or "").lstrip().split("\n", 1)[0].strip()
    m = re.match(r"^(?:HTTP/[\d.]+\s+)?(\d{3})\b", first)
    return int(m.group(1)) if m else None


def _head(path, n=512):
    try:
        with open(path, "rb") as f:
            return f.read(n).decode("utf-8", "replace")
    except OSError:
        return ""


def _harvest_dir(d):
    """{normalised path} for the non-404 captures in one raw dir: .req (+ .hdr or .resp) pairs and http_request
    *.json files ({"request": {"url"}, "response": {"status"}})."""
    out = set()
    try:
        names = os.listdir(d)
    except OSError:
        return out
    have = set(names)
    for nm in names:
        full = os.path.join(d, nm)
        url, status = "", None
        if nm.endswith(".req"):
            first = _head(full).split("\n", 1)[0].split()
            if len(first) >= 2 and _METHOD.fullmatch(first[0].upper()):
                url = first[1]
            stem = nm[:-4]
            for ext in (".hdr", ".resp"):
                if stem + ext in have:
                    status = _status_of(_head(os.path.join(d, stem + ext), 64))
                    if status:
                        break
        elif nm.endswith(".json"):
            try:
                if os.path.getsize(full) > HARVEST_JSON_MAX:
                    continue
                with open(full) as f:
                    j = json.load(f)
                url = str(((j.get("request") or {}).get("url")) or "") if isinstance(j, dict) else ""
                st = (j.get("response") or {}).get("status") if url else None
                status = int(st) if str(st).isdigit() else None
            except (OSError, ValueError, AttributeError, TypeError):
                continue
        else:
            continue
        if not url or not status or status == 404:
            continue
        path = urllib.parse.urlsplit(url).path if "://" in url else url.split("?", 1)[0]
        if path.startswith("/"):
            out.add(norm_path(path).rstrip("/") or "/")
    return out


def captured_paths(program):
    """F2 2026-11-09: the routes this program's captures show ANSWERING (any status but 404), from every
    targets/<p>/hunts/*/raw/ dir, ids folded to {id}. program-28 had 172+ non-404 captures on disk while
    existing_paths knew ONE route, so every real hypothesis was refused as a ghost route. Cached per process on
    the raw dirs' mtimes (a new capture changes its dir's mtime), so a repeat call is one stat per dir."""
    if not program:
        return frozenset()
    dirs = _raw_dirs(program)
    sig = []
    for d in dirs:
        try:
            sig.append((d, os.stat(d).st_mtime_ns))
        except OSError:
            pass
    sig = tuple(sig)
    hit = _HARVEST.get(program)
    if hit and hit[0] == sig:
        return hit[1]
    out = set()
    for d, _ in sig:
        out |= _harvest_dir(d)
    out.discard("/")
    res = frozenset(out)
    _HARVEST[program] = (sig, res)
    return res


def existing_paths(program):
    """Paths the program is known to have: the mined routes (hunts/gnoc/known-paths.txt) plus every ledger route that
    answered anything but a 404. D79 (cycle 24, 10:00Z-10:12Z): H40 /api/v1/follow-up, H42 /api/v1/session/state,
    H43 /api/v1/user/profile, H41 /api/v1/async/trigger were all tournament inventions; each burned a 20-probe
    budget on a route that does not exist, and the ghost gate's two-segment prefix rule (/api/v1/...) let them by.
    F2 2026-11-09: plus every route a raw capture under hunts/*/raw/ shows answering (captured_paths)."""
    out = set()
    try:
        out |= set(captured_paths(program))
    except Exception:  # noqa: BLE001 - a harvest failure must not take the ghost gate down
        pass
    try:
        with open(os.path.join(WS, "targets", program, "hunts/gnoc/known-paths.txt")) as _kp:
            _kp_lines = _kp.read().splitlines()
        for ln in _kp_lines:
            if ln.strip() and not ln.startswith("#"):
                out.add(ln.strip().rstrip("/"))
    except OSError:
        pass
    try:
        for h in load(program).get("hypotheses", []):
            for route, shapes in (h.get("routes") or {}).items():
                rk = route_key(route)
                if "/" in rk and any(not str(x).startswith("404") for x in shapes):
                    out.add(("/" + rk.split("/", 1)[1]).rstrip("/"))
    except Exception:  # noqa: BLE001
        pass
    return out


def _violation_paths(violation):
    """The path tokens of a violation with trailing placeholder segments ({id}, <B>, :id) stripped to the parent."""
    out = []
    for m in _PATH_TOKEN.findall(str(violation or "")):
        segs = [x for x in m.split("/") if x]
        while segs and re.match(r"^[{<:$].*|^[0-9]+$|^<.*>$", segs[-1]):
            segs.pop()
        if segs:
            out.append("/" + "/".join(segs))
    return out


def unknown_route_refusal(program, violation):
    """The refusal when the violation names routes and none of them exists, else None. A route exists when it is
    mined, answered anything but 404, is the parent of a known route, or the child of a known route of 3+ segments.

    SOURCE lane (2026-11-02): a violation that names a sink file:line is not a route claim, so the routes quoted in it
    (a source path, a shell fragment) must not be checked against known HTTP paths. Without this the proven
    node-problem-detector exec was refused with "the violation's route /usr/bin/touch does not exist"."""
    if _source_violation(str(violation or "")):
        return None
    paths = _violation_paths(violation)
    if not paths:
        return None
    known = existing_paths(program)
    if not known:
        return None

    known_n = {norm_path(k).lower() for k in known} | {k.rstrip("/").lower() for k in known}

    def _exists(pth):
        p = norm_path(pth.rstrip("/")).lower()   # F2: /accounts/1234567/x and /accounts/{id}/x are one route
        for kl in known_n:
            if p == kl or kl.startswith(p + "/"):
                return True
            if p.startswith(kl + "/") and kl.count("/") >= 3:
                return True
        return False
    if any(_exists(pth) for pth in paths):
        return None
    first = paths[0].split("/")[1] if "/" in paths[0][1:] else paths[0].strip("/")
    near = sorted(k for k in known if k.lower().startswith("/" + first.lower() + "/"))[:6]
    return (f"the violation's route {paths[0]} does not exist on {program}: it is not a mined route and no probe ever "
            f"saw it answer. Aim at a route that exists (known-paths, js_mine, hunt_search, the vendor docs)"
            + (f"; nearest known under /{first}/: {', '.join(near)}" if near else "")
            + ". If you read this route out of a bundle yourself, do NOT re-send this add: fire ONE http_request at it "
            "first (any answer but a 404 registers the route), or re-mine the bundle with js_mine, then add.")


def accepted_example(program, param="id=1"):
    """F3 2026-11-09: one violation string built from this program's existing_paths() that the add-time gates
    (concrete_input, the wall gate, the ghost-route gate) all accept, or "" when none does. Shown after the third
    identical refusal in a turn, so the lead copies a passing shape instead of looping (11 refusals on 2026-11-09)."""
    try:
        known = sorted(existing_paths(program), key=lambda k: (k.count("{"), "%" in k, k.startswith("/."), len(k), k))
    except Exception:  # noqa: BLE001
        return ""
    for route in known[:60]:
        if not route.startswith("/") or not _PATH_TOKEN.search(" " + route):
            continue
        v = f"GET {route}?{param}"
        if concrete_input(v) and not violation_on_wall(program, v) and not unknown_route_refusal(program, v):
            return v
    return ""


def note_shapes(program, hyp_id, artifacts):
    """Record the route shapes of extra captures (a burst's other arms) WITHOUT counting probes: log_probe counts one
    and mark_burst adds the rest, but only the first capture's route was recorded, so a 20-request burst at a route
    that never answered never formed a wall (D80, H40: 20 probes, one recorded route shape)."""
    if not program or not hyp_id or not artifacts:
        return
    shapes = [_route_shape(a) for a in artifacts]
    shapes = [(r, sh) for r, sh in shapes if r and sh]
    if not shapes:
        return

    def _add(d):
        h = _find_hyp(d["hypotheses"], hyp_id)
        if not h:
            return
        routes = h.setdefault("routes", {})
        for route, shape in shapes:
            if route in routes or len(routes) < 40:
                rs = routes.setdefault(route, {})
                if shape in rs or len(rs) < 30:
                    rs[shape] = rs.get(shape, 0) + 1
    try:
        modify(program, _add)
    except Exception:  # noqa: BLE001
        pass


def violation_on_wall(program, violation):
    """The refusal line when the violation's path is a route the whole program has walled past 2 x WALL_MIN probes,
    else None. Drive cycle 21 (2026-10-26 08:10Z): H18 spent 17 probes on api.program-0.example/api/account (403 len=215
    unauth, 405 on POST), then the lead minted H33 'GET-only endpoint on /api/account' on the same route and spent 16
    more. A hypothesis whose crafted request is a wall is the same probe under a new id (T-49, T-266)."""
    v = str(violation or "")
    paths = [m.rstrip("/") for m in _PATH_TOKEN.findall(v) if len(m.rstrip("/")) > 2]
    if not paths:
        return None
    try:
        walls = program_walls(program)
    except Exception:  # noqa: BLE001
        return None
    for route, (shape, n) in walls.items():
        if n < 2 * WALL_MIN:
            continue
        rpath = "/" + route.split("/", 1)[1] if "/" in route else ""
        for pth in paths:
            if rpath and (rpath.lower() == pth.lower() or rpath.lower().endswith(pth.lower())):
                return (f"refused: the violation's route {route} is a program wall ({shape.replace(':', ' len=')} on "
                        f"{n} probes across every hypothesis, never a 2xx/3xx). A hypothesis on a wall is the same "
                        "probe under a new id (T-49, T-266). Aim it at a route that has answered: known-paths, "
                        "js_mine, the vendor docs, or a different host.")
    return None


SHELL_ROUTE_MIN = 20   # probes on one route, every answer the shell or a refusal, before it is closed ground


def program_shell_routes(program):
    """{route: probes} for routes that took SHELL_ROUTE_MIN+ probes across the program's hypotheses and never once
    answered with a small granted body (every 2xx/3xx shape is SHELL_MIN bytes or more, or there is none): the SPA
    shell every path gets. Drive cycle 12 (2026-10-26): H12-H17, six hypotheses in a row, each spent its 20-probe
    budget on console oauth/vault/callback and each was refused as the shell; the route itself was never closed."""
    merged = {}
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001
        return {}
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            m = merged.setdefault(route_key(route), {})
            for s, n in shapes.items():
                m[s] = m.get(s, 0) + int(n or 0)
    out = {}
    for route, shapes in merged.items():
        total = sum(shapes.values())
        if total < SHELL_ROUTE_MIN:
            continue
        granted_small = any(_granted(s) and s.split(":")[1].isdigit() and int(s.split(":")[1]) < SHELL_MIN for s in shapes)
        granted_big = any(_granted(s) and s.split(":")[1].isdigit() and int(s.split(":")[1]) >= SHELL_MIN for s in shapes)
        if granted_big and not granted_small:
            out[route] = total
    return out


def backfill_routes(program):
    """Rebuild every hypothesis's per-route answer shapes from the captures already in its evidence list, so a
    ledger written before 2026-10-25 gets wall detection without re-probing. Returns the walls found."""
    def _go(d):
        found = []
        for h in d.get("hypotheses") or []:
            routes = {}
            for ev in h.get("evidence") or []:
                route, shape = _route_shape(ev)
                if route and shape:
                    routes.setdefault(route, {})
                    routes[route][shape] = routes[route].get(shape, 0) + 1
            if routes:
                h["routes"] = routes
                found += [(h["id"],) + w for w in walled_routes(h)]
        return found
    return modify(program, _go)


def any_granted(h):
    """True when at least one probe under the hypothesis drew a 2xx/3xx on a route that is not the host's root
    document: the surface was reached. D77 (cycle 24, 10:06Z): H36 went DEAD on 19 probes whose only 2xx were two
    GETs of https://api.program-0.example/ (the app shell); a landing page is not the seam."""
    for route, shapes in (h.get("routes") or {}).items():
        if "/" not in route_key(route):   # a bare host = the root document
            continue
        if any(_granted(s) for s in shapes):
            return True
    return False


_KB_SHAPE = re.compile(r'[":{}=\[\]<>]')


def weak_kill_byte(kb, h=None):
    """The refusal reason when the kill byte cannot discriminate a response, else None. D70 (drive cycle 23,
    2026-10-26 09:18Z): H36 became a LEAD with kill_byte 'api' on the console root HTML document (207 KB), and bot 2
    claimed a CANDIDATE on 'enriched'. A kill byte is the private or state-changing BYTES the response carries (a
    field with its value, an id, a token); a short bare word or a fragment of the route being probed is in every
    answer, including the control."""
    kb = str(kb or "").strip()
    if not kb:
        return None
    if len(kb) < 8 and not _KB_SHAPE.search(kb):
        return (f"kill_byte={kb!r} is a short bare word; name the private or state-changing bytes the response "
                "carries (a field with its value, an id, a token, at least 8 characters or a JSON shape)")
    if re.fullmatch(r"[A-Za-z0-9_./-]+", kb) and h:
        hay = " ".join(str(h.get(k) or "") for k in ("title", "violation", "prediction")).lower()
        routes = " ".join((h.get("routes") or {}).keys()).lower()
        if kb.lower() in hay or kb.lower() in routes:
            return (f"kill_byte={kb!r} is a fragment of the route or the hypothesis text itself, so it appears in the "
                    "control as well; name a byte only the mechanism produces")
    return None


def untagged_probes(program):
    """How many probes this program fired with NO hypothesis tag, i.e. outside every budget and the
    floor. See log_probe for why they are counted rather than refused."""
    try:
        return int(load(program).get("untagged_probes") or 0)
    except Exception:  # noqa: BLE001 - accounting never breaks a hunt
        return 0


def counted_probes(h, program=None):
    """Probes that count toward the floor: everything logged minus the probes spent on walled routes. D76 (drive
    cycle 24, 2026-10-26 09:58Z): H36 held 9 wall refusals and stayed 'probing' because its own 2-3 probes on
    api.program-0.example/v1/messages were under WALL_MIN while the PROGRAM had walled that route at 12; with the
    program known, probes on program-wide walls do not count either."""
    walls = {r for r, _, _ in walled_routes(h)}
    spent = sum(n for _, _, n in walled_routes(h))
    if program:
        try:
            pw = program_walls(program)
        except Exception:  # noqa: BLE001
            pw = {}
        for route, shapes in (h.get("routes") or {}).items():
            rk = route_key(route)
            if rk in pw and route not in walls and rk not in walls:
                spent += sum(int(n or 0) for n in shapes.values())
    return max(0, int(h.get("probes") or 0) - spent)


def wall_text(h):
    walls = walled_routes(h)
    if not walls:
        return ""
    return "ROUTE WALL: " + "; ".join(f"{r} answered {s.replace(':', ' len=')} on all {n} probes and never a 2xx"
                                     for r, s, n in walls) + \
        f". A route that only ever refuses is absent surface (T-49), not a tested negative; those probes do not " \
        f"count ({counted_probes(h)} of {h.get('probes', 0)} count, floor {FLOOR}). Do not send it another variant."

def _via_same(a, b):
    """Two edges between the same capabilities are the same hop when their primitives read alike: token overlap
    (the fast path) or a character ratio of 0.7 ('H1: ws drift' vs 'H1: ws drift probe' are one hop)."""
    import difflib
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b:
        return a == b
    return _sim(a, b) >= 0.6 or difflib.SequenceMatcher(None, a, b).ratio() >= 0.7

_ERROR_MARKER = re.compile(r"(error_?code|\"error\"|\"errors\"|forbidden|unauthori[sz]ed|denied|invalid|not[ _]found|"
                           r"system busy|_error\b|\berror\b|exception|bad[ _]request|rate[ _]limit|too many)", re.I)


def _terminal_shape(evidence, must_contain):
    """(ok, why): a PROVEN edge needs a capture whose response is not a refusal. The lead tried to prove
    'unauth -> ato' with a 403 whose body was error_code 40003 and must_contain='error_code:40003' (program-101
    2026-10-23): a refused request proves the CONTROL, never the capability."""
    try:
        p = evidence if os.path.isabs(evidence) else os.path.join(WS, evidence)
        with open(p) as f:
            d = json.load(f)
    except (OSError, ValueError, TypeError):
        return False, ("the evidence is not a raw JSON capture with request+response; a proven edge needs the "
                       "bytes that came off the wire, not a note or a hand-written file")
    if not isinstance(d, dict) or not isinstance(d.get("response"), dict):
        return False, ("the evidence JSON has no response object; a proven edge needs the raw request+response "
                       "capture, not a hand-written file")
    resp = d["response"]
    try:
        status = int(resp.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    if not 200 <= status < 400:
        return False, (f"the evidence is HTTP {status or 'unknown'}: a proven edge needs the response that GRANTS "
                       "the capability (2xx/3xx with the private bytes); the 4xx/5xx is the negative control "
                       "(control=<that file>).")
    shell, why = is_soft200_shell(evidence)
    if shell:
        return False, why
    if must_contain and _ERROR_MARKER.search(must_contain) and len(must_contain) < 60:
        return False, (f"must_contain={must_contain!r} is an error marker; the terminal bytes of a capability are "
                       "the private data, the changed state or the executed command, never an error code.")
    return True, ""

def _capture_response(f):
    """The response dict of a raw JSON capture, or None when the file is not one (missing, not JSON, no response)."""
    if not f:
        return None
    try:
        p = f if os.path.isabs(f) else os.path.join(WS, f)
        with open(p) as fh:
            d = json.load(fh)
    except (OSError, ValueError, TypeError):
        return None
    r = d.get("response") if isinstance(d, dict) else None
    return r if isinstance(r, dict) else None


def _resp_status(r):
    try:
        return int(r.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def _resp_body(r):
    b = r.get("body")
    if b is None:
        return ""
    return b if isinstance(b, str) else json.dumps(b)


def _resp_headers(r):
    """Headers as a list of (lower-name, value) pairs, from a dict or a list of pairs."""
    h = r.get("headers") or {}
    pairs = h.items() if isinstance(h, dict) else (x for x in h if isinstance(x, (list, tuple)) and len(x) == 2) \
        if isinstance(h, list) else ()
    return [(str(k).lower(), v if isinstance(v, str) else json.dumps(v)) for k, v in pairs]


def _capture_request(f):
    """The request dict of a raw JSON capture, or None."""
    if not f:
        return None
    try:
        pth = f if os.path.isabs(f) else os.path.join(WS, f)
        with open(pth) as fh:
            d = json.load(fh)
    except (OSError, ValueError, TypeError):
        return None
    return d.get("request") if isinstance(d, dict) and isinstance(d.get("request"), dict) else None


def _request_vars(req):
    """The five variables a control may differ in: method, path, query, headers (minus the identification header),
    body. Lower-cased where case carries no meaning."""
    u = urllib.parse.urlsplit(str(req.get("url") or ""))
    hdrs = {str(k).lower(): str(v) for k, v in (req.get("headers") or {}).items()
            if not str(k).lower().startswith("x-hackerone")}
    return {"method": str(req.get("method") or "GET").upper(), "path": u.path or "/", "query": u.query or "",
            "headers": hdrs, "body": req.get("body") if req.get("body") not in ("", None) else None}


def _edge_hypothesis(program, edge_id):
    m = re.match(r"(?i)^(h\d+)", str(edge_id or "").strip())
    if not program or not m:
        return None
    try:
        return next((h for h in load(program).get("hypotheses", []) if str(h.get("id", "")).upper() == m.group(1).upper()), None)
    except Exception:  # noqa: BLE001
        return None


def _sends_edge_input(program, edge_id, evidence):
    """(ok, why): the edge's hypothesis names inputs and the evidence request sends at least one, or it names none."""
    h = _edge_hypothesis(program, edge_id)
    if not h:
        return True, ""
    names = violation_inputs(h.get("violation"))
    present, missing = capture_sends(evidence, names)
    if names and not present:
        return False, (f"the evidence never sends {h['id']}'s own input ({', '.join(missing)}); its request is the "
                       "plain one, so the response is the route's baseline, not a mechanism")
    return True, ""


def _proof_shape(evidence, control, must_contain, to, program=None, edge_id=None):
    """(ok, why): the shape a PROVEN edge needs beyond 'the file exists and is not a 4xx' (2026-10-25). Two ledgers
    held proven edges today's gates never accept: program-0 E1 unauth -> cross-user-read was an 85 KB SPA shell (200
    text/html) with an 84.6 KB copy of the same shell as its control and no claimed byte; program-101 H2-escalate unauth ->
    ato was a 403 error_code 40003 for both evidence and control. A proof names the terminal byte on a crown, is not
    an SPA soft-200 (T-60), and its control is a DIFFERENT answer (T-31)."""
    mc = must_contain or ""
    if node(to) in CROWNS and not mc:
        return False, (f"the edge claims the crown {node(to)} but names no terminal byte; set must_contain=<the "
                       "private data, changed state or command output in the evidence> (e.g. the victim's email or "
                       "the mutated field) so code can see it.")
    ev = _capture_response(evidence)
    if ev is None:
        return False, ("the evidence is not a raw JSON capture with a response object; a proven edge needs the "
                       "request+response bytes that came off the wire")
    body = _resp_body(ev)
    headers = _resp_headers(ev)
    ctype = " ".join(v for k, v in headers if k == "content-type").lower()
    head = body.lstrip()[:32].lower()
    if "html" in ctype or head.startswith("<!doctype html") or head.startswith("<html"):
        outside = mc and any(mc in v for _, v in headers)
        if not outside:
            return False, ("the evidence is an HTML page (an SPA shell answers 200 + index.html for every path, "
                           "T-60) and " + ("names no byte" if not mc else f"must_contain={mc[:60]!r} sits only in "
                           "that HTML") + "; supply evidence=<the raw JSON/API capture that returns the private "
                           "bytes> with must_contain=<that byte>.")
    ctl = _capture_response(control) if control else None
    if control and ctl is None:
        return False, ("the negative control is not a raw JSON capture with a response object; a control is the "
                       "OTHER request's captured bytes (or name control_na=<why none is possible>)")
    if control and _capture_request(control) is None:
        return False, ("the negative control capture has no request object; the control must show the request that "
                       "was refused, so code can verify it differs in one variable")
    if _capture_request(evidence) is None:
        return False, ("the evidence capture has no request object; a proof must show the exact request that "
                       "produced the terminal bytes")
    if ctl is not None:
        cbody = _resp_body(ctl)
        same_status = _resp_status(ctl) == _resp_status(ev)
        a, b = len(body), len(cbody)
        near = cbody == body or abs(a - b) <= 0.02 * max(a, b)
        if mc and mc in cbody:   # D98: the more specific refusal first
            return False, (f"must_contain={mc[:60]!r} is in the CONTROL's body as well, so it is what the route answers "
                           "anyone (the baseline), not the capability; name a byte the control does NOT carry.")
        if same_status and near:
            return False, (f"the control answered the same status {_resp_status(ev)} with a body of {b} bytes "
                           f"against the evidence's {a} (within 2%), so it shows no boundary; supply control=<the "
                           "raw capture of the REFUSED request that differs in one variable (T-31)>.")
        ereq, creq = _capture_request(evidence), _capture_request(control)
        if ereq and creq:
            ev_v, ct_v = _request_vars(ereq), _request_vars(creq)
            diff = [k for k in ev_v if ev_v[k] != ct_v[k]]
            if len(diff) > 1:   # D98 (T-31: one variable)
                return False, (f"the control differs from the evidence in {len(diff)} variables ({', '.join(diff)}); "
                               "a negative control is the SAME request with ONE thing removed or changed (the edge's "
                               "input), so the boundary it shows is that input's. Fire that control and cite it.")
    # D98 (cycle 26, 11:26Z): H47-edge "unauth -> ato" was proven on a plain POST that never sent the X-Partner-Token
    # header its hypothesis named; a proof must SEND the input the hypothesis says breaks the boundary.
    h = _edge_hypothesis(program, edge_id)
    if h:
        names = violation_inputs(h.get("violation"))
        present, missing = capture_sends(evidence, names)
        if names and not present:
            return False, (f"the evidence never sends {h['id']}'s own input ({', '.join(missing)}); its request is "
                           "the plain one, so the response is the route's baseline. Fire the request WITH that input "
                           "(http_request headers=/body=) and cite that capture as the proof.")
    return True, ""


def _next_id(rows, prefix):
    n = max([int(r["id"][1:]) for r in rows if re.fullmatch(prefix + r"\d+", r.get("id", ""))] or [0])
    return f"{prefix}{n + 1}"


def _find(rows, rid):
    # case-insensitive (2026-10-23): ids the model mints like "H2-edge-1" are stored as typed, but the lookup
    # upper-cased the query only, so every update on such an id answered "no edge H2-edge-1" while the listing
    # showed it - the lead re-added the edge instead (launch #15/#16 on program-101).
    rid = (rid or "").strip().upper()
    return next((r for r in rows if str(r.get("id", "")).upper() == rid), None)


GHOST_GUESSES = 3   # routes answering only a generic 404 that one hypothesis may spend probes on


def ghost_routes(h):
    """Routes of this hypothesis whose every recorded answer was a 404: the host's generic not-found page, i.e. a
    route that does not exist. Drive cycle 17 (2026-10-26): H22 spent 12 probes on nine such guesses."""
    out = []
    for route, shapes in (h.get("routes") or {}).items():
        keys = [str(k) for k in (shapes or {})]
        if keys and all(k.startswith("404:") for k in keys):
            out.append(route)
    return out


def ghost_guesses_spent(program, hyp_id):
    """The refusal line when the hypothesis has already spent GHOST_GUESSES routes on nothing, else None."""
    if not program or not hyp_id:
        return None
    try:
        h = _find_hyp(load(program).get("hypotheses", []), hyp_id)
    except Exception:  # noqa: BLE001
        return None
    if not h:
        return None
    ghosts = ghost_routes(h)
    if len(ghosts) < GHOST_GUESSES:
        return None
    return (f"refused: {h['id']} has already spent {len(ghosts)} routes that do not exist (every answer a 404: "
            + ", ".join(ghosts[:4]) + ("..." if len(ghosts) > 4 else "") + "); no more guessed paths for this "
            "hypothesis. Probe a route from KNOWN ROUTES (targets/<p>/hunts/gnoc/known-paths.txt), js_mine the app "
            "bundle for the real one, or hunt_hypothesis(action=update, status=unfired, notes='no surface').")


GHOST_REFUSALS_PARK = 3   # guessed-path refusals (D44) a hypothesis takes before it is parked UNFIRED


def note_ghost_refusal(program, hyp_id):
    """Count a D44 refusal on the hypothesis; at GHOST_REFUSALS_PARK park it UNFIRED (no surface) and return the
    park line, else None. Drive cycle 18 (2026-10-26 05:35Z): H24 was refused four times across turns and the lead
    re-sent a new guess every turn, because the refusal-streak breaker resets per turn and nothing parked it."""
    if not program or not hyp_id:
        return None
    parked = []

    def _bump(d, hid=hyp_id):
        h = _find_hyp(d["hypotheses"], hid)
        if not h or h.get("status") not in ("open", "probing"):
            return
        h["ghost_refusals"] = int(h.get("ghost_refusals") or 0) + 1
        if h["ghost_refusals"] >= GHOST_REFUSALS_PARK:
            h["status"] = "unfired"
            h["notes"] = ((h.get("notes") or "") + f" | parked UNFIRED: {h['ghost_refusals']} guessed-path refusals, "
                          f"no real route carried the seam ({_now()})").strip(" |")
            parked.append(h["id"])
    try:
        modify(program, _bump)
    except Exception:  # noqa: BLE001
        return None
    if parked:
        return (f"{parked[0]} is now UNFIRED: {GHOST_REFUSALS_PARK} refusals for guessed paths and no real route carried "
                "its seam. Move to the next open hypothesis, or hypothesize for a seam on a route in KNOWN ROUTES.")
    return None


WALL_REFUSALS_PARK = 3   # D64: wall refusals a hypothesis gets before code parks it (floor never reached)


def note_wall_refusal(program, hyp_id):
    """Count a route-wall refusal on the hypothesis; at WALL_REFUSALS_PARK, when the counted probes are under the
    floor, park it UNFIRED by code and return the park line, else ''. Drive cycle 22 (2026-10-26 08:43Z): the wall
    refused 37 probes in 30 minutes, 13 of them under H33 (22 probes, 3 counted); the wall check runs before the
    budget check in the sender, so park_spent (D63) never ran and the lead kept re-sending."""
    if not program or not hyp_id:
        return ""
    parked = []

    def _bump(d, hid=hyp_id):
        h = _find_hyp(d["hypotheses"], hid)
        if not h or h.get("status") not in ("open", "probing"):
            return
        h["wall_refusals"] = int(h.get("wall_refusals") or 0) + 1
        if h["wall_refusals"] >= WALL_REFUSALS_PARK and counted_probes(h, program) < FLOOR:
            h["status"] = "unfired"
            h["notes"] = ((h.get("notes") or "") + f" | parked UNFIRED by code: {h['wall_refusals']} wall refusals, "
                          f"{counted_probes(h, program)} of {h['probes']} probes reached a route that answered ({_now()})").strip(" |")
            parked.append(h["id"])
    try:
        modify(program, _bump)
    except Exception:  # noqa: BLE001
        return ""
    if parked:
        return (f" {parked[0]} is now UNFIRED by code: its probes keep hitting walls and the floor was never reached "
                "on a route that answered. Probe a different open hypothesis, or add one on a route that exists.")
    return ""


def scope_hosts(program):
    """The literal in-scope hosts of targets/<program>/SCOPE.txt (rows read `URL <host> [...]`), file order."""
    out = []
    try:
        for ln in open(os.path.join(WS, "targets", program, "SCOPE.txt")).read().splitlines():
            if ln.lstrip().startswith("#"):
                continue
            m = re.search(r"(?:^|\s|=)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=\s|$|\t)", ln.strip().lower())
            if m and m.group(1) not in out:
                out.append(m.group(1))
    except OSError:
        pass
    return out


def route_answered(program, path):
    """True when some hypothesis of the program recorded a 2xx/3xx on a route ending in this path (a real route)."""
    path = "/" + str(path or "").strip().strip("/")
    if path == "/":
        return False
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001
        return False
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            rk = route_key(route)
            if "/" in rk and ("/" + rk.split("/", 1)[1]).rstrip("/") == path and any(_granted(x) for x in shapes):
                return True
    return False


PREFIX_DEAD_PATHS = 2   # distinct non-granting paths under one prefix before the PREFIX is the thing that is dead
# A STATIC ASSET: a cacheable file the CDN serves identically to everyone. It is js_mine INPUT, never a seam.
_STATIC_PREFIX = re.compile(r"^/(?:static|assets?|_next/static|dist|build|public|css|img|images|fonts|media)(?:/|$)",
                            re.I)
_STATIC_EXT = re.compile(r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|pdf)$", re.I)


def is_static_asset(path):
    """True when this path is a cacheable static asset rather than a handler that can hold state."""
    p = "/" + str(path or "").strip().strip("/")
    return bool(_STATIC_PREFIX.match(p) or _STATIC_EXT.search(p.split("?", 1)[0]))


def _prefix_of(path):
    """The first two path segments, the unit a route actually lives under. '/static/js/fetchConfig/app' -> '/static/js'."""
    segs = [x for x in str(path or "").strip("/").split("/") if x][:2]
    return "/" + "/".join(segs) if segs else ""


def dead_prefixes(program):
    """{prefix: (shape, distinct paths)} for the path PREFIXES where every probe this program ever fired was refused.

    D80 (program-72 drive r11, 2026-10-28 13:26Z): the reopen gate compares WHOLE PATHS, so the lead escaped a spent
    budget three times by permuting the tail under one dead prefix - /static/js/fetchConfig/app, then .../social, then
    .../translations, all `403 len=716`, 20 probes on a static-asset prefix under a hypothesis whose seam was
    pay-then-verify. Each path was genuinely new, so each reopen was genuinely accepted, and the cap bought nothing.
    What is dead is the PREFIX, not the spelling: once two distinct paths under it answer only refusals, a third
    spelling is the same probe, which is exactly what WALL_* already says one route at a time."""
    per = {}
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001
        return {}
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            rk = route_key(route)
            if "/" not in rk:
                continue
            path = "/" + rk.split("/", 1)[1]
            pref = _prefix_of(path)
            if not pref:
                continue
            b = per.setdefault(pref.lower(), {"paths": {}, "granted": False})
            for sh, n in bucketed(shapes).items():
                b["paths"].setdefault(path.rstrip("/"), {})[sh] = int(n or 0)
                if _granted(sh):
                    b["granted"] = True
    out = {}
    for pref, b in per.items():
        if b["granted"] or len(b["paths"]) < PREFIX_DEAD_PATHS:
            continue
        shapes = {}
        for per_path in b["paths"].values():
            for sh, n in per_path.items():
                shapes[sh] = shapes.get(sh, 0) + n
        top = max(shapes.items(), key=lambda kv: kv[1])[0]
        out[pref] = (top, len(b["paths"]))
    return out


def reopen_refusal(program, h, notes):
    """The refusal when a dead/unfired hypothesis is set back to open without a NEW route in notes, else None. D78
    (cycle 24, 10:07Z): H40's DEAD was refused for never reaching a route; the lead set it open again with notes
    'positive control: /api/account' (a program wall, 151 refusals) and spent a second budget on the same wall."""
    paths = [m.rstrip("/") for m in _PATH_TOKEN.findall(str(notes or "")) if len(m.rstrip("/")) > 2]
    if not paths:
        return (f"refused: reopening {h['id']} needs notes naming a NEW route for its seam (a path it has not probed, "
                "not a program wall), e.g. notes='new route: /v1/skills from js_mine'.")
    try:
        walls = program_walls(program)
    except Exception:  # noqa: BLE001
        walls = {}
    probed = {("/" + route_key(r).split("/", 1)[1]).rstrip("/") for r in (h.get("routes") or {}) if "/" in route_key(r)}
    wall_paths = {("/" + rk.split("/", 1)[1]).rstrip("/") for rk in walls if "/" in rk}
    for pth in paths:
        if pth.lower() in {w.lower() for w in wall_paths}:
            return f"refused: {pth} is a program wall; reopening {h['id']} on it is the same probe again."
        if pth.lower() in {w.lower() for w in probed}:
            return f"refused: {pth} was already probed under {h['id']}; a reopen needs a route it has not seen."
    for pth in paths:
        if is_static_asset(pth):
            return (f"refused: {pth} is a STATIC ASSET, so it cannot be the seam a reopen buys a new budget for. "
                    f"A cacheable file the CDN serves identically to everyone holds no state to race, no owner key "
                    f"to drift and no money to move; it is js_mine INPUT. Fetch it to MINE it if you like, then "
                    f"reopen {h['id']} on a handler one of its literals names.")
    try:
        dead = dead_prefixes(program)
    except Exception:  # noqa: BLE001
        dead = {}
    for pth in paths:
        pref = _prefix_of(pth).lower()
        if pref and pref in dead:
            shape, n = dead[pref]
            return (f"refused: {pth} is a NEW SPELLING under a dead prefix. Every one of the {n} paths this program "
                    f"probed under {pref} answered {shape} and none granted, so reopening {h['id']} there is the same "
                    f"probe again. Name a route under a DIFFERENT prefix, or record the verdict.")
    return None


def park_spent(program, hyp_id):
    """'' or the line saying the hypothesis was parked UNFIRED because its budget is spent and the floor was never
    reached on a route that answered (every probe past the counted few hit a wall). D63 (drive cycle 22, 2026-10-26
    08:20Z): H33 sat at 22 probes, 3 counted, status probing; the wall refused each probe, the budget refused the rest,
    verdict_owed needs counted probes, and the lead spent its turns re-asking. UNFIRED is a fact about the probes
    (they never reached a surface), the same status the DEAD gate already records by code."""
    try:
        d = load(program)
        h = _find_hyp(d.get("hypotheses", []), hyp_id)
    except Exception:  # noqa: BLE001
        return ""
    if not h or h.get("status") not in ("open", "probing"):
        return ""
    counted = counted_probes(h, program)
    if counted >= FLOOR:
        return ""
    walls = walled_routes(h)
    h["status"] = "unfired"
    h["notes"] = (str(h.get("notes") or "") + f" | parked by code: budget spent, {h['probes']} probes, {counted} counted "
                  f"(floor {FLOOR}); walls: {'; '.join(r for r, _, _ in walls) or 'none recorded'}").strip(" |")
    save(program, d)
    return (f" {h['id']} is now UNFIRED by code: {counted} of {h['probes']} probes reached a route that answered (floor "
            f"{FLOOR}); the rest hit walls. Reopen it only with a NEW route for its seam.")


def open_with_budget(program, budget_fn, skip=None):
    """[(id, probes, budget)] for the live hypotheses (open/probing/lead) with budget left, most room first. D60:
    the budget refusal names where to go next instead of letting the lead walk every exhausted id in turn."""
    out = []
    try:
        rows = load(program).get("hypotheses", [])
    except Exception:  # noqa: BLE001
        return out
    for h in rows:
        if h.get("status") not in ("open", "probing", "lead") or h.get("id") == skip:
            continue
        try:
            b = int(budget_fn(program, h["id"]))
        except Exception:  # noqa: BLE001
            b = 20
        if h.get("probes", 0) < b:
            out.append((h["id"], int(h.get("probes", 0)), b))
    out.sort(key=lambda t: t[1] - t[2])
    return out


def closed_hypothesis(program, hyp_id):
    """The refusal line when the hypothesis is dead or unfired, else None. Drive cycle 21 (2026-10-26 07:50Z): H26
    was parked UNFIRED at 12 probes, took another probe, and was parked again at 13; a closed hypothesis is not a
    budget to keep spending. Reopening is one explicit call, so a real new surface is never blocked."""
    if not program or not hyp_id:
        return None
    try:
        h = _find_hyp(load(program).get("hypotheses", []), hyp_id)
    except Exception:  # noqa: BLE001
        return None
    if not h or h.get("status") not in ("dead", "unfired"):
        return None
    return (f"refused: {h['id']} is {h['status']} and takes no probe. If you found a REAL new route for its seam, "
            f"reopen it first: hunt_hypothesis(action=update, id={h['id']}, status=open, notes='<the route and why>'); "
            "otherwise probe a live hypothesis (hunt_hypothesis action=list).")


def verdict_owed(program, hyp_id):
    """The refusal line when the hypothesis is in PHASE VERDICT (still probing past 2 x the floor, counted or spent,
    and the directive has already asked for a decision at least once), else None. Drive cycle 17 (2026-10-26
    04:11Z): in its first verdict turn the lead fired eight more H16 probes at a walled route instead of deciding."""
    if not program or not hyp_id:
        return None
    try:
        h = _find_hyp(load(program).get("hypotheses", []), hyp_id)
    except Exception:  # noqa: BLE001
        return None
    if not h or h.get("status") != "probing" or int(h.get("verdict_turns") or 0) < 1:
        return None
    if counted_probes(h, program) < VERDICT_AT and int(h.get("probes") or 0) < VERDICT_AT:
        return None
    return (f"refused: {h['id']} owes a VERDICT, not another probe ({h['probes']} probes spent, floor {FLOOR}). "
            f"Decide now with hunt_hypothesis(action=update, id={h['id']}, status=lead|dead|unfired, notes=<the "
            f"deciding bytes or the wall shape>), then probe the next open hypothesis.")


def canonical_hyp_id(program, hyp_id):
    """The ledger id a typed hypothesis id resolves to ("H16-mutated" -> "H16"), or the typed id when it resolves to
    nothing. Drive cycle 15 (2026-10-26): the lead fired under 'H16-mutated'; log_probe counted the probe on H16 through
    _find_hyp, but the economy keyed the budget on the raw string, so the mutation carried a budget of its own."""
    if not program or not hyp_id:
        return hyp_id
    try:
        h = _find_hyp(load(program).get("hypotheses", []), hyp_id)
    except Exception:  # noqa: BLE001
        return hyp_id
    return h["id"] if h and h.get("id") else hyp_id


def _find_hyp(rows, rid):
    """A hypothesis by id, or by the H# inside an edge-style id ("H1-escalation-1" -> H1): launch #20 fired
    http_request(hypothesis='H1-escalation-1') and the probe was counted against nothing, bypassing the budget."""
    h = _find(rows, rid)
    if h is None and rid:
        m = re.search(r"\b(H\d+)\b", str(rid), re.I)
        if m and m.group(1).upper() != str(rid).strip().upper():
            h = _find(rows, m.group(1))
    return h


# ---------------------------------------------------------------- evidence (proof integrity in code)

SHELL_BAND = 0.15   # an HTML 2xx within 15% of another route's answer length on the same host = the same shell
SHELL_MIN = 20000   # under this an HTML answer is too small to be an app shell


def _program_of(path):
    m = re.search(r"targets/([A-Za-z0-9_.-]+)/", str(path or ""))
    return m.group(1) if m else ""


def shell_lengths(program, host):
    """Body lengths of 2xx answers this host gave, keyed by the routes that gave them (from the ledger's per-route
    shapes). A length that recurs within SHELL_BAND on 2+ distinct routes is the host's shell band."""
    out = []
    try:
        H = load(program)["hypotheses"]
    except Exception:  # noqa: BLE001
        return out
    for h in H:
        for route, shapes in (h.get("routes") or {}).items():
            if route.split("/")[0].lower() != host.lower():
                continue
            for s in shapes:
                st, _, ln = s.partition(":")
                if st.isdigit() and ln.isdigit():   # any status: the shell answers 200 on app routes, 404 elsewhere
                    out.append((route_key(route), int(ln)))
    return out


def is_soft200_shell(evidence):
    """(True, why) when the capture is a 2xx HTML document whose length matches, within SHELL_BAND, 2xx answers the
    same host gave on at least two OTHER distinct routes. Drive cycle 10 (2026-10-26): H12/H14/H15 became leads on
    api.program-0.example answers of 84.6-85.3 KB that every path on that host returns (the SPA shell, length drifting
    with a per-response nonce), the same shell the handoff's E1 'proof' was built on."""
    try:
        p = os.path.realpath(evidence if os.path.isabs(evidence) else os.path.join(WS, evidence))
        j = json.loads(open(p, "rb").read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return False, ""
    req, resp = (j.get("request") or {}), (j.get("response") or {})
    st = resp.get("status")
    body = resp.get("body")
    body = body if isinstance(body, str) else (json.dumps(body) if body is not None else "")
    if not (isinstance(st, int) and 200 <= st < 300) or not re.search(r"<!doctype html|<html", body[:600], re.I):
        return False, ""
    if len(body) < SHELL_MIN:
        return False, ""
    url = str(req.get("url") or "")
    m = re.match(r"https?://([^/\s]+)", url)
    if not m:
        return False, ""
    host, me = m.group(1), route_key(url)
    n = len(body)
    if me.lower() == host.lower():   # D70: GET https://host/ is the app's landing document (H36, 207 KB console root)
        return True, (f"the capture is {host}'s root document ({st} HTML, {n} bytes): the application shell every "
                      "visitor gets, not a mechanism. Cite the response of the route the VIOLATION names.")
    others = {r for r, ln in shell_lengths(_program_of(evidence), host) if r != me and abs(ln - n) <= SHELL_BAND * max(n, 1)}
    if len(others) >= 1:
        return True, (f"the capture is a {st} HTML document of {n} bytes, within {int(SHELL_BAND * 100)}% of what {host} "
                      f"answers on {len(others)} other route(s) ({', '.join(sorted(others)[:2])}): the SPA shell every "
                      "path gets, not a mechanism (T-60). A mechanism is bytes that differ from the control.")
    return False, ""


def _mechanism_shape(evidence):
    """A lead's capture must show the mechanism: a refused response (4xx/5xx) with no claimed byte is the NEGATIVE,
    not a lead (launch #18 stored a 403 as 'unauth -> ato [lead]')."""
    p = os.path.realpath(evidence if os.path.isabs(evidence) else os.path.join(WS, evidence))
    try:
        j = json.loads(open(p, "rb").read().decode("utf-8", "replace"))
    except (OSError, ValueError):
        return False, ("the evidence is not a raw JSON capture with request+response; a lead needs the bytes that "
                       "show the mechanism, not a note or a hand-written file")
    if not isinstance(j, dict) or not isinstance(j.get("response"), dict):
        return False, ("the evidence JSON has no response object; a lead needs the raw request+response capture, "
                       "not a hand-written file")
    st = j["response"].get("status")
    if isinstance(st, int) and st >= 400:
        return False, (f"the capture is an HTTP {st} refusal; a lead needs a response that shows the mechanism "
                       "(2xx/3xx, or must_contain=<the byte that proves it>)")
    shell, why = is_soft200_shell(evidence)
    if shell:
        return False, why
    return True, "ok"


def check_evidence(evidence, must_contain=None):
    """(ok, why). Evidence must be a non-empty file inside the workspace; must_contain must appear in it."""
    if not evidence:
        return False, "no evidence path"
    p = os.path.realpath(evidence if os.path.isabs(evidence) else os.path.join(WS, evidence))
    if not p.startswith(WS + os.sep):
        return False, f"evidence must live inside the workspace: {evidence}"
    if not os.path.isfile(p):
        return False, f"evidence file does not exist: {evidence}"
    if os.path.getsize(p) == 0:
        return False, f"evidence file is empty: {evidence}"
    if must_contain:
        with open(p, "rb") as f:
            blob = f.read()
        # the raw capture is JSON, so a body byte like "email":"x" sits on disk as \"email\":\"x\": compare against
        # the decoded body too, or every quoted terminal byte would be refused as absent
        forms = [blob, blob.replace(b"\\/", b"/"), blob.replace(b'\\"', b'"').replace(b"\\/", b"/")]
        try:
            j = json.loads(blob.decode("utf-8", "replace"))
            body = (j.get("response") or {}).get("body") if isinstance(j, dict) else None
            if body is not None:
                forms.append((body if isinstance(body, str) else json.dumps(body)).encode())
        except ValueError:
            pass
        if not any(must_contain.encode() in f for f in forms):
            return False, f"evidence does not contain the claimed bytes {must_contain[:80]!r}"
    return True, "ok"


# ---------------------------------------------------------------- the trust model (theorize before probing)

MODEL_KEYS = ("actors", "boundaries", "promises", "catastrophes", "stack")


def _serialized(fn):
    """Every read-modify-write of the ledger runs under locked(program). run_tools fires approved calls IN
    PARALLEL (up to 4), so three hunt_hypothesis adds in one turn each loaded the ledger, computed H1, and saved:
    last writer won and the ledger kept ONE of three hypotheses, all three answered 'added H1' (program-101, 2026-10-23).
    The lock is re-entrant, so a function that calls modify() or another serialized function still works."""
    import functools

    @functools.wraps(fn)
    def wrapped(program, *a, **kw):
        with locked(program):
            return fn(program, *a, **kw)
    return wrapped


@_serialized
def model(program, action="show", actors=None, boundaries=None, promises=None, catastrophes=None, stack=None):
    """The target model an expert reasons FROM: actors + roles, trust boundaries (each names the asset it protects
    AND the actor it excludes), the vendor's documented promises (verbatim + URL: the cash multiplier), the
    catastrophe list, the fingerprinted stack. Hypotheses cite a boundary; a hypothesis that cites none is a guess."""
    d = load(program)
    M = d["model"]
    if action in ("add", "set"):
        # PARTIAL ACCEPT (2026-10-23): one malformed item used to refuse the WHOLE call, so the actors, boundaries
        # and catastrophes typed beside it were thrown away too, and a small lead model re-sent the identical call
        # in a loop (measured on program-101: the same hunt_model add refused three times for one URL-less promise).
        # Now every well-formed item is SAVED, the malformed ones are dropped, and the note names exactly what to
        # fix: progress plus a precise correction instead of a dead end.
        notes = []
        for key, val in (("actors", actors), ("boundaries", boundaries), ("promises", promises),
                         ("catastrophes", catastrophes), ("stack", stack)):
            if val is None:
                continue
            sep = r"\n|;" if key in ("actors", "catastrophes", "stack") else r"\n| \| "
            items = val if isinstance(val, list) else [x.strip() for x in re.split(sep, str(val)) if x.strip()]
            if key == "boundaries":
                bad = [b for b in items if not re.search(r"(protect|excl|must not|cannot|only)", b, re.I)]
                if bad:
                    notes.append("DROPPED boundary (each boundary names the ASSET it protects and the ACTOR it "
                                 "excludes, e.g. 'B1: order records are readable only by their owner; excludes other "
                                 f"customers and anonymous'): {bad[0][:120]}")
                    items = [b for b in items if b not in bad]
            if key == "promises":
                bad = [x for x in items if "http" not in x]
                if bad:
                    notes.append("DROPPED promise (quote the vendor's sentence VERBATIM and give its URL; a promise "
                                 "without a URL is not anchorable in a report; web_fetch the policy or help page "
                                 f"first, then re-add ONLY the promise): {bad[0][:120]}")
                    items = [x for x in items if x not in bad]
            if key == "catastrophes" and items:
                # THE ROOT CAUSE. This store is free text an agent types, nothing checked it against
                # the file, and SPINE 2 tells every hunt to reason FROM it. That is how program-64's slot
                # came to hold Gatewayco's model and program-32' came to hold program-101's vocabulary.
                # Checked PER ITEM, not on the merged list: a two-thirds test on the whole store lets
                # contamination in one item at a time, which is exactly how a store drifts (caught by
                # this module's own test, 2026-10-25). Each item has to be recognisable in the file.
                filed = filed_catastrophes(program)
                if filed:
                    fw = [set(re.findall(r"[a-z]{4,}", ln.lower())) for ln in filed]
                    bad = [it for it in items
                           if not any(len(set(re.findall(r"[a-z]{4,}", str(it).lower())) & w) >= 2
                                      for w in fw)]
                    if bad:
                        notes.append("DROPPED " + str(len(bad)) + " catastrophe(s) that appear nowhere in "
                                     "targets/" + program + "/TARGET-MODEL.md, which carries the program's "
                                     "OWN words (SPINE 2): " + "; ".join(str(b)[:70] for b in bad[:3])
                                     + ". A catastrophe typed from memory is how one program's store ended "
                                     "up holding another program's model. The file says:\n"
                                     + "\n".join(f"      {i + 1}. {x}" for i, x in enumerate(filed[:12])))
                        items = [it for it in items if it not in bad]
                    if not items:
                        continue
            cur = M.get(key) or []
            if key == "catastrophes" and action == "set":
                cur = []
            for it in items:
                if it not in cur:
                    cur.append(it)
            M[key] = cur
        d["model"] = M
        save(program, d)
        out = model(program, "show")
        if notes:
            out = "saved the well-formed items; " + "; ".join(notes) + "\n" + out
        return out
    if action == "stored":
        cur = M.get("catastrophes") or []
        if not cur:
            return "nothing stored for catastrophes."
        return ("STORED catastrophes, as typed by an agent. This is NOT the program's wording and is not "
                "what a hunt reasons from when it disagrees with targets/" + program + "/TARGET-MODEL.md:\n"
                + "\n".join(f"  {i + 1}. {x}" for i, x in enumerate(cur)))
    if not any(M.get(k) for k in MODEL_KEYS):
        return ("no model yet. Build it before hypothesizing: hunt_model(action=add, actors=..., boundaries=..., "
                "promises=..., catastrophes=...). Boundaries drive hypotheses; promises drive the paid shape.")
    # GATE, not a note (GreyNOC, 2026-10-25). The note version was read and ignored: handed program-64's
    # stored list - which is GATEWAYCO's model - the agent reasoned from it, never opened TARGET-MODEL.md, and
    # fired real requests at facebook.com chasing Gatewayco's surface. SPINE 2 says the catastrophes are the
    # program's OWN words, the file carries those, and a free-text store an agent typed does not outrank
    # it. So a drifted store is REPLACED here by the file's list and is not shown: the model cannot
    # reason from material it is not given. The store is untouched on disk and `action=stored` prints it.
    drifted = catastrophes_drifted(program, M.get("catastrophes") or [])
    gate = ""
    if drifted:
        filed = filed_catastrophes(program)
        M = dict(M, catastrophes=filed)
        gate = ("\nCATASTROPHES came from targets/" + program + "/TARGET-MODEL.md, not from this store. The "
                f"stored list ({len(load(program)['model'].get('catastrophes') or [])} items) does not match the "
                "file and is WITHHELD: it was typed in by an agent, it is not the program's words, and on "
                "2026-10-25 one program's store held another program's model. Quote the list above, which is "
                "the file. To see the stored text anyway: hunt_model(action=stored). To correct the store: "
                "hunt_model(action=set, catastrophes=<the file's items>).")
    out = []
    for k in MODEL_KEYS:
        if M.get(k):
            out.append(k.upper() + ":")
            out += [f"  {i + 1}. {x}" if k != "stack" else f"  {x}" for i, x in enumerate(M[k])]
    if drifted and not M.get("catastrophes"):
        out.append("CATASTROPHES: the stored list is WITHHELD (see below) and the file has none to show.")
    note = "" if drifted else _catastrophe_provenance(program, M.get("catastrophes") or [])
    return "\n".join(out + ([gate] if gate else []) + ([note] if note else []))


def filed_catastrophes(program):
    """The catastrophe list from targets/<program>/TARGET-MODEL.md: the program's OWN words (SPINE 2)."""
    path = os.path.join(WS, "targets", program, "TARGET-MODEL.md")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    # "CATASTROPHE LIST" (program-32) and "## 7. What would be catastrophic here" (program-64) are both
    # the section SPINE 2 asks for; matching only the first spelling skipped the second in silence.
    m = re.search(r"^#+[^\n]*catastroph[^\n]*\n(.*?)(?=^#|\Z)", text, re.S | re.M | re.I)
    if not m:
        return []
    # NUMBERED items only. Every non-empty line swept up wrapped continuations and trailing prose, which
    # inflated the denominator and fired on a stored list that DID quote the file.
    filed = [ln.strip().strip("*_ ") for ln in
             re.findall(r"^\s*[*_]{0,2}\s*\d+\.\s*(.+)$", m.group(1), re.M)]
    return [ln for ln in filed if len(ln) > 12]


def catastrophes_drifted(program, stored):
    """True when a stored list exists, the file has one too, and the stored one does not track it."""
    filed = filed_catastrophes(program)
    if not stored or not filed:
        return False
    words = set(re.findall(r"[a-z]{4,}", " ".join(stored).lower()))
    overlap = sum(1 for ln in filed if len(words & set(re.findall(r"[a-z]{4,}", ln.lower()))) >= 2)
    return overlap < max(1, (len(filed) * 2 + 2) // 3)   # two thirds recognisable = close enough to quote


def _catastrophe_provenance(program, stored):
    """Say where the catastrophe list came from when the file disagrees with it.

    This store is free text an agent TYPED with action=add; it is not derived from TARGET-MODEL.md.
    On 2026-10-25 program-32' stored list read "ATO via PID forgery / cross-tenant access via EAA
    replay / mass-PII leakage / admin twin impersonation" while the file says "Remote impersonation /
    Forgery of arbitrary identities / Mass leakage of identity data / Systemic compromise of signing
    authority". "admin twin" is program-101 vocabulary that leaked in from a hunt running at the time. Asked
    for the catastrophes "in the program's own words", the agent quoted this store and called it the
    program's words. SPINE section 2 requires the vendor's OWN words, so the file wins; this note does
    not overwrite the store, it just stops the paraphrase being passed off as a quotation."""
    if not catastrophes_drifted(program, stored):
        return ""
    return ("\nNOTE on CATASTROPHES: the list above was TYPED into this store by an agent and does not "
            f"match targets/{program}/TARGET-MODEL.md, which carries the program's OWN words (SPINE 2 "
            "requires those). Read the file before quoting a catastrophe as the program's wording.")


def boundaries(program):
    return load(program)["model"].get("boundaries") or []


def stack_tags(program):
    return load(program)["model"].get("stack") or []


# ---------------------------------------------------------------- hypotheses

@_serialized
def hypothesis(program, action="list", id=None, title=None, crown=None, assumption=None, violation=None,
               prediction=None, kill_byte=None, status=None, notes=None, evidence=None, burst=None,
               boundary=None, requires=None):
    d = load(program)
    H = d["hypotheses"]
    if action == "add":
        if not (title and assumption and violation and prediction):
            return "refused: a hypothesis needs title, assumption, violation and prediction (SPINE 4)"
        crown_n = node(crown) if crown else None
        if crown_n not in CROWNS:
            # five of nine program-101 hypotheses had crown None and were the escalation plan's own HEADINGS ("THE PAIRED
            # WRITE", "WHAT THE DISCLOSED THING UNLOCKS") copied back as new hypotheses (2026-10-23)
            return (f"refused: crown={crown!r} is not a crown class. A hypothesis names the terminal it reaches: one of "
                    f"{', '.join(CROWNS)}. If this is an escalation MOVE on an existing lead, record it as a hop with "
                    "hunt_edge (frm=<the held capability>, to=<crown>, via=<the concrete request>) instead.")
        if _EDGE_TITLE.search(title or ""):
            return ("refused: that title is an edge id, not a hypothesis. Record a hop with hunt_edge; a hypothesis "
                    "names an actor, an asset and the boundary that should stop it.")
        if _MOVE_TITLE.search(title or ""):
            return ("refused: that title is one of the five escalation MOVES, not a hypothesis. Apply the move to the "
                    "held lead as a concrete hop: hunt_edge frm=<capability> to=<crown> via=<method path field>, then "
                    "prove it with a request and a negative control.")
        if _HOP_TITLE.search(title or ""):
            return ("refused: the title starts with another hypothesis id, so this is an escalation HOP on that "
                    "hypothesis, not a new one (program-101 minted H5, H6 and H7 this way, all the same idea). Record it with "
                    "hunt_edge frm=<the capability that hypothesis holds> to=<crown> via=<method path field>, or give "
                    "this hypothesis its own title naming an actor, an asset and the boundary.")
        if not concrete_input(violation):
            return ("refused: the violation names no concrete request. Write the ONE crafted request: the PATH (a route "
                    "from known-paths or js_mine, starting with /), the method, and the field, header or parameter you "
                    "mutate (e.g. 'POST /api/v1/transfer dest_id=<B's id> as A'). A violation that cannot be typed into "
                    "http_request cannot be probed, and without a path the wall and ghost-route gates cannot check it.")
        bad, why = prediction_is_refusal(prediction, kill_byte)
        if bad:
            return f"refused: {why}."
        walled = violation_on_wall(program, violation)   # D58
        if walled:
            return walled
        unknown = unknown_route_refusal(program, violation)   # D79
        if unknown:
            return f"refused: {unknown}"
        bad, why = prediction_is_self_read(prediction, kill_byte, crown_n)
        if bad:
            return f"refused: {why}."
        req = [r.strip() for r in (requires if isinstance(requires, list) else str(requires or "").split(",")) if r.strip()]
        ok, why = DOC.premise_gate("unauth", req, crown_n or "")
        if not ok:
            return f"refused: {why}. Re-aim at a terminal the premise does not already grant."
        # NEAR-DUPLICATE guard (2026-10-23): after a restart the lead re-added "100-bucket session collision" as H3
        # next to the live H1 with the same title and violation, then split its probes between them. The same
        # title (or the same crown + violation) IS the existing hypothesis: point at it instead of minting a twin.
        for prev in H:
            same_title = _sim(prev.get("title"), title) >= 0.85
            same_shape = prev.get("crown") == crown_n and _sim(prev.get("violation"), violation) >= 0.85
            if same_title or same_shape:
                return (f"duplicate of {prev['id']} ({prev['status']}, {prev.get('probes', 0)} probes): "
                        f"{prev['title']!r}. Not added. Continue on {prev['id']} (probe it, or hunt_hypothesis "
                        f"action=update id={prev['id']} to change its violation or status) instead of a twin.")
        h = {"id": _next_id(H, "H"), "title": title, "crown": crown_n, "assumption": assumption,
             "violation": violation, "prediction": prediction, "kill_byte": kill_byte or "", "status": "open",
             "probes": 0, "burst": False, "evidence": [], "notes": notes or "", "ts": _now(),
             "boundary": (boundary or "").strip(), "requires": req}
        H.append(h)
        save(program, d)
        _econ("hyp-add", program=program, hyp_id=h["id"])  # ECON: the author posts the market (stake 10 LONG)
        warn = "" if crown_n in CROWNS else f"  (crown {crown!r} is not a crown class: aim at {', '.join(CROWNS)})"
        if not h["boundary"] and d["model"].get("boundaries"):
            warn += "  (cites no trust boundary from the model: a hypothesis that names no boundary is a guess, T-01)"
        kills = DOC.kill_match(f"{title} {assumption} {violation} {prediction}")
        if kills:
            warn += f"  (reads like a pre-rejected shape: {kills[0][0]}; the captured bytes must show the capability)"
        # a hypothesis aimed at a host that cannot pay or cannot be filed is said so NOW, before the first probe
        import gnoc_pay
        seen = set()
        for host in re.findall(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,}\b",
                               f"{title} {assumption} {violation} {h['boundary']}".lower()):
            if host in seen:
                continue
            seen.add(host)
            v, why, _ = gnoc_pay.payability(program, host)
            if v in ("descoped", "not-submittable", "verify-only"):
                warn += f"  (MONEY: {host} is {gnoc_pay.VERDICT_WORD[v]} - a finding there can never be filed; re-aim)"
            elif v == "no-bounty":
                warn += f"  (MONEY: {host} is a no-bounty row - a VDP filing, no payout)"
        return f"added {h['id']}: {title}{warn}{class_precision_note(title, violation, prediction)}"
    if action in ("update", "set"):
        h = _find(H, id)
        if not h:
            return f"no hypothesis {id}; list them with action=list"
        if kill_byte:
            weak = weak_kill_byte(kill_byte, h)   # D70
            if weak:
                return f"refused: {weak}."
        if status:
            status = status.lower()
            if status not in STATUSES:
                return f"status must be one of {', '.join(STATUSES)}"
            if status in ("lead", "candidate") and budget_left(program, h) <= 0 and not any_granted(h) \
                    and h["status"] in ("open", "probing"):
                # D88 (cycle 25, 10:45Z): four LEAD attempts on H40 in five minutes, each refused on a different
                # ground, while its budget was spent and no probe had ever drawn a 2xx/3xx. The decision tools are
                # exempt from the streak breaker, so the ledger ends it: nothing left to probe, nothing to promote.
                h["status"] = "unfired"
                h["notes"] = (h["notes"] + f" | parked UNFIRED by code: {status} refused with the budget spent and no "
                              "route ever answered").strip(" |")
                save(program, d)
                return (f"refused {status.upper()} for {h['id']}: its budget is spent and none of its {h['probes']} probes "
                        "drew a 2xx/3xx, so there is no mechanism to promote and nothing left to probe. Recorded as "
                        "UNFIRED. Move to the next open hypothesis or add one on a route that exists.")
            if status in ("lead", "candidate"):
                weak = weak_kill_byte(kill_byte or h.get("kill_byte"), h)   # D70: H36 'api', bot 2 'enriched'
                if weak:
                    return f"refused {status.upper()} for {h['id']}: {weak}."
            if status in ("open", "probing") and h["status"] in ("dead", "unfired"):
                bad = reopen_refusal(program, h, notes)   # D78
                if bad:
                    return bad
            reason = (notes or "").strip()
            counted = counted_probes(h, program)
            if status in ("dead", "unfired") and h["probes"] == 0 and not _BLOCKER_WORD.search(reason):
                # D59 (drive cycle 21, 2026-10-26 07:5xZ): H32 was added and parked UNFIRED at 0 probes, twice, with
                # notes "awaiting probe". An unprobed hypothesis is OPEN. Unfired at zero probes needs the blocker named.
                return (f"refused {status.upper()} for {h['id']}: 0 probes logged. An unprobed hypothesis stays open; "
                        f"fire http_request(hypothesis='{h['id']}') on the route its violation names. If something "
                        "blocks the probe (a wall, a NEEDS, scope, a refusal), say which in notes= and it parks.")
            if status == "dead" and counted < FLOOR <= h["probes"]:
                # the floor was reached only by hammering a route that never once answered: no surface was tested
                walls = walled_routes(h)
                h["status"] = "unfired"
                h["notes"] = (h["notes"] + f" | dead refused: {h['probes']} probes but {h['probes'] - counted} hit a "
                              f"wall ({'; '.join(r for r, _, _ in walls)}), {counted} count (floor {FLOOR})").strip(" |")
                save(program, d)
                return (f"refused DEAD for {h['id']}: {wall_text(h)} Recorded as UNFIRED. Prove the surface exists "
                        "first with ONE positive control (the owner's own request that must succeed, or a route from "
                        f"targets/{program}/hunts/gnoc/known-paths.txt or js_mine), then fire the variants on THAT route.")
            pc = re.search(r"(?i)positive control:\s*(\S+)", reason)
            if status == "dead" and not any_granted(h) and not (pc and route_answered(program, pc.group(1).rstrip(",;"))):
                # D68 (drive cycle 23, 2026-10-26 09:03Z): H34 went DEAD at 25 probes with every route a 404 or 405
                # (3 x /api/v1/messages 404, a 405 burst on /api/account): no probe ever reached the seam, so the
                # verdict tested nothing (T-32, T-266). UNFIRED is the fact; a positive control reopens it.
                h["status"] = "unfired"
                h["notes"] = (h["notes"] + f" | dead refused: {h['probes']} probes, no route ever answered 2xx/3xx "
                              f"({'; '.join(sorted((h.get('routes') or {}).keys())[:4]) or 'no routes recorded'})").strip(" |")
                save(program, d)
                return (f"refused DEAD for {h['id']}: none of its {h['probes']} probes drew a 2xx/3xx, so the surface was "
                        "never reached and nothing was tested. Recorded as UNFIRED. Find the route that answers (known-paths, "
                        "js_mine, the vendor docs) and fire ONE positive control there first; a DEAD may cite "
                        "notes='positive control: <route>' only for a route the ledger has seen answer 2xx/3xx.")
            if status == "dead" and counted >= FLOOR and not h.get("bursts") and \
                    not re.match(r"(?i)not single-use:\s*\S.{10,}", reason):
                return (f"refused DEAD for {h['id']}: no concurrent burst was fired (race tool). Burst its single-use "
                        "step, or pass notes='not single-use: <why this path has no one-shot step>'.")
            if status == "dead" and h["probes"] < FLOOR:
                h["status"] = "unfired"
                h["notes"] = (h["notes"] + f" | dead refused at {h['probes']} probes (floor {FLOOR})").strip(" |")
                save(program, d)
                return (f"refused DEAD for {h['id']}: only {h['probes']} probes logged against it (floor {FLOOR} plus "
                        "a burst on any single-use path). Recorded as UNFIRED. Fire more crafted variants with "
                        f"http_request(hypothesis='{h['id']}') first.")
            if status == "candidate":
                # drive cycle 5 (2026-10-26 00:05Z): H6 became CANDIDATE on a 200 len=39 from a public analytics
                # batch route with kill_byte='200_with_accepted_count' - a status description, not a byte in the
                # body. A candidate is the kill byte, literally, in a capture whose response grants (2xx/3xx).
                kb = str(kill_byte or h.get("kill_byte") or "").strip()
                ev = evidence or (h["evidence"] or [None])[-1]
                if not kb:
                    return (f"refused CANDIDATE for {h['id']}: no kill byte. Set kill_byte=<the exact bytes in the "
                            "response that show the capability> and cite evidence=<the raw capture that carries them>.")
                if re.match(r"^\s*\d{3}([_\s-]|$)", kb) or re.search(r"(?i)^(http[_ ]?)?\d{3}[_ ]", kb):
                    return (f"refused CANDIDATE for {h['id']}: kill_byte={kb!r} describes a status code, not bytes. "
                            "Name the private or state-changing bytes the response carries (an id, a token, a field "
                            "of another account, a count that changed).")
                ok, why = check_evidence(ev, kb)
                if ok:
                    ok, why = _terminal_shape(ev, kb)
                if not ok:
                    return f"refused CANDIDATE for {h['id']}: {why}. A candidate needs captured terminal bytes on disk."
            if status == "lead" and h["status"] != "lead":
                # launch #19 set H1 to lead with notes "11 probes (exceeds floor of 8)" and no capture: a probe COUNT
                # is not a mechanism. A lead is a raw file whose response shows the mechanism (2xx/3xx or a byte).
                ev = evidence or ""
                ok, why = check_evidence(ev) if ev else (False, "no evidence= given")
                if ok:
                    ok, why = _mechanism_shape(ev)
                # D46 (drive cycle 18, 2026-10-26 05:08Z): H24 ("second handler skipped the check", kill byte
                # '"fallback_mode": true') was set to LEAD on a POST to the public event-logging batch route that
                # answered 200 {"accepted_count":0,"rejected_count":0}: a 2xx that is not a shell is any public sink.
                # The capture must carry the bytes the hypothesis itself said would confirm it.
                kb = str(kill_byte or h.get("kill_byte") or "").strip()
                if ok and kb:
                    ok, why = check_evidence(ev, must_contain=kb)
                    if not ok:
                        why = (f"the capture does not carry this hypothesis's kill byte {kb!r} ({why}); a 2xx on some "
                               "route is not the mechanism H predicted. Set kill_byte= to the bytes that confirm it "
                               "and cite the capture that holds them")
                if ok:
                    # D96 (cycle 25, 11:18Z): H47 "POST .../batch with X-Partner-Token header" went LEAD on a capture
                    # whose request carried no such header; its 200 {"accepted_count":0} is what the public route
                    # answers anyone. The capture must SEND the input the violation names, or it is the baseline.
                    names = violation_inputs(h.get("violation"))
                    present, missing = capture_sends(ev, names)
                    if names and not present:
                        ok = False
                        why = (f"the cited capture never sends the violation's own input ({', '.join(missing)}): its "
                               "request is the plain one, so the response is the route's BASELINE, not the mechanism. "
                               "Fire the request WITH that input (http_request headers=/body=), cite that capture, and "
                               "cite the plain request as the control it must differ from")
                if not ok:
                    return (f"refused LEAD for {h['id']}: {why}. A lead needs evidence=<raw capture whose response "
                            "shows the mechanism>; the probe count alone proves nothing (status stays "
                            f"{h['status']}).")
            h["status"] = status
        for k, v in (("notes", notes), ("kill_byte", kill_byte), ("prediction", prediction)):
            if v:
                h[k] = (h[k] + " | " + v).strip(" |") if k == "notes" else v
        if evidence and evidence not in h["evidence"]:
            h["evidence"].append(evidence)
        # burst is set only by the race tool (mark_burst): a model saying it burst is not a burst
        save(program, d)
        return f"{h['id']} -> {h['status']} ({h['probes']} probes)"
    rows = sorted(H, key=lambda h: (STATUSES.index(h["status"]) if h["status"] in STATUSES else 9,
                                    -CROWNS.get(h.get("crown") or "", 0)))
    if not rows:
        return "no hypotheses yet: add 3+ crown-aimed ones (action=add)"
    return "\n".join(f"{h['id']} [{h['status']}] {h['title']}  crown={h.get('crown') or '-'}  probes={h['probes']}"
                     f"{' burst' if h.get('burst') else ''}"
                     # spelled out, not "WALLED 14/20": asked what counts toward the floor, the live lead read
                     # that as "the floor is 14, and 20 exceeds it" and said the hypothesis was past the floor
                     # when 6 of its probes counted against a floor of 8 (QA run 2, 2026-10-25)
                     + (f"  [only {counted_probes(h, program)} of {h['probes']} probes count toward the floor of {FLOOR}; "
                        f"{h['probes'] - counted_probes(h, program)} hit a route that never answered: "
                        + ", ".join(r for r, _, _ in walled_routes(h)) + "]" if walled_routes(h) else "")
                     + (f"  boundary={h['boundary'][:40]}" if h.get('boundary') else "")
                     + (f"  ev={h['evidence'][-1]}" if h['evidence'] else "")
                     for h in rows[:25])


@_serialized
def log_probe(program, hyp_id, artifact):
    """http_request(hypothesis=H#) calls this: probes are counted against the hypothesis they test.

    AN UNTAGGED PROBE IS STILL A PROBE. `hypothesis` is optional on http_request, and this used to
    return early without a hyp_id, so an untagged probe reached the wire and landed in NO hypothesis
    and NO budget - _econ_budget returns early on the same condition, so neither the probe count nor
    the budget refusal ever saw it. A probe could therefore exist on disk and in no accounting at all,
    which is a hole straight through the empirical floor: the floor reads counted_probes(h), and an
    agent that omits the tag is invisible to it. Found 2026-11-03 on program-63, by the chat auditing
    its own control probe (capture 210947717597-get.json carried "hyp": null and appeared in no
    hypothesis's evidence).

    Untagged probes are now counted at PROGRAM level instead of being dropped. Deliberately NOT a
    refusal: recon, policy reads and dedup checks legitimately carry no hypothesis, and hard-failing
    them mid-hunt would break more than it fixes. untagged_probes() surfaces the number so the
    orchestrator and the floor can see what was spent off-ledger."""
    if not program:
        return
    if not hyp_id:
        d = load(program)
        d["untagged_probes"] = int(d.get("untagged_probes") or 0) + 1
        if artifact:
            ua = d.setdefault("untagged_artifacts", [])
            if len(ua) < 40:
                ua.append(artifact)
        save(program, d)
        return
    d = load(program)
    h = _find_hyp(d["hypotheses"], hyp_id)
    if not h:
        return
    h["probes"] += 1
    if h["status"] == "open":
        h["status"] = "probing"
    if artifact and len(h["evidence"]) < 40:
        h["evidence"].append(artifact)
    route, shape = _route_shape(artifact) if artifact else (None, None)
    if route and shape:  # per-route answer shapes: what walled_routes() reads
        routes = h.setdefault("routes", {})
        if route in routes or len(routes) < 40:
            shapes = routes.setdefault(route, {})
            if shape in shapes or len(shapes) < 30:
                shapes[shape] = shapes.get(shape, 0) + 1
    save(program, d)
    _econ("probe", program=program, hyp_id=hyp_id, probes=h["probes"])  # ECON: prober lineage + lane bond


@_serialized
def mark_burst(program, hyp_id, n):
    """race calls this: a hypothesis that got a concurrent burst (with its serial control) is floor-eligible."""
    if not program or not hyp_id:
        return
    d = load(program)
    h = _find_hyp(d["hypotheses"], hyp_id)
    if not h:
        return
    h["bursts"] = h.get("bursts", 0) + 1
    h["burst"] = True
    h["probes"] += max(0, int(n) - 1)  # log_probe already counted one
    save(program, d)
    _econ("burst", program=program, hyp_id=hyp_id, n=int(n), probes=h["probes"])  # ECON: debit burst, refund bond at floor


def _econ(kind, **kw):
    """ECON: one economy hook call. Fires only for a ledger on the real workspace path (a test that redirects
    path() is never booked) and can never raise into the hunt."""
    try:
        if not path(kw.get("program") or "").startswith(os.path.join(WS, "targets") + os.sep):
            return None
        import gnoc_economy
        return gnoc_economy.on_event(kind, **kw)
    except Exception:
        return None


def floor_status(program, hyp_id, counted=False):
    """(probes, bursts) the LEDGER counted for a hypothesis; (0, 0) when unknown. counted=True subtracts the
    probes spent on walled routes (walled_routes), which is what a floor verdict must read."""
    if not program or not hyp_id:
        return 0, 0
    h = _find_hyp(load(program).get("hypotheses", []), hyp_id)
    if not h:
        return 0, 0
    return (counted_probes(h, program) if counted else h.get("probes", 0)), h.get("bursts", 0)


# ---------------------------------------------------------------- capability graph and chains

@_serialized
def edge(program, action="add", frm=None, to=None, via=None, status=None, evidence=None,
         must_contain=None, requires=None, id=None, control=None, control_na=None):
    d = load(program)
    E = d["edges"]
    if action == "list":
        if not E:
            return "no edges yet"
        return "\n".join(f"{e['id']} {e['frm']} -> {e['to']} [{e['status']}] via {e['via']}"
                         + (f"  ev={e['evidence']}" if e.get("evidence") else "") for e in E[-40:])
    if action == "update":
        e = _find(E, id)
        if not e:
            have = ", ".join(list(dict.fromkeys(x["id"] for x in E))[-12:]) or "none"
            return (f"no edge {id}; the ledger has: {have}. Update one of those, or add the hop with action=add "
                    "(frm, to, via, status, evidence).")
        frm, to, via = e["frm"], e["to"], via or e["via"]
        evidence, must_contain = evidence or e.get("evidence"), must_contain or e.get("must_contain")
        requires = requires if requires is not None else e.get("requires")
        status = status or e["status"]
        control = control or e.get("control")
        control_na = control_na or e.get("control_na")
        E.remove(e)
        prev_rec = e   # the proof budget below counts attempts against the record being replaced
    else:
        prev_rec = None
    if not (frm and to and via):
        return "refused: an edge needs frm (capability you hold), to (capability you gain) and via (the primitive)"
    status = (status or "hypothesized").lower()
    if status not in CONF:
        return f"status must be one of {', '.join(CONF)}"
    # DEAD GROUND (2026-10-23, fix 38): launch #18 re-recorded H2-edge-1 as a lead with a fresh 403 one turn after
    # H2 was marked exhausted. An edge whose hypothesis is dead or exhausted is never written again.
    hyp = _edge_hyp({"id": id or "", "via": via or ""})
    if hyp:
        h = _find(d.get("hypotheses") or [], hyp)
        if h and (h.get("status") == "dead" or h.get("escalation") == "exhausted"):
            return (f"refused: {hyp} is {'dead' if h.get('status') == 'dead' else 'escalation-exhausted'}; its edges "
                    "are closed ground. Open a different hypothesis (hunt_hypothesis action=add) on a different "
                    "surface, or pick the next open one from hunt_brief.")
    if evidence and control and os.path.realpath(evidence if os.path.isabs(evidence) else os.path.join(WS, evidence)) \
            == os.path.realpath(control if os.path.isabs(control) else os.path.join(WS, control)):
        return ("refused: evidence and control are the same capture; the control is the DIFFERENT request that was "
                "refused (one variable changed), captured to its own raw file.")
    note = ""
    prev = prev_rec if prev_rec is not None else \
        (next((x for x in E if str(x.get("id", "")).upper() == str(id or "").strip().upper()), None) if id else None)
    refusals = 0
    if status == "proven":
        ok, why = check_evidence(evidence, must_contain)
        if ok:
            ok, why = _terminal_shape(evidence, must_contain)
        if ok:
            ok, why = _proof_shape(evidence, control, must_contain, to, program, id)
        if not ok:
            # PROOF BUDGET (drive cycle 2, 2026-10-25): the same capture was offered as proof of E1-oauth-vault-state
            # five times in two cycles with a different must_contain each time. Three refusals on one capture close
            # the edge to further proof until a NEW capture is cited.
            same = prev is not None and (prev.get("evidence") or "") == (evidence or "")
            refusals = int(prev.get("proof_refusals") or 0) + 1 if same else 1
            if same and refusals > PROOF_ATTEMPTS:
                return (f"refused: {prev['id']} has been offered as proven {refusals} times with the same capture "
                        f"{(evidence or '')[-48:]} and its bytes do not show {node(to)}: {why}. No more proof attempts "
                        "on this edge with that file. Fire the request that would carry the terminal bytes, then cite "
                        "THAT raw file, or leave the edge a lead and work a different hop.")
            status, note = "lead", f"  (stored as LEAD, not proven: {why}; proof attempt {refusals} of {PROOF_ATTEMPTS} on this capture)"
            # drive cycle 4 (2026-10-25): a proven offer carrying a 404 capture and must_contain='200_with_session_cookies'
            # landed as LEAD because the downgrade skipped the lead checks; the "lead" then anchored PHASE CHAIN for
            # three cycles. A refusal-shaped capture holds no lead: it is the negative control, so the edge stays
            # hypothesized.
            mok, mwhy = _mechanism_shape(evidence)
            if not mok:
                status, note = "hypothesized", f"  (stored as HYPOTHESIZED, not lead: {mwhy}; proof attempt {refusals} of {PROOF_ATTEMPTS} on this capture)"
    if status == "lead":
        # 23 of 29 program-101 edges were "lead" with no capture (2026-10-23): a lead is a MECHANISM CONFIRMED BY BYTES,
        # a claim without a raw file is a hypothesis.
        # drive cycle 6 (2026-10-26 00:34Z): a 404 capture plus must_contain='"error_code":"account_session_invalid"'
        # (absent from the body, and an error marker) became "unauth -> ato [lead]" because a named must_contain
        # skipped every check. The claimed bytes must be IN the capture, and an error string is the control holding.
        ok, why = check_evidence(evidence, must_contain or None)
        if ok and must_contain and _ERROR_MARKER.search(must_contain) and len(must_contain) < 60:
            ok, why = False, (f"must_contain={must_contain!r} is an error marker: an error string is the control "
                              "holding, not a mechanism; name the private or state-changing bytes")
        if ok and must_contain and (len(must_contain.strip()) < 6 or re.search(r"(?i)<!doctype|<html|<head|<body|<script|<div", must_contain)):
            ok, why = False, (f"must_contain={must_contain[:40]!r} is generic markup: it is in every page this host "
                              "serves, so it shows no mechanism")
        if ok and not must_contain:
            ok, why = _mechanism_shape(evidence)
        if ok:
            ok, why = _sends_edge_input(program, id, evidence)   # D98b
        if ok and not must_contain and node(to) in CROWNS:
            # launch #20: "100-bucket-session-collision -> ato [lead]" on a 200 of the seller home page. A lead that
            # claims a CROWN capability names the byte in the capture that shows it.
            ok, why = False, (f"the edge claims {node(to)}; name must_contain=<the byte in the capture that shows "
                              "that capability> (a 200 of a public page shows none)")
        if not ok:
            status, note = "hypothesized", f"  (stored as HYPOTHESIZED, not lead: {why}; a lead needs the raw capture that shows the mechanism)"
    req = [r.strip() for r in (requires if isinstance(requires, list) else str(requires or "").split(",")) if r.strip()]
    if control:
        cok, cwhy = check_evidence(control)
        if not cok:
            note += f"  (control not recorded: {cwhy})"
            control = ""
    # EDGE DEDUP (2026-10-23): the lead re-added "H9-edge-1 unauth -> ato via THE PAIRED WRITE / admin twin" more than
    # 60 times in three hours (160 edges for 9 hypotheses on program-101). Same id, or same (frm, to) with the same via, is
    # the same edge: it is replaced in place (a stronger status wins), the chain search never sees twins.
    twin = None
    if action != "update":
        want_id = (id or "").strip().upper()
        if want_id:  # an explicit id wins over a look-alike with another id (case-insensitive, as _find)
            twin = next((prev for prev in E if str(prev.get("id", "")).upper() == want_id), None)
        if twin is None:
            twin = next((prev for prev in E if prev["frm"] == node(frm) and prev["to"] == node(to)
                         and _via_same(prev.get("via"), via)), None)
    if twin is not None:
        rank = {"hypothesized": 0, "lead": 1, "proven": 2}
        if rank.get(status, 0) < rank.get(twin["status"], 0):
            return (f"edge {twin['id']} already exists as {twin['frm']} -> {twin['to']} [{twin['status']}] via "
                    f"{twin['via'][:80]}; your {status} version adds nothing. Prove it (hunt_edge action=update "
                    f"id={twin['id']} status=proven evidence=<raw> control=<raw>) or move to a different hop.")
        E.remove(twin)
        id, note = twin["id"], note + f"  (replaced the existing {twin['id']}, not a new edge)"
        evidence = evidence or twin.get("evidence")
        control = control or twin.get("control")
        control_na = control_na or twin.get("control_na")
    e = {"id": id or _next_id(E, "E"), "frm": node(frm), "to": node(to), "via": via, "status": status,
         "evidence": evidence or "", "must_contain": must_contain or "", "requires": req, "ts": _now(),
         "control": control or "", "control_na": (control_na or "").strip()}
    if refusals:
        e["proof_refusals"] = refusals
    E.append(e)
    save(program, d)
    if status == "proven":
        _econ("edge-proven", program=program, edge=e["id"])  # ECON: lineage only, never a mint
    if status == "proven" and not e["control"] and not e["control_na"]:
        note += "  (PROVEN but no negative control: SHIP needs control=<raw file of the refused request> on every edge)"
    pg_ok, pg = DOC.premise_gate(e["frm"], e["requires"], e["to"])
    if not pg_ok:
        note += f"  (WARNING {pg})"
    return f"{e['id']}: {e['frm']} -> {e['to']} [{status}]{note}"


def _rejudge_proven(e, program=None):
    """(new_status, why) for a stored PROVEN edge under today's gates, or (None, "") when it still holds. Mirrors
    edge(): a proof that fails check_evidence is HYPOTHESIZED; one that fails _terminal_shape or _proof_shape drops
    to LEAD and then meets the same lead gate edge() applies (raw capture, mechanism shape, a crown names its byte),
    so a healed edge is never one that the next hunt_edge update would demote again."""
    ev, mc, to, ctl = e.get("evidence") or "", e.get("must_contain") or "", e.get("to"), e.get("control") or ""
    ok, why = check_evidence(ev, mc)
    if not ok:
        return "hypothesized", why
    for gate in (lambda: _terminal_shape(ev, mc), lambda: _proof_shape(ev, ctl, mc, to, program, e.get("id"))):
        ok, why = gate()
        if not ok:
            break
    if ok:
        return None, ""
    lok, lwhy = check_evidence(ev, None)
    if lok and not mc:
        lok, lwhy = _mechanism_shape(ev)
    if lok and not mc and node(to) in CROWNS:
        lok, lwhy = False, f"a lead on the crown {node(to)} names must_contain=<the byte that shows it>"
    if lok:
        lok, lwhy = _sends_edge_input(program, e.get("id"), ev)   # D98b
    if not lok:
        return "hypothesized", f"{why} Lead gate: {lwhy}."
    return "lead", why


def heal_proofs(program):
    """Re-judge every PROVEN edge of a ledger against today's proof gates and demote the ones that fail, with the
    reason and a timestamp appended to the edge's note. Explicit only: it reads capture files, so it is never run
    from load()/_heal(). Returns [(edge_id, new_status, why)]. A ledger with nothing to demote is not rewritten."""
    if not os.path.isfile(path(program)):
        return []
    if not any(_rejudge_proven(e, program)[0] for e in load(program)["edges"] if e.get("status") == "proven"):
        return []

    def fn(d):
        out = []
        for e in d["edges"]:
            if e.get("status") != "proven":
                continue
            new, why = _rejudge_proven(e, program)
            if not new:
                continue
            e["status"] = new
            e["note"] = (e.get("note") or "") + f" [demoted from proven: {why} {_now()}]"
            out.append((e["id"], new, why))
        return out
    return modify(program, fn)


def ship_ready(chain):
    """(ok, missing): every edge proven AND every edge carries a refused negative control (or a stated reason)."""
    missing = []
    for e in chain:
        if e["status"] != "proven":
            missing.append(f"{e['id']} is {e['status']}")
        elif not e.get("control") and not e.get("control_na"):
            missing.append(f"{e['id']} has no negative control")
    return not missing, missing


def frontier(chain):
    """The furthest capability a chain actually holds (last proven or lead edge's target), for next-hop advice."""
    held = [e for e in chain if e["status"] in ("proven", "lead")]
    return held[-1]["to"] if held else chain[0]["frm"]


def _paths(E, max_len=5):
    out_edges = {}
    for e in E:
        out_edges.setdefault(e["frm"], []).append(e)
    found = []

    def walk(n, trail, seen):
        if len(trail) > max_len:
            return
        if trail and n in CROWNS:
            found.append(list(trail))
        for e in out_edges.get(n, []):
            if e["to"] not in seen:
                walk(e["to"], trail + [e], seen | {e["to"]})
    for s in START:
        walk(s, [], {s})
    return found


def score(chain):
    s = CROWNS[chain[-1]["to"]]
    for e in chain:
        s *= CONF.get(e["status"], 0.3)
    if any(INTERACTION.search(" ".join(e.get("requires") or []) + " " + e["via"]) for e in chain):
        s *= 0.7
    if chain[0]["frm"] == "own-account":
        s *= 0.85
    return round(s * (1 - 0.04 * (len(chain) - 1)), 2)


def _edge_hyp(e):
    """The hypothesis an edge belongs to (H# in its id or via), or None."""
    m = re.search(r"\b(H\d+)\b", f"{e.get('id', '')} {e.get('via', '')}", re.I)
    return m.group(1).upper() if m else None


def live_edges(d):
    """Edges whose hypothesis is not dead or escalation-exhausted. The chain search kept picking "unauth -> ato via
    H2 ..." as the best chain after H2 was exhausted and dead-walled, so every CHAIN turn re-proved the same 403
    (launches #15-#17 on program-101, 2026-10-23)."""
    gone = {h["id"].upper() for h in d.get("hypotheses") or []
            if h.get("status") in ("dead", "unfired") or h.get("escalation") == "exhausted"
            # a hypothesis whose probes all hit a wall (2026-10-25): its edges sit on a route that never answered,
            # and PHASE CHAIN kept sending the lead back to prove "H5-edge ... via admin twin" on program-101
            or (walled_routes(h) and counted_probes(h) < FLOOR)}
    return [e for e in d.get("edges") or [] if (_edge_hyp(e) or "") not in gone]


def chains(program, top=5):
    """Ranked chains (list of (score, [edges])) over the edges of live hypotheses."""
    E = live_edges(load(program))
    ranked = sorted(((score(c), c) for c in _paths(E)), key=lambda x: -x[0])
    seen, out = set(), []
    for sc, c in ranked:
        key = tuple(e["id"] for e in c)
        if key not in seen:
            seen.add(key)
            out.append((sc, c))
    return out[:top]


def weakest(chain):
    order = {"hypothesized": 0, "lead": 1, "proven": 2}
    return min(chain, key=lambda e: order.get(e["status"], 0))


def chains_text(program, top=5):
    cs = chains(program, top)
    E = load(program)["edges"]
    if not cs:
        reached = sorted({e["to"] for e in E})
        return ("no chain reaches a crown yet." + (f" Capabilities you hold or hypothesize: {', '.join(reached)}. "
                "Add edges from them toward a crown (ato, rce, cross-tenant, money, mass-pii ...)." if reached else
                " Add capability edges (hunt_edge) starting from unauth or own-account."))
    lines = []
    for i, (sc, c) in enumerate(cs, 1):
        done = all(e["status"] == "proven" for e in c)
        ready, missing = ship_ready(c)
        path_s = " -> ".join([c[0]["frm"]] + [f"{e['to']}" for e in c])
        w = weakest(c)
        tag = "SHIP-READY (every edge proven with a negative control)" if ready else \
            ("all edges proven; " + "; ".join(missing) if done else "")
        lines.append(f"#{i} score {sc}  {c[-1]['to'].upper()}  {tag}\n"
                     f"   {path_s}\n" + "".join(f"   {e['id']} [{e['status']}{'+ctl' if e.get('control') else ''}] "
                                                f"{e['frm']} -> {e['to']} via {e['via']}\n" for e in c)
                     + ("" if done else f"   next: prove {w['id']} ({w['frm']} -> {w['to']})"))
        if not done:
            ftag, hops = DOC.next_hops(frontier(c), 3)
            if hops and ftag not in CROWNS:
                lines.append(f"   from {ftag} the chain table also offers: "
                             + "; ".join(f"{to} via {via}" for via, to, _, _ in hops))
    held = sorted({e["to"] for e in E if e["status"] in ("proven", "lead") and e["to"] not in CROWNS})
    extra = []
    for cap in held[:6]:
        ftag, hops = DOC.next_hops(cap, 2)
        if hops:
            extra.append(f"  {cap} -> " + "; ".join(f"{to} via {via}" for via, to, _, _ in hops))
    if extra:
        lines.append("HELD CAPABILITIES AND WHAT THEY UNLOCK (add each as a hypothesized edge, then prove it):\n"
                     + "\n".join(extra))
    return "\n".join(lines)


# ---------------------------------------------------------------- hypothesis tournament (scoring is code)

_CONCRETE = re.compile(r"(/[\w.{}:-]+|\b(GET|POST|PUT|PATCH|DELETE)\b|\b[a-z_]+=|\bheader\b|\bparam)", re.I)
_UNAUTH = re.compile(r"\b(unauth|anonymous|no (session|token|cookie|auth)|without (a )?(session|token|login|auth)|"
                     r"logged[- ]out|zero[- ]credential)", re.I)
_GENERIC = re.compile(r"\b(test for|check if|look for|might be vulnerable|common vulnerabilit|owasp|scan)\b", re.I)


def _sim(a, b):
    wa = set(re.findall(r"[a-z0-9/._-]{3,}", (a or "").lower()))
    wb = set(re.findall(r"[a-z0-9/._-]{3,}", (b or "").lower()))
    return len(wa & wb) / max(1, len(wa | wb))


def score_hypothesis(h, known=(), dead="", bounds=(), program=None):
    """Code-side judge for a proposed hypothesis. Returns (score, reasons); score < 0 means drop it."""
    why = []
    crown = node(h.get("crown"))
    s = float(CROWNS.get(crown, 0))
    if not s:
        return -1, ["not aimed at a crown"]
    text = " ".join(str(h.get(k, "")) for k in ("title", "assumption", "violation", "prediction"))
    if not all(str(h.get(k, "")).strip() for k in ("title", "assumption", "violation", "prediction")):
        return -1, ["missing assumption / violation / prediction"]
    req = h.get("requires") or []
    req = req if isinstance(req, list) else [x.strip() for x in str(req).split(",") if x.strip()]
    ok, pg = DOC.premise_gate(node(h.get("start")) or "unauth", req, crown)
    if not ok:
        return -1, [f"fails the premise gate: {pg[:90]}"]
    kills = DOC.kill_match(text)
    if kills:
        s -= 3
        why.append(f"pre-rejected shape ({kills[0][0]}) -3")
    b = str(h.get("boundary", "")).strip()
    if b and bounds and any(_sim(b, x) >= 0.3 or b.split(":")[0].strip().lower() == x.split(":")[0].strip().lower()
                            for x in bounds):
        s += 2
        why.append("cites a model boundary +2")
    elif bounds:
        s -= 1
        why.append("cites no model boundary -1")
    if _UNAUTH.search(text) or node(h.get("start")) == "unauth":
        s += 3
        why.append("unauth +3")
    if not concrete_input(h.get("violation", "")):
        # a hypothesis that does not name the crafted input (method, path, field, header) cannot be probed
        return -1, ["violation names no concrete input (method, path, field)"]
    weak = weak_kill_byte(h.get("kill_byte", ""), h)   # D76: H36 came in with kill_byte 'api' from a tournament
    if weak:
        return -1, [weak[:120]]
    if program:
        unknown = unknown_route_refusal(program, h.get("violation", ""))   # D79: H40-H43 were invented routes
        if unknown:
            return -1, [unknown[:160]]
    if prediction_is_refusal(h.get("prediction", ""), h.get("kill_byte", ""))[0]:
        return -1, ["predicts the refusal, not the capability"]
    if prediction_is_self_read(h.get("prediction", ""), h.get("kill_byte", ""), crown)[0]:
        return -1, ["confirms on the prober's own data, not a crossing"]
    s += 2
    why.append("concrete input +2")
    if str(h.get("kill_byte", "")).strip():
        s += 1
        why.append("kill byte +1")
    if re.search(r"\b[1-5]\d\d\b|bytes|field|key|body", str(h.get("prediction", "")), re.I):
        s += 1
        why.append("checkable prediction +1")
    if _GENERIC.search(text):
        s -= 3
        why.append("generic -3")
    near = max([_sim(h.get("title"), k) for k in known] or [0])
    if near >= 0.5:
        return -1, [f"duplicate of an existing hypothesis ({near:.2f})"]
    for line in (dead or "").splitlines():
        if line.strip() and _sim(text, line) >= 0.35:
            return -1, ["matches a do-not-rehunt line"]
    return round(s, 1), why


def tournament(program, proposals, n=3):
    """proposals: [(source, hypothesis_dict)]. Scores in code, dedups, adds the top n to the ledger with a
    hypothesized edge start -> crown. Returns a table of every proposal and its fate."""
    d = load(program)
    known = [h["title"] for h in d["hypotheses"]]
    dead = _read(os.path.join(WS, ".claude/state/do-not-rehunt", program + ".txt"))
    bounds = d["model"].get("boundaries") or []
    scored, rows = [], []
    for src, h in proposals:
        sc, why = score_hypothesis(h, known + [x["title"] for _, x, _ in scored], dead, bounds, program=program)
        rows.append((sc, src, h.get("title", "?"), ", ".join(why)))
        if sc >= 0:
            scored.append((sc, h, src))
    scored.sort(key=lambda x: -x[0])
    added = []
    for sc, h, src in scored[:n]:
        r = hypothesis(program, "add", title=str(h["title"])[:200], crown=h.get("crown"),
                       assumption=str(h["assumption"]), violation=str(h["violation"]),
                       prediction=str(h["prediction"]), kill_byte=str(h.get("kill_byte", "")),
                       notes=f"tournament {sc} from {src}", boundary=str(h.get("boundary", "")),
                       requires=h.get("requires"))
        hid = r.split(":")[0].replace("added ", "") if r.startswith("added") else None
        if hid:
            start = "unauth" if (_UNAUTH.search(str(h)) or node(h.get("start")) == "unauth") else "own-account"
            edge(program, "add", start, h.get("crown"), f"{hid}: {str(h['title'])[:80]}", "hypothesized")
            added.append(hid)
    table = "\n".join(f"  {'KEEP' if sc >= 0 and t in [str(h['title']) for _, h, _ in scored[:n]] else 'drop'} "
                      f"{sc:>5}  {src:<7} {t[:90]}  ({w})" for sc, src, t, w in sorted(rows, key=lambda r: -r[0]))
    return added, f"{len(proposals)} proposals, added {', '.join(added) or 'none'}:\n{table}"


# ---------------------------------------------------------------- program intel pack



@_serialized
def import_held(program):
    """Seed the graph once with what the workspace already holds for this program: queued leads and HELD
    drafts become 'lead' edges from unauth, so the chain search can compose them with new primitives."""
    d = load(program)
    if d.get("imported"):
        return 0
    n = 0
    q = os.path.join(WS, ".claude/state/hunt-loop/leads-queue.jsonl")
    for ln in _read(q).splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") != program or not r.get("capability"):
            continue
        d["edges"].append({"id": _next_id(d["edges"], "E"), "frm": "unauth", "to": node(r["capability"][:60]),
                           "via": (r.get("lead") or "")[:120], "status": "lead", "evidence": r.get("artifact") or "",
                           "must_contain": "", "requires": [], "ts": _now(), "src": "leads-queue"})
        n += 1
    dd = os.path.join(WS, "reports/drafts", program)
    for slug in sorted(os.listdir(dd)) if os.path.isdir(dd) else []:
        held = _read(os.path.join(dd, slug, "HELD-REASON.md"), 600)
        if held:
            d["edges"].append({"id": _next_id(d["edges"], "E"), "frm": "unauth", "to": node(slug[:60]),
                               "via": f"held draft reports/drafts/{program}/{slug}", "status": "lead",
                               "evidence": f"reports/drafts/{program}/{slug}/report.md", "must_contain": "",
                               "requires": [], "ts": _now(), "src": "held-draft"})
            n += 1
    d["imported"] = True
    save(program, d)
    return n


def _seen_hosts(program, limit=12):
    """In-scope hosts the hunt index has ACTUALLY captured, most-captured first.

    SCOPE.txt lists apex domains ALPHABETICALLY, which is not a ranking and is read as one: on program-72 the
    agent took `app.example.com` (Brazil) and fired Romanian `/ro/` paths at it for ~40 probes, purely
    because `.app.example.com` sorts above `.ro`. Meanwhile the index already held the real API hosts
    (api-loyalty..., api-freetoplay..., api.web.production.betler...), which is where the business logic
    lives and which no apex row names. 97% of our shipped findings opened from a seed like this, so the
    brief hands them over instead of making the model guess from an alphabetical list.
    Scope-gated: a host is only listed if lib_scope still allows it for this programme.
    """
    try:
        import sqlite3
        from bbtools import lib_scope
    except Exception:  # noqa: BLE001
        return []
    db = os.path.join(WS, ".hunt-index", "hunts.db")
    if not os.path.isfile(db):
        return []
    # Query by THIS programme's own domains. A global "top 400 hosts" ordering was the first attempt and
    # returned nothing: 7,737 hosts in the index have as many captures as program-72's busiest, so the
    # programme's hosts sat far outside any global head. Scope apexes are the only sane filter.
    apexes = set()
    for ln in _read(os.path.join(WS, "targets", program, "SCOPE.txt")).splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        for tok in re.findall(r"[A-Za-z0-9*][A-Za-z0-9.*-]*\.[A-Za-z]{2,}", ln):
            tok = tok.lstrip("*.").lower().rstrip("/")
            if tok.count(".") >= 1 and " " not in tok:
                apexes.add(tok)
    if not apexes:
        return []
    rows = []
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        where = " OR ".join("host LIKE ?" for _ in apexes)
        cur = con.execute("SELECT host, COUNT(*) n FROM hosts WHERE host IS NOT NULL AND (" + where + ") "
                          "GROUP BY host ORDER BY n DESC LIMIT 60",
                          tuple("%" + a for a in sorted(apexes)))
        cand = cur.fetchall()
        con.close()
    except Exception:  # noqa: BLE001
        return []
    for host, n in cand:
        if not host or len(host) < 4:
            continue
        try:
            ok, _ = lib_scope.program_allows("https://" + host + "/", program, WS)
        except Exception:  # noqa: BLE001
            continue
        if ok:
            rows.append((host, n))
        if len(rows) >= limit:
            break
    return rows


def _unprobed_routes(program, limit=18):
    """Known routes this programme has NEVER fired a probe at, money-looking ones first.

    The agent knows its route list and its hypotheses, but nothing ever subtracted one from the other.
    Watching a live hunt on 2026-10-28: with 73 known routes it burned every hypothesis budget on five
    dead ones and then spent whole turns trying to REOPEN them ("refused: reopening H12 needs notes
    naming a NEW route"), because inventing a fresh hypothesis is the hardest thing a small model does
    and nothing offered it the easy move. A list of untouched routes turns "invent a seam" into "pick
    one", which is the shape these models are actually good at.
    """
    try:
        import gnoc_agent
        known = gnoc_agent._load_known_paths(program)
    except Exception:  # noqa: BLE001
        return []
    if not known:
        return []
    probed = set()
    try:
        for h in (load(program).get("hypotheses") or []):
            for route in (h.get("routes") or {}):
                r = str(route)
                probed.add(r)
                if "/" in r:                      # routes are stored host/path or bare path
                    probed.add("/" + r.split("/", 1)[1])
    except Exception:  # noqa: BLE001
        pass
    MONEY = ("purchase", "shop", "wallet", "balance", "bonus", "coupon", "currency", "inventory",
             "payment", "pay", "withdraw", "deposit", "award", "redeem", "voucher", "promo", "credit",
             "cashout", "transfer", "order", "price", "spin", "claim")
    left = [r for r in known if r not in probed and r.rstrip("/") not in probed]
    left.sort(key=lambda r: (0 if any(m in r.lower() for m in MONEY) else 1, len(r)))
    return left[:limit]


def brief(program, cap=7000):
    """One compact pack of what is already known, so the model starts from the workspace, not from zero."""
    t = os.path.join(WS, "targets", program)
    parts = []
    scope = [l for l in _read(os.path.join(t, "SCOPE.txt")).splitlines() if l.strip() and not l.startswith("#")]
    parts.append("SCOPE (first 25, ALPHABETICAL - this is not a ranking): " + ", ".join(scope[:25]))
    # The alphabetical head is URL rows only (rows start with the kind word, so every WILDCARD row sorts after
    # every URL row): on program-50 the lead read "SCOPE.txt has 50 rows" while 184 well-formed wildcard zones
    # sat below the cut (measured 2026-11-10 01:03Z). Name the SIZE of both halves and the wildcard apexes.
    try:
        from bbtools import lib_scope
        ex, wz = lib_scope.exact_hosts(program, WS), lib_scope.wildcard_apexes(program, WS)
        if ex or wz:
            parts.append(f"SCOPE SIZE: {len(ex)} exact host row(s) + {len(wz)} wildcard zone(s)"
                         + (" - any host under these apexes is in scope: " + ", ".join(wz[:30])
                            + (f" (+{len(wz) - 30} more)" if len(wz) > 30 else "") if wz else ""))
    except Exception:  # noqa: BLE001 - the brief still stands without the size line
        pass
    seen = _seen_hosts(program)
    if seen:
        parts.append("LIVE HOSTS we already have captures for (in-scope, most-captured first - prefer these "
                     "over an apex guess; the API subdomains are where the logic is):\n  "
                     + ", ".join(f"{h} ({n})" for h, n in seen))
    try:
        hw = host_walls(program)
    except Exception:  # noqa: BLE001
        hw = {}
    if hw:
        parts.append("HOST WALLS (every distinct path tried on these hosts answered the SAME thing - that is "
                     "ABSENT SURFACE, not an auth wall; change the HOST, not the method or the path):\n  "
                     + "\n  ".join(f"{h}: {sh.replace(':', ' len=')} on {n} distinct paths"
                                    for h, (sh, n) in sorted(hw.items(), key=lambda kv: -kv[1][1])[:6]))
    unprobed = _unprobed_routes(program)
    if unprobed:
        parts.append("UNPROBED ROUTES (known to us, never fired, money-looking first). Opening a hypothesis "
                     "on one of these beats reopening a dead one:\n  " + "\n  ".join(unprobed))
    prog = _read(os.path.join(t, "PROGRAM.md"))
    excl = [l.strip() for l in prog.splitlines()
            if re.search(r"out of scope|not eligible|exclu|do not|prohibit|automat|rate limit", l, re.I)][:12]
    if excl:
        parts.append("POLICY LINES (exclusions, automation, rate):\n- " + "\n- ".join(x[:200] for x in excl))
    tm = _read(os.path.join(t, "TARGET-MODEL.md"))
    if tm:
        m = re.search(r"(?is)(#+[^\n]*catastroph[^\n]*\n.*?)(\n#+ |\Z)", tm)
        parts.append("TARGET-MODEL catastrophes:\n" + (m.group(1) if m else tm)[:1500])
    hand = [l.strip() for l in _read(os.path.join(WS, "HANDOFF-CURRENT.md")).splitlines() if program in l][:6]
    if hand:
        parts.append("HANDOFF lines:\n- " + "\n- ".join(h[:300] for h in hand))
    dnr = _read(os.path.join(WS, ".claude/state/do-not-rehunt", program + ".txt"), 1200)
    if dnr:
        parts.append("DO-NOT-REHUNT (already receipt-dead; find NEW ground):\n" + dnr)
    seeds = _read(os.path.join(t, "recon/oss-bot/SEEDS.md"), 1500)
    if seeds:
        parts.append("SCANNER SEEDS (leads only):\n" + seeds)
    dd = os.path.join(WS, "reports/drafts", program)
    if os.path.isdir(dd):
        rows = []
        for slug in sorted(os.listdir(dd)):
            held = _read(os.path.join(dd, slug, "HELD-REASON.md"), 300).replace("\n", " ")
            rows.append(f"{slug}" + (f" [HELD: {held[:160]}]" if held else ""))
        parts.append("EXISTING DRAFTS (do not re-find; chain FROM them):\n- " + "\n- ".join(rows[:15]))
    n = import_held(program)
    if n:
        parts.append(f"(imported {n} held leads/drafts into the capability graph as lead edges)")
    parts.append("TRUST MODEL:\n" + model(program, "show"))
    parts.append("HYPOTHESES:\n" + hypothesis(program, "list"))
    parts.append("CHAINS:\n" + chains_text(program, 3))
    out = "\n\n".join(parts)
    return out[:cap] + (f"\n[... brief cut at {cap} chars; read the files for more]" if len(out) > cap else "")


# ---------------------------------------------------------------- the phase director

def budget_left(program, h):
    """Probes the hypothesis may still spend (the economy's budget when it can be asked, else 20)."""
    try:
        import gnoc_economy
        b = int(gnoc_economy.budget(program, h["id"]))
    except Exception:  # noqa: BLE001
        b = 20
    return max(0, b - int(h.get("probes") or 0))


def probe_briefs(program, n=3):
    """Parallel worker briefs for the PROBE phase: the n most crown-worthy live hypotheses, one bot each. Every
    brief is self-contained (the worker sees nothing else) and ends in a fixed digest shape the lead can check."""
    H = load(program)["hypotheses"]
    live = sorted([h for h in H if h["status"] in ("open", "probing") and not violation_on_wall(program, h["violation"])
                   and budget_left(program, h) > 0],
                  key=lambda h: (-CROWNS.get(h.get("crown") or "", 0), counted_probes(h, program)))[:max(1, n)]
    # D81 (cycle 24, 10:14Z): H42 had its 20-probe budget spent and was still briefed to three bots in a row, each
    # refused at the budget gate on its first probe. A spent hypothesis is the lead's verdict, not a bot's job.
    # D76: cycle 24 bot 1 was briefed on H36, whose violation names api.program-0.example/v1/messages (a program wall);
    # it spent 13 of 20 steps on wall refusals and fired nothing. A wall is not a bot's job.
    out = []
    for h in live:
        tells = "\n".join(f"- {i}: {t}" for i, t in DOC.moves("BE", h["title"] + " " + h["violation"], 3, 260))
        out.append((h["id"], f"Program {program}. Test ONE hypothesis live, {h['id']}: {h['title']}\n"
                    f"ASSUMPTION: {h['assumption']}\nVIOLATION: {h['violation']}\nPREDICTION: {h['prediction']}\n"
                    f"KILL BYTE: {h.get('kill_byte') or '-'}\nTELLS TO WATCH:\n{tells}\n"
                    + (wall_text(h) + "\n" if walled_routes(h) else "") +
                    f"Do: dedup on the host first; probe_matrix(url=the route the VIOLATION names, hypothesis='{h['id']}'); then 6+ "
                    f"crafted http_request(hypothesis='{h['id']}') variants on every '!' row (schema fields, encodings, "
                    "the second handler, a sibling object, the enforcing twin) plus one negative control; race on any "
                    "single-use step if it is offered to you. Probe only in-scope hosts, as the saved identities when "
                    "`identities action=list` names any (NONE saved = send every request unauth, never pass "
                    "as_identity or identities), "
                    "never real users' data.\nAnswer with exactly: VERDICT: LEAD|CANDIDATE|NOTHING-YET, "
                    "PROBES: n, EVIDENCE: the raw capture paths, BYTES: the load-bearing response bytes quoted, "
                    "NEXT: the next probe."))
    return out


ESCALATE_TURNS = 3  # turns a lead may be escalated without proving an edge

def nudge(program, text):
    """One line the NEXT directive carries, then forgets (the hunt loop's stuck detector writes it)."""
    def _set(dd):
        dd["nudge"] = (text or "").strip()[:400]
    modify(program, _set)


def _capture_iso(path):
    """ISO time of a raw capture file (its mtime), or '' when it is missing. An edge's own ts is renewed on every
    rewrite, so it cannot say how old the EVIDENCE is; the file can."""
    try:
        p = path if os.path.isabs(path) else os.path.join(WS, path)
        return datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    except (OSError, TypeError, ValueError):
        return ""


def chain_has_substance(c):
    """A chain worth a CHAIN turn holds at least one lead or proven edge and is not fully proven. Drive cycle 6
    (2026-10-26 00:30Z): every edge on program-0 was hypothesized and PHASE CHAIN still picked the top-scored one
    (E1-oauth-vault-state, a walled route) and sent the lead back to it; a chain of hypothesized edges is a
    hypothesis, which PROBE and HYPOTHESIZE already own."""
    st = [e.get("status") for e in c]
    return any(s in ("lead", "proven") for s in st) and not all(s == "proven" for s in st)


def chain_waits(d, live):
    """True when an unprobed CROWN hypothesis is newer than every lead edge's capture: fresh ground is probed before
    the loop re-proves a stale chain. Drive cycle 2 (2026-10-25 23:44Z): /goal added H5-H7 (ato, 0 probes) and the
    loop still opened in PHASE CHAIN on E1-oauth-vault-state, whose capture was a day old, and spent five turns
    re-offering that capture as proof."""
    fresh = [h for h in live if int(h.get("probes") or 0) == 0 and node(h.get("crown") or "") in CROWNS]
    if not fresh:
        return False
    newest = max((_capture_iso(e.get("evidence") or "") for e in (d.get("edges") or [])
                  if e.get("status") == "lead" and _granted(_route_shape(e.get("evidence") or "")[1] or "")),
                 default="")
    return any((h.get("ts") or "")[:19] > newest for h in fresh)


def verdict_owed_set(program, live):
    """The live hypotheses that owe a verdict: probing past twice the floor (counted or spent), or ANY open/probing
    hypothesis whose probe budget is gone. D82 (cycle 24, 10:18Z): H40, H42 and H43 sat 'open' at 20 of 20 probes
    after a reopen, so PHASE PROBE picked them every turn and the budget gate refused every probe (11 refusals)."""
    out = []
    for h in live:
        spent = budget_left(program, h) <= 0
        over = counted_probes(h, program) >= VERDICT_AT or int(h.get("probes") or 0) >= VERDICT_AT
        if (h["status"] == "probing" and over) or (h["status"] in ("open", "probing") and spent):
            out.append(h)
    return out


def _api_shaped_path(k):
    return not (k.startswith("/docs/") or k.startswith("/blog/") or k.endswith((".html", ".md")))


def mined_hosts(program):
    """Hosts js_mine has already walked for this program (hunts/gnoc/mined-hosts.txt, written by the js_mine tool)."""
    try:
        return [l.strip().lower() for l in open(os.path.join(WS, "targets", program, "hunts/gnoc/mined-hosts.txt"))
                .read().splitlines() if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def surface_exhausted(program):
    """(unfired, total, unmined_hosts): the API-shaped mined routes no hypothesis has fired and no wall has closed,
    how many API-shaped mined routes exist, and the in-scope hosts js_mine has not walked. D89 (cycle 25, 10:48Z): all
    27 API-shaped routes on program-0 were fired or walled, the tournament's five proposals were refused as routes
    that do not exist, the lead's adds hit a wall, and the directive still said PHASE HYPOTHESIZE."""
    try:
        kp = [l.strip().rstrip("/") for l in open(os.path.join(WS, "targets", program, "hunts/gnoc/known-paths.txt"))
              .read().splitlines() if l.strip() and not l.startswith("#")]
    except OSError:
        kp = []
    api = [k for k in kp if _api_shaped_path(k)]
    fired = set()
    try:
        for h in load(program).get("hypotheses", []):
            for route in (h.get("routes") or {}):
                rk = route_key(route)
                if "/" in rk:
                    fired.add(("/" + rk.split("/", 1)[1]).rstrip("/").lower())
    except Exception:  # noqa: BLE001
        pass
    try:
        for rk in program_walls(program):
            if "/" in rk:
                fired.add(("/" + rk.split("/", 1)[1]).rstrip("/").lower())
    except Exception:  # noqa: BLE001
        pass
    unfired = [k for k in api if k.lower() not in fired]
    mined = set(mined_hosts(program))
    unmined = [h for h in scope_hosts(program) if h.lower() not in mined]
    return unfired, len(api), unmined


def admissible_routes_block(program, cap=18):
    """The prompt block naming the mined API routes no hypothesis has probed (D91, cycle 25 10:52Z): from the chat
    ledger's view 17 of program-0's 27 mined API routes had never been probed, and the tournament kept proposing
    routes that do not exist (refused by D79) because nothing told it what was admissible."""
    unfired, total, _ = surface_exhausted(program)
    if not total:
        return ""
    if not unfired:
        return (f"ADMISSIBLE ROUTES: none left - all {total} mined API routes were probed or walled. Propose only on a "
                "route js_mine adds or one a lane saw answer; a violation on an unknown route is refused.")
    return (f"ADMISSIBLE ROUTES ({len(unfired)} of {total} mined API routes that no hypothesis has probed; a violation "
            "on any OTHER route is refused, so put ONE of these in every violation):\n  "
            + "\n  ".join(unfired[:cap]))


DEEPDIVE_CROWNS = ("ato", "rce", "cross-tenant", "cross-user-read", "money")


def deep_dive(program, top=5):
    """Write targets/<program>/hunts/gnoc/DEEPDIVE-<date>.md and return (path, summary). D105 (2026-10-26): with the
    unauth surface exhausted and no identity, the bot had nothing to do but park; the dossier is the investigation it
    CAN do - every crown-bound chain laid out as the request it needs, against what the routes have answered."""
    d = load(program)
    hyps = {str(h.get("id", "")).upper(): h for h in d.get("hypotheses", [])}
    edges = d.get("edges", [])
    walls = program_walls(program)
    unfired, total_api, unmined = surface_exhausted(program)
    crown = [e for e in edges if node(e.get("to")) in DEEPDIVE_CROWNS]
    # rank: proven > lead > hypothesized; then edges whose hypothesis has a concrete route; then recency
    rank = {"proven": 3, "lead": 2, "hypothesized": 1, "refuted": 0}
    def hyp_of(e):
        m = re.match(r"(?i)^(h\d+)", str(e.get("id", "")))
        return hyps.get(m.group(1).upper()) if m else None
    def key(e):
        h = hyp_of(e)
        return (rank.get(e.get("status"), 0), 1 if h and _PATH_TOKEN.search(str(h.get("violation") or "")) else 0,
                str(e.get("ts") or ""))
    crown.sort(key=key, reverse=True)
    lines = [f"# DEEP DIVE {program} ({_now()[:16]}Z)", "",
             f"Surface: {total_api} mined API routes, {len(unfired)} never probed, {len(walls)} walled; "
             f"{len(unmined)} in-scope hosts not yet mined. Edges: {len(edges)} total, {len(crown)} crown-bound.", ""]
    for i, e in enumerate(crown[:top], 1):
        h = hyp_of(e)
        lines.append(f"## {i}. {e['id']}: {e.get('frm')} -> {e.get('to')} [{e.get('status')}] via {e.get('via')}")
        if h:
            lines.append(f"- hypothesis {h['id']} [{h.get('status')}] {str(h.get('title') or '')[:90]}")
            lines.append(f"- assumption: {str(h.get('assumption') or '')[:200]}")
            lines.append(f"- the request: {str(h.get('violation') or '')[:200]}")
            lines.append(f"- kill byte: {str(h.get('kill_byte') or '-')[:80]}; prediction: {str(h.get('prediction') or '')[:140]}")
            routes = h.get("routes") or {}
            if routes:
                lines.append("- what the routes answered so far:")
                for rk, shapes in list(routes.items())[:6]:
                    lines.append(f"    {rk}: " + ", ".join(f"{sh} x{n}" for sh, n in list(shapes.items())[:4])
                                 + ("  (WALL)" if rk in walls else ""))
            granted = any(any(str(sh).split(":")[0].startswith(("2", "3")) for sh in shapes) for shapes in routes.values())
            if not granted:
                lines.append("- precondition: no request on this seam has ever been granted unauthenticated; the next "
                             "probe is the SAME request as a saved identity (as_identity=A), then the cross-user "
                             "variant as B. Without an identity this chain cannot advance.")
            else:
                lines.append("- precondition: a granted answer exists; the next probe is the violation input on that "
                             "granted request with a one-variable control.")
        else:
            lines.append(f"- evidence: {e.get('evidence') or 'none'}; must_contain: {e.get('must_contain') or '-'}")
        lines.append("")
    if walls:
        lines.append("## Walls (refused before the wire for any hypothesis)")
        for rk, (shape, n) in sorted(walls.items(), key=lambda kv: -kv[1][1])[:12]:
            lines.append(f"- {rk}: {shape} x{n}")
        lines.append("")
    if unfired:
        lines.append("## Mined routes no hypothesis has probed")
        lines.extend(f"- {r}" for r in unfired[:20])
        lines.append("")
    lines.append("## The one unlock")
    lines.append("Every crown chain above waits on the same precondition when no route is granted: a saved identity "
                 "on the program (provision action=pair, or the user's hand signup saved to ACCOUNTS.md). With it, "
                 "re-fire each chain's request as A, then as B against A's object.")
    out = os.path.join(WS, "targets", program, "hunts", "gnoc", f"DEEPDIVE-{_now()[:10]}.md")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    return out, f"{len(crown[:top])} crown chains laid out, {len(walls)} walls, {len(unfired)} unprobed routes"


def deep_dive_due(program, hours=24):
    """True when no DEEPDIVE-*.md for the program is newer than `hours`."""
    import glob as _glob, time as _time
    files = _glob.glob(os.path.join(WS, "targets", program, "hunts", "gnoc", "DEEPDIVE-*.md"))
    newest = max((os.path.getmtime(f) for f in files), default=0)
    return _time.time() - newest > hours * 3600


def directive(program, goal="", briefed=False, peek=False):
    """What the model must do THIS turn, decided from the ledger, not from the model's memory.

    peek=True makes it PURE: no nudge consumed, no escalation or parking counter ticked. A directive has side
    effects by design (a turn spent on a lead counts against its budget), so anything that only wants to SHOW
    the phase must pass peek, or reading the phase spends the hunt's budget. Measured 2026-10-25: verifying the
    new phases on the live ledgers ticked three hypotheses' counters and one had to be un-parked by hand."""
    d = load(program)
    if d.get("nudge"):
        n = d["nudge"]
        if not peek:
            modify(program, lambda dd: dd.pop("nudge", None))
        return "STUCK: " + n + "\n" + _directive(program, goal, briefed, peek)
    return _directive(program, goal, briefed, peek)


def _directive(program, goal="", briefed=False, peek=False):
    d = load(program)
    H = d["hypotheses"]
    live = [h for h in H if h["status"] in ("open", "probing")]
    leads = [h for h in H if h["status"] in ("lead", "candidate")]
    cs = chains(program, 3)
    head = f"[HUNT {program}{' / focus: ' + goal if goal else ''}] "
    try:  # the lead asked for as_identity=A six times in one turn with no A saved (program-101 2026-10-23)
        import gnoc_ident
        names = sorted(gnoc_ident.load(program).keys())
        head += (f"IDENTITIES: {', '.join(names)}. " if names else
                 "IDENTITIES: none saved (hunt unauth; provision action=pair mints one; never pass as_identity). ")
    except Exception:  # noqa: BLE001
        pass
    tail = ("\nEnd the turn with one line: NEXT: <what you will do>. Start a line with READY: only when a draft is "
            "written, NEEDS: only for something only the user can provide.")
    # drive cycle 8 (2026-10-26): 61 of 83 probe attempts in one cycle went to one walled route and were refused one by
    # one. Name the walls up front, every turn, so the lead stops spending calls on them.
    try:
        walls = program_walls(program)
    except Exception:  # noqa: BLE001
        walls = {}
    if walls:
        head += ("WALLED ROUTES (refused before the wire for any hypothesis and any method past the cap; pick other routes): "
                 + "; ".join(f"{r} ({s.replace(':', ' len=')} x{n})" for r, (s, n) in list(walls.items())[:6]) + ". ")
    if not briefed and d["model"].get("boundaries") and H:
        # RE-ENTRY (2026-10-23): a /hunt restart used to re-run the whole COMPREHEND turn even though the model and
        # the hypotheses were already on disk (program-101: five restarts, each ~10 min of the 9B lead re-modelling the
        # same target). The brief is one cheap call; the ledger decides the phase as usual.
        head += (f"RE-ENTRY: the trust model ({len(d['model']['boundaries'])} boundaries) and {len(H)} hypotheses "
                 "are already on disk from an earlier turn. Call hunt_brief once to reload them, do NOT re-model or "
                 "re-fingerprint, then do this: ")
    elif not briefed:
        return head + ("PHASE COMPREHEND. Call hunt_brief first, then fingerprint (stack tags from the captures on "
                       "disk, or probe one in-scope root to get some). Then THEORIZE and write the trust model with "
                       "hunt_model(action=add): actors and roles; 3-6 boundaries, each naming the asset it protects AND "
                       "the actor it excludes; the vendor's documented promises VERBATIM with URL (web_fetch the docs: "
                       "a runtime that violates a written promise is the shape that pays); 3-5 catastrophes "
                       "(crown-class: rce, ato, cross-tenant, money, mass-pii) and which is REACHABLE unauth or with a "
                       "self-provisioned account. What did the developer TRUST? Attack that." + tail)
    complete = [(sc, c) for sc, c in cs if all(e["status"] == "proven" for e in c)]
    if complete:
        sc, c = complete[0]
        ready, missing = ship_ready(c)
        if not ready:
            return head + (f"PHASE CONTROL. Chain to {c[-1]['to'].upper()} (score {sc}) is proven but not shippable: "
                           + "; ".join(missing) + ". For each edge fire the request that MUST be refused (the excluded "
                           "actor, the wrong id, the missing token: one variable different from the positive), capture "
                           "it, and hunt_edge(action=update, id=E#, control=<raw file>). If an edge truly has no "
                           "negative, give control_na=<why>. Triagers praised the negative control by name; a report "
                           "without one dies as 'no boundary shown'.\n" + chains_text(program, 1) + tail)
        # whether a draft here can be FILED is a fact on disk, decided before the model spends the write
        # (gnoc_pay: the asset's bounty row, and the account's standing on the program under T-254)
        import gnoc_pay
        fok, fwhy = gnoc_pay.filing_gate(program, offline=True)
        money = ("" if fok else f"\nFILING IS BLOCKED FOR US: {fwhy}\nbuild_report will write the draft HELD (evidence "
                 "is perishable) and it must not be promoted. Say NEEDS: with that reason, or move to a program that "
                 "takes our reports (pick_target ranks them).")
        return head + (f"PHASE SHIP. Chain to {c[-1]['to'].upper()} (score {sc}) has every edge proven with controls:\n"
                       + chains_text(program, 1) + money + "\nRe-fire the source leg once to confirm it is still live, "
                       "then call build_report (it refuses an asset the program does not take reports on, writes the "
                       "draft from the raw captures, byte-faithful, FORM.md, and GATES.md with the CVSS arithmetic, the "
                       "capability gate, the money gate and the Burp-panel checklist, and runs the instant code gate), "
                       "read its message, fix every line it flags, run liveness on the draft dir (the sink must be "
                       "re-fired on the day it is filed), then call ship_chain on the draft dir and say "
                       "READY: <draft dir>" + tail)
    # ESCALATION BUDGET (2026-10-23): the directive picked the same top lead (H2) every turn for three hours and the
    # lead wrote the same NEXT line 19 times without one proven edge. A lead gets ESCALATE_TURNS turns; a turn that
    # proves no new edge counts against it; past the budget it is marked exhausted (its negatives are the receipt)
    # and the loop moves to the next hypothesis. hunt_hypothesis action=update id=H# status=lead re-opens it.
    leads = [h for h in leads if h.get("escalation") != "exhausted"]
    if leads:
        h = sorted(leads, key=lambda h: -CROWNS.get(h.get("crown") or "", 0))[0]
        proven_now = sum(1 for e in d["edges"] if e["status"] == "proven" and h["id"] in (e.get("via") or ""))
        turns = int(h.get("escalate_turns") or 0)
        if proven_now <= int(h.get("escalate_proven") or 0):
            turns += 1
        else:
            turns = 0
        def _tick(dd, hid=h["id"], t=turns, pn=proven_now):
            hh = _find(dd["hypotheses"], hid)
            if hh is not None:
                hh["escalate_turns"], hh["escalate_proven"] = t, pn
                if t > ESCALATE_TURNS:
                    hh["escalation"] = "exhausted"
                    hh["notes"] = (hh.get("notes") or "") + f" [escalation exhausted after {t} turns, {_now()}]"
        if not peek:
            modify(program, _tick)
        if turns > ESCALATE_TURNS:
            return head + (f"PHASE ESCALATE EXHAUSTED on {h['id']} ({h['title']}): {turns} turns and no edge proven. "
                           "Write its negatives in ONE call: hunt_hypothesis action=update id=" + h["id"] +
                           " status=dead notes='not single-use: <why no burst applies>; hops tried: <each with the "
                           "byte that refused it>' (a dead needs either a race burst on its single-use step or that "
                           "'not single-use:' note; a plain notes update keeps it a lead). Then move on: the next "
                           "open hypothesis, or hypothesize for a fresh seam (a different host, route family or "
                           "actor). Do not add edges to this hypothesis again." + tail)
        held = [e for e in d["edges"] if e["status"] in ("lead", "proven") and (h["id"] in (e.get("via") or ""))]
        cap = held[-1]["to"] if held else h["title"]
        plan = DOC.escalation_plan(cap)
        return head + (f"PHASE ESCALATE + CHAIN on {h['id']} ({h['title']}), escalation turn {turns} of "
                       f"{ESCALATE_TURNS}. A LEAD alone ships nothing, and a turn that only RECORDS an edge is a "
                       "wasted turn (measured: 17 of 25 escalate turns ran one hunt_edge call and no request). THIS "
                       "TURN, in this order: (1) pick ONE hop from the plan below toward a crown; (2) write "
                       "ASSUMPTION / VIOLATION / PREDICTION for it in one line each; (3) FIRE it now with http_request "
                       "(a mined route, as the identity that holds the capability, plus the negative control that "
                       "must be refused); (4) only then hunt_edge it with the raw capture as evidence (status=lead "
                       "needs the capture; proven needs the terminal bytes and the control). Hops you reject: one "
                       "line each with the byte that refuses them.\n" + plan
                       + "\nCurrent chains:\n" + chains_text(program, 3) + tail)
    # SURFACE and VERDICT (2026-10-25). Two shapes of waste the ledger can see and the model cannot: a hypothesis
    # whose probes all hit a route that only ever refused (no surface was tested), and one still "probing" past
    # twice the floor with no mechanism and no verdict. Each gets a bounded number of turns, then is parked UNFIRED
    # (never dead: nothing was tested) so it stops occupying a live slot and the loop moves on.
    walled = [h for h in live if h["status"] == "probing" and walled_routes(h) and counted_probes(h, program) < FLOOR]
    if walled:
        h = sorted(walled, key=lambda h: -h["probes"])[0]
        turns = int(h.get("surface_turns") or 0) + 1
        def _park_wall(dd, hid=h["id"], t=turns):
            hh = _find(dd["hypotheses"], hid)
            if hh is None:
                return
            hh["surface_turns"] = t
            if t > SURFACE_TURNS:
                hh["status"] = "unfired"
                hh["notes"] = ((hh.get("notes") or "") + f" | parked UNFIRED: {wall_text(hh)[:200]} ({_now()})").strip(" |")
        if not peek:
            modify(program, _park_wall)
        if turns > SURFACE_TURNS:
            return head + (f"PHASE SURFACE PARKED {h['id']} ({h['title']}): {SURFACE_TURNS} turns and no positive "
                           "control on a real route; it is UNFIRED (not dead: no surface was tested). Move on: the next "
                           "open hypothesis, or hypothesize for a seam on a route that exists (hunt_brief lists "
                           "targets/<p>/hunts/gnoc/known-paths.txt; js_mine the app bundle for more)." + tail)
        return head + (f"PHASE SURFACE {h['id']} ({h['title']}), turn {turns} of {SURFACE_TURNS}. {wall_text(h)} "
                       "THIS TURN: prove the surface before another variant. Fire ONE positive control that MUST "
                       "succeed on the seam this hypothesis attacks (the owner's own read of their own object as the "
                       "saved identity, or a route that appears in known-paths.txt or a mined bundle). If it answers "
                       "2xx, continue the variants on THAT route with http_request(hypothesis='" + h["id"] + "'). If "
                       "no real route carries this seam, set hunt_hypothesis action=update id=" + h["id"] +
                       " status=unfired notes='no surface: <the wall shape and the routes tried>' and move on." + tail)
    # D40 (drive cycles 13-16, 2026-10-26): H16 sat at 20 probes with 13 counted - under VERDICT_AT - while every new
    # probe went to a walled route and was refused before the wire, so neither counter ever moved and the lead
    # re-mutated it for four cycles. A hypothesis that has SPENT twice the floor in probes, counted or not, owes a
    # verdict too: the budget is gone either way.
    owed = verdict_owed_set(program, live)
    if owed:
        h = sorted(owed, key=lambda h: -counted_probes(h, program))[0]
        turns = int(h.get("verdict_turns") or 0) + 1
        def _park_verdict(dd, hid=h["id"], t=turns):
            hh = _find(dd["hypotheses"], hid)
            if hh is None:
                return
            hh["verdict_turns"] = t
            if t > VERDICT_TURNS:
                hh["status"] = "unfired"
                hh["notes"] = ((hh.get("notes") or "") + f" | parked UNFIRED: {hh['probes']} probes, no mechanism "
                               f"captured and no verdict given in {VERDICT_TURNS} verdict turns ({_now()})").strip(" |")
        if not peek:
            modify(program, _park_verdict)
        if turns > VERDICT_TURNS:
            return head + (f"PHASE VERDICT PARKED {h['id']} ({h['title']}): {h['probes']} probes, no mechanism and no "
                           "verdict in {VERDICT_TURNS} turns; it is UNFIRED and off the live list. Move on to the next "
                           "open hypothesis, or hypothesize for a fresh seam." + tail)
        return head + (f"PHASE VERDICT {h['id']} ({h['title']}): {counted_probes(h, program)} counted probes (floor {FLOOR}), "
                       f"{'a burst ran' if h.get('bursts') else 'NO burst yet'}, no mechanism captured. Variant number "
                       f"{h['probes'] + 1} is not the move; a decision is (turn {turns} of {VERDICT_TURNS}). Exactly one "
                       "of: (a) race(hypothesis='" + h["id"] + "') on its single-use or check-then-act step if it has "
                       "one, then decide; (b) hunt_hypothesis action=update id=" + h["id"] + " status=dead notes='not "
                       "single-use: <why>; variants: <each with the byte that refused it>'; (c) status=lead "
                       "evidence=<the raw capture whose 2xx/3xx shows the mechanism>. A refusal is not a mechanism." + tail)
    open_chain = [] if chain_waits(d, live) else \
        [(sc, c) for sc, c in cs if chain_has_substance(c)]
    if open_chain:
        sc, c = open_chain[0]
        w = weakest(c)
        return head + (f"PHASE CHAIN. Best chain reaches {c[-1]['to'].upper()} (score {sc}). Prove its weakest "
                       f"edge {w['id']}: {w['frm']} -> {w['to']} via {w['via']}. Write ASSUMPTION / VIOLATION / "
                       "PREDICTION, fire it with a negative control, then hunt_edge(action=update, id="
                       f"{w['id']}, status=proven, evidence=<raw file>, must_contain=<the terminal bytes>, "
                       "control=<raw file of the refused negative control>)." + tail)
    if not live:
        unfired_routes, total_api, unmined = surface_exhausted(program)   # D89
        if total_api and not unfired_routes:
            moves = []
            if unmined:
                moves.append("(1) MINE the in-scope hosts js_mine has not walked, one call each, then hypothesize from what "
                             "they add: " + ", ".join(f"js_mine(url='https://{h}/')" for h in unmined[:6]))
            moves.append(f"({len(moves) + 1}) PROVISION an identity if none is saved (identities action=list; then "
                         "provision action=pair with the program's signup URL): every API route above answers 401/403 "
                         "unauth, so the authed seams are the only ground left; re-aim the hypotheses at the owner-key "
                         "and cross-user routes AS the saved identity")
            moves.append(f"({len(moves) + 1}) if provisioning is walled (phone, captcha, blocked mailbox), record it: "
                         "record_outcome(verdict='NEEDS', notes='<the exact wall>') and stop inventing routes")
            return head + (f"PHASE SURFACE EXHAUSTED. Every one of the {total_api} API-shaped mined routes on {program} "
                           "has been fired or walled unauth, the tournament's proposals are refused as routes that do not "
                           "exist, and no hypothesis is live. Do not add a hypothesis on a guessed or walled route; the "
                           "moves, in order: " + "; ".join(moves) + "." + tail)
    if len(live) < 3:
        mdl = d["model"]
        need = "" if mdl.get("boundaries") else ("The model has no boundaries yet: write them first with hunt_model "
                                                 "(each names the asset it protects and the actor it excludes). ")
        if goal and node(goal) in CROWNS:
            held = [e["to"] for e in d["edges"] if e["status"] in ("proven", "lead")]
            need += "\n" + DOC.attack_tree(goal, held, 2) + "\nAim the hypotheses at the leaves closest to a held capability.\n"
        return head + ("PHASE HYPOTHESIZE. " + need + "Call hypothesize (both GPUs propose from the trust model, the "
                       "doctrine pack and the matching pattern cards; code scores and keeps the best). Then, if you "
                       "see a better idea from THIS target's model, add it yourself with hunt_hypothesis(action=add): "
                       "title, crown, boundary (the model boundary it breaks), assumption (what the developer "
                       "trusted), violation (ONE crafted input: method, path, field), prediction (the bytes that "
                       "confirm, distinct from the negative control), kill_byte, requires (preconditions). Aim the "
                       "first three at the openers: seam race, documented-control contradiction, sibling authz drift, "
                       "merge/transfer owner-key drift, second handler, read-never-branched. playbook(kind=cards, "
                       "query=<stack or seam>) shows shapes that paid elsewhere; vary the mechanism for THIS target. "
                       "Then add each as a hypothesized capability edge (hunt_edge) so the chain search sees it.\n"
                       + admissible_routes_block(program)
                       + tail)
    fresh = [h for h in live if budget_left(program, h) > 0] or live   # D82
    h = sorted(fresh, key=lambda h: (-CROWNS.get(h.get("crown") or "", 0), counted_probes(h, program)))[0]
    tells = "\n".join(f"- {i}: {t}" for i, t in DOC.moves("BEF" if h["probes"] >= 5 else "BE",
                                                            h["title"] + " " + h["violation"], 3, 240))
    wall = wall_text(h)
    return head + (f"PHASE PROBE {h['id']}: {h['title']} ({counted_probes(h, program)} probes count so far, floor {FLOOR}).\n"
                   + (wall + "\n" if wall else "") +
                   f"ASSUMPTION: {h['assumption']}\nVIOLATION: {h['violation']}\nPREDICTION: {h['prediction']}\n"
                   f"TELLS TO WATCH (doctrine):\n{tells}\n"
                   "Start with probe_matrix(url=..., hypothesis='" + h["id"] + "') on the seam: it fires the "
                   "identity, method, path-shape and id variants with a nonsense control and returns only what "
                   "differs. Follow every '!' row with crafted http_request(hypothesis='" + h["id"] + "') calls - mutate schema fields, "
                   "encodings, the second handler, sibling objects, the enforcing twin - plus a negative control, "
                   "and race(hypothesis='" + h["id"] + "') on any single-use path (burst + serial control; a dead needs it). "
                   "Probe as the saved identities (identities action=list), never as the user; if the hypothesis needs an "
                   "account and none is saved, MAKE it first with provision(action=pair, signup_url=<signup page>) - an "
                   "account you can mint yourself is never a NEEDS. Then set its status: lead (mechanism, no "
                   "terminal), candidate (terminal bytes captured, give evidence), or dead (only past the floor)."
                   + tail)
