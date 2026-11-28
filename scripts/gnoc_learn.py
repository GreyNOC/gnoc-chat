"""gnoc_learn.py - the lesson book gnoc chat writes for itself and keeps rewriting as it learns.

Files (append-friendly, readable by any agent):
    .claude/state/orch/agent/lessons.jsonl          live lessons, one JSON object per line
    .claude/state/orch/agent/lessons-retired.jsonl  retired lessons with the reason; never deleted, so a lesson
                                                    that was proven wrong is not learned again blindly
A lesson: {id: "L12", kind: pref|rule|fact, text, why, program ("*" = every program), reinforced, uses,
           created, updated, source}
    pref  how the user wants the agent to work (their corrections); always recalled
    rule  a hunting technique that worked or failed, with the reason
    fact  something true about one program (a dead seam, a working account, a WAF quirk)

The loop (recursive: each pass edits the book the previous passes wrote):
    1. recall   before a turn, the prefs plus the lessons most relevant to the program and the request are put
                in the system prompt (relevance = program match + word overlap + how often it was reinforced)
    2. reflect  after a turn that used tools, or a hunt round, the worker model reads that turn plus the
                lessons it was given and returns operations: add new ones, reinforce ones that held, revise
                ones that were incomplete, retire ones the turn contradicted
    3. apply    code checks every operation: near-duplicates become reinforcements, ids must exist, text is
                capped, the book is capped at MAX_LIVE (the weakest are retired, with the reason)
the user's own words win: a message that corrects the agent ("no", "don't", "stop doing", "I told you") is
recorded as a pref directly, without waiting for the model.
"""
import contextlib
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = os.path.join(WS, ".claude/state/orch/agent")
LIVE = os.path.join(DIR, "lessons.jsonl")
RETIRED = os.path.join(DIR, "lessons-retired.jsonl")
# the measured hunt history (built from OUTCOMES, never by a model) and every tool turn with its measured outcome
GROUND = os.path.join(DIR, "lessons-ground.jsonl")
TRAJ = os.path.join(DIR, "trajectories.jsonl")
OUTCOMES = os.path.join(WS, ".claude/state/hunt-loop/outcomes.jsonl")
MAX_LIVE = 200
KINDS = ("pref", "rule", "fact")
_lock = threading.Lock()
_WORD = re.compile(r"[a-z0-9][a-z0-9._/-]{2,}")
_STOP = set("the and for with that this from you your are was were have has not but all any can will into "
            "when then than them they its it's our out use used using via per one two".split())
CORRECTION = re.compile(r"^\s*(no\s*[,.!]|no\s*$|nope\b|don'?t\b|do not\b|stop (doing|telling|asking)|never\b|"
                        r"i told you|that'?s wrong|wrong[,. ]|instead[,. ]|always\b|from now on\b)", re.I)
# ordinary sentences that open like a correction: "Never mind", "No problem", "Don't know why this fails",
# "Always the same error?" were each stored as a standing preference the agent then had to obey forever
NOT_CORRECTION = re.compile(r"^\s*(never\s*mind|nevermind|no (problem|worries|thanks|thank you|rush|idea|need|clue)\b|"
                            r"no,? thanks?\b|(don'?t|do not) (know|worry|mind|care|forget to (tell|show|explain))\b|"
                            r"(don'?t|do not) (you|we|i|they|it|this|that)\b[^.!]*\?\s*$|(always|never)\b[^.!,]*\?\s*$)", re.I)
# a limit, then the request it limits: "do not commit. what would a good commit message be". A complaint ("don't
# do that, why did you delete the evidence?") is still a correction.
_SCOPED = re.compile(r"[.!;:,]\s*(?:just\s+|only\s+|but\s+)?(?!why\s+(?:did|would|do|are|were|have)\s+you\b)"
                     r"(?:what|which|how|why|when|where|who|can|could|would|should|is|are|does|do|tell|show|explain|"
                     r"give|list|describe|say|plan|draft|write)\b[^\n]*$", re.I)
# A fact worth keeping is about the TARGET: an HTTP surface, a host, a status, a parameter, a header, a token,
# or a measured count. Anything else the reflection writes as a "fact" is a note about our own repo or tooling.
_TARGET_FACT = re.compile(r"(/[a-z0-9_.{}-]+|\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|io|test|dev|app|co|org)\b|"
                          r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b|\b[1-5]\d\d\b|\b[A-Z][A-Z0-9_]{2,}\b|"
                          r"\b\d+\b)", re.I)




@contextlib.contextmanager
def isolated(path=None):
    """Point the whole lesson book at a throwaway directory (benchmarks, tests): nothing they recall marks a
    real lesson used and nothing they learn reaches the real book. Restores the real paths on exit."""
    global DIR, LIVE, RETIRED, GROUND, TRAJ, OUTCOMES
    saved = (DIR, LIVE, RETIRED, GROUND, TRAJ, OUTCOMES)
    d = path or tempfile.mkdtemp(prefix="gnoc-lessons-")
    DIR, LIVE, RETIRED = d, os.path.join(d, "lessons.jsonl"), os.path.join(d, "lessons-retired.jsonl")
    GROUND, TRAJ, OUTCOMES = (os.path.join(d, "lessons-ground.jsonl"), os.path.join(d, "trajectories.jsonl"),
                              os.path.join(d, "outcomes.jsonl"))
    try:
        yield d
    finally:
        DIR, LIVE, RETIRED, GROUND, TRAJ, OUTCOMES = saved


# a reflection lesson that only narrates what happened in the turn ("the script X was added") teaches nothing a
# future turn can act on; neither does one about the chat itself
TRIVIA = re.compile(r"\b(was|were|has been|have been|got)\s+(added|created|written|saved|updated|modified|edited|"
                    r"committed|renamed|moved|deleted)\b|\b(user|greynoc)\s+(requested|asked|wanted|said)\b|"
                    r"^\s*(the\s+)?(assistant|agent|model)\s+(ran|used|called|read|answered)\b|"
                    # "ledger.jsonl updated with unique entry for 2026-10-22T16:27:00Z" (the 8B reflector, replay)
                    r"^\s*(the\s+)?[\w./:-]+\s+(updated|added|created|edited|modified|written|saved|fixed|resolved|"
                    r"adjusted|cleaned)\b(?!\s+(only|when|if|unless|before|after)\b)|^\s*(adjusted|updated|fixed|resolved|"
                    r"added|edited)\b|"
                    # past-tense events of one request are a log, not a lesson ("The GET request to X was successful
                    # with status 200", "the entry was duplicated and corrected"), bench 2026-10-22
                    r"\b(was|were)\s+(successfully\s+\w+|successful|unsuccessful|duplicated|corrected|fixed|resolved|completed|performed|"
                    r"sent|made|executed|returned|received)\b", re.I)
# A status or log line ("qaqc functional battery ran", "The Burp MCP is operational") is not a lesson: it
# teaches no future turn anything, it is only true until it is not. The live book's most-reinforced
# entry on 2026-10-22 was exactly this, reinforced 27 times. Only a WHOLE statement of status is caught;
# a fact with a condition ("the WAF is operational on /api but not /v1") is kept.
STATUS = re.compile(r"^\s*(the\s+)?[\w ./:@-]{1,48}?\s+(ran|was run|has run|completed|finished|passed|succeeded|"
                    r"failed|works|worked|is (up|down|running|operational|online|offline|available|working|"
                    r"reachable|unreachable|live|ready))\s*\.?\s*$", re.I)
# "No identity 'A' found for program-64" sat in the live book as a fact: an absence with no count is a moment in
# time, not a negative. One that carries its measure ("no /graphql after 40 probes") is kept.
ABSENCE = re.compile(r"^\s*no\s+[^.]{1,80}?\b(found|exists?|available|configured|present|set)\b|"
                     r"\b(does not|doesn't|did not|didn't) exist\b|\bwas not found\b", re.I)
# a concrete anchor: a path, host, endpoint, file, identifier, number or quoted token. A lesson with none is
# generic advice ("adjust the snippet to make it unique") that no future turn can act on differently.
ANCHOR = re.compile(r"[\w-]*[/._:@=#\d][\w./:@=#-]*|'[^']{2,40}'|\"[^\"]{2,40}\"|`[^`]{2,40}`")
# bench and test fixtures use these; a lesson that names one must never reach the real book
FICTIONAL = re.compile(r"\b[\w-]+\.(test|example|invalid)\b|\bacme\b", re.I)
# A "lesson" whose SUBJECT is our own harness behaving: "The host 'bb-hunt-system' (via read_file)
# correctly identifies 'hunt-index.py' as a real file". It teaches a future turn nothing, and the
# reflection writes one whenever a tool call is uneventful. The 2026-10-25 soak put four in the live
# book in one night, one of them FALSE ("reports no such file for a path that exists" - the path never
# existed). A lesson about a tool is kept when it says what the tool REQUIRES or how it FAILS, which is
# why this matches the narration shape and not the word "tool".
HARNESS_TRIVIA = re.compile(r"\(via\s+[\w.-]+\s*\)|\bthe host ['\"`]?bb-hunt-system['\"`]?", re.I)
# PROGRAM-BOUND anchors: a host, a URL path, a ledger id (H2, E1, H2-edge), a specific error code, or the "admin
# twin" an escalation aimed at. A lesson carrying one is true about ONE program and can never be filed under "*".
# Measured 2026-10-25: six "*" rules about program-101's INVENTED /api/v1/admin/twin ("the admin twin endpoint requires a
# JSON body with pid, device_class and action to trigger the terminal capability") were recalled on program-32
# and program-0, and both hunts then aimed hypotheses at an "admin twin" that neither program has.
_HOST = r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|io|dev|app|cloud|tech|co|ai|rest|xyz)\b"
_HUNT_ANCHOR = (r"(?<![\w:./])/[a-z0-9_{}-]{2,}(?:/[a-z0-9_{}.-]+)*|\b[HE]\d{1,3}(-[a-z]+)?\b(?![.\w])|"
                r"\berror[_ ]?code\s*:?\s*\d{3,}|\badmin[ _]twin\b")
PROGRAM_BOUND = re.compile(_HOST + "|" + _HUNT_ANCHOR, re.I)
# the subset that can only be about a hunt: a route, a ledger id, an error code, the admin twin. A "*" lesson that
# names a host alone may be about GreyNOC's own site or infrastructure (your-site.example is served by pm2), which
# no program owns and which must stay learnable; a route or a ledger id with hunting vocabulary cannot be universal.
HUNT_BOUND = re.compile(_HUNT_ANCHOR, re.I)
HUNT_WORDS = re.compile(r"\b(probe[sd]?|hypothes[ie]s|terminal|capabilit(y|ies)|lead|edge|authz|endpoint|burst|"
                        r"payload|bypass|exploit|crown|ato|unauth|403|401)\b", re.I)
# A lesson that restates the doctrine's own move names, the harness's tool arguments or its ledger state machine
# teaches a future turn nothing the directive does not already say, and it is where the reflector's fiction lived:
# "The 'via' parameter in the hunt_edge tool call is 'websocket-message-level-authz-drift / admin twin'".
DOCTRINE_ECHO = re.compile(r"\b(same defect,? higher.value asset|the paired write|the partner bug|the missing context|"
                           r"what the disclosed thing unlocks)\b|"
                           r"\b(hunt_edge|hunt_hypothesis|hunt_model|hunt_brief|record_outcome|probe_matrix)\b[^.]{0,80}"
                           r"\b(parameter|tool call|argument|field|call)\b|"
                           r"\b(the|an?)\s+['\"`]?(unauth|lead|ato|own-account|candidate)['\"`]?\s+(state|status)\b", re.I)
# a fact that claims what a route REQUIRES or TRIGGERS is a claim about the target's behaviour on that route
CAPABILITY_CLAIM = re.compile(r"\b(trigger|terminal|capabilit|unlock|grants?|requires?|required|reach(es)?)\b", re.I)
_LESSON_PATH = re.compile(r"(?<![\w:./])(/[a-z0-9_{}-]{2,}(?:/[a-z0-9_{}.-]+)*)", re.I)
_LINE_STATUS = re.compile(r"\bHTTP\s+(\d{3})\b|\"status\":\s*(\d{3})\b|\b(\d{3})\s+len=", re.I)


def worth_keeping(text, why="", kind="rule", source="model"):
    """Code-side gate on what the reflection may add. The user's own corrections always pass."""
    if source == "greynoc":
        return True, ""
    if FICTIONAL.search(text or "") or FICTIONAL.search(why or ""):
        return False, "names a fictional benchmark/test target"
    if TRIVIA.search(text or ""):
        return False, "narrates the turn instead of teaching something"
    if HARNESS_TRIVIA.search(text or ""):
        return False, "narrates how our own tooling behaved, which teaches a future turn nothing"
    if DOCTRINE_ECHO.search(text or ""):
        return False, "restates the doctrine's move names or the harness's own tool vocabulary, not what the target did"
    if STATUS.search(text or ""):
        return False, "a status or log line, not a lesson a future turn can act on"
    if ABSENCE.search(text or "") and not re.search(r"\d", text or ""):
        return False, "an absence with no count is a moment in time, not a negative"
    if kind in ("rule", "fact") and len((why or "").strip()) < 12:
        return False, "no evidence in why"
    if kind == "fact" and not _TARGET_FACT.search(text or ""):
        # A fact is a claim about a TARGET. The reflection was storing what it had just read in our own repo
        # ("the 'svc/api.py' file imports 'plus' from 'svc.calc'", "test_strutil.py contains 7 tests") and in
        # our own tooling ("the OAST tool caches calls and refuses the 5th poll"). Those are not facts a future
        # hunt can act on, and recall() scores them like any other line, so they crowded real receipts out of
        # the prompt. A fact must name an HTTP surface, a host, a status, a parameter or a measured count.
        return False, "a fact must be about the target (a path, host, status, parameter or measured count), not about our own files or tools"
    return True, ""


def _anchors(text):
    out = set()
    for a in ANCHOR.findall(text or ""):
        a = a.strip("'\"`.:,").lower()
        if len(a) >= 3 or (len(a) >= 2 and a.isdigit()):   # "28 origins" is a measure; "a." is not an anchor
            out.add(a)
    return out


def grounded(text, kind, turn_text, user_text):
    """Code-side check that a MODEL-written lesson comes from this turn, not from the model's priors.

    rule/fact: at least one concrete anchor of the lesson appears in the turn. pref: how the user wants the agent
    to work can only come from the user, so at least two of its content words must be their words this turn."""
    if kind == "pref":
        mine = _words(text)   # most of it must be HIS words (a 2-word overlap let an invented pref through, bench)
        return (len(mine & _words(user_text)) >= max(3, len(mine) // 2 + 1),
                "a preference the model inferred; only the user's own words this turn make a pref")
    anchors = _anchors(text)
    if not anchors:
        return False, "generic advice: names no path, host, endpoint, identifier or number"
    low = (turn_text or "").lower()
    if not any(a in low for a in anchors):
        return False, "its anchors (" + ", ".join(sorted(anchors)[:3]) + ") are not in the turn"
    for pth in {m.lower() for m in _LESSON_PATH.findall(text or "")}:
        # a route the turn itself flagged as a ghost, or one that only ever refused, teaches what it "requires" to
        # nobody: the 25 admin-twin lessons of 2026-10-25 were all about a path whose every answer was 403 len=35
        if re.search(r"ghost[- ]path:?\s*" + re.escape(pth), low):
            return False, f"{pth} was flagged GHOST-PATH this turn; a lesson about a route that does not exist is fiction"
        if CAPABILITY_CLAIM.search(text or ""):
            codes = route_statuses(pth, turn_text)
            if codes and min(codes) >= 400:
                return False, (f"every capture of {pth} this turn was a refusal ({', '.join(str(c) for c in sorted(codes))}); "
                               "what the route 'requires' or 'triggers' is a guess until a 2xx/3xx is seen")
    return True, ""


def route_statuses(pth, turn_text):
    """The HTTP statuses the turn's tool output shows on lines that mention this path."""
    codes = set()
    for ln in (turn_text or "").splitlines():
        if pth not in ln.lower():
            continue
        for m in _LINE_STATUS.finditer(ln):
            code = next((g for g in m.groups() if g), None)
            if code:
                codes.add(int(code))
    return codes


def _words(t):
    return {w for w in _WORD.findall((t or "").lower()) if w not in _STOP}


def similar(a, b):
    wa, wb = _words(a), _words(b)
    return len(wa & wb) / max(1, len(wa | wb))


def load(path=None):
    rows = []
    try:
        with open(path or LIVE, encoding="utf-8", errors="replace") as f:
            for ln in f:
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                # every caller indexes r["id"] / r["text"]: one foreign line (a bare string, a row without an id)
                # raised inside recall(), i.e. inside the system prompt, on every turn
                if isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("text"), str):
                    rows.append(r)
    except OSError:
        pass
    return rows


def _save(rows):
    os.makedirs(DIR, exist_ok=True)
    tmp = f"{LIVE}.{os.getpid()}.{threading.get_ident()}.tmp"   # two chats shared one tmp name
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, LIVE)


def _retire(row, reason):
    os.makedirs(DIR, exist_ok=True)
    with open(RETIRED, "a") as f:
        f.write(json.dumps(dict(row, retired=_now(), reason=reason)) + "\n")


def _next_id(rows):
    ids = [int(r["id"][1:]) for r in rows + load(RETIRED) if re.fullmatch(r"L\d+", r.get("id", ""))]
    return f"L{max(ids or [0]) + 1}"


def _stale(r):
    """Recalled again and again but never once confirmed: likely noise. Grows past 20 unconfirmed uses."""
    return 0.0 if r.get("reinforced", 0) or r.get("kind") == "pref" else max(0, r.get("uses", 0) - 20) * 0.05


def _strength(r):
    return (r.get("reinforced", 0) * 2 + min(r.get("uses", 0), 20) * 0.1 + (5 if r.get("kind") == "pref" else 0)
            - _stale(r))


def repo_scope():
    """"repo:<path>" when this chat is working in a code repo outside the hunt workspace, else None.

    A FACT learned there is about that repo's files. Stored for every chat ("*"), "The file 'tests/test_store.py'
    contains 4 distinct tests ..." came back in an unrelated JavaScript repo and the lead's first move was to read
    tests/test_store.py (2026-11-21 drives); 22 such facts sat in the book, recalled into hunts too. Rules and
    preferences are how to work and stay global."""
    import sys
    G = sys.modules.get("gnoc_agent")
    if G is None:
        return None
    try:
        r, ws = os.path.realpath(G.root()), os.path.realpath(G.WS)
    except Exception:   # noqa: BLE001 - no scope is an answer
        return None
    return None if r == ws else "repo:" + r


def add(text, why="", kind="rule", program="*", source="model"):
    """Add a lesson, or reinforce the near-duplicate already in the book. Returns (id, 'added'|'reinforced')."""
    if kind == "fact" and program in (None, "", "*") and source != "greynoc":
        program = repo_scope() or "*"
    try:  # a lesson must never carry a credential, even if someone pasted one into the chat
        import gnoc_secrets
        text, why = gnoc_secrets.redact(text or ""), gnoc_secrets.redact(why or "")
    except ImportError:
        pass
    text = " ".join((text or "").split())[:400]
    if len(text) < 12:
        return None, "too short"
    bad = _poisoned(text, why)
    if bad and source != "greynoc":
        return None, bad
    text, why = _clean(text), _clean(why)
    if source != "greynoc" and (FICTIONAL.search(text) or FICTIONAL.search(why or "")):
        return None, "fictional target"
    if source != "greynoc" and (program or "*") == "*" and HUNT_BOUND.search(text) and HUNT_WORDS.search(text):
        return None, "program-bound (a route, ledger id or error code of one hunt) but filed under every program"
    kind = kind if kind in KINDS else "rule"
    with _lock:
        rows = load()
        for r in rows:
            if r.get("program", "*") in ("*", program) and similar(r["text"], text) >= 0.6:
                r["reinforced"] = r.get("reinforced", 0) + 1
                r["updated"] = _now()
                _save(rows)
                return r["id"], "reinforced"
        r = {"id": _next_id(rows), "kind": kind, "text": text, "why": " ".join((why or "").split())[:300],
             "program": program or "*", "reinforced": 0, "uses": 0, "created": _now(), "updated": _now(),
             "source": source}
        rows.append(r)
        if len(rows) > MAX_LIVE:
            rows.sort(key=lambda x: (x.get("kind") == "pref", _strength(x), x.get("updated", "")))
            for gone in rows[:len(rows) - MAX_LIVE]:
                _retire(gone, f"book over {MAX_LIVE}: weakest lesson")
            rows = rows[len(rows) - MAX_LIVE:]
        _save(rows)
        return r["id"], "added"


def reinforce(lid):
    with _lock:
        rows = load()
        for r in rows:
            if r["id"] == lid:
                r["reinforced"] = r.get("reinforced", 0) + 1
                r["updated"] = _now()
                _save(rows)
                return True
    return False


def weaken(lid):
    """A lesson recalled into a turn that measurably FAILED loses one reinforcement. At zero it stays (a
    single bad turn is not proof), but it sorts below lessons that keep working, and the cap retires the
    weakest first - so a lesson that keeps failing is eventually dropped, with the reason on record."""
    rows = load()
    for r in rows:
        if r["id"] == lid:
            if r.get("source") == "greynoc":
                return False        # his own corrections are never weakened by a model's failed turn
            r["reinforced"] = max(0, int(r.get("reinforced", 0)) - 1)
            r["weakened"] = int(r.get("weakened", 0)) + 1
            r["updated"] = _now()
            _save(rows)
            return True
    return False


def _clean(text):
    """A lesson without invisible characters (they hide text from them, not from the model)."""
    try:
        import gnoc_comms
        return gnoc_comms.injection_signs(text or "")[0]
    except Exception:  # noqa: BLE001
        return text or ""


def _poisoned(text, why=""):
    """Why a model-written lesson is refused when it reads like an injected instruction, else ''. A lesson is
    recalled into every later turn, so one drawn from a hostile web page would instruct gnoc for good (the Hermes
    Agent review: memory writes are scanned for injection, 2026-11-23)."""
    try:
        import gnoc_comms
        _c, signs = gnoc_comms.injection_signs(f"{text}\n{why or ''}")
    except Exception:  # noqa: BLE001
        return ""
    hit = [s for s in signs if s.split(":")[0] in ("override", "role", "exfiltrate", "hidden-html", "tool-call",
                                                     "command")]
    return ("reads like an injected instruction (" + "; ".join(hit)[:160] + ")") if hit else ""


def revise(lid, text, why=""):
    if _poisoned(text, why):
        return None
    text, why = _clean(text), _clean(why)
    with _lock:
        rows = load()
        for r in rows:
            if r["id"] == lid:
                _retire(dict(r), f"revised into a new text ({_now()})")
                r["text"] = " ".join(text.split())[:400]
                if why:
                    r["why"] = " ".join(why.split())[:300]
                r["updated"] = _now()
                _save(rows)
                return True
    return False


def retire(lid, reason):
    with _lock:
        rows = load()
        keep = [r for r in rows if r["id"] != lid]
        if len(keep) == len(rows):
            return False
        _retire(next(r for r in rows if r["id"] == lid), reason or "retired")
        _save(keep)
        return True


def recall(query="", program=None, k=12, mark_used=True):
    """The lessons for this turn: every pref (up to 8) plus the k most relevant rules/facts."""
    if os.environ.get("GNOC_NO_LEARN"):
        mark_used = False   # a test drive reads the lesson book and leaves its counters alone
    rows = load()
    q = _words(query)
    prefs = sorted([r for r in rows if r.get("kind") == "pref"], key=lambda r: -_strength(r))[:8]
    scored = []
    here = repo_scope()
    for r in rows:
        if r.get("kind") == "pref":
            continue
        rp = r.get("program", "*")
        if rp not in ("*", program, here) or (str(rp).startswith("repo:") and rp != here):
            continue   # another program's lesson, or a fact about a different repo's files
        s = (2.0 if program and rp == program else 0.0) + 3.0 * len(q & _words(r["text"] + " " + r.get("why", ""))) \
            / max(1, len(q)) + 0.3 * r.get("reinforced", 0) - _stale(r)
        scored.append((s, r))
    picked = prefs + [r for s, r in sorted(scored, key=lambda x: -x[0])[:k] if s > 0.2]
    if mark_used and picked:
        ids = {r["id"] for r in picked}
        with _lock:
            rows = load()
            for r in rows:
                if r["id"] in ids:
                    r["uses"] = r.get("uses", 0) + 1
            try:  # a use count is bookkeeping; an unwritable book must not break the turn that recalls it
                _save(rows)
            except OSError:
                pass
    return picked


def recall_block(query="", program=None):
    rows = recall(query, program)
    ground = ""
    with contextlib.suppress(OSError, ValueError):
        ground = ground_block(query, program)
    if not rows:
        return ground
    line = lambda r: (f"- [{r['id']} {r['kind']}{'' if r.get('program', '*') == '*' else ' ' + r['program']}] "
                      f"{r['text']}" + (f" (why: {r['why']})" if r.get("why") else ""))
    # Two trust tiers. Model reflections had outranked GreyNOC's own receipts by sheer reinforcement: on one program the
    # verified "ROPC is no capability" sat under five learned lines framing it as one, and the answer followed
    # them (training run 2026-10-22). The verified tier comes first and wins every conflict.
    verified = [r for r in rows if r.get("source") == "greynoc"]   # "agent" = the model's own learn tool
    learned = [r for r in rows if r not in verified]
    out = []
    if verified:
        out.append("VERIFIED LESSONS (the user's own rules and receipt-backed facts; they win any conflict):\n"
                   + "\n".join(line(r) for r in verified))
    if learned:
        out.append("LEARNED FROM YOUR OWN PAST TURNS (lower trust: a verified lesson or a receipt you read now "
                   "overrides these; when one turns out wrong say so so it can be retired):\n"
                   + "\n".join(line(r) for r in learned))
    return "\n\n".join(out) + ("\n\n" + ground if ground else "")


def capture_correction(user_text, program=None):
    """The user correcting the agent is the strongest signal there is: store it as a pref at once."""
    t = (user_text or "").strip() if isinstance(user_text, str) else ""
    if not t or len(t) > 600 or not CORRECTION.search(t) or NOT_CORRECTION.search(t):
        return None
    if os.environ.get("GNOC_NO_LEARN"):
        return None   # a test drive's prompts are not GreyNOC's corrections
    if _SCOPED.search(t):
        # "do not commit. what would a good commit message be", "do not change anything. which one would you fix
        # first": a limit on THIS request, followed by the request. Each was stored as a standing preference
        # that would have forbidden every later commit or change (four of them, 2026-11-21/22).
        return None
    try:  # runs before every turn, outside any tool guard: a full or read-only disk must not stop the chat
        return add(t, "The user's own correction", "pref", "*", "greynoc")
    except OSError:
        return None


REFLECT_SYSTEM = """You maintain the lesson book of GNOC, a bug-bounty hunting agent. Read one turn of its work and
the lessons it was given, then return ONLY a JSON object, no prose:
{"add": [{"kind": "rule|fact", "text": "...", "why": "...", "program": "<handle or *>"}],
 "reinforce": ["L3"], "revise": [{"id": "L5", "text": "...", "why": "..."}], "retire": [{"id": "L7", "reason": "..."}]}
What is worth learning: a technique that produced evidence or failed for a clear reason (rule), something true
about this program that saves probes next time (fact: a dead seam with its probe count, a WAF or client quirk, a
working account, an endpoint shape). Never add a pref: the user's preferences are recorded from their own
corrections, never by you. Lessons marked (the user) are their: never revise or retire them. Each lesson is one concrete
sentence a future turn can act on; "why" cites what in this turn shows it. Reinforce a given lesson the turn
confirmed, revise one it showed was incomplete, retire one it contradicted. Do not restate the turn, do not add
generic advice, do not invent results that are not in the turn. Every rule or fact must name the concrete
thing it is about (a path, host, endpoint, parameter, file, tool or number) exactly as it appears in the turn.
Code drops anything else. If nothing is worth learning return {}."""


def _turn_text(msgs, cap=9000):
    out = []
    for m in msgs:
        if m.get("role") == "system":
            continue
        c = (m.get("content") or "")
        if m.get("tool_calls"):
            c += " CALLS: " + "; ".join(f"{(t.get('function') or {}).get('name')}"
                                        f"({json.dumps((t.get('function') or {}).get('arguments'))[:200]})"
                                        for t in m["tool_calls"])
        out.append(f"[{m.get('role')}{':' + m['tool_name'] if m.get('tool_name') else ''}] {c[:1500]}")
    t = "\n".join(out)
    return t[-cap:]


def json_objects(text):
    """Every complete top-level {...} in text, parsed (small models wrap JSON in prose or fences, leave trailing
    commas, or get cut off; this keeps every object that did complete)."""
    text = re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).rsplit("</think>", 1)[-1]
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_str:
            esc = (ch == "\\") and not esc
            if ch == '"' and not esc:
                in_str = False
            continue
        if ch == '"':
            in_str, esc = True, False
        elif ch == "{":
            depth += 1
            if depth == 1:
                start = i
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    out.append(json.loads(re.sub(r",\s*([}\]])", r"\1", text[start:i + 1])))
                except ValueError:
                    pass
    return [o for o in out if isinstance(o, dict)]


OPS = ("add", "reinforce", "revise", "retire")


def parse_ops(text):
    objs = json_objects(text)
    for o in objs:
        if any(k in o for k in OPS):
            return o
    # some models return the lessons themselves instead of the envelope
    lessons = [o for o in objs if o.get("text") and o.get("kind") in KINDS]
    if lessons:
        return {"add": lessons}
    return objs[0] if len(objs) == 1 and not objs[0] else {}


# A reading of the machine as it was at one moment. It is read again each time it is asked, never remembered:
# a reflection kept "the machine exposes 6 CPU threads" (it has 16; the lead had counted six rows of a process
# table), and the next 46 turns that asked were answered "6" from the lesson, with no look (2026-11-22).
_LIVE_READING = re.compile(
    r"\b\d[\d,.]*\s*(?:cpu\s+|high[- ]priority\s+|security\s+|pending\s+|open\s+|failed\s+|running\s+)*"
    r"(?:threads?|cores?|cpus?|processes|services|alerts?|findings?|updates?|cves?|logins?|connections?|devices?|"
    r"gi?b|mi?b|users?|packages?|sockets?|neighbou?rs?)\b"
    r"|\b(?:currently|right now|at the moment|as of (?:now|today))\b"
    r"|\b(?:machine|system|host|box|server|firewall|service|daemon)\b[^.]{0,60}\bis (?:running|active|inactive|enabled|"
    r"disabled|on|off|up|down|listening|installed|not (?:running|installed|enabled|active))\b", re.I)


def live_reading(text):
    return bool(_LIVE_READING.search(str(text or "")))


LAST_REJECTS = []   # why each op of the most recent apply_ops was refused (the reflection's monitor log shows it)


def apply_ops(ops, program=None, given_ids=(), outcome=None, turn=None):
    """Apply reflection output after validating it. Returns counts.

    `outcome` (turn_outcome) gates reinforcement: only a turn MEASURED as good may reinforce, and a
    measured failure WEAKENS the lessons it was given instead. Without an outcome (a caller that does not
    measure one) the old behaviour stands, so nothing breaks for callers that predate this."""
    n = {"added": 0, "reinforced": 0, "revised": 0, "retired": 0, "rejected": 0, "weakened": 0}
    good = None if outcome is None else outcome.get("good")
    live = {r["id"] for r in load()}
    del LAST_REJECTS[:]
    turn_text = user_text = None
    if turn is not None:   # callers that pass the turn get grounding; older callers keep the old gate
        turn_text = _turn_text(turn, cap=10 ** 6)
        user_text = " ".join(str(m.get("content") or "") for m in turn if m.get("role") == "user")
    for a in (ops.get("add") or [])[:5]:
        if not isinstance(a, dict):
            continue
        kind = a.get("kind") if a.get("kind") in KINDS else "rule"
        if kind == "pref":
            # GreyNOC's prefs come only from his own typed corrections (capture_correction). The grounding check
            # read every user-role message as his, harness nudges included, and let an invented "End the turn
            # with NEXT:" pref through (audit 2026-10-22).
            n["rejected"] += 1
            LAST_REJECTS.append(f"{(a.get('text') or '')[:80]!r}: a reflection cannot create a preference; "
                                "only the user's own correction does")
            continue
        ok, why = worth_keeping(a.get("text", ""), a.get("why", ""), kind, "reflection")
        if ok and kind == "fact" and live_reading(a.get("text", "")):
            ok, why = False, ("a reading of the machine at one moment (a count, a state, 'currently'): it is read "
                              "again when asked, never remembered")
        if ok and turn_text is not None:
            ok, why = grounded(a.get("text", ""), kind, turn_text, user_text)
        if not ok:
            n["rejected"] += 1
            LAST_REJECTS.append(f"{(a.get('text') or '')[:80]!r}: {why}")
            continue
        prog = a.get("program") or "*"
        if prog not in ("*", program):  # a turn can only teach about its own program, or every program
            prog = program or "*"
        if kind == "fact" and program:  # a fact is true about one program; it never goes to every program
            prog = program
        if program and PROGRAM_BOUND.search(a.get("text", "")):  # a host, route or ledger id is this program's
            prog = program
        _, how = add(a.get("text", ""), a.get("why", ""), a.get("kind", "rule"), prog, "reflection")
        if how in n:
            n[how] += 1
        else:
            n["rejected"] += 1
            LAST_REJECTS.append(f"{(a.get('text') or '')[:80]!r}: {how}")
    if good is not False:   # a measured FAILURE cannot reinforce; untested (None) keeps the old behaviour
        for lid in (ops.get("reinforce") or [])[:10]:
            if isinstance(lid, str) and lid in live and reinforce(lid):
                n["reinforced"] += 1
    else:
        refused = [x for x in (ops.get("reinforce") or []) if isinstance(x, str)]
        n["rejected"] += len(refused)
        if refused:
            LAST_REJECTS.append(f"reinforce {', '.join(refused[:5])}: the turn measurably failed")
        for lid in given_ids:   # the lessons this failed turn was GIVEN lose strength; the weakest get retired
            if lid in live and weaken(lid):
                n["weakened"] += 1
    # GreyNOC's own lessons are his, not the model's: a reflection rewrote the "why" of his raw-Burp-panels rule into
    # "file-based evidence is sufficient to replace the proxy history requirement" (2026-10-22). Never again.
    protected = {r["id"] for r in load() if r.get("source") == "greynoc"}
    for key in ("revise", "retire"):
        for r in [x for x in (ops.get(key) or []) if isinstance(x, dict) and x.get("id") in protected]:
            n["rejected"] += 1
            LAST_REJECTS.append(f"{key} {r['id']}: the user's own lesson; only the user changes it")
        ops[key] = [x for x in (ops.get(key) or []) if not (isinstance(x, dict) and x.get("id") in protected)]
    for r in (ops.get("revise") or [])[:5]:
        if isinstance(r, dict) and r.get("id") in live and len(r.get("text") or "") >= 12 \
                and worth_keeping(r["text"], r.get("why", ""), "pref")[0]:
            if turn_text is not None:   # a rewrite is an add that destroys the old text: same grounding
                ok, why = grounded(r["text"], "rule", turn_text, user_text)
                if not ok:
                    n["rejected"] += 1
                    LAST_REJECTS.append(f"revise {r['id']} {(r.get('text') or '')[:60]!r}: {why}")
                    continue
            if revise(r["id"], r["text"], r.get("why", "")):
                n["revised"] += 1
    for r in (ops.get("retire") or [])[:5]:
        # only lessons the turn was actually shown can be retired by it
        if isinstance(r, dict) and r.get("id") in live and r.get("id") in given_ids \
                and retire(r["id"], "reflection: " + (r.get("reason") or "")[:200]):
            n["retired"] += 1
    return n


_TOOL_FAIL = re.compile(r"^\s*(refused|bad arguments|not run|unknown or unavailable tool|no such|error|"
                        r"failed|\S+ failed:|\S+ timed out|timed out|out_of_scope|blocked)", re.I)


def turn_outcome(msgs):
    """What actually happened in a turn, measured from its tool results - never asked of a model.

    {ok, failed, verdict, receipt, good}: `good` is the gate on reinforcement. A turn is good when at least
    one tool did real work and failures did not dominate; a recorded verdict or a milestone closed with a
    receipt makes it good on its own. A turn with no tool results has no measured outcome (good=None)."""
    ok = failed = 0
    verdict = receipt = False
    for m in msgs or []:
        if m.get("role") == "tool":
            txt = str(m.get("content") or "")
            if _TOOL_FAIL.search(txt):
                failed += 1
            else:
                ok += 1
        for c in m.get("tool_calls") or []:
            fn = (c.get("function") or {}) if isinstance(c, dict) else {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                with contextlib.suppress(ValueError):
                    args = json.loads(args)
            args = args if isinstance(args, dict) else {}
            if fn.get("name") == "record_outcome" and args.get("verdict"):
                verdict = True
            if fn.get("name") == "goal" and args.get("action") in ("milestone", "done") and \
                    (args.get("receipt") or args.get("artifact")):
                receipt = True
    if not ok and not failed:
        good = None
    else:
        good = bool(verdict or receipt or (ok >= 1 and failed <= ok))
    return {"ok": ok, "failed": failed, "verdict": verdict, "receipt": receipt, "good": good}


def outcome_text(o):
    """The measured outcome, as the reflecting model is shown it."""
    if o.get("good") is None:
        return "OUTCOME (measured by code): no tool ran this turn - nothing here was tested, so do not reinforce."
    bits = [f"{o['ok']} tool call(s) did real work, {o['failed']} failed or were refused"]
    if o.get("verdict"):
        bits.append("a hunt verdict was recorded")
    if o.get("receipt"):
        bits.append("a milestone was closed with a receipt")
    head = "this turn WORKED" if o["good"] else "this turn FAILED"
    return (f"OUTCOME (measured by code, not by you): {head}: " + "; ".join(bits) + ". "
            + ("Lessons that held up may be reinforced." if o["good"] else
               "Do NOT reinforce anything from a failed turn. A lesson that led here should be revised or retired."))


def _ground_key(o):
    return (str(o.get("target") or ""), re.sub(r"\s+", " ", str(o.get("vector") or "")).strip().lower()[:160])


def rebuild_ground(force=False):
    """The measured hunt history, one row per (program, vector), newest verdict wins. Built by code from the
    outcomes ledger - every row there was written by a lane that FIRED the probes - so recall can say "this
    vector is DEAD after 195 probes and a burst, refused by X" instead of a model's guess. Rebuilt only when the
    ledger is newer than the store. Returns the row count."""
    try:
        src = os.path.getmtime(OUTCOMES)
    except OSError:
        return 0
    with contextlib.suppress(OSError):
        if not force and os.path.getmtime(GROUND) >= src:
            with open(GROUND, encoding="utf-8") as f:
                return sum(1 for _ in f)
    rows = {}
    with open(OUTCOMES, encoding="utf-8", errors="replace") as f:
        for ln in f:
            try:
                o = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(o, dict) or not o.get("target") or not o.get("vector") or not o.get("verdict"):
                continue
            k = _ground_key(o)
            if k not in rows or str(o.get("ts") or "") >= str(rows[k].get("ts") or ""):
                rows[k] = o
    os.makedirs(DIR, exist_ok=True)
    tmp = GROUND + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for i, o in enumerate(sorted(rows.values(), key=lambda o: str(o.get("ts") or "")), 1):
            f.write(json.dumps({
                "id": f"G{i}", "program": o["target"], "ts": o.get("ts", ""), "verdict": str(o["verdict"]),
                "vector": str(o["vector"])[:300], "capability": str(o.get("capability") or "")[:300],
                "probes": o.get("probes"), "burst": bool(o.get("burst")), "floor": o.get("floor", ""),
                "artifact": str(o.get("artifact") or "")[:200], "notes": str(o.get("notes") or "")[:300]}) + "\n")
    os.replace(tmp, GROUND)
    return len(rows)


def recall_ground(query="", program=None, k=6):
    """The measured verdicts for THIS program most relevant to the request (newest first on a tie)."""
    if not program:
        return []
    with contextlib.suppress(OSError):
        rebuild_ground()
    rows = []
    with contextlib.suppress(OSError):
        with open(GROUND, encoding="utf-8", errors="replace") as f:
            for ln in f:
                with contextlib.suppress(ValueError):
                    r = json.loads(ln)
                    if isinstance(r, dict) and r.get("program") == program:
                        rows.append(r)
    q = _words(query)
    scored = [(len(q & _words(r["vector"] + " " + r["capability"] + " " + r["notes"])), r["ts"], r) for r in rows]
    scored.sort(key=lambda x: x[1], reverse=True)   # newest first ...
    scored.sort(key=lambda x: -x[0])                 # ... then by relevance (stable, so ties stay newest-first)
    hits = [r for s, _, r in scored if s][:k]
    if len(hits) < k:   # fill with the newest verdicts so a fresh turn on the program still sees its history
        seen = {r["id"] for r in hits}
        hits += [r for r in sorted(rows, key=lambda r: r["ts"], reverse=True) if r["id"] not in seen][:k - len(hits)]
    return hits


def ground_block(query="", program=None):
    rows = recall_ground(query, program)
    if not rows:
        return ""
    lines = []
    for r in rows:
        m = f"{r['probes']} probes" if r.get("probes") is not None else "probes n/a"
        m += ", burst" if r.get("burst") else ""
        lines.append(f"- [{r['id']} {r['verdict']} {r['ts'][:10]}, {m}] {r['vector'][:160]}"
                     + (f" -> {r['capability'][:160]}" if r.get("capability") else "")
                     + (f" ({r['artifact']})" if r.get("artifact") else ""))
    return (f"MEASURED HUNT HISTORY for {program} (from the outcomes ledger, written by lanes that fired the probes; "
            "do not re-fire a DEAD vector without a NEW angle, and read its artifact first):\n" + "\n".join(lines))


def trajectory_record(msgs, program, outcome):
    """The one trajectory shape, shared by log_trajectory and the headless batch runner (gnoc_trajectories), so
    `gnoc export trajectories` reads both without a second schema."""
    keep = []
    for m in msgs or []:
        if m.get("role") == "system":
            continue
        r = {"role": m.get("role"), "content": str(m.get("content") or "")[:4000]}
        if m.get("tool_calls"):
            r["tool_calls"] = m["tool_calls"]
        if m.get("tool_name"):
            r["tool_name"] = m["tool_name"]
        keep.append(r)
    return {"ts": _now(), "program": program, "outcome": outcome, "messages": keep}


def log_trajectory(msgs, program, outcome):
    """Every tool turn with its measured outcome, for a later fine-tune on what WORKED. Best effort: a full
    disk must never cost the user a turn."""
    if not outcome or outcome.get("good") is None:
        return
    with contextlib.suppress(OSError, TypeError, ValueError):
        rec = trajectory_record(msgs, program, outcome)
        os.makedirs(DIR, exist_ok=True)
        with _lock, open(TRAJ, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")


def reflect(llm, msgs, program=None, given=()):
    """One reflection pass. llm(messages) -> assistant text. Returns the counts applied."""
    given_txt = "\n".join(f"{r['id']} [{r['kind']}{' (the user)' if r.get('source') == 'greynoc' else ''}] "
                          f"{r['text']}" for r in given) or "(none)"
    outcome = turn_outcome(msgs)
    ask = [{"role": "system", "content": REFLECT_SYSTEM},
           {"role": "user", "content": f"PROGRAM: {program or '-'}\nLESSONS GIVEN TO THE AGENT:\n{given_txt}\n\n"
                                       f"{outcome_text(outcome)}\n\nTHE TURN:\n{_turn_text(msgs)}"}]
    out = llm(ask)
    ops = parse_ops(out)
    if not ops and not re.search(r"^\s*\{\s*\}\s*$", re.sub(r"<think>.*?</think>", "", out or "", flags=re.S)):
        # no parsable answer (prose, a fence, a cut-off): ask once for the bare object
        out = llm(ask + [{"role": "assistant", "content": (out or "")[:1500]},
                         {"role": "user", "content": "Return ONLY the JSON object now (or {} if nothing is worth "
                                                     "learning), no prose, no code fence."}])
        ops = parse_ops(out)
    log_trajectory(msgs, program, outcome)
    return apply_ops(ops, program, {r["id"] for r in given}, outcome=outcome, turn=msgs)


def summary(n):
    bits = [f"{v} {k}" for k, v in n.items() if v]
    return ", ".join(bits)


def listing(query="", limit=40):
    rows = load()
    if query:
        q = _words(query)
        rows = [r for r in rows if q & _words(r["text"] + " " + r.get("program", ""))] or \
               [r for r in rows if query.lower() in json.dumps(r).lower()]
    rows.sort(key=lambda r: (-_strength(r), r["id"]))
    return rows[:limit]


# ---------------------------------------------------------------- audit: re-judge the live book with today's gates

def _program_dirs():
    try:
        return sorted(p for p in os.listdir(os.path.join(WS, "targets"))
                      if not p.startswith(("_", ".")) and os.path.isdir(os.path.join(WS, "targets", p)))
    except OSError:
        return []


def owner_program(text, cache=None):
    """The program whose SCOPE.txt lists a host named in the text, else whose known-paths.txt lists a path in it."""
    cache = cache if cache is not None else {}
    hosts = {m.group(0).lower() for m in re.finditer(
        r"\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(com|net|org|io|dev|app|cloud|tech|co|ai|rest|xyz)\b", text or "", re.I)}
    paths = {m.lower() for m in _LESSON_PATH.findall(text or "")}
    for p in _program_dirs():
        if p not in cache:
            scope = known = ""
            with contextlib.suppress(OSError):
                with open(os.path.join(WS, "targets", p, "SCOPE.txt"), errors="replace") as fh:
                    scope = fh.read().lower()
            with contextlib.suppress(OSError):
                with open(os.path.join(WS, "targets", p, "hunts", "gnoc", "known-paths.txt"), errors="replace") as fh:
                    known = fh.read().lower()
            cache[p] = (scope, known)
        scope, known = cache[p]
        if any(h in scope for h in hosts) or any(("\n" + pth + "\n") in ("\n" + known + "\n") for pth in paths):
            return p
    return None


def route_index(program, cache=None):
    """path -> set(statuses) over every raw capture under targets/<program>/hunts/*/raw/. Built once per program."""
    cache = cache if cache is not None else {}
    if program in cache:
        return cache[program]
    idx = {}
    import glob
    for f in glob.glob(os.path.join(WS, "targets", program, "hunts", "*", "raw", "*.json")):
        try:
            with open(f) as fh:
                j = json.load(fh)
            url = str((j.get("request") or {}).get("url") or "")
            st = (j.get("response") or {}).get("status")
        except (OSError, ValueError, AttributeError):
            continue
        pth = re.sub(r"^https?://[^/]+", "", url).split("?", 1)[0].rstrip("/").lower()
        if pth and isinstance(st, int):
            idx.setdefault(pth, set()).add(st)
    cache[program] = idx
    return idx


def ghost_routes_on_disk(program, text, cache=None):
    """Paths the lesson names whose every capture for this program on disk is a refusal (>= 400)."""
    idx = route_index(program, cache)
    out = []
    for pth in {m.lower() for m in _LESSON_PATH.findall(text or "")}:
        codes = idx.get(pth) or idx.get(pth.rstrip("/"))
        if codes and min(codes) >= 400:
            out.append(pth)
    return out


def audit(apply=False, grep=None):
    """Re-judge every model-written lesson with today's gates: retire what worth_keeping refuses now, bind a "*"
    lesson that names a host or route to the program that owns it (retire it when none does), retire a program
    fact about a route that never once answered 2xx/3xx on disk, and (grep=) retire lessons matching a pattern
    the user names. The user's own lessons are never touched. Returns [(id, action, reason)]; apply=True does it."""
    rows = load()
    pat = re.compile(grep, re.I) if grep else None
    scope_cache, route_cache, actions = {}, {}, []
    for r in rows:
        if r.get("source") == "greynoc":
            continue
        text, prog, kind = r.get("text") or "", r.get("program", "*") or "*", r.get("kind", "rule")
        if pat and (pat.search(text) or pat.search(r.get("why") or "")):
            actions.append((r["id"], "retire", f"matches audit pattern {grep!r}"))
            continue
        ok, why = worth_keeping(text, r.get("why", ""), kind, r.get("source") or "model")
        if not ok:
            actions.append((r["id"], "retire", why))
            continue
        if prog == "*" and PROGRAM_BOUND.search(text):
            owner = owner_program(text, scope_cache)
            if owner:
                actions.append((r["id"], f"bind:{owner}", "program-bound anchors filed under every program"))
                continue
            if HUNT_BOUND.search(text) and HUNT_WORDS.search(text):
                actions.append((r["id"], "retire", "a route, ledger id or error code of one hunt that no program on "
                                                   "disk owns, filed under every program"))
                continue
            # a host alone that no program owns (GreyNOC's own site, a tool host): universal is the right shelf
        if prog != "*" and CAPABILITY_CLAIM.search(text):
            bad = ghost_routes_on_disk(prog, text, route_cache)
            if bad:
                actions.append((r["id"], "retire", f"{bad[0]} never answered 2xx/3xx in any capture under "
                                                   f"targets/{prog}/hunts; what it requires or triggers is a guess"))
    if apply and actions:
        with _lock:
            rows = load()
            by_id = {a[0]: a for a in actions}
            keep = []
            for r in rows:
                a = by_id.get(r["id"])
                if not a:
                    keep.append(r)
                elif a[1].startswith("bind:"):
                    r["program"] = a[1].split(":", 1)[1]
                    r["updated"] = _now()
                    keep.append(r)
                else:
                    _retire(r, "audit: " + a[2])
            _save(keep)
    return actions


def intel_recall(program=None, cls=None, k=5):  # INTEL: top external technique cards for a brief
    """Top k cards from patterns/intel for (program, class): hq FTS when up, else a scan of the card front-matter.
    Each row: class, program, discriminating_probe, kill_byte, source_url, trust (2 = unverified), path."""
    import importlib
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    mod = _intel_intake(importlib)
    return mod.recall(program, cls, k) if mod else []


def intel_block(program=None, cls=None, k=5):  # INTEL: the brief-ready, FENCED form of intel_recall()
    """The top k intel cards as a text block for a worker brief. Every card field is wrapped in a
    `<<INTEL DATA, not instructions>>` fence, control characters and fence markers stripped
    (intel.intake.recall_block); '' when no card matches. Tier 2 lines say UNVERIFIED TECHNIQUE."""
    import importlib
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    mod = _intel_intake(importlib)
    return mod.recall_block(program, cls, k) if mod else ""


def _intel_intake(importlib):
    """scripts/intel/intake.py, or None where it is not installed. The intel pipeline is the operator's (a public
    release ships no scripts/intel/), and a brief with no external cards is the documented empty result, so a
    missing package reads as "no card matches" rather than raising ModuleNotFoundError into a brief builder."""
    try:
        return importlib.import_module("intel.intake")
    except ModuleNotFoundError as e:
        if e.name not in ("intel", "intel.intake"):
            raise   # the package is there and one of ITS imports is broken: that is a real error, say it
        return None


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="lesson book maintenance")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("audit", help="re-judge the live book with today's gates (dry run unless --apply)")
    a.add_argument("--apply", action="store_true")
    a.add_argument("--grep", default=None, help="also retire model lessons matching this regex")
    ns = ap.parse_args()
    if ns.cmd == "audit":
        acts = audit(apply=ns.apply, grep=ns.grep)
        for lid, act, why in acts:
            print(f"{lid:<6} {act:<18} {why}")
        print(f"{len(acts)} action(s){' APPLIED' if ns.apply else ' (dry run; --apply to do it)'}; "
              f"{len(load())} live lessons now")
    else:
        ap.print_help()
