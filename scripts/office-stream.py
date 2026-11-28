#!/usr/bin/env python3
"""office-stream - the live gnoc-office, rendered headless in PUBLIC MODE, streamed as frames on 127.0.0.1.

The website's operator page (your-site.example /office, reached by typing "office" on the operator dashboard)
proxies GET /stream through its ops-token gate. This service binds loopback only and never sees the token.

What leaves this process (two layers, so one mistake cannot leak):
  1. gnoc-office runs with GNOC_OFFICE_PUBLIC=1: no gnoc chat, no orch.log text, no rail, every real-event text
     replaced by a generic phrase (see REDACT in gnoc-office.py).
  2. Every rendered row is scrubbed again here: any token shaped like a domain, file, path, URL, e-mail or IP,
     and any word matching a program handle under targets/ (or its brand stem), is overwritten with ▒. So is
     every secret (exact values from ~/.config/gnoc and the targets' ACCOUNTS.md, caught even as an 8-char
     fragment, plus key/JWT/password=/Bearer/hex/UUID/high-entropy shapes) and every name (the operator's
     identities, persona and mailbox names, dictionary-only proper nouns). See "secrets and names" below.

    office-stream.py [--port 8791] [--size 200x60]      serve (pm2: office-stream)
    office-stream.py --frame                            print one scrubbed frame as text, then exit (QA)
    office-stream.py --selftest                         every known program/target name must be blanked (QA)

GET /stream  text/event-stream. event "frame": {"w","h","full":bool,"rows":{"<y>": [[text, fg, bg, attr], ...]}}
             (256-colour indices; attr bits 1 bold, 2 dim, 4 italic, 8 underline, 16 reverse). A full frame
             first, then only the rows that changed, about 3 per second. Rendering pauses when nobody watches.
GET /healthz "ok"
"""
import importlib.machinery
import importlib.util
import glob
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ["GNOC_OFFICE_PUBLIC"] = "1"  # must be set before the office module is loaded
WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ld = importlib.machinery.SourceFileLoader("gnoc_office", os.path.join(WS, "scripts/gnoc-office.py"))
_sp = importlib.util.spec_from_loader("gnoc_office", _ld)
O = importlib.util.module_from_spec(_sp)
_ld.exec_module(O)
O.jsave = lambda *a, **k: None  # the web view never writes office state (mood, settings)

IDLE_PAUSE = 30  # seconds with no viewer before rendering pauses

# ---------- the scrubber (layer 2) ----------
GENERIC = {"bbp", "vdp", "bug", "bounty", "program", "public", "the", "and", "inc", "com", "app", "web", "api",
           "labs", "test", "demo", "security", "company", "group", "global", "online", "cloud", "network", "data",
           "hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "huntr", "core", "main", "team", "open",
           "brain", "desk", "office", "board", "feed", "lead", "leads", "report", "hunt", "work", "order", "result"}


try:
    _DICT = {w.strip().lower() for w in open("/usr/share/dict/words", errors="ignore")}
except OSError:
    _DICT = set()
try:  # ordinary lower-case English only (the full _DICT also lower-cases proper nouns: medicaid, bühler)
    _COMMON = {w.strip() for w in open("/usr/share/dict/words", errors="ignore") if w.strip().islower()}
except OSError:
    _COMMON = set()


def _generic_corpus():
    """Words used by the target-agnostic method docs (2k+ pattern cards, SPINE): technical vocabulary."""
    seen = set()
    for f in glob.glob(os.path.join(WS, "patterns", "**", "*.md"), recursive=True) + [os.path.join(WS, "SPINE.md")]:
        try:
            seen.update(w.lower() for w in re.findall(r"[A-Za-z]{5,}", open(f, errors="ignore").read(200000)))
        except OSError:
            pass
    return seen


_GENERIC_CORPUS = _generic_corpus()


def _vocab():
    """Program handles under targets/, their brand stems (program-64 -> meta), and the brand label of every scope
    host (the label before the public suffix), so a bare brand word in free text is blacked out too.
    Over-redacting an ordinary word is the safe failure; matching is substring and case-insensitive."""
    words = set()
    tdir = os.path.join(WS, "targets")
    for name in os.listdir(tdir) if os.path.isdir(tdir) else []:
        n = name.lower()
        if len(n) >= 3:
            words.add(n)
        for stem in re.split(r"[-_.]+", n):
            if len(stem) >= 3 and stem not in GENERIC and not stem.isdigit():  # 3-letter stems match whole-word only
                words.add(stem)
        try:
            scope = open(os.path.join(tdir, name, "SCOPE.txt"), errors="ignore").read().splitlines()
        except OSError:
            scope = []
        for ln in scope:
            tok = (ln.strip().split() or [""])[0].lower().lstrip("*.").split("/")[0]
            parts = [p for p in tok.split(".") if p]
            if len(parts) >= 2 and not tok.startswith("#"):
                label = parts[-3] if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac") else parts[-2]
                if len(label) >= 4 and label not in GENERIC and not label.isdigit():
                    words.add(label)
        # product names the brand does not spell (Gatewayco's "Konnect"): Capitalized words in the target's own notes
        # that are not dictionary words. All-caps acronyms (JWT, OAuth, SSRF) are deliberately not matched.
        for md in glob.glob(os.path.join(tdir, name, "*.md")):
            try:
                txt = open(md, errors="ignore").read(400000)
            except OSError:
                continue
            for wd in set(re.findall(r"\b[A-Z][a-z]{4,}\b", txt)):
                w_ = wd.lower()
                # a word the generic method docs also use is security vocabulary (callback, redirect), not a name
                if w_ not in _DICT and w_ not in GENERIC and w_ not in _GENERIC_CORPUS:
                    words.add(w_)
    words |= _program_words()
    return sorted(words, key=len, reverse=True)


def _office_ui_words():
    try:
        src = open(os.path.join(WS, "scripts/gnoc-office.py"), errors="ignore").read()
    except OSError:
        return set()
    return {w.lower() for w in re.findall(r"[A-Za-z]{3,}", src)}


def _program_names():
    """Every program or target name the hunt knows, from every source the office could ever print one from:
    the platform program lists (scripts/bbp-data), the rotation and park lists, the outcome, ship and rescue
    ledgers, the oss-bot jobs and the orch-bot state. Returns raw names (handles and display names)."""
    names = set()
    for f in glob.glob(os.path.join(WS, "scripts/bbp-data", "*.json")):
        try:
            data = json.load(open(f, errors="ignore"))
        except (OSError, ValueError):
            continue
        for row in data if isinstance(data, list) else []:
            if not isinstance(row, dict):
                continue
            for k in ("name", "handle", "company_handle", "slug", "program", "company"):
                if isinstance(row.get(k), str):
                    names.add(row[k])
            if isinstance(row.get("url"), str):
                names.update(p for p in row["url"].rstrip("/").split("/")[-2:] if p and "." not in p)
    hl = os.path.join(WS, ".claude/state/hunt-loop")
    for f in glob.glob(os.path.join(hl, "priority*.txt")) + [os.path.join(hl, "no-yield.txt")]:
        try:
            for ln in open(f, errors="ignore"):
                tok = ln.strip().split()[:1]
                if tok and not tok[0].startswith("#"):
                    names.add(tok[0].strip(",:|"))
        except OSError:
            pass
    # ships carry a real program field; outcome and brain rows also put free text ("attacker") in target
    for f, keys in ((os.path.join(hl, "ships.jsonl"), ("program",)),):
        try:
            for ln in open(f, errors="ignore"):
                try:
                    row = json.loads(ln)
                except ValueError:
                    continue
                for k in keys:
                    if isinstance(row.get(k), str):
                        names.add(row[k])
        except OSError:
            pass
    try:
        for iid, row in json.load(open(os.path.join(hl, "rescue-ledger.json"))).items():
            if isinstance(row, dict) and isinstance(row.get("program"), str):
                names.add(row["program"])
    except (OSError, ValueError):
        pass
    try:
        import sqlite3
        con = sqlite3.connect(f"file:{os.path.join(WS, '.claude/state/oss-bot/bot.db')}?mode=ro", uri=True, timeout=2)
        names.update(r[0] for r in con.execute("SELECT DISTINCT program FROM leads") if r[0])
        names.update(r[0] for r in con.execute("SELECT DISTINCT program FROM runs") if r[0])
        con.close()
    except Exception:
        pass
    return {n.strip() for n in names if isinstance(n, str) and 2 < len(n.strip()) < 80}


def _brand_words(name):
    """The words of one program name that identify it. A handle (program-64, program-19): every stem. A display
    name ("Medicare & Medicaid Services Bug Bounty"): the brand, which is the first word (plus the second when the
    first is an acronym or an ordinary word: "New Relic", "DPG Media"), and any word the dictionary does not know.
    Ordinary words further in ("Services", "Trading") are not names and are left readable."""
    n = name.lower().strip()
    stems = [w for w in re.split(r"[\W_]+", n) if w]  # \W is unicode-aware: Bühler, Wärtsilä stay whole
    display = " " in n
    brand_len = 2 if stems and (len(stems[0]) <= 3 or stems[0] in _COMMON) else 1
    out = set()
    for k, stem in enumerate(stems):
        if len(stem) < 3 or stem.isdigit() or stem in GENERIC or stem in PROGRAM_FILLER:
            continue
        if display and k >= brand_len and stem in _COMMON:
            continue
        out.add(stem)
    return out


def _program_words():
    """Program names -> vocabulary: the whole handle (program-64), its stems (meta), and the distinctive words of a
    display name ("Tiffany & Co Bug Bounty" -> tiffany). The office's own UI words are left out, so a program
    called after an office word cannot black out the furniture labels."""
    ui = _office_ui_words()
    words = set()
    for name in _program_names():
        n = name.lower()
        display = " " in n.strip()
        if not display and n not in GENERIC and n not in ui:
            words.add(n)
        words |= {w for w in _brand_words(n) if w not in ui}
    return words


# words that sit in program titles without naming anyone ("Vulnerability Disclosure Program", "Bug Bounty")
PROGRAM_FILLER = {"vulnerability", "disclosure", "program", "programme", "bounty", "bug", "bugs", "public", "private",
                  "responsible", "coordinated", "policy", "platform", "services", "service", "systems", "technologies",
                  "technology", "solutions", "international", "limited", "corp", "corporation", "holdings", "the", "and",
                  "for", "vdp", "bbp", "inc", "ltd", "llc", "gmbh", "plc", "company", "group", "official", "scope",
                  "web", "app", "apps", "mobile", "api", "data", "cloud", "network", "security", "bounties", "with",
                  "self", "hosted", "managed"}


# The office's own words that collided with the vocabulary (2026-10-22: "live" in the board header). Never a
# program handle; "threads" deliberately stays out of this list (it is also a scope brand).
OFFICE_WORDS = {"live", "home", "codes", "seek", "telemetry"}


# The words where that rule BITES: a program handle or brand stem that is also a word somewhere in
# gnoc-office.py's source, so `_program_words` leaves it out of the vocabulary and the public stream prints it
# in the clear. The exclusion is deliberate (a program named after a furniture label must not black out the
# label), but which names it costs us has to be a decision, not a side effect of a comment someone typed. The
# selftest fails on any collision NOT in this set, and the fix is one of three: reword the office source so it
# no longer spells the word (the usual answer - a loop variable called "ring" cost us a program, and a
# plural in a comment cost us Tools for Humanity), accept it by adding it here with a reason, or add the word
# to OFFICE_WORDS if the office genuinely needs to say it.
OFFICE_WORD_COLLISIONS = frozenset({
    # Pinned 2026-10-22. A few are not programs at all (a file in targets/, a word off a ledger row);
    # they are listed all the same, because what matters is that the set does not GROW unnoticed.
    "application", "best", "block", "blue", "box", "broken", "browser", "build", "chain", "clear", "cloudflare",
    "codes", "crypto", "curl", "department", "detail", "directly", "dot", "dust", "early", "energy",
    "escalation", "every", "files", "front", "general", "grab", "health", "here", "home", "identity", "inf",
    "ips", "just", "gatewayco", "link", "live", "meta", "mon", "move", "new", "node", "one", "people", "poll",
    "port", "product", "readme", "real", "recorded", "red", "room", "ruby", "seek", "selftest", "sky", "state",
    "telemetry", "third", "toast", "top", "trip", "trusted", "under", "version", "via", "water", "weave",
    "website", "who", "you",
})
_VOCAB = [w for w in _vocab() if w not in OFFICE_WORDS]


def _vocab_pattern(words):
    """3-letter words match only as whole words (the handle "ion" had blacked out "onion", "action", "decision");
    longer ones also match as the START of a word, so "acmehq" is caught by "gatewayco" but "janitor" is not by "nitor"."""
    short = [re.escape(w) for w in words if len(w) <= 3]
    long_ = [re.escape(w) for w in words if len(w) > 3]
    parts = []
    if long_:
        parts.append(r"(?<![A-Za-z0-9])(?i:" + "|".join(long_) + r")[\w-]*")
    if short:
        parts.append(r"(?<![A-Za-z0-9])(?i:" + "|".join(short) + r")(?![A-Za-z0-9])")
    return "|".join(parts)
_SENSITIVE = re.compile(
    r"[\w-]*[A-Za-z0-9][\w-]*(?:\.[\w-]*[A-Za-z0-9][\w-]*)+"  # anything dotted: domains, files, IPs, versions
    r"|\S*(?:[A-Za-z_]/[A-Za-z0-9_]|[A-Za-z0-9_]/[A-Za-z_])\S*"   # paths (a bare 9/11 or 5/5 is a count)
    r"|\S+@\S+"                                                  # e-mails, user@host
    r"|https?:\S*")
# the vocabulary is matched by set lookup, not one regex: ~2k alternatives made a row cost 6 ms
_VOCAB_LONG = {w for w in _VOCAB if len(w) > 3}
_VOCAB_SHORT = {w for w in _VOCAB if len(w) <= 3}
_VOCAB_LENS = sorted({len(w) for w in _VOCAB}, reverse=True)


def _vocab_spans(text):
    """Same rule as _vocab_pattern: a word of 4+ letters matches at the START of a word and blanks the whole
    word-character run after it ("acmehq" by "gatewayco"); a 3-letter word matches only as a whole word."""
    low, n = text.lower(), len(text)
    i = 0
    while i < n:
        if not text[i].isalnum() or (i and text[i - 1].isalnum()):
            i += 1
            continue
        end = None
        for L in _VOCAB_LENS:
            if i + L > n:
                continue
            frag = low[i:i + L]
            if L > 3 and frag in _VOCAB_LONG:
                end = i + L
                while end < n and (text[end].isalnum() or text[end] in "_-"):
                    end += 1
                break
            if L <= 3 and frag in _VOCAB_SHORT and (i + L == n or not text[i + L].isalnum()):
                end = i + L
                break
        if end:
            yield i, end
            i = end
        else:
            i += 1


# ---------- secrets and names (layer 2, continued) ----------
# Three more nets, each failing toward over-redaction:
#   KNOWN SECRETS  every value in the operator's secret files and every credential-looking value in a target's
#                  ACCOUNTS.md, matched by any 8-character run of it, so a value clipped by a bubble ("ab12cd34..")
#                  or wrapped across two board rows is still caught. Re-read every 5 minutes.
#   SECRET SHAPES  vendor key prefixes, JWTs, PEM headers, `password=`/`token:`/`Bearer` values, long hex,
#                  UUIDs, base32 seeds, phone numbers and any long mixed-case-and-digit blob.
#   NAMES          the operator's own identities and handles, persona and e-mail names from ACCOUNTS.md, and
#                  every Title-case word the dictionary knows only as a proper noun (the operator, Okta), unless the
#                  office itself uses it.
HOME = os.path.expanduser("~")
SECRET_GLOBS = [os.path.join(HOME, ".config/gnoc", p) for p in ("*.env", "*.token", "*.key", "*.json", "*/*.json")] + \
    [os.path.join(HOME, "Desktop/your-site.example/.env")]
OPERATOR_NAMES = {n for n in os.environ.get("GNOC_OPERATOR_NAMES", "").lower().split(",") if n}
_GRAM = 8
# The scrubber never holds a secret. Every value is reduced, inside _known_secrets(), to 16-byte HMAC-SHA256
# digests (per-process random key) of its 8-character windows and of the whole value; the plaintext is dropped
# before that function returns. Text is matched by hashing the same windows with the same key.
_KEY = os.urandom(32)
_MAC = hmac.new(_KEY, digestmod=hashlib.sha256)


def _dg(s):
    h = _MAC.copy()
    h.update(s.encode("utf-8", "replace"))
    return h.digest()[:16]


def _digest_value(v, sink):
    """Add the digests of the value and of its 8-character windows that could not be ordinary text (a digit, a
    symbol, or mixed case: a fragment of a value is caught, the word "password" inside one is not)."""
    if len(v) >= _GRAM:
        sink.add(_dg(v))
    for i in range(len(v) - _GRAM + 1):
        g = v[i:i + _GRAM]
        if " " in g:
            continue
        if re.search(r"[\d_+/=-]", g) or (re.search(r"[a-z]", g) and re.search(r"[A-Z]", g)):
            sink.add(_dg(g))


def _harvest_json(obj, out):  # out: a set of plaintext values local to _known_secrets
    if isinstance(obj, dict):
        for v in obj.values():
            _harvest_json(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _harvest_json(v, out)
    elif isinstance(obj, str) and len(obj) >= 10 and " " not in obj:
        out.add(obj)


def _known_secrets(globs=None, ws=None, name_ok=None):
    """(digests, extra names, hashed names) from the operator's secret files and the targets' ACCOUNTS.md.
    Plaintext secrets live only in this function's locals; callers get HMAC digests. Handle-like values from
    the secret files come back as digests of the lowercase name (a password can look like a handle)."""
    digests, names, hnames, vals = set(), set(), set(), set()
    for pat in (SECRET_GLOBS if globs is None else globs):
        for f in glob.glob(pat):
            try:
                txt = open(f, errors="ignore").read(2_000_000)
            except OSError:
                continue
            if f.endswith(".json"):
                try:
                    _harvest_json(json.loads(txt), vals)
                except ValueError:
                    pass
                continue
            for ln in txt.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                v = ln.split("=", 1)[1] if "=" in ln else ln
                v = v.strip().strip("'\"")
                if len(v) >= 6:
                    vals.add(v)
                    if re.fullmatch(r"[A-Za-z][\w.-]{2,30}", v) and not re.search(r"\d{4}", v):
                        if name_ok is None or name_ok(v.lower()):
                            hnames.add(_dg(v.lower()))  # a handle or username value (HACKERONE_HANDLE=...)
    for v in vals:
        _digest_value(v, digests)
    vals = set()  # ACCOUNTS.md credentials go through the same digest path
    for f in glob.glob(os.path.join(ws or WS, "targets", "*", "ACCOUNTS.md")):
        try:
            txt = open(f, errors="ignore").read(400000)
        except OSError:
            continue
        for m in re.finditer(r"(?i)(?:pass(?:word)?|pw|secret|token|api[_-]?key|cookie|seed|totp|otp|session)"
                             r"[\w ]{0,12}[\"'`]?\s*[:=|]\s*[\"'`]?([^\s\"'`|,]{6,})", txt):
            vals.add(m.group(1))
        for m in re.finditer(r"`([^`\s]{10,128})`", txt):  # backticked credential-shaped values
            v = m.group(1)
            if re.search(r"\d", v) and re.search(r"[A-Za-z]", v) and "/" not in v and "(" not in v:
                vals.add(v)
        for m in re.finditer(r"([\w.+-]+)@[\w-]+\.[\w.]+", txt):  # e-mail local parts: persona names
            for part in re.split(r"[.+_-]+", m.group(1)):
                p = part.lower()
                # an ordinary word as a mailbox name (account@, forum@) is not a person; a digit-run alias is
                if len(p) >= 4 and not p.isdigit() and p not in GENERIC and p not in _DICT and re.match(r"[a-z]+", p):
                    names.add(re.match(r"[a-z]+", p).group(0))
        for m in re.finditer(r"(?i)\b(?:first|last|full|display|nick|user)[ _-]?name\b\W{0,4}([A-Z][a-z]{2,})", txt):
            names.add(m.group(1).lower())
    for v in vals:
        _digest_value(v, digests)
    return digests, names, hnames


def _office_words():
    """Every word the office's own source spells, so its UI text (labels, phrases) is never taken for a name."""
    try:
        src = open(os.path.join(WS, "scripts/gnoc-office.py"), errors="ignore").read()
    except OSError:
        return set()
    return {w.lower() for w in re.findall(r"[A-Za-z]{3,}", src)}


def _proper_nouns():
    """Dictionary entries that exist ONLY capitalized: given names, surnames, brands, places."""
    try:
        words = [w.strip() for w in open("/usr/share/dict/words", errors="ignore")]
    except OSError:
        return set()
    lower = {w for w in words if w.islower()}
    keep = _office_words() - OPERATOR_NAMES
    return {w.lower() for w in words if w[:1].isupper() and w[1:].islower() and w.isalpha() and len(w) >= 3
            and w.lower() not in lower and w.lower() not in keep}


_SECRET_SHAPES = re.compile(
    r"-----BEGIN[^-]*-----"
    r"|\beyJ[\w-]{8,}(?:\.[\w-]*)*"                                            # JWT / JWS
    r"|\b(?:sk|pk|rk)[_-](?:live|test|proj|ant)?[_-]?[A-Za-z0-9_-]{8,}"         # Stripe, OpenAI, Anthropic
    r"|\b(?:ghp|gho|ghu|ghs|ghr|github_pat|glpat|xox[abprs]|hf|npm|shpat|shpss|pypi|dop_v1|SG)[_.-][\w.-]{10,}"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAIza[\w-]{30,}"
    r"|(?i:\b(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|cookie|session(?:id)?|authorization|auth"
    r"|client[_-]?secret|access[_-]?key|private[_-]?key|otp|totp|seed|signature|sig))[\"']?\s*[:=]\s*[\"']?[^\s\"',;]{3,}"
    r"|(?i:\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b)"  # UUIDs (object and account ids)
    r"|\b[0-9a-fA-F]{24,}\b"                                                   # hashes, hex keys
    r"|\b(?=[A-Z2-7]*\d)[A-Z2-7]{16,}\b"                                       # base32 TOTP seeds
    r"|\+\d[\d ().-]{7,}\d")                                                   # phone numbers
_BEARER = re.compile(r"(?i:\b(?:bearer|basic)\s+)\S{6,}")  # its own pass: "Authorization: Bearer x" overlaps
_BLOB = re.compile(r"[A-Za-z0-9_+/=-]{20,}")


class _Secrets:
    """Known secret values and names, refreshed from disk every 5 minutes (a new token file is picked up live)."""
    def __init__(self):
        self.at, self.grams, self.names = 0.0, set(), set(OPERATOR_NAMES)  # grams: HMAC digests, never plaintext
        self.hnames = set()  # HMAC digests of handle-like values from the secret files
        self.globs, self.ws = None, None  # None = SECRET_GLOBS / WS (tests point these at a temp dir)
        self.proper = _proper_nouns()
        self.ui = (_office_words() | OFFICE_WORDS) - OPERATOR_NAMES  # the office's own vocabulary is never a name

    def _name_ok(self, n):
        return len(n) >= 4 and n not in self.ui and n not in GENERIC and n not in _DICT

    def fresh(self, force=False):
        if force or time.time() - self.at > 300:
            self.grams, names, self.hnames = _known_secrets(self.globs, self.ws, self._name_ok)
            self.names = set(OPERATOR_NAMES) | {n for n in names if self._name_ok(n)}
            self.at = time.time()
            _ROW_CACHE.clear()  # a new secret must reach rows that were already scrubbed
        return self


_ROW_CACHE = {}  # row digest -> indexes to blank; most rows are unchanged frame to frame
SECRETS = _Secrets()


def scrub_row(chars):
    """chars: list of 1-cell strings. Returns the indexes to blank."""
    text = "".join(chars)
    s = SECRETS.fresh()
    key = _dg(text)  # keyed by digest: a row that carried a secret must not be kept as plaintext
    hit = _ROW_CACHE.get(key)
    if hit is not None:
        return hit
    if len(_ROW_CACHE) > 4000:
        _ROW_CACHE.clear()
    out = _ROW_CACHE[key] = []
    for m in _SENSITIVE.finditer(text):
        out.extend(range(m.start(), m.end()))
    for a, b in _vocab_spans(text):
        out.extend(range(a, b))
    for rx in (_SECRET_SHAPES, _BEARER):
        for m in rx.finditer(text):
            out.extend(range(m.start(), m.end()))
    for m in _BLOB.finditer(text):  # a long token with mixed case and a digit is a credential, not a word
        b = m.group(0)
        if re.search(r"\d", b) and re.search(r"[a-z]", b) and re.search(r"[A-Z]", b):
            out.extend(range(m.start(), m.end()))
    grams = s.grams
    for i in range(len(text) - _GRAM + 1):
        g = text[i:i + _GRAM]
        if " " not in g and _dg(g) in grams:  # stored windows never hold a space
            out.extend(range(i, i + _GRAM))
    for m in re.finditer(r"\S{%d,}" % _GRAM, text):  # a whole token equal to a whole secret value
        if _dg(m.group(0)) in grams:
            out.extend(range(m.start(), m.end()))
    for m in re.finditer(r"[A-Za-z][\w'-]*", text):
        w = m.group(0).lower()
        if w in s.names or (s.hnames and _dg(w) in s.hnames) or any(w.startswith(n) for n in OPERATOR_NAMES):
            out.extend(range(m.start(), m.end()))
        elif m.group(0)[:1].isupper() and w.split("'")[0] in s.proper:
            out.extend(range(m.start(), m.end()))
    return out


# ---------- rendering ----------
class Renderer:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.feed = O.Feed()
        self.feed.prime()
        self.feed.start()
        self.app = O.App(self.feed)
        self.rows = []      # list of row-run lists
        self.version = 0
        self.cond = threading.Condition()
        self.viewers = 0
        self.last_viewer = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def encode(self, cv):
        rows = []
        for y in range(cv.h):
            ch, fg, bg, at = list(cv.ch[y]), cv.fg[y], cv.bg[y], cv.at[y]
            for x in scrub_row(ch):
                if ch[x] != " ":
                    ch[x] = "▒"
            fg = [240 if ch[x] == "▒" else fg[x] for x in range(cv.w)]
            runs, cur = [], None
            for x in range(cv.w):
                key = [fg[x], bg[x], at[x]]
                if cur and cur[1:] == key:
                    cur[0] += ch[x]
                else:
                    cur = [ch[x], *key]
                    runs.append(cur)
            rows.append(runs)
        return rows

    def render(self):
        return self.encode(O.compose(self.app, self.w, self.h))

    def loop(self):
        """The office simulates at its own 10 fps (walking speed and timers are per frame); every 3rd frame is
        scrubbed, encoded and published (~3.3 per second). All of it pauses when nobody has watched for a while."""
        n = 0
        while True:
            t0 = time.time()
            if self.viewers or time.time() - self.last_viewer < IDLE_PAUSE or not self.rows:
                try:
                    cv = O.compose(self.app, self.w, self.h)
                    if n % 3 == 0 or not self.rows:
                        rows = self.encode(cv)
                        with self.cond:
                            self.rows, self.version = rows, self.version + 1
                            self.cond.notify_all()
                    n += 1
                except Exception as e:  # never die on a bad frame; the office recovers on the next poll
                    sys.stderr.write(f"render error: {e}\n")
                    time.sleep(1)
            time.sleep(max(0.0, 1 / O.FPS - (time.time() - t0)))


R = None


# DNS-rebinding guard: a page in a local browser can point its own hostname at
# 127.0.0.1 and then talk to this port as "same origin". Every real caller names
# the loopback address, so a request for any other Host is refused before it is
# read.
LOOPBACK_HOSTNAMES = {"127.0.0.1", "localhost", "[::1]"}


def host_is_loopback(host):
    host = (host or "").strip().lower()
    name = host if host.endswith("]") else host.rsplit(":", 1)[0]
    return name in LOOPBACK_HOSTNAMES


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if not host_is_loopback(self.headers.get("Host")):
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if self.path != "/stream":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        with R.cond:
            R.viewers += 1
        sent, ver, last_beat = None, -1, time.time()
        try:
            while True:
                with R.cond:
                    R.cond.wait_for(lambda: R.version != ver, timeout=15)
                    rows, ver = R.rows, R.version
                if rows and rows is not sent:
                    if sent is None or len(sent) != len(rows):
                        payload = {"w": R.w, "h": R.h, "full": True, "rows": {str(i): r for i, r in enumerate(rows)}}
                    else:
                        payload = {"w": R.w, "h": R.h, "full": False,
                                   "rows": {str(i): r for i, r in enumerate(rows) if r != sent[i]}}
                    if payload["full"] or payload["rows"]:
                        self.wfile.write(b"event: frame\ndata: " + json.dumps(payload, separators=(",", ":"),
                                                                            ensure_ascii=False).encode() + b"\n\n")
                        self.wfile.flush()
                    sent = rows
                if time.time() - last_beat > 15:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    last_beat = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with R.cond:
                R.viewers -= 1
                R.last_viewer = time.time()


def selftest():
    """Every program and target name the hunt knows, in the sentence shapes the office prints, must come out
    fully blanked; the office's own UI lines must come out untouched. Exit 1 on any leak."""
    def scrubbed(t):
        idx = set(scrub_row(list(t)))
        return "".join("▒" if i in idx and c != " " else c for i, c in enumerate(t))
    names = _program_names() | set(os.listdir(os.path.join(WS, "targets")))
    shapes = ["work order: auto {}", "LAST {} 1 host 24 fired", "thinking... escalate {} (3m)",
              "LEAD: {} unauth reach", "{} picked up {}/some-lead: rung 2", "the bot should hunt {} next"]
    leaks = []
    for n in sorted(names):
        for sh in shapes:
            line = sh.format(n, n)
            out = scrubbed(line)
            # a leak = any distinctive word of the name (4+ letters, not filler) still readable in the output
            must = _brand_words(n)
            for wd in re.findall(r"[^\W_]{4,}", n):
                w = wd.lower()
                if w not in must or w in GENERIC or w in PROGRAM_FILLER or w in OFFICE_WORDS or w in _office_ui_words():
                    continue
                if re.search(r"(?i)(?<![^\W_])" + re.escape(wd) + r"(?![^\W_])", out):
                    leaks.append((n, line, out))
                    break
    ui = ["TODAY ships 0  probes 41  leads 83", "COFFEE FRIDGE  COOLER  PRINTER  LEAD TRIAGE  FILES",
          "GPU DESK -> BRAIN: swept host: fired 42, hits 0, leads 0", "BOSS IN 8m43s  Thu 15:46:32 EDT",
          "auto-target: priority lists exhausted - ranking fresh candidates (paid-rotation fallback)",
          "LAB exposure-hunter picked up a parked lead: rung 2 what it unlocks",
          "GNOC CHAT  WEBSITE  PROCESSES  WAR ROOM  ORCH LOG  SERVER ROOM  RESCUE BOARD  STANDUP  REPORTS",
          "analyst + models   public site   unattended   LAB BENCH   drafted   your call   FILED"]
    broken = [(u, scrubbed(u)) for u in ui if scrubbed(u) != u]
    # ...and the quiet one the shapes above cannot catch, because the leak check excludes office words by the
    # same rule the vocabulary does: a program whose name the office source happens to spell is never redacted
    # at all. See OFFICE_WORD_COLLISIONS.
    office_ui = _office_ui_words()
    collide = set()
    for name in names:
        n = name.lower()
        if " " not in n.strip() and n not in GENERIC and n in office_ui:
            collide.add(n)
        collide |= {w for w in _brand_words(n) if w in office_ui}
    fresh = sorted(collide - OFFICE_WORD_COLLISIONS)
    for n, line, out in leaks[:40]:
        print(f"LEAK  {n!r}: {out}")
    for u, out in broken:
        print(f"UI    {out}")
    for w in fresh:
        print(f"CLEAR {w!r}: gnoc-office.py spells this word, so this program name is never blacked out. "
              f"Reword the office source, or accept it in OFFICE_WORD_COLLISIONS.")
    print(f"{len(names)} program/target names x {len(shapes)} shapes: {len(leaks)} leaks; "
          f"{len(ui)} UI lines: {len(broken)} damaged; "
          f"{len(collide)} office-word collisions, {len(fresh)} of them new")
    return 1 if leaks or broken or fresh else 0


def main(argv):
    global R
    if "--selftest" in argv:
        return selftest()
    w, h = 200, 60
    if "--size" in argv:
        w, h = (int(v) for v in argv[argv.index("--size") + 1].lower().split("x"))
    if "--frame" in argv:
        R = Renderer(w, h)
        time.sleep(3)
        for runs in R.render():
            print("".join(r[0] for r in runs))
        return 0
    port = int(argv[argv.index("--port") + 1]) if "--port" in argv else int(os.environ.get("OFFICE_STREAM_PORT", 8791))
    R = Renderer(w, h)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)  # loopback only: the website proxies it behind the ops token
    srv.daemon_threads = True
    print(f"office-stream on 127.0.0.1:{port} ({w}x{h}, public mode)", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
