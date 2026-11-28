#!/usr/bin/env python3
"""slop-gate.py - pre-send verification gate for a bug bounty report draft.

Every check in this file is a defect that actually happened in our own work, not a
hypothetical. The doctrine and the story behind each rule is in
reports/EVIDENCE-INTEGRITY.md. Checks 1-10 are HARD (non-zero exit on failure),
11-12 are ADVISORY (reported, never fatal).

usage:
  slop-gate.py <draft.md> [--evidence DIR ...] [--attachments DIR] [--program NAME] [--json]
  slop-gate.py --selfcheck [--json]
"""
import argparse
import hashlib
import json
import os
import re
import sys

WS = re.compile(r"\s+")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def norm(s):
    return WS.sub(" ", s).strip()


# ---------------------------------------------------------------- result model
class Result:
    def __init__(self):
        self.checks = []

    def add(self, num, name, hard, passed, detail=None, note=None):
        self.checks.append({
            "check": num, "name": name, "hard": hard,
            "status": ("PASS" if passed else ("FAIL" if hard else "WARN")),
            "detail": detail or [], "note": note,
        })

    @property
    def failed(self):
        return [c for c in self.checks if c["hard"] and c["status"] == "FAIL"]

    def render(self, out=sys.stdout):
        for c in self.checks:
            tag = "HARD " if c["hard"] else "ADV  "
            print("%s%-2s %-26s %s" % (tag, c["check"], c["name"], c["status"]), file=out)
            if c["note"]:
                print("        %s" % c["note"], file=out)
            for d in c["detail"][:40]:
                print("        %s" % d, file=out)
            if len(c["detail"]) > 40:
                print("        ... %d more" % (len(c["detail"]) - 40), file=out)


# ---------------------------------------------------------------- corpus loader
TEXT_EXT_SKIP = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tgz",
                 ".webp", ".har.gz", ".ico", ".woff", ".woff2"}


def read_text(path, cap=12 * 1024 * 1024):
    try:
        with open(path, "rb") as fh:
            b = fh.read(cap)
    except OSError:
        return None
    if b"\0" in b[:8192]:
        return None
    return b.decode("utf-8", "replace")


class Corpus:
    """Every byte we can prove we captured, in three views.

    raw      - whitespace-normalised file contents plus relative paths
    unesc    - the same with JSON string escaping undone, because a wire capture
               stores a response body as an escaped JSON string and the draft
               quotes it unescaped
    files    - path -> text, for per-attachment citation resolution
    """

    def __init__(self, dirs):
        self.dirs = [d for d in dirs if d]
        self.files = {}
        chunks = []
        for d in self.dirs:
            if os.path.isfile(d):
                walk = [(os.path.dirname(d), [], [os.path.basename(d)])]
            else:
                walk = os.walk(d)
            for r, _, fs in walk:
                for f in sorted(fs):
                    p = os.path.join(r, f)
                    rel = os.path.relpath(p, d) if os.path.isdir(d) else f
                    chunks.append(rel)
                    chunks.append(f)
                    if os.path.splitext(f)[1].lower() in TEXT_EXT_SKIP:
                        continue
                    t = read_text(p)
                    if t is None:
                        continue
                    self.files[p] = t
                    chunks.append(t)
        self.raw = norm("\n".join(chunks))
        unesc = self.raw.replace('\\"', '"').replace("\\/", "/").replace("\\n", " ")
        self.unesc = norm(unesc)

    def has(self, s):
        n = norm(s)
        if len(n) < 3:
            return True
        return n in self.raw or n in self.unesc

    def count(self, s):
        n = norm(s)
        return self.raw.count(n) + self.unesc.count(n)


# ---------------------------------------------------------------- draft parsing
class Draft:
    def __init__(self, path):
        self.path = path
        self.text = read_text(path) or ""
        self.lines = self.text.split("\n")
        self.blocks = []          # (start_line_1based, [lines])
        self.in_block = set()     # 1-based line numbers inside a fence
        fence = None
        cur = []
        start = 0
        for i, ln in enumerate(self.lines, 1):
            if re.match(r"^\s*```", ln):
                if fence is None:
                    fence = i
                    cur = []
                    start = i + 1
                else:
                    self.blocks.append((start, cur))
                    fence = None
                continue
            if fence is not None:
                cur.append((i, ln))
                self.in_block.add(i)
        if fence is not None and cur:
            self.blocks.append((start, cur))
        self.sections = self._sections()
        self.steps = self._steps()

    def _sections(self):
        out = {}
        name = "_preamble"
        buf = []
        for i, ln in enumerate(self.lines, 1):
            m = re.match(r"^#{1,6}\s*(.+?)\s*$", ln)
            if m and i not in self.in_block:
                out.setdefault(name, []).extend(buf)
                buf = []
                name = m.group(1)
            else:
                buf.append((i, ln))
        out.setdefault(name, []).extend(buf)
        return out

    def _steps(self):
        """Ordered PoC steps. Accepts 'Step N.' headings and plain numbered lists."""
        marks = []
        for i, ln in enumerate(self.lines, 1):
            if i in self.in_block:
                continue
            m = re.match(r"^\s*(?:#+\s*)?[Ss]tep\s+(\d+)[.:)]", ln)
            if not m:
                m = re.match(r"^\s*(\d{1,2})[.)]\s+\S", ln)
            if m:
                marks.append((i, int(m.group(1))))
        steps = []
        for k, (ln, num) in enumerate(marks):
            end = marks[k + 1][0] - 1 if k + 1 < len(marks) else len(self.lines)
            body = "\n".join(self.lines[ln - 1:end])
            steps.append({"num": num, "line": ln, "end": end, "text": body})
        return steps

    def section_text(self, *names):
        out = []
        for n in names:
            for key, body in self.sections.items():
                if key.lower().startswith(n.lower()):
                    out.extend(body)
        return out

    def sentences(self, pairs=None):
        """[(line_no, sentence)] over prose (fenced blocks excluded)."""
        pairs = pairs if pairs is not None else list(enumerate(self.lines, 1))
        out = []
        for i, ln in pairs:
            if i in self.in_block:
                continue
            for s in re.split(r"(?<=[.!?])\s+", ln.strip()):
                if s:
                    out.append((i, s))
        return out


# ---------------------------------------------------------------- shared regexes
RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_UUIDH = re.compile(r"\b[0-9a-f]{20,40}\b")
RE_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
RE_B64 = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-+/=.]{24,}")
RE_JSONKEY = re.compile(r'"[A-Za-z_][\w.\-]*"\s*:')
RE_HDR = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,30}:\s+\S")
RE_REQLINE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S{4,}")
RE_STATUSLINE = re.compile(r"^HTTP/\d")
RE_URLQ = re.compile(r"https?://[^\s\"'<>]+\?[^\s\"'<>]+")
RE_BACKTICK = re.compile(r"`([^`]+)`")
RE_ADDRID = re.compile(r"[A-Za-z0-9 %+]{4,60}\s*(?:\||%7C|%7c)\s*[0-9a-f]{20,32}")
RE_TS = re.compile(r"\b(\d{2}:\d{2}:\d{2}Z?|\d{4}-\d{2}-\d{2}T[\d:]+Z?)\b")
RE_REPORTID = re.compile(r"(YWH-PGM\d+-\d+|#\d{6,}|H1-\d+)")
ELISION = re.compile(r"\[[^\]]*?(?:ELIDED|TRUNCATED|elided|truncated|omitted|left out|"
                     r"redacted|REDACTED|snip|SNIP|remaining|rest of|other)[^\]]*?\]")
BRACKETED = re.compile(r"\[[^\]]+\]")   # non-empty only: a JSON empty array [] is a captured byte, not an editorial note


def b64ish(tok):
    """A token that looks like a captured opaque value, not an English word."""
    if len(tok) < 25:
        return False
    if not re.search(r"\d", tok):
        return False
    if not (re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok)):
        return not re.fullmatch(r"[a-z0-9._\-/]+", tok) is None and len(tok) >= 25
    return True


# ---------------------------------------------------------------- 1 provenance
def _prov_one(stripped, ln, corpus, tested, bad):
    """Test one candidate segment for byte provenance."""
    if (RE_JSONKEY.search(stripped) or RE_HDR.match(stripped)
            or RE_REQLINE.match(stripped) or RE_STATUSLINE.match(stripped)
            or RE_URLQ.search(stripped)):
        if len(norm(stripped)) >= 25:
            tested += 1
            if not corpus.has(stripped):
                bad.append("line %d  block-line not in evidence: %s" % (ln, norm(stripped)[:110]))
            return tested, bad
    for tok in set(RE_EMAIL.findall(stripped)) | set(RE_UUID.findall(stripped)) \
            | set(RE_UUIDH.findall(stripped)) | {t for t in RE_B64.findall(stripped) if b64ish(t)}:
        tested += 1
        if not corpus.has(tok):
            bad.append("line %d  token not in evidence: %s" % (ln, tok[:110]))
    return tested, bad


def check_provenance(draft, corpus, res):
    if not corpus.dirs:
        res.add(1, "byte provenance", True, True, note="SKIPPED, no --evidence given")
        return
    bad = []
    tested = 0
    for start, body in draft.blocks:
        for ln, raw in body:
            line = raw.rstrip()
            if not line.strip():
                continue
            stripped = BRACKETED.sub(" ", line).strip()
            if len(stripped) < 4:
                continue      # the line was entirely an editorial note
            # an arrow line is our own shorthand annotation, not a quoted capture:
            # test each side of the arrow on its own merits, never the composite
            for seg in (re.split(r"\s*(?:->|=>)\s*", stripped)
                        if re.search(r"\s(?:->|=>)\s", stripped) else [stripped]):
                tested, bad = _prov_one(seg, ln, corpus, tested, bad)
            continue
    for i, ln in enumerate(draft.lines, 1):
        if i in draft.in_block:
            continue
        for s in RE_BACKTICK.findall(ln):
            if len(s) <= 24:
                continue
            s2 = BRACKETED.sub(" ", s).strip()
            if RE_JSONKEY.search(s2) or RE_HDR.match(s2) or RE_URLQ.search(s2) or RE_STATUSLINE.match(s2):
                tested += 1
                if not corpus.has(s2):
                    bad.append("line %d  backticked capture not in evidence: %s" % (i, norm(s2)[:110]))
                continue
            for tok in set(RE_EMAIL.findall(s2)) | set(RE_UUID.findall(s2)) | set(RE_UUIDH.findall(s2)) \
                    | {t for t in RE_B64.findall(s2) if b64ish(t)}:
                tested += 1
                if not corpus.has(tok):
                    bad.append("line %d  backticked token not in evidence: %s" % (i, tok[:110]))
    res.add(1, "byte provenance", True, not bad, sorted(set(bad)),
            note="%d quoted strings tested against %d evidence files" % (tested, len(corpus.files)))


# ---------------------------------------------------------------- 2 truncation
def check_truncation(draft, res):
    bad = []
    for start, body in draft.blocks:
        parity = 0
        parities = []
        for ln, raw in body:
            q = len(re.findall(r'(?<!\\)"', raw))
            parity = (parity + q) % 2
            parities.append((ln, raw, parity))
            t = raw.rstrip()
            trailing = t.endswith("...") or t.endswith("…") or re.search(r"=\s*\.\.\.$", t)
            if trailing and not marked(body, ln):
                bad.append("line %d  trailing elision with no marker: %s" % (ln, norm(t)[-90:]))
        if parities and parities[-1][2] == 1:
            ln, raw, _ = parities[-1]
            if not marked(body, ln):
                bad.append("line %d  block ends inside an unterminated string: %s" % (ln, norm(raw)[-90:]))
        txt = "\n".join(r for _, r in body)
        for op, cl, what in (("{", "}", "brace"), ("[", "]", "bracket")):
            if txt.count(op) > txt.count(cl):
                last = body[-1][0]
                if not marked(body, last):
                    bad.append("line %d  block ends with an unclosed %s (%d open, %d closed)"
                               % (last, what, txt.count(op), txt.count(cl)))
    res.add(2, "unmarked truncation", True, not bad, bad)


def marked(body, ln):
    """An elision marker on this line or either neighbour excuses the cut."""
    for n, raw in body:
        if abs(n - ln) <= 1 and ELISION.search(raw):
            return True
    return False


# ---------------------------------------------------------------- 3 citations
def check_citations(draft, attach_dir, corpus, res):
    files = {}
    if attach_dir and os.path.isdir(attach_dir):
        for r, _, fs in os.walk(attach_dir):
            for f in fs:
                p = os.path.join(r, f)
                t = read_text(p)
                if t is not None:
                    files[f] = t
    files.update({os.path.basename(p): t for p, t in corpus.files.items()})
    if not files:
        res.add(3, "citation resolution", True, True, note="SKIPPED, no attachment or evidence text")
        return
    bad = []
    n = 0
    for i, ln in enumerate(draft.lines, 1):
        named = named_attachments(ln, files)
        if not named:
            continue
        cites = set(RE_TS.findall(ln)) | {"line " + m for m in re.findall(r"\bline\s+(\d+)\b", ln)}
        for c in cites:
            n += 1
            tgt = c[5:] if c.startswith("line ") else c
            if c.startswith("line "):
                ok = any(len(t.split("\n")) >= int(tgt) for f, t in named)
            else:
                ok = any(tgt.rstrip("Z") in t for f, t in named)
            if not ok:
                bad.append("line %d  %s not found in %s" % (i, c, ", ".join(f for f, _ in named)))
    res.add(3, "citation resolution", True, not bad, bad,
            note="%d citations resolved against named attachments" % n)


def named_attachments(line, files):
    """Resolve 'attachment 04', 'A11', or a literal filename to real files."""
    out = []
    for f in files:
        if f in line:
            out.append((f, files[f]))
    for m in re.finditer(r"\battachment[s]?\s+(\d{1,2})\b", line, re.I):
        k = m.group(1).zfill(2)
        for f in files:
            if re.match(r"^%s[-_.]" % k, f):
                out.append((f, files[f]))
    for m in re.finditer(r"\b(A\d{2})\b", line):
        for f in files:
            if f.startswith(m.group(1) + "-"):
                out.append((f, files[f]))
    seen = set()
    uniq = []
    for f, t in out:
        if f not in seen:
            seen.add(f)
            uniq.append((f, t))
    return uniq


# ---------------------------------------------------------------- 4 manifest
def check_manifest(draft, attach_dir, res):
    if not attach_dir:
        res.add(4, "manifest symmetry", True, True, note="SKIPPED, no --attachments given")
        return
    if not os.path.isdir(attach_dir):
        res.add(4, "manifest symmetry", True, False, ["attachments dir missing: %s" % attach_dir])
        return
    ondisk = []
    for r, _, fs in os.walk(attach_dir):
        for f in fs:
            ondisk.append(os.path.relpath(os.path.join(r, f), attach_dir))
    text = draft.text
    missing_from_draft = []
    for rel in sorted(ondisk):
        base = os.path.basename(rel)
        if base in text or rel in text:
            continue
        m = re.match(r"^(A\d{2})-", base)
        if m and re.search(r"\b%s\b" % m.group(1), text):
            continue
        m = re.match(r"^(\d{2})[-_.]", base)
        if m and re.search(r"\battachment[s]?\s+0*%d\b" % int(m.group(1)), text, re.I):
            continue
        missing_from_draft.append(rel)
    named = set()
    for m in re.finditer(r"\b[\w-]+(?:[./][\w-]+)*\.(?:md|png|jpg|jpeg|log|txt|sh|py|json|html|pdf|har|zip)(?![\w.])", text):
        named.add(os.path.basename(m.group(0)))
    missing_on_disk = sorted(n for n in named if n not in {os.path.basename(x) for x in ondisk})
    bad = (["named in draft but not on disk: %s" % x for x in missing_on_disk]
           + ["on disk but never named in draft: %s" % x for x in missing_from_draft])
    res.add(4, "manifest symmetry", True, not bad, bad,
            note="%d files on disk (directory walk, no manifest read)" % len(ondisk))


# ---------------------------------------------------------------- 5 duplicates
IMG = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


def check_dupes(attach_dir, res):
    if not attach_dir or not os.path.isdir(attach_dir):
        res.add(5, "duplicate evidence", True, True, note="SKIPPED, no --attachments given")
        return
    by = {}
    n = 0
    for r, _, fs in os.walk(attach_dir):
        for f in fs:
            if os.path.splitext(f)[1].lower() not in IMG:
                continue
            p = os.path.join(r, f)
            h = hashlib.sha256(open(p, "rb").read()).hexdigest()
            by.setdefault(h, []).append(os.path.relpath(p, attach_dir))
            n += 1
    bad = ["sha256 %s shared by: %s" % (h[:16], ", ".join(v)) for h, v in by.items() if len(v) > 1]
    res.add(5, "duplicate evidence", True, not bad, bad,
            note="%d images, %d distinct sha256" % (n, len(by)))


# ---------------------------------------------------------------- 6 one-shot poc
MUTATE = [
    (r"\bclean(?:ed|ing)?\s*up\b|\bcleanup\b", "cleanup"),
    (r"\brevert(?:ed|ing)?\b|\bI reverted\b", "reverted"),
    (r"\brestor(?:ed|ing)\b", "restored"),
    (r"\bdelet(?:e|es|ed|ing)\b", "deleted"),
    (r"\bempti(?:ed)\b|\bemptied\b", "emptied"),
    (r"\bset\s+(?:it\s+)?private\b", "set private"),
    (r"publicList\s*=\s*false|publicList\"?\s*:\s*false", "publicList=false"),
    (r"\brevok(?:ed|ing)\b", "revoked"),
    (r"\bdisabl(?:ed|ing)\b", "disabled"),
    (r"\bchanged the email\b|\bemail change\b|\bmoved the (?:login )?email\b", "changed the email"),
    (r"\bput theirs back\b|\bput it back\b|\bleft as found\b", "restored"),
]
PROVISION = re.compile(
    r"\bregister\b|\bregistered\b|\bregistration\b|\bsign(?:ed)?\s*up\b|\bsignup\b|"
    r"\bcreate[sd]?\b|\bcreating\b|\bprovision(?:ed|ing)?\b|\bmint(?:ed|s)?\b|"
    r"\bAccount-SubmitRegistration\b|\bnew account\b|\badd an address\b|\bI made (?:it|one)\b", re.I)
PRECOND = re.compile(
    r"\bhas no\b|\bhave no\b|\bno identity\b|\bno provider identity\b|\bdoes not exist\b|"
    r"\bdoesn't know\b|\bdoes not know\b|\bnot yet\b|\bstarting state\b|\bbefore anything\b|"
    r"\bconfirm the access boundary\b|\binvalid_grant\b|\bzero cookies\b|\bno session\b|"
    r"\bunreachable\b|\bcheck the starting\b|\bpre-state\b|\babsent\b", re.I)
SUBJECT_WORDS = re.compile(r"\b(victim|owner|existing customer|pre-existing|that customer|the record)\b", re.I)
# A step that only POINTS BACK at an earlier step's object ("the commit step 1 created",
# "the one step 1 made") is citing provenance, not provisioning a new subject.
BACKREF = re.compile(
    r"\b(?:step|steps)\s+\d+\b[^.]{0,40}\b(?:created|made|provisioned|registered|minted|set up)\b|"
    r"\b(?:created|made|provisioned|registered|minted)\b[^.]{0,20}\b(?:in|by)\s+step\s+\d+\b", re.I)


def distinctive(text):
    """Named objects a step can be keyed on."""
    toks = set()
    toks |= set(RE_EMAIL.findall(text))
    toks |= set(RE_UUID.findall(text))
    toks |= set(RE_UUIDH.findall(text))
    toks |= {m for m in RE_ADDRID.findall(text)}
    toks |= {t for t in RE_BACKTICK.findall(text) if 6 <= len(t) <= 60}
    toks |= set(re.findall(r'"([A-Z][A-Za-z0-9 ]{4,40})"', text))
    toks |= set(re.findall(r"\b(?:Apt|APT)\s+[A-Z0-9]{3,20}\b", text))
    return {t.strip() for t in toks if len(t.strip()) >= 5}


def check_oneshot(draft, res):
    bad = []
    steps = draft.steps
    if not steps:
        res.add(6, "one-shot poc", True, False, ["no PoC steps could be parsed"])
        return
    # 6a: a later step mutates an object an earlier step reads or depends on
    for k, st in enumerate(steps):
        hits = [name for rx, name in MUTATE if re.search(rx, st["text"], re.I)]
        if not hits:
            continue
        objs = distinctive(st["text"])
        for prev in steps[:k]:
            shared = objs & distinctive(prev["text"])
            shared = {s for s in shared if not s.lower().startswith(("http", "get ", "post "))}
            # A bare commit hash shared with an earlier step is provenance, not a subject:
            # the step quotes the id it is reporting on, it does not delete the commit.
            shared = {s for s in shared if not RE_UUIDH.fullmatch(s)}
            if shared:
                bad.append("step %d (line %d) %s touches %s which step %d (line %d) already depends on"
                           % (st["num"], st["line"], "/".join(hits),
                              ", ".join(sorted(shared)[:3]), prev["num"], prev["line"]))
                break
    # 6b: step 1 must PROVISION what the PoC consumes
    def _provisions(s):
        """True when the step creates a subject, not when it cites an earlier step's."""
        if not PROVISION.search(s["text"]):
            return False
        return not BACKREF.search(s["text"])

    first_prov = next((s for s in steps if _provisions(s)), None)
    first_pre = next((s for s in steps if PRECOND.search(s["text"])), None)
    subjects = set()
    for rx in (RE_EMAIL, RE_UUIDH, RE_ADDRID):
        subjects |= set(rx.findall(draft.text))
    if subjects and first_prov is None:
        bad.append("the draft names a subject (%s) and no step provisions it"
                   % ", ".join(sorted(subjects)[:3]))
    elif first_prov and first_pre and first_prov["num"] > first_pre["num"]:
        bad.append("step %d (line %d) provisions the subject that step %d (line %d) asserts as a "
                   "precondition: the PoC burns its own precondition and runs once"
                   % (first_prov["num"], first_prov["line"], first_pre["num"], first_pre["line"]))
    elif first_prov and SUBJECT_WORDS.search(draft.text):
        # The provisioning step need not be numbered first (a step 0 may only quote deployment
        # context), but no step BEFORE it may consume a subject the PoC has not created yet.
        earlier_consumes = [s for s in steps
                            if s["num"] < first_prov["num"]
                            and (MUTATE and any(re.search(rx, s["text"], re.I) for rx, _ in MUTATE)
                                 or PRECOND.search(s["text"]))]
        if earlier_consumes:
            bad.append("the first provisioning step is step %d, but step %d already consumes a "
                       "subject before it is created; the PoC runs once"
                       % (first_prov["num"], earlier_consumes[0]["num"]))
    res.add(6, "one-shot poc", True, not bad, bad,
            note="%d steps parsed, first provisioning step %s, first precondition step %s"
                 % (len(steps), first_prov["num"] if first_prov else "none",
                    first_pre["num"] if first_pre else "none"))


# ---------------------------------------------------------------- 7 stale ids
DEAD = re.compile(r"\bDEAD\b|\bFAILS\b|no longer authenticat|\bMOVED\b|\bmoved\b|\brelocat|"
                  r"\bsupersed|\bIS LOST\b|\bSTALE\b|\bdead login\b|\bdoes not authenticate\b", re.I)
LIVE = re.compile(r"\bACTIVE\b|\bOK\b|\bstill works\b|\bSTILL VALID\b|\bstill authenticat|"
                  r"\bauthenticates\b|\bis unchanged and still works\b|\bintact\b|"
                  r"\*\*200\*\*|\|\s*200\s*\|", re.I)


def check_stale(draft, program, res):
    acc = os.path.join(ROOT, "targets", program or "", "ACCOUNTS.md")
    if not program or not os.path.isfile(acc):
        res.add(7, "stale identifier", True, True, note="SKIPPED, no ACCOUNTS.md for program %r" % program)
        return
    txt = read_text(acc) or ""
    # a verdict in a table row outweighs one in a wrapped prose line, because prose wrap
    # puts "A2 authenticates fine at +t7@" on the same line as the dead +tcoA3@
    dead_w, live_w = {}, {}
    for ln in txt.split("\n"):
        w = 2 if ln.lstrip().startswith("|") else 1
        toks = set(RE_EMAIL.findall(ln)) | set(RE_UUIDH.findall(ln)) | set(RE_UUID.findall(ln))
        # plus-addressed tag, the way ACCOUNTS.md abbreviates a moved login
        toks |= {"tag:" + t for t in re.findall(r"(\+[A-Za-z0-9]{1,14})@", ln)}
        # password-shaped literals only: a digit plus punctuation, never a route name
        toks |= {t for t in re.findall(r"`([A-Za-z0-9][\w!@#$%^&*.+-]{5,40})`", ln)
                 if re.search(r"\d", t) and re.search(r"[!@#$%^&*]", t)}
        if DEAD.search(ln):
            for t in toks:
                dead_w[t] = dead_w.get(t, 0) + w
        if LIVE.search(ln):
            for t in toks:
                live_w[t] = live_w.get(t, 0) + w
    stale = {t for t, dw in dead_w.items() if dw > live_w.get(t, 0)}
    bad = []
    for t in sorted(stale):
        needle = t[4:] + "@" if t.startswith("tag:") else t
        if len(needle) < 5:
            continue
        ls = [i for i, ln in enumerate(draft.lines, 1) if needle in ln]
        if ls:
            bad.append("draft names %s which ACCOUNTS.md records only as dead/moved/superseded "
                       "(draft line %s)" % (needle, ls[0]))
    res.add(7, "stale identifier", True, not bad, bad,
            note="%d dead-only identifiers in ACCOUNTS.md" % len(stale))


# ---------------------------------------------------------------- 8 paid / dupe
PAIDMARK = re.compile(r"\bPAID\b|\bACCEPTED\b|\bbounty paid\b|\bDo not re-report\b|"
                      r"\bdo not re-report\b", re.I)
GENERIC_PATH = {"/account/", "/account", "/login", "/logout", "/home", "/search", "/checkout",
                "/cart", "/en_US", "/identity", "/oauth", "/api", "/profile"}


def check_paid(draft, program, res):
    if not program:
        res.add(8, "paid or known duplicate", True, True, note="SKIPPED, no program")
        return
    sources = []
    pe = os.path.join(ROOT, "targets", program, "PRIOR-ENGAGEMENT.md")
    if os.path.isfile(pe):
        sources.append(pe)
    sub = os.path.join(ROOT, "reports", "submitted", program)
    if os.path.isdir(sub):
        for r, _, fs in os.walk(sub):
            sources += [os.path.join(r, f) for f in fs if f.endswith((".md", ".txt"))]
    for d in (os.path.join(ROOT, ".claude", "state", "hunt-loop", "do-not-rehunt.txt"),
              os.path.join(ROOT, ".claude", "state", "do-not-rehunt")):
        if os.path.isfile(d):
            sources.append(d)
        elif os.path.isdir(d):
            for r, _, fs in os.walk(d):
                sources += [os.path.join(r, f) for f in fs]
    if not sources:
        res.add(8, "paid or known duplicate", True, True, note="SKIPPED, no prior-engagement sources")
        return
    # tokens that a prior PAID/SUBMITTED block names
    paid_tokens = {}
    for s in sources:
        t = read_text(s)
        if t is None:
            continue
        lines = t.split("\n")
        for i, ln in enumerate(lines):
            ctx = "\n".join(lines[max(0, i - 12):i + 13])
            # a prior engagement only counts as paid/submitted ground when the block
            # carries BOTH a paid/accepted marker and a real platform report id
            if not (PAIDMARK.search(ctx) and RE_REPORTID.search(ctx)):
                continue
            for p in re.findall(r"https?://[\w.-]+(/[\w./%-]{10,})", ln):
                if p not in GENERIC_PATH:
                    paid_tokens.setdefault(p, (s, i + 1))
            for p in re.findall(r"(?<![\w/])(/[\w][\w./-]{10,})", ln):
                if p not in GENERIC_PATH and p.strip("/").count("/") >= 0:
                    paid_tokens.setdefault(p, (s, i + 1))
            for p in re.findall(r"\*\*`([\w-]{3,30})`\*\*|parameter[s]?\s+\*\*`([\w-]+)`\*\*", ln):
                for q in p:
                    if q:
                        paid_tokens.setdefault("param:" + q, (s, i + 1))
            for p in re.findall(r"^\|\s*Parameters\s*\|(.+)\|$", ln):
                for q in re.findall(r"`([\w-]{3,30})`", p):
                    paid_tokens.setdefault("param:" + q, (s, i + 1))
    cited = set(RE_REPORTID.findall(draft.text))
    hits = []
    for tok, (src, lno) in sorted(paid_tokens.items()):
        if tok.startswith("param:"):
            p = tok[6:]
            if re.search(r"[?&]%s=" % re.escape(p), draft.text):
                hits.append("parameter %s already %s (%s:%d)" % (p, "submitted/paid",
                                                                 os.path.relpath(src, ROOT), lno))
        elif tok in draft.text:
            hits.append("endpoint %s already submitted/paid (%s:%d)"
                        % (tok, os.path.relpath(src, ROOT), lno))
    bad = []
    if hits and not cited:
        bad = hits + ["draft cites no prior report id"]
    res.add(8, "paid or known duplicate", True, not bad, bad,
            note="%d prior paid/submitted tokens checked; draft cites %s"
                 % (len(paid_tokens), ", ".join(sorted(cited)) or "no report id"))


# ---------------------------------------------------------------- 9 contradiction
NEG = re.compile(r"\bis not\b|\bwas never\b|\bdoes not\b|\bdoesn't\b|\bno such\b|\bnot an?\b|"
                 r"\brather than\b|\bnever\b|\bno\s+\w+\s+is\b", re.I)


def check_contradiction(draft, res):
    claim_pairs = draft.section_text("Summary", "Impact")
    claim = draft.sentences(claim_pairs)
    for st in draft.steps:
        for i, ln in enumerate(st["text"].split("\n")):
            claim.append((st["line"] + i, ln))
    controls = []
    for i, ln in enumerate(draft.lines, 1):
        if re.search(r"\bcontrol\b", ln, re.I) or re.match(r"^\s*\d+\s{2,}\S", ln):
            controls.append((i, ln))
    for key, body in draft.sections.items():
        if "control" in key.lower():
            controls.extend(body)
    bad = []
    for ci, cln in controls:
        if not NEG.search(cln):
            continue
        for m in NEG.finditer(cln):
            tail = cln[m.end():m.end() + 60]
            head = re.findall(r"\b([a-z]{4,20})\b", tail)
            if not head:
                continue
            noun = head[0]
            near = cln[max(0, m.start() - 80):m.end() + 80]
            toks = {t for t in re.findall(r"`([^`]{3,40})`", near)} | set(re.findall(r"\b([1-5]\d\d)\b", near))
            for t in toks:
                for qi, qln in claim:
                    if qi == ci or t not in qln:
                        continue
                    if noun not in qln.lower():
                        continue
                    if NEG.search(qln):
                        continue
                    bad.append("control line %d negates %r about %s, asserted at line %d: %s"
                               % (ci, noun, t, qi, norm(cln)[:90]))
                    break
    # 9b: a control that re-reads the SAME bytes as a numbered item it names, and reaches
    # the opposite conclusion. "byte-identical to control 1, so the 422 is a record gate,
    # not an identity gate" while item 1 uses that same 422 as the denial baseline.
    bynum = {}
    for st in draft.steps:
        bynum.setdefault(st["num"], st)
    for ci, cln in controls:
        if not NEG.search(cln):
            continue
        ctx = cln
        if not re.search(r"\b(?:control|step|item)\s+(\d+)\b", ctx, re.I):
            prev = draft.lines[ci - 2] if ci >= 2 else ""
            ctx = prev + " " + cln
        for m in re.finditer(r"\b(?:control|step|item)\s+(\d+)\b", ctx, re.I):
            ref = bynum.get(int(m.group(1)))
            if not ref or ref["line"] == ci:
                continue
            if NEG.search(ref["text"].split("\n")[0]):
                continue
            a = set(re.findall(r"\b([1-5]\d\d)\b", ctx)) | set(re.findall(r"`([^`]{3,40})`", ctx))
            b = set(re.findall(r"\b([1-5]\d\d)\b", ref["text"])) | set(re.findall(r"`([^`]{3,40})`", ref["text"]))
            shared = a & b
            if shared:
                bad.append("control at line %d negates item %s about %s while item %s asserts it "
                           "(line %d): %s" % (ci, m.group(1), ", ".join(sorted(shared)[:3]),
                                              m.group(1), ref["line"], norm(cln)[:90]))
    res.add(9, "self-contradiction", True, not bad, sorted(set(bad)))


# ---------------------------------------------------------------- 10 controls
CTRL_CLAIM = [
    (re.compile(r"\bpositive control\b|\bpos(?:itive)?[- ]ctl\b", re.I), "positive control",
     re.compile(r"POSCTL|POSITIVE CONTROL|positive control|pos_control|pos-control", re.I)),
    (re.compile(r"\bnegative control\b|\bneg(?:ative)?[- ]ctl\b", re.I), "negative control",
     re.compile(r"NEGCTL|NEGATIVE CONTROL|negative control|neg_control|neg-control|negctl", re.I)),
    (re.compile(r"\bghost control\b|\bghost[- ]ctl\b", re.I), "ghost control",
     re.compile(r"GHOST", re.I)),
]


def check_controls(draft, corpus, res):
    if not corpus.dirs:
        res.add(10, "unbacked control claim", True, True, note="SKIPPED, no --evidence given")
        return
    bad = []
    hay = corpus.raw + " " + corpus.unesc + " " + " ".join(corpus.files)
    for rx, name, ev in CTRL_CLAIM:
        lines = [i for i, ln in enumerate(draft.lines, 1) if rx.search(ln)]
        if lines and not ev.search(hay):
            bad.append("draft claims a %s (line %s) and no evidence file records one"
                       % (name, lines[0]))
    for i, ln in enumerate(draft.lines, 1):
        for m in re.finditer(r"\b(\d+)\s+of\s+\1\b", ln):
            n = int(m.group(1))
            runs = len({re.sub(r"\d+", "#", f) for f in corpus.files})
            marks = len(re.findall(r"\b(?:run|leg|wire_)", hay, re.I))
            if marks < n:
                bad.append("line %d claims %d of %d runs; evidence carries %d run markers"
                           % (i, n, n, marks))
    res.add(10, "unbacked control claim", True, not bad, bad)


# ---------------------------------------------------------------- 11 prose tells
FILLER = ["it is worth noting", "that said", "in essence", "fundamentally", "delve",
          "robust", "leverage", "seamless", "comprehensive", "worth sitting with"]
SIGNPOST = re.compile(r"\bI will start with\b|\bthen explain\b|\bbelow I will\b|\bin this report I\b|"
                      r"\bfirst I will\b|\bI will then\b|\bthis section (?:will|covers)\b", re.I)


def check_prose(draft, res):
    det = []
    score = 0
    bold = [i for i, ln in enumerate(draft.lines, 1)
            if i not in draft.in_block and re.match(r"^\*\*[^*]{3,80}\*\*[:.,]?\s+\S", ln.strip())]
    if bold:
        det.append("bolded lead-in paragraphs: %d  lines %s" % (len(bold), bold[:10]))
        score += 2 * len(bold)
    numh = [i for i, ln in enumerate(draft.lines, 1)
            if i not in draft.in_block and re.match(r"^#{1,6}\s+\d+\.\s", ln)]
    if numh:
        det.append("numbered headings '## N.': %d  lines %s" % (len(numh), numh[:10]))
        score += 2 * len(numh)
    sp = [i for i, s in draft.sentences() if SIGNPOST.search(s)]
    if sp:
        det.append("structure-announcing sentences: %d  lines %s" % (len(sp), sp[:10]))
        score += 3 * len(sp)
    closers = []
    for i, ln in enumerate(draft.lines, 1):
        if i in draft.in_block or not ln.strip():
            continue
        s = ln.strip()
        if s.endswith(".") and s.count(",") >= 2:
            clauses = [c for c in s.rstrip(".").split(",") if c.strip()]
            if len(clauses) in (3, 4) and all(6 <= len(c.strip()) <= 60 for c in clauses):
                closers.append(i)
    if closers:
        det.append("rhetorically balanced closers: %d  lines %s" % (len(closers), closers[:10]))
        score += 1 * len(closers)
    prose = " ".join(ln for i, ln in enumerate(draft.lines, 1) if i not in draft.in_block)
    contractions = len(re.findall(r"\b\w+['’](?:s|t|re|ve|ll|d|m)\b", prose))
    if contractions == 0:
        det.append("zero contractions across the document")
        score += 10
    else:
        det.append("contractions: %d" % contractions)
    sents = [s for _, s in draft.sentences() if len(s.split()) > 2]
    lens = [len(s.split()) for s in sents]
    if len(lens) >= 10:
        mean = sum(lens) / len(lens)
        var = sum((x - mean) ** 2 for x in lens) / len(lens)
        sd = var ** 0.5
        det.append("sentence length mean %.1f sd %.1f (low sd under 5.0 reads machine-even)" % (mean, sd))
        if sd < 5.0:
            score += 8
    for f in FILLER:
        ls = [i for i, ln in enumerate(draft.lines, 1) if f in ln.lower()]
        if ls:
            det.append("banned filler %r: %d  lines %s" % (f, len(ls), ls[:8]))
            score += 3 * len(ls)
    det.append("SLOP SCORE %d  (0-9 human, 10-24 mixed, 25+ reads machine-written)" % score)
    res.add(11, "prose tells", False, score < 25, det, note="advisory, never fatal")


# ---------------------------------------------------------------- 12 hedges
MECH = re.compile(r"\bbecause\b|\bresolves\b|\bbinds\b|\bthe reason is\b|\bis caused by\b|"
                  r"\btreats\b|\bwhich is why\b|\bthe mechanism\b|\bmeans that\b|\bso that\b", re.I)
HEDGE = re.compile(r"\bmy reading\b|\bI did not capture\b|\bI didn't capture\b|\bI only saw this once\b|"
                   r"\bI cannot say\b|\bI can't say\b|\bI only caught that once\b|\bI haven't reproduced\b|"
                   r"\bone observation\b|\btreat (?:it|this) as\b|\brather than claiming\b|"
                   r"\bI don't know\b|\bI do not know\b", re.I)
SINGLE = re.compile(r"\bonce\b|\bone observation\b|\ba single\b|\bonly saw\b|\bonly caught\b|"
                    r"\bhaven't reproduced\b|\bhave not reproduced\b|\bone account\b", re.I)


def check_hedges(draft, res):
    det = []
    unhedged = 0
    for i, s in draft.sentences():
        if not MECH.search(s) or len(s.split()) < 6:
            continue
        ctx = " ".join(draft.lines[max(0, i - 3):i + 2])
        if HEDGE.search(s) or HEDGE.search(ctx):
            continue
        if SINGLE.search(s) or SINGLE.search(ctx):
            unhedged += 1
            det.append("line %d  mechanism claim on a single observation, no hedge: %s" % (i, norm(s)[:100]))
    det.insert(0, "unhedged single-observation mechanism claims: %d" % unhedged)
    res.add(12, "hedge preservation", False, unhedged == 0, det, note="advisory, never fatal")


# ---------------------------------------------------------------- driver
def program_of(path):
    p = os.path.abspath(path)
    m = re.search(r"/reports/(?:drafts|submitted)/([^/]+)/", p)
    if m:
        return m.group(1)
    m = re.search(r"/targets/([^/]+)/", p)
    return m.group(1) if m else None


def run(draft_path, evidence, attachments, program=None):
    draft = Draft(draft_path)
    corpus = Corpus(evidence or [])
    program = program or program_of(draft_path)
    res = Result()
    check_provenance(draft, corpus, res)
    check_truncation(draft, res)
    check_citations(draft, attachments, corpus, res)
    check_manifest(draft, attachments, res)
    check_dupes(attachments, res)
    check_oneshot(draft, res)
    check_stale(draft, program, res)
    check_paid(draft, program, res)
    check_contradiction(draft, res)
    check_controls(draft, corpus, res)
    check_prose(draft, res)
    check_hedges(draft, res)
    return draft, res, program


D = os.path.join(ROOT, "reports/drafts/program-01")
T = os.path.join(ROOT, "targets/program-01/evidence")
FIXTURES = [
    ("KNOWN-BAD  (closed invalid 2026-09-30)",
     os.path.join(D, "preauth-ato-identity-split-20260930.md"),
     [T], None, {"must_fail": [6]}),
    ("KNOWN-GOOD (survived four adversarial rounds)",
     os.path.join(D, "preauth-ato-identity-split-20260930/triage-reply-20261001/REOPEN-REQUEST.md"),
     [os.path.join(T, "recapture-triage-20261001"), os.path.join(T, "dupe-identity-20261001")],
     os.path.join(D, "preauth-ato-identity-split-20260930/triage-reply-20261001/attachments"),
     {"must_pass_hard": True}),
]


def selfcheck(as_json=False):
    out = []
    ok = True
    for label, path, ev, att, expect in FIXTURES:
        draft, res, prog = run(path, ev, att)
        fired = [c["check"] for c in res.failed]
        verdict = "OK"
        for n in expect.get("must_fail", []):
            if n not in fired:
                verdict = "GATE BROKEN: check %d did not fire on the known-bad fixture" % n
                ok = False
        if expect.get("must_pass_hard") and fired:
            verdict = "known-good fired hard checks %s - investigate before weakening them" % fired
        out.append({"fixture": label, "path": path, "hard_fails": fired,
                    "verdict": verdict, "checks": res.checks})
        if not as_json:
            print("=" * 78)
            print(label)
            print("  draft      %s" % path)
            print("  evidence   %s" % ", ".join(ev))
            print("  attachments %s" % (att or "-"))
            print("-" * 78)
            res.render()
            print("  -> hard checks failed: %s" % (fired or "none"))
            print("  -> %s" % verdict)
    if as_json:
        print(json.dumps({"selfcheck": out, "acceptance": ok}, indent=2))
    else:
        print("=" * 78)
        print("ACCEPTANCE: %s" % ("PASS, the gate catches the known failure"
                                  if ok else "FAIL, the gate is broken"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("draft", nargs="?")
    ap.add_argument("--evidence", action="append", default=[])
    ap.add_argument("--attachments")
    ap.add_argument("--program")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selfcheck", action="store_true")
    a = ap.parse_args()
    if a.selfcheck:
        return selfcheck(a.json)
    if not a.draft:
        ap.error("a draft path or --selfcheck is required")
    draft, res, prog = run(a.draft, a.evidence, a.attachments, a.program)
    if a.json:
        print(json.dumps({"draft": a.draft, "program": prog, "checks": res.checks,
                          "hard_fails": [c["check"] for c in res.failed]}, indent=2))
    else:
        print("slop-gate  %s" % a.draft)
        print("program    %s" % prog)
        print("-" * 78)
        res.render()
        print("-" * 78)
        print("RESULT: %s" % ("PASS, mechanically clean. STILL REQUIRES HUMAN REVIEW."
                              if not res.failed else
                              "FAIL on hard checks %s - do not send" % [c["check"] for c in res.failed]))
    return 1 if res.failed else 0


if __name__ == "__main__":
    sys.exit(main())
