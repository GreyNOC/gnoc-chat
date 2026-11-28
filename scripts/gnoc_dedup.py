"""gnoc_dedup.py - "have we already done this?" from VERDICTS only, before the first probe.

A mention is not coverage (Manual T-219): a host showing up in a note or a capture log says nothing. This module
reads only the places that record a decision:
    .claude/state/do-not-rehunt/<program>.txt        receipt-dead / do-not-file entries
    reports/{submitted,drafts,archive,leads}/<program>/   our own reports, by state (submitted = never refile)
    .claude/state/hunt-loop/outcomes.jsonl          recorded verdicts (DEAD / LEAD / CANDIDATE ...)
    targets/<program>/hunts/gnoc/ledger.json        gnoc chat's own hypotheses and their status
    HANDOFF-CURRENT.md section 3                     the do-not-file list
    .claude/state/hunt-loop/public-dedup.jsonl       the PUBLIC prior-art verdicts (H1 hacktivity / GHSA / google),
                                                     recorded per (program, host, class, endpoint) by
                                                     scripts/learn/public-dedup.sh: MATCH:#N is a filed duplicate
check(program, terms) -> text; program_summary(program) -> text for set_program.
"""
import json
import glob
import os
import re

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _read

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PUBLIC_LEDGER = os.path.join(WS, ".claude/state/hunt-loop/public-dedup.jsonl")
STATES = ("submitted", "drafts", "archive", "leads")
STATE_NOTE = {"submitted": "FILED, never refile", "drafts": "drafted",
              "drafts-killed": "drafted then KILLED by its own gates (reviewer / repro-checker): not a prior finding, "
                               "its premise is unproven", "archive": "archived (read WHY-ARCHIVED)",
              "leads": "lead"}




def _terms(terms):
    if isinstance(terms, str):
        terms = re.split(r"[\s,]+", terms)
    return [t.strip().lower() for t in (terms or []) if isinstance(t, str) and len(t.strip()) >= 3]


def _hit(text, terms):
    t = text.lower()
    return all(x in t for x in terms)


def _title(d):
    for name in ("report.md", "report-as-filed.md", "report-staged.md", "WHY-ARCHIVED.md", "HELD-REASON.md"):
        for ln in _read(os.path.join(d, name)).splitlines():
            if ln.startswith("# ") and "FROZEN" not in ln:
                return ln[2:].strip()[:110]
    return ""


def reports(program, terms=None):
    """[(state, rel path, title)] of our own reports for the program, optionally only those matching all terms."""
    out = []
    for st in STATES:
        base = os.path.join(WS, "reports", st, program)
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            p = os.path.join(base, name)
            if os.path.isdir(p):
                body = " ".join(_read(os.path.join(p, f)) for f in os.listdir(p) if f.endswith(".md"))
                title = _title(p) or name
            elif name.endswith(".md"):
                body, title = _read(p), name[:-3]
            else:
                continue
            if terms is None or _hit(name + " " + body, terms):
                out.append((gate_state(st, p), os.path.relpath(p, WS), title))
    return out


def gate_state(st, d):
    """'drafts-killed' when the draft's newest GATE-*.md verdict is KILL (gnoc_report writes the verdict as the first
    line). Drive cycle 4 (2026-10-26): five gate-killed copies of one draft were shown to the lead as '[drafted]'
    prior findings on api.program-0.example, which kept their invented route alive for three cycles."""
    if st != "drafts" or not os.path.isdir(d):
        return st
    gates = sorted(glob.glob(os.path.join(d, "GATE-*.md")), key=os.path.getmtime)
    for g in reversed(gates):
        first = _read(g)[:200].strip().splitlines()[:1]
        if first:
            return "drafts-killed" if first[0].strip().upper().startswith("KILL") else st
    return st


def outcomes(program, terms, limit=8):
    rows = []
    p = os.path.join(WS, ".claude/state/hunt-loop/outcomes.jsonl")
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            for ln in f:
                if f'"{program}"' not in ln:
                    continue
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("target") == program and _hit(f"{r.get('vector', '')} {r.get('notes', '')} "
                                                       f"{r.get('artifact', '')}", terms):
                    rows.append(r)
    except OSError:
        pass
    return rows[-limit:]


def do_not_rehunt(program, terms):
    lines = _read(os.path.join(WS, ".claude/state/do-not-rehunt", f"{program}.txt")).splitlines()
    return [ln.strip()[:200] for ln in lines if ln.strip() and not ln.startswith("#") and _hit(ln, terms)]


def ledger(program, terms):
    try:
        d = json.loads(_read(os.path.join(WS, "targets", program, "hunts", "gnoc", "ledger.json")) or "{}")
    except ValueError:
        return []
    hyps = d.get("hypotheses") if isinstance(d, dict) else None   # a list / string on disk raised here
    return [h for h in (hyps if isinstance(hyps, list) else [])
            if isinstance(h, dict) and _hit(" ".join(str(h.get(k, "")) for k in ("title", "violation", "notes", "evidence")), terms)]


def handoff_do_not_file(program, terms):
    text = _read(os.path.join(WS, "HANDOFF-CURRENT.md"))
    m = re.search(r"^## 3\..*?(?=^## 4\.)", text, re.S | re.M)
    block = m.group(0) if m else ""
    return [ln.strip()[:220] for ln in block.splitlines() if program.lower() in ln.lower() and _hit(ln, terms)]


def check(program, terms):
    """Verdict-only dedup for a host / endpoint / class. Returns (hit_count, text)."""
    terms = _terms(terms)
    if not program or not terms:
        return 0, "dedup needs a program and a host, endpoint or class term"
    if not _ok_program(program):
        return 0, f"dedup: {program!r} is not a program handle"
    secs, n = [], 0
    rep = reports(program, terms)
    if rep:
        n += len(rep)
        secs.append("OUR REPORTS:\n" + "\n".join(f"  [{STATE_NOTE[s]}] {t}  ({p})" for s, p, t in rep[:10]))
    dnr = do_not_rehunt(program, terms)
    if dnr:
        n += len(dnr)
        secs.append("DO-NOT-REHUNT:\n" + "\n".join(f"  {x}" for x in dnr[:8]))
    hd = handoff_do_not_file(program, terms)
    if hd:
        n += len(hd)
        secs.append("HANDOFF DO-NOT-FILE:\n" + "\n".join(f"  {x}" for x in hd[:5]))
    pub = public_ledger(program, terms)
    if pub:
        n += len(pub)
        secs.append("PUBLIC PRIOR ART (hacktivity / GHSA, verified by a human or a scout):\n" + "\n".join(
            f"  {str(r.get('result') or 'none').upper():5} {r.get('host')} {r.get('endpoint')} [{r.get('class')}]"
            + (f" prior {r.get('prior')}" if r.get("prior") else "") + (f" angle {r.get('angle')}" if r.get("angle") else "")
            for r in pub))
    oc = outcomes(program, terms)
    if oc:
        n += len(oc)
        secs.append("RECORDED VERDICTS:\n" + "\n".join(
            f"  {str(r.get('ts') or '')[:10]} {r.get('verdict')} probes={r.get('probes')} burst={r.get('burst')} "
            f"{str(r.get('vector') or '')[:90]}  ({r.get('artifact') or ''})" for r in oc))
    lg = ledger(program, terms)
    if lg:
        n += len(lg)
        secs.append("GNOC LEDGER:\n" + "\n".join(f"  {h.get('id', '?')} [{h.get('status')}] {h.get('title')} "
                                                 f"probes={h.get('probes')}" for h in lg[:8]))
    head = f"DEDUP {program} [{' '.join(terms)}]: "
    if not secs:
        return 0, head + "no prior verdict. (Mentions in notes are not coverage; hunt_search finds raw mentions.)"
    return n, head + f"{n} prior verdict(s). Read them before probing; a FILED one is never refiled.\n" + \
        "\n\n".join(secs)


def public_ledger(program, terms=None, limit=8):
    """Rows of the public prior-art ledger for this program, newest first; with terms, only rows whose host /
    endpoint / class carry every term. A MATCH row is a disclosed duplicate: 8 of our 12 H1 reports closed that way."""
    out = []
    try:
        with open(PUBLIC_LEDGER, encoding="utf-8", errors="replace") as f:
            for ln in f:
                if f'"{program}"' not in ln:
                    continue
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                if not isinstance(r, dict) or r.get("program") != program:
                    continue
                hay = " ".join(str(r.get(k) or "") for k in ("host", "endpoint", "class")).lower()
                if terms is None or all(t in hay for t in _terms(terms)):
                    out.append(r)
    except OSError:
        return []
    out.sort(key=lambda r: -(r.get("ts") or 0))
    return out[:limit]


def public_verdict(program, host):
    """(result, row) for the newest public-dedup row naming this host (or a row with no host filter when none
    names it): 'MATCH' / 'NOVEL' / 'none', or (None, None) when the query was never run for the host."""
    h = (host or "").lower()
    rows = public_ledger(program, None, limit=200)
    for r in rows:
        if h and (r.get("host") or "").lower() == h:
            return str(r.get("result") or "none").upper(), r
    return None, None


def _ok_program(program):
    """A handle names one directory under reports/ and targets/: '../x' or 'a/b' would read outside them."""
    return isinstance(program, str) and bool(re.fullmatch(r"[\w][\w.-]*", program))


def _draft_line(rel):
    """'slug [HELD: why]' or 'slug [draft]' for one draft dir: the first real line of HELD-REASON.md is the why."""
    p = os.path.join(WS, rel)
    slug = os.path.basename(rel.rstrip("/"))
    held = os.path.join(p, "HELD-REASON.md") if os.path.isdir(p) else ""
    if held and os.path.exists(held):
        lines = [ln.strip(" *#-") for ln in _read(held).splitlines()
                 if ln.strip(" *#-") and not ln.lstrip().startswith("#")]
        # a status line ("Status: HELD. Written, not staged") says nothing; the line that names the reason does
        why = next((ln for ln in lines if re.search(r"(?i)\b(reason|why|out of scope|descoped|because|kill|"
                                                     r"unlock|blocked|severity)\b", ln)), lines[0] if lines else "")
        return f"{slug} [HELD: {why[:160]}]"
    return f"{slug} [draft]"


def program_summary(program):
    if not _ok_program(program):
        return f"{program!r} is not a program handle"
    rep = reports(program)
    by = {}
    for s, _, _ in rep:
        by[s] = by.get(s, 0) + 1
    dnr = [ln for ln in _read(os.path.join(WS, ".claude/state/do-not-rehunt", f"{program}.txt")).splitlines()
           if ln.strip() and not ln.startswith("#")]
    filed = [t for s, _, t in rep if s == "submitted"]
    out = [f"Prior work on {program}: " + (", ".join(f"{v} {k}" for k, v in by.items()) or "no reports")
           + f", {len(dnr)} do-not-rehunt entries."]
    if filed:
        out.append("FILED (never refile): " + "; ".join(filed[:8]))
    drafts = [p for s, p, _ in rep if s == "drafts"]
    if drafts:
        # "is the X draft filable?" took 24 calls of searching targets/ (training run 2026-10-22): the answer was
        # the HELD-REASON.md beside the draft, which the brief never named
        out.append("DRAFTS (reports/drafts/" + program + "/): " + "; ".join(_draft_line(p) for p in drafts[:8]))
    lanes = _lane_lines(program)
    if lanes:
        # "what have we tested?" was answered from whichever STATUS.md a search hit first (a 24-probe sweep)
        # while the 169-probe lane sat unread (training run 2026-10-22): name the lanes and their verdicts
        out.append("HUNT LANES (newest first, targets/" + program + "/hunts/): " + "; ".join(lanes))
    out.append("Run dedup <host or endpoint> before probing a surface; it also runs by itself on each new host.")
    return "\n".join(out)


_VERDICT = re.compile(r"\b(DEAD|LEAD|CANDIDATE|CRITICAL|NEEDS|UNFIRED|KILL|PROMOTE|NO CHAIN|REFUTED|"
                      r"\d+\s*(probes|requests|calls))\b", re.I)


def _lane_lines(program, k=8):
    base = os.path.join(WS, "targets", program, "hunts")
    found = []
    for st in glob.glob(os.path.join(base, "*", "STATUS.md")):
        try:
            found.append((os.path.getmtime(st), st))
        except OSError:
            pass
    out = []
    for _, st in sorted(found, reverse=True)[:k]:
        lane = os.path.basename(os.path.dirname(st))
        line = next((ln.strip(" *#-|") for ln in _read(st).splitlines()[:60] if _VERDICT.search(ln)), "")
        out.append(f"{lane}" + (f" [{line[:110]}]" if line else ""))
    return out
