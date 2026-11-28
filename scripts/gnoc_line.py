#!/usr/bin/env python3
"""gnoc_line.py - THE LINE: the hunt as a nine-station production line whose every handoff is code-gated.

Spec: scripts/learn/SPEC-xbow-intel-economy-20261022.md section 6. Process doc: scripts/HUNT-PROCESS-V2.md.

A WORK ORDER (WO) moves SALES -> INTEL -> MODEL -> MARKET, then each hypothesis on it moves PROBE -> ESCALATE ->
QA -> BOOKS, and the manager files a RETRO. No station can be skipped. Every gate below is a pure function over
artifact files and ledgers (gnoc_pay, gnoc_hunt, gnoc_oracle, gnoc_economy, outcomes.jsonl, do-not-rehunt,
public-dedup.jsonl). A model's own "verdict" field is advisory: it may BLOCK a station, it never PASSES one.

    open(program, wo)                       station 0 gate, writes targets/<p>/line/WO-<id>.json
    advance(program, wo_id, station, art)   runs that station's gate; refuses with the exact failing check
    market(program, wo_id, hyps)            station 3 helper: registers A/V/P hypotheses in gnoc_hunt, commits one
                                            oracle per hypothesis (preimage returned ONCE), then advance(3)
    status(program)                         every open WO at its station, age, RC spent of budget
    brief(program, wo_id, bot)              the dispatch brief for the NEXT station

State: targets/<p>/line/ (WO-*.json, SP-*.md, TM-*.json, MK-*.json, PR/ES/QA/BK/RT-*.json) and the office summary
.claude/state/economy/line.json. Every advance emits gnoc_economy.on_event("line-advance", ...) (never raises).
    log_capture / log_burst                 Claude lanes feed the PROBE floor from capture FILES (sha-deduped; a burst
                                            needs its serial-control capture and >= 2 burst captures)

CLI: python3 scripts/gnoc_line.py open|advance|market|current|show|log|burst|status|brief|trap  (JSON for gates)
  market <p> <wo> --file HY.json[,AT.json] [--only id1,id2] | --data <urlencoded JSON>
  log <p> <H#> <capture>...      burst <p> <H#> --serial <control> <capture> <capture>...
"""
import contextlib
import fcntl
import glob
import json
import os
import re
import secrets
import sys
import time
import urllib.parse
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGETS = os.path.join(WS, "targets")
LINE_JSON = os.path.join(WS, ".claude/state/economy/line.json")
LESSONS = os.path.join(WS, ".claude/state/learning/LESSONS.md")
MANUAL_INDEX = os.path.join(WS, "Manual/MANUAL-INDEX.md")
DNR_DIR = os.path.join(WS, ".claude/state/do-not-rehunt")
DNR_GLOBAL = os.path.join(WS, ".claude/state/hunt-loop/do-not-rehunt.txt")
OUTCOMES = os.path.join(WS, ".claude/state/hunt-loop/outcomes.jsonl")
PUBLIC_DEDUP = os.path.join(WS, ".claude/state/hunt-loop/public-dedup.jsonl")
INBOX = os.path.join(WS, "reports/INBOX.md")

FLOOR = 8                 # SPINE 4 empirical floor: 8 crafted live probes plus a burst with a serial control
LIVENESS_MAX_S = 24 * 3600  # T-241: the source leg is re-fired within 24 h of READY
WORD_CAP = 35             # CLAUDE.md REPORT LENGTH HARDRULE: Summary and Impact each <= 35 words
DUPE_ODDS_REFUSE = 0.7    # filing-futures: refuse QA when resolved history says >= 70% duplicate (n >= 3)
STATIONS = ((0, "SALES", "manager (orch-bot)"), (1, "INTEL", "intel dept"), (2, "MODEL", "target-modeler"),
            (3, "MARKET", "hypothesis-generator + skeptics"), (4, "PROBE", "class hunter"),
            (5, "ESCALATE", "escalation agent (different model)"),
            (6, "QA", "dedup-scout, triage-validator, reviewer, report-killer, cvss, repro-checker"),
            (7, "BOOKS", "manager"), (8, "RETRO", "manager"))
NAME = {n: s for n, s, _ in STATIONS}
OWNER = {n: o for n, _, o in STATIONS}
ART = {1: "SP", 2: "TM", 3: "MK", 4: "PR", 5: "ES", 6: "QA", 7: "BK", 8: "RT"}
ITEM_STATIONS = (4, 5, 6, 7)
TRAP_MARK = "TRAP, these are our WORST converters"
TRAP_FALLBACK = ("Insecure Direct Object Reference (IDOR)", "Information Disclosure",
                 "Improper Restriction of Authentication Attempts")
TRAP_ALIASES = {"idor": ("insecure direct object reference", "idor"), "bola": ("insecure direct object reference",),
                "exposure": ("information disclosure", "information exposure"),
                "info-disclosure": ("information disclosure", "information exposure"),
                "disclosure": ("information disclosure",),
                "brute-force": ("improper restriction of authentication attempts",),
                "rate-limit": ("improper restriction of authentication attempts",),
                "otp": ("improper restriction of authentication attempts",)}
# workflow canonical class -> oracle kind (gnoc_oracle.VALIDATORS); anything else uses the WO's oracle_class
CLASS_ORACLE = {"idor": "cross-user-read", "graphql": "cross-user-read", "unauth": "auth-bypass",
                "oauth": "auth-bypass", "saml": "auth-bypass", "jwt": "auth-bypass", "ssrf": "ssrf-internal",
                "rce": "rce", "race": "race-single-use", "cache": "cache-poisoning", "sqli": "sqli-boolean",
                "xss": "xss-dom", "exposure": "info-disclosure"}
# class keyword -> extra Manual index search terms for the brief's T-ids
CLASS_TERMS = {"idor": ("idor", "cross-user", "bola"), "business-logic": ("business-logic", "burst", "limit"),
               "race": ("burst", "concurren", "race"), "unauth": ("unauth", "credential"),
               "ssrf": ("ssrf", "fetcher"), "oauth": ("oauth", "redirect"), "exposure": ("disclosure", "leak")}
_PROG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,80}")
_WOID = re.compile(r"[0-9]{12}-[0-9a-f]{4}")


def _bopen(p, mode, errors=None):
    """builtins.open: this module defines open() (station 0), which would shadow it for every global lookup."""
    import builtins
    return builtins.open(p, mode, encoding="utf-8", errors=errors)




def _ts(s):
    try:
        return datetime.fromisoformat(str(s)).timestamp()
    except ValueError:
        return time.time()


def _check_program(p):
    if not p or not _PROG.fullmatch(str(p)) or ".." in str(p):
        raise ValueError(f"bad program name {p!r}")
    return str(p)


def line_dir(program):
    return os.path.join(TARGETS, _check_program(program), "line")


def wo_path(program, wo_id):
    if not _WOID.fullmatch(str(wo_id or "")):
        raise ValueError(f"bad work order id {wo_id!r}")
    return os.path.join(line_dir(program), f"WO-{wo_id}.json")


@contextlib.contextmanager
def _locked(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _bopen(path + ".lock", "a") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{secrets.token_hex(3)}.tmp"
    with _bopen(tmp, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _read_json(path):
    try:
        with _bopen(path, "r") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _read(path):
    try:
        with _bopen(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def _abs(p):
    p = str(p or "")
    return os.path.realpath(p if os.path.isabs(p) else os.path.join(WS, p))


def load_wo(program, wo_id):
    return _read_json(wo_path(program, wo_id))


def _econ(kind, **kw):
    try:
        import gnoc_economy
        return gnoc_economy.on_event(kind, **kw)
    except Exception:  # noqa: BLE001 - the economy can never block the line
        return None


# ---------------------------------------------------------------- inputs the gates read

def trap_list():
    """Our WORST converters from the live consolidate output (LESSONS.md CLASS STEER), else the fallback."""
    for ln in _read(LESSONS).splitlines():
        if TRAP_MARK in ln:
            body = ln.split(":", 1)[1] if ":" in ln else ""
            names = [re.sub(r"\s+\d+%.*$", "", x).strip() for x in body.split(";")]
            names = [n for n in names if n and n.lower() != "unlabelled"]
            if names:
                return tuple(names)
    return TRAP_FALLBACK


def trap_match(cls):
    """The TRAP row name a class falls in, or ''."""
    c = str(cls or "").strip().lower()
    if not c:
        return ""
    terms = TRAP_ALIASES.get(c, ()) + ((c,) if len(c) > 3 else ())
    for t in trap_list():
        tl = t.lower()
        if any(x in tl for x in terms) or (len(tl) > 3 and tl in c):
            return t
    return ""


def dnr_lines(program):
    out = []
    for p in (os.path.join(DNR_DIR, f"{program}.txt"), DNR_GLOBAL):
        for ln in _read(p).splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                out.append(ln)
    return out


def dnr_hit(program, seed):
    """The do-not-rehunt line a seed repeats (same host AND same class or endpoint), or ''."""
    host = str(seed.get("host") or "").strip().lower()
    cls = str(seed.get("class") or "").strip().lower()
    ep = str(seed.get("endpoint") or "").strip()
    if not host:
        return ""
    for ln in dnr_lines(program):
        fields = [f.strip().lower() for f in ln.split("#")[0].split("|")]
        if host not in fields:
            continue
        if (cls and any(cls in f for f in fields if f != host)) or (ep and ep in ln):
            return ln[:160]
    return ""


def outcome_row(program, hyp_id):
    """Newest outcomes.jsonl row for this program naming the hypothesis (field `hypothesis` or in `lane`)."""
    best = None
    for ln in _read(OUTCOMES).splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(r, dict) or (r.get("target") or r.get("program")) != program:
            continue
        if r.get("hypothesis") == hyp_id or re.search(rf"(?<![A-Za-z0-9]){re.escape(hyp_id)}(?![0-9])",
                                                     str(r.get("lane") or "")):
            best = r
    return best


def _json_block(md):
    m = re.search(r"```json\s*\n(.*?)\n```", md, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(1))
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _section_words(md, name):
    m = re.search(rf"^#+\s*{name}\b[^\n]*\n(.*?)(?=^#+\s|\Z)", md, re.S | re.M | re.I)
    return None if not m else len(re.findall(r"\S+", m.group(1)))


def _hyp(program, hid):
    import gnoc_hunt as H
    for h in H.load(program).get("hypotheses", []):
        if h.get("id") == hid:
            return h
    return None


# ---------------------------------------------------------------- the station gates (pure: (ok, check, extra))

def gate_sales(program, wo):
    import gnoc_oracle as O
    import gnoc_pay as P
    miss = [k for k in ("crown", "class", "asset", "oracle_class") if not str(wo.get(k) or "").strip()]
    if miss:
        return False, f"work order missing field(s): {', '.join(miss)}", {}
    try:
        b = int(wo.get("budget_rc") or 0)
    except (TypeError, ValueError):
        b = 0
    if b <= 0:
        return False, "budget_rc must be a positive integer (1 RC ~ one live probe)", {}
    if wo["oracle_class"] not in O.VALIDATORS:
        return False, f"oracle_class {wo['oracle_class']!r} is not a gnoc_oracle validator", {}
    ok, why = P.filing_gate(program)
    if not ok:
        return False, f"pay gate (gnoc_pay.filing_gate): {why}", {}
    v, pwhy, _ = P.payability(program, wo["asset"])
    if not (v == "pays" or (v == "no-bounty" and wo.get("vdp") is True)):
        return False, f"scope row does not pay (gnoc_pay.payability={v}): {pwhy}", {}
    trap = trap_match(wo["class"])
    if trap and len(str(wo.get("new_root_cause") or "").strip()) < 20:
        return False, (f"class {wo['class']!r} is in the TRAP list ({trap}): open it only with a seed naming a "
                       "NEW root cause (new_root_cause, >= 20 chars)"), {}
    phase = O.release_phase(wo["oracle_class"], program)
    if phase not in ("GA", "preview", "private"):
        return False, f"release phase unknown for {wo['oracle_class']}", {}
    if wo.get("release_phase") and wo["release_phase"] != phase:
        return False, f"release phase stale: work order says {wo['release_phase']}, ledger says {phase}", {}
    if wo.get("bounty_id"):
        try:
            import gnoc_economy as E
            bs = E.bounties()
        except Exception:  # noqa: BLE001
            bs = None
        if bs is not None and f"bty:{wo['bounty_id']}" not in bs:
            return False, f"bounty {wo['bounty_id']} is not on the economy board", {}
    return True, f"SALES ok: pay {why}; scope {v}; phase {phase}" + (f"; TRAP {trap} with new root cause" if trap else ""), \
        {"release_phase": phase}


def gate_intel(program, wo, path):
    md = _read(path)
    if not md:
        return False, f"seed pack missing or empty: {path}", {}
    d = _json_block(md)
    if d is None:
        return False, "seed pack has no ```json block {seeds, dedup, promises}", {}
    stamp = str((d.get("dedup") or {}).get("stamp") or "").strip() if isinstance(d.get("dedup"), dict) else ""
    if not stamp:
        return False, "seed pack has no dedup stamp (dedup.stamp: hq + public dedup result)", {}
    seeds = [s for s in (d.get("seeds") or []) if isinstance(s, dict)]
    keyed = [s for s in seeds if str(s.get("kill_byte") or "").strip()]
    if not keyed:
        return False, f"no seed carries a kill byte ({len(seeds)} seed(s), 0 with kill_byte)", {}
    live, dropped = [], []
    for s in keyed:
        hit = dnr_hit(program, s)
        (dropped if hit else live).append(dict(s, dnr=hit) if hit else s)
    if not live:
        return False, f"every seed with a kill byte matches do-not-rehunt ({dropped[0]['dnr']})", {"dropped": dropped}
    bad = [p for p in (d.get("promises") or []) if isinstance(p, dict) and
           not str(p.get("url") or "").startswith(("http://", "https://"))]
    if bad:
        return False, f"{len(bad)} vendor promise(s) without a URL", {}
    return True, f"INTEL ok: {len(live)} seed(s) live, {len(dropped)} dropped by do-not-rehunt, dedup {stamp[:60]}", \
        {"seeds": live, "dropped": dropped}


def gate_model(program, wo, path):
    d = _read_json(path)
    if d is None:
        return False, f"target model artifact missing or not JSON: {path}", {}
    bnd = [b for b in (d.get("boundaries") or []) if isinstance(b, dict)]
    if not bnd:
        return False, "target model has no trust boundaries", {}
    bad = [str(b.get("name") or i) for i, b in enumerate(bnd)
           if not str(b.get("asset") or "").strip() or not str(b.get("excludes") or "").strip()]
    if bad:
        return False, f"boundary without asset AND excluded actor: {', '.join(bad[:5])}", {}
    cat = d.get("catastrophic") or d.get("catastrophes") or []
    if not [c for c in cat if str(c).strip()]:
        return False, "catastrophe list is empty", {}
    return True, f"MODEL ok: {len(bnd)} boundaries, {len(cat)} catastrophes", {}


def gate_market(program, wo, path):
    import gnoc_oracle as O
    d = _read_json(path)
    if d is None:
        return False, f"market artifact missing or not JSON: {path}", {}
    hs = [h for h in (d.get("hyps") or []) if isinstance(h, dict)]
    if not hs:
        return False, "no hypothesis on the market (every proposal lacked A/V/P + kill byte)", {}
    orc = O.oracles(program)
    for h in hs:
        hid = h.get("hid")
        row = _hyp(program, hid) if hid else None
        if not row:
            return False, f"hypothesis {hid!r} is not in the gnoc_hunt ledger", {}
        miss = [k for k in ("assumption", "violation", "prediction", "kill_byte") if not str(row.get(k) or "").strip()]
        if miss:
            return False, f"{hid} missing {', '.join(miss).upper()}", {}
        o = orc.get(h.get("oracle_id") or "")
        if not o or o.get("hyp_id") != hid:
            return False, f"{hid} has no oracle COMMITTED (canary) before PROBE", {}
    return True, f"MARKET ok: {len(hs)} hypothesis(es), each with A/V/P, kill byte and a committed oracle", \
        {"hyps": hs}


def gate_probe(program, wo, path):
    """Floor and oracle by code. The finder's advisory outcome can only lower the verdict, never raise it."""
    import gnoc_hunt as H
    import gnoc_oracle as O
    d = _read_json(path)
    if d is None:
        return False, f"probe artifact missing or not JSON: {path}", {}
    hid = d.get("hyp_id")
    item = (wo.get("hyps") or {}).get(hid)
    if not item:
        return False, f"{hid!r} is not a hypothesis of this work order", {}
    # counted=True: probes spent on a route that only ever refused (gnoc_hunt.walled_routes, T-49) do not reach
    # the floor; 14 of program-101 H6's 20 probes were one 403 shape on an invented path (2026-10-25)
    probes, bursts = H.floor_status(program, hid, counted=True) if "counted" in H.floor_status.__code__.co_varnames \
        else H.floor_status(program, hid)
    o = O.oracles(program).get(item.get("oracle_id") or "") or {}
    adv = str(d.get("advisory") or "").upper()
    row = outcome_row(program, hid)
    if row and str(row.get("verdict") or "").upper() == "DEAD" and row.get("floor") != "met":
        return False, f"outcome row for {hid} claims DEAD with floor={row.get('floor')!r}", {}
    if o.get("status") == "passed":
        return True, f"PROBE ok: {hid} CANDIDATE, oracle {item['oracle_id']} PASS (code), {probes} probes", \
            {"verdict": "CANDIDATE", "probes": probes, "bursts": bursts}
    if probes < FLOOR:
        raw = H.floor_status(program, hid)[0]
        wall = f" ({raw} logged, {raw - probes} on a walled route that never answered 2xx)" if raw > probes else ""
        return False, f"floor: {probes} probes < {FLOOR} on {hid} (counted, gnoc_hunt ledger){wall} and no oracle PASS", \
            {"verdict": "UNFIRED", "probes": probes, "bursts": bursts}
    if bursts < 1:
        return False, f"floor: no burst with a serial control on {hid} (ledger bursts=0) and no oracle PASS", \
            {"verdict": "UNFIRED", "probes": probes, "bursts": bursts}
    verdict = "LEAD" if adv in ("LEAD", "CANDIDATE") else "DEAD"
    note = " (finder said CANDIDATE; no oracle PASS, so LEAD)" if adv == "CANDIDATE" else ""
    return True, f"PROBE ok: {hid} {verdict} at floor ({probes} probes, {bursts} burst){note}", \
        {"verdict": verdict, "probes": probes, "bursts": bursts}


def gate_escalate(program, wo, path):
    import gnoc_hunt as H
    d = _read_json(path)
    if d is None:
        return False, f"escalation artifact missing or not JSON: {path}", {}
    hid = d.get("hyp_id")
    item = (wo.get("hyps") or {}).get(hid) or {}
    if item.get("verdict") != "CANDIDATE":
        return False, f"{hid} PROBE verdict is {item.get('verdict')!r}: only an oracle PASS escalates", {}
    cap = str(d.get("capability") or "").strip()
    if not cap or cap.lower() in ("none", "n/a", "na", "-", "unknown"):
        return False, "capability gate: no NEW capability named", {}
    n = H.node(cap)
    if n not in H.CROWNS:
        return False, f"capability gate: {cap!r} is a standalone primitive, not a crown capability = LEAD", {}
    row = _hyp(program, hid) or {}
    if n in [H.node(r) for r in (row.get("requires") or [])]:
        return False, f"capability gate: the premise already grants {n}", {}
    ok, why = H.check_evidence(d.get("evidence"), d.get("must_contain"))
    if not ok:
        return False, f"capability gate: capture not on disk ({why})", {}
    dial = d.get("dial", 0)
    if dial not in (0, 1, 2):
        return False, f"intrusiveness dial must be 0, 1 or 2, not {dial!r}", {}
    return True, f"ESCALATE ok: {hid} -> {n}, captured at {d.get('evidence')}", {"capability": n}


def gate_qa(program, wo, path):
    import gnoc_economy as E
    import gnoc_hunt as H
    import gnoc_oracle as O
    import gnoc_pay as P
    d = _read_json(path)
    if d is None:
        return False, f"QA artifact missing or not JSON: {path}", {}
    hid = d.get("hyp_id")
    item = (wo.get("hyps") or {}).get(hid) or {}
    if item.get("station", 0) < 5:
        return False, f"{hid} has not passed ESCALATE", {}
    draft = d.get("draft_path")
    ok, why = H.check_evidence(draft)
    if not ok:
        return False, f"draft: {why}", {}
    md = _read(_abs(draft))
    for stamp in ("Dedup:", "Gate:"):
        if not re.search(rf"^{stamp}", md, re.M):
            return False, f"draft has no '{stamp}' header stamp", {}
    for sec in ("Summary", "Impact"):
        w = _section_words(md, sec)
        if w is None:
            return False, f"draft has no {sec} section", {}
        if w > WORD_CAP:
            return False, f"draft {sec} is {w} words (cap {WORD_CAP})", {}
    try:
        risk = float((d.get("dedup") or {}).get("matchRisk") or 0)
    except (TypeError, ValueError):
        risk = 100.0
    if risk >= 70:
        return False, f"public dedup: dedup-scout matchRisk {risk:.0f} >= 70", {}
    host = str(d.get("host") or "").lower()
    for ln in _read(PUBLIC_DEDUP).splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") == program and host and str(r.get("host") or "").lower() == host \
                and str(r.get("result") or "").upper().startswith("MATCH") \
                and (not d.get("class") or str(d.get("class")).lower() in str(r.get("class") or "").lower()):
            return False, f"public dedup ledger MATCH on {host} ({r.get('class')} {r.get('prior')})", {}
    cls = d.get("class") or wo.get("class") or ""
    odds, n = E.dupe_odds(cls, program)
    if n >= 3 and odds >= DUPE_ODDS_REFUSE:
        return False, f"filing futures: P(duplicate)={odds} over {n} resolved filings", {}
    ddir = os.path.dirname(_abs(draft))
    live = [p for p in glob.glob(os.path.join(ddir, "evidence", "liveness-*.json"))
            if time.time() - os.path.getmtime(p) < LIVENESS_MAX_S]
    if not live:
        return False, "no independent re-run of the terminal: evidence/liveness-*.json under 24 h (T-241)", {}
    pngs = glob.glob(os.path.join(ddir, "**", "*.png"), recursive=True)
    refuse, fadv = _finding_qa(ddir, draft)   # T1.5 + T1.6
    if refuse:
        return False, refuse, {}
    if _finding_mode() != "enforce" and len(pngs) < 2:   # enforce: the manifest's panel-pair check replaced this
        return False, (f"raw Burp panels: {len(pngs)} PNG(s) beside the draft, need a request+response pair"
                       + _finding_adv(fadv)), {}
    if str(d.get("repro") or "").upper() != "REPRODUCES":
        return False, f"repro-checker verdict is {d.get('repro')!r}, not REPRODUCES", {}
    kind = item.get("kind") or wo.get("oracle_class")
    phase = O.release_phase(kind, program)
    if phase == "preview" and not os.path.isfile(os.path.join(ddir, "RELEASE-ACK.md")):
        return False, f"release phase preview for {kind}: needs the user's per-draft RELEASE-ACK.md", {}
    if phase == "private" and not O.passed(program, hyp_id=hid):
        return False, f"release phase private for {kind}: needs a deterministic oracle PASS", {}
    fok, fwhy = P.filing_gate(program)
    if not fok:
        return False, f"pay gate at QA: {fwhy}", {}
    return True, f"QA ok: draft READY, dupe odds {odds} (n={n}), phase {phase}, {len(pngs)} panels" + _finding_adv(fadv), \
        {"draft_path": draft, "phase": phase, "dupe_odds": odds}


FINDING_GATE_ENV = "GNOC_FINDING_GATE"


def _finding_mode():
    """advisory (DEFAULT for the first week, spec SPEC-0security-alignment-20261109 T1.5/T1.6) | enforce | off."""
    v = str(os.environ.get(FINDING_GATE_ENV) or "advisory").strip().lower()
    return v if v in ("advisory", "enforce", "off") else "advisory"


def _finding_qa(ddir, draft):
    """(refusal or None, advisories). finding.json validator plus the evidence-manifest refusals: in enforce mode the
    first error refuses QA; in advisory mode they ride on the verdict text and the gate result is unchanged; off
    skips both. A model verdict never passes this; it only reads files (SPINE 8b)."""
    mode = _finding_mode()
    if mode == "off":
        return None, []
    try:
        import gnoc_finding as F
        errs = F.validate(ddir) + F.manifest_check(ddir)
    except Exception as e:  # noqa: BLE001
        errs = [f"finding check failed: {type(e).__name__}: {e}"]
    if mode == "enforce" and errs:
        more = f" (+{len(errs) - 1} more: python3 scripts/gnoc_finding.py check {os.path.dirname(str(draft))})" \
            if len(errs) > 1 else ""
        return f"finding record: {errs[0]}{more}", errs
    return None, errs


def _finding_adv(errs):
    return f" | finding advisory ({len(errs)}): {errs[0][:200]}" if errs else ""


def gate_books(program, wo, path):
    d = _read_json(path)
    if d is None:
        return False, f"books artifact missing or not JSON: {path}", {}
    hid = d.get("hyp_id")
    item = (wo.get("hyps") or {}).get(hid) or {}
    if item.get("station", 0) < 6:
        return False, f"{hid} has not passed QA", {}
    draft = d.get("draft_path") or item.get("draft_path")
    if not draft or _abs(draft) != _abs(item.get("draft_path")):
        return False, "draft path differs from the one QA passed", {}
    if os.sep + os.path.join("reports", "submitted") + os.sep in _abs(draft):
        return False, "draft already sits under reports/submitted", {}
    return True, f"BOOKS ok: {hid} to INBOX, pending the user's approval (approval is their only)", {"draft_path": draft}


def gate_retro(program, wo, path):
    d = _read_json(path)
    if d is None:
        return False, f"retro artifact missing or not JSON: {path}", {}
    props = [p for p in (d.get("proposals") or []) if isinstance(p, dict)]
    if len(props) != 3:
        return False, f"RETRO needs exactly three proposals, got {len(props)}", {}
    outc = _read(OUTCOMES)
    for i, p in enumerate(props, 1):
        if not str(p.get("kill_byte") or "").strip():
            return False, f"proposal {i} has no kill byte", {}
        rows = [str(r) for r in (p.get("rows") or []) if str(r).strip()]
        if not rows:
            return False, f"proposal {i} cites no rows", {}
        for r in rows:
            if not (os.path.exists(_abs(r)) and _abs(r).startswith(WS + os.sep)) and f'"{r}"' not in outc:
                return False, f"proposal {i} row {r[:60]!r} is neither a workspace file nor an outcomes.jsonl value", {}
    return True, "RETRO ok: three proposals, each with rows and a kill byte", {}


GATES = {0: gate_sales, 1: gate_intel, 2: gate_model, 3: gate_market, 4: gate_probe, 5: gate_escalate,
         6: gate_qa, 7: gate_books, 8: gate_retro}


# ---------------------------------------------------------------- the state machine

def _summary():
    """Rewrite .claude/state/economy/line.json from every targets/*/line/WO-*.json (the office renders it)."""
    out = {"updated": _now(), "programs": {}}
    for p in sorted(glob.glob(os.path.join(TARGETS, "*", "line", "WO-*.json"))):
        wo = _read_json(p)
        if not wo or wo.get("closed"):
            continue
        out["programs"].setdefault(wo.get("program", "?"), []).append(_wo_view(wo))
    try:
        with _locked(LINE_JSON):
            _write_json(LINE_JSON, out)
    except OSError:
        pass
    return out


def _rc_spent(wo):
    import gnoc_hunt as H
    tot = 0
    for hid in (wo.get("hyps") or {}):
        tot += H.floor_status(wo["program"], hid)[0]
    return tot


def _wo_view(wo):
    items = {h: f"{NAME.get(i.get('station', 3))}" + (f" {i['verdict']}" if i.get("verdict") else "")
             for h, i in (wo.get("hyps") or {}).items()}
    try:
        spent = _rc_spent(wo)
    except Exception:  # noqa: BLE001
        spent = 0
    return {"id": wo["id"], "station": wo.get("station", 0), "name": NAME.get(wo.get("station", 0)),
            "age_s": int(time.time() - _ts(wo.get("opened"))), "rc_spent": spent, "budget_rc": wo.get("budget_rc"),
            "class": wo.get("class"), "crown": wo.get("crown"), "items": items}


def open(program, wo):  # noqa: A001 - the spec names it open()
    """Station 0. Returns {ok, check, wo_id?}. A refused work order writes nothing."""
    program = _check_program(program)
    wo = dict(wo or {})
    wo["program"] = program
    ok, check, extra = gate_sales(program, wo)
    res = {"ok": ok, "station": 0, "name": "SALES", "check": check if ok else f"SALES refused: {check}"}
    if ok:
        wid = datetime.now(timezone.utc).strftime("%Y%m%d%H%M") + "-" + secrets.token_hex(2)
        wo.update(id=wid, opened=_now(), station=0, hyps={}, seeds=[], closed=False,
                  release_phase=extra["release_phase"],
                  history=[{"station": 0, "ts": _now(), "ok": True, "check": check}])
        with _locked(wo_path(program, wid)):
            _write_json(wo_path(program, wid), wo)
        res["wo_id"] = wid
        res["release_phase"] = wo["release_phase"]
        _summary()
    res["economy"] = _econ("line-advance", program=program, wo=res.get("wo_id"), station=0, ok=ok, check=check)
    return res


def _artifact_path(program, wo_id, station, artifact, hid=None):
    """A dict artifact is written by the line itself; a path is used as given (relative = workspace)."""
    if isinstance(artifact, dict):
        hid = hid or artifact.get("hyp_id")
        suffix = f"-{re.sub(r'[^A-Za-z0-9]', '', str(hid))}" if hid and station in ITEM_STATIONS else ""
        base = f"{ART[station]}-{wo_id}{suffix}"
        if station == 1:
            p = os.path.join(line_dir(program), base + ".md")
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with _bopen(p, "w") as fh:
                fh.write(f"# SEED PACK {wo_id} ({program})\n\n```json\n{json.dumps(artifact, indent=1)}\n```\n")
            return p
        p = os.path.join(line_dir(program), base + ".json")
        _write_json(p, artifact)
        return p
    return _abs(artifact)


def advance(program, wo_id, station, artifact):
    """Run one station's gate on an artifact. {ok, station, name, check, verdict?}. Refusal names the check."""
    program = _check_program(program)
    station = _station_no(station)
    res = {"ok": False, "station": station, "name": NAME.get(station, "?")}
    p = wo_path(program, wo_id)
    with _locked(p):
        wo = _read_json(p)
        if not wo:
            res["check"] = f"no work order {wo_id} for {program} (station 0 SALES must open it first)"
            return _emit(program, wo_id, res)
        if station not in GATES or station == 0:
            res["check"] = "station 0 runs only through open(); stations are 1..8"
            return _emit(program, wo_id, res)
        hid = artifact.get("hyp_id") if isinstance(artifact, dict) else None
        cur = wo.get("station", 0)
        if station in (1, 2, 3) and station > cur + 1:  # re-gating a passed station is allowed, never regresses
            res["check"] = f"{NAME[station]} refused: work order is at {NAME[cur]}; a station cannot be skipped"
            return _emit(program, wo_id, res)
        if station in ITEM_STATIONS + (8,) and cur < 3:
            res["check"] = f"{NAME[station]} refused: work order is at {NAME[cur]}, MARKET has not passed"
            return _emit(program, wo_id, res)
        try:
            ap = _artifact_path(program, wo_id, station, artifact, hid)
        except (OSError, ValueError) as e:
            res["check"] = f"{NAME[station]} refused: artifact not writable ({e})"
            return _emit(program, wo_id, res)
        if station in ITEM_STATIONS:
            hid = hid or (_read_json(ap) or {}).get("hyp_id")
            item = (wo.get("hyps") or {}).get(hid)
            if not item:
                res["check"] = f"{NAME[station]} refused: {hid!r} is not a hypothesis of WO {wo_id}"
                return _emit(program, wo_id, res)
            if item.get("station", 3) not in (station - 1, station) or \
                    (item.get("station") == station and station != 4):
                res["check"] = (f"{NAME[station]} refused: {hid} is at {NAME.get(item.get('station', 3))}; "
                                "a station cannot be skipped")
                return _emit(program, wo_id, res)
            if station == 4:
                _adjudicate(program, item, _read_json(ap) or {})
        if station == 8 and not any(i.get("station", 3) >= 4 for i in (wo.get("hyps") or {}).values()):
            res["check"] = "RETRO refused: no hypothesis on this work order reached PROBE"
            return _emit(program, wo_id, res)
        ok, check, extra = GATES[station](program, wo, ap)
        res.update(ok=ok, check=check if ok else f"{NAME[station]} refused: {check}", artifact=ap)
        if extra.get("verdict"):
            res["verdict"] = extra["verdict"]
        hist = {"station": station, "ts": _now(), "ok": ok, "check": res["check"][:300], "artifact": ap}
        if hid:
            hist["hyp_id"] = hid
        wo.setdefault("history", []).append(hist)
        if ok:
            _apply(wo, station, hid, extra, ap)
        _write_json(p, wo)
    if ok and station == 7:
        res["inbox"] = _inbox(program, wo_id, extra["draft_path"])
    if ok and station == 6:
        try:
            import gnoc_economy as E
            res["filing_market"] = E.filing_market("open", program, os.path.basename(
                os.path.dirname(_abs(extra["draft_path"]))), cls=wo.get("class") or "")
        except Exception:  # noqa: BLE001
            pass
    _summary()
    return _emit(program, wo_id, res)


def _emit(program, wo_id, res):
    res["economy"] = _econ("line-advance", program=program, wo=wo_id, station=res.get("station"),
                           ok=res.get("ok"), verdict=res.get("verdict"), check=res.get("check"))
    return res


def _adjudicate(program, item, art):
    """Before the PROBE gate: hand the finder's captures to gnoc_oracle.verify (non-AI). The gate then reads status."""
    caps = art.get("captures") or []
    oid = item.get("oracle_id")
    if not caps or not oid:
        return
    try:
        import gnoc_oracle as O
        if (O.oracles(program).get(oid) or {}).get("status") != "passed":
            O.verify(program, oid, caps)
    except Exception:  # noqa: BLE001 - a broken capture is a failed verify, not a crashed line
        pass


def _apply(wo, station, hid, extra, ap):
    if station in (1, 2, 3):
        wo["station"] = max(wo.get("station", 0), station)
    if station == 1:
        wo["seeds"] = extra.get("seeds", [])
        wo["seed_pack"] = ap
    if station == 3:
        for h in extra.get("hyps", []):
            wo.setdefault("hyps", {})[h["hid"]] = {"station": 3, "oracle_id": h.get("oracle_id"),
                                                   "kill_byte": h.get("kill_byte"), "wid": h.get("wid"),
                                                   "kind": h.get("kind"), "class": h.get("class")}
    if station in ITEM_STATIONS and hid:
        it = wo["hyps"][hid]
        it["station"] = station
        for k in ("verdict", "capability", "draft_path"):
            if extra.get(k):
                it[k] = extra[k]
    if station == 8:
        wo["retro"] = ap


def _inbox(program, wo_id, draft):
    line = (f"- [ ] {_now()} | {program} | {_abs(draft)} | LINE READY WO-{wo_id}: pending the user review and "
            "explicit approval (never auto-submitted)\n")
    try:
        with _locked(INBOX):
            with _bopen(INBOX, "a") as fh:
                fh.write(line)
        return "appended"
    except OSError as e:
        return f"inbox not written: {e}"


def _station_no(s):
    if isinstance(s, int):
        return s
    s = str(s).strip()
    if s.isdigit():
        return int(s)
    for n, name, _ in STATIONS:
        if name.lower() == s.lower():
            return n
    raise ValueError(f"unknown station {s!r}")


def market(program, wo_id, hyps):
    """Station 3 helper. Registers each proposal that carries ASSUMPTION/VIOLATION/PREDICTION + a kill byte in
    gnoc_hunt (which posts its economy market), commits one oracle per hypothesis, writes MK-<id>.json, advances.
    Returns the advance result plus hyps=[{wid, hid, oracle_id, kind, preimage, kill_byte}] and rejected=[...].
    The preimage is returned ONCE here (for the prober to plant) and is never written to the line state."""
    import gnoc_hunt as H
    import gnoc_oracle as O
    program = _check_program(program)
    wo = load_wo(program, wo_id)
    if not wo:
        return {"ok": False, "station": 3, "name": "MARKET", "check": f"no work order {wo_id}"}
    accepted, rejected, secret = [], [], {}
    for h in hyps or []:
        if not isinstance(h, dict):
            continue
        wid = str(h.get("id") or h.get("wid") or "")
        a, v, pr = (str(h.get(k) or "").strip() for k in ("assumption", "violation", "prediction"))
        kb = str(h.get("killByte") or h.get("kill_byte") or "").strip()
        miss = [n for n, x in (("ASSUMPTION", a), ("VIOLATION", v), ("PREDICTION", pr), ("kill byte", kb)) if not x]
        if miss:
            rejected.append({"wid": wid, "why": "missing " + ", ".join(miss)})
            continue
        out = H.hypothesis(program, "add", title=str(h.get("statement") or h.get("title") or wid)[:160],
                           crown=h.get("crown_class") or wo.get("crown"), assumption=a, violation=v, prediction=pr,
                           kill_byte=kb, boundary=h.get("boundary"), notes=f"line WO-{wo_id} {wid}")
        m = re.match(r"added (H\d+)", out or "")
        if not m:
            rejected.append({"wid": wid, "why": (out or "")[:160]})
            continue
        cls = str(h.get("class") or "").lower()
        kind = h.get("oracle") if h.get("oracle") in O.VALIDATORS else CLASS_ORACLE.get(cls, wo["oracle_class"])
        oid, pre = O.commit(program, m.group(1), kind, note=f"line WO-{wo_id} {wid}")
        accepted.append({"wid": wid, "hid": m.group(1), "oracle_id": oid, "kind": kind, "kill_byte": kb,
                         "class": cls})
        secret[m.group(1)] = pre
    res = advance(program, wo_id, 3, {"hyps": accepted, "rejected": rejected})
    res["hyps"] = [dict(a, preimage=secret[a["hid"]]) for a in accepted] if res.get("ok") else []
    res["rejected"] = rejected
    return res


def _sha_file(p):
    import hashlib
    with _bopen_b(p) as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _bopen_b(p):
    import builtins
    return builtins.open(p, "rb")


def _capture_ok(program, c):
    p = _abs(c)
    root = os.path.realpath(os.path.join(TARGETS, program)) + os.sep
    if not p.startswith(root):
        return None, f"{c}: a capture must sit under targets/{program}/"
    if not os.path.isfile(p) or os.path.getsize(p) == 0:
        return None, f"{c}: missing or empty"
    return p, ""


def _seen_path(program, hid):
    return os.path.join(line_dir(program), f"seen-{re.sub(r'[^A-Za-z0-9]', '', str(hid))}.txt")


def log_capture(program, hid, captures):
    """Feed the gnoc_hunt floor from Claude-lane captures: one probe per DISTINCT non-empty capture file under
    targets/<p>/ (sha256-deduplicated per hypothesis). A typed count is never accepted, only files on disk."""
    program = _check_program(program)
    if not _hyp(program, hid):
        return {"ok": False, "check": f"no hypothesis {hid!r} in the gnoc_hunt ledger of {program}"}
    sp = _seen_path(program, hid)
    logged, refused = 0, []
    with _locked(sp):
        seen = set(_read(sp).split())
        for c in captures or []:
            p, why = _capture_ok(program, c)
            if not p:
                refused.append(why)
                continue
            h = _sha_file(p)
            if h in seen:
                refused.append(f"{c}: same bytes already logged")
                continue
            import gnoc_hunt as H
            H.log_probe(program, hid, os.path.relpath(p, WS))
            seen.add(h)
            logged += 1
        os.makedirs(os.path.dirname(sp), exist_ok=True)
        with _bopen(sp, "w") as fh:
            fh.write("\n".join(sorted(seen)) + "\n")
    import gnoc_hunt as H
    probes, bursts = H.floor_status(program, hid)
    return {"ok": logged > 0, "logged": logged, "refused": refused, "probes": probes, "bursts": bursts,
            "check": f"logged {logged} capture(s) on {hid}; ledger {probes} probes, {bursts} burst(s)"}


def log_burst(program, hid, serial, captures):
    """A burst counts only with its SERIAL CONTROL capture plus >= 2 distinct burst captures on disk."""
    program = _check_program(program)
    if not _hyp(program, hid):
        return {"ok": False, "check": f"no hypothesis {hid!r} in the gnoc_hunt ledger of {program}"}
    sp_, why = _capture_ok(program, serial)
    if not sp_:
        return {"ok": False, "check": f"burst refused: serial control {why}"}
    shas = set()
    for c in captures or []:
        p, why = _capture_ok(program, c)
        if not p:
            return {"ok": False, "check": f"burst refused: {why}"}
        if p == sp_:
            return {"ok": False, "check": "burst refused: the serial control is not a burst arm"}
        shas.add(_sha_file(p) + p)
    if len(shas) < 2:
        return {"ok": False, "check": f"burst refused: {len(shas)} distinct burst capture(s), need >= 2"}
    import hashlib
    key = "burst:" + hashlib.sha256("".join(sorted(shas)).encode()).hexdigest()[:24]
    seen_p = _seen_path(program, hid)
    with _locked(seen_p):
        seen = set(_read(seen_p).split())
        if key in seen:
            return {"ok": False, "check": "burst refused: this exact burst was already logged"}
        import gnoc_hunt as H
        H.mark_burst(program, hid, len(shas))
        seen.add(key)
        os.makedirs(os.path.dirname(seen_p), exist_ok=True)
        with _bopen(seen_p, "w") as fh:
            fh.write("\n".join(sorted(seen)) + "\n")
    import gnoc_hunt as H
    probes, bursts = H.floor_status(program, hid)
    return {"ok": True, "probes": probes, "bursts": bursts,
            "check": f"burst of {len(shas)} with serial control logged on {hid}; ledger {probes} probes, {bursts} burst(s)"}


def current(program):
    """The newest open work order for a program, or None."""
    best = None
    for p in glob.glob(os.path.join(line_dir(program), "WO-*.json")):
        wo = _read_json(p)
        if wo and not wo.get("closed") and (best is None or wo.get("opened", "") > best.get("opened", "")):
            best = wo
    return best


def status(program=None):
    progs = [program] if program else sorted({os.path.basename(os.path.dirname(os.path.dirname(p)))
                                              for p in glob.glob(os.path.join(TARGETS, "*", "line", "WO-*.json"))})
    out = []
    for pg in progs:
        for p in sorted(glob.glob(os.path.join(line_dir(pg), "WO-*.json"))):
            wo = _read_json(p)
            if not wo or wo.get("closed"):
                continue
            v = _wo_view(wo)
            age = v["age_s"]
            out.append(f"{pg} WO-{v['id']} at {v['station']} {v['name']}  age {age // 3600}h{age % 3600 // 60:02d}m  "
                       f"RC {v['rc_spent']}/{v['budget_rc']}  {v['class']} -> {v['crown']}")
            for h, s in sorted(v["items"].items()):
                out.append(f"    {h} {s}")
            last = [x for x in wo.get("history", []) if not x.get("ok")][-1:]
            if last:
                out.append(f"    last refusal: {last[0]['check'][:160]}")
    return "\n".join(out) or "no open work orders"


def tids(cls, n=6):
    """Top-n Manual T-ids whose index line mentions the class (or its search terms)."""
    c = str(cls or "").lower()
    terms = (c,) + CLASS_TERMS.get(c, ())
    out = []
    for ln in _read(MANUAL_INDEX).splitlines():
        m = re.match(r"\|\s*\*\*(T-\w+)\*\*\s*\|\s*(.*?)\s*\|\s*\d+\s*\|", ln)
        if m and any(t and t in ln.lower() for t in terms):
            out.append(f"{m.group(1)}: {re.sub(r'[*]', '', m.group(2))[:110]}")
        if len(out) >= n:
            break
    return out


def brief(program, wo_id, bot=None):
    """The dispatch brief for the NEXT station of a work order (and of each open hypothesis on it)."""
    wo = load_wo(program, wo_id)
    if not wo:
        return f"no work order {wo_id} for {program}"
    cur = wo.get("station", 0)
    nxt = cur + 1 if cur < 3 else None
    items = wo.get("hyps") or {}
    lines = [f"# LINE BRIEF {program} WO-{wo_id}" + (f" for {bot}" if bot else ""),
             "",
             "MANAGER 1:1: <the manager writes this paragraph before dispatch; gnoc_line never generates it>",
             ""]
    if nxt is not None:
        lines.append(f"NEXT STATION: {nxt} {NAME[nxt]} (owner: {OWNER[nxt]}); its gate is code in "
                     f"scripts/gnoc_line.py gate_{NAME[nxt].lower()}")
    else:
        for h, it in sorted(items.items()):
            s = it.get("station", 3)
            if s < 7 and it.get("verdict") not in ("DEAD", "LEAD"):
                lines.append(f"NEXT STATION for {h}: {s + 1} {NAME[s + 1]} (owner: {OWNER[s + 1]})")
    show = {k: wo.get(k) for k in ("program", "crown", "class", "asset", "seed_hint", "new_root_cause", "budget_rc",
                                   "oracle_class", "release_phase", "bounty_id")}
    lines += ["", "WORK ORDER:", json.dumps(show, indent=1), ""]
    sp = wo.get("seed_pack")
    lines.append(f"SEED PACK: {sp or 'not yet passed (station 1 INTEL)'}")
    for s in wo.get("seeds") or []:
        lines.append(f"  - {s.get('id', '')} {s.get('host', '')} {s.get('endpoint', '')} class={s.get('class', '')} "
                     f"KILL BYTE: {s.get('kill_byte')}")
    lines.append("")
    budget = []
    for h, it in sorted(items.items()):
        try:
            import gnoc_economy as E
            b = E.budget(program, h)
        except Exception:  # noqa: BLE001
            b = "?"
        lines.append(f"ORACLE {it.get('oracle_id')} ({it.get('kind')}) for {h}; KILL BYTE: {it.get('kill_byte')}; "
                     f"market budget {b} probes; at {NAME.get(it.get('station', 3))}"
                     + (f" {it['verdict']}" if it.get("verdict") else ""))
        budget.append(b)
    lines += ["", f"FLOOR: >= {FLOOR} crafted live probes logged against the hypothesis AND a concurrent burst with a "
                  "serial control (gnoc_hunt.mark_burst), or an oracle PASS. The finder's verdict is advisory.",
              f"RELEASE PHASE: {wo.get('release_phase')} ({wo.get('oracle_class')})",
              f"BUDGET: {wo.get('budget_rc')} RC on the work order; spent {_rc_spent(wo)} RC",
              "", f"T-IDS for {wo.get('class')}:"]
    lines += [f"  {t}" for t in tids(wo.get("class"))] or ["  (none matched in Manual/MANUAL-INDEX.md)"]
    trap = trap_match(wo.get("class"))
    if trap:
        lines.append(f"TRAP CLASS: {trap}. New root cause: {wo.get('new_root_cause')}")
    return "\n".join(lines)


# ---------------------------------------------------------------- CLI

def _data(args):
    """--data <urlencoded JSON> | --json <file> | a path. Returns (dict|None, path|None)."""
    if "--data" in args:
        return json.loads(urllib.parse.unquote(args[args.index("--data") + 1])), None
    if "--json" in args:
        with _bopen(args[args.index("--json") + 1], "r") as fh:
            return json.load(fh), None
    return None, None


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "open":
            d, _ = _data(rest)
            r = open(rest[0], d or {})
        elif cmd == "advance":
            d, _ = _data(rest)
            r = advance(rest[0], rest[1], rest[2], d if d is not None else rest[3])
        elif cmd == "market":
            d, _ = _data(rest)
            hy = d if isinstance(d, list) else (d or {}).get("hyps", [])
            if "--file" in rest:
                for f in rest[rest.index("--file") + 1].split(","):
                    j = json.loads(_read(_abs(f)) or "[]")
                    hy += j if isinstance(j, list) else (j.get("hypotheses") or j.get("leaves") or [])
            if "--only" in rest:
                only = set(rest[rest.index("--only") + 1].split(","))
                hy = [h for h in hy if isinstance(h, dict) and str(h.get("id")) in only]
            r = market(rest[0], rest[1], hy)
        elif cmd == "show":
            wo = load_wo(rest[0], rest[1])
            r = {"ok": bool(wo), "wo": wo, "check": "work order found" if wo else
                 f"no work order {rest[1]} for {rest[0]}: station 0 SALES (gnoc_line.py open) must run first"}
        elif cmd == "log":
            r = log_capture(rest[0], rest[1], rest[2:])
        elif cmd == "burst":
            i = rest.index("--serial")
            r = log_burst(rest[0], rest[1], rest[i + 1], [x for j, x in enumerate(rest[2:], 2) if j not in (i, i + 1)])
        elif cmd == "current":
            wo = current(rest[0])
            r = {"ok": bool(wo), "wo": wo, "check": "open work order found" if wo else
                 f"no open work order for {rest[0]}: station 0 SALES (gnoc_line.py open) must run first"}
        elif cmd == "status":
            print(status(rest[0] if rest else None))
            return 0
        elif cmd == "brief":
            bot = rest[rest.index("--bot") + 1] if "--bot" in rest else None
            print(brief(rest[0], rest[1], bot))
            return 0
        elif cmd == "trap":
            print("\n".join(trap_list()))
            return 0
        else:
            print(f"unknown command {cmd}; one of open|advance|market|current|show|log|burst|status|brief|trap", file=sys.stderr)
            return 2
    except IndexError:
        r = {"ok": False, "check": f"usage error: '{cmd}' is missing argument(s); run `gnoc line help` for the forms"}
    except (ValueError, OSError) as e:
        r = {"ok": False, "check": f"usage/input error: {type(e).__name__}: {e}"}
    print(json.dumps(r, default=str))
    return 0 if r.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
