#!/usr/bin/env python3
"""Continuous-learning consolidator. Rolls the deterministic worker-outcome ledger
(.claude/state/learning/outcomes.jsonl, appended by the subagent-floor-gate hook) plus
the freshest H1 triager sync into a short LESSONS.md that learning-inject.sh feeds back
into every hunt prompt. Rule-based tally, no model calls. Idempotent - safe to re-run.

ponytail: a tally, not an analytics pipeline. Upgrade to per-program/per-class rollups
only if a profiler (i.e. real usage) shows the flat digest is too coarse to steer by.
"""
import json, os, re, collections, datetime

ROOT = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LDIR = f"{ROOT}/.claude/state/learning"
OUTC = f"{LDIR}/outcomes.jsonl"
# FIX (2026-10-22): the learning loop was SPLIT-BRAINED. This consolidator read only the floor-gate
# hook's ledger above, while every hunting agent records its real verdicts through
# `scripts/hunt-state.py append-outcome` into the ledger below (HARNESS.md section 3a). The two files
# have different schemas, so ~890 agent-authored outcomes - every DEAD/LEAD/CRITICAL-CANDIDATE, with
# probe counts and floor claims - contributed NOTHING to the steering block, and the hook ledger it
# did read carries a literal verdict:"other" on 81% of its rows. Read BOTH, normalised.
HUNT_OUTC = f"{ROOT}/.claude/state/hunt-loop/outcomes.jsonl"
H1 = f"{ROOT}/scripts/h1-feedback/triager_analysis.latest.json"
LESSONS = f"{LDIR}/LESSONS.md"
WINDOW = 300  # last N worker outcomes

# FIX (2026-07-19): synthetic/test outcome rows (hook self-tests, floor-gate probes, win-precedence
# fixtures) were interleaved with real hunt data and inflated every outcomes-derived count - incl. a
# FAKE verdict:"win". Drop any row whose session id looks like a test fixture BEFORE any aggregate.
# Matches: test-session-*, *-test / test-*, ^floortest*, ^fgtest*, ^digest-fix*, win-precedence*, wtest.
_TEST_SESSION = re.compile(r"(?:^|-)test(?:-|$)|^floortest|^fgtest|^digest-fix|win-precedence|^wtest$|test-session-")


def _is_test_row(r):
    # the gate ledger keys this as `session`, the agent ledger as `lane`
    return bool(_TEST_SESSION.search(str(r.get("session") or r.get("lane") or "")))


# canonical verdict buckets, so one spelling is counted one way no matter which ledger wrote it
_CANDIDATE = ("critical-candidate", "medium-candidate", "finding-candidate", "candidate")


def _norm(r, src):
    """One row shape from two ledgers.
    gate  = the floor-gate hook: lowercase verdict, `receipt`, `probe_count`, `role`, `session`.
    hunt  = an agent via hunt-state.py: UPPERCASE verdict enum, `floor`/`probes`/`burst`, `lane`.
    An agent row is hunt work by construction, so it carries role=hunter; its floor receipt is the
    `floor` field reading "met...", which is this schema's spelling of `receipt`."""
    out = dict(r)
    v = str(r.get("verdict") or "other").strip().lower()
    if v.startswith("dead"):
        v = "dead"
    elif v in _CANDIDATE:
        v = "candidate"
    elif v not in ("lead", "win", "unfired", "needs", "other"):
        v = "other"
    out["verdict"] = v
    out["_src"] = src
    if src == "hunt":
        out.setdefault("role", "hunter")
        try:
            out["probe_count"] = int(r.get("probes") or 0)
        except (TypeError, ValueError):
            out["probe_count"] = 0
        out["probed"] = out["probe_count"] > 0
        out["receipt"] = r.get("receipt") or str(r.get("floor") or "").lower().startswith("met")
    return out


def load_jsonl(p):
    rows = []
    if not os.path.exists(p):
        return rows
    for line in open(p, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue  # tolerate a malformed capture line
    return rows


os.makedirs(LDIR, exist_ok=True)
_gate_rows = [_norm(r, "gate") for r in load_jsonl(OUTC)]
_hunt_rows = [_norm(r, "hunt") for r in load_jsonl(HUNT_OUTC)]
# merged and ordered by time, so WINDOW really is the newest N across BOTH ledgers
_all_raw = sorted(_gate_rows + _hunt_rows, key=lambda r: str(r.get("ts") or ""))
_test_n = sum(1 for r in _all_raw if _is_test_row(r))
_all = [r for r in _all_raw if not _is_test_row(r)]  # real rows only for every derived count
# FIX 3d (2026-07-19): the probe-return population is HUNTERS only (role tag from the floor gate).
# FIX 3d-v2 (2026-07-19): role field was added late; only 4 rows carry it, making the hunter-only
# filter useless on the legacy population. Include legacy rows where role is ABSENT and probed==True
# (the pre-role signal that distinguishes hunters from support/orchestrator in older outcomes).
# Support and orchestrator rows are excluded from all probe/receipt aggregates.
out = [r for r in _all
       if r.get("role") == "hunter"
       or (r.get("role") is None and r.get("probed") is True)][-WINDOW:]
support_n = len([r for r in _all if r.get("role") == "support"])
n = len(out)
vc = collections.Counter(r.get("verdict", "other") for r in out)
dead = [r for r in out if r.get("verdict") == "dead"]
# Receipt-rate over AGENT rows only. A `gate` row is the floor-gate hook recording a dead claim it
# BLOCKED and it never populates its own `receipt` field, so including gate rows pinned the rate near
# zero no matter how the agents behaved: measured 2026-10-27, the window's dead rows were 126 gate rows
# and ZERO agent rows, and the blob still printed "receipt-rate 15%" as if hunters were skipping the
# work. The 2026-10-22 FIX comment below names this exact mis-attribution; it was never applied here.
_dead_win_own = [r for r in dead if r.get("_src") == "hunt"]
_dead_win_gate = [r for r in dead if r.get("_src") == "gate"]
dead_no_receipt = sum(1 for r in _dead_win_own if not r.get("receipt"))
rrate = (100 * (len(_dead_win_own) - dead_no_receipt) // len(_dead_win_own)) if _dead_win_own else 0


# FIX (2026-10-22): "receipt-rate" alone conflated two DIFFERENT failures and mis-attributed both -
# a hook that never populates its own `receipt` field read as hunters skipping the work. Decompose
# over EVERY dead claim in BOTH ledgers, which is where the discipline actually shows:
#   probe-floor violation = a DEAD recorded on fewer than 8 real probes
#   burst skipped         = a DEAD that has the probes but no concurrent burst
# SPINE 4 requires both before a DEAD, so these are the two numbers worth steering by.
def _pc(r):
    try:
        return int(r.get("probe_count") or 0)
    except (TypeError, ValueError):
        return 0


# The burst half of the floor became a CODE GATE in hunt-state.py on 2026-10-22 (a DEAD with floor=met
# now needs burst=true or a written not_single_use reason). Everything before that date is history, and
# counting it here made this blob - which is injected into EVERY session - lecture the agent about a
# defect that was already fixed: measured 2026-10-27, since the gate there are 4 DEAD rows and ZERO
# burst-less ones, while the headline still read "426 of 698 had no burst". A steering signal dominated
# by dead history hides a live regression. So split them: audit the PRE-GATE rows as history, and judge
# the post-gate rows on their own.  (Pre-gate breadth-sweep rows were separately retired to UNFIRED by
# scripts/learn/retire-sweep-deads.py - see Manual T-266.)
#
# AND audit only the `hunt` rows. A `gate` row IS the floor-gate hook recording a dead claim it
# BLOCKED, so a gate row with probe_count<8 is the gate working, not a verdict that got through.
# Counting those as violations said "126 live regressions" on a first pass of this very change
# (2026-10-27) when the real number of agent-written dead claims since the gate was 4.
_GATE_DAY = "2026-10-22"
_dead_all = [r for r in _all if r.get("verdict") == "dead"]
_dead_own = [r for r in _dead_all if r.get("_src") == "hunt"]
_dead_live = [r for r in _dead_own if str(r.get("ts", "")) >= _GATE_DAY]
_dead_hist = [r for r in _dead_own if str(r.get("ts", "")) < _GATE_DAY]
_dead_blocked = [r for r in _dead_all if r.get("_src") == "gate" and str(r.get("ts", "")) >= _GATE_DAY]
_dead_lowprobe = [r for r in _dead_live if _pc(r) < 8]
_dead_noburst = [r for r in _dead_live if _pc(r) >= 8 and not r.get("burst")
                 and not str(r.get("not_single_use") or "").strip()]
_src_mix = collections.Counter(r.get("_src") for r in out)

L = []
L.append("# LESSONS (auto, dynamic) - self-learning feedback")
L.append(f"<!-- generated {datetime.datetime.now(datetime.timezone.utc).isoformat()} by scripts/learn/consolidate.py -->")
L.append("")

# TELEMETRY HEALTH self-check (2026-07-16): the root cause of "nothing improves" was corrupt
# telemetry going undetected for weeks. Flag the exact regressions that were fixed, so a broken
# gauge surfaces in the NEXT session instead of silently rotting the learning loop. Silent when OK.
_polluted = sum(1 for r in _all if (not r.get("probed")) and (r.get("probe_count") or 0) > 0)
_orch = sum(1 for r in _all if r.get("role") == "orchestrator")   # FIX 3d: role-gate leak sentinel
if _test_n:  # transparency: N synthetic/test rows were dropped from every count below
    L.append(f"<!-- excluded {_test_n} synthetic/test outcome rows (test-session/floortest/fgtest/digest-fix/win-precedence/wtest) from all counts -->")
_ships = load_jsonl(f"{ROOT}/.claude/state/hunt-loop/ships.jsonl")
_health = []
if _polluted:
    _health.append(f"outcomes.jsonl re-polluting: {_polluted} non-probed records carry a probe_count>0 - the floor-gate JOB-1 write regressed (should write 0 when not probed).")
if _orch:
    _health.append(f"orchestrator rows leaking into outcomes.jsonl ({_orch}) - the floor-gate role-gate (FIX 3c) regressed; the write must SKIP role=orchestrator.")
if not _ships:
    _health.append("ships.jsonl is EMPTY - the north-star is not recording; draft-surface.sh append may be unwired.")
# FIX (2026-10-21): a SINGLE session can dominate the whole outcomes.jsonl population when the
# floor-gate's role classifier (a FIRSTMSG keyword regex, not an actual hunt confirmation) tags a
# long non-hunting session as role:"hunter" and then re-fires on every one of its turns. Found by a
# workspace audit: 71 of 89 rows in this exact file traced to one session whose content was entirely
# about scp'ing a script to a Windows desktop - zero bug-hunting content - because its first message
# happened to contain a hunt-adjacent keyword. That session alone was silently setting every stat
# below (dead-claim rate, verdict mix). Detector only (does not drop rows; this file is a tally, not
# a filter) - surfaces the session id so a human can judge whether the population is real.
_session_counts = collections.Counter(r.get("session") for r in _all if r.get("session") and not _is_test_row(r))
if _session_counts:
    _dom_session, _dom_n = _session_counts.most_common(1)[0]
    _dom_frac = _dom_n / max(1, len(_all))
    if _dom_n >= 20 and _dom_frac >= 0.4:
        _health.append(
            f"POPULATION DOMINATED BY ONE SESSION: {_dom_session} alone contributes {_dom_n}/{len(_all)} "
            f"rows ({_dom_frac:.0%}) to outcomes.jsonl. Every count below may just be describing that one "
            f"session, not the hunt population. Check its role tag and content before trusting the stats "
            f"(see the role-classifier finding in the 2026-10-21 workspace audit receipt, "
            f"CLAUDE-HANDOFF-CRITICAL-10-04.md)."
        )
if _health:
    L.append("## TELEMETRY HEALTH - ACTION NEEDED (a gauge is broken; fix before trusting the numbers below)")
    L.extend(f"- {h}" for h in _health)
    L.append("")

# NOTE (2026-07-19): the "## AGGRESSION MANDATE" static block was removed here - it duplicated
# CLAUDE.md verbatim (the mandate remains authoritative there). This is a de-duplication of the
# generated LESSONS output, NOT a reduction of aggression. The dynamic sections below
# (kill-rules, worker outcomes, H1 stats) stay - they are the self-learning signal.

# Open findings (pipeline-sweep ledger). Every open item has an owner and a cadence; only FILED and
# DEAD-CONFIRMED are quiet (SPEC-pipeline-sweep-20261021.md change 3). Falls back to the old regex count.
import re as _re, glob as _g, os as _os, json as _json
_ledger_p = f"{ROOT}/.claude/state/hunt-loop/rescue-ledger.json"
_led = None
try:
    _led = _json.load(open(_ledger_p, encoding="utf-8"))
except Exception:
    _led = None
if isinstance(_led, dict) and len(_led) > 1:
    from datetime import datetime as _dt, timezone as _tz
    _rows = [v for k, v in _led.items() if k != "_meta" and isinstance(v, dict) and not v.get("gone_from_disk")]
    _cnt = {}
    for _v in _rows:
        _s = _v.get("state", "?")
        if _s == "DEAD-CONFIRMED":
            _s = f"DEAD-CONFIRMED({(_v.get('dead_reason') or '').split(':', 1)[0]})"
        _cnt[_s] = _cnt.get(_s, 0) + 1
    _now = _dt.now(_tz.utc)
    _stale = []
    for _v in _rows:
        if _v.get("state") in ("FILED", "DEAD-CONFIRMED"):
            continue
        try:
            _lt = _dt.strptime(_v.get("last_touched") or "", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc)
            if (_now - _lt).days > 7:
                _stale.append(_v["id"])
        except ValueError:
            pass
    _prom = [_v["id"] for _v in _rows if _v.get("state") in ("PROMOTE", "EXHAUSTED-FILABLE")]
    L.append("## Open findings (pipeline-sweep)")
    L.append(f"- Ledger {(_led.get('_meta') or {}).get('last_sweep', '?')}: " +
             ", ".join(f"{k}={_cnt[k]}" for k in sorted(_cnt)) +
             ". Board: .claude/state/hunt-loop/RESCUE-BOARD.md; per item: scripts/learn/pipeline-sweep.py show <id>.")
    if _stale:
        L.append(f"- STALE (>7d untouched, {len(_stale)}): " + ", ".join(sorted(_stale)))
    if _prom:
        L.append("- orchestrator: run SPINE 5 ship order, then ask the user to approve: " + ", ".join(sorted(_prom)))
    L.append("")
else:
    _dead = 0
    for _f in _g.glob(f"{ROOT}/reports/drafts/**/*.md", recursive=True):
        try:
            _b = open(_f, encoding="utf-8", errors="replace").read(8000)
        except Exception:
            continue
        if _re.search(r'KILLED|HELD|NOT[- ]SUBMIT|KILL-PENDING', _b) and not _re.search(r'by[- ]design|duplicate|out of scope|\bOOS\b|risk[- ]accepted', _b, _re.I):
            _dead += 1
    if _dead:
        L.append("## Rescuable dead findings")
        L.append(f"- {_dead} killed/held draft(s) may be RESCUABLE (died for depth, not a triager verdict). Run scripts/learn/rescue.sh - salvage with MORE TIME (push the missing terminal leg) or a SIMILAR-SEARCH (sibling host / adjacent class / staging twin), do not leave them dead.")
        L.append("")

# Hard kill-rules mined from real triager comments (newest TRIAGER-KILLRULES file) - most valuable, first.
import glob as _glob
_kr = sorted(_glob.glob(f"{ROOT}/patterns/kill-knowledge/TRIAGER-KILLRULES-*.md"))
if _kr:
    _rules = []
    for _ln in open(_kr[-1], encoding="utf-8", errors="replace"):
        _s = _ln.strip()
        if _s.startswith("- **RULE"):
            _rules.append(_s.replace("**", "").lstrip("- "))
        if len(_rules) >= 6:
            break
    if _rules:
        L.append("## Hard kill-rules from real triager comments (apply BEFORE submit)")
        L.extend(f"- {_r}" for _r in _rules)
        L.append("")

L.append(f"## Our own worker outcomes (last {n})")
if n:
    L.append("- verdicts: " + ", ".join(f"{k}={v}" for k, v in vc.most_common()))
    L.append(f"- window source mix: " + ", ".join(f"{k}={v}" for k, v in _src_mix.most_common())
             + "  (gate = floor-gate hook, hunt = agent via hunt-state.py)")
    if _dead_win_own:
        L.append(f"- dead claims in window: {len(_dead_win_own)} agent-written; {dead_no_receipt} carried no "
                 f"floor receipt (receipt-rate {rrate}%)."
                 + (f" The floor-gate hook separately BLOCKED {len(_dead_win_gate)} under-floor dead claim(s) "
                    "in the same window - those are refusals, not agent misses."
                    if _dead_win_gate else ""))
    elif _dead_win_gate:
        L.append(f"- dead claims in window: 0 agent-written. The floor-gate hook BLOCKED "
                 f"{len(_dead_win_gate)} under-floor dead claim(s) - that is the gate working, not a miss.")
    if _dead_live:
        _bad = len(_dead_lowprobe) + len(_dead_noburst)
        if _bad:
            L.append(f"- FLOOR AUDIT, dead claims since the burst gate went in ({_GATE_DAY}): "
                     f"{len(_dead_live)} total, {len(_dead_lowprobe)} under the 8-probe floor, "
                     f"{len(_dead_noburst)} with the probes but NO concurrent burst. SPINE 4 requires BOTH, "
                     f"so these are LIVE regressions - the gate should have refused them. Investigate.")
        else:
            L.append(f"- FLOOR AUDIT: the burst gate ({_GATE_DAY}) is HOLDING - {len(_dead_live)} "
                     f"agent-written dead claim(s) since, none under the probe floor, none burst-less; the "
                     f"hook separately blocked {len(_dead_blocked)} under-floor dead claim(s). "
                     f"({len(_dead_hist)} older pre-gate rows are history, not a live signal.)")
    elif _dead_hist:
        L.append(f"- FLOOR AUDIT: no dead claims at all since the burst gate ({_GATE_DAY}); "
                 f"{len(_dead_hist)} pre-gate rows remain as history.")
    # Only lecture when the LIVE rows earn it. The window reaches back past the 2026-10-22 burst gate, so
    # this fired on pre-gate history every session and read as a standing accusation against the agent.
    if _dead_live and rrate < 60:
        L.append(f"- STEER: dead-claim receipt-rate is low ({rrate}%). Before returning DEAD, fire the untried "
                 "variants (concurrent burst, second-handler, un-keyed side, enforcer-twin, sibling host) and report "
                 "counts. The floor gate rejects a bare dead.")
else:
    L.append("- (no worker outcomes captured yet - the floor gate will populate this)")
L.append("")

# NORTH-STAR (FIX 4 2026-07-19): the cash proxy is H1 POSITIVE-STATE per program, NOT draft count.
# SPINE 0 forbids optimizing proxies; draft-count was a Goodhart proxy (53% of drafts never
# submitted). Load h1 here so the positive-state metric prints ABOVE the demoted draft log.
h1 = None
if os.path.exists(H1):
    try:
        h1 = json.load(open(H1))
    except Exception:
        h1 = None

ships = load_jsonl(f"{ROOT}/.claude/state/hunt-loop/ships.jsonl")
POS = {"resolved", "triaged", "retesting", "pending-program-review"}

def _class_steer(min_n=4):
    """The class table, ordered by what was ACCEPTED, straight from the adjudicated ledger.

    Steering by draft-count is the Goodhart trap SPINE 0 warns about: 53% of drafts are never submitted and
    draft-count has never predicted cash. Classes with n < min_n are not printed as steer (too thin to act on).
    """
    import json as _json
    led_path = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "research/technique/PRECISION-LEDGER.json")
    try:
        led = _json.load(open(led_path))
        by = led.get("by_class") or {}
    except Exception:
        return ["- CLASS STEER: precision ledger unreadable; fall back to business-logic and auth first, "
                "and query scripts/bbtools/prt.py precision --class <name> before opening a class."]
    rows = [(c, d) for c, d in by.items() if (d.get("n") or 0) >= min_n]
    if not rows:
        return []
    rows.sort(key=lambda kv: (-(kv[1].get("precision_pct") or 0), -(kv[1].get("n") or 0)))
    fmt = lambda c, d: (f"{c} {d.get('precision_pct', 0)}% ({d.get('positive', 0)}/{d.get('n', 0)}"
                        + (f", {d['dupe_pct']}% dupes" if d.get("dupe_pct") else "") + ")")
    best = [fmt(c, d) for c, d in rows[:4]]
    worst = [fmt(c, d) for c, d in rows[-4:]][::-1]
    out = [f"## CLASS STEER (what triagers ACCEPTED, n={led.get('n_adjudicated', '?')}; this outranks draft-count)"]
    out.append("- OPEN HERE (best converters): " + "; ".join(best))
    out.append("- TRAP, these are our WORST converters and the ones we hunt most: " + "; ".join(worst))
    out.append("- CHAIN, do not stop at the easy bug: land the high-converter first, then escalate it with the "
               "five moves (same defect on a higher-value asset, what the disclosure UNLOCKS, the paired write, "
               "the partner bug, the missing context). A business-logic or auth primitive is the SOURCE leg of "
               "an ATO/money chain, not the finding.")
    out.append("- Before opening any class on a program: scripts/bbtools/prt.py precision --class <name> "
               "--program <handle>. A high dupe_pct means the asset is already fully hunted; pick another class.")
    return out

if h1:
    pos = [r for r in h1 if r.get("state") in POS]
    pos_by_prog = collections.Counter(r.get("program") for r in pos)
    # FIX (2026-07-19): the label hard-coded "resolved/triaged/retesting" (=33) while the value was
    # len(pos) over the wider POS set incl. pending-program-review (=34) - an internal off-by-1.
    # Build the label AND the breakdown from the SAME state counts so the value always == the sum.
    pos_by_state = collections.Counter(r.get("state") for r in pos)
    _pos_label = "/".join(f"{k}={v}" for k, v in sorted(pos_by_state.items()))
    drafted_progs = collections.Counter(s.get("program") for s in ships)
    submitted_progs = collections.Counter(r.get("program") for r in h1)
    # FIX (2026-09-30): the de-rank set conflated NEVER-FILED with FILED-AND-FAILED, and so
    # permanently de-ranked every non-H1 venue by construction. A program that has no H1
    # report at all (self-hosted like program-64, or Immunefi, or simply not submitted yet)
    # can never hold an H1 positive state, so its absence says nothing about conversion.
    # De-rank ONLY a program we actually FILED to H1 (it appears in the H1 data) that still
    # has zero positive state. The never-filed pile gets its own honest line below.
    zero_pos = [p for p in drafted_progs
                if p and p in submitted_progs and p not in pos_by_prog]
    never_filed = [p for p in drafted_progs if p and p not in submitted_progs]
    L.append("## NORTH-STAR: H1 positive-state per program (the CASH proxy - steer by THIS, not draft count)")
    L.append(f"- positive: {len(pos)} across {len(pos_by_prog)} programs (by state: {_pos_label})")
    L.append(f"- top converters: {pos_by_prog.most_common(6)}")
    L.append("- STEER: pour effort into the CONVERTER shape (initech-like: fresh/low-saturation, unauth "
             "race + info-disclosure + stored-XSS). A drafted-but-never-submitted pile is NOT progress.")
    L.append(f"- RECONCILE: {len(zero_pos)} programs were FILED to H1 and still hold ZERO positive state - de-rank them"
             + (f" ({', '.join(sorted(p for p in zero_pos if p)[:8])})" if zero_pos else "") + ".")
    if never_filed:
        L.append(f"- BACKLOG: {len(never_filed)} programs have drafts NEVER FILED anywhere "
                 f"({', '.join(sorted(never_filed)[:8])}) - this is unrealised value sitting on disk, "
                 "NOT a conversion failure. Do not de-rank on this line; either file them or kill them "
                 "with a reason. Non-H1 venues (self-hosted, Immunefi) will never appear in H1 state data.")
    L.append("")

# Draft log (FIX 4): retitled from "North-star receipts" - a draft is a LOG entry, not the metric
# (53% were never submitted, zero cash). Steer by the H1 positive-state block above, not this count.
# FIX (2026-07-19): ships.jsonl mixes kinds - LABEL them (draft vs submitted vs other), do NOT call
# the total "drafts". And RECONCILE the ledger against the on-disk .md files so a future drift shows.
if ships:
    prog = collections.Counter(s.get("program") for s in ships)
    _kc = collections.Counter(s.get("kind") or "other" for s in ships)
    _n_draft = _kc.get("draft", 0)
    _n_sub = _kc.get("submitted", 0)
    _n_other = sum(v for k, v in _kc.items() if k not in ("draft", "submitted"))
    # COUNT THE CANONICAL UNIT, not every markdown file in the tree. CLAUDE.md fixes the draft
    # shape as reports/drafts/<program>/<slug>/report.md plus sidecars (GATES.md, FORM.md,
    # HELD-REASON.md, SOURCE-LINES.md, numbered form sections). Globbing **/*.md counted those
    # sidecars as drafts and reported 146 for 46 real drafts, and 17 for 2 real submissions, which
    # made the RECONCILE line below scream a false ledger/disk divergence every single session.
    # Fixed 2026-10-12.
    _disk_draft = len(_g.glob(f"{ROOT}/reports/drafts/**/report.md", recursive=True))

    def _submission_units(base):
        """A submission is one of two shapes: <program>/<slug>/report.md, or a flat
        <program>/<slug>.md. Everything under form/, triage-reply*/ or attachments/ is a PART of a
        submission, never a submission."""
        units = set()
        for f in _g.glob(f"{base}/**/*.md", recursive=True):
            rel = _os.path.relpath(f, base)
            parts = rel.split(_os.sep)
            if any(seg == "form" or seg == "attachments" or seg.startswith("triage-reply")
                   for seg in parts[:-1]):
                continue
            if parts[-1] == "report.md" and len(parts) >= 2:
                units.add(_os.sep.join(parts[:-1]))          # <program>/<slug>/
            elif len(parts) == 2:
                units.add(rel)                               # <program>/<slug>.md
        return units

    _disk_sub = len(_submission_units(f"{ROOT}/reports/submitted"))
    _label = f"{_n_draft} drafts, {_n_sub} submitted" + (f", {_n_other} other" if _n_other else "")
    L.append(f"## Ship log (a LOG, not the steering metric - 53% of drafts never submitted): {_label} across {len(prog)} programs")
    # RECONCILE ledger vs disk - print both when they diverge so drift is visible next session.
    if _n_draft != _disk_draft or _n_sub != _disk_sub:
        L.append(f"- RECONCILE(ledger vs disk): drafts ledger={_n_draft}/disk={_disk_draft}, submitted ledger={_n_sub}/disk={_disk_sub} - a divergence means the ships.jsonl append or a manual file move drifted; trust the DISK count.")
    L.append("- top ship-programs: " + ", ".join(f"{k}={v}" for k, v in prog.most_common(6)))
    # HOW we hunt (still true, and class-independent): unauth first, always from a seed.
    L.append("- WIN-SHAPE (how, measured over 67 shipped findings): 88% are UNAUTH / zero-credential; 97% opened "
             "from a SEED (pre-mined JS/GraphQL route, disclosed-report, vendor-doc at the seam), ~1% from cold "
             "subdomain enum.")
    # WHICH class to hunt: driven by what triagers ACCEPTED, never by what we wrote. The old line here named the
    # four classes that dominate our DRAFTS and sent every session at them; measured against the adjudicated
    # ledger those same classes convert at 6-20% while the one we barely hunt converts at 83% (2026-10-22).
    L.extend(_class_steer())
    L.append("- STEER: open every target UNAUTH on its authz/disclosure surface from a seed; provision an authed 2nd "
             "account only to ESCALATE a specific credential-gated crown (that wall is 47% of quits and where the "
             "unshipped crits sit). 28% of past effort went to targets that NEVER shipped - de-rank those.")
    L.append("")

if h1:
    NEG = {"informative", "not-applicable", "duplicate", "spam"}
    neg = [r for r in h1 if r.get("state") in NEG]
    tc = collections.Counter()
    for r in neg:
        for t in (r.get("tags") or "").split(","):
            if t:
                tc[t] += 1
    st = collections.Counter(r.get("state", "?") for r in h1)
    L.append(f"## H1 triager reality ({len(h1)} reports, {len(neg)} negative-closed)")
    L.append("- states: " + ", ".join(f"{k}={v}" for k, v in st.most_common()))
    L.append("- kill tags: " + ", ".join(f"{k}={v}" for k, v in tc.most_common(6)))
    top = tc.most_common(1)
    if top and top[0][0] not in ("(no-comment)", "(unclassified)"):
        L.append(f"- DOMINANT KILL: '{top[0][0]}' ({top[0][1]}). Clear the CAPABILITY GATE (a NEW "
                 "cross-tenant / state-change / exfil / RCE capability captured in a response) before ship.")
    L.append("")

open(LESSONS, "w", encoding="utf-8").write("\n".join(L) + "\n")
print(f"consolidate: wrote {LESSONS} ({n} worker outcomes, H1={'yes' if h1 else 'no'})")
