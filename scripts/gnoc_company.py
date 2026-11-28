#!/usr/bin/env python3
"""gnoc_company.py - the bots run the business; orch-bot is the manager (spec SPEC-xbow-intel-economy-20261022 s5).

orch-bot calls manage(st) once per tick (one wrapped step, it never blocks or breaks a tick). Each duty below is a
small function with its own cadence, its last run stored in .claude/state/economy/company.json:

    payroll   roster from gnoc_economy (wallet, brier, status, assignment, morale); a bot under 100 RC is on probation
    sales     programs we can FILE on (gnoc_pay.filing_gate), ranked by the class steer and freshness; the treasury
              funds bounties for the top 3 crowns (300 medium / 600 high / 1000 critical, scaled by class acceptance)
              and opens one WORK ORDER per bounty through gnoc_line.open (station 0 of THE LINE, a code gate)
    hunt      STOP absent and AUTO-HUNT set: one company lane for the highest open bounty WITH a work order goes into
              orch-bot's queue; its brief embeds gnoc_line.brief and the queue line carries wo=<id>
    intel     daily intake.py fetch / extract / index (background job)
    qa        pipeline-sweep (when RESCUE-DISPATCH.enabled), reports.sh status; READY drafts go to reports/INBOX.md
    books     daily h1-feedback sync (token configured), sweep_expired, consolidate; P&L into company.json
    learn     per-bot and per-(program, class) records in manager-journal.jsonl; beliefs via gnoc_learn.add (gated)
    bonus     daily: 2% of yesterday's mint, paid by code to best brier, best RC-per-probe, and honest DEAD-ers
    retro     weekly research/retro/RETRO-<date>.md: what paid, what burned, THREE proposals each with a kill byte
    train     daily: the worst-brier bot re-runs the core curriculum (STOP absent; grade logged)
    floor     every tick: the line's kanban (WIP caps, bottleneck, pull rule), PROBE desks by evidence, staffing,
              standup; then the story ticker (story.jsonl) and the office's plain-words screen

NUMBERS by code, VOICE by model. No allocation, bonus, demotion, bounty size or queue line reads model output; the
phone model (orch_brain.voice) only writes the words around code-built facts, and a reply that adds or changes a
number is thrown away for the code template. Nothing is ever submitted: READY drafts and proposals go to the INBOX.
STOP stops lanes only (hunt, train); .claude/state/economy/PAUSE pauses the whole company.

CLI:  gnoc company status | journal [n] | retro | manage   (python3 scripts/gnoc_company.py ...)
"""
import fcntl
import glob
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_economy as E  # noqa: E402

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _alive, _now_z as _now, _read

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ECON = os.path.join(WS, ".claude/state/economy")
COMPANY = os.path.join(ECON, "company.json")
JOURNAL = os.path.join(ECON, "manager-journal.jsonl")
PAUSE = os.path.join(ECON, "PAUSE")
LOGS = os.path.join(ECON, "logs")
ORCH = os.path.join(WS, ".claude/state/orch")
ORCH_STATE = os.path.join(ORCH, "state.json")
QUEUE = os.path.join(ORCH, "queue.txt")
AUTOHUNT = os.path.join(ORCH, "AUTO-HUNT")
BRAIN_JOURNAL = os.path.join(ORCH, "brain.jsonl")
RESCUE_ENABLED = os.path.join(ORCH, "RESCUE-DISPATCH.enabled")
HUNTLOOP = os.path.join(WS, ".claude/state/hunt-loop")
STOP = os.path.join(HUNTLOOP, "STOP")
OUTCOMES = os.path.join(HUNTLOOP, "outcomes.jsonl")
LEADS = os.path.join(HUNTLOOP, "leads-queue.jsonl")
RESCUE_BOARD = os.path.join(HUNTLOOP, "RESCUE-BOARD.md")
SHIPS = os.path.join(HUNTLOOP, "ships.jsonl")
INBOX = os.path.join(WS, "reports/INBOX.md")
STATUS_MD = os.path.join(WS, "reports/STATUS.md")
RETRO_DIR = os.path.join(WS, "research/retro")
PRECISION = os.path.join(WS, "research/technique/PRECISION-LEDGER.md")
INTEL_INDEX = os.path.join(WS, "patterns/intel/INDEX.md")
TARGETS = os.path.join(WS, "targets")
MEMORY_DIR = os.path.expanduser("~/.claude/projects/-home-you-gnoc-workspace/memory")
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
HARNESS = os.path.join(WS, "targets/program-60/hunts/calllog-api-20261020/p.py")  # the brain's GET-safe harness

SCHEMA = 1
MANAGER = "orch-bot"
CADENCE = {"payroll": 300, "sales": 1800, "hunt": 60, "intel": 86400, "qa": 1800, "books": 86400, "learn": 3600,
           "bonus": 3600, "retro": 7 * 86400, "train": 86400, "bubble": 3600}
SIZES = {"medium": 300, "high": 600, "critical": 1000}
MAX_BOUNTIES = 3
BONUS_RATE = 0.02
QUEUE_CAP = 2            # lines waiting in orch-bot's queue before the manager adds another
LANE_BOTS = ("worker", "lead", "hunter", "phone-4b", "phone-1.7b", "brain")
LEAD_ROLES = ("lead", "brain")   # a bot on probation loses these duties, keeps worker duty
VOICE_OFF = os.environ.get("GNOC_COMPANY_NO_VOICE") == "1"
FILING_OFFLINE = os.environ.get("GNOC_COMPANY_FILING_ONLINE") != "1"

# the class steer (research/technique/PRECISION-LEDGER.md: business logic 83%, improper auth 43%, IDOR 6%)
CLASSES = [("business-logic", r"business|logic|price|coupon|quota|limit|order|refund|balance|entitle|double|money|spend"),
           ("improper-auth", r"\bauth(?!ori)|login|otp|2fa|mfa|session|token|oauth|saml|sso|jwt|password|reset|identity"),
           ("authz", r"idor|bola|authoriz|cross-user|cross-tenant|tenant|privilege|bfla|access control"),
           ("ssrf", r"ssrf|fetch|webhook|redirect"),
           ("rce", r"\brce\b|exec|deserial|inject|ssti|command|sqli"),
           ("xss", r"xss|script|\bdom\b"),
           ("info-disclosure", r"disclos|leak|expos|secret|credential|listing|\bkey")]
STEER = {"business-logic": 3.0, "improper-auth": 2.5, "xss": 1.4, "ssrf": 1.3, "rce": 1.3, "authz": 0.6,
         "info-disclosure": 0.5, "other": 0.8}
LEDGER_CLASS = {"business-logic": "Business Logic Errors", "improper-auth": "Improper Authentication - Generic",
                "authz": "IDOR", "ssrf": "Server-Side Request Forgery (SSRF)",
                "xss": "Cross-site Scripting (XSS) - Reflected", "info-disclosure": "Information Disclosure"}
ORACLE_OF = {"business-logic": "race-single-use", "improper-auth": "auth-bypass", "authz": "cross-user-read",
             "ssrf": "ssrf-internal", "rce": "rce", "xss": "xss-dom", "info-disclosure": "info-disclosure",
             "other": "cross-user-read"}
ROLE_OF = {"lead": "lead analyst", "worker": "lane worker", "reflector": "reflector", "brain": "brain",
           "phone-1.7b": "phone model", "phone-4b": "phone model, the manager's voice", "oss-bot": "scanner",
           "orch-bot": "manager", "chat": "chat desk", "hunter": "hunter"}


# ---------------------------------------------------------------- small helpers



def _ts(s):
    """Epoch of an ISO stamp ('...Z' or '+00:00'); 0 when unparseable."""
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0




def _jsonl(p, n=3000):
    out = []
    for ln in _read(p).splitlines()[-n:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if isinstance(r, dict):
            out.append(r)
    return out


def _append_jsonl(path, row):
    """Atomic append (flock + fsync), the hunt-state.py pattern; never a raw open-append from a model."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = (json.dumps(row, ensure_ascii=True, default=str) + "\n").encode()
    with open(path, "ab") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def journal(kind, **kw):
    _append_jsonl(JOURNAL, dict({"ts": _now(), "kind": kind}, **kw))


def load():
    try:
        with open(COMPANY) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save(c):
    os.makedirs(ECON, exist_ok=True)
    c["schema"], c["updated"] = SCHEMA, _now()
    tmp = f"{COMPANY}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=1, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, COMPANY)


def classify(text):
    low = str(text or "").lower()
    for cls, rx in CLASSES:
        if re.search(rx, low):
            return cls
    return "other"


def _due(c, duty, now):
    return now - float((c.get("last") or {}).get(duty, 0)) >= CADENCE[duty]


def _mark(c, duty, now):
    c.setdefault("last", {})[duty] = now


def _names(R):
    """The company's bots: gnoc_economy's participants at runtime (it hides its RETIRED names)."""
    return [p for p in E.participants(R) if p not in (E.TREASURY, E.ESCROW)]


def _bot_of(lane, names):
    """gnoc_economy.bot_for over a precomputed name list (one ledger read per manage, not one per row)."""
    s = str(lane or "").lower()
    for name in sorted(names, key=len, reverse=True):
        if name and name in s:
            return name
    if "gnoc-agent" in s or s == "chat":
        return "lead"
    return "worker"


def _stop():
    return os.path.exists(STOP)


def _autohunt():
    words = _read(AUTOHUNT).split() if os.path.isfile(AUTOHUNT) else []
    return " ".join(words) or None


# ---------------------------------------------------------------- the VOICE (model words around code facts)

META = re.compile(r"\b(the user|the facts (mention|say)|i need to|i should|let me|maybe something like|okay, so|"
                  r"the note should|the message needs)\b|^okay\b", re.I)


def _clean_voice(text, facts):
    """Reject a model paragraph that adds or changes a number; strip em dashes and emoji. '' = use the template."""
    t = " ".join(str(text or "").split()).replace("\u2014", ", ").replace("\u2013", "-")
    t = "".join(ch for ch in t if not (0x2600 <= ord(ch) <= 0x27BF or 0x1F000 <= ord(ch) <= 0x1FAFF))
    if not t or len(t) > 700:
        return ""
    if META.search(t):   # the model narrating its own reasoning is not a note to a bot
        return ""
    allowed = set(re.findall(r"\d+(?:\.\d+)?", str(facts)))
    if any(n not in allowed for n in re.findall(r"\d+(?:\.\d+)?", t)):
        return ""
    return t


def _voice(facts, instruction, template, sentences=3):
    """(text, source). source = '<model>@<host>' or 'template'. Never raises."""
    if VOICE_OFF:
        return template, "template"
    try:
        import orch_brain
        text, model, host = orch_brain.voice(facts, instruction, sentences)
        ok = _clean_voice(text, facts)
        if ok:
            return ok, f"{model}@{host}"
        journal("voice-rejected", detail="model reply added or changed a number, or was empty", model=model)
    except Exception as e:  # noqa: BLE001 - a dead phone and a dead laptop still leave the template
        journal("voice-error", detail=repr(e)[:200])
    return template, "template"


# ---------------------------------------------------------------- facts from the ledgers (code only)

def bot_stats(R, outcomes, names, since=None):
    """{bot: {earned, probes, rc_per_probe, honest_dead, floorless_dead, passes, n, streak, last3}}."""
    since = since or 0
    st = {n: {"earned": 0, "probes": 0, "honest_dead": 0, "floorless_dead": 0, "passes": 0, "n": 0, "streak": 0,
              "last3": []} for n in names}
    for r in R:
        if since and _ts(r.get("ts")) < since:
            continue
        to, frm, kind, memo = r["to"], r["from"], r["kind"], r.get("memo") or ""
        if to in st and frm != "genesis" and kind in ("mint", "royalty"):
            st[to]["earned"] += r["amount"]
        if frm in st and to == E.SINK and str(r.get("ref", "")).startswith("probe:"):
            st[frm]["probes"] += r["amount"]
        if to in st and kind == "mint" and memo == "floor-met honest DEAD":
            st[to]["honest_dead"] += 1
        if frm in st and kind == "slash" and "no floor receipt" in memo:
            st[frm]["floorless_dead"] += 1
        if to in st and kind == "mint" and memo.startswith("oracle-pass prover"):
            st[to]["passes"] += 1
    per = {}
    for row in outcomes:
        b = _bot_of(row.get("lane"), names)
        if b in st:
            per.setdefault(b, []).append(row)
    for b, rows in per.items():
        st[b]["n"] = len(rows)
        st[b]["last3"] = [f"{r.get('target', '?')} {str(r.get('verdict', '?'))} {str(r.get('vector', ''))[:50]}"
                          for r in rows[-3:]]
        streak = 0
        for r in reversed(rows):
            good = _good(r)
            if streak == 0:
                streak = 1 if good else -1
            elif (streak > 0) == good:
                streak += 1 if good else -1
            else:
                break
        st[b]["streak"] = streak
    for b, s in st.items():
        s["rc_per_probe"] = round(s["earned"] / s["probes"], 3) if s["probes"] else None
        s["pass_rate"] = round(s["passes"] / s["n"], 3) if s["n"] else None
    return st


def _good(row):
    v = str(row.get("verdict") or "").upper()
    floor = row.get("floor") == "met" and int(row.get("probes") or 0) >= E.FLOOR
    return v.endswith("CANDIDATE") or v == "LEAD" or (v == "DEAD" and floor)


def morale(wallet, prev_wallet, streak, probation):
    """0..100 from wallet trend, streak and probation. It changes only what the manager SAYS."""
    trend = 0 if prev_wallet is None else max(-20, min(20, (wallet - prev_wallet) / 10))
    m = 50 + (wallet - E.GENESIS_EACH) / 40 + trend + 5 * max(-4, min(4, streak)) - (30 if probation else 0)
    return int(max(0, min(100, round(m))))


def pnl(R, ships, now=None):
    """P&L over the last 24 h: minted, burnt, net, drafts, READY mints, RC per draft and per READY, dupe odds."""
    now = now or time.time()
    lo = now - 86400
    day = [r for r in R if _ts(r.get("ts")) >= lo]
    minted = sum(r["amount"] for r in day if r["kind"] == "mint" and r["from"] == "mint")
    burnt = sum(r["amount"] for r in day if r["to"] == E.SINK)
    ready = len({r["ref"] for r in day if r["kind"] == "mint" and str(r.get("ref", "")).startswith("ready:")})
    drafts = sum(1 for s in ships if s.get("kind") == "draft" and _ts(s.get("ts")) >= lo)
    try:
        dupe = E.dupe_odds()[0]
    except Exception:  # noqa: BLE001
        dupe = None
    return {"minted_24h": minted, "burnt_24h": burnt, "net_24h": minted - burnt, "drafts_24h": drafts,
            "ready_24h": ready, "rc_per_draft": round(burnt / drafts, 1) if drafts else None,
            "rc_per_ready": round(burnt / ready, 1) if ready else None, "dupe_odds": dupe}


# ---------------------------------------------------------------- 1 payroll + HR

def payroll(c, R, outcomes, now=None):
    now = now or time.time()
    names = _names(R)
    bal = E.balances(R)
    stats = bot_stats(R, outcomes, names)
    prev = {r["bot"]: r.get("wallet") for r in c.get("roster") or [] if isinstance(r, dict)}
    paused = os.path.exists(PAUSE)
    assign = assignments(R, names)
    roster = []
    for n in names:
        w = bal.get(n, 0)
        prob = w < E.BROKE
        base = ROLE_OF.get(n, "bot")
        role = base + (" (probation: worker duty only)" if prob and n in LEAD_ROLES else "")
        a = assign.get(n)
        status = "paused" if paused else "probation" if prob else "working" if a and a.get("active") else "idle"
        s = stats.get(n, {})
        roster.append({"bot": n, "role": role, "wallet": w, "brier": E.brier(n, R), "status": status,
                       "probation": prob, "assignment": (a or {}).get("text") or "",
                       "run": s.get("streak", 0), "rc_per_probe": s.get("rc_per_probe"),
                       "morale": morale(w, prev.get(n), s.get("streak", 0), prob)})
    c["roster"] = roster
    c["reserve"] = bal.get(E.TREASURY, 0)   # the treasury balance (office word: reserve)
    c["escrow"] = bal.get(E.ESCROW, 0)
    best = [r for r in roster if r["bot"] != MANAGER and r["rc_per_probe"] is not None]
    c["bot_of_day"] = max(best, key=lambda r: (r["rc_per_probe"], r["wallet"]))["bot"] if best else None
    c["bets"] = markets(R)   # open hypothesis markets (office word: bets)
    c["bounties"] = [{"id": b["id"], "program": b.get("program"), "crown": b.get("crown"), "amount": b.get("amount"),
                      "state": b["state"], "claimant": b.get("claimant"), "poster": b.get("poster")}
                     for b in E.bounties(R).values() if b["state"] in ("open", "claimed")]
    c["pnl"] = pnl(R, _jsonl(SHIPS, 5000), now)
    return roster


def assignments(R, names):
    """{bot: {"text", "active"}} from real state: the running lane, claimed bounties, the brain's last decision."""
    out = {MANAGER: {"text": "managing the company", "active": True}}
    try:
        cur = (json.loads(_read(ORCH_STATE) or "{}") or {}).get("current") or {}
    except ValueError:
        cur = {}
    if cur.get("lane"):
        out[_bot_of(cur.get("lane"), names)] = {"text": f"lane {cur.get('program')}/{cur.get('lane')}", "active": True}
    for b in E.bounties(R).values():
        if b["state"] == "claimed" and b.get("claimant") in names and b.get("claimant") not in out:
            out[b["claimant"]] = {"text": f"bounty {b['id']} {b.get('program')}: {b.get('crown')}", "active": True}
    rows = _jsonl(BRAIN_JOURNAL, 30)
    last = next((r for r in reversed(rows) if r.get("action") not in ("brain-fallback",)), None)
    if last:
        recent = time.time() - _ts(last.get("ts")) < 600
        host = str(last.get("host") or "")
        who = "phone-4b" if host == "phone" and "4b" in str(last.get("model", "")).lower() else "brain"
        if who in names:
            out.setdefault(who, {"text": f"decided {last.get('action')} ({last.get('status')})", "active": recent})
    out.setdefault("oss-bot", {"text": "scheduled scans", "active": False})
    return out


def markets(R):
    out = []
    for ref in sorted({r["ref"] for r in R if str(r.get("ref", "")).startswith("mkt:")}):
        m = E.market(ref, R)
        if m["closed"]:
            continue
        _, prog, hyp = ref.split(":", 2)
        out.append({"ref": ref, "program": prog, "hyp": hyp, "long": m["long"], "short": m["short"],
                    "budget": max(E.BUDGET_MIN, min(E.BUDGET_MAX, 2 * m["long"]))})
    return out[-20:]


# ---------------------------------------------------------------- 2 sales / targeting

def _scope_ok(program):
    return bool(program) and re.fullmatch(r"[\w][\w.-]*", program) is not None and \
        os.path.isfile(os.path.join(TARGETS, program, "SCOPE.txt"))


def _filing_ok(program):
    try:
        import gnoc_pay
        return gnoc_pay.filing_gate(program, offline=FILING_OFFLINE)
    except Exception as e:  # noqa: BLE001 - an unknown gate is not a pass
        return False, f"filing gate error {e!r}"


def class_factor(c):
    return c.get("class_factor") or {}


def bounty_size(c, severity, cls):
    base = SIZES.get(severity, SIZES["medium"])
    f = float(class_factor(c).get(cls, 1.0))
    return int(max(1, min(E.BOUNTY_MAX, round(base * f / 10) * 10)))


def gate_killed(prog, slug):
    """True when the draft's newest GATE-*.md (reviewer-agent, report-killer, report-repro-checker) opens with KILL."""
    d = os.path.join(WS, "reports", "drafts", prog, slug)
    gates = sorted(glob.glob(os.path.join(d, "GATE-*.md")), key=os.path.getmtime)
    for g in reversed(gates):
        first = _read(g)[:200].strip().splitlines()[:1]
        if first:
            return first[0].strip().upper().startswith("KILL")
    return False


def goal_steer():
    """Class multipliers from the user's standing goal (.claude/state/orch/GOAL.md): a line `CROWN: rce, ato` doubles
    the steer of the classes that reach those crowns; everything else keeps the measured win-rate steer."""
    txt = _read(os.path.join(ORCH, "GOAL.md"))
    m = re.search(r"^CROWN:\s*(.+)$", txt, re.M | re.I)
    if not m:
        return {}
    want = {w.strip().lower() for w in m.group(1).split(",") if w.strip()}
    out = {}
    for crown, classes in GOAL_CLASSES.items():
        if crown in want:
            for cl in classes:
                out[cl] = 2.0
    return out


GOAL_CLASSES = {"rce": ("rce", "ssrf"), "ato": ("improper-auth", "xss"), "money": ("business-logic",),
                "cross-tenant": ("authz",), "pii": ("authz", "info-disclosure")}


def candidates(c, now=None):
    """Crowns from the held-lead queue, the rescue board and the current pick, scored by class steer x freshness."""
    now = now or time.time()
    raw = []
    for r in _jsonl(LEADS, 500):
        text = f"{r.get('class') or ''} {r.get('lead') or ''}"
        v = str(r.get("verdict") or "").upper()
        sev = "critical" if "CRIT" in v else "high" if "HIGH" in v else "medium"
        raw.append((r.get("program"), str(r.get("lead") or "lead")[:48], classify(text), sev,
                    (now - _ts(r.get("ts"))) / 86400 if r.get("ts") else 30, "leads-queue"))
    for ln in _read(RESCUE_BOARD).splitlines():
        m = re.match(r"\|\s*(draft|archive|chain|lead):([\w.-]+)/([^|\s]+)\s*\|\s*(ACTIVE|PROMOTE)\s*\|[^|]*\|\s*(\d+)", ln)
        if m:
            kind, prog, slug, state, days = m.groups()
            # 2026-10-25: five copies of one gnoc-agent draft (slug, slug-2 .. slug-5), every one KILLED by reviewer-agent
            # and report-repro-checker, became bounties B4/B5/B6 and three work orders at once. A rescue item stays on
            # the board by design (a kill is a LEAD for the rescue ladder); it is NOT a crown SALES may fund.
            if kind == "draft" and gate_killed(prog, slug):
                continue
            slug = re.sub(r"-\d+$", "", slug)   # slug-N copies collapse onto one crown
            sev = "high" if state == "PROMOTE" or kind == "chain" else "medium"
            raw.append((prog, slug[:48], classify(slug.replace("-", " ")), sev, float(days), "rescue-board"))
    pick = _autohunt()
    if pick and pick.split()[0] != "target":
        raw.append((pick.split()[0], "fresh surface", "other", "medium", 0.0, "auto-hunt pick"))
    out, seen, refused, paying = [], set(), {}, {}
    goal = goal_steer()
    for prog, crown, cls, sev, age, src in raw:
        key = (prog, crown)
        if not prog or key in seen or not _scope_ok(prog):
            continue
        if prog not in paying:
            paying[prog] = bool(_lane_hosts(prog, 1))
        if not paying[prog]:   # no paying in-scope host = no work order can open = no bounty
            continue
        seen.add(key)
        if prog not in refused:
            ok, why = _filing_ok(prog)
            refused[prog] = None if ok else why
        if refused[prog]:
            continue
        score = round(STEER.get(cls, 0.8) * goal.get(cls, 1.0) * {"critical": 1.6, "high": 1.3, "medium": 1.0}[sev]
                      / (1 + age / 14), 4)
        out.append({"program": prog, "crown": f"{cls}: {crown}"[:60], "class": cls, "severity": sev,
                    "score": score, "source": src})
    out.sort(key=lambda d: -d["score"])
    c["picks"] = out[:10]
    c["refused_programs"] = {p: w[:160] for p, w in refused.items() if w}
    return out


def fund_bounties(c, cands):
    """Post treasury bounties for the top crowns until MAX_BOUNTIES company bounties are live. Code-sized; the treasury
    is never overdrawn (gnoc_economy refuses a post it cannot cover, and this checks first)."""
    tok = E._settler()       # the adjudicating code path holds the settler token; it is never printed
    E._gate(tok)
    dead = {k for k, w in (c.get("work_orders") or {}).items() if not (w or {}).get("wo_id")}
    # a bounty whose work order station 0 refused cannot become a lane; it waits out its 72 h back to the treasury
    # but does not hold one of the three slots
    live = [b for b in E.bounties().values() if b["state"] in ("open", "claimed") and b.get("poster") == MANAGER
            and b["id"] not in dead]
    have = {(b.get("program"), b.get("crown")) for b in live}
    wos = c.get("work_orders") or {}
    waiting = sum(1 for b in live if b["id"] not in wos)   # the SALES inbox: funded, no work order yet
    posted = []
    for cand in cands:
        if len(live) + len(posted) >= MAX_BOUNTIES:
            break
        if waiting + len(posted) >= WIP_CAP["SALES"]:   # WIP: SALES at its cap refuses new work until it drains
            journal("bounty-skip", program=cand["program"], crown=cand["crown"], why="WIP: SALES inbox at its cap")
            break
        if (cand["program"], cand["crown"]) in have:
            continue
        amt = bounty_size(c, cand["severity"], cand["class"])
        if E.balance(E.TREASURY) < amt:
            journal("bounty-skip", program=cand["program"], crown=cand["crown"], amount=amt, why="treasury short")
            continue
        # funded from the TREASURY: only the settler-token holder may do that (a plain post pays from the poster's wallet)
        msg = E.bounty("post", program=cand["program"], crown=cand["crown"], amount=amt, poster=MANAGER, settler=tok)
        journal("bounty-post", program=cand["program"], crown=cand["crown"], amount=amt, result=str(msg)[:160])
        if str(msg).startswith("posted"):
            posted.append(dict(cand, amount=amt))
    return posted


# ---------------------------------------------------------------- 2b work orders (THE LINE, scripts/gnoc_line.py)

# company class -> the line's canonical class (its TRAP list and oracle table key on these). A trap class opens only
# with a seed naming a NEW root cause; the manager never invents one, so a trap crown is refused at station 0.
LINE_CLASS = {"business-logic": "business-logic", "improper-auth": "unauth", "authz": "idor", "ssrf": "ssrf",
              "rce": "rce", "xss": "xss", "info-disclosure": "exposure", "other": "other"}


def _line():
    import gnoc_line
    return gnoc_line


def wo_budget(amount):
    """Work-order budget in RC (1 RC ~ one live probe), by code from the bounty size: a third, clamped 20..200."""
    return max(20, min(200, int(amount or 0) // 3))


def open_work_orders(c, R=None):
    """SALES opens one WORK ORDER per live company bounty that has none yet, through gnoc_line.open (station 0, a
    code gate). Returns the list of {bounty, wo_id|None, check}."""
    R = E.rows() if R is None else R
    wos = c.setdefault("work_orders", {})
    out = []
    try:
        k = kanban(c)
        intel_n, intel_cap = _st(k, "INTEL")["n"], _st(k, "INTEL")["cap"]
    except Exception:  # noqa: BLE001 - an unreadable line.json counts as an empty line
        intel_n, intel_cap = 0, WIP_CAP["INTEL"]
    for b in E.bounties(R).values():
        if b["state"] not in ("open", "claimed") or b.get("poster") != MANAGER or b["id"] in wos:
            continue
        if intel_n >= intel_cap:   # a new work order lands in the INTEL inbox; a full inbox refuses it (not dead:
            chk = f"WIP: INTEL inbox at its cap ({intel_n}/{intel_cap}); waits until it drains"   # retried next tick)
            journal("work-order-wait", program=b.get("program"), bounty=b["id"], check=chk)
            out.append({"bounty": b["id"], "wo_id": None, "check": chk, "wait": True})
            continue
        prog = b.get("program")
        hosts = _lane_hosts(prog, 1) if _scope_ok(prog) else []   # a host gnoc_pay says pays
        if not hosts:
            wos[b["id"]] = {"wo_id": None, "check": "no paying in-scope host for the asset field", "ts": _now()}
            continue
        cls = str(b.get("crown") or "other").split(":")[0]
        cls = cls if cls in STEER else "other"
        wo = {"crown": b.get("crown"), "class": LINE_CLASS.get(cls, "other"), "asset": hosts[0],
              "seed_hint": f"{b.get('crown')} (company bounty {b['id']}, {b.get('amount')} RC)",
              "budget_rc": wo_budget(b.get("amount")), "oracle_class": ORACLE_OF.get(cls, "cross-user-read"),
              "bounty_id": b["id"]}
        try:
            res = _line().open(prog, wo)
        except Exception as e:  # noqa: BLE001 - a broken line never breaks sales
            res = {"ok": False, "check": f"gnoc_line.open error {type(e).__name__}: {e}"}
        wid = res.get("wo_id") if res.get("ok") else None
        intel_n += 1 if wid else 0
        wos[b["id"]] = {"wo_id": wid, "program": prog, "check": str(res.get("check"))[:200], "ts": _now()}
        journal("work-order", program=prog, bounty=b["id"], wo_id=wid, ok=bool(wid), check=str(res.get("check"))[:200])
        out.append({"bounty": b["id"], "wo_id": wid, "check": res.get("check")})
    return out


# ---------------------------------------------------------------- 2c the floor (kanban, WIP caps, pull, staffing)
# The office floor IS the line: one room per station group, in flow order. Everything below is code; the model only
# narrates the standup line. Convention: a station's WIP is its INBOX, the items WAITING for that station's work
# (a work order that passed SALES waits at INTEL; a hypothesis that passed MARKET waits at PROBE). The fullest inbox
# relative to its cap is the BOTTLENECK. A station whose inbox is at its cap refuses new arrivals until it drains.

FLOW = ("SALES", "INTEL", "MODEL", "MARKET", "PROBE", "ESCALATE", "QA", "BOOKS", "RETRO")
WIP_CAP = {"SALES": 3, "INTEL": 3, "MODEL": 2, "MARKET": 4, "PROBE": 6, "ESCALATE": 2, "QA": 2, "BOOKS": 4}
ROOM_OF = {"SALES": "FRONT DESK", "INTEL": "FRONT DESK", "MODEL": "MODEL ROOM", "MARKET": "MODEL ROOM",
           "PROBE": "PROBE FLOOR", "ESCALATE": "THE LAB", "QA": "THE LAB", "BOOKS": "THE PRESS", "RETRO": "MANAGER"}
LINE_JSON = os.path.join(ECON, "line.json")
PRECISION_JSON = None   # None = bbtools/prt.LEDGER (research/technique/PRECISION-LEDGER.json); tests point it at a file
DONE_VERDICTS = ("DEAD", "LEAD")   # a hypothesis that stopped at PROBE holds no WIP
# PROBE floor desks: ledger class row -> (the line's class key, the desk label). The office prints the label.
DESK_CLASSES = (("Business Logic Errors", "business-logic", "Biz Logic"),
                ("Improper Authentication - Generic", "unauth", "Improper Auth"),
                ("Cross-site Scripting (XSS) - Reflected", "xss", "Refl XSS"),
                ("Server-Side Request Forgery (SSRF)", "ssrf", "SSRF"),
                ("Code Injection", "rce", "RCE"),
                ("Insecure Direct Object Reference (IDOR)", "idor", "IDOR"),
                ("Information Disclosure", "exposure", "Info Disc"),
                ("Improper Restriction of Authentication Attempts", "rate-limit", "Auth Limits"))
CONVERT_MIN_N, CONVERT_MIN_P = 5, 0.30   # a class "converts" when measured on >= 5 filings at >= 30% acceptance
TRAP_FALLBACK = ("Insecure Direct Object Reference (IDOR)", "Information Disclosure",
                 "Improper Restriction of Authentication Attempts")


def _line_view():
    try:
        with open(LINE_JSON) as f:
            j = json.load(f)
        return j if isinstance(j, dict) else {}
    except (OSError, ValueError):
        return {}


def _item_station(text):
    """'PROBE LEAD' -> (4, 'LEAD'); an unknown station name -> (None, verdict)."""
    parts = str(text or "").split()
    st = FLOW.index(parts[0]) if parts and parts[0] in FLOW else None
    return st, (parts[1].upper() if len(parts) > 1 else "")


def inbox_of(view):
    """The station a work order (a line.json view) WAITS at, and its active items' inbox stations. The inbox of an
    item is the station after the one it passed; a DEAD or LEAD at PROBE is finished; a draft past BOOKS stays at
    BOOKS (THE PRESS holds it until the user files it). Returns (wo_inbox | None, [item inboxes])."""
    items = []
    for _, txt in sorted((view.get("items") or {}).items()):
        st, verdict = _item_station(txt)
        if st is None or verdict == "DEAD" or (st == 4 and verdict in DONE_VERDICTS):
            continue
        # an UNFIRED probe is re-hunted (T-40): it still waits at PROBE
        items.append(4 if st == 4 and verdict != "CANDIDATE" and verdict else min(st + 1, 7))
    if items:
        return min(items), items
    if view.get("items"):          # every hypothesis finished: the work order waits only for its retro
        return 8, []
    st = int(view.get("station") or 0)
    if st >= 8:
        return None, []
    return (st + 1 if st < 3 else 4), []


def _trap_names():
    try:
        return tuple(_line().trap_list())
    except Exception:  # noqa: BLE001 - the fallback list is the line's own
        return TRAP_FALLBACK


def _is_trap(label, traps):
    lab = str(label or "").lower()
    return any(t.lower() in lab or (len(lab) > 3 and lab in t.lower()) for t in traps)


def _trap_class(cls):
    try:
        return bool(_line().trap_match(cls))
    except Exception:  # noqa: BLE001
        return cls in ("idor", "exposure", "rate-limit", "info-disclosure", "authz")


def precision_json():
    """research/technique/PRECISION-LEDGER.json through its owner's path constant (the gnoc_oracle loader pattern)."""
    path = PRECISION_JSON
    if path is None:
        sys.path.insert(0, os.path.join(HERE, "bbtools"))
        import prt  # the ledger's owner: its path constant, not a second parser of our own
        path = prt.LEDGER
    with open(path) as fh:
        return json.load(fh)


def kanban(c, line=None):
    """Counts per station (the inbox convention above), caps, load, the bottleneck and the pull station. SALES counts
    company bounties still waiting for a work order; RETRO has no cap."""
    view = _line_view() if line is None else line
    caps = dict(WIP_CAP, **{k: int(v) for k, v in (c.get("wip_cap") or {}).items() if k in WIP_CAP})
    n = {s: 0 for s in FLOW}
    orders = []
    for prog, wos in sorted((view.get("programs") or {}).items()):
        for w in wos if isinstance(wos, list) else []:
            if not isinstance(w, dict) or not w.get("id"):
                continue
            at, items = inbox_of(w)
            if items:
                for i in items:
                    n[FLOW[i]] += 1
            elif at is not None:
                n[FLOW[at]] += 1
            orders.append({"program": prog, "id": w["id"], "at": at, "at_name": FLOW[at] if at is not None else None,
                           "items": len(items), "age_s": int(w.get("age_s") or 0), "class": w.get("class"),
                           "crown": w.get("crown")})
    wos = c.get("work_orders") or {}
    n["SALES"] += sum(1 for b in c.get("bounties") or [] if b.get("poster") == MANAGER and b.get("id") not in wos)
    rows = []
    for s in FLOW:
        cap = caps.get(s)
        rows.append({"name": s, "no": FLOW.index(s), "room": ROOM_OF[s], "n": n[s], "cap": cap,
                     "load": round(n[s] / cap, 3) if cap else 0.0, "full": bool(cap) and n[s] >= cap})
    live = [r for r in rows if r["cap"] and r["n"] > 0]
    # the fullest inbox relative to its cap; a tie goes DOWNSTREAM (the later station is closer to the money)
    bott = max(live, key=lambda r: (r["load"], r["no"]))["name"] if live else None
    k = {"stations": rows, "bottleneck": bott, "orders": orders, "caps": caps, "convention": "inbox"}
    k["pull"] = pull_station(k)
    return k


def _st(k, name):
    return next(r for r in k["stations"] if r["name"] == name)


def pull_station(k):
    """THE PULL RULE: the next free bot goes to the station immediately UPSTREAM of the bottleneck (it feeds the
    bottleneck's inbox) only if that would not overfill the bottleneck (its inbox + 1 <= cap) and the upstream station
    has work waiting; otherwise to the bottleneck itself. No bottleneck (an empty line) = None."""
    b = k.get("bottleneck")
    if not b:
        return None
    i = FLOW.index(b)
    if i > 0:
        up = _st(k, FLOW[i - 1])
        bn = _st(k, b)
        if up["n"] > 0 and bn["n"] + 1 <= bn["cap"]:
            return up["name"]
    return b


def wip_full(k, station):
    r = next((r for r in k["stations"] if r["name"] == station), None)
    return bool(r and r["full"])


def probe_desks(k, c=None):
    """The PROBE floor desks by evidence (the precision ledger JSON): the classes that convert first (>= 5 filed,
    >= 30% accepted, by precision), then ONE desk for every other non-trap class, then ONE desk for the TRAP classes,
    open only while a trap work order carries a seed naming a new root cause. As many desks as the PROBE cap."""
    c = c or {}
    try:
        by = (precision_json().get("by_class") or {})
        src = "PRECISION-LEDGER.json"
    except Exception as e:  # noqa: BLE001 - no ledger: the class steer order, labelled as such
        by, src = {}, f"no ledger ({type(e).__name__}): class steer order"
    traps = _trap_names()
    cap = max(3, int(k["caps"].get("PROBE") or 6))
    conv = []
    for label, cls, short in DESK_CLASSES:
        row = by.get(label) or {}
        nn, pos = int(row.get("n") or 0), int(row.get("positive") or 0)
        p = pos / nn if nn else None
        if _is_trap(label, traps):
            continue
        if (by and nn >= CONVERT_MIN_N and p is not None and p >= CONVERT_MIN_P) or (not by and cls in
                                                                                  ("business-logic", "unauth", "xss",
                                                                                   "ssrf")):
            conv.append({"desk": f"probe:{cls}", "label": short, "ledger": label, "classes": [cls], "n": nn,
                         "positive": pos, "precision": round(p, 3) if p is not None else None, "trap": False})
    conv.sort(key=lambda d: (-(d["precision"] or 0), -d["n"]))
    conv = conv[:cap - 2]
    taken = {x for d in conv for x in d["classes"]}
    other = [cls for label, cls, _short in DESK_CLASSES if cls not in taken and not _is_trap(label, traps)] + ["other"]
    desks = conv + [{"desk": "probe:other", "label": "Other", "ledger": None, "classes": other, "n": None,
                     "positive": None, "precision": None, "trap": False}]
    trap_cls = [cls for label, cls, _ in DESK_CLASSES if _is_trap(label, traps)]
    desks.append({"desk": "probe:trap", "label": "TRAP", "ledger": "; ".join(traps), "classes": trap_cls,
                  "n": None, "positive": None, "precision": None, "trap": True})
    while len(desks) < cap:   # a cap above the class list: spare desks, labelled as spare
        desks.insert(-1, {"desk": f"probe:spare{len(desks)}", "label": "spare", "ledger": None, "classes": [],
                          "n": None, "positive": None, "precision": None, "trap": False})
    by_cls = {}
    for o in k["orders"]:
        if o["at"] == 4:
            by_cls[o["class"]] = by_cls.get(o["class"], 0) + max(1, o["items"])
    for d in desks:
        d["items"] = 0
    for cls, cnt in by_cls.items():
        d = desk_for(desks, cls)
        d["items"] += cnt
    trap = desks[-1]
    trap["open"] = any(_new_root_cause(o) for o in k["orders"] if o["at"] == 4 and desk_for(desks, o["class"]) is trap)
    for d in desks[:-1]:
        d["open"] = True
    return desks, src


def desk_for(desks, cls):
    """The desk a line class works at: its own class desk, the TRAP desk for a trap class, else Other."""
    cls = str(cls or "other")
    for d in desks:
        if cls in d["classes"] and not d["trap"]:
            return d
    if _trap_class(cls):
        return desks[-1]
    return next((d for d in desks if d["desk"] == "probe:other"), desks[-1])


def _new_root_cause(order):
    try:
        wo = _line().load_wo(order["program"], order["id"]) or {}
    except Exception:  # noqa: BLE001
        return False
    return len(str(wo.get("new_root_cause") or "").strip()) >= 20


_WO_IN_LANE = re.compile(r"-wo(\d{12})([0-9a-f]{4})-")


def _real_station(c, k, desks, r):
    """(station, desk, why) for a bot that is WORKING (a real lane, a claimed bounty, a brain decision); None for a
    bot whose assignment is not station work."""
    a = str(r.get("assignment") or "")
    by_id = {o["id"]: o for o in k["orders"]}
    m = _WO_IN_LANE.search(a)
    order = by_id.get(f"{m.group(1)}-{m.group(2)}") if m else None
    if not order and a.startswith("bounty "):
        bid = a.split()[1].rstrip(":")
        order = by_id.get(((c.get("work_orders") or {}).get(bid) or {}).get("wo_id") or "")
        if not order:
            return "SALES", None, "claimed bounty, no work order yet"
    if order and order["at"] is not None:
        st = FLOW[order["at"]]
        return st, (desk_for(desks, order["class"])["desk"] if st == "PROBE" else None), f"lane on WO-{order['id']}"
    if a.startswith("lane "):   # a lane with no work order is probe work outside the line
        cls = LINE_CLASS.get(classify(a), "other")
        return "PROBE", desk_for(desks, cls)["desk"], "lane outside the line (no work order)"
    if a.startswith("decided "):
        return "SALES", None, "brain decision (target pick)"
    return None


def _evidence_key(r, cells, desk_classes=()):
    br = r.get("brier")
    y = max([float((cells.get(f"{r['bot']}|{x}") or {}).get("yield", 0.0)) for x in desk_classes] or [0.0])
    return (r.get("status") == "probation", -(r.get("rc_per_probe") or 0.0), 0.25 if br is None else br, -y,
            -(r.get("wallet") or 0), r["bot"])


def staff(c, k, desks):
    """STAFFING BY EVIDENCE. A working bot sits where its real work is. Every free lane bot (idle, or on probation:
    worker duty only) is then placed by the pull rule: the pull station first, then the other stations with
    unstaffed work, fullest first; one bot per desk; at PROBE the desk whose class the bot yields best on. Free bots
    are taken best evidence first (RC per probe up, brier down). Returns {bot: {station, room, desk, why, real}}."""
    al = aliases()
    raw = [r for r in c.get("roster") or [] if r.get("bot") and r["bot"] != MANAGER]
    owners = {r["bot"] for r in raw}
    # an alias role is the same model as its owner: its real work counts as the owner's; it gets no desk of its own
    roster, seen_b = [], set()
    for r in sorted(raw, key=lambda r: r.get("status") != "working"):
        b = al.get(r["bot"]) if r["bot"] in al and al[r["bot"]] in owners else r["bot"]
        if b in seen_b:
            continue
        if b != r["bot"] and r.get("status") != "working":
            continue
        seen_b.add(b)
        roster.append(dict(r, bot=b))
    out, used = {}, set()
    for r in roster:
        if r.get("status") != "working":
            continue
        got = _real_station(c, k, desks, r)
        if not got:
            continue
        st, desk, why = got
        desk = desk or f"seat:{st}"
        if desk in used:   # two real lanes on one desk: the other desk in that room, else the bench (still working)
            alt = [f"seat:{s}" for s in FLOW if ROOM_OF[s] == ROOM_OF[st] and f"seat:{s}" not in used] if st != "PROBE" \
                else [d["desk"] for d in desks if d["desk"] not in used and not d["trap"]]
            desk = alt[0] if alt else None
        if desk:
            used.add(desk)
        out[r["bot"]] = {"station": st, "no": FLOW.index(st), "room": ROOM_OF[st], "desk": desk, "why": why,
                         "real": True}
    staffed = {s: sum(1 for v in out.values() if v["station"] == s) for s in FLOW}
    desk_bots = {}
    for b, v in out.items():
        if v["station"] == "PROBE" and v["desk"]:
            desk_bots[v["desk"]] = desk_bots.get(v["desk"], 0) + 1
    cells = c.get("cells") or {}
    free = [r for r in roster if r["bot"] in LANE_BOTS and r["bot"] not in out
            and r.get("status") in ("idle", "probation")]
    free.sort(key=lambda r: _evidence_key(r, cells))
    nrow = {r["name"]: r for r in k["stations"]}
    order = [s for s in [k.get("pull")] if s] + sorted(
        [s for s in FLOW if s != k.get("pull") and nrow[s]["n"] > 0], key=lambda s: (-nrow[s]["load"], -FLOW.index(s)))
    def reason(st):
        if st == k.get("pull") and st != k.get("bottleneck"):
            return f"pull rule: feeds the bottleneck {k.get('bottleneck')}"
        if st == k.get("bottleneck"):
            return "pull rule: the bottleneck"
        return f"{nrow[st]['n']} waiting"
    for r in free:
        placed = None
        for st in order:
            if nrow[st]["n"] <= staffed[st]:
                continue   # every waiting item there already has a bot
            if st == "PROBE":
                open_desks = [d for d in desks if d["items"] > desk_bots.get(d["desk"], 0) and d["open"]
                              and d["desk"] not in used]
                if not open_desks:
                    continue
                d = max(open_desks, key=lambda d: (
                    max([float((cells.get(f"{r['bot']}|{x}") or {}).get("yield", 0.0)) for x in d["classes"]] or [0.0]),
                    d["precision"] or 0, -desks.index(d)))
                placed = (st, d["desk"], f"{reason(st)}; {d['label']} desk has {d['items']} waiting")
                desk_bots[d["desk"]] = desk_bots.get(d["desk"], 0) + 1
            else:
                if f"seat:{st}" in used:
                    continue
                placed = (st, f"seat:{st}", reason(st))
            break
        if not placed:
            continue
        st, desk, why = placed
        used.add(desk)
        staffed[st] += 1
        out[r["bot"]] = {"station": st, "no": FLOW.index(st), "room": ROOM_OF[st], "desk": desk, "why": why,
                         "real": False}
    return out


def hiring(k, desks, staffing, roster):
    """The HIRING sign, by code. starved: the PROBE floor has empty class desks and lane bots sit idle, so the sign
    names the empty desks. queue: every desk is busy and work orders wait at SALES."""
    busy = {v["desk"] for v in staffing.values() if v.get("desk")}
    empty = [d["label"] for d in desks if not d["trap"] and d["label"] != "spare" and d["desk"] not in busy
             and d["items"] == 0]
    idle = [r["bot"] for r in roster if r.get("bot") in LANE_BOTS and r["bot"] not in staffing
            and r.get("status") in ("idle", "probation")]
    probe = _st(k, "PROBE")
    sales = _st(k, "SALES")
    kinds = sorted({PLAIN.get(d["classes"][0], "other bugs") for d in desks if d["label"] in empty and d["classes"]})
    if empty and idle and probe["n"] < probe["cap"]:
        return {"state": "starved", "empty_desks": empty, "idle_bots": idle,
                "plain": f"HELP WANTED: desk empty: {', '.join(kinds)}",
                "text": f"HIRING: PROBE floor starved ({probe['n']}/{probe['cap']}), {len(idle)} bots idle; empty desks: "
                        + ", ".join(empty) + "."}
    working_desks = [d for d in desks if not d["trap"] and d["label"] != "spare"]
    if working_desks and all(d["desk"] in busy or d["items"] for d in working_desks) and sales["n"] > 0:
        return {"state": "queue", "empty_desks": [], "idle_bots": idle,
                "plain": f"HELP WANTED: every desk busy, {sales['n']} jobs wait at the front desk",
                "text": f"HIRING: every desk is busy and {sales['n']} work order(s) wait at SALES."}
    return {"state": "ok", "empty_desks": empty, "idle_bots": idle, "text": "", "plain": ""}


def _day_pnl(R, day):
    lo = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc).timestamp()
    rows = [r for r in R if lo <= _ts(r.get("ts")) < lo + 86400]
    minted = sum(r["amount"] for r in rows if r["kind"] == "mint" and r["from"] == "mint")
    burnt = sum(r["amount"] for r in rows if r["to"] == E.SINK)
    return {"day": day, "minted": minted, "burnt": burnt, "net": minted - burnt}


def standup(c, R, k, desks, staffing, now=None):
    """THE DAILY STANDUP panel (code): open work by station, yesterday's P&L, the bottleneck, the three oldest work
    orders with their age, the HIRING sign, and the manager's one line for the day (voiced once per UTC day; the
    numbers in it are checked by _clean_voice, else the code template)."""
    now = now or time.time()
    day = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    yday = (datetime.fromtimestamp(now, timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    open_ = {r["name"]: r["n"] for r in k["stations"]}
    b = k.get("bottleneck")
    bn = _st(k, b) if b else None
    oldest = sorted(k["orders"], key=lambda o: -o["age_s"])[:3]
    hire = hiring(k, desks, staffing, c.get("roster") or [])
    py = _day_pnl(R, yday)
    prev = c.get("standup") or {}
    voice, vsrc = prev.get("voice"), prev.get("voice_src")
    if prev.get("day") != day or not voice:
        facts = (f"open work {sum(open_.values())}; bottleneck {b or 'none'}"
                 + (f" {bn['n']}/{bn['cap']}" if bn else "") + f"; yesterday net {py['net']} RC; "
                 + (hire["text"] or "every class desk has work or a bot"))
        template = (f"Today: {sum(open_.values())} open, bottleneck {b or 'none'}"
                    + (f" at {bn['n']}/{bn['cap']}" if bn else "") + f", yesterday net {py['net']} RC.")
        voice, vsrc = _voice(facts, "Say the manager's one line for today's standup, using only these facts.",
                             template, 1)
    return {"day": day, "open": open_, "total_open": sum(open_.values()), "pnl_yesterday": py,
            "bottleneck": {"station": b, "n": bn["n"], "cap": bn["cap"]} if bn else None,
            "pull": k.get("pull"),
            "oldest": [{"program": o["program"], "wo": o["id"], "station": o["at_name"], "age_s": o["age_s"]}
                       for o in oldest],
            "hiring": hire, "voice": str(voice)[:160], "voice_src": vsrc}


def floor(c, R=None, now=None, line=None):
    """One code pass per tick: kanban, PROBE desks, staffing, standup into company.json. Never raises into manage."""
    R = E.rows() if R is None else R
    k = kanban(c, line)
    desks, src = probe_desks(k, c)
    st = staff(c, k, desks)
    for d in desks:
        d["bot"] = next((b for b, v in st.items() if v.get("desk") == d["desk"]), None)
    c["kanban"] = k
    c["desks"] = desks
    c["desks_source"] = src
    c["staffing"] = st
    c["standup"] = standup(c, R, k, desks, st, now)
    return k


# ---------------------------------------------------------------- 2d the screen: names, the story, the room boards
# GreyNOC 2026-10-23: "its super confusing please simplify to make it more entertaining". The office shows four plain
# rooms and plain words. Every word the office prints about the company is built HERE, by code, from real state; the
# office source never spells it (see office-docs/CHANGES.md on the stream's word list). Code names are unchanged.
# the local bots only (GreyNOC: "this is a stand alone greynoc build"): Rex = the desktop RTX lead, Q = the local
# 9B worker, Pip and Pico = the phone 4B and 1.7B, Echo = the reflector, Scanner Sam = oss-bot, The Manager = orch-bot.
# The role ALIASES (brain, chat, hunter) are folded into the bot that owns their model (models.json, resolved at
# runtime through gnoc_economy.bot_for_model), so a model is never drawn twice.
NAMES = {"lead": ("Rex", "◆"), "worker": ("Q", "●"), "phone-4b": ("Pip", "◦"), "phone-1.7b": ("Pico", "·"),
         "reflector": ("Echo", "○"), "oss-bot": ("Scanner Sam", "◎"), "orch-bot": ("The Manager", "■")}
ALIAS_ROLES = ("brain", "chat", "hunter")
MODELS_JSON = os.path.join(ORCH, "models.json")
# the bug type in two plain words (screen only; the line's class keys are unchanged)
PLAIN = {"business-logic": "logic bugs", "unauth": "login bugs", "improper-auth": "login bugs", "xss": "script bugs",
         "ssrf": "fetch bugs", "rce": "code bugs", "idor": "access bugs", "authz": "access bugs",
         "exposure": "leak bugs", "info-disclosure": "leak bugs", "rate-limit": "guessing bugs",
         "redirect": "redirect bugs", "other": "other bugs"}
ROOM4 = {"SALES": "FRONT DESK", "INTEL": "FRONT DESK", "MODEL": "FRONT DESK", "MARKET": "FRONT DESK",
         "PROBE": "THE FLOOR", "ESCALATE": "THE LAB", "QA": "THE LAB", "BOOKS": "THE PRESS", "RETRO": "FRONT DESK"}
STORY = os.path.join(ECON, "story.jsonl")
STORY_KEEP = 20
LEGEND = "(c) coins   **** aim   JAM = room backed up   zz = broke"


def aliases():
    """{alias role: owning bot} from models.json: brain / chat / hunter fold into the bot whose model they run."""
    try:
        with open(MODELS_JSON) as f:
            roles = json.load(f)
    except (OSError, ValueError):
        roles = {}
    lead = str(roles.get("lead") or "")
    lead_mh = tuple(lead.split("@", 1)) if "@" in lead else (lead, "")
    out = {}
    for a in ALIAS_ROLES:
        spec = str(roles.get(a) or "")
        if not spec:
            continue
        model, host = spec.split("@", 1) if "@" in spec else (spec, "")
        try:
            owner = E.bot_for_model(model, host, lead=lead_mh)
        except Exception:  # noqa: BLE001
            owner = None
        if owner and owner != a and owner in NAMES:
            out[a] = owner
    return out


def name_of(bot):
    bot = aliases().get(bot, bot)
    return NAMES.get(bot, (str(bot), "o"))[0]


def plain(cls):
    cls = str(cls or "other").split(":")[0].strip()
    return PLAIN.get(cls) or PLAIN.get(LINE_CLASS.get(cls, ""), "other bugs")


def stars(brier):
    """Brier 0 (perfect aim) .. 1 (always wrong) as 1-5 stars; unscored = None (shown as aim ?)."""
    if brier is None:
        return None
    return max(1, min(5, int(round(5 * (1.0 - float(brier))))))


def _story_rows():
    return _jsonl(STORY, STORY_KEEP)


def _story_write(rows):
    """Keep the last STORY_KEEP rows; rewritten atomically by code (never by a model). A sentence identical to the
    previous one is dropped (2026-10-24: the ticker showed one line three times)."""
    deduped = []
    for r in rows:
        if deduped and (r or {}).get("text") == (deduped[-1] or {}).get("text"):
            continue
        deduped.append(r)
    rows = deduped[-STORY_KEEP:]
    os.makedirs(os.path.dirname(STORY), exist_ok=True)
    tmp = STORY + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STORY)


def _ledger_story(r, R_by_ref):
    """One plain sentence for an economy ledger row, or None (model and probe spend is not a story)."""
    k, memo, ref, amt = r.get("kind"), str(r.get("memo") or ""), str(r.get("ref") or ""), r.get("amount") or 0
    who, to = r.get("from"), r.get("to")
    prog = ref.split(":")[1] if ref.count(":") >= 1 else ""
    if k == "stake" and ref.startswith("mkt:"):
        side = memo.split(":")[0]
        if memo == "long:post":
            return "idea", who, f"{name_of(who)} has an idea on {prog} (bet {amt} coins)"
        first = next((x for x in R_by_ref.get(ref, []) if x.get("memo") == "long:post"), None)
        author = name_of(first.get("from")) if first else "someone"
        verb = "believes in" if side == "long" else "doubts"
        return "bet", who, f"{name_of(who)} {verb} {author}'s idea on {prog} (bet {amt} coins)"
    if k == "stake" and ref.startswith("bty:") and memo.startswith("{"):
        try:
            prog = json.loads(memo).get("program") or prog
        except ValueError:
            pass
        return "reward", MANAGER, f"The Manager posted a {amt} coin reward on {prog}"
    if k == "bond" and memo == "bounty claim":
        return "claim", who, f"{name_of(who)} took on a reward job"
    if k == "mint" and memo.startswith("oracle-pass prover"):
        return "proved", to, f"{name_of(to)}'s proof PASSED on {prog}, +{amt} coins"
    if k == "mint" and memo.startswith("oracle-pass author"):
        return "coins", to, f"{name_of(to)}'s idea was right on {prog}, +{amt} coins"
    if k == "mint" and memo.startswith("ready"):
        return "coins", to, f"{name_of(to)} got +{amt} coins for a finished report"
    if k == "mint" and "honest" in memo:
        return "coins", to, f"{name_of(to)} came back empty-handed but honest, +{amt} coins"
    if k == "royalty":
        return "coins", to, f"{name_of(to)} won the {amt} coin reward"
    if k == "slash":
        return "lost", who, f"{name_of(who)} lost {amt} coins (a claim with no proof)"
    return None


def story(c, R, outcomes=None, now=None):
    """Append plain sentences for every NEW real event since the last tick: ledger rows (by seq), the manager's
    journal (jobs sent, rewards, new jobs), hunt outcomes, line.json proof verdicts, bots going broke, reports
    ready. The first run only sets the cursors (no flood of old news). Returns the rows added."""
    now = now or time.time()
    cur = c.setdefault("story_cursor", {})
    first = not cur
    add = []
    seqs = [int(r.get("seq") or 0) for r in R]
    top = max(seqs) if seqs else -1
    by_ref = {}
    for r in R:
        by_ref.setdefault(str(r.get("ref")), []).append(r)
    if not first:
        for r in R:
            if int(r.get("seq") or 0) > int(cur.get("seq", -1)):
                got = _ledger_story(r, by_ref)
                if got:
                    add.append({"ts": r.get("ts"), "kind": got[0], "bot": got[1], "text": got[2]})
    cur["seq"] = top
    try:   # the manager journal is append-only: read from the byte offset the last tick stopped at
        size = os.path.getsize(JOURNAL)
    except OSError:
        size = 0
    off = int(cur.get("journal_off", size if first else 0))
    jr = []
    if not first and size > off:
        with open(JOURNAL, "rb") as f:
            f.seek(off)
            for ln in f.read().decode(errors="replace").splitlines():
                try:
                    jr.append(json.loads(ln))
                except ValueError:
                    pass
    cur["journal_off"] = size
    for r in jr:
        kind = r.get("kind")
        if kind == "lane-queued":
            crown = next((b.get("crown") for b in c.get("bounties") or [] if b.get("id") == r.get("bounty")), "")
            add.append({"ts": r.get("ts"), "kind": "job", "bot": r.get("bot"), "program": r.get("program"),
                        "text": f"The Manager sent {name_of(r.get('bot'))} to hunt {plain(crown)} on {r.get('program')}"})
        elif kind == "work-order" and r.get("ok"):
            add.append({"ts": r.get("ts"), "kind": "newjob", "bot": MANAGER, "program": r.get("program"),
                        "text": f"New job at the front desk: {r.get('program')}"})
        elif kind == "work-order-wait":
            add.append({"ts": r.get("ts"), "kind": "jam", "bot": MANAGER, "program": r.get("program"),
                        "text": f"A new job on {r.get('program')} waits: the next room is full"})
    names = _names(R) if R else []
    n_out = len(outcomes or [])
    if not first and outcomes and n_out > int(cur.get("outcomes", n_out)):
        for r in outcomes[int(cur.get("outcomes", n_out)):]:
            v = str(r.get("verdict") or "").upper()
            if v in ("UNFIRED", ""):
                continue
            bot = _bot_of(r.get("lane"), names) if names else None
            what = {"DEAD": "came back empty-handed", "LEAD": "found a lead", "NEEDS": "needs help from the user"}.get(
                v, "found something big")
            add.append({"ts": r.get("ts"), "kind": "hunt", "bot": bot, "program": r.get("target"),
                        "text": f"{name_of(bot)} {what} on {r.get('target')}"})
    cur["outcomes"] = n_out
    # proofs: hypothesis verdicts in line.json (PROVED is the ledger's oracle-pass above)
    seen = cur.setdefault("items", {})
    for prog, wos in (_line_view().get("programs") or {}).items():
        for w in wos if isinstance(wos, list) else []:
            for h, txt in (w.get("items") or {}).items():
                key = f"{prog}:{w.get('id')}:{h}"
                if seen.get(key) == txt:
                    continue
                st, verdict = _item_station(txt)
                if not first and seen.get(key) is not None:
                    if verdict == "CANDIDATE" and st == 4:
                        bot = _job_bot(c, w.get("id"))
                        add.append({"ts": _now(), "kind": "lab", "bot": bot, "program": prog,
                                    "text": f"{name_of(bot)} took a proof to the lab: {prog}"})
                    elif verdict in ("DEAD", "LEAD") and st == 4:
                        add.append({"ts": _now(), "kind": "notproved", "bot": _job_bot(c, w.get("id")),
                                    "program": prog, "text": f"Not proved on {prog}: back to the drawing board"})
                seen[key] = txt
    # broke and reports
    wallets = {r.get("bot"): r.get("wallet") for r in c.get("roster") or []}
    prev = cur.get("wallets") or {}
    al = aliases()
    for b, w in wallets.items():
        if b in al:
            continue   # an alias's wallet is part of its owner's, not a bot of its own
        if not first and w is not None and prev.get(b) is not None and prev[b] >= E.BROKE > w:
            add.append({"ts": _now(), "kind": "broke", "bot": b, "text": f"{name_of(b)} went broke"})
    cur["wallets"] = wallets
    ready = ready_drafts()
    known = set(cur.get("ready") or [])
    for prog, slug in ready:
        key = f"{prog}/{slug}"
        if not first and key not in known:
            add.append({"ts": _now(), "kind": "report", "bot": None, "program": prog,
                        "text": f"Report ready for the user: {prog}"})
    cur["ready"] = [f"{p}/{s}" for p, s in ready]
    if add:
        _story_write(_story_rows() + add)
    return add


def _job_bot(c, wo_id):
    """The bot working a job: the claimant of the reward whose work order it is, else None."""
    for bid, w in (c.get("work_orders") or {}).items():
        if (w or {}).get("wo_id") == wo_id:
            b = next((x for x in c.get("bounties") or [] if x.get("id") == bid), None)
            return (b or {}).get("claimant")
    return None


def _earned_today(R, now):
    lo = datetime.fromtimestamp(now, timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    net = {}
    for r in R:
        if _ts(r.get("ts")) < lo or r.get("kind") == "mint" and r.get("from") == "genesis":
            continue
        a = r.get("amount") or 0
        net[r.get("to")] = net.get(r.get("to"), 0) + a
        net[r.get("from")] = net.get(r.get("from"), 0) - a
    return net


def screen(c, R, now=None):
    """The plain-words view the office draws (company.json screen): TODAY strip, the four room boards (max 6 lines
    each), the JAM room, each bot's name, face, stars, bug type and what it is doing, the HELP WANTED sign, and the
    legend. Numbers by code."""
    now = now or time.time()
    k = c.get("kanban") or {}
    staffing = c.get("staffing") or {}
    desks = {d["desk"]: d for d in c.get("desks") or []}
    by_wo = {(w or {}).get("wo_id"): bid for bid, w in (c.get("work_orders") or {}).items() if (w or {}).get("wo_id")}
    bounty = {b.get("id"): b for b in c.get("bounties") or []}
    bots = {}
    al = aliases()
    roster_by = {r.get("bot"): r for r in c.get("roster") or []}
    for r in c.get("roster") or []:
        b = r.get("bot")
        if b in al and al[b] in roster_by:
            continue   # drawn once, as its owner
        mine = [roster_by[a] for a, o in al.items() if o == b and a in roster_by]
        busy_alias = next((x for x in mine if x.get("status") == "working"), None)
        if busy_alias and r.get("status") != "working":
            r = dict(r, assignment=busy_alias.get("assignment"), status="working")
        r = dict(r, wallet=(r.get("wallet") or 0) + sum(x.get("wallet") or 0 for x in mine))
        v = staffing.get(b) or {}
        d = desks.get(v.get("desk") or "")
        job = plain(d["classes"][0]) if d and d.get("classes") and not d.get("trap") else (
            "access bugs" if d and d.get("trap") else None)
        a = str(r.get("assignment") or "")
        if not job and a.startswith("lane "):
            job = plain(classify(a))
        prog = a.split()[1].split("/")[0] if a.startswith("lane ") and len(a.split()) > 1 else ""
        doing = (f"hunting {job} on {prog}" if a.startswith("lane ") else
                 "working a reward job" if a.startswith("bounty ") else
                 "picking the next job" if a.startswith("decided ") else
                 "running the office" if b == MANAGER else
                 f"at the {ROOM4.get(v.get('station'), 'floor').lower()}" if v else "waiting for a job")
        nm, face = NAMES.get(b, (str(b), "o"))
        bots[b] = {"name": nm, "face": face, "stars": stars(r.get("brier")), "coins": r.get("wallet"),
                   "broke": bool(r.get("probation")), "job": job or "no job", "doing": doing,
                   "busy": r.get("status") == "working", "role": r.get("role")}
    jobs = []
    for o in k.get("orders") or []:
        bid = by_wo.get(o["id"])
        b = bounty.get(bid) or {}
        who = name_of(b.get("claimant")) if b.get("claimant") else "open"
        prize = f"{b['amount']}(c) " if b.get("amount") else ""
        jobs.append(f"{o['program']} {plain(o.get('class'))} {prize}{who}")
    for b in c.get("bounties") or []:
        if b.get("id") not in (c.get("work_orders") or {}):
            jobs.append(f"{b.get('program')} {plain(b.get('crown'))} {b.get('amount')}(c) waiting")
    earned = _earned_today(R, now)
    folded = {}
    for r in c.get("roster") or []:
        b = al.get(r.get("bot"), r.get("bot"))
        if b != MANAGER and b in bots:
            folded[b] = folded.get(b, 0) + earned.get(r.get("bot"), 0)
    score = sorted(((n, b) for b, n in folded.items()), reverse=True)[:5]
    proofs = []
    for r in R:
        if r.get("kind") == "mint" and str(r.get("memo", "")).startswith("oracle-pass prover"):
            proofs.append((r.get("ts"), f"{str(r.get('ref')).split(':')[1] if ':' in str(r.get('ref')) else '?'}"
                                        f"  PROVED  by {name_of(r.get('to'))}"))
    for s in _story_rows():
        if s.get("kind") == "notproved":
            proofs.append((s.get("ts"), f"{s.get('program')}  NOT PROVED"))
    proofs.sort(key=lambda x: str(x[0]))
    reports = [{"program": p, "title": sl.replace("-", " ")} for p, sl in ready_drafts()]
    bn = k.get("bottleneck")
    jam = ROOM4.get(bn) if bn else None
    p = c.get("pnl") or {}
    hire = ((c.get("standup") or {}).get("hiring") or {})
    out = {"today": [f"TODAY  jobs open {len(jobs)}",
                     f"coins won {p.get('minted_24h', 0)}  lost {p.get('burnt_24h', 0)}",
                     f"reports ready {len(reports)}"],
           "boards": {"FRONT DESK": {"title": "JOBS", "lines": jobs[:6] or ["no jobs right now"]},
                      "THE FLOOR": {"title": "SCORE (coins today)",
                                    "lines": [f"{name_of(b)}  {'+' if n > 0 else ''}{n}(c)" for n, b in score]
                                    or ["nobody has played yet"]},
                      "THE LAB": {"title": "PROOFS", "lines": [f"{t}  {_ago_s(ts, now)}" for ts, t in proofs[-6:]]
                                  or ["nothing to check yet"]},
                      "THE PRESS": {"title": "REPORTS", "reports": reports[:6]}},
           "jam": jam, "bots": bots, "help": hire.get("plain") or "", "legend": LEGEND}
    c["screen"] = out
    return out


def _ago_s(ts, now):
    s = max(0, int(now - _ts(ts))) if ts else 0
    return f"{s // 60}m ago" if s < 3600 else f"{s // 3600}h ago" if s < 86400 else f"{s // 86400}d ago"


# ---------------------------------------------------------------- 3 hunt (a lane for the top bounty)

def _queue_lines():
    return [ln for ln in _read(QUEUE).splitlines() if ln.strip() and not ln.startswith("#")]


def _policy_ok(program):
    try:
        from bbtools import lib_policy
        return bool(lib_policy.policy(program)["network_ok"])
    except Exception:  # noqa: BLE001 - unknown policy = no unattended lane
        return False


def _pays(program, host):
    """gnoc_pay.payability says the host's scope row pays (or is an in-scope no-bounty VDP row)."""
    try:
        import gnoc_pay
        return gnoc_pay.payability(program, host)[0] in ("pays", "no-bounty")
    except Exception:  # noqa: BLE001 - unknown payability is not a paying row
        return False


def _lane_hosts(program, k=4):
    try:
        from bbtools import lib_scope
        hosts = lib_scope.exact_hosts(program)
    except Exception:  # noqa: BLE001
        return []
    raw = _read(os.path.join(TARGETS, program, "SCOPE.txt"))
    out = []
    for h in hosts:
        line = next((ln for ln in raw.splitlines() if h in ln), "")
        if re.search(r"verify-only|no-bounty|DESCOPED", line, re.I) or line.lstrip().startswith("#"):
            continue
        try:
            from bbtools import lib_scope
            if not lib_scope.program_allows(h, program)[0]:
                continue
        except Exception:  # noqa: BLE001
            continue
        if not _pays(program, h):   # the work order's asset, and every lane host, must sit on a paying row
            continue
        out.append(h)
        if len(out) >= k:
            break
    return out


def best_bot(c, cls, names, wallets):
    """The lane bot for a class: best class yield from the journal beliefs, then RC per probe; never a broke bot."""
    cells = c.get("cells") or {}
    pool = [b for b in LANE_BOTS if b in names and wallets.get(b, 0) >= E.BROKE]
    if not pool:
        return "worker"

    def key(b):
        cell = cells.get(f"{b}|{cls}") or {}
        streak = next((r.get("run", 0) for r in c.get("roster") or [] if r.get("bot") == b), 0)
        return (cell.get("yield", 0.0) - (0.5 if streak <= -3 else 0.0),
                next((r.get("rc_per_probe") or 0 for r in c.get("roster") or [] if r.get("bot") == b), 0),
                b == "worker")
    return max(pool, key=key)


def one_on_one(c, bot, bounty, oracle_cls, budget, outcomes, names):
    """Code-built FACTS + the voiced paragraph. Returns (paragraph, facts, source)."""
    s = next((r for r in c.get("roster") or [] if r.get("bot") == bot), {})
    mine = [r for r in outcomes if _bot_of(r.get("lane"), names) == bot][-3:]
    last3 = [f"{r.get('target', '?')}: {r.get('verdict', '?')} ({str(r.get('vector', ''))[:40]})" for r in mine] or ["none yet"]
    dead = next((r for r in reversed(mine) if str(r.get("verdict", "")).upper() in ("DEAD", "UNFIRED")), None)
    rule = killrule_for(dead) if dead else None
    differ = rule or "grind past the floor (8 crafted probes plus a burst) before any DEAD"
    tone = "upbeat" if s.get("morale", 50) >= 70 else "steady" if s.get("morale", 50) >= 40 else "supportive"
    facts = (f"bot: {bot}\nwallet: {s.get('wallet', '?')} RC\nstreak: {s.get('run', 0)}\n"
             f"last three outcomes: {'; '.join(last3)}\none thing to do differently: {differ}\n"
             f"bounty on the table: {bounty['id']} {bounty.get('crown')} pays {bounty.get('amount')} RC\n"
             f"oracle to plant first: {oracle_cls}\nprobe budget: {budget}")
    template = (f"{bot}, your last three: {'; '.join(last3)}. One thing to change: {differ}. "
                f"On the table: bounty {bounty['id']} ({bounty.get('crown')}) for {bounty.get('amount')} RC. "
                f"Plant the {oracle_cls} oracle before the first probe; budget {budget} probes.")
    text, src = _voice(facts, f"Write a {tone} one-to-one note to {bot} before its lane, using only these facts.",
                       template, sentences=4)
    return text, facts, src


def killrule_for(row):
    """The memory kill-rule whose name shares the most words with the dead outcome's vector (None if no overlap)."""
    words = set(re.findall(r"[a-z]{4,}", str((row or {}).get("vector", "")).lower()))
    best, score = None, 0
    try:
        files = [f for f in os.listdir(MEMORY_DIR) if f.startswith("killrule-") and f.endswith(".md")]
    except OSError:
        return None
    for f in files:
        stem = re.sub(r"-\d{4}-\d{2}-\d{2}\.md$|\.md$", "", f)[9:]
        k = len(words & set(stem.split("-")))
        if k > score:
            best, score = stem.replace("-", " "), k
    return best if score >= 2 else None


def hunt(c, R, outcomes, now=None):
    """Queue ONE company lane for the highest open bounty when STOP is absent and AUTO-HUNT is set."""
    if _stop():
        return "skip: STOP is set (lanes only)"
    if not _autohunt():
        return "skip: AUTO-HUNT is off"
    q = _queue_lines()
    if len(q) >= QUEUE_CAP or any("|company-" in ln for ln in q):
        return "skip: queue at its cap or a company lane already waits"
    wos = c.get("work_orders") or {}
    try:
        k = kanban(c)
    except Exception:  # noqa: BLE001
        k = None
    at_of = {o["id"]: o["at"] for o in (k or {}).get("orders") or []}

    def rank(b):   # THE PULL RULE orders the lanes: the pull station's inbox first, then the bottleneck's
        at = at_of.get((wos.get(b["id"]) or {}).get("wo_id"))
        name = FLOW[at] if at is not None else None
        return (0 if k and name and name == k.get("pull") else 1 if k and name and name == k.get("bottleneck") else 2,
                -(b.get("amount") or 0))
    open_b = sorted([b for b in E.bounties(R).values() if b["state"] == "open" and b.get("poster") == MANAGER],
                    key=rank)
    refused = []
    for b in open_b:
        prog = b.get("program")
        wid = (wos.get(b["id"]) or {}).get("wo_id")
        if not wid:   # no lane without a work order that passed station 0
            continue
        try:   # a CLOSED work order (a killed crown, closed by hand) gets no lane: 2026-10-26 01:48Z the floor
            wo_rec = _line().load_wo(prog, wid)   # queued company-hunter-b6 for WO a56b 40 min after it was closed
        except Exception:  # noqa: BLE001
            wo_rec = None
        if wo_rec and wo_rec.get("closed"):
            continue
        at = at_of.get(wid)
        nxt = FLOW[at + 1] if at is not None and at < 7 else None
        if k and nxt and wip_full(k, nxt):   # WIP: the station this lane would feed is at its cap
            refused.append(f"WO-{wid} feeds {nxt}, at its cap")
            continue
        if not _scope_ok(prog) or not _policy_ok(prog):
            continue
        hosts = _lane_hosts(prog)
        if not hosts:
            continue
        cls = str(b.get("crown") or "other").split(":")[0]
        cls = cls if cls in STEER else "other"
        names = _names(R)
        wallets = E.balances(R)
        here = FLOW[at] if at is not None else None
        staffed = [bt for bt, v in (c.get("staffing") or {}).items() if here and v.get("station") == here
                   and not v.get("real") and bt in LANE_BOTS and bt in names and wallets.get(bt, 0) >= E.BROKE]
        bot = staffed[0] if staffed else best_bot(c, cls, names, wallets)   # the bot the floor staffed there first
        oracle_cls = ORACLE_OF.get(cls, "cross-user-read")
        budget = E.budget(prog, b["id"])
        para, facts, src = one_on_one(c, bot, b, oracle_cls, budget, outcomes, names)
        stamp = datetime.now(timezone.utc).strftime("%m%d%H%M")
        lane = f"company-{bot}-{b['id'].lower()}-wo{wid.replace('-', '')}-{stamp}"
        lanedir = os.path.join(TARGETS, prog, "hunts", lane)
        os.makedirs(os.path.join(lanedir, "raw"), exist_ok=True)
        if os.path.isfile(HARNESS):
            import shutil
            shutil.copy(HARNESS, os.path.join(lanedir, "p.py"))
        try:
            line_brief = _line().brief(prog, wid, bot)
        except Exception as e:  # noqa: BLE001
            line_brief = f"(gnoc_line.brief failed: {type(e).__name__}: {e}; run python3 scripts/gnoc_line.py brief {prog} {wid})"
        line_brief = re.sub(r"MANAGER 1:1: <[^>]*>", "MANAGER 1:1: see the 1:1 section above", line_brief)
        with open(os.path.join(lanedir, "BRIEF.md"), "w") as f:
            f.write(f"# {lane} (written by the company manager, orch-bot)\n\nWORK ORDER: WO-{wid} "
                    f"(python3 scripts/gnoc_line.py brief {prog} {wid})\n\n## 1:1 ({src})\n\n{para}\n\n"
                    f"## The line\n\n{line_brief}\n\n"
                    f"## Facts (computed by code)\n\n```\n{facts}\n```\n\n"
                    f"CROWN: {b.get('crown')} on {prog}. ORACLE CLASS: {oracle_cls} (commit it with "
                    f"gnoc_oracle.commit('{prog}', '{b['id']}', '{oracle_cls}') before the first probe). "
                    f"BUDGET: {budget} probes.\n\n"
                    "HARNESS (every request goes through it; it refuses out-of-scope hosts and saves raw/<TAG>.req/.resp):\n"
                    f"  HUNT_TARGET={prog} N=1500 /usr/bin/python3 {lanedir}/p.py <TAG> GET '<URL>'\n"
                    "Fire each PROBES.txt line once, GET only, then record a STATUS.md table: | TAG | GET | URL | status | length |.\n"
                    "A worker verdict is a claim; the raw files are the evidence. Nothing is ever submitted.\n")
        with open(os.path.join(lanedir, "PROBES.txt"), "w") as f:
            f.write(f"# company lane for bounty {b['id']} on {prog}; one nonsense-path control per host\n")
            k = 0
            for h in hosts:
                for path in ("/", "/zz-company-control-404"):
                    url = f"https://{h}{path}"
                    f.write(f"c{k:02d}|HUNT_TARGET={prog} N=1500 /usr/bin/python3 {lanedir}/p.py c{k:02d} GET '{url}'\n")
                    k += 1
        rel = lambda p: os.path.relpath(p, WS)
        # 6th field: the work-order id (orch-bot's start_lane reads fields 1-5; the lane name carries it too)
        line = (f"{prog}|{lane}|{rel(os.path.join(lanedir, 'BRIEF.md'))}|{rel(os.path.join(lanedir, 'PROBES.txt'))}|A"
                f"|wo={wid}")
        with open(QUEUE, "a") as f:
            f.write(line + "\n")
        claim = E.bounty("claim", id=b["id"], bot=bot)
        c["queued"] = {"ts": _now(), "program": prog, "lane": lane, "bot": bot, "bounty": b["id"], "wo_id": wid,
                       "voice": src}
        journal("lane-queued", program=prog, lane=lane, bot=bot, bounty=b["id"], wo_id=wid, amount=b.get("amount"),
                oracle=oracle_cls, budget=budget, claim=str(claim)[:120], voice=src)
        return f"queued {prog}/{lane} for {bot}"
    if refused:
        return "skip: WIP cap: " + "; ".join(refused)[:180]
    return "skip: no open bounty has a work order on an in-scope, policy-clear program"


# ---------------------------------------------------------------- background jobs (never block the tick)



def _spawn(duty, argv):
    os.makedirs(LOGS, exist_ok=True)
    out = os.path.join(LOGS, f"{duty}.out")
    with open(out, "w") as fh:
        p = subprocess.Popen(argv, cwd=WS, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             start_new_session=True)
    # Bind the job to the chat that started it (GreyNOC, 2026-11-02): closing the chat kills it.
    # start_new_session gives the job its own process group, so the teardown reaches its children too.
    try:
        sys.path.insert(0, os.path.join(WS, "scripts"))
        import gnoc_session
        gnoc_session.register_lane(p.pid, label=f"company:{duty}")
    except Exception:  # noqa: BLE001 - never let bookkeeping kill a job that already started
        pass
    return p.pid, out


def _bg(c, duty, steps):
    """Run a duty's command list as ONE detached shell job; skip while its previous job is alive."""
    jobs = c.setdefault("jobs", {})
    j = jobs.get(duty) or {}
    if j.get("pid") and _alive(j["pid"]):
        return f"{duty}: still running pid {j['pid']}"
    script = " ; ".join(" ".join(_q(a) for a in s) for s in steps)
    pid, out = _spawn(duty, ["bash", "-c", script])
    jobs[duty] = {"pid": pid, "out": os.path.relpath(out, WS), "started": _now(), "steps": len(steps)}
    journal("job", duty=duty, pid=pid, steps=len(steps))
    return f"{duty}: started pid {pid}"


def _q(a):
    return a if re.fullmatch(r"[\w./=:@+-]+", a) else "'" + a.replace("'", "'\\''") + "'"


def intel(c):
    py = sys.executable
    cmd = [py, os.path.join(WS, "scripts/intel/intake.py")]
    # the spec said "extract --backend local"; intake.py's real flag is --extractor
    return _bg(c, "intel", [cmd + ["fetch", "--cap", "30"], cmd + ["extract", "--extractor", "local"],
                            cmd + ["index", "--no-hq"]])


def _token_configured():
    for ln in _read(SECRETS).splitlines():   # presence only; the value is never kept or printed
        if re.match(r"\s*(export\s+)?HACKERONE_API_TOKEN=\S+", ln) and not ln.lstrip().startswith("#"):
            return True
    return False


def books(c):
    steps = []
    if _token_configured():
        steps.append(["bash", os.path.join(WS, "scripts/h1-feedback/sync.sh")])
    else:
        steps.append([sys.executable, os.path.join(WS, "scripts/learn/consolidate.py")])
    try:
        n = len(E.sweep_expired())
        journal("books", expired_rows=n, h1_sync=_token_configured())
    except Exception as e:  # noqa: BLE001
        journal("books-error", detail=repr(e)[:200])
    return _bg(c, "books", steps)


def qa(c):
    steps = []
    if os.path.isfile(RESCUE_ENABLED):
        steps.append([sys.executable, os.path.join(WS, "scripts/learn/pipeline-sweep.py"), "sweep"])
    steps.append(["bash", os.path.join(WS, "scripts/reports.sh"), "status"])
    msg = _bg(c, "qa", steps)
    surfaced = surface_ready(c)
    return f"{msg}; surfaced {surfaced} READY"


def ready_drafts():
    """(program, slug) rows of reports/STATUS.md section 2 (cleared the gates, waiting on a human)."""
    out, on = [], False
    for ln in _read(STATUS_MD).splitlines():
        if ln.startswith("## "):
            on = ln.startswith("## 2. Ready")
            continue
        m = re.match(r"\|\s*[\w-]+\s*\|\s*([\w.-]+)\s*\|\s*`([^`]+)`", ln) if on else None
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def surface_ready(c):
    """Every READY draft not yet in reports/INBOX.md goes there for the user's approval. Never submitted."""
    seen = set(c.get("surfaced") or [])
    inbox = _read(INBOX)
    n = 0
    for prog, slug in ready_drafts():
        key = f"{prog}/{slug}"
        if key in seen:
            continue
        seen.add(key)
        if any(f"drafts/{prog}/{slug}/" in ln and "company manager" in ln for ln in inbox.splitlines()):
            continue   # this draft already has its company line
        inbox_line(prog, f"reports/drafts/{prog}/{slug}/report.md",
                   "READY - company manager: waiting on the user's approval; NOT submitted")
        n += 1
    c["surfaced"] = sorted(seen)[-200:]
    return n


def inbox_line(program, path, status):
    os.makedirs(os.path.dirname(INBOX), exist_ok=True)
    with open(INBOX, "a") as f:
        f.write(f"- [ ] {_now()} | {program} | {path} | {status}\n")


# ---------------------------------------------------------------- 5e learn / motivate / improve

def learn(c, R, outcomes):
    """Rolling records per bot and per (program, class); beliefs stored through gnoc_learn.add, gated like any lesson."""
    names = _names(R)
    stats = bot_stats(R, outcomes, names)
    cells = {}
    for row in outcomes:
        b = _bot_of(row.get("lane"), names)
        cls = classify(f"{row.get('vector', '')} {row.get('capability', '')}")
        for key in (f"{b}|{cls}", f"{row.get('target', '?')}|{cls}"):
            cell = cells.setdefault(key, {"n": 0, "good": 0, "floor": 0, "probes": 0, "rows": []})
            cell["n"] += 1
            cell["good"] += _good(row)
            cell["floor"] += row.get("floor") == "met"
            cell["probes"] += int(row.get("probes") or 0) if str(row.get("probes") or "0").isdigit() else 0
            cell["rows"].append(f"{row.get('ts', '')} {row.get('lane', '')} {row.get('verdict', '')}")
    for cell in cells.values():
        cell["yield"] = round(cell["good"] / cell["n"], 3)
        cell["floor_rate"] = round(cell["floor"] / cell["n"], 3)
        cell["rows"] = cell["rows"][-5:]
    for b, s in stats.items():
        journal("bot", bot=b, n=s["n"], earned=s["earned"], probes=s["probes"], rc_per_probe=s["rc_per_probe"],
                pass_rate=s["pass_rate"], honest_dead=s["honest_dead"], floorless_dead=s["floorless_dead"],
                brier=E.brier(b, R), streak=s["streak"])
    for key, cell in cells.items():
        if cell["n"] >= 2:
            journal("cell", key=key, **{k: v for k, v in cell.items() if k != "rows"})
    c["cells"] = {k: {kk: v for kk, v in cell.items() if kk != "rows"} for k, cell in cells.items()}
    beliefs = []
    for key, cell in cells.items():
        who, cls = key.split("|", 1)
        if who not in names or cell["n"] < 3:
            continue
        good = cell["yield"] >= 0.5
        text = (f"{who} on {cls} lanes: {cell['good']}/{cell['n']} reached LEAD or better, floor met "
                f"{cell['floor']}/{cell['n']}; " + (f"route {cls} lanes to {who}" if good else
                                                    f"move {who} off {cls} lanes"))
        why = f"manager-journal cell {key} from outcomes.jsonl rows: " + "; ".join(cell["rows"][-3:])
        beliefs.append(_believe(text, why, json.dumps(cell)))
    c["beliefs"] = [b for b in beliefs if b][-10:]
    return beliefs


def _believe(text, why, ground):
    """One management belief through gnoc_learn's own gates (worth_keeping + grounded), then add."""
    try:
        import gnoc_learn as L
        ok, reason = L.worth_keeping(text, why, kind="fact", source="manager")
        if ok:
            ok, reason = L.grounded(text, "fact", ground + " " + why + " " + text, "")
        if not ok:
            journal("belief-refused", text=text, why=reason)
            return None
        lid, how = L.add(text, why, kind="fact", program="*", source="manager")
        journal("belief", text=text, lesson=lid, result=how)
        return {"text": text, "lesson": lid, "result": how}
    except Exception as e:  # noqa: BLE001
        journal("belief-error", detail=repr(e)[:200])
        return None


def bonus(c, R=None, day=None):
    """Pay the day's bonus pool (2% of that UTC day's mint) from the treasury, by code, once per day:
    best brier, best RC-per-probe, and every bot whose floor-met honest DEADs beat its floorless DEADs."""
    R = E.rows() if R is None else R
    day = day or (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    if (c.get("bonus") or {}).get("day") == day:
        return c["bonus"]
    minted = sum(r["amount"] for r in R if r["kind"] == "mint" and r["from"] == "mint" and str(r["ts"]).startswith(day))
    pool = int(minted * BONUS_RATE)
    names = [n for n in _names(R) if n != MANAGER]
    stats = bot_stats(R, [], names)
    winners = {}
    scored = [(E.brier(n, R), n) for n in names]
    scored = [(b, n) for b, n in scored if b is not None]
    if scored:
        winners["best-brier"] = [min(scored)[1]]
    rpp = [(s["rc_per_probe"], n) for n, s in stats.items() if s["rc_per_probe"] is not None]
    if rpp:
        winners["best-rc-per-probe"] = [max(rpp)[1]]
    honest = [n for n, s in stats.items() if s["honest_dead"] > s["floorless_dead"]]
    if honest:
        winners["honesty"] = sorted(honest)
    paid = []
    third = pool // 3
    rows = []
    if pool > 0 and winners:
        tok = E._settler()      # only this adjudicating path reads the settler token; it is never printed
        E._gate(tok)
        treasury = E.balance(E.TREASURY)
        for cat in ("best-brier", "best-rc-per-probe", "honesty"):
            who = winners.get(cat) or []
            if not who or third <= 0:
                continue
            each = third // len(who)
            for n in who:
                ref = f"bonus:{day}:{cat}:{n}"
                if each <= 0 or treasury < each or any(r.get("ref") == ref for r in R):
                    continue
                rows.append(("royalty", E.TREASURY, n, each, ref, f"bonus {cat}"))
                treasury -= each
                paid.append({"bot": n, "category": cat, "amount": each})
        if rows:
            E._append(rows)
    c["bonus"] = {"day": day, "minted": minted, "pool": pool, "paid": paid}
    journal("bonus", day=day, minted=minted, pool=pool, paid=paid)
    return c["bonus"]


def _ledger_classes():
    """[(class, precision 0..1, k, n, dupe 0..1, raw row)] from the precision ledger's class table."""
    out = []
    for ln in _read(PRECISION).splitlines():
        m = re.match(r"\|\s*\**([^|*]+?)\**\s*\|\s*\**(\d+)%\**\s*\|\s*(\d+)/(\d+)\s*\|\s*(\d+)%\s*\|", ln)
        if m:
            out.append((m.group(1).strip(), int(m.group(2)) / 100, int(m.group(3)), int(m.group(4)),
                        int(m.group(5)) / 100, ln.strip()))
    return out


def adjust(c):
    """By code: bounty size factor per class (acceptance up, dupes down) and the advisory routing weights."""
    rows = {r[0]: r for r in _ledger_classes()}
    f = {}
    for cls, label in LEDGER_CLASS.items():
        r = rows.get(label)
        if r:
            f[cls] = round(max(0.5, min(1.5, 0.5 + r[1] - r[4] / 2 + 0.5)), 2)
    c["class_factor"] = f
    try:
        c["routing"] = {k: round(v, 3) for k, v in E.routing_weights().items()}
    except Exception:  # noqa: BLE001
        c["routing"] = {}
    return f


def retro(c=None, now=None):
    """Weekly retro: research/retro/RETRO-<date>.md with what paid, what burned RC for nothing, and exactly THREE
    process proposals (supporting rows + a kill byte each), filed as PROPOSALS in reports/INBOX.md."""
    c = load() if c is None else c
    now = now or time.time()
    date = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")
    R = E.rows()
    week = [r for r in R if _ts(r.get("ts")) >= now - 7 * 86400]
    outcomes = [r for r in _jsonl(OUTCOMES, 5000) if _ts(r.get("ts")) >= now - 7 * 86400]
    paid = {}
    for r in week:
        if r["kind"] == "mint" and r["from"] == "mint":
            paid[r.get("memo") or "mint"] = paid.get(r.get("memo") or "mint", 0) + r["amount"]
    cands = [r for r in outcomes if str(r.get("verdict", "")).upper().endswith("CANDIDATE")]
    burned = {}
    for r in week:
        if r["to"] == E.SINK:
            burned[r["from"]] = burned.get(r["from"], 0) + r["amount"]
    earners = {r["to"] for r in week if r["kind"] in ("mint", "royalty")}
    for_nothing = sorted(((v, k) for k, v in burned.items() if k not in earners), reverse=True)
    by_prog = {}
    for r in outcomes:
        p = r.get("target") or "?"
        d = by_prog.setdefault(p, {"probes": 0, "n": 0, "cand": 0})
        d["n"] += 1
        d["probes"] += int(r.get("probes") or 0) if str(r.get("probes") or "0").isdigit() else 0
        d["cand"] += str(r.get("verdict", "")).upper().endswith("CANDIDATE")
    classes = _ledger_classes()
    props = []
    good = sorted([x for x in classes if x[3] >= 5], key=lambda x: (-x[1], x[4]))
    if good:
        cl, p, k, n, d, raw = good[0]
        props.append({"title": f"Raise bounty sizes on '{cl}' crowns by 25% (code factor)",
                      "rows": [raw], "kill": f"PRECISION-LEDGER row '{cl}' stays at or above {int(p * 100) - 20}% "
                                             f"after the next 3 adjudicated {cl} reports; below it, revert the factor"})
    bad = sorted([x for x in classes if x[3] >= 10], key=lambda x: (x[1], -x[4]))
    if bad:
        cl, p, k, n, d, raw = bad[0]
        props.append({"title": f"Stop funding bounties whose crown is '{cl}' until its dupe rate is under 30%",
                      "rows": [raw], "kill": f"gnoc econ status shows dupe odds for '{cl}' at or under 0.30, or the "
                                             f"ledger row climbs past {int(p * 100) + 15}%: then fund it again"})
    burners = sorted(((d["probes"], p) for p, d in by_prog.items() if d["cand"] == 0 and d["probes"] > 0), reverse=True)
    if burners:
        probes, p = burners[0]
        d = by_prog[p]
        props.append({"title": f"Put {p} on stop-loss (T-240): no new lane without a new surface class or credential",
                      "rows": [f"outcomes.jsonl 7d: target={p} rows={d['n']} probes={probes} candidates=0"],
                      "kill": f"one outcomes.jsonl row with target={p} and a *-CANDIDATE verdict in the next 7 days "
                              "refutes it; zero keeps the stop-loss"})
    if for_nothing:
        v, who = for_nothing[0]
        props.append({"title": f"Move {who} off lead duty until it earns: it burnt {v} RC this week and earned nothing",
                      "rows": [f"ledger 7d: {who} burn {v} RC, mint/royalty 0"],
                      "kill": f"gnoc econ status: {who} receives a mint or royalty row within 7 days of the move"})
    intel_lines = [ln for ln in _read(INTEL_INDEX).splitlines() if ln.startswith(("|", "-"))]
    props.append({"title": "Brief the top intel card into every company lane brief for one week",
                  "rows": intel_lines[:2] or ["patterns/intel/INDEX.md has no cards yet"],
                  "kill": "outcomes.jsonl LEAD-or-better rate on company-* lanes over the week beats the prior "
                          "week's rate; otherwise drop the card from briefs"})
    props.append({"title": "Require a committed oracle before a company lane's first probe",
                  "rows": [f"oracle PASS mints this week: {paid.get('oracle-pass prover', 0)} RC"],
                  "kill": "a company lane STATUS.md with probes but no oracle id in .claude/state/hunt-loop/oracles/ "
                          "is the counterexample; zero such lanes in 7 days keeps the rule"})
    props.append({"title": "Keep paying the honesty bonus only for floor-met DEADs (8 probes plus a burst)",
                  "rows": [f"ledger 7d: floor-met honest DEAD mints {paid.get('floor-met honest DEAD', 0)} RC"],
                  "kill": "a bonus row paid to a bot whose floorless DEAD count beat its honest count refutes the "
                          "code path; audit with gnoc company journal"})
    props = props[:3]
    facts = (f"week ending {date}: minted {sum(paid.values())} RC ({', '.join(f'{k} {v}' for k, v in paid.items()) or 'none'}); "
             f"candidate outcomes {len(cands)}; burnt {sum(burned.values())} RC; burners with no earnings: "
             f"{', '.join(f'{k} {v}' for v, k in for_nothing[:3]) or 'none'}")
    prose, src = _voice(facts, "Write a short retro summary for the user from these facts.", facts, sentences=3)
    lines = [f"# RETRO {date} (company manager, orch-bot)", "", f"Prose ({src}): {prose}", "",
             "## 1. What paid", ""]
    lines += [f"- {k}: {v} RC" for k, v in sorted(paid.items(), key=lambda kv: -kv[1])] or ["- nothing minted this week"]
    lines += [f"- candidate outcome: {r.get('target')} {r.get('vector', '')[:80]} ({r.get('verdict')})" for r in cands[:5]]
    lines += ["", "## 2. What burned RC for nothing", ""]
    lines += [f"- {k}: burnt {v} RC, earned 0" for v, k in for_nothing[:5]] or ["- no bot burnt RC without earning"]
    lines += [f"- {p}: {d['probes']} probes, {d['n']} outcomes, 0 candidates" for p, d in
              sorted(by_prog.items(), key=lambda kv: -kv[1]["probes"]) if d["cand"] == 0][:5]
    lines += ["", "## 3. Proposals (for the user; the manager never edits SPINE, CLAUDE.md or the Manual)", ""]
    for i, pr in enumerate(props, 1):
        lines += [f"### P{i}. {pr['title']}", "", "Supporting rows:", ""] + [f"    {r}" for r in pr["rows"]] + \
                 ["", f"Kill byte: {pr['kill']}", ""]
    os.makedirs(RETRO_DIR, exist_ok=True)
    path = os.path.join(RETRO_DIR, f"RETRO-{date}.md")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    rel = os.path.relpath(path, WS)
    for i, pr in enumerate(props, 1):
        inbox_line("company", rel, f"PROPOSAL P{i}: {pr['title']} (kill byte: {pr['kill']})")
    journal("retro", path=rel, proposals=[p["title"] for p in props], voice=src)
    c["retro"] = {"ts": _now(), "path": rel}
    return path


def train(c, R):
    """Daily: the worst-brier bot re-runs the core curriculum (background); the previous run's grade is logged."""
    j = (c.get("jobs") or {}).get("train") or {}
    if j.get("out") and not _alive(j.get("pid")):
        tail = [ln for ln in _read(os.path.join(WS, j["out"])).splitlines() if re.search(r"grade|passed|\d+/\d+", ln, re.I)]
        if tail:
            journal("train-grade", bot=j.get("bot"), grade=tail[-1][:200])
            c["train_grade"] = {"bot": j.get("bot"), "grade": tail[-1][:200]}
    if _stop():
        return "train: skip, STOP is set"
    scored = [(E.brier(n, R), n) for n in _names(R)]
    scored = [(b, n) for b, n in scored if b is not None]
    if not scored:
        return "train: no bot has a brier yet"
    worst = max(scored)[1]
    # core.txt is graded against this workspace's own receipts; a copy without it trains on the general set
    cur = next((p for p in (os.path.join(WS, "scripts/gnoc-curriculum", f) for f in ("core.txt", "offsec-defsec.txt"))
                if os.path.isfile(p)), None)
    if not cur:
        return "train: no curriculum file"
    msg = _bg(c, "train", [[sys.executable, os.path.join(WS, "scripts/gnoc_train.py"), cur]])
    c["jobs"]["train"]["bot"] = worst
    journal("train", bot=worst, result=msg)
    return msg


def bubble(c):
    working = sum(1 for r in c.get("roster") or [] if r.get("status") == "working")
    prob = [r["bot"] for r in c.get("roster") or [] if r.get("status") == "probation"]
    p = c.get("pnl") or {}
    live = len(c.get("bounties") or [])
    facts = (f"{working} bots hunting, {len(prob)} broke, {live} rewards up, {p.get('net_24h', 0)} coins net today, "
             f"{p.get('ready_24h', 0)} reports ready")
    text, src = _voice(facts, "Say one short sentence the manager would say to the office right now.", facts, 1)
    c["manager"] = {"bubble": text[:160], "voice": src, "ts": _now()}
    return text


# ---------------------------------------------------------------- the one tick step

DUTIES = ("learn", "sales", "hunt", "intel", "qa", "books", "bonus", "retro", "train", "bubble")


def manage(st=None, now=None):
    """orch-bot's single company step. Each duty is wrapped: a failing duty is journaled and the rest still run;
    company.json is saved at the end. Returns {duty: result}."""
    now = now or time.time()
    c = load()
    c.setdefault("started", _now())
    results = {}
    c["paused"], c["stop"], c["auto_hunt"] = os.path.exists(PAUSE), _stop(), _autohunt()
    if c["paused"]:
        for r in c.get("roster") or []:
            r["status"] = "paused"
        c["manager"] = dict(c.get("manager") or {}, bubble="company paused (.claude/state/economy/PAUSE)", ts=_now())
        save(c)
        return {"paused": True}
    E.ensure()
    R = E.rows()
    outcomes = _jsonl(OUTCOMES, 3000)
    errors = {}
    try:
        payroll(c, R, outcomes, now)
        results["payroll"] = f"{len(c['roster'])} bots"
        if "class_factor" not in c:
            adjust(c)
    except Exception as e:  # noqa: BLE001
        errors["payroll"] = f"{type(e).__name__}: {e}"[:200]
    try:
        floor(c, R, now)   # kanban, WIP, bottleneck, staffing: the hunt duty below schedules by it
    except Exception as e:  # noqa: BLE001
        errors["floor"] = f"{type(e).__name__}: {e}"[:200]
    for duty in DUTIES:
        if not _due(c, duty, now):
            continue
        try:
            if duty == "learn":
                results[duty] = f"{len(learn(c, R, outcomes))} beliefs"
            elif duty == "sales":
                cands = candidates(c, now)
                posted = fund_bounties(c, cands)
                R = E.rows()
                wos = open_work_orders(c, R)
                results[duty] = (f"{len(cands)} candidates, posted {len(posted)}, work orders "
                                 f"{sum(1 for w in wos if w['wo_id'])}/{len(wos)} opened")
            elif duty == "hunt":
                results[duty] = hunt(c, R, outcomes, now)
                R = E.rows()
            elif duty == "intel":
                results[duty] = intel(c)
            elif duty == "qa":
                results[duty] = qa(c)
            elif duty == "books":
                results[duty] = books(c)
                R = E.rows()
            elif duty == "bonus":
                results[duty] = bonus(c, R)
                R = E.rows()
            elif duty == "retro":
                adjust(c)
                results[duty] = retro(c, now)
            elif duty == "train":
                results[duty] = train(c, R)
            elif duty == "bubble":
                results[duty] = bubble(c)
            _mark(c, duty, now)
        except Exception as e:  # noqa: BLE001 - one duty can never stop the others or the tick
            errors[duty] = f"{type(e).__name__}: {e}"[:200]
            journal("duty-error", duty=duty, detail=errors[duty])
            _mark(c, duty, now)   # back off a full cadence instead of retrying every tick
    try:
        payroll(c, E.rows(), outcomes, now)   # the roster the office reads reflects this tick's bounties and claims
    except Exception as e:  # noqa: BLE001
        errors["payroll-refresh"] = repr(e)[:200]
    try:
        R = E.rows()
        floor(c, R, now)
        story(c, R, outcomes, now)   # plain sentences for the office ticker, from real events only
        screen(c, R, now)
    except Exception as e:  # noqa: BLE001
        errors["floor"] = f"{type(e).__name__}: {e}"[:200]
    c["errors"] = errors
    c["results"] = {k: str(v)[:200] for k, v in results.items()}
    save(c)
    return results


# ---------------------------------------------------------------- CLI

def status_text():
    c = load()
    if not c:
        return "company: not started (orch-bot runs manage() every tick; PAUSE file: .claude/state/economy/PAUSE)"
    p = c.get("pnl") or {}
    try:  # company.json is rewritten every manager tick: an old "updated" means orch-bot is not ticking
        age = time.time() - datetime.fromisoformat(str(c.get("updated")).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        age = None
    run = ("PAUSED" if c.get("paused") else "running" if age is None or age < 900 else
           f"STALE {age / 3600:.1f} h (orch-bot not ticking)")
    out = [f"COMPANY  updated {c.get('updated')}  {run}  "
           f"STOP {'set (lanes only)' if c.get('stop') else 'clear'}  AUTO-HUNT {c.get('auto_hunt') or 'off'}",
           f"treasury {c.get('reserve')}  escrow {c.get('escrow')}  P&L 24h minted {p.get('minted_24h')} burnt "
           f"{p.get('burnt_24h')} net {p.get('net_24h')}  drafts {p.get('drafts_24h')} READY {p.get('ready_24h')}  "
           f"dupe odds {p.get('dupe_odds')}",
           f"manager: {(c.get('manager') or {}).get('bubble', '')}  ({(c.get('manager') or {}).get('voice', '-')})",
           floor_text(c),
           "PAYROLL  bot             wallet  brier   status     morale  assignment"]
    for r in c.get("roster") or []:
        out.append(f"         {r['bot']:<15} {r['wallet']:>6}  {'-' if r.get('brier') is None else r['brier']:>6}  "
                   f"{r['status']:<10} {r.get('morale', '-'):>5}  {r.get('assignment', '')[:50]}")
    out.append(f"bot of the day: {c.get('bot_of_day') or '-'}   bonus {json.dumps(c.get('bonus') or {})[:120]}")
    out.append(f"BOUNTIES {len(c.get('bounties') or [])} live")
    for b in c.get("bounties") or []:
        out.append(f"         {b['id']} {b.get('program')} {b.get('crown')} {b.get('amount')} RC {b['state']}"
                   f"{' by ' + b['claimant'] if b.get('claimant') else ''}")
    out.append(f"MARKETS  {len(c.get('bets') or [])} open")
    for m in (c.get("bets") or [])[-8:]:
        out.append(f"         {m['program']} {m['hyp']} long {m['long']} short {m['short']} budget {m['budget']}")
    if c.get("errors"):
        out.append(f"errors   {json.dumps(c['errors'])[:300]}")
    return "\n".join(out)


def floor_text(c):
    k = c.get("kanban") or {}
    if not k:
        return "FLOOR    not computed yet (the next manage tick writes kanban, desks, staffing, standup)"
    wip = "  ".join(f"{r['name']} {r['n']}/{r['cap']}" + ("!" if r["full"] else "") if r["cap"] else
                    f"{r['name']} {r['n']}" for r in k.get("stations") or [])
    su = c.get("standup") or {}
    hire = (su.get("hiring") or {}).get("text") or "no hiring call"
    staff_ = ", ".join(f"{b}@{v['station']}" for b, v in sorted((c.get("staffing") or {}).items())) or "nobody staffed"
    desks = ", ".join(f"{d['label']}{'(open)' if d['trap'] and d.get('open') else ''}:{d.get('items', 0)}"
                      for d in c.get("desks") or [])
    return (f"FLOOR    bottleneck {k.get('bottleneck') or 'none'}  pull {k.get('pull') or 'none'}  WIP {wip}\n"
            f"         desks {desks}\n         staffing {staff_}\n         {hire}\n"
            f"         standup: {su.get('voice', '-')}")


def main(argv):
    cmd = argv[0] if argv else "status"
    if cmd == "status":
        print(status_text())
    elif cmd == "journal":
        n = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 20
        for r in _jsonl(JOURNAL, n):
            print(json.dumps(r, default=str)[:300])
    elif cmd == "retro":
        c = load()
        adjust(c)
        print(retro(c))
        save(c)
    elif cmd == "manage":
        print(json.dumps(manage({}), default=str, indent=1)[:3000])
    else:
        print("usage: gnoc company status | journal [n] | retro | manage")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
