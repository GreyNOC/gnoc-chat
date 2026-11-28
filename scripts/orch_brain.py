#!/usr/bin/env python3
"""orch_brain.py - the decision layer of orch-bot: a local open-weight model picks the next move.

Model: qwen3-14b-oc (Qwen3 14B abliterated, mlabonne, Q4_K_M) on the user Ollama 127.0.0.1:11434, the same model the
OpenCode worker uses, so a decision never forces a model swap. Override with ORCH_BRAIN_MODEL / ORCH_BRAIN_URL.

How it works. orch-bot calls decide(st, launch) only when it is IDLE (no job running, no hand-started lane, no STOP).
The brain builds a compact snapshot of the hunt (focus program, its unswept host families, recent sweeps and hits,
escalations, the lane queue, inbox, candidate programs, its own last decisions with their results), asks the model
for ONE action as schema-constrained JSON, VALIDATES it in code, executes it, and journals it. If the model is down,
slow, or proposes something invalid, orch-bot falls back to its old fixed rules for that tick.

The model can only choose from this menu; it never gets a shell, never files, never edits a report:
  run_queue        start the next queued OpenCode lane
  sweep_host       auto-hunt one NAMED unswept host of the focus program (must be in its plan)
  sweep_next       auto-hunt the next batch in plan order
  skip_family      mark every unswept host matching a suffix pattern (e.g. *.app.example.com) as skipped
  escalate         run auto-escalate.py on the focus program's hits
  follow_up_lane   write a GET-only lane (brief + up to 20 in-scope URLs) and queue it for the GPU worker
  pivot            switch the hunt to another program (gnoc pivot, intake first if new)
  pick_target      park the focus program and let auto-target choose
  notify           put a NEEDS/NOTE line in the orch inbox for the user
  wait             do nothing for N minutes
Hard limits stay in code: SCOPE.txt on every URL, the program's automation ban (auto-hunt refuses), STOP, GET only.

Files: .claude/state/orch/BRAIN.enabled (on/off), brain.jsonl (decision journal), BRAIN-NOTES.md (standing notes
the user can edit; fed to the model every call).
"""
import glob
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
ENABLED = os.path.join(ORCH, "BRAIN.enabled")
JOURNAL = os.path.join(ORCH, "brain.jsonl")
NOTES = os.path.join(ORCH, "BRAIN-NOTES.md")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import llm_endpoints  # noqa: E402  role -> (laptop | linked desktop) Ollama, with fallback

URL = os.environ.get("ORCH_BRAIN_URL", "")      # empty = the "brain" role's host (gnoc models use brain X [--on desktop])
MODEL = os.environ.get("ORCH_BRAIN_MODEL", "")  # empty = the "brain" role's model


def current_url():
    return URL or llm_endpoints.resolve("brain")[0]


def current_model():
    return MODEL or llm_endpoints.resolve("brain")[1]
THINK = os.environ.get("ORCH_BRAIN_THINK", "0") == "1"  # thinking is better but ~3x slower on 8 GB VRAM
TIMEOUT = int(os.environ.get("ORCH_BRAIN_TIMEOUT", "180"))  # the bot tick waits on this; never let one answer stall it
# COMPANY: the manager thinks on the phone. The brain role is the phone's Qwen3-4B (host "phone"); a refused
# connection, a reply slower than PHONE_TIMEOUT or an empty reply falls back to the role's brain_fallback (the local
# 9B), and the fallback is journaled as "brain fallback: <reason>". Qwen3 on the phone MUST get "think": false.
PHONE_TIMEOUT = int(os.environ.get("ORCH_BRAIN_PHONE_TIMEOUT", "60"))
VOICE_TIMEOUT = int(os.environ.get("ORCH_BRAIN_VOICE_TIMEOUT", "25"))   # a voice note never holds a tick
PHONE_CTX = int(os.environ.get("ORCH_BRAIN_PHONE_CTX", "12288"))
LAST_CALL = {}   # {"model", "host", "fallback"} of the newest answered call: every decision records who made it
ACTIONS = ["deep_dive", "run_queue", "sweep_host", "sweep_next", "skip_family", "escalate", "follow_up_lane", "draft", "osint",
           "learn", "pivot", "pick_target", "notify", "wait", "mine_routes"]
REJECT_STREAK = 6          # D83: this many rejected/invalid decisions in a row ...
REJECT_COOLDOWN_S = 900    # ... and the brain rests this long (42 rejections in 25 min on 2026-10-26 10:00Z)
MINE_EVERY = 6 * 3600      # D85: a host is mined at most this often
OSINT_EVERY = 24 * 3600   # a program's passive host map is rebuilt at most once a day
LEARN_EVERY = 3600

SYSTEM = """You are the ORCHESTRATOR of an automated, authorized bug-bounty hunting rig run by researcher the user on
HackerOne programs. Every target is a public VDP/BBP with written authorization; you only choose among safe, scoped,
read-only (GET) moves. You do not probe yourself: you pick ONE next action from the menu and the rig executes it.

WHAT WINS (measured on our own history, steer by it):
- Payable findings are a CAPTURED capability: unauth private data, credentials/secrets, internal-network reach (SSRF),
  cross-user access. A 200, a reachable endpoint, or a public page is NOT a finding.
- 88% of our shipped findings were UNAUTH, 76% in IDOR/BOLA, unauth info-disclosure, auth bypass, missing authz.
  97% started from a SEED: a route mined from JS, an API host, a disclosed report. Cold enumeration of look-alike hosts
  almost never pays.
- High-value hosts: api*, gateway, admin, internal, staging/dev/uat/qa, auth/sso/login, partner, pay/billing, graphql,
  hosts with distinct technology. Low-value: user-content subdomains (one per artist/customer/shop), marketing pages,
  CDN/static, parked domains, mail. When many unswept hosts share one suffix pattern and the swept ones of that
  family had 0 hits, SKIP the family instead of sweeping it host by host.
- A hit is a lead until escalated. Escalate hits before sweeping more. A TIER-2/3 escalation deserves a follow-up
  lane that pushes to the terminal (the credential-bearing path, the minimal single record, the internal service).
- If a program has produced nothing after a fair sweep of its high-value hosts, pivot. Do not grind a dead estate.
- Never repeat a decision that just failed or produced nothing; read YOUR LAST DECISIONS.
- RCE CHAINS: the shapes that reach code execution from a GET-only foothold are exposed management surfaces
  (actuator env/heapdump/jolokia, debug consoles, h2/werkzeug consoles, exposed .git/.env with keys, swagger with
  admin routes, SSRF to an internal management port). When a hit shows one, a follow_up_lane maps the next chain link
  (the credential, the internal port, the console) GET-only. Firing an execution payload is never your move: notify.

MENU (choose exactly one; fill only the fields it needs):
- run_queue: a lane is queued in LANE QUEUE; run it (queued lanes are deliberate work, usually run them first).
- sweep_host {program, host}: sweep ONE host copied exactly from UNSWEPT HOSTS. Prefer high-value hosts.
- sweep_next {program}: sweep the next batch in plan order (only when plan order is already sensible).
- skip_family {program, pattern}: pattern like "*.app.example.com" or "*.shop.example.com"; marks those unswept
  hosts skipped. Use for big low-value families. Must match at least 3 unswept hosts.
- escalate {program}: there are un-escalated hits in RECENT SWEEPS/INBOX for the focus program.
- follow_up_lane {program, lane, brief, urls}: up to 20 GET URLs on in-scope hosts that push a specific lead to its
  terminal; brief = 2-6 sentences: the lead, the kill byte that would prove impact, the negative control. Include
  one nonsense-path control URL. Only for a concrete lead you can see in the snapshot; never invent hosts.
- mine_routes {program, host}: when KNOWN ROUTES says every mined API route was fired, mine another in-scope host's
  bundles for new routes (js_mine on its landing page). One host per call, at most once per host per 6 hours.
- draft {program}: PENDING DRAFTS lists a TIER-3 escalation with no report; the local writer builds a HELD draft that
  quotes the raw bytes (a human reviews it). Do this before more sweeping: a finding not written up is lost.
- osint {program}: rebuild the program's passive host map (subdomains, certificates, liveness) when OSINT says it is
  stale or never run, or when few unswept hosts are left; new hosts are the freshest, least-tested ground.
- learn: refresh the lessons file from all outcomes (only when LEARN says it is due).
- pivot {program}: hunt a different program from CANDIDATE PROGRAMS.
- pick_target: park the focus program and let the ranker choose the next.
- notify {message}: something only the user can do (an account, a ruling, a payment); short.
- wait {minutes}: nothing useful to do right now.

Answer with JSON only. "reason" first: 1-3 sentences citing the snapshot facts behind the choice."""


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enabled():
    return os.path.isfile(ENABLED)


def read(p, default=""):
    try:
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return default


def run(cmd, timeout=120, env=None):
    try:
        r = subprocess.run(cmd, cwd=WS, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                           env=dict(os.environ, **(env or {})))
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def journal(rec):
    with open(JOURNAL, "a") as f:
        f.write(json.dumps(rec) + "\n")


def last_decisions(n=8):
    out = []
    for ln in read(JOURNAL).splitlines()[-n:]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def note_result(result):
    """Attach the outcome of the job a decision started (called by orch-bot when that job ends)."""
    lines = read(JOURNAL).splitlines()
    for i in range(len(lines) - 1, -1, -1):
        try:
            rec = json.loads(lines[i])
        except ValueError:
            continue
        if rec.get("started_job") and not rec.get("result"):
            rec["result"] = result[:300]
            lines[i] = json.dumps(rec)
            with open(JOURNAL, "w") as f:
                f.write("\n".join(lines) + "\n")
            return


# ---------- snapshot ----------

def focus_program():
    words = read(os.path.join(ORCH, "AUTO-HUNT")).split()
    p = words[0] if words and words[0] != "target" else ""
    return p if p and os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt")) else ""


GOAL = os.path.join(ORCH, "GOAL.md")   # GreyNOC's standing goal; read by the brain and by gnoc_company's steer


def goal_text():
    return read(GOAL).strip()[-1500:]


def line_work(program):
    """Open LINE work orders and queued lanes for a program: the work a brain move must not abandon."""
    if not program:
        return [], []
    wos = []
    try:
        rc, out = run([sys.executable, os.path.join(WS, "scripts/gnoc_line.py"), "status", program], timeout=30)
    except Exception:  # noqa: BLE001 - a broken line reads as no work; the gate then falls back to churn only
        out = ""
    for ln in out.splitlines():
        if ln.startswith(program + " WO-"):
            wos.append(ln.strip()[:160])
    lanes = [l for l in read(os.path.join(ORCH, "queue.txt")).splitlines()
             if l.strip() and not l.startswith("#") and l.split("|")[0].strip() == program]
    return wos, lanes


CHAIN_KINDS = ("ssrf", "redirect", "oauth", "login", "token", "auth", "actuator", "admin", "console", "upload",
               "import", "render", "callback", "webhook", "unauth-json", "secret", "debug", "graphql")


def chain_leads(program, limit=8):
    """Leads of the focus program that no lane has followed yet, chain-relevant kinds first. A lead is FOLLOWED when
    its URL (or its host plus the first path segment) appears in any PROBES.txt under targets/<program>/hunts/.
    Sources: hunts/auto-exposure/LEADS.md (`- ts kind status url :: detail (raw)`) and escalations.jsonl rows."""
    if not program:
        return []
    probed = ""
    for p in glob.glob(os.path.join(WS, "targets", program, "hunts", "*", "PROBES.txt")):
        probed += read(p) + "\n"
    rows = []
    for ln in read(os.path.join(WS, "targets", program, "hunts/auto-exposure/LEADS.md")).splitlines()[-200:]:
        m = re.match(r"-\s+(\S+)\s+(\S+)\s+(\S+)\s+(https?://\S+)(?:\s+::\s+(.*?))?(?:\s+\(raw/.*\))?\s*$", ln)
        if m:
            rows.append((m.group(2), m.group(4), (m.group(5) or "").strip()))
    for ln in read(os.path.join(ORCH, "escalations.jsonl")).splitlines()[-100:]:
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if e.get("program") == program and int(e.get("tier") or 0) >= 2 and e.get("url"):
            rows.append((f"tier-{e.get('tier')}", str(e["url"]), str(e.get("verdict", ""))[:80]))
    out, seen = [], set()
    for kind, url, detail in rows:
        m = re.match(r"https?://([^/\s]+)(/[^?\s]*)?", url)
        if not m:
            continue
        host, path = m.group(1), (m.group(2) or "/")
        seg = "/" + path.strip("/").split("/")[0] if path.strip("/") else "/"
        key = (host, seg, detail[:40])
        if key in seen:
            continue
        seen.add(key)
        followed = url in probed or (seg != "/" and f"{host}{seg}" in probed) or (detail and detail.split()[0] in probed)
        if not followed:
            out.append({"kind": kind, "url": url, "detail": detail,
                        "chain": any(k in (kind + " " + detail + " " + path).lower() for k in CHAIN_KINDS)})
    out.sort(key=lambda r: (not r["chain"]))
    return out[:limit]


LOCK_FILE = os.path.join(WS, ".claude/state/hunt-loop/LOCK")


def locked_program():
    """The program the session LOCK pins (scripts/hunt-loop/lock.sh set <handle>), or ''. A locked program is
    the user's named target: the bot works it indefinitely and never rotates off it on its own (CLAUDE.md, SINGLE
    NAMED TARGET). 2026-10-26 00:30Z: program-0 (locked) finished its 6-host sweep, the fixed rules marked it
    exhausted, rewrote AUTO-HUNT to `target` and auto-target intook and swept program-07 for 40 minutes."""
    p = read(LOCK_FILE).strip().split()[:1]
    p = p[0] if p else ""
    return p if p and os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt")) else ""


def churn(n=6):
    """(moves, programs) over the last n decisions: how many were a pivot/pick_target that went through, and which
    programs they left or parked. Two moves with no job in between is churn; moving back to a program just left is
    ping-pong. Measured 2026-10-25: 423 of 847 journal rows were pick_target and only 107 rows ever started a job."""
    moved, progs = 0, set()
    for d in last_decisions(n):
        if d.get("action") in ("pivot", "pick_target") and d.get("status") == "ok":
            moved += 1
            det = str(d.get("detail", ""))
            m = re.search(r"pivot: (\S+) -> (\S+)", det)
            if m:
                progs.update(m.groups())
            m = re.search(r"parked (\S+)", det)
            if m:
                progs.add(m.group(1).rstrip(";,"))
        elif d.get("started_job"):
            moved = 0   # real work resets the churn count
    return moved, {p for p in progs if p and p != "(none)"}


_PLAN_CACHE = {}
PLAN_CACHE_S = 120   # D95: one tick called plan() up to six times, a 90 s subprocess each


def plan(program):
    """(swept, unswept) host lists in auto-hunt's own order (cached PLAN_CACHE_S per program)."""
    hit = _PLAN_CACHE.get(program)
    if hit and time.time() - hit[0] < PLAN_CACHE_S:
        return list(hit[1]), list(hit[2])
    rc, out = run([sys.executable, "scripts/auto-hunt.py", program, "--plan", "--all"], timeout=90)
    swept, unswept = [], []
    for ln in out.splitlines():
        m = re.match(r"\s*(done|todo|\S+)\s+https?://([^/\s]+)", ln)
        if m:
            (swept if m.group(1) == "done" else unswept).append(m.group(2).lower())
    _PLAN_CACHE[program] = (time.time(), list(swept), list(unswept))
    return swept, unswept


def family(host):
    """app.example.com -> *.app.example.com ; a.b.example.co.uk -> *.b.example.co.uk"""
    parts = host.split(".")
    return "*." + ".".join(parts[1:]) if len(parts) > 2 else host


def auto_state(program):
    try:
        return json.load(open(os.path.join(ORCH, f"auto-{program}.json")))
    except (OSError, ValueError):
        return {"swept": {}}


def oss_worklist(prog, n=5):
    """The triaged oss-bot pile (scripts/oss-bot/triage.py writes it; orch-bot runs it when the pile grows).
    Network rows for the FOCUS program are follow_up_lane material: GET-verify the exact URL, never file from it."""
    try:
        wl = json.load(open(os.path.join(WS, ".claude/state/oss-bot/worklist.json"))).get("items") or []
    except (OSError, ValueError):
        return "OSS-BOT SCANNER LEADS: (no worklist yet)"
    net = [w for w in wl if w.get("kind") == "network" and w.get("program") == prog][:n]
    sec = sum(1 for w in wl if w.get("kind") == "secret")
    out = [f"OSS-BOT SCANNER LEADS (triaged; LEADs only, never findings; {sec} secret file reviews are for the user, "
           "not you):"]
    out += [f"  {w['program']} {w['rule']} {w['severity']} score {w['score']}: {w['url']}" for w in net]
    if net:
        out.append("  -> a follow_up_lane on 2-6 of these exact URLs (GET only) is a good move when no sweep is due.")
    else:
        out.append(f"  (no network scanner leads for {prog or 'the focus program'})")
    return "\n".join(out)


def snapshot(st):
    prog = focus_program()
    parts = [f"TIME {now()}   FOCUS PROGRAM: {prog or '(none - pivot or pick_target)'}"]
    lock = locked_program()
    if lock:
        parts.append(f"LOCKED TARGET: {lock} is the session's named target. pivot and pick_target are REFUSED for it; "
                     "do not propose them. When every host is swept, the work is follow_up_lane (2-20 GET URLs on its "
                     "api / auth / console routes from known-paths or a mined bundle, one nonsense-path control), "
                     "escalate when a hit exists, osint when due, or wait.")
    q = [l for l in read(os.path.join(ORCH, "queue.txt")).splitlines() if l.strip() and not l.startswith("#")]
    parts.append("LANE QUEUE:\n" + ("\n".join(f"  {l[:160]}" for l in q[:5]) or "  (empty)"))
    if prog:
        swept, unswept = plan(prog)
        sw = auto_state(prog).get("swept", {})
        hits = sum(v.get("hits", 0) for v in sw.values())
        leads = sum(v.get("leads", 0) for v in sw.values())
        parts.append(f"FOCUS STATS: {len(swept)} swept, {len(unswept)} unswept, {hits} hits, {leads} leads total")
        fam_un = Counter(family(h) for h in unswept)
        fam_sw = Counter()
        fam_hits = Counter()
        for h, v in sw.items():
            fam_sw[family(h)] += 1
            fam_hits[family(h)] += v.get("hits", 0) + v.get("leads", 0)
        rows = [f"  {f}: {n} unswept, {fam_sw[f]} swept, {fam_hits[f]} hits+leads" for f, n in fam_un.most_common(12)]
        parts.append("UNSWEPT HOST FAMILIES (largest first):\n" + ("\n".join(rows) or "  (none)"))
        singles = [h for h in unswept if fam_un[family(h)] <= 3]
        rest = [h for h in unswept if h not in singles]
        pick = (singles + rest)[:40]
        parts.append("UNSWEPT HOSTS (copy exactly for sweep_host; small families first):\n  " + "\n  ".join(pick))
        recent = sorted(sw.items(), key=lambda kv: kv[1].get("ts", ""))[-10:]
        parts.append("RECENT SWEEPS (ALREADY DONE - never choose these hosts again):\n" + "\n".join(
            f"  {h}: fired {v.get('fired', 0)} hits {v.get('hits', 0)} leads {v.get('leads', 0)}"
            + (" (skipped)" if v.get("skipped") else "") for h, v in recent))
        lf = os.path.join(WS, "targets", prog, "hunts/auto-exposure/LEADS.md")
        ll = read(lf).splitlines()[-8:]
        if ll:
            parts.append("FOCUS LEADS (newest):\n" + "\n".join(f"  {l[:220]}" for l in ll))
    if prog:
        # mined routes (js_mine / hunt_brief write them): the material for a follow_up_lane. The brain's first
        # follow-up on program-0 (2026-10-26 01:20Z) guessed /internal/debug while 14 mined routes sat on disk.
        kp, total, fired_n = unfired_known_routes(prog)   # D65: the routes no lane has fired yet
        if kp and not any(_api_shaped(k) for k in kp):
            parts.append(f"KNOWN ROUTES for {prog}: every API-shaped mined route ({fired_n} of {total}) was fired by a "
                         "lane or walled by the hunt; the rest are documentation pages, which are not lane material. "
                         "A new lane needs js_mine on another in-scope host "
                         f"({', '.join(scope_hosts(prog)[:6]) or 'see SCOPE.txt'}), osint, or escalate on a flagged row.")
            kp = []
        if kp:
            parts.append(f"KNOWN ROUTES for {prog} (mined from its bundles; {total} known, {fired_n} already fired by "
                         f"a lane or walled by the hunt, these {len(kp)} are UNFIRED; build follow_up_lane URLs from "
                         f"THESE on the in-scope hosts {', '.join(scope_hosts(prog)[:6]) or '(see SCOPE.txt)'}, never "
                         "from guesses, never from routes a lane already fired):\n  " + "\n  ".join(kp))
        elif total:
            parts.append(f"KNOWN ROUTES for {prog}: all {total} mined routes were fired by a lane or walled; a new lane "
                         "needs js_mine on another in-scope host, osint, or escalate on a flagged row.")
    if prog:
        cl = chain_leads(prog)
        if cl:
            parts.append("CHAIN LEADS WITHOUT A FOLLOW-UP LANE (depth before breadth; sweeps and moves are refused "
                         "while these wait):\n" + "\n".join(
                f"  {l['url'][:120]}  [{l['kind']}{', chain' if l['chain'] else ''}] {l['detail'][:80]}" for l in cl))
    if prog:
        wos, lanes = line_work(prog)
        parts.append(f"LINE WORK for {prog} (open work orders own the program; queued lanes run before any move):\n"
                     + ("\n".join(f"  {w}" for w in wos[:6]) or "  (no open work orders)")
                     + (f"\n  queued lanes: {len(lanes)}" if lanes else ""))
    parts.append(oss_worklist(prog))
    esc = []
    for ln in read(os.path.join(ORCH, "escalations.jsonl")).splitlines()[-6:]:
        try:
            e = json.loads(ln)
            esc.append(f"  {e.get('program')} {e.get('tier', '')} {str(e.get('url', ''))[:140]} {str(e.get('why', ''))[:80]}")
        except ValueError:
            pass
    parts.append("RECENT ESCALATIONS:\n" + ("\n".join(esc) or "  (none)"))
    parts.append("INBOX (last 10):\n" + "\n".join(
        f"  {l[2:240]}" for l in read(os.path.join(ORCH, "INBOX.md")).splitlines()[-10:] if l.startswith("- ")))
    rc, pend = run([sys.executable, "scripts/local-draft.py", "--pending"], timeout=60)
    parts.append("PENDING DRAFTS (TIER-3 escalations with no report):\n" + ("\n".join(f"  {l}" for l in pend.splitlines()[:5]) or "  (none)"))
    if prog:
        last = st.get("osint", {}).get(prog, 0)
        parts.append(f"OSINT for {prog}: " + ("never run by the brain" if not last else
                     f"last {int((time.time() - last) / 3600)} h ago" + (" (due)" if time.time() - last > OSINT_EVERY else " (not due)")))
    parts.append("LEARN: " + ("due" if time.time() - st.get("last_learn", 0) > LEARN_EVERY else "not due"))
    rc, rank = run([sys.executable, "scripts/auto-target.py", "--rank"], timeout=60)
    ok = [re.sub(r"^(VDP|paid)\s+(\S+)", r"\2  [\1]", l.strip())
          for l in rank.splitlines() if l.strip().endswith(" ok") or "needs intake" in l][:12]
    parts.append("CANDIDATE PROGRAMS (ranker order; 'needs intake' is fine, pivot intakes it):\n  " + "\n  ".join(ok))
    dec = last_decisions()
    parts.append("YOUR LAST DECISIONS (oldest first):\n" + ("\n".join(
        f"  {d['ts']} {d.get('action')} {d.get('detail', '')[:100]} -> {d.get('status')}"
        f"{' | result: ' + d['result'][:140] if d.get('result') else ''}" for d in dec) or "  (none)"))
    goal = goal_text()
    if goal:
        parts.append("STANDING GOAL FROM GREYNOC (outranks the win-rate steer in your instructions):\n" + goal)
    notes = read(NOTES).strip()
    if notes:
        parts.append("STANDING NOTES FROM GREYNOC:\n" + notes[-1500:])
    return "\n\n".join(parts)[-12000:], prog


# ---------- model ----------

SCHEMA = {
    "type": "object",
    "properties": {
        "reason": {"type": "string"},
        "action": {"type": "string", "enum": ACTIONS},
        "program": {"type": "string"},
        "host": {"type": "string"},
        "pattern": {"type": "string"},
        "lane": {"type": "string"},
        "brief": {"type": "string"},
        "urls": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
        "message": {"type": "string"},
        "minutes": {"type": "integer"},
    },
    "required": ["reason", "action"],
}


def _targets(role="brain"):
    """[(chat_url, model, host)] in the order they are tried for ROLE: the role as written, then <role>_fallback, then
    the brain chain, then whatever llm_endpoints.resolve("brain") answers. The user 2026-10-23: the STRONGEST bot
    (the desktop RTX lead) is the brain that DECIDES and dishes out orders; the phone 4B is the VOICE (1:1 notes,
    bubbles, retro prose) and a cheap skeptic. A full decision on the phone measured 127 s, its voice calls 5 s.
    ORCH_BRAIN_URL / ORCH_BRAIN_MODEL pin one target and skip the chain. A stock (censored) model is never tried."""
    if URL or MODEL:
        return [(current_url(), current_model(), "env")]
    r = llm_endpoints.roles()
    out = []
    specs = [r.get(role), r.get(role + "_fallback")]
    if role != "brain":
        specs += [r.get("brain"), r.get("brain_fallback")]
    for spec in specs:
        if not isinstance(spec, str) or not spec.strip():
            continue
        name, host = llm_endpoints.split(spec)
        if not name or not llm_endpoints.HOSTS.get(host):
            # an unknown host, or one this machine never set up (no phone on a fresh install): there is no URL to
            # try, and "http:///api/chat" only burned a failed call before the fallback (release suite 2026-11-28)
            continue
        if not llm_endpoints.allow_stock() and llm_endpoints.stock(name, host) is True:
            continue
        t = (f"http://{llm_endpoints.HOSTS[host]}/api/chat", name, host)
        if t not in out:
            out.append(t)
    try:
        t = llm_endpoints.resolve("brain")
        if t not in out:
            out.append(t)
    except Exception:  # noqa: BLE001 - the chain above may still answer
        pass
    return out


def _post_chat(url, body, timeout):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()).get("message", {}).get("content", "")


def _why(e):
    r_ = getattr(e, "reason", e)
    if isinstance(e, TimeoutError) or isinstance(r_, TimeoutError) or "timed out" in str(e):
        return "timeout"
    if isinstance(e, ConnectionRefusedError) or isinstance(r_, ConnectionRefusedError):
        return "connection refused"
    return f"{type(e).__name__}: {e}"[:200]


def _call(messages, fmt=None, num_predict=400, temperature=0.2, role="brain"):
    """One chat call down the target chain for ROLE. Returns the cleaned content; records LAST_CALL; journals each fallback."""
    errs, targets = [], _targets(role)
    for i, (url, model, host) in enumerate(targets):
        phone = host == "phone"
        body = {"model": model, "stream": False, "think": False if phone else THINK, "messages": messages,
                "keep_alive": "30m",   # D84: the same runner as the lead's, kept warm between ticks
                "options": {"num_ctx": PHONE_CTX if phone else llm_endpoints.ctx_for_host(host),   # D67: one table
                            "temperature": temperature,
                            "num_predict": num_predict if (phone or not THINK) else max(num_predict, 1500)}}
        if fmt:
            body["format"] = fmt
        try:
            content = _post_chat(url, body, VOICE_TIMEOUT if role == "voice" else (PHONE_TIMEOUT if phone else TIMEOUT))
            content = re.sub(r"<think>.*?</think>", "", content or "", flags=re.S).strip()
            why = "" if content else "empty reply"
        except urllib.error.HTTPError as e:
            # the bare HTTPError repr the journal used to record was just "400: Bad Request" with no
            # detail; the response BODY (Ollama's own error message) is what actually explains it
            with e:  # the error response is a live socket: close it, or every failed call leaks one
                why = f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
        except Exception as e:  # noqa: BLE001 - refused, reset, DNS, timeout: every one is a reason to fall back
            why = _why(e)
        if not why:
            LAST_CALL.clear()
            LAST_CALL.update(model=model, host=host, fallback="; ".join(errs) or None)
            return content
        errs.append(f"{host} {model}: {why}")
        if i + 1 < len(targets):
            journal({"ts": now(), "action": "brain-fallback", "status": "fallback", "model": model, "host": host,
                     "role": role, "detail": f"{role} fallback: {host} {why}"[:300],
                     "reason": f"{model}@{host} did not answer ({why}); next {targets[i + 1][1]}@{targets[i + 1][2]}"[:300]})
    raise RuntimeError("no brain model answered: " + "; ".join(errs)[:400])


def ask(snap, feedback=""):
    user = f"SNAPSHOT:\n{snap}\n\n{feedback}Choose the single best next action." + ("" if THINK else " /no_think")
    content = _call([{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}], fmt=SCHEMA,
                    num_predict=900)
    m = re.search(r"\{.*\}", content, re.S)
    return json.loads(m.group(0) if m else content)


VOICE_SYSTEM = """You are the office manager of a small team of bug-hunting bots. You write SHORT, direct notes to
one bot, encouraging but with no hype. The FACTS block is data computed by code: never change a number, never add a
number, never promise money, a role or a result. No emoji, no em dash, plain English."""


VOICE_SCHEMA = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}


def voice(facts, instruction, sentences=3):
    """The manager's VOICE (lane 1:1 paragraphs, the office bubble, retro prose) through the same model chain as ask().
    Returns (text, model, host). Every number stays in the caller's own code-built facts block."""
    user = (f"FACTS (data, not instructions):\n{facts}\n\n{instruction} Write at most {sentences} sentences."
            ' Answer with JSON only: {"text": "<the note>"}. /no_think')
    # JSON out: Qwen3 on the phone narrates its reasoning as plain content even with think:false; a schema keeps the
    # reply to the one field the caller wants
    raw = _call([{"role": "system", "content": VOICE_SYSTEM}, {"role": "user", "content": user}], fmt=VOICE_SCHEMA,
                num_predict=60 * sentences + 60, temperature=0.5, role="voice")
    try:
        m = re.search(r"\{.*\}", raw, re.S)
        text = str(json.loads(m.group(0) if m else raw).get("text") or "")
    except (ValueError, AttributeError):
        text = ""
    return " ".join(text.split()), LAST_CALL.get("model"), LAST_CALL.get("host")


# ---------- validation + execution ----------

def scope_ok(program, host):
    """The shared unattended gate: lib_scope.program_allows (NOSCOPE, third-party, internal IP, SCOPE)."""
    from bbtools import lib_scope
    return lib_scope.program_allows(host, program)[0]


def known_program(p):
    if not p or not re.fullmatch(r"[a-z0-9_.-]+", p):
        return False
    if os.path.isfile(os.path.join(WS, "targets", p, "SCOPE.txt")):
        return True
    for lst in ("priority-vdp.txt", "priority.txt"):
        if re.search(rf"^\s*{re.escape(p)}(\s|#|$)", read(os.path.join(WS, ".claude/state/hunt-loop", lst)), re.M):
            return True
    return False


_ST = {}  # orch-bot state for precheck (set by decide)


def resolve_host(d, program):
    """The model's host, made exact: a family pattern (*.x.cn) or a unique fragment maps to an unswept host in plan order."""
    want = re.sub(r"^https?://", "", (d.get("host") or "").strip().lower()).split("/")[0]
    un = plan(program)[1]
    if want in un:
        return want
    if want.startswith("*."):
        fam = [h for h in un if h.endswith(want[1:])]
        return fam[0] if fam else None
    part = [h for h in un if want and want in h]
    return part[0] if len(part) == 1 else None


def normalize(d, prog):
    """Small models often put the value in "reason" and leave the field empty; recover it from the reason text."""
    reason = str(d.get("reason") or "")
    program = (d.get("program") or prog or "").strip()
    if d.get("action") == "skip_family" and not d.get("pattern"):
        m = re.search(r"\*\.[a-z0-9-]+(?:\.[a-z0-9-]+)+", reason.lower())
        if m:
            d["pattern"] = m.group(0)
    if d.get("action") == "sweep_host" and not d.get("host") and program and \
            os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        un = plan(program)[1]
        named = [h for h in un if h in reason.lower()]
        fam = re.search(r"\*\.[a-z0-9-]+(?:\.[a-z0-9-]+)+", reason.lower())
        if named:
            d["host"] = named[0]
        elif fam:
            d["host"] = fam.group(0)
    if d.get("action") in ("pivot",) and not d.get("program"):
        m = re.search(r"\b(?:pivot(?: to)?|switch to)\s+([a-z0-9_.-]+)", reason.lower())
        if m:
            d["program"] = m.group(1)
    return d


def policy_refusal(program):
    """harmony 2.3: same rule as gnoc _policy_refusal. None = allowed (or no SCOPE.txt yet: intake gates it)."""
    if not program or not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return None
    try:
        from bbtools import lib_policy
        pol = lib_policy.policy(program)
    except Exception as e:  # fail closed
        return f"policy unreadable ({e})"
    return None if pol.get("network_ok") else f"{pol.get('status')}: {pol.get('evidence')}"[:160]



def complete(d, prog):
    """The model PROPOSES, code COMPLETES (2026-10-23). A follow_up_lane answer that names no urls gets the
    oss-bot worklist's network rows for the program (the exact rows the snapshot offered), and a brief built by
    code from the model's reason. Nothing here invents a URL: no rows, no fill, and precheck rejects as before."""
    if not isinstance(d, dict) or d.get("action") != "follow_up_lane":
        return d
    program = (d.get("program") or prog or "").strip()
    urls = [u.strip() for u in (d.get("urls") or []) if isinstance(u, str) and u.strip()]
    if len(urls) < 2:
        try:
            wl = json.load(open(os.path.join(WS, ".claude/state/oss-bot/worklist.json"))).get("items") or []
        except (OSError, ValueError):
            wl = []
        rows = [w.get("url") for w in wl if w.get("kind") == "network" and w.get("program") == program
                and isinstance(w.get("url"), str) and w.get("url").startswith("http")]
        for u in rows:
            if u not in urls:
                urls.append(u)
            if len(urls) >= 6:
                break
        d["urls"] = urls[:20]
        d["completed_by"] = "code:oss-worklist"
    brief = (d.get("brief") or "").strip()
    if len(brief) < 40 and len(urls) >= 2:
        reason = " ".join(str(d.get("reason", "")).split())[:300]
        d["brief"] = (f"Follow up the scanner leads on {program}: GET-verify each exact URL below, compare status and "
                      f"body length against a nonsense sibling path, record the raw capture, never file from it. "
                      f"Manager's reason: {reason}")
    return d


def precheck(d, prog):
    """Cheap validation before anything runs; the message goes back to the model for ONE retry."""
    act = d.get("action")
    program = (d.get("program") or prog or "").strip()
    reason = (d.get("reason") or "").strip()
    if act not in ACTIONS:
        return f"action {act!r} is not on the menu"
    if len(reason) < 30:
        return "your reason must state, in your own words, the snapshot facts (numbers, hosts, hits) behind the choice"
    if act in ("sweep_host", "sweep_next", "osint", "pivot", "pick_target", "skip_family") and prog:
        pending = [l for l in chain_leads(prog) if l["chain"]]
        if pending and act != "osint" or (pending and act == "osint" and len(pending) >= 3):
            top = "; ".join(f"{l['url'][:90]} ({l['kind']}{': ' + l['detail'][:50] if l['detail'] else ''})" for l in pending[:3])
            return (f"depth before breadth: {prog} has {len(pending)} chain lead(s) with no follow-up lane: {top}. "
                    "Choose follow_up_lane on one of them (2-20 GET URLs that test the next link, one nonsense-path "
                    "control) or escalate; a new sweep or a move is refused while they wait")
    if act in ("pivot", "pick_target"):
        lock = locked_program()
        if lock and prog == lock:
            return (f"{prog} is the session's LOCKED target (the user named it); the bot never rotates off it on its "
                    "own. Work it: escalate, follow_up_lane, osint, draft, or wait")
        wos, lanes = line_work(prog)
        if lanes:
            return f"{prog} has {len(lanes)} queued lane(s); queued lanes run first: choose run_queue"
        if wos:
            return (f"{prog} has {len(wos)} open LINE work order(s) ({wos[0][:90]}); the line owns this program until "
                    "they close: choose escalate, follow_up_lane, draft, osint or wait, not a move")
        moved, left = churn()
        if moved >= 2:
            return ("you moved programs twice in your last six decisions and started no work in between; a third move "
                    "is churn. Choose work on the focus program (sweep_host, escalate, follow_up_lane, osint) or wait")
        if act == "pivot" and program in left:
            return f"you just left {program}; pivoting back is ping-pong. Choose work on the focus program or wait"
    if act == "pivot" and (not known_program(program) or program == prog):
        names = [n for n in candidate_names() if n != prog][:8]
        return (f"pivot needs a program from CANDIDATE PROGRAMS other than the focus; {program!r} is not valid. "
                f"Valid program names: {', '.join(names) or '(none - choose pick_target)'}")
    if act == "pivot":
        why = policy_refusal(program)
        if why:
            return (f"pivot to {program!r} is refused: its policy forbids unattended hunting ({why}); "
                    "choose another program or pick_target")
    if act == "escalate":
        why = escalate_noop(program)
        if why:
            return why
    if act == "follow_up_lane":
        dup = duplicate_lane(d, program)
        if dup:
            return dup
    if act == "mine_routes":
        why = mine_refusal(program, d.get("host"))
        if why:
            return why
    if act in ("sweep_host", "sweep_next", "skip_family", "escalate", "follow_up_lane", "osint", "draft") and \
            not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return f"{act} needs a program that has a scope; {program!r} has none (pivot or pick_target first)"
    if act in ("sweep_next", "sweep_host") and program and not plan(program)[1]:
        return (f"{program} has no unswept hosts; a sweep is a no-op. The move is follow_up_lane (2-20 GET URLs on its "
                "api / auth / console routes, one nonsense-path control), escalate if a hit exists, osint if due, or wait")
    if act == "sweep_host":
        host = resolve_host(d, program)
        un = plan(program)[1]
        if host is None:
            return (f"{repr(d.get('host')) + ' is already swept or not in the plan' if d.get('host') else 'the decision named no host'}. Valid choices include: {', '.join(un[:8])}"
                    if un else f"{program} has no unswept hosts left; choose pick_target or pivot")
    if act == "skip_family":
        pat = (d.get("pattern") or "").strip().lower()
        n = sum(1 for h in plan(program)[1] if h.endswith(pat[1:])) if pat.startswith("*.") else 0
        if n < 3:
            return f"pattern {pat!r} matches {n} unswept hosts; it must look like *.example.com and match at least 3"
    if act == "pick_target" and prog:
        sw = auto_state(prog).get("swept", {})
        swept, un = plan(prog)
        floor = min(8, len(swept) + len(un))
        if un and sum(1 for v in sw.values() if not v.get("skipped")) < floor:
            return (f"{prog} has only {sum(1 for v in sw.values() if not v.get('skipped'))} hosts really swept; sweep at "
                    f"least {floor} (prefer api/admin/auth hosts) before leaving it")
    if act == "osint" and time.time() - _ST.get("osint", {}).get(program, 0) < OSINT_EVERY:
        return f"osint for {program} ran less than 24 h ago; choose something else"
    if act == "learn" and time.time() - _ST.get("last_learn", 0) < LEARN_EVERY:
        return "learn is not due; choose something else"
    if act == "draft" and not [l for l in run([sys.executable, "scripts/local-draft.py", "--pending", program],
                                              timeout=60)[1].splitlines() if l.strip()]:
        return f"no pending TIER-3 escalation for {program}"
    if act == "notify" and not (d.get("message") or "").strip():
        return "notify needs a message"
    if act == "run_queue" and not [l for l in read(os.path.join(ORCH, "queue.txt")).splitlines()
                                   if l.strip() and not l.startswith("#")]:
        return "the lane queue is empty"
    if act == "follow_up_lane" and (len(d.get("urls") or []) < 2 or len((d.get("brief") or "")) < 40):
        return "follow_up_lane needs a brief (2-6 sentences) and at least 2 in-scope URLs"
    return ""


PARK_S = 3600            # D95: a program with no code-legal move rests this long
CODE_FILLABLE = ("run_queue", "sweep_host", "escalate", "osint", "mine_routes", "deep_dive")


def legal_moves(st, program):
    """The moves the gates would accept RIGHT NOW, computed by code: [(action, extra)]. D95 (2026-10-26 11:05Z): in
    three hours the brain made 152 decisions and 140 were rejected or invalid (escalate with nothing to escalate 28x,
    pivot off the locked target 23x, follow_up_lane on guessed or bare paths 44x) because nothing told it, before the
    call, which moves were open. A program whose set is empty is credential-walled, not a reason to ask again."""
    moves = []
    if not program:
        return moves
    q = [l for l in read(os.path.join(ORCH, "queue.txt")).splitlines() if l.strip() and not l.startswith("#")]
    if q:
        moves.append(("run_queue", {}))
    try:
        unswept = plan(program)[1]
    except Exception:  # noqa: BLE001
        unswept = []
    if unswept:
        moves.append(("sweep_host", {"host": unswept[0]}))
    try:
        pending = [l for l in chain_leads(program) if l.get("chain")]
    except Exception:  # noqa: BLE001
        pending = []
    if pending:
        moves.append(("follow_up_lane", {"leads": len(pending)}))
    try:
        left, total, _ = unfired_known_routes(program)
    except Exception:  # noqa: BLE001
        left, total = [], 0
    if left:
        moves.append(("follow_up_lane", {"routes": left[:20]}))
    try:
        if not escalate_noop(program):
            moves.append(("escalate", {}))
    except Exception:  # noqa: BLE001
        pass
    if time.time() - (st.get("osint") or {}).get(program, 0) >= OSINT_EVERY:
        moves.append(("osint", {}))
    for h in scope_hosts(program):
        try:
            if not mine_refusal(program, h):
                moves.append(("mine_routes", {"host": h}))
        except Exception:  # noqa: BLE001
            continue
    try:   # D105: the deep-dive dossier, once a day, when the live moves are spent
        import gnoc_hunt
        if not moves and gnoc_hunt.deep_dive_due(program):
            moves.append(("deep_dive", {}))
    except Exception:  # noqa: BLE001
        pass
    return moves


def legal_block(moves):
    if not moves:
        return ""
    names = []
    for a, x in moves:
        tag = x.get("host") or (f"{x['leads']} chain lead(s)" if x.get("leads") else "") \
            or (f"{len(x['routes'])} unfired mined route(s)" if x.get("routes") else "")
        names.append(f"{a}" + (f" ({tag})" if tag else ""))
    return ("\n\nLEGAL MOVES NOW (checked by code this tick; any other move is refused and costs a strike): "
            + "; ".join(names))


def code_pick(moves):
    """The move code takes WITHOUT asking the model: when every legal move is one code can fill in completely, the
    model has nothing to decide, so the first is taken. A chain lead or a route list still goes to the model."""
    if moves and all(a in CODE_FILLABLE for a, _ in moves):
        return moves[0]
    return None


def _inbox_once(msg):
    recent = read(os.path.join(ORCH, "INBOX.md"))[-6000:]
    if msg[:80] in recent:
        return False
    with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
        f.write(f"- [{now()}] {msg[:400]}\n")
    return True


def decide(st, launch, queue_runner):
    """Returns True when the brain handled this tick (a job started, or a deliberate no-op); False = use the fixed rules.
    launch(kind, program, argv, lane) starts a tracked job; queue_runner() pops and starts the next queued lane."""
    if time.time() < st.get("brain_wait_until", 0):
        return True
    if int(st.get("brain_rejects") or 0) >= REJECT_STREAK:   # D83: the brain has nothing it is allowed to do; rest
        st["brain_rejects"] = 0
        st["brain_wait_until"] = time.time() + REJECT_COOLDOWN_S
        journal({"ts": now(), "action": "cooldown", "status": "wait",
                 "detail": f"{REJECT_STREAK} rejected or invalid decisions in a row; resting {REJECT_COOLDOWN_S // 60} min "
                           "(the fixed rules keep running)"})
        return True
    _ST.clear()
    _ST.update(st)
    t0 = time.time()
    snap, prog = snapshot(st)
    moves = legal_moves(st, prog)   # D95
    if prog and not moves:
        st["brain_wait_until"] = time.time() + PARK_S
        detail = (f"{prog}: no code-legal move is left (every host swept, every mined route fired or walled, nothing "
                  "to escalate, osint and route mining inside their windows); the remaining ground is credential-gated. "
                  f"Resting {PARK_S // 60} min. NEEDS: an identity on {prog} (a saved login) reopens the authed seams.")
        journal({"ts": now(), "action": "parked", "status": "wait", "detail": detail})
        _inbox_once(f"**BRAIN** {detail}")
        print(f"[{now()}] brain parked: {detail[:160]}", flush=True)
        return True
    pick = code_pick(moves)
    feedback = ""
    for attempt in (1, 2):
        if pick:
            act0, extra = pick
            d = {"action": act0, "program": prog, "picked_by": "code",
                 "reason": "code: every legal move this tick is one code can fill, so the first is taken: "
                           + legal_block(moves)[:200]}
            d.update(extra)
            pick = None
        else:
            try:
                d = ask(snap + legal_block(moves), feedback)
            except Exception as e:
                journal({"ts": now(), "action": "model-error", "status": "fallback", "detail": repr(e)[:200]})
                return False
        d = normalize(d, prog)
        d = complete(d, prog)
        err = precheck(d, prog)
        if not err:
            break
        journal({"ts": now(), "action": d.get("action"), "status": "rejected", "detail": err[:200],
                 "reason": str(d.get("reason", ""))[:200], "attempt": attempt})
        feedback = f"YOUR PREVIOUS ANSWER WAS REJECTED: {err}. Previous answer: {json.dumps(d)[:400]}\n\n"
        st["brain_rejects"] = int(st.get("brain_rejects") or 0) + 1   # D83
    else:
        return False  # two rejected answers: fixed rules run this tick
    secs = int(time.time() - t0)
    act = d.get("action")
    program = (d.get("program") or prog or "").strip()
    rec = {"ts": now(), "action": act, "reason": d.get("reason", "")[:400], "secs": secs,
           "model": "code" if d.get("picked_by") == "code" else (LAST_CALL.get("model") or current_model()),
           "host": LAST_CALL.get("host"), "fallback": LAST_CALL.get("fallback"), "picked_by": d.get("picked_by")}

    def done(status, detail="", started=False):
        rec.update(status=status, detail=detail[:300], started_job=started)
        st["brain_rejects"] = int(st.get("brain_rejects") or 0) + 1 if status == "invalid" else 0   # D83
        journal(rec)
        print(f"[{now()}] brain {act}: {status} {detail[:160]} ({secs}s) - {rec['reason'][:160]}", flush=True)
        return status in ("ok", "wait")

    if act not in ACTIONS:
        return done("invalid", f"unknown action {act!r}")

    if act == "wait":
        mins = max(1, min(int(d.get("minutes") or 10), 60))
        st["brain_wait_until"] = time.time() + mins * 60
        return done("wait", f"{mins} min")

    if act == "notify":
        msg = (d.get("message") or "").strip()
        if not msg:
            return done("invalid", "notify without a message")
        recent = read(os.path.join(ORCH, "INBOX.md"))[-4000:]
        if msg[:60] in recent:
            return done("invalid", "duplicate notify")
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **BRAIN** {msg[:400]}\n")
        st["brain_wait_until"] = time.time() + 300
        return done("ok", msg)

    if act == "run_queue":
        if not [l for l in read(os.path.join(ORCH, "queue.txt")).splitlines() if l.strip() and not l.startswith("#")]:
            return done("invalid", "queue is empty")
        queue_runner()
        return done("ok" if st.get("current") else "invalid", "queued lane")

    if act == "pick_target":
        rc, out = run(["~/.local/bin/gnoc", "pivot", "--no-lock"], timeout=60)
        done("ok" if rc == 0 else "failed", out.strip().splitlines()[-1] if out.strip() else "")
        return False  # AUTO-HUNT now says "target": the fixed rules launch auto-target.py --pick this same tick

    if act == "pivot":
        if not known_program(program) or program == prog:
            return done("invalid", f"pivot to unknown or current program {program!r}")
        rc, out = run(["~/.local/bin/gnoc", "pivot", program, "--no-lock"], timeout=900)
        return done("ok" if rc == 0 else "failed", f"{program}: {out.strip()[-200:]}")

    if act == "deep_dive":
        try:
            import gnoc_hunt
            path, summary = gnoc_hunt.deep_dive(program)
        except Exception as e:  # noqa: BLE001
            return done("failed", f"deep_dive: {e!r}"[:200])
        _inbox_once(f"**BRAIN** deep dive {program}: {summary}; dossier {os.path.relpath(path, WS)}")
        return done("ok", f"{summary} -> {os.path.relpath(path, WS)}")

    if act == "learn":
        st["last_learn"] = time.time()
        rc, out = run([sys.executable, os.path.join(WS, "scripts/learn/consolidate.py")], timeout=600)
        return done("ok" if rc == 0 else "failed", out.strip()[-160:])

    # everything below acts on a program with a SCOPE.txt
    if not program or not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return done("invalid", f"no SCOPE.txt for {program!r}")

    if act == "sweep_host":
        host = resolve_host(d, program)
        if not host:
            return done("invalid", f"{host!r} is not an unswept host of {program}")
        launch("auto", program, [sys.executable, os.path.join(WS, "scripts/auto-hunt.py"), program, "--host", host],
               "auto-exposure")
        return done("ok", f"{program} {host}", started=True)

    if act == "sweep_next":
        launch("auto", program, [sys.executable, os.path.join(WS, "scripts/auto-hunt.py"), program, "--next",
                                 os.environ.get("AUTO_BATCH", "4"), "--workers", os.environ.get("AUTO_WORKERS", "4")],
               "auto-exposure")
        return done("ok", program, started=True)

    if act == "skip_family":
        pat = (d.get("pattern") or "").strip().lower()
        if not re.fullmatch(r"\*\.[a-z0-9-]+(\.[a-z0-9-]+)+", pat):
            return done("invalid", f"bad pattern {pat!r}")
        _, unswept = plan(program)
        victims = [h for h in unswept if h.endswith(pat[1:])]
        if len(victims) < 3:
            return done("invalid", f"{pat} matches {len(victims)} unswept hosts (<3)")
        sp = os.path.join(ORCH, f"auto-{program}.json")
        a = auto_state(program)
        for h in victims:
            a.setdefault("swept", {})[h] = {"ts": now(), "fired": 0, "hits": 0, "leads": 0, "skipped": True,
                                            "skipped_by": "brain", "pattern": pat}
        json.dump(a, open(sp, "w"), indent=1)
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **BRAIN** skipped {len(victims)} hosts of {program} matching {pat}: "
                    f"{rec['reason'][:200]} (undo: remove entries with skipped_by=brain from {os.path.relpath(sp, WS)})\n")
        return done("ok", f"{program} {pat} ({len(victims)} hosts)")

    if act == "escalate":
        launch("escalate", program, [sys.executable, os.path.join(WS, "scripts/auto-escalate.py"), program],
               "auto-escalate")
        return done("ok", program, started=True)

    if act == "follow_up_lane":
        return follow_up_lane(d, program, done)
    if act == "mine_routes":
        return mine_routes(d, program, done)

    if act == "osint":
        st.setdefault("osint", {})[program] = time.time()
        launch("osint", program, [sys.executable, os.path.join(WS, "scripts/auto-target.py"), "--remap", program], "osint")
        return done("ok", program, started=True)

    if act == "draft":
        rc, pend = run([sys.executable, "scripts/local-draft.py", "--pending", program], timeout=60)
        esc = pend.split()[1] if pend.split()[1:] else ""
        if not esc:
            return done("invalid", "nothing pending")
        launch("draft", program, [sys.executable, os.path.join(WS, "scripts/local-draft.py"), os.path.join(WS, esc)], "draft")
        return done("ok", esc, started=True)

    return done("invalid", "unhandled")


def lane_slug(name, program=None):
    """The model copies lane names from LANE QUEUE, so strip our own 'brain-' prefixes and '-MMDDHHMM' stamps before
    re-adding them: otherwise every follow-up nests one level deeper (brain-brain-brain-x-10211646). D61: the model
    also copies 'program/lane' as one token, so the program name is stripped too (brain-anthropic-brain-api-auth-
    console-10260759, 2026-10-26 08:00Z)."""
    slug = re.sub(r"[^a-z0-9-]+", "-", (name or "lead").lower()).strip("-")
    prog = re.sub(r"[^a-z0-9-]+", "-", str(program or "").lower()).strip("-")
    while True:
        new = re.sub(r"^brain-", "", re.sub(r"-\d{6,}$", "", slug))
        if prog and new.startswith(prog + "-") and len(new) > len(prog) + 1:
            new = new[len(prog) + 1:]
        if new == slug:
            break
        slug = new
    slug = re.sub(r"-\d{6,}(?=-|$)", "", slug)
    return slug[:40].strip("-") or "lead"


def _lane_urls(probes_rel):
    return set(re.findall(r"GET '([^']+)'", read(os.path.join(WS, probes_rel))))


def _rk(url):
    """host/path of a URL, no scheme, query, fragment or trailing slash (gnoc_hunt.route_key when importable). D62:
    the first lane after D61 passed with 4 URLs that were all api.program-0.example/api/auth/console plus a query string
    (?nonsense=true, ?test=1, ?debug=true) while the lane before it had fired that route 20 times as ?session=bNN."""
    try:
        import gnoc_hunt
        return gnoc_hunt.route_key(url)
    except Exception:  # noqa: BLE001
        k = re.sub(r"^https?://", "", str(url or "")).split("?", 1)[0].split("#", 1)[0]
        return (k.rstrip("/") or "/")[:200]


DONE_LEDGER = os.path.join(ORCH, "done.jsonl")   # orch-bot screen() appends one row per finished lane round
LANE_REPEAT_HOURS = 24
LANE_REPEAT_RUNS = 2        # D61: the same slug finished this many times in the window -> the next needs new URLs
LANE_NEW_URL_SHARE = 0.5    # ... at least this share of its URLs never fired under that slug before


def finished_lanes(program, base, hours=LANE_REPEAT_HOURS):
    """[(lane, flags)] for the program's finished lanes with this base slug in the window, oldest first. Drive review
    2026-10-26 08:15Z: the brain queued 'api-auth-console' 18 times in seven hours (01:20Z-08:09Z), 4-20 GETs each on
    the same three api.program-0.example routes, 16 of them 'every row matched the majority shape'. duplicate_lane only
    looked at queued and running lanes, so a lane re-queued a minute after it finished passed."""
    out = []
    cutoff = time.time() - hours * 3600
    for ln in read(DONE_LEDGER).splitlines()[-2000:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") != program or lane_slug(r.get("lane"), program) != base:
            continue
        try:
            t = datetime.strptime(str(r.get("ts", ""))[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
        if t >= cutoff:
            out.append((r.get("lane"), list(r.get("flags") or [])))
    return out


def walled_urls(program, urls):
    """The subset of urls whose route the hunt ledger has walled program-wide (gnoc_hunt.program_walls: never a
    2xx/3xx on WALL_MIN+ probes). The orch-bot's lanes fired api.program-0.example/api/account, /api/auth/aws_refresh_creds
    and /admin-settings/billing round after round while the chat hunt had already closed them (2026-10-26)."""
    try:
        import gnoc_hunt
        walls = gnoc_hunt.program_walls(program)
        return [u for u in urls if gnoc_hunt.route_key(u) in walls]
    except Exception:  # noqa: BLE001 - no hunt ledger, no walls
        return []


def duplicate_lane(d, program):
    """'' or why this follow_up_lane repeats one already queued or running for the program: the same base slug, or
    URLs that are all already in that lane's PROBES.txt (6 queued copies of one host on 2026-10-21). D61: also a slug
    that FINISHED LANE_REPEAT_RUNS+ times in LANE_REPEAT_HOURS unless at least LANE_NEW_URL_SHARE of the URLs are new
    to that slug."""
    want = {u.strip().replace("'", "%27") for u in (d.get("urls") or []) if isinstance(u, str) and u.strip()}
    base = lane_slug(d.get("lane"), program)
    prior = finished_lanes(program, base)
    if len(prior) >= LANE_REPEAT_RUNS and want:
        fired = set()
        for lane, _ in prior:
            fired |= {_rk(u) for u in _lane_urls(os.path.join("targets", program, "hunts", lane, "PROBES.txt"))}
        want_routes = {_rk(u) for u in want}
        new = want_routes - fired   # D62: by route, a query string is not a new route
        if len(new) / len(want_routes) < LANE_NEW_URL_SHARE:
            quiet = sum(1 for _, fl in prior if not fl)
            return (f"follow_up_lane repeats '{base}', which finished {len(prior)} times in the last {LANE_REPEAT_HOURS} h "
                    f"({quiet} with no anomaly); {len(want_routes) - len(new)} of {len(want_routes)} routes already fired "
                    "under it (a query string on a fired route is the same route). A third identical lane is a re-sweep, "
                    "not depth: read the flagged rows' raw bytes (escalate), follow up a DIFFERENT lead or host, or bring "
                    "mostly new routes")
    lanes = []
    for ln in read(os.path.join(ORCH, "queue.txt")).splitlines():
        f = ln.split("|")
        if len(f) >= 4 and f[0] == program and not ln.startswith("#"):
            lanes.append(("queued", f[1], f[3]))
    cur = _ST.get("current") or {}
    if cur.get("program") == program and cur.get("lane"):
        lanes.append(("running", cur["lane"], os.path.join("targets", program, "hunts", cur["lane"], "PROBES.txt")))
    for where, lane, probes in lanes:
        have = _lane_urls(probes)
        if lane_slug(lane) == base or (want and have and want <= have):
            return (f"follow_up_lane duplicates the {where} lane {lane} ({len(want & have)} of {len(want)} URLs already in it); "
                    "let it finish, or follow up a different host/lead")
    return ""


def escalate_noop(program):
    """'' or why escalate is pointless now: the last escalate for this program (< 60 min ago) found no un-escalated
    HITs and no sweep since has recorded a hit (22 identical no-op escalates on 2026-10-21)."""
    last = None
    for ln in read(JOURNAL).splitlines()[-300:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("action") == "escalate" and r.get("status") == "ok" and str(r.get("detail", "")).startswith(program):
            last = r
    if not last or "no un-escalated" not in str(last.get("result", "")):
        return ""
    t = datetime.strptime(last["ts"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    if time.time() - t > 3600:
        return ""
    for v in auto_state(program).get("swept", {}).values():
        try:
            vt = datetime.strptime(str(v.get("ts", ""))[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
        if vt > t and v.get("hits", 0) > 0:
            return ""
    return (f"escalate for {program} ran at {last['ts']} and found no un-escalated HITs, and no sweep since has a hit; "
            "choose sweep_host, sweep_next, follow_up_lane, pick_target or wait")


def candidate_names():
    rc, rank = run([sys.executable, "scripts/auto-target.py", "--rank"], timeout=60)
    out = []
    for l in rank.splitlines():
        m = re.match(r"\s*(?:VDP|paid)\s+(\S+)", l)
        if m and (l.strip().endswith(" ok") or "needs intake" in l):
            out.append(m.group(1))
    return out


def scope_hosts(program):
    """The literal in-scope hosts of a program's SCOPE.txt, in file order."""
    out = []
    sf = os.path.join(WS, "targets", program, "SCOPE.txt")
    try:
        from bbtools import lib_scope
        out = [h.lstrip("=") for h in lib_scope.parse_scope(sf)
               if isinstance(h, str) and "." in h and "*" not in h]   # rows come back as '=host'
    except Exception:  # noqa: BLE001
        out = []
    if not out:   # the rows read `URL <tab> host <tab> [bounty; ...]` (or `=host` in the hook summary)
        for ln in read(sf).splitlines():
            if ln.lstrip().startswith("#"):
                continue
            m = re.search(r"(?:^|\s|=)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?=\s|$|\t)", ln.strip().lower())
            if m and m.group(1) not in out:
                out.append(m.group(1))
    return out


def unfired_known_routes(program, limit=24):
    """(routes, total, fired_or_walled): the program's mined routes (hunts/gnoc/known-paths.txt) minus every path a
    finished brain lane fired (done.jsonl -> PROBES.txt) minus the hunt's program walls. D65 (2026-10-26 08:43Z): the
    prompt showed the FIRST 24 lines of a 526-line file every tick, so the brain could only ever propose the same
    lane; after D61/D62 refused it, every decision for eight minutes was rejected."""
    kp = [l.strip() for l in read(os.path.join(WS, "targets", program, "hunts/gnoc/known-paths.txt")).splitlines()
          if l.strip() and not l.startswith("#")]
    if not kp:
        return [], 0, 0
    fired = set()
    for ln in read(DONE_LEDGER).splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") != program or not r.get("lane"):
            continue
        for u in _lane_urls(os.path.join("targets", program, "hunts", r["lane"], "PROBES.txt")):
            rk = _rk(u)
            fired.add("/" + rk.split("/", 1)[1] if "/" in rk else "/")
    try:
        import gnoc_hunt
        for rk in gnoc_hunt.program_walls(program):
            fired.add("/" + rk.split("/", 1)[1] if "/" in rk else "/")
    except Exception:  # noqa: BLE001
        pass
    left = [k for k in kp if k.rstrip("/") not in fired and k not in fired and _api_shaped(k)]
    # D75: docs and blog pages are never lane material (lane 10260938 spent 14 of 20 GETs on /docs/ pages)
    total = sum(1 for k in kp if _api_shaped(k))
    return left[:limit], total, total - len(left)


def _api_shaped(path):
    return not (path.startswith("/docs/") or path.startswith("/blog/") or path.endswith((".html", ".md")))


_CONTROL_PATH = re.compile(r"(?i)nonsense|fake|gnoc[0-9a-f]{4,}|does-not-exist|xyz$")


def known_paths(program):
    """The program's mined routes (hunts/gnoc/known-paths.txt) plus every path a finished brain lane fired that
    ANSWERED (not a 404): the material a lane may be built from."""
    paths = {l.strip().rstrip("/") for l in read(os.path.join(WS, "targets", program, "hunts/gnoc/known-paths.txt")).splitlines()
             if l.strip() and not l.startswith("#")}
    for ln in read(DONE_LEDGER).splitlines()[-400:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") != program or not r.get("lane"):
            continue
        st = read(os.path.join(WS, "targets", program, "hunts", r["lane"], "STATUS.md"))
        for m in re.finditer(r"\|\s*b\d+\s*\|\s*GET\s*\|\s*(\S+)\s*\|\s*(\d{3})\s*\|", st):
            if m.group(2) != "404":
                paths.add("/" + _rk(m.group(1)).split("/", 1)[1].rstrip("/") if "/" in _rk(m.group(1)) else "/")
    return paths


def guessed_urls(program, urls):
    """The urls whose path is neither mined nor previously answered, minus one nonsense-path control. D75
    (2026-10-26 09:50Z): the brain wrote /v1/auth/credentials, /v1/internal/service and /v1/auth/session the
    moment the unfired mined routes ran out; the prompt says 'never from guesses' and code now holds it to that."""
    known = known_paths(program)
    out, controls = [], 0
    for u in urls:
        rk = _rk(u)
        path = "/" + rk.split("/", 1)[1].rstrip("/") if "/" in rk else "/"
        if path in known or path.rstrip("/") in known:
            continue
        if _CONTROL_PATH.search(path) and controls == 0:
            controls += 1
            continue
        out.append(u)
    return out


def mine_refusal(program, host):
    """'' or why mine_routes is refused: no host, host out of scope, or mined within MINE_EVERY (journal)."""
    host = str(host or "").strip().lower()
    if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
        return "mine_routes needs host=<an in-scope host name>"
    if not scope_ok(program, host):
        return f"mine_routes: {host} is not in {program}'s scope; the in-scope hosts are {', '.join(scope_hosts(program)[:6])}"
    for ln in read(JOURNAL).splitlines()[-500:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("action") == "mine_routes" and r.get("status") == "ok" and host in str(r.get("detail", "")):
            try:
                t = datetime.strptime(r["ts"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            except (KeyError, ValueError):
                continue
            if time.time() - t < MINE_EVERY:
                return f"mine_routes: {host} was mined at {r['ts']}; once per host per {MINE_EVERY // 3600} h"
    return ""


def mine_routes(d, program, done):
    """Run the chat's js_mine on https://host/ in a subprocess and add what it finds to known-paths.txt through the
    same writer the chat uses (_learn_paths), so the next KNOWN ROUTES block has fresh material. D85 (2026-10-26
    10:18Z): with every mined API route fired, the brain's only moves were refused 42 times in 25 minutes."""
    host = str(d.get("host") or "").strip().lower()
    code = ("import sys, os; sys.path.insert(0, 'scripts'); import gnoc_sec, gnoc_agent\n"
            f"text = gnoc_sec.js_mine('https://{host}/', os.path.join('targets', {program!r}, 'SCOPE.txt'))\n"
            f"print('LEARNED', gnoc_agent._learn_paths({program!r}, '', text or ''))")
    rc, out = run([sys.executable, "-c", code], timeout=360)
    m = re.search(r"LEARNED (\d+)", out or "")
    if rc != 0 or not m:
        return done("invalid", f"mine_routes {host} failed (rc {rc}): {(out or '')[-200:]}")
    try:   # D105b: the chat's js_mine records the host (D89); the bot's mining must too, or the two views disagree
        fp = os.path.join(WS, "targets", program, "hunts", "gnoc", "mined-hosts.txt")
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        have = set(l.strip().lower() for l in open(fp).read().splitlines()) if os.path.exists(fp) else set()
        if host not in have:
            with open(fp, "a") as f:
                f.write(host + "\n")
    except OSError:
        pass
    return done("ok", f"mine_routes {host}: {m.group(1)} new route(s) in targets/{program}/hunts/gnoc/known-paths.txt")


def lane_host(program):
    """The host a bare path resolves against: the host the program's finished brain lanes fired most, else the first
    in-scope host named api., else the first in-scope host. D73 (2026-10-26 08:52Z-09:08Z): the brain proposed
    '/v1/oauth/token', '/v1/sessions', '/v1/models' bare six times in a row, each rejected as malformed."""
    cnt = Counter()
    for ln in read(DONE_LEDGER).splitlines()[-400:]:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("program") == program and r.get("lane"):
            for u in _lane_urls(os.path.join("targets", program, "hunts", r["lane"], "PROBES.txt")):
                m = re.match(r"https?://([^/]+)", u)
                if m:
                    cnt[m.group(1).lower()] += 1
    hosts = scope_hosts(program)
    for h, _ in cnt.most_common():
        if h in hosts:
            return h
    return next((h for h in hosts if h.startswith("api.")), hosts[0] if hosts else "")


def follow_up_lane(d, program, done):
    urls = [u.strip() for u in (d.get("urls") or []) if isinstance(u, str) and u.strip()][:20]
    host = lane_host(program)
    bare = [u for u in urls if u.startswith("/")]
    if bare and host:   # D73
        urls = [f"https://{host}{u}" if u.startswith("/") else u for u in urls]
        d = dict(d, urls=urls)
    brief = (d.get("brief") or "").strip()
    if len(urls) < 2 or len(brief) < 40:
        return done("invalid", "follow_up_lane needs a brief and at least 2 URLs")
    bad = []
    for u in urls:
        m = re.match(r"https?://([A-Za-z0-9.-]+)(:\d+)?(/[^\s']*)?$", u)
        if not m or not scope_ok(program, m.group(1)):
            bad.append(u)
    if bad:
        hosts = scope_hosts(program)[:6]
        return done("invalid", f"out of scope or malformed: {bad[:3]}. Every url is a full https URL on one of the "
                               f"in-scope hosts: {', '.join(hosts) or '(see SCOPE.txt)'}")   # D65: 08:43Z '/api/account'
    guessed = guessed_urls(program, urls)   # D75: mined or answered routes only, plus one control
    if guessed:
        urls = [u for u in urls if u not in guessed]
        if len(urls) < 2:
            return done("invalid", f"{len(guessed)} URL(s) are guessed paths, not mined routes: {guessed[:3]}. A lane is "
                                   "built from KNOWN ROUTES (js_mine, known-paths) or routes a lane already saw answer; "
                                   "when none is unfired, choose osint, escalate on a flagged row, or js_mine another host")
        d = dict(d, urls=urls)
    walled = walled_urls(program, urls)   # D61: the hunt's walls bind the bot's lanes too
    if walled:
        urls = [u for u in urls if u not in walled]
        if len(urls) < 2:
            return done("invalid", f"{len(walled)} of {len(walled) + len(urls)} URLs are program walls (never a 2xx on "
                                   f"any hypothesis): {walled[:3]}. A lane on walls is a re-sweep; pick routes that "
                                   "have answered (KNOWN ROUTES) or a different host")
        d = dict(d, urls=urls)
    dup = duplicate_lane(d, program)
    if dup:
        return done("invalid", dup)
    slug = lane_slug(d.get("lane"), program)
    lane = f"brain-{slug}-{datetime.now(timezone.utc):%m%d%H%M}"
    lanedir = os.path.join(WS, "targets", program, "hunts", lane)
    os.makedirs(os.path.join(lanedir, "raw"), exist_ok=True)
    harness = os.path.join(WS, "targets/program-60/hunts/calllog-api-20261020/p.py")  # generic, scope-checked, GET-safe
    import shutil
    shutil.copy(harness, os.path.join(lanedir, "p.py"))
    with open(os.path.join(lanedir, "BRIEF.md"), "w") as f:
        f.write(f"# {lane} (written by orch-brain, {LAST_CALL.get("model") or current_model()})\n\n{brief}\n\n"
                "HARNESS (every request goes through it; it refuses out-of-scope hosts and saves raw/<TAG>.req/.resp):\n"
                f"  HUNT_TARGET={program} N=1500 /usr/bin/python3 {lanedir}/p.py <TAG> GET '<URL>'\n"
                "Fire each PROBES.txt line once, GET only, then record a STATUS.md table: | TAG | GET | URL | status | length |.\n"
                "A worker verdict is a claim; the raw files are the evidence.\n")
    with open(os.path.join(lanedir, "PROBES.txt"), "w") as f:
        f.write(f"# orch-brain follow-up lane for {program}\n")
        for i, u in enumerate(urls):
            safe = u.replace("'", "%27")
            f.write(f"b{i:02d}|HUNT_TARGET={program} N=1500 /usr/bin/python3 {lanedir}/p.py b{i:02d} GET '{safe}'\n")
    rel = lambda p: os.path.relpath(p, WS)
    with open(os.path.join(ORCH, "queue.txt"), "a") as f:
        f.write(f"{program}|{lane}|{rel(os.path.join(lanedir, 'BRIEF.md'))}|{rel(os.path.join(lanedir, 'PROBES.txt'))}|A\n")
    return done("ok", f"queued {program}/{lane} with {len(urls)} URLs")


if __name__ == "__main__":
    # dry run: print the snapshot and the model's proposal without executing anything
    snap, _ = snapshot({})
    if "--snapshot" in sys.argv:
        print(snap)
        sys.exit(0)
    t0 = time.time()
    print(json.dumps(ask(snap), indent=1))
    print(f"({time.time() - t0:.0f}s, {LAST_CALL.get('model')}@{LAST_CALL.get('host')}"
          + (f", fell back: {LAST_CALL['fallback']}" if LAST_CALL.get("fallback") else "") + ")")
