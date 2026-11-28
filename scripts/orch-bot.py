#!/usr/bin/env python3
"""orch-bot.py - the no-Claude orchestrator. Runs under pm2 as `orch-bot`; zero cloud model tokens.

What it does every tick (default 60s), in order, and only what can be done mechanically:
  1. HEALTH   ollama-oc up (pm2 restart if not); STOP file honoured (pauses lanes, keeps gating)
  2. LANES    if no OpenCode driver is running, pop the next entry of the lane queue, verify every
              host in its probes file against targets/<program>/SCOPE.txt, then launch
              scripts/opencode-lane.sh. One lane at a time (the GPU holds one model).
  3. SCREEN   when a lane finishes, read its commands.txt + raw/ and flag every response whose
              (status, length class) differs from the lane's own control rows. The 8B worker's
              VERDICT line is ignored (it is a claim, T-142); flags go to the review inbox.
  4. DRAFTS   ship-pipeline local gates on drafts changed in the last 48h (no live repro, no LLM)
  5. H1       refresh our own H1 report list for the self-duplicate check (every 30 min)
  6. REPORT   heartbeat + state for `gnoc`, and a review inbox for the user (and for Claude later)

It never files, never submits, never edits a report, never writes a brief. A human (or Claude, when
usage is back) adds lanes:  gnoc orch add <program> <lane-dir> <brief.md> <probes.txt> [round]

Files: .claude/state/orch/{queue.txt, done.jsonl, state.json, INBOX.md, orch.log}
"""
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------- RETIRED 2026-11-02
# GreyNOC retired the unattended orchestrator, verbatim: "No more orch bot or oss bot. Lets just have
# the gnoc chat orchistrate everything when requested." Hunting is now bound to a live gnoc chat
# session (scripts/gnoc_session.py) and dies with it, so nothing may tick and launch lanes on its own.
# The code is kept, not deleted, so the lane/screen/gate logic stays readable and revivable. This guard
# runs before any import that costs anything, and before any network or model work can start.
_UNRETIRE = "GNOC_ORCH_BOT_UNRETIRE"
if not os.environ.get(_UNRETIRE):
    sys.stderr.write(
        "orch-bot is RETIRED (2026-11-02): hunting runs only inside a gnoc chat session.\n"
        "  start a hunt:   gnoc chat   then ask it to hunt\n"
        "  see the gate:   python3 scripts/gnoc_session.py status\n"
        f"  override once:  {_UNRETIRE}=1 (deliberate, unattended, not the house default)\n")
    sys.exit(78)  # EX_CONFIG: a configuration refusal, not a crash - pm2 will not treat it as flapping
# ---------------------------------------------------------------------------------------------------

import orch_brain as brain  # noqa: E402  the local-model decision layer (gnoc orch brain on|off)
from bbtools import lib_scope  # noqa: E402  the shared unattended scope gate (NOSCOPE, third-party, internal IP)

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
QUEUE = os.path.join(ORCH, "queue.txt")
DONE = os.path.join(ORCH, "done.jsonl")
STATEF = os.path.join(ORCH, "state.json")
INBOX = os.path.join(ORCH, "INBOX.md")
LOG = os.path.join(ORCH, "orch.log")
STOP = os.path.join(WS, ".claude/state/hunt-loop/STOP")
ECON_PAUSE = os.path.join(WS, ".claude/state/economy/PAUSE")  # COMPANY: pauses the whole company, not just lanes
TICK = int(os.environ.get("ORCH_TICK", "60"))
# gnoc-office's "work harder" slider (1-5) writes an intensity level here; read fresh every tick so
# the slider has a real effect without restarting the pm2 process. Clamped so a stuck/garbage file
# can never make the loop busy-spin or stall for absurdly long - a cosmetic control, never a hazard.
INTENSITY_FILE = os.path.join(ORCH, "office-intensity")
TICK_BY_INTENSITY = {1: 120, 2: 90, 3: 60, 4: 35, 5: 20}


def tick_seconds():
    try:
        level = int(open(INTENSITY_FILE).read().strip())
    except (OSError, ValueError):
        return TICK
    return TICK_BY_INTENSITY.get(max(1, min(5, level)), TICK)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    os.makedirs(ORCH, exist_ok=True)
    with open(LOG, "a") as f:
        f.write(f"[{now()}] {msg}\n")
    print(f"[{now()}] {msg}", flush=True)


def inbox(kind, msg):
    new = not os.path.isfile(INBOX)
    with open(INBOX, "a") as f:
        if new:
            f.write("# ORCH INBOX - items the bot cannot decide (newest last). Clear a line when handled.\n\n")
        f.write(f"- [{now()}] **{kind}** {msg}\n")
    log(f"INBOX {kind}: {msg[:160]}")


def sh(cmd, timeout=120, env=None):
    try:
        r = subprocess.run(cmd, cwd=WS, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, **(env or {})), stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 1, str(e)


def load_state():
    try:
        return json.load(open(STATEF))
    except (OSError, ValueError):
        return {"current": None, "last_h1": 0, "last_drafts": 0, "screened": []}


def save_state(st):
    st["heartbeat"] = now()
    tmp = STATEF + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATEF)  # atomic: a signal mid-write can no longer tear state.json


# ---------- 1 health ----------

def ollama_ok():
    rc, out = sh(["curl", "-s", "-m", "5", "127.0.0.1:11434/api/version"], timeout=10)
    return rc == 0 and "version" in out


def health(st):
    if not ollama_ok():
        log("ollama-oc down, restarting via pm2")
        sh(["pm2", "restart", "qwen3:8b"], timeout=60)
        time.sleep(10)
        if not ollama_ok():
            inbox("HEALTH", "ollama-oc (127.0.0.1:11434) is down and a pm2 restart did not bring it back")
            return False
    return True


# ---------- 2 lanes ----------

def running_driver():
    rc, out = sh(["pgrep", "-af", "scripts/opencode-lane.sh"], timeout=10)
    return [l for l in out.splitlines() if "opencode-lane.sh" in l and "pgrep" not in l and "bash -c" not in l]


class _ScopePats(list):
    """The parsed pattern list, carrying its program so in_scope() can delegate to lib_scope."""
    program = None


def _prog_allows(host, program):
    return bool(program) and lib_scope.program_allows(host, program)[0]


def scope_patterns(program):
    pats = _ScopePats()
    pats.program = program
    for ln in open(os.path.join(WS, "targets", program, "SCOPE.txt"), encoding="utf-8", errors="replace"):
        if re.match(r"^\s*#\s*=+\s*OUT[- ]OF[- ]SCOPE", ln, re.I):  # the divider, not prose mentioning it
            break  # allowlist stops at the OUT-OF-SCOPE section, like scope-gate.sh
        ln = ln.split("#")[0].strip()
        for tok in re.findall(r"(\*\.[A-Za-z0-9.-]+|=?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", ln):
            if tok.endswith("."):  # a TLD wildcard like *.brand.* parses to "*.brand.": unmatchable, and crt.sh stalls on it
                continue
            pats.append(tok.lstrip("=").lower())
    return pats


def in_scope(host, pats):
    # name kept for importers; the pattern contents are ignored and the decision is lib_scope.program_allows
    # (NOSCOPE first, third-party, internal IP, SCOPE allowlist). A plain list with no program fails closed.
    return _prog_allows(host, getattr(pats, "program", None))


def lane_hosts(probes):
    hosts = set()
    for ln in open(probes, encoding="utf-8", errors="replace"):
        if ln.strip().startswith("#"):
            continue
        hosts |= {h.lower() for h in re.findall(r"https?://([A-Za-z0-9.-]+)", ln)}
    return hosts


def pop_queue():
    if not os.path.isfile(QUEUE):
        return None
    lines = open(QUEUE).read().splitlines()
    for i, ln in enumerate(lines):
        if ln.strip() and not ln.startswith("#"):
            rest = lines[:i] + lines[i + 1:]
            with open(QUEUE, "w") as f:
                f.write("\n".join(rest) + ("\n" if rest else ""))
            return ln.strip()
    return None


def start_lane(st):
    entry = pop_queue()
    if not entry:
        return
    parts = [p.strip() for p in entry.split("|")]
    if len(parts) < 4:
        inbox("QUEUE", f"malformed queue line skipped: {entry}")
        return
    program, lane, brief, probes = parts[:4]
    if os.path.exists(os.path.join(WS, ".claude/state/orch/lane-scope-pause", program)):  # lane egress audit failed earlier
        inbox("SCOPE", f"lane {program}/{lane} skipped: lanes for {program} are paused by a lane egress audit failure "
                       f"(rm .claude/state/orch/lane-scope-pause/{program} after review)")
        return
    rnd = parts[4] if len(parts) > 4 else ""
    absp = lambda p: p if os.path.isabs(p) else os.path.join(WS, p)
    brief, probes = absp(brief), absp(probes)
    for need in (brief, probes, os.path.join(WS, "targets", program, "SCOPE.txt")):
        if not os.path.isfile(need):
            inbox("QUEUE", f"lane {program}/{lane} skipped: missing {os.path.relpath(need, WS)}")
            return
    # harmony 2.3: the OpenCode worker is an AI agent; a program banning automation or AI agents covers it.
    # Override = GreyNOC's own policy-overrides.txt "<program> allow <quote + date>" line, read by lib_policy.
    from bbtools import lib_policy
    pol = lib_policy.policy(program)
    if not pol["network_ok"]:
        inbox("POLICY", f"lane {program}/{lane} REFUSED: {pol['status']} {pol['evidence']}"[:300])
        return
    bad = sorted(h for h in lane_hosts(probes) if not lib_scope.program_allows(h, program)[0])
    if bad:
        inbox("SCOPE", f"lane {program}/{lane} REFUSED, hosts not in SCOPE.txt: {', '.join(bad)}")
        return
    env = dict(os.environ, HUNT_TARGET=program)
    if rnd:
        env["ROUND"] = rnd
    out = os.path.join(WS, ".claude/state/opencode", f"{lane}-orch-{datetime.now(timezone.utc):%m%dT%H%M%S}.out")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    lanedir = os.path.join(WS, "targets", program, "hunts", lane)
    cmds = os.path.join(lanedir, "commands.txt")
    start_line = len(open(cmds).read().splitlines()) if os.path.isfile(cmds) else 0
    with open(out, "w") as fh:
        p = subprocess.Popen([os.path.join(WS, "scripts/opencode-lane.sh"), program, lane, brief, probes],
                             cwd=WS, env=env, stdout=fh, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    st["current"] = {"program": program, "lane": lane, "round": rnd, "pid": p.pid, "out": out,
                     "started": now(), "start_line": start_line}
    log(f"lane started pid {p.pid} {program}/{lane} round={rnd or '-'}")


# ---------- 3 screen ----------

ROW_RE = re.compile(r"^\|\s*(\S+)\s*\|\s*(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\|\s*(\S+)\s*\|\s*(\d{3})\s*\|\s*(\d+)\s*[bB]?\s*\|")


def length_class(n):
    return 0 if n == 0 else len(str(n))  # 0, 1-9, 10-99, 100-999, ...


def screen(cur):
    """Compare every fired row of the finished round against the round's own majority shapes."""
    lanedir = os.path.join(WS, "targets", cur["program"], "hunts", cur["lane"])
    status = os.path.join(lanedir, "STATUS.md")
    text = open(status, encoding="utf-8", errors="replace").read() if os.path.isfile(status) else ""
    sections = text.split("\n## Round ")
    rows = [m.groups() for m in (ROW_RE.match(l) for l in sections[-1].splitlines()) if m] if len(sections) > 1 else []
    fired = len(rows)
    shapes = {}
    for tag, meth, url, code, ln in rows:
        shapes.setdefault((code, length_class(int(ln))), []).append(tag)
    common = max(shapes.values(), key=len) if shapes else []
    flags = []
    for (code, lc), tags in shapes.items():
        if tags is common:
            continue
        interesting = code.startswith("2") or (code in ("401", "403") and len(tags) <= 2)
        if interesting:
            flags.append(f"{code}/len~{'0' if lc == 0 else '1' + '0' * (lc - 1)}+: {', '.join(tags[:6])}")
    rec = {"ts": now(), "program": cur["program"], "lane": cur["lane"], "round": cur.get("round"),
           "fired": fired, "shapes": {f"{k[0]}/{k[1]}": len(v) for k, v in shapes.items()}, "flags": flags}
    with open(DONE, "a") as f:
        f.write(json.dumps(rec) + "\n")
    where = os.path.relpath(lanedir, WS)
    if fired == 0:
        inbox("LANE-UNFIRED", f"{cur['program']}/{cur['lane']} round {cur.get('round') or '-'} fired 0 requests; check {where}/STATUS.md and the driver log {os.path.relpath(cur['out'], WS)}")
    elif flags:
        inbox("REVIEW", f"{cur['program']}/{cur['lane']} round {cur.get('round') or '-'}: {fired} fired, rows that differ from the round's majority shape: "
              + " | ".join(flags) + f". Bytes: {where}/raw/. Worker verdicts are not trusted; a human or Claude reads the raw files.")
    else:
        inbox("LANE-DONE", f"{cur['program']}/{cur['lane']} round {cur.get('round') or '-'}: {fired} fired, every row matched the majority shape (no anomaly). {where}/STATUS.md")
    log(f"screened {cur['program']}/{cur['lane']}: fired={fired} flags={len(flags)}")


def lanes(st):
    cur = st.get("current")
    if cur:
        alive = True
        try:
            os.kill(cur["pid"], 0)
        except OSError:
            alive = False
        if alive:
            return
        if cur.get("kind") == "auto":
            txt = open(cur["out"]).read() if os.path.isfile(cur["out"]) else ""
            if re.search(r"hits [1-9]", txt):  # a bug signal is not a payable exploit: escalate before anyone sees it
                rc, eout = sh([sys.executable, os.path.join(WS, "scripts/auto-escalate.py"), cur["program"]],
                              timeout=900, env={"HUNT_TARGET": cur["program"]})
                log(f"auto-escalate: {eout.strip()[-300:]}")
            # every TIER-2/3 escalation becomes a queued GPU lane (auto-lane.py); lanes run before the next sweep
            rc, lout = sh([sys.executable, os.path.join(WS, "scripts/auto-lane.py"), cur["program"]], timeout=120)
            if "queued " in lout:
                log(f"auto-lane: {lout.strip()[-200:]}")
            log(f"auto-hunt done: {txt.strip().splitlines()[-1][:160] if txt.strip() else 'no output'}")
            if "all hosts swept" in txt or "REFUSED" in txt:
                sp = os.path.join(ORCH, f"auto-{cur['program']}.json")
                try:
                    a = json.load(open(sp))
                except (OSError, ValueError):
                    a = {"swept": {}}
                a["exhausted"] = True
                json.dump(a, open(sp, "w"), indent=1)
                af = os.path.join(ORCH, "AUTO-HUNT")
                words = open(af).read().split() if os.path.isfile(af) else []
                if words[:1] != [cur["program"]]:
                    log(f"{cur['program']} exhausted, but AUTO-HUNT now says {' '.join(words) or 'off'}; left as is")
                elif "target" in words and brain.locked_program() == cur["program"]:
                    log(f"{cur['program']} sweep finished but it is the session LOCK; staying (the brain works leads, lanes and osint)")
                elif "target" in words:
                    inbox("AUTO", f"{cur['program']} finished ({txt.strip().splitlines()[-1][:120]}); auto-target picks the next program")
                    with open(af, "w") as fh:
                        fh.write("target\n")
                else:
                    inbox("AUTO", f"{cur['program']}: {txt.strip().splitlines()[-1][:200]}; auto mode stopped")
                    try:
                        os.remove(af)
                    except OSError:
                        pass
        elif cur.get("kind") == "target":
            txt = open(cur["out"]).read() if os.path.isfile(cur["out"]) else ""
            log(f"auto-target done: {txt.strip().splitlines()[-1][:160] if txt.strip() else 'no output'}")
        elif cur.get("kind") in ("osint", "draft"):
            txt = open(cur["out"]).read() if os.path.isfile(cur["out"]) else ""
            log(f"{cur['kind']} done: {txt.strip()[-200:] or 'no output'}")
            if cur["kind"] == "draft" and "drafted (HELD)" in txt:
                inbox("DRAFT", f"local-model draft (HELD, needs review): {txt.strip().splitlines()[-1][:200]}")
        elif cur.get("kind") == "escalate":
            txt = open(cur["out"]).read() if os.path.isfile(cur["out"]) else ""
            log(f"escalate done: {txt.strip()[-300:]}")
            rc, lout = sh([sys.executable, os.path.join(WS, "scripts/auto-lane.py"), cur["program"]], timeout=120)
            if "queued " in lout:
                log(f"auto-lane: {lout.strip()[-200:]}")
        else:
            screen(cur)
        if cur.get("brain"):
            txt = open(cur["out"]).read() if os.path.isfile(cur.get("out", "")) else ""
            brain.note_result(txt.strip().splitlines()[-1] if txt.strip() else "no output")
        st["current"] = None
    if os.path.exists(STOP):
        return
    if running_driver():  # a lane someone started by hand; wait for it
        return
    if brain.enabled():
        # a queued lane is deliberate work (the company's work order, a rescue, a chain edge): it runs before the brain
        # is even asked, so a brain `wait` or `pivot` can never starve the queue (watched live 2026-10-25: three pivots
        # in a row while a company lane sat queued)
        if [l for l in open(QUEUE).read().splitlines() if l.strip() and not l.startswith("#")] if os.path.isfile(QUEUE) else []:
            start_lane(st)
            if st.get("current"):
                return
        def launch(kind, program, argv, lane):
            out = os.path.join(WS, ".claude/state/opencode", f"brain-{kind}-{program}-{datetime.now(timezone.utc):%m%dT%H%M%S}.out")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "w") as fh:
                p = subprocess.Popen(argv, cwd=WS, env=dict(os.environ, HUNT_TARGET=program), stdout=fh,
                                     stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
            st["current"] = {"program": program, "lane": lane, "round": "brain", "pid": p.pid, "out": out,
                             "started": now(), "kind": kind, "brain": True}
            log(f"brain started {kind} pid {p.pid} {program}: {' '.join(argv[1:])[:160]}")
        try:
            if brain.decide(st, launch, lambda: start_lane(st)):
                return
        except Exception as e:  # a broken brain must never stop the hunt
            log(f"brain error, fixed rules this tick: {e!r}")
    start_lane(st)
    if not st.get("current"):
        start_auto(st)


def start_auto(st):
    """`gnoc orch auto <program>`: with the queue empty, sweep the program's next host (auto-hunt.py)."""
    f = os.path.join(ORCH, "AUTO-HUNT")
    if not os.path.isfile(f):
        return
    words = open(f).read().split()
    program = words[0] if words and words[0] != "target" else ""
    target_mode = "target" in words
    lock = brain.locked_program()
    if lock and program != lock:
        # the session LOCK pins the bot (CLAUDE.md single-named-target): whatever AUTO-HUNT says, the bot works it
        with open(f, "w") as fh:
            fh.write(f"{lock} target\n" if target_mode else f"{lock}\n")
        log(f"AUTO-HUNT re-pinned to the session LOCK {lock} (was {' '.join(words) or 'empty'})")
        program = lock
    exhausted = program and json.load(open(os.path.join(ORCH, f"auto-{program}.json"))).get("exhausted") \
        if program and os.path.isfile(os.path.join(ORCH, f"auto-{program}.json")) else False
    if exhausted and brain.locked_program() == program:
        # every host of the locked program is swept: auto-hunt would print "all hosts swept" and exit (it did so three
        # times a minute on 2026-10-26 01:17Z). The brain works it (follow_up_lane, escalate, osint); nothing to launch.
        if time.time() - st.get("_lock_idle_logged", 0) > 600:
            st["_lock_idle_logged"] = time.time()
            log(f"{program} is the session LOCK and fully swept; no auto-hunt to launch (the brain works leads, lanes and osint)")
        return
    if target_mode and (not program or exhausted) and not brain.locked_program():
        # let auto-target pick (and intake) the next program; it rewrites AUTO-HUNT when done
        out = os.path.join(WS, ".claude/state/opencode", f"auto-target-{datetime.now(timezone.utc):%m%dT%H%M%S}.out")
        with open(out, "w") as fh:
            p = subprocess.Popen([sys.executable, os.path.join(WS, "scripts/auto-target.py"), "--pick", "--write"],
                                 cwd=WS, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        st["current"] = {"program": program or "-", "lane": "auto-target", "round": "pick", "pid": p.pid, "out": out,
                         "started": now(), "kind": "target"}
        log(f"auto-target pick started pid {p.pid}")
        return
    if program:
        # gnoc pivot to a NEW program runs intake in the background: h1-scope.sh writes SCOPE.txt BEFORE the host map
        # exists, so wait for the intake process itself, not for the file, or a 0-host program reads as exhausted
        rc, ps = sh(["pgrep", "-af", f"auto-target.py --intake {program}"], timeout=10)
        if any("--intake" in l and "pgrep" not in l for l in ps.splitlines()):
            return
    if program and not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        why = open(os.path.join(ORCH, f"intake-{program}.log")).read().strip().splitlines()[-1:] \
            if os.path.isfile(os.path.join(ORCH, f"intake-{program}.log")) else ["no intake log"]
        if target_mode:
            inbox("AUTO", f"intake of {program!r} failed ({why[0][:160]}); target mode picks the next program")
            with open(f, "w") as fh:
                fh.write("target\n")
        else:
            inbox("AUTO", f"AUTO-HUNT names {program!r} but it has no SCOPE.txt ({why[0][:160]}); auto mode off. "
                  "Fix: gnoc pivot <real-handle> or gnoc orch auto target")
            os.remove(f)
        return
    if not program:
        inbox("AUTO", "AUTO-HUNT is empty; auto mode off")
        os.remove(f)
        return
    out = os.path.join(WS, ".claude/state/opencode", f"auto-{program}-{datetime.now(timezone.utc):%m%dT%H%M%S}.out")
    with open(out, "w") as fh:
        p = subprocess.Popen([sys.executable, os.path.join(WS, "scripts/auto-hunt.py"), program, "--next",
                              os.environ.get("AUTO_BATCH", "4"), "--workers", os.environ.get("AUTO_WORKERS", "4")],
                             cwd=WS, env=dict(os.environ, HUNT_TARGET=program), stdout=fh, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL, start_new_session=True)
    st["current"] = {"program": program, "lane": "auto-exposure", "round": "auto", "pid": p.pid, "out": out,
                     "started": now(), "kind": "auto"}
    log(f"auto-hunt started pid {p.pid} {program}")


# ---------- 4 drafts / 5 H1 ----------

def drafts(st):
    if time.time() - st.get("last_drafts", 0) < 300:
        return
    st["last_drafts"] = time.time()
    rc, out = sh([sys.executable, os.path.join(WS, "scripts/ship-pipeline.py"), "--all"], timeout=1800)
    # final gates: Claude (kill pass + repro check, only on drafts whose LOCAL gates all pass, cached per byte hash)
    # or GreyNOC's own QAQC (scripts/final-gate.py mode claude|human)
    try:
        gate = open(os.path.join(ORCH, "FINAL-GATE")).read().strip() or "claude"
    except OSError:
        gate = "claude"
    rc, q = sh([sys.executable, os.path.join(WS, "scripts/final-gate.py"), "queue"], timeout=120)
    waiting = [l.strip() for l in q.splitlines() if l.strip()]
    told = st.setdefault("qa_told", [])
    for d in waiting:
        if gate == "claude":
            rc, o2 = sh([sys.executable, os.path.join(WS, "scripts/ship-pipeline.py"), os.path.join(WS, d), "--llm"],
                        timeout=3600, env={"HUNT_TARGET": d.split("/")[2]})
            out += "\n" + o2
            log(f"final gates (claude) on {d}: {(re.findall(r'verdict: (.*)', o2) or ['?'])[-1][:80]}")
        elif d not in told:
            told.append(d)
            inbox("QAQC", f"{d}: every local gate passes; your QAQC is the final gate. Read it, then "
                  f"python3 scripts/final-gate.py pass {d}   (or fail {d} <why>)")
    for ln in out.splitlines():
        if ln.startswith("run ") and "READY TO FILE" in ln:
            inbox("DRAFT", ln)
    rc, pend = sh([sys.executable, os.path.join(WS, "scripts/vdp-autosubmit.py"), "--pending"], timeout=120)
    asked = st.setdefault("approve_told", [])
    for ln in pend.splitlines():
        d = ln.strip().split()[0] if ln.strip() else ""
        if d and d not in asked:
            asked.append(d)
            inbox("APPROVE", f"{d} is READY. One tap to file: python3 scripts/vdp-autosubmit.py --approve {d}"
                  + (" (policy wants your own verification: run its repro.sh first)" if "verified" in ln else ""))
    # a draft held back ONLY by missing raw Burp panels must not sit unnoticed (panels are mandatory on every filing)
    root = os.path.join(WS, "reports/drafts")
    owed = st.setdefault("panels_owed", [])
    for prog in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        for slug in sorted(os.listdir(os.path.join(root, prog))) if os.path.isdir(os.path.join(root, prog)) else []:
            pl = os.path.join(root, prog, slug, "PIPELINE.md")
            if not os.path.isfile(pl):
                continue
            fails = re.findall(r"^- FAIL (\w+)", open(pl).read(), re.M)
            key = f"{prog}/{slug}"
            if fails == ["panels"] and key not in owed:
                owed.append(key)
                inbox("NEEDS", f"{key}: every gate passes except the raw Burp panels; capture them (panel worker or by hand "
                      f"through Burp Proxy history, curl --path-as-is) into reports/drafts/{key}/panels/ + BURP-INDEX.txt")


def autosubmit(st):
    # VDP-only unattended filing; vdp-autosubmit.py re-checks every gate and is OFF without its enable file
    if time.time() - st.get("last_autosubmit", 0) < 900:
        return
    st["last_autosubmit"] = time.time()
    if not os.path.isfile(os.path.join(ORCH, "AUTO-SUBMIT-VDP.enabled")):
        return
    rc, out = sh([sys.executable, os.path.join(WS, "scripts/vdp-autosubmit.py"), "--scan"], timeout=3600)
    for ln in out.splitlines():
        if ln.startswith(("FILED", "FAILED")):
            log(f"autosubmit: {ln[:200]}")


def h1(st):
    if time.time() - st.get("last_h1", 0) < 1800:
        return
    st["last_h1"] = time.time()
    rc, out = sh([sys.executable, os.path.join(WS, "scripts/h1-selfdup.py"), "--sync"], timeout=180)
    if rc != 0:
        log(f"h1 sync failed: {out.strip()[:200]}")
        return
    try:
        reps = json.load(open(os.path.join(WS, ".claude/state/h1-self/my-reports.json")))["reports"]
    except (OSError, ValueError, KeyError):
        return
    rc, rout = sh([sys.executable, os.path.join(WS, "scripts/h1-replies.py"), "sync"], timeout=1200)
    if rc != 0:
        log(f"h1 replies sync failed: {rout.strip()[-200:]}")
    seen = st.setdefault("h1_states", {})
    for r in reps:
        old = seen.get(r["id"])
        if old and old != r["state"]:
            inbox("H1", f"report #{r['id']} ({r['program']}) changed state {old} -> {r['state']}: {r['title'][:80]}")
        seen[r["id"]] = r["state"]


OSS_DB = os.path.join(WS, ".claude/state/oss-bot/bot.db")
OSS_TRIAGE_PILE = 100      # open oss-bot leads at which the pile is culled right away
OSS_TRIAGE_JUMP = 50       # ...or this many new open leads since the last triage
OSS_TRIAGE_EVERY = 6 * 3600


def oss_leads(st):
    """Notice the oss-bot lead pile and keep it workable (2026-10-21: 1079 open, 1001 of them test-vector noise).
    Every 5 min a read-only count; when the pile is big or jumped, run scripts/oss-bot/triage.py --apply (local,
    deterministic, reversible with --undo), then ONE inbox line saying what is left to work and where. Network
    survivors reach the brain through its snapshot (follow_up_lane); secret survivors are file reviews for a human."""
    if time.time() - st.get("last_oss_check", 0) < 300 or not os.path.isfile(OSS_DB):
        return
    st["last_oss_check"] = time.time()
    import sqlite3
    try:
        con = sqlite3.connect(f"file:{OSS_DB}?mode=ro", uri=True, timeout=5)
        n_open = con.execute("SELECT count(*) FROM leads WHERE state='LEAD' AND (suppressed IS NULL OR suppressed='')").fetchone()[0]
        open_secret = {r[0] for r in con.execute("SELECT fp FROM leads WHERE state='LEAD' AND (suppressed IS NULL OR "
                                                  "suppressed='') AND tool IN ('gitleaks','trufflehog')")}
        con.close()
    except sqlite3.Error as e:
        log(f"oss leads: db read failed: {e}")
        return
    last = st.get("oss_triage") or {}
    if last and n_open < last.get("open_after", 0):  # a review or a hand mark shrank the pile: measure jumps from here
        last["open_after"] = n_open
    base = last.get("open_after", 0)
    due = (n_open >= OSS_TRIAGE_PILE and n_open != base) or n_open - base >= OSS_TRIAGE_JUMP or \
        (n_open > base and time.time() - last.get("t", 0) > OSS_TRIAGE_EVERY)
    if due:
        oss_triage(st, last)
    try:
        reviewed = set(json.load(open(os.path.join(WS, ".claude/state/oss-bot/review.json"))))
    except (OSError, ValueError):
        reviewed = set()
    if open_secret - reviewed:
        oss_review(st, len(open_secret - reviewed))


def oss_review(st, waiting):
    """Work the open secret leads: scripts/oss-bot/review.py run (public-by-design rules auto-applied, the rest to the
    brain model on the DESKTOP only, possibly-live ones posted to the inbox by review.py itself)."""
    rc, out = sh([sys.executable, os.path.join(WS, "scripts/oss-bot/review.py"), "run", "--max", "4", "--quiet"], timeout=300)  # 4 x 60 s worst case: the tick must not stall
    try:
        s = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        log(f"oss review failed rc={rc}: {out.strip()[-200:]}")
        return
    st["oss_review"] = {"ts": now(), **{k: s.get(k) for k in ("rules", "model", "surfaced", "waiting", "unlocated")}}
    if (s.get("rules") or 0) >= 20:  # a pile was cleared: say so once (possibly-live leads post their own lines)
        inbox("OSS-REVIEW", f"cleared {s['rules']} secret leads by rule (public config, per-request ids, own cookies, "
              f"JWT claims); {s.get('model', 0)} judged by the desktop model, {s.get('surfaced', 0)} possibly live, "
              f"{s.get('waiting', 0)} waiting. Details: python3 scripts/oss-bot/review.py show")
    # log only on STATE CHANGE (waiting count or endpoint changed), not every 5-minute tick
    sig = [s.get("waiting"), s.get("endpoint"), bool(s.get("skipped_no_model")), waiting]
    if (st.get("oss_review_sig") != sig) or (s.get("model") or s.get("rules") or s.get("surfaced")):
        st["oss_review_sig"] = sig
        log(f"oss review: {waiting} waiting -> {s.get('rules')} public by rule, {s.get('model')} model, "
            f"{s.get('surfaced')} possibly-live surfaced, {s.get('waiting')} left, endpoint={s.get('endpoint') or 'none'}"
            + (" (no model endpoint healthy)" if s.get("skipped_no_model") else ""))


def oss_triage(st, last):
    rc, out = sh([sys.executable, os.path.join(WS, "scripts/oss-bot/triage.py"), "--apply", "--quiet"], timeout=300)
    try:
        s = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        log(f"oss triage failed rc={rc}: {out.strip()[-200:]}")
        return
    st["oss_triage"] = {"t": time.time(), "ts": s["ts"], "open_after": s["open_after"], "culled": s["culled"]}
    log(f"oss triage: open {s['open_before']} -> {s['open_after']}, culled {s['culled']} {json.dumps(s['by_reason'])}")
    if s["culled"] or s["open_after"] - (last.get("told_open") or 0) >= OSS_TRIAGE_JUMP:  # never "culled 0" noise
        st["oss_triage"]["told_open"] = s["open_after"]
        progs = ", ".join(f"{p} {n}" for p, n in sorted(s["by_program"].items(), key=lambda kv: -kv[1])[:6])
        inbox("OSS-TRIAGE", f"culled {s['culled']} of {s['open_before']} scanner leads {json.dumps(s['by_reason'])}; "
              f"{s['open_after']} left to work ({progs}): {s['network_open']} network (brain follow-up lanes), "
              f"{s['secret_open']} secret file reviews. List: .claude/state/oss-bot/worklist.json; "
              "undo: python3 scripts/oss-bot/triage.py --undo")


def company_step(st):  # COMPANY: the manager's duties (scripts/gnoc_company.py); a failure never breaks the tick
    try:
        import gnoc_company
        gnoc_company.manage(st)
    except Exception as e:
        log(f"company error: {e!r}")


def tick():
    st = load_state()
    if os.path.exists(ECON_PAUSE):  # COMPANY: PAUSE stops everything (STOP stops lanes only)
        st["company_paused"] = True
        company_step(st)  # writes only the paused flag the office shows
        save_state(st)
        return
    st.pop("company_paused", None)
    save_state(st)   # heartbeat at tick START too: a long brain or company call must not read as a dead bot
    try:
        if health(st):
            lanes(st)
        drafts(st)
        h1(st)
        autosubmit(st)
        oss_leads(st)
    except Exception as e:  # never die; log and keep ticking
        log(f"tick error: {e!r}")
    company_step(st)
    save_state(st)


_STOP = False


def _on_signal(signum, _frame):
    global _STOP
    if not _STOP:
        _STOP = True
        log(f"orch-bot stopping on {signal.Signals(signum).name}")


def main(argv):
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    os.makedirs(ORCH, exist_ok=True)
    if argv[:1] == ["--once"]:
        tick()
        return 0
    log(f"orch-bot up, tick {TICK}s (gnoc-office's slider can speed this up to {TICK_BY_INTENSITY[5]}s"
        f" or slow it to {TICK_BY_INTENSITY[1]}s)")
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    while not _STOP:
        tick()
        end = time.time() + tick_seconds()
        while not _STOP and time.time() < end:
            time.sleep(1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
