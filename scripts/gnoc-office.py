#!/usr/bin/env python3
"""gnoc-office - the hunt workspace as a living office. One desk per real pm2 process, one server rack per
linked machine, and every sprite, screen, light and number on the floor is read live off the same files
gnoc watch uses. Nothing is invented: it is a skin on real telemetry.

WHAT YOU ARE LOOKING AT
  Read first: scripts/office-docs/OFFICE_HANDBOOK.md (who does what, the rules) and FLOW.md (the pipeline and where
  every count comes from); press ? in the office for both, plus the legend. Under the header: FLOW TODAY (probes >
  leads > in lab > proven > drafted > filed, the stalled stage marked) and NOW (one sentence from live state). Desk
  state is one grammar everywhere: ▲ working, ● idle, ‖ paused (STOP), ■ stopped, ✖ blocked (legend in the key bar).
  "drafts" = written, waiting for approval; "filed" = submitted to a platform; only a filing or an H1 accept parties.
  The office map (left) is a full room drawn to fit your terminal: a back wall with windows that show the
  real local sky (day, dusk, night), a wall clock, and a WHITEBOARD with today's real ship and probe counts.
  Each desk's MONITOR shows what that process is actually doing (scrolling code = working, cursor = idle,
  dark = stopped, red ERR = the brain's last decision failed). Under each desk: a status light, the desk
  number, a cpu sparkline sampled from pm2, and an energy battery (the cosmetic coffee meter).
  Along the bottom: the BREAK ROOM (coffee, fridge, water cooler), the table in the middle - STANDUP, and
  labelled LAB BENCH while a lead is actually being worked on it - and REPORTS, which is where every other
  room's work is meant to end up (printer, the LEAD TRIAGE in-tray with the real open oss-bot lead count, the
  shredder that runs while a real triage culls leads, the filing cabinet). On the right: the BOSS office
  (lit when a lane or a brain decision is live) and the SERVER ROOM, one rack per machine in hosts.json with
  live Ollama status.

  Workers walk real aisles (shortest path, they never walk through furniture): a real new event sends the
  desk to the FILING CABINET, a lead cull sends BRAIN to the SHREDDER, idle desks wander to the cooler,
  a treat sends them to fetch it, and standup mode gathers everyone online at the table. A real new report
  throws an OFFICE PARTY (disco floor, confetti, dancing); `!` throws one by hand.

  THE HUNT AS PAPERWORK. Every handoff is one real log line, walked desk to desk with the paper in hand:
    BRAIN -> hunter desk (GPU DESK, or UPLINK when the hunter model is on the desktop): a work order, when
      orch.log says a hunt/escalate/osint started.  The whiteboard's third line follows that hunt live.
    hunter -> BRAIN: a result sheet per swept host ("fired N, hits H, leads L"); leads go on to LEAD TRIAGE,
      a HIT goes to the BOSS as a red folder.
    BRAIN -> FILES and back with a target folder when the target picker runs; DEAD/UNFIRED verdicts are
      filed, LEAD verdicts go to the tray; a triage cull is picked up at the tray and carried to the SHREDDER.
    OSS BOT -> LEAD TRIAGE with a scan's new leads.  FRONT DESK -> PRINTER -> BOSS with a new draft report.
    PIPELINE -> FILES -> BOSS when a parked lead is rescued, promoted, or needs you.
  A delivered paper sits on the receiving desk (right end of the desktop, count beside it) for ~2.5 min;
  the boss's desk shows what is waiting for you. A busy worker's papers wait their turn (up to 2 min).
  Every trip is also a ticker line ("GPU DESK -> BRAIN: swept host: fired 42, ...").

  THE UNITS FLOOR (the default; GNOC_OFFICE_UNITS=0 for the COMPANY floor, plus GNOC_OFFICE_BOTS_ONLY=0 for the
    pm2 floor the rest of this section describes). The workers are the processing units wired to the harness,
    found live, and orch-bot is the manager who hands them jobs:
    MANAGER  orch-bot's desk (its own pm2 row: a dark room and an empty chair while pm2 has it stopped), a board
      with queue.txt, THE LINE's open work orders, what it sent to which unit, units on shift; and its OUT tray,
      where a paper nobody was seen taking waits marked ?.
    THE FLOOR  one desk per unit: GPU0, GPU1 (each sysfs card with gpu_busy_percent, numbered by VRAM; busy % on
      the monitor, VRAM in use / total under it), the CPU cores four to a desk (/proc/stat deltas, one bar per
      core on the monitor), DESKTOP GPU (the uplink's open calls, the model on its monitor) and PHONE (phone.json,
      its Ollama, the split). The sign on a desk is the job it holds right now (unit_duty).
    PROD  the website and its traffic: a board (health, edge, requests a minute, 4xx / 5xx, tunnel / onion /
      janitor, uplink requests a minute by caller) polled while the room is on screen, a console per site
      process, and the seat of whichever unit is serving a gnoc chat call that names the site. Its STUDIO board
      follows video work (scripts/video, by hand or from gnoc chat): a compile or edit is one node process, its
      children name the stage (piper, chrome, ffmpeg), its work dir counts the frames, the CPU desk of its core sits
      in PROD while it runs and carries the reel home when its manifest lands (a CPU job: the encoders run on cores).
    SERVER ROOM  every other service, one LED each.
    A job walks MANAGER -> unit only when a reading names the unit (a hunter call on the proxy, a proxy row from
    the job's process tree, a probe in the job's process tree, the laptop Ollama answering the job's model) and
    walks back on the row that closes it (the proxy's ms + status, orch.log's fired / hits / leads, a brain row's
    host). No reading, no desk: the paper goes to the OUT tray as ? and the ticker says unattributed (the UNITS
    block above d_units holds the rules; OFFICE_HANDBOOK.md spells them out).

  THE FLOOR PLAN, in the order a visitor walks it (and the order of desk numbers and Tab):
    GNOC CHAT  the analyst's desk and the kit that answers it - the live `gnoc chat` agent at desk 1, GPU
      DESK, UPLINK, SPLIT LLM, FRONT DESK (the desktop rig's control panel) and PHONE LINK. First room, and
      the biggest: this is where a case is actually worked.
    WEBSITE  your-site.example - WEBSITE, TUNNEL, ONION, JANITOR, OFFICE CAM.
    PROCESSES  what runs with nobody sitting at it: BRAIN (picks the target), OSS BOT (the scheduled
      scanners) and PIPELINE (the rescue sweep that reopens parked leads). The global STOP pauses THIS room;
      the analyst's desk is never paused by it.
    Anything new lands in GENERAL (edit OFFICES in this file to move a desk).
    All three rooms point at the same thing, and the funnel under the header counts it: a REPORT, written,
    approved by the user, and filed. "your call" is the stage only the user can clear. The GNOC CHAT desk is the
    one desk that is not a pm2 app: it is every running `gnoc chat` process (from /proc), and it works the floor
    off its own live activity log (agent/activity.jsonl, which gnoc_agent writes from the one choke point every
    call of its goes through, as that call opens and as it closes). The call it has open right now sits over
    the desk with its real age and is spelled out on its monitor; a finished call speaks and lands in the
    ticker; and the calls that are really a HANDOVER walk like any other paper - a read to the FILING CABINET,
    a draft to the PRINTER and on to the BOSS, a job to the LAB BENCH, a recorded verdict to the triage tray
    or onto the file (CHAT_TOOL_ACT holds the whole mapping).
    Selecting the WEBSITE desk turns on its telemetry (health, the public edge through the tunnel,
    traffic, latency, realtime, node, store, GreyWatch, inbox, stderr), read from the site's own endpoints only
    while selected; in the side rail's INSPECTOR, or as a floating card when the rail is hidden, and in `t`.
    Each office has its own carpet, its name on
    the wall and a door in the bottom wall; workers walk out through it. On a terminal too small for walled
    offices (about 140x45) the floor falls back to the open plan.
  WAR ROOM. Leftover floor becomes the war room: a wall board with the gnoc chat conversation (you, gnoc, its
    tool calls, and the bot events handed to it; from the newest .claude/state/orch/agent/sessions/<sid>.json, or
    the older chat histories if newer) beside the live orch.log, times in local time, newest at the bottom; a red dot blinks
    when a chat message just landed. No room for it: the chat moves to a GNOC CHAT panel in the side rail.

  MORE REAL WORK ON THE FLOOR
    THE NETWORK. The UPLINK cable is routed like real cabling: out of the UPLINK office door, along the
      corridors, through the server-room wall to the desktop rack. Every model call rides from the desk that
      MADE it (the uplink proxy names the calling process: GNOC CHAT, BRAIN, the hunter = BRAIN's child,
      FRONT DESK, ...) along the corridors to UPLINK and down the cable: a blue diamond with a trail. It leaves
      the moment the proxy opens it (.claude/state/orch/desktop-inflight.json) and the reply (green ok, red
      failed) heads home the moment the proxy logs the answer (desktop-traffic.jsonl) - live, not a replay.
      A call too short to be seen open is replayed at its logged latency. A caller with no desk (a terminal
      `gnoc`, a health poll, curl) starts at UPLINK; polls are faint dots. Brain decisions answered by the
      laptop GPU run BRAIN -> GPU DESK (purple; a replay at the decision's own seconds - the laptop Ollama has no
      proxy). The rack's LEDs flash when a packet lands; its label shows the calls open and who opened them.
      Every call is a NET ticker line (throttled per caller).
    LAB BENCH: the standup table while a lead is under investigation. Each live pipeline-sweep rescue worker
      (rescue-ledger.json dispatch pid alive) is a visitor in a white lab coat: PIPELINE hands it the lead at the
      LEAD TRIAGE tray, it walks to the bench and works there. On the bench in front of it is the lead's 5-rung
      escalation ladder (× tried, ✓ paid off, ! needs you, - n/a, · untried; the rung being worked blinks ▲, a
      ladder audit sweeps all five); its laptop scrolls while a test is in flight (a new curl/python/... child of
      the worker, named with the host it hits). Its bubble cycles hunter + lead, the rung, commands run and the
      last test; once the worker records its outcomes.jsonl row the bubble shows the verdict and probe count.
      When the pid exits it walks the verdict out: candidate or NEEDS -> BOSS, DEAD -> SHREDDER, a tried rung ->
      back to the tray, no verdict -> FILES. The rail's LAB panel lists every live one (plus BRAIN's running
      escalation and any OpenCode lane) or, when idle, the last recorded rescue verdicts. Ticker tag LAB.
    RESCUE BOARD: the corkboard in the rightmost window bay, one sticky per pipeline-sweep state (act, you
      = needs you, blinks; pro = promote; ded = dead), read from RESCUE-BOARD.md.
    BRAIN's thought cloud: an action orch-bot dispatched (escalate, osint, ...) and is still running.
    BRAIN's wastebasket: today's real rejected / fallback / error decisions; each new one is a crumpled
      paper tossed in.  Typing speed at every desk follows that process's real cpu.
    HUNT PAUSED: the global STOP flag is set. Idle workers do chores in turns: mostly they grab a broom and
      sweep up the litter (scraps dropped by real paper trips and the shredder, plus slow dust), sometimes a
      short coffee break; up to half the floor is up at once, then back to the desk. Anyone with real work in
      hand (working, a paper trip, BRAIN mid-action) keeps working.
  COSMETIC RESIDENTS (never telemetry)
    The office cat naps on the warmest desk (the process with the highest real cpu) and wanders otherwise.
    JANITOR (the keepalive process) mops an aisle now and then; the wet floor and its sign dry in ~40 s.

  Amber speech bubbles are real log lines (the verb in front is flavor, the fact never is). Blue bubbles are
  water-cooler jokes and are never presented as telemetry. Red bubbles are real alerts.

  The side panel (right) is the ops rail: INSPECTOR (the selected desk in depth, or the floor summary),
  TODAY (verdict mix + probes per local hour), REPORTS, H1 INBOX, BRAIN quest log and LEADS. The ticker at
  the bottom is the timestamped stream of every real event this screen has seen.

  gnoc-office                 the live office (full screen)
  gnoc-office --no-anim       one static frame, no input loop (for piping and screenshots)

KEYS
  Tab / arrows   cycle the selected desk          mouse click   select a desk or rack
  1-9, 0         select desk 1-10                 Esc / x       clear selection, close a panel
  c p b j        feed the selected desk (or the whole floor): coffee, pizza, beer, a joint
  [ / ]          pace slider 1-5 - a REAL lever: rewrites .claude/state/orch/office-intensity, which
                 orch-bot reads every tick (120 / 90 / 60 / 35 / 20 s per tick)
  !              office party            m   standup (workers gather, real counts)
  i              boss in / out (also: click the BOSS button in the header); shown on the office cam too
  t              telemetry panel         o   options (reset moods)
  v              show or hide the side panel   ?   help            q / Ctrl-C   quit

ADDING ANOTHER MACHINE (the same protocol as the Windows desktop link):
  1. On the new machine, run the same kind of link script as scripts/desktop-link/link-desktop.ps1,
     pointed at this laptop with a RemotePort nobody else is using yet (11436 is the desktop; the
     next one is free to pick, e.g. 11441). It reverse-tunnels that machine's own Ollama to
     127.0.0.1:<port> here, same as the desktop.
  2. Add one entry to .claude/state/orch/hosts.json:
       "newmachine": {"label": "Jump box (RTX 4090)", "ollama": "127.0.0.1:11441"}
  3. A new rack appears in the SERVER ROOM on the next poll (hosts.json is re-read every 6 s).
"""
from collections import deque
import base64
import json
import math
import os
import random
import re
import select
import shutil
import subprocess
import sys
import termios
import threading
import time
import tty
import urllib.error
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(WS, ".claude/state")
ORCH = os.path.join(STATE, "orch")
HUNTLOOP = os.path.join(STATE, "hunt-loop")
OFFICE_DIR = os.path.join(STATE, "office")
HOSTS_FILE = os.path.join(ORCH, "hosts.json")
MOOD_FILE = os.path.join(OFFICE_DIR, "mood.json")
SETTINGS_FILE = os.path.join(OFFICE_DIR, "settings.json")
BOSS_FILE = os.path.join(OFFICE_DIR, "boss.json")  # {"here": bool, "since": epoch}: GreyNOC's own in/out toggle
INTENSITY_FILE = os.path.join(ORCH, "office-intensity")
OSS_DIR = os.path.join(STATE, "oss-bot")
# COMPANY (scripts/gnoc_company.py): the bots run the business and orch-bot is the manager. With BOTS_ONLY (the
# default; GNOC_OFFICE_BOTS_ONLY=0 restores the old floor) the people on the floor are the economy roster, orch-bot
# sits in the MANAGER office, pm2 infra is a SERVER RACK, and GreyNOC's avatar is not drawn.
ECON_DIR = os.path.join(STATE, "economy")
COMPANY_FILE = os.path.join(ECON_DIR, "company.json")
ECON_PAUSE_FILE = os.path.join(ECON_DIR, "PAUSE")
LINE_FILE = os.path.join(ECON_DIR, "line.json")  # THE LINE (scripts/gnoc_line.py): every open work order + station
# UNITS (the default since 2026-10-24; GNOC_OFFICE_UNITS=0 brings back the COMPANY floor above, or with
# GNOC_OFFICE_BOTS_ONLY=0 as well the old pm2 floor): the workers are the processing units wired to the harness (each
# laptop GPU from sysfs, the CPU cores from /proc/stat, the desktop GPU behind the uplink, the phone), orch-bot is the
# manager that hands them jobs, and PROD is the room that reads the website and its traffic. See "UNITS" below.
UNITS = os.environ.get("GNOC_OFFICE_UNITS", "1") != "0"
BOTS_ONLY = os.environ.get("GNOC_OFFICE_BOTS_ONLY", "1") != "0" and not UNITS
COMPANY_BOTS = ("lead", "worker", "reflector", "phone-4b", "phone-1.7b", "oss-bot")  # the local bots; the role
# aliases (brain, chat, hunter) are drawn once, as the bot that owns their model (company.json screen.bots)
_TICK_TABLE = {1: 120, 2: 90, 3: 60, 4: 35, 5: 20}

FPS = 10
# PUBLIC MODE (GNOC_OFFICE_PUBLIC=1, set only by scripts/office-stream.py for the website's operator page):
# the real work text stays (GreyNOC 2026-10-22: "it will be cool to see actual work even redacted") and the
# streamer blacks out names, hosts, paths, URLs and e-mails in every rendered row. What this mode removes at
# the source: the gnoc chat CONVERSATION (never read, and the turn text is dropped before it can be drawn),
# the side rail (report titles, leads, brain reasons) and draft report titles on the whiteboard (an unfiled
# finding's title is the finding). What the chat agent DOES stays - the verb of every tool call, which is
# work and not conversation; the path or host it names is blacked out by the streamer like any other.
REDACT = os.environ.get("GNOC_OFFICE_PUBLIC") == "1"
#
# CARE WITH THE WORDS IN THIS FILE. The public streamer takes EVERY word of this source as office vocabulary
# that it may not black out (office-stream.py `_office_words` / `_program_words`: a program named after a
# furniture label must not redact the furniture). So an ordinary English word written here, if it is also a
# program handle or a brand stem, UN-REDACTS that program on the website - the office's own selftest cannot
# see it, because it excludes office words from its leak check by the same rule. Two such words went in with
# the chat desk's block (a loop variable and a plural) and came straight back out. Its collision set is
# pinned in office-stream.py, so a new one fails QA instead of shipping.
LOCK = threading.RLock()  # guards BUBBLES / EVENTS / TOASTS, which the poll threads write and the UI reads


# ---------- tiny disk helpers ----------

def jload(path, default):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return default


def jsave(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def jsonl_tail(path, n):
    try:
        lines = open(path).read().splitlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            pass
    return out


def http_json(url, timeout=1.5):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _ts_epoch(ts):
    """ISO time -> epoch; an explicit offset is honoured (ships.jsonl has -04:00 rows), bare or Z is UTC."""
    try:
        d = datetime.fromisoformat(str(ts).strip().replace("Z", "+00:00"))
    except (ValueError, TypeError):
        try:
            d = datetime.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S")
        except (ValueError, TypeError):
            return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _local_day(ts):
    """(local date, local hour) of a stored UTC timestamp, or (None, None)."""
    e = _ts_epoch(ts)
    if e is None:
        return None, None
    d = datetime.fromtimestamp(e).astimezone()
    return d.date(), d.hour


def _ago(ts):
    """Relative time from a real ISO-8601 UTC timestamp; an unparseable one is shown verbatim, never hidden."""
    t0 = _ts_epoch(ts)
    if t0 is None:
        return str(ts)[:16]
    secs = max(0, time.time() - t0)
    if secs < 60:
        return "now"
    if secs < 3600:
        return f"{int(secs // 60)}m"
    if secs < 86400:
        return f"{int(secs // 3600)}h"
    return f"{int(secs // 86400)}d"


def _recent(ts, secs):
    t0 = _ts_epoch(ts)
    return t0 is not None and time.time() - t0 < secs


def _dur(secs):
    secs = int(secs)
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m{secs % 60:02d}s"
    if secs < 86400:
        return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"
    return f"{secs // 86400}d{(secs % 86400) // 3600:02d}h"


def clip(s, n):
    s = str(s)
    if n <= 0:
        return ""
    return s if len(s) <= n else (s[:n - 2] + ".." if n > 3 else s[:n])


def wrap(text, width, max_lines):
    words, lines, cur = str(text).split(), [], ""
    for w in words:
        if len(cur) + len(w) + (1 if cur else 0) <= width:
            cur = f"{cur} {w}" if cur else w
        else:
            if cur:
                lines.append(cur)
            cur = w[:width]
        if len(lines) >= max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    if len(lines) == max_lines and len(" ".join(lines)) < len(str(text).strip()):
        lines[-1] = clip(lines[-1] + " ...", width)
    return lines


# ---------- real data collectors (mirrors gnoc watch's Feed pattern, self-contained here) ----------

CPU_HIST = {}  # pm2 name -> deque of cpu % samples, one per pm2 poll (real samples, nothing interpolated)
PM2_LAST = []  # the newest d_pm2() rows, so d_events reads them instead of running pm2 jlist a second time
CHAT_KEY = "gnoc-chat"  # the GNOC CHAT desk: not a pm2 app, it is every live `gnoc chat` process on this machine
_CHAT_CPU = {}  # pid -> (cpu ticks, epoch) from the previous poll, for a real current-cpu % (not ps's lifetime avg)


def _gnoc_chat_procs():
    """Live `gnoc chat` processes: an argv element named gnoc (the CLI, run directly or by an interpreter)
    followed by `chat`. A shell whose command STRING mentions "gnoc chat" is not a match (argv, not text)."""
    out = []
    for pid in (d for d in os.listdir("/proc") if d.isdigit()):
        try:
            argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        except OSError:
            continue
        argv = [a.decode(errors="replace") for a in argv if a]
        if any(os.path.basename(a) in ("gnoc", "gnoc.py") and argv[i + 1:i + 2] == ["chat"]
               for i, a in enumerate(argv[:3])):
            out.append(int(pid))
    return out


def _chat_row():
    """A pm2-shaped row for the GNOC CHAT desk, built from /proc so every number on it is real."""
    pids, now = _gnoc_chat_procs(), time.time()
    hz = os.sysconf("SC_CLK_TCK")
    try:
        boot = next(float(ln.split()[1]) for ln in open("/proc/stat") if ln.startswith("btime"))
    except (OSError, StopIteration, ValueError):
        boot = None
    cpu = mem = 0.0
    start = None
    for pid in pids:
        try:
            st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            ticks = int(st[11]) + int(st[12])  # utime + stime
            started = boot + int(st[19]) / hz if boot else None
            mem += int(open(f"/proc/{pid}/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1e6
        except (OSError, IndexError, ValueError):
            continue
        prev = _CHAT_CPU.get(pid)
        if prev and now > prev[1]:
            cpu += 100.0 * (ticks - prev[0]) / hz / (now - prev[1])
        _CHAT_CPU[pid] = (ticks, now)
        if started and (start is None or started < start):
            start = started
    for pid in [p for p in _CHAT_CPU if p not in pids]:
        del _CHAT_CPU[pid]
    return {"name": CHAT_KEY, "status": "online" if pids else "stopped", "cpu": round(cpu, 1), "mem_mb": mem,
            "restarts": 0, "uptime_ms": start * 1000 if start else None, "pid": pids[0] if pids else None,
            "virtual": True, "n_procs": len(pids)}


def d_pm2():
    global PM2_LAST
    try:
        out = subprocess.run(["pm2", "jlist"], capture_output=True, text=True, timeout=6).stdout
        procs = json.loads(out)
    except Exception:
        return []
    out = []
    for p in procs:
        env = p.get("pm2_env", {})
        mon = p.get("monit") or {}
        row = {"name": p.get("name"), "status": env.get("status", "?"),
               "cpu": mon.get("cpu", 0) or 0, "mem_mb": (mon.get("memory") or 0) / 1e6,
               "restarts": env.get("restart_time", 0), "uptime_ms": env.get("pm_uptime"),
               "pid": p.get("pid"),
               # a cron job with autorestart off (pipeline-sweep) exits between runs: stopped is its resting state
               "cron": env.get("cron_restart") if env.get("autorestart") is False else None}
        CPU_HIST.setdefault(row["name"], deque(maxlen=48)).append(row["cpu"])
        out.append(row)
    if out:  # pm2 answered: the GNOC CHAT desk sits beside its apps
        row = _chat_row()
        CPU_HIST.setdefault(row["name"], deque(maxlen=48)).append(row["cpu"])
        out.append(row)
    PM2_LAST = out
    return out


def d_brain():
    rows = jsonl_tail(os.path.join(ORCH, "brain.jsonl"), 20)
    last = rows[-1] if rows else {}
    recent, seen = [], set()  # last DISTINCT actions, a repeated action collapses to one quest-log line
    for r in reversed(rows):
        a = str(r.get("action") or "").strip()
        if a and a not in seen:
            seen.add(a)
            recent.append({"action": a, "status": r.get("status"), "ts": r.get("ts"),
                           "reason": str(r.get("reason") or r.get("detail") or "")})
        if len(recent) >= 4:
            break
    # "today" counts read a long tail (the 20-row window above capped "brain today" at 20), local day
    today = datetime.now().astimezone().date()
    day = [r for r in jsonl_tail(os.path.join(ORCH, "brain.jsonl"), 3000) if _local_day(r.get("ts"))[0] == today]
    rejects = sum(1 for r in day if r.get("status") in ("rejected", "fallback", "error"))
    return {"status": last.get("status"), "action": last.get("action"), "ts": last.get("ts"),
            "reason": str(last.get("reason") or last.get("detail") or ""), "n_today": len(day),
            "rejects_today": rejects, "recent": recent}


def d_company():
    """COMPANY: company.json (written by orch-bot's manager step every tick) plus the PAUSE and STOP flags."""
    c = jload(COMPANY_FILE, None)
    return {"started": isinstance(c, dict) and bool(c), "c": c if isinstance(c, dict) else {},
            "paused": os.path.exists(ECON_PAUSE_FILE), "stop": os.path.exists(os.path.join(HUNTLOOP, "STOP"))}


def d_line():
    """THE LINE: line.json as gnoc_line rewrites it on every open/advance; a flat list of open work orders."""
    j = jload(LINE_FILE, {})
    rows = []
    for prog, wos in ((j.get("programs") or {}) if isinstance(j, dict) else {}).items():
        for w in wos if isinstance(wos, list) else []:
            if isinstance(w, dict):
                rows.append(dict(w, program=prog))
    rows.sort(key=lambda w: (-int(w.get("station") or 0), w.get("age_s") or 0))
    return {"updated": j.get("updated") if isinstance(j, dict) else None, "orders": rows}


STORY_FILE = os.path.join(ECON_DIR, "story.jsonl")


def d_story():
    """The story ticker: the last 20 plain sentences gnoc_company wrote from real events (story.jsonl)."""
    return [r for r in jsonl_tail(STORY_FILE, 20) if isinstance(r, dict) and r.get("text")]


def company_rows(d):
    """The PEOPLE in bots-only mode: one pm2-shaped row per roster bot (orch-bot is the manager, not a desk)."""
    d = d or {}
    roster = {r["bot"]: r for r in (d.get("c") or {}).get("roster") or [] if isinstance(r, dict) and r.get("bot")}
    view = ((d.get("c") or {}).get("screen") or {}).get("bots") or {}
    if view:   # the company's own list: local bots, aliases folded into their owner (gnoc_company.screen)
        names = ["orch-bot"] + [n for n in view if n != "orch-bot"]
    else:      # before the first tick: the local bots
        names = ["orch-bot"] + list(COMPANY_BOTS)
    out = []
    for n in names:
        r = roster.get(n, {})
        v = view.get(n) or {}
        out.append({"name": n, "status": "online", "cpu": 0, "mem_mb": 0, "restarts": 0, "uptime_ms": None,
                    "pid": None, "virtual": True, "bot": True,
                    "bstate": "paused" if d.get("paused") else str(r.get("status") or "idle"),
                    "wallet": v.get("coins", r.get("wallet")), "brier": r.get("brier"),
                    "assignment": str(r.get("assignment") or ""), "morale": r.get("morale"), "nick": v.get("name") or n, "glyph": v.get("face"),
                    "stars": v.get("stars"), "job": v.get("job"), "doing": v.get("doing"), "broke": v.get("broke")})
    return out


def d_lanes():
    """Any live OpenCode driver process (ps-based, same convention gnoc uses)."""
    try:
        out = subprocess.run(["pgrep", "-af", "opencode-lane.sh"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        out = ""
    return [ln for ln in out.splitlines() if ln.strip()]


HOSTS_LAST = {}  # the newest d_hosts() result, for the units poller (it runs on a thread of its own)


def d_hosts():
    """Every registered remote machine (hosts.json) + its live Ollama status, polled directly."""
    hosts = jload(HOSTS_FILE, {})
    out = {}
    for key, cfg in hosts.items():
        addr = cfg.get("ollama", "")
        row = {"label": cfg.get("label", key), "addr": addr}
        if cfg.get("status_file"):  # a USB machine (the phone): its link supervisor says whether the cable is live
            link = jload(os.path.join(WS, cfg["status_file"]), {})
            row["link"] = link
            if link.get("state") != "device":
                row.update(up=False, err=link.get("hint") or f"adb: {link.get('state', 'no status yet')}")
                out[key] = row
                continue
        if cfg.get("rpc"):  # in the running split? split-llm logs every RPC device it starts with
            log = os.path.expanduser("~/.pm2/logs/split-llm-out.log")
            try:
                with open(log, "rb") as fh:
                    fh.seek(max(0, os.path.getsize(log) - 20000))
                    tail = fh.read().decode("utf-8", "replace")
                last = tail.rsplit("split-llm: devices", 1)[-1] if "split-llm: devices" in tail else ""
                split_on = any(p.get("name") == "split-llm" and p.get("status") == "online" for p in PM2_LAST)
                row["in_split"] = bool(split_on and cfg["rpc"] in last)
            except OSError:
                row["in_split"] = False
        try:
            ver = http_json(f"http://{addr}/api/version", 2)
            ps = http_json(f"http://{addr}/api/ps", 2)
            row["up"] = True
            row["version"] = ver.get("version")
            row["models"] = ps.get("models") or []
        except Exception as e:
            row["up"] = False
            row["err"] = str(e)[:60]
        out[key] = row
    HOSTS_LAST.clear()
    HOSTS_LAST.update(out)
    return out


SECRETS_FILE = os.path.expanduser("~/.config/gnoc/secrets.env")
H1_CACHE_FILE = os.path.join(OFFICE_DIR, "h1-activity.json")
H1_API = "https://api.hackerone.com/v1/hackers"


def _h1_creds():
    try:
        text = open(SECRETS_FILE).read()
    except OSError:
        return None, None

    def grab(key):
        m = re.search(rf"^{key}=(.*)$", text, re.M)
        return m.group(1).strip().strip('"').strip("'") if m else ""
    handle, token = grab("HACKERONE_HANDLE"), grab("HACKERONE_API_TOKEN")
    return (handle, token) if handle and token else (None, None)


def _h1_get(path, handle, token, timeout=8):
    auth = base64.b64encode(f"{handle}:{token}".encode()).decode()
    req = urllib.request.Request(f"{H1_API}{path}",
                                 headers={"Authorization": f"Basic {auth}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def d_h1_activity():
    """Our own submitted-report activity, read-only. ONE cheap list call (GET /me/reports) carries
    `last_program_activity_at` per report - the real signal that something changed. Only once a report's
    stamp actually moves does this spend a second call on THAT report's detail to pull the real latest
    comment. The seen-stamps cache persists so a restart does not replay every report as new, and the
    first-ever poll primes the cache silently instead of firing N stale events."""
    handle, token = _h1_creds()
    cache = jload(H1_CACHE_FILE, {"seen": {}, "events": []})
    if not handle:
        return {"up": False, "reason": "no HACKERONE_API_TOKEN in secrets.env", "events": cache.get("events", [])}
    try:
        data = _h1_get("/me/reports?page[size]=50", handle, token)
    except Exception as e:
        return {"up": False, "reason": str(e)[:80], "events": cache.get("events", [])}
    rows = data.get("data", [])
    cold = not cache["seen"]
    new_events = []
    states = {}
    for row in rows:
        rid = row["id"]
        attrs = row.get("attributes", {})
        states[attrs.get("state") or "?"] = states.get(attrs.get("state") or "?", 0) + 1
        stamp = attrs.get("last_program_activity_at") or attrs.get("last_activity_at")
        if not stamp or cache["seen"].get(rid) == stamp:
            continue
        prev_seen = rid in cache["seen"]
        cache["seen"][rid] = stamp
        if cold or not prev_seen:
            continue
        message = None
        try:
            detail = _h1_get(f"/reports/{rid}", handle, token)
            acts = (detail.get("data", {}).get("relationships", {}) or {}).get("activities", {}).get("data", [])
            if acts:
                message = acts[-1].get("attributes", {}).get("message")
        except Exception:
            pass
        new_events.append({"ts": stamp, "report_id": rid, "title": (attrs.get("title") or "?")[:70],
                           "state": attrs.get("state"), "message": (message or "")[:220]})
    if new_events:
        cache["events"] = (new_events + cache.get("events", []))[:20]
    jsave(H1_CACHE_FILE, cache)
    return {"up": True, "events": cache.get("events", []), "n_reports": len(rows), "states": states}


def d_outcomes_today():
    """Today = the viewer's LOCAL day, hours are local hours (the file stores UTC)."""
    today = datetime.now().astimezone().date()
    verdicts, hours, n, probes, classes, kills, weak = {}, [0] * 24, 0, 0, {}, [], 0
    for r in jsonl_tail(os.path.join(HUNTLOOP, "outcomes.jsonl"), 4000):
        day, hour = _local_day(r.get("ts"))
        if day != today:
            continue
        n += 1
        v = r.get("verdict", "?")
        verdicts[v] = verdicts.get(v, 0) + 1
        hours[hour] += 1
        try:
            probes += int(r.get("probes") or 0)
        except (TypeError, ValueError):
            pass
        cls = verdict_class(v)
        classes[cls] = classes.get(cls, 0) + 1
        m = re.search(r"weak leads (\d+)", str(r.get("notes") or ""))  # auto-hunt's signal-only finds (LEADS.md)
        if m:
            weak += int(m.group(1))
        if cls in ("dead", "unfired"):
            kills.append((str(r.get("target") or "?"), str(v), str(r.get("notes") or r.get("capability") or "")))
    # n = outcome ROWS (one per lane that recorded a verdict); probes = the requests those lanes report firing
    return {"n": n, "verdicts": verdicts, "hours": hours, "probes": probes, "classes": classes, "kills": kills[-3:],
            "weak": weak}


def verdict_class(v):
    """One outcomes.jsonl verdict -> the funnel stage it proves: candidate (a captured terminal), lead (a real
    mechanism, no terminal yet), needs (blocked on the user), dead (tried and refuted), unfired (not tried)."""
    v = str(v or "").upper()
    if "CANDIDATE" in v or v.startswith("FINDING"):
        return "candidate"
    if v.startswith("LEAD"):
        return "lead"
    if v.startswith("NEEDS"):
        return "needs"
    if v.startswith("DEAD"):
        return "dead"
    if v.startswith("UNFIRED"):
        return "unfired"
    return "other"


def ship_kind(r):
    """ships.jsonl mixes rows: a DRAFT written, a SUBMISSION filed on a platform, a CLOSURE recorded, and untyped
    hunt notes. Only a submission is a ship; a draft is written but not filed; a note is neither."""
    k = r.get("kind")
    if k in ("draft", "submission", "closure"):
        return k
    path = " ".join(str(r.get(f) or "") for f in ("path", "draft", "report"))
    return "draft" if "reports/drafts" in path else "note"


def d_ships_today():
    today = datetime.now().astimezone().date()
    return [r for r in jsonl_tail(os.path.join(HUNTLOOP, "ships.jsonl"), 500) if _local_day(r.get("ts"))[0] == today]


def oss_snapshot():
    """Real oss-bot lead state, read-only: open count, newest finished scan, last triage, review tallies."""
    out = {"open": None, "last_run": None, "triage": jload(os.path.join(OSS_DIR, "triage.json"), {}), "review": {}}
    try:
        import sqlite3
        con = sqlite3.connect(f"file:{os.path.join(OSS_DIR, 'bot.db')}?mode=ro", uri=True, timeout=2)
        out["open"] = con.execute("SELECT count(*) FROM leads WHERE state='LEAD' AND (suppressed IS NULL OR "
                                  "suppressed='')").fetchone()[0]
        out["last_run"] = con.execute("SELECT id, program, job, rc, audit, leads_new FROM runs WHERE ended IS NOT NULL "
                                      "AND audit != 'DRY' ORDER BY ended DESC LIMIT 1").fetchone()
        con.close()
    except Exception:
        pass
    rev = jload(os.path.join(OSS_DIR, "review.json"), {})
    out["review"] = {"n": len(rev), "rule": sum(1 for v in rev.values() if v.get("kind") == "rule"),
                     "live": [v for v in rev.values() if v.get("verdict") == "possibly-live" and v.get("told")]}
    return out


# ---------- events: real log lines turned into speech + a ticker, never invented (the PHRASING can be
# funny; the FACT inside it never is) ----------

_BUBBLE_TIMES = deque(maxlen=20)  # creation times of recent bubbles, for the floor-wide rate limit
BUBBLES = {}  # desk key -> {"text", "until", "created", "flavor", "dest", "alert"}
EVENTS = deque(maxlen=200)  # (epoch, tag, text, color) - the ticker; only real events land here
TOASTS = []  # {"text", "color", "until"}
_LAST_SEEN = {}
# speech bubbles say the real event plainly (GreyNOC 2026-10-22 brief: bubbles are for real events only)
BRAIN_PLAIN = {"ok": "decided:", "wait": "waiting:", "rejected": "decision rejected:", "fallback": "model failed, fell back:",
               "error": "decision failed:"}
BRAIN_VERB = {
    "ok": ["thinking:", "crunching it:", "on it, boss:", "brain cell activated:"],
    "wait": ["thinking:", "hmm, let me think...", "gimme a sec:"],
    "rejected": ["pfft, rejected:", "nope, that got shot down:", "well THAT didn't fly:", "the model said no to:"],
    "fallback": ["ugh, model hiccup on:", "brain fart, falling back on:", "my brain just buffered on:"],
    "error": ["something broke on:", "nope nope nope:", "that's a paddlin':"],
}
RESTART_LINES = ["ouch, I just got restarted", "whoa, did I just die and come back?",
                 "pm2 revived me, don't ask what happened", "note to self: don't do THAT again",
                 "I blacked out for a second there"]
SHIP_LINES = ["just wrote up: {t}", "hot off the press: {t}", "fresh report, still warm: {t}",
              "boom, filed the paperwork on: {t}"]
# pure flavor - idle small talk, NEVER presented as a real log line or fact (blue bubbles, never in the ticker)
IDLE_CHATTER = [
    "is it Friday yet?", "anyone else smell burnt toast?", "the printer jammed again, don't ask",
    "I swear this chair has a mind of its own", "coffee machine's out, this is a crisis",
    "did someone leave a sandwich in the fridge? it's sentient now", "just five more minutes...",
    "wait, are we getting paid in crypto now?", "I heard the boss is in a good mood today",
    "someone left their mic on in the last meeting", "is the AC broken or is it just me?",
    "I think my monitor is possessed", "my chair squeaks every time I breathe", "has anyone seen my stapler",
    "I've been staring at this cursor blink for ten minutes", "the vending machine ate my dollar again",
    "I think I left the stove on. I don't own a stove",
]
SWEEP_LINES = ["hunt's paused, might as well tidy up", "who leaves paper on the floor?", "sweep sweep sweep",
               "this place is a mess when the bots are busy", "found a lead under the desk. kidding. it's dust"]
MOP_LINES = ["mopping aisle 3, mind the floor", "who tracked coffee all the way to the server room?",
             "wet floor, walk around", "keeping it alive and clean, that's the job"]
KEY_TAG = {"orch-bot": "BRAIN", "ship-desk": "SHIP", "h1-desk": "H1", "hunt-floor": "HUNT", "oss-bot": "OSS",
           CHAT_KEY: "CHAT"}

PARTY_UNTIL = 0.0
PARTY_REASON = ""
WHITEBOARD_FLASH_UNTIL = 0.0  # a new ships.jsonl row or H1 reply just landed
RESTART_FLASH_UNTIL = 0.0     # a real pm2 restart-count increase was just seen
SHRED_UNTIL = 0.0             # a real triage/review run is suppressing leads: the shredder runs
LEAD_ALERT_UNTIL = 0.0        # a real AUDIT FAIL or a lead the review called possibly-live
PRINT_UNTIL = 0.0             # a real report was just written: the printer prints it
TRAY_FLASH_UNTIL = 0.0        # a real lead was just dropped in the LEAD TRIAGE tray

# ---------- the hunt as paperwork ----------
# Every trip below is ONE real log line made visible: a worker walks a paper from where the work came from to
# where it goes next. The handoff is the fact; the walking is the skin. Sources: orch.log (target picks, hunt
# orders, one result line per swept host), oss-bot runs + triage, outcomes.jsonl verdicts, ships.jsonl drafts,
# and the bot INBOX (hits, exploit candidates, rescue promotions). Each trip is also a ticker line.
HANDOFFS = deque(maxlen=12)   # pending trips: {"who", "legs": [(dest, doc)], "bring", "label", "created"}
PILES = {}                    # desk key or "boss" -> [(doc, until)]: papers on a desk after a real delivery
HUNT_NOW = {}                 # the hunt as orch.log tells it: prog, hosts swept, fired, hits, leads, last
DOCS = {"order": ("▤", 117, "work order"), "result": ("▤", 252, "sweep result"), "lead": ("▤", 221, "lead"),
        "hit": ("▤", 203, "HIT"), "junk": ("▤", 245, "junk"), "archive": ("▤", 246, "dead verdict"),
        "report": ("▤", 78, "report"), "folder": ("▥", 179, "target folder"), "split": ("▤", 141, "shared paper"),
        "reel": ("▦", 213, "video reel")}  # reel: UNITS STUDIO, a compile whose manifest landed
PLACE = {"tray": "LEAD TRIAGE", "shredder": "SHREDDER", "cabinet": "FILING", "printer": "PRINTER", "boss": "BOSS"}
_EVERY = {}


def _every(key, secs):
    """Rate limit for trips whose source line repeats in bursts (the picker logs every ~20 s when dry)."""
    now = time.time()
    if now - _EVERY.get(key, 0) < secs:
        return False
    _EVERY[key] = now
    return True


def hunter_desk():
    """auto-hunt runs on the hunter-role model: the laptop Ollama (GPU DESK) or the desktop one (UPLINK)."""
    roles = jload(os.path.join(ORCH, "models.json"), {})
    return "desktop-proxy" if str(roles.get("hunter") or "").endswith("@desktop") else "qwen3:8b"


def handoff(who, legs, label, tag="HUNT", bring=None, color=None):
    """Queue one trip and write its ticker line now (the event is real whether or not anyone can walk it)."""
    dest = legs[-1][0] if legs else ""
    where = label_of(dest[5:]) if dest.startswith("desk:") else PLACE.get(dest, dest.upper())
    if REDACT and tag == "SHIP":  # report papers carry the draft title: the kind only
        label = "report for approval"
    with LOCK:
        HANDOFFS.append({"who": who, "legs": list(legs), "bring": bring, "label": label, "created": time.time()})
    log_event(tag, f"{label_of(who)} -> {where}: {label}", color or TAG_COLOR.get(tag, C_INFO), safe=REDACT)


# ---------- more of the real work, drawn ----------
TRAFFIC = deque(maxlen=200)    # new desktop-traffic.jsonl rows: every request the UPLINK proxy forwarded
TRAFFIC_FILE = os.path.join(ORCH, "desktop-traffic.jsonl")
INFLIGHT_FILE = os.path.join(ORCH, "desktop-inflight.json")  # the proxy's open model calls, live (id -> caller)
INFLIGHT = {}                  # the newest copy of that file's "open" map
UNIT_TRAFFIC = deque(maxlen=400)  # the same new rows for the units poller (tick_uplink drains TRAFFIC every frame)
LAPTOP_CALLS = deque(maxlen=20)  # brain decisions answered by the laptop GPU (the brain log rows), BRAIN<->GPU DESK
# which desk a proxy caller works at (traffic_proxy._classify names); a caller with no desk (a terminal `gnoc`,
# a viewer polling health, a stray curl) starts at the UPLINK desk itself
CALLER_DESK = {"gnoc-chat": CHAT_KEY, "orch-bot": "orch-bot", "hunter": "orch-bot", "control-panel": "control-panel",
               "pipeline-sweep": "pipeline-sweep", "oss-bot": "oss-bot"}
RESCUE = {}                    # RESCUE-BOARD.md state counts (pipeline-sweep), for the corkboard
RESCUE_AGE = [None]            # seconds since pipeline-sweep last rewrote the board (it runs every 4 h)
BRAIN_THINK = {}               # an action orch-bot dispatched and is still running (orch.log start .. done)
BALLS = deque(maxlen=20)       # epochs of real rejected/fallback/error brain decisions: crumpled-paper tosses
STOP_FILE = os.path.join(HUNTLOOP, "STOP")


def _traffic_watermark(path, size):
    """(ts, id) of the last row in the log now, so a resync after a trim can tell new rows from drawn ones."""
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 4096))
            lines = fh.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return 0.0, None
    for ln in reversed(lines):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        return float(r.get("ts") or 0), r.get("id")
    return 0.0, None


def d_traffic():
    """Tail the uplink proxy's request log by byte offset. First call primes at EOF (no replay of history).

    When the proxy trims the log the file shrinks under us. Priming at the new end of file then threw away every
    row written since the last poll, which is why this panel emptied out exactly when traffic was heaviest.
    Instead we re-read the tail and keep only rows newer than the last one we drew (by ts, with the recent ids
    as the tie-break), so a trim costs nothing and replays nothing.
    """
    try:
        st = os.stat(TRAFFIC_FILE)
    except OSError:
        return {"n": 0}
    size, ino = st.st_size, st.st_ino
    off = _LAST_SEEN.get("traffic_off")
    if off is None:
        ts, rid = _traffic_watermark(TRAFFIC_FILE, size)
        _LAST_SEEN.update({"traffic_off": size, "traffic_ino": ino, "traffic_ts": ts,
                           "traffic_ids": [rid] if rid else []})
        return {"n": 0}
    # a trim replaces the file (new inode) or truncates it (smaller than our offset); either way our byte
    # offset means nothing any more, so re-read the tail and let the watermark say what is actually new. A
    # rewrite can even leave the size unchanged, which is why the inode is checked and not just the size.
    resynced = size < off or ino != _LAST_SEEN.get("traffic_ino")
    _LAST_SEEN["traffic_ino"] = ino
    if resynced:
        off = max(0, size - 200000)
    rows = []
    if size > off:
        with open(TRAFFIC_FILE, "rb") as fh:
            fh.seek(off)
            chunk = fh.read(min(size - off, 200000))
        cut = chunk.rfind(b"\n") + 1
        _LAST_SEEN["traffic_off"] = off + cut
        lines = chunk[:cut].decode("utf-8", "replace").splitlines()
        if resynced and off and lines:
            lines = lines[1:]  # the seek landed mid-row
        mark = float(_LAST_SEEN.get("traffic_ts") or 0)
        seen = _LAST_SEEN.setdefault("traffic_ids", [])
        seen_set = set(seen)
        for ln in lines:
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if resynced:
                ts = float(r.get("ts") or 0)
                if ts < mark or (ts == mark and r.get("id") in seen_set):
                    continue  # already drawn, before the trim renumbered the offsets
            rows.append(r)
        if rows:
            _LAST_SEEN["traffic_ts"] = max([mark] + [float(r.get("ts") or 0) for r in rows])
            seen[:] = ([r.get("id") for r in rows] + seen)[:600]
    with LOCK:
        TRAFFIC.extend(rows[-60:])
        if UNITS:
            UNIT_TRAFFIC.extend(rows[-200:])
    d = jload(INFLIGHT_FILE, {})
    INFLIGHT.clear()
    if time.time() - (d.get("ts") or 0) < 400:  # the proxy rewrites it on every call start and end
        INFLIGHT.update({k: v for k, v in (d.get("open") or {}).items() if time.time() - (v.get("ts") or 0) < 310})
    return {"n": len(rows)}


# gnoc chat keeps each conversation in agent/sessions/<sid>.json and only its settings in agent/session.json (since
# per-launch sessions); the two older chat histories are kept as fallbacks for a machine that never ran it.
CHAT_SETTINGS = os.path.join(ORCH, "agent", "session.json")
CHAT_SESSIONS = os.path.join(ORCH, "agent", "sessions")
CHAT_FILES = [os.path.join(ORCH, "desktop-chat-history.json"), os.path.join(ORCH, "chat-history.json")]


def _chat_session_file():
    """The newest per-launch gnoc chat conversation file, or None."""
    try:
        files = [e for e in os.scandir(CHAT_SESSIONS) if e.name.endswith(".json") and e.is_file()]
    except OSError:
        return None
    return max(files, key=lambda e: e.stat().st_mtime).path if files else None


def _md_plain(t):
    """Markdown -> one plain line. Only markup is removed: a single _ inside a word is content (the workspace)."""
    t = re.sub(r"```.*?```", " [code] ", str(t), flags=re.S)
    t = re.sub(r"(\*\*|__|\*|`)", "", t)
    t = re.sub(r"(?m)^\s*(#+|>)\s*", "", t)
    return re.sub(r"\s+", " ", t).strip()


def _tool_args(a):
    """Tool-call arguments (a dict, or a JSON string of one) as `key=value ...`."""
    if isinstance(a, str):
        try:
            a = json.loads(a)
        except ValueError:
            return _md_plain(a)
    if isinstance(a, dict):
        return " ".join(f"{k}={_md_plain(v)}" for k, v in a.items())
    return _md_plain(a)


def d_chat():
    """The gnoc chat conversation for the WAR ROOM board: the newest of the agent session and the two older
    chat histories. Injected 'BOT EVENTS' turns are shown as bot events, not as something you typed."""
    cands = [f for f in [_chat_session_file()] + CHAT_FILES if f and os.path.exists(f)]
    best = None if REDACT else max(cands, key=os.path.getmtime, default=None)
    rows = []
    if best:
        d = jload(best, {})
        hist = d.get("history") if isinstance(d, dict) else d
        for m in (hist or [])[-40:]:
            role, txt = m.get("role"), m.get("content") or ""
            if role == "user" and str(txt).startswith("BOT EVENTS"):
                n = len(re.findall(r"\[\d{4}-\d{2}-\d{2}T", str(txt)))  # one timestamped line per event
                rows.append(("bot", f"{n} bot event{'s' * (n != 1)} handed to the chat"))
            elif role == "user":
                rows.append(("you", _md_plain(txt)))
            elif role == "assistant":
                for tc in m.get("tool_calls") or []:
                    fn = (tc.get("function") or {}) if isinstance(tc, dict) else {}
                    rows.append(("tool", f"{fn.get('name', '?')} {_tool_args(fn.get('arguments', ''))[:80]}"))
                if txt:
                    rows.append(("gnoc", _md_plain(txt)))
    try:
        log = [ln for ln in open(os.path.join(ORCH, "orch.log")).read().splitlines()[-24:] if ln.strip()]
    except OSError:
        log = []
    out_log = []
    for ln in log:
        m = re.match(r"^\[([^\]]+)\]\s*(.*)$", ln)
        e = _ts_epoch(m.group(1)) if m else None
        out_log.append((datetime.fromtimestamp(e).strftime("%H:%M:%S") if e else "", m.group(2) if m else ln))
    return {"chat": rows[-24:], "src": os.path.basename(best) if best else None,
            "mtime": os.path.getmtime(best) if best else None, "log": out_log}


# ---------- the GNOC CHAT desk's real work (agent/activity.jsonl) ----------
# The chat agent appends one row per tool call as it OPENS and as it CLOSES, and one per turn (gnoc_agent.py
# `_activity`). That file is the only live signal there is: the session file is written when a turn ENDS, so
# before this the desk sat idle through a ten-minute `bash` and then blinked "working" for 90 s after the work
# was over. Read the same way as the uplink's traffic log - by byte offset, tailing, never re-reading the file.
CHAT_ACT_FILE = os.path.join(ORCH, "agent", "activity.jsonl")
CHAT_LIVE = {}                   # call id -> {"name", "arg", "t0"}: the tool calls open RIGHT NOW
# pid -> {"t0", "text", "program"} for each turn being written. Keyed by pid because GreyNOC runs more than
# one `gnoc chat` at a time (the desk is every one of them): a single slot meant the second window's turn
# ending wiped the first window's, and the desk went quiet in the middle of its own work.
CHAT_TURNS = {}
CHAT_DONE = deque(maxlen=12)     # (epoch, name, arg, secs, ok) of finished calls, newest last, for the rail
CHAT_COUNT = {"calls": 0, "turns": 0, "blocked": 0, "failed": 0, "by": {}}  # since this view attached, not
# since midnight: the log is a tail, so a count over "today" would be a count over whatever has not been
# trimmed yet. The rail says "watched" for exactly that reason.
_CHAT_STALE = 900                # a call with no end row after 15 min: the office stops claiming it is running


# Every one of the agent's own instruments, as the office sees it. (verb, dest, doc, bring, tag, every):
#   verb   a plain line for the bubble and the ticker - the fact, never a joke
#   dest   where the work is really HANDED OVER, so a worker walks it; None = desk work, which still speaks
#          and still lands in the ticker, it just does not make anyone get up
#   doc    the paper left at dest; bring: what they carry back (a folder from FILES)
#   every  the floor-wide minimum seconds between two trips of this kind, because four parallel reads are one
#          errand to the filing cabinet, not four
# One missing from this table is desk work under its own name, so adding one to the agent can never break
# this screen - it just arrives unglamorous.
_FILES = ("cabinet", None, "folder", "CHAT")
CHAT_TOOL_ACT = {
    # the filing cabinet: anything that fetches filed material
    "read_file": ("reading a file", *_FILES, 40), "list_dir": ("listing a folder", *_FILES, 60),
    "grep": ("searching the files", *_FILES, 40), "find_symbol": ("looking up a symbol", *_FILES, 60),
    "repo_map": ("mapping the repo", *_FILES, 90), "hunt_search": ("querying the hunt index", *_FILES, 40),
    "hunt_brief": ("pulling the hunt brief", *_FILES, 60), "dedup": ("checking for a duplicate", *_FILES, 45),
    "playbook": ("reading a playbook", *_FILES, 60), "set_program": ("switching the program", *_FILES, 20),
    "pick_target": ("picking the next target", *_FILES, 20),
    # the mail room: a draft is printed and carried to the boss, exactly like the hunt loop's own
    "build_report": ("writing the report up", "printer", "report", None, "SHIP", 20),
    "draft_outgoing": ("drafting a reply", "printer", "report", None, "SHIP", 20),
    "ship_chain": ("running the ship gates", "boss", "report", None, "SHIP", 20),
    # ...and the ledger, whose paper is routed by the verdict itself (_chat_outcome_legs)
    "record_outcome": ("recording the verdict", "cabinet", "archive", None, "HUNT", 20),
    # the lab bench: a job handed to a worker bot
    "delegate": ("handing a job to a bot", "table", "order", None, "LAB", 25),
    "fan_out": ("fanning the job out to the bots", "table", "order", None, "LAB", 25),
    "claude_worker": ("handing a job to a worker", "table", "order", None, "LAB", 25),
    "second_opinion": ("asking for a second opinion", "table", "order", None, "LAB", 30),
    # desk work
    "write_file": ("writing a file", None, None, None, "CHAT", 0),
    "edit_file": ("editing a file", None, None, None, "CHAT", 0),
    "apply_patch": ("applying a patch", None, None, None, "CHAT", 0),
    "touch": ("touching a file", None, None, None, "CHAT", 0),
    "bash": ("running a command", None, None, None, "CHAT", 0),
    "git": ("running git", None, None, None, "CHAT", 0),
    "run_tests": ("running the tests", None, None, None, "CHAT", 0),
    "lint": ("linting", None, None, None, "CHAT", 0),
    "code_review": ("reviewing code", None, None, None, "CHAT", 0),
    "sast": ("running SAST over the source", None, None, None, "CHAT", 0),
    "malware": ("analysing a sample", None, None, None, "CHAT", 0),
    "decode": ("decoding something", None, None, None, "CHAT", 0),
    "js_mine": ("mining JavaScript", None, None, None, "HUNT", 0),
    "scan": ("running a scan", None, None, None, "HUNT", 0),
    "recon": ("running recon", None, None, None, "HUNT", 0),
    "http_request": ("sending a request", None, None, None, "HUNT", 0),
    "probe_matrix": ("running a probe matrix", None, None, None, "HUNT", 0),
    "race": ("racing a request", None, None, None, "HUNT", 0),
    "oast": ("checking the OAST callback", None, None, None, "HUNT", 0),
    "burp_panels": ("working the Burp panels", None, None, None, "HUNT", 0),
    "burp_check": ("checking Burp", None, None, None, "HUNT", 0),
    "browser": ("driving the browser", None, None, None, "HUNT", 0),
    "web_fetch": ("fetching a page", None, None, None, "CHAT", 0),
    "web_search": ("searching the web", None, None, None, "CHAT", 0),
    "repro_check": ("reproducing the draft", None, None, None, "SHIP", 0),
    "hunt_model": ("updating the target model", None, None, None, "HUNT", 0),
    "hunt_hypothesis": ("writing a hypothesis", None, None, None, "HUNT", 0),
    "hunt_edge": ("recording an edge", None, None, None, "HUNT", 0),
    "hunt_chains": ("searching for a chain", None, None, None, "HUNT", 0),
    "hypothesize": ("hypothesising", None, None, None, "HUNT", 0),
    "fingerprint": ("fingerprinting the stack", None, None, None, "HUNT", 0),
    "identities": ("provisioning an identity", None, None, None, "HUNT", 0),
    "desktop": ("working the desktop", None, None, None, "CHAT", 0),
    "gnoc": ("running a gnoc command", None, None, None, "CHAT", 0),
    "change_dir": ("changing the working repo", None, None, None, "CHAT", 0),
    "goal": ("setting the goal", None, None, None, "CHAT", 0),
    "tasks": ("working the task list", None, None, None, "CHAT", 0),
    "jobs": ("checking the jobs", None, None, None, "CHAT", 0),
    "bot": ("talking to the bots", None, None, None, "CHAT", 0),
    "learn": ("writing a lesson down", None, None, None, "CHAT", 0),
    "generate_image": ("generating an image", None, None, None, "CHAT", 0),
    "email_inbox": ("reading the inbox", None, None, None, "CHAT", 0),
    "discord_read": ("reading Discord", None, None, None, "CHAT", 0),
}


def chat_act(name):
    return CHAT_TOOL_ACT.get(name) or (f"running {name}", None, None, None, "CHAT", 0)


def _chat_said(arg):
    """The one argument the floor shows. In public mode it stays: the streamer blacks out paths, hosts and
    URLs in the rendered row (REDACT at the top of this file), and seeing WHICH KIND of work is the point."""
    return clip(re.sub(r"\s+", " ", str(arg or "")).strip(), 48)


def _chat_outcome_legs(arg):
    """A recorded outcome goes where the hunt loop's own verdicts go: a lead to the triage tray, a dead or
    unfired verdict onto the file."""
    v = str(arg or "").strip().upper()
    if v.startswith(("LEAD", "CRITICAL", "MEDIUM", "NEEDS")):
        return [("tray", "lead")], "HUNT"
    return [("cabinet", "archive")], "HUNT"


def _chat_act_row(r, quiet=False):
    """One activity row -> the floor. `quiet` replays the file's tail on the first poll so that attaching to
    the office mid-turn shows the call that is ALREADY running, without re-announcing an hour of history."""
    ev, phase, name = r.get("ev"), r.get("phase"), str(r.get("name") or "")
    arg = _chat_said(r.get("arg"))
    if ev == "turn":
        pid = r.get("pid")
        if phase == "start":
            text = "" if REDACT else str(r.get("text") or "")
            CHAT_TURNS[pid] = {"t0": r.get("ts") or time.time(), "program": r.get("program"), "text": text}
            if not quiet:  # what GreyNOC asked is the conversation, so the public floor only sees that one came in
                _bubble(CHAT_KEY, ("The user: " + clip(text, 60)) if text else "a new message from the user",
                        ttl=24, tag="CHAT")
        else:
            secs = r.get("secs") or 0
            CHAT_TURNS.pop(pid, None)
            CHAT_COUNT["turns"] += 1
            if not quiet:
                _bubble(CHAT_KEY, ("answered the user" if r.get("ok") else "turn ended early")
                        + f" after {_dur(secs)}", ttl=22, tag="CHAT")
        return
    if ev != "tool":
        return
    verb, dest, doc, bring, tag, every = chat_act(name)
    if phase == "start":
        cid = r.get("id")
        if cid:
            CHAT_LIVE[cid] = {"name": name, "arg": arg, "t0": r.get("ts") or time.time(), "pid": r.get("pid"),
                              "site": _names_site(r.get("arg"))}  # UNITS: a website call is PROD's job
        return
    if phase == "blocked":
        CHAT_COUNT["blocked"] += 1
        if not quiet:
            _bubble(CHAT_KEY, f"The user declined this: {verb}" + (f" ({arg})" if arg else ""), ttl=30,
                    alert=True, tag="CHAT")
        return
    # phase == "end"
    CHAT_LIVE.pop(r.get("id"), None)
    ok, secs = r.get("ok", True), r.get("secs") or 0
    CHAT_COUNT["calls"] += 1
    CHAT_COUNT["by"][name] = CHAT_COUNT["by"].get(name, 0) + 1
    if not ok:
        CHAT_COUNT["failed"] += 1
    CHAT_DONE.append((r.get("ts") or time.time(), name, arg, secs, ok))
    if quiet:
        return
    said = f"{verb}" + (f": {arg}" if arg else "") + (f" ({_dur(secs)})" if secs >= 3 else "")
    if not ok:
        _bubble(CHAT_KEY, f"{verb} failed" + (f": {arg}" if arg else ""), ttl=26, alert=True, tag="CHAT")
        return
    legs = [(dest, doc)] if dest else []
    if name == "record_outcome":
        legs, tag = _chat_outcome_legs(r.get("arg"))
    if legs and _every(f"chat:{name}", every or 20):
        handoff(CHAT_KEY, legs, said, tag=tag, bring=bring)   # handoff writes the ticker line itself
    else:
        _bubble(CHAT_KEY, said, ttl=20, tag=tag)


def d_chat_activity():
    """Tail the chat agent's activity log. Returns the live picture; the side effects (bubbles, ticker lines,
    paper trips) happen in _chat_act_row as each row is read."""
    try:
        size = os.path.getsize(CHAT_ACT_FILE)
    except OSError:
        CHAT_LIVE.clear()
        CHAT_TURNS.clear()
        return {"live": 0, "turn": None}
    off = _LAST_SEEN.get("chat_act_off")
    quiet = off is None or size < off          # first poll, or the agent trimmed the file under us
    if quiet:
        off = max(0, size - 65536)             # replay the tail silently: what is open NOW is what matters
        CHAT_LIVE.clear()
        CHAT_TURNS.clear()
    rows = []
    if size > off:
        with open(CHAT_ACT_FILE, "rb") as fh:
            fh.seek(off)
            chunk = fh.read(min(size - off, 400000))
        cut = chunk.rfind(b"\n") + 1
        _LAST_SEEN["chat_act_off"] = off + cut
        text = chunk[:cut].decode("utf-8", "replace").splitlines()
        if quiet and off > 0:
            text = text[1:]                    # a mid-file seek lands in the middle of a line; offset 0 does not
        for ln in text:
            try:
                rows.append(json.loads(ln))
            except ValueError:
                continue
    else:
        _LAST_SEEN["chat_act_off"] = size
    for r in rows:
        try:
            _chat_act_row(r, quiet=quiet)
        except Exception:  # one odd row must never stop the tail
            continue
    now = time.time()
    for cid in [c for c, v in CHAT_LIVE.items() if now - v["t0"] > _CHAT_STALE]:
        del CHAT_LIVE[cid]                     # no end row in 15 min: stop claiming it is still running
    for pid in [k for k, v in CHAT_TURNS.items() if now - v.get("t0", now) > 3 * _CHAT_STALE]:
        del CHAT_TURNS[pid]
    # A killed `gnoc chat` never writes its end rows, so the log alone would show a call running forever and
    # the NOW line would contradict a desk drawn STOPPED. The desk is the truth: no process, no work.
    row = next((r for r in (PM2_LAST or []) if r.get("name") == CHAT_KEY), None)
    if row and row.get("status") != "online":
        CHAT_LIVE.clear()
        CHAT_TURNS.clear()
    turn = min(CHAT_TURNS.values(), key=lambda v: v["t0"]) if CHAT_TURNS else None
    return {"live": len(CHAT_LIVE), "turn": dict(turn) if turn else None,
            "done": list(CHAT_DONE), "count": dict(CHAT_COUNT)}


def chat_now():
    """What the chat desk is doing right now as (verb, argument, started), or None. The LONGEST-running open
    call wins: that is the one a watcher is waiting on. Verb and argument stay apart because the desk overlay
    is clipped at its office wall, and the age has to survive that clip - it is the part worth reading."""
    live = sorted(CHAT_LIVE.values(), key=lambda v: v["t0"])
    if live:
        v = live[0]
        return chat_act(v["name"])[0], v["arg"], v["t0"]
    if CHAT_TURNS:
        return "writing the answer", "", min(v["t0"] for v in CHAT_TURNS.values())
    return None


SITE_DIR = os.path.expanduser("~/gnoc-site")
SITE_ENV = os.path.join(SITE_DIR, ".env")
SITE_WATCH = [0.0]  # epoch until which the website feed polls: the WEBSITE desk selected, or PROD on screen (UNITS);
# the App renews it every frame
SITE = {"hist": deque(maxlen=40), "next": {}, "mine": deque(maxlen=200)}  # rpm samples, next-poll epochs, and
# the epoch of every request this view itself sent (the site counts those too; the card says how many were ours)
PM2_LOGS = os.path.expanduser("~/.pm2/logs")


def _site_env():
    """PORT, PUBLIC_URL and the two ops tokens from the website's own .env (chmod 600, same user). The tokens
    only ever go to 127.0.0.1 in a request header; they are never stored on SITE, logged or drawn."""
    env = {}
    try:
        for ln in open(SITE_ENV):
            m = re.match(r"^\s*([A-Z_]+)\s*=\s*(.*)$", ln)
            if m:
                env[m.group(1)] = m.group(2).strip().strip("\"'")
    except OSError:
        pass
    return env


_SITE_MARKS = {}


def _names_site(arg):
    """True when a tool call's argument names the website: its public host, its loopback port or its directory.
    That is the whole test for "this call reads the site" (gnoc chat has no tool of its own for it)."""
    a = str(arg or "").lower()
    if not a:
        return False
    marks = _SITE_MARKS.get("v")
    if marks is None:
        env = _site_env()
        pub = re.sub(r"^https?://", "", env.get("PUBLIC_URL", "")).split("/")[0].lower()
        port = env.get("PORT") or "6969"
        marks = _SITE_MARKS["v"] = [m for m in (pub, f"127.0.0.1:{port}", f"localhost:{port}", SITE_DIR.lower(),
                                                os.path.basename(SITE_DIR).lower()) if m]
    return any(m in a for m in marks)


def _site_get(url, headers, timeout=4):
    t0 = time.time()
    SITE["mine"].append(t0)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2_000_000)
            code = r.status
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            return e.code, None, (time.time() - t0) * 1000
    try:
        return code, json.loads(body), (time.time() - t0) * 1000
    except ValueError:
        return code, None, (time.time() - t0) * 1000


def _log_tail_age(name):
    """(seconds since the pm2 log was written, its last non-empty line) for one website process's error log."""
    f = os.path.join(PM2_LOGS, f"{name}-error.log")
    try:
        age = time.time() - os.path.getmtime(f)
        with open(f, "rb") as fh:
            fh.seek(max(0, os.path.getsize(f) - 4096))
            last = [ln for ln in fh.read().decode(errors="replace").splitlines() if ln.strip()]
        ln = re.sub(r"^\S+:\s+(\S+Z\s+)?", "", last[-1]) if last else ""  # pm2's and cloudflared's timestamps
        # visitor and edge addresses (GreyWatch bans, cloudflared ip=) and anything token-shaped stay off screen
        ln = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b|\b[0-9a-fA-F:]*:[0-9a-fA-F:]{6,}\b|\b[0-9a-fA-F]{24,}\b", "▒", ln)
        return age, ln
    except OSError:
        return None, ""


def d_website():
    """your-site.example, read from the site's own endpoints while the WEBSITE desk is selected or the UNITS floor's
    PROD room is on screen (no network otherwise): /healthz with the monitoring token (version, uptime, ready), /api/server-status (build, mode),
    /api/dashboard/overview with the ops token (traffic, latency, realtime, process, store, GreyWatch, inbox and
    community COUNTS; the sessions, roster, IPs and messages in that payload are dropped on arrival), and the
    public edge through the Cloudflare tunnel. Each source keeps its own pace; an unselected desk costs nothing."""
    out = dict(SITE.get("last") or {})
    now = time.time()
    if REDACT or now > SITE_WATCH[0]:
        return out
    env = _site_env()
    port = env.get("PORT") or "6969"
    pub = env.get("PUBLIC_URL", "").rstrip("/")
    host = re.sub(r"^https?://", "", pub).split("/")[0]
    base = f"http://127.0.0.1:{port}"
    nxt = SITE["next"]
    # loopback as the tunnel delivers it: the public Host plus https from a trusted (loopback) proxy
    fwd = {"Host": host, "X-Forwarded-Proto": "https"} if host else {}
    if now >= nxt.get("health", 0):
        nxt["health"] = now + 15
        code, j, ms = _site_get(base + "/healthz", {"x-healthz-token": env.get("HEALTHZ_DETAIL_TOKEN", "")})
        out["health"] = {"code": code, "ok": bool(j and j.get("ok")), "ms": ms, "version": (j or {}).get("version"),
                         "uptime": (j or {}).get("uptime"), "reason": (j or {}).get("reason"), "ts": now}
        code, j, _ = _site_get(base + "/api/server-status", {}) if not env.get("OPS_ADMIN_TOKEN") else (0, None, 0)
        if j:
            out["status"] = {"build": j.get("build"), "mode": j.get("mode"), "pm2": j.get("pm2"),
                             "lastWipe": j.get("lastWipe")}
        out["logs"] = {n: _log_tail_age(n) for n in ("greynoc", "greynoc-tunnel", "greynoc-onion", "keepalive")}
    if env.get("OPS_ADMIN_TOKEN") and now >= nxt.get("ops", 0):
        # 10 s: this is the console's own heaviest read (rate limit 120/min); it also resets the console's
        # event-loop peak, so the peak shown here is the max since the previous read, same as the console's
        nxt["ops"] = now + 10
        code, j, _ = _site_get(base + "/api/dashboard/overview?n=1", dict(fwd, **{"x-ops-token": env["OPS_ADMIN_TOKEN"]}), 6)
        if j and j.get("ok"):
            m = j.get("metrics") or {}
            sec = j.get("security") or {}
            summ = sec.get("summary") or {}
            com = j.get("community") or {}
            out["ops"] = {"http": m.get("http") or {}, "realtime": m.get("realtime") or {},
                          "process": m.get("process") or {}, "store": m.get("store") or {},
                          "sec": {k: (summ.get(k) or {}) for k in ("last15m", "last1h", "last24h")},
                          "bans": (sec.get("stats") or {}).get("activeBans", 0),
                          "inbox": {k: (j.get("inbox") or {}).get(k, 0) for k in ("open", "emergencies")},
                          "online": com.get("onlineVisible"), "sockets": com.get("socketsConnected"),
                          "pro": (com.get("pro") or {}).get("total"),
                          "maintenance": bool((j.get("controls") or {}).get("maintenance")),
                          "alerts": [str(a.get("title") or a.get("message") or a)[:60] for a in (j.get("alerts") or [])][:3],
                          "ts": now}
            srv = j.get("server") or {}  # build and mode ride along here, so /api/server-status is not polled
            out["status"] = {"build": srv.get("build"), "mode": "maintenance" if out["ops"]["maintenance"] else "operational"}
            out["ops"]["mine_1m"] = sum(1 for e in SITE["mine"] if now - e <= 60)
            SITE["hist"].append(((m.get("http") or {}).get("oneMinute") or {}).get("requests", 0))
        else:
            out["ops"] = {"err": f"overview HTTP {code}", "ts": now}
    if pub and now >= nxt.get("edge", 0):
        nxt["edge"] = now + 30  # the real public path: Cloudflare edge -> tunnel -> this laptop
        code, j, ms = _site_get(pub + "/healthz", {"User-Agent": "gnoc-office"}, 8)
        out["edge"] = {"code": code, "ok": bool(j and j.get("ok")), "ms": ms, "ts": now}
    SITE["last"] = out
    return out


def d_rescue():
    try:
        txt = open(os.path.join(HUNTLOOP, "RESCUE-BOARD.md"), encoding="utf-8").read()
    except OSError:
        return {}
    out = {}
    for state, n in re.findall(r"^\|\s*([A-Z][A-Z-]+)(?:\([^)]*\))?\s*\|\s*(\d+)\s*\|", txt, re.M):
        out[state] = out.get(state, 0) + int(n)
    RESCUE.clear()
    RESCUE.update(out)
    try:
        RESCUE_AGE[0] = time.time() - os.path.getmtime(os.path.join(HUNTLOOP, "RESCUE-BOARD.md"))
    except OSError:
        RESCUE_AGE[0] = None
    return out


# ---------- the LAB: leads under investigation, escalation rungs, tests being run ----------
# Source of truth is pipeline-sweep's rescue ledger: every parked lead / held draft it dispatches gets a real
# `claude --agent <hunter>` worker whose pid, rung ("move") and start time are written to the item's `dispatch`.
# While that pid is alive the lead IS being investigated; its child processes are the tests being run (each new
# shell is one tool run, a live curl/python is the test in flight); the outcomes.jsonl row the worker appends
# under lane rescue-<id> is its verdict. Nothing here is invented: no pid, no investigator.
LEDGER_FILE = os.path.join(HUNTLOOP, "rescue-ledger.json")
RUNGS = {1: "same defect, higher asset", 2: "what it unlocks", 3: "paired write", 4: "partner bug",
         5: "missing context"}
RUNG_MARK = {"TRIED-NEG": ("×", 203), "TRIED-POS": ("✓", 78), "NEEDS": ("!", 212), "NA": ("-", 241),
             "UNTRIED": ("·", 246)}  # colors as numbers: the C_* palette is defined further down
LAB = {}            # id -> live investigation (see d_lab)
LAB_DONE = deque(maxlen=8)  # finished investigations waiting for their walk-out: {"id", "verdict", "dest", ...}
LAB_HIST = deque(maxlen=6)  # the last finished ones, newest last, for the rail
LAB_STATS = {"today": 0}    # rescue dispatches started today
_LAB_PIDS = {}      # id -> {"base": pids present at first sight, "seen": shells seen since, "first": epoch}
_TEST_COMMS = ("curl", "python3", "python", "node", "httpx", "nuclei", "ffuf", "wget", "openssl", "nc", "ncat",
               "chromium", "chrome", "playwright", "go", "ruby", "perl", "dig", "nmap", "sqlmap")


def _proc_tree():
    kids, comm = {}, {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            st = open(f"/proc/{d}/stat").read()
        except OSError:
            continue
        r = st.rfind(")")
        pid, ppid = int(d), int(st[r + 2:].split()[1])
        comm[pid] = st[st.find("(") + 1:r]
        kids.setdefault(ppid, []).append(pid)
    return kids, comm


def _descendants(pid, kids):
    out, todo = [], list(kids.get(pid, []))
    while todo:
        p = todo.pop()
        out.append(p)
        todo.extend(kids.get(p, []))
    return out


def _cmd_summary(pid, comm):
    """The test in flight, short: the program plus the first host it names (`curl api.example.com`)."""
    try:
        argv = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
        argv = [a.decode("utf-8", "replace") for a in argv if a]
    except OSError:
        return comm
    if REDACT:
        return comm
    m = re.search(r"https?://([^/\s'\"]+)", " ".join(argv))
    if m:
        return f"{comm} {m.group(1)}"
    script = next((os.path.basename(a) for a in argv[1:] if a.endswith((".py", ".sh", ".js"))), "")
    return f"{comm} {script}".strip()


def _claude_pid_alive(pid):
    try:
        return b"claude" in open(f"/proc/{int(pid)}/cmdline", "rb").read()  # a recycled pid is not our worker
    except (OSError, ValueError, TypeError):
        return False


def _lab_name(iid):
    """gatewayco/LEAD-konnect-cors-credentials-2026-10-04.md -> gatewayco/konnect-cors-credentials"""
    body = iid.split(":", 1)[-1]
    prog, _, rest = body.partition("/")
    rest = re.sub(r"\.md$", "", rest)
    rest = re.sub(r"^(LEAD|CANDIDATE|RESCUE-LADDER)-", "", rest)
    rest = re.sub(r"-20\d\d-\d\d-\d\d.*$", "", rest)
    return f"{prog}/{rest}" if rest else prog


def _verdict_dest(verdict):
    v = str(verdict or "").upper()
    if v.startswith(("CRITICAL", "MEDIUM", "FINDING", "PROMOTE", "TRIED-POS")):
        return "boss", "hit"
    if v.startswith("NEEDS"):
        return "boss", "lead"
    if v.startswith("DEAD"):
        return "shredder", "junk"
    if v.startswith("UNFIRED"):
        return "cabinet", "archive"
    return "tray", "lead"  # LEAD / TRIED-NEG: back in the tray for the next rung


def d_lab():
    """Live rescue workers from the ledger + their process trees + their recorded verdicts."""
    if BOTS_ONLY:   # standalone GreyNOC build (2026-10-24): the LAB seats no external rescue processes; PROOFS board only
        return {}
    led = jload(LEDGER_FILE, {})
    outs = jsonl_tail(os.path.join(HUNTLOOP, "outcomes.jsonl"), 40)
    kids, comm = _proc_tree()
    live = {}
    for iid, row in led.items():
        if iid == "_meta" or not isinstance(row, dict):
            continue
        d = row.get("dispatch") or {}
        if not d.get("pid") or d.get("reaped") or not _claude_pid_alive(d["pid"]):
            continue
        moves = row.get("moves") or {}
        mv = str(d.get("move") or "")
        cur = int(mv) if mv.isdigit() else None
        if row.get("kind") == "chain":
            n = int(row.get("edges") or 1)
            ladder = [(moves.get(str(k)) or {}).get("status") or "UNTRIED" for k in range(1, n + 1)]
            m = re.match(r"edge-(\d+)", mv)
            cur = int(m.group(1)) if m else 1
        else:
            ladder = [(moves.get(str(k)) or {}).get("declared") or (moves.get(str(k)) or {}).get("status") or
                      "UNTRIED" for k in range(1, 6)]
        live[iid] = {"id": iid, "pid": int(d["pid"]), "prog": row.get("program") or "?", "name": _lab_name(iid),
                     "hunter": d.get("hunter") or row.get("hunter") or "hunter", "move": mv, "cur": cur,
                     "kind": row.get("kind"), "ladder": ladder, "ts": d.get("ts"), "t0": _ts_epoch(d.get("ts"))}
    for prog, ent in ((led.get("_meta") or {}).get("chain_map") or {}).items():
        if ent.get("pid") and not ent.get("reaped") and _claude_pid_alive(ent["pid"]):
            iid = f"chainmap:{prog}"
            live[iid] = {"id": iid, "pid": int(ent["pid"]), "prog": prog, "name": f"{prog} chain map",
                         "hunter": "chain-mapper", "move": "map", "cur": None, "kind": "chainmap", "ladder": [],
                         "ts": ent.get("ts"), "t0": _ts_epoch(ent.get("ts"))}
    now = time.time()
    for iid, inv in live.items():
        desc = _descendants(inv["pid"], kids)
        st = _LAB_PIDS.get(iid)
        if st is None or st.get("pid") != inv["pid"]:
            st = _LAB_PIDS[iid] = {"pid": inv["pid"], "base": set(desc), "seen": set(), "first": now,
                                   "last_cmd": None, "last_cmd_t": 0}
        for p in desc:
            if p not in st["base"] and (comm.get(p) in ("bash", "sh", "zsh") or comm.get(p) in _TEST_COMMS):
                st["seen"].add(p)  # a tool run: its shell, or the test itself when bash exec'd straight into it
        tests = [p for p in desc if p not in st["base"] and comm.get(p) in _TEST_COMMS]
        if tests:
            st["last_cmd"], st["last_cmd_t"] = _cmd_summary(max(tests), comm[max(tests)]), now
        inv["runs"] = len(st["seen"])
        inv["testing"] = st["last_cmd"] if tests else None
        inv["last_cmd"] = st["last_cmd"]
        inv["last_cmd_ago"] = now - st["last_cmd_t"] if st["last_cmd_t"] else None
        rows = [r for r in outs if r.get("lane") == f"rescue-{iid}" and str(r.get("ts")) >= str(inv["ts"] or "")]
        inv["verdict"] = rows[-1] if rows else None
    prev = _LAST_SEEN.get("lab")
    if prev is not None:
        for iid, inv in live.items():
            if iid not in prev:
                rung = f"rung {inv['cur']} {RUNGS.get(inv['cur'], '')}".strip() if inv["cur"] and inv["kind"] != "chain" \
                    else inv["move"] or "ladder audit"
                what = "a parked lead" if REDACT else inv["name"]
                log_event("LAB", f"{inv['hunter']} picked up {what}: {rung}", C_GOLD, safe=REDACT)
                handoff("pipeline-sweep", [("tray", None)], f"lead to the lab: {what}", bring="lead", tag="LAB")
            elif inv["verdict"] and not prev[iid].get("verdict"):
                v = inv["verdict"]
                log_event("LAB", f"{inv['hunter']} recorded {str(v.get('verdict', '?')).split()[0]} on "
                                 f"{'a parked lead' if REDACT else inv['name']} ({v.get('probes', '?')} probes"
                                 f"{', burst' if v.get('burst') else ''})", C_GOLD, safe=REDACT)
        for iid, old in prev.items():
            if iid in live:
                continue
            # the worker exited: re-read its verdict (it may have landed between polls) and walk the result out
            rows = [r for r in outs if r.get("lane") == f"rescue-{iid}" and str(r.get("ts")) >= str(old.get("ts") or "")]
            v = rows[-1] if rows else old.get("verdict")
            verdict = str(v.get("verdict") or "?").split()[0].strip(":,") if v else "no verdict"
            dest, doc = _verdict_dest(verdict if v else "UNFIRED")
            done = dict(old, verdict=verdict, probes=(v or {}).get("probes"), burst=(v or {}).get("burst"),
                        dest=dest, doc=doc, t_end=now)
            with LOCK:
                LAB_DONE.append(done)
                LAB_HIST.append(done)
            log_event("LAB", f"{old['hunter']} done with {'a parked lead' if REDACT else old['name']}: {verdict}"
                             f" -> {PLACE.get(dest, dest)}", C_BAD if dest == "boss" else C_GOLD, safe=REDACT)
            if dest == "boss":
                toast(f"LAB  {verdict}  {'' if REDACT else old['name']}".strip(), C_BAD, 10)
            _LAB_PIDS.pop(iid, None)
    elif not LAB_HIST:  # first poll: seed the rail's history with the last few recorded rescue verdicts
        last = {r["lane"]: r for r in outs if str(r.get("lane", "")).startswith("rescue-")}  # newest row per lane
        for r in sorted(last.values(), key=lambda r: str(r.get("ts")))[-3:]:
            iid = r["lane"][len("rescue-"):]
            LAB_HIST.append({"id": iid, "name": _lab_name(iid), "hunter": "", "verdict":
                             str(r.get("verdict", "?")).split()[0], "probes": r.get("probes"), "burst": r.get("burst"),
                             "t_end": _ts_epoch(r.get("ts")) or 0, "dest": _verdict_dest(r.get("verdict"))[0]})
    _LAST_SEEN["lab"] = {k: dict(v) for k, v in live.items()}
    today = datetime.now().astimezone().date()
    LAB_STATS["today"] = sum(1 for ts in ((led.get("_meta") or {}).get("dispatch_log") or [])
                             if _local_day(ts)[0] == today)  # rescue workers started today (pipeline-sweep's log)
    with LOCK:
        LAB.clear()
        LAB.update(live)
    return {"n": len(live)}


_START_RE = re.compile(r"(?:brain started ([\w-]+)|auto-hunt started) pid \d+ ([\w.-]+)")  # "prog: /path" in the real log
_DONE_RE = re.compile(r"auto-hunt done: (\S+): fired (\d+), hits (\d+), leads (\d+)")
_ACT_RE = re.compile(r"^(escalate|osint|follow_up_lane|learn|draft) done")
_INBOX_RE = re.compile(r"^- \[([^\]]+)\] \*\*([^*]+)\*\*\s*(.*)$")


def _line_epoch(ln):
    """orch.log lines start with [ISO-8601 UTC]: the event's own time (now, if a line has no stamp)."""
    m = re.match(r"\[([^\]]+)\]", ln)
    return (_ts_epoch(m.group(1)) if m else None) or time.time()


def _hunt_line(ln, hd, quiet=False):
    """One orch.log line -> HUNT_NOW bookkeeping and (unless priming) the trip it stands for."""
    body = re.sub(r"^\[.*?\]\s*", "", ln)
    m = _START_RE.search(body)
    if m:
        action, prog = m.group(1) or "auto", m.group(2)
        if action != "auto":
            BRAIN_THINK.clear()
            BRAIN_THINK.update(action=action, prog=prog, t=time.time())
        if action == "auto":
            HUNT_NOW.clear()
            HUNT_NOW.update(prog=prog, hosts=0, fired=0, hits=0, leads=0, last=None, t=_line_epoch(ln))
        if UNITS:  # the work order walks only once a reading names the unit that took it (unit_job_open)
            pm = re.search(r"\bpid (\d+)\b", body)
            unit_job_open(action, prog, int(pm.group(1)) if pm else None, _line_epoch(ln), quiet)
        elif not quiet and _every(f"order:{action}:{prog}", 30):
            handoff("orch-bot", [(f"desk:{hd}", "order")], f"work order: {action} {prog}")
        return
    m = _DONE_RE.search(body)
    if m:
        host, fired, hits, leads = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        if HUNT_NOW:
            HUNT_NOW.update(hosts=HUNT_NOW.get("hosts", 0) + 1, fired=HUNT_NOW.get("fired", 0) + fired,
                            hits=HUNT_NOW.get("hits", 0) + hits, leads=HUNT_NOW.get("leads", 0) + leads,
                            last=host, t=_line_epoch(ln))
        if quiet:
            return
        if UNITS:  # the unit that holds the hunt walks the sheet back; unattributed, it waits in the out-tray as ?
            hd = unit_job_result("auto", f"swept {host}: fired {fired}, hits {hits}, leads {leads}")
        else:
            handoff(hd, [("desk:orch-bot", "result")], f"swept {host}: fired {fired}, hits {hits}, leads {leads}")
        if leads and hd:
            handoff(hd, [("tray", "lead")], f"{leads} lead{'s' * (leads != 1)} from {host}")
        if hits:
            if hd:
                handoff(hd, [("boss", "hit")], f"unverified signal on {host} ({hits}), auto-escalate tests it next",
                        color=C_BAD)
            toast(f"SIGNAL (unverified)  {host}", C_BAD, 10)
        return
    if quiet:
        m = _ACT_RE.search(body)
        if m and BRAIN_THINK.get("action") == m.group(1):
            BRAIN_THINK.clear()
        if m and UNITS:
            unit_job_result(m.group(1), None, close=True, quiet=True)
        return
    m = _ACT_RE.search(body)
    if m and BRAIN_THINK.get("action") == m.group(1):
        BRAIN_THINK.clear()
    if m and UNITS:
        rest = clip(body[m.end():].strip(" :,-"), 40)
        unit_job_result(m.group(1), f"{m.group(1)} result" + (f": {rest}" if rest else ""), close=True)
    elif m:
        handoff(hd, [("desk:orch-bot", "result")], f"{m.group(1)} result")
    elif body.startswith("auto-escalate:") and _every("escalate", 20):  # a hit was just pushed up the ladder
        if UNITS:
            unit_job_result("auto", f"escalating a hit: {clip(body[14:].strip(), 44)}", doc="hit")
        else:
            handoff(hd, [("desk:orch-bot", "hit")], f"escalating a hit: {clip(body[14:].strip(), 44)}", tag="LAB")
    elif body.startswith("auto-target pick started") and _every("pick", 90):
        handoff("orch-bot", [("cabinet", None)], "pulling target folders to pick the next program", bring="folder")


def d_paperwork():
    """New orch.log / outcomes / INBOX lines since the last poll -> trips. The first poll primes silently, but
    replays the recent orch.log so the whiteboard knows the hunt in progress."""
    hd = hunter_desk()
    try:
        lines = [ln for ln in open(os.path.join(ORCH, "orch.log")).read().splitlines()[-60:] if ln.strip()]
    except OSError:
        lines = []
    prev = _LAST_SEEN.get("papers")
    if lines:
        if prev is None:
            for ln in lines:
                _hunt_line(ln, hd, quiet=True)
        else:
            idx = max((i for i, ln in enumerate(lines) if ln == prev), default=None)
            for ln in (lines[idx + 1:] if idx is not None else lines[-5:]):
                _hunt_line(ln, hd)
        _LAST_SEEN["papers"] = lines[-1]
    cur = jload(os.path.join(ORCH, "state.json"), {}).get("current") or {}
    HUNT_NOW["live"] = bool(HUNT_NOW.get("prog")) and cur.get("program") == HUNT_NOW.get("prog")

    rows = jsonl_tail(os.path.join(HUNTLOOP, "outcomes.jsonl"), 5)
    last = rows[-1].get("ts") if rows else None
    if "outcome" in _LAST_SEEN and last and last != _LAST_SEEN["outcome"]:
        new = [r for r in rows if str(r.get("ts")) > str(_LAST_SEEN["outcome"])][-2:]
        for r in new:
            v = str(r.get("verdict", "?")).split()[0].strip(":,")
            what = f"{r.get('target', '?')} {r.get('vector', '')}".strip()
            if v.startswith(("LEAD", "CRITICAL", "MEDIUM", "FINDING")) and _every("out-lead", 20):
                handoff("orch-bot", [("tray", "lead")], f"{v}: {'a lane verdict' if REDACT else clip(what, 50)}", tag="HUNT")
            elif v.startswith(("DEAD", "UNFIRED")) and _every("out-dead", 30):
                handoff("orch-bot", [("cabinet", "archive")], f"filing {v}: {'a lane verdict' if REDACT else clip(what, 50)}",
                        tag="HUNT")
    _LAST_SEEN["outcome"] = last

    try:
        with open(os.path.join(ORCH, "INBOX.md"), "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 6000))
            tail = fh.read().decode("utf-8", "replace").splitlines()[1:]
    except OSError:
        tail = []
    items = [m.groups() for m in (_INBOX_RE.match(ln) for ln in tail) if m]
    seen = _LAST_SEEN.get("inbox_ts")
    if seen is not None:
        for ts, kind, text in [it for it in items if it[0] > seen][-3:]:
            kind = kind.strip()
            if REDACT:
                text = "details redacted"
            if kind in ("EXPLOIT-CANDIDATE", "AUTO-HIT", "HIT") and _every(f"ib:{kind}", 20):
                handoff(hd, [("boss", "hit")], f"{kind}: {clip(text, 50)}", color=C_BAD)
            elif kind == "RESCUE-PROMOTE" and _every("ib:promote", 20):
                handoff("pipeline-sweep", [("cabinet", None), ("boss", "report")], f"rescued lead promoted: {clip(text, 44)}",
                        tag="SHIP")
            elif kind == "RESCUE-NEEDS" and _every("ib:needs", 30):
                handoff("pipeline-sweep", [("cabinet", None), ("boss", "lead")], f"parked lead needs you: {clip(text, 44)}")
            elif kind.startswith("RESCUE-") and _every("ib:rescue", 45):
                handoff("pipeline-sweep", [("cabinet", "archive")], f"{kind.lower()}: {clip(text, 44)}")
    if items:
        _LAST_SEEN["inbox_ts"] = max(seen or "", items[-1][0])


def _ship_title(row):
    """A ships.jsonl row doesn't always carry a title, so fall back to the slug, then the report's own
    directory name - never invent a name, just find the closest real one on disk."""
    t = row.get("title") or row.get("slug")
    if t:
        return str(t)
    path = row.get("path") or ""
    base = os.path.basename(os.path.dirname(path)) if path else ""
    return base or "a report"


def start_party(reason, secs=40):
    global PARTY_UNTIL, PARTY_REASON
    PARTY_UNTIL = time.time() + secs
    PARTY_REASON = reason


def party_active():
    return time.time() < PARTY_UNTIL


def log_event(tag, text, color, safe=False):
    with LOCK:
        EVENTS.append((time.time(), tag, re.sub(r"\s+", " ", str(text)).strip(), color))


def toast(text, color, secs=5):
    if REDACT and str(text).startswith("NEW REPORT"):
        text = "NEW REPORT"  # a draft's title is the unfiled finding itself
    with LOCK:
        TOASTS.append({"text": text, "color": color, "until": time.time() + secs})
        del TOASTS[:-4]


def _bubble(key, text, ttl=28, flavor=False, dest=None, alert=False, tag=None):
    """dest: where the worker walks to act on it ('cabinet' default, 'shredder'); alert: drawn red.
    Every non-flavor bubble is also a ticker line - the ticker is the record of what this screen saw."""
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return
    now = time.time()
    with LOCK:
        recent = [t for t in _BUBBLE_TIMES if now - t < 10]
        prev = BUBBLES.get(key)
        limited = not alert and ((prev and now - prev["created"] < 12) or len(recent) >= 4)
    if limited:  # the ticker still records it; the floor just does not get another balloon this second
        if not flavor:
            log_event(tag or KEY_TAG.get(key, "PM2"), text, TAG_COLOR.get(tag or KEY_TAG.get(key), C_WARN), safe=REDACT)
        return
    _BUBBLE_TIMES.append(now)

    with LOCK:
        BUBBLES[key] = {"text": text, "until": time.time() + ttl, "created": time.time(), "flavor": flavor,
                        "dest": dest, "alert": alert}
    if not flavor:
        log_event(tag or KEY_TAG.get(key, "PM2"), text, C_BAD if alert else TAG_COLOR.get(tag or KEY_TAG.get(key), C_WARN),
                  safe=REDACT)


def d_events():
    """Reads the SAME logs the other collectors read, but only to notice something CHANGED since the last
    poll, and turns that change into a bubble + a ticker line. The first observation of each source primes
    silently (so opening the office does not throw a party for a report shipped hours ago)."""
    global WHITEBOARD_FLASH_UNTIL, RESTART_FLASH_UNTIL, SHRED_UNTIL, LEAD_ALERT_UNTIL, PRINT_UNTIL
    rows = jsonl_tail(os.path.join(ORCH, "brain.jsonl"), 1)
    if rows:
        r = rows[0]
        sig = (r.get("ts"), r.get("action"), r.get("status"))
        if _LAST_SEEN.get("brain") != sig:
            first_brain = "brain" not in _LAST_SEEN  # the first poll primes: no toss for an old decision
            _LAST_SEEN["brain"] = sig
            reason = str(r.get("reason") or r.get("detail") or "").strip()
            verb = BRAIN_PLAIN.get(r.get("status"), f"{r.get('action') or 'decision'}:")
            if r.get("status") in ("rejected", "fallback", "error") and not first_brain:
                BALLS.append(time.time())
            if not UNITS and not first_brain and r.get("secs") and not str(jload(os.path.join(ORCH, "models.json"), {})
                                                            .get("brain") or "").endswith("@desktop"):
                LAPTOP_CALLS.append(r)  # a desktop brain call already rides the uplink as a proxied request
            if not first_brain:  # the first poll primes: a decision from before the office opened is not news
                _bubble("orch-bot", f"{verb} {reason}".strip() or "...", ttl=32)

    ships = d_ships_today()
    sig = len(ships)
    if _LAST_SEEN.get("ships") != sig:
        first = "ships" not in _LAST_SEEN
        _LAST_SEEN["ships"] = sig
        if ships and not first:
            title = _ship_title(ships[-1])
            kind = ship_kind(ships[-1])
            what = "a report" if REDACT else title
            if kind == "submission":  # a real ship: filed on a platform. The only thing (with an H1 accept) that parties
                _bubble("ship-desk", f"filed: {what}", ttl=45)
                handoff("control-panel", [("printer", None), ("boss", "report")], f"filed: {clip(title, 50)}",
                        tag="SHIP", color=C_GOOD)
                start_party("a report was filed" if REDACT else f"{title} was filed")
                toast(f"FILED  {title}", C_GOOD, 12)
                WHITEBOARD_FLASH_UNTIL = PRINT_UNTIL = time.time() + 45
            elif kind == "draft":  # written, not filed: the printer prints it and it waits on the boss's desk
                _bubble("ship-desk", f"draft written, waiting for approval: {what}", ttl=45)
                handoff("control-panel", [("printer", None), ("boss", "report")], f"draft for approval: {clip(title, 50)}",
                        tag="SHIP", color=C_GOOD)
                toast(f"DRAFT WRITTEN (not filed)  {title}", C_GOOD, 10)
                WHITEBOARD_FLASH_UNTIL = PRINT_UNTIL = time.time() + 30
            elif kind == "closure":
                log_event("SHIP", f"closure recorded: {what}", C_MUTED, safe=REDACT)

    h1_events = jload(H1_CACHE_FILE, {"events": []}).get("events") or []
    sig = h1_events[0].get("ts") if h1_events else None
    if _LAST_SEEN.get("h1") != sig:
        first = "h1" not in _LAST_SEEN
        _LAST_SEEN["h1"] = sig
        if sig and not first:
            ev = h1_events[0]
            preview = ev.get("message") or f"state changed to {ev.get('state', '?')}"
            title = "a report" if REDACT else ev.get("title", "?")  # public view: a reply happened, never its words
            _bubble("h1-desk", f'new reply on "{title}"' + ("" if REDACT else f": {preview}"), ttl=50)
            toast(f"H1 REPLY  {title}", C_PINK, 12)
            if str(ev.get("state", "")).lower() in ("triaged", "resolved", "bounty", "accepted"):
                start_party(f"H1 accepted: {'a report' if REDACT else ev.get('title', '?')}")
            WHITEBOARD_FLASH_UNTIL = time.time() + 50

    try:
        lines = [ln for ln in open(os.path.join(ORCH, "orch.log")).read().splitlines()[-8:] if ln.strip()]
    except OSError:
        lines = []
    if lines and _LAST_SEEN.get("hunt") != lines[-1]:
        primed = "hunt" in _LAST_SEEN
        _LAST_SEEN["hunt"] = lines[-1]
        if primed:
            _bubble("hunt-floor", re.sub(r"^\[.*?\]\s*", "", lines[-1]), ttl=28)

    for p in PM2_LAST or d_pm2():  # the pm2 job's rows: a second jlist here also double-sampled CPU_HIST
        key = f"restart:{p['name']}"
        prev = _LAST_SEEN.get(key)
        if prev is not None and p["restarts"] > prev:
            _bubble(p["name"], f"restarted by pm2 (restart #{p['restarts']})", ttl=30, tag="PM2")
            log_event("PM2", f"{p['name']} restarted (restart #{p['restarts']})", C_WARN, safe=True)
            RESTART_FLASH_UNTIL = time.time() + 6
        _LAST_SEEN[key] = p["restarts"]

    o = oss_snapshot()
    lr = o.get("last_run")
    if lr and _LAST_SEEN.get("oss_run") != lr[0]:
        first = "oss_run" not in _LAST_SEEN
        _LAST_SEEN["oss_run"] = lr[0]
        _id, prog, job, rc, audit, leads = lr
        if not first:
            fail = str(audit or "").startswith("AUDIT FAIL")
            _bubble("oss-bot", f"{prog} {job} done: {audit or 'rc ' + str(rc)}" + (f", +{leads} leads" if leads else ""),
                    ttl=26, alert=fail, dest="stay" if leads else None)
            if leads:
                handoff("oss-bot", [("tray", "lead")], f"{leads} new lead{'s' * (leads != 1)} from {prog} {job}", tag="OSS")
            if fail:
                LEAD_ALERT_UNTIL = time.time() + 60
    tri = o.get("triage") or {}
    if tri.get("ts") and _LAST_SEEN.get("oss_triage") != tri["ts"]:
        first = "oss_triage" not in _LAST_SEEN
        _LAST_SEEN["oss_triage"] = tri["ts"]
        if not first and tri.get("culled"):
            top = max((tri.get("by_reason") or {"junk": 0}).items(), key=lambda kv: kv[1])[0]
            _bubble("orch-bot", f"shredding {tri['culled']} junk leads (mostly {top}), {tri.get('open_after')} left",
                    ttl=30, dest="stay", tag="OSS")
            handoff("orch-bot", [("tray", None), ("shredder", "junk")], f"{tri['culled']} junk leads to the shredder",
                    tag="OSS")
            SHRED_UNTIL = time.time() + 25
    rv = o.get("review") or {}
    sig = (rv.get("n"), rv.get("rule"), len(rv.get("live") or []))
    if _LAST_SEEN.get("oss_review") != sig:
        prev = _LAST_SEEN.get("oss_review")
        _LAST_SEEN["oss_review"] = sig
        if prev is not None:
            new_live = (rv.get("live") or [])[prev[2]:] if sig[2] > prev[2] else []
            if new_live:
                _bubble("orch-bot", f"possibly LIVE key: {new_live[-1].get('file', '?')[-60:]}", ttl=60, alert=True,
                        tag="OSS")
                toast("POSSIBLY LIVE KEY in oss-bot review", C_BAD, 15)
                LEAD_ALERT_UNTIL = time.time() + 120
                WHITEBOARD_FLASH_UNTIL = time.time() + 60
            elif (sig[1] or 0) > (prev[1] or 0):
                _bubble("orch-bot", f"reviewed {sig[1] - prev[1]} secrets: public by design, shredding them",
                        ttl=28, dest="stay", tag="OSS")
                handoff("orch-bot", [("tray", None), ("shredder", "junk")], f"{sig[1] - prev[1]} public-by-design secrets",
                        tag="OSS")
                SHRED_UNTIL = time.time() + 20
    d_paperwork()
    stop = os.path.exists(STOP_FILE)
    if _LAST_SEEN.get("stop") is not None and stop != _LAST_SEEN["stop"]:
        log_event("YOU", "STOP set: hunting paused, the floor does chores" if stop else "STOP cleared: back to work",
                  C_BAD if stop else C_GOOD)
        toast("HUNT PAUSED" if stop else "HUNT RESUMED", C_BAD if stop else C_GOOD, 8)
    _LAST_SEEN["stop"] = stop
    if BRAIN_THINK and time.time() - BRAIN_THINK.get("t", 0) > 900:
        BRAIN_THINK.clear()  # no done line in 15 min: stop claiming it is still running
    _LAST_SEEN["oss_open"] = o.get("open")
    _LAST_SEEN["oss_last"] = lr
    _LAST_SEEN["oss_triage_row"] = tri

    with LOCK:
        for k in [k for k, v in BUBBLES.items() if time.time() > v["until"]]:
            del BUBBLES[k]
        return dict(BUBBLES)


# ---------- UNITS: the processing units wired to the harness, and the jobs the manager hands them ----------
# The workers on this floor are the hardware that does GreyNOC's work: each laptop GPU (sysfs, amdgpu), the laptop's
# CPU cores (/proc/stat), the desktop GPU behind the UPLINK proxy and the USB phone. orch-bot is the manager. A job
# walks from the manager to a unit only when a real reading says THAT unit took it, and walks back only when a real
# row says it finished. A job nobody can be shown to have taken waits in the manager's out-tray marked ?, and the
# ticker says so. Which reading names the unit, strongest first:
#   desktop  the proxy opened a call for the hunter (caller "hunter" = an auto-hunt), or a proxy row's pid is inside
#            the job's own process tree (desktop-inflight.json, desktop-traffic.jsonl)
#   shell    a curl / httpx / nuclei / ffuf ... descendant of the job's pid: the CPU desk that holds the core it last
#            ran on (/proc/<pid>/stat field 39)
#   laptop   the laptop Ollama shows a call land (a model appears in /api/ps, or its expires_at moves on) for a model
#            the job's role runs (models.json): the GPU whose VRAM in use covers that model's size_vram
#   phone    a brain.jsonl row that names host phone; split-llm busy (/slots) with the phone in the split: the PHONE
#            and the one laptop GPU busy at that moment share the paper
UNIT_ROOMS = ("MANAGER", "THE FLOOR", "PROD", "SERVER ROOM")
PROD_PROCS = ("greynoc", "greynoc-tunnel", "greynoc-onion", "keepalive", "office-stream")  # PROD's consoles, not people
DESKTOP_KEY = "desktop"   # the hosts.json machine the UPLINK proxy forwards to: its in-flight file is that desk's load
OLLAMA_LAPTOP = "127.0.0.1:11434"  # ollama-oc (pm2), the laptop Ollama
UNIT_ATTR_SECS = 25       # how long a new job waits for the reading that names its unit before it is unattributed
MANAGER_CALLERS = ("orch-bot", "hunter")  # proxy caller names that are the manager, or a job the manager launched
# the probe programs (no interpreters: a python child is as likely the job's own model client as a probe)
_PROBE_COMMS = tuple(c for c in _TEST_COMMS if c not in ("python3", "python", "node", "chromium", "chrome",
                                                          "playwright", "go", "ruby", "perl"))
UNIT_GPU = {}        # key -> {"dev", "pci", "kind", "busy", "used", "total", "up"}: sysfs, re-read every poll
_GPU_CARDS = {}      # sysfs device dir -> key, fixed at first sight so a card that vanishes keeps its desk (stopped)
UNIT_CPU = {"groups": [], "busy": {}, "load": None}  # groups: [(key, [cpu ids], label)]; busy: cpu id -> % last poll
_CPU_PREV = {}       # cpu id -> (busy ticks, total ticks) at the previous /proc/stat read
UNIT_LABEL = {}      # unit key -> the name on its desk
UJOBS = {}           # job id -> {"what", "action", "prog", "pid", "t0", "seen", "unit", "units", "closed", ...}
UNIT_DUTY = {}       # unit key -> (text, until): work it is doing that no manager job owns (a chat call, a probe)
UNIT_VISIT = {}      # unit key -> {"cid", "label", "t0"}: the website-analysis call that unit is serving in PROD;
#                      a STUDIO compile adds "src": "video", "carry" / "bring" (the paper each way) and "pid"
UNATTRIBUTED = deque(maxlen=8)  # (epoch, label): papers in the manager's out-tray, marked ?
UNIT_SENT = deque(maxlen=8)     # (epoch, unit, what): the manager's last attributed dispatches, for its board
UNIT_COUNT = {"jobs": 0, "attributed": 0, "unattributed": 0}  # since this view attached (the logs are tails)
UPLINK_RATE = deque(maxlen=2000)  # (epoch, caller) per proxied request, for PROD's requests/min by caller
SPLIT_PAPERS = deque(maxlen=4)  # (epoch, [unit keys]): one split-llm call, one paper on each desk it spans
_U = {}              # the units poller's own memory (signatures, seen ids, last reads)
if UNITS:
    UNIT_LABEL.update({DESKTOP_KEY: "DESKTOP GPU", "phone": "PHONE", "orch-bot": "MANAGER"})


def _sysfs(path, cast=int):
    try:
        return cast(open(path).read().strip())
    except (OSError, ValueError):
        return None


def _units_gpus():
    """Every card with a gpu_busy_percent node (amdgpu): busy %, VRAM in use / total. Desks are numbered by VRAM,
    biggest first, the first time a card is seen; a card that vanishes keeps its desk and is drawn stopped."""
    try:
        cards = sorted(d for d in os.listdir("/sys/class/drm") if re.fullmatch(r"card\d+", d))
    except OSError:
        cards = []
    found = {}
    for c in cards:
        dev = f"/sys/class/drm/{c}/device"
        busy = _sysfs(f"{dev}/gpu_busy_percent")
        if busy is not None:
            found[dev] = {"busy": busy, "used": _sysfs(f"{dev}/mem_info_vram_used") or 0,
                          "total": _sysfs(f"{dev}/mem_info_vram_total") or 0}
    for dev in sorted((d for d in found if d not in _GPU_CARDS), key=lambda d: -found[d]["total"]):
        _GPU_CARDS[dev] = f"gpu{len(_GPU_CARDS)}"
    for dev, key in _GPU_CARDS.items():
        g = UNIT_GPU.setdefault(key, {"dev": dev})
        if "pci" not in g:
            try:
                g["pci"] = next((ln.split("=", 1)[1].strip() for ln in open(f"{dev}/uevent")
                                 if ln.startswith("PCI_ID=")), "")
            except OSError:
                g["pci"] = ""
        r = found.get(dev)
        if r:
            # under 2 GB of VRAM is the integrated card: its "VRAM" is a carve-out of system memory
            g.update(r, up=True, kind="dGPU" if r["total"] >= 2 * 1024 ** 3 else "iGPU")
        else:
            g.update(up=False, busy=0)
        UNIT_LABEL[key] = f"GPU{key[3:]}"
        CPU_HIST.setdefault(key, deque(maxlen=48)).append(g.get("busy") or 0)


def _units_cpus():
    """Per-core busy % from /proc/stat deltas between two polls (busy = all ticks minus idle and iowait). The cores
    are grouped onto at most four desks, sibling threads of one physical core side by side (topology/core_id)."""
    rows = {}
    try:
        for ln in open("/proc/stat"):
            if ln.startswith("cpu") and ln[3:4].isdigit():
                f = ln.split()
                v = [int(x) for x in f[1:9]]
                rows[int(f[0][3:])] = (sum(v) - v[3] - v[4], sum(v))
    except (OSError, ValueError):
        return
    if not UNIT_CPU["groups"] and rows:
        ids = sorted(rows, key=lambda c: (_sysfs(f"/sys/devices/system/cpu/cpu{c}/topology/core_id") or 0, c))
        per = max(2, -(-len(ids) // 4))
        for g, k in enumerate(range(0, len(ids), per)):
            cpus = sorted(ids[k:k + per])
            lab = (f"CPU {cpus[0]}-{cpus[-1]}" if cpus == list(range(cpus[0], cpus[-1] + 1)) else
                   "CPU " + ",".join(map(str, cpus)))
            UNIT_CPU["groups"].append((f"cpu{g}", cpus, lab))
    for c, (b, t) in rows.items():
        pb, pt = _CPU_PREV.get(c, (b, t))
        if t > pt:
            UNIT_CPU["busy"][c] = max(0.0, min(100.0, 100.0 * (b - pb) / (t - pt)))
        _CPU_PREV[c] = (b, t)
    for key, cpus, lab in UNIT_CPU["groups"]:
        UNIT_LABEL[key] = lab
        CPU_HIST.setdefault(key, deque(maxlen=48)).append(
            sum(UNIT_CPU["busy"].get(c, 0.0) for c in cpus) / max(1, len(cpus)))
    try:
        UNIT_CPU["load"] = open("/proc/loadavg").read().split()[:3]
    except OSError:
        pass


def _ollama_ps(addr):
    try:
        return http_json(f"http://{addr}/api/ps", 1.5).get("models") or []
    except Exception:
        return None


def _ps_landed(key, models):
    """Model names that took a call since the last read: new in /api/ps, or their expires_at moved on (Ollama
    pushes it out by keep_alive on every request it serves; reading /api/ps does not)."""
    prev = _U.get(key)
    cur = {str(m.get("name")): str(m.get("expires_at") or "") for m in models or []}
    _U[key] = cur
    if prev is None:
        return []
    return [n for n, exp in cur.items() if n not in prev or exp > prev[n]]


def _ollama_gpu(models):
    """The laptop GPU a loaded model sits in: the one whose VRAM in use covers the model's size_vram (the biggest
    card when both would). None when the model is not in VRAM at all (size_vram 0: it runs on the CPU)."""
    need = max([int(m.get("size_vram") or 0) for m in models or []] or [0])
    if need <= 0:
        return None
    fits = [k for k, g in UNIT_GPU.items() if g.get("up") and (g.get("used") or 0) >= need * 0.9]
    return max(fits, key=lambda k: UNIT_GPU[k].get("total") or 0) if fits else None


def short_model(name):
    """hf.co/owner/Some-Model-GGUF:Q4_K_M -> Some-Model (the part a person reads)."""
    s = str(name or "?").split("@")[0].split("/")[-1].split(":")[0]
    return re.sub(r"(?i)-gguf$", "", s) or "?"


def _role_models(action):
    """The laptop model names a job's role runs (models.json): an auto-hunt runs the hunter role; any other job the
    manager starts runs on the brain's roles. A role pinned @desktop or @phone is not a laptop model."""
    roles = jload(os.path.join(ORCH, "models.json"), {})
    want = ("hunter",) if action == "auto" else ("brain", "brain_fallback", "lead", "worker")
    return {str(roles[r]).split("@")[0].lower() for r in want
            if roles.get(r) and not str(roles[r]).endswith(("@desktop", "@phone"))}


def _proc_core(pid):
    """The core a process last ran on: /proc/<pid>/stat field 39."""
    try:
        return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[36])
    except (OSError, IndexError, ValueError):
        return None


def _cpu_desk(core):
    return next((k for k, cpus, _ in UNIT_CPU["groups"] if core in cpus), None) if core is not None else None


def _proc_started(pid):
    """Epoch a process started (stat field 22), or None: a pid from an old log line may since have been reused."""
    try:
        st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        boot = next(float(ln.split()[1]) for ln in open("/proc/stat") if ln.startswith("btime"))
        return boot + int(st[19]) / os.sysconf("SC_CLK_TCK")
    except (OSError, StopIteration, IndexError, ValueError):
        return None


def _unattributed(label, why):
    with LOCK:
        UNATTRIBUTED.append((time.time(), label))
    UNIT_COUNT["unattributed"] += 1
    log_event("UNIT", f"MANAGER -> ?: {label} (unattributed: {why})", C_WARN)


def _mgr_on():
    """pm2 has orch-bot online: only then is a job on the floor the manager's dispatch."""
    return any(p.get("name") == "orch-bot" and p.get("status") == "online" for p in PM2_LAST or [])


def _to_mgr(unit, doc, text, color=None):
    """A unit's sheet for the manager: walked to its desk while orch-bot runs, a ticker line only when it does not
    (nobody is there to hand it to)."""
    if _mgr_on():
        handoff(unit, [("desk:orch-bot", doc)], text, tag="UNIT", color=color)
    else:
        log_event("UNIT", f"{label_of(unit)}: {text} (orch-bot is stopped: not walked)", color or C_MUTED)


def _attribute(job, unit, detail, late=False):
    """Name the unit that took a job, and walk the work order to it (a job already running when the office opened
    is only said, not walked: that hand-off happened before anyone was watching; with orch-bot stopped in pm2 the
    job did not come from the manager, so nobody walks it either)."""
    job["unit"], job["units"] = unit, [unit]
    UNIT_COUNT["attributed"] += 1
    with LOCK:
        UNIT_SENT.append((time.time(), unit, job["what"]))
    if job.get("quiet") or not _mgr_on():
        log_event("UNIT", f"{label_of(unit)} is on {job['what']} ({detail})" +
                  ("" if job.get("quiet") else ", not dispatched from here: orch-bot is stopped"), C_MUTED)
    else:
        handoff("orch-bot", [(f"desk:{unit}", "order")],
                f"work order: {job['what']} ({detail}{', seen late' if late else ''})", tag="UNIT")


def unit_job_open(action, prog, pid, t0, quiet=False):
    """orch.log says the manager started a job (a hunt, an escalate, an osint, a draft ...). It is not walked yet:
    the units poller walks it to whichever unit is SEEN taking it (see the rules above), or calls it unattributed."""
    what = f"{'hunt' if action == 'auto' else action} {prog}"
    if pid:
        st = _proc_started(pid)
        if st is None or st < t0 - 30:  # gone already, or a recycled pid: no process tree to read
            pid = None
    if quiet and not pid:  # a line from the log's tail whose process is gone: history, not a job on the floor
        return
    with LOCK:
        for j in UJOBS.values():  # a new job of the same kind replaces the old one (orch-bot runs one at a time)
            if j["action"] == action and not j.get("closed"):
                j["closed"] = time.time()
        UJOBS[f"{action}:{prog}:{pid or int(t0)}"] = {"what": what, "action": action, "prog": prog, "pid": pid,
                                                      "t0": t0, "seen": time.time(), "unit": None, "units": [],
                                                      "quiet": quiet}
        for k in [k for k, j in UJOBS.items() if j.get("closed") and time.time() - j["closed"] > 600]:
            del UJOBS[k]
    if not quiet:
        UNIT_COUNT["jobs"] += 1
        log_event("UNIT", f"MANAGER opened {what}: watching for the unit that takes it", C_MUTED)


def unit_job_result(action, text, doc="result", close=False, quiet=False):
    """A real result line (orch.log) for an open job: its unit walks the sheet back to the manager. Returns the unit
    key, or None when nobody was ever shown to hold the job (the sheet then waits in the out-tray as ?)."""
    with LOCK:
        job = max((j for j in UJOBS.values() if j["action"] == action and not j.get("closed")),
                  key=lambda j: j["t0"], default=None)
        if job and close:
            job["closed"] = time.time()
    unit = job.get("unit") if job else None
    if quiet or not text:
        return unit
    if unit:
        if _every(f"ures:{unit}", 6):
            _to_mgr(unit, doc, text)
        else:  # a burst of result lines: the ticker has each one, one walk carries them
            log_event("UNIT", f"{label_of(unit)} -> MANAGER: {text}", C_GOLD)
    else:
        _unattributed(text, "no unit was seen taking this job")
    return unit


def unit_duty(key):
    """The job a unit holds right now, in words: a manager job attributed to it, the website call it is serving in
    PROD, or the work it was last seen doing (a model call, a probe), else nothing."""
    with LOCK:
        jobs = [j for j in UJOBS.values() if not j.get("closed") and key in (j.get("units") or [])]
        visit = UNIT_VISIT.get(key)
    if jobs:
        return max(jobs, key=lambda j: j["t0"])["what"]
    if visit:
        if visit.get("src") == "video":  # a compile in PROD: its stage as this walk read it, else the job's own row
            d = UNIT_DUTY.get(key)
            if d and d[1] > time.time() and d[0].startswith("STUDIO"):
                return "PROD: " + d[0]
            job = VIDEO_LIVE.get(visit.get("pid"))
            if job:
                return "PROD: STUDIO: " + _video_text(job)
        return "PROD: " + visit["label"]
    d = UNIT_DUTY.get(key)
    return d[0] if d and d[1] > time.time() else ""


def _units_desktop(first, kids):
    """The desktop GPU's real load: calls the uplink proxy has open (desktop-inflight.json) and the rows it logs
    as each one answers (desktop-traffic.jsonl: model, ms, status, caller, pid)."""
    now = time.time()
    open_now = dict(INFLIGHT)
    seen = _U.setdefault("inflight", {})
    with LOCK:
        rows = list(UNIT_TRAFFIC)
        UNIT_TRAFFIC.clear()
    for r in rows:
        UPLINK_RATE.append((r.get("ts") or now, str(r.get("caller") or "?")))
    open_jobs = [j for j in list(UJOBS.values()) if not j.get("closed")]
    for rid, c in open_now.items():
        if rid in seen:
            continue
        seen[rid] = dict(c, t_seen=now)
        caller, model = str(c.get("caller") or "?"), short_model(c.get("model"))
        if first:
            continue
        if caller in MANAGER_CALLERS:
            job = next((j for j in open_jobs if j["unit"] is None and j["action"] == "auto"), None) \
                if caller == "hunter" else None
            if job:
                _attribute(job, DESKTOP_KEY, f"{model} via the uplink", late=job.get("timed_out"))
                seen[rid]["job"] = True
            elif _mgr_on() and _every("uord:desktop", 10):
                handoff("orch-bot", [(f"desk:{DESKTOP_KEY}", "order")], f"model call: {model}", tag="UNIT")
                seen[rid]["walked"] = True
    for r in rows:
        if not r.get("model") or first:
            continue
        caller, pid = str(r.get("caller") or "?"), r.get("pid")
        tree_job = next((j for j in open_jobs if j.get("pid") and pid and
                         (pid == j["pid"] or pid in _descendants(j["pid"], kids))), None)
        if tree_job and tree_job["unit"] is None:
            _attribute(tree_job, DESKTOP_KEY, f"{short_model(r.get('model'))} via the uplink",
                       late=tree_job.get("timed_out"))
        if caller not in MANAGER_CALLERS and not tree_job:
            continue  # someone else's call (gnoc chat, a terminal): the desk lights, the manager gets no sheet
        if not tree_job and caller == "hunter":  # the hunter role is the open auto-hunt, when it is on this desk
            tree_job = next((j for j in open_jobs if j["action"] == "auto" and j.get("unit") == DESKTOP_KEY), None)
        bad = (r.get("status") or 0) >= 400 or r.get("err")
        text = (f"{tree_job['what']}: " if tree_job else "") + \
            f"{short_model(r.get('model'))}, {int(r.get('ms') or 0):,} ms, {r.get('status') or r.get('err') or '?'}"
        _U["desktop_res"] = now
        if caller in MANAGER_CALLERS:
            _U.setdefault("mgr_calls", deque(maxlen=50)).append(r.get("ts") or now)
        if _every("ures:desktop", 8):
            _to_mgr(DESKTOP_KEY, "hit" if bad else "result", text, color=C_BAD if bad else None)
        elif _every("utick:desktop", 3):
            log_event("UNIT", f"{label_of(DESKTOP_KEY)} -> MANAGER: {text}", C_BAD if bad else C_GOLD)
    for rid in [k for k, v in seen.items() if k not in open_now and now - v["t_seen"] > 400]:
        del seen[rid]
    if open_now:
        c = max(open_now.values(), key=lambda v: v.get("ts") or 0)
        who = label_of(CALLER_DESK[c["caller"]]) if CALLER_DESK.get(c.get("caller")) else str(c.get("caller", "?"))
        UNIT_DUTY[DESKTOP_KEY] = (f"{who}: {short_model(c.get('model'))}", now + 5)


def _units_ollama(first, open_jobs):
    """The laptop Ollama and the phone's: a call landing names the unit that served it."""
    now = time.time()
    if now >= _U.get("ps_next", 0):
        _U["ps_next"] = now + 2
        ps = _ollama_ps(OLLAMA_LAPTOP)
        if ps is not None:
            if ps:
                _U["ps_last"], _U["ps_at"] = ps, now
            landed = _ps_landed("ps_laptop", ps)
            gpu = _ollama_gpu(ps)
            for name in landed if not first else []:
                if gpu:
                    _U["touch:" + gpu] = now
                    UNIT_DUTY[gpu] = (f"model {short_model(name)}", now + 20)
                job = next((j for j in open_jobs if j["unit"] is None and name.lower() in _role_models(j["action"])),
                           None)
                if job and gpu:
                    _attribute(job, gpu, f"{short_model(name)} on the laptop Ollama", late=job.get("timed_out"))
                elif job and not job.get("cpu_note"):  # the model is not in any GPU's VRAM: no GPU desk to name
                    job["cpu_note"] = True
                    log_event("UNIT", f"{job['what']}: the laptop Ollama answered {short_model(name)} from system "
                                      "memory, so no GPU desk is named", C_MUTED)
    ph = HOSTS_LAST.get("phone") or {}
    if ph.get("models") is not None and ph.get("up"):
        for name in _ps_landed("ps_phone", ph.get("models")) if not first else []:
            _U["touch:phone"] = now
            UNIT_DUTY["phone"] = (f"model {short_model(name)}", now + 20)


def _units_split(first):
    """split-llm (one model over the laptop GPU and the phone): busy when llama-server's /slots has a slot
    processing. One busy call is one shared paper on the PHONE and on the laptop GPU busy at that moment."""
    now = time.time()
    on = any(p.get("name") == "split-llm" and p.get("status") == "online" for p in PM2_LAST or [])
    in_split = bool((HOSTS_LAST.get("phone") or {}).get("in_split"))
    if not (on and in_split):
        _U["split_busy"] = False
        return
    if now < _U.get("split_next", 0):
        return
    _U["split_next"] = now + 2
    port = _U.get("split_port")
    if port is None:
        try:
            with open(os.path.join(PM2_LOGS, "split-llm-out.log"), "rb") as fh:
                fh.seek(max(0, os.path.getsize(fh.name) - 20000))
                hits = re.findall(rb"\bport (\d+)", fh.read())
            port = _U["split_port"] = int(hits[-1]) if hits else 0
        except (OSError, ValueError):
            port = _U["split_port"] = 0
    if not port:
        return
    try:
        slots = http_json(f"http://127.0.0.1:{port}/slots", 1.5)
        busy = any(isinstance(s, dict) and s.get("is_processing") for s in (slots if isinstance(slots, list) else []))
    except Exception:
        busy = False
    was, _U["split_busy"] = _U.get("split_busy"), busy
    if busy:
        hot = [k for k, g in UNIT_GPU.items() if g.get("up") and (g.get("busy") or 0) > 5]
        units = ["phone"] + (hot if len(hot) == 1 else [])
        for u in units:
            UNIT_DUTY[u] = ("split-llm: one model, two units", now + 5)
        if not was and not first:
            with LOCK:
                SPLIT_PAPERS.append((now, units))
            other = label_of(units[1]) if len(units) > 1 else "? (no single laptop GPU busy)"
            log_event("UNIT", f"{other} + PHONE: a split-llm call, one shared paper", C_PURPLE)


def _units_shell(first, kids, comm, open_jobs):
    """Probe programs running on the laptop: each lights the CPU desk of the core it last ran on; one inside a
    job's process tree is that job's (and names its unit when nothing else has)."""
    now = time.time()
    chat_pids = {v.get("pid") for v in list(CHAT_LIVE.values()) if v.get("pid")}
    trees = {id(j): {j["pid"], *_descendants(j["pid"], kids)} for j in open_jobs if j.get("pid")}
    chat_tree = set().union(*[{p, *_descendants(p, kids)} for p in chat_pids]) if chat_pids else set()
    for pid, c in comm.items():
        if c not in _PROBE_COMMS:
            continue
        desk = _cpu_desk(_proc_core(pid))
        if not desk:
            continue
        what = _cmd_summary(pid, c)
        job = next((j for j in open_jobs if pid in trees.get(id(j), ())), None)
        owner = f"{job['what']}: " if job else ("gnoc chat: " if pid in chat_tree else "")
        UNIT_DUTY[desk] = (owner + what, now + 4)
        if not job or first:
            continue
        if job["unit"] is None:
            _attribute(job, desk, f"{what} on core {_proc_core(pid)}", late=job.get("timed_out"))
        elif desk not in job["units"]:
            job["units"].append(desk)
            log_event("UNIT", f"{label_of(desk)} joins {job['what']}: {what} on core {_proc_core(pid)}", C_GOLD)


def _units_site(first, kids):
    """A gnoc chat tool call whose argument names the website is a website-analysis job: the CPU desk running it
    (the core its newest probe child, else the chat process itself, last ran on) takes it to PROD and sits there
    until the call's end row; then it walks the result back."""
    now = time.time()
    live = {cid: v for cid, v in list(CHAT_LIVE.items()) if v.get("site")}
    with LOCK:
        visits = dict(UNIT_VISIT)
    held = {v["cid"] for v in visits.values()}
    for unit, v in visits.items():
        if v.get("src") == "video":  # a STUDIO compile: _units_video ends it when the compile's process does
            continue
        if v["cid"] not in live:
            with LOCK:
                UNIT_VISIT.pop(unit, None)
            log_event("PROD", f"PROD -> {label_of(unit)}: {v['label']} done ({_dur(now - v['t0'])})", C_GOLD)
    done_ = _U.setdefault("site_seen", set())
    for cid, v in live.items():
        if cid in held or cid in done_:
            continue
        done_.add(cid)
        if first:  # already open when the office attached: not walked
            continue
        pid = v.get("pid")
        probes = [p for p in _descendants(pid, kids)] if pid else []
        core = _proc_core(max(probes)) if probes else (_proc_core(pid) if pid else None)
        unit = _cpu_desk(core)
        label = chat_act(v["name"])[0] + (f": {v['arg']}" if v.get("arg") else "")
        if unit is None or unit in UNIT_VISIT:
            if unit is None:
                _unattributed(f"site read: {label}", "the chat process was not found on any core")
            continue
        with LOCK:
            UNIT_VISIT[unit] = {"cid": cid, "label": label, "t0": now}
        log_event("PROD", f"GNOC CHAT on {label_of(unit)} -> PROD: {label}", C_GOLD)
    if len(done_) > 400:
        done_.clear()


# STUDIO (UNITS, 2026-10-24, GreyNOC: "have the office include and show when we are compiling and editing video").
# The campus video tool (your-site.example/scripts/video), run by hand or by gnoc chat through `gnoc video ...`.
# The builders and the editor import its renderer script IN-PROCESS, so one compile (a video rendered to files) is ONE
# node process whose cmdline names one of the four scripts. The office's word for that job is "compile" (GreyNOC:
# "compiling and editing video"). What the office reads, on the 2 s process walk:
#   job     a node pid whose cmdline names scripts/video/<one of VIDEO_SCRIPTS> (and whose parent is not one): its
#           argv gives the kind (compile; edit = edit-video without its compile flag; build = a builder without it) and
#           the video id. `edit-video --list / --show` read a board and edit nothing: not a job
#   stage   its descendants' comm names: ffmpeg = ENCODE (its cmdline names the <id>.<ext>.partial.tmp target, whose
#           size is the bytes written so far; an ffmpeg writing a .wav is the audio track), chrome / headless_shell
#           = CAPTURE (Playwright), piper = VOICE (narration). No child yet = PLAN, or WRITE when its partial files
#           already sit in the output folder; between two children the last stage holds (piper runs once a scene)
#   frames  the file count in <TMPDIR>/gnoc-video-*/frames (the tool's work dir; TMPDIR from the process's own
#           environ), only when the ffmpeg child names the dir, or exactly ONE such dir changed since the job started
#           (a stale or a second job's dir makes it two: "?"). Planned = sum(scenes[].seconds) x fps of the
#           storyboard, marked ~ because narration stretches a scene to fit its line
#   unit    the CPU desk of the core the stage child (else the node process) last ran on (/proc/<pid>/stat field
#           39), named by the first walk that reads one and then held until the job ends, as a manager job is (the
#           scheduler moves the process between cores every few seconds; the inspector shows the latest core's desk).
#           Encoding is libx264 / libvpx-vp9 on the cores and capture is a headless browser: a compile is a CPU job, never
#           a GPU one. A core that cannot be read names no desk: the board and ticker say "?"
#   by      "gnoc chat" when the node pid is inside a live chat tool call's process tree, else "hand (CLI)"
#   done    <out>/<id>.manifest.json with an mtime at or after the job started (the tool writes it last, after
#           every partial is renamed to its final name); an edit is its board folder's edits.jsonl row
# Two names the tool fixes are also program handles on the public stream's redaction list (office-stream.py,
# OFFICE_WORD_COLLISIONS): they are spelled in halves below, so this source never spells them whole and the stream
# keeps blacking out those programs.
_VID_R = "ren" "der"  # the renderer script's stem, and the builders' / editor's flag that compiles after the edit
VIDEO_RENDERER, VIDEO_RFLAG = _VID_R + ".mjs", "--" + _VID_R
VIDEO_SCRIPTS = (VIDEO_RENDERER, "build-course-video.mjs", "build-tutorial.mjs", "edit-video.mjs")
VIDEO_STAGE_COMMS = (("ENCODE", ("ffmpeg",)), ("CAPTURE", ("chrome", "headless_shell")), ("VOICE", ("piper",)))
VIDEO_DL = os.path.expanduser("~/Downloads")      # the tool's default --out
VIDEO_BOARDS = os.path.join(VIDEO_DL, "video-" "proj" "ects")  # editable boards: <id>/<id>.json + edits.jsonl
_VIDEO_VALUE_FLAGS = {"out", "fps", "size", "formats", "browser-path", "poster-at", "narrate-cmd", "voice", "music",
                      "music-seed", "ops", "ops-file", "class", "track", "marketing", "instantiate", "port",
                      "max-scenes", "lesson", "ctf", "explainer"}
_VIDEO_FMT = ((".poster.jpg", "poster"), (".manifest.json", "manifest"), (".mp4", "mp4"), (".webm", "webm"),
              (".vtt", "captions"), (".srt", "captions"))
VIDEO_LIVE = {}               # node pid -> the job as its readings say (kind, id, stage, detail, unit, by, ...)
VIDEO_DONE = deque(maxlen=6)  # {"what": "wrote" | "edited" | "failed" | "built", "id", "at", "text"}, newest last
VISIT_END = {}                # visit cid -> the paper its unit carries home from PROD (None: nothing came out)


def _argv(pid):
    try:
        return [a.decode("utf-8", "replace") for a in open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") if a]
    except OSError:
        return []


def _vopt(args, name):
    """The value of --name V or --name=V at any position in argv (the flags after `--` included)."""
    for i, a in enumerate(args):
        if a == f"--{name}" and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(f"--{name}="):
            return a.split("=", 1)[1]
    return None


def _vpositional(args):
    """The first positional argument (the board or the id), skipping the values of the value flags."""
    skip = False
    for a in args:
        if skip:
            skip = False
        elif a == "--":
            return None
        elif a.startswith("--"):
            skip = a[2:] in _VIDEO_VALUE_FLAGS
        elif not a.startswith("-"):
            return a
    return None


def _jdict(path):
    d = jload(path, {}) if path else {}
    return d if isinstance(d, dict) else {}


def _vbytes(b):
    return "?" if b is None else (f"{b / 1048576:.1f} MB" if b >= 1048576 else f"{b // 1024} KB")


def _ls(d, prefix="", suffix=""):
    try:
        return [os.path.join(d, n) for n in os.listdir(d) if n.startswith(prefix) and n.endswith(suffix)]
    except OSError:
        return []


def _video_quick_fps():
    """--quick's frame rate, read from the tool itself (lib/storyboard.mjs), or None: then no planned count."""
    if "vid_qfps" not in _U:
        try:
            src = open(os.path.join(SITE_DIR, "scripts", "video", "lib", "storyboard.mjs")).read()
            m = re.search(r"if \(opts\.quick\) \{\s*fps = (\d+)", src)
            _U["vid_qfps"] = int(m.group(1)) if m else None
        except OSError:
            _U["vid_qfps"] = None
    return _U["vid_qfps"]


def _video_cmd(pid):
    """(script, args, cwd) when this node process runs one of the four video scripts, else None."""
    argv = _argv(pid)
    if not argv or not os.path.basename(argv[0]).startswith("node"):
        return None
    script = next((a for a in argv[1:] if not a.startswith("-")), None)
    if not script or os.path.basename(script) not in VIDEO_SCRIPTS:
        return None
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        cwd = ""
    full = os.path.normpath(script if os.path.isabs(script) else os.path.join(cwd, script))
    if "/scripts/video/" not in full:
        return None
    return os.path.basename(script), argv[argv.index(script) + 1:], cwd


def _video_job(pid, script, args, cwd, now, chat_tree):
    """A new job from its argv, or None for a read that edits nothing (--list, --show, --help)."""
    pre = args[:args.index("--")] if "--" in args else args
    if any(a in ("--list", "--help", "-h") for a in pre):
        return None
    pos = _vpositional(pre)
    res = (lambda p: os.path.normpath(p if os.path.isabs(p) else os.path.join(cwd, p))) if cwd else os.path.abspath
    board, kind, vid = None, "compile" if VIDEO_RFLAG in pre else "build", None
    if script == VIDEO_RENDERER:
        kind = "compile"
        if pos:
            board, vid = res(pos), os.path.basename(pos)[:-5] if pos.endswith(".json") else os.path.basename(pos)
    elif script == "edit-video.mjs":
        if not any(a in pre for a in ("--ops", "--ops-file", "--set", VIDEO_RFLAG)) and \
                not any(a.startswith(("--ops=", "--ops-file=")) for a in pre):
            return None  # `<id>` or `<id> --show`: prints the board, edits nothing
        kind = "compile" if VIDEO_RFLAG in pre else "edit"
        if pos and pos.endswith(".json"):
            board, vid = res(pos), os.path.basename(pos)[:-5]
        elif pos:
            vid = pos
            board = os.path.join(VIDEO_BOARDS, pos, f"{pos}.json")
    else:  # the builders: the flag that picks the content names it until the encoder names the real id
        for flag in ("class", "track", "marketing", "instantiate", "lesson", "ctf", "explainer"):
            v = _vopt(pre, flag)
            if v:
                vid = f"{flag} {os.path.basename(v)}"
                if flag == "instantiate":
                    board = res(v)
                break
        vid = vid or " ".join(a for a in pre if a != VIDEO_RFLAG)[:40] or script[:-4]
    sb = _jdict(board)
    out = _vopt(args, "out")
    board_how = sb.get(_VID_R) if isinstance(sb.get(_VID_R), dict) else {}  # how the board was last compiled (editor)
    if not out and board_how:  # ... and where to
        out = board_how.get("out") or _vopt([str(a) for a in board_how.get("args") or []], "out")
    if isinstance(sb.get("id"), str) and sb["id"] and script != "build-course-video.mjs":
        vid = sb["id"]  # the storyboard's own id is the one the tool names its files by
    planned = None
    saved = [str(a) for a in board_how.get("args") or []]
    quick = ("--quick" in args or "--quick" in saved) and not any(a in ("--no-quick", "--full") for a in args)
    try:  # the tool's precedence (lib/storyboard.mjs planStoryboard): --quick, then --fps, then the board, then 30
        secs = sum(float(s.get("seconds") or 0) for s in sb.get("scenes") or [])
        fps = _video_quick_fps() if quick else float(_vopt(args, "fps") or _vopt(saved, "fps") or sb.get("fps") or 30)
        planned = int(round(secs * fps)) if fps else None
    except (TypeError, ValueError, AttributeError):
        pass
    tmp = "/tmp"
    try:  # os.tmpdir() honours the process's own TMPDIR
        env = open(f"/proc/{pid}/environ", "rb").read().split(b"\0")
        tmp = next((e[7:].decode() for e in env if e.startswith(b"TMPDIR=") and len(e) > 7), "/tmp")
    except OSError:
        pass
    return {"pid": pid, "start": _proc_started(pid), "script": script, "kind": kind, "id": vid or "?",
            "board": board, "named": script in (VIDEO_RENDERER, "edit-video.mjs") and bool(vid), "ids": {vid} if vid else set(),
            "out": res(out) if out else VIDEO_DL, "outs": set(), "planned": planned, "tmp": tmp, "work": None,
            "t0": _proc_started(pid) or now, "seen": now, "by": "gnoc chat" if pid in chat_tree else "hand (CLI)",
            "stage": None, "key": None, "detail": "", "frames": None, "unit": None, "core_unit": None,
            "visit": None}


def _video_read(job, kids, comm):
    """Stage, detail, frames and unit for one job from this walk (see the STUDIO block above)."""
    pid = job["pid"]
    desc = _descendants(pid, kids)
    found = {st: sorted(p for p in desc if (comm.get(p) or "").startswith(names)) for st, names in VIDEO_STAGE_COMMS}
    stage = next((st for st, _ in VIDEO_STAGE_COMMS if found[st]), None)
    child = found[stage][-1] if stage else None
    fmt, detail = None, ""
    work = None
    if stage == "ENCODE":
        av = _argv(child)
        for a in av:
            m = re.search(r"^(.*/gnoc-video-[^/]+)/", a)
            if m:
                work = m.group(1)
        t = next((a for a in reversed(av) if a.endswith(".partial.tmp")), None)
        if t:
            base = os.path.basename(t)[:-len(".partial.tmp")]
            sfx = next(((s, f) for s, f in _VIDEO_FMT if base.endswith(s)), None)
            fmt = sfx[1] if sfx else base.rsplit(".", 1)[-1]
            if sfx and base[:-len(sfx[0])]:
                real = base[:-len(sfx[0])]
                job["ids"].add(real)
                if not job["named"]:  # a builder: the encoder's target is the first reading of the real id
                    job["id"], job["named"] = real, True
            job["outs"].add(os.path.dirname(t))
            try:
                size = os.path.getsize(t)
            except OSError:
                size = None
            detail = f"{fmt} {_vbytes(size)}" if size is not None else f"{fmt} (file not on disk yet)"
        else:
            fmt, detail = "audio", "audio track (wav)"
    elif stage == "VOICE":
        detail = "piper"
    if not job.get("work") or not os.path.isdir(job["work"]):
        dirs = []
        for d in _ls(job["tmp"], "gnoc-video-"):
            try:
                if os.stat(d).st_ctime >= job["t0"] - 2:  # changed since the job started: a stale one is not it
                    dirs.append(d)
            except OSError:
                pass
        job["work"] = work or (dirs[0] if len(dirs) == 1 else None)
    try:
        job["frames"] = sum(1 for _ in os.scandir(os.path.join(job["work"], "frames"))) if job["work"] else None
    except OSError:
        job["frames"] = None
    if stage == "CAPTURE":
        detail = f"frames {job['frames'] if job['frames'] is not None else '?'}" + \
                 (f"/~{job['planned']}" if job["planned"] else "")
    unit = _cpu_desk(_proc_core(child or pid))
    if stage is None:  # no child right now: the last stage holds; before any, PLAN or WRITE (partials on disk)
        if job["stage"] not in (None, "PLAN", "WRITE"):
            return job["stage"], job["key"], job["detail"], unit
        outs = {job["out"], *job["outs"]}
        parts = [p for d in outs for p in _ls(d, suffix=".partial.tmp")
                 if any(os.path.basename(p).startswith(i + ".") for i in job["ids"])]
        stage = "WRITE" if parts else "PLAN"
        detail = f"{len(parts)} partial file{'s' * (len(parts) != 1)}" if parts else ""
    return stage, (stage, fmt), detail, unit


def _video_text(job):
    return f"{job['kind']} {_pub(job['id'])} · {job['stage']}" + (f" {job['detail']}" if job["detail"] else "")


def _video_said(kind, vid, text, color, unit=None, toast_it=False, reel=False, brief=""):
    """One finished thing: ticker, VIDEO_DONE (the STUDIO board; brief = its words there), optionally a toast and a
    reel on the unit's desk."""
    now = time.time()
    log_event("STUDIO", text, color)
    with LOCK:
        VIDEO_DONE.append({"what": kind, "id": vid, "at": now, "text": text, "brief": brief})
        if reel and unit:
            PILES.setdefault(unit, []).append(("reel", now + 150))
            del PILES[unit][:-6]
    if toast_it:
        toast(text, C_PINK, 6)


def _video_manifest(job):
    """The manifest this job wrote: <out>/<id>.manifest.json for every id and output folder it was seen using, with
    an mtime at or after it started; for a builder whose encoder was never seen, the newest such manifest in its
    output folder. Returns (path, mtime, json) or None."""
    outs = {job["out"], *job["outs"]}
    cands = [os.path.join(d, f"{i}.manifest.json") for d in outs for i in job["ids"]]
    if not job["named"]:
        cands += [p for d in outs for p in _ls(d, suffix=".manifest.json")]
    best = None
    for p in cands:
        try:
            mt = os.path.getmtime(p)
        except OSError:
            continue
        if mt >= job["t0"] - 5 and (best is None or mt > best[1]):
            best = (p, mt)
    return (best[0], best[1], _jdict(best[0])) if best else None


def _video_edit_row(job, since):
    """The newest edits.jsonl row beside the job's board (the editor appends one per saved batch) written at or
    after `since`: (path, row) or (None, None)."""
    board = job.get("board") or os.path.join(VIDEO_BOARDS, str(job["id"]), f"{job['id']}.json")
    path = os.path.join(os.path.dirname(board), "edits.jsonl")
    for r in reversed(jsonl_tail(path, 5) or []):
        at = _ts_epoch(r.get("at"))
        if at is not None and at >= since - 2:
            return path, r
    return None, None


def _video_finish(job, now):
    """The job's process is gone: say what it left behind (its manifest, its edits.jsonl row) or that it left
    nothing, end its PROD visit, and put the reel on its desk if nobody walked it home."""
    who = label_of(job["unit"]) if job["unit"] else "?"
    seen = _U.setdefault("vid_seen", set())
    vid, took = _pub(job["id"]), _dur(now - job["t0"])
    wrote = False
    if job["script"] == "edit-video.mjs":
        path, row = _video_edit_row(job, job["t0"])
        if row and (path, row.get("at")) not in seen:
            seen.add((path, row.get("at")))
            notes = "; ".join(str(n) for n in row.get("notes") or []) or f"{len(row.get('ops') or [])} op(s)"
            _video_said("edited", job["id"], f"edited {vid}: {_pub(notes)} (edits.jsonl, on {who})", C_GOLD,
                        brief=_pub(notes))
        elif job["kind"] == "edit":
            _video_said("failed", job["id"], f"edit of {vid} ended with no edits.jsonl row (a dry run, or refused)",
                        C_WARN, brief="edit: no edits.jsonl row")
    if job["kind"] == "compile":
        man = _video_manifest(job)
        if man:
            path, mt, m = man
            seen.add((path, mt))
            wrote = True
            vid = _pub(str(m.get("id") or job["id"]))
            secs = m.get("totalSeconds")
            brief = (f"{secs if secs is not None else '?'}s, {len(m.get('scenes') or [])} scenes, "
                     f"{'narrated' if m.get('narrated') else 'silent'}")
            text = f"wrote {vid}: {brief} ({took}, on {who}, ordered by {job['by']})"
            visit = job.get("visit")
            with LOCK:
                walked = bool(visit and (UNIT_VISIT.get(visit) or {}).get("walked"))
            _video_said("wrote", str(m.get("id") or job["id"]), text, C_GOOD, unit=job["unit"] or visit,
                        toast_it=True, reel=not walked, brief=brief)
        else:
            _video_said("failed", job["id"], f"compile of {vid} ended with no manifest (failed or cancelled, {took}, "
                                             f"on {who})", C_WARN, brief="no manifest: failed or cancelled")
    elif job["kind"] == "build":
        _video_said("built", job["id"], f"built {vid}: storyboard written, not compiled ({took}, on {who})", C_MUTED,
                    brief="storyboard, not compiled")
    with LOCK:
        for unit, v in list(UNIT_VISIT.items()):
            if v.get("cid") == f"video:{job['pid']}":
                VISIT_END[v["cid"]] = "reel" if wrote else None
                UNIT_VISIT.pop(unit, None)
        if len(VISIT_END) > 24:
            VISIT_END.clear()


def _video_scan(first):
    """Every 5 s, independent of the process walk (an edit is over in well under the walk's 2 s): new rows in any
    board folder's edits.jsonl, and new <id>.manifest.json files in ~/Downloads and every output folder a job used. The
    first scan primes silently; a row or manifest a live job will report at its end is left to that job."""
    seen = _U.setdefault("vid_seen", set())
    offs = _U.setdefault("vid_offs", {})
    prime = _U.get("vid_prime", 0)
    with LOCK:
        live = list(VIDEO_LIVE.values())
    for path in [os.path.join(d, "edits.jsonl") for d in _ls(VIDEO_BOARDS)]:
        try:
            size = os.path.getsize(path)
        except OSError:
            continue
        off = offs.get(path)
        if first:
            offs[path] = size
            continue
        if off is None or size < off:
            off = 0
        if size == off:
            continue
        try:
            with open(path, "rb") as f:
                f.seek(off)
                chunk = f.read(size - off)
        except OSError:
            continue
        end = chunk.rfind(b"\n") + 1  # whole lines only: a row being appended is read next time
        offs[path] = off + end
        vid = os.path.basename(os.path.dirname(path))
        for ln in chunk[:end].splitlines():
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            at = _ts_epoch(r.get("at"))
            if at is None or at < prime - 1 or (path, r.get("at")) in seen:
                continue
            if any(j["script"] == "edit-video.mjs" and (j["id"] == vid or os.path.dirname(j.get("board") or "") ==
                                                         os.path.dirname(path)) for j in live):
                continue  # its process is still on the walk: it reports the row when it ends
            seen.add((path, r.get("at")))
            notes = "; ".join(str(n) for n in r.get("notes") or []) or f"{len(r.get('ops') or [])} op(s)"
            _video_said("edited", vid, f"edited {_pub(vid)}: {_pub(notes)} (edits.jsonl; its process ended "
                                       f"between two walks, so no desk)", C_GOLD, brief=_pub(notes))
    dirs = {VIDEO_DL, *_U.setdefault("vid_dirs", set())}
    for d in dirs:
        for path in _ls(d, suffix=".manifest.json"):
            try:
                mt = os.path.getmtime(path)
            except OSError:
                continue
            if first or mt < prime:
                seen.add((path, mt))
                continue
            vid = os.path.basename(path)[:-len(".manifest.json")]
            if (path, mt) in seen or any(vid in j["ids"] or not j["named"] for j in live if j["kind"] == "compile"):
                continue
            seen.add((path, mt))
            m = _jdict(path)
            brief = f"{m.get('totalSeconds', '?')}s, {len(m.get('scenes') or [])} scenes"
            _video_said("wrote", vid, f"wrote {_pub(vid)}: {brief} (the manifest appeared; no compile process was "
                                      f"seen)", C_GOOD, brief=brief + ", no process seen")
    if len(seen) > 600:
        seen.clear()


def _units_video(first, kids, comm):
    """The STUDIO poller (on the 2 s process walk): find every video job, read its stage, frames and unit, walk the
    unit to PROD while it runs and home with the reel when its manifest lands (see the STUDIO block above)."""
    now = time.time()
    if first:
        _U["vid_prime"] = now
    chat_pids = {v.get("pid") for v in list(CHAT_LIVE.values()) if v.get("pid")}
    chat_tree = set().union(*[{p, *_descendants(p, kids)} for p in chat_pids]) if chat_pids else set()
    cands = {}
    for pid, c in comm.items():
        if c == "node":
            r = _video_cmd(pid)
            if r:
                cands[pid] = r
    inner = set().union(*[set(_descendants(p, kids)) for p in cands]) if cands else set()
    roots = {p: r for p, r in cands.items() if p not in inner}
    with LOCK:
        live = dict(VIDEO_LIVE)
    for pid, job in live.items():  # gone (or the pid was reused by another process): finished
        if pid not in roots or _proc_started(pid) != job["start"]:
            with LOCK:
                VIDEO_LIVE.pop(pid, None)
            _video_finish(job, now)
    for pid, (script, args, cwd) in roots.items():
        with LOCK:
            job = VIDEO_LIVE.get(pid)
        new = job is None
        if new:
            job = _video_job(pid, script, args, cwd, now, chat_tree)
            if job is None:
                continue
        stage, key, detail, core_unit = _video_read(job, kids, comm)
        old_key, named_now = job["key"], job["unit"] is None and core_unit is not None
        job.update(stage=stage, key=key, detail=detail, core_unit=core_unit, seen=now)
        if named_now:
            job["unit"] = core_unit  # the first core reading names the desk; it holds the job from here on
        unit = job["unit"]
        _U.setdefault("vid_dirs", set()).update({job["out"], *job["outs"]})
        with LOCK:
            VIDEO_LIVE[pid] = job
        who = label_of(unit) if unit else "? (the core it ran on could not be read: no desk)"
        if unit:
            UNIT_DUTY[unit] = ("STUDIO: " + _video_text(job), now + 4)
        if new and first:  # already running when the office opened: on the board, not walked
            job["primed"] = True
            continue
        if new:
            log_event("STUDIO", f"{who} starts {job['kind']} {_pub(job['id'])} ({stage}, ordered by {job['by']})",
                      C_PINK)
        elif named_now and not job.get("primed"):
            log_event("STUDIO", f"{who} takes {job['kind']} {_pub(job['id'])} (its core was read only now)", C_PINK)
        if (new or named_now) and not job.get("primed"):
            if unit:
                with LOCK:
                    if unit not in UNIT_VISIT:
                        UNIT_VISIT[unit] = {"cid": f"video:{pid}", "label": f"STUDIO {job['kind']} {_pub(job['id'])}",
                                            "t0": now, "src": "video", "carry": "reel", "bring": "reel", "pid": pid}
                        job["visit"] = unit
        if not new and key != old_key and not first:
            log_event("STUDIO", f"{label_of(unit) if unit else '?'}: {_video_text(job)}", C_PINK)
    if first or _every("video:scan", 5):
        _video_scan(first)


def _units_brain(first):
    """A new brain.jsonl row is a decision a model already answered: the unit its row names (host) walks it back to
    the manager. A row without a host is the desktop's only if a proxy row from orch-bot closed in that window."""
    rows = jsonl_tail(os.path.join(ORCH, "brain.jsonl"), 1)
    if not rows:
        return
    r = rows[0]
    sig = (r.get("ts"), r.get("action"), r.get("status"))
    if _U.get("brain") == sig:
        return
    _U["brain"] = sig
    if first:
        return
    now, host = time.time(), r.get("host")
    try:
        secs = float(r.get("secs") or 0)
    except (TypeError, ValueError):
        secs = 0.0
    t1 = _ts_epoch(r.get("ts")) or now
    unit, how = None, ""
    if host == "phone":
        unit, how = "phone", "the row names host phone"
    elif host == "desktop":
        unit, how = DESKTOP_KEY, "the row names host desktop"
    elif host == "local":
        ps = _U.get("ps_last") if now - _U.get("ps_at", 0) < 600 else None
        unit, how = _ollama_gpu(ps), "the row names the laptop"
    elif any(t1 - secs - 10 <= ts <= t1 + 10 for ts in list(_U.get("mgr_calls") or [])):
        unit, how = DESKTOP_KEY, "a proxy row from orch-bot closed in that window"
    status = r.get("status")
    text = (f"decided {r.get('action') or '?'}" + (f" ({status})" if status not in ("ok", None) else "")
            + (f": {short_model(r.get('model'))}" if r.get("model") else "") + (f", {secs:.0f}s" if secs else ""))
    if unit and unit not in UNIT_LABEL:
        unit = None  # the row names a machine with no desk on this floor
    if unit == DESKTOP_KEY and now - _U.get("desktop_res", 0) < 20:
        log_event("UNIT", f"{label_of(unit)} -> MANAGER: {text} (its proxy row already walked)", C_MUTED)
    elif unit:
        _to_mgr(unit, "result", text)
    else:
        _unattributed(text, "the decision row names no host and no proxy row matches it")
    if unit:
        _U["touch:" + unit] = now


def d_units():
    """UNITS poller (1 s): the units' own readings, then the evidence that moves jobs between them and the manager.
    The first poll primes silently: nothing that happened before the office opened is walked."""
    if not UNITS:
        return {}
    first = not _U.get("primed")
    _units_gpus()
    _units_cpus()
    now = time.time()
    fresh = now >= _U.get("tree_next", 0) or first  # one /proc walk every 2 s (d_lab walks it on its own clock)
    if fresh:
        _U["tree_next"] = now + 2
        _U["tree"] = _proc_tree()
    kids, comm = _U.get("tree") or ({}, {})
    with LOCK:
        open_jobs = [j for j in UJOBS.values() if not j.get("closed")]
    _units_desktop(first, kids)
    _units_ollama(first, open_jobs)
    _units_split(first)
    if fresh:  # the probe, site and studio checks read the process walk
        _units_shell(first, kids, comm, open_jobs)
        _units_site(first, kids)
        _units_video(first, kids, comm)
    _units_brain(first)
    for j in open_jobs:  # the job's own process exited (or, with no pid to watch, 15 min passed): it is over
        if (j.get("pid") and not os.path.exists(f"/proc/{j['pid']}")) or (not j.get("pid") and now - j["t0"] > 900):
            j["closed"] = now
            if not j.get("quiet"):
                who = label_of(j["unit"]) if j.get("unit") else "?"
                log_event("UNIT", f"{who}: {j['what']} finished ({_dur(now - j['t0'])})", C_MUTED)
        elif j["unit"] is None and not j.get("timed_out") and now - j["seen"] > UNIT_ATTR_SECS:
            j["timed_out"] = True
            if not j.get("quiet"):
                _unattributed(f"work order: {j['what']}", f"no proxy call, laptop model call or probe of its "
                                                          f"process seen in {UNIT_ATTR_SECS} s")
    try:
        q = [ln.strip() for ln in open(os.path.join(ORCH, "queue.txt")) if ln.strip() and not ln.startswith("#")]
    except OSError:
        q = []
    _U["queue"] = q
    _U["primed"] = True
    return {"gpus": len(UNIT_GPU), "cpus": len(UNIT_CPU["groups"]), "video": len(VIDEO_LIVE)}


def unit_rows(pm2):
    """The people in UNITS mode: the manager (orch-bot's own pm2 row) then one pm2-shaped row per processing unit,
    each with its state from its own reading (worker_state reads "ustate"):
      GPU      stopped = the sysfs node is gone; working = busy above 5 %, a call landed on the laptop Ollama in it
               in the last 10 s, or it holds a job; idle otherwise
      CPU      working = its cores average above 25 % busy since the last poll, or it holds a job; idle otherwise
      DESKTOP  working = the proxy has a call open; idle = its Ollama answers /api/version (via the uplink);
               stopped = it does not; blocked = the desktop-proxy process errored in pm2
      PHONE    stopped = adb does not see it; working = split-llm busy with it in the split, or a call landed on its
               Ollama or a brain row named it in the last 30 s; idle = its Ollama answers or it is in the split;
               blocked = plugged in, out of the split, and its Ollama does not answer"""
    by = {p["name"]: p for p in pm2 or []}
    now = time.time()
    mgr = dict(by.get("orch-bot") or {"name": "orch-bot", "status": "stopped", "cpu": 0, "mem_mb": 0,
                                      "restarts": 0, "uptime_ms": None, "pid": None})
    out = [mgr]

    def row(key, kind, st, pct, info):
        return {"name": key, "status": "stopped" if st == "sleeping" else "online", "cpu": pct, "mem_mb": 0,
                "restarts": 0, "uptime_ms": None, "pid": None, "virtual": True, "unit": kind, "ustate": st,
                "info": info}
    for key, g in sorted(UNIT_GPU.items()):
        busy = g.get("busy") or 0
        touched = now - _U.get("touch:" + key, 0) < 10
        st = "sleeping" if not g.get("up") else ("working" if busy > 5 or touched or unit_duty(key) else "idle")
        out.append(row(key, "gpu", st, busy, dict(g)))
    for key, cpus, lab in UNIT_CPU["groups"]:
        hist = CPU_HIST.get(key) or [0]
        pct = hist[-1]
        st = "working" if pct > 25 or unit_duty(key) else "idle"
        out.append(row(key, "cpu", st, pct, {"cores": cpus}))
    hosts = HOSTS_LAST
    if DESKTOP_KEY in hosts:
        h = hosts[DESKTOP_KEY]
        proxy = by.get("desktop-proxy") or {}
        n_open = len(INFLIGHT)
        st = ("error" if proxy.get("status") == "errored" else "working" if n_open else
              "idle" if h.get("up") else "sleeping")
        last = max(INFLIGHT.values(), key=lambda v: v.get("ts") or 0) if INFLIGHT else {}
        out.append(row(DESKTOP_KEY, "desktop", st, 0, {"open": n_open, "model": last.get("model"),
                                                       "up": h.get("up"), "models": h.get("models") or [],
                                                       "vram": jload(os.path.join(ORCH, "desktop.json"), {}).get("vram_gb"),
                                                       "err": h.get("err")}))
        UNIT_LABEL[DESKTOP_KEY] = "DESKTOP GPU"
    if "phone" in hosts:
        h = hosts["phone"]
        lk = h.get("link") or {}
        recent = now - _U.get("touch:phone", 0) < 30
        if lk.get("state") != "device":
            st = "sleeping"
        elif (_U.get("split_busy") and h.get("in_split")) or recent:
            st = "working"
        elif h.get("up") or h.get("in_split"):
            st = "idle"
        else:
            st = "error"
        out.append(row("phone", "phone", st, 0, {"link": lk, "up": h.get("up"), "in_split": h.get("in_split"),
                                                 "models": h.get("models") or [], "err": h.get("err")}))
        UNIT_LABEL["phone"] = "PHONE"
    return out


class Feed:
    JOBS = [("pm2", d_pm2, 4), ("brain", d_brain, 3), ("lanes", d_lanes, 5), ("hosts", d_hosts, 6),
            ("outcomes", d_outcomes_today, 10), ("ships", d_ships_today, 15), ("events", d_events, 4),
            ("h1", d_h1_activity, 300), ("traffic", d_traffic, 1), ("rescue", d_rescue, 30), ("lab", d_lab, 2),
            ("chat", d_chat, 3), ("chatact", d_chat_activity, 1), ("website", d_website, 1),
            ("company", d_company, 10), ("line", d_line, 10), ("story", d_story, 3),  # COMPANY, THE LINE
            ("units", d_units, 1)]  # UNITS
    if REDACT:  # no H1 API calls in the public renderer (d_chat reads only orch.log in this mode)
        JOBS = [j for j in JOBS if j[0] not in ("h1", "website")]  # h1: api.hackerone.com; website: ops tokens

    def __init__(self):
        self.data = {}
        self.started = time.time()

    def _loop(self, name, fn, every):
        while True:
            try:
                self.data[name] = fn()
            except Exception as e:
                self.data[name] = self.data.get(name) or {}
                self.data.setdefault("_err", {})[name] = str(e)[:80]
            time.sleep(every)

    def start(self):
        for name, fn, every in self.JOBS:
            threading.Thread(target=self._loop, args=(name, fn, every), daemon=True).start()

    def prime(self):
        """Synchronous first poll of the cheap local sources, so frame one is never 'loading'."""
        for name, fn, _ in self.JOBS:
            if name in ("pm2", "brain", "outcomes", "ships", "events", "traffic", "rescue", "chat", "chatact",
                        "lab", "company", "line", "units"):
                try:
                    self.data[name] = fn()
                except Exception:
                    pass


# ---------- mood / treats (cosmetic; persisted so the floor remembers who got coffee) ----------

TREATS = {"c": ("coffee", 25, "coffee"), "p": ("pizza", 20, "table"),
          "b": ("beer", 15, "fridge"), "j": ("joint", 10, "window")}
TREAT_GLYPH = {"coffee": ("u", 180), "pizza": ("^", 214), "beer": ("U", 221), "joint": ("~", 114)}
DECAY_PER_MIN = 0.3


def load_mood():
    return jload(MOOD_FILE, {})


def mood_of(mood, key):
    row = mood.setdefault(key, {"energy": 80, "last_fed": None, "treat": None, "treat_until": 0})
    if row.get("last_fed"):
        try:
            last = datetime.fromisoformat(row["last_fed"])
            mins = (datetime.now(timezone.utc) - last).total_seconds() / 60
            row["energy"] = max(0, row["energy"] - mins * DECAY_PER_MIN)
            row["last_fed"] = datetime.now(timezone.utc).isoformat()
        except ValueError:
            pass
    else:
        row["last_fed"] = datetime.now(timezone.utc).isoformat()
    return row


def feed_worker(mood, key, treat_key):
    name, boost, _ = TREATS[treat_key]
    row = mood_of(mood, key)
    row["energy"] = min(100, row["energy"] + boost)
    row["last_fed"] = datetime.now(timezone.utc).isoformat()
    row["treat"] = name
    row["treat_until"] = time.time() + 60
    return name


def _chat_turn_age():
    """Seconds since the gnoc chat agent last wrote its session (it saves after every turn)."""
    try:
        return time.time() - max(os.path.getmtime(f) for f in (CHAT_SETTINGS, _chat_session_file()) if f)
    except (OSError, ValueError):
        return float("inf")


def worker_state(name, pm2row, mood_row, brain=None):
    """ONE state per desk, each from a real signal (the legend in the key bar and the ? overlay):
    blocked  the process errored in pm2, or BRAIN's last decision failed (status error, last 30 min)
    stopped  the pm2 process is not running (a cron job resting between runs is idle, not stopped)
    working  a real action in the last 90 s (a BRAIN decision other than wait, a gnoc chat turn) or cpu above 3 %
    paused   online but the global STOP is set (the PROCESSES room only: its work is on hold)
    idle     online, nothing to do right now
    The coffee meter (mood_row) is cosmetic and never changes a desk's state.
    A COMPANY bot row (bots-only mode) takes its state from company.json: probation reads as tired."""
    if pm2row.get("unit"):  # UNITS: decided from the unit's own reading (unit_rows)
        return pm2row.get("ustate") or "idle"
    if pm2row.get("bot"):
        return {"working": "working", "idle": "idle", "probation": "tired", "paused": "paused"}.get(
            pm2row.get("bstate"), "idle")
    if pm2row["status"] == "errored":
        return "error"
    if name == "orch-bot" and brain and brain.get("status") == "error" and _recent(brain.get("ts"), 1800):
        return "error"  # its last decision FAILED in the last 30 min (rejected / fallback are not failures)
    if pm2row["status"] != "online":
        return "idle" if pm2row.get("cron") and pm2row["status"] == "stopped" else "sleeping"
    if name == "orch-bot" and brain and brain.get("action") != "wait" and _recent(brain.get("ts"), 90):
        return "working"
    if name == CHAT_KEY and (CHAT_LIVE or CHAT_TURNS or _chat_turn_age() < 90):
        return "working"  # a tool call is open, a turn is being written, or one was saved in the last 90 s
    if pm2row.get("cpu", 0) and pm2row["cpu"] > 3:
        return "working"
    if _LAST_SEEN.get("stop") and DEPT_OF.get(name) == AUTOMATED:
        return "paused"
    return "idle"


# Rank is a re-framing of a real number (pm2's own process uptime) as a title for a duration bracket.
RANK_BRACKETS = [(3600, "ROOKIE"), (86400, "OPERATIVE"), (604800, "VETERAN"), (float("inf"), "ELITE")]


def rank_for(uptime_ms):
    if not uptime_ms:
        return "ROOKIE", 0.0
    secs = max(0, time.time() - uptime_ms / 1000)
    lo = 0
    for hi, title in RANK_BRACKETS:
        if secs < hi:
            frac = (secs - lo) / (hi - lo) if hi != float("inf") else 1.0
            return title, min(1.0, max(0.0, frac))
        lo = hi
    return "ELITE", 1.0


LABELS = {"orch-bot": "BRAIN", "qwen3:8b": "GPU DESK", "desktop-proxy": "UPLINK",
          "control-panel": "FRONT DESK", "greynoc": "WEBSITE", "greynoc-tunnel": "TUNNEL",
          "greynoc-onion": "ONION", "keepalive": "JANITOR", "oss-bot": "OSS BOT",
          "pipeline-sweep": "PIPELINE", "office-stream": "OFFICE CAM", CHAT_KEY: "GNOC CHAT", "phone-link": "PHONE LINK"}


# The floor plan, laid out the way a security firm actually works, nearest the door first (the packer fills
# left to right, top to bottom, and desk numbers and Tab follow it). Anything not listed lands in GENERAL.
#   GNOC CHAT  the analyst's desk and the machines that answer it. This is where the work is DONE now - the
#              operator works a case with `gnoc chat`, and the laptop GPU, the desktop uplink, the split model,
#              the rig's control panel and the phone are the kit behind that one chair. It is first and it is
#              the biggest room on purpose.
#   WEBSITE    your-site.example: the server, its Cloudflare tunnel, the onion service, the keep-alive
#              watchdog, and the office cam that streams this floor to the site's operator page.
#   PROCESSES  the work that runs without anybody sitting at it: target selection, the scheduled scanners, and
#              the rescue sweep that reopens parked leads. A firm's overnight jobs, not its analysts.
# Everything all three of them do is aimed at one thing, and it is along the bottom of the floor: REPORTS.
OFFICES = [("GNOC CHAT", (CHAT_KEY, "qwen3:8b", "desktop-proxy", "split-llm", "control-panel", "phone-link")),
           ("WEBSITE", ("greynoc", "greynoc-tunnel", "greynoc-onion", "keepalive", "office-stream")),
           ("PROCESSES", ("orch-bot", "oss-bot", "pipeline-sweep"))]
class _CompanyRoom(tuple):
    """COMPANY room membership: the named local roster."""


# THE FLOOR IS THE LINE (bots-only, GreyNOC 2026-10-23: "its super confusing please simplify to make it more
# entertaining"). Four rooms, left to right, in plain words: FRONT DESK (the manager takes jobs in; his desk is
# here), THE FLOOR (one desk per bot, the sign on it is the kind of bug it hunts), THE LAB (where the bots' claims
# are checked) and THE PRESS (reports ready for GreyNOC). Each room has ONE board. Every word on those boards, the
# bots' names, the TODAY strip, the story ticker and the legend come from company.json "screen", built by code in
# scripts/gnoc_company.py; this file draws them and spells as little of that vocabulary as it can (see the CARE
# WITH THE WORDS note above). The line's stations map onto the rooms: 0-3 and the weekly look back at the front
# desk, 4 on the floor, 5-6 in the lab, 7 at the press.
LINE_ROOMS = ("FRONT DESK", "THE FLOOR", "THE LAB", "THE PRESS", "SERVER ROOM")  # SERVER ROOM: the infra racks
ROOM_OF_STATION = {0: "FRONT DESK", 1: "FRONT DESK", 2: "FRONT DESK", 3: "FRONT DESK", 4: "THE FLOOR",
                   5: "THE LAB", 6: "THE LAB", 7: "THE PRESS", 8: "FRONT DESK"}
if BOTS_ONLY:  # COMPANY: the roster bots are the only people; infra is furniture (the SERVERS box)
    OFFICES = [("FRONT DESK", ("orch-bot",)), ("THE FLOOR", _CompanyRoom(COMPANY_BOTS))]
if UNITS:  # UNITS: the manager has an office; the units are found live, so they are not listed here (unit_rows)
    OFFICES = [("MANAGER", ("orch-bot",))]
DEPT_OF = {n: title for title, members in OFFICES for n in members}
# Where each desk sits INSIDE its room. Seating used to fall out of the alphabet, which put the control panel
# at desk 1 and the analyst at desk 6 in its own room; a room now reads in the order the work moves through it.
DESK_SEAT = {n: (di, mi) for di, (_, members) in enumerate(OFFICES) for mi, n in enumerate(members)}
AUTOMATED = "COMPANY" if BOTS_ONLY else ("MANAGER" if UNITS else "PROCESSES")  # the room the global STOP puts on hold; the analyst's desk is never paused by it
WEBSITE_KEY = "greynoc"  # the WEBSITE desk: selecting it turns on the website telemetry feed (d_website)
# offices are darker, calmer carpet than the corridors (so a room reads as a room); each office's identity
# is its wall colour, so the floor never fights the people and desks for attention
ROOM_CARPET = {"COMPANY": ((234, 236), (233, 234)), "FRONT DESK": ((234, 23), (233, 234)),
               "MANAGER": ((234, 23), (233, 234)), "PROD": ((234, 22), (233, 234)),
               "THE FLOOR": ((234, 236), (233, 234)), "THE LAB": ((234, 24), (233, 234)),
               "THE PRESS": ((234, 58), (233, 234)), "SERVER ROOM": ((17, 18), (233, 17)), "PROCESSES": ((234, 235), (233, 234)), "GNOC CHAT": ((234, 17), (233, 234)),
               "WEBSITE": ((234, 22), (233, 234)), "GENERAL": ((235, 236), (234, 235)),
               "WAR ROOM": ((233, 234), (232, 233))}
ROOM_WALL = {"COMPANY": 179, "FRONT DESK": 110, "MANAGER": 110, "PROD": 72, "THE FLOOR": 179, "THE LAB": 117, "THE PRESS": 186,
             "SERVER ROOM": 75, "PROCESSES": 179, "GNOC CHAT": 141, "WEBSITE": 72, "GENERAL": 245, "WAR ROOM": 167}


NICK = {}  # bots-only: bot -> its short name, refreshed from company.json screen (gnoc_company.NAMES)


def label_of(name):
    if UNITS and name in UNIT_LABEL:
        return UNIT_LABEL[name]
    if BOTS_ONLY and name in NICK:
        return NICK[name]
    return LABELS.get(name, name.upper().replace("-", " "))


# ---------- palette + the cell canvas (one compositor for the whole screen) ----------

C_BG, C_PANEL, C_PANEL_HI, C_EDGE = 234, 235, 236, 238
C_TEXT, C_MUTED, C_FAINT, C_BLACK, C_WHITE = 252, 246, 241, 16, 231
C_ACCENT, C_GOOD, C_WARN, C_BAD, C_INFO, C_PINK, C_PURPLE, C_GOLD = 80, 78, 214, 203, 111, 212, 141, 221
A_B, A_D, A_I, A_U, A_R = 1, 2, 4, 8, 16
TAG_COLOR = {"BRAIN": C_PURPLE, "SHIP": C_GOOD, "H1": C_PINK, "HUNT": C_INFO, "OSS": C_ACCENT,
             "PM2": C_WARN, "YOU": C_MUTED, "LAB": C_GOLD, "CHAT": C_PURPLE, "UNIT": C_GOLD, "PROD": 72,
             "STUDIO": C_PINK}
STATE_COLOR = {"working": C_GOOD, "idle": C_ACCENT, "paused": C_WARN, "sleeping": C_FAINT, "error": C_BAD,
               "tired": C_WARN, "party": C_PINK}
# the one visual grammar for desk state: glyph + colour + word ("sleeping" / "error" are the internal names)
STATE_WORD = {"working": "WORKING", "idle": "IDLE", "paused": "PAUSED", "sleeping": "STOPPED", "error": "BLOCKED",
              "tired": "TIRED", "party": "PARTYING"}
STATE_GLYPH = {"working": "▲", "idle": "●", "paused": "‖", "sleeping": "■", "error": "✖", "tired": "●", "party": "●"}
LEGEND_STATES = ("working", "idle", "paused", "sleeping", "error")
SHIRTS = [75, 114, 179, 168, 141, 80, 215, 110, 204, 147, 222, 43, 186, 39]
SKINS = [223, 180, 216, 137, 222, 230]
PANTS = [60, 24, 59, 17, 238, 95]
SPARK = "▁▂▃▄▅▆▇█"

_SGR = {}


def sgr(fg, bg, at):
    key = (fg, bg, at)
    s = _SGR.get(key)
    if s is None:
        codes = ["0"]
        if at & A_B:
            codes.append("1")
        if at & A_D:
            codes.append("2")
        if at & A_I:
            codes.append("3")
        if at & A_U:
            codes.append("4")
        if at & A_R:
            codes.append("7")
        codes += [f"38;5;{fg}", f"48;5;{bg}"]
        s = _SGR[key] = "\x1b[" + ";".join(codes) + "m"
    return s


# PUBLIC MODE, layer 1 for names: every string drawn has the hunt's own program handles (targets/ and the rescue
# ledger) blacked out here, before office-stream's scrubber ever sees the row. Same length, so layout holds.
_PUB = {"re": None, "at": 0.0}


def _pub_names_re():
    if time.time() - _PUB["at"] < 60:
        return _PUB["re"]
    names = set()
    try:
        names.update(n.lower() for n in os.listdir(os.path.join(WS, "targets")) if not n.startswith("."))
    except OSError:
        pass
    for iid, row in jload(LEDGER_FILE, {}).items():
        if isinstance(row, dict) and isinstance(row.get("program"), str):
            names.add(row["program"].lower())
    try:
        own = {w.lower() for w in re.findall(r"[A-Za-z]{3,}", open(os.path.abspath(__file__), errors="ignore").read())}
    except OSError:
        own = set()
    words = set()
    for n in names:
        if len(n) >= 3 and n not in ("readme.md",):
            words.add(n)
        for stem in re.split(r"[^a-z0-9]+", n):
            if len(stem) >= 4 and not stem.isdigit() and stem not in own and stem not in ("bbp", "vdp", "bounty", "public"):
                words.add(stem)
    pat = "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True))
    _PUB["re"] = re.compile(r"(?<![A-Za-z0-9])(?i:" + pat + r")[\w-]*") if pat else None
    _PUB["at"] = time.time()
    return _PUB["re"]


def _pub(s):
    rx = _pub_names_re() if REDACT and len(s) >= 3 else None
    return rx.sub(lambda m: "▒" * len(m.group(0)), s) if rx else s


class Canvas:
    def __init__(self, w, h, bg=C_BG, fg=C_TEXT):
        self.w, self.h = w, h
        self.ch = [[" "] * w for _ in range(h)]
        self.fg = [[fg] * w for _ in range(h)]
        self.bg = [[bg] * w for _ in range(h)]
        self.at = [[0] * w for _ in range(h)]

    def copy(self):
        c = Canvas.__new__(Canvas)
        c.w, c.h = self.w, self.h
        c.ch = [r[:] for r in self.ch]
        c.fg = [r[:] for r in self.fg]
        c.bg = [r[:] for r in self.bg]
        c.at = [r[:] for r in self.at]
        return c

    def put(self, x, y, s, fg=None, bg=None, at=None):
        if not (0 <= y < self.h):
            return
        rc, rf, rb, ra = self.ch[y], self.fg[y], self.bg[y], self.at[y]
        w = self.w
        if REDACT:
            s = _pub(s)
        for i, ch in enumerate(s):
            xx = x + i
            if 0 <= xx < w:
                rc[xx] = ch
                if fg is not None:
                    rf[xx] = fg
                if bg is not None:
                    rb[xx] = bg
                if at is not None:
                    ra[xx] = at

    def fill(self, x, y, w, h, ch=" ", fg=None, bg=None, at=None):
        for yy in range(max(0, y), min(self.h, y + h)):
            self.put(x, yy, ch * w, fg, bg, at)

    def tint(self, x, y, w, h, bg):
        for yy in range(max(0, y), min(self.h, y + h)):
            row = self.bg[yy]
            for xx in range(max(0, x), min(self.w, x + w)):
                row[xx] = bg

    def segs(self, x, y, parts, maxw, bg=None):
        """parts: [(text, fg, attr)]. Clipped to maxw columns from x. Returns the x after the last char."""
        cx, end = x, x + maxw
        for text, fg, at in parts:
            room = end - cx
            if room <= 0:
                break
            text = str(text)[:room]
            self.put(cx, y, text, fg, bg, at)
            cx += len(text)
        return cx

    def blit(self, other, ox, oy):
        for y in range(other.h):
            ty = oy + y
            if not (0 <= ty < self.h):
                continue
            x0, x1 = max(0, -ox), min(other.w, self.w - ox)
            if x1 <= x0:
                continue
            self.ch[ty][ox + x0:ox + x1] = other.ch[y][x0:x1]
            self.fg[ty][ox + x0:ox + x1] = other.fg[y][x0:x1]
            self.bg[ty][ox + x0:ox + x1] = other.bg[y][x0:x1]
            self.at[ty][ox + x0:ox + x1] = other.at[y][x0:x1]

    def frame(self, x, y, w, h, fg, bg=None, title=None, title_fg=None, heavy=False):
        tl, tr, bl, br, hz, vt = ("┏", "┓", "┗", "┛", "━", "┃") if heavy else ("╭", "╮", "╰", "╯", "─", "│")
        self.put(x, y, tl + hz * (w - 2) + tr, fg, bg)
        for yy in range(y + 1, y + h - 1):
            self.put(x, yy, vt, fg, bg)
            self.put(x + w - 1, yy, vt, fg, bg)
        self.put(x, y + h - 1, bl + hz * (w - 2) + br, fg, bg)
        if title:
            self.put(x + 2, y, f" {title} ", title_fg or fg, bg, A_B)

    def lines(self, color=True):
        out = []
        for y in range(self.h):
            if not color:
                out.append("".join(self.ch[y]).rstrip())
                continue
            rc, rf, rb, ra = self.ch[y], self.fg[y], self.bg[y], self.at[y]
            parts, last = [], None
            for x in range(self.w):
                st = (rf[x], rb[x], ra[x])
                if st != last:
                    parts.append(sgr(*st))
                    last = st
                parts.append(rc[x])
            parts.append("\x1b[0m")
            out.append("".join(parts))
        return out


def sparkline(vals, width, floor=0):
    """floor: the smallest full-scale value (cpu sparklines pass 10, so 0.3 % reads as flat, not as full bars)."""
    vals = [v for v in list(vals)[-width:]]
    if not vals:
        return " " * width
    m = max(max(vals), floor) or 1
    s = "".join(SPARK[min(7, int(v / m * 7.999))] if v > 0 else "▁" for v in vals)
    return s.rjust(width)


def meter(frac, width, full="█", empty="░"):
    n = int(round(max(0.0, min(1.0, frac)) * width))
    return full * n + empty * (width - n)


# ---------- the scene: room geometry, furniture, walkable mask (rebuilt only when the room resizes) ----------

WALL_H, STRIP_H, DESK_W, DESK_DW = 5, 8, 15, 18


def time_of_day(hour=None):
    h = datetime.now().hour if hour is None else hour
    if 8 <= h < 17:
        return "day"
    if 6 <= h < 8 or 17 <= h < 20:
        return "dusk"
    return "night"


class Scene:
    def __init__(self, MW, MH, n_desks, n_hosts, names=()):
        self.MW, self.MH, self.n_desks, self.n_hosts = MW, MH, n_desks, n_hosts
        self.names = tuple(names)
        ft = self.ft = WALL_H
        sy = self.sy = MH - STRIP_H
        self.right_w = 30 if MW >= 100 and not BOTS_ONLY and not UNITS else 0  # bots-only: the servers are a small box
        rx = self.rx = MW - self.right_w if self.right_w else MW - 1
        self.rooms, self.war = [], None  # offices: [(title, x, y, w, h)]; war: (x, y, w, h) or None
        self.boards = {}  # bots-only: room title -> (x, y, w, h) of that room's one board
        # UNITS: furniture nobody walks through, the manager's out-tray, PROD's consoles and visitor seats
        self.extra_blocks, self.mgr_tray, self.prod_consoles, self._prod_seats = [], None, None, []
        names_ = list(self.names) or [f"desk{i}" for i in range(n_desks)]
        lay = (self._units_layout(names_, ft, sy, rx) if UNITS else
               self._line_layout(names_, ft, sy, rx) if BOTS_ONLY else self._offices(names_, ft, sy, rx))
        if lay:
            self.DH, self.desks, self.rooms, self.war = lay
            self.block = None
        else:  # too small for walled offices: the original open-plan floor
            area_x0, area_x1 = 3, rx - 3
            area_w = area_x1 - area_x0
            avail = sy - (ft + 2) - 1
            pitch = DESK_DW
            self.cols = max(1, (area_w + pitch - DESK_W) // pitch)
            rows = max(1, -(-max(1, n_desks) // self.cols))
            if rows * 6 > avail:  # the desks would run into the break room: close the aisles to one column
                pitch = DESK_W + 1
                self.cols = max(1, (area_w + pitch - DESK_W) // pitch)
                rows = max(1, -(-max(1, n_desks) // self.cols))
            self.DH = max(6, min(10, avail // rows))  # a taller room spreads the pods out instead of leaving dead floor
            self.desk_y0 = ft + 2 + max(0, (avail - rows * self.DH + (self.DH - min(6, self.DH - 1))) // 2)
            used = min(self.cols, max(1, n_desks)) * pitch - (pitch - DESK_W)
            x0 = area_x0 + max(0, (area_w - used) // 2)
            self.block = (x0, self.desk_y0, used, rows * self.DH)
            self.desks = [(x0 + (i % self.cols) * pitch, self.desk_y0 + (i // self.cols) * self.DH)
                          for i in range(n_desks)]
        self.spark = self.DH >= 7
        self.block_rows = 6 if self.spark else 5
        self.doors = [(x + 3, y + self.block_rows) for x, y in self.desks]

        # walkable mask over FEET cells: floor yes, walls / furniture no
        mask = [[False] * MW for _ in range(MH)]
        for y in range(ft, sy):
            for x in range(1, rx if self.right_w else MW - 1):
                mask[y][x] = True
        for y in range(sy + 1, MH - 1):
            for x in range(1, MW - 1):
                mask[y][x] = True
        self.mask = mask

        def block(x, y, w, h):
            for yy in range(max(0, y), min(MH, y + h)):
                for xx in range(max(0, x), min(MW, x + w)):
                    mask[yy][xx] = False

        def free(x, y, w, h):
            for yy in range(max(0, y), min(MH, y + h)):
                for xx in range(max(0, x), min(MW, x + w)):
                    mask[yy][xx] = True
        self._free = free
        for x, y in self.desks:
            block(x, y, DESK_W, self.block_rows)
        # office walls are solid except a 3-cell door in the middle of the bottom wall
        for _, rx0, ry0, rw, rh in self.rooms + ([("WAR", *self.war)] if self.war else []):
            block(rx0, ry0, rw, 1)
            block(rx0, ry0 + rh - 1, rw, 1)
            block(rx0, ry0, 1, rh)
            block(rx0 + rw - 1, ry0, 1, rh)
            free(rx0 + rw // 2 - 1, ry0 + rh - 1, 3, 1)
        boxes = self.rooms + ([("WAR", *self.war)] if self.war else [])
        for _, ax, ay, aw, ah in boxes:  # close the gap column between two side-by-side offices
            for _, bx, by, bw, bh in boxes:
                if bx == ax + aw + 1 and by == ay:
                    block(ax + aw, ay, 1, min(ah, bh))
        for bx_, by_, bw_, bh_ in self.boards.values():  # a room board is a wall, nobody walks through it
            block(bx_, by_, bw_, bh_)
        for b in self.extra_blocks:
            block(*b)
        if self.war:  # a display room: the board fills it and nobody walks in (a 3-row sprite covered the board)
            block(*self.war)
            if BOTS_ONLY and line_board_box(self)[3] >= 3:  # THE LINE board hangs on the floor under it
                block(*line_board_box(self))
        # potted plants flanking the desk block, where there is room for them (open plan only)
        self.plants = []
        if self.block:
            bx0, by0, bw, bh = self.block
            for px, py in ((bx0 - 5, by0), (bx0 + bw + 2, by0), (bx0 - 5, by0 + bh - 4), (bx0 + bw + 2, by0 + bh - 4)):
                if px >= 2 and px + 3 < rx - 1 and ft + 1 <= py and py + 3 < sy - 1 and (px, py) not in self.plants:
                    self.plants.append((px, py))
                    block(px, py, 3, 3)

        # bottom strip: break room (left), standup table (middle), mail room (right)
        fy = sy + 4  # fixtures occupy sy+4 .. sy+6, labels on sy+3, bottom wall on MH-1
        self.fix = {}
        bx = 3
        self.fix["coffee"] = (bx, fy, 4)
        self.fix["fridge"] = (bx + 7, fy, 4)
        self.fix["cooler"] = (bx + 15, fy, 3)
        self.fix["plant_b"] = (bx + 22, fy, 3)
        self.fix["cabinet"] = (MW - 9, fy, 5)
        self.fix["shredder"] = (MW - 18, fy, 7)
        self.fix["tray"] = (MW - 27, fy, 7)
        self.fix["printer"] = (MW - 36, fy, 6)
        left_end, right_start = bx + 26, MW - 38
        tw = min(24, right_start - left_end - 6)
        self.table = None
        if tw >= 10:
            tx = left_end + (right_start - left_end - tw) // 2
            self.table = (tx, sy + 4, tw)
        for name, (x, y, w) in self.fix.items():
            if not name.startswith("plant"):
                block(x, y, w, 3)
        if self.table:
            tx, ty, tw = self.table
            block(tx, ty, tw, 2)
        # partition with three door gaps
        self.gaps = [bx + 10, (self.table[0] + self.table[2] // 2) if self.table else MW // 2, MW - 22]
        self.spots = {}
        for name in ("coffee", "fridge", "cooler", "cabinet", "shredder", "tray", "printer"):
            x, y, w = self.fix[name]
            self.spots[name] = [(x + w // 2 + d, sy + 3) for d in (-1, 0, 1)]
        if self.table:
            tx, ty, tw = self.table
            self.spots["table"] = [(tx + 1 + 3 * i, sy + 3) for i in range(max(1, tw // 3))]
            # sprites are 5 wide: seats every 6 columns, a second standing row behind, one at each end
            self.meeting = ([(tx + 3 + 6 * i, sy + 3) for i in range(max(1, (tw - 2) // 6))] +
                            [(tx - 4, sy + 5), (tx + tw + 3, sy + 5)] +
                            [(tx + 6 * i, sy + 1) for i in range(max(1, tw // 6 + 1))] +
                            [(tx - 4, sy + 2), (tx + tw + 3, sy + 2)])
        else:
            mid = MW // 2
            self.spots["table"] = [(mid, sy + 3)]
            self.meeting = [(mid - 12 + 3 * i, sy + 3) for i in range(9)]
        self.spots["window"] = [(x, ft + 1) for x in range(8, max(9, rx - 8), 9)]
        for title, key in (("FRONT DESK", "front"), ("THE LAB", "lab"), ("THE PRESS", "press")):
            box = next(((x, y, w, h) for t_, x, y, w, h in self.rooms if t_ == title), None)
            if box:   # where a bot stands when it brings a folder to that room: open floor under the board
                bx_, by_, bw_, bh_ = box
                top_ = by_ + 1 + (self.boards[title][3] if title in self.boards else 0) + 2
                self.spots[key] = [(xx, yy) for yy in range(top_ + 2, by_ + bh_ - 2, 3)
                                   for xx in range(bx_ + 4, bx_ + bw_ - 4, 6) if mask[yy][xx]][:8]
        if UNITS:  # where a unit serving a website-analysis job sits in PROD
            self.spots["prod"] = [c for c in self._prod_seats if 0 <= c[1] < MH and mask[c[1]][c[0]]][:6]

        # right column: boss office (top) + server room (below)
        self.boss_home = None
        self.racks = []
        if self.right_w:
            for y in range(ft, sy):
                mask[y][rx] = False
            self.office_bottom = ft + 9
            for x in range(rx, MW):
                mask[self.office_bottom][x] = False
            for y in range(ft, self.office_bottom):
                for x in range(rx + 1, MW - 1):
                    mask[y][x] = True
            self.boss_door = (ft + 4, ft + 7)  # rows of the gap in the office's left wall
            for y in range(*self.boss_door):
                mask[y][rx] = True
            block(rx + 9, ft + 4, 14, 2)  # boss desk
            self.boss_home = (rx + 16, ft + 7)
            self.boss_seat = (rx + 14, ft + 2)
            sx0, sy0 = rx + 2, self.office_bottom + 2
            per_row = max(1, (self.right_w - 3) // 13)
            for i in range(n_hosts):
                r, cidx = divmod(i, per_row)
                self.racks.append((sx0 + cidx * 13, sy0 + r * 7))
        self.windows = []
        self.wb = None
        self.clock = None
        self._layout_wall()
        self.bases = {}
        self.crac = None

    def _offices(self, names, ft, sy, rx):
        """Group desks into walled offices by what the process does (OFFICES), shelf-packed left to right, top
        to bottom, with a corridor row under each shelf. Leftover space becomes the WAR ROOM (the chat + log
        board). Returns None when even the tightest packing does not fit; the caller falls back to open plan."""
        groups, used = [], set()
        for title, members in OFFICES:
            idx = [i for i, n in enumerate(names) if n in members]
            if idx:
                groups.append((title, idx))
                used.update(idx)
        rest = [i for i in range(len(names)) if i not in used]
        if rest:
            groups.append(("GENERAL", rest))
        if not groups:
            return None
        import itertools
        ax0, ax1 = 3, rx - 2
        AW = ax1 - ax0
        top, bottom = ft + 2, sy - 2  # sy - 1 stays a corridor along the break-room partition
        best = None
        for DH in (8, 7, 6):
            # every per-office column count (1-3 desks wide): a fixed count left 160x50 with no fit at all
            for cs in itertools.product(*[range(1, min(3, len(idx)) + 1) for _, idx in groups]):
                rooms = []
                for (title, idx), c in zip(groups, cs):
                    r = -(-len(idx) // c)
                    # +3 rows: two walls and a headroom row, so a desk's speech bubble never covers the room name
                    rooms.append((title, idx, c, r, c * DESK_DW - (DESK_DW - DESK_W) + 4, r * DH + 3))
                if any(rm[4] > AW for rm in rooms):
                    continue
                shelves, cur, cw = [], [], 0
                for rm in rooms:
                    need = rm[4] + (1 if cur else 0)
                    if cur and cw + need > AW:
                        shelves.append(cur)
                        cur, cw, need = [], 0, rm[4]
                    cur.append(rm)
                    cw += need
                shelves.append(cur)
                H = sum(max(rm[5] for rm in sh) for sh in shelves) + len(shelves) - 1
                if H > bottom - top + 1:
                    continue
                desks = [None] * len(names)
                out, spare, y = [], [], top
                for sh in shelves:
                    shh, x = max(rm[5] for rm in sh), ax0
                    for title, idx, c, r, w, h in sh:
                        out.append((title, x, y, w, h))
                        for k, i in enumerate(idx):
                            desks[i] = (x + 2 + (k % c) * DESK_DW, y + 2 + (k // c) * DH)
                        x += w + 1
                    if ax1 - x >= 36 and shh >= 8:
                        spare.append((x + 1, y, ax1 - x - 1, shh))
                    y += shh + 1
                if bottom - y + 1 >= 7:
                    spare.append((ax0, y, AW, bottom - y + 1))
                war = max(spare, key=lambda r: r[2] * r[3]) if spare else None
                if war:
                    war = (war[0], war[1], min(war[2], 110), min(war[3], 18))
                # a war room first (the chat board), then taller desk rows (sparklines), then a bigger board
                score = (war is not None, DH, (war[2] * war[3]) if war else 0, -len(shelves))
                if best is None or score > best[0]:
                    best = (score, (DH, desks, out, war))
        if best:
            return best[1]
        return None

    def _line_layout(self, names, ft, sy, rx):
        """Bots-only: the four rooms side by side, full height, one board at the top of each. FRONT DESK holds the
        manager's desk (names[0]), THE FLOOR one desk per bot in a grid, THE LAB and THE PRESS a board and open
        floor. Returns (DH, desks, rooms, None) or None when it does not fit (the caller falls back to open plan)."""
        ax0, ax1 = 3, rx - 2
        AW = ax1 - ax0
        top, bottom = ft + 2, sy - 2
        H = bottom - top + 1
        side = max(22, min(34, AW // 6))
        front_w = max(DESK_W + 6, side)
        floor_w = AW - front_w - 3 * side - 4
        if floor_w < DESK_W + 4:
            return None
        nf = max(1, len(names) - 1)
        cols = max(1, (floor_w - 4 + DESK_DW - DESK_W) // DESK_DW)
        rows = -(-nf // cols)
        for DH, bl in [(d, b) for d in (8, 7) for b in (6, 5, 4, 3)] + [(6, b) for b in (6, 5, 4, 3, 2)]:
            brows = 6 if DH >= 7 else 5
            need = 2 + (bl + 1) + 1 + (rows - 1) * DH + brows + 1
            if need <= H:
                break
        else:
            return None
        ws = [front_w, floor_w, side, side, side]
        xs = [ax0]
        for w_ in ws[:-1]:
            xs.append(xs[-1] + w_ + 1)
        rooms = [(t_, x, top, w, H) for t_, x, w in zip(LINE_ROOMS, xs, ws)]
        self.boards = {t_: (x + 1, top + 1, w - 2, bl + 1) for t_, x, _, w, _ in rooms if t_ != "SERVER ROOM"}
        y0 = top + 1 + bl + 1 + 1
        desks = [None] * len(names)
        desks[0] = (xs[0] + max(2, (front_w - DESK_W) // 2), y0)
        used = min(cols, nf) * DESK_DW - (DESK_DW - DESK_W)
        fx0 = xs[1] + 2 + max(0, (floor_w - 4 - used) // 2)
        for k in range(1, len(names)):
            i = k - 1
            desks[k] = (fx0 + (i % cols) * DESK_DW, y0 + (i // cols) * DH)
        return DH, desks, rooms, None

    def _units_layout(self, names, ft, sy, rx):
        """UNITS: four rooms side by side, full height. MANAGER (orch-bot's desk, its board, the out-tray beside the
        desk), THE FLOOR (one desk per processing unit, names[1:]), PROD (the website board, one console per site
        process, seats for a visiting unit) and the SERVER ROOM (the other services, one LED row each). Returns
        (DH, desks, rooms, None), or None when it does not fit (the caller falls back to the open plan)."""
        ax0, ax1 = 3, rx - 2
        AW = ax1 - ax0
        top, bottom = ft + 2, sy - 2
        H = bottom - top + 1
        side = max(22, min(30, AW // 7))
        mgr_w = max(DESK_W + 10, side)
        prod_w = max(34, min(52, AW // 4))
        floor_w = AW - mgr_w - prod_w - side - 3
        if floor_w < DESK_W + 4:
            return None
        nf = max(1, len(names) - 1)
        cols = max(1, (floor_w - 4 + DESK_DW - DESK_W) // DESK_DW)
        rows = -(-nf // cols)
        for DH, bl in [(d, b) for d in (8, 7) for b in (6, 5, 4, 3)] + [(6, b) for b in (6, 5, 4, 3, 2)]:
            brows = 6 if DH >= 7 else 5
            if 2 + (bl + 1) + 1 + (rows - 1) * DH + brows + 1 <= H:
                break
        else:
            return None
        ws = [mgr_w, floor_w, prod_w, side]
        xs = [ax0]
        for w_ in ws[:-1]:
            xs.append(xs[-1] + w_ + 1)
        rooms = [(t_, x, top, w, H) for t_, x, w in zip(UNIT_ROOMS, xs, ws)]
        pb = min(9, max(bl, H // 3))  # PROD's board is the point of the room: it gets the rows
        if top + 1 + pb + 1 + len(PROD_PROCS) + 2 > top + H - 2:
            pb = bl
        self.boards = {"MANAGER": (xs[0] + 1, top + 1, mgr_w - 2, bl + 1),
                       "THE FLOOR": (xs[1] + 1, top + 1, floor_w - 2, bl + 1),
                       "PROD": (xs[2] + 1, top + 1, prod_w - 2, pb + 1)}
        y0 = top + 1 + bl + 1 + 1
        desks = [None] * len(names)
        desks[0] = (xs[0] + 2, y0)
        self.mgr_tray = (xs[0] + 2 + DESK_W + 2, y0 + 1)
        self.extra_blocks.append((*self.mgr_tray, 5, 3))
        used = min(cols, nf) * DESK_DW - (DESK_DW - DESK_W)
        fx0 = xs[1] + 2 + max(0, (floor_w - 4 - used) // 2)
        for k in range(1, len(names)):
            i = k - 1
            desks[k] = (fx0 + (i % cols) * DESK_DW, y0 + (i // cols) * DH)
        cy = top + 1 + pb + 1 + 1
        self.prod_consoles = (xs[2] + 2, cy, prod_w - 4, len(PROD_PROCS))
        self.extra_blocks.append(self.prod_consoles)
        seat0 = cy + len(PROD_PROCS) + 3  # a seat is a sprite's feet: its label row and 3 sprite rows above it
        sb_y = cy + len(PROD_PROCS) + 1
        if sb_y + 4 + 3 < top + H - 1:  # STUDIO (title + 3 lines) under the consoles, and still one row of seats
            self.boards["STUDIO"] = (xs[2] + 1, sb_y, prod_w - 2, 4)
            seat0 = sb_y + 4 + 3
        self._prod_seats = [(xx, yy) for yy in range(seat0, top + H - 1, 4)
                            for xx in range(xs[2] + 4, xs[2] + prod_w - 3, 7)]
        return DH, desks, rooms, None

    def in_room(self, x, y):
        return any(rx0 <= x < rx0 + rw and ry0 <= y < ry0 + rh
                   for _, rx0, ry0, rw, rh in self.rooms + ([("WAR", *self.war)] if self.war else []))

    def _layout_wall(self):
        MW = self.MW
        wbw = max(30, min(58, MW // 3))
        wbx = max(14, (self.rx - wbw) // 2)
        self.wb = (wbx, 1, wbw)
        self.clock = (wbx + wbw + 3, 1)
        occupied = [(0, 13), (wbx - 2, wbx + wbw + 1), (self.clock[0] - 1, self.clock[0] + 8)]
        x = 15
        while x + 12 < MW - 2:
            if all(x + 12 < a or x > b for a, b in occupied):
                self.windows.append(x)
                x += 16
            else:
                x += 1

    def walkable(self, x, y):
        return 0 <= y < self.MH and 0 <= x < self.MW and self.mask[y][x]

    def path(self, start, goal):
        if start == goal:
            return []
        if not self.walkable(*goal):
            return None
        sx, sy = start
        if not self.walkable(sx, sy):
            return None
        prev = {start: None}
        q = deque([start])
        W, H, mask = self.MW, self.MH, self.mask
        while q:
            cur = q.popleft()
            if cur == goal:
                break
            x, y = cur
            for nx, ny in ((x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)):
                if 0 <= nx < W and 0 <= ny < H and mask[ny][nx] and (nx, ny) not in prev:
                    prev[(nx, ny)] = cur
                    q.append((nx, ny))
        if goal not in prev:
            return None
        out, cur = [], goal
        while cur != start:
            out.append(cur)
            cur = prev[cur]
        return out[::-1]

    # ----- the static layer (walls, carpet, furniture frames), cached per time of day -----

    def base(self, tod):
        b = self.bases.get(tod)
        if b is None:
            b = self.bases[tod] = self._build_base(tod)
        return b

    def _build_base(self, tod):
        MW, MH, ft, sy = self.MW, self.MH, self.ft, self.sy
        dark = tod == "night"
        carpet = (236, 237) if not dark else (234, 235)
        cv = Canvas(MW, MH, bg=carpet[0])
        for y in range(ft, MH):
            row = cv.bg[y]
            for x in range(MW):
                row[x] = carpet[1] if (x * 3 + y * 7) % 23 == 0 else carpet[0]  # a sparse weave, not a checkerboard
        # back wall
        wall = 239 if not dark else 237
        cv.fill(0, 0, MW, WALL_H - 1, " ", bg=wall)
        cv.put(0, 0, "▀" * MW, fg=242 if not dark else 239, bg=wall)
        cv.put(0, WALL_H - 1, "▀" * MW, fg=wall, bg=carpet[0])
        for y in range(ft, sy):  # baseboard shadow under the wall
            pass
        cv.put(0, ft, "░" * MW, fg=carpet[1] + 1)
        # light through the windows: sun by day, moon by night, a widening patch on the carpet
        for wx in self.windows:
            for r in range(4):
                for x in range(wx - r, wx + 12 + r):
                    if 1 <= x < (self.rx if self.right_w else MW - 1) and ft + r < sy:
                        cv.bg[ft + r][x] = cv.bg[ft + r][x] + 2
        # offices: their own carpet, thin walls, a name on the top wall, a door gap at the bottom
        for title, rx0, ry0, rw, rh in self.rooms + ([("WAR ROOM", *self.war)] if self.war else []):
            pair = ROOM_CARPET.get(title, ((235, 236), (233, 234)))[1 if dark else 0]
            for yy in range(ry0 + 1, ry0 + rh - 1):
                for xx in range(rx0 + 1, rx0 + rw - 1):
                    cv.bg[yy][xx] = pair[1] if (xx * 5 + yy * 3) % 29 == 0 else pair[0]
            wc = ROOM_WALL.get(title, 245) if not dark else 240
            cv.put(rx0, ry0, "┌" + "─" * (rw - 2) + "┐", wc)
            for yy in range(ry0 + 1, ry0 + rh - 1):
                cv.put(rx0, yy, "│", wc)
                cv.put(rx0 + rw - 1, yy, "│", wc)
            gap = rx0 + rw // 2 - 1
            door = "   " if title != "WAR ROOM" else "───"  # the war room is a display room, no door
            cv.put(rx0, ry0 + rh - 1, "└" + "─" * (gap - rx0 - 1) + door + "─" * (rx0 + rw - 2 - gap - 2) + "┘", wc)
            cv.put(rx0 + 2, ry0, f"┤ {title} ├", C_GOLD if title == "WAR ROOM" else C_TEXT, None, A_B)
        # side walls
        for y in range(WALL_H, MH):
            cv.put(0, y, "▌", fg=wall)
            cv.put(MW - 1, y, "▐", fg=wall)
        # logo sign
        cv.frame(1, 1, 12, 3, C_ACCENT, bg=233, heavy=True)
        cv.put(2, 2, " G N O C  ", C_ACCENT, 233, A_B)
        # windows (frames only; the sky is dynamic)
        for wx in self.windows:
            cv.put(wx, 0, "▁" * 12, fg=250, bg=wall)
            cv.put(wx, WALL_H - 1, "▀" * 12, fg=250, bg=carpet[0])
        # whiteboard frame + marker tray
        wbx, wby, wbw = self.wb
        cv.fill(wbx - 1, wby - 1, wbw + 2, 4, " ", bg=244)
        cv.put(wbx, WALL_H - 1, "▀" * wbw, fg=244, bg=carpet[0])
        # clock frame
        cx, cy = self.clock
        cv.frame(cx, cy - 1 if cy > 0 else 0, 9, 3, 245, bg=233)
        # bottom strip: partition, tiles, zone labels
        cv.put(1, sy, "▄" * (MW - 2), fg=241, bg=carpet[0])
        for g in self.gaps:
            for d in (-1, 0, 1):
                cv.put(g + d, sy, " ")
                self.mask[sy][g + d] = True
        tile = (238, 239) if not dark else (236, 237)
        bx_end = self.fix["plant_b"][0] + 4
        for y in range(sy + 1, MH - 1):
            for x in range(1, bx_end):
                cv.bg[y][x] = tile[(x + y) % 2]
        cv.put(1, MH - 1, "▀" * (MW - 2), fg=wall, bg=233)
        cv.put(3, sy, " BREAK ROOM ", C_MUTED, carpet[0], A_B)
        if self.table:
            tx, ty, tw = self.table
            # the same table is the LAB BENCH while a lead is actually being worked on it (the white coats
            # sit here), so it is labelled for whichever it is right now
            with LOCK:
                in_lab = bool(LAB)
            tag = " STANDUP " if BOTS_ONLY else (" LAB BENCH " if in_lab else " STANDUP ")
            cv.put(tx + tw // 2 - len(tag) // 2, sy, tag, C_GOLD if in_lab else C_MUTED, carpet[0], A_B)
        cv.put(self.fix["printer"][0], sy, " REPORTS ", C_MUTED, carpet[0], A_B)
        # fixtures
        x, y, _ = self.fix["coffee"]
        cv.put(x, y, "╓──╖", 245)
        cv.put(x, y + 1, "║  ║", 245)
        cv.put(x, y + 2, "╙┬┬╜", 245)
        cv.put(x - 1, y - 1, "COFFEE", C_FAINT)
        x, y, _ = self.fix["fridge"]
        cv.fill(x, y, 4, 3, " ", bg=250)
        cv.put(x, y, "  ▪ ", 240, 250)
        cv.put(x, y + 1, "▔▔▔▔", 244, 250)
        cv.put(x, y + 2, "  ▪ ", 240, 250)
        cv.put(x - 1, y - 1, "FRIDGE", C_FAINT)
        x, y, _ = self.fix["cooler"]
        cv.put(x, y, "▗█▖", 117)
        cv.put(x, y + 1, "▐▒▌", 252)
        cv.put(x, y + 2, "▝▀▘", 248)
        cv.put(x - 1, y - 1, "COOLER", C_FAINT)
        for x, y in [self.fix["plant_b"][:2]] + self.plants:
            cv.put(x, y, "\\|/", 71)
            cv.put(x, y + 1, "-*-", 71 if (x + y) % 2 else 107)
            cv.put(x, y + 2, "(_)", 130)
        if self.table:
            tx, ty, tw = self.table
            cv.put(tx, ty, "▄" * tw, 137)
            cv.fill(tx, ty + 1, tw, 1, "▀", fg=94)
            for i in range(tw // 3):
                cv.put(tx + 2 + 3 * i, ty + 2, "▘▝"[i % 2], 240)
        x, y, _ = self.fix["printer"]
        cv.put(x, y, "┌────┐", 247)
        cv.put(x, y + 1, "│▀▀▀▀│", 247)
        cv.put(x, y + 2, "└────┘", 247)
        cv.put(x - 1, y - 1, "PRINTER", C_FAINT)
        x, y, _ = self.fix["cabinet"]
        cv.put(x, y, "┌───┐", 180)
        cv.put(x, y + 1, "│▤▤▤│", 180)
        cv.put(x, y + 2, "└───┘", 180)
        cv.put(x - 1, y - 1, "FILES", C_FAINT)
        # desks
        for i, (x, y) in enumerate(self.desks):
            bezel = 238 if not dark else 236
            cv.put(x + 8, y, "▗▄▄▄▄▖", bezel)                     # monitor: bezel top
            cv.put(x + 8, y + 1, "▐", bezel)                      # screen cells x+9..x+12 are drawn live
            cv.put(x + 13, y + 1, "▌", bezel)
            wood = 137 if not dark else 94
            edge = 173 if not dark else 130                      # the lit top edge of the desk
            cv.fill(x, y + 2, DESK_W, 1, " ", bg=wood)
            cv.put(x, y + 2, "▔" * DESK_W, edge, wood)
            cv.put(x + 10, y + 2, "▀▀", bezel, wood)              # monitor stand on the desk
            cv.put(x + 2, y + 2, "▃▃▃", 250, wood)                # keyboard
            front = 94 if not dark else 52
            cv.put(x, y + 3, "▀" * DESK_W, front)                 # desk front, in shadow
            cv.put(x + 1, y + 3, "▐", 236)                        # legs
            cv.put(x + DESK_W - 2, y + 3, "▌", 236)
            cv.put(x + 9, y + 3, "▀▀▀", 130 if not dark else 94)  # drawer
        # right column
        if self.right_w:
            rx = self.rx
            obot = self.office_bottom
            rug = 52 if not dark else 233
            for y in range(ft, obot):
                for x in range(rx + 1, MW - 1):
                    cv.bg[y][x] = rug if (x + y) % 2 == 0 else (rug + 1 if not dark else 234)
            for y in range(ft, sy):
                cv.put(rx, y, "█", 242)
            for y in range(*self.boss_door):
                cv.put(rx, y, " ", bg=carpet[0])
            cv.put(rx, obot, "█" * (MW - rx), 242)
            cv.fill(rx + 9, ft + 4, 14, 1, "▄", fg=130)
            cv.fill(rx + 9, ft + 5, 14, 1, "▀", fg=94)
            cv.put(rx + 2, ft + 1, " BOSS ", C_GOLD, 233, A_B)
            cv.put(MW - 5, ft + 6, "\\|/", 71)
            cv.put(MW - 5, ft + 7, "(_)", 130)
            srv = 17 if not dark else 233
            cv.fill(rx + 1, obot + 1, MW - rx - 2, sy - obot - 1, " ", bg=srv)
            for y in range(obot + 1, sy):  # raised-floor tiles
                for x in range(rx + 1, MW - 1):
                    if (x - rx) % 6 == 0 and (y - obot) % 3 == 0:
                        cv.put(x, y, "+", 19 if not dark else 236, srv)
            if sy - obot > 12:  # the cooling unit along the bottom of the server room
                cy = sy - 4
                cv.put(rx + 3, cy, "┌" + "─" * 20 + "┐", 244, srv)
                cv.put(rx + 3, cy + 1, "│" + " " * 20 + "│", 244, 236)
                cv.put(rx + 3, cy + 2, "└" + "─" * 20 + "┘", 244, srv)
                cv.put(rx + 3 + 7, cy + 1, " CRAC ", 250, 236, A_B)
                self.crac = (rx + 4, cy + 1)
            cv.put(rx + 2, obot, " SERVER ROOM ", C_INFO, 233, A_B)
            for i, (x, y) in enumerate(self.racks):
                if y + 5 >= sy:
                    break
                cv.put(x, y, "┌" + "─" * 10 + "┐", 245, srv)
                cv.put(x, y + 1, "│" + " " * 10 + "│", 245, 233)
                cv.put(x, y + 2, "│" + " " * 10 + "│", 245, 233)
                cv.put(x, y + 3, "└" + "─" * 10 + "┘", 245, srv)
        return cv


# ---------- walkers: a worker leaves its desk door, follows a real shortest path, holds, comes back ----------

class Walker:
    __slots__ = ("pos", "phase", "path", "dest", "kind", "hold_until", "carry", "home", "last_bubble", "bubble",
                 "task", "leg", "bring")

    def __init__(self, home):
        self.home = home
        self.pos = home
        self.phase = "seated"
        self.path = []
        self.dest = None
        self.kind = None
        self.hold_until = 0
        self.carry = None
        self.last_bubble = None
        self.bubble = None  # a bubble shown while on the trip (flavor or real)
        self.task = None    # a paper trip from HANDOFFS: {"legs": [(dest, doc)], "label", "bring", "at"}
        self.leg = 0
        self.bring = None   # a paper fetched on the trip, put on the own desk once seated

    def send(self, scene, dest, kind, hold=3.0, carry=None):
        if self.phase not in ("seated", "hold"):
            return False
        p = scene.path(self.pos, dest)
        if p is None:
            return False
        self.path, self.dest, self.kind, self.phase = p, dest, kind, "walk"
        self.hold_until = hold
        self.carry = carry
        return True

    def go_home(self, scene):
        p = scene.path(self.pos, self.home)
        if p is None:
            self.snap()
            return
        self.path, self.phase = p, "return"

    def snap(self):
        self.pos, self.phase, self.path, self.kind, self.carry = self.home, "seated", [], None, None
        self.task, self.bring = None, None

    def step(self, scene):
        if self.phase in ("walk", "return"):
            for _ in range(2):
                if not self.path:
                    break
                nxt = self.path.pop(0)
                horiz = nxt[1] == self.pos[1]
                self.pos = nxt
                if not horiz or not self.path or self.path[0][1] != nxt[1]:
                    break
            if not self.path:
                if self.phase == "walk":
                    self.phase = "hold"
                    self.hold_until = time.time() + (self.hold_until if self.hold_until < 1e6 else 3)
                else:
                    self.phase = "seated"
                    self.kind = None
                    self.carry = None
        elif self.phase == "hold" and self.kind != "meeting" and time.time() >= self.hold_until:
            if self.kind in ("coffee", "table", "fridge", "window") and self.carry:
                pass  # keep carrying the treat home
            self.go_home(scene)


HAIRS = [94, 178, 130, 248, 137, 173, 101, 180]  # all readable on the night carpet (near-black hair vanished)
CHAIR = 239


def hair_for(name):
    return HAIRS[sum(ord(c) * (i + 3) for i, c in enumerate(name)) % len(HAIRS)]


def look_for(name):
    h = sum(ord(c) * (i + 1) for i, c in enumerate(name))
    return SHIRTS[h % len(SHIRTS)], SKINS[(h // 7) % len(SKINS)], PANTS[(h // 3) % len(PANTS)]


FACES = {
    "working": ["(•_•)", "(•_•)", "(•-•)", "(•_•)"],
    "idle": ["(-_-)", "(-_-)", "(._.)", "(-_-)"],
    "sleeping": ["(-.-)"],
    "error": ["(x_x)", "(>_<)"],
    "tired": ["(u_u)", "(u_u)"],
    "party": ["(^o^)", "(^O^)"],
    "walk": ["(•_•)"],
}


def face_for(state, treat, t):
    if treat == "joint" and state not in ("sleeping", "error"):
        return "(~_~)"
    if treat == "beer" and state in ("idle", "working"):
        return "(^_~)"
    fs = FACES.get(state, FACES["idle"])
    return fs[(t // 4) % len(fs)]


def screen_cells(state, idx, t, tod):
    """The desk monitor shows what the process is really doing - 4 cells of (char, fg, bg)."""
    if state == "sleeping":
        return [(" ", 232, 232)] * 4
    glass = 17 if tod != "night" else 16
    if state == "error":
        on = (t // 4) % 2 == 0
        return [(c, 231 if on else 203, 160 if on else 52) for c in "ERR!"]
    if state == "party":
        cols = [196, 208, 226, 46, 51, 21, 201]
        return [("▓", cols[(t // 2 + i + idx) % len(cols)], 16) for i in range(4)]
    if state == "working":
        glyphs = "{}<>=;/*+()[]#$"
        rnd = random.Random(idx * 7919 + t // 2)
        return [(rnd.choice(glyphs), rnd.choice((114, 120, 78, 150)), 22) for _ in range(4)]  # green-lit glass
    if state == "tired":
        return [(c, 214, 52) for c in "zz.."]
    if state == "paused":  # the global STOP: the screen shows the pause sign, not idle
        return [(c, 214, 236) for c in " ‖‖ "]
    cur = "_" if (t // 5) % 2 == 0 else " "
    return [(">", 117, glass), (cur, 153, glass), (" ", glass, glass), (" ", glass, glass)]


def chat_screen_cells(t):
    """The GNOC CHAT monitor while a tool call is open: the tool's own name, scrolled through the 4 cells, so
    you can read WHAT it is doing from across the floor. Four cells, so a longer name marches past."""
    live = sorted(CHAT_LIVE.values(), key=lambda v: v["t0"])
    word = (live[0]["name"] if live else "").replace("_", " ").upper() + "   "
    off = (t // 4) % len(word) if len(word) > 4 else 0
    loop = word + word
    return [(loop[off + i], 120, 22) for i in range(4)]


# ---------- the app ----------

class App:
    def __init__(self, feed):
        self.feed = feed
        self.mood = load_mood()
        self.settings = jload(SETTINGS_FILE, {"intensity": 3})
        try:
            self.settings["intensity"] = int(open(INTENSITY_FILE).read().strip())
        except (OSError, ValueError):
            pass
        self.selected = None  # 0-based index into desk_keys()
        self.modal = None  # None | help | telemetry | options | meeting
        self.rail_pref = None  # None = auto by width
        self.scene = None
        self.walkers = {}
        self.boss = None
        self._boss, self._boss_read = {}, 0.0  # the in/out toggle, cached (boss_here)
        self.boss_btn = None                   # (x0, x1) of the header's BOSS button, for a click
        self.boss_next = 0
        self.particles = []
        self.hits = []
        self.gossip = None
        self.gossip_until = 0
        self.next_gossip = time.time() + random.uniform(20, 40)
        self.pending_treats = []  # (when, key, treat_name, dest_kind)
        self.t = 0
        # cosmetic residents (never telemetry): the cat and the janitor's wet floor
        self.cat, self.cat_desk, self.cat_next = None, None, 0
        self.wet = {}             # (x, y) -> dry-at epoch, left by JANITOR's mop
        self.litter = {}          # (x, y) -> glyph: scraps from real paper trips + shredder spill + slow ambient dust
        self.next_dust = 0
        # real-work animation state
        self.pkts = []            # packets in flight: {"route", "pos", "speed", "glyph", "col", "kind", "end"}
        self.pkt_queue = []       # (start-at, kind, info): a reply replayed at its row's real latency
        self.cable, self.cable_key = None, None
        self.routes = {}          # (scene id, from, to) -> floor cells: BFS over the walkable floor, cached
        self.rack_flash = 0
        self.gpu_flash = 0        # a brain call just reached the laptop GPU (GPU DESK)
        self.desk_flash = {}      # desk -> epoch: a reply just landed there
        self.sent = {}            # proxy call id -> (caller desk, epoch) for calls whose packet already left
        self.replays = 0          # replayed replies still on their way back (a call too short to catch live)
        self.last_call = None     # newest model call row seen on the uplink
        self.balls = []           # start epochs of crumpled-paper tosses (real rejected decisions)
        self.visitors = {}        # LAB investigators: rescue id -> {"w": Walker, "stage", "seat", "inv", "done"}
        self.lab_primed = False   # the first frame seats the workers already running, no walk-in replay

    @property
    def inflight(self):
        """Open model calls: live from the proxy's in-flight file, plus replies still being replayed."""
        return len(INFLIGHT) + self.replays

    # --- roster ---
    def procs(self):
        """Room by room (OFFICES order, GENERAL last) and, inside a room, in seating order rather than
        alphabetical, so desk numbers and Tab walk the floor the way a visitor would."""
        last = (len(OFFICES), len(DESK_SEAT))
        if UNITS:  # the manager first (orch-bot's own pm2 row), then one desk per processing unit found live
            return unit_rows(self.feed.data.get("pm2"))
        if BOTS_ONLY:  # COMPANY: the manager first (front desk), then the roster
            rows = company_rows(self.feed.data.get("company"))
            NICK.update({p["name"]: p["nick"] for p in rows if p.get("nick")})
            return rows
        return sorted(self.feed.data.get("pm2") or [],
                      key=lambda p: (DESK_SEAT.get(p["name"], last), p["name"]))

    def hosts(self):
        return self.feed.data.get("hosts") or {}

    def desk_keys(self):
        if UNITS:  # the linked machines are desks here, not racks
            return [p["name"] for p in self.procs()]
        return [p["name"] for p in self.procs()] + [f"host:{k}" for k in self.hosts()]

    def states(self):
        brain = self.feed.data.get("brain") or {}
        out = {}
        for p in self.procs():
            mrow = mood_of(self.mood, p["name"])
            out[p["name"]] = worker_state(p["name"], p, mrow, brain if p["name"] == "orch-bot" else None)
        return out

    def boss_here(self):
        """The user's own toggle (i, or click the header button): a file, so the website's office cam sees it too.
        Re-read every 2 s; it is the only state the office shares across viewers that a viewer sets by hand."""
        now = time.time()
        if now - self._boss_read > 2:
            self._boss_read = now
            self._boss = jload(BOSS_FILE, {})
        return bool(self._boss.get("here"))

    def work_live(self):
        """A real lane or a brain decision in the last 90 s (the boss office used to light only for this)."""
        brain = self.feed.data.get("brain") or {}
        return bool(self.feed.data.get("lanes")) or _recent(brain.get("ts"), 90)

    def boss_active(self):
        return self.boss_here() or self.work_live()

    def toggle_boss(self):
        here = not self.boss_here()
        self._boss = {"here": here, "since": time.time()}
        self._boss_read = time.time()
        jsave(BOSS_FILE, self._boss)
        if here:
            log_event("YOU", "the boss walked in", C_GOLD)
            toast("BOSS IN  the floor knows you're here", C_GOLD, 4)
            sc, b = self.scene, self.boss
            if sc and b and sc.doors:  # a lap of the floor on the way in
                tgt = random.choice(sc.doors)
                tgt = (tgt[0], tgt[1] + 1) if sc.walkable(tgt[0], tgt[1] + 1) else tgt
                if b.phase != "seated":
                    b.snap()
                b.send(sc, tgt, "patrol", hold=2.5)
                self.boss_next = time.time() + random.uniform(25, 60)
        else:
            log_event("YOU", "the boss left the office", C_MUTED)
            toast("BOSS OUT", C_MUTED, 3)

    # --- actions ---
    def feed_treat(self, key_char):
        keys = self.desk_keys()
        if not keys:
            return
        targets = [keys[self.selected]] if self.selected is not None and self.selected < len(keys) else keys
        name = None
        for i, key in enumerate(targets):
            name = feed_worker(self.mood, key, key_char)
            if not key.startswith("host:"):
                self.pending_treats.append((time.time() + (0 if len(targets) == 1 else random.uniform(0, 4)),
                                            key, name, TREATS[key_char][2]))
        jsave(MOOD_FILE, self.mood)
        who = label_of(targets[0]) if len(targets) == 1 and not targets[0].startswith("host:") else (
            self.hosts().get(targets[0][5:], {}).get("label", "rack") if len(targets) == 1 else "the whole floor")
        toast(f"{name.upper()} for {who}  +{TREATS[key_char][1]} energy", C_GOLD, 4)

    def set_pace(self, delta):
        try:  # start from the live value: `gnoc orch speed` writes the same file while the office is open
            self.settings["intensity"] = int(open(INTENSITY_FILE).read().strip())
        except (OSError, ValueError):
            pass
        v = max(1, min(5, self.settings["intensity"] + delta))
        self.settings["intensity"] = v
        try:
            open(INTENSITY_FILE, "w").write(str(v))
        except OSError:
            pass
        jsave(SETTINGS_FILE, self.settings)
        log_event("YOU", f"pace slider set to {v}/5 (orch-bot tick ~{_TICK_TABLE[v]}s)", C_MUTED)
        toast(f"PACE {v}/5  orch-bot tick ~{_TICK_TABLE[v]}s", C_ACCENT, 3)

    def toggle_meeting(self):
        sc = self.scene
        if self.modal == "meeting":
            self.modal = None
            for w in self.walkers.values():
                if w.kind == "meeting":
                    w.go_home(sc)
            return
        self.modal = "meeting"
        if not sc:
            return
        states = self.states()
        taken = [v["seat"] for v in self.visitors.values()]
        spots = [c for c in sc.meeting if all(abs(c[0] - s[0]) > 4 or c[1] != s[1] for s in taken)]
        for name, w in self.walkers.items():
            if states.get(name) in ("sleeping",) or not spots:
                continue
            if w.phase != "seated":
                w.snap()
            spot = spots.pop(0)
            w.send(sc, spot, "meeting", hold=1e9)

    # --- paper trips (the hunt pipeline made visible; see HANDOFFS) ---
    def dest_xy(self, sc, dest):
        if dest.startswith("desk:"):
            names = [p["name"] for p in self.procs()]
            if dest[5:] not in names or names.index(dest[5:]) >= len(sc.doors):
                return None
            dx, dy = sc.doors[names.index(dest[5:])]
            return next((c for c in ((dx, dy), (dx, dy + 1), (dx + 3, dy), (dx - 3, dy)) if sc.walkable(*c)), None)
        if dest == "boss":
            if sc.right_w and sc.boss_home and sc.walkable(*sc.boss_home):
                return sc.boss_home
            dest = "cabinet"  # narrow terminal: no boss office on screen, the paper goes on file instead
        spots = [c for c in sc.spots.get(dest) or [] if sc.walkable(*c)]
        return random.choice(spots) if spots else None

    def start_leg(self, sc, w, task, i):
        dest, doc = task["legs"][i]
        xy = self.dest_xy(sc, dest)
        if xy is None or xy == w.pos:
            return False
        w.task, w.leg = task, i
        task["at"] = -1
        if not w.send(sc, xy, "deliver", hold=1.6, carry=doc):
            w.task = None
            return False
        return True

    def arrive(self, dest, doc):
        """The paper is dropped where it was going: it sits on that desk, or the fixture reacts."""
        global TRAY_FLASH_UNTIL, SHRED_UNTIL
        if not doc:
            return
        now = time.time()
        if dest.startswith("desk:") or dest == "boss":
            pile = PILES.setdefault(dest[5:] if dest.startswith("desk:") else "boss", [])
            pile.append((doc, now + 150))
            del pile[:-6]
        elif dest == "tray":
            TRAY_FLASH_UNTIL = now + 10
        elif dest == "shredder":
            SHRED_UNTIL = max(SHRED_UNTIL, now + 6)

    def run_handoffs(self, sc, states):
        now = time.time()
        with LOCK:
            pending = list(HANDOFFS)
        for h in pending:
            w = self.walkers.get(h["who"])
            if w is not None and states.get(h["who"]) != "sleeping" and now - h["created"] <= 120:
                on_break = w.kind == "break" and w.phase == "hold"
                if (w.phase != "seated" and not on_break) or w.task or self.modal == "meeting":
                    continue  # busy: the paper waits its turn (max 2 min), like a real in-tray
                self.start_leg(sc, w, h, 0)
            with LOCK:
                if h in HANDOFFS:
                    HANDOFFS.remove(h)

    def drop_litter(self, sc, x, y, n=1, glyphs="·'`,"):
        """Put n scraps on free floor near (x, y). Cosmetic, but only ever caused by a real event or slow dust."""
        for _ in range(n):
            if len(self.litter) >= 45:
                return
            for _ in range(6):
                cx, cy = x + random.randint(-3, 3), y + random.choice((-1, 0, 0, 1))
                # never on the fixture-label row: a sweeper's dust puff there broke the label ("∴ILES")
                if sc.walkable(cx, cy) and (cx, cy) not in self.litter and cy != sc.sy + 3:
                    self.litter[(cx, cy)] = random.choice(glyphs)
                    break

    def break_room(self, sc, states):
        """Global STOP is set: nothing to hunt, so the floor does chores. Mostly they grab a broom and sweep up the
        litter the work left behind (the user 2026-10-22: "if the hunt is paused make them sweep and clean up the
        office"), sometimes a short break (25-75 s) at the coffee machine, fridge, cooler or the partition queue.
        Up to half the floor is up at once and everyone goes back to the desk after. (The first version parked
        everyone in the break queue until STOP cleared: after a long STOP the office looked frozen in a corner.)
        Paper trips still run during chores: a real event is still real."""
        stop = bool(_LAST_SEEN.get("stop"))
        if not stop:
            for w in self.walkers.values():
                if w.kind == "break" and w.phase == "hold":
                    w.go_home(sc)
            return
        right = sc.rx if sc.right_w else sc.MW
        spots = [(x, y) for y in (sc.sy - 1, sc.sy - 3) for x in range(4, right - 4, 6)
                 if sc.walkable(x, y) and not sc.in_room(x, y)]
        spots += [c for k in ("coffee", "fridge", "cooler") for c in sc.spots.get(k, []) if sc.walkable(*c)]
        away = [w for w in self.walkers.values() if w.kind in ("break", "sweep") and w.phase != "seated"]
        if len(away) >= max(1, len(self.walkers) // 2) or self.modal == "meeting":
            return
        taken = {w.dest for w in away}
        for name, w in self.walkers.items():
            busy = states.get(name) in ("sleeping", "working", "tired") or (name == "orch-bot" and BRAIN_THINK)
            if w.phase != "seated" or w.task or busy or random.random() >= 0.003:  # ~ once per 33 s each
                continue
            mess = [c for c in self.litter if all(abs(c[0] - d[0]) > 2 or c[1] != d[1] for d in taken if d)]
            if mess and random.random() < 0.75:
                c = min(mess, key=lambda m: abs(m[0] - w.pos[0]) + abs(m[1] - w.pos[1]) + random.uniform(0, 12))
                if w.send(sc, c, "sweep", hold=random.uniform(2.5, 4.5)):
                    pass  # the broom is the signal; no chatter (bubbles are for real events)
                    return  # one departure per frame, so they trickle out instead of leaving as a crowd
            free = [c for c in spots if c not in taken]
            if free and w.send(sc, random.choice(free), "break", hold=random.uniform(25, 75)):
                return

    def tick_cat(self, sc):
        """COSMETIC. The office cat naps on the warmest desk - the one whose process has the highest real cpu."""
        now = time.time()
        if self.cat is None:
            cx, _, cwid = sc.fix["cooler"]  # by the cooler, on the floor above the fixture labels
            home = next(((x, y) for y in (sc.sy + 2, sc.sy + 1) for x in (cx + 1, cx + 3, cx - 2) if sc.walkable(x, y)), None)
            if not home:
                return
            self.cat = Walker(home)
        c = self.cat
        if c.phase == "seated":
            if not self.cat_next:
                self.cat_next = now + random.uniform(3, 10)
            elif now >= self.cat_next:
                self.cat_next = 0
                procs = [p for p in self.procs()[:len(sc.doors)] if p.get("status") == "online"]
                if procs and random.random() < 0.65:
                    hot = max(procs, key=lambda p: (p.get("cpu") or 0, random.random()))
                    i = [p["name"] for p in self.procs()].index(hot["name"])
                    if c.send(sc, sc.doors[i], "nap", hold=random.uniform(30, 70)):
                        self.cat_desk = i
                else:
                    cells = [x for k in ("window", "table", "fridge") for x in sc.spots.get(k, []) if sc.walkable(*x)]
                    if cells:
                        c.send(sc, random.choice(cells), "roam", hold=random.uniform(5, 12))
        c.step(sc)

    def tick_janitor(self, sc, states):
        """COSMETIC skin on a real process: JANITOR (keepalive) mops an aisle now and then; the floor dries."""
        now = time.time()
        jw = self.walkers.get("keepalive")
        if (jw and states.get("keepalive") in ("idle", "working") and jw.phase == "seated" and not jw.task
                and not _LAST_SEEN.get("stop") and self.modal != "meeting" and random.random() < 0.0015):
            cells = [(x, y) for y in range(sc.ft + 1, sc.sy - 1, 2) for x in range(3, (sc.rx if sc.right_w else sc.MW) - 3, 3)
                     if sc.walkable(x, y)]
            if cells and jw.send(sc, random.choice(cells), "mop", hold=2.5):
                pass  # the mop is cosmetic and says nothing
        if jw and jw.kind == "mop" and jw.phase in ("walk", "hold"):
            for dx in (-1, 0, 1):
                self.wet[(jw.pos[0] + dx, jw.pos[1])] = now + 40
        if self.t % 10 == 0:
            self.wet = {k: v for k, v in self.wet.items() if v > now}

    def tick_litter(self, sc):
        """Slow ambient dust (so a long pause still has something to sweep) + brooms clearing what they stand on."""
        now = time.time()
        if now >= self.next_dust:
            self.next_dust = now + random.uniform(10, 25)
            cells = [(x, y) for y in range(sc.ft + 1, sc.sy) for x in range(2, (sc.rx if sc.right_w else sc.MW) - 2, 3)
                     if sc.walkable(x, y)]
            if cells:
                self.drop_litter(sc, *random.choice(cells), n=1, glyphs="·.")
        for w in self.walkers.values():
            if w.kind == "sweep" and w.phase == "hold":
                for c in [c for c in self.litter if abs(c[0] - w.pos[0]) <= 3 and abs(c[1] - w.pos[1]) <= 1]:
                    del self.litter[c]

    # --- the network: every model call travels caller desk -> UPLINK -> desktop rack, and back ---
    def _door(self, sc, name):
        names = [p["name"] for p in self.procs()]
        i = names.index(name) if name in names else None
        return sc.doors[i] if i is not None and i < len(sc.doors) else None

    def _floor_route(self, sc, a, b):
        """Cells from desk a's door to desk b's door along the corridors (through office doors, never walls)."""
        key = (id(sc), a, b)
        if key not in self.routes:
            da, db = self._door(sc, a), self._door(sc, b)
            path = sc.path(da, db) if da and db else None
            self.routes[key] = ([da] + path) if path is not None else []
        return self.routes[key]

    def _cable(self, sc):
        """UPLINK desk -> the desktop rack: along the floor to the server-room wall, through it, to the rack."""
        key = (id(sc), "desktop-proxy", "rack")
        if key in self.routes:
            return self.routes[key]
        route = []
        hkeys = list(self.hosts().keys())
        door = self._door(sc, "desktop-proxy")
        if sc.right_w and door and hkeys and sc.racks:
            ri = hkeys.index("desktop") if "desktop" in hkeys else 0
            if ri < len(sc.racks):
                hx, hy = sc.racks[ri]
                ry = hy + 1  # the rack's LED row
                # the floor cell nearest the wall on that row (a desk or a room may sit against the wall)
                spot = next(((x, y) for d in range(0, 6) for y in (ry - d, ry + d) for x in range(sc.rx - 1, sc.rx - 8, -1)
                             if sc.walkable(x, y)), None)
                path = sc.path(door, spot) if spot else None
                if path is not None:
                    route = [door] + path
                    x, y = spot
                    route += [(xx, y) for xx in range(x + 1, sc.rx)]  # straight run to the wall
                    step_ = 1 if ry >= y else -1
                    route += [(sc.rx, yy) for yy in range(y, ry + step_, step_)] if y != ry else [(sc.rx, y)]
                    route += [(xx, ry) for xx in range(sc.rx + 1, hx)]
        self.routes[key] = route
        return route

    def _to_rack(self, sc, desk):
        if UNITS:  # the manager's own model calls ride the floor from its desk to the DESKTOP GPU desk
            return self._floor_route(sc, "orch-bot", DESKTOP_KEY) if desk == "orch-bot" else []
        legs = self._floor_route(sc, desk, "desktop-proxy") if desk and desk != "desktop-proxy" else []
        cable = self._cable(sc)
        return (legs[:-1] + cable) if legs and cable else cable

    def _launch(self, route, kind, glyph, col, back=False, end=None):
        if len(route) < 2:
            return False
        r = list(reversed(route)) if back else route
        # a trip takes about 3.5 s whatever its length, so a far desk's packet is not left crawling
        self.pkts.append({"route": r, "pos": 0.0, "speed": max(1.0, len(r) / 35), "glyph": glyph, "col": col,
                          "kind": kind, "end": end})
        return True

    def tick_uplink(self, sc=None):
        """Real model traffic as packets that follow the floor. A call leaves its CALLER's desk the moment the
        uplink proxy opens it (its in-flight file), rides the cable to the desktop rack, and the reply comes back
        to the same desk the moment the proxy logs the answer. A call too short to be seen open is replayed at
        its logged latency. Brain decisions answered by the laptop GPU run BRAIN -> GPU DESK (a replay too)."""
        now = time.time()
        sc = sc or self.scene
        with LOCK:
            new = list(TRAFFIC)
            TRAFFIC.clear()
            laptop = list(LAPTOP_CALLS)
            LAPTOP_CALLS.clear()
        if not sc:
            return
        for rid, c in list(INFLIGHT.items()):  # calls the proxy has open right now
            if rid in self.sent:
                continue
            desk = CALLER_DESK.get(c.get("caller"))
            self.sent[rid] = (desk, now)
            self._launch(self._to_rack(sc, desk), "call", "◆", 117, end="rack")
            if _every(f"net-out:{c.get('caller')}", 15):
                log_event("NET", f"{label_of(desk) if desk else str(c.get('caller', '?'))} -> DESKTOP: "
                                 f"{c.get('model', '?')}", 117)
        for r in new:
            model = bool(r.get("model"))
            bad = (r.get("status") or 0) >= 400 or r.get("err")
            desk = CALLER_DESK.get(r.get("caller"))
            if model:
                self.last_call = r
            if model and r.get("id") in self.sent:  # its packet left live: the answer goes home now
                desk = self.sent.pop(r["id"])[0]
                self._launch(self._to_rack(sc, desk), "reply", "◆", 203 if bad else 78, back=True, end=desk)
                if _every(f"net-in:{r.get('caller')}", 15):
                    who = label_of(desk) if desk else str(r.get("caller", "?"))
                    log_event("NET", f"DESKTOP -> {who}: {r.get('model')} {(r.get('ms') or 0) / 1000:.1f}s"
                                     f"{' ERR ' + str(r.get('status')) if bad else ''}", C_BAD if bad else C_GOOD)
            elif model:  # done before the in-flight file showed it: replay at its real latency
                self._launch(self._to_rack(sc, desk), "call", "◆", 117, end="rack")
                self.pkt_queue.append((now + min(60.0, (r.get("ms") or 0) / 1000), "reply",
                                       (self._to_rack(sc, desk), 203 if bad else 78, desk)))
                self.replays += 1
            elif sum(1 for pk in self.pkts if pk["kind"] == "poll") < 12:  # health polls: thinned, never calls
                self._launch(self._to_rack(sc, desk), "poll", "•", 242, end="rack")
        for r in laptop:
            route = self._floor_route(sc, "orch-bot", "qwen3:8b")
            self._launch(route, "call", "◆", 141, end="gpu")
            self.pkt_queue.append((now + min(60.0, float(r.get("secs") or 0)), "lreply", (route, 141, "orch-bot")))
        for rid in [k for k, (_, t0) in self.sent.items() if k not in INFLIGHT and now - t0 > 15]:
            del self.sent[rid]  # closed without a log row we could match (an older proxy, a trimmed log)
        due = [q for q in self.pkt_queue if q[0] <= now]
        self.pkt_queue = [q for q in self.pkt_queue if q[0] > now]
        for _, kind, (route, col, desk) in due:
            if kind == "reply":
                self.replays = max(0, self.replays - 1)
            self._launch(route, "reply", "◆", col, back=True, end=desk)
        live = []
        for pk in self.pkts:
            pk["pos"] += pk["speed"]
            if pk["pos"] < len(pk["route"]) - 1:
                live.append(pk)
            elif pk["end"] == "rack":
                self.rack_flash = now + (0.8 if pk["kind"] == "call" else 0.25)
            elif pk["end"] == "gpu":
                self.gpu_flash = now + 0.8
            elif pk["end"]:
                self.desk_flash[pk["end"]] = now + 1.2
        self.pkts = live

    # --- per-frame simulation ---
    # --- the LAB: a visiting investigator per live rescue worker (see d_lab) ---
    def lab_seats(self, sc):
        if BOTS_ONLY and sc.spots.get("lab"):  # the visiting investigators work inside THE LAB
            return list(sc.spots["lab"])
        if sc.table:
            tx, ty, tw = sc.table
            return [(tx + 3 + 6 * i, sc.sy + 3) for i in range(max(1, (tw - 2) // 6))]
        return list(sc.spots.get("table") or [])

    def tick_lab(self, sc):
        """Real worker appears -> PIPELINE hands it the lead at the triage tray, it walks to the LAB BENCH and works
        there (ladder on the bench, tests on its laptop) until the pid exits; then it walks the verdict out: a
        candidate or a NEEDS to the BOSS, DEAD to the SHREDDER, a tried rung back to the tray, no verdict on FILE."""
        with LOCK:
            live = dict(LAB)
            done = list(LAB_DONE)
            LAB_DONE.clear()
        for d in done:
            v = self.visitors.get(d["id"])
            if not v or v["stage"] in ("out", "gone"):
                continue
            v.update(stage="out", done=d)
            w = v["w"]
            if w.phase not in ("seated", "hold"):
                w.snap()
                w.pos = v["seat"]
            w.phase = "hold"
            xy = self.dest_xy(sc, d["dest"])
            if xy is None or not w.send(sc, xy, "deliver", hold=3, carry=d["doc"]):
                self.arrive(d["dest"], d["doc"])
                v["stage"] = "gone"
        for iid, v in list(self.visitors.items()):
            w = v["w"]
            if iid in live:
                v["inv"] = live[iid]
            elif v["stage"] in ("tray", "bench"):  # gone without a LAB_DONE (missed between polls): file it
                with LOCK:
                    LAB_DONE.append(dict(v["inv"], verdict="no verdict", dest="cabinet", doc="archive", t_end=time.time()))
                v["stage"] = "leaving"  # walked out on the next tick
            if v["stage"] == "tray" and w.phase == "hold":  # picked the lead up at the tray: to the bench
                if not w.send(sc, v["seat"], "lab", hold=1e5, carry="lead"):
                    w.pos, w.phase, w.hold_until, w.kind = v["seat"], "hold", time.time() + 1e5, "lab"
                v["stage"] = "bench"
            elif v["stage"] == "out" and w.phase == "hold" and w.kind == "deliver":
                if not v.get("dropped"):
                    v["dropped"] = True
                    self.arrive(v["done"]["dest"], v["done"]["doc"])
                    w.carry = None
                if time.time() >= w.hold_until - 0.1:
                    v["stage"] = "gone"
            if v["stage"] == "gone":
                del self.visitors[iid]
                continue
            if w.phase in ("walk", "return"):
                w.step(sc)
            elif w.phase == "hold" and v["stage"] == "out" and time.time() >= w.hold_until:
                v["stage"] = "gone"
        seats = self.lab_seats(sc)
        for iid, inv in live.items():
            if iid in self.visitors:
                continue
            free = [c for c in seats if c not in {v["seat"] for v in self.visitors.values()}]
            if not free:
                break  # more live workers than bench seats: the rail still lists every one
            seat = free[0]
            w = Walker(seat)
            v = self.visitors[iid] = {"w": w, "stage": "bench", "seat": seat, "inv": inv, "done": None}
            start = self.dest_xy(sc, "desk:pipeline-sweep") if self.lab_primed else None
            tray = self.dest_xy(sc, "tray")
            if start and tray and sc.path(start, tray) is not None:
                w.pos = start
                w.send(sc, tray, "deliver", hold=1.5)
                v["stage"] = "tray"
            else:  # already running when the office opened: it is at the bench
                w.pos, w.phase, w.hold_until, w.kind, w.carry = seat, "hold", time.time() + 1e5, "lab", "lead"
        self.lab_primed = True

    def tick_units(self, sc):
        """UNITS: a unit serving a website-analysis call (UNIT_VISIT, from the chat's activity log) walks to PROD with
        the work and sits there until the call's end row, then walks home with the result; a split-llm call puts one
        shared paper on every desk it spans."""
        with LOCK:
            visits = dict(UNIT_VISIT)
            papers = list(SPLIT_PAPERS)
            SPLIT_PAPERS.clear()
        now = time.time()
        for _, units in papers:
            for u in units:
                PILES.setdefault(u, []).append(("split", now + 150))
                del PILES[u][:-6]
        seats = list(sc.spots.get("prod") or [])
        taken = {w.dest for w in self.walkers.values() if w.kind == "prod"}
        brings = self.__dict__.setdefault("visit_bring", {})  # walker -> (visit cid, the paper it brings home)
        for key, w in self.walkers.items():
            v = visits.get(key)
            if v and w.kind != "prod" and w.phase == "seated" and not w.task:
                free = [c for c in seats if c not in taken]
                if free and w.send(sc, free[0], "prod", hold=1e5, carry=v.get("carry", "order")):
                    taken.add(free[0])
                    brings[key] = (v.get("cid"), v.get("bring", "result"))
                    with LOCK:
                        v["walked"] = True  # the same dict as UNIT_VISIT's (a shallow copy): its poller reads it
            elif not v and w.kind == "prod" and w.phase in ("walk", "hold"):
                w.go_home(sc)
                cid, bring = brings.pop(key, (None, "result"))
                with LOCK:
                    if cid in VISIT_END:  # a STUDIO compile: the reel only when its manifest landed
                        bring = VISIT_END.pop(cid)
                w.carry = w.bring = bring

    def tick_story(self, sc):
        """The story's walks (the only animations on the line): a bot sent on a job fetches its folder at the
        FRONT DESK and carries it to its desk; a bot whose claim goes to be checked carries it to THE LAB; a report
        ready is carried to THE PRESS by the manager; a PROVED floats "+N (c)" over the bot for 2 s. The first
        frame primes (old news does not walk)."""
        rows = self.feed.data.get("story") or []
        seen = self.__dict__.setdefault("story_seen", None)
        keys = [f"{r.get('ts')}|{r.get('text')}" for r in rows]
        if seen is None:
            self.story_seen = set(keys)
            return
        floats = self.__dict__.setdefault("floats", [])
        for r, key in zip(rows, keys):
            if key in seen:
                continue
            seen.add(key)
            kind, who = r.get("kind"), r.get("bot")
            legs = {"job": ([("front", None)], "order"), "lab": ([("lab", "lead")], None),
                    "report": ([("press", "report")], None)}.get(kind)
            if kind == "report":
                who = who or "orch-bot"
            if legs and who in self.walkers:
                with LOCK:
                    HANDOFFS.append({"who": who, "legs": legs[0], "bring": legs[1], "label": str(r.get("text"))[:60],
                                     "created": time.time()})
            if kind == "proved" and who:
                amt = "".join(ch for ch in str(r.get("text", "")).split("+")[-1] if ch.isdigit()) or "?"
                floats.append((who, f"+{amt} (c)", time.time() + 2.0))
        self.floats = [f for f in floats if f[2] > time.time()]

    def tick(self, sc, states, bubbles):
        now = time.time()
        self.run_handoffs(sc, states)
        self.break_room(sc, states)
        self.tick_cat(sc)
        self.tick_janitor(sc, states)
        self.tick_litter(sc)
        self.tick_uplink(sc)
        self.tick_lab(sc)
        if UNITS:
            self.tick_units(sc)
        if BOTS_ONLY:
            self.tick_story(sc)
        while BALLS:
            BALLS.popleft()
            self.balls.append(now + 0.4 * len(self.balls))
        self.balls = [b for b in self.balls if now - b < 1.5]
        # treat errands
        due = [p for p in self.pending_treats if p[0] <= now]
        self.pending_treats = [p for p in self.pending_treats if p[0] > now]
        for _, key, treat, dest in due:
            w = self.walkers.get(key)
            if w and states.get(key) not in ("sleeping",) and w.phase == "seated":
                w.send(sc, random.choice(sc.spots.get(dest) or [w.home]), dest, hold=2.5, carry=treat)
        for name, w in self.walkers.items():
            state = states.get(name, "idle")
            bub = bubbles.get(name)
            if state == "sleeping" and w.phase != "seated" and w.kind != "meeting":
                w.snap()
            if w.task and w.phase == "hold" and now >= w.hold_until:  # leg done: next leg, or home
                task = w.task
                if w.leg + 1 < len(task["legs"]) and self.start_leg(sc, w, task, w.leg + 1):
                    pass
                else:
                    w.task = None
                    w.bring = task.get("bring")
                    w.go_home(sc)
                    w.carry = w.bring  # walks home holding what it fetched
            if w.phase == "seated" and w.bring:
                PILES.setdefault(name, []).append((w.bring, now + 150))
                del PILES[name][:-6]
                w.bring = None
            if w.phase == "seated" and self.modal != "meeting" and not w.task:
                if bub and not bub.get("flavor") and w.last_bubble != bub.get("created") and state != "sleeping":
                    w.last_bubble = bub.get("created")
                    if bub.get("dest") != "stay":  # "stay": a paper trip already walks this event
                        dest = "shredder" if bub.get("dest") == "shredder" else "cabinet"
                        w.send(sc, random.choice(sc.spots[dest]), dest, hold=3)
                elif state == "idle" and random.random() < 0.0025:
                    w.send(sc, random.choice(sc.spots["cooler"]), "cooler", hold=random.uniform(4, 7))
                # (idle small talk removed: an idle desk stays quiet)
            w.step(sc)
            if w.task and w.phase == "hold" and w.task.get("at") != w.leg:  # just arrived at this leg's stop
                w.task["at"] = w.leg
                dest, doc = w.task["legs"][w.leg]
                self.arrive(dest, doc)
                if doc and random.random() < (0.9 if dest == "shredder" else 0.35):
                    self.drop_litter(sc, *w.pos, n=3 if dest == "shredder" else 1)
                w.carry = None
        # the boss: walks the floor while a lane or a brain decision is live, otherwise the office is dark
        if self.boss:
            b = self.boss
            if self.boss_active():
                if b.phase == "seated" and now >= self.boss_next and sc.doors:
                    tgt = random.choice(sc.doors)
                    tgt = (tgt[0], tgt[1] + 1) if sc.walkable(tgt[0], tgt[1] + 1) else tgt
                    b.send(sc, tgt, "patrol", hold=random.uniform(2, 4))
                    self.boss_next = now + random.uniform(25, 60)
            elif b.phase == "walk":
                b.go_home(sc)
            b.step(sc)
        # gossip at the cooler (built from real numbers)
        if now >= self.next_gossip:
            self.gossip = gossip_for(self.feed)
            self.gossip_until = now + 14
            self.next_gossip = now + random.uniform(30, 55)
        # confetti
        if party_active():
            for _ in range(3):
                self.particles.append([random.randrange(1, sc.MW - 1), sc.ft, random.choice("*.'o+▪"),
                                       random.choice([196, 208, 226, 46, 51, 201, 93, 231]), random.choice((1, 2))])
        live = []
        for p in self.particles:
            if self.t % p[4] == 0:
                p[1] += 1
                p[0] += random.choice((-1, 0, 0, 1))
            if p[1] < sc.MH - 1:
                live.append(p)
        self.particles = live[-400:]
        self.t += 1


def gossip_for(feed):
    """A water-cooler line generated from whatever REAL facts are on hand - picked and phrased informally."""
    brain = feed.data.get("brain") or {}
    o = feed.data.get("outcomes") or {}
    ships = feed.data.get("ships") or []
    procs = feed.data.get("pm2") or []
    hosts = feed.data.get("hosts") or {}
    candidates = []
    if brain.get("action") and brain.get("status"):
        candidates.append(f"did you hear BRAIN's last call got {brain['status']}? \"{brain['action']}\"")
    if o.get("n"):
        top = max((o.get("verdicts") or {}).items(), key=lambda kv: kv[1], default=(None, 0))
        if top[0]:
            candidates.append(f"{o['n']} probes fired today, mostly {top[0]}")
    restarters = [p for p in procs if p.get("restarts")]
    if restarters:
        p = max(restarters, key=lambda p: p["restarts"])
        candidates.append(f"{label_of(p['name'])} has restarted {p['restarts']} times. yikes")
    candidates.append(f"ship desk wrote up {len(ships)} report(s) today" if ships else "ship desk's dead quiet today")
    if hosts and not any(h.get("models") for h in hosts.values()):
        candidates.append("the server room GPU's been idle for a while, lucky thing")
    return random.choice(candidates)


# ---------- drawing: the office map ----------

def draw_sky(cv, x, tod, t, seed):
    rnd = random.Random(seed)
    if tod == "day":
        rows = [75, 111, 153]
    elif tod == "dusk":
        rows = [61, 168, 216]
    else:
        rows = [17, 17, 18]
    for r in range(3):
        cv.put(x, 1 + r, " " * 12, bg=rows[r])
    if tod == "night":
        for _ in range(5):
            sx, sy = rnd.randrange(12), rnd.randrange(3)
            tw = (t // 6 + sx) % 4
            cv.put(x + sx, 1 + sy, "·+·*"[tw], 229 if tw else 250, rows[sy])
        if seed % 3 == 0:
            cv.put(x + 8, 1, "●", 230, rows[0])
    elif tod == "day":
        cx = (seed * 5 + t // 20) % 16 - 3
        for i, ch in enumerate("▄▆▆▄"):
            if 0 <= cx + i < 12:
                cv.put(x + cx + i, 2, ch, 231, rows[1])
    else:
        cv.put(x + 5, 3, "▄█▄", 229, rows[2])
    cv.put(x, 1, "▕", 250, None)
    cv.put(x + 6, 1, "│", 250)
    cv.put(x + 6, 2, "│", 250)
    cv.put(x + 6, 3, "│", 250)
    for r in range(3):
        cv.put(x, 1 + r, "▕", 250)
        cv.put(x + 11, 1 + r, "▏", 250)


def draw_bubble(cv, x, y, text, kind, maxw=40):
    bg, fg = {"real": (222, 16), "flavor": (153, 17), "alert": (203, 231), "boss": (183, 16), "think": (189, 17)}[kind]
    text = clip(text, min(maxw, cv.w - 4))
    s = f" {text} "
    x = max(1, min(x, cv.w - len(s) - 1))
    cv.put(x, y, s, fg, bg)
    return x


def draw_sprite(cv, fx, fy, face, shirt, skin, pants, t, moving, carry=None, arms="/█\\", dance=False, hair=None):
    cv.put(fx - 2, fy - 2, face, skin, None, A_B)
    if hair is not None:
        cv.put(fx - 2, fy - 2, "(", hair, None, A_B)
        cv.put(fx + 2, fy - 2, ")", hair, None, A_B)
    if dance:
        arms = ("\\█/", "/█\\")[(t // 3) % 2]
    cv.put(fx - 1, fy - 1, arms[0], skin)
    cv.put(fx, fy - 1, arms[1], shirt)
    cv.put(fx + 1, fy - 1, arms[2], skin)
    legs = ("/ \\", "| |")[(t // 2) % 2] if moving else "/ \\"
    cv.put(fx - 1, fy, legs, pants)
    if carry:
        g, col = DOCS[carry][:2] if carry in DOCS else TREAT_GLYPH.get(carry, ("o", 250))
        cv.put(fx + 2, fy - 1, g, col, None, A_B)


BOSS_SUIT, BOSS_TIE, BOSS_SHIRT, BOSS_HAIR, BOSS_SKIN = 17, 160, 231, 94, 223


def draw_boss(cv, fx, fy, t, moving, seated=False, dance=False):
    """The boss: a man in a dark suit, white shirt and a red tie, short hair. Same footprint as a worker
    (face row, body row, legs row) so every path and overlay that fits a worker fits them."""
    cv.put(fx - 2, fy - 2, "(ò_ó)", BOSS_SKIN, None, A_B)
    cv.put(fx - 2, fy - 2, "(", BOSS_HAIR, None, A_B)  # short hair at the temples, as the workers wear it
    cv.put(fx + 2, fy - 2, ")", BOSS_HAIR, None, A_B)
    cv.put(fx - 1, fy - 3, "▄▄▄", BOSS_HAIR)           # and on top: the boss is the only one with a haircut
    left, right = ("\\", "/") if dance and (t // 3) % 2 == 0 else ("/", "\\")
    cv.put(fx - 1, fy - 1, left, BOSS_SUIT, None, A_B)   # suit sleeves
    cv.put(fx, fy - 1, "▼", BOSS_TIE, BOSS_SHIRT, A_B)   # the tie, on the white shirt
    cv.put(fx + 1, fy - 1, right, BOSS_SUIT, None, A_B)
    if not seated:
        legs = ("/ \\", "| |")[(t // 2) % 2] if moving else "/ \\"
        cv.put(fx - 1, fy, legs, BOSS_SUIT, None, A_B)    # suit trousers


LAB_COAT, LAB_PANTS = 255, 24


def _lab_lines(inv, now):
    """What an investigator at the bench says, every phrase a real field of its worker (rotates every ~4 s)."""
    if inv.get("testing"):
        return [f"testing: {inv['testing']}"]
    who = "a parked lead" if REDACT else inv["name"]
    if inv.get("kind") == "chainmap":
        step = "mapping chains across held leads"
    elif inv.get("kind") == "chain":
        step = f"chain edge {inv.get('cur') or 1} of {len(inv.get('ladder') or [1])}"
    elif inv.get("cur"):
        step = f"escalating, rung {inv['cur']}: {RUNGS.get(inv['cur'], '')}"
    else:
        step = "auditing the escalation ladder"
    lines = [f"{inv['hunter']}: {who}", step,
             f"{inv.get('runs', 0)} commands, {_dur(now - inv['t0']) if inv.get('t0') else '?'} in"]
    if inv.get("last_cmd") and inv.get("last_cmd_ago") is not None:
        lines.append(f"last test {inv['last_cmd']} ({_dur(inv['last_cmd_ago'])} ago)")
    v = inv.get("verdict")
    if v:
        lines = [f"recorded {str(v.get('verdict', '?')).split()[0]}, {v.get('probes', '?')} probes"
                 f"{' + burst' if v.get('burst') else ''}"] + lines[:1]
    return lines


def draw_lab(cv, app, sc, t, overlays):
    """The LAB BENCH (the standup table while any lead is under investigation): one visiting investigator per
    live rescue worker, the 5-rung escalation ladder on the bench in front of it (× tried, ✓ paid off, ! needs
    you, - n/a, · untried, the rung being worked blinks), its laptop showing a test in flight, and the
    investigator walking its verdict out when the worker exits."""
    if not app.visitors:
        return
    now = time.time()
    if sc.table:
        tx, ty, tw = sc.table
        lx = tx + tw // 2 - 6
        cv.put(lx, sc.sy, " LAB BENCH ", C_GOLD, cv.bg[sc.sy][lx], A_B)
    for iid, v in app.visitors.items():
        w, inv = v["w"], v["inv"]
        fx, fy = w.pos
        at_bench = v["stage"] == "bench" and w.phase == "hold"
        skin = look_for(inv["hunter"])[1]
        testing = at_bench and inv.get("testing")
        face = ("(ò_ó)", "(ó_ò)")[(t // 3) % 2] if testing else face_for("working" if at_bench else "walk", None, t)
        carry = w.carry if w.phase in ("walk", "return") else None
        draw_sprite(cv, fx, fy, face, LAB_COAT, skin, LAB_PANTS, t, w.phase in ("walk", "return"), carry=carry,
                    hair=hair_for(inv["hunter"]))
        if at_bench:
            sx, sy_ = v["seat"]
            by = sy_ + 1
            if by < sc.MH - 1 and inv.get("ladder"):
                lad = inv["ladder"][:5]
                for k, st in enumerate(lad):
                    g, col = RUNG_MARK.get(st, ("·", C_MUTED))
                    if inv.get("cur") == k + 1 or (inv.get("cur") is None and inv.get("kind") != "chainmap"
                                                   and (t // 4) % len(lad) == k):
                        g, col = ("▲", C_GOLD) if (t // 4) % 2 == 0 else (g, C_WARN)
                    cv.put(sx - 2 + k, by, g, col, cv.bg[by][sx - 2 + k], A_B)
            if by + 1 < sc.MH - 1:  # the laptop: a test in flight scrolls, otherwise a dim idle screen
                if testing:
                    rnd = random.Random(hash(iid) + t // 2)
                    for k in range(5):
                        cv.put(sx - 2 + k, by + 1, rnd.choice("{}<>=;/*+#$"), rnd.choice((114, 120, 150)), 22)
                else:
                    cv.put(sx - 2, by + 1, "▁▁▁▁▁", 60, 17)
            lines = _lab_lines(inv, now)
            overlays.append((fx - 2, fy - 3, lines[(t // 40 + hash(iid)) % len(lines)], "real", False))
        elif v["stage"] == "out" and v.get("done"):
            d = v["done"]
            overlays.append((fx - 2, fy - 3, f"{d['verdict']}: {'a parked lead' if REDACT else d['name']} "
                                             f"-> {PLACE.get(d['dest'], d['dest'])}",
                             "alert" if d["dest"] == "boss" else "real", False))
        elif v["stage"] == "tray":
            overlays.append((fx - 2, fy - 3, f"{inv['hunter']}: picking up {'a lead' if REDACT else inv['name']}",
                             "real", False))


def draw_map(app, MW, MH):
    feed, t = app.feed, app.t
    procs = app.procs()
    hosts = app.hosts()
    sc = app.scene
    tod = time_of_day()
    cv = sc.base(tod).copy()
    states = app.states()
    with LOCK:
        bubbles = dict(BUBBLES) if not BOTS_ONLY else {}
    partying = party_active()
    now = time.time()

    # sky + wall gadgets
    for i, wx in enumerate(sc.windows):
        draw_sky(cv, wx, tod, t, i * 31 + 7)
    o = feed.data.get("outcomes") or {}
    ships = feed.data.get("ships") or []
    wbx, wby, wbw = sc.wb
    flash = now < WHITEBOARD_FLASH_UNTIL and (t // 4) % 2 == 0
    wbg = 229 if flash else 255
    cv.fill(wbx, wby, wbw, 3, " ", bg=wbg)
    if BOTS_ONLY:  # the TODAY strip: three plain lines from company.json screen (code-built)
        today = (((feed.data.get("company") or {}).get("c") or {}).get("screen") or {}).get("today") or \
            ["TODAY  the manager has not opened the office yet"]
        for r, txt in enumerate(today[:3]):
            cv.put(wbx + 1, wby + r, clip(str(txt), wbw - 2), 160 if r == 0 else 25, wbg, A_B if r == 0 else 0)
    else:
        open_leads = _LAST_SEEN.get("oss_open")
        nd, nf = ship_counts(ships)
        tray_txt = "?" if open_leads is None else str(open_leads)
        today_line = [("TODAY ", 160, A_B), (str(nf), 236, A_B), (" filed", 240, 0),
                      ("   ", 0, 0), (str(nd), 236, A_B), (f" draft{'s' * (nd != 1)}", 240, 0),
                      ("   ", 0, 0), (str(o.get("n", 0)), 236, A_B), (" lanes ran", 240, 0),
                      ("   ", 0, 0), (tray_txt, 236, A_B), (" waiting in the tray", 240, 0)]
        if sum(len(t) for t, _, _ in today_line) > wbw - 2:  # a narrow board keeps the short words
            today_line = [("TODAY ", 160, A_B), (str(nf), 236, A_B), (" filed", 240, 0), ("  ", 0, 0),
                          (str(nd), 236, A_B), (f" draft{'s' * (nd != 1)}", 240, 0), ("  ", 0, 0),
                          (str(o.get("n", 0)), 236, A_B),
                          (" lanes", 240, 0), ("  ", 0, 0), (tray_txt, 236, A_B), (" in tray", 240, 0)]
        cv.segs(wbx + 1, wby, today_line, wbw - 2)
        real = [s for s in ships if ship_kind(s) in ("draft", "submission")]  # untyped hunt notes are not reports
        lines = [(f"> {'FILED' if ship_kind(s) == 'submission' else 'draft'}: "
                  f"{'a report' if REDACT else _ship_title(s)}", _ago(s.get("ts"))) for s in reversed(real[-2:])]
        if not lines:
            lines = [("> no drafts or filings yet today", "")]
        if not REDACT and not sc.war and not getattr(app, "rail_on", False) and not ships:  # no war room and no rail: the chat still has to show somewhere
            last = [r for r in ((feed.data.get("chat") or {}).get("chat") or []) if r[0] in ("you", "gnoc")][-1:]
            if last:
                lines = [(f"{last[0][0]}: {last[0][1]}", "chat")]
        hn = dict(HUNT_NOW)
        if hn.get("prog") and (hn.get("live") or time.time() - hn.get("t", 0) < 900):
            word = "HUNT" if hn.get("live") else "LAST"  # the right-hand slot carries the result counts
            n = hn.get("hosts", 0)
            lines = lines[:1] + [(f"{word} {hn['prog']}{'' if scope_on_file(hn['prog']) else ' NO SCOPE!'} "
                                  f"{n} host{'s' * (n != 1)} {hn.get('fired', 0)} fired",
                                  f"{hn.get('leads', 0)} weak" + (f" {hn['hits']} signal" if hn.get("hits") else ""))]
        for r, (txt, ago) in enumerate(lines[:2]):
            cv.segs(wbx + 1, wby + 1 + r, [(clip(txt, wbw - 4 - max(4, len(ago))), 25, 0)], wbw - 2)
            if ago:
                cv.put(wbx + wbw - 1 - len(ago), wby + 1 + r, ago, 244)
    cx, cy = sc.clock
    lt = datetime.now()
    colon = ":" if (t // 5) % 2 == 0 else " "
    cv.put(cx + 1, cy, f" {lt:%H}{colon}{lt:%M} ", 229 if tod == "night" else 231, 233, A_B)

    # party: disco floor
    if partying:
        # a few lit tiles chase across the carpet; most of the floor stays carpet so the desks still read
        disco = [54, 24, 89, 23, 53, 58]
        for y in range(sc.ft + 1, sc.sy):
            row = cv.bg[y]
            for x in range(1, sc.rx if sc.right_w else sc.MW - 1):
                tile = (x // 4) * 7 + (y // 2) * 13
                if cv.ch[y][x] == " " and row[x] in (234, 235, 236, 237) and (tile + t // 4) % 5 == 0:
                    row[x] = disco[(tile // 5 + t // 8) % len(disco)]

    # JANITOR's wet floor (cosmetic) - drawn on bare carpet only, with a sign where it is wettest
    sign = None
    for (wx_, wy_), until in app.wet.items():
        if until > now and 0 <= wy_ < sc.MH and 0 <= wx_ < sc.MW and cv.ch[wy_][wx_] == " ":
            cv.bg[wy_][wx_] = 24 if until - now > 15 else 23
            if sign is None or until > sign[2]:
                sign = (wx_, wy_, until)
    if sign and sign[1] - 1 > sc.ft and cv.ch[sign[1] - 1][sign[0]] == " ":
        cv.put(sign[0], sign[1] - 1, "⚠", C_GOLD, None, A_B)

    # litter on bare floor (paper scraps from real trips, shredder spill, dust); swept up while the hunt is paused
    for (lx, ly), g in app.litter.items():
        if 0 <= ly < sc.MH and 0 <= lx < sc.MW and cv.ch[ly][lx] == " ":
            cv.put(lx, ly, g, 250 if g in "'`," else 244)

    # the UPLINK cable: UPLINK desk -> the desktop rack along the corridors, through the server-room wall; every
    # real model call rides from its caller's desk to UPLINK and down the cable, and its reply comes back the same way
    cable = app._cable(sc) if any(p["name"] == "desktop-proxy" for p in procs) else []
    app.cable = cable or None
    for k, (cx_, cy_) in enumerate(cable):
        if 0 <= cy_ < sc.MH and 0 <= cx_ < sc.MW:
            if cx_ == sc.rx:
                cv.put(cx_, cy_, "╪", 244)
            elif cv.ch[cy_][cx_] == " " and k % 2 == 0:
                cv.put(cx_, cy_, "·", 239)
    for pk in app.pkts:
        route, k = pk["route"], int(pk["pos"])
        if pk["kind"] != "poll":  # a two-cell trail shows which way a call or a reply is heading
            for back_, col_ in ((2, 238), (1, 244)):
                if 0 <= k - back_ < len(route):
                    tx_, ty_ = route[k - back_]
                    if 0 <= ty_ < sc.MH and 0 <= tx_ < sc.MW and cv.ch[ty_][tx_] in (" ", "·"):
                        cv.put(tx_, ty_, "·", col_)
        if 0 <= k < len(route):
            cx_, cy_ = route[k]
            if 0 <= cy_ < sc.MH and 0 <= cx_ < sc.MW:
                cv.put(cx_, cy_, pk["glyph"], pk["col"], None, A_B if pk["kind"] != "poll" else 0)

    # RESCUE corkboard in the rightmost window bay: the live pipeline-sweep ledger, one sticky per state
    if len(sc.windows) >= 2 and RESCUE:
        bx_ = sc.windows[-1]
        cv.put(bx_, 1, "PARKED WORK " if BOTS_ONLY else "RESCUE BOARD", 230, 94, A_B)
        if RESCUE_AGE[0] is not None and bx_ + 18 < sc.MW - 1:  # how old the board is: it is a 4-hourly snapshot
            a = RESCUE_AGE[0]
            cv.put(bx_ + 13, 1, f"{int(a // 60)}m old" if a < 3600 else f"{int(a // 3600)}h old", 244)
        dead = sum(v for k, v in RESCUE.items() if k.startswith("DEAD"))
        # stickies: open / needs YOU / ready to promote / dead, in the board's own words. A wide enough
        # window bay gets the full word (5 cells); a tight one falls back to the 4-cell shorthand.
        roomy = bx_ + 6 * 4 < sc.MW - 1
        promote = "ready" if roomy and not BOTS_ONLY else "good"  # tight bay: the plainest 4-letter word
        notes = [(RESCUE.get("ACTIVE", 0), 228, "open"), (RESCUE.get("NEEDS", 0), 218, "YOU!" if roomy else "YOU"),
                 (RESCUE.get("PROMOTE", 0), 157, promote), (dead, 250, "dead")]
        cw = 5 if roomy else 4                                      # sticky width
        step = cw + 1 if bx_ + (cw + 1) * len(notes) < sc.MW - 1 else cw   # a gap between stickies when it fits
        if step > cw:  # the cork between the stickies (the window behind showed through the gaps)
            cv.fill(bx_, 2, step * len(notes) - 1, 2, " ", bg=94)
        for k, (n, col, tag) in enumerate(notes):
            blink = tag.startswith("YOU") and n and (t // 5) % 2 == 0
            bgc = 203 if blink else col
            num = f"{n:>{cw}}" if len(str(n)) <= cw else "9" * cw
            cv.put(bx_ + step * k, 2, num, 16, bgc, A_B)
            cv.put(bx_ + step * k, 3, f"{tag:<{cw}}", 238, bgc)

    # WAR ROOM board: the gnoc chat conversation (left) and orch.log (right), local times, newest at the bottom
    if sc.war:
        if BOTS_ONLY and not REDACT:
            draw_company_board(cv, app, sc, t)
        else:
            draw_war_board(cv, app, sc, t)

    # global STOP: a sign on the floor (the break room fills up, see App.break_room)
    comp = feed.data.get("company") or {}
    if BOTS_ONLY and comp.get("paused") and not partying:  # COMPANY: PAUSE pauses the whole company
        msg = " ■ OFFICE CLOSED  (the PAUSE file is set)  remove it to open again "
        sx_ = max(1, ((sc.rx if sc.right_w else sc.MW) - len(msg)) // 2)
        cv.put(sx_, sc.ft + 1, clip(msg, sc.MW - 2), 231, 160 if (t // 10) % 2 else 124, A_B)
    elif BOTS_ONLY and _LAST_SEEN.get("stop") and not partying:
        msg = " ■ HUNTING PAUSED  (STOP is set; the bots tidy up and keep the books)  gnoc resume "
        sx_ = max(1, ((sc.rx if sc.right_w else sc.MW) - len(msg)) // 2)
        cv.put(sx_, sc.ft + 1, clip(msg, sc.MW - 2), 231, 130, A_B)
    elif _LAST_SEEN.get("stop") and not partying:
        msg = " ■ HUNT PAUSED  (STOP is set)  gnoc resume to restart "
        sx_ = max(1, ((sc.rx if sc.right_w else sc.MW) - len(msg)) // 2)
        cv.put(sx_, sc.ft + 1, clip(msg, sc.MW - 2), 231, 160 if (t // 10) % 2 else 124, A_B)

    # desks
    sel = app.selected
    keys = app.desk_keys()
    sel_key = keys[sel] if sel is not None and sel < len(keys) else None
    app.hits = []
    overlays = []
    for i, p in enumerate(procs):
        if i >= len(sc.desks):
            break
        name = p["name"]
        x, y = sc.desks[i]
        state = states.get(name, "idle")
        vstate = "party" if partying and state not in ("sleeping", "error") else state
        mrow = mood_of(app.mood, name)
        is_sel_early = sel_key == name
        treat = mrow.get("treat") if now < mrow.get("treat_until", 0) else None
        shirt, skin, pants = look_for(name)
        w = app.walkers.get(name)
        # monitor
        cells = screen_cells(vstate, i, t, tod)
        if name == CHAT_KEY and vstate == "working" and CHAT_LIVE:
            cells = chat_screen_cells(t)   # the glass names the tool actually running
        elif p.get("unit"):
            cells = unit_screen_cells(p, vstate, t, tod)
        for j, (ch, fg, bg) in enumerate(cells):
            cv.put(x + 9 + j, y + 1, ch, fg, bg)
        if state != "sleeping" and tod == "night":
            cv.put(x + 8, y + 2, "▁", 229)  # desk lamp on at night
        # treat on the desk
        if treat and w and w.phase == "seated":
            g, col = TREAT_GLYPH.get(treat, ("o", 250))
            cv.put(x + 6, y + 2, g, col, None, A_B)
        # the worker at the desk or the empty chair (UNITS: a stopped manager is not at his desk at all)
        if (w is None or w.phase == "seated") and not (UNITS and name == "orch-bot" and state == "sleeping"):
            if vstate == "working":
                cpu = p.get("cpu") or 0  # typing speed follows the process's real cpu
                spd = 1 if cpu >= 30 else 2 if cpu >= 10 else 3 if cpu >= 3 else 4
                arms = ("/█-", "/█=")[(t // spd) % 2]
            elif vstate == "party":
                arms = ("\\█/", "/█\\")[(t // 3) % 2]
            else:
                arms = "/█\\"
            face = face_for(vstate, treat, t)
            g = p.get("glyph")
            if g and vstate in ("working", "idle"):  # each bot has its own eyes (gnoc_company.NAMES)
                face = f"({g}_{g})"
            cv.put(x + 1, y, face, skin, None, A_B | (A_D if state == "sleeping" else 0))
            if p.get("broke"):  # broke: asleep at the desk
                cv.put(x + 5, y - 1, ("zz ", " zz")[(t // 6) % 2], 250)
            hair = hair_for(name)
            cv.put(x + 1, y, "(", hair, None, A_B)                # hair frames the face
            cv.put(x + 5, y, ")", hair, None, A_B)
            cv.put(x + 1, y + 1, "▐", CHAIR)                      # the chair they sit in
            cv.put(x + 5, y + 1, "▌", CHAIR)
            cv.put(x + 2, y + 1, arms[0], skin)
            cv.put(x + 3, y + 1, arms[1], shirt if state != "sleeping" else 240)
            cv.put(x + 4, y + 1, arms[2], skin)
            if state == "sleeping":
                z = ("z  ", " z ", "  Z")[(t // 6) % 3]
                cv.put(x + 5, y - 1, z, 250)
            if treat == "joint":
                cv.put(x + 6, y - 1, ("~", "'", "~ ")[(t // 4) % 3], 250)
        else:  # nobody at the desk: the empty office chair
            cv.put(x + 2, y, "▗▄▖", CHAIR)
            cv.put(x + 2, y + 1, "▐█▌", CHAIR)
        if name == "orch-bot":
            # wastebasket: today's real rejected / fallback / error decisions, each one a crumpled paper
            nrej = (feed.data.get("brain") or {}).get("rejects_today", 0)
            if x >= 2:  # one cell left of the desk: inside the office wall in the office layout
                cv.put(x - 1, y + 2, "u", 250 if nrej else 244, None, A_B)
                if nrej:
                    cv.put(x - 1, y + 3, str(nrej) if nrej < 10 else "+", C_FAINT)
            for b0 in app.balls:
                f = (now - b0) / 1.2
                if 0 <= f <= 1 and (w is None or w.phase == "seated"):
                    bx = round(x + 3 + (x - 1 - (x + 3)) * f)
                    by = round(y - 1 + 3 * f - 2 * math.sin(math.pi * f))
                    if by >= 1:
                        cv.put(bx, by, "o", 255, None, A_B)
            th = dict(BRAIN_THINK)
            if th and (w is None or w.phase == "seated"):
                dots = "." * ((t // 5) % 3 + 1)
                ty_ = y - 2 if bubbles.get(name) and y - 2 > sc.ft else y - 1  # above a speech bubble, never hidden by it
                overlays.append((x, ty_, f"thinking{dots:<3}" if BOTS_ONLY else
                                 f"thinking{dots:<3} {th.get('action')} {th.get('prog', '')} "
                                 f"({_dur(now - th.get('t', now))})", "think", is_sel_early))
        if name == CHAT_KEY:
            # the chat desk gets the same treatment: the tool call that is OPEN right now, with its real age.
            # This is the whole point of the activity log - the desk works while the work happens, not after.
            nw = chat_now()
            if nw and (w is None or w.phase == "seated"):
                dots = "." * ((t // 5) % 3 + 1)
                ty_ = y - 2 if bubbles.get(name) and y - 2 > sc.ft else y - 1
                extra = f" +{len(CHAT_LIVE) - 1}" if len(CHAT_LIVE) > 1 else ""
                # age before argument: the wall clips the tail, and how long it has been running is the fact
                overlays.append((x, ty_, f"{nw[0]} {_dur(now - nw[2])}{dots:<3}{extra}"
                                         + (f": {nw[1]}" if nw[1] else ""), "think", is_sel_early))
        cat = app.cat
        if cat and cat.kind == "nap" and cat.phase == "hold" and app.cat_desk == i:
            cv.put(x + 1, y + 2, "=^.^=", 180, None, A_B)
            cv.put(x + 6, y + 1, ("z", "Z", " ")[(t // 6) % 3], 250)
        # papers delivered to this desk by a real handoff (fade after ~2.5 min)
        pile = [d for d, until in PILES.get(name, []) if until > now]
        PILES[name] = [(d, u) for d, u in PILES.get(name, []) if u > now]
        if pile:
            g, col = DOCS[pile[-1]][:2]
            cv.put(x + 13, y + 2, g, col, None, A_B)
            if len(pile) > 1:
                cv.put(x + 14, y + 2, str(min(9, len(pile))), C_BLACK, None, A_B)
        # nameplate
        num = i + 1
        is_sel = sel_key == name
        plate = clip(f" {num} {label_of(name)}", DESK_W - (1 if UNITS else 2))
        if is_sel:
            cv.put(x, y + 4, " " * DESK_W, bg=C_ACCENT)
            cv.put(x, y + 4, STATE_GLYPH.get(state, "●"), STATE_COLOR[state], C_ACCENT)
            cv.put(x + 1, y + 4, plate, C_BLACK, C_ACCENT, A_B)
        else:
            cv.put(x, y + 4, STATE_GLYPH.get(state, "●"), STATE_COLOR[state], None, A_B)
            cv.put(x + 1, y + 4, plate, C_TEXT if state != "sleeping" else C_FAINT, None, A_B)
        if p.get("bot") and p.get("job"):  # the sign on the desk: the kind of bug this bot hunts
            cv.put(x + 1, y + 3, clip(str(p["job"]), DESK_W - 2).center(DESK_W - 2), 230, 94, A_B)
        duty = unit_duty(name) if p.get("unit") else ""
        if duty:  # UNITS: the sign on the desk is the job this unit holds right now
            cv.put(x + 1, y + 3, clip(duty, DESK_W - 2).center(DESK_W - 2), 230, 94, A_B)
        if sc.spark and p.get("unit"):  # its own reading: busy history and VRAM, cores, calls open, battery
            cv.put(x, y + 5, clip(unit_spark(p, state), DESK_W), STATE_COLOR[state])
        elif sc.spark and p.get("bot"):  # name tag: coins (wallet) and aim stars (from the brier, by code)
            n_st = p.get("stars")
            aim = ("*" * n_st) if n_st else "aim ?"
            cv.put(x, y + 5, clip(f"(c){p.get('wallet') if p.get('wallet') is not None else '?'} {aim}", DESK_W),
                   C_BAD if p.get("broke") else C_GOLD)
        elif sc.spark:
            hist = CPU_HIST.get(name) or []
            col = STATE_COLOR[state]
            cv.put(x, y + 5, sparkline(hist, 6, floor=10), col)
            cv.put(x + 7, y + 5, f"{min(99, int(p.get('cpu', 0))):>2}%", C_MUTED)
            e = mrow.get("energy", 80)
            ecol = C_GOOD if e >= 50 else (C_WARN if e >= 20 else C_BAD)
            cv.put(x + 11, y + 5, meter(e / 100, 4, "▮", "▯"), ecol)
        if is_sel and (t // 5) % 2 == 0:
            cv.put(x - 1, y - 1, "┌", C_ACCENT, None, A_B)
            cv.put(x + DESK_W, y - 1, "┐", C_ACCENT, None, A_B)
            cv.put(x - 1, y + sc.block_rows - 1, "└", C_ACCENT, None, A_B)
            cv.put(x + DESK_W, y + sc.block_rows - 1, "┘", C_ACCENT, None, A_B)
        app.hits.append((x - 1, y - 1, x + DESK_W, y + sc.block_rows, i))
        # bubble
        bub = bubbles.get(name)
        if not bub and p.get("bot") and (w is None or w.phase == "seated"):
            if name == "orch-bot":   # the manager's line for the office (company.json, numbers checked by code)
                say = (((feed.data.get("company") or {}).get("c") or {}).get("manager") or {}).get("bubble")
                if say and not BRAIN_THINK:
                    overlays.append((x, y - 1, say, "real", is_sel))
            elif state == "working" and (p.get("doing") or p.get("assignment")):
                overlays.append((x, y - 1, p.get("doing") or p["assignment"], "real", is_sel))
        if not bub and duty and (len(duty) > DESK_W - 2 or is_sel) and (w is None or w.phase == "seated"):
            overlays.append((x, y - 1, duty, "real", is_sel))  # the sign is short: the whole job, over the desk
        if bub:
            kind = "alert" if bub.get("alert") else ("flavor" if bub.get("flavor") else "real")
            if w is None or w.phase == "seated":
                overlays.append((x, y - 1, bub["text"], kind, is_sel))
            elif w.phase == "hold" and not w.task:
                overlays.append((w.pos[0] - 2, w.pos[1] - 3,
                                 ("filing: " if w.kind == "cabinet" else "") + bub["text"], kind, is_sel))

    # fixtures with live state
    x, y, _ = sc.fix["coffee"]
    cv.put(x + 1, y + 1, ("▒▓", "▓▒")[(t // 3) % 2] if tod != "night" else "▒▒", 137)
    x, y, _ = sc.fix["tray"]
    alert = now < LEAD_ALERT_UNTIL
    n_open = _LAST_SEEN.get("oss_open")
    tcol = C_BAD if alert else (C_GOLD if now < TRAY_FLASH_UNTIL else (C_WARN if n_open else C_FAINT))
    cv.put(x, y, "┌─IN──┐", tcol, None, A_B if alert else 0)
    tray = "  ?  " if n_open is None else ("empty" if n_open == 0 else f"▤{min(n_open, 9999):>4}")
    cv.put(x, y + 1, f"│{tray}│", tcol, None, A_B)
    cv.put(x, y + 2, "└─────┘", tcol)
    cv.put(x - 1, y - 1, "SCAN FINDS " if BOTS_ONLY else "LEAD TRIAGE", C_BAD if alert else C_FAINT, None,
           A_B if alert else 0)
    x, y, _ = sc.fix["shredder"]
    shred = now < SHRED_UNTIL
    scol = C_GOOD if shred else 245
    cv.put(x, y, "┌SHRED┐", scol)
    cv.put(x, y + 1, "│" + (("/////", "\\\\\\\\\\")[t % 2] if shred else "▔▔▔▔▔") + "│", scol)
    cv.put(x, y + 2, "└─────┘", scol)
    if shred:
        for k in range(3):
            cv.put(x + 1 + random.randrange(5), y + 3 if y + 3 < sc.MH - 1 else y + 2, "'", 250)
    x, y, _ = sc.fix["printer"]
    if now < PRINT_UNTIL:
        k = (t // 3) % 4
        cv.put(x + 1, y + 1, "▀▀▀▀", C_GOOD)
        cv.put(x + 1, y - 1 - (k % 2), " ▤▤ ", 255, None)
    x, y, _ = sc.fix["cabinet"]
    if any(w.kind == "cabinet" and w.phase == "hold" for w in app.walkers.values()):
        cv.put(x, y, "┌───┐", C_GOLD, None, A_B)
        cv.put(x + 1, y + 1, "▤▤▤", C_GOLD, None, A_B)

    # boss office + server room (COMPANY: the MANAGER office, orch-bot at the desk)
    if sc.right_w and BOTS_ONLY:
        draw_manager_office(cv, app, sc, t, overlays)
    if sc.right_w:
        active = app.boss_active() if not BOTS_ONLY else bool(comp.get("started")) and not comp.get("paused")
        rx = sc.rx
        here = app.boss_here()
        if not BOTS_ONLY:
            cv.put(rx + 2, sc.ft + 2, " IN  " if here else (" LIT " if active else " OUT "), C_BLACK,
                   C_GOOD if here else (C_WARN if active else C_FAINT), A_B)
        if not active:
            cv.tint(rx + 1, sc.ft, sc.MW - rx - 2, sc.office_bottom - sc.ft, 233)
        bp = [d for d, until in PILES.get("boss", []) if until > now]
        PILES["boss"] = [(d, u) for d, u in PILES.get("boss", []) if u > now]
        for k, d in enumerate(bp[-4:]):  # reports / hits waiting on the boss's desk
            g, col = DOCS[d][:2]
            cv.put(rx + 18 + k, sc.ft + 4, g, col, 130 if d != "hit" or (t // 4) % 2 else 52, A_B)
        b = app.boss
        if b and active and not BOTS_ONLY:
            if b.phase == "seated":
                bx, by = sc.boss_seat
                draw_boss(cv, bx + 2, by + 2, t, False, seated=True)  # behind the desk: no legs
        for i, (hx, hy) in enumerate(sc.racks):
            if hy + 5 >= sc.sy:
                break
            key = list(hosts.keys())[i] if i < len(hosts) else None
            row = hosts.get(key) if key else None
            if not row:
                continue
            num = len(procs) + i + 1
            is_sel = sel_key == f"host:{key}"
            fcol = C_ACCENT if is_sel else 245
            cv.put(hx, hy, "┌" + f"{num:>2}" + "─" * 8 + "┐", fcol, None, A_B if is_sel else 0)
            bat = (row.get("link") or {}).get("battery")
            if bat is not None:  # a phone: its real battery level in the rack frame (red under 20 %)
                chg = "+" if (row.get("link") or {}).get("charging") else ""
                cv.put(hx + 4, hy, f"{bat}%{chg}", C_BAD if bat < 20 else C_GOOD, None, A_B)
            models = row.get("models") or []
            for r in range(2):
                for k in range(5):
                    if not row.get("up"):
                        ch, col = "▫", 52
                    elif key == "desktop" and now < app.rack_flash:
                        ch, col = "▪", 231  # a packet from the uplink just landed
                    elif models:
                        ch, col = "▪", (46 if random.random() < 0.6 else 214)
                    else:
                        ch, col = "▪", 28 if (t // 10 + k + r) % 5 else 46
                    cv.put(hx + 1 + k * 2, hy + 1 + r, ch, col, 233)
            cv.put(hx, hy + 3, "└" + "─" * 10 + "┘", fcol)
            cv.put(hx, hy + 4, clip(row.get("label", key), 12), C_TEXT if row.get("up") else C_FAINT, None, A_B)
            sub = models[0]["name"] if models else ("idle" if row.get("up") else "not linked")
            if row.get("in_split"):
                sub = "RPC in split" + (f" +{models[0]['name']}" if models else "")
            lc = app.last_call
            if key == "desktop" and app.inflight:
                who = {label_of(CALLER_DESK[c["caller"]]) if CALLER_DESK.get(c.get("caller")) else str(c.get("caller"))
                       for c in INFLIGHT.values()}
                sub = (f"◆{app.inflight} {next(iter(who))}" if len(who) == 1 else
                       f"◆ {app.inflight} call{'s' * (app.inflight != 1)} open")
            elif key == "desktop" and lc and time.time() - (lc.get("ts") or 0) < 300:
                sub = f"{lc.get('model', '?')} {(lc.get('ms') or 0) / 1000:.0f}s" + (" ERR" if (lc.get("status") or 0) >= 400 else "")
            cv.put(hx, hy + 5, clip(sub, 12), C_GOOD if models else C_MUTED)
            app.hits.append((hx, hy, hx + 12, hy + 5, len(procs) + i))
            bub = bubbles.get(f"host:{key}")
            if bub:
                overlays.append((hx, hy - 1, bub["text"], "real", is_sel))
        if sc.crac:
            fx, fy = sc.crac
            blades = "|/-\\"[t % 4]
            cv.put(fx + 1, fy, f"({blades})", 117)
            cv.put(fx + 15, fy, f"({blades})", 117)
        if not hosts and not BOTS_ONLY:
            cv.put(rx + 3, sc.office_bottom + 3, "no machines linked", C_FAINT)
            cv.put(rx + 3, sc.office_bottom + 4, "see gnoc-office --help", C_FAINT)
        if BOTS_ONLY:
            draw_server_rack(cv, app, sc, t, len(hosts))

    if BOTS_ONLY:
        draw_line_floor(cv, app, sc, t)
    if UNITS:
        draw_units_floor(cv, app, sc, t, procs, states)

    feet = [w.pos for w in list(app.walkers.values()) + [app.boss] if w and w.phase != "seated"]
    feet += [v["w"].pos for v in app.visitors.values()]
    if app.cat and not (app.cat.kind == "nap" and app.cat.phase == "hold"):
        feet += [(app.cat.pos[0] + d, app.cat.pos[1]) for d in (-2, 2)]  # the cat is 5 wide on its feet row
    for fname, label in (("coffee", "COFFEE"), ("fridge", "FRIDGE"), ("cooler", "COOLER"), ("printer", "PRINTER"),
                         ("cabinet", "FILES"), ("tray", "LEAD TRIAGE")):
        if fname in sc.fix:
            fx_, fy_, _ = sc.fix[fname]
            lx0, lx1 = fx_ - 1, fx_ - 1 + len(label)
            # a sprite's legs are 3 wide on its feet row: any feet on the label row near it would leave fragments
            # feet on the label row, or 1-2 rows below it in the gaps between fixtures (the head lands on the label)
            if any(fy_ - 1 <= py <= fy_ + 1 and lx0 - 2 <= px < lx1 + 2 for px, py in feet):
                cv.put(lx0, fy_ - 1, " " * len(label))

    # walkers on the floor (drawn after furniture so they pass in front of it)
    for i, p in enumerate(procs):
        w = app.walkers.get(p["name"])
        if not w or w.phase == "seated":
            continue
        shirt, skin, pants = look_for(p["name"])
        state = states.get(p["name"], "idle")
        fx, fy = w.pos
        face = "(^o^)" if partying else face_for("walk", None, t)
        carrying = w.phase == "return" or (w.phase == "walk" and w.kind in ("deliver", "prod"))
        carry = "coffee" if w.kind == "break" and w.phase == "hold" else (w.carry if carrying else None)
        if w.kind == "mop" and w.phase in ("walk", "hold"):
            carry = None
            cv.put(fx + 2, fy, "⌐", 179)  # the mop
        if w.kind == "sweep" and w.phase in ("walk", "hold"):
            carry = None
            cv.put(fx + 2, fy, ("╲", "╱")[(t // 3) % 2] if w.phase == "hold" else "╱", 137, None, A_B)  # the broom
            if w.phase == "hold":
                cv.put(fx + 3, fy, ("≈", "∴", "·")[(t // 2) % 3], 250)  # dust puff
        draw_sprite(cv, fx, fy, face, shirt, skin, pants, t, w.phase in ("walk", "return"),
                    carry=carry, dance=partying and w.phase == "hold", hair=hair_for(p["name"]))
        if w.task and w.phase == "hold":  # dropping the paper off: say what it is (the real ticker line)
            overlays.append((fx - 2, fy - 3, w.task["label"], "real", sel_key == p["name"]))
        if w.kind == "prod" and w.phase == "hold" and UNIT_VISIT.get(p["name"]):  # in PROD: the call it serves
            overlays.append((fx - 2, fy - 3, UNIT_VISIT[p["name"]]["label"], "real", sel_key == p["name"]))
        if sel_key == p["name"] and fy + 1 < sc.MH - 1:
            cv.put(fx - 1, fy + 1, f"▲{i + 1}", C_ACCENT, None, A_B)
        # (cooler gossip removed: bubbles carry real events only)
    b = app.boss
    if b and b.phase != "seated" and app.boss_active() and not BOTS_ONLY:
        draw_boss(cv, b.pos[0], b.pos[1], t, b.phase in ("walk", "return"), dance=partying)
        if b.phase == "hold":
            pass  # the boss walks the floor while work is live; he does not speak invented lines

    draw_lab(cv, app, sc, t, overlays)

    cat = app.cat
    if cat and not (cat.kind == "nap" and cat.phase == "hold"):
        cx_, cy_ = cat.pos
        moving = cat.phase in ("walk", "return")
        cv.put(cx_ - 2, cy_, ("=^.^=", "=^-^=")[(t // 3) % 2] if moving else "=^.^=", 180, None, A_B)

    # depth: an office's top and side walls are BEHIND the people inside it, so they are redrawn over the sprites
    # (QA 2026-10-22: a worker walking the 1-column lane beside a wall drew its arms through the wall); the
    # bottom wall stays under them, since anyone touching it is standing in front of the office
    for title, rx0, ry0, rw, rh in sc.rooms + ([("WAR ROOM", *sc.war)] if sc.war else []):
        wc = ROOM_WALL.get(title, 245) if tod != "night" else 240
        for yy in range(ry0 + 1, ry0 + rh - 1):
            for xx in (rx0, rx0 + rw - 1):
                if cv.ch[yy][xx] != "│":
                    cv.put(xx, yy, "│", wc)
        top = "┌" + "─" * (rw - 2) + "┐"
        duty = ROOM_DUTY.get(title)
        name = f"┤ {title} · {duty} ├" if duty and len(title) + len(duty) + 9 <= rw else f"┤ {title} ├"
        top = top[:2] + name + top[2 + len(name):]
        for k, ch in enumerate(top):
            if cv.ch[ry0][rx0 + k] != ch:
                cv.put(rx0 + k, ry0, ch, C_GOLD if (title == "WAR ROOM" and 2 <= k < 2 + len(name)) else
                       (C_TEXT if 2 <= k < 2 + len(name) else wc), None, A_B if 2 <= k < 2 + len(name) else None)

    if BOTS_ONLY:
        draw_jam_and_floats(cv, app, sc, t, procs)
    for p in app.particles:
        x, y = p[0], p[1]
        if 0 <= y < sc.MH and 0 <= x < sc.MW and cv.ch[y][x] == " ":
            cv.put(x, y, p[2], p[3], None, A_B)

    walls = sc.rooms + ([("WAR", *sc.war)] if sc.war else [])
    overlays.sort(key=lambda o: (o[4], o[1], o[0]))  # the selected desk's bubble last, on top
    drawn = {}  # row -> [(x0, x1)]
    for k, (x, y, text, kind, is_sel) in enumerate(overlays):
        if not is_sel and any(a <= x < b for a, b in drawn.get(y, [])):
            continue  # same spot as a bubble already drawn (several workers at the cooler share the gossip)
        maxw = 60 if is_sel else 36
        # fit at the screen's right edge here, so draw_bubble never shifts it left (a shifted bubble slid across
        # an office wall past the clip below; QA 2026-10-22)
        maxw = min(maxw, cv.w - 1 - x - 2)
        if not is_sel:
            # stop at the wall of the office the bubble starts in (QA 2026-10-22: a desk bubble ran across the
            # wall and over the war-room board) and before the next bubble on the same row (they overwrote)
            for _, rx0, ry0, rw, rh in walls:
                if ry0 <= y < ry0 + rh:  # stop before the first side wall in its way, whichever side it starts on
                    if x in (rx0, rx0 + rw - 1):
                        x += 1
                    for wx in (rx0, rx0 + rw - 1):
                        if wx > x:
                            maxw = min(maxw, wx - x - 2)
            nxt = [ox for ox, oy, _, _, osel in overlays if oy == y and ox > x and not osel]
            if nxt:
                maxw = min(maxw, min(nxt) - x - 3)
        if maxw >= 6:
            drawn.setdefault(y, []).append((x, x + min(maxw, len(text)) + 2))  # the width really drawn
            draw_bubble(cv, x, y, text, kind, maxw=maxw)

    # toasts (top-right, under the wall)
    with LOCK:
        live = [tt for tt in TOASTS if tt["until"] > now]
        TOASTS[:] = live
    ty = sc.ft + 1
    for tt in live[-3:]:
        s = f" {tt['text']} "
        tx = max(2, (sc.rx if sc.right_w else sc.MW) - len(s) - 2)
        cv.put(tx, ty, s, C_BLACK, tt["color"], A_B)
        cv.put(tx + 1, ty + 1, " " * len(s), None, 232)
        ty += 2
    if partying:
        banner = f"  OFFICE PARTY  {PARTY_REASON}  "
        bx = max(1, (sc.MW - len(banner)) // 2)
        cv.put(bx, sc.sy - 1, clip(banner, sc.MW - 2), C_BLACK, [201, 214, 226, 51][(t // 3) % 4], A_B)
    return cv


# ---------- drawing: header, rail, ticker, key bar, modals ----------

CHAT_STYLE = {"you": ("you ", 25), "gnoc": ("gnoc", 54), "tool": ("tool", 94), "bot": ("bot ", 240)}


def chat_lines(feed, width):
    """Wrapped chat rows (prefix, colour, text) for any width, newest last."""
    ch = (feed.data.get("chat") or {}).get("chat") or []
    out = []
    for role, txt in ch:
        tag, col = CHAT_STYLE.get(role, (role[:4], 240))
        for k, piece in enumerate(wrap(txt, max(8, width - 6), 3 if role == "gnoc" else 2) or [""]):
            out.append((tag if k == 0 else "    ", col, piece))
    return out


def draw_war_board(cv, app, sc, t):
    x0, y0, w, h = sc.war
    if REDACT:  # public view: no gnoc chat; the real orch.log across the board, names blacked out downstream
        bx, by, bw, bh = x0 + 1, y0 + 1, w - 2, h - 2
        cv.fill(bx, by, bw, bh, " ", 236, 255)
        cv.put(bx + 1, by, "ORCH LOG", 25, 255, A_B)  # no dot: the streamer blacks out anything dotted
        cv.put(bx + 11, by, "live, names redacted", 244, 255)
        log = (app.feed.data.get("chat") or {}).get("log") or []
        for k, (ts, txt) in enumerate(log[-(bh - 1):] if bh > 1 else []):
            cv.put(bx + 1, by + 1 + k, ts[:8], 244, 255)
            cv.put(bx + 10, by + 1 + k, clip(txt, bw - 11), 238, 255)
        return
    bx, by, bw, bh = x0 + 1, y0 + 1, w - 2, h - 2  # the board fills the room
    cv.fill(bx, by, bw, bh, " ", 236, 255)
    data = app.feed.data.get("chat") or {}
    split = bw >= 70
    cw = (bw * 55) // 100 if split else bw
    lw = bw - cw - 1 if split else bw
    ch_rows = bh - 1 if split else max(2, (bh - 2) // 2)
    age = _ago(datetime.fromtimestamp(data["mtime"], timezone.utc).isoformat()) if data.get("mtime") else ""
    cv.put(bx + 1, by, clip(f"GNOC CHAT  {age}", cw - 2), 160, 255, A_B)
    lines = chat_lines(app.feed, cw - 1)[-(ch_rows - 1):] if ch_rows > 1 else []
    if not lines:
        lines = [("    ", 244, "no gnoc chat yet (gnoc chat)")]
    for k, (tag, col, piece) in enumerate(lines):
        cv.put(bx + 1, by + 1 + k, tag, col, 255, A_B)
        cv.put(bx + 6, by + 1 + k, clip(piece, cw - 7), 236, 255)
    if split:
        lx, ly, rows = bx + cw + 1, by, bh
        for yy in range(by, by + bh):
            cv.put(bx + cw, yy, "┊", 250, 255)
    else:
        lx, ly, rows = bx, by + ch_rows + 1, bh - ch_rows - 1
    cv.put(lx + 1, ly, "ORCH.LOG", 25, 255, A_B)
    log = data.get("log") or []
    for k, (ts, txt) in enumerate(log[-(rows - 1):] if rows > 1 else []):
        cv.put(lx + 1, ly + 1 + k, ts[:5], 244, 255)
        cv.put(lx + 7, ly + 1 + k, clip(txt, lw - 8), 238, 255)
    # a marker on the tray, and the board flashes for a moment when a new chat message lands
    if data.get("mtime") and time.time() - data["mtime"] < 6 and (t // 3) % 2 == 0:
        cv.put(bx + bw - 3, by, " ● ", 160, 255, A_B)


def draw_company_board(cv, app, sc, t):
    """COMPANY wall boards: PAYROLL (wallet, brier, status, run of results, star bot), BETS (open hypothesis
    bets, the spec's wager board) and the BOUNTY board, all read from company.json."""
    x0, y0, w, h = sc.war
    bx, by, bw, bh = x0 + 1, y0 + 1, w - 2, h - 2
    cv.fill(bx, by, bw, bh, " ", 236, 255)
    comp = app.feed.data.get("company") or {}
    c = comp.get("c") or {}
    if not comp.get("started"):
        cv.put(bx + 1, by, "PAYROLL  BETS  BOUNTY BOARD", 25, 255, A_B)
        cv.put(bx + 1, by + 2, clip("company: not started", bw - 2), 160, 255, A_B)
        cv.put(bx + 1, by + 3, clip("orch-bot's manager step writes .claude/state/economy/company.json each tick",
                                    bw - 2), 244, 255)
        return
    pw = max(32, (bw * 46) // 100)
    rest = bw - pw - 1
    mw = rest // 2
    kx = bx + pw + 1 + mw + 1
    for yy in range(by, by + bh):
        cv.put(bx + pw, yy, "┊", 250, 255)
        if rest > 20:
            cv.put(bx + pw + 1 + mw, yy, "┊", 250, 255)
    head = "PAUSED" if comp.get("paused") else "lanes stopped" if comp.get("stop") else "open"
    cv.put(bx + 1, by, clip(f"PAYROLL {head}  star: {c.get('bot_of_day') or '-'}", pw - 2), 25, 255, A_B)
    orders = (app.feed.data.get("line") or {}).get("orders") or []
    fx, fy, fw, fh = line_board_box(sc)
    if fh >= 3:                                   # THE LINE gets its own board on the floor under the war room
        draw_line_board(cv, orders, fx, fy, fw, fh)
    elif bh >= 6:                                 # no floor room: a strip along the bottom of this board
        nl = min(len(orders), bh - 5) + 1
        bh -= nl
        draw_line_board(cv, orders, bx, by + bh, bw, nl, framed=False)
    roster = c.get("roster") or []
    stc = {"working": 28, "idle": 25, "probation": 166, "paused": 130}
    for k, r in enumerate(roster[:max(0, bh - 2)]):
        br = r.get("brier")
        st4 = {"working": "work", "idle": "idle", "probation": "PROB", "paused": "paus"}.get(r.get("status"), "?")
        sk = r.get("run") or 0
        line = (f"{str(r.get('bot'))[:10]:<10}{str(r.get('wallet', '?')):>6} {'-' if br is None else f'{br:.2f}':<4} "
                f"{st4}{('+' if sk > 0 else '') + str(sk):>3}")
        cv.put(bx + 1, by + 1 + k, clip(line, pw - 2), stc.get(r.get("status"), 238), 255)
    bon = c.get("bonus") or {}
    if bh >= 3 and bon:
        cv.put(bx + 1, by + bh - 1, clip(f"bonus {bon.get('day', '-')}: pool {bon.get('pool', 0)} RC, "
                                         f"{len(bon.get('paid') or [])} paid", pw - 2), 244, 255)
    if rest > 20:
        mx = bx + pw + 2
        cv.put(mx, by, clip(f"BETS  {len(c.get('bets') or [])} open", mw - 1), 25, 255, A_B)
        for k, m in enumerate((c.get("bets") or [])[-max(0, bh - 1):]):
            cv.put(mx, by + 1 + k, clip(f"{m.get('program')} {m.get('hyp')} L{m.get('long')} S{m.get('short')} "
                                        f"b{m.get('budget')}", mw - 1), 238, 255)
        if not c.get("bets"):
            cv.put(mx, by + 1, clip("no open bets", mw - 1), 244, 255)
        cv.put(kx, by, clip(f"BOUNTY BOARD  {len(c.get('bounties') or [])} live", bw - (kx - bx) - 1), 160, 255, A_B)
        for k, b in enumerate((c.get("bounties") or [])[:max(0, (bh - 1) // 2)]):
            cv.put(kx, by + 1 + 2 * k, clip(f"{b.get('id')} {b.get('amount')} RC {b.get('program')}",
                                            bw - (kx - bx) - 1), 236, 255, A_B)
            cv.put(kx, by + 2 + 2 * k, clip(f"  {b.get('crown')}" + (f" [{b.get('claimant')}]" if b.get("claimant")
                                                                       else " [open]"), bw - (kx - bx) - 1), 238, 255)
        if not c.get("bounties"):
            cv.put(kx, by + 1, clip("no bounties funded", bw - (kx - bx) - 1), 244, 255)


def line_board_box(sc):
    """(x, y, w, h) of the floor under the war room, where THE LINE board hangs (h < 3 = no room)."""
    x0, y0, w, h = sc.war
    top = y0 + h + 1
    return x0, top, w, min(7, sc.sy - 2 - top)


def draw_line_board(cv, orders, x, y, w, h, framed=True):
    """THE LINE (line.json): one row per open work order, its station 0-8 as a progress bar, age and RC spent."""
    if framed:
        cv.fill(x, y, w, h, " ", 236, 255)
    cv.put(x + 1, y, clip(f"THE LINE  {len(orders)} open work order{'s' * (len(orders) != 1)}  "
                          "stations 0-8, sales to retro", w - 2), 25, 255, A_B)
    if not orders:
        cv.put(x + 1, y + 1, clip("no open work orders (the manager opens one per funded bounty)", w - 2), 244, 255)
        return
    for k, wo in enumerate(orders[:max(0, h - 1)]):
        st_ = max(0, min(8, int(wo.get("station") or 0)))
        age = int(wo.get("age_s") or 0)
        cv.put(x + 1, y + 1 + k, "■" * (st_ + 1) + "□" * (8 - st_), 28, 255, A_B)
        cv.put(x + 11, y + 1 + k, clip(f"{st_} {wo.get('name') or ''}  {wo.get('program')} WO-{wo.get('id')}  "
                                       f"age {age // 3600}h{age % 3600 // 60:02d}m  RC {wo.get('rc_spent', 0)}/"
                                       f"{wo.get('budget_rc', '?')}  {wo.get('crown') or ''}", w - 12), 238, 255)


# ---------- bots-only: the four rooms' boards, the hallway folders, HELP WANTED, the servers box, JAM, floats ----------

def _screen(app):
    return (((app.feed.data.get("company") or {}).get("c") or {}).get("screen") or {})


def _room_rect(sc, title):
    return next(((x, y, w, h) for t_, x, y, w, h in sc.rooms if t_ == title), None)


def _room_door(sc, title):
    """The floor cell just outside a room's door: where a folder enters the hallway."""
    r = _room_rect(sc, title)
    if not r:
        return None
    x, y, w, h = r
    cell = (x + w // 2, y + h)
    return cell if sc.walkable(*cell) else None


def draw_room_boards(cv, app, sc):
    """ONE board per room, one line per item, max 6 (company.json screen.boards, built by gnoc_company.screen)."""
    boards = _screen(app).get("boards") or {}
    for title, (bx, by, bw, bh) in sc.boards.items():
        cv.fill(bx, by, bw, bh, " ", 236, 255)
        b = boards.get(title) or {}
        cv.put(bx + 1, by, clip(str(b.get("title") or title), bw - 2), 25, 255, A_B)
        if "reports" in b:  # THE PRESS: an unfiled report's title is the finding, so the public stream sees the kind only
            lines = [f"{r.get('program')} waiting for the user: {'a report' if REDACT else r.get('title')}"
                     for r in b["reports"]] or ["nothing waiting for the user"]
        else:
            lines = b.get("lines") or (["the manager has not opened the office yet"] if not boards else [])
        for k, ln in enumerate(lines[:max(0, bh - 1)]):
            col = C_GOOD if " PROVED" in ln and "NOT" not in ln else (160 if "NOT " in ln else 238)
            cv.put(bx + 1, by + 1 + k, clip(str(ln), bw - 2), col, 255)


def draw_folders(cv, app, sc, t):
    """THE HALLWAY: every open job (line.json work order) is a folder in the out-tray of the room it waits in, on
    that room's bottom wall left of the door. When it moves on, the folder walks down the hallway to the next
    room's door, two cells a frame (company.json kanban orders; before the first company tick, line.json)."""
    c = (app.feed.data.get("company") or {}).get("c") or {}
    orders = (c.get("kanban") or {}).get("orders")
    if isinstance(orders, list) and orders:
        where = [(str(o.get("id")), o.get("at")) for o in orders if isinstance(o, dict) and o.get("at") is not None]
    else:
        where = [(str(w.get("id")), min(int(w.get("station") or 0) + 1, 4)) for w in
                 (app.feed.data.get("line") or {}).get("orders") or []]
    folders = app.__dict__.setdefault("folders", {})
    resting, live = {}, set()
    for wid, at in where:
        title = ROOM_OF_STATION.get(at)
        if not title or not _room_rect(sc, title):
            continue
        live.add(wid)
        f = folders.get(wid)
        if f is None or f.get("scene") != id(sc):
            folders[wid] = f = {"room": title, "path": [], "k": 0, "scene": id(sc)}
        elif f["room"] != title:
            a, b = _room_door(sc, f["room"]), _room_door(sc, title)
            path = sc.path(a, b) if a and b else None
            f.update(room=title, path=([a] + path) if path else [], k=0)
        if f["path"] and f["k"] < len(f["path"]) - 1:
            f["k"] = min(len(f["path"]) - 1, f["k"] + 2)
            fx, fy = f["path"][f["k"]]
            if cv.ch[fy][fx] in (" ", "·"):
                cv.put(fx, fy, "▤", C_GOLD, None, A_B)
            continue
        f["path"] = []
        resting.setdefault(title, []).append(wid)
    for wid in [w for w in folders if w not in live]:
        del folders[wid]
    for title, ids in resting.items():
        x, y, w, h = _room_rect(sc, title)
        room = max(1, w // 2 - 3)
        shown = ids[:room - 2] if len(ids) > room else ids
        for k in range(len(shown)):
            cv.put(x + 1 + k, y + h - 1, "▤", 180, None, A_B)
        if len(shown) < len(ids):
            cv.put(x + 1 + len(shown), y + h - 1, clip(f"+{len(ids) - len(shown)}", 3), 180, None, A_B)


def draw_server_room(cv, app, sc, t):
    """THE SERVER ROOM: one rack per linked machine (laptop, desktop, phone: up LEDs, battery, the model loaded) and
    one rack row per pm2 infra process that is not a bot (LED + name). The LED blink is cosmetic."""
    r = _room_rect(sc, "SERVER ROOM")
    if not r:
        return
    x0, y0, w0, h0 = r
    x, y, w = x0 + 2, y0 + 2, w0 - 4
    last = y0 + h0 - 2
    procs = [p for p in (app.feed.data.get("pm2") or []) if p.get("name") not in COMPANY_BOTS + ("orch-bot",)]
    up = sum(p.get("status") == "online" for p in procs)
    cv.put(x, y, clip(f"{up}/{len(procs)} racks up", w), C_GOOD if up == len(procs) else C_WARN, None, A_B)
    y += 2
    for key, row in (app.hosts() or {}).items():
        if y + 2 > last:
            break
        on = bool(row.get("up"))
        leds = "".join("▪" for _ in range(5))
        cv.put(x, y, "┌" + "─" * (w - 2) + "┐", 245)
        cv.put(x + 1, y + 1, leds, (46 if (t // 10) % 5 else 28) if on else 52, 233)
        bat = (row.get("link") or {}).get("battery")
        lab = clip(str(row.get("label", key)) + (f" {bat}%" if bat is not None else ""), w - 9)
        cv.put(x + 7, y + 1, lab, C_TEXT if on else C_FAINT, None, A_B)
        models = row.get("models") or []
        cv.put(x, y + 2, "└" + "─" * (w - 2) + "┘", 245)
        cv.put(x + 2, y + 2, clip(f" {models[0]['name'] if models else ('idle' if on else 'not linked')} ", w - 4),
               C_GOOD if models else C_MUTED)
        y += 4
    for k, p in enumerate(procs):
        if y > last:
            cv.put(x, last, clip(f"+{len(procs) - k} more", w), C_FAINT)
            break
        on = p.get("status") == "online"
        col = (46 if (t // 10 + k) % 7 else 28) if on else (C_BAD if p.get("status") == "errored" else 52)
        cv.put(x, y, "▪", col)
        cv.put(x + 2, y, clip(str(p.get("name")), w - 2), C_MUTED if on else C_FAINT)
        y += 1


def draw_line_floor(cv, app, sc, t):
    sv = _screen(app)
    LEGEND_TEXT[0] = str(sv.get("legend") or "")
    draw_room_boards(cv, app, sc)
    draw_folders(cv, app, sc, t)
    draw_server_room(cv, app, sc, t)
    hlp = sv.get("help")
    r = _room_rect(sc, "THE FLOOR")
    if hlp and r:   # the manager's HELP WANTED sign, on the floor where the empty desks are
        x, y, w, h = r
        cv.put(x + 2, y + h - 2, clip(f" {hlp} ", w - 4), C_BLACK, C_INFO, A_B)


def draw_jam_and_floats(cv, app, sc, t, procs):
    """JAM: a red sign on the top wall of the room that is backed up (the line's fullest inbox, by code). PROVED: a
    two-second "+N (c)" float over the bot's desk."""
    jam = _screen(app).get("jam")
    r = _room_rect(sc, jam) if jam else None
    if r:
        x, y, w, h = r
        cv.put(x + w - 8, y, " JAM ", C_WHITE, 160 if (t // 5) % 2 else 124, A_B)
    names = [p["name"] for p in procs]
    now = time.time()
    for who, text, until in getattr(app, "floats", []):
        if who in names and names.index(who) < len(sc.desks) and until > now:
            dx, dy = sc.desks[names.index(who)]
            rise = int((2.0 - (until - now)) * 1.5)
            yy = max(sc.ft, dy - 2 - rise)
            cv.put(dx + 1, yy, text, C_GOLD, None, A_B)


def manager_bubble(app):
    """orch-bot's speech: the brain's last decision (brain.jsonl), else the manager's own line from company.json."""
    brain = app.feed.data.get("brain") or {}
    if brain.get("action"):
        return clip(f"{brain.get('action')}: {brain.get('reason') or brain.get('status') or ''}", 120)
    c = (app.feed.data.get("company") or {}).get("c") or {}
    return clip((c.get("manager") or {}).get("bubble") or "", 120)


def draw_manager_office(cv, app, sc, t, overlays):
    """COMPANY: the MANAGER office in the right column (the old boss office): orch-bot at the desk."""
    rx = sc.rx
    comp = app.feed.data.get("company") or {}
    lit = comp.get("started") and not comp.get("paused")
    cv.put(rx + 2, sc.ft + 1, "MANAGER", C_BLACK, C_GOOD if lit else (C_WARN if comp.get("paused") else C_FAINT), A_B)
    cv.put(rx + 10, sc.ft + 1, "orch-bot", C_TEXT, None, A_B)
    bx, by = sc.boss_seat
    shirt, skin, pants = look_for("orch-bot")
    cv.put(bx, by + 0, face_for("working" if lit else "idle", None, t), skin, None, A_B)
    cv.put(bx + 1, by + 1, "/", skin)
    cv.put(bx + 2, by + 1, "█", shirt)
    cv.put(bx + 3, by + 1, "\\", skin)
    th = (BRAIN_THINK or {}).get("action")
    if th:
        overlays.append((rx + 2, sc.ft + 7, f"thinking... {th}", "think", False))
    else:
        text = manager_bubble(app)
        if text:
            overlays.append((rx + 2, sc.ft + 7, text, "real", False))


def draw_server_rack(cv, app, sc, t, n_hosts):
    """COMPANY: pm2 infra (ollama-oc, desktop-proxy, tunnels, website...) drawn as one SERVER RACK, not as people."""
    procs = [p for p in (app.feed.data.get("pm2") or []) if p.get("name") not in COMPANY_BOTS + ("orch-bot",)]
    per_row = max(1, (sc.right_w - 3) // 13)
    y = sc.office_bottom + 2 + -(-n_hosts // per_row) * 7 if n_hosts else sc.office_bottom + 2
    x = sc.rx + 2
    avail = sc.sy - y - 1
    if avail < 2:
        return
    cv.put(x, y, clip(f"SERVER RACK  {sum(p.get('status') == 'online' for p in procs)}/{len(procs)} up",
                      sc.right_w - 3), C_TEXT, None, A_B)
    colw = 13
    cols = max(1, (sc.right_w - 3) // colw)
    for k, p in enumerate(procs[:(avail - 1) * cols]):
        r, cc = divmod(k, cols)
        on = p.get("status") == "online"
        led = "▪" if on else "▫"
        col = (46 if (t // 10 + k) % 7 else 28) if on else (C_BAD if p.get("status") == "errored" else 52)
        cv.put(x + cc * colw, y + 1 + r, led, col, 233)
        cv.put(x + cc * colw + 1, y + 1 + r, clip(str(p.get("name")), colw - 2), C_MUTED if on else C_FAINT)


# ---------- UNITS: the desks' glass, the four rooms' boards, PROD's consoles, the manager's out-tray ----------

def _gb(b):
    return f"{(b or 0) / 1024 ** 3:.1f}"


def _video_on(key):
    """The STUDIO job whose stage child (else node process) last ran on this unit's cores, or None."""
    with LOCK:
        return next((j for j in VIDEO_LIVE.values() if j.get("unit") == key), None)


def unit_screen_cells(p, state, t, tod):
    """A unit's monitor, 4 cells: a GPU shows its busy % (sysfs), a CPU desk one bar per core (its 4 cores, /proc/stat
    since the last poll), the desktop GPU the model of the call open on it, scrolled; the rest, the usual glass."""
    if state in ("sleeping", "error", "party", "paused"):
        return screen_cells(state, 0, t, tod)
    kind, info = p.get("unit"), p.get("info") or {}
    glass = 22 if state == "working" else (17 if tod != "night" else 16)
    if kind == "gpu":
        s = f"{min(99, int(info.get('busy') or 0))}%"
        return [(c, 120 if state == "working" else 153, glass) for c in f"{s:>4}"]
    if kind == "cpu" and _video_on(p["name"]):  # STUDIO: a film strip marching, brightest while it encodes
        stage = _video_on(p["name"])["stage"]
        col = {"ENCODE": 213, "CAPTURE": 176, "VOICE": 139}.get(stage, 96)
        return [("▮" if (i + t // 3) % 2 == 0 else "▯", col, glass) for i in range(4)]
    if kind == "cpu":
        cells = []
        for c in (info.get("cores") or [])[:4]:
            b = UNIT_CPU["busy"].get(c, 0.0)
            cells.append((SPARK[min(7, int(b / 12.5))], 120 if b > 50 else (114 if b > 15 else 67), glass))
        return (cells + [(" ", glass, glass)] * 4)[:4]
    if kind == "desktop" and state == "working" and info.get("model"):
        word = short_model(info["model"]).upper() + "   "
        off = (t // 4) % len(word)
        return [((word + word)[off + i], 120, 22) for i in range(4)]
    return screen_cells(state, sum(map(ord, p["name"])), t, tod)


def unit_spark(p, state):
    """The row under a unit's nameplate: what its own reading says, in 15 cells."""
    kind, info = p.get("unit"), p.get("info") or {}
    hist = CPU_HIST.get(p["name"]) or []
    if kind == "gpu":
        return sparkline(hist, 6, floor=100) + f" {_gb(info.get('used'))}/{_gb(info.get('total'))}G"
    if kind == "cpu":
        return sparkline(hist, 6, floor=100) + f" {min(99, int(p.get('cpu') or 0)):>2}% x{len(info.get('cores') or [])}"
    if kind == "desktop":
        vram = f"{info['vram']:.1f}G" if isinstance(info.get("vram"), (int, float)) else ""
        if info.get("open"):
            return f"◆{info['open']} open {vram}"
        return f"{'linked' if info.get('up') else 'no link'} {vram}"
    if kind == "phone":
        lk = info.get("link") or {}
        bat = f"{lk['battery']}%{'+' if lk.get('charging') else ''}" if lk.get("battery") is not None else "-"
        mem = f" {lk['mem_avail_mb'] / 1024:.1f}G" if lk.get("mem_avail_mb") else ""
        return f"{bat}{' SPLIT' if info.get('in_split') else ''}{mem}"
    return ""


def unit_lines(p, state, w):
    """The INSPECTOR for a unit: every line is that unit's own reading and where it came from."""
    kind, info, key = p.get("unit"), p.get("info") or {}, p["name"]
    hist = CPU_HIST.get(key) or []
    L = []
    if kind == "gpu":
        L.append([("source ", C_MUTED, 0), (clip(f"{info.get('dev', '?')} ({info.get('kind', '?')} {info.get('pci', '')})",
                                              w - 10), C_FAINT, 0)])
        L.append([("busy   ", C_MUTED, 0), (sparkline(hist, w - 16, floor=100), STATE_COLOR[state], 0),
                  (f" {int(info.get('busy') or 0):>3}%", C_TEXT, A_B)])
        tot = info.get("total") or 0
        L.append([("vram   ", C_MUTED, 0), (meter((info.get("used") or 0) / tot if tot else 0, 12), C_GOLD, 0),
                  (f" {_gb(info.get('used'))}/{_gb(tot)} GB in use", C_TEXT, 0)])
        ps = _U.get("ps_last") if _ollama_gpu(_U.get("ps_last")) == key else None
        if ps:
            L.append([("ollama ", C_MUTED, 0), (clip(", ".join(short_model(m.get("name")) for m in ps), w - 10), C_GOOD, 0)])
    elif kind == "cpu":
        L.append([("source ", C_MUTED, 0), ("/proc/stat deltas, cores " + ",".join(map(str, info.get("cores") or [])),
                                           C_FAINT, 0)])
        L.append([("busy   ", C_MUTED, 0), (sparkline(hist, w - 16, floor=100), STATE_COLOR[state], 0),
                  (f" {p.get('cpu', 0):>3.0f}%", C_TEXT, A_B)])
        for c in info.get("cores") or []:
            b = UNIT_CPU["busy"].get(c, 0.0)
            L.append([(f"core{c:<3}", C_MUTED, 0), (meter(b / 100, 16), C_GOOD if b > 50 else C_ACCENT, 0),
                      (f" {b:4.0f}%", C_TEXT, 0)])
        if UNIT_CPU.get("load"):
            L.append([("load   ", C_MUTED, 0), (" ".join(UNIT_CPU["load"]) + "  (/proc/loadavg)", C_TEXT, 0)])
        job = _video_on(key)
        if job:
            fr = job.get("frames")
            frames = "" if job["stage"] == "CAPTURE" else (  # CAPTURE's detail already counts them
                f"  frames {fr if fr is not None else '?'}" + (f"/~{job['planned']}" if job.get("planned") else ""))
            L.append([("studio ", C_MUTED, 0), (clip(_video_text(job) + frames, w - 10), C_PINK, A_B)])
            if job.get("core_unit") and job["core_unit"] != key:
                L.append([("core   ", C_MUTED, 0), (f"last ran on {label_of(job['core_unit'])} (held here since its "
                                                     f"first core reading)", C_FAINT, 0)])
            L.append([("source ", C_MUTED, 0), (clip("/proc children (piper, chrome, ffmpeg), /tmp/gnoc-video-*/frames, "
                                                    "~/Downloads partials", w - 10), C_FAINT, 0)])
    elif kind == "desktop":
        L.append([("source ", C_MUTED, 0), ("desktop-inflight.json + /api/version through the uplink", C_FAINT, 0)])
        L.append([("open   ", C_MUTED, 0), (f"{info.get('open', 0)} call{'s' * (info.get('open') != 1)}", C_TEXT, A_B),
                  (f"  {short_model(info.get('model'))}" if info.get("model") else "", C_GOOD, 0)])
        L.append([("link   ", C_MUTED, 0), ("answering" if info.get("up") else clip(f"no answer: {info.get('err') or '?'}",
                                                                                   w - 10), C_GOOD if info.get("up") else C_BAD, 0)])
        if info.get("models"):
            L.append([("loaded ", C_MUTED, 0), (clip(", ".join(short_model(m.get("name")) for m in info["models"]), w - 10),
                      C_GOOD, 0)])
        if isinstance(info.get("vram"), (int, float)):
            L.append([("vram   ", C_MUTED, 0), (f"{info['vram']} GB (desktop.json)", C_TEXT, 0)])
    elif kind == "phone":
        lk = info.get("link") or {}
        L.append([("source ", C_MUTED, 0), ("phone.json (phone-link) + its Ollama /api/ps", C_FAINT, 0)])
        L.append([("adb    ", C_MUTED, 0), (str(lk.get("state") or "?"), C_GOOD if lk.get("state") == "device" else C_WARN, 0),
                  (f"  {lk.get('model') or ''}", C_TEXT, 0)])
        if lk.get("battery") is not None:
            L.append([("power  ", C_MUTED, 0), (f"{lk['battery']}%{' charging' if lk.get('charging') else ''}", C_TEXT, 0)])
        if lk.get("mem_total_mb"):
            L.append([("memory ", C_MUTED, 0), (f"{lk.get('mem_avail_mb')}/{lk['mem_total_mb']} MB free", C_TEXT, 0)])
        L.append([("split  ", C_MUTED, 0), ("in the running split" if info.get("in_split") else "not in the split",
                                           C_GOOD if info.get("in_split") else C_FAINT, 0)])
        L.append([("ollama ", C_MUTED, 0), ("answering" if info.get("up") else clip(f"no answer: {info.get('err') or '?'}",
                                                                                  w - 10), C_GOOD if info.get("up") else C_BAD, 0)])
    duty = unit_duty(key)
    L.append([("job    ", C_MUTED, 0), (clip(duty, w - 10) if duty else "none held right now", C_GOLD if duty else C_FAINT,
                                       A_B if duty else 0)])
    return L


def studio_lines(w):
    """The STUDIO board in PROD: one line per live video job (its process, its stage from its children, frames from
    its work dir, the unit from the core), then what the last ones left (manifests, edits.jsonl rows)."""
    now = time.time()
    with LOCK:
        live = sorted(VIDEO_LIVE.values(), key=lambda j: j["t0"])
        done = list(VIDEO_DONE)
    L = []
    for j in live:
        on = f"  on {label_of(j['unit']) if j.get('unit') else '?'}  {_dur(now - j['t0'])}"
        if j["kind"] == "compile":
            L.append([("▶ ", C_GOOD, A_B), (f"{_pub(j['id'])}  ", C_TEXT, A_B),
                      (j["stage"] or "PLAN", C_GOLD if j["stage"] == "ENCODE" else C_WARN, A_B),
                      (f" {j['detail']}" if j.get("detail") else "", C_TEXT, 0), (on, C_MUTED, 0)])
        else:
            L.append([("✎ ", C_GOLD, A_B), (f"{'editing' if j['kind'] == 'edit' else 'building'} {_pub(j['id'])}",
                                            C_TEXT, 0), (on, C_MUTED, 0)])
    if not live:
        L.append([("no compile or edit running", C_MUTED, 0)])
    col = {"wrote": C_GOOD, "edited": C_GOLD, "failed": C_WARN}
    for d in reversed(done):
        hhmm = time.strftime("%H:%M", time.localtime(d["at"]))
        sep = f": {d['brief']}" if d["what"] == "edited" else (f" ({d['brief']})" if d.get("brief") else "")
        L.append([(f"{d['what']} {_pub(str(d['id']))} {hhmm}{sep}", col.get(d["what"], C_MUTED), 0)])
    return L


def prod_lines(app, w, studio_board=True):
    """PROD's wall board: the website as its own endpoints report it (d_website, polled while this room is on screen)
    and the uplink proxy's requests per minute by caller (desktop-traffic.jsonl). With no room for the STUDIO board,
    a live compile's line goes on top of this one."""
    d = SITE.get("last") or {}
    by = {p["name"]: p for p in app.feed.data.get("pm2") or []}
    L = []
    if not studio_board and VIDEO_LIVE:
        L.append(studio_lines(w)[0])
    h, edge, ops = d.get("health") or {}, d.get("edge") or {}, d.get("ops") or {}
    if REDACT:
        L.append([("site   ", C_MUTED, 0), ("not read in public mode", C_FAINT, 0)])
    elif not d:
        L.append([("site   ", C_MUTED, 0), ("first read pending", C_FAINT, 0)])
    else:
        if h:
            L.append([("site   ", C_MUTED, 0), (" UP " if h.get("ok") else f" DOWN {h.get('code') or ''} ", C_BLACK, A_B),
                      (f" {h.get('ms', 0):.0f} ms  v{h.get('version') or '?'}", C_TEXT, 0)])
        if edge:
            L.append([("edge   ", C_MUTED, 0), (str(edge.get("code") or "no answer"), C_GOOD if edge.get("ok") else C_BAD, A_B),
                      (f" through the tunnel {edge.get('ms', 0):.0f} ms, {_dur(time.time() - edge['ts'])} ago", C_TEXT, 0)])
        if ops.get("http"):
            one, five = ops["http"].get("oneMinute") or {}, ops["http"].get("fiveMinutes") or {}
            L.append([("http   ", C_MUTED, 0), (sparkline(list(SITE["hist"]), max(6, w - 26)), C_ACCENT, 0),
                      (f" {one.get('requests', 0)}/min", C_TEXT, A_B), (f" ({ops.get('mine_1m', 0)} ours)", C_FAINT, 0)])
            for tag, b in (("1m", one), ("5m", five)):
                L.append([(f"codes {tag} ", C_MUTED, 0), (f"4xx {b.get('status4xx', 0)} ", C_WARN if b.get("status4xx") else C_MUTED, 0),
                          (f"5xx {b.get('status5xx', 0)} ", C_BAD if b.get("status5xx") else C_MUTED, 0),
                          (f"of {b.get('requests', 0)}  avg {b.get('avgMs', 0):.0f} ms", C_TEXT, 0)])
        elif ops.get("err"):
            L.append([("ops    ", C_MUTED, 0), (ops["err"], C_BAD, 0)])
    parts = [("links  ", C_MUTED, 0)]
    for name in PROD_PROCS[1:4]:
        st = (by.get(name) or {}).get("status")
        parts += [("●" if st == "online" else "■", C_GOOD if st == "online" else C_BAD, A_B),
                  (f" {label_of(name).lower()}  ", C_TEXT if st == "online" else C_FAINT, 0)]
    L.append(parts)
    now = time.time()
    rate = {}
    for ts, caller in list(UPLINK_RATE):
        if now - ts <= 60:
            rate[caller] = rate.get(caller, 0) + 1
    top = ", ".join(f"{c} {n}" for c, n in sorted(rate.items(), key=lambda kv: -kv[1])[:4]) or "none"
    L.append([("uplink ", C_MUTED, 0), (f"{sum(rate.values())}/min", C_TEXT, A_B), (f"  {top}", C_FAINT, 0)])
    return L


# the rail's colours are for a dark panel; on a white board each one is swapped for a darker twin
_ON_WHITE = {C_TEXT: 238, C_MUTED: 240, C_FAINT: 245, C_GOOD: 28, C_WARN: 166, C_BAD: 160, C_GOLD: 136,
             C_ACCENT: 25, C_BLACK: 16}


def _board(cv, box, title, lines, accent=25):
    bx, by, bw, bh = box
    cv.fill(bx, by, bw, bh, " ", 236, 255)
    cv.put(bx + 1, by, clip(title, bw - 2), accent, 255, A_B)
    for k, ln in enumerate(lines[:max(0, bh - 1)]):
        if isinstance(ln, list):
            cv.segs(bx + 1, by + 1 + k, [(t_, _ON_WHITE.get(c_, c_), a_) for t_, c_, a_ in ln], bw - 2, bg=255)
        else:
            cv.put(bx + 1, by + 1 + k, clip(str(ln), bw - 2), 238, 255)


def draw_units_floor(cv, app, sc, t, procs, states):
    """UNITS: the MANAGER board (queue, open work orders, what it sent and to whom, units on shift) and its out-tray
    of unattributed papers; THE FLOOR board (every unit in one line of numbers); PROD's board and one console per site
    process; the SERVER ROOM's infra LEDs. With orch-bot stopped in pm2 the manager's office is dark."""
    now = time.time()
    units = [p for p in procs if p.get("unit")]
    on = sum(1 for p in units if states.get(p["name"]) not in ("sleeping",))
    work = sum(1 for p in units if states.get(p["name"]) == "working")
    mgr_state = states.get("orch-bot", "sleeping")
    if "MANAGER" in sc.boards:
        orders = (app.feed.data.get("line") or {}).get("orders") or []
        q = _U.get("queue") or []
        lines = [f"queue {len(q)}, orders {len(orders)}" + (f": {q[0]}" if q else ""),
                 f"on shift {on}/{len(units)}, {work} working"]
        with LOCK:
            sent = list(UNIT_SENT)[-3:]
            n_q = sum(1 for e, _ in UNATTRIBUTED if now - e < 600)
        for ts, unit, what in reversed(sent):
            lines.append(f"{label_of(unit)} {_dur(now - ts)}: {what}")
        if not sent:
            lines.append("no dispatch seen yet")
        lines.append(f"OUT ?{n_q}: unattributed" if n_q else "OUT tray: no ? papers")
        _board(cv, sc.boards["MANAGER"], "orch-bot " + ("STOPPED" if mgr_state == "sleeping" else
                                                        STATE_WORD.get(mgr_state, "?")), lines)
    if sc.mgr_tray:
        x, y = sc.mgr_tray
        with LOCK:
            n_q = sum(1 for e, _ in UNATTRIBUTED if now - e < 600)
        col = C_WARN if n_q else C_FAINT
        cv.put(x, y, "┌OUT┐", col)
        cv.put(x, y + 1, f"│{('?' + str(min(n_q, 9))) if n_q else '  '} │", col, None, A_B)
        cv.put(x, y + 2, "└───┘", col)
    if "THE FLOOR" in sc.boards:
        load = " ".join(UNIT_CPU.get("load") or []) or "?"
        allc = list(UNIT_CPU["busy"].values())
        lines = [f"{len(_CPU_PREV)} cores {sum(allc) / max(1, len(allc)):.0f}% busy  load {load}  (/proc)"]
        lines.append("   ".join(f"{label_of(k)} {g.get('kind', '')} {int(g.get('busy') or 0)}% {_gb(g.get('used'))}/"
                                f"{_gb(g.get('total'))} GB" if g.get("up") else f"{label_of(k)} gone from sysfs"
                                for k, g in sorted(UNIT_GPU.items())))
        for p in units:
            if p["unit"] in ("desktop", "phone"):
                lines.append(f"{label_of(p['name'])}: {STATE_WORD.get(states.get(p['name'], 'idle'), '?').lower()}"
                             f"  {unit_spark(p, states.get(p['name']))}  {unit_duty(p['name'])}")
        lines.append(f"jobs watched {UNIT_COUNT['jobs']}, attributed {UNIT_COUNT['attributed']}, "
                     f"unattributed {UNIT_COUNT['unattributed']}")
        _board(cv, sc.boards["THE FLOOR"], f"THE FLOOR · units on shift {on}/{len(units)}, {work} working", lines)
    if "PROD" in sc.boards:
        _board(cv, sc.boards["PROD"], "LIVE  site endpoints + uplink log",
               prod_lines(app, sc.boards["PROD"][2] - 2, "STUDIO" in sc.boards), 22)
    if "STUDIO" in sc.boards:
        _board(cv, sc.boards["STUDIO"], "STUDIO  compile + edit (procs, /tmp/gnoc-video-*, ~/Downloads)",
               studio_lines(sc.boards["STUDIO"][2] - 2), 25)
    if sc.prod_consoles:
        x, y, w, n = sc.prod_consoles
        by = {p["name"]: p for p in app.feed.data.get("pm2") or []}
        for k, name in enumerate(PROD_PROCS[:n]):
            p = by.get(name) or {}
            st = p.get("status") or "absent"
            ok = st == "online"
            col = (46 if (t // 10 + k) % 7 else 28) if ok else (C_BAD if st == "errored" else 52)
            cv.put(x, y + k, "▕", 245, 233)
            cv.put(x + 1, y + k, "▪▪", col, 233)
            cv.put(x + 3, y + k, "▏", 245, 233)
            cv.put(x + 5, y + k, clip(f"{label_of(name):<10} {st:<8} cpu {p.get('cpu', 0):>3.0f}%  "
                                      f"{p.get('mem_mb', 0):>4.0f} MB", w - 5), C_TEXT if ok else C_FAINT)
    r = _room_rect(sc, "SERVER ROOM")
    if r:
        x0, y0, w0, h0 = r
        skip = set(PROD_PROCS) | {"orch-bot"}
        infra = [p for p in app.feed.data.get("pm2") or [] if p.get("name") not in skip and not p.get("virtual")]
        y, last = y0 + 2, y0 + h0 - 2
        cv.put(x0 + 2, y, clip(f"{sum(p.get('status') == 'online' for p in infra)}/{len(infra)} services up", w0 - 4),
               C_GOOD if all(p.get("status") == "online" for p in infra) else C_WARN, None, A_B)
        y += 2
        for k, p in enumerate(infra):
            if y > last:
                break
            ok = p.get("status") == "online"
            col = (46 if (t // 10 + k) % 7 else 28) if ok else (C_BAD if p.get("status") == "errored" else 52)
            cv.put(x0 + 2, y, "▪", col)
            cv.put(x0 + 4, y, clip(f"{label_of(p['name'])}", w0 - 6), C_MUTED if ok else C_FAINT)
            y += 1
    if mgr_state == "sleeping":  # pm2 says the manager is not running: its office is dark and its chair empty
        r = _room_rect(sc, "MANAGER")
        if r:
            x0, y0, w0, h0 = r
            top = sum(sc.boards["MANAGER"][1::2]) if "MANAGER" in sc.boards else y0 + 1  # under its board
            cv.tint(x0 + 1, top, w0 - 2, y0 + h0 - 1 - top, 232)
            cv.put(x0 + 2, y0 + h0 - 2, clip(" lights off: orch-bot stopped ", w0 - 4), C_FAINT, 232)


# ---------- legibility: job titles, the flow funnel, the one-sentence "now" ----------
# Each desk's job, from what its process actually does (OFFICE_HANDBOOK.md says the same in prose).
DESK_DUTY = {
    "orch-bot": ("Chief Strategist", "picks the target, decides hunt / escalate / pivot / wait"),
    "pipeline-sweep": ("Rescue Coordinator", "reopens parked leads and held drafts, sends one investigator in"),
    "oss-bot": ("Scout", "runs scheduled scans and drops what they find in the triage tray"),
    CHAT_KEY: ("Operator Console", "the gnoc chat agent the user talks to"),
    "qwen3:8b": ("Laptop Model Server", "Ollama on the laptop GPU: answers hunter and brain calls"),
    "desktop-proxy": ("Uplink", "relays model calls to the desktop GPU and logs each one"),
    "split-llm": ("Split Model Server", "one model spread over the GPUs (and the phone, when it is in)"),
    "phone-link": ("Phone Link", "keeps the USB phone's adb forwards alive and reports its battery and memory"),
    "control-panel": ("Front Desk", "the desktop rig's control panel; carries new drafts to the boss"),
    "greynoc": ("Website", "serves the public site"),
    "greynoc-tunnel": ("Tunnel", "publishes the site through the edge tunnel"),
    "greynoc-onion": ("Onion", "publishes the site as an onion service"),
    "keepalive": ("Janitor", "keeps the site services alive"),
    "office-stream": ("Office Cam", "streams this office, redacted, to the website"),
}
ROOM_DUTY = {"COMPANY": "the bots, on payroll", "GNOC CHAT": "analyst + models", "WEBSITE": "public site", "PROCESSES": "unattended",
             "GENERAL": "other", "WAR ROOM": "payroll, bets, bounties" if BOTS_ONLY else "chat and orch log"}
if UNITS:
    ROOM_DUTY.update({"MANAGER": "hands out the jobs", "THE FLOOR": "the processing units",
                      "PROD": "the website and its traffic", "SERVER ROOM": "the services"})
_SCOPE_CACHE = {}


def scope_on_file(prog):
    """True when targets/<prog>/SCOPE.txt holds at least one in-scope row. The office never shows activity against a
    program as normal without it: a program with no scope on file is flagged NO SCOPE in red wherever it appears."""
    if not prog:
        return True
    hit = _SCOPE_CACHE.get(prog)
    if hit and time.time() - hit[1] < 60:
        return hit[0]
    ok = False
    try:
        with open(os.path.join(WS, "targets", os.path.basename(str(prog)), "SCOPE.txt"), errors="ignore") as fh:
            ok = any(ln.strip() and not ln.lstrip().startswith("#") for ln in fh)
    except OSError:
        pass
    _SCOPE_CACHE[prog] = (ok, time.time())
    return ok


def _report_ids(r):
    """Every name a ships row gives its report (rows of different kinds carry different fields)."""
    ids = {str(r.get(k)).strip().lower() for k in ("path", "slug", "title", "report_id", "draft") if r.get(k)}
    return ids or {str(r.get("ts"))}


def ship_counts(ships):
    """(drafts, filed) counted per REPORT: a draft whose HELD-REASON or liveness file is re-recorded is still one
    draft, and a report filed today is not also counted as a draft."""
    filed_rows = [r for r in ships if ship_kind(r) == "submission"]
    filed_ids = set().union(*(_report_ids(r) for r in filed_rows)) if filed_rows else set()
    drafts, seen = 0, set()
    for r in ships:
        if ship_kind(r) != "draft":
            continue
        ids = _report_ids(r)
        if ids & filed_ids or ids & seen:
            continue  # filed today, or the same draft re-recorded
        seen |= ids
        drafts += 1
    return drafts, len({min(_report_ids(r)) for r in filed_rows})


def funnel(app):
    """Today's flow for the running office. See funnel_of()."""
    return funnel_of(app.feed.data)


def funnel_of(data):
    """Today's flow, every number a real count (local day). Returns stages [(label, short, n, source)] plus the index
    of the bottleneck: the first stage that got nothing although the stage before it did (None = no stall).

    Takes the feed dict rather than the app so the chat agent can read the same numbers without a TUI: asked what
    the office funnel says, the agent had no tool for it and answered from oss-bot lead rows instead, which are a
    different pipeline entirely (soak batch8 2026-10-25)."""
    o = data.get("outcomes") or {}
    cls = o.get("classes") or {}
    drafts, filed = ship_counts(data.get("ships") or [])
    stages = [("probes", "prb", o.get("probes", 0), "requests the lanes report firing"),
              ("leads", "lead", cls.get("lead", 0) + cls.get("needs", 0) + cls.get("candidate", 0),
               "lane verdicts LEAD / NEEDS / CANDIDATE"),
              ("in lab", "lab", LAB_STATS.get("today", 0), "rescue investigations started"),
              ("proven", "prov", cls.get("candidate", 0), "a captured terminal (CANDIDATE)"),
              ("drafted", "drft", drafts + filed, "reports written today (filed ones included)"),
              ("your call", "you", drafts, "written, waiting on your approval - the only stage you clear"),
              ("FILED", "filed", filed, "submitted to a platform: the goal")]
    # the flow STOPPED at a stage: it got nothing, the stage before it got something, and nothing got past it
    # (a finding that skipped the lab and went on to a draft is not a stall at the lab)
    stall = next((i for i in range(1, len(stages)) if stages[i][2] == 0 and stages[i - 1][2] > 0
                  and all(st[2] == 0 for st in stages[i:])), None)
    return stages, stall


STAGE_WORDS = {  # how each funnel number reads out loud: (one, many)
    "probes": ("probe fired", "probes fired"),
    "leads": ("lead", "leads"),
    "in lab": ("in the lab", "in the lab"),
    "proven": ("proven", "proven"),
    "drafted": ("drafted", "drafted"),
    "your call": ("needs your OK", "need your OK"),
    "FILED": ("filed", "filed"),
}


STAGE_AFTER = {"your call": "waiting on your OK"}  # the same stage, read as the thing a later stage came from


def stage_phrase(label, n, after=False):
    """The words after a funnel number, so '1569' reads as '1569 probes fired'. after=True phrases the stage as
    the place the flow came FROM ('0 filed after 1 waiting on your OK')."""
    if after and label in STAGE_AFTER:
        return STAGE_AFTER[label]
    one, many = STAGE_WORDS.get(label, (label, label))
    return one if n == 1 else many


def h1_tally(app):
    st = (app.feed.data.get("h1") or {}).get("states") or {}
    acc = sum(v for k, v in st.items() if k in ("triaged", "resolved", "bounty", "accepted"))
    closed = sum(v for k, v in st.items() if k in ("duplicate", "not-applicable", "informative", "spam"))
    return acc, closed, sum(st.values())


def now_sentence(app):
    """'What is happening now', one sentence built only from live state: [(text, colour)] pieces."""
    out = []
    if _LAST_SEEN.get("stop"):
        out.append(("hunt paused (STOP is set)", C_BAD))
    hn = dict(HUNT_NOW)
    th = dict(BRAIN_THINK)
    brain = app.feed.data.get("brain") or {}
    if hn.get("live") and hn.get("prog"):
        out.append((f"BRAIN's hunter is sweeping {hn['prog']}: {hn.get('hosts', 0)} hosts done, "
                    f"{hn.get('fired', 0)} probes fired", C_TEXT))
        if not scope_on_file(hn["prog"]):
            out.append((f"NO SCOPE ON FILE for {hn['prog']}", C_BAD))
    elif th:
        out.append((f"BRAIN is running {th.get('action')} on {th.get('prog', '?')} ({_dur(time.time() - th.get('t', time.time()))})",
                    C_TEXT))
        if not scope_on_file(th.get("prog")):
            out.append((f"NO SCOPE ON FILE for {th.get('prog')}", C_BAD))
    elif brain.get("action"):
        out.append((f"BRAIN last decided '{brain['action']}' {_ago(brain.get('ts'))} ago", C_MUTED))
    if UNITS:  # which units are working, and on what
        st = app.states()
        busy = [label_of(p["name"]) + (f" ({unit_duty(p['name'])})" if unit_duty(p["name"]) else "")
                for p in app.procs() if p.get("unit") and st.get(p["name"]) == "working"]
        out.append((f"units working: {', '.join(busy[:4])}" + (f" +{len(busy) - 4}" if len(busy) > 4 else "")
                    if busy else "no unit is working right now", C_TEXT))
    nw = chat_now()
    if nw:
        out.append((f"GNOC CHAT is {nw[0]}{': ' + nw[1] if nw[1] else ''} ({_dur(time.time() - nw[2])})",
                    C_PURPLE))
    with LOCK:
        live = list(LAB.values())
    if live:
        inv = live[0]
        rung = f"rung {inv['cur']}" if inv.get("cur") else "ladder audit"
        out.append((f"{len(live)} lead{'s' * (len(live) != 1)} in the lab ({inv['hunter']}, {rung})", C_GOLD))
    tray = _LAST_SEEN.get("oss_open")
    if tray:
        out.append((f"{tray} scanner leads waiting in triage", C_WARN))
    states = app.states()
    on = sum(1 for p in app.procs() if p["status"] == "online")
    work = sum(1 for v in states.values() if v == "working")
    out.append((f"{work} of {on} desks working", C_TEXT))
    blocked = [label_of(k) for k, v in states.items() if v == "error"]
    stopped = [label_of(k) for k, v in states.items() if v == "sleeping"]
    if blocked:
        out.append((f"blocked: {', '.join(blocked)}", C_BAD))
    if stopped:
        out.append((f"stopped: {', '.join(stopped)}", C_MUTED))
    drafts, filed = ship_counts(app.feed.data.get("ships") or [])
    if filed:
        out.append((f"{filed} report{'s' * (filed != 1)} filed today", C_GOOD))
    elif drafts:
        out.append((f"{drafts} draft{'s' * (drafts != 1)} waiting for your approval", C_GOOD))
    if not app.boss_here():
        out.append(("you are out: the fleet is running unattended", C_MUTED))
    return out


def strip_rows(H):
    """Collapse order for small terminals: the NOW sentence goes first, then the funnel strip."""
    return 2 if H >= 40 else 1 if H >= 30 else 0


def draw_strip(cv, app, y, W, rows):
    """Row 1: today's funnel with the bottleneck marked. Row 2: the 'now' sentence."""
    if rows <= 0:
        return
    cv.fill(0, y, W, rows, " ", bg=C_PANEL)
    stages, stall = funnel(app)
    short = W < 150     # abbreviate the stage names
    roomy = W >= 185    # room for the trailing sentences (the stall, H1, the tray) as well
    parts = [(" FLOW TODAY ", C_BLACK, A_B)]
    x = cv.segs(0, y, parts, W, bg=C_INFO)
    segs = []
    for i, (label, sh, n, _) in enumerate(stages):
        if i:
            segs.append(("  ▸ ", C_FAINT, 0))
        hot = i == stall
        goal = i == len(stages) - 1          # FILED
        mine = label == "your call"          # written, waiting on GreyNOC
        segs += [(str(n), C_BAD if hot else (C_GOOD if goal and n else (C_WARN if mine and n else
                  (C_TEXT if n else C_FAINT))), A_B),
                 (" " + (sh if short else stage_phrase(label, n)),
                  C_GOLD if hot else (C_GOOD if goal else C_MUTED), A_B if hot or goal else 0)]
        weak = (app.feed.data.get("outcomes") or {}).get("weak", 0)
        if label == "leads" and weak:
            segs.append((f" (+{weak} weak)", C_FAINT, 0))
        if hot:  # name both stages: nothing got here although the stage before it produced
            prev_label, _, prev_n, _ = stages[i - 1]
            segs.append((f"  ◀ stuck: 0 {stage_phrase(label, 0)} after {prev_n} "
                         f"{stage_phrase(prev_label, prev_n, after=True)}" if roomy else "  ◀ stuck here",
                         C_BAD, A_B))
    acc, closed, total = h1_tally(app)
    if total:
        segs += [("    HACKERONE, all time: " if roomy else "    H1 ", C_PINK, A_B),
                 (f"{acc} accepted", C_GOOD if acc else C_FAINT, 0),
                 (f" · {closed} closed", C_FAINT, 0)]
    tray = _LAST_SEEN.get("oss_open")
    if tray:
        segs += [("    ", 0, 0), (str(tray), C_WARN, A_B),
                 (" scanner leads waiting in triage" if roomy else " in the tray" if not short else " tray",
                  C_FAINT, 0)]
    if all(n == 0 for _, _, n, _ in stages):
        segs.append(("    quiet so far today", C_FAINT, 0))
    cv.segs(x, y, segs, W - x - 1, bg=C_PANEL)
    if rows >= 2:
        x = cv.segs(0, y + 1, [(" NOW ", C_BLACK, A_B)], W, bg=C_GOLD)
        pieces = []
        for k, (txt, col) in enumerate(now_sentence(app)):
            if k:
                pieces.append(("  ·  ", C_FAINT, 0))
            pieces.append((txt, col, A_B if col == C_BAD else 0))
        cv.segs(x + 1, y + 1, pieces, W - x - 2, bg=C_PANEL)


def draw_header(cv, app, W):
    feed = app.feed
    procs = app.procs()
    states = app.states()
    on = sum(1 for p in procs if p["status"] == "online")
    working = sum(1 for s in states.values() if s == "working")
    drafts, filed = ship_counts(feed.data.get("ships") or [])
    if time.time() - getattr(app, "_pace_read", 0) > 5:  # `gnoc orch speed` can change it from outside
        app._pace_read = time.time()
        try:
            app.settings["intensity"] = max(1, min(5, int(open(INTENSITY_FILE).read().strip())))
        except (OSError, ValueError):
            pass
    v = app.settings["intensity"]
    restart = time.time() < RESTART_FLASH_UNTIL
    bg = 52 if restart else C_PANEL_HI
    cv.fill(0, 0, W, 1, " ", bg=bg)
    x = cv.segs(0, 0, [(" ◆ GNOC OFFICE ", C_BLACK, A_B)], W, bg=C_ACCENT)
    wide = W >= 170   # room to spell each number out; a narrower header keeps the short words
    mid = W >= 140
    parts = [("  ●", C_GOOD if on == len(procs) and procs else C_WARN, A_B),
             (f" {on}/{len(procs)} desks online" if mid else f" {on}/{len(procs)} online", C_TEXT, 0),
             ("  ▲", C_GOOD, A_B), (f" {working} of them working" if wide else f" {working} working", C_TEXT, 0),
             ("  pace ", C_MUTED, 0), ("▰" * v + "▱" * (5 - v), C_ACCENT, A_B),
             (f" {v}/5, a hunt tick every ~{_TICK_TABLE[v]}s" if wide else f" {v}/5 ~{_TICK_TABLE[v]}s", C_MUTED, 0),
             ("  ", 0, 0), (str(drafts), C_GOOD if drafts else C_FAINT, A_B),
             (f" draft{'s' * (drafts != 1)}" + (" waiting on you" if wide else ""), C_MUTED, 0),
             ("  ", 0, 0), (str(filed), C_GOOD if filed else C_FAINT, A_B),
             (" filed today" if wide else " filed", C_MUTED, 0)]
    if restart:
        parts.append(("  PM2 RESTART", C_BAD, A_B))
    if party_active():
        parts.append(("  PARTY", C_PINK, A_B))
    if _LAST_SEEN.get("stop"):
        parts.append(("  HUNT PAUSED", C_BAD, A_B))
    now = datetime.now()
    right = f" {now:%a %H:%M:%S} {datetime.now().astimezone():%Z} "
    if app.boss_here():  # you, by your own toggle
        since = app._boss.get("since")
        boss, bcol = f" BOSS IN {_dur(time.time() - since) if since else ''} ".replace("  ", " "), C_GOLD
    elif app.work_live():  # nobody toggled in, but a lane or a brain decision is live: the office is lit for it
        boss, bcol = " BOSS OUT  work live ", C_WARN
    else:
        boss, bcol = " BOSS OUT ", C_FAINT
    x = cv.segs(x, 0, parts, W - x - len(right) - len(boss) - 1, bg=bg)  # was a fixed 22: BOSS OUT overwrote "probes"
    bx0 = W - len(right) - len(boss)
    cv.put(bx0, 0, boss, C_BLACK, bcol, A_B)
    app.boss_btn = (bx0, bx0 + len(boss) - 1)
    cv.put(W - len(right), 0, right, C_MUTED, bg)


def panel(cv, x, y, w, title, lines, max_h, accent=C_ACCENT):
    if max_h < 2:
        return 0
    cv.fill(x, y, w, 1, " ", bg=C_PANEL_HI)
    cv.segs(x + 1, y, [("▍", accent, A_B), (title, C_TEXT, A_B)], w - 2, bg=C_PANEL_HI)
    n = 0
    for ln in lines[:max_h - 1]:
        n += 1
        cv.segs(x + 2, y + n, ln, w - 3)
    return n + 2


def _mb(b):
    return f"{(b or 0) / 1e6:,.0f} MB" if (b or 0) < 1e9 else f"{b / 1e9:,.1f} GB"


def website_lines(w):
    """The WEBSITE desk's telemetry (d_website), as rail rows. Every number is read from the site itself."""
    d = SITE.get("last") or {}
    L = []
    if not d:
        return [[("polling your-site.example ...", C_FAINT, 0)]]
    h, st, ops, edge = d.get("health") or {}, d.get("status") or {}, d.get("ops") or {}, d.get("edge") or {}
    if h:
        up = _dur(h["uptime"]) if h.get("uptime") else "-"
        L.append([("site   ", C_MUTED, 0), (" UP " if h.get("ok") else f" DOWN {h.get('code') or ''} ", C_BLACK,
                  A_B), (f" v{h.get('version') or '?'}  build {str(st.get('build') or '?')[:7]}  up {up}", C_TEXT, 0)])
        if h.get("reason"):
            L.append([("       ", 0, 0), (clip(h["reason"], w - 10), C_BAD, 0)])
    if ops.get("maintenance") or st.get("mode") == "maintenance":
        L.append([("mode   ", C_MUTED, 0), (" MAINTENANCE ", C_BLACK, A_B)])
    if edge:
        ok = edge.get("ok")
        L.append([("edge   ", C_MUTED, 0), (f"{edge.get('code') or 'no answer'}", C_GOOD if ok else C_BAD, A_B),
                  (f" via the tunnel  {edge.get('ms', 0):.0f} ms", C_TEXT, 0),
                  (f"  {_dur(time.time() - edge['ts'])} ago", C_FAINT, 0)])
    if ops.get("err"):
        L.append([("ops    ", C_MUTED, 0), (ops["err"], C_BAD, 0)])
    elif ops:
        one, five = (ops.get("http") or {}).get("oneMinute") or {}, (ops.get("http") or {}).get("fiveMinutes") or {}
        L.append([("http   ", C_MUTED, 0), (sparkline(list(SITE["hist"]), max(6, w - 24)), C_ACCENT, 0),
                  (f" {one.get('requests', 0)}/min", C_TEXT, A_B), (f" ({ops.get('mine_1m', 0)} ours)", C_FAINT, 0)])
        for tag, b in (("1m", one), ("5m", five)):
            bad = b.get("status5xx", 0)
            L.append([(f"  {tag}   ", C_MUTED, 0), (f"{b.get('requests', 0)} req  ", C_TEXT, 0),
                      (f"4xx {b.get('status4xx', 0)}  ", C_WARN if b.get("status4xx") else C_MUTED, 0),
                      (f"5xx {bad}  ", C_BAD if bad else C_MUTED, A_B if bad else 0),
                      (f"avg {b.get('avgMs', 0):.1f}  max {b.get('maxMs', 0):.0f} ms", C_TEXT, 0)])
        rt = ops.get("realtime") or {}
        L.append([("live   ", C_MUTED, 0), (f"{ops.get('online') or 0} online  {ops.get('sockets') or 0} sockets  "
                  f"{rt.get('events1m', 0)} rt/min  {(ops.get('http') or {}).get('lifetime', 0):,} req total", C_TEXT, 0)])
        pr = ops.get("process") or {}
        lag = pr.get("eventLoopLagAvgMs", 0)
        L.append([("node   ", C_MUTED, 0), (f"cpu {pr.get('cpuPercent', 0):.1f}%  heap {_mb(pr.get('heapUsedBytes'))}  "
                  f"rss {_mb(pr.get('rssBytes'))}  ", C_TEXT, 0),
                  (f"lag {lag:.1f}/{pr.get('eventLoopLagPeakMs', 0):.0f} ms", C_BAD if lag > 50 else C_TEXT, 0)])
        sto = ops.get("store") or {}
        saved = _dur(time.time() - sto["lastPersistAt"] / 1000) + " ago" if sto.get("lastPersistAt") else "never"
        L.append([("store  ", C_MUTED, 0), (f"{(sto.get('fileBytes') or 0) / 1e3:,.0f} KB{' enc' if sto.get('encrypted') else ''}"
                  f"  saved {saved}  disk {_mb(sto.get('diskFreeBytes'))} free", C_TEXT, 0)]
                 + ([("  READ-ONLY", C_BAD, A_B)] if sto.get("readOnly") else [])
                 + ([("  persist error", C_BAD, A_B)] if sto.get("lastPersistError") else []))
        sec = ops.get("sec") or {}
        q, hr, day = sec.get("last15m") or {}, sec.get("last1h") or {}, sec.get("last24h") or {}
        hot = sum((q.get("severities") or {}).get(k, 0) for k in ("high", "crit"))
        L.append([("watch  ", C_MUTED, 0), (f"{q.get('events', 0)} ev/15m  {hr.get('events', 0)}/1h  "
                  f"{day.get('events', 0)}/24h ({day.get('uniqueIps', 0)} ips)  ", C_TEXT, 0),
                  (f"bans {ops.get('bans', 0)}", C_WARN if ops.get("bans") else C_MUTED, 0)]
                 + ([(f"  {hot} high", C_BAD, A_B)] if hot else []))
        ib = ops.get("inbox") or {}
        L.append([("inbox  ", C_MUTED, 0), (f"{ib.get('open', 0)} open", C_WARN if ib.get("open") else C_TEXT, 0),
                  (f"  {ib.get('emergencies', 0)} emergencies", C_BAD if ib.get("emergencies") else C_MUTED, 0),
                  (f"   pro members {ops.get('pro') or 0}", C_TEXT, 0)])
        for a in ops.get("alerts") or []:
            L.append([("alert  ", C_MUTED, 0), (clip(a, w - 10), C_BAD, 0)])
    else:
        L.append([("ops    ", C_MUTED, 0), ("no OPS_ADMIN_TOKEN in the site .env: traffic hidden", C_FAINT, 0)])
    for name, (age, last) in (d.get("logs") or {}).items():
        if age is not None and age < 600 and last:  # an error log written in the last 10 minutes
            L.append([(f"{label_of(name).lower()[:6]:<7}", C_MUTED, 0), (f"stderr {_dur(age)} ago: ", C_WARN, 0),
                      (clip(last, max(8, w - 30)), C_FAINT, 0)])
    return L


def chat_desk_lines(w):
    """The GNOC CHAT desk: the live conversation file and its last turn (the rail is off in public mode)."""
    f = _chat_session_file()
    if not f:
        return [[("chat   ", C_MUTED, 0), ("no gnoc chat session on disk yet", C_FAINT, 0)]]
    d = jload(f, {})
    hist = d.get("history") or []
    L = [[("chat   ", C_MUTED, 0), (clip(str(d.get("title") or os.path.basename(f)), w - 10), C_TEXT, A_B)],
         [("turns  ", C_MUTED, 0), (f"{sum(1 for m in hist if m.get('role') == 'user')} you, "
          f"{sum(len(m.get('tool_calls') or []) for m in hist)} tool calls", C_TEXT, 0),
          (f"   last write {_dur(_chat_turn_age())} ago", C_FAINT, 0)]]
    if d.get("program"):
        L.append([("prog   ", C_MUTED, 0), (str(d["program"]), C_TEXT, 0)])
    # ...and what it is doing RIGHT NOW, off the activity log rather than off the saved file: every open call
    # with its real age, then the ones that just finished, newest first.
    now = time.time()
    for v in sorted(CHAT_LIVE.values(), key=lambda r: r["t0"])[:3]:
        verb = chat_act(v["name"])[0]
        L.append([("now    ", C_MUTED, 0), (clip(verb + (f": {v['arg']}" if v["arg"] else ""), w - 16), C_GOOD, A_B),
                  (f"  {_dur(now - v['t0'])}", C_FAINT, 0)])
    if CHAT_TURNS and not CHAT_LIVE:
        L.append([("now    ", C_MUTED, 0), ("writing the answer", C_GOOD, A_B),
                  (f"  {_dur(now - min(v['t0'] for v in CHAT_TURNS.values()))}", C_FAINT, 0)])
    for ts, nm, arg, secs, ok in list(CHAT_DONE)[-4:][::-1]:
        L.append([("       ", C_MUTED, 0), (clip(chat_act(nm)[0] + (f": {arg}" if arg else ""), w - 18),
                                            C_TEXT if ok else C_BAD, 0),
                  (f"  {_dur(secs)} {_dur(now - ts)} ago", C_FAINT, 0)])
    c = CHAT_COUNT
    if c["calls"] or c["turns"]:
        top = sorted(c["by"].items(), key=lambda kv: -kv[1])[:3]
        L.append([("watched", C_MUTED, 0), (" " + f"{c['turns']} turns, {c['calls']} calls"
                                            + (f", {c['failed']} failed" if c["failed"] else "")
                                            + (f", {c['blocked']} declined" if c["blocked"] else ""), C_TEXT, 0)])
        if top:
            L.append([("mostly ", C_MUTED, 0), (clip(", ".join(f"{n} {k}" for k, n in top), w - 10), C_FAINT, 0)])
    return L


def rail_inspector(app, w):
    keys = app.desk_keys()
    sel = app.selected
    states = app.states()
    if sel is not None and sel < len(keys):
        key = keys[sel]
        if key.startswith("host:"):
            row = app.hosts().get(key[5:], {})
            mrow = mood_of(app.mood, key)
            lines = [[(f"{sel + 1} ", C_ACCENT, A_B), (clip(row.get("label", key), w - 6), C_TEXT, A_B)],
                     [(" LINKED " if row.get("up") else " NOT LINKED ", C_BLACK, A_B)]]
            lines[-1] = [(" LINKED " if row.get("up") else " NOT LINKED ", C_BLACK, A_B)]
            lines.append([("addr   ", C_MUTED, 0), (row.get("addr", "?"), C_TEXT, 0)])
            lk = row.get("link") or {}
            if lk:
                lines.append([("adb    ", C_MUTED, 0), (f"{lk.get('state')}", C_GOOD if lk.get("state") == "device" else C_WARN, 0),
                              (f"  {lk.get('model') or ''} Android {lk.get('android') or '?'}" if lk.get("model") else "", C_TEXT, 0)])
                if lk.get("battery") is not None:
                    lines.append([("power  ", C_MUTED, 0), (f"{lk['battery']}%{' charging' if lk.get('charging') else ''}"
                                                            + (f"  {lk.get('battery_c')} C" if lk.get("battery_c") else ""), C_TEXT, 0)])
                if lk.get("mem_total_mb"):
                    lines.append([("memory ", C_MUTED, 0), (f"{lk.get('mem_avail_mb')}/{lk['mem_total_mb']} MB free", C_TEXT, 0)])
                lines.append([("split  ", C_MUTED, 0), ("RPC device in the running split" if row.get("in_split") else
                                                       "not in the split (gnoc split up adds it)", C_GOOD if row.get("in_split") else C_FAINT, 0)])
            if row.get("up"):
                lines.append([("ollama ", C_MUTED, 0), (str(row.get("version", "?")), C_TEXT, 0)])
                ms = row.get("models") or []
                lines.append([("loaded ", C_MUTED, 0), (", ".join(m["name"] for m in ms) or "nothing (idle)",
                                                        C_GOOD if ms else C_MUTED, 0)])
            else:
                lines.append([("error  ", C_MUTED, 0), (clip(row.get("err", "?"), w - 10), C_BAD, 0)])
            lines.append([("energy ", C_MUTED, 0), (meter(mrow["energy"] / 100, 12), C_GOLD, 0),
                          (f" {mrow['energy']:.0f}", C_MUTED, 0)])
            return lines
        p = next((p for p in app.procs() if p["name"] == key), None)
        if not p:
            return [[("(desk vanished from pm2)", C_FAINT, 0)]]
        state = states.get(key, "idle")
        if p.get("unit"):  # a processing unit: its own readings, not pm2's
            return [[(f"{sel + 1} ", C_ACCENT, A_B), (label_of(key), C_TEXT, A_B), (f"  {key}", C_FAINT, 0)],
                    [(f" {STATE_WORD[state]} ", C_BLACK, A_B), (f"  processing unit ({p['unit']})", C_MUTED, 0)]] \
                + unit_lines(p, state, w)
        mrow = mood_of(app.mood, key)
        title, frac = rank_for(p.get("uptime_ms"))
        up = _dur(time.time() - p["uptime_ms"] / 1000) if p.get("uptime_ms") and p["status"] == "online" else "-"
        src = (f"  {p.get('n_procs', 0)} gnoc chat process{'es' * (p.get('n_procs') != 1)}  pid {p.get('pid') or '-'}"
               if p.get("virtual") else f"  pm2 {p['status']}  pid {p.get('pid') or '-'}"
               + (f"  scheduled: cron {p['cron']}" if p.get("cron") else ""))
        lines = [[(f"{sel + 1} ", C_ACCENT, A_B), (label_of(key), C_TEXT, A_B), (f"  {key}", C_FAINT, 0),
                  (f"  {DEPT_OF.get(key, 'GENERAL')}", C_FAINT, 0)],
                 [(f" {STATE_WORD[state]} ", C_BLACK, A_B), (src, C_MUTED, 0)]]
        lines[-1][0] = (f" {STATE_WORD[state]} ", C_BLACK, A_B)
        job = DESK_DUTY.get(key)
        if job:
            lines.insert(2, [(job[0], C_GOLD, A_B), (": " + clip(job[1], w - len(job[0]) - 6), C_MUTED, 0)])
        hist = CPU_HIST.get(key) or []
        lines.append([("cpu    ", C_MUTED, 0), (sparkline(hist, w - 16, floor=10), STATE_COLOR[state], 0),
                      (f" {p.get('cpu', 0):>3.0f}%", C_TEXT, A_B)])
        lines.append([("mem    ", C_MUTED, 0), (f"{p.get('mem_mb', 0):.0f} MB", C_TEXT, 0),
                      ("   up ", C_MUTED, 0), (up, C_TEXT, 0), ("   restarts ", C_MUTED, 0),
                      (str(p.get("restarts", 0)), C_WARN if p.get("restarts") else C_TEXT, 0)])
        lines.append([("rank   ", C_MUTED, 0), (f"{title:<10}", C_GOLD, A_B), (meter(frac, 12, "▓", "░"), C_GOLD, 0)])
        treat = mrow.get("treat") if time.time() < mrow.get("treat_until", 0) else None
        lines.append([("energy ", C_MUTED, 0), (meter(mrow["energy"] / 100, 12), C_GOOD if mrow["energy"] >= 50 else C_WARN, 0),
                      (f" {mrow['energy']:.0f}", C_MUTED, 0), (f"  {treat}" if treat else "", C_GOLD, 0)])
        with LOCK:
            bub = BUBBLES.get(key)
        if bub:
            col = C_BAD if bub.get("alert") else (C_INFO if bub.get("flavor") else C_WARN)
            for i, ln in enumerate(wrap(bub["text"], w - 10, 3)):
                lines.append([("says   " if i == 0 else "       ", C_MUTED, 0), (ln, col, 0)])
        if key == WEBSITE_KEY:
            lines += [[("── your-site.example " + "─" * max(0, w - 25), C_EDGE, 0)]] + website_lines(w)
        elif key == CHAT_KEY:
            lines += chat_desk_lines(w)
        return lines
    procs = app.procs()
    on = sum(1 for p in procs if p["status"] == "online")
    by = {}
    for s in states.values():
        by[s] = by.get(s, 0) + 1
    lines = [[("FLOOR  ", C_MUTED, 0), (f"{on}/{len(procs)} desks online", C_TEXT, A_B)]]
    lines.append([(f"{by.get(s, 0)} {STATE_WORD[s].lower()}  ", STATE_COLOR[s], 0)
                  for s in LEGEND_STATES if by.get(s)])
    idle = [label_of(n) for n, s in states.items() if s == "idle"]
    if idle:
        for i, ln in enumerate(wrap("idle (online, nothing to do this minute): " + ", ".join(idle), w - 4, 2)):
            lines.append([(ln, C_FAINT, 0)])
    lines.append([("Tab", C_ACCENT, A_B), (" or click a desk to inspect it", C_FAINT, 0)])
    return lines


VERDICT_COLOR = {"DEAD": 240, "LEAD": C_WARN, "UNFIRED": 67, "NEEDS": C_INFO, "CRITICAL-CANDIDATE": C_BAD,
                 "MEDIUM-CANDIDATE": C_PINK}


def rail_today(app, w):
    o = app.feed.data.get("outcomes") or {}
    brain = app.feed.data.get("brain") or {}
    ships = app.feed.data.get("ships") or []
    n = o.get("n", 0)
    nd, nf = ship_counts(ships)
    lines = [[(str(n), C_INFO, A_B), (" lanes ran", C_MUTED, 0), ("   ", 0, 0),
              (str(o.get("probes", 0)), C_INFO, A_B), (" probes fired", C_MUTED, 0)],
             [(str(nd), C_GOOD, A_B), (f" draft{'s' * (nd != 1)} waiting on you", C_MUTED, 0), ("   ", 0, 0),
              (str(nf), C_GOOD, A_B), (" filed", C_MUTED, 0)],
             [(str(brain.get("n_today", 0)), C_PURPLE, A_B), (" brain decisions today", C_MUTED, 0)]]
    verdicts = sorted((o.get("verdicts") or {}).items(), key=lambda kv: -kv[1])
    bw = w - 4
    if n:
        bar, used = [], 0
        palette = [C_ACCENT, 110, 180, 139]
        for k, (v, c) in enumerate(verdicts):
            cells = max(1, round(c / n * bw)) if used < bw else 0
            cells = min(cells, bw - used)
            used += cells
            bar.append(("█" * cells, VERDICT_COLOR.get(v, palette[k % len(palette)]), 0))
        lines.append(bar)
        leg = []
        for k, (v, c) in enumerate(verdicts[:4]):
            leg += [("■", VERDICT_COLOR.get(v, palette[k % len(palette)]), 0), (f" {clip(v, 10)} {c}  ", C_MUTED, 0)]
        lines.append(leg)
    hours = o.get("hours") or [0] * 24
    cur = datetime.now().hour
    m = max(hours) or 1
    sp = [(SPARK[min(7, int(v / m * 7.999))] if v else "▁", C_GOLD if i == cur else (C_INFO if v else C_FAINT), 0)
          for i, v in enumerate(hours)]
    lines.append([("by hour", C_MUTED, 0)] + sp)
    lines.append([("       0     6     12    18  " + datetime.now().astimezone().strftime("%Z"), C_FAINT, 0)])
    return lines


def rail_reports(app, w):
    ships = [r for r in app.feed.data.get("ships") or [] if ship_kind(r) in ("draft", "submission")]
    flashing = time.time() < WHITEBOARD_FLASH_UNTIL
    if not ships:
        return [[("no drafts or filings yet today", C_FAINT, 0)]]
    out = []
    for k, s in enumerate(reversed(ships[-5:])):
        filed = s.get("kind") == "submission"
        ago = _ago(s.get("ts"))
        title = clip(_ship_title(s), w - 15)
        hot = k == 0 and flashing
        out.append([(" FILED " if filed else " DRAFT ", C_BLACK, A_B), (" " + title.ljust(w - 15), C_GOLD if hot else C_TEXT,
                                                                       A_B if hot else 0), (f"{ago:>4}", C_FAINT, 0)])
    return out


def rail_h1(app, w):
    h1_raw = app.feed.data.get("h1")
    h1 = h1_raw or {}
    if h1_raw is None:
        return [[("checking api.hackerone.com ...", C_FAINT, 0)]]
    if not h1.get("up"):
        return [[("not linked: ", C_FAINT, 0), (clip(h1.get("reason", "no token"), w - 16), C_FAINT, 0)]]
    st = h1.get("states") or {}
    lines = [[(str(h1.get("n_reports", 0)), C_TEXT, A_B), (" reports, all time", C_MUTED, 0)] +
             [(f"   {v} {k}", C_MUTED, 0) for k, v in sorted(st.items(), key=lambda kv: -kv[1])[:3]]]
    evs = h1.get("events") or []
    if not evs:
        lines.append([("no new replies since the cache was primed", C_FAINT, 0)])
    for ev in evs[:3]:
        preview = (ev.get("message") or f"state -> {ev.get('state', '?')}").replace("\n", " ")
        lines.append([(f"{_ago(ev.get('ts')):>4} ", C_FAINT, 0), (clip(ev.get("title", "?"), w - 10), C_PINK, A_B)])
        lines.append([("     ", 0, 0), (clip(preview, w - 10), C_MUTED, 0)])
    return lines


def rail_brain(app, w):
    brain = app.feed.data.get("brain") or {}
    recent = brain.get("recent") or []
    if not recent:
        return [[("(no brain decisions recorded yet)", C_FAINT, 0)]]
    out = []
    for i, r in enumerate(recent):
        st = r.get("status") or "?"
        col = {"ok": C_GOOD, "wait": C_MUTED, "rejected": C_WARN, "fallback": C_WARN, "error": C_BAD}.get(st, C_MUTED)
        out.append([("▶ " if i == 0 else "✓ " if False else "· ", C_GOLD if i == 0 else C_FAINT, A_B),
                    (clip(r["action"], w - 18), C_TEXT if i == 0 else C_MUTED, A_B if i == 0 else 0),
                    (f" {st}", col, 0), (f" {_ago(r.get('ts'))}", C_FAINT, 0)])
    if recent[0].get("reason"):
        for ln in wrap(recent[0]["reason"], w - 6, 2):
            out.append([("  " + ln, C_FAINT, A_I)])
    return out


def rail_leads(app, w):
    n_open = _LAST_SEEN.get("oss_open")
    lr = _LAST_SEEN.get("oss_last")
    tri = _LAST_SEEN.get("oss_triage_row") or {}
    alert = time.time() < LEAD_ALERT_UNTIL
    lines = [[("?" if n_open is None else str(n_open), C_BAD if alert else C_WARN, A_B),
              (" scanner leads waiting in the tray", C_MUTED, 0)]]
    if lr:
        _id, prog, job, rc, audit, leads = lr
        lines.append([("last ", C_MUTED, 0), (clip(f"{prog} {job}", w - 22), C_TEXT, 0),
                      (f" {clip(audit or 'rc ' + str(rc), 12)}", C_BAD if str(audit).startswith("AUDIT FAIL") else C_GOOD, 0)])
    if tri.get("ts"):
        lines.append([("cull ", C_MUTED, 0), (f"{tri.get('culled', 0)} culled, {tri.get('open_after', '?')} left", C_TEXT, 0),
                      (f" {_ago(tri.get('ts'))}", C_FAINT, 0)])
    return lines


def rail_lab(app, w):
    """Leads under investigation right now: the rescue workers (ledger pid alive), BRAIN's running escalation,
    and any OpenCode lane; when nothing is live, the last recorded rescue verdicts."""
    now = time.time()
    with LOCK:
        live = list(LAB.values())
        hist = list(LAB_HIST)
    out = []
    for inv in sorted(live, key=lambda i: i.get("t0") or 0):
        out.append([("▶ ", C_GOLD, A_B), (clip(inv["name"], w - 14), C_TEXT, A_B),
                    (f" {_dur(now - inv['t0']) if inv.get('t0') else ''}", C_FAINT, 0)])
        if not scope_on_file(inv.get("prog")):
            out.append([("  NO SCOPE ON FILE for this program", C_BAD, A_B)])
        row = [("  ", 0, 0), (clip(inv["hunter"], 16), C_PURPLE, 0), (" ", 0, 0)]
        for k, st in enumerate((inv.get("ladder") or [])[:5]):
            g, col = RUNG_MARK.get(st, ("·", C_MUTED))
            if inv.get("cur") == k + 1:
                g, col = ("▲", C_GOLD)
            row.append((g, col, A_B))
        step = (f" rung {inv['cur']} {RUNGS.get(inv['cur'], '')}" if inv.get("cur") and inv.get("kind") != "chain"
                else f" edge {inv.get('cur') or 1}" if inv.get("kind") == "chain"
                else " chain map" if inv.get("kind") == "chainmap" else " ladder audit")
        row.append((clip(step, max(4, w - 30)), C_MUTED, 0))
        out.append(row)
        if inv.get("testing"):
            out.append([("  testing ", C_GOOD, A_B), (clip(inv["testing"], w - 14), C_TEXT, 0)])
        else:
            last = f", last {inv['last_cmd']} {_dur(inv['last_cmd_ago'])} ago" if inv.get("last_cmd") else ""
            out.append([("  ", 0, 0), (clip(f"{inv.get('runs', 0)} commands{last}", w - 6), C_FAINT, 0)])
        v = inv.get("verdict")
        if v:
            out.append([("  recorded ", C_MUTED, 0), (str(v.get("verdict", "?")).split()[0], C_WARN, A_B),
                        (f" {v.get('probes', '?')} probes{' +burst' if v.get('burst') else ''}", C_FAINT, 0)])
    th = dict(BRAIN_THINK)
    if th:
        out.append([("▶ ", C_GOLD, A_B), ("BRAIN ", C_PURPLE, A_B), (clip(f"{th.get('action')} {th.get('prog', '')}",
                    w - 18), C_TEXT, 0), (f" {_dur(now - th.get('t', now))}", C_FAINT, 0)])
    for ln in app.feed.data.get("lanes") or []:
        m = re.search(r"opencode-lane\.sh\s+(\S+)\s+(\S+)", ln)
        if m:
            out.append([("▶ ", C_GOLD, A_B), ("lane ", C_INFO, A_B), (clip(f"{m.group(1)}/{m.group(2)}", w - 10), C_TEXT, 0)])
    if not out:
        out.append([("no lead under investigation right now", C_FAINT, 0)])
        for d in reversed(hist[-3:]):
            col = C_BAD if d.get("dest") == "boss" else C_WARN if d.get("dest") == "tray" else C_MUTED
            out.append([("· ", C_FAINT, 0), (clip(d["name"], w - 24), C_MUTED, 0), (f" {d['verdict']}", col, A_B),
                        (f" {_dur(now - d['t_end'])} ago" if d.get("t_end") else "", C_FAINT, 0)])
    return out


def rail_chat(app, w):
    """The same chat the WAR ROOM board shows, for a floor too small to have a war room."""
    rows = chat_lines(app.feed, w - 2)[-6:]
    bright = {25: C_INFO, 54: C_PURPLE, 94: C_WARN, 240: C_FAINT}  # board inks are dark-on-white; the rail is dark
    return [[(f"{tag} ", bright.get(col, C_MUTED), A_B), (clip(piece, w - 9), C_TEXT, 0)] for tag, col, piece in rows] or \
        [[("no gnoc chat yet", C_FAINT, 0)]]


# rail panels say what they hold (the short name stays first, the jargon second)
RAIL_TITLE = {"LAB": "LAB · leads being investigated", "TODAY": "TODAY · lane verdicts",
              "REPORTS": "REPORTS · drafts and filings", "BRAIN": "BRAIN · latest decisions",
              "H1 INBOX": "H1 INBOX · platform replies", "LEADS": "LEADS · scanner triage tray",
              "GNOC CHAT": "GNOC CHAT · operator console"}


def draw_rail(cv, app, x, y, w, h):
    cv.fill(x, y, w, h, " ", bg=C_PANEL)
    for yy in range(y, y + h):
        cv.put(x - 1, yy, "▕", C_EDGE, C_BG)
    sections = [("INSPECTOR", rail_inspector, C_ACCENT), ("LAB", rail_lab, C_GOLD), ("TODAY", rail_today, C_INFO),
                *([("GNOC CHAT", rail_chat, C_PURPLE)] if app.scene and not app.scene.war else []),
                ("REPORTS", rail_reports, C_GOOD), ("BRAIN", rail_brain, C_PURPLE),
                ("H1 INBOX", rail_h1, C_PINK), ("LEADS", rail_leads, C_WARN)]
    cy = y
    for title, fn, accent in sections:
        room = y + h - cy
        if room < 3:
            break
        lines = fn(app, w)
        # the state/linked chip needs its background, which segs() cannot express: patch it after
        used = panel(cv, x, cy, w, RAIL_TITLE.get(title, title), lines, room, accent)
        if title == "INSPECTOR" and app.selected is not None and len(lines) > 1:
            chip = lines[1][0][0]
            keys = app.desk_keys()
            key = keys[app.selected] if app.selected < len(keys) else ""
            if key.startswith("host:"):
                col = C_GOOD if app.hosts().get(key[5:], {}).get("up") else C_BAD
            else:
                col = STATE_COLOR.get(app.states().get(key, "idle"), C_MUTED)
            cv.put(x + 2, cy + 2, chip, C_BLACK, col, A_B)
        if title == "REPORTS":
            for k, ln in enumerate(lines[:used - 2]):
                chip = ln[0][0]
                if chip in (" FILED ", " DRAFT "):
                    cv.put(x + 2, cy + 1 + k, chip, C_BLACK, C_GOOD if chip == " FILED " else C_WARN, A_B)
        cy += used


def pnl_line(app):
    """COMPANY: the P&L line of the ticker, from company.json (orch-bot's manager step)."""
    comp = app.feed.data.get("company") or {}
    if not comp.get("started"):
        return "company: not started (orch-bot's manager step writes .claude/state/economy/company.json)"
    c = comp.get("c") or {}
    p = c.get("pnl") or {}
    flag = " PAUSED" if comp.get("paused") else (" lanes stopped" if comp.get("stop") else "")
    return (f"P&L 24h  minted {p.get('minted_24h', 0)}  burnt {p.get('burnt_24h', 0)}  net {p.get('net_24h', 0)} RC"
            f"  |  READY {p.get('ready_24h', 0)}  drafts {p.get('drafts_24h', 0)}  |  dupe odds {p.get('dupe_odds', '-')}"
            f"  |  reserve {c.get('reserve', '-')}  bounties {len(c.get('bounties') or [])}{flag}")


def draw_ticker(cv, app, y, rows, W):
    cv.fill(0, y, W, rows, " ", bg=233)
    if BOTS_ONLY:  # the STORY TICKER: plain sentences gnoc_company wrote from real events, newest first
        rows_ = (app.feed.data.get("story") or [])[-rows:]
        if not rows_:
            cv.put(2, y, "the story starts with the next real event ...", C_FAINT, 233)
            return
        for k, r in enumerate(reversed(rows_)):
            ts = _ts_epoch(r.get("ts"))
            stamp = datetime.fromtimestamp(ts).strftime("%H:%M") if ts else "--:--"
            col = {"proved": C_GOOD, "broke": C_BAD, "lost": C_BAD, "report": C_GOLD, "jam": C_BAD}.get(
                r.get("kind"), C_TEXT)
            cv.segs(1, y + k, [(stamp, C_FAINT, 0), ("  ", 0, 0), (str(r.get("text") or ""), col, 0)], W - 2, bg=233)
        return
    with LOCK:
        evs = list(EVENTS)[-rows:]
    if not evs:
        cv.put(2, y, "waiting for the first real event ...", C_FAINT, 233)
        return
    for k, (ts, tag, text, col) in enumerate(reversed(evs)):
        yy = y + k
        age = time.time() - ts
        cv.segs(1, yy, [(datetime.fromtimestamp(ts).strftime("%H:%M:%S"), C_FAINT, 0), ("  ", 0, 0),
                        (f"{tag:<5}", col, A_B), ("  ", 0, 0), (text, C_TEXT if age < 30 else C_MUTED, 0)], W - 2,
                bg=233)


def draw_keybar(cv, y, W, app):
    cv.fill(0, y, W, 1, " ", bg=C_PANEL_HI)
    if REDACT:  # the website view is read-only: no keys reach this process from a browser
        cv.put(1, y, " VIEW ONLY ", C_BLACK, C_ACCENT, A_B)
        msg = "the live hunt office; names, hosts, paths and secrets are redacted before they leave the machine"
        cv.put(13, y, msg, C_MUTED, C_PANEL_HI)
        draw_legend(cv, y, W, 13 + len(msg) + 2)  # a browser viewer cannot press ?: the legend stays on screen
        return
    keys = [("Tab", "select"), ("i", "boss in/out"), ("c p b j", "feed"), ("[ ]", "pace"), ("!", "party"), ("m", "standup"),
            ("t", "stats"), ("v", "panel"), ("?", "help"), ("q", "quit")]
    legend_w = sum(len(t) for t, _, _ in legend_parts()) + 22
    if sum(len(k) + len(lb) + 5 for k, lb in keys) + legend_w > W:  # short labels keep the state legend on screen
        keys = [("Tab", "sel"), ("i", "boss"), ("cpbj", "feed"), ("[]", "pace"), ("!", "party"), ("m", "standup"),
                ("t", "stats"), ("v", "panel"), ("?", "help"), ("q", "quit")]
        if W < 175:  # the treats and the manual party are toys: they move to the ? overlay first
            keys = [kk for kk in keys if kk[0] not in ("cpbj", "!")]
    x = 1
    for k, label in keys:
        if x + len(k) + len(label) + 4 >= W:
            break
        cv.put(x, y, f" {k} ", C_BLACK, 250, A_B)
        cv.put(x + len(k) + 2, y, f" {label}  ", C_MUTED, C_PANEL_HI)
        x += len(k) + len(label) + 5
    if app.selected is not None:
        keys_ = app.desk_keys()
        if app.selected < len(keys_):
            k = keys_[app.selected]
            lab = label_of(k) if not k.startswith("host:") else app.hosts().get(k[5:], {}).get("label", k)
            s = f" desk {app.selected + 1}: {clip(lab, 20)} "
            cv.put(W - len(s) - 1, y, s, C_BLACK, C_ACCENT, A_B)
        return
    draw_legend(cv, y, W, x)


def legend_parts():
    return [(f"{STATE_GLYPH[s]} {STATE_WORD[s].lower()}  ", STATE_COLOR[s], A_B) for s in LEGEND_STATES]


LEGEND_TEXT = [""]  # bots-only: company.json screen.legend (gnoc_company.LEGEND), refreshed by draw_line_floor


def draw_legend(cv, y, W, x_used):
    """The one-line state legend, right-aligned in the key bar when it fits (otherwise it lives in the ? overlay)."""
    if BOTS_ONLY and LEGEND_TEXT[0]:
        txt = LEGEND_TEXT[0]
        if W - x_used - 2 >= len(txt) + 2:
            cv.put(W - len(txt) - 2, y, txt, C_GOLD, C_PANEL_HI, A_B)
        return
    parts = legend_parts() + [("speech bubble: ", C_FAINT, 0), ("● real event  ", 222, 0), ("● alert", C_BAD, 0)]
    width = sum(len(t) for t, _, _ in parts) + 2
    if W - x_used - 2 < width:  # narrower: the states alone
        parts = legend_parts()
        width = sum(len(t) for t, _, _ in parts) + 2
    if W - x_used - 2 < width:
        return
    cv.segs(W - width - 1, y, parts, width + 1, bg=C_PANEL_HI)


UNITS_HELP = [
    ("UNITS (the default floor; GNOC_OFFICE_UNITS=0 for the COMPANY floor)", C_GOLD, A_B),
    ("the desks      one per processing unit, found live: each GPU (sysfs gpu_busy_percent, mem_info_vram_*),", C_MUTED, 0),
    ("               the CPU cores four to a desk (/proc/stat), DESKTOP GPU (the uplink's open calls), PHONE", C_MUTED, 0),
    ("               (phone.json, its Ollama, the split); the sign on a desk is the job it holds right now", C_MUTED, 0),
    ("monitor        GPU busy %  ·  CPU one bar per core  ·  DESKTOP the model of the open call", C_MUTED, 0),
    ("MANAGER        orch-bot: queue, open work orders, what it sent to whom; dark and empty when pm2 has it stopped", C_MUTED, 0),
    ("hand-offs      walked only when a real row names the unit: a proxy call, a laptop Ollama call for the job's", C_MUTED, 0),
    ("               model, a probe in the job's process tree, a brain row's host; results walk back on the row", C_MUTED, 0),
    ("               that closes them. Nobody seen taking it: the paper waits in the manager's OUT tray as ?", C_MUTED, 0),
    ("PROD           the website board (health, edge, requests, status codes, links, uplink rate by caller) and", C_MUTED, 0),
    ("               a console per site process; a unit serving a website call from gnoc chat sits here", C_MUTED, 0),
    ("STUDIO         PROD's video board: a compile or edit of scripts/video (by hand or from gnoc chat) is one node", C_MUTED, 0),
    ("               process; its children name the stage (piper VOICE, chrome CAPTURE, ffmpeg ENCODE), frames are", C_MUTED, 0),
    ("               files in its /tmp/gnoc-video-* work dir; the CPU desk of its core walks to PROD (film strip ▮▯ on", C_MUTED, 0),
    ("               its monitor) and home with a reel ▦ when the manifest lands. A CPU job: x264 / vp9 on the cores", C_MUTED, 0),
    ("", 0, 0)]


def modal_lines(app, kind):
    feed = app.feed
    o = feed.data.get("outcomes") or {}
    ships = feed.data.get("ships") or []
    brain = feed.data.get("brain") or {}
    procs = app.procs()
    hosts = app.hosts()
    L = []
    if kind == "help":
        page = getattr(app, "help_page", 0) % 3
        tabs = [(f"{'▶' if i == page else ' '} {name}", C_GOLD if i == page else C_FAINT, A_B if i == page else 0)
                for i, name in enumerate(("1 HANDBOOK", "2 FLOW (live)", "3 LEGEND + KEYS"))]
        head = [("   ".join(t for t, _, _ in tabs), C_GOLD, A_B),
                ("? or Tab next page  ·  arrows up/down scroll  ·  Esc close", C_FAINT, 0), ("", 0, 0)]
        if page == 0:
            return head + _doc_lines("OFFICE_HANDBOOK.md")
        if page == 1:
            return head + flow_lines(app) + [("", 0, 0)] + _doc_lines("FLOW.md", skip_fence=True)
        L = [("THE OFFICE IS A SKIN ON REAL TELEMETRY", C_ACCENT, A_B), ("", 0, 0),
             ("Tab / arrows, click   select a desk or a server rack", C_TEXT, 0),
             ("1-9, 0                select desk 1-10      Esc / x  clear", C_TEXT, 0),
             ("c p b j               coffee, pizza, beer, a joint (energy is cosmetic)", C_TEXT, 0),
             ("[ ]                   pace slider: rewrites orch-bot's REAL tick interval", C_TEXT, 0),
             ("!  m  t  o  v         party, standup, stats, options, side panel", C_TEXT, 0),
             ("i  or click BOSS      you in / out: lights your office, the boss sits in (shown on the office cam)",
              C_TEXT, 0), ("", 0, 0),
             ("desk state     " + "   ".join(f"{STATE_GLYPH[x]} {STATE_WORD[x].lower()}" for x in LEGEND_STATES), C_TEXT, A_B),
             ("               working = real action < 90 s or cpu > 3 %;  paused = STOP set (PROCESSES only);", C_MUTED, 0),
             ("               stopped = pm2 not running;  blocked = errored, or BRAIN's last decision failed", C_MUTED, 0),
             ("amber bubble   a real event, said plainly (max one per desk per 12 s; the ticker has every one)", 222, 0),
             ("red bubble     a real alert", C_BAD, 0),
             ("monitor        code = working   cursor = idle   ‖ = paused   dark = stopped   ERR = blocked", C_MUTED, 0),
             ("               (GNOC CHAT: the name of the tool it is running)", C_MUTED, 0),
             ("under a desk   cpu sparkline (pm2 samples), cpu %, coffee battery (cosmetic, never changes state)", C_MUTED, 0),
             ("header         'N drafts waiting on you' = written today, not filed;  'N filed today' =", C_MUTED, 0),
             ("               submitted to a platform today;  'pace' = orch-bot's real tick interval", C_MUTED, 0),
             ("FLOW strip     today's funnel, each count followed by the words for what it counts;", C_MUTED, 0),
             ("               'stuck:' marks the first stage that got 0 after the one before it produced", C_MUTED, 0),
             ("NOW line       one sentence built from live state only", C_MUTED, 0),
             ("narrow screen  collapses in this order: side panel (< 150 cols), toy keys (< 175 cols), state legend", C_MUTED, 0),
             ("               (< 150 cols, always here), NOW line (< 40 rows), ticker 3 -> 1 row (< 34 rows),", C_MUTED, 0),
             ("               FLOW strip (< 30 rows), walled offices -> open plan (below ~140x45), 64x24 minimum", C_MUTED, 0),
             ("boss office    IN = you (i), LIT = a lane or a brain decision is live, OUT = dark", C_MUTED, 0),
             ("network        ◆ a real model call: caller desk -> UPLINK -> desktop rack, reply back home;", C_MUTED, 0),
             ("               BRAIN -> GPU DESK for laptop brain calls; · = health poll; ticker tag NET", C_MUTED, 0),
             ("server room    one rack per hosts.json machine, LEDs = Ollama state", C_MUTED, 0),
             ("the floor      GNOC CHAT (the analyst, desk 1), WEBSITE, PROCESSES (+ GENERAL), then", C_MUTED, 0),
             ("               REPORTS along the bottom: desk numbers walk it in that order", C_MUTED, 0),
             ("the funnel     ends 'drafted > your call > FILED'; 'your call' is yours alone to clear", C_MUTED, 0),
             ("website desk   select it for live site telemetry (health, edge, traffic, GreyWatch)", C_MUTED, 0),
             ("war room       board: gnoc chat (left) + orch.log (right), local time", C_MUTED, 0),
             ("gnoc chat desk the tool call it has OPEN right now, over the desk and spelled on its", C_MUTED, 0),
             ("               monitor, with its real age; its errands walk like any other paper", C_MUTED, 0),
             ("papers ▤       a real handoff carried desk to desk: blue order, grey result,", C_MUTED, 0),
             ("               gold lead, red HIT, green report; piles fade after ~2.5 min", C_MUTED, 0),
             ("uplink cable   routed along the corridors, through the server-room wall to the rack", C_MUTED, 0),
             ("rescue board   parked leads from the pipeline sweep - open, need YOU, ready to promote, dead;", C_MUTED, 0),
             ("               the title row says how old the snapshot is; wastebasket = today's rejected calls", C_MUTED, 0),
             ("whiteboard     TODAY: filed / drafts / lanes that recorded a verdict / leads in the triage tray", C_MUTED, 0),
             ("lab bench      white coat = a live rescue worker on a parked lead: ladder on the bench", C_MUTED, 0),
             ("               (× tried, ✓ paid, ! needs you, ▲ rung in progress), laptop = test in flight;", C_MUTED, 0),
             ("               its verdict walks to BOSS, SHREDDER, the tray or FILES; rail panel LAB", C_MUTED, 0),
             ("HUNT PAUSED    STOP is set: idle desks sweep up the litter and take short breaks", C_MUTED, 0),
             ("cat / mop      cosmetic: the cat naps on the warmest (highest cpu) desk", C_MUTED, 0), ("", 0, 0),
             ("any key to close", C_FAINT, 0)]
        if UNITS:
            L[2:2] = UNITS_HELP
    elif kind == "meeting":
        now = datetime.now().strftime("%a %d %b, %H:%M")
        on = sum(1 for p in procs if p["status"] == "online")
        L = [(f"DAILY STANDUP  {now}", C_GOLD, A_B), ("every line below is a real number, not flavor text", C_FAINT, 0),
             ("", 0, 0), (f"front desk   {on}/{len(procs)} desks staffed and online", C_TEXT, 0),
             (f"brain        {brain.get('n_today', 0)} decisions, last '{brain.get('action', 'none')}' "
              f"({brain.get('status', '-')})", C_TEXT, 0)]
        cls = o.get("classes") or {}
        if o.get("n"):
            L.append((f"hunt floor   {o['n']} lanes recorded a verdict, {o.get('probes', 0)} probes fired: "
                      f"{cls.get('candidate', 0)} proven, {cls.get('lead', 0)} leads, {cls.get('needs', 0)} need you, "
                      f"{cls.get('dead', 0)} dead, {cls.get('unfired', 0)} not fired", C_TEXT, 0))
        else:
            L.append(("hunt floor   quiet so far today", C_TEXT, 0))
        real = [r for r in ships if ship_kind(r) in ("draft", "submission")]
        nd, nf = ship_counts(ships)
        L.append(("SHIPPED", C_GOLD, A_B))
        filed_titles = [clip(_ship_title(r), 34) for r in real if ship_kind(r) == "submission"][-3:]
        L.append((f"  filed      {nf}" + (": " + "; ".join(filed_titles) if nf else " (nothing filed today)"),
                  C_TEXT, 0))
        L.append((f"  drafted    {nd} waiting for your approval" if nd else "  drafted    0", C_TEXT, 0))
        L.append(("STUCK", C_GOLD, A_B))
        stages, stall = funnel(app)
        if stall is not None:
            L.append((f"  flow       stalls at '{stages[stall][0]}' today", C_BAD, 0))
        if RESCUE.get("NEEDS"):
            L.append((f"  rescue     {RESCUE['NEEDS']} parked item(s) need you (rescue board: YOU)", C_PINK, 0))
        blocked = [label_of(k) for k, v in app.states().items() if v == "error"]
        if blocked:
            L.append((f"  blocked    {', '.join(blocked)}", C_BAD, 0))
        n_open = _LAST_SEEN.get("oss_open")
        L.append((f"  triage     {'?' if n_open is None else n_open} scanner leads waiting in the tray", C_TEXT, 0))
        L.append(("KILLED (and why)", C_GOLD, A_B))
        kills = o.get("kills") or []
        if not kills:
            L.append(("  nothing killed today", C_FAINT, 0))
        for tgt, v, why in kills:
            L.append((f"  {'a program' if REDACT else tgt}: {v} - {clip(why or 'no reason recorded', 70)}", C_MUTED, 0))
        up = [h.get("label", k) for k, h in hosts.items() if h.get("up")]
        L.append((f"server room  {len(up)}/{len(hosts)} machines linked", C_TEXT, 0))
        L += [("", 0, 0), ("m or Esc to end the meeting", C_FAINT, 0)]
    elif kind == "telemetry":
        L = [("TELEMETRY  today (local time)", C_ACCENT, A_B), ("", 0, 0),
             (f"lane verdicts    {o.get('n', 0)}   probes fired {o.get('probes', 0)}", C_TEXT, A_B)]
        for v, n in sorted((o.get("verdicts") or {}).items(), key=lambda kv: -kv[1]):
            L.append((f"  {v:<22} {n}", C_MUTED, 0))
        nd, nf = ship_counts(ships)
        L.append((f"drafts / filed   {nd} / {nf}", C_TEXT, A_B))
        for s in [r for r in ships if ship_kind(r) in ("draft", "submission")][-5:]:
            L.append((f"  - {ship_kind(s):<10} {clip(_ship_title(s), 56)}", C_MUTED, 0))
        L.append((f"brain decisions  {brain.get('n_today', 0)}, last {brain.get('action', '-')} ({brain.get('status', '-')})",
                  C_TEXT, A_B))
        L.append(("", 0, 0))
        on = sum(1 for p in procs if p["status"] == "online")
        L.append((f"desks staffed    {on}/{len(procs)} online, {sum(p.get('restarts', 0) for p in procs)} restarts lifetime",
                  C_TEXT, A_B))
        moving = sum(1 for wk in app.walkers.values() if wk.phase != "seated")
        L.append((f"on the move      {moving}", C_TEXT, 0))
        for p in sorted(procs, key=lambda p: -p.get("cpu", 0))[:6]:
            up = _dur(time.time() - p["uptime_ms"] / 1000) if p.get("uptime_ms") else "-"
            L.append((f"  {label_of(p['name']):<14} cpu {p.get('cpu', 0):4.0f}%  mem {p.get('mem_mb', 0):5.0f} MB  up {up}",
                      C_MUTED, 0))
        for k, row in hosts.items():
            if row.get("up"):
                ms = ", ".join(m["name"] for m in (row.get("models") or [])) or "idle"
                L.append((f"  {clip(row.get('label', k), 30):<30} Ollama {row.get('version', '?')}  {ms}", C_MUTED, 0))
            else:
                L.append((f"  {clip(row.get('label', k), 30):<30} not linked", C_FAINT, 0))
        keys = app.desk_keys()
        if not REDACT and app.selected is not None and app.selected < len(keys) and keys[app.selected] == WEBSITE_KEY:
            L += [("", 0, 0), ("WEBSITE  your-site.example", ROOM_WALL["WEBSITE"], A_B)]
            for ln in website_lines(76):
                txt = "".join(t for t, _, _ in ln)
                bad = any(c == C_BAD for _, c, _ in ln)
                L.append((txt, C_BAD if bad else C_MUTED, 0))
        L += [("", 0, 0), (f"this view up {_dur(time.time() - feed.started)}      any key to close", C_FAINT, 0)]
    elif kind == "options":
        L = [("OPTIONS", C_ACCENT, A_B), ("", 0, 0), ("z   reset everyone's mood to default", C_TEXT, 0),
             ("v   show or hide the side panel", C_TEXT, 0),
             ("    hosts.json is re-read every 6 s, no reload needed", C_FAINT, 0), ("", 0, 0),
             ("any other key to close", C_FAINT, 0)]
    return L


OFFICE_DOCS = os.path.join(WS, "scripts", "office-docs")


def _doc_lines(name, skip_fence=False):
    """A handbook / flow doc as overlay lines: the overlay and the file are the same words."""
    try:
        raw = open(os.path.join(OFFICE_DOCS, name), encoding="utf-8").read().splitlines()
    except OSError:
        return [(f"({name} not found in scripts/office-docs)", C_BAD, 0)]
    out, fence = [], False
    for ln in raw:
        if ln.startswith("```"):
            fence = not fence
            continue
        if fence and skip_fence:
            continue
        if ln.startswith("#"):
            out.append((ln.lstrip("# ").upper(), C_GOLD, A_B))
        else:
            out.append((ln.replace("`", ""), C_TEXT if ln[:1].isupper() or ln[:1].isdigit() else C_MUTED, 0))
    return out


def flow_lines(app):
    """The flow diagram with today's live numbers on every stage."""
    stages, stall = funnel(app)
    acc, closed, total = h1_tally(app)
    tray = _LAST_SEEN.get("oss_open")
    cells = [f"{n} {stage_phrase(label, n)}" for label, _, n, _ in stages]
    row = "  >  ".join(cells)
    L = [("TODAY'S FLOW (live)", C_GOLD, A_B), ("", 0, 0),
         ("One case, desk to desk, the way the floor walks it:", C_MUTED, 0),
         ("  targeting -> recon + OSINT -> LEAD TRIAGE -> investigation at the LAB BENCH -> verdict", C_MUTED, 0),
         ("  -> write-up at the PRINTER -> your approval at the BOSS desk -> FILED, then on file", C_MUTED, 0),
         ("Everything upstream is only worth what the last two produce: a report, approved and filed.",
          C_FAINT, 0),
         (row, C_TEXT, A_B)]
    if stall is not None:
        L.append((f"stalls at: {stages[stall][0]} (got 0 while '{stages[stall - 1][0]}' got {stages[stall - 1][2]})", C_BAD, A_B))
    elif all(n == 0 for _, _, n, _ in stages):
        L.append(("quiet so far today (zero is a state, not a failure)", C_FAINT, 0))
    L.append((f"H1 all time: {acc} accepted, {closed} closed, {total} reports" if total else "H1: not linked", C_PINK, 0))
    L.append((f"tray: {'?' if tray is None else tray} scanner leads waiting in LEAD TRIAGE", C_WARN, 0))
    weak = (app.feed.data.get("outcomes") or {}).get("weak", 0)
    if weak:
        L.append((f"weak: {weak} signal-only finds from auto-hunt sweeps today (saved to LEADS.md, not verdicts)", C_FAINT, 0))
    for label, _, n, src in stages:
        L.append((f"  {label:<8} {n:>5}   {src}", C_MUTED, 0))
    return L


def draw_modal(cv, app, kind, mx, my, mw, mh):
    L = modal_lines(app, kind)
    if kind == "help":  # page head stays, long lines wrap, the body scrolls
        width = max(20, mw - 4 - 5)
        body = []
        for text, fg, at in L[3:]:
            for k, piece in enumerate(wrap(text, width, 20) if len(text) > width else [text]):
                body.append(("   " + piece if k else piece, fg, at))
        off = max(0, min(getattr(app, "help_scroll", 0), max(0, len(body) - (mh - 2 - 3))))
        app.help_scroll = off
        L = L[:3] + body[off:]
    w = min(mw - 4, max(len(t) for t, _, _ in L) + 6)
    h = min(mh - 2, len(L) + 2)
    x = mx + (mw - w) // 2
    y = my + (1 if kind == "meeting" else max(1, (mh - h) // 2))
    cv.tint(x + 2, y + 1, w, h, 232)
    cv.fill(x, y, w, h, " ", bg=C_PANEL_HI)
    cv.frame(x, y, w, h, C_GOLD if kind == "meeting" else C_ACCENT, bg=C_PANEL_HI)
    for i, (text, fg, at) in enumerate(L[:h - 2]):
        cv.put(x + 3, y + 1 + i, clip(text, w - 5), fg or C_TEXT, C_PANEL_HI, at)


# ---------- frame assembly ----------

def compose(app, W, H):
    cv = Canvas(W, H, bg=C_BG)
    ticker_rows = 3 if H >= 34 else 1
    srows = 0 if BOTS_ONLY else strip_rows(H)  # the funnel + "now" strip (bots-only: the TODAY strip replaces it)
    MH = H - 2 - ticker_rows - srows
    show_rail = False if REDACT else (app.rail_pref if app.rail_pref is not None else
                                      W >= (210 if UNITS else 150) and not BOTS_ONLY)  # UNITS: the floor needs width
    RW = 46 if show_rail and W >= 110 else 0
    app.rail_on = bool(RW)  # draw_map's chat fallback needs to know whether the rail is on screen
    MW = W - RW - (1 if RW else 0)
    draw_header(cv, app, W)
    if (MW < 64 or MH < 24) and BOTS_ONLY and W >= 40 and H >= 8:
        # a small terminal: the same plain-words office as a list (TODAY, the four boards, the story), no floor
        sv = (((app.feed.data.get("company") or {}).get("c") or {}).get("screen") or {})
        rows = [(t_, C_GOLD, A_B) for t_ in (sv.get("today") or ["TODAY  the manager has not opened the office yet"])]
        if sv.get("jam"):
            rows.append((f"JAM: {sv['jam']} is backed up", C_BAD, A_B))
        for title, b in (sv.get("boards") or {}).items():
            items = [f"{r.get('program')} waiting for the user: {'a report' if REDACT else r.get('title')}"
                     for r in b.get("reports") or []] if "reports" in b else list(b.get("lines") or [])
            rows.append((f"{title}: {b.get('title', '')}", C_ACCENT, A_B))
            rows += [(f"  {ln}", C_TEXT, 0) for ln in items[:3]]
        for r in reversed((app.feed.data.get("story") or [])[-3:]):
            rows.append((f"> {r.get('text')}", C_MUTED, 0))
        for k, (txt, col, at) in enumerate(rows[:H - 2]):
            cv.put(1, 1 + k, clip(str(txt), W - 2), col, None, at)
        draw_keybar(cv, H - 1, W, app)
        return cv
    if MW < 64 or MH < 24:
        msg = f"the office needs at least {64 + RW}x{24 + 2 + ticker_rows + srows}; this terminal is {W}x{H}"
        cv.put(max(0, (W - len(msg)) // 2), H // 2, clip(msg, W), C_WARN, None, A_B)
        draw_keybar(cv, H - 1, W, app)
        return cv
    procs = app.procs()
    hosts = app.hosts()
    names = tuple(p["name"] for p in procs)
    sig = (MW, MH, len(procs), len(hosts), names)
    if app.scene is None or (app.scene.MW, app.scene.MH, app.scene.n_desks, app.scene.n_hosts, app.scene.names) != sig:
        app.scene = Scene(MW, MH, len(procs), len(hosts), names)
        app.walkers = {}
        app.cat, app.cat_desk, app.cat_next = None, None, 0  # the room was rebuilt: old coordinates are void
        app.cable_key, app.pkts, app.wet, app.routes = None, [], {}, {}  # routes are per scene
        app.visitors, app.lab_primed = {}, False  # investigators re-seat at the new bench
        app.boss = Walker(app.scene.boss_home) if app.scene.boss_home and not BOTS_ONLY else None
        if app.modal == "meeting":
            app.modal = None
    sc = app.scene
    keys = app.desk_keys()
    sel_key = keys[app.selected] if app.selected is not None and app.selected < len(keys) else None
    if sel_key == WEBSITE_KEY:
        SITE_WATCH[0] = time.time() + 3  # the website feed polls only while this desk stays selected
    if UNITS and _room_rect(sc, "PROD"):  # ...or while PROD's board is on screen (same per-source cadence)
        SITE_WATCH[0] = time.time() + 3
    for i, p in enumerate(procs):
        if p["name"] not in app.walkers and i < len(sc.doors):
            app.walkers[p["name"]] = Walker(sc.doors[i])
    states = app.states()
    with LOCK:
        bubbles = dict(BUBBLES) if not BOTS_ONLY else {}
    app.tick(sc, states, bubbles)
    mc = draw_map(app, MW, MH)
    top = 1 + srows
    cv.blit(mc, 0, top)
    app.hits = [(x0, y0 + top, x1, y1 + top, idx) for x0, y0, x1, y1, idx in app.hits]
    draw_strip(cv, app, 1, W, srows)
    if RW:
        draw_rail(cv, app, W - RW, top, RW, MH)
    elif sel_key == WEBSITE_KEY and not REDACT:  # no rail to inspect in: the website card floats over the floor
        cw = min(56, MW - 4)
        lines = website_lines(cw)
        ch = min(MH - 2, len(lines) + 2)
        cx, cy = MW - cw - 2, 1 + top
        cv.tint(cx + 1, cy + 1, cw, ch, 232)
        cv.fill(cx, cy, cw, ch, " ", bg=C_PANEL)
        panel(cv, cx, cy, cw, "WEBSITE  your-site.example  (Esc to close)", lines, ch, ROOM_WALL["WEBSITE"])
    draw_ticker(cv, app, H - 1 - ticker_rows, ticker_rows, W)
    draw_keybar(cv, H - 1, W, app)
    if app.modal:
        draw_modal(cv, app, app.modal, 0, top, MW, MH)
    return cv


# ---------- input ----------

def parse_input(buf):
    """Split raw bytes into key tokens: plain chars, 'TAB', 'BTAB', 'UP'..., 'ESC', ('CLICK', x, y)."""
    out, i, s = [], 0, buf
    while i < len(s):
        ch = s[i]
        if ch == "\x1b":
            m = re.match(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])", s[i:])
            if m:
                b, x, y, kind = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
                if kind == "M" and b == 0:
                    out.append(("CLICK", x - 1, y - 1))
                i += m.end()
                continue
            m = re.match(r"\x1b\[([ABCDZ])", s[i:])
            if m:
                out.append({"A": "UP", "B": "DOWN", "C": "RIGHT", "D": "LEFT", "Z": "BTAB"}[m.group(1)])
                i += m.end()
                continue
            m = re.match(r"\x1b\[[0-9;]*[~A-Za-z]", s[i:])
            if m:
                i += m.end()
                continue
            out.append("ESC")
            i += 1
            continue
        out.append("TAB" if ch == "\t" else ch)
        i += 1
    return out


def handle_key(app, k):
    """Returns False to quit."""
    n = len(app.desk_keys())
    if k in ("q", "\x03"):
        return False
    if isinstance(k, tuple) and k[0] == "CLICK":
        _, x, y = k
        if y == 0 and app.boss_btn and app.boss_btn[0] <= x <= app.boss_btn[1]:
            app.toggle_boss()
            return True
        hit = next((idx for x0, y0, x1, y1, idx in app.hits if x0 <= x <= x1 and y0 <= y <= y1), None)
        if app.modal and app.modal != "meeting":
            app.modal = None
        app.selected = hit
        return True
    if app.modal == "help":
        if k in ("?", "TAB", "RIGHT", "BTAB", "LEFT"):
            app.help_page = (getattr(app, "help_page", 0) + (-1 if k in ("BTAB", "LEFT") else 1)) % 3
            app.help_scroll = 0
        elif k in ("DOWN", "j"):
            app.help_scroll = getattr(app, "help_scroll", 0) + 3
        elif k in ("UP", "k"):
            app.help_scroll = max(0, getattr(app, "help_scroll", 0) - 3)
        elif isinstance(k, str) and k in "123":
            app.help_page, app.help_scroll = int(k) - 1, 0
        else:
            app.modal = None
        return True
    if app.modal == "telemetry":
        app.modal = None
        return True
    if app.modal == "options":
        if k == "z":
            app.mood = {}
            jsave(MOOD_FILE, app.mood)
            toast("moods reset", C_MUTED, 3)
        elif k == "v":
            app.rail_pref = not (app.rail_pref if app.rail_pref is not None else shutil.get_terminal_size().columns >= 150)
        app.modal = None
        return True
    if k == "ESC" or k == "x":
        if app.modal == "meeting":
            app.toggle_meeting()
        else:
            app.selected = None
        return True
    if k in ("TAB", "RIGHT", "DOWN") and n:
        app.selected = 0 if app.selected is None else (app.selected + 1) % n
    elif k in ("BTAB", "LEFT", "UP") and n:
        app.selected = n - 1 if app.selected is None else (app.selected - 1) % n
    elif isinstance(k, str) and k.isdigit():
        idx = 9 if k == "0" else int(k) - 1
        if idx < n:
            app.selected = idx
    elif k in TREATS:
        app.feed_treat(k)
    elif k == "[":
        app.set_pace(-1)
    elif k == "]":
        app.set_pace(+1)
    elif k == "!":
        ships = app.feed.data.get("ships") or []
        start_party("MANUAL PARTY (nothing was filed; thrown by the boss)")
        log_event("YOU", "threw an office party", C_PINK)
    elif k == "m":
        app.toggle_meeting()
    elif k == "i":
        app.toggle_boss()
    elif k == "t":
        app.modal = "telemetry"
    elif k == "o":
        app.modal = "options"
    elif k == "?":
        app.modal, app.help_page, app.help_scroll = "help", 0, 0
    elif k == "v":
        cur = app.rail_pref if app.rail_pref is not None else shutil.get_terminal_size().columns >= 150
        app.rail_pref = not cur
    return True


# ---------- main loop ----------

def funnel_json():
    """Today's funnel as JSON, with no TUI and no threads: the three collectors the funnel reads, run once.

    The chat agent needs these numbers to answer "where is work stuck today". It had no tool for them and
    answered from oss-bot lead rows, a different pipeline (soak batch8 2026-10-25)."""
    data = {}
    for key, fn in (("outcomes", d_outcomes_today), ("ships", d_ships_today), ("lab", d_lab)):
        try:
            data[key] = fn()
        except Exception as e:
            data[key] = {}
            data.setdefault("_err", {})[key] = str(e)[:120]
    stages, stall = funnel_of(data)
    out = {"day": datetime.now().astimezone().date().isoformat(),
           "stages": [{"stage": lab, "n": n, "counts": src} for lab, _short, n, src in stages],
           "bottleneck": None if stall is None else stages[stall][0],
           "note": ("the office funnel: today's hunt pipeline, probes through to FILED. This is NOT the "
                    "oss-bot lead list and NOT the lead lab queue.")}
    if data.get("_err"):
        out["errors"] = data["_err"]
    print(json.dumps(out, indent=2))
    return 0


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return 0
    if "--funnel-json" in sys.argv:
        return funnel_json()
    no_anim = "--no-anim" in sys.argv or not sys.stdout.isatty() or not sys.stdin.isatty()
    fd = None
    if not no_anim:
        # Keys come from a private dup of the tty and fd 0 becomes /dev/null BEFORE the collectors start: they run
        # children (pm2 jlist every 4 s) that inherit stdin, and one holding the tty swallowed keys (measured
        # 2026-10-22: q ignored in 1 of 3 runs at 200x60). Same fix as gnoc chair and gnoc dash.
        fd = os.dup(sys.stdin.fileno())
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
    feed = Feed()
    feed.prime()
    feed.start()
    app = App(feed)

    if no_anim:
        size = shutil.get_terminal_size((180, 50))
        cv = compose(app, size.columns, size.lines)
        print("\n".join(cv.lines(color=sys.stdout.isatty())))
        return 0

    saved = termios.tcgetattr(fd)
    prev, prev_size = [], None
    try:
        tty.setcbreak(fd)
        sys.stdout.write("\033[?1049h\033[?25l\033[?1000h\033[?1006h\033[2J")
        sys.stdout.flush()
        while True:
            t0 = time.time()
            size = shutil.get_terminal_size((120, 40))
            W, H = size.columns, size.lines
            cv = compose(app, W, H)
            lines = cv.lines()
            out = []
            if (W, H) != prev_size:
                out.append("\033[2J")
                prev = []
                prev_size = (W, H)
            for y, ln in enumerate(lines):
                if y >= len(prev) or prev[y] != ln:
                    out.append(f"\033[{y + 1};1H{ln}")
            if out:
                sys.stdout.write("".join(out))
                sys.stdout.flush()
            prev = lines
            wait = max(0.0, 1.0 / FPS - (time.time() - t0))
            r, _, _ = select.select([fd], [], [], wait)
            if r:
                buf = os.read(fd, 1024).decode(errors="replace")
                for k in parse_input(buf):
                    if not handle_key(app, k):
                        return 0
    except KeyboardInterrupt:
        return 0
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\033[?1000l\033[?1006l\033[0m\033[?1049l\033[?25h")
        sys.stdout.flush()
        try:
            jsave(MOOD_FILE, app.mood)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
