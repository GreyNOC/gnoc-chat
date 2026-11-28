#!/usr/bin/env python3
"""gnoc leads - LEAD LAB: a live board of every rescue-pipeline lead and what is being tested NOW
(scripts/GNOC-LEADS.md, spec scripts/learn/SPEC-gnoc-leads-20261021.md). Not Model Lab: that is `gnoc lab`.

    gnoc leads                       live board (the view and theme you used last on THIS board)
    gnoc leads --once [--size WxH]   one frame to stdout, no input (pipes, screenshots, tests)
    gnoc leads --view simple|technical  --theme neon|contrast|mono  --demo
    gnoc leads --snapshot            print the snapshot both views are drawn from, as JSON
    gnoc leads --once --drill <id>   one frame of the drill-down for one ledger item

KEYS (while the command box is empty; once you type, keys edit the command exactly as in gnoc dash)
    Up/Down       select a lead (in a drill-down: scroll)      Enter   open / close the drill-down
    Esc           close the drill-down (or leave a zoomed panel)
    , and .       cycle the filter (open, live, waiting, all) / the program filter
    Tab or v      Simple <-> Technical view (remembered in .claude/state/orch/leads-view.txt)
    1-4           Technical: zoom one panel; 0 or Esc back; PgUp/PgDn scroll it (or the drill-down)
    Ctrl-P/Ctrl-N command history (the arrows select leads while the box is empty)
    t or Ctrl-T   theme   Ctrl-D demo mode   q quit
Every gnoc command still works in the box (pipeline-sweep list is `!scripts/learn/pipeline-sweep.py list`).

READ-ONLY over all hunt state: the ledger is read lock-free (pipeline-sweep writes it atomically), workers are
found by scanning /proc/<pid>/environ in Python, and nothing here sends a signal, writes the ledger, INBOX,
outcomes or reports/. The only file written is the view/theme prefs file.
"""
from __future__ import annotations

import glob
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

WS = os.environ.get("GNOC_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ORCH_DIR = os.path.join(WS, ".claude/state/orch")  # == gnoc's ORCH_DIR, needed BEFORE the dashboard import


def _load(name, rel):
    ld = importlib.machinery.SourceFileLoader(name, os.path.join(WS, rel))
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, ld))
    ld.exec_module(mod)
    return mod


# the dashboard evaluates PREFS at import: point it at THIS board's prefs, then restore the caller's env so a
# `gnoc dash` started from the command box keeps its own dashboard-view.txt
_prev_prefs = os.environ.get("GNOC_DASH_PREFS")
os.environ["GNOC_DASH_PREFS"] = os.environ.get("GNOC_LEADS_PREFS") or os.path.join(ORCH_DIR, "leads-view.txt")
try:
    d = _load("gnoc_dash", "scripts/gnoc-dashboard.py")
finally:
    if _prev_prefs is None:
        os.environ.pop("GNOC_DASH_PREFS", None)
    else:
        os.environ["GNOC_DASH_PREFS"] = _prev_prefs
g = d.g  # the one gnoc module the dashboard (and its Look classes) already loaded
ps = _load("pipeline_sweep", "scripts/learn/pipeline-sweep.py")  # ONE classifier, ONE score: read-only names only
P = ps.Paths(WS)

TERMINAL = ps.TERMINAL
LIVE_NOW = ("RUNNING", "EXITED-UNREAPED", "GONE-PID-REUSED")
HEALTH_LEVEL = {"KEEPING UP": "ok", "BEHIND": "watch", "CLOGGED": "act"}
MV_CH = {"UNTRIED": "-", "TRIED-NEG": "N", "TRIED-POS": "P", "NEEDS": "?", "NA": "x"}
FILTERS = ("open", "live", "waiting", "all")
STATE_LEVEL = {"ACTIVE": "info", "NEEDS": "watch", "EXHAUSTED-FILABLE": "ok", "PROMOTE": "ok", "SKIPPED-POLICY": "muted",
               "FILED": "ok", "DEAD-CONFIRMED": "faint"}
STATE_WORDS = {"ACTIVE": "waiting its turn", "NEEDS": "needs you", "EXHAUSTED-FILABLE": "ready for the ship gates",
               "PROMOTE": "ready for the ship gates", "SKIPPED-POLICY": "skipped by policy", "FILED": "filed",
               "DEAD-CONFIRMED": "closed dead"}
MOVE_WORDS = {"same-defect-higher-asset": "trying the same defect on a higher-value asset",
              "what-it-unlocks": "checking what the finding unlocks", "paired-write": "trying the paired write",
              "partner-bug": "looking for the partner bug", "missing-context": "finding the missing context",
              "ladder-audit": "auditing the escalation ladder"}
TOOL_WORDS = {"Bash": "running a command", "Read": "reading a file", "Write": "writing notes", "Edit": "writing notes",
              "MultiEdit": "writing notes", "Grep": "searching files", "Glob": "searching files", "WebFetch": "fetching a page"}
ORDER_RANK = {"NEEDS": 2, "EXHAUSTED-FILABLE": 3, "PROMOTE": 3, "ACTIVE": 4, "SKIPPED-POLICY": 6, "FILED": 7,
              "DEAD-CONFIRMED": 8}


def ledger_path():
    return os.environ.get("GNOC_LEADS_LEDGER") or P.ledger


def leads_reports_dir():
    """reports/leads/ root: the chain-map mtimes are read from here. Overridable like the ledger, so a test
    fixture never sees the live workspace's CHAINMAP.md files (that leak put real programs in a test panel)."""
    return os.environ.get("GNOC_LEADS_REPORTS") or os.path.join(WS, "reports", "leads")


def proj_dir():
    return os.environ.get("GNOC_LEADS_PROJ") or os.path.join(os.path.expanduser("~/.claude/projects"),
                                                             re.sub(r"[^A-Za-z0-9]", "-", WS))


# ======================================================================================================
# helpers: /proc, transcripts, redaction
# ======================================================================================================

_CLK = os.sysconf("SC_CLK_TCK")
_BTIME = []
ENV_KEY = b"RESCUE_ITEM="  # the ONLY occurrence of this literal: matched against /proc environ bytes, never an argv
# Container plumbing that podman daemonizes: it reparents to init, so the "is it the live worker's child" test
# below cannot catch it, and it inherited RESCUE_ITEM from the lane that ran `sandbox`. It is not a rescue
# worker that escaped the ledger, it is the surface a lane left running, so it is counted on its own line
# (QAQC 2026-10-24: two gatewayco containers from a live lane read as six ORPHAN workers).
_SANDBOX_COMMS = ("pasta", "aardvark-dns", "conmon", "rootlessport", "rootlessport-child", "slirp4netns",
                  "podman", "netavark", "catatonit", "fuse-overlayfs")


def _btime():
    if not _BTIME:
        for ln in g.read("/proc/stat").splitlines():
            if ln.startswith("btime "):
                _BTIME.append(int(ln.split()[1]))
                break
        else:
            _BTIME.append(0)
    return _BTIME[0]


def _stat(pid):
    """(state, session_id, start_epoch) from /proc/<pid>/stat, or None when the process is gone."""
    try:
        with open(f"/proc/{int(pid)}/stat") as fh:
            s = fh.read()
    except (OSError, ValueError):
        return None
    rest = s[s.rfind(")") + 2:].split()  # rest[0] = field 3 (state); field N = rest[N - 3]
    try:
        return rest[0], int(rest[3]), _btime() + int(rest[19]) / _CLK
    except (IndexError, ValueError):
        return None


def _argv(pid):
    try:
        with open(f"/proc/{int(pid)}/cmdline", "rb") as fh:
            return [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
    except (OSError, ValueError):
        return []


def _alive(pid):
    """Same as pipeline-sweep's pid_alive, except a zombie counts as gone (it finished, nobody reaped it yet)."""
    if not ps.pid_alive(pid):
        return False
    st = _stat(pid)
    return st is not None and st[0] != "Z"


def rescue_procs():
    """{iid: [(pid, start_epoch, cmdline)]} for every process whose ENVIRONMENT carries the rescue item tag.
    Pure Python over /proc; pgrep -f cannot do this (it reads argv, and the tag lives only in the env)."""
    out = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/environ", "rb") as fh:
                env = fh.read()
        except OSError:  # PermissionError (other users), FileNotFoundError / ProcessLookupError (exited)
            continue
        if ENV_KEY not in env:
            continue
        for var in env.split(b"\0"):
            if var.startswith(ENV_KEY):
                pid = int(name)
                st = _stat(pid)
                if st is None or st[0] == "Z":
                    break
                out.setdefault(var[len(ENV_KEY):].decode("utf-8", "replace"), []).append(
                    (pid, st[2], " ".join(_argv(pid))[:300]))
                break
    return out


def out_kind(path):
    """("none" | "api-error" | "ok", first line). Text-mode workers write the .out only at exit."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(4096)
    except (OSError, TypeError):
        return ("none", "")
    txt = data.decode("utf-8", "replace")
    first = next((ln.strip() for ln in txt.splitlines() if ln.strip()), "")
    if not first:
        return ("none", "")
    return ("api-error" if first.startswith("API Error") else "ok", redact(first))


def worker_state(row, procs, now):
    dd = row.get("dispatch") or {}
    pid = dd.get("pid")
    if not pid:
        return None
    t0 = ps.parse_iso(dd.get("ts"))
    base = {"pid": pid, "ts": dd.get("ts"), "lane": dd.get("lane"), "move": dd.get("move"), "hunter": dd.get("hunter"),
            "out": dd.get("out"), "reaped": dd.get("reaped"), "elapsed_s": (now - t0.timestamp()) if t0 else None}
    if dd.get("reaped"):
        k, first = out_kind(P.abs(dd["out"])) if dd.get("out") else ("none", "")
        return dict(base, now="DONE", out_kind=k, out_first=first)
    if any(p[0] == pid for p in procs.get(row["id"], [])):
        av = _argv(pid)
        model = av[av.index("--model") + 1] if "--model" in av and av.index("--model") + 1 < len(av) else "opus"
        return dict(base, now="RUNNING", model=model)
    if _alive(pid):
        return dict(base, now="GONE-PID-REUSED")
    k, first = out_kind(P.abs(dd["out"])) if dd.get("out") else ("none", "")
    return dict(base, now="EXITED-UNREAPED", out_kind=k, out_first=first)


_RED = re.compile(r"""(?i)(authorization:\s*(?:bearer\s+|basic\s+|token\s+)?\S+|bearer\s+\S+|"""
                  r"""(?:token|secret|password|passwd|api[_-]?key|cookie)["']?\s*[:=]\s*\S+)""")


def redact(s):
    s = _RED.sub("<redacted>", str(s or ""))
    return re.sub(r"\s+", " ", s).strip()[:200]


_TX_CACHE = {}  # (iid, ts) -> transcript path, for the life of the process
_TX_MISS = {}   # (iid, ts) -> last glob time (re-glob a miss at most every 30 s)


def find_transcript(iid, ts):
    key = (iid, ts)
    if key in _TX_CACHE:
        return _TX_CACHE[key]
    if time.time() - _TX_MISS.get(key, 0) < 30:
        return None
    _TX_MISS[key] = time.time()
    t0 = ps.parse_iso(ts)
    since = (t0.timestamp() if t0 else 0) - 60
    needle = f"RESCUE of {iid} (".encode()
    cands = []
    for f in glob.glob(os.path.join(proj_dir(), "*.jsonl")):
        try:
            mt = os.stat(f).st_mtime
        except OSError:
            continue
        if mt >= since:
            cands.append((mt, f))
    for _, f in sorted(cands, reverse=True):
        try:
            with open(f, "rb") as fh:
                head = fh.read(8192)
        except OSError:
            continue
        if b'"agentSetting"' in head and needle in head:
            _TX_CACHE[key] = f
            _TX_MISS.pop(key, None)
            return f
    return None


def transcript_events(path, n=25):
    """[(epoch, kind, text)] oldest first, newest last; kind in tool | say | result | error. Thinking is skipped."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 262144))
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    if size > 262144:
        lines = lines[1:]
    out = []
    for ln in reversed(lines):
        if len(out) >= n:
            break
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        typ = o.get("type")
        if typ not in ("assistant", "user"):
            continue
        content = (o.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        ts = g._ts(o.get("timestamp"))
        evs = []
        for b in content:
            if not isinstance(b, dict):
                continue
            bt = b.get("type")
            if typ == "assistant" and bt == "tool_use":
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                det = (inp.get("description") or inp.get("command") or inp.get("file_path") or inp.get("pattern")
                       or inp.get("url") or "")
                evs.append((ts, "tool", redact(f"{b.get('name', '?')}: {det}")))
            elif typ == "assistant" and bt == "text":
                evs.append((ts, "say", redact(str(b.get("text", ""))[:160])))
            elif typ == "user" and bt == "tool_result":
                cc = b.get("content")
                if isinstance(cc, list):
                    cc = " ".join(str(x.get("text", "")) for x in cc if isinstance(x, dict))
                evs.append((ts, "error" if b.get("is_error") else "result", redact(str(cc or "")[:120])))
        out.extend(reversed(evs))
    out = out[:n]
    out.reverse()
    return out


def worker_child(pid):
    """The newest non-claude process in the worker's session (it is a session leader). argv: ps only."""
    try:
        r = subprocess.run(["ps", "-o", "pid=,etimes=,args=", "-s", str(int(pid))], capture_output=True, text=True,
                           timeout=5, stdin=subprocess.DEVNULL)
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""
    best = None
    for ln in r.stdout.splitlines():
        parts = ln.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        cpid, et, args = int(parts[0]), int(parts[1]), parts[2]
        if cpid == int(pid) or args.startswith("claude"):
            continue
        if best is None or et < best[0]:
            best = (et, args)
    return redact(best[1])[:120] if best else ""


def next_sweep(cron, now_local):
    """Next fire time of a `M */N * * *` cron (pm2 cron_restart, local time); any other shape -> None."""
    m = re.fullmatch(r"\s*(\d{1,2})\s+\*/(\d{1,2})\s+\*\s+\*\s+\*\s*", cron or "")
    if not m or not now_local:
        return None
    mi, n = int(m.group(1)), int(m.group(2))
    if n <= 0 or mi > 59:
        return None
    base = now_local.replace(minute=0, second=0, microsecond=0)
    for k in range(0, 50):
        t = (base + timedelta(hours=k)).replace(minute=mi)
        if t > now_local and t.hour % n == 0:
            return t
    return None


def health(open_n, stale_n, active_n, cap):
    """(days_to_clear, word). CLOGGED: over half the open leads stale or > 14 days of backlog; BEHIND: any stale
    or > 3 days; else KEEPING UP."""
    dtc = math.ceil(active_n / cap) if cap > 0 else (0 if not active_n else 999)
    if stale_n * 2 > open_n or dtc > 14:
        return dtc, "CLOGGED"
    if stale_n > 0 or dtc > 3:
        return dtc, "BEHIND"
    return dtc, "KEEPING UP"


def dispatch_gate(meta, items, armed, stop, cap, used, running):
    """Read-only mirror of pipeline-sweep dispatch()'s order of checks: what the NEXT sweep would do."""
    if not armed:
        return "disarmed (RESCUE-DISPATCH.enabled absent)"
    if stop:
        return "STOP present"
    if running:
        return "worker running"
    if used >= cap:
        return f"daily cap reached ({used}/{cap})"
    now = ps.now_dt()
    rows = list(items.values()) if isinstance(items, dict) else list(items)
    act = [v for v in rows if v.get("state") == "ACTIVE" and not v.get("gone_from_disk")]
    act.sort(key=lambda v: (-ps.score(v, now), v["id"]))
    blocked = []
    for v in act:
        busy = ps.program_busy(P, v["program"], now)
        if busy:
            blocked.append(f"{v['id']} blocked: {busy} holds {v['program']}")
            continue
        tail = f" (skipped {len(blocked)}: {'; '.join(blocked[:2])})" if blocked else ""
        return f"ready: next sweep sends {v['id']} to {v.get('hunter')}{tail}"
    return "no eligible ACTIVE item" + (f" ({len(blocked)} blocked: {'; '.join(blocked[:2])})" if blocked else "")


# ======================================================================================================
# collectors
# ======================================================================================================

_OUTC = {"key": None, "rows": []}


def _rescue_outcomes():
    try:
        st = os.stat(P.outcomes)
    except OSError:
        return []
    key = (st.st_mtime_ns, st.st_size)
    if _OUTC["key"] != key:
        rows = g._jsonl_tail(P.outcomes, 6000, maxbytes=4_000_000)
        _OUTC["rows"] = [r for r in rows if str(r.get("lane", "")).startswith("rescue-")]
        _OUTC["key"] = key
    return _OUTC["rows"]


def _moves_brief(mv):
    if not mv:
        return ""
    return " ".join(f"{k}{MV_CH.get((mv.get(str(k)) or {}).get('status'), '-')}" for k in range(1, 6))


def _order_key(it):
    now = (it.get("worker") or {}).get("now")
    if now == "RUNNING":
        return (0, 0, it["id"])
    if now in ("EXITED-UNREAPED", "GONE-PID-REUSED"):
        return (1, 0, it["id"])
    r = ORDER_RANK.get(it["state"], 5)
    return (r, -it["score"] if r == 4 else 0, it["id"])


def d_leadlab():
    path = ledger_path()
    with open(path, encoding="utf-8") as fh:  # atomic os.replace on the writer side: no lock needed
        ledger = json.load(fh)
    now_dt = ps.now_dt()
    now = now_dt.timestamp()
    meta = ledger.get("_meta") or {}
    rows = {k: v for k, v in ledger.items() if k != "_meta" and isinstance(v, dict)}
    procs = rescue_procs()
    cap = int(os.environ.get("RESCUE_DAILY_CAP", "2"))
    today = now_dt.strftime("%Y-%m-%d")
    dispatch_today = [t for t in meta.get("dispatch_log", []) if str(t).startswith(today)]
    armed, stop = os.path.isfile(P.enable), os.path.isfile(P.stop)
    items, counts, live_pid = [], {}, {}
    for iid, row in rows.items():
        lt = ps.parse_iso(row.get("last_touched"))
        days = (now_dt - lt).days if lt else None
        kind, _, rest = iid.partition(":")
        prog, _, slug = rest.partition("/")
        ws = worker_state(row, procs, now)
        it = {"id": iid, "kind": row.get("kind", kind), "program": row.get("program", prog), "slug": slug,
              "class": row.get("class"), "hunter": row.get("hunter"), "state": row.get("state", "?"),
              "label": ps.state_label(row), "state_reason": row.get("state_reason"), "next_move": row.get("next_move"),
              "last_touched": row.get("last_touched"), "days": days, "attempts": row.get("attempts", 0),
              "crown": bool(row.get("crown")), "sev": row.get("severity_captured"), "cia": bool(row.get("cia")),
              "home": row.get("home"), "ladder_file": row.get("ladder_file"), "moves": row.get("moves") or {},
              "moves_brief": _moves_brief(row.get("moves")),
              "unfired": row.get("unfired") or {}, "unfired_total": sum((row.get("unfired") or {}).values()),
              "score": ps.score(row, now_dt), "gone": bool(row.get("gone_from_disk")), "worker": ws, "now_line": "",
              "members": list(row.get("members") or []), "chains": list(row.get("chains") or [])}
        counts[it["label"]] = counts.get(it["label"], 0) + 1
        if ws and ws["now"] == "RUNNING":
            live_pid[iid] = ws["pid"]
            tx = find_transcript(iid, ws["ts"])
            ws["transcript"] = os.path.basename(tx) if tx else None
            ev = transcript_events(tx, 1) if tx else []
            if ev:
                ets, ekind, etext = ev[-1]
                ws["last_ev_ts"], ws["last_ev_kind"] = ets, ekind
                it["now_line"] = etext
                it["now_age_s"] = (now - ets) if ets else None
            ws["child"] = worker_child(ws["pid"])
            try:
                ws["out_bytes"] = os.path.getsize(P.abs(ws["out"])) if ws.get("out") else None
            except OSError:
                ws["out_bytes"] = None
        items.append(it)
    items.sort(key=_order_key)
    cmeta = meta.get("chain_map") or {}
    orphans, chainmap_live, sandbox_procs = [], [], []
    for iid, plist in procs.items():
        for pid, start, cmd in plist:
            lp = live_pid.get(iid)
            st = _stat(pid)
            if lp and (pid == lp or (st and st[1] == lp)):
                continue  # the live worker or one of its own children (they inherit the env tag)
            if iid.startswith("chainmap:"):  # a sweep-dispatched chain-mapper pass (or one of its children)
                cprog = iid.partition(":")[2]
                cpid = (cmeta.get(cprog) or {}).get("pid")
                if cpid and (pid == cpid or (st and st[1] == cpid)):
                    if pid == cpid:
                        chainmap_live.append({"prog": cprog, "pid": pid, "elapsed": (now - start) if start else None})
                    continue
            row = {"pid": pid, "iid": iid, "etime": (now - start) if start else None, "cmd": redact(cmd)[:120]}
            prog0 = os.path.basename((cmd.split() or [""])[0])
            (sandbox_procs if prog0 in _SANDBOX_COMMS else orphans).append(row)
    chainmap = {}
    for cprog, ent in cmeta.items():
        if isinstance(ent, dict):
            chainmap[cprog] = {"ts": ent.get("ts"), "reaped": ent.get("reaped")}
    chainmap_mtime = {}
    for f in glob.glob(os.path.join(leads_reports_dir(), "*", "chains", "CHAINMAP.md")):
        try:
            chainmap_mtime[f.split(os.sep)[-3]] = os.stat(f).st_mtime
        except OSError:
            pass
    chain_open = {}
    for i in items:
        if i["kind"] == "chain" and i["state"] not in TERMINAL and not i["gone"]:
            chain_open[i["program"]] = chain_open.get(i["program"], 0) + 1
    open_rows = [i for i in items if i["state"] not in TERMINAL and not i["gone"]]
    open_n = len(open_rows)
    stale_n = sum(1 for i in open_rows if i["days"] is not None and i["days"] > 7)
    active_n = sum(1 for i in open_rows if i["state"] == "ACTIVE")
    dtc, word = health(open_n, stale_n, active_n, cap)
    blocking = any(ps.pid_alive((v.get("dispatch") or {}).get("pid")) for v in rows.values()) \
        or any(ps.pid_alive((e or {}).get("pid")) for e in cmeta.values() if isinstance(e, dict))  # dispatch()'s own test
    try:
        age = now - os.stat(path).st_mtime
    except OSError:
        age = None
    return {"ledger": path, "ledger_ok": True, "ledger_age_s": age, "last_sweep": meta.get("last_sweep"),
            "last_sweep_dry": bool(meta.get("last_sweep_dry")), "armed": armed, "stop": stop, "cap": cap,
            "used_today": len(dispatch_today), "dispatch_today": dispatch_today,
            "gate": dispatch_gate(meta, rows, armed, stop, cap, len(dispatch_today), blocking),
            "items": items, "counts": counts, "open_n": open_n, "stale_n": stale_n, "active_n": active_n,
            "days_to_clear": dtc, "health": word, "order": [i["id"] for i in items], "orphans": orphans,
            "sandbox_procs": sandbox_procs,
            "rescue_outcomes": _rescue_outcomes()[-15:],
            "chainmap": chainmap, "chainmap_live": chainmap_live, "chainmap_mtime": chainmap_mtime,
            "chain_open": chain_open, "chain_armed": os.path.isfile(getattr(P, "chain_enable", ""))}


def d_sweepproc():
    rc, out, err = g.sh("pm2 jlist", timeout=6)
    if rc != 0:
        raise RuntimeError(f"pm2 jlist failed: {err.strip()[:80]}")
    res = {}
    for p in json.loads(out):
        name = p.get("name")
        if name not in ("pipeline-sweep", "orch-bot", "oss-bot"):
            continue
        e = p.get("pm2_env") or {}
        res[name] = {"status": e.get("status", "?"), "cron_restart": e.get("cron_restart"),
                     "autorestart": e.get("autorestart"), "restart_time": e.get("restart_time"),
                     "pm_uptime": e.get("pm_uptime")}
    for name in ("pipeline-sweep", "orch-bot", "oss-bot"):
        r = res.setdefault(name, {"status": "missing", "cron_restart": None})
        st = r["status"]
        if name == "pipeline-sweep" and st == "stopped" and r.get("cron_restart"):
            r["word"], r["level"] = "between runs (cron)", "muted"  # pm2 cron job, autorestart off: normal
        elif st == "online":
            r["word"], r["level"] = ("running now" if name == "pipeline-sweep" else "online"), "ok"
        else:
            r["word"], r["level"] = ("missing from pm2" if st == "missing" else st), "act"
    return res


class LeadFeed(g.Feed):
    JOBS = [("leadlab", d_leadlab, 3), ("sweepproc", d_sweepproc, 30), ("services", g.d_services, 5)]

    def once(self, budget=4.0):
        """g.Feed.once without the trailing `totals` job (that one runs d_hunt; this board never needs it)."""
        ths = []
        for name, fn, _ in self.JOBS:
            th = threading.Thread(target=self._run, args=(name, fn), daemon=True)
            th.start()
            ths.append(th)
        end = time.time() + budget
        for th in ths:
            th.join(max(0.05, end - time.time()))


# ======================================================================================================
# snapshot
# ======================================================================================================

def _next_sweep_text(data):
    sp = (data.get("sweepproc") or {}).get("pipeline-sweep") or {}
    cron = sp.get("cron_restart")
    if not cron:
        return None
    nx = next_sweep(cron, datetime.now().astimezone())
    return nx.astimezone(timezone.utc).strftime("%H:%MZ") if nx else f"cron {cron}"


def _sentence(data):
    ll = data.get("leadlab")
    if not ll:
        return "Reading the rescue ledger...", "muted"
    lvl = HEALTH_LEVEL.get(ll.get("health"), "muted")
    runs = [i for i in ll["items"] if (i.get("worker") or {}).get("now") == "RUNNING"]
    if runs:
        parts = [f"{i['program']} {i['slug']} ({i['hunter']}, {g._dur(i['worker'].get('elapsed_s'))})" for i in runs]
        n = len(runs)
        return f"{n} lead{' is' if n == 1 else 's are'} being tested right now: {'; '.join(parts)}.", lvl
    gate = ll.get("gate", "")
    gate = "the next sweep sends " + gate[len("ready: next sweep sends "):] if gate.startswith("ready: ") else gate
    s = f"Nothing is being tested right now: {gate}."
    nx = _next_sweep_text(data)
    if nx:
        s += f" Next sweep {nx}" + (" will wait for tomorrow." if gate.startswith("daily cap") else ".")
    return s, lvl


def _vocab(data):
    ll = data.get("leadlab") or {}
    words = ["LEAD LAB", "KEEPING UP", "BEHIND", "CLOGGED", "RESCUE-DISPATCH.enabled", "RESCUE_ITEM", "ORPHAN",
             "api-error", "ladder-audit", "between runs", "cron", "opus", "sonnet", "haiku", "draft", "leadmd", "leadq",
             "archive", "pipeline-sweep", "orch-bot", "oss-bot", "rescue", "ok", "act", "watch", "muted", "faint", "info"]
    words += list(LIVE_NOW) + ["DONE"] + list(ORDER_RANK) + list(ps.MOVES.values()) + [h for _, h in ps.HUNTER_MAP]
    words += [ps.FALLBACK_HUNTER] + list(MOVE_WORDS) + list(STATE_WORDS.values())
    for i in ll.get("items") or []:
        words += [i.get("hunter"), i.get("label"), i.get("class") or ""]
    return [w for w in words if w]


def build_lead_snapshot(feed, demo=False, scrub=None):
    data, err = d._copy_feed(feed)
    sentence, level = _sentence(data)
    real = None
    if demo:
        scrub.allow(*_vocab(data))
        real_items = (data.get("leadlab") or {}).get("items") or []
        data, err, sentence = scrub.tree(data), scrub.tree(err), scrub.text(sentence)
        real = {scrub.text(i["id"]): i for i in real_items}
    snap = {"ver": feed.ver, "built": time.time(), "started": feed.started, "demo": demo, "data": data, "err": err,
            "sentence": sentence, "level": level, "next_sweep": _next_sweep_text(data)}
    if real is not None:
        snap["_real"] = real  # fake id -> real item: the drill-down reads files by the REAL home, prints scrubbed
    return snap


# ======================================================================================================
# drill-down (built on demand, memoised by the app)
# ======================================================================================================

def _head(path, n=40, cap=8192):
    try:
        with open(path, "rb") as fh:
            data = fh.read(cap)
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()[:n]


def _newest(paths):
    best = None
    for p in paths:
        try:
            mt = os.stat(p).st_mtime
        except OSError:
            continue
        if best is None or mt > best[0]:
            best = (mt, p)
    return best[1] if best else None


def _files_since(roots, since, limit=8, depth=3):
    found = []

    def walk(d_, lvl):
        try:
            with os.scandir(d_) as it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if lvl < depth:
                                walk(e.path, lvl + 1)
                        elif e.is_file(follow_symlinks=False):
                            st = e.stat(follow_symlinks=False)
                            if st.st_mtime >= since:
                                found.append((st.st_mtime, e.path, st.st_size))
                    except OSError:
                        continue
        except OSError:
            return
    for r in roots:
        if os.path.isdir(r):
            walk(r, 1)
    found.sort(reverse=True)
    return found[:limit]


def _find_item(iid, snap):
    ll = snap["data"].get("leadlab") or {}
    shown = next((i for i in ll.get("items") or [] if i["id"] == iid), None)
    real = snap.get("_real")
    if real is not None:
        if shown is None:  # a REAL id given on the command line while demo mode is on
            for fake, it in real.items():
                if it["id"] == iid:
                    shown = next((i for i in ll.get("items") or [] if i["id"] == fake), None)
                    return shown, it
            return None, None
        return shown, real.get(iid, shown)
    return shown, shown


def drill_lines(iid, snap):
    """[[(text, level, bold), ...], ...] for one item. Reads files only for that item; head 40 lines / 8 KB each."""
    shown, it = _find_item(iid, snap)
    if it is None:
        return [[(f"no ledger item {iid}", "act", True)]]
    L = []

    def sec(title):
        L.append([("", "text", False)])
        L.append([(title, "info", True)])

    def kv(k, v, level="text"):
        L.append([(f"  {k:<14}", "muted", False), (str(v), level, False)])

    now = time.time()
    lvl = STATE_LEVEL.get(it["state"], "text")
    L.append([(it["id"], "text", True), ("  ", "", False), (it["label"], lvl, True)])
    kv("reason", it.get("state_reason") or "-")
    kv("hunter", f"{it.get('hunter')}   class {it.get('class') or '-'}")
    kv("crown/sev/cia", f"{'crown' if it['crown'] else 'no crown'} / {it.get('sev') or '-'} / {'CIA' if it['cia'] else 'no CIA'}")
    kv("attempts", f"{it['attempts']}   unfired {it.get('unfired') or {}}   untouched {it['days'] if it['days'] is not None else '?'} days   score {it['score']}")
    kv("home", it.get("home"))
    kv("next move", it.get("next_move"), "hilite")
    if it.get("members") or it.get("chains"):
        real_items = list((snap.get("_real") or {}).values()) or list((snap["data"].get("leadlab") or {}).get("items") or [])
        st_of = {x["id"]: x.get("label") or x.get("state") for x in real_items}
        if it.get("members"):
            kv("members", "   ".join(f"{m} ({st_of.get(m, 'not in ledger')})" for m in it["members"]))
        if it.get("chains"):
            kv("in chains", "   ".join(f"{c} ({st_of.get(c, '?')})" for c in it["chains"]))
    home = P.abs(it.get("home") or "")
    w = it.get("worker") or {}
    if w.get("now") == "RUNNING":
        sec("NOW")
        kv("worker", f"pid {w['pid']}  model {w.get('model')}  move {w.get('move')}  elapsed {g._dur(w.get('elapsed_s'))}", "hilite")
        if w.get("child"):
            kv("child", w["child"])
        tx = find_transcript(it["id"], w.get("ts"))
        if tx:
            kv("transcript", os.path.basename(tx), "muted")
            for ts, kind, text in transcript_events(tx, 25):
                L.append([(f"  {g._local(ts, '%H:%M:%S') if ts else '--:--:--'} ", "muted", False),
                          (f"{kind:<7}", {"tool": "info", "error": "act", "say": "hilite"}.get(kind, "muted"), True),
                          (text, "text", False)])
        else:
            kv("transcript", "not found yet (re-checked every 30 s)", "muted")
        since = (ps.parse_iso(w.get("ts")) or ps.now_dt()).timestamp()
        roots = [home, os.path.join(WS, "targets", it["program"], "hunts")]
        L.append([("  files touched since dispatch:", "muted", False)])
        for mt, path, size in _files_since(roots, since):
            L.append([(f"    {os.path.relpath(path, WS)}", "text", False), (f"  {size} B  {d._ago(mt, now)}", "muted", False)])
    sec("LADDER")
    mv = it.get("moves") or {}
    if not mv:
        L.append([(f"  no {it.get('ladder_file') or 'RESCUE-LADDER.md'} yet (next: ladder-audit)", "muted", False)])
    for k in sorted(mv, key=int):
        m = mv[k]
        st = m.get("status", "?")
        dec = f" (declared {m.get('declared')})" if m.get("declared") and m.get("declared") != st else ""
        L.append([(f"  {k} {ps.move_label(it, k) if it.get('kind') == 'chain' else ps.MOVES.get(int(k), '?'):<26}", "text", True),
                  (f"{st}{dec}", {"TRIED-NEG": "muted", "TRIED-POS": "ok", "NEEDS": "watch"}.get(st, "info"), True),
                  (f"  probes {m.get('probes', 0)}  burst {'yes' if m.get('burst') else 'no'}  {m.get('artifact') or '-'}", "muted", False)])
        if m.get("note"):
            L.append([(f"      {redact(m['note'])}", "faint", False)])
    ctx = [os.path.join(home, "HELD-REASON.md")]
    if it.get("kind") == "leadmd":
        ctx.append(os.path.join(home, it["id"].split("/", 1)[-1]))
    ctx += [os.path.join(home, "WHY-ARCHIVED.md"), os.path.join(home, "DEAD-CONFIRMED.md")]
    kp = _newest(glob.glob(os.path.join(home, "KILLPASS*.txt")))
    if kp:
        ctx.append(kp)
    cf = next((c for c in ctx if os.path.isfile(c)), None)
    if cf:
        sec("CONTEXT FILE")
        L.append([(f"  {os.path.relpath(cf, WS)}", "muted", False)])
        L += [[(f"  {redact(ln)}", "text", False)] for ln in _head(cf, 40)]
    st_cands = []
    for m in mv.values():
        art = str(m.get("artifact") or "")
        if art.startswith("targets/"):
            a = P.abs(art)
            dd = a if os.path.isdir(a) else os.path.dirname(a)
            if os.path.isfile(os.path.join(dd, "STATUS.md")):
                st_cands.append(os.path.join(dd, "STATUS.md"))
    hunts = os.path.join(WS, "targets", it["program"], "hunts")
    stf = (_newest(st_cands) or _newest(glob.glob(os.path.join(hunts, "rescue-*", "STATUS.md")))
           or _newest(glob.glob(os.path.join(hunts, "*", "STATUS.md"))))
    if stf:
        sec("HUNT STATUS")
        L.append([(f"  {os.path.relpath(stf, WS)}", "muted", False)])
        L += [[(f"  {redact(ln)}", "text", False)] for ln in _head(stf, 30)]
    dsp = it.get("worker")
    if dsp:
        sec("LAST RUN")
        kv("dispatched", f"{dsp.get('ts')}   reaped {dsp.get('reaped') or '-'}   now {dsp.get('now')}")
        kv("out", dsp.get("out") or "-", "muted")
        ok_, first = out_kind(P.abs(dsp["out"])) if dsp.get("out") else ("none", "")
        kv("out_kind", f"{ok_}  {first}" if ok_ == "api-error" else ok_, "act" if ok_ == "api-error" else "ok" if ok_ == "ok" else "muted")
        if dsp.get("out"):
            L += [[(f"  {redact(ln)}", "text", False)] for ln in _head(P.abs(dsp["out"]), 30)]
        lane = f"rescue-{it['id']}"
        rows = [r for r in _rescue_outcomes() if r.get("lane") == lane][-5:]
        for r in rows:
            L.append([(f"  {r.get('ts', '')} ", "muted", False), (f"{r.get('verdict', '?')} ", "watch", True),
                      (f"probes {r.get('probes')} burst {r.get('burst')} ", "muted", False), (redact(r.get("notes") or r.get("vector") or ""), "text", False)])
    prog = it["program"]
    br = [r for r in g._jsonl_tail(os.path.join(g.ORCH_DIR, "brain.jsonl"), 300)
          if prog in str(r.get("detail") or "") or prog in str(r.get("reason") or "")][-3:]
    ch = [r for r in g._jsonl_tail(g.CHANGES_LOG, 300)
          if prog in str(r.get("detail") or "") or prog in str(r.get("reason") or "")][-3:]
    if br or ch:
        sec("PROGRAM ACTIVITY")
        for src, rows in (("brain", br), ("change", ch)):
            for r in rows:
                L.append([(f"  {str(r.get('ts', ''))[:19]} ", "muted", False), (f"{src} {r.get('action') or r.get('kind') or ''} ", "info", False),
                          (redact(r.get("detail") or r.get("reason") or ""), "text", False)])
    if snap.get("demo") and snap.get("_scrub") is not None:
        sc = snap["_scrub"]
        L = [[(sc.text(t), lv, b) for t, lv, b in line] for line in L]
    return L


# ======================================================================================================
# views
# ======================================================================================================

def _T(lk, parts):
    return lk.T(*[(t, lk.S(lv, bold=b) if lv else "") for t, lv, b in parts])


def midcut(s, n, uni=True):
    s = str(s or "")
    if n <= 3 or len(s) <= n:
        return s[:max(0, n)]
    dots = "…" if uni else "~"
    a = (n - 1) // 2
    return s[:a] + dots + s[-(n - 1 - a):]


def filtered(app, snap):
    ll = snap["data"].get("leadlab") or {}
    by = {i["id"]: i for i in ll.get("items") or []}
    allit = [by[k] for k in ll.get("order") or [] if k in by]
    f = FILTERS[app.filt % len(FILTERS)]
    live = lambda i: (i.get("worker") or {}).get("now") in LIVE_NOW  # noqa: E731
    if f == "open":
        items = [i for i in allit if i["state"] not in TERMINAL or live(i)]
    elif f == "live":
        items = [i for i in allit if live(i)]
    elif f == "waiting":
        items = [i for i in allit if i["state"] in ("NEEDS", "EXHAUSTED-FILABLE", "PROMOTE")]
    else:
        items = allit
    progs = ["all"]
    for i in allit:
        if i["program"] not in progs:
            progs.append(i["program"])
    pf = progs[app.prog_f % len(progs)]
    if pf != "all":
        items = [i for i in items if i["program"] == pf]
    return items, f, pf, len(allit)


def _window(n, sel, avail):
    """(start, end, above, below) for a list of n rows with `avail` rows of room, keeping sel visible and reserving
    one row for each 'more' marker, so a list is never cut silently and the marker never covers the selection."""
    avail = max(1, avail)
    if n <= avail:
        return 0, n, 0, 0
    if avail < 3:  # no room for markers: just the selected row
        return sel, sel + 1, sel, n - sel - 1
    vis = avail - 1
    if sel < vis:
        return 0, vis, 0, n - vis
    if sel >= n - vis:  # near the end: only the 'above' marker is needed
        return n - vis, n, n - vis, 0
    vis = avail - 2
    start = sel - vis + 1
    return start, start + vis, start, n - start - vis


def _marker(lk, text):
    return lk.T((f"  {lk.G['more']} {text}", lk.S("muted", italic=True)))


def chainmap_parts(ll, now=None):
    """[(prog, status)] for the chain-map health line: 'running 4m' or '2h ago (2 open)' per program."""
    now = now or time.time()
    live = {c["prog"]: c for c in ll.get("chainmap_live") or []}
    cmeta, cmt, copen = ll.get("chainmap") or {}, ll.get("chainmap_mtime") or {}, ll.get("chain_open") or {}
    parts = []
    for prog in sorted(set(live) | set(cmeta) | set(cmt) | set(copen)):
        if prog in live:
            parts.append((prog, f"running {g._dur(live[prog].get('elapsed'))}"))
            continue
        last = max([x for x in (cmt.get(prog), g._ts((cmeta.get(prog) or {}).get("ts"))) if x] or [0])
        st = d._ago(last, now) if last else "never mapped"
        parts.append((prog, f"{st} ({copen.get(prog, 0)} open)"))
    return parts


def chainmap_line(lk, ll):
    parts = chainmap_parts(ll)
    t = lk.T(("chain map  ", lk.S("muted")))
    if not parts:
        t.append("none yet", style=lk.S("muted"))
    for prog, st in parts:
        t.append(f"{prog} ", style=lk.S("text", bold=True))
        t.append(f"{st}  ", style=lk.S("hilite" if st.startswith("running") else "text"))
    t.append("   chain dispatch ", style=lk.S("muted"))
    t.append("armed" if ll.get("chain_armed") else "disarmed",
             style=lk.S("ok" if ll.get("chain_armed") else "watch", bold=True))
    return t


def _move_words(move):
    m = re.match(r"^(?:\d+\s+)?edge-(\d+)", str(move or ""))
    if m:  # a chain item's ladder rows are its edges (pipeline-sweep move_label)
        return f"testing chain edge {m.group(1)}"
    if move and str(move).isdigit():
        move = ps.MOVES.get(int(move), move)
    return MOVE_WORDS.get(str(move), str(move or "?"))


class LeadSimple:
    def __init__(self, app):
        self.app = app

    def header(self, lk, snap, width, t):
        ll = snap["data"].get("leadlab") or {}
        hw = ll.get("health")
        chips = [lk.chip("LEAD LAB", "info"), " "]
        if hw:
            chips += [lk.chip(hw, HEALTH_LEVEL[hw]), " "]
        if snap["demo"]:
            chips += [lk.chip("DEMO", "hilite"), " "]
        fl = self.app.flash_text()
        if fl:
            chips += [lk.chip(f"{lk.G['star']} {fl}", "act" if (t // 3) % 2 == 0 else "hilite"), " "]
        top = lk.T(" ", lk.small_mark(t), "  ", *chips, (" " + snap["sentence"], lk.S("text", bold=True)))
        second = lk.T(" ", d.clock_ribbon(lk, snap, t, compact=width < 100), ("   ", ""), d.uptime_ribbon(lk, snap))
        return [lk.lines(top, width)[0], lk.lines(second, width)[0], lk.lines(lk.scan_rule(t, width), width)[0]]

    def working(self, lk, snap, w, t):
        ll = snap["data"].get("leadlab") or {}
        out = []
        spin = lk.G["spin"][t // 3 % len(lk.G["spin"])]
        now = time.time()
        for i in ll.get("items") or []:
            wk = i.get("worker") or {}
            if wk.get("now") == "RUNNING":
                out.append(lk.T((spin + " ", lk.S("ok", bold=True)), (f"{i['program']} {i['slug']}", lk.S("text", bold=True))))
                out.append(lk.T(("  ", ""), (i.get("hunter") or "?", lk.S("hilite")), (f" {lk.G['sep']} ", lk.S("faint")),
                                (_move_words(wk.get("move")), lk.S("text")), (f" {lk.G['sep']} {g._dur(wk.get('elapsed_s'))}", lk.S("muted"))))
                if i.get("now_line"):
                    name, _, det = i["now_line"].partition(": ")
                    kind = wk.get("last_ev_kind")
                    words = TOOL_WORDS.get(name, name) if kind == "tool" else {"say": "said", "error": "got an error",
                                                                              "result": "got a result"}.get(kind, kind or "")
                    det = det if kind == "tool" else i["now_line"]
                    age = f"  ({g._dur(i['now_age_s'])} ago)" if i.get("now_age_s") is not None else ""
                    out.append(lk.T(("  last: ", lk.S("muted")), (words, lk.S("info")), (f" - {det}", lk.S("text")), (age, lk.S("muted"))))
                else:
                    out.append(lk.T(("  last: ", lk.S("muted")), ("no transcript activity found yet", lk.S("muted"))))
                if wk.get("child"):
                    out.append(lk.T(("  now:  ", lk.S("muted")), (wk["child"], lk.S("text"))))
            elif wk.get("now") in ("EXITED-UNREAPED", "GONE-PID-REUSED"):
                out.append(lk.T((lk.G["ring"] + " ", lk.S("muted")), (f"{i['program']} {i['slug']}", lk.S("text")),
                                (": finished, waiting for the next sweep to log it", lk.S("muted"))))
        if not out:
            out.append(lk.T((lk.G["ring"] + " Idle - ", lk.S("muted")), (ll.get("gate") or "reading the ledger...", lk.S("text"))))
        orph = ll.get("orphans") or []
        if orph:
            out.append(lk.T((f"! {len(orph)} rescue worker process(es) not in the ledger (see the technical view)", lk.S("act", bold=True))))
        sbx = ll.get("sandbox_procs") or []
        if sbx:
            iids = sorted({o["iid"] for o in sbx})
            out.append(lk.T((f"{lk.G['ring']} {len(sbx)} sandbox container process(es) still up from ", lk.S("muted")),
                            (", ".join(iids[:2]) + ("..." if len(iids) > 2 else ""), lk.S("text")),
                            (" (podman ps; they are surfaces, not workers)", lk.S("muted"))))
        return out

    def health_body(self, lk, snap, w, big):
        ll = snap["data"].get("leadlab") or {}
        if not ll:
            return [lk.T(("reading the ledger...", lk.S("muted")))]
        cells = [("open", str(ll["open_n"]), "info"), ("stale >7d", str(ll["stale_n"]), "act" if ll["stale_n"] else "ok"),
                 ("slots today", f"{ll['used_today']}/{ll['cap']}", "watch" if ll["used_today"] >= ll["cap"] else "ok")]
        cw = max(10, w // 3)
        cols = []
        for label, s, lv in cells:
            if big and lk.uni and len(s) * 4 <= cw:
                cols.append([lk.T((label, lk.S("muted")))] + lk.bigdigits(s.replace("/", " "), lv))
            else:
                cols.append([lk.T((s, lk.S(lv, bold=True)), (f" {label}", lk.S("muted")))])
        rows = []
        for r in range(max(len(c) for c in cols)):
            line = lk.Text(no_wrap=True)
            for c in cols:
                cell = c[r] if r < len(c) else lk.T("")
                line.append_text(cell)
                line.append(" " * max(1, cw - cell.cell_len))
            rows.append(line)
        counts = ll.get("counts") or {}
        total = sum(counts.values()) or 1
        bar = lk.Text(no_wrap=True)
        legend = lk.Text(no_wrap=True)
        bw = max(10, w - 2)
        used = 0
        groups = sorted(counts.items(), key=lambda kv: (ORDER_RANK.get(kv[0].split("(")[0], 5), kv[0]))
        for k, (label, n) in enumerate(groups):
            lv = STATE_LEVEL.get(label.split("(")[0], "muted")
            seg = bw - used if k == len(groups) - 1 else max(1, round(n / total * bw))
            seg = max(0, min(seg, bw - used))
            used += seg
            bar.append(lk.G["full"] * seg, style=lk.S(lv, bold=True))
            legend.append(f"{lk.G['dot']} ", style=lk.S(lv, bold=True))
            legend.append(f"{label} {n}  ", style=lk.S("text"))
        rows += [bar, legend]
        rows.append(lk.T((f"At {ll['cap']} a day the {ll['active_n']} active leads take ~{ll['days_to_clear']} days to clear", lk.S("text"))))
        ls = g._ts(ll.get("last_sweep"))
        nx = snap.get("next_sweep")
        rows.append(lk.T(("last sweep ", lk.S("muted")), (d._ago(ls) if ls else "never", lk.S("text")),
                         (f" ({'dry run' if ll.get('last_sweep_dry') else 'live'})", lk.S("muted")),
                         (f", next {nx}" if nx else "", lk.S("text"))))
        rows.append(lk.T(("rescue dispatch ", lk.S("muted")), ("armed" if ll.get("armed") else "disarmed", lk.S("ok" if ll.get("armed") else "watch", bold=True)),
                         ("   STOP set" if ll.get("stop") else "", lk.S("act", bold=True))))
        rows.append(chainmap_line(lk, ll))
        return rows

    def waiting(self, lk, snap, w):
        ll = snap["data"].get("leadlab") or {}
        out = []
        for i in ll.get("items") or []:
            if i["state"] == "NEEDS":
                txt = i.get("next_move") or i.get("state_reason") or ""
                out.append(lk.T((lk.G["dot"] + " ", lk.S("watch", bold=True)), (f"{i['program']} {i['slug']}: ", lk.S("text", bold=True)), (txt, lk.S("text"))))
            elif i["state"] in ("EXHAUSTED-FILABLE", "PROMOTE"):
                out.append(lk.T((lk.G["dot"] + " ", lk.S("ok", bold=True)), (f"{i['program']} {i['slug']}: ", lk.S("text", bold=True)),
                                ("ladder exhausted; run the ship gates, then it needs your approval", lk.S("text"))))
        return out or [lk.T((lk.G["ok"] + " nothing is waiting on you", lk.S("ok")))]

    def open_list(self, lk, snap, w, inner):
        items, f, pf, total = filtered(self.app, snap)
        self.app.sel = max(0, min(self.app.sel, len(items) - 1)) if items else 0
        head = lk.T(("filter ", lk.S("muted")), (f, lk.S("info", bold=True)), ("  , cycles   program ", lk.S("muted")),
                    (pf, lk.S("info", bold=True)), ("  . cycles   ", lk.S("muted")), (f"{len(items)}/{total}", lk.S("faint")),
                    ("   arrows select, Enter opens", lk.S("faint")))
        start, end, above, below = _window(len(items), self.app.sel, inner - 1)
        out = [head] + ([_marker(lk, f"{above} above")] if above else [])
        for k, i in enumerate(items[start:end], start):
            wk = (i.get("worker") or {}).get("now")
            word = "being tested now" if wk == "RUNNING" else "finished, not logged yet" if wk in LIVE_NOW else STATE_WORDS.get(i["state"], i["label"])
            lv = "ok" if wk == "RUNNING" else STATE_LEVEL.get(i["state"], "text")
            sel = k == self.app.sel
            days = f"untouched {i['days']} days" if i.get("days") is not None else "never touched"
            line = lk.T(((lk.G["arrow"] if sel else " ") + " ", lk.S("info", bold=True)),
                        (f"{i['program']} {i['slug']}"[:max(10, w // 2)], lk.S("text", bold=True)), ("  ", ""),
                        (word, lk.S(lv, bold=True)), (f"  {days}", lk.S("muted")),
                        (f"  tried {i['attempts']} time{'' if i['attempts'] == 1 else 's'}", lk.S("muted")))
            if sel:
                line.stylize("reverse")
            out.append(line)
        if not items:
            out.append(lk.T(("no leads match this filter", lk.S("muted"))))
        return out + ([_marker(lk, f"+{below} more (arrows scroll)")] if below else [])

    def render(self, lk, snap, width, height, t):
        head = self.header(lk, snap, width, t)
        room = height - len(head)
        if room <= 0:
            return head[:height]
        big = width >= 110 and height >= 34
        key = ("lsimple", id(lk), self.app.snap_key, width, height, self.app.sel, self.app.filt, self.app.prog_f, t // 3)
        body = self.app.cached("lead-simple", key, lambda: self.body(lk, snap, width, room, big, t))
        return (head + body + [""] * height)[:height]

    def body(self, lk, snap, width, room, big, t):
        out = []
        side = width >= 120
        if side:
            lw = int(width * 0.55)
            rw = width - lw
            wb = self.working(lk, snap, lw - 4, t)
            hb = self.health_body(lk, snap, rw - 4, big)
            top_h = min(max(len(wb), len(hb)) + 2, max(6, room // 2))
            out += d.hjoin([lk.block("WORKING NOW", wb, lw, top_h, "ok"), lk.block("PIPELINE HEALTH", hb, rw, top_h, "watch")], [lw, rw])
        else:
            wb = self.working(lk, snap, width - 4, t)
            hb = self.health_body(lk, snap, width - 4, False)
            wh = min(len(wb) + 2, max(3, room // 4))
            hh = min(len(hb) + 2, max(4, room // 3))
            out += lk.block("WORKING NOW", wb, width, wh, "ok")
            out += lk.block("PIPELINE HEALTH", hb, width, hh, "watch")
        left = room - len(out)
        wt = self.waiting(lk, snap, width - 4)
        wh = min(len(wt) + 2, max(3, left // 3))
        if left - wh >= 4:
            out += lk.block("WAITING ON YOU", wt, width, wh, "watch")
            left -= wh
        if left >= 3:
            out += lk.block("OPEN LEADS", self.open_list(lk, snap, width - 4, left - 2), width, left, "info")
        return out[:room]


class LeadTech(d.Technical):
    PANELS = [("leads", "LEADS", "info", "head"), ("live", "LIVE WORKERS", "hilite", "head"),
              ("health", "BACKLOG HEALTH", "watch", "head"), ("activity", "RESCUE ACTIVITY", "muted", "tail")]
    TABS = {"leads": "leads", "live": "live", "health": "health", "activity": "activity"}

    def p_leads(self, lk, snap, w, t):
        ll = snap["data"].get("leadlab")
        if not ll:
            return self.err(lk, snap, "leadlab") or [lk.T(("loading...", lk.S("muted")))]
        out = self.err(lk, snap, "leadlab")
        items, f, pf, total = filtered(self.app, snap)
        self.app.sel = max(0, min(self.app.sel, len(items) - 1)) if items else 0
        out.append(lk.T(("filter ", lk.S("muted")), (f, lk.S("info", bold=True)), ("  program ", lk.S("muted")),
                        (pf, lk.S("info", bold=True)), (f"  {len(items)}/{total}", lk.S("faint")), ("   , . cycle  Enter opens", lk.S("faint"))))
        wide = w >= 110
        idw = max(18, (w - 78) // 2) if wide else max(14, w - 50)
        nmw = max(10, w - idw - 78) if wide else 0
        hdr = f"  {'NOW':<5}{'id':<{idw}} {'label':<20}" + (f"{'hunter':<15}{'class':<10}{'next_move':<{nmw}} " if wide else "") \
            + f"{'days':>4} {'att':>3}" + (f" {'score':>5} {'C/sev':<7}" if wide else "")
        out.append(lk.T((hdr, lk.S("faint"))))
        start, end, above, below = _window(len(items), self.app.sel, self.room - len(out))
        if above:
            out.append(_marker(lk, f"{above} above"))
        for k, i in enumerate(items[start:end], start):
            wk = (i.get("worker") or {}).get("now")
            nw = {"RUNNING": "RUN", "EXITED-UNREAPED": "EXIT", "GONE-PID-REUSED": "GONE"}.get(wk, "")
            term = i["state"] in TERMINAL
            base = "faint" if term else "text"
            lv = STATE_LEVEL.get(i["state"], "text")
            sel = k == self.app.sel
            parts = [(("> " if sel else "  "), lk.S("info", bold=True)), (f"{nw:<5}", lk.S("ok" if nw == "RUN" else "watch", bold=True)),
                     (f"{midcut(i['id'], idw - 1, lk.uni):<{idw}} ", lk.S(base, bold=not term)),
                     (f"{midcut(i['label'], 19, lk.uni):<20}", lk.S("faint" if term else lv, bold=not term))]
            if wide:
                parts += [(f"{str(i.get('hunter') or '-')[:14]:<15}", lk.S(base)), (f"{str(i.get('class') or '-')[:9]:<10}", lk.S("muted")),
                          (f"{str(i.get('next_move') or '-')[:nmw - 1]:<{nmw}} ", lk.S(base))]
            parts += [(f"{i['days'] if i['days'] is not None else '?':>4} ", lk.S("act" if (i.get('days') or 0) > 7 and not term else "muted")),
                      (f"{i['attempts']:>3}", lk.S("muted"))]
            if wide:
                cs = ("C" if i["crown"] else "-") + "/" + str(i.get("sev") or "-")
                parts += [(f" {i['score']:>5}", lk.S("info")), (f" {cs:<7}", lk.S("hilite" if i["crown"] else "muted"))]
            line = lk.T(*parts)
            if sel:
                line.stylize("reverse")
            out.append(line)
        if not items:
            out.append(lk.T(("no leads match this filter", lk.S("muted"))))
        return out + ([_marker(lk, f"+{below} more (arrows scroll)")] if below else [])

    def p_live(self, lk, snap, w, t):
        ll = snap["data"].get("leadlab")
        if not ll:
            return [lk.T(("loading...", lk.S("muted")))]
        out = []
        for i in ll["items"]:
            wk = i.get("worker") or {}
            if wk.get("now") != "RUNNING":
                continue
            ob = wk.get("out_bytes")
            obt = "-" if ob is None else (f"{ob} B (text mode, written at exit)" if ob == 0 else f"{ob} B")
            out.append(lk.T((lk.G["dot"] + " RUN ", lk.S("ok", bold=True)), (f"pid {wk['pid']}  ", lk.S("muted")), (i["id"], lk.S("text", bold=True))))
            out.append(lk.T(("  ", ""), (f"{i.get('hunter')}  model {wk.get('model')}  move {wk.get('move')}  elapsed {g._dur(wk.get('elapsed_s'))}", lk.S("text"))))
            out.append(lk.T(("  out ", lk.S("muted")), (obt, lk.S("text")), ("  transcript ", lk.S("muted")),
                            (wk.get("transcript") or "not found yet", lk.S("text" if wk.get("transcript") else "muted")),
                            ("  last event ", lk.S("muted")), (g._local(wk["last_ev_ts"], "%H:%M:%S") if wk.get("last_ev_ts") else "-", lk.S("text"))))
            if i.get("now_line"):
                out.append(lk.T(("  now   ", lk.S("muted")), (i["now_line"], lk.S("info"))))
            if wk.get("child"):
                out.append(lk.T(("  child ", lk.S("muted")), (wk["child"], lk.S("text"))))
        for i in ll["items"]:
            wk = i.get("worker") or {}
            if wk.get("now") in ("EXITED-UNREAPED", "GONE-PID-REUSED"):
                why = "next sweep reaps it" if wk["now"] == "EXITED-UNREAPED" else "pid now belongs to another process; awaiting reap"
                ok_ = wk.get("out_kind")
                out.append(lk.T((f"{lk.G['ring']} {wk['now'][:4]} ", lk.S("watch", bold=True)), (f"pid {wk['pid']}  ", lk.S("muted")),
                                (i["id"], lk.S("text")), (f"  {why}", lk.S("muted")),
                                (f"  out {ok_}" if ok_ else "", lk.S("act" if ok_ == "api-error" else "muted"))))
        for o in ll.get("orphans") or []:
            out.append(lk.T(("! ORPHAN ", lk.S("act", bold=True)), (f"pid {o['pid']}  ", lk.S("act")), (o["iid"], lk.S("act", bold=True)),
                            (f"  up {g._dur(o['etime'])}" if o.get("etime") is not None else "", lk.S("muted")),
                            ("  RESCUE_ITEM worker not in the ledger", lk.S("act"))))
            if o.get("cmd"):
                out.append(lk.T(("    ", ""), (o["cmd"], lk.S("muted"))))
        for o in ll.get("sandbox_procs") or []:
            out.append(lk.T((f"{lk.G['ring']} SANDBOX ", lk.S("watch", bold=True)), (f"pid {o['pid']}  ", lk.S("muted")),
                            (o["iid"], lk.S("text")),
                            (f"  up {g._dur(o['etime'])}" if o.get("etime") is not None else "", lk.S("muted")),
                            ("  container plumbing the lane left running (podman ps)", lk.S("muted"))))
            if o.get("cmd"):
                out.append(lk.T(("    ", ""), (o["cmd"], lk.S("muted"))))
        if not out:
            out.append(lk.T((lk.G["ring"] + " no rescue worker is running", lk.S("muted"))))
            out.append(lk.T(("  gate: ", lk.S("muted")), (ll.get("gate") or "-", lk.S("text"))))
        return out

    def p_health(self, lk, snap, w, t):
        ll = snap["data"].get("leadlab")
        if not ll:
            return [lk.T(("loading...", lk.S("muted")))]
        sp = snap["data"].get("sweepproc") or {}
        out = self.err(lk, snap, "sweepproc")
        hw = ll["health"]
        out.append(lk.T(lk.chip(hw, HEALTH_LEVEL[hw]), (f"  open {ll['open_n']}  stale>7d {ll['stale_n']}  active {ll['active_n']}"
                                                         f"  ~{ll['days_to_clear']}d to clear", lk.S("text", bold=True))))
        total = sum(ll["counts"].values()) or 1
        lw = max((len(k) for k in ll["counts"]), default=8) + 1
        for label, n in sorted(ll["counts"].items(), key=lambda kv: (ORDER_RANK.get(kv[0].split("(")[0], 5), kv[0])):
            lv = STATE_LEVEL.get(label.split("(")[0], "muted")
            out.append(lk.T((f"  {label:<{lw}}", lk.S("text")), (f"{n:>3} ", lk.S(lv, bold=True)), lk.bar(n / total, max(4, w - lw - 8), lv)))
        cap_lv = "watch" if ll["used_today"] >= ll["cap"] else "ok"
        out.append(lk.T(("cap  ", lk.S("muted")), (f"{ll['used_today']}/{ll['cap']} today", lk.S(cap_lv, bold=True)),
                        (("  " + " ".join(x[11:16] + "Z" for x in ll["dispatch_today"])) if ll["dispatch_today"] else "", lk.S("muted"))))
        out.append(lk.T(("armed ", lk.S("muted")), ("yes" if ll["armed"] else "no", lk.S("ok" if ll["armed"] else "watch", bold=True)),
                        ("   STOP ", lk.S("muted")), ("SET" if ll["stop"] else "clear", lk.S("act" if ll["stop"] else "ok", bold=True))))
        out.append(lk.T(("gate ", lk.S("muted")), (ll["gate"], lk.S("text"))))
        ls = g._ts(ll.get("last_sweep"))
        out.append(lk.T(("last sweep ", lk.S("muted")), (f"{ll.get('last_sweep') or 'never'}", lk.S("text")),
                        (f"  {d._ago(ls)}" if ls else "", lk.S("muted")), ("  DRY" if ll.get("last_sweep_dry") else "  live", lk.S("watch" if ll.get("last_sweep_dry") else "muted")),
                        (f"  next {snap.get('next_sweep')}" if snap.get("next_sweep") else "", lk.S("text"))))
        age = ll.get("ledger_age_s")
        late = age is not None and age > 5 * 3600
        out.append(lk.T(("ledger age ", lk.S("muted")), (g._dur(age) if age is not None else "?", lk.S("act" if late else "text", bold=late)),
                        ("  sweep overdue for a 4 h cron" if late else "", lk.S("act"))))
        for name in ("pipeline-sweep", "orch-bot", "oss-bot"):
            r = sp.get(name)
            if not r:
                continue
            extra = f"  cron {r['cron_restart']}" if r.get("cron_restart") else ""
            out.append(lk.T((f"  {name:<15}", lk.S("text")), (r.get("word", "?"), lk.S(r.get("level", "muted"), bold=True)),
                            (f"{extra}  restarts {r.get('restart_time', '?')}", lk.S("muted"))))
        return out

    def p_activity(self, lk, snap, w, t):
        ll = snap["data"].get("leadlab")
        if not ll:
            return [lk.T(("loading...", lk.S("muted")))]
        out = []
        for r in ll.get("rescue_outcomes") or []:
            v = str(r.get("verdict", "?"))
            out.append(lk.T((f"{str(r.get('ts', ''))[5:16].replace('T', ' ')}Z ", lk.S("muted")),
                            (midcut(str(r.get("lane", ""))[len("rescue-"):], 40, lk.uni) + " ", lk.S("text")),
                            (f"{v[:10]:<11}", lk.S(d.VERDICT_LEVEL.get(v, "muted"), bold=True)),
                            (f"p{r.get('probes', 0)} {'burst' if r.get('burst') else '-'} ", lk.S("muted")),
                            (redact(r.get("notes") or "")[:120], lk.S("faint"))))
        return out or [lk.T(("no rescue outcome recorded yet", lk.S("muted")))]

    def builders(self):
        return {"leads": self.p_leads, "live": self.p_live, "health": self.p_health, "activity": self.p_activity}

    def subtitle(self, key, snap):
        ll = snap["data"].get("leadlab") or {}
        return {"leads": f"{len(ll.get('items') or [])} in ledger", "health": ll.get("health") or "",
                "live": f"{sum(1 for i in ll.get('items') or [] if (i.get('worker') or {}).get('now') == 'RUNNING')} running",
                "activity": "outcomes.jsonl rescue-*"}.get(key, "")

    def header(self, lk, snap, width, t, hidden, zoom):
        ll = snap["data"].get("leadlab") or {}
        left = lk.T(" ", lk.small_mark(t), "  ", lk.chip("LEAD LAB", "info"), (f" {lk.G['sep']} technical", lk.S("info")))
        right = lk.T(d.clock_ribbon(lk, snap, t, compact=width < 110), " ")
        top = lk.T(left, " " * max(1, width - left.cell_len - right.cell_len), right)
        chips = []
        if ll.get("health"):
            chips += [lk.chip(ll["health"], HEALTH_LEVEL[ll["health"]]), " "]
        nrun = sum(1 for i in ll.get("items") or [] if (i.get("worker") or {}).get("now") == "RUNNING")
        chips += [lk.chip(f"{nrun} RUNNING", "ok" if nrun else "muted"), " "]
        chips += [lk.chip("DISPATCH armed" if ll.get("armed") else "DISPATCH off", "info" if ll.get("armed") else "muted"), " "]
        if ll.get("orphans"):
            chips += [lk.chip(f"{len(ll['orphans'])} ORPHAN", "act"), " "]
        if snap["demo"]:
            chips += [lk.chip("DEMO", "hilite"), " "]
        fl = self.app.flash_text()
        if fl:
            chips += [lk.chip(f"{lk.G['star']} {fl}", "act"), " "]
        sub = lk.T(" ", *chips, ("  ", ""), d.uptime_ribbon(lk, snap))
        tabs = lk.Text(no_wrap=True)
        tabs.append(" ")
        for i, (key, title, level, _) in enumerate(self.PANELS, 1):
            st = lk.S(level, bold=True, reverse=True) if zoom == i else lk.S("faint") if key in hidden else lk.S("text")
            tabs.append(f" {i} ", style=lk.S("info", bold=True) if zoom != i else st)
            tabs.append(self.TABS[key] + " ", style=st)
        tip = "0/Esc back  PgUp/PgDn scroll" if zoom else ("hidden: " + " ".join(str(i) for i, (k, *_r) in enumerate(self.PANELS, 1) if k in hidden)
                                                          + "  press its number" if hidden else "1-4 zoom a panel")
        tabs.append("  " + tip, style=lk.S("muted", italic=True))
        return [lk.lines(x, width)[0] for x in (top, sub, tabs)] + [lk.lines(lk.scan_rule(t, width), width)[0]]

    def grid(self, lk, snap, width, height, t):
        """LEADS full width on top; the other panels in a row (or stacked) below; LEADS takes what is left."""
        cols = 3 if width >= 150 else 2 if width >= 100 else 1
        min_h = 5
        bl = self.builders()
        rest = list(self.PANELS[1:])
        rows = [rest[k:k + cols] for k in range(0, len(rest), cols)]
        idx = {key: i for i, (key, *_r) in enumerate(self.PANELS, 1)}
        self.room = 10
        built = []
        for row in rows:
            widths = [width // len(row) + (1 if i < width % len(row) else 0) for i in range(len(row))]
            built.append([(it, wd, bl[it[0]](lk, snap, wd - 4, t)) for it, wd in zip(row, widths)])
        dem = [max(min_h, min(14, max(len(b) + 2 for _, _, b in row))) for row in built]
        hidden = []
        leads_min = 8 if height >= 24 else 6
        while built and sum(dem) + leads_min > height:
            hidden += [it[0] for it, _, _ in built[-1]]
            built.pop()
            dem.pop()
        lh = max(3, height - sum(dem))
        self.room = max(1, lh - 2)
        out = lk.block("LEADS", bl["leads"](lk, snap, width - 4, t), width, lh, "info", self.subtitle("leads", snap), key="1")
        for row, rh in zip(built, dem):
            blocks = [lk.block(title, body, wd, rh, level, self.subtitle(key, snap), key=str(idx[key]), mode=mode)
                      for (key, title, level, mode), wd, body in row]
            out += d.hjoin(blocks, [wd for _, wd, _ in row])
        return (out + [""] * height)[:height], hidden

    def render(self, lk, snap, width, height, t):
        app = self.app
        zoom = app.zoom if 0 < app.zoom <= len(self.PANELS) else 0
        if zoom:
            key, title, level, mode = self.PANELS[zoom - 1]
            head = self.header(lk, snap, width, t, [], zoom)
            bh = height - len(head)
            inner = max(1, bh - 2)
            self.room = inner
            ck = ("lzoom", id(lk), app.snap_key, width, height, zoom, app.sel, app.filt, app.prog_f, t // 3)
            body = app.cached("lead-zoom", ck, lambda: self.builders()[key](lk, snap, width - 4, t))
            maxs = max(0, len(body) - inner)
            app.zscroll = min(app.zscroll, maxs)
            start = 0 if key == "leads" else max(0, len(body) - inner - app.zscroll) if mode == "tail" else app.zscroll
            view = body[start:start + inner]
            sub = f"rows {start + 1}-{start + len(view)} of {len(body)}" if len(body) > inner else self.subtitle(key, snap)
            blk = lk.lines(lk.frame(title, view, width, bh, level, sub, kind="double", key=str(zoom)), width)[:bh]
            return (head + blk + [""] * height)[:height]
        key = ("ltech", id(lk), app.snap_key, width, height, app.sel, app.filt, app.prog_f, t // 2)
        body, hidden = app.cached("lead-grid", key, lambda: self.grid(lk, snap, width, height - 4, t))
        head = self.header(lk, snap, width, t, hidden, 0)
        return (head + body + [""] * height)[:height]


# ======================================================================================================
# app
# ======================================================================================================

class LeadApp(d.App):
    def __init__(self, view=None, theme=None, demo=None, caps=None, persist=True):
        super().__init__(view, theme, demo, caps, persist)
        self.feed = LeadFeed()
        self.simple = LeadSimple(self)
        self.tech = LeadTech(self)
        self.sel = 0
        self.drill = None
        self.dscroll = 0
        self.filt = 0
        self.prog_f = 0

    def snapshot(self):
        key = (self.demo, int(time.time() / 1.5))
        if self.snap is None or (key != self.snap_key and self.feed.ver != self.snap["ver"]) or key[0] != self.snap_key[0]:
            self.snap = build_lead_snapshot(self.feed, self.demo, self.scrub if self.demo else None)
            if self.demo:
                self.snap["_scrub"] = self.scrub
            self.snap_key = key
            items = (self.snap["data"].get("leadlab") or {}).get("items") or []
            n = sum(1 for i in items if (i.get("worker") or {}).get("now") == "RUNNING")
            if self.prev_hv is not None and n > self.prev_hv:
                self.flash_until = time.time() + 6
                self.flash_msg = f"+{n - self.prev_hv} worker started"
            self.prev_hv = n
        return self.snap

    def drilldown(self, width, height, t):
        lk = self.look
        snap = self.snapshot()
        head = self.simple.header(lk, snap, width, t)
        bh = max(0, height - len(head))
        if bh < 3:
            return (head + [""] * height)[:height]
        segs = self.cached(("drill", self.drill), (self.drill, int(time.time() / 2), self.snap_key, self.demo),
                           lambda: drill_lines(self.drill, snap))
        lines = [_T(lk, s) for s in segs]
        inner = max(1, bh - 2)
        self.dscroll = max(0, min(self.dscroll, max(0, len(lines) - inner)))
        view = lines[self.dscroll:self.dscroll + inner]
        sub = (f"rows {self.dscroll + 1}-{self.dscroll + len(view)} of {len(lines)}  " if len(lines) > inner else "") + "Esc back"
        title = f"LEAD {midcut(self.drill, max(10, width - 40), lk.uni)}"
        blk = lk.lines(lk.frame(title, view, width, bh, "info", sub, kind="double"), width)[:bh]
        return (head + blk + [""] * height)[:height]

    def body(self, width, height, t):
        if self.drill:
            return self.drilldown(width, height, t)
        return super().body(width, height, t)

    def hints(self, width):
        lk = self.look
        cmds = ["!scripts/learn/pipeline-sweep.py list", "orch", "inbox", "dash", "help"]
        t = lk.Text(no_wrap=True, overflow="ellipsis" if lk.uni else "crop")
        t.append(f" {lk.G['arrow']} ", style=lk.S("info", bold=True))
        for i, cmd in enumerate(cmds):
            if i:
                t.append(f" {lk.G['sep']} ", style=lk.S("faint"))
            t.append(cmd, style=lk.S("text", bold=True))
        t.append("   arrows select | Enter open | Esc back | , filter | . program | Tab view", style=lk.S("muted"))
        if self.note:
            t.append(f"   {self.note}", style=lk.S("hilite"))
        return lk.lines(t, width)[0]

    def submit_line(self, run_fullscreen):
        line = self.box["buf"].strip()
        if line in ("help", "?"):
            self.box["buf"], self.box["cur"] = "", 0
            self.box["out"] = [g.bold("gnoc> help")] + __doc__.strip().splitlines() + [""] + g.__doc__.strip().splitlines()
            self.box["scroll"] = len(self.box["out"])
            return True
        return super().submit_line(run_fullscreen)

    def _move(self, delta):
        if self.drill:
            self.dscroll = max(0, self.dscroll + delta)
            return
        snap = self.snapshot()
        items, *_ = filtered(self, snap)
        self.sel = max(0, min(len(items) - 1, self.sel + delta)) if items else 0

    def _toggle_drill(self):
        if self.drill:
            self.drill, self.dscroll = None, 0
            return
        items, *_ = filtered(self, self.snapshot())
        if items:
            self.drill, self.dscroll = items[min(self.sel, len(items) - 1)]["id"], 0

    @staticmethod
    def _tokens(data):
        i = 0
        while i < len(data):
            if data[i] == "\x1b":
                if data[i:i + 4] in ("\x1b[5~", "\x1b[6~"):
                    yield data[i:i + 4]
                    i += 4
                    continue
                seq = data[i:i + 3]
                if len(seq) == 3 and seq[1] in "[O":
                    yield seq
                    i += 3
                    continue
                yield "\x1b"
                i += 1
                continue
            yield data[i]
            i += 1

    def handle(self, data, run_fullscreen, term_h):
        for tok in self._tokens(data):
            empty = not self.box["buf"]
            if tok == "\x10":
                tok = "\x1b[A"  # Ctrl-P: history back (the arrows select leads while the box is empty)
            elif tok == "\x0e":
                tok = "\x1b[B"  # Ctrl-N: history forward
            elif empty and tok in ("\x1b[A", "\x1b[B"):
                self._move(-1 if tok[2] == "A" else 1)
                continue
            elif empty and tok in ("\r", "\n"):
                self._toggle_drill()
                continue
            elif tok == "\x1b" and self.drill:
                self.drill, self.dscroll = None, 0
                continue
            elif tok in ("\x1b[5~", "\x1b[6~") and self.drill and not self.box["out"]:
                step = max(1, term_h // 3 - 2)
                self.dscroll = max(0, self.dscroll + (-step if tok[2] == "5" else step))
                continue
            elif empty and tok == ",":
                self.filt, self.sel = self.filt + 1, 0
                continue
            elif empty and tok == ".":
                self.prog_f, self.sel = self.prog_f + 1, 0
                continue
            elif empty and tok.isdigit() and (self.drill or self.view != "technical" or int(tok) > len(self.tech.PANELS)):
                continue
            if not super().handle(tok, run_fullscreen, term_h):
                return False
        return True


# ======================================================================================================
# CLI (mirrors gnoc-dashboard.py main)
# ======================================================================================================

def main(argv):
    def opt(name, default=None):
        if name in argv:
            i = argv.index(name)
            return argv[i + 1] if i + 1 < len(argv) else default
        return default

    if any(a in ("-h", "--help", "help") for a in argv):
        print(__doc__)
        return 0
    view, theme = opt("--view"), opt("--theme")
    if view and view not in d.VIEWS or theme and theme not in d.THEMES:
        print(f"--view is one of {', '.join(d.VIEWS)}; --theme is one of {', '.join(d.THEMES)}", file=sys.stderr)
        return 2
    demo = True if "--demo" in argv else None
    if "--snapshot" in argv:
        app = LeadApp(view, theme, demo, persist=False)
        app.feed.once(4.0)
        snap = {k: v for k, v in app.snapshot().items() if not k.startswith("_")}
        json.dump(snap, sys.stdout, indent=1, default=str)
        print()
        return 0
    if "--once" in argv or not (sys.stdin.isatty() and sys.__stdout__.isatty()):
        import shutil
        size = opt("--size")
        if size:
            width, height = (int(v) for v in size.lower().split("x"))
        else:
            ts = shutil.get_terminal_size((120, 40))
            width, height = ts.columns, ts.lines
        app = LeadApp(view, theme, demo, persist=False)
        app.drill = opt("--drill")
        if app.drill:  # a printed frame cannot scroll: grow it to the whole drill-down (header 3 + frame 2 + box 4)
            app.feed.once(4.0)
            height = max(height, len(drill_lines(app.drill, app.snapshot())) + 9)
        rows = d.render_once(app, width, height, t=int(opt("--t", "0")))
        sys.stdout.write("\n".join(rows) + "\033[0m\n")
        return 0
    LeadApp(view, theme, demo, persist=os.environ.get("GNOC_DASH_NOPERSIST") != "1").run(fps=int(opt("--fps", "10")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
