#!/usr/bin/env python3
"""gnoc chair - the captain's chair: a one-screen helm for the orch bot, with levers and buttons.

    gnoc chair            the live helm (keys below; every action shows its real result in the BRIDGE LOG)
    gnoc chair --once     one frame, no input (for a pipe or a screenshot)

What it drives is the same machinery the CLI drives, by calling the same commands, so nothing here can drift from
`gnoc orch ...`, `gnoc models ...`, `gnoc stop|resume`, `gnoc pivot`, `gnoc gate`, `bot.py pause|resume`:

  LEVERS   [-] [+]  tick speed 1-5      .claude/state/orch/office-intensity (orch-bot: 120 / 90 / 60 / 35 / 20 s per tick)
           [a]      auto mode           off <-> target (bot picks the program);  [P] pin a program by name
           [b]      brain               on/off: the local-model decision layer (off = orch-bot's fixed rules only)
           [m]      brain model         pick any model on the laptop or the desktop Ollama (gnoc models use brain ...)
           [o]      oss-bot scanner     pause/resume (bot.py pause|resume; its own PAUSE file, not the global STOP)
           [g]      final gate          claude <-> human (who runs the kill pass + repro check before READY)
  BUTTONS  [SPACE]  ALL STOP / RESUME   the global STOP flag (halts orch-bot, oss-bot, fleet workers, hunt loops);
                                        press twice within 4 s to stop, once to resume
           [p]      pivot               park the current program, the bot picks the next best (press twice)
           [k]      kill lane           stop the running OpenCode lane driver (press twice; with several, pick one first)
           [t] [r]  triage / review     run the oss-bot lead triage or the secret review right now
           [w] [l] [i]                  brain decisions (why) / orch log / bot inbox, into the BRIDGE LOG
           [c]  clear the log        [q] or Esc  leave the chair      PgUp/PgDn  scroll the BRIDGE LOG
Not a lever, on purpose: report filing. AUTO-SUBMIT is shown read-only; filing stays one-tap with you (gnoc approve).
Every action is appended to .claude/state/orch/changes.jsonl as kind CHAIR (the OUTCOMES panel in gnoc watch shows it).
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import re
import select
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_ld = importlib.machinery.SourceFileLoader("gnoc_mod", os.path.join(WS, "scripts/gnoc"))
_spec = importlib.util.spec_from_loader("gnoc_mod", _ld)
g = importlib.util.module_from_spec(_spec)
_ld.exec_module(g)

ORCH = g.ORCH_DIR
INTENSITY = os.path.join(ORCH, "office-intensity")
TICKS = {1: 120, 2: 90, 3: 60, 4: 35, 5: 20}  # mirrors orch-bot.py TICK_BY_INTENSITY
OSS_PAUSE = os.path.join(WS, ".claude/state/oss-bot/PAUSE")
GNOC = [sys.executable, os.path.join(WS, "scripts/gnoc")]
PY = sys.executable
MOUSE_RE = re.compile(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])")  # SGR mouse report: button;col;row;(M=press, m=release)


def when(ts):
    """Local HH:MM for today, MM-DD for an earlier day (same rule as gnoc dash)."""
    d = datetime.fromtimestamp(ts).astimezone()
    return d.strftime("%H:%M") if d.date() == datetime.now().astimezone().date() else d.strftime("%m-%d")


def _read(path, default=""):
    try:
        return open(path, encoding="utf-8").read()
    except OSError:
        return default


def helm_state():
    """Chair-only facts the gnoc Feed does not carry (cheap local reads)."""
    try:
        level = max(1, min(5, int(_read(INTENSITY, "3").strip() or 3)))
    except ValueError:
        level = 3
    words = _read(os.path.join(ORCH, "AUTO-HUNT")).split()
    mode = "target" if "target" in words else ("pinned" if words else "off")
    focus = next((w for w in words if w != "target"), None)
    gate = (_read(os.path.join(ORCH, "FINAL-GATE")).strip() or "claude")
    roles = g._roles()
    return {"level": level, "tick": TICKS[level], "mode": mode, "focus": focus, "gate": gate, "roles": roles,
            "brain_on": os.path.isfile(os.path.join(ORCH, "BRAIN.enabled")),
            "oss_paused": os.path.exists(OSS_PAUSE),
            # harmony 2.5: an "INCIDENT " PAUSE is the scope-proxy audit latch; no lever clears it
            "oss_incident": (_read(OSS_PAUSE).strip() if _read(OSS_PAUSE).startswith("INCIDENT ") else None),
            "autosubmit": os.path.isfile(os.path.join(ORCH, "AUTO-SUBMIT-VDP.enabled")),
            "lanes": g.running_drivers()}


def model_options():
    """Every model on the laptop (11435) and the desktop (11440) Ollama, big enough to be a brain (>1.5 GB)."""
    out = []
    for host, url in (("laptop", g.OLLAMA), ("desktop", "http://" + g.DESKTOP_OLLAMA)):
        try:
            with urllib.request.urlopen(url + "/api/tags", timeout=3) as r:
                tags = json.loads(r.read().decode()).get("models") or []
        except Exception:
            continue
        for m in tags:
            size = (m.get("size") or 0) / 1e9
            if size >= 1.5:
                out.append((m["name"], host, size))
    return sorted(out, key=lambda x: (x[1] != "desktop", x[2]))


class Chair:
    def __init__(self):
        self.feed = g.Feed()
        self.lk = g.look()
        self.log = []          # BRIDGE LOG lines (plain text)
        self.busy = None
        self.confirm = None    # (key, until, label, action)
        self.picker = None     # {"title", "options": [(label, action)], "page"}
        self.lscroll = 0       # BRIDGE LOG rows scrolled up from the bottom (PgUp/PgDn)
        self.prompt = None     # {"label", "buf", "action"}
        self.hs = helm_state()
        self.hits = []              # [(y, x0, x1, key_char)] clickable regions, rebuilt every frame()
        self._button_hits = []      # scratch list p_buttons() fills in, row-relative (y within its own panel)

    # ----- actions -----
    def note(self, text):
        stamp = datetime.now().astimezone().strftime("%H:%M:%S")  # local, like every other on-screen gnoc time
        for i, ln in enumerate(str(text).splitlines() or [""]):
            self.log.append(f"{stamp if i == 0 else ' ' * len(stamp)}  {ln}")
        self.log = self.log[-500:]
        self.lscroll = 0  # new output snaps the BRIDGE LOG back to the bottom

    def run(self, label, argv, timeout=300):
        if self.busy:
            self.note(f"busy with: {self.busy} (wait for it)")
            return
        self.busy = label  # set before the thread starts, so a fast double key press cannot launch two commands

        def work():
            self.note(f"> {label}")
            g._log_change("chair", detail=label)
            try:
                r = subprocess.run(argv, cwd=WS, capture_output=True, text=True, timeout=timeout,
                                   stdin=subprocess.DEVNULL, env=dict(os.environ, GNOC_PLAIN="1"))
                text = g.ANSI_RE.sub("", (r.stdout + r.stderr).strip())
                lines = text.splitlines()
                if len(lines) > 60:  # keep the head too: a long report's first lines are usually the verdict
                    lines = lines[:10] + [f"... {len(lines) - 50} lines cut, full output: run it on the CLI ..."] + lines[-40:]
                self.note("\n".join(lines) if lines else "(no output)")
                if r.returncode:
                    self.note(f"[exit {r.returncode}]")
            except subprocess.TimeoutExpired:
                self.note(f"[timed out after {timeout}s]")
            self.busy = None
            self.hs = helm_state()
            self.feed.poke()
        threading.Thread(target=work, daemon=True).start()

    def set_level(self, d):
        # Deliberately bypasses self.run()'s busy-gate/thread: tick speed is the one lever meant for
        # rapid repeated taps (+/- chained to jump several steps), and self.run() silently drops any
        # action fired while a previous one is still in flight - fine for a slow one-shot like triage,
        # but it swallowed fast presses here and made the lever look stuck. Still calls the real CLI
        # command synchronously (same argv/env/log line as every other control), just not threaded.
        lv = max(1, min(5, self.hs["level"] + d))
        self.hs = dict(self.hs, level=lv, tick=TICKS[lv])
        label = f"tick speed -> {lv} ({TICKS[lv]}s/tick)"
        self.note(f"> {label}")
        g._log_change("chair", detail=label)
        try:
            r = subprocess.run(GNOC + ["orch", "speed", str(lv)], cwd=WS, capture_output=True, text=True,
                                timeout=10, stdin=subprocess.DEVNULL, env=dict(os.environ, GNOC_PLAIN="1"))
            if r.returncode:
                text = g.ANSI_RE.sub("", (r.stdout + r.stderr).strip())
                self.note("\n".join(text.splitlines()[-4:]) or f"[exit {r.returncode}]")
        except subprocess.TimeoutExpired:
            self.note("[tick speed write timed out]")
        self.hs = helm_state()

    def arm(self, key, label, action):
        """Two-press safety: the first press arms for 4 s, the second inside the window fires."""
        if self.confirm and self.confirm[0] == key and time.time() < self.confirm[1]:
            self.confirm = None
            action()
        else:
            self.confirm = (key, time.time() + 4, label, action)

    def open_model_picker(self):
        self.note("loading model lists from the laptop and desktop Ollama...")

        def load():
            opts = model_options()
            cur = self.hs["roles"].get("brain", "")
            choices = []
            for name, host, size in opts:
                want = f"{name}@desktop" if host == "desktop" else name
                mark = " (current)" if cur in (want, name if host == "laptop" else want) else ""
                argv = GNOC + ["models", "use", "brain", name] + (["--on", "desktop"] if host == "desktop" else [])
                short = name if len(name) <= 44 else name[:20] + "..." + name[-21:]
                choices.append((f"{short:<44} {host:<8} {size:5.1f} GB{mark}",
                                (lambda a=argv, n=want: self.run(f"brain model -> {n}", a))))
            self.picker = {"title": "BRAIN MODEL (number to pick, Esc to cancel)", "options": choices, "page": 0} \
                if choices else None
            if not choices:
                self.note("no models reachable on either Ollama")
        threading.Thread(target=load, daemon=True).start()

    def key(self, ch):
        hs = self.hs
        if self.prompt:
            p = self.prompt
            if ch in ("\r", "\n"):
                self.prompt = None
                if p["buf"].strip():
                    p["action"](p["buf"].strip())
            elif ch == "\x1b":
                self.prompt = None
            elif ch in ("\x7f", "\b"):
                p["buf"] = p["buf"][:-1]
            elif ch >= " ":
                p["buf"] += ch
            return True
        if self.picker:
            if ch == "\x1b":
                self.picker = None
            elif ch in ("n", "]"):
                self.picker["page"] += 1
            elif ch in ("[",):
                self.picker["page"] = max(0, self.picker["page"] - 1)
            elif ch.isdigit() and ch != "0":
                i = self.picker["page"] * 9 + int(ch) - 1
                opts = self.picker["options"]
                if i < len(opts):
                    self.picker = None
                    opts[i][1]()
            return True
        if ch in ("q", "\x1b", "\x04"):
            return False
        if ch == " ":
            if os.path.exists(os.path.join(g.STATE, "STOP")):
                self.run("ALL RESUME (clear STOP)", GNOC + ["resume"])
            else:
                self.arm(" ", "ALL STOP: press SPACE again", lambda: self.run("ALL STOP", GNOC + ["stop"]))
        elif ch in ("+", "="):
            self.set_level(+1)
        elif ch in ("-", "_"):
            self.set_level(-1)
        elif ch == "a":
            nxt = "off" if hs["mode"] in ("target", "pinned") else "target"
            self.run(f"auto mode -> {nxt}", GNOC + ["orch", "auto", nxt])
        elif ch == "P":
            self.prompt = {"label": "pin the hunt to program", "buf": "",
                           "action": lambda prog: self.run(f"auto mode -> pinned {prog}", GNOC + ["orch", "auto", prog])}
        elif ch == "b":
            self.run(f"brain -> {'off' if hs['brain_on'] else 'on'}", GNOC + ["orch", "brain", "off" if hs["brain_on"] else "on"])
        elif ch == "m":
            self.open_model_picker()
        elif ch == "o" and hs.get("oss_incident"):
            self.note("oss-bot is latched by a SCOPE INCIDENT, the chair will not clear it:\n  " + hs["oss_incident"][:160]
                      + "\n  read .claude/state/hunt-loop/SCOPE-INCIDENTS.md, then on the CLI: "
                      "gnoc oss resume --ack-incident")
        elif ch == "o":
            self.run(f"oss-bot -> {'resume' if hs['oss_paused'] else 'pause'}",
                     GNOC + ["oss", "resume" if hs["oss_paused"] else "pause"])
        elif ch == "g":
            nxt = "human" if hs["gate"] == "claude" else "claude"
            self.run(f"final gate -> {nxt}", GNOC + ["gate", nxt])
        elif ch == "p":
            self.arm("p", "PIVOT: press p again (park this program, bot picks the next)",
                     lambda: self.run("pivot (bot picks)", GNOC + ["pivot"], timeout=900))
        elif ch == "k":
            if not hs["lanes"]:
                self.note("no OpenCode lane is running")
            else:
                def arm_kill(pid, prog, lane):
                    self.arm("k", f"KILL LANE {prog}/{lane}: press k again",
                             lambda: self.run(f"kill lane {prog}/{lane}", GNOC + ["kill-lane", str(pid)]))
                if self.confirm and self.confirm[0] == "k" and time.time() < self.confirm[1]:
                    fire = self.confirm[3]  # second k inside the window fires the lane already chosen
                    self.confirm = None
                    fire()
                elif len(hs["lanes"]) == 1:
                    arm_kill(*hs["lanes"][0])
                else:  # several lanes: pick which one first, then the usual second k press confirms
                    self.picker = {"title": "KILL WHICH LANE (number, Esc to cancel)", "page": 0,
                                   "options": [(f"{prog}/{lane}  pid {pid}", (lambda a=(pid, prog, lane): arm_kill(*a)))
                                               for pid, prog, lane in hs["lanes"]]}
        elif ch == "t":
            self.run("triage now", GNOC + ["oss", "triage", "--apply"])
        elif ch == "r":
            self.run("review now", GNOC + ["oss", "review", "--max", "6"], timeout=600)
        elif ch == "w":
            self.run("brain why", GNOC + ["orch", "brain", "why", "4"])
        elif ch == "l":
            self.run("orch log", GNOC + ["orch", "log"])
        elif ch == "i":
            self.run("bot inbox", GNOC + ["orch", "inbox"])
        elif ch == "c":
            self.log = []
        return True

    def click(self, x, y):
        """A plain left-button click at 1-based terminal (col, row). Replays the exact same key the
        clicked region is bound to through self.key(), so a click can never behave differently from
        its keyboard shortcut - same guarantee this file already gives every lever and button.
        Returns what self.key() returns (False = quit the chair, e.g. clicking LEAVE CHAIR), True
        on a miss, so the caller can honour it exactly like a typed key."""
        row = y - 1  # self.hits is built against the 0-based row list frame() returns
        hit = next(((y0, x0, x1, target) for y0, x0, x1, target in self.hits if y0 == row and x0 <= x - 1 < x1), None)
        if os.environ.get("CHAIR_DEBUG"):
            open(os.environ["CHAIR_DEBUG"], "a").write(f"click x={x} y={y} -> {hit}\n")
        return self.key(hit[3]) if hit else True

    # ----- drawing -----
    def seg(self, options, current, key):
        T = self.lk.T
        parts = []
        for o in options:
            on = o.lower() == str(current).lower()
            parts.append((f" {o} ", f"bold #052e16 on {g.C_OK}" if on else g.C_MUTED))
            parts.append((" ", ""))
        return T(*parts)

    def lever(self, keys, name, body):
        return self.lk.T((f"{keys:<7}", f"bold {g.C_ACC}"), (f"{name:<13}", f"bold {g.C_TEXT}"), body)

    def p_helm(self, w):
        T, hs, f = self.lk.T, self.hs, self.feed.data
        h, b, s = f.get("hunt") or {}, f.get("brain") or {}, f.get("system") or {}
        out = [T(("focus  ", g.C_MUTED), (hs["focus"] or h.get("focus") or "none", f"bold {g.C_ACC}"),
                 (f"   {hs['mode']}", g.C_MUTED))]
        cur = h.get("cur")
        if cur and h.get("alive"):
            el = g._dur(time.time() - h["cur_start"]) if h.get("cur_start") else ""
            qt = h.get("quiet")
            out.append(T(("job    ", g.C_MUTED), (f"{cur.get('program')}/{cur.get('lane')}"[:w - 20], g.C_TEXT), (f"  {el}", g.C_MUTED),
                         (f"  quiet {g._dur(qt)}" if qt and qt > 600 else "", f"bold {g.C_WARN}")))
        else:
            out.append(T(("job    ", g.C_MUTED), ("idle", g.C_MUTED)))
        out.append(T(("queue  ", g.C_MUTED), (str(h.get("queue", 0)), f"bold {g.C_TEXT}"),
                     ("   bot tick ", g.C_MUTED), (f"{g._dur(h['hb_age'])} ago" if h.get("hb_age") is not None else "?",
                                                   g.C_BAD if (h.get("hb_age") or 0) > 300 else g.C_TEXT)))
        last = (b.get("rows") or [{}])[-1]
        out.append(T(("brain  ", g.C_MUTED), (f"{last.get('action', '-')} {last.get('status', '')}", g.C_TEXT),
                     (f"  {when(g._ts(last.get('ts')))}" if g._ts(last.get("ts")) else "", g.C_MUTED)))
        out.append(T(("model  ", g.C_MUTED), (hs["roles"].get("brain", "?"), f"bold {g.C_VIO}"),
                     ("   hunter ", g.C_MUTED), (hs["roles"].get("hunter", "?"), g.C_TEXT)))
        gl = s.get("glock")
        out.append(T(("lock   ", g.C_MUTED), (gl or "none", g.C_BAD if s.get("glock_policy") == "BANNED" else g.C_TEXT),
                     ("   lanes ", g.C_MUTED), (str(len(hs["lanes"])), g.C_TEXT)))
        return out

    def p_levers(self, w):
        hs = self.hs
        ticks = self.lk.T(*sum(([(f" {i} ", f"bold #052e16 on {g.C_OK}" if i == hs['level'] else g.C_MUTED), (" ", "")]
                               for i in range(1, 6)), []), (f" {hs['tick']}s/tick", g.C_TEXT))
        o = self.feed.data.get("oss") or {}
        ost = "INCIDENT" if hs.get("oss_incident") else "PAUSED" if hs["oss_paused"] else ("DRY" if o.get("dry") else "LIVE")
        return [self.lever("[-][+]", "TICK SPEED", ticks),
                self.lever("[a][P]", "AUTO MODE", self.seg(["OFF", "TARGET", "PINNED"], hs["mode"], "a")),
                self.lever("[b]", "BRAIN", self.seg(["OFF", "ON"], "ON" if hs["brain_on"] else "OFF", "b")),
                self.lever("[m]", "BRAIN MODEL", self.lk.T((" " + hs["roles"].get("brain", "?"), f"bold {g.C_VIO}"), ("  press m to change", g.C_MUTED))),
                self.lever("[o]", "OSS-BOT", self.seg(["LIVE", "PAUSED"] + (["INCIDENT"] if ost == "INCIDENT" else []), ost, "o")),
                self.lever("[g]", "FINAL GATE", self.seg(["CLAUDE", "HUMAN"], hs["gate"], "g"))]

    def p_buttons(self, w):
        T = self.lk.T
        self._button_hits = []  # [(row-within-this-panel, x0, x1, key)], translated to screen coords by frame()
        if self.prompt:
            return [T((f"{self.prompt['label']}: ", f"bold {g.C_ACC}"), (self.prompt["buf"] + "_", g.C_TEXT)),
                    T(("Enter to confirm, Esc to cancel", g.C_MUTED))]
        if self.picker:
            opts, pg = self.picker["options"], self.picker["page"]
            pg = min(pg, max(0, (len(opts) - 1) // 9))
            self.picker["page"] = pg
            title = self.picker["title"]
            prefix = f"   page {pg + 1}/{(len(opts) + 8) // 9}  "
            nav_next, gap, nav_prev = "] next", "  ", "[ prev"
            rows = [T((title, f"bold {g.C_ACC}"), (prefix, g.C_MUTED), (nav_next, g.C_MUTED), (gap, g.C_MUTED),
                     (nav_prev, g.C_MUTED))]
            x0 = len(title) + len(prefix)
            self._button_hits.append((0, x0, x0 + len(nav_next), "]"))
            x0 += len(nav_next) + len(gap)
            self._button_hits.append((0, x0, x0 + len(nav_prev), "["))
            for i, (label, _) in enumerate(opts[pg * 9:pg * 9 + 9], 1):
                rows.append(T((f" {i} ", f"bold {g.C_ACC}"), (label[:w - 6], g.C_TEXT)))
                self._button_hits.append((i, 0, w, str(i)))  # whole row clickable, not just the digit cell
            return rows
        armed = self.confirm and time.time() < self.confirm[1]
        stop = os.path.exists(os.path.join(g.STATE, "STOP"))

        def btn(k, label, danger=False):
            hot = armed and self.confirm[0] == k
            style = f"bold #fff1f2 on #b91c1c" if hot else (f"bold {g.C_BAD}" if danger else f"bold {g.C_TEXT}")
            return [(f"[{'SPACE' if k == ' ' else k}]", f"bold {g.C_ACC}"), (f" {label} ", style), ("   ", "")]
        allb = [btn(" ", "RESUME ALL" if stop else "ALL STOP", danger=not stop), btn("p", "PIVOT"), btn("k", "KILL LANE", True),
                btn("t", "TRIAGE NOW"), btn("r", "REVIEW NOW"), btn("w", "BRAIN WHY"), btn("l", "ORCH LOG"),
                btn("i", "BOT INBOX"), btn("c", "CLEAR LOG"), btn("q", "LEAVE CHAIR")]
        allk = [" ", "p", "k", "t", "r", "w", "l", "i", "c", "q"]  # same order as allb, for hit-mapping
        rows, cur, curk, used = [], [], [], 0
        for b, k in zip(allb, allk):  # flow the buttons into as many rows as the width needs
            n = sum(len(p[0]) for p in b)
            if cur and used + n > w:
                rows.append(T(*sum(cur, [])))
                x = 0
                for seg, kk in curk:
                    self._button_hits.append((len(rows) - 1, x, x + seg, kk))
                    x += seg
                cur, curk, used = [], [], 0
            cur.append(b)
            curk.append((n, k))
            used += n
        if cur:
            rows.append(T(*sum(cur, [])))
            x = 0
            for seg, kk in curk:
                self._button_hits.append((len(rows) - 1, x, x + seg, kk))
                x += seg
        if armed:
            rows.append(T(("ARMED: ", f"bold {g.C_BAD}"), (self.confirm[2], f"bold {g.C_WARN}"),
                          (f"  ({self.confirm[1] - time.time():.0f}s)", g.C_MUTED)))
        else:
            rows.append(T(("two-press safety on STOP, PIVOT, KILL; filing is not a button (gnoc approve)", g.C_FAINT)))
        return rows

    def p_log(self, w, n):
        T = self.lk.T
        self.lscroll = max(0, min(self.lscroll, len(self.log) - n))
        end = len(self.log) - self.lscroll
        lines = self.log[max(0, end - n):end] if self.log else ["(each action's real output appears here)"]
        out = [T((ln[:w], g.C_TEXT if not ln.startswith("(") else g.C_MUTED)) for ln in lines]
        if self.busy:
            out.append(T(("◐ running: ", f"bold {g.C_WARN}"), (self.busy, g.C_TEXT)))
        return out

    def log_sub(self, n):
        if len(self.log) <= n:
            return "your commands"
        end = len(self.log) - self.lscroll
        return f"{max(1, end - n + 1)}-{end}/{len(self.log)} PgUp/PgDn"

    def p_deck(self, w):
        T, f, hs = self.lk.T, self.feed.data, self.hs
        o, ib, rp, sv, m = f.get("oss") or {}, f.get("inbox") or {}, f.get("reports") or {}, f.get("services") or {}, f.get("metrics") or {}
        rv = o.get("review") or {}
        procs = sv.get("pm2", [])
        on = sum(1 for p in procs if p[1] == "online")
        heat = lambda v: g.C_BAD if (v or 0) >= 90 else g.C_WARN if (v or 0) >= 75 else g.C_TEXT  # noqa: E731
        return [T(("leads  ", g.C_MUTED), (f"{o.get('open', '?')} open", f"bold {g.C_WARN if o.get('open') else g.C_OK}"),
                  ("  live? ", g.C_MUTED), (str(rv.get("live_open", 0)), f"bold {g.C_BAD if rv.get('live_open') else g.C_TEXT}")),
                T(("reports", g.C_MUTED), (f" READY {rp.get('ready', '?')}", f"bold {g.C_OK}"), (f"  HELD {rp.get('held', '?')}", g.C_WARN)),
                T(("inbox  ", g.C_MUTED), (f"{ib.get('unread', '?')} unread", g.C_TEXT), (f" ({ib.get('distinct', '?')} distinct)", g.C_MUTED)),
                T(("pm2    ", g.C_MUTED), (f"{on}/{len(procs)} online", f"bold {g.C_OK if on == len(procs) else g.C_WARN}")),
                T(("host   ", g.C_MUTED), (f"cpu {m.get('cpu', 0):.0f}%", heat(m.get("cpu"))), (f"  ram {m.get('ram', 0):.0f}%", heat(m.get("ram")))),
                T(("filing ", g.C_MUTED), ("AUTO-SUBMIT " + ("ON" if hs["autosubmit"] else "off"), g.C_WARN if hs["autosubmit"] else g.C_MUTED),
                  ("  (read-only)", g.C_FAINT))]

    def _lever_hits(self, panel_start, x0, w):
        """One representative key per lever row, same order as p_levers(). A click anywhere on a
        lever's row fires the same single-key action its label already documents - exact same
        'click can never drift from the CLI' guarantee the rest of this file gives every control."""
        for i, k in enumerate(["+", "a", "b", "m", "o", "g"]):
            self.hits.append((panel_start + 1 + i, x0, x0 + w, k))

    def frame(self, width, height, t):
        lk = self.lk
        self.hits = []
        if t % 12 == 0:
            self.hs = helm_state()
        now = datetime.now().astimezone()
        left = lk.T(" ", lk.small_mark(t), ("   CAPTAIN'S CHAIR", f"bold {g.C_ACC}"))
        right = lk.T((now.strftime("%H:%M:%S %Z"), f"bold {g.C_ACC}"), " ")
        top = lk.T(left, " " * max(1, width - left.cell_len - right.cell_len), right)
        rows = [lk.lines(top, width)[0], lk.lines(lk.T(" ", lk.chips(self.feed, compact=width < 100)), width)[0],
                lk.lines(lk.rule(t, width), width)[0]]
        if width >= 110:  # side by side
            lw = max(40, width * 9 // 20)
            rw = width - lw
            helm = self.p_helm(lw - 4)
            levers = self.p_levers(rw - 4)
            hh = max(len(helm), len(levers)) + 2
            panel_start = len(rows)
            rows += self.hjoin([lk.panel("HELM", helm, lw, hh, g.C_ACC), lk.panel("LEVERS", levers, rw, hh, g.C_VIO)], [lw, rw], hh)
            self._lever_hits(panel_start, lw + 2, rw - 4)
        else:  # narrow terminal: stack them, the levers need the full width to show every position
            levers = self.p_levers(width - 4)
            panel_start = len(rows)
            rows += self.hjoin([lk.panel("LEVERS", levers, width, len(levers) + 2, g.C_VIO)], [width], len(levers) + 2)
            self._lever_hits(panel_start, 2, width - 4)
            # HELM gets only what is left after BUTTONS and a readable BRIDGE LOG (8 rows): at 80x24 a full HELM
            # pushed the log, where every action reports its result, off the bottom of the screen
            need_below = len(self.p_buttons(width - 4)) + 2 + 8
            n = min(len(self.p_helm(width - 4)), height - len(rows) - need_below - 2)
            if n >= 2:
                helm = self.p_helm(width - 4)[:n]
                rows += self.hjoin([lk.panel("HELM", helm, width, len(helm) + 2, g.C_ACC)], [width], len(helm) + 2)
        btn = self.p_buttons(width - 4)
        bh = len(btn) + 2
        title = "PICK" if self.picker else ("INPUT" if self.prompt else "BUTTONS")
        panel_start = len(rows)
        rows += self.hjoin([lk.panel(title, btn, width, bh, g.C_WARN)], [width], bh)
        for row_i, x0, x1, key in self._button_hits:
            self.hits.append((panel_start + 1 + row_i, x0 + 2, x1 + 2, key))
        rest = max(6, height - len(rows))
        dw = max(34, width // 3)
        logw = width - dw
        rows += self.hjoin([lk.panel("BRIDGE LOG", self.p_log(logw - 4, rest - 2 - (1 if self.busy else 0)), logw, rest, g.C_BLUE, self.log_sub(rest - 2)),
                            lk.panel("DECK", self.p_deck(dw - 4), dw, rest, g.C_OK)], [logw, dw], rest)
        return rows[:height]

    def hjoin(self, panels, widths, h):
        blocks = [self.lk.lines(p, w)[:h] for p, w in zip(panels, widths)]
        return ["".join(b[i] if i < len(b) else " " * widths[j] for j, b in enumerate(blocks)) for i in range(h)]

    # ----- loop -----
    def once(self):
        self.feed.once(budget=5.0)
        size = shutil.get_terminal_size((120, 40))
        sys.stdout.write("\n".join(self.frame(max(80, size.columns), max(24, size.lines), 0)) + "\033[0m\n")  # same floor as live()

    def live(self):
        import termios
        import tty
        # Read keys from a private dup of the tty and point fd 0 at /dev/null BEFORE the feed starts: its collectors
        # (pm2 jlist every 5 s) and our own subprocess.run actions inherit stdin, and a child holding the tty
        # swallowed the key (measured 2026-10-22: a single q quit the chair only 2 of 5 times). Same fix as gnoc dash.
        fd = os.dup(sys.stdin.fileno())
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
        self.feed.start()
        saved = termios.tcgetattr(fd)
        term = sys.__stdout__
        tty.setcbreak(fd)
        term.write("\033[?1049h\033[?25l\033[2J\033[?1000h\033[?1006h")  # + SGR mouse click reporting
        t = 0
        try:
            while True:
                size = shutil.get_terminal_size((120, 40))
                rows = self.frame(max(80, size.columns), max(24, size.lines), t)
                term.write("\033[?2026h\033[H" + "\033[K\n".join(rows) + "\033[K\033[0m\033[0J\033[?2026l")
                term.flush()
                r, _, _ = select.select([fd], [], [], 1 / 10)
                if r:
                    data = os.read(fd, 64).decode("utf-8", "ignore")
                    if os.environ.get("CHAIR_DEBUG"):
                        open(os.environ["CHAIR_DEBUG"], "a").write(repr(data) + "\n")
                    quit_clicked = False
                    for m in MOUSE_RE.finditer(data):
                        btn, mx, my, kind = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
                        if kind == "M" and btn == 0 and not self.click(mx, my):  # plain left press only
                            quit_clicked = True  # e.g. LEAVE CHAIR - honour it exactly like a typed 'q'
                    if quit_clicked:
                        return
                    data = MOUSE_RE.sub("", data)
                    page = max(1, size.lines // 3)
                    self.lscroll += page * (data.count("\x1b[5~") - data.count("\x1b[6~"))
                    self.lscroll = max(0, self.lscroll)
                    if data.startswith("\x1b[") or data.startswith("\x1bO"):
                        data = ""  # arrow / function keys are not bound; never read them as Esc + letters
                    for ch in data:
                        if not self.key(ch):
                            return
                if self.confirm and time.time() > self.confirm[1]:
                    self.confirm = None
                t += 1
        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            term.write("\033[?1006l\033[?1000l\033[0m\033[?25h\033[?1049l")
            term.flush()


def main(a):
    if "-h" in a or "--help" in a:
        print(__doc__)
        return 0
    os.environ.setdefault("GNOC_FORCE_COLOR", "1")
    ch = Chair()
    if "--test-click" in a:  # offline: render one frame at a given size, resolve a click, print the hit - no tty needed
        i = a.index("--test-click")
        x, y = int(a[i + 1]), int(a[i + 2])
        size = shutil.get_terminal_size((140, 40))
        w = int(a[i + 3]) if len(a) > i + 3 else size.columns
        h = int(a[i + 4]) if len(a) > i + 4 else size.lines
        ch.feed.once(budget=3.0)
        ch.frame(max(80, w), max(24, h), 0)
        row = y - 1
        hit = next(((y0, x0, x1, t) for y0, x0, x1, t in ch.hits if y0 == row and x0 <= x - 1 < x1), None)
        print(f"frame {w}x{h}, click ({x},{y}) -> {hit}")
        return 0 if hit else 1
    if "--once" in a or not (sys.stdin.isatty() and sys.stdout.isatty()):
        ch.once()
        return 0
    ch.live()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
