#!/usr/bin/env python3
"""gnoc_schedule.py - scheduled tasks: a prompt the user saves with a cron schedule, run unattended.

The user sets one in the chat, from a line typed at the prompt (never a model, a tool or a pasted pipe):

    /schedule add "<cron>" <prompt> [--deliver telegram|desktop|file]
    /schedule list                 what is scheduled, and what each was saved with
    /schedule rm <id>              remove its timer (or cron line) and its record
    /schedule run <id>             run it now, in the background

What the timer runs (and what a person can run by hand):

    gnoc schedule run <id>         python3 scripts/gnoc_schedule.py run <id>
    gnoc schedule list             python3 scripts/gnoc_schedule.py list

A run is NON-INTERACTIVE: a call that needs approval is held, listed in the delivery and never executed. It runs
with what was in force when the schedule was made (the scope, the folder, the permission rules, the effort and the
models), saved in the record and shown by /schedule list, so a later settings change does not change what an
existing schedule may do. The one exception is a deny rule added later: it applies too, because a scheduled run
must never be the one place a "never do this" rule does not reach.

Records live in ~/.gnoc/schedules/<id>.json (GNOC_HOME moves it; 0700 dir, 0600 files). Reports land in
~/.gnoc/schedules/out/<id>/<timestamp>.md (0600) every run; desktop and telegram are delivered in addition.
Backends: a systemd user timer, else a marked crontab line, else (Termux) a crontab line for crond.
"""
from __future__ import annotations

import contextlib
import datetime as _dt
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets as _secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

HERE = os.path.dirname(os.path.abspath(__file__))

ID_RX = re.compile(r"^[0-9a-f]{8}$")
DELIVERIES = ("file", "desktop", "telegram")
DEFAULT_WALL_S = 900          # a run that is still going after 15 minutes is stopped, not left to pile up
DEFAULT_TOKENS = 200_000      # estimated (chars / 4) over every model call of one run
MARK = "# gnoc-schedule:"     # crontab marker; the defender's own line is "# gnoc-defender-schedule"
UNIT = "gnoc-schedule-"       # systemd unit name prefix
TELEGRAM_API = "https://api.telegram.org"
TELEGRAM_LIMIT = 3900         # Telegram's sendMessage takes 4096 characters; room for the "full report" line

Runner = Callable[..., Any]


# ------------------------------------------------------------------------------------------- where things live

def home(env=None) -> str:
    env = os.environ if env is None else env
    return env.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def sched_dir(env=None) -> str:
    return os.path.join(home(env), "schedules")


def out_dir(sid, env=None) -> str:
    return os.path.join(sched_dir(env), "out", sid)


def _private_dir(path):
    """A 0700 directory (and its schedules parents). A record holds a prompt and the rules it may act under."""
    os.makedirs(path, mode=0o700, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o700)


def _write_private(path, text, private_parent=True):
    if private_parent:
        _private_dir(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _rec_path(sid, env=None):
    return os.path.join(sched_dir(env), sid + ".json")


def load(sid, env=None) -> Optional[dict]:
    """The record for a well-formed id, or None. The id is checked first: it becomes a file name."""
    if not ID_RX.match(str(sid or "")):
        return None
    try:
        with open(_rec_path(sid, env), encoding="utf-8") as fh:
            rec = json.load(fh)
    except (OSError, ValueError):
        return None
    return rec if isinstance(rec, dict) and rec.get("id") == sid else None


def save(rec, env=None):
    _write_private(_rec_path(rec["id"], env), json.dumps(rec, indent=1, sort_keys=True) + "\n")


def records(env=None) -> list:
    d = sched_dir(env)
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return []
    out = []
    for n in names:
        if n.endswith(".json"):
            rec = load(n[:-5], env)
            if rec:
                out.append(rec)
    return sorted(out, key=lambda r: str(r.get("created_at") or ""))


# ------------------------------------------------------------------------------------------- cron -> OnCalendar

_FIELDS = (("minute", 0, 59), ("hour", 0, 23), ("day of month", 1, 31), ("month", 1, 12), ("weekday", 0, 7))
_MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
_DAYS = {d: i for i, d in enumerate("sun mon tue wed thu fri sat".split())}
_DAY_NAMES = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
_MACROS = {"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0",
           "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}


def _num(tok, name, names):
    t = tok.lower()
    if names and t in names:
        return names[t]
    if not t.isdigit():
        raise ValueError(f"{name}: {tok!r} is not a number")
    return int(t)


def _field(text, name, lo, hi, names):
    """Sorted values the field allows, or None for '*' (every value)."""
    if text == "*":
        return None
    top = 6 if name == "weekday" else hi   # '*' and 'n/step' over weekdays: 0-6, so Sunday is not counted twice
    vals: set = set()
    for part in text.split(","):
        if not part:
            raise ValueError(f"{name}: empty list item in {text!r}")
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            if not s.isdigit() or int(s) < 1:
                raise ValueError(f"{name}: bad step {s!r}")
            step = int(s)
        if part == "*":
            a, b = lo, top
        elif "-" in part:
            x, y = part.split("-", 1)
            a, b = _num(x, name, names), _num(y, name, names)
            if a > b:
                # cron implementations disagree on wrap-around ranges; guessing would fire at the wrong times
                raise ValueError(f"{name}: the range {part!r} runs backwards; write it as two ranges")
        else:
            a = _num(part, name, names)
            b = a if step == 1 else top
        for v in (a, b):
            if not lo <= v <= hi:
                raise ValueError(f"{name}: {v} is outside {lo}-{hi}")
        vals.update(range(a, b + 1, step))
    if name == "weekday":
        vals = {0 if v == 7 else v for v in vals}
    return sorted(vals)


def parse_cron(expr):
    """(the five field texts, [values or None per field]) for a 5-field cron line or @macro; raises ValueError."""
    e = normalize_cron(expr)
    if e.startswith("@"):
        raise ValueError(f"{e} has no calendar time (only @hourly, @daily, @weekly, @monthly, @yearly)")
    parts = e.split(" ")
    if len(parts) != 5:
        raise ValueError(f"a cron schedule has five fields (minute hour day-of-month month weekday); got {len(parts)}")
    vals = [_field(p, n, lo, hi, _MONTHS if n == "month" else _DAYS if n == "weekday" else None)
            for p, (n, lo, hi) in zip(parts, _FIELDS)]
    return parts, vals


def cron_to_oncalendar(expr):
    """(OnCalendar string, None) for a 5-field cron line or @macro, or (None, why). Ranges and steps are expanded to
    explicit lists, which systemd reads exactly as cron does. Refused instead of guessed: @reboot, a sixth field, and
    a line restricting BOTH the day of month and the weekday (cron fires when EITHER matches, systemd only when both
    do, so no single OnCalendar says the same thing)."""
    try:
        parts, (mi, hr, dom, mon, dow) = parse_cron(expr)
    except ValueError as err:
        return None, str(err)
    if not parts[2].startswith("*") and not parts[4].startswith("*"):
        return None, ("this line restricts both the day of month and the weekday; cron runs it when EITHER matches "
                      "and a systemd timer only when both do. Make two schedules, one for each")

    def lst(vals):
        return "*" if vals is None else ",".join(str(v) for v in vals)

    days = "" if dow is None else ",".join(_DAY_NAMES[v] for v in dow) + " "
    return f"{days}*-{lst(mon)}-{lst(dom)} {lst(hr)}:{lst(mi)}:00", None


def normalize_cron(expr):
    """The cron line as stored and written to crontab (macros expanded, single spaces)."""
    e = " ".join(str(expr or "").split())
    return _MACROS.get(e.lower(), e)


# ------------------------------------------------------------------------------------------- backends

def _run(argv, input=None, timeout=30):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)


def detect_backend(env=None, which=shutil.which, runner: Runner = _run, exists=os.path.exists):
    """'termux', 'systemd', 'cron' or None. Termux first: it has no systemd, and its crond is not started for you."""
    env = os.environ if env is None else env
    import gnoc_platform   # the one Termux detector (phase 9), so the scheduler and the defender never disagree
    if gnoc_platform.is_termux(env, isdir=exists):
        return "termux"
    if which("systemctl"):
        try:
            # show-environment answers only when a user manager is running (not in most containers, not over a
            # bare su); is-system-running would also answer "offline" with a non-zero code on a working box
            if runner(["systemctl", "--user", "show-environment"]).returncode == 0:
                return "systemd"
        except (OSError, subprocess.SubprocessError):
            pass
    if which("crontab"):
        return "cron"
    return None


def launcher():
    """The command that starts gnoc from a timer: the installed launcher (it knows the venv), else this checkout."""
    for p in (os.path.expanduser("~/.local/bin/gnoc"), shutil.which("gnoc")):
        if p and os.path.isfile(p):
            return [p]
    return [sys.executable, os.path.join(HERE, "gnoc")]


def unit_dir(env=None):
    env = os.environ if env is None else env
    base = env.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "systemd", "user")


def _sd_quote(arg):
    # systemd reads % as a specifier and $ as a variable in ExecStart: both are doubled, then the word is quoted
    a = str(arg).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
    return f'"{a}"'


def _unit_path_env():
    return os.pathsep.join(p for p in os.environ.get("PATH", "").split(os.pathsep)
                           if p and '"' not in p and "\n" not in p and "%" not in p and "$" not in p)


def service_text(sid, argv, wall_s):
    return ("[Unit]\nDescription=gnoc scheduled task " + sid + "\n\n[Service]\nType=oneshot\n"
            "Environment=GNOC_NO_UPDATE_CHECK=1\nEnvironment=GNOC_SCHEDULED=" + sid + "\n"
            f"Environment=\"PATH={_unit_path_env()}\"\n"
            "ExecStart=" + " ".join(_sd_quote(a) for a in list(argv) + ["schedule", "run", sid]) + "\n"
            f"Nice=10\nTimeoutStartSec={int(wall_s) + 300}\n")


def timer_text(sid, cron, oncal):
    return ("[Unit]\nDescription=gnoc scheduled task " + sid + "\n"
            "# cron: " + cron.replace("\n", " ") + "\n\n[Timer]\nOnCalendar=" + oncal + "\n"
            # cron does not catch up runs missed while the machine was off; neither does this timer
            "Persistent=false\n\n[Install]\nWantedBy=timers.target\n")


def cron_line(sid, cron, argv, log):
    cmd = (f"GNOC_NO_UPDATE_CHECK=1 GNOC_SCHEDULED={sid} " + " ".join(shlex.quote(a) for a in argv)
           + f" schedule run {sid} >> {shlex.quote(log)} 2>&1")
    return f"{cron} {cmd.replace('%', chr(92) + '%')} {MARK}{sid}"   # % ends the command in crontab: escape it


def merge_crontab(existing, sid, line):
    """Their crontab with this schedule's one marked line replaced (line) or removed (None); every other line kept."""
    mark = MARK + sid
    kept = [ln for ln in str(existing or "").splitlines() if not ln.rstrip().endswith(mark)]
    while kept and not kept[-1].strip():
        kept.pop()
    if line:
        kept.append(line)
    return ("\n".join(kept) + "\n") if kept else ""


def _crontab_read(runner):
    r = runner(["crontab", "-l"])
    if r.returncode != 0 and "no crontab" not in (r.stderr or "").lower():
        raise RuntimeError((r.stderr or "crontab -l failed").strip()[:200])
    return r.stdout if r.returncode == 0 else ""


def install(rec, backend, *, runner: Runner = _run, which=shutil.which, env=None, argv=None, vouch=None):
    """Put the schedule in place. -> (ok, text). Nothing is left half-installed on a failure."""
    sid, cron = rec["id"], rec["cron"]
    argv = list(argv or launcher())
    if backend == "systemd":
        oncal, why = cron_to_oncalendar(cron)
        if not oncal:
            return False, why
        if which("systemd-analyze"):
            r = runner(["systemd-analyze", "calendar", oncal])
            if r.returncode != 0:
                return False, f"systemd does not accept OnCalendar={oncal}: {(r.stderr or r.stdout).strip()[:200]}"
        d = unit_dir(env)
        os.makedirs(d, exist_ok=True)
        texts = {os.path.join(d, UNIT + sid + ".service"): service_text(sid, argv, rec["caps"]["wall_s"]),
                 os.path.join(d, UNIT + sid + ".timer"): timer_text(sid, cron, oncal)}
        for path, text in texts.items():
            _write_private(path, text, private_parent=False)   # ~/.config/systemd/user keeps its own mode
        if vouch:
            with contextlib.suppress(Exception):
                vouch(texts)   # gnoc wrote these exact bytes for the user: the defender does not call them drift
        for cmd in (["systemctl", "--user", "daemon-reload"],
                    ["systemctl", "--user", "enable", "--now", UNIT + sid + ".timer"]):
            r = runner(cmd)
            if r.returncode != 0:
                for path in texts:
                    with contextlib.suppress(OSError):
                        os.unlink(path)
                runner(["systemctl", "--user", "daemon-reload"])
                return False, f"systemctl refused it: {(r.stderr or r.stdout).strip()[:200]}"
        rec["backend"] = {"kind": "systemd", "oncalendar": oncal, "units": sorted(texts)}
        return True, f"systemd user timer {UNIT}{sid}.timer (OnCalendar={oncal})"
    if backend in ("cron", "termux"):
        if not which("crontab"):
            return False, ("no crontab here: on Termux, `pkg install cronie termux-services`, then `sv-enable crond`"
                           if backend == "termux" else "no crontab on this computer (install cron)")
        log = os.path.join(out_dir(sid, env), "cron.log")
        _private_dir(os.path.dirname(log))
        try:
            cur = _crontab_read(runner)
        except RuntimeError as err:
            return False, f"could not read your crontab: {err}"
        r = runner(["crontab", "-"], input=merge_crontab(cur, sid, cron_line(sid, cron, argv, log)))
        if r.returncode != 0:
            return False, "crontab refused it: " + (r.stderr or "").strip()[:200]
        rec["backend"] = {"kind": backend, "mark": MARK + sid, "log": log}
        note = (" Termux runs it only while crond runs: `pkg install termux-services`, then `sv-enable crond` "
                "(termux-wake-lock keeps Android from pausing it)." if backend == "termux" else "")
        return True, f"one crontab line marked {MARK}{sid} (your other lines are unchanged).{note}"
    return False, "no scheduler here: neither a systemd user session nor crontab was found"


def uninstall(rec, *, runner: Runner = _run, env=None):
    """Take the timer or cron line away. -> (ok, text)."""
    sid = rec["id"]
    be = rec.get("backend") or {}
    kind = be.get("kind")
    if kind == "systemd":
        runner(["systemctl", "--user", "disable", "--now", UNIT + sid + ".timer"])
        d = unit_dir(env)
        for ext in (".service", ".timer"):
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(d, UNIT + sid + ext))
        runner(["systemctl", "--user", "daemon-reload"])
        return True, "timer removed"
    if kind in ("cron", "termux"):
        try:
            cur = _crontab_read(runner)
        except RuntimeError as err:
            return False, f"could not read your crontab: {err}"
        r = runner(["crontab", "-"], input=merge_crontab(cur, sid, None))
        if r.returncode != 0:
            return False, "crontab refused the change: " + (r.stderr or "").strip()[:200]
        return True, "cron line removed (your other lines are unchanged)"
    return True, "nothing was installed"


# ------------------------------------------------------------------------------------------- the snapshot

def secrets_file():
    return os.path.join(os.path.expanduser("~"), ".config", "gnoc", "secrets.env")


def conf(name, path=None, env=None):
    """A setting from the environment, else from secrets.env. Never shown to a model."""
    env = os.environ if env is None else env
    if env.get(name):
        return env[name]
    try:
        with open(path or secrets_file(), encoding="utf-8") as fh:
            for ln in fh:
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", ln)
                if m and m.group(1) == name:
                    return m.group(2).strip().strip("'\"")
    except OSError:
        pass
    return None


def perms_snapshot(rules):
    """{'allow': [...], 'deny': [...], 'sha256': ...} of the user's permission rules, in a canonical order."""
    rules = rules if isinstance(rules, dict) else {}
    norm: dict = {k: sorted(({"rule": str(e.get("rule")), "repo": e.get("repo")} for e in rules.get(k) or []
                       if isinstance(e, dict) and e.get("rule")), key=lambda e: (e["rule"], str(e["repo"])))
            for k in ("allow", "deny")}
    norm["sha256"] = hashlib.sha256(json.dumps({"allow": norm["allow"], "deny": norm["deny"]},
                                               sort_keys=True).encode()).hexdigest()
    return norm


def snapshot(*, program=None, hunt_target=None, folder=None, effort="medium", steps=None, lead="", worker="",
             perms=None):
    """What a run of this schedule acts under, captured when it is made."""
    if perms is None:
        import gnoc_perms
        perms = gnoc_perms.load()
    return {"scope": {"program": program or None, "hunt_target": hunt_target or None},
            "folder": os.path.realpath(folder) if folder else None,
            "effort": effort or "medium", "steps": steps if isinstance(steps, int) and steps > 0 else None,
            "model": {"lead": lead or "", "worker": worker or ""},
            "permissions": perms_snapshot(perms)}


# ------------------------------------------------------------------------------------------- add / rm / list

_INVISIBLE = re.compile("[­​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")


def parse_add(rest):
    """'"<cron>" <prompt> [--deliver X]' -> (cron, prompt, deliver) or raises ValueError with what to type."""
    text = str(rest or "").strip()
    deliver = "file"
    m = re.search(r"(?:^|\s)--deliver(?:=|\s+)(\S+)\s*", text)
    if m:
        deliver = m.group(1).strip("'\"").lower()
        text = (text[:m.start()] + " " + text[m.end():]).strip()
    if deliver not in DELIVERIES:
        raise ValueError(f"--deliver takes {', '.join(DELIVERIES)} (got {deliver!r})")
    if text[:1] in ("'", '"'):
        end = text.find(text[0], 1)
        if end < 0:
            raise ValueError("the cron schedule's quote does not close")
        cron, prompt = text[1:end], text[end + 1:]
    elif text.startswith("@"):
        cron, _, prompt = text.partition(" ")
    else:
        bits = text.split(None, 5)
        if len(bits) < 6:
            raise ValueError('usage: /schedule add "<min hour dom month weekday>" <prompt> [--deliver telegram|desktop|file]')
        cron, prompt = " ".join(bits[:5]), bits[5]
    prompt = prompt.strip()
    if len(prompt) >= 2 and prompt[0] == prompt[-1] and prompt[0] in ("'", '"'):
        prompt = prompt[1:-1].strip()
    if not prompt:
        raise ValueError("say what to run: /schedule add \"0 9 * * 1-5\" summarise yesterday's CI failures")
    return normalize_cron(cron), prompt, deliver


def add(rest, snap, *, env=None, runner: Runner = _run, which=shutil.which, backend=None, argv=None, vouch=None,
        wall_s=DEFAULT_WALL_S, tokens=DEFAULT_TOKENS):
    """/schedule add. -> text for the user. Only ever called for a line the user typed (commands.py checks)."""
    try:
        cron, prompt, deliver = parse_add(rest)
    except ValueError as err:
        return f"not scheduled: {err}"
    if len(prompt) > 4000:
        return "not scheduled: the prompt is over 4000 characters; put the long part in a file and name the file"
    if _INVISIBLE.search(prompt):
        return "not scheduled: the prompt carries invisible characters (pasted text?); retype it"
    try:
        parse_cron(cron)
    except ValueError as err:
        return f"not scheduled: {err}"
    target: dict = {"kind": deliver}
    if deliver == "telegram":
        # the recipient is the owner chat id from HIS config, fixed now; never the model's, never the prompt's
        chat = str(conf("TELEGRAM_OWNER_CHAT_ID", env=env) or "").strip()
        if not chat:
            # the messaging gateway's owner list (GNOC_TELEGRAM_OWNERS) already names him: a private chat with the bot
            # has his user id as its chat id, so the first owner IS his chat. Still his config, never the model's.
            owners = re.findall(r"\d{1,20}", str(conf("GNOC_TELEGRAM_OWNERS", env=env) or ""))
            chat = owners[0] if owners else ""
        if not re.fullmatch(r"-?\d{1,20}", chat):
            return ("not scheduled: telegram delivery needs TELEGRAM_OWNER_CHAT_ID (your own numeric chat id; the "
                    "gateway's GNOC_TELEGRAM_OWNERS also works) and "
                    f"TELEGRAM_BOT_TOKEN in {secrets_file()}")
        if not conf("TELEGRAM_BOT_TOKEN", env=env):
            return f"not scheduled: telegram delivery needs TELEGRAM_BOT_TOKEN in {secrets_file()}"
        api = str(conf("TELEGRAM_API_BASE", env=env) or conf("GNOC_TELEGRAM_API", env=env) or TELEGRAM_API).rstrip("/")
        bad = _api_base_problem(api)
        if bad:
            return f"not scheduled: {bad}"
        target.update(chat_id=chat, api_base=api)
    be = backend or detect_backend(env, which, runner)
    if not be:
        return ("not scheduled: no scheduler here (no systemd user session and no crontab). Install cron, or on "
                "Termux `pkg install cronie termux-services`")
    if be == "systemd":
        oncal, why = cron_to_oncalendar(cron)
        if not oncal:
            return f"not scheduled: {why}"
    sid = _secrets.token_hex(4)
    while load(sid, env):
        sid = _secrets.token_hex(4)
    rec = {"id": sid, "created_at": _dt.datetime.now().isoformat(timespec="seconds"), "cron": cron, "prompt": prompt,
           "deliver": target, "snapshot": snap, "caps": {"wall_s": int(wall_s), "tokens": int(tokens)},
           "backend": {"kind": be}, "runs": []}
    ok, said = install(rec, be, runner=runner, which=which, env=env, argv=argv, vouch=vouch)
    if not ok:
        return f"not scheduled: {said}"
    save(rec, env)
    return (f"scheduled {sid}: cron '{cron}' via {said}\n" + describe(rec)
            + f"\n  /schedule run {sid} runs it now; /schedule rm {sid} removes it")


def remove(sid, *, env=None, runner: Runner = _run):
    rec = load(sid, env)
    if not rec:
        return f"no schedule {sid!r} (/schedule list shows the ids)"
    ok, said = uninstall(rec, runner=runner, env=env)
    if not ok:
        return f"not removed: {said}; the record stays so you can try again"
    with contextlib.suppress(OSError):
        os.unlink(_rec_path(sid, env))
    return f"removed {sid}: {said}. Its past reports stay in {out_dir(sid, env)}"


def _home_rel(p):
    h = os.path.expanduser("~")
    return ("~" + p[len(h):]) if p and (p == h or p.startswith(h + os.sep)) else (p or "")


def describe(rec):
    """The lines /schedule list shows for one record: everything a run will act under."""
    s = rec.get("snapshot") or {}
    sc = s.get("scope") or {}
    pm = s.get("permissions") or {}
    model = s.get("model") or {}
    dv = rec.get("deliver") or {}
    be = rec.get("backend") or {}
    caps = rec.get("caps") or {}
    where = {"systemd": f"systemd timer, OnCalendar={be.get('oncalendar')}", "cron": "crontab line",
             "termux": "crontab line (Termux crond)"}.get(str(be.get("kind")), str(be.get("kind")))
    scope = ", ".join(f"{k} {v}" for k, v in (("scope", sc.get("program")), ("HUNT_TARGET", sc.get("hunt_target")))
                      if v) or "none"
    rules = [f"allow {e['rule']}" for e in pm.get("allow") or []] + [f"deny {e['rule']}" for e in pm.get("deny") or []]
    last = (rec.get("runs") or [])[-1:] or [{}]
    lines = [f"  {rec['id']}  cron '{rec.get('cron')}'  ({where})  deliver: {dv.get('kind')}"
             + (f" to chat {dv.get('chat_id')}" if dv.get("kind") == "telegram" else ""),
             f"     prompt: {str(rec.get('prompt') or '')[:200]}",
             f"     saved with: {scope} · folder {_home_rel(s.get('folder') or '') or '(home)'} · effort "
             f"{s.get('effort')}" + (f" ({s.get('steps')} steps)" if s.get("steps") else "")
             + f" · lead {model.get('lead') or '(default)'} · worker {model.get('worker') or '(default)'}",
             f"     permissions: {len(pm.get('allow') or [])} allow / {len(pm.get('deny') or [])} deny, sha256 "
             f"{str(pm.get('sha256') or '')[:12]}" + (": " + "; ".join(rules)[:400] if rules else ""),
             f"     caps: {caps.get('wall_s')} s, ~{caps.get('tokens')} tokens · approval: none in a run (held and "
             "reported, never run)"
             + (f" · last run {last[0].get('at')}: {last[0].get('status')}, {last[0].get('held', 0)} held"
                if last[0].get("at") else "")]
    return "\n".join(lines)


def listing(env=None):
    recs = records(env)
    if not recs:
        return ('no scheduled tasks. Add one: /schedule add "0 9 * * 1-5" <prompt> [--deliver telegram|desktop|file]'
                f"  (records in {_home_rel(sched_dir(env))})")
    return "SCHEDULED TASKS (each runs unattended; anything needing approval is held and reported)\n" + \
        "\n".join(describe(r) for r in recs)


def run_now(sid, *, env=None, spawn=None, argv=None):
    """/schedule run <id>: the same command the timer runs, started in the background so the chat stays usable."""
    rec = load(sid, env)
    if not rec:
        return f"no schedule {sid!r} (/schedule list shows the ids)"
    log = os.path.join(out_dir(sid, env), "manual.log")
    _private_dir(os.path.dirname(log))
    cmd = list(argv or launcher()) + ["schedule", "run", sid]
    child_env = dict(os.environ if env is None else env, GNOC_NO_UPDATE_CHECK="1", GNOC_SCHEDULED=sid)
    try:
        if spawn:
            spawn(cmd, log, child_env)
        else:
            fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                subprocess.Popen(cmd, stdout=fd, stderr=fd, stdin=subprocess.DEVNULL, start_new_session=True,
                                 env=child_env)
            finally:
                os.close(fd)
    except OSError as err:
        return f"could not start it: {err}"
    return (f"started {sid} in the background (the same unattended run the timer does; nothing needing approval "
            f"runs). Its report lands in {_home_rel(out_dir(sid, env))}/")


def command(rest, *, snap_fn=None, env=None, runner: Runner = _run, which=shutil.which, backend=None, spawn=None,
            argv=None, vouch=None):
    """The /schedule command after the typed-line check. snap_fn builds the snapshot (only add needs it)."""
    words = str(rest or "").split(maxsplit=1)
    sub = words[0].lower() if words else "list"
    arg = words[1] if len(words) > 1 else ""
    if sub in ("list", "ls", "show", "status"):
        return listing(env)
    if sub == "add":
        return add(arg, snap_fn() if snap_fn else snapshot(), env=env, runner=runner, which=which, backend=backend,
                   argv=argv, vouch=vouch)
    if sub in ("rm", "remove", "delete", "del"):
        return remove(arg.strip(), env=env, runner=runner)
    if sub == "run":
        return run_now(arg.strip(), env=env, spawn=spawn, argv=argv)
    return ('usage: /schedule add "<cron>" <prompt> [--deliver telegram|desktop|file] · /schedule list · '
            "/schedule rm <id> · /schedule run <id>")


# ------------------------------------------------------------------------------------------- the model may not

# A job that makes jobs is the Hermes/OpenClaw lesson: only a line the user types sets a schedule. These are the
# shapes a model's tool call could set one with. The approval gate already asks for most of them; this refuses them
# outright, -s-p and /auto included, and names the line the user would type.
_CMD_POS = r"(?:^|[;&|(`\n]|\$\(|&&|\|\|)\s*(?:sudo\s+(?:-\S+\s+)*|env\s+(?:\S+=\S*\s+)*|nohup\s+|exec\s+)*(?:\S*/)?"
_SCHED_TEXT = [
    ("the /schedule command", re.compile(r"(?:^|[\s\"'`(=;&|])/schedule(?=$|[\s\"'`);&|])", re.I)),
    ("gnoc schedule", re.compile(r"(?:^|[\s;&|(`/\"'])gnoc(?:\.py)?\s+schedule\b", re.I)),
    ("the scheduler module", re.compile(r"\bpython[\w.]*\b[^|;&\n]*\bgnoc_schedule\b|\b(?:import|from)\s+gnoc_schedule"
                                        r"\b|(?:^|[;&|]\s*)[^\s;&|]*gnoc_schedule\.py\b")),
    ("a crontab change", re.compile(_CMD_POS + r"crontab\b(?!\s+-l\s*(?:$|[;&|)>\n]))")),
    ("a systemd timer", re.compile(r"\bsystemctl\b[^\n;&|]*\b(?:enable|start|restart|reenable|link|preset|unmask)\b"
                                   r"[^\n;&|]*(?:\.timer\b|gnoc-vulnwatch|gnoc-schedule-)|\bsystemctl\b[^\n;&|]*"
                                   r"\bedit\b|\bsystemd-run\b[^\n;&|]*--(?:on-|timer-property)")),
    ("an at job", re.compile(_CMD_POS + r"(?:at|batch)\s+(?:-\S+\s+)*(?:now|noon|midnight|teatime|tomorrow|today|\d)"
                             r"|\|\s*(?:\S*/)?(?:at|batch)\b(?!-)", re.I)),
    ("the vulnerability watch timer", re.compile(r"\bgnoc_vulnwatch(?:\.py)?\b[^\n;&|]*\btimer\b|"
                                                 r"\bgnoc_vulnwatch\b[^\n]*\.timer\s*\(|/defender\s+vulnwatch\s+"
                                                 r"(?:on|off)\b", re.I)),
]
_SCHED_PATH = re.compile(r"(?:\.config/systemd/|\.local/share/systemd/|/etc/systemd/|/etc/cron|/var/spool/cron|"
                         r"/etc/anacrontab|\.termux/boot|/spool/cron/|\.gnoc/schedules\b|systemd/user/[^\s'\"]*\.timer)")
_WRITES = re.compile(r">|\b(?:tee|cp|mv|ln|install|rsync|dd|touch|mkdir|chmod|rm|rmdir|unlink|truncate|shred|printf|"
                     r"echo|curl|wget|tar|unzip|git|"
                     r"python[\w.]*|perl|ruby|node|php)\b|\bsed\b[^|;&\n]*\s-i|\b(?:ba|z|da)?sh\s+-c\b")


def _texts(args, keys):
    a = args if isinstance(args, dict) else {}
    out = []
    for k in keys:
        v = a.get(k)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (list, tuple)):
            out.extend(str(x) for x in v)
    return out


def _patch_paths(args, root):
    """The files an apply_patch call touches (headers of a unified, git or *** patch, inline or in patch_file)."""
    text = str((args or {}).get("patch") or "")
    pf = (args or {}).get("patch_file")
    if isinstance(pf, str) and pf:
        with contextlib.suppress(OSError, ValueError):
            with open(os.path.join(root or "", os.path.expanduser(pf)), encoding="utf-8", errors="replace") as fh:
                text += "\n" + fh.read(400_000)
    return re.findall(r"(?m)^(?:\+\+\+|---)\s+(?:[ab]/)?(\S+)|^\*\*\*\s+(?:Add|Update|Delete|Move)\s+File:\s*(.+?)\s*$"
                      r"|^diff --git a/(\S+)", text)


def _is_sched_path(p, root, env=None):
    if not p:
        return False
    raw = str(p)
    full = os.path.realpath(os.path.join(root or os.getcwd(), os.path.expanduser(raw)))
    sd = os.path.realpath(sched_dir(env))
    ud = os.path.realpath(unit_dir(env))
    return bool(_SCHED_PATH.search(raw) or _SCHED_PATH.search(full)
                or full == sd or full.startswith(sd + os.sep) or full == ud or full.startswith(ud + os.sep))


def model_refusal(name, args, root=None, env=None):
    """The refusal text when a MODEL's tool call would create, change or run a schedule, else None."""
    a = args if isinstance(args, dict) else {}
    hit = None
    if name in ("bash", "bg"):
        cmd = "\n".join(_texts(a, ("command", "text", "cmd")))
        hit = next((what for what, rx in _SCHED_TEXT if rx.search(cmd)), None)
        if not hit and _SCHED_PATH.search(cmd) and _WRITES.search(cmd):
            hit = "a write to a scheduler file"
    elif name == "gnoc":
        w = " ".join(_texts(a, ("args",))).split()
        if w and w[0].lower() == "schedule":
            hit = "gnoc schedule"
        elif any(rx.search(" ".join(w)) for _, rx in _SCHED_TEXT[:1] + _SCHED_TEXT[-1:]):
            hit = "the /schedule command"
    elif name == "defend":
        act = str(a.get("action") or "").lower()
        op = str(a.get("op") or "").lower()
        if act == "vulnwatch" and op in ("on", "off", "enable", "disable", "start", "stop", "install", "uninstall",
                                         "timer"):
            return ("refused: only the user turns the hourly vulnerability watch on or off (it installs a systemd "
                    "timer, and only the user sets a schedule). Give them the line to type in this chat: "
                    f"/defender vulnwatch {'off' if op in ('off', 'disable', 'stop', 'uninstall') else 'on'}. "
                    "defend(action=vulnwatch) reads its state; op=run does one pass now.")
        blob = json.dumps(a, default=str)
        if _SCHED_TEXT[0][1].search(blob) or _SCHED_TEXT[1][1].search(blob):
            hit = "the /schedule command"
    elif name in ("write_file", "edit_file", "apply_patch"):
        paths = _texts(a, ("path", "paths", "file", "files"))
        if name == "apply_patch":
            paths += [next(x for x in m if x) for m in _patch_paths(a, root) if any(m)]
        if any(_is_sched_path(p, root, env) for p in paths):
            hit = "a write to a scheduler file"
    elif name == "claude_worker":
        # an outside agent running with its own permissions: no brief may ask it for a schedule
        brief = "\n".join(_texts(a, ("brief", "task")))
        if re.search(r"(?i)\bcrontab\b|\bOnCalendar\b|\bsystemd-run\b|\.timer\b|\bsystemd\s+(?:user\s+)?timer|"
                     r"\.termux/boot|\bcrond\b|\bgnoc\s+schedule\b|(?:^|\s)/schedule\b|\bat\s+now\b", brief):
            hit = "a schedule set by another agent"
    if not hit:
        return None
    return (f"refused: only the user sets a schedule ({hit}), and no tool or command line can, skip-perms and /auto "
            "included. Give them the line to type in this chat: /schedule add \"<min hour day month weekday>\" "
            "<what to run> [--deliver telegram|desktop|file] (/schedule list shows them, /schedule rm <id> removes "
            "one). It is not scheduled until the user types it.")


# ------------------------------------------------------------------------------------------- one unattended run

def _est_tokens(msgs):
    n = 0
    for m in msgs or ():
        if isinstance(m, dict):
            n += len(str(m.get("content") or "")) + len(json.dumps(m.get("tool_calls") or "", default=str))
        else:
            n += len(str(m))
    return n // 4 + 1


def _summary(name, args):
    a = args if isinstance(args, dict) else {}
    d = a.get("command") or a.get("args") or a.get("path") or a.get("url") or a.get("brief") or a.get("action")
    d = d if isinstance(d, str) and d else json.dumps(a, default=str)
    return " ".join(d.split())[:300]


@contextlib.contextmanager
def _applied(G, rec, agent_dir, held, budget):
    """The snapshot in force for the length of one run, every change undone afterwards (a test or a later run in
    the same process must not inherit it)."""
    import gnoc_goal
    import gnoc_perms
    snap = rec.get("snapshot") or {}
    sc = snap.get("scope") or {}
    model = snap.get("model") or {}
    pm = snap.get("permissions") or {}
    saved_attrs = {k: getattr(G, k) for k in ("AGENT_DIR", "OUT_DIR", "JOBS_DIR", "SESSIONS_DIR", "ACTIVITY",
                                              "_approve", "llm_chat")}
    saved_lists = (G.SKIP_PERMS[0], G.EFFORT[0], G.STEPS_OVERRIDE[0], G._ACTIVE_ROOT[0])
    saved_goal = gnoc_goal.PATH
    saved_env = {k: os.environ.get(k) for k in ("HUNT_TARGET", "GNOC_ROLE_LEAD", "GNOC_ROLE_WORKER")}
    saved_perm_path = gnoc_perms.path
    # allow rules: exactly the snapshot. deny rules: the snapshot AND today's, so a "never" added later still holds
    try:
        today_deny = list((gnoc_perms.load() or {}).get("deny") or [])
    except Exception:  # noqa: BLE001 - an unreadable rules file adds nothing, it never removes the snapshot's
        today_deny = []
    rules = {"allow": list(pm.get("allow") or []),
             "deny": list(pm.get("deny") or []) + [e for e in today_deny if e not in (pm.get("deny") or [])]}
    perm_file = os.path.join(agent_dir, "permissions.json")
    _write_private(perm_file, json.dumps(rules))
    lock = threading.Lock()
    real_llm = G.llm_chat
    cap = int((rec.get("caps") or {}).get("tokens") or DEFAULT_TOKENS)

    def capped_llm(model_name, host, msgs, *a, **k):
        with lock:
            if budget["used"] >= cap:
                budget["hit"] = True
                return {"role": "assistant", "content": f"(stopped: this scheduled run reached its token cap of {cap})"}
            budget["used"] += _est_tokens(msgs)
        out = real_llm(model_name, host, msgs, *a, **k)
        with lock:
            budget["used"] += _est_tokens([out] if isinstance(out, dict) else [str(out)])
        return out

    def held_approve(name, args, interactive):
        # nobody is at a prompt: the call is recorded for the report and refused, whatever `interactive` says
        held.append({"tool": str(name), "summary": _summary(name, args)})
        return False

    try:
        # its own agent dir: the run's settings, conversation and activity never mix with a live chat's
        for k, v in {"AGENT_DIR": agent_dir, "OUT_DIR": os.path.join(agent_dir, "out"),
                     "JOBS_DIR": os.path.join(agent_dir, "jobs"), "SESSIONS_DIR": os.path.join(agent_dir, "sessions"),
                     "ACTIVITY": os.path.join(agent_dir, "activity.jsonl"), "_approve": held_approve,
                     "llm_chat": capped_llm}.items():
            setattr(G, k, v)
        gnoc_goal.PATH = os.path.join(agent_dir, "goal.json")
        gnoc_perms.path = lambda: perm_file
        G.SKIP_PERMS[0] = False
        G.EFFORT[0] = snap.get("effort") if snap.get("effort") in G.EFFORTS else "medium"
        # never unbounded: the snapshot's own step cap, else the effort's preset
        G.STEPS_OVERRIDE[0] = snap.get("steps") or G.EFFORTS[G.EFFORT[0]]["steps"]
        if snap.get("folder") and os.path.isdir(snap["folder"]):
            G._ACTIVE_ROOT[0] = snap["folder"]
        for k, v in (("HUNT_TARGET", sc.get("hunt_target")), ("GNOC_ROLE_LEAD", model.get("lead")),
                     ("GNOC_ROLE_WORKER", model.get("worker"))):
            if v:
                os.environ[k] = str(v)
            else:
                os.environ.pop(k, None)
        yield
    finally:
        for k, v in saved_attrs.items():
            setattr(G, k, v)
        G.SKIP_PERMS[0], G.EFFORT[0], G.STEPS_OVERRIDE[0], G._ACTIVE_ROOT[0] = saved_lists
        gnoc_goal.PATH = saved_goal
        gnoc_perms.path = saved_perm_path
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _refusals(history):
    out = []
    for m in history or ():
        if isinstance(m, dict) and m.get("role") == "tool":
            c = " ".join(str(m.get("content") or "").split())
            if c.startswith(("refused", "not run")) and "needs the user's approval" not in c:
                out.append(f"{m.get('tool_name') or 'tool'}: {c[:200]}")
    return out[:20]


def _redact(text, extra=()):
    try:
        import gnoc_secrets
        text = gnoc_secrets.redact(text) or text
    except Exception:  # noqa: BLE001 - the explicit values below are still removed
        pass
    for v in extra:
        if v and len(v) >= 6:
            text = text.replace(v, "[REDACTED]")
    return text


def report_text(rec, status, answer, held, refused, started, seconds, used):
    s = rec.get("snapshot") or {}
    lines = [f"# gnoc scheduled task {rec['id']}", "",
             f"- ran: {started} for {seconds:.0f} s (cron '{rec.get('cron')}')",
             f"- prompt: {rec.get('prompt')}",
             f"- status: {status}",
             f"- model calls: ~{used} tokens (estimated, cap {(rec.get('caps') or {}).get('tokens')})",
             f"- held for approval, NOT run: {len(held)}"]
    lines += [f"  - held for approval: {h['tool']} {h['summary']}" for h in held]
    if refused:
        lines.append(f"- refused by a rule, not run: {len(refused)}")
        lines += [f"  - {r}" for r in refused]
    lines += ["", "## Answer", "", (answer or "(no answer)").strip(), "", "## Saved with", "",
              f"- scope: {(s.get('scope') or {}).get('program') or 'none'}; folder: {s.get('folder') or '(home)'}",
              f"- effort: {s.get('effort')}; lead: {(s.get('model') or {}).get('lead') or '(default)'}",
              f"- permission rules sha256: {(s.get('permissions') or {}).get('sha256')}"]
    if held:
        lines += ["", "Nothing above marked held was run. To do one, run it yourself or ask for it in a chat."]
    return "\n".join(lines) + "\n"


def _api_base_problem(api):
    u = urllib.parse.urlsplit(api)
    if u.scheme == "https" and u.hostname:
        return None
    if u.scheme == "http" and u.hostname:
        with contextlib.suppress(ValueError):
            if u.hostname == "localhost" or ipaddress.ip_address(u.hostname).is_loopback:
                return None
    return f"TELEGRAM_API_BASE {api!r} must be https (plain http only to this machine): the bot token is in the URL"


def telegram_send(token, chat_id, text, api_base=TELEGRAM_API, timeout=15):
    """POST sendMessage to the owner chat. -> (ok, text). The token never appears in what is returned."""
    bad = _api_base_problem(api_base)
    if bad:
        return False, bad
    url = f"{api_base.rstrip('/')}/bot{token}/sendMessage"
    body = urllib.parse.urlencode({"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            got = json.loads(r.read(65536).decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as err:
        return False, _redact(f"telegram answered HTTP {err.code}", (token,))
    except (urllib.error.URLError, OSError, ValueError) as err:
        return False, _redact(f"telegram not reached: {type(err).__name__}: {err}", (token,))
    if not (isinstance(got, dict) and got.get("ok")):
        return False, _redact(f"telegram refused it: {str(got)[:200]}", (token,))
    return True, "sent to telegram"


def deliver(rec, report, path, *, env=None, notify=None, send=None):
    """Hand the report to where the schedule says. The file was already written. -> what happened, in words."""
    dv = rec.get("deliver") or {}
    kind = dv.get("kind") or "file"
    if kind == "desktop":
        if notify is None:
            import gnoc_notify
            notify = gnoc_notify.notify
        status = next((ln[len("- status: "):] for ln in report.splitlines() if ln.startswith("- status: ")), "")
        held = next((ln[2:] for ln in report.splitlines() if ln.startswith("- held for approval")), "")
        ok = notify(f"gnoc task {rec['id']}", f"{status}; {held}; report {path}"[:200], force=True)
        return "desktop notification sent" if ok else "no desktop notification (no notifier here); the file has it"
    if kind == "telegram":
        token = conf("TELEGRAM_BOT_TOKEN", env=env)
        if not token:
            return "telegram not sent: TELEGRAM_BOT_TOKEN is no longer configured; the file has the report"
        text = _redact(report, (token,))
        if len(text) > TELEGRAM_LIMIT:
            text = text[:TELEGRAM_LIMIT] + f"\n... (cut; the full report is {path})"
        ok, said = (send or telegram_send)(token, dv.get("chat_id"), text, dv.get("api_base") or TELEGRAM_API)
        return said if ok else f"telegram not sent: {said}"
    return "written to the file"


def run(sid, *, G=None, env=None, notify=None, send=None, now=None):
    """One unattended run of schedule sid. -> (exit code, text). What the timer calls."""
    rec = load(sid, env)
    if not rec:
        return 2, f"no schedule {sid!r}"
    lock_fh = None
    try:
        import fcntl
        _private_dir(sched_dir(env))
        lock_fh = open(os.path.join(sched_dir(env), f".{sid}.lock"), "a")
        fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except ImportError:
        lock_fh = None
    except OSError:
        return 0, f"{sid} is still running from its last start: this start was skipped"
    try:
        return _run_locked(rec, G=G, env=env, notify=notify, send=send, now=now)
    finally:
        if lock_fh:
            lock_fh.close()


def _run_locked(rec, *, G=None, env=None, notify=None, send=None, now=None):
    sid = rec["id"]
    if G is None:
        import importlib
        G = importlib.import_module("gnoc_agent")   # the facade is the agent; loaded only when a run needs it
    started = (now or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    t0 = time.monotonic()
    wall = int((rec.get("caps") or {}).get("wall_s") or DEFAULT_WALL_S)
    held: list = []
    budget = {"used": 0, "hit": False}
    box: dict = {}
    runs_root = os.path.join(sched_dir(env), "runs")
    _private_dir(runs_root)
    agent_dir = tempfile.mkdtemp(prefix=sid + "-", dir=runs_root)
    os.makedirs(os.path.join(agent_dir, "agent"), exist_ok=True)
    sink = io.StringIO()
    history: list = []
    try:
        with _applied(G, rec, os.path.join(agent_dir, "agent"), held, budget):
            try:
                agent = G.Agent(interactive=False)
            except Exception as err:  # noqa: BLE001 - a broken setting is a failed run in the report, not a trace
                box["error"], agent = err, None
            if agent is not None:
                snap = rec.get("snapshot") or {}
                if (snap.get("scope") or {}).get("program"):
                    agent.s["program"] = snap["scope"]["program"]
                agent.s["effort"], agent.s["steps_override"] = G.EFFORT[0], G.STEPS_OVERRIDE[0]
                agent.s["auto"] = False
                # no lesson writing: the reflection runs on a thread AFTER the turn, outside both caps, and would write
                # the user's lesson book from a transcript nobody read (measured: model calls after the run returned)
                agent.s["learn"] = False
                agent.s["_typed"] = rec["prompt"]
                agent.s["_scheduled"] = sid

                def go():
                    try:
                        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                            box["answer"] = agent.turn(rec["prompt"])
                    except BaseException as err:  # noqa: BLE001 - reported, never raised out of a timer
                        box["error"] = err

                th = threading.Thread(target=go, daemon=True, name=f"gnoc-schedule-{sid}")
                th.start()
                th.join(wall)
                if th.is_alive():
                    G.INTERRUPT.set()   # every model stream and tool loop checks it and bails
                    th.join(30)
                    box["timeout"] = True
                    G.INTERRUPT.clear()   # a later run in this process (a test) starts clean
                history = list(agent.s.get("history") or [])
    except Exception as err:  # noqa: BLE001 - the snapshot could not be applied (an unwritable folder)
        box.setdefault("error", err)
    finally:
        shutil.rmtree(agent_dir, ignore_errors=True)
    if box.get("timeout"):
        status = f"stopped at the wall-clock cap ({wall} s)"
    elif "error" in box:
        status = f"failed: {type(box['error']).__name__}: {str(box['error'])[:200]}"
    elif budget["hit"]:
        status = f"stopped at the token cap (~{(rec.get('caps') or {}).get('tokens')} tokens)"
    else:
        status = "finished"
    answer = box.get("answer") or next((str(m.get("content") or "") for m in reversed(history)
                                        if isinstance(m, dict) and m.get("role") == "assistant"
                                        and str(m.get("content") or "").strip()), "")
    report = _redact(report_text(rec, status, answer, held, _refusals(history), started,
                                 time.monotonic() - t0, budget["used"]),
                     (conf("TELEGRAM_BOT_TOKEN", env=env) or "",))
    path = os.path.join(out_dir(sid, env), (now or _dt.datetime.now()).strftime("%Y%m%d-%H%M%S") + ".md")
    _write_private(path, report)
    said = deliver(rec, report, path, env=env, notify=notify, send=send)
    fresh = load(sid, env)
    if fresh:   # removed mid-run: the report stands, the record is not brought back
        fresh["runs"] = (list(fresh.get("runs") or []) + [{"at": started, "status": status, "held": len(held),
                                                           "report": path, "delivery": said}])[-20:]
        save(fresh, env)
    return (0 if status == "finished" else 1), f"{sid}: {status}; {len(held)} held; {said}; report {path}"


# ------------------------------------------------------------------------------------------- CLI

def main(argv):
    cmd = argv[0] if argv else "list"
    if cmd == "run" and len(argv) == 2 and ID_RX.match(argv[1]):
        code, text = run(argv[1])
        print(text)
        return code
    if cmd in ("list", "ls"):
        print(listing())
        return 0
    if cmd in ("add", "rm", "remove"):
        print(f"`gnoc schedule {cmd}` is typed inside the chat: open `gnoc chat` and type /schedule {cmd} ...")
        return 2
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
