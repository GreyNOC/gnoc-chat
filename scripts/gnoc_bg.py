"""gnoc_bg.py - long-running processes the agent starts and comes back to: a dev server, a watcher, a REPL.

`bash` runs one command to completion under a time limit, so the start-a-server / change-code / check-it loop
had no handle: the only advice was `nohup ... &`, after which nothing could read the server's new output, type
into it, or stop it. This module keeps a small table of processes started by THIS gnoc process:

    start(name, command, cwd, env, tty=False)   own process group; output goes to a log file
    output(name, tail=60, new=True)             what it printed since the last look (or the last N lines)
    send(name, text)                            write a line to its stdin (a REPL, a prompt, a debugger)
    stop(name)                                  SIGTERM the whole group, SIGKILL after a grace period
    listing()                                   every process, its state, pid and uptime

tty=True runs it under a pseudo-terminal, so a program that only talks to a terminal (a REPL, `pdb`, an
installer that asks questions) behaves as it does for a person. Every process is killed when gnoc exits.
Nothing here decides whether a command is allowed: the caller runs the same gates `bash` runs first.
"""
from __future__ import annotations

import atexit
import os
import re
import signal
import subprocess
import threading
import time

import gnoc_compat   # the shell (bash / PowerShell) and process-tree kill on every platform

MAX_PROCS = 8
LOG_TAIL_BYTES = 256 * 1024
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\r(?!\n)")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,40}$")

_LOCK = threading.Lock()
_PROCS: dict[str, dict] = {}


def _log_dir():
    d = os.environ.get("GNOC_BG_DIR") or os.path.join(os.path.expanduser("~"), ".gnoc", "bg")
    os.makedirs(d, exist_ok=True)
    return d


def _pump(src, log_path, closer=None):
    """Copy a process's output to its log until EOF. Runs in a daemon thread."""
    try:
        with open(log_path, "ab", buffering=0) as out:
            while True:
                try:
                    chunk = os.read(src, 65536) if isinstance(src, int) else src.read1(65536)
                except OSError:      # a pty master raises EIO once the child side closes
                    break
                if not chunk:
                    break
                out.write(chunk)
    finally:
        if closer:
            try:
                closer()
            except OSError:
                pass


def start(name, command, cwd, env=None, tty=False, argv=None, killer=None, popen=None):
    """Start `command` under bash. Returns (ok, message).

    argv/killer/popen come from a sandbox backend (gnoc_sandbox): argv runs the command in the session's container or
    on its ssh host instead of a local bash, and killer() stops it THERE on stop, because killing the local client
    (`docker exec`, `ssh`) leaves the remote process running. The caller has already run bash's gates."""
    name = str(name or "").strip()
    if not _NAME.match(name):
        return False, "name must be 1-41 letters, digits, '.', '_' or '-' (e.g. name=web or name=api-dev)"
    with _LOCK:
        old = _PROCS.get(name)
        if old and old["proc"].poll() is None:
            return False, (f"a process named {name} is already running (pid {old['proc'].pid}); stop it first or "
                           "pick another name")
        if sum(1 for p in _PROCS.values() if p["proc"].poll() is None) >= MAX_PROCS:
            return False, f"{MAX_PROCS} background processes are already running; stop one first"
        log_path = os.path.join(_log_dir(), f"{name}-{int(time.time())}-{os.getpid()}.log")
        open(log_path, "wb").close()
        if tty and gnoc_compat.IS_WINDOWS:
            tty = False   # Windows has no pty: the process gets pipes, which every REPL there accepts
        if tty:
            import pty
            master, slave = pty.openpty()
            proc = (popen or subprocess.Popen)(argv or gnoc_compat.shell_argv(command), stdin=slave, stdout=slave,
                                               stderr=slave, cwd=cwd, env=env, start_new_session=True, close_fds=True)
            os.close(slave)
            writer = master
            t = threading.Thread(target=_pump, args=(master, log_path, lambda: os.close(master)), daemon=True)
        else:
            proc = (popen or subprocess.Popen)(argv or gnoc_compat.shell_argv(command), stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, env=env,
                                               start_new_session=True)
            writer = proc.stdin
            t = threading.Thread(target=_pump, args=(proc.stdout, log_path), daemon=True)
        t.start()
        _PROCS[name] = {"proc": proc, "command": command, "cwd": cwd, "log": log_path, "started": time.time(),
                        "read_at": 0, "writer": writer, "tty": bool(tty), "pump": t, "killer": killer}
    return True, f"started {name} (pid {proc.pid}{', in a terminal' if tty else ''}); log {log_path}"


def _state(p):
    code = p["proc"].poll()
    return "running" if code is None else f"exited {code}"


def _clean(raw):
    return _ANSI.sub("", raw.decode("utf-8", "replace")).replace("\r\n", "\n")


def output(name, tail=60, new=True, wait=0.0):
    """(ok, text): the output since the last look (new=True) or the last `tail` lines. wait= seconds to let a
    just-started server print its ready line first (max 30)."""
    p = _PROCS.get(str(name or ""))
    if not p:
        return False, f"no background process named {name!r}" + (f"; running: {', '.join(_PROCS)}" if _PROCS else "")
    wait = max(0.0, min(float(wait or 0), 30.0))
    if wait:
        deadline = time.time() + wait
        size0 = os.path.getsize(p["log"])
        while time.time() < deadline and p["proc"].poll() is None:
            time.sleep(0.2)
            if os.path.getsize(p["log"]) > size0 and time.time() > deadline - wait + 1.0:
                break
    if p["proc"].poll() is not None:
        p["pump"].join(timeout=2)
    size = os.path.getsize(p["log"])
    tail = max(1, min(int(tail or 60), 400))
    with open(p["log"], "rb") as f:
        if new:
            start_at = max(p["read_at"], size - LOG_TAIL_BYTES)
            skipped = start_at - p["read_at"]
            f.seek(start_at)
            raw = f.read()
        else:
            f.seek(max(0, size - LOG_TAIL_BYTES))
            raw, skipped = f.read(), 0
    p["read_at"] = size
    lines = _clean(raw).splitlines()
    cut = len(lines) - tail
    shown = lines[-tail:]
    head = f"{name}: {_state(p)}, pid {p['proc'].pid}, up {int(time.time() - p['started'])}s"
    note = []
    if skipped > 0:
        note.append(f"{skipped} older bytes not shown")
    if cut > 0:
        note.append(f"{cut} earlier lines not shown (tail={tail})")
    body = "\n".join(shown) if shown else ("(no new output)" if new else "(no output yet)")
    return True, head + (f" [{'; '.join(note)}; full log {p['log']}]" if note else "") + "\n" + body


def send(name, text):
    p = _PROCS.get(str(name or ""))
    if not p:
        return False, f"no background process named {name!r}"
    if p["proc"].poll() is not None:
        return False, f"{name} has {_state(p)}; nothing is reading its input"
    data = str(text if text is not None else "")
    if not data.endswith("\n"):
        data += "\n"
    try:
        if p["tty"]:
            os.write(p["writer"], data.encode())
        else:
            p["writer"].write(data.encode())
            p["writer"].flush()
    except (OSError, ValueError) as e:
        return False, f"could not write to {name}: {e}"
    return True, f"sent {len(data)} bytes to {name}; read the reply with action=output name={name}"


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _kill(p, grace=3.0):
    """TERM, then KILL, the whole process GROUP. A leader that already exited (`server &`, a wrapper that forks)
    used to end the stop early and leave the server running (QAQC r2): the group is checked, not the leader."""
    proc = p["proc"]
    pgid = proc.pid   # start_new_session: the group id is the leader's pid
    if p.get("killer"):
        try:
            p["killer"]()   # the sandbox side first, while its pidfile still names the process
        except Exception:  # noqa: BLE001 - the local group is still killed below
            pass
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 2.0)):
        if proc.poll() is not None and not _group_alive(pgid):
            return
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        deadline = time.time() + wait
        while time.time() < deadline:
            if proc.poll() is not None and not _group_alive(pgid):
                return
            time.sleep(0.05)


def stop(name):
    p = _PROCS.get(str(name or ""))
    if not p:
        return False, f"no background process named {name!r}"
    was = _state(p)
    _kill(p)
    ok, tail = output(name, tail=15, new=True)
    return True, f"stopped {name} (was {was}, now {_state(p)})\n" + (tail.split("\n", 1)[1] if ok and "\n" in tail else "")


def listing():
    if not _PROCS:
        return "background processes: none running (start one with action=start name=<name> command=<command>)"
    rows = []
    for n, p in _PROCS.items():
        rows.append(f"{n}: {_state(p)}, pid {p['proc'].pid}, up {int(time.time() - p['started'])}s, "
                    f"{'tty, ' if p['tty'] else ''}cwd {p['cwd']}\n    $ {p['command'][:160]}")
    return "\n".join(rows)


def stop_all():
    for p in list(_PROCS.values()):
        _kill(p, grace=1.0)


# ---- headless browsers this chat started, whichever way it started them ----------------------------------------
# A CDP browser a hunt launched (`chrome --headless=new --remote-debugging-port=9351 ... &` through bash, for the
# scripts that connect_over_cdp to it) outlived the call that started it, and nothing tracked it: two were found
# idle after three days (2026-11-21, GreyNOC: "make sure that gnoc chat is closing cdp headless browsers after its
# done"). Every process gnoc starts carries SPAWN_VAR in its environment - set on gnoc's own environment, so it
# survives nohup, setsid, `&`, re-parenting and in-process Playwright - and the chat closes the HEADLESS browsers
# carrying its mark when it exits, and at start the ones whose chat is gone. A headed browser and the persistent
# ~/.config/gnoc profiles (his real logins, browser-budget.py's exemption) are never touched.
SPAWN_VAR = "GNOC_SPAWNED_BY"
_BROWSER_EXE = re.compile(r"(?:^|/)(?:chrome|chromium(?:-browser)?|google-chrome(?:-stable|-beta|-unstable)?|"
                          r"chrome-headless-shell|headless_shell|msedge|brave(?:-browser)?)$")
_PROTECTED_PROFILES = (os.path.realpath(os.path.expanduser("~/.config/gnoc")),)


def _start_ticks(pid):
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[1].split()[19]      # field 22: the start time, in clock ticks
    except (OSError, IndexError):
        return None


MARK = f"{os.getpid()}:{_start_ticks(os.getpid()) or 0}"
_MARK_OWNER = os.getpid()
os.environ[SPAWN_VAR] = MARK


def _mark_alive(mark):
    pid, _, ticks = str(mark).partition(":")
    return pid.isdigit() and _start_ticks(int(pid)) == ticks


def _protected(profile):
    real = os.path.realpath(profile)
    return any(real == p or real.startswith(p + os.sep) for p in _PROTECTED_PROFILES)


def _headless_browsers():
    """[(pid, mark)] for every headless browser MAIN process this user runs that carries a gnoc mark; [] without
    /proc (macOS, Windows): there the bg jobs are still stopped at exit."""
    out = []
    if not os.path.isdir("/proc"):
        return out
    for e in os.scandir("/proc"):
        if not e.name.isdigit():
            continue
        try:
            with open(os.path.join(e.path, "cmdline"), "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
            if not argv or not _BROWSER_EXE.search(argv[0]) or any(a.startswith("--type=") for a in argv):
                continue                     # a renderer or zygote goes with its browser
            if not any(a == "--headless" or a.startswith("--headless=") for a in argv):
                continue                     # a browser with a window is a person's
            prof = next((a.split("=", 1)[1] for a in argv if a.startswith("--user-data-dir=")), "")
            if prof and _protected(prof):
                continue
            with open(os.path.join(e.path, "environ"), "rb") as fh:
                env = fh.read().split(b"\0")
        except OSError:
            continue
        mark = next((v.split(b"=", 1)[1].decode("ascii", "replace") for v in env
                     if v.startswith(SPAWN_VAR.encode() + b"=")), None)
        if mark:
            out.append((int(e.name), mark))
    return out


def reap_browsers(orphans=False, grace=3.0):
    """Close the headless browsers this chat started (orphans=False, at exit), or the ones whose chat is no longer
    running (orphans=True, at start). Returns the pids that were closed."""
    if os.getpid() != _MARK_OWNER:
        return []                            # a forked child is not the chat
    if orphans:
        pids = [pid for pid, mark in _headless_browsers() if mark != MARK and not _mark_alive(mark)]
    else:
        pids = [pid for pid, mark in _headless_browsers() if mark == MARK]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)     # a clean browser shutdown takes its renderers with it
        except OSError:
            pass
    end = time.time() + grace
    while pids and time.time() < end and any(os.path.exists(f"/proc/{p}") for p in pids):
        time.sleep(0.1)
    for pid in pids:
        if os.path.exists(f"/proc/{pid}"):
            try:
                os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
            except OSError:
                pass
    return pids


def chat_started(say=None):
    """At the start of a chat: close the headless browsers earlier chats left behind, and make a closed terminal
    (SIGHUP) or a plain kill (SIGTERM) end the chat through its exit path, so its own browsers are closed too."""
    import sys
    if threading.current_thread() is threading.main_thread():
        for name in ("SIGHUP", "SIGTERM"):
            sig = getattr(signal, name, None)
            if sig is not None and signal.getsignal(sig) in (signal.SIG_DFL, None):
                try:
                    signal.signal(sig, lambda s, f: sys.exit(128 + int(s)))
                except (OSError, ValueError, RuntimeError):
                    pass
    try:
        gone = reap_browsers(orphans=True)
    except Exception:   # noqa: BLE001 - housekeeping must never stop a chat from starting
        gone = []
    if gone and say:
        say(f"  closed {len(gone)} headless browser(s) an earlier gnoc chat left running")
    return gone


def _at_exit():
    stop_all()
    try:
        reap_browsers()
    except Exception:   # noqa: BLE001 - exit housekeeping
        pass


atexit.register(_at_exit)
