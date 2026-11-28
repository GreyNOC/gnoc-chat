#!/usr/bin/env python3
"""gnoc_session.py - hunting is bound to a LIVE gnoc chat session, and dies with it.

The user's rule (2026-11-02, verbatim): "Lets keep hunting to the gnoc chat sessions and when gnoc
chat is closed the hunting should stop as well. No more orch bot or oss bot. Lets just have the
gnoc chat orchistrate everything when requested."

So there is no unattended hunter any more. The model is:

  OPEN     gnoc chat registers itself here at startup (one file per chat pid).
  GATE     the automated probe engines (opencode-lane.sh, auto-hunt.py, auto-target --pick)
           refuse to start unless at least one chat session is live.
  CLOSE    when the chat exits - cleanly, by a hangup or terminate signal, or by the terminal
           closing - every lane that chat started is killed by process group, and the session
           file is removed.
  REAP     a chat that was hard-killed leaves a stale file; any reader reaps it by checking the
           pid, so a crashed chat can never leave the gate propped open.

WHAT THIS GATES: the unattended automation that fires probes on its own. It deliberately does NOT
gate the user's own hand-run commands - a curl the user types themselves is their business, not an autonomous
hunt. The gate exists to stop the machine hunting while nobody is watching.

Files: .claude/state/hunt-loop/sessions/<pid>.json
"""
import contextlib
import threading
import json
import os
import signal
import sys
import time
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_z as _now

WS = os.environ.get("GNOC_WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SESSIONS = os.path.join(WS, ".claude/state/hunt-loop/sessions")

# Set deliberately by a human who wants one automated engine run with no chat open. It is reported
# in the refusal path so an unexplained unattended hunt is always traceable to someone setting it.
OVERRIDE_ENV = "GNOC_HUNT_NO_SESSION"

_MINE = [None]        # path of the session file this process owns
_CLOSING = [False]    # re-entrancy guard: the exit handler and a signal can both land

_TERM = signal.SIGTERM
_KILL = signal.SIGKILL
# SIGINT is deliberately NOT here. Arming a terminating handler on it turned every Ctrl-C into a chat
# death: the handler closed the session and re-sent the signal with SIG_DFL, so the REPL's
# KeyboardInterrupt guards (the ones that stop a /goal or /hunt loop) never ran. Measured 2026-11-10
# 00:42Z: one C-c between goal turns killed `gnoc chat` ("Pane is dead (signal 2)"). Python's default
# SIGINT -> KeyboardInterrupt is what the chat expects; a real exit still closes the session via atexit.
_EXIT_SIGNALS = (signal.SIGHUP, signal.SIGTERM)




def _alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except PermissionError:
        return True          # exists, owned by someone else
    except (OSError, ValueError, TypeError):
        return False


def _read(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write(path, obj):
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"   # one tmp per writer: a shared name raced
    with open(tmp, "w") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)     # atomic: a reader never sees a half-written session


_LANE_LOCK = threading.Lock()


@contextlib.contextmanager
def _locked(path):
    """This process's threads AND other processes: read-modify-write of the session record under one lock.
    Lanes registered at the same moment were lost (16 threads -> 4 recorded), and an unrecorded lane outlives
    the chat (QAQC r2)."""
    import fcntl
    with _LANE_LOCK:
        with open(path + ".lock", "a") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)


# ------------------------------------------------------------------ the registry

def live_sessions():
    """Every live chat session, stale files reaped. A dead pid never holds the gate open."""
    out = []
    try:
        names = os.listdir(SESSIONS)
    except OSError:
        return out
    for name in sorted(names):
        if not name.endswith(".json"):
            continue
        path = os.path.join(SESSIONS, name)
        rec = _read(path)
        if not rec or not _alive(rec.get("pid")):
            # REAP: a crashed chat must not look live, and must not leave its lanes probing.
            # A hard-killed chat runs no handler of its own, so whoever notices does the killing.
            if rec:
                _kill_lanes(rec)
            with contextlib.suppress(OSError):
                os.unlink(path)
            continue
        out.append(rec)
    return out


def hunting_allowed():
    return bool(live_sessions())


def require(what="this hunt"):
    """Return (ok, reason). The caller decides whether to exit; this never kills the process."""
    if hunting_allowed():
        return True, ""
    if os.environ.get(OVERRIDE_ENV):
        return True, f"{OVERRIDE_ENV} set by hand: {what} runs with no chat session open"
    return False, (
        f"refusing to start {what}: no gnoc chat session is open.\n"
        "Hunting is bound to a live chat (2026-11-02). Open one with `gnoc chat`, or set "
        f"{OVERRIDE_ENV}=1 for a single deliberate unattended run."
    )


# ------------------------------------------------------------------ open / close

def open_session(sid=None, program=None, kind="chat"):
    """Register THIS process as a live chat and arm the teardown. Idempotent per process."""
    if _MINE[0]:
        return _MINE[0]
    os.makedirs(SESSIONS, exist_ok=True)
    path = os.path.join(SESSIONS, f"{os.getpid()}.json")
    _write(path, {"pid": os.getpid(), "sid": sid, "program": program, "kind": kind,
                  "started": _now(), "lanes": []})
    _MINE[0] = path
    _arm()
    return path


def register_lane(pid, label="", pgid=None):
    """Record a lane this chat started, so closing the chat kills it. No session: no record."""
    if not _MINE[0]:
        return False
    try:
        pgid = int(pgid) if pgid is not None else os.getpgid(int(pid))
    except (OSError, ValueError, TypeError):
        pgid = None
    with _locked(_MINE[0]):
        rec = _read(_MINE[0])
        if not rec:
            return False
        rec.setdefault("lanes", []).append({"pid": int(pid), "pgid": pgid, "label": label,
                                            "started": _now()})
        _write(_MINE[0], rec)
    return True


def _signal_group(pid, pgid, sig):
    """Signal the lane's whole process group when we know it, else just the pid."""
    with contextlib.suppress(OSError, ValueError, TypeError):
        if pgid:
            os.killpg(pgid, sig)      # the whole lane tree, not just the driver
        else:
            os.kill(pid, sig)
        return True
    return False


def _kill_lanes(rec):
    """Terminate the lane process groups, give them a moment, then hard-kill what is left."""
    killed = []
    targets = []
    for lane in rec.get("lanes") or []:
        pid, pgid = lane.get("pid"), lane.get("pgid")
        if pid and _alive(pid):
            targets.append((pid, pgid, lane.get("label", "")))
    for pid, pgid, label in targets:
        if _signal_group(pid, pgid, _TERM):
            killed.append(label or str(pid))
    if targets:
        time.sleep(2)
        for pid, pgid, _label in targets:
            if _alive(pid):
                _signal_group(pid, pgid, _KILL)
    return killed


def close_session():
    """Kill this chat's lanes and deregister. Safe to call twice; safe to call with no session."""
    if _CLOSING[0] or not _MINE[0]:
        return []
    _CLOSING[0] = True
    path, _MINE[0] = _MINE[0], None
    rec = _read(path) or {}
    killed = _kill_lanes(rec)
    with contextlib.suppress(OSError):
        os.unlink(path)
    return killed


def _arm():
    """Close on every exit route a terminal actually takes."""
    import atexit
    atexit.register(close_session)
    for sig in _EXIT_SIGNALS:
        def _bye(signum, frame, _sig=sig):
            close_session()
            with contextlib.suppress(Exception):
                signal.signal(_sig, signal.SIG_DFL)
                os.kill(os.getpid(), _sig)
        with contextlib.suppress(Exception):
            signal.signal(sig, _bye)


# ------------------------------------------------------------------ cli

def _cmd_status():
    live = live_sessions()
    if not live:
        print("no gnoc chat session open - hunting is GATED OFF")
        return 1
    print(f"{len(live)} live chat session(s) - hunting is allowed")
    for rec in live:
        lanes = [la for la in (rec.get("lanes") or []) if _alive(la.get("pid"))]
        print(f"  pid {rec['pid']}  started {rec.get('started')}  "
              f"program {rec.get('program') or '-'}  lanes {len(lanes)}")
        for la in lanes:
            print(f"      lane pid {la['pid']}  {la.get('label', '')}")
    return 0


def main(argv):
    cmd = argv[0] if argv else "status"
    if cmd in ("status", "list"):
        return _cmd_status()
    if cmd == "allowed":
        ok = hunting_allowed()
        print("yes" if ok else "no")
        return 0 if ok else 1
    if cmd == "require":
        ok, why = require(" ".join(argv[1:]) or "this hunt")
        if not ok:
            print(why, file=sys.stderr)
            return 1
        if why:
            print(why, file=sys.stderr)
        return 0
    if cmd == "reap":
        live = live_sessions()
        print(f"reaped; {len(live)} live session(s) remain")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
