#!/usr/bin/env python3
"""lib_state - shared state-file helpers for the daemons and the dashboard (harmony 2.6, 2026-10-21). Stdlib only.

    from bbtools import lib_state
    lib_state.atomic_write_json(path, obj)          # tmp in the same dir, fsync, os.replace
    with lib_state.locked(path):                    # fcntl.flock on path + ".lock"
        st = lib_state.load_json(path, {}, strict=True)   # strict: a torn file RAISES, never a silent default
    lib_state.active_programs()                     # ONE answer for "what is being hunted right now"

active_programs(root, max_age_s=86400) -> {"auto": str|None, "global_lock": str|None,
    "session_locks": [(sid, prog, mtime)], "fleet": [prog]}
  - auto: first token of orch/AUTO-HUNT unless it is the mode word "target"
  - global_lock: first non-comment token of hunt-loop/LOCK
  - session_locks: hunt-loop/LOCK.<sid> newer than max_age_s (a dead session's lock is NOT active;
    gnoc d_system already applied this 24 h rule, oss-bot tiers() did not)
  - fleet: hunt-loop/fleet/claims/<prog> with an owner file and a live pid
This is a READER for display and tiering only. The scope authority stays scope-gate.sh / lock-lib.sh
(HUNT_TARGET > LOCK.<sid> > LOCK); nothing here decides what a host may be probed against.

CLI: --selfcheck (offline, temp dirs), or no argument = print active_programs() as JSON.
"""
from __future__ import annotations
import contextlib
import errno
import fcntl
import glob
import json
import os
import sys
import tempfile
import time

WS_ROOT = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def atomic_write_text(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def atomic_write_json(path: str, obj, indent: int = 1) -> None:
    atomic_write_text(path, json.dumps(obj, indent=indent) + "\n")


@contextlib.contextmanager
def locked(path: str, timeout: float | None = 30.0, blocking: bool = True):
    """Exclusive flock on path + '.lock'. blocking=False raises BlockingIOError at once on contention;
    blocking with a timeout raises TimeoutError when it expires (None = wait forever)."""
    lp = path + ".lock"
    os.makedirs(os.path.dirname(os.path.abspath(lp)) or ".", exist_ok=True)
    fd = os.open(lp, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        if not blocking:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif timeout is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            end = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError as e:
                    if e.errno not in (errno.EAGAIN, errno.EACCES):
                        raise
                    if time.monotonic() >= end:
                        raise TimeoutError(f"lock busy: {lp}")
                    time.sleep(0.05)
        yield
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def load_json(path: str, default=None, *, strict: bool = False):
    """Missing file -> default (both modes). Unparseable file -> default, or ValueError when strict, so a
    read-modify-write caller never writes a default back over a torn file."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return default
    try:
        return json.loads(raw)
    except ValueError as e:
        if strict:
            raise ValueError(f"torn or invalid JSON in {path}: {e}") from e
        return default


def _first_token(path: str):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                tok = ln.split("#", 1)[0].split()
                if tok:
                    return tok[0]
    except OSError:
        pass
    return None


def _pid_alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
        return True
    except (ValueError, TypeError, ProcessLookupError):
        return False
    except PermissionError:
        return True


def active_programs(root: str = WS_ROOT, max_age_s: float = 86400, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    hl = os.path.join(root, ".claude/state/hunt-loop")
    auto = _first_token(os.path.join(root, ".claude/state/orch/AUTO-HUNT"))
    if auto == "target":
        auto = None
    sess = []
    for f in sorted(glob.glob(os.path.join(hl, "LOCK.*"))):
        base = os.path.basename(f)
        if base.endswith((".lock", ".tmp")) or ".bak" in base:
            continue
        try:
            mt = os.path.getmtime(f)
        except OSError:
            continue
        prog = _first_token(f)
        if prog and now - mt < max_age_s:
            sess.append((base[5:], prog, mt))
    fleet = []
    for d in sorted(glob.glob(os.path.join(hl, "fleet", "claims", "*"))):
        pid = (_first_token(os.path.join(d, "pid")) or "")
        if os.path.isfile(os.path.join(d, "owner")) and pid and _pid_alive(pid):
            fleet.append(os.path.basename(d))
    return {"auto": auto, "global_lock": _first_token(os.path.join(hl, "LOCK")),
            "session_locks": sorted(sess, key=lambda s: -s[2]), "fleet": fleet}


def active_set(ap: dict) -> set:
    """Union of every active program in an active_programs() result."""
    s = set(ap.get("fleet") or []) | {p for _, p, _ in ap.get("session_locks") or []}
    s |= {p for p in (ap.get("global_lock"), ap.get("auto")) if p}
    return s


def selfcheck() -> None:
    with tempfile.TemporaryDirectory() as root:
        p = os.path.join(root, "x", "s.json")
        atomic_write_json(p, {"a": 1})
        assert load_json(p, {}, strict=True) == {"a": 1}
        assert not [f for f in os.listdir(os.path.dirname(p)) if f.endswith(".tmp")], "tmp left behind"
        atomic_write_text(p, '{"a": 1, "sw')                      # a torn file
        assert load_json(p, {"d": 0}) == {"d": 0}
        try:
            load_json(p, {}, strict=True)
            raise AssertionError("strict load did not raise on a torn file")
        except ValueError:
            pass
        assert load_json(os.path.join(root, "missing.json"), [], strict=True) == []
        with locked(p):
            try:
                with locked(p, blocking=False):
                    raise AssertionError("second exclusive lock was granted")
            except BlockingIOError:
                pass
        with locked(p, blocking=False):                            # released after the with
            pass
        hl = os.path.join(root, ".claude/state/hunt-loop")
        od = os.path.join(root, ".claude/state/orch")
        os.makedirs(os.path.join(hl, "fleet", "claims", "liveprog"))
        os.makedirs(os.path.join(hl, "fleet", "claims", "deadprog"))
        os.makedirs(od)
        now = time.time()
        for sid, prog, age in (("old", "staleprog", 25 * 3600), ("new", "freshprog", 3600)):
            f = os.path.join(hl, f"LOCK.{sid}")
            atomic_write_text(f, prog + "\n")
            os.utime(f, (now - age, now - age))
        atomic_write_text(os.path.join(hl, "LOCK"), "# comment\nglobprog\n")
        atomic_write_text(os.path.join(od, "AUTO-HUNT"), "autoprog target\n")
        for name, pid in (("liveprog", os.getpid()), ("deadprog", 2 ** 22 + 7)):
            atomic_write_text(os.path.join(hl, "fleet", "claims", name, "owner"), "t\n")
            atomic_write_text(os.path.join(hl, "fleet", "claims", name, "pid"), f"{pid}\n")
        ap = active_programs(root, now=now)
        assert [s[1] for s in ap["session_locks"]] == ["freshprog"], ap
        assert ap["global_lock"] == "globprog" and ap["auto"] == "autoprog" and ap["fleet"] == ["liveprog"], ap
        assert active_set(ap) == {"freshprog", "globprog", "autoprog", "liveprog"}
        atomic_write_text(os.path.join(od, "AUTO-HUNT"), "target\n")
        assert active_programs(root, now=now)["auto"] is None
    print("lib_state selfcheck: PASS (atomic write, torn-file strict raise, flock exclusion, "
          "25 h session lock dropped, 1 h kept, dead fleet pid dropped)")


if __name__ == "__main__":
    if sys.argv[1:] == ["--selfcheck"]:
        selfcheck()
    else:
        print(json.dumps(active_programs(), indent=1))
