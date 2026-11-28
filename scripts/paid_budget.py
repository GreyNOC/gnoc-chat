#!/usr/bin/env python3
"""paid_budget.py - monthly ceiling + per-run wall-clock cap for unattended paid `claude -p` runs.

State: <root>/.claude/state/orch/paid-budget.json  {"month": "YYYY-MM", "runs": N, "cap": 120, "notice_day": "YYYY-MM-DD"}
Cap comes from env PAID_RUNS_MONTHLY_CAP (default 120). reserve() increments under flock + atomic replace.

CLI (used to wrap detached children so a wall-clock cap can write the INBOX note):
  paid_budget.py run --timeout SECS --label NAME -- cmd args...
"""
import fcntl
import json
import os
import signal
import subprocess
import sys
from datetime import datetime

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _paths(root):
    d = os.path.join(root, ".claude/state/orch")
    return d, os.path.join(d, "paid-budget.json"), os.path.join(d, "INBOX.md")


def cap_from_env():
    try:
        return max(0, int(os.environ.get("PAID_RUNS_MONTHLY_CAP", "120")))
    except ValueError:
        return 120


def inbox(root, kind, msg):
    d, _, ib = _paths(root)
    os.makedirs(d, exist_ok=True)
    line = ""
    if not os.path.isfile(ib):
        line += "# ORCH INBOX - items the bot cannot decide (newest last). Clear a line when handled.\n\n"
    line += f"- [{datetime.now().astimezone().isoformat(timespec='seconds')}] **{kind}** {msg}\n"
    fd = os.open(ib, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o664)
    try:
        os.write(fd, line.encode("utf-8")[:4000])
    finally:
        os.close(fd)


def reserve(root=DEFAULT_ROOT, label="paid", now=None):
    """Atomically count one paid dispatch. Returns (allowed, runs, cap). At/over cap: not counted, one INBOX line per day."""
    now = now or datetime.now()
    d, bf, _ = _paths(root)
    os.makedirs(d, exist_ok=True)
    cap = cap_from_env()
    with open(bf + ".lock", "a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            with open(bf) as fh:
                st = json.load(fh)
            if not isinstance(st, dict):
                st = {}
        except (OSError, ValueError):
            st = {}
        month = now.strftime("%Y-%m")
        if st.get("month") != month:
            st = {"month": month, "runs": 0}
        st["cap"] = cap
        runs = int(st.get("runs", 0))
        ok = runs < cap
        if ok:
            st["runs"] = runs + 1
        else:
            day = now.strftime("%Y-%m-%d")
            if st.get("notice_day") != day:
                st["notice_day"] = day
                inbox(root, "PAID-BUDGET", f"monthly paid-run cap {cap} reached ({runs} runs in {month}); "
                                           f"skipped {label}. Raise PAID_RUNS_MONTHLY_CAP to continue.")
        tmp = bf + f".tmp{os.getpid()}"
        with open(tmp, "w") as fh:
            json.dump(st, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, bf)
        return ok, int(st.get("runs", 0)), cap


def run_capped(cmd, timeout, label, root=DEFAULT_ROOT, **popen_kw):
    """Run cmd; on wall-clock expiry kill its process group and write a 'capped' INBOX line. Returns rc (124 on cap)."""
    p = subprocess.Popen(cmd, start_new_session=True, **popen_kw)
    try:
        return p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(p.pid, sig)
            except OSError:
                break
            try:
                p.wait(timeout=20)
                break
            except subprocess.TimeoutExpired:
                continue
        inbox(root, "PAID-CAPPED", f"{label} hit its {int(timeout // 60)}m wall-clock cap and was killed")
        return 124


def _main(argv):
    if len(argv) > 1 and argv[1] == "run" and "--" in argv:
        i = argv.index("--")
        opts, cmd = argv[2:i], argv[i + 1:]
        o = dict(zip(opts[::2], opts[1::2]))
        root = o.get("--root", DEFAULT_ROOT)
        return run_capped(cmd, float(o.get("--timeout", "900")), o.get("--label", "paid run"), root)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
