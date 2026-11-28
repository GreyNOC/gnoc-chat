#!/usr/bin/env python3
"""Prove the chat-bound hunting lifecycle: gate, lane teardown on exit, stale reap."""
import json
import os
import subprocess
import sys
import time

import tempfile

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
# Its OWN sessions folder. These checks start by emptying the folder and then assert that no chat is open: run
# against the live one they deleted the record of every chat GreyNOC had open (his hunting gate closed under him,
# his lanes were no longer tracked) and failed whenever a chat was open (2026-11-21).
_STATE = tempfile.mkdtemp(prefix="gnoc-session-test-")
_was = os.environ.get("GNOC_WS")
os.environ["GNOC_WS"] = _STATE
_shared = sys.modules.pop("gnoc_session", None)
import gnoc_session as S  # noqa: E402
assert S.SESSIONS.startswith(_STATE), S.SESSIONS
sys.modules.pop("gnoc_session", None)          # a private copy: other test files import their own
if _shared is not None:
    sys.modules["gnoc_session"] = _shared
# only this module and the stand-in chats it starts see the scratch folder: the rest of the suite keeps its own
if _was is None:
    del os.environ["GNOC_WS"]
else:
    os.environ["GNOC_WS"] = _was
CHILD_ENV = dict(os.environ, GNOC_WS=_STATE)

FAIL = []


def check(name, cond):
    print(("  PASS  " if cond else "  FAIL  ") + name)
    if not cond:
        FAIL.append(name)


# ---------- 1. gate is closed with no session
print("1. gate with no chat open")
for f in os.listdir(S.SESSIONS) if os.path.isdir(S.SESSIONS) else []:
    os.unlink(os.path.join(S.SESSIONS, f))
check("hunting_allowed() is False", S.hunting_allowed() is False)
ok, why = S.require("a lane")
check("require() refuses", ok is False and "no gnoc chat session" in why)

# ---------- 2. override escape hatch
print("2. deliberate override")
os.environ[S.OVERRIDE_ENV] = "1"
ok, why = S.require("a lane")
check("override permits and explains", ok is True and S.OVERRIDE_ENV in why)
del os.environ[S.OVERRIDE_ENV]

# ---------- 3. a child 'chat' opens a session, starts a lane, then exits
print("3. lane dies with the chat")
child = f"""
import os, sys, time
sys.path.insert(0, {os.path.join(WS, 'scripts')!r})
import gnoc_session as S
import subprocess
S.open_session(sid="test", program="program-64")
p = subprocess.Popen(["sleep", "300"], start_new_session=True)
S.register_lane(p.pid, label="test-lane")
print(p.pid, flush=True)
time.sleep(60)
"""
proc = subprocess.Popen([sys.executable, "-c", child], stdout=subprocess.PIPE, text=True, env=CHILD_ENV)
lane_pid = int(proc.stdout.readline().strip())
time.sleep(1)

check("session visible while chat is up", S.hunting_allowed() is True)
ok, _ = S.require("a lane")
check("require() permits while chat is up", ok is True)
check("lane process is running", S._alive(lane_pid))
recs = S.live_sessions()
check("session records the lane", bool(recs) and len(recs[0].get("lanes") or []) == 1)

# close the chat the way a terminal would: SIGTERM
proc.terminate()
proc.wait(timeout=20)
time.sleep(3)

check("lane was killed with the chat", not S._alive(lane_pid))
check("session file removed on exit", S.hunting_allowed() is False)

# ---------- 4. a crashed chat is reaped, not trusted
print("4. stale session reap")
os.makedirs(S.SESSIONS, exist_ok=True)
stale = os.path.join(S.SESSIONS, "999999.json")
with open(stale, "w") as fh:
    json.dump({"pid": 999999, "sid": "dead", "started": "x", "lanes": []}, fh)
check("stale file does not hold the gate open", S.hunting_allowed() is False)
check("stale file was deleted", not os.path.exists(stale))

# ---------- 5. hard-kill leaves a stale file that still gets reaped
print("5. hard-killed chat (SIGKILL) is reaped")
proc2 = subprocess.Popen([sys.executable, "-c", child], stdout=subprocess.PIPE, text=True, env=CHILD_ENV)
lane2 = int(proc2.stdout.readline().strip())
time.sleep(1)
check("gate open while chat alive", S.hunting_allowed() is True)
proc2.kill()
proc2.wait(timeout=20)
check("gate closed after hard kill (reaped)", S.hunting_allowed() is False)
time.sleep(3)
check("orphaned lane killed by the reaper", not S._alive(lane2))
if S._alive(lane2):
    os.killpg(os.getpgid(lane2), 9)

# ---------- 6. Ctrl-C reaches the chat as KeyboardInterrupt (2026-11-10: it used to kill the process)
print("6. SIGINT is a KeyboardInterrupt, not a teardown")
child_int = f"""
import os, sys, time, signal
sys.path.insert(0, {os.path.join(WS, 'scripts')!r})
import gnoc_session as S
S.open_session(sid="test-int", program="program-64")
print("default" if signal.getsignal(signal.SIGINT) is signal.default_int_handler else "overridden", flush=True)
try:
    time.sleep(60)
except KeyboardInterrupt:
    print("caught", flush=True)
"""
proc3 = subprocess.Popen([sys.executable, "-c", child_int], stdout=subprocess.PIPE, text=True, env=CHILD_ENV)
handler = proc3.stdout.readline().strip()
check("open_session leaves the default SIGINT handler", handler == "default")
time.sleep(0.5)
import signal as _sig
proc3.send_signal(_sig.SIGINT)
got = proc3.stdout.readline().strip()
check("SIGINT raised KeyboardInterrupt inside the chat", got == "caught")
proc3.wait(timeout=20)
check("session file closed on the normal exit that followed", S.hunting_allowed() is False)

print()
print(("FAILED: " + ", ".join(FAIL)) if FAIL else "ALL CHECKS PASSED")


def test_every_check_passed():
    """pytest entry: the checks above run at import; this fails if any of them did."""
    assert not FAIL, FAIL


if __name__ == "__main__":
    sys.exit(1 if FAIL else 0)
