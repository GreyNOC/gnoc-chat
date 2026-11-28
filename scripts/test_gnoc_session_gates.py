#!/usr/bin/env python3
"""With a chat session open, the gates must PERMIT. Proves the gate is not simply always-closed."""
import os
import subprocess
import sys
import time

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
import gnoc_session as S  # noqa: E402

FAIL = []


def check(name, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + name + (f"   {detail}" if detail and not cond else ""))
    if not cond:
        FAIL.append(name)


# stand up a fake chat session that just sleeps
child = f"""
import os, sys, time
sys.path.insert(0, {os.path.join(WS, 'scripts')!r})
import gnoc_session as S
S.open_session(sid="gatetest", program="program-64")
print("up", flush=True)
time.sleep(90)
"""
proc = subprocess.Popen([sys.executable, "-c", child], stdout=subprocess.PIPE, text=True)
proc.stdout.readline()
time.sleep(1)

try:
    check("gate reports allowed", S.hunting_allowed() is True)

    # the lane harness must get PAST the session gate (it will then fail on its own
    # preconditions - empty brief/probes, ollama - which is exactly what we want to see)
    r = subprocess.run(["bash", os.path.join(WS, "scripts/opencode-lane.sh"),
                        "program-64", "zzz-gate-test", "/dev/null", "/dev/null"],
                       capture_output=True, text=True, cwd=WS, timeout=60)
    out = (r.stdout + r.stderr)
    check("lane harness passes the session gate", "no gnoc chat session is open" not in out,
          out[:200])
    check("lane harness then stops on its own preconditions", r.returncode != 0, f"rc={r.returncode}")

    # auto-hunt --plan is read-only and must work regardless
    r2 = subprocess.run([sys.executable, os.path.join(WS, "scripts/auto-hunt.py"),
                         "program-64", "--plan"], capture_output=True, text=True, cwd=WS, timeout=120)
    out2 = r2.stdout + r2.stderr
    check("auto-hunt --plan not gate-blocked", "no gnoc chat session is open" not in out2, out2[:200])
    if os.path.isfile(os.path.join(WS, "targets", "program-64", "SCOPE.txt")):
        check("auto-hunt --plan (read-only) runs", r2.returncode == 0, out2[:200])
    else:   # a fresh workspace (the public build) has no programs: past the gate, the plan stops on its own check
        check("auto-hunt --plan stops on its own precondition", "no scope.txt" in out2.lower(), out2[:200])

    # auto-target --rank is read-only and must work regardless
    r3 = subprocess.run([sys.executable, os.path.join(WS, "scripts/auto-target.py"), "--rank"],
                        capture_output=True, text=True, cwd=WS, timeout=180)
    check("auto-target --rank (read-only) runs", r3.returncode == 0, (r3.stdout + r3.stderr)[:200])
    check("auto-target --rank not gate-blocked",
          "no gnoc chat session is open" not in (r3.stdout + r3.stderr))
finally:
    proc.terminate()
    proc.wait(timeout=20)
    time.sleep(1)

# THIS chat's session is gone. It used to assert that NO chat was open, which failed whenever GreyNOC had one
# open (2026-11-21): his chat is not this test's to judge.
check("gate closed again after the chat exits", not any(r.get("pid") == proc.pid for r in S.live_sessions()))

print()
print(("FAILED: " + ", ".join(FAIL)) if FAIL else "ALL CHECKS PASSED")


def test_every_check_passed():
    """pytest entry: the checks above run at import; this fails if any of them did."""
    assert not FAIL, FAIL


if __name__ == "__main__":
    sys.exit(1 if FAIL else 0)
