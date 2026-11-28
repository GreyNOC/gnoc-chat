#!/usr/bin/env python3
"""
browser-budget.py - keep a browser swarm from wedging the user's desktop.

RECEIPT that bought this file (2026-11-08, cost: a frozen desktop and a hard reboot
mid-filing). While the program-28 Vault report was being finished, a lane
(targets/program-28/hunts/selforigin-20261108/spray3.py) launched browsers in a
loop. Over that boot 237 Chromium instances started; three went long-lived at 4.8 GB
/ 20m55s CPU, 4.5 GB / 18m50s CPU and 2.9 GB. No OOM kill fired - the box has 30 GB.
What died was the COMPOSITOR: kwin_wayland_drm logged "The main thread was hanging
temporarily!" continuously from 12:10:04 until the 12:54 reboot, with libinput
reporting input "lagging behind ... your system is too slow". The desktop was
unusable and the session was lost.

WHY THIS LAYER AND NOT A LIBRARY CAP. The lane did not go through lib_browser. It
imported playwright.async_api directly and called chromium.launch_persistent_context
itself, so a semaphore inside lib_browser would NOT have stopped this incident. A
guard is only worth its receipt if it binds every launcher, including a worker script
written five minutes ago. This enforces at the PROCESS layer, where they all land.

WHAT IT DOES. Censuses live browser instances, compares them against a budget, and
reaps the NEWEST offenders (never the oldest, which is normally the operator's own
Chrome). Three enforcement triggers, any one of which fires:
  - instance count over MAX_LANE_BROWSERS
  - total browser RSS over MAX_TOTAL_RSS_GB
  - a single instance over MAX_PER_INSTANCE_RSS_GB  (the 4.8 GB shape above)

WHAT IT NEVER TOUCHES. The operator's own CDP Chrome, identified by
--remote-debugging-port plus the persistent bb-hunt profile (scripts/cdp-chrome.sh).
That browser holds their real logins; killing it would cost more than the swarm did.
It is exempt from the count and never reaped.

DESKTOP EXCLUSIVITY. Raw Burp panel capture needs the live desktop to itself (the
other half of the same incident). While the panel lock is held, the lane budget drops
to zero, so a lane cannot start a browser underneath a capture.

USAGE
  scripts/browser-budget.py status            one-screen census + budget verdict
  scripts/browser-budget.py reap              one-shot enforcement pass
  scripts/browser-budget.py watch             supervise continuously (the backstop)
  scripts/browser-budget.py lint <path..>     flag scripts that bypass lib_browser
  scripts/browser-budget.py lock <cmd..>      hold the desktop lock while cmd runs
  scripts/browser-budget.py selfcheck         offline logic check, no processes killed

Budget overrides (env): BB_MAX_BROWSERS, BB_MAX_TOTAL_RSS_GB, BB_MAX_RSS_GB,
BB_WATCH_INTERVAL, BB_GRACE_SEC. Set BB_BUDGET_DRYRUN=1 to log without killing.
"""
import os
import re
import signal
import subprocess
import sys
import time

WS = os.environ.get("WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
STATE = os.path.join(WS, ".claude/state/browser-budget")
EVENTS = os.path.join(STATE, "events.log")
DESKTOP_LOCK = os.path.join(STATE, "desktop.lock")

# Budget. Chosen against the incident: the swarm that wedged the compositor ran three
# instances over 2.9 GB at once, so a per-instance ceiling of 2.5 GB plus a total of
# 6 GB stops that shape while leaving room for a normal 2-3 browser lane.
#
# THE TOTAL MUST SIT BELOW count x per-instance, or it is dead config. The first draft
# of this file used 8 GB against a cap of 3 x 2.5 GB, whose maximum reachable total is
# 7.5 GB - the ceiling could never fire and the selfcheck caught it. At 6 GB all three
# triggers are live: three 2.4 GB instances each pass the per-instance ceiling and the
# count cap, and are still stopped.
MAX_LANE_BROWSERS = int(os.environ.get("BB_MAX_BROWSERS", "3"))
MAX_TOTAL_RSS_GB = float(os.environ.get("BB_MAX_TOTAL_RSS_GB", "6"))
MAX_PER_INSTANCE_RSS_GB = float(os.environ.get("BB_MAX_RSS_GB", "2.5"))
WATCH_INTERVAL = float(os.environ.get("BB_WATCH_INTERVAL", "5"))
GRACE_SEC = float(os.environ.get("BB_GRACE_SEC", "3"))
DRYRUN = os.environ.get("BB_BUDGET_DRYRUN") == "1"

BROWSER_RE = re.compile(r"(^|/)(chrome|chromium|chromium-browser|chrome-headless-shell|"
                        r"headless_shell|google-chrome|google-chrome-stable|msedge|firefox)$")
# The operator's own Chrome: a debugging port AND the persistent bb-hunt profile.
OPERATOR_PROFILE_RE = re.compile(r"--user-data-dir=\S*(bb-hunt/chrome-profile|\.config/gnoc)")
DEBUG_PORT_RE = re.compile(r"--remote-debugging-port=(\d+)")


def log(msg):
    line = f"[{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}] {msg}"
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(EVENTS, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def _read(path, default=""):
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return default


def _mem_bytes(pid):
    """Proportional set size for one process, falling back to RSS.

    MEASURED 2026-11-08 on this box: four trivial `about:blank` headless browsers
    summed to 5048 MB of RSS but only 1073 MB of PSS, a 4.7x overcount, because a
    chrome tree shares most of its mapped pages between the main process and every
    renderer and plain RSS counts each copy. Budgeting on RSS would have reaped
    perfectly healthy lanes well under the real ceiling. PSS divides a shared page by
    the number of processes mapping it, so a tree's PSS sums to its true footprint.
    smaps_rollup is one read per process; the fallback keeps the watchdog working if
    it is ever unreadable.
    """
    for line in _read(f"/proc/{pid}/smaps_rollup").splitlines():
        if line.startswith("Pss:"):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1]) * 1024
    statm = _read(f"/proc/{pid}/statm").split()
    if len(statm) > 1 and statm[1].isdigit():
        return int(statm[1]) * os.sysconf("SC_PAGE_SIZE")
    return 0


def classify(pid, cmdline, exe_base):
    """Return the role of a browser process.

    Only a MAIN browser process counts against the budget. Chromium's renderer, gpu
    and utility children all carry --type=<role>; the main process never does. Counting
    every chrome pid would read a single normal browser as a dozen instances and reap
    a healthy session.
    """
    if " --type=" in cmdline or cmdline.startswith("--type="):
        return "child"
    if not BROWSER_RE.search(exe_base):
        return "other"
    if DEBUG_PORT_RE.search(cmdline) and OPERATOR_PROFILE_RE.search(cmdline):
        return "operator"
    return "lane"


def is_headless(cmdline):
    """Does this browser contend for the desktop?

    MEASURED 2026-11-08 while testing this file: the desktop lock reaped a browser
    belonging to a DIFFERENT Claude session running a localhost QA suite
    (scripts/qa-teach-authoring.mjs). That browser was headless, so it could never
    have wedged the compositor the lock exists to protect - the lock was destroying
    unrelated work for no safety gain. A headless browser still burns CPU and memory,
    so it stays bound by the count and memory caps; it is only exempt from the
    desktop-exclusivity rule, which is about the GUI.
    """
    return "--headless" in cmdline or "headless_shell" in cmdline


def census():
    """Every live browser process, with role, RSS and start time. /proc only, no deps."""
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        cmdline = _read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
        if not cmdline:
            continue
        comm = _read(f"/proc/{pid}/comm").strip()
        try:
            exe = os.path.realpath(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        exe_base = os.path.basename(exe) or comm
        if not BROWSER_RE.search(exe_base) and not BROWSER_RE.search(comm):
            continue
        role = classify(pid, cmdline, exe_base or comm)
        if role == "other":
            continue
        rss_bytes = _mem_bytes(pid)
        try:
            start = os.stat(f"/proc/{pid}").st_mtime
        except OSError:
            start = 0.0
        try:
            pgid = os.getpgid(pid)
        except (OSError, ProcessLookupError):
            pgid = pid
        out.append({"pid": pid, "pgid": pgid, "role": role, "cmd": cmdline,
                    "exe": exe_base or comm, "rss": rss_bytes, "start": start})
    return out


def rollup(procs):
    """Group child RSS onto its main process so a budget reflects the real footprint.

    A main chrome process is small; its renderers hold the memory. The 4.8 GB peak in
    the incident was a TREE. Attributing only the main process RSS would read that
    tree as ~300 MB and never trip the ceiling.
    """
    mains = [p for p in procs if p["role"] in ("lane", "operator")]
    by_pid = {p["pid"]: p for p in procs}
    for m in mains:
        m["tree_rss"] = m["rss"]
    # Walk every browser child up to its nearest main ancestor.
    for p in procs:
        if p["role"] != "child":
            continue
        cur, hops = p["pid"], 0
        while cur > 1 and hops < 24:
            ppid_line = [l for l in _read(f"/proc/{cur}/status").splitlines()
                         if l.startswith("PPid:")]
            if not ppid_line:
                break
            try:
                cur = int(ppid_line[0].split()[1])
            except (IndexError, ValueError):
                break
            hops += 1
            anc = by_pid.get(cur)
            if anc and anc["role"] in ("lane", "operator"):
                anc["tree_rss"] = anc.get("tree_rss", anc["rss"]) + p["rss"]
                break
    return mains


def desktop_locked():
    """True when a raw Burp panel capture owns the desktop. A stale lock from a killed
    process must not wedge the budget at zero forever, so the holder pid is verified."""
    txt = _read(DESKTOP_LOCK).strip()
    if not txt:
        return False
    holder = txt.split()[0]
    if holder.isdigit() and not os.path.exists(f"/proc/{holder}"):
        try:
            os.unlink(DESKTOP_LOCK)
        except OSError:
            pass
        log(f"desktop lock: cleared stale holder pid {holder}")
        return False
    return True


GB = float(1 << 30)


def verdict(mains, locked):
    """Decide which instances to reap. Returns (reasons, [victims newest-first])."""
    lanes = [m for m in mains if m["role"] == "lane"]
    lanes.sort(key=lambda m: m["start"], reverse=True)  # newest first
    budget = 0 if locked else MAX_LANE_BROWSERS
    reasons, victims = [], []

    fat = [m for m in lanes if m.get("tree_rss", 0) > MAX_PER_INSTANCE_RSS_GB * GB]
    for m in fat:
        reasons.append(f"instance pid {m['pid']} tree RSS "
                       f"{m.get('tree_rss', 0) / GB:.1f} GB over per-instance ceiling "
                       f"{MAX_PER_INSTANCE_RSS_GB} GB")
        victims.append(m)

    survivors = [m for m in lanes if m not in victims]
    if locked:
        # The lock protects the GUI, so it only displaces browsers that use the GUI.
        headed = [m for m in survivors if not is_headless(m["cmd"])]
        if headed:
            reasons.append(f"desktop lock held, reaping {len(headed)} headed browser(s); "
                           f"headless lanes are left running")
            victims.extend(headed)
            survivors = [m for m in survivors if m not in headed]
        budget = MAX_LANE_BROWSERS
    if len(survivors) > budget:
        over = survivors[: len(survivors) - budget]
        reasons.append(f"{len(survivors)} lane browsers over cap {budget}")
        victims.extend(over)
        survivors = survivors[len(survivors) - budget:]

    total = sum(m.get("tree_rss", 0) for m in survivors)
    while total > MAX_TOTAL_RSS_GB * GB and survivors:
        m = survivors.pop(0)
        reasons.append(f"total lane RSS {total / GB:.1f} GB over "
                       f"{MAX_TOTAL_RSS_GB} GB, reaping pid {m['pid']}")
        victims.append(m)
        total = sum(s.get("tree_rss", 0) for s in survivors)

    # De-dupe, keep order.
    seen, uniq = set(), []
    for m in victims:
        if m["pid"] not in seen:
            seen.add(m["pid"])
            uniq.append(m)
    return reasons, uniq


def reap(victims):
    """SIGTERM the process group, then SIGKILL what is left. A browser spawns a tree;
    signalling only the main pid orphans its renderers, which keep the memory."""
    for m in victims:
        tag = f"pid {m['pid']} pgid {m['pgid']} rss {m.get('tree_rss', 0) / GB:.1f}GB"
        if DRYRUN:
            log(f"DRYRUN would reap {tag}: {m['cmd'][:120]}")
            continue
        for sig, name in ((signal.SIGTERM, "TERM"), (None, None)):
            if sig is None:
                time.sleep(GRACE_SEC)
                if not os.path.exists(f"/proc/{m['pid']}"):
                    log(f"reaped {tag} on TERM")
                    break
                try:
                    os.killpg(m["pgid"], signal.SIGKILL)
                    log(f"reaped {tag} on KILL (survived TERM)")
                except (OSError, ProcessLookupError) as exc:
                    log(f"reap {tag}: {exc}")
                break
            try:
                os.killpg(m["pgid"], sig)
            except (OSError, ProcessLookupError):
                try:
                    os.kill(m["pid"], sig)
                except (OSError, ProcessLookupError) as exc:
                    log(f"reap {tag}: already gone ({exc})")
                    break


def enforce():
    procs = census()
    mains = rollup(procs)
    locked = desktop_locked()
    reasons, victims = verdict(mains, locked)
    if not victims:
        return 0
    for r in reasons:
        log(f"BUDGET: {r}")
    reap(victims)
    return len(victims)


def cmd_status():
    procs = census()
    mains = rollup(procs)
    locked = desktop_locked()
    lanes = [m for m in mains if m["role"] == "lane"]
    oper = [m for m in mains if m["role"] == "operator"]
    total = sum(m.get("tree_rss", 0) for m in lanes) / GB
    print(f"budget      : max {MAX_LANE_BROWSERS} lane browsers, "
          f"{MAX_TOTAL_RSS_GB} GB total, {MAX_PER_INSTANCE_RSS_GB} GB per instance")
    print(f"desktop lock: "
          f"{'HELD (headed lanes displaced, headless still capped)' if locked else 'free'}")
    print(f"operator    : {len(oper)} exempt browser(s) - never counted, never reaped")
    for m in oper:
        port = DEBUG_PORT_RE.search(m["cmd"])
        print(f"  pid {m['pid']}  port {port.group(1) if port else '?'}  "
              f"{m.get('tree_rss', 0) / GB:.2f} GB")
    print(f"lane        : {len(lanes)} browser(s), {total:.2f} GB total")
    for m in sorted(lanes, key=lambda x: x.get("tree_rss", 0), reverse=True):
        print(f"  pid {m['pid']}  {m.get('tree_rss', 0) / GB:.2f} GB  "
              f"age {int(time.time() - m['start'])}s  {m['exe']}")
    reasons, victims = verdict(mains, locked)
    if victims:
        print(f"VERDICT     : OVER BUDGET, {len(victims)} would be reaped")
        for r in reasons:
            print(f"  - {r}")
        return 1
    print("VERDICT     : within budget")
    return 0


def cmd_watch():
    log(f"watch: start, cap {MAX_LANE_BROWSERS} browsers / {MAX_TOTAL_RSS_GB} GB total "
        f"/ {MAX_PER_INSTANCE_RSS_GB} GB each, interval {WATCH_INTERVAL}s"
        + (" DRYRUN" if DRYRUN else ""))
    while True:
        try:
            enforce()
        except Exception as exc:  # a watchdog that dies on a transient /proc race is no watchdog
            log(f"watch: non-fatal {type(exc).__name__}: {exc}")
        time.sleep(WATCH_INTERVAL)


# Only an actual LAUNCH counts. The first draft of this lint matched any mention of
# playwright and reported 743 files, including an analysis script whose only sin was
# grepping for the word "playwright" - a number that large is noise nobody will act on.
# Attaching to an already-running browser (connect_over_cdp) starts no process and is
# deliberately not flagged.
BYPASS_RE = re.compile(r"\b(?:chromium|firefox|webkit)\s*\.\s*"
                       r"(?:launch|launch_persistent_context)\s*\(")
_LINT_SKIP = ("/scripts/learn/out/", "/h1-feedback/", "/node_modules/", "/__pycache__/",
              "/salvage/", "/bb-hunt-system/", ".bak")


def cmd_lint(paths):
    """Flag a script that launches a browser without going through lib_browser.

    This is the exact bypass that caused the incident, and it is visible in the source
    before the script ever runs.
    """
    hits = 0
    for path in paths:
        if os.path.isdir(path):
            files = [os.path.join(dp, f) for dp, _, fs in os.walk(path)
                     for f in fs if f.endswith(".py")]
        else:
            files = [path]
        files = [f for f in files if not any(s in f for s in _LINT_SKIP)]
        for f in files:
            txt = _read(f)
            if not BYPASS_RE.search(txt):
                continue
            if "lib_browser" in txt or "browser-budget" in txt:
                continue
            hits += 1
            if hits <= 10:   # a 444-line wall is not actionable; show a sample
                bad = next((f"{i}:{l.strip()[:88]}"
                            for i, l in enumerate(txt.splitlines(), 1)
                            if BYPASS_RE.search(l)), "")
                print(f"BYPASS {f}\n  {bad}")
    if hits:
        if hits > 10:
            print(f"  ... and {hits - 10} more")
        print(f"\n{hits} script(s) launch a browser outside lib_browser.")
        print("The process watchdog (browser-budget.py watch) caps them regardless, so "
              "these are\nnot an emergency - 444 of them are throwaway scripts from past "
              "hunt lanes. What\nmatters is NEW lane code: route it through\n"
              "  from bbtools.lib_browser import browser\n"
              "which holds a launch slot and WAITS instead of piling up and being reaped.")
        return 1
    print("no bypass found")
    return 0


def cmd_lock(argv):
    """Hold the desktop lock for the duration of a command (panel capture)."""
    if not argv:
        print("usage: browser-budget.py lock <command> [args..]", file=sys.stderr)
        return 2
    os.makedirs(STATE, exist_ok=True)
    try:
        fd = os.open(DESKTOP_LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        if desktop_locked():
            holder = _read(DESKTOP_LOCK).strip()
            print(f"desktop lock already held by: {holder}", file=sys.stderr)
            return 3
        fd = os.open(DESKTOP_LOCK, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
    os.write(fd, f"{os.getpid()} {' '.join(argv)}\n".encode())
    os.close(fd)
    log(f"desktop lock: held by pid {os.getpid()} for {argv[0]}")
    try:
        enforce()  # clear any lane browser standing in the capture's way
        return subprocess.call(argv)
    finally:
        try:
            os.unlink(DESKTOP_LOCK)
        except OSError:
            pass
        log(f"desktop lock: released by pid {os.getpid()}")


def cmd_selfcheck():
    """Offline logic check. Kills nothing, needs no live browser."""
    fails = []

    def eq(label, got, want):
        if got != want:
            fails.append(f"{label}: got {got!r} want {want!r}")

    eq("renderer is a child",
       classify(1, "/opt/chrome --type=renderer --lang=en", "chrome"), "child")
    eq("gpu process is a child",
       classify(1, "/opt/chrome --type=gpu-process", "chrome"), "child")
    eq("plain headless chrome is a lane",
       classify(1, "/opt/chrome --headless --no-sandbox", "chrome"), "lane")
    eq("operator chrome is exempt",
       classify(1, "/usr/bin/google-chrome --remote-debugging-port=9222 "
                   "--user-data-dir=~/.config/gnoc/chrome-profile",
                "google-chrome"), "operator")
    eq("a debug port on a throwaway profile is still a lane",
       classify(1, "/opt/chrome --remote-debugging-port=9222 --user-data-dir=/tmp/x",
                "chrome"), "lane")
    eq("non-browser ignored", classify(1, "/usr/bin/python3 spray.py", "python3"), "other")

    eq("headless flag detected", is_headless("/opt/chrome --headless=new"), True)
    eq("headless_shell binary detected", is_headless("/opt/headless_shell --x"), True)
    eq("headed browser detected", is_headless("/opt/chrome --no-sandbox"), False)

    now = time.time()
    def mk(pid, gb, age, role="lane", cmd="c"):
        return {"pid": pid, "pgid": pid, "role": role, "cmd": cmd, "exe": "chrome",
                "rss": 0, "start": now - age, "tree_rss": int(gb * GB)}

    # The incident shape: three fat instances. Each trips the per-instance ceiling.
    r, v = verdict([mk(1, 4.8, 300), mk(2, 4.5, 280), mk(3, 2.9, 200)], False)
    eq("incident shape is fully reaped", len(v), 3)

    # Within budget: three small browsers, nothing reaped.
    r, v = verdict([mk(1, 0.3, 300), mk(2, 0.3, 200), mk(3, 0.3, 100)], False)
    eq("three small browsers pass", len(v), 0)

    # Over the count cap: newest reaped, oldest kept.
    r, v = verdict([mk(1, 0.2, 400), mk(2, 0.2, 300), mk(3, 0.2, 200), mk(4, 0.2, 10)], False)
    eq("one over cap reaps one", len(v), 1)
    eq("the newest is the victim", v[0]["pid"], 4)

    # 237-instance swarm: everything above the cap goes.
    r, v = verdict([mk(i, 0.1, 500 - i) for i in range(1, 238)], False)
    eq("swarm trimmed to cap", len(v), 237 - MAX_LANE_BROWSERS)

    # Total-RSS trigger with no single fat instance and no count breach.
    r, v = verdict([mk(1, 2.4, 300), mk(2, 2.4, 200), mk(3, 2.4, 100)], False)
    eq("total ceiling trips", len(v), 1)

    # Desktop lock: headed lanes are displaced, the operator is untouched.
    r, v = verdict([mk(1, 0.2, 300, cmd="/opt/chrome --no-sandbox"),
                    mk(2, 0.2, 100, cmd="/opt/chrome --no-sandbox"),
                    mk(9, 1.0, 900, "operator")], True)
    eq("lock reaps headed lane browsers", len(v), 2)
    eq("operator never reaped", [m["pid"] for m in v].count(9), 0)

    # Under the lock a HEADLESS lane keeps running: it cannot touch the compositor.
    # This is the other-session QA browser the first draft destroyed.
    r, v = verdict([mk(1, 0.2, 300, cmd="/opt/chrome --headless=new --remote-debugging-pipe"),
                    mk(2, 0.2, 100, cmd="/opt/chrome --headless=new")], True)
    eq("lock spares headless lanes", len(v), 0)

    # Mixed under the lock: the headed one goes, the headless one stays.
    r, v = verdict([mk(1, 0.2, 300, cmd="/opt/chrome --headless=new"),
                    mk(2, 0.2, 100, cmd="/opt/chrome --no-sandbox")], True)
    eq("lock reaps only the headed one", [m["pid"] for m in v], [2])

    # The caps still bind under the lock: 5 headless lanes exceed the count cap.
    r, v = verdict([mk(i, 0.2, 500 - i, cmd="/opt/chrome --headless=new")
                    for i in range(1, 6)], True)
    eq("count cap still applies to headless under lock", len(v), 5 - MAX_LANE_BROWSERS)

    # Operator alone, lock free: nothing to do even when it is fat.
    r, v = verdict([mk(9, 6.0, 900, "operator")], False)
    eq("fat operator browser is left alone", len(v), 0)

    if fails:
        print("SELFCHECK FAIL")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("SELFCHECK OK (22 assertions: role classification, headless detection, incident "
          "shape, count cap, total ceiling, desktop lock headed-vs-headless, "
          "operator exemption)")
    return 0


def main():
    argv = sys.argv[1:]
    cmd = argv[0] if argv else "status"
    if cmd == "status":
        return cmd_status()
    if cmd == "reap":
        n = enforce()
        print(f"reaped {n}")
        return 0
    if cmd == "watch":
        return cmd_watch()
    if cmd == "lint":
        return cmd_lint(argv[1:] or [os.path.join(WS, "targets"), os.path.join(WS, "scripts")])
    if cmd == "lock":
        return cmd_lock(argv[1:])
    if cmd == "selfcheck":
        return cmd_selfcheck()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
