#!/usr/bin/env python3
"""webdrive - drive `gnoc chat` at real website-code work and GRADE it by code, not by reading its prose.

Why it exists: the soak driver (scripts/learn/soak.py) can only see crash-shaped defects - a traceback, an
empty turn, a context overflow. It cannot see the thing that actually matters for coding ability: the bot
answered confidently and was WRONG, or it edited the right file and broke the suite. So every task here
carries a GRADE command that exits 0 only when the work is actually correct, plus GUARD commands that must
stay 0 so a task cannot be "passed" by deleting the test or ripping out the feature (GNOC.md forbids both).

Each task runs against the SANDBOX mirror, never the live production checkout, and the mirror is reset to
its baseline commit between tasks so tasks never contaminate each other.

usage:
  webdrive.py run [--tasks F] [--only ID,ID] [--repeat N] [--tag T]
  webdrive.py report [--tag T]
"""
import argparse, json, os, re, subprocess, sys, time

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
GNOC = f"{WS}/scripts/gnoc"
SANDBOX = "~/gnoc-site.drive"
LIVE = os.path.expanduser("~/gnoc-site")
STATE = f"{WS}/.claude/state/webdrive-20261026"
BASELINE = "webdrive-baseline"


def sh(cmd, cwd=None, timeout=900, env=None):
    e = dict(os.environ)
    e.update(env or {})
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=e)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired as ex:
        tail = ex.stdout or b""
        return 124, (tail.decode(errors="replace") if isinstance(tail, bytes) else str(tail)) + "\n<timeout>"


def guard_live_untouched():
    """The live checkout is production. A run that dirtied it is a STOP, not a finding to note later."""
    rc, out = sh("git status --short", cwd=LIVE, timeout=60)
    return out


def reset_sandbox():
    """Back to the baseline commit, and nothing left behind. `clean -fd` is safe HERE and only here:
    this is a throwaway mirror, and -e keeps node_modules/build out of the sweep."""
    sh(f"git checkout -q {BASELINE} -- .", cwd=SANDBOX, timeout=120)
    sh(f"git reset -q --hard {BASELINE}", cwd=SANDBOX, timeout=120)
    sh("git clean -qfd -e node_modules -e build -e data", cwd=SANDBOX, timeout=120)


def diff_stat():
    rc, out = sh(f"git diff --stat {BASELINE}", cwd=SANDBOX, timeout=120)
    rc2, names = sh(f"git diff --name-only {BASELINE}", cwd=SANDBOX, timeout=120)
    rc3, untracked = sh("git ls-files --others --exclude-standard", cwd=SANDBOX, timeout=120)
    files = [f for f in (names.split() + untracked.split()) if f]
    return out.strip()[-1200:], sorted(set(files))


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s or "")


def run_task(t, tag):
    """One task: reset, drive the bot, grade by code, record, reset again."""
    tid = t["id"]
    reset_sandbox()
    pre_live = guard_live_untouched()

    # the prompt the bot sees. No hints about the answer: a hint grades the hint, not the bot.
    prompt = t["brief"]
    cmd = [GNOC, "chat", "-s-p", "--repo", SANDBOX, prompt]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=t.get("max_secs", 1200))
        out, rc = (p.stdout or "") + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired as ex:
        out = (ex.stdout or b"")
        out = out.decode(errors="replace") if isinstance(out, bytes) else (out or "")
        out, rc = out + "\n<<WEBDRIVE TIMEOUT>>", -1
    secs = round(time.time() - t0, 1)
    clean = strip_ansi(out)

    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tag": tag, "id": tid,
           "kind": t.get("kind", "fix"), "rc": rc, "secs": secs, "chars": len(clean)}

    # tool-call census: what it actually did, not what it said it did
    row["tool_calls"] = len(re.findall(r"^\s+● (\w+)\(", clean, re.M))
    row["tools_used"] = sorted(set(re.findall(r"^\s+● (\w+)\(", clean, re.M)))
    m = re.search(r"(\d+) calls\s+([\d.]+)k in / (\d+) out", clean)
    if m:
        row["calls"], row["kin"], row["kout"] = int(m.group(1)), float(m.group(2)), int(m.group(3))

    # crash-shaped flags, same vocabulary as soak.py so the two drivers compare
    flags = []
    for rx, name in ((r"turn failed:", "turn-failed"), (r"Traceback \(most recent call last\)", "traceback"),
                     (r"the model ended the turn without an answer", "empty-turn"),
                     (r"exceeds the (?:available )?context|context length", "context-overflow"),
                     (r"timed out after", "tool-timeout"), (r"could not be parsed", "toolcall-parse"),
                     (r"bad arguments:", "bad-args")):
        if re.search(rx, clean):
            flags.append(name)
    if rc == -1:
        flags.append("hard-timeout")

    if t.get("kind") == "knowledge":
        # a read-only question with a checkable answer. The answer is the LAST assistant block.
        ans = clean[-4000:]
        want = t["expect_re"]
        row["correct"] = bool(re.search(want, ans, re.I))
        if t.get("wrong_re") and re.search(t["wrong_re"], ans, re.I):
            flags.append("wrong-answer")
            row["correct"] = False
        row["verdict"] = "PASS" if row["correct"] else "FAIL"
    else:
        stat, files = diff_stat()
        row["diff_stat"], row["files_touched"] = stat, files
        row["edited"] = bool(files)
        grc, gout = sh(t["grade"], cwd=SANDBOX, timeout=t.get("grade_secs", 900))
        row["grade_rc"] = grc
        row["grade_tail"] = gout.strip()[-900:]
        broke = []
        for g in t.get("guards", []):
            rc2, o2 = sh(g["cmd"], cwd=SANDBOX, timeout=g.get("secs", 600))
            if rc2 != 0:
                broke.append(g["name"])
        row["guards_broken"] = broke
        off = [f for f in files if t.get("files") and not any(f.startswith(p) for p in t["files"])]
        row["off_target_files"] = off
        row["verdict"] = ("PASS" if grc == 0 and not broke else
                          "CHEATED" if grc == 0 and broke else
                          "NO-EDIT" if not files else "FAIL")

    post_live = guard_live_untouched()
    if post_live != pre_live:
        flags.append("TOUCHED-LIVE-REPO")
        row["live_diff"] = post_live[:1000]
    rc3, hstat = sh("git status --short scripts/ .claude/", cwd=WS, timeout=60)
    row["ws_dirty_lines"] = len([l for l in hstat.splitlines() if l.strip()])
    row["flags"] = sorted(set(flags))
    row["tail"] = clean[-2500:]

    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, "runs.jsonl"), "a") as fh:
        fh.write(json.dumps(row) + "\n")
    with open(os.path.join(STATE, f"transcript-{tag}-{tid}-{int(t0)}.log"), "w") as fh:
        fh.write(clean)
    reset_sandbox()
    return row


def report(tag=None):
    path = os.path.join(STATE, "runs.jsonl")
    if not os.path.isfile(path):
        print("no runs yet")
        return 0
    rows = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if not tag or r.get("tag") == tag:
            rows.append(r)
    if not rows:
        print(f"no runs for tag {tag}")
        return 0
    by_tag = {}
    for r in rows:
        by_tag.setdefault(r.get("tag", "-"), []).append(r)
    print(f"{'tag':<16}{'runs':>5}{'pass':>6}{'fail':>6}{'noedit':>7}{'cheat':>6}{'med s':>7}  flags")
    print("-" * 78)
    for tg, rs in by_tag.items():
        v = [r.get("verdict") for r in rs]
        secs = sorted(float(r.get("secs") or 0) for r in rs)
        fl = {}
        for r in rs:
            for f in r.get("flags") or []:
                fl[f] = fl.get(f, 0) + 1
        print(f"{tg:<16}{len(rs):>5}{v.count('PASS'):>6}{v.count('FAIL'):>6}"
              f"{v.count('NO-EDIT'):>7}{v.count('CHEATED'):>6}{secs[len(secs)//2]:>7.0f}  "
              f"{', '.join(f'{k}x{n}' for k, n in sorted(fl.items())) or '-'}")
    print("-" * 78)
    print(f"{'per task':<16}")
    per = {}
    for r in rows:
        per.setdefault(r["id"], []).append(r.get("verdict"))
    for tid, v in sorted(per.items()):
        print(f"  {tid:<28} {v.count('PASS')}/{len(v)} pass   {' '.join(v)}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["run", "report"])
    ap.add_argument("--tasks", default=os.path.join(STATE, "tasks.json"))
    ap.add_argument("--only", default="")
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--tag", default=time.strftime("%H%M"))
    a = ap.parse_args()
    if a.action == "report":
        return report(a.tag if a.tag != time.strftime("%H%M") else None)
    tasks = json.load(open(a.tasks))
    if a.only:
        want = set(a.only.split(","))
        tasks = [t for t in tasks if t["id"] in want]
    if not os.path.isdir(SANDBOX):
        sys.exit(f"webdrive: no sandbox at {SANDBOX}")
    for n in range(a.repeat):
        for t in tasks:
            r = run_task(t, a.tag)
            extra = ""
            if r.get("guards_broken"):
                extra = " broke:" + ",".join(r["guards_broken"])
            if r.get("off_target_files"):
                extra += " off-target:" + ",".join(r["off_target_files"][:3])
            print(f"[{a.tag}] {r['id']:<26} {r['verdict']:<8} {r['secs']:6.0f}s "
                  f"calls={r.get('tool_calls', 0):>2} in={r.get('kin', 0):>6.1f}k "
                  f"flags={','.join(r['flags']) or '-'}{extra}", flush=True)
    return 0


sys.exit(main())
