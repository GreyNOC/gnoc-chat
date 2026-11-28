"""Soak driver for `gnoc chat`: push real prompts through the live agent, one at a time, and flag
anything that looks like a defect rather than an answer. Writes one JSON row per run.

usage: soak.py <batch-name> <<'EOF'
       prompt one
       prompt two
       EOF
"""
import json, os, re, subprocess, sys, time

GNOC = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scripts/gnoc")
WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _out_dir():
    """Rows land in the CURRENT directory, not beside the script. When soak.py was promoted into
    scripts/learn/ the rows started landing in the tracked repo dir instead of the run dir, and
    scripts/learn/batch3.jsonl sat untracked in git until someone noticed (2026-10-25). Documenting
    that was not a fix, so a run started from inside the tracked tree is now refused by name."""
    d = os.environ.get("SOAK_OUT")
    if d:
        os.makedirs(d, exist_ok=True)
        return d
    d = os.getcwd()
    inside = os.path.realpath(d).startswith(os.path.realpath(WS) + os.sep)
    state = os.path.join(os.path.realpath(WS), ".claude", "state") + os.sep
    if inside and not os.path.realpath(d).startswith(state):
        sys.exit(f"soak: refusing to write rows into the tracked tree ({d}).\n"
                 f"      cd into a run dir under {WS}/.claude/state/, or set SOAK_OUT=<dir>.")
    return d


# Resolved in main(), not at import: the refusal below is about a RUN, and firing it on import made the
# module unimportable from inside the repo, which broke its own test (2026-10-25).
BAD = [
    (re.compile(r"turn failed: (\w+)"), "turn-failed"),
    (re.compile(r"model error: (\w+)"), "model-error"),
    (re.compile(r"Traceback \(most recent call last\)"), "traceback"),
    (re.compile(r"the model ended the turn without an answer"), "empty-turn"),
    (re.compile(r"exceeds the (?:available )?context|context length|too many tokens"), "context-overflow"),
    (re.compile(r"cannot start|failed twice"), "model-down"),
    (re.compile(r"bad arguments:"), "bad-args"),
    (re.compile(r"timed out after"), "tool-timeout"),
    (re.compile(r"could not be parsed"), "toolcall-parse"),
]

def quoting(line, col):
    """True when the match at `col` in `line` is the model TALKING ABOUT a flag rather than the harness
    emitting one.

    Batch 8 run 12 ("read soak.py and suggest one more defect class it should flag") answered correctly and
    was flagged model-down and toolcall-parse: the answer reproduced this file's own table, so
    "`model-down` | Cannot start or failed twice" matched the pattern that detects a dead model. A driver
    that flags a good answer for describing the driver is worse than no flag, because every later flag then
    has to be re-read by hand before it can be trusted."""
    if line.count("|") >= 2:                 # a markdown table row the model wrote
        return True
    return line[:col].count("`") % 2 == 1    # the match sits inside `backticks`


def first_real_hit(rx, text):
    """The first match that is not the model quoting the flag table, or None."""
    for m in rx.finditer(text):
        bol = text.rfind("\n", 0, m.start()) + 1
        eol = text.find("\n", m.end())
        line = text[bol: eol if eol != -1 else len(text)]
        if not quoting(line, m.start() - bol):
            return m
    return None


def run(prompt, timeout=int(os.environ.get("SOAK_TIMEOUT") or 300), cont=False):
    """One turn. cont=True continues the previous conversation instead of starting a new one.

    Every batch through batch 9 was one-shot, so nothing exercised the multi-turn paths: history
    compaction, tools kept sticky across turns, a goal set in one turn and read in the next. Those are
    the paths a real session spends almost all of its time in (2026-10-25)."""
    t0 = time.time()
    cmd = [GNOC, "chat"] + (["-c"] if cont else []) + [prompt]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")) 
        rc, out = -1, out + "\n<<SOAK TIMEOUT>>"
    clean = re.sub(r"\x1b\[[0-9;]*m", "", out)
    flags, evidence = [], {}
    for rx, tag in BAD:
        m = first_real_hit(rx, clean)
        if m and tag not in evidence:
            flags.append(tag)
            i = max(0, m.start() - 120)
            evidence[tag] = clean[i:m.end() + 240].replace("\n", " | ")[:360]
    flags = sorted(set(flags))
    if rc == -1:
        flags.append("hard-timeout")
    body = re.sub(r"\x1b\[[0-9;]*m", "", out)
    answer = [l for l in body.splitlines() if l.strip() and not l.strip().startswith(("⎿", "●", "?"))]
    return {"prompt": prompt, "rc": rc, "secs": round(time.time() - t0, 1), "flags": flags,
            "evidence": evidence,          # the matching line, not just the tail: a 700-char tail hid it
            "chars": len(body), "tail": body[-900:], "answer_lines": len(answer)}

def report(out_dir):
    """Every batch in a run directory as one table. Fourteen batches of rows were only readable one
    jsonl at a time, so the trend that actually matters - flags falling while findings got worse - was
    invisible without re-deriving it by hand each time (2026-10-25)."""
    import glob
    rows_by_batch, order = {}, []
    for path in sorted(glob.glob(os.path.join(out_dir, "*.jsonl"))):
        name = os.path.basename(path)[:-len(".jsonl")]
        rows = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(r, dict) and "prompt" in r:
                    rows.append(r)
        if rows:
            rows_by_batch[name] = rows
            order.append(name)
    if not order:
        print(f"no batch rows in {out_dir}")
        return 0
    print(f"{'batch':<12} {'runs':>5} {'flagged':>8} {'chained':>8} {'median s':>9}  flags")
    print("-" * 72)
    tot = flagged_tot = 0
    tally = {}
    for name in order:
        rows = rows_by_batch[name]
        bad = [r for r in rows if r.get("flags")]
        secs = sorted(float(r.get("secs") or 0) for r in rows)
        med = secs[len(secs) // 2] if secs else 0.0
        kinds = {}
        for r in bad:
            for f in r.get("flags") or []:
                kinds[f] = kinds.get(f, 0) + 1
                tally[f] = tally.get(f, 0) + 1
        chained = "yes" if any(r.get("turn") for r in rows) else "-"
        print(f"{name:<12} {len(rows):>5} {len(bad):>8} {chained:>8} {med:>9.1f}  "
              f"{', '.join(f'{k}x{v}' for k, v in sorted(kinds.items())) or '-'}")
        tot += len(rows)
        flagged_tot += len(bad)
    print("-" * 72)
    pct = (100.0 * flagged_tot / tot) if tot else 0.0
    print(f"{'TOTAL':<12} {tot:>5} {flagged_tot:>8} {'':>8} {'':>9}  {pct:.0f}% flagged")
    if tally:
        print("\nby flag: " + ", ".join(f"{k} {v}" for k, v in sorted(tally.items(), key=lambda x: -x[1])))
    print("\nA flag is a CRASH-SHAPED defect. It cannot see a wrong answer, a confabulated finding or a\n"
          "question the agent had no tool for: those are found by reading runs that exited 0.")
    return 0


def main():
    if "--report" in sys.argv:
        return report(os.environ.get("SOAK_OUT") or os.getcwd())
    batch = sys.argv[1]
    chain = "--chain" in sys.argv          # one CONVERSATION, each prompt a turn in it
    print(f"(per-run cap {os.environ.get('SOAK_TIMEOUT') or 300}s"
          f"{', chained: one conversation' if chain else ''})", flush=True)
    prompts = [l.rstrip("\n") for l in sys.stdin if l.strip()]
    rows = []
    path = os.path.join(_out_dir(), f"{batch}.jsonl")
    for i, pr in enumerate(prompts, 1):
        r = run(pr, cont=chain and i > 1)
        r["turn"] = i if chain else None
        rows.append(r)
        with open(path, "a") as f:
            f.write(json.dumps(r) + "\n")
        print(f"[{i}/{len(prompts)}] {r['secs']:6.1f}s rc={r['rc']} flags={','.join(r['flags']) or '-':24} "
              f"{pr[:60]}", flush=True)
    bad = [r for r in rows if r["flags"]]
    print(f"\n== {batch}: {len(rows)} runs, {len(bad)} flagged", flush=True)
    for r in bad:
        print("  !", ",".join(r["flags"]), "|", r["prompt"][:70], flush=True)
        for tag, ev in (r.get("evidence") or {}).items():
            print(f"      {tag}: {ev[:200]}", flush=True)

main()
