"""gnoc_train.py - run a curriculum through the real gnoc chat agent so it learns, without touching the user's chat.

    python3 scripts/gnoc_train.py <curriculum.txt> [--dry]

A curriculum is plain text, one item per line:
    /program <handle>    switch program (starts a fresh conversation)
    # comment            ignored
    expect: <regex>      (after a turn) its final answer must match, case-insensitive; graded by code
    anything else        one turn, exactly as the user would type it

What it shares with the live chat: the REAL lesson book (lessons.jsonl), the measured hunt history and the trajectory
log - that is what training is for. What it does NOT share: the session, the conversation history, checkpoints and
the standing /goal (a live "hunt meta until RCE" goal steered every training turn into live probes, 2026-10-22).
It runs non-interactive: every action that needs approval is refused, so writes, non-GET HTTP, workers and the
shell beyond read-only commands never run. Read-only GETs to in-scope hosts still can, scope-gated as always.
"""
import os
import re
import shutil
import sys
import tempfile
import time

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))


def _count(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return sum(1 for _ in f)
    except OSError:
        return 0


def parse(path):
    items, prog = [], None
    with open(path, encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            if ln.startswith("/program "):
                prog = ln.split(None, 1)[1].strip()
                items.append(("program", prog))
            elif ln.lower().startswith("expect:"):
                items.append(("expect", ln.split(":", 1)[1].strip()))
            else:
                items.append(("turn", ln))
    return items


def isolate():
    """A private session, history and goal; the lesson book and trajectory log stay the real ones."""
    import gnoc_agent as G
    import gnoc_goal
    d = tempfile.mkdtemp(prefix="gnoc-train-")
    agent = os.path.join(d, "agent")
    os.makedirs(agent)
    for k, v in {"AGENT_DIR": agent, "SESSION": os.path.join(agent, "session.json"),
                 "OUT_DIR": os.path.join(agent, "out"), "JOBS_DIR": os.path.join(agent, "jobs"),
                 "SESSIONS_DIR": os.path.join(agent, "sessions")}.items():
        setattr(G, k, v)
    gnoc_goal.PATH = os.path.join(agent, "goal.json")
    return d


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 2
    items = parse(argv[0])
    if "--dry" in argv:
        for kind, v in items:
            print(f"{kind:8} {v}")
        return 0
    d = isolate()
    import gnoc_agent as G
    import gnoc_learn as L
    book0, traj0 = len(L.load()), _count(L.TRAJ)
    ids0 = {r["id"] for r in L.load()}
    agent = G.Agent(interactive=False)
    agent.s["learn"] = True
    t0 = time.time()
    graded, last = [], ""
    try:
        for kind, v in items:
            if kind == "program":
                agent.reset()
                print(G.t_set_program(agent.ctx, v))
                continue
            if kind == "expect":
                ok = bool(re.search(v, last or "", re.I | re.S))
                graded.append((ok, v))
                print(f"  {'PASS' if ok else 'FAIL'} expect /{v}/")
                continue
            print(f"\n=== [{agent.ctx.program or '-'}] {v}")
            agent.turn(v)
            last = next((m.get("content") or "" for m in reversed(agent.s.get("history") or [])
                         if m.get("role") == "assistant" and (m.get("content") or "").strip()), "")
            G.wait_reflection()   # one reflection per turn: a busy reflector would otherwise skip the next one
    finally:
        G.wait_reflection()
        err = os.path.join(d, "agent", "last-model-error.json")
        if os.path.exists(err):   # the private dir is about to go: keep the evidence of a model-server refusal
            shutil.copy(err, os.path.join(WS, ".claude/state/orch/agent/last-model-error.train.json"))
            print("model-server refusal recorded: .claude/state/orch/agent/last-model-error.train.json")
        shutil.rmtree(d, ignore_errors=True)
    book = L.load()
    new = [r for r in book if r["id"] not in ids0]
    print(f"\n--- training done in {time.time() - t0:.0f}s: {len(items)} items, lessons {book0} -> {len(book)}, "
          f"trajectories +{_count(L.TRAJ) - traj0}")
    for r in new:
        print(f"  + {r['id']} [{r['kind']} {r.get('program', '*')}] {r['text'][:140]}")
    for why in L.LAST_REJECTS[:10]:
        print(f"  refused: {why}")
    if graded:
        print(f"GRADE {sum(ok for ok, _ in graded)}/{len(graded)} answers matched their expect: line")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
