#!/usr/bin/env python3
"""gnoc_hunt_audit.py - measure how well the gnoc chat is hunting, from its own exhaust (2026-10-23).

"As good as Claude Code" needs a number. This reads .claude/state/orch/agent/activity.jsonl (one row per tool call
and per turn, written by gnoc_agent) and the program's hunt ledger, and prints per-turn efficiency:

    turn  tools  distinct  probes  refused  ghost  blocked  waste%   phase/first tool
    ...
    TOTALS over N turns: tools, probes, refused, waste%; ledger: hypotheses by status, probes, edges, exhausted leads

waste% = refused / tools (a refusal is any result starting with refused / not run / bad arguments / no raw capture /
no such / unknown or unavailable / duplicate of / GHOST-PATH). A Claude Code session on the same task runs at
roughly 0-5% waste and 3-8 tools per probe turn; the 9B lead measured 30-60% before the 2026-10-23 gates.

    python3 scripts/gnoc_hunt_audit.py [--program program-101] [--since 2026-10-23T05:00] [--turns 20] [--json]
"""
import argparse
import collections
import json
import os
import re
import sys
from datetime import datetime, timezone

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTIVITY = os.path.join(WS, ".claude/state/orch/agent/activity.jsonl")
REFUSED = re.compile(r"^\s*(refused|not run|bad arguments|no raw capture|no such (file|identity|folder|directory)|"
                     r"unknown or unavailable|duplicate of|GHOST-PATH|edge \S+ already exists)", re.I)
PROBE_TOOLS = {"http_request", "probe_matrix", "race", "sweep", "browser", "scan", "js_mine", "recon"}


def _ts(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def load_events(since=None):
    out = []
    try:
        with open(ACTIVITY) as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    e = json.loads(ln)
                except ValueError:
                    continue
                if since and _ts(e.get("ts")) < since:
                    continue
                out.append(e)
    except OSError:
        pass
    return out


def turns_from(events, program=None):
    """Group tool events into the turn that was open for their pid when they happened."""
    turns = []
    open_by_pid = {}
    for e in events:
        pid = e.get("pid")
        if e.get("ev") == "turn" and e.get("phase") == "start":
            if program and e.get("program") not in (None, program):
                continue
            t = {"pid": pid, "sid": e.get("sid"), "start": _ts(e.get("ts")), "end": None, "text": e.get("text") or "",
                 "tools": [], "ok": None}
            open_by_pid[pid] = t
            turns.append(t)
        elif e.get("ev") == "turn" and e.get("phase") == "end":
            t = open_by_pid.pop(pid, None)
            if t:
                t["end"], t["ok"] = _ts(e.get("ts")), e.get("ok")
        elif e.get("ev") == "tool" and e.get("phase") in ("end", "blocked"):
            t = open_by_pid.get(pid)
            if t is not None:
                t["tools"].append(e)
    return turns


def audit_turn(t):
    tools = t["tools"]
    n = len(tools)
    names = [x.get("name") for x in tools]
    refused = sum(1 for x in tools if x.get("phase") == "blocked" or REFUSED.search(str(x.get("out") or "")))
    ghost = sum(1 for x in tools if "GHOST-PATH" in str(x.get("out") or "") or "GHOST path" in str(x.get("out") or ""))
    blocked = sum(1 for x in tools if x.get("phase") == "blocked")
    probes = sum(1 for x in tools if x.get("name") in PROBE_TOOLS and x.get("phase") == "end"
                 and not REFUSED.search(str(x.get("out") or "")))
    m = re.search(r"PHASE (\w+)", t.get("text") or "")
    phase = m.group(1) if m else (names[0] if names else "-")
    secs = (t["end"] - t["start"]) if t.get("end") and t.get("start") else None
    return {"pid": t.get("pid"), "start": datetime.fromtimestamp(t["start"], timezone.utc).strftime("%H:%M") if t.get("start") else "-",
            "secs": int(secs) if secs is not None else None, "tools": n, "distinct": len(set(names)),
            "probes": probes, "refused": refused, "ghost": ghost, "blocked": blocked,
            "waste": round(100.0 * refused / n, 1) if n else 0.0, "phase": phase,
            "top": collections.Counter(names).most_common(1)[0][0] if names else "-"}


def ledger_summary(program):
    try:
        sys.path.insert(0, os.path.join(WS, "scripts"))
        import gnoc_hunt
        d = gnoc_hunt.load(program)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:80]}
    H = d.get("hypotheses") or []
    E = d.get("edges") or []
    walls = {h["id"]: [f"{r} {s.replace(':', ' len=')} x{n}" for r, s, n in gnoc_hunt.walled_routes(h)]
             for h in H if gnoc_hunt.walled_routes(h)}
    return {"hypotheses": len(H), "by_status": dict(collections.Counter(h.get("status") for h in H)),
            "probes": sum(int(h.get("probes") or 0) for h in H),
            # counted = minus the probes spent on routes that only ever refused (gnoc_hunt.walled_routes, T-49)
            "counted_probes": sum(gnoc_hunt.counted_probes(h) for h in H), "walled": walls,
            "bursts": sum(1 for h in H if h.get("burst")),
            "exhausted": sum(1 for h in H if h.get("escalation") == "exhausted"),
            "edges": len(E), "edges_by_status": dict(collections.Counter(e.get("status") for e in E)),
            "proven": sum(1 for e in E if e.get("status") == "proven")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", default=None)
    ap.add_argument("--since", default=None, help="ISO time (UTC) or hours like 6h")
    ap.add_argument("--turns", type=int, default=30)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--all-turns", action="store_true", help="include chat and test turns, not only [HUNT directives")
    ap.add_argument("--pid", type=int, default=None, help="only turns of this chat process (several chats share the log)")
    a = ap.parse_args()
    since = None
    if a.since:
        if re.fullmatch(r"\d+h", a.since):
            since = datetime.now(timezone.utc).timestamp() - 3600 * int(a.since[:-1])
        else:
            since = datetime.fromisoformat(a.since.replace("Z", "")).replace(tzinfo=timezone.utc).timestamp()
    turns = turns_from(load_events(since), a.program)
    if not a.all_turns:
        turns = [t for t in turns if (t.get("text") or "").startswith("[HUNT ")]
    if a.pid:
        turns = [t for t in turns if t.get("pid") == a.pid]
    rows = [audit_turn(t) for t in turns][-a.turns:]
    tot_tools = sum(r["tools"] for r in rows)
    tot_ref = sum(r["refused"] for r in rows)
    totals = {"turns": len(rows), "tools": tot_tools, "probes": sum(r["probes"] for r in rows), "refused": tot_ref,
              "ghost": sum(r["ghost"] for r in rows), "waste": round(100.0 * tot_ref / tot_tools, 1) if tot_tools else 0.0,
              "tools_per_turn": round(tot_tools / len(rows), 1) if rows else 0.0}
    led = ledger_summary(a.program) if a.program else {}
    if a.json:
        print(json.dumps({"turns": rows, "totals": totals, "ledger": led}, indent=1))
        return
    print(f"{'turn':>5} {'pid':>8} {'start':>5} {'secs':>5} {'tools':>5} {'dist':>4} {'probe':>5} {'refus':>5} {'ghost':>5} "
          f"{'blk':>3} {'waste%':>6}  phase / top tool")
    for i, r in enumerate(rows, 1):
        print(f"{i:>5} {str(r['pid']):>8} {r['start']:>5} {str(r['secs'] if r['secs'] is not None else '-'):>5} {r['tools']:>5} "
              f"{r['distinct']:>4} {r['probes']:>5} {r['refused']:>5} {r['ghost']:>5} {r['blocked']:>3} "
              f"{r['waste']:>6}  {r['phase']} / {r['top']}")
    print(f"TOTALS: {totals['turns']} turns, {totals['tools']} tools ({totals['tools_per_turn']}/turn), "
          f"{totals['probes']} probes, {totals['refused']} refused ({totals['waste']}% waste), {totals['ghost']} ghost")
    if led:
        print(f"LEDGER {a.program}: {led}")


if __name__ == "__main__":
    main()
