"""gnoc_plan.py - the plan document gnoc chat proposes, shows and works, deepcode-style.

The plan is the senior-dev artifact: a goal, the constraints it must respect, ordered steps (each with
the ACTION, how it is VERIFIED, and WHY it is in the plan), the risks, and what is deliberately NOT done.
It lives per conversation (agent/plans/<sid>.json), shows in a colored panel the moment the model sets it
(plan preview), rides in the system prompt of every later turn, and its steps sync into the tasks ledger.

    plan(action=set, goal=..., steps=[{action, verify, why}, ...], risks=..., not_doing=...)
    plan(action=show | update | clear)
"""
import json
import os
import re
import threading
import time

WS = os.environ.get("GNOC_WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLAN_DIR = os.path.join(WS, ".claude", "state", "orch", "agent", "plans")

STEP_STATUS = ("pending", "doing", "done", "skipped")
_GOAL_MAX = 240
_STEP_MAX = 8     # a plan with more steps than this is a list, not a plan: the model gets told to split
_TEXT_MAX = 200


def plan_path(sid):
    sid = re.sub(r"[^A-Za-z0-9._-]", "-", str(sid or "unknown"))
    return os.path.join(PLAN_DIR, f"{sid}.json")


def validate(plan):
    """(ok, err). Shape and sanity, before anything is written or shown. Steps need an ACTION; verify/why
    default to '' (the model must not be forced to invent a check it does not know yet)."""
    if not isinstance(plan, dict):
        return False, "plan is not a dict"
    goal = " ".join(str(plan.get("goal") or "").split())
    if len(goal) < 8:
        return False, "plan needs goal=<what this plan achieves, in one sentence>"
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        return False, "plan needs steps=[{action, verify, why}, ...] - at least one step"
    if len(steps) > _STEP_MAX:
        return False, (f"a plan is at most {_STEP_MAX} steps; {len(steps)} is a task list - split it into "
                       f"plans per phase, or put the details in one step's action")
    for i, s in enumerate(steps, 1):
        if not isinstance(s, dict):
            return False, f"step {i} is not a dict"
        action = " ".join(str(s.get("action") or "").split())
        if len(action) < 4:
            return False, f"step {i} needs action=<what to DO, concretely>"
        status = str(s.get("status") or "pending").lower()
        if status not in STEP_STATUS:
            return False, f"step {i} status {status!r} is not one of {', '.join(STEP_STATUS)}"
    return True, ""


def normalize(plan):
    """The stored shape: trimmed text, defaults filled, exactly the fields the panel reads."""
    steps = []
    for s in plan.get("steps") or []:
        steps.append({"action": " ".join(str(s.get("action") or "").split())[:_TEXT_MAX],
                      "verify": " ".join(str(s.get("verify") or "").split())[:_TEXT_MAX],
                      "why": " ".join(str(s.get("why") or "").split())[:_TEXT_MAX],
                      "status": str(s.get("status") or "pending").lower(),
                      "evidence": " ".join(str(s.get("evidence") or "").split())[:400],
                      "done_at": s.get("done_at") or "",
                      "task_id": str(s.get("task_id") or "")})
    return {"goal": " ".join(str(plan.get("goal") or "").split())[:_GOAL_MAX],
            "constraints": " ".join(str(plan.get("constraints") or "").split())[:_TEXT_MAX],
            "steps": steps,
            "risks": " ".join(str(plan.get("risks") or "").split())[:_TEXT_MAX],
            "not_doing": " ".join(str(plan.get("not_doing") or "").split())[:_TEXT_MAX],
            "updated": time.time()}


def load(sid):
    try:
        with open(plan_path(sid), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or not d.get("goal") or not isinstance(d.get("steps"), list):
        return None
    # The file is data and may be hand-edited: one bad step or a status word nobody knows must not break the
    # panel, the block or the prompt bar (the same contract gnoc_goal._clean keeps for the goal file).
    steps = []
    for s in d.get("steps"):
        if not isinstance(s, dict) or not isinstance(s.get("action"), str) or not s["action"].strip():
            continue
        status = str(s.get("status") or "pending").lower()
        if status not in STEP_STATUS:
            status = "pending"
        steps.append({**s, "action": s["action"], "status": status,
                      "evidence": str(s.get("evidence") or ""), "done_at": s.get("done_at") or "",
                      "task_id": str(s.get("task_id") or "")})
    if not steps:
        return None
    d["steps"] = steps
    d.setdefault("updated", time.time())
    return d


def save(sid, plan):
    os.makedirs(PLAN_DIR, exist_ok=True)
    # The pid alone is not unique: a hunt/fan-out thread can update the same plan as the REPL in one
    # process, and two writers shared the tmp name (the goal writer hit the same race on 2026-10-22).
    tmp = plan_path(sid) + f".{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=1)
        os.replace(tmp, plan_path(sid))
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def clear(sid):
    with_context = __import__("contextlib")
    with with_context.suppress(OSError):
        os.remove(plan_path(sid))
    return True


def progress(plan):
    done = sum(1 for s in plan["steps"] if s["status"] == "done")
    return done, len(plan["steps"])


def one_line(plan):
    """The prompt-bar shape: '▣ 2/5 goal…' - short enough to sit beside the goal field."""
    if not plan:
        return ""
    d, n = progress(plan)
    mark = "✓" if all_resolved(plan) else "▣"
    return f"{mark} {d}/{n} " + " ".join(str(plan.get("goal") or "").split())[:26]


def next_step(plan):
    """The step the next turn works on: a step already marked doing first (that is where work started),
    else the first pending one. None means every step is done or skipped."""
    for status in ("doing", "pending"):
        for i, s in enumerate(plan["steps"], 1):
            if s["status"] == status:
                return i, s
    return None, None


def all_resolved(plan):
    """Every step is done or deliberately skipped (nothing pending/doing)."""
    return bool(plan and plan.get("steps")) and next_step(plan)[0] is None


def panel(plan, highlight=None):
    """The colored plan preview, deepcode's Plan block in GreyNOC's palette. Plain text when piped."""
    try:
        import gnoc_theme as T
        c_border, c_head, c_step, c_meta, c_done, c_do = T.byellow, T.bold, T.white, T.dim, T.bgreen, T.bblue
    except Exception:  # noqa: BLE001 - no theme: plain text is still a plan
        c_border = c_head = c_step = c_meta = c_done = c_do = lambda s: str(s)
    d, n = progress(plan)
    w = 78
    lines = [c_border("┌─ PLAN ") + c_head(f"{d}/{n} steps") + c_border(" " + "─" * max(4, w - 14 - len(str(d)) - len(str(n))))]
    lines.append(c_border("│ ") + c_head("goal  ") + c_step(" ".join(str(plan.get("goal") or "").split())))
    if plan.get("constraints"):
        lines.append(c_border("│ ") + c_meta("must  ") + c_meta(" ".join(str(plan["constraints"]).split())[:120]))
    for i, s in enumerate(plan["steps"], 1):
        col = c_done if s["status"] == "done" else c_do if s["status"] in ("doing", "skipped") else c_step
        mark = {"done": "✓", "doing": "▶", "skipped": "·", "pending": "○"}[s["status"]]
        star = " ✻" if highlight and i == highlight else ""
        lines.append(c_border("│ ") + col(f"{mark} {i}. {s['action']}") + c_meta(f"  [{s['status']}]{star}"))
        for key, label in (("verify", "verify"), ("why", "why")):
            if s.get(key):
                lines.append(c_border("│ ") + c_meta(f"     {label}: " + " ".join(str(s[key]).split())[:110]))
        if s["status"] == "done" and s.get("evidence"):
            lines.append(c_border("│ ") + c_meta("     proof: " + " ".join(str(s["evidence"]).split())[:110]))
    if plan.get("risks"):
        lines.append(c_border("│ ") + c_meta("risks ") + c_meta(" ".join(str(plan["risks"]).split())[:120]))
    if plan.get("not_doing"):
        lines.append(c_border("│ ") + c_meta("NOT   ") + c_meta(" ".join(str(plan["not_doing"]).split())[:120]))
    lines.append(c_border("└" + "─" * (w - 1)))
    return "\n".join(lines)


def block(plan):
    """The system-prompt block for an ACTIVE plan: what is done, what is next, what the turn must do."""
    if not plan:
        return ""
    d, n = progress(plan)
    i, s = next_step(plan)
    head = f"ACTIVE PLAN ({d}/{n} steps done): " + " ".join(str(plan.get("goal") or "").split())
    out = [head]
    if s:
        out.append(f"  NEXT: step {i} - {s['action']}" + (f"  (verify: {s['verify']})" if s.get("verify") else ""))
        out.append("  Work THIS step with your tools now; when its verification passed, mark it with "
                   f"plan(action=update, index={i}, status=done, evidence=<the output, diff or path that "
                   "proved it>), then start the next step.")
    elif d >= n:
        out.append("  every step is done: verify the whole result once more, then report and offer "
                   "plan(action=clear).")
    else:
        # every remaining step is skipped: nothing is pending. Say that plainly instead of claiming the plan
        # is finished, and never say "none is done" when earlier steps already were.
        done_txt = f"{d}/{n} step(s) are done" if d else "none of the steps is done"
        out.append(f"  every remaining step is skipped ({done_txt}): re-open one with "
                   "plan(action=update, index=N, status=doing) and work it, or say plainly why the plan is dead.")
    if plan.get("constraints"):
        out.append("  constraints: " + str(plan["constraints"]))
    if plan.get("not_doing"):
        out.append("  NOT in this plan: " + str(plan["not_doing"]))
    return "\n".join(out)


def tasks_rows(plan):
    """The plan steps as tasks-ledger rows: [(text, tag)] for t_tasks-style sync."""
    return [(f"plan: {s['action']}"[:160], "plan") for s in plan["steps"]]


def checklist(plan, highlight=None, header="Update Todos"):
    """The LIVE task list, Claude-Code shaped: one header row and one row per step, checked or not, the
    step being worked marked. This is what the user reads while the bot works, so it is deliberately
    narrower and quieter than panel(): no verify/why lines, no box, nothing that scrolls the actions
    off the screen. panel() stays the one-time plan PREVIEW; this is the running progress.

        ● Update Todos
          ⎿  ☒ read the turn loop
             ▶ patch the think flag          <- doing
             ☐ run the suite

    highlight: a 1-based step index to mark with ✻ (the step that just changed)."""
    if not plan or not plan.get("steps"):
        return ""
    try:
        import gnoc_theme as T
        c_head, c_done, c_do, c_todo, c_meta = T.bblue, T.dim, T.bgreen, T.white, T.dim
    except Exception:  # noqa: BLE001 - no theme: the list still reads as a list
        c_head = c_done = c_do = c_todo = c_meta = lambda s: str(s)
    d, n = progress(plan)
    rows = [c_do("● ") + c_head(header) + c_meta(f"  {d}/{n}")]
    for i, s in enumerate(plan["steps"], 1):
        mark, col = {"done": ("☒", c_done), "doing": ("▶", c_do),
                     "skipped": ("·", c_meta), "pending": ("☐", c_todo)}[s["status"]]
        lead = "  ⎿  " if i == 1 else "     "
        star = c_do(" ✻") if highlight and i == highlight else ""
        rows.append(c_meta(lead) + col(f"{mark} {s['action']}") + star)
    return "\n".join(rows)
