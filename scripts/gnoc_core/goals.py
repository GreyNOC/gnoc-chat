"""The standing goal and the plan block: what rides each turn, when a turn may stop, and the /goal command."""
import re
from .runtime import bind


def _goal_field(width=34):
    """The standing goal as a prompt segment, next to [skip-perms]. The user asked for it there (2026-10-22):
    the banner scrolls away, the prompt is in front of them on every line the user types."""
    (
        _CHAT_SID, gnoc_goal,
    ) = bind(
        "_CHAT_SID", "gnoc_goal",
    )
    try:
        g = gnoc_goal.one_line(width, owner=_CHAT_SID[0])
    except Exception:
        return None
    return ("◎ " + g) if g else None


def _plan_field():
    """The active plan as a prompt segment ('▣ 2/5 …'), beside the goal: the plan stays in front of them."""
    (
        _CHAT_SID, gnoc_plan,
    ) = bind(
        "_CHAT_SID", "gnoc_plan",
    )
    try:
        plan = gnoc_plan.load(_CHAT_SID[0])
    except Exception:  # noqa: BLE001 - a plan read never breaks the prompt
        return None
    return gnoc_plan.one_line(plan) or None


# The live task list. Without this, nothing told the lead to keep one outside plan mode, so a long turn
# showed only a wall of tool rows and GreyNOC could not see what it was working on or what was left
# (2026-10-31). Deliberately NOT "always plan first": a one-step answer must stay one step.
TASKLIST_SYSTEM = """TASK LIST. When my request needs three or more steps, or several files, or any work I will
wait on, open a task list FIRST with plan(action=set, goal=..., steps=[{action, verify, why}, ...]) - ACTION is
what you do, VERIFY is the test, command or page that proves it, WHY is what it buys. At most 8 steps. Then, as
you work, keep it current: plan(action=update, index=N, status=doing) when you start a step and
plan(action=update, index=N, status=done, evidence=<the output, diff or path that proved it>) the moment its
verification passed. Never mark a step done you have not verified, and never batch the updates at the end - the
list is how I watch the work. A single-step request gets no list: just do it."""


def _plan_block(ctx):
    """The ACTIVE PLAN block every turn's system prompt carries, so the work stays on the plan - plus the
    standing instruction to keep the list current, which is what makes the progress visible at all."""
    (
        TASKLIST_SYSTEM, gnoc_plan,
    ) = bind(
        "TASKLIST_SYSTEM", "gnoc_plan",
    )
    try:
        active = gnoc_plan.block(gnoc_plan.load(ctx.s.get("sid")))
    except Exception:  # noqa: BLE001
        active = ""
    return (active + "\n\n" + TASKLIST_SYSTEM) if active else TASKLIST_SYSTEM


def goal_before_stop(why="", touched=False):
    """One line on where the standing goal stands, for the moment work stops. "" when there is nothing
    to say (no goal, no goal owned by this conversation, or the goal is done).

    `touched` is True when this turn already moved the goal (a note, a milestone, a close), in which
    case the turn spoke for itself and this stays quiet."""
    (
        T, _CHAT_SID, dim, gnoc_goal,
    ) = bind(
        "T", "_CHAT_SID", "dim", "gnoc_goal",
    )
    d = gnoc_goal.load()
    if not gnoc_goal._owned(d, _CHAT_SID[0]) or touched:
        return ""
    ms = d.get("milestones") or []
    acc = d.get("acceptance") or []
    open_ms = [m for m in ms if m.get("status") != "done"]
    open_acc = [a for a in acc if a.get("status") != "met"]
    head = T.blue("  ◎ goal still open") + (dim(f" ({why})") if why else "") + ": " + T.white(
        " ".join(str(d.get("text") or "").split())[:90])
    counts = []
    if ms:
        counts.append(f"{len(ms) - len(open_ms)}/{len(ms)} milestones")
    if acc:
        counts.append(f"{len(acc) - len(open_acc)}/{len(acc)} criteria")
    if counts:
        head += dim("   " + " · ".join(counts))
    nxt = (open_ms[0].get("text") if open_ms else None) or (open_acc[0].get("text") if open_acc else None)
    if nxt:
        head += "\n" + dim("    next: ") + str(nxt)[:110]
    return head


def goal_touched(msgs):
    """Did this turn actually move the goal? A goal tool call that recorded something counts; asking to
    SEE the goal does not."""
    (
        contextlib, json,
    ) = bind(
        "contextlib", "json",
    )
    for m in msgs or []:
        for c in (m.get("tool_calls") or []):
            fn = (c.get("function") or {}) if isinstance(c, dict) else {}
            if fn.get("name") == "goal":
                args = fn.get("arguments") or ""
                if isinstance(args, str):
                    with contextlib.suppress(Exception):
                        args = json.loads(args)
                if isinstance(args, dict) and args.get("action") in ("note", "milestone", "accept", "pause",
                                                                      "resume", "done", "set", "clear"):
                    return True
    return False


def warn_goal_excluded(prog, goal):
    """THE GOAL TEXT GETS THE SAME EXCLUSION CHECK A HYPOTHESIS GETS. T-303's warning lives in
    hunt_hypothesis(add/update/list), so it only ever sees a hypothesis the agent TYPED. A goal handed in
    prose - which is how the orchestrator briefs a lane - walked straight past it: on 2026-10-28 a brief
    aimed a program-72 lane at the registration couponCode field while PROGRAM.md:10 says "All our LOGIN
    services are out of scope for the moment", and the whole run was spent before anything said so. Same
    warning, same reason it is a warning: whether an exclusion reaches the surface is the hunter's
    judgement, it just has to be made before the probes, not after.

    EVERY path that turns goal prose into probes calls this. /hunt did; /goal and goal(action=set) did not,
    and they auto-hunt the program named in the goal text (QAQC 2026-11-03). Returns the hits it printed."""
    (
        dim, say, yellow,
    ) = bind(
        "dim", "say", "yellow",
    )
    if not (prog and goal):
        return []
    try:
        from bbtools import lib_policy as _lp
        hits = _lp.excluded_match(prog, goal)
    except Exception:  # noqa: BLE001 - an advisory never blocks a hunt
        return []
    if hits:
        say(yellow(f"  ! this goal touches what {prog} puts OUT OF SCOPE. Decide before probing, "
                   "and say which way:"))
        for ln, txt, _ in hits:
            say(dim(f"    PROGRAM.md:{ln}  {txt[:120]}"))
    return hits


_GOAL_SEEN = [""]   # the goal last shown in this chat, so a CHANGE is announced and a repeat is not


def _criteria(values):
    (
        re,
    ) = bind(
        "re",
    )
    out = []
    for v in values or []:
        out += [c.strip() for c in re.split(r"[;\n]", str(v)) if c.strip()]
    return out


def announce_goal_change():
    """Say it when the standing goal appears, changes, pauses, closes or is achieved. The agent can set its
    own goal now, and a goal that arrives silently is one the operator never saw."""
    (
        T, _CHAT_SID, _GOAL_SEEN, dim, gnoc_goal, say, shutil,
    ) = bind(
        "T", "_CHAT_SID", "_GOAL_SEEN", "dim", "gnoc_goal", "say", "shutil",
    )
    fp = gnoc_goal.fingerprint(owner=_CHAT_SID[0])
    if fp == _GOAL_SEEN[0]:
        return
    was, _GOAL_SEEN[0] = _GOAL_SEEN[0], fp
    d = gnoc_goal.load()
    line = gnoc_goal.one_line(shutil.get_terminal_size((100, 24)).columns - 14, owner=_CHAT_SID[0])
    if not fp:
        say(T.blue("  ◎ ") + dim("standing goal cleared"))
    elif d.get("status") == "achieved":
        say(T.bgreen("  ◎ goal ACHIEVED  ") + T.white(" ".join(str(d.get("text") or "").split())[:90])
            + dim("   /goal to review the receipt, /goal clear to drop it"))
    elif d.get("status") == "paused":
        say(T.blue("  ◎ goal paused  ") + T.white(" ".join(str(d.get("text") or "").split())[:90])
            + dim("   /goal resume continues it"))
    elif not was:
        say(T.blue("  ◎ goal set  ") + T.white(line) + dim("   every turn works toward this; /goal clear drops it"))
    else:
        say(T.blue("  ◎ goal  ") + T.white(line))


GOAL_REENTRY_MAX = 3


GOAL_RESUME_PROMPT = ("The lead's connection dropped mid-turn and was retried. Resume the standing goal from where "
                      "it stood: take the next real step with your tools, record it with goal(action=note), and end "
                      "with NEXT: <the next step>.")


GOAL_STALL_MAX = 6        # consecutive turns with no tool call and no goal movement before it hands back


GOAL_EMPTY_MAX = 3        # consecutive empty answers (lead down) before it hands back


GOAL_CONTINUE = """Continue the standing goal: {goal}

Take the NEXT real step toward it NOW with your tools - do not summarize, do not ask whether to go on. Record
what each step established with goal(action=note, text=..., artifact=<a file that exists, if any>). Close a
milestone or acceptance criterion the moment its receipt exists. When EVERY constraint and acceptance criterion is
met, close the goal with goal(action=done, receipt=<the artifact that proves it>) - that is the only way this
work ends. If one approach is exhausted, switch to a different one and say why in a note. Stop with
"NEEDS: <exactly what only the user can provide>" ONLY for something you truly cannot do or decide yourself
(credentials, a scope or payment decision, physical access); everything else you do yourself."""


GOAL_STALL_NUDGE = ("You have not called a tool or moved the goal for {n} turns. THIS turn: take one concrete "
                    "step with a tool (a probe, a read, a search, a test) or switch to a different approach and "
                    "note why. Talking about the goal is not progress.\n\n")


GOAL_SAID_DONE = ("You said the goal is done, but it is still OPEN: nothing closed it. If it really is met, call "
                  "goal(action=done, receipt=<the artifact that proves it>) now; if the receipt does not exist yet, "
                  "produce it. Otherwise keep working.\n\n")


_SAID_DONE = re.compile(r"\b(goal (is )?(achieved|complete|met|done)|achieved the goal|mission accomplished)\b", re.I)


_CONTINUE_WORDS = re.compile(r"^\s*(continue|keep going|go on|resume|carry on|proceed)\b", re.I)


def _goal_set(agent, arg):
    """Set (or deliberately replace) the standing goal. Kept separate from the command table so every verb
    shares ONE replacement guard instead of each branch inventing its own."""
    (
        SPIN, T, _criteria, _goal_hypotheses, _goal_program, _goal_turn_text, _seed_goal, _split_flags, dim,
        drive_goal, gnoc_goal, green, note_program_source, red, say, warn_goal_excluded, white,
    ) = bind(
        "SPIN", "T", "_criteria", "_goal_hypotheses", "_goal_program", "_goal_turn_text", "_seed_goal",
        "_split_flags", "dim", "drive_goal", "gnoc_goal", "green", "note_program_source", "red", "say",
        "warn_goal_excluded", "white",
    )
    parsed, err = _split_flags(arg, value=("--accept", "--milestone"), boolean=("--no-start", "--force"))
    if err:
        say(red("  " + err))
        return
    words, vals, flags = parsed
    text = " ".join(words).strip()
    if not text:
        say(red("  usage: /goal <objective> [--accept \"criterion; ...\"] [--milestone \"step\"] [--no-start]"))
        return
    sid = agent.s.get("sid")
    force = "--force" in flags
    cur = gnoc_goal.load()
    status = (cur or {}).get("status")
    if cur and status in ("active", "paused") and cur.get("text") == text and not force:
        say(dim("  that goal is already " + status + "; its progress is kept")
            + dim("  (/goal resume continues it)" if status == "paused"
                  else "  (/goal show for progress, /goal <new objective> --force to replace it)"))
        return
    if cur and status in ("active", "paused") and not force:
        mine = cur.get("sid") == sid
        say(red("  refused: a goal is already active - ") + white(repr(cur["text"]))
            + dim("" if mine else "  (set by another conversation in this repo)")
            + dim("  (/goal clear first, or /goal <new goal> --force to replace it)"))
        return
    criteria = _criteria(vals.get("--accept"))
    milestones = [m for m in vals.get("--milestone", []) if str(m).strip()]
    prog = _goal_program(text, agent.ctx.program)
    d, err = gnoc_goal.set_goal(text, prog, milestones=milestones, owner=sid, acceptance=criteria)
    if err:
        say(red("  " + err))
        return
    seeded = _seed_goal(d)
    say(green("● ") + white("goal set: ") + d["text"])
    if prog and prog != agent.ctx.program:
        agent.s["program"] = prog
        note_program_source(agent, "named in /goal")
        agent.save()
        say(dim(f"  program set to {prog} (named in the goal)"))
    if seeded:
        say(dim("  " + seeded))
    say(dim(gnoc_goal.status_text()))
    say(dim("  /goal show for detail · /goal accept|milestone to close the definition of done · "
            "/goal pause|resume · /goal clear drops it"))
    if "--no-start" in flags:
        say(dim("  not started (--no-start); /hunt or just talk to it when you are ready"))
        return
    if prog:
        # a goal is an instruction to work, not a note: start the loop on it now
        warn_goal_excluded(prog, d["text"])   # T-303, before the probes rather than after
        say(T.bred("  ▶ ") + T.byellow(f"working on it now: hunting {prog} toward the goal")
            + dim("  (Ctrl-C hands control back)"))
        # SAY IT BEFORE THE SLOW PART, AND SPIN THROUGH IT. _goal_hypotheses can hold the thread for minutes;
        # printed after it, the terminal went dead silent and read as a broken chat (T-270, 2026-11-03).
        SPIN.start("Aiming hypotheses at the goal", kind="think")
        try:
            _goal_turn_text(agent, d)
            fresh = _goal_hypotheses(agent, d)
        finally:
            SPIN.stop()
        if fresh:
            say(dim("  " + fresh[:300]))
        agent.hunt(prog, d["text"])
    else:
        agent.s.pop("_goal_hold", None)   # a new goal is an order to work, whatever an old Ctrl-C held
        drive_goal(agent, first_prompt=(
            "Start on the standing goal now. In one line say what reaching it would take and what acceptance "
            "criteria make it DONE (add any missing ones with goal(action=accept, status=open, text=...)), then "
            "take the first real step yourself with your tools this turn (do not describe it, do it). Record what "
            "you learn with goal(action=note). Never close the goal without the receipt that proves it. Stop with "
            "NEEDS: only for something only the user can give."), why="new goal")


def goal_cmd(agent, rest):
    """/goal with explicit verbs. A goal text is still the common case, so a verb counts only as a whole
    first token ('donate ...' stays an objective), and 'clear the backlog' stays an objective too."""
    (
        _goal_set, _split_flags, dim, drive_goal, gnoc_goal, green, red, say,
    ) = bind(
        "_goal_set", "_split_flags", "dim", "drive_goal", "gnoc_goal", "green", "red", "say",
    )
    arg = (rest or "").strip()
    low = arg.lower()
    verb = low.split(maxsplit=1)[0] if low else ""
    body = arg[len(verb):].strip()
    sid = agent.s.get("sid")
    d = gnoc_goal.load()
    if not arg:
        say(dim(gnoc_goal.status_text()))
        return
    if verb in ("help", "?"):
        say(dim(gnoc_goal.USAGE))
        return
    if verb in ("show", "status"):
        say(dim(gnoc_goal.status_text()))
        return
    if verb in ("clear", "off", "none"):
        parsed, err = _split_flags(body, boolean=("--force",))
        if not err and not parsed[0]:
            say(green("● ") + gnoc_goal.clear(owner=sid, force="--force" in parsed[2]))
            return
        # "clear the gatewayco backlog" is an objective, not a drop: fall through to set.
    if verb == "done":
        parsed, err = _split_flags(body, boolean=("--force",))
        if err:
            say(red("  " + err))
            return
        words, _, flags = parsed
        say(green("● ") + gnoc_goal.done(" ".join(words).strip(), "--force" in flags, owner=sid))
        return
    if verb == "note":
        parsed, err = _split_flags(body, value=("--artifact",))
        if err:
            say(red("  " + err))
            return
        words, vals, _ = parsed
        text = " ".join(words).strip()
        if not d and text:
            _goal_set(agent, arg)   # "note <objective>" with no goal at all is an objective
            return
        say(green("● ") + gnoc_goal.note(text, (vals.get("--artifact") or [""])[-1], owner=sid))
        return
    if verb in ("milestone", "accept"):
        parsed, err = _split_flags(body, value=("--receipt",), boolean=("--open",))
        if err:
            say(red("  " + err))
            return
        words, vals, flags = parsed
        text = " ".join(words).strip()
        receipt = (vals.get("--receipt") or [""])[-1]
        if verb == "milestone":
            st = "open" if "--open" in flags else "done"
            say(green("● ") + gnoc_goal.milestone(text, st, receipt, owner=sid))
        else:
            st = "open" if "--open" in flags else "met"
            say(green("● ") + gnoc_goal.accept(text, st, receipt, owner=sid))
        return
    if verb == "pause":
        say(green("● ") + gnoc_goal.pause(owner=sid))
        return
    if verb == "resume":
        cur = gnoc_goal.load()
        if not (cur and cur.get("status") == "active"):
            say(green("● ") + gnoc_goal.resume(owner=sid))
        agent.s.pop("_goal_hold", None)
        drive_goal(agent, why="resumed")
        return
    _goal_set(agent, arg)
