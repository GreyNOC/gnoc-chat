"""Plan-mode proposals, receipts and the long-horizon work loop."""
from gnoc_core.runtime import bind


def _plan_request(agent, request):
    """Plan mode for ONE request: the lead proposes plan(action=set ...), the panel shows, the user decides."""
    (
        PLAN_IMPLEMENT_PROMPT, PLAN_MODE_PROMPT, T, dim, gnoc_plan, red, say, sys,
        white,
    ) = bind(
        "PLAN_IMPLEMENT_PROMPT", "PLAN_MODE_PROMPT", "T", "dim", "gnoc_plan", "red", "say",
        "sys", "white",
    )
    say(T.bblue("  💡 plan mode: ") + white(" ".join(str(request).split())[:90]))
    agent.s["_planning_turn"] = True   # no ultra pre-fan-out, no deep side worker: planning is the deliverable
    try:
        agent.turn(PLAN_MODE_PROMPT.format(request=request))
    finally:
        agent.s.pop("_planning_turn", None)
    plan = gnoc_plan.load(agent.s.get("sid"))
    if not plan:
        # The tool is always loaded; a model can still describe the plan in prose instead of calling it.
        # ONE strict retry - the plan document is what later turns work from, prose is not.
        say(dim("  no plan document was set; asking once more, it must call the tool this time"))
        agent.s["_planning_turn"] = True
        try:
            agent.turn("You described a plan in prose but did not call the tool. Call plan(action=set, goal=..., "
                       "steps=[{action, verify, why}, ...]) with your proposed steps NOW. Do not describe it - "
                       "call the tool, then stop.")
        finally:
            agent.s.pop("_planning_turn", None)
        plan = gnoc_plan.load(agent.s.get("sid"))
    if not plan:
        say(red("  no plan was proposed") + dim("  (tell it to propose one with plan(action=set, ...))"))
        return
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        say(dim("  plan ready. Implement it with: go ahead, implement the plan  (or /plan go)"))
        return
    try:
        ans = input(T.byellow("  enter = implement · e = edit the plan · q = leave it for later > ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        say("")
        return
    if ans in ("q", "quit"):
        say(dim("  plan kept; implement later with 'go ahead, implement the plan' or /plan go"))
    elif ans.startswith("e"):
        want = ans[1:].strip() or "address the user's feedback"
        say(dim(f"  revising the plan: {want}"))
        agent.turn("Adjust the plan to " + want + ". Then call plan(action=set, ...) again with the revised "
                   "steps and stop - do not implement yet.")
        revised = gnoc_plan.load(agent.s.get("sid"))
        if revised:
            say(gnoc_plan.panel(revised))
            say(dim("  enter to implement · q to leave it for later"))
            try:
                ans = input(T.byellow("  > ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                say("")
                return
            if ans in ("q", "quit"):
                return
        else:
            say(red("  no revised plan was proposed"))
            return
        say(T.bgreen("  ▶ ") + dim("implementing the plan"))
        agent.turn(PLAN_IMPLEMENT_PROMPT)
    else:
        say(T.bgreen("  ▶ ") + dim("implementing the plan"))
        agent.turn(PLAN_IMPLEMENT_PROMPT)


def _work_receipt(agent, plan, task="", outcome="completed"):
    """Write the completion record that closes a /work goal. A goal receipt must exist on disk; this is the
    one artifact that ties the plan, its evidence and the goal together."""
    (
        WS, contextlib, datetime, json, os, re, time, timezone,
    ) = bind(
        "WS", "contextlib", "datetime", "json", "os", "re", "time", "timezone",
    )
    sid = str(agent.s.get("sid") or "unknown")
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", sid)[:80] or "unknown"
    outdir = os.path.join(WS, ".claude", "state", "orch", "agent", "work")
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(outdir, f"{safe}-{stamp}-{os.getpid()}-{time.time_ns() % 1000000}.json")
    payload = {"kind": "work-completion", "outcome": outcome, "sid": sid, "task": task,
               "completed": datetime.now(timezone.utc).isoformat(timespec="seconds"), "plan": plan}
    tmp = f"{path}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=1)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
    return path


def _work_complete(agent, plan, task="", close_goal=True):
    """Plan completion and goal completion are ONE event. Returns a line for the chat ("" when this was a
    plan-only run or the goal belongs to another conversation). A deliberately skipped step is not a done
    step: the default criterion only closes when every step is actually done."""
    (
        WORK_DONE_CRITERION, _work_receipt, contextlib, gnoc_goal, gnoc_plan, time,
    ) = bind(
        "WORK_DONE_CRITERION", "_work_receipt", "contextlib", "gnoc_goal", "gnoc_plan",
        "time",
    )
    if not close_goal or not plan or not gnoc_plan.all_resolved(plan):
        return ""
    sid = agent.s.get("sid")
    d = gnoc_goal.load()
    if not gnoc_goal._owned(d, sid) or not str(d.get("text") or "").startswith("WORK:"):
        return ""
    done, total = gnoc_plan.progress(plan)
    if done < total:
        # Keep the goal open, but leave an artifact and a note so the next turn knows why.
        try:
            receipt = _work_receipt(agent, plan, task, outcome="partial")
        except OSError as e:
            return f"plan ended {done}/{total}; the goal stays open (completion record failed: {e})"
        with contextlib.suppress(Exception):
            gnoc_goal.note(f"work plan ended with {done}/{total} done and {total - done} skipped; "
                           "the default criterion still requires every step done", artifact=receipt, owner=sid)
        return (f"plan ended with {done}/{total} done; the goal stays open (a skipped step is not proof). "
                f"Record: {receipt}")
    plan["finished"], plan["outcome"] = time.time(), "completed"
    try:
        gnoc_plan.save(sid, plan)
        receipt = _work_receipt(agent, plan, task, outcome="completed")
    except OSError as e:
        return f"plan is done, but the completion record could not be written ({type(e).__name__}: {e}); goal open"
    acc = gnoc_goal.accept(WORK_DONE_CRITERION, "met", receipt, owner=sid)
    if acc.startswith(("refused", "NOT", "no active", "the goal is")):
        return f"completion record: {receipt}\ngoal NOT closed: {acc}"
    closing = gnoc_goal.done(receipt, owner=sid)
    return f"completion record: {receipt}\n{closing}"


def _work_resolved(agent, plan, task, close_goal):
    """Report an already-resolved plan once, without spending another model turn."""
    (
        _work_complete, gnoc_plan, green, say, white, yellow,
    ) = bind(
        "_work_complete", "gnoc_plan", "green", "say", "white", "yellow",
    )
    done, total = gnoc_plan.progress(plan)
    if total and done == total:
        say(green("● ") + white(f"all {total} plan step(s) done"))
    elif done:
        say(yellow(f"  plan ended with {done}/{total} step(s) done; the rest were skipped"))
    else:
        say(yellow(f"  plan ended with no completed step ({total} skipped)"))
    closing = _work_complete(agent, plan, task, close_goal)
    if closing:
        say(closing)


def _work_loop(agent, task, cap=None, close_goal=True):
    """Long-horizon autonomous task completion: turn after turn until the plan is done, the user is needed,
    the budget runs out, or the user types. The plan block in the system prompt carries the next step across turns;
    this loop is the discipline that makes the turns happen. A completed plan is reconciled with the standing
    goal (its acceptance criteria and a receipt) instead of leaving the goal active forever."""
    # No default turn budget (GreyNOC 2026-11-18: a goal must not stop until it is complete). The guards are
    # the stall detector below, Ctrl-C, typing and NEEDS:. GNOC_WORK_TURNS / --cap still set a budget.
    (
        GOAL_EMPTY_MAX, GOAL_STALL_MAX, INTERRUPT, T, TYPED, WORK_CONTINUE, WORK_PROMPT,
        WORK_STALL_NUDGE, _goal_live, _work_resolved, contextlib, dim, drive_goal,
        gnoc_plan, goal_before_stop, os, re, red, say, yellow,
    ) = bind(
        "GOAL_EMPTY_MAX", "GOAL_STALL_MAX", "INTERRUPT", "T", "TYPED", "WORK_CONTINUE", "WORK_PROMPT",
        "WORK_STALL_NUDGE", "_goal_live", "_work_resolved", "contextlib", "dim",
        "drive_goal", "gnoc_plan", "goal_before_stop", "os", "re", "red", "say", "yellow",
    )
    try:
        cap = int(cap or os.environ.get("GNOC_WORK_TURNS") or 0)
    except (TypeError, ValueError):
        cap = 0
    cap = min(max(cap, 0), 1000)   # a typo in an explicit budget must not start a thousand-turn runaway
    plan = gnoc_plan.load(agent.s.get("sid"))
    if not task and not plan:
        say(red("  /work <task> starts a long task; /work alone continues the active plan"))
        return 0
    if plan and gnoc_plan.all_resolved(plan):
        _work_resolved(agent, plan, task, close_goal)
        return 0
    say(T.bgreen("  ▶ ") + T.byellow("working") + dim(("  ·  " + (f"up to {cap} turn(s)" if cap else "until done"))
                                                   + ", Ctrl-C hands control back, it stops on NEEDS: or when "
                                                   "the plan is done"))
    rounds, stall, last_prog, stop, empty = 0, 0, None, "", 0
    try:
        while not cap or rounds < cap:
            agent.interrupted = False
            INTERRUPT.clear()
            if stall >= GOAL_STALL_MAX:
                stop = "stalled"
                say(yellow(f"  {stall} turns without the plan advancing or a tool call; handing back to you")
                    + dim("  ·  /work continues"))
                break
            prompt = WORK_PROMPT.format(task=task) if rounds == 0 else WORK_CONTINUE
            if stall >= 3:
                prompt = WORK_STALL_NUDGE.format(n=stall) + prompt
            ans = agent.turn(prompt)
            rounds += 1
            plan = gnoc_plan.load(agent.s.get("sid"))
            if not plan and rounds == 1 and not int(agent.s.get("_turn_tools_last") or 0):
                # No plan AND no tool ran: the turn was prose, not a small one-step task done without a plan.
                say(dim("  no plan document yet; asking once more, it must call the tool"))
                ans = agent.turn("Call plan(action=set, goal=..., steps=[{action, verify, why}, ...]) with your "
                                 "steps NOW - do not describe them in prose - then start step 1.")
                rounds += 1
                plan = gnoc_plan.load(agent.s.get("sid"))
            if TYPED.pending():
                stop = "typed"
                say(yellow("  you typed while it worked; handing control back"))
                break
            if agent.interrupted:
                stop = "interrupted"
                say(yellow("  work paused; talk to it, or /work to continue"))
                break
            if not (ans or "").strip():
                # One empty answer is not a dead model: right after plan(action=set) the lead answered nothing and
                # /work stopped with "lead model down?" eleven seconds after the model answered (2026-11-20 SWE
                # drive). Like /goal, it takes GOAL_EMPTY_MAX empty turns in a row; the plan carries the work on.
                empty += 1
                if empty >= GOAL_EMPTY_MAX:
                    stop = "error"
                    say(red(f"  {empty} turns in a row with no answer (lead model down?); work paused")
                        + dim("  ·  /work resumes"))
                    break
                if plan:
                    stall += 1
                    continue
                stop = "error"
                say(red("  no answer and no plan yet; work paused") + dim("  ·  /work resumes"))
                break
            empty = 0
            if not plan and rounds > 1:
                stop = "noplan"
                say(red("  no plan document after two turns; work stopped") + dim("  ·  /work <task> to restart"))
                break
            if re.search(r"(?m)^\s*NEEDS:", ans or ""):
                stop = "needs"
                say(yellow("  the work is waiting on you (see NEEDS: above)"))
                with contextlib.suppress(Exception):
                    closing = goal_before_stop("work waiting on you")
                    if closing:
                        say(closing)
                break
            if plan:
                prog = gnoc_plan.progress(plan)
                if gnoc_plan.all_resolved(plan):
                    _work_resolved(agent, plan, task, close_goal)
                    stop = "done" if prog[1] and prog[0] >= prog[1] else "skipped"
                    break
                if last_prog is not None and prog == last_prog:
                    tools_now = int(agent.s.get("_turn_tools_last") or 0)
                    stall = stall + 1 if tools_now == 0 else 0
                else:
                    stall = 0
                last_prog = prog
            else:
                stall = 0
        if not stop and cap and rounds >= cap:
            plan = gnoc_plan.load(agent.s.get("sid"))
            done = gnoc_plan.progress(plan)[0] if plan else 0
            say(yellow(f"  work budget reached ({cap} turn(s))") + dim(f"  ·  /work continues ({done} step(s) done)"))
            with contextlib.suppress(Exception):
                closing = goal_before_stop("work budget reached")
                if closing:
                    say(closing)
    except KeyboardInterrupt:
        say(yellow("\n  work paused; talk to it, or /work to continue"))
        with contextlib.suppress(Exception):
            closing = goal_before_stop("work interrupted")
            if closing:
                say(closing)
    say(dim(f"  {rounds} work turn(s)"))
    if stop in ("done", "skipped") and close_goal and _goal_live(agent):
        # the plan is finished but the goal is not (his own --accept criteria are still open): keep going
        rounds += drive_goal(agent, why="the plan is done; the goal's acceptance criteria are still open")
    return rounds


def t_plan(ctx, action="show", goal=None, steps=None, index=None, status=None, risks=None,
           constraints=None, not_doing=None, evidence=None):
    """The deepcode-style plan document. action=set proposes a plan and SHOWS it as a panel; update marks a
    step (status: doing|done|skipped, index 1-based or 'next'); show reprints it; clear drops it. A done step
    that has a verify= needs evidence= (the command output, diff or path that proved it)."""
    (
        _now, contextlib, gnoc_plan, say, tasks_add, tasks_find, tasks_mark,
    ) = bind(
        "_now", "contextlib", "gnoc_plan", "say", "tasks_add", "tasks_find", "tasks_mark",
    )
    action = str(action or "show").lower()
    sid = ctx.s.get("sid") or "unknown"
    if action not in ("set", "show", "update", "clear"):
        return f"plan action is set, show, update or clear (got {action!r}); nothing changed"
    if action == "clear":
        plan = gnoc_plan.load(sid)
        if plan:
            for s in plan["steps"]:
                tid = s.get("task_id") or tasks_find(f"plan: {s['action']}"[:160], "plan")
                with contextlib.suppress(Exception):
                    tasks_mark(tid, "done", note="plan cleared")
        gnoc_plan.clear(sid)
        return "plan cleared" + (" (open plan rows in the tasks ledger were closed)" if plan else "")
    if action == "show":
        plan = gnoc_plan.load(sid)
        if not plan:
            return "no plan yet (plan action=set proposes one)"
        if gnoc_plan.all_resolved(plan):
            d, n = gnoc_plan.progress(plan)
            return gnoc_plan.panel(plan) + f"\nplan resolved: {d}/{n} done, the rest skipped"
        return gnoc_plan.panel(plan)
    if action == "update":
        plan = gnoc_plan.load(sid)
        if not plan:
            return "no plan to update (plan action=set proposes one)"
        want = str(status or "").lower()
        if want not in gnoc_plan.STEP_STATUS:
            return f"status must be one of {', '.join(gnoc_plan.STEP_STATUS)} (got {status!r})"
        i, s = gnoc_plan.next_step(plan)
        if index is not None and str(index).lower() != "next":   # 'next' is the default the docstring promises
            try:
                i = int(index)
            except (TypeError, ValueError):
                return f"index must be a step number (1-{len(plan['steps'])}) or 'next'; got {index!r}"
        if not i:
            if gnoc_plan.all_resolved(plan):
                d, n = gnoc_plan.progress(plan)
                return f"every step is already resolved ({d}/{n} done, the rest skipped); nothing to update"
            return f"no step {index!r} to update (the plan has {len(plan['steps'])} steps)"
        if not (1 <= i <= len(plan["steps"])):
            return f"no step {index!r} to update (the plan has {len(plan['steps'])} steps)"
        step = plan["steps"][i - 1]
        proof = " ".join(str(evidence or "").split())[:400]
        if want == "done":
            if step.get("verify") and not proof:
                return (f"refused: step {i} is verified by {step['verify']!r}; marking it done needs "
                        f"evidence=<the command output, diff or artifact path that proved it>. Nothing changed.")
            step["evidence"] = proof
            step["done_at"] = _now().isoformat(timespec="seconds")
        elif want in ("pending", "doing"):
            step["evidence"] = ""
            step.pop("done_at", None)
        else:   # skipped: keep the reason (if given) but never a stale done timestamp
            step["evidence"] = proof
            step.pop("done_at", None)
        step["status"] = want
        try:
            gnoc_plan.save(sid, plan)
        except OSError as e:
            return f"NOT recorded: the plan file could not be written ({type(e).__name__}: {e})"
        # Keep the tasks ledger in step with the plan. The old sync only ADDED rows at plan-set time, so a
        # finished plan still showed every step open in GreyNOC's to-do list.
        tid = step.get("task_id") or tasks_find(f"plan: {step['action']}"[:160], "plan")
        if tid:
            with contextlib.suppress(Exception):
                if want in ("done", "skipped"):
                    tasks_mark(tid, "done", note="plan step skipped" if want == "skipped" else None)
                else:
                    tasks_mark(tid, "open")
        # the compact live list, not panel(): a box per step update scrolled the actions off the screen
        say("")
        say(gnoc_plan.checklist(plan, highlight=i))
        d, n = gnoc_plan.progress(plan)
        return f"step {i} -> {want} ({d}/{n} done)" + (f"; evidence: {proof[:120]}" if proof else "")
    # action == "set": validate, persist, SHOW the panel (the plan preview, deepcode-style), sync the tasks ledger
    ok, err = gnoc_plan.validate({"goal": goal, "steps": steps, "risks": risks,
                                  "constraints": constraints, "not_doing": not_doing})
    if not ok:
        return f"bad arguments: {err}"
    plan = gnoc_plan.normalize({"goal": goal, "steps": steps, "risks": risks,
                                "constraints": constraints, "not_doing": not_doing})
    # A plan being replaced must not leave its old rows open in GreyNOC's tasks ledger. Close them with a
    # note before the new rows are added, or every revision silently doubles the to-do list.
    old = gnoc_plan.load(sid)
    for s in (old or {}).get("steps", []):
        tid = s.get("task_id") or tasks_find(f"plan: {s['action']}"[:160], "plan")
        with contextlib.suppress(Exception):
            tasks_mark(tid, "done", note="plan replaced")
    try:
        gnoc_plan.save(sid, plan)
    except OSError as e:
        return f"NOT recorded: the plan file could not be written ({type(e).__name__}: {e})"
    say(gnoc_plan.panel(plan))
    linked = False
    for step, (text, tag) in zip(plan["steps"], gnoc_plan.tasks_rows(plan)):
        try:
            step["task_id"] = tasks_add(text, tag=tag)
            linked = True
        except OSError:
            break
    if linked:
        with contextlib.suppress(OSError):
            gnoc_plan.save(sid, plan)
    d, n = gnoc_plan.progress(plan)
    return (f"plan set: {d}/{n} steps, shown above and synced to tasks. Work step 1; mark each done with "
            f"plan(action=update, status=done, evidence=<the proof>) once its verification passed.")
