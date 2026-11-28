"""Slash-command dispatch, extracted from the gnoc_agent facade."""
from .runtime import bind


# Read-only status commands whose output the NEXT message talks about ("/defender alerts" then "acknowledge the
# newest one"; "/defender triage" then "close any case with no evidence"). Their output never reached the
# conversation, so the lead went to the bug-bounty inbox and marked an unrelated report read (defense drive
# 2026-11-22). The command and what it printed are kept in the conversation as one exchange.
_SLASH_KEPT = {"defender": None, "ledger": None, "chains": None, "report": None, "approvals": None, "tasks": None,
               "jobs": None, "agents": None, "changes": None, "brief": None, "lessons": None, "econ": None}
_SLASH_KEEP_CHARS = 3000


def _from_terminal(sys_mod):
    """True when stdin is a terminal. A tool's subprocess (bash, bg) gets /dev/null, so a one-shot `gnoc chat
    "/schedule ..."` started by a model is refused even though that launcher marks its own argv as typed."""
    try:
        return bool(sys_mod.stdin and sys_mod.stdin.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _slash_kept(line):
    parts = str(line or "")[1:].split()
    if not parts or parts[0].lower() not in _SLASH_KEPT:
        return False
    if parts[0].lower() == "defender" and len(parts) > 1 and parts[1].lower() in (
            "enforce", "undo", "auto", "watch", "allow", "deny", "admin", "target", "install", "setup"):
        return False   # a change, not a view: what it did is in the journal, and it is not a view to talk about
    return True


def _slash_remembered(agent, line, legacy):
    import contextlib
    import re
    import sys

    class _Tee:
        def __init__(self, real):
            self.real, self.buf, self.n = real, [], 0

        def write(self, x):
            if self.n < 40000:
                self.buf.append(str(x))
                self.n += len(str(x))
            return self.real.write(x)

        def __getattr__(self, name):
            return getattr(self.real, name)

    real = sys.stdout
    tee = _Tee(real)
    sys.stdout = tee
    agent._slash_capturing = True
    try:
        return handle_slash(agent, line, legacy)
    finally:
        sys.stdout = real
        agent._slash_capturing = False
        text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", "".join(tee.buf)).strip()
        s = getattr(agent, "s", None)
        if isinstance(s, dict) and s.get("_one_shot") and not s.get("history") \
                and __import__("os").environ.get("GNOC_KEEP_SLASH_ONESHOT") != "1":
            s = None   # `gnoc chat "/defender sweep"` from cron: no new conversation per run (a resumed one keeps it)
        if text and isinstance(s, dict):
            if len(text) > _SLASH_KEEP_CHARS:
                text = text[:_SLASH_KEEP_CHARS] + f"\n... ({len(text) - _SLASH_KEEP_CHARS} more characters not kept)"
            s.setdefault("history", []).extend([
                {"role": "user", "content": line.strip()},
                {"role": "assistant", "content": f"[output of {line.strip()}, shown to the user]\n{text}"}])
            with contextlib.suppress(Exception):
                agent.save()


_BUILTIN_CMDS = []


def builtin_command_names(legacy=()):
    """Every slash command gnoc itself answers: read from handle_slash's own branches, so a command added there is
    covered without a second list to keep in step. A plugin command with one of these names never runs."""
    import inspect
    import re
    if not _BUILTIN_CMDS:
        src = inspect.getsource(handle_slash)
        names = set(re.findall(r'cmd == "([a-z0-9?-]+)"', src))
        for grp in re.findall(r"cmd in \(([^)]*)\)", src):
            names |= set(re.findall(r'"([a-z0-9?-]+)"', grp))
        from gnoc_core.cli import OPERATOR_COMMANDS
        _BUILTIN_CMDS.append(frozenset(names | set(OPERATOR_COMMANDS)))
    return _BUILTIN_CMDS[0] | set(legacy or ())


def handle_slash(agent, line, legacy):
    (
        BAR, DEFENDER_WATCH, _turn_core, EFFORT, EFFORTS, MON, OFFLINE, PLAIN, REASONING_NAMES, SKIP_PERMS, SPIN,
        STEPS_OVERRIDE, T, THINK_UI, TYPED, WS, _BTW, _BTW_LOCK, _LEARN_NOTES, _cloud_text, _compact, _criteria,
        _defender_state, _dir_from, _git, _gpu1_worker, _graph_db, _graph_import_scope, _lead_host, _lead_llm,
        _plan_request, _rel_home, _role_set, _short_model, _split_flags, _title_of, _tool_tokens, _turn_call_cap,
        attach_collab, blue, change_dir, changes, clear_program, cmd_gpus, contextlib, copy_cmd, ctx_for,
        ctx_pct_of, defender_cmd, diff_panel, dim, effort, export_transcript, fit_tools, gnoc_collab, gnoc_comms,
        gnoc_goal, gnoc_graph, gnoc_hf, gnoc_hunt, gnoc_learn, gnoc_modes, gnoc_plan, gnoc_report, gnoc_secrets,
        gnoc_ws, goal_cmd, green, help_text, hunt_stance, list_sessions, llm_endpoints, model_rows,
        note_program_source, offline, os, page_answer, pick_model, program_origin, prompt_ctx_pct, re, red,
        resolve, resolve_program, role_spec, root, routing_text, run_reflection, say, set_repo, set_role, shlex,
        shutil, steps_label, subprocess, sys, t_bot, t_jobs, t_pay_check, t_plan, t_second_opinion, t_set_program,
        t_tasks, time, tool_budget, turn_tools, undo, warn_goal_excluded, white, yellow,
    ) = bind(
        "BAR", "DEFENDER_WATCH", "_turn_core", "EFFORT", "EFFORTS", "MON", "OFFLINE", "PLAIN", "REASONING_NAMES",
        "SKIP_PERMS", "SPIN", "STEPS_OVERRIDE", "T", "THINK_UI", "TYPED", "WS", "_BTW", "_BTW_LOCK",
        "_LEARN_NOTES", "_cloud_text", "_compact", "_criteria", "_defender_state", "_dir_from", "_git",
        "_gpu1_worker", "_graph_db", "_graph_import_scope", "_lead_host", "_lead_llm", "_plan_request",
        "_rel_home", "_role_set", "_short_model", "_split_flags", "_title_of", "_tool_tokens", "_turn_call_cap",
        "attach_collab", "blue", "change_dir", "changes", "clear_program", "cmd_gpus", "contextlib", "copy_cmd",
        "ctx_for", "ctx_pct_of", "defender_cmd", "diff_panel", "dim", "effort", "export_transcript", "fit_tools",
        "gnoc_collab", "gnoc_comms", "gnoc_goal", "gnoc_graph", "gnoc_hf", "gnoc_hunt", "gnoc_learn", "gnoc_modes",
        "gnoc_plan", "gnoc_report", "gnoc_secrets", "gnoc_ws", "goal_cmd", "green", "help_text", "hunt_stance",
        "list_sessions", "llm_endpoints", "model_rows", "note_program_source", "offline", "os", "page_answer",
        "pick_model", "program_origin", "prompt_ctx_pct", "re", "red", "resolve", "resolve_program", "role_spec",
        "root", "routing_text", "run_reflection", "say", "set_repo", "set_role", "shlex", "shutil", "steps_label",
        "subprocess", "sys", "t_bot", "t_jobs", "t_pay_check", "t_plan", "t_second_opinion", "t_set_program",
        "t_tasks", "time", "tool_budget", "turn_tools", "undo", "warn_goal_excluded", "white", "yellow",
    )
    if not getattr(agent, "_slash_capturing", False) and _slash_kept(line):
        return _slash_remembered(agent, line, legacy)
    parts = line[1:].split(maxsplit=1)
    cmd, rest = (parts[0].lower(), parts[1] if len(parts) > 1 else "") if parts else ("help", "")
    if cmd in ("help", "?"):
        say(help_text())
    elif cmd == "deep":
        if rest:
            agent.s["_typed"] = rest
            agent.turn(rest, deep=True)
        else:
            say(red("usage: /deep <request>"))
    elif cmd == "hunt":
        w = rest.split(maxsplit=1)
        d = _dir_from(w[0]) if w and ("/" in w[0] or w[0].startswith("~")) else None
        prog = resolve_program(d or w[0]) if w else None
        goal = (w[1] if len(w) > 1 else "") if (prog or d) else rest
        if len(w) == 1 and not (prog or d):
            # '/hunt kongg' is a typo, not a goal: it must not start an endless hunt on whatever program is active
            say(red(f"  no program matches {w[0]!r}") + dim("  (/hunt <program> [goal]; gnoc pivot <handle> intakes "
                                                           "a new one; /hunt alone hunts the active program)"))
            return
        if d:
            say(green("● ") + change_dir(agent.ctx, d, goal or f"hunt {prog or ''}".strip()))
        warn_goal_excluded(prog, goal)   # T-303: the goal text gets the same exclusion check a hypothesis gets
        agent.hunt(prog, goal)
    elif cmd == "bot":
        say(t_bot(agent.ctx, rest.strip() or "summary"))
    elif cmd == "goal":
        goal_cmd(agent, rest)
    elif cmd in ("tasks", "todo"):
        arg = rest.strip()
        low = arg.lower()
        if not arg or low in ("list", "show"):
            say(t_tasks(agent.ctx, "list"))
        else:
            verb, _, body = arg.partition(" ")
            verb, body = verb.lower(), body.strip()
            if verb == "add" and body:
                say(t_tasks(agent.ctx, "add", text=body))
            elif verb in ("done", "reopen") and body:
                say(t_tasks(agent.ctx, verb, id=body))
            elif verb == "note" and body:
                tid, _, note = body.partition(" ")
                say(t_tasks(agent.ctx, "note", id=tid, text=note) if note.strip()
                    else red("  usage: /tasks note <T-id> <what you learned>"))
            elif verb in ("done", "reopen", "note"):
                say(red(f"  usage: /tasks {verb} <T-id>" + (" <text>" if verb == "note" else "")))
            else:
                # a bare line is a new task, the way a to-do list should behave
                say(t_tasks(agent.ctx, "add", text=arg))
    elif cmd == "mode":
        want = rest.strip().lower()
        if want == "general":
            want = "auto"
        extra = ""
        if want.startswith("defender "):          # /mode defender auto  ->  the mode plus auto-defense
            want, extra = "defender", want.split(None, 1)[1]
        if want in ("auto", *gnoc_modes.MODES):
            was = agent.s.get("mode")
            agent.s["mode"] = want
            if want not in gnoc_modes.HUNT_STANCE_MODES:
                agent.s.pop("stance", None)   # /mode auto (or general): back to the general assistant
            agent.save()
            if want == "defender":
                st = _defender_state(agent.ctx)
                if extra in ("auto off", "watch off"):
                    defender_cmd(agent, extra)
                elif extra in ("auto", "auto on"):
                    st["auto"] = True
                    defender_cmd(agent, "auto on")
                else:
                    # AUTO-DEFENSE IS THE DEFAULT (2026-11-18). Entering defender mode starts the watcher
                    # in auto mode unless GreyNOC explicitly turned it off for this chat.
                    if st.get("auto") is not False:
                        st["auto"] = True
                        defender_cmd(agent, "auto on")
                if was != "defender":
                    say(T.bred("  ⛨ ") + T.byellow("defender mode: sweeping "
                                                     + (_defender_state(agent.ctx).get("target") or "this machine")
                                                     + " now") + dim("  (/defender for status and controls)"))
                    agent.turn("Defender mode is on and auto-defense is ON. Run defend(action=sweep) now. Report the "
                               "findings worst first in plain words, say exactly what auto-defense applied or "
                               "contained (journal ids), show any TRIAGE case with its priority and playbook, then ask "
                               "me the sweep's QUESTIONS in one numbered message. Do not claim a fix the journal does "
                               "not show.")
            elif was == "defender" and DEFENDER_WATCH.running():
                DEFENDER_WATCH.stop()
                say(dim("  defender watcher stopped (left defender mode)"))
        elif want:
            say(red("usage: /mode auto|general|swe|design|review|hunt|chain|prod|defender [auto]"))
        cur = agent.s.get("mode") or "auto"
        say(dim("  mode: ") + green(cur) + dim("  (auto = picked from each request: "
            + ", ".join(f"{k} = {v['label']}" for k, v in gnoc_modes.MODES.items()) + ")"))
        say(dim("  chat: ") + green("hunt" if hunt_stance(agent.ctx) else "general")
            + dim("  (general until you order a hunt: hunt <program>, keep hunting, /hunt, /mode hunt)"))
    elif cmd == "defender" and os.name == "nt":
        say(dim("  the defender checks a Linux machine (ss, /proc, systemd, ufw) and is not available on native "
                "Windows yet. It works on Linux, including a Linux computer you reach over SSH."))
    elif cmd == "defender":
        _dw = rest.lower().split()
        if (_dw[:1] == ["vulnwatch"] and _dw[1:2] in (["on"], ["off"])) or (
                _dw[:1] == ["schedule"] and len(_dw) > 1 and _dw[1] not in ("show", "status", "list")):
            # both install or remove a timer, and only the user sets a schedule: the /schedule typed-line check
            if getattr(agent, "_typed_line", None) is not line or not _from_terminal(sys):
                say(red(f"  /defender {' '.join(_dw[:2])} runs only from a line you typed at the prompt: refused, "
                        "nothing changed"))
                return
        defender_cmd(agent, rest)
    elif cmd == "plan":
        # /plan | /plan <request> | /plan on|off | /plan show|status|next | /plan done N [proof] | /plan go
        arg = rest.strip()
        low = arg.lower()
        sid = agent.s.get("sid")
        word = low.split(maxsplit=1)[0] if low else ""
        if not arg:
            plan = gnoc_plan.load(sid)
            say(gnoc_plan.panel(plan) if plan else dim("  no plan yet") + dim("  (/plan <request> proposes one; "
                "/plan on pins plan mode for every message)"))
        elif word in ("help", "?"):
            say(dim("  /plan <request> proposes a plan · /plan on|off · /plan show|status|next · "
                    "/plan done|doing|skip N [proof] · /plan go (works it across turns with /work) · /plan clear"))
        elif low in ("on", "off"):
            agent.s["plan_mode"] = low == "on"
            agent.save()
            say((green("  💡 plan mode: ON") if agent.s["plan_mode"] else dim("  plan mode: off"))
                + dim("  (every message proposes a plan first; enter implements it)"))
        elif low in ("show", "view"):
            plan = gnoc_plan.load(sid)
            say(gnoc_plan.panel(plan) if plan else dim("  no plan yet"))
        elif low in ("status", "next"):
            plan = gnoc_plan.load(sid)
            if not plan:
                say(dim("  no plan yet"))
            else:
                say(gnoc_plan.checklist(plan))
                d, n = gnoc_plan.progress(plan)
                i, s = gnoc_plan.next_step(plan)
                if s:
                    say(dim(f"  next: step {i}/{n} - {s['action']}"
                            + (f"  (verify: {s['verify']})" if s.get("verify") else "")))
                else:
                    say(green("  every step is done or skipped") + dim("  (/plan clear when reviewed)"))
        elif low in ("clear", "none", "drop"):
            say(dim("  " + t_plan(agent.ctx, "clear")))
        elif low in ("go", "implement", "do"):
            plan = gnoc_plan.load(sid)
            if plan:
                say(T.bgreen("  ▶ ") + dim("working the plan across turns (/work loop; Ctrl-C hands control back)"))
                agent.work("")
            else:
                say(red("  no plan to implement") + dim("  (/plan <request> proposes one)"))
        elif word in ("done", "doing", "start", "skip", "skipped", "reopen"):
            parts = arg.split(maxsplit=2)
            if len(parts) < 2:
                say(red(f"  usage: /plan {word} <step-number> [proof]"))
            else:
                st = {"done": "done", "doing": "doing", "start": "doing", "skip": "skipped",
                      "skipped": "skipped", "reopen": "pending"}[word]
                say(t_plan(agent.ctx, "update", index=parts[1], status=st,
                           evidence=parts[2] if len(parts) > 2 else ""))
        else:
            _plan_request(agent, arg)
    elif cmd == "setup":
        # the guided first-run setup, again: a model on this computer (Ollama) or a cloud API key
        import gnoc_setup
        ok, how = gnoc_setup.usable(role_spec("lead"), role_spec("worker"))
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            say(("  model ready: " + how if ok else "  no working model: " + how)
                + dim("  ·  /setup asks questions, so it needs an interactive terminal"))
        else:
            gnoc_setup.run(set_role, reason="" if ok else how, current=how if ok else "")
    elif cmd == "init":
        # workspace setup, Claude-Code-strong: /init [refresh] | /init project <name> [node|python|web]
        parts = rest.split()
        if parts and parts[0].lower() in ("project", "new"):
            name = parts[1] if len(parts) > 1 else ""
            stack = parts[2].lower() if len(parts) > 2 else None
            parent = root() if root() != WS else os.path.expanduser("~")
            path, lines = gnoc_ws.scaffold_project(parent, name, stack)
            for ln in lines:
                say(green("● ") + white(ln) if ln.startswith("created") else dim("  ") + ln)
            if path and set_repo(agent, path):
                say(dim("  the repo is set up; give it the first task (or /work <task>)"))
        else:
            if root() == WS:
                say(dim("  the hunt workspace is already a working workspace") + dim("  (/init project <name> "
                    "scaffolds a new project)"))
            else:
                lines = gnoc_ws.init_workspace(root(), program=agent.ctx.program)
                for ln in lines:
                    say(green("● ") + white(ln))
                say(dim("  GNOC.md rides the system prompt from the next turn; gchat.md keeps the session notes"))
    elif cmd == "work":
        arg = rest.strip()
        if arg.lower() in ("status", "show"):
            say(dim(gnoc_goal.status_text()))
            plan = gnoc_plan.load(agent.s.get("sid"))
            if plan:
                say(gnoc_plan.checklist(plan))
                i, s = gnoc_plan.next_step(plan)
                if s:
                    say(dim(f"  next: step {i} - {s['action']}"
                            + (f"  (verify: {s['verify']})" if s.get("verify") else "")))
            else:
                say(dim("  no plan yet"))
            return
        parsed, err = _split_flags(arg, value=("--turns", "--accept"),
                                   boolean=("--force", "--no-goal"))
        if err:
            say(red("  " + err))
            return
        words, vals, flags = parsed
        task = " ".join(words).strip()
        cap = None
        if vals.get("--turns"):
            try:
                cap = int(vals["--turns"][-1])
            except (TypeError, ValueError):
                say(red(f"  --turns needs a whole number, not {vals['--turns'][-1]!r}"))
                return
            if cap < 1:
                say(red("  --turns must be at least 1"))
                return
        if not task and not gnoc_plan.load(agent.s.get("sid")):
            say(red("  /work <task> starts a long task; /work alone continues the active plan")
                + dim("  (--turns N caps the loop, --accept \"criterion\" gates the goal, --no-goal plans only)"))
            return
        agent.work(task, cap=cap, force="--force" in flags, acceptance=_criteria(vals.get("--accept")),
                   no_goal="--no-goal" in flags)
    elif cmd == "thoughts":
        want = rest.strip().lower()
        if want in ("on", "off"):
            SPIN.show_thoughts = (want == "on")   # the display only: the model reasons either way
            agent.s["thoughts_shown"] = SPIN.show_thoughts   # kept for every later chat
            agent.save()
        elif want:
            say(red("  usage: /thoughts on|off"))
        say(dim("  reasoning display (live status-line ticker + the ✻ thinking block kept above each answer/action): ")
            + (green("on") if SPIN.show_thoughts else yellow("off"))
            + dim("  (/thoughts on|off; the model reasons either way, /reasoning sets how hard)"))
    elif cmd == "gpus":
        cmd_gpus()
    elif cmd == "tools":
        # Since the tool list is FITTED per turn (the whole registry is 18k tokens and the fallback model
        # has 16k of context), what the model can actually call is no longer obvious. This shows it.
        model, host = resolve("lead", quiet=True)
        # the same selection Agent.turn makes for a plain request here: code trimming in a repo, the general
        # stance otherwise, and the turn's pinned core (it showed the unfiltered registry, QAQC 2026-11-19)
        in_code = root() != WS
        allt = turn_tools(False, False, code=in_code, general=not in_code and not hunt_stance(agent.ctx, rest))
        budget = tool_budget(host, model)
        kept, dropped = fit_tools(allt, budget, rest.strip(), agent.ctx.s.get("_tool_sticky") or [],
                                  core=_turn_core(rest.strip(), hunting=bool(agent.ctx.s.get("hunting")),
                                                 in_code=in_code))
        names = sorted((t.get("function") or {}).get("name") for t in kept)
        say(f"  {len(kept)} of {len(allt)} tools loaded for the next turn on "
            + blue(f"{_short_model(model)}@{host}")
            + dim(f"  ({_tool_tokens(kept)} of {budget} budget tokens, context {ctx_for(host, model)})"))
        for i in range(0, len(names), 6):
            say(dim("    " + "  ".join(f"{n:<16}" for n in names[i:i + 6]).rstrip()))
        if dropped:
            say(dim(f"  not loaded ({len(dropped)}): ") + dim(", ".join(dropped[:18])
                                                              + (" ..." if len(dropped) > 18 else "")))
            say(dim("  name one in your message and it loads next turn, or /tools <words> to preview the pick"))
        sticky = agent.ctx.s.get("_tool_sticky") or []
        if sticky:
            say(dim("  kept because this conversation used them: " + ", ".join(sticky[:10])))
    elif cmd == "lessons":
        rows = gnoc_learn.listing(rest.strip())
        if not rows:
            say(dim("  no lessons yet" + (f" matching {rest.strip()!r}" if rest.strip() else "")))
        for r in rows:
            say(f"  {yellow(r['id'])} {blue(r['kind'])}{dim(' ' + r['program'] if r.get('program', '*') != '*' else '')}"
                f"  {r['text']}" + dim(f"  (+{r.get('reinforced', 0)} · used {r.get('uses', 0)})"))
    elif cmd == "forget":
        lid = rest.strip().upper()
        say(green(f"  {lid} retired (kept in lessons-retired.jsonl)") if lid and gnoc_learn.retire(lid, "The user: /forget")
            else red(f"  no lesson {lid or '?'}: /lessons shows the ids"))
    elif cmd == "learn":
        arg = rest.strip().lower()
        if arg in ("on", "off"):
            agent.s["learn"] = arg == "on"
            agent.save()
            say(f"  learning {'ON' if agent.s['learn'] else 'off'}")
        elif arg == "now":
            start = max((i for i, m in enumerate(agent.s.get("history") or []) if m.get("role") == "user"), default=None)
            if start is None:
                say(red("  nothing to learn from yet"))
            else:
                SPIN.start("Reflecting")
                try:
                    n = run_reflection(agent.s["history"][start:], agent.ctx.program)
                finally:
                    SPIN.stop()
                say(green("● ") + (gnoc_learn.summary(n) or "nothing new worth keeping"))
                _LEARN_NOTES.clear()
        else:
            if arg:
                say(red("  usage: /learn on|off|now"))
            say(f"  learning {'ON' if agent.s.get('learn', True) else 'off'} · {len(gnoc_learn.load())} lessons"
                "   (/learn on|off|now, /lessons [query], /forget L#)")
    elif cmd == "notify":
        import gnoc_notify
        arg = rest.strip().lower()
        if arg in ("on", "off"):
            gnoc_notify.OFF[0] = arg == "off"
        elif arg == "test":
            say(green("● ") + ("sent a test notification" if gnoc_notify.notify("gnoc", "notifications work", True)
                               else "no notifier here (notify-send, a WSL toast or osascript)"))
        elif arg:
            say(red("  usage: /notify on|off|test"))
        say(dim(f"  desktop notifications {'off' if gnoc_notify.OFF[0] else 'on'} for turns over "
                f"{gnoc_notify.after_seconds()}s and approval waits (GNOC_NOTIFY_AFTER sets the seconds)"))
    elif cmd == "save":
        # "can the harness create and give me the html file in the chat so I can choose where to save?" (GreyNOC,
        # 2026-11-23): the system's own Save As window, starting in Downloads with the file's name
        import gnoc_export
        files = gnoc_export.made_files(agent.ctx)
        parts = rest.split(maxsplit=1)
        chosen = gnoc_export.pick(files, parts[0] if parts else "")
        if not files:
            say(dim("  " + gnoc_export.listing(files)))
        elif not chosen:
            say(red(f"  no file matches {(parts[0] if parts else '')!r}: /files lists them"))
        else:
            src = chosen[0]
            dest = parts[1].strip() if len(parts) > 1 else None
            if dest is None:
                say(dim(f"  choose where to save {os.path.basename(src)} ..."))
                dest = gnoc_export.save_dialog(src)
            if dest is None:
                # no window here (an ssh session, no desktop): ask in the terminal
                default = os.path.join(gnoc_export.downloads_dir(), os.path.basename(src))
                try:
                    typed = input(f"  save {os.path.basename(src)} to [{default}]: ").strip()
                except (EOFError, KeyboardInterrupt):
                    typed = None
                dest = default if typed == "" else typed
            if not dest:
                say(dim("  not saved (cancelled)"))
            else:
                try:
                    say(green("● ") + f"saved {gnoc_export.save_as(src, dest)}")
                except OSError as e:
                    say(red(f"  could not save it there: {e}"))
    elif cmd in ("files", "download", "open"):
        # "can we give it the capability to download the file from chat? i want to export attachments straight from
        # chat" (GreyNOC, 2026-11-23): what this chat made, copied to Downloads or opened in its app
        import gnoc_export
        files = gnoc_export.made_files(agent.ctx)
        parts = rest.split(maxsplit=1)
        if cmd == "files":
            say(gnoc_export.listing(files))
        elif not files:
            say(dim("  " + gnoc_export.listing(files)))
        else:
            which = parts[0] if parts else ""
            chosen = gnoc_export.pick(files, which)
            if not chosen:
                say(red(f"  no file matches {which!r}: /files lists them"))
            elif cmd == "open":
                try:
                    how = gnoc_export.open_file(chosen[0])
                    say(green("● ") + f"opened {chosen[0]} ({how})")
                except Exception as e:  # noqa: BLE001
                    say(red(f"  could not open it: {e}"))
            else:
                folder = parts[1].strip() if len(parts) > 1 else None
                try:
                    for _src, dest in gnoc_export.export(chosen, folder):
                        say(green("● ") + f"exported {dest}")
                except OSError as e:
                    say(red(f"  export failed: {e}"))
    elif cmd == "recall":
        # search past chats by hand (2026-11-23): the same index the recall tool uses
        if not rest.strip():
            say(red("  usage: /recall <words>   (searches your saved chats; the original messages)"))
        else:
            import gnoc_recall
            SPIN.start("Searching past chats")
            try:
                rows = gnoc_recall.search(rest.strip(), 8, exclude_sid=str(agent.s.get("sid") or ""))
            finally:
                SPIN.stop()
            say(gnoc_recall.render(rows, rest.strip()))
    elif cmd == "agents" and sys.stdin.isatty() and sys.stdout.isatty() and not rest.strip():
        # only a bare /agents opens the picker; "/agents list 5" and "/agents 5" print the table (QAQC 2026-11-19)
        import gnoc_agents_ui
        try:
            gnoc_agents_ui.main()  # arrow keys: pick a sub-agent, read its log or its whole chat live
        finally:
            with contextlib.suppress(Exception):
                BAR.rearm()        # curses' endwin resets the scroll region the input bar lives under
                BAR.paint(TYPED.buf)
    elif cmd == "agents":
        nums = [w for w in rest.split() if w.isdigit()]
        rows = MON.load_all()[: int(nums[0]) if nums else 20]
        if not rows:
            say(dim("  no sub-agents yet (workers, fan_out bots, reflection, gates and cloud jobs appear here)"))
        for r in rows:
            q = MON.quiet_s(r)
            st = r.get("status", "?")
            col = green if st == "done" else red if st in ("failed", "orphaned") else \
                (red if q > MON.QUIET_S else yellow) if st == "running" else dim
            say(f"  {col('● ' + st):<22} {yellow(r['id']):<26} {blue(r.get('kind', '')):<24} "
                + dim(f"{r.get('model', '')[:40]}@{r.get('host', '')}  steps {r.get('steps', 0)}  "
                      f"↓{MON.fmt_n(r.get('tokens', 0))}  last {MON.fmt_s(q)} ago")
                + (red("  ⚠ quiet") if st == "running" and q > MON.QUIET_S else ""))
            say(dim(f"      {r.get('task', '')[:110]}"))
        say(dim("  /agent <id> shows its log · /agent <id> follow tails it live (Ctrl-C to stop) · works from a "
                "second terminal too: gnoc chat /agents"))
    elif cmd == "agent":
        w = rest.split()
        if not w:
            say(red("  /agent <id> [n|follow]   (/agents lists the ids)"))
        else:
            r, lines = MON.tail(w[0], int(w[1]) if len(w) > 1 and w[1].isdigit() else 40)
            if not r:
                say(red(f"  no sub-agent {w[0]} (/agents)"))
            else:
                say(green("● ") + yellow(r["id"]) + " " + blue(r.get("kind", "")) + dim(
                    f"  {r.get('model', '')}@{r.get('host', '')} · {r.get('status')} · started {r.get('started')}"
                    f" · log {os.path.relpath(r['log'], WS) if r['log'].startswith(WS) else r['log']}"))
                for ln in lines:
                    say("  " + gnoc_secrets.redact(ln)[:300])
                if len(w) > 1 and w[1] == "follow":
                    seen = len(open(r["log"], errors="replace").read().splitlines()) if os.path.exists(r["log"]) else 0
                    say(dim("  following, Ctrl-C to stop"))
                    try:
                        while True:
                            time.sleep(1)
                            try:
                                cur = open(r["log"], errors="replace").read().splitlines()
                            except OSError:
                                cur = []
                            for ln in cur[seen:]:
                                say("  " + gnoc_secrets.redact(ln)[:300])
                            seen = len(cur)
                            r2 = MON.find(r["id"])
                            if r2 and r2.get("status") != "running":
                                say(dim(f"  {r['id']} finished: {r2.get('status')}"))
                                break
                    except KeyboardInterrupt:
                        say(dim("  stopped following"))
    elif cmd == "bench":
        import gnoc_bench
        w = rest.split()
        quick = "quick" in w or "--quick" in w
        w = [x for x in w if x not in ("quick", "--quick")]
        sub = w[0].lower() if w else "both"
        if sub in ("recommend", "results", "show"):
            lead, worker, table = gnoc_bench.recommend()
            say(table)
            if lead:
                say(gnoc_bench.recommendation_line(lead, worker) + dim("   /bench apply"))
        elif sub == "apply":
            lead, worker, table = gnoc_bench.recommend()
            if not lead:
                say(red("  no benchmark results yet: /bench"))
            else:
                errs = [e for e in (set_role(role, spec.replace("@local", ""))
                                    for role, spec in (("lead", lead), ("worker", worker))) if e]
                for e in errs:
                    say(red("  " + e))
                if not errs:
                    say(green(f"  lead -> {lead}   worker -> {worker}"))
        else:
            picks = {"lead": [resolve("lead")], "worker": [resolve("worker")],
                     "both": [resolve("lead"), resolve("worker")]}.get(sub) or [llm_endpoints.split(w[0])]
            for model, host in dict.fromkeys(picks):
                say(T.bred("  ▶ ") + T.byellow(f"bench {model}@{host}") + dim("  (synthetic cases, graded by code; "
                                                                               "Ctrl-C stops)"))
                try:
                    r = gnoc_bench.run(model, host, quick, log=lambda m: say(dim(m)))
                except KeyboardInterrupt:
                    say(yellow("  bench interrupted"))
                    break
                say(gnoc_bench.result_line(r))
            lead, worker, table = gnoc_bench.recommend()
            if lead:
                say("")
                say(table)
                say(gnoc_bench.recommendation_line(lead, worker) + dim("   /bench apply"))
    elif cmd == "econ":  # ECON
        import gnoc_economy
        say(gnoc_economy.audit_text() if rest.strip() == "audit" else gnoc_economy.status_text())
    elif cmd == "pay":
        w = rest.split()
        prog = (resolve_program(w[0]) if w else None) or agent.ctx.program
        host = w[1] if len(w) > 1 else (w[0] if w and not resolve_program(w[0]) and "." in w[0] else None)
        if not prog:
            say(red("  /pay [program] [host]  (no active program)"))
        else:
            say(T.render_markdown(t_pay_check(agent.ctx, prog, host, refresh=True)))
    elif cmd == "report":
        prog = (resolve_program(rest.strip()) if rest.strip() else None) or agent.ctx.program
        if not prog:
            say(red("  /report <program>  (no active program)"))
        else:
            SPIN.start("Building the draft")
            try:
                rel, msg = gnoc_report.build(prog, llm=_lead_llm)
            finally:
                SPIN.stop()
            say((green("● ") if rel else red("● ")) + msg)
            if rel:
                say(T.render_markdown(open(os.path.join(WS, rel, "report.md")).read()[:6000]))
    elif cmd in ("ledger", "chains", "brief"):
        prog = (resolve_program(rest.strip()) if rest.strip() else None) or agent.ctx.program
        if not prog:
            say(red(f"  /{cmd} <program>  (no active program)"))
        elif cmd == "ledger":
            say(T.render_markdown("### hypotheses\n") + gnoc_hunt.hypothesis(prog, "list"))
            say(T.render_markdown("### capability edges\n") + gnoc_hunt.edge(prog, "list"))
        elif cmd == "chains":
            say(gnoc_hunt.chains_text(prog, 8))
        else:
            say(gnoc_hunt.brief(prog))
    elif cmd == "copy":
        say(copy_cmd(agent, rest.strip().lower()))
    elif cmd in ("top", "bottom"):
        out = page_answer(agent, rest, end=(cmd == "bottom"))
        if out is not None:
            say(out)
    elif cmd == "reasoning":
        lvl = REASONING_NAMES.get(rest.strip().lower())
        if lvl:
            EFFORT[0] = agent.s["effort"] = lvl
            agent.save()
        elif rest.strip():
            say(red("  reasoning: low | med | high | ultra"))
        e = effort()
        say(green("● ") + white("reasoning ") + yellow({"medium": "med"}.get(EFFORT[0], EFFORT[0])) + dim(
            f"  ·  model thinking {e['think']}  ·  {steps_label(e)} steps a turn  ·  up to {e['fanout']} parallel bot(s)"
            + ("  ·  both GPUs on every message" if e["deep"] else "")
            + ("  ·  the lead fans big work out to bots on both GPUs" if EFFORT[0] == "ultra" else "")))
    elif cmd == "effort":
        w = rest.split()
        if w and w[0].lower() in ("steps", "step"):
            # /effort steps <n> | 0 | off - the lead's per-turn tool budget, without editing EFFORTS
            arg = (w[1] if len(w) > 1 else "").lower()
            if arg in ("off", "preset", "auto", "default"):
                STEPS_OVERRIDE[0] = agent.s["steps_override"] = None
                agent.save()
            elif arg.isdigit():
                STEPS_OVERRIDE[0] = agent.s["steps_override"] = int(arg)
                agent.save()
            elif arg:
                say(red("  /effort steps <n>   (0 = unlimited, off = back to the preset)"))
            else:
                say(dim("  /effort steps <n>   (0 = unlimited, off = back to the preset)"))
        else:
            lvl = rest.strip().lower()
            if lvl in EFFORTS:
                EFFORT[0] = agent.s["effort"] = lvl
                agent.save()
            elif lvl:
                say(red(f"  effort: {' | '.join(EFFORTS)}   (or /effort steps <n>)"))
        e = effort()
        say(green("● ") + white("effort ") + yellow(EFFORT[0]) + dim(
            f"  ·  reasoning {e['think']} (qwen thinking {'on' if e['qwen_think'] else 'off'})  ·  "
            f"{steps_label(e)} lead / {e['worker_steps']} worker steps per turn"
            + (f" (preset {EFFORTS[EFFORT[0]]['steps']}, overridden)" if STEPS_OVERRIDE[0] is not None else "")
            + (f"  ·  per-tool loop guard {_turn_call_cap('http_request') or 'off'}"
               if STEPS_OVERRIDE[0] is not None else "")
            + ("  ·  both GPUs on every message" if e["deep"] else "")))
    elif cmd in ("cd", "dir"):  # /dir is the same command: GreyNOC types either
        if not rest:
            say(f"  working directory: {_rel_home(root())}")
        else:
            w = rest.split(maxsplit=1)
            d = _dir_from(w[0])
            say((green("● ") + change_dir(agent.ctx, d, w[1] if len(w) > 1 else "")) if d
                else red(f"  no such directory: {w[0]}"))
            agent.save()
    elif cmd == "repo":
        if rest:
            set_repo(agent, rest.strip())
        else:
            say(f"  repo: {_rel_home(root())}   (/repo <path|url|owner/repo> | website | off)")
    elif cmd in ("model", "lead", "worker"):
        # "model" is the lead: the model you are talking to. It used to fall through to the legacy
        # simple-chat handler, which writes a different file than the agent routes from, so it reported
        # success and changed nothing.
        role = "lead" if cmd == "model" else cmd
        if not rest:
            picked = pick_model(role_spec("lead"), role_spec("worker")) if cmd == "model" else None
            if picked:
                _role_set(*picked)
            say(routing_text() + _cloud_text())
        else:
            spec = rest.strip()
            name, host = llm_endpoints.split(spec)
            if not llm_endpoints.is_cloud(host):
                # "/model deepseek" names a registered cloud PROVIDER: its default model becomes the role,
                # exactly like /deepseek on. A bare provider name is not a local model name (2026-10-29).
                try:
                    import gnoc_cloud
                    prov = gnoc_cloud.canonical(name)   # "/model claude" = Anthropic's default model
                    cfg = gnoc_cloud.providers().get(prov)
                    if cfg:
                        spec = f"{cfg[2]}@{prov}"
                except Exception:  # noqa: BLE001 - no gnoc_cloud module: the spec stays a local name
                    pass
            _role_set(role, spec)
    elif cmd in ("cloud", "claude", "anthropic", "openai", "gpt", "chatgpt", "gemini", "google", "xai", "grok",
                 "meta", "llama", "mistral", "deepseek", "moonshot", "kimi", "qwen", "alibaba"):
        # /claude api <key> | /claude on [model] | /claude off | /claude models | /claude   (any provider or alias)
        # /cloud add <name> <base-url> <model> [api-key|-] | /cloud rm <name> | /cloud list
        # /cloud <name> api <key> | on [model] | off | models | check | <name> (status)
        import gnoc_cloud
        provider = gnoc_cloud.canonical(cmd) if cmd != "cloud" else "anthropic"
        args = rest.split()
        if cmd == "cloud" and args and gnoc_cloud.canonical(args[0]) in gnoc_cloud.providers():
            provider, args = gnoc_cloud.canonical(args[0]), args[1:]
        sub = (args[0].lower() if args else "")
        if cmd == "cloud" and sub == "add":
            # /cloud add <name> <base-url> <default-model> [api-key|-] [wire=openai|anthropic|gemini]
            # wire= picks the API shape (Phase 1); without it the endpoint is OpenAI-compatible, as it always was
            wire = next((a.split("=", 1)[1] for a in args if a.lower().startswith("wire=")), None)
            args = [a for a in args if not a.lower().startswith("wire=")]
            if len(args) < 4:
                say(red("  usage: /cloud add <name> <base-url> <default-model> [api-key|-] [wire=anthropic|gemini]"))
                say(dim("  api-key stored inline (or '-' / omitted = keyless, for a self-hosted server); "
                        "wire= for an Anthropic- or Gemini-shaped API (default: OpenAI-compatible)"))
                return
            name, base, model = args[1].lower(), args[2], args[3]
            key = " ".join(args[4:]) if len(args) > 4 else None
            ok, msg = gnoc_cloud.add_provider(name, base, model, api_key=key, wire=wire)
            say(green("  " + msg) if ok else red("  " + msg))
            if ok:
                say(dim("  checking it against the live API ..."))
                live, detail = gnoc_cloud.check(name)
                say(green("  " + detail) if live else red("  " + detail))
                if live:
                    say(dim(f"  make it the lead with  /cloud {name} on"))
        elif cmd == "cloud" and sub in ("rm", "remove"):
            if len(args) < 2:
                say(red("  usage: /cloud rm <name>   (/cloud list shows the custom providers)"))
            else:
                ok, msg = gnoc_cloud.remove_provider(args[1].lower())
                say(green("  " + msg) if ok else red("  " + msg))
        elif cmd == "cloud" and sub == "list":
            names = list(gnoc_cloud.providers())
            if not names:
                say(dim("  no providers"))
            for n in names:
                base, env, default, models = gnoc_cloud.providers()[n]
                k = gnoc_cloud.key_for(n)
                state = "keyless" if gnoc_cloud.keyless(n) else (f"key {len(k)} chars" if k else "no key")
                mark = "  <-- lead" if llm_endpoints.split(role_spec("lead"))[1] == n else ""
                say(f"  {yellow(n):<16} {default}  {dim(state)}  {dim(base)}{blue(mark)}")
                if len(models) > 1:
                    say(dim("      models: " + ", ".join(models)))
            say(dim("  /cloud <name> on [model] makes one the lead · /cloud add registers any endpoint"))
        elif sub in ("api", "key", "set"):
            ok, msg = gnoc_cloud.save_key(provider, " ".join(args[1:]))
            say(green("  " + msg) if ok else red("  " + msg))
            if ok:
                say(dim("  checking the key against the live API ..."))
                live, detail = gnoc_cloud.check(provider)
                say(green("  " + detail) if live else red("  " + detail))
                if live:
                    say(dim(f"  make it the lead with  /{provider} on"))
        elif sub == "off":
            cur = role_spec("lead")
            if llm_endpoints.is_cloud(llm_endpoints.split(cur)[1]):
                err = set_role("lead", llm_endpoints.DEFAULT)
                say(red("  " + err) if err else green(f"  lead -> {llm_endpoints.DEFAULT}  (back on this machine)"))
            else:
                say(dim(f"  the lead is already local ({cur})"))
        elif sub in ("on", "use"):
            cfg = gnoc_cloud.providers().get(provider)
            if not cfg:
                say(red(f"  unknown provider {provider}") + dim("  (/cloud list; /cloud add registers one)"))
                return
            base, env, default, models = cfg
            model = args[1] if len(args) > 1 else default
            if models and model not in models:
                # advisory only: the provider list is a hint, not a gate (model-agnostic means any name)
                say(yellow(f"  {model} is not a name {provider} is known to serve "
                           f"({', '.join(models)}); trying it anyway"))
            if not gnoc_cloud.key_for(provider) and not gnoc_cloud.keyless(provider):
                say(red(f"  no {provider} API key") + dim(f"   set one with  /{provider} api <key>"))
                return
            err = set_role("lead", f"{model}@{provider}")
            if err:
                say(red("  " + err))
                return
            say(green(f"  lead -> {model}@{provider}"))
            say(yellow("  OFF-MACHINE MODEL: this hunt's conversation - captured bytes, hostnames, account "
                       "names, draft findings - now leaves this machine on every turn."))
            say(dim(f"  secrets are scrubbed from each message first; /{provider} off puts the lead back local"))
        elif sub in ("models",):
            cfg = gnoc_cloud.providers().get(provider)
            say(dim("  " + ", ".join(cfg[3])) if cfg else red(f"  unknown provider {provider}"))
        elif sub in ("clear", "forget"):
            ok, msg = gnoc_cloud.clear_key(provider)
            say(green("  " + msg) if ok else dim("  " + msg))
        elif sub in ("check", "test"):
            live, detail = gnoc_cloud.check(provider)
            say(green("  " + detail) if live else red("  " + detail))
        else:
            say(dim(gnoc_cloud.status(provider)))
    elif cmd == "btw":
        # at the prompt there is no running turn to hand it to: queue it for the next one, so it is never lost
        note = rest.strip()
        if not note:
            say(dim("  /btw <note>   hands a side note to the turn that is already running (it reads it at its "
                    "next step). Typed here, it goes to the next turn instead."))
        else:
            with _BTW_LOCK:
                _BTW.append(note)
            say(T.bblue("  btw: ") + white(note[:160]) + dim("  (nothing is running; the next turn starts with it)"))
    elif cmd == "route":
        # Same bug as /model: the legacy handler re-pointed the simple chat, not the agent.
        want = rest.strip().lower()
        hosts = {"laptop": "local", "local": "local", "desktop": "desktop"}
        if want not in hosts:
            say(routing_text() + dim("\n  /route laptop | /route desktop   (moves the lead; /worker for the other)"))
        else:
            name, _ = llm_endpoints.split(role_spec("lead"))
            spec = name if hosts[want] == "local" else f"{name}@desktop"
            if hosts[want] != "local" and not llm_endpoints.up(hosts[want]):
                say(red(f"  the {want} Ollama is not reachable: lead unchanged") + dim("  (gnoc svc)"))
                return   # it said "not reachable" and then switched anyway (QAQC 2026-11-19)
            have = {n for h, n, _ in model_rows() if h == hosts[want]}
            if have and name not in have and name + ":latest" not in have:
                say(red(f"  {name} is not installed on the {want}: lead unchanged")
                    + dim(f"  (/model picks one that is; /lead <name>{'' if hosts[want] == 'local' else '@desktop'})"))
                return
            err = set_role("lead", spec)
            say(red("  " + err) if err else green(f"  lead -> {spec}"))
    elif cmd in ("approvals", "approve", "deny"):
        w = rest.split(maxsplit=1)
        if cmd == "approvals":
            state = (w[0].strip().lower() if w and w[0].strip() else "pending")
            try:
                say(gnoc_graph.approvals_text(agent.ctx.program or None, state=state, db_path=_graph_db()))
            except Exception as e:  # noqa: BLE001 - a bad state must not kill the REPL
                say(red(f"  approvals failed: {type(e).__name__}: {str(e)[:200]}"))
        elif not w or not w[0].strip().isdigit():
            say(red(f"  usage: /{cmd} <approval-id> [reason]"))
        else:
            reason = w[1].strip() if len(w) > 1 else ""
            try:
                row = gnoc_graph.approval_decide(int(w[0]), approve=(cmd == "approve"), program=None,
                                                 decided_by="operator", reason=reason, db_path=_graph_db())
                if row["state"] == "approved":
                    say(green(f"  approval #{row['id']} approved (single use, until {row['expires_at']})")
                        + dim("  the model can retry that exact call"))
                elif row["state"] == "denied":
                    say(red(f"  approval #{row['id']} denied") + (dim(f"  {row['reason']}") if row.get("reason") else ""))
                elif row["state"] == "expired":
                    say(red(f"  approval #{row['id']} expired before a decision"))
                else:
                    say(yellow(f"  approval #{row['id']} is already {row['state']}"))
            except Exception as e:  # noqa: BLE001
                say(red(f"  approval failed: {type(e).__name__}: {str(e)[:200]}"))
    elif cmd == "graph":
        # The dual graph at a glance. Everything here is read-only state the model also has as tools.
        if not agent.ctx.program:
            say(red("  no active program: /program <handle> first"))
        else:
            _graph_import_scope(agent.ctx.program)
            w = rest.split(maxsplit=1)
            action = (w[0].lower() if w else "overview")
            arg = (w[1].strip() if len(w) > 1 else "")
            prog = agent.ctx.program
            dbp = _graph_db()
            try:
                if action in ("overview", "status", "graph"):
                    say(gnoc_graph.overview_text(prog, dbp))
                elif action in ("assets", "asset"):
                    if arg.isdigit():
                        say(gnoc_graph.asset_text(int(arg), dbp))
                    else:
                        kind = wanted = ""
                        words = []
                        for w in arg.split():
                            if w.startswith("kind="):
                                kind = w.split("=", 1)[1]
                            elif w.startswith("coverage="):
                                wanted = w.split("=", 1)[1].lower()
                            else:
                                words.append(w)
                        if kind or wanted:
                            say(gnoc_graph.assets_filter_text(prog, kind=kind, coverage_state=wanted,
                                                              query=" ".join(words), db_path=dbp))
                        else:
                            say(gnoc_graph.assets_text(prog, query=arg, db_path=dbp))
                elif action in ("stats", "dashboard"):
                    say(gnoc_graph.stats_text(prog, dbp))
                elif action in ("coverage", "untested"):
                    say(gnoc_graph.coverage_text(prog, dbp))
                elif action in ("snapshot", "snap"):
                    snap = gnoc_graph.take_snapshot(prog, label=arg, db_path=dbp)
                    say(green(f"  snapshot #{snap['id']}  ") + f"{snap['assets']} assets  "
                            f"sha {snap['sha256'][:16]}")
                elif action == "snapshots":
                    say(gnoc_graph.snapshots_text(prog, dbp))
                elif action in ("diff", "surface-diff"):
                    say(gnoc_graph.diff_text(prog, since=(arg or None), db_path=dbp))
                elif action == "path":
                    parts = arg.split()
                    if len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
                        say(red("  usage: /graph path <from_node> <to_node>"))
                    else:
                        say(gnoc_graph.path_text(prog, int(parts[0]), int(parts[1]), db_path=dbp))
                elif action in ("lineage", "ancestors"):
                    if not arg.isdigit():
                        say(red("  usage: /graph lineage <node_id>"))
                    else:
                        say(gnoc_graph.lineage_text(prog, int(arg), db_path=dbp))
                elif action in ("nodes", "node"):
                    say(gnoc_graph.node_text(prog, int(arg), dbp) if arg.isdigit()
                        else gnoc_graph.nodes_text(prog, query=arg, db_path=dbp))
                elif action in ("todos", "todo"):
                    say(gnoc_graph.todos_text(prog, dbp))
                elif action in ("traces", "trace"):
                    say(gnoc_graph.traces_text(prog, query=arg, db_path=dbp))
                elif action in ("evidence", "ev"):
                    say(gnoc_graph.evidence_text(prog, query=arg, db_path=dbp))
                elif action in ("traffic", "http"):
                    parts = arg.split()
                    sub = parts[0].lower() if parts else ""
                    if sub in ("hosts", "host"):
                        say(gnoc_graph.traffic_hosts_text(prog, dbp))
                    elif sub in ("show", "detail", "get"):
                        if len(parts) < 2 or not parts[1].isdigit():
                            say(red("  usage: /graph traffic show <id>"))
                        else:
                            say(gnoc_graph.traffic_detail_text(prog, int(parts[1]), dbp))
                    elif sub in ("purge", "clear"):
                        host = parts[1] if len(parts) > 1 else ""
                        n = gnoc_graph.traffic_purge(prog, host=host, db_path=dbp)
                        say(f"  purged {n} traffic row(s)" + (f" for host {host}" if host else ""))
                    else:
                        say(gnoc_graph.traffic_text(prog, query=arg, db_path=dbp))
                elif action in ("findings", "finding"):
                    say(gnoc_graph.findings_text(prog, state=arg, db_path=dbp))
                elif action in ("draft", "artifact"):
                    if not arg.isdigit():
                        say(red("  usage: /graph draft <finding_id>")
                            + dim("  (/graph findings lists the ids; the finding must be confirmed)"))
                    else:
                        got = gnoc_graph.finding_artifact(prog, int(arg), db_path=dbp)
                        say(green("  draft: ") + got["report_path"])
                        for w in got.get("warnings") or []:
                            say(yellow("  WARNING: ") + w)
                        errs = got.get("house_errors") or []
                        if (got.get("house") or {}).get("checked"):
                            say(dim(f"  house validator: {len(errs)} error(s)" if errs
                                    else "  house validator: no errors"))
                        for e in errs[:4]:
                            say(yellow("    - ") + e)
                        if got.get("version", 1) > 1:
                            say(dim(f"  version {got['version']}; the earlier draft was left untouched"))
                        say(dim("  NOT FILED - review it in chat, then file it yourself"))
                elif action in ("retest", "retests", "retest-done"):
                    parts = arg.split()
                    if action == "retests":
                        say(gnoc_graph.retests_text(prog, active_only=(parts[:1] != ["all"]), db_path=dbp))
                    elif action == "retest-done":
                        if len(parts) < 2 or not parts[0].isdigit():
                            say(red("  usage: /graph retest-done <retest_id> reproduces|fixed|cancelled [note]"))
                        else:
                            row = gnoc_graph.retest_update(prog, int(parts[0]), parts[1],
                                                           note=" ".join(parts[2:]), db_path=dbp)
                            say(f"  retest #{row['id']} -> {row['state']}")
                    elif parts and parts[0].isdigit():
                        days = parts[1] if len(parts) > 1 and parts[1].isdigit() else 14
                        row = gnoc_graph.retest_add(prog, int(parts[0]), due_in_days=days, db_path=dbp)
                        say(green(f"  retest #{row['id']} ") + f"due {row['due_at'][:16]}")
                    else:
                        say(red("  usage: /graph retest <finding_id> [days]  |  /graph retests [all]"))
                elif action in ("rules", "rule"):
                    say(gnoc_graph.rules_text(prog, dbp))
                elif action in ("export", "web", "html", "cockpit"):
                    # only a real desktop session gets a browser window; a headless run just writes the file
                    display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
                    got = gnoc_graph.export_html(prog, out_path=(arg or None), db_path=dbp,
                                                 open_in_browser=display)
                    say(green("  cockpit: ") + got["path"])
                    say(dim(f"  {got['nodes']} nodes, {got['edges']} edges, {got['assets']} assets, "
                            f"{got['findings']} findings, {got['pending_approvals']} pending approvals; "
                            + ("self-contained, opened in the browser" if display
                               else "self-contained; open it with a browser")))
                    say(dim("  refresh after new work with /graph export again"))
                else:
                    say(red(f"  unknown graph action: {action}")
                        + dim("  (overview|assets|coverage|nodes|todos|traces|evidence|findings|draft|export)"))
            except Exception as e:  # noqa: BLE001 - graph state must never kill the REPL
                say(red(f"  graph failed: {type(e).__name__}: {str(e)[:200]}"))
    elif cmd == "collab":
        # A collaborator engagement: the partner's initial handoff IS the scope. No bounty program is needed.
        w = rest.split(maxsplit=1)
        action = (w[0].lower() if w else "status")
        arg = (w[1].strip() if len(w) > 1 else "")
        if action in ("off", "clear", "none"):
            cur = agent.s.get("collab") or {}
            if cur.get("project") and cur.get("sha256"):
                # remembered: this folder is not an engagement, so the next launch does not ask again
                gnoc_collab.decline(cur["project"], cur["sha256"], WS)
            say("  " + clear_program(agent.ctx))
            agent.save()
        elif action == "refresh":
            prog = arg or agent.ctx.program or (agent.s.get("collab") or {}).get("program")
            if not prog:
                say(red("  no collaborator engagement is active: /collab import <dir>"))
            else:
                got = gnoc_collab.refresh(prog, WS)
                if not got.get("ok"):
                    say(red("  refresh failed: ") + dim(str(got.get("reason"))[:240]))
                else:
                    ctx = agent.ctx
                    ctx.s["program"] = prog
                    ctx.s["collab"] = {k: got.get(k) for k in
                                       ("program", "project", "handoff", "handoff_rel", "sha256", "hosts",
                                        "out", "paperwork", "scope_ok", "imported")}
                    note_program_source(agent, f"collaborator handoff {os.path.basename(str(got.get('handoff')))}")
                    say(green("● ") + gnoc_collab.summary(prog, WS))
                    agent.save()
        elif action in ("import", "add") or action != "status":
            # /collab <dir|file> means import it; /collab status [x] only shows
            dst = (arg or root()) if action in ("import", "add") else rest.strip()
            target = _dir_from(dst) or os.path.realpath(os.path.expanduser(dst))
            if os.path.isfile(target):   # typing the command is the consent
                got = attach_collab(agent, handoff_path=target, explicit=True)   # the partner's document itself
            elif os.path.isdir(target):
                got = attach_collab(agent, target, explicit=True)
            else:
                got = None
            if got:
                agent.save()
                say(green("● ") + f"collaborator engagement -> {got['program']}")
                say(gnoc_collab.summary(got["program"], WS))
            elif not os.path.exists(target):
                say(red(f"  no such file or directory: {dst}"))
            else:
                say(yellow("  no partner handoff found in ") + _rel_home(target)
                    + dim("  (looked for a file named HANDOFF* or kickoff*; any other document: "
                          "/collab import <that file>)"))
        else:
            active = (agent.s.get("collab") or {}).get("program") or agent.ctx.program
            if gnoc_collab.is_profile(active or "", WS):
                say(gnoc_collab.summary(active, WS))
            else:
                got = attach_collab(agent, root())
                if got:
                    agent.save()
                    say(gnoc_collab.summary(got["program"], WS))
                else:
                    say(dim("  no collaborator engagement here. /collab import <dir> reads that project's "
                            "initial handoff as the scope; a handoff is HANDOFF*.md / kickoff / onboarding, or "
                            "SCOPE/AUTHORIZATION/ROE/SOW paperwork (Markdown, text, PDF, DOCX)."))
    elif cmd == "program":
        if rest.strip().lower() in ("clear", "none", "off", "-"):
            say("  " + clear_program(agent.ctx))
        elif rest.strip():
            before = agent.ctx.program
            say(t_set_program(agent.ctx, rest.strip()))
            # keep the engagement-specific origin when /program names a collaborator profile
            if agent.ctx.program and agent.ctx.program != before \
                    and (agent.s.get("collab") or {}).get("program") != agent.ctx.program:
                note_program_source(agent, "set with /program")
        else:
            prog = agent.ctx.program
            say(f"  program: {prog or 'none'}" + (dim(f"  ({program_origin(agent)})") if prog
                                                  else dim("  (/program <handle> sets one)")))
        agent.save()
    elif cmd == "auto":
        rest = rest.strip().lower()
        if rest in ("on", "off"):
            agent.s["auto"] = rest == "on"
            agent.save()
        elif rest:
            say(red("  usage: /auto on|off"))
        say(f"  auto-approve: {'ON' if agent.ctx.auto else 'off'}"
            + ("   (on for this whole launch: gnoc chat -s-p; scans past this machine, commits, screen control "
               "and target-driven actions still ask)" if SKIP_PERMS[0] else ""))
        if rest == "on":
            # recommend, never switch: where commands run is the user's choice (phase 7)
            tip = __import__("gnoc_sandbox").auto_tip(agent.s)
            if tip:
                say(dim("  " + tip))
    elif cmd == "sandbox":
        # Changing the executor is typed-only, like /file: the REPL and the one-shot launcher set agent._typed_line
        # to the exact string read from the keyboard; a status read needs no marker.
        import gnoc_sandbox
        msg, changed = gnoc_sandbox.command(agent.s, rest, getattr(agent, "_typed_line", None) is line, root())
        if msg.startswith("usage"):
            say(dim(msg))
        elif msg.startswith("sandbox:"):
            say("  " + msg.replace("\n", "\n  "))
        else:
            say(red("  " + msg.replace("\n", "\n  ")))
        if changed:
            agent.save()
    elif cmd == "jobs":
        say(t_jobs(agent.ctx))
    elif cmd == "offline":
        if rest.strip() in ("on", "off"):
            OFFLINE[0] = agent.s["offline"] = rest.strip() == "on"
            __import__("gnoc_privacy").SESSION_LOCAL[0] = OFFLINE[0]   # /offline means local-only for this run
            agent.save()
        elif rest.strip():
            say(red("  usage: /offline on|off"))
        say(f"  offline mode: {'ON' if OFFLINE[0] else 'off'}   while it is on nothing leaves this computer: no web "
            "search or fetch, no picture lookups, no cloud model, no update check (/privacy lists every switch; "
            "/privacy local-only on keeps it on across chats)")
    elif cmd == "privacy":
        say(__import__("gnoc_privacy").command(rest))
    elif cmd == "skipperms":  # skip-permissions toggle for THIS session (launch flag: -s-p / --skip-permissions)
        if rest.strip().lower() in ("on", "off"):
            SKIP_PERMS[0] = rest.strip().lower() == "on"  # session-only by design: never persisted to disk
        elif rest.strip():
            say(red("  usage: /skipperms on|off"))
        say((T.bred("  skip-permissions: ON") if SKIP_PERMS[0] else dim("  skip-permissions: off"))
            + dim("   writes, shell and non-GET HTTP run without asking; a commit, ship, scan and the fleet "
                  "controls still ask every time"))
    elif cmd == "plain":
        if rest.strip().lower() in ("on", "off"):
            PLAIN[0] = agent.s["plain"] = rest.strip().lower() == "on"
            agent.save()
        elif rest.strip():
            say(red("  usage: /plain on|off"))
        say((T.blue("  plain chat: ON") if PLAIN[0] else dim("  plain chat: off"))
            + dim("   just talk, no hunt program or scope; /plain off returns to the hunt agent"))
    elif cmd == "gpu1":  # ask the worker model on the second GPU directly (like /btw, but it answers now)
        if not rest.strip():
            say(red("  usage: /gpu1 <request>   (send it straight to the worker model on the second GPU)"))
        else:
            wmodel, whost = resolve("worker")
            SPIN.start("GPU1 worker", who=f"{wmodel}@{whost}")
            try:
                label, out = _gpu1_worker(rest)
            finally:
                SPIN.stop()
            say(dim(f"  ● {label}"))
            say(out)
    elif (cmd == "hf" or (cmd == "clone" and gnoc_hf.is_hf(rest.strip()))) and offline() and \
            (cmd == "clone" or (rest.split() or [""])[0].lower() in ("clone", "search", "files")
             or gnoc_hf.is_hf((rest.split() or [""])[0])):
        say(red("  offline mode: cloning or searching Hugging Face needs the internet. /hf list and /hf use work "
                "on models already installed; /offline off to go online."))
    elif cmd == "hf" or (cmd == "clone" and gnoc_hf.is_hf(rest.strip())):
        gnoc_hf.cmd((["clone"] if cmd == "clone" else []) + shlex.split(rest), set_role=set_role)
    elif cmd in ("reset", "new", "clear"):
        agent.reset()
        say("  new conversation (the previous one is saved: /resume)")
    elif cmd == "undo":
        bits = rest.split()
        if any(b != "force" and not b.isdigit() for b in bits):
            # '/undo zz' used to revert one write anyway: an unreadable undo must do nothing
            say(red("  usage: /undo [n] [force]") + dim("  (nothing reverted)"))
            return
        nums = [int(b) for b in bits if b.isdigit()]   # `/undo force 3` is 3, not 1 (QAQC 2026-11-19)
        n = nums[0] if nums else 1
        if n < 1:   # `/undo 0` sliced rows[-0:], the WHOLE list, and reverted every write of the conversation
            say(red("  /undo 0 reverts nothing; give a count of 1 or more") + dim("  (nothing reverted)"))
            return
        for ln in undo(agent.ctx, n, force="force" in bits):
            say(("  " + green("● ") if ln.startswith(("restored", "removed")) else "  " + yellow("! ")) + ln)
    elif cmd in ("changes", "diff"):
        if rest.strip() not in ("", "short"):
            say(red(f"  usage: /{cmd} [short]"))
            return
        rows = changes(agent.ctx)
        if not rows:
            say(dim("  the agent has not changed any file in this conversation (shell edits are not tracked)"))
            return
        if rest.strip() != "short":
            out = diff_panel([(rel, drows, adds, dels) for rel, _st, (drows, adds, dels) in rows])
            if out:
                say(dim("  " + out) if not out.startswith("  ") else out)
            return
        for rel, state, (drows, adds, dels) in rows:   # /changes short: names and counts only
            say(f"  {T.byellow(rel)} {dim(state)} " + green(f"+{adds}") + " " + red(f"-{dels}"))
        say(dim("  /undo [n] reverts the agent's last n writes; /changes short for names only"))
    elif cmd == "review":
        code, diff = _git(root(), "diff", "HEAD", "--", *(rest.split() if rest.strip() else []))
        if (code or not diff.strip()) and rest.strip():
            # "/review inventory/store.py" on a file with no changes (or a new, untracked one) means "review this
            # file": it used to answer "nothing to review" (2026-11-20 SWE drive)
            (t_code_review,) = bind("t_code_review")
            say(dim(f"  no uncommitted changes in {rest.strip()}: reviewing the file(s) as they are ..."))
            say(t_code_review(agent.ctx, "files", paths=rest.split()))
        elif code or not diff.strip():
            say(dim("  nothing to review (no uncommitted changes" + (f" in {rest}" if rest.strip() else "") + ")"))
        else:
            say(dim(f"  the worker GPU is reviewing {diff.count(chr(10))} diff lines ..."))
            ans = t_second_opinion(agent.ctx, "Review this diff like a senior engineer: real bugs first (wrong logic, "
                                   "edge cases, error handling, security), then risky changes, then style only if it "
                                   "matters. Quote the line for each point. Say 'no issues' if there are none.",
                                   diff[:24000])
            say(ans)
    elif cmd == "outbox":
        rows = gnoc_comms.listing(None if rest.strip() == "all" else "draft")
        arg = rest.strip().upper()
        if re.fullmatch(r"O\d+", arg):
            d = gnoc_comms.load(arg)
            say(gnoc_comms.show(d) if d else red(f"  no draft {arg}"))
        elif not rows:
            say(dim("  outbox empty (the bot drafts with draft_outgoing; /outbox all shows sent and discarded too)"))
        else:
            for d in rows:
                first = " ".join(d["text"].split())[:70]
                say(f"  {yellow(d['id'])} {dim(d['status'])} {T.blue(d['channel'])}"
                    + (dim(f" to {d['to']}") if d.get("to") else "") + f"  {first}")
            say(dim("  /outbox <id> shows the exact text  ·  /send <id>  ·  /edit <id>  ·  /discard <id>"))
    elif cmd == "send":
        oid = rest.strip().upper()
        d = gnoc_comms.load(oid) if oid else None
        if not d:
            say(red("  usage: /send <id>   (/outbox lists drafts)"))
        elif d["status"] != "draft":
            say(red(f"  {oid} is {d['status']}, not a draft"))
        else:
            say(gnoc_comms.show(d))
            shown = gnoc_comms.fingerprint(d)
            try:
                ans = input(yellow(f"  send this exact {d['channel']} message now? type yes > ")).strip().lower()
            except EOFError:
                ans = ""
            if ans != "yes":
                say(dim("  not sent"))
            else:
                ok, msg = gnoc_comms.send(oid, approved=shown)
                say((green("● ") if ok else red("  ✗ ")) + msg)
    elif cmd == "file":
        # FILING IS HUMAN-ONLY (GreyNOC 2026-11-25, "yes build /file"; CLAUDE.md SUBMISSION IS APPROVAL-GATED).
        # The REPL and the one-shot launcher set agent._typed_line to the exact string they read from GreyNOC's
        # keyboard just before calling here, and clear it after. Anything else that reaches handle_slash (a model
        # reply, a tool result, a goal loop, a stand-in) does not carry that object, so it is refused here.
        import gnoc_file
        if getattr(agent, "_typed_line", None) is not line:
            say(red("  /file runs only from a line you typed at the prompt: refused, nothing sent"))
            return
        agent._typed_line = None   # one use
        gnoc_file.run(rest, out=say, typed=True)
    elif cmd == "schedule":
        # ONLY THE USER SETS A SCHEDULE (a job that makes jobs: the Hermes/OpenClaw lesson). add, rm and run take the
        # /file check - the exact string object the REPL or the one-shot launcher read - and a terminal on stdin: a
        # model's bash runs `gnoc chat "/schedule add ..."` with stdin on /dev/null, where that launcher would
        # otherwise hand its own argv over as "typed". list only reads, so it is open.
        import gnoc_schedule
        sub = (rest.split() or ["list"])[0].lower()
        if sub in ("add", "rm", "remove", "delete", "del", "run"):
            if getattr(agent, "_typed_line", None) is not line or not _from_terminal(sys):
                say(red(f"  /schedule {sub} runs only from a line you typed at the prompt: refused, nothing changed"))
                return
            agent._typed_line = None   # one use

        def _snap():
            return gnoc_schedule.snapshot(program=agent.ctx.program, hunt_target=os.environ.get("HUNT_TARGET"),
                                          folder=root(), effort=EFFORT[0], steps=STEPS_OVERRIDE[0],
                                          lead=role_spec("lead"), worker=role_spec("worker"))

        def _vouch(texts):   # gnoc wrote these unit files for the user: the defender's sweep must not call them drift
            return __import__("gnoc_defender").vouch_host_files(texts)

        say(gnoc_schedule.command(rest, snap_fn=_snap, vouch=_vouch))
    elif cmd == "edit":
        oid = rest.strip().upper()
        d = gnoc_comms.load(oid) if oid else None
        if not d or d["status"] != "draft":
            say(red("  usage: /edit <draft id>"))
        else:
            import tempfile
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
                f.write(d["text"])
            try:
                # EDITOR may carry arguments ("code --wait"); the draft file is removed whatever happens
                subprocess.call(shlex.split(os.environ.get("EDITOR") or "nano") + [f.name])
                with open(f.name) as fh:
                    d["text"] = fh.read().rstrip("\n")
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(f.name)
            problems = gnoc_comms.validate(d)
            if problems:
                say(red("  not saved: " + "; ".join(problems)))
            else:
                gnoc_comms.save(d)
                say(gnoc_comms.show(d))
    elif cmd == "discard":
        say(("  " + gnoc_comms.discard(rest.strip().upper())) if rest.strip()
            else red("  usage: /discard <id>   (/outbox lists drafts)"))
    elif cmd == "comms":
        say(gnoc_comms.setup_status() + dim(f"\n  secrets file: {gnoc_comms.SECRETS} (values never shown to models)"))
    elif cmd == "sessions":
        if rest.strip() and not rest.strip().isdigit():
            say(red("  usage: /sessions [n]"))
            return
        rows = list_sessions(int(rest) if rest.strip().isdigit() else 15)
        if not rows:
            say(dim("  no saved conversations"))
        for i, r in enumerate([r for r in rows if r["sid"] != agent.s.get("sid")], 1):
            say(f"  {yellow(str(i)):>4} {dim(r['updated'][:16].replace('T', ' '))}  {r['title']}"
                + dim(f"  ({r['n']} msgs{', ' + r['program'] if r.get('program') else ''})"))
    elif cmd == "resume":
        got = agent.resume(rest.strip() or "last")
        if got:
            agent.save()
            say(green("● ") + f"resumed: {got['title']}" + dim(f"  ({got['n']} messages)"))
        elif not getattr(agent, "resume_blocked", None):  # a BUSY conversation already said so; getattr: handle_slash is also driven with stand-ins
            say(red("  no such saved conversation (/sessions lists them)"))
    elif cmd == "fork":
        # deepcode's /fork: copy a conversation into a NEW one and keep talking; the source is untouched
        got = agent.fork(rest.strip() or "")
        if got:
            say(green("● ") + f"forked: {got['title']}" + dim(f"  ({got['n']} messages, new conversation)"))
        else:
            say(red("  nothing to fork (/sessions lists saved conversations)"))
    elif cmd == "continue":
        # deepcode's /continue: keep the active conversation, or resume one when this chat is empty
        if agent.s.get("history"):
            say(dim("  this conversation is active: ") + white(_title_of(agent.s["history"]))
                + dim("  (/resume switches to a saved one)"))
        else:
            got = agent.resume(rest.strip() or "last")
            if got:
                agent.save()
                say(green("● ") + f"resumed: {got['title']}" + dim(f"  ({got['n']} messages)"))
            elif not getattr(agent, "resume_blocked", None):  # a BUSY conversation already said so; getattr: handle_slash is also driven with stand-ins
                say(red("  no saved conversation to continue (/sessions lists them)"))
    elif cmd == "raw":
        # deepcode's /raw: toggle the reasoning display. gnoc's switch is /thoughts; this is the same knob
        SPIN.show_thoughts = not SPIN.show_thoughts   # the same knob as /thoughts: the display only
        agent.s["thoughts_shown"] = SPIN.show_thoughts
        agent.save()
        say(dim("  reasoning display (live ticker + ✻ thinking blocks): ") + (green("on") if SPIN.show_thoughts else yellow("off"))
            + dim("  (/raw again toggles it; /thoughts on|off is the same switch)"))
    elif cmd == "usage":
        u = MON.session_usage()
        if not u["models"]:
            say(dim("  no model calls this session yet"))
        else:
            # "N cached": the part of the input a provider served from its prompt cache (shown only when one did)
            say(dim(f"  session  {u['calls']} calls  {MON.fmt_n(u['in'])} in / {MON.fmt_n(u['out'])} out  "
                    + (f"({MON.fmt_n(u['cached'])} cached)  " if u.get("cached") else "")
                    + f"{MON.fmt_s(u['elapsed'])}"))
            for k, v in u["models"]:
                say(dim(f"    {MON.short_model(k)}  {v['calls']} calls  {MON.fmt_n(v['in'])} in / "
                        f"{MON.fmt_n(v['out'])} out  "
                        + (f"({MON.fmt_n(v['cached'])} cached)  " if v.get("cached") else "")
                        + f"{MON.fmt_s(v['secs'])}"))
        host = _lead_host()
        say(dim(f"  context  {prompt_ctx_pct(agent)}% full (lead on {host}, {ctx_for(host) // 1024}k window)"))
    elif cmd == "compact":
        host = _lead_host()
        before = ctx_pct_of(agent.s.get("history") or [], host)
        n0 = len(agent.s.get("history") or [])
        # Phase 2: the same archive-first lineage and summary stage as a turn's own compaction
        from .compact import chat_kwargs
        from .llm import llm_chat as _llm_chat
        from .state import STATE as _STATE
        kw = chat_kwargs(_STATE.sessions_dir, agent.s.get("sid"), hunt_stance(agent.ctx, ""),
                         llm_chat=_llm_chat, resolve=resolve)
        _compact(agent.s["history"], ctx_for(host), overhead=_tool_tokens(turn_tools(False, False)), **kw)
        if kw["lineage"] is not None and kw["lineage"].last_error:
            say(yellow(f"  could not archive the folded messages ({kw['lineage'].last_error[:120]})"))
        agent.save()
        after = ctx_pct_of(agent.s.get("history") or [], host)
        say(green("● ") + f"compacted {n0} → {len(agent.s['history'])} messages"
            + dim(f"  ·  ctx {before}% → {after}%"))
    elif cmd == "export":
        path, err = export_transcript(agent, rest.strip() or None)
        if err:
            say(red("  " + err))
        else:
            say(green("● ") + "exported " + _rel_home(path)
                + dim(f"  ({len(agent.s.get('history') or [])} messages)"))
    elif cmd == "exit":
        say(dim("  leaving the chat"))
        return "exit"  # the REPL loop reads this and leaves the same way q does
    elif cmd == "hooks":
        (gnoc_hooks,) = bind("gnoc_hooks")
        sub = rest.strip().lower()
        if sub == "trust":
            say(green("● ") + gnoc_hooks.trust(root()))
        elif sub == "untrust":
            say(green("● ") + gnoc_hooks.untrust(root()))
        else:
            say(gnoc_hooks.describe(root()))
            say(dim("  /hooks trust runs this repo's .gnoc/hooks.json (until it changes); format: gnoc_hooks.py docstring"))
    elif cmd == "skills":
        # Saved procedures (Phase 3). review, rm and trust change what loads into later turns, so they take the
        # /file identity check: only the exact string the REPL read from the keyboard passes. A model reply, a
        # tool result, a goal loop or a repo command file that produces "/skills review" is refused.
        import gnoc_skills
        typed = getattr(agent, "_typed_line", None) is line
        agent._typed_line = None   # one use

        def _ask(prompt):
            try:
                return input(yellow(prompt))
            except EOFError:
                return ""
        gnoc_skills.command(root(), rest, say, _ask, typed)
    elif cmd == "plugins":
        import gnoc_agent
        import gnoc_plugins
        w = rest.split()
        sub = w[0].lower() if w else ""
        if sub in ("enable", "disable"):
            # A plugin runs inside gnoc with his rights on every call, so turning one on is HIS act, checked like
            # /file: only the exact string object the REPL read from the keyboard passes (a model reply, a tool
            # result or a goal loop producing the same text does not).
            if getattr(agent, "_typed_line", None) is not line:
                say(red(f"  /plugins {sub} runs only from a line you typed at the prompt: refused, nothing changed"))
                return
            agent._typed_line = None   # one use
            if len(w) != 2:
                say(red(f"  usage: /plugins {sub} <name>"))
                return
            ok, msg = (gnoc_plugins.enable if sub == "enable" else gnoc_plugins.disable)(w[1])
            gnoc_plugins.sync_tools(gnoc_agent.TOOLS, gnoc_agent.CODE_TOOLS, gnoc_agent.ACTING_TOOLS)
            say((green("● ") if ok else red("  ")) + msg)
        elif sub in ("", "list", "show"):
            say(gnoc_plugins.describe(builtin_command_names(legacy)))
        else:
            say(red("  usage: /plugins [list] | /plugins enable <name> | /plugins disable <name>"))
    elif cmd == "permissions":
        import gnoc_perms
        w = rest.split(maxsplit=1)
        sub = w[0].lower() if w else ""
        if sub in ("allow", "deny") and len(w) > 1:
            text = w[1]
            flags = set(re.findall(r"(?:^|\s)(--(?:global|here|repo))\b", text))
            text = re.sub(r"(?:^|\s)--(?:global|here|repo)\b", " ", text).strip()
            # allow: this repo unless --global; deny: everywhere unless --here
            here = ("--here" in flags or "--repo" in flags) if sub == "deny" else "--global" not in flags
            ok, msg = gnoc_perms.add(sub, text, repo=root() if here else None)
            say((green("● ") if ok else red("  ")) + msg)
        elif sub in ("rm", "remove", "del", "delete") and len(w) > 1:
            ok, msg = gnoc_perms.remove(w[1].strip().lstrip("#"))
            say((green("● ") if ok else red("  ")) + msg)
        elif sub in ("", "list", "show"):
            here = os.path.realpath(root())
            got = gnoc_perms.rows()
            for prob in gnoc_perms.problems():
                say(red("  " + prob))
            if not got:
                say(dim("  no permission rules yet. At an approval prompt, p saves \"always allow this here\"; or:"))
            for n, kind, rule, repo in got:
                where = "everywhere" if not repo else ("this repo" if repo == here else _rel_home(repo))
                live = (not repo) or here == repo or here.startswith(repo.rstrip(os.sep) + os.sep)
                line = f"  #{n:<3} {kind:<5} {rule}"
                say((line if live else dim(line)) + dim(f"   ({where})"))
            say(dim("  /permissions allow bash(pytest *) [--global] · allow edit(src/*) · allow run_tests\n"
                    "  /permissions deny bash(rm -rf *) [--here] · /permissions rm <#>   "
                    f"({_rel_home(gnoc_perms.path())})\n"
                    "  deny blocks even under /auto; allow never covers commits, pushes, scans or desktop control"))
        else:
            say(red("  usage: /permissions [allow|deny <rule>|rm <#>]"))
    elif cmd == "doctor":
        import gnoc_doctor
        say(gnoc_doctor.report(gnoc_doctor.run_checks(role_spec)))
    elif cmd == "commands":
        (gnoc_hooks,) = bind("gnoc_hooks")
        got = gnoc_hooks.commands(root())
        if not got:
            say(dim("  no custom commands. Put a Markdown prompt in ~/.gnoc/commands/<name>.md or "
                    "<repo>/.gnoc/commands/<name>.md; /<name> args runs it ($ARGUMENTS is replaced)."))
        for n, (p, desc) in sorted(got.items()):
            say(f"  /{n}" + (dim(f"  {desc}") if desc else "") + dim(f"  ({_rel_home(p)})"))
    elif cmd == "bg":
        (t_bg,) = bind("t_bg")
        w = rest.split(maxsplit=1)
        if not w or w[0] == "list":
            say(t_bg(agent.ctx, "list"))
        elif w[0] in ("stop", "output", "log") and len(w) > 1:
            say(t_bg(agent.ctx, w[0], name=w[1].strip()))
        else:
            say(red("  usage: /bg [list] | /bg output <name> | /bg log <name> | /bg stop <name>"))
    elif cmd == "mcp":
        (register_mcp_tools,) = bind("register_mcp_tools")
        if rest.strip() in ("refresh", "reload"):
            n = register_mcp_tools(refresh=True)
            say(green("● ") + f"{n} MCP tool(s) offered as native tools")
        else:
            say(red("  usage: /mcp refresh   (list every configured server's tools again; configure with gnoc mcp add)"))
    elif cmd in legacy:
        legacy[cmd](rest.split())
    else:
        import gnoc_plugins
        got = gnoc_plugins.run_command(cmd, rest, builtin_command_names(legacy))
        if got is not None:   # an enabled plugin's command: its output is shown, never sent to the model
            say(got)
            return
        (gnoc_hooks,) = bind("gnoc_hooks")
        try:
            text = gnoc_hooks.expand(root(), cmd, rest)
        except OSError:
            text = None
        if text:
            say(dim(f"  /{cmd}: running your command file"))
            agent.s["_typed"] = text          # his own command file: his words
            agent.turn(text)
        else:
            say(red(f"  unknown command /{cmd} - /help (your own: /commands)"))
