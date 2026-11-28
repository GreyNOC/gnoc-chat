"""Reflection, learning, ship gates, background jobs, fan-out, team and economy tools."""
import os
from gnoc_core.runtime import bind


def _reflect_target():
    (
        REFLECT_PREFER, _REFLECT_PICK, contextlib, json, llm_endpoints, os, resolve,
        urllib,
    ) = bind(
        "REFLECT_PREFER", "_REFLECT_PICK", "contextlib", "json", "llm_endpoints", "os",
        "resolve", "urllib",
    )
    model, host = resolve("worker")
    want = os.environ.get("GNOC_REFLECT_MODEL", "").strip()
    if want:
        w = (want.split("@", 1)[0], want.split("@", 1)[1]) if "@" in want else (want, host)
        if llm_endpoints.allow_stock() or not llm_endpoints.stock(*w):
            return w
    if host not in _REFLECT_PICK:
        have = set()
        with contextlib.suppress(Exception):
            with urllib.request.urlopen("http://" + llm_endpoints.HOSTS[host] + "/api/tags", timeout=4) as r:
                have = {m.get("name") for m in json.load(r).get("models") or []}
        _REFLECT_PICK[host] = next((m for m in REFLECT_PREFER if m in have), None)
    pick = _REFLECT_PICK[host] or model
    if not llm_endpoints.allow_stock() and llm_endpoints.stock(pick, host):
        pick = llm_endpoints.DEFAULT
    return pick, host


def _reflect_llm(messages):
    """The reflector: thinking OFF and room for the JSON. With Qwen3's thinking on, num_predict=700 was spent
    reasoning and the answer arrived cut off mid-object (replayed 2026-10-22: 111 s, then a 56 s retry)."""
    (
        TOOL_LLM_TIMEOUT, _reflect_target, llm_chat,
    ) = bind(
        "TOOL_LLM_TIMEOUT", "_reflect_target", "llm_chat",
    )
    model, host = _reflect_target()
    return llm_chat(model, host, messages, num_predict=1200, think=False,
                    timeout=TOOL_LLM_TIMEOUT).get("content") or ""


def run_reflection(turn_msgs, program, llm=None):
    """One recursive-learning pass over a finished turn (the worker GPU does it). Returns the counts."""
    (
        _LEARN_NOTES, _reflect_llm, gnoc_learn,
    ) = bind(
        "_LEARN_NOTES", "_reflect_llm", "gnoc_learn",
    )
    query = " ".join((m.get("content") or "")[:300] for m in turn_msgs if m.get("role") == "user")
    given = gnoc_learn.recall(query, program, mark_used=False)
    n = gnoc_learn.reflect(llm or _reflect_llm, turn_msgs, program, given)
    msg = gnoc_learn.summary(n)
    if msg:
        _LEARN_NOTES.append("learned: " + msg)
    return n


def start_reflection(turn_msgs, program):
    """Reflect in the background so the user never waits on it; one pass at a time, a busy worker skips.
    A piped session (gnoc chat < turns.txt) has nobody waiting, so it queues instead: skipping there dropped the
    reflection, and the trajectory with it, for every turn that finished while the last one was reflecting."""
    (
        MON, _LEARN_NOTES, _REFLECTING, _reflect_target, gnoc_learn, run_reflection,
        sys, threading,
    ) = bind(
        "MON", "_LEARN_NOTES", "_REFLECTING", "_reflect_target", "gnoc_learn",
        "run_reflection", "sys", "threading",
    )
    got = _REFLECTING.acquire(timeout=240) if not sys.stdin.isatty() else _REFLECTING.acquire(blocking=False)
    if not got:
        return
    _PENDING_REFLECTION[0] = (turn_msgs, program)   # what an exit hands to a detached process if it is not done

    def go():
        m, h = _reflect_target()
        sid = MON.start("reflect", m, h, f"lesson book after a turn ({program or '-'})")
        MON.bind(sid)
        st = "done"
        try:
            n = run_reflection(turn_msgs, program)
            MON.append(sid, "result: " + (gnoc_learn.summary(n) or "nothing new"))
            for why in gnoc_learn.LAST_REJECTS[:8]:
                MON.append(sid, "refused " + why)
        except Exception as e:
            st = "failed"
            _LEARN_NOTES.append(f"reflection skipped: {type(e).__name__}")
        finally:
            MON.finish(sid, st)
            MON.unbind()
            _PENDING_REFLECTION[0] = None
            _REFLECTING.release()
    threading.Thread(target=go, daemon=True).start()


_PENDING_REFLECTION = [None]


def _detach_reflection(pending):
    """Finish the last turn's reflection in a process of its own, so the person at the terminal is not held at
    exit. Returns the child's pid, or None when it could not be started (the caller then waits as before)."""
    import json
    import os
    import subprocess
    import sys
    import tempfile
    msgs, program = pending
    scripts = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        fd, path = tempfile.mkstemp(prefix="gnoc-reflect-", suffix=".json")   # 0600: the turn may hold code
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"msgs": msgs, "program": program}, fh)
    except (OSError, TypeError, ValueError):
        return None
    code = ("import json, os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import gnoc_compat\n"
            "gnoc_compat.install()\n"
            "with open(sys.argv[2], encoding='utf-8') as fh:\n"
            "    d = json.load(fh)\n"
            "os.remove(sys.argv[2])\n"
            "import gnoc_agent as G\n"
            "G.run_reflection(d['msgs'], d.get('program'))\n")
    try:
        child = subprocess.Popen([sys.executable, "-c", code, scripts, path], cwd=scripts,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True, start_new_session=True,
                                 creationflags=(0x00000008 | 0x00000200) if os.name == "nt" else 0)
    except OSError:
        try:
            os.remove(path)
        except OSError:
            pass
        return None
    return child.pid


def wait_reflection(timeout=240):
    """Let the last turn's reflection finish before the process exits. It runs on a daemon thread, so a one-shot
    `gnoc chat "..."` or a q / Ctrl-D right after a turn killed it mid-call: no lesson and no trajectory was ever
    written (trajectories.jsonl did not exist after a day of use, 2026-10-22)."""
    (
        _REFLECTING, contextlib, dim, say,
    ) = bind(
        "_REFLECTING", "contextlib", "dim", "say",
    )
    if _REFLECTING.locked():
        import os
        import sys
        # A person at the terminal waited 3.5 minutes after a two-line answer while a slow worker reflected
        # (2026-11-20 SWE drive): the unfinished pass now goes to a process of its own and gnoc exits at once.
        # Piped and batch runs keep waiting - nobody is held, and their turns do not overlap the next run's.
        pending = _PENDING_REFLECTION[0]
        mode = os.environ.get("GNOC_REFLECT_DETACH", "")
        if pending and mode != "0" and (mode == "1" or sys.stdout.isatty()):
            pid = _detach_reflection(pending)
            if pid:
                say(dim(f"  ⎿  the lesson-book reflection finishes in the background (pid {pid})"))
                return
        say(dim("  ⎿  finishing the lesson-book reflection before exit (Ctrl-C skips)"))
        with contextlib.suppress(KeyboardInterrupt):
            if _REFLECTING.acquire(timeout=timeout):
                _REFLECTING.release()


def t_learn(ctx, text, why="", kind="rule", everywhere=False):
    (
        _LEARN_READ_WORDS, gnoc_learn,
    ) = bind(
        "_LEARN_READ_WORDS", "gnoc_learn",
    )
    text, kind = str(text or "").strip(), str(kind or "rule").lower()
    # learn WRITES. Asked to read the lesson book the agent tried learn(action='list') and then
    # learn(text='list'), which would have stored a lesson whose whole content was "list" if the length
    # floor had not caught it (soak batch11 2026-10-25). A read verb is a wrong tool, not a short lesson.
    if text.lower().strip(" .:-") in _LEARN_READ_WORDS:
        return (f"bad arguments: learn WRITES one lesson; {text!r} is a read. To read the lesson book use "
                f"lessons() for the most recent, or lessons(query=<words>) to search it.")
    if len(text) < 12:
        return "bad arguments: learn needs text=<one concrete sentence a future turn can act on>"
    if kind not in ("rule", "fact", "pref"):
        return f"bad arguments: kind is rule or fact (got {kind!r})"
    if kind == "pref":
        # recall() injects EVERY pref into EVERY turn, so an invented one is permanent background noise.
        # The reflection has refused model-written prefs since 2026-10-22; this tool did not, and on
        # 2026-10-25 the agent stored two invented design opinions ("implement a tool manifest with
        # pre-flight validation") as standing preferences of GreyNOC's.
        return ("refused: a preference is how the user wants the work done, so it comes from their own words, "
                "not from you. Record what you found as kind='rule' (how to act) or kind='fact' (what is true).")
    ok, why_not = gnoc_learn.worth_keeping(text, why, kind, "agent")
    if not ok:
        # add() checks only length and fictional targets; worth_keeping lived on the reflection path alone,
        # so this tool was the unguarded way into the book (2026-10-25).
        return f"not stored: {why_not}"
    everywhere = everywhere is True or str(everywhere).lower() in ("true", "1", "yes")
    lid, how = gnoc_learn.add(text, str(why or ""), kind,
                              "*" if everywhere or kind == "pref" else (ctx.program or "*"), "agent")
    return f"lesson {lid} {how}" if lid else f"not stored: {how}"


def ship_chain(ctx, draft_dir):
    """Write CHAIN.md (the proven chain and its evidence) into the draft dir, then run the three Claude gates in
    order as ONE background job. Nothing is filed: submission stays the user's call after the user reads the verdicts."""
    (
        CLAUDE_WORKER_MAX_S, JOBS_DIR, MON, SHIP_GATES, WS, _bind_lane, _claude_auth_allow, _lane_line,
        _now, gnoc_hunt, gnoc_secrets, json, local_gates, offline, os, shlex,
        subprocess,
    ) = bind(
        "CLAUDE_WORKER_MAX_S", "JOBS_DIR", "MON", "SHIP_GATES", "WS", "_bind_lane", "_claude_auth_allow",
        "_lane_line", "_now", "gnoc_hunt", "gnoc_secrets", "json", "local_gates",
        "offline", "os", "shlex", "subprocess",
    )
    d = os.path.realpath(os.path.join(WS, draft_dir) if not os.path.isabs(draft_dir) else draft_dir)
    base = os.path.join(WS, "reports", "drafts")
    if not d.startswith(base + os.sep) or not os.path.isfile(os.path.join(d, "report.md")):
        return f"refused: {draft_dir} is not a draft dir with a report.md under reports/drafts/"
    program = os.path.relpath(d, base).split(os.sep)[0]
    complete = [(sc, c) for sc, c in gnoc_hunt.chains(program, 10) if all(e["status"] == "proven" for e in c)]
    lines = [f"# Chain behind this draft ({_now():%Y-%m-%d %H:%MZ}, gnoc chat ledger)", ""]
    if complete:
        sc, c = complete[0]
        lines.append(f"Crown: {c[-1]['to']}  ·  prestige score {sc}  ·  every edge proven against captured bytes")
        lines.append("")
        for e in c:
            lines.append(f"- {e['id']} `{e['frm']}` -> `{e['to']}` via {e['via']}")
            lines.append(f"  evidence: {e['evidence']}" + (f"  (contains `{e['must_contain']}`)" if e.get("must_contain") else ""))
            if e.get("requires"):
                lines.append(f"  requires: {', '.join(e['requires'])}")
    else:
        lines.append("No fully proven chain in the ledger: the gates judge the report on its own evidence.")
    with open(os.path.join(d, "CHAIN.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    rel = os.path.relpath(d, WS)
    if offline():
        return local_gates(d, program, rel)
    os.makedirs(JOBS_DIR, exist_ok=True)
    stamp = f"{_now():%Y%m%d-%H%M%S}"
    script = ["set -u", f"cd {shlex.quote(WS)}"]
    outs = []
    for agent in SHIP_GATES:
        outf = os.path.join(JOBS_DIR, f"{stamp}-gate-{agent}.out")
        outs.append(os.path.relpath(outf, WS))
        prompt = (f"Read Manual/HARNESS.md first and follow it. Program: {program}. Run your gate on the draft "
                  f"{rel}/report.md. The chain behind it and every evidence path are in {rel}/CHAIN.md; the CVSS "
                  f"arithmetic, the capability gate, the dedup stamp and the Burp-panel checklist are in {rel}/GATES.md. Re-observe "
                  f"the terminal in the captured bytes yourself. Write your verdict (first line: PASS, FIXABLE or "
                  f"KILL) with the exact gaps to {rel}/GATE-{agent}.md. Never submit or file anything.")
        # a real wall clock, as claude_worker has: the message below promised one that did not exist (QAQC 2026-11-19)
        script.append(f"timeout --kill-after=30 {int(CLAUDE_WORKER_MAX_S)} claude -p {shlex.quote(prompt)} --agent "
                      f"{agent} --model opus --permission-mode bypassPermissions --output-format text "
                      f"> {shlex.quote(outf)} 2>&1")
    env = gnoc_secrets.child_env({"HUNT_TARGET": program}, allow=_claude_auth_allow())   # T1.7
    log = os.path.join(JOBS_DIR, f"{stamp}-ship-gates.out")
    with open(log, "w") as fh:
        p = subprocess.Popen(["bash", "-c", "\n".join(script)], cwd=WS, stdin=subprocess.DEVNULL, stdout=fh,
                             stderr=subprocess.STDOUT, env=env, start_new_session=True)
    lane = _bind_lane(p.pid, "ship-gates")   # T1.0: the gate job dies with this chat
    with open(log + ".meta", "w") as fh:
        json.dump({"pid": p.pid, "agent": "ship-gates", "model": "opus", "program": program,
                   "brief": f"gates {', '.join(SHIP_GATES)} on {rel}", "ts": _now().isoformat(),
                   "lane_registered": lane}, fh)
    MON.start("claude:ship-gates", "opus", "cloud", f"{' -> '.join(SHIP_GATES)} on {rel}", pid=p.pid, log=log)
    return (f"wrote {rel}/CHAIN.md; started the ship gates ({' -> '.join(SHIP_GATES)}, opus) pid {p.pid}. "
            f"Verdicts land in {rel}/GATE-<agent>.md; outputs: {', '.join(outs)}. Nothing is filed. "
            + _lane_line(lane))


def _bind_lane(pid, label):
    """T1.0 (spec SPEC-0security-alignment-20261109): register a detached background job as a lane of THIS chat so
    closing the chat kills its whole process group (the user 2026-11-02: "when gnoc chat is closed the hunting should
    stop as well"). The job runs in its own session, so its pgid IS its pid. Before this only gnoc_company.py
    registered lanes, and a claude_worker or ship-gates job outlived the chat by up to 90 minutes (T10 red run).
    False when no chat session is open in this process (an offline test, GNOC_HUNT_NO_SESSION): today's behaviour."""
    (
        gnoc_session,
    ) = bind(
        "gnoc_session",
    )
    try:
        return bool(gnoc_session.register_lane(pid, label=label, pgid=pid))
    except Exception:  # noqa: BLE001 - a registry failure must not lose the job; the start line says it is unbound
        return False


def _claude_auth_allow():
    """T1.7: the claude CLI may authenticate with ANTHROPIC_API_KEY; it is the ONE secret a Claude child keeps, and
    only when it is set. No other call site allows any credential-shaped name."""
    (
        os,
    ) = bind(
        "os",
    )
    return ("ANTHROPIC_API_KEY",) if os.environ.get("ANTHROPIC_API_KEY") else ()


def _lane_line(bound):
    return ("It stops when this chat closes." if bound else
            "It is not bound to a chat session (none open in this process), so it runs to its wall clock.")


def _lead_llm(messages):
    (
        TOOL_LLM_TIMEOUT, llm_chat, resolve,
    ) = bind(
        "TOOL_LLM_TIMEOUT", "llm_chat", "resolve",
    )
    model, host = resolve("lead")
    return llm_chat(model, host, messages, num_predict=1200, timeout=TOOL_LLM_TIMEOUT).get("content") or ""


def local_gates(d, program, rel):
    """Offline ship gates: the code checks now, then the three model roles on the local GPUs in the background."""
    (
        MON, _LEARN_NOTES, _lead_llm, gnoc_gates, resolve, threading,
    ) = bind(
        "MON", "_LEARN_NOTES", "_lead_llm", "gnoc_gates", "resolve", "threading",
    )
    verdict, nbad = gnoc_gates.write_format_gate(d, program)

    def go():
        m, h = resolve("lead")
        sid = MON.start("gates", m, h, f"local ship gates on {rel}")
        MON.bind(sid)
        try:
            res = gnoc_gates.run_all(_lead_llm, d, program)
            MON.finish(sid, "done", ", ".join(f"{k} {v}" for k, v in res.items()))
            _LEARN_NOTES.append(f"local gates on {rel}: " + ", ".join(f"{k} {v}" for k, v in res.items())
                                + f" (see {rel}/GATES-local.md)")
        except Exception as e:
            MON.finish(sid, "failed", str(e))
            _LEARN_NOTES.append(f"local gates on {rel} failed: {type(e).__name__}: {e}")
        finally:
            MON.unbind()
    threading.Thread(target=go, daemon=True).start()
    return (f"offline: wrote {rel}/CHAIN.md; code checks {verdict} ({nbad} failing, {rel}/GATE-local-format.md). "
            f"The local reviewer, killer and repro roles are running on your GPUs; verdicts land in "
            f"{rel}/GATE-local-<role>.md and {rel}/GATES-local.md. Nothing is filed.")


def t_ship_chain(ctx, draft_dir):
    (
        ship_chain,
    ) = bind(
        "ship_chain",
    )
    return ship_chain(ctx, draft_dir)


def floor_check(program, hypothesis, not_single_use=""):
    """None when a DEAD may be recorded, else the refusal. The counts come from the hunt ledger (what the tools
    actually fired against the hypothesis), never from the model's own numbers."""
    (
        FLOOR_PROBES, gnoc_hunt,
    ) = bind(
        "FLOOR_PROBES", "gnoc_hunt",
    )
    if not hypothesis:
        return ("refused: a DEAD needs the hypothesis id (hunt_hypothesis) so the ledger can verify the floor; "
                "record LEAD or UNFIRED instead, or test it under a hypothesis first")
    # An id that is not on THIS program's ledger used to come back as "0 counted probes", which reads as "your
    # 20 probes do not count" and invited a confabulated reason for it: the live lead answered "the tool treats
    # them as 0 because they were not mutated" (QA runs 2 and 3, 2026-10-25). Say what is actually wrong.
    if gnoc_hunt._find_hyp(gnoc_hunt.load(program).get("hypotheses") or [], hypothesis) is None:
        have = ", ".join(h["id"] for h in (gnoc_hunt.load(program).get("hypotheses") or [])[:12]) or "none"
        return (f"refused: there is no hypothesis {hypothesis} on {program} (it has: {have}). Either the id is wrong "
                f"or the hypothesis lives on another program, in which case set_program first. Nothing was recorded. "
                "Do NOT add a hypothesis to make this row legal: the floor is what the tools fired against a real "
                "hypothesis, so a fresh one has 0 probes and the row would still be refused. Record UNFIRED, or "
                "probe the hypothesis you mean.")
    # counted=True: probes spent on a route that only ever refused do not reach the floor (gnoc_hunt.walled_routes,
    # T-49). The ledger's own dead gate already refuses them; record_outcome is the second door into a DEAD row.
    probes, bursts = gnoc_hunt.floor_status(program, hypothesis, counted=True)
    raw = gnoc_hunt.floor_status(program, hypothesis)[0]
    if probes < FLOOR_PROBES:
        wall = f" ({raw} logged, {raw - probes} on a route that never answered 2xx)" if raw > probes else ""
        return (f"refused: {hypothesis} has {probes} counted probes{wall}, the floor is {FLOOR_PROBES}. Mutate the input "
                "(probe_matrix: methods, path shapes, version twins, neighbour ids, identities) or record UNFIRED "
                "with what blocked you")
    if not bursts and len((not_single_use or "").strip()) < 15:
        return (f"refused: {hypothesis} never got a concurrent burst. Run race on its single-use / check-then-act "
                "request, or give not_single_use = why this path has no one-shot step")
    return None


def _ledger_status(program, hypothesis):
    (
        gnoc_hunt,
    ) = bind(
        "gnoc_hunt",
    )
    try:
        hid = gnoc_hunt.canonical_hyp_id(program, hypothesis)
        for h in gnoc_hunt.load(program).get("hypotheses", []):
            if str(h.get("id", "")).upper() == str(hid or "").upper():
                return str(h.get("status") or "").lower()
    except Exception:  # noqa: BLE001
        return ""
    return ""


def _verdict_vs_ledger(program, hypothesis, verdict):
    """The refusal when the outcome verdict claims more than the hypothesis ledger holds, else "". D102 (cycle 28):
    LEAD rows were written for two UNFIRED hypotheses whose every capture was a 401. The ledger's status is set by
    the promotion gates, which read the captures; the outcome row may not outrank them."""
    (
        _ledger_status,
    ) = bind(
        "_ledger_status",
    )
    st = _ledger_status(program, hypothesis)
    if not st:
        return ""
    want = {"LEAD": ("lead", "candidate"), "CRITICAL-CANDIDATE": ("candidate",), "MEDIUM-CANDIDATE": ("candidate",),
            "DEAD": ("dead",)}
    if verdict in want and st not in want[verdict]:
        fix = ("hunt_hypothesis action=update status=lead evidence=<the capture that shows the mechanism>"
               if verdict == "LEAD" else "hunt_hypothesis action=update status=candidate ..." if "CANDIDATE" in verdict
               else "hunt_hypothesis action=update status=dead notes=...")
        return (f"refused: {hypothesis} is {st.upper()} in the hypothesis ledger, so the outcome cannot be {verdict}. "
                f"Record verdict={'UNFIRED' if st in ('open', 'probing', 'unfired') else st.upper()} for what the ledger "
                f"holds, or change the ledger first ({fix}); the promotion gate reads the captures and refuses a "
                "refusal-only capture.")
    return ""


def t_record_outcome(ctx, vector, verdict, capability="none", probes=0, burst=False, artifact="", notes="",
                     hypothesis=None, not_single_use=""):
    (
        FLOOR_PROBES, WS, _now, _program_gate_write, _verdict_vs_ledger, floor_check,
        gnoc_hunt, json, os, subprocess, sys,
    ) = bind(
        "FLOOR_PROBES", "WS", "_now", "_program_gate_write", "_verdict_vs_ledger",
        "floor_check", "gnoc_hunt", "json", "os", "subprocess", "sys",
    )
    refused = _program_gate_write(ctx, "an outcome row")
    if refused:
        return refused
    verdict = str(verdict or "").strip().upper()
    allowed = ("CRITICAL-CANDIDATE", "MEDIUM-CANDIDATE", "LEAD", "DEAD", "NEEDS", "UNFIRED")
    if verdict not in allowed:
        return f"bad arguments: verdict is one of {', '.join(allowed)} (got {verdict[:30]!r})"
    if not str(vector or "").strip():
        return "bad arguments: record_outcome needs vector=<what was tested, e.g. 'GET /api/v2/orders/{id} IDOR'>"
    if isinstance(burst, str):
        burst = burst.strip().lower() in ("true", "1", "yes")
    self_reported = not hypothesis
    if verdict in ("LEAD", "CRITICAL-CANDIDATE", "MEDIUM-CANDIDATE") and not hypothesis:
        return (f"refused: a {verdict} outcome needs hypothesis=<id> whose ledger status is lead or candidate; "
                "promote it with hunt_hypothesis first (the promotion gate checks the capture), then record.")
    if hypothesis:  # the ledger's counts win over the model's, and a walled route does not count (T-49)
        lp, lb = gnoc_hunt.floor_status(ctx.program, hypothesis, counted=True)
        probes, burst = max(lp, 0), lb > 0
        why = _verdict_vs_ledger(ctx.program, hypothesis, verdict)   # D102
        if why:
            return why
    if verdict == "DEAD":
        why = floor_check(ctx.program, hypothesis, not_single_use)
        if why:
            return why
        if not burst:
            notes = (notes + f" | no burst: {not_single_use}").strip(" |")
    row = {"ts": _now().isoformat(timespec="seconds"), "lane": "gnoc-agent", "target": ctx.program or "?",
           "vector": vector, "verdict": verdict, "capability": capability, "probes": int(probes or 0),
           # Without a hypothesis id nothing counted these probes but the model, so the row may not claim a
           # met floor. Asked to LIST the tools it would use for a cross-tenant read, the agent called
           # record_outcome(verdict='CANDIDATE', probes='8') on a hunt it had not run, and only the verdict
           # enum refused it (soak batch9 2026-10-25). gnoc_economy already recomputes the floor and ignores
           # this field; the funnel and the lesson book do not.
           "burst": bool(burst),
           "minutes": 0, "floor": "not-met" if self_reported else (
               "met" if int(probes or 0) >= FLOOR_PROBES else "not-met"),
           "artifact": artifact,
           "notes": (notes + (f" [{hypothesis}]" if hypothesis
                              else " | probes self-reported, no hypothesis id: floor unverified")).strip(" |")}
    try:
        r = subprocess.run([sys.executable, os.path.join(WS, "scripts/hunt-state.py"), "append-outcome"],
                           input=json.dumps(row), capture_output=True, text=True, timeout=30, cwd=WS)
    except subprocess.TimeoutExpired:
        return "NOT recorded: hunt-state.py timed out after 30s (a ledger lock?); call record_outcome again"
    return "recorded" if r.returncode == 0 else f"hunt-state refused it: {(r.stderr or r.stdout).strip()[:300]}"


def t_claude_worker(ctx, agent, brief, program=None, model="sonnet"):
    (
        CLAUDE_WORKER_MAX_S, JOBS_DIR, MON, WORKER_RETRY_FRAMING, WS, _bind_lane,
        _claude_auth_allow, _lane_line, _now, _worker_script, gnoc_secrets, json,
        offline, os, re, subprocess,
    ) = bind(
        "CLAUDE_WORKER_MAX_S", "JOBS_DIR", "MON", "WORKER_RETRY_FRAMING", "WS",
        "_bind_lane", "_claude_auth_allow", "_lane_line", "_now", "_worker_script",
        "gnoc_secrets", "json", "offline", "os", "re", "subprocess",
    )
    import shutil
    import gnoc_subagents
    if shutil.which("claude") is None:
        # offline() is also true without the CLI, and "offline mode" sent the lead to tell the user to turn
        # offline mode off. Name the real cause and the fix (phase 4: the worker is optional and detected).
        return gnoc_subagents.CLAUDE_MISSING
    if offline():
        return ("refused: offline mode, no cloud models. Do it yourself with your tools, or delegate to the worker "
                "model on the other GPU.")
    program = program or ctx.program
    agent, model, brief = str(agent or "").strip(), str(model or "sonnet").lower(), str(brief or "")
    known = sorted(f[:-3] for f in os.listdir(os.path.join(WS, ".claude", "agents")) if f.endswith(".md")) \
        if os.path.isdir(os.path.join(WS, ".claude", "agents")) else []
    if known and agent not in known:
        import difflib
        near = difflib.get_close_matches(agent, known, n=6, cutoff=0.4) or [a for a in known if a.endswith("-hunter")]
        return f"bad arguments: no agent {agent!r} in .claude/agents/. Closest: {', '.join(near[:12])}"
    if model not in ("haiku", "sonnet", "opus"):
        return f"bad arguments: model is haiku, sonnet or opus (got {model!r})"
    if len(brief.strip()) < 20:
        return "bad arguments: brief must say the task, the target paths and what to report back (20+ characters)"
    os.makedirs(JOBS_DIR, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", agent)
    outf = os.path.join(JOBS_DIR, f"{_now():%Y%m%d-%H%M%S}-{safe}.out")
    prompt = gnoc_secrets.redact("Read Manual/HARNESS.md first and follow it. "
                                 + (f"Program: {program}. " if program else "") + brief)
    # a background worker still gets a wall clock: coreutils timeout ends it (exit 124 in the log) at the cap
    def cmd(text):
        return ["timeout", "--kill-after=30", str(CLAUDE_WORKER_MAX_S),
                "claude", "-p", text, "--agent", agent, "--model", model,
                "--permission-mode", "bypassPermissions", "--output-format", "text"]
    env = gnoc_secrets.child_env({"HUNT_TARGET": program} if program else {}, allow=_claude_auth_allow())  # T1.7
    # T1.3: ONE approved dispatch runs a wrapper that labels the output and, on an empty / error / refused first
    # attempt, retries ONCE with the authorized-research framing. No second retry, no new approval.
    script = _worker_script(cmd(prompt), cmd(WORKER_RETRY_FRAMING + prompt), outf)
    with open(outf, "w") as fh:
        p = subprocess.Popen(["bash", "-c", script], cwd=WS, stdin=subprocess.DEVNULL, stdout=fh,
                             stderr=subprocess.STDOUT, env=env, start_new_session=True)
    lane = _bind_lane(p.pid, f"claude:{agent}")   # T1.0: the worker dies with this chat
    gnoc_subagents.register_claude_worker(p.pid)   # phase 4: ...and with a Ctrl-C (its own session: pgid == pid)
    with open(outf + ".meta", "w") as fh:
        json.dump({"pid": p.pid, "agent": agent, "model": model, "program": program,
                   "brief": gnoc_secrets.redact(brief)[:500],
                   "ts": _now().isoformat(), "timeout_s": CLAUDE_WORKER_MAX_S, "lane_registered": lane,
                   "health": 1}, fh)
    MON.start("claude:" + agent, model, "cloud", gnoc_secrets.redact(brief), pid=p.pid, log=outf)
    return (f"started claude worker {agent} ({model}) pid {p.pid}; output {os.path.relpath(outf, WS)}; it is "
            f"stopped after {CLAUDE_WORKER_MAX_S // 60} min, or by Ctrl-C. {_lane_line(lane)} Check it with jobs (do "
            "not wait in a loop)")


def _worker_script(first, retry, outf):
    """The bash the ONE approved dispatch runs: attempt, label it, at most one retry after 30 s, exit markers."""
    (
        JOB_RETRYABLE, WS, os, shlex, sys,
    ) = bind(
        "JOB_RETRYABLE", "WS", "os", "shlex", "sys",
    )
    q = shlex.quote
    label = f"{q(sys.executable)} {q(os.path.join(WS, 'scripts', 'gnoc_agent.py'))} --job-health {q(outf)}"
    return "\n".join([
        "set -u",
        f"cd {q(WS)}",
        " ".join(q(x) for x in first),
        'echo "[gnoc-exit $?]"',
        f'lab=$({label} 2>/dev/null)',
        'case "$lab" in',
        "  " + "|".join(JOB_RETRYABLE) + ")",
        '    echo "[gnoc-retry 1] first attempt was $lab; one retry in 30 s with the research framing"',
        "    sleep 30",
        "    " + " ".join(q(x) for x in retry),
        '    echo "[gnoc-exit $?]"',
        "    ;;",
        "esac",
    ]) + "\n"


def _pid_running(pid):
    """True for a live process; a zombie (finished, not yet reaped by the chat) is not running."""
    try:
        with open(f"/proc/{int(pid)}/stat") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X")
    except (OSError, ValueError, IndexError, TypeError):
        return False


def _job_attempt(text):
    """(body of the LAST attempt with the wrapper markers removed, its exit code or None)."""
    (
        _JOB_MARK, re,
    ) = bind(
        "_JOB_MARK", "re",
    )
    i = text.rfind("[gnoc-retry")
    if i >= 0:
        nl = text.find("\n", i)
        text = text[nl + 1:] if nl >= 0 else ""
    codes = re.findall(r"^\[gnoc-exit (\d+)\]", text, re.M)
    return _JOB_MARK.sub("", text).strip(), (int(codes[-1]) if codes else None)


def _job_health(outf, meta=None):
    """RUNNING | STALLED | TIMEOUT | REFUSED | FAILED-ERROR | FAILED-EMPTY | DONE for one job output file."""
    (
        JOB_STALL_S, REFUSAL, _JOB_DIGEST, _JOB_ERROR, _JOB_REFUSED, _job_attempt,
        _pid_running, _read, os, time,
    ) = bind(
        "JOB_STALL_S", "REFUSAL", "_JOB_DIGEST", "_JOB_ERROR", "_JOB_REFUSED",
        "_job_attempt", "_pid_running", "_read", "os", "time",
    )
    meta = meta or {}
    if meta.get("pid") and _pid_running(meta["pid"]):
        try:
            idle = time.time() - os.path.getmtime(outf)
        except OSError:
            idle = 0
        return "STALLED" if idle >= JOB_STALL_S else "RUNNING"
    body, rc = _job_attempt(_read(outf))
    if rc == 124:
        return "TIMEOUT"
    if _JOB_DIGEST.search(body):
        return "DONE"   # a real digest wins over its size and over a word like "rate limit" inside it
    head = body[:3000]
    if REFUSAL.search(head) or _JOB_REFUSED.search(head):
        return "REFUSED"
    if _JOB_ERROR.search(head):
        return "FAILED-ERROR"
    if len(body.encode("utf-8", "replace")) < 200:
        return "FAILED-EMPTY"
    return "DONE"


def _append_outcome(row):
    """One outcome row through the sanctioned writer (HARNESS 3a). Returns the writer's verdict text."""
    (
        WS, json, os, subprocess, sys,
    ) = bind(
        "WS", "json", "os", "subprocess", "sys",
    )
    try:
        r = subprocess.run([sys.executable, os.path.join(WS, "scripts/hunt-state.py"), "append-outcome"],
                           input=json.dumps(row), capture_output=True, text=True, timeout=30, cwd=WS)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"not recorded ({type(e).__name__})"
    return "recorded" if r.returncode == 0 else f"refused: {(r.stderr or r.stdout).strip()[:200]}"


def _record_failed_job(outf, meta, label):
    """ONE UNFIRED outcome row per failed job (guarded by <out>.recorded), so the floor ledger never counts a
    worker that produced no digest as a lane. Only jobs started with the health wrapper (meta health=1)."""
    (
        JOB_FAILED, WS, _append_outcome, _now, datetime, os,
    ) = bind(
        "JOB_FAILED", "WS", "_append_outcome", "_now", "datetime", "os",
    )
    if not (meta.get("health") and meta.get("program")) or label not in JOB_FAILED:
        return None
    mark = outf + ".recorded"
    if os.path.exists(mark):
        return None
    try:
        started = datetime.fromisoformat(str(meta.get("ts")))
        minutes = round(max(0.0, (_now() - started).total_seconds()) / 60, 1)
    except (TypeError, ValueError):
        minutes = 0
    rel = os.path.relpath(outf, WS) if os.path.realpath(outf).startswith(WS + os.sep) else outf
    row = {"ts": _now().isoformat(timespec="seconds"), "lane": f"claude-worker:{meta.get('agent')}",
           "target": meta.get("program"), "vector": f"claude_worker {meta.get('agent')} ({meta.get('model')}) job",
           "verdict": "UNFIRED", "capability": "none", "probes": 0, "burst": False, "minutes": minutes,
           "floor": "not-met", "artifact": rel, "notes": f"worker {label}: no digest, not a lane result"}
    got = _append_outcome(row)
    with open(mark, "w") as fh:
        fh.write(f"{_now().isoformat(timespec='seconds')} {label} {got}\n")
    return got


def t_jobs(ctx, tail=15):
    (
        JOBS_DIR, JOB_FAILED, _job_health, _pid_running, _read, _record_failed_job,
        _spill, json, os,
    ) = bind(
        "JOBS_DIR", "JOB_FAILED", "_job_health", "_pid_running", "_read",
        "_record_failed_job", "_spill", "json", "os",
    )
    if not os.path.isdir(JOBS_DIR):
        return "no jobs yet (claude_worker and ship_chain start them)"
    tail = max(1, min(int(tail or 15), 80))
    rows = []
    for m in sorted(f for f in os.listdir(JOBS_DIR) if f.endswith(".meta"))[-8:]:
        try:
            meta = json.loads(_read(os.path.join(JOBS_DIR, m)) or "{}")
        except ValueError:
            meta = {}
        outf = os.path.join(JOBS_DIR, m[:-5])
        out = _read(outf).splitlines()
        if meta.get("agent") == "ship-gates":   # its log is bash noise; the verdicts land in GATE-<agent>.md
            label = "RUNNING" if meta.get("pid") and _pid_running(meta["pid"]) else "DONE"
        else:
            label = _job_health(outf, meta)
        head = f"== {m[:-5]}  {label}  {meta.get('agent')}  pid {meta.get('pid')}"
        if label in JOB_FAILED:
            rec = _record_failed_job(outf, meta, label)
            rows.append(head + "\nno digest: do not summarise this as a worker result"
                        + (f" (outcome UNFIRED {rec})" if rec else "") + "\n" + "\n".join(out[-5:]))
        else:
            rows.append(head + "\n" + "\n".join(out[-tail:]))
    return _spill("\n\n".join(rows) or "no jobs yet", "jobs")


def t_bot(ctx, view="summary", n=20):
    """What the background hunt bot is doing: summary | inbox | log | brain | leads."""
    (
        INBOX, ORCH_LOG, _read, t_gnoc,
    ) = bind(
        "INBOX", "ORCH_LOG", "_read", "t_gnoc",
    )
    n = max(1, min(int(n or 20), 80))
    if view not in ("summary", "inbox", "log", "brain", "leads"):
        return f"view is summary, inbox, log, brain or leads (got {view!r})"
    if view == "inbox":
        return "\n".join(_read(INBOX).splitlines()[-n:]) or "(inbox empty)"
    if view == "log":
        return "\n".join(_read(ORCH_LOG).splitlines()[-n:]) or "(no bot log)"
    if view == "brain":
        return t_gnoc(ctx, f"orch brain why {n}")
    if view == "leads":
        return t_gnoc(ctx, "oss leads")
    return t_gnoc(ctx, "orch status") + "\n\n== last bot log ==\n" + "\n".join(_read(ORCH_LOG).splitlines()[-10:])


def bot_events_since(session):
    """New INBOX / bot-log lines since this chat last looked; advances the cursor."""
    (
        INBOX, ORCH_LOG, _read,
    ) = bind(
        "INBOX", "ORCH_LOG", "_read",
    )
    cur = session.setdefault("bot_cursor", {})
    out = []
    for key, path in (("inbox", INBOX), ("log", ORCH_LOG)):
        lines = _read(path).splitlines()
        seen = cur.get(key)
        if seen is None or seen > len(lines):  # first look, or the file was rotated
            cur[key] = len(lines)
            continue
        new = lines[seen:]
        cur[key] = len(lines)
        out += [f"[{key}] {l}" for l in new[-12:]]
    return out


def _bot_slots():
    """The GPUs a fan-out can use: the laptop worker, plus the desktop's lead model when the desktop is up
    (the lead is blocked waiting on the fan_out result anyway, so its GPU is free). Split mode is one slot pair."""
    (
        _slot_answers, dim, orange, resolve, say,
    ) = bind(
        "_slot_answers", "dim", "orange", "resolve", "say",
    )
    slots = [resolve("worker")]
    lead = resolve("lead")
    if lead[1] in ("desktop", "split") and lead not in slots:
        slots.append(lead)
    live = [s for s in slots if _slot_answers(*s)]
    if live:
        return live
    # No worker slot can answer: 2026-11-10 02:04Z the local 9B had nothing loaded and no VRAM to load into, so
    # all three fan-out bots sat on a cold model until "model error: timed out" (7 min each) and the lead was
    # blocked the whole time with the screen saying "3 bots probe ... in parallel". A fan-out onto a dead slot
    # is a silent stall; the lead's own model is a worse GPU citizen but it answers, so it takes the bots.
    say(dim("    ↳ ") + orange("✻ ") + dim("no worker slot answers a 6-token warm-up; the bots run on the lead "
                                          f"model {lead[0]}@{lead[1]} this round"))
    return [lead]


def _slot_answers(model, host, ttl=600, wait=45):
    """True when the slot produces one short completion within `wait` seconds (a cold model has to load inside
    that budget or it is not a slot for this round). Cached per (model, host) for `ttl` seconds."""
    (
        _SLOT_OK, llm_chat, time,
    ) = bind(
        "_SLOT_OK", "llm_chat", "time",
    )
    key = (model, host)
    hit = _SLOT_OK.get(key)
    if hit and time.time() - hit[1] < ttl:
        return hit[0]
    ok = False
    try:
        r = llm_chat(model, host, [{"role": "user", "content": "Reply with the single word: ready"}],
                     num_predict=8, think="low", retry=False, timeout=wait)
        ok = bool(r is not None)
    except Exception:  # noqa: BLE001 - any failure to answer is "not a slot right now"
        ok = False
    _SLOT_OK[key] = (ok, time.time())
    return ok


def _ultra_plan(model, host, msgs):
    """Ask the lead (no tools, quick) to split the request into independent sub-tasks for parallel bots.
    Returns [] when the request is not worth splitting, so a short question still gets a direct answer."""
    (
        SPIN, TOOL_LLM_TIMEOUT, effort, json, llm_chat, re,
    ) = bind(
        "SPIN", "TOOL_LLM_TIMEOUT", "effort", "json", "llm_chat", "re",
    )
    cap = effort()["fanout"]
    ask = msgs + [{"role": "user", "content":
                   f"Before answering: split my last request into at most {cap} INDEPENDENT sub-tasks that parallel "
                   "worker bots can do on their own with file reading, grep, past-hunt search and in-scope GET "
                   "probes. Each sub-task must be self-contained (full absolute paths, exact hosts, what to "
                   'report back). Reply with ONLY JSON: {"tasks": ["...", "..."]}. If the request is small, '
                   'conversational, a question you can answer from what you already know, about anything that is '
                   'not on this machine, or cannot be split, reply {"tasks": []}. Never send bots to search the '
                   'disk for a topic that has nothing to do with the files here.'}]
    SPIN.start("Planning the fan-out")
    try:
        # quick bookkeeping, not deep thought: at ultra's "high" the reasoning ate the whole budget, no JSON
        text = llm_chat(model, host, ask, num_predict=2500, think="low", timeout=TOOL_LLM_TIMEOUT)["content"]
    except Exception:
        return []
    finally:
        SPIN.stop()
    m = re.search(r"\{.*\}", text or "", re.S)
    try:
        tasks = json.loads(m.group(0)).get("tasks") if m else []
    except ValueError:
        return []
    tasks = [str(t) for t in (tasks or []) if str(t).strip()][:cap]
    return tasks if len(tasks) >= 2 else []


def _oversized_file_in(tasks):
    """(path, size) of the first file a brief names that a worker cannot ingest, else None.

    2026-11-10 03:35Z program-50: the lead delegated "read raw/022350524378-get.json and extract the routes"
    to the local 9B worker. The file is a 1.5 MB minified-bundle capture; the worker timed out after 420 s
    and the lead sat blocked the whole time (T-255: a small local worker is an executor, not a reader). A
    brief naming a file above DELEGATE_FILE_CAP is refused up front with the two tools that do the job."""
    (
        DELEGATE_FILE_CAP, WS, os, re,
    ) = bind(
        "DELEGATE_FILE_CAP", "WS", "os", "re",
    )
    for t in tasks:
        for tok in re.findall(r"(?<![\w-])(?:/|\.{0,2}/|targets/|hunts/|raw/)[\w./-]+", str(t or "")):
            tok = tok.rstrip(".,;:)")
            cands = [tok]
            if not os.path.isabs(tok):
                cands.append(os.path.join(WS, tok))
            for p in cands:
                try:
                    if os.path.isfile(p):
                        size = os.path.getsize(p)
                        if size > DELEGATE_FILE_CAP:
                            return p, size
                        break
                except OSError:
                    continue
    return None


def _oversized_note(hit):
    p, size = hit
    return (f"refused: {p} is {size // 1024} KB; a worker cannot ingest a file that large (the last such "
            f"delegate timed out after 420 s with nothing back). For a JS bundle call js_mine yourself on the "
            f"in-scope PAGE URL that loads it (it mines the routes and feeds known-paths); for a capture use "
            f"grep(pattern=, path=, around=) for a byte window or read_file with offset and limit; then "
            f"delegate the SMALL extract, not the file.")


def _placeholder_in(tasks):
    """An unsubstituted <placeholder> handed to a bot is always a bug: every bot then works a path that
    cannot exist (measured 2026-10-22: 6 bots sent to targets/<program>/SCOPE.txt, 6 failures)."""
    (
        re,
    ) = bind(
        "re",
    )
    for t in tasks or []:
        m = re.search(r"<[a-z][a-z0-9_ -]{2,20}>", str(t), re.I)
        if m:
            return m.group(0)
    return None


def _lead_tool_in(tasks):
    """A brief that names a LEAD-only tool sends the worker hunting the DISK for it: it grepped for fan_out and
    read invented paths like ./model/fan_out.py until its budget ran out (the user's meta session 2026-10-22)."""
    # Only names that cannot be ordinary words or path segments, and never one INSIDE a path: the brief
    # "read targets/program-64/hunts/gnoc/ledger.json" is legitimate and must not be refused.
    (
        TOOLS, WORKER_TOOLS, re,
    ) = bind(
        "TOOLS", "WORKER_TOOLS", "re",
    )
    names = sorted((set(n for n in TOOLS if "_" in n) | {"delegate"}) - set(WORKER_TOOLS))
    pat = re.compile(r"(?<![\w/.-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w/.-])")
    for t in tasks or []:
        m = pat.search(str(t))
        if m:
            return m.group(1)
    return None


def t_fan_out(ctx, tasks):
    """Run several independent sub-tasks as parallel worker bots across both GPUs; returns every digest."""
    (
        WS, _fan_out_run, _lead_tool_in, _oversized_file_in, _oversized_note,
        _placeholder_in, os,
    ) = bind(
        "WS", "_fan_out_run", "_lead_tool_in", "_oversized_file_in", "_oversized_note",
        "_placeholder_in", "os",
    )
    if isinstance(tasks, str):
        tasks = [t.strip() for t in tasks.split("\n") if t.strip()]
    tasks = [str(t) for t in (tasks or []) if str(t).strip()]
    if not tasks:
        return "refused: fan_out needs a list of sub-tasks"
    bad = _lead_tool_in(tasks)
    if bad:
        return (f"refused: the brief names {bad}, which is one of YOUR tools, not the worker's. A worker has "
                "read_file, list_dir, grep, hunt_search, dedup, hunt_brief, hunt_chains, playbook and the probe "
                f"tools. Say what to READ or PROBE and what to report back, or call {bad} yourself.")
    ph = _placeholder_in(tasks)
    if ph:
        where = os.path.join(WS, "targets", ctx.program) if ctx.program else "(no program set)"
        return (f"refused: a task still carries the placeholder {ph}. Substitute the real value first - "
                f"every bot would work a path that cannot exist. The program's directory is {where}.")
    big = _oversized_file_in(tasks)
    if big:
        return _oversized_note(big)
    seq = _sequential_steps(tasks)
    if seq:
        return (f"refused: these are steps of one plan, not independent tasks - step {seq} needs what an earlier "
                "step produces, and parallel bots all start at once with nothing. Do step 1 yourself now; fan out "
                "only work that needs nothing from another task (e.g. one probe per host from a list you hold).")
    return _fan_out_run(ctx, tasks)


def _sequential_steps(tasks):
    """The number of the first numbered task that consumes an earlier task's output, or 0. Massive hunt 2026-11-25:
    "1. pull CT  2. diff it  3. GET each new host  ..." went to 6 bots at once; bot 3 had no hosts, bots 4-5 hit
    their caps with no probe fired, and the turn ended on a context overflow."""
    (
        re,
    ) = bind(
        "re",
    )
    nums = [re.match(r"\s*(?:step\s*)?(\d+)[.):]\s", str(t), re.I) for t in tasks]
    if len(tasks) < 2 or not all(nums) or [int(m.group(1)) for m in nums] != list(range(1, len(tasks) + 1)):
        return 0
    dep = re.compile(r"(?i)\b(?:diff|the (?:results?|output|names|hosts|data|list)|from step|previous|above|"
                     r"resolve them|each new|the new|the best|most interesting|non-envoy|then)\b")
    for i, t in enumerate(tasks[1:], start=2):
        if dep.search(str(t)):
            return i
    return 0


def _bot_probed(digest):
    """True when a bot's digest reports at least one probe (PROBES: n with n > 0). D87 (drive cycle 24, 2026-10-26
    10:35Z): the local 9B bots hit their turn cap without firing in every round and were respawned every time (4 of 9
    dispatches); the respawn ran the same brief into the same refusals. A bot that never probed has nothing to retry."""
    (
        re,
    ) = bind(
        "re",
    )
    m = re.search(r"PROBES:\s*(\d+)", str(digest or ""))
    return bool(m) and int(m.group(1)) > 0


def _fan_out_run(ctx, tasks):
    """The fan-out proper, past the model-typo checks. _probe_round calls this directly: its briefs are written by the
    harness (gnoc_hunt.probe_briefs), and on 2026-10-26 (drive cycles 13-16, D41) a tell naming "delegate" and the
    template word "<the seam>" made t_fan_out refuse every round, so the lead hunted alone for hours while the
    screen said "fan-out: 3 bots probe ... in parallel"."""
    (
        _bot_probed, _bot_slots, _parallel, dim, effort, orange, run_worker, say,
    ) = bind(
        "_bot_probed", "_bot_slots", "_parallel", "dim", "effort", "orange", "run_worker",
        "say",
    )
    cap = effort()["fanout"]
    dropped = tasks[cap:]
    tasks = tasks[:cap]
    slots = _bot_slots()
    say(dim("    ↳ ") + orange("✻ ") + dim(f"fanning out {len(tasks)} bot(s) over {len(slots)} GPU(s): "
                                          + ", ".join(f"{m}@{h}" for m, h in slots)))
    jobs = [(i, t, slots[i % len(slots)]) for i, t in enumerate(tasks)]
    # one bot per slot at a time per GPU would serialize anyway inside Ollama; let each GPU run two.
    # Daemon threads via _parallel (not a ThreadPoolExecutor) so a Ctrl-C with several bots running
    # returns control to GreyNOC at once instead of waiting for every bot's LLM call to finish.
    funcs = [(lambda t=t, m=m, h=h, i=i: run_worker(ctx, t, m, h, f"bot {i + 1}")) for i, t, (m, h) in jobs]
    got = _parallel(funcs, max_workers=min(len(jobs), 2 * len(slots)))
    results = {}
    for (i, t, (m, h)), r in zip(jobs, got):
        results[i] = (f"bot failed: {r}" if isinstance(r, BaseException)
                      else (r if r is not None else "bot did not finish (interrupted)"))
    # ORACLE: a lane that hit its cap with no anomaly carries a RESPAWN BRIEF; re-dispatch it FRESH, once
    again = [(i, "[respawn 1] " + results[i][results[i].index("RESPAWN BRIEF"):], s) for i, t, s in jobs
             if "RESPAWN BRIEF" in results[i] and "[respawn 1]" not in t and _bot_probed(results[i])]
    for i, t, (m, h) in jobs:   # D87: say why a capped bot is NOT re-dispatched
        if "RESPAWN BRIEF" in results[i] and "[respawn 1]" not in t and not _bot_probed(results[i]):
            say(dim("    ↳ ") + orange("✻ ") + dim(f"bot {i + 1} hit its cap having fired no probe; not respawned "
                                                  "(a fresh run of the same brief repeats it)"))
    if again:
        got = _parallel([(lambda t=t, m=m, h=h, i=i: run_worker(ctx, t, m, h, f"bot {i + 1}r"))
                         for i, t, (m, h) in again], max_workers=min(len(again), 2 * len(slots)))
        for (i, t, _), r in zip(again, got):  # ORACLE
            results[i] += f"\n\n== [respawn 1] bot {i + 1}r:\n" + (f"bot failed: {r}" if isinstance(r, BaseException)
                                                                   else r or "bot did not finish (interrupted)")
    return ("\n\n".join(f"== bot {i + 1} ({m}@{h}): {t[:120]}\n{results[i]}" for i, t, (m, h) in jobs)
            + (f"\n\nNOT RUN ({len(dropped)} task(s) over the /reasoning width of {cap}): "
               + " | ".join(t[:80] for t in dropped) + " - fan_out them in a second call" if dropped else ""))


def _team_members(brief, members):
    """(ok, jobs) where jobs = [(role, task)] - the validation half of t_team, split out so tests can drive it
    without GPUs. members: a list of dicts {role, task} or strings 'role: task'; when omitted the roles are
    picked from the brief (design words -> designer+frontend+reviewer, security -> security+reviewer, else
    architect+reviewer). Returns (False, err) on any bad input, before a single bot starts."""
    (
        TEAM_ROLES, re,
    ) = bind(
        "TEAM_ROLES", "re",
    )
    brief = " ".join(str(brief or "").split())
    if len(brief) < 15:
        return False, "team needs brief=<what the team should analyse or design, with real paths>"
    rows = []
    if members is None:
        low = brief.lower()
        if re.search(r"\b(design|layout|css|landing|home ?page|ui|ux|redesign|style)\b", low):
            roles = ["designer", "frontend", "reviewer"]
        elif re.search(r"\b(secur|vuln|exploit|injection|auth\w*)\b", low):
            roles = ["security", "reviewer"]
        elif re.search(r"\b(test|break|qa|coverage)\b", low):
            roles = ["tester", "reviewer"]
        else:
            roles = ["architect", "reviewer"]
        rows = [(r, "") for r in roles]
    elif isinstance(members, str):
        parts = re.split(r"[,;\n]", members)
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if ":" in p:
                role, task = p.split(":", 1)
            else:
                role, task = p, ""
            rows.append((role.strip().lower(), task.strip()))
    else:
        for m in members:
            if isinstance(m, str):
                if ":" in m:
                    role, task = m.split(":", 1)
                else:
                    role, task = m, ""
                rows.append((role.strip().lower(), task.strip()))
            elif isinstance(m, dict):
                role = str(m.get("role") or "").strip().lower()
                task = str(m.get("task") or "").strip()
                rows.append((role, task))
            else:
                return False, f"member {m!r} is not a role string or a dict with role/task"
    rows = [r for r in rows if r[0]]
    if not rows:
        return False, "team needs at least one member, e.g. members=[reviewer, tester]"
    bad = [r for r, _ in rows if r not in TEAM_ROLES]
    if bad:
        return False, f"unknown team role(s) {', '.join(bad)}; roles: {', '.join(sorted(TEAM_ROLES))}"
    seen, jobs = set(), []
    for role, task in rows:
        if role in seen:
            continue  # one specialist per team; duplicates waste a slot
        seen.add(role)
        jobs.append((role, task))
    return True, jobs


def t_team(ctx, brief, members=None):
    """SENIOR-DEV TEAM LEAD: run a small team of specialist bots in parallel over both GPUs and merge their
    digests. Members are read-only analysts (the lead still edits): architect, backend, frontend, designer,
    reviewer, tester, security, researcher, docs. members=["designer: critique the landing page", "reviewer"]
    or [{"role": "tester", "task": "which suites cover server.js"}]; omitted = picked from the brief.
    Cap is the /reasoning fan-out width."""
    (
        TEAM_ROLES, TEAM_SYSTEM, _bot_slots, _parallel, _short_model, _team_members,
        dim, effort, orange, root, run_worker, say,
    ) = bind(
        "TEAM_ROLES", "TEAM_SYSTEM", "_bot_slots", "_parallel", "_short_model",
        "_team_members", "dim", "effort", "orange", "root", "run_worker", "say",
    )
    ok, jobs = _team_members(brief, members)
    if not ok:
        return f"bad arguments: {jobs}"
    brief = " ".join(str(brief).split())
    cap = effort()["fanout"]
    jobs = jobs[:cap]
    slots = _bot_slots()
    say(dim("    ↳ ") + orange("✻ ") + dim(f"team of {len(jobs)} bot(s) over {len(slots)} GPU(s): "
                                          + ", ".join(r for r, _ in jobs)))
    repo = root()
    runs = [(i, role, task, slots[i % len(slots)]) for i, (role, task) in enumerate(jobs)]
    funcs = []
    for i, role, task, (m, h) in runs:
        scope = TEAM_ROLES[role]
        text = (f"TEAM BRIEF (from the lead):\n{brief}\n\nYOUR ROLE: {role} - {scope}."
                + (f"\nYOUR SPECIFIC TASK: {task}" if task else "") + "\n\nWork the brief in your role, in the "
                "repo shown in your system prompt. Analyse with your tools, then report the senior-level digest.")
        system = TEAM_SYSTEM.format(role=role, repo=repo)
        funcs.append((lambda t=text, m=m, h=h, r=role, i=i, s=system:
                      run_worker(ctx, t, m, h, f"team {r}", system=s)))
    got = _parallel(funcs, max_workers=min(len(funcs), 2 * len(slots)))
    out = [f"TEAM OF {len(jobs)} on: {brief[:140]}"]
    for (i, role, task, (m, h)), r in zip(runs, got):
        res = (f"bot failed: {r}" if isinstance(r, BaseException)
               else (r or "bot did not finish (interrupted)"))
        out.append(f"\n== {role} ({_short_model(m)}@{h}): {task or 'the brief'}\n{res}")
    out.append("\nYou are the lead: decide, then implement with your own tools.")
    return "\n".join(out)


def _delegate_items(task, tasks, isolated):
    """[(text, isolated, tokens, seconds)] from delegate's arguments, or a refusal string. tasks takes strings or
    {task, isolated, tokens, seconds} dicts (a JSON-encoded list from a small model is decoded first)."""
    import json
    items = []
    if isinstance(tasks, str):
        try:
            tasks = json.loads(tasks)
        except ValueError:
            tasks = [t.strip() for t in tasks.split("\n") if t.strip()]
    if tasks is not None and not isinstance(tasks, (list, tuple)):
        return "bad arguments: tasks is a list of self-contained jobs (strings, or {task, isolated} objects)"
    for t in ([task] if str(task or "").strip() else []) + list(tasks or []):
        if isinstance(t, dict):
            items.append((str(t.get("task") or "").strip(), bool(t.get("isolated", isolated)),
                          t.get("tokens"), t.get("seconds")))
        else:
            items.append((str(t or "").strip(), bool(isolated), None, None))
    return items


def t_delegate(ctx, task="", worker_note="", isolated=False, tasks=None):
    """One child (task=...) or several (tasks=[...]) through the shared child pool (gnoc_subagents.POOL)."""
    (
        INTERRUPT, TOOLS, _cancelled, _lead_tool_in, _oversized_file_in, _oversized_note, _parallel, _placeholder_in,
        run_worker, run_builder,
    ) = bind(
        "INTERRUPT", "TOOLS", "_cancelled", "_lead_tool_in", "_oversized_file_in", "_oversized_note", "_parallel",
        "_placeholder_in", "run_worker", "run_builder",
    )
    import gnoc_subagents as SA
    s = ctx.s if isinstance(getattr(ctx, "s", None), dict) else {}
    if s.get("_worker"):
        # dispatch refuses this first for any worker; this is the same rule for a direct caller (a builder used to
        # be the only kind of child checked here)
        return SA.child_refusal("delegate")
    multi = tasks is not None
    items = _delegate_items(task, tasks, isolated)
    if isinstance(items, str):
        return items
    if not items:
        return ("bad arguments: delegate needs task=<a self-contained job: real paths/hosts and what to report "
                "back>, or tasks=[...] for several jobs that run at once")
    if s.get("_walls"):
        # `pip install mypy && mypy ...` waited on approval twice; the lead then delegated "mypy inventory/ tests/"
        # to a worker, which cannot run it either and spent its whole time limit elsewhere (tool drive 2026-11-21)
        return ("not run: an action in this turn is waiting for the user's approval, and a worker cannot do it for "
                "you (workers read and probe; they do not install or run what was held). Delegating changes "
                "nothing. Answer now: what you found, and the exact action that is waiting for approval.")
    # every task is checked before ANY child starts: a bad fourth task must not leave three children running
    for n, (text, iso, _t, _sec) in enumerate(items, 1):
        where = f"task {n}: " if len(items) > 1 else ""
        if len(text) < 15:
            return (f"bad arguments: {where}delegate needs task=<a self-contained job: real paths/hosts and what "
                    "to report back>")
        if iso:
            continue
        bad = _lead_tool_in([text])
        if bad:
            return (f"refused: {where}the brief names {bad}, which is one of YOUR tools, not the worker's. A worker "
                    "has read_file, list_dir, grep, hunt_search, dedup, hunt_brief, hunt_chains, playbook and the GET "
                    f"probe tools. Say what to READ or PROBE and what to report back, or call {bad} yourself.")
        ph = _placeholder_in([text])
        if ph:  # same failure as fan_out: a worker cannot resolve <program> or <path> on its own
            return f"refused: {where}the task still carries the placeholder {ph}; substitute the real value first"
        big = _oversized_file_in([text])
        if big:
            return _oversized_note(big)
    tok_ceiling = SA.child_token_budget()

    def stop():
        return INTERRUPT.is_set() or _cancelled()

    # the read-only default toolset, from the tools this edition actually has (gnoc_subagents.CHILD_READ_TOOLS)
    child_tools = tuple(n for n in SA.CHILD_READ_TOOLS if n in TOOLS)

    def one(text, iso, tokens, seconds, legacy):
        """Run one child inside a pool slot: (raw result, requests, usage, builder out {files, patch}, cancelled)."""
        requests, usage, out = [], {"tokens": 0}, {}
        extra = {"_child": True, "_child_requests": requests, "_child_usage": usage,
                 "_child_budget": SA.clamp_budget(tokens, tok_ceiling, SA.MIN_CHILD_TOKENS)}
        with SA.POOL.slot(stop) as got:
            if not got:   # queued, and Ctrl-C (or a cancelled parent) came first: it never started
                return None, requests, usage, out, True
            if iso:
                res = run_builder(ctx, text + ("" if legacy else SA.SUMMARY_NOTE), extra=extra, out=out,
                                  wall=SA.clamp_budget(seconds, SA.child_seconds(BUILDER_WALL_S), 20))
            elif legacy:   # delegate(task=...): the digest reads as before; the toolset is the read-only one now
                res = run_worker(ctx, text, tool_names=child_tools, extra=extra)
            else:
                wall = SA.clamp_budget(seconds, SA.child_seconds(int(os.environ.get("GNOC_WORKER_WALL") or 210)),
                                       20)
                res = run_worker(ctx, text + SA.SUMMARY_NOTE, tag="child", tool_names=child_tools, extra=extra,
                                 wall=wall)
            return res, requests, usage, out, stop()

    if not multi:
        text, iso, tokens, seconds = items[0]
        res, requests, _usage, _files, _stopped = one(text, iso, tokens, seconds, legacy=True)
        if res is None:
            return "delegate did not run: cancelled while waiting for a child slot (Ctrl-C)"
        res = res if isinstance(res, str) else str(res)
        if requests:   # appended only when there is something to hand up, so a plain digest reads exactly as before
            res += ("\n\nHELD FOR APPROVAL (the worker could not approve; run it yourself if it is right, which "
                    "asks the user):\n" + "\n".join(f"- {r}" for r in requests))
        return res
    got = _parallel([(lambda it=it: one(*it, legacy=False)) for it in items], max_workers=len(items))
    rows = []
    for (text, _iso, _t, _sec), r in zip(items, got):
        if isinstance(r, BaseException):
            rows.append((text, SA.summary(f"worker failed: {type(r).__name__}: {r}", status="failed")))
        elif r is None:   # its slot never finished: abandoned by an interrupt
            rows.append((text, SA.summary(None, status="cancelled")))
        else:
            res, requests, usage, out, cancelled = r
            # a builder's patch is never applied for the lead: its path goes in the evidence, applying it is the
            # lead's own (approved) apply_patch call
            ev = ([f"patch (NOT applied): {out['patch']}; apply_patch patch_file=<that path> after review"]
                  if out.get("patch") else [])
            rows.append((text, SA.summary(res, requests=requests, tokens=usage.get("tokens", 0),
                                          status="cancelled" if cancelled or res is None else None,
                                          files=out.get("files") or [], evidence=ev)))
    return SA.render(rows)


def t_second_opinion(ctx, question, context=""):
    (
        TOOL_LLM_TIMEOUT, llm_chat, resolve,
    ) = bind(
        "TOOL_LLM_TIMEOUT", "llm_chat", "resolve",
    )
    question, context = str(question or "").strip(), str(context or "")
    if not question:
        return "bad arguments: second_opinion needs question=<what you want judged>"
    model, host = resolve("worker")
    msgs = [{"role": "system", "content": "You are a senior bug-bounty reviewer giving an independent second "
                                          "opinion. Be concrete and skeptical; say what you would check."},
            {"role": "user", "content": f"{question}\n\nCONTEXT:\n{context[:12000]}"
                                        + ("\n[context cut at 12000 chars]" if len(context) > 12000 else "")}]
    try:
        return llm_chat(model, host, msgs, num_predict=900,
                        timeout=TOOL_LLM_TIMEOUT)["content"] or "(empty answer)"
    except Exception as e:
        return f"worker unavailable: {e}"


def t_econ_status(ctx, bot=None):  # ECON: read-only view of the proof market
    import gnoc_economy as ECON
    if bot and bot not in ECON.participants():
        # launch #19 asked econ_status(bot='program-101') and read "program-101: 0 RC" as the hunt's wallet
        return (f"no bot named {bot!r}; bots are {', '.join(ECON.participants())}. The acting bot is "
                f"{ECON.current_bot('lead')} ({ECON.balance(ECON.current_bot('lead'))} RC).")
    return ECON.status_text() if not bot else f"{bot}: {ECON.balance(bot)} RC, brier {ECON.brier(bot)}"


def t_office_funnel(ctx):
    """Today's hunt pipeline, probes through to FILED, from the office's own collectors.

    Asked "what does the office funnel tell you about where work is stuck today", the agent had no tool for
    it and answered from oss-bot lead rows, which are a different pipeline entirely (soak batch8 2026-10-25).
    The office computes these stages in gnoc-office.funnel_of; this reads the same function headless rather
    than recounting, so the two can never drift apart."""
    (
        WS, _run_group, gnoc_secrets, json, os, subprocess, sys,
    ) = bind(
        "WS", "_run_group", "gnoc_secrets", "json", "os", "subprocess", "sys",
    )
    try:
        r = _run_group([sys.executable, os.path.join(WS, "scripts/gnoc-office.py"), "--funnel-json"],
                       capture_output=True, text=True, timeout=180, cwd=WS,
                       stdin=subprocess.DEVNULL, env=gnoc_secrets.child_env({"GNOC_PLAIN": "1"}))  # T1.7
    except subprocess.TimeoutExpired:
        return "the office funnel collectors did not finish in 180 s"
    if r.returncode != 0:
        return f"could not read the office funnel: {(r.stderr or r.stdout or '').strip()[:300]}"
    try:
        d = json.loads(r.stdout)
    except ValueError:
        return f"the office funnel returned something that is not JSON: {r.stdout.strip()[:300]}"
    lines = [f"OFFICE FUNNEL for {d.get('day')} - today's hunt pipeline, probes through to FILED.",
             "This is not the oss-bot lead list and not the lead lab queue.", ""]
    for st in d.get("stages") or []:
        lines.append(f"  {st['stage']:<10} {st['n']:>6}   {st['counts']}")
    b = d.get("bottleneck")
    lines.append("")
    lines.append(f"bottleneck: {b} - the first stage that got nothing although the stage before it did."
                 if b else "no stall: every stage that could advance work did.")
    if d.get("errors"):
        lines.append(f"collectors that failed: {', '.join(d['errors'])}")
    return "\n".join(lines)


def t_lessons(ctx, query="", n=10, retire=None, why=""):
    """Read the lesson book. `learn` only WRITES one, which left no way to answer "what have you learned".

    Soak batch11 2026-10-25: asked to read the lesson book, the agent called learn(action='list') and
    then learn(text='list'). The second would have WRITTEN a lesson whose whole content was the word
    "list"; only the 12-character minimum refused it.

    retire=L# moves one lesson to the retired book with a reason. Without it the book only ever grew: 155 of
    its 200 rows were reflection-written, and the noise (notes about our own repo files and tools) was recalled
    into every prompt with the same weight as a receipt."""
    (
        gnoc_learn, re,
    ) = bind(
        "gnoc_learn", "re",
    )
    rows = gnoc_learn.load()
    if retire:
        lid = str(retire).strip()
        if not re.fullmatch(r"L\d+", lid):
            return f"bad arguments: retire takes a lesson id like L123 (got {lid!r})"
        if len(str(why or "").strip()) < 12:
            return "bad arguments: retire needs why=<what is wrong with it>, so the retirement is reviewable"
        if not gnoc_learn.retire(lid, str(why).strip()):
            return f"no live lesson {lid}"
        return f"retired {lid} ({str(why).strip()[:120]}); it stays in the retired book for audit"
    if not rows:
        return "the lesson book is empty"
    live = [r for r in rows if not r.get("retired")]
    q = str(query or "").strip()
    if q:
        picked = gnoc_learn.recall(q, ctx.program, k=max(1, int(n or 10)), mark_used=False)
        head = f"{len(picked)} lesson(s) matching {q!r}, most relevant first"
    else:
        # the row's field is "created", not "ts": sorting on a key no row has made "newest first" a
        # label that only held by accident of file order (found reading batch12 output, 2026-10-25)
        picked = sorted(live, key=lambda r: str(r.get("created") or ""), reverse=True)[:max(1, int(n or 10))]
        head = f"the {len(picked)} most recent of {len(live)} live lessons, newest first"
    out = [head, ""]
    for r in picked:
        when = str(r.get("created") or "")[:10]
        scope = r.get("program") or "*"
        out.append(f"  [{r.get('id')}] {r.get('kind', 'rule')} {scope} {when}  used {r.get('uses', 0)}x")
        out.append(f"      {r.get('text', '')}")
        if r.get("why"):
            out.append(f"      why: {r['why']}")
    return "\n".join(out)


def t_econ_bet(ctx, program, id, side, stake):  # ECON: the acting bot stakes; it can never settle
    import gnoc_economy as ECON
    bot = ECON.current_bot("lead")
    if str(side).lower() in ECON.FILING_SIDES:
        return ECON.filing_market("bet", program, id, bot=bot, side=side, stake=stake)
    return ECON.bet(program, id, bot, side, stake)


def t_econ_bounty(ctx, action="list", program=None, crown=None, amount=0, id=None):  # ECON: post/claim/list
    import gnoc_economy as ECON
    if action not in ("list", "post", "claim"):
        return "refused: a bounty settles only on an oracle PASS or a READY draft, never from chat"
    if action == "list":
        return "\n".join(f"{b['id']} {b.get('program')} {b.get('crown')} {b.get('amount')} RC {b['state']}"
                         for b in ECON.bounty("list").values()) or "no bounties"
    return ECON.bounty(action, program=program or ctx.program, crown=crown, amount=amount, id=id,
                       bot=ECON.current_bot("lead"), poster=ECON.current_bot("lead"))  # ECON: poster's own wallet


def _gpu1_async(text):
    """A '/gpu1 ...' line typed mid-turn: fire the worker model on the second GPU now, in the background, and
    print its answer when it lands. Like /btw it never waits for the next turn, but it bypasses the lead
    entirely instead of feeding the running turn - the lead keeps thinking on its own GPU."""
    (
        T, _gpu1_worker, dim, say, threading, white,
    ) = bind(
        "T", "_gpu1_worker", "dim", "say", "threading", "white",
    )
    text = str(text or "").strip()
    if not text:
        return
    say("\n" + T.byellow("  gpu1: ") + white(text[:160]) + dim("  (straight to the worker GPU; the lead keeps working)"))

    def _run():
        label, out = _gpu1_worker(text)
        say(dim(f"  ● {label}") + dim("  (gpu1)"))
        say(out)

    threading.Thread(target=_run, daemon=True, name="gnoc-gpu1").start()


def _gpu1_worker(rest):
    """Send `rest` straight to the worker model on the second GPU. Returns (label, answer) and never raises:
    a worker that is down must not kill the REPL or the thread that called this. Shared by the /gpu1 command
    (at the prompt) and _gpu1_async (typed mid-turn)."""
    (
        GPU1_SYSTEM, TOOL_LLM_TIMEOUT, llm_chat, resolve,
    ) = bind(
        "GPU1_SYSTEM", "TOOL_LLM_TIMEOUT", "llm_chat", "resolve",
    )
    wmodel, whost = resolve("worker")
    try:
        thought = []
        out = (llm_chat(wmodel, whost,
                        [{"role": "system", "content": GPU1_SYSTEM}, {"role": "user", "content": rest}],
                        num_predict=1200, think=False, timeout=TOOL_LLM_TIMEOUT,  # must answer, not just think
                        on_think=lambda d: thought.append(d)) or {})
        out = (out.get("content") or "").strip() or ("".join(thought).strip())
    except Exception as e:
        out = f"(worker call failed: {type(e).__name__}: {e})"
    return f"{wmodel.split('/')[-1]}@{whost}", (out.strip() or "(the worker returned nothing)")


BUILDER_TOOLS = ("read_file", "list_dir", "grep", "find_file", "find_symbol", "repo_map", "edit_file", "write_file",
                 "apply_patch", "run_tests", "lint", "typecheck")


BUILDER_WALL_S = int(os.environ.get("GNOC_BUILDER_WALL") or 900)


BUILDER_SYSTEM = """You are a BUILDER bot. You work in a private git worktree at {wt}: a copy of the repo {repo} as
it is right now (committed files plus uncommitted changes to tracked files; files that were never added to git
are NOT in this copy). Nothing you do here touches the original checkout. Every path you use is relative to the
worktree.

Do the job in the brief: read the code you change and its callers first, make the smallest correct change with
edit_file / write_file / apply_patch, then VERIFY it with run_tests on the tests that cover it (and typecheck or
lint where the repo uses them), and fix what fails. You cannot run shell commands.

Finish with a short digest: the files you changed and why, the exact test / type-check result, and anything left
undone. The lead reviews your change as a patch and decides whether to apply it."""


def run_builder(ctx, task, extra=None, wall=None, out=None):
    """delegate isolated=true: a worker with write and test tools, confined to its own git worktree. Returns its
    digest and the patch file the lead can apply with apply_patch patch_file=<path>."""
    (
        BUILDER_SYSTEM, BUILDER_TOOLS, BUILDER_WALL_S, STATE, _now, _rel_home, contextlib, gnoc_worktree, os, root,
        run_worker,
    ) = bind(
        "BUILDER_SYSTEM", "BUILDER_TOOLS", "BUILDER_WALL_S", "STATE", "_now", "_rel_home", "contextlib",
        "gnoc_worktree", "os", "root", "run_worker",
    )
    repo = root()
    try:
        wt, base = gnoc_worktree.create(repo)
    except Exception as e:  # noqa: BLE001
        return f"refused: {e}"
    try:
        # the child extras (phase 4: requests, token tally) ride along; the worktree override is always the builder's
        res = run_worker(ctx, task, tag="builder", system=BUILDER_SYSTEM.format(wt=wt, repo=_rel_home(repo)),
                         tool_names=BUILDER_TOOLS, extra=dict(extra or {}, _root_override=wt),
                         wall=wall or BUILDER_WALL_S)
        patch = gnoc_worktree.diff(wt, base)
        files = gnoc_worktree.changed_files(wt, base)
        if isinstance(out, dict):   # "M\ta.py" rows -> paths, for the structured summary
            out["files"] = [ln.split("\t")[-1] for ln in str(files or "").splitlines() if ln.strip()]
    finally:
        with contextlib.suppress(Exception):
            gnoc_worktree.remove(wt)
    if not patch.strip():
        return f"BUILDER DIGEST:\n{res}\n\nThe builder changed no files; nothing to apply."
    os.makedirs(STATE.out_dir, exist_ok=True)
    pf = os.path.join(STATE.out_dir, f"{_now():%Y%m%d-%H%M%S-%f}-builder-{os.getpid()}.patch")
    with open(pf, "w") as f:
        f.write(patch)
    if isinstance(out, dict):
        out["patch"] = pf
    return (f"BUILDER DIGEST:\n{res}\n\nCHANGED (relative to your checkout when it started):\n{files}\n\n"
            f"The change is NOT applied. Patch: {pf} ({len(patch.splitlines())} lines). Review it (read_file), "
            "then apply it with apply_patch patch_file=<that path>, or leave it.")


def run_worker(ctx, task, model=None, host=None, tag="worker", system=None, tool_names=None, extra=None, wall=None):
    (
        Ctx, MON, _run_worker, resolve, taint,
    ) = bind(
        "Ctx", "MON", "_run_worker", "resolve", "taint",
    )
    if not model:
        model, host = resolve("worker")
    sid = MON.start(tag.replace(" ", ""), model, host, task)
    MON.bind(sid)
    status, res = "failed", ""
    # Each bot gets its own view of the session: settings and program are shared (shallow copy), but the taint
    # list and the repeat breaker are per bot. With one shared dict, one bot's web_fetch tainted the session and
    # every other bot's plain GET was then auto-declined as "GreyNOC declined this action"; parallel bots also
    # trimmed one shared _calls dict and raised KeyError. Any taint a bot picks up is handed UP to the lead's
    # session when it finishes, so the lead's own unattended actions stay gated.
    wctx = Ctx(dict(ctx.s))
    wctx.s.pop("_tainted", None)
    # QAQC 2026-11-19: the shallow copy shared the lead's per-turn rail dicts, so six fan-out bots' probes ran
    # up the LEAD's volume cap (its next http_request was switched off) and four bots reading one path tripped
    # the near-repeat breaker for each other, from several threads at once. Every bot starts its own.
    for k in ("_turn_off", "_refusals", "_turn_calls", "_near", "_near_hist", "_osc_told", "_verdict_tries",
              "_turn_allowed", "_ghost", "_lead_thin", "_failed_tests"):
        wctx.s.pop(k, None)
    wctx.s["_seen_files"] = dict(ctx.s.get("_seen_files") or {})
    wctx.s["_calls"] = {}
    wctx.s["_worker"] = True              # F5: a bot's probes are not the lead probing hands-on
    wctx.s["_lead_probes"] = {}           # and the shallow copy must not share the lead's counters
    wctx.s["_add_refusals"] = {}
    wctx.s["_program_fence"] = ctx.program   # a worker reads its own program's material, not every program's
    wctx.s.update(extra or {})
    if wctx.s.get("_child"):
        # A delegated child never inherits the lead's /auto: that grant was the user's answer to the LEAD's
        # questions. What a child needs approved comes back to the lead as a request (phase 4).
        wctx.s.pop("auto", None)
    usage = wctx.s.get("_child_usage")
    import contextlib as _cl
    from gnoc_core import receipts
    actor_tok = receipts.ACTOR.set(str(tag))   # RECEIPTS: this bot's captures are listed under its own tag
    try:
        # the child's own token tally: every model call it makes (and every call its tools make) is booked on it
        # by MON.record, the same numbers the turn's footer adds up, so its tokens are charged to the turn too
        with (MON.tally(usage) if isinstance(usage, dict) else _cl.nullcontext()):
            res = _run_worker(wctx, task, model, host, tag, sid, system=system, tool_names=tool_names, wall=wall)
        status = "failed" if res.startswith("worker failed") else "done"
        return res
    except KeyboardInterrupt:
        status = "interrupted"
        raise
    finally:
        receipts.ACTOR.reset(actor_tok)
        for src in wctx.s.get("_tainted") or []:
            taint(ctx, src)
        MON.finish(sid, status, res[:300] if isinstance(res, str) else "")
        MON.unbind()


def _run_worker(ctx, task, model, host, tag, sid, system=None, tool_names=None, wall=None):  # ECON: the slot's model pays
    (
        _run_worker_body, contextlib,
    ) = bind(
        "_run_worker_body", "contextlib",
    )
    try:
        import gnoc_economy
        bot = gnoc_economy.bot_for_model(model, host)
        scope = gnoc_economy.acting_as(bot)
    except Exception:  # noqa: BLE001 - no economy: run the worker unbooked
        scope = contextlib.nullcontext()
    with scope:
        return _run_worker_body(ctx, task, model, host, tag, sid, system=system, tool_names=tool_names, wall=wall)


def _book_estimate(mon, model, host, msgs, m):
    """A child's model call that reported no usage (a server without a usage block, a stub): book chars/4 on the
    child's tally and the turn's, as calls=0 so the call itself is not counted twice."""
    import json as _json
    from gnoc_core.llmwire import _approx_tokens
    try:
        reply = str((m or {}).get("content") or "") + _json.dumps((m or {}).get("tool_calls") or [], default=str)
    except (TypeError, ValueError):
        reply = str((m or {}).get("content") or "")
    mon.record(model, host, _approx_tokens(msgs), len(reply) // 4, 0, calls=0)


PROBE_TOOLS = frozenset({"http_request", "graphql", "probe_matrix", "race", "sweep", "browser"})


READ_STEPS_BEFORE_PROBE = 4   # D53: tool steps a probe bot may spend reading before it is told to fire


def _run_worker_body(ctx, task, model, host, tag, sid, system=None, tool_names=None, wall=None):
    (
        MON, PROBE_TOOLS, READ_STEPS_BEFORE_PROBE, TOOLS, WORKER_SYSTEM, WORKER_TOOLS, WS, _args, _compact,
        _fit_width, _live_tools, _row_text, _short_model, _term_cols, _tool_tokens, ctx_for, dim, effort, gnoc_hf,
        gnoc_oracle, json, llm_chat, orange, os, resolve, run_tools, say, time,
    ) = bind(
        "MON", "PROBE_TOOLS", "READ_STEPS_BEFORE_PROBE", "TOOLS", "WORKER_SYSTEM", "WORKER_TOOLS", "WS", "_args",
        "_compact", "_fit_width", "_live_tools", "_row_text", "_short_model", "_term_cols", "_tool_tokens",
        "ctx_for", "dim", "effort", "gnoc_hf", "gnoc_oracle", "json", "llm_chat", "orange", "os", "resolve",
        "run_tools", "say", "time",
    )
    # only the tools this edition has: the public build drops site_status (and others) from TOOLS while
    # WORKER_TOOLS still names them, and every default worker died on KeyError: 'site_status' before its first step
    names = tuple(n for n in (tool_names or WORKER_TOOLS) if n in TOOLS)
    tools = [TOOLS[n][1] for n in names]
    default_system = WORKER_SYSTEM.format(ws=WS, program=ctx.program or "none",
                                          progdir=(os.path.join("targets", ctx.program)
                                                   if getattr(ctx, "program", None) else "targets/<the program>/"))
    _repo = __import__("gnoc_agent").root()
    if not system and not getattr(ctx, "program", None) and os.path.realpath(_repo) != os.path.realpath(WS):
        # a coding chat's worker: the prompt above names only the hunt workspace, and a worker handed
        # "mypy inventory/ tests/" opened the workspace instead of the repo the chat is in
        default_system += (f"\nTHIS TASK IS IN THE CODE REPO {_repo}. Paths in the task are relative to it: read "
                           "and search THERE. The workspace above is not this task's.")
    msgs = [{"role": "system", "content": (system or default_system)},
            {"role": "user", "content": task}]
    brief = " ".join(str(task).split())   # the brief can carry newlines; one row, cut to the window
    say(_fit_width(_row_text(dim("    ↳ ") + orange("✻ ") + dim(f"{tag} [{sid}] {_short_model(model)}@{host}: {brief}")),
                   _term_cols() - 1))
    alloy = None  # ORACLE: the XBOW alloy, two endpoints alternate turns on a [hard] / GNOC_ALLOY=1 / stuck lane
    nsteps = effort()["worker_steps"]
    # A WALL, not just a step count. delegate / second_opinion / fan_out / code_review each get 4x the tool
    # timeout, which is 1200 s: one of them could hold an interactive turn for twenty minutes and then be
    # killed with nothing to show. Measured 2026-10-25: two soak prompts ("delegate ... read every STATUS.md",
    # "second opinion from the worker") were still running at 300 s with no answer. Past the wall the loop
    # stops taking new steps and spends its last call writing the digest from what it already has, so the
    # lead gets partial work instead of a kill.
    deadline = time.time() + float(wall or os.environ.get("GNOC_WORKER_WALL") or 210)
    out_of_time = False
    # PHASE 4: a delegated child also has a TOKEN budget, read from its MON tally (real usage where the server
    # reported it; a chars/4 estimate booked below only for a call that reported nothing). Past it the child stops
    # taking steps and writes its digest from what it has, exactly like the wall.
    usage = ctx.s.get("_child_usage") if isinstance(ctx.s.get("_child_usage"), dict) else None
    budget = int(ctx.s.get("_child_budget") or 0) if usage is not None else 0
    out_of_tokens = False
    nudged = {}                                               # D53: the one-shot nudges this bot has had
    probe_brief = "Test ONE hypothesis live" in str(task)    # D53: the harness's fan-out brief shape
    for step in range(nsteps):
        if time.time() > deadline:
            out_of_time = True
            MON.append(sid, f"wall reached after {step} step(s); writing the digest from what it has")
            break
        if budget and usage["tokens"] >= budget:
            out_of_tokens = True
            MON.append(sid, f"token budget {budget} reached after {step} step(s) ({usage['tokens']} used); "
                            "writing the digest from what it has")
            break
        anom = gnoc_oracle.lane_anomalous(msgs)  # ORACLE
        if alloy is None and gnoc_oracle.alloy_on(step, task, anom, nsteps):  # ORACLE: from half the budget
            # D53 (drive cycle 20, 2026-10-26 07:01Z): bot 3's turn 12 went to the phone 4B and timed out, the
            # whole bot was lost after eleven steps. A worker alloy rotates between the two GPUs only.
            alloy = [(model, host)] + [s for s in (resolve("lead", quiet=True), resolve("worker", quiet=True))
                                       if tuple(s) != (model, host)][:1]
            if os.environ.get("GNOC_ALLOY_PHONE") == "1":
                alloy.append(gnoc_oracle.phone_slot())
        (tm, th), alloyed = gnoc_oracle.alloy_slot(step, task, alloy or [(model, host)], anom, nsteps)  # ORACLE
        if alloyed:
            MON.append(sid, f"turn {step + 1} by {tm}@{th}")  # ORACLE
        try:
            left = max(20.0, deadline - time.time())   # never below 20 s: a tiny budget is not a timeout
            before = usage["tokens"] if usage is not None else 0
            m = llm_chat(tm, th, msgs, tools=_live_tools(tools, ctx), think=False if th == "phone" else None,
                         timeout=left)
            if usage is not None and usage["tokens"] == before:
                _book_estimate(MON, tm, th, msgs, m)
        except Exception as e:
            MON.append(sid, f"model error: {e}")
            return f"worker failed: {e}"
        gnoc_hf.touch(tm, th)
        msgs.append(m)
        MON.save_chat(sid, msgs)
        if not m.get("tool_calls"):
            content = (m.get("content") or "").strip()
            if not content and not nudged.get("empty"):
                # D53: bot 1 answered nothing at step 1 and the round took that as its digest. One nudge, once.
                nudged["empty"] = True
                MON.append(sid, "empty answer; nudged once", step=True)
                msgs.append({"role": "user", "content": "Your answer was empty. Do the task: call the tool that "
                                                        "does the next step now (a probe for a probe brief), or "
                                                        "write the digest with what you found."})
                continue
            MON.append(sid, "answer: " + content[:2000].replace("\n", " | "), step=True)
            return content or "(worker returned nothing)"
        for c in m["tool_calls"]:
            MON.append(sid, f"step {step + 1} call {(c.get('function') or {}).get('name')}"
                            f"({json.dumps(_args(c))[:300]})", step=True)
        # the worker cannot ask GreyNOC: anything that needs approval is declined for it
        res = run_tools(m["tool_calls"], ctx, interactive=False, prefix="      ", allowed=names)
        # D53: bot 2 spent ten steps on grep and read_file in a probe brief and never fired. After READ_STEPS_BEFORE_PROBE
        # tool steps without a probe tool, one nudge names the probe; the brief already carries the route.
        if probe_brief and not nudged.get("probe"):
            # `called`, not `names`: reusing `names` here replaced the bot's allowed tool list with this step's
            # calls, so a bot that read at step 1 could never probe again (QAQC 2026-11-19)
            called = {(c.get("function") or {}).get("name") for c in m["tool_calls"]}
            if called & PROBE_TOOLS:
                nudged["probe"] = True   # it fired: no nudge needed
            else:
                reads = nudged.get("reads", 0) + 1
                nudged["reads"] = reads
                if reads >= READ_STEPS_BEFORE_PROBE:
                    nudged["probe"] = True
                    MON.append(sid, f"{reads} steps without a probe; nudged once", step=True)
                    res.append({"role": "user", "content": "You have read for several steps and fired nothing. This is "
                                                           "a probe brief: call probe_matrix or http_request on the "
                                                           "route the VIOLATION names NOW, as the saved identity, "
                                                           "then read the bytes it returns."})
        for r in res:
            MON.append(sid, f"  -> {r.get('tool_name')}: " + (r.get("content") or "")[:400].replace("\n", " | "))
        msgs += res
        MON.save_chat(sid, msgs)
        # a worker's transcript is not a saved chat: no lineage, no model stage. Hunt notes only for a hunt's worker
        _compact(msgs, ctx_for(host, model), overhead=_tool_tokens(tools), hunt=bool(ctx.program))
    # the last message here is a TOOL result: handing that back as "partial work" gave the lead raw bytes and no
    # digest (GreyNOC's meta session 2026-10-22). One tool-free call writes the digest from what was found.
    try:
        why = "TOKEN LIMIT" if out_of_tokens else "TIME LIMIT" if out_of_time else "STEP LIMIT"
        kind = "token" if out_of_tokens else "time" if out_of_time else "step"
        closing = msgs + [{"role": "user", "content": f"{why} reached: no more tools. Write "
                                                      "the digest now from what your tools showed: found, evidence "
                                                      "paths, what is still unchecked."}]
        before = usage["tokens"] if usage is not None else 0
        # the one closing call is allowed past a token budget: without it the lead gets raw tool bytes, no digest
        m = llm_chat(model, host, closing)
        if usage is not None and usage["tokens"] == before:
            _book_estimate(MON, model, host, closing, m)
        if (m.get("content") or "").strip():
            MON.append(sid, "answer (at step limit): " + m["content"][:2000].replace("\n", " | "), step=True)
            return (f"worker hit its {kind} limit; its digest:\n"
                    + m["content"]) + gnoc_oracle.respawn_tail(  # ORACLE
                ctx.program, sid, task, msgs, m["content"])
    except Exception:   # noqa: BLE001 - fall back to the old partial-work line
        pass
    return "worker hit its step limit; partial work:\n" + (msgs[-1].get("content") or "") + gnoc_oracle.respawn_tail(
        ctx.program, sid, task, msgs, msgs[-1].get("content") or "")  # ORACLE: fresh RESPAWN BRIEF from disk state
