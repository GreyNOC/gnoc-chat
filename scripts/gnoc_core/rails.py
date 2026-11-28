"""Loop rails: repeat and near-repeat breakers, per-turn volume caps, the edit epoch, and each tool's time limit."""
import contextlib
import os
import re
from .runtime import bind


SIDE_WORKER_MAX_S = int(os.environ.get("GNOC_SIDE_WORKER_MAX_S", "600"))  # /deep second opinion backstop


REPEAT_LIMIT = 3


# a matrix tool fires 11+ requests per call: the identical matrix a second time is 11 wasted probes, not one
# (launch #21 ran probe_matrix twice on the same app.example.com route in one turn, 2026-10-23). One identical
# call per turn for these; REPEAT_LIMIT for everything else.
_REPEAT_LIMIT_BY_TOOL = {"probe_matrix": 1, "sweep": 1, "race": 1}


_SKIP_REPEAT = {"hunt_hypothesis", "hunt_chains", "hunt_edge", "jobs", "bot"}


# Re-running the SAME verification after an edit is the WHOLE POINT of a fix loop, not a repeat: the repo
# changed, so the answer can change. These tools' repeat-count is keyed to an edit epoch that advances on every
# successful file mutation, so a re-run after a fix is a fresh call while a pointless re-run with no change in
# between is still caught (found 2026-10-23: the guard refused run_tests after the agent fixed the code).
_VERIFY_TOOLS = {"run_tests", "lint", "typecheck"}


_EDIT_TOOLS = {"edit_file", "write_file", "apply_patch"}


def _advance_edit_epoch(ctx, name, args, result):
    """A file mutation advances the edit epoch, so a following run_tests/lint is a fresh call (see _VERIFY_TOOLS
    in _repeat_note), never refused as a repeat. Returns True when it advanced."""
    (
        _EDIT_TOOLS, _FAIL, _bash_readonly, re,
    ) = bind(
        "_EDIT_TOOLS", "_FAIL", "_bash_readonly", "re",
    )
    if name in _EDIT_TOOLS:
        mutated = not _FAIL.match(re.sub(r"\s+", " ", str(result)).strip())  # not a refusal / bad-args / failure
    else:
        mutated = name == "bash" and not _bash_readonly((args or {}).get("command", ""))
    if mutated:
        ctx.s["_edit_epoch"] = int(ctx.s.get("_edit_epoch", 0) or 0) + 1
    return mutated


# A tool that SUCCEEDS over and over is the loop neither other breaker sees: _repeat_note only catches the
# identical call, and the refusal streak only counts refusals. Measured 2026-10-25: asked one question about
# what to probe first, the lead called hunt_hypothesis 25 times with different text, 41 calls in all, 1.0M
# input tokens and three minutes, and answered with a confabulation. hunt_hypothesis is in _SKIP_REPEAT
# precisely because writing several hypotheses in a turn is legitimate - several, not twenty-five.
# The cap is per TOOL per TURN and generous by default: a hunt really does fire many probes (the floor is 8
# plus a burst), and reading many files is how a repo gets understood.
TURN_CALL_CAP = 40


_TURN_CALL_CAP = {"hunt_hypothesis": 10, "hunt_model": 6, "learn": 6, "goal": 6,
                  "record_outcome": 10, "hunt_brief": 6, "dedup": 10, "second_opinion": 4, "delegate": 6}


# Caps that apply ONLY while /hunt is running (ctx.s["_hunting"]). program-50 2026-11-10 03:04-03:40Z: after
# one unfired verdict the lead spent the rest of a 224-call, 28-minute, 13.6M-token turn WRITING a bundle miner
# with its own unit-test suite (37 run_tests, 32 edit_file, 14 write_file) and fired 6 probes; the report file
# it was building was still empty at the interrupt. Developing is a different session (work/team); a hunting
# turn that edits and tests code is a loop wearing a lab coat. Outside a hunt these tools stay uncapped.
_HUNT_DEV_CAP = {"edit_file": 10, "write_file": 10, "run_tests": 6}


VERDICT_RETRIES = 3   # the same (hypothesis, status) verdict write passes the hunt_hypothesis cap this many times


def _turn_call_cap(name, hunting=False):
    """This turn's per-tool volume cap, or None for no cap.

    The NAMED caps are fixed at any turn length: writing 25 hypotheses or 11 notes is a bookkeeping loop
    whether the turn has 24 steps or none. The DEFAULT was sized for a 24-40 step turn, so it silently became
    the real limit once /effort steps lifted the step cap - the user 2026-10-28: an agent on `/effort steps 0`
    reported being "cut by the loop guard at 40". A hunting turn that may now run for hundreds of steps lost
    http_request mid-probe and kept going WITHOUT its instrument, because _live_tools drops a switched-off
    tool and the turn no longer ends on a step limit. So the default scales with the budget the operator
    actually asked for, and only when they asked: with no override every preset behaves byte-identically to
    before. The exact-repeat breaker (_repeat_note) still runs either way, and a probing tool is still bounded
    by the per-hypothesis economy budget."""
    (
        STEPS_OVERRIDE, TURN_CALL_CAP, UNBOUNDED_STEPS, _HUNT_DEV_CAP, _TURN_CALL_CAP, effort,
    ) = bind(
        "STEPS_OVERRIDE", "TURN_CALL_CAP", "UNBOUNDED_STEPS", "_HUNT_DEV_CAP", "_TURN_CALL_CAP", "effort",
    )
    if name in _TURN_CALL_CAP:
        return _TURN_CALL_CAP[name]
    if hunting and name in _HUNT_DEV_CAP:
        return _HUNT_DEV_CAP[name]
    if STEPS_OVERRIDE[0] is None:
        return TURN_CALL_CAP
    steps = effort()["steps"]
    return None if steps >= UNBOUNDED_STEPS else max(TURN_CALL_CAP, 2 * steps)


def _turn_volume_note(ctx, name, args=None):
    """'you have called this tool N times this turn' - a loop that never fails is still a loop."""
    (
        VERDICT_RETRIES, _HUNT_DEV_CAP, _turn_call_cap,
    ) = bind(
        "VERDICT_RETRIES", "_HUNT_DEV_CAP", "_turn_call_cap",
    )
    hunting = bool(ctx.s.get("_hunting"))
    cap = _turn_call_cap(name, hunting=hunting)
    seen = ctx.s.setdefault("_turn_calls", {})
    seen[name] = seen.get(name, 0) + 1   # counted even when uncapped, so the count stays honest
    if cap is None or seen[name] <= cap:
        return None
    a = args or {}
    if name == "hunt_hypothesis" and str(a.get("action", "")).lower() == "update" and a.get("status"):
        # A VERDICT is never a loop. program-50 2026-11-10 02:24Z: the cap was spent on adds and list calls, and
        # the lead ended the turn with "the ledger is blocked on H7's decision, which I can't record because the
        # hunt_hypothesis cap is spent" - 17 probes fired, no verdict written until the next turn. Status writes
        # pass the cap; adds and reads still hit it.
        # ...but a REFUSED verdict re-sent is a loop. program-50 2026-11-10 04:07Z: 266 `update status=dead`
        # calls in one process, every one refused by the floor ("none of its 0 probes drew a 2xx") and re-sent
        # with slightly different notes, so neither the exact nor the near repeat guard fired and this exemption
        # let it run. The same (id, status) passes VERDICT_RETRIES times per turn; after that the verdict stands
        # as whatever the floor recorded and the tool is switched off for the turn like any other loop.
        key = f"{a.get('id') or a.get('hypothesis') or '?'}:{str(a.get('status')).lower()}"
        tries = ctx.s.setdefault("_verdict_tries", {})
        tries[key] = tries.get(key, 0) + 1
        if tries[key] <= VERDICT_RETRIES:
            return None
        off = ctx.s.setdefault("_turn_off", [])
        if name not in off:
            off.append(name)
        return (f"refused: you have sent this verdict ({key}) {tries[key] - 1} times this turn and the floor refused "
                f"it every time; it stays as the floor recorded it (UNFIRED). Re-sending it with new notes is a loop, "
                f"so hunt_hypothesis is off for the rest of the turn. Fire probes that REACH a route, or move to a "
                f"hypothesis whose host answers.")
    off = ctx.s.setdefault("_turn_off", [])
    if name not in off:
        off.append(name)
    if hunting and name in _HUNT_DEV_CAP:
        return (f"refused: {seen[name] - 1} {name} calls in this ONE hunting turn (cap {cap}); {name} is off for the "
                f"rest of the turn. You are hunting, not developing: a miner with a unit-test suite is not a probe. "
                f"js_mine the page that loads the bundle, grep(around=) the capture for the one string you need, "
                f"then FIRE the http_request and record the verdict. If a tool is genuinely missing, say so in a "
                f"NEXT: line and the user will build it.")
    return (f"refused: you have called {name} {seen[name] - 1} times in this ONE turn (cap {cap}), which is a "
            f"loop rather than progress, so it is switched off for the rest of the turn. Use what you already "
            f"have and answer the user; if the work genuinely needs more, say so in a NEXT: line and the user will "
            f"continue it.")


# ---------- T1.1 loop rails (spec SPEC-0security-alignment-20261109) ----------
# F11 receipt (2026-11-09): 416 bash heredocs in 30 minutes, each slicing one minified bundle at shifted offsets
# (b[i-N:i-M]); every call had a NEW exact signature, so the exact-repeat guard never fired. The near signature
# blanks digits and long hex runs, so "only the numbers changed" is a repeat. 0sec-labs/0 keeps digits in its
# fingerprints (agent/doom-loop.ts, native-loop.ts LoopDetector, coordinator-rails.ts), so a literal copy would
# have missed F11 too; reimplemented here, no code copied.
# EXEMPT by design: http_request, probe_matrix, race, sweep and browser are NOT in NEAR_TOOLS. The empirical floor
# demands mutated ids (/orders/1, /orders/2 ...) and gnoc_economy already budgets those calls.
NEAR_TOOLS = {"bash", "read_file", "grep", "find_file", "list_dir", "web_fetch"}


NEAR_REPEAT_LIMIT = 3      # the 4th near-identical call in a turn is refused


NEAR_OFF_AT = 6            # the 6th switches the tool off for the turn, like the exact-repeat path


_HEX_RUN = re.compile(r"[0-9a-f]{8,}")


_DIGIT_RUN = re.compile(r"[0-9]+")


_SPACE_RUN = re.compile(r"\s+")


_OSC_PENDING = {}          # id(args) -> advisory text, appended to that call's result by run_tools


OSC_ADVISORY = ("ADVISORY: you are alternating between two calls; neither result is changing. Change the input or "
                "record the verdict.")


def _near_on():
    """GNOC_NEAR_REPEAT=0 bypasses the near-duplicate refusal and the oscillation nudge (rollback switch)."""
    (
        os,
    ) = bind(
        "os",
    )
    return str(os.environ.get("GNOC_NEAR_REPEAT") or "1").strip() != "0"


def _bash_turn_cap():
    """GNOC_BASH_TURN_CAP, read at call time: bash calls allowed per turn; 0 disables the cap. Default 60."""
    (
        os,
    ) = bind(
        "os",
    )
    try:
        return int(os.environ.get("GNOC_BASH_TURN_CAP") or 60)
    except ValueError:
        return 60


_NEAR_EXACT_KEYS = ("path", "name", "glob")   # a different FILE is different work: file1..file4 are four reads


def _norm_sig(name, args):
    """The call with whitespace collapsed, 8+ hex runs as H and digit runs as #: equal for calls that differ only
    in numbers (offsets, line ranges, ids). A path / name / glob argument stays exact, so reading four numbered
    files is four calls, while paging ONE file by offset or slicing one bundle in bash is a repeat."""
    (
        _DIGIT_RUN, _HEX_RUN, _NEAR_EXACT_KEYS, _SPACE_RUN, json,
    ) = bind(
        "_DIGIT_RUN", "_HEX_RUN", "_NEAR_EXACT_KEYS", "_SPACE_RUN", "json",
    )
    exact = {}
    if isinstance(args, dict):
        exact = {k: args[k] for k in _NEAR_EXACT_KEYS if k in args}
        args = {k: v for k, v in args.items() if k not in exact}
    t = json.dumps(args, sort_keys=True, default=str).lower().replace("\\n", " ").replace("\\t", " ")
    t = _DIGIT_RUN.sub("#", _HEX_RUN.sub("H", _SPACE_RUN.sub(" ", t)))
    return f"{name}:{json.dumps(exact, sort_keys=True, default=str)}:{t[:400]}"


def _nth(n):
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def _turn_off_tool(ctx, name):
    off = ctx.s.setdefault("_turn_off", [])
    if name not in off:
        off.append(name)


def _near_note(ctx, name, args):
    """Refusal for the 4th near-identical call of a NEAR_TOOLS tool in one turn (tool off at the 6th); queues ONE
    oscillation advisory per A-B-A-B pair per turn. None when the call may run."""
    (
        NEAR_OFF_AT, NEAR_REPEAT_LIMIT, NEAR_TOOLS, OSC_ADVISORY, _OSC_PENDING, _near_on, _norm_sig, _nth,
        _turn_off_tool,
    ) = bind(
        "NEAR_OFF_AT", "NEAR_REPEAT_LIMIT", "NEAR_TOOLS", "OSC_ADVISORY", "_OSC_PENDING", "_near_on", "_norm_sig",
        "_nth", "_turn_off_tool",
    )
    if name not in NEAR_TOOLS or not _near_on():
        return None
    sig = _norm_sig(name, args)
    seen = ctx.s.setdefault("_near", {})
    seen[sig] = seen.get(sig, 0) + 1
    hist = ctx.s.setdefault("_near_hist", [])
    hist.append(sig)
    del hist[:-4]
    n = seen[sig]
    if n > NEAR_REPEAT_LIMIT:
        off = ""
        if n >= NEAR_OFF_AT:
            _turn_off_tool(ctx, name)
            off = f" {name} is switched off for the rest of this turn."
        return (f"refused: this is the {_nth(n)} near-identical {name} call this turn (only numbers changed). Read the "
                "region once: grep path=<file> pattern=<marker> around=2000, or move on." + off)
    if len(hist) == 4 and hist[0] == hist[2] and hist[1] == hist[3] and hist[0] != hist[1]:
        told = ctx.s.setdefault("_osc_told", [])
        key = "|".join(sorted(hist[:2]))
        if key not in told:
            told.append(key)
            _OSC_PENDING[id(args)] = OSC_ADVISORY
    return None


def _take_osc_note(args):
    (
        _OSC_PENDING,
    ) = bind(
        "_OSC_PENDING",
    )
    return _OSC_PENDING.pop(id(args), None)


def _bash_cap_note(ctx, name):
    """The (cap+1)th bash call in a turn is refused and bash is off for the rest of the turn (F11 b)."""
    (
        _bash_turn_cap, _turn_off_tool,
    ) = bind(
        "_bash_turn_cap", "_turn_off_tool",
    )
    if name != "bash":
        return None
    cap = _bash_turn_cap()
    n = int((ctx.s.get("_turn_calls") or {}).get("bash", 0))
    if cap <= 0 or n <= cap:
        return None
    _turn_off_tool(ctx, "bash")
    return (f"refused: {n - 1} bash calls this turn reached the cap ({cap}); bash is off for the rest of the turn. "
            "Use grep (around= for a byte window), read_file with offset, or run_tests.")


def _reset_turn_rails(s):
    """Per-turn loop-rail state, cleared when a turn ends (the turn reset calls this)."""
    # _verdict_tries joined 2026-11-19: it was never cleared, so "VERDICT_RETRIES per turn" lasted the session
    for k in ("_turn_off", "_refusals", "_turn_calls", "_calls", "_near", "_near_hist", "_osc_told", "_verdict_tries"):
        s.pop(k, None)


def _repeat_note(ctx, name, args):
    """The same call with the same arguments a 4th time in a session is a loop, not a probe: refuse it and say so."""
    (
        REPEAT_LIMIT, _REPEAT_LIMIT_BY_TOOL, _SKIP_REPEAT, _VERIFY_TOOLS, _bash_cap_note, _near_note,
        _turn_volume_note, json,
    ) = bind(
        "REPEAT_LIMIT", "_REPEAT_LIMIT_BY_TOOL", "_SKIP_REPEAT", "_VERIFY_TOOLS", "_bash_cap_note", "_near_note",
        "_turn_volume_note", "json",
    )
    volume = _turn_volume_note(ctx, name, args)
    if volume:
        return volume
    capped = _bash_cap_note(ctx, name)   # T1.1
    if capped:
        return capped
    # hunt_hypothesis is exempt for list/show/update (re-reading the ledger is normal), but an IDENTICAL `add` is a
    # loop like any other: on program-50 2026-11-10 the lead re-sent one refused add ("route does not exist") 6 and
    # then 7 times in a row until the per-turn cap of 10, with the F3 accepted_example hint ignored each time.
    identical_add = name == "hunt_hypothesis" and str((args or {}).get("action", "add")).lower() == "add"
    if name in _SKIP_REPEAT and not identical_add:
        return None
    if name == "generate_image" and str((args or {}).get("seed") or "").strip() in ("", "-1", "None"):
        # no seed = a new random picture each call: "four variations of an owl logo" IS four identical calls. The
        # repeat guard refused the 3rd and 4th, and the lead wandered off for 14 minutes (image batch 6). A cap
        # per turn keeps a real loop bounded.
        n = ctx.s.setdefault("_images_this_turn", [0])
        n[0] += 1
        if n[0] > 8:
            return ("refused: 8 pictures this turn already. Answer now with the files that were saved; the user can ask "
                    "for more.")
        return None
    sig = name + json.dumps(args, sort_keys=True, default=str)
    if name in _VERIFY_TOOLS:  # a re-run after an edit is a new call, not a loop
        sig += f"|epoch={ctx.s.get('_edit_epoch', 0)}"
    seen = ctx.s.setdefault("_calls", {})
    seen[sig] = seen.get(sig, 0) + 1
    if len(seen) > 400:
        for k in list(seen)[:200]:
            del seen[k]
    limit = _REPEAT_LIMIT_BY_TOOL.get(name, REPEAT_LIMIT)
    if seen[sig] > limit:
        off = ""
        if seen[sig] > limit + 1:
            # refusing it was not enough: the 9B lead sent one refused bash call 8 times in a row (training run,
            # 2026-10-22). Take the tool away for the rest of this turn so the loop has to move on.
            turn_off = ctx.s.setdefault("_turn_off", [])
            if name not in turn_off:
                turn_off.append(name)
            off = f" {name} is switched off for the rest of this turn."
        return (f"refused: you already made this exact {name} call {seen[sig] - 1} times. Repeating it will not "
                "change the answer: mutate the input (another field, encoding, handler, sibling object or host) "
                "or move to the next hypothesis." + off)
    return _near_note(ctx, name, args)   # T1.1: numbers-only variants of a read/shell call


def _live_tools(tools, ctx):
    """The turn's tools minus any switched off by the repeat breaker this turn, or removed for a gateway session."""
    off = set((getattr(ctx, "s", None) or {}).get("_turn_off") or []) | set(getattr(ctx, "remote_denied", None) or ())
    return [t for t in tools or [] if (t.get("function") or {}).get("name") not in off] if off else tools


TOOL_TIMEOUT_S = float(os.environ.get("GNOC_TOOL_TIMEOUT") or 300)


# tools that legitimately run model loops, test suites or scanners for many minutes get 4x the wall
_LONG_TOOLS = {"delegate", "fan_out", "team", "second_opinion", "claude_worker", "ship_chain", "code_review", "hypothesize",
               "run_tests", "scan", "sast", "recon", "malware", "race", "probe_matrix", "generate_image"}


VIDEO_RENDER_LIMIT_S = 1800


def _video_render_words(w):
    """True when a `gnoc video ...` word list renders a video: minutes of work by design (1080p, voice, two
    formats), and the plain 300 s tool limit abandoned one mid-encode and reported the stale quick render
    as the result (2026-10-25). Listing, showing and editing stay on the normal limit."""
    if not w or w[0] != "video":
        return False
    return any(x in w for x in ("--render", "rerender", "course", "track", "marketing", "lesson", "explainer", "ctf", "render", "clip"))


def _tool_limit(name, args):
    """Wall-clock seconds a tool may run before run_tools stops waiting for it (GNOC_TOOL_TIMEOUT overrides)."""
    (
        TOOL_TIMEOUT_S, VIDEO_RENDER_LIMIT_S, _LONG_TOOLS, _video_render_words, shlex,
    ) = bind(
        "TOOL_TIMEOUT_S", "VIDEO_RENDER_LIMIT_S", "_LONG_TOOLS", "_video_render_words", "shlex",
    )
    base = TOOL_TIMEOUT_S * (4 if name in _LONG_TOOLS else 1)
    if name == "gnoc" and isinstance(args, dict):
        try:
            if _video_render_words(shlex.split(str(args.get("args") or args.get("command") or ""))):
                base = max(base, VIDEO_RENDER_LIMIT_S)
        except ValueError:
            pass
    if name == "delegate" and isinstance(args, dict) and isinstance(args.get("tasks"), list) and args["tasks"]:
        # PHASE 4: tasks past the pool cap queue for a slot. Each child keeps its own wall; this only stops run_tools
        # from abandoning a queued child mid-run: rounds of the cap times the longest wall (builders 900 s), plus
        # a margin for the closing digest call.
        with contextlib.suppress(Exception):
            import gnoc_subagents
            rounds = -(-len(args["tasks"]) // gnoc_subagents.delegate_cap())
            iso = any(isinstance(t, dict) and t.get("isolated") for t in args["tasks"]) or bool(args.get("isolated"))
            wall = gnoc_subagents.child_seconds(int(os.environ.get("GNOC_BUILDER_WALL") or 900) if iso else
                                                int(os.environ.get("GNOC_WORKER_WALL") or 210))
            base = max(base, rounds * (wall + 90))
    try:
        own = float(args.get("timeout") or 0)  # a tool given its own timeout gets that plus a margin
    except (TypeError, ValueError):
        own = 0
    return max(base, own + 60) if own > 0 else base
