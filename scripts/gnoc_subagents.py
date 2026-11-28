"""gnoc_subagents.py - the rules every delegated child runs under, kept in one place.

delegate used to run ONE worker per call. Several delegate calls in one step already ran side by side (run_tools
runs approved calls four at a time), so the real width was whatever the lead happened to emit, with nothing
bounding it. This module holds what makes a fan-out of children safe to hand to a small lead model:

    POOL            ONE process-wide bounded pool. Every child of every delegate call takes a slot first, so
                    two delegate calls of three tasks each in one step still run at most `delegate_cap()` at once;
                    the rest wait in the queue. Waiting is interruptible (Ctrl-C, a cancelled parent).
    child_refusal   what a child may never do: approve, start another child, set a schedule, widen scope, write
                    standing policy. dispatch._plan_call asks it for every worker call, whatever tool list the
                    caller passed, so a future caller that hands a child the wrong list still cannot.
    parse_summary   the child's closing JSON {result, evidence, files, open_questions}, read tolerantly (fenced,
                    trailing prose, single quotes in the prose around it); anything unreadable becomes result=text.
    claude workers  the pids of the `claude` CLI workers this process started, so Ctrl-C can kill their process
                    groups (they already died with the chat; a Ctrl-C used to leave them running for 90 minutes).

Settings: GNOC_DELEGATE_CAP / GNOC_CHILD_TOKENS / GNOC_CHILD_SECONDS, else the "delegate" block of
$GNOC_HOME/settings.json (~/.gnoc/settings.json), e.g. {"delegate": {"cap": 3, "child_tokens": 150000}}. The file
lives in the user's home, never in a repo: a repo cannot widen the pool or the budgets it runs under.

Dependencies are passed in (the stop predicate, the tool table); nothing here reaches back into the facade.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import threading
import time
from typing import Any, Callable, Iterable

DEFAULT_CAP = 3
MAX_CAP = 8                      # a pool wider than this outruns two GPUs' slots; the model call queues anyway
DEFAULT_CHILD_TOKENS = 150_000   # a 9B worker's typical 20-step run is ~60-90k tokens in and out (MON tallies)
MIN_CHILD_TOKENS = 2_000
DEFAULT_CHILD_SECONDS = 210      # GNOC_WORKER_WALL's default: the wall a single delegate worker always had
SUMMARY_KEYS = ("result", "evidence", "files", "open_questions")

# The read-only default. WORKER_TOOLS also carries tools that WRITE harness state (node/asset upserts, identities
# save, oracle commits, phase release) or send bursts (race, sweep, oast registrations); a delegated child gets
# none of those. The GET probe tools stay: their non-GET forms need approval, which a child never has, so those
# come back to the lead as requests instead of running.
CHILD_READ_TOOLS = ("read_file", "list_dir", "grep", "find_file", "find_symbol", "repo_map", "hunt_search",
                    "dedup", "pay_check", "web_search", "web_fetch", "decode", "sast", "hunt_brief", "hunt_chains",
                    "playbook", "graph_overview", "oracle_status", "http_request", "graphql", "probe_matrix")
FILE_WRITE_TOOLS = frozenset({"write_file", "edit_file", "apply_patch", "bash", "bg"})

# What a child is refused whatever list it was given. Grandchildren: a child that fans out multiplies the pool by
# itself and nobody bounds the tree. Schedules: only the user sets one (the Hermes/OpenClaw lesson). Scope: a
# child works the program and repo it was handed. Standing policy: a lesson or a goal outlives the turn.
_SPAWN = frozenset({"delegate", "fan_out", "team", "claude_worker", "second_opinion", "escalate"})
_SCHEDULE = frozenset({"goal", "tasks", "defend", "gnoc", "bg"})
_SCOPE = frozenset({"set_program", "pick_target", "change_dir"})
_POLICY = frozenset({"learn"})


def child_refusal(name: str) -> str | None:
    """The refusal text for a tool a delegated child (any worker bot) may never call, or None."""
    name = str(name or "")
    if name in _SPAWN:
        return (f"refused: a child cannot start another child ({name}). Do the work yourself with your own tools, "
                "or say in open_questions what the lead should hand out next.")
    if name in _SCHEDULE:
        return (f"refused: a child cannot set a schedule, a goal or a background job ({name}); only the user does. "
                "If one is needed, say so in open_questions.")
    if name in _SCOPE:
        return (f"refused: a child cannot change its program, target or folder ({name}). Work the scope you were "
                "given; name anything outside it in open_questions.")
    if name in _POLICY or name.startswith("propose_"):
        return (f"refused: a child cannot write standing rules or policy ({name}). Put the suggestion in "
                "open_questions for the lead.")
    return None


def needs_approval_line(name: str, args: Any) -> str:
    """'needs approval: http_request POST https://x/y' - one line the lead can act on (args summarised, cut)."""
    a = args if isinstance(args, dict) else {}
    bits = []
    for k in ("method", "url", "command", "path", "action", "op", "target", "query", "args"):
        v = a.get(k)
        if v not in (None, "", [], {}):
            bits.append(str(v) if k in ("method", "url", "command", "path") else f"{k}={v}")
    if not bits and a:
        bits.append(json.dumps(a, default=str, sort_keys=True))
    text = " ".join(" ".join(bits).split())
    return f"needs approval: {name} {text[:200]}".rstrip()


# ---------------------------------------------------------------- settings

def _home() -> str:
    return os.environ.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def _settings() -> dict:
    try:
        with open(os.path.join(_home(), "settings.json"), encoding="utf-8") as f:
            got = json.load(f)
    except (OSError, ValueError):
        return {}
    block = got.get("delegate") if isinstance(got, dict) else None
    return block if isinstance(block, dict) else {}


def _int_setting(env: str, key: str, default: int, lo: int, hi: int) -> int:
    raw: Any = os.environ.get(env)
    if raw in (None, ""):
        raw = _settings().get(key, default)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        n = default        # a typo in the settings never widens anything: it is the default
    return max(lo, min(hi, n))


def delegate_cap() -> int:
    return _int_setting("GNOC_DELEGATE_CAP", "cap", DEFAULT_CAP, 1, MAX_CAP)


def child_token_budget() -> int:
    return _int_setting("GNOC_CHILD_TOKENS", "child_tokens", DEFAULT_CHILD_TOKENS, MIN_CHILD_TOKENS, 10_000_000)


def child_seconds(default: int = DEFAULT_CHILD_SECONDS) -> int:
    return _int_setting("GNOC_CHILD_SECONDS", "child_seconds", default, 20, 3600)


def clamp_budget(asked: Any, ceiling: int, floor: int) -> int:
    """A per-task budget the lead asked for may LOWER the configured ceiling, never raise it."""
    try:
        n = int(asked)
    except (TypeError, ValueError):
        return ceiling
    return max(floor, min(ceiling, n)) if n > 0 else ceiling


# ---------------------------------------------------------------- the pool

class ChildPool:
    """A counting gate read at every acquire, so a cap changed mid-session applies to the next child. Not a
    Semaphore: the cap is not fixed at construction, and the queue length is reported (the lead and the tests can
    see that the fourth task is WAITING, not lost)."""

    def __init__(self, cap: Callable[[], int] = delegate_cap) -> None:
        self._cap = cap
        self._cv = threading.Condition()
        self.active = 0
        self.waiting = 0
        self.peak = 0

    def acquire(self, should_stop: Callable[[], bool] = lambda: False, poll: float = 0.1) -> bool:
        """Wait for a slot; False (no slot taken) when should_stop() turns true while queued."""
        with self._cv:
            self.waiting += 1
            try:
                while self.active >= max(1, int(self._cap())):
                    if should_stop():
                        return False
                    self._cv.wait(poll)   # timed: a Ctrl-C or a cancelled parent is seen within `poll`
                if should_stop():
                    return False
                self.active += 1
                self.peak = max(self.peak, self.active)
                return True
            finally:
                self.waiting -= 1

    def release(self) -> None:
        with self._cv:
            self.active = max(0, self.active - 1)
            self._cv.notify_all()

    @contextlib.contextmanager
    def slot(self, should_stop: Callable[[], bool] = lambda: False):
        got = self.acquire(should_stop)
        try:
            yield got
        finally:
            if got:
                self.release()


POOL = ChildPool()


# ---------------------------------------------------------------- the structured summary

SUMMARY_NOTE = (
    "\n\nWHEN YOU FINISH, end your answer with ONE JSON object, exactly these keys: "
    '{"result": "<what you found or did, a few sentences>", "evidence": ["<file:line, capture path or output '
    'that shows it>"], "files": ["<files you read or changed>"], "open_questions": ["<what is still unchecked>"]}. '
    "You cannot approve anything and cannot start other workers: a step that needs approval is held and handed "
    "to the lead, so carry on without it and finish.")

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def _as_list(v: Any) -> list[str]:
    if v in (None, "", [], {}):
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)]


def _objects(text: str) -> Iterable[str]:
    """Every balanced {...} span, last first (the summary is at the end; an earlier one is quoted data)."""
    spans, depth, start, in_str, esc = [], 0, -1, False, False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"' and depth:
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                spans.append(text[start:i + 1])
    return reversed(spans)


def parse_summary(text: Any) -> dict:
    """{result, evidence, files, open_questions} from the child's final answer. Fenced JSON, bare JSON, trailing
    prose and a trailing comma are all read; no JSON at all gives result = the whole text. Never raises."""
    raw = str(text or "").strip()
    cands = [m.group(1) for m in _FENCE.finditer(raw)][::-1] + list(_objects(raw))
    for c in cands:
        for attempt in (c, re.sub(r",\s*([}\]])", r"\1", c)):
            try:
                obj = json.loads(attempt)
            except ValueError:
                continue
            if isinstance(obj, dict) and "result" in obj:
                out: dict[str, Any] = {"result": str(obj.get("result") or "").strip()}
                for k in SUMMARY_KEYS[1:]:
                    out[k] = _as_list(obj.get(k))
                if not out["result"]:
                    out["result"] = raw.replace(c, "").strip()[:4000]
                return out
    return {"result": raw[:8000], "evidence": [], "files": [], "open_questions": []}


def status_of(text: Any, cancelled: bool = False) -> str:
    """The harness's own status for a child, from how run_worker ended (never from the child's claims)."""
    if cancelled or text is None:
        return "cancelled"
    t = str(text)
    if t.startswith("worker failed") or t.startswith("bot failed"):
        return "failed"
    if t.startswith("refused") or t.startswith("bad arguments") or t.startswith("not run"):
        return "refused"
    for kind in ("token", "time", "step"):
        if t.startswith(f"worker hit its {kind} limit"):
            return f"{kind}_limit"
    return "done"


def summary(text: Any, *, requests: Iterable[str] = (), tokens: int = 0, status: str | None = None,
            files: Iterable[str] = (), evidence: Iterable[str] = ()) -> dict:
    """The full schema {result, evidence, files, open_questions, needs_approval, tokens, status}."""
    st = status or status_of(text)
    body = str(text or "")
    if st in ("token_limit", "time_limit", "step_limit") and "; its digest:\n" in body:
        body = body.split("; its digest:\n", 1)[1]
    out = parse_summary(body) if st != "cancelled" else {"result": "cancelled before it finished",
                                                         "evidence": [], "files": [], "open_questions": []}
    out["files"] = list(dict.fromkeys(list(out["files"]) + [f for f in files if f]))
    out["evidence"] = list(dict.fromkeys(list(out["evidence"]) + [e for e in evidence if e]))
    out["needs_approval"] = list(dict.fromkeys(str(r) for r in requests if r))
    out["tokens"] = int(tokens or 0)
    out["status"] = st
    return out


def render(rows: list[tuple[str, dict]]) -> str:
    """What the lead reads: one header line and the JSON summary per child, then the requests gathered in one
    place (the lead or the user acts on them; the children could not)."""
    out = []
    for i, (task, s) in enumerate(rows, 1):
        out.append(f"== child {i} [{s['status']}, {s['tokens']} tokens]: {' '.join(task.split())[:120]}")
        out.append(json.dumps(s, ensure_ascii=False, indent=1))
    asks = [(i, r) for i, (_t, s) in enumerate(rows, 1) for r in s["needs_approval"]]
    if asks:
        out.append("\nHELD FOR APPROVAL (no child can approve; run it yourself if it is right, which asks the user):")
        out += [f"- child {i}: {r}" for i, r in asks]
    out.append(f"\n{len(rows)} child(ren), {sum(s['tokens'] for _t, s in rows)} tokens charged to this turn.")
    return "\n".join(out)


# ---------------------------------------------------------------- claude CLI workers

_CLAUDE_PGIDS: dict[int, float] = {}   # session id -> start time; the worker runs in its own session (sid == pid)
_CLAUDE_LOCK = threading.Lock()


def register_claude_worker(pid: int) -> None:
    with _CLAUDE_LOCK:
        _CLAUDE_PGIDS[int(pid)] = time.time()


def claude_workers() -> list[int]:
    with _CLAUDE_LOCK:
        return sorted(_CLAUDE_PGIDS)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    with contextlib.suppress(ChildProcessError, OSError):   # reap our own exited child so it stops counting
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            return False
    return True


def _session_groups(sid: int) -> set[int]:
    """Every process group inside session `sid`. The worker runs `timeout ... claude`, and coreutils timeout moves
    itself and claude into a NEW process group (setpgid, unless --foreground), so a killpg of the wrapper's group
    TERMed bash and left claude running. The session is the one id nothing in the tree changes. Linux reads
    /proc; elsewhere only the wrapper's own group is known."""
    groups = {sid}
    with contextlib.suppress(OSError):
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            with contextlib.suppress(OSError, ValueError, IndexError):
                with open(f"/proc/{d}/stat", encoding="utf-8", errors="replace") as f:
                    rest = f.read().rsplit(")", 1)[1].split()   # comm may hold spaces and parens
                if int(rest[3]) == sid:                          # fields after comm: state ppid pgrp session
                    groups.add(int(rest[2]))
    return groups


def kill_claude_workers(grace: float = 2.0) -> list[int]:
    """Ctrl-C: TERM every process group of every claude worker session this process started, KILL what is still
    up after `grace`. Returns the worker ids (session ids) signalled. Never raises (it runs in an interrupt
    handler)."""
    with _CLAUDE_LOCK:
        sids = list(_CLAUDE_PGIDS)
        _CLAUDE_PGIDS.clear()
    hit, groups = [], set()
    for sid in sids:
        gs = _session_groups(sid)
        live = False
        for g in gs:
            with contextlib.suppress(OSError):
                os.killpg(g, signal.SIGTERM)
                live = True
        if live:
            hit.append(sid)
            groups |= gs
    end = time.time() + grace
    while groups and time.time() < end and any(_group_alive(g) for g in groups):
        time.sleep(0.05)
    for g in groups:
        with contextlib.suppress(OSError):
            os.killpg(g, signal.SIGKILL)
    for sid in hit:
        _alive(sid)   # reap the wrapper if it is our child
    return hit


def _group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except OSError:
        return False
    _alive(pgid)
    return True


CLAUDE_MISSING = ("not available: claude_worker needs the Claude Code CLI (`claude`), and it is not installed or "
                  "not on PATH. Install it (npm install -g @anthropic-ai/claude-code, then run `claude` once to sign "
                  "in) and restart gnoc chat, or use delegate for a local worker.")
