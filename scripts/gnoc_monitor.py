"""gnoc_monitor.py - what gnoc chat is spending and who is working: token/time accounting and the sub-agent registry.

USAGE (per turn, like Claude Code's footer):
    llm_chat calls record(model, host, tokens_in, tokens_out, seconds) once per model call (Ollama's
    prompt_eval_count / eval_count, llama-server's usage block) and tick() per streamed chunk, so the spinner can
    show a live count. turn_summary() is the line printed under every answer.
SUB-AGENTS (on disk, so a second terminal sees them too: `gnoc chat /agents`):
    .claude/state/orch/agent/subagents/<id>.json   {id, kind, model, host, task, pid, started, last, steps, tokens,
                                                   status running|done|failed|interrupted, summary, log}
    .claude/state/orch/agent/subagents/<id>.log    every step the sub-agent took, appended live
    A thread that runs a sub-agent calls bind(id); every streamed chunk in that thread is a heartbeat, so a model
    that is thinking is never mistaken for a frozen one. quiet() > QUIET_S with status running = shown as a warning.
    External Claude workers are registered with their pid and own output file; alive = pid still running.
"""
import contextlib
import contextvars
import json
import os
import threading
import time
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _alive, _now_iso as _now

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = os.path.join(WS, ".claude/state/orch/agent/subagents")
QUIET_S = 90
_lock = threading.Lock()
_local = threading.local()
_mem = {}          # id -> live record (this process)
_turn = {"calls": 0, "in": 0, "out": 0, "secs": 0.0, "models": {}, "t0": time.time(), "live": 0}
_session = {"models": {}, "t0": 0.0}   # the per-launch tally /usage reads




def short_model(key):
    """'hf.co/owner/Name-9B-GGUF:Q4_K_M@host' -> 'Name-9B@host': the status lines name the model, the full id
    stays where it is an identity key. Same rule as gnoc_agent._short_model, kept here so this module stays
    import-free of the agent."""
    import re as _re
    model, sep, host = str(key or "").partition("@")
    m = model.split("/")[-1]
    m = _re.sub(r"-i1-GGUF|-GGUF", "", m, flags=_re.I)
    m = _re.sub(r":[A-Za-z0-9_.]+$", "", m)
    return (m or model) + sep + host


def fmt_n(n):
    return f"{n / 1000:.1f}k" if n >= 1000 else str(int(n))


def fmt_s(s):
    return f"{s:.1f}s" if s < 60 else f"{int(s // 60)}m{int(s % 60):02d}s"


# ---------------------------------------------------------------- usage

def reset_turn():
    with _lock:
        _turn.update(calls=0, models={}, t0=time.time(), live=0, secs=0.0, **{"in": 0, "out": 0})


def tick(n=1):
    """One streamed chunk: the live token counter, and a heartbeat for the sub-agent this thread runs."""
    with _lock:
        _turn["live"] += n
        sid = getattr(_local, "sid", None)
        if sid and sid in _mem:
            _mem[sid]["last_ts"] = time.time()
            _mem[sid]["tokens"] = _mem[sid].get("tokens", 0) + n


# PER-CHILD TALLIES (phase 4). A delegated child's budget is counted from the same numbers this module records for
# the turn, so its tokens can never be counted in one place and missed in the other. A contextvar, not the
# thread-local above: _parallel copies the caller's context into every slot, so a tool that itself calls a model
# inside the child (hypothesize, code_review) still lands on the child's tally.
_SINKS = contextvars.ContextVar("gnoc_token_sinks", default=())


@contextlib.contextmanager
def tally(sink):
    """Within this block every record() also adds its tokens to sink["tokens"] (and to any outer tally)."""
    sink.setdefault("tokens", 0)
    tok = _SINKS.set(_SINKS.get() + (sink,))
    try:
        yield sink
    finally:
        _SINKS.reset(tok)


def record(model, host, tin, tout, secs, cached=0, calls=1):
    """cached: the part of tin the provider served from its prompt cache (Phase 1: the Anthropic, Gemini and
    OpenAI usage blocks report it; Ollama never does). Kept per model so /usage can show the cache working.
    calls=0 books an ESTIMATE for a call that reported no usage (Phase 4): its tokens count, the call was already
    counted (or never went through a model server at all)."""
    n = int(tin or 0) + int(tout or 0)
    for sink in _SINKS.get():
        with _lock:
            sink["tokens"] = int(sink.get("tokens") or 0) + n
    with _lock:
        _turn["calls"] += calls
        _turn["in"] += int(tin or 0)
        _turn["out"] += int(tout or 0)
        _turn["secs"] += float(secs or 0)
        k = f"{model}@{host}"
        m = _turn["models"].setdefault(k, {"calls": 0, "in": 0, "out": 0})
        m["calls"] += calls
        m["in"] += int(tin or 0)
        m["out"] += int(tout or 0)
        # The SESSION tally: /usage reads it. Same numbers, but never reset per turn.
        s = _session["models"].setdefault(k, {"calls": 0, "in": 0, "out": 0, "secs": 0.0})
        s["calls"] += calls
        s["in"] += int(tin or 0)
        s["out"] += int(tout or 0)
        s["secs"] += float(secs or 0)
        s["cached"] = s.get("cached", 0) + int(cached or 0)


def reset_session():
    """A fresh launch starts a fresh tally; /usage then describes THIS session only."""
    with _lock:
        _session["models"].clear()
        _session["t0"] = time.time()


def session_usage():
    """{models: [(key, {calls, in, out, secs})], calls, in, out, elapsed} since reset_session()."""
    with _lock:
        if not _session["t0"]:
            _session["t0"] = time.time()
        rows = sorted(_session["models"].items(), key=lambda kv: -kv[1]["out"])
        return {"models": rows, "elapsed": time.time() - _session["t0"],
                "calls": sum(v["calls"] for _, v in rows),
                "in": sum(v["in"] for _, v in rows),
                "out": sum(v["out"] for _, v in rows),
                "cached": sum(v.get("cached", 0) for _, v in rows)}


def live_tokens():
    return _turn["live"]


def turn_summary(ctx_pct=None):
    """'gpt-oss:20b@desktop 3 calls 4.1k in / 612 out · ctx 42% · 23.4s'.
    ctx_pct is the caller's estimate of how full the context window is after the
    turn; omitted, the line reads exactly as it always has."""
    el = time.time() - _turn["t0"]
    if not _turn["calls"] and not _turn["models"]:   # an estimate-only child still shows
        base = f"{fmt_s(el)}"
        return base + (f" · ctx {int(ctx_pct)}%" if ctx_pct is not None else "")
    parts = [f"{short_model(k)}  {v['calls']} call{'s' if v['calls'] != 1 else ''}  {fmt_n(v['in'])} in / {fmt_n(v['out'])} out"
             for k, v in sorted(_turn["models"].items(), key=lambda kv: -kv[1]["out"])]
    if ctx_pct is not None:
        parts.append(f"ctx {int(ctx_pct)}%")
    return " · ".join(parts) + f" · {fmt_s(el)}"


# ---------------------------------------------------------------- sub-agents

def _path(sid, ext):
    return os.path.join(DIR, f"{sid}.{ext}")


def _write(rec):
    # Best effort: the registry is a view of the work, and a full or read-only disk must never kill the sub-agent
    # it describes. The tmp name is per thread: the record is written from the sub-agent's thread and the main one,
    # and a shared tmp name let one os.replace() steal the other's file (FileNotFoundError).
    tmp = _path(rec["id"], f"json.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        os.makedirs(DIR, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump({k: v for k, v in rec.items() if k != "last_ts"} | {"last": rec.get("last_iso", rec.get("last"))},
                      f, default=str)
        os.replace(tmp, _path(rec["id"], "json"))
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def _red(text):
    """Every sub-agent log line passes the secret scrubber: the task, the step calls and the answers were written
    raw (QAQC r2), while save_chat already redacted the same content."""
    try:
        import gnoc_secrets
        return gnoc_secrets.redact(text)
    except Exception:  # noqa: BLE001 - a missing scrubber never stops the log
        return text


def start(kind, model="", host="", task="", pid=None, log=None):
    kind, task = str(kind or "agent"), _red(str(task or ""))
    with _lock:
        try:
            n = len(os.listdir(DIR)) // 2 + 1 if os.path.isdir(DIR) else 1
        except OSError:
            n = 1
        # the file count is not unique (an external worker writes no .log, so two starts in one second got the
        # SAME id and the second overwrote the first's record): step past any id already taken
        while True:
            sid = f"{kind.split(':')[0][:6]}-{n}-{int(time.time()) % 10000:04d}"
            if sid not in _mem and not os.path.exists(_path(sid, "json")):
                break
            n += 1
        rec = {"id": sid, "kind": kind, "model": model, "host": host, "task": task[:300],
               "pid": pid or os.getpid(), "external": bool(pid), "started": _now(), "last_ts": time.time(),
               "last_iso": _now(), "steps": 0, "tokens": 0, "status": "running", "summary": "",
               "log": log or _path(sid, "log")}
        _mem[sid] = rec
    _write(rec)
    if not pid:
        append(sid, f"start {kind} {model}@{host}: {task[:500]}")
    return sid


def bind(sid):
    _local.sid = sid


def unbind():
    _local.sid = None


def append(sid, line, step=False):
    rec = _mem.get(sid)
    if not rec:
        return
    with _lock:
        rec["last_ts"] = time.time()
        rec["last_iso"] = _now()
        if step:
            rec["steps"] += 1
    with contextlib.suppress(OSError):  # best effort, as _write
        os.makedirs(DIR, exist_ok=True)
        with open(rec["log"], "a", encoding="utf-8", errors="replace") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {_red(str(line))}\n")
    _write(rec)


def save_chat(sid, msgs):
    """The sub-agent's whole conversation (system brief, task, every model turn and tool result), so it can be read
    back step by step: gnoc agents -> select -> c. Secrets are redacted before it is written."""
    try:
        import gnoc_secrets
        red = gnoc_secrets.redact
    except ImportError:
        red = str
    rows = []
    for m in msgs:
        calls = [{"name": (c.get("function") or {}).get("name"), "args": (c.get("function") or {}).get("arguments")}
                 for c in m.get("tool_calls") or []]
        rows.append({"role": m.get("role"), "tool": m.get("tool_name"), "content": red(m.get("content") or ""),
                     "calls": json.loads(red(json.dumps(calls, default=str))) if calls else []})
    tmp = _path(sid, f"chat.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        os.makedirs(DIR, exist_ok=True)
        with open(tmp, "w") as f:
            json.dump(rows, f, default=str)
        os.replace(tmp, _path(sid, "chat"))
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def chat(sid):
    try:
        with open(_path(sid, "chat")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return []


def finish(sid, status="done", summary=""):
    rec = _mem.get(sid)
    if not rec:
        return
    summary = str(summary or "")
    rec["status"], rec["summary"] = status, summary[:300]
    append(sid, f"{status}: {summary[:500]}")
    with _lock:
        _mem.pop(sid, None)
    _write(rec)




def load_all():
    """Every registered sub-agent (this process and others), newest first, with live status fixed up."""
    rows = []
    if os.path.isdir(DIR):
        for f in os.listdir(DIR):
            if not f.endswith(".json"):
                continue
            try:
                with open(os.path.join(DIR, f)) as fh:   # the spinner calls this once a second: do not leak the fd
                    r = json.load(fh)
            except (OSError, ValueError):
                continue
            # a hand-edited or foreign file ({} / a list / no id) used to raise here, once a second, in the spinner
            if not isinstance(r, dict) or not isinstance(r.get("id"), str):
                continue
            mem = _mem.get(r["id"])
            if mem:
                r["last_epoch"] = mem["last_ts"]
                r["tokens"] = mem.get("tokens", r.get("tokens", 0))
            else:
                try:
                    r["last_epoch"] = datetime.fromisoformat(r.get("last") or r.get("started")).timestamp()
                except (ValueError, TypeError):
                    r["last_epoch"] = 0
                if r.get("status") == "running":
                    if r.get("external"):
                        if not _alive(r.get("pid")):
                            r["status"] = "done"
                            try:
                                r["last_epoch"] = os.path.getmtime(r["log"])
                            except OSError:
                                pass
                        else:
                            try:  # an external worker's heartbeat is its output file growing
                                r["last_epoch"] = max(r["last_epoch"], os.path.getmtime(r["log"]))
                            except OSError:
                                pass
                    elif not _alive(r.get("pid")):
                        r["status"] = "orphaned"  # the chat that ran it exited mid-task
            rows.append(r)
    return sorted(rows, key=lambda r: str(r.get("started") or ""), reverse=True)


def running():
    return [r for r in load_all() if r.get("status") == "running"]


def quiet_s(r):
    return max(0.0, time.time() - (r.get("last_epoch") or 0))


def spinner_note():
    """' · 2 sub-agents' plus a warning naming any running one that has been silent too long."""
    rs = running()
    if not rs:
        return ""
    stuck = [r for r in rs if quiet_s(r) > QUIET_S]
    note = f" · {len(rs)} sub-agent{'s' if len(rs) != 1 else ''} (↓ watch)"
    if stuck:
        r = max(stuck, key=quiet_s)
        note += f" · ⚠ {r['id']} quiet {fmt_s(quiet_s(r))} (/agent {r['id']})"
    return note


def find(sid):
    rows = load_all()
    return next((r for r in rows if r["id"] == sid), None) or \
        next((r for r in rows if r["id"].startswith(sid) or r["id"].endswith(sid)), None)


def tail(sid, n=40):
    r = find(sid)
    if not r:
        return None, []
    try:
        with open(r["log"], encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    return r, lines[-n:]


def prune(keep=200):
    """Keep the registry bounded: drop the oldest finished records and logs beyond `keep`."""
    # never a running record, and never one this process still holds in memory (it is running by definition,
    # whatever its file says); the .chat transcript goes with its record or it piled up forever
    rows = [r for r in load_all() if r.get("status") != "running" and r["id"] not in _mem]
    for r in rows[max(0, keep):]:
        for ext in ("json", "log", "chat"):
            try:
                os.remove(_path(r["id"], ext))
            except OSError:
                pass
