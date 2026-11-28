"""gnoc_distill.py - turn our own Claude Code (Opus) transcripts into training data and an eval for the local models.

The workspace holds ~1,700 Claude Code sessions (~94k Opus tool calls) run on THIS repo. That is the closest thing we
have to "how Opus works here", so it is used two ways:

  build   SFT corpus: every session becomes multi-turn chat samples in the OpenAI/Ollama tool-call shape, with
          Claude Code tool names mapped onto gnoc chat's own tools (Bash->bash, Read->read_file, Edit->edit_file ...).
          Secrets are redacted, tool results are clipped, hook-blocked calls are dropped, long sessions are windowed.
          Sessions are split train/held-out by a hash of the session id, so the eval never sees training sessions.
  evalset From the held-out sessions only: (context, Opus's next tool call) pairs, stratified by tool.
  sft     The subset worth imitating (error-heavy, looping and thin samples dropped), cut for a 16 GB QLoRA run.
  stats   Counts of what the corpus holds.

Outputs under .claude/state/orch/distill/ (train.jsonl, heldout.jsonl, evalset.jsonl, stats.json).
Thinking blocks in the transcripts are redacted by the API (signature only), so the corpus carries actions and the
visible text between them, not hidden reasoning.

    python3 scripts/gnoc_distill.py build [--max-chars 40000]
    python3 scripts/gnoc_distill.py evalset [--n 240]
    python3 scripts/gnoc_distill.py stats
"""
import collections
import glob
import hashlib
import json
import os
import random
import re
import sys

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(WS, ".claude/state/orch/distill")
SRC = os.path.expanduser("~/.claude/projects")
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
RESULT_HEAD, RESULT_TAIL = 1500, 500
SYSTEM = ("You are gnoc, the user's local bug-bounty and engineering agent working in the repo "
          f"{WS}. Act with tools rather than describing what to type. Read before you edit, keep evidence "
          "byte-faithful, stay in scope, and answer in short plain English.")

S = {"type": "string"}
I = {"type": "integer"}


def _fn(name, desc, props, req):
    return {"type": "function", "function": {"name": name, "description": desc,
                                             "parameters": {"type": "object", "properties": props,
                                                            "required": list(req)}}}


# The gnoc tools the corpus can express, with gnoc's own argument names (a subset of gnoc_agent.TOOLS).
TOOLS = [
    _fn("bash", "Run a shell command in the working directory.", {"command": S, "timeout": I}, ["command"]),
    _fn("read_file", "Read a file with line numbers.", {"path": S, "offset": I, "limit": I}, ["path"]),
    _fn("write_file", "Create or replace a whole file.", {"path": S, "content": S}, ["path", "content"]),
    _fn("edit_file", "Replace one exact unique snippet in a file.", {"path": S, "old": S, "new": S},
        ["path", "old", "new"]),
    _fn("grep", "Regex search across the repo.", {"pattern": S, "path": S, "glob": S}, ["pattern"]),
    _fn("web_search", "Web search; returns titles and URLs.", {"query": S}, ["query"]),
    _fn("web_fetch", "Read a public page as text.", {"url": S}, ["url"]),
    _fn("delegate", "Hand a self-contained sub-task to the worker model; returns its digest.", {"task": S},
        ["task"]),
]
TOOL_NAMES = {t["function"]["name"] for t in TOOLS}


def _rel(p):
    p = str(p or "")
    return p[len(WS) + 1:] or "." if p.startswith(WS + "/") or p == WS else p


def map_call(name, a):
    """Claude Code tool call -> (gnoc tool, args), or None when gnoc has no equivalent."""
    a = a or {}
    if name == "Bash":
        out = {"command": a.get("command", "")}
        if a.get("timeout"):
            out["timeout"] = min(900, max(1, int(a["timeout"]) // 1000))
        return "bash", out
    if name == "Read":
        out = {"path": _rel(a.get("file_path"))}
        for k in ("offset", "limit"):
            if isinstance(a.get(k), int):
                out[k] = a[k]
        return "read_file", out
    if name == "Write":
        return "write_file", {"path": _rel(a.get("file_path")), "content": a.get("content", "")}
    if name == "Edit":
        return "edit_file", {"path": _rel(a.get("file_path")), "old": a.get("old_string", ""),
                             "new": a.get("new_string", "")}
    if name == "Grep":
        out = {"pattern": a.get("pattern", "")}
        if a.get("path"):
            out["path"] = _rel(a["path"])
        if a.get("glob"):
            out["glob"] = a["glob"]
        return "grep", out
    if name == "WebSearch":
        return "web_search", {"query": a.get("query", "")}
    if name == "WebFetch":
        return "web_fetch", {"url": a.get("url", "")}
    if name in ("Agent", "Task"):
        return "delegate", {"task": a.get("prompt", "")}
    return None


# ---------------------------------------------------------------- redaction
_PATTERNS = [re.compile(p) for p in (
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}",       # JWT
    r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}",
    r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"(?i)(authorization:\s*(?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{12,}",
    r"(?i)((?:set-)?cookie:\s*)[^\n\"'\\]{12,}",                         # session cookies of our test accounts
    r"(?i)((?:api[_-]?key|token|secret|password|passwd|app_pass|cookie)\s*[=:]\s*['\"]?)[^\s'\"&;]{8,}",
)]


def _secret_values():
    vals = set()
    try:
        for line in open(SECRETS):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                v = line.split("=", 1)[1].strip().strip("'\"")
                if len(v) >= 8:
                    vals.add(v)
    except OSError:
        pass
    return sorted(vals, key=len, reverse=True)


SECRET_VALUES = _secret_values()


def redact(s):
    if not isinstance(s, str) or not s:
        return s
    for v in SECRET_VALUES:
        if v in s:
            s = s.replace(v, "<REDACTED>")
    for p in _PATTERNS:
        s = p.sub(lambda m: (m.group(1) if m.groups() else "") + "<REDACTED>", s)
    return s


def redact_obj(o):
    if isinstance(o, str):
        return redact(o)
    if isinstance(o, dict):
        return {k: redact_obj(v) for k, v in o.items()}
    if isinstance(o, list):
        return [redact_obj(v) for v in o]
    return o


# ---------------------------------------------------------------- parsing
_REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
_BLOCKED = re.compile(r"hook error|PreToolUse:|was blocked|denied this|user doesn't want|Permission to use", re.I)


def _text_of(content):
    if isinstance(content, str):
        return content
    out = []
    for b in content or []:
        if isinstance(b, dict):
            if b.get("type") == "text":
                out.append(b.get("text", ""))
            elif b.get("type") == "tool_result":
                out.append(_text_of(b.get("content")))
    return "\n".join(x for x in out if x)


def _clip(s):
    s = s or ""
    if len(s) <= RESULT_HEAD + RESULT_TAIL + 50:
        return s
    return s[:RESULT_HEAD] + f"\n[... {len(s) - RESULT_HEAD - RESULT_TAIL} chars cut ...]\n" + s[-RESULT_TAIL:]


def session_messages(path):
    """One transcript -> a gnoc-shaped message list (user / assistant with tool_calls / tool)."""
    rows, sub = [], "/subagents/" in path   # a subagent transcript is all sidechain rows: keep them there
    with open(path, errors="ignore") as fh:
        lines = fh.readlines()
    for line in lines:
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("type") in ("user", "assistant") and (sub or not d.get("isSidechain")) and isinstance(d.get("message"), dict):
            rows.append(d)
    msgs, pending, cur, cur_id = [], {}, None, None

    def flush():
        nonlocal cur
        if cur and (cur["content"].strip() or cur.get("tool_calls")):
            msgs.append(cur)
        cur = None

    for d in rows:
        m = d["message"]
        if d["type"] == "assistant":
            if m.get("id") != cur_id:
                flush()
                cur, cur_id = {"role": "assistant", "content": ""}, m.get("id")
            for b in m.get("content") or []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text" and b.get("text", "").strip():
                    cur["content"] = (cur["content"] + "\n" + b["text"]).strip()
                elif b.get("type") == "tool_use":
                    mapped = map_call(b.get("name"), b.get("input"))
                    if mapped:
                        cur.setdefault("tool_calls", []).append(
                            {"id": b.get("id"), "type": "function",
                             "function": {"name": mapped[0], "arguments": mapped[1]}})
                        pending[b.get("id")] = mapped[0]
            continue
        flush()
        cur_id = None
        content = m.get("content")
        results = [b for b in (content if isinstance(content, list) else []) if isinstance(b, dict)
                   and b.get("type") == "tool_result"]
        if results:
            for r in results:
                tid = r.get("tool_use_id")
                if tid not in pending:
                    continue
                text = _text_of(r.get("content"))
                msgs.append({"role": "tool", "tool_call_id": tid, "name": pending.pop(tid),
                             "content": _clip(_REMINDER.sub("", text)).strip() or "(no output)",
                             "_blocked": bool(_BLOCKED.search(text[:400]))})
            continue
        text = _REMINDER.sub("", _text_of(content)).strip()
        if text and not text.startswith(("<local-command", "<command-name>", "Caveat:")):
            msgs.append({"role": "user", "content": _clip(text) if len(text) > 6000 else text})
    flush()
    return _drop_blocked(msgs)


def _drop_blocked(msgs):
    """Remove calls a hook or the user refused (and their results): we want the move Opus made next, not the refusal."""
    bad = {m["tool_call_id"] for m in msgs if m.get("role") == "tool" and m.get("_blocked")}
    out = []
    for m in msgs:
        if m.get("role") == "tool":
            if m["tool_call_id"] in bad:
                continue
            m = {k: v for k, v in m.items() if k != "_blocked"}
        elif m.get("tool_calls"):
            calls = [c for c in m["tool_calls"] if c["id"] not in bad]
            m = dict(m, tool_calls=calls) if calls else {k: v for k, v in m.items() if k != "tool_calls"}
            if not calls and not m["content"].strip():
                continue
        out.append(m)
    # every tool message must answer a call still present, and every call must have its answer
    ids = {c["id"] for m in out for c in m.get("tool_calls", [])}
    answered = {m["tool_call_id"] for m in out if m.get("role") == "tool"}
    out = [m for m in out if m.get("role") != "tool" or m["tool_call_id"] in ids]
    for m in out:
        if m.get("tool_calls"):
            m["tool_calls"] = [c for c in m["tool_calls"] if c["id"] in answered]
            if not m["tool_calls"]:
                del m["tool_calls"]
    return [m for m in out if m.get("role") != "assistant" or m["content"].strip() or m.get("tool_calls")]


def _size(m):
    return len(m.get("content") or "") + sum(len(json.dumps(c["function"]["arguments"]))
                                              for c in m.get("tool_calls", []))


def windows(msgs, max_chars):
    """Split a long session into samples that each start with its first user turn (the task)."""
    first = next((i for i, m in enumerate(msgs) if m["role"] == "user"), None)
    if first is None:
        return []
    head = msgs[first]
    body = msgs[first + 1:]
    out, cur, size = [], [], _size(head)
    for m in body:
        # cut only before an assistant turn, so a tool result is never separated from its call
        if m["role"] == "assistant" and cur and size + _size(m) > max_chars:
            out.append(cur)
            cur, size = [], _size(head)
        cur.append(m)
        size += _size(m)
    if cur:
        out.append(cur)
    samples = []
    for k, w in enumerate(out):
        h = head if k == 0 else {"role": "user", "content": head["content"][:3000]
                                 + "\n\n[earlier steps of this session omitted]"}
        if any(m["role"] == "assistant" for m in w):
            samples.append([h] + w)
    return samples


def sessions():
    for f in sorted(glob.glob(os.path.join(SRC, "-home-you-gnoc-workspace*", "**", "*.jsonl"), recursive=True)):
        yield f, os.path.basename(f)[:-6]


def held_out(sid):
    return int(hashlib.sha256(sid.encode()).hexdigest(), 16) % 10 == 0


def build(max_chars=40000):
    os.makedirs(OUT, exist_ok=True)
    stats = {"sessions": 0, "train": 0, "heldout": 0, "calls": {}, "skipped_empty": 0}
    with open(os.path.join(OUT, "train.jsonl"), "w") as tr, open(os.path.join(OUT, "heldout.jsonl"), "w") as ho:
        for path, sid in sessions():
            try:
                msgs = session_messages(path)
            except Exception:
                continue
            if not any(m.get("tool_calls") for m in msgs):
                stats["skipped_empty"] += 1
                continue
            stats["sessions"] += 1
            split = "heldout" if held_out(sid) else "train"
            fh = ho if split == "heldout" else tr
            for w in windows(msgs, max_chars):
                for m in w:
                    for c in m.get("tool_calls", []):
                        n = c["function"]["name"]
                        stats["calls"][n] = stats["calls"].get(n, 0) + 1
                rec = {"session": sid, "subagent": "/subagents/" in path,
                       "messages": [{"role": "system", "content": SYSTEM}] + redact_obj(w), "tools": TOOLS}
                fh.write(json.dumps(rec) + "\n")
                stats[split] += 1
    json.dump(stats, open(os.path.join(OUT, "stats.json"), "w"), indent=1)
    return stats


def evalset(n=240, seed=7):
    """(context, Opus's next call) pairs from held-out sessions, at most 3 per sample, stratified by tool."""
    rng = random.Random(seed)
    by_tool = {}
    for line in open(os.path.join(OUT, "heldout.jsonl")):
        rec = json.loads(line)
        msgs = rec["messages"]
        idx = [i for i, m in enumerate(msgs) if m["role"] == "assistant" and m.get("tool_calls") and i >= 2]
        for i in rng.sample(idx, min(3, len(idx))):
            ctx = msgs[:i]
            if sum(_size(m) for m in ctx) > 30000:   # keep each item inside a 16k-token window with the tools
                ctx = [ctx[0], ctx[1]] + _tail(ctx[2:], 24000)
            call = msgs[i]["tool_calls"][0]["function"]
            by_tool.setdefault(call["name"], []).append(
                {"session": rec["session"], "messages": ctx, "target": call, "text": msgs[i]["content"][:400]})
    quota = {"bash": 0.55, "read_file": 0.12, "edit_file": 0.1, "write_file": 0.08, "delegate": 0.06,
             "web_search": 0.04, "grep": 0.02, "web_fetch": 0.03}
    items = []
    for t, frac in quota.items():
        pool = by_tool.get(t, [])
        items += rng.sample(pool, min(len(pool), max(1, round(n * frac))))
    rng.shuffle(items)
    with open(os.path.join(OUT, "evalset.jsonl"), "w") as fh:
        for k, it in enumerate(items):
            fh.write(json.dumps(dict(it, id=k)) + "\n")
    return {t: sum(1 for i in items if i["target"]["name"] == t) for t in quota}


_ERR = re.compile(r"Traceback \(most recent|command not found|No such file or directory|Permission denied|"
                  r"SyntaxError|^Exit code [1-9]|InputValidationError|<tool_use_error>", re.M)


def sft(max_chars=24000, max_err=0.4):
    """train.jsonl -> train-sft.jsonl: the subset worth imitating, cut to fit a 16 GB QLoRA run.

    Successful trajectories are what the distillation papers keep, but sessions carry no success label, so the filter
    uses what IS observable: a sample is dropped when over max_err of its tool results are errors, when it repeats one
    identical call 3+ times (a loop), or when it holds fewer than 2 tool calls. Long samples are re-windowed."""
    stats = {"in": 0, "out": 0, "drop_err": 0, "drop_loop": 0, "drop_thin": 0}
    with open(os.path.join(OUT, "train.jsonl")) as fi, open(os.path.join(OUT, "train-sft.jsonl"), "w") as fo:
        for line in fi:
            rec = json.loads(line)
            stats["in"] += 1
            body = rec["messages"][1:]
            for w in (windows(body, max_chars) if sum(_size(m) for m in body) > max_chars else [body]):
                calls = [json.dumps(c["function"], sort_keys=True) for m in w for c in m.get("tool_calls", [])]
                results = [m["content"] for m in w if m["role"] == "tool"]
                if len(calls) < 2:
                    stats["drop_thin"] += 1
                    continue
                if max(collections.Counter(calls).values()) >= 3:
                    stats["drop_loop"] += 1
                    continue
                if results and sum(bool(_ERR.search(r)) for r in results) / len(results) > max_err:
                    stats["drop_err"] += 1
                    continue
                while w and w[-1]["role"] != "assistant":   # end on the model's move, not on a dangling result
                    w = w[:-1]
                fo.write(json.dumps(dict(rec, messages=[rec["messages"][0]] + w)) + "\n")
                stats["out"] += 1
    return stats


def _tail(msgs, budget):
    out, size = [], 0
    for m in reversed(msgs):
        size += _size(m)
        if size > budget:
            break
        out.append(m)
    out.reverse()
    while out and out[0]["role"] == "tool":   # never start on an orphan tool result
        out.pop(0)
    return out


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    if cmd == "build":
        mc = int(sys.argv[sys.argv.index("--max-chars") + 1]) if "--max-chars" in sys.argv else 40000
        print(json.dumps(build(mc), indent=1))
    elif cmd == "sft":
        print(json.dumps(sft(), indent=1))
    elif cmd == "evalset":
        n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 240
        print(json.dumps(evalset(n), indent=1))
    else:
        print(open(os.path.join(OUT, "stats.json")).read())
