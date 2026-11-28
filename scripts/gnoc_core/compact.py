"""Compaction: folding older turns into dense notes so the history fits the model's window without losing a tool reply.

Two stages since Phase 2 (2026-11-26):
  1. deterministic (always, cheap): old tool output shrinks, old turns fold into one SESSION NOTES message, one line
     per tool call. With a lineage, the ORIGINAL form of everything removed or shortened is archived to disk first
     (gnoc_core/lineage.py), so recall can still return the exact words.
  2. model-written (optional, general mode only): when the deterministic notes lose too much, the worker model
     rewrites the notes from the archived originals and a validator restores dropped paths and user constraints
     (gnoc_core/summary.py). Any failure leaves stage 1's notes in place.
"""
import copy
import os
import re

from . import lineage as _lineage
from . import summary as _summary
from .runtime import bind
from .session import _own_text


NOTES_CAP = 8000


# hunt mode only: the workspace's evidence paths and verdict vocabulary. A general (coding) chat has neither, and its
# notes used to keep no file path at all because this pattern only knew targets/, reports/ and .claude/state.
_PATHS = re.compile(r"\b(?:targets|reports|\.claude/state)/[\w.@%+-]+(?:/[\w.@%+-]+)+")


_VERDICT = re.compile(r"\b(DEAD|LEAD|NEEDS|READY|UNFIRED|CRITICAL-CANDIDATE|MEDIUM-CANDIDATE|REFUTED|CONFIRMED)\b")


# the first line of the notes body once a lineage exists: which archived segments the notes stand for, how far the
# model summary reaches, and whether some folded text has no archive under it (then the model stage never runs)
ARCHIVE_HEAD = "[archived originals:"
_HEAD = re.compile(r"^\[archived originals: chat (?P<sid>\S+), segments (?:(?P<lo>\d+)-(?P<hi>\d+)|none); "
                   r"(?:model summary through segment (?P<summ>\d+)|no model summary)(?P<gap>; some earlier notes have "
                   r"no archive)?; the recall tool returns their exact words\]$")


def parse_head(line):
    m = _HEAD.match(str(line or "").strip())
    if not m:
        return None
    return {"sid": m.group("sid"), "lo": int(m.group("lo") or 0), "hi": int(m.group("hi") or 0),
            "summ": int(m.group("summ") or 0), "gap": bool(m.group("gap"))}


def make_head(h):
    segs = f"segments {h['lo']}-{h['hi']}" if h["hi"] else "segments none"
    summ = f"model summary through segment {h['summ']}" if h["summ"] else "no model summary"
    return (f"{ARCHIVE_HEAD} chat {h['sid']}, {segs}; {summ}"
            + ("; some earlier notes have no archive" if h["gap"] else "")
            + "; the recall tool returns their exact words]")


def _split_notes(content):
    """(head dict or None, body lines) of a notes message."""
    (
        NOTES_TAG,
    ) = bind(
        "NOTES_TAG",
    )
    lines = [ln for ln in (content or "").replace(NOTES_TAG, "").split("\n") if ln.strip()]
    head = parse_head(lines[0]) if lines else None
    return head, (lines[1:] if head else lines)


def _paths(text, hunt=True):
    (
        _PATHS,
    ) = bind(
        "_PATHS",
    )
    if not hunt:
        return _summary.paths(text)
    return list(dict.fromkeys(_PATHS.findall(text or "")))


def _note_lines(dropped, hunt=True):
    """What dropped messages leave behind: one line per tool call (call -> outcome [verdicts] | files), plus the
    asks and answers around them. Dense on purpose: ~40 probes fit in the notes. Verdict words are a hunt's
    vocabulary and are only picked out in hunt mode; a general chat's notes keep its file paths instead."""
    (
        NOTES_TAG, _PATHS, _VERDICT, _args, _brief, _paths,
    ) = bind(
        "NOTES_TAG", "_PATHS", "_VERDICT", "_args", "_brief", "_paths",
    )
    out, pending = [], []
    for m in dropped:
        c = " ".join((m.get("content") or "").split())
        if m["role"] == "user":
            if c and not c.startswith(NOTES_TAG):
                out.append(f"Q: {c[:120]}")
        elif m["role"] == "tool":
            call = pending.pop(0) if pending else m.get("tool_name") or "tool"
            files = _paths(m.get("content"), hunt)
            if hunt:
                head = _PATHS.sub("", c).replace("raw=", "").strip()[:90]
                v = list(dict.fromkeys(_VERDICT.findall(m.get("content") or "")))
            else:
                head = c
                for p in files:
                    head = head.replace(p, "")
                head = " ".join(head.split())[:90]
                v = []
            out.append(f"- {call} -> {head}" + (f" [{','.join(v)}]" if v else "")
                       + (f" | {', '.join(files[:4])}" if files else ""))
        else:
            pending += [f"{(t.get('function') or {}).get('name')}({_brief(_args(t))[:110]})"
                        for t in m.get("tool_calls") or []]
            if c:
                out.append(f"A: {c[:140]}")
    return out + [f"- {p} -> (result not kept)" for p in pending]


def _merge_notes(old, lines, head=None):
    """The notes after a fold: the old body plus the new lines, cut to NOTES_CAP (chatter first). `head` is the
    lineage header to write as the body's first line; without one the notes are exactly what they were before
    Phase 2."""
    (
        NOTES_CAP, NOTES_TAG,
    ) = bind(
        "NOTES_CAP", "NOTES_TAG",
    )
    _old_head, old_body = _split_notes(old)
    body = old_body + lines

    def size():
        return sum(len(x) + 1 for x in body)
    # over the cap: the oldest asks/answers go first, then the oldest probe lines; probes outlive chatter
    i = 0
    while size() > NOTES_CAP and i < len(body):
        if body[i].startswith(("Q: ", "A: ", "[...")):
            del body[i]
        else:
            i += 1
    while size() > NOTES_CAP and body:
        del body[0]
    return NOTES_TAG + "\n" + ((make_head(head) + "\n") if head else "") + "\n".join(body)


def _trim_tool(m, cap, tag, hunt=True):
    (
        _paths,
    ) = bind(
        "_paths",
    )
    c = m.get("content") or ""
    if len(c) > cap and "tool output trimmed]" not in c:
        keep = _paths(c, hunt)
        m["content"] = c[:cap] + f"\n[{tag}]" + (("\nfiles: " + ", ".join(keep[:8])) if keep else "")


def _tool_tokens(tools):
    """What a tool list costs in the prompt. Ollama renders every schema into it; 62 tools are ~10k tokens, which
    the compaction budget never counted, so a full history plus tools ran past num_ctx and the server cut the
    prompt itself (2026-10-22: ~21k input tokens per call)."""
    (
        json,
    ) = bind(
        "json",
    )
    return len(json.dumps(tools or [])) // 3 if tools else 0


def _archive(lineage, before, originals, dropped_ids, start, notes_before):
    """Write the originals of everything this compaction removed or shortened, in conversation order, each tagged
    with its turn. -> (segment number or 0, error or None). Runs BEFORE the notes are rewritten."""
    (
        NOTES_TAG,
    ) = bind(
        "NOTES_TAG",
    )
    base = lineage.turns_archived()
    turn, out, turns_after = base, [], base
    for i, m in enumerate(before):
        if i < start or (m.get("role") == "user" and (m.get("content") or "").startswith(NOTES_TAG)):
            continue
        orig = originals[id(m)]
        if orig.get("role") == "user" and _own_text(orig.get("content")):
            turn += 1
        gone = id(m) in dropped_ids
        if gone and orig.get("role") == "user" and _own_text(orig.get("content")):
            turns_after = turn
        if not gone and m.get("content") == orig.get("content"):
            continue
        row = dict(orig, turn=turn, state="dropped" if gone else "trimmed")
        if "tool output trimmed]" in str(orig.get("content") or ""):
            row["trimmed_earlier"] = True   # its full text is in the segment that trimmed it
        out.append(row)
    if not out:
        return 0, None
    try:
        ident = lineage.archive(out, base, turns_after, notes_before=notes_before)
    except (OSError, ValueError, TypeError) as e:
        return 0, f"{type(e).__name__}: {e}"
    return int(ident.rsplit("~s", 1)[1]), None


def upgrade_notes(msgs, start, lineage, summarize):
    """Stage 2: rewrite the notes at msgs[start] with the worker model, from the archived originals of every segment
    the model summary does not cover yet. Refuses (returns why) unless every segment the notes cover is readable on
    disk and no folded text lacks an archive: a summary is never made of a summary whose originals are gone.
    -> None when the notes were rewritten, else the reason they were not."""
    (
        NOTES_CAP, NOTES_TAG,
    ) = bind(
        "NOTES_CAP", "NOTES_TAG",
    )
    if lineage is None or summarize is None or len(msgs) <= start:
        return "no lineage or no summarizer"
    note = msgs[start]
    if note.get("role") != "user" or not (note.get("content") or "").startswith(NOTES_TAG):
        return "no notes"
    head, body = _split_notes(note["content"])
    if head is None or head["sid"] != lineage.sid:
        return "notes have no archive header for this chat"
    if head["gap"]:
        return "some folded text has no archive; the notes stay deterministic"
    if head["summ"] >= head["hi"]:
        return "nothing new to summarize"
    ids = [f"{lineage.sid}~s{n:04d}" for n in range(head["lo"], head["hi"] + 1)]
    if not head["lo"] or not lineage.reachable(ids):
        return "an archived segment is missing; refusing to summarize the summary"
    originals = []
    for n in range(head["summ"] + 1, head["hi"] + 1):
        seg = lineage.read(n) or {}
        originals += [m for m in seg.get("messages") or [] if not m.get("trimmed_earlier")]
    text = "\n".join(body)
    if not _summary.lossy(text, originals, _own_text, NOTES_CAP):
        return "the deterministic notes are enough"
    import gnoc_comms
    import gnoc_secrets
    new_body, why = _summary.run(summarize, text, originals, own_text=_own_text, redact=gnoc_secrets.redact,
                                 scan=gnoc_comms.injection_signs, cap=NOTES_CAP)
    if new_body is None:
        return why
    head = dict(head, summ=head["hi"])
    note["content"] = NOTES_TAG + "\n" + make_head(head) + "\n" + new_body
    return None


def _compact(msgs, ctx_tokens, keep_from=None, overhead=0, hunt=True, lineage=None, summarize=None):
    """Keep the conversation inside the model's window. Old tool output shrinks first (its file paths are kept),
    then the newest tool outputs shrink too if that was not enough, then old turns fold into one SESSION NOTES
    message: what was asked, every tool call, the outcome line, any verdict and every evidence path. A long
    /hunt therefore never forgets what it already probed.
    keep_from: index of the current turn's first message; nothing at or after it is ever dropped (a turn
    with a few big reads used to fold its own request into the notes). An assistant call is always dropped
    together with ALL its tool results, so no orphan tool message is left for the chat template.
    hunt: hunt vocabulary in the notes (verdicts, evidence paths); False gives a general chat's notes.
    lineage: a gnoc_core.lineage.Lineage; the originals of everything removed or shortened are archived there
    BEFORE the history is rewritten. summarize: the worker call for stage 2 (general mode only, see upgrade_notes).
    Returns the index shift for positions >= keep_from (negative for drops, +1 if a notes message was
    inserted) so the caller can keep its own bookmarks right."""
    (
        NOTES_TAG, _merge_notes, _note_lines, _trim_tool, json,
    ) = bind(
        "NOTES_TAG", "_merge_notes", "_note_lines", "_trim_tool", "json",
    )
    budget = int(max(ctx_tokens - overhead, ctx_tokens * 0.35) * 2.6)   # overhead: tool schemas, see _tool_tokens

    def size():
        return sum(len(m.get("content") or "") + len(json.dumps(m.get("tool_calls") or "")) for m in msgs)
    start = 1 if msgs and msgs[0]["role"] == "system" else 0
    over = size() > budget
    # the originals, taken before anything is cut, so the archive holds what the model actually saw
    before = list(msgs) if (lineage is not None and over) else None
    originals = {id(m): copy.deepcopy(m) for m in before} if before is not None else None
    tool_idx = [i for i, m in enumerate(msgs) if m["role"] == "tool"]
    for i in tool_idx[:-6]:
        if size() <= budget:
            break
        _trim_tool(msgs[i], 300, "older tool output trimmed", hunt)
    for i in tool_idx[-6:-1]:  # still over: the fresh ones shrink too, oldest first, but keep more of them
        if size() <= budget:
            break
        _trim_tool(msgs[i], 1500, "tool output trimmed", hunt)
    # never the NEWEST result: the model has not read it yet. Cutting it to 1500 chars sent the lead back to
    # read_file the same page again, step after step (2026-10-24); older turns fold below instead
    has_note = len(msgs) > start and msgs[start]["role"] == "user" and \
        (msgs[start].get("content") or "").startswith(NOTES_TAG)
    first = start + 1 if has_note else start
    limit = len(msgs) if keep_from is None else max(first, min(keep_from, len(msgs)))
    floor = 3 if keep_from is None else 0  # with no protected tail keep at least a few messages
    dropped = []
    while size() > budget and limit - first > floor:
        m = msgs.pop(first)
        limit -= 1
        dropped.append(m)
        if m.get("tool_calls") or m["role"] == "tool":
            while limit - first > 0 and msgs[first]["role"] == "tool":
                dropped.append(msgs.pop(first))
                limit -= 1
    shift = -len(dropped)
    old_note = msgs[start]["content"] if has_note else ""
    seg, archive_err = 0, None
    if before is not None and originals is not None:
        seg, archive_err = _archive(lineage, before, originals, {id(m) for m in dropped}, start, old_note)
        if archive_err:   # sticky for the turn: a later clean fold must not hide that an earlier one lost text
            lineage.last_error = archive_err   # the caller says it out loud; compaction itself never blocks a turn
    if dropped:
        head = None
        if lineage is not None:
            head, old_body = _split_notes(old_note)
            if head is None or head["sid"] != lineage.sid:
                # notes written before Phase 2 (or by another chat) have no archive under them
                head = {"sid": lineage.sid, "lo": 0, "hi": 0, "summ": 0, "gap": bool(old_body)}
            if seg:
                head = dict(head, lo=head["lo"] or seg, hi=seg)
            else:
                head = dict(head, gap=True)   # folded with nothing archived: the model stage stays off
        note = _merge_notes(old_note, _note_lines(dropped, hunt), head)
        if has_note:
            msgs[start]["content"] = note
        else:
            msgs.insert(start, {"role": "user", "content": note})
            shift += 1
    if summarize is not None and not hunt and lineage is not None:
        # hunt mode never gets here: its notes are receipts (call -> outcome [verdict] | evidence) and a model's
        # paraphrase of a verdict is not one
        upgrade_notes(msgs, start, lineage, summarize)
    return shift


def chat_kwargs(sessions_dir, sid, hunt, llm_chat=None, resolve=None, env=None):
    """The _compact keywords for a saved chat: its lineage, hunt or general notes, and the worker summary stage
    (general chats only; GNOC_COMPACT_SUMMARY=0 turns the model stage off and leaves archive + deterministic notes).
    A chat with no sid (a one-shot run) gets no lineage and therefore no model stage either."""
    env = os.environ if env is None else env
    lin = _lineage.for_session(sessions_dir, sid)
    summ = None
    if (not hunt and lin is not None and llm_chat is not None and resolve is not None
            and env.get("GNOC_COMPACT_SUMMARY", "1") != "0"):
        summ = _summary.worker_summarizer(llm_chat, resolve)
    return {"hunt": bool(hunt), "lineage": lin, "summarize": summ}
