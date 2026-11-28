"""Per-conversation session persistence, writer locks, checkpoints and saved-history listing."""
import contextlib
import fcntl
import json
import os
import re

from .paths import _rel_home
from .state import STATE
from .util import _now, _read, _sha


PER_CHAT = ("history", "briefed", "auto", "_calls", "sid", "title", "_dedup_hosts", "_whole_files", "_desktop", "_tainted", "_untrusted_text", "_turn_off", "_refusals", "_ghost", "_turn_tools", "_turn_probes", "_receipts_from", "_briefed_for", "collab",
            # set for the length of ONE /plan turn. A /plan turn that was killed never cleared it, session.json kept
            # it, and every later chat inherited plan mode: the first plan(action=set) ended the turn on the spot,
            # no answer, plan at 0/6 (SWE marathon 2026-11-21, turn 10)
            "_planning_turn",
            # set by `gnoc chat "<one message>"`: never a setting the next chat inherits
            "_one_shot",
            # a quoted order and the rule a question rested on belong to ONE conversation: saved as settings, a
            # drive's quoted 'rm -rf /home' put "a line you quoted earlier is data" into an unrelated chat
            # (2026-11-22); a resumed chat rebuilds both from its own history
            "_quoted_order", "_last_rule")


NOTES_TAG = "[SESSION NOTES - earlier turns compacted; these probes, verdicts and files are real, do not redo them]"


INJECTED = (NOTES_TAG, "[HUNT ", "BOT EVENTS", "BOT FINDINGS", "Now answer me directly", "Do not tell me how",
            "That was a refusal", "The WORKER model",
            # the turn loop's own nudges (gnoc_core/agent.py). Titles only: a saved chat was listed in
            # /sessions as "You laid out a plan but have not carried it out" when GreyNOC's own first message
            # had been wrapped in a preamble (2026-11-18 QA/QC)
            "[an earlier request here was interrupted", "You laid out a plan but have not carried it out",
            "You carried out part of this", "You produced no answer", "You answered with nothing",
            "You wrote ", "Your answer ended with", "Your last tool call could not be parsed",
            "Your last test run FAILED", "You changed code and have not run", "You changed a file the browser",
            "An independent review of your diff", "That is the same answer as your last turn",
            "3 tool steps left", "Plan set and shown", "STEP LIMIT reached",
            # the end-of-turn request receipts (gnoc_core/receipts.py TAG), a harness note, never his words
            "[RECEIPTS (harness)")
# preambles gnoc puts IN FRONT of GreyNOC's own words; the words after the first blank line are still his
_PREAMBLES = ("BOT EVENTS since my last message:", "[I interrupted my previous request on purpose")


_SID_N = [0]


_SID_LOCK = [None]  # (fd, path, sid) of the ONE conversation this process may write


def legacy_session():
    """The single machine-wide settings file gnoc chat used before 2026-10-28. Still read ONCE by a new
    origin so nobody's settings vanish, and still the whole story for a run with no tty and no session
    id. Computed live, not at import, because the tests relocate STATE.agent_dir."""
    return os.path.join(STATE.agent_dir, "session.json")


def session_file():
    """The SETTINGS file for THIS chat: one per window, not one per machine.

    The user, 2026-10-28: "make sure each gnoc chat we open is its seperate chat". The conversation
    already was separate - every launch mints a fresh sid and pops PER_CHAT - but the settings beside it
    were not: one global session.json, last writer wins. Measured the same minute: three live chats
    (two of their terminals on pts/3 and pts/5, one detached hunt) all writing `repo`, `mode`, `effort` and
    `program_src` into that one file, so a detached hunt moving itself to targets/program-72 moved THEIR
    working directory too, and the program their next turn probed was whichever chat saved last.

    Keyed on _origin(), the same identity resume('last') uses, so a terminal keeps its own settings
    across restarts. Roles (the model per role) stay GLOBAL on purpose: llm_endpoints.ROLES is re-read
    per call by every chat and by orch-bot, which is what makes `/deepseek on` apply everywhere.
    """
    o = os.environ.get("GNOC_SESSION_KEY") or _origin()
    if not o:
        return legacy_session()         # no tty and no session id: behave exactly as before
    slug = re.sub(r"[^A-Za-z0-9]+", "-", o).strip("-")[:60].lower()
    return os.path.join(STATE.agent_dir, f"session-{slug}.json")


def _fresh_defaults(s):
    """The clean slate every NEW conversation starts from (2026-10-29): program clear, unlimited
    lead steps (/effort steps 0), and auto mode - each request picks swe / hunt / review / ... instead of a
    pin left by the window's last chat. All three can still be changed inside the session."""
    s.pop("program", None)
    s.pop("program_src", None)
    s.pop("stance", None)   # a new chat is a general chat; the last chat's hunt never carries over (2026-11-11)
    s["mode"] = "auto"
    s["steps_override"] = 0
    # what THIS conversation made and asked: /files listed the last chats' pictures as "files this chat made", and
    # the delete guard ("only a picture this conversation made") trusted the same carried-over list (image batch 6)
    for k in ("_images_made", "_media_asked", "_last_image_seed", "_boundary_kind", "_screen_sensitive",
              "_gnoc_own_pids", "_gpu_note_said", "_desktop"):   # desktop control never carries over
        s.pop(k, None)


def _new_sid():
    _SID_N[0] += 1  # two conversations started in one second by one process (a quick /new) stay distinct
    return f"{_now():%Y%m%d-%H%M%S}-{os.getpid()}-{_SID_N[0]}"


def _origin():
    """Who is driving this chat: the Claude Code session when an agent runs `gnoc chat`, else the terminal.

    Two agents drove `gnoc chat -c` from different Claude sessions at once (2026-10-25): -c resumes "the
    last conversation" and that is global, so one agent's video brief landed in the other's image chat
    ("Nobody asked for an image and there is no lighthouse") and was then stored as a standing preference.
    resume('last') prefers the newest conversation with the SAME origin and falls back to the global newest,
    so a person opening a new terminal still gets what they expect."""
    env = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if env:
        return "cc:" + env
    for fd in (0, 1, 2):
        with contextlib.suppress(OSError):
            return "tty:" + os.ttyname(fd)
    return ""


def _session_path(sid):
    return os.path.join(STATE.sessions_dir, f"{sid}.json")


def _sid_lock_path(sid):
    return _session_path(sid) + ".lock"


def _lock_holder(path):
    """The pid written into a lock file, or None when it cannot be read."""
    try:
        return int((_read(path) or "").split()[0])
    except (ValueError, IndexError):
        return None


def claim_sid(sid):
    """Take the exclusive writer slot for ONE conversation. Return None on success, else the pid holding it.

    WHY (measured 2026-11-03): a conversation IS a file, and nothing checked whether another process was
    already writing it. Two runs resumed the same conversation (pids 391723 and 397548); both saved the
    same history, so each save silently dropped the other's turns, AND both chats drove the same hunt,
    doubling the live request rate against a programme's 5 req/s cap. Same one-row-one-writer defect as
    the goal clobber, one level up. The lock is an flock, so a crashed or killed chat releases it with
    its fd and the conversation is resumable again with no stale-lock cleanup.
    A pid of 0 means the slot is held but the holder could not be read; it is still held."""
    if _SID_LOCK[0] and _SID_LOCK[0][2] == sid:
        return None  # already ours
    path = _sid_lock_path(sid)
    try:
        os.makedirs(STATE.sessions_dir, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None  # cannot lock (read-only state dir): never block the chat on the guard itself
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        holder = _lock_holder(path) or 0
        with contextlib.suppress(OSError):
            os.close(fd)
        return holder
    with contextlib.suppress(OSError):
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
    release_sid()  # only now: the old slot is given up once the new one is actually held
    _SID_LOCK[0] = (fd, path, sid)
    return None


def release_sid():
    """Give up this process's conversation slot. Exiting does the same via the closed fd."""
    held, _SID_LOCK[0] = _SID_LOCK[0], None
    if not held:
        return
    with contextlib.suppress(OSError):
        fcntl.flock(held[0], fcntl.LOCK_UN)
    with contextlib.suppress(OSError):
        os.close(held[0])


def _log_error(e):
    """Write the full traceback of a turn-ending error to disk; return where (the chat shows one line only)."""
    import traceback
    path = os.path.join(STATE.agent_dir, "last-error.txt")
    try:
        os.makedirs(STATE.agent_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{_now().isoformat()}\n" + "".join(traceback.format_exception(type(e), e, e.__traceback__)))
        return _rel_home(path)
    except OSError:
        return "(not saved)"


def _close_dangling(history):
    """Every assistant tool_calls message must be followed by one tool message per call. A Ctrl-C at an approval
    prompt or mid-tools, or a turn that died between the call and its results, used to save the call alone, and
    the split server (OpenAI format) then rejects the whole history on every later turn. Fill the gap in place."""
    i = 0
    while i < len(history):
        m = history[i]
        calls = m.get("tool_calls") if m.get("role") == "assistant" else None
        if calls:
            j = i + 1
            while j < len(history) and history[j].get("role") == "tool":
                j += 1
            for c in calls[j - i - 1:]:
                name = ((c.get("function") if isinstance(c, dict) else None) or {}).get("name") or "?"
                history.insert(j, {"role": "tool", "tool_name": name,
                                   "content": f"{name} was not run: the turn was interrupted before it finished"})
                j += 1
            i = j
        else:
            i += 1
    return history


def _own_text(content):
    """The user's own words in a user message: the preambles peeled off; "" when the harness wrote it."""
    c = str(content or "").strip()
    while c.startswith(_PREAMBLES):
        c = c.split("\n\n", 1)[1].strip() if "\n\n" in c else ""
    c = " ".join(c.split())
    return "" if not c or c.startswith(INJECTED) else c


def _title_of(history):
    for m in history:
        c = _own_text(m.get("content")) if m.get("role") == "user" else ""
        if c:
            return c[:70]
    return "(no message)"


def _stored_title(d):
    """A saved chat's title: the stored one unless it was taken from an injected message before
    _own_text existed, in which case it is worked out again from the history."""
    t = d.get("title") or ""
    return t if t and _own_text(t) and t != "(no message)" else _title_of(d.get("history") or [])


def list_sessions(limit=15):
    """Saved conversations, newest first: [{sid, title, n, updated, program}]."""
    rows = []
    with contextlib.suppress(OSError):
        for fn in os.listdir(STATE.sessions_dir):
            if not fn.endswith(".json"):
                continue
            try:
                d = json.loads(_read(os.path.join(STATE.sessions_dir, fn)) or "{}")
            except ValueError:
                continue
            rows.append({"sid": fn[:-5], "title": _stored_title(d),
                         "n": len(d.get("history") or []), "updated": d.get("updated", ""),
                         "program": d.get("program"), "origin": d.get("origin", "")})
    rows.sort(key=lambda r: r["updated"], reverse=True)
    return rows[:limit]


CHECKPOINT_MAX = 2_000_000  # bytes; a bigger file is still written, but /undo cannot restore it


def _ckpt_path(ctx):
    # A run with no session id (a test, a QAQC probe, a one-shot) used to append to one shared 'nosid'
    # ledger in LIVE state, which grew without bound (777 KB by 2026-10-22). Keep it per-process and
    # trimmed, so real sessions keep their undo history and throwaway runs cannot bloat it.
    sid = ctx.s.get("sid") or f"nosid-{os.getpid()}"
    return os.path.join(STATE.agent_dir, "checkpoints", f"{sid}.jsonl")


def _checkpoint(ctx, p, before, existed, after):
    """Record one write so /undo can put the file back. Kept per conversation (sid)."""
    row = {"ts": _now().isoformat(timespec="seconds"), "path": p, "existed": existed,
           "after_sha": _sha(after)}
    if len(before.encode("utf-8", "replace")) <= CHECKPOINT_MAX:
        row["before"] = before
    os.makedirs(os.path.dirname(_ckpt_path(ctx)), exist_ok=True)
    with open(_ckpt_path(ctx), "a") as f:
        f.write(json.dumps(row) + "\n")


def _checkpoints(ctx):
    rows = []
    with contextlib.suppress(OSError):
        with open(_ckpt_path(ctx)) as f:
            for ln in f:
                with contextlib.suppress(ValueError):
                    rows.append(json.loads(ln))
    return rows


def reset_state():
    """Reset per-process conversation counters (a facade reload starts clean, as before)."""
    _SID_N[0] = 0
    release_sid()
