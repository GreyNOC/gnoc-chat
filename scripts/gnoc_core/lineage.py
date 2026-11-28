"""Compaction lineage: the original messages a compaction removes are archived BEFORE the live history is rewritten.

WHY (Phase 2, 2026-11-26): compaction folded old turns into notes and Agent.save overwrote sessions/<sid>.json, and
gnoc_recall re-indexed a changed session by deleting its rows first. Once a long chat was compacted and saved, its
early turns existed nowhere: "what was the flag I told you in turn 3" had no answer, from the model or from recall.

Each compaction that drops or trims messages writes one SEGMENT: the original (pre-compaction) form of every message
it removed or shortened, in conversation order, each tagged with the turn it belonged to. Segments form a chain:

    sessions/<sid>.json                 parent -> <sid>~s0003  (the live, compacted conversation)
    sessions/segments/<sid>/s0003.json  parent -> <sid>~s0002
    sessions/segments/<sid>/s0002.json  parent -> <sid>~s0001
    sessions/segments/<sid>/s0001.json  parent -> None

Segments live in a subdirectory so /sessions, resume and the session listing never see them as chats of their own.
A segment is written once and never rewritten, so the originals cannot be lost by a later compaction.
"""
import contextlib
import json
import os
import re

from .util import _atomic_json, _now

SEG_DIR = "segments"
_SEG_FILE = re.compile(r"^s(\d{4,})\.json$")
_SEG_ID = re.compile(r"^(?P<sid>.+)~s(?P<n>\d{4,})$")


def seg_id(sid, n):
    return f"{sid}~s{int(n):04d}"


def parse_seg_id(sid_or_seg):
    """("<sid>", n) for a segment id, (sid, 0) for a plain session id."""
    m = _SEG_ID.match(str(sid_or_seg or ""))
    return (m.group("sid"), int(m.group("n"))) if m else (str(sid_or_seg or ""), 0)


class Lineage:
    """The archive of one conversation. Dependencies are explicit: the sessions directory and the session id."""

    def __init__(self, sessions_dir, sid):
        if not sessions_dir or not sid:
            raise ValueError("a lineage needs a sessions directory and a session id")
        # a sid is a file name component; one with a path separator could write outside the sessions dir
        if os.sep in str(sid) or (os.altsep and os.altsep in str(sid)) or str(sid) in (".", ".."):
            raise ValueError(f"not a session id: {sid!r}")
        self.sessions_dir = sessions_dir
        self.sid = str(sid)
        self.last_error = None   # why the last compaction could not archive, for the caller to report

    @property
    def dir(self):
        return os.path.join(self.sessions_dir, SEG_DIR, self.sid)

    def path(self, n):
        return os.path.join(self.dir, f"s{int(n):04d}.json")

    def numbers(self):
        """Segment numbers on disk, oldest first."""
        try:
            names = os.listdir(self.dir)
        except OSError:
            return []
        return sorted(int(m.group(1)) for m in map(_SEG_FILE.match, names) if m)

    def head(self):
        """The newest segment's id (what the live session's `parent` points at), or None."""
        nums = self.numbers()
        return seg_id(self.sid, nums[-1]) if nums else None

    def read(self, ident):
        """One segment by id or number; None when it is missing or unreadable."""
        n = parse_seg_id(ident)[1] if isinstance(ident, str) else int(ident)
        if isinstance(ident, str) and parse_seg_id(ident)[0] != self.sid:
            return None
        try:
            with open(self.path(n), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return None
        return d if isinstance(d, dict) and isinstance(d.get("messages"), list) else None

    def turns_archived(self):
        """How many of the user's turns the archive already holds (the next segment's turn base)."""
        nums = self.numbers()
        d = self.read(nums[-1]) if nums else None
        try:
            return int((d or {}).get("turns_after") or 0)
        except (TypeError, ValueError):
            return 0

    def reachable(self, ids):
        """True when every segment id is this chat's and readable on disk. The model summary refuses to run on
        notes whose originals are not all reachable (a summary of a summary with nothing under it)."""
        return all(self.read(i) is not None for i in ids)

    def archive(self, messages, turn_base, turns_after, notes_before=""):
        """Write the next segment and return its id. Raises OSError when it cannot be written: the caller decides
        what a compaction without an archive may still do."""
        nums = self.numbers()
        n = (nums[-1] + 1) if nums else 1
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        doc = {"id": seg_id(self.sid, n), "sid": self.sid, "segment": n,
               "parent": seg_id(self.sid, nums[-1]) if nums else None,
               "created": _now().isoformat(timespec="seconds"),
               "turn_base": int(turn_base), "turns_after": int(turns_after),
               "notes_before": notes_before or "", "messages": list(messages)}
        path = self.path(n)
        if os.path.exists(path):   # never overwrite an original (two writers racing): fail loudly instead
            raise OSError(f"segment {n} of {self.sid} already exists")
        _atomic_json(path, doc)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)   # chat content: the owner's only, like the secrets it may quote
        return doc["id"]

    def chain(self):
        """Segment ids from the newest back to the first, following each `parent` link."""
        out, cur, seen = [], self.head(), set()
        while cur and cur not in seen:
            seen.add(cur)
            out.append(cur)
            cur = (self.read(cur) or {}).get("parent")
        return out


def for_session(sessions_dir, sid):
    """A Lineage for a saved conversation, or None when there is nothing to archive under (no sid, a worker)."""
    try:
        return Lineage(sessions_dir, sid)
    except ValueError:
        return None
