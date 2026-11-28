"""Generic, side-effect-free helpers: safe file reads, UTC clock, atomic JSON, hashing, diffs."""
import contextlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone


def _read(p, default=""):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return default


def _read_n(p, n=None):
    """Whole-file read with optional character limit; a missing file is empty."""
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read(n) if n else f.read()
    except OSError:
        return ""


def _read_strict(p):
    """Whole-file read that lets OSError propagate (callers decide whether absence is fatal)."""
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def _alive(pid):
    """True when a process id exists and is signalable by this user."""
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _now():
    """UTC datetime, for callers that format it themselves."""
    return datetime.now(timezone.utc)


def _now_iso():
    """UTC ISO-8601, second precision (the most common sibling `_now` shape)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _now_z():
    """UTC ISO-8601 with a literal trailing Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_local():
    """Local time without a zone suffix (alert/triage row shape)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _now_micro():
    """UTC ISO-8601 with microseconds (oracle ordering)."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _now_stamp():
    """Compact UTC filename stamp."""
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _norm_answer(text):
    """The comparable shape of a final answer: lowercase words, numbers dropped, first 400 chars."""
    t = re.sub(r"\d+", "", str(text or "").lower())
    return re.sub(r"\W+", " ", t).strip()[:400]


def _same_answer(prev_norm, answer):
    """True when this turn's final answer is the previous turn's, word for word (D86)."""
    cur = _norm_answer(answer)
    return bool(prev_norm) and len(cur) >= 80 and cur == prev_norm


def _diff_rows(old, new, ctx_lines=2):
    """Numbered diff rows '  12 - text' / '  13 + text' / '  14   text', '⋯' between hunks. Removed lines carry
    their OLD line number, added and context lines the NEW one (what Claude Code shows)."""
    import difflib
    a, b = old.splitlines(), new.splitlines()
    rows, adds, dels = [], 0, 0
    for gi, group in enumerate(difflib.SequenceMatcher(None, a, b, autojunk=False).get_grouped_opcodes(ctx_lines)):
        if gi:
            rows.append("   ⋯")
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                rows += [f"{j + 1:>4}   {b[j]}" for j in range(j1, j2)]
                continue
            if tag in ("replace", "delete"):
                rows += [f"{i + 1:>4} - {a[i]}" for i in range(i1, i2)]
                dels += i2 - i1
            if tag in ("replace", "insert"):
                rows += [f"{j + 1:>4} + {b[j]}" for j in range(j1, j2)]
                adds += j2 - j1
    return rows, adds, dels


def _sha(text):
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _json_content_type(headers, body):
    """A JSON body with no Content-Type measures the WRONG code path.

    A real lane sent `{}` to an admin route and got 406 "Only application/json request bodies are accepted",
    then concluded both verbs shared one guard - when it had never reached the authorization check at all
    (2026-10-22, the T-37 trap: validation runs before authz). An API that wants JSON must be told it is JSON.
    An explicit Content-Type from the caller always wins, so a deliberate wrong-type probe still works."""
    b = body if isinstance(body, str) else (json.dumps(body) if body is not None else "")
    if not b.strip():
        return headers
    h = dict(headers or {})
    if any(k.lower() == "content-type" for k in h):
        return h
    probe = b.lstrip()[:1]
    if probe in ("{", "["):
        with contextlib.suppress(ValueError):
            json.loads(b)
            h["Content-Type"] = "application/json"
    return h


def _age_days(path):
    try:
        return (time.time() - os.path.getmtime(path)) / 86400.0
    except OSError:
        return None


def _truthy(v):
    """A model sends booleans as strings: confirm='True', refresh='false', include='0'. bool('false') is True,
    so a plain bool() on that turns a NO into a YES - and for site_redteam's loud burst that is the difference
    between asking and firing. Only an explicit yes is yes."""
    if isinstance(v, str):
        return v.strip().lower() in ("true", "yes", "y", "1", "on")
    return bool(v)


def _json_objects(text):
    """Every complete top-level {...} in text, parsed. Small models wrap JSON in prose or fences, emit one
    object instead of a list, nest the list under a key, leave trailing commas, or get cut off mid-array: this
    recovers every object that did complete."""
    out, depth, start, in_str, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if in_str:
            # the escape state of THIS char is decided by the previous one: recomputing it first made every
            # `\"` close the string, so {"a":"x\"y"} parsed to nothing (QAQC 2026-11-19)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str, esc = True, False
        elif ch == "{":
            depth += 1
            if depth == 1:
                start = i
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                chunk = re.sub(r",\s*([}\]])", r"\1", text[start:i + 1])
                try:
                    out.append(json.loads(chunk))
                except ValueError:
                    pass
    return out


def _parse_literal(s):
    """A JSON value, or a Python literal ("['A', 'B']", "{'k': 1}"), or raise ValueError."""
    import ast
    try:
        return json.loads(s)
    except ValueError:
        pass
    try:
        return ast.literal_eval(s)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        raise ValueError(s) from None


def _atomic_json(path, obj):
    """Write JSON so a crash, Ctrl-C or full disk mid-write leaves the OLD file intact, never a torn one.
    default=str: one stray non-JSON value in a history must not make the whole conversation unsavable."""
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(obj, f, default=str)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
