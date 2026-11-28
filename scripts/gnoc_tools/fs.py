"""File, search, edit, git, undo and task tools."""
import contextlib as _contextlib
import os as _os
import re as _re
import threading as _threading

from gnoc_core.runtime import bind


# ---- exact file I/O and per-file locks for the edit tools (QAQC 2026-11-19 r2) ----
# The edit tools read with errors="replace" and universal newlines, and wrote the whole file back: a one-line edit
# turned a CRLF file into LF and every non-UTF-8 byte into U+FFFD, and /undo stored the already-damaged text. Now the
# file is read exactly (surrogateescape, newline=""), edited as "\n" text, and written back in its own convention.
_FILE_LOCKS, _FILE_LOCKS_GUARD = {}, _threading.Lock()


def _file_lock(p):
    """One lock per real path: run_tools runs up to four calls at once, and two edits of one file in a batch each
    read the old text and the later write silently dropped the earlier change."""
    with _FILE_LOCKS_GUARD:
        return _FILE_LOCKS.setdefault(_os.path.realpath(str(p)), _threading.RLock())


@_contextlib.contextmanager
def _locked(paths):
    locks = [_file_lock(x) for x in sorted({_os.path.realpath(str(x)) for x in paths if x})]
    for lk in locks:
        lk.acquire()
    try:
        yield
    finally:
        for lk in reversed(locks):
            lk.release()


def _load_exact(p):
    """(text with "\n" newlines, the file's newline, the exact text) - the exact text round-trips to the same bytes."""
    try:
        with open(p, encoding="utf-8", errors="surrogateescape", newline="") as f:
            raw = f.read()
    except OSError:
        return "", "\n", ""
    crlf = raw.count("\r\n") > 0 and raw.count("\r\n") * 2 >= raw.count("\n")
    return (raw.replace("\r\n", "\n") if crlf else raw), ("\r\n" if crlf else "\n"), raw


def _exact_out(text, nl):
    return text.replace("\n", nl) if nl != "\n" else text


def _write_exact(p, exact):
    with open(p, "w", encoding="utf-8", errors="surrogateescape", newline="") as f:
        f.write(exact)


READ_LINE_MAX = 400   # a longer line is shown cut, WITH a marker saying so (it used to be cut silently)


def _outside_scope(path, listing=False):
    """The honest answer for a path that EXISTS outside the repo and workspace (read_file / list_dir reach only those).

    "no such file in the active repo or workspace: /etc/group" was a lie the model believed: asked to explain the
    docker group risk, six bots spent seven minutes on find_file, list_dir and file:// requests looking for files that
    were there all along (2026-11-20 defender drive). Say it exists, and give the read that works."""
    import shlex
    (
        _is_secret, _rel_home, gnoc_secrets, os, root,
    ) = bind(
        "_is_secret", "_rel_home", "gnoc_secrets", "os", "root",
    )
    ap = os.path.expanduser(str(path or ""))
    if not os.path.isabs(ap) or not os.path.exists(ap):
        return None
    real = os.path.realpath(ap)
    home = os.path.realpath(os.path.expanduser("~"))
    rel = os.path.relpath(real, home) if real.startswith(home + os.sep) else ""
    if rel.startswith(".") or (os.path.isfile(real) and _is_secret(real)) or gnoc_secrets.is_secret_path(real):
        # a secret, or anything under a home dot-folder (~/.config, ~/.ssh, ~/.gnupg ...): no hint, no
        # confirmation it exists, and never a `cat` to read it (the skip-perms invariant, secrets.env)
        return None
    q = shlex.quote(path)
    if os.path.isdir(ap) or listing:
        return (f"refused: {path} is outside what list_dir opens (the active repo {_rel_home(root())} and the "
                f"workspace); it exists - look with a read-only shell command: bash command='ls -la {q}' "
                "(read-only commands run without asking).")
    return (f"refused: {path} is outside what read_file opens (the active repo {_rel_home(root())} and the "
            f"workspace); it exists - read it with a read-only shell command: bash command='cat {q}' "
            "(read-only commands run without asking).")


def t_read_file(ctx, path, offset=1, limit=250, question=""):
    (
        _binary_kind, _fence, _inside_ws, _is_foreign_bytes, _is_secret, _near_paths,
        _read, _rel, _rel_home, _session_hint, _tmp_file, gnoc_collab, os, root,
        web_bytes,
    ) = bind(
        "_binary_kind", "_fence", "_inside_ws", "_is_foreign_bytes", "_is_secret",
        "_near_paths", "_read", "_rel", "_rel_home", "_session_hint", "_tmp_file",
        "gnoc_collab", "os", "root", "web_bytes",
    )
    path = str(path or "")
    why = _fence(ctx, path)
    if why:
        return why
    p = _inside_ws(path) or _tmp_file(path)
    if not p or not os.path.isfile(p):
        if p and os.path.isdir(p):
            return f"{path} is a directory, not a file: call list_dir path={path}"
        outside = _outside_scope(path)
        if outside:
            return outside
        near = _near_paths(path)
        return (f"no such file in the active repo or workspace: {path} (working dir {_rel_home(root())}; "
                + (("closest real files: " + ", ".join(near) + ")") if near else
                   "find it with find_file name='<the filename>', or list_dir to look around)"))
    if _is_secret(p):
        return ("refused: that is a secrets file (.env / private key); its values never go into the chat"
                + _session_hint(ctx))
    if p.endswith(os.path.join("hunts", "gnoc", "ledger.json")):
        # launch #15 (2026-10-23) read the raw ledger in three slices (350 lines) to find an edge id: the ledger tools
        # answer that in one call and never spend the context on JSON punctuation
        prog = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(p))))
        return (f"that is the hunt ledger's raw JSON; read it through its tools instead: hunt_brief(program={prog}) for "
                "the summary, hunt_hypothesis action=list for the hypotheses, hunt_edge action=list for every edge "
                "with its id and status, hunt_chains for the chains.")
    if p.lower().endswith(".ipynb"):
        return _read_notebook(ctx, p)
    if _IMAGE_EXT.search(p):
        return _read_image(ctx, p, question)
    kind = _binary_kind(p)
    doc_kind = p.lower().endswith((".pdf", ".docx"))
    doc_label = ("PDF document" if p.lower().endswith(".pdf") else "DOCX document") if doc_kind else ""
    if kind and not doc_kind:
        # a PNG read as text was 250 lines of mojibake in the model's window (training run 2026-10-22)
        return (f"{_rel(p)} is a binary {kind} file ({os.path.getsize(p)} bytes); its bytes are not text. Cite the "
                "path as evidence, or read the text capture beside it (.hdr / .body / .json / .md).")
    prefix = ""
    if doc_kind:
        text = gnoc_collab.doc_text(p)
        if not text.strip():
            return (f"{_rel(p)} is a {doc_label} ({os.path.getsize(p)} bytes) with no extractable "
                    "text layer (a scanned PDF needs OCR: tesseract, or ask the user for a text version). "
                    "The path is still citable as paperwork.")
        lines = text.splitlines()
        prefix = (f"[{doc_label} text extracted from {_rel(p)} "
                  f"({os.path.getsize(p)} bytes on disk)]\n")
    else:
        lines = _read(p).splitlines()
    offset, limit = max(1, int(offset or 1)), max(1, min(int(limit or 250), 800))
    if lines and offset > len(lines):
        return f"{_rel(p)} has only {len(lines)} lines; offset={offset} is past the end (use offset=1)"
    chunk = lines[offset - 1: offset - 1 + limit]
    whole = offset == 1 and offset - 1 + limit >= len(lines)
    seen = ctx.s.setdefault("_whole_files", {}) if isinstance(getattr(ctx, "s", None), dict) else {}
    stamp = (_file_sig(p), len(lines))
    if whole and seen.get(p) == stamp:
        # launch #18 read a 37-line capture four times with limit 200, 300, 350: the whole file was in the window
        # after the first call
        return (f"{_rel(p)} was already shown in full ({len(lines)} lines) this chat; it has no more lines. "
                "Use what you read, or grep it for a byte.")
    if whole:
        # The line count alone is not enough: an edit that keeps the line count (the common case) left this cache
        # thinking the old bytes were still on screen, so the next read hid the changed file from the model.
        seen[p] = stamp
    # number, a TAB, then the line exactly: with two spaces the separator ran into the indentation ("    4    lab.py"
    # for a 2-space line) and the lead copied 4 spaces into every edit_file old text (2026-10-24)
    long_lines = [i for i, l in enumerate(chunk, offset) if len(l) > READ_LINE_MAX]
    body = "\n".join(f"{i:>5}\t{_cut_line(l)}" for i, l in enumerate(chunk, offset))
    if not doc_kind:
        _mark_seen(ctx, p)
    more = (f"\n[{len(lines)} lines total; next: offset={offset + limit}]" if offset - 1 + limit < len(lines)
            else f"\n[entire file: {len(lines)} lines, nothing more to read]")
    if long_lines:
        # The cut used to be silent while the header promised "the file's exact bytes": a minified bundle's line
        # was copied into edit_file old, could never match, and the model blamed the file.
        more += (f"\n[line(s) {', '.join(map(str, long_lines[:8]))}{' ...' if len(long_lines) > 8 else ''} are longer "
                 f"than {READ_LINE_MAX} chars and are shown CUT (marked '...[+N chars]'): do not copy them into "
                 "edit_file old. Read the rest with grep pattern=<text on that line> path=<file> around=300, or "
                 "replace the whole line with edit_file start_line/end_line.]")
    if _is_foreign_bytes(p):
        # A raw capture or a cloned vendor file is somebody else's text on disk: the same fence and copy gate a
        # response gets, so a payload planted in a capture cannot be pasted into bash unasked (audit A-08, 2026-10-28).
        # The fence goes OUTSIDE the line numbers so the "N<TAB>text" contract the model copies from is unchanged.
        return web_bytes(f"file {_rel(p)}", prefix + (body or "(empty)") + more, ctx)
    return prefix + (body or "(empty)") + more


def _cut_line(line):
    if len(line) <= READ_LINE_MAX:
        return line
    return line[:READ_LINE_MAX] + f"...[+{len(line) - READ_LINE_MAX} chars]"


def _file_sig(p):
    (os,) = bind("os")
    try:
        st = os.stat(p)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _mark_seen(ctx, p):
    """Remember the file as the agent last saw it (read or wrote it), so a later edit by LINE NUMBER or a
    whole-file write can tell when someone else changed it in between."""
    (os,) = bind("os")
    s = getattr(ctx, "s", None)
    if not isinstance(s, dict) or not p:
        return
    seen = s.setdefault("_seen_files", {})
    key = os.path.realpath(p)
    seen.pop(key, None)
    seen[key] = _file_sig(p)
    while len(seen) > 400:   # it rides in the saved session: keep the most recently touched files only
        seen.pop(next(iter(seen)))


def _stale(ctx, p):
    """A refusal when the file changed on disk since the agent last read or wrote it, else None. A file the
    agent never looked at this chat is not judged here (nothing to compare against)."""
    (os, _rel) = bind("os", "_rel")
    s = getattr(ctx, "s", None)
    if not isinstance(s, dict):
        return None
    seen = (s.get("_seen_files") or {}).get(os.path.realpath(p), "never")
    if isinstance(seen, list):   # a resumed session: the saved JSON turned the (mtime, size) tuple into a list
        seen = tuple(seen)
    if seen == "never" or seen == _file_sig(p):
        return None
    return (f"refused: {_rel(p)} changed on disk since you last read or wrote it (a formatter, a hook, a bash "
            "command, another process or the user changed it), so your line numbers / your copy may be stale. "
            "read_file it again, then make the change against what is there now.")


_IMAGE_EXT = _re.compile(r"\.(png|jpe?g|gif|webp|bmp)$", _re.I)


def _read_notebook(ctx, p):
    (_rel, _spill, gnoc_notebook) = bind("_rel", "_spill", "gnoc_notebook")
    try:
        text = gnoc_notebook.render(p)
    except (ValueError, OSError) as e:
        return f"{_rel(p)} could not be read as a notebook: {e}"
    _mark_seen(ctx, p)
    return _spill(text, "notebook")


def _read_image(ctx, p, question=""):
    """An image cannot go into a text window; a vision model can LOOK at it and say what is there. An image that
    does not decode, or a look that fails, gets the plain binary-file answer (the capture beside it is the text)."""
    (_rel, _vision_model, _binary_kind, gnoc_vision, os) = bind(
        "_rel", "_vision_model", "_binary_kind", "gnoc_vision", "os")
    size = os.path.getsize(p)
    plain = (f"{_rel(p)} is a binary {_binary_kind(p) or 'image'} file ({size} bytes); its bytes are not text. "
             "Cite the path as evidence, or read the text capture beside it (.hdr / .body / .json / .md).")
    try:
        from PIL import Image
        with Image.open(p) as im:
            im.verify()
    except ImportError:
        pass
    except Exception:  # noqa: BLE001 - not a decodable picture: no model can describe it
        return plain
    got = gnoc_vision.describe(p, question, _vision_model)
    if got and str(got[1]).startswith("(the vision model failed"):
        return plain + f" (A vision model was asked to look and failed: {got[1].strip('()')})"
    if got is None:
        return (f"{_rel(p)} is an image ({size} bytes). No vision model is installed, so its content cannot be "
                "seen here: say so plainly instead of guessing. (ollama pull qwen2.5vl:7b, or set "
                "GNOC_VISION_MODEL, gives read_file eyes.)")
    model, text = got
    return (f"{_rel(p)}: image, {size} bytes. What the vision model {model} sees"
            + (f" (asked: {question})" if question else "") + f":\n{text}\n[a model's description, not "
            "the pixels: confirm anything decisive another way]")


def _is_foreign_bytes(p):
    """True for a file whose CONTENT was written by someone else: a saved target response, a cloned vendor repo."""
    (
        WS, _FOREIGN_PATH, os,
    ) = bind(
        "WS", "_FOREIGN_PATH", "os",
    )
    r = "/" + os.path.relpath(p, WS).replace(os.sep, "/")
    return bool(_FOREIGN_PATH.search(r))


def _draft_tag(parent, name):
    """'  [KILL]' and friends for a draft directory, so a listing can never present a gate-killed draft as
    live work. Empty for anything that is not a draft folder. Never raises into a listing."""
    (
        contextlib, gnoc_gates, os,
    ) = bind(
        "contextlib", "gnoc_gates", "os",
    )
    with contextlib.suppress(Exception):
        if os.sep + "reports" + os.sep + "drafts" + os.sep not in parent + os.sep:
            return ""
        state = gnoc_gates.draft_state(os.path.join(parent, name))
        if state == "KILL":
            return "   [KILL - gate-killed, not a live draft]"
        if state == "HELD":
            return "   [HELD - see HELD-REASON.md]"
        if state == "gated":
            return "   [gates run]"
    return ""


def t_list_dir(ctx, path="."):
    (
        _draft_tag, _fence, _inside_ws, _rel_home, datetime, os, root,
    ) = bind(
        "_draft_tag", "_fence", "_inside_ws", "_rel_home", "datetime", "os", "root",
    )
    why = _fence(ctx, path)
    if why:
        return why
    p = _inside_ws(str(path or "."))
    if not p or not os.path.isdir(p):
        if p and os.path.isfile(p):
            return f"{path} is a file, not a directory: call read_file path={path}"
        outside = _outside_scope(str(path or "."), listing=True)
        if outside:
            return outside
        return (f"no such directory in the active repo: {path} (working dir {_rel_home(root())}; list_dir path=. "
                "shows what is here, change_dir moves elsewhere)")
    names = os.listdir(p)
    dirs = [n for n in names if os.path.isdir(os.path.join(p, n))]
    files = [n for n in names if n not in dirs]
    if not names:
        return "(empty)"
    # the counting and the "newest" are done here, exactly: local models miscount long listings (a live test
    # gave 30, 26, 25 and 46 for folders holding 7 and 30 directories) and read "newest" off the name
    def mtime(n):
        # lstat, not stat: a dangling symlink (~/.steampath) made getmtime raise, and the whole listing of the
        # home directory failed with FileNotFoundError (GreyNOC 2026-11-18)
        try:
            return os.lstat(os.path.join(p, n)).st_mtime
        except OSError:
            return 0.0

    def size(n):
        try:
            return os.lstat(os.path.join(p, n)).st_size
        except OSError:
            return 0
    newest = sorted(dirs or files, key=mtime, reverse=True)[:3]
    head = (f"{len(dirs)} directories, {len(files)} files. Newest {'directories' if dirs else 'files'} by "
            f"modification time: " + ", ".join(f"{n} ({datetime.fromtimestamp(mtime(n)):%Y-%m-%d %H:%M})"
                                                for n in newest))
    rows = [n + "/" + _draft_tag(p, n) for n in sorted(dirs)]
    # a raw capture dir holds hundreds of files; 300 rows of timestamps taught the model nothing (launch #18, 558
    # files, 301 lines). Show the newest 40 files; a specific one is found with grep.
    LIM = 40
    fs = sorted(files, key=mtime, reverse=True)
    rows += [f"{n}  ({size(n)} B)" + (" -> missing target" if os.path.islink(os.path.join(p, n))
                                       and not os.path.exists(os.path.join(p, n)) else "") for n in fs[:LIM]]
    tail = (f"\n[... {len(fs) - LIM} older files not listed; grep pattern=<byte> path={path} finds one]"
            if len(fs) > LIM else "")
    return head + "\n" + "\n".join(rows[:300]) + tail


def t_find_file(ctx, name, path="."):
    """Files whose NAME matches, under path. The gap this fills: asked to run test_gnoc_oast.py the lead had
    only content-grep to locate it, searched for the string inside files, found nothing, widened to the whole
    workspace, hit grep's 60 s cap and burned the turn (soak batch 1, 2026-10-25)."""
    (
        _inside_ws, _rel_home, os, root, subprocess,
    ) = bind(
        "_inside_ws", "_rel_home", "os", "root", "subprocess",
    )
    name = str(name or "").strip()
    if not name:
        return "bad arguments: find_file needs a name or glob, e.g. name='test_*.py'"
    why = bind("_sandbox_fence")[0](ctx, path, "find_file")
    if why:
        return why
    p = _inside_ws(str(path or "."))
    if not p:
        return f"refused: {path} is outside the active repo ({_rel_home(root())})"
    if not os.path.isdir(p):
        return f"no such directory {path} in {_rel_home(root())}"
    pat = name if any(c in name for c in "*?[") else f"*{name}*"
    cmd = ["find", p, "-type", "f", "-iname", pat,
           "-not", "-path", "*/.git/*", "-not", "-path", "*/node_modules/*",
           "-not", "-path", "*/__pycache__/*", "-not", "-path", "*/profile-*/*"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, cwd=root(),
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return f"find timed out after 30s under {_rel_home(p)}: narrow it with path=<a subfolder>"
    hits = [h for h in (r.stdout or "").splitlines() if h.strip()][:60]
    if not hits:
        return f"no file named {pat} under {_rel_home(p)}"
    out = "\n".join(_rel_home(h) for h in hits)
    more = "" if len(hits) < 60 else "\n(60 shown; narrow the name or the path for the rest)"
    return f"{len(hits)} file(s) matching {pat} under {_rel_home(p)}:\n{out}{more}"


def _grep_windows(ctx, pattern, path, around, max_hits):
    """T1.2 (spec SPEC-0security-alignment-20261109): byte windows around a regex in ONE file. F11 receipt: the lead
    read a one-line minified bundle by slicing it around `hasIntercom` one model round trip at a time; a line-based
    grep cannot window a single 2 MB line. idea: 0sec-labs/0 packages/core/src/agent/output-truncation.ts
    (bounded large output); reimplemented, no code copied. The fence, workspace and secrets refusals run BEFORE
    any byte is read."""
    (
        GREP_AROUND_MAX, GREP_WINDOW_READ_MAX, _inside_ws, _is_secret, _rel, _rel_home,
        _session_hint, _spill, os, re, root,
    ) = bind(
        "GREP_AROUND_MAX", "GREP_WINDOW_READ_MAX", "_inside_ws", "_is_secret", "_rel",
        "_rel_home", "_session_hint", "_spill", "os", "re", "root",
    )
    p = _inside_ws(path)
    if not p:
        return f"refused: {path} is outside the active repo ({_rel_home(root())}); use a path inside it"
    if _is_secret(p):
        return ("refused: that is a secrets file (.env / private key); its values never go into the chat"
                + _session_hint(ctx))
    if not os.path.isfile(p):
        return (f"bad arguments: around= reads byte windows in ONE file; {path} is "
                + ("a directory" if os.path.isdir(p) else "not a file") + ". Pass the file path, or drop around=.")
    try:
        rx = re.compile(str(pattern).encode("utf-8", "surrogateescape"))
    except re.error:
        rx = re.compile(re.escape(str(pattern).encode("utf-8", "surrogateescape")))
    around = max(1, min(int(around), GREP_AROUND_MAX))
    max_hits = max(1, min(int(max_hits or 5), 20))
    with open(p, "rb") as f:
        blob = f.read(GREP_WINDOW_READ_MAX)
    out = []
    for m in rx.finditer(blob):
        i, j = m.start(), m.end()
        win = blob[max(0, i - around):j + around].decode("utf-8", "replace")
        out.append(f"@{i}: {win}")
        if len(out) >= max_hits:
            break
    if not out:
        return f"(no matches for /{pattern}/ in {_rel(p)}, {len(blob)} bytes read)"
    head = f"{_rel(p)}: {len(out)} window(s) of +-{around} bytes" + (
        f" (first {GREP_WINDOW_READ_MAX // (1024 * 1024)} MB read)" if len(blob) >= GREP_WINDOW_READ_MAX else "")
    return _spill(head + "\n" + "\n\n".join(out), "grep")


GREP_PER_FILE = 20      # matches per file on a tree search (a single named file gets GREP_ONE_FILE)
GREP_ONE_FILE = 200
GREP_LINES = 300
GREP_LINE_MAX = 300


def t_grep(ctx, pattern, path=".", glob=None, around=0, max_hits=5, ignore_case=False, files_only=False,
           context=0):
    (
        WS, _fence, _grep_windows, _inside_ws, _is_secret, _rel_home, os, root,
        subprocess,
    ) = bind(
        "WS", "_fence", "_grep_windows", "_inside_ws", "_is_secret", "_rel_home", "os",
        "root", "subprocess",
    )
    path = str(path or ".")
    why = _fence(ctx, path)
    if why:
        return why
    try:
        around = int(around or 0)
    except (TypeError, ValueError):
        return "bad arguments: around is a number of bytes (0 = normal line grep, max 4000)"
    if around > 0 and os.path.isdir(_inside_ws(path) or ""):
        # around= is for ONE file; over a folder it is the ordinary search. gpt-oss sends around=2 with every
        # grep and was refused five times in one turn for it (BB drive 2026-11-21).
        around = 0
    if around > 0:
        if not str(pattern or ""):
            return "bad arguments: grep needs a non-empty pattern"
        return _grep_windows(ctx, pattern, path, around, max_hits)
    if not glob and any(c in path for c in "*?[") and not os.path.exists(_inside_ws(path) or ""):
        path, glob = (os.path.dirname(path) or "."), os.path.basename(path)  # path='*.md' meant glob='*.md'
    if not str(pattern or ""):
        return "bad arguments: grep needs a non-empty pattern (an extended regex, e.g. 'def t_\\w+')"
    p = _inside_ws(path)
    if not p:
        return f"refused: {path} is outside the active repo ({_rel_home(root())}); use a path inside it"
    if not os.path.exists(p):
        return f"no such path {path} in {_rel_home(root())}: grep path=. searches everything here"
    # The hunt workspace holds 1.66 MILLION files, nearly all of them captured bytes under targets/.
    # A root grep can never finish inside the 60 s cap, so "grep path=." used to be a guaranteed timeout
    # and the model would then widen or give up (soak 2026-10-25). Root means the CODE AND DOCS, and the
    # answer says how to search a program's own material.
    roots, scoped = [p], False
    if os.path.realpath(p) == os.path.realpath(WS):
        fenced = (getattr(ctx, "s", None) or {}).get("_program_fence") if isinstance(getattr(ctx, "s", None),
                                                                                    dict) else None
        picked = [d for d in ("scripts", "reports", "patterns", "Manual", ".claude/skills", "intake")
                  if os.path.isdir(os.path.join(WS, d)) and not (fenced and d == "reports")]
        # NB: this function's own `glob` parameter shadows the glob module, so list the top-level
        # docs with listdir rather than reaching for it
        tops = [os.path.join(WS, f) for f in sorted(os.listdir(WS)) if f.endswith(".md")]
        roots = [os.path.join(WS, d) for d in picked] + tops
        scoped = True
    one_file = os.path.isfile(p)
    per_file = GREP_ONE_FILE if one_file else GREP_PER_FILE
    try:
        context = max(0, min(int(context or 0), 5))
    except (TypeError, ValueError):
        context = 0
    # -Z: the file name ends in a NUL on match AND context lines (`file-12-text` context lines carried a dash, so
    # the secrets-file filter never matched them and a key body leaked with context=2, QAQC r2)
    flags = "-rIEZ" + ("" if files_only else "n") + ("i" if ignore_case else "") + ("l" if files_only else "")
    cmd = ["grep", flags, "--exclude-dir=.git", "--exclude-dir=node_modules", "--exclude-dir=salvage",
           "--exclude-dir=build", "--exclude-dir=dist", "--exclude-dir=__pycache__", "--exclude-dir=.venv",
           "--exclude-dir=worktrees", "--exclude-dir=profile-*",  # browser profiles: megabytes, no content
           "--exclude=.env*", "--exclude=*.pem", "--exclude=*.key", "--exclude=*.bak*",
           "-m", str(per_file), "-e", pattern] + roots  # -e: a pattern like --accent is not an option
    if context and not files_only:
        cmd.insert(2, f"-C{context}")
    if glob:  # grep --include matches basenames: '**/*.css' and 'public/*.css' both mean '*.css'
        cmd.insert(1, f"--include={glob.rsplit('/', 1)[-1]}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=root(), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return f"grep timed out after 60s over {_rel_home(p)}: narrow it with path=<a subfolder> or glob='*.py'"
    if r.returncode == 2 and not r.stdout:
        return (f"grep error: {r.stderr.strip()[:300]} - the pattern is an extended regex (grep -E): escape ( ) "
                "[ { + ? | with a backslash to match them literally")
    secret = {}

    def from_secret(line):  # drop every match that comes from a secrets file, not only its BEGIN line
        f = line.split("\0", 1)[0] if "\0" in line else line.split(":", 1)[0]
        if f not in secret:
            secret[f] = _is_secret(f) or bind("gnoc_secrets")[0].is_secret_path(f)
        return secret[f]
    note = ("\n(root grep searched the code and docs: scripts, reports, patterns, Manual, intake and the "
            "top-level *.md. The workspace holds 1.66M files, nearly all captured bytes under targets/, so a "
            "true root grep cannot finish. For a program's own material pass path='targets/<program>'.)"
            if scoped else "")
    lines = [l.replace("\0", "" if files_only else ":", 1) for l in r.stdout.splitlines() if not from_secret(l)]
    # Say every cut out loud. The per-file cap, the line cap and the line-width cut were all silent: a search
    # that stopped at 20 matches in a file read as "these are all the call sites".
    cuts = []
    if not files_only and not context:
        per = {}
        for l in lines:
            f = l.split(":", 1)[0]
            per[f] = per.get(f, 0) + 1
        # one named file: grep prints no file name, so the count is the whole output
        capped = ([path] if len(lines) >= per_file else []) if one_file else [f for f, n in per.items() if n >= per_file]
        if capped:
            cuts.append(f"{len(capped)} file(s) stopped at {per_file} matches each ("
                        + ", ".join(c.replace(root() + "/", "") for c in capped[:4])
                        + (" ..." if len(capped) > 4 else "") + "): grep that file alone (path=<file>) for up to "
                        f"{GREP_ONE_FILE}, or narrow the pattern")
    if len(lines) > GREP_LINES:
        cuts.append(f"showing the first {GREP_LINES} of {len(lines)} lines: narrow the path or glob, or "
                    "files_only=true for just the file names")
    wide = 0

    def cut(l):
        nonlocal wide
        l = l.replace(root() + "/", "")
        if len(l) <= GREP_LINE_MAX:
            return l
        wide += 1
        return l[:GREP_LINE_MAX] + f"...[+{len(l) - GREP_LINE_MAX} chars]"
    out = "\n".join(cut(l) for l in lines[:GREP_LINES])
    if wide:
        cuts.append(f"{wide} long line(s) shown cut (marked ...[+N chars]); grep around=300 path=<file> shows "
                    "the bytes around a match")
    if out:
        return out + note + ("\n[" + "; ".join(cuts) + "]" if cuts else "")
    return out or (f"(no matches for /{pattern}/ under {_rel_home(p)}"
                   + (f" in files named {glob.rsplit('/', 1)[-1]}" if glob else "") + ")")


def _diff(old, new, name):
    (
        DIFF_MAX, _diff_rows,
    ) = bind(
        "DIFF_MAX", "_diff_rows",
    )
    rows, adds, dels = _diff_rows(old, new)
    return (f"(+{adds} -{dels})\n" + "\n".join(r[:400] for r in rows[:DIFF_MAX])
            + (f"\n   ⋯ {len(rows) - DIFF_MAX} more diff lines" if len(rows) > DIFF_MAX else ""))


def _secret_write_refusal(text):
    (
        gnoc_secrets,
    ) = bind(
        "gnoc_secrets",
    )
    names = gnoc_secrets.find(text)
    return (f"refused: the content contains the value of {', '.join(names)}. Write the credential's NAME, never "
            "its value.") if names else None


def undo(ctx, n=1, force=False):
    """Undo the last n file writes of this conversation, newest first. A file changed since the agent wrote it
    (by the user, the shell or another tool) is left alone unless force: undo never clobbers someone else's edit."""
    (
        _checkpoints, _ckpt_path, _inside_ws, _read, _rel, _sha, _write_refusal,
        contextlib, json, os,
    ) = bind(
        "_checkpoints", "_ckpt_path", "_inside_ws", "_read", "_rel", "_sha",
        "_write_refusal", "contextlib", "json", "os",
    )
    rows = _checkpoints(ctx)
    if not rows:
        return ["nothing to undo in this conversation"]
    out, keep = [], rows[:]
    for row in reversed(rows[-n:]):
        p = str(row.get("path") or "")
        if p.startswith("ssh://"):
            why = _undo_remote(ctx, row, force)
            if why:
                out.append(why)
                break
            out.append(f"restored {p}" if row["existed"] else f"removed {p} (the agent had created it)")
            keep.pop()
            continue
        if _inside_ws(p) != os.path.realpath(p) or _write_refusal(os.path.realpath(p)):
            # the checkpoint file is on disk; a forged or stale row must not become a write outside the repo
            out.append(f"skipped {p}: outside the active repo or protected")
            break
        cur = _load_exact(p)[2] if os.path.isfile(p) else None
        if cur is not None and _sha(cur) != row["after_sha"] and _sha(_read(p)) != row["after_sha"] and not force:
            out.append(f"skipped {_rel(p)}: changed since the agent wrote it (/undo {n} force to override)")
            break
        if "before" not in row:
            out.append(f"skipped {_rel(p)}: too large to have been checkpointed")
            break
        if row["existed"]:
            _write_exact(p, row["before"])   # the exact text: CRLF and non-UTF-8 bytes come back as they were
            out.append(f"restored {_rel(p)}")
        else:
            with contextlib.suppress(OSError):
                os.remove(p)
            out.append(f"removed {_rel(p)} (the agent had created it)")
        keep.pop()
    with open(_ckpt_path(ctx), "w") as f:
        f.writelines(json.dumps(r) + "\n" for r in keep)
    return out


def _undo_remote(ctx, row, force=False):
    """Undo one checkpoint taken on an ssh sandbox: only through that same host, only inside its directory, never
    over a file changed since, never onto a protected name. '' when it was put back, else why it was not."""
    import gnoc_sandbox
    (WRITE_DENY, _sha) = bind("WRITE_DENY", "_sha")
    key = str(row.get("path") or "")
    host, _, rest = key[len("ssh://"):].partition("/")
    path = "/" + rest
    be = gnoc_sandbox.for_session(getattr(ctx, "s", None))
    if be.kind != "ssh" or be.host != host:
        return f"skipped {key}: taken on the ssh sandbox {host}; type /sandbox ssh {host} first to undo it there"
    import posixpath   # a remote path is POSIX whatever this machine is
    if not be.inside_dir(path) or WRITE_DENY.search(posixpath.relpath(path, be.dir)) or "/.git/" in path + "/":
        return f"skipped {key}: outside {be.dir} or protected"
    if "before" not in row:
        return f"skipped {key}: too large to have been checkpointed"
    cur = be.read_many([path]).get(path)
    if cur is not None and _sha(cur) != row.get("after_sha") and not force:
        return f"skipped {key}: changed since the agent wrote it (/undo force to override)"
    ok, msg = be.restore(path, row["before"], row["existed"])
    return "" if ok else f"skipped {key}: the restore failed on {host} ({msg})"


def changes(ctx):
    """Every file the agent wrote in this conversation: its diff from before the first write to now."""
    (
        _checkpoints, _diff_rows, _read, _rel, os,
    ) = bind(
        "_checkpoints", "_diff_rows", "_read", "_rel", "os",
    )
    first = {}
    for row in _checkpoints(ctx):
        if str(row.get("path") or "").startswith("ssh://"):
            continue   # on an ssh sandbox host: /undo puts it back there; there is no local copy to diff
        first.setdefault(row["path"], row)
    out = []
    for p, row in first.items():
        before = (row.get("before", "") if row["existed"] else "").replace("\r\n", "\n")
        now = _load_exact(p)[0] if os.path.isfile(p) else ""
        if before == now:
            continue
        state = "new" if not row["existed"] else ("deleted" if not os.path.isfile(p) else "changed")
        out.append((_rel(p), state, _diff_rows(before, now)))
    return out


def _is_capture(path):
    (
        _EVIDENCE_CLOSED, _RAW_DIRS, _RAW_EXT,
    ) = bind(
        "_EVIDENCE_CLOSED", "_RAW_DIRS", "_RAW_EXT",
    )
    r = "/" + str(path or "").replace("\\", "/").lstrip("/")
    return (any(d in r for d in _RAW_DIRS) or r.lower().endswith(_RAW_EXT)
            or bool(_EVIDENCE_CLOSED.search(r)))


def _gate_owned(path):
    (
        _GATE_OWNED, _is_capture,
    ) = bind(
        "_GATE_OWNED", "_is_capture",
    )
    r = str(path or "").replace("\\", "/")
    if _is_capture(r):
        return (f"refused: {r} is a CAPTURE. Raw bytes off the wire are evidence and are never edited, by "
                "anyone, for any reason - every sha, every byte-faithfulness check and every report quote "
                "depends on them being untouched (T-106, T-107). If the capture does not say what you need, "
                "the answer is to FIRE THE REQUEST THAT WOULD, and cite that new file. If it refutes your "
                "hypothesis, record the refutation: that is a result, not an obstacle.")
    for suffix in _GATE_OWNED:
        if r.endswith(suffix) or (suffix.lstrip("/") == r):
            return (f"refused: {r} is written by the harness (js_mine, the hypothesis ledger, the scope intake), not "
                    f"by the model. A route typed into known-paths.txt is not a mined route; a status typed into the "
                    f"ledger skips its gates. Use js_mine for routes and hunt_hypothesis for the ledger.")
    return None


def _gate_owned_real(path):
    """_gate_owned on the path as typed AND as it resolves: `x.hdr/.`, a doubled slash or a trailing slash
    resolve to the protected capture or ledger while the typed text matched nothing (QAQC 2026-11-19)."""
    (
        STATE, _gate_owned, _inside_ws, os,
    ) = bind(
        "STATE", "_gate_owned", "_inside_ws", "os",
    )
    why = _gate_owned(path)
    if why:
        return why
    p = _inside_ws(str(path or ""))
    if not p:
        return None
    for base in (STATE.ws, os.path.realpath(STATE.ws)):
        if p.startswith(base + os.sep):
            return _gate_owned(os.path.relpath(p, base))
    return _gate_owned(p)


def t_write_file(ctx, path, content):
    (
        _gate_owned_real, _inside_ws, _sandbox_fence, _t_write_file_body,
    ) = bind(
        "_gate_owned_real", "_inside_ws", "_sandbox_fence", "_t_write_file_body",
    )
    why = _sandbox_fence(ctx, path, "write_file")
    if why:
        return why
    owned = _gate_owned_real(path)
    if owned:
        return owned
    with _locked([_inside_ws(str(path or "")) or str(path or "")]):
        return _t_write_file_body(ctx, path, content)


def _t_write_file_body(ctx, path, content):
    (
        _checkpoint, _diff, _inside_ws, _read, _rel, _secret_write_refusal,
        _write_refusal, os,
    ) = bind(
        "_checkpoint", "_diff", "_inside_ws", "_read", "_rel", "_secret_write_refusal",
        "_write_refusal", "os",
    )
    content = "" if content is None else str(content)
    why = _secret_write_refusal(content)
    if why:
        return why
    p = _inside_ws(str(path or ""))
    why = _write_refusal(p, content, whole_file=True)
    if why:
        return why
    if os.path.isdir(p):
        return f"refused: {path} is a directory; give a file path inside it"
    existed = os.path.isfile(p)
    if existed:
        why = _stale(ctx, p)
        if why:
            return why.replace("make the change", "write it")
    old, nl, raw = _load_exact(p) if existed else ("", "\n", "")
    lost = _dropped_tests(old, content) if existed and not _made_here(ctx, p) else []
    if lost:
        # SWE batch 1: "add a `done N` command ... with a test" rewrote test_todo.py whole and the existing
        # test_add_and_list was gone; the suite still "passed" with only the new test in it
        return (f"refused: this rewrite of {_rel(p)} deletes its existing test(s) {', '.join(lost[:5])}. Add the new "
                "test beside them with edit_file (old = the file's last lines, new = those lines plus your test), "
                "or put it in a new test file. Delete a test only when the user asks.")
    if existed and old == content:
        # "updated x (+0 -0)" read as success: the model re-sent the same buggy file five times believing its fix
        # was in it, then the repeat breaker cut the turn off untested (SWE gauntlet 2026-10-24)
        return (f"NOTHING CHANGED: the content you sent is byte-identical to {_rel(p)} as it already is, so the "
                "change you intended is NOT in it. Do not resend the whole file: use edit_file with old = the exact "
                "current line(s) you want to change (read_file them) and new = the fixed line(s).")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    exact = _exact_out(content, nl)   # an existing CRLF file stays CRLF
    _checkpoint(ctx, p, raw, existed, exact)
    _write_exact(p, exact)
    _mark_seen(ctx, p)
    return f"{'updated' if old else 'created'} {_rel(p)} " + _diff(old, content, _rel(p))


def _made_here(ctx, p):
    """True when this conversation created the file (its first checkpoint says it did not exist). Its tests are the
    model's own work in progress: SWE batch 2 wrote a Jest-style test file, then was refused twice converting it to
    node:test, because the rewrite 'deleted' the tests it had written a minute before."""
    with _contextlib.suppress(Exception):
        rows = __import__("gnoc_core.session", fromlist=["_checkpoints"])._checkpoints(ctx)
        first = next((r for r in rows if r.get("path") == p), None)
        return bool(first) and first.get("existed") is False
    return False


def _dropped_tests(old, new):
    """Test names the old text defines that the new text no longer has (pytest/unittest defs, node/jest test("..."),
    Go func TestX)."""
    rx = __import__("re").compile(r"(?m)^\s*(?:async\s+)?def\s+(test\w*)\s*\(|^\s*func\s+(Test\w*)\s*\(|"
                                  r"\b(?:test|it)\(\s*[\"'`]([^\"'`]{1,80})[\"'`]")
    names = lambda t: {next(g for g in m.groups() if g) for m in rx.finditer(str(t or ""))}
    return sorted(names(old) - names(new))


def t_edit_file(ctx, path, old=None, new=None, start_line=None, end_line=None, replace_all=False, edits=None,
                cell=None, cell_action="replace", cell_type=None):
    (
        _gate_owned_real, _inside_ws, _sandbox_fence, _t_edit_file_body,
    ) = bind(
        "_gate_owned_real", "_inside_ws", "_sandbox_fence", "_t_edit_file_body",
    )
    why = _sandbox_fence(ctx, path, "edit_file")
    if why:
        return why
    owned = _gate_owned_real(path)
    if owned:
        return owned
    with _locked([_inside_ws(str(path or "")) or str(path or "")]):
        if cell is not None and not str(path or "").lower().endswith(".ipynb") \
                and (old is not None or edits or start_line is not None):
            # gpt-oss fills every field of the schema: cell='0', cell_action='insert', cell_type='python' beside a
            # real old/new on a .py file, refused three times in a row and a task to the 420 s cap (SWE drive
            # 2026-11-22). The notebook fields mean nothing for this file; the edit it describes goes ahead.
            cell = None
        if cell is not None or str(path or "").lower().endswith(".ipynb"):
            return _edit_notebook(ctx, path, cell, new, cell_action, cell_type)
        if edits:
            return _edit_many(ctx, path, edits)
        return _t_edit_file_body(ctx, path, old, new, start_line, end_line, replace_all=replace_all)


def _edit_many(ctx, path, edits):
    """Several old -> new replacements in ONE file, applied in order, all or nothing. Each must match exactly once
    in the text as the earlier ones left it (replace_all=true on an edit lifts that for that edit)."""
    (
        _checkpoint, _diff, _inside_ws, _read, _rel, _secret_write_refusal, _write_refusal, json, os,
    ) = bind(
        "_checkpoint", "_diff", "_inside_ws", "_read", "_rel", "_secret_write_refusal", "_write_refusal", "json",
        "os",
    )
    if isinstance(edits, str):
        try:
            edits = json.loads(edits)
        except ValueError:
            return "bad arguments: edits is a list of {old, new} objects"
    if not isinstance(edits, list) or not edits or not all(isinstance(e, dict) for e in edits):
        return "bad arguments: edits is a list of {old, new} objects (optional replace_all per edit)"
    p = _inside_ws(str(path or ""))
    if not p or not os.path.isfile(p):
        return f"no such file in the active repo: {path} (edit_file only changes an existing file)"
    why = _write_refusal(p)
    if why:
        return why
    text, nl, raw = _load_exact(p)
    after = text
    for k, e in enumerate(edits, 1):
        o, n = e.get("old"), e.get("new")
        if not isinstance(o, str) or not o or not isinstance(n, str):
            return f"refused: edit {k} needs old (non-empty) and new; nothing was changed"
        why = _secret_write_refusal(n)
        if why:
            return why
        c = after.count(o)
        if c == 0 and not e.get("replace_all"):
            got = _reindent_match(after, o, n)
            if got:
                o, n, c = after[got[0]:got[1]], got[2], 1
        if c == 0:
            # An edits list changes ONE file. A rename's two edits (the def in store.py, the call in
            # tests/test_store.py) sent as one list was refused with "read_file and copy it exactly", which is
            # wrong advice: the text was copied exactly, from the other file. The lead resent it, tried sed, and
            # the turn ended empty (verification drive 2026-11-21). Say where the text is.
            try:
                other = bind("_file_with_unique")[0](o)
            except Exception:   # noqa: BLE001 - a hint is never worth a failed edit
                other = None
            if other and os.path.realpath(os.path.join(bind("root")[0](), other)) != os.path.realpath(p):
                return (f"refused: edit {k} of {len(edits)}: its old text is not in {_rel(p)}, it is in {other}. An "
                        f"edits list changes ONE file, so nothing was changed. Call edit_file path='{_rel(p)}' with "
                        f"only the edits for that file, then edit_file path='{other}' with this one.")
            return (f"refused: edit {k} of {len(edits)}: old text not found in {_rel(p)} (after the edits before "
                    "it); nothing was changed. read_file and copy it exactly.")
        if c > 1 and not e.get("replace_all"):
            return (f"refused: edit {k} of {len(edits)}: old text found {c} times in {_rel(p)}; add context so it is "
                    "unique, or set replace_all=true on that edit. Nothing was changed.")
        after = after.replace(o, n) if e.get("replace_all") else after.replace(o, n, 1)
    if after == text:
        return f"NOTHING CHANGED: the edits leave {_rel(p)} exactly as it was."
    exact = _exact_out(after, nl)
    _checkpoint(ctx, p, raw, True, exact)
    _write_exact(p, exact)
    _mark_seen(ctx, p)
    return f"edited {_rel(p)} ({len(edits)} edits) " + _diff(text, after, _rel(p))


def _edit_notebook(ctx, path, cell, new, cell_action="replace", cell_type=None):
    (
        _checkpoint, _inside_ws, _rel, _secret_write_refusal, _write_refusal, gnoc_notebook, os,
    ) = bind(
        "_checkpoint", "_inside_ws", "_rel", "_secret_write_refusal", "_write_refusal", "gnoc_notebook", "os",
    )
    p = _inside_ws(str(path or ""))
    if not p or not os.path.isfile(p):
        return f"no such notebook in the active repo: {path}"
    if not p.lower().endswith(".ipynb"):
        return "bad arguments: cell= is for Jupyter notebooks (.ipynb); for other files use old/new or start_line"
    if cell is None:
        return ("bad arguments: a notebook is edited one cell at a time: cell=<number from read_file> new=<source>"
                " (cell_action=insert|delete)")
    if str(cell_action or "").lower() == "insert" and not str(new or "").strip():
        # an insert with no source put an EMPTY cell in the notebook; the lead then inserted the real one and
        # reported "a second cell" in a notebook that had three (verification drive 2026-11-21)
        return ("bad arguments: an inserted cell needs new=<its source>, in the same call. Nothing was changed. "
                "Example: cell=1 cell_action='insert' new='print(len(store.items))'")
    took = ""
    _re, _json = __import__("re"), __import__("json")
    if isinstance(new, str) and _re.search(r'"cell_type"\s*:', new) and _re.search(r'"source"\s*:', new):
        # new= is the cell's SOURCE. Handed the notebook's own JSON for a cell ('"cell_type": "code", ...
        # "source": [...]'), it was stored as the code, the cell was broken, and the lead said it "prints the
        # number of SKUs" (tool drive 2026-11-21). The source inside it is taken out; if it cannot be, nothing is
        # written.
        m = _re.search(r'"source"\s*:\s*(\[.*?\]|"(?:[^"\\]|\\.)*")', new, _re.S)
        src = None
        if m:
            try:
                src = _json.loads(m.group(1))
            except ValueError:
                src = None
        if isinstance(src, list) and all(isinstance(x, str) for x in src):
            src = "".join(src)
        if not isinstance(src, str) or not src.strip():
            return ("bad arguments: new= must be the cell's source code (the Python or Markdown text), not notebook "
                    "JSON. Send only what belongs inside the cell, for example new='print(len(store.items))'")
        kind = _re.search(r'"cell_type"\s*:\s*"(code|markdown|raw)"', new)
        cell_type = cell_type or (kind.group(1) if kind else None)
        new, took = src, " (new= was notebook JSON; its source was taken out and stored as the cell)"
    why = _write_refusal(p) or _secret_write_refusal(new or "")
    if why:
        return why
    why = _stale(ctx, p)
    if why:
        return why
    try:
        before, after, msg = gnoc_notebook.edit_cell(p, cell, new, cell_action, cell_type)
    except ValueError as e:
        return f"refused: {e}; nothing changed"
    _checkpoint(ctx, p, before, True, after)
    with open(p, "w", encoding="utf-8") as f:
        f.write(after)
    _mark_seen(ctx, p)
    return f"{msg} in {_rel(p)}{took}; read_file it to see the cells now"


def _t_edit_file_body(ctx, path, old=None, new=None, start_line=None, end_line=None, replace_all=False):
    (
        _checkpoint, _closest_hint, _diff, _edit_lines, _inner_ws_match, _inside_ws,
        _read, _rel, _secret_write_refusal, _write_refusal, os,
    ) = bind(
        "_checkpoint", "_closest_hint", "_diff", "_edit_lines", "_inner_ws_match",
        "_inside_ws", "_read", "_rel", "_secret_write_refusal", "_write_refusal", "os",
    )
    why = _secret_write_refusal(new)
    if why:
        return why
    p = _inside_ws(str(path or ""))
    if not p or not os.path.isfile(p):
        return (f"no such file in the active repo: {path} (edit_file only changes an existing file; write_file "
                "creates one)")
    why = _write_refusal(p)
    if why:
        return why
    if new is None:
        if old is not None and (start_line is not None or end_line is not None):
            # old + start_line/end_line and no new: 6 of 14 malformed edits in one SWE drive batch (2026-11-20)
            return ("bad arguments: edit_file needs new (the replacement text; \"\" deletes). You sent old AND a "
                    "line range: pick ONE mode - old=<exact current text> + new=<replacement>, or start_line/"
                    "end_line + new=<replacement for those lines> (no old).")
        return ("bad arguments: edit_file needs new (the replacement text; \"\" deletes), in the SAME call: "
                "edit_file(path, old=<exact current text>, new=<what it becomes>)")
    if not old and start_line is not None:
        why = _stale(ctx, p)   # line numbers from an old read point at the wrong lines once the file moved
        if why:
            return why
        return _edit_lines(ctx, p, start_line, end_line, str(new))
    old, new = str(old or ""), str(new)
    if not old:
        if end_line is not None:
            # new + end_line, no start_line and no old: the other half of the same mix-up (2026-11-20 SWE drive)
            return ("bad arguments: you sent new and end_line without start_line. Line mode needs BOTH start_line "
                    "and end_line (the numbers read_file shows) + new; or use old=<exact current text> + new and "
                    "no line numbers.")
        return ("refused: old is empty; give the exact existing text to replace (read_file first), or start_line "
                "and end_line (the line numbers read_file shows) to replace whole lines")
    text, nl, raw = _load_exact(p)
    n = text.count(old)
    note = ""
    if n == 0:
        span = _inner_ws_match(text, old)
        if span:
            # unique once runs of spaces INSIDE lines are ignored (indentation still exact): a column-aligned usage
            # table re-typed with one space off sent the lead into od/xxd/hexdump for 6 steps (2026-10-24)
            old, n = text[span[0]:span[1]], 1
            note = " (matched ignoring the width of spacing inside lines; indentation matched exactly)"
        elif old.strip() and text.count(old.strip()) == 1:
            # only the whitespace at the two EDGES differed (the first line's indentation, a trailing newline): the
            # file keeps its own edge whitespace and the model's new text drops its version of it. The lead used
            # its remaining steps on write_file and sed after this exact refusal (2026-10-24)
            old, new, n = old.strip(), new.strip(), 1
            note = " (matched with the file's own indentation at the start and whitespace at the end)"
        elif _reindent_match(text, old, new):
            a, b, new = _reindent_match(text, old, new)
            old, n = text[a:b], 1
            note = " (matched reading your tabs as the file's spaces, or the reverse; new was converted the same way)"
        elif _numbered(old) and text.count(_unnumber(old)) == 1:
            # old copied from read_file WITH its line numbers ("14\tdef empty(store):"): four refusals and a loop
            # breaker on a merge-conflict fix (SWE drive 2026-11-22). The numbers are read_file's, not the file's.
            old, n, both = _unnumber(old), 1, _numbered(new)
            new = _unnumber(new) if both else new
            note = " (matched after removing read_file's line numbers from old" + (" and new" if both else "") + ")"
        else:
            return (f"refused: old text not found in {_rel(p)}. " + _closest_hint(text, old)
                    + "Copy the old text byte for byte from the lines shown (read_file them if none are shown), or "
                    "edit a smaller span.")
    if n != 1 and not replace_all:
        return (f"refused: old text found {n} times in {_rel(p)}; it must match exactly once - add the "
                "neighbouring line(s) so it is unique, or replace_all=true to change every one")
    if old == new:
        return (f"NOTHING CHANGED: old and new are identical, so {_rel(p)} is as it was. Put the corrected text in "
                "new.")
    after = text.replace(old, new) if replace_all else text.replace(old, new, 1)
    if replace_all and n > 1:
        note += f" ({n} occurrences replaced)"
    exact = _exact_out(after, nl)
    _checkpoint(ctx, p, raw, True, exact)
    _write_exact(p, exact)
    _mark_seen(ctx, p)
    return f"edited {_rel(p)}{note} " + _diff(text, after, _rel(p))


def _lines_after(text, start_line, end_line, new):
    """(text after replacing lines start..end with new, a, b, error-or-None). Pure: the edit and the approval
    preview share it."""
    try:
        a = int(start_line)
        b = int(end_line if end_line is not None else start_line)
    except (TypeError, ValueError):
        return None, 0, 0, "bad arguments: start_line and end_line are line numbers (integers)"
    lines = text.split("\n")
    trailing = text.endswith("\n")
    if trailing:
        lines = lines[:-1]
    if not (1 <= a <= b <= len(lines)):
        return None, a, b, f"refused: lines {a}-{b} are outside {{file}} (it has {len(lines)} lines)"
    repl = new[:-1] if new.endswith("\n") else new
    after_lines = lines[:a - 1] + (repl.split("\n") if new else []) + lines[b:]
    return "\n".join(after_lines) + ("\n" if trailing else ""), a, b, None


def _edit_lines(ctx, p, start_line, end_line, new):
    """Replace lines start_line..end_line (1-based, inclusive, the numbers read_file shows) with new. No old text
    to copy: the 35B lead could not reproduce a 16-line function with a nested f-string byte for byte (four
    misses at 99.6% similar, 2026-10-24), and a line range needs no copying at all."""
    (
        _checkpoint, _diff, _lines_after, _read, _rel,
    ) = bind(
        "_checkpoint", "_diff", "_lines_after", "_read", "_rel",
    )
    text, nl, raw = _load_exact(p)
    after, a, b, err = _lines_after(text, start_line, end_line, new)
    if err:
        return err.replace("{file}", _rel(p))
    if after == text:
        return f"NOTHING CHANGED: lines {a}-{b} of {_rel(p)} already read exactly like new."
    exact = _exact_out(after, nl)
    _checkpoint(ctx, p, raw, True, exact)
    _write_exact(p, exact)
    _mark_seen(ctx, p)
    return f"edited {_rel(p)} (lines {a}-{b} replaced) " + _diff(text, after, _rel(p))


def _reindent_match(text, old, new):
    """(start, end, new) when `old` is a UNIQUE run of whole lines of `text` once each line's leading whitespace is
    read one consistent way - the model's tabs for the file's spaces (or the reverse) at one width - with `new`
    converted the same way, so every line keeps its nesting level. None when the reading is not consistent on
    every line, or would need a shift to another level: then nothing is guessed.
    The 35B lead typed tab indentation into old for a 4-space file twice in a row, in edits=[...] where nothing was
    tolerant, then rewrote the whole file with write_file (2026-11-20 SWE drive)."""
    flines, olines, nlines = text.split("\n"), old.split("\n"), new.split("\n")
    lead = trail = 0
    while olines and not olines[0].strip():
        olines.pop(0)
        lead += 1
    while olines and not olines[-1].strip():
        olines.pop()
        trail += 1
    for _ in range(lead):
        if nlines and not nlines[0].strip():
            nlines.pop(0)
    for _ in range(trail):
        if nlines and not nlines[-1].strip():
            nlines.pop()
    if not olines:
        return None
    want = [ln.strip() for ln in olines]
    hits = [i for i in range(len(flines) - len(olines) + 1)
            if all(flines[i + j].strip() == want[j] for j in range(len(olines)))]
    if len(hits) != 1:
        return None
    i = hits[0]

    def ind(s):
        return s[:len(s) - len(s.lstrip(" \t"))]
    pairs = [(ind(olines[j]), ind(flines[i + j])) for j in range(len(olines)) if olines[j].strip()]

    def tabs_to_spaces(w):
        return lambda m: m.replace("\t", " " * w)

    def spaces_to_tabs(w):
        return lambda m: (None if (len(m) % w or m.strip(" ")) else "\t" * (len(m) // w))
    convert = None
    for cand in [tabs_to_spaces(w) for w in (4, 8, 2)] + [spaces_to_tabs(w) for w in (4, 8, 2)]:
        if all(cand(mi) == fi for mi, fi in pairs):
            convert = cand
            break
    if convert is None:
        # Only the REPRESENTATION of one nesting level may differ (tabs for spaces). A snippet typed one level
        # in or out is refused: matching it would move a Python block to another level, which this tool never
        # does (test_edit_tolerates_inner_spacing_but_never_indentation).
        return None
    out = []
    for ln in nlines:
        if not ln.strip():
            out.append("")
            continue
        got = convert(ind(ln))
        if got is None:
            return None
        out.append(got + ln.lstrip(" \t"))
    start = sum(len(x) + 1 for x in flines[:i])
    end = start + len("\n".join(flines[i:i + len(olines)]))
    return start, end, "\n".join(out)


def _inner_ws_match(text, old):
    """(start, end) of the ONE span of text that equals old when every run of spaces/tabs after a line's first
    non-blank character is treated as a single space; None when there is no match or more than one. Leading
    indentation is compared exactly, so a Python block can never be re-indented by this."""
    (
        re,
    ) = bind(
        "re",
    )
    lines = old.split("\n")
    if not old.strip() or len(lines) > 200:
        return None

    def pat(ln):
        m = re.match(r"^([ \t]*)(.*)$", ln)
        body = re.split(r"[ \t]+", m.group(2))
        return re.escape(m.group(1)) + r"[ \t]+".join(re.escape(x) for x in body)
    rx = re.compile("\n".join(pat(ln) for ln in lines))
    hits = [m.span() for m in rx.finditer(text)]
    return hits[0] if len(hits) == 1 else None


_LINE_NO = __import__("re").compile(r"^[ \t]*\d{1,6}\t", __import__("re").M)


def _numbered(t):
    """True when EVERY non-empty line starts with a read_file line number and a tab."""
    lines = [ln for ln in str(t or "").split("\n") if ln.strip()]
    return bool(lines) and all(_LINE_NO.match(ln) for ln in lines)


def _unnumber(t):
    return _LINE_NO.sub("", str(t or ""))


def _closest_hint(text, old):
    """The file region most like old, and the first line that differs, so the model can copy the real bytes
    instead of guessing again."""
    import difflib
    flines, olines = text.split("\n"), old.split("\n")
    k = max(1, len(olines))
    if not flines or len(flines) > 20000:
        return ""
    first = olines[0].strip()
    starts = [i for i, ln in enumerate(flines) if first and difflib.SequenceMatcher(None, ln.strip(), first).ratio() > 0.6]
    starts = starts[:200] or range(0, max(1, len(flines) - k + 1))
    best, bi = 0.0, None
    for i in starts:
        r = difflib.SequenceMatcher(None, "\n".join(flines[i:i + k]), old).ratio()
        if r > best:
            best, bi = r, i
    if bi is None or best < 0.5:
        return ""
    span = f"Or skip the copying: edit_file start_line={bi + 1} end_line={bi + k} new=<the replacement lines>. "
    for j, (a, b) in enumerate(zip(flines[bi:bi + k], olines)):
        if a != b:
            # the column too: one dropped "]" in a 100-char f-string line was missed three times on "line 341
            # differs" alone (2026-10-24)
            col = next((c for c, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
            lo = max(0, col - 20)
            return (f"Closest match is lines {bi + 1}-{bi + k} ({best:.1%} similar). First difference on line "
                    f"{bi + j + 1}, column {col + 1}:\n  file has: ...{a[lo:col + 20]!r}...\n"
                    f"  you sent: ...{b[lo:col + 20]!r}...\n  full file line: {a!r}\n" + span)
    return f"Closest match is lines {bi + 1}-{bi + k} ({best:.0%} similar); the line count differs. " + span


def _git(r, *args, timeout=30):
    (
        gnoc_worktree, subprocess,
    ) = bind(
        "gnoc_worktree", "subprocess",
    )
    try:
        # git_env: an inherited GIT_DIR / GIT_INDEX_FILE (a git hook) would send `-C r` to another repo
        out = subprocess.run(["git", "-C", r] + list(args), capture_output=True, text=True, timeout=timeout,
                             stdin=subprocess.DEVNULL, env=gnoc_worktree.git_env())
    except subprocess.TimeoutExpired:
        return 124, f"git {args[0] if args else ''} timed out after {timeout}s (name fewer paths, or a narrower ref)"
    return out.returncode, (out.stdout or "") + (out.stderr or "")


GIT_ACTIONS = ("status", "diff", "log", "show", "blame", "branch", "switch", "stash", "restore", "commit", "push",
               "pr")
_REF_OK = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^-]{0,200}$")


def _ref_bad(ref):
    """A ref that git would read as an option or that carries whitespace: ref='--output=/x' once wrote a file."""
    return not ref or ref.startswith("-") or not _REF_OK.match(ref)


def _protected_under(r, paths, staged, ref=""):
    """Protected files a restore / commit of these pathspecs would touch. The pathspec TEXT was checked before,
    so `.`, `reports/submitted` (no trailing slash) or `:(top).claude/hooks/x` passed and restore threw away
    changes under protected folders (QAQC 2026-11-19). Pathspec magic is refused outright."""
    (
        WRITE_DENY, _git,
    ) = bind(
        "WRITE_DENY", "_git",
    )
    magic = [x for x in paths if str(x).startswith(":")]
    if magic:
        return magic
    if staged is None:   # commit: everything `git add` would stage, tracked or new
        _, out = _git(r, "ls-files", "-m", "-o", "-d", "--exclude-standard", "--", *paths)
        _, out2 = _git(r, "diff", "--cached", "--name-only", "--", *paths)
        out += "\n" + out2
    elif ref:   # restore --source=REF rewrites every file that differs from REF, changed in the tree or not
        _, out = _git(r, "diff", "--name-only", *(["--cached"] if staged else []), ref, "--", *paths)
    else:
        _, out = _git(r, "diff", "--name-only", *(["--cached"] if staged else []), "--", *paths)
    hit = sorted({f for f in out.splitlines() if f.strip() and WRITE_DENY.search(f.strip())})
    return hit[:8]


def t_git(ctx, action="status", paths=None, message="", ref="", staged=False, lines="", create=False,
          op="", remote="", title="", body="", base="", draft=False, number=None):
    """Git in the active repo. Reading is free. commit, push and opening a pull request need the user's approval
    every time; commit only commits the paths it names; push never forces."""
    (
        _git, _inside_ws, _protected_under, _rel_home, _spill, root, shutil, subprocess,
    ) = bind(
        "_git", "_inside_ws", "_protected_under", "_rel_home", "_spill", "root", "shutil", "subprocess",
    )
    r = root()
    code, _ = _git(r, "rev-parse", "--is-inside-work-tree")
    if code:
        return f"{_rel_home(r)} is not a git repo"
    paths = [paths] if isinstance(paths, str) else list(paths or [])
    for x in paths:
        if not _inside_ws(x):
            return f"refused: {x} is outside the active repo"
    ref = str(ref or "").strip()
    action = str(action or "status").lower()
    if action == "status":
        return _git(r, "status", "--short", "--branch")[1] or "clean"
    if action == "diff":
        if ref and _ref_bad(ref):
            return "refused: ref must be a commit, branch or A..B range"
        return _spill(_git(r, "diff", *(["--cached"] if staged else []), *([ref] if ref else []), "--stat",
                           "--patch", "--", *paths)[1] or "no differences", "git-diff")
    if action == "log":
        if ref and _ref_bad(ref):
            return "refused: ref must be a commit, branch or A..B range"
        # who and when on every line: "who last changed store.py and when?" got `1b2cd57 init`, and the lead
        # asked for the same log four times before falling back to `show` (history drive 2026-11-21)
        return _git(r, "log", "--format=%h %ad %an: %s", "--date=short", "-30", *([ref] if ref else []),
                    *(["--", *paths] if paths else []))[1]
    if action == "show":
        ref = ref or "HEAD"
        if _ref_bad(ref):
            return "refused: ref must be a commit, tag or branch name (ref='--output=/x' once wrote a file)"
        return _spill(_git(r, "show", "--stat", "--patch", ref, "--")[1], "git-show")
    if action == "blame":
        if len(paths) != 1:
            return "bad arguments: blame needs exactly one path (paths=['src/x.py']) and optionally lines='40,80'"
        span = []
        if lines:
            m = _re.match(r"^\s*(\d+)\s*[,-]\s*(\d+)\s*$", str(lines))
            if not m:
                return "bad arguments: lines is 'START,END' (1-based), e.g. lines='40,80'"
            span = ["-L", f"{m.group(1)},{m.group(2)}"]
        return _spill(_git(r, "blame", "--date=short", *span, *([ref] if ref and not _ref_bad(ref) else []), "--",
                           paths[0])[1], "git-blame")
    if action == "branch":
        if not ref:
            return _git(r, "branch", "-vv", "--sort=-committerdate")[1]
        if _ref_bad(ref):
            return "refused: give a plain branch name"
        code, out = _git(r, "branch", ref)
        return out.strip() or f"created branch {ref} (still on the current branch; git action=switch ref={ref})"
    if action == "switch":
        if _ref_bad(ref):
            return "bad arguments: switch needs ref=<branch> (create=true makes it first)"
        st = _git(r, "status", "--porcelain", "--untracked-files=no")[1].strip()
        if st and not create:
            return ("refused: the working tree has uncommitted changes; commit them, or git action=stash first, so "
                    "switching cannot carry or clobber them:\n" + st[:600])
        code, out = _git(r, "switch", *(["-c"] if create else []), ref)
        return out.strip() or f"switched to {ref}"
    if action == "stash":
        op = str(op or "list").lower()
        if op == "list":
            return _git(r, "stash", "list")[1] or "no stashes"
        if op in ("push", "save"):
            return _git(r, "stash", "push", "-m", str(message or "stashed by the agent"),
                        *(["--", *paths] if paths else []))[1]
        if op in ("pop", "apply"):
            return _git(r, "stash", op, *([ref] if ref and not _ref_bad(ref) else []))[1]
        if op == "show":
            return _spill(_git(r, "stash", "show", "-p", *([ref] if ref and not _ref_bad(ref) else []))[1], "git-stash")
        return "bad arguments: stash op is list, push, pop, apply or show (no drop: a dropped stash is gone)"
    if action == "restore":
        if not paths:
            return "refused: name the paths to restore (restore throws away their uncommitted changes)"
        bad = _protected_under(r, paths, staged, ref if ref and not _ref_bad(ref) else "")
        if bad:
            return f"refused: protected path(s) {', '.join(bad)}"
        code, out = _git(r, "restore", *(["--staged"] if staged else []),
                         *([f"--source={ref}"] if ref and not _ref_bad(ref) else []), "--", *paths)
        return out.strip() or ("unstaged " if staged else "restored ") + ", ".join(paths)
    if action == "commit":
        if not paths:
            return "refused: name the paths to commit (the workspace always has unrelated changes in flight)"
        if len((message or "").strip()) < 8:
            return "refused: give a real commit message (message=<what changed and why>, 8+ characters)"
        bad = _protected_under(r, paths, None)
        if bad:
            return f"refused: protected path(s) {', '.join(bad)}"
        code, out = _git(r, "add", "--", *paths)
        if code:
            return f"git add failed: {out[:400]}"
        code, out = _git(r, "commit", "-m", message, "--", *paths, timeout=120)
        return out[-1500:] if out else f"git commit exit {code}"
    if action == "push":
        branch = ref or _git(r, "branch", "--show-current")[1].strip()
        if not branch or _ref_bad(branch):
            return "refused: no branch to push (detached HEAD?); pass ref=<branch>"
        if branch in ("main", "master") and not ref:
            return ("refused: you are on {0}; pushing {0} goes straight to the shared branch. Push a feature branch, "
                    "or pass ref={0} to say you mean it.").format(branch)
        rem = str(remote or "origin")
        if _ref_bad(rem):
            return "refused: remote must be a remote name like origin"
        code, out = _git(r, "push", "--set-upstream", rem, branch, timeout=180)   # never --force
        return (out.strip() or f"git push exit {code}")[-1500:]
    if action == "pr":
        if not shutil.which("gh"):
            return "the GitHub CLI (gh) is not installed: pull requests need it (https://cli.github.com)"
        op = str(op or "view").lower()
        if op == "create":
            if len(str(title or "").strip()) < 5:
                return "bad arguments: pr op=create needs title=<what the change does> and body=<why / how tested>"
            argv = ["gh", "pr", "create", "--title", str(title), "--body", str(body or "")]
            if base and not _ref_bad(str(base)):
                argv += ["--base", str(base)]
            if draft:
                argv.append("--draft")
        elif op in ("view", "status", "list", "checks", "diff"):
            argv = ["gh", "pr", op] + ([str(int(number))] if number not in (None, "") and op not in ("status", "list") else [])
        else:
            return "bad arguments: pr op is view, list, status, checks, diff or create"
        try:
            pr = subprocess.run(argv, cwd=r, capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL,
                                env=bind("gnoc_worktree")[0].git_env())
        except subprocess.TimeoutExpired:
            return f"gh pr {op} timed out after 120s"
        return _spill(((pr.stdout or "") + (pr.stderr or "")).strip() or f"gh pr {op} exit {pr.returncode}", "gh-pr")
    return "action is " + ", ".join(GIT_ACTIONS)


def _changed_paths(r, limit=40):
    """The repo-relative paths git says are modified or added (staged or not), newest shape first."""
    (
        _git,
    ) = bind(
        "_git",
    )
    code, out = _git(r, "status", "--porcelain")
    if code:
        return []
    paths = []
    for ln in (out or "").splitlines():
        p = ln[3:].strip() if len(ln) > 3 else ""
        if " -> " in p:                      # a rename: the destination is what changed
            p = p.split(" -> ")[-1]
        p = p.strip('"')
        if p and not p.endswith("/"):
            paths.append(p)
    return paths[:limit]


def t_run_tests(ctx, files=None, timeout=600, name=None, coverage=False):
    """Run the repo's tests: the named test files (fast, the ones that cover what you changed), or the full suite.
    name= narrows to the tests matching it; files="failed" re-runs only what failed last time; coverage=true adds
    the runner's coverage report where it has one."""
    (
        _changed_paths, _inside_ws, _run_group, _spill, detect_tests, os, root, subprocess, tests_for,
        test_argv, suite_with_name,
    ) = bind(
        "_changed_paths", "_inside_ws", "_run_group", "_spill", "detect_tests", "os", "root", "subprocess",
        "tests_for", "test_argv", "suite_with_name",
    )
    r = root()
    files = [files] if isinstance(files, str) else list(files or [])
    # files='["\'/abs/test_server.py\'"]' and '["[\'/abs/test_server.py\']"]': a list packed into a string, then
    # quoted again inside it; each layer became part of a path that does not exist (SWE batch 1, twice in one turn)
    _flat = []
    for _f in files:
        _t = str(_f or "").strip()
        for _ in range(3):
            if _t[:1] == "[" and _t[-1:] == "]":
                _v = None
                with __import__("contextlib").suppress(Exception):
                    _v = __import__("ast").literal_eval(_t)
                if isinstance(_v, (list, tuple)) and len(_v) == 1:
                    _t = str(_v[0]).strip()
                    continue
                if isinstance(_v, (list, tuple)):
                    _flat.extend(str(x).strip().strip("'\" ") for x in _v)
                    _t = ""
                    break
                _t = _t[1:-1].strip()
            _t = _t.strip("'\" ").strip()
        if _t:
            _flat.append(_t)
    files = [x for x in _flat if x]
    s = ctx.s if isinstance(getattr(ctx, "s", None), dict) else {}
    notes = []
    runs = []
    if str(name or "").strip().lower() in ("all", "*", "any", "every", "everything", "none", "null", "auto",
                                           "default", "tests", "test"):   # name='auto': SWE drive 2026-11-22
        # name= is a FILTER. name='all' selected the tests whose name contains "all": none, so nothing ran, node
        # exited 0 and it read "1/1 test command passed" over a file whose test fails (web drive 2026-11-21).
        notes.append(f"name={name!r} is not a filter: every test in the file(s) ran")
        name = None
    _nm = str(name or "").strip()
    if _nm and ("/" in _nm or __import__("re").search(r"\.(?:py|js|mjs|cjs|ts|tsx|jsx|go|rs|rb)$|\.(?:test|spec)$", _nm)):
        # name='slug.test', then slug.test3, slug.test4 ... to the 420 s cap: the FILE's name passed as a test-name
        # filter, so nothing matched (SWE drive 2026-11-22). A file name selects the file; it never filters.
        _fp = os.path.join(r, _nm)
        if os.path.isfile(_fp) and (not files or [str(f).strip().lower() for f in files] in (["auto"], ["changed"])):
            files = [_nm]
        notes.append(f"name={name!r} names a test FILE, not a test, so it was not used as a filter")
        name = None
    if len(files) == 1 and str(files[0]).strip().lower() in ("failed", "last-failed", "failing"):
        prev = [tuple(x) for x in (s.get("_failed_tests") or []) if x and x[2] == r] if s else []
        if not prev:
            return "nothing failed in the last run_tests in this repo (or nothing has run yet): name the files"
        runs = [(label, list(argv)) for label, argv, _ in prev]
        files = []
    # files="auto": run the tests that COVER what this turn changed. On a big site the whole-suite command
    # is not a usable check (the website's `npm test` chains ~200 files behind a 25-file pretest), so the
    # narrow set is what actually gets run - and an unrun change is a claim, not a change (T-269).
    if len(files) == 1 and str(files[0]).strip().lower() in ("auto", "changed"):
        changed = _changed_paths(r)
        if not changed:
            return ("nothing is changed in the active repo, so there is nothing to cover: name the test "
                    "files, or omit files for the whole suite")
        files = tests_for(r, changed)
        if not files:
            cmd = detect_tests(r)
            return (f"no test file in this repo's test tree matches {', '.join(changed[:4])} by name. "
                    + (f"The whole suite is `{cmd}` - run it with files omitted if you want it, " if cmd else "")
                    + "or name the covering test yourself.")
    _testing = __import__("gnoc_core.testing", fromlist=["_TEST_NAME"])
    expanded = []
    for f in files:
        p = _inside_ws(f)
        if p and os.path.isdir(p):
            # "run the whole test folder": files=['test/'] was answered "no test file test/ in the active repo"
            inside = sorted(os.path.relpath(x, r) for x in _testing.find_test_files(r)
                            if os.path.realpath(x).startswith(os.path.realpath(p).rstrip(os.sep) + os.sep))
            if not inside:
                return f"no test files under {f} in the active repo"
            if len(inside) > 40:
                notes.append(f"{f} holds {len(inside)} test files: ran the first 40 (name files for the rest)")
            expanded += [x for x in inside[:40] if x not in expanded]
            continue
        if not p or not os.path.isfile(p):
            return f"no test file {f} in the active repo"
        rel = os.path.relpath(p, r)
        in_test_dir = any(part in ("test", "tests", "__tests__", "spec", "specs") for part in rel.split(os.sep)[:-1])
        if not _testing._TEST_NAME.search(os.path.basename(p)) and not in_test_dir:
            # A SOURCE file handed to run_tests: `node --test src/slug.js` runs it, finds no test, exits 0, and
            # the lead reported "All tests passed" in a repo whose slug test fails (multi-file drive 2026-11-21).
            # The tests that cover it are what was meant.
            cover = tests_for(r, [rel])
            if not cover:
                return (f"{f} is a source file with no tests in it, so running it would prove nothing. Name a test "
                        "file, or omit files to run the whole suite.")
            notes.append(f"{f} is a source file, not a test file: ran the test(s) that cover it instead "
                         f"({', '.join(cover)})")
            expanded += [c for c in cover if c not in expanded]
            continue
        if f not in expanded:
            expanded.append(f)
    for f in expanded:
        p = _inside_ws(f)
        if not p or not os.path.isfile(p):
            return f"no test file {f} in the active repo"
        argv, note = test_argv(r, p, name=name, coverage=coverage)
        if argv is None:
            return note
        if note:
            notes.append(note)
        runs.append((f, argv))
    if not runs:
        cmd = detect_tests(r)
        if not cmd:
            return ("no test command found (package.json scripts.test, a 'test: `cmd`' line in GNOC.md/CLAUDE.md, "
                    "pytest, go.mod, Cargo.toml, make test); name the test files instead")
        cmd, note = suite_with_name(cmd, name)
        if note:
            notes.append(note)
        if coverage:
            notes.append("coverage= applies to named test files; the suite ran as configured")
        import gnoc_compat   # bash on Linux/macOS, PowerShell on native Windows
        runs.append((cmd, gnoc_compat.shell_argv(cmd, login=True)))
    out, failed, failing = [], 0, []
    limit = max(10, min(int(timeout or 600), 1800))
    for label, argv in runs:
        try:
            # the repo's own code runs here: never with the chat's credentials in its environment (QAQC r2)
            pr = _run_group(argv, cwd=r, capture_output=True, text=True, timeout=limit, stdin=subprocess.DEVNULL,
                            env=bind("gnoc_secrets")[0].user_env({}))
            code, text = pr.returncode, (pr.stdout or "") + (pr.stderr or "")
        except subprocess.TimeoutExpired as e:
            got = e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            code, text = 124, (f"TIMED OUT after {limit}s (timeout= caps at 1800; name fewer test files to go "
                               f"faster). Output so far:\n{got}")
        except FileNotFoundError as e:
            code, text = 127, f"cannot run {argv[0]}: {e}"
        is_pytest = "pytest" in argv or "pytest" in str(argv[-1] if argv else "")
        no_tests = is_pytest and code == 5
        if not no_tests and code == 0 and name and __import__("re").search(
                r"(?m)^1\.\.0\s*$|^# tests 0\s*$|\bno tests to run\b|\bNo tests found\b|\b0 passed\b.*\b0 failed\b"
                r"|^testing: warning: no tests to run", text):
            no_tests = True   # node --test-name-pattern / go -run / jest -t that matched nothing: exit 0, zero tests
        if not no_tests and code == 0 and name and __import__("re").search(r"(?m)^# pass 0\s*$", text) and \
                __import__("re").search(r"(?m)^# fail 0\s*$", text):
            # Node 20 (the version Debian and Ubuntu ship) does not drop a test the name pattern rules out: it
            # reports it as skipped, so the summary reads "# tests 1 / # pass 0 / # skipped 1" and the line above,
            # written against Node 22's "# tests 0", read that as a pass. With a name filter, nothing passed and
            # nothing failed means nothing matched (Phase 0, 2026-11-26).
            no_tests = True
        if no_tests and name:
            ok = False   # a name that selects nothing is a typo, not a pass
            text += f"\n[no test matched name={name!r}]"
        else:
            ok = code == 0 or no_tests  # pytest exit 5 = no tests collected, not a failure
        failed += not ok
        if not ok:
            failing.append((label, argv, r))
        note = " no tests collected" if no_tests else ""
        if name and not no_tests:
            # SWE batch 1: run_tests(name='cap') ran ONE of capitalize.test.js's 8 tests ("already capitalized"),
            # read "1/1 passed", and the answer said "All tests pass!" over a failing "with punctuation" test.
            # A FILTERED FAILURE needs the same warning: only the matching tests ran, so the file is not
            # wholly broken either (1000-turn drive 2026-11-24).
            _m = __import__("re").search(r"(?m)^# tests (\d+)|\b(\d+) passed\b|^ok\s+(\d+)\s", text)
            _n = next((g for g in (_m.groups() if _m else ()) if g), "")
            note += (f" (FILTERED by name={name!r}: only " + (f"{_n} test(s) " if _n else "the tests ")
                     + "whose names match ran; the rest of these files did NOT run."
                     + (" Run again without name= before saying the tests pass." if ok else "") + ")")
        out.append(f"{'PASS' if ok else 'FAIL'} ({code}){note} {label}\n{text[-2500:]}")
    if s is not None and isinstance(s, dict):
        s["_failed_tests"] = failing
    # Say WHAT the count is over. "1/1 passed" above a block reading "11 passed in 0.24s" is ambiguous,
    # and the lead resolved it by inventing: it reported "100% coverage (11 tests total)" to GreyNOC
    # when nothing had measured coverage (driven under -s-p, 2026-10-25).
    unit = "command" if len(runs) == 1 else "commands"
    tail = ("\nre-run only the failures with files=['failed']" if failing and len(runs) > 1 else "")
    return _spill(f"{len(runs) - failed}/{len(runs)} test {unit} passed (this is a count of commands "
                  f"run, not of tests or coverage; the per-command output below has the test counts)"
                  + ("".join(f"\n[note] {n}" for n in dict.fromkeys(notes))) + tail
                  + "\n\n" + "\n\n".join(out), "tests")


def _unquote_name(x):
    """A file name as patch(1) or git print it: bare, 'single-quoted' or "C-quoted"."""
    x = str(x or "").strip().split("\t")[0]
    if len(x) > 1 and x[0] == x[-1] == "'":
        return x[1:-1]
    if len(x) > 1 and x[0] == x[-1] == '"':
        try:
            return x[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape").encode("latin-1").decode(
                "utf-8", "replace")
        except (UnicodeError, ValueError):
            return x[1:-1]
    return x


def t_apply_patch(ctx, patch=None, patch_file=None):
    """Apply a unified diff (one or many files) in the active repo, checked first, every touched file checkpointed
    for /undo. patch_file= reads the diff from a file (a builder's patch) instead of the argument."""
    (
        STATE, _checkpoint, _diff, _gate_owned, _inside_ws, _is_secret, _read, _rel, _secret_write_refusal,
        _write_refusal, os, re, root, subprocess,
    ) = bind(
        "STATE", "_checkpoint", "_diff", "_gate_owned", "_inside_ws", "_is_secret", "_read", "_rel",
        "_secret_write_refusal", "_write_refusal", "os", "re", "root", "subprocess",
    )
    r = root()
    if patch_file and not patch:
        why = bind("_sandbox_fence")[0](ctx, patch_file, "apply_patch") if not str(patch_file).startswith(
            os.path.realpath(STATE.out_dir) + os.sep) else ""
        if why:
            return why
        pf = os.path.realpath(os.path.expanduser(str(patch_file)))
        out_dir = os.path.realpath(STATE.out_dir)
        if not (pf.startswith(out_dir + os.sep) or _inside_ws(str(patch_file)) == pf):
            return "refused: patch_file must be a builder's patch (the path delegate returned) or a file in the repo"
        if not os.path.isfile(pf):
            return f"no such patch file: {patch_file}"
        patch = _read(pf)
    patch = str(patch or "")
    # EVERY name in a '---' or '+++' header is checked, quoted (C-style "b/x y") or not: patch(1) picks whichever
    # of the old / new names exists, so a '--- a/.claude/hooks/scope-gate.sh' with a harmless '+++ b/new.txt'
    # once patched the hook. Names also go through the same containment + deny list as write_file.
    names = []
    for m in re.finditer(r'(?m)^(?:---|\+\+\+) (?:"((?:[^"\\]|\\.)*)"|(\S+))', patch):
        n = (m.group(1) or m.group(2) or "").encode().decode("unicode_escape") if m.group(1) else (m.group(2) or "")
        n = n.split("\t")[0]
        if n and n != "/dev/null":
            names.append(re.sub(r"^[ab]/", "", n))
    # git's rename / copy headers name files with no ---/+++ line at all: `rename from .claude/hooks/x` moved a hook
    # away and `copy from .env` copied a secret (QAQC r2). Both sides are checked like any other name.
    renames = re.findall(r"(?m)^(?:rename|copy) (from|to) (.+)$", patch)
    names += [_unquote_name(x) for _, x in renames]
    copied_from = [_unquote_name(x) for k, x in re.findall(r"(?m)^copy (from) (.+)$", patch)]
    files = [n for n in dict.fromkeys(names)]
    if not files:
        return "no files in the patch (expected '--- a/path' / '+++ b/path' headers)"
    for f in files:
        if os.path.isabs(f) or f.startswith("../") or "/../" in f:
            return f"{f}: refused: patch paths must be relative to the repo"
        why = (bind("_sandbox_fence")[0](ctx, f, "apply_patch") or _write_refusal(_inside_ws(f))
               or _secret_write_refusal(patch))
        if why:
            return f"{f}: {why}"
    for f in copied_from:   # a copy SOURCE is read, not written: refuse copying a secret out
        p = _inside_ws(f)
        if p and _is_secret(p):
            return f"{f}: refused: a secrets file is never copied"
    strip = "-p1" if re.search(r"(?m)^\+\+\+ b/", patch) else "-p0"
    # The files patch(1) will REALLY touch, from patch itself: it strips -p components its own way and also reads
    # context diffs ("*** name"), so a header parse alone let `--- c/.claude/hooks/x` (with -p1) and a context diff
    # patch a protected file, and /undo then had no record of it (QAQC 2026-11-19). --batch never prompts.
    chk = subprocess.run(["patch", strip, "--dry-run", "--forward", "--batch", "--verbose"], input=patch, text=True,
                         cwd=r, capture_output=True, timeout=60)
    if chk.returncode:
        return f"patch does not apply cleanly (nothing changed):\n{(chk.stdout + chk.stderr)[-1500:]}"
    # "checking file NEW (renamed from OLD)" / "(copied from OLD)": both names, each unquoted (patch quotes names
    # with special characters, in single OR double quotes)
    real = []
    for m in re.finditer(r"(?m)^checking file (.+?)(?: \((?:renamed|copied) from (.+)\))?$", chk.stdout):
        real += [_unquote_name(x) for x in m.groups() if x]
    real = list(dict.fromkeys(real))
    for f in real:
        p = _inside_ws(f)
        why = ("refused: patch paths must be relative to the repo" if not p or os.path.isabs(f) or ".." in f.split("/")
               else _write_refusal(p) or _gate_owned(f))
        if why:
            return f"{f}: {why}"
    files = list(dict.fromkeys(real + [f for f in files if f not in real]))
    paths = [_inside_ws(f) or os.path.join(r, f) for f in files]
    with _locked(paths):
        before = {p: (_load_exact(p)[2], os.path.isfile(p)) for p in paths}
        out = subprocess.run(["patch", strip, "--forward", "--batch", "-s"], input=patch, text=True, cwd=r,
                             capture_output=True, timeout=60)
        for p, (old, existed) in before.items():
            now = _load_exact(p)[2] if os.path.isfile(p) else ""
            if now != old or existed != os.path.isfile(p):
                _checkpoint(ctx, p, old, existed, now)
            _mark_seen(ctx, p)
    rows = [f"{_rel(p)} " + _diff(old.replace("\r\n", "\n"), _load_exact(p)[0] if os.path.isfile(p) else "",
                                  _rel(p)).split("\n", 1)[0]
            for p, (old, _) in before.items()]
    return ("applied:\n" + "\n".join(rows) + (f"\n{out.stdout + out.stderr}" if out.returncode else "")
            + "\nNow run_tests on what you changed.")


def t_lint(ctx, files=None):
    """The repo's own lint script if it has one, else ruff/flake8 for .py, eslint for .js/.mjs/.ts, shellcheck .sh."""
    (
        LINTERS, _inside_ws, _read, _run_group, _spill, contextlib, json, os, root,
        shutil, subprocess,
    ) = bind(
        "LINTERS", "_inside_ws", "_read", "_run_group", "_spill", "contextlib", "json",
        "os", "root", "shutil", "subprocess",
    )
    r = root()
    files = [files] if isinstance(files, str) else list(files or [])
    for f in files:
        if str(f).startswith("-"):   # `--config=x.js` / `--python-executable=x` would be read as an option
            return f"refused: {f} is not a file name (names starting with '-' are options to the linter)"
        if not _inside_ws(f):
            return f"refused: {f} is outside the active repo"
    pj = os.path.join(r, "package.json")
    if not files and os.path.isfile(pj):
        with contextlib.suppress(ValueError):
            if (json.loads(_read(pj)).get("scripts") or {}).get("lint"):
                try:
                    pr = _run_group(["npm", "run", "-s", "lint"], cwd=r, capture_output=True, text=True,
                                    timeout=600, stdin=subprocess.DEVNULL, env=bind("gnoc_secrets")[0].user_env({}))
                except subprocess.TimeoutExpired:
                    return "npm run lint timed out after 600s: lint the files you changed instead (files=[...])"
                return _spill(f"npm run lint -> exit {pr.returncode}\n{(pr.stdout + pr.stderr)[-4000:]}", "lint")
    by_ext = {".py": ("ruff", "flake8", "pyflakes"), ".js": ("eslint",), ".mjs": ("eslint",), ".cjs": ("eslint",),
              ".jsx": ("eslint",), ".ts": ("eslint",), ".tsx": ("eslint",), ".sh": ("shellcheck",)}
    note = ""
    if not files:
        # "lint this repo": the repo's own source files. It used to answer "name the files to lint (or add a lint
        # script to package.json)" in a Python repo; the lead read every file, tried `pip install flake8` three
        # times and the turn ended with no answer (tool drive 2026-11-21).
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            ls = subprocess.run(["git", "-C", r, "ls-files", "-co", "--exclude-standard"], capture_output=True,
                                text=True, timeout=20, stdin=subprocess.DEVNULL,
                                env=bind("gnoc_worktree")[0].git_env())
            files = [f for f in ls.stdout.splitlines() if os.path.splitext(f)[1] in by_ext][:60]
        if not files:
            return ("nothing to lint: no .py / .js / .ts / .sh file is tracked in this repo "
                    "(name the files with files=[...])")
        note = f"linted this repo's {len(files)} source file(s); files=[...] narrows it\n"
    out = []
    for f in files:
        for name in by_ext.get(os.path.splitext(f)[1], ()):
            cmd = dict(LINTERS)[name]
            if shutil.which(cmd[0]):
                try:
                    pr = _run_group(cmd + [f], cwd=r, capture_output=True, text=True, timeout=300,
                                    stdin=subprocess.DEVNULL, env=bind("gnoc_secrets")[0].user_env({}))
                except subprocess.TimeoutExpired:
                    out.append(f"{name} {f}: timed out after 300s")
                    break
                text = (pr.stdout or "") + (pr.stderr or "")
                if name == "eslint" and pr.returncode != 0 and __import__("re").search(
                        r"canceled due to missing packages|could not determine executable|ESLint couldn't find "
                        r"(?:a|an eslint\.config)|No ESLint configuration", text):
                    # npx found no eslint in this repo (or no config): that is "not set up", never "issues"
                    out.append(f"{f}: eslint is not set up in this repo (no eslint in node_modules, or no eslint "
                               "config), so it was not linted")
                    break
                out.append(f"{name} {f}: {'clean' if pr.returncode == 0 else 'issues'}\n{text[-2000:]}")
                break
        else:
            if f.endswith(".py"):
                # no ruff / flake8 / pyflakes: say so ONCE, and still answer what can be answered (does it compile)
                # rather than leave the lead to `pip install` one, which asks for approval
                try:
                    pr = _run_group([__import__("gnoc_core.testing", fromlist=["project_python"]).project_python(r),
                                     "-m", "py_compile", f], cwd=r, capture_output=True,
                                    text=True, timeout=60, stdin=subprocess.DEVNULL,
                                    env=bind("gnoc_secrets")[0].user_env({"PYTHONDONTWRITEBYTECODE": "1"}))
                    out.append(f"{f}: no Python linter is installed (ruff, flake8 or pyflakes); syntax check only: "
                               + ("compiles" if pr.returncode == 0 else "DOES NOT COMPILE\n" + (pr.stderr or "")[-800:]))
                except (OSError, subprocess.SubprocessError):
                    out.append(f"{f}: no linter installed for it")
            else:
                out.append(f"{f}: no linter installed for it")
    return _spill(note + "\n".join(out), "lint")


def t_typecheck(ctx, files=None, timeout=600):
    """The repo's type checker (tsc --noEmit, mypy / pyright, go vet, cargo check, or its own typecheck script)
    over the whole project or the files named. Lint is style; this is whether the code is CALLED correctly."""
    (
        _inside_ws, _run_group, _spill, gnoc_typecheck, root, subprocess,
    ) = bind(
        "_inside_ws", "_run_group", "_spill", "gnoc_typecheck", "root", "subprocess",
    )
    r = root()
    files = [files] if isinstance(files, str) else list(files or [])
    for f in files:
        if str(f).startswith("-"):   # mypy --python-executable=x would RUN x (QAQC 2026-11-19)
            return f"refused: {f} is not a file name (names starting with '-' are options to the checker)"
        if not _inside_ws(f):
            return f"refused: {f} is outside the active repo"
    plan = gnoc_typecheck.plan(r, files)
    if isinstance(plan, str):
        return plan
    limit = max(30, min(int(timeout or 600), 1800))
    out, bad = [], 0
    for label, argv in plan:
        try:
            pr = _run_group(argv, cwd=r, capture_output=True, text=True, timeout=limit, stdin=subprocess.DEVNULL,
                            env=bind("gnoc_secrets")[0].user_env({}))
            code, text = pr.returncode, ((pr.stdout or "") + (pr.stderr or "")).strip()
        except subprocess.TimeoutExpired:
            code, text = 124, f"timed out after {limit}s: check fewer files (files=[...])"
        except FileNotFoundError as e:
            code, text = 127, str(e)
        bad += code != 0
        errs = sum(1 for ln in text.splitlines() if _re.search(r"\berror\b", ln, _re.I))
        out.append(f"{'CLEAN' if code == 0 else 'ERRORS'} ({code}) {label}"
                   + (f" - {errs} error line(s)" if code and errs else "") + "\n" + (text[-4000:] or "(no output)"))
    head = ("type check clean" if not bad else f"type check found problems in {bad} of {len(plan)} run(s)")
    return _spill(head + "\n\n" + "\n\n".join(out), "typecheck")


def _tasks_rows():
    (
        TASKS, _read, contextlib, json,
    ) = bind(
        "TASKS", "_read", "contextlib", "json",
    )
    rows = []
    for ln in _read(TASKS).splitlines():  # _read: no file handle left open, a missing file is just empty
        with contextlib.suppress(ValueError):
            if ln.strip():
                row = json.loads(ln)
                if isinstance(row, dict) and row.get("id"):
                    row.setdefault("text", "")
                    row.setdefault("status", "open")
                    row.setdefault("notes", [])
                    rows.append(row)
    return rows


def _tasks_write(rows):
    (
        ORCH, TASKS, contextlib, json, os, threading,
    ) = bind(
        "ORCH", "TASKS", "contextlib", "json", "os", "threading",
    )
    os.makedirs(ORCH, exist_ok=True)
    tmp = f"{TASKS}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(r) + "\n" for r in rows)
        os.replace(tmp, TASKS)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def tasks_add(text, tag=None, due=None):
    """Add one task and return its id. The plan uses this so a plan step and its ledger row stay linked."""
    (
        _now, _tasks_rows, _tasks_write,
    ) = bind(
        "_now", "_tasks_rows", "_tasks_write",
    )
    rows = _tasks_rows()
    n = max([int(str(r.get("id", ""))[1:]) for r in rows
             if str(r.get("id", ""))[1:].isdigit()] or [0]) + 1
    row = {"id": f"T{n}", "text": str(text)[:300], "due": due, "tag": tag, "status": "open",
           "created": _now().isoformat(timespec="seconds"), "notes": []}
    rows.append(row)
    _tasks_write(rows)
    return row["id"]


def tasks_find(text, tag=None):
    """The id of the open ledger row for this plan step, if any (legacy plans had no stored task_id)."""
    (
        _tasks_rows,
    ) = bind(
        "_tasks_rows",
    )
    want = str(text or "")
    for r in _tasks_rows():
        if r.get("status") != "open":
            continue
        if tag and r.get("tag") != tag:
            continue
        if str(r.get("text") or "") == want:
            return r.get("id")
    return None


def tasks_mark(task_id, status, note=None):
    (
        _now, _tasks_rows, _tasks_write,
    ) = bind(
        "_now", "_tasks_rows", "_tasks_write",
    )
    if not task_id:
        return False
    rows = _tasks_rows()
    r = next((x for x in rows if x.get("id") == str(task_id).strip().upper()), None)
    if not r:
        return False
    if status == "done":
        r["status"], r["closed"] = "done", _now().isoformat(timespec="seconds")
    elif status == "open":
        r["status"] = "open"
        r.pop("closed", None)
    if note:
        r.setdefault("notes", []).append(f"{_now():%Y-%m-%d} {note}"[:300])
    _tasks_write(rows)
    return True


def t_tasks(ctx, action="list", text=None, id=None, due=None, tag=None):
    """The user's running to-do list for the business and the hunt: add / list / done / note / reopen."""
    (
        _now, _tasks_rows, _tasks_write, tasks_add,
    ) = bind(
        "_now", "_tasks_rows", "_tasks_write", "tasks_add",
    )
    action = str(action or "list").lower()
    if action not in ("add", "list", "done", "note", "reopen"):
        return f"action is add, list, done, note or reopen (got {action!r}); nothing changed"
    if action == "add":
        if not text:
            return "bad arguments: tasks action=add needs text=<the task> (optional due=YYYY-MM-DD, tag=...)"
        tasks_add(text, tag=tag, due=due)
        rows = _tasks_rows()
    else:
        rows = _tasks_rows()
        if action in ("done", "note", "reopen"):
            r = next((r for r in rows if r["id"] == str(id or "").strip().upper()), None)
            if not r:
                return f"no task {id!r}: give id=T<number> as shown by tasks action=list"
            if action == "done":
                r["status"], r["closed"] = "done", _now().isoformat(timespec="seconds")
            elif action == "reopen":
                r["status"] = "open"
                r.pop("closed", None)
            else:
                r.setdefault("notes", []).append(f"{_now():%Y-%m-%d} {text or ''}"[:300])
            _tasks_write(rows)
    show = [r for r in rows if r["status"] == "open" or action != "list"]
    show.sort(key=lambda r: (r.get("due") or "9999", r["id"]))
    return "\n".join(f"{r['id']} [{r['status']}] {r['text']}" + (f"  due {r['due']}" if r.get("due") else "")
                     + (f"  #{r['tag']}" if r.get("tag") else "") + (f"  ({len(r['notes'])} notes)" if r["notes"] else "")
                     for r in show[-40:]) or "no open tasks"
