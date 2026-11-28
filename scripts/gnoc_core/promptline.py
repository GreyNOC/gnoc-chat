"""The prompt line: @mentions expanded into the message, tab completion, a prefilled next prompt, and transcript export."""
import re
from .runtime import bind


def _prefilled_input(prompt_text):
    """input() that seeds the editable line with NEXT_SUGGESTION, consumed once: the suggested next prompt
    shows in the field, Enter accepts it, any typing overrides it, Ctrl-U clears it. Falls back to a plain
    input() when there is no suggestion or readline cannot pre-seed."""
    (
        NEXT_SUGGESTION, contextlib, readline,
    ) = bind(
        "NEXT_SUGGESTION", "contextlib", "readline",
    )
    sug, NEXT_SUGGESTION[0] = NEXT_SUGGESTION[0], ""
    if not sug:
        return input(prompt_text)
    def _hook():
        with contextlib.suppress(Exception):
            readline.insert_text(sug)
            readline.redisplay()
    with contextlib.suppress(Exception):
        readline.set_pre_input_hook(_hook)
    try:
        return input(prompt_text)
    finally:
        with contextlib.suppress(Exception):
            readline.set_pre_input_hook(None)


# ---------------------------------------------------------------- the prompt line: @mentions, tab completion
# Claude-Code-style @-mentions: '@file.py' in GreyNOC's OWN message attaches the file's content to the turn,
# so the model gets the bytes without spending a tool call to fetch them. Presentation only: the text is
# appended to his message, the model is told it is an attachment, and every cap is enforced here.
_MENTION = re.compile(r"@([~/\w.@%+-]+)")


_MENTION_FILE_CAP = 8000     # characters per attached file


_MENTION_TOTAL_CAP = 24000   # characters across all attachments in one message


def expand_mentions(text):
    """Append the content of every @file mention to the message. Files only; unreadable, missing or
    binary paths are left as plain text so the model can read the mention itself and say why."""
    (
        _MENTION, _MENTION_FILE_CAP, _MENTION_TOTAL_CAP, _rel_home, gnoc_collab, os, root,
    ) = bind(
        "_MENTION", "_MENTION_FILE_CAP", "_MENTION_TOTAL_CAP", "_rel_home", "gnoc_collab", "os", "root",
    )
    if not text or "@" not in text:
        return text
    base, seen, total, blocks = root(), set(), 0, []
    for m in _MENTION.finditer(text):
        raw = m.group(1)
        if not raw or raw in seen:
            continue
        seen.add(raw)

        def resolve(r):
            r = os.path.expanduser(r)   # BEFORE the isabs test: "~/x" is not absolute until expanded (QAQC 2026-11-19)
            return os.path.realpath(r if os.path.isabs(r) else os.path.join(base, r))
        path = resolve(raw)
        if not os.path.isfile(path) and raw.rstrip(".,;:!?)") != raw:
            raw = raw.rstrip(".,;:!?)")   # "see @README.md." - the sentence's full stop is not the file's
            path = resolve(raw)
        if not os.path.isfile(path):
            continue
        import gnoc_secrets
        if gnoc_secrets.is_secret_path(path):
            # read_file refuses these; an @mention inlined them whole (QAQC r2: @.env, @~/.ssh/id_rsa)
            blocks.append(f"@{raw} is a secrets file: never attached (refer to a credential by its name)")
            continue
        doc_kind = path.lower().endswith((".pdf", ".docx"))
        if doc_kind:
            body = gnoc_collab.doc_text(path, _MENTION_FILE_CAP + 2000)
            if not body.strip():
                blocks.append(f"@{raw} is a document with no extractable text layer ({os.path.getsize(path)} bytes);"
                              " the path is attached, not its content.")
                continue
        else:
            try:
                with open(path, encoding="utf-8", errors="replace") as f:
                    body = f.read(_MENTION_FILE_CAP + 1)   # never the whole of a multi-GB log
            except OSError:
                continue
        if not doc_kind and "\x00" in body[:1024]:
            blocks.append(f"@{raw} is a binary file ({os.path.getsize(path)} bytes); the path is attached, not its content.")
            continue
        cut = body if len(body) <= _MENTION_FILE_CAP \
            else body[:_MENTION_FILE_CAP] + f"\n[… truncated: {os.path.getsize(path)} bytes total …]"
        blocks.append(f"[attached @{raw} → {_rel_home(path)}"
                      + (" - document text extracted]" if doc_kind else "]") + f"\n{cut}")
        total += len(cut)
        if total > _MENTION_TOTAL_CAP:
            break
    if not blocks:
        return text
    return text + "\n\n" + "\n\n".join(blocks) + "\n[attachments end]"


def _mention_paths(word):
    """Files and dirs matching a @mention fragment, for Tab completion. Relative results are relative to
    the active repo; the hunt workspace joins when it is not the active root. ~ and / fragments resolve
    normally. Dirs get a trailing slash so they read as dirs."""
    (
        WS, glob, os, root,
    ) = bind(
        "WS", "glob", "os", "root",
    )
    word = word or ""
    out = []
    if word.startswith("~"):
        full = os.path.expanduser(word)
        for c in sorted(glob.glob(full + "*")):
            out.append(c + ("/" if os.path.isdir(c) else ""))
        return out[:50]
    if word.startswith("/"):
        for c in sorted(glob.glob(word + "*")):
            out.append(c + ("/" if os.path.isdir(c) else ""))
        return out[:50]
    bases = [root()]
    if WS != root():
        bases.append(WS)
    for b in bases:
        for c in sorted(glob.glob(os.path.join(b, word) + "*")):
            out.append(os.path.relpath(c, root()) + ("/" if os.path.isdir(c) else ""))
            if os.path.isdir(c):   # one level of look-ahead: 'src' completes src/app.py, not just src/
                for child in sorted(glob.glob(os.path.join(c, "*")))[:20]:
                    out.append(os.path.relpath(child, root()) + ("/" if os.path.isdir(child) else ""))
    return list(dict.fromkeys(out))[:50]


def _setup_completion():
    """Tab completes /commands and @paths on the prompt line. readline stays fully intact (emacs keys,
    history); this only adds a completer, the same way a shell adds its own. Ctrl-R / Ctrl-S are bound
    explicitly so they work on every readline build."""
    (
        AGENT_HELP, FILE_MARKER, _mention_paths, re, readline, sys,
    ) = bind(
        "AGENT_HELP", "FILE_MARKER", "_mention_paths", "re", "readline", "sys",
    )
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return
    try:
        names = tuple(dict.fromkeys(re.findall(r"^  /([a-z0-9]+)\b", AGENT_HELP, re.M)))

        def complete(text, state):
            # readline replaces only the word under the cursor (`text`), so return THAT word's completion: the
            # whole buffer was returned before, and `read @al<Tab>` became `read read @alpha.py` (QAQC 2026-11-19)
            buf = readline.get_line_buffer()[:readline.get_endidx()]
            if text.startswith("/") and buf.lstrip() == text:   # the command word itself
                hits = [n for n in names if n.startswith(text[1:])]
                return ("/" + hits[state] + " ") if state < len(hits) else None
            if text.startswith("@"):
                hits = _mention_paths(text[1:])
                return ("@" + hits[state]) if state < len(hits) else None
            return None

        readline.set_completer(complete)
        readline.set_completer_delims(" \t\n\"'`")
        readline.parse_and_bind('"\\t": complete')
        readline.parse_and_bind(r'"\C-r": reverse-search-history')
        readline.parse_and_bind(r'"\C-s": forward-search-history')
        # Ctrl-O appends the attach marker and submits: the REPL asks for a file and attaches it as an
        # @path mention. The typed line rides along, so the file lands at the END of the message.
        readline.parse_and_bind('"\\C-o": "\\C-e' + FILE_MARKER + '\\n"')
    except Exception:  # noqa: BLE001 - completion is garnish; the prompt works without it
        pass


def export_transcript(agent, path=None):
    """Write this conversation to Markdown. Default: out/chat-<sid>.md under the active repo. A named
    target stays inside the repo or the workspace, and the name is whitelisted so a stray byte can never
    pick a path outside them."""
    (
        WS, _now, _title_of, contextlib, json, os, re, root,
    ) = bind(
        "WS", "_now", "_title_of", "contextlib", "json", "os", "re", "root",
    )
    if path:
        if not re.fullmatch(r"[\w./~-]+", path):
            return None, "usage: /export [name.md]  (letters, digits, / . _ - ~ only)"
        if not path.endswith(".md"):
            path += ".md"
        target = os.path.realpath(os.path.expanduser(path if os.path.isabs(path) else os.path.join(root(), path)))
    else:
        target = os.path.realpath(os.path.join(root(), "out", f"chat-{agent.s.get('sid', 'session')}.md"))
    if not (target.startswith(os.path.realpath(root()) + os.sep) or target.startswith(os.path.realpath(WS) + os.sep)):
        return None, "export stays inside the active repo or the workspace"
    lines = [f"# gnoc chat — {_title_of(agent.s.get('history') or [])}", "",
             f"- session: {agent.s.get('sid', '?')}", f"- program: {agent.ctx.program or 'none'}",
             f"- repo: {root()}", f"- exported: {_now().isoformat()}", ""]
    for m in agent.s.get("history") or []:
        role, c = m.get("role"), (m.get("content") or "").strip()
        if role == "user":
            lines += ["## You", "", c, ""]
        elif role == "assistant":
            if c:
                lines += ["## gnoc", "", c, ""]
            for t in m.get("tool_calls") or []:
                fn = (t.get("function") or {})
                args = fn.get("arguments")
                if isinstance(args, str) and args.strip():
                    with contextlib.suppress(Exception):
                        args = json.dumps(json.loads(args), indent=2)
                lines += [f"### tool: {fn.get('name')}", "", "```json", str(args)[:4000], "```", ""]
        elif role == "tool":
            lines += ["```", c[:8000], "```", ""]
    os.makedirs(os.path.dirname(target), exist_ok=True)
    import gnoc_secrets
    with open(target, "w", encoding="utf-8") as f:
        # an export is a file people share: every known secret is redacted, the operator's own pastes included
        f.write(gnoc_secrets.redact("\n".join(lines)))
    return target, None
