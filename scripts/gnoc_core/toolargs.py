"""Tool-argument hardening: aliases, coercion, placeholder/refusal checks and the per-tool wrapper."""
import json
import re

from .util import _parse_literal


_LEARN_READ_WORDS = {"list", "read", "show", "recent", "all", "recall", "search", "get", "view", "ls"}


class _BadArg(ValueError):
    pass


_ARG_ALIASES = {"file": "path", "file_path": "path", "filepath": "path", "filename": "path", "dir": "path",
                "directory": "path", "cmd": ("command", "args"), "command": "args", "q": ("query", "pattern"),
                "search": ("query", "pattern"),
                # grep(query='truncate') three times in a row, a task to the 420 s cap (SWE drive 2026-11-22):
                # a tool with pattern and no query takes the query as its pattern
                "query": "pattern", "regex": "pattern", "link": "url", "uri": "url", "id_": "id",
                "identity": "as_identity", "timeout_s": "timeout"}


def _alias_targets(k):
    t = _ARG_ALIASES.get(k)
    return () if t is None else ((t,) if isinstance(t, str) else tuple(t))


def apply_arg_aliases(args, accepted):
    """Rename what the model sent to what the tool takes, in place. Returns the same dict."""
    for k in list(args):
        if k in accepted:
            continue
        for target in _alias_targets(k):
            if target in accepted and target not in args:
                args[target] = args.pop(k)
                break
    return args


_JSON_STRING_KEYS = {"body", "revert_body", "data", "js", "content", "patch", "rules_string"}


def _coerce(key, v, spec):
    """One argument -> the type its schema names. Raises _BadArg with the fix."""
    spec = spec or {}
    t = spec.get("type")
    shown = repr(str(v)[:60])
    if t == "integer":
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip().strip("'\"")
        if re.fullmatch(r"[+-]?\d+(\.0*)?", s):
            return int(float(s))
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", s):
            return int(s, 16)  # malware start=0x401000
        raise _BadArg(f"{key} must be a whole number like 20, got {shown}")
    if t == "boolean":
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return bool(v)
        s = str(v).strip().strip("'\"").lower()
        if s in ("true", "yes", "y", "1", "on"):
            return True
        if s in ("false", "no", "n", "0", "off", "none", "null", ""):
            return False
        raise _BadArg(f"{key} must be true or false, got {shown}")
    if t == "array":
        if isinstance(v, (list, tuple)):
            items = list(v)
        elif isinstance(v, dict):
            items = [v]  # one op object where a list of ops was meant
        else:
            s = str(v).strip()
            items = []
            if s and s[:1] in "[{(":   # "" is "in" every string: an empty value is an empty list, not a parse
                try:
                    got = _parse_literal(s)
                    items = list(got) if isinstance(got, (list, tuple)) else [got]
                except ValueError:
                    raise _BadArg(f"{key} must be a list like [\"a\", \"b\"], got {shown}") from None
            elif "\n" in s:
                items = [x.strip() for x in s.splitlines() if x.strip()]
            elif re.fullmatch(r"[\w./@:+-]+(\s*,\s*[\w./@:+-]+)+", s):
                items = [x.strip() for x in s.split(",")]  # 'A,B' / 'semgrep,gitleaks', never prose with commas
            elif s:
                items = [s]
        enum = (spec.get("items") or {}).get("enum")
        if enum:
            items = [_coerce(key, x, spec["items"]) for x in items]
        return items
    if t == "object":
        if isinstance(v, dict):
            return v
        s = str(v).strip()
        if not s:
            return {}
        try:
            got = _parse_literal(s)
            if isinstance(got, dict):
                return got
        except ValueError:
            pass
        lines = [ln for ln in s.splitlines() if ln.strip()]
        if lines and all(re.match(r"^[\w-]+\s*:", ln) for ln in lines):  # raw 'Cookie: a=b' header lines
            return {ln.split(":", 1)[0].strip(): ln.split(":", 1)[1].strip() for ln in lines}
        raise _BadArg(f"{key} must be an object like {{\"Cookie\": \"a=b\"}}, got {shown}")
    if t == "string":
        if isinstance(v, (dict, list)) and key in _JSON_STRING_KEYS:
            v = json.dumps(v)
        elif isinstance(v, list):
            # a command given as argv joins with spaces (["pytest", "-x"] is `pytest -x`, not "pytest, -x");
            # anything else is a list of names (QAQC 2026-11-19)
            import shlex
            v = shlex.join(str(x) for x in v) if key in ("command", "cmd", "args") else ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = json.dumps(v)
        elif not isinstance(v, str):
            v = str(v).lower() if isinstance(v, bool) else str(v)
        enum = spec.get("enum")
        if enum and v not in enum:
            low = {str(e).lower(): e for e in enum}
            if v.strip().lower() in low:
                return low[v.strip().lower()]
            raise _BadArg(f"{key} must be one of {', '.join(map(str, enum))}; got {shown}")
        return v
    return v  # untyped or a union ('object or string'): the tool handles it


_PLACEHOLDER_ARG = re.compile(r"^<[^<>\n]{2,60}>$")


_REFERENCE_ARGS = {"path", "paths", "url", "read_url", "write_url", "file", "dir", "draft_dir", "program", "name",
                   "from_raw", "host", "sid", "uid", "id", "agent", "model", "artifact", "receipt", "repo", "target",
                   "tool", "channel", "to", "as_identity", "image", "wordlist"}


_PRECHECK = {}   # tool name -> precheck(args): the missing-argument refusal, asked before any approval prompt


_SHELLISH = re.compile(r"^\s*(?:(?:bash|sh|zsh)\s+-c\b|(?:python3?|pytest|npm|node|go|cargo)\s+\S|"
                       r"cd\s+\S+\s*&&|\./\S+\.(?:sh|py)\b)")


# bg: it STARTS commands. Left out, `bg action=start command='python3 -m http.server 8765'` (and every npm / node /
# go / cargo dev server) was refused as "bg does not run commands"; the lead fell back to `bash ... &`, which needs
# approval, and no server ever started (verification drive 2026-11-21).
_COMMAND_TOOLS = {"bash", "bg", "run_tests", "apply_patch", "write_file", "edit_file", "delegate", "fan_out",
                  "team", "second_opinion", "claude_worker", "hypothesize", "code_review", "provision", "desktop",
                  "gnoc", "goal", "notes", "todo", "scan", "recon", "sast", "plan"}


_FREE_TEXT_KEYS = frozenset({"message", "query", "text", "body", "js", "content", "brief", "task", "title",
                             "description", "note", "notes", "reason", "why", "hypothesis", "assumption",
                             "violation", "prompt", "question", "focus", "terms", "summary", "subject",
                             "worker_note", "new", "old", "pattern", "revert_body", "payload", "data"})


def misrouted_command(name, args):
    """'you asked a non-command tool to run a command' - the fix, named.

    Measured 2026-10-25: asked to run a test file, the lead called oast(args="bash -c 'cd ... && python3
    scripts/test_gnoc_oast.py'") five times. The repeat breaker refused the repeats but nothing ever told
    it which tool it actually wanted, so it spent 25 calls and 488k tokens and never ran the tests."""
    if name in _COMMAND_TOOLS:
        return None
    for k, v in (args or {}).items():
        # free text may START with "go " or "npm " and be prose: a commit message, a search query, a note, a
        # request body (QAQC 2026-11-19: git(message='npm scripts: add lint') was refused as a shell command)
        if k in _FREE_TEXT_KEYS:
            continue
        if k in ("path", "paths", "file", "files", "dir", "folder") and isinstance(v, str) and not v.strip().count(" "):
            continue    # read_file(path='./tests/test_store.py') is a path, not `./script.py` run (2026-11-22)
        if isinstance(v, str) and _SHELLISH.match(v):
            cmd = v.strip()[:80]
            return (f"bad arguments: {name} does not run commands - {k}={cmd!r} is a shell command. "
                    f"To run a command use bash(command=...); to run a test file use "
                    f"run_tests(files=['<path>']); to find a file use find_file(name=...).")
    return None


_PATHISH_ARGS = ("path", "file", "file_path", "filepath", "filename", "dir", "directory")


_LOOKS_LIKE_PATH = re.compile(r"^[\w./~*-]+(?:/[\w./*-]+)*\.[A-Za-z0-9]{1,6}$|/")


def misrouted_lesson_read(name, args):
    """'you asked the WRITER to read' - the fix, named. learn(action='list') and learn(text='list') were
    both tried for "read the lesson book" (soak batch11 2026-10-25); the second would have stored a
    lesson whose content was the word "list"."""
    if name != "learn":
        return None
    # only the keys that carry the INTENT: a real lesson with why="show" is not a read request
    for k in ("text", "action", "kind", "query", "cmd", "command"):
        v = (args or {}).get(k)
        if isinstance(v, str) and v.lower().strip(" .:-") in _LEARN_READ_WORDS:
            return (f"bad arguments: learn WRITES one lesson; {v.strip()!r} is a read. To read the lesson "
                    f"book use lessons() for the most recent, or lessons(query=<words>) to search it.")
    return None


def misrouted_file_read(name, args, accepted):
    """'you handed a file path to a tool that does not read files' - the fix, named.

    Measured 2026-10-25 (soak batch7): asked to explain LEAD vs FINDING-CANDIDATE, the agent wanted
    scripts/learn/SPEC-gnoc-leads-20261021.md and called learn(limit='200', path='learn/SPEC-...md'),
    twice. learn WRITES a lesson; the path merely starts with the same word as the directory. The
    unknown arguments were dropped silently and the refusal then complained about missing text, which
    names neither the mistake nor the tool that does the job, so the model repeated the call."""
    if "path" in accepted:
        return None
    for k in _PATHISH_ARGS:
        v = (args or {}).get(k)
        if isinstance(v, str) and v.strip() and _LOOKS_LIKE_PATH.search(v.strip()):
            got = v.strip()[:80]
            if name == "touch":
                # `touch` here is proof-ladder rung 4: a REAL reversible write against a live target.
                # It shares its name with the shell command every model knows, so a path in the
                # arguments means the model wanted the other one. Driven under -s-p 2026-10-25: asked
                # to create an empty file, the lead called touch(path=...). Say what this tool is, or
                # the next attempt guesses read_url/write_url and fires at a bug-bounty target.
                return (f"bad arguments: this `touch` is NOT the shell's touch and does not take a "
                        f"path ({k}={got!r}). It performs a REAL reversible write on a live target "
                        f"object one of our research accounts owns, and it is the user's call every "
                        f"time. To create or write a file use write_file(path=..., content=...); to "
                        f"run the shell's touch use bash(command='touch <path>').")
            return (f"bad arguments: {name} does not read files - it has no {k} argument, and {k}={got!r} "
                    f"is a path. To read a file use read_file(path=...); to find one use "
                    f"find_file(name=...); to search inside files use grep(pattern=...).")
    return None


# name -> (accepted args, required args, {arg: enum}) for every hardened tool: lets a refusal name the tool whose
# signature the model's arguments actually fit
_SIGNATURES = {}


def fits_other_tool(name, args):
    """Other tools these exact arguments fit (every passed name accepted, every required one present, every enum
    value allowed), best first. team(action='answer', answers={...}) is defend's signature; saying only "team needs
    brief" sent the lead round twice and then off looking for a way past approval (2026-11-20 defender drive)."""
    keys = {k for k, v in (args or {}).items() if v is not None}
    if not keys:
        return []
    out = []
    for other, (acc, req, enums) in _SIGNATURES.items():
        if other == name or not keys <= set(acc) or any(r not in keys for r in req):
            continue
        if any(k in enums and str(args.get(k)) not in enums[k] for k in keys):
            continue
        out.append((len(set(acc) - keys), other))
    return [t for _, t in sorted(out)][:2]


def _harden(name, impl, schema):
    """Wrap one tool so the model's arguments are fixed up (or refused with the fix) before the tool sees them."""
    import functools
    import inspect
    params_spec = schema["function"]["parameters"]
    props = params_spec.get("properties") or {}
    sig = inspect.signature(impl)
    accepted = [p for p in sig.parameters if p != "ctx"]
    # only what the FUNCTION cannot default: git with no action still means status, as it always did
    required = [p for p in accepted if sig.parameters[p].default is inspect.Parameter.empty]
    _SIGNATURES[name] = (accepted, required, {k: [str(x) for x in v["enum"]] for k, v in props.items()
                                              if isinstance(v, dict) and isinstance(v.get("enum"), list)})

    def usage():
        """'It takes: args (? = optional)' read as "args is optional" while the same line demanded it
        (soak batch7 2026-10-25). The legend only belongs on a signature that actually has a ? in it."""
        shown = [f"{p}{'' if p in required else '?'}" for p in accepted if p in props]
        return ", ".join(shown) + (" (? = optional)" if any(p.endswith("?") for p in shown) else "")

    def missing_of(args):
        return [k for k in required if args.get(k) is None or (isinstance(args.get(k), str) and
                                                               not args[k].strip() and k not in ("new", "content"))]

    def refusal(args, missing):
        """An argument the tool does not take is dropped silently, so "gnoc needs args" was all the agent
        saw after sending gnoc(command='status') - nothing connected the two, and it re-sent the same call
        (soak batch7 2026-10-25). An alias table only covers the renames we thought of; naming the dropped
        argument beside the missing one covers the rest."""
        msg = f"bad arguments: {name} needs {', '.join(missing)}. It takes: {usage()}"
        unknown = [k for k in args if k not in accepted]
        if not unknown:
            return msg
        got = ", ".join(sorted(unknown))
        # another tool's signature only when the call is not a plain rename (learn(limit=) wants "text", not a tool
        # that happens to take limit): two or more stray arguments, or one that carries a whole action
        other = fits_other_tool(name, args) if (len(unknown) >= 2 or set(unknown) & {"command", "url", "answers"}) \
            else []
        if other:
            return (f"{msg}. You passed {got}, which {name} does not take - those arguments are "
                    f"{' or '.join(other)}'s: call {other[0]} with them instead.")
        if len(unknown) == 1 and len(missing) == 1:
            return f"{msg}. You passed {got}, which {name} does not take: did you mean {missing[0]}?"
        return f"{msg}. You passed {got}, which {name} does not take."

    def precheck(args):
        """The refusal call() would give for a missing argument, or None. _plan_call asks this BEFORE the
        approval prompt: an edit_file with no path was put to the user as "allow edit_file?", and their yes was
        then refused here anyway (driven 2026-10-24)."""
        a = apply_arg_aliases(dict(args or {}), accepted)
        # the same redirect call() gives, because _plan_call returns THIS refusal and call() never runs:
        # gnoc(path='scripts/gnoc_pay.py') got the generic "gnoc does not take path" and not the line
        # naming read_file, because misrouted_file_read was wired into call() alone (soak batch9 2026-10-25)
        astray = misrouted_file_read(name, a, accepted) or misrouted_lesson_read(name, a)
        if astray:
            return astray
        missing = missing_of(a)
        return refusal(a, missing) if missing else None

    _PRECHECK[name] = precheck

    @functools.wraps(impl)
    def call(ctx, **args):
        args, notes = apply_arg_aliases(dict(args), accepted), []
        unknown = [k for k in args if k not in accepted]
        astray = misrouted_file_read(name, args, accepted) or misrouted_lesson_read(name, args)
        if astray:
            return astray
        dropped = {k: args.pop(k) for k in unknown}
        if unknown:
            notes.append(f"(ignored unknown argument(s) {', '.join(unknown)}: {name} takes {usage()})")
        for k in [k for k, v in args.items() if v is None and k not in required]:
            del args[k]  # null for an optional = use the default
        missing = missing_of(args)
        if missing:
            return refusal(dict(args, **dropped), missing)
        for k, v in args.items():
            # "<login raw capture>" was passed to identities(from_raw=) verbatim (2026-10-22): a literal
            # placeholder is never a real value, and this is the one place every call passes. But a security
            # tool legitimately greps for "<img src=x onerror=alert(1)>" and writes "<svg onload=...>": only a
            # REFERENCE argument (a path, url, program, name...) is checked, never free text.
            if isinstance(v, str) and k in _REFERENCE_ARGS and _PLACEHOLDER_ARG.match(v.strip()):
                return (f"bad arguments: {name} {k}={v.strip()!r} is a placeholder, not a value. Substitute the "
                        f"real {k} (read it from a file or a tool result first), or leave {k} out.")
        wrong = misrouted_command(name, args)
        if wrong:
            return wrong
        try:
            for k in list(args):
                args[k] = _coerce(k, args[k], props.get(k))
        except _BadArg as e:
            return f"bad arguments: {name}: {e}. It takes: {usage()}"
        out = impl(ctx, **args)
        return (str(out) + "\n" + " ".join(notes)) if notes else out
    return call
