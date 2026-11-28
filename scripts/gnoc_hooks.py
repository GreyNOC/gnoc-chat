"""gnoc_hooks.py - the operator's own automation around tool calls, and their own slash commands.

HOOKS. A hook is a shell command the harness runs around a tool call, so a rule holds every time instead of
whenever the model remembers it: format a file after every edit, run the type checker after a patch, refuse
writes under migrations/. Two files are read:

    ~/.gnoc/hooks.json          yours; always active
    <repo>/.gnoc/hooks.json     the repo's; active only after `/hooks trust` in that repo, and only while the
                                file is byte-identical to what was trusted (a pulled change turns it off again)

    {"pre_tool":  [{"tools": "edit_file|write_file|apply_patch", "files": "migrations/*",
                    "command": "echo 'migrations are generated, never hand-edited' >&2; exit 2"}],
     "post_tool": [{"tools": "edit_file|write_file|apply_patch", "files": "*.py",
                    "command": "ruff format $GNOC_FILES"}]}

tools is a regex over the tool name (full match). files, optional, is a glob (or a list) matched against the
repo-relative paths the call touches; a hook with files set is skipped by a call that touches none of them.
The command runs under bash in the repo with GNOC_TOOL, GNOC_FILES (space-separated) and GNOC_REPO set and a
JSON object on stdin ({tool, args, cwd} and, for post_tool, result). A pre_tool hook that exits 2 BLOCKS the
call and its stderr is the reason the model reads; any other exit lets it run. A post_tool hook's output is
appended to the tool result, so the model sees the formatter's or the type checker's verdict at once.

COMMANDS. A Markdown file in ~/.gnoc/commands/, <repo>/.gnoc/commands/ or <repo>/.claude/commands/ is a slash
command named after the file: /review-pr 42 sends the file's text with $ARGUMENTS replaced by "42". A first
line `description: ...` (or YAML front matter with description) is shown in /commands.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import subprocess

HOOK_TIMEOUT = 60
OUT_MAX = 1500


def _home():
    return os.environ.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def user_hooks_path():
    return os.path.join(_home(), "hooks.json")


def repo_hooks_path(repo):
    return os.path.join(repo, ".gnoc", "hooks.json")


def _trust_path():
    return os.path.join(_home(), "trusted-hooks.json")


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _read_once(path):
    """(bytes, sha256) from ONE read: hashing one read and parsing another let a file swapped in between run
    unverified hooks (QAQC r2)."""
    with open(path, "rb") as f:
        data = f.read()
    return data, hashlib.sha256(data).hexdigest()


def _trusted():
    try:
        with open(_trust_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def trust(repo):
    """Trust the repo's hooks file exactly as it is now. Returns a message."""
    p = repo_hooks_path(repo)
    if not os.path.isfile(p) or os.path.islink(p):
        return f"no {p} to trust (a symlink is never trusted)"
    data, sha = _read_once(p)
    _load(p, data)   # refuse to trust a file that does not parse - the SAME bytes that are hashed
    d = _trusted()
    d[os.path.realpath(p)] = sha
    os.makedirs(_home(), exist_ok=True)
    tmp = _trust_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, _trust_path())
    return f"trusted {p} (sha256 {d[os.path.realpath(p)][:12]}); it stops running if the file changes"


def untrust(repo):
    d = _trusted()
    if d.pop(os.path.realpath(repo_hooks_path(repo)), None) is None:
        return "this repo's hooks were not trusted"
    with open(_trust_path(), "w") as f:
        json.dump(d, f, indent=1)
    return "repo hooks untrusted"


def _load(path, data=None):
    if data is None:
        with open(path, "rb") as f:
            data = f.read()
    d = json.loads(data.decode("utf-8"))
    if not isinstance(d, dict):
        raise ValueError("hooks.json must be an object with pre_tool / post_tool lists")
    out = {}
    for phase in ("pre_tool", "post_tool"):
        rows = d.get(phase) or []
        if not isinstance(rows, list):
            raise ValueError(f"{phase} must be a list")
        good = []
        for r in rows:
            if not isinstance(r, dict) or not str(r.get("command") or "").strip():
                raise ValueError(f"each {phase} hook needs a command")
            re.compile(str(r.get("tools") or ".*"))
            good.append(r)
        out[phase] = good
    return out


def repo_state(repo):
    """'none' | 'trusted' | 'untrusted' | 'changed' for the repo's hooks file."""
    p = repo_hooks_path(repo)
    if not os.path.isfile(p):
        return "none"
    want = _trusted().get(os.path.realpath(p))
    if not want:
        return "untrusted"
    return "trusted" if want == _sha(p) else "changed"


def active(repo):
    """[(source, phase, hook)] for every hook that runs here, plus [warnings]."""
    rows, warn = [], []
    srcs = [("user", user_hooks_path(), None)]
    st = repo_state(repo) if repo else "none"
    if st == "trusted":
        p = repo_hooks_path(repo)
        try:
            data, sha = _read_once(p)
        except OSError:
            data, sha = b"", ""
        if sha and sha == _trusted().get(os.path.realpath(p)) and not os.path.islink(p):
            srcs.append(("repo", p, data))
        else:
            warn.append(f"{p} changed while it was being read; it does not run")
    elif st in ("untrusted", "changed"):
        warn.append(f"{repo_hooks_path(repo)} is {'not trusted' if st == 'untrusted' else 'changed since you trusted it'}"
                    " and does not run (/hooks trust to allow it)")
    for src, p, data in srcs:
        if data is None and not os.path.isfile(p):
            continue
        try:
            d = _load(p, data)
        except (OSError, ValueError, re.error) as e:
            warn.append(f"{p}: {type(e).__name__}: {e}")
            continue
        for phase in ("pre_tool", "post_tool"):
            for h in d.get(phase, []):
                rows.append((src, phase, h))
    return rows, warn


_PATCH_NAME = re.compile(r'(?m)^(?:---|\+\+\+|\*\*\*) (?:"([^"]*)"|(\S+))|^(?:rename|copy) (?:from|to) (.+)$')


def touched_files(tool, args):
    """Repo-relative paths a call names (best effort)."""
    args = args if isinstance(args, dict) else {}
    out = []
    for k in ("path", "file"):
        if isinstance(args.get(k), str) and args[k]:
            out.append(args[k])
    for k in ("paths", "files"):
        v = args.get(k)
        if isinstance(v, str) and v:
            out.append(v)
        elif isinstance(v, list):
            out += [str(x) for x in v if x]
    if tool == "apply_patch" and isinstance(args.get("patch"), str):
        for m in _PATCH_NAME.finditer(args["patch"]):
            n = (m.group(1) or m.group(2) or m.group(3) or "").split("\t")[0].strip()
            if n and n != "/dev/null" and not n.startswith("*"):
                out.append(re.sub(r"^[ab]/", "", n))
    return list(dict.fromkeys(out))


def _rel_paths(repo, files):
    """Each name as the repo-relative REAL path, the form the docs promise a `files` glob is matched against:
    `./migrations/1.py` and `/abs/repo/migrations/1.py` slipped past a "migrations/*" block (QAQC r2)."""
    out = []
    root = os.path.realpath(repo) if repo else ""
    for f in files:
        p = os.path.realpath(os.path.join(root, os.path.expanduser(f)) if root and not os.path.isabs(
            os.path.expanduser(f)) else os.path.expanduser(f))
        out.append(os.path.relpath(p, root) if root and (p + os.sep).startswith(root + os.sep) else f)
    return list(dict.fromkeys(out + list(files)))


def _matches(hook, tool, files):
    try:
        if not re.fullmatch(str(hook.get("tools") or ".*"), tool):
            return False
    except re.error:
        return False
    pats = hook.get("files")
    if not pats:
        return True
    pats = [pats] if isinstance(pats, str) else list(pats)
    return any(fnmatch.fnmatch(f, p) or fnmatch.fnmatch(os.path.basename(f), p) for f in files for p in pats)


def _run(hook, repo, tool, files, payload, env_base=None):
    env = dict(env_base if env_base is not None else os.environ)
    env.update({"GNOC_TOOL": tool, "GNOC_FILES": " ".join(files), "GNOC_REPO": repo})
    limit = max(1, min(int(hook.get("timeout") or HOOK_TIMEOUT), 600))
    try:
        import gnoc_compat   # bash on Linux/macOS, PowerShell on native Windows
        p = subprocess.Popen(gnoc_compat.shell_argv(str(hook["command"])), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, cwd=repo, env=env, errors="replace",
                             start_new_session=True)
    except OSError as e:
        return 127, "", str(e)
    try:
        so, se = p.communicate(json.dumps(payload, default=str), timeout=limit)
        return p.returncode, (so or "").strip(), (se or "").strip()
    except subprocess.TimeoutExpired:
        # the WHOLE group: killing bash alone left `sleep | cat` children running (QAQC r2)
        import signal
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return 124, "", f"hook timed out after {limit}s"


def pre(repo, tool, args, env=None):
    """None to let the call run, or the block reason (a string) when a pre_tool hook exits 2."""
    rows, _ = active(repo)
    files = _rel_paths(repo, touched_files(tool, args))
    for src, phase, h in rows:
        if phase != "pre_tool" or not _matches(h, tool, files):
            continue
        code, out, err = _run(h, repo, tool, files, {"tool": tool, "args": args, "cwd": repo}, env)
        if code == 124:   # a guard that could not decide does not wave the call through
            return f"BLOCKED: your {src} pre_tool hook timed out ({str(h['command'])[:80]}); the call did not run"
        if code == 2:
            return (f"BLOCKED by your {src} pre_tool hook ({str(h['command'])[:80]}): "
                    + ((err or out)[:OUT_MAX] or "it exited 2 without a reason"))
    return None


def post(repo, tool, args, result, env=None):
    """Text to append to the tool result ('' when no hook ran or none printed anything)."""
    rows, _ = active(repo)
    files = _rel_paths(repo, touched_files(tool, args))
    notes = []
    for src, phase, h in rows:
        if phase != "post_tool" or not _matches(h, tool, files):
            continue
        code, out, err = _run(h, repo, tool, files, {"tool": tool, "args": args, "cwd": repo,
                                                     "result": str(result)[:4000]}, env)
        text = "\n".join(x for x in (out, err) if x)
        if code or text:
            notes.append(f"[{src} post_tool hook `{str(h['command'])[:60]}` exit {code}]"
                         + (("\n" + text[-OUT_MAX:]) if text else ""))
    return "\n".join(notes)


def describe(repo):
    rows, warn = active(repo)
    out = [f"user hooks: {user_hooks_path()}" + ("" if os.path.isfile(user_hooks_path()) else " (none)"),
           f"repo hooks: {repo_hooks_path(repo)} ({repo_state(repo)})"]
    for src, phase, h in rows:
        out.append(f"  [{src}] {phase} tools={h.get('tools') or '.*'}"
                   + (f" files={h.get('files')}" if h.get("files") else "") + f": {str(h['command'])[:100]}")
    out += [f"  ! {w}" for w in warn]
    return "\n".join(out)


# ------------------------------------------------------------------ custom slash commands
def command_dirs(repo):
    dirs = [os.path.join(_home(), "commands")]
    if repo:
        dirs += [os.path.join(repo, ".gnoc", "commands"), os.path.join(repo, ".claude", "commands")]
    return dirs


def _parse(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    desc = ""
    m = re.match(r"^---\n(.*?)\n---\n?", text, re.S)
    if m:
        dm = re.search(r"(?m)^description:\s*(.+)$", m.group(1))
        desc = dm.group(1).strip().strip("\"'") if dm else ""
        text = text[m.end():]
    else:
        dm = re.match(r"^description:\s*(.+)\n", text)
        if dm:
            desc, text = dm.group(1).strip(), text[dm.end():]
    return desc, text.strip()


def commands(repo):
    """{name: (path, description)}; a repo command overrides a user command of the same name."""
    out = {}
    for d in command_dirs(repo):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith(".md") and re.match(r"^[A-Za-z0-9][\w-]*\.md$", fn):
                p = os.path.join(d, fn)
                try:
                    desc, _ = _parse(p)
                except OSError:
                    continue
                out[fn[:-3].lower()] = (p, desc)
    return out


def expand(repo, name, arguments):
    """The prompt text for /name arguments, or None when there is no such command."""
    got = commands(repo).get(str(name or "").lower())
    if not got:
        return None
    _, body = _parse(got[0])
    args = str(arguments or "").strip()
    if "$ARGUMENTS" in body:
        return body.replace("$ARGUMENTS", args)
    return body + (f"\n\n{args}" if args else "")
