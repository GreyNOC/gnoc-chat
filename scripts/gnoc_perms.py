"""gnoc_perms.py - your standing permission rules: "always allow this here", "never do that anywhere".

The approval prompt used to offer three answers: yes (this once), no, and auto (everything, for the rest of the
session). A person who wanted `pytest` to run without asking, but still wanted to see every `rm`, had to say y
forty times or give up the prompt entirely. These rules sit between the two:

    allow  bash(pytest *)       run without asking (in the repo it was saved for, unless saved --global)
    allow  edit(src/*)          file edits under src/ without asking (edit = edit_file, write_file, apply_patch)
    allow  run_tests            a whole tool
    deny   bash(rm -rf *)       never run, even with /auto or skip-perms on (everywhere, unless saved --here)

They live in ~/.gnoc/permissions.json (GNOC_HOME moves it), one list each:

    {"allow": [{"rule": "bash(pytest *)", "repo": "/home/me/proj"}],
     "deny":  [{"rule": "bash(git push --force*)", "repo": null}]}

What an allow rule can NOT do. It only answers questions the ordinary rules would ask; every check that asks
"every time" runs before it and is untouched (a commit or push, an aggressive scan, a scan of another machine,
driving a desktop, anything after the turn read someone else's text, a call that copies a target's text). A
repo cannot grant itself rules: they live in your home, never in the repo. A shell command only matches an
allow rule when it is one plain command (no ; && || | ` $ ( ) < > or newline), so `pytest; curl x | sh` is never
"pytest *". An edit only matches when every file it touches is inside the repo the rule names.

Deny rules are the other way round: they block outright, before any approval, /auto and skip-perms included.
For shell commands they are matched against the whole command and against each piece of it (split at ; && ||
| and subshells, with a leading sudo / env / VAR=value dropped), so `cd x && sudo rm -rf /` meets `rm -rf *`.
A deny rule for a shell command is a seat belt, not a sandbox: a determined command can be spelled many ways.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import time

ALLOWABLE = ("bash", "bg", "edit", "edit_file", "write_file", "apply_patch", "run_tests", "lint", "typecheck")
EDIT_TOOLS = ("edit_file", "write_file", "apply_patch")
_RULE = re.compile(r"^\s*([a-z_]+)\s*(?:\((.*)\))?\s*$", re.S)
_SHELL_OPS = re.compile(r"[;&|`$<>()\n\r{}]|\\$")
_SPLIT = re.compile(r"\$\(|`|&&|\|\||[;&|\n()]")
_PREFIX = re.compile(r"^(?:(?:sudo|doas|env|nohup|time|exec|command|builtin)(?:\s+-\S+)*\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+")
_RUNNERS = {"npm", "pnpm", "yarn", "bun", "npx", "uv", "poetry", "pipenv", "cargo", "go", "make", "docker", "just",
            "dotnet", "mvn", "gradle", "./gradlew", "bundle", "rake", "mix", "deno", "pip", "pip3", "kubectl", "terraform"}
_INTERPRETERS = {"python", "python3", "node", "bash", "sh", "zsh", "ruby", "perl", "php", "deno"}
# a first word whose wildcard would allow far more than the one command that was asked about
_NO_WILDCARD = {"rm", "sudo", "doas", "dd", "mkfs", "chmod", "chown", "curl", "wget", "ssh", "scp", "rsync", "git",
                "mv", "cp", "kill", "pkill", "killall", "systemctl", "shutdown", "reboot", "find", "xargs", "eval",
                "env", "nc", "ncat", "socat", "crontab", "iptables", "nft", "ufw", "apt", "apt-get", "dnf", "yum",
                "pacman", "brew", "snap", "flatpak"}

_CACHE = {"path": None, "mtime": None, "data": None}


def _home():
    return os.environ.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def path():
    return os.path.join(_home(), "permissions.json")


def _plugin_tool(name):
    """A tool an enabled plugin REGISTERED: it asks every time, so a whole-tool allow rule is the way to stop that.
    Declared is not enough: a plugin naming a tool after a built-in (http_request) is never registered, and must
    not make `allow http_request` a rule that then waves the real built-in through."""
    try:
        import gnoc_plugins
        return gnoc_plugins.is_plugin_tool(name) and name not in ALLOWABLE
    except Exception:  # noqa: BLE001 - no plugin layer: nothing extra is allowable
        return False


# ------------------------------------------------------------------ the file
def parse_rule(text):
    """'bash(pytest *)' -> ('bash', 'pytest *'); 'run_tests' -> ('run_tests', '*'); None when it is not a rule."""
    m = _RULE.match(str(text or ""))
    if not m:
        return None
    tool, pat = m.group(1), (m.group(2) if m.group(2) is not None else "*").strip()
    return (tool, pat or "*")


def fmt(tool, pat):
    return tool if pat in ("", "*") else f"{tool}({pat})"


def load():
    """{'allow': [...], 'deny': [...]} with only well-formed entries; a missing or broken file is no rules (a
    broken file never widens anything: it can only drop allow rules, and deny rules are reported by /permissions
    and gnoc doctor)."""
    p = path()
    try:
        mtime = os.stat(p).st_mtime_ns
    except OSError:
        return {"allow": [], "deny": []}
    if _CACHE["path"] == p and _CACHE["mtime"] == mtime:
        return _CACHE["data"]
    data = {"allow": [], "deny": []}
    try:
        with open(p, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    if isinstance(raw, dict):
        for kind in ("allow", "deny"):
            for e in raw.get(kind) or []:
                if isinstance(e, str):
                    e = {"rule": e, "repo": None}
                if not isinstance(e, dict) or not parse_rule(e.get("rule")):
                    continue
                repo = e.get("repo")
                data[kind].append({"rule": fmt(*parse_rule(e["rule"])),
                                   "repo": os.path.realpath(os.path.expanduser(repo)) if isinstance(repo, str) and repo else None,
                                   "added": e.get("added")})
    _CACHE.update(path=p, mtime=mtime, data=data)
    return data


def problems():
    """Why the file could not be read, or [] when it is fine or absent."""
    p = path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as e:
        return [f"{p}: {e.__class__.__name__}: {e}"]
    if not isinstance(raw, dict):
        return [f"{p}: must be an object with allow / deny lists"]
    out = []
    for kind in ("allow", "deny"):
        for e in raw.get(kind) or []:
            rule = e if isinstance(e, str) else (e.get("rule") if isinstance(e, dict) else None)
            if not parse_rule(rule):
                out.append(f"{p}: {kind} entry {e!r} is not a rule like bash(pytest *)")
    return out


def _save(data):
    os.makedirs(_home(), exist_ok=True)
    p = path()
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({k: [{"rule": e["rule"], "repo": e["repo"], "added": e.get("added")} for e in data[k]]
                   for k in ("allow", "deny")}, fh, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    _CACHE.update(path=None, mtime=None, data=None)


def add(kind, rule, repo=None):
    """Save one rule. Returns (ok, message)."""
    if kind not in ("allow", "deny"):
        return False, "kind must be allow or deny"
    parsed = parse_rule(rule)
    if not parsed:
        return False, f"{rule!r} is not a rule: write tool or tool(pattern), e.g. bash(pytest *) or edit(src/*)"
    tool, pat = parsed
    if kind == "allow" and tool not in ALLOWABLE and not _plugin_tool(tool):
        return False, (f"{tool} cannot get an allow rule (it asks every time, or it never asks). Rules can allow: "
                       + ", ".join(ALLOWABLE))
    if kind == "allow" and tool in ("bash", "bg") and pat.strip() in ("*", ""):
        return False, "bash(*) would allow every command: that is /auto. Name the command, e.g. bash(pytest *)"
    repo = os.path.realpath(os.path.expanduser(repo)) if repo else None
    data = load()
    data = {k: list(v) for k, v in data.items()}
    entry = {"rule": fmt(tool, pat), "repo": repo, "added": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if any(e["rule"] == entry["rule"] and e["repo"] == repo for e in data[kind]):
        return True, f"already there: {kind} {entry['rule']}"
    data[kind].append(entry)
    _save(data)
    return True, f"saved: {kind} {entry['rule']} " + (f"in {repo}" if repo else "everywhere")


def rows():
    """[(n, kind, rule, repo)] in the order /permissions shows and `remove` numbers them."""
    d = load()
    out = []
    for kind in ("deny", "allow"):
        for e in d[kind]:
            out.append((len(out) + 1, kind, e["rule"], e["repo"]))
    return out


def remove(n):
    r = [x for x in rows() if str(x[0]) == str(n).strip()]
    if not r:
        return False, f"no rule #{n} (/permissions lists them)"
    _, kind, rule, repo = r[0]
    data = {k: list(v) for k, v in load().items()}
    data[kind] = [e for e in data[kind] if not (e["rule"] == rule and e["repo"] == repo)]
    _save(data)
    return True, f"removed: {kind} {rule}" + (f" ({repo})" if repo else "")


# ------------------------------------------------------------------ matching
def _norm(cmd):
    return " ".join(str(cmd or "").split())


def _cmd_matches(cmd, pat):
    c, p = _norm(cmd), _norm(pat)
    if not c:
        return False
    return fnmatch.fnmatchcase(c, p) or (p.endswith(" *") and c == p[:-2])


def _in_scope(repo_rule, root):
    if not repo_rule:
        return True
    r = os.path.realpath(root or os.getcwd())
    return r == repo_rule or r.startswith(repo_rule.rstrip(os.sep) + os.sep)


_LEADING_CD = re.compile(r"^\s*cd\s+(?:'([^']+)'|\"([^\"]+)\"|([^\s;&|`$<>()]+))\s*&&\s*")


def _strip_cd_into(cmd, root):
    """`cd <the repo or a folder in it> && pytest -q` -> `pytest -q`. Models prefix nearly every command with a cd
    into the folder they are already in; that chain made "allow bash(pytest *)" ask anyway, eleven times in one
    SWE drive batch (2026-11-20). Only a cd that stays INSIDE the rule's repo is dropped; anything else stays a
    chain, and a chain never matches an allow rule."""
    m = _LEADING_CD.match(cmd or "")
    if not m:
        return cmd
    target = os.path.expanduser(next(g for g in m.groups() if g is not None))
    base = os.path.realpath(root or os.getcwd())
    real = os.path.realpath(target if os.path.isabs(target) else os.path.join(base, target))
    if real == base or real.startswith(base.rstrip(os.sep) + os.sep):
        return cmd[m.end():]
    return cmd


def _command_of(name, args):
    if name == "bash":
        return str(args.get("command") or "")
    if name == "bg" and str(args.get("action") or "start").lower() in ("start", "run"):
        return str(args.get("command") or "")
    return None


def _files(name, args, root):
    """(repo-relative paths, all inside root) for an edit call."""
    try:
        import gnoc_hooks
        names = gnoc_hooks.touched_files(name, args)
    except Exception:  # noqa: BLE001
        names = [args.get("path")] if isinstance(args.get("path"), str) else []
    base = os.path.realpath(root or os.getcwd())
    rel, inside = [], bool(names)
    for f in names:
        f = os.path.expanduser(str(f))
        p = os.path.realpath(f if os.path.isabs(f) else os.path.join(base, f))
        if p == base or not p.startswith(base.rstrip(os.sep) + os.sep):
            inside = False
            rel.append(p)
        else:
            rel.append(os.path.relpath(p, base))
    return rel, inside


def _tool_hits(rule_tool, name):
    return rule_tool == name or (rule_tool == "edit" and name in EDIT_TOOLS)


def allowed(name, args, root):
    """The allow rule that lets this call run without asking, or None."""
    args = args if isinstance(args, dict) else {}
    if name not in ALLOWABLE and not _plugin_tool(name):
        return None
    rules = [e for e in load()["allow"] if _in_scope(e["repo"], root)]
    if not rules:
        return None
    cmd = _command_of(name, args)
    if name in ("bash", "bg"):
        if cmd is None:   # a bg call that is not a start (input, stop ...): only a tool-wide bg rule covers it
            return next((e["rule"] for e in rules if parse_rule(e["rule"]) == ("bg", "*") and name == "bg"), None)
        cmd = _strip_cd_into(cmd, root)
        if _SHELL_OPS.search(cmd):
            # one plain command only: an allow rule never covers `x; y`, `x | sh` or `$(...)`. The one exception
            # is `a && b && c` where EVERY part is a plain command a rule allows by itself: that is the same
            # permission asked three times. `python3 todo.py add "x" && python3 todo.py list` was held under the
            # rule bash(python3 todo.py *) and the turn ended with nothing run (CLI drive 2026-11-21).
            if name != "bash":
                return None
            parts = _and_parts(cmd)
            if len(parts) < 2 or len(parts) > 6 or any(_SHELL_OPS.search(x) for x in parts):
                return None
            hit = None
            for part in parts:
                got = allowed(name, dict(args, command=part), root)
                if not got:
                    return None
                hit = hit or got
            return hit
    files, inside = _files(name, args, root) if name in EDIT_TOOLS else ([], False)
    for e in rules:
        tool, pat = parse_rule(e["rule"])
        if not _tool_hits(tool, name):
            continue
        if name in ("bash", "bg"):
            if pat.strip() not in ("*", "") and _cmd_matches(cmd, pat):
                return e["rule"]
        elif name in EDIT_TOOLS:
            if inside and all(fnmatch.fnmatchcase(f, pat) for f in files):
                return e["rule"]
        elif pat in ("*", ""):
            return e["rule"]
    return None


def _and_parts(cmd):
    """`a && b && c` split at each && that is outside quotes; [] when the quoting is unbalanced."""
    out, cur, q, i = [], [], None, 0
    while i < len(cmd):
        ch = cmd[i]
        if q:
            if ch == "\\" and q == '"' and i + 1 < len(cmd):
                cur.append(cmd[i:i + 2])
                i += 2
                continue
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif cmd.startswith("&&", i):
            out.append("".join(cur).strip())
            cur, i = [], i + 2
            continue
        cur.append(ch)
        i += 1
    if q:
        return []
    out.append("".join(cur).strip())
    return out if all(out) else []


def _pieces(cmd):
    out = []
    for part in [cmd] + _SPLIT.split(cmd):
        part = _norm(part)
        if part:
            out.append(part)
            stripped = _PREFIX.sub("", part)
            if stripped and stripped != part:
                out.append(stripped)
    return list(dict.fromkeys(out))


def _detail(args):
    for k in ("command", "args", "path", "url", "text", "brief"):
        if args.get(k):
            return str(args[k])
    return json.dumps(args, sort_keys=True, default=str)


def denied(name, args, root):
    """The deny rule that blocks this call, or None."""
    args = args if isinstance(args, dict) else {}
    rules = [e for e in load()["deny"] if _in_scope(e["repo"], root)]
    if not rules:
        return None
    for e in rules:
        tool, pat = parse_rule(e["rule"])
        if not _tool_hits(tool, name):
            continue
        if pat in ("*", ""):
            return e["rule"]
        if name in ("bash", "bg"):
            cmd = str(args.get("command") or args.get("text") or "")
            if cmd and any(fnmatch.fnmatchcase(p, _norm(pat)) or _cmd_matches(p, pat) for p in _pieces(cmd)):
                return e["rule"]
        elif name in EDIT_TOOLS:
            files, _ = _files(name, args, root)
            if any(fnmatch.fnmatchcase(f, pat) or fnmatch.fnmatchcase(os.path.basename(f), pat) for f in files):
                return e["rule"]
        elif fnmatch.fnmatchcase(_detail(args), pat):
            return e["rule"]
    return None


# ------------------------------------------------------------------ the prompt's offer
def suggest(name, args, root):
    """The rule an approval prompt offers as "always allow here", or None when no narrow rule fits this call."""
    args = args if isinstance(args, dict) else {}
    if name in EDIT_TOOLS:
        files, inside = _files(name, args, root)
        return "edit" if inside else None
    if name in ("run_tests", "lint", "typecheck"):
        return name
    cmd = _command_of(name, args) if name in ("bash", "bg") else None
    if not cmd or _SHELL_OPS.search(cmd):
        return None
    t = _norm(cmd).split(" ")
    first = os.path.basename(t[0]) if not t[0].startswith("./") else t[0]
    if first in _NO_WILDCARD or "*" in cmd or "?" in cmd or "[" in cmd:
        return f"{name}({_norm(cmd)})"   # this exact command, nothing wider
    if first in ("python", "python3") and len(t) >= 3 and t[1] == "-m":
        prefix = t[:3]
    elif first in _RUNNERS and len(t) >= 3 and t[1] in ("run", "exec", "test", "x") and not t[2].startswith("-"):
        prefix = t[:3]
    elif first in _RUNNERS and len(t) >= 2 and re.fullmatch(r"[A-Za-z0-9_.:-]+", t[1]) and not t[1].startswith("-"):
        prefix = t[:2]
    elif first in _INTERPRETERS or first in _RUNNERS:
        return f"{name}({_norm(cmd)})"   # `python x.py` / bare `npm`: a wildcard would allow any script
    else:
        prefix = t[:1]
    return f"{name}({' '.join(prefix)} *)"
