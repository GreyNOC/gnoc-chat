"""gnoc_plugins.py - your own Python plugins, run inside gnoc around its actions and its model calls.

Shell hooks (gnoc_hooks.py, ~/.gnoc/hooks.json) stay exactly as they were. A plugin is the in-process version for
the rules a shell command cannot express: look at the model's messages before they leave, keep a tool result
out of the conversation, add a tool or a slash command of your own.

WHERE THEY LIVE. Only in your home: ~/.gnoc/plugins/<name>.py, or ~/.gnoc/plugins/<name>/plugin.py for a plugin
with more files (GNOC_HOME moves ~/.gnoc). Never from a repo, never from the current folder, and never through
sys.path: the code is compiled from the bytes that were hashed and runs as the module gnoc_plugin_<name>, so a
plugin cannot shadow a standard or gnoc module. A plugin is refused when any of its files or folders is
group- or world-writable, owned by another user, or a symlink that leads out of ~/.gnoc/plugins (the ssh rule:
a file someone else can change is not yours).

ENABLING. Nothing runs until you type /plugins enable <name> at the prompt (the same typed-only check as /file:
a model reply or a tool result cannot do it). Enabling records the sha256 of every file of the plugin in
~/.gnoc/plugins/enabled.json; if any file changes later the plugin stops loading until you enable it again
(the repo-hook trust model). The agent's file and shell tools refuse to write into ~/.gnoc/plugins/.

THE API. plugin.py defines register(api):

    def register(api):
        api.on("pre_tool", guard)                 # one handler per call; several per event are fine
        api.tool("word_count", count, "Count the words in a text",
                 {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]})
        api.command("hello", lambda rest: f"hello {rest}", "say hello")

    def guard(ev):                                # ev = {"event": "pre_tool", "tool": ..., "args": {...}}
        if ev["tool"] == "bash" and "terraform apply" in ev["args"].get("command", ""):
            return {"block": "terraform apply is typed by hand"}
        return None                               # None = pass

A handler gets a COPY of the event and returns None (pass), {"block": "reason"} or {"rewrite": {...}}:

    pre_tool           {tool, args}            rewrite tool and/or args, or block the call
    post_tool          {tool, args, result}    rewrite result (text), or block = the result is withheld
    pre_llm            {model, host, messages} rewrite messages, or block = the model call is not sent
    post_llm           {model, host, content}  rewrite content, or block = the answer is withheld (and its tool
                                               calls dropped)
    approval_request   {tool, args, required}  {"require": true} adds an approval; {"block": ...} refuses
    approval_response  {tool, args, answer}    observe only
    session_start / session_end {sid}          observe only

WHAT A PLUGIN CANNOT DO (the core enforces it, whatever the handler returns):
  - loosen approval. A rewritten call is planned again from scratch (every refusal, the user's deny rules, the
    tool's own gates such as the shell deny list and the scope gate), and it asks for approval if the ORIGINAL
    call or the REWRITTEN call needs it: rewriting `rm -rf build` into `ls` still asks.
  - approve. approval_request can only add a requirement; "approve", "skip" or {"require": false} is ignored
    and logged. approval_response cannot turn a no into a yes: only the human answers.
  - send a secret to a cloud model. pre_llm runs BEFORE secret redaction and before the privacy switch, so a
    rewritten message is scrubbed and refused exactly like an original one.
  - shadow a built-in. A plugin tool or command named like an existing one is not registered (/plugins says so).
  - run a tool unasked. A plugin tool asks every time, /auto and skip-perms included, unless you saved a rule
    for it: /permissions allow <tool>.

FAILURES. Each handler has a time budget (GNOC_PLUGIN_TIMEOUT seconds, default 5). A handler that raises, times
out or returns something malformed fails CLOSED for pre_tool, pre_llm and approval_request (the call is
blocked, with a message saying why) and OPEN for post_tool, post_llm, approval_response and session_* (the
event goes on unchanged). Every failure and every ignored loosening is written to ~/.gnoc/plugins.log. A
handler that times out keeps running in its own thread (Python cannot stop it) but its answer is dropped.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import sys
import threading
import time

EVENTS = ("pre_tool", "post_tool", "pre_llm", "post_llm", "approval_request", "approval_response",
          "session_start", "session_end")
# events whose handler acts as a GUARD: a guard that could not decide does not wave the action through
FAIL_CLOSED = frozenset({"pre_tool", "pre_llm", "approval_request"})
HANDLER_TIMEOUT = float(os.environ.get("GNOC_PLUGIN_TIMEOUT") or 5)
LOAD_TIMEOUT = 10.0
NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
# letters and _ only: a /permissions rule names a tool with [a-z_]+ (gnoc_perms._RULE)
TOOL_NAME = re.compile(r"^[a-z][a-z_]{1,47}$")
CMD_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
TREE_MAX_FILES = 200
TREE_MAX_BYTES = 5_000_000
LOG_MAX = 200_000
ROLES = ("system", "user", "assistant", "tool")


class PluginBlocked(Exception):
    """A pre_llm handler blocked (or could not judge) a model call. Deliberately NOT a RuntimeError/OSError: the
    chat loop treats those as a dead model server and fails over to another model, which would only send the same
    blocked messages somewhere else."""


def _home():
    return os.environ.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def plugins_dir():
    return os.path.join(_home(), "plugins")


def enabled_path():
    return os.path.join(plugins_dir(), "enabled.json")


def log_path():
    return os.path.join(_home(), "plugins.log")


def block(reason):
    """What a handler returns to block: {"block": reason}."""
    return {"block": str(reason)}


def rewrite(**fields):
    """What a handler returns to rewrite: {"rewrite": {...}}."""
    return {"rewrite": fields}


# ------------------------------------------------------------------ log
_LOG_LOCK = threading.Lock()


def _log(plugin, msg):
    """One line in ~/.gnoc/plugins.log, secrets scrubbed. Never raises: a log that fails is not a failed call."""
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} [{plugin}] {msg}"
    try:
        import gnoc_secrets
        line = gnoc_secrets.redact(line)
    except Exception:  # noqa: BLE001 - the redactor itself missing: keep the line short instead
        line = line[:300]
    try:
        with _LOG_LOCK:
            os.makedirs(_home(), exist_ok=True)
            p = log_path()
            if os.path.exists(p) and os.path.getsize(p) > LOG_MAX:
                with open(p, "rb") as fh:
                    fh.seek(-LOG_MAX // 2, os.SEEK_END)
                    tail = fh.read()
                with open(p, "wb") as fh:
                    fh.write(tail[tail.find(b"\n") + 1:])
            with open(p, "a", encoding="utf-8") as fh:
                fh.write(line[:2000] + "\n")
    except OSError:
        pass
    with _LOG_LOCK:   # not _STATE_LOCK: a plugin logging while it LOADS runs in another thread under that lock
        _STATE["notes"].setdefault(plugin, []).append(msg[:300])
        del _STATE["notes"][plugin][:-20]


# ------------------------------------------------------------------ discovery and integrity
def _inside(path, root):
    rp, rr = os.path.realpath(path), os.path.realpath(root)
    return rp == rr or rp.startswith(rr + os.sep)


def _mode_problem(path):
    """Why this file or folder is not safe to load code from, or None. POSIX only: Windows ACLs are not modes."""
    if os.name == "nt":
        return None
    try:
        st = os.stat(path)
    except OSError as e:
        return f"cannot stat {path}: {e}"
    if st.st_mode & 0o022:
        return f"{path} is group- or world-writable (chmod go-w it)"
    if hasattr(os, "getuid") and st.st_uid not in (os.getuid(), 0):
        return f"{path} is owned by another user"
    return None


def _candidates():
    """{name: (path, entry)} for every plugin-shaped name in the folder, plus {name: problem} for clashes."""
    d = plugins_dir()
    out, bad = {}, {}
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out, bad
    for fn in names:
        p = os.path.join(d, fn)
        if fn.endswith(".py") and not os.path.isdir(p):
            name, entry = fn[:-3], p
        elif os.path.isdir(p):
            name, entry = fn, os.path.join(p, "plugin.py")
        else:
            continue
        if not NAME.match(name):
            continue
        if name in out:
            bad[name] = f"both {name}.py and {name}/ exist: remove one"
            continue
        out[name] = (p, entry)
    for name in bad:
        out.pop(name, None)
    return out, bad


def _tree(path, entry):
    """(sha256 of every file, the entry file's bytes) from ONE read of the entry, or raise ValueError with the
    reason it must not load. Hashing one read and running another let a file swapped in between run unverified
    code (the same QAQC r2 lesson as gnoc_hooks._read_once)."""
    root = plugins_dir()
    for p in (_home(), root):
        why = _mode_problem(p)
        if why:
            raise ValueError(why)
    if not _inside(path, root):
        raise ValueError(f"{path} leads outside {root} (a symlink out of the plugins folder is never loaded)")
    if not os.path.isfile(entry):
        raise ValueError(f"{entry} is missing")
    files = []
    if os.path.isdir(path):
        why = _mode_problem(path)
        if why:
            raise ValueError(why)
        for d, dirs, names in os.walk(path, followlinks=False):
            for x in list(dirs):
                full = os.path.join(d, x)
                if not _inside(full, root):
                    raise ValueError(f"{full} leads outside {root}")
                why = _mode_problem(full)
                if why:
                    raise ValueError(why)
            for x in names:
                files.append(os.path.join(d, x))
    else:
        files.append(path)
    if len(files) > TREE_MAX_FILES:
        raise ValueError(f"{path} has more than {TREE_MAX_FILES} files")
    h, total, entry_data = hashlib.sha256(), 0, None
    for f in sorted(files):
        if not _inside(f, root):
            raise ValueError(f"{f} leads outside {root}")
        why = _mode_problem(f)
        if why:
            raise ValueError(why)
        with open(f, "rb") as fh:
            data = fh.read(TREE_MAX_BYTES + 1)
        total += len(data)
        if total > TREE_MAX_BYTES:
            raise ValueError(f"{path} is larger than {TREE_MAX_BYTES} bytes")
        if os.path.realpath(f) == os.path.realpath(entry):
            entry_data = data
        rel = os.path.relpath(f, path) if os.path.isdir(path) else os.path.basename(f)
        h.update(rel.encode("utf-8", "surrogateescape") + b"\0" + hashlib.sha256(data).digest() + b"\0")
    if entry_data is None:
        raise ValueError(f"{entry} could not be read")
    return h.hexdigest(), entry_data


def _enabled():
    try:
        with open(enabled_path(), encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return {}
    d = d.get("plugins") if isinstance(d, dict) else None
    return {k: v for k, v in (d or {}).items() if isinstance(v, dict) and isinstance(v.get("sha256"), str)}


def _save_enabled(d):
    os.makedirs(plugins_dir(), exist_ok=True)
    tmp = enabled_path() + f".{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"plugins": d}, fh, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, enabled_path())


# ------------------------------------------------------------------ the API a plugin registers with
class PluginAPI:
    def __init__(self, name):
        self.name = name
        self.handlers = {e: [] for e in EVENTS}
        self.tools = {}
        self.commands = {}

    block = staticmethod(block)
    rewrite = staticmethod(rewrite)

    def on(self, event, fn):
        if event not in EVENTS:
            raise ValueError(f"unknown event {event!r}; events: {', '.join(EVENTS)}")
        if not callable(fn):
            raise TypeError("a handler must be callable")
        self.handlers[event].append(fn)

    def tool(self, name, fn, description="", parameters=None):
        if not isinstance(name, str) or not TOOL_NAME.match(name):
            raise ValueError(f"tool name {name!r} must be lower-case letters and _ (2-48 characters)")
        if not callable(fn):
            raise TypeError("a tool must be callable")
        if parameters is not None and not isinstance(parameters, dict):
            raise TypeError("parameters must be a JSON schema object")
        self.tools[name] = (fn, str(description or name)[:700], parameters or {"type": "object", "properties": {}})

    def command(self, name, fn, description=""):
        if not isinstance(name, str) or not CMD_NAME.match(name):
            raise ValueError(f"command name {name!r} must be lower-case letters, digits and - (up to 32)")
        if not callable(fn):
            raise TypeError("a command must be callable")
        self.commands[name] = (fn, str(description or "")[:200])

    def log(self, msg):
        _log(self.name, str(msg))


# ------------------------------------------------------------------ running plugin code with a budget
_TL = threading.local()


def _budget(fn, args, seconds, tag):
    """("ok", value) | ("error", text) | ("timeout", None). The call runs in its own daemon thread, marked as
    plugin code, so an event fired from inside a handler does not run the handlers again (no recursion)."""
    box = {}

    def go():
        _TL.in_plugin = True
        try:
            box["v"] = fn(*args)
        except BaseException as e:  # noqa: BLE001 - a plugin's SystemExit must not end the chat either
            box["e"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=go, daemon=True, name=f"gnoc-plugin-{tag}")
    t.start()
    t.join(seconds)
    if t.is_alive():
        return "timeout", None
    if "e" in box:
        return "error", box["e"]
    return "ok", box.get("v")


def _exec_module(name, entry, data):
    modname = "gnoc_plugin_" + name.replace("-", "_")
    # spec_from_loader with no loader, not spec_from_file_location: a file loader would READ THE FILE AGAIN, and
    # what it read need not be the bytes that matched the enabled sha256
    spec = importlib.util.spec_from_loader(modname, loader=None, origin=entry)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = entry
    sys.modules[modname] = mod   # the namespaced name only: gnoc_plugin_<x> cannot shadow a stdlib/gnoc module
    exec(compile(data, entry, "exec"), mod.__dict__)  # noqa: S102 - the operator's own enabled plugin
    reg = getattr(mod, "register", None)
    if not callable(reg):
        raise ValueError("plugin.py defines no register(api) function")
    api = PluginAPI(name)
    reg(api)
    return api


# ------------------------------------------------------------------ the registry
_STATE_LOCK = threading.RLock()
_STATE: dict = {"key": None, "apis": {}, "states": {}, "notes": {}, "registered": set()}


def _key():
    try:
        st = os.stat(enabled_path())
        return (plugins_dir(), st.st_mtime_ns, st.st_size)
    except OSError:
        return (plugins_dir(), None, None)


def _ensure():
    """Load the enabled, unchanged plugins once; again whenever enabled.json changes (another chat enabled one)."""
    k = _key()
    with _STATE_LOCK:
        if _STATE["key"] == k:
            return _STATE["apis"]
        _STATE["key"] = k
        for n in list(_STATE["apis"]):
            sys.modules.pop("gnoc_plugin_" + n.replace("-", "_"), None)
        _STATE["apis"], _STATE["states"] = {}, {}
        if k[1] is None:
            return _STATE["apis"]   # nothing was ever enabled: not even the folder is read
        want = _enabled()
        cands, bad = _candidates()
        for name in sorted(want):
            if name in bad:
                _STATE["states"][name] = "refused: " + bad[name]
                continue
            if name not in cands:
                _STATE["states"][name] = "missing (enabled, but its file is gone)"
                continue
            path, entry = cands[name]
            try:
                sha, data = _tree(path, entry)
            except (OSError, ValueError) as e:
                _STATE["states"][name] = f"refused: {e}"
                _log(name, f"not loaded: {e}")
                continue
            if sha != want[name]["sha256"]:
                _STATE["states"][name] = f"changed since you enabled it (/plugins enable {name} to run it again)"
                _log(name, "not loaded: a file changed since it was enabled")
                continue
            st, v = _budget(_exec_module, (name, entry, data), LOAD_TIMEOUT, name)
            if st != "ok":
                why = "loading timed out" if st == "timeout" else f"loading failed: {v}"
                _STATE["states"][name] = "error: " + why
                _log(name, why)
                continue
            _STATE["apis"][name] = v
            _STATE["states"][name] = "enabled"
        return _STATE["apis"]


def reload():
    with _STATE_LOCK:
        _STATE["key"] = ("reload",)
    return _ensure()


def _handlers(event):
    if getattr(_TL, "in_plugin", False):
        return []   # an event raised by plugin code itself (a handler calling into gnoc): no re-entry
    try:
        apis = _ensure()
    except Exception as e:  # noqa: BLE001 - the loader itself broke: say so; guards then fail closed
        return [("(loader)", _raiser(e))]
    return [(n, fn) for n in sorted(apis) for fn in apis[n].handlers.get(event, [])]


def _raiser(e):
    def fn(_ev):
        raise RuntimeError(f"the plugin loader failed: {type(e).__name__}: {e}")
    return fn


def _copy(x):
    try:
        return copy.deepcopy(x)
    except Exception:  # noqa: BLE001 - something deepcopy cannot copy: hand over its JSON shape instead
        return json.loads(json.dumps(x, default=str))


def _call(plugin, event, fn, payload):
    """(status, value). status: ok | error | timeout | malformed."""
    st, v = _budget(fn, (payload,), HANDLER_TIMEOUT, plugin)
    if st == "timeout":
        _log(plugin, f"{event} handler timed out after {HANDLER_TIMEOUT:g}s")
        return st, f"timed out after {HANDLER_TIMEOUT:g}s"
    if st == "error":
        _log(plugin, f"{event} handler raised {v}")
        return st, f"raised {v}"
    if v is not None and not isinstance(v, dict):
        _log(plugin, f"{event} handler returned {type(v).__name__}, not None or a dict")
        return "malformed", f"returned {type(v).__name__} (expected None, {{'block': ...}} or {{'rewrite': ...}})"
    return "ok", v


def _closed(plugin, event, why):
    return (f"BLOCKED: plugin {plugin}'s {event} handler {why}, so the action did not run (a guard that cannot "
            f"decide does not wave anything through; /plugins disable {plugin} turns it off)")


# ------------------------------------------------------------------ events
def pre_tool(tool, args):
    """(tool, args, block_reason_or_None, [plugins that rewrote]). The caller plans the returned call again from
    scratch and asks for approval if the original OR the returned call needs it (see dispatch.run_tools)."""
    hs = _handlers("pre_tool")
    if not hs:
        return tool, args, None, []
    cur_t, cur_a, by = tool, args, []
    for plugin, fn in hs:
        st, v = _call(plugin, "pre_tool", fn, {"event": "pre_tool", "tool": cur_t, "args": _copy(cur_a)})
        if st != "ok":
            return cur_t, cur_a, _closed(plugin, "pre_tool", v), by
        if v is None:
            continue
        if "block" in v:
            return cur_t, cur_a, f"BLOCKED by plugin {plugin}: {str(v['block'])[:1500] or 'no reason given'}", by
        rw = v.get("rewrite")
        if not isinstance(rw, dict) or set(rw) - {"tool", "args"}:
            _log(plugin, f"pre_tool returned a malformed answer: {str(v)[:200]}")
            return cur_t, cur_a, _closed(plugin, "pre_tool", "returned a malformed rewrite"), by
        nt, na = rw.get("tool", cur_t), rw.get("args", cur_a)
        if not isinstance(nt, str) or not nt.strip() or not isinstance(na, dict):
            return cur_t, cur_a, _closed(plugin, "pre_tool", "rewrote the call into something that is not a "
                                                             "tool name and an argument object"), by
        try:
            json.dumps(na)
        except (TypeError, ValueError):
            return cur_t, cur_a, _closed(plugin, "pre_tool", "rewrote the arguments into non-JSON values"), by
        if (nt, na) != (cur_t, cur_a):
            _log(plugin, f"pre_tool rewrote {cur_t} -> {nt}")
            cur_t, cur_a = nt, _copy(na)
            if plugin not in by:
                by.append(plugin)
    return cur_t, cur_a, None, by


def note_loosening(by, tool, new_tool):
    """The core rejected a rewrite that would have turned an approval-needed call into one that runs unasked."""
    for p in by:
        _log(p, f"rejected: the rewrite of {tool} into {new_tool} would have skipped approval; approval is still asked")


def post_tool(tool, args, result):
    """The result the model sees. Fails open: a broken handler leaves the result as it was."""
    hs = _handlers("post_tool")
    out = result
    for plugin, fn in hs:
        st, v = _call(plugin, "post_tool", fn, {"event": "post_tool", "tool": tool, "args": _copy(args),
                                                 "result": str(out)})
        if st != "ok" or v is None:
            continue
        if "block" in v:
            out = f"[this {tool} result was withheld by plugin {plugin}: {str(v['block'])[:300]}]"
            continue
        rw = v.get("rewrite")
        if isinstance(rw, dict) and isinstance(rw.get("result"), str) and set(rw) == {"result"}:
            out = rw["result"]
        else:
            _log(plugin, "post_tool returned a malformed rewrite; the result is unchanged")
    return out


def _valid_messages(m):
    return isinstance(m, list) and all(
        isinstance(x, dict) and x.get("role") in ROLES and isinstance(x.get("content", ""), (str, type(None), list))
        for x in m)


def pre_llm(model, host, messages):
    """The messages to send. Raises PluginBlocked on a block or a failure (closed). The caller (llm.llm_chat)
    hands the result to _llm_chat_once, which applies the privacy switch and secret redaction AFTER this."""
    hs = _handlers("pre_llm")
    if not hs:
        return messages
    cur = messages
    for plugin, fn in hs:
        st, v = _call(plugin, "pre_llm", fn, {"event": "pre_llm", "model": model, "host": host,
                                               "messages": _copy(cur)})
        if st != "ok":
            raise PluginBlocked(f"not sent: plugin {plugin}'s pre_llm handler {v} (it fails closed; "
                                f"/plugins disable {plugin} turns it off)")
        if v is None:
            continue
        if "block" in v:
            raise PluginBlocked(f"not sent: plugin {plugin} blocked this model call: {str(v['block'])[:500]}")
        rw = v.get("rewrite")
        if not isinstance(rw, dict) or set(rw) != {"messages"} or not _valid_messages(rw["messages"]):
            _log(plugin, "pre_llm returned a malformed rewrite")
            raise PluginBlocked(f"not sent: plugin {plugin}'s pre_llm handler returned a malformed rewrite")
        cur = _copy(rw["messages"])
    return cur


def post_llm(model, host, msg):
    """The model's answer, possibly rewritten. Fails open. Only the text is rewritable: tool calls the model made
    stay as they were and go through every dispatch gate; a block drops them (that can only take power away)."""
    hs = _handlers("post_llm")
    if not hs or not isinstance(msg, dict):
        return msg
    out = msg
    for plugin, fn in hs:
        st, v = _call(plugin, "post_llm", fn, {"event": "post_llm", "model": model, "host": host,
                                                "content": str(out.get("content") or ""),
                                                "tool_calls": _copy(out.get("tool_calls") or [])})
        if st != "ok" or v is None:
            continue
        if "block" in v:
            out = dict(out, content=f"[the model's answer was withheld by plugin {plugin}: {str(v['block'])[:300]}]")
            out.pop("tool_calls", None)
            continue
        rw = v.get("rewrite")
        if isinstance(rw, dict) and set(rw) == {"content"} and isinstance(rw["content"], str):
            out = dict(out, content=rw["content"])
        else:
            _log(plugin, "post_llm returned a malformed rewrite; the answer is unchanged")
    return out


def approval_request(tool, args, required):
    """(required, block_reason_or_None). A plugin can only ADD a requirement or refuse; it can never approve."""
    hs = _handlers("approval_request")
    req = bool(required)
    for plugin, fn in hs:
        st, v = _call(plugin, "approval_request", fn, {"event": "approval_request", "tool": tool,
                                                        "args": _copy(args), "required": req})
        if st != "ok":
            return req, "not run: " + _closed(plugin, "approval_request", v)
        if v is None:
            continue
        if "block" in v:
            return req, f"not run: plugin {plugin} refused this call: {str(v['block'])[:500]}"
        if v.get("require") is True:
            if not req:
                _log(plugin, f"approval_request added an approval to {tool}")
            req = True
            continue
        # {"require": false}, {"approve": true}, {"skip": true}, a rewrite...: none of them is a plugin's to give
        _log(plugin, f"ignored: approval_request answered {str(v)[:120]}; only the user approves")
    return req, None


def approval_response(tool, args, answer):
    """Observe the user's answer. Whatever a handler returns is ignored (and logged when it tried to change it)."""
    for plugin, fn in _handlers("approval_response"):
        st, v = _call(plugin, "approval_response", fn, {"event": "approval_response", "tool": tool,
                                                         "args": _copy(args), "answer": answer})
        if st == "ok" and v is not None:
            _log(plugin, f"ignored: approval_response returned {str(v)[:120]}; the user's answer stands")
    return answer


def session_start(sid):
    for plugin, fn in _handlers("session_start"):
        _call(plugin, "session_start", fn, {"event": "session_start", "sid": sid})


def session_end(sid):
    for plugin, fn in _handlers("session_end"):
        _call(plugin, "session_end", fn, {"event": "session_end", "sid": sid})


# ------------------------------------------------------------------ plugin tools and commands
class _AlwaysAsk:
    """A plugin tool's approval rule. gnoc_core.approval reads the plugin_tool marker: such a tool asks every time,
    /auto and skip-perms included, unless the user saved a /permissions rule. Called like any rule, it says ask."""
    plugin_tool = True

    def __call__(self, _args):
        return True


RULE = _AlwaysAsk()


def tool_names():
    """Names the enabled plugins declare as tools (registered or not)."""
    try:
        apis = _ensure()
    except Exception:  # noqa: BLE001
        return set()
    return {t for a in apis.values() for t in a.tools}


def is_plugin_tool(name):
    with _STATE_LOCK:
        return name in _STATE["registered"]


def _impl(plugin, tool, fn):
    def call(ctx, **arguments):
        try:
            got = fn(dict(arguments))
        except Exception as e:  # noqa: BLE001 - a broken plugin tool is a result, never a crash of the turn
            _log(plugin, f"tool {tool} raised {type(e).__name__}: {e}")
            return f"plugin tool {tool} failed: {type(e).__name__}: {str(e)[:300]}"
        return "" if got is None else str(got)
    call.__name__ = f"plugin_{tool}"
    return call


def sync_tools(tools, *sets):
    """Register the enabled plugins' tools into the tool table (and into each of `sets`, e.g. CODE_TOOLS and
    ACTING_TOOLS), after removing the ones this function registered before. A name already in the table is a
    built-in (or another plugin's): it is NOT registered, and /plugins shows why. Returns how many."""
    with _STATE_LOCK:
        for n in _STATE["registered"]:
            if n in tools and getattr(tools[n][2], "plugin_tool", False):
                tools.pop(n, None)
            for s in sets:
                s.discard(n)
        _STATE["registered"] = set()
        try:
            apis = _ensure()
        except Exception:  # noqa: BLE001
            return 0
        for plugin in sorted(apis):
            for t, (fn, desc, params) in sorted(apis[plugin].tools.items()):
                if t in tools:
                    _log(plugin, f"tool {t} is not registered: that name is already a tool")
                    continue
                schema = {"type": "function", "function": {
                    "name": t, "description": f"[plugin {plugin}] {desc}", "parameters": params}}
                tools[t] = (_impl(plugin, t, fn), schema, RULE)
                for s in sets:
                    s.add(t)
                _STATE["registered"].add(t)
        return len(_STATE["registered"])


def run_command(name, rest, builtin=()):
    """The text a plugin command printed, or None when no enabled plugin has a command of that name. A name that
    is a built-in is never run here (the built-in already ran, and /plugins says the plugin's is shadowed)."""
    if name in builtin:
        return None
    try:
        apis = _ensure()
    except Exception:  # noqa: BLE001
        return None
    for plugin in sorted(apis):
        got = apis[plugin].commands.get(name)
        if not got:
            continue
        st, v = _budget(got[0], (str(rest or ""),), max(HANDLER_TIMEOUT, 30.0), plugin)
        if st == "timeout":
            _log(plugin, f"/{name} timed out")
            return f"plugin {plugin}: /{name} timed out"
        if st == "error":
            _log(plugin, f"/{name} raised {v}")
            return f"plugin {plugin}: /{name} failed: {v}"
        return "" if v is None else str(v)
    return None


def commands(builtin=()):
    """{name: (plugin, description, shadowed)} for every enabled plugin's command."""
    out = {}
    try:
        apis = _ensure()
    except Exception:  # noqa: BLE001
        return out
    for plugin in sorted(apis):
        for n, (_fn, desc) in sorted(apis[plugin].commands.items()):
            out.setdefault(n, (plugin, desc, n in builtin))
    return out


# ------------------------------------------------------------------ enable / disable / list
def enable(name):
    """Pin the plugin's files as they are now and load it. Returns (ok, message). Called only from the typed
    /plugins enable command."""
    name = str(name or "").strip()
    if not NAME.match(name):
        return False, f"{name!r} is not a plugin name (lower-case letters, digits, - and _)"
    cands, bad = _candidates()
    if name in bad:
        return False, bad[name]
    if name not in cands:
        return False, f"no plugin {name} in {plugins_dir()} (put {name}.py or {name}/plugin.py there)"
    path, entry = cands[name]
    try:
        sha, data = _tree(path, entry)
    except (OSError, ValueError) as e:
        return False, f"refused: {e}"
    try:
        compile(data, entry, "exec")
    except SyntaxError as e:
        return False, f"{entry} does not compile: {e}"
    d = _enabled()
    d[name] = {"sha256": sha, "enabled": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    _save_enabled(d)
    reload()
    state = _STATE["states"].get(name, "")
    if state != "enabled":
        return False, f"enabled {name}, but it does not run: {state}"
    return True, f"enabled {name} (sha256 {sha[:12]}); it stops running if any of its files changes"


def disable(name):
    d = _enabled()
    if d.pop(str(name or "").strip(), None) is None:
        return False, f"{name} is not enabled"
    _save_enabled(d)
    reload()
    return True, f"disabled {name}"


def rows():
    """[(name, state, detail)] for /plugins: every plugin in the folder, and every enabled one that is gone."""
    apis = _ensure()
    want = _enabled()
    cands, bad = _candidates()
    out = []
    for name in sorted(set(cands) | set(bad) | set(want)):
        if name in apis:
            a = apis[name]
            n_h = sum(len(v) for v in a.handlers.values())
            detail = f"{n_h} handler(s), {len(a.tools)} tool(s), {len(a.commands)} command(s)"
            notes = _STATE["notes"].get(name) or []
            if notes:
                detail += f"; last note: {notes[-1]}"
            out.append((name, "enabled", detail))
        elif name in bad:
            out.append((name, "refused", bad[name]))
        elif name in want:
            st = _STATE["states"].get(name) or "not loaded"
            out.append((name, st.split(":", 1)[0].split(" ", 1)[0], st))
        else:
            try:
                _tree(*cands[name])
                out.append((name, "disabled", f"/plugins enable {name} to run it"))
            except (OSError, ValueError) as e:
                out.append((name, "refused", str(e)))
    return out


def describe(builtin=()):
    lines = [f"plugins folder: {plugins_dir()}"]
    got = rows()
    if not got:
        lines.append(f"  no plugins. Put <name>.py (or <name>/plugin.py) with a register(api) function in "
                     f"{plugins_dir()}, then /plugins enable <name>.")
    for name, state, detail in got:
        lines.append(f"  {name:<20} {state:<9} {detail}")
    with _STATE_LOCK:
        reg = set(_STATE["registered"])
    for name, state, _d in got:
        if state != "enabled":
            continue
        a = _STATE["apis"].get(name)
        for t in sorted(a.tools if a else ()):
            lines.append(f"    tool {t}" + ("" if t in reg else "  (NOT registered: the name is already a tool)"))
    for n, (plugin, _desc, shadowed) in sorted(commands(builtin).items()):
        lines.append(f"    /{n} ({plugin})" + ("  (NOT available: a built-in command has that name)" if shadowed else ""))
    lines.append("  /plugins enable <name> · /plugins disable <name>   (the log: " + log_path() + ")")
    return "\n".join(lines)


# ------------------------------------------------------------------ the model cannot install or enable a plugin
_SHELL_MENTION = re.compile(r"\.gnoc/+plugins\b")   # a bare enabled.json is any project's file name
_SHELL_HOME = re.compile(r"\.gnoc\b")
_SHELL_PLUG = re.compile(r"\bplugins\b")


def protected(path):
    """True when writing `path` would install, change or enable a plugin."""
    if not path:
        return False
    p = os.path.realpath(os.path.expanduser(str(path)))
    return _inside(p, plugins_dir()) or p == os.path.realpath(enabled_path())


def model_write_refusal(tool, args, root=None):
    """The refusal for a model tool call that would write into ~/.gnoc/plugins (or None). The shell check is a
    seat belt: the real guarantee is that a plugin runs only after a TYPED /plugins enable pinned its sha256,
    so a file the model managed to drop there anyway never runs, and an enabled plugin it changed stops."""
    args = args if isinstance(args, dict) else {}
    why = ("refused: ~/.gnoc/plugins is yours: a plugin runs inside gnoc with your rights, so the agent never "
           "writes, changes or enables one. Show the user the code and let them save it and type /plugins enable.")
    if tool in ("write_file", "edit_file", "apply_patch", "notebook_edit"):
        try:
            import gnoc_hooks
            names = gnoc_hooks.touched_files(tool, args)
        except Exception:  # noqa: BLE001
            names = [args.get("path")] if isinstance(args.get("path"), str) else []
        for f in names:
            f = os.path.expanduser(str(f))
            if protected(f if os.path.isabs(f) or not root else os.path.join(root, f)):
                return why
        return None
    if tool in ("bash", "bg"):
        cmd = str(args.get("command") or args.get("cmd") or args.get("text") or "")
        home = os.path.realpath(_home())
        mentions = bool(_SHELL_MENTION.search(cmd)) or plugins_dir() in cmd or os.path.realpath(plugins_dir()) in cmd \
            or ((bool(_SHELL_HOME.search(cmd)) or home in cmd) and bool(_SHELL_PLUG.search(cmd)))
        if not mentions:
            return None
        # a plain look is fine (ls, cat, sha256sum ...); anything that could write is refused
        if re.match(r"^\s*(?:ls|cat|head|tail|wc|stat|file|sha256sum|md5sum|less|grep|tree)\b", cmd) \
                and not re.search(r"[>;&|`]|\$\(|\b(?:tee|cp|mv|ln|rm|chmod|touch|install|sed|dd|python\w*|perl)\b", cmd):
            return None
        return why
    return None
