"""gnoc_lsp.py - precise code navigation: the definition of THIS name at THIS spot, and every real reference.

find_symbol's regex search answers "which lines mention a word": it cannot tell a method `save` on one class from
`save` on another, follows no import, and misses a definition its patterns do not know. When the model has a
location (a path, a line, the name on that line) this module answers from the language's own resolver:

    Python      jedi, when it is importable (pip install jedi); no server process needed
    any         a language server on PATH, spoken over stdio (LSP): pyright-langserver, pylsp,
                typescript-language-server, gopls, rust-analyzer, clangd, jdtls

navigate(root, path, line, name=None, column=None, action="definition"|"references") returns
(ok, text). ok=False means no precise backend could answer, and the text says why, so the caller can fall back
to the regex search and SAY that it did.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.parse

SERVERS = {   # extension -> candidate commands, first found wins
    ".py": (["pyright-langserver", "--stdio"], ["pylsp"], ["jedi-language-server"]),
    ".ts": (["typescript-language-server", "--stdio"],), ".tsx": (["typescript-language-server", "--stdio"],),
    ".js": (["typescript-language-server", "--stdio"],), ".jsx": (["typescript-language-server", "--stdio"],),
    ".mjs": (["typescript-language-server", "--stdio"],), ".cjs": (["typescript-language-server", "--stdio"],),
    ".go": (["gopls"],), ".rs": (["rust-analyzer"],),
    ".c": (["clangd"],), ".h": (["clangd"],), ".cpp": (["clangd"],), ".cc": (["clangd"],), ".hpp": (["clangd"],),
    ".java": (["jdtls"],),
}
LANG_ID = {".py": "python", ".ts": "typescript", ".tsx": "typescriptreact", ".js": "javascript",
           ".jsx": "javascriptreact", ".mjs": "javascript", ".cjs": "javascript", ".go": "go", ".rs": "rust",
           ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".java": "java"}
MAX_RESULTS = 60


def _uri(p):
    return "file://" + urllib.parse.quote(os.path.abspath(p))


def _path(uri):
    return urllib.parse.unquote(uri[7:]) if uri.startswith("file://") else uri


def _column(text_line, name, column):
    """0-based column of `name` on the line (the model knows names, not columns)."""
    if column is not None:
        try:
            return max(0, int(column) - 1)
        except (TypeError, ValueError):
            pass
    if name:
        import re
        short = str(name).split(".")[-1]
        # the name as a WHOLE identifier: find() put `load` inside `reload_all` and resolved the wrong symbol
        m = re.search(r"(?<![\w$])" + re.escape(short) + r"(?![\w$])", text_line)
        if m:
            return m.start()
    return len(text_line) - len(text_line.lstrip())


def _fmt(root, rows, label):
    seen, out = set(), []
    for p, ln in rows:
        key = (p, ln)
        if key in seen or not p:
            continue
        seen.add(key)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read().split("\n")[ln - 1].strip()
        except (OSError, IndexError):
            text = ""
        rel = os.path.relpath(p, root) if p.startswith(os.path.abspath(root) + os.sep) else p
        out.append(f"  {rel}:{ln}: {text[:200]}")
    if not out:
        return f"{label}: none found"
    more = f"\n  ... {len(out) - MAX_RESULTS} more" if len(out) > MAX_RESULTS else ""
    return f"{label} ({len(out)}):\n" + "\n".join(out[:MAX_RESULTS]) + more


# ------------------------------------------------------------------ jedi (Python, in-process)
def _jedi(root, path, line, col, action):
    try:
        import jedi
    except Exception:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            src = f.read()
        proj = jedi.Project(path=root)
        script = jedi.Script(code=src, path=path, project=proj)
        if action == "references":
            names = script.get_references(line, col, include_builtins=False)
        else:
            names = script.goto(line, col, follow_imports=True, follow_builtin_imports=False)
            if not names:
                names = script.infer(line, col)
        rows = [(str(n.module_path), n.line) for n in names if n.module_path and n.line]
        return "jedi", rows
    except Exception as e:  # noqa: BLE001 - a resolver crash falls back, it never breaks the tool
        return "jedi", f"jedi failed: {type(e).__name__}: {str(e)[:160]}"


# ------------------------------------------------------------------ a minimal LSP client over stdio
class LspClient:
    def __init__(self, argv, root, timeout=30.0):
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  cwd=root, start_new_session=True)
        self.timeout = timeout
        self.n = 0
        self.lock = threading.Lock()

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.p.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
        self.p.stdin.flush()

    def _read(self):
        headers = {}
        while True:
            ln = self.p.stdout.readline()
            if not ln:
                raise EOFError("language server closed its output")
            ln = ln.decode("ascii", "replace").strip()
            if not ln:
                break
            k, _, v = ln.partition(":")
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get("content-length", "0"))
        return json.loads(self.p.stdout.read(n).decode("utf-8", "replace")) if n else {}

    def request(self, method, params, timeout=None):
        self.n += 1
        rid = self.n
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        result, err = [None], [None]

        def wait():
            try:
                while True:
                    msg = self._read()
                    if msg.get("id") == rid and ("result" in msg or "error" in msg):
                        result[0], err[0] = msg.get("result"), msg.get("error")
                        return
                    if "id" in msg and "method" in msg:   # a server->client request: answer it empty
                        self._send({"jsonrpc": "2.0", "id": msg["id"], "result": None})
            except Exception as e:  # noqa: BLE001
                err[0] = {"message": f"{type(e).__name__}: {e}"}
        t = threading.Thread(target=wait, daemon=True)
        t.start()
        t.join(timeout or self.timeout)
        if t.is_alive():
            raise TimeoutError(f"{method} got no answer in {timeout or self.timeout:.0f}s")
        if err[0]:
            raise RuntimeError(str(err[0].get("message") if isinstance(err[0], dict) else err[0]))
        return result[0]

    def notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def close(self):
        try:
            self.request("shutdown", None, timeout=3)
            self.notify("exit", None)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.p.kill()
        except OSError:
            pass


def server_for(path):
    for argv in SERVERS.get(os.path.splitext(path)[1].lower(), ()):
        if shutil.which(argv[0]):
            return argv
    return None


def _lsp(root, path, line, col, action, argv=None):
    argv = argv or server_for(path)
    if not argv:
        return None
    c = LspClient(argv, root)
    try:
        c.request("initialize", {"processId": os.getpid(), "rootUri": _uri(root),
                                 "workspaceFolders": [{"uri": _uri(root), "name": os.path.basename(root)}],
                                 "capabilities": {"textDocument": {"definition": {}, "references": {}}}},
                  timeout=60)
        c.notify("initialized", {})
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        ext = os.path.splitext(path)[1].lower()
        c.notify("textDocument/didOpen", {"textDocument": {"uri": _uri(path), "languageId": LANG_ID.get(ext, "plaintext"),
                                                           "version": 1, "text": text}})
        pos = {"textDocument": {"uri": _uri(path)}, "position": {"line": line - 1, "character": col}}
        if action == "references":
            pos["context"] = {"includeDeclaration": True}
        method = "textDocument/references" if action == "references" else "textDocument/definition"
        res = None
        for attempt in range(3):   # a server still indexing answers [] at first
            res = c.request(method, pos)
            if res:
                break
            time.sleep(1.0 + attempt)
        locs = res if isinstance(res, list) else ([res] if isinstance(res, dict) else [])
        rows = []
        for loc in locs:
            uri = loc.get("uri") or loc.get("targetUri") or ""
            rng = loc.get("range") or loc.get("targetSelectionRange") or loc.get("targetRange") or {}
            rows.append((_path(uri), int((rng.get("start") or {}).get("line", 0)) + 1))
        return os.path.basename(argv[0]), rows
    except Exception as e:  # noqa: BLE001
        return os.path.basename(argv[0]), f"{argv[0]} failed: {type(e).__name__}: {str(e)[:160]}"
    finally:
        c.close()


def navigate(root, path, line, name=None, column=None, action="definition"):
    action = "references" if str(action or "").lower().startswith("ref") else "definition"
    try:
        line = int(line)
    except (TypeError, ValueError):
        return False, "line must be the 1-based line number where the name appears"
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().split("\n")
    except OSError as e:
        return False, f"cannot read {path}: {e}"
    if not 1 <= line <= len(lines):
        return False, f"line {line} is outside {os.path.basename(path)} ({len(lines)} lines)"
    if name and str(name).split(".")[-1] not in lines[line - 1]:
        return False, (f"{name} does not appear on line {line} of {os.path.relpath(path, root)}: "
                       f"{lines[line - 1].strip()[:160]!r}")
    col = _column(lines[line - 1], name, column)
    tried, why = [], []
    backends = []
    if path.endswith(".py"):
        backends.append(lambda: _jedi(root, path, line, col, action))
    backends.append(lambda: _lsp(root, path, line, col, action))
    for b in backends:
        got = b()
        if got is None:
            continue
        who, rows = got
        tried.append(who)
        if isinstance(rows, str):
            why.append(rows)
            continue
        label = ("REFERENCES" if action == "references" else "DEFINITION") + f" via {who}"
        return True, _fmt(root, rows, label)
    if not tried:
        ext = os.path.splitext(path)[1]
        cands = ", ".join(a[0] for a in SERVERS.get(ext.lower(), ())) or "none known"
        return False, (f"no precise resolver for {ext or 'this file'} here (" + ("pip install jedi, or " if ext == ".py" else "")
                       + f"install a language server: {cands})")
    return False, "; ".join(why)
