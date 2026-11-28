"""gnoc_typecheck.py - which type checker a repo uses, and how to run it on all of it or on some files.

lint catches style; it does not catch a wrong argument type, a missing attribute or a call to a function that
was renamed. Each language's own checker does, so this picks it from what the repo already has:

    TypeScript  tsconfig.json             npx --no-install tsc --noEmit -p <tsconfig>   (the repo's own tsc)
    Python      mypy / pyright config, or mypy | pyright on PATH      mypy <files or .> / pyright <files>
    Go          go.mod                    go vet ./...
    Rust        Cargo.toml                cargo check --message-format short
    a repo's own `typecheck` script in package.json, or a 'typecheck: `cmd`' line in GNOC.md / CLAUDE.md, wins.

plan(root, files) -> list of (label, argv) or an explanation string when nothing applies.
"""
from __future__ import annotations

import json
import os
import re
import shutil

PY_EXT = (".py", ".pyi")
TS_EXT = (".ts", ".tsx", ".mts", ".cts")


def _read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _own_command(root):
    pj = os.path.join(root, "package.json")
    if os.path.isfile(pj):
        try:
            scripts = (json.loads(_read(pj)).get("scripts") or {})
        except ValueError:
            scripts = {}
        for k in ("typecheck", "type-check", "check-types", "tsc"):
            if scripts.get(k):
                return f"npm run -s {k}"
    for name in ("GNOC.md", "CLAUDE.md", "AGENTS.md"):
        m = re.search(r"(?im)^\s*(?:-\s*)?type-?check:\s*`([^`]+)`", _read(os.path.join(root, name)))
        if m:
            return m.group(1)
    return None


def _has_py_config(root, tool):
    if tool == "mypy":
        return (os.path.isfile(os.path.join(root, "mypy.ini")) or "[tool.mypy" in _read(os.path.join(root, "pyproject.toml"))
                or "[mypy" in _read(os.path.join(root, "setup.cfg")))
    return (os.path.isfile(os.path.join(root, "pyrightconfig.json")) or "[tool.pyright" in _read(os.path.join(root, "pyproject.toml")))


def plan(root, files=None):
    files = [f for f in (files or []) if f]
    own = _own_command(root)
    if own and not files:
        return [(own, ["bash", "-lc", own])]
    runs = []
    want_py = [f for f in files if f.endswith(PY_EXT)]
    want_ts = [f for f in files if f.endswith(TS_EXT)]
    other = [f for f in files if not f.endswith(PY_EXT + TS_EXT)]
    whole = not files
    # TypeScript: tsc checks a project, not a file list (a file list ignores tsconfig's settings), so a
    # .ts file named means "check the project it belongs to".
    tsconfig = os.path.join(root, "tsconfig.json")
    if (whole or want_ts) and os.path.isfile(tsconfig):
        local = os.path.join(root, "node_modules", ".bin", "tsc")
        if os.path.isfile(local):
            runs.append(("tsc --noEmit", [local, "--noEmit", "-p", tsconfig, "--pretty", "false"]))
        elif shutil.which("tsc"):
            runs.append(("tsc --noEmit", ["tsc", "--noEmit", "-p", tsconfig, "--pretty", "false"]))
    py_files = want_py or (["."] if whole and _looks_python(root) else [])
    if py_files:
        tool = None
        for t in ("mypy", "pyright"):
            if _has_py_config(root, t) and shutil.which(t):
                tool = t
                break
        tool = tool or next((t for t in ("mypy", "pyright") if shutil.which(t)), None)
        if tool == "mypy":
            runs.append(("mypy", ["mypy", "--hide-error-context", "--no-error-summary", "--show-column-numbers",
                                  "--ignore-missing-imports"] + py_files))
        elif tool == "pyright":
            runs.append(("pyright", ["pyright"] + ([] if py_files == ["."] else py_files)))
    if whole or any(f.endswith(".go") for f in other):
        if os.path.isfile(os.path.join(root, "go.mod")) and shutil.which("go"):
            runs.append(("go vet", ["go", "vet", "./..."]))
    if whole or any(f.endswith(".rs") for f in other):
        if os.path.isfile(os.path.join(root, "Cargo.toml")) and shutil.which("cargo"):
            runs.append(("cargo check", ["cargo", "check", "--quiet", "--message-format", "short"]))
    if runs:
        return runs
    missing = []
    if (whole or want_py) and (want_py or _looks_python(root)):
        missing.append("Python: pip install mypy (or pyright)")
    if (whole or want_ts) and os.path.isfile(tsconfig):
        missing.append("TypeScript: npm install --save-dev typescript")
    if missing:
        return "no type checker installed for this repo; " + "; ".join(missing)
    return ("nothing to type-check: no tsconfig.json, Python files, go.mod or Cargo.toml here, and no "
            "'typecheck' script (add one to package.json or a 'typecheck: `cmd`' line to GNOC.md)")


def _looks_python(root):
    if any(os.path.isfile(os.path.join(root, n)) for n in ("pyproject.toml", "setup.py", "setup.cfg", "mypy.ini")):
        return True
    try:
        return any(n.endswith(".py") for n in os.listdir(root))
    except OSError:
        return False
