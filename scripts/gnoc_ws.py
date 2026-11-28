"""gnoc_ws.py - workspace setup for gnoc chat, as strong as Claude Code.

What Claude Code does on first entry - know the repo before touching it - gnoc chat gets here, automatically
when it can, and on one command when it cannot:

    first_open(path)        True when the repo has no instruction file yet (GNOC/CLAUDE/AGENTS.md) and no gchat.md
    sniff(path)             the stack, the entry points, the build/test/lint/run commands, the layout
    init_workspace(path)    writes GNOC.md (from the sniff, never overwrites one that exists) + a gchat.md session
    scaffold_project(...)   a NEW project from scratch: dir, git init, stack template, README, .gitignore, GNOC.md

Everything here is data: files are only created in the directory the user pointed at, never elsewhere, and an
existing instruction file is never overwritten.
"""
import json
import os
import re
import subprocess
import time

GCHAT = "gchat.md"
INSTRUCTION_FILES = ("GNOC.md", "CLAUDE.md", "AGENTS.md")
_MAX_LAYOUT_LINES = 14

# stack -> detectors in order: (name, file/glob evidence). The first detector that matches wins; the layout
# and commands are derived from the files found. Keep the evidence filesystem-only: no package installs.
STACKS = (
    ("node", ("package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "next.config.js", "vite.config.js")),
    ("python", ("pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "Pipfile", "uv.lock")),
    ("go", ("go.mod",)),
    ("rust", ("Cargo.toml",)),
    ("php", ("composer.json",)),
    ("ruby", ("Gemfile",)),
    ("java", ("pom.xml", "build.gradle", "settings.gradle")),
    ("dotnet", ("*.csproj", "*.sln")),
    ("web", ("*.html",)),
)

_GENERATED = ("node_modules", "dist", "build", "public", "static", "vendor", "__pycache__", ".venv", "venv",
              "target", ".git", "coverage", "site-packages", ".next")


def sniff(path):
    """What is this repo? -> {name, stack, purpose, run, build, test, lint, layout, files}. Pure reading."""
    path = os.path.realpath(path or ".")
    files = set(os.listdir(path)) if os.path.isdir(path) else set()
    harness = "scripts" in files and "gnoc" in files and os.path.isfile(os.path.join(path, "scripts", "gnoc_agent.py"))
    stack = "gnoc-harness" if harness else "unknown"
    if not harness:
        for name, marks in STACKS:
            if any(m in files or (m.startswith("*.") and any(f.endswith(m[1:]) for f in files)) for m in marks):
                stack = name
                break
    run = build = test = lint = ""
    if stack == "gnoc-harness":
        run, test, lint = "./scripts/gnoc chat", "python3 scripts/gnoc qaqc", "python3 -m pyflakes scripts"
    elif stack == "node":
        pkg = os.path.join(path, "package.json")
        scripts = {}
        if os.path.isfile(pkg):
            try:
                with open(pkg, encoding="utf-8") as fh:
                    scripts = json.load(fh).get("scripts") or {}
            except (OSError, ValueError):
                pass
        run = scripts.get("start") or scripts.get("dev") or ""
        build = scripts.get("build") or ""
        test = next((c for k, c in scripts.items() if "test" in k.lower()), "") or "npm test"
        lint = scripts.get("lint") or ""
    elif stack == "python":
        if os.path.isfile(os.path.join(path, "uv.lock")):
            run, test, lint = "uv run python -m <module>", "uv run pytest", "uv run ruff check ."
        elif os.path.isfile(os.path.join(path, "requirements.txt")):
            run, test, lint = "python -m <module>", "python -m pytest", "python -m ruff check ."
        else:
            test = "python -m pytest"
            lint = "python -m ruff check ."
    elif stack == "go":
        run, build, test, lint = "go run .", "go build ./...", "go test ./...", "go vet ./..."
    elif stack == "rust":
        run, build, test, lint = "cargo run", "cargo build", "cargo test", "cargo clippy"
    elif stack == "web":
        test = "(the page in the browser is the test: open it, check the console and both viewports)"
    name = os.path.basename(path.rstrip(os.sep)) or "project"
    purpose = ""
    for readme in ("README.md", "README.txt", "readme.md"):
        if os.path.isfile(os.path.join(path, readme)):
            try:
                with open(os.path.join(path, readme), encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith(("#", "=", "-", "!", "<", "[")):
                            purpose = line[:160]
                            break
            except OSError:
                pass
            break
    layout = []
    for entry in sorted(files):
        full = os.path.join(path, entry)
        if os.path.isdir(full) and not entry.startswith("."):
            try:
                inner = [x for x in sorted(os.listdir(full)) if not x.startswith(".")]
            except OSError:
                inner = []
            layout.append(f"{entry}/ ({', '.join(inner[:4])}{', …' if len(inner) > 4 else ''})"
                          if inner else f"{entry}/")
        elif os.path.isfile(full) and not entry.startswith("."):
            layout.append(entry)
    return {"name": name, "stack": stack, "purpose": purpose, "run": run, "build": build, "test": test,
            "lint": lint, "layout": layout[:_MAX_LAYOUT_LINES],
            "files": sorted(f for f in files if not f.startswith("."))}


def first_open(path):
    """True on the first gnoc chat entry: no instruction file the agent could read AND no session notes yet."""
    path = os.path.realpath(path or ".")
    try:
        files = set(os.listdir(path))
    except OSError:
        return False
    return instruction_file(path) is None and GCHAT not in files


def instruction_file(path):
    """The repo's own instruction file, or a collaborator project's partner handoff.

    Only used when no GNOC.md / CLAUDE.md / AGENTS.md exists, so a repo that already
    documents itself keeps its own instructions.
    """
    for f in INSTRUCTION_FILES:
        if os.path.isfile(os.path.join(path, f)):
            return f
    try:
        import gnoc_collab
        handoff = gnoc_collab.find_handoff(path)
        if handoff:
            return os.path.relpath(handoff, os.path.realpath(path))
    except Exception:  # noqa: BLE001 - a broken handoff must never make a repo look uninitialised
        pass
    return None


def _gnoc_md(s):
    generated = ", ".join(f"{g}/" for g in _GENERATED if g != ".git")
    run = f"- run: `{s['run']}`" if s["run"] else "- run: (none detected - add the command that starts it)"
    build = f"- build: `{s['build']}`" if s["build"] else ""
    test = f"- test: `{s['test']}`" if s["test"] else "- test: (none detected - add how it is verified)"
    lint = f"- lint: `{s['lint']}`" if s["lint"] else ""
    layout = "\n".join(f"- {l}" for l in s["layout"]) or "- (empty directory)"
    purpose = s["purpose"] or f"a {s['stack']} project (auto-detected)"
    return f"""# GNOC.md

Instructions for gnoc chat (and any AI) working in this repo. Generated {time.strftime('%Y-%m-%d %H:%MZ')} by
gnoc chat's workspace setup; keep it current as the project grows - the agent reads it on every entry.

## Project
{os.path.basename(s['name'])} - {purpose}

## Stack
{s['stack']} (auto-detected from {', '.join(s['files'][:6]) or 'the layout'})

## Commands
{run}
{build}
{test}
{lint}

## Layout
{layout}

## Rules
- Read the file and its callers before editing; make the smallest correct change.
- After a change, run the verification above; a change that was not run is a claim, not a fix.
- Never edit generated or vendored folders ({generated}).
- Match the surrounding style; no drive-by cleanup in a functional change.
- When a task is bigger than a one-liner, propose plan(action=set, steps=[{{action, verify, why}}, ...]) first;
  gnoc chat shows it and its steps ride every later turn.

## Work in progress
gnoc chat keeps its session notes in gchat.md in this directory.
"""


def _gchat_block(path, program="", task="", mode="append"):
    stamp = time.strftime("%Y-%m-%d %H:%MZ", time.localtime())
    block = (f"## Session {stamp}\n\n**Task:** {task or '(not stated yet)'}\n**Program:** {program or '-'}\n"
             f"**Directory:** {path}\n\n### State\n- started\n\n### Log\n- {stamp} entered {path}\n\n"
             "### Next\n- \n")
    f = os.path.join(path, GCHAT)
    if mode == "append" and os.path.isfile(f):
        with open(f, "a", encoding="utf-8") as fh:
            fh.write("\n" + block)
        return f"{GCHAT}: new session block appended"
    with open(f, "w", encoding="utf-8") as fh:
        fh.write(f"# gchat - {os.path.basename(path)}\n\nWorking notes kept by gnoc chat for this directory: "
                 "what it is doing here, what it found, and what comes next. Each session adds a block; keep "
                 "State and Next current, append to Log.\n\n" + block)
    return f"{GCHAT}: written"


def init_workspace(path, program="", task="", force_gchat=True):
    """First-open setup. Writes GNOC.md ONLY when none of GNOC/CLAUDE/AGENTS.md exists (never overwrites a
    repo's own instructions), and a gchat.md session block. Returns the summary lines to print."""
    path = os.path.realpath(os.path.expanduser(path or "."))
    if not os.path.isdir(path):
        return [f"no such directory: {path}"]
    s = sniff(path)
    out = []
    if instruction_file(path):
        out.append(f"kept {instruction_file(path)} (the repo's own instructions are never overwritten)")
    else:
        try:
            with open(os.path.join(path, "GNOC.md"), "w", encoding="utf-8") as fh:
                fh.write(_gnoc_md(s))
            out.append(f"GNOC.md written: {s['stack']} detected, commands and layout captured")
        except OSError as e:
            out.append(f"GNOC.md could not be written: {e}")
    if force_gchat:
        try:
            out.append(_gchat_block(path, program, task))
        except OSError as e:
            out.append(f"gchat.md could not be written: {e}")
    return out


_PYPROJECT = """[project]
name = "{name}"
version = "0.1.0"
description = "{name}"
requires-python = ">=3.10"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.pytest.ini_options]
testpaths = ["tests"]
"""

_PACKAGE_JSON = """{{
  "name": "{name}",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {{
    "start": "node index.js",
    "test": "node --test",
    "lint": "node --check index.js"
  }}
}}
"""

_GITIGNORE = """node_modules/
dist/
build/
__pycache__/
*.pyc
.venv/
venv/
.env
.DS_Store
coverage/
"""

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{name}</title>
  <style>
    body {{ margin: 2rem; font-family: system-ui, sans-serif; max-width: 60rem; }}
  </style>
</head>
<body>
  <h1>{name}</h1>
  <p>Fresh start - build from here.</p>
</body>
</html>
"""

_INDEX_JS = """// {name} - entry point
console.log("{name} started");
"""

_PY_INIT = '"""{} package."""\n'


def scaffold_project(parent, name, stack=None):
    """A NEW project from scratch: mkdir, git init, a real starter for the stack, README, .gitignore and a
    GNOC.md so the first gnoc chat entry is already a working workspace. Returns (path, summary lines)."""
    parent = os.path.realpath(os.path.expanduser(parent or "."))
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "").strip()).strip("-") or "new-project"
    path = os.path.join(parent, name)
    if os.path.exists(path):
        return None, [f"{path} already exists"]
    if stack not in (None, "node", "python", "web"):
        return None, [f"stack is node, python or web (got {stack!r})"]
    try:
        os.makedirs(path)
        subprocess.run(["git", "-C", path, "init", "-q"], capture_output=True, timeout=15)
        stack = stack or ("web" if name.endswith((".site", ".web", "-web")) else "python")
        readme = f"# {name}\n\nA new {stack} project. See GNOC.md for how to build, run and verify it.\n"
        files = {"README.md": readme, ".gitignore": _GITIGNORE}
        if stack == "node":
            files["package.json"] = _PACKAGE_JSON.format(name=name)
            files["index.js"] = _INDEX_JS.format(name=name)
        elif stack == "python":
            files["pyproject.toml"] = _PYPROJECT.format(name=name)
            os.makedirs(os.path.join(path, "src", name))
            os.makedirs(os.path.join(path, "tests"))
            files[f"src/{name}/__init__.py"] = _PY_INIT.format(name)
            files["tests/test_smoke.py"] = (f"def test_smoke():\n    import {name}\n    assert {name}\n")
        else:
            files["index.html"] = _INDEX_HTML.format(name=name)
        for rel, content in files.items():
            with open(os.path.join(path, rel), "w", encoding="utf-8") as fh:
                fh.write(content)
        with open(os.path.join(path, "GNOC.md"), "w", encoding="utf-8") as fh:
            fh.write(_gnoc_md(sniff(path)))
        out = _gchat_block(path, task=f"scaffold new {stack} project {name}")
    except OSError as e:
        return path, [f"scaffold failed: {e}"]
    extra = ", ".join(k for k in files if "/" not in k and k not in ("README.md", ".gitignore"))
    return path, [f"created {path}", "git init done",
                  f"{stack} starter written (README, .gitignore" + (f", {extra}" if extra else "") + ")",
                  out]
