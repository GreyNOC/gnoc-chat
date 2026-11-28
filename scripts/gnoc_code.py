"""gnoc_code.py - code navigation for gnoc chat's small local models: where a symbol is DEFINED vs USED, and a
compact map of a repo (files + their top-level definitions) so the model knows where to look before it reads.

    find_symbol(root, name)   definitions first, then references, via ripgrep (respects .gitignore)
    repo_map(root, sub="")    every source file with its classes / functions / exports, capped
"""
import ast
import os
import re
import shutil
import subprocess

SRC_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".kts", ".rb", ".php",
           ".sh", ".c", ".h", ".cpp", ".cc", ".hpp", ".cs", ".swift"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "vendor", "__pycache__", ".venv", "venv", ".next", "target",
             "coverage", ".cache"}
WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# The hunt workspace is 50+ GB, and almost none of it is code: targets/ alone holds 43 GB of captured HTTP
# bodies, APKs and recon output. Grepping it for a symbol times out every time and tells you nothing, so the
# CODE tools search the code and say so. Point them at a path to look anywhere else.
CODE_ROOTS = ("scripts", ".claude")

# A public clone is somebody else's tree, and a hostile one can carry a symlink to a file on THIS machine
# (`innocent.py -> ~/.ssh/id_rsa`). repo_map used to open it: the link's target was outside the repo but
# nothing resolved it, so the map printed the target's line count and any definition-shaped names. The map
# now skips a file whose real path leaves the repo and says how many it skipped.
#
# Two size caps keep one generated file from becoming the whole turn, and stop the walk at the file cap:
# the old loop kept walking every remaining directory after the cap, so repo_map on a large public repo
# spent its time listing files it then threw away.
MAX_DEF_BYTES = 2_000_000
MAX_COUNT_BYTES = 20_000_000


def _inside(root, path):
    """True when `path` resolves inside `root` (a symlink out of the repo is not)."""
    try:
        r = os.path.realpath(root)
        p = os.path.realpath(path)
    except OSError:          # a path component changed under us: treat it as outside, never read it
        return False
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def _search_roots(root):
    """(paths to search, note). Only the hunt workspace is narrowed; a real repo is searched whole."""
    if os.path.realpath(root) != WS:
        return [root], ""
    paths = [os.path.join(WS, d) for d in CODE_ROOTS if os.path.isdir(os.path.join(WS, d))]
    return paths, (" (searched " + ", ".join(CODE_ROOTS) + ": the rest of the workspace is captures and "
                   "archives, not code. Give a path to search elsewhere.)")


def _def_patterns(name):
    n = re.escape(name)
    return [rf"^\s*(async\s+)?def\s+{n}\b", rf"^\s*class\s+{n}\b", rf"\bfunction\s*\*?\s*{n}\s*\(",
            rf"\b(const|let|var)\s+{n}\s*=", rf"^\s*(export\s+)?(default\s+)?(async\s+)?function\s+{n}\b",
            rf"^\s*(export\s+)?(abstract\s+)?(class|interface|type|enum)\s+{n}\b", rf"^\s*func\s+(\([^)]*\)\s*)?{n}\s*\(",
            rf"^\s*(pub(\([^)]*\))?\s+)?(async\s+)?(unsafe\s+)?(fn|struct|enum|trait|type|mod|const|static)\s+{n}\b",
            rf"^\s*{n}\s*\(\)\s*\{{", rf"^\s*{n}\s*=\s*",
            # a METHOD: JS/TS class members (incl. static / async / get / set / private / generics), Java / C# /
            # Kotlin / Swift / PHP / Ruby methods. Without these `Agent.turn` found no definition at all.
            rf"^\s*(public\s+|private\s+|protected\s+|static\s+|readonly\s+|override\s+|async\s+|get\s+|set\s+|\*\s*)*"
            rf"#?{n}\s*(<[^>]*>)?\s*\([^;]*$",
            rf"^\s*((public|private|protected|internal|static|final|abstract|virtual|override|synchronized|async|"
            rf"open|suspend|inline)\s+)*[A-Za-z0-9_<>,.? ]+\s+{n}\s*\(",
            rf"^\s*(override\s+|private\s+|public\s+|internal\s+)*(fun|func)\s+(<[^>]*>\s*)?{n}\b",
            rf"^\s*((public|private|protected|static|final|abstract)\s+)*function\s+&?{n}\s*\(",
            rf"^\s*def\s+(self\.)?{n}\b",
            rf"^\s*(typedef\s+)?(struct|class|union|enum)\s+{n}\b", rf"^\s*#define\s+{n}\b",
            rf"^\s*(export\s+)?(declare\s+)?(type|interface)\s+{n}\b"]


# lines a method pattern also matches but which are CALLS or control flow, not definitions
_NOT_DEF = re.compile(r"^\s*(return|if|else|for|while|switch|catch|await|new|throw|yield|case|do|print|echo)\b|"
                      r"^\s*[\w.]+\s*\(.*\)\s*;\s*$")


def _rg(root, pattern, extra=(), timeout=45):
    """ripgrep when it is installed as a binary, else GNU grep -E (same \\s and \\b), skipping vendored dirs.
    A timeout returns what a search of this size can honestly give - nothing - instead of raising into the
    caller: a 50 GB tree used to crash find_symbol with TimeoutExpired."""
    paths, _ = _search_roots(root)
    exe = shutil.which("rg")
    if exe:
        args = [exe, "-n", "--no-heading", "-S", "--max-columns", "220", *extra, "-e", pattern, *paths]
    else:
        args = ["grep", "-rnIE", "--binary-files=without-match"] + [f"--exclude-dir={d}" for d in SKIP_DIRS] + \
            ["--exclude=*.bak*", "--exclude=*.min.js", "-e", pattern, *paths]
    try:
        pr = subprocess.run(args, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return ["__TIMEOUT__"]
    return [ln[:260] for ln in pr.stdout.splitlines()]


def find_symbol(root, name, limit=40):
    if not re.fullmatch(r"[A-Za-z_$][\w$.]*", name or ""):
        return "give a plain identifier (function, class, variable, method)"
    short = name.split(".")[-1]
    _, note = _search_roots(root)
    # ONE pass over the tree: every definition line also contains the name, so the definition patterns are
    # matched here against the hits of a single word search. Running each pattern as its own search cost one
    # full scan per pattern (18 of them once methods and more languages were added: 34 s on the workspace).
    got = _rg(root, rf"\b{re.escape(short)}\b")
    timed_out = got == ["__TIMEOUT__"]
    if timed_out:
        # The old tail appended a timeout note only when hits existed, but a timed-out search returns NO hits:
        # so the one case that mattered said "not found" - a false negative on exactly the big trees where a
        # miss looks like a fact (public clone 2026-11-27). Say the search did not finish; absence is unknown.
        return (f"{name}: the search TIMED OUT after 45 s, so it is NOT evidence this name is absent. "
                "Narrow it with grep (pattern=<name on that line>, path=<a file or folder>) or read the "
                "likely file.")
    hits = [ln for ln in got if ln != "__TIMEOUT__"]
    pats = [re.compile(p) for p in _def_patterns(short)]
    defs = []
    for ln in hits:
        text = ln.split(":", 2)[-1]
        if not _NOT_DEF.match(text) and any(p.search(text) for p in pats):
            defs.append(ln)
    defs = list(dict.fromkeys(defs))
    refs = [ln for ln in hits if ln not in defs]
    rel = lambda ln: os.path.relpath(ln, root) if ln.startswith(root) else ln
    out = [f"DEFINED ({len(defs)}):"] + [f"  {rel(d)}" for d in defs[:15]]
    out += [f"USED ({len(refs)}):"] + [f"  {rel(r)}" for r in refs[:limit]]
    if len(refs) > limit:
        out.append(f"  ... {len(refs) - limit} more (grep with a path to narrow)")
    return "\n".join(out) if defs or refs else (f"{name}: not found" + (note or f" under {root}"))


def _py_defs(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # No .py file in a public clone is allowed to take the map down. A generated file with one long
        # binary-operator chain (`x = 1+1+...`, ~100 KB) raises RecursionError out of ast, and it used to
        # escape repo_map and fail the tool; the file is still listed by line count, with no definitions.
        return []
    out = []
    for n in tree.body:
        if isinstance(n, ast.ClassDef):
            meths = [m.name for m in n.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))]
            out.append(f"class {n.name}" + (f"({', '.join(meths[:8])}{', ...' if len(meths) > 8 else ''})" if meths else ""))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append(f"def {n.name}")
    return out


_JS_DEF = re.compile(r"^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?(?:function\s*\*?\s*([A-Za-z_$][\w$]*)|"
                     r"class\s+([A-Za-z_$][\w$]*)|(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(|function|"
                     r"[A-Za-z_$][\w$]*\s*=>))", re.M)
_GO_DEF = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", re.M)
_OTHER_DEF = {
    ".rs": (re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(fn|struct|enum|trait|impl|mod|type)\s+"
                       r"(?:<[^>]*>\s*)?([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".java": (re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract|sealed)\s+)*"
                         r"(class|interface|enum|record)\s+([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".kt": (re.compile(r"^\s*(?:(?:public|private|internal|open|data|sealed|abstract|override|suspend|inline)\s+)*"
                       r"(class|interface|object|fun)\s+(?:<[^>]*>\s*)?([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".cs": (re.compile(r"^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|readonly)\s+)*"
                       r"(class|interface|struct|enum|record)\s+([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".swift": (re.compile(r"^\s*(?:(?:public|private|internal|open|final|fileprivate)\s+)*"
                          r"(class|struct|enum|protocol|extension|func)\s+([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".rb": (re.compile(r"^\s*(class|module|def)\s+(?:self\.)?([A-Za-z_]\w*[?!]?)", re.M), "{0} {1}"),
    ".php": (re.compile(r"^\s*(?:(?:abstract|final|public|private|protected|static)\s+)*(class|interface|trait|function)\s+"
                        r"&?([A-Za-z_]\w*)", re.M), "{0} {1}"),
    ".c": (re.compile(r"^(?:static\s+|inline\s+|extern\s+)*[A-Za-z_][\w\s*]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{?\s*$|"
                      r"^\s*(?:typedef\s+)?struct\s+([A-Za-z_]\w*)\s*\{", re.M), None),
}
_OTHER_DEF[".h"] = _OTHER_DEF[".cpp"] = _OTHER_DEF[".cc"] = _OTHER_DEF[".hpp"] = _OTHER_DEF[".c"]
_OTHER_DEF[".kts"] = _OTHER_DEF[".kt"]


def _other_defs(path, ext):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(400_000)
    except OSError:
        return []
    if ext in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
        return [next(g for g in m.groups() if g) for m in _JS_DEF.finditer(text)]
    if ext == ".go":
        return [f"func {m.group(1)}" for m in _GO_DEF.finditer(text)]
    if ext == ".sh":
        return [m.group(1) for m in re.finditer(r"^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\)", text, re.M)]
    got = _OTHER_DEF.get(ext)
    if got:
        rx, fmt = got
        out = []
        for m in rx.finditer(text):
            if fmt:
                out.append(fmt.format(m.group(1), m.group(2)))
            else:   # C/C++: a function name or a struct name, whichever alternative matched
                name = next((g for g in m.groups() if g), "")
                if name and name not in ("if", "for", "while", "switch", "return", "sizeof"):
                    out.append(name)
        return out
    return []


def repo_map(root, sub="", max_files=150, max_defs=12):
    base = os.path.realpath(os.path.join(root, sub)) if sub else root
    if sub and (not _inside(root, base) or not os.path.isdir(base)):
        # t_repo_map already refuses an escaping sub; this is the same boundary one layer down, so a caller
        # that reached the function directly (or a symlinked subfolder) cannot map the rest of the machine.
        return (f"no source files under {base}: give a subfolder of {root} (a path outside the repo, "
                "or a symlink to one, is not mapped)")
    rows, n, skipped_links, capped = [], 0, 0, False
    for dp, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(files):
            ext = os.path.splitext(f)[1]
            if ext not in SRC_EXT or ".bak" in f or ".min." in f:
                continue
            p = os.path.join(dp, f)
            if os.path.islink(p) and not _inside(root, p):
                # A cloned public repo can carry `innocent.py -> ~/.ssh/id_rsa`. It is not part of the repo,
                # so it is never opened; the note tells the model the map skipped something.
                skipped_links += 1
                continue
            if n >= max_files:
                # Stop the WALK, not just the appending: the old loop kept visiting every later directory
                # after the cap, so a big repo spent the whole call listing files it then discarded.
                capped = True
                break
            n += 1
            try:
                size = os.path.getsize(p)
            except OSError:
                size = 0
            rel = os.path.relpath(p, root)
            if size > MAX_COUNT_BYTES:
                rows.append(f"{rel} ({size} bytes: too large to map, not read)")
                continue
            if size > MAX_DEF_BYTES:
                defs, big = [], " (large file: definitions not scanned)"
            else:
                defs, big = (_py_defs(p) if ext == ".py" else _other_defs(p, ext)), ""
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    lines = sum(1 for _ in fh)
            except OSError:
                lines = 0
            rows.append(f"{rel} ({lines} lines)" + big
                        + (": " + ", ".join(defs[:max_defs]) + (" ..." if len(defs) > max_defs else "") if defs else ""))
        if capped:
            break
    if capped:
        rows.append(f"... stopped at the {max_files}-file cap: more source files exist "
                    "(repo_map sub=<dir> to zoom in)")
    if skipped_links:
        rows.append(f"... skipped {skipped_links} symlink(s) that resolve outside the repo (never read)")
    return "\n".join(rows) or f"no source files under {base}"
