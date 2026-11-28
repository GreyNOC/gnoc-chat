#!/usr/bin/env python3
"""gnoc_extract.py - move a section of the gnoc_agent.py facade into a gnoc_core / gnoc_tools module, the way the
2026-11-18 split did by hand: every moved function reads the facade's globals at CALL time through bind(), so a
test that patches gnoc_agent.X, and every sibling that calls X, still sees the patched X.

    python3 scripts/tools/gnoc_extract.py --start LINE --end LINE --to gnoc_core/models.py [--doc "..."] [--dry-run]

What moves (top-level statements whose first line is inside [start, end]):
  * functions: a bind() preamble is inserted after the docstring, listing every facade global the function (and
    any nested function / lambda / comprehension inside it) reads. Refused: a function that declares `global`,
    reads __file__ / __name__ / globals(), or whose decorators / defaults / annotations need a facade name that
    is not a plain stdlib module import.
  * constants (simple assignments): only when every name their value reads is a builtin, a stdlib module the
    facade imports, or a constant moved earlier in the same batch. The value is then evaluated in the module
    and the facade imports the same object back.
  * the comment block directly above a moved statement moves with it.
Everything else stays in the facade, in place: classes, augmented assignments, calls with side effects,
constants that depend on facade code. The facade gets `from <module> import (...)` at the position of the first
moved statement, so module-level code below still finds every name.

The result is checked: the new module and the facade must parse; --dry-run prints the plan only.
"""
import argparse
import ast
import builtins
import os
import re
import symtable
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FACADE = os.path.join(HERE, "gnoc_agent.py")
BUILTINS = set(dir(builtins))
FORBIDDEN = {"__file__", "__name__", "globals", "__spec__", "__loader__"}


def facade_globals(tree):
    names, modules = set(), {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                n = a.asname or a.name.split(".")[0]
                names.add(n)
                modules[n] = node
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.asname or a.name)
                if node.level == 0 and node.module and not node.module.startswith("gnoc_agent"):
                    # re-importable in the new module (a gnoc_core leaf, a stdlib name)
                    modules[a.asname or a.name] = ast.ImportFrom(module=node.module, names=[a], level=0)
        else:
            for t in ast.walk(node):
                if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store):
                    names.add(t.id)
    return names, modules


def _tables(src):
    """name -> symtable of every top-level function or class."""
    top = symtable.symtable(src, FACADE, "exec")
    return {c.get_name(): c for c in top.get_children() if c.get_type() in ("function", "class")}


def _globals_of(table, out, declared):
    for s in table.get_symbols():
        if s.is_declared_global():
            declared.add(s.get_name())
        if s.is_global() and s.is_referenced():
            out.add(s.get_name())
        if s.is_free():   # a nested function reading an enclosing local: not a global
            pass
    for c in table.get_children():
        _globals_of(c, out, declared)


def def_time_names(fn):
    """Names evaluated when the def statement runs: decorators, defaults, annotations."""
    nodes = list(fn.decorator_list) + list(fn.args.defaults) + [d for d in fn.args.kw_defaults if d is not None]
    if fn.returns is not None:
        nodes.append(fn.returns)
    for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs + \
            ([fn.args.vararg] if fn.args.vararg else []) + ([fn.args.kwarg] if fn.args.kwarg else []):
        if a.annotation is not None:
            nodes.append(a.annotation)
    out = set()
    for n in nodes:
        for t in ast.walk(n):
            if isinstance(t, ast.Name):
                out.add(t.id)
    return out


def value_names(node):
    """Names an expression reads from its enclosing scope (comprehension and lambda variables excluded)."""
    local = set()
    for t in ast.walk(node):
        if isinstance(t, ast.comprehension):
            local |= {n.id for n in ast.walk(t.target) if isinstance(n, ast.Name)}
        elif isinstance(t, ast.Lambda):
            local |= {a.arg for a in t.args.args + t.args.kwonlyargs}
        elif isinstance(t, ast.NamedExpr):
            local.add(t.target.id)
    return {t.id for t in ast.walk(node) if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Load)} - local


def comment_start(lines, lineno):
    """1-based first line of the contiguous comment block directly above `lineno` (or lineno)."""
    i = lineno - 1
    while i - 1 >= 0 and lines[i - 1].lstrip().startswith("#") and not lines[i - 1].startswith((" ", "\t")):
        i -= 1
    return i + 1


def bind_block(names, indent):
    names = sorted(names)
    pad = indent + "    "

    def wrap(items, quote):
        rows, cur = [], pad
        for it in items:
            tok = (f'"{it}"' if quote else it) + ","
            if len(cur) + len(tok) + 1 > 116 and cur.strip():
                rows.append(cur.rstrip())
                cur = pad
            cur += tok + " "
        if cur.strip():
            rows.append(cur.rstrip())
        return rows
    return "\n".join([f"{indent}(", *wrap(names, False), f"{indent}) = bind(", *wrap(names, True), f"{indent})"])


def plan(src, start, end, only=None):
    tree = ast.parse(src)
    lines = src.split("\n")
    fglobals, modules = facade_globals(tree)
    tables = _tables(src)
    seen, dup = set(), set()
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            (dup if n.name in seen else seen).add(n.name)
    moved, kept, consts_moved = [], [], set()
    for node in tree.body:
        if not (start <= node.lineno <= end):
            continue
        if only and not (({getattr(node, "name", None)} | _assigned(node)) & only):
            continue   # not selected: it stays in the facade, so nothing selected may depend on it moving
        name = getattr(node, "name", None)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            reads, declared = set(), set()
            _globals_of(tables[name], reads, declared)
            body_names = {t.id for t in ast.walk(node) if isinstance(t, ast.Name)}
            if declared:
                kept.append((node, f"declares global {sorted(declared)}"))
                continue
            if body_names & FORBIDDEN:
                kept.append((node, f"reads {sorted(body_names & FORBIDDEN)}"))
                continue
            if name in dup or node.body[0].lineno == node.lineno:
                kept.append((node, "defined twice in the facade" if name in dup else "one-line def"))
                continue
            dt = def_time_names(node) - BUILTINS
            bad = {n for n in dt if n in fglobals and n not in modules and n not in consts_moved}
            if bad:
                kept.append((node, f"decorators/defaults/annotations need {sorted(bad)}"))
                continue
            need = sorted((reads & fglobals) - (BUILTINS - fglobals))
            moved.append(("def", node, need, {n for n in dt if n in modules}))
        elif isinstance(node, ast.ClassDef):
            why, methods = _class_plan(node, tables[name], fglobals, modules, consts_moved, dup)
            if why:
                kept.append((node, why))
                continue
            need_mods = set()
            for t in ast.walk(node):
                if isinstance(t, ast.Name) and t.id in modules:
                    need_mods.add(t.id)
            moved.append(("class", node, methods, need_mods))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not all(isinstance(t, ast.Name) for t in targets):
                kept.append((node, "assignment target is not a plain name"))
                continue
            vals = value_names(node.value)
            if vals & FORBIDDEN:
                kept.append((node, f"reads {sorted(vals & FORBIDDEN)}"))
                continue
            deps = {n for n in vals if n in fglobals and n not in consts_moved and n not in modules}
            if deps:
                kept.append((node, f"value needs facade names {sorted(deps)[:6]}"))
                continue
            moved.append(("const", node, [], {n for n in vals if n in modules}))
            consts_moved.update(t.id for t in targets)
        else:
            kept.append((node, type(node).__name__))
    return tree, lines, moved, kept, modules


def _class_plan(node, table, fglobals, modules, consts_moved, dup):
    """(refusal or None, {method name: [names to bind]}) for a class moved whole."""
    if node.name in dup:
        return "defined twice in the facade", None
    head = set()
    for n in list(node.bases) + [k.value for k in node.keywords] + list(node.decorator_list):
        head |= {t.id for t in ast.walk(n) if isinstance(t, ast.Name)}
    bad = {n for n in head if n in fglobals and n not in modules and n not in consts_moved} - BUILTINS
    if bad:
        return f"bases/decorators need {sorted(bad)}", None
    mtables = {c.get_name(): c for c in table.get_children() if c.get_type() == "function"}
    methods = {}
    for st in node.body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            reads, declared = set(), set()
            _globals_of(mtables[st.name], reads, declared)
            names = {t.id for t in ast.walk(st) if isinstance(t, ast.Name)}
            if declared or names & FORBIDDEN:
                return f"method {st.name} declares global / reads {sorted(names & FORBIDDEN)}", None
            dt = def_time_names(st) - BUILTINS
            if {n for n in dt if n in fglobals and n not in modules and n not in consts_moved}:
                return f"method {st.name} defaults/decorators need facade names", None
            if st.body[0].lineno == st.lineno:
                return f"method {st.name} is a one-line def", None
            methods[st.lineno] = (st, sorted((reads & fglobals) - (BUILTINS - fglobals)))
        elif isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant):
            continue   # docstring
        elif isinstance(st, (ast.Assign, ast.AnnAssign)):
            vals = value_names(st.value) if st.value is not None else set()
            if {n for n in vals if n in fglobals and n not in modules and n not in consts_moved} - BUILTINS:
                return "class attribute needs facade names", None
        elif isinstance(st, ast.Pass):
            continue
        else:
            return f"class body has a {type(st).__name__}", None
    # the class symtable lists its attribute names as locals; a method reading a class attribute by bare
    # name is impossible in Python, so method globals are all that matter
    return None, methods


def _insert_binds(lines, fn, need, base):
    """Return (anchor index relative to base, block lines) for one function's bind preamble."""
    body0 = fn.body[0]
    has_doc = isinstance(body0, ast.Expr) and isinstance(getattr(body0, "value", None), ast.Constant) \
        and isinstance(body0.value.value, str)
    anchor = body0.end_lineno if has_doc else body0.lineno - 1
    return anchor - base, bind_block(need, " " * body0.col_offset).split("\n")


def render_class(lines, node, methods):
    first = comment_start(lines, node.decorator_list[0].lineno if node.decorator_list else node.lineno)
    seg = lines[first - 1: node.end_lineno]
    for lineno in sorted(methods, reverse=True):
        fn, need = methods[lineno]
        if not need:
            continue
        rel, block = _insert_binds(lines, fn, need, first - 1)
        seg = seg[:rel] + block + seg[rel:]
    return first, node.end_lineno, "\n".join(seg)


def render_function(lines, node, need):
    first = comment_start(lines, node.decorator_list[0].lineno if node.decorator_list else node.lineno)
    seg = lines[first - 1: node.end_lineno]
    if not need:
        return first, node.end_lineno, "\n".join(seg)
    body0 = node.body[0]
    has_doc = isinstance(body0, ast.Expr) and isinstance(getattr(body0, "value", None), ast.Constant) \
        and isinstance(body0.value.value, str)
    if body0.lineno == node.lineno:
        raise ValueError(f"{node.name}: one-line def")
    # insert AFTER this 1-based line: the docstring, else right before the first statement
    anchor = body0.end_lineno if has_doc else body0.lineno - 1
    indent = " " * body0.col_offset
    rel = anchor - (first - 1)
    out = seg[:rel] + bind_block(need, indent).split("\n") + seg[rel:]
    return first, node.end_lineno, "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--end", type=int, default=10 ** 9)
    ap.add_argument("--to", required=True, help="gnoc_core/x.py or gnoc_tools/x.py (relative to scripts/)")
    ap.add_argument("--doc", default="")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", default="", help="comma-separated names: move only these")
    a = ap.parse_args()
    src = open(FACADE, encoding="utf-8").read()
    only = {x.strip() for x in a.only.split(",") if x.strip()}
    tree, lines, moved, kept, modules = plan(src, a.start, a.end, only or None)
    if only:
        moved = [m for m in moved if _name(m[1]) in only]
        kept = [k for k in kept if getattr(k[0], "name", None) in only or _assigned(k[0]) & only]
        missing = only - {_name(m[1]) for m in moved} - {getattr(k[0], "name", None) for k in kept} - \
            set().union(*[_assigned(k[0]) for k in kept] or [set()])
        if missing:
            print(f"  not top-level names in the facade: {sorted(missing)}")
    print(f"move {len(moved)} statement(s); keep {len(kept)} in the facade")
    for k, why in kept:
        print(f"  keep line {k.lineno} {getattr(k, 'name', type(k).__name__)}: {why}")
    if a.dry_run:
        for kind, node, need, _ in moved:
            print(f"  {kind:5} {_name(node)}  binds {len(need) if kind != 'class' else sum(len(v[1]) for v in need.values())}")
        return 0
    if not moved:
        return 1
    target = os.path.join(HERE, a.to)
    pkg = os.path.dirname(a.to)
    chunks, spans, names, imports = [], [], [], set()
    for kind, node, need, mods in moved:
        if kind == "def":
            s, e, text = render_function(lines, node, need)
            names.append(node.name)
        elif kind == "class":
            s, e, text = render_class(lines, node, need)
            names.append(node.name)
        else:
            s = comment_start(lines, node.lineno)
            e = node.end_lineno
            text = "\n".join(lines[s - 1: e])
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names += [t.id for t in targets]
        imports |= mods
        chunks.append(text)
        spans.append((s, e))
    imp_lines = []
    for m in sorted(imports):
        node = modules[m]
        imp_lines.append(ast.unparse(node) if isinstance(node, ast.ImportFrom) or len(node.names) == 1
                         else f"import {m}")
    new = os.path.isfile(target)
    if new:
        body = open(target, encoding="utf-8").read().rstrip("\n") + "\n\n\n" + "\n\n\n".join(chunks) + "\n"
        if imp_lines:
            body = re.sub(r"(from (?:gnoc_core|\.)\S* import bind\n)", lambda m: "\n".join(imp_lines) + "\n" + m.group(1),
                          body, count=1)
    else:
        doc = a.doc or f"Extracted from the gnoc_agent facade."
        header = f'"""{doc}"""\n' + "".join(f"{l}\n" for l in imp_lines) + \
            ("from .runtime import bind\n" if pkg == "gnoc_core" else "from gnoc_core.runtime import bind\n")
        body = header + "\n\n" + "\n\n\n".join(chunks) + "\n"
    ast.parse(body)
    # facade: drop the moved spans (and the blank lines that separated them), import the names back
    drop = set()
    for s, e in spans:
        drop.update(range(s, e + 1))
    first = min(s for s, _ in spans)
    modname = (pkg + "." + os.path.splitext(os.path.basename(a.to))[0])
    rows, cur = [], "    "
    for n in names:
        tok = n + ", "
        if len(cur) + len(tok) > 116:
            rows.append(cur.rstrip())
            cur = "    "
        cur += tok
    rows.append(cur.rstrip().rstrip(","))
    imp = f"from {modname} import (  # noqa: E402,F401\n" + "\n".join(rows) + "\n)"
    out = []
    for i, ln in enumerate(lines, 1):
        if i == first:
            out.append(imp)
        if i in drop:
            continue
        out.append(ln)
    text = re.sub(r"\n{4,}", "\n\n\n", "\n".join(out))
    ast.parse(text)
    with open(target, "w", encoding="utf-8") as f:
        f.write(body)
    with open(FACADE, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.to} ({len(body.splitlines())} lines); facade now {len(text.splitlines())} lines")
    return 0


def _assigned(node):
    if isinstance(node, ast.Assign):
        return {t.id for t in node.targets if isinstance(t, ast.Name)}
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def _name(node):
    if hasattr(node, "name"):
        return node.name
    t = node.targets[0] if isinstance(node, ast.Assign) else node.target
    return getattr(t, "id", "?")


if __name__ == "__main__":
    sys.exit(main())
