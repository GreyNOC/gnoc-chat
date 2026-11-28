#!/usr/bin/env python3
"""gnoc_unbind.py - drop bind() names a function never uses (gnoc_core / gnoc_tools). --check only reports."""
import ast
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def fix(path, check=False):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    edits = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for st in fn.body[:2]:
            if isinstance(st, ast.Assign) and isinstance(st.value, ast.Call) \
                    and getattr(st.value.func, "id", None) == "bind" and isinstance(st.targets[0], ast.Tuple):
                names = [a.value for a in st.value.args]
                used = set()
                for node in ast.walk(fn):
                    if node is st:
                        continue
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                        used.add(node.id)
                # names used only inside the bind statement itself are not used
                inner = {n.id for n in ast.walk(st) if isinstance(n, ast.Name)}
                body_used = set()
                for node in fn.body:
                    if node is st:
                        continue
                    body_used |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                keep = [n for n in names if n in body_used]
                if keep != names:
                    edits.append((st, names, keep, fn.name))
    if not edits:
        return []
    if check:
        return [(f.split("/")[-1], fn, sorted(set(n) - set(k))) for st, n, k, fn in edits for f in [path]]
    lines = src.split("\n")
    for st, names, keep, fname in sorted(edits, key=lambda e: -e[0].lineno):
        indent = re.match(r"\s*", lines[st.lineno - 1]).group(0)
        if not keep:
            block = []
        else:
            pad = indent + "    "

            def wrap(items, quote):
                rows, cur = [], pad
                for it in items:
                    tok = (f'"{it}"' if quote else it) + ","
                    if len(cur) + len(tok) + 1 > 116 and cur.strip():
                        rows.append(cur.rstrip())
                        cur = pad
                    cur += tok + " "
                rows.append(cur.rstrip())
                return rows
            block = [f"{indent}(", *wrap(keep, False), f"{indent}) = bind(", *wrap(keep, True), f"{indent})"]
        lines[st.lineno - 1: st.end_lineno] = block
    out = "\n".join(lines)
    ast.parse(out)
    open(path, "w", encoding="utf-8").write(out)
    return [(os.path.basename(path), fn, sorted(set(n) - set(k))) for st, n, k, fn in edits]


if __name__ == "__main__":
    check = "--check" in sys.argv
    total = []
    for pkg in ("gnoc_core", "gnoc_tools"):
        for f in sorted(glob.glob(os.path.join(HERE, pkg, "*.py"))):
            total += fix(f, check)
    for row in total:
        print(*row)
    print(f"{len(total)} function(s) {'with' if check else 'cleaned of'} unused binds")
