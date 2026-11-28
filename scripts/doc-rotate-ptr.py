#!/usr/bin/env python3
"""Repoint the "(active)" volume sentence after a rotation. Idempotent."""
import re, sys, pathlib

POINTER_FILES = ["CLAUDE.md"]

def repoint(stem, ext, newpath):
    pat = re.compile(r'`' + re.escape(stem) + r'(?:-\d+)?\.' + re.escape(ext) + r'` \(active\)')
    changed = []
    for f in POINTER_FILES:
        p = pathlib.Path(f)
        if not p.exists():
            continue
        t = p.read_text()
        new = pat.sub('`' + newpath + '` (active)', t)
        if new != t:
            p.write_text(new)
            changed.append(f)
    return changed

if __name__ == "__main__":
    stem, ext, newpath = sys.argv[1], sys.argv[2], sys.argv[3]
    c = repoint(stem, ext, newpath)
    print("  POINTER: updated " + ", ".join(c) if c else "  POINTER: no '(active)' sentence found to update")
