#!/usr/bin/env python3
"""Diff the ships ledger against what is actually on disk, and say which one is lying.

WHY (2026-10-27). `ships.jsonl` disagreed with `reports/` in three ways at once: 44 of 103 rows carried
no `kind` at all, the ledger showed 3 submissions against 7 directories under reports/submitted/, and
55 drafts against 57 on disk. Both the dashboard and the steering blob read that ledger, so a drift
there is worse than having no ledger: it is a confident wrong number. The blob had already noticed
("RECONCILE(ledger vs disk) ... trust the DISK count") without anything acting on it.

DISK WINS. A report directory is the artifact; a ledger row is a claim about one. This never deletes a
row and never invents one - it reports, and with --heal it appends the rows the disk can prove are
missing, tagged so their provenance is obvious.

    python3 scripts/learn/reconcile-ledgers.py          # report
    python3 scripts/learn/reconcile-ledgers.py --heal   # append the provable missing rows
"""
import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHIPS = os.path.join(WS, ".claude/state/hunt-loop/ships.jsonl")


def rows():
    out = []
    if not os.path.exists(SHIPS):
        return out
    with open(SHIPS) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def disk():
    """{(program, slug): kind} from the directories that actually exist."""
    found = {}
    for kind, pat in (("draft", "reports/drafts/*/*/report.md"),
                      ("submission", "reports/submitted/*/*")):
        for p in glob.glob(os.path.join(WS, pat)):
            d = p if os.path.isdir(p) else os.path.dirname(p)
            slug, program = os.path.basename(d), os.path.basename(os.path.dirname(d))
            if kind == "submission" and not os.path.isdir(d):
                continue
            found[(program, slug)] = kind
    return found


def main():
    heal = "--heal" in sys.argv
    R, D = rows(), disk()
    by_kind = {}
    for r in R:
        by_kind.setdefault(r.get("kind") or "(no kind)", []).append(r)

    print(f"ships.jsonl: {len(R)} row(s)")
    for k, v in sorted(by_kind.items(), key=lambda kv: -len(kv[1])):
        print(f"   {k:14s} {len(v)}")
    dk = {}
    for k in D.values():
        dk[k] = dk.get(k, 0) + 1
    print("disk:")
    for k, v in sorted(dk.items()):
        print(f"   {k:14s} {v}")

    # a row "covers" a disk item when its program+slug appear anywhere in the row's own fields
    def covered(program, slug):
        for r in R:
            blob = json.dumps(r)
            if slug and slug in blob and program in blob:
                return True
        return False

    missing = [(p, s, k) for (p, s), k in sorted(D.items()) if not covered(p, s)]
    print(f"\non disk but NOT in the ledger: {len(missing)}")
    for p, s, k in missing[:20]:
        print(f"   {k:11s} {p}/{s}")
    if len(missing) > 20:
        print(f"   ... and {len(missing) - 20} more")

    noknd = len(by_kind.get("(no kind)", []))
    if noknd:
        print(f"\n{noknd} row(s) carry no `kind`: they cannot be counted as draft or submission by any "
              f"reader. Left alone (a row is a historical record), but every NEW row must set kind.")

    if heal and missing:
        n = 0
        for p, s, k in missing:
            row = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": k,
                   "program": p, "slug": s, "path": f"reports/{'drafts' if k == 'draft' else 'submitted'}/{p}/{s}",
                   "notes": "backfilled 2026-10-27 by reconcile-ledgers.py from the directory on disk; "
                            "the artifact is the receipt, this row is only its index entry"}
            r = subprocess.run([sys.executable, os.path.join(WS, "scripts/hunt-state.py"), "append-ship"],
                               input=json.dumps(row), text=True, cwd=WS, capture_output=True)
            if r.returncode == 0:
                n += 1
            else:
                print(f"   refused by hunt-state.py: {p}/{s}: {(r.stderr or r.stdout).strip()[:160]}")
        print(f"\nhealed: appended {n} row(s) through hunt-state.py (direct writes are forbidden)")
    elif missing:
        print("\nreport only - re-run with --heal to append the missing rows")


if __name__ == "__main__":
    main()
