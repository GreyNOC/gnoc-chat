#!/usr/bin/env python3
"""Keep HANDOFF-CURRENT under the auto-load budget by moving its OLDEST loop-state entries to the archive.

WHY (2026-10-27). The auto-loaded instruction set has a 150k budget; past it the files are SILENTLY
TRUNCATED and which rules are in force becomes unknowable. HANDOFF-CURRENT is the only one of the five
that GROWS every session - every lane appends a dated entry to section 2 - so it is the one that breaks
the budget, and it broke it repeatedly within a single session even while being hand-trimmed. Hand
trimming does not survive contact with four concurrent lanes.

The file's own doctrine already says what to do: it carries "only what is true NOW", and the dated
receipts live append-only in the CLAUDE-HANDOFF-CRITICAL-10-NN volumes. This enforces that.

NOTHING IS DELETED. Entries move VERBATIM into the newest archive volume under a dated COMPACTION
heading, exactly as the hand-done compactions 1-7 did, and a pointer line tells the next reader where
to grep. Idempotent: run it as often as you like.

    python3 scripts/learn/handoff-compact.py              # report what it would move
    python3 scripts/learn/handoff-compact.py --apply       # move them
    python3 scripts/learn/handoff-compact.py --apply --keep 6 --budget 148000
"""
import argparse
import datetime
import glob
import os
import re
import shutil

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CUR = os.path.join(WS, "HANDOFF-CURRENT.md")
# the five files doc-index.py counts; keep this list in step with it
AUTOLOADED = ["CLAUDE.md", "SPINE.md", "Manual/MANUAL-INDEX.md", "Manual/HARNESS.md", "HANDOFF-CURRENT.md"]


def budget_now():
    return sum(os.path.getsize(os.path.join(WS, f)) for f in AUTOLOADED if os.path.exists(os.path.join(WS, f)))


def newest_volume():
    vols = sorted(glob.glob(os.path.join(WS, "CLAUDE-HANDOFF-CRITICAL-10-*.md")))
    return vols[-1] if vols else os.path.join(WS, "CLAUDE-HANDOFF-CRITICAL-10-07.md")


def next_compaction_number(archive_text):
    ns = [int(m) for m in re.findall(r"COMPACTION (\d+)", archive_text)]
    return (max(ns) + 1) if ns else 8


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--keep", type=int, default=5, help="newest section-2 entries to keep (default 5)")
    ap.add_argument("--budget", type=int, default=148000, help="target total bytes for the auto-loaded set")
    a = ap.parse_args()

    before = budget_now()
    s = open(CUR).read()
    m = re.search(r"(?m)^## 2\. LOOP STATE$", s)
    e = re.search(r"(?m)^## 3\. ", s)
    if not (m and e):
        print("section 2 not found in the expected shape; nothing done")
        return
    lines = s[m.end():e.start()].splitlines(True)
    entries = [i for i, ln in enumerate(lines) if ln.startswith("**")]
    print(f"auto-loaded set: {before} bytes (budget {a.budget})")
    print(f"section 2 holds {len(entries)} dated entr(ies); keeping the newest {a.keep}")

    if before <= a.budget and len(entries) <= a.keep:
        print("under budget and within the keep count: nothing to do")
        return
    if len(entries) <= a.keep:
        print(f"only {len(entries)} entries, at or under --keep: NOT touching them. The overage is in another "
              f"file - trim Manual/MANUAL-INDEX.md's caps in scripts/doc-index.py, or SPINE/CLAUDE.md.")
        return

    cut = entries[a.keep]
    keep_txt, move_txt = "".join(lines[:cut]), "".join(lines[cut:])
    moved_n = len(entries) - a.keep
    arch = newest_volume()
    atext = open(arch).read() if os.path.exists(arch) else ""
    num = next_compaction_number(atext)
    day = datetime.date.today().isoformat()

    pointer = (f"\n### Older loop state: MOVED VERBATIM to `{os.path.basename(arch)}` under "
               f'"{day} COMPACTION {num}"\n'
               f"{moved_n} dated entr(ies), unedited. Grep before assuming anything:\n"
               f"    grep -n '{day} COMPACTION {num}' -A400 {os.path.basename(arch)}\n"
               "Still true unless a line above contradicts it.\n")

    print(f"would move {moved_n} entr(ies) -> {os.path.basename(arch)} COMPACTION {num}")
    if not a.apply:
        print("report only - re-run with --apply")
        return

    shutil.copy2(CUR, CUR + ".bak-compact")
    open(CUR, "w").write(s[:m.end()] + "\n" + keep_txt.rstrip() + "\n" + pointer + "\n" + s[e.start():])
    with open(arch, "a") as fh:
        fh.write(f"\n\n## {day} COMPACTION {num} - section 2 of HANDOFF-CURRENT, moved here verbatim\n\n"
                 f"Moved by scripts/learn/handoff-compact.py to keep the auto-loaded set under its "
                 f"{a.budget}-byte budget (it was {before}). Past the budget the instruction files are "
                 f"silently truncated, so which rules apply becomes unknowable. Not one character edited.\n\n"
                 + move_txt.rstrip() + "\n")
    after = budget_now()
    print(f"moved {moved_n}; auto-loaded set {before} -> {after} bytes "
          f"({'UNDER' if after <= a.budget else 'STILL OVER'} the {a.budget} budget)")


if __name__ == "__main__":
    main()
