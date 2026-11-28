#!/usr/bin/env python3
"""Retire the pre-gate breadth-sweep DEAD rows in place: DEAD -> UNFIRED, reason recorded.

WHY (2026-10-27). `auto-hunt.py` used to write verdict DEAD with `burst` hardcoded False and `floor`
derived from wall-clock alone. That is a verdict its own evidence cannot support: the lane fires each
URL ONCE across many URLs, which is BREADTH, while the floor is DEPTH - 8 crafted mutations of one
vector plus a concurrent burst with its serial control (SPINE 4). T-266: probes against routes that
only ever refused are ABSENT SURFACE, not a tested negative.

Measured before this ran: 452 DEAD rows in outcomes.jsonl, 371 of them from `auto-exposure-*` lanes,
368 burst-less. Those rows are what the steering blob reads back as "the surface is dead", and RULE 3
records a stale dead suppressing a re-hunt that later paid two massive criticals.

NOT A DELETE. The retirement protocol says a refuted verdict MOVES with its refutation and is never
deleted, so nobody re-derives it: each row keeps every field, gains `retired_from: "DEAD"` and a
`retired_why`, and becomes UNFIRED. Idempotent - a row already retired is left alone.

    python3 scripts/learn/retire-sweep-deads.py            # report only
    python3 scripts/learn/retire-sweep-deads.py --apply     # rewrite (backs up first)
"""
import json
import os
import shutil
import sys
from datetime import datetime, timezone

WS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LEDGERS = [os.path.join(WS, ".claude/state/hunt-loop/outcomes.jsonl"),
           os.path.join(WS, ".claude/state/learning/outcomes.jsonl")]
WHY = ("breadth sweep retired 2026-10-27: one request per URL and no concurrent burst, so this is "
       "absent surface (UNFIRED), not a tested negative (SPINE 4 floor, Manual T-266). The surface "
       "is OPEN for a class hunter to mutate one vector 8+ times with a burst.")


def is_sweep_dead(row):
    return (str(row.get("verdict", "")).upper() == "DEAD"
            and str(row.get("lane", "")).startswith("auto-exposure-")
            and not row.get("burst")
            and not str(row.get("not_single_use") or "").strip())


def main():
    apply = "--apply" in sys.argv
    total = 0
    for path in LEDGERS:
        if not os.path.exists(path):
            continue
        out, hit = [], 0
        with open(path) as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                try:
                    row = json.loads(s)
                except ValueError:
                    out.append(s)       # never drop a line we cannot parse
                    continue
                if is_sweep_dead(row):
                    row["verdict"] = "UNFIRED"
                    row["retired_from"] = "DEAD"
                    row["retired_why"] = WHY
                    row["retired_ts"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    hit += 1
                out.append(json.dumps(row, ensure_ascii=False) if isinstance(row, dict) else s)
        total += hit
        print(f"{os.path.relpath(path, WS)}: {hit} sweep DEAD row(s) to retire")
        if apply and hit:
            shutil.copy2(path, path + ".bak-retire-20261027")
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                fh.write("\n".join(out) + "\n")
            os.replace(tmp, path)
            print(f"   rewritten (backup at {os.path.basename(path)}.bak-retire-20261027)")
    print(f"\ntotal: {total}")
    if not apply:
        print("report only - re-run with --apply to rewrite")


if __name__ == "__main__":
    main()
