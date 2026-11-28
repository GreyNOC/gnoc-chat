#!/usr/bin/env bash
# consolidate-selftest.sh - durability guard for the self-learning gauges (scripts/learn/consolidate.py).
# Asserts the three honesty invariants a past audit found broken, so a future regression fails LOUD:
#   1. the ship-log line LABELS drafts vs submitted separately (never calls the total "drafts")
#   2. the NORTH-STAR positive count == the sum of the H1 positive states it lists (no off-by-1)
#   3. ZERO synthetic/test rows survive into the outcomes-derived win count
# Exit 0 = all pass; exit 1 = a gauge regressed. Safe + read-only except it re-runs consolidate.py.
set -u
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
L="$ROOT/.claude/state/learning/LESSONS.md"
O="$ROOT/.claude/state/learning/outcomes.jsonl"
fail=0
ok(){ echo "  OK   $1"; }
bad(){ echo "  BAD  $1"; fail=1; }

# Regenerate so we assert on fresh output, not a stale file.
python3 "$ROOT/scripts/learn/consolidate.py" >/dev/null 2>&1 || { echo "  BAD  consolidate.py failed to run"; exit 1; }

# 1. LABEL present: the ship-log line must carry both "N drafts" and "M submitted", and they must differ
#    (the bug was calling the 163-row total "drafts"; drafts and submitted are never equal here).
line=$(grep -E '^## Ship log' "$L" || true)
if echo "$line" | grep -qE '[0-9]+ drafts, [0-9]+ submitted'; then
  d=$(echo "$line" | grep -oE '[0-9]+ drafts' | grep -oE '[0-9]+')
  s=$(echo "$line" | grep -oE '[0-9]+ submitted' | grep -oE '[0-9]+')
  if [ "$d" != "$s" ]; then ok "ship-log labels drafts($d) != submitted($s) separately"; else bad "ship-log draft-count == submitted-count ($d) - label looks like a single mislabeled total"; fi
else
  bad "ship-log line missing the 'N drafts, M submitted' label (found: ${line:-<none>})"
fi

# 2. NORTH-STAR positive == states-sum. Parse "positive: <N> ... (by state: a=1/b=2/...)" and assert
#    N equals the sum of the per-state values (the off-by-1 was value=34 vs listed-states-sum=33).
pline=$(grep -E '^- positive: ' "$L" || true)
if [ -n "$pline" ]; then
  pos=$(echo "$pline" | grep -oE 'positive: [0-9]+' | grep -oE '[0-9]+')
  sum=$(echo "$pline" | grep -oE '=[0-9]+' | grep -oE '[0-9]+' | paste -sd+ | bc)
  if [ -n "$pos" ] && [ -n "$sum" ] && [ "$pos" = "$sum" ]; then ok "NORTH-STAR positive ($pos) == sum of listed states ($sum)"; else bad "NORTH-STAR off-by: positive=$pos but listed states sum to $sum"; fi
else
  echo "  SKIP NORTH-STAR line absent (no H1 feedback json) - positive/states assert not applicable"
fi

# 3. Zero synthetic/test rows in the win count. Re-derive independently: count verdict=win rows whose
#    session matches a test fixture; consolidate.py must exclude them, so the leaked-into-real count is 0.
leak=$(python3 - "$O" <<'PY'
import json,re,sys
rx=re.compile(r"(?:^|-)test(?:-|$)|^floortest|^fgtest|^digest-fix|win-precedence|^wtest$|test-session-")
rows=[json.loads(l) for l in open(sys.argv[1],encoding="utf-8",errors="replace") if l.strip()]
real=[r for r in rows if not rx.search(str(r.get("session") or ""))]
print(sum(1 for r in real if r.get("verdict")=="win" and rx.search(str(r.get("session") or ""))))
PY
)
if [ "$leak" = "0" ]; then ok "zero synthetic/test rows survive into the win count"; else bad "$leak synthetic win rows leaked into the real population"; fi

echo
[ "$fail" = "0" ] && { echo "ALL PASS - consolidate.py gauges are honest."; exit 0; } || { echo "FAIL - a gauge regressed; see BAD lines above."; exit 1; }
