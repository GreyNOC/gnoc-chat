#!/usr/bin/env bash
# scripts/suite.sh - the one command that says whether the harness is green.
#
# WHY THIS EXISTS (2026-10-27): nothing ran the test suite automatically. 23 tests sat red for days and
# the handoff recorded them as "pre-existing" noise; twelve of them traced to ONE stale fixture line.
# A red suite nobody reads is not a safety net. See Manual T-272.
#
#   scripts/suite.sh            full suite + qaqc, one summary line (what pre-commit runs)
#   scripts/suite.sh --fast     tests only, no qaqc
#   scripts/suite.sh --quiet    only print on failure (for hooks)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

FAST=0 QUIET=0
for a in "$@"; do
  case "$a" in
    --fast)  FAST=1 ;;
    --quiet) QUIET=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  esac
done

OUT=$(mktemp); trap 'rm -f "$OUT"' EXIT
rc=0

timeout 2400 python3 -m pytest scripts/test_*.py -q --no-header -p no:cacheprovider >"$OUT" 2>&1 || rc=1
line=$(grep -E "^[0-9]+ (passed|failed)|passed|failed" "$OUT" | tail -1)
failed=$(grep -c "^FAILED" "$OUT" || true)

if [ "$FAST" -eq 0 ]; then
  qaqc=$(timeout 900 python3 scripts/gnoc-qaqc.py --quick 2>&1 | tail -1)
  case "$qaqc" in *PASS*) : ;; *) rc=1 ;; esac
else
  qaqc="(skipped)"
fi

if [ "$rc" -eq 0 ]; then
  [ "$QUIET" -eq 1 ] || echo "SUITE GREEN  ·  $line  ·  qaqc: $qaqc"
else
  echo "SUITE RED  ·  $line  ·  qaqc: $qaqc"
  echo "--- failures ---"
  grep "^FAILED" "$OUT" | head -25
  echo "(full output: re-run scripts/suite.sh without --quiet, or python3 -m pytest scripts/test_*.py -q)"
fi
exit $rc
