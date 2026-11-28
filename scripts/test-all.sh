#!/usr/bin/env bash
# test-all.sh - every self-test for the report pipeline, one command.
# Run by FILENAME. Exit 0 only if all suites pass.
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rc=0
run(){ printf '\n== %s ==\n' "$1"; shift; "$@" 2>&1 | tail -3; [ "${PIPESTATUS[0]}" -ne 0 ] && rc=1; }
run "report-flow regression (qaqc rules)"  "$WS/scripts/test-report-flow.sh"
run "pipeline end-to-end (sandboxed)"      "$WS/scripts/test-pipeline-e2e.sh"
run "qaqc selftest"                        "$WS/scripts/qaqc.sh" --selftest
run "dispatch/dedup hook selftest"         "$WS/.claude/hooks/concurrency-gate.sh" --selftest
printf '\n== OVERALL: %s ==\n' "$([ $rc -eq 0 ] && echo ALL GREEN || echo FAILURES)"
exit $rc
