#!/usr/bin/env bash
# verify-fleet.sh - one comprehensive health gate for the whole agent/loop fleet.
# Runs the static checks the operator asked for ("verify absolutely everything works") in one pass:
#   1. agent spec-conformance (verify-agents.sh, all PASS)
#   2. every workflow JS parses (node --check)
#   3. every hook is valid bash (bash -n)
#   4. routing coherence: every agent referenced in hunt-cycle.js exists as a file
#   5. bbtools self-tests pass
#   6. key artifacts present
# Read-only. Exit 0 only if every section passes. Re-run after any fleet edit.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
fail=0
hr() { printf '%s\n' "----------------------------------------"; }

hr; echo "[1] agent spec-conformance"
out=$(bash scripts/verify-agents.sh 2>&1)
echo "$out" | tail -1
echo "$out" | grep -q ' WARN: 0' || { echo "  FAIL: some agents WARN"; fail=1; }

hr; echo "[2] workflow JS parse"
for f in .claude/workflows/*.js; do
  [ -f "$f" ] || continue
  # workflow scripts are engine-wrapped (top-level await/return + `export const meta`);
  # mirror that wrap so node --check validates them on any node version (node 18's --check
  # lacks node 22's module auto-detection and rejects the raw file).
  wtmp=$(mktemp --suffix=.js)
  { echo 'async function __wf(){'; sed 's/^export //' "$f"; echo '}'; } > "$wtmp"
  if node --check "$wtmp" 2>/dev/null; then echo "  OK   $(basename "$f")"; else echo "  FAIL $(basename "$f")"; fail=1; fi
  rm -f "$wtmp"
done

hr; echo "[3] hook bash syntax"
for h in .claude/hooks/*.sh; do
  [ -f "$h" ] || continue
  if bash -n "$h" 2>/dev/null; then :; else echo "  FAIL $(basename "$h")"; fail=1; fi
done
echo "  $(ls .claude/hooks/*.sh 2>/dev/null | wc -l) hooks checked"

hr; echo "[4] routing coherence (hunt-cycle.js agentType + CLASS_AGENT targets exist)"
# Precise extraction: CLASS_AGENT mapping VALUES are "], 'name']," (inner array close, then the
# agent); agentType refs are "agentType: 'name'". Keyword tokens inside the match arrays are
# "'k', 'k'" and never preceded by "], " so they are excluded. Plus the hardcoded bb-researcher fallback.
refs=$( { grep -oE "\], '[a-z][a-z-]+'\]," .claude/workflows/hunt-cycle.js | grep -oE "'[a-z-]+'" | tr -d "'";
          grep -oE "agentType: '[a-z][a-z-]+'" .claude/workflows/hunt-cycle.js | sed -E "s/agentType: '//; s/'//";
          echo bb-researcher; } | sort -u )
for a in $refs; do
  if [ -f ".claude/agents/$a.md" ]; then :; else echo "  FAIL missing agent file: $a"; fail=1; fi
done
echo "  $(echo "$refs" | wc -w) routed agents checked"

hr; echo "[5] bbtools self-tests"
for t in scripts/bbtools/lib_scope.py scripts/bbtools/lib_egress.py; do
  if [ -f "$t" ] && python3 "$t" >/dev/null 2>&1; then echo "  OK   $(basename "$t")"; else echo "  FAIL $(basename "$t")"; fail=1; fi
done

hr; echo "[6] key artifacts"
for f in SPINE.md CLAUDE.md .claude/workflows/hunt-cycle.js \
         .claude/agents/unauth-access-hunter.md .claude/agents/unauth-surface-mapper.md \
         patterns/kill-knowledge/FLEET-CHANGES-today.md patterns/intel/INTEL-INDEX-2026-06-20.md; do
  if [ -f "$f" ]; then :; else echo "  FAIL missing: $f"; fail=1; fi
done
echo "  artifact set checked"

hr
if [ "$fail" -eq 0 ]; then echo "VERIFY-FLEET: ALL PASS"; else echo "VERIFY-FLEET: FAILURES ABOVE"; fi
exit "$fail"
