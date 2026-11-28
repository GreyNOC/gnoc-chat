#!/usr/bin/env bash
# health-check.sh - one-command hunt-system health dashboard (2026-07-16).
#
# The root cause of the "nothing improves" era was corrupt telemetry going UNDETECTED for weeks.
# This runs, in one command, every integrity check the 2026-07-16 architecture review established,
# so a broken gauge / hook / selftest surfaces in seconds. Read-only, no network, safe to run anytime.
#   Run: bash scripts/learn/health-check.sh
set -u
R="${GNOC_WORKSPACE:-$HOME/.gnoc}"; cd "$R" 2>/dev/null || exit 1
fail=0; ok(){ printf '  OK   %s\n' "$1"; }; bad(){ printf '  FAIL %s\n' "$1"; fail=1; }

echo "== hooks =="
b=0; for h in .claude/hooks/*.sh; do bash -n "$h" 2>/dev/null || b=1; done
[ $b = 0 ] && ok "all $(ls .claude/hooks/*.sh|wc -l) hooks parse" || bad "a hook has a syntax error"
jq -e . .claude/settings.json >/dev/null 2>&1 && ok "settings.json valid JSON" || bad "settings.json invalid"
bash .claude/hooks/dedup-gate.sh --selftest >/dev/null 2>&1 && ok "dedup-gate selftest" || bad "dedup-gate selftest"
bash .claude/hooks/draft-write-gate.selfcheck.sh 2>&1 | grep -q '0 failed' && ok "draft-write-gate selftest" || bad "draft-write-gate selftest"

grep -qF 'read)).*(curl|send_http|wget' .claude/hooks/subagent-floor-gate.sh && ok "floor-gate burst anchored (recon-loop is not a false burst)" || bad "floor-gate burst regex reverted to the bare-loop false-positive (empirical_ok would re-pollute)"

echo "== telemetry (the gauges) =="
python3 scripts/hunt-state.py validate && ok "hunt-loop JSONL parseable; canonical writer available" || bad "hunt-loop state malformed or ships have zero programs"
python3 - << 'PY' && ok "outcomes.jsonl valid + honest (probed:false => probe_count:0)" || bad "outcomes.jsonl corrupt or re-polluting"
import json,sys
n=viol=bad=0
for l in open(".claude/state/learning/outcomes.jsonl",encoding="utf-8",errors="ignore"):
    l=l.strip()
    if not l: continue
    n+=1
    try:
        o=json.loads(l)
        if (not o.get("probed")) and (o.get("probe_count") or 0)>0: viol+=1
    except: bad+=1
sys.exit(1 if (bad or viol) else 0)
PY
S=".claude/state/hunt-loop/ships.jsonl"
if [ -s "$S" ]; then
  read -r N P <<EOF
$(python3 - "$S" <<'PY'
import json, sys
rows=[]
for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    try: rows.append(json.loads(line))
    except json.JSONDecodeError: pass
print(len(rows), len({r.get("program") for r in rows if isinstance(r,dict) and r.get("program")}))
PY
)
EOF
  [ "${P:-0}" -gt 0 ] && ok "ships.jsonl north-star live ($N receipts / $P programs)" || bad "ships.jsonl has receipts but zero programs"
else bad "ships.jsonl empty (north-star not recording)"; fi
L=".claude/state/learning/LESSONS.md"
if [ -f "$L" ]; then
  grep -q 'North-star\|WIN-SHAPE\|CREDENTIAL WALL\|search PUBLIC' "$L" && ok "LESSONS carries the honest steers" || bad "LESSONS missing the honest steers (re-run consolidate.py)"
  grep -q 'TELEMETRY HEALTH - ACTION NEEDED' "$L" && bad "LESSONS shows a TELEMETRY HEALTH warning - a gauge is broken" || ok "no telemetry-health warning"
else bad "LESSONS.md missing (consolidate.py never ran)"; fi
grep -qE '"(sim|u[0-9]|t[0-9]|b[0-9]|tf-test|regtest|realtest|bitettest|ctxtest)"' .claude/state/learning/outcomes.jsonl && bad "test-session pollution in the ledger" || ok "no test pollution in the ledger"

echo "== consolidate + tooling =="
python3 scripts/learn/consolidate.py >/dev/null 2>&1 && ok "consolidate.py runs" || bad "consolidate.py errors"
node --check .claude/workflows/hunt-cycle.js 2>/dev/null && ok "hunt-cycle.js parses" || bad "hunt-cycle.js broken"

echo
[ $fail = 0 ] && echo "ALL GREEN - the hunt system's gauges and gates are healthy." || echo "RED - fix the FAIL line(s) above before trusting the numbers."
exit $fail
