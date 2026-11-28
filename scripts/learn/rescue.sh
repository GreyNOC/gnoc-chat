#!/usr/bin/env bash
# rescue.sh [program|all] - resurfaces DEAD findings that are RESCUABLE. Many of our killed/held
# drafts died for LACK OF DEPTH (a primitive with no captured terminal, a missing second-account
# or paired-write or concurrent-burst, an untried variant) - NOT because a triager rejected them.
# Those are salvageable with a bit more time or by searching SIMILAR things (sibling host, adjacent
# class, staging twin), but they get abandoned instead. This lists them with a concrete rescue plan.
#
# It distinguishes RESCUABLE (internal, depth-kill) from PERMANENTLY DEAD (triager/structural:
# by-design / duplicate / OOS / risk-accepted) and only surfaces the rescuable ones. Read-only.
# Primary source: reports/drafts/ markers. Secondary: .claude/state/learning/rescue-queue.jsonl
# (workflow-captured kills, with attempt tracking so a finding retired after 3 tries).
set -u
# 2026-10-21: one classifier, not two. The ledger (pipeline-sweep) is the truth; the body below is kept as
# dead reference text so the regex origin stays visible (SPEC-pipeline-sweep-20261021.md change 2).
exec /usr/bin/python3 ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/learn/pipeline-sweep.py list "${1:-all}"
ROOT=${GNOC_WORKSPACE:-$HOME/.gnoc}
PROG="${1:-all}"
Q="$ROOT/.claude/state/learning/rescue-queue.jsonl"

DEADMARK='KILLED|HELD|NOT[- ]SUBMIT|DO-NOT-SUBMIT|KILL-PENDING|DEAD-with|report-killer.*KILL'
RESCUABLE='primitive|no terminal|capability[- ]empty|capability empty|needs? (a )?(2nd|second|third|another) (account|session|token)|one[- ](probe|receipt)[- ]away|\bHELD\b|KILL-PENDING|timid|reachability leg|source leg|SOURCE (leg )?missing|inference|not captured|un-?escalat|missing (the )?(write|read|burst|terminal)|concurrent burst|sink proven'
PERMADEAD='by[- ]design|duplicate|out of scope|\bOOS\b|informative[- ]confirmed|policy[- ]exclud|not (a )?(trust|access[- ]control) boundary|risk[- ]accepted|working as intended|intended behaviou?r|known issue|already (reported|tracked)'

n=0
echo "=== RESCUE QUEUE ($PROG) - dead findings worth another push ==="
echo

if [ -d "$ROOT/reports/drafts" ]; then
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    body=$(head -c 8000 "$f" 2>/dev/null)
    echo "$body" | grep -qiE "$DEADMARK" || continue          # must be dead/killed/held
    echo "$body" | grep -qiE "$PERMADEAD" && continue          # triager/structural -> not rescuable
    echo "$body" | grep -qiE "$RESCUABLE" || continue          # must carry a depth-kill signal
    prog=$(printf '%s' "$f" | sed -n 's#.*/drafts/\([^/]*\)/.*#\1#p'); [ -z "$prog" ] && prog="?"
    [ "$PROG" != all ] && [ "$prog" != "$PROG" ] && continue
    why=$(echo "$body" | grep -oiE "$RESCUABLE" | head -1)
    n=$((n + 1))
    echo "- [$prog] $(basename "$f")"
    echo "    died-for: ${why:-depth}"
    echo "    rescue: (1) MORE TIME - push the leg the kill exposed (the terminal capture / second-account cross-actor / the concurrent burst); (2) SIMILAR - same class on a SIBLING host, the ADJACENT class on this surface, the SAME bug on staging or a sibling brand (variant-cascade L1-L4)."
    echo
  done < <(find "$ROOT/reports/drafts" -name '*.md' 2>/dev/null)
fi

if [ -f "$Q" ] && command -v jq >/dev/null 2>&1; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    p=$(printf '%s' "$line" | jq -r '.program // "?"' 2>/dev/null)
    [ "$PROG" != all ] && [ "$p" != "$PROG" ] && continue
    at=$(printf '%s' "$line" | jq -r '.attempts // 0' 2>/dev/null); at=${at%%.*}
    [ "${at:-0}" -ge 3 ] 2>/dev/null && continue               # tried 3x -> retire
    fnd=$(printf '%s' "$line" | jq -r '.finding // "?"' 2>/dev/null)
    rp=$(printf '%s' "$line" | jq -r '(.rescuePath // ["push the missing leg","similar-search"])|join("; ")' 2>/dev/null)
    n=$((n + 1))
    echo "- [$p] $fnd  (attempts=${at:-0})"
    echo "    rescue: $rp"
    echo
  done < "$Q"
fi

echo "=== $n rescuable finding(s). Re-attack the top ones: they died for lack of depth, not a triager verdict. ==="
[ "$n" = 0 ] && echo "(none rescuable - either no dead findings, or every remaining death is triager/structural by-design/duplicate/OOS)"
exit 0
