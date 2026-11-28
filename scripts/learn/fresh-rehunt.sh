#!/usr/bin/env bash
# fresh-rehunt.sh <target> - the safe, repeatable version of "delete the hunt files and
# re-hunt from scratch", which on massive surfaced 2 PAID CRITICALS that the agents had
# called dead. A past 'dead' is a hypothesis, not a fact: stale dead-memory anchors an
# agent to confirm-dead instead of hunting honestly. This ARCHIVES (never deletes) a
# target's dead-memory so the next hunt starts clean, and logs what moved so it is fully
# recoverable. Evidence/PoC artifacts are kept; only the 'dead' CONCLUSIONS are archived.
set -u
ROOT=${GNOC_WORKSPACE:-$HOME/.gnoc}
T="${1:-}"
[ -z "$T" ] && { echo "usage: fresh-rehunt.sh <target-handle>"; exit 1; }
TDIR="$ROOT/targets/$T"
[ -d "$TDIR" ] || { echo "no such target dir: $TDIR" >&2; exit 1; }
STAMP=$(date +%Y%m%d-%H%M%S)
ARC="$TDIR/.dead-archive-$STAMP"
mkdir -p "$ARC" || exit 1
moved=0

# 1. the do-not-rehunt indexes the dedup-gate and agents read
for f in "$TDIR/do-not-rehunt.txt" "$TDIR/do-not-rehunt.md" "$TDIR/hunts/do-not-rehunt.md"; do
  [ -f "$f" ] && mv "$f" "$ARC/" 2>/dev/null && moved=$((moved + 1))
done

# 2. self-authored DEAD verdicts (keep evidence/poc; archive only the dead conclusions)
while IFS= read -r v; do
  [ -f "$v" ] || continue
  grep -qiE 'RECEIPT-DEAD|DEAD-with|dead-with-control|no findings|ceiling|receipt-dead' "$v" 2>/dev/null || continue
  rel=${v#"$TDIR"/}
  mkdir -p "$ARC/$(dirname "$rel")" 2>/dev/null
  mv "$v" "$ARC/$rel" 2>/dev/null && moved=$((moved + 1))
done < <(find "$TDIR" -name 'VERDICT*.md' 2>/dev/null)

echo "$STAMP  archived $moved dead-memory artifacts for $T -> $ARC" | tee -a "$ROOT/.claude/state/learning/fresh-rehunt.log"
echo "Re-hunt $T FRESH now: model it as if new, IGNORE every prior 'dead' claim, run the crown hypotheses first."
echo "Recover anytime with:  mv \"$ARC\"/* back into targets/$T/"
