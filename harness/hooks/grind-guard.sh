#!/usr/bin/env bash
# grind-guard.sh - SessionStart hook. Advisory only (never blocks). Two steers:
#   - OVER-GRIND: counts sessions locked on the current target; past a cap, flags that
#     re-sweeping a ceiling'd target with no ship is low-EV.
#   - STALE-DEAD (the massive lesson): a past 'dead' is a hypothesis, not a fact -
#     deleting massive's dead-memory and re-hunting FRESH paid 2 criticals the agents
#     had called dead. So when a locked target looks exhausted, the HIGH-EV move is a
#     clean-context re-hunt (scripts/learn/fresh-rehunt.sh <handle>), not skipping it.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

ROOT=${GNOC_WORKSPACE:-$HOME/.gnoc}
LOCKF="$ROOT/.claude/state/hunt-loop/LOCK"
LDIR="$ROOT/.claude/state/learning"; mkdir -p "$LDIR" 2>/dev/null
# Prefer THIS session's own target (HUNT_TARGET, exported per-process by the fleet
# launcher); fall back to the legacy global LOCK for a plain single session.
HANDLE="$(printf '%s' "${HUNT_TARGET:-}" | tr -dc 'a-zA-Z0-9_-')"
# per-session LOCK (LOCK.<session_id>) then the legacy global LOCK (2026-07-19).
if [ -z "$HANDLE" ]; then
  . "$ROOT/scripts/hunt-loop/lock-lib.sh" 2>/dev/null || true
  _SID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")
  command -v hl_lock_file >/dev/null 2>&1 && LOCKF="$(hl_lock_file "$_SID")"
  [ -s "$LOCKF" ] && HANDLE=$(head -c 64 "$LOCKF" 2>/dev/null | tr -dc 'a-zA-Z0-9_-')
fi
[ -z "$HANDLE" ] && exit 0

CF="$LDIR/grind-${HANDLE}.count"
CUR=$(cat "$CF" 2>/dev/null || echo 0); case $CUR in ''|*[!0-9]*) CUR=0;; esac; NEW=$((CUR + 1)); echo "$NEW" > "$CF" 2>/dev/null
[ "$NEW" -lt 8 ] && exit 0

# DATA-BACKED (2026-07-16): consult the ships.jsonl north-star. A PROVEN shipper is not a sunk cost;
# only many sessions with ZERO shipped receipts is the measured 28%-waste never-shipper pattern.
SHIPS_F="$ROOT/.claude/state/hunt-loop/ships.jsonl"
SHIPN=0
[ -f "$SHIPS_F" ] && SHIPN=$(grep -cE "\"program\": ?\"$HANDLE\"" "$SHIPS_F" 2>/dev/null)
SHIPN=$(( ${SHIPN:-0} + 0 ))

if [ "$SHIPN" -eq 0 ]; then
  MSG="GRIND + STALE-DEAD CHECK: ~session $NEW on $HANDLE with 0 shipped receipts (ships.jsonl). Measured: 28% of all past effort went to targets that NEVER shipped - this is that pattern. Two high-EV moves, in order: (1) a past 'dead' is a HYPOTHESIS not a fact - on massive a clean-context re-hunt of a 'dead' target paid 2 CRITICALS agents had skipped; run scripts/learn/fresh-rehunt.sh $HANDLE and re-derive every old dead verdict on FRESH ground (new subdomain/surface/actor), do NOT trust the dead index. (2) if the reachable free-venue surface is genuinely exhausted, surface the frontier to GreyNOC and (rotate mode only) advance to a win-shaped target: live, free-venue, unauth-reachable web/API with fresh scope and a mined seed - 88% of our ships are UNAUTH in IDOR/BOLA/disclosure/BFLA."
else
  MSG="GRIND NOTE: ~session $NEW on $HANDLE, a PROVEN shipper ($SHIPN receipt(s) in ships.jsonl) - NOT a sunk cost. Keep hunting it, but on FRESH ground: a new subdomain/surface/actor/flow, or a clean-context re-hunt of a stale 'dead' (scripts/learn/fresh-rehunt.sh $HANDLE - a past dead paid 2 massive criticals). Do not re-sweep an already-covered surface; DRAFTED findings are off the board."
fi
jq -nc --arg c "$MSG" '{hookSpecificOutput:{hookEventName:"SessionStart", additionalContext:$c}}' 2>/dev/null
exit 0
