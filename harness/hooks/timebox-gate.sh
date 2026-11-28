#!/usr/bin/env bash
# timebox-gate.sh - Stop hook.
#
# Structural clock (part 2 of 2). Reads the deadline pinned by timebox-set.sh
# (state/hunt-loop/until, epoch). While now < deadline, BLOCKS the stop and tells the
# agent to keep working - the time-box is enforced by the harness, not by the model
# remembering it. This is the fix for "asked for 90 min, quit at 30".
#
# A legitimate stop is never trapped: a shipped draft, GreyNOC's explicit stop (STOP
# file), or the deadline reached all release it. Fail-open everywhere. Capped per
# session so it can never wedge into an infinite block loop.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

STOP_HOOK_ACTIVE=$(printf '%s' "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null || echo "false")
[ "$STOP_HOOK_ACTIVE" = "true" ] && exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
TRANSCRIPT=$(echo "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null || echo "")
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop"
UNTIL="$STATE_DIR/until"
[ -f "$UNTIL" ] || exit 0            # no timebox set -> allow stop
DEADLINE=$(grep -oE '^[0-9]+' "$UNTIL" 2>/dev/null | head -1)
[ -n "$DEADLINE" ] || exit 0
NOW=$(date +%s)

# Deadline reached -> clear and allow the stop.
if [ "$NOW" -ge "$DEADLINE" ]; then
  rm -f "$UNTIL" 2>/dev/null
  exit 0
fi

# GreyNOC's explicit graceful stop -> allow (and clear the timebox).
[ -f "$STATE_DIR/STOP" ] && { rm -f "$UNTIL" 2>/dev/null; exit 0; }

# Exempt a genuine shipped draft (a legitimate stop before the deadline).
if [ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ]; then
  LAST=$(tac "$TRANSCRIPT" 2>/dev/null | jq -c 'select(.type=="assistant")' 2>/dev/null | head -1 | \
         jq -r '.message.content[]? | select(.type=="text") | .text' 2>/dev/null)
  echo "$LAST" | grep -qiE 'report (saved|drafted|written|submitted)|reports/(drafts|submitted)/' && exit 0
fi

# Cap blocks per session, then allow (safety valve against an infinite loop).
CF="$STATE_DIR/.timebox-block-${SESSION_ID}.count"
CUR=$(cat "$CF" 2>/dev/null || echo 0); case $CUR in ''|*[!0-9]*) CUR=0;; esac; NEW=$((CUR + 1)); echo "$NEW" > "$CF"
# GC old per-session block counters (were accumulating unbounded, 53+ dead-session files); keep 24h.
find "$STATE_DIR" -maxdepth 1 -name '.timebox-block-*.count' -mmin +1440 -delete 2>/dev/null
[ "$NEW" -gt 40 ] && exit 0

REMAIN=$(( (DEADLINE - NOW + 59) / 60 ))
HUMAN=$(date -d "@$DEADLINE" '+%H:%M' 2>/dev/null || echo "?")
REASON="TIME-BOX ACTIVE: ~${REMAIN} min remain until ${HUMAN}. GreyNOC set a working-window and reaching it is the only clean stop (a shipped draft or an explicit stop also release it). Do NOT stop now. Continue: go deeper on a live lead, escalate a held primitive, enumerate another surface, or model another asset. Re-check the clock between phases."
jq -nc --arg r "$REASON" '{decision:"block", reason:$r}'
exit 0
