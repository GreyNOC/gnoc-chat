#!/usr/bin/env bash
# session-stamp.sh - SessionStart hook.
#
# Records the ORCHESTRATOR (main-loop) session identity to disk so the partition hook
# can tell the main loop apart from worker sub-agents at PreToolUse time. Also appends
# every SessionStart to a debug log so we can confirm whether SessionStart even fires
# for sub-agents (it should not, but we verify rather than assume). Fail-open, never blocks.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

SID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null)
TP=$(echo "$INPUT"  | jq -r '.transcript_path // empty' 2>/dev/null)
SRC=$(echo "$INPUT" | jq -r '.source // empty' 2>/dev/null)
STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state"
mkdir -p "$STATE_DIR" 2>/dev/null || exit 0

# Stamp main-session identity on a real session lifecycle event (startup/resume/clear/compact).
case "$SRC" in
  startup|resume|clear|compact|"")
    printf 'session_id=%s\ntranscript_path=%s\nsource=%s\nstamped=%s\n' \
      "$SID" "$TP" "$SRC" "$(date +%H:%M:%S)" > "$STATE_DIR/orchestrator-session" 2>/dev/null
    ;;
esac
DBGLOG="$STATE_DIR/orchestrator-partition.debug.log"
printf '%s\tSESSIONSTART\tsrc=%s\tsid=%s\ttp=%s\n' "$(date +%H:%M:%S)" "$SRC" "$SID" "$TP" \
  >> "$DBGLOG" 2>/dev/null
# cap growth: keep the last 500 lines (was unbounded, had reached 343KB).
if [ -f "$DBGLOG" ] && [ "$(wc -l < "$DBGLOG" 2>/dev/null || echo 0)" -gt 800 ]; then
  tail -n 500 "$DBGLOG" > "$DBGLOG.tmp" 2>/dev/null && mv "$DBGLOG.tmp" "$DBGLOG" 2>/dev/null
fi
exit 0
