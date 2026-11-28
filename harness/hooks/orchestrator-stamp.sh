#!/usr/bin/env bash
# orchestrator-stamp.sh - UserPromptSubmit hook. The fix for the stale-stamp bug that let the
# orchestrator fail-open into bulk probing (the 138KB-WebFetch byte-burn).
#
# The orchestrator (main loop) is the ONLY session that receives HUMAN prompts; worker sub-agents
# are invoked programmatically via the Task tool and never fire UserPromptSubmit. So stamping the
# main-session identity HERE, every user turn, keeps it FRESH and CORRECT - unlike the old
# SessionStart stamp that churned stale across /clear + compact (dozens of SessionStarts overwrote
# each other; the live orchestrator stopped matching MAIN_SID and was mis-tagged WORKER -> fail-open).
# Records session_id AND transcript_path; transcript_path is the strongest main-vs-worker
# discriminator (each sub-agent runs on its own agent-*.jsonl transcript). Fail-open, never blocks.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

SID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null)
TP=$(echo "$INPUT"  | jq -r '.transcript_path // empty' 2>/dev/null)
STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state"
mkdir -p "$STATE_DIR" 2>/dev/null || exit 0

# Stamp PER-SESSION (keyed by sid) so N parallel main loops no longer clobber one global stamp -
# each orchestrator identifies itself independently. Keep the legacy global file as a fallback.
if [ -n "$SID" ]; then
  SAFE_SID=$(echo "$SID" | tr -c 'A-Za-z0-9' '_')
  STAMP=$(printf 'session_id=%s\ntranscript_path=%s\nsource=userprompt\nstamped=%s' \
    "$SID" "$TP" "$(date +%H:%M:%S)")
  printf '%s\n' "$STAMP" > "$STATE_DIR/orchestrator-session.$SAFE_SID" 2>/dev/null
  printf '%s\n' "$STAMP" > "$STATE_DIR/orchestrator-session" 2>/dev/null
fi
exit 0
