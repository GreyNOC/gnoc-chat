#!/usr/bin/env bash
# orchestrator-byte-guard.sh - PreToolUse hook (Read | Bash).
#
# GOAL: keep the ORCHESTRATOR (main loop) THIN. An ADVISORY nudge - NEVER a block - when the main
# session is about to pull byte-heavy local content into its OWN context instead of delegating to a
# worker sub-agent (SPINE section 7 ORCHESTRATOR DISCIPLINE). It complements orchestrator-partition.sh
# (which HARD-BLOCKS the main loop's NETWORK probing); this one covers LOCAL byte-eaters: a full-file
# cat, an unbounded grep -r, an ls -R, a 200-file ls dump, a full-file Read of a large / byte-heavy
# file (JS bundle, .log, .jsonl, decompiled source, recon artifact).
#
# WHY ADVISORY, NEVER BLOCK: SPINE explicitly allows a THIN EXCEPTION - a single cheap confirmation
# or the final PoC edit. A hard block would wedge that legitimate move. So this is fail-open (exit 0)
# and merely nudges "delegate this, stay thin". Under-firing is far better than nagging a worker's
# legitimate Read/cat, so anything uncertain -> no nudge.
#
# MAIN-vs-WORKER DISCRIMINATOR (identical to orchestrator-partition.sh - reuse the proven marker):
#   The main loop is the ONLY session that receives HUMAN prompts, so orchestrator-stamp.sh
#   (UserPromptSubmit) stamps its identity fresh every turn to
#   .claude/state/orchestrator-session.<sid> (session_id + transcript_path). A worker sub-agent is
#   invoked via the Task tool, never fires UserPromptSubmit, and runs on its OWN agent-*.jsonl
#   transcript_path - so its transcript NEVER matches the stamped orchestrator transcript => ROLE
#   stays WORKER => this hook exits 0 with no nudge. Missing stamp (NOSTAMP) or any parse gap also
#   fail-open. Net effect: ONLY the orchestrator whose live transcript matches its own fresh stamp
#   is ever nudged; every worker eats its bytes in peace.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

SID=$(echo "$INPUT"  | jq -r '.session_id // empty' 2>/dev/null)
TP=$(echo "$INPUT"   | jq -r '.transcript_path // empty' 2>/dev/null)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state"

# --- ROLE (fail-open to WORKER on any doubt) ---------------------------------------------------
SAFE_SID=$(echo "$SID" | tr -c 'A-Za-z0-9' '_')
STAMP_FILE="$STATE_DIR/orchestrator-session.$SAFE_SID"
[ -f "$STAMP_FILE" ] || STAMP_FILE="$STATE_DIR/orchestrator-session"
MAIN_SID=$(grep -oE '^session_id=.*'      "$STAMP_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
MAIN_TP=$(grep -oE  '^transcript_path=.*' "$STAMP_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
ROLE="WORKER"
# POSITIVE WORKER DISCRIMINATOR (fix 2026-10-02, GreyNOC session): a sub-agent's hook payload
# carries agent_id / agent_type keys; the orchestrator's payload does NOT. Sub-agents inherit the
# parent's session_id AND transcript_path, so the stamp comparison below matched for workers too
# and tagged 100% of traffic as MAIN (981/981 debug rows, zero WORKER). Effect: every worker in the
# fleet was hard-blocked from WebFetch/WebSearch and capped at 3 bash probes, which is a direct
# cause of thin probe counts and early quits. Check the agent keys FIRST so workers fail-open.
AGENT_ID=$(echo "$INPUT" | jq -r '.agent_id // empty' 2>/dev/null)
AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // empty' 2>/dev/null)
if [ -n "$AGENT_ID" ] || [ -n "$AGENT_TYPE" ]; then
  ROLE="WORKER"
elif [ -z "$MAIN_SID" ] && [ -z "$MAIN_TP" ]; then
  ROLE="NOSTAMP"
elif [ -n "$MAIN_TP" ] && [ "$TP" = "$MAIN_TP" ]; then
  ROLE="MAIN"
elif [ -z "$MAIN_TP" ] && [ -n "$SID" ] && [ "$SID" = "$MAIN_SID" ]; then
  ROLE="MAIN"
fi
# ONLY the orchestrator is nudged. Worker / no-stamp / parse-gap -> fail-open (bytes are their job).
[ "$ROLE" = "MAIN" ] || exit 0

# --- BYTE-HEAVY HEURISTIC (tight + high-precision) ---------------------------------------------
BIG_LINES=500      # a full-file Read past this many lines is byte-heavy
BIG_BYTES=51200    # ...or past ~50KB
THING=""           # set = fire; names the byte-eater for the nudge

if [ "$TOOL" = "Read" ]; then
  FP=$(echo "$INPUT"  | jq -r '.tool_input.file_path // empty' 2>/dev/null)
  LIM=$(echo "$INPUT" | jq -r '.tool_input.limit // empty'     2>/dev/null)
  # A Read WITH a limit is already thin -> never fire.
  if [ -z "$LIM" ] && [ -n "$FP" ]; then
    # Byte-heavy by PATH TYPE (content is raw bytes regardless of size): logs, jsonl, JS/map
    # bundles, decompiled source, or a target recon/hunt artifact.
    if echo "$FP" | grep -qiE '\.(log|jsonl|ndjson|min\.js|js\.map|har)$|\.(js|ts)$|(^|/)(decompiled|smali|sources|jadx)/|/targets/[^/]+/(recon|hunts|evidence|poc)/'; then
      THING="the file $FP (byte-heavy content type)"
    else
      # Otherwise fire only if the concrete file is large. stat: a small state file never fires.
      if [ -f "$FP" ]; then
        SZ=$(stat -c %s "$FP" 2>/dev/null || echo 0); case "$SZ" in ''|*[!0-9]*) SZ=0 ;; esac
        LN=$(wc -l < "$FP" 2>/dev/null || echo 0);    case "$LN" in ''|*[!0-9]*) LN=0 ;; esac
        if [ "$SZ" -gt "$BIG_BYTES" ] || [ "$LN" -gt "$BIG_LINES" ]; then
          THING="the file $FP (~${LN} lines / ${SZ}B - read it with a limit or delegate)"
        fi
      fi
    fi
  fi

elif [ "$TOOL" = "Bash" ]; then
  CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
  # A size limiter anywhere in the command means the operator already bounded the output -> skip.
  # (head/tail/wc/-c/-l/-c-count/-maxdepth-with-wc etc.) Keep this generous: err toward NOT firing.
  PIPED_SAFE=0
  echo "$CMD" | grep -qE '\|[[:space:]]*(head|tail|wc|jq|cut|awk[^|]*(NR|print \$)|sed -n)' && PIPED_SAFE=1
  if [ "$PIPED_SAFE" = 0 ]; then
    # cat / tac / nl / less / more of a file (not `| head`ed) -> full dump.
    if echo "$CMD" | grep -qE '(^|[;&|`]|&&|\|\|)[[:space:]]*(cat|tac|nl|less|more|bat)[[:space:]]+[^|]*[^ ]'; then
      THING="a full-file dump ($(echo "$CMD" | head -c 80))"
    # grep -r / -R / --recursive WITHOUT -l / -c / --count (those return only names/counts) -> body dump.
    elif echo "$CMD" | grep -qE '(^|[;&|`]|&&|\|\|)[[:space:]]*(grep|rg|egrep|fgrep)[[:space:]]' \
         && echo "$CMD" | grep -qE '(-[A-Za-z]*[rR]|--recursive|--include|--dereference-recursive)' \
         && ! echo "$CMD" | grep -qE '(-[A-Za-z]*[lc]|--count|--files-with-matches|--files-without-match)'; then
      THING="an unbounded recursive grep ($(echo "$CMD" | head -c 80))"
    # ls -R  OR  find ... (not -delete, no `| wc`/`head`) -> a big listing dumped into context.
    elif echo "$CMD" | grep -qE '(^|[;&|`]|&&|\|\|)[[:space:]]*ls[[:space:]]([^|]*-[A-Za-z]*R)'; then
      THING="a recursive ls ($(echo "$CMD" | head -c 80))"
    elif echo "$CMD" | grep -qE '(^|[;&|`]|&&|\|\|)[[:space:]]*find[[:space:]]' \
         && ! echo "$CMD" | grep -qE '(-delete|-exec[[:space:]]+rm)'; then
      THING="a find listing ($(echo "$CMD" | head -c 80))"
    fi
  fi
fi

[ -z "$THING" ] && exit 0   # not a byte-eater -> silent pass

# --- RATE-LIMIT the nudge (session-keyed counter, mirrors the other hooks) ----------------------
# One nudge per N qualifying fires per session, so we inform without nagging.
NUDGE_EVERY=4
CNT_FILE="$STATE_DIR/.byte-guard-count.$SAFE_SID"
cnt=$(cat "$CNT_FILE" 2>/dev/null || echo 0); case "$cnt" in ''|*[!0-9]*) cnt=0 ;; esac
cnt=$((cnt + 1)); echo "$cnt" > "$CNT_FILE" 2>/dev/null || true
# Nudge on the 1st fire and every Nth after (1, 5, 9, ...); stay silent (but still exit 0) between.
if [ "$cnt" -ne 1 ] && [ $(( (cnt - 1) % NUDGE_EVERY )) -ne 0 ]; then exit 0; fi

MSG="ORCHESTRATOR THIN-CONTEXT: you are about to pull byte-heavy ${THING} into your OWN context. Delegate to a worker (Explore / log-eater / recon-scout / the class-hunter) and read its DIGEST. Thin-exception only: a single cheap confirmation or the final PoC edit."
jq -nc --arg c "$MSG" '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$c}}' 2>/dev/null
exit 0
