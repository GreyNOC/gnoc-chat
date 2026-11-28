#!/usr/bin/env bash
# learning-inject.sh - UserPromptSubmit hook. Feeds the dynamic LESSONS.md
# (self-learning digest: recent worker outcomes + freshest H1 triager kill tags,
# produced by scripts/learn/consolidate.py) back into hunt prompts so every agent
# re-primes on what keeps dying. Fail-open, cwd-gated, hunt-gated to spare meta chats.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

# Skip empty/no-op turns and clearly meta/admin prompts EVEN under a LOCK, so the ~6KB LESSONS
# block is not injected on git/ls/cost/hook-review chatter every single turn (a per-turn token tax
# + cache invalidation that bit under a long-lived LOCK).
[ -z "$PROMPT" ] && exit 0
echo "$PROMPT" | grep -qiE 'how much|token usage|token cost|^ *(git|ls|cat|rm|mv|cp|mkdir|chmod|grep|find|sed|awk)\b|\b(git )?status\b|\bcommit\b|\bpush\b|\bhooks?\b|settings\.json|\baudit\b|review (the|all|this) (hook|agent|workspace|report|draft|code|file)|fix (the|this)' && exit 0

LESSONS="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/learning/LESSONS.md"
[ -f "$LESSONS" ] || exit 0

# Only inject on a hunt-ish prompt, or whenever a program is LOCKed (skip pure meta chats).
# per-session LOCK (2026-07-19): resolve THIS session's lock (LOCK.<session_id>) so a parallel
# session's pin does not force-inject here; degrades to the global LOCK for a lone session.
. "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/hunt-loop/lock-lib.sh" 2>/dev/null || true
_SID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")
if command -v hl_lock_file >/dev/null 2>&1; then LOCK="$(hl_lock_file "$_SID")"; else LOCK="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/LOCK"; fi
if [ ! -s "$LOCK" ]; then
  # short ambiguous tokens (scope/idor/ssrf/xss/bola/rce/race) are word-anchored so a substring
  # (rce in "source", race in "trace", scope in "microscope") no longer force-injects the ~6KB
  # LESSONS block on benign prose; long distinctive tokens stay bare so "hunting"/"targets" match.
  echo "$PROMPT" | grep -qiE 'hunt|target|probe|recon|(^|[^a-z])(scope|idor|ssrf|xss|bola|rce|race)([^a-z]|$)|oauth|unauth|graphql|takeover|program|platform|hackerone|bugcrowd|intigriti|yeswehack|immunefi|huntr|dale|sigue|a-muerte' || exit 0
fi

BODY=$(head -n 120 "$LESSONS" 2>/dev/null)
[ -z "$BODY" ] && exit 0

jq -nc --arg c "[SELF-LEARNING FEEDBACK - what our own past hunts and H1 triagers keep telling us; steer by it]
$BODY" '{hookSpecificOutput:{hookEventName:"UserPromptSubmit", additionalContext:$c}}'
exit 0
