#!/usr/bin/env bash
# Stop hook - detects cyber-classifier refusals in the assistant's last
# response, logs them to state/refusals.jsonl, and maintains a per-session
# refusal counter. When 3+ refusals accumulate in one session, writes a
# "fallback advisory" flag that SessionStart and statusline can surface.
#
# Triggers on: "violative cyber content", "Usage Policy", "unable to respond",
# "I cannot", "I'm not able", "cyber-verification", specific refusal markers.

set -u  # Removed pipefail/-e: this hook MUST never abort with a non-zero status
        # without printing context (caller surfaces empty errors as noise to
        # the user). Any internal failure -> silent exit 0.

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
TRANSCRIPT=$(echo "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null || echo "")
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")

# Only operate in the bug-bounty workspace
case "$CWD" in
  ${GNOC_WORKSPACE:-$HOME/.gnoc}*)
    ;;
  *)
    exit 0
    ;;
esac

# Silently skip if we don't have required inputs
[[ -z "$TRANSCRIPT" || -z "$SESSION_ID" || ! -f "$TRANSCRIPT" ]] && exit 0

STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/auth-setup"
REFUSALS_LOG="$STATE_DIR/refusals.jsonl"
SESSION_COUNTER="$STATE_DIR/session-${SESSION_ID}.count"
ADVISORY_FLAG="$STATE_DIR/fallback-advisory.flag"

mkdir -p "$STATE_DIR"

# Extract the last assistant turn from the transcript (JSONL, one message per line)
LAST_ASSISTANT=$(
  tac "$TRANSCRIPT" 2>/dev/null | jq -c 'select(.type == "assistant")' 2>/dev/null | head -1 | \
    jq -r '.message.content[]? | select(.type == "text") | .text' 2>/dev/null
)

[[ -z "$LAST_ASSISTANT" ]] && exit 0

# Pattern match (grep -qiE returns 0 on match)
REFUSAL_PATTERN='violative cyber content|Usage Policy|unable to respond to this request|Cyber Verification Program|cyber-use-case|I cannot help with|I am not able to assist|I can'\''t help with that|against our policies|prohibited cybersecurity|high-risk cybersecurity'

if echo "$LAST_ASSISTANT" | grep -qiE "$REFUSAL_PATTERN"; then
  # Log the refusal
  TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  MATCHED=$(echo "$LAST_ASSISTANT" | grep -oiE "$REFUSAL_PATTERN" | head -1 || echo "pattern_match")
  SNIPPET=$(echo "$LAST_ASSISTANT" | head -c 400 | tr '\n' ' ' | jq -Rs .)

  jq -nc \
    --arg ts "$TS" \
    --arg sid "$SESSION_ID" \
    --arg cwd "$CWD" \
    --arg pattern "$MATCHED" \
    --argjson snippet "$SNIPPET" \
    '{timestamp: $ts, session_id: $sid, cwd: $cwd, pattern: $pattern, snippet: $snippet}' \
    >> "$REFUSALS_LOG"

  # Increment per-session counter
  CURRENT=$(cat "$SESSION_COUNTER" 2>/dev/null || echo 0)
  case "$CURRENT" in ''|*[!0-9]*) CURRENT=0 ;; esac   # sanitize: a corrupt counter must not abort under set -u
  NEW=$((CURRENT + 1))
  echo "$NEW" > "$SESSION_COUNTER"

  # If 3+ refusals in this session, raise the advisory flag
  if (( NEW >= 3 )); then
    cat > "$ADVISORY_FLAG" <<EOF
{
  "session_id": "$SESSION_ID",
  "raised_at": "$TS",
  "refusal_count": $NEW,
  "recommendation": "Consider switching to Sonnet: /model sonnet"
}
EOF
  fi
fi

# Stop hook output is optional. Exit 0 = let the session continue normally.
exit 0
