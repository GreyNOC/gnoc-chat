#!/usr/bin/env bash
#
# runtime-complete-gate.sh - Stop hook (post-turn).
#
# Enforces the verify-everything floor (CLAUDE.md): never claim "I confirmed"
# / COMPLETE / ready-to-submit without having actually run the reproduction
# command in-session. 77% of source-only findings die at runtime (S9); this
# gate refuses a closing turn that asserts confirmation but shows no executed
# reproduction command (curl_cffi / aafetch / docker run / Burp send_http)
# carrying a non-empty tool_result in the same transcript.
#
# Output contract (Stop hook): to advise the model to continue, print a JSON
# object {"decision":"block","reason":"..."} on stdout and exit 0. The Claude
# Code wrapper feeds `reason` back to the model. We NEVER exit non-zero and
# NEVER block on internal failure (a broken Stop hook would wedge the session).
#
# Gate scope: only when cwd is under ${GNOC_WORKSPACE:-$HOME/.gnoc}. Otherwise the
# hook is a no-op (exit 0 silent).

set -u  # no -e / no pipefail: any internal failure must fall through to a
        # silent exit 0.

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null) || exit 0
case "$CWD" in
  ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;;
  *) exit 0 ;;
esac

# Already inside a Stop re-prompt cycle: do not stack another block (loop guard).
STOP_HOOK_ACTIVE=$(printf '%s' "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null || echo "false")
[ "$STOP_HOOK_ACTIVE" = "true" ] && exit 0

TRANSCRIPT=$(printf '%s' "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null) || exit 0
[ -z "$TRANSCRIPT" ] && exit 0
[ -f "$TRANSCRIPT" ] || exit 0

# --- Pull last assistant text turn -----------------------------------------
LAST=$(tac "$TRANSCRIPT" 2>/dev/null | \
       jq -cr 'select(.type == "assistant") | (.message.content // [])[]? | select(.type == "text") | .text' 2>/dev/null | \
       head -1)
[ -z "$LAST" ] && exit 0

# Does the closing turn assert confirmation / submission readiness?
CLAIM_RE='COMPLETE|ready to submit|/pre-submit|SUBMITTED|I confirmed|finding ready'
if ! printf '%s' "$LAST" | grep -qE "$CLAIM_RE" 2>/dev/null; then
  exit 0
fi

# --- Scan transcript for an executed reproduction command ------------------
# A qualifying repro = a tool_use (Bash or any mcp__burp* tool) whose input
# text contains curl_cffi|aafetch|docker run|send_http AND that has a matching
# non-empty tool_result (linked by tool_use_id) somewhere in the transcript.
#
# We do this in one jq pass over the whole JSONL:
#   1. Collect ids of qualifying tool_use blocks.
#   2. Collect ids of tool_result blocks whose content (string or array) is
#      non-empty.
#   3. If the intersection is non-empty -> repro present.
# Match INVOCATIONS, not bare words: "grep curl notes.txt" / "cat docker-compose.yml" must
# NOT count as a repro. A verb is followed by a flag, a URL, or a path -> a real run.
REPRO_RE='curl\s+(-|http|"|[a-z0-9._-]+/)|curl_cffi|aafetch|docker\s+(run|compose|exec)|nuclei\s+-|httpx\s+-|sqlmap\s+-|ffuf\s+-|feroxbuster\s|websocat\s|playwright|puppeteer|frida\s+-|wscat\s+-|grpcurl\s|requests\.(get|post|put|delete|patch|request)|urllib|http\.client|python[0-9]?\s+\S+\.py'

REPRO_PRESENT=$(jq -rs --arg re "$REPRO_RE" '
  # qualifying tool_use ids
  ( [ .[]
      | select(.type=="assistant")
      | (.message.content // [])[]?
      | select(.type=="tool_use")
      | { id: .id, name: .name, blob: (.input | tostring) }
      # repro = ANY send_http* MCP tool (sending the request IS the repro; matches both the
      # burp and caveman-shrink mirrors), OR a Bash command that INVOKES a repro tool.
      | select( (.name | test("send_http")) or ((.name=="Bash") and (.blob | test($re))) )
      | .id
    ] ) as $uses
  |
  # tool_result ids with non-empty content
  ( [ .[]
      | select(.type=="user")
      | (.message.content // [])
      | if type=="array" then .[]? else empty end
      | select(.type=="tool_result")
      | { id: .tool_use_id,
          txt: ( .content
                 | if type=="array" then (map(.text? // (. | tostring)) | join(""))
                   elif type=="string" then .
                   else "" end ) }
      | select((.txt | gsub("\\s";"") | length) > 0)
      | .id
    ] ) as $results
  |
  ( $uses - ($uses - $results) ) as $matched
  |
  if ($matched | length) > 0 then "yes" else "no" end
' "$TRANSCRIPT" 2>/dev/null)

# jq failure -> empty -> treat as fail-open (do not block).
[ -z "$REPRO_PRESENT" ] && exit 0

if [ "$REPRO_PRESENT" = "no" ]; then
  jq -nc '{decision:"block", reason:"COMPLETE/submit rejected: no executed reproduction command in-session. Run the exact request and diff response byte-for-byte before claiming confirmed."}' 2>/dev/null
  exit 0
fi

exit 0
