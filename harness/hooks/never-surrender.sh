#!/usr/bin/env bash
# never-surrender.sh - Stop hook.
#
# The #1 workspace failure is the premature quit. The hunt ends on exactly two
# conditions: a finding ships, or GreyNOC says stop. This hook BLOCKS a premature
# surrender during an ACTIVE hunt (real probe tools fired this session) when the
# dead-claim carries no receipt, and pushes a productive pivot to a NEW surface or
# subdomain. Empirical: most paid wins followed at least one premature "this is dead".
#
# Fail-open everywhere. Only blocks when real probing happened (never nags a
# planning/building session). Receipt-backed dead claims and shipped findings are
# exempt. Capped per session to avoid an infinite block loop.
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
[ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ] || exit 0

# Last assistant text turn.
LAST=$(tac "$TRANSCRIPT" 2>/dev/null | jq -c 'select(.type=="assistant")' 2>/dev/null | head -1 | \
       jq -r '.message.content[]? | select(.type=="text") | .text' 2>/dev/null)
[ -z "$LAST" ] && exit 0

# BLOCK only during an ACTIVE hunt: real probe tools fired recently. A turn that
# only TALKS about hunting (planning, building, this rebuild) never blocks.
RECENT_TOOLS=$(tac "$TRANSCRIPT" 2>/dev/null | \
  jq -cr 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | "\(.name) \(.input|tostring)"' 2>/dev/null | \
  head -c 200000)   # whole-transcript scan (was 'head -12': missed early probes when the recent tool-uses were Read/Grep/Edit, letting a receiptless quit escape - 2026-07-07 audit)
echo "$RECENT_TOOLS" | grep -qiE 'mcp__[a-z0-9_-]*(send_http|burp)|"command":"[^"]{0,120}(curl|nuclei|ffuf|wfuzz|httpx|katana|subfinder|gau|sqlmap|ghauri|websocat|wscat|nikto|amass|dalfox|frida|curl_cffi)' || exit 0

# Exempt a shipped finding (legitimate stop).
echo "$LAST" | grep -qiE 'report (saved|submitted|written|drafted)|submitted to (h1|hackerone|bugcrowd|intigriti|huntr|yeswehack|immunefi)|(wrote|written|saved|drafted|created|shipped|surfaced)[^.]{0,25}reports/(drafts|submitted)/[^ ]+\.md' && exit 0

# Exempt a receipt-backed dead claim (variants tried + sibling subdomains pivoted).
# Concrete receipts only. Bare intent phrases ("pivoted to", "do-not-rehunt", "coverage
# matrix") were removed: they are this gate's own trigger vocabulary, so they let a
# receiptless quit exempt itself. A real receipt carries a COUNT or an enumerated sibling.
RECEIPT='variants?=?[0-9]+/?[0-9]*|[0-9]+ ?(variant|bypass|sibling|subdomain|endpoint|payload|probe|actor|surface)|positive[- ]control|negative[- ]control|concurrent burst|burst=?[0-9]+|[0-9]+ (tried|tested|fired|enumerated|swept)'
echo "$LAST" | grep -qiE "$RECEIPT" && exit 0

# Surrender words (EN + ES).
PATTERN='no findings|nothing more|nothing else|nothing left|exhausted|looks dry|ran out|tried everything|let me move on|move to a different target|target is dead|vector is dead|surface is dead|fully hardened|dead end|no surface|nothing actionable|give up|sin hallazgos|nada m[aá]s|agotado|target muerto|vector muerto|callej[oó]n sin salida|me rindo|abandonemos|no hay nada'
echo "$LAST" | grep -qiE "$PATTERN" || exit 0

# Cap blocks per session to avoid an infinite loop, then allow.
STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/never-surrender"
mkdir -p "$STATE_DIR" 2>/dev/null || exit 0
CF="$STATE_DIR/session-${SESSION_ID}.count"
CUR=$(cat "$CF" 2>/dev/null || echo 0); case $CUR in ''|*[!0-9]*) CUR=0;; esac; NEW=$((CUR + 1)); echo "$NEW" > "$CF"
[ "$NEW" -gt 6 ] && exit 0

REASON="NEVER SURRENDER. The hunt ends only on a shipped finding or an explicit stop from GreyNOC, and this turn shows neither. This asset is not dead until you hold a receipt (variants tried plus sibling subdomains enumerated). Pivot NOW, do not stop: (1) enumerate another subdomain or surface (recon-scout), (2) rank the next-highest-EV asset (picker), (3) or go deeper on a live lead (autonomy-deep-dive, creative-pivots, hypothesis-engine). There is always another subdomain. There is always another surface. Continue."

jq -nc --arg r "$REASON" '{decision:"block", reason:$r}'
exit 0
