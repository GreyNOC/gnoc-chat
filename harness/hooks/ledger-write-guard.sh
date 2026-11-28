#!/usr/bin/env bash
#
# ledger-write-guard.sh - PreToolUse hook for Write|Edit|Bash.
#
# The hunt ledgers are APPEND-ONLY THROUGH ONE VALIDATOR. HARNESS.md section 3e:
# "Direct writes to either JSONL ledger are forbidden." scripts/hunt-state.py is the
# only sanctioned writer: it enforces the verdict enum, the required fields, and the
# SPINE 4 DEAD floor (>=8 probes, >=30 min, AND a concurrent burst or a written
# not_single_use reason).
#
# That validator existed but was ADVISORY - nothing stopped a direct append, so prose
# verdicts ("3x lead + 1 dead", "blocked", "held") reached outcomes.jsonl and counted
# as 'other' forever, and 425 DEAD rows landed with no burst. This hook makes the
# validator mandatory by blocking every write path that goes around it.
#
# READS ARE ALWAYS ALLOWED - cat/grep/wc/jq on a ledger are normal and untouched.
# Only a write to a ledger is denied, with the correct command in the reason.

set -u

PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null)

# the protected ledgers, by basename (path-independent: a relative or absolute path both match)
LEDGERS='(outcomes|ships)\.jsonl'

deny() {
  jq -nc --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

REASON_W="Direct writes to the hunt ledgers are forbidden (HARNESS.md 3e). They are append-only through the ONE validator that enforces the verdict enum and the SPINE 4 DEAD floor (>=8 probes, >=30 min, and a burst or a written not_single_use reason). A direct write bypasses all of it. Use:  echo '<json>' | python3 scripts/hunt-state.py append-outcome   (or append-ship). Reading the ledger is fine."

case "$TOOL" in
  Write|Edit|NotebookEdit)
    FILE=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
    [ -z "$FILE" ] && exit 0
    if printf '%s' "$FILE" | grep -Eq "$LEDGERS$"; then
      deny "$REASON_W"
    fi
    ;;
  Bash)
    CMD=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // empty' 2>/dev/null)
    [ -z "$CMD" ] && exit 0
    # the sanctioned writer is allowed through even though it names the ledger
    printf '%s' "$CMD" | grep -q 'hunt-state\.py' && exit 0

    # A redirect whose TARGET is a ledger: `>> out/outcomes.jsonl`, `> ships.jsonl`.
    # Scoped to the redirect target so `grep x outcomes.jsonl > /tmp/f` stays allowed.
    if printf '%s' "$CMD" | grep -Eq ">>?[[:space:]]*[^|;&<>]*$LEDGERS"; then
      deny "$REASON_W"
    fi
    # tee / sed -i / truncate / mv / cp / dd onto a ledger
    if printf '%s' "$CMD" | grep -Eq "\b(tee([[:space:]]+-a)?|truncate|dd)\b[^|;&]*$LEDGERS"; then
      deny "$REASON_W"
    fi
    if printf '%s' "$CMD" | grep -Eq "\bsed\b[^|;&]*-i[^|;&]*$LEDGERS"; then
      deny "$REASON_W"
    fi
    if printf '%s' "$CMD" | grep -Eq "\b(mv|cp|install)\b[^|;&]*$LEDGERS([[:space:]]|\"|'|$)"; then
      deny "$REASON_W"
    fi
    # an inline interpreter opening a ledger for write/append
    if printf '%s' "$CMD" | grep -Eq "open\([^)]*$LEDGERS[^)]*,[[:space:]]*['\"][aw]" ; then
      deny "$REASON_W"
    fi
    ;;
esac

exit 0
