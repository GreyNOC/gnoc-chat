#!/usr/bin/env bash
#
# scope-inject.sh - UserPromptSubmit hook (scope AWARENESS).
#
# Complements scope-gate.sh (PreToolUse hard BLOCK) by injecting the active
# program's in-scope host allowlist into context, so the model always knows
# the allowlist before it picks a probe target.
#
# Active program resolution (first wins):
#   1. cwd under .../targets/<prog>/...  -> <prog>  (sed extract)
#   2. else lowercased prompt scanned for any targets/<dir> name as a WHOLE
#      WORD; first/longest match picked.
#
# Output (additionalContext via jq):
#   - program found + SCOPE.txt exists -> "# ACTIVE SCOPE: <prog>" block with
#     up to ~40 comment-stripped hosts + an mtime/staleness footer.
#   - cwd under targets/<prog>/ but SCOPE.txt MISSING -> one-line warning.
#   - otherwise (no program, parse error, non-hunting prompt) -> SILENT.
#
# Design rule (matches scope-gate.sh): a buggy awareness hook must never halt
# the live session. Every uncertain path exits 0 with no output.

set -u  # no -e / no pipefail: must always exit 0.

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
TARGETS_DIR="$ROOT/targets"
HOST_CAP=40

# --- Shared in-scope extraction (identical logic in scope-gate.sh) ----------
# Print the IN-SCOPE host tokens of a SCOPE.txt: every first-token host on a
# non-comment, non-blank line that appears BEFORE the first genuine OUT-OF-SCOPE
# section divider. A divider is a comment/text line whose stripped text (leading
# '#', whitespace and '='/'-' decoration removed) STARTS with an OOS phrase AND
# does NOT itself name a bare host on the same line (the guard keeps an inline
# note like "# OUT OF SCOPE: vinda.com ..." from nuking the whole file, as in
# targets/essity/SCOPE.txt where the note precedes the in-scope list).
# A SCOPE.txt with no divider yields all host lines (legacy behavior).
# Failure-isolated: any awk error yields empty output and the caller exits 0.
scope_inscope_hosts() {
  awk '
    function strip_decor(s) {
      gsub(/^[[:space:]]*#+[[:space:]]*/, "", s)
      gsub(/^[-=[:space:]]+/, "", s)
      return s
    }
    BEGIN { IGNORECASE = 1 }
    {
      raw = $0
      is_comment = (raw ~ /^[[:space:]]*#/)
      line = strip_decor(raw)
      if (line ~ /^(out.?of.?scope|oos([^a-z0-9]|$)|exclud|ineligib|not[[:space:]]+in[[:space:]]+scope|do[[:space:]]+not[[:space:]]+test|forbidden)/) {
        if (line ~ /[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}/) { next }
        exit
      }
      if (is_comment) next
      if (raw ~ /^[[:space:]]*$/) next
      sub(/[[:space:]]*#.*$/, "", raw)
      sub(/^[[:space:]]+/, "", raw)
      sub(/[[:space:]]+$/, "", raw)
      if (raw == "") next
      n = split(raw, a, /[[:space:]]+/)
      tok = a[1]
      # H1 TABULAR FORMAT (fix 2026-10-02, parity with scope-gate.sh). Platform exports prefix
      # each row with the asset TYPE ("WILDCARD  *.foo.com\t[bounty]"), so printing a[1] showed
      # the keyword and this hook injected "URL" and "APPLE_STORE_APP_ID" to the agent as the
      # list of in-scope HOSTS - a display that disagreed with the gate it is meant to preview.
      if (n > 1 && tok !~ /\./ && tok ~ /^[A-Za-z][A-Za-z0-9_]*$/) {
        atype = toupper(tok)
        tok = a[2]
        sub(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "", tok)
        sub(/\/.*$/, "", tok)
        sub(/^[^@]*@/, "", tok)
        sub(/:[0-9]+$/, "", tok)
        # Non-WILDCARD bare domains are exact-only on HackerOne; keep the "=" so the preview
        # cannot imply a subdomain is in scope when the gate will refuse it.
        if (atype != "WILDCARD" && tok !~ /^\*/) tok = "=" tok
      }
      if (tok != "") print tok
    }
  ' "$1" 2>/dev/null
}

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

# --- Parse stdin JSON (fail-safe) ------------------------------------------
PROMPT=$(printf '%s' "$INPUT" | jq -r '.prompt // empty' 2>/dev/null) || exit 0
CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null) || exit 0
[ -z "$CWD" ] && exit 0

# --- Act ONLY inside the workspace -----------------------------------------
case "$CWD" in
  "$ROOT"|"$ROOT"/*) ;;
  *) exit 0 ;;
esac

# --- Resolve active program ------------------------------------------------
# (1) cwd under .../targets/<prog>/... or .../targets/<prog>
PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)/.*#\1#p' 2>/dev/null)
if [ -z "$PROG" ]; then
  PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)$#\1#p' 2>/dev/null)
fi

CWD_MATCH=0
[ -n "$PROG" ] && CWD_MATCH=1

# (2) else scan the lowercased prompt for a program name as a whole word.
if [ -z "$PROG" ] && [ -n "$PROMPT" ] && [ -d "$TARGETS_DIR" ]; then
  LPROMPT=$(printf '%s' "$PROMPT" | tr '[:upper:]' '[:lower:]' 2>/dev/null)
  BEST=""
  for d in "$TARGETS_DIR"/*/; do
    [ -d "$d" ] || continue
    NAME=$(basename "$d" 2>/dev/null)
    [ -z "$NAME" ] && continue
    # skip short handles (<=4 chars) in the fuzzy PROMPT match: they collide with common words
    # (short handles) and would inject the WRONG program's scope allowlist on
    # benign prose. A short-handle program still resolves via the authoritative cwd/targets path above.
    [ "${#NAME}" -le 4 ] && continue
    LNAME=$(printf '%s' "$NAME" | tr '[:upper:]' '[:lower:]' 2>/dev/null)
    # escape ERE metacharacters so a dotted dir name (e.g. next.js) word-matches
    # literally instead of as a live regex (parity with contextual-memory-injector).
    LRE=$(printf '%s' "$LNAME" | sed 's/[][^$.*+?(){}|\\]/\\&/g')
    # whole-word match: not flanked by [a-z0-9] on either side.
    if printf '%s' "$LPROMPT" | grep -qE "(^|[^a-z0-9])${LRE}([^a-z0-9]|\$)" 2>/dev/null; then
      # keep the longest match (most specific program name).
      if [ ${#LNAME} -gt ${#BEST} ]; then
        BEST="$LNAME"
        PROG="$NAME"
      fi
    fi
  done
fi

[ -z "$PROG" ] && exit 0   # no active program -> SILENT.

SCOPE="$TARGETS_DIR/$PROG/SCOPE.txt"

# --- SCOPE.txt missing under an explicit targets/<prog>/ cwd ---------------
if [ ! -f "$SCOPE" ]; then
  if [ "$CWD_MATCH" = "1" ]; then
    MSG="# SCOPE: targets/$PROG/SCOPE.txt missing - build it before probing (scope-gate fails open without it)."
    jq -nc --arg ctx "$MSG" \
      '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $ctx}}' 2>/dev/null
  fi
  exit 0   # prompt-name match with no scope file -> SILENT (nothing to assert).
fi

# --- Build the host list ----------------------------------------------------
# IN-SCOPE allowlist only: shared extraction stops at the first OUT-OF-SCOPE
# section divider, so OOS carve-out hosts are NEVER injected under the
# "probe ONLY these in-scope hosts" header. Cap to HOST_CAP.
HOSTS=$(scope_inscope_hosts "$SCOPE" | head -n "$HOST_CAP")

[ -z "$HOSTS" ] && exit 0   # no parseable hosts -> SILENT.

# --- mtime footer -----------------------------------------------------------
MTIME=$(date -r "$SCOPE" '+%Y-%m-%d' 2>/dev/null || echo "unknown")

# --- Assemble context block -------------------------------------------------
CTX="# ACTIVE SCOPE: $PROG
Probe ONLY these in-scope hosts (scope-gate.sh hard-blocks anything else):
$HOSTS
SCOPE.txt last modified $MTIME - re-verify against the program policy page if older than 7 days."

jq -nc --arg ctx "$CTX" \
  '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $ctx}}' 2>/dev/null

exit 0
