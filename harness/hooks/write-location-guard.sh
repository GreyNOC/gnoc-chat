#!/usr/bin/env bash
#
# write-location-guard.sh - PreToolUse hook for Write|Edit.
#
# Enforces the CLAUDE.md layout: NO new files written directly to the
# workspace root. Hunt artifacts belong under targets/<program>/, reports
# under reports/, tooling under scripts/, patterns under patterns/, infra
# under .claude/. The root holds only the workspace docs. A blocked write
# is a hard deny so a stray repro/recon/header dump cannot reclutter root.
#
# Allowed at root: the workspace doc set + dotfiles (.gitignore etc).
# Everything in any subdirectory is allowed.

set -u

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"

PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null)
case "$TOOL" in Write|Edit) ;; *) exit 0 ;; esac

FILE=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
[ -z "$FILE" ] && exit 0

# Normalize: make relative paths absolute against the workspace root, collapse //.
case "$FILE" in
  /*) ABS="$FILE" ;;
  *)  ABS="$ROOT/$FILE" ;;
esac
ABS=$(printf '%s' "$ABS" | sed 's#//*#/#g')

# Only police writes inside this workspace.
case "$ABS" in "$ROOT"/*) ;; *) exit 0 ;; esac

DIR=$(dirname "$ABS")
BASE=$(basename "$ABS")

# Not at root (lives in a subdir) -> always allowed.
[ "$DIR" = "$ROOT" ] || exit 0

# At root: allow the workspace doc set + any dotfile.
case "$BASE" in
  .*) exit 0 ;;
  CLAUDE.md|SPINE.md|HUNT-LOOP.md|ARCHITECTURE.md|outcome-ledger.md|VPS-SETUP.md|README.md|MEMORY.md) exit 0 ;;
  HANDOFF-CURRENT.md|CLAUDE-HANDOFF-CRITICAL-10*.md) exit 0 ;;
esac

# Block: deny the write to root with a corrective reason.
REASON="Write to the workspace ROOT is forbidden (file: $BASE). Per CLAUDE.md layout, put it under: targets/<program>/ (recon, hunts, poc, evidence), reports/drafts|submitted/<program>/ (reports), scripts/ (tooling), patterns/ (cards), or .claude/ (infra). Root holds only the workspace docs."
jq -nc --arg r "$REASON" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
exit 0
