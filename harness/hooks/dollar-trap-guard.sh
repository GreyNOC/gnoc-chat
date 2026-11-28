#!/usr/bin/env bash
#
# dollar-trap-guard.sh - PreToolUse hook for Write on reports/drafts paths.
#
# Stops the most expensive sunk-cost trap: writing a full report for a
# program that pays $0 or has documented dead status. Failures are
# documented per session: S12 (Kedro), S14 (h5py), S15 (huntr local libs).
#
# Triggers when the target path or first KB of content references a
# known $0 / dead program. Advisory only (lean rebuild 2026-06-14): emits a
# stderr warning and always exits 0, never blocks the Write.

set -u
IFS=$'\n\t'

PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null)
[ "$TOOL" = "Write" ] || exit 0

FILE=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
case "$FILE" in
  *reports/*.md|*reports/*.MD|*drafts/*.md|*reports/*-h1.md|*reports/*-huntr.md|*reports/*-intigriti.md|*reports/*-bugcrowd.md|*reports/*-ywh.md|*reports/*-immunefi.md) ;;
  *) exit 0 ;;
esac

# Programs known $0 / dead. Update from
# ~/.claude/skills/bounty-verify/SKILL.md and reviewer Gate 1.
TRAPS='\bvllm\b|\blangchain\b|\bbentoml\b|\bkedro\b|\btokenizers\b|\bh5py\b|\bmlflow\b|\bkeras\b|\bonnx\b|\bdify\b|\bopen-webui\b|\bragflow\b|\blollms\b|\bfeast\b|\bopenpgp\.js\b|\bopenpgpjs\b|\btriton\b|\bchia\b|\bkeycloak\b|\bnltk\b'

# Inspect the path and the first 2 KB of the content (already in tool_input.content).
CONTENT=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.content // empty' 2>/dev/null | head -c 2048)

PATH_HIT=$(echo "$FILE" | grep -ioE "$TRAPS" | head -1)
CONTENT_HIT=$(echo "$CONTENT" | grep -ioE "$TRAPS" | head -1)

if [ -n "$PATH_HIT" ] || [ -n "$CONTENT_HIT" ]; then
  HIT="${PATH_HIT:-$CONTENT_HIT}"
  printf '[dollar-trap-guard] target "%s" is on the documented $0 / dead-program list (see ~/.claude/skills/bounty-verify/SKILL.md). Confirm bounty is real before writing this report.\n' "$HIT" >&2
fi

# FAIL-OPEN (lean rebuild 2026-06-14): advisory only. Always exits 0; never
# blocks the Write. The former TRAP_HARD=1 exit-2 path was removed.
exit 0
