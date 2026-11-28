#!/usr/bin/env bash
# Append-only volume rotation gate.
# Fires after a write that could have grown an archive volume. If the active volume
# passed its byte threshold, open the next one and tell the agent to append THERE.
# Advisory only - never blocks a write. See Manual/MANUAL-VOLUMES.md.
set -uo pipefail
WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
payload=$(cat 2>/dev/null || true)

# Cheap short-circuit: a Bash call that never names a volume cannot have grown one.
tool=$(printf '%s' "$payload" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
if [ "$tool" = "Bash" ]; then
  printf '%s' "$payload" | grep -qE 'CRITICAL-10|GREYNOC-MANUAL' || exit 0
fi

cd "$WS" 2>/dev/null || exit 0
out=$(scripts/doc-rotate.sh --rotate 2>&1 || true)
printf '%s' "$out" | grep -q 'ROTATED:' || exit 0

newvol=$(printf '%s' "$out" | sed -n 's/.*ROTATED: opened \(.*\)$/\1/p' | head -1)
oldvol=$(printf '%s' "$out" | sed -n 's/.*active=v[0-9]* \([^ ]*\).*OVER.*/\1/p' | head -1)
cat <<MSG
VOLUME ROTATED: \`$oldvol\` passed the 150000-byte threshold and is now FROZEN for new entries.
The next volume \`$newvol\` has been opened and the "(active)" pointer in CLAUDE.md was updated.
Append every further receipt to \`$newvol\`. Nothing was moved, edited or truncated.
MSG
exit 0
