#!/usr/bin/env bash
# HANDOFF-CURRENT.md size check: warn, never edit.
# HANDOFF-CURRENT.md is AUTO-LOADED and REWRITTEN in place (it cannot rotate like the
# append-only volumes in scripts/doc-rotate.sh). Over the cap it must be COMPACTED by a
# human or agent: move dated/narrative text to the active CLAUDE-HANDOFF-CRITICAL-10-NN.md.
# This script only measures and names the biggest section so the compactor knows where
# to cut first. It is READ-ONLY: it never edits, moves or truncates the file (live shared
# state read by concurrent sessions).
#
# usage: scripts/handoff-rotate.sh            report (always exit 0)
#        scripts/handoff-rotate.sh --check    exit 1 when over the threshold
# env:   HANDOFF_THRESHOLD (default 25000 bytes), HANDOFF_FILE (default HANDOFF-CURRENT.md)
set -euo pipefail
cd "$(dirname "$0")/.."

THRESHOLD="${HANDOFF_THRESHOLD:-25000}"
FILE="${HANDOFF_FILE:-HANDOFF-CURRENT.md}"
MODE="${1:-report}"

[ -f "$FILE" ] || { echo "handoff-rotate: $FILE not found" >&2; exit 2; }

size=$(wc -c <"$FILE" | tr -d ' ')
head=$(( THRESHOLD - size ))

# Per-section byte sizes. A section runs from its "## " header to the next one; text
# above the first header is the preamble. Output: bytes<TAB>header, largest first.
sections=$(LC_ALL=C awk '
  BEGIN { name="(preamble before first ## header)"; bytes=0 }
  /^## / { print bytes "\t" name; name=$0; bytes=0 }
  { bytes += length($0) + 1 }
  END { print bytes "\t" name }
' "$FILE" | sort -t$'\t' -k1,1nr)

if [ "$size" -le "$THRESHOLD" ]; then
  printf 'handoff  %-28s %8d bytes  headroom=%8d  ok\n' "$FILE" "$size" "$head"
  exit 0
fi

top=$(printf '%s\n' "$sections" | head -1)
top_bytes=${top%%$'\t'*}
top_name=${top#*$'\t'}
over=$(( size - THRESHOLD ))

bar='!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
{
  echo "$bar"
  echo "!!  HANDOFF OVER CAP: $FILE is $size bytes, threshold $THRESHOLD bytes"
  echo "!!  over by $over bytes ($(( size * 100 / THRESHOLD ))% of cap). It is AUTO-LOADED every session."
  echo "!!  LARGEST SECTION (cut here first): $top_bytes bytes  $top_name"
  echo "!!  COMPACT, do not rotate: move dated/narrative text VERBATIM to the newest"
  echo "!!  CLAUDE-HANDOFF-CRITICAL-10-NN.md volume and leave a pointer line behind."
  echo "$bar"
  echo "section sizes, largest first:"
  printf '%s\n' "$sections" | awk -F'\t' '{ printf "  %8d  %s\n", $1, $2 }'
} >&2

if [ "$MODE" = "--check" ]; then
  echo "CHECK FAIL: $FILE over $THRESHOLD bytes" >&2
  exit 1
fi
exit 0
