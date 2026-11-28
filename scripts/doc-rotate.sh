#!/usr/bin/env bash
# Document volume rotation: rotate, never truncate.
# Opens the next numbered volume when the active one passes the byte threshold.
# Never edits, moves or truncates an existing volume. See Manual/MANUAL-VOLUMES.md.
set -euo pipefail
cd "$(dirname "$0")/.."

THRESHOLD=150000
# The AUTO-LOADED index layer shares one harness budget. These cannot rotate (they are
# regenerated or rewritten in place), so going over means COMPACT, not open a new volume.
BUDGET=150000
INDEX_LAYER=(CLAUDE.md SPINE.md Manual/MANUAL-INDEX.md Manual/HARNESS.md HANDOFF-CURRENT.md)

# series: label|volume01-path|basename-stem|extension
SERIES=(
  "manual|Manual/GREYNOC-MANUAL.md|Manual/GREYNOC-MANUAL|md"
  "handoff|CLAUDE-HANDOFF-CRITICAL-10.md|CLAUDE-HANDOFF-CRITICAL-10|md"
)

active_volume() {
  # echoes "path num" for the highest-numbered existing volume of a series
  local v01="$1" stem="$2" ext="$3"
  local best="$v01" bestnum=1 n p
  for p in "${stem}"-*."${ext}"; do
    [ -e "$p" ] || continue
    n=$(printf '%s\n' "$p" | sed -E "s|^${stem}-0*([0-9]+)\.${ext}$|\1|")
    [[ "$n" =~ ^[0-9]+$ ]] || continue
    if [ "$n" -gt "$bestnum" ]; then bestnum="$n"; best="$p"; fi
  done
  printf '%s %s\n' "$best" "$bestnum"
}

MODE="${1:-report}"
over=0

for row in "${SERIES[@]}"; do
  IFS='|' read -r label v01 stem ext <<<"$row"
  read -r apath anum < <(active_volume "$v01" "$stem" "$ext")
  size=$(wc -c <"$apath" | tr -d ' ')
  head=$(( THRESHOLD - size ))
  state="ok"; [ "$size" -ge "$THRESHOLD" ] && { state="OVER"; over=1; }
  printf '%-8s active=v%02d %-40s %8d bytes  headroom=%8d  %s\n' \
    "$label" "$anum" "$apath" "$size" "$head" "$state"

  if [ "$MODE" = "--rotate" ] && [ "$state" = "OVER" ]; then
    next=$(( anum + 1 ))
    npath=$(printf '%s-%02d.%s' "$stem" "$next" "$ext")
    if [ -e "$npath" ]; then
      echo "  REFUSE: $npath already exists, not overwriting" >&2
      continue
    fi
    today=$(date +%F)
    {
      echo "# $(basename "$stem") - VOLUME $(printf '%02d' "$next")"
      echo
      echo "Continuation volume. Previous volume: \`$apath\` (frozen for new entries at $size bytes, $today)."
      echo "Everything in earlier volumes remains authoritative; nothing was moved or deleted by rotation."
      echo
      echo "- **Owner:** GreyNOC"
      echo "- **Volume:** $(printf '%02d' "$next")"
      echo "- **Opened:** $today"
      echo "- **Rotation rule:** Manual/MANUAL-VOLUMES.md. T-NN ids (manual) and report-package"
      echo "  entries (handoff) are GLOBAL across volumes and never reused."
      echo
      echo "Precedence unchanged: SPINE.md over the Manual, the Manual over any older fragment, a"
      echo "newer volume over an older one where they disagree."
      echo
      echo "---"
      echo
      echo "# NEW ENTRIES (Volume $(printf '%02d' "$next"))"
      echo
      echo "_No entries yet._"
    } >"$npath"
    echo "  ROTATED: opened $npath"
    python3 -I scripts/doc-rotate-ptr.py "$stem" "$ext" "$npath"
    echo "  APPEND NEW ENTRIES TO: $npath  (previous volume is frozen)"
  fi
done

# ---- index layer: one shared auto-load budget, cannot rotate ----
if [ "$MODE" = "report" ] || [ "$MODE" = "--check" ] || [ "$MODE" = "--budget" ] || [ "$MODE" = "--rotate" ]; then
  total=0
  for f in "${INDEX_LAYER[@]}"; do
    [ -e "$f" ] || continue
    s=$(wc -c <"$f" | tr -d ' ')
    total=$(( total + s ))
    [ "$MODE" = "--budget" ] && printf '  %8d  %s\n' "$s" "$f"
  done
  bhead=$(( BUDGET - total ))
  bstate="ok"
  if [ "$total" -ge "$BUDGET" ]; then bstate="OVER"; over=1
  elif [ "$bhead" -lt 10000 ]; then bstate="TIGHT"; fi
  printf '%-8s auto-loaded set (%d files)%17s %8d bytes  headroom=%8d  %s\n' \
    "index" "${#INDEX_LAYER[@]}" "" "$total" "$bhead" "$bstate"
  if [ "$bstate" != "ok" ]; then
    echo "  index layer cannot rotate - COMPACT it (move dated/narrative text to the active archive volume)" >&2
    # ...and on --rotate, actually do it. HANDOFF-CURRENT is the only index-layer file that GROWS every
    # session (every lane appends a dated entry to section 2), so it is what breaks the budget - and it
    # broke it three times inside one session on 2026-10-27 even while being hand-trimmed. Hand trimming
    # does not survive four concurrent lanes. The move is VERBATIM into the newest archive volume under a
    # dated COMPACTION heading, which is the file's own doctrine ("only what is true NOW"); nothing is
    # deleted and the compactor is idempotent.
    if [ "$MODE" = "--rotate" ]; then
      echo "  compacting HANDOFF-CURRENT section 2 (verbatim, into the active volume)..." >&2
      python3 "$(dirname "$0")/learn/handoff-compact.py" --apply --budget "$BUDGET" >&2 || true
    fi
  fi
fi

if [ "$MODE" = "--check" ]; then
  [ "$over" -eq 0 ] || { echo "CHECK FAIL: a volume is over $THRESHOLD bytes (run --rotate), or the index layer is over $BUDGET" >&2; exit 1; }
  echo "CHECK OK: active volumes under $THRESHOLD bytes, index layer under $BUDGET"
fi
exit 0
