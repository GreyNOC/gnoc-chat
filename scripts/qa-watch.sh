#!/usr/bin/env bash
#
# qa-watch.sh - continuously stage new reports into the QA pipeline.
#
# WHY A WATCHER AND NOT JUST THE HOOK. The PostToolUse hook only fires in the session that
# writes the draft. Another agent is producing reports concurrently in its own session, and a
# report written there is invisible to this one until something scans for it. This loop is that
# scan. It is also the backstop if the hook is not loaded in a session.
#
# It stages. It never marks anything QA-READY (a gate has to do that), never sends mail, and
# never touches _held or _closed. Auto-staged bundles carry STATUS.md saying exactly that.
#
# Usage: qa-watch.sh [--interval N] [--once]
set -u
WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
LOG="$WS/QA handoff/_WATCH.log"
INTERVAL=60
ONCE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --interval) shift; INTERVAL="${1:-60}" ;;
    --once) ONCE=1 ;;
  esac
  shift
done

say(){ printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG"; }

mkdir -p "$(dirname "$LOG")" 2>/dev/null
say "qa-watch start (interval ${INTERVAL}s)"

prev_count=-1
while :; do
  # count report-shaped drafts cheaply, so a quiet cycle costs almost nothing
  n=$(find "$WS/reports/drafts" -type f -name 'report.md' 2>/dev/null | wc -l)
  m=$(find "$WS/reports/drafts" -maxdepth 2 -type f -name '*.md' 2>/dev/null | wc -l)
  total=$((n+m))

  out=$("$WS/scripts/qa-handoff.sh" --all 2>&1 | grep -E '^  (staged|moving)' || true)
  if [ -n "$out" ]; then
    say "NEW/CHANGED:"
    printf '%s\n' "$out" | tee -a "$LOG"
    "$WS/scripts/qa-sweep.sh" --quiet 2>/dev/null || true
    # surface anything whose checksums do NOT verify - that is a staging defect, not a nit
    while IFS= read -r d; do
      [ -d "$d/evidence" ] || continue
      ( cd "$d/evidence" && sha256sum -c SHA256SUMS.txt >/dev/null 2>&1 ) \
        || say "  CHECKSUM FAIL: $(basename "$d") - investigate before any handoff"
    done < <(find "$WS/QA handoff" -type d -name '*_*' -exec test -f '{}/REPORT.md' \; -print 2>/dev/null)
  elif [ "$total" != "$prev_count" ]; then
    say "draft count ${total} (no staging change)"
  fi
  prev_count=$total

  [ "$ONCE" -eq 1 ] && break
  sleep "$INTERVAL"
done
say "qa-watch stop"
