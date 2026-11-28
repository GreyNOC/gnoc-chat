#!/usr/bin/env bash
#
# saturation.sh <program> - cycle-1 selection signal (operationalizes SPINE 0b).
#
# The dominant waste the audit found: the loop kept discovering at cycle ~18 what
# was knowable at cycle 1, re-grinding surfaces already receipt-dead. This script
# reads the on-disk dead-knowledge for a program and prints the cycle-1 verdict
# (FAST-LANE / CAP-SOON / ABORT-RESWEEP) so the call is made in the first cycle,
# not the eighteenth. Read-only. Called standalone and by hunt-trigger.sh.
#
# Signals (all from disk, no network):
#   - receipt-dead vector count   : RECEIPT-DEAD/DEAD-with/OUT-OF-SCOPE lines in
#                                   the program's per-target do-not-rehunt index
#   - distinct session-dates      : how many days this program was ground (proxy
#                                   for "sessions"); SPINE 0b caps at 2+ dead sessions
#   - NEEDS/PARKED markers        : a crown gated by a the operator-only unlock -> NEEDS-PARK
#   - ledger line                 : paid / unpaid signal from outcome-ledger.md
#   - LOCK                        : is the loop locked to this program
#
# Usage:  scripts/saturation.sh <program>     (or no arg -> use the LOCK'd program)

set -u
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
PROG="${1:-}"

# Resolve the per-session lock library (fail-open if missing).
. "$ROOT/scripts/hunt-loop/lock-lib.sh" 2>/dev/null || true

# No arg: fall back to the locked program (per-session > global LOCK, precedence via hl_lock_target).
if [ -z "$PROG" ]; then
  if command -v hl_lock_target >/dev/null 2>&1; then
    PROG="$(hl_lock_target 2>/dev/null | tr -d '[:space:]')"
  else
    [ -f "$ROOT/.claude/state/hunt-loop/LOCK" ] && \
      PROG=$(grep -vE '^[[:space:]]*#' "$ROOT/.claude/state/hunt-loop/LOCK" 2>/dev/null | head -1 | tr -d '[:space:]')
  fi
fi
[ -z "$PROG" ] && { echo "usage: saturation.sh <program>"; exit 1; }

TDIR="$ROOT/targets/$PROG"
[ -d "$TDIR" ] && [ ! -e "$TDIR/SCOPE.txt" ] && echo "SATURATION NOTE: $PROG has a target dir but no SCOPE.txt (scope-gate unconfigured)." >&2
if [ ! -d "$TDIR" ]; then
  echo "SATURATION: $PROG -> no targets/$PROG dir yet = FRESH (never hunted). VERDICT: FAST-LANE."
  exit 0
fi

# Collect this program's dead-knowledge: all lines from the per-target index files
# PLUS the program-owned lines of the global index (keyed "<prog>-..." / "<prog>:...").
# The global file is cross-program, so only its program-prefixed lines count here.
collect() {
  for f in "$TDIR/do-not-rehunt.txt" "$TDIR/do-not-rehunt.md" "$TDIR/hunts/do-not-rehunt.md"; do
    [ -f "$f" ] && cat "$f"
  done
  GLOBAL="$ROOT/.claude/state/hunt-loop/do-not-rehunt.txt"
  [ -f "$GLOBAL" ] && awk -v p="$PROG" 'index($0,p)==1 && (substr($0,length(p)+1,1)=="-" || substr($0,length(p)+1,1)==":")' "$GLOBAL" 2>/dev/null
}
BODY=$(collect)
DEAD=$(printf '%s\n' "$BODY" | grep -ciE 'RECEIPT-DEAD|DEAD-with|DEAD-EXTERNAL|OUT-OF-SCOPE|KYC-DEAD' 2>/dev/null); DEAD=${DEAD:-0}
DATES=$(printf '%s\n' "$BODY" | grep -oE '20[0-9]{2}-[0-9]{2}-[0-9]{2}' 2>/dev/null | sort -u | wc -l | tr -d ' ')
NEEDS=$(printf '%s\n' "$BODY" | grep -ciE 'PARKED|NEEDS|pending-NEEDS|one-receipt-away|one-probe-away|LIVE-' 2>/dev/null); NEEDS=${NEEDS:-0}

# Ledger signal (paid / unpaid).
LEDGER="unknown"
if [ -f "$ROOT/outcome-ledger.md" ]; then
  L=$(grep -iE "(^|[^a-z])$PROG([^a-z]|$)" "$ROOT/outcome-ledger.md" 2>/dev/null | head -3 | tr '\n' ';' | cut -c1-200)
  [ -n "$L" ] && LEDGER="$L"
fi

# LOCK status (per-session > global LOCK via hl_lock_target / hl_lock_file).
LOCK="no"
if command -v hl_lock_target >/dev/null 2>&1; then
  LK="$(hl_lock_target 2>/dev/null | tr -d '[:space:]')"
  LKF="$(hl_lock_file 2>/dev/null)"
else
  LK=""; LKF="$ROOT/.claude/state/hunt-loop/LOCK"
  [ -f "$LKF" ] && LK=$(grep -vE '^[[:space:]]*#' "$LKF" 2>/dev/null | head -1 | tr -d '[:space:]')
fi
if [ -n "$LK" ]; then
  [ "$LK" = "$PROG" ] && LOCK="yes (this program)"
  [ "$LK" != "$PROG" ] && LOCK="held by $LK"
  # Annotate whether this is a per-session or global lock file.
  case "${LKF:-}" in
    *LOCK.*) LOCK="$LOCK [per-session: $LKF]" ;;
    *) : ;;
  esac
fi

# Verdict per SPINE 0b thresholds.
VERDICT="FAST-LANE"
GUIDE="No saturation signal. Hunt now; aim the first 3 hypotheses at seams (SPINE 0b SIG-1..6)."
if [ "$DATES" -ge 3 ] || [ "$DEAD" -ge 30 ]; then
  VERDICT="ABORT-RESWEEP"
  GUIDE="Surface heavily ground ($DATES day-sessions, $DEAD dead vectors). Do NOT re-sweep. Pivot to a FRESH subdomain/surface/actor not in the index, or surface the ceiling. If LOCK'd, within-program pivot ONLY."
elif [ "$DEAD" -ge 10 ]; then
  VERDICT="CAP-SOON"
  GUIDE="$DEAD vectors already dead. Cap this surface at a few cycles; prefer a fresh surface. Dedup-gate will block exact re-probes."
fi
if [ "$NEEDS" -ge 1 ] && [ "$VERDICT" != "FAST-LANE" ]; then
  GUIDE="$GUIDE  ($NEEDS parked/LIVE markers - re-check NEEDS unlocks before re-grinding the free surface.)"
fi

cat <<EOF
SATURATION REPORT: $PROG
  LOCK:                 $LOCK
  receipt-dead vectors: $DEAD
  day-sessions ground:  $DATES
  parked/NEEDS/live:    $NEEDS
  ledger:               $LEDGER
  VERDICT: $VERDICT
  GUIDANCE: $GUIDE
EOF
