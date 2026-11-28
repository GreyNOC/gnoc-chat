#!/usr/bin/env bash
# timebox-set.sh - UserPromptSubmit hook.
#
# Structural clock (part 1 of 2). GreyNOC's #1 complaint: the time-box ("hunt until
# HH:MM") was instruction-only, so the model forgot it under context load and quit
# at 30 min instead of 90. This hook PARSES a working-window from GreyNOC's prompt and
# pins the DEADLINE to disk (state/hunt-loop/until, epoch seconds). The companion
# Stop hook (timebox-gate.sh) then blocks any early stop while now < deadline.
# The clock lives on disk so context rot or a window flush cannot evict it.
#
# Additive context only. Fail-open. Never blocks.
# ponytail: EN+ES keyword parse of the common window phrasings; extend the regexes
# if a new phrasing shows up. Good enough until a real miss is observed.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac
[ -z "$PROMPT" ] && exit 0

STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop"
UNTIL="$STATE_DIR/until"
mkdir -p "$STATE_DIR" 2>/dev/null || exit 0

LP=$(printf '%s' "$PROMPT" | tr '[:upper:]' '[:lower:]')
NOW=$(date +%s)
TARGET=""
LABEL=""

# Clear the timebox on an explicit clear/stop-timebox intent.
if echo "$LP" | grep -qiE '(sin limite de tiempo|sin lImite|cancela.*(tiempo|timebox|reloj)|clear.*timebox|quita.*(el )?tiempo|no time-?box)'; then
  rm -f "$UNTIL" 2>/dev/null
  echo "[TIMEBOX] cleared - no working-window deadline active."
  exit 0
fi

# Form 1: explicit clock "until HH:MM" / "hasta (las) HH:MM"
HM=$(echo "$LP" | grep -oE '(until|hasta( las| la)?)[[:space:]]+[0-2]?[0-9]:[0-5][0-9]' | grep -oE '[0-2]?[0-9]:[0-5][0-9]' | head -1)
# Form 2: whole-hour clock "until HH" / "hasta las HH"
if [ -z "$HM" ]; then
  H=$(echo "$LP" | grep -oE '(until|hasta( las| la)?)[[:space:]]+[0-2]?[0-9]([^0-9:]|$)' | grep -oE '[0-2]?[0-9]' | head -1)
  [ -n "$H" ] && HM="${H}:00"
fi
if [ -n "$HM" ]; then
  T=$(date -d "today $HM" +%s 2>/dev/null || echo "")
  if [ -n "$T" ]; then
    if [ "$T" -le "$NOW" ]; then
      HH=$((10#${HM%%:*}))
      if [ "$HH" -ge 1 ] && [ "$HH" -le 12 ] && [ $((T + 43200)) -gt "$NOW" ]; then
        T=$((T + 43200))   # 12-hour clock: an evening "las 9:30" = 21:30, not tomorrow 09:30
      else
        T=$((T + 86400))   # truly past today -> next day
      fi
    fi
    TARGET="$T"; LABEL="until $HM"
  fi
fi

# Form 3: duration "for/durante/en N min|minutos|hours|horas|h"
if [ -z "$TARGET" ]; then
  PH=$(echo "$LP" | grep -oE '(for|durante|en|in)[[:space:]]+[0-9]+[[:space:]]*(minutos?|minutes?|min|horas?|hours?|h)' | head -1)
  if [ -n "$PH" ]; then
    N=$(echo "$PH" | grep -oE '[0-9]+' | head -1)
    if echo "$PH" | grep -qiE '(horas?|hours?|[0-9][[:space:]]*h$)'; then
      TARGET=$((NOW + N*3600)); LABEL="for ${N}h"
    else
      TARGET=$((NOW + N*60));   LABEL="for ${N}min"
    fi
  fi
fi

[ -z "$TARGET" ] && exit 0   # no window named -> nothing to do

# safety clamp: never pin a window more than 24h out. A typo ("for 100000 hours", or "500" read
# as a duration) would otherwise wedge the timebox-gate Stop hook into a near-permanent no-stop
# state. Cap to NOW+24h so a mis-parse self-heals within a day.
MAXT=$((NOW + 86400))
if [ "$TARGET" -gt "$MAXT" ] 2>/dev/null; then TARGET="$MAXT"; LABEL="$LABEL (capped to 24h)"; fi

echo "$TARGET" > "$UNTIL" 2>/dev/null
HUMAN=$(date -d "@$TARGET" '+%H:%M %Z' 2>/dev/null || echo "?")
REMAIN=$(( (TARGET - NOW + 59) / 60 ))
cat <<EOF
[TIMEBOX SET] Working-window deadline pinned to disk: $LABEL (until $HUMAN, ~${REMAIN} min from now). This is now STRUCTURAL - the Stop hook blocks any early stop until the deadline. Work continuously and re-check the clock between phases. Reaching the end of a task before the deadline is NOT a stop: find the next genuine improvement, deeper validation, or another surface and keep going.
EOF
exit 0
