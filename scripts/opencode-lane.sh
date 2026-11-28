#!/usr/bin/env bash
# Drive ONE hunt lane through the OpenCode worker (local Hermes 3 on the user Ollama server 11435).
# The orchestrator (Claude) writes the BRIEF (context, kill byte) and the PROBES file (one exact
# command per line). This driver feeds the worker ONE command per turn, verifies on DISK that it
# fired (the lane harness appends a line to commands.txt), retries once, then builds the results
# table FROM DISK, asks the worker for VERDICT and NEXT PROBE lines (after it reads the raw bytes),
# and appends the outcome line itself. The worker never submits.
#
# usage: scripts/opencode-lane.sh <program> <lane-dir-name> <brief.md> <probes.txt> [agent] [total-timeout-s]
#   probes.txt lines: TAG|command      (# comments and blank lines ignored)
#   env PROGRESS_FILE=path   file whose line count = requests fired (default <lane>/commands.txt)
#   env ROUND=C              label for the STATUS.md section (default: derived from the probes file name)
#
# LESSONS BAKED IN (2026-10-20, all measured on Hermes 3 8B):
# - A long brief makes the model NARRATE commands as prose and never call the tool. One short line per
#   turn, phrased "Use the bash tool to run exactly: <cmd> ; then print its output verbatim and stop.",
#   fires every time (the smoke-test phrasing).
# - `opencode run` reads STDIN and appends it to the message; inside a `while read` loop it swallowed
#   the rest of the probe file and the model FABRICATED fifteen results it never ran. Always </dev/null,
#   and never trust the chat: commands.txt and raw/ are the only truth.
# - One lane at a time: the 8 GB GPU holds one model.
set -u
WS=${GNOC_WORKSPACE:-$HOME/.gnoc}
PROG=${1:?program}; LANE=${2:?lane}; BRIEF=${3:?brief}; PROBES=${4:?probes}; AGENT=${5:-hunter}; TOTAL=${6:-5400}
TURN_TMO=${TURN_TMO:-900}  # the 14B worker (hunter) takes ~3.5 min per warm turn on this 8 GB GPU
# Qwen3 agents think before every reply; one-command turns do not need it (and the 14B copied a trailing
# "; then ..." clause into the shell when the command was not fenced, so the command is now in backticks)
grep -qiE '^model:.*qwen' "$WS/.opencode/agent/$AGENT.md" 2>/dev/null && NOTHINK=" /no_think" || NOTHINK=""; MAX_VERDICT=${MAX_VERDICT:-2}
# the verdict stage reads bytes and writes two lines; 2026-10-26 02:28Z a lane spent 32 min in it (the 9B re-read
# SCOPE.txt and tried its own probes). Two turns of five minutes is the budget; the raw files are the evidence anyway.
VERDICT_TMO=${VERDICT_TMO:-300}
DB=$HOME/.local/share/opencode/opencode.db
LANEDIR="$WS/targets/$PROG/hunts/$LANE"
PROGRESS=${PROGRESS_FILE:-$LANEDIR/commands.txt}
ROUND=${ROUND:-$(basename "$PROBES" .txt | sed 's/^PROBES-//')}
# HUNTING IS BOUND TO A LIVE gnoc chat (GreyNOC, 2026-11-02): no chat open, no lane. The engine that
# used to start lanes unattended (orch-bot) is retired; this is the chokepoint that enforces it.
/usr/bin/python3 "$WS/scripts/gnoc_session.py" require "lane $PROG/$LANE" || exit 3
[ -f "$WS/targets/$PROG/SCOPE.txt" ] || { echo "no SCOPE.txt for $PROG" >&2; exit 2; }
[ -f "$BRIEF" ] || { echo "brief not found: $BRIEF" >&2; exit 2; }
[ -f "$PROBES" ] || { echo "probes not found: $PROBES" >&2; exit 2; }
curl -s -m 5 127.0.0.1:11435/api/version >/dev/null || { echo "ollama-oc (11435) is down: pm2 restart ollama-oc" >&2; exit 2; }
# scope net for the lane's shell (2026-10-24): a paused program starts no lane; LANE_PROXY=0 disables the proxy (escape hatch)
python3 "$WS/scripts/lane_egress_audit.py" --paused "$PROG" && { echo "lanes for $PROG are paused by a scope incident: rm $WS/.claude/state/orch/lane-scope-pause/$PROG after review" >&2; exit 2; }
mkdir -p "$LANEDIR/raw" "$WS/.claude/state/opencode"
touch "$PROGRESS"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="$WS/.claude/state/opencode/$PROG-$LANE-$TS.log"
TITLE="$PROG/$LANE/$TS"
START=$(date +%s)
cd "$WS" || exit 2
export HUNT_TARGET="$PROG"
export LANE_PROBES="$(readlink -f "$PROBES")"
# ---- per-lane deny-by-default scope proxy (the oss-bot one), inherited by the model's shell ----
PXLOG=""; PXPID=""
if [ "${LANE_PROXY:-1}" != "0" ]; then
  PXLOG="$LANEDIR/egress-$TS.jsonl"; PXOUT=$(mktemp)
  python3 "$WS/scripts/oss-bot/scope_proxy.py" --program "$PROG" --port 0 --log "$PXLOG" --rps "${LANE_RPS:-5}" --max-conn-per-host 4 >"$PXOUT" 2>>"$LOG" </dev/null &
  PXPID=$!
  trap '[ -n "$PXPID" ] && kill "$PXPID" 2>/dev/null; rm -f "$PXOUT"' EXIT
  PXPORT=""
  for _ in $(seq 1 50); do PXPORT=$(sed -n 's/^PORT //p' "$PXOUT" | head -1); [ -n "$PXPORT" ] && break; kill -0 "$PXPID" 2>/dev/null || break; sleep 0.3; done
  [ -n "$PXPORT" ] || { echo "scope proxy did not start for $PROG; refusing to run an unconstrained lane" >&2; exit 2; }
  for v in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do export "$v=http://127.0.0.1:$PXPORT"; done
  export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost
fi
count() { grep -c . "$PROGRESS"; }
elapsed() { echo $(( $(date +%s) - START )); }
BASE=$(count)
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
log "lane=$LANE round=$ROUND agent=$AGENT probes=$PROBES base_requests=$BASE log=$LOG"
echo "$TS $PROG $LANE $AGENT round=$ROUND log=$LOG" >> "$WS/.claude/state/opencode/dispatch.log"

SID=""
# D34 (2026-10-26): the worker rewrote this driver through its bash tool. Every model turn is bracketed by the harness
# guard: anything it changes or creates under scripts/ or .opencode/ is restored or deleted and logged, and the
# verdict of a turn that touched the harness is discarded (HARNESS_HIT=1).
. "$WS/scripts/lane-harness-guard.sh"; HG_LOG="$LOG"; harness_snap; HARNESS_HIT=0
run_turn() {  # $1 = message ; stdin closed so nothing leaks into the prompt
  if [ -n "$SID" ]; then
    timeout "$TURN_TMO" opencode run --agent "$AGENT" -s "$SID" "$1" </dev/null >> "$LOG" 2>&1
  else
    timeout "$TURN_TMO" opencode run --agent "$AGENT" --title "$TITLE" "$1" </dev/null >> "$LOG" 2>&1
    SID=$(sqlite3 "$DB" "select id from session where title='$TITLE' order by time_created desc limit 1;" 2>/dev/null)
    log "session=$SID"
  fi
  echo >> "$LOG"
  harness_check "$TITLE" "$SID" || { HARNESS_HIT=1; log "HARNESS WRITE in $TITLE: the turn's verdict is discarded"; }
}

# ---- probes, one per turn, verified on disk ----
UNFIRED=""; FIREDTAGS=""
while IFS='|' read -r TAG CMD <&3; do
  case "$TAG" in ''|'#'*) continue;; esac
  [ "$(elapsed)" -ge "$TOTAL" ] && { log "total timeout before $TAG"; break; }
  BEFORE=$(count); SID=""; TITLE="$PROG/$LANE/$TS/$TAG"
  if [ "${LANE_FIRE:-shell}" = "model" ]; then
    run_turn "Use the bash tool to run exactly this command and nothing else: \`lane $TAG\` Then print its output verbatim and stop.$NOTHINK"
    if [ "$(count)" -le "$BEFORE" ]; then
      log "$TAG not fired, retrying once"
      run_turn "Use the bash tool to run exactly this command and nothing else: \`lane $TAG\` Then print its output verbatim and stop.$NOTHINK"
    fi
  else
    # T-255: a small local model is an executor, not a hunter. Watched live 2026-10-25: the 9B spent 6 minutes reading
    # p.py and mistyping SCOPE.txt instead of running `lane c00`. The shell fires the exact probe line (same env: scope
    # proxy, HUNT_TARGET, LANE_PROBES); the model is used afterwards only to read the bytes and write the verdict.
    log "$TAG firing from the shell (T-255)"
    ( cd "$WS" && timeout "${PROBE_TMO:-120}" "$WS/scripts/lane" "$TAG" ) >> "$LOG" 2>&1 || log "$TAG probe exit $?"
  fi
  if [ "$(count)" -le "$BEFORE" ]; then log "$TAG UNFIRED after retry"; UNFIRED="$UNFIRED $TAG"; else log "$TAG fired (round total $(( $(count) - BASE )))"; FIREDTAGS="$FIREDTAGS $TAG"; fi
done 3< "$PROBES"
FIRED=$(( $(count) - BASE ))

# ---- results table FROM DISK (never from the chat) ----
{
  echo
  echo "## Round $ROUND (OpenCode worker $AGENT, $(date -u +%Y-%m-%d) $TS)"
  echo "Driver: scripts/opencode-lane.sh. Requests fired this round: $FIRED${UNFIRED:+; UNFIRED: $UNFIRED}. Rows below are parsed from commands.txt; bytes are in raw/."
  echo
  echo "| tag | method | url | status | length |"
  echo "|---|---|---|---|---|"
  tail -n "$FIRED" "$PROGRESS" | awk '{
    tag=$2; meth=$3; url=$4; st=""; ln="";
    for(i=1;i<=NF;i++){ if($i=="->"){ st=$(i+1); ln=$(i+2) } }
    gsub(/\|/,"%7C",url); if(length(url)>150) url=substr(url,1,150)"...";
    printf("| %s | %s | %s | %s | %s |\n", tag, meth, url, st, ln) }'
} >> "$LANEDIR/STATUS.md"
log "results table appended to STATUS.md ($FIRED rows)"

# ---- the worker reads the bytes, then writes VERDICT and NEXT PROBE ----
if [ "$FIRED" -gt 0 ]; then
  TURN_TMO=$VERDICT_TMO
  SID=""; TITLE="$PROG/$LANE/$TS/verdict"
  SHOW="for f in $(for t in $FIREDTAGS; do printf '%s ' "$LANEDIR/raw/$t.body $LANEDIR/raw/$t.resp"; done); do [ -f \"\$f\" ] && { echo \"== \$f\"; head -c 400 \"\$f\" | tr -d '\\r' | tail -c 300; echo; }; done 2>/dev/null"
  run_turn "Use the bash tool to run exactly: $SHOW ; then print its output verbatim and stop."
  n=0
  while [ $n -lt "$MAX_VERDICT" ] && [ "$(elapsed)" -lt "$TOTAL" ]; do
    grep -q "^VERDICT:" "$LANEDIR/STATUS.md" && [ "$(stat -c %Y "$LANEDIR/STATUS.md")" -ge "$START" ] && tail -5 "$LANEDIR/STATUS.md" | grep -q '^VERDICT:' && break
    n=$((n+1)); log "verdict turn $n/$MAX_VERDICT"
    run_turn "You have now seen the real response bytes for round $ROUND. The brief below defines the kill byte. Decide: FINDING-CANDIDATE only if a response carries the kill byte; LEAD if a mechanism showed without the kill byte; DEAD if every probe hit the negative; UNFIRED if the harness errored. Use the bash tool to run exactly: printf '%s\n' 'VERDICT: <your verdict> - <one sentence naming the tags and bytes that decide it>' 'EVIDENCE: <TAG> <up to 60 bytes copied EXACTLY from raw/<TAG>.resp that carry the kill byte, or the word none>' 'NEXT PROBE: <the single most useful next request>' >> $LANEDIR/STATUS.md ; replacing the angle-bracket parts with your own words, then stop."$'\n\n--- BRIEF ---\n'"$(sed -n '1,60p' "$BRIEF")"
  done
fi
# ---- end-of-lane egress audit (oss-bot net 3 equivalent): any violation pauses further lanes for this program ----
if [ -n "$PXLOG" ]; then
  python3 "$WS/scripts/lane_egress_audit.py" "$PROG" "$PXLOG" --commands "$PROGRESS" --fired "$FIRED" 2>&1 | tee -a "$LOG" || true
fi
VERD=$(tail -5 "$LANEDIR/STATUS.md" | grep '^VERDICT:' | tail -1 | sed 's/^VERDICT: *//' | grep -o -E '^(FINDING-CANDIDATE|CRITICAL-CANDIDATE|MEDIUM-CANDIDATE|LEAD|DEAD|UNFIRED)' | head -1)
[ -n "$VERD" ] || VERD=UNFIRED
if [ "$HARNESS_HIT" = 1 ]; then VERD=UNFIRED; printf '%s\n' "VERDICT: UNFIRED - the worker wrote outside its lane directory (harness files restored, see the driver log); its verdict is discarded" >> "$LANEDIR/STATUS.md"; fi
harness_done
[ "$VERD" = "DEAD" ] && [ "$FIRED" -lt 8 ] && VERD=UNFIRED
# ---- evidence gate (T-255, 2026-10-25): a candidate verdict is a claim until the cited bytes are found on disk ----
# Watched live: the 9B wrote "FINDING-CANDIDATE - platform.claude.com 301 route leaking identity" over six responses that
# were 301/302/404 with empty bodies. The model must cite TAG + bytes; code greps raw/<TAG>.resp. No match = LEAD.
case "$VERD" in *CANDIDATE)
  EV=$(tail -6 "$LANEDIR/STATUS.md" | grep '^EVIDENCE:' | tail -1 | sed 's/^EVIDENCE: *//')
  EVTAG=$(printf '%s' "$EV" | awk '{print $1}'); EVBYTES=$(printf '%s' "$EV" | cut -d' ' -f2- | cut -c1-200)
  if [ -z "$EVTAG" ] || [ "$EVTAG" = "none" ] || [ ! -f "$LANEDIR/raw/$EVTAG.resp" ] || [ -z "$EVBYTES" ] \
     || ! grep -qF -- "$EVBYTES" "$LANEDIR/raw/$EVTAG.resp" 2>/dev/null; then
    log "verdict gate: $VERD demoted to LEAD (cited evidence '${EV:0:80}' not found in raw/)"
    printf 'VERDICT-GATE: %s demoted to LEAD by the driver: cited evidence not found in raw/ (%s)\n' "$VERD" "${EV:0:120}" >> "$LANEDIR/STATUS.md"
    VERD=LEAD
  else
    log "verdict gate: $VERD kept, bytes found in raw/$EVTAG.resp"
    [ "$VERD" = "FINDING-CANDIDATE" ] && VERD=MEDIUM-CANDIDATE   # the ledger vocabulary; severity is for a human or Claude
  fi;;
esac
MIN=$(( $(elapsed) / 60 ))
printf '%s' "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"lane\":\"$LANE-$ROUND\",\"target\":\"$PROG\",\"vector\":\"$(head -1 "$BRIEF" | sed 's/^# *//; s/\"/\\\"/g' | cut -c1-120)\",\"verdict\":\"$VERD\",\"capability\":\"see STATUS.md\",\"probes\":$FIRED,\"burst\":false,\"minutes\":$MIN,\"floor\":\"$([ "$FIRED" -ge 8 ] && [ "$MIN" -ge 30 ] && echo met || echo not-met)\",\"artifact\":\"targets/$PROG/hunts/$LANE/STATUS.md\",\"notes\":\"opencode worker $AGENT, driver round $ROUND${UNFIRED:+, unfired:$UNFIRED}\"}" | python3 "$WS/scripts/hunt-state.py" append-outcome >> "$LOG" 2>&1 && log "outcome appended verdict=$VERD"
log "END fired=$FIRED unfired=[${UNFIRED# }] verdict=$VERD minutes=$MIN session=$SID"
