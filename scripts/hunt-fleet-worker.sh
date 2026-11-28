#!/usr/bin/env bash
# hunt-fleet-worker.sh <target> - supervise ONE pinned hunt agent.
#
# Claims the target, then runs `claude` pinned to it (HUNT_TARGET), relaunching when a
# session ends so the hunt is indefinite. Releases the claim on exit. A crash-loop guard
# stops relaunching a command that keeps dying fast, so a broken setup never spins forever.
#
# Env overrides: FLEET_MODEL (default opus), FLEET_CLAUDE_ARGS, FLEET_PROMPT,
# FLEET_DRY_RUN=1 (echo instead of launching claude - used by the launcher self-test).
set -u
ROOT="${HUNT_FLEET_ROOT:-${GNOC_WORKSPACE:-$HOME/.gnoc}}"
FLEET="$(cd "$(dirname "$0")" && pwd)/hunt-fleet.sh"   # sibling, independent of ROOT override
T="${1:?usage: hunt-fleet-worker.sh <target>}"
SID="fleet:$T"
MODEL="${FLEET_MODEL:-opus}"
cd "$ROOT" 2>/dev/null || exit 1

# Claim with THIS supervisor's pid (long-lived); refuse if a live sibling already owns it.
if ! "$FLEET" claim "$T" "$SID" "$$" >/dev/null 2>&1; then
  echo "[$T] already owned by a live session -> not launching"; exit 1
fi
trap '"$FLEET" release "$T" "$SID" >/dev/null 2>&1' EXIT INT TERM

PROMPT="${FLEET_PROMPT:-You are in the the workspace workspace pinned to a single program via HUNT_TARGET=$T. \
Enter the indefinite hunt loop from CLAUDE.md and SPINE.md for THIS program ONLY - model the target, \
hypothesize from the model, probe, escalate and chain to terminal impact, run the ship gates. Do NOT \
rotate to any other program. If you capture a terminal receipt, write the draft to reports/drafts/$T/ \
(it auto-surfaces to reports/INBOX.md for manual submit by the operator) and keep hunting. Never stop when \
a surface looks exhausted - pivot within $T. Before the first probe read targets/$T/recon/oss-bot/SEEDS.md \
(scanner LEADs refreshed every few hours; verify each by hand, never file from it) and re-read it at the \
start of each cycle.}"

fails=0
while :; do
  if "$FLEET" stopped "$T" >/dev/null 2>&1; then echo "[$T] stop flag set -> exiting supervisor"; break; fi
  "$FLEET" beat "$T" "$SID" >/dev/null 2>&1
  start=$(date +%s)
  if [ "${FLEET_DRY_RUN:-0}" = "1" ]; then
    echo "[$T] DRY_RUN would launch: claude -p --model $MODEL --permission-mode bypassPermissions"
    break
  else
    HUNT_TARGET="$T" HUNT_SID="$SID" claude -p "$PROMPT" \
      --model "$MODEL" --permission-mode bypassPermissions ${FLEET_CLAUDE_ARGS:-} || true
  fi
  dur=$(( $(date +%s) - start ))
  "$FLEET" stopped "$T" >/dev/null 2>&1 && { echo "[$T] stopped after run -> exiting"; break; }
  if [ "$dur" -lt 20 ]; then fails=$((fails+1)); else fails=0; fi
  if [ "$fails" -ge 5 ]; then echo "[$T] 5 fast exits in a row (crash-loop) -> giving up"; break; fi
  wait=$(( fails*5 + 3 )); echo "[$T] session ended (${dur}s); relaunch in ${wait}s (fails=$fails)"; sleep "$wait"
done
