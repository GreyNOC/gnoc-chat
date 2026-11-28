#!/usr/bin/env bash
# hunt-fleet-launch.sh - launch/monitor several hunt agents, one per target, in parallel.
#
# Each agent runs in its own tmux window, pinned to one program (HUNT_TARGET), claim-guarded
# so two agents never hunt the same program. Attach to watch; stop gracefully or kill hard.
#
#   hunt-fleet-launch.sh <t1> [t2 ...]   launch these targets (must have targets/<t>/SCOPE.txt)
#   hunt-fleet-launch.sh -n <N>          launch the top-N onboarded targets from priority.txt
#   hunt-fleet-launch.sh --list          fleet status (who owns what, alive/stale)
#   hunt-fleet-launch.sh --attach        tmux attach to the fleet
#   hunt-fleet-launch.sh --stop <t>      set stop flag (agent finishes its run then exits)
#   hunt-fleet-launch.sh --kill <t>      kill the window now and release the claim
#   hunt-fleet-launch.sh --stop-all      stop every agent gracefully
#   hunt-fleet-launch.sh --selftest      dry-run launch logic without starting claude
set -u
ROOT="${HUNT_FLEET_ROOT:-${GNOC_WORKSPACE:-$HOME/.gnoc}}"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"                # scripts are siblings of this file
FLEET="$SELF_DIR/hunt-fleet.sh"
WORKER="$SELF_DIR/hunt-fleet-worker.sh"
SESSION="${FLEET_TMUX:-huntfleet}"
cd "$ROOT" 2>/dev/null || { echo "no workspace at $ROOT" >&2; exit 1; }

win_name() { printf '%s' "$1" | tr -c 'a-zA-Z0-9_.-' '_'; }   # tmux-safe window name

spawn() {   # spawn <target>
  local t="$1" w; w=$(win_name "$t")
  if [ ! -s "targets/$t/SCOPE.txt" ]; then
    echo "SKIP $t: no targets/$t/SCOPE.txt (onboard it first: scripts/*-scope.sh)"; return 1
  fi
  if printf '%s\n' "$("$FLEET" owned-by-others "__launcher__" 2>/dev/null)" | grep -qxF "$t"; then
    echo "SKIP $t: already owned by a live session"; return 1   # worker also hard-guards
  fi
  if [ "${FLEET_DRY_RUN:-0}" = "1" ]; then
    FLEET_DRY_RUN=1 "$WORKER" "$t"; return $?
  fi
  if ! tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux new-session -d -s "$SESSION" -n "$w" "$WORKER" "$t"
  else
    tmux new-window -t "$SESSION" -n "$w" "$WORKER" "$t"
  fi
  echo "LAUNCHED $t (tmux $SESSION:$w)"
}

case "${1:-}" in
  ""|-h|--help) sed -n '2,17p' "$0"; exit 0;;
  --list|--status) "$FLEET" list; exit 0;;
  --attach) exec tmux attach -t "$SESSION";;
  --stop)  "$FLEET" stop "${2:?--stop <target>}"; echo "stop flag set; agent exits after its current run"; exit 0;;
  --kill)
    t="${2:?--kill <target>}"; tmux kill-window -t "$SESSION:$(win_name "$t")" 2>/dev/null
    "$FLEET" release "$t" "fleet:$t" >/dev/null 2>&1; "$FLEET" stop "$t" >/dev/null 2>&1
    echo "killed + released $t"; exit 0;;
  --stop-all)
    "$FLEET" list | awk 'NR>1 && $1!~/no active/{print $1}' | while read -r t; do "$FLEET" stop "$t"; done
    echo "all agents flagged to stop"; exit 0;;
  --selftest)
    tmp=$(mktemp -d); mkdir -p "$tmp/targets/aaa" "$tmp/targets/bbb"
    echo scope > "$tmp/targets/aaa/SCOPE.txt"; echo scope > "$tmp/targets/bbb/SCOPE.txt"
    out=$(HUNT_FLEET_ROOT="$tmp" HUNT_FLEET_DIR="$tmp/fleet" FLEET_DRY_RUN=1 bash "$0" aaa bbb 2>&1)
    n=$(printf '%s\n' "$out" | grep -c "DRY_RUN would launch")
    [ "$n" -eq 2 ] || { echo "FAIL: expected 2 dry-run launches, got $n"; echo "$out"; rm -rf "$tmp"; exit 1; }
    out2=$(HUNT_FLEET_ROOT="$tmp" HUNT_FLEET_DIR="$tmp/fleet" FLEET_DRY_RUN=1 bash "$0" ccc 2>&1)
    printf '%s\n' "$out2" | grep -q "SKIP ccc" || { echo "FAIL: missing-scope target not skipped"; rm -rf "$tmp"; exit 1; }
    rm -rf "$tmp"; echo "SELFTEST OK"; exit 0;;
  -n)
    n="${2:?-n <N>}"; mapfile -t picks < <(
      grep -vE '^[[:space:]]*#' "$ROOT/.claude/state/hunt-loop/priority.txt" 2>/dev/null \
        | awk 'NF{print $1}' | head -n "$n")
    [ "${#picks[@]}" -eq 0 ] && { echo "priority.txt empty; pass target names explicitly"; exit 1; }
    for t in "${picks[@]}"; do spawn "$t"; done
    echo; "$FLEET" list; exit 0;;
  --*) echo "unknown option $1 (see --help)" >&2; exit 2;;
  *)
    for t in "$@"; do spawn "$t"; done
    echo; "$FLEET" list; exit 0;;
esac
