#!/usr/bin/env bash
# hunt-fleet.sh - single source of truth for "which agent owns which target".
#
# Problem it solves: the hunt loop had ONE global LOCK file naming ONE program, so a
# second parallel session clobbered the first. This gives every session its OWN target
# binding and an ATOMIC claim so two agents never hunt the same program at once.
#
# Identity: a session is a (target, sid) pair. sid defaults to $HUNT_SID, else
# $CLAUDE_SESSION_ID, else the pid. "Which target am I?" resolves env HUNT_TARGET first
# (set by the launcher, per-process, zero contention), then this registry, then the
# legacy global LOCK (so a plain single session behaves exactly as before).
#
# Bulletproof bits:
#  - claim uses mkdir (a single atomic syscall) as the mutex: only one racer wins.
#  - a crashed agent self-heals: its claim goes stale (dead pid AND old heartbeat) and
#    the next claimer steals it. No target stays wedged.
#  - all reads/writes are single small files; no read-modify-write on shared state.
#
# Run `hunt-fleet.sh selftest` to verify the locking logic.
set -u

ROOT="${HUNT_FLEET_ROOT:-${GNOC_WORKSPACE:-$HOME/.gnoc}}"
FLEET="${HUNT_FLEET_DIR:-$ROOT/.claude/state/hunt-loop/fleet}"
LEGACY_LOCK="$ROOT/.claude/state/hunt-loop/LOCK"
LEGACY_STOP="$ROOT/.claude/state/hunt-loop/STOP"
TTL="${HUNT_FLEET_TTL:-1800}"          # a claim with no live pid and no beat < TTL sec is stale
CLAIMS="$FLEET/claims"; SESS="$FLEET/sessions"; STOPS="$FLEET/stops"
mkdir -p "$CLAIMS" "$SESS" "$STOPS" 2>/dev/null || true

now()  { date +%s; }
host() { hostname 2>/dev/null || echo localhost; }
me()   { echo "${HUNT_SID:-${CLAUDE_CODE_SESSION_ID:-${CLAUDE_SESSION_ID:-$$}}}"; }   # real env var is CLAUDE_CODE_SESSION_ID
slug() { printf '%s' "$1" | tr -dc 'a-zA-Z0-9_.-'; }   # target names are filesystem-safe

_read() { cat "$1" 2>/dev/null || true; }

is_alive() {   # is_alive <target> ; 0=alive 1=dead/free
  local t; t=$(slug "$1"); local d="$CLAIMS/$t"
  [ -d "$d" ] || return 1
  local h p b; h=$(_read "$d/host"); p=$(_read "$d/pid"); b=$(_read "$d/beat")
  if [ "$h" = "$(host)" ] && [ -n "$p" ] && kill -0 "$p" 2>/dev/null; then return 0; fi
  b=$((b + 0)); [ "$b" -gt 0 ] && [ $(( $(now) - b )) -lt "$TTL" ] && return 0
  return 1
}

owner() { _read "$CLAIMS/$(slug "$1")/owner"; }   # empty if unclaimed

gc() {   # reap stale claim dirs + dangling session pointers
  local d t mt
  for d in "$CLAIMS"/*/; do
    [ -d "$d" ] || continue
    t=$(basename "$d")
    if [ -s "$d/owner" ]; then
      is_alive "$t" || rm -rf "$d" 2>/dev/null           # normal: dead owner -> reap
    else
      # half-written claim (mkdir done, owner not yet): reap ONLY once clearly abandoned,
      # so we never race-reap a claim that is mid-write in another process.
      mt=$(stat -c %Y "$d" 2>/dev/null || echo 0)
      [ $(( $(now) - mt )) -gt 15 ] && rm -rf "$d" 2>/dev/null
    fi
  done
  for f in "$SESS"/*; do
    [ -f "$f" ] || continue
    t=$(_read "$f"); [ -n "$t" ] && [ -d "$CLAIMS/$(slug "$t")" ] || rm -f "$f" 2>/dev/null
  done
}

_write_claim() {   # _write_claim <target> <sid>
  local t s d; t=$(slug "$1"); s="$2"; d="$CLAIMS/$t"
  printf '%s' "$s"        > "$d/owner"
  printf '%s' "$$"        > "$d/pid"        # pid of THIS process; launcher overwrites with claude pid
  printf '%s' "$(host)"   > "$d/host"
  printf '%s' "$(now)"    > "$d/beat"
  [ -f "$d/since" ] || date '+%Y-%m-%d %H:%M' > "$d/since"
  printf '%s' "$1"        > "$SESS/$(slug "$s")"   # reverse pointer (raw target name)
}

cmd_claim() {   # claim <target> [sid] [pid]
  local t s pid; t="${1:?usage: claim <target> [sid]}"; s="${2:-$(me)}"; pid="${3:-}"
  local ts; ts=$(slug "$t"); local d="$CLAIMS/$ts"
  gc
  if mkdir "$d" 2>/dev/null; then
    _write_claim "$t" "$s"; [ -n "$pid" ] && printf '%s' "$pid" > "$d/pid"
    echo "CLAIMED $t -> $s"; return 0
  fi
  local cur; cur=$(owner "$t")
  if [ "$cur" = "$s" ]; then
    printf '%s' "$(now)" > "$d/beat"; [ -n "$pid" ] && printf '%s' "$pid" > "$d/pid"
    echo "REENTRANT $t -> $s"; return 0
  fi
  if [ -z "$cur" ]; then
    # dir exists but no owner written yet = another process is mid-claim. Never steal it.
    echo "TAKEN $t (claim in progress)"; return 1
  fi
  if is_alive "$t"; then
    echo "TAKEN $t owned by ${cur:-?} (alive)"; return 1
  fi
  # stale owner -> steal atomically enough (dir already exists; overwrite the metadata)
  _write_claim "$t" "$s"; [ -n "$pid" ] && printf '%s' "$pid" > "$d/pid"
  echo "STOLEN $t -> $s (previous owner ${cur:-?} was dead)"; return 0
}

cmd_release() {   # release [target] [sid]
  local s t; s="${2:-$(me)}"; t="${1:-}"
  [ -z "$t" ] && t=$(_read "$SESS/$(slug "$s")")
  [ -z "$t" ] && { echo "nothing to release for $s"; return 0; }
  local cur; cur=$(owner "$t")
  if [ -n "$cur" ] && [ "$cur" != "$s" ]; then echo "NOT-OWNER $t owned by $cur, refusing"; return 1; fi
  rm -rf "$CLAIMS/$(slug "$t")" 2>/dev/null; rm -f "$SESS/$(slug "$s")" 2>/dev/null
  echo "RELEASED $t"
}

cmd_current() {   # current [sid]  -> the target this session should hunt
  local s; s="${1:-$(me)}"
  if [ -n "${HUNT_TARGET:-}" ]; then echo "$HUNT_TARGET"; return 0; fi
  local t; t=$(_read "$SESS/$(slug "$s")")
  if [ -n "$t" ]; then echo "$t"; return 0; fi
  # legacy fallback: the old global single-target LOCK
  if [ -s "$LEGACY_LOCK" ]; then
    grep -vE '^[[:space:]]*#' "$LEGACY_LOCK" 2>/dev/null | awk 'NF{print $1; exit}'
  fi
}

cmd_beat() {   # beat [target] [sid]
  local s t; s="${2:-$(me)}"; t="${1:-${HUNT_TARGET:-}}"
  [ -z "$t" ] && t=$(_read "$SESS/$(slug "$s")")
  [ -z "$t" ] && return 0
  local d="$CLAIMS/$(slug "$t")"; [ -d "$d" ] && printf '%s' "$(now)" > "$d/beat"
}

cmd_stop()    { touch "$STOPS/$(slug "${1:?usage: stop <target>}")"; echo "STOPPED $1"; }
cmd_resume()  { rm -f "$STOPS/$(slug "${1:?usage: resume <target>}")"; echo "RESUMED $1"; }
cmd_stopped() {   # stopped [target] ; exit 0 if this target OR the global STOP is set
  [ -f "$LEGACY_STOP" ] && return 0
  local t; t="${1:-${HUNT_TARGET:-$(cmd_current)}}"
  [ -n "$t" ] && [ -f "$STOPS/$(slug "$t")" ]
}

cmd_owned_by_others() {   # print targets currently claimed by a LIVE session other than me
  local s; s="${1:-$(me)}"; gc
  local d t cur
  for d in "$CLAIMS"/*/; do
    [ -d "$d" ] || continue; t=$(basename "$d"); cur=$(_read "$d/owner")
    [ "$cur" = "$s" ] && continue
    is_alive "$t" && echo "$t"
  done
}

cmd_list() {
  gc
  local d t cur pid beat st age al
  printf '%-24s %-14s %-8s %-7s %-6s %s\n' TARGET OWNER PID AGE STATE STOP
  for d in "$CLAIMS"/*/; do
    [ -d "$d" ] || continue
    t=$(basename "$d"); cur=$(_read "$d/owner"); pid=$(_read "$d/pid"); beat=$(_read "$d/beat")
    beat=$((beat + 0)); age=$(( $(now) - beat )); [ "$beat" -eq 0 ] && age=-1
    is_alive "$t" && al=alive || al=STALE
    [ -f "$STOPS/$t" ] && st=STOP || st=-
    printf '%-24s %-14s %-8s %-7s %-6s %s\n' "$t" "${cur:0:14}" "${pid:-?}" "${age}s" "$al" "$st"
  done
  [ -z "$(ls -A "$CLAIMS" 2>/dev/null)" ] && echo "(no active claims)"
}

selftest() {
  local tmp; tmp=$(mktemp -d)
  ( export HUNT_FLEET_DIR="$tmp/fleet" HUNT_FLEET_ROOT="$tmp" HUNT_SID=""; unset HUNT_TARGET CLAUDE_SESSION_ID CLAUDE_CODE_SESSION_ID
    fail() { echo "FAIL: $1"; exit 1; }
    # 1) first claim wins
    HUNT_SID=alice "$0" claim demoA >/dev/null || fail "alice claim demoA"
    # 2) a live different owner is refused
    HUNT_SID=bob   "$0" claim demoA >/dev/null 2>&1 && fail "bob should be refused (alice alive)" || true
    # 3) re-entrant claim by same owner ok
    HUNT_SID=alice "$0" claim demoA >/dev/null || fail "alice reentrant"
    # 4) current resolves the pointer
    [ "$(HUNT_SID=alice "$0" current)" = "demoA" ] || fail "current!=demoA"
    # 5) env HUNT_TARGET overrides
    [ "$(HUNT_TARGET=demoZ HUNT_SID=alice "$0" current)" = "demoZ" ] || fail "env override"
    # 6) steal a STALE claim (dead pid + zero beat)
    printf '%s' 999999 > "$tmp/fleet/claims/demoA/pid"; printf '%s' 0 > "$tmp/fleet/claims/demoA/beat"
    HUNT_SID=bob "$0" claim demoA >/dev/null || fail "bob steal stale demoA"
    [ "$(HUNT_SID=bob "$0" current)" = "demoA" ] || fail "steal did not rebind owner"
    # 7) per-target stop + global stop
    HUNT_SID=bob "$0" stop demoA >/dev/null; HUNT_TARGET=demoA "$0" stopped || fail "per-target stop"
    HUNT_TARGET=other "$0" stopped 2>/dev/null && fail "unrelated target should not be stopped" || true
    # 8) release frees it
    HUNT_SID=bob "$0" release demoA >/dev/null || fail "release"
    HUNT_SID=carol "$0" claim demoA >/dev/null || fail "carol claim after release"
    # 9) owned-by-others excludes self, includes live others
    HUNT_SID=dave "$0" claim demoB >/dev/null || fail "dave claim demoB"
    [ "$(HUNT_SID=carol "$0" owned-by-others | sort | tr '\n' ' ')" = "demoB " ] || fail "owned-by-others"
    echo "SELFTEST OK"
  )
  local rc=$?; rm -rf "$tmp"; return $rc
}

sub="${1:-list}"; shift 2>/dev/null || true
case "$sub" in
  claim)            cmd_claim "$@";;
  release)          cmd_release "$@";;
  current)          cmd_current "$@";;
  beat)             cmd_beat "$@";;
  owner)            owner "${1:?usage: owner <target>}";;
  stop)             cmd_stop "$@";;
  resume)           cmd_resume "$@";;
  stopped)          cmd_stopped "$@";;
  owned-by-others)  cmd_owned_by_others "$@";;
  gc)               gc; echo "gc done";;
  list|status|ls)   cmd_list;;
  selftest|test)    selftest;;
  *) echo "usage: hunt-fleet.sh {claim|release|current|beat|owner|stop|resume|stopped|owned-by-others|list|gc|selftest}" >&2; exit 2;;
esac
