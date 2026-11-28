#!/usr/bin/env bash
# lock.sh - per-session hunt-loop LOCK CLI for the main agent.
#
#   scripts/hunt-loop/lock.sh set <handle>   pin THIS session to <handle>  (writes LOCK.<session_id>)
#   scripts/hunt-loop/lock.sh clear          unpin THIS session
#   scripts/hunt-loop/lock.sh get            print the effective locked handle for THIS session
#   scripts/hunt-loop/lock.sh file           print the effective lock FILE path for THIS session
#   scripts/hunt-loop/lock.sh status         human-readable: sid, effective file, handle
#
# The session id comes from $CLAUDE_CODE_SESSION_ID (the agent's own shell has it). Parallel
# sessions therefore each pin their OWN target and never stomp each other. The global LOCK stays
# as a legacy fallback, so a lone session behaves exactly as before. HUNT_TARGET (fleet) wins over
# both. This is the SINGLE-NAMED-TARGET pin from CLAUDE.md, made per-session.
set -u
. "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/hunt-loop/lock-lib.sh"

cmd="${1:-status}"
case "$cmd" in
  set)
    [ -n "${2:-}" ] || { echo "usage: lock.sh set <handle>" >&2; exit 2; }
    hl_lock_set "$2"
    hl_lock_gc 2>/dev/null || true
    echo "locked THIS session -> $2   (file: $(hl_lock_file))"
    ;;
  clear)
    hl_lock_clear
    echo "cleared THIS session lock   (effective now: $(hl_lock_target 2>/dev/null || echo none))"
    ;;
  get)   hl_lock_target ;;
  file)  hl_lock_file ;;
  status)
    printf 'session=%s\nfile=%s\nhandle=%s\nHUNT_TARGET=%s\n' \
      "$(_hl_sid)" "$(hl_lock_file)" "$(hl_lock_target 2>/dev/null)" "${HUNT_TARGET:-}"
    ;;
  *) echo "usage: lock.sh set <handle>|clear|get|file|status" >&2; exit 2 ;;
esac
