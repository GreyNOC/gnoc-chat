#!/usr/bin/env bash
# lock-lib.sh - sourceable resolver for the hunt-loop LOCK, keyed PER SESSION.
#
# Problem (the operator 2026-07-19): the global .claude/state/hunt-loop/LOCK is ONE file, so two
# parallel main-session agents stomp each other's single-target pin. Fix: key the LOCK by
# session id, with the global file kept as a legacy fallback.
#
# Precedence (highest first) - "what ONE target is THIS session pinned to":
#   1. HUNT_TARGET env      - the fleet launcher's per-PROCESS pin (unchanged).
#   2. LOCK.<session_id>    - THIS session's own lock file (NEW, the per-session isolation).
#   3. LOCK (global)        - legacy single-session fallback; a lone session or anything that
#                             never set a per-session lock behaves EXACTLY as before.
#
# Session id: an explicit first arg (hooks pass the payload .session_id) else the environment
# ($CLAUDE_CODE_SESSION_ID is present in the agent's own shell and inherited by hooks/scripts of
# the same session; CLAUDE_SESSION_ID / HUNT_SID are also honored as fallbacks).
#
# Pure, read-mostly, fail-safe: every function degrades to the global LOCK when no sid is known.

_HL_STATE="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop"

# Normalize a session id to a safe filename fragment ('' if none resolvable).
_hl_sid() {
  printf '%s' "${1:-${CLAUDE_CODE_SESSION_ID:-${CLAUDE_SESSION_ID:-${HUNT_SID:-}}}}" \
    | tr -c 'A-Za-z0-9_.-' '_' | cut -c1-80
}

# Effective lock FILE to READ (the per-session file if it exists and is non-empty, else global).
hl_lock_file() {
  local sid; sid="$(_hl_sid "${1:-}")"
  if [ -n "$sid" ] && [ "$sid" != "_" ] && [ -s "$_HL_STATE/LOCK.$sid" ]; then
    printf '%s\n' "$_HL_STATE/LOCK.$sid"
  else
    printf '%s\n' "$_HL_STATE/LOCK"
  fi
}

# Effective locked HANDLE for this session (HUNT_TARGET wins; else the first non-comment token
# of the effective lock file; else empty).
hl_lock_target() {
  if [ -n "${HUNT_TARGET:-}" ]; then printf '%s\n' "$HUNT_TARGET"; return 0; fi
  local f; f="$(hl_lock_file "${1:-}")"
  [ -s "$f" ] && grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | awk 'NF{print $1; exit}'
}

# WRITE this session's lock. Per-session file when a sid is known, else the legacy global file.
hl_lock_set() {
  local handle="$1"; local sid; sid="$(_hl_sid "${2:-}")"
  mkdir -p "$_HL_STATE" 2>/dev/null
  if [ -n "$sid" ] && [ "$sid" != "_" ]; then
    printf '%s\n' "$handle" > "$_HL_STATE/LOCK.$sid"
  else
    printf '%s\n' "$handle" > "$_HL_STATE/LOCK"
  fi
}

# CLEAR this session's lock. Removes the per-session file; if no sid is known, empties the
# legacy global file (preserving single-session semantics).
hl_lock_clear() {
  local sid; sid="$(_hl_sid "${1:-}")"
  if [ -n "$sid" ] && [ "$sid" != "_" ]; then
    rm -f "$_HL_STATE/LOCK.$sid" 2>/dev/null
  else
    : > "$_HL_STATE/LOCK" 2>/dev/null
  fi
}

# GC: drop per-session lock files with no live tmux/fleet owner (best-effort, never fails).
# A stale LOCK.<sid> is harmless (only that dead session would have read it), but sweep so the
# state dir does not accumulate. Called opportunistically by the CLI.
hl_lock_gc() {
  local f sid
  for f in "$_HL_STATE"/LOCK.*; do
    [ -e "$f" ] || continue
    sid="${f##*/LOCK.}"
    # keep files touched in the last 24h; older ones are almost certainly dead sessions
    [ -n "$(find "$f" -mmin -1440 2>/dev/null)" ] || rm -f "$f" 2>/dev/null
  done
}
