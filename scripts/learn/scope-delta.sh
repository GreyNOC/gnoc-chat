#!/usr/bin/env bash
# scope-delta.sh - detect new in-scope hosts and queue them for a fresh sweep.
#
# WHY THIS EXISTS (root-cause fix, 2026-07-09):
# On a live multi-tenant SaaS "dead" is a TIMESTAMP, not a property. The vendor
# ships new tenants and patches old ones constantly. Every paid massive crit was
# a DEPLOY-PATH defect (open dev-IdP signup, unsigned-SAML) that recurs on each
# fresh tenant BEFORE hardening. Scope grew +1777 hosts on 2026-07-08 and NOTHING
# machine-detected it - only a human memory noted it. This closes gap (d): diff
# SCOPE.txt against a snapshot, emit the NEW hosts as a fresh-hunt queue tagged
# with the program's known paid tells. A new host is an un-patched instance.
#
# Composes with: fresh-rehunt.sh (archives dead state), do-not-rehunt (suppresses
# TRUE-dead). This adds the missing FRESHNESS signal. Cheap + idempotent: run at
# session start, from cron, or by hand. No network, read-only except its snapshot.
#
# Usage:  scope-delta.sh [<handle>]     # one program, or omit for ALL under targets/
set -euo pipefail

QUIET=0
if [ "${1:-}" = "-q" ] || [ "${1:-}" = "--quiet" ]; then QUIET=1; shift; fi
# quiet suppresses "no delta"/"baseline"/"skip" chatter; real deltas still print.
info() { [ "$QUIET" = 1 ] || echo "$@"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SNAP_DIR="$ROOT/.claude/state/scope-snapshots"
mkdir -p "$SNAP_DIR"
DATE="$(date +%Y%m%d)"

# host lines only: strip comments, blanks, CR, surrounding whitespace; sort-uniq.
# `|| true` on grep: an all-comment/empty SCOPE.txt makes grep -v exit 1, which under
# pipefail would kill the caller. An empty host set is valid, not an error.
hosts() { { grep -vE '^\s*(#|$)' "$1" || true; } | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sort -u; }

scan() {
  local handle="$1"
  local scope="$ROOT/targets/$handle/SCOPE.txt"
  [ -f "$scope" ] || { info "[$handle] no SCOPE.txt, skip"; return; }
  local snap="$SNAP_DIR/$handle.txt"
  local cur
  cur="$(hosts "$scope")"

  if [ ! -f "$snap" ]; then
    printf '%s\n' "$cur" > "$snap"
    echo "[$handle] baseline set ($(printf '%s\n' "$cur" | grep -c . || true) hosts) - no delta on first run"
    return
  fi

  local added removed
  added="$(comm -13 "$snap" <(printf '%s\n' "$cur") || true)"
  removed="$(comm -23 "$snap" <(printf '%s\n' "$cur") || true)"
  printf '%s\n' "$cur" > "$snap"   # always advance snapshot so removals don't re-alert

  local nadd; nadd="$(printf '%s\n' "$added" | grep -c . || true)"
  local nrem; nrem="$(printf '%s\n' "$removed" | grep -c . || true)"

  if [ "$nadd" -eq 0 ] && [ "$nrem" -eq 0 ]; then
    info "[$handle] no scope delta"
    return
  fi

  echo "[$handle] SCOPE DELTA: +$nadd new host(s), -$nrem removed"
  if [ "$nadd" -gt 0 ]; then
    local q="$ROOT/targets/$handle/scope-delta-$DATE.txt"
    {
      echo "# NEW in-scope hosts detected $DATE - FRESH un-hardened surface, sweep BEFORE the vendor patches."
      echo "# A new tenant/pod is an un-patched instance of any deploy-path defect. Run the program's paid tells first:"
      if [ -f "$ROOT/targets/$handle/paid-tells.txt" ]; then
        sed 's/^/#   /' "$ROOT/targets/$handle/paid-tells.txt"
      else
        echo "#   (no paid-tells.txt yet - add one listing the cheap confirm-signal per paid class)"
      fi
      printf '%s\n' "$added"
    } > "$q"
    echo "  -> queue: $q"
    printf '%s\n' "$added" | sed 's/^/     + /' | head -20
    [ "$nadd" -gt 20 ] && echo "     ... (+$((nadd-20)) more in the queue file)" || true
  fi
  if [ "$nrem" -gt 0 ]; then
    echo "  removed (now OOS, do not probe):"
    printf '%s\n' "$removed" | sed 's/^/     - /' | head -10
  fi
  return 0
}

if [ $# -ge 1 ]; then
  scan "$1"
else
  for d in "$ROOT"/targets/*/; do
    [ -f "$d/SCOPE.txt" ] && scan "$(basename "$d")"
  done
fi
