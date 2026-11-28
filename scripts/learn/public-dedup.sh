#!/usr/bin/env bash
# public-dedup.sh - FIX 2 (2026-07-19). PUBLIC prior-art dedup ledger writer.
#
# The dedup-scout (or the orchestrator) runs the actual WebFetch queries against H1 hacktivity /
# GHSA / google site:hackerone.com PRE-PROBE (SPINE 0b "DEDUP BEFORE FIRST PROBE"), then records a
# VERIFIED verdict per (program, host, class, endpoint) here. The draft-write gate later READS this
# ledger (read-only) to verify the query happened and to HARD-BLOCK a confirmed public duplicate.
# The network work stays in the worker's scoped WebFetch; this helper only appends a ledger line and
# prints the exact stamp string to paste into the draft header.
#
# Usage:
#   public-dedup.sh <program> <host> <class> <endpoint> --result none
#   public-dedup.sh <program> <host> <class> <endpoint> --result MATCH:#412011
#   public-dedup.sh <program> <host> <class> <endpoint> --result NOVEL:fixbypass
#   ... or pipe the WebFetch findings on stdin and omit --result (recorded as note, result=none).
#
# MATCH threshold (what counts as a real public dupe): a disclosed/hacktivity/GHSA report for the
# SAME program AND (same host OR same endpoint path) AND same class, cited by a concrete prior #NNNN
# or GHSA id. Host-only or class-only overlap is NOT a match. NOVEL angle re-opens a known bug:
# chain (new terminal), fixbypass (bypasses the prior fix), newversion (new asset/version).
set -u

LEDGER="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/public-dedup.jsonl"

if [ "${1:-}" = "--selftest" ]; then
  T=$(mktemp); LEDGER="$T"
  export PUBLIC_DEDUP_LEDGER="$T"
  echo "(selftest ledger: $T)"
  bash "$0" tprog a.com idor "/obj/{id}" --result none >/dev/null 2>&1 || true
  tail -1 "$T" | grep -q '"result":"none"' && echo "ok: none line written" || echo "FAIL: none line"
  rm -f "$T"; exit 0
fi

# allow test override of the ledger path
[ -n "${PUBLIC_DEDUP_LEDGER:-}" ] && LEDGER="$PUBLIC_DEDUP_LEDGER"

if [ "$#" -lt 4 ]; then
  echo "usage: public-dedup.sh <program> <host> <class> <endpoint> [--result none|MATCH:#NNNN|NOVEL:<angle>]" >&2
  exit 1
fi
command -v jq >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }

PROGRAM="$1"; HOST="$2"; CLASS="$3"; ENDPOINT="$4"; shift 4
RESULT="none"; PRIOR=""; ANGLE=""; NOTE=""

# parse --result if present
while [ "$#" -gt 0 ]; do
  case "$1" in
    --result)
      shift; RAW="${1:-none}"
      case "$RAW" in
        MATCH:*)  RESULT="MATCH"; PRIOR="${RAW#MATCH:}" ;;
        NOVEL:*)  RESULT="NOVEL"; ANGLE="${RAW#NOVEL:}" ;;
        none|NONE) RESULT="none" ;;
        *) RESULT="none"; NOTE="$RAW" ;;
      esac
      ;;
    --result=*)
      RAW="${1#--result=}"
      case "$RAW" in
        MATCH:*)  RESULT="MATCH"; PRIOR="${RAW#MATCH:}" ;;
        NOVEL:*)  RESULT="NOVEL"; ANGLE="${RAW#NOVEL:}" ;;
        *) RESULT="none"; NOTE="$RAW" ;;
      esac
      ;;
  esac
  shift
done

# validate NOVEL angle is one of the recognised carve-outs (else demote to a note, keep result=NOVEL)
case "$RESULT" in
  NOVEL)
    case "$ANGLE" in chain|fixbypass|newversion) : ;; *) NOTE="unrecognised-angle:$ANGLE"; ;; esac ;;
esac

# fold any stdin (the pasted WebFetch findings) into the note, capped
if [ ! -t 0 ]; then
  IN=$(timeout 2 cat 2>/dev/null | head -c 600 | tr '\n' ' ' | tr -d '\000-\010\013\014\016-\037' || true)
  [ -n "$IN" ] && NOTE="${NOTE:+$NOTE; }$IN"
fi

TS=$(date +%s 2>/dev/null || echo 0)
mkdir -p "$(dirname "$LEDGER")" 2>/dev/null
jq -nc \
  --argjson ts "$TS" --arg program "$PROGRAM" --arg host "$HOST" --arg class "$CLASS" \
  --arg endpoint "$ENDPOINT" --arg result "$RESULT" --arg prior "$PRIOR" --arg angle "$ANGLE" \
  --arg note "$NOTE" \
  '{ts:$ts,program:$program,host:$host,class:$class,endpoint:$endpoint,result:$result,prior:$prior,angle:$angle,note:$note}' \
  >> "$LEDGER" 2>/dev/null

# print the exact stamp the orchestrator pastes into the draft header
TODAY=$(date +%Y-%m-%d 2>/dev/null || echo "")
case "$RESULT" in
  MATCH) STAMP="Dedup: public-checked $TODAY (dup${PRIOR})" ;;
  NOVEL) STAMP="Dedup: public-checked $TODAY (novel:${ANGLE})" ;;
  *)     STAMP="Dedup: public-checked $TODAY (none)" ;;
esac
echo "$STAMP"
[ "$RESULT" = "MATCH" ] && echo "PUBLIC DUPLICATE recorded: ${PRIOR} for ${PROGRAM} on ${HOST} ${ENDPOINT} (${CLASS}) - the draft-write gate will HARD-BLOCK a draft for this surface." >&2
exit 0
