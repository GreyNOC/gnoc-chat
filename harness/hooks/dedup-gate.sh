#!/usr/bin/env bash
#
# dedup-gate.sh - PreToolUse hook for Bash | WebFetch | Burp MCP send_http.
#
# Blocks a probe that re-hits a vector already marked RECEIPT-DEAD / OUT-OF-SCOPE
# in the ACTIVE program's do-not-rehunt index. This is the #1 efficiency leak
# the 2026-06-22 audit (and the workspace retrospective) found: 62% of negative
# closes were self-dupe re-finds, the index already existed and was correct, but
# NO PreToolUse gate consulted it before a probe fired - dedup ran only at draft
# time, after the cycle (and the 1.9G fork DB) was already burned. This is that
# missing gate. It mirrors scope-gate.sh in shape and fail-open philosophy.
#
# Match handle: do-not-rehunt lines carry DISTINCTIVE tokens verbatim - GraphQL
# Query/Mutation op names (RefreshMetadataMutation), unusual REST path segments
# (onboarding-signup, simulate). A probe whose command contains such a token AND
# whose token sits on a DEAD (non-live) line for THIS program is a near-certain
# re-grind -> advisory nudge (additionalContext, not a hard block) and hand back the receipt line so the agent pivots
# to fresh ground instead of re-burning the cycle.
#
# Scope of enforcement: the active program's PER-TARGET index files only
# (targets/<prog>/do-not-rehunt.{txt,md}, targets/<prog>/hunts/do-not-rehunt.md).
# The cross-program global index is deliberately NOT consulted for blocking - a
# token dead for program Y must never block a live probe for program X.
#
# FAIL-OPEN (exit 0, never block) on: no jq/payload/parse-error, no active
# run-bound program, no per-target index, no distinctive token, only generic
# tokens, or a match that lands on a LIVE/LEAD/PARKED line. Design rule (same as
# scope-gate): a buggy gate that halts a live session is worse than a missed
# re-grind. Every uncertain path exits 0.
#
# Self-test:  .claude/hooks/dedup-gate.sh --selftest
set -u

# Generic web words that are too common to be a reliable dead-vector handle.
GENERIC='^(graphql|frontend|backend|static|public|assets|images?|index|common|wrapper|healthz|metrics|favicon|robots|sitemap|accounts?|profiles?|search|settings|passwords?|register|login|logout|signup|signin|uploads?|callback|redirect|dashboard|version|health|config|api[0-9]*|webhooks?)$'
# Status markers that mean DEAD (do not re-grind).
DEADRE='RECEIPT-DEAD|OUT-OF-SCOPE|DEAD-with|DEAD-EXTERNAL|GATE1-FAIL|KYC-DEAD|I:N CONFIRMED'
# Status markers that mean STILL LIVE (re-probing is allowed; never block these).
LIVERE='LIVE-|LEAD|PARKED|PENDING|one-probe-away|one-receipt-away'

# distinctive_tokens <text> : print de-duped distinctive tokens, generic-filtered.
#   - CamelCase op names with >=2 humps (RefreshMetadataMutation)
#   - URL path segments of >=6 chars (onboarding-signup)
distinctive_tokens() {
  { printf '%s' "$1" | grep -oE '[A-Z][a-z]+([A-Z][a-z0-9]+)+' 2>/dev/null
    printf '%s' "$1" | grep -oE '/[a-zA-Z][a-zA-Z0-9._-]{5,}' 2>/dev/null | sed 's#^/##'
  } | sort -u | grep -ivE "$GENERIC" 2>/dev/null
}

# dedup_hit <text> <indexfile> : if a distinctive token of <text> sits on a DEAD
# (non-live) line of <indexfile>, print "<token>\t<line>" and return 0.
dedup_hit() {
  local txt="$1" idx="$2" prog="${3:-}" tok hit deadlines cnt
  [ -f "$idx" ] || return 1
  while IFS= read -r tok; do
    [ -z "$tok" ] && continue
    [ "${#tok}" -lt 6 ] && continue
    # Structural tokens are never a dead-VECTOR handle: the program handle itself
    # and workspace scaffolding dir names sit on the index as path/bookkeeping
    # text, not as the vector. Skipping them stops a genuinely-new probe from
    # being path-string-blocked just because its command names the cwd/host.
    case "$tok" in
      "$prog"|targets|hunts|reports|drafts|submitted|evidence|recon|patterns|salvage|scripts|state) continue ;;
    esac
    deadlines=$(grep -F -- "$tok" "$idx" 2>/dev/null | grep -iE "$DEADRE" 2>/dev/null | grep -ivE "$LIVERE" 2>/dev/null)
    cnt=$(printf '%s\n' "$deadlines" | grep -c . 2>/dev/null || true)
    [ "${cnt:-0}" -eq 0 ] && continue
    # A token on MANY dead lines is structural (a hostname/apex, a recurring path
    # component, the handle) - never a specific vector handle, so never block on
    # it. A real dead op-name / unusual path sits on 1-few lines. (Fail-open: a
    # missed re-grind beats halting a live session on a path-word collision.)
    [ "${cnt:-0}" -gt 4 ] && continue
    hit=$(printf '%s\n' "$deadlines" | head -1)
    if [ -n "$hit" ]; then printf '%s\t%s' "$tok" "$hit"; return 0; fi
  done <<EOT
$(distinctive_tokens "$txt")
EOT
  return 1
}

# --- self-test --------------------------------------------------------------
if [ "${1:-}" = "--selftest" ]; then
  t=$(mktemp)
  printf '%s\n' \
    'prog:refreshmeta | RECEIPT-DEAD | RefreshMetadataMutation ownership-check fail-closed 2026-06-16' \
    'prog:beam | LIVE-ASYNC | CreateSpamReportMutation blind XSS beacons armed' \
    'prog:onboard | KYC-DEAD-with-receipt | /onboarding-signup re-checked server-side' \
    'prog:mp1 | RECEIPT-DEAD | app.example.com site-claim host-dispatch' \
    'prog:mp2 | DEAD-with-control | app.example.com cross-site state pinned' \
    'prog:mp3 | RECEIPT-DEAD | app.example.com oracle enumeration only' \
    'prog:mp4 | DEAD-with-control | app.example.com 307 zero body' \
    'prog:mp5 | RECEIPT-DEAD | app.example.com samesite cookie' > "$t"
  rc=0
  [ -n "$(dedup_hit 'curl -d {RefreshMetadataMutation:x} https://h/graphql' "$t")" ] || { echo "FAIL dead op not caught"; rc=1; }
  [ -n "$(dedup_hit 'curl https://h/onboarding-signup/abc' "$t")" ] || { echo "FAIL dead path not caught"; rc=1; }
  dedup_hit 'curl -d {CreateSpamReportMutation:x} https://h/graphql' "$t" >/dev/null && { echo "FAIL live op blocked"; rc=1; }
  dedup_hit 'curl https://h/graphql?q=1' "$t" >/dev/null && { echo "FAIL generic token blocked"; rc=1; }
  # structural host on MANY dead lines (cnt>4) must NOT block a fresh angle:
  dedup_hit 'curl https://app.example.com/fresh-angle' "$t" >/dev/null && { echo "FAIL structural host over-block"; rc=1; }
  # program handle + scaffolding dir names must NOT block:
  dedup_hit 'cat targets/myprog/hunts/notes.md' "$t" "myprog" >/dev/null && { echo "FAIL handle/scaffold blocked"; rc=1; }
  rm -f "$t"
  [ "$rc" = 0 ] && echo "selftest OK"
  exit "$rc"
fi

# --- hook path --------------------------------------------------------------
PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
case "$TOOL" in
  Bash|WebFetch) ;;
  mcp__*send_http1_request|mcp__*send_http2_request) ;;
  Agent|Task)
    # PROGRAM-LEVEL dead-scope advisory on a worker dispatch. The #1 waste the session
    # audit found: ~40% of sessions dispatch a full worker to re-scope a PROGRAM already
    # whole-surface receipt-dead, discovering it only after the worker returns. Warn (never
    # block - a past dead can be a false dead, GreyNOC's massive lesson) so the orchestrator
    # pivots to fresh ground or runs fresh-rehunt.sh instead of re-confirming the corpse.
    PROMPT=$(printf '%s' "$PAYLOAD" | jq -r '[.tool_input.prompt, .tool_input.description] | map(select(. != null and . != "")) | join(" ")' 2>/dev/null)
    [ -z "$PROMPT" ] && exit 0
    CWD=$(printf '%s' "$PAYLOAD" | jq -r '.cwd // empty' 2>/dev/null || echo "")
    R2="${GNOC_WORKSPACE:-$HOME/.gnoc}"
    # RE-MODEL / RE-RECON CACHE (2026-07-16): support agents are 36% of all sub-agent effort, and the
    # measured waste is re-comprehending an already-modeled target (initech modeled 24x, re-recon 16x).
    # SPINE's cache rule was doctrine-only; enforce it as an advisory. If this dispatch is a MODELER or
    # RECON for a target that already has a fresh TARGET-MODEL.md, advise LOAD instead of re-deriving.
    if printf '%s' "$PROMPT" | grep -qiE 'target-?model|model (this|the) target|comprehend the target|recon-scout|map the (attack |trust )?(surface|boundar)|threat.?model the'; then
      MH=$(printf '%s' "$PROMPT" | grep -oE 'targets/[a-zA-Z0-9_-]+' | head -1 | sed 's#targets/##')
      if [ -n "$MH" ] && [ -f "$R2/targets/$MH/TARGET-MODEL.md" ]; then
        MDATE=$(date -r "$R2/targets/$MH/TARGET-MODEL.md" +%Y-%m-%d 2>/dev/null || echo "?")
        MSG2=$(printf 'CACHE-HIT: targets/%s/TARGET-MODEL.md already exists (modeled %s). If scope is unchanged, LOAD it and skip re-modeling - re-comprehending an already-modeled target is measured waste (initech was modeled 24x; support agents are 36%% of all sub-agent effort, the largest non-probing pool). Re-derive ONLY on a scope change or an explicit refresh; otherwise spend the worker on a fresh hunt vector instead.' "$MH" "$MDATE")
        jq -nc --arg c "$MSG2" '{hookSpecificOutput:{hookEventName:"PreToolUse", additionalContext:$c}}' 2>/dev/null
        exit 0
      fi
    fi
    for idx in "$R2"/.claude/state/do-not-rehunt/*.txt "$R2"/.claude/state/do-not-rehunt/*.md "$R2"/targets/*/do-not-rehunt.txt; do
      [ -f "$idx" ] || continue
      grep -qiE 'whole.{0,15}surface|entire surface|all .{0,20}dead|PROGRAM-DEAD|receipt-dead-with-control' "$idx" 2>/dev/null || continue
      case "$idx" in
        */targets/*) H=$(printf '%s' "$idx" | sed -n 's#.*/targets/\([^/]*\)/.*#\1#p') ;;
        *) H=$(basename "$idx"); H=${H%.txt}; H=${H%.md} ;;
      esac
      [ -z "$H" ] && continue
      # Fire ONLY on a genuine re-scope signal: the dispatch points at the program's
      # target directory (prompt references targets/<handle>, or cwd is under it). A bare
      # mention of the handle - inside an agent filename (starknet-cairo-hunter.md), inside
      # another word (ens in "tokens"), or a stray path - must NOT fire. Advisory, not a block.
      hit=no
      printf '%s' "$PROMPT" | grep -qE "targets/${H}(/|[^a-z0-9_-]|$)" && hit=yes
      case "$CWD" in */targets/"$H"|*/targets/"$H"/*) hit=yes ;; esac
      [ "$hit" = yes ] || continue
      # SHIPS/LOCK-AWARE (2026-07-16 review): a PROVEN shipper or a LOCKed/pinned target is NOT a corpse
      # to leave - the note must be a WITHIN-program pivot, never "re-scope a dead program" (which would
      # contradict grind-guard's proven-shipper steer and nudge an off-target rotate a LOCK forbids).
      IS_SHIPPER=no
      grep -qE "\"program\": ?\"$H\"" "$R2/.claude/state/hunt-loop/ships.jsonl" 2>/dev/null && IS_SHIPPER=yes
      LOCKED=""
      # Resolve lock-holder using per-session > global precedence (lock-lib.sh).
      if ( . "$R2/scripts/hunt-loop/lock-lib.sh" 2>/dev/null && command -v hl_lock_target >/dev/null 2>&1 ); then
        LOCKED=$(. "$R2/scripts/hunt-loop/lock-lib.sh" 2>/dev/null; hl_lock_target 2>/dev/null | awk 'NF{print $1; exit}')
      else
        [ -s "$R2/.claude/state/hunt-loop/LOCK" ] && LOCKED=$(grep -vE '^[[:space:]]*#' "$R2/.claude/state/hunt-loop/LOCK" 2>/dev/null | awk 'NF{print $1; exit}')
      fi
      [ -n "${HUNT_TARGET:-}" ] && LOCKED="$HUNT_TARGET"
      if [ "$IS_SHIPPER" = yes ] || [ "$H" = "$LOCKED" ]; then
        MSG=$(printf 'DISPATCH-NOTE: "%s" has a receipt-dead SURFACE in the index, but it is a shipper / your locked target - do NOT leave it. Pivot WITHIN the program to a NEW subdomain / surface / actor / flow NOT in the index (that within-program pivot IS the loop), or clean-context re-hunt a stale dead: scripts/learn/fresh-rehunt.sh %s . A past dead can be a false dead (massive paid 2 crits on a fresh re-hunt). Never rotate off a named/locked target.' "$H" "$H")
      else
        MSG=$(printf 'DISPATCH-DEAD-NOTE: this worker dispatch names "%s", a program whose do-not-rehunt index marks the surface receipt-dead. Re-scoping a dead program is our #1 waste (~40%% of sessions re-confirm a corpse). Before spending a worker: pivot to FRESH ground (a subdomain/surface/actor NOT in the index), or if you are DELIBERATELY re-hunting fresh (a past dead can be a false dead), archive the stale dead-memory first: scripts/learn/fresh-rehunt.sh %s' "$H" "$H")
      fi
      jq -nc --arg c "$MSG" '{hookSpecificOutput:{hookEventName:"PreToolUse", additionalContext:$c}}' 2>/dev/null
      exit 0
    done
    exit 0
    ;;
  *) exit 0 ;;
esac

CWD=$(printf '%s' "$PAYLOAD" | jq -r '.cwd // empty' 2>/dev/null) || exit 0
[ -z "$CWD" ] && CWD=$(pwd 2>/dev/null || echo "")

ROOT=$(printf '%s' "$CWD" | sed -n 's#\(.*/.gnoc\)/.*#\1#p' 2>/dev/null)
[ -z "$ROOT" ] && ROOT=$(printf '%s' "$CWD" | sed -n 's#\(.*/.gnoc\)$#\1#p' 2>/dev/null)
[ -z "$ROOT" ] && ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"

# The selector/fleet binds a run to HUNT_TARGET or a per-session lock.  Consult
# that context before cwd so root-run workers still receive target-local dedup.
SID=$(printf '%s' "$PAYLOAD" | jq -r '.session_id // empty' 2>/dev/null || echo "")
PROG=""
if [ -r "$ROOT/scripts/hunt-loop/lock-lib.sh" ]; then
  PROG=$(. "$ROOT/scripts/hunt-loop/lock-lib.sh" 2>/dev/null; hl_lock_target "$SID" 2>/dev/null | awk 'NF{print $1; exit}')
fi
if [ -z "$PROG" ]; then
  PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)/.*#\1#p' 2>/dev/null)
  [ -z "$PROG" ] && PROG=$(printf '%s' "$CWD" | sed -n 's#.*/targets/\([^/]*\)$#\1#p' 2>/dev/null)
fi
case "$PROG" in *[!A-Za-z0-9._-]* ) PROG="" ;; esac
[ -z "$PROG" ] && exit 0

case "$TOOL" in
  WebFetch) TXT=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.url // empty' 2>/dev/null) ;;
  Bash)     TXT=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // empty' 2>/dev/null) ;;
  *)        TXT=$(printf '%s' "$PAYLOAD" | jq -r '[.tool_input.targetHostname, .tool_input.content] | map(select(. != null and . != "")) | join(" ")' 2>/dev/null) ;;
esac
[ -z "$TXT" ] && exit 0

for idx in \
  "$ROOT/targets/$PROG/do-not-rehunt.txt" \
  "$ROOT/targets/$PROG/do-not-rehunt.md" \
  "$ROOT/targets/$PROG/hunts/do-not-rehunt.md" \
  "$ROOT/.claude/state/do-not-rehunt/$PROG.txt"; do
  [ -f "$idx" ] || continue
  HIT=$(dedup_hit "$TXT" "$idx" "$PROG") || continue
  [ -z "$HIT" ] && continue
  TOK=${HIT%%$'\t'*}
  LINE=${HIT#*$'\t'}
  # WARN, do not hard-block. GreyNOC's massive proof: a past 'dead' can be a FALSE dead -
  # deleting the dead-memory and re-hunting FRESH paid 2 criticals the agents had skipped
  # as 'already searched'. A hard block here suppressed those. So this now advises and lets
  # the probe proceed; the agent decides. Self-dupe waste is the smaller cost vs a missed crit.
  MSG=$(printf 'DEDUP-NOTE: this probe names "%s", marked dead for %s on a PAST hunt. A past dead is a HYPOTHESIS, not a fact - on massive a FRESH re-hunt of a "dead" target paid 2 criticals. Do NOT skip on this alone: if the dead is stale, or you hold a fresh angle (concurrent burst, second-handler, un-keyed side, new actor, or a clean-context re-hunt), PROBE IT. To re-hunt a dead target clean, archive its stale dead-memory first: scripts/learn/fresh-rehunt.sh %s . Receipt: %s' \
    "$TOK" "$PROG" "$PROG" "$(printf '%s' "$LINE" | cut -c1-300)")
  jq -nc --arg c "$MSG" '{hookSpecificOutput:{hookEventName:"PreToolUse", additionalContext:$c}}' 2>/dev/null
  exit 0
done

exit 0
