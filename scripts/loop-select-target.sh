#!/usr/bin/env bash
# loop-select-target.sh - print the next target handle for the autonomous hunt loop.
#
# Universe  = onboarded targets/<handle>/ with a non-empty SCOPE.txt (in-scope, ready).
# Excludes  = handles listed in .claude/state/hunt-loop/do-not-rehunt.txt (receipt-dead).
# Order     = .claude/state/hunt-loop/priority.txt (one handle per line) first, if present;
#             then remaining onboarded handles in directory order.
# Output    = exactly one handle on stdout, or the literal NONE if nothing is left.
#
# Read-only. No network. Used by /hunt-loop step SELECT.
set -u
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
cd "$ROOT" 2>/dev/null || { echo NONE; exit 0; }

STATE="$ROOT/.claude/state/hunt-loop"
DNR="$STATE/do-not-rehunt.txt"
PRIO="$STATE/priority.txt"
NOYIELD="$STATE/no-yield.txt"       # venue-gated / fully-walled -> skip in ROTATE mode only
mkdir -p "$STATE" 2>/dev/null || true
touch "$DNR" "$NOYIELD" 2>/dev/null || true

# Fleet awareness: skip targets a LIVE sibling session already owns, and claim the one we
# return so a parallel selector cannot hand the same program to two agents. Degrades to the
# old single-session behavior if hunt-fleet.sh is absent.
FLEET="$ROOT/scripts/hunt-fleet.sh"
SID="${HUNT_SID:-${CLAUDE_CODE_SESSION_ID:-${CLAUDE_SESSION_ID:-}}}"   # real env var is CLAUDE_CODE_SESSION_ID
OTHERS=""
[ -x "$FLEET" ] && OTHERS="$("$FLEET" owned-by-others "$SID" 2>/dev/null)"
is_owned_by_other() { [ -n "$OTHERS" ] && printf '%s\n' "$OTHERS" | grep -qxF "$1"; }
claim_and_echo() {   # in rotate mode, claim before returning; env-pinned sessions skip this
  if [ -x "$FLEET" ] && [ -z "${HUNT_TARGET:-}" ]; then
    "$FLEET" claim "$1" "$SID" >/dev/null 2>&1 || return 1
  fi
  echo "$1"; exit 0
}

# Candidate set: every handle with a non-empty SCOPE.txt.
candidates=()
for s in targets/*/SCOPE.txt; do
  [ -s "$s" ] || continue
  h="$(basename "$(dirname "$s")")"
  candidates+=("$h")
done
[ "${#candidates[@]}" -eq 0 ] && { echo NONE; exit 0; }

# A handle is excluded if it appears as a whole word at the start of any do-not-rehunt line
# (lines may carry a trailing receipt: "betsson  variants 12/12, 9 subs enumerated").
is_excluded() {
  # do-not-rehunt.txt is a PER-VECTOR dead index (a program with one dead vector still has live
  # surfaces - SPINE: pivot WITHIN it). It must NOT drive whole-PROGRAM selection exclusion. The
  # whole-program exclusion is no-yield.txt (is_no_yield, rotate mode) + the LOCK/HUNT_TARGET pin
  # override + the grind-guard/saturation soft-de-rank. So do-not-rehunt never hard-excludes a program.
  # 2026-07-16: the old "$1==h" check wrongly de-selected 28 LIVE programs (incl. stockx/workleap and
  # shippers moonpay/thredup/kiwicom/mux) because their per-vector dead notes start with the handle;
  # verified every genuinely whole-surface-dead program (massive/umbrella/leadfeeder) is in no-yield.
  return 1
}
# SELECTION GATE (2026-07-07): venue-gated (fee/level) OR fully-walled (source-IP/CDN/audited-
# clean, no reachable seam) programs. 44% of past effort went to these for ZERO valid findings.
# Skipped in ROTATE mode ONLY; the LOCK and HUNT_TARGET branches above return before this, so an
# explicitly named target is always honored.
is_no_yield() {
  awk -v h="$1" '{ if ($1 == h) { found=1; exit } } END { exit (found?0:1) }' "$NOYIELD" 2>/dev/null
}
is_candidate() { printf '%s\n' "${candidates[@]}" | grep -qxF "$1"; }

# ROTATE-mode soft de-rank: programs with drafts>=3 AND h1_positive==0 get a lower score so
# fresh/converting targets always sort ahead of non-converters. Data-driven: reads ships.jsonl
# (draft counts) and triager_analysis.latest.json (H1 positive-states). A program that later
# earns a positive auto-recovers its rank because the source data changes. LOCK/HUNT_TARGET
# both return before this point and are never affected.
#
# Returns 0 (true) if the handle should be de-ranked in ROTATE mode.
SHIPS_FILE="$ROOT/.claude/state/hunt-loop/ships.jsonl"
H1_FILE="$ROOT/scripts/h1-feedback/triager_analysis.latest.json"
_derank_cache=""
_build_derank_cache() {
  # Emit a newline-separated list of handles that qualify for de-ranking.
  # Requires python3 (present; consolidate.py uses it). Falls back to empty on any error.
  python3 - "$SHIPS_FILE" "$H1_FILE" <<'PYEOF' 2>/dev/null
import sys, json, collections
ships_path, h1_path = sys.argv[1], sys.argv[2]
POS = {'resolved','triaged','retesting','pending-program-review'}
try:
    ships = [json.loads(l) for l in open(ships_path) if l.strip()]
    draft_cnt = collections.Counter(s.get('program') for s in ships)
except Exception:
    draft_cnt = {}
try:
    h1 = json.load(open(h1_path))
    pos_progs = {r['program'] for r in h1 if r.get('state') in POS}
except Exception:
    pos_progs = set()
for prog, cnt in draft_cnt.items():
    if prog and cnt >= 3 and prog not in pos_progs:
        print(prog)
PYEOF
}
is_deranked() {
  # Lazy-build the cache once per selector invocation.
  if [ -z "$_derank_cache" ]; then
    _derank_cache="$(_build_derank_cache)"$'\nSENTINEL'
  fi
  printf '%s\n' "$_derank_cache" | grep -qxF "$1"
}

# STOP-LOSS (T-240): a handle with >10000 summed probes OR >8 rows verdict=DEAD floor=met in
# outcomes.jsonl is demoted to a final pass (still selectable, last), unless
# stop-loss-override.txt has a line starting with the handle ("<handle> <reason>").
# Malformed JSONL lines are skipped. Read-only, no network. Debug list -> stderr only.
OUTCOMES_FILE="${OUTCOMES_FILE:-$STATE/outcomes.jsonl}"
STOPLOSS_OVERRIDE="${STOPLOSS_OVERRIDE:-$STATE/stop-loss-override.txt}"
_stoploss_cache="$(python3 - "$OUTCOMES_FILE" "$STOPLOSS_OVERRIDE" <<'PYEOF' 2>/dev/null
import sys, json, collections
probes = collections.Counter(); dead = collections.Counter()
try:
    for l in open(sys.argv[1], errors='replace'):
        try:
            r = json.loads(l)
            if not isinstance(r, dict): continue
            t = r.get('target')
            if not isinstance(t, str) or not t: continue
            try: probes[t] += int(r.get('probes') or 0)
            except Exception: pass
            if r.get('verdict') == 'DEAD' and r.get('floor') == 'met': dead[t] += 1
        except Exception:
            continue
except Exception:
    pass
ov = set()
try:
    for l in open(sys.argv[2], errors='replace'):
        w = l.split()
        if w and not w[0].startswith('#'): ov.add(w[0])
except Exception:
    pass
for t in sorted(set(probes) | set(dead)):
    if (probes[t] > 10000 or dead[t] > 8) and t not in ov:
        print(t)
PYEOF
)"
[ "${LOOP_SELECT_DEBUG:-0}" = 1 ] && [ -n "$_stoploss_cache" ] && printf 'stop-loss demoted: %s\n' "$(echo $_stoploss_cache)" >&2
is_stoploss() { [ -n "$_stoploss_cache" ] && printf '%s\n' "$_stoploss_cache" | grep -qxF "$1"; }

# 0a) PER-SESSION PIN: the launcher exports HUNT_TARGET for this process, pinning THIS
# agent to ONE program (the multi-agent equivalent of LOCK, but per-process not global).
if [ -n "${HUNT_TARGET:-}" ]; then
  if is_candidate "$HUNT_TARGET" && ! is_excluded "$HUNT_TARGET"; then echo "$HUNT_TARGET"; exit 0; fi
  echo NONE; exit 0
fi

# 0) SINGLE-TARGET LOCK (hard guard): if .claude/state/hunt-loop/LOCK names ONE handle, the operator
# named a single program -> loop ONLY that program, NEVER rotate to another. The universe
# collapses to {locked}: return it while it is a live candidate, else NONE (hold, do NOT fall
# through to other programs). Platform / "hunt" mode leaves LOCK absent or empty = rotate freely.
# PER-SESSION LOCK (2026-07-19): key the single-target pin by session id so parallel main-session
# agents do not stomp each other. Precedence: HUNT_TARGET (0a above) > LOCK.<sid> > global LOCK.
# Resolve via the shared lib (sid from $CLAUDE_CODE_SESSION_ID); degrades to the global LOCK file.
. "$ROOT/scripts/hunt-loop/lock-lib.sh" 2>/dev/null || true
if command -v hl_lock_file >/dev/null 2>&1; then LOCK="$(hl_lock_file)"; else LOCK="$STATE/LOCK"; fi
if [ -s "$LOCK" ]; then
  locked="$(grep -vE '^[[:space:]]*#' "$LOCK" | awk 'NF{print $1; exit}')"
  if [ -n "$locked" ] && is_candidate "$locked" && ! is_excluded "$locked"; then
    echo "$locked"; exit 0
  fi
  echo NONE; exit 0
fi

# 1) priority.txt order (only handles that are actually onboarded + not excluded).
# ROTATE soft de-rank: two passes - non-de-ranked first, de-ranked second.
if [ -s "$PRIO" ]; then
  # Pass 1a: priority handles that are NOT de-ranked.
  while IFS= read -r line; do
    h="$(printf '%s' "$line" | awk '{print $1}')"
    [ -z "$h" ] && continue
    case "$h" in \#*) continue ;; esac
    is_candidate "$h" || continue
    is_excluded "$h" && continue
    is_no_yield "$h" && continue
    is_stoploss "$h" && continue
    is_deranked "$h" && continue
    is_owned_by_other "$h" && continue
    claim_and_echo "$h" || continue
  done < "$PRIO"
  # Pass 1b: priority handles that ARE de-ranked (non-converters, only if nothing else left).
  while IFS= read -r line; do
    h="$(printf '%s' "$line" | awk '{print $1}')"
    [ -z "$h" ] && continue
    case "$h" in \#*) continue ;; esac
    is_candidate "$h" || continue
    is_excluded "$h" && continue
    is_no_yield "$h" && continue
    is_stoploss "$h" && continue
    is_deranked "$h" || continue
    is_owned_by_other "$h" && continue
    claim_and_echo "$h" || continue
  done < "$PRIO"
fi

# 2) fallback: onboarded handles in directory order, same two-pass de-rank.
# Pass 2a: non-de-ranked.
for h in "${candidates[@]}"; do
  is_excluded "$h" && continue
  is_no_yield "$h" && continue
  is_stoploss "$h" && continue
  is_deranked "$h" && continue
  is_owned_by_other "$h" && continue
  claim_and_echo "$h" || continue
done
# Pass 2b: de-ranked (non-converters, only if nothing else is available).
for h in "${candidates[@]}"; do
  is_excluded "$h" && continue
  is_no_yield "$h" && continue
  is_stoploss "$h" && continue
  is_deranked "$h" || continue
  is_owned_by_other "$h" && continue
  claim_and_echo "$h" || continue
done

# Pass 3 (T-240): stop-loss handles, last. Priority order first, then directory order.
for h in $( [ -s "$PRIO" ] && awk '!/^[[:space:]]*#/ && NF{print $1}' "$PRIO"; printf '%s\n' "${candidates[@]}" ); do
  is_candidate "$h" || continue
  is_no_yield "$h" && continue
  is_stoploss "$h" || continue
  is_owned_by_other "$h" && continue
  claim_and_echo "$h" || continue
done

echo NONE
