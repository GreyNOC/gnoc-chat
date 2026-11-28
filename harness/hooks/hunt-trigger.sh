#!/usr/bin/env bash
# hunt-trigger.sh - UserPromptSubmit hook.
#
# GreyNOC's UX: he never types a slash command. He names a TARGET (a program handle) or
# a PLATFORM (HackerOne/Bugcrowd/...) in natural language, or says "hunt", and the main
# agent must ENTER THE INDEFINITE HUNT LOOP. This hook detects that intent and injects
# the loop directive so the behavior fires reliably without a command.
#
# Additive context only. Fail-open. Never blocks. Does not fire on a stop/control phrase.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac
[ -z "$PROMPT" ] && exit 0

LP=$(printf '%s' "$PROMPT" | tr '[:upper:]' '[:lower:]')
# Compound-stripped copy (2026-09-30): a FILENAME like hunt-index / hunt-loop / hunt-fleet /
# hunt-cycle / hunt-stack contains "hunt" with a word boundary, so \bhunt\b matched it and any
# ordinary build/status sentence naming one of those files cold-entered the hunt loop.
# All intent matching below uses $_LPV; only these hunt-* compounds are removed, so platform
# names and target handles are unaffected.
_LPV=$(printf '%s' "$LP" | sed -E 's/hunt-(index|loop|loops|fleet|cycle|cycles|stack|trigger|select)//g')

# Control phrase -> never (re)trigger the loop.
echo "$_LPV" | grep -qiE '(^|[^a-z])(stop|para|det[eé]n|alto|pausa|pause|cancel)([^a-z]|$)' && exit 0
# Negation guard (2026-07-16): an explicit "do not hunt" / "don't hunt" must NOT trigger the loop -
# a verification/architecture prompt that merely mentions hunting is not a hunt request (observed
# self-trigger on a scheduled hold prompt this session).
echo "$_LPV" | grep -qiE "do ?n[o']?t hunt|no caces|sin caza|architecture.{0,15}(only|work)" && exit 0

PLATFORMS='hackerone|hacker one|\bh1\b|bugcrowd|intigriti|yeswehack|yes we hack|immunefi|huntr'
# Clear hunt-intent verbs only (no bare "target/program/platform" - too noisy in build talk).
# Bare Spanish delegation words (dale/sigue/hazlo/arranca) are NOT hunt-loop entry triggers: they
# mean "continue/proceed" and fired the loop cold on ordinary Spanish ("dale un vistazo al archivo").
# Kept as autonomy signals by doctrine, not by this cold-entry hook. Only unambiguous hunt verbs here.
VERBS='\bhunt\b|\bcaza\b|\bcazar\b|a[ -]?muerte|busca bugs|find bugs|empieza a caz|caza bugs|hunt bugs'

HIT=""
# A short handle (<=4 chars) is often a common English/Spanish word (short handles such as 
# mux/ovh) - matching it bare wrongly enters the hunt loop on ordinary prose. So a short handle
# triggers ONLY when a hunt verb or platform also appears; a handle >=5 chars triggers on its bare name.
HAS_HUNT_CTX=false
echo "$_LPV" | grep -qiE "($VERBS)|($PLATFORMS)" && HAS_HUNT_CTX=true
# Known onboarded target handle named (word-bounded).
if [ -d ${GNOC_WORKSPACE:-$HOME/.gnoc}/targets ]; then
  for d in ${GNOC_WORKSPACE:-$HOME/.gnoc}/targets/*/; do
    [ -d "$d" ] || continue
    h=$(basename "$d")
    # skip _-prefixed scaffolding AND any handle with a regex-metachar (a botched-glob dir like
    # '*' or 'pal[a]ntir_public' - a literal '*' is a regex quantifier that matched EVERY prompt,
    # hijacking all hunt-trigger detection to target:* until 2026-07-16).
    case "$h" in _*) continue ;; *[!a-zA-Z0-9_-]*) continue ;; esac
    if echo "$_LPV" | grep -qiE "(^|[^a-z0-9_])$h([^a-z0-9_]|$)"; then
      # short handles are dictionary words: require hunt context to avoid a false loop-entry
      if [ "${#h}" -le 4 ] && [ "$HAS_HUNT_CTX" != true ]; then continue; fi
      HIT="target:$h"; break
    fi
  done
fi
[ -z "$HIT" ] && echo "$_LPV" | grep -qiE "($PLATFORMS)" && HIT="platform"
[ -z "$HIT" ] && echo "$_LPV" | grep -qiE "($VERBS)" && HIT="verb"
[ -z "$HIT" ] && exit 0

# COLD-ENTRY SAFETY GUARD (2026-09-30). A platform/handle NAME alone is not hunt intent.
# Observed misfires this session, each injecting the full loop directive while the operator was
# only doing setup: "H1 Handle - GreyNOC" and "H1 API <token>" both matched PLATFORMS via \bh1\b,
# and a pasted HackerOne report page matched on "Hackerone". With a live API token configured, a
# cold loop entry on arbitrary text is how out-of-scope testing happens under the operator's handle,
# so this is a safety gate, not cosmetics.
# Design: an EXPLICIT hunt verb always wins and is never suppressed, so the intended
# "name a platform -> hunt" UX is preserved. Suppression applies ONLY to a bare
# platform/target-name hit that also looks like (a) credential/setup talk, or (b) pasted
# reference material (a real hunt order from this operator is short; a 4KB paste is not).
_HAS_VERB=false
# strip compound tokens so a FILENAME like hunt-index / hunt-loop / hunt-fleet / hunt-cycle
# does not read as the hunt VERB (these appear constantly in build and status talk).
echo "$_LPV" | grep -qiE "($VERBS)" && _HAS_VERB=true
if [ "$_HAS_VERB" != true ]; then
  # (a) credential / install / workspace-setup vocabulary
  if echo "$_LPV" | grep -qiE '(\bapi\b|\btoken\b|\bkey\b|\bhandle\b|secrets?\.env|\bcredential|\bpassword\b|app[ -]?pass|\binstall|\bconfigur|\bset ?up\b|\bscaffold|\bmarketplace\b|\bplugin\b|\bvenv\b|\bpath\b|\bbuild\b|\brebuild\b|\breindex\b|\bintake\b|\bonboard|\bautomat|\bwrite\b|\bupdate\b|\bfix\b|\bverify\b|\baudit\b|[a-z0-9+/]{16,}={0,2}$)'; then
    exit 0
  fi
  # (b) pasted reference material rather than an instruction
  if [ "${#PROMPT}" -gt 1200 ]; then
    exit 0
  fi
fi

cat <<'EOF'
[HUNT-LOOP TRIGGER] GreyNOC named a target/platform or asked to hunt. ENTER THE INDEFINITE HUNT LOOP NOW - do NOT wait for a slash command, do NOT ask for confirmation. You (the main agent) orchestrate the other agents in a continuous feedback loop per HUNT-LOOP.md:
- If a SPECIFIC target was named, start there. If a PLATFORM was named, rank its programs (scripts/h1-rank-programs.sh), seed .claude/state/hunt-loop/priority.txt, then start at the top.
- Per target: dispatch the hunt-cycle workflow ( Workflow({name:'hunt-cycle', args:{target:'<handle>'}}) ) = model -> hypothesize -> probe -> escalate+chain -> dedup/triage/report-killer/cvss -> draft -> learn. Deep-dive ONE target to draft-or-receipt-dead before advancing.
- On completion: if a draft shipped, STOP and surface it for GreyNOC's manual submit (NEVER auto-submit). Else advance to the next-EV target via scripts/loop-select-target.sh. Loop INDEFINITELY.
  NOTE: do NOT write to cycle-log.jsonl - it is stale (last write 2026-07-15), schema-less (88 free-form keys), and its shipped=0 was never updated. The live signals are ships.jsonl (draft north-star) and outcomes.jsonl (worker probe counts); write there instead.
- Stop ONLY on: a shipped draft, GreyNOC saying stop, or .claude/state/hunt-loop/STOP. "Exhausted/dead/hardened" is never a stop - pivot to the next subdomain/surface/target.
- Dispatch is not a stop: while the workflow runs, keep a NON-overlapping vector moving (prep the next target). Never poll-wait.
EOF

# REACTIVATABLE CROWNS (2026-07-16): in ROTATE mode ONLY (a bare platform match with NO active LOCK,
# where "what next" is the open question), surface the re-triaged "next Criticals" map so the loop
# opens on the highest-EV self-provisionable crown instead of cold recon. Gated tighter (2026-07-19):
# it fires ONLY on a 'platform' hit AND when the LOCK is ABSENT - a locked-target follow-up (a 'verb'
# continuation like "hunt"/"a-muerte" under a single named LOCK) must NOT get the 4.3KB rotate map,
# which would steer a pinned session off its target. A specific named target is handled by saturation below.
# per-session LOCK: resolve THIS session's lock (LOCK.<session_id>); degrades to the global LOCK for a lone session.
. "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/hunt-loop/lock-lib.sh" 2>/dev/null || true
_SID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")
if command -v hl_lock_file >/dev/null 2>&1; then LOCK="$(hl_lock_file "$_SID")"; else LOCK="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/LOCK"; fi
if [ ! -s "$LOCK" ]; then
  case "$HIT" in
    platform)
      RC=$(ls -t ${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/REACTIVATABLE-CROWNS-*.md 2>/dev/null | head -1)
      if [ -n "$RC" ] && [ -f "$RC" ]; then
        echo ""
        echo "[NEXT-CRITS MAP] Before cold recon, read $RC - the re-triaged frontier of self-provisionable crowns. Top reactivations (accounts already in hand, no GreyNOC-NEEDS): stockx (full-ATO via Google-merge, Turnstile now solvable) and workleap (cross-tenant mass-PII, gmail_read defeats the email denylist). Open UNAUTH from a seed (88% of ships); provision authed only to escalate the specific credential-gated crown."
      fi
      ;;
  esac
fi

# Cycle-1 saturation signal (SPINE 0b): when a KNOWN target was named, surface its
# on-disk saturation verdict so the loop decides FAST-LANE vs ABORT-RESWEEP in the
# first cycle instead of re-grinding a swept surface (the "knew at cycle 1" leak).
if [ "${HIT#target:}" != "$HIT" ]; then
  echo ""
  echo "[CYCLE-1 SATURATION] ${HIT#target:}: read this BEFORE re-sweeping. ABORT-RESWEEP = pivot to FRESH ground (new subdomain/surface/actor), do NOT re-grind the dead index:"
  bash ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/saturation.sh "${HIT#target:}" 2>/dev/null
fi
exit 0
