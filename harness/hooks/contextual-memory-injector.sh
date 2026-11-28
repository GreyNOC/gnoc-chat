#!/usr/bin/env bash
#
# contextual-memory-injector.sh - UserPromptSubmit hook.
#
# When the user mentions a target with prior session memory, automatically
# inject a compact summary so the model carries forward known killed
# vectors, saturated classes, $0 traps, and active reports without the
# user having to remember to /resume.
#
# Performance: O(prompt size); only fires for the specific bb workspace.

set -u  # NOT pipefail/-e: hook MUST exit 0 silently on any internal failure.
        # Claude Code surfaces non-zero+empty-stderr as user-visible noise.

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
command -v awk >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in
  ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;;
  *) exit 0 ;;
esac

PROMPT=$(echo "$INPUT" | jq -r '.prompt // empty' 2>/dev/null || echo "")
[ -z "$PROMPT" ] && exit 0

LOWER=$(echo "$PROMPT" | tr '[:upper:]' '[:lower:]')

# ---------------------------------------------------------------------------
# INTENT GATE (2026-06-10 retrieval-engine, context-budget lean pass).
# Mirror of pattern-auto-suggest's gate so the two hooks stay aligned and we do
# not spend the injection budget loading a 50-line target memory on a clearly
# non-hunting prompt (token-cost / billing / status / file-mgmt / trainer-meta).
# Fail-open: any explicit hunt/target verb DISARMS the gate, so a real
# "resume <target> hunt" is never suppressed - the gate only catches meta
# chatter that happens to contain a target substring with no hunting intent.
META_RE='(token cost|token budget|token usage|token spend|rtk gain|how much.*(cost|token|paid|spend|owe|bill)|^[[:space:]]*(ls|cd|cat|mkdir|rm|mv|cp|pwd|du|df)([[:space:]]|$)|git (status|add|commit|push|pull|log|diff|stash)|trainer (cron|run)|run the trainer|whats my (cost|budget|usage|bill)|what is my (cost|budget|usage|bill))'
HUNT_RE='\b(hunt|probe|recon|test|resume|report|finding|scope|exploit|payload|bypass|vuln|idor|ssrf|xss|csrf|oauth|graphql|takeover|submit|dedup|cvss|poc|endpoint|api|auth)\b'
if echo "$LOWER" | grep -Eq "$META_RE"; then
  if ! echo "$LOWER" | grep -Eq "$HUNT_RE"; then
    exit 0   # clearly non-hunting meta prompt -> do not inject target memory
  fi
fi

MEM_DIR="$HOME/.claude/projects/-home-you-gnoc-workspace/memory"
[ -d "$MEM_DIR" ] || exit 0   # FAIL-OPEN: no memory dir, nothing to inject.

# LOWER already computed above (before the intent gate).
HITS=()
declare -A SEEN=()   # dedup guard: never add the same reference file twice.

# ---------------------------------------------------------------------------
# DYNAMIC GLOB RETRIEVAL (lean rebuild 2026-06-14).
# The hardcoded curated TARGETS keyword->file map (~46 program names) was
# REMOVED: a static map drifts the moment a target is added/retired and pins
# program names into the hook. Memory selection is now PURELY DYNAMIC - resolve
# a target by matching a prompt token against a reference_*<tok>*.md filename in
# the memory dir, and (second source) against a reference link recorded in
# active-programs-index.md so a program listed only in the long-tail index also
# auto-resolves. There are ZERO hardcoded program names in this hook.
#
# Safety rails so this never injects noise (a memory dir of 300+ files makes a
# loose substring match dangerous: common prose/descriptor segments like
# _resume / _session / _state / _hunt would false-resolve on prompt verbs):
#   - token must be >= 3 chars (skip "lv"/dates that collide w/ prose; 3 lets real 3-char handles brg/ovh match)
#   - token must NOT be a hunting verb or generic prose word (STOPWORDS set)
#   - the matched filename's TARGET (the leading underscore-segment of the stem,
#     which is always the program name) must EQUAL the token. So "uber" resolves
#     reference_uber_* but "resume" never resolves reference_etoro_..._resume.md
#     and "client" never resolves reference_clientside_*.
#   - SEEN guard keeps any single file unique across all matched tokens
#   - at most 1 file per token (the single most-recent ref) so a prolific
#     target does not dump many files into context
# Multiple targets named in the same prompt each resolve once; the dedup guard
# keeps any single file unique. The TOKEN-BUDGET pass below trims the output.
#
# STOPWORDS: prompt words that frequently appear as a trailing descriptor in a
# reference filename but are never a TARGET name. Without this guard a hunting
# prompt ("resume X recon") would false-resolve on the verb.
declare -A STOPWORDS=()
for w in resume hunt hunts recon report reports finding findings probe probes \
         test tests session sessions state states submitted submission notes \
         scope exploit payload bypass vuln vulns chain chains round rounds \
         endpoint endpoints unauth authed escalation followup continuation \
         draft drafts active program programs target targets memory reference \
         http https json html cors xss idor ssrf csrf oauth graphql takeover \
         general explain caching cache works working about which while these \
         system scan verify verifying health healthy check clean architecture \
         full history feature stability improvement scanning green drift gauge gauges \
         agent agents pattern patterns claude burp curl fork substrate dos autonomous \
         mcp hook hooks skill skills injection injections context contexts prompt prompts; do
  STOPWORDS[$w]=1
done

INDEX_FILE="$MEM_DIR/active-programs-index.md"
shopt -s nullglob 2>/dev/null
declare -A STEM_DONE=()
for tok in $(echo "$LOWER" | tr -c 'a-z' ' ' | tr -s ' '); do
  [ ${#tok} -ge 3 ] || continue        # 3 so real 3-char handles (brg, ovh) match; the reference_*<tok>* stem-equals check below rejects noise
  [ -n "${STEM_DONE[$tok]:-}" ] && continue
  STEM_DONE[$tok]=1
  [ -n "${STOPWORDS[$tok]:-}" ] && continue        # generic word, never a target

  cand=""
  # Source A: filename glob reference_*<tok>*.md. Keep ONLY files whose leading
  # stem segment (the program name) equals <tok>, then pick the most-recent.
  matchlist=""
  for g in "$MEM_DIR"/reference_*"$tok"*.md; do
    [ -f "$g" ] || continue
    lead=$(basename "$g" | sed -E 's/^reference_//; s/[_.].*$//')
    [ "$lead" = "$tok" ] && matchlist="$matchlist $g"
  done
  # Guard: only invoke ls when matchlist is non-empty. A bare `ls -t` would list
  # the CURRENT directory and false-resolve an unrelated file.
  [ -n "$matchlist" ] && cand=$(ls -t $matchlist 2>/dev/null | head -n 1)

  # Source B: if no file matched directly, look in active-programs-index.md for a
  # reference_<tok>*.md link (program listed only in the long-tail index). Same
  # leading-stem rule: the linked filename's program name must equal <tok>.
  if [ -z "$cand" ] && [ -f "$INDEX_FILE" ]; then
    while IFS= read -r linked; do
      [ -f "$MEM_DIR/$linked" ] || continue
      cand="$MEM_DIR/$linked"
      break
    done < <(grep -oE "reference_${tok}[_.][a-z0-9_]*\.md|reference_${tok}\.md" "$INDEX_FILE" 2>/dev/null | sort -u)
  fi

  [ -n "$cand" ] || continue
  rel="${cand#$MEM_DIR/}"
  if [ -z "${SEEN[$rel]:-}" ]; then
    HITS+=("$rel")
    SEEN[$rel]=1
  fi
done
shopt -u nullglob 2>/dev/null

if [ ${#HITS[@]} -eq 0 ]; then
  exit 0
fi

# Build context block. Strip frontmatter (everything between first 2 '---' lines)
# to avoid leaking originSessionId UUIDs into the additionalContext.
strip_frontmatter() {
  awk 'BEGIN{c=0} /^---[[:space:]]*$/{c++; next} c>=2 || c==0' "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# TOKEN BUDGET (2026-06-10 context-engineering).
# Cap the COMBINED injected body to ~1200 tokens (~150 body lines) across ALL
# matched refs, not 50 lines per ref unbounded. HITS is ordered in prompt-token
# order (most-recent ref per resolved target), so we fill the budget in that
# order and trim the ref that crosses the line.
# A per-ref soft cap (PER_REF_MAX) stops one large ref eating the whole budget
# before a later, possibly more relevant ref gets any lines.
TOTAL_BUDGET=150     # ~1200 tokens of body across all refs combined
PER_REF_MAX=80       # no single ref may consume more than this many lines

CONTEXT="# Auto-loaded target memory"
remaining=$TOTAL_BUDGET
for f in "${HITS[@]}"; do
  [ "$remaining" -le 0 ] && break
  take=$PER_REF_MAX
  [ "$take" -gt "$remaining" ] && take=$remaining
  body=$(strip_frontmatter "$MEM_DIR/$f" | head -n "$take")
  [ -z "$body" ] && continue
  used=$(printf '%s\n' "$body" | wc -l | tr -d ' ')
  remaining=$((remaining - used))
  CONTEXT="${CONTEXT}

## ${f}
${body}"
done

jq -nc --arg ctx "$CONTEXT" \
  '{hookSpecificOutput: {hookEventName: "UserPromptSubmit", additionalContext: $ctx}}' 2>/dev/null
exit 0
