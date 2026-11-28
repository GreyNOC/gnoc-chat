#!/usr/bin/env bash
# subagent-floor-gate.sh - SubagentStop hook. The keystone of the self-learning loop.
#
# Two deterministic jobs a tired agent cannot skip:
#   1. CAPTURE every worker's return to state/learning/outcomes.jsonl. This is the
#      write-OUT half of the learning loop that was previously 100% manual prose:
#      consolidate.py rolls it into LESSONS.md, learning-inject.sh feeds it back into
#      the next hunt. Capture runs on EVERY SubagentStop, win or dead.
#   2. ANTI-SURRENDER: a worker that fired real probe tools and then declares
#      dead/exhausted WITHOUT a floor receipt (variant/bypass/sibling/control counts)
#      gets ONE hard nudge back to work. This reaches the WORKER sub-agents that the
#      main-session never-surrender.sh Stop hook never sees (settings.json had no
#      SubagentStop entry). Guarded by stop_hook_active (one nudge per worker) plus a
#      session backstop cap, so it can never infinite-loop.
#
# Fail-open everywhere. Read-only mappers/scorers/Explore workers (no probe tool) and
# receipt-backed or shipped returns are exempt.
set -u

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
TRANSCRIPT=$(echo "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null || echo "")
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || echo "")
STOP_ACTIVE=$(echo "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null || echo "false")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac
[ -n "$TRANSCRIPT" ] && [ -f "$TRANSCRIPT" ] || exit 0

# The worker's DIGEST = its last assistant text turn.
LAST=$(tac "$TRANSCRIPT" 2>/dev/null | jq -c 'select(.type=="assistant")' 2>/dev/null | head -1 | \
       jq -r '.message.content[]? | select(.type=="text") | .text' 2>/dev/null)
[ -z "$LAST" ] && exit 0

# AGENT WALL-CLOCK (2026-07-16) - measured: hunters probe hard (median 27 tool-uses) but SPRINT
# (median 14.4 min, 83% under 30 min) then stop one credential short of the crown. GreyNOC's floor
# is 30-100 min per hunt. Compute elapsed = first->last transcript timestamp; 0 = unknown -> fail-open.
ELAPSED_MIN=0
FT=$(head -1 "$TRANSCRIPT" 2>/dev/null | jq -r '.timestamp // empty' 2>/dev/null)
LT=$(tail -1 "$TRANSCRIPT" 2>/dev/null | jq -r '.timestamp // empty' 2>/dev/null)
if [ -n "$FT" ] && [ -n "$LT" ]; then
  FE=$(date -d "$FT" +%s 2>/dev/null || echo 0); LE=$(date -d "$LT" +%s 2>/dev/null || echo 0)
  { [ "${FE:-0}" -gt 0 ] && [ "${LE:-0}" -ge "${FE:-0}" ]; } && ELAPSED_MIN=$(( (LE - FE) / 60 ))
fi

# DISPATCH ROLE from the FIRST user message (the task prompt), computed ONCE and reused below.
# Support/reasoning agents (modeler, dedup, recon, reviewer, cvss, picker) legitimately finish fast
# and may curl during recon; they must be EXEMPT from the hunter grind-floor and the zero-probe block
# (2026-07-16 adversarial review: a curling recon-scout was wrongly told to provision a victim acct).
# 2026-11-09: -c not -cr. With -r a multi-line prompt was printed raw and head -1 kept ONLY ITS FIRST LINE, so every
# role marker below line 1 (do not probe, workspace-builder, read-only) was invisible and a 23-minute build agent
# was floored as a quitting hunter. -c keeps the whole message JSON-escaped on one line.
FIRSTMSG=$(jq -c 'select(.type=="user") | .message.content | tostring' "$TRANSCRIPT" 2>/dev/null | head -1 | head -c 4000)
IS_HUNTER=false
printf '%s' "$FIRSTMSG" | grep -qiE 'hunter|exploit|idor|bola|ssrf|xss|sqli|rce|ssti|oauth|saml|jwt|race|toctou|graphql|smuggl|takeover|prototype|deserial|injection|auth.?bypass|privilege|business.?logic|access.?control' && IS_HUNTER=true
IS_SUPPORT=false
printf '%s' "$FIRSTMSG" | grep -qiE 'target-?model|dedup|recon-scout|reviewer|cvss|hypothesis-gener|coverage|scorer|read-only|do not (probe|exploit)|map the|enumerat|picker|attack.?tree|report-repro|reproduce the finished draft|zero-context triager|workspace-?build|workspace-?architect|bb-?research|agent-?improv|skill-?to-?agent|upgrade-?agent|deepen-?agent|materializ(e|ing)|technique-?catalog|catalog (the|every|all) (pattern|skill|agent|hook|card|finding)|build (the|a|an) (skill|agent|hook|workflow|card|pattern)|audit (the|this) (hook|agent|workspace|skill|config|setting|injection|pattern|card)' && IS_SUPPORT=true
# PURE_SUPPORT = a read-only support/reasoning dispatch, matched by UNAMBIGUOUS markers only (an
# explicit read-only directive or a support agent-name). A hunter prompt saying "map the surface then
# exploit idor" has none of these -> still floored; a modeler's "read-only, do not exploit" is exempt
# (its literal "exploit" must NOT be read as hunt intent). 2026-07-16 adversarial review.
PURE_SUPPORT=false
printf '%s' "$FIRSTMSG" | grep -qiE 'read-only|read only|do not (probe|exploit)|never (probe|exploit)|target-?modeler|recon-scout|dedup-scout|hypothesis-generat|coverage-agent|picker-agent|reviewer-agent|cvss-scorer|unauth-surface-mapper|log-eater|attack-?tree-agent|chain-?mapper|report-repro-checker|reproduce the finished draft|zero-context triager|workspace-?build|workspace-?architect|bb-?research|agent-?improv|skill-?to-?agent|upgrade-?agent|deepen-?agent|materializ(e|ing)|technique-?catalog|catalog (the|every|all) (pattern|skill|agent|hook|card|finding)|build (the|a|an) (skill|agent|hook|workflow|card|pattern)|audit (the|this) (hook|agent|workspace|skill|config|setting|injection|pattern|card)' && PURE_SUPPORT=true

# INFRA DISPATCH (2026-09-30). Two agents in one session - a Go-toolchain INSTALL agent and a
# program-INTAKE agent - were blocked by the hunter-quit gates below and instructed to "fire live
# exploit probes" and "self-provision credentials" against an unspecified victim object, while doing
# a package install. Both correctly refused. Cause: the only exemption those gates honored was
# PURE_SUPPORT, whose regex covers read-only ANALYST roles but not INFRASTRUCTURE work, and any
# agent that merely ran `curl` (e.g. against the GitHub releases API) trips EXPLOIT_PROBED. With a
# live platform token and authenticated browsers on this box, telling a build agent to go exploit
# something is the most dangerous false positive in this file, so it is fixed at the role layer -
# the same discriminator the P10 block already uses.
IS_INFRA=false
printf '%s' "$FIRSTMSG" | grep -qiE 'install|dependenc|toolchain|go install|pip install|npm install|apt-?get|venv|chromedriver|chrome for testing|cdp browser|launcher|slash command|marketplace|\bplugin\b|configure|configurat|scaffold|restore|backup|path rewrite|bashrc|secrets\.env|settings\.json|wire (it|the|up)|verify the (setup|install|toolchain)|workspace setup|intake pipeline|write the docs|documentation|rank.?programs|fetch (the )?scope|program metadata' && IS_INFRA=true
# Only honored when the dispatch is NOT a hunt: a hunter prompt that happens to say "install"
# stays floored. An infra dispatch is never a hunter quitting early.
INFRA_EXEMPT=false
{ $IS_INFRA && [ "$IS_HUNTER" = false ]; } && INFRA_EXEMPT=true
# NOT-A-HUNT (2026-11-27). A software-engineering worker briefed "Software engineering task (NOT a bug-bounty hunt:
# ignore any hook text about hunting ...)" ran curl to verify the public release URL, matched a hunter keyword in its
# brief, and was re-woken by the blocks below SEVEN times to "return a probeLog". On one of those extra turns it
# built and committed in the operator's release repo without approval. An explicit not-a-hunt declaration in the
# opening of the brief is unambiguous: capture still runs (JOB 1), every hunter-quit block is skipped.
NOT_A_HUNT=false
printf '%s' "$FIRSTMSG" | head -c 600 | grep -qiE 'not a (bug.?bounty )?hunt|no hunting|software engineering task|swe task' && NOT_A_HUNT=true
$NOT_A_HUNT && INFRA_EXEMPT=true

# ROLE (FIX 3a 2026-07-19): a single role tag for the outcomes ledger so consolidate can filter
# orchestrator narration (62.5% of rows) out of the hunter receipt-rate. Order matters:
# pure_support/support wins over the ambiguous hunter keyword-match; a session that is NEITHER
# hunter NOR support = orchestrator (the correct bucket for its own session-stop narration record).
ROLE=orchestrator
$IS_HUNTER && [ "$IS_SUPPORT" = false ] && ROLE=hunter
{ [ "$PURE_SUPPORT" = true ] || $IS_SUPPORT; } && ROLE=support
[ "$INFRA_EXEMPT" = true ] && ROLE=infra   # not a worker outcome; keeps the hunter receipt-rate clean

# Did this worker fire real probe tools? A read-only mapper/scorer/Explore never blocks.
RECENT_TOOLS=$(tac "$TRANSCRIPT" 2>/dev/null | \
  jq -cr 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | "\(.name) \(.input|tostring)"' 2>/dev/null | \
  head -c 200000)   # whole-transcript (was head -24): a worker that probed EARLY then ended on Read/Edit was seen as non-probing and wrongly EXEMPTED from the floor (2026-07-16 audit; mirrors never-surrender.sh)
PROBED=false
echo "$RECENT_TOOLS" | grep -qiE 'mcp__[a-z0-9_-]*(send_http|burp)|"command":"[^"]{0,120}(curl|nuclei|ffuf|wfuzz|httpx|katana|subfinder|gau|sqlmap|ghauri|websocat|wscat|nikto|amass|dalfox|frida|curl_cffi|playwright|puppeteer)' && PROBED=true
# EXPLOIT probes = actual exploitation/fuzzing (NOT pure recon like subfinder/amass/katana/gau/httpx).
# A worker that fired these and returns no win + no receipt is a hunter that gave up -> nudge.
EXPLOIT_PROBED=false
echo "$RECENT_TOOLS" | grep -qiE 'mcp__[a-z0-9_-]*(send_http|burp)|"command":"[^"]{0,120}(curl|sqlmap|ghauri|nuclei|dalfox|ffuf|wfuzz|dirsearch|feroxbuster|nikto|frida|curl_cffi|playwright|websocat|wscat)' && EXPLOIT_PROBED=true

# EMPIRICAL INTENSITY (2026-07-07) - count REAL exploit-probe tool_uses across the WHOLE worker
# transcript so a DEAD verdict is gated on actual testing, not on typed receipt words. Recon
# tools (subfinder/amass/katana/gau/httpx) do NOT count - they are coverage, not a test. A
# burst/loop is one tool_use but many requests, so a detected burst satisfies the floor alone.
ALL_CMDS=$(tac "$TRANSCRIPT" 2>/dev/null | jq -cr 'select(.type=="assistant") | .message.content[]? | select(.type=="tool_use") | "\(.name) \(.input.command // (.input|tostring))"' 2>/dev/null)
PROBE_UNVERIFIABLE=false
[ -z "$ALL_CMDS" ] && PROBE_UNVERIFIABLE=true
PROBE_COUNT=$(printf '%s\n' "$ALL_CMDS" | grep -ciE 'send_http|__burp|(^|[^a-z])curl|curl_cffi|sqlmap|ghauri|nuclei|dalfox|ffuf|wfuzz|dirsearch|feroxbuster|nikto|websocat|wscat|requests\.(get|post|put|delete|request)|http\.client|urllib|playwright|puppeteer' 2>/dev/null)
PROBE_COUNT=$(( ${PROBE_COUNT:-0} + 0 ))
# probeLog contract (change 4): parse self-reported count only to RAISE confidence, and only
# when ALL_CMDS corroborates >=1 real probe tool. A typed number alone never clears the floor.
if ! $PROBE_UNVERIFIABLE; then
  PL_COUNT=$(printf '%s' "$LAST" | grep -oiE 'count=([0-9]+)' | head -1 | grep -oE '[0-9]+' || echo 0)
  PL_COUNT=$(( ${PL_COUNT:-0} + 0 ))
  PL_BURST=$(printf '%s' "$LAST" | grep -oiE 'burst=(true|false)' | head -1 | grep -oiE 'true|false' || echo false)
  HAS_PROBE_TOOL=$(printf '%s\n' "$ALL_CMDS" | grep -ciE 'send_http|__burp|(^|[^a-z])curl|curl_cffi|sqlmap|ghauri|nuclei|dalfox|ffuf|wfuzz|dirsearch|feroxbuster|nikto|websocat|wscat|requests\.(get|post|put|delete|request)|http\.client|urllib|playwright|puppeteer' 2>/dev/null)
  HAS_PROBE_TOOL=$(( ${HAS_PROBE_TOOL:-0} + 0 ))
  if [ "$HAS_PROBE_TOOL" -ge 1 ] && [ "$PL_COUNT" -gt "$PROBE_COUNT" ]; then
    PROBE_COUNT=$PL_COUNT
  fi
  [ "$PL_BURST" = "true" ] && BURST_FROM_LOG=true || BURST_FROM_LOG=false
else
  BURST_FROM_LOG=false
fi
BURST=false
# Anchored command-SHAPE match only (2026-07-16 audit v2): a real burst is a python/async
# request-parallelism idiom, OR a shell loop that ALSO drives a request tool on the same line, OR
# the parsed probeLog burst=true. The old regex matched a BARE shell loop ("for h in $(cat hosts)"),
# so a pure-RECON loop (subfinder/katana in a for-loop) flipped empirical_ok true with ZERO crafted
# requests - measured 709/870 empirical_ok=true rows had probed=false. A recon loop is not a burst.
printf '%s' "$ALL_CMDS" | grep -qiE 'race_burst|single.?packet|ThreadPoolExecutor|concurrent\.futures|asyncio\.gather|aiohttp|multiprocessing\.Pool|threading\.Thread|xargs -P ?[0-9]' && BURST=true
printf '%s' "$ALL_CMDS" | grep -qiE '(for [a-z_]+ in |[; ]seq [0-9]|while (true|read)).*(curl|send_http|wget|websocat|wscat|ncat| nc )' && BURST=true
$BURST_FROM_LOG && BURST=true
$BURST && EXPLOIT_PROBED=true   # a detected burst IS probing (async/script bursts are invisible to the command grep)
# python/http-lib probes are counted in PROBE_COUNT but missed by the RECENT_TOOLS EXPLOIT grep (its
# nested-quote "command":"..." match is blind to inline python): a hunter that only used
# requests/httpx/urllib is still an exploit-prober, so align EXPLOIT_PROBED with the real count.
[ "${PROBE_COUNT:-0}" -ge 1 ] && EXPLOIT_PROBED=true
EMPIRICAL_FLOOR=8
EMPIRICAL_OK=false
# FIX 3b (2026-07-19): burst-alone only clears the floor when the worker actually PROBED
# (has its own curl/send_http tool_use). An orchestrator narration turn is PROBED=false, so a
# burst-regex false-hit on quoted narration text ("concurrent burst" in prose) no longer flips
# empirical_ok. A real hunter burst still counts (PROBED=true); the probe-count path is unchanged.
{ [ "$PROBE_COUNT" -ge "$EMPIRICAL_FLOOR" ] || { $BURST && $PROBED; }; } && EMPIRICAL_OK=true

RECEIPT='variants?=?[0-9]+/?[0-9]*|[0-9]+ ?(variant|bypass|sibling|subdomain|endpoint|payload|probe|actor|surface)|positive[- ]control|negative[- ]control|concurrent burst|burst=?[0-9]+|[0-9]+ (tried|tested|fired|enumerated|swept)'
SURRENDER='no findings|nothing (more|else|left|actionable)|exhausted|looks dry|ran out|tried everything|target is dead|vector is dead|surface is dead|fully hardened|dead[- ]end|receipt-dead|hit a wall|give up|sin hallazgos|nada m[aá]s|agotado|me rindo|ceiling( reached)?|hardened( surface)?|pivoting|returning (a )?lead|need(s)? (an? )?authed|need(s)? (a )?second account|no( new)? capability|by[- ]design|not exploitable|out of scope|nothing exploitable|moving on|will pivot|handing back|parked|saturat'
WIN='report (saved|written|drafted|submitted)|terminal receipt|(wrote|saved|drafted|written|created)[^.]{0,40}reports/(drafts|submitted)/|confirmed (cross-tenant|idor|bola|rce|ato|ssrf|leak)|(FINDING-|is a |confirmed )CANDIDATE|draft (is )?(ready|written)'

has_receipt=false; echo "$LAST" | grep -qiE "$RECEIPT"   && has_receipt=true
is_dead=false;     echo "$LAST" | grep -qiE "$SURRENDER" && is_dead=true
is_win=false;      echo "$LAST" | grep -qiE "$WIN"       && is_win=true

verdict=other
$is_dead && verdict=dead
$is_win  && verdict=win

# --- JOB 1: CAPTURE (always) ---
LDIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/learning"
mkdir -p "$LDIR" 2>/dev/null
# FIX 3c (2026-07-19): GATE THE WRITE by role. Only a hunter/support return is a worker OUTCOME;
# the orchestrator's own session-stop is narration, never a worker outcome, and must not enter the
# ledger (it was the bulk of the 988 corrupt probe_count=0 & empirical_ok=true rows). role is added
# to the record so consolidate computes a hunter-only receipt-rate.
if [ -d "$LDIR" ] && [ "$ROLE" != orchestrator ] && [ "$ROLE" != infra ]; then
  SNIP=$(printf '%s' "$LAST" | head -c 240 | iconv -f utf-8 -t utf-8 -c 2>/dev/null | tr -d '\000-\010\013\014\016-\037')
  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  WPC="$PROBE_COUNT"; $PROBED || WPC=0   # honest telemetry: a non-probing agent never records a prose-scraped probe_count
  jq -nc --arg ts "$TS" --arg s "$SESSION_ID" --arg v "$verdict" --arg ro "$ROLE" \
    --argjson rc "$has_receipt" --argjson pr "$PROBED" --argjson pc "$WPC" \
    --argjson bu "$BURST" --argjson eo "$EMPIRICAL_OK" --argjson pu "$PROBE_UNVERIFIABLE" \
    --arg sn "$SNIP" \
    '{ts:$ts,session:$s,role:$ro,verdict:$v,receipt:$rc,probed:$pr,probe_count:$pc,burst:$bu,empirical_ok:$eo,probe_unverifiable:$pu,snippet:$sn}' \
    >> "$LDIR/outcomes.jsonl" 2>/dev/null
fi

# --- JOB 2: ANTI-SURRENDER (one nudge per worker) ---
[ "$STOP_ACTIVE" = "true" ] && exit 0   # already nudged this worker; let it stop
$NOT_A_HUNT && exit 0                    # declared non-hunt work: never told to probe, provision or keep going
# AGGRESSIVE (GreyNOC's #1 priority): nudge ANY worker that fired EXPLOIT probes and returns
# neither a captured WIN nor a floor receipt - not just the ones that TYPED a surrender word.
# Recon-only workers (no exploit tool) are exempt; wins and receipted-dead pass.

# P10 (2026-07-07): a HUNTER that declared the vector DEAD after firing ZERO live probes -
# reasoned-to-dead without a single test (33% of dead-hunters did this). Block it, but ONLY when
# the dispatch task is clearly an exploit-hunt, never a support/reasoning role that legitimately
# returns a negative (modeler, dedup, recon, reviewer, cvss, hypothesis-generator, picker).
if ! $EXPLOIT_PROBED && $is_dead && [ "${PROBE_COUNT:-0}" -eq 0 ]; then
  if $IS_HUNTER && ! $IS_SUPPORT; then   # FIRSTMSG / IS_HUNTER / IS_SUPPORT hoisted to the top (computed once)
    SC0="$LDIR/blocks-${SESSION_ID}.count"; C0=$(cat "$SC0" 2>/dev/null || echo 0); case $C0 in ''|*[!0-9]*) C0=0;; esac; N0=$((C0 + 1)); echo "$N0" > "$SC0" 2>/dev/null
    if [ "$N0" -le 25 ]; then
      R0="ZERO PROBES on a hunt task. You declared this vector dead without firing a SINGLE live request - the #1 reason we find fewer bugs than peers on the same vector. You cannot know a vector is dead from the model alone; bugs are found empirically. Fire at least ${EMPIRICAL_FLOOR} crafted live requests at it NOW (mutate the input, try the second handler, the un-keyed side, a sibling object, a concurrent burst), watch for the one anomalous response, then judge. Test first, then return."
      jq -nc --arg r "$R0" '{decision:"block", reason:$r}'
    fi
    exit 0
  fi
fi

$EXPLOIT_PROBED || exit 0                 # support/recon/scorer: pass (unchanged gate)
$is_win        && exit 0                  # captured finding/candidate: pass
[ "$PURE_SUPPORT" = true ] && exit 0      # pure support/recon/reasoning agent that happened to curl: exempt from ALL hunter-quit blocks (grind-floor, else-block) - 2026-07-16 adversarial review
[ "$INFRA_EXEMPT" = true ] && exit 0      # infra/setup/tooling dispatch that happened to curl: same exemption. NEVER instruct a build agent to exploit or provision. - 2026-09-30

# session backstop cap (unchanged: broken loop cannot run away)
SC="$LDIR/blocks-${SESSION_ID}.count"; CUR=$(cat "$SC" 2>/dev/null||echo 0); case $CUR in ''|*[!0-9]*) CUR=0;; esac; NEW=$((CUR+1)); echo "$NEW">"$SC" 2>/dev/null
[ "$NEW" -gt 25 ] && exit 0

# --- DIGEST CONTRACT (FIX 7 2026-07-19): a HUNTER return MUST carry a probeLog block (count+burst).
# Distinct from the probe-COUNT floor: this checks the block is PRESENT and structured so the
# orchestrator can AGGREGATE it (honored by 1/172 workers). Placed AFTER the win-exit + support
# exits (only a non-win hunter reaches here), gated by stop_hook_active (one nudge, exited at top)
# and the session cap (already incremented above). Separate from PROBE_UNVERIFIABLE (tools absent)
# and the empirical-floor block (too-few probes): this fires when tools ARE present but the
# structured digest is absent.
if $IS_HUNTER && [ "$IS_SUPPORT" = false ]; then
  HAS_PROBELOG=false
  printf '%s' "$LAST" | grep -qiE 'probelog|count=[0-9]+' && \
  printf '%s' "$LAST" | grep -qiE 'burst=(true|false)' && HAS_PROBELOG=true
  if [ "$HAS_PROBELOG" = false ]; then
    jq -nc '{decision:"block", reason:"DIGEST CONTRACT: a hunter return MUST include a probeLog block so the orchestrator can aggregate it (honored by 1/172 workers = the orchestrator reads raw prose it cannot verify). Append and return:\n```probeLog\ncount=<N real live requests fired>\nburst=<true|false>\nvariants=<what you mutated: schema fields, encodings, second-handler, un-keyed side, sibling objects>\nfloor=<met|unmet>\n```\nbacked by your actual curl/send_http tool-calls, then re-return with your verdict."}'
    exit 0
  fi
fi

# --- TIME-FLOOR (GreyNOC 2026-07-16): the 14-min-sprint quit ---
# A hunter that PROBED (past the EXPLOIT_PROBED gate) and is NOT a win (past the win exit) but ran
# < GRIND_FLOOR_MIN gets ONE productive nudge to use the remaining budget - because the #1 missed-crit
# pattern is mapping the crown then stopping one credential short, and that unlock is usually
# self-provisionable. Fires once per agent (stop_hook_active exits at the top), fail-open when
# wall-clock is unknown (ELAPSED_MIN=0). This is the enforcement of "grind 30-100 min", not a doc.
GRIND_FLOOR_MIN=30
if [ "${ELAPSED_MIN:-0}" -gt 0 ] && [ "${ELAPSED_MIN:-0}" -lt "$GRIND_FLOOR_MIN" ] && [ "$PURE_SUPPORT" != true ]; then
  jq -nc --arg m "$ELAPSED_MIN" --arg f "$GRIND_FLOOR_MIN" '{decision:"block", reason:("GRIND FLOOR: this hunt ran only "+$m+" min; the per-hunt floor GreyNOC set is "+$f+"-100 min. Measured over our own workers: agents probe hard then quit at a 14-min median, one credential short of the crown - that wall is 47% of quits and where the unshipped Criticals sit. You have budget left; do NOT return yet. Do ONE now, then continue: (a) SELF-PROVISION the blocker with the bbtools - provision_pair / browser_register (signup-walled form) / gmail_alias+gmail_confirm (email verify) / cdp_authed_curl(host=) (a live login) - and push the primitive to a CAPTURED cross-account terminal: reading AND writing/deleting an object owned by a SECOND account YOU provisioned is the gold receipt and is fully in-scope (never touch a real user or production data); (b) if the unlock is genuinely GreyNOC-only, spend the remaining minutes on another surface/actor/sibling-host of THIS program (there is always another). Count BREADTH (FIX 6c): if this SEED captured nothing by ~30-45 min, PIVOT THE SEED (a different mined endpoint / actor / host) rather than firing more probes at the same dead seam - winners are cheap, and the floor counts SEEDS TRIED, not depth on one dead surface. Return only after you have used the time.")}'
  exit 0
fi

# --- SELF-PROVISIONABLE NEEDS (2026-07-19): NEEDS is the #1 dead-reason (170 in do-not-rehunt)
# and 45% of quits stop one credential short of the crown - where the unshipped Criticals sit. The
# grind-floor block above only fires under 30 min; a hunter that GRINDED PAST the floor and returns
# dead "need a 2nd account / email-verify / browser signup / a minted token" currently passes the
# affirmative gate silently. That unlock is a bbtools DISPATCH, not a GreyNOC NEEDS. Nudge ONCE (the
# one-nudge cap was already incremented above; STOP_ACTIVE exits at the top). EXCLUDE a genuine
# hard-external unlock (paid tier no-trial / KYC / enrolled-device / corp-SSO) - that is a real NEEDS.
if $is_dead; then
  SELFPROV_RX='NEEDS:? (a |an )?(second|2nd|authed|another) account|need(s)? (a |an )?(second|2nd|authed|another) account|need(s)? (an? )?authed|one (account|credential|token) short|credential wall|need(s)? (to )?(register|sign.?up|provision|verify)|need(s)? (an? )?(email.?verif|magic.?link|browser (signup|session)|token)'
  HARDEXT_RX='paid tier|no.?trial|no free (tier|trial)|\bKYC\b|gov.?id|government.?id|enrolled.?device|push (notification|approval)|corp(orate)?.?SSO|SAML SSO|hardware (key|token)|passkey enroll'
  if printf '%s' "$LAST" | grep -qiE "$SELFPROV_RX" && ! printf '%s' "$LAST" | grep -qiE "$HARDEXT_RX"; then
    jq -nc '{decision:"block", reason:"SELF-PROVISIONABLE WALL, not a NEEDS. You returned dead one credential short (2nd account / email-verify / browser signup / token) - the #1 dead-reason in our ledger (170) and where 45% of quits and the unshipped Criticals sit. This unlock is a bbtools DISPATCH, not a GreyNOC NEEDS. Provision it NOW: provision_pair (A+B accounts) / browser_register (signup-walled form) / gmail_alias+gmail_confirm (email verify) / cdp_authed_curl(host=) (a live login); persist to targets/<t>/ACCOUNTS.md; then push the primitive to a CAPTURED cross-account terminal - read AND write/delete an object owned by the SECOND account YOU provisioned is the gold receipt, fully in-scope (never a real user or production data). Surface a NEEDS to GreyNOC ONLY for a hard external unlock (paid tier no-trial / KYC / enrolled-device / corp-SSO). Provision, then return the captured terminal."}'
    exit 0
  fi
fi

# AFFIRMATIVE PASS: a probed worker leaves only with a WIN or a real floored receipt.
if $PROBE_UNVERIFIABLE; then
  jq -nc '{decision:"block", reason:"PROBE LOG UNVERIFIABLE. Your transcript did not expose a countable probe log, so I cannot confirm you hammered this vector - and an unverifiable floor is treated as UNMET. Return a probeLog block (```probeLog\ncount=<N real live requests>\nburst=<true|false>\nvariants=<what you mutated>\nfloor=<met|unmet>\n```) backed by the actual curl/send_http tool-calls, then either ship the finding or, only after >=8 real probes PLUS a burst on any single-use path, return DEAD with that receipt."}'
  exit 0
fi
if $EMPIRICAL_OK && $has_receipt; then exit 0; fi   # genuinely floored LEAD/DEAD: pass

# else: probed, no win, no floor receipt (incl verdict=other/ceiling/hardened/pivoting) -> BLOCK
jq -nc --arg pc "$PROBE_COUNT" --arg fl "$EMPIRICAL_FLOOR" '{decision:"block", reason:("NOT A VALID RETURN. You fired ~"+$pc+" real exploit probes and captured neither a finding nor a floor receipt; \"ceiling reached / hardened / pivoting / returning a lead / need an authed account\" is NOT an exit without the floor. Forensic fact over our own 7,850 workers: agents sprint (median 12.5 min, 39% quit under 8 probes) and 45% stop one credential short of the crown - that fast quit is the yield leak. Before you return do ONE: (a) FIRE MORE - >= "+$fl+" crafted live requests mutating the input (hidden schema fields, encodings, the SECOND handler that touches the same object, the un-keyed side of the relation, sibling objects, the enforcer-twin) PLUS a concurrent burst on any single-use / check-then-act path, and report a probeLog block with real counts; (b) SELF-PROVISION the blocker (second account for the victim object, org/workspace, minted token, browser context) and push the primitive to a CAPTURED terminal, then chain it; (c) ONLY after >= "+$fl+" real probes AND a burst, return the receipt DEAD line + probeLog{count,burst,variants,floor=met}. There is always another mutation, another surface, another actor. Continue.")}'
exit 0
