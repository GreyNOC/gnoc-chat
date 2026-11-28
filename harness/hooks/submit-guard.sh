#!/usr/bin/env bash
# submit-guard.sh - PreToolUse(Bash|WebFetch|burp send). HARD-BLOCK a network submission
# to a bug-bounty platform. Enforces the workspace's hardest invariant (SPINE 5 / CLAUDE.md):
# NEVER auto-submit; drafts only; GreyNOC submits manually via the platform web UI.
#
# Scope is deliberately NARROW to avoid false blocks: fires ONLY when a command both
#   (a) looks like an HTTP POST/PUT/PATCH (a write), AND
#   (b) targets a known platform submission surface.
# A scope-pull GET to api.hackerone.com (h1-scope.sh) has no write verb -> ALLOWED.
# A POST to an in-scope TARGET host (normal probing) has no platform host -> ALLOWED.
# Local file writes (including reports/submitted/ archival) are NOT touched.
#
# Override ONE submission: create .claude/state/GREYNOC-APPROVED-SUBMIT immediately before the
# submit. It is honoured only while FRESH (SUBMIT_OVERRIDE_TTL seconds, default 900) and is
# CONSUMED by the block it overrides. "Override one submission" is the contract; a sentinel that
# never expires is the whole gate switched off. Measured 2026-11-04: a 2026-10-25 sentinel written
# for one 8x8 filing had disabled this hook for ten days, and every rule below was bypassed.
set -u
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
IN="$(cat)"
SENTINEL="$ROOT/.claude/state/GREYNOC-APPROVED-SUBMIT"
APPROVED=0
if [ -f "$SENTINEL" ]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$SENTINEL" 2>/dev/null || echo 0) ))
  if [ "$AGE" -le "${SUBMIT_OVERRIDE_TTL:-900}" ]; then
    APPROVED=1
  else
    printf 'submit-guard: IGNORING stale approval %s (age %ss > %ss). The gate is ACTIVE; re-create it for a deliberate submit.\n' \
      "$SENTINEL" "$AGE" "${SUBMIT_OVERRIDE_TTL:-900}" >&2
  fi
fi

CMD=""; FALLBACK=false
if command -v jq >/dev/null 2>&1; then
  CMD="$(printf '%s' "$IN" | jq -r '.tool_input.command // .tool_input.url // empty' 2>/dev/null)"
fi
[ -z "$CMD" ] && { CMD="$IN"; FALLBACK=true; }
low="$(printf '%s' "$CMD" | tr 'A-Z' 'a-z')"

# BROWSER-DRIVEN SEND (2026-09-30). A Playwright or CDP script that clicks Submit never
# looks like an HTTP write verb, so check (a) below would let it through. On 2026-09-30 a
# report was filed to Meta this way. Submission is HUMAN ONLY per CLAUDE.md: the agent
# prepares the form, the human clicks. Blocks before the verb test deliberately.
# PLATFORM-HOST REQUIREMENT (narrowed 2026-10-03). The clause below previously fired on
# (any browser-driver mention) AND (the bare word submit/click anywhere), with NO platform
# host required - which contradicted this file's own header promise of condition (b), and
# produced 5 false blocks in one session on target signup forms, on a log line describing
# NOT clicking, and even on an attempt to READ this hook. The RULE is unchanged: a
# browser-driven send to a bug-bounty PLATFORM is still hard-blocked. What changed is that
# a platform hostname must now appear in the same command, so driving a signup form on an
# in-scope TARGET host counts as provisioning, not submission.
# NARROWED AGAIN 2026-10-06. The clause still matched BARE VENDOR WORDS, which are
# redundant with the fully-qualified host forms in the same list and far too broad. Two
# consequences, both observed live: (1) several in-scope programs REQUIRE a researcher
# header (X-HackerOne-Research: <handle>), so every browser-driven probe of such a target
# carried the token and was blocked; (2) merely grepping this hook for its own trigger
# words tripped it 3x in one session, the same failure the 2026-10-03 note describes.
# Fix: strip the researcher-header token, then require a FULLY-QUALIFIED platform host or
# an explicit submission path. THE RULE IS UNCHANGED - a real browser-driven send still
# navigates to a platform host plus /reports/new, which stays matched.
hdrless="$(printf '%s' "$low" | sed -E 's/x?-?hackerone-research//g')"
if printf '%s' "$hdrless" | grep -qE 'playwright|connect_over_cdp|:9222|devtools/browser'; then
  if printf '%s' "$hdrless" | grep -qE 'submit|click'; then
    if printf '%s' "$hdrless" | grep -qE 'hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|immunefi\.com|huntr\.(dev|com)|bugbounty\.meta\.com|facebook\.com/whitehat|h1\.sec|/reports/new|/submit_report'; then
      if [ "$APPROVED" = 1 ]; then
        rm -f "$SENTINEL"
        echo "submit-guard: one-shot approval honoured and consumed (browser-driven send)." >&2
        exit 0
      fi
      printf 'BLOCKED: browser-driven send to a bug bounty PLATFORM detected. Submission is
HUMAN ONLY (CLAUDE.md). Fill and screenshot the form, run scripts/presubmit-verify.sh, then
hand it to GreyNOC.\n' >&2
      exit 2
    fi
  fi
fi
# For a real shell command, strip QUOTED argument values (request bodies/headers) before the
# platform-path match, so a platform report URL carried INSIDE a -d/--data/-H payload of a legit
# in-scope probe does not trip the block; only a platform host in the actual (unquoted) request-
# target position should block. In FALLBACK mode (Burp/MCP split-field, CMD is the raw JSON) do
# NOT strip - the host+path tokens live in JSON-quoted fields the split-field block needs. 2026-07-19.
if [ "$FALLBACK" = true ]; then stripped="$low"; else stripped="$(printf '%s' "$low" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")"; fi

# (a) must look like an HTTP write verb: curl flags, --data, httpie "http POST url",
# a raw request line "POST /path HTTP/2" (Burp send_http* channel), or a JSON method field.
printf '%s' "$low" | grep -qE -- '(-x[[:space:]]*(post|put|patch|delete)|--request[[:space:]]*(post|put|patch|delete)|--data|--data-raw|--data-binary|--json|[[:space:]]-d[[:space:]]|httpie|https?[[:space:]]+(post|put|patch|delete)|(post|put|patch|delete)[[:space:]]+[^[:space:]]+[[:space:]]+http/|"method"[[:space:]]*:[[:space:]]*"?(post|put|patch|delete))' || exit 0

# (b) ...aimed at a bounty-platform submission surface.
# NOTE: bugs.immunefi.com is an IN-SCOPE RESEARCH TARGET (Immunefi's own bug-bounty SaaS),
# not a submission surface - probing it must be ALLOWED per the header contract (line 10).
# The Immunefi SUBMISSION surface is the dashboard/report/bounty path on the apex/www, so the
# immunefi.com match is narrowed to those paths and the target host is explicitly excluded.
if printf '%s' "$low" | grep -qE -- 'bugs\.immunefi\.com'; then
  exit 0
fi
# DEDUP READ CARVE-OUT (2026-10-11, GreyNOC): a READ-ONLY hacktivity GraphQL query is the public
# dedup list, not a submission. Allowed ONLY when the raw command names hacktivity AND carries no
# mutation or submit verb. Mutations and every submit path still block.
if printf '%s' "$low" | grep -qE 'hackerone\.com/graphql' \
   && printf '%s' "$low" | grep -qE 'hacktivity' \
   && ! printf '%s' "$low" | grep -qiE 'mutation|createreport|create_report|reportcreate|updatereport|deletereport|submit'; then
  exit 0
fi
if printf '%s' "$stripped" | grep -qE -- '(api\.hackerone\.com|hackerone\.com/[^ ]*report|bugcrowd\.com/[^ ]*submi|researcher\.bugcrowd|app\.intigriti\.com|api\.intigriti\.com|api\.yeswehack\.com|yeswehack\.com/[^ ]*report|(app|dashboard|www)\.immunefi\.com|immunefi\.com/[^ ]*(dashboard|bounty|report|submit)|huntr\.(dev|com))'; then
  if [ "$APPROVED" = 1 ]; then
    rm -f "$SENTINEL"
    echo "submit-guard: one-shot approval honoured and consumed (platform submission)." >&2
    exit 0
  fi
  echo "BLOCKED by submit-guard: this command looks like a network SUBMISSION to a bug-bounty platform." >&2
  echo "Invariant (SPINE 5 / CLAUDE.md): drafts only; GreyNOC submits manually. Surface the draft for review instead." >&2
  echo "If GreyNOC explicitly approved THIS submit: create $ROOT/.claude/state/GREYNOC-APPROVED-SUBMIT and retry." >&2
  exit 2
fi

# Burp MCP / split-field payload: when jq found no .command/.url, the host (targetHostname /
# Host header) and the path (raw request line) live in SEPARATE fields, so the adjacency
# match above misses them. Block when BOTH a platform host AND a submission-path token appear.
# (Only WRITE verbs reach here - a GET fails check (a) and already exited. bugs.immunefi.com
# is carved out above, so an in-scope Immunefi probe never reaches this branch.)
if printf '%s' "$stripped" | grep -qE -- 'hackerone\.com|bugcrowd\.com|intigriti\.com|yeswehack\.com|(app|dashboard|www)\.immunefi\.com|huntr\.(dev|com)' \
   && printf '%s' "$stripped" | grep -qE -- '(/[^ "]*(report|submit)|graphql|submission)'; then
  if [ "$APPROVED" = 1 ]; then
    rm -f "$SENTINEL"
    echo "submit-guard: one-shot approval honoured and consumed (split-field Burp/MCP write)." >&2
    exit 0
  fi
  echo "BLOCKED by submit-guard: split-field (Burp/MCP) write to a bug-bounty platform host + submission path." >&2
  echo "Invariant (SPINE 5 / CLAUDE.md): drafts only; GreyNOC submits manually. Surface the draft instead." >&2
  echo "If GreyNOC explicitly approved THIS submit: create $ROOT/.claude/state/GREYNOC-APPROVED-SUBMIT and retry." >&2
  exit 2
fi
exit 0
