#!/usr/bin/env bash
#
# runtime-evidence-guard.sh - PostToolUse hook for Write/Edit on reports.
#
# Catches the most expensive recurring failure mode (77% of source-code-only
# findings die at runtime per S9). When a report claims runtime confirmation
# but no captured output is visible, the hook emits a loud advisory.
#
# Triggers:
#   - report contains "runtime_confirmed: true" / "Runtime: confirmed" /
#     "Verified runtime" / "runtime-verified"
#   - AND the same file does NOT contain any of:
#       captured curl output (HTTP/1.1 ddd or HTTP/2 ddd)
#       JSON response body block fenced ```json or response: {
#       PoC script reference (./poc.py / ./poc.sh / poc.py)
#       attached evidence file (reports/.../*.png / *.har / *.mp4)
#
# CHECK C (2026-09-30): CANONICAL ATTACHMENTS. reports/REPORT-FORMAT.md section 10
# requires repro.sh + capture.log + one screenshot per ROLE (poc-1-boundary.png,
# poc-2-attack.png, poc-3-control.png) alongside the draft. draft-write-gate.sh reads
# the draft TEXT from stdin and is blind to the filesystem, so it cannot check this;
# this hook already has the file on disk, so the check lives here. Advisory only.
#
# Advisory only (lean rebuild 2026-06-14): always exits 0, never blocks.

set -u
IFS=$'\n\t'

PAYLOAD=$(cat 2>/dev/null || true)
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null)
case "$TOOL" in
  Write|Edit) ;;
  *) exit 0 ;;
esac

FILE=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null)
case "$FILE" in
  *reports/*.md|*reports/*.MD|*-h1.md|*-huntr.md|*-intigriti.md|*-bugcrowd.md|*-ywh.md|*-immunefi.md|*/platform.md) ;;
  *) exit 0 ;;
esac
[ -f "$FILE" ] || exit 0

# --- CHECK A: internal-ID + internal-path + internal-tooling leak (2026-05-15 expanded) -----
# Triage notes commonly use shorthand IDs, workspace paths, state files, skill names.
# These should never reach a vendor-facing report. Triagers see "F12" or "RELAY.md" or
# "/devils-advocate" without context and get confused or reject.
# Patterns covered:
#   - Internal finding IDs: F12, F-MFA-6, OND-6, V1, TR-1, W8, R5, Unit 4, E41
#   - Internal session markers: wave3, round 9, cycle 5, session 22, S12, S37
#   - Internal file paths: $HOME/, targets/, reports/drafts, mobile/Helper, BACKUP/
#   - Internal state files: RELAY.md, FUNNEL.md, KG.md, MEMORY.md, SCOPE.txt, INCIDENTS.log
#   - Internal memory files: feedback_*, reference_*, project_*, AUDIT-2026, audit-2026, phase[123].md
#   - Internal slash commands: /picker /bounty-check /health /scope /recon /surface /hunt
#                              /dedup /poc-template /repro /triage /report /cvss /ai-check
#                              /slim /trim /reviewer /devils-advocate /pre-submit /post-submit
#                              /cascade /relay /llm /mobile /graphql /smuggle /race /ws
#                              /web3-audit /nmi-recover /pivot /hats /heatmap /hyp /dig
#                              /depth-matrix /persist /pollinate /analogy /intel /health
#                              /bounty-check /next-target /attack-tree /chain /repro /scope
#                              /surface /resume /lateral /pivot /jwt /oauth /takeover
#   - Internal hook names: contextual-memory-injector, ai-smell-guard, cvss-validator,
#                          runtime-evidence-guard, dollar-trap-guard, session-start-auth
#   - Internal sub-agent names: Hunter-Fix, scout, triage agent, reviewer agent, orchestrator
LEAK_PATTERNS='$HOME/|targets/[a-z]|reports/drafts|RELAY\.md|FUNNEL\.md|\bKG\.md|MEMORY\.md|SCOPE\.txt|INCIDENTS\.log|\bfeedback_[a-z]|\breference_[a-z]|\bproject_[a-z]|AUDIT-2026|audit-2026-|phase[123]\.md|consolidated/|BACKUP/2026|mobile/Helper|prompts/BACKUP|/picker\b|/bounty-check\b|/scope\b|/recon\b|/surface\b|/hunt\b|/dedup\b|/poc-template\b|/repro\b|/triage\b|/report\b|/cvss\b|/ai-check\b|/slim\b|/trim\b|/reviewer\b|/devils-advocate\b|/pre-submit\b|/post-submit\b|/cascade\b|/relay\b|/llm\b|/mobile\b|/graphql\b|/smuggle\b|/race\b|/ws\b|/web3-audit\b|/nmi-recover\b|/pivot\b|/hats\b|/heatmap\b|/hyp\b|/dig\b|/depth-matrix\b|/persist\b|/pollinate\b|/analogy\b|/intel\b|/health\b|/next-target\b|/attack-tree\b|/chain\b|/resume\b|/lateral\b|/jwt\b|/oauth\b|/takeover\b|/auto\b|/autopilot\b|contextual-memory-injector|ai-smell-guard|cvss-validator|runtime-evidence-guard|dollar-trap-guard|session-start-auth|Hunter-Fix|orchestrator agent|memory-autoindex|wave[0-9]|round [0-9]|cycle [0-9]|session [0-9]|\bS[0-9]{1,2}\b|F-[A-Z][A-Z0-9]{1,8}-[0-9]+|\bF[0-9]{1,3}\b|OND-[0-9]+|TR-[0-9]+|\bV[0-9]+ |Unit [0-9]+|E[0-9]{2,3}\b'

if grep -nE "$LEAK_PATTERNS" "$FILE" 2>/dev/null \
   | grep -vE '(EC2|F5|F500|F1000|S3|HTTP/[12]|^[^:]+:#?[0-9]+:.*HackerOne|^[^:]+:#?[0-9]+:.*CVE-)' \
   | head -10 > /tmp/.id-leak-$$ 2>/dev/null
then
  if [ -s /tmp/.id-leak-$$ ]; then
    printf '[runtime-evidence-guard] %s leaks INTERNAL references (IDs, paths, slash-commands, hook names):\n' "$FILE" >&2
    sed 's/^/  /' /tmp/.id-leak-$$ >&2
    printf '  Triagers have ZERO context on the workspace. Each leak confuses the triager and may trigger Informative or NMI.\n' >&2
    printf '  Replace with public anchor (HackerOne #N URL, CVE-YYYY-NNNNN, GHSA-..., vendor doc URL) or remove the line entirely.\n' >&2
    printf '  Cross-references between active workspace findings are noise. Each submission is self-contained.\n' >&2
  fi
  rm -f /tmp/.id-leak-$$
fi

# --- CHECK C: canonical attachment set on disk (advisory, 2026-09-30) ----------------
# Only for a canonical report-shaped draft (it has all three sections). Names the exact
# missing files so the writer can attach them before submit. Never blocks.
if grep -qE '^##[[:space:]]*Summary[[:space:]]*$' "$FILE" 2>/dev/null \
   && grep -qiE '^##[[:space:]]*(PoC|Proof of Concept)[[:space:]]*$' "$FILE" 2>/dev/null \
   && grep -qE '^##[[:space:]]*Impact[[:space:]]*$' "$FILE" 2>/dev/null; then
  DDIR=$(dirname "$FILE")
  MISSING=""
  for want in repro.sh capture.log; do
    [ -e "$DDIR/$want" ] || MISSING="$MISSING $want"
  done
  # one screenshot per ROLE (boundary / attack / control), named by role not by sequence
  for role in boundary attack control; do
    ls "$DDIR"/poc-*-"$role".png >/dev/null 2>&1 || MISSING="$MISSING poc-N-$role.png"
  done
  if [ -n "$MISSING" ]; then
    printf '[runtime-evidence-guard] %s is canonical-shaped but its attachment set is incomplete. Missing:%s\n' "$FILE" "$MISSING" >&2
    printf '  REPORT-FORMAT.md section 10 requires repro.sh (runnable end to end), capture.log (the raw traffic every fenced PoC block was pasted from), and at least ONE screenshot per ROLE - boundary (the 401/403 denial), attack (the crossing), control (the Controls battery). Screenshots are named by role, not by order of capture.\n' >&2
    printf '  Advisory only: the draft is saved. Attach these before submit or the triager reproduces from prose alone.\n' >&2
  fi
fi

# Look for runtime claim
if ! grep -qiE "runtime[_ -]?confirmed[: ]*true|runtime: confirmed|verified.runtime|runtime-verified|reproduced live|reproduced on production|reproduced on live|verified live|confirmed live|tested live|production-confirmed" "$FILE" 2>/dev/null; then
  exit 0
fi

# Look for evidence
HAS_HTTP=$(grep -cE "HTTP/[12](\.[01])? [0-9]{3}" "$FILE" 2>/dev/null || true)
HAS_HTTP=${HAS_HTTP:-0}
HAS_JSON=$(grep -cE "^[[:space:]]*\"[A-Za-z0-9_]+\"[[:space:]]*:|\\\`\\\`\\\`json" "$FILE" 2>/dev/null || true)
HAS_JSON=${HAS_JSON:-0}
HAS_POC=$(grep -cE "poc\.(py|sh|js|ts)|run\.sh|reproduce\.sh" "$FILE" 2>/dev/null || true)
HAS_POC=${HAS_POC:-0}
HAS_ATTACH=$(grep -cE "\\.(png|jpg|gif|har|mp4|webm)" "$FILE" 2>/dev/null || true)
HAS_ATTACH=${HAS_ATTACH:-0}

EVIDENCE=$(( HAS_HTTP + HAS_JSON + HAS_POC + HAS_ATTACH ))

if [ "$EVIDENCE" -lt 1 ]; then
  printf '[runtime-evidence-guard] %s claims runtime confirmed but contains no captured output, PoC script, or attachment. 77%% of source-only findings die here (S9). See ~/.claude/skills/runtime-repro/SKILL.md.\n' "$FILE" >&2
fi

# FAIL-OPEN (lean rebuild 2026-06-14): advisory only. This guard NEVER blocks -
# it emits a stderr warning and always exits 0. The former RUNTIME_HARD=1 exit-2
# path was removed so a hook hiccup can never wedge a report save.
exit 0
