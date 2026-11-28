#!/usr/bin/env bash
# draft-dead-risk-gate.sh - PostToolUse(Write|Edit) hook. Fires when a report DRAFT is
# written or edited under reports/drafts/. Directly targets GreyNOC's reported disease:
# "we generate drafts but on review they are dead." A dead draft is a MECHANISM or a
# PRIMITIVE dressed as a finding with NO captured terminal receipt - the adversarial
# kill pass then kills it, a week of them, zero valid reports.
#
# It inspects the just-written draft for captured-evidence signatures. If the draft is
# prose-only (no HTTP capture / no runnable PoC) OR carries theoretical hedging language,
# it warns the orchestrator LOUDLY to run the kill pass and clear the three gates BEFORE
# surfacing the draft to GreyNOC. Non-blocking (AUTO-WRITE doctrine never loses a finding) -
# it forces the review to happen at write time, not after GreyNOC finds it dead.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

FP=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null || echo "")
case "$FP" in */reports/drafts/*) ;; *) exit 0 ;; esac
case "$FP" in *.md) ;; *) exit 0 ;; esac
[ -f "$FP" ] || exit 0

BODY=$(head -c 40000 "$FP" 2>/dev/null)
[ -z "$BODY" ] && exit 0

# Captured-evidence signatures a LIVE PoC carries (status line, curl, real response bytes).
EVID='HTTP/[12]|< HTTP|HTTP/1\.1 [0-9]|(200 OK|201 Created|204 |301 |302 |307 |401 Unauth|403 Forbid|500 )|curl -|curl "|send_http|set-cookie:|content-length:|content-type:|capture\.log|repro\.(sh|py)|attacker\.(html|py)|X-Cache|Location: https?:'
# Theoretical / no-capture red-flag language (the vendor reads only what you PROVED). The second
# half is the exact string set that leaked into our real dead-on-review drafts (source-leg missing,
# capability asserted not captured): "pending a captured", "inference", "one account away", etc.
THEORY='could allow|may allow|an attacker could|it is possible that|theoretically|would be able to|this could lead|potentially allow|might be able|is vulnerable to.*(if|when)|pending a captured|labeled inference|\binference\b|very likely|one account away|definitional|narrated|assuming (the|a|an)|would be possible'

has_evid=false;   echo "$BODY" | grep -qiE "$EVID"   && has_evid=true
has_theory=false; echo "$BODY" | grep -qiE "$THEORY" && has_theory=true

# Healthy draft: captured evidence present AND no theoretical hedging. Pass silently.
$has_evid && ! $has_theory && exit 0

WHY=""
$has_evid || WHY="${WHY}no captured HTTP/response/PoC evidence in the draft body; "
$has_theory && WHY="${WHY}theoretical language present (could/may/would/potentially); "

MSG="DEAD-DRAFT RISK on $(basename "$FP"): ${WHY}this is the exact shape that closed our last week of drafts dead-on-review. Before you tell GreyNOC this draft is ready or point him at the INBOX, you MUST run report-killer (fresh context, tries to KILL it) and triage-validator (re-run the PoC, capture the byte-level terminal response), and confirm all three gates: CAPABILITY (a NEW cross-tenant / state-change / exfil / RCE capability captured in a real response, not a mechanism), TERMINAL (the PoC ends at the terminal action with captured bytes), REACHABILITY (the precondition is produced on the real production path with its own captured receipt, not hand-injected). If any gate fails, this is a LEAD, not a finding - return to hunting and do not surface it. Never auto-submit."

jq -nc --arg c "$MSG" '{hookSpecificOutput:{hookEventName:"PostToolUse", additionalContext:$c}}'
exit 0
