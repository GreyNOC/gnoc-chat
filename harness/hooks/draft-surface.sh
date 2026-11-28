#!/usr/bin/env bash
#
# draft-surface.sh - PostToolUse(Write|Edit).
#
# Findings were getting LOST (GreyNOC, 2026-06-22): an agent either never wrote the
# report (asked "shall I generate it?" instead) or wrote it and it was never
# surfaced. This hook closes the second hole structurally: the instant a file under
# reports/drafts/ is written or edited, it is logged to reports/INBOX.md and a loud
# notice is emitted into context so the orchestrator relays it to GreyNOC. The first
# hole (never written) is closed by doctrine (SPINE 5: a captured terminal receipt
# auto-dispatches the report-writer; never ask).
#
# NEVER blocks (exit 0 always). Surfacing only - submit stays MANUAL. The inbox path
# is reports/INBOX.md (NOT under reports/drafts|submitted, so report-access-gate
# leaves it readable by the main loop and GreyNOC).
set -u

WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
INBOX="$WS/reports/INBOX.md"

PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
case "$TOOL" in Write|Edit) ;; *) exit 0 ;; esac

# workspace-scope guard: never fire on a draft path outside THIS workspace (a cross-repo
# $HOME/reports/drafts/... write was surfacing + inflating the ship ledger).
CWD=$(printf '%s' "$PAYLOAD" | jq -r '.cwd // empty' 2>/dev/null)
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

FP=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
[ -z "$FP" ] && exit 0
case "$FP" in "$WS"/reports/drafts/*|reports/drafts/*) ;; *) exit 0 ;; esac   # only in-workspace drafts
# a finding is the report .md; skip attachments/support files so ships.jsonl (the north-star ledger)
# is not ~3x inflated by repro.sh / capture.log / attacker.html.
case "$FP" in */attachments/*) exit 0 ;; esac
case "$FP" in *.md) ;; *) exit 0 ;; esac

PROG=$(printf '%s' "$FP" | sed -n 's#.*/reports/drafts/\([^/]*\)/.*#\1#p')
TS=$(date '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')

# Seed the inbox once.
if [ ! -f "$INBOX" ]; then
  {
    echo "# Findings inbox - drafts pending GreyNOC's MANUAL submit"
    echo ""
    echo "One line per draft written. A line here means a finding is READY for GreyNOC to"
    echo "submit by hand. Nothing here is auto-submitted. Clear a line after submitting."
    echo ""
  } > "$INBOX" 2>/dev/null
fi

# Log once per path (idempotent across re-edits of the same draft).
if ! grep -qF -- "$FP" "$INBOX" 2>/dev/null; then
  printf -- '- [ ] %s | %s | %s | PENDING-SUBMIT\n' "$TS" "${PROG:-?}" "$FP" >> "$INBOX" 2>/dev/null
fi

# HONEST SHIP LEDGER (the north-star metric SPINE 0 steers by). cycle-log's shipped=0 was
# never wired to anything; this makes terminal-receipts-per-target a real automatic counter.
# Append once per NEW draft path (idempotent).
SHIPS="$WS/.claude/state/hunt-loop/ships.jsonl"
if [ ! -f "$SHIPS" ] || ! grep -qF -- "\"path\":\"$FP\"" "$SHIPS" 2>/dev/null; then
  ISOTS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
  printf '{"ts":"%s","program":"%s","kind":"draft","path":"%s"}\n' "$ISOTS" "${PROG:-?}" "$FP" >> "$SHIPS" 2>/dev/null
fi

# Surface into context (stdout on a PostToolUse exit-0 is shown to the model).
printf '[DRAFT SURFACED -> reports/INBOX.md] A finding draft was written for "%s": %s\n' "${PROG:-?}" "$FP"
printf 'TELL GREYNOC NOW: this draft is READY and PENDING his MANUAL submit. Do NOT auto-submit. Do NOT re-open it (DRAFTED IS DONE). If more findings exist, write their drafts too - never ask permission to write a report.\n'

# Format lint - PLATFORM-AWARE. Immunefi drafts use the 7-section dashboard form
# (impact-based, NO CVSS/CWE header, 2500-3000 words - GreyNOC 2026-06-28); every other
# platform uses the H1 3-section shape (CVSS+Asset+CWE header above a sub-120 title,
# body under 1200). Non-blocking - surfaces the fix into context before GreyNOC submits.
if [ -f "$FP" ]; then
  SCOPE="$WS/targets/${PROG:-_}/SCOPE.txt"
  if [ -f "$SCOPE" ] && grep -qi 'immunefi\.com' "$SCOPE" 2>/dev/null; then
    # --- Immunefi 7-section dashboard form ---
    WARN=""
    for s in TITLE ASSET IMPACT "BUG DESCRIPTION" "PROOF OF CONCEPT" RECOMMENDATION REFERENCES; do
      grep -qiE "^#{1,3}[[:space:]]+$s" "$FP" 2>/dev/null || WARN="$WARN missing '$s';"
    done
    WC=$(wc -w < "$FP" 2>/dev/null | tr -d ' ')
    if [ -n "$WC" ]; then
      [ "$WC" -lt 2500 ] 2>/dev/null && WARN="$WARN body ${WC} words (Immunefi band 2500-3000, too thin);"
      [ "$WC" -gt 3000 ] 2>/dev/null && WARN="$WARN body ${WC} words (Immunefi band 2500-3000, compress);"
    fi
    [ -n "$WARN" ] && printf 'IMMUNEFI FORMAT-FIX before submit:%s  Required: 7 dashboard sections (TITLE/ASSET/IMPACT/BUG DESCRIPTION/PROOF OF CONCEPT/RECOMMENDATION/REFERENCES), 2500-3000 words, impact-based (no CVSS).\n' "$WARN"
    printf 'IMMUNEFI BULLET GATE (1 submit/week - cannot miss): before READY run  scripts/immunefi-presubmit.sh "%s" <gist_dir>  then report-killer Primacy-of-Rules + a clean-container repro. Declared asset AND the fix-bearing component must BOTH be LISTED in-scope (berachain #83336 closed OOS in 29 min).\n' "$FP"
  else
    # --- H1 / default 3-section shape ---
    WARN=""
    TLINE=$(grep -nE '^# ' "$FP" 2>/dev/null | head -1)
    if [ -n "$TLINE" ]; then
      TNUM=${TLINE%%:*}
      TTXT=${TLINE#*:}; TTXT=${TTXT#"# "}
      [ "${#TTXT}" -gt 120 ] && WARN="$WARN title is ${#TTXT} chars (cap 120);"
      HN=0; [ "$TNUM" -gt 1 ] 2>/dev/null && HN=$((TNUM-1))
      HEAD=$(head -n "$HN" "$FP" 2>/dev/null)
      printf '%s' "$HEAD" | grep -qiE 'CVSS'   || WARN="$WARN CVSS header missing above title;"
      printf '%s' "$HEAD" | grep -qiE '^asset' || WARN="$WARN Asset header missing above title;"
      printf '%s' "$HEAD" | grep -qiE 'CWE'    || WARN="$WARN CWE header missing above title;"
    else
      WARN="$WARN no '# <title>' line found;"
    fi
    WC=$(wc -w < "$FP" 2>/dev/null | tr -d ' ')
    [ -n "$WC" ] && [ "$WC" -gt 1200 ] 2>/dev/null && WARN="$WARN body is ${WC} words (cap 1200, ideal 600-800 - compress);"
    [ -n "$WARN" ] && printf 'FORMAT-FIX before GreyNOC submits:%s  Required shape: CVSS + Asset + CWE lines ABOVE a sub-120-char title, then Summary / PoC / Impact only, max compression, zero-context reproducible.\n' "$WARN"
  fi
fi
exit 0
