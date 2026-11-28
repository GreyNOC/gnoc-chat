#!/usr/bin/env bash
#
# qa-handoff-stage.sh - PostToolUse(Write|Edit).
#
# Closes the last hole in the finding pipeline. draft-surface.sh already logs a finalized
# draft to reports/INBOX.md so it is not LOST. This hook goes one step further and STAGES it
# into the QA handoff pipeline, so a human QA has the report plus every artifact it
# references, with manifests generated from a directory walk, without anyone doing it by hand.
#
# It stages. It does NOT submit, and it does NOT mark anything verified - the staged
# STATUS.md says plainly that it was auto-staged and still needs QA. Submission is human-only.
#
# NEVER blocks (exit 0 always). Cheap by construction: it only fires on a canonical report
# filename, and the stager is idempotent, so a re-edit of the same draft re-syncs rather than
# duplicating. The full pipeline SWEEP (scripts/qa-sweep.sh) is NOT run here - it walks
# targets/, which is 13G and 560k files, and belongs on-demand or at session start.
set -u

WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
STAGER="$WS/scripts/qa-handoff.sh"
[ -x "$STAGER" ] || exit 0

PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
case "$TOOL" in Write|Edit) ;; *) exit 0 ;; esac

# workspace-scope guard, same reasoning as draft-surface.sh: never fire on a draft path
# outside THIS workspace.
CWD=$(printf '%s' "$PAYLOAD" | jq -r '.cwd // empty' 2>/dev/null)
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

FP=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
[ -z "$FP" ] && exit 0
case "$FP" in /*) ;; *) FP="$WS/$FP" ;; esac
case "$FP" in "$WS"/reports/drafts/*) ;; *) exit 0 ;; esac
[ -f "$FP" ] || exit 0

# Only a canonical REPORT file. Form fields, gate logs, audits, recapture plans and triager
# replies are support files - staging on those would re-sync the bundle dozens of times per
# report and (measured) inflate a draft count of 11 into 31.
case "$FP" in */form/*|*/attachments/*|*/triage-reply-*) exit 0 ;; esac
case "$FP" in *.md) ;; *) exit 0 ;; esac
BASE=$(basename "$FP")
case "$BASE" in
  GATES.md|FORM-STAGED.md|PRESEND-AUDIT-*.md|RECAPTURE-PLAN.md|REOPEN-REQUEST.md|REPLY-*.md|NOTES*.md|LEAD.md|CLOSEOUT.md|INBOX.md) exit 0 ;;
esac

# A report is report.md, or a <slug>.md sitting at the program root. Anything deeper that is
# not report.md is a support note.
REL=${FP#"$WS"/reports/drafts/}
DEPTH=$(printf '%s' "$REL" | tr -cd '/' | wc -c)
if [ "$BASE" != "report.md" ] && [ "$DEPTH" -gt 1 ]; then exit 0; fi

# Stage it. Quiet, idempotent, and tolerant of its own failure - a staging problem must never
# break the write that triggered it.
OUT=$("$STAGER" --quiet "$FP" 2>&1) || {
  printf '[QA-HANDOFF] staging FAILED for %s - stage it by hand with: scripts/qa-handoff.sh "%s"\n' "${FP#$WS/}" "${FP#$WS/}"
  printf '%s\n' "$OUT" | tail -3
  exit 0
}

DEST=$(printf '%s' "$OUT" | tail -1)
case "$DEST" in
  "$WS"/QA*)
    NF=0; [ -f "$DEST/ATTACHMENTS.txt" ] && NF=$(wc -l < "$DEST/ATTACHMENTS.txt" 2>/dev/null | tr -d ' ')
    SHA="n/a"
    [ -d "$DEST/evidence" ] && { ( cd "$DEST/evidence" && sha256sum -c SHA256SUMS.txt >/dev/null 2>&1 ) && SHA=PASS || SHA=FAIL; }
    printf '[QA-HANDOFF] staged -> %s  (evidence=%s, sha=%s)\n' "${DEST#$WS/}" "$NF" "$SHA"
    printf 'It is AUTO-STAGED, not QA-verified: STATUS.md in that folder lists what was checked and what a human QA still owns. Nothing was submitted.\n'
    [ "$SHA" = "FAIL" ] && printf 'WARNING: the staged evidence checksums do NOT verify. Fix before handing to QA.\n'
    ;;
  *) : ;;
esac
exit 0
