#!/usr/bin/env bash
#
# qa-sweep.sh - find every report the QA pipeline is not yet seeing.
#
# WHY. Reports do not only live in the drafts tree. A hunt finalizes something inside
# targets/<program>/ and it then never reaches QA, and a NEW program can be intaken without
# anyone noticing it has findings. This sweep answers, on demand:
#   1. which programs are new since the last sweep
#   2. which report- or finding-shaped artifacts exist ANYWHERE in the workspace, and what
#      their triage state is
#   3. which drafts exist but were never staged for QA
#
# WHAT CHANGED 2026-10-02. Detection used to live in this file: it walked only targets/ and
# the reports tree, keyed on a CVSS line or a Summary+Impact pair, and treated "this program
# has something staged" as "every artifact of this program is accounted for". That
# combination reported 2 artifacts inside targets/ when there were 18, because a
# hunt-authored FINDINGS.txt / FINDING.md / lead.md carries neither content signal, and
# because one staged report masked its siblings. Detection now lives in
# scripts/qa-report-scan.py, which walks the WHOLE workspace except the QA pipeline itself,
# matches per ARTIFACT rather than per program, and resolves each one through
# .claude/state/hunt-loop/qa-artifact-ledger.tsv into covered / to-draft / lead /
# not-a-report. UNRESOLVED is the only state that asks for a human decision.
#
# Read-only except for its own ledger and the report it writes. Never submits anything.
#
# Usage: qa-sweep.sh [--quiet] [--stage]      --stage auto-stages unstaged drafts
set -u
WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
QA="$WS/QA handoff"
DRAFTS="$WS/reports/drafts"
LEDGER="$WS/.claude/state/hunt-loop/qa-seen-programs.txt"
SCAN="$WS/scripts/qa-report-scan.py"
OUT="$QA/_SWEEP.md"
QUIET=0; DOSTAGE=0
for a in "$@"; do case "$a" in --quiet) QUIET=1 ;; --stage) DOSTAGE=1 ;; esac; done
log(){ [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }

mkdir -p "$(dirname "$LEDGER")" "$QA" 2>/dev/null
touch "$LEDGER" 2>/dev/null

# ---------- 1. programs + new intakes ----------
ALLPROGS=$(ls -d "$WS"/targets/*/ 2>/dev/null | sed 's#.*/targets/##; s#/$##' | sort)
NPROG=$(printf '%s\n' "$ALLPROGS" | grep -c . || true)
NEW=""
while IFS= read -r p; do
  [ -z "$p" ] && continue
  grep -qxF "$p" "$LEDGER" 2>/dev/null || NEW="$NEW $p"
done <<< "$ALLPROGS"

intaken(){ local p="$1"
  [ -f "$WS/targets/$p/SCOPE.txt" ] || [ -f "$WS/targets/$p/scope.txt" ] \
  || [ -f "$WS/targets/$p/PROGRAM.md" ] || [ -f "$WS/targets/$p/intake.json" ]
}

# ---------- 2. every report + finding artifact, workspace-wide ----------
SCANJSON=$(mktemp); SCANMD=$(mktemp)
trap 'rm -f "$SCANJSON" "$SCANMD" 2>/dev/null' EXIT
python3 "$SCAN" --json > "$SCANJSON" 2>/dev/null || { echo "qa-report-scan.py failed" >&2; exit 1; }
python3 "$SCAN"        > "$SCANMD"   2>/dev/null
read -r NREPORT NFIND NUNRES NTODRAFT NLEAD < <(python3 - "$SCANJSON" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))["rows"]
r=[x for x in d if x["cls"]=="REPORT"]; f=[x for x in d if x["cls"]=="FINDING-NOTE"]
u=[x for x in r+f if not x["represented"]]
print(len(r),len(f),len(u),
      sum(1 for x in r+f if x["state"]=="to-draft"),
      sum(1 for x in r+f if x["state"]=="lead"))
PY
)

# ---------- 3. drafts never staged ----------
# Filename and shape only. This never prints a draft's contents, so the sweep stays usable
# from a context that is not allowed to read the drafts themselves.
is_draft_report(){ local f="$1"
  case "$f" in */form/*|*/triage-reply-*|*/attachments/*) return 1 ;; esac
  case "$(basename "$f")" in report.md) return 0 ;; esac
  grep -qE '^(CVSS:|\*\*CVSS)' "$f" 2>/dev/null && return 0
  grep -qE '^##[[:space:]]*Summary' "$f" 2>/dev/null \
    && grep -qE '^##[[:space:]]*Impact' "$f" 2>/dev/null && return 0
  return 1
}
UNSTAGED=""; NDRAFT=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  is_draft_report "$f" || continue
  NDRAFT=$((NDRAFT+1))
  prog=${f#$DRAFTS/}; prog=${prog%%/*}
  slug=$(basename "$f" .md); [ "$slug" = "report" ] && slug=$(basename "$(dirname "$f")")
  if ! find "$QA" -type d \( -name "${prog}_${slug}" -o -name "*_${prog}_${slug}" \) 2>/dev/null | grep -q .; then
    UNSTAGED="${UNSTAGED}${prog}/${slug}|$f
"
  fi
done < <(find "$DRAFTS" -type f -name '*.md' 2>/dev/null | sort)
NUNSTAGED=$(printf '%s' "$UNSTAGED" | grep -c . || true)

# ---------- report ----------
{
  echo "# QA pipeline sweep"
  echo
  echo "Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by scripts/qa-sweep.sh"
  echo "Detection: scripts/qa-report-scan.py (whole workspace, QA pipeline excluded)"
  echo
  echo "## Coverage"
  echo
  echo "| Metric | Count |"
  echo "|---|---|"
  echo "| Program folders under targets/ | $NPROG |"
  echo "| Programs new since last sweep | $(printf '%s' "$NEW" | wc -w) |"
  echo "| Draft reports in the drafts tree | $NDRAFT |"
  echo "| Staged in the QA pipeline | $(find "$QA" -type d -name '*_*' -exec test -f '{}/REPORT.md' \; -print 2>/dev/null | wc -l) |"
  echo "| Reports found workspace-wide | $NREPORT |"
  echo "| Finding notes found workspace-wide | $NFIND |"
  echo "| Report-grade with no draft (to-draft) | $NTODRAFT |"
  echo "| Tracked leads, correctly not reports yet | $NLEAD |"
  echo "| UNRESOLVED (needs a human decision) | $NUNRES |"
  echo "| Drafts never staged | $NUNSTAGED |"
  echo
  if [ -n "$(printf '%s' "$NEW" | tr -d ' ')" ]; then
    echo "## NEW programs since the last sweep"
    echo
    for p in $NEW; do
      if intaken "$p"; then echo "- \`$p\` - intaken (scope/program files present)"
      else echo "- \`$p\` - **folder exists but NOT intaken** (no SCOPE.txt / PROGRAM.md / intake.json)"; fi
    done
    echo
  fi
  if [ "$NUNSTAGED" -gt 0 ]; then
    echo "## Drafts never staged for QA"
    echo
    printf '%s' "$UNSTAGED" | grep . | while IFS='|' read -r id path; do
      echo "- \`$id\` -> \`${path#$WS/}\`"
    done
    echo
    echo "Stage them with: \`scripts/qa-handoff.sh --all\`"
    echo
  fi
  echo "## Every report and finding artifact, with its triage state"
  echo
  sed '1d' "$SCANMD"
  echo
  echo "## How a state is set"
  echo
  echo "UNRESOLVED means nobody has read the artifact and decided. Resolve it by appending a"
  echo "line to \`.claude/state/hunt-loop/qa-artifact-ledger.tsv\`:"
  echo
  echo '```'
  echo "<path><TAB>covered|to-draft|lead|not-a-report<TAB><one-line reason>"
  echo '```'
  echo
  echo "A hunt closing-package or a route-sweep note is not a report. A finding note whose"
  echo "defect is captured in response bytes and has no draft on disk is \`to-draft\`, and that"
  echo "is the state worth money."
  echo
  echo "## Not checked here"
  echo
  echo "This sweep finds reports and records a triage state. It does not re-judge the evidence."
  echo "Whether a staged report is submittable is a QA question, and whether a new program is"
  echo "worth hunting is an EV question."
} > "$OUT"

printf '%s\n' "$ALLPROGS" > "$LEDGER" 2>/dev/null

if [ "$DOSTAGE" -eq 1 ] && [ "$NUNSTAGED" -gt 0 ]; then
  log "staging unstaged drafts ..."
  "$WS/scripts/qa-handoff.sh" --all ${QUIET:+--quiet} >/dev/null 2>&1
fi

# keep the human dashboard in step with the sweep. Non-fatal: a dashboard that fails to
# rebuild must never break the sweep or the hook that calls it.
"$WS/scripts/reports.sh" status >/dev/null 2>&1 || true

log "sweep written: ${OUT#$WS/}"
[ "$QUIET" -eq 1 ] || sed -n '/## Coverage/,/^$/p;/^| /p' "$OUT" | head -18
exit 0
