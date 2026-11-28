#!/usr/bin/env bash
# qaqc.sh - mechanical QA/QC gate. Run BEFORE a report is promoted to QA-READY.
# Checks only what a machine can check with certainty. Judgement stays with
# triage-validator / report-killer; this catches the MECHANICAL defects, which is
# every defect our last 7 closed H1 reports actually had.
# Usage: scripts/qaqc.sh <program>/<slug> [--quiet]
# Exit 0 = PASS, 1 = FAIL, 2 = usage.
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "${1:-}" = "--selftest" ]; then
  t=$(mktemp -d); mkdir -p "$t/p/s/evidence"
  printf '**Summary**\n\nI read a private object across a tenant boundary.\n\n**Proof of Concept**\n\n1. Probe\n```bash\ncurl -s https://x.test/a\n```\nConfirmed result:\n```\nHTTP 200\n```\n\n## Impact\n\nI read another tenant object.\n' > "$t/p/s/report.md"
  echo "x" > "$t/p/s/evidence/capture.log"
  printf 'Title: a\nAsset: b\nCWE: CWE-200\nCVSS: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3 Medium\n' > "$t/p/s/FORM.md"
  out=$(D_OVERRIDE="$t" "$0" p/s --quiet 2>&1); rc=$?
  [ $rc -eq 0 ] && echo "ok:   clean report PASSes" || { echo "FAIL: clean report rejected:"; echo "$out"; exit 1; }
  printf '\nIt is worth noting this leverages a comprehensive bypass -- see ${GNOC_WORKSPACE:-$HOME/.gnoc}/x.\n' >> "$t/p/s/report.md"
  out=$(D_OVERRIDE="$t" "$0" p/s --quiet 2>&1); rc=$?
  [ $rc -ne 0 ] && echo "ok:   slop + workspace path REJECTED" || { echo "FAIL: slop not caught"; exit 1; }
  for p in "it is worth noting" "leverag" "comprehensive" "double-hyphen" "workspace path"; do
    printf '%s' "$out" | grep -qi -- "$p" && echo "ok:   flagged $p" || echo "warn: did not name $p"
  done
  rm -rf "$t"; echo "---- selftest done ----"; exit 0
fi

T="${1:-}"; [ -n "$T" ] || { echo "usage: qaqc.sh <program>/<slug>" >&2; exit 2; }
QUIET=0; [ "${2:-}" = "--quiet" ] && QUIET=1
D="${D_OVERRIDE:-$WS/reports/drafts}"
DIR="$D/${T%%/*}/${T#*/}"; R="$DIR/report.md"
[ -f "$R" ] || { echo "no such draft: $R" >&2; exit 2; }

FAIL=(); WARN=()
f(){ FAIL+=("$1"); }
w(){ WARN+=("$1"); }

# prose = report with fenced blocks stripped. Code is never linted for voice.
PROSE="$(awk '/^```/{inb=!inb; next} !inb' "$R")"

# ---- 1. structure -----------------------------------------------------------
grep -qiE '^\*\*Summary\*\*|^## Summary' "$R" || f "no Summary section"
grep -qiE '^[*][*]proof of concept[*][*]|^#+ *(poc|proof of concept|steps to reproduce|reproduction)' "$R" || f "no Proof of Concept section"
grep -qiE '^## Impact|^\*\*Impact\*\*' "$R" || f "no Impact section"

# ---- 2. evidence ------------------------------------------------------------
NB=$(grep -c '^```' "$R"); NB=$((NB/2))
[ "$NB" -ge 1 ] || f "zero fenced code blocks (3 of our 7 closed reports had none)"
grep -qiE 'confirmed result|relevant results|captured|HTTP [0-9]{3}|^HTTP/' "$R" \
  || w "no captured-output marker (Confirmed result: / HTTP nnn) - is the response shown?"
if [ -d "$DIR/evidence" ]; then
  [ -n "$(ls -A "$DIR/evidence" 2>/dev/null)" ] || f "evidence/ exists but is EMPTY"
fi

# ---- 3. anti-slop voice (prose only) ---------------------------------------
# em dash / double-hyphen standing in for one
printf '%s' "$PROSE" | grep -q '—' && f "em dash in prose (banned)"
printf '%s' "$PROSE" | grep -qE '[a-zA-Z] -- [a-zA-Z]' && f "double-hyphen used as an em dash (banned)"
SLOP='it is worth noting|it.s worth noting|important to note|notably,|crucially|significantly,|comprehensive|robust|seamless|leverag|utiliz|delve|underscore|pivotal|in today.s|as a security researcher|this finding demonstrates|could potentially|may possibly|might be able to|it should be noted'
while IFS= read -r hit; do [ -n "$hit" ] && f "AI-slop phrase: \"$hit\""; done < <(printf '%s' "$PROSE" | grep -oiE "$SLOP" | sort -u)
printf '%s' "$PROSE" | LC_ALL=C grep -qP '[\x{1F300}-\x{1FAFF}]' 2>/dev/null && f "emoji in prose"
printf '%s' "$PROSE" | grep -q '!' && w "exclamation mark in prose - check it is inside a command, not a claim"

# ---- 4. internal references (never leak our own plumbing) -------------------
while IFS= read -r hit; do [ -n "$hit" ] && f "internal workspace path leaked: $hit"; done \
  < <(grep -rhoE '$HOME/[A-Za-z0-9_./-]+|/tmp/claude-[0-9]+/[A-Za-z0-9_./-]+' "$R" "$DIR"/*.log "$DIR"/*.sh "$DIR"/evidence/* 2>/dev/null | sort -u | head -5)
# Gate:/Dedup: lines are REQUIRED in the draft (the draft-write gate blocks a save without
# them) and are STRIPPED from the staged bundle by qa-handoff.sh:203, so they never reach a
# vendor. Exclude those lines before scanning, or every compliant draft fails. Verified
# empirically 2026-10-05 after this check produced 12 false positives, all on the stamp line.
while IFS= read -r hit; do [ -n "$hit" ] && f "internal agent/tool name leaked: $hit"; done \
  < <(grep -vE '^[[:space:]]*(Gate|Dedup): ' "$R" \
      | grep -ohiE 'report-killer|triage-validator|report-writer-agent|reviewer-agent|dedup-scout|scratchpad|subagent|hunt-loop|do-not-rehunt' \
      2>/dev/null | sort -u | head -5)
grep -qE '^[[:space:]]*Gate: ' "$R" || w "no Gate: stamp - the draft-write gate requires one (it is stripped at staging)"

# ---- 5. placeholders --------------------------------------------------------
while IFS= read -r hit; do [ -n "$hit" ] && f "placeholder left in draft: $hit"; done \
  < <(grep -ohE '\bTODO\b|\bTBD\b|\bFIXME\b|XXXX|<[A-Z_]{3,}>|\bREDACTED\b|\bPLACEHOLDER\b' "$R" | sort -u | head -5)

# ---- 6. title ---------------------------------------------------------------
TITLE="$(grep -m1 '^# ' "$R" | sed 's/^# //')"
if [ -n "$TITLE" ]; then
  [ "${#TITLE}" -le 120 ] || f "title is ${#TITLE} chars, cap 120"
  printf '%s' "$TITLE" | grep -qE '[`*|#]' && f "markdown characters in the title field (backtick, asterisk, pipe or hash)"
  printf '%s' "$TITLE" | LC_ALL=C grep -qP '[^\x20-\x7E]' 2>/dev/null && f "non-ASCII character in the title"
fi

# ---- 7. prose word caps (fenced blocks excluded) ---------------------------
sec_words(){ awk -v pat="$1" '
  /^```/{inb=!inb; next} inb{next}
  tolower($0) ~ pat {on=1; next}
  on && /^([*][*][A-Z]|## )/ {on=0}
  on {print}' "$R" | wc -w; }
SW=$(sec_words '^[*][*]summary[*][*]|^## summary')
IW=$(sec_words '^## impact|^[*][*]impact[*][*]')
[ "${SW:-0}" -gt 150 ] && f "Summary prose is $SW words, cap 150"
[ "${IW:-0}" -gt 150 ] && f "Impact prose is $IW words, cap 150"

# ---- 8. FORM.md (the platform's own fields live here, not in the body) -----
if [ -f "$DIR/FORM.md" ]; then
  for k in Title Asset CWE CVSS; do grep -qi "^$k:" "$DIR/FORM.md" || f "FORM.md missing '$k:'"; done
else
  f "no FORM.md (platform field values: Title, Asset, CWE, CVSS)"
fi
grep -qE '^(CVSS|Asset|CWE):' "$R" && w "CVSS/Asset/CWE header block is in the BODY - style says it belongs in FORM.md"

# ---- 9. manifest reconciles with a directory walk, BOTH directions ---------
if [ -f "$DIR/ATTACHMENTS.txt" ]; then
  # Staging builds ATTACHMENTS.txt from the evidence directory ONLY, with paths relative to
  # it (qa-handoff.sh:238). Walk the same set, or the comparison flags report.md and FORM.md
  # as missing attachments and the check is noise. Caught by the regression suite 2026-10-05.
  if [ -d "$DIR/evidence" ]; then
    WALK=$(cd "$DIR/evidence" && find . -type f ! -name ATTACHMENTS.txt ! -name SHA256SUMS.txt -printf '%P\n' | sort)
  else
    WALK=$(cd "$DIR" && find . -maxdepth 1 -type f ! -name ATTACHMENTS.txt ! -name SHA256SUMS.txt \
             ! -name report.md ! -name FORM.md ! -name GATES.md ! -name LEAD.md -printf '%P\n' | sort)
  fi
  MAN=$(sort "$DIR/ATTACHMENTS.txt" | sed 's#^\./##' | grep -v '^$')
  while IFS= read -r m; do [ -n "$m" ] && ! printf '%s\n' "$WALK" | grep -qxF "$m" && f "ATTACHMENTS names a file not on disk: $m"; done <<< "$MAN"
  while IFS= read -r d; do [ -n "$d" ] && ! printf '%s\n' "$MAN" | grep -qxF "$d" && w "on disk but not in ATTACHMENTS: $d"; done <<< "$WALK"
fi

# ---- 10. staged form must not drift from report.md --------------------------
# A near-miss 2026-10-05: a report sat one click from a vendor with its staged form text TWO
# generations behind report.md - missing the determinism block, the isolation control and the
# provenance disclaimers, which turned condensed quotes into unlabelled edits of captures.
FORMTXT=""
for c in "$DIR"/form/*.md "$DIR"/form/*.txt "$DIR"/FORM-STAGED.md "$DIR"/submission.txt; do
  [ -f "$c" ] && FORMTXT="$FORMTXT
$(cat "$c")"
done
if [ -n "${FORMTXT// /}" ]; then
  NORM_FORM="$(printf '%s' "$FORMTXT" | tr 'A-Z' 'a-z' | tr -s '[:space:]' ' ')"
  MISS=0; TOT=0
  while IFS= read -r sent; do
    sent="$(printf '%s' "$sent" | sed 's/^ *//;s/ *$//')"
    [ "${#sent}" -ge 40 ] || continue
    TOT=$((TOT+1))
    key="$(printf '%s' "$sent" | tr 'A-Z' 'a-z' | tr -s '[:space:]' ' ')"
    printf '%s' "$NORM_FORM" | grep -qF -- "$key" || MISS=$((MISS+1))
  done < <(printf '%s' "$PROSE" | tr '.' '\n')
  if [ "$TOT" -gt 0 ]; then
    PCT=$(( MISS * 100 / TOT ))
    if [ "$PCT" -gt 20 ]; then
      f "STAGED FORM HAS DRIFTED from report.md: $MISS of $TOT prose sentences ($PCT%) are in the report but NOT in the staged form text. Regenerate form/ from the current report before filing."
    elif [ "$MISS" -gt 0 ]; then
      w "staged form differs from report.md in $MISS of $TOT sentences ($PCT%) - check it is intentional"
    fi
  fi
fi

# ---- 11. re-run the draft-write gate (closes the Bash authoring bypass) -----
# That gate is PreToolUse on Write|Edit only. Agents are told to prefer Bash for file changes,
# so a draft written with a heredoc never meets it - including its substantive
# CAPABILITY+TERMINAL check. Re-running it HERE gates the PROMOTION boundary, which no
# authoring method can route around. Measured 2026-10-05: a draft was authored via Bash
# carrying no captured new capability; the gate would have refused it at write time.
GATEHOOK="$WS/.claude/hooks/draft-write-gate.sh"
if [ -x "$GATEHOOK" ] && command -v jq >/dev/null 2>&1; then
  rm -f "$WS/.claude/state/learning/draftgate-qaqc-promote.count" 2>/dev/null
  GOUT="$(jq -nc --arg p "$R" --rawfile c "$R" \
      '{cwd:"${GNOC_WORKSPACE:-$HOME/.gnoc}",session_id:"qaqc-promote",tool_name:"Write",tool_input:{file_path:$p,content:$c}}' \
      2>/dev/null | "$GATEHOOK" 2>&1)"
  GRC=$?
  rm -f "$WS/.claude/state/learning/draftgate-qaqc-promote.count" 2>/dev/null
  if [ "$GRC" -eq 2 ]; then
    GWHY="$(printf '%s' "$GOUT" | grep -oE 'DRAFT BLOCKED \([^)]*\)' | head -1)"
    f "draft-write gate REFUSES this draft: ${GWHY:-see gate output}. It was authored in a way that skipped that gate. Fix the defect; if it is a genuine edge case, GreyNOC approves the override sentinel - never self-approve it."
  fi
fi

# ---- verdict ----------------------------------------------------------------
if [ "$QUIET" -eq 0 ]; then
  echo "QAQC  $T"
  echo "      prose: Summary=${SW:-?}w Impact=${IW:-?}w | fenced blocks: $NB"
fi
for x in "${WARN[@]:-}"; do [ -n "$x" ] && echo "  WARN  $x"; done
for x in "${FAIL[@]:-}"; do [ -n "$x" ] && echo "  FAIL  $x"; done
NF=0; for x in "${FAIL[@]:-}"; do [ -n "$x" ] && NF=$((NF+1)); done
if [ "$NF" -gt 0 ]; then echo "QAQC FAIL ($NF blocking) - not promoted."; exit 1; fi
echo "QAQC PASS"; exit 0
