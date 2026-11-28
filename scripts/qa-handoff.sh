#!/usr/bin/env bash
#
# qa-handoff.sh - stage a finalized report into the QA handoff pipeline.
#
# WHY THIS EXISTS. Reports were finalized in reports/drafts/ and then sat there: 53% of
# drafts were never submitted, and the ones that were had manifest defects that a human QA
# would have caught. This script makes the handoff structural instead of manual, and it
# generates every manifest from a DIRECTORY WALK rather than from typed text, because a
# typed manifest naming files that are not on disk has already cost this workspace a report.
#
# It stages. It does NOT submit, and it does NOT claim a report is verified. It records
# exactly which checks it ran so a human QA knows what is still theirs to do.
#
# Usage:
#   qa-handoff.sh <draft.md>                  stage that report
#   qa-handoff.sh --program <p> --slug <s>    stage by program + slug
#   qa-handoff.sh --all                       stage every draft not yet staged
#   qa-handoff.sh --ready <draft.md>          stage and mark QA-READY (a gate passed)
#   qa-handoff.sh --list                      show the queue
# Flags: --quiet  --force (re-sync even if unchanged)
set -u

# Overridable so the pipeline can be exercised against a sandbox root by the e2e test.
# Default is unchanged, so production behaviour is identical. reports.sh already did this.
WS="${WS:-${GNOC_WORKSPACE:-$HOME/.gnoc}}"
QA="$WS/QA handoff"
QUIET=0; READY=0; FORCE=0
MAX_FILES=3000          # refuse to copy a pathological tree (a 19k-file browser profile dir)
MAX_BYTES=314572800     # 300MB

log(){ [ "$QUIET" -eq 1 ] || printf '%s\n' "$*"; }
die(){ printf 'qa-handoff: %s\n' "$*" >&2; exit 1; }

# ---------- venue detection, from the program's own files ----------
venue_of(){
  # split the declarations: `local p="$1" t="$WS/targets/$p"` is not reliably evaluated
  # left-to-right under set -u and threw "p: unbound variable", which silently produced an
  # empty venue prefix on staged folder names.
  local p t v
  p="$1"; t="$WS/targets/$p"; v=""
  # 1. an explicit intake record wins
  if [ -f "$t/intake.json" ]; then
    v=$(grep -oE '"platform"[[:space:]]*:[[:space:]]*"[^"]+"' "$t/intake.json" 2>/dev/null | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
  fi
  # 2. otherwise sniff every file a program plausibly carries its venue in. program-52 has
  #    no PROGRAM.md and no intake.json - it names HackerOne in policy.md / RULES.md / the
  #    pinned scope header - which is why an earlier version of this produced an empty venue.
  if [ -z "$v" ]; then
    local f hit=""
    for f in "$t/PROGRAM.md" "$t/policy.md" "$t/RULES.md" "$t/SCOPE.txt" "$t/scope.txt" \
             "$t/scope.md" "$t/brief_rules.html" "$t/notes.md" "$t/NOTES.md"; do
      [ -f "$f" ] || continue
      hit=$(grep -ohiE 'yeswehack|bugbounty\.meta\.com|facebook\.com/whitehat|immunefi|bugcrowd|hackerone|intigriti|huntr' "$f" 2>/dev/null | head -1 | tr 'A-Z' 'a-z')
      [ -n "$hit" ] && break
    done
    case "$hit" in
      yeswehack)                        v=yeswehack ;;
      bugbounty.meta.com|facebook.com/whitehat) v=meta ;;
      immunefi)                         v=immunefi ;;
      bugcrowd)                         v=bugcrowd ;;
      hackerone)                        v=hackerone ;;
      intigriti)                        v=intigriti ;;
      huntr)                            v=huntr ;;
    esac
  fi
  [ -z "$v" ] && v=unknown
  printf '%s' "$v"
}

# ---------- period folders ----------
month_dir(){ date -u +%Y-%m-%B; }
week_dir(){
  local mon sun
  mon=$(date -u -d 'last monday' +%Y-%m-%d 2>/dev/null) || mon=$(date -u +%Y-%m-%d)
  sun=$(date -u -d 'last monday +6 days' +%Y-%m-%d 2>/dev/null) || sun="$mon"
  printf '%s_%s_to_%s' "$(date -u +%G-W%V)" "$mon" "$sun"
}

# ---------- evidence discovery: the draft's own dir, plus the target's matching dirs ----------
evidence_sources(){
  local draft="$1" prog="$2" slug="$3" d
  d=$(dirname "$draft")
  [ -d "$d/evidence" ] && printf '%s\n' "$d/evidence"
  [ -d "$d/form" ]     && printf '%s\n' "$d/form"
  [ -d "$d/upload" ]   && printf '%s\n' "$d/upload"
  # a sibling dir named after the draft file (slug/ next to slug.md)
  [ -d "$d/$slug" ]    && printf '%s\n' "$d/$slug"
  # the target's evidence dir for this slug, if one matches
  local te="$WS/targets/$prog/evidence"
  if [ -d "$te" ]; then
    find "$te" -maxdepth 1 -type d -name "*${slug}*" 2>/dev/null
  fi
}

# FLAT SIBLING ARTIFACTS. The canonical report shape in reports/REPORT-FORMAT.md puts its three
# attachments (repro.sh, capture.log, attacker.html|py) FLAT beside report.md, not in an
# evidence/ subdir. Missing this staged four real reports with zero evidence. Returns the files
# to treat as evidence; report.md and the bundle-root support files are excluded.
flat_artifacts(){
  local draft d base
  draft="$1"; d=$(dirname "$draft")
  find "$d" -maxdepth 1 -type f 2>/dev/null | while IFS= read -r f; do
    base=$(basename "$f")
    [ "$f" = "$draft" ] && continue
    case "$base" in
      report.md|GATES.md|FORM.md|FORM-STAGED.md|STATUS.md|QA-CHECKLIST.md|ATTACHMENTS.txt) continue ;;
      HELD-REASON.md|CLOSED-REASON.md|QA-NOTE-read-this.md|SUBMISSION.md) continue ;;
      submission.txt|SUPERSEDED-submission.txt) continue ;;
    esac
    printf '%s\n' "$f"
  done
}

tree_too_big(){
  local d="$1" n b
  n=$(find "$d" -type f 2>/dev/null | wc -l)
  b=$(du -sb "$d" 2>/dev/null | cut -f1); b=${b:-0}
  [ "$n" -gt "$MAX_FILES" ] && { printf 'files=%s' "$n"; return 0; }
  [ "$b" -gt "$MAX_BYTES" ] && { printf 'bytes=%s' "$b"; return 0; }
  return 1
}

# A draft REPORT is not just any .md under reports/drafts/. Form fields, gate logs, audits,
# recapture plans and triager replies are SUPPORT files that belong inside a report's bundle,
# not beside it as reports of their own. Without this filter, --all staged 39 "reports" out of
# 11 real ones and created folders named ..._GATES and ..._03-impact.
is_draft_report(){
  local f base
  f="$1"
  case "$f" in */form/*|*/triage-reply-*|*/attachments/*) return 1 ;; esac
  base=$(basename "$f")
  case "$base" in
    GATES.md|FORM.md|FORM-STAGED.md|PRESEND-AUDIT-*.md|RECAPTURE-PLAN.md|REOPEN-REQUEST.md|REPLY-*.md|NOTES*.md|LEAD.md|CLOSEOUT.md|INBOX.md|STATUS.md|QA-CHECKLIST.md|HELD-REASON.md|CLOSED-REASON.md) return 1 ;;
  esac
  [ "$base" = "report.md" ] && return 0
  # a <slug>.md directly under the program dir is a report; anything deeper is a support note
  local rel depth
  rel=${f#"$WS"/reports/drafts/}
  depth=$(printf '%s' "$rel" | tr -cd '/' | wc -c)
  [ "$depth" -le 1 ] && return 0
  return 1
}

stage_one(){
  local draft="$1"
  # normalise to an absolute path: the program is extracted with a leading-path regex, so a
  # relative "reports/drafts/..." silently failed to match and reported "not under drafts".
  case "$draft" in /*) ;; *) draft="$PWD/$draft" ;; esac
  draft=$(readlink -f -- "$draft" 2>/dev/null || printf '%s' "$draft")
  [ -f "$draft" ] || { log "  skip (not a file): $draft"; return 1; }
  case "$draft" in *.md) ;; *) log "  skip (not .md): $draft"; return 1 ;; esac
  is_draft_report "$draft" || { log "  skip (support file, not a report): ${draft#$WS/}"; return 1; }

  local prog slug venue month week dest
  prog=$(printf '%s' "$draft" | sed -n 's#.*/reports/drafts/\([^/]*\)/.*#\1#p')
  [ -z "$prog" ] && { log "  skip (not under reports/drafts/): $draft"; return 1; }
  slug=$(basename "$draft" .md)
  # a report.md inside <slug>/ takes the dir name as the slug
  if [ "$slug" = "report" ]; then slug=$(basename "$(dirname "$draft")"); fi
  venue=$(venue_of "$prog")
  month=$(month_dir); week=$(week_dir)
  # DAY PRODUCED, not day staged. Another agent writes drafts concurrently, so a report can be
  # staged hours after it was produced; filing it under today would misdate it. Taken from the
  # source draft's mtime.
  local day
  day=$(date -u -r "$draft" +%Y-%m-%d 2>/dev/null) || day=$(date -u +%Y-%m-%d)
  dest="$QA/$month/$week/${venue}/${day}/${prog}_${slug}"

  # TIER AWARENESS. If a human already triaged this report into _held or _closed, re-sync it
  # THERE. Staging a second copy into the weekly READY folder would silently resurrect a
  # report that was deliberately held, which is worse than not staging at all.
  local triaged="" alt
  for tier in _held _closed; do
    [ -d "$QA/$tier" ] || continue
    alt=$(find "$QA/$tier" -type d \( -name "${prog}_${slug}" -o -name "*_${prog}_${slug}" \) 2>/dev/null | head -1)
    [ -n "$alt" ] && { triaged="$alt"; break; }
  done
  # already staged somewhere in the READY tree under a different day or platform folder?
  if [ -z "$triaged" ]; then
    alt=$(find "$QA/$month/$week" -type d \( -name "${prog}_${slug}" -o -name "*_${prog}_${slug}" \) 2>/dev/null | grep -v "^$dest$" | head -1)
    if [ -n "$alt" ] && [ "$alt" != "$dest" ]; then
      log "  moving: $(basename "$alt") -> ${venue}/${day}/"
      mkdir -p "$(dirname "$dest")" && mv "$alt" "$dest" 2>/dev/null
      find "$QA/$month/$week" -type d -empty -delete 2>/dev/null
    fi
  fi
  if [ -n "$triaged" ]; then
    dest="$triaged"
    log "  already triaged ($(basename "$(dirname "$triaged")")): re-syncing in place, NOT promoting to READY"
  fi

  # already staged and unchanged -> nothing to do (idempotent; the hook fires on every edit)
  if [ -f "$dest/REPORT.md" ] && [ "$FORCE" -eq 0 ] && [ ! "$draft" -nt "$dest/REPORT.md" ]; then
    log "  unchanged: ${venue}_${prog}_${slug}"
    return 0
  fi

  mkdir -p "$dest" || return 1
  cp -- "$draft" "$dest/REPORT.md" || return 1
  # The draft-write gate HARD-BLOCKS a save lacking the `Gate:` and `Dedup:` stamps, but
  # REPORT-FORMAT.md bans internal references in a report body. Both can hold: the stamps stay in
  # the DRAFT so the gate passes, and are stripped from the BUNDLE, which is what gets pasted into
  # the platform. Without this, hooli/sigv4-signing-proxy would have published
  # "Gate: report-killer KILL-PENDING" above its own title on 2026-10-04.
  # Also strip the OVERRIDE-DRAFT-GATE sentinel. The draft-write gate REQUIRES it in the draft
  # (it is how a real-but-non-keyword capability passes the CAP regex), so it must never be
  # deleted from reports/drafts/. But it is an HTML comment carrying the operator's name and our
  # internal gate vocabulary, and the old strip only matched the `Gate:`/`Dedup:` line prefixes,
  # so it would have been pasted into the platform verbatim. Caught 2026-10-05 by the repro gate
  # on hooli/unauth-reservation-number-existence-oracle before anything shipped with it.
  sed -i -E '/^(Gate|Dedup): /d; /<!-- *OVERRIDE-DRAFT-GATE:/d' "$dest/REPORT.md" || return 1
  # Fail loudly rather than silently shipping an internal reference. Only UNAMBIGUOUSLY internal
  # markers belong in this pattern: HTML comments, our own agent names, and workspace paths.
  # DO NOT add the researcher handle here: it legitimately appears in every PoC as the
  # `X-HackerOne: <handle>` identification header, which is deliberate and vendor-facing. A first
  # version of this guard matched it and would have refused to stage every valid draft.
  if grep -qE '<!--|report-killer|repro-checker|report-writer-agent|dedup-scout|$HOME/|reports/drafts/|targets/[a-z_]+/hunts/' "$dest/REPORT.md"; then
    echo "  REFUSING to stage: an internal reference survived into REPORT.md" >&2
    grep -nE '<!--|report-killer|repro-checker|report-writer-agent|dedup-scout|$HOME/|reports/drafts/|targets/[a-z_]+/hunts/' "$dest/REPORT.md" >&2
    return 1
  fi

  # support files that live beside the report
  local dd; dd=$(dirname "$draft")
  for extra in GATES.md FORM.md FORM-STAGED.md submission.txt SUPERSEDED-submission.txt; do
    [ -f "$dd/$extra" ] && cp -- "$dd/$extra" "$dest/" 2>/dev/null
  done

  # evidence, from every discovered source, with a size guard
  local skipped=""
  mkdir -p "$dest/evidence"
  while IFS= read -r src; do
    [ -z "$src" ] && continue
    local why
    if why=$(tree_too_big "$src"); then
      skipped="$skipped $(basename "$src")($why)"
      continue
    fi
    case "$(basename "$src")" in
      form)   mkdir -p "$dest/form";   cp -r -- "$src"/. "$dest/form/"   2>/dev/null ;;
      upload) mkdir -p "$dest/upload"; cp -r -- "$src"/. "$dest/upload/" 2>/dev/null ;;
      *)      cp -r -- "$src"/. "$dest/evidence/" 2>/dev/null ;;
    esac
  done < <(evidence_sources "$draft" "$prog" "$slug")

  # flat sibling artifacts land in evidence/ too
  while IFS= read -r f; do
    [ -n "$f" ] && cp -- "$f" "$dest/evidence/" 2>/dev/null
  done < <(flat_artifacts "$draft")

  # ---- manifests, ALWAYS from a directory walk, never from typed text ----
  local nfiles=0 sha_ok="n/a"
  if [ -n "$(ls -A "$dest/evidence" 2>/dev/null)" ]; then
    ( cd "$dest/evidence" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z \
        | xargs -0 sha256sum > SHA256SUMS.txt 2>/dev/null )
    ( cd "$dest/evidence" && find . -type f | sed 's|^\./||' | sort > "$dest/ATTACHMENTS.txt" )
    nfiles=$(wc -l < "$dest/ATTACHMENTS.txt" 2>/dev/null | tr -d ' ')
    if ( cd "$dest/evidence" && sha256sum -c SHA256SUMS.txt >/dev/null 2>&1 ); then sha_ok="PASS"; else sha_ok="FAIL"; fi
  else
    rmdir "$dest/evidence" 2>/dev/null
    : > "$dest/ATTACHMENTS.txt"
  fi

  [ -f "$QA/_CHECKLIST-TEMPLATE.md" ] && cp -- "$QA/_CHECKLIST-TEMPLATE.md" "$dest/QA-CHECKLIST.md" 2>/dev/null

  # ---- STATUS: say exactly what was checked and what was not ----
  local wc_body summary_w impact_w
  wc_body=$(wc -w < "$draft" 2>/dev/null | tr -d ' ')
  summary_w=$(awk '/^##[[:space:]]*Summary/{f=1;next} /^##[[:space:]]/{f=0} f' "$draft" 2>/dev/null | wc -w | tr -d ' ')
  impact_w=$(awk '/^##[[:space:]]*Impact/{f=1;next} /^##[[:space:]]/{f=0} f' "$draft" 2>/dev/null | wc -w | tr -d ' ')
  {
    echo "# STATUS - ${venue} / ${prog} / ${slug}"
    echo
    echo "Auto-staged by scripts/qa-handoff.sh at $(date -u +%Y-%m-%dT%H:%M:%SZ)."
    echo "Source draft: \`${draft#$WS/}\`"
    echo
    echo "## QA state"
    if [ -n "$triaged" ]; then
      echo "**ALREADY TRIAGED into \`$(basename "$(dirname "$triaged")")\`.** This was re-synced in place"
      echo "because the draft changed. It was NOT promoted to the READY queue. The reason it sits"
      echo "in that tier is in HELD-REASON.md or CLOSED-REASON.md beside this file."
    elif [ "$READY" -eq 1 ]; then
      echo "**QA-READY.** A verification gate passed before staging."
    else
      echo "**AUTO-STAGED, NOT YET QA-VERIFIED.** This was staged because the draft was"
      echo "finalized, not because a gate cleared it. A human QA review is still required,"
      echo "and so is a repro check if one has not been run."
    fi
    echo
    echo "## What this script checked"
    echo
    echo "| Check | Result |"
    echo "|---|---|"
    echo "| Evidence files staged | ${nfiles} |"
    echo "| SHA256SUMS regenerated from a directory walk | yes |"
    echo "| SHA256SUMS verify | ${sha_ok} |"
    echo "| ATTACHMENTS.txt generated from the same walk | yes |"
    echo "| Report body word count | ${wc_body} |"
    echo "| Summary section words | ${summary_w:-0} |"
    echo "| Impact section words | ${impact_w:-0} |"
    [ -n "$skipped" ] && echo "| Evidence trees SKIPPED as oversized |${skipped} |"
    echo
    echo "## What this script did NOT check, and QA must"
    echo
    echo "- Whether the finding is real, and whether a NEW attacker capability is captured in bytes."
    echo "- Whether every quoted capture line matches its evidence file byte for byte."
    echo "- Whether the PoC runs from cold without consuming its own precondition."
    echo "- Whether the asset is in the program's current scope and the class qualifies."
    echo "- Whether a public duplicate already exists."
    echo "- Whether any live submission form already holds stale text."
    echo
    echo "Nothing here is submitted. Submission is human-only."
  } > "$dest/STATUS.md"

  # ---- queue index ----
  local idx="$QA/_QUEUE.md"
  [ -f "$idx" ] || {
    { echo "# QA queue index"; echo; echo "Auto-maintained by scripts/qa-handoff.sh. Newest last."; echo;
      echo "| Produced | Staged (UTC) | Venue | Program | Report | State | Files | SHA |"; echo "|---|---|---|---|---|---|---|---|"; } > "$idx"
  }
  local state
  if [ -n "$triaged" ]; then state="$(basename "$(dirname "$triaged")")"
  elif [ "$READY" -eq 1 ]; then state="QA-READY"
  else state="NEEDS-QA"; fi
  local line="| ${day} | $(date -u +%Y-%m-%dT%H:%MZ) | ${venue} | ${prog} | \`${slug}\` | ${state} | ${nfiles} | ${sha_ok} |"
  grep -qF "| ${venue} | ${prog} | \`${slug}\` |" "$idx" 2>/dev/null \
    && sed -i "s#^| .* | ${venue} | ${prog} | \`${slug}\` |.*#${line}#" "$idx" 2>/dev/null \
    || printf '%s\n' "$line" >> "$idx"

  log "  staged: ${venue}_${prog}_${slug}  (evidence=${nfiles}, sha=${sha_ok})"
  [ -n "$skipped" ] && log "    NOTE oversized tree(s) skipped:${skipped} - stage by hand if QA needs them"
  printf '%s\n' "$dest"
  return 0
}

# ---------- arg parsing ----------
TARGETS=(); MODE=one
while [ $# -gt 0 ]; do
  case "$1" in
    --quiet) QUIET=1 ;;
    --force) FORCE=1 ;;
    --ready) READY=1 ;;
    --all)   MODE=all ;;
    --list)  MODE=list ;;
    --program) shift; PROG_ARG="${1:-}" ;;
    --slug)    shift; SLUG_ARG="${1:-}" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done

case "$MODE" in
  list)
    [ -f "$QA/_QUEUE.md" ] && cat "$QA/_QUEUE.md" || echo "queue empty"
    exit 0 ;;
  all)
    log "staging every draft report under reports/drafts/ ..."
    n=0
    while IFS= read -r f; do
      case "$f" in *$'\n'*) continue ;; esac
      stage_one "$f" >/dev/null && n=$((n+1))
    done < <(find "$WS/reports/drafts" -type f -name '*.md' ! -path '*/attachments/*' 2>/dev/null | sort)
    log "done: $n report(s) processed"
    exit 0 ;;
esac

if [ "${PROG_ARG:-}" != "" ] && [ "${SLUG_ARG:-}" != "" ]; then
  for cand in "$WS/reports/drafts/$PROG_ARG/$SLUG_ARG/report.md" "$WS/reports/drafts/$PROG_ARG/$SLUG_ARG.md"; do
    [ -f "$cand" ] && { stage_one "$cand"; exit $?; }
  done
  die "no draft found for program=$PROG_ARG slug=$SLUG_ARG"
fi

[ "${#TARGETS[@]}" -eq 0 ] && die "nothing to stage (give a draft path, or --all, or --list)"
rc=0
for t in "${TARGETS[@]}"; do stage_one "$t" || rc=1; done
exit $rc
