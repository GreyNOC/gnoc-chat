#!/usr/bin/env bash
# reports.sh - the one entry point for the report pipeline.
#
#   reports.sh status            rebuild and print reports/STATUS.md (the dashboard)
#   reports.sh new [WINDOW]      what changed in the last WINDOW (default 1h)
#   reports.sh ready <prog>/<slug>   mark a draft READY and flow it to the dated QA handoff
#   reports.sh ready <prog>/<slug> [--force-no-liveness]   (T-241: needs evidence/*liveness* < 24h old; flag is GreyNOC only)
#   reports.sh flow              stage every unstaged draft into the dated QA handoff
#
# Submission is human-only. Nothing here submits anything.
set -uo pipefail
WS="${WS:-${GNOC_WORKSPACE:-$HOME/.gnoc}}"
QA="$WS/QA handoff"
D="$WS/reports/drafts"
STATUS="$WS/reports/STATUS.md"
TSV="$WS/.claude/state/hunt-loop/pipeline.tsv"
FROZEN="$WS/reports/FROZEN-DO-NOT-EDIT.md"

# ---------- helpers ----------
# is <prog>/<slug> in the frozen (submitted or filed) set? exact path-component match,
# never a substring of the surrounding prose.
is_frozen(){ local prog="$1" slug="$2"
  [ -f "$FROZEN" ] || return 1
  grep -qE "(^|[/_[:space:]])${prog}_${slug}([/[:space:],]|$)|/${slug}(/|\.md|[[:space:]]|$)" "$FROZEN"; }

mt(){ [ -e "$1" ] && date -u -r "$1" +%Y-%m-%dT%H:%MZ || echo "-"; }
mts(){ [ -e "$1" ] && date -u -r "$1" +%s || echo 0; }

# T-235 / T-241 helpers. mtime of newest file matching *liveness* under a draft's evidence/ tree
# (0 if none). perishable_old: draft has a PERISHABLE marker and report.md is older than 48h.
liveness_newest(){ local ev="$1"
  [ -d "$ev" ] || { echo 0; return; }
  (cd "$ev" && find . -type f -path '*liveness*' -printf '%T@\n' 2>/dev/null) | sort -n | tail -1 | cut -d. -f1 | grep . || echo 0; }
liveness_fresh(){ local ev="$1" n; n=$(liveness_newest "$ev"); [ "$n" -gt 0 ] && [ "$n" -ge $(( $(date -u +%s) - 86400 )) ]; }
perishable_old(){ local dir="$1"
  [ -f "$dir/PERISHABLE" ] && [ -f "$dir/report.md" ] || return 1
  [ "$(mts "$dir/report.md")" -lt $(( $(date -u +%s) - 172800 )) ]; }

# venue for a program: from a staged path if present, else sniff the target files
venue_of(){ local prog="$1" v
  v=$(find "$QA" -mindepth 5 -maxdepth 5 -type d -name "${prog}_*" -printf '%h\n' 2>/dev/null \
        | head -1 | awk -F/ '{print $(NF-1)}')
  [ -n "$v" ] && { echo "$v"; return; }
  v=$(ls -d "$QA"/_held/*_"${prog}"_* "$QA"/_closed/*_"${prog}"_* 2>/dev/null | head -1)
  [ -n "$v" ] && { basename "$v" | sed "s/_${prog}_.*//"; return; }
  for f in "$WS/targets/$prog/intake.json" "$WS/targets/$prog/PROGRAM.md"; do
    [ -f "$f" ] || continue
    grep -qi 'hackerone\|h1' "$f" && { echo hackerone; return; }
    grep -qi 'bugcrowd'        "$f" && { echo bugcrowd;  return; }
    grep -qi 'yeswehack\|ywh'  "$f" && { echo yeswehack; return; }
    grep -qi 'intigriti'       "$f" && { echo intigriti; return; }
    grep -qi 'immunefi'        "$f" && { echo immunefi;  return; }
  done
  echo unknown; }

# locate the staged bundle for prog/slug -> prints "TIER<TAB>PATH"
staged_of(){ local prog="$1" slug="$2" p
  p=$(ls -d "$QA"/_closed/*_"${prog}"_"${slug}" 2>/dev/null | head -1)
  [ -n "$p" ] && { printf 'CLOSED\t%s\n' "$p"; return; }
  p=$(ls -d "$QA"/_held/*_"${prog}"_"${slug}" 2>/dev/null | head -1)
  [ -n "$p" ] && { printf 'HELD\t%s\n' "$p"; return; }
  p=$(find "$QA" -mindepth 5 -maxdepth 5 -type d -name "${prog}_${slug}" 2>/dev/null | head -1)
  if [ -n "$p" ]; then
    if grep -q 'QA-READY' "$p/STATUS.md" 2>/dev/null; then printf 'READY\t%s\n' "$p"
    else printf 'NEEDS-QA\t%s\n' "$p"; fi
    return
  fi
  # DRAFT-SIDE HOLD (2026-10-06, SEVERITY FLOOR). A Low/Medium is written up in full with its
  # evidence saved, then held rather than staged - so it has no bundle under "$QA"/_held. Without
  # this branch it resolved to DRAFT and disappeared from section 5, and the comment in section 5 is
  # right that an invisible one is lost. A STAGED hold still wins, because those checks run first.
  [ -f "$D/$prog/$slug/HELD-REASON.md" ] && { printf 'HELD\t%s\n' "$D/$prog/$slug"; return; }
  printf 'DRAFT\t-\n'; }

# ---------- build the machine-readable table ----------
build_tsv(){
  mkdir -p "$(dirname "$TSV")"
  : > "$TSV.tmp"
  # live drafts
  while IFS= read -r r; do
    local rel prog slug st sp
    rel="${r#"$D"/}"; prog="${rel%%/*}"; slug="$(dirname "${rel#*/}")"
    [ "$slug" = "." ] && slug="$(basename "${rel%.md}")"
    IFS=$'\t' read -r st sp < <(staged_of "$prog" "$slug")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$st" "$(venue_of "$prog")" "$prog" "$slug" "$(mt "$r")" \
      "$([ "$sp" != "-" ] && mt "$sp/REPORT.md" || echo -)" \
      "${r#"$WS"/}" "$([ "$sp" != "-" ] && echo "${sp#"$WS"/}" || echo -)" >> "$TSV.tmp"
  done < <(find "$D" -mindepth 3 -maxdepth 3 -name report.md 2>/dev/null | sort)
  # staged bundles with no live draft: already filed, or the draft moved on
  while IFS= read -r b; do
    local base prog slug venue
    base="$(basename "$b")"; prog="${base%%_*}"; slug="${base#*_}"
    venue="$(basename "$(dirname "$(dirname "$b")")")"
    [ -f "$D/$prog/$slug/report.md" ] && continue
    if is_frozen "$prog" "$slug"; then st=FILED; else st=ORPHAN; fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$st" "$venue" "$prog" "$slug" "$(mt "$b/REPORT.md")" "$(mt "$b/REPORT.md")" \
      "${b#"$WS"/}/REPORT.md" "${b#"$WS"/}" >> "$TSV.tmp"
  done < <(find "$QA" -mindepth 5 -maxdepth 5 -type d -name '*_*' 2>/dev/null | sort)

  # terminal states, listed so the picture is complete. One row per REPORT, so a bundle
  # that also carries a plan or a reply note is not counted twice.
  for tier in submitted archive leads; do
    local up; up=$(echo "$tier" | tr a-z A-Z)
    # bundles: a directory holding report.md
    while IFS= read -r r; do
      local rel prog slug
      rel="${r#"$WS"/reports/$tier/}"; prog="${rel%%/*}"; slug="$(basename "$(dirname "$r")")"
      printf '%s\t%s\t%s\t%s\t%s\t-\t%s\t-\n' \
        "$up" "$(venue_of "$prog")" "$prog" "$slug" "$(mt "$r")" "${r#"$WS"/}" >> "$TSV.tmp"
    done < <(find "$WS/reports/$tier" -mindepth 3 -maxdepth 3 -name report.md 2>/dev/null | sort)
    # loose reports: a .md sitting directly under the program dir with no bundle of its own
    while IFS= read -r r; do
      local prog slug
      prog="$(basename "$(dirname "$r")")"; slug="$(basename "${r%.md}")"
      case "$slug" in WHY-*|LEAD|GATES|PRESEND-*|README) continue;; esac
      [ -d "$(dirname "$r")/$slug" ] && continue
      printf '%s\t%s\t%s\t%s\t%s\t-\t%s\t-\n' \
        "$up" "$(venue_of "$prog")" "$prog" "$slug" "$(mt "$r")" "${r#"$WS"/}" >> "$TSV.tmp"
    done < <(find "$WS/reports/$tier" -mindepth 2 -maxdepth 2 -name '*.md' 2>/dev/null | sort)
  done

  # _held / _closed bundles whose source draft is gone: a demoted or superseded framing.
  # These stay visible, because a held report is not a dead one and an invisible one is lost.
  # Bundle names are <venue>_<program>_<slug>. Splitting that on the first underscore assumed no
  # program handle contains one, which was never true: program-19, program-32, program-60,
  # program-50 and program-65 all do. program-19/autorelease-... was read as program "massive",
  # slug "public_autorelease-...", the dedup check below then failed to match the real row, and a
  # PHANTOM draft appeared in section 5 for a program with nothing on disk (2026-10-25). Resolve the
  # handle against the ones that actually exist, longest match first.
  for tier in _held _closed; do
    local st2; [ "$tier" = _held ] && st2=HELD || st2=CLOSED
    while IFS= read -r b; do
      [ -d "$b" ] || continue
      local base ven2 rest prog slug alt
      base="$(basename "$b")"; ven2="${base%%_*}"; rest="${base#*_}"
      prog=""; slug=""
      local cand
      for cand in $(ls -1 "$D" "$WS/targets" 2>/dev/null | sort -u); do
        case "$rest" in
          "${cand}_"*) [ "${#cand}" -gt "${#prog}" ] && { prog="$cand"; slug="${rest#"${cand}_"}"; } ;;
        esac
      done
      [ -z "$prog" ] && { prog="${rest%%_*}"; slug="${rest#*_}"; }
      alt="${slug#LEAD-}"   # leads are staged with a LEAD- prefix the source file lacks
      awk -F'\t' -v p="$prog" -v s="$slug" -v a="$alt" \
          'BEGIN{r=1} $3==p && ($4==s || $4==a){r=0} END{exit r}' "$TSV.tmp" && continue
      printf '%s\t%s\t%s\t%s\t%s\t%s\t-\t%s\n' \
        "$st2" "$ven2" "$prog" "$slug" \
        "$(mt "$b/REPORT.md")" "$(mt "$b/REPORT.md")" "${b#"$WS"/}" >> "$TSV.tmp"
    done < <(find "$QA/$tier" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
  done

  sort -o "$TSV" "$TSV.tmp"; rm -f "$TSV.tmp"; }

row(){ # pretty one line
  printf '| %s | %s | %s | %s | %s |\n' "$2" "$3" "$4" "$5" "$6"; }

cmd_status(){
  build_tsv
  local now; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local hr; hr=$(( $(date -u +%s) - 3600 ))
  {
  echo "# Report pipeline - STATUS"
  echo
  echo "Rebuilt $now by \`scripts/reports.sh status\`. Submission is human-only; nothing here is sent."
  echo
  echo "The flow, left to right:"
  echo
  echo '```'
  echo 'reports/drafts/<program>/<slug>/report.md'
  echo '        |  every draft write auto-stages (dated)'
  echo '        v'
  echo '"QA handoff"/<YYYY-MM-Month>/<ISO-week>/<venue>/<YYYY-MM-DD>/<program>_<slug>/'
  echo '        |                 NEEDS-QA  -> a human reviews it'
  echo '        |  scripts/reports.sh ready <program>/<slug>'
  echo '        v                  READY    -> GreyNOC submits by hand'
  echo 'reports/submitted/   (filed)      reports/archive/  (no action)   reports/leads/ (not a report yet)'
  echo '```'
  echo
  # ---- 1. last hour
  echo "## 1. New in the last hour"
  echo
  local any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    local f="$WS/$path" sf="" newest=0
    [ -e "$f" ] && newest=$(mts "$f")
    [ "$spath" != "-" ] && [ -e "$WS/$spath/REPORT.md" ] && sf=$(mts "$WS/$spath/REPORT.md")
    [ -n "$sf" ] && [ "$sf" -gt "$newest" ] && newest="$sf"
    [ "$newest" -ge "$hr" ] || continue
    [ "$any" = 0 ] && { echo "| State | Venue | Program | Report | Written | Staged |"; echo "|---|---|---|---|---|---|"; any=1; }
    printf '| %s | %s | %s | `%s` | %s | %s |\n' "$st" "$ven" "$prog" "$slug" "$prod" "$stg"
  done < "$TSV"
  [ "$any" = 0 ] && echo "Nothing written in the last hour."
  echo
  # ---- 2. ready for QA
  echo "## 2. Ready for QA - cleared the gates, waiting on a human"
  echo
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    [ "$st" = READY ] || continue
    [ "$any" = 0 ] && { echo "| Venue | Program | Report | Written | Staged | Bundle |"; echo "|---|---|---|---|---|---|"; any=1; }
    printf '| %s | %s | `%s` | %s | %s | `%s` |\n' "$ven" "$prog" "$slug" "$prod" "$stg" "$spath"
  done < "$TSV"
  [ "$any" = 0 ] && echo "None."
  echo
  # ---- 2b. pending action on an already-filed report
  any=0
  while IFS= read -r f; do
    case "$f" in *do-not-send*|*superseded*) continue;; esac
    local rel prog
    rel="${f#"$WS"/reports/submitted/}"; prog="${rel%%/*}"
    local rpt kind base
    rpt="${rel#*/}"; rpt="${rpt%%/*}"
    base="$(basename "$f")"
    case "$base" in
      REOPEN-REQUEST*) kind="reopen request";;
      REPLY-*)         kind="reply to the triager";;
      PENDING-*)       kind="pending note";;
      *)               kind="follow-up";;
    esac
    [ "$any" = 0 ] && { echo "## 2b. Pending action on an ALREADY-FILED report - waiting on a manual send"; echo
                        echo "These reports are FILED. What waits on GreyNOC is the follow-up document in the last"
                        echo "column, not the report itself. Nothing here is an unfiled finding."; echo
                        echo "| Program | Filed report | Waiting to send | Document | Written |"; echo "|---|---|---|---|---|"; any=1; }
    printf '| %s | `%s` | %s | `%s` | %s |\n' "$prog" "$rpt" "$kind" "${f#"$WS"/}" "$(mt "$f")"
  done < <(find "$WS/reports/submitted" -type f \( -iname 'REOPEN-REQUEST*' -o -iname 'PENDING-*' \
             -o -iname 'REPLY-*' \) 2>/dev/null | sort)
  [ "$any" = 1 ] && echo

  # ---- 3. needs QA
  echo "## 3. Staged, needs QA - auto-staged, no gate pass recorded yet"
  echo
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    [ "$st" = NEEDS-QA ] || continue
    [ "$any" = 0 ] && { echo "| Venue | Program | Report | Written | Staged |"; echo "|---|---|---|---|---|"; any=1; }
    printf '| %s | %s | `%s` | %s | %s |\n' "$ven" "$prog" "$slug" "$prod" "$stg"
  done < "$TSV"
  [ "$any" = 0 ] && echo "None."
  echo
  # ---- 4. drafts
  # Every section below is a SLICE. Asked "how many drafts do we have for gatewayco", the agent read
  # section 4, found one gatewayco row and answered "1 draft"; gatewayco has three, the other two sitting in
  # section 5 under Held (2026-10-25). A reader counting rows in one section gets a wrong total, so
  # the totals are stated once, up front, per program.
  echo "## 3b. Draft count per program - EVERY live draft, whatever section it appears in below"
  echo
  echo "The sections after this one are SLICES of this list (staged / unstaged / held). Counting the"
  echo "rows of any one section gives a wrong total. Count here."
  echo
  rows=$(awk -F'\t' 'BEGIN{split("DRAFT STAGED HELD READY NEEDS-QA",L," "); for(i in L) live[L[i]]=1}
       live[$1]{n[$3]++; c[$3"|"$1]++}
       END{for(k in n){p=k; out="";
             for(st in c){split(st,a,"|"); if(a[1]==p) out=out sprintf("%s%d %s", (out?", ":""), c[st], a[2])}
             printf "| %s | %d | %s |\n", p, n[p], out}}' "$TSV" | sort)
  if [ -z "$rows" ]; then echo "None."; else
    echo "| Program | Live drafts | States |"; echo "|---|---|---|"; echo "$rows"
    echo
    echo "Total live drafts: $(echo "$rows" | wc -l) programs, $(awk -F'\t' 'BEGIN{split("DRAFT STAGED HELD READY NEEDS-QA",L," "); for(i in L) live[L[i]]=1} live[$1]' "$TSV" | wc -l) drafts."
  fi
  echo
  echo "## 4. Drafts - in progress, not staged (a SLICE of 3b, not the total)"
  echo
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    [ "$st" = DRAFT ] || continue
    [ "$any" = 0 ] && { echo "| Venue | Program | Report | Written | Path |"; echo "|---|---|---|---|---|"; any=1; }
    printf '| %s | %s | `%s` | %s | `%s` |\n' "$ven" "$prog" "$slug" "$prod" "$path"
  done < "$TSV"
  [ "$any" = 0 ] && echo "None - every live draft is staged."
  echo
  # ---- 4b. perishable (T-235): third-party-hosted terminal, draft older than 48h
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    case "$st" in DRAFT|NEEDS-QA|READY|HELD) ;; *) continue;; esac
    [ "$path" = "-" ] && continue
    perishable_old "$(dirname "$WS/$path")" || continue
    [ "$any" = 0 ] && { echo "## 4b. PERISHABLE>48h - file or kill now, re-fire the source leg first (T-235)"; echo
                        echo "| State | Program | Report | Written | Flag |"; echo "|---|---|---|---|---|"; any=1; }
    printf '| %s | %s | `%s` | %s | PERISHABLE>48h |\n' "$st" "$prog" "$slug" "$prod"
  done < "$TSV"
  [ "$any" = 1 ] && echo
  # ---- 5. held
  echo "## 5. Held - real work, blocked on one named unlock (a SLICE of 3b, not the total)"
  echo
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    [ "$st" = HELD ] || continue
    [ "$any" = 0 ] && { echo "| Venue | Program | Report | Blocking reason |"; echo "|---|---|---|---|"; any=1; }
    local why="see HELD-REASON.md" nodraft=""
    [ "$path" = "-" ] && nodraft=" (no live draft: superseded framing)"
    if [ -f "$WS/$spath/HELD-REASON.md" ]; then
      # prefer an explicit Verdict line, else the first real sentence of "why it is not ready"
      why=$(grep -m1 -E '^\*\*(Verdict|Overturn|Unlock)' "$WS/$spath/HELD-REASON.md" \
            | sed -E 's/\*\*//g' | cut -c1-120)
      [ -z "$why" ] && why=$(awk '/^## /{f=1;next} f && NF && $0 !~ /^\*\*[A-Z][a-z]+:/' \
            "$WS/$spath/HELD-REASON.md" | sed -E 's/^[0-9]+\. *//; s/^[-*] *//; s/\*\*//g; s/`//g' \
            | head -1 | cut -c1-120)
      [ -z "$why" ] && why="see HELD-REASON.md"
    fi
    printf '| %s | %s | `%s` | %s%s |\n' "$ven" "$prog" "$slug" "$why" "$nodraft"
  done < "$TSV"
  [ "$any" = 0 ] && echo "None."
  echo
  # ---- 5b. drift
  any=0
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    [ "$st" = ORPHAN ] || continue
    [ "$any" = 0 ] && { echo "## 5b. Needs a decision - staged bundle with no live draft and no filed record"; echo
                        echo "| Venue | Program | Report | Staged |"; echo "|---|---|---|---|"; any=1; }
    printf '| %s | %s | `%s` | %s |\n' "$ven" "$prog" "$slug" "$stg"
  done < "$TSV"
  [ "$any" = 1 ] && echo

  # ---- 6. terminal
  echo "## 6. Terminal states"
  echo
  echo "| State | Count | Meaning |"
  echo "|---|---|---|"
  printf '| SUBMITTED | %s | filed with the program. Frozen, do not edit |\n' "$(awk -F'\t' '$1=="SUBMITTED"' "$TSV" | wc -l)"
  printf '| FILED | %s | already sent to the program, bundle retained |\n'    "$(awk -F'\t' '$1=="FILED"' "$TSV" | wc -l)"
  printf '| CLOSED | %s | staged then dispositioned, no action pending |\n'   "$(ls -d "$QA"/_closed/*/ 2>/dev/null | wc -l)"
  printf '| ARCHIVE | %s | killed, dropped on policy, or target closed out |\n' "$(awk -F'\t' '$1=="ARCHIVE"' "$TSV" | wc -l)"
  printf '| LEADS | %s | real work, correctly not a report yet |\n'           "$(awk -F'\t' '$1=="LEADS"' "$TSV" | wc -l)"
  echo
  [ -f "$FROZEN" ] && { echo "Frozen set (submitted or filed, never edited): see \`reports/FROZEN-DO-NOT-EDIT.md\`."; echo; }
  echo "Machine-readable table: \`.claude/state/hunt-loop/pipeline.tsv\`"
  echo "(columns: state, venue, program, slug, written, staged, draft path, bundle path)"
  } > "$STATUS"
  cat "$STATUS"; }

cmd_new(){ local w="${1:-1h}" secs
  case "$w" in *h) secs=$(( ${w%h} * 3600 ));; *m) secs=$(( ${w%m} * 60 ));; *d) secs=$(( ${w%d} * 86400 ));; *) secs="$w";; esac
  [ -s "$TSV" ] || build_tsv
  local cut=$(( $(date -u +%s) - secs )) n=0
  echo "Reports touched in the last $w:"
  while IFS=$'\t' read -r st ven prog slug prod stg path spath; do
    local f="$WS/$path"; [ -e "$f" ] || continue
    [ "$(mts "$f")" -ge "$cut" ] || continue
    printf '  %-9s %-11s %s/%s   (%s)\n' "$st" "$ven" "$prog" "$slug" "$prod"; n=$((n+1))
  done < "$TSV"
  [ "$n" = 0 ] && echo "  nothing."
  return 0; }

cmd_ready(){ local force=0 t="" a
  for a in "$@"; do case "$a" in --force-no-liveness) force=1;; *) t="$a";; esac; done
  [ -n "$t" ] || { echo "usage: reports.sh ready <program>/<slug> [--force-no-liveness]" >&2; exit 1; }
  local prog slug r
  prog="${t%%/*}"; slug="${t#*/}"; r="$D/$prog/$slug/report.md"
  # the frozen set is checked FIRST: a filed report has no draft, and the honest
  # answer there is "already sent", not "no such draft".
  if is_frozen "$prog" "$slug"; then
    echo "REFUSED: $t is in the frozen set (submitted or filed). See reports/FROZEN-DO-NOT-EDIT.md" >&2; exit 1; fi
  [ -f "$r" ] || { echo "no such draft: ${r#"$WS"/}" >&2; exit 1; }
  # KILL GATE (added 2026-10-26). A draft another gate already killed must never reach QA-READY. On 2026-10-26
  # GreyNOC was handed a "Critical ATO 9.1" whose whole PoC was GET -> 405 / POST -> 200 on a public telemetry
  # route, from a family of seven copies, three of which already carried a KILL gate file that nothing read.
  local kf
  kf=$(grep -lis '^KILL' "$D/$prog/$slug"/GATE*.md "$D/$prog/$slug"/HELD*.md 2>/dev/null | head -1)
  if [ -n "$kf" ]; then
    echo "REFUSED: $t carries a KILL verdict in ${kf#"$WS"/}" >&2
    sed -n '1,6p' "$kf" | sed 's/^/    /' >&2
    echo "    Resolve or delete that gate file before promoting." >&2; exit 3; fi
  # CLAIM GATE (added 2026-10-26, gnoc_gates.claim_checks): the four checks a hollow draft cannot tick - its own
  # Gate:/Dedup: stamps have actually run, the negative control is not a method-table answer, the control and the
  # terminal are not the same response body, and no sibling copy of this slug was already killed.
  if ! python3 - "$D/$prog/$slug" <<'PY' >&2
import sys, os
sys.path.insert(0, os.path.join(os.environ.get("WS", "${GNOC_WORKSPACE:-$HOME/.gnoc}"), "scripts"))
import gnoc_gates
bad = [r for r in gnoc_gates.claim_checks(sys.argv[1]) if not r[0]]
for _, name, why in bad:
    print(f"    {name}: {why}")
sys.exit(1 if bad else 0)
PY
  then
    echo "REFUSED: the claim gate above failed. These are not prose defects: run the gate it says never ran, or supply a control that varies one security-relevant variable." >&2
    exit 3; fi
  # LIVENESS GATE (T-241): a fresh re-fire of the source leg must be on disk.
  local evd="$D/$prog/$slug/evidence"
  if ! liveness_fresh "$evd"; then
    if [ "$force" = 1 ]; then
      echo "WARNING: --force-no-liveness: bypassing the T-241 liveness gate (looked under $evd). GreyNOC only." >&2
    else
      echo "REFUSED: no *liveness* file under $evd modified within 24h (T-241); re-fire the source leg, save it there" >&2; exit 2
    fi
  fi
  # QAQC GATE (added 2026-10-05). Promotion to QA-READY now REQUIRES a mechanical pass.
  # Before this, `ready` staged with no QA at all, which is how seven drafts reached a submit
  # brief unvalidated and one reached a vendor form two generations out of date.
  echo "running QAQC on $t"
  if ! "$WS/scripts/qaqc.sh" "$t"; then
    echo "" >&2
    echo "NOT PROMOTED. Fix the blocking defects above, then re-run:" >&2
    echo "  scripts/reports.sh ready $t" >&2
    echo "To stage it as NEEDS-QA anyway (not QA-READY):  scripts/qa-handoff.sh \"$r\"" >&2
    exit 1
  fi
  echo "flowing $t to the dated QA handoff as QA-READY"
  # --force is required: without it the stager's idempotency check short-circuits on an
  # already-staged report and the NEEDS-QA -> QA-READY promotion silently never happens.
  "$WS/scripts/qa-handoff.sh" --ready --force "$r" || exit 1
  # ECON: the READY verdict is final here (liveness + QAQC + QA-READY staging passed): mint the READY split once.
  # Never on --force-no-liveness, and never fails the promotion.
  [ "$force" = 1 ] || timeout 10 python3 "$WS/scripts/gnoc_economy.py" ready-hook "$prog" "$slug" 2>/dev/null || true
  cmd_status >/dev/null; echo "STATUS.md refreshed."; return 0; }

cmd_flow(){ echo "staging every draft into the dated QA handoff"
  "$WS/scripts/qa-handoff.sh" --all || true
  cmd_status >/dev/null; echo "STATUS.md refreshed."; }

[ "${REPORTS_SH_SOURCE_ONLY:-0}" = 1 ] && return 0 2>/dev/null
case "${1:-status}" in
  status) cmd_status ;;
  new)    shift; cmd_new "${1:-1h}" ;;
  ready)  shift; cmd_ready "$@" ;;
  flow)   cmd_flow ;;
  *) sed -n '2,10p' "$0"; exit 1 ;;
esac
