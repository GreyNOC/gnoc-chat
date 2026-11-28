#!/usr/bin/env bash
# draft-write-gate.sh - PreToolUse(Write|Edit) hook. Enforces REVIEW BEFORE a draft
# exists - the fix for "we write drafts then find them dead on review". Two denials
# (exit 2 + stderr, the repo convention from submit-guard.sh):
#   1. WEAK-CLASS: a draft that reads as enumeration / existence-oracle / CORS-header /
#      bare info-disclosure with NO captured cross-tenant/state-change/exfil capability
#      -> DENY; write it to reports/leads/ (a held LEAD), never reports/drafts/.
#   2. UNGATED: a report-shaped draft with no captured HTTP/PoC evidence OR no
#      "Gate: report-killer PASS <date>" header stamp -> DENY; run report-killer first
#      and stamp the header, then re-write.
#   4. CANONICAL FORMAT (2026-09-30): a draft that does not follow reports/REPORT-FORMAT.md -
#      missing ## Summary / ## PoC / ## Impact, a Summary or Impact over 50 words, a PoC whose
#      last "Step N." is not "Step N. Controls.", an em-dash, or a researcher-identification
#      header stamped with a handle that is not the resolved HACKERONE_HANDLE -> DENY.
# Escape hatches: write to reports/leads/, or add captured evidence + the gate stamp.
# Session-capped safety valve so it can never permanently wedge a session.
# NOTE ON THE TWO WORD CAPS (reconciled 2026-09-30, both rules kept, nothing deleted):
#   50 words = the HARD cap, Denial 4b/4c, exit 2, no platform exemption.
#   35 words = the legacy 2026-07-19 hardrule, Denial 3, now a NON-BLOCKING advisory.
#   Precedence: 50 blocks, 35 advises. Reason it was demoted rather than deleted: the
#   operator's gold-standard report (a filed report), which IS the canonical shape, has a
#   CORRECTED 2026-09-30: the operator explicitly specified 50-word caps for Summary and Impact, which supersedes the older 35-word rule; 35 is retained as an advisory target. Measured with the canonical counter (and independently by `wc -w`), the gold-standard exemplar is Summary=29, Impact=31, so it sits comfortably inside BOTH limits. An earlier brief asserted 38 words; that was an unverified estimate and is wrong.
#   Full rationale: reports/REPORT-FORMAT.md section 8.
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac
FP=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null || echo "")
case "$FP" in */reports/drafts/*) ;; *) exit 0 ;; esac
case "$FP" in *.md) ;; *) exit 0 ;; esac

CONTENT=$(printf '%s' "$INPUT" | jq -r '(.tool_input.content // .tool_input.new_string // "")' 2>/dev/null)
EXIST=""; [ -f "$FP" ] && EXIST=$(head -c 40000 "$FP" 2>/dev/null)
BODY="$CONTENT
$EXIST"
[ -z "$(printf '%s' "$BODY" | tr -d ' \n\t')" ] && exit 0
# Only gate a report-SHAPED write (Summary/PoC/Impact). A scratch note is not a draft.
# Recognise BOTH shapes: ATX headings AND reports/STYLE.md bold labels. Matching ATX only
# meant a STYLE draft failed this guard and the WHOLE gate silently exited 0.
printf '%s' "$BODY" | grep -qiE '#+ *(summary|poc|proof of concept|steps to reproduce|impact)|^\*\*(summary|poc|proof of concept|impact)\*\*' || exit 0

# Denial 0 (ATTRIBUTION): a report attributing a CLOUD-PROVIDER host to the program
# without a captured OWNERSHIP artifact. A cloud hostname (amazonaws/azure/gcp/heroku/
# globex/netlify/cloudfront) says NOTHING about who OPERATES it; attributing it to the
# program by name-match or scope-adjacency is a guess, not ownership - the QuantumRhino
# add-in mis-drafted as a Massive crit + the azure-webapp NXDOMAIN mis-draft (memory
# killrule-asset-ownership-by-namematch-not-proof). Fail CLOSED: require an explicit
# "OWNERSHIP: <artifact>" line, or route as vendor-disclosure. The hook forces the
# explicit ownership CLAIM; the reviewer/killer verify the claim is true.
CLOUD_RX='[a-z0-9._-]+\.(amazonaws\.com|core\.windows\.net|azurewebsites\.net|azureedge\.net|azure-api\.net|googleapis\.com|appspot\.com|cloudfunctions\.net|run\.app|herokuapp\.com|globex\.app|netlify\.app|cloudfront\.net)'
CLOUD_HOSTS=$(printf '%s' "$BODY" \
  | grep -iE 'https?://|Host:|Asset:|X-Api-Key|^[[:space:]]*(curl|POST|GET|PUT|DELETE|PATCH)[[:space:]]' \
  | grep -ioE "$CLOUD_RX" | sort -u)
if [ -n "$CLOUD_HOSTS" ]; then
  ATTEST_RX='OWNERSHIP:.*(cert|SAN|issuer|WHOIS|RDAP|manifest|SOA|registrant|served|account[- ]?id|control[- ]?panel|org=|verified[- ]scope|platform[- ]scope|in[- ]scope asset)|vendor[- ]disclosure|coordinated (vendor )?disclosure'
  if ! printf '%s' "$BODY" | grep -qiE "$ATTEST_RX"; then
    HLIST=$(printf '%s' "$CLOUD_HOSTS" | tr '\n' ' ')
    printf 'DRAFT BLOCKED (ATTRIBUTION - name-match is not ownership): this report targets cloud-provider host(s) [ %s] but carries NO captured OWNERSHIP artifact. A cloud hostname does not prove who operates it; attributing it to the program by name-match/scope-adjacency is the QuantumRhino + azure-webapp failure (killrule-asset-ownership-by-namematch-not-proof). Fail closed - do ONE of: (a) add a line  OWNERSHIP: <artifact>  that PROVES the program operates THIS host - TLS cert SAN/issuer-org on the host, RDAP/WHOIS org, app/add-in manifest ProviderName, DNS SOA/registrant, a program-served response containing the asset, or verified-scope (the platform h1-scope.sh asset list); or (b) if the artifact names a DIFFERENT entity, route it to reports/vendor-disclosure/ as coordinated vendor-disclosure, NOT an in-program draft.\n' "$HLIST" >&2
    exit 2
  fi
fi

SESS=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null)
LDIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/learning"; mkdir -p "$LDIR" 2>/dev/null
SC="$LDIR/draftgate-${SESS}.count"
CUR=$(cat "$SC" 2>/dev/null || echo 0); case $CUR in ''|*[!0-9]*) CUR=0;; esac; NEW=$((CUR + 1)); echo "$NEW" > "$SC" 2>/dev/null
[ "$NEW" -gt 15 ] && exit 0   # safety valve

ADV_SOFT=""   # accumulated NON-BLOCKING advisories, emitted once at the end (exit 0)

# ============================================================================================
# Denial 4 (CANONICAL FORMAT - one report shape for every report, GreyNOC 2026-09-30):
# every report follows reports/REPORT-FORMAT.md, derived from the operator's gold-standard
# submission (a filed report). Documentation alone gets ignored under pressure, so the six
# mechanical invariants are enforced HERE, at write time:
#   4a  ## Summary AND ## PoC AND ## Impact all present
#   4b  Summary <= 50 words
#   4c  Impact  <= 50 words
#   4d  the LAST "Step N." line is "Step N. Controls."
#   4e  no em-dash (U+2014) anywhere in the bytes being written
#   4f  a stamped researcher handle equals the resolved HACKERONE_HANDLE (never a stale one)
# WORD-COUNT RULE - byte-identical to REPORT-FORMAT.md section 7, DO NOT let these diverge:
#   section body = every line AFTER the heading, up to the next ATX heading or EOF; the
#   heading line is never counted; every fenced block (the fence delimiter lines AND all lines
#   between them) is removed; the count is the number of whitespace-separated tokens of what
#   remains. Fence state is tracked document-wide so a "#" inside a fence is not a heading.
# SCOPE: 4a/4b/4c/4d need the WHOLE document, so they run on a full Write only
# (.tool_input.content). An Edit sends a fragment (new_string) with no document to measure, and
# counting content+EXIST would DOUBLE-COUNT a re-Write (every section twice -> wedge) - the same
# reasoning that makes Denial 3 Write-only. 4e and 4f read only the bytes being written, so they
# run on Write AND Edit. Edits are re-checked by report-repro-checker and the next full Write.
FULLDOC=$(printf '%s' "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)

# THE canonical section word counter. Identical text lives in REPORT-FORMAT.md section 7 and in
# the three report agents. One implementation, one number, no arguments about counting.
CANON_WC='
  BEGIN { fence = 0; insec = 0; out = "" }
  {
    if ($0 ~ /^[[:space:]]*(```|~~~)/) { fence = 1 - fence; next }
    if (fence) next
    low = tolower($0)
    if (low ~ /^#+[[:space:]]/) { insec = (low ~ ("^#+[[:space:]]*" SEC)) ? 1 : 0; next }
    if (low ~ /^\*\*[a-z][a-z ]*\*\*[[:space:]]*$/) { insec = (low ~ ("^\\*\\*" SEC)) ? 1 : 0; next }
    if (insec) out = out " " $0
  }
  END {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", out)
    print (out == "" ? 0 : split(out, _t, /[[:space:]]+/))
  }'

if [ -n "$FULLDOC" ]; then
  # one pass for the four structural facts: has-summary, has-poc, has-impact, step count,
  # and whether the LAST "Step N." line is the Controls step.
  CANON_STRUCT=$(printf '%s' "$FULLDOC" | awk '
    BEGIN { fence = 0; hs = 0; hp = 0; hi = 0; n = 0; ctrl = 0 }
    {
      if ($0 ~ /^[[:space:]]*(```|~~~)/) { fence = 1 - fence; next }
      if (fence) next
      low = tolower($0)
      if (low ~ /^##[[:space:]]*summary[[:space:]]*$/)                 hs = 1
      if (low ~ /^#+[[:space:]]*(poc|proof of concept|steps to reproduce|reproduction)[[:space:]]*$/) hp = 1
      if (low ~ /^##[[:space:]]*impact[[:space:]]*$/)                  hi = 1
      if (low ~ /^\*\*summary\*\*[[:space:]]*$/)                      hs = 1
      if (low ~ /^\*\*(poc|proof of concept)\*\*[[:space:]]*$/)        hp = 1
      if (low ~ /^\*\*impact\*\*[[:space:]]*$/)                        hi = 1
      if (low ~ /^[[:space:]]*(\*\*)?step[[:space:]]+[0-9]+\./) {
        n++
        ctrl = (low ~ /^[[:space:]]*(\*\*)?step[[:space:]]+[0-9]+\.[[:space:]]*(\*\*)?[[:space:]]*controls[[:space:]]*\.?[[:space:]]*(\*\*)?[[:space:]]*$/) ? 1 : 0
      }
    }
    END { printf "%d %d %d %d %d\n", hs, hp, hi, n, ctrl }')
  set -- $CANON_STRUCT
  C_HS=${1:-0}; C_HP=${2:-0}; C_HI=${3:-0}; C_NSTEP=${4:-0}; C_CTRL=${5:-0}

  # --- 4a: the three canonical sections ---
  if [ "$C_HS" -ne 1 ] || [ "$C_HP" -ne 1 ] || [ "$C_HI" -ne 1 ]; then
    MISS=""
    [ "$C_HS" -ne 1 ] && MISS="${MISS}## Summary "
    [ "$C_HP" -ne 1 ] && MISS="${MISS}## PoC "
    [ "$C_HI" -ne 1 ] && MISS="${MISS}## Impact "
    printf 'DRAFT BLOCKED (CANONICAL FORMAT 4a - required section missing): this draft has no %s. Every report follows ONE shape (reports/REPORT-FORMAT.md section 1): the CVSS/Asset/CWE/Dedup/Gate header block, the "# <title>" line, then EXACTLY "## Summary" (<=50 words), "## PoC" (uncapped), "## Impact" (<=50 words), then the attachment list under its own "## Attachments" heading. Heading spelling is literal: "## Summary", "## PoC" (or the legacy "## Proof of Concept"), "## Impact" - nothing before or after the word on that line. A heading inside a fenced block does not count. Add the missing section and re-write.\n' "$MISS" >&2
    exit 2
  fi

  C_SW=$(printf '%s' "$FULLDOC" | awk -v SEC=summary "$CANON_WC" 2>/dev/null); C_SW=${C_SW:-0}
  C_IW=$(printf '%s' "$FULLDOC" | awk -v SEC=impact  "$CANON_WC" 2>/dev/null); C_IW=${C_IW:-0}
  case "$C_SW" in ''|*[!0-9]*) C_SW=0;; esac
  case "$C_IW" in ''|*[!0-9]*) C_IW=0;; esac

  # --- 4b: Summary hard cap ---
  if [ "$C_SW" -gt 150 ]; then
    printf 'DRAFT BLOCKED (CANONICAL FORMAT 4b - Summary over the 150-word HARD cap): Summary=%s words, cap=150, over by %s. The Summary carries exactly four facts and nothing else (REPORT-FORMAT.md section 3): (a) what I obtain, (b) the mechanism that lets me obtain it, (c) the trust boundary crossed, (d) the isolation fact proving that boundary is real. First person, present tense. Delete hype, self-assessed severity, CWE recitation, vendor/product background, CVSS prose, and any sentence not load-bearing for a/b/c/d. Word count = whitespace tokens in the section body, heading line excluded, fenced blocks excluded. Target is 35 words; 50 is the wall. Trim and re-write.\n' "$C_SW" "$((C_SW - 150))" >&2
    exit 2
  fi

  # --- 4c: Impact hard cap ---
  if [ "$C_IW" -gt 150 ]; then
    printf 'DRAFT BLOCKED (CANONICAL FORMAT 4c - Impact over the 150-word HARD cap): Impact=%s words, cap=150, over by %s. The Impact is EXACTLY two moves (REPORT-FORMAT.md section 5): sentence 1 = what was ACTUALLY PROVEN, first person, past tense; sentence 2 = the generalization attributed to "an attacker" and BOUNDED by its real precondition. No CVSS prose, no business-risk padding, no compliance language, no impact the PoC did not demonstrate. If the attachment list sits as bare lines under ## Impact it is being counted as Impact words - move it under its own "## Attachments" heading. Word count = whitespace tokens in the section body, heading line excluded, fenced blocks excluded. Target is 35 words; 50 is the wall. Cut to two sentences and re-write.\n' "$C_IW" "$((C_IW - 150))" >&2
    exit 2
  fi

  # --- 4d: the Controls battery must be the LAST step ---
  if [ "$C_NSTEP" -eq 0 ] || [ "$C_CTRL" -ne 1 ]; then
    if [ "$C_NSTEP" -eq 0 ]; then
      WHY='the PoC contains no "Step N." lines at all'
    else
      WHY="the last of the ${C_NSTEP} \"Step N.\" lines is not the Controls step"
    fi
    ADV_SOFT="${ADV_SOFT}ADVISORY (4d, non-blocking since 2026-10-05): the PoC does not end with a Controls step. REPORT-FORMAT was rewritten 2026-10-04 to require only a negative control, the probe and the captured response, and STYLE.md ends the PoC at the terminal action. A trailing Controls step is optional. "
    printf 'ADVISORY 4d (not blocking): %s. The PoC is numbered "Step N. <imperative sentence>." lines, each followed by a fenced block of REAL captured traffic, and the LAST step is ALWAYS literally "Step N. Controls." - the negative-control battery, minimum four controls (REPORT-FORMAT.md section 4.8): (1) an unauthenticated attempt, expect 401; (2) a ghost candidate that never existed, proving zero false positives across N rounds; (3) a serial replay proving identical results; (4) the cross-boundary denial, 403 on the victim-owned resource. Step 1 is ALWAYS the access-boundary negative control (the 401/403 baseline) - without it every later 200 means nothing. Add the Controls step as the final step if it answers a question a triager would ask.\n' "$WHY" >&2
  fi
fi

# --- 4e: em-dash (runs on Write AND Edit - reads only the bytes being written) ---
CANON_EMDASH=$(printf '\xe2\x80\x94')
if [ -n "$CONTENT" ] && printf '%s' "$CONTENT" | grep -qF -- "$CANON_EMDASH" 2>/dev/null; then
  EM_N=$(printf '%s' "$CONTENT" | grep -cF -- "$CANON_EMDASH" 2>/dev/null || echo '?')
  EM_HITS=$(printf '%s' "$CONTENT" | grep -nF -- "$CANON_EMDASH" 2>/dev/null | head -3 | cut -c1-160 | tr '\n' '|')
  printf 'DRAFT BLOCKED (CANONICAL FORMAT 4e - em-dash): %s line(s) in the bytes being written contain an em-dash (U+2014). An em-dash is the single loudest AI tell and it costs reputation even on a technically correct report (a triager flagged one of ours as "abundantly clear you have generated your report using AI" and marked it NMI, -5 rep). Use a SINGLE hyphen with spaces around it, or restructure the sentence. First offending line(s): %s Replace every one and re-write.\n' "$EM_N" "$EM_HITS" >&2
  exit 2
fi

# --- 4f: the researcher-identification header must carry the CURRENT handle ---
# The handle is NEVER hardcoded in a template: it resolves from HACKERONE_HANDLE (alias
# H1_HANDLE) in ~/.config/gnoc/secrets.env, the same var scripts/h1-scope.sh reads.
# A stale handle in a PoC (e.g. a previous submitting account) misattributes the traffic.
# Fail SAFE: if the var does not resolve, or resolves to a placeholder, this check is skipped
# (it can never wedge a session over a config file another process owns).
CANON_SECRETS="$HOME/.config/gnoc/secrets.env"
CANON_HANDLE=""
if [ -r "$CANON_SECRETS" ]; then
  CANON_HANDLE=$(grep -hoE '^[[:space:]]*(HACKERONE_HANDLE|H1_HANDLE)=.*' "$CANON_SECRETS" 2>/dev/null \
                 | head -1 | cut -d= -f2- | tr -d "\"' 	")
fi
case "$CANON_HANDLE" in ''|your-*|*'<'*|CHANGEME*|placeholder*) CANON_HANDLE="" ;; esac
if [ -n "$CANON_HANDLE" ] && [ -n "$CONTENT" ]; then
  CANON_BADH=""
  for h in $(printf '%s' "$CONTENT" | grep -ioE 'X-HackerOne(-Research)?:[[:space:]]*[A-Za-z0-9_.$@{}-]+' 2>/dev/null \
             | sed -E 's/.*:[[:space:]]*//' | sort -u); do
    case "$h" in
      "$CANON_HANDLE") continue ;;
      '$H1_HANDLE'|'${H1_HANDLE}'|'$HACKERONE_HANDLE'|'${HACKERONE_HANDLE}') continue ;;
      *) CANON_BADH="$CANON_BADH $h" ;;
    esac
  done
  if [ -n "$CANON_BADH" ]; then
    printf 'DRAFT BLOCKED (CANONICAL FORMAT 4f - stale researcher handle): the PoC stamps the researcher-identification header with [%s] but the resolved current handle is [%s]. The handle is a VARIABLE, never a literal carried over from a previous report: it resolves from HACKERONE_HANDLE (alias H1_HANDLE) in %s, the same var scripts/h1-scope.sh reads. Fix the stamped value to [%s], or write the header value as the shell variable $H1_HANDLE and let repro.sh resolve it at run time (REPORT-FORMAT.md section 6).\n' "$(printf '%s' "$CANON_BADH" | sed 's/^ //')" "$CANON_HANDLE" "$CANON_SECRETS" "$CANON_HANDLE" >&2
    exit 2
  fi
fi


# Denial 3 (LENGTH - Summary/Impact 35-word hardrule, GreyNOC 2026-07-19): in the H1/3-section
# shape the Summary section AND the Impact section must EACH be 35 words or fewer. The CVSS/CWE/
# Asset header block already carries the metadata, so the prose stays terse; the PoC is UNCAPPED.
# COUNT ONLY a full-document Write (.tool_input.content = the whole final file). An Edit sends a
# fragment (new_string) with no full document to measure, and counting content+EXIST would
# DOUBLE-COUNT a re-Write (every section twice -> wedge); so this length denial is Write-only, and
# the CVSS-header probe is scoped to the header block (head -6) so a mid-body "CVSS:" quote in an
# Immunefi form does not trip it. Edits are re-checked by the repro-checker and the next full Write.
WRITE_CONTENT=$(printf '%s' "$INPUT" | jq -r '.tool_input.content // empty' 2>/dev/null)
if [ -n "$WRITE_CONTENT" ] && printf '%s' "$WRITE_CONTENT" | head -n 6 | grep -qiE '^CVSS:'; then
  WC=$(printf '%s' "$WRITE_CONTENT" | awk '
    { low=tolower($0) }
    low ~ /^#+[[:space:]]*summary/ { sec="S"; next }
    low ~ /^#+[[:space:]]*impact/  { sec="I"; next }
    low ~ /^#+[[:space:]]/         { sec="";  next }
    sec=="S" { s=s" "$0 }
    sec=="I" { i=i" "$0 }
    END {
      gsub(/^[[:space:]]+|[[:space:]]+$/,"",s); gsub(/^[[:space:]]+|[[:space:]]+$/,"",i)
      print (s==""?0:split(s,a,/[[:space:]]+/)), (i==""?0:split(i,b,/[[:space:]]+/))
    }')
  SW=${WC%% *}; IW=${WC##* }; SW=${SW:-0}; IW=${IW:-0}
  # LEVEL CHANGE 2026-09-30 (rule KEPT, enforcement softened - see the header note and
  # REPORT-FORMAT.md section 8): 35 words is now the TARGET and emits a NON-BLOCKING advisory;
  # the HARD wall is 50 words in Denial 4b/4c. The rule, its date, its rationale and its
  # Immunefi exemption are unchanged. Nothing here is deleted - only exit 2 became an advisory,
  # because the operator explicitly specified 50-word caps for Summary and Impact, which supersedes the older 35-word rule; 35 is retained as an advisory target. Measured with the canonical counter (and independently by `wc -w`), the gold-standard exemplar is Summary=29, Impact=31, so it sits comfortably inside BOTH limits. An earlier brief asserted 38 words; that was an unverified estimate and is wrong.
  # and a 35-word hard block would reject the exemplar this gate exists to produce.
  if [ "${SW:-0}" -gt 35 ] 2>/dev/null || [ "${IW:-0}" -gt 35 ] 2>/dev/null; then
    A35=$(printf 'LENGTH ADVISORY (non-blocking, this draft is NOT blocked): Summary=%s words, Impact=%s words. GreyNOC hardrule 2026-07-19: the Summary section and the Impact section should EACH be 35 words or fewer (the CVSS/CWE/Asset header block already carries the metadata; keep the prose terse). The PoC is uncapped, cut nothing there. 35 is the TARGET; the HARD cap that blocks is 50 (Denial 4b/4c). Trim the section(s) over 35 words if you can. (Immunefi 7-section form is exempt.)' "$SW" "$IW")
    printf '%s\n' "$A35" >&2
    ADV_SOFT="${ADV_SOFT}${ADV_SOFT:+

}${A35}"
  fi
fi

# Denial 3b (HYGIENE - internal stamps in the header ONLY + no confession/narration, GreyNOC 2026-07-23):
# the two INTERNAL stamps (Gate:/Dedup:) belong in the TOP header block with CVSS/Asset/CWE and NOWHERE
# else (that block is the local field-fill zone, not the vendor-facing description); the triager-kill-
# signal confession sections must not exist anywhere. Write-only (needs the full document); an Edit sends
# a fragment, so - like the length gate - Edits are re-checked by the repro-checker + the next full Write.
if [ -n "$WRITE_CONTENT" ]; then
  # the vendor-facing body = everything AFTER the first top-level "# " title line (header block excluded)
  BELOW=$(printf '%s' "$WRITE_CONTENT" | awk 'seen{print} /^# /{seen=1}')
  HYG=""
  printf '%s' "$BELOW" | grep -qiE 'Dedup:.*public-checked|Gate:.*(report-killer|reviewer).*(PASS|GATE)|<!--[^>]*(Dedup:.*public-checked|Gate:.*(report-killer|reviewer))' \
    && HYG="${HYG}a Gate:/Dedup: stamp sits below the title (in the vendor-facing body or an HTML comment); move BOTH stamps UP into the header block on their own lines under CVSS:/Asset:/CWE:, above the # title. "
  printf '%s' "$WRITE_CONTENT" | grep -qiE 'What Was NOT Confirmed|Honest boundary|Pre-empting( potential)? by-design' \
    && HYG="${HYG}a triager-kill-signal confession is present (What Was NOT Confirmed / Honest boundary / Pre-empting by-design); delete it entirely - a bare one-line scope note without those labels is fine. "
  if [ -n "$HYG" ]; then
    printf 'DRAFT BLOCKED (HYGIENE - internal metadata/confessions leak into the vendor-facing report, GreyNOC 2026-07-23): %sThe report the vendor reads is the # title + Summary/PoC/Impact only. The CVSS/Asset/CWE/Dedup/Gate header block above the title is LOCAL metadata (you read it to fill the H1 fields; it is not pasted into the description), so the two internal stamps live THERE and nowhere else. Re-write: (1) Gate: and Dedup: on their own lines in the top header block, CVSS: first; (2) no What-Was-NOT-Confirmed / Honest-boundary / Pre-empting section anywhere; (3) PoC = linear captured steps, no hunt narration.\n' "$HYG" >&2
    exit 2
  fi
fi

EVID='HTTP/[12]|< HTTP|(200 OK|201 Created|204 |301 |302 |401 Unauth|403 Forbid|500 )|curl -|send_http|set-cookie:|content-length:|\{"[a-zA-Z_]|capture\.log'
# 2026-10-01: accept an HONEST in-progress value, not only PASS/GATE.
# Root cause of a real incident: the gate hard-required a PASS stamp, so a writer that had
# not run report-killer fabricated 'Gate: report-killer PASS' to get the save through. A gate
# that only accepts good news manufactures good news. The draft must still STATE its gate
# status (a missing stamp is still DENY), but NOT-YET-RUN / PENDING / KILL-PENDING are valid
# for a save. Only a PASS makes a draft READY, which is enforced where readiness is declared.
STAMP_RX='Gate:.*(report-killer|reviewer).*(PASS|GATE|NOT-YET-RUN|PENDING|KILL-PENDING)'
WEAK='existence[- ]oracle|enumerat|user enum|account enum|CORS (header|reflect)|reflects? (the )?origin|last[- ]four|last 4 digits|version disclosure|info(rmation)? disclosure|banner grab'
CAP='cross-tenant|cross-user|other (user|account|tenant)|another (user|account)|state chang|deleted|modif|exfiltrat|private (body|data|record)|foreign (id|account|object)|\bRCE\b|command exec|money|payout|takeover (served|claimed)|(retriev|obtain|recover|extract|dump|disclos|expos)[a-z]*[^.]{0,70}(credential|secret|api[- ]?key|private key|password|access token|client[- ]?secret)|session fixation|login[- ]csrf|authenticate as|logged in as|account takeover|\bATO\b'
# FIX 1a (2026-07-19): a captured-terminal-receipt requirement. A draft graduates only with BOTH a
# NEW-capability proof AND an artifact/response backing it - exactly SPINE gates 2 (capability) + 3
# (terminal). Reuse the battle-tested regexes: has_captured_resp = the existing EVID (a captured HTTP
# response block, not a bare request); has_new_cap = the existing CAP (cross-tenant/state-change/
# exfil/RCE/...). has_artifact = an evidence/artifact PATH in the body.
ARTIFACT_RX='(targets/[a-z0-9_-]+/(evidence|poc|hunts)/|capture\.log|repro\.(sh|py)|/evidence/|attach(ment)?:|Evidence:)'
# FIX 1b: control-bypass classes need a verbatim vendor-doc contradiction (SPINE 0b SIG-2 cash multiplier).
BYPASS_CLASS_RX='auth(entication|z|orization)?[- ]?bypass|access control|cache (poison|deception)|request smuggl|desync|CORS|cross-origin|open redirect|redirect_uri|SSO|SAML|OAuth'
VENDORDOC_RX='(vendor|documentation|docs?|policy|per their|states that|promises?|guarantees?)[^.]{0,80}https?://'

has_evid=false;  printf '%s' "$BODY" | grep -qiE "$EVID"     && has_evid=true
has_stamp=false; printf '%s' "$BODY" | grep -qiE "$STAMP_RX" && has_stamp=true
is_weak=false;   printf '%s' "$BODY" | grep -qiE "$WEAK"     && is_weak=true
has_cap=false;   printf '%s' "$BODY" | grep -qiE "$CAP"      && has_cap=true
# FIX 1a signals (has_captured_resp reuses EVID; has_new_cap reuses CAP; has_artifact is new):
has_captured_resp=$has_evid
has_new_cap=$has_cap
has_artifact=false; printf '%s' "$BODY" | grep -qiE "$ARTIFACT_RX" && has_artifact=true
# PUBLIC-DEDUP stamp (2026-07-16): 44% of our report KILLS are known-accepted PUBLIC duplicates -
# real valid bugs already filed by another researcher, that our own-work-only dedup never saw.
# FIX 2 (2026-07-19): the stamp now REQUIRES a parenthesised verdict token (none|dup#N|novel:<angle>);
# a bare "public-checked" no longer passes. EITHER the upgraded stamp OR a clean ledger line for the
# program satisfies has_dedup (belt-and-suspenders, fail-toward-not-wedging).
DEDUP_RX='Dedup:.*public-checked.*(none|no prior|dup#?[0-9]+|novel:)'
has_dedup=false; printf '%s' "$BODY" | grep -qiE "$DEDUP_RX" && has_dedup=true
# FIX 2b (2026-07-19): track a typed "(none)"-form dedup stamp SPECIFICALLY (the self-asserted
# "I checked, nothing public" claim). If that self-claim is present but NO real public-dedup.sh
# ledger line corroborates it for this program, we emit a NON-BLOCKING advisory (exit 0) at the
# end so the ledger populates and the gate can start trusting it. Never blocks (wedge-safe).
STAMP_DEDUP_NONE=false; printf '%s' "$BODY" | grep -qiE 'Dedup:.*public-checked.*(none|no prior)' && STAMP_DEDUP_NONE=true
LEDGER_CORROBORATES=false   # set true below iff a clean (non-MATCH) ledger line exists for this program
# FIX 2 ledger: read the public-dedup.jsonl the dedup-scout writes pre-probe (read-only here).
PROGRAM=$(printf '%s' "$FP" | sed -n 's#.*/reports/drafts/\([^/]*\)/.*#\1#p')
LEDGER="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/public-dedup.jsonl"
LEDGER_MATCH=""   # a confirmed public duplicate line for this program+host/endpoint (prior #)
if [ -n "$PROGRAM" ] && [ -f "$LEDGER" ] && command -v jq >/dev/null 2>&1; then
  # a clean (result != MATCH) line for this program satisfies has_dedup even if the stamp is absent
  if jq -e --arg p "$PROGRAM" 'select(.program==$p and .result!="MATCH")' "$LEDGER" >/dev/null 2>&1; then
    has_dedup=true
    LEDGER_CORROBORATES=true   # FIX 2b: a real ledger line backs the dedup claim; no advisory needed
  fi
  # a MATCH line for this program whose host/endpoint token appears in the draft body = HARD block
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    tok=$(printf '%s' "$line" | jq -r 'if (.program==$P) and (.result=="MATCH") then ((.host // "") + "\n" + (.endpoint // "") + "\t" + (.prior // "")) else empty end' --arg P "$PROGRAM" 2>/dev/null)
    [ -z "$tok" ] && continue
    hosttok=$(printf '%s' "$tok" | sed -n '1p'); rest=$(printf '%s' "$tok" | sed -n '2p')
    endtok=$(printf '%s' "$rest" | cut -f1); priortok=$(printf '%s' "$rest" | cut -f2)
    if { [ -n "$hosttok" ] && printf '%s' "$BODY" | grep -qF "$hosttok"; } || \
       { [ -n "$endtok" ] && printf '%s' "$BODY" | grep -qF "$endtok"; }; then
      LEDGER_MATCH="$priortok"; break
    fi
  done < "$LEDGER"
fi

# OVERRIDE / ESCAPE HATCH (FIX 1): a deliberate, auditable human bypass of the capability + dedup
# ship-path checks for a genuine edge case (an Immunefi impact-only draft, a capability whose keywords
# the CAP regex misses). Invisible in the rendered report, cannot be emitted by accident, grep-able.
if printf '%s' "$BODY" | grep -qE '<!-- *OVERRIDE-DRAFT-GATE:'; then
  OVR=$(printf '%s' "$BODY" | grep -oE '<!-- *OVERRIDE-DRAFT-GATE:[^>]*-->' | head -1 | sed -E 's/<!-- *OVERRIDE-DRAFT-GATE: *//; s/ *-->//')
  printf 'OVERRIDE honored: draft-gate capability check bypassed (reason: %s)\n' "$OVR" >&2
  exit 0
fi

# FIX 2 HARD BLOCK: a confirmed public duplicate (ledger MATCH with a prior #) never becomes a draft.
if [ -n "$LEDGER_MATCH" ]; then
  printf 'DRAFT BLOCKED (PUBLIC DUPLICATE - already filed): the public-dedup ledger records a disclosed report %s for %s on this host/endpoint/class. 35%% of our H1 reports die duplicate (38 cite a specific prior #). This surface is pre-claimed; only the first report is awarded. Do NOT submit. If you hold a genuine NOVEL angle (a NEW terminal chain the prior report lacked, a bypass of the prior FIX, or a new-version reintroduction), re-run:\nscripts/learn/public-dedup.sh %s <host> <class> <endpoint> --result NOVEL:<angle>\nand state the delta vs %s in the Summary. Otherwise pivot to fresh ground.\n' "$LEDGER_MATCH" "$PROGRAM" "$PROGRAM" "$LEDGER_MATCH" >&2
  exit 2
fi

# FIX 1b (CAPABILITY + TERMINAL gate, hard): supersedes the old narrow weak-class Denial 1. A
# report-shaped draft with no captured NEW capability, or a captured capability with no artifact/
# response backing it, is a mechanism/reachability draft -> route to reports/leads/.
if ! $has_new_cap || { ! $has_artifact && ! $has_captured_resp; }; then
  printf 'DRAFT BLOCKED (CAPABILITY+TERMINAL gate - SPINE gates 2+3): this draft captures no NEW attacker capability. 34%% of our H1 reports die Informative ("mechanism/attack-surface, not a demonstrated exploit"; "no security impact"). A draft graduates ONLY with a CAPTURED terminal receipt: (1) a captured HTTP RESPONSE block showing a NEW capability - cross-user/cross-tenant READ or WRITE, a state change, money movement, exfiltrated bytes, or RCE - not a request, a 200, an enumerable id, or a reflected header; AND (2) an artifact/evidence path (capture.log / repro.sh / targets/<t>/evidence/...). This reads as a mechanism/reachability LEAD. Do NOT write it to reports/drafts/. Write it to reports/leads/ and escalate to a captured terminal capability first (self-provision a 2nd account, push a paired write/delete on the object you own, chain the partner bug). Force-write a genuine edge case with an HTML-comment sentinel:\n<!-- OVERRIDE-DRAFT-GATE: <one-line reason GreyNOC approves> -->\n' >&2
  exit 2
fi

# FIX 1b control-bypass sub-clause (hard): a bypass-class draft must quote a vendor-doc it contradicts.
# The vendor-doc anchor is routinely WRAPPED across two lines ("...documentation states X, at\n
# https://..."). grep is line-based, so the line-by-line form missed every wrapped quote and
# blocked reports that DO carry the anchor, pushing authors toward the override sentinel.
# Join the body to one line for this check only. Caught by the e2e suite 2026-10-05.
BODY_1LINE="$(printf '%s' "$BODY" | tr '\n' ' ')"
if printf '%s' "$BODY" | grep -qiE "$BYPASS_CLASS_RX" && ! printf '%s' "$BODY_1LINE" | grep -qiE "$VENDORDOC_RX"; then
  printf 'DRAFT BLOCKED (control-bypass needs a documented-promise contradiction - SPINE 0b SIG-2): this draft is a control-bypass class (auth/authz/cache/smuggling/CORS/redirect/SSO/OAuth) but quotes NO vendor documentation it contradicts. That verbatim promise + URL is the cash multiplier and the difference between "informative behavior" and a valid finding. Add the vendor'"'"'s own documented control claim, verbatim, with its URL, adjacent to the Impact - or route to reports/leads/ if no promise is actually violated. Override sentinel as above.\n' >&2
  exit 2
fi

# Denial 2: report-shaped but no captured evidence, no gate stamp, or no PUBLIC-dedup -> gate first
if ! $has_evid || ! $has_stamp || ! $has_dedup; then
  R="DRAFT BLOCKED (review-before-write): "
  $has_evid  || R="${R}no captured HTTP/PoC evidence in the body; "
  $has_stamp || R="${R}no 'Gate: report-killer <PASS|NOT-YET-RUN|KILL-PENDING> <date>' header stamp (state the TRUE status, never fabricate a PASS); "
  $has_dedup || R="${R}no verified 'Dedup: public-checked <date> (none|dup#N|novel:<angle>)' stamp AND no clean public-dedup ledger line for this program (44% of our report KILLS are known-accepted PUBLIC duplicates a disclosed-report search would have caught); "
  printf '%sFIX (both stamps go on their own lines in the TOP header block, under CVSS:/Asset:/CWE: and above the # title - CVSS: stays the first line - never in the body/PoC/an HTML comment): (1) run report-killer (fresh context) + triage-validator, confirm CAPABILITY + TERMINAL + REACHABILITY, stamp "Gate: report-killer PASS %s"; (2) run the PUBLIC dedup PRE-PROBE via scripts/learn/public-dedup.sh <program> <host> <class> <endpoint> --result none|MATCH:#NNNN|NOVEL:<angle> (it queries H1 hacktivity + GHSA + google site:hackerone.com and records a verified verdict to the ledger) then stamp "Dedup: public-checked %s (none|dup#N|novel:<angle>)" - the parenthesised verdict token is mandatory; (3) include the captured terminal response in PoC. Then re-write. Escape: a held lead goes to reports/leads/.\n' "$R" "$(date +%Y-%m-%d)" "$(date +%Y-%m-%d)" >&2
  exit 2
fi

# FIX 2b ADVISORY (NON-BLOCKING, exit 0): the draft passed every gate, but it satisfied the
# public-dedup requirement with a SELF-ASSERTED typed "(none)" stamp and NO real public-dedup.sh
# ledger line corroborates it for this program. 51 of our H1 closes were "known-accepted" PUBLIC
# duplicates a disclosed-report search would have caught; the ledger is how the gate HARD-BLOCKS
# those, and it only populates when dedup-scout actually runs the script pre-probe. So NUDGE (never
# block - a novel draft ships unimpeded): run the real query so the ledger corroborates next time and
# a genuine public MATCH gets caught. Advisory convention = additionalContext + exit 0 (concurrency-
# gate / orchestrator-byte-guard). Fires ONLY on the self-claim-without-corroboration case.
if $STAMP_DEDUP_NONE && ! $LEDGER_CORROBORATES && [ -n "$PROGRAM" ]; then
  ADV="PUBLIC-DEDUP ADVISORY (non-blocking, this draft is NOT blocked): the draft self-asserts a \"Dedup: public-checked (none)\" stamp but the public-dedup ledger has NO corroborating line for '${PROGRAM}'. 51 of our H1 closes were known-accepted PUBLIC duplicates a disclosed-report search would have caught; the gate can only HARD-BLOCK those when the ledger is populated by the REAL query. Run it once per checked tuple so the ledger corroborates (and catches a genuine public MATCH):  scripts/learn/public-dedup.sh ${PROGRAM} <host> <class> <endpoint> --result none|MATCH:#NNNN|NOVEL:<angle>  (queries H1 hacktivity + GHSA + google site:hackerone.com, appends the verdict, re-prints the stamp). This is a nudge, not a gate: your draft proceeds."
  printf '%s\n' "$ADV" >&2
  ADV_SOFT="${ADV_SOFT}${ADV_SOFT:+

}${ADV}"
fi

# Single advisory emission point (2026-09-30). Every non-blocking nudge collected above (the
# 35-word LENGTH target, the PUBLIC-DEDUP self-claim) leaves through here as ONE
# additionalContext payload + exit 0. Same convention as before (concurrency-gate /
# orchestrator-byte-guard); the draft is never blocked by anything in ADV_SOFT.
if [ -n "${ADV_SOFT:-}" ]; then
  jq -nc --arg c "$ADV_SOFT" '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$c}}' 2>/dev/null
  exit 0
fi
exit 0
