#!/usr/bin/env bash
# bugcrowd-rank-programs.sh [--stats N] [--category bug_bounty|vdp|...] [--all]
#
# Rank every PUBLIC Bugcrowd engagement by an "easy + pays + fresh + wide-scope" EV
# proxy, to pick the next target. Mirrors scripts/h1-rank-programs.sh in shape and
# intent. Read-only, ZERO AUTH, talks only to bugcrowd.com.
#
# Data source (verified live 2026-09-30, plain curl, HTTP 200 application/json):
#   GET https://bugcrowd.com/engagements.json?category=bug_bounty&sort_by=promoted&sort_direction=desc&page=N
#     -> {"engagements":[ {name, briefUrl, tagline, accessStatus, isPrivate, isBanned,
#                          isDemo, badgeVariant, scopeRank, serviceLevel, endsAt,
#                          industryName, productEngagementType{label,iconVariant},
#                          rewardSummary{summary,minReward,maxReward,hint}}, ... ],
#         "paginationMeta":{limit:24,totalCount:288}}
#   GET https://bugcrowd.com/engagements/<code>/statistics                (--stats only)
#     -> {rewardedVulnerabilities, averagePayout, validSubmissionCount, validationWithin}
#
# Criteria -> signal mapping (all straight from the directory JSON):
#   pays cash        -> rewardSummary.maxReward contains a "$"     (hard filter)
#   accepting        -> accessStatus == "open", not isBanned/isDemo (hard filter)
#   payout ceiling   -> maxReward parsed to a number               (score, bucketed)
#   scope breadth    -> scopeRank 1..5, Bugcrowd's own scope-size rank (score)
#   freshness        -> badgeVariant "new" / "updated"             (score)
#   novelty/commerce -> keyword match on name+tagline              (score)
#   saturation       -> rewardedVulnerabilities from /statistics   (penalty, --stats only)
#   dead-listed      -> .claude/state/hunt-loop/no-yield.txt       (row dropped)
#
# SCORE is an ordering heuristic, not a promise. Gate any pick through the real
# eligibility check before hunting:  scripts/bugcrowd-scope.sh <code>
#
# Full platform notes: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/BUGCROWD.md
set -u

STATS_N=0
CATEGORY="bug_bounty"
SHOW_ALL=0
TSV=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stats) STATS_N="${2:-25}"; shift 2 ;;
    --category) CATEGORY="${2:-bug_bounty}"; shift 2 ;;
    --all) SHOW_ALL=1; shift ;;
    --tsv|--machine) TSV=1; shift ;;
    -h|--help)
      echo "usage: bugcrowd-rank-programs.sh [--stats N] [--category bug_bounty] [--all] [--tsv]" >&2
      echo "  --stats N   enrich the top N rows with /statistics (N extra GETs; default off)" >&2
      echo "  --all       keep non-cash and non-open engagements too (no hard filters)" >&2
      echo "  --tsv       raw tab-separated rows for a script to parse (auto-target.py's rank fallback)," >&2
      echo "              no column -t alignment. Header row included; CODE is the parseable column." >&2
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$STATS_N" in ''|*[!0-9]*) echo "--stats takes a number" >&2; exit 2 ;; esac

command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }

SITE="https://bugcrowd.com"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
RAW=$(mktemp "${TMPDIR:-/tmp}/bc-rank.XXXXXX.jsonl") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$RAW"' EXIT

# --- page through the public directory -------------------------------------------------
page=1
total=""
while : ; do
  resp=$(curl -s --max-time 40 -A "$UA" -H 'Accept: application/json' \
    "$SITE/engagements.json?category=$CATEGORY&sort_by=promoted&sort_direction=desc&page=$page")
  [ -z "$resp" ] && { echo "empty response on page $page (network/egress)" >&2; exit 2; }
  if printf '%s' "$resp" | jq -e '.errors? // empty' >/dev/null 2>&1; then
    printf '%s' "$resp" | jq -r '.errors[]?.detail // "unknown"' >&2
    exit 2
  fi
  n=$(printf '%s' "$resp" | jq -r '.engagements | length' 2>/dev/null) || n=0
  [ -z "$total" ] && total=$(printf '%s' "$resp" | jq -r '.paginationMeta.totalCount // 0')
  [ "$n" = "0" ] && break
  printf '%s' "$resp" | jq -c '.engagements[]?' >> "$RAW"
  got=$(wc -l < "$RAW")
  [ "$got" -ge "${total:-0}" ] && break
  page=$((page+1))
  [ "$page" -gt 40 ] && break     # hard stop; the directory is ~12 pages
done
got=$(wc -l < "$RAW")
echo "# Pulled $got of $total '$CATEGORY' engagement(s) across $page page(s) from $SITE/engagements.json" >&2
[ "$got" = "0" ] && { echo "no engagements returned" >&2; exit 2; }

# --- optional per-engagement statistics (bounded by --stats N) -------------------------
STATS=$(mktemp "${TMPDIR:-/tmp}/bc-stats.XXXXXX.jsonl") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$RAW" "$STATS" "$RAW.tsv"' EXIT
: > "$STATS"
if [ "$STATS_N" -gt 0 ]; then
  echo "# Enriching the first $STATS_N engagement(s) with /statistics ..." >&2
  jq -r '.briefUrl' "$RAW" | sed -E 's#^/+engagements/##' | head -n "$STATS_N" | while IFS= read -r code; do
    [ -z "$code" ] && continue
    s=$(curl -s --max-time 20 -A "$UA" -H 'Accept: application/json' "$SITE/engagements/$code/statistics")
    printf '%s' "$s" | jq -c --arg c "$code" '{code:$c, rewarded:(.rewardedVulnerabilities // null), avg:(.averagePayout // null)}' 2>/dev/null >> "$STATS"
  done
fi

# --- dead-list (mirror of h1-rank-programs.sh; fail-open when the file is absent) ------
NOYIELD="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/no-yield.txt"
DEAD=""
[ -f "$NOYIELD" ] && DEAD=$(grep -vE '^[[:space:]]*#' "$NOYIELD" 2>/dev/null | awk '{print $1}' | grep -vE '^$' | tr '\n' ' ')

jq -rs --arg dead " $DEAD " --argjson showall "$SHOW_ALL" --slurpfile stats "$STATS" '
  ( $dead | ascii_downcase ) as $deadl
  | ( ($stats | map({key:.code, value:.}) | from_entries) ) as $st
  | map(
      . + { _code: ((.briefUrl // "") | sub("^/+engagements/"; "")) }
    )
  | map( (._code | ascii_downcase) as $h
         | select( ($deadl | contains(" " + $h + " ")) | not ) )
  # parse "$4,000" / "Points" / "-" into a number; Points and swag are 0.
  | map(
      ( (.rewardSummary.maxReward // "") ) as $mx
      | ( (.rewardSummary.minReward // "") ) as $mn
      | ( ($mx | if test("\\$") then (gsub("[^0-9]";"") | if . == "" then 0 else tonumber end) else 0 end) ) as $max_usd
      | ( ($mn | if test("\\$") then (gsub("[^0-9]";"") | if . == "" then 0 else tonumber end) else 0 end) ) as $min_usd
      | . + { _max_usd: $max_usd, _min_usd: $min_usd }
    )
  | ( if $showall == 1 then .
      else map(select(._max_usd > 0
                      and (.accessStatus // "") == "open"
                      and (.isBanned // false) == false
                      and (.isDemo // false) == false))
      end )
  | map(
      ( ((.name // "") + " " + (.tagline // "")) ) as $nm
      | ( (.scopeRank // 0) ) as $sr
      | ( (.badgeVariant // "") ) as $bv
      | ( ($st[._code].rewarded // null) ) as $rewarded
      | ( ($st[._code].avg // null) ) as $avgpay
      | ( $nm | test("web3|onchain|chain|protocol|defi|token|nft|wallet|\\bai\\b|\\bml\\b|llm|genai|copilot|agent"; "i") ) as $novel
      | ( $nm | test("checkout|cart|coupon|payment|marketplace|booking|order|shop|commerce|bank|fintech"; "i") ) as $commerce
      | ( ._max_usd ) as $mx
      | . + {
          _score: ( ( if   $mx >= 10000 then 40
                      elif $mx >=  5000 then 32
                      elif $mx >=  2500 then 24
                      elif $mx >=  1000 then 16
                      else 8 end )
                    + ($sr * 4)
                    + (if $bv == "new" then 20 elif $bv == "updated" then 10 else 0 end)
                    + (if $novel then 15 else 0 end)
                    + (if $commerce then 10 else 0 end)
                    + (if (.serviceLevel // "") == "Platform" then 0 else 5 end)
                    - (if $rewarded == null then 0
                       else ([ (($rewarded / 5) | floor), 30 ] | min) end) ),
          _sat: (if $rewarded == null then "-"
                 else (($rewarded|tostring) + "rew" + (if $avgpay then "/" + $avgpay else "" end)) end),
          _nov: ( (if $bv == "new" then "NEW " elif $bv == "updated" then "UPD " else "" end)
                  + (if $novel then "NOVEL " else "" end)
                  + (if $commerce then "COMMERCE" else "" end) )
        }
    )
  | sort_by(._score) | reverse
  | .[]
  | [ (._score | tostring),
      (.rewardSummary.summary // "-"),
      ((.scopeRank // 0) | tostring),
      (.accessStatus // "?"),
      (.serviceLevel // "?"),
      (._sat // "-"),
      ((._nov // "") | if . == "" then "-" else . end),
      ._code,
      (.name // "?") ]
  | @tsv
' "$RAW" > "$RAW.tsv"

if [ "$TSV" = "1" ]; then
  (echo -e "SCORE\tREWARD\tSCOPE\tACCESS\tSERVICE\tSAT\tFLAGS\tCODE\tNAME"; cat "$RAW.tsv")
else
  (echo -e "SCORE\tREWARD\tSCOPE\tACCESS\tSERVICE\tSAT\tFLAGS\tCODE\tNAME"; cat "$RAW.tsv") | column -t -s $'\t'
fi
rm -f "$RAW.tsv"

echo "# next: scripts/bugcrowd-scope.sh <CODE>   then scripts/intake.sh verify <CODE>" >&2
