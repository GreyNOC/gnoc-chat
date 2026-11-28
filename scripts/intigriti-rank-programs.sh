#!/usr/bin/env bash
# intigriti-rank-programs.sh [--all] [--min-max N] [--vdp]
#
# Rank every PUBLIC Intigriti program by an "easy + pays + alive + fresh" EV proxy, to
# pick the next target. Mirrors scripts/h1-rank-programs.sh in shape and intent.
# Read-only, ZERO AUTH, talks only to app.intigriti.com.
#
# Data source (verified live 2026-09-30, plain curl, HTTP 200 application/json):
#   GET https://app.intigriti.com/api/core/public/programs
#     -> [ {programId, status, confidentialityLevel, companyHandle, companyName, handle,
#           name, description, industry, minBounty{value,currency}, maxBounty{...},
#           lastUpdatedAt, lastSubmissionAt, createdAt, tacRequired, twoFactorRequired,
#           companySustainable, logoId}, ... ]
#   188 programs on 2026-09-30. All timestamps are UNIX SECONDS.
#
# Criteria -> signal mapping:
#   pays cash        -> maxBounty.value > 0                        (hard filter, -a disables)
#   fetchable        -> confidentialityLevel == 4                  (hard filter, -a disables)
#                       cl=4 is the only level scripts/intigriti-scope.sh can read; cl=2
#                       programs answer HTTP 403 on the public program endpoint.
#   payout ceiling   -> maxBounty.value, bucketed                  (score)
#   alive            -> lastSubmissionAt recency                   (score / stale penalty)
#   fresh scope      -> lastUpdatedAt recency                      (score)
#   saturation proxy -> createdAt age in years                     (penalty; older = picked over)
#   novelty/commerce -> keyword match on name + description        (score)
#   friction         -> tacRequired / twoFactorRequired            (small penalty)
#   dead-listed      -> .claude/state/hunt-loop/no-yield.txt       (row dropped)
#
# HONEST GAP: the `status` field takes values 3 (175 programs) and 4 (13) and its meaning
# is NOT confirmed. It is not open-vs-closed: status=4 includes AMD (max 30,000), Grafana
# Labs OSS (15,000) and Coveo (5,500), all with submissions in the last few days, and a
# status=4 program still serves its full detail JSON. So status is SHOWN as a column and
# never filtered on. Do not read it as a liveness signal.
#
# SCORE is an ordering heuristic, not a promise. Gate any pick through the real
# eligibility check before hunting:  scripts/intigriti-scope.sh <company>/<program>
#
# Full platform notes: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/INTIGRITI.md
set -u

SHOW_ALL=0
MIN_MAX=0
VDP_ONLY=0
TSV=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --all) SHOW_ALL=1; shift ;;
    --min-max) MIN_MAX="${2:-0}"; shift 2 ;;
    --vdp) VDP_ONLY=1; shift ;;
    --tsv|--machine) TSV=1; shift ;;
    -h|--help)
      echo "usage: intigriti-rank-programs.sh [--all] [--min-max N] [--vdp] [--tsv]" >&2
      echo "  --all        drop the hard filters (show non-cash and restricted programs too)" >&2
      echo "  --min-max N  only programs whose max bounty is >= N" >&2
      echo "  --vdp        INVERT: show only the no-cash (VDP) programs" >&2
      echo "  --tsv        raw tab-separated rows for a script to parse (auto-target.py's rank" >&2
      echo "               fallback), no column -t alignment. COMPANY/PROGRAM is the parseable column." >&2
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$MIN_MAX" in ''|*[!0-9]*) echo "--min-max takes a number" >&2; exit 2 ;; esac

command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }

API="https://app.intigriti.com/api/core/public/programs"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
RAW=$(mktemp "${TMPDIR:-/tmp}/ig-rank.XXXXXX.json") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$RAW" "$RAW.tsv"' EXIT

code=$(curl -s --max-time 45 -A "$UA" -H 'Accept: application/json' -o "$RAW" -w '%{http_code}' "$API")
if [ "$code" != "200" ]; then
  echo "public program list returned HTTP $code (network/egress or shape change)" >&2
  exit 2
fi
if ! jq -e 'type == "array" and length > 0' "$RAW" >/dev/null 2>&1; then
  echo "public program list was not a non-empty JSON array" >&2
  exit 2
fi
echo "# Pulled $(jq -r 'length' "$RAW") public program(s) from the Intigriti public program API" >&2

# --- dead-list (mirror of h1-rank-programs.sh; fail-open when the file is absent) ------
NOYIELD="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/no-yield.txt"
DEAD=""
[ -f "$NOYIELD" ] && DEAD=$(grep -vE '^[[:space:]]*#' "$NOYIELD" 2>/dev/null | awk '{print $1}' | grep -vE '^$' | tr '\n' ' ')
TODAY_EPOCH=$(date +%s)

jq -r --arg dead " $DEAD " --argjson today "$TODAY_EPOCH" \
      --argjson showall "$SHOW_ALL" --argjson minmax "$MIN_MAX" --argjson vdp "$VDP_ONLY" '
  ( $dead | ascii_downcase ) as $deadl
  | map( ((.handle // "")|ascii_downcase) as $h
         | select( ($deadl | contains(" " + $h + " ")) | not ) )
  | map( . + { _max: (.maxBounty.value // 0), _min: (.minBounty.value // 0),
               _cur: (.maxBounty.currency // .minBounty.currency // "-") } )
  | ( if $showall == 1 then .
      elif $vdp == 1 then map(select(._max == 0 and .confidentialityLevel == 4))
      else map(select(._max > 0 and .confidentialityLevel == 4 and ._max >= $minmax))
      end )
  | map(
      ( ((.name // "") + " " + (.description // "")) ) as $nm
      | ( ((.lastSubmissionAt // 0)) ) as $ls
      | ( ((.lastUpdatedAt // 0)) ) as $lu
      | ( ((.createdAt // 0)) ) as $cr
      | ( (if $ls > 0 then (($today - $ls) / 86400) else 99999 end) ) as $sub_days
      | ( (if $lu > 0 then (($today - $lu) / 86400) else 99999 end) ) as $upd_days
      | ( (if $cr > 0 then (($today - $cr) / 31536000) else 0 end) ) as $age_years
      | ( $nm | test("web3|onchain|chain|protocol|defi|token|nft|wallet|\\bai\\b|\\bml\\b|llm|genai|copilot|agent"; "i") ) as $novel
      | ( $nm | test("checkout|cart|coupon|payment|marketplace|booking|order|shop|commerce|bank|fintech|invoic"; "i") ) as $commerce
      | ( ._max ) as $mx
      | . + {
          _score: ( ( if   $mx >= 15000 then 40
                      elif $mx >=  7500 then 32
                      elif $mx >=  5000 then 26
                      elif $mx >=  2500 then 18
                      elif $mx >     0  then 10
                      else 0 end )
                    + (if $sub_days <=  14 then 20 elif $sub_days <=  60 then 12
                       elif $sub_days <= 180 then 4 else -10 end)
                    + (if $upd_days <=  30 then 15 elif $upd_days <=  90 then 8 else 0 end)
                    + (if $novel    then 15 else 0 end)
                    + (if $commerce then 10 else 0 end)
                    - ( [ (($age_years * 5) | floor), 35 ] | min )
                    - (if (.tacRequired // false)        then 3 else 0 end)
                    - (if (.twoFactorRequired // false)  then 2 else 0 end) ),
          _sat: ((($age_years * 5) | floor | if . > 35 then 35 else . end | tostring) + "a"),
          _sub: (if $ls > 0 then (($sub_days | floor | tostring) + "d") else "never" end),
          _upd: (if $lu > 0 then (($upd_days | floor | tostring) + "d") else "-" end),
          _nov: ( (if $sub_days <= 14 then "HOT " else "" end)
                  + (if $upd_days <= 30 then "FRESH " else "" end)
                  + (if $novel then "NOVEL " else "" end)
                  + (if $commerce then "COMMERCE" else "" end) ),
          _friction: ( (if (.tacRequired // false) then "ToS " else "" end)
                       + (if (.twoFactorRequired // false) then "2FA" else "" end) )
        }
    )
  | sort_by(._score) | reverse
  | .[]
  | [ (._score | tostring),
      ((._min | floor | tostring) + "-" + (._max | floor | tostring) + " " + ._cur),
      (.confidentialityLevel | tostring),
      (.status | tostring),
      ._sub,
      ._upd,
      ._sat,
      ((._friction // "") | if . == "" then "-" else . end),
      ((._nov // "")      | if . == "" then "-" else . end),
      ((.companyHandle // "?") + "/" + (.handle // "?")),
      (.name // "?") ]
  | @tsv
' "$RAW" > "$RAW.tsv"

if [ "$TSV" = "1" ]; then
  (echo -e "SCORE\tPAYOUT\tCL\tST\tLAST_SUB\tSCOPE_UPD\tSAT\tFRICTION\tFLAGS\tCOMPANY/PROGRAM\tNAME"; cat "$RAW.tsv")
else
  (echo -e "SCORE\tPAYOUT\tCL\tST\tLAST_SUB\tSCOPE_UPD\tSAT\tFRICTION\tFLAGS\tCOMPANY/PROGRAM\tNAME"; cat "$RAW.tsv") | column -t -s $'\t'
fi
rm -f "$RAW.tsv"

echo "# CL=confidentialityLevel (4=fetchable, 2=HTTP 403). ST=status (meaning unconfirmed, not filtered)." >&2
echo "# LAST_SUB=days since the last submission. SCOPE_UPD=days since the scope was last updated." >&2
echo "# next: scripts/intigriti-scope.sh <COMPANY/PROGRAM>   then scripts/intake.sh verify <PROGRAM>" >&2
