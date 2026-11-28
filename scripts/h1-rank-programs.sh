#!/usr/bin/env bash
# h1-rank-programs.sh
#
# Rank every HackerOne program the authenticated hacker can see by an
# "easy + pays + actively-resolving + few-reports" EV proxy, to pick the next
# target. Read-only against the H1 hacker API. NEVER prints the token.
#
# Criteria -> signal mapping (all from /v1/hackers/programs):
#   pays                 -> offers_bounties == true        (hard filter)
#   actively resolving   -> submission_state == "open"     (hard filter)
#   few reports (proxy)  -> started_accepting_at recent     (sort key; newer = less saturated)
#   public vs invited    -> state                           (SHOWN as a column, NOT filtered:
#                           private invited programs are valid targets, so left in)
#   fresh for me         -> number_of_reports_for_user      (SHOWN as a column for the human to
#                           judge self-dupe risk; NOT a hard filter)
# To hard-filter to public-only or zero-self-report programs, add those two predicates to the
# jq select() below. Left soft on purpose so invited private programs still rank.
#
# Token store (chmod 600): ~/.config/gnoc/secrets.env
#   HACKERONE_HANDLE=researcher
#   HACKERONE_API_TOKEN=<token from hackerone.com/settings/api_token>
set -u

SECRETS="$HOME/.config/gnoc/secrets.env"
[ -f "$SECRETS" ] || { echo "no secrets file at $SECRETS" >&2; exit 1; }
# shellcheck disable=SC1090
. "$SECRETS"
: "${HACKERONE_HANDLE:?set HACKERONE_HANDLE in $SECRETS}"
: "${HACKERONE_API_TOKEN:?set HACKERONE_API_TOKEN in $SECRETS}"
command -v jq >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }

AUTH="$HACKERONE_HANDLE:$HACKERONE_API_TOKEN"
API="https://api.hackerone.com/v1/hackers"
RAW=$(mktemp)
trap 'rm -f "$RAW" "$RAW.tsv"' EXIT

url="$API/programs?page%5Bsize%5D=100"
page=0
while [ -n "$url" ]; do
  resp=$(curl -s -u "$AUTH" -H 'Accept: application/json' "$url")
  [ -z "$resp" ] && { echo "empty response (network/token/CF block)" >&2; exit 2; }
  if echo "$resp" | jq -e '.errors? // empty' >/dev/null 2>&1; then
    echo "API error (check token / handle):" >&2
    echo "$resp" | jq -r '.errors[]?.detail // .errors[]?.title // "unknown"' >&2
    exit 2
  fi
  echo "$resp" | jq -c '.data[]?' >> "$RAW"
  url=$(echo "$resp" | jq -r '.links.next // empty')
  page=$((page+1))
done

total=$(wc -l < "$RAW")
echo "# Pulled $total programs across $page page(s)" >&2

# SATURATION SCORE (FIX 5 2026-07-19): rank toward CONVERTERS + FRESH scope, away from
# picked-over flagships. The workspace flags (dead-list / positive-converter) are not in the API
# JSON, so compute them in bash and inject as space-delimited lookup strings into the jq pass.
# Fail-open: a missing triager file simply skips the positive-bonus (age-only ranking).
NOYIELD="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/no-yield.txt"
TRIAGER="${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/h1-feedback/triager_analysis.latest.json"
DEAD=""; [ -f "$NOYIELD" ] && DEAD=$(grep -vE '^[[:space:]]*#' "$NOYIELD" 2>/dev/null | awk '{print $1}' | grep -vE '^$' | tr '\n' ' ')
POS=""; [ -f "$TRIAGER" ] && POS=$(jq -r '.[]? | select((.state|type=="string") and (.state|test("resolved|triaged|retesting|pending-program-review"))) | .program' "$TRIAGER" 2>/dev/null | sort -u | tr '\n' ' ')
TODAY_EPOCH=$(date +%s)

# Rank: bounty-paying + open submission (hard filters preserved), scored by converter/fresh/
# novelty bonuses minus saturation-by-age + exhausted-for-us penalties; dead-listed rows dropped.
jq -rs \
  --arg dead " $DEAD " --arg pos " $POS " --argjson today "$TODAY_EPOCH" '
  ( $dead | ascii_downcase ) as $deadl
  | ( $pos  | ascii_downcase ) as $posl
  | map(.attributes)
  | map(select(.offers_bounties == true
               and .submission_state == "open"))
  # drop dead-listed handles entirely (mirror the rotate-selector). Bind the handle-token to a
  # var FIRST: inside `$deadl | contains(x)` the `.` is $deadl (a string), so `.handle` there
  # would fail "Cannot index string" - capture it in the object context before the pipe.
  | map( ((( .handle // "")|ascii_downcase)) as $h
         | select( ($deadl | contains(" " + $h + " ")) | not ) )
  | map(
      ( ((.name // "") + " " + (.handle // "")) ) as $nm
      | ( ((.handle // "")|ascii_downcase) ) as $h
      | ( (.started_accepting_at // "") ) as $sa
      | ( if $sa == "" then 0
          else ( ($today - (($sa[0:19] + "Z") | try (fromdateiso8601) catch $today)) / 86400 )
          end ) as $age_days
      | ( ($age_days / 365) ) as $age_years
      | ( (.number_of_reports_for_user // 0) - (.number_of_valid_reports_for_user // 0) ) as $self_dupe
      | ( $posl | contains(" " + $h + " ") ) as $is_pos
      | ( $age_days <= 180 ) as $fresh
      | ( $nm | test("web3|onchain|chain|protocol|defi|token|nft|wallet|\\bai\\b|\\bml\\b|llm|genai|copilot|agent"; "i") ) as $novel
      | ( $nm | test("checkout|cart|coupon|payment|marketplace|booking|order|shop|commerce"; "i") ) as $commerce
      | ( (.open_scope // false) == true ) as $openscope
      | . + {
          _score: ( (if $is_pos then 50 else 0 end)
                    + (if $fresh then 20 else 0 end)
                    + (if $novel then 15 else 0 end)
                    + (if $openscope then 5 else 0 end)
                    + (if $commerce then 10 else 0 end)
                    - ( [ ($age_years * 4), 40 ] | min | floor )
                    - ( [ ($self_dupe * 3), 30 ] | min | floor ) ),
          _sat: ( ((( [ ($age_years * 4), 40 ] | min | floor )) | tostring) + "a/"
                  + (( [ ($self_dupe * 3), 30 ] | min | floor ) | tostring) + "d" ),
          _nov: ( (if $is_pos then "POS " else "" end)
                  + (if $fresh then "FRESH " else "" end)
                  + (if $novel then "NOVEL " else "" end)
                  + (if $commerce then "COMMERCE" else "" end) ),
          _commerce: $commerce
        }
    )
  | sort_by(._score) | reverse
  | .[]
  | [ (._score | tostring),
      (.started_accepting_at // "n/a")[0:10],
      (.number_of_reports_for_user // 0 | tostring),
      .state,
      (._sat // ""),
      ((._nov // "") | if . == "" then "-" else . end),
      .handle,
      .name ]
  | @tsv
' "$RAW" > "$RAW.tsv"
rm -f "$RAW"

# --tsv (or --machine): raw tab-separated rows for a script to parse (auto-target.py's rank
# fallback reads this - the default pretty table below reflows NOV into a multi-word cell,
# which is not safely whitespace-splittable).
if [ "${1:-}" = "--tsv" ] || [ "${1:-}" = "--machine" ]; then
  (echo -e "SCORE\tSTARTED_ACCEPTING\tMY_REPORTS\tSTATE\tSAT\tNOV\tHANDLE\tNAME"; cat "$RAW.tsv")
else
  (echo -e "SCORE\tSTARTED_ACCEPTING\tMY_REPORTS\tSTATE\tSAT\tNOV\tHANDLE\tNAME"; cat "$RAW.tsv") | column -t -s $'\t'
fi
rm -f "$RAW.tsv"

rm -f "$RAW"
