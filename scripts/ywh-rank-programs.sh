#!/usr/bin/env bash
# ywh-rank-programs.sh
#
# Rank every YesWeHack program visible to the API by an "easy + pays +
# active + few-reports" EV proxy, to pick the next target. Mirrors
# scripts/h1-rank-programs.sh. Read-only against api.yeswehack.com. NEVER
# prints any credential.
#
# Criteria -> signal mapping (all from GET /programs?page=N items):
#   pays                 -> bounty == true                 (hard filter)
#   live                 -> disabled == false AND archived == false (hard filter)
#   reward ceiling       -> bounty_reward_max              (higher = better EV)
#   responsiveness       -> average_first_response_time    (lower = better)
#   saturation (proxy)   -> reports_count                  (fewer = less duped)
#   attack surface       -> scopes_count                   (more = more surface)
#
# Auth: the public program list answers unauthenticated, so this runs with no
# token. To also see private programs you belong to, set a credential in
# ~/.config/gnoc/secrets.env (chmod 600, outside the workspace):
#   YWH_API_TOKEN=<personal access token>
#   (or YWH_EMAIL / YWH_PASSWORD / YWH_TOTP for the login -> JWT fallback)
set -u

SECRETS="$HOME/.config/gnoc/secrets.env"
[ -f "$SECRETS" ] && { # shellcheck disable=SC1090
  . "$SECRETS"; }
command -v jq   >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }

API="https://api.yeswehack.com"
UA="ywh-onboard/1.0"

YWH_API_TOKEN="${YWH_API_TOKEN:-}"
YWH_EMAIL="${YWH_EMAIL:-}"
YWH_PASSWORD="${YWH_PASSWORD:-}"
YWH_TOTP="${YWH_TOTP:-}"

BEARER=""
if [ -n "$YWH_API_TOKEN" ]; then
  BEARER="$YWH_API_TOKEN"
elif [ -n "$YWH_EMAIL" ] && [ -n "$YWH_PASSWORD" ]; then
  login=$(curl -s --max-time 25 -X POST "$API/login" \
            -H 'Content-Type: application/json' -H "User-Agent: $UA" \
            --data "$(jq -nc --arg e "$YWH_EMAIL" --arg p "$YWH_PASSWORD" \
                       '{email:$e,password:$p}')")
  totp_token=$(echo "$login" | jq -r '.totp_token // empty')
  if [ -n "$totp_token" ] && [ -n "$YWH_TOTP" ]; then
    otp=$(curl -s --max-time 25 -X POST "$API/account/totp" \
            -H 'Content-Type: application/json' -H "User-Agent: $UA" \
            --data "$(jq -nc --arg t "$totp_token" --arg c "$YWH_TOTP" \
                       '{token:$t,code:$c}')")
    BEARER=$(echo "$otp" | jq -r '.token // empty')
  else
    BEARER=$(echo "$login" | jq -r '.token // empty')
  fi
fi

ywh_get() {
  if [ -n "$BEARER" ]; then
    curl -s --max-time 30 -H "User-Agent: $UA" -H "Authorization: Bearer $BEARER" "$API$1"
  else
    curl -s --max-time 30 -H "User-Agent: $UA" "$API$1"
  fi
}

RAW=$(mktemp)
page=1
nb_pages=1
while [ "$page" -le "$nb_pages" ]; do
  resp=$(ywh_get "/programs?page=$page")
  if ! echo "$resp" | jq -e '.items? // empty' >/dev/null 2>&1; then
    msg=$(echo "$resp" | jq -r '.message // "no items in response"' 2>/dev/null)
    echo "API error on page $page: $msg" >&2
    [ "$page" = 1 ] && { rm -f "$RAW"; exit 2; }
    break
  fi
  echo "$resp" | jq -c '.items[]?' >> "$RAW"
  nb_pages=$(echo "$resp" | jq -r '((.pagination.nb_pages // 1)|floor)' 2>/dev/null); nb_pages=${nb_pages:-1}
  page=$((page+1))
done

total=$(wc -l < "$RAW")
echo "# Pulled $total programs across $((page-1)) page(s)" >&2

# Rank: bounty-paying + live, sorted by reward ceiling desc then fewest reports
# then fastest first-response. Columns mirror h1-rank-programs.sh (a leading
# sort key, my-saturation proxy, status, handle/slug, name).
jq -rs '
  map(select(.bounty == true and (.disabled // false | not) and (.archived // false | not)))
  | map(. + { _commerce: (
      ((.title // "") + " " + (.slug // ""))
      | test("checkout|cart|coupon|payment|marketplace|booking|order|shop|commerce"; "i")
    ) })
  | sort_by([
      (if ._commerce then 0 else 1 end),
      (-((.bounty_reward_max // 0) | tonumber? // 0)),
      ((.reports_count // 999999) | tonumber? // 999999),
      ((.average_first_response_time // 999) | tonumber? // 999)
    ])
  | .[]
  | [ ((.bounty_reward_max // 0) | tostring),
      ((.reports_count // 0) | tostring),
      ((.scopes_count // 0) | tostring),
      ((.average_first_response_time // "n/a") | tostring),
      (if .public then "public" else "private" end),
      (if ._commerce then "COMMERCE" else "" end),
      .slug,
      .title ]
  | @tsv
' "$RAW" | (echo -e "MAX_REWARD\tREPORTS\tSCOPES\tFIRST_RESP_D\tVISIBILITY\tCOMMERCE\tSLUG\tNAME"; cat) | column -t -s $'\t'

rm -f "$RAW"
