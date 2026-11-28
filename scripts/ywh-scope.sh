#!/usr/bin/env bash
# ywh-scope.sh <program-slug>
#
# Given a YesWeHack program slug, pull its in-scope assets + policy via the YWH
# REST API and write targets/<slug>/SCOPE.txt + PROGRAM.md, ready for the
# scope-gate and target-modeler. Mirrors scripts/h1-scope.sh exactly. Read-only
# against api.yeswehack.com. NEVER prints any credential.
#
# API contract (verified live + from yeswehack/YesWeBurp source):
#   host            api.yeswehack.com (HTTPS)
#   list            GET /programs?page=N
#                     -> {items:[{title,slug,...}], pagination:{nb_pages,...}}
#   detail          GET /programs/<slug>
#                     -> {scopes:[{scope,scope_type,asset_value}],
#                         out_of_scope:[...], qualifying_vulnerability:[...],
#                         non_qualifying_vulnerability:[...], rules_html, public,
#                         vdp, bounty*, reward_grid_*, account_access_html, ...}
#   auth            Authorization: Bearer <JWT|PAT>  (omit header for public progs)
#
# Auth (preferred): a Personal Access Token (PAT). Set in the secrets file:
#   ~/.config/gnoc/secrets.env  (chmod 600, outside the workspace)
#     YWH_API_TOKEN=<personal access token from the YWH platform>
# Auth (fallback, email/password[/TOTP] -> short-lived JWT):
#     YWH_EMAIL=<account email>
#     YWH_PASSWORD=<account password>
#     YWH_TOTP=<6-digit current TOTP>   # only if 2FA / "Secured" program
# Public programs need no token; private/secured ones do.
set -u

SLUG="${1:-}"
[ -z "$SLUG" ] && { echo "usage: ywh-scope.sh <program-slug>" >&2; exit 1; }

SECRETS="$HOME/.config/gnoc/secrets.env"
[ -f "$SECRETS" ] && { # shellcheck disable=SC1090
  . "$SECRETS"; }
command -v jq   >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
OUT="$ROOT/targets/$SLUG"
mkdir -p "$OUT"
API="https://api.yeswehack.com"
UA="ywh-onboard/1.0"

YWH_API_TOKEN="${YWH_API_TOKEN:-}"
YWH_EMAIL="${YWH_EMAIL:-}"
YWH_PASSWORD="${YWH_PASSWORD:-}"
YWH_TOTP="${YWH_TOTP:-}"

# --- 1. obtain a bearer token (PAT direct, or email/password[/TOTP] -> JWT) ---
# The token may stay empty: the public program list/detail endpoints answer
# unauthenticated. Private/secured programs return an API error without one.
BEARER=""
if [ -n "$YWH_API_TOKEN" ]; then
  BEARER="$YWH_API_TOKEN"
elif [ -n "$YWH_EMAIL" ] && [ -n "$YWH_PASSWORD" ]; then
  login=$(curl -s --max-time 25 -X POST "$API/login" \
            -H 'Content-Type: application/json' -H "User-Agent: $UA" \
            --data "$(jq -nc --arg e "$YWH_EMAIL" --arg p "$YWH_PASSWORD" \
                       '{email:$e,password:$p}')")
  totp_token=$(echo "$login" | jq -r '.totp_token // empty')
  if [ -n "$totp_token" ]; then
    if [ -z "$YWH_TOTP" ]; then
      echo "NEEDS: the operator please add YWH_TOTP (current 6-digit code) to $SECRETS - this program requires 2FA login" >&2
      exit 3
    fi
    otp=$(curl -s --max-time 25 -X POST "$API/account/totp" \
            -H 'Content-Type: application/json' -H "User-Agent: $UA" \
            --data "$(jq -nc --arg t "$totp_token" --arg c "$YWH_TOTP" \
                       '{token:$t,code:$c}')")
    BEARER=$(echo "$otp" | jq -r '.token // empty')
  else
    BEARER=$(echo "$login" | jq -r '.token // empty')
  fi
  [ -z "$BEARER" ] && { echo "YWH login failed (check YWH_EMAIL/YWH_PASSWORD/YWH_TOTP in $SECRETS). Token was never printed." >&2; exit 2; }
fi

ywh_get() { # ywh_get <path>  -> body on stdout
  if [ -n "$BEARER" ]; then
    curl -s --max-time 30 -H "User-Agent: $UA" -H "Authorization: Bearer $BEARER" "$API$1"
  else
    curl -s --max-time 30 -H "User-Agent: $UA" "$API$1"
  fi
}

# --- 2. program detail ------------------------------------------------------
prog=$(ywh_get "/programs/$SLUG")
[ -z "$prog" ] && { echo "empty response from YWH API (network/token) - refusing to write an empty SCOPE.txt" >&2; exit 2; }
if echo "$prog" | jq -e '.code? // .message? // empty' >/dev/null 2>&1 \
   && ! echo "$prog" | jq -e '.scopes? // empty' >/dev/null 2>&1; then
  msg=$(echo "$prog" | jq -r '.message // "unknown"')
  echo "API error for slug '$SLUG': $msg" >&2
  if [ -z "$BEARER" ]; then
    echo "NEEDS: the operator please add YWH_API_TOKEN (or YWH_EMAIL/YWH_PASSWORD[/YWH_TOTP]) to $SECRETS - this program is private/secured and needs auth" >&2
  fi
  exit 2
fi

# --- 3. SCOPE.txt: host-like scope types, then an OOS divider ---------------
# Host-like YWH scope_type values: web-application, wildcard, api, other,
# application. Mobile-application-* are package/store ids (non-host) -> OOS list.
# Never clobber a hand-annotated SCOPE.txt: write the fresh pull to SCOPE.txt.new if one exists.
DEST="$OUT/SCOPE.txt"
if [ -s "$DEST" ]; then
  DEST="$OUT/SCOPE.txt.new"
  echo "NOTE: $OUT/SCOPE.txt exists -> writing fresh pull to SCOPE.txt.new (diff + merge to keep manual annotations)." >&2
fi
{
  echo "# $SLUG - auto-pulled from YesWeHack API (in-scope scopes only)"
  echo "# VERIFY against the live program page before probing. Source: api.yeswehack.com/programs/$SLUG"
  echo "$prog" | jq -r '
    .scopes[]?
    | select(.scope_type | test("web-application|wildcard|api|^other$|^application$"))
    | .scope' \
    | sed -E 's#^https?://##; s#/+$##; s#/.*$##' | sort -u
  echo ""
  echo "# === OUT OF SCOPE (explicit out_of_scope + non-host scope types) ==="
  echo "$prog" | jq -r '.out_of_scope[]? | "# OOS " + .' 2>/dev/null | sort -u
  echo "$prog" | jq -r '
    .scopes[]?
    | select(.scope_type | test("web-application|wildcard|api|^other$|^application$") | not)
    | "# " + .scope_type + " " + .scope' 2>/dev/null | sort -u
} > "$DEST"

# --- 4. PROGRAM.md: policy, rules, qualifying vulns, reward info ------------
{
  echo "# $SLUG - program rules (auto-pulled from YesWeHack API)"
  echo
  echo "## Submission state / bounties"
  echo "$prog" | jq -r '
    "public: \(.public // "?")",
    "vdp: \(.vdp // "?")",
    "bounty: \(.bounty // "?")",
    "bounty_reward_min: \(.bounty_reward_min // "?")",
    "bounty_reward_max: \(.bounty_reward_max // "?")",
    "disabled: \(.disabled // "?")",
    "archived: \(.archived // "?")",
    "vpn_active: \(.vpn_active // .restricted_ips // "?")",
    "reports_count: \(.reports_count // "?")"' 2>/dev/null
  echo
  echo "## Reward grid (default)"
  echo "$prog" | jq -r '(.reward_grid_default // {}) | to_entries[] | "  \(.key): \(.value)"' 2>/dev/null
  echo
  echo "## Qualifying vulnerabilities"
  echo "$prog" | jq -r '.qualifying_vulnerability[]? | "- " + .' 2>/dev/null
  echo
  echo "## Non-qualifying vulnerabilities"
  echo "$prog" | jq -r '.non_qualifying_vulnerability[]? | "- " + .' 2>/dev/null
  echo
  echo "## Account access"
  echo "$prog" | jq -r '.account_access // .account_access_html // "none documented via API"' 2>/dev/null
  echo
  echo "## Rules"
  echo "$prog" | jq -r '.rules // .rules_html // "rules not exposed - read the live program page"' 2>/dev/null
} > "$OUT/PROGRAM.md"

CNT=$(grep -cvE '^#|^$' "$DEST" 2>/dev/null); CNT=${CNT:-0}
echo "wrote $DEST ($CNT in-scope host lines) and $OUT/PROGRAM.md"
echo "next: review SCOPE.txt, then model the target (target-modeler) and hunt. No credential was printed."
