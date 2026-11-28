#!/usr/bin/env bash
# h1-scope.sh <program-handle>
#
# Given just a HackerOne program handle, pull its in-scope assets + policy via
# the H1 hacker API and write targets/<handle>/SCOPE.txt + PROGRAM.md, ready for
# the scope-gate and target-modeler. Read-only against the API. NEVER prints the
# token.
#
# Token store (chmod 600, outside the workspace so it never syncs/commits):
#   ~/.config/gnoc/secrets.env  with:
#     HACKERONE_HANDLE=researcher
#     HACKERONE_API_TOKEN=<your api token>   (hackerone.com/settings/api_token)
# H1 API auth is Basic: username = your H1 handle, password = the API token.
set -u

HANDLE="${1:-}"
[ -z "$HANDLE" ] && { echo "usage: h1-scope.sh <program-handle>" >&2; exit 1; }

SECRETS="$HOME/.config/gnoc/secrets.env"
[ -f "$SECRETS" ] || { echo "no secrets file at $SECRETS (create it, chmod 600)" >&2; exit 1; }
# shellcheck disable=SC1090
# ponytail: grep-extract only the 2 vars we need; full-source dies under set -u
# when another secrets line holds a literal $N (e.g. a password with $8).
HACKERONE_HANDLE=$(grep -E '^HACKERONE_HANDLE=' "$SECRETS" | head -1 | cut -d= -f2- | tr -d '"'"'"'')
HACKERONE_API_TOKEN=$(grep -E '^HACKERONE_API_TOKEN=' "$SECRETS" | head -1 | cut -d= -f2- | tr -d '"'"'"'')
: "${HACKERONE_HANDLE:?set HACKERONE_HANDLE in $SECRETS}"
: "${HACKERONE_API_TOKEN:?set HACKERONE_API_TOKEN in $SECRETS}"
command -v jq >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
OUT="$ROOT/targets/$HANDLE"
mkdir -p "$OUT"
AUTH="$HACKERONE_HANDLE:$HACKERONE_API_TOKEN"
API="https://api.hackerone.com/v1/hackers"

# --- 1. structured scopes (paginated) --------------------------------------
ASSETS=$(mktemp)
url="$API/programs/$HANDLE/structured_scopes?page%5Bsize%5D=100"
http_ok=0
while [ -n "$url" ]; do
  resp=$(curl -s -u "$AUTH" -H 'Accept: application/json' "$url")
  [ -z "$resp" ] && { echo "empty response (network/token/CF block) - refusing to write an empty SCOPE.txt" >&2; exit 2; }
  # auth / handle error guard (never prints token)
  if echo "$resp" | jq -e '.errors? // empty' >/dev/null 2>&1; then
    echo "API error for $HANDLE (check token, API access, and that you are a member of the program):" >&2
    echo "$resp" | jq -r '.errors[]?.detail // .errors[]?.title // "unknown"' >&2
    exit 2
  fi
  # Carry eligible_for_bounty + max_severity through (fix 2026-10-02): without them the
  # SELECTION GATE cannot tell a cash asset from a no-bounty one, and a whole program was
  # selected this session whose every FRESH asset turned out to be [no-bounty].
  echo "$resp" | jq -r '.data[]? | select(.attributes.eligible_for_submission==true)
        | "\(.attributes.asset_type)\t\(.attributes.asset_identifier)\t\(if .attributes.eligible_for_bounty then "bounty" else "no-bounty" end)\t\(.attributes.max_severity // "?")"' >> "$ASSETS"
  url=$(echo "$resp" | jq -r '.links.next // empty')
  http_ok=1
done
[ "$http_ok" = 1 ] || { echo "no response from API" >&2; exit 2; }

# --- 2. SCOPE.txt: host-like identifiers, then an OOS divider ---------------
# Never clobber a hand-annotated SCOPE.txt: if one exists, write the fresh pull to
# SCOPE.txt.new so manual scope notes survive (diff + merge by hand).
DEST="$OUT/SCOPE.txt"
if [ -s "$DEST" ]; then
  DEST="$OUT/SCOPE.txt.new"
  echo "NOTE: $OUT/SCOPE.txt exists -> writing fresh pull to SCOPE.txt.new (diff + merge to keep manual annotations)." >&2
fi
{
  echo "# $HANDLE - auto-pulled from HackerOne API (eligible_for_submission=true only)"
  # Do NOT assert a header NAME here. This line used to read "Header X-HackerOne: <handle>", a name
  # that appears in no policy, and programs differ: program-0's says you "must" send
  # `X-HackerOne-Handle`. On 2026-10-27 two lanes sent the wrong name on that program - their probes
  # were not attributable - and this generated comment is one of the two places that told them so.
  # The name is per-program, so point at the policy instead of guessing for every program at once.
  echo "# VERIFY against the live policy page before probing."
  echo "# IDENTIFICATION HEADER: grep PROGRAM.md for the exact name this program requires --"
  echo "#   grep -i 'x-hackerone' $OUT/PROGRAM.md"
  echo "#   handle value = \$HACKERONE_HANDLE from ~/.config/gnoc/secrets.env (currently: $HACKERONE_HANDLE)"
  echo "#"
  echo "# READ THIS BEFORE CONCLUDING A PROGRAM HAS NOTHING TO HUNT:"
  echo "# the OUT OF SCOPE divider below carries TWO different things mixed together --"
  echo "#   (a) genuinely ineligible assets, and"
  echo "#   (b) BOUNTY-ELIGIBLE assets whose type is not a host (SOURCE_CODE, OTHER,"
  echo "#       APPLE_STORE_APP_ID, GOOGLE_PLAY_APP_ID, CIDR, hardware, ...)."
  echo "# Type (b) is listed there only because this host-based gate cannot check a"
  echo "# non-host identifier -- NOT because it is out of scope. A program whose only"
  echo "# in-scope asset is a git repo will therefore look empty here."
  echo "# ALWAYS confirm the real in-scope set in PROGRAM.md before skipping a program."
  echo "# Do not move a type (b) line above the divider: the divider is what stops the"
  echo "# gate allowlisting everything below it."
  if awk -F'\t' '$1 ~ /URL|API/ && $2 ~ /:\/\/[^\/]+\/./ && $2 !~ /:\/\/[^\/]+\/\*?$/' "$ASSETS" | grep -q .; then
    echo "#"
    echo "# !! PATH-RESTRICTED PROGRAM. The assets below are in scope ONLY at these exact paths."
    echo "#    The host alone is NOT in scope. The scope-gate can only match hostnames, so it"
    echo "#    CANNOT enforce this for you - you must honour it yourself on every probe."
    awk -F'\t' '$1 ~ /URL|API/ && $2 ~ /:\/\/[^\/]+\/./ && $2 !~ /:\/\/[^\/]+\/\*?$/ {print "#      " $2}' "$ASSETS" | sort -u
  fi
  # PATH SCOPING (fix 2026-10-02). The previous writer ran 's#/.*$##', which DELETED the path
  # from every asset. A program scoped to three payment paths (program-30: /account/agodacash,
  # /book/, /account/cashback) was therefore recorded as the bare host, telling every agent and
  # every gate that the WHOLE site was in scope. That is a scope-SAFETY defect, not cosmetics:
  # it authorises out-of-scope testing. The host is still emitted on its own column because the
  # scope-gate matches hostnames out of a command line and cannot match paths - but the path now
  # rides along in the tag so no reader can miss it, and it is restated in the banner above.
  # ASSET-TYPE vs ASSET-SHAPE (fix 2026-10-03). Routing on the declared type alone filed
  # `OTHER https://api.ring.com/*` under the out-of-scope divider, commented out. Eight
  # bounty-eligible, max=critical production hosts (api, oauth, app, admin, billing, nw,
  # fw, ring.com) were therefore invisible to every agent and hard-blocked by the scope gate.
  # H1 lets a programme file a perfectly ordinary host under OTHER, so the identifier SHAPE
  # decides, not the label: anything that parses as a URL or a bare hostname is a host asset.
  # Prose assets ("Intellectual Property on Public Domains") contain spaces and stay below.
  awk -F'\t' '
    function host_like(t, id) {
      # A real hostname never contains a space, so this MUST be tested before the declared-type
      # check below. Without it, a programme that files PROSE under a host type has that prose
      # promoted above the divider, and the scope gate reads its first token as a host - which
      # can grant an entire apex plus every subdomain, far wider than the programme granted.
      if (id ~ / /) return 0
      if (t ~ /URL|WILDCARD|DOMAIN|IP_ADDRESS|CIDR|API/) return 1
      # a declared non-host type is never promoted, whatever its identifier looks like.
      # This matters: an app id like com.paypal.merchant is host-SHAPED and is not a host.
      if (t ~ /APP_ID|HARDWARE|SOURCE_CODE|CPE|EXECUTABLE|AI_MODEL|SMART_CONTRACT|OTHER_ASSET/) return 0
      if (id ~ / /) return 0
      if (id ~ /^https?:\/\/[^\/]+\./) return 1
      # bare hostname, but reject reverse-DNS package names (com.foo.bar, io.foo.bar)
      if (id ~ /^(com|org|net|io|co|app|dev)\./) return 0
      if (id ~ /^[A-Za-z0-9*][A-Za-z0-9*._-]*\.[A-Za-z]{2,}(\/|$)/) return 1
      return 0
    }
    host_like($1, $2) {
      id = $2
      sub(/^https?:\/\//, "", id)
      host = id; sub(/\/.*$/, "", host)
      path = ""
      if (match(id, /\//)) path = substr(id, RSTART)
      tag = "[" $3 "; max=" $4
      # "/" and "/*" are the WHOLE host, not a restriction - flagging them would send a
      # worker chasing a path constraint that does not exist (seen on ring: *.blinkforhome.com//*).
      if (path != "" && path != "/" && path != "/*") tag = tag "; PATH-ONLY: " path
      tag = tag "]"
      # an OTHER-typed host is reported as the URL it actually is, with its origin kept
      type = ($1 ~ /URL|WILDCARD|DOMAIN|IP_ADDRESS|CIDR|API/) ? $1 : "URL"
      if (type == "URL" && $1 !~ /URL/) tag = tag "  # filed by the programme as " $1
      printf "%-14s %s\t%s\n", type, host, tag
    }' "$ASSETS" | sort -u
  echo ""
  echo "# === OUT OF SCOPE (non-host asset types below; see PROGRAM.md) ==="
  awk -F'\t' '
    function host_like(t, id) {
      # A real hostname never contains a space, so this MUST be tested before the declared-type
      # check below. Without it, a programme that files PROSE under a host type has that prose
      # promoted above the divider, and the scope gate reads its first token as a host - which
      # can grant an entire apex plus every subdomain, far wider than the programme granted.
      if (id ~ / /) return 0
      if (t ~ /URL|WILDCARD|DOMAIN|IP_ADDRESS|CIDR|API/) return 1
      # a declared non-host type is never promoted, whatever its identifier looks like.
      # This matters: an app id like com.paypal.merchant is host-SHAPED and is not a host.
      if (t ~ /APP_ID|HARDWARE|SOURCE_CODE|CPE|EXECUTABLE|AI_MODEL|SMART_CONTRACT|OTHER_ASSET/) return 0
      if (id ~ / /) return 0
      if (id ~ /^https?:\/\/[^\/]+\./) return 1
      # bare hostname, but reject reverse-DNS package names (com.foo.bar, io.foo.bar)
      if (id ~ /^(com|org|net|io|co|app|dev)\./) return 0
      if (id ~ /^[A-Za-z0-9*][A-Za-z0-9*._-]*\.[A-Za-z]{2,}(\/|$)/) return 1
      return 0
    }
    !host_like($1, $2) {print "# " $1 " " $2 "\t[" $3 "; max=" $4 "]"}' "$ASSETS" | sort -u
} > "$DEST"

# --- 3. program policy / rules ---------------------------------------------
prog=$(curl -s -u "$AUTH" -H 'Accept: application/json' "$API/programs/$HANDLE")
{
  echo "# $HANDLE - program rules (auto-pulled from H1 API)"
  echo
  echo "## Submission state / bounties"
  echo "$prog" | jq -r '(.data.attributes // .attributes) | "offers_bounties: \(.offers_bounties // "?")\nsubmission_state: \(.submission_state // "?")"' 2>/dev/null
  echo
  echo "## Policy"
  echo "$prog" | jq -r '(.data.attributes // .attributes).policy // "policy not exposed via hacker API - read the live program page"' 2>/dev/null
} > "$OUT/PROGRAM.md"

rm -f "$ASSETS"
CNT=$(grep -cvE '^#|^$' "$DEST" 2>/dev/null); CNT=${CNT:-0}
echo "wrote $DEST ($CNT in-scope host lines) and $OUT/PROGRAM.md"
echo "next: review SCOPE.txt, then model the target (target-modeler) and hunt. Token was never printed."
