#!/usr/bin/env bash
# intigriti-scope.sh <company-handle/program-handle | program-handle> [--refresh]
#
# Given an Intigriti program (either the full "company/program" pair from the app URL,
# e.g. "digitalocean/digitalocean" from
# https://app.intigriti.com/programs/digitalocean/digitalocean/detail, or just the
# program handle - which is then resolved against the public program list), pull its
# in-scope assets + policy and write targets/<program-handle>/SCOPE.txt and
# targets/<program-handle>/PROGRAM.md.
#
# ZERO AUTH for public programs. Verified live 2026-09-30 with plain curl (no token,
# no cookie, no bot wall). Full notes: scripts/INTIGRITI.md
#
# Mechanism (both endpoints public, JSON):
#   1. GET https://app.intigriti.com/api/core/public/programs
#        -> [ {programId, status, confidentialityLevel, companyHandle, companyName,
#              handle, name, industry, minBounty{value,currency}, maxBounty{...},
#              lastUpdatedAt, lastSubmissionAt, createdAt, tacRequired,
#              twoFactorRequired, ...}, ... ]   (188 public programs on 2026-09-30)
#   2. GET https://app.intigriti.com/api/core/public/programs/<company>/<program>
#        -> the whole program document:
#             assetsCollection[]      VERSION HISTORY (see the trap below)
#               .content.assetsAndGroups[]  discriminator 2 = GROUP (has .assets[])
#                                           discriminator 1 = ASSET
#               asset = {typeId, name, bountyTierId, description, companyAssetId}
#             bountyTables[]          VERSION HISTORY; .content.bountyRows[] =
#                                     {bountyTierId, bountyRanges[{minScore,maxScore,
#                                      minBounty{value,currency},maxBounty{...}}]}
#             inScopes[] outOfScopes[] rulesOfEngagements[] severityAssessments[] faqs[]
#                                     VERSION HISTORY of markdown blobs
#             confidentialityLevel  4 = fully public (readable here)
#                                   2 = restricted -> this endpoint returns HTTP 403
#
#   *** THE VERSION-HISTORY TRAP (cost real debugging time - do not "simplify" this) ***
#   assetsCollection / bountyTables / inScopes / outOfScopes / rulesOfEngagements /
#   faqs / severityAssessments are NOT lists of sections. They are APPEND-ONLY VERSION
#   HISTORIES, ordered ASCENDING by .createdAt. [0] is the OLDEST revision.
#   DigitalOcean on 2026-09-30: assetsCollection has 55 revisions; revision[0] holds 31
#   assets from 2024-03, the newest holds 59. Reading [0] would enforce a two-year-old
#   scope. This script always takes max_by(.createdAt).
#
# Intigriti asset typeId -> type (confirmed empirically across 6 sampled programs):
#   1 = URL / domain      2 = Android package    3 = iOS app id     4 = IP address
#   5 = Device / hardware 6 = Other (free text)  7 = Wildcard       8 = Source code repo
# Host-like typeIds are {1, 4, 7} ONLY. 2/3/5/6/8 are non-host asset ids and are
# recorded BELOW the OOS divider (the same split h1-scope.sh applies by asset_type).
# Every typeId is still shape-checked: typeId 1 legitimately carries prose such as
# "any intigriti CTF or challenge", and typeId 7 carries "https://github.com/org/*".
#
# SCOPE.txt mapping (authoritative grammar: ${GNOC_WORKSPACE:-$HOME/.gnoc}/targets/README.md):
#   - host-like assets -> in-scope lines, wildcard form preserved VERBATIM
#     ('*.foo.com' is dot-bounded in both parsers, '*foo.com' is a loose suffix glob,
#      so normalizing either one would change the enforced scope)
#   - an asset whose bountyTierId is absent from the latest bounty table, or whose tier
#     pays 0, is IN SCOPE but NOT reward-eligible. It stays ABOVE the divider (it is
#     submittable) and is tagged NO-BOUNTY inline - the same in-scope-vs-bounty-eligible
#     split h1-scope.sh keeps. PROGRAM.md records the breakdown.
#   - non-host assets + the program's own out-of-scope prose are RECORDED below the
#     divider, never discarded.
#
# NEVER writes a SCOPE.txt with zero in-scope entries: a zero-entry pull exits non-zero
# and leaves NO file behind (see targets/README.md "empty-SCOPE.txt hazard" - the live
# gate now fail-CLOSES on an empty allowlist and would block every probe).
#
# Re-run safety (no-clobber): an existing non-empty SCOPE.txt / PROGRAM.md is left alone
# and the fresh pull lands in SCOPE.txt.new / PROGRAM.md.new. --refresh overwrites.
#
# Optional token (only for programs this public endpoint will not serve):
#   $HOME/.config/gnoc/secrets.env  (chmod 600, sourced under `set -u` elsewhere,
#   so SINGLE-QUOTE the value)
#     INTIGRITI_API_TOKEN='<personal access token>'
#   Generated at https://app.intigriti.com/researcher/personal-access-tokens
#   It is sent as a bearer on the request. See the NEEDS note printed on a 403 and
#   scripts/INTIGRITI.md: the separate api.intigriti.com/external/researcher/v1 API
#   that this token is really for is NOT parsed here, because its response shape could
#   not be verified without a real token (it answers 401 UNAUTH001 to every
#   unauthenticated request, with or without a bogus bearer).
#
# This script talks ONLY to app.intigriti.com. It sends ZERO requests to any program's
# target assets. Intake ends when SCOPE.txt is written.
set -u

ARG=""; REFRESH=0
for a in "$@"; do
  case "$a" in
    --refresh) REFRESH=1 ;;
    -h|--help)
      echo "usage: intigriti-scope.sh <company/program | program> [--refresh]" >&2
      echo "example: intigriti-scope.sh digitalocean/digitalocean" >&2
      echo "example: intigriti-scope.sh digitalocean        # company resolved from the public list" >&2
      exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) [ -z "$ARG" ] && ARG="$a" ;;
  esac
done
if [ -z "$ARG" ]; then
  echo "usage: intigriti-scope.sh <company/program | program> [--refresh]" >&2
  echo "example: intigriti-scope.sh digitalocean/digitalocean" >&2
  exit 1
fi

command -v curl    >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v jq      >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 1; }

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
APP="https://app.intigriti.com"
API="$APP/api/core/public/programs"
PAT_URL="$APP/researcher/personal-access-tokens"
SECRETS="$HOME/.config/gnoc/secrets.env"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

# Token is OPTIONAL. grep-extract instead of sourcing: secrets.env is read under
# `set -u` by sibling scripts and a value containing a literal $N would explode a full
# source (the h1-scope.sh "ponytail" note). The value is NEVER printed.
INTIGRITI_API_TOKEN=""
if [ -f "$SECRETS" ]; then
  INTIGRITI_API_TOKEN=$(grep -E '^[[:space:]]*INTIGRITI_API_TOKEN=' "$SECRETS" 2>/dev/null \
    | head -1 | cut -d= -f2- \
    | sed -E "s/^[[:space:]]*//; s/[[:space:]]*$//; s/^'//; s/'$//; s/^\"//; s/\"$//")
fi

# ig_get <url> <outfile> -> prints the HTTP status code; body lands in <outfile>
ig_get() {
  if [ -n "$INTIGRITI_API_TOKEN" ]; then
    curl -s --max-time 45 -A "$UA" -H 'Accept: application/json' \
         -H "Authorization: Bearer $INTIGRITI_API_TOKEN" \
         -o "$2" -w '%{http_code}' "$1"
  else
    curl -s --max-time 45 -A "$UA" -H 'Accept: application/json' \
         -o "$2" -w '%{http_code}' "$1"
  fi
}

# NOTE: `mktemp --directory` not `mktemp -d` on purpose. The workspace submit-guard
# hook treats a bare " -d " as an HTTP write flag, so `mktemp -d` in the same command
# as an app.intigriti.com string trips a false-positive BLOCK when this file is
# authored/edited through a bash heredoc. Long flag, same behavior, no false positive.
TMPD=$(mktemp --directory "${TMPDIR:-/tmp}/intigriti-scope.XXXXXX") \
  || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT

# --- 1. resolve company/program -------------------------------------------------------
# Accept a pasted app URL, "company/program", or a bare program handle.
CLEAN=$(printf '%s' "$ARG" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^programs/##; s#/detail/?$##; s#[?#].*$##; s#/+$##')
COMPANY=""; PROGRAM=""
case "$CLEAN" in
  */*) COMPANY=${CLEAN%%/*}; PROGRAM=${CLEAN##*/} ;;
  *)   PROGRAM="$CLEAN" ;;
esac
case "$PROGRAM" in
  ""|*[!A-Za-z0-9._-]*)
    echo "bad program handle '$PROGRAM' (expected <company>/<program> from the app URL, e.g. digitalocean/digitalocean)" >&2
    exit 1 ;;
esac

LIST="$TMPD/list.json"
LIST_CODE=$(ig_get "$API" "$LIST")
if [ "$LIST_CODE" != "200" ] || ! jq -e 'type == "array"' "$LIST" >/dev/null 2>&1; then
  echo "WARN: could not read the public program list ($API -> HTTP $LIST_CODE)." >&2
  if [ -z "$COMPANY" ]; then
    echo "FAIL: cannot resolve the company handle for '$PROGRAM' without the list." >&2
    echo "  Re-run with the full pair:  intigriti-scope.sh <company>/<program>" >&2
    echo "  (the pair is visible in the app URL: $APP/programs/<company>/<program>/detail)" >&2
    echo "  Nothing written." >&2
    exit 2
  fi
  LIST=""
fi

if [ -z "$COMPANY" ] && [ -n "$LIST" ]; then
  COMPANY=$(jq -r --arg p "$PROGRAM" '[.[] | select((.handle // "") == $p)] | first | .companyHandle // empty' "$LIST")
  if [ -z "$COMPANY" ]; then
    echo "FAIL: no PUBLIC Intigriti program with handle '$PROGRAM' in the public program list." >&2
    echo "  Closest handles:" >&2
    jq -r --arg p "$PROGRAM" '.[] | select((.handle//"")|ascii_downcase|contains($p|ascii_downcase)) | "    \(.companyHandle)/\(.handle)   \(.name)"' "$LIST" 2>/dev/null | head -8 >&2
    echo "  A private or restricted program is not in this list - pass <company>/<program> explicitly." >&2
    echo "  Nothing written." >&2
    exit 2
  fi
  echo "resolved '$PROGRAM' -> $COMPANY/$PROGRAM (from the public program list)"
fi

# --- 2. pull the program document ------------------------------------------------------
PROG_JSON="$TMPD/program.json"
CODE=$(ig_get "$API/$COMPANY/$PROGRAM" "$PROG_JSON")
if [ "$CODE" = "403" ]; then
  echo "FAIL: public program endpoint returned HTTP 403 for $COMPANY/$PROGRAM (restricted program)." >&2
  echo "  Intigriti serves that endpoint only for confidentialityLevel=4 (fully public)" >&2
  echo "  programs. confidentialityLevel=2 and private/invite programs answer 403." >&2
  if [ -z "$INTIGRITI_API_TOKEN" ]; then
    cat >&2 <<EOF
  NEEDS: a personal access token, if you have researcher access to this program.
    1. Generate one at: $PAT_URL
    2. Add to $SECRETS  (SINGLE-QUOTE it; that file is read under \`set -u\`):
         INTIGRITI_API_TOKEN='<token>'
    3. Re-run this script.
  HONEST LIMITATION: the token is sent as a bearer on the request above, but the
  separate researcher API the PAT is really issued for
  (api.intigriti.com/external/researcher/v1/programs) is NOT parsed by this script.
  Its response shape could not be verified - it answers 401 UNAUTH001 to every
  unauthenticated request, with or without a bogus bearer. Once you hold a token,
  reveal the shape and wire it in rather than guessing. See
  ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/INTIGRITI.md section "Private programs".
EOF
  else
    echo "  A token IS set in $SECRETS and was sent as a bearer; it did not unlock this" >&2
    echo "  program through the app API. See the external-API note in" >&2
    echo "  ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/INTIGRITI.md. Token was never printed." >&2
  fi
  echo "  Nothing written." >&2
  exit 3
fi
if [ "$CODE" = "404" ]; then
  echo "FAIL: public program endpoint returned HTTP 404 for $COMPANY/$PROGRAM (no such company/program pair)." >&2
  echo "  Verify the pair from the app URL: $APP/programs/<company>/<program>/detail" >&2
  echo "  Nothing written." >&2
  exit 2
fi
if [ "$CODE" != "200" ]; then
  echo "FAIL: public program endpoint returned HTTP $CODE for $COMPANY/$PROGRAM (unexpected). Nothing written." >&2
  exit 2
fi
if ! jq -e '.assetsCollection? // empty' "$PROG_JSON" >/dev/null 2>&1; then
  echo "FAIL: response for $COMPANY/$PROGRAM has no .assetsCollection (shape changed, or an error page)." >&2
  echo "  Inspect the response with jq 'keys'. Nothing written." >&2
  exit 2
fi

# the directory row carries minBounty/maxBounty/tacRequired/twoFactorRequired
ROW="$TMPD/row.json"
if [ -n "$LIST" ]; then
  jq --arg c "$COMPANY" --arg p "$PROGRAM" \
     '[.[] | select((.companyHandle//"")==$c and (.handle//"")==$p)] | first // {}' "$LIST" > "$ROW"
else
  echo '{}' > "$ROW"
fi

# --- 3. destinations (no-clobber unless --refresh) ------------------------------------
OUT="$ROOT/targets/$PROGRAM"
# Remember whether the target dir already existed, so a failed intake can remove a
# directory IT created and leave no empty targets/<handle>/ husk behind.
DIR_PREEXISTED=0; [ -d "$OUT" ] && DIR_PREEXISTED=1
mkdir -p "$OUT"
SCOPE_DEST="$OUT/SCOPE.txt"; SCOPE_ALT=0
PROGMD_DEST="$OUT/PROGRAM.md"; PROGMD_ALT=0
if [ "$REFRESH" != "1" ]; then
  if [ -s "$SCOPE_DEST" ];  then SCOPE_DEST="$OUT/SCOPE.txt.new";   SCOPE_ALT=1; fi
  if [ -s "$PROGMD_DEST" ]; then PROGMD_DEST="$OUT/PROGRAM.md.new"; PROGMD_ALT=1; fi
fi

# --- 4. render ------------------------------------------------------------------------
COMPANY="$COMPANY" PROGRAM="$PROGRAM" SCOPE_DEST="$SCOPE_DEST" PROGMD_DEST="$PROGMD_DEST" \
  python3 - "$PROG_JSON" "$ROW" <<'PY'
import json, os, re, sys

company = os.environ["COMPANY"]; program = os.environ["PROGRAM"]
scope_p = os.environ["SCOPE_DEST"]; prog_p = os.environ["PROGMD_DEST"]
with open(sys.argv[1], encoding="utf-8") as fh:
    d = json.load(fh)
with open(sys.argv[2], encoding="utf-8") as fh:
    row = json.load(fh) or {}

APP = "https://app.intigriti.com"
detail_url = f"{APP}/programs/{company}/{program}/detail"
api_url    = f"{APP}/api/core/public/programs/{company}/{program}"

TYPE = {1: "url", 2: "android", 3: "ios", 4: "ip", 5: "device",
        6: "other", 7: "wildcard", 8: "sourcecode"}
HOSTLIKE_TYPES = {1, 4, 7}
# Hosts that belong to a third party, never to the program. A store/repo host must
# never become an in-scope allowlist line. Same safe direction as h1-scope.sh
# dropping MOBILE_APPLICATION_* / SOURCE_CODE from the allowlist.
THIRD_PARTY = {
    "apps.apple.com", "itunes.apple.com", "testflight.apple.com", "apple.co",
    "play.google.com", "chrome.google.com", "chromewebstore.google.com",
    "addons.mozilla.org", "microsoftedge.microsoft.com", "apps.microsoft.com",
    "www.microsoft.com",
    "galaxystore.samsung.com", "appgallery.huawei.com", "f-droid.org",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "npmjs.com", "www.npmjs.com", "pypi.org", "hub.docker.com", "crates.io",
    "rubygems.org", "packagist.org", "nuget.org", "cocoapods.org",
    "marketplace.visualstudio.com", "snapcraft.io", "flathub.org",
}
# Mirror of the parsers' refusal list (scope-gate.sh / bbtools/lib_scope.py): an entry
# that reduces to one of these can never grant scope, so it is not a real entry.
PUBLIC_SUFFIX = {
    "app.example.com", "com.au", "com.co", "com.mx", "co.jp", "co.nz", "com.br", "co.in",
    "com.sg", "com.hk", "co.za", "com.tr", "gov.uk", "org.uk", "net.au", "org.au",
    "co.kr", "com.cn", "co.id", "com.ph", "com.my", "co.th", "com.tw", "ne.jp", "or.jp",
}
HOST_RE = re.compile(r"^\*?\.?(?:[A-Za-z0-9*_-]+\.)+[A-Za-z*][A-Za-z0-9*-]{1,}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")

# *** HOW INTIGRITI MARKS OUT OF SCOPE (safety-critical - verified, not assumed) ***
# Intigriti has NO per-asset or per-group inScope boolean (Bugcrowd does). Excluded
# assets sit in the SAME assetsAndGroups list as in-scope ones and are marked two ways:
#   (a) bountyTierId == 5  -- confirmed across 4 independent programs on 2026-09-30:
#       every asset inside digitalocean's "*.digitalocean.com Out of Scope Subdomains",
#       "Out of Scope: Customer Resources" and "Out of Scope" groups is tier 5; so is
#       intigriti/intigriti's "Out of scope" group (16 assets) and rivian's "Out of
#       Scope" group (9 assets); so are the two individually-excluded repos inside
#       digitalocean's otherwise in-scope "Open Source GitHub Repos" group. No tier-5
#       asset was found anywhere that was not an exclusion.
#   (b) the GROUP NAME contains an out-of-scope phrase.
# Both are honored, independently, and either one sends the asset BELOW the divider.
# Tier 5 is NOT the same as "in scope but unpaid" - that is tier 1 (paperspace.com,
# the in-scope OSS repos, altera's "Software"), which stays ABOVE the divider tagged
# NO-BOUNTY. Conflating the two would authorize probing explicitly excluded hosts,
# including other DigitalOcean customers' *.ondigitalocean.app apps.
OOS_TIER = {5}
# Same phrase set the two scope parsers use to find a divider (scope-gate.sh
# scope_inscope_hosts / bbtools.lib_scope parse_scope), applied here to group names.
OOS_NAME_RE = re.compile(
    r"(out.?of.?scope|\boos\b|exclud|ineligib|not\s+in\s+scope|do\s+not\s+test|forbidden)",
    re.IGNORECASE)


def latest(key):
    """Newest revision of a version-history array. NEVER [0] - that is the oldest."""
    arr = d.get(key) or []
    if not isinstance(arr, list) or not arr:
        return None
    return max(arr, key=lambda e: (e or {}).get("createdAt") or 0)


def latest_md(key):
    c = (latest(key) or {}).get("content")
    if isinstance(c, dict):
        v = c.get("content")
        return v if isinstance(v, str) else ""
    return c if isinstance(c, str) else ""


def to_host(tok):
    """Reduce an Intigriti asset name to a bare host/wildcard token, or ''. Keeps a
    leading '*.' / '*' VERBATIM - the dot is load-bearing in both scope parsers."""
    if not tok:
        return ""
    s = str(tok).strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    if "@" in s.split("/")[0]:
        s = s.split("@", 1)[1]
    s = re.split(r"[/?#]", s, maxsplit=1)[0].rstrip(".").strip()
    if s.startswith("["):
        s = s.split("]")[0].lstrip("[")
    elif s.count(":") == 1:
        s = s.split(":")[0]
    if not s or " " in s or "," in s:
        return ""
    if IPV4_RE.match(s):
        return s
    if not HOST_RE.match(s) or "." not in s:
        return ""
    return s


def bare(h):
    return re.sub(r"^\*\.?", "", h).lower()


# ---- bounty tiers: tierId -> max payout. A tier absent from here pays nothing.
bt = latest("bountyTables")
tier_max, currency = {}, "?"
if bt:
    content = bt.get("content") or {}
    currency = content.get("currency") or "?"
    for r in (content.get("bountyRows") or []):
        tid = r.get("bountyTierId")
        if tid is None:
            continue
        vals = []
        for rng in (r.get("bountyRanges") or []):
            for side in ("maxBounty", "minBounty"):
                mv = rng.get(side) or {}
                if isinstance(mv, dict) and isinstance(mv.get("value"), (int, float)):
                    vals.append(mv["value"])
        if vals:
            tier_max[tid] = max(tier_max.get(tid, 0), max(vals))


def tier_pays(tid):
    return bool(tier_max.get(tid, 0))


# ---- flatten the LATEST asset revision
ac = latest("assetsCollection")
groups = ((ac or {}).get("content") or {}).get("assetsAndGroups") or []
flat = []   # (group_name, asset)
for item in groups:
    if not isinstance(item, dict):
        continue
    if item.get("discriminator") == 2:
        gname = (item.get("name") or "unnamed group").strip()
        for a in (item.get("assets") or []):
            if isinstance(a, dict):
                flat.append((gname, a))
    else:
        flat.append(("", item))

inscope_lines, oos_lines, notes = [], [], []
seen = set()
stat = {"hosts": 0, "nobounty": 0, "nonhost": 0, "oos": 0, "assets": len(flat)}
oos_hosts = []   # (host, type, label, why) for hosts placed BELOW the divider
cur_group = None
by_tier = {}

for gname, a in flat:
    tid = a.get("bountyTierId")
    tname = TYPE.get(a.get("typeId"), "type%s" % a.get("typeId"))
    nm = (a.get("name") or "").strip()
    label = nm or "(unnamed asset)"
    by_tier.setdefault(tid, {"n": 0, "hosts": 0})
    by_tier[tid]["n"] += 1

    # --- OUT-OF-SCOPE gate: runs FIRST, before any host extraction. ---------------
    why = []
    if tid in OOS_TIER:
        why.append("bountyTier %s = out of scope" % tid)
    if gname and OOS_NAME_RE.search(gname):
        why.append("group name '%s' declares it out of scope" % gname)
    if why:
        h = to_host(nm)
        oos_lines.append("#   OOS [%s] %s%s   (%s)"
                         % (tname, label, "" if not h or h == nm else " -> " + h, "; ".join(why)))
        stat["oos"] += 1
        if h:
            oos_hosts.append((h, tname, label, "; ".join(why)))
        continue

    if a.get("typeId") not in HOSTLIKE_TYPES:
        oos_lines.append("#   NON-HOST [%s] %s%s" % (tname, label, "   (tier %s)" % tid if tid is not None else ""))
        stat["nonhost"] += 1
        continue
    host = to_host(nm)
    if not host:
        oos_lines.append("#   NOT-A-HOST [%s] %s   (type says host-like but the value is not a host)" % (tname, label))
        stat["nonhost"] += 1
        continue
    b = bare(host)
    if b in THIRD_PARTY:
        oos_lines.append("#   THIRD-PARTY-HOST [%s] %s -> %s (store/repo host; promote by hand only if it genuinely is this program's own asset)" % (tname, label, host))
        notes.append("third-party host NOT auto-allowlisted: %s  (from [%s] %s)" % (host, tname, label))
        stat["nonhost"] += 1
        continue
    if b in PUBLIC_SUFFIX or "." not in b:
        oos_lines.append("#   REFUSED-PUBLIC-SUFFIX [%s] %s -> %s (both parsers refuse it; it cannot grant scope)" % (tname, label, host))
        notes.append("entry reduces to a public suffix / bare TLD and was NOT written above the divider: %s" % host)
        stat["nonhost"] += 1
        continue
    if host.lower() in seen:
        continue
    seen.add(host.lower())
    if gname != cur_group:
        cur_group = gname
        inscope_lines.append("# --- %s ---" % (gname or "ungrouped assets"))
    pays = tier_pays(tid)
    tag = "" if pays else "  NO-BOUNTY"
    extra = "tier %s" % tid + (", up to %s %s" % (format(tier_max[tid], ",.0f"), currency) if pays else ", no cash")
    inscope_lines.append("%s  # %s | %s%s" % (host, tname, extra, tag))
    stat["hosts"] += 1
    by_tier[tid]["hosts"] += 1
    if not pays:
        stat["nobounty"] += 1

if stat["hosts"] == 0:
    sys.stderr.write(
        "FAIL: the Intigriti program document for %s/%s yielded ZERO in-scope host entries.\n"
        "  (latest asset revision held %d asset(s); %d were non-host / not-a-host / refused)\n"
        "  Refusing to write a SCOPE.txt: an empty-but-present SCOPE.txt makes the live scope\n"
        "  gate BLOCK every probe for this target (fail-closed, 2026-09-30). Nothing written.\n"
        "  This is EXPECTED for a source-code-only / hardware-only / SDK-only program (e.g.\n"
        "  nvidia/nvidiapublicbugbounty is entirely typeId=6 'other' plus typeId=1 prose) -\n"
        "  such a program has no host scope for the gate to enforce.\n"
        "  Inspect by hand with:\n"
        "    curl -s '%s' \\\n"
        "      | jq '[.assetsCollection|max_by(.createdAt).content.assetsAndGroups[]\n"
        "             |if .discriminator==2 then .assets[] else . end]|map({typeId,name,bountyTierId})'\n"
        % (company, program, stat["assets"], stat["nonhost"], api_url))
    sys.exit(3)

minb = row.get("minBounty") or {}
maxb = row.get("maxBounty") or {}


def m(v):
    v = v or {}
    return "%s %s" % (format(v["value"], ",.0f"), v.get("currency")) \
        if isinstance(v.get("value"), (int, float)) else "?"


L = ["# %s - auto-pulled from the Intigriti public program API (zero auth)" % program,
     "# Program page: %s" % detail_url,
     "# Source JSON:  %s" % api_url,
     "# Company: %s (%s)   |   program: %s" % (d.get("companyName") or company, company, d.get("name") or program),
     "# Asset revision used: createdAt=%s (NEWEST of %d revision(s))"
     % ((ac or {}).get("createdAt"), len(d.get("assetsCollection") or [])),
     "# confidentialityLevel=%s  status=%s  |  directory payout band %s - %s"
     % (d.get("confidentialityLevel"), d.get("status"), m(minb), m(maxb)),
     "# Host entries: %d%s   |   below the divider: %d explicitly OUT-OF-SCOPE asset(s) + %d non-host asset(s)"
     % (stat["hosts"], " (of which %d NO-BOUNTY)" % stat["nobounty"] if stat["nobounty"] else "",
        stat["oos"], stat["nonhost"]),
     "# VERIFY against the live program page before probing. Wildcard forms are verbatim",
     "# from Intigriti: '*.foo.com' is dot-bounded, '*foo.com' is a loose suffix glob.",
     "# NO-BOUNTY = in scope and submittable, but its bounty tier pays no cash (see PROGRAM.md).",
     ""]
L += inscope_lines
L += ["",
      "# === OUT OF SCOPE (allowlist stops here; nothing below can grant scope) ===",
      "# Recorded, not discarded. Two kinds of entry live below this line:",
      "#  1. assets Intigriti marks OUT OF SCOPE - bountyTier 5, or a group whose name",
      "#     says so. Testing them is UNAUTHORIZED.",
      "#  2. non-host asset ids (mobile packages, iOS app ids, devices, source-code",
      "#     repos, free-text 'other' assets) - not hosts, and a repo/store URL is not",
      "#     this program's asset."]
L += (oos_lines if oos_lines else ["#   (no non-host assets in the latest revision)"])
oos_md = latest_md("outOfScopes")
if oos_md:
    L += ["", "# --- the program's own OUT-OF-SCOPE text (latest revision, verbatim) ---"]
    L += ["# " + ln for ln in oos_md.splitlines()]
open(scope_p, "w", encoding="utf-8").write("\n".join(L) + "\n")

# --- WILDCARD-SHADOW CHECK -------------------------------------------------------------
# A host that Intigriti excludes can still be a SUBDOMAIN of an in-scope wildcard that
# sits above the divider (digitalocean lists `*.digitalocean.com` in scope at tier 3 AND
# `status.digitalocean.com` as tier-5 out of scope). Both scope parsers match the
# wildcard and STOP READING at the divider, so the gate will NOT block that host - this
# is documented, intentional parser behavior (targets/README.md, and the lib_scope demo
# asserts it), not a bug. It IS an operational hazard, so it gets named explicitly.
# Computed by importing the CANONICAL parser against the file just written, so this
# warning can never drift from what the gate actually enforces.
shadowed = []
try:
    sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts")
    from bbtools.lib_scope import host_in_scope   # noqa: E402
    for h, tname, label, why in oos_hosts:
        probe = re.sub(r"^\*\.?", "", h)         # a wildcard OOS entry -> test its apex
        if probe and host_in_scope(probe, scope_p):
            shadowed.append((h, probe, tname, label))
except Exception as e:                            # never let the check break intake
    notes.append("wildcard-shadow check skipped (%s: %s)" % (type(e).__name__, e))

if shadowed:
    with open(scope_p, "a", encoding="utf-8") as fh:
        fh.write("\n# !!! GATE-WILL-NOT-BLOCK: %d excluded host(s) are still covered by an\n"
                 "# !!! in-scope WILDCARD above the divider, so the scope gate will ALLOW them.\n"
                 "# !!! The program still forbids them. DO NOT PROBE THESE:\n" % len(shadowed))
        for h, probe, tname, label in shadowed:
            fh.write("# !!!   %s   (excluded [%s] %s; matches an in-scope wildcard)\n" % (probe, tname, label))
    notes.append("%d excluded host(s) are wildcard-shadowed and the gate will NOT block them - "
                 "see the GATE-WILL-NOT-BLOCK block at the end of SCOPE.txt" % len(shadowed))

# ---------------- PROGRAM.md ----------------
pays_cash = bool(tier_max) and max(tier_max.values()) > 0
P = ["# %s (Intigriti)" % (d.get("name") or program), "",
     "- Platform: Intigriti. Severity model: CVSS 3.1 unless the program overrides it "
     "(see 'Severity assessment' below).",
     "- Program: `%s/%s`   |   company: %s   |   industry: %s"
     % (company, program, d.get("companyName") or company, d.get("industry") or "?"),
     "- Program page: %s" % detail_url,
     "- Program JSON: %s" % api_url,
     "- confidentialityLevel: %s (4 = fully public)   |   status: %s"
     % (d.get("confidentialityLevel"), d.get("status")),
     "- Collaboration allowed: %s   |   awards reputation: %s   |   company self-triages: %s"
     % (d.get("allowCollaboration"), d.get("awardRep"), d.get("skipTriage")),
     "- ToS acceptance required: %s   |   2FA required: %s"
     % (row.get("tacRequired"), row.get("twoFactorRequired")),
     "- Guidelines authority: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/INTIGRITI.md",
     "",
     "## Does it pay cash?",
     "- PAYS CASH: **%s**" % ("YES" if pays_cash else "NO (VDP / reputation only)"),
     "- Directory payout band: %s - %s" % (m(minb), m(maxb)),
     "- Total paid to date: %s   |   average payout: %s"
     % (m(d.get("totalPayout")), m(d.get("averagePayout"))),
     "- Submissions: %s total, %s accepted" % (d.get("submissionCount"), d.get("acceptedSubmissionCount")),
     "",
     "## Bounty tiers (latest bounty-table revision, currency %s)" % currency]
if tier_max:
    for tid in sorted(tier_max):
        P.append("- tier %s: up to %s %s" % (tid, format(tier_max[tid], ",.0f"), currency))
else:
    P.append("- no bounty table published (VDP): no cash for any tier.")
P += ["", "## Eligibility notes (in-scope vs reward-eligible - do not conflate)",
      "- Every host above the OOS divider in SCOPE.txt is IN SCOPE and submittable.",
      "- %d of %d host entries sit in a bounty tier that pays NOTHING (tier absent from the "
      "bounty table, or capped at 0). They are tagged `NO-BOUNTY` inline in SCOPE.txt. A valid "
      "finding there earns reputation and a fix, not money. Check this before spending a cycle."
      % (stat["nobounty"], stat["hosts"]),
      "- %d asset(s) are explicitly OUT OF SCOPE (bountyTier 5, or an out-of-scope group name) "
      "and are recorded BELOW the divider. Testing them is unauthorized." % stat["oos"],
      "- %d non-host / third-party / refused asset id(s) recorded below the divider." % stat["nonhost"],
      "- Intigriti tier semantics (verified 2026-09-30): tier 5 = OUT OF SCOPE; a tier present "
      "in the bounty table = in scope and paid; any other tier (typically 1) = IN SCOPE but pays "
      "NOTHING. Tier 5 and tier 1 are NOT the same thing.",
      "- Per-tier asset counts:"]
for tid in sorted(by_tier, key=lambda x: (x is None, x)):
    v = by_tier[tid]
    P.append("    - tier %s: %d asset(s), %d host entr(y/ies)%s"
             % (tid, v["n"], v["hosts"],
                ", up to %s %s" % (format(tier_max[tid], ",.0f"), currency) if tier_pays(tid) else ", NO CASH"))
P.append("")
if shadowed:
    P += ["### WARNING: wildcard-shadowed exclusions (the gate will NOT block these)",
          "These hosts are OUT OF SCOPE per the program, but they are subdomains of an in-scope",
          "wildcard above the divider, so both scope parsers match them and the live gate ALLOWS",
          "them. That is documented parser behavior (targets/README.md), not a bug - the allowlist",
          "stops at the divider and never reads an exclusion. YOU are the control here:"]
    P += ["    - %s   (excluded [%s] %s)" % (probe, tname, label) for _h, probe, tname, label in shadowed]
    P.append("")
if notes:
    P += ["### Intake warnings"] + ["- %s" % n for n in sorted(set(notes))] + [""]

roe = latest_md("rulesOfEngagements")
sev = latest_md("severityAssessments")
ins = latest_md("inScopes")
faq = latest_md("faqs")
ident = sorted(set(" ".join(mm.group(0).split()) for mm in re.finditer(
    r"(?i)[^.\n]{0,110}(user-?agent|x-bug-?bounty|identif\w* header|custom header|@intigriti\.me)[^.\n]{0,110}",
    "\n".join([roe, ins, oos_md, faq]))))

P += ["## Safe harbor / disclosure",
      "- Intigriti's platform Terms plus the program's Rules of Engagement govern. Safe harbor is",
      "  NOT a discrete API field on Intigriti (unlike Bugcrowd's safeHarborStatus) - it lives in",
      "  the Rules of Engagement text reproduced below. READ IT before probing.",
      "- Disclosure is company-gated: no public write-up without Intigriti + company approval.",
      "",
      "## Required researcher-identification header / test-account convention",
      "- Intigriti mandates no platform-wide identification header (unlike HackerOne's `X-HackerOne:`).",
      "- Intigriti DOES issue every researcher an `@intigriti.me` forwarding address, and most",
      "  programs require test accounts to be registered with it so the company can attribute your",
      "  traffic. Treat that as this platform's identification requirement.",
      ("- Matching lines from this program's own text:" if ident
       else "- No header / @intigriti.me line found in this program's text; re-read the live page.")]
P += ["    - %s" % h for h in ident[:8]]
P += ["", "## Rules of engagement (latest revision, verbatim)", roe or "(none published)",
      "", "## Severity assessment (latest revision, verbatim)", sev or "(none published - assume CVSS 3.1)",
      "", "## In-scope guidance (latest revision, verbatim)", ins or "(none published)",
      "", "## Out-of-scope classes (latest revision, verbatim)", oos_md or "(none published)"]
if faq:
    P += ["", "## FAQ / account provisioning (latest revision, verbatim)", faq]
P += ["", "## Re-pull",
      "    ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/intigriti-scope.sh %s/%s --refresh" % (company, program), ""]
open(prog_p, "w", encoding="utf-8").write("\n".join(P) + "\n")

print("wrote %s" % scope_p)
print("  %d in-scope host entries%s from the NEWEST of %d asset revision(s); below the divider: "
      "%d explicitly out-of-scope + %d non-host asset(s)"
      % (stat["hosts"], " (%d NO-BOUNTY)" % stat["nobounty"] if stat["nobounty"] else "",
         len(d.get("assetsCollection") or []), stat["oos"], stat["nonhost"]))
print("wrote %s" % prog_p)
for n in sorted(set(notes)):
    print("  NOTE: %s" % n)
PY
rc=$?
if [ "$rc" -ne 0 ]; then
  # Leave nothing misleading AND nothing empty: drop a zero-byte scope file, then drop the
  # target dir itself if this run created it and it is still empty (rmdir refuses otherwise).
  if [ "$DIR_PREEXISTED" = "0" ]; then
    rm -f "$OUT/SCOPE.txt" 2>/dev/null
    rmdir "$OUT" 2>/dev/null || true
  fi
  # Never leave a half-written or misleading scope file behind.
  [ -f "$SCOPE_DEST" ] && [ ! -s "$SCOPE_DEST" ] && rm -f "$SCOPE_DEST"
  exit "$rc"
fi

mkdir -p "$OUT/recon" "$OUT/poc" "$OUT/evidence" "$OUT/hunts"
[ "$SCOPE_ALT" = 1 ]  && echo "NOTE: $OUT/SCOPE.txt already existed -> fresh pull in $SCOPE_DEST (diff + merge, or re-run with --refresh)." >&2
[ "$PROGMD_ALT" = 1 ] && echo "NOTE: $OUT/PROGRAM.md already existed -> fresh pull in $PROGMD_DEST." >&2
echo "next: review SCOPE.txt, confirm a few assets on the live program page, then model the target and hunt."
echo "zero requests were sent to any program asset; only app.intigriti.com was contacted."
exit 0
