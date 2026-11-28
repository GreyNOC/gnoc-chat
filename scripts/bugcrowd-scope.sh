#!/usr/bin/env bash
# bugcrowd-scope.sh <engagement-code> [--refresh]
#
# Given a Bugcrowd engagement code (the last path segment of the public brief URL,
# e.g. "program-25" from https://bugcrowd.com/engagements/program-25), pull
# its in-scope targets + program policy and write targets/<code>/SCOPE.txt and
# targets/<code>/PROGRAM.md, ready for the scope gate and target-modeler.
#
# ZERO AUTH. Verified live 2026-09-30 against bugcrowd.com with plain curl (no
# Cloudflare/JA3 wall, no cookie, no token). Full notes: scripts/BUGCROWD.md
#
# Mechanism (two JSON GETs, both public):
#   1. GET https://bugcrowd.com/engagements/<code>/changelog.json
#        -> {"changelogs":[{id, publishedAt, changelogState:"Latest"|null, ...}, ...]}
#        Pick the entry with changelogState == "Latest" (that is the live brief).
#   2. GET https://bugcrowd.com/engagements/<code>/changelog/<id>.json
#        -> the whole published brief document, including:
#             .data.scope[]                 target GROUPS, each with:
#                 .name .inScope(bool) .rewardRangeData{"1".."5":{min,max}} .targets[]
#             .data.scope[].targets[]        {uri, name, category, ipAddress, description, tags[]}
#             .data.brief.{name,tagline,description,targetsOverview,safeHarborStatus,additionalInformation}
#             .coordinatedDisclosure .participation .rewardAllocation .serviceLevel
#             .vrtVersion .statusLabel .submitReportUrl .totalRewardPool
#
# SCOPE.txt mapping (see targets/README.md for the authoritative grammar):
#   - group .inScope == true   -> its host-like targets become in-scope lines
#   - group .inScope == false  -> ALL its targets are RECORDED BELOW the OOS divider
#                                 (never silently dropped)
#   - non-host target categories in an in-scope group (android/ios/hardware/...) are
#     also recorded below the divider, like h1-scope.sh does for MOBILE_APPLICATION_*.
#     This matters for safety: an `ios` target's uri is apps.apple.com and an
#     `android` target's uri is play.google.com - writing those as in-scope host
#     lines would put Apple's and Google's stores in scope. They never go above.
#   - an in-scope group whose rewardRangeData is entirely null pays NO CASH. Those
#     targets are still IN SCOPE and still submittable, so they stay ABOVE the
#     divider (mirroring h1-scope.sh's eligible_for_submission-vs-eligible_for_bounty
#     split) and are annotated `NO-BOUNTY` inline; PROGRAM.md records the breakdown.
#   - wildcard forms are preserved VERBATIM: `*.foo.com` stays `*.foo.com` and
#     `*foo.com` stays `*foo.com`. Since the 2026-09-30 parser change the dot
#     carries meaning (`*.foo.com` is dot-bounded, `*foo.com` is a loose suffix
#     glob), so normalizing either form would change the enforced scope.
#
# NEVER writes a SCOPE.txt with zero in-scope entries. An empty-but-present
# SCOPE.txt is a live-gate hazard (see targets/README.md); a zero-entry pull exits
# non-zero and leaves NO file behind.
#
# Re-run safety (no-clobber): an existing non-empty SCOPE.txt / PROGRAM.md is left
# alone and the fresh pull lands in SCOPE.txt.new / PROGRAM.md.new for a hand
# diff+merge (h1-scope.sh / ywh-scope.sh behavior). --refresh overwrites in place.
#
# This script talks ONLY to bugcrowd.com. It sends ZERO requests to any program's
# target assets. Intake ends when SCOPE.txt is written.
set -u

HANDLE=""; REFRESH=0
for a in "$@"; do
  case "$a" in
    --refresh) REFRESH=1 ;;
    -h|--help)
      echo "usage: bugcrowd-scope.sh <engagement-code> [--refresh]" >&2
      echo "example: bugcrowd-scope.sh program-25" >&2
      echo "find codes: curl -s 'https://bugcrowd.com/engagements.json?category=bug_bounty' | jq -r '.engagements[].briefUrl'" >&2
      exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) [ -z "$HANDLE" ] && HANDLE="$a" ;;
  esac
done
if [ -z "$HANDLE" ]; then
  echo "usage: bugcrowd-scope.sh <engagement-code> [--refresh]" >&2
  echo "example: bugcrowd-scope.sh program-25" >&2
  exit 1
fi
# Accept a pasted brief URL or "engagements/<code>" and reduce it to the bare code.
HANDLE=$(printf '%s' "$HANDLE" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^engagements/##; s#[/?#].*$##')
case "$HANDLE" in
  ""|*[!A-Za-z0-9._-]*)
    echo "bad engagement code '$HANDLE' (expected the last path segment of the brief URL, e.g. program-25)" >&2
    exit 1 ;;
esac

command -v curl    >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v jq      >/dev/null 2>&1 || { echo "need jq" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 1; }

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
OUT="$ROOT/targets/$HANDLE"
SITE="https://bugcrowd.com"
BRIEF_URL="$SITE/engagements/$HANDLE"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

bc_get() {  # bc_get <url> -> body on stdout (empty on transport failure)
  curl -s --max-time 40 -A "$UA" -H 'Accept: application/json' "$1"
}

# --- 1. resolve the LATEST published brief changelog id --------------------------------
CL=$(bc_get "$SITE/engagements/$HANDLE/changelog.json")
if [ -z "$CL" ]; then
  echo "FAIL: empty response from $SITE/engagements/$HANDLE/changelog.json (network/egress)." >&2
  echo "  Nothing written. Retry from a working egress." >&2
  exit 2
fi
if printf '%s' "$CL" | jq -e '.errors? // empty' >/dev/null 2>&1; then
  detail=$(printf '%s' "$CL" | jq -r '.errors[]?.detail // .errors[]?.title // "unknown"' | paste -sd'; ' -)
  echo "FAIL: Bugcrowd returned an error for engagement '$HANDLE': $detail" >&2
  echo "  Check the code against the public directory (it is the last segment of briefUrl):" >&2
  echo "    curl -s '$SITE/engagements.json?category=bug_bounty' | jq -r '.engagements[].briefUrl'" >&2
  echo "  A private/invite-only engagement is not readable unauthenticated. Nothing written." >&2
  exit 2
fi
CLID=$(printf '%s' "$CL" | jq -r '
  ([.changelogs[]? | select(.changelogState == "Latest")] | first | .id)
  // ([.changelogs[]? | select((.tags // "") == "brief")] | last | .id)
  // (.changelogs[0]?.id) // empty' 2>/dev/null)
if [ -z "$CLID" ]; then
  echo "FAIL: no published brief version found for '$HANDLE' (changelog.json had no usable entry)." >&2
  echo "  Nothing written. Verify the engagement is public and has a published brief." >&2
  exit 2
fi

# --- 2. pull the published brief document ---------------------------------------------
BRIEF=$(bc_get "$SITE/engagements/$HANDLE/changelog/$CLID.json")
if [ -z "$BRIEF" ]; then
  echo "FAIL: empty response for brief document $HANDLE/changelog/$CLID.json. Nothing written." >&2
  exit 2
fi
if printf '%s' "$BRIEF" | jq -e '.errors? // empty' >/dev/null 2>&1; then
  detail=$(printf '%s' "$BRIEF" | jq -r '.errors[]?.detail // .errors[]?.title // "unknown"' | paste -sd'; ' -)
  echo "FAIL: brief document unreadable for '$HANDLE': $detail. Nothing written." >&2
  exit 2
fi
if ! printf '%s' "$BRIEF" | jq -e '.data.scope? // empty' >/dev/null 2>&1; then
  echo "FAIL: brief document for '$HANDLE' has no .data.scope (shape changed, or not an engagement brief)." >&2
  echo "  Inspect: curl -s '$SITE/engagements/$HANDLE/changelog/$CLID.json' | jq 'keys'" >&2
  echo "  Nothing written." >&2
  exit 2
fi

# --- 3. pick destinations (no-clobber unless --refresh) -------------------------------
# Remember whether the target dir already existed, so a failed intake can remove a
# directory IT created and leave no empty targets/<handle>/ husk behind.
DIR_PREEXISTED=0; [ -d "$OUT" ] && DIR_PREEXISTED=1
mkdir -p "$OUT"
SCOPE_DEST="$OUT/SCOPE.txt"; SCOPE_ALT=0
PROG_DEST="$OUT/PROGRAM.md";  PROG_ALT=0
if [ "$REFRESH" != "1" ]; then
  if [ -s "$SCOPE_DEST" ]; then SCOPE_DEST="$OUT/SCOPE.txt.new"; SCOPE_ALT=1; fi
  if [ -s "$PROG_DEST" ];  then PROG_DEST="$OUT/PROGRAM.md.new";  PROG_ALT=1; fi
fi

# --- 4. render SCOPE.txt + PROGRAM.md -------------------------------------------------
BRIEF_TMP=$(mktemp "${TMPDIR:-/tmp}/bugcrowd-brief.XXXXXX.json") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -f "$BRIEF_TMP"' EXIT
printf '%s' "$BRIEF" > "$BRIEF_TMP"
# NOTE: the python program arrives on stdin via the heredoc, so the brief JSON cannot
# also be piped in - it is handed over as a temp FILE path in argv instead.
HANDLE="$HANDLE" BRIEF_URL="$BRIEF_URL" CLID="$CLID" \
  SCOPE_DEST="$SCOPE_DEST" PROG_DEST="$PROG_DEST" python3 - "$BRIEF_TMP" <<'PY'
import json, os, re, sys

handle   = os.environ["HANDLE"]
brief_url= os.environ["BRIEF_URL"]
clid     = os.environ["CLID"]
scope_p  = os.environ["SCOPE_DEST"]
prog_p   = os.environ["PROG_DEST"]
with open(sys.argv[1], encoding="utf-8") as _fh:
    d = json.load(_fh)

# Bugcrowd target categories whose identifier is a HOST. `other` is included on
# purpose: real programs file wildcard hosts under it (*.app.example.com, *.app.example.com,
# *.app.example.com all arrive as category="other"). Everything else - android, ios,
# hardware, ... - is a non-host asset id and is recorded BELOW the OOS divider.
HOSTLIKE = {"website", "api", "other"}

# Hosts that belong to a third party, never to the program. A store/repo URL must
# never become an in-scope host line. Same safe direction as h1-scope.sh dropping
# MOBILE_APPLICATION_* / SOURCE_CODE from the allowlist.
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
# Mirror of the parsers' refusal list (scope-gate.sh / bbtools/lib_scope.py): an
# entry that reduces to one of these can never grant scope, so it is not an entry.
PUBLIC_SUFFIX = {
    "app.example.com","com.au","com.co","com.mx","co.jp","co.nz","com.br","co.in","com.sg",
    "com.hk","co.za","com.tr","gov.uk","org.uk","net.au","org.au","co.kr","com.cn",
    "co.id","com.ph","com.my","co.th","com.tw","ne.jp","or.jp",
}
HOST_RE = re.compile(r"^\*?\.?(?:[A-Za-z0-9*_-]+\.)+[A-Za-z*][A-Za-z0-9*-]{1,}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")

def to_host(tok):
    """Reduce a Bugcrowd target identifier to a bare host/wildcard token, or ''.
    Keeps a leading '*.' / '*' verbatim - the dot is load-bearing in both parsers."""
    if not tok:
        return ""
    s = str(tok).strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)   # scheme
    s = s.split("@")[-1] if "@" in s.split("/")[0] else s  # userinfo
    s = re.split(r"[/?#]", s, maxsplit=1)[0]                     # path/query/fragment
    s = s.rstrip(".").strip()
    if s.startswith("[") or ":" in s.replace("::", ""):  # port / IPv6 literal
        s = s.split("]")[0].lstrip("[") if s.startswith("[") else s.split(":")[0]
    if not s or " " in s or "," in s:
        return ""
    if IPV4_RE.match(s):
        return s
    if not HOST_RE.match(s):
        return ""
    if "." not in s:
        return ""
    return s

def bare(h):
    return re.sub(r"^\*\.?", "", h).lower()

def group_pays(g):
    rrd = g.get("rewardRangeData")
    if not isinstance(rrd, dict):
        return False
    for k, v in rrd.items():
        if isinstance(v, dict) and (v.get("min") is not None or v.get("max") is not None):
            return True
        # a scalar cap (e.g. "programMax": 5000) also proves the group pays
        if not str(k).isdigit() and isinstance(v, (int, float)) and v:
            return True
    return False

def money(g):
    # rewardRangeData is {"1".."5": {min,max}} PLUS occasionally a scalar key such as
    # "programMax": 5000 (seen on webdotcom). Non-dict values are not priority rows.
    rrd = g.get("rewardRangeData")
    if not isinstance(rrd, dict):
        return "no cash reward for this group"
    out = []
    for k in sorted((k for k in rrd if str(k).isdigit()), key=lambda x: int(x)):
        v = rrd[k]
        if not isinstance(v, dict):
            continue
        lo, hi = v.get("min"), v.get("max")
        if lo is None and hi is None:
            continue
        out.append(f"P{k} ${lo:,}-${hi:,}" if lo is not None and hi is not None
                   else f"P{k} ${(lo if lo is not None else hi):,}")
    extra = [f"{k}=${v:,}" for k, v in rrd.items()
             if not str(k).isdigit() and isinstance(v, (int, float))]
    if extra:
        out.append("(" + ", ".join(sorted(extra)) + ")")
    return ", ".join(out) if out else "no cash reward for this group"

scope   = d.get("data", {}).get("scope") or []
brief   = d.get("data", {}).get("brief") or {}
inscope_lines, oos_lines, notes = [], [], []
oos_hosts = []   # (host, category, label) for hosts placed BELOW the divider
seen = set()
stat = {"grp_in": 0, "grp_oos": 0, "hosts": 0, "nobounty_hosts": 0, "nonhost": 0, "oos_tgt": 0}

for g in sorted(scope, key=lambda x: (x.get("sortOrder") if isinstance(x.get("sortOrder"), int) else 999)):
    gname   = (g.get("name") or "unnamed group").strip()
    gin     = bool(g.get("inScope"))
    pays    = group_pays(g)
    targets = g.get("targets") or []
    if not gin:
        stat["grp_oos"] += 1
        oos_lines.append(f"# --- group '{gname}' (inScope=false): {len(targets)} target(s), NOT testable ---")
        for t in targets:
            nm0 = (t.get("name") or "").strip()
            uri0 = (t.get("uri") or "").strip()
            ident = nm0 or uri0 or (t.get("ipAddress") or "").strip() or "?"
            oos_lines.append(f"#   OOS [{t.get('category') or '?'}] {ident}"
                             + (f"   <{uri0}>" if uri0 and uri0 != ident else ""))
            stat["oos_tgt"] += 1
            oh = to_host(nm0) or to_host(uri0)
            if oh:
                oos_hosts.append((oh, t.get("category") or "?", ident))
        continue

    stat["grp_in"] += 1
    tag = "" if pays else "  NO-BOUNTY"
    inscope_lines.append(f"# --- group '{gname}' -- rewards: {money(g)} ---")
    for t in sorted(targets, key=lambda x: (x.get("sortOrder") if isinstance(x.get("sortOrder"), int) else 999)):
        cat   = (t.get("category") or "").strip().lower()
        nm    = (t.get("name") or "").strip()
        uri   = (t.get("uri") or "").strip()
        ipadr = (t.get("ipAddress") or "").strip()
        label = nm or uri or ipadr or "?"
        if cat not in HOSTLIKE:
            oos_lines.append(f"#   NON-HOST [{cat or '?'}] {label}" + (f"   <{uri}>" if uri else ""))
            stat["nonhost"] += 1
            continue
        # Prefer `name` when it is host-shaped: it carries the wildcard form
        # (name="*.app.example.com" while uri="https://app.example.com/"). Fall back
        # to uri, then to the ipAddress column.
        host = to_host(nm) or to_host(uri) or to_host(ipadr)
        if not host:
            oos_lines.append(f"#   NOT-A-HOST [{cat}] {label}" + (f"   <{uri}>" if uri else ""))
            stat["nonhost"] += 1
            continue
        b = bare(host)
        if b in THIRD_PARTY:
            oos_lines.append(f"#   THIRD-PARTY-HOST [{cat}] {label} -> {host} (store/repo host; promote by hand if genuinely the program's own asset)")
            notes.append(f"third-party host not auto-allowlisted: {host}  (from [{cat}] {label})")
            stat["nonhost"] += 1
            continue
        if b in PUBLIC_SUFFIX or "." not in b:
            oos_lines.append(f"#   REFUSED-PUBLIC-SUFFIX [{cat}] {label} -> {host} (both parsers refuse it; cannot grant scope)")
            notes.append(f"entry reduces to a public suffix / bare TLD and was NOT written above the divider: {host}")
            stat["nonhost"] += 1
            continue
        key = host.lower()
        if key in seen:
            continue
        seen.add(key)
        note = f"  # {cat}"
        if nm and nm.lower() != host.lower():
            note += f" | {nm}"
        inscope_lines.append(f"{host}{note}{tag}")
        stat["hosts"] += 1
        if not pays:
            stat["nobounty_hosts"] += 1

if stat["hosts"] == 0:
    sys.stderr.write(
        "FAIL: the Bugcrowd brief for '%s' yielded ZERO in-scope host entries.\n"
        "  (in-scope groups=%d, out-of-scope groups=%d, non-host/refused targets=%d)\n"
        "  Refusing to write a SCOPE.txt: an empty-but-present SCOPE.txt makes the live\n"
        "  scope gate BLOCK every probe for this target (fail-closed, 2026-09-30) and an\n"
        "  all-comment one is equally useless. Nothing was written.\n"
        "  This is normal for a source-code-only / hardware-only engagement - such a\n"
        "  program has no host scope to enforce.\n"
        "  Inspect by hand: curl -s 'https://bugcrowd.com/engagements/%s/changelog/%s.json' | jq '.data.scope'\n"
        % (handle, stat["grp_in"], stat["grp_oos"], stat["nonhost"], handle, clid))
    sys.exit(3)

sh   = brief.get("safeHarborStatus") or {}
nl   = "\n"
L = [f"# {handle} - auto-pulled from the Bugcrowd public engagement brief (zero auth)",
     f"# Brief page:  {brief_url}",
     f"# Source JSON: https://bugcrowd.com/engagements/{handle}/changelog/{clid}.json",
     f"# Brief version published: {d.get('publishedAt') or '?'}   |   pulled by scripts/bugcrowd-scope.sh",
     f"# Safe harbor: {sh.get('status') or '?'}   |   coordinated disclosure: {d.get('coordinatedDisclosure')}",
     f"# Groups: {stat['grp_in']} in-scope, {stat['grp_oos']} out-of-scope. Host entries: {stat['hosts']}"
     + (f" (of which {stat['nobounty_hosts']} NO-BOUNTY)" if stat["nobounty_hosts"] else ""),
     "# VERIFY against the live brief before probing. Wildcard forms are verbatim from",
     "# Bugcrowd: '*.foo.com' is dot-bounded, '*foo.com' is a loose suffix glob.",
     "# NO-BOUNTY = in scope and submittable, but its target group pays no cash (see PROGRAM.md).",
     ""]
L += inscope_lines
L += ["",
      "# === OUT OF SCOPE (allowlist stops here; nothing below can grant scope) ===",
      "# Recorded, not discarded: out-of-scope groups plus every non-host asset id.",
      "# Non-host targets are NEVER written above this line - an ios/android target's uri",
      "# is apps.apple.com / play.google.com, which is not this program's asset."]
L += (oos_lines if oos_lines else ["#   (none reported by the brief)"])
open(scope_p, "w", encoding="utf-8").write(nl.join(L) + nl)

# --- WILDCARD-SHADOW CHECK -------------------------------------------------------------
# A target Bugcrowd puts in an inScope=false group can still be a SUBDOMAIN of an
# in-scope WILDCARD sitting above the divider (program-93 lists `*.app.example.com` in scope
# and `*.app.example.com` out of scope). Both scope parsers match the wildcard and
# STOP READING at the divider, so the gate will NOT block that host. That is documented,
# intentional parser behavior (targets/README.md; the lib_scope demo asserts it), not a
# bug - but it is an operational hazard, so name it explicitly. Computed by importing
# the CANONICAL parser against the file just written, so it cannot drift from the gate.
shadowed = []
try:
    sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts")
    from bbtools.lib_scope import host_in_scope   # noqa: E402
    for oh, ocat, olabel in oos_hosts:
        probe = re.sub(r"^\*\.?", "", oh)
        if probe and host_in_scope(probe, scope_p):
            shadowed.append((probe, ocat, olabel))
except Exception as e:
    notes.append(f"wildcard-shadow check skipped ({type(e).__name__}: {e})")

if shadowed:
    with open(scope_p, "a", encoding="utf-8") as fh:
        fh.write(f"\n# !!! GATE-WILL-NOT-BLOCK: {len(shadowed)} out-of-scope host(s) are still covered\n"
                 "# !!! by an in-scope WILDCARD above the divider, so the scope gate will ALLOW them.\n"
                 "# !!! The program still forbids them. DO NOT PROBE THESE:\n")
        for probe, ocat, olabel in shadowed:
            fh.write(f"# !!!   {probe}   (out-of-scope [{ocat}] {olabel}; matches an in-scope wildcard)\n")
    notes.append(f"{len(shadowed)} out-of-scope host(s) are wildcard-shadowed and the gate will NOT "
                 "block them - see the GATE-WILL-NOT-BLOCK block at the end of SCOPE.txt")

# ---------------- PROGRAM.md ----------------
def strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", "", s or "")
    s = re.sub(r"(?i)<br\s*/?>", "\n", s)
    s = re.sub(r"(?i)</(p|div|li|h[1-6]|tr)>", "\n", s)
    s = re.sub(r"(?i)<li[^>]*>", "- ", s)
    s = re.sub(r"<[^>]+>", "", s)
    for a, b in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                 ("&#39;", "'"), ("&nbsp;", " "), ("&rsquo;", "'"), ("&mdash;", "-")):
        s = s.replace(a, b)
    return re.sub(r"\n{3,}", "\n\n", s).strip()

paid_groups = [g for g in scope if g.get("inScope") and group_pays(g)]
free_groups = [g for g in scope if g.get("inScope") and not group_pays(g)]
pays_cash   = bool(paid_groups)
alltxt = " ".join([strip_html(brief.get("targetsOverview") or ""),
                   strip_html(brief.get("description") or ""),
                   strip_html(brief.get("additionalInformation") or "")])
hdr_hits = sorted(set(m.group(0).strip() for m in
                      re.finditer(r"(?i)[^.\n]{0,110}(user-?agent|x-bug-?bounty|identif\w* header|custom header)[^.\n]{0,110}", alltxt)))

P = [f"# {brief.get('name') or handle} (Bugcrowd)", "",
     f"- Platform: Bugcrowd. Severity model: VRT {d.get('vrtVersion') or '?'} (Bugcrowd Vulnerability Rating Taxonomy), CVSS 3.1 for the score.",
     f"- Engagement code: `{handle}`   |   product: {(d.get('engagementTypeDetail') or {}).get('productLabel') or '?'}",
     f"- Brief page: {brief_url}",
     f"- Brief JSON: https://bugcrowd.com/engagements/{handle}/changelog/{clid}.json",
     f"- Status: {d.get('statusLabel') or '?'}   |   participation: {d.get('participation') or '?'}   |   service level: {d.get('serviceLevel') or '?'}",
     f"- Submit at: https://bugcrowd.com{d.get('submitReportUrl') or '/engagements/' + handle + '/submissions/new'}",
     f"- Guidelines authority: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/BUGCROWD.md",
     "",
     "## Does it pay cash?",
     f"- PAYS CASH: **{'YES' if pays_cash else 'NO'}**   (reward allocation: {d.get('rewardAllocation') or '?'}"
     + (f", total pool {d['totalRewardPool']}" if d.get("totalRewardPool") else "") + ")",
     f"- Reward-bearing in-scope groups: {len(paid_groups)}   |   in-scope groups paying nothing: {len(free_groups)}",
     "",
     "## Reward table per target group (P1 highest .. P5 lowest, USD)"]
for g in scope:
    if not g.get("inScope"):
        continue
    P.append(f"- **{g.get('name')}**: {money(g)}")
P += ["",
      "## Eligibility notes (in-scope vs reward-eligible - do not conflate)",
      "- Every host above the OOS divider in SCOPE.txt is IN SCOPE and submittable.",
      f"- {stat['nobounty_hosts']} of {stat['hosts']} host entries sit in a group with NO cash reward; they are tagged `NO-BOUNTY` inline in SCOPE.txt. A valid finding there earns points/kudos and a fix, not money. Check this before spending a cycle.",
      f"- {stat['oos_tgt']} target(s) in {stat['grp_oos']} out-of-scope group(s) are recorded BELOW the divider. Testing them is unauthorized.",
      f"- {stat['nonhost']} non-host / third-party / refused asset id(s) recorded below the divider (mobile packages, store URLs, repos, public-suffix-only entries).",
      ""]
if shadowed:
    P += ["### WARNING: wildcard-shadowed exclusions (the gate will NOT block these)",
          "These hosts are OUT OF SCOPE per the brief, but they are subdomains of an in-scope",
          "wildcard above the divider, so both scope parsers match them and the live gate ALLOWS",
          "them. Documented parser behavior (targets/README.md), not a bug - the allowlist stops",
          "at the divider and never reads an exclusion. YOU are the control here:"]
    P += [f"    - {probe}   (out-of-scope [{ocat}] {olabel})" for probe, ocat, olabel in shadowed]
    P.append("")
if notes:
    P += ["### Intake warnings"] + [f"- {n}" for n in sorted(set(notes))] + [""]
P += ["## Safe harbor / disclosure",
      f"- Safe harbor: **{sh.get('label') or '?'}** (status `{sh.get('status') or '?'}`) - {sh.get('description') or 'not stated in the brief'}",
      f"- Coordinated disclosure required: **{d.get('coordinatedDisclosure')}**"
      + ("  (disclosure terms are displayed on the brief)" if d.get("displayDisclosureTerms") else ""),
      "- Bugcrowd Standard Disclosure Terms govern unless the brief overrides them. Do not publish without written permission.",
      f"- Collaboration allowed: {d.get('collaborationEnabled')}   |   known-issues list published: {d.get('knownIssuesEnabled')}",
      "",
      "## Required researcher-identification header",
      "- Bugcrowd mandates no platform-wide identification header (unlike HackerOne's `X-HackerOne:`).",
      ("- The brief text mentions a header/User-Agent requirement - READ THESE BEFORE PROBING:" if hdr_hits
       else "- No header/User-Agent requirement found in the brief text. Still re-read the live brief; a per-program ask is common."),
      ]
P += [f"    - {h}" for h in hdr_hits[:6]]
P += ["", "## Scope and rewards prose (from the brief, verbatim minus HTML)",
      strip_html(brief.get("targetsOverview") or "") or "(brief has no targetsOverview section)",
      "", "## Program description",
      strip_html(brief.get("description") or "") or "(none)"]
if strip_html(brief.get("additionalInformation") or ""):
    P += ["", "## Additional information", strip_html(brief["additionalInformation"])]
P += ["", "## Out-of-scope classes",
      "- Bugcrowd's global non-qualifying list applies: https://bugcrowd.com/vulnerability-rating-taxonomy",
      "- Anything not listed as an in-scope target is out of scope. Per-group and per-target",
      "  carve-outs live in the group/target descriptions in the brief JSON:",
      f"    curl -s 'https://bugcrowd.com/engagements/{handle}/changelog/{clid}.json' | jq -r '.data.scope[] | \"\\(.name): \\(.description)\"'",
      "- The out-of-scope groups and their targets are enumerated below the divider in SCOPE.txt.",
      ""]
open(prog_p, "w", encoding="utf-8").write("\n".join(P) + "\n")

print(f"wrote {scope_p}")
print(f"  {stat['hosts']} in-scope host entries"
      + (f" ({stat['nobounty_hosts']} NO-BOUNTY)" if stat["nobounty_hosts"] else "")
      + f", {stat['grp_in']} in-scope group(s), {stat['grp_oos']} out-of-scope group(s),"
      + f" {stat['oos_tgt']} OOS target(s) + {stat['nonhost']} non-host asset(s) recorded below the divider")
print(f"wrote {prog_p}")
for n in sorted(set(notes)):
    print(f"  NOTE: {n}")
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

[ "$SCOPE_ALT" = 1 ] && echo "NOTE: $OUT/SCOPE.txt already existed -> fresh pull in $SCOPE_DEST (diff + merge to keep manual annotations; or re-run with --refresh)." >&2
[ "$PROG_ALT" = 1 ]  && echo "NOTE: $OUT/PROGRAM.md already existed -> fresh pull in $PROG_DEST." >&2
echo "next: review SCOPE.txt, confirm a few targets on $BRIEF_URL, then model the target and hunt."
echo "zero requests were sent to any program asset; only bugcrowd.com was contacted."
exit 0
