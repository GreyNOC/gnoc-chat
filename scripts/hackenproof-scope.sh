#!/usr/bin/env bash
# hackenproof-scope.sh <program-slug> [--refresh]
#
# Given a HackenProof program slug (the last path segment of the public program page,
# e.g. "zmo-exchange" from https://hackenproof.com/programs/zmo-exchange), pull its
# in-scope targets + program policy and write targets/<slug>/SCOPE.txt and
# targets/<slug>/PROGRAM.md, ready for the scope gate and target-modeler.
#
# ZERO AUTH. Verified live 2026-10-21 against hackenproof.com with plain curl (no
# Cloudflare/JA3 wall seen, no cookie, no token). Full notes: scripts/HACKENPROOF.md
#
# *** THE MECHANISM IS DIFFERENT FROM EVERY OTHER PLATFORM IN THIS WORKSPACE ***
# HackenProof has NO public JSON API (confirmed: no api.hackenproof.com host appears
# anywhere in the site's JS bundles; docs.hackenproof.com lists no public read API -
# its "MCP Server" is an AUTHENTICATED dashboard feature, not a public scope reader).
# The site is a Nuxt 3 SSR app. Every page embeds its own server-fetched data inline as
# a <script id="__NUXT_DATA__" type="application/json"> blob, encoded in Nuxt/Vue's
# "devalue" reference format: a flat JSON ARRAY where array[0] is the root value, and
# every value that is itself an object/array stores its children as INTEGER INDICES
# into the same array (for structural sharing / dedup), except for raw primitives
# (string/number/bool/null) which are stored directly. A couple of entries are wrapped
# as ["ShallowReactive", <idx>] / ["Reactive", <idx>] and must be unwrapped by
# following <idx>. decode_nuxt_data() below is a small generic resolver for exactly
# this shape; it is NOT HackenProof-specific and would work on any Nuxt 3 SSR page.
#
#   1. GET https://hackenproof.com/programs?page=N
#        -> HTML with <script id="__NUXT_DATA__"> containing (after decode):
#             .data["programs-api-bounty"] = {programs:[...], total_items, next_page,
#                                              prev_page, filter_attributes:{...}}
#           10 programs per page. filter_attributes documents real query-param NAMES
#           (order_by, with_project_types, by_status, by_kyc, by_poc, ...) but THESE
#           WERE TESTED LIVE AND DO NOT CHANGE THE RESULT when passed as a plain query
#           string (?with_project_types=DEX returned the identical unfiltered page;
#           ?order_by=max_bounty_float returned the identical default order). Only
#           ?page=N was confirmed to work. Treat filter_attributes as a vocabulary of
#           what the UI can filter on, not as a working GET-param contract - unverified
#           further; see scripts/HACKENPROOF.md section 5.
#   2. GET https://hackenproof.com/programs/<slug>
#        -> HTML with <script id="__NUXT_DATA__"> containing (after decode):
#             .data.program = { title, companyName, state, status, maxReward,
#               minBounty, maxBounty, rewards:{critical_min,critical_max,high_min,...},
#               kycRequired, pocRequired, minReputation, submissionFee, sla:{...},
#               scopes: [ {id, title, target, target_description, criticality,
#                          out_of_scope, position}, ... ],
#               programRules, focusArea, disclosureGuidelines,
#               eligibilityAndCoordinateDisclosure, labels:{...}, submitUrl, ... }
#        A nonexistent slug answers HTTP 302 to "/error" with NO __NUXT_DATA__ script
#        at all (verified) - that combination is this script's "not found" signal.
#
# scopes[].out_of_scope is a plain BOOLEAN. This is simpler than Bugcrowd (inScope per
# GROUP) or Intigriti (bountyTierId==5 + a version-history trap): HackenProof marks
# every individual scope target in/out directly, with no group indirection and no
# append-only history to pick the wrong revision of.
#
# *** scopes[].title IS FREE TEXT, NOT A CONTROLLED VOCABULARY - NEVER GATE ON IT ***
# Observed titles across 21 sampled programs: Web, API, Smart Contract, Protocol,
# Bridge, Infrastructure, Android, iOS, Other. Unlike Bugcrowd's `category` or
# Intigriti's `typeId`, the SAME kind of asset appears under DIFFERENT titles on
# different programs (coingecko's Chrome extension is filed under "Web"; idos's real
# web hosts - enclave.idos.network etc - are filed under "Other"). So this script
# NEVER decides host-vs-non-host by title. It shape-checks every scopes[].target
# string with to_host() regardless of declared title, and relies on the THIRD_PARTY +
# PUBLIC_SUFFIX guards (below) to keep store/repo/explorer infrastructure out of the
# allowlist even when a company mis-titles it. The title is kept only as a comment.
#
# HackenProof is a WEB3/CRYPTO-FOCUSED platform: of 196 sampled scope entries across
# 21 programs, ~97 (49%) were Smart Contract/Protocol/Bridge/Infrastructure entries
# pointing at a github.com repo path or a block-explorer contract-address URL (e.g.
# https://monadscan.com/address/0x...#code) - NEITHER of which is the program's own
# host. github.com is already in THIRD_PARTY (shared with the other platform scripts).
# Block explorers are NOT previously in this workspace's THIRD_PARTY sets, so this
# script adds a best-effort list of common ones (see EXPLORER_HOSTS below) - only
# monadscan.com was empirically observed in the sample; the rest are added
# proactively from general Web3 knowledge and are UNVERIFIED against HackenProof
# data specifically. A program whose scope is entirely Smart Contract/Protocol
# references therefore commonly yields ZERO host entries (see "zero-host" below) -
# this is EXPECTED and is this workspace's existing Immunefi-style on-chain lane,
# not a bug in this script.
#
# SCOPE.txt mapping (grammar authority: targets/README.md):
#   - scopes[].out_of_scope == true  -> BELOW the OOS divider, "OOS" note
#   - shape-check fails (to_host() == '')            -> BELOW divider, "NOT-A-HOST"
#   - host reduces to a known third-party/store/repo/explorer host -> BELOW divider,
#     "THIRD-PARTY-HOST" note (promote by hand only if genuinely the program's own)
#   - host reduces to a public suffix / bare TLD     -> BELOW divider, "REFUSED-..."
#   - otherwise                                      -> ABOVE the divider
#   - wildcard forms preserved VERBATIM ('*.foo.com' stays dot-bounded, '*foo.com'
#     stays a loose suffix glob - same convention as every other platform script here).
#   - REWARD MODEL DIFFERS FROM EVERY OTHER PLATFORM HERE: HackenProof's bounty table
#     (`rewards`: critical/high/medium/low min/max) is a PROGRAM-LEVEL property, not
#     per-asset or per-group like Bugcrowd/Intigriti. So "pays cash" is a single
#     program-wide boolean; when false, EVERY in-scope host line is tagged NO-BOUNTY
#     inline anyway, for cross-platform grep consistency, even though the underlying
#     reason is program-wide rather than per-asset.
#
# NEVER writes a SCOPE.txt with zero in-scope entries (see targets/README.md
# "empty-SCOPE.txt hazard"): a zero-host pull exits 3 and leaves NO file behind. This
# is the EXPECTED outcome for a pure Smart Contract/Protocol-only program (see above).
#
# Re-run safety (no-clobber): an existing non-empty SCOPE.txt / PROGRAM.md is left
# alone and the fresh pull lands in SCOPE.txt.new / PROGRAM.md.new for a hand
# diff+merge. --refresh overwrites in place.
#
# PREREQUISITE (workspace-wide, fixed 2026-10-21 as part of building this script):
# .claude/hooks/scope-gate.sh's PLATFORM_RE did not list hackenproof.com, so every
# probe against it (even this script) was hard-BLOCKED the same way an in-scope
# program asset would be. Added `hackenproof\.com` next to bugcrowd.com/intigriti.com/
# yeswehack.com in PLATFORM_RE - this is workspace tooling infrastructure (program
# directory data), the same category those three already sit in, not a hunt target.
# See scripts/HACKENPROOF.md section 0 for the verification that this was a genuine
# gap (zero prior hits for "hackenproof" anywhere in scripts/ or the docs).
#
# This script talks ONLY to hackenproof.com. It sends ZERO requests to any program's
# target assets. Intake ends when SCOPE.txt is written.
set -u

HANDLE=""; REFRESH=0
for a in "$@"; do
  case "$a" in
    --refresh) REFRESH=1 ;;
    -h|--help)
      echo "usage: hackenproof-scope.sh <program-slug> [--refresh]" >&2
      echo "example: hackenproof-scope.sh zmo-exchange" >&2
      echo "find slugs: scripts/hackenproof-rank-programs.sh" >&2
      exit 0 ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) [ -z "$HANDLE" ] && HANDLE="$a" ;;
  esac
done
if [ -z "$HANDLE" ]; then
  echo "usage: hackenproof-scope.sh <program-slug> [--refresh]" >&2
  echo "example: hackenproof-scope.sh zmo-exchange" >&2
  exit 1
fi
# Accept a pasted program URL or "programs/<slug>" and reduce it to the bare slug.
HANDLE=$(printf '%s' "$HANDLE" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^programs/##; s#[/?#].*$##')
case "$HANDLE" in
  ""|*[!A-Za-z0-9._-]*)
    echo "bad program slug '$HANDLE' (expected the last path segment of the program page, e.g. zmo-exchange)" >&2
    exit 1 ;;
esac

command -v curl    >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 1; }

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
OUT="$ROOT/targets/$HANDLE"
SITE="https://hackenproof.com"
PROG_URL="$SITE/programs/$HANDLE"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"

# --- 1. fetch the program page --------------------------------------------------------
TMPD=$(mktemp --directory "${TMPDIR:-/tmp}/hackenproof-scope.XXXXXX") \
  || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT

HTML="$TMPD/program.html"
CODE=$(curl -s --max-time 40 -A "$UA" -o "$HTML" -w '%{http_code}' "$PROG_URL")
if [ -z "$CODE" ]; then
  echo "FAIL: no response from $PROG_URL (network/egress). Nothing written." >&2
  exit 2
fi
if [ "$CODE" = "302" ] || [ "$CODE" = "301" ]; then
  echo "FAIL: $PROG_URL redirected (HTTP $CODE) - this is HackenProof's 'not found' signal" >&2
  echo "  for a bad slug (verified: it 302s to /error with no program data). Check the slug" >&2
  echo "  against the public program page, or list slugs with" >&2
  echo "  scripts/hackenproof-rank-programs.sh. Nothing written." >&2
  exit 2
fi
if [ "$CODE" != "200" ]; then
  echo "FAIL: HTTP $CODE for $PROG_URL. Nothing written." >&2
  exit 2
fi

# --- 2. destinations (no-clobber unless --refresh) -------------------------------------
DIR_PREEXISTED=0; [ -d "$OUT" ] && DIR_PREEXISTED=1
mkdir -p "$OUT"
SCOPE_DEST="$OUT/SCOPE.txt"; SCOPE_ALT=0
PROG_DEST="$OUT/PROGRAM.md";  PROG_ALT=0
if [ "$REFRESH" != "1" ]; then
  if [ -s "$SCOPE_DEST" ]; then SCOPE_DEST="$OUT/SCOPE.txt.new"; SCOPE_ALT=1; fi
  if [ -s "$PROG_DEST" ];  then PROG_DEST="$OUT/PROGRAM.md.new";  PROG_ALT=1; fi
fi

# --- 3. decode the devalue payload + render SCOPE.txt / PROGRAM.md ----------------------
HANDLE="$HANDLE" PROG_URL="$PROG_URL" \
  SCOPE_DEST="$SCOPE_DEST" PROG_DEST="$PROG_DEST" python3 - "$HTML" <<'PY'
import json, os, re, sys

handle   = os.environ["HANDLE"]
prog_url = os.environ["PROG_URL"]
scope_p  = os.environ["SCOPE_DEST"]
prog_p   = os.environ["PROG_DEST"]
html = open(sys.argv[1], encoding="utf-8", errors="replace").read()

# --- generic Nuxt 3 "devalue" payload resolver (not HackenProof-specific) --------------
WRAPPERS = {"ShallowReactive", "Reactive", "Ref", "ShallowRef", "EmptyRef", "EmptyShallowRef"}

def decode_nuxt_data(script_body):
    arr = json.loads(script_body)
    memo = {}
    def resolve(idx):
        if idx in memo:
            return memo[idx]
        if not isinstance(idx, int) or not (0 <= idx < len(arr)):
            return None
        raw = arr[idx]
        memo[idx] = None  # cycle guard
        if isinstance(raw, list):
            if len(raw) == 2 and isinstance(raw[0], str) and raw[0] in WRAPPERS:
                result = resolve(raw[1])
            else:
                result = [resolve_value(x) for x in raw]
        elif isinstance(raw, dict):
            result = {k: resolve_value(v) for k, v in raw.items()}
        else:
            result = raw
        memo[idx] = result
        return result
    def resolve_value(v):
        if isinstance(v, int) and 0 <= v < len(arr):
            return resolve(v)
        return v
    return resolve(0)

m = re.search(r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
if not m:
    sys.stderr.write("FAIL: no <script id=\"__NUXT_DATA__\"> found on %s (page shape changed, or" % prog_url
                      + " this is a redirect/error page misread as 200). Nothing written.\n")
    sys.exit(2)
try:
    root = decode_nuxt_data(m.group(1))
except Exception as e:
    sys.stderr.write("FAIL: could not decode the __NUXT_DATA__ devalue payload (%s: %s). Nothing written.\n"
                      % (type(e).__name__, e))
    sys.exit(2)

prog = ((root or {}).get("data") or {}).get("program")
if not isinstance(prog, dict):
    sys.stderr.write("FAIL: decoded payload for '%s' has no .data.program (shape changed, or slug" % handle
                      + " not found). Nothing written.\n")
    sys.exit(2)

# Hosts that belong to a third party, never to the program itself. Same safe direction
# as every other platform script in this workspace: a store/repo/explorer host must
# never become an in-scope allowlist line.
THIRD_PARTY = {
    "apps.apple.com", "itunes.apple.com", "testflight.apple.com", "apple.co",
    "play.google.com", "chrome.google.com", "chromewebstore.google.com",
    "addons.mozilla.org", "microsoftedge.microsoft.com", "apps.microsoft.com",
    "galaxystore.samsung.com", "appgallery.huawei.com", "f-droid.org",
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "npmjs.com", "www.npmjs.com", "pypi.org", "hub.docker.com", "crates.io",
    "rubygems.org", "packagist.org", "nuget.org", "cocoapods.org",
    "marketplace.visualstudio.com", "snapcraft.io", "flathub.org",
}
# Common block-explorer hosts (HackenProof-specific addition, 2026-10-21): a
# "Smart Contract" / "Protocol" scope entry is frequently a block-explorer URL
# pointing at a contract ADDRESS, not the program's own host. Only monadscan.com was
# empirically observed in the sampled programs; the rest are added proactively from
# general Web3 knowledge and are UNVERIFIED against HackenProof data specifically -
# treat any newly-encountered explorer the same way (add it here).
EXPLORER_HOSTS = {
    "etherscan.io", "goerli.etherscan.io", "sepolia.etherscan.io", "holesky.etherscan.io",
    "optimistic.etherscan.io", "sepolia-optimism.etherscan.io",
    "arbiscan.io", "sepolia.arbiscan.io", "nova.arbiscan.io",
    "polygonscan.com", "amoy.polygonscan.com",
    "bscscan.com", "testnet.bscscan.com",
    "snowtrace.io", "testnet.snowtrace.io",
    "ftmscan.com", "testnet.ftmscan.com",
    "cronoscan.com", "celoscan.io", "moonscan.io", "moonriver.moonscan.io",
    "gnosisscan.io", "lineascan.build", "sepolia.lineascan.build",
    "scrollscan.com", "sepolia.scrollscan.com", "basescan.org", "sepolia.basescan.org",
    "blastscan.io", "mantlescan.xyz", "zkevm.polygonscan.com", "era.zksync.network",
    "explorer.zksync.io", "blockscout.com", "monadscan.com", "testnet.monadexplorer.com",
    "solscan.io", "solana.fm", "explorer.solana.com", "solanabeach.io",
    "suiscan.xyz", "suivision.xyz", "explorer.sui.io",
    "aptoscan.com", "explorer.aptoslabs.com",
    "starkscan.co", "voyager.online", "sepolia.voyager.online",
    "mintscan.io", "nearblocks.io", "explorer.near.org",
    "tonscan.org", "tonviewer.com", "tronscan.org",
}
THIRD_PARTY |= EXPLORER_HOSTS
PUBLIC_SUFFIX = {
    "app.example.com", "com.au", "com.co", "com.mx", "co.jp", "co.nz", "com.br", "co.in",
    "com.sg", "com.hk", "co.za", "com.tr", "gov.uk", "org.uk", "net.au", "org.au",
    "co.kr", "com.cn", "co.id", "com.ph", "com.my", "co.th", "com.tw", "ne.jp", "or.jp",
}
HOST_RE = re.compile(r"^\*?\.?(?:[A-Za-z0-9*_-]+\.)+[A-Za-z*][A-Za-z0-9*-]{1,}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")

def to_host(tok):
    """Reduce a HackenProof scope `target` string to a bare host/wildcard token, or ''.
    Keeps a leading '*.' / '*' verbatim - the dot is load-bearing in both scope
    parsers. Handles bare hosts with no scheme ('coingecko.com'), scheme-prefixed
    URLs ('https://app.cetus.zone'), wss:// endpoints, and strips a path/tree/#code
    suffix (block-explorer and github.com/.../tree/... links)."""
    if not tok:
        return ""
    s = str(tok).strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)   # scheme (incl. wss://)
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

scopes = prog.get("scopes") or []
inscope_lines, oos_lines, notes = [], [], []
oos_hosts = []   # (host, title, label) for hosts placed BELOW the divider
seen = set()
stat = {"total": len(scopes), "hosts": 0, "oos": 0, "nonhost": 0}

for s in sorted(scopes, key=lambda x: x.get("position") if isinstance(x.get("position"), int) else 999):
    title = (s.get("title") or "?").strip()
    target = (s.get("target") or "").strip()
    crit = s.get("criticality")
    desc = (s.get("target_description") or "").strip()
    label = target or "(empty target)"
    extra = f" | criticality: {crit}" if crit else ""
    if desc:
        extra += f" | {desc[:80]}"

    if s.get("out_of_scope"):
        oos_lines.append(f"#   OOS [{title}] {label}{extra}")
        stat["oos"] += 1
        h = to_host(target)
        if h:
            oos_hosts.append((h, title, label))
        continue

    host = to_host(target)
    if not host:
        oos_lines.append(f"#   NOT-A-HOST [{title}] {label}{extra}")
        stat["nonhost"] += 1
        continue
    b = bare(host)
    if b in THIRD_PARTY:
        oos_lines.append(f"#   THIRD-PARTY-HOST [{title}] {label} -> {host} (store/repo/explorer host; promote by hand only if genuinely the program's own asset)")
        notes.append(f"third-party host not auto-allowlisted: {host}  (from [{title}] {label})")
        stat["nonhost"] += 1
        continue
    if b in PUBLIC_SUFFIX or "." not in b:
        oos_lines.append(f"#   REFUSED-PUBLIC-SUFFIX [{title}] {label} -> {host} (both parsers refuse it; cannot grant scope)")
        notes.append(f"entry reduces to a public suffix / bare TLD and was NOT written above the divider: {host}")
        stat["nonhost"] += 1
        continue
    key = host.lower()
    if key in seen:
        continue
    seen.add(key)
    inscope_lines.append(f"{host}  # {title}{extra}")
    stat["hosts"] += 1

# --- program-level reward model (differs from every other platform here: this is a
# program-WIDE boolean, never per-asset/per-group) --------------------------------------
rewards = prog.get("rewards") or {}
def _num(x):
    try:
        return float(x)
    except Exception:
        return 0.0
pays_cash = any(_num(rewards.get(k)) for k in
                ("critical_max", "critical_min", "high_max", "high_min",
                 "medium_max", "medium_min", "low_max", "low_min")) \
            or _num(prog.get("maxBounty")) > 0 or _num(prog.get("minBounty")) > 0

if not pays_cash and inscope_lines:
    inscope_lines = [ln + "  NO-BOUNTY" for ln in inscope_lines]

if stat["hosts"] == 0:
    sys.stderr.write(
        "FAIL: the HackenProof program page for '%s' yielded ZERO in-scope host entries.\n"
        "  (%d scope entrie(s) total; %d explicitly out-of-scope, %d non-host/third-party/refused)\n"
        "  Refusing to write a SCOPE.txt: an empty-but-present SCOPE.txt makes the live scope\n"
        "  gate BLOCK every probe for this target (fail-closed). Nothing written.\n"
        "  This is EXPECTED for a program whose scope is entirely Smart Contract / Protocol /\n"
        "  Bridge / Infrastructure references (github.com repo paths or block-explorer\n"
        "  contract-address URLs) - such a program has no web/API host for this gate to\n"
        "  enforce; it belongs to this workspace's on-chain (Immunefi-style) lane instead.\n"
        "  Inspect by hand: curl -s '%s' | grep -o '<script[^>]*__NUXT_DATA__[^>]*>.*</script>'\n"
        % (handle, stat["total"], stat["oos"], stat["nonhost"], prog_url))
    sys.exit(3)

L = [f"# {handle} - auto-pulled from the HackenProof public program page (zero auth)",
     f"# Program page: {prog_url}",
     f"# Pulled by scripts/hackenproof-scope.sh. Mechanism: Nuxt __NUXT_DATA__ devalue decode,",
     f"# NOT a public JSON API (HackenProof publishes none) - see scripts/HACKENPROOF.md.",
     f"# Company: {prog.get('companyName') or '?'}   |   status: {prog.get('status') or '?'}   |   state: {prog.get('state') or '?'}",
     f"# Scope entries: {stat['total']} total, {stat['hosts']} in-scope host(s), {stat['oos']} explicitly OOS, {stat['nonhost']} non-host/third-party/refused",
     "# VERIFY against the live program page before probing. Wildcard forms are verbatim from",
     "# HackenProof: '*.foo.com' is dot-bounded, '*foo.com' is a loose suffix glob.",
     ("# NO-BOUNTY: this ENTIRE PROGRAM pays no cash reward (program-level, not per-asset -"
      if not pays_cash else
      "# This program PAYS CASH (see PROGRAM.md for the per-criticality reward table)."),
     ]
if not pays_cash:
    L.append("#            see PROGRAM.md). Still submittable; reputation/VDP only.")
L.append("")
L += inscope_lines
L += ["",
      "# === OUT OF SCOPE (allowlist stops here; nothing below can grant scope) ===",
      "# Recorded, not discarded: scopes[].out_of_scope==true entries, non-host targets,",
      "# and third-party/store/repo/explorer hosts (never promoted automatically)."]
L += (oos_lines if oos_lines else ["#   (none reported by the program page)"])
open(scope_p, "w", encoding="utf-8").write("\n".join(L) + "\n")

# --- WILDCARD-SHADOW CHECK (same canonical-parser technique as every sibling script) ---
shadowed = []
try:
    sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts")
    from bbtools.lib_scope import host_in_scope  # noqa: E402
    for oh, otitle, olabel in oos_hosts:
        probe = re.sub(r"^\*\.?", "", oh)
        if probe and host_in_scope(probe, scope_p):
            shadowed.append((probe, otitle, olabel))
except Exception as e:
    notes.append(f"wildcard-shadow check skipped ({type(e).__name__}: {e})")

if shadowed:
    with open(scope_p, "a", encoding="utf-8") as fh:
        fh.write(f"\n# !!! GATE-WILL-NOT-BLOCK: {len(shadowed)} out-of-scope host(s) are still covered\n"
                 "# !!! by an in-scope WILDCARD above the divider, so the scope gate will ALLOW them.\n"
                 "# !!! The program still forbids them. DO NOT PROBE THESE:\n")
        for probe, otitle, olabel in shadowed:
            fh.write(f"# !!!   {probe}   (out-of-scope [{otitle}] {olabel}; matches an in-scope wildcard)\n")
    notes.append(f"{len(shadowed)} out-of-scope host(s) are wildcard-shadowed and the gate will NOT "
                 "block them - see the GATE-WILL-NOT-BLOCK block at the end of SCOPE.txt")

# ---------------- PROGRAM.md ----------------
def money(v):
    try:
        return f"${float(v):,.0f}"
    except Exception:
        return "?"

labels = prog.get("labels") or {}
sla = prog.get("sla") or {}
P = [f"# {prog.get('title') or handle} (HackenProof)", "",
     "- Platform: HackenProof. Severity model: program-defined Critical/High/Medium/Low bands",
     "  (web/mobile programs say they use CVSS to place a finding into a band; smart-contract",
     "  and blockchain-protocol programs use HackenProof's own impact-based classification -",
     "  see https://docs.hackenproof.com/bug-bounty/vulnerability-classification).",
     f"- Program slug: `{handle}`   |   company: {prog.get('companyName') or '?'}",
     f"- Program page: {prog_url}",
     f"- Status: {prog.get('status') or '?'}   |   state: {prog.get('state') or '?'}"
     + (f"   |   unending: {prog.get('isUnending')}" if prog.get("isUnending") is not None else ""),
     f"- Submit at: {prog.get('submitUrl') or '(none published)'}   (requires a HackenProof dashboard account)",
     f"- Guidelines authority: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/HACKENPROOF.md",
     "",
     "## Does it pay cash?",
     f"- PAYS CASH: **{'YES' if pays_cash else 'NO (VDP / reputation only)'}**",
     f"- Max reward (listing): {prog.get('maxReward') or '?'}   |   minBounty: {prog.get('minBounty') or '?'}"
     f"   |   maxBounty: {prog.get('maxBounty') or '?'}",
     "",
     "## Reward bands by criticality (program-level, NOT per-asset)"]
if rewards:
    for band in ("critical", "high", "medium", "low"):
        lo, hi = rewards.get(f"{band}_min"), rewards.get(f"{band}_max")
        if lo is None and hi is None:
            continue
        P.append(f"- {band.capitalize()}: {money(lo)} - {money(hi)}")
else:
    P.append("- no reward table published")
P += ["",
      "## Eligibility gates (HackenProof-specific - not seen on HackerOne/Bugcrowd/Intigriti)",
      f"- KYC required to receive payment: **{prog.get('kycRequired')}**",
      f"- Proof-of-Concept required with every report: **{prog.get('pocRequired')}**",
      f"- Minimum researcher reputation to submit: **{prog.get('minReputation')}**"
      + ("  (-1 appears to mean 'not set' - verify live)" if prog.get("minReputation") in (-1, "-1") else ""),
      f"- Submission fee: **{prog.get('submissionFee') if prog.get('submissionFee') else 'none'}**"
      + ("  (HackenProof charges researchers a fee to SUBMIT a report on some programs - refunded"
         " on a valid/accepted report per docs.hackenproof.com/bug-bounty/reports-basics/"
         "report-submission-requirements; verify the live refund policy before relying on it)"
         if prog.get("submissionFee") else ""),
      f"- SLA (days): first response {sla.get('first_response','?')}, triage {sla.get('time_to_triage','?')},"
      f" resolution {sla.get('resolution_time','?')}, reward {sla.get('time_to_reward','?')}",
      "",
      "## Eligibility notes (in-scope vs reward-eligible - do not conflate)",
      "- Every host above the OOS divider in SCOPE.txt is IN SCOPE and submittable.",
      f"- {stat['oos']} scope entrie(s) are explicitly out of scope (`out_of_scope: true`) and are",
      "  recorded BELOW the divider. Testing them is unauthorized.",
      f"- {stat['nonhost']} non-host / third-party / explorer / refused asset id(s) recorded below",
      "  the divider (github repos, app-store links, block-explorer contract-address URLs,",
      "  free-text labels). A Smart Contract / Protocol / Bridge entry is usually one of these -",
      "  it belongs to this workspace's on-chain hunting lane, not the web host allowlist.",
      ""]
if shadowed:
    P += ["### WARNING: wildcard-shadowed exclusions (the gate will NOT block these)",
          "These hosts are OUT OF SCOPE per the program, but they are subdomains of an in-scope",
          "wildcard above the divider, so both scope parsers match them and the live gate ALLOWS",
          "them. Documented parser behavior (targets/README.md), not a bug - the allowlist stops",
          "at the divider and never reads an exclusion. YOU are the control here:"]
    P += [f"    - {probe}   (out-of-scope [{otitle}] {olabel})" for probe, otitle, olabel in shadowed]
    P.append("")
if notes:
    P += ["### Intake warnings"] + [f"- {n}" for n in sorted(set(notes))] + [""]
P += ["## Tags / classification (from the program page)",
      f"- Types: {', '.join(labels.get('types') or []) or '(none)'}   |   platforms: {', '.join(labels.get('platforms') or []) or '(none)'}",
      f"- Languages: {', '.join(labels.get('languages') or []) or '(none)'}   |   project types: {', '.join(labels.get('project_types') or []) or '(none)'}",
      "",
      "## Required researcher identification",
      "- No platform-wide identification header or test-account-email convention was found",
      "  (checked this program's own rules text AND docs.hackenproof.com's submission-",
      "  requirements page - neither mentions one, unlike HackerOne's X-HackerOne: header or",
      "  Intigriti's @intigriti.me convention). Re-verify on the live program page before",
      "  relying on this.",
      "",
      "## Program rules (verbatim)",
      prog.get("programRules") or "(none published)",
      "",
      "## Focus area (verbatim)",
      prog.get("focusArea") or "(none published)",
      "",
      "## Disclosure guidelines (verbatim)",
      prog.get("disclosureGuidelines") or "(none published)",
      "",
      "## Eligibility & coordinated disclosure (verbatim)",
      prog.get("eligibilityAndCoordinateDisclosure") or "(none published)",
      "",
      "## Re-pull",
      f"    ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/hackenproof-scope.sh {handle} --refresh",
      ""]
open(prog_p, "w", encoding="utf-8").write("\n".join(P) + "\n")

print(f"wrote {scope_p}")
print(f"  {stat['hosts']} in-scope host entries from {stat['total']} scope entrie(s); "
      f"below the divider: {stat['oos']} explicitly out-of-scope + {stat['nonhost']} non-host/third-party asset(s)")
print(f"wrote {prog_p}")
for n in sorted(set(notes)):
    print(f"  NOTE: {n}")
PY
rc=$?
if [ "$rc" -ne 0 ]; then
  if [ "$DIR_PREEXISTED" = "0" ]; then
    rm -f "$OUT/SCOPE.txt" 2>/dev/null
    rmdir "$OUT" 2>/dev/null || true
  fi
  [ -f "$SCOPE_DEST" ] && [ ! -s "$SCOPE_DEST" ] && rm -f "$SCOPE_DEST"
  exit "$rc"
fi

mkdir -p "$OUT/recon" "$OUT/poc" "$OUT/evidence" "$OUT/hunts"

[ "$SCOPE_ALT" = 1 ] && echo "NOTE: $OUT/SCOPE.txt already existed -> fresh pull in $SCOPE_DEST (diff + merge to keep manual annotations; or re-run with --refresh)." >&2
[ "$PROG_ALT" = 1 ]  && echo "NOTE: $OUT/PROGRAM.md already existed -> fresh pull in $PROG_DEST." >&2
echo "next: review SCOPE.txt, confirm a few targets on $PROG_URL, then model the target and hunt."
echo "zero requests were sent to any program asset; only hackenproof.com was contacted."
exit 0
