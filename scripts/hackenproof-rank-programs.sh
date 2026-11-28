#!/usr/bin/env bash
# hackenproof-rank-programs.sh [--all] [--max-pages N]
#
# Rank every PUBLIC HackenProof bug-bounty program by an "easy + pays + fresh + not
# oversubmitted" EV proxy, to pick the next target. Mirrors scripts/bugcrowd-rank-programs.sh
# and scripts/h1-rank-programs.sh in shape and intent. Read-only, ZERO AUTH, talks only
# to hackenproof.com.
#
# MECHANISM (verified live 2026-10-21; see scripts/HACKENPROOF.md for the full writeup):
# HackenProof has no public JSON API. The program directory is a Nuxt 3 SSR page at
#   GET https://hackenproof.com/programs?page=N
# which embeds its data as a <script id="__NUXT_DATA__"> "devalue"-encoded blob (a flat
# JSON array with internal integer references - see decode_nuxt_data() in
# hackenproof-scope.sh for the generic resolver, duplicated here so this script stays
# self-contained). After decoding, .data["programs-api-bounty"] = {programs:[...10 per
# page...], total_items, next_page, prev_page, filter_attributes}. 10 programs per page,
# 325 total on 2026-10-21 -> 33 pages.
#
# filter_attributes documents query-param NAMES the UI can filter on (order_by,
# with_project_types, by_status, by_kyc, by_poc, reputation_up_to, ...) but these were
# TESTED LIVE as a plain query string and had NO EFFECT (?with_project_types=DEX and
# ?order_by=max_bounty_float both returned the byte-identical unfiltered, default-order
# first page). Only ?page=N was confirmed to work. So this script pages through
# EVERYTHING and filters/sorts CLIENT-SIDE after decoding, rather than trusting a
# server-side filter that could not be made to respond differently.
#
# Each listing-row program object carries: slug, name, description, state, status,
# startDate, lastUpdated, isUnending, endDate, submittedReports, reward (string, e.g.
# "$10,000" - this is the program's max reward), rewardPaid, tags{platforms,
# project_types, types, languages}, triagedByHackenproof, programOfTheWeek, dualDefence,
# isAudit, scopeReview, activityStatus{name, downtime}. It does NOT carry kycRequired /
# pocRequired / minReputation / submissionFee or the per-asset scope list - those are
# only on the per-program detail page. Gate any pick through the real eligibility +
# scope check before hunting: scripts/hackenproof-scope.sh <slug>
#
# Hard filters (default; --all keeps everything):
#   pays cash        -> reward parses to a nonzero USD amount
#   not an audit      -> isAudit == false (HackenProof runs separate "Audit"/
#                        "DualDefence Audit" contests judged differently from a bug
#                        bounty; --all includes them)
#   accepting         -> activityStatus.name == "Active" (a "Completed" program is a
#                        past campaign, not open for new submissions)
#
# Criteria -> signal mapping:
#   payout ceiling   -> reward string parsed to a number           (score, bucketed)
#   saturation       -> submittedReports                           (penalty)
#   quality signal    -> triagedByHackenproof, programOfTheWeek, dualDefence (score)
#   novelty/commerce  -> keyword match on name+description          (score)
#   freshness         -> lastUpdated parsed, days-ago bucketed       (score)
#   dead-listed       -> .claude/state/hunt-loop/no-yield.txt        (row dropped)
#
# SCORE is an ordering heuristic, not a promise, and does NOT reflect real scope
# breadth or the KYC/PoC/reputation/submission-fee eligibility gates (those need the
# per-program detail pull). Gate any pick through the real eligibility check before
# hunting: scripts/hackenproof-scope.sh <slug>
#
# Full platform notes: ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/HACKENPROOF.md
set -u

SHOW_ALL=0
MAX_PAGES=40   # the directory was 33 pages on 2026-10-21; hard stop well above that
while [ "$#" -gt 0 ]; do
  case "$1" in
    --all) SHOW_ALL=1; shift ;;
    --max-pages) MAX_PAGES="${2:-40}"; shift 2 ;;
    -h|--help)
      echo "usage: hackenproof-rank-programs.sh [--all] [--max-pages N]" >&2
      echo "  --all         keep audits and non-cash / inactive programs too (no hard filters)" >&2
      echo "  --max-pages N hard page-count ceiling (default 40; directory is ~33 pages)" >&2
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
case "$MAX_PAGES" in ''|*[!0-9]*) echo "--max-pages takes a number" >&2; exit 2 ;; esac

command -v curl    >/dev/null 2>&1 || { echo "need curl" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "need python3" >&2; exit 1; }

SITE="https://hackenproof.com"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
TMPD=$(mktemp --directory "${TMPDIR:-/tmp}/hp-rank.XXXXXX") || { echo "mktemp failed" >&2; exit 2; }
trap 'rm -rf "$TMPD"' EXIT

# --- page through the public directory, one HTML fetch per page (?page=N confirmed) ----
echo "# Paging https://hackenproof.com/programs?page=N (devalue-decoded; no working" >&2
echo "# server-side filter was found, so this collects everything and filters locally) ..." >&2
page=1
while [ "$page" -le "$MAX_PAGES" ]; do
  out="$TMPD/p$page.html"
  code=$(curl -s --max-time 30 -A "$UA" -o "$out" -w '%{http_code}' "$SITE/programs?page=$page")
  if [ "$code" != "200" ]; then
    echo "stopping at page $page (HTTP $code)" >&2
    break
  fi
  n=$(grep -c '__NUXT_DATA__' "$out" 2>/dev/null || true)
  [ "$n" = "0" ] && { echo "stopping at page $page (no __NUXT_DATA__ found)" >&2; break; }
  page=$((page + 1))
done
got_pages=$((page - 1))
[ "$got_pages" -lt 1 ] && { echo "no pages fetched (network/egress, or page shape changed)" >&2; exit 2; }
echo "# fetched $got_pages page(s)" >&2

# --- dead-list (mirror of bugcrowd-rank-programs.sh / h1-rank-programs.sh) --------------
NOYIELD="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop/no-yield.txt"
DEAD=""
[ -f "$NOYIELD" ] && DEAD=$(grep -vE '^[[:space:]]*#' "$NOYIELD" 2>/dev/null | awk '{print $1}' | grep -vE '^$' | tr '\n' ' ')

RESULT="$TMPD/result.tsv"
SHOW_ALL="$SHOW_ALL" DEAD_SLUGS="$DEAD" GOT_PAGES="$got_pages" python3 - "$TMPD" > "$RESULT" <<'PY'
import datetime, json, os, re, sys

tmpd = sys.argv[1]
show_all = os.environ.get("SHOW_ALL") == "1"
dead = set(s.lower() for s in os.environ.get("DEAD_SLUGS", "").split() if s)
got_pages = int(os.environ.get("GOT_PAGES", "0"))

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
        memo[idx] = None
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

programs = {}
total_items = None
for i in range(1, got_pages + 1):
    path = os.path.join(tmpd, f"p{i}.html")
    if not os.path.exists(path):
        continue
    html = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r'<script[^>]*id="__NUXT_DATA__"[^>]*>(.*?)</script>', html, re.S)
    if not m:
        continue
    try:
        root = decode_nuxt_data(m.group(1))
    except Exception as e:
        sys.stderr.write(f"WARN: could not decode page {i} ({type(e).__name__}: {e})\n")
        continue
    pb = (root.get("data") or {}).get("programs-api-bounty") or {}
    if total_items is None:
        total_items = pb.get("total_items")
    for p in (pb.get("programs") or []):
        slug = p.get("slug")
        if slug and slug not in programs:
            programs[slug] = p

sys.stderr.write(f"# decoded {len(programs)} unique program(s) across {got_pages} page(s)"
                  + (f" (directory reports total_items={total_items})" if total_items else "") + "\n")
if not programs:
    sys.stderr.write("no programs decoded - page shape may have changed\n")
    sys.exit(2)

USD_RE = re.compile(r"[\d,]+(?:\.\d+)?")
def usd(s):
    if not s:
        return 0.0
    m = USD_RE.search(str(s))
    if not m:
        return 0.0
    try:
        return float(m.group(0).replace(",", ""))
    except Exception:
        return 0.0

def days_ago(s):
    # observed formats: "19 Oct 2026", "14 Oct 2026"
    if not s:
        return None
    for fmt in ("%d %b %Y",):
        try:
            d = datetime.datetime.strptime(s, fmt).date()
            return (datetime.date.today() - d).days
        except Exception:
            continue
    return None

rows = []
for slug, p in programs.items():
    if slug.lower() in dead:
        continue
    reward_usd = usd(p.get("reward"))
    is_audit = bool(p.get("isAudit"))
    active = ((p.get("activityStatus") or {}).get("name") or "") == "Active"
    if not show_all:
        if reward_usd <= 0:
            continue
        if is_audit:
            continue
        if not active:
            continue
    name = p.get("name") or slug
    desc = p.get("description") or ""
    tags = p.get("tags") or {}
    types = tags.get("types") or []
    ptypes = tags.get("project_types") or []
    nm = f"{name} {desc}"
    novel = bool(re.search(r"web3|onchain|chain|protocol|defi|token|nft|wallet|\bai\b|\bml\b|llm|genai|copilot|agent", nm, re.I))
    commerce = bool(re.search(r"checkout|cart|coupon|payment|marketplace|booking|order|shop|commerce|bank|fintech|exchange|cex|dex", nm, re.I))
    try:
        submitted = int(p.get("submittedReports") or 0)
    except Exception:
        submitted = 0
    triaged = bool(p.get("triagedByHackenproof"))
    potw = bool(p.get("programOfTheWeek"))
    dual = bool(p.get("dualDefence"))
    da = days_ago(p.get("lastUpdated"))

    score = 0
    if reward_usd >= 100000: score += 40
    elif reward_usd >= 25000: score += 32
    elif reward_usd >= 10000: score += 24
    elif reward_usd >= 2000: score += 16
    elif reward_usd > 0: score += 8
    score += 10 if triaged else 0
    score += 8 if potw else 0
    score += 15 if novel else 0
    score += 10 if commerce else 0
    score -= min(int(submitted / 10), 25)   # saturation penalty
    if da is not None:
        if da <= 7: score += 15
        elif da <= 30: score += 8
        elif da <= 90: score += 3

    flags = []
    if potw: flags.append("POTW")
    if triaged: flags.append("TRIAGED")
    if dual: flags.append("DUAL")
    if is_audit: flags.append("AUDIT")
    if novel: flags.append("NOVEL")
    if commerce: flags.append("COMMERCE")
    if not active: flags.append("INACTIVE")

    rows.append({
        "score": score, "reward": p.get("reward") or "-",
        "status": (p.get("activityStatus") or {}).get("name") or "?",
        "submitted": submitted, "flags": ",".join(flags) or "-",
        "types": "/".join(types) or (",".join(ptypes) or "-"),
        "slug": slug, "name": name,
    })

rows.sort(key=lambda r: r["score"], reverse=True)
print("\t".join(["SCORE", "REWARD", "STATUS", "SUBMITTED", "FLAGS", "TYPES", "SLUG", "NAME"]))
for r in rows:
    print("\t".join(str(r[k]) for k in ("score", "reward", "status", "submitted", "flags", "types", "slug", "name")))
PY
status=$?
column -t -s $'\t' "$RESULT"
echo "# next: scripts/hackenproof-scope.sh <SLUG>   then scripts/intake.sh verify <SLUG>" >&2
exit "$status"
