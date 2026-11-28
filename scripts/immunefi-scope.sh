#!/usr/bin/env bash
# immunefi-scope.sh <program-slug> [program-url] [--refresh]
# Auto-fetch an Immunefi smart-contract program's ASSETS + RULES (zero auth) and write
# targets/<slug>/SCOPE.txt + PROGRAM.md. Immunefi is a Next.js App-Router SPA; the program data
# streams inline as RSC flight chunks, so scripts/immunefi-fetch.py pulls the in-scope contract
# addresses, chains, payout table, KYC flag, primacy and launch date with no API token. If the
# fetch fails (network/403/CF) it falls back to a hand-paste skeleton. --refresh overwrites files.
# Full platform guidelines: scripts/IMMUNEFI.md
set -u

SLUG=""; URL=""; REFRESH=0
for a in "$@"; do
  case "$a" in
    --refresh) REFRESH=1 ;;
    http*) URL="$a" ;;
    -*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) [ -z "$SLUG" ] && SLUG="$a" ;;
  esac
done
if [ -z "$SLUG" ]; then
  echo "usage: immunefi-scope.sh <program-slug> [program-url] [--refresh]" >&2
  echo "example: immunefi-scope.sh veda" >&2
  exit 1
fi
[ -z "$URL" ] && URL="https://immunefi.com/bug-bounty/${SLUG}/information/"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/targets/$SLUG"
mkdir -p "$OUT"

# --- auto-fetch the program (zero auth); empty JSON on failure -----------------------------------
JSON="$(python3 "$ROOT/scripts/immunefi-fetch.py" "$SLUG" 2>/dev/null)"
if ! echo "$JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("asset_count") else 1)' 2>/dev/null; then
  echo "note: live fetch returned no assets (network/403/CF or non-SC program). Falling back to skeleton."
  JSON=""
fi

skip_or_refresh() {  # $1=path -> 0 = write it, 1 = leave it
  [ ! -f "$1" ] && return 0
  [ "$REFRESH" = "1" ] && { echo "refresh: overwriting $1"; return 0; }
  echo "note: $1 already exists, leaving it untouched (use --refresh to overwrite)"; return 1
}

# --- SCOPE.txt: one in-scope identifier per line (addresses + chains + fork RPC hosts) -----------
if skip_or_refresh "$OUT/SCOPE.txt"; then
  if [ -n "$JSON" ]; then
    echo "$JSON" | SLUG="$SLUG" URL="$URL" python3 - "$OUT/SCOPE.txt" <<'PY'
import json, os, sys
d = json.load(sys.stdin); out = sys.argv[1]
slug, url = os.environ["SLUG"], os.environ["URL"]
L = [f"# {slug} - Immunefi smart-contract program. Auto-filled by immunefi-scope.sh from the live page.",
     f"# Program page: {url}",
     f"# Fetched: launch={d.get('launchDate')} assets={d['asset_count']} kyc={d.get('kyc')} primacyOfImpact={d.get('primacyOfImpact')}",
     "# FORK-ONLY: test on a local fork (Foundry anvil / vm.createSelectFork). Mainnet or public",
     "# testnet testing = permanent ban. Lines starting with # are ignored by scope-gate.", "",
     "# --- in-scope chains ---"]
L += sorted(c for c in d["chains"])
L += ["", "# --- fork RPC hosts to fork from (public archive; researcher-controlled ok) ---"]
L += sorted(f"{v['rpc'].split('//')[-1]}   # {c}" for c, v in d["chains"].items() if v.get("rpc"))
L += ["", "# --- block-explorer hosts (read-only scope research) ---"]
hosts = sorted({a["url"].split("/")[2] for a in d["assets"] if a.get("url")})
L += hosts
L += ["", f"# --- in-scope contract addresses ({d['asset_count']}), one per line for scope-gate ---"]
for a in d["assets"]:
    if a.get("address"):
        tag = "  # POI" if a.get("primacyOfImpact") else ""
        L.append(f"{a['address']}   # {a.get('chain')} {a.get('name') or ''}{tag}".rstrip())
L += ["", "# === OUT OF SCOPE + impacts-in-scope + payouts: see PROGRAM.md ==="]
open(out, "w").write("\n".join(L) + "\n")
print(f"wrote {out} ({d['asset_count']} addresses, {len(d['chains'])} chains)")
PY
  else
    {
      echo "# $SLUG - Immunefi smart-contract program. Scaffolded (live fetch failed - hand-paste)."
      echo "# Program page: $URL"
      echo "# FORK-ONLY: local fork only; mainnet/public-testnet testing = permanent ban."
      echo "# PASTE from the Scope tab, one per line: each 0x... address, each chain, each fork RPC host."
      echo "# Lines starting with # are ignored by scope-gate."
      echo ""
      echo "# --- in-scope contract addresses ---"
      echo "# 0x0000000000000000000000000000000000000000"
      echo "# --- in-scope chains ---"
      echo "# ethereum"
      echo "# --- fork RPC hosts ---"
      echo "# eth.llamarpc.com"
      echo ""
      echo "# === OUT OF SCOPE: see PROGRAM.md ==="
    } > "$OUT/SCOPE.txt"
    echo "wrote $OUT/SCOPE.txt (skeleton - paste the asset list, or retry with a working egress)"
  fi
fi

# --- PROGRAM.md: auto-filled payout/KYC/primacy + Immunefi SC severity model + intake checklist --
if skip_or_refresh "$OUT/PROGRAM.md"; then
  RULES="(live fetch failed - fill the payout/KYC/primacy fields from the program page by hand)"
  if [ -n "$JSON" ]; then
    RULES="$(echo "$JSON" | python3 - <<'PY'
import json, sys
d = json.load(sys.stdin)
lines = [f"- Launch: {d.get('launchDate')}  |  KYC required: {d.get('kyc')}  |  Primacy-of-Impact: {d.get('primacyOfImpact')}",
         f"- Assets in scope: {d['asset_count']} across chains " + ", ".join(f"{c} ({v['count']})" for c, v in sorted(d["chains"].items())),
         "- Payouts (from the live page):"]
for p in d["payouts"]:
    pct = f", {p['pctFunds']}% of funds at risk" if p.get("pctFunds") else ""
    lines.append(f"    {p['severity']} / {p['assetType']}: ${p['min']:,} - ${p['max']:,} ({p['model']}{pct})")
print("\n".join(lines))
PY
)"
  fi
  cat > "$OUT/PROGRAM.md" <<EOF
# $SLUG (Immunefi)

- Platform: Immunefi (smart-contract / on-chain). Severity = IMPACT-based, NOT CVSS.
- Program page: $URL
- Guidelines authority: scripts/IMMUNEFI.md

## Program facts (auto-fetched - re-run \`immunefi-scope.sh $SLUG --refresh\` to update)
$RULES

## Intake checklist (verify the auto-fetched values, fill the rest from the page)
- [ ] PRIMACY: Primacy of Impact vs Primacy of Rules (decides if an unlisted contract is eligible)
- [ ] ASSETS: confirmed in SCOPE.txt (auto-filled) - spot-check a few on the Scope tab
- [ ] FORK RPC: archive RPC host(s) present in SCOPE.txt (auto-suggested public RPCs)
- [ ] PAYOUT: confirm the critical "% of funds at risk, min \$Y" formula above
- [ ] KYC: required before payout (passport + proof of residence + wallet; W-9 for US persons)
- [ ] DISCLOSURE category (approval-required?): __________

## Smart-contract impact categories (Immunefi v2.3 - the CANDIDATE must terminate at one)
CRITICAL: direct theft of funds (not yield); permanent freeze of funds/NFTs; unauthorized NFT mint;
  manipulable RNG abusing principal/NFT; NFT-representation alteration; protocol insolvency;
  governance vote manipulation that changes the voted outcome.
HIGH: theft of unclaimed yield/royalties; permanent freeze of unclaimed yield/royalties; temporary
  freeze of principal funds/NFTs.
MEDIUM: contract unable to operate (no token funds); block stuffing; griefing (no attacker profit);
  theft of gas; unbounded gas consumption.
LOW: fails to deliver promised returns without value loss.

## PoC + ship rules (hard-enforced - see scripts/IMMUNEFI.md section 7 for the six gates)
- PoC MANDATORY. Runnable Foundry .t.sol or Hardhat fork test at a pinned block, real deployed
  addresses, terminal-state assertion. Unit-test/mock PoC = rejected.
- FORK-ONLY. Mainnet or public-testnet testing = permanent ban.
- Report = the Immunefi 7-section dashboard form (Title / Asset / Impact / Bug Description / PoC /
  Recommendation / References). Draft to reports/drafts/$SLUG/; the operator submits manually.
- Disclosure project-gated: no public disclosure until written approval.
EOF
  echo "wrote $OUT/PROGRAM.md"
fi

echo ""
if [ -n "$JSON" ]; then
  echo "done: $SLUG auto-filled from the live page (assets + payouts + KYC + primacy)."
  echo "next: verify a few addresses on the Scope tab, then model (target-modeler) + hunt with the"
  echo "EVM layer specialists. Severity is impact-based; PoC is fork-only. Full rules: scripts/IMMUNEFI.md"
else
  echo "next: live fetch failed - hand-fill SCOPE.txt + the PROGRAM.md checklist from the page, or"
  echo "retry from a working egress:  curl -sL 'https://immunefi.com/bug-bounty/$SLUG/information/' \\"
  echo "    | python3 scripts/immunefi-fetch.py $SLUG --stdin   (then paste the JSON assets)"
fi
