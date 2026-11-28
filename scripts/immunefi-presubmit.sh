#!/usr/bin/env bash
# immunefi-presubmit.sh - the Immunefi "bullet" gate.
#
# Run before declaring an Immunefi draft READY for the operator's MANUAL dashboard submit.
# Immunefi allows ONE submit per week, so the draft must be a bullet that cannot miss:
# in-scope, correctly sized, and reproducible from a clean environment.
#
# Enforces three rules the operator set 2026-06-28 (after berachain #83336 closed OOS in 29 min):
#   1. NEVER submit out-of-scope. The declared asset must be a LISTED in-scope asset, and
#      no component the report blames may be an OOS/unlisted sibling. (#83336 died because
#      the declared asset was bera-reth but the fix lands in bera-geth, an UNLISTED client,
#      and "Upstream reth bugs" are OOS - a laundered OOS root cause.)
#   2. The PoC gist must be VERIFIED and reproducible from ANY environment: no host-path /
#      username / VPS leaks, a Docker-first repro present, and a clean-container run confirmed.
#      (C1's native repro failed because $HOME/bin/cc shadowed the real compiler;
#      Docker-first is the fix.)
#   3. Immunefi reports are 2500-3000 words - OVERRIDES the workspace <1000-word default.
#
# Mechanical checks hard-FAIL (exit non-zero). Judgment checks the script cannot decide
# print as CONFIRM / MANUAL-VERIFY and DO NOT fail the run - report-killer's Primacy-of-Rules
# gate and a triage-validator clean-container run own those. A PASS here is necessary, not
# sufficient: the judgment CONFIRM lines must still be cleared by a human/agent.
#
# Usage:  immunefi-presubmit.sh <draft_file> [gist_dir]
#         immunefi-presubmit.sh --self-check
# Exit 0 = all mechanical checks pass; 1 = a mechanical FAIL; 2 = bad invocation.
set -u
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
WMIN=2500
WMAX=3000

FAIL=0
hd()   { printf '\n== %s ==\n' "$*"; }
ok()   { printf '  PASS    %s\n' "$*"; }
bad()  { printf '  FAIL    %s\n' "$*"; FAIL=1; }
warn() { printf '  WARN    %s\n' "$*"; }
note() { printf '  CONFIRM %s\n' "$*"; }

# gate DRAFT SCOPE GIST  - the whole gate, parameterized so --self-check can drive it.
gate() {
  local DRAFT="$1" SCOPE="$2" GIST="${3:-}"
  FAIL=0

  printf 'draft:   %s\n' "$DRAFT"
  printf 'scope:   %s\n' "$SCOPE"
  printf 'gist:    %s\n' "${GIST:-<none passed>}"

  # platform sanity
  if [ -f "$SCOPE" ] && grep -qi 'immunefi\.com' "$SCOPE"; then
    :
  else
    warn "SCOPE.txt missing or does not cite immunefi.com - confirm this is an Immunefi target"
  fi

  hd "1. word count (Immunefi band ${WMIN}-${WMAX})"
  local wc
  wc=$(wc -w < "$DRAFT" | tr -d ' ')
  if   [ "$wc" -lt "$WMIN" ]; then bad "words=$wc < $WMIN - too thin for a one-shot bullet; deepen root-cause / PoC / impact"
  elif [ "$wc" -gt "$WMAX" ]; then warn "words=$wc > $WMAX - compress toward $WMIN-$WMAX (no hard dashboard max; C1 ran 3359)"
  else ok "words=$wc in band"
  fi

  hd "2. seven dashboard sections present"
  local s miss=""
  for s in TITLE ASSET IMPACT "BUG DESCRIPTION" "PROOF OF CONCEPT" RECOMMENDATION REFERENCES; do
    grep -qiE "^#{1,3}[[:space:]]+$s" "$DRAFT" || miss="$miss '$s'"
  done
  [ -n "$miss" ] && bad "missing section(s):$miss" || ok "all 7 sections present"

  hd "3. asset in scope (Primacy of Rules - the #83336 gate)"
  if [ ! -f "$SCOPE" ]; then
    bad "SCOPE.txt not found - cannot verify asset scope"
  else
    local inscope oos addrs repos tok
    inscope=$(grep -vE '^[[:space:]]*OOS' "$SCOPE")          # haystack of in-scope lines
    oos=$(grep -E '^[[:space:]]*OOS' "$SCOPE")               # explicitly out-of-scope lines
    # component-identity tokens in the draft: 0x addresses + github repo paths
    addrs=$(grep -oiE '0x[0-9a-f]{40}' "$DRAFT" | sort -u)
    repos=$(grep -oiE 'github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+' "$DRAFT" | sed 's#\.git$##' | sort -u)

    # 3a: any cited component that is EXPLICITLY OOS = hard fail (laundered OOS root cause)
    local hitoos=""
    for tok in $addrs $repos; do
      printf '%s\n' "$oos" | grep -qiF "$tok" && hitoos="$hitoos $tok"
    done
    [ -n "$hitoos" ] && bad "draft cites EXPLICITLY out-of-scope component(s):$hitoos"

    # 3b: declared ## ASSET must match an in-scope token. Hard-fail only when the ASSET
    # section HAS a 0x/github token that is NOT in scope; when it has NONE (non-EVM
    # target, e.g. Clarity/Cairo named contracts), drop to CONFIRM - the script cannot
    # machine-check it, report-killer 2b owns it.
    local assetblk declared_ok=0 asset_tokens
    assetblk=$(awk 'BEGIN{p=0} /^#{1,3}[[:space:]]+ASSET([[:space:]]|$)/{p=1;next} /^#{1,3}[[:space:]]/{if(p)exit} p{print}' "$DRAFT")
    asset_tokens=$(printf '%s\n' "$assetblk" | grep -oiE '0x[0-9a-f]{40}|github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+' | sed 's#\.git$##' | sort -u)
    if [ -z "$asset_tokens" ]; then
      note "## ASSET names no machine-checkable 0x/github token (non-EVM target?) - manually confirm the declared asset is a LISTED in-scope asset"
    else
      for tok in $asset_tokens; do
        printf '%s\n' "$inscope" | grep -qiF "$tok" && { declared_ok=1; ok "declared asset token in scope: $tok"; }
      done
      [ "$declared_ok" -eq 0 ] && bad "the ## ASSET section's 0x/github token(s) are not on any non-OOS SCOPE line"
    fi

    # 3c: components referenced but NOT a listed asset -> force a human confirm
    local unlisted=""
    for tok in $addrs $repos; do
      printf '%s\n' "$inscope" | grep -qiF "$tok" && continue
      printf '%s\n' "$oos"     | grep -qiF "$tok" && continue
      unlisted="$unlisted $tok"
    done
    [ -n "$unlisted" ] && note "referenced but NOT a listed asset (confirm none is the at-fault component):$unlisted"
    note "AT-FAULT COMPONENT: name the file/contract whose code MUST change to fix this. It must BE the declared in-scope asset, not a sibling. (#83336: fix lived in bera-geth, an unlisted client -> OOS.)"
  fi

  hd "4. gist verified + reproducible from a clean environment"
  if [ -z "$GIST" ]; then
    warn "no gist dir passed - an Immunefi PoC gist MUST be leak-free, Docker-first, and clean-container verified before submit"
  elif [ ! -d "$GIST" ]; then
    bad "gist dir not found: $GIST"
  else
    local leakers
    leakers=$(grep -rIlE '/home/|/Users/|your-login|your-host|203\.0\.113\.10' "$GIST" 2>/dev/null)
    if [ -n "$leakers" ]; then
      bad "gist leaks host path / username / VPS IP - scrub these files:"; printf '          %s\n' $leakers
    else
      ok "gist free of host-path / username / VPS leaks"
    fi
    if ls "$GIST"/[Dd]ockerfile >/dev/null 2>&1 || grep -rIlqi 'docker' "$GIST" 2>/dev/null; then
      ok "Docker-based repro present (clean-env path)"
    else
      bad "no Dockerfile / docker repro in gist - native repro is environment-fragile (C1: shadowed cc). Ship a Docker-first repro."
    fi
    note "MANUAL-VERIFY: clone the gist to an EMPTY dir on a clean box and run the Docker repro end to end; PASS only if the terminal receipt prints from the clean container."
  fi

  hd "verdict"
  if [ "$FAIL" -eq 0 ]; then
    printf '  MECHANICAL PASS. Clear every CONFIRM/MANUAL-VERIFY line above, then run report-killer + triage-validator before READY.\n'
  else
    printf '  MECHANICAL FAIL. Fix the FAIL line(s); this draft is NOT a bullet yet.\n'
  fi
  return "$FAIL"
}

self_check() {
  local t rc=0
  t=$(mktemp -d)
  # synthetic in-scope SCOPE
  cat > "$t/SCOPE.txt" <<'EOF'
# program: https://immunefi.com/bug-bounty/demo/scope/
REPO https://github.com/demo/core [Smart Contract]
CONTRACT 0x1111111111111111111111111111111111111111 Vault
OOS https://github.com/demo/legacy [deprecated]
OOS Distributor1.sol [entire file excluded]
EOF
  # a passing draft: in band, all sections, declared asset in scope, no OOS cite
  { printf '# t\n## TITLE\nx\n## ASSET\nthe asset github.com/demo/core\n## IMPACT\nx\n## BUG DESCRIPTION\n0x1111111111111111111111111111111111111111\n## PROOF OF CONCEPT\nx\n## RECOMMENDATION\nx\n## REFERENCES\nx\n'; yes word | head -2700 | tr '\n' ' '; } > "$t/pass.md"
  # a failing draft: too thin, cites OOS component, asset not in scope
  printf '# t\n## TITLE\nx\n## ASSET\ngithub.com/demo/legacy\n## IMPACT\nx\n## BUG DESCRIPTION\nbug in Distributor1.sol\n## PROOF OF CONCEPT\nx\n## RECOMMENDATION\nx\n## REFERENCES\nx\n' > "$t/fail.md"
  # passing gist
  mkdir -p "$t/gist_ok"; printf 'FROM ubuntu\n' > "$t/gist_ok/Dockerfile"; printf 'run docker build\n' > "$t/gist_ok/README.md"
  # leaky gist
  mkdir -p "$t/gist_bad"; printf 'cd $HOME/x\n' > "$t/gist_bad/run.sh"

  printf '### self-check: PASS draft (expect exit 0) ###\n'
  gate "$t/pass.md" "$t/SCOPE.txt" "$t/gist_ok"; [ $? -eq 0 ] || { printf 'SELFCHECK-FAIL: passing draft did not pass\n'; rc=1; }
  printf '\n### self-check: FAIL draft (expect exit 1) ###\n'
  gate "$t/fail.md" "$t/SCOPE.txt" "$t/gist_bad"; [ $? -ne 0 ] || { printf 'SELFCHECK-FAIL: failing draft passed\n'; rc=1; }

  rm -rf "$t"
  [ "$rc" -eq 0 ] && printf '\nSELF-CHECK OK\n' || printf '\nSELF-CHECK BROKEN\n'
  return "$rc"
}

# ---- main ----
[ "${1:-}" = "--self-check" ] && { self_check; exit $?; }

DRAFT="${1:-}"
GIST="${2:-}"
[ -z "$DRAFT" ] && { echo "usage: immunefi-presubmit.sh <draft_file> [gist_dir]  |  --self-check"; exit 2; }
[ -f "$DRAFT" ] || { echo "draft not found: $DRAFT"; exit 2; }

PROG=$(printf '%s' "$DRAFT" | sed -n 's#.*reports/\(drafts\|submitted\)/\([^/]*\)/.*#\2#p')
SCOPE="$ROOT/targets/${PROG:-_unknown_}/SCOPE.txt"

printf '== Immunefi pre-submit bullet gate (program: %s) ==\n' "${PROG:-unknown}"
gate "$DRAFT" "$SCOPE" "$GIST"
exit $?
