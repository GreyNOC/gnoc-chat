#!/usr/bin/env bash
# Run every bbtools lib self-check. Green = the shared hunt tooling is sound.
# Usage: scripts/bbtools/selfcheck-all.sh
set -u
cd "$(dirname "$0")/../.." || exit 2
fail=0
run() {
  local name="$1"; shift
  printf "%-24s " "$name"
  if timeout 90 python3 "$@" >/tmp/bbtools_sc.out 2>&1; then
    if tail -3 /tmp/bbtools_sc.out | grep -qiE "SELFCHECK OK|self-?check|pass|OK"; then
      echo "PASS"
    else
      echo "PASS (no marker)"
    fi
  else
    echo "FAIL"; sed 's/^/    /' /tmp/bbtools_sc.out | tail -4; fail=1
  fi
}
run lib_scope        scripts/bbtools/lib_scope.py
run lib_policy       scripts/bbtools/lib_policy.py --selfcheck
run lib_commerce     scripts/bbtools/lib_commerce.py selfcheck
run lib_provision    scripts/bbtools/lib_provision.py selfcheck
run lib_browser      scripts/bbtools/lib_browser.py selfcheck
run lib_browser_nd   scripts/bbtools/lib_browser_nd.py selfcheck
run lib_unauth       scripts/bbtools/lib_unauth.py selfcheck
run lib_auth         scripts/bbtools/lib_auth.py selfcheck
run bola_discriminant scripts/bbtools/bola_discriminant.py selfcheck
run race_burst       scripts/bbtools/race_burst.py selfcheck
run commerce_receipt scripts/bbtools/commerce_receipt.py selfcheck
run commerce_webhook scripts/bbtools/commerce_webhook.py selfcheck
run commerce_tamper  scripts/bbtools/commerce_tamper.py selfcheck
run gql              scripts/bbtools/gql.py selfcheck
run onchain          scripts/bbtools/onchain.py selfcheck
run demo_chain       scripts/bbtools/demo_chain.py
run burp_resolve     scripts/bbtools/burp_resolve.py selfcheck
run bh               scripts/bbtools/bh.py selfcheck
run test_commerce_chain scripts/bbtools/test_commerce_chain.py
# lib_egress needs a browser + network (clear_cloudflare); run it manually.
echo "---"
[ $fail -eq 0 ] && echo "ALL GREEN" || echo "SOME FAILED"
exit $fail
