#!/usr/bin/env bash
# Scaffold a runnable Immunefi fork-PoC harness for an on-chain target.
# Usage: scaffold-fork-poc.sh <target> <chain> [fork_block]
#   target     targets/<target>/poc/ is created (target dir need not pre-exist)
#   chain      ethereum|optimism|base|arbitrum|polygon|bsc|avalanche|gnosis|sei|berachain|ink|scroll|linea|mantle|blast
#   fork_block optional; pin for a stable receipt. Omit = latest.
# Writes foundry.toml + test/ + .env (keyless archive RPC, or Alchemy if ALCHEMY_KEY in secrets.env).
set -euo pipefail
ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
TPL="$ROOT/targets/_templates/fork-poc"
SECRETS="$HOME/.config/gnoc/secrets.env"

[ $# -ge 2 ] || { grep -m1 '^# Usage' "$0" | sed 's/^# //'; exit 1; }
TARGET="$1"; CHAIN="$2"; BLOCK="${3:-}"
DST="$ROOT/targets/$TARGET/poc"

# chain -> "keyless_archive_rpc chain_id [alchemy_subdomain]"
# drpc.org keyless subdomains serve ARCHIVE state (historical-block forks) with no token, unlike
# publicnode/ankr which 403 archive requests. Rate-limited; ALCHEMY_KEY upgrades reliability.
case "$CHAIN" in
  ethereum|eth|mainnet) RPC="https://eth.drpc.org"; CID=1; AL="eth-mainnet";;
  optimism|op)          RPC="https://optimism.drpc.org"; CID=10; AL="opt-mainnet";;
  base)                 RPC="https://base.drpc.org"; CID=8453; AL="base-mainnet";;
  arbitrum|arb)         RPC="https://arbitrum.drpc.org"; CID=42161; AL="arb-mainnet";;
  polygon|matic)        RPC="https://polygon.drpc.org"; CID=137; AL="polygon-mainnet";;
  bsc|bnb)              RPC="https://bsc.drpc.org"; CID=56; AL="bnb-mainnet";;
  avalanche|avax)       RPC="https://avalanche.drpc.org"; CID=43114; AL="avax-mainnet";;
  gnosis|xdai)          RPC="https://gnosis.drpc.org"; CID=100; AL="";;
  sei)                  RPC="https://sei.drpc.org"; CID=1329; AL="";;
  berachain|bera)       RPC="https://berachain.drpc.org"; CID=80094; AL="";;
  ink)                  RPC="https://ink.drpc.org"; CID=57073; AL="";;
  scroll)               RPC="https://scroll.drpc.org"; CID=534352; AL="";;
  linea)                RPC="https://linea.drpc.org"; CID=59144; AL="linea-mainnet";;
  mantle)               RPC="https://mantle.drpc.org"; CID=5000; AL="";;
  blast)                RPC="https://blast.drpc.org"; CID=81457; AL="blast-mainnet";;
  *) echo "unknown chain '$CHAIN' — add it to the case in $0 (keyless archive RPC + chainid)"; exit 1;;
esac

# Prefer a real archive node if the operator added a free Alchemy key (deep-historical forks need it).
[ -f "$SECRETS" ] && source "$SECRETS" 2>/dev/null || true
if [ -n "${ALCHEMY_KEY:-}" ] && [ -n "$AL" ]; then
  RPC="https://${AL}.g.alchemy.com/v2/${ALCHEMY_KEY}"; echo "[scaffold] using Alchemy archive for $CHAIN"
else
  echo "[scaffold] using keyless archive $RPC (add ALCHEMY_KEY to secrets.env for deep-historical blocks)"
fi

mkdir -p "$DST"
cp "$TPL/foundry.toml" "$DST/foundry.toml"
cp -r "$TPL/test" "$DST/test"
mkdir -p "$DST/src"; cp "$TPL/src/Placeholder.sol" "$DST/src/Placeholder.sol"
{ echo "RPC_URL=$RPC"; echo "CHAIN_ID=$CID"; [ -n "$BLOCK" ] && echo "FORK_BLOCK=$BLOCK"; } > "$DST/.env"

cat <<EOF
[scaffold] wrote $DST  (chain=$CHAIN cid=$CID block=${BLOCK:-latest})
Next:
  cd $DST && set -a && . ./.env && set +a
  forge test --mp test/Example.t.sol -vvvv        # runs test_harness_selfcheck -> proves the fork
  cp test/Example.t.sol test/<Weakness>.t.sol     # then write test_exploit
EOF
