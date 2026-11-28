#!/usr/bin/env bash
# split-llm.sh - ONE model across BOTH GPUs: the laptop's RX 7700S (Vulkan) + the desktop GPU (llama.cpp RPC).
#
# The desktop runs ggml-rpc-server (scripts/desktop-link/rpc-desktop.ps1), reachable here at 127.0.0.1:50052
# through its reverse SSH tunnel. This script runs llama-server on the laptop with that RPC device plus the
# laptop's discrete GPU, so the layers are split across ~24 GB of VRAM and the model never spills to the CPU.
# The 680M iGPU is left out on purpose: it borrows system RAM and would slow every token down.
#
# Serves an OpenAI-compatible API on 127.0.0.1:11450 with 2 slots, so the gnoc agent's lead and worker
# both use the big model at once. Run under pm2 as `split-llm` (gnoc split up|down|status).
# Both ends must be llama.cpp b11476 (the RPC protocol is version-locked).
set -euo pipefail
BUILD="${SPLIT_BUILD:-b11476}"
BIN="$HOME/.local/opt/llama.cpp/$BUILD/llama-$BUILD"
# one or more RPC endpoints, comma-separated: the desktop (50052, required) and, when it answers, the phone
# (50053 = adb forward to the phone's rpc-server, scripts/phone-link). gnoc split up builds this list.
RPC="${SPLIT_RPC:-127.0.0.1:50052}"
PORT="${SPLIT_PORT:-11450}"
MODEL="${SPLIT_MODEL:?SPLIT_MODEL must be the GGUF path (gnoc split up sets it)}"
ALIAS="${SPLIT_ALIAS:-split}"
CTX="${SPLIT_CTX:-16384}"  # was 32768 with a q8_0 KV cache; see the --fit-target / -ctk note below
# Slots SHARE -c: with -np 2 a request got CTX/2, so 8192 served 4096 per request while the agent assumed 16384
# and every turn overflowed (measured 2026-10-22). gnoc chat needs ~14k for its system prompt plus tool schemas
# BEFORE any history, so one full-size slot beats two unusable ones; 32768 over two slots did not fit VRAM.
PARALLEL="${SPLIT_PARALLEL:-1}"
export LD_LIBRARY_PATH="$BIN"

# device names come from llama.cpp itself, not guessed: RPC devices are RPC0, RPC1, ... in --rpc order and the
# listing prints each one's endpoint ("  RPC1: 127.0.0.1:50053 (7820 MiB, ...)"), which picks its headroom below
# llama-server ABORTS (SIGABRT, exit 134) when an --rpc endpoint accepts the TCP connection but is not a working
# ggml-rpc-server - exactly what a dead desktop behind the reverse SSH tunnel looks like, because sshd keeps the
# forwarded port listening either way. Under `set -e` that killed this script right here, at the assignment, before
# the guard below could ever run, and 2>/dev/null swallowed the reason: pm2 saw a silent exit 134 and relaunched
# forever (3431 times, measured 2026-10-26 - eight hours of it writing nothing to the log at all). Capture the
# failure and let the guard report it. GGML_NO_BACKTRACE keeps ggml's abort handler from shelling out to gdb and
# dumping core on every probe.
LISTING=""; LIST_RC=0
LISTING=$(GGML_NO_BACKTRACE=1 "$BIN/llama-server" --rpc "$RPC" --list-devices 2>&1) || LIST_RC=$?
if [ "$LIST_RC" -ne 0 ]; then
  echo "split-llm: llama-server could not list devices over RPC $RPC (exit $LIST_RC): the port is open but the" >&2
  echo "split-llm: far end is not a working ggml-rpc-server (dead, or built against another llama.cpp than $BUILD)." >&2
  printf '%s\n' "$LISTING" | tail -3 | sed 's/^/split-llm:   /' >&2
  exit 3
fi
mapfile -t DEVS < <(printf '%s\n' "$LISTING" | sed -nE 's/^ +([A-Za-z]+[0-9]*(\[[^]]*\])?): .*/\1/p')
declare -A EP
while read -r dev ep; do EP[$dev]=$ep; done < <(printf '%s\n' "$LISTING" | sed -nE 's/^ +(RPC[0-9]+): ([^ ]+) .*/\1 \2/p')
# RPC (the desktop's 16 GB card) FIRST, the laptop's 8 GB Vulkan0 LAST. Order decides which device gets the
# later layers and the output tensor; measured 2026-10-22, desktop-first is the faster of the two orders.
PICK=()
for d in "${DEVS[@]}"; do case "$d" in RPC*) PICK+=("$d") ;; esac; done
for d in "${DEVS[@]}"; do case "$d" in Vulkan0) PICK+=("$d") ;; esac; done
if ! printf '%s\n' "${PICK[@]}" | grep -q '^RPC'; then
  echo "split-llm: no RPC device at $RPC (is rpc-desktop.ps1 running on the desktop?)" >&2
  exit 3
fi
DEVLIST=$(IFS=,; echo "${PICK[*]}")
echo "split-llm: devices $DEVLIST  model $MODEL  ctx $CTX  slots $PARALLEL (${CTX}/${PARALLEL} per request)  port $PORT  ubatch ${SPLIT_UBATCH:-default}"
# no -ngl: a fixed layer count makes --fit give up; let --fit size the split to each card's free memory
# --fit-target: MiB of headroom --fit leaves free PER DEVICE, in -dev order. The default is 1024, which is
# too thin on a 16 GB card that is also driving a Windows desktop: the model loaded and then died allocating
# compute buffers at the first token ("Remote RPC server crashed", every attempt before 2026-10-22). 3 GiB on
# the desktop, 1 GiB on the laptop, loads and generates.
# The phone (any RPC endpoint that is not the desktop's 50052) reports its whole free RAM as device memory, but
# Android's low-memory killer takes the app long before that is used up: it gets SPLIT_PHONE_HEADROOM (4 GiB).
HEAD=()
for d in "${PICK[@]}"; do
  case "$d" in
    RPC*) if [ "${EP[$d]:-}" = "127.0.0.1:50052" ]; then HEAD+=(3072); else HEAD+=("${SPLIT_PHONE_HEADROOM:-4096}"); fi ;;
    *) HEAD+=(1024) ;;
  esac
done
FIT_TARGET="${SPLIT_FIT_TARGET:-$(IFS=,; echo "${HEAD[*]}")}"
for d in "${PICK[@]}"; do [ -n "${EP[$d]:-}" ] && echo "split-llm: $d = ${EP[$d]}"; done
# No -ctk/-ctv q8_0: measured 2026-10-22 at ctx 4096, a quantized KV cache costs 3x generation over RPC
# (2.63 and 2.59 t/s against 7.94 plain, repeated). It was there to fit a 32k context, so CTX is lower now
# instead - raise it with SPLIT_CTX if a run needs more and still fits. -fa on is free (7.58 vs 7.94, inside jitter).
if [ -n "${SPLIT_DRY:-}" ]; then  # print the launch, do not run it (gnoc split / tests)
  echo "split-llm DRY: -dev $DEVLIST --fit-target $FIT_TARGET --rpc $RPC"; exit 0
fi
# Prefill batch: unset = llama.cpp's default (-ub 512). SPLIT_UBATCH=N sets -ub/-b for one launch. A 2026-10-24
# sweep looked like 4096 was 3.5x faster, but every probe there ran first after a reload; a controlled rerun had
# 512 at 179 t/s against 139-166 for 4096 on a fresh 14k prompt. No default change until a warm A/B says so.
UB_ARGS=()
[ -n "${SPLIT_UBATCH:-}" ] && UB_ARGS=(-ub "$SPLIT_UBATCH" -b "$SPLIT_UBATCH")
# SPLIT_EXTRA_ARGS: extra llama-server flags for one launch (tuning experiments).
# shellcheck disable=SC2086
exec "$BIN/llama-server" -m "$MODEL" --alias "$ALIAS" --rpc "$RPC" -dev "$DEVLIST" --fit on \
  --fit-target "$FIT_TARGET" -c "$CTX" -np "$PARALLEL" -fa on --jinja --host 127.0.0.1 --port "$PORT" \
  "${UB_ARGS[@]}" ${SPLIT_EXTRA_ARGS:-}
