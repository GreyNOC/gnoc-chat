#!/usr/bin/env bash
# User-level Ollama for the OpenCode worker (2026-10-20). Why a second server: the system
# service (port 11434, user ollama, root-owned config) runs with Ollama's auto num_parallel=2,
# which SPLITS a 16k model into two 8k slots and silently truncates every prompt over ~8190
# tokens (measured: a 12k-token prompt returned prompt_tokens 8194 and lost its system message).
# Fixing that needs a root systemd override; this server needs none. One slot, full context.
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11435}"
export OLLAMA_MODELS="${OLLAMA_MODELS:-$HOME/.ollama/models}"
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_MAX_LOADED_MODELS=1
export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-16384}"
export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
export OLLAMA_FLASH_ATTENTION=1
export OLLAMA_KV_CACHE_TYPE="${OLLAMA_KV_CACHE_TYPE:-q8_0}"
mkdir -p "$OLLAMA_MODELS"
# The GPU is a seat device: logind grants this user /dev/dri/renderD128 only once the login session is
# up, and pm2 starts this server before that at boot. Started too early, Ollama's Vulkan discovery finds
# no device and EVERY model runs on the CPU until someone restarts it by hand (measured 2026-10-25 after
# a reboot: "inference compute library=cpu", the 9B worker at 58 s for three tokens, the image vision
# check timing out at 120 s; a pm2 restart two hours later found "Vulkan0 RX 7700S 8 GiB"). Wait for the
# device, bounded, so a boot never leaves the card unused.
for _i in $(seq 1 90); do
  [ -w /dev/dri/renderD128 ] && break
  sleep 2
done
exec ollama serve
