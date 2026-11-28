#!/usr/bin/env bash
# gnoc's own model server on the laptop (scripts/gnoc_engine.py), in the place ollama-oc.sh had: same address
# (127.0.0.1:11435), one model loaded at a time, one slot with the full context, models kept 30 minutes.
# Back to Ollama at any time:  pm2 stop gnoc-engine && pm2 start scripts/ollama-oc.sh --name ollama-oc
# (ollama-oc was removed from pm2 on 2026-11-27: kept beside this one, the two raced for the port on every boot.)
export GNOC_ENGINE_ADDR="${GNOC_ENGINE_ADDR:-127.0.0.1:11435}"
export GNOC_ENGINE_KEEP_ALIVE="${GNOC_ENGINE_KEEP_ALIVE:-30m}"
export GNOC_ENGINE_MAX_LOADED="${GNOC_ENGINE_MAX_LOADED:-1}"
# The discrete card only (the integrated 680M shares system RAM and slows a split model down), and the q8
# KV cache ollama-oc ran with (OLLAMA_KV_CACHE_TYPE=q8_0), so a 16k context costs the same VRAM as before.
export GNOC_ENGINE_ARGS="${GNOC_ENGINE_ARGS:---device Vulkan0 -ctk q8_0 -ctv q8_0}"
# The GPU is a seat device: logind grants /dev/dri/renderD128 only once the login session is up, and pm2 starts
# this before that at boot. Started too early, Vulkan finds no device and every model runs on the CPU (measured
# with ollama-oc on 2026-10-25). Wait for the device, bounded.
for _i in $(seq 1 90); do
  [ -w /dev/dri/renderD128 ] && break
  sleep 2
done
# Refuse a taken port slowly. pm2 restarts this with no delay, so on 2026-11-23 a leftover ollama-oc on the same
# address made the engine die on "Address already in use" 49,935 times in three hours (a 51 MB error log). Wait
# before exiting so a clash costs a retry every 30 s instead, and say who holds the port.
_port="${GNOC_ENGINE_ADDR##*:}"
if ss -Hltn "sport = :${_port}" 2>/dev/null | grep -q .; then
  echo "gnoc-engine: ${GNOC_ENGINE_ADDR} is already taken; not starting. Holder: $(ss -Hltnp "sport = :${_port}" 2>/dev/null | grep -o 'users:.*' | head -1)" >&2
  echo "gnoc-engine: if that is ollama-oc, run: pm2 stop ollama-oc" >&2
  sleep 30
  exit 1
fi
exec python3 "$(dirname "$(readlink -f "$0")")/gnoc_engine.py" serve
