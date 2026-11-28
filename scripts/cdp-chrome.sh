#!/usr/bin/env bash
# cdp-chrome.sh - launch the operator's persistent Chrome with CDP enabled
#
# USAGE:
#   scripts/cdp-chrome.sh
#
# FIRST RUN: Chrome opens. Log into Google, HackerOne, and any target you want
# to hunt. Your sessions are saved to the persistent profile dir. Every hunter
# agent that calls lib_browser.attach_cdp() / cdp_fetch() reuses those sessions
# automatically; no re-provisioning.
#
# IDEMPOTENT: if Chrome is already up on $CDP_PORT, prints the ws URL and exits 0.
#
# ENV OVERRIDES:
#   CDP_PORT       - default 9222
#   CHROME_PROFILE - default ~/.config/gnoc/chrome-profile  (PERSISTENT, NOT /tmp)

set -euo pipefail

PORT="${CDP_PORT:-9222}"
PROFILE="${CHROME_PROFILE:-$HOME/.config/gnoc/chrome-profile}"
VERSION_URL="http://localhost:${PORT}/json/version"

# ------------------------------------------------------------------
# guard: refuse if the profile is under /tmp (volatile - lost on reboot)
# ------------------------------------------------------------------
RESOLVED_PROFILE=$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "${PROFILE}" 2>/dev/null || echo "${PROFILE}")
case "${RESOLVED_PROFILE}" in
    /tmp/*|/tmp)
        echo "ERROR: CHROME_PROFILE resolves to ${RESOLVED_PROFILE} which is under /tmp." >&2
        echo "  Profiles under /tmp are wiped on reboot - logins and cookies will not survive." >&2
        echo "  Use the persistent default:  ~/.config/gnoc/chrome-profile" >&2
        echo "  Or set:  export CHROME_PROFILE=~/.config/gnoc/chrome-profile" >&2
        exit 1
        ;;
esac

# ------------------------------------------------------------------
# idempotency check: if the endpoint already answers, we are done
# ------------------------------------------------------------------
if curl -sf "${VERSION_URL}" -o /dev/null 2>/dev/null; then
    WS=$(curl -sf "${VERSION_URL}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('webSocketDebuggerUrl','(ws not in response)'))" 2>/dev/null || echo "(parse error)")
    echo "CDP already up on port ${PORT}"
    echo "  ws: ${WS}"
    exit 0
fi

# ------------------------------------------------------------------
# ensure the persistent profile dir exists
# ------------------------------------------------------------------
mkdir -p "${PROFILE}"

# ------------------------------------------------------------------
# locate google-chrome (or chromium as a fallback)
# ------------------------------------------------------------------
CHROME=""
for candidate in google-chrome google-chrome-stable chromium-browser chromium; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        CHROME="${candidate}"
        break
    fi
done

if [ -z "${CHROME}" ]; then
    echo "ERROR: google-chrome not found. Install it first:" >&2
    echo "  sudo apt-get install -y google-chrome-stable" >&2
    exit 1
fi

# ------------------------------------------------------------------
# launch Chrome in the background with CDP enabled
# ------------------------------------------------------------------
# --load-extension: any unpacked extension staged under <profile-parent>/extensions/*
EXT_ROOT="$(dirname "${PROFILE}")/extensions"
EXT_DIRS=""
if [ -d "${EXT_ROOT}" ]; then
    for d in "${EXT_ROOT}"/*/; do
        [ -f "${d}manifest.json" ] && EXT_DIRS="${EXT_DIRS:+${EXT_DIRS},}${d%/}"
    done
fi
LOAD_FLAG=""
[ -n "${EXT_DIRS}" ] && LOAD_FLAG="--load-extension=${EXT_DIRS}" && echo "  extensions: ${EXT_DIRS}"

echo "Launching Chrome with CDP on port ${PORT} ..."
echo "  profile: ${PROFILE}"
nohup "${CHROME}" \
    --remote-debugging-port="${PORT}" \
    --user-data-dir="${PROFILE}" \
    ${LOAD_FLAG} \
    --restore-last-session \
    --no-first-run \
    --no-default-browser-check \
    >/dev/null 2>&1 &

CHROME_PID=$!

# ------------------------------------------------------------------
# poll /json/version until Chrome answers (up to ~15 s)
# ------------------------------------------------------------------
DEADLINE=$(( $(date +%s) + 15 ))
echo -n "Waiting for CDP endpoint"
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    if curl -sf "${VERSION_URL}" -o /dev/null 2>/dev/null; then
        echo " up"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -sf "${VERSION_URL}" -o /dev/null 2>/dev/null; then
    echo ""
    echo "ERROR: Chrome did not answer on port ${PORT} within 15 s (PID ${CHROME_PID})." >&2
    echo "Check: ps aux | grep chrome" >&2
    exit 1
fi

WS=$(curl -sf "${VERSION_URL}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('webSocketDebuggerUrl','(ws not in response)'))" 2>/dev/null || echo "(parse error)")

echo ""
echo "CDP ready."
echo "  port   : ${PORT}"
echo "  ws     : ${WS}"
echo "  profile: ${PROFILE}  (persistent - logins survive reboot)"
echo ""
echo "Next step: log into Google / HackerOne / targets ONCE in the browser window."
echo "Every hunter agent then reuses your live session via lib_browser.cdp_fetch()."
