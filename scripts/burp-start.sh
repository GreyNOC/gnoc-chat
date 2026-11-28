#!/usr/bin/env bash
# burp-start.sh - launch Burp Suite Community headed on this box, with the official
# PortSwigger MCP Server extension auto-loading on 127.0.0.1:9876.
#
# Why this exists: the archived scripts/hunt-stack.sh expects a launcher at
# ~/.local/bin/burp, which does NOT exist here. Point it at this script instead:
#     BURP_LAUNCHER=${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/burp-start.sh hunt-stack.sh start
#
# This session is KDE *Wayland* + Xwayland, so DISPLAY alone is not enough: an
# XAUTHORITY cookie is required or Burp dies with
#   "Can't connect to X11 window server using ':0'".
# The cookie path is taken from the running kwin_wayland --xwayland-xauthority arg.
set -uo pipefail

BURP_HOME=/usr/share/burpsuite
LAUNCHER="$BURP_HOME/BurpSuiteCommunity"       # install4j launcher; prefers $BURP_HOME/jre
LOG="${BURP_LOG:-/tmp/burp-start.$(id -u).log}"

if pgrep -f 'burpsuite[_]community' >/dev/null 2>&1; then
    echo "Burp is already running (pid $(pgrep -f 'burpsuite[_]community' | tr '\n' ' '))"
    ss -tlnp 2>/dev/null | grep -E ':9876|:8080' || echo "  (no 9876/8080 listener yet)"
    exit 0
fi

export DISPLAY="${DISPLAY:-:0}"
[ -z "${DISPLAY}" ] && export DISPLAY=:0

# Resolve an X11 auth cookie if we do not already have a usable one.
if [ -z "${XAUTHORITY:-}" ] || [ ! -r "${XAUTHORITY:-/nonexistent}" ]; then
    XA=$(ps -eo args 2>/dev/null | grep -o -- '--xwayland-xauthority [^ ]*' | head -1 | awk '{print $2}')
    [ -z "$XA" ] && XA=$(ps -eo args 2>/dev/null | grep -oE '/usr/bin/Xwayland .*-auth [^ ]*' | grep -oE '\-auth [^ ]*' | head -1 | awk '{print $2}')
    # Recent Plasma sessions can keep the cookie in /run/user/<uid>/xauth_* without
    # exposing its path in either process command line above. Prefer the newest
    # readable cookie in that runtime directory before falling back to ~/.Xauthority.
    if [ -z "$XA" ]; then
        RUNTIME_DIR="/run/user/$(id -u)"
        if [ -d "$RUNTIME_DIR" ]; then
            XA=$(find "$RUNTIME_DIR" -maxdepth 1 -type f -name 'xauth_*' -readable \
                -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
        fi
    fi
    [ -z "$XA" ] && [ -r "$HOME/.Xauthority" ] && XA="$HOME/.Xauthority"
    if [ -n "$XA" ] && [ -r "$XA" ]; then
        export XAUTHORITY="$XA"
    else
        echo "WARNING: could not find an X11 auth cookie; Burp may fail to open a window." >&2
    fi
fi
echo "DISPLAY=$DISPLAY  XAUTHORITY=${XAUTHORITY:-<none>}"

# NOTE: do NOT pass --use-defaults. It makes Burp ignore saved user settings, which
# includes the extender section that registers the MCP Server extension - so the MCP
# server never starts. Launch plain so UserConfigCommunity.json is honoured.
cd "$BURP_HOME" || exit 1
setsid nohup "$LAUNCHER" > "$LOG" 2>&1 < /dev/null &
echo "launched Burp (log: $LOG)"

echo
echo "*** MANUAL STEP REQUIRED ***"
echo "Burp Suite COMMUNITY always shows its startup wizard and will sit there until a"
echo "human clicks. In the 'Burp Suite Community Edition' window:"
echo "  1. leave 'Temporary project' selected  ->  click  Next"
echo "  2. leave 'Use Burp defaults' selected  ->  click  Start Burp"
echo "There is no CLI flag that skips this on Community (--use-defaults does not, and"
echo "--project-file is silently ignored because Community cannot make disk projects)."
echo
echo "Waiting up to 180s for the MCP server on 127.0.0.1:9876 ..."
for i in $(seq 1 60); do
    if ss -tlnp 2>/dev/null | grep -q ':9876'; then
        echo "MCP server UP:"
        ss -tlnp 2>/dev/null | grep -E ':9876|:8080'
        exit 0
    fi
    sleep 3
done
echo "TIMED OUT: 9876 is not listening. Click through the startup wizard, then re-check:"
echo "  ss -tlnp | grep 9876"
exit 1
