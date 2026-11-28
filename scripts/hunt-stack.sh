#!/usr/bin/env bash
# hunt-stack.sh - persistent, restart-survivable hunting stack controller
#
# SUBCOMMANDS:  start | stop | status | ensure-ext | install | uninstall | --help
#
# ENVIRONMENT OVERRIDES:
#   CHROME_PROFILE   - default ~/.config/gnoc/chrome-profile  (must NOT be under /tmp)
#   CDP_PORT         - default 9222
#   BURP_LAUNCHER    - default ~/.local/bin/burp
#   BURP_PROJECT     - default ~/.BurpSuite/projects/bb-default.burp

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
CHROME_PROFILE="${CHROME_PROFILE:-$HOME/.config/gnoc/chrome-profile}"
CDP_PORT="${CDP_PORT:-9222}"
BURP_LAUNCHER="${BURP_LAUNCHER:-$HOME/.local/bin/burp}"
BURP_PROJECT="$HOME/.BurpSuite/projects/bb-default.burp"
USER_CONFIG="$HOME/.BurpSuite/UserConfig.json"
BBHUNT_JAR="$(cd "$(dirname "$0")/.." && pwd)/burp-ext/build/libs/bbhunt-burp-ext.jar"
AUTOSTART_FILE="$HOME/.config/autostart/hunt-stack.desktop"
THIS_SCRIPT="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

CDP_URL="http://127.0.0.1:${CDP_PORT}/json/version"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
port_up() {
    nc -z 127.0.0.1 "$1" 2>/dev/null
}

burp_running() {
    pgrep -f "[bB]urp" >/dev/null 2>&1 || port_up 9876 || port_up 8080
}

cdp_up() {
    curl -sf "${CDP_URL}" -o /dev/null 2>/dev/null
}

check_profile_not_tmp() {
    local resolved
    resolved=$(python3 -c "import os,sys; print(os.path.realpath(sys.argv[1]))" "${CHROME_PROFILE}" 2>/dev/null || echo "${CHROME_PROFILE}")
    case "${resolved}" in
        /tmp/*|/tmp)
            echo "ERROR: CHROME_PROFILE resolves to ${resolved} which is under /tmp." >&2
            echo "  Set CHROME_PROFILE to a persistent path, e.g. ~/.config/gnoc/chrome-profile" >&2
            exit 1
            ;;
    esac
}

locate_chrome() {
    local c
    for c in google-chrome google-chrome-stable chromium-browser chromium; do
        if command -v "${c}" >/dev/null 2>&1; then
            echo "${c}"
            return 0
        fi
    done
    echo ""
}

poll_up() {
    # poll_up <check_fn> <label> <seconds>
    local fn="$1" label="$2" secs="$3"
    local deadline=$(( $(date +%s) + secs ))
    echo -n "Waiting for ${label}"
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        if ${fn}; then
            echo " up"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo ""
    return 1
}

# ---------------------------------------------------------------------------
# ensure_burp_extensions
# ---------------------------------------------------------------------------
ensure_burp_extensions() {
    echo "--- ensure_burp_extensions ---"

    if burp_running; then
        echo "ERROR: Burp is currently RUNNING. The patch must be applied while Burp is closed." >&2
        echo "  Burp overwrites UserConfig.json on exit, so a live edit would be clobbered." >&2
        echo "  Steps to fix:" >&2
        echo "    1. Close Burp (File -> Quit, or: hunt-stack stop)" >&2
        echo "    2. Run:  hunt-stack ensure-ext" >&2
        echo "    3. Run:  hunt-stack start" >&2
        return 1
    fi

    if [ ! -f "${USER_CONFIG}" ]; then
        echo "ERROR: ${USER_CONFIG} not found. Launch Burp once to create it, then close it and re-run." >&2
        return 1
    fi

    if [ ! -f "${BBHUNT_JAR}" ]; then
        echo "WARNING: bbhunt jar not found at ${BBHUNT_JAR}" >&2
        echo "  Build it first:  cd burp-ext && ./gradlew jar" >&2
        echo "  Patching MCP Server loaded=true only (bbhunt entry skipped)." >&2
    fi

    # Backup first
    cp "${USER_CONFIG}" "${USER_CONFIG}.bak"
    echo "  Backup written: ${USER_CONFIG}.bak"

    python3 - "${USER_CONFIG}" "${BBHUNT_JAR}" <<'PYEOF'
import sys, json, copy

cfg_path = sys.argv[1]
bbhunt_jar = sys.argv[2]

with open(cfg_path, "r") as f:
    cfg = json.load(f)

ext_section = cfg["user_options"]["extender"]

# Ensure auto-reload
ext_section["settings"]["automatically_reload_extensions_on_startup"] = True

exts = ext_section["extensions"]

# Build lookup by name
by_name = {e.get("name"): i for i, e in enumerate(exts)}

# --- MCP Server: set loaded=true (entry already exists) ---
if "MCP Server" in by_name:
    exts[by_name["MCP Server"]]["loaded"] = True
    print("  MCP Server: loaded -> true")
else:
    # Construct from scratch matching the existing shape
    mcp_entry = {
        "auto_reload": False,
        "bapp_serial_version": 10,
        "bapp_uuid": "9952290f04ed4f628e624d0aa9dccebc",
        "errors": "ui",
        "extension_file": "bapps/9952290f04ed4f628e624d0aa9dccebc/burp-mcp-all.jar",
        "extension_type": "java",
        "loaded": True,
        "name": "MCP Server",
        "output": "ui",
        "use_ai": False
    }
    exts.insert(0, mcp_entry)
    print("  MCP Server: inserted (loaded=true)")

# --- YesWeBurp: preserve as-is (just confirm it is present) ---
if "YesWeBurp" in by_name:
    print("  YesWeBurp: preserved (loaded={})".format(exts[by_name["YesWeBurp"]]["loaded"]))
else:
    print("  WARNING: YesWeBurp entry not found in UserConfig - it may have been removed externally.")

# --- bbhunt-control: upsert ---
import os
if os.path.isfile(bbhunt_jar):
    if "bbhunt-control" in by_name:
        exts[by_name["bbhunt-control"]]["extension_file"] = bbhunt_jar
        exts[by_name["bbhunt-control"]]["loaded"] = True
        print("  bbhunt-control: updated (loaded=true, path={})".format(bbhunt_jar))
    else:
        # Clone the YesWeBurp shape as a template (same structure, no bapp fields)
        if "YesWeBurp" in by_name:
            template = copy.deepcopy(exts[by_name["YesWeBurp"]])
        else:
            template = {"auto_reload": False, "errors": "ui", "extension_type": "java", "output": "ui", "use_ai": False}
        template["extension_file"] = bbhunt_jar
        template["loaded"] = True
        template["name"] = "bbhunt-control"
        exts.append(template)
        print("  bbhunt-control: inserted (loaded=true, path={})".format(bbhunt_jar))
else:
    print("  bbhunt-control: JAR not found at {} - skipped".format(bbhunt_jar))

ext_section["extensions"] = exts
cfg["user_options"]["extender"] = ext_section

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=4)

print("  UserConfig.json written OK")
print("  Extensions present: {}".format([e.get("name") for e in exts]))
PYEOF

    echo "--- done ---"
}

# ---------------------------------------------------------------------------
# start
# ---------------------------------------------------------------------------
cmd_start() {
    check_profile_not_tmp

    # --- Chrome ---
    if cdp_up; then
        echo "Chrome CDP :${CDP_PORT} already answers."
        # Warn if running against /tmp
        local cdp_profile
        cdp_profile=$(pgrep -a chrome 2>/dev/null | grep -- "--remote-debugging-port=${CDP_PORT}" | grep -o -- '--user-data-dir=[^ ]*' | head -1 | cut -d= -f2 || echo "")
        if [[ "${cdp_profile}" == /tmp/* ]]; then
            echo ""
            echo "WARNING: the answering Chrome is using a VOLATILE profile: ${cdp_profile}"
            echo "  Its logins and cookies will be lost on reboot."
            echo "  To switch to the persistent profile:"
            echo "    hunt-stack stop"
            echo "    hunt-stack start"
            echo ""
        fi
    else
        local CHROME
        CHROME=$(locate_chrome)
        if [ -z "${CHROME}" ]; then
            echo "ERROR: google-chrome not found. Install it first:" >&2
            echo "  sudo apt-get install -y google-chrome-stable" >&2
            exit 1
        fi
        mkdir -p "${CHROME_PROFILE}"
        echo "Launching Chrome (persistent profile: ${CHROME_PROFILE}) ..."
        nohup "${CHROME}" \
            --remote-debugging-port="${CDP_PORT}" \
            --user-data-dir="${CHROME_PROFILE}" \
            --restore-last-session \
            --no-first-run \
            --no-default-browser-check \
            >/dev/null 2>&1 &
        if ! poll_up cdp_up "CDP :${CDP_PORT}" 15; then
            echo "ERROR: Chrome did not answer within 15 s." >&2
            exit 1
        fi
        echo "Chrome up. Profile: ${CHROME_PROFILE}"
    fi

    # --- Burp ---
    if port_up 9876 || port_up 8080; then
        echo "Burp already running (:8080 or :9876 up)."
    else
        if [ ! -f "${BURP_LAUNCHER}" ]; then
            echo "Burp launcher not found at ${BURP_LAUNCHER}"
            echo "  Set BURP_LAUNCHER=/path/to/burp and re-run, or launch Burp manually."
        else
            ensure_burp_extensions || true  # warn but don't abort if Burp is already up
            echo "Launching Burp (project: ${BURP_PROJECT}) ..."
            nohup "${BURP_LAUNCHER}" >/dev/null 2>&1 &
            if ! poll_up "port_up 8080" "Burp proxy :8080" 30; then
                echo "WARNING: Burp proxy :8080 did not answer in 30 s - it may still be starting." >&2
            fi
        fi
    fi

    cmd_status
}

# ---------------------------------------------------------------------------
# stop
# ---------------------------------------------------------------------------
cmd_stop() {
    echo "Stopping Chrome CDP (--remote-debugging-port=${CDP_PORT}) ..."
    # Kill only the browser process that owns --remote-debugging-port=PORT, not all chrome
    local pids
    pids=$(pgrep -f -- "--remote-debugging-port=${CDP_PORT}" 2>/dev/null | head -20 || true)
    if [ -n "${pids}" ]; then
        # Find the root (non-renderer) process: the one whose parent is NOT in the set
        local root_pid
        root_pid=$(echo "${pids}" | while read -r pid; do
            ppid=$(awk '/^PPid:/{print $2}' /proc/"${pid}"/status 2>/dev/null || echo 0)
            if ! echo "${pids}" | grep -qx "${ppid}"; then
                echo "${pid}"
            fi
        done | head -1)
        if [ -n "${root_pid}" ]; then
            kill "${root_pid}" 2>/dev/null && echo "  Sent SIGTERM to Chrome PID ${root_pid}" || true
        else
            echo "  Could not isolate root Chrome PID; killing matched set."
            echo "${pids}" | xargs -r kill 2>/dev/null || true
        fi
    else
        echo "  No Chrome process matched --remote-debugging-port=${CDP_PORT}"
    fi

    echo "Stopping Burp ..."
    local burp_pids
    burp_pids=$(pgrep -f "[jJ]ava.*[bB]urp" 2>/dev/null || true)
    if [ -n "${burp_pids}" ]; then
        echo "${burp_pids}" | xargs -r kill 2>/dev/null && echo "  Sent SIGTERM to Burp PID(s) ${burp_pids}" || true
    else
        echo "  No Burp JVM process found."
    fi

    sleep 2
    cmd_status
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
cmd_status() {
    local cdp_state burp_proxy_state burp_mcp_state bbhunt_state autostart_state

    cdp_up                        && cdp_state="UP"        || cdp_state="DOWN"
    port_up 8080                  && burp_proxy_state="UP" || burp_proxy_state="DOWN"
    port_up 9876                  && burp_mcp_state="UP"   || burp_mcp_state="DOWN"
    port_up 9877                  && bbhunt_state="UP"     || bbhunt_state="DOWN"
    [ -f "${AUTOSTART_FILE}" ]    && autostart_state="installed" || autostart_state="not installed"

    echo "-------- hunt-stack status --------"
    printf "  :%-4s  Chrome CDP       %s\n"  "${CDP_PORT}" "${cdp_state}"
    printf "  :%-4s  Burp proxy       %s\n"  "8080"        "${burp_proxy_state}"
    printf "  :%-4s  Burp MCP         %s\n"  "9876"        "${burp_mcp_state}"
    printf "  :%-4s  bbhunt-control   %s\n"  "9877"        "${bbhunt_state}"
    echo "  autostart:               ${autostart_state}"

    if [ "${cdp_state}" = "UP" ]; then
        local cdp_profile
        cdp_profile=$(pgrep -a chrome 2>/dev/null | grep -- "--remote-debugging-port=${CDP_PORT}" | grep -o -- '--user-data-dir=[^ ]*' | head -1 | cut -d= -f2 || echo "unknown")
        printf "  Chrome profile:          %s\n" "${cdp_profile}"
        if [[ "${cdp_profile}" == /tmp/* ]]; then
            echo "  WARNING: profile is VOLATILE (/tmp). Run: hunt-stack stop && hunt-stack start"
        fi
    fi
    echo "-----------------------------------"
}

# ---------------------------------------------------------------------------
# install / uninstall autostart
# ---------------------------------------------------------------------------
cmd_install() {
    mkdir -p "$(dirname "${AUTOSTART_FILE}")"
    cat > "${AUTOSTART_FILE}" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Hunt Stack
Comment=Start Chrome CDP + Burp on graphical login
Exec=${THIS_SCRIPT} start
X-GNOME-Autostart-enabled=true
StartupNotify=false
Terminal=false
DESKTOP
    echo "Autostart entry written: ${AUTOSTART_FILE}"
    echo "The stack will start automatically on next graphical login (GNOME/KDE/XFCE)."
    echo ""
    echo "To also start before any graphical login (systemd linger):"
    echo "  loginctl enable-linger ${USER}"
    echo "  (then add a systemd user service; the .desktop entry alone covers the GUI session)"
}

cmd_uninstall() {
    if [ -f "${AUTOSTART_FILE}" ]; then
        rm "${AUTOSTART_FILE}"
        echo "Removed: ${AUTOSTART_FILE}"
    else
        echo "Autostart entry not present: ${AUTOSTART_FILE}"
    fi
}

# ---------------------------------------------------------------------------
# help
# ---------------------------------------------------------------------------
cmd_help() {
    cat <<'HELP'
hunt-stack.sh - persistent Chrome CDP + Burp stack controller

SUBCOMMANDS
  start         Idempotent. Launch Chrome (persistent profile) + Burp if not running.
                Warns if an existing Chrome is on /tmp (volatile) profile.
  stop          Gracefully terminate the CDP Chrome and Burp JVM.
  status        Print UP/DOWN for :9222 (CDP), :8080 (proxy), :9876 (MCP), :9877 (bbhunt),
                and whether the autostart entry is installed.
  ensure-ext    Patch UserConfig.json: MCP Server loaded=true, bbhunt-control added,
                YesWeBurp preserved. REFUSES if Burp is running. Always backs up first.
  install       Write ~/.config/autostart/hunt-stack.desktop for graphical-login autostart.
  uninstall     Remove the autostart entry.
  --help        This message.

ENV OVERRIDES
  CHROME_PROFILE   (default ~/.config/gnoc/chrome-profile)  must not be under /tmp
  CDP_PORT         (default 9222)
  BURP_LAUNCHER    (default ~/.local/bin/burp)
HELP
}

# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------
CMD="${1:-}"
case "${CMD}" in
    start)        cmd_start ;;
    stop)         cmd_stop ;;
    status)       cmd_status ;;
    ensure-ext)   ensure_burp_extensions ;;
    install)      cmd_install ;;
    uninstall)    cmd_uninstall ;;
    --help|-h)    cmd_help ;;
    "")           cmd_help ;;
    *)
        echo "Unknown subcommand: ${CMD}" >&2
        cmd_help
        exit 1
        ;;
esac
