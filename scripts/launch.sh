#!/usr/bin/env bash
# LAUNCH - multi-browser CDP launcher for the the workspace hunting workstation.
#
# Brings up four INDEPENDENT headed Chrome instances, each with its own persistent
# profile and its own CDP debugging port, so the "distinct-victim gate" holds:
# attacker and victim never share a cookie jar.
#
#   name      port  profile                                      role
#   main      9222  ~/.config/gnoc/chrome-profile              operator's real authed identity
#   attacker  9223  ~/.config/gnoc/profiles/attacker           provisioned attacker account
#   victim    9224  ~/.config/gnoc/profiles/victim             provisioned victim account
#   clean     9225  ~/.config/gnoc/profiles/clean              unauth baseline (negative control)
#
# USAGE
#   LAUNCH                 start all four, print status table
#   LAUNCH <name>          start one (main|attacker|victim|clean)
#   LAUNCH status          status table only, start nothing
#   LAUNCH stop [name]     stop all, or one (precise kill by --user-data-dir)
#   LAUNCH restart [name]  stop then start
#   LAUNCH urls            JSON map name -> {port, ws} for scripts/agents
#
# OPT-IN FLAGS (all default OFF - see LAUNCH.md for why)
#   --headless     add --headless=new. ONLY for a box with no display. The operator
#                  cannot log in to a headless browser and bot-walls fingerprint it.
#   --insecure     add --disable-web-security --no-sandbox. These CHANGE TARGET
#                  BEHAVIOUR and INVALIDATE FINDINGS. Never use for a report PoC.
#
# ENV OVERRIDES
#   CFT_ROOT   Chrome for Testing install root (default ~/.local/opt/chrome-for-testing/current)
#   BB_ROOT    bb-hunt config root (default ~/.config/gnoc)
#
# Self-contained: depends only on bash, curl, python3 (stdlib), ps/pgrep. It does NOT
# read anything under .gnoc, so an incomplete workspace restore cannot
# break it.

set -uo pipefail

BB_ROOT="${BB_ROOT:-$HOME/.config/gnoc}"
LOG_DIR="${BB_ROOT}/logs"
CFT_ROOT="${CFT_ROOT:-$HOME/.local/opt/chrome-for-testing/current}"

# ---------------------------------------------------------------- instance table
NAMES=(main attacker victim clean)

port_for() {
    case "$1" in
        main)     echo 9222 ;;
        attacker) echo 9223 ;;
        victim)   echo 9224 ;;
        clean)    echo 9225 ;;
        *)        return 1 ;;
    esac
}

profile_for() {
    case "$1" in
        main)     echo "${BB_ROOT}/chrome-profile" ;;      # MUST stay this exact path
        attacker) echo "${BB_ROOT}/profiles/attacker" ;;
        victim)   echo "${BB_ROOT}/profiles/victim" ;;
        clean)    echo "${BB_ROOT}/profiles/clean" ;;
        *)        return 1 ;;
    esac
}

role_for() {
    case "$1" in
        main)     echo "operator real authed identity" ;;
        attacker) echo "provisioned attacker account" ;;
        victim)   echo "provisioned victim account" ;;
        clean)    echo "unauth baseline / negative control" ;;
    esac
}

OPT_HEADLESS=0
OPT_INSECURE=0

# ---------------------------------------------------------------- display (headed)
# Agent shells on this box inherit no DISPLAY/XAUTHORITY even though a real KDE
# Plasma Wayland session with XWayland on :0 is running.
#
# X AUTHORITY IS THE HARD PART, not the display. Observed on this box:
#   - $HOME/.Xauthority is created by any SSH login with X11 forwarding and holds a
#     cookie for the FORWARDED display (:10), NOT the local :0. Preferring it breaks
#     headed Chrome with "Authorization required, but no authorization protocol
#     specified" + "Missing X server or $DISPLAY" - which looks like "no display"
#     but is really "wrong cookie".
#   - The authoritative cookie for the running XWayland server is the one kwin_wayland
#     was started with, passed as --xwayland-xauthority (here /run/user/1000/xauth_*).
# So: build candidates most-authoritative-first and VALIDATE each against the real
# display before committing. Never trust a candidate just because the file exists.
_x_probe() {
    # 0 = we can actually talk to $DISPLAY with the current XAUTHORITY
    if command -v xdpyinfo >/dev/null 2>&1; then
        xdpyinfo >/dev/null 2>&1
    elif command -v xset >/dev/null 2>&1; then
        xset q >/dev/null 2>&1
    else
        return 0        # no validator installed: accept priority order untested
    fi
}

resolve_display() {
    export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"

    if [ -z "${DISPLAY:-}" ]; then
        local d
        for d in /tmp/.X11-unix/X*; do
            [ -S "${d}" ] || continue
            export DISPLAY=":${d##*/X}"
            break
        done
    fi
    [ -n "${DISPLAY:-}" ] || return 0        # nothing to authorise against

    # already working? leave the caller's environment completely alone
    if [ -n "${XAUTHORITY:-}" ] && [ -r "${XAUTHORITY}" ] && _x_probe; then
        return 0
    fi

    local -a cands=()
    [ -n "${XAUTHORITY:-}" ] && [ -r "${XAUTHORITY:-}" ] && cands+=("${XAUTHORITY}")

    # the cookie the running XWayland server was actually started with
    local kw
    kw=$(ps -eo args= 2>/dev/null \
         | grep -o -- '--xwayland-xauthority[= ][^ ]*' \
         | head -1 | sed 's/^--xwayland-xauthority[= ]//')
    [ -n "${kw}" ] && [ -r "${kw}" ] && cands+=("${kw}")

    local c
    for c in "${XDG_RUNTIME_DIR}"/xauth_*; do
        [ -r "${c}" ] && cands+=("${c}")
    done

    # LAST: an SSH-forwarded cookie file lives here and is usually for :10, not :0
    [ -r "${HOME}/.Xauthority" ] && cands+=("${HOME}/.Xauthority")

    for c in ${cands[@]+"${cands[@]}"}; do
        export XAUTHORITY="${c}"
        if _x_probe; then
            return 0
        fi
    done

    # nothing validated; try with no cookie at all (works if the server allows it)
    unset XAUTHORITY
    _x_probe && return 0

    # leave the best candidate set so Chrome's own error lands in the logfile
    [ "${#cands[@]}" -gt 0 ] && export XAUTHORITY="${cands[0]}"
    return 0
}

have_display() { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }

# x_status: human-readable line for diagnostics
x_status() {
    if _x_probe; then echo "DISPLAY=${DISPLAY:-<none>} XAUTHORITY=${XAUTHORITY:-<none>} (validated OK)"
    else echo "DISPLAY=${DISPLAY:-<none>} XAUTHORITY=${XAUTHORITY:-<none>} (NOT validated)"; fi
}

# ---------------------------------------------------------------- chrome binary
locate_chrome() {
    if [ -x "${CFT_ROOT}/chrome-linux64/chrome" ]; then
        echo "${CFT_ROOT}/chrome-linux64/chrome"; return 0
    fi
    local c
    for c in google-chrome google-chrome-stable chromium-browser chromium; do
        command -v "${c}" >/dev/null 2>&1 && { command -v "${c}"; return 0; }
    done
    return 1
}

# ---------------------------------------------------------------- CDP probing
# Chrome may bind IPv4-only or IPv6-only depending on build/flags, so probe BOTH
# literal IPs. NEVER use the hostname "localhost": a resolver that returns
# 127.0.0.1 first will hard-fail instead of falling through to ::1.
cdp_json() {
    local port="$1" host
    for host in 127.0.0.1 "[::1]"; do
        local out
        out=$(curl -sf --max-time 3 "http://${host}:${port}/json/version" 2>/dev/null) || continue
        [ -n "${out}" ] && { printf '%s' "${out}"; return 0; }
    done
    return 1
}

cdp_up() { cdp_json "$1" >/dev/null 2>&1; }

cdp_ws() {
    cdp_json "$1" 2>/dev/null | python3 -c \
      'import sys,json
try: print(json.load(sys.stdin).get("webSocketDebuggerUrl","-"))
except Exception: print("-")' 2>/dev/null || echo "-"
}

cdp_browser() {
    cdp_json "$1" 2>/dev/null | python3 -c \
      'import sys,json
try: print(json.load(sys.stdin).get("Browser","-"))
except Exception: print("-")' 2>/dev/null || echo "-"
}

# ---------------------------------------------------------------- process lookup
# Root Chrome browser process = has --user-data-dir=<profile> and NOT --type=
# (the --type= ones are its zygote/renderer/gpu children).
root_pid_for_profile() {
    local profile="$1" pid args
    for pid in $(pgrep -f -- "--user-data-dir=${profile}" 2>/dev/null); do
        args=$(ps -p "${pid}" -o args= 2>/dev/null) || continue
        case "${args}" in
            *--type=*) continue ;;                 # child process
        esac
        case "${args}" in
            *chrome*--user-data-dir="${profile}"*|*chrome*--user-data-dir="${profile}" ) ;;
            *) continue ;;
        esac
        # must be the actual chrome binary, not a shell/grep that mentions the path
        case "${args}" in
            /*chrome*|*/chrome\ *) echo "${pid}"; return 0 ;;
        esac
    done
    return 1
}

all_pids_for_profile() {
    local profile="$1" pid args
    for pid in $(pgrep -f -- "--user-data-dir=${profile}" 2>/dev/null); do
        [ "${pid}" = "$$" ] && continue
        args=$(ps -p "${pid}" -o args= 2>/dev/null) || continue
        case "${args}" in
            *chrome*) echo "${pid}" ;;             # chrome binary or crashpad handler
        esac
    done
}

# ---------------------------------------------------------------- guards
guard_tmp_profile() {
    local profile="$1" resolved
    resolved=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${profile}" 2>/dev/null || echo "${profile}")
    case "${resolved}" in
        /tmp/*|/tmp|/var/tmp/*|/dev/shm/*)
            echo "ERROR: profile resolves to ${resolved}, which is volatile (wiped on reboot)." >&2
            echo "  Saved logins and cookies would not survive. Refusing." >&2
            return 1 ;;
    esac
    return 0
}

# ---------------------------------------------------------------- start one
start_one() {
    local name="$1"
    local port profile
    port=$(port_for "${name}") || { echo "LAUNCH: unknown instance '${name}'" >&2; return 2; }
    profile=$(profile_for "${name}")

    guard_tmp_profile "${profile}" || return 1

    if cdp_up "${port}"; then
        if root_pid_for_profile "${profile}" >/dev/null 2>&1; then
            echo "  ${name}: already up on port ${port} (not spawning a duplicate)"
            return 0
        fi
        # Port answers but no Chrome holds our profile: something else owns this port.
        # Do NOT claim success - the operator's profile is not loaded.
        echo "  ${name}: WARNING port ${port} answers but NO Chrome holds ${profile}." >&2
        echo "    Another browser is squatting the port. Not spawning a duplicate." >&2
        echo "    Investigate:  ss -tlnp | grep ${port}" >&2
        return 1
    fi

    local chrome
    chrome=$(locate_chrome) || {
        echo "ERROR: no Chrome binary found." >&2
        echo "  Expected Chrome for Testing at ${CFT_ROOT}/chrome-linux64/chrome" >&2
        return 1
    }

    resolve_display
    if ! have_display && [ "${OPT_HEADLESS}" -eq 0 ]; then
        echo "ERROR: no display found (DISPLAY and WAYLAND_DISPLAY both empty, no /tmp/.X11-unix/X*)." >&2
        echo "  These browsers are HEADED on purpose: the operator must be able to log in," >&2
        echo "  and bot-walls fingerprint headless. Not silently falling back." >&2
        echo "  If this box truly has no display, re-run with:  LAUNCH --headless ${name}" >&2
        return 1
    fi

    # clean = negative control: must be pristine every launch. We WIPE the persistent
    # profile dir rather than use --incognito (see LAUNCH.md for the tradeoff).
    if [ "${name}" = "clean" ]; then
        if [ -d "${profile}" ]; then
            rm -rf "${profile}" 2>/dev/null || true
            echo "  clean: wiped profile for a pristine baseline"
        fi
    fi

    mkdir -p "${profile}" "${LOG_DIR}"

    local -a flags=(
        --remote-debugging-port="${port}"
        --user-data-dir="${profile}"
        --no-first-run
        --no-default-browser-check
        --disable-session-crashed-bubble
        --disable-features=Translate
    )
    [ "${name}" = "main" ] && flags+=( --restore-last-session )

    # honour the legacy cdp-chrome.sh extension staging dir, main only
    if [ "${name}" = "main" ]; then
        local ext_root="${BB_ROOT}/extensions" ext_dirs="" d
        if [ -d "${ext_root}" ]; then
            for d in "${ext_root}"/*/; do
                [ -f "${d}manifest.json" ] && ext_dirs="${ext_dirs:+${ext_dirs},}${d%/}"
            done
        fi
        [ -n "${ext_dirs}" ] && flags+=( --load-extension="${ext_dirs}" )
    fi

    if [ "${OPT_HEADLESS}" -eq 1 ]; then
        flags+=( --headless=new )
        echo "  ${name}: WARNING --headless=new (operator cannot log in; bot-walls detect this)"
    fi
    if [ "${OPT_INSECURE}" -eq 1 ]; then
        flags+=( --disable-web-security --no-sandbox )
        echo "  ${name}: WARNING --disable-web-security --no-sandbox -> findings from this instance are NOT valid"
    fi

    local log="${LOG_DIR}/${name}.log"
    {
        echo ""
        echo "=== LAUNCH ${name} $(date -Is) port=${port} profile=${profile} ==="
        echo "=== X: $(x_status) ==="
    } >> "${log}" 2>/dev/null

    # setsid + nohup + closed stdin: survives the parent shell exiting
    setsid nohup "${chrome}" "${flags[@]}" >> "${log}" 2>&1 < /dev/null &
    disown 2>/dev/null || true

    local deadline=$(( $(date +%s) + 20 ))
    while [ "$(date +%s)" -lt "${deadline}" ]; do
        cdp_up "${port}" && { echo "  ${name}: up on port ${port}"; return 0; }
        sleep 1
    done

    echo "  ${name}: FAILED - no CDP answer on port ${port} within 20s. Log tail:" >&2
    tail -n 12 "${log}" >&2
    return 1
}

# ---------------------------------------------------------------- stop one
stop_one() {
    local name="$1"
    local port profile pid
    port=$(port_for "${name}") || { echo "LAUNCH: unknown instance '${name}'" >&2; return 2; }
    profile=$(profile_for "${name}")

    pid=$(root_pid_for_profile "${profile}" 2>/dev/null || true)

    if [ -z "${pid}" ] && ! cdp_up "${port}"; then
        echo "  ${name}: not running"
        return 0
    fi

    if [ -n "${pid}" ]; then
        # SIGTERM the ROOT process only and let Chrome tear down its own children.
        # Matching on --user-data-dir (as hunt-stack.sh does) never touches the
        # operator's unrelated browsing; a blanket `pkill chrome` would.
        kill "${pid}" 2>/dev/null && echo "  ${name}: SIGTERM to root PID ${pid}"
        local deadline=$(( $(date +%s) + 10 ))
        while [ "$(date +%s)" -lt "${deadline}" ]; do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 1
        done
        if kill -0 "${pid}" 2>/dev/null; then
            kill -9 "${pid}" 2>/dev/null && echo "  ${name}: SIGKILL to PID ${pid}"
            sleep 1
        fi
    fi

    # sweep any orphaned children/crashpad still holding this exact profile
    local leftovers
    leftovers=$(all_pids_for_profile "${profile}" | tr '\n' ' ')
    if [ -n "${leftovers// /}" ]; then
        echo "${leftovers}" | xargs -r kill 2>/dev/null || true
        sleep 1
        leftovers=$(all_pids_for_profile "${profile}" | tr '\n' ' ')
        [ -n "${leftovers// /}" ] && { echo "${leftovers}" | xargs -r kill -9 2>/dev/null || true; }
    fi

    if cdp_up "${port}"; then
        echo "  ${name}: WARNING port ${port} still answers" >&2
        return 1
    fi
    echo "  ${name}: stopped"
    return 0
}

# ---------------------------------------------------------------- status
print_status() {
    printf '%-9s %-6s %-8s %-43s %-6s %s\n' NAME PORT PID PROFILE STATE "CDP webSocketDebuggerUrl"
    printf '%-9s %-6s %-8s %-43s %-6s %s\n' \
        --------- ------ -------- ------------------------------------------- ------ ------------------------------------------------
    local name port profile pid state ws
    for name in "${NAMES[@]}"; do
        port=$(port_for "${name}")
        profile=$(profile_for "${name}")
        pid=$(root_pid_for_profile "${profile}" 2>/dev/null || echo "-")
        [ -z "${pid}" ] && pid="-"
        if cdp_up "${port}"; then
            # A port answering is NOT proof OUR instance is up: another Chrome (the
            # operator's personal one, playwright's, a stale one) can squat the port.
            # Our instance is only confirmed when a root PID holds THIS profile.
            if [ "${pid}" = "-" ]; then state=FOREIGN; else state=UP; fi
            ws=$(cdp_ws "${port}")
        else
            state=DOWN
            ws="-"
        fi
        printf '%-9s %-6s %-8s %-43s %-6s %s\n' \
            "${name}" "${port}" "${pid}" "${profile}" "${state}" "${ws}"
    done
    echo
    echo "STATE: UP = our profile is loaded | FOREIGN = port answers but another browser owns it | DOWN = not running"
    echo "Clients: connect to the LITERAL IP in the ws URL. Never the hostname 'localhost'."
    echo "Chrome >=111 rejects a CDP websocket with a non-allowlisted Origin -> suppress_origin=True."
}

print_urls() {
    local name port ws first=1
    echo "{"
    for name in "${NAMES[@]}"; do
        port=$(port_for "${name}")
        if cdp_up "${port}"; then ws=$(cdp_ws "${port}"); else ws=""; fi
        [ "${first}" -eq 0 ] && echo ","
        first=0
        printf '  "%s": {"port": %s, "ws": %s, "profile": "%s", "up": %s}' \
            "${name}" "${port}" \
            "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1] or None))' "${ws}")" \
            "$(profile_for "${name}")" \
            "$(cdp_up "${port}" && echo true || echo false)"
    done
    echo
    echo "}"
}

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
}

# ---------------------------------------------------------------- arg parsing
ARGS=()
for a in "$@"; do
    case "${a}" in
        --headless) OPT_HEADLESS=1 ;;
        --insecure) OPT_INSECURE=1 ;;
        -h|--help)  usage; exit 0 ;;
        *)          ARGS+=("${a}") ;;
    esac
done
set -- "${ARGS[@]+${ARGS[@]}}"

CMD="${1:-all}"

case "${CMD}" in
    all)
        echo "LAUNCH: starting all CDP browsers"
        rc=0
        for n in "${NAMES[@]}"; do start_one "${n}" || rc=1; done
        echo
        print_status
        exit "${rc}"
        ;;
    status)
        print_status
        ;;
    urls)
        print_urls
        ;;
    stop)
        if [ -n "${2:-}" ]; then
            stop_one "$2"; exit $?
        fi
        echo "LAUNCH: stopping all CDP browsers"
        rc=0
        for n in "${NAMES[@]}"; do stop_one "${n}" || rc=1; done
        exit "${rc}"
        ;;
    restart)
        if [ -n "${2:-}" ]; then
            stop_one "$2"; start_one "$2"; rc=$?
            echo; print_status; exit "${rc}"
        fi
        for n in "${NAMES[@]}"; do stop_one "${n}"; done
        rc=0
        for n in "${NAMES[@]}"; do start_one "${n}" || rc=1; done
        echo; print_status; exit "${rc}"
        ;;
    main|attacker|victim|clean)
        start_one "${CMD}"; rc=$?
        echo
        print_status
        exit "${rc}"
        ;;
    *)
        echo "LAUNCH: unknown command '${CMD}'" >&2
        echo >&2
        usage >&2
        exit 2
        ;;
esac
