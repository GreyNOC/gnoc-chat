#!/usr/bin/env bash
# proof-record.sh - "GreyNOC"-watermarked proof videos (approved by GreyNOC 2026-10-21:
# ffmpeg route, watermark text exactly "GreyNOC").
#
# WHY PER-WINDOW: this desktop is KDE Wayland + ROOTLESS Xwayland. A full-screen x11grab of
# :0 records black (verified 2026-10-21); a Wayland screencast needs an interactive portal
# prompt. Grabbing ONE X11 window by id works and records real pixels, and it also keeps
# every other window (other tabs, secrets) out of the frame.
#
# usage:
#   proof-record.sh run   <out.mp4> -- <command> [args...]
#       Opens an xterm, prints "$ <command>", runs it, records ONLY that window until the
#       command ends (+2 s hold). Also writes <out>.log (byte-exact stdout+stderr via tee),
#       <out>.json (UTC start/end, command, exit code) and <out>.sha256. Exits with the
#       command's exit code.
#   proof-record.sh start <out.mp4> --window <title-substring|0xWINDOWID>
#       Record an EXISTING X11 window (Burp, an X11 browser) in the background.
#   proof-record.sh stop  <out.mp4>      finalize a 'start' recording (+ .json, .sha256)
#   proof-record.sh status               list running 'start' recordings
#   proof-record.sh selftest             3 s recording to the scratch dir, then verifies it
#
# env: PROOF_FPS (default 10), PROOF_CRF (default 28), PROOF_HOLD (default 2 seconds)
# Evidence rule: a video is ADDITIONAL to the raw Burp panels and byte captures (SPINE 5),
# never a replacement.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$ROOT/.claude/state/proof-record"
FPS="${PROOF_FPS:-10}"
CRF="${PROOF_CRF:-28}"
HOLD="${PROOF_HOLD:-2}"
WATERMARK="GreyNOC"
VF="drawtext=text='${WATERMARK}':fontsize=28:fontcolor=white@0.6:borderw=2:bordercolor=black@0.6:x=w-tw-20:y=20,scale=trunc(iw/2)*2:trunc(ih/2)*2"

die() { echo "proof-record: $*" >&2; exit 2; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Same display/cookie resolution as scripts/burp-start.sh (Wayland needs the Xwayland cookie).
setup_display() {
  export DISPLAY="${DISPLAY:-:0}"
  if [ -z "${XAUTHORITY:-}" ] || [ ! -r "${XAUTHORITY:-/nonexistent}" ]; then
    local xa
    xa=$(ps -eo args 2>/dev/null | grep -o -- '-auth /run/user/[^ ]*' | head -1 | awk '{print $2}')
    [ -n "$xa" ] || xa=$(ps -eo args 2>/dev/null | grep -o -- '--xwayland-xauthority [^ ]*' | head -1 | awk '{print $2}')
    [ -n "$xa" ] || xa=$(find "/run/user/$(id -u)" -maxdepth 1 -type f -name 'xauth_*' -readable 2>/dev/null | head -1)
    [ -n "$xa" ] || xa="$HOME/.Xauthority"
    export XAUTHORITY="$xa"
  fi
  xwininfo -root >/dev/null 2>&1 || die "cannot open X display $DISPLAY (XAUTHORITY=$XAUTHORITY)"
}

resolve_window() { # title substring or 0x id -> 0x id
  local w="$1" id
  if [[ "$w" =~ ^0x[0-9a-fA-F]+$ ]]; then echo "$w"; return; fi
  id=$(xwininfo -root -tree 2>/dev/null | grep -F "\"" | grep -iF -- "$w" | awk '{print $1}' | head -1 || true)
  [ -n "$id" ] || die "no X11 window whose title contains: $w (Wayland-native windows cannot be grabbed; start the app on X11, e.g. QT_QPA_PLATFORM=xcb or chrome --ozone-platform=x11)"
  echo "$id"
}

start_ffmpeg() { # winid out logfile -> echoes pid
  local wid="$1" out="$2" flog="$3"
  ffmpeg -hide_banner -loglevel error -y -nostdin -f x11grab -framerate "$FPS" -window_id "$wid" -i "$DISPLAY" \
    -vf "$VF" -c:v libx264 -preset veryfast -crf "$CRF" -pix_fmt yuv420p -movflags +faststart \
    "$out" >"$flog" 2>&1 &
  echo $!
}

stop_ffmpeg() { # pid
  local pid="$1" i
  kill -INT "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.2; done
  kill -TERM "$pid" 2>/dev/null || true
}

finalize() { # out json-fields...
  local out="$1"; shift
  [ -s "$out" ] || die "recording is empty: $out"
  local dur size
  dur=$(ffprobe -v error -show_entries format=duration -of default=nw=1:nk=1 "$out" 2>/dev/null || echo 0)
  size=$(wc -c <"$out" | tr -d ' ')
  python3 -I -c 'import json,sys; d=dict(a.split("=",1) for a in sys.argv[2:]); d["watermark"]="GreyNOC"; d["duration_s"]=sys.argv[1]; print(json.dumps(d, indent=1))' \
    "$dur" "$@" "bytes=$size" "file=$(basename "$out")" >"${out%.*}.json"
  ( cd "$(dirname "$out")" && sha256sum "$(basename "$out")" >"$(basename "${out%.*}").sha256" )
  echo "proof-record: saved $out (${dur}s, $size bytes) + .json + .sha256"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  run)
    out="${1:-}"; shift || true
    [ -n "$out" ] && [ "${1:-}" = "--" ] || die "usage: run <out.mp4> -- <command> [args...]"
    shift; [ $# -gt 0 ] || die "no command given"
    setup_display; mkdir -p "$(dirname "$out")"; out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
    tag="gnoc-proof-$$-$(date +%s)"
    work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
    log="${out%.*}.log"
    printf '%q ' "$@" >"$work/cmd"
    printf '%s' "$*" >"$work/show"
    cat >"$work/inner.sh" <<EOF
#!/usr/bin/env bash
printf '\$ %s\n' "\$(cat '$work/show')"
bash -c "\$(cat '$work/cmd')" 2>&1 | tee '$log'
echo "\${PIPESTATUS[0]}" >'$work/rc'
sleep 600
EOF
    chmod +x "$work/inner.sh"
    xterm -geometry 120x34 -fa 'Noto Sans Mono' -fs 11 -bg black -fg white -T "$tag" -e "$work/inner.sh" &
    xpid=$!
    wid=""; for i in $(seq 1 50); do wid=$(xwininfo -name "$tag" 2>/dev/null | awk '/Window id:/{print $4}' || true); [ -n "$wid" ] && break; sleep 0.1; done
    [ -n "$wid" ] || { kill "$xpid" 2>/dev/null; die "xterm window did not appear"; }
    t0=$(utc); fpid=$(start_ffmpeg "$wid" "$out" "$work/ffmpeg.log")
    while [ ! -s "$work/rc" ]; do kill -0 "$xpid" 2>/dev/null || break; sleep 0.2; done
    sleep "$HOLD"; stop_ffmpeg "$fpid"; t1=$(utc)
    kill "$xpid" 2>/dev/null || true
    rc=$(cat "$work/rc" 2>/dev/null || echo 255)
    [ -s "$out" ] || { cat "$work/ffmpeg.log" >&2; die "ffmpeg produced no file"; }
    finalize "$out" "mode=run" "start_utc=$t0" "end_utc=$t1" "command=$(cat "$work/cmd")" "exit_code=$rc" "log=$(basename "$log")"
    exit "$rc"
    ;;
  start)
    out="${1:-}"; [ "${2:-}" = "--window" ] && [ -n "${3:-}" ] || die "usage: start <out.mp4> --window <title|0xID>"
    setup_display; mkdir -p "$(dirname "$out")" "$STATE"; out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
    wid=$(resolve_window "$3")
    key=$(printf '%s' "$out" | sha256sum | cut -c1-16)
    [ ! -e "$STATE/$key.pid" ] || die "already recording $out (run stop first)"
    fpid=$(start_ffmpeg "$wid" "$out" "$STATE/$key.ffmpeg.log")
    sleep 0.5; kill -0 "$fpid" 2>/dev/null || { cat "$STATE/$key.ffmpeg.log" >&2; die "ffmpeg failed to start"; }
    printf '%s\n%s\n%s\n%s\n' "$fpid" "$out" "$(utc)" "$wid" >"$STATE/$key.pid"
    echo "proof-record: recording window $wid -> $out (pid $fpid); stop with: $0 stop $out"
    ;;
  stop)
    out="${1:-}"; [ -n "$out" ] || die "usage: stop <out.mp4>"
    out="$(cd "$(dirname "$out")" && pwd)/$(basename "$out")"
    key=$(printf '%s' "$out" | sha256sum | cut -c1-16); pf="$STATE/$key.pid"
    [ -e "$pf" ] || die "no running recording for $out"
    { read -r fpid; read -r _; read -r t0; read -r wid; } <"$pf"
    stop_ffmpeg "$fpid"; rm -f "$pf" "$STATE/$key.ffmpeg.log"
    finalize "$out" "mode=window" "start_utc=$t0" "end_utc=$(utc)" "window_id=$wid"
    ;;
  status)
    ls "$STATE"/*.pid >/dev/null 2>&1 || { echo "no recordings running"; exit 0; }
    for pf in "$STATE"/*.pid; do { read -r p; read -r o; read -r t; } <"$pf"; s=dead; kill -0 "$p" 2>/dev/null && s=running; echo "$s pid=$p since=$t $o"; done
    ;;
  selftest)
    sp="${TMPDIR:-/tmp}/proof-record-selftest-$$"; mkdir -p "$sp"
    PROOF_HOLD=1 "$0" run "$sp/selftest.mp4" -- bash -c 'for i in 1 2 3; do echo "GNOC_SELFTEST line $i"; sleep 0.5; done'
    grep -q 'GNOC_SELFTEST line 3' "$sp/selftest.log" || die "SELFTEST FAIL: log missing output"
    ( cd "$sp" && sha256sum -c selftest.sha256 >/dev/null ) || die "SELFTEST FAIL: sha256"
    yavg=$(ffmpeg -hide_banner -sseof -0.5 -i "$sp/selftest.mp4" -vf signalstats,metadata=print:key=lavfi.signalstats.YMAX -f null - 2>&1 | grep -o 'YMAX=[0-9.]*' | tail -1 | cut -d= -f2)
    [ "${yavg%.*}" -gt 100 ] || die "SELFTEST FAIL: frame looks blank (YMAX=$yavg)"
    echo "SELFTEST OK: $sp/selftest.mp4 (non-blank frame, YMAX=$yavg)"
    ;;
  *) sed -n '2,25p' "$0"; exit 1;;
esac
