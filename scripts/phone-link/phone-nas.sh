#!/usr/bin/env bash
# phone-nas.sh mount|umount|status|speed|conf - the phone's 462 GB of shared storage as a local folder.
#
# The transport is the SAME ssh link the reviver uses: Termux's sshd on the phone's loopback, reached through
# `adb forward` on 127.0.0.1:8022. Nothing is on WiFi; unplug the cable and the mount simply goes away.
# rclone's sftp backend does the work (it is already installed, and unlike sshfs it needs no apt and no root).
set -uo pipefail

MNT="${PHONE_NAS_MNT:-$HOME/phone-nas}"
KEY="${PHONE_SSH_KEY:-$HOME/.ssh/gnoc-phone}"
PORT="${PHONE_SSH_PORT:-8022}"
REMOTE_PATH="${PHONE_NAS_PATH:-/storage/emulated/0}"
CONF="$HOME/.config/rclone/rclone.conf"
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# phone_link.py (the pm2 supervisor) re-mounts whenever this flag exists and the mount is gone or stale,
# so the NAS survives a replug, a phone reboot and Android recycling Termux, without anyone typing anything.
ON_FLAG="$WS/.claude/state/orch/phone-nas.on"
LOG="$HOME/.cache/phone-nas.log"
DROP="GNOC-NAS"          # a plain folder on the phone to drop things in; the rest of /sdcard is there too

ssh_phone() {
  # `timeout` as well as ConnectTimeout: a session that hangs AFTER connecting would otherwise block the
  # supervisor's mount attempt indefinitely.
  timeout 15 ssh -i "$KEY" -p "$PORT" -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR 127.0.0.1 "$@"
}

# The Termux app's Android user name (u0_aNN). It changes if Termux is reinstalled, so it is looked up, not
# hardcoded; Termux's sshd actually accepts any name, but rclone insists on being told one.
phone_user() {
  local u
  u="$(ssh_phone whoami 2>/dev/null | tr -d '\r')"
  [ -n "$u" ] && { echo "$u"; return 0; }
  sed -n 's/^user *= *//p' "$CONF" 2>/dev/null | head -1    # fall back to what we configured last time
}

ensure_conf() {
  local u; u="$(phone_user)"
  [ -n "$u" ] || { echo "cannot reach the phone's sshd on 127.0.0.1:$PORT (gnoc phone status)" >&2; return 1; }
  mkdir -p "$(dirname "$CONF")"
  if ! grep -q '^\[phone\]' "$CONF" 2>/dev/null; then
    cat >> "$CONF" <<CONFEOF
[phone]
type = sftp
host = 127.0.0.1
port = $PORT
user = $u
key_file = $KEY
shell_type = unix
set_modtime = true
CONFEOF
  else
    sed -i "/^\[phone\]/,/^\[/{s|^user *=.*|user = $u|}" "$CONF"
  fi
}

mounted() {
  mountpoint -q "$MNT" 2>/dev/null || return 1
  ls "$MNT" >/dev/null 2>&1          # a dead FUSE mount answers ENOTCONN here instead of hanging
}

do_mount() {
  mkdir -p "$(dirname "$ON_FLAG")" && : > "$ON_FLAG"      # tell the supervisor to keep it mounted
  mounted && { echo "already mounted at $MNT"; return 0; }
  # Serialise. A mount takes a few seconds to come up, and during that window `mounted` is still false, so a
  # second caller (the supervisor's 60s retry, or someone typing the command) would start a SECOND rclone
  # daemon on the same mountpoint. The two then unmount each other on exit and the NAS flaps - which is
  # exactly what the "mount failed" lines over a working mount turned out to be on 2026-10-25.
  exec 9>"${TMPDIR:-/tmp}/phone-nas.lock"
  flock -n 9 || { echo "another mount is already starting"; return 0; }
  ensure_conf || return 1
  mkdir -p "$MNT" "$(dirname "$LOG")"
  fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || true   # clear a stale mount
  ssh_phone "mkdir -p \$HOME/storage/shared/$DROP" >/dev/null 2>&1
  # --vfs-cache-mode writes: Android's emulated storage cannot do the partial/random writes a plain
  # passthrough needs, so writes are staged locally and uploaded whole. Reads stream straight through.
  rclone mount "phone:$REMOTE_PATH" "$MNT" \
    --daemon \
    --vfs-cache-mode writes \
    --vfs-cache-max-size 4G \
    --vfs-read-chunk-size 32M \
    --vfs-read-chunk-size-limit 256M \
    --buffer-size 32M \
    --transfers 4 \
    --dir-cache-time 30s \
    --attr-timeout 5s \
    --log-level INFO --log-file "$LOG"
  local rc=$?
  # The MOUNTPOINT is the authority, not rclone's exit code: with --daemon the parent can return non-zero
  # while the forked daemon goes on to mount perfectly well, which had the supervisor logging "mount failed"
  # over a mount that was in fact up (seen 2026-10-25). Poll for it instead.
  for _ in $(seq 1 25); do mounted && break; sleep 1; done
  mounted || { echo "mount did not come up (rclone rc=$rc, see $LOG)" >&2; return 1; }
  echo "mounted: $MNT  ->  the phone's $REMOTE_PATH   (drop folder: $MNT/$DROP)"
}

do_umount() {
  rm -f "$ON_FLAG"                                        # stop the supervisor putting it straight back
  mountpoint -q "$MNT" 2>/dev/null || { echo "not mounted"; return 0; }
  fusermount3 -u "$MNT" 2>/dev/null || fusermount -u "$MNT" 2>/dev/null || {
    echo "busy - something still has a file open under $MNT" >&2; return 1; }
  echo "unmounted $MNT"
}

do_status() {
  if mounted; then
    echo "mounted  $MNT"
    df -h "$MNT" 2>/dev/null | tail -1 | awk '{printf "  %s used of %s, %s free\n", $3, $2, $4}'
  elif mountpoint -q "$MNT" 2>/dev/null; then
    echo "STALE    $MNT (the cable or the phone went away; phone-nas.sh mount fixes it)"
  else
    echo "not mounted  ($MNT)"
  fi
  [ -e "$ON_FLAG" ] && echo "  keeper   on (phone-link re-mounts it after a replug or a phone reboot)"
  # The link speed is the thing people get wrong: a USB 2.0 cable caps this at ~40 MB/s no matter what.
  local dev speed
  dev="$(for d in /sys/bus/usb/devices/*/; do
           [ "$(cat "$d/idVendor" 2>/dev/null)" = "04e8" ] && { echo "$d"; break; }; done)"
  [ -n "$dev" ] && speed="$(cat "$dev/speed" 2>/dev/null)"
  case "${speed:-}" in
    "") echo "  usb      phone not on USB" ;;
    480) echo "  usb      480 Mbit/s (USB 2.0) - about 40 MB/s. This port can do 5 Gbit/s:" \
              "a USB 3 cable (not the charging one) is the whole difference." ;;
    *) echo "  usb      $speed Mbit/s" ;;
  esac
}

do_speed() {
  # Measured with `rclone copyto`, NOT through the mount: the mount stages writes in a local cache
  # (--vfs-cache-mode writes) and serves recent reads from it, so timing a dd against $MNT measures
  # this laptop's SSD and reports hundreds of MB/s over a 40 MB/s cable. This is the real link.
  ensure_conf || return 1
  local mb="${PHONE_NAS_SPEED_MB:-128}"
  local tmp="${TMPDIR:-/tmp}/phone-nas-speed.$$" back="${TMPDIR:-/tmp}/phone-nas-speed.back.$$"
  local remote="phone:$REMOTE_PATH/$DROP/.speedtest.bin" w r
  head -c $((mb * 1048576)) /dev/urandom > "$tmp"       # incompressible, so nothing is won by compression
  echo "  $mb MB over the USB link, cache bypassed:"
  local t0
  t0=$(date +%s.%N); rclone copyto "$tmp" "$remote" >/dev/null 2>&1 || w=""; w=$(echo "$(date +%s.%N) - $t0" | bc)
  t0=$(date +%s.%N); rclone copyto "$remote" "$back" >/dev/null 2>&1 || r=""; r=$(echo "$(date +%s.%N) - $t0" | bc)
  awk -v w="$w" -v r="$r" -v mb="$mb" 'BEGIN{
    if (w+0>0) printf "  write  %.1f MB/s  (%.1fs)\n", mb/w, w; else print "  write  failed";
    if (r+0>0) printf "  read   %.1f MB/s  (%.1fs)\n", mb/r, r; else print "  read   failed"; }'
  rclone delete "$remote" >/dev/null 2>&1
  rm -f "$tmp" "$back"
}

case "${1:-status}" in
  mount) do_mount ;;
  umount|unmount) do_umount ;;
  status) do_status ;;
  speed) do_speed ;;
  conf) ensure_conf && echo "rclone remote [phone] is configured in $CONF" ;;
  *) echo "usage: phone-nas.sh [mount|umount|status|speed|conf]" >&2; exit 2 ;;
esac
