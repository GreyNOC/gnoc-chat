#!/usr/bin/env bash
# enable-btrfs-compression.sh - turn on transparent zstd compression for the system btrfs, then
# compress the existing workspace in place. Run ONCE with sudo, AFTER scripts/cold-archive.sh is done:
#
#   sudo ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/enable-btrfs-compression.sh
#
# Safe by construction: refuses if any snapshot subvolume exists (defragment would un-share snapshot
# extents and GROW usage), backs up /etc/fstab first, and only adds compress=zstd:3 to the two btrfs
# lines (/ and /home share one filesystem).
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
WS=${GNOC_WORKSPACE:-$HOME/.gnoc}
if pgrep -f scripts/cold-archive.sh >/dev/null; then echo "cold-archive.sh is still running; wait for it"; exit 1; fi
snaps=$(btrfs subvolume list -s / | wc -l)
if [ "$snaps" -gt 0 ]; then echo "REFUSED: $snaps snapshot(s) exist; defragment would duplicate their data"; exit 1; fi
cp -a /etc/fstab "/etc/fstab.bak-$(date +%Y%m%d%H%M%S)"
sed -i -E '/\sbtrfs\s/ { /compress=/! s/(subvol=\/@[a-z]*)/\1,compress=zstd:3/ }' /etc/fstab
grep -E '\sbtrfs\s' /etc/fstab
mount -o remount,compress=zstd:3 /
findmnt -no OPTIONS /home
before=$(df --output=used -B1M /home | tail -1)
# compress what is already on disk (text, captures, source); new writes are compressed automatically
btrfs filesystem defragment -r -czstd "$WS" $HOME/.claude 2>/dev/null || true
after=$(df --output=used -B1M /home | tail -1)
echo "used before ${before} MB, after ${after} MB, saved $(( before - after )) MB"
