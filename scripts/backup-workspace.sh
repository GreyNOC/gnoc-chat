#!/usr/bin/env bash
# Backup the workspace workspace + global ~/.claude to the 1.8TB HDD as tar.zst.
# Integrity-gated: each archive is verified with `zstd -t` (CRC of the
# compressed stream) before it counts as done. Re-runnable; dated artifacts.
# ponytail: tar.zst over rsync because target is NTFS (perms/symlinks map badly)
set -u

DEST=/mnt/backup
DATE=$(date +%Y-%m-%d)
STAMP=$(date +%Y-%m-%d-%H%M%S)
THREADS=$(nproc)
LOG="$DEST/.bb-backup-$STAMP.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

backup() {  # $1=src_parent  $2=src_name  $3=archive_basename
  local parent="$1" name="$2" out="$DEST/$3-$DATE.tar.zst"
  log "ARCHIVE start: $parent/$name -> $out"
  # --warning=no-file-changed + ignore-failed-read so a live transcript write
  # does not abort the run; real integrity is the zstd -t gate below.
  tar --warning=no-file-changed --ignore-failed-read \
      -I "zstd -T$THREADS -3" -cf "$out" -C "$parent" "$name" 2>>"$LOG"
  local sz; sz=$(du -h "$out" | cut -f1)
  log "ARCHIVE written: $out ($sz). Verifying..."
  if zstd -t "$out" 2>>"$LOG"; then
    log "VERIFY OK: $out"
    return 0
  else
    log "VERIFY FAILED: $out"
    return 1
  fi
}

log "=== Backup run $STAMP (threads=$THREADS, dest=$DEST) ==="
df -h "$DEST" | tail -1 | tee -a "$LOG"

rc=0
backup $HOME/Desktop the workspace the workspace-backup || rc=1
backup $HOME      .claude    global-claude-backup || rc=1

if [ "$rc" -eq 0 ]; then
  log "=== ALL BACKUPS VERIFIED OK ==="
else
  log "=== BACKUP RUN HAD FAILURES (rc=$rc) ==="
fi
echo "$LOG"
exit "$rc"
