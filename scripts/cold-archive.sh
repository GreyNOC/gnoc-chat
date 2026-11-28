#!/usr/bin/env bash
# cold-archive.sh - move idle bulk dirs off the system disk onto the 2TB drive, safely.
#
#   scripts/cold-archive.sh <dir> [<dir> ...]     archive each dir, verify, then remove the original
#   scripts/cold-archive.sh --restore <archive>   unpack an archive back to its original path
#
# Each dir becomes ONE .tar.zst on the 2TB drive (NTFS cannot hold Unix permissions or symlinks,
# a tarball can). The original is removed ONLY after: zstd -t passes AND the archive lists exactly
# as many entries as the original holds. A <name>.ARCHIVED.md pointer is left where the dir was.
# Log: .claude/state/cold-archive.log
set -uo pipefail
WS=${GNOC_WORKSPACE:-$HOME/.gnoc}
COLD=${COLD:-/media/gn/1E7C7E757C7E4813/the workspace-cold}
LOG=$WS/.claude/state/cold-archive.log
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

if [ "${1:-}" = "--restore" ]; then
  a=${2:?archive}; rel=$(basename "$a" .tar.zst | sed 's#__#/#g')
  mkdir -p "$WS/$(dirname "$rel")" && tar --zstd -xpf "$a" -C "$WS/$(dirname "$rel")" && rm -f "$WS/$rel.ARCHIVED.md" \
    && log "restored $rel from $a"; exit $?
fi

mountpoint -q "$(dirname "$COLD")" || { log "ABORT: 2TB drive not mounted at $(dirname "$COLD")"; exit 2; }
mkdir -p "$COLD"
for d in "$@"; do
  src=$(realpath -s "$WS/$d" 2>/dev/null || true)
  case "$src" in "$WS"/*) ;; *) log "SKIP $d: not inside the workspace"; continue;; esac
  [ -d "$src" ] || { log "SKIP $d: not a directory"; continue; }
  rel=${src#"$WS"/}; name=$(echo "$rel" | sed 's#/#__#g'); out="$COLD/$name.tar.zst"
  if lsof +D "$src" >/dev/null 2>&1; then log "SKIP $rel: files are open"; continue; fi
  size=$(du -xsh "$src" | cut -f1)
  log "archiving $rel ($size) -> $out"
  if ! tar --zstd -cpf "$out.part" -C "$(dirname "$src")" "$(basename "$src")" 2>>"$LOG"; then
    log "FAIL tar $rel; original kept"; rm -f "$out.part"; continue
  fi
  want=$(find "$src" -mindepth 0 | wc -l)
  zstd -tq "$out.part" 2>>"$LOG" || { log "FAIL zstd -t $rel; original kept"; continue; }
  got=$(tar --zstd -tf "$out.part" | wc -l)
  if [ "$got" -ne "$want" ]; then log "FAIL count $rel: archive $got entries vs original $want; original kept"; continue; fi
  mv "$out.part" "$out"
  rm -rf "$src"
  cat > "$src.ARCHIVED.md" <<EOF
# ARCHIVED to the 2TB drive $(date -u +%F)
This directory ($size, $want entries) was moved off the system disk.
Archive: $out
Restore: scripts/cold-archive.sh --restore "$out"
EOF
  log "DONE $rel: $want entries verified, archive $(du -h "$out" | cut -f1), original removed"
done
log "batch finished; /home now: $(df -h /home | tail -1 | awk '{print $4" free ("$5" used)"}')"
