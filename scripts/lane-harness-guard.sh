#!/usr/bin/env bash
# Lane harness guard (2026-10-26, drive D34). The lane worker is a small local model with a bash tool. In its verdict
# turn on program-0/brain-api-auth-console-10260155 it "fixed the driver script's tag-parsing" (its own words) and
# left scripts/opencode-lane.sh with a case statement swallowed by a comment, so every later lane would have died at
# parse time. The worker owns targets/<program>/hunts/<lane>/ and nothing else. Sourced by opencode-lane.sh:
#   harness_snap            at lane start: tar the harness text files into $SNAP
#   harness_check <label>   after every model turn: restore any harness file the turn changed, delete any it created,
#                           log the names; returns 1 when something was reverted
# The file set is the text of scripts/ and .opencode/ (no node_modules, no h1-feedback out/, no raw bytes).
HG_WS=${HG_WS:-${WS:-${GNOC_WORKSPACE:-$HOME/.gnoc}}}
HG_LOG=${HG_LOG:-/dev/stderr}

hg_files() {  # relative paths, newline separated
  ( cd "$HG_WS" && find scripts .opencode -type f \
      \( -name '*.py' -o -name '*.sh' -o -name '*.md' -o -name '*.json' -o -name '*.txt' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o -name '*.js' -o -name '*.mjs' \) \
      -not -path '*/node_modules/*' -not -path '*/out/*' -not -path '*/__pycache__/*' -not -path '*/.venv/*' 2>/dev/null )
}

harness_snap() {
  HG_SNAP=$(mktemp -d /tmp/lane-harness-XXXXXX)
  hg_files > "$HG_SNAP/list"
  ( cd "$HG_WS" && tar cf "$HG_SNAP/h.tar" -T "$HG_SNAP/list" 2>/dev/null )
  HG_MARK="$HG_SNAP/mark"; touch "$HG_MARK"
  echo "[$(date -u +%FT%TZ)] harness guard: $(wc -l < "$HG_SNAP/list") files snapshotted" >> "$HG_LOG"
}

HG_DB=${HG_DB:-$HOME/.local/share/opencode/opencode.db}

hg_worker_wrote() {  # $1 = opencode session id, $2.. = changed files; prints "file<TAB>command" per attributed write
  [ -n "$1" ] && [ -f "$HG_DB" ] || return 1
  local sid="$1"; shift
  python3 - "$HG_DB" "$sid" "$@" <<'PY'
import json, os, re, sqlite3, sys
db, sid, files = sys.argv[1], sys.argv[2], sys.argv[3:]
# a write-shaped command: an in-place editor, a redirection, a copy/move/link, a heredoc or a patch. "python3 ... -c"
# is NOT one: on 2026-10-26 03:14Z it matched "auth-console" inside a worker's JSON and the guard restored a file
# the operator had just patched (false positive, the one failure mode the guard must never have).
WRITE = re.compile(r"(sed\s+-i|perl\s+-i|\btee\b|(?<![<|])>>?(?!&)|\bcp\b|\bmv\b|\bln\b|\bpatch\b|\bchmod\b|<<)")
cmds = []
for (data,) in sqlite3.connect(db).execute("select data from part where session_id=? and data like '%\"tool\":\"bash\"%'", (sid,)):
    try:
        cmd = (json.loads(data).get("state") or {}).get("input", {}).get("command") or ""
    except Exception:
        continue
    if cmd:
        cmds.append(cmd)
hits = []
for f in files:
    base = os.path.basename(f)
    for cmd in cmds:
        # the file is named in the command AND the command writes: a `python3 scripts/x.py` run or a `cat` is not it
        if base in cmd and WRITE.search(cmd):
            hits.append(f + "\t" + cmd[:160].replace("\n", " "))
            break
print("\n".join(hits))
sys.exit(0 if hits else 1)
PY
}

harness_check() {  # $1 = label for the log, $2 = the worker's opencode session id
  [ -n "${HG_SNAP:-}" ] || return 0
  local changed new f rc=0 cmds
  changed=$( ( cd "$HG_WS" && find scripts .opencode -type f -newer "$HG_MARK" -not -path '*/__pycache__/*' -not -path '*/node_modules/*' -not -path '*/out/*' 2>/dev/null ) )
  [ -n "$changed" ] || { touch "$HG_MARK"; return 0; }
  # attribute: only a write-shaped command in the worker's OWN session naming the harness makes it the worker's edit;
  # the operator patches scripts/ while lanes run, and those edits must survive (2026-10-26).
  if ! cmds=$(hg_worker_wrote "${2:-}" $changed); then
    echo "[$(date -u +%FT%TZ)] harness guard ($1): changed during the turn but no write command naming them in the worker's session, left in place: $(echo $changed)" >> "$HG_LOG"
    touch "$HG_MARK"; return 0
  fi
  echo "[$(date -u +%FT%TZ)] harness guard ($1): worker write command(s): $(printf '%s' "$cmds" | tr '\t' ' ' | tr '\n' ';')" >> "$HG_LOG"
  changed=$(printf '%s\n' "$cmds" | cut -f1)
  for f in $changed; do
    if grep -qxF -- "$f" "$HG_SNAP/list"; then
      ( cd "$HG_WS" && tar xf "$HG_SNAP/h.tar" -- "$f" 2>/dev/null ) && echo "[$(date -u +%FT%TZ)] HARNESS WRITE by the worker ($1): $f changed, RESTORED from the lane-start snapshot" >> "$HG_LOG"
    else
      rm -f -- "$HG_WS/$f" && echo "[$(date -u +%FT%TZ)] HARNESS WRITE by the worker ($1): $f created outside its lane, DELETED" >> "$HG_LOG"
    fi
    rc=1
  done
  touch "$HG_MARK"
  return $rc
}

harness_done() { [ -n "${HG_SNAP:-}" ] && rm -rf "$HG_SNAP"; return 0; }
