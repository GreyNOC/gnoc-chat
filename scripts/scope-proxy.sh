#!/usr/bin/env bash
# scope-proxy.sh start|stop|status [program]  - network scope enforcement (bbtools/scope_proxy.py)
# Clients: export GNOC_SCOPE_PROXY=http://127.0.0.1:8084 (lib_egress.make_session honours it).
# Program: arg, else HUNT_TARGET, else this session's LOCK.<sid>, else every LOCK.<sid> (conflict = refuse
# to start), else the global LOCK - resolved by scope_proxy.py itself so the shell and the addon agree.
# SCOPE_PROXY_STRICT=1 (default) drops github.io + storage.googleapis.com from the toolchain allowlist.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ST="$ROOT/.claude/state/hunt-loop"; PIDF="$ST/scope-proxy.pid"; LOG="$ST/scope-proxy.log"; PORT=8084
alive() { [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }
case "$1" in
  start)
    alive && { echo "already running pid $(cat "$PIDF")"; exit 0; }
    if [ -n "$2" ]; then PROG="$2"
    else PROG="$(python3 "$ROOT/scripts/bbtools/scope_proxy.py" resolve)" || { echo "no program: pass one, or set HUNT_TARGET (see message above)"; exit 2; }
    fi
    case "$PROG" in ""|*[!A-Za-z0-9._-]*) echo "bad or empty program '$PROG'"; exit 2 ;; esac
    [ -f "$ROOT/targets/$PROG/SCOPE.txt" ] || { echo "no SCOPE.txt for $PROG"; exit 2; }
    mkdir -p "$ST"
    # system pyOpenSSL is too old for cryptography 50 (mitmdump import fails); a --target shim fixes it.
    [ -d "$ST/pyossl" ] && export PYTHONPATH="$ST/pyossl${PYTHONPATH:+:$PYTHONPATH}"
    HUNT_TARGET="$PROG" SCOPE_PROXY_ACTIVE=1 nohup mitmdump -s "$ROOT/scripts/bbtools/scope_proxy.py" \
      --listen-host 127.0.0.1 -p $PORT --set connection_strategy=lazy >"$LOG" 2>&1 &
    echo $! >"$PIDF"; sleep 3
    alive && echo "scope-proxy up pid $(cat "$PIDF") program=$PROG 127.0.0.1:$PORT" || { echo "failed, see $LOG"; tail -5 "$LOG"; rm -f "$PIDF"; exit 1; } ;;
  stop)
    alive && { kill "$(cat "$PIDF")"; echo stopped; } || echo "not running"; rm -f "$PIDF" ;;
  status)
    alive && echo "running pid $(cat "$PIDF") 127.0.0.1:$PORT" || echo "not running"
    echo "strict: SCOPE_PROXY_STRICT=${SCOPE_PROXY_STRICT:-1} (1 = github.io and storage.googleapis.com NOT allowlisted on the wire)"
    echo "burp: lib_egress cannot chain Burp itself. To scope-proxy Burp traffic set Burp > Settings > Network >"
    echo "      Connections > Upstream proxy servers: destination host *, proxy host 127.0.0.1, port $PORT."
    echo "      Without it Burp-routed sessions get only the python scope gate (lib_egress warns once)."
    [ -f "$ST/SCOPE-INCIDENTS.jsonl" ] && echo "incidents: $(wc -l <"$ST/SCOPE-INCIDENTS.jsonl")" ;;
  *) echo "usage: $0 start|stop|status [program]"; exit 2 ;;
esac
