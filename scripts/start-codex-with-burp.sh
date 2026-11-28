#!/usr/bin/env bash
# One-shot launcher that does not require a persistent mcp_servers.burp entry.
# It still requires Burp to be running on the graphical desktop first.
set -uo pipefail

WORKSPACE=${GNOC_WORKSPACE:-$HOME/.gnoc}
BRIDGE="$WORKSPACE/scripts/mcp_sse_stdio_bridge.py"

python3 "$WORKSPACE/scripts/bbtools/burp_resolve.py" || exit 1

exec codex \
  -C "$WORKSPACE" \
  -c 'mcp_servers.burp.command="python3"' \
  -c "mcp_servers.burp.args=['$BRIDGE','http://127.0.0.1:9876/']" \
  "$@"
