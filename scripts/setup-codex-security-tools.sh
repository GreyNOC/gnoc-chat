#!/usr/bin/env bash
# Persist the browser and Burp MCP integrations for a new local Codex session.
# Run this from an ordinary desktop shell, not from the restricted hunt sandbox.
set -uo pipefail

WORKSPACE=${GNOC_WORKSPACE:-$HOME/.gnoc}
BRIDGE="$WORKSPACE/scripts/mcp_sse_stdio_bridge.py"
BURP_SSE_URL=http://127.0.0.1:9876/
SETUP_STATUS=0

if ! command -v codex >/dev/null 2>&1; then
    echo "ERROR: codex CLI is not on PATH" >&2
    exit 1
fi

if ! python3 "$BRIDGE" --selfcheck "$BURP_SSE_URL" >/dev/null; then
    echo "ERROR: the Burp SSE-to-stdio bridge failed its self-check" >&2
    exit 1
fi

echo "Installing the supported Chrome plugin..."
codex plugin add chrome@openai-bundled || {
    echo "WARNING: Chrome plugin installation failed. Check that ~/.codex is writable." >&2
    SETUP_STATUS=1
}

if codex mcp get burp >/dev/null 2>&1; then
    echo "Burp MCP entry already exists; leaving it unchanged:"
    codex mcp get burp
else
    echo "Registering Burp's legacy SSE server through the stdio bridge..."
    codex mcp add burp -- python3 "$BRIDGE" "$BURP_SSE_URL" || SETUP_STATUS=1
fi

echo
echo "Configured MCP servers:"
codex mcp list
echo
echo "Next: start Burp from the graphical desktop, complete its two-screen wizard,"
echo "verify it with: python3 $WORKSPACE/scripts/bbtools/burp_resolve.py"
echo "then start a NEW Codex session in $WORKSPACE so its tool inventory refreshes."

exit "$SETUP_STATUS"
