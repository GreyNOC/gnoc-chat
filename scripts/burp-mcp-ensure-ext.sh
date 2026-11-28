#!/usr/bin/env bash
# burp-mcp-ensure-ext.sh - register the official Burp MCP Server extension in Burp's
# USER config so it auto-loads on startup.
#
# Why this exists: the archived scripts/hunt-stack.sh `ensure-ext` hardcodes
#   $HOME/.BurpSuite/UserConfig.json
# which is the Burp *Professional* filename. Burp Suite COMMUNITY writes
#   $HOME/.BurpSuite/UserConfigCommunity.json
# so hunt-stack.sh ensure-ext fails outright on this box. This script auto-detects
# whichever file exists, and otherwise keeps hunt-stack.sh's approach: refuse to run
# while Burp is open, always back up first, patch
# user_options.extender.{settings,extensions}, and validate the JSON afterwards.
#
# Usage: burp-mcp-ensure-ext.sh [/abs/path/to/extension.jar]
set -euo pipefail

BURP_DIR="${BURP_DIR:-$HOME/.BurpSuite}"
MCP_JAR="${1:-$HOME/.local/opt/burp-extensions/burp-mcp-server.jar}"

# --- pick the right config file (Community vs Professional) ---
USER_CONFIG=""
for cand in "$BURP_DIR/UserConfigCommunity.json" "$BURP_DIR/UserConfig.json"; do
    if [ -f "$cand" ]; then USER_CONFIG="$cand"; break; fi
done
if [ -z "$USER_CONFIG" ]; then
    echo "ERROR: no Burp user config found. Looked for:" >&2
    echo "  $BURP_DIR/UserConfigCommunity.json   (Community)" >&2
    echo "  $BURP_DIR/UserConfig.json            (Professional)" >&2
    echo "  Launch Burp once so it creates one, close it, then re-run." >&2
    exit 1
fi
echo "--- burp-mcp-ensure-ext ---"
echo "  config: $USER_CONFIG"

# --- refuse to run while Burp is open: Burp rewrites this file on exit ---
if pgrep -f 'burpsuite_community\.jar|burpsuite_pro\.jar|BurpSuiteCommunity|BurpSuitePro' >/dev/null 2>&1; then
    echo "ERROR: Burp is RUNNING. Patch must be applied while Burp is CLOSED," >&2
    echo "       otherwise Burp overwrites the file on exit and the edit is lost." >&2
    echo "  1. Close Burp (File -> Quit)" >&2
    echo "  2. Re-run this script" >&2
    echo "  3. Relaunch Burp" >&2
    exit 1
fi

if [ ! -f "$MCP_JAR" ]; then
    echo "ERROR: extension jar not found: $MCP_JAR" >&2
    exit 1
fi

# --- timestamped backup ---
BAK="${USER_CONFIG}.$(date +%Y%m%d-%H%M%S).bak"
cp -p "$USER_CONFIG" "$BAK"
echo "  backup: $BAK"

python3 - "$USER_CONFIG" "$MCP_JAR" <<'PYEOF'
import sys, json, os

cfg_path, jar = sys.argv[1], os.path.abspath(sys.argv[2])

with open(cfg_path) as f:
    cfg = json.load(f)

ext = cfg.setdefault("user_options", {}).setdefault("extender", {})
settings = ext.setdefault("settings", {})
settings["automatically_reload_extensions_on_startup"] = True
print("  automatically_reload_extensions_on_startup -> True")

exts = ext.setdefault("extensions", [])
by_name = {e.get("name"): i for i, e in enumerate(exts)}

NAME = "Burp MCP Server"   # matches api.extension().setName() in the extension
entry = {
    "auto_reload": False,
    "errors": "ui",
    "extension_file": jar,
    "extension_type": "java",
    "loaded": True,
    "name": NAME,
    "output": "ui",
    "use_ai": False,
}

# Upsert, tolerating the BApp-store name ("MCP Server") if a previous install used it.
target = None
for alias in (NAME, "MCP Server"):
    if alias in by_name:
        target = by_name[alias]
        break

if target is None:
    exts.insert(0, entry)
    print("  %s: inserted (loaded=True, %s)" % (NAME, jar))
else:
    exts[target].update(entry)
    print("  %s: updated (loaded=True, %s)" % (NAME, jar))

ext["extensions"] = exts

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=4)

print("  extensions now: %s" % [e.get("name") for e in exts])
PYEOF

# --- validate ---
if python3 -m json.tool "$USER_CONFIG" >/dev/null; then
    echo "  JSON validates OK"
else
    echo "ERROR: JSON is invalid after patch. Restoring backup." >&2
    cp -p "$BAK" "$USER_CONFIG"
    exit 1
fi
echo "--- done ---"
