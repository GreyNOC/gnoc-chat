#!/usr/bin/env bash
# wire-support-child.sh - grant the `Agent` tool to every FINDER agent so it can spawn a
# read-only support-child (AGENT-HIERARCHY.md + AGENT-DOCTRINE DOCTRINE-SUPPORT-CHILD).
# Idempotent (skips a file that already has Agent) and reversible (per-file .bak).
# Rollback: for f in .claude/agents/*.md.bak; do mv "$f" "${f%.bak}"; done
set -u
cd "$(dirname "$0")/.." || exit 1
AGENTS=.claude/agents
WIRED=0 SKIP=0 MISS=0

# Finders = every *-hunter.md plus the generalist bb-researcher.md. Children/gates are excluded.
for f in "$AGENTS"/*-hunter.md "$AGENTS"/bb-researcher.md; do
  [ -f "$f" ] || continue
  if ! grep -q '^tools:' "$f"; then echo "NO-TOOLS-LINE  $f"; MISS=$((MISS+1)); continue; fi
  if grep '^tools:' "$f" | grep -qw 'Agent'; then echo "skip(has Agent) $(basename "$f")"; SKIP=$((SKIP+1)); continue; fi
  cp "$f" "$f.bak"
  awk 'BEGIN{d=0} /^tools:/ && !d { if($0 !~ /(^|[, ])Agent([, ]|$)/){$0=$0", Agent"} d=1 } {print}' "$f.bak" > "$f"
  echo "wired          $(basename "$f")"; WIRED=$((WIRED+1))
done

echo "---"
echo "wired=$WIRED skip=$SKIP miss=$MISS"
echo "verify (every finder tools line must contain Agent):"
for f in "$AGENTS"/*-hunter.md "$AGENTS"/bb-researcher.md; do
  [ -f "$f" ] || continue
  grep '^tools:' "$f" | grep -qw 'Agent' || echo "  MISSING Agent -> $(basename "$f")"
done
echo "verify done (no MISSING lines above = all finders wired)"
