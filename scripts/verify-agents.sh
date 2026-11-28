#!/usr/bin/env bash
# verify-agents.sh - check every .claude/agents/*.md against AGENT-SPEC.
# Per file: frontmatter (name/description/tools), the body sections, and the output
# contract (DEAD/LEAD/CANDIDATE). Prints PASS or WARN+missing. Read-only.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" 2>/dev/null || exit 1
DIR=".claude/agents"
pass=0; warn=0; total=0

for f in "$DIR"/*.md; do
  [ -f "$f" ] || continue
  case "$(basename "$f")" in _*) continue ;; esac   # skip templates
  total=$((total+1))
  miss=""
  head -1 "$f" | grep -q '^---' || miss="$miss frontmatter"
  grep -qiE '^name:' "$f" || miss="$miss name"
  grep -qiE '^description:|^description:[[:space:]]*>' "$f" || miss="$miss description"
  grep -qiE '^tools:' "$f" || miss="$miss tools"
  grep -qiE 'mission' "$f" || miss="$miss MISSION"
  # Hunter-section requirements apply only to actual hunters (*-hunter.md or bb-researcher.md).
  # Infra/support agents (log-eater, workspace-architect, workspace-builder, etc.) are exempt.
  base="$(basename "$f")"
  if [[ "$base" == *-hunter.md ]] || [[ "$base" == "bb-researcher.md" ]]; then
    grep -qiE 'scope' "$f" || miss="$miss SCOPE"
    grep -qiE 'playbook|technique|procedure' "$f" || miss="$miss PLAYBOOK"
    grep -qiE 'capability gate|capability|terminal gate' "$f" || miss="$miss GATES"
    grep -qiE 'escalat|chain' "$f" || miss="$miss ESCALATE"
    grep -qiE 'DEAD|LEAD|CANDIDATE' "$f" || miss="$miss OUTPUT-CONTRACT"
  fi
  lines=$(wc -l < "$f")
  if [ -z "$miss" ]; then
    pass=$((pass+1)); printf "PASS  %-26s %s lines\n" "$(basename "$f" .md)" "$lines"
  else
    warn=$((warn+1)); printf "WARN  %-26s %s lines  missing:%s\n" "$(basename "$f" .md)" "$lines" "$miss"
  fi
done

echo ""
echo "agents: $total   PASS: $pass   WARN: $warn"
[ "$warn" -eq 0 ]

# --- critical-agent assertion (added 2026-06-19) ---
crit=0
[ -f "$DIR/bb-researcher.md" ] || { echo "CRITICAL: bb-researcher.md MISSING from $DIR (workflows dispatch it)"; crit=1; }
[ "$warn" -eq 0 ] && [ "$crit" -eq 0 ]
