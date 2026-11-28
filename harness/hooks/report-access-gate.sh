#!/usr/bin/env bash
# report-access-gate.sh  (PreToolUse: Read|Grep|Glob|Bash)
#
# Structural enforcement of "agents do not LOOK at the reports" (GreyNOC, 2026-06-20):
# the soft .md rule (DRAFTED IS DONE + the leak-free gate) was ignored, so it becomes a hook.
# Blocks every agent AND the main loop from READING reports/drafts|submitted.
#
# Carve-out: the report-consumers (dedup-scout prior-art sweep, reviewer, report-killer,
# report-writer, report-repro-checker, cvss-scorer) self-touch the allow-token as their first
# step, which opens a TTL window. The last two joined the ship flow later; see CLAUDE.md.
# The hook can NOT see which sub-agent is calling (no agent-type field at PreToolUse), so a
# self-touched token beats trying to identify the agent.
#
# ponytail: presence+TTL token (global window: a concurrent hunter could ride an open window).
#   Path-scope the token (match the read against the token's contents) if that race ever bites.
#   reports/eval-set stays readable (regression data, not a vendor report).
#   A Bash write redirect into reports/ (echo > reports/drafts/x) would also trip this; convention
#   is the Write tool, not shell, so not handled. Add a redirect carve-out if it bites.
# Mirrors scope-gate.sh: set -u only, FAIL-OPEN (exit 0) on any internal failure; exit 2 blocks.
set -u

WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
TOKEN="$WS/.claude/state/report-access-allow"
TTL_MIN=15

PAYLOAD=$(cat 2>/dev/null) || exit 0
[ -z "$PAYLOAD" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

TOOL=$(printf '%s' "$PAYLOAD" | jq -r '.tool_name // empty' 2>/dev/null) || exit 0
case "$TOOL" in Read|Grep|Glob|Bash) ;; *) exit 0 ;; esac

# Read/Grep/Glob: any path field naming the protected tree is a content-read attempt -> gate.
# Bash: only a CONTENT reader (cat/grep/head/...) of the tree leaks prose; a command that
# merely NAMES the path (ls, echo, git log, find, rm, stat) does not -> do NOT block those.
PATHS=$(printf '%s' "$PAYLOAD" | jq -r '
  [ .tool_input.file_path, .tool_input.path, .tool_input.pattern ]
  | map(select(. != null)) | join("\n")' 2>/dev/null) || exit 0
CMD=$(printf '%s' "$PAYLOAD" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0

HIT=""
printf '%s' "$PATHS" | grep -Eq 'reports/(drafts|submitted)' && HIT=1
printf '%s' "$CMD" | grep -Eq '(cat|less|more|head|tail|tac|nl|grep|rg|egrep|fgrep|awk|sed|strings|xxd|od|bat|view|cut|paste|column)([[:space:]]|$)[^|;&`]*reports/(drafts|submitted)' && HIT=1
[ -z "$HIT" ] && exit 0   # not a read of the protected tree

# Fresh allow-token -> a report-consumer opened the carve-out -> allow.
[ -n "$(find "$TOKEN" -mmin -"$TTL_MIN" 2>/dev/null)" ] && exit 0

printf 'BLOCKED reading reports/drafts|submitted: gated (DRAFTED IS DONE + leak-free gate).\n' >&2
printf 'Only dedup-scout, reviewer, report-killer, report-writer, report-repro-checker and cvss-scorer may read reports/.\n' >&2
printf 'Those agents open the carve-out (good for %s min) with:  touch %s\n' "$TTL_MIN" "$TOKEN" >&2
printf 'Hunter / modeler / orchestrator: do NOT read drafts. Pivot to fresh ground.\n' >&2
exit 2
