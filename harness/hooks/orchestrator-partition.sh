#!/usr/bin/env bash
# orchestrator-partition.sh - PreToolUse hook (Bash | WebFetch | WebSearch | mcp send_http).
#
# GOAL: hard-block the ORCHESTRATOR (main loop) from doing BULK hands-on network probing / recon.
# That work goes to a worker sub-agent whose isolated context absorbs the raw bytes - the fix for
# the main-loop byte-burn (a 138KB certspotter WebFetch, repeated brg.sec fetches) that rots
# context and causes the early quit. The orchestrator COMPREHENDS, DISPATCHES, and reads DIGESTS.
#
# WHY THE OLD VERSION FAILED (2026-06-24): it tagged main-vs-worker by session_id against a stamp
# written on SessionStart. SessionStart churns on every /clear + compact (dozens overwrote the
# stamp), so the live orchestrator stopped matching MAIN_SID, was tagged WORKER, and FAIL-OPENED
# into free probing. FIX: the stamp is now written on UserPromptSubmit (orchestrator-stamp.sh) -
# only the orchestrator gets human prompts - and the discriminator keys on TRANSCRIPT_PATH (each
# sub-agent has its own agent-*.jsonl), with session_id as a fallback.
#
# POLICY (role=MAIN only; WORKER / NOSTAMP / parse-gap always fail-open):
#   - WebFetch / WebSearch  -> HARD BLOCK. The orchestrator has no thin-exception need for these;
#     they are exploratory recon and always byte-heavy. Delegate to recon-scout / a class hunter.
#     Deliberate override: `touch .claude/state/orchestrator-fetch-allow` (good 15 min).
#   - Bash network probe (curl/cast/nuclei/...) -> small per-session BUDGET (the thin exception:
#     one cheap one-shot confirm + the final copy-paste PoC re-run). Over budget -> block, delegate.
#   - Non-probe Bash (ls/cat/grep/jq/git/sed/awk over local files) -> ALWAYS allowed (reading state).
set -u
INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0
CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac

SID=$(echo "$INPUT"  | jq -r '.session_id // empty' 2>/dev/null)
TP=$(echo "$INPUT"   | jq -r '.transcript_path // empty' 2>/dev/null)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
CMD=$(echo "$INPUT"  | jq -r '.tool_input.command // .tool_input.url // .tool_input.query // empty' 2>/dev/null | tr '\n' ' ' | head -c 120)

STATE_DIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state"
# Read THIS session's own stamp (multi-agent safe): each parallel main loop stamps a file keyed by
# its sid, so N orchestrators no longer clobber one global stamp. Fall back to the legacy global.
SAFE_SID=$(echo "$SID" | tr -c 'A-Za-z0-9' '_')
STAMP_FILE="$STATE_DIR/orchestrator-session.$SAFE_SID"
[ -f "$STAMP_FILE" ] || STAMP_FILE="$STATE_DIR/orchestrator-session"
MAIN_SID=$(grep -oE '^session_id=.*'      "$STAMP_FILE" 2>/dev/null | head -1 | cut -d= -f2-)
MAIN_TP=$(grep -oE  '^transcript_path=.*' "$STAMP_FILE" 2>/dev/null | head -1 | cut -d= -f2-)

# Role: MAIN only if the incoming transcript matches the stamped orchestrator transcript (strong),
# else fall back to session_id match when no TP was stamped. A worker has its own transcript_path,
# so it never matches -> WORKER -> fail-open. Missing stamp -> NOSTAMP -> fail-open.
ROLE="WORKER"
# POSITIVE WORKER DISCRIMINATOR (fix 2026-10-02, GreyNOC session): a sub-agent's hook payload
# carries agent_id / agent_type keys; the orchestrator's payload does NOT. Sub-agents inherit the
# parent's session_id AND transcript_path, so the stamp comparison below matched for workers too
# and tagged 100% of traffic as MAIN (981/981 debug rows, zero WORKER). Effect: every worker in the
# fleet was hard-blocked from WebFetch/WebSearch and capped at 3 bash probes, which is a direct
# cause of thin probe counts and early quits. Check the agent keys FIRST so workers fail-open.
AGENT_ID=$(echo "$INPUT" | jq -r '.agent_id // empty' 2>/dev/null)
AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // empty' 2>/dev/null)
if [ -n "$AGENT_ID" ] || [ -n "$AGENT_TYPE" ]; then
  ROLE="WORKER"
elif [ -z "$MAIN_SID" ] && [ -z "$MAIN_TP" ]; then
  ROLE="NOSTAMP"
elif [ -n "$MAIN_TP" ] && [ "$TP" = "$MAIN_TP" ]; then
  ROLE="MAIN"
elif [ -z "$MAIN_TP" ] && [ -n "$SID" ] && [ "$SID" = "$MAIN_SID" ]; then
  ROLE="MAIN"
fi

# Classify the probe. WebFetch / WebSearch / send_http are recon by nature. For Bash, only a
# command SEGMENT that actually invokes a probe binary counts (start of command or right after
# a pipe / ; / && / ||) - so `grep curl file` or `sed over a script` stay off the budget.
KIND=none
case "$TOOL" in
  WebFetch|WebSearch) KIND=fetch ;;
  *) echo "$TOOL" | grep -q "send_http" && KIND=fetch ;;
esac
if [ "$KIND" = none ] && echo "$CMD" | grep -qiE '(^|[;&|])[[:space:]]*(curl|curl_cffi|wget|nuclei|ffuf|wfuzz|httpx|katana|gau|sqlmap|ghauri|gobuster|feroxbuster|masscan|nmap|amass|subfinder|dalfox|nikto|wpscan|httprobe|websocat|wscat|cast)([[:space:]]|$)'; then
  KIND=bashprobe
fi

# Bounded debug trace (the prior version grew to 17MB - this self-caps to the last ~1500 lines).
DBG="$STATE_DIR/orchestrator-partition.debug.log"
if [ "${BB_PARTITION_DEBUG:-1}" = "1" ]; then
  KEYS=$(echo "$INPUT" | jq -r 'keys|join(",")' 2>/dev/null)
  PTU=$(echo "$INPUT" | jq -r '.parent_tool_use_id // "-"' 2>/dev/null)
  printf '%s\tPRETOOL\trole=%s\tkind=%s\ttool=%s\tsid=%s\tptu=%s\tkeys=%s\tcmd=%s\n' \
    "$(date +%H:%M:%S)" "$ROLE" "$KIND" "$TOOL" "$SID" "$PTU" "$KEYS" "$CMD" >> "$DBG" 2>/dev/null
  lines=$(wc -l < "$DBG" 2>/dev/null || echo 0)
  case "$lines" in ''|*[!0-9]*) lines=0 ;; esac
  if [ "$lines" -gt 1800 ]; then tail -1500 "$DBG" > "$DBG.tmp" 2>/dev/null && mv "$DBG.tmp" "$DBG" 2>/dev/null; fi
fi

# Only the orchestrator is partitioned.
[ "$ROLE" = "MAIN" ] || exit 0

# Deliberate override (mirrors report-access-allow): touch the file to permit fetches for 15 min.
ALLOW="$STATE_DIR/orchestrator-fetch-allow"
if [ -f "$ALLOW" ]; then
  age=$(( $(date +%s) - $(stat -c %Y "$ALLOW" 2>/dev/null || echo 0) ))
  [ "$age" -lt 900 ] && exit 0
fi

if [ "$KIND" = "fetch" ]; then
  echo "orchestrator-partition: the MAIN loop must NOT WebFetch/WebSearch/send_http - that is exploratory recon and byte-heavy. DELEGATE it to a worker sub-agent (recon-scout for discovery, a class hunter to probe); its isolated context absorbs the raw bytes and you read its one-screen digest. This is the fix for the main-loop context-burn that rots quality and causes the early quit (SPINE section 7 ORCHESTRATOR DISCIPLINE). If you truly need one fetch yourself: touch .claude/state/orchestrator-fetch-allow (good 15 min)." >&2
  exit 2
fi

if [ "$KIND" = "bashprobe" ]; then
  BUDGET_FILE="$STATE_DIR/.main-probe-budget.$SAFE_SID"
  used=$(cat "$BUDGET_FILE" 2>/dev/null || echo 0)
  case "$used" in ''|*[!0-9]*) used=0 ;; esac
  MAX_MAIN_PROBES=3   # ponytail: thin-exception budget (one-shot confirm + final PoC). Raise here if a legit confirm flow needs more.
  if [ "$used" -ge "$MAX_MAIN_PROBES" ]; then
    echo "orchestrator-partition: the MAIN loop has spent its $MAX_MAIN_PROBES one-shot-confirm budget this session. Further hands-on probing is the context-burn that rots quality - DELEGATE this to a worker sub-agent (it absorbs the bytes; you read the digest). The thin exception is one cheap confirm + the final copy-paste PoC, not a recon sweep (SPINE section 7)." >&2
    exit 2
  fi
  echo $((used + 1)) > "$BUDGET_FILE" 2>/dev/null || true
fi
exit 0
