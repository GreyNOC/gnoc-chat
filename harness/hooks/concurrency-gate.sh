#!/usr/bin/env bash
# concurrency-gate.sh - PreToolUse(Agent) hook. ADVISORY ONLY (FIX 6a + 6b 2026-07-19).
#
# NEVER blocks a dispatch. The harness does not expose a live count of in-flight sub-agents to a
# PreToolUse hook, and fleet processes are separate sessions, so a HARD concurrency block would
# false-fire on state it cannot read AND would contradict SPINE 7 PARALLELISM ("dispatching is NOT
# a stop ... never poll-wait"). So this hook only EMITS an advisory via additionalContext + exit 0:
#   6a CONCURRENCY: a per-session rolling dispatch tally; when the rate exceeds the cap it nudges
#      "winners are cheap, prefer pivoting the SEED over spraying agents" (SPINE 7 cap 3-5).
#   6b MODEL DEFAULT: if the Agent dispatch carries no model AND the task looks trivial/routine,
#      it nudges the right model (haiku/sonnet vs opus). A PreToolUse hook cannot MUTATE tool_input
#      to inject a model in this harness; the real enforcement is the CLAUDE.md default table.
#
# Conventions obeyed (FIX-SPEC): advisory = jq additionalContext + exit 0; FAIL-OPEN on every
# uncertain path (no jq, empty payload, parse error, cwd outside the workspace, wrong tool) -> exit 0.
# All paths absolute. --selftest path included.
set -u

# --selftest: prove advisory-only (never a non-zero/deny), fires on unset-model + high-rate.
if [ "${1:-}" = "--selftest" ]; then
  H="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/hooks/concurrency-gate.sh"
  pass=0; fail=0
  chk(){ if [ "$1" = "$2" ]; then echo "ok:   $3"; pass=$((pass+1)); else echo "FAIL: $3 (got $1 want $2)"; fail=$((fail+1)); fi; }
  # 1. unset-model provision dispatch -> exit 0 + emits a model advisory
  O=$(printf '%s' '{"tool_name":"Agent","cwd":"${GNOC_WORKSPACE:-$HOME/.gnoc}","session_id":"selftest-a","tool_input":{"description":"Provision Codacy account A","prompt":"provision_pair signup"}}' | bash "$H"); RC=$?
  chk "$RC" 0 "unset-model provision dispatch exits 0 (advisory, never blocks)"
  printf '%s' "$O" | grep -q 'MODEL UNSET' && echo "ok:   model advisory emitted" || { echo "FAIL: no model advisory"; fail=$((fail+1)); }
  # 2. non-Agent tool -> fail-open exit 0, no output
  O=$(printf '%s' '{"tool_name":"Bash","cwd":"${GNOC_WORKSPACE:-$HOME/.gnoc}","tool_input":{"command":"ls"}}' | bash "$H"); RC=$?
  chk "$RC" 0 "non-Agent tool fails open (exit 0)"
  [ -z "$O" ] && echo "ok:   non-Agent emits nothing" || { echo "FAIL: non-Agent emitted output"; fail=$((fail+1)); }
  # 3. cwd outside workspace -> fail-open
  O=$(printf '%s' '{"tool_name":"Agent","cwd":"/tmp","tool_input":{"description":"x","prompt":"y"}}' | bash "$H"); RC=$?
  chk "$RC" 0 "cwd outside workspace fails open (exit 0)"
  # 4. empty payload -> fail-open
  echo "" | bash "$H" >/dev/null 2>&1; chk "$?" 0 "empty payload fails open (exit 0)"
  # 5. model=opus set -> no model advisory (still exit 0)
  O=$(printf '%s' '{"tool_name":"Agent","cwd":"${GNOC_WORKSPACE:-$HOME/.gnoc}","session_id":"selftest-b","tool_input":{"description":"reason about the exploit chain","prompt":"hypothesis","model":"opus"}}' | bash "$H"); RC=$?
  chk "$RC" 0 "model-set dispatch exits 0"
  printf '%s' "$O" | grep -q 'MODEL UNSET' && { echo "FAIL: model advisory fired with model set"; fail=$((fail+1)); } || echo "ok:   no model advisory when model set"
  echo "---- $pass ok checks, $fail failed ----"
  [ "$fail" -eq 0 ]
  exit $?
fi

INPUT=$(cat 2>/dev/null || true)
[ -z "$INPUT" ] && exit 0
command -v jq >/dev/null 2>&1 || exit 0

CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || echo "")
case "$CWD" in ${GNOC_WORKSPACE:-$HOME/.gnoc}*) ;; *) exit 0 ;; esac
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || echo "")
[ "$TOOL" = "Agent" ] || exit 0   # only advise on sub-agent dispatch; every other tool fails open

SESS=$(printf '%s' "$INPUT" | jq -r '.session_id // "nosession"' 2>/dev/null || echo "nosession")
PROMPT=$(printf '%s' "$INPUT" | jq -r '(.tool_input.prompt // "") + " " + (.tool_input.description // "")' 2>/dev/null | head -c 4000)
MODEL=$(printf '%s' "$INPUT" | jq -r '.tool_input.model // empty' 2>/dev/null || echo "")

NOTES=""

# --- 6a CONCURRENCY tally (advisory) ---
# Append a unix ts to a per-session rolling file; count dispatches in the last 3 min + the cycle.
SDIR="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/hunt-loop"
mkdir -p "$SDIR" 2>/dev/null
CF="$SDIR/dispatch-${SESS}.count"
NOWS=$(date +%s 2>/dev/null || echo 0)
[ "$NOWS" -gt 0 ] 2>/dev/null && echo "$NOWS" >> "$CF" 2>/dev/null
RECENT=0; CYCLE=0
if [ -f "$CF" ] && [ "$NOWS" -gt 0 ] 2>/dev/null; then
  CUT=$((NOWS - 180))
  RECENT=$(awk -v c="$CUT" '$1+0>=c{n++} END{print n+0}' "$CF" 2>/dev/null || echo 0)
  CYCLE=$(wc -l < "$CF" 2>/dev/null | tr -d ' ' || echo 0)
fi
RECENT=$((RECENT + 0)); CYCLE=$((CYCLE + 0))
if [ "$RECENT" -gt 5 ] || [ "$CYCLE" -gt 40 ]; then
  NOTES="${NOTES}CONCURRENCY ADVISORY: ${RECENT} dispatches in the last 3 min (cycle total ${CYCLE}); the SPINE 7 cap is 3-5 concurrent. MAPTA: winners are CHEAP (~40 tool calls; success correlates NEGATIVELY with resource burn). Are these NON-overlapping vectors, or are you spraying a dead seam? Prefer pivoting the SEED (a different mined endpoint / actor / host) over adding agents. "
fi

# --- 6b MODEL DEFAULT (advisory) ---
# Only nudge when the dispatch carries NO model AND the task-type is detectable.
if [ -z "$MODEL" ]; then
  TASK=""
  printf '%s' "$PROMPT" | grep -qiE 'provision|browser_register|dedup|recon|scope|enumerat|sitemap|crawl' && TASK="trivial/routine (haiku for provision/dedup/recon/scope; sonnet routine)"
  printf '%s' "$PROMPT" | grep -qiE 'reason|review|crown|hypothes|exploit.?chain|report-killer|cvss|target-model|adversar' && TASK="reasoning/review/crown -> opus"
  if [ -n "$TASK" ]; then
    NOTES="${NOTES}MODEL UNSET on a ${TASK} task. Set model on EVERY dispatch (SPINE 7 MODEL BY EV): Opus for reasoning/crown/review, Sonnet routine, Haiku trivial. 22% of our dispatches ran model-unset = uncontrolled cost. "
  fi
fi


# --- DEDUP-BEFORE-DISPATCH (advisory, added 2026-10-05) ---
# Root cause of 3 measured repeats: a host named in a worker brief already had prior coverage
# in the hunt index, and nobody ran `hq host` first. One lane burned ~7h re-deriving a LEAD
# that was found and parked on 2026-07-21. This surfaces that at dispatch time instead.
HQDB="${GNOC_WORKSPACE:-$HOME/.gnoc}/.hunt-index/hunts.db"
if [ -s "$HQDB" ] && command -v sqlite3 >/dev/null 2>&1; then
  HOSTS=$(printf '%s' "$PROMPT" \
    | grep -oE '\b[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,}\b' \
    | grep -vE '\.(md|sh|py|js|txt|json|log|yml|yaml|png|jpg)$' \
    | sort -u | head -8)
  HITS=""
  # ONE exclusion list, used by BOTH the count and the namer below. They used to disagree: the count
  # excluded only patterns/ and salvage/, so it counted our OWN exhaust - opencode lane transcripts,
  # orch logs, scope snapshots, the jsonl ledgers - while the namer already filtered those out. Measured
  # 2026-10-27 on program-0: the advisory said "app.example.com (149 prior)" and every single row
  # was one of our own lane logs plus a scope snapshot. Zero hunt verdicts. A false "already covered" is
  # expensive in the wrong direction - RULE 3 records a stale dead suppressing a re-hunt that later paid
  # 2 massive criticals - so the count must only count rows that could actually change a brief.
  # A chat transcript is not a finding about the target (same hazard as Manual T-271).
  # NOTE: .claude/state/do-not-rehunt/ is deliberately NOT excluded - that one IS a real hunt verdict.
  EXCL="AND d.path NOT LIKE '%/patterns/%'
        AND d.path NOT LIKE '%/salvage/%'
        AND d.path NOT LIKE '%/.claude/state/opencode/%'
        AND d.path NOT LIKE '%/.claude/state/orch/%'
        AND d.path NOT LIKE '%/.claude/state/scope-snapshots/%'
        AND d.path NOT LIKE '%.jsonl'"
  for H in $HOSTS; do
    N=$(timeout 3 sqlite3 "$HQDB" \
      "SELECT count(*) FROM hosts h JOIN docs d ON d.id=h.doc_id
       WHERE h.host='$(printf '%s' "$H" | sed "s/'/''/g")'
         $EXCL;" 2>/dev/null)
    case "$N" in ''|0) : ;; *) HITS="${HITS}${H} (${N} prior) " ;; esac
    # Name the prior work, do not just count it. A bare count forced a second round-trip AFTER the brief was
    # already written and sent (measured 2026-10-22: an agent was dispatched to provision accounts that three
    # earlier lanes had already made). Reports, ACCOUNTS.md and RESUME/SESSION notes are the rows that actually
    # change a brief, so surface those paths inline, newest first.
    case "$N" in ''|0) : ;; *)
      WHERE=$(timeout 3 sqlite3 "$HQDB" \
        "SELECT DISTINCT d.path FROM hosts h JOIN docs d ON d.id=h.doc_id
         WHERE h.host='$(printf '%s' "$H" | sed "s/'/''/g")'
           $EXCL
           AND (d.path LIKE '%/reports/%' OR d.path LIKE '%ACCOUNTS.md'
                OR d.path LIKE '%RESUME%' OR d.path LIKE '%SESSION%' OR d.path LIKE '%DEDUP%')
         ORDER BY d.mtime DESC LIMIT 5;" 2>/dev/null \
        | sed "s#^${GNOC_WORKSPACE:-$HOME/.gnoc}/##" \
        | tr '\n' ' ')
      case "$WHERE" in "") : ;; *) HITS="${HITS}-> read first: ${WHERE}" ;; esac
    ;; esac
  done
  if [ -n "$HITS" ]; then
    NOTES="${NOTES}DEDUP ADVISORY - these hosts in the brief ALREADY have coverage in the hunt index: ${HITS}. Read the files named above (and 'scripts/hq host <h>' for the rest) BEFORE this agent probes, then tell it in the brief what is already dead so it hunts the NEW ground instead of re-deriving a parked LEAD. This exact miss has cost 3 duplicate derivations, one of them a 7-hour lane. "
  fi
fi

[ -z "$NOTES" ] && exit 0   # nothing to advise: silent pass
jq -nc --arg c "$NOTES" '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$c}}' 2>/dev/null
exit 0
