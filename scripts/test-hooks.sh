#!/usr/bin/env bash
# test-hooks.sh - LIVE behavioral test harness for the workspace hooks.
# Complements verify-fleet.sh (syntax/routing) with real payloads piped into each hook:
# fail-open, counter-abort resistance, loop-safety (stop_hook_active), and the specific
# 2026-07-19 fixes. Read-only against the repo (uses throwaway sessions + temp counters).
# Run: bash scripts/test-hooks.sh
set -u
ROOT=${GNOC_WORKSPACE:-$HOME/.gnoc}
cd "$ROOT" || exit 1
HK="$ROOT/.claude/hooks"
pass=0; fail=0
ok(){ printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad(){ printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
ae(){ [ "$1" = "$2" ] && ok "$3 (exit $1)" || bad "$3 (exit $1 want $2)"; }
j(){ jq -nc "$@"; }   # tiny jq helper
# capture any REAL timebox pin up front so we can assert the harness leaves it untouched (a live
# test of timebox-set writes state/hunt-loop/until; the harness must never pin/unpin a real window).
UNTIL_PRE=$(cat "$ROOT/.claude/state/hunt-loop/until" 2>/dev/null || echo __none__)

echo "== 1. syntax (all hooks + hunt-loop scripts) =="
sn=0
for f in "$HK"/*.sh scripts/hunt-loop/lock-lib.sh scripts/hunt-loop/lock.sh scripts/loop-select-target.sh; do
  bash -n "$f" 2>/tmp/th.syn || { bad "syntax $f"; sed 's/^/      /' /tmp/th.syn; sn=1; }
done
[ "$sn" = 0 ] && ok "all files parse"

echo "== 2. fail-open: every blocking hook exits 0 on empty AND garbage stdin =="
for h in scope-gate dedup-gate submit-guard orchestrator-partition dollar-trap-guard \
         write-location-guard draft-write-gate report-access-gate runtime-complete-gate \
         refusal-monitor never-surrender timebox-gate subagent-floor-gate concurrency-gate; do
  rc=$(printf ''            | bash "$HK/$h.sh" >/dev/null 2>&1; echo $?); ae "$rc" 0 "$h empty-stdin"
  rc=$(printf 'not json{{{' | bash "$HK/$h.sh" >/dev/null 2>&1; echo $?); ae "$rc" 0 "$h garbage-stdin"
done

echo "== 3. counter-abort resistance (the 2026-07-19 sanitize) =="
# 3a. no hook still uses the abort-prone X=\$((X+0)) idiom on a file-read counter
if grep -rEn '(CUR|C0|CURRENT)=\$\(\( *(CUR|C0|CURRENT) *\+ *0 *\)\)' "$HK"/*.sh >/tmp/th.ab 2>/dev/null; then
  bad "abort-prone \$((X+0)) still present:"; sed 's/^/      /' /tmp/th.ab
else ok "no abort-prone \$((X+0)) counter reads remain"; fi
# 3b. end-to-end: a CORRUPT (alpha) counter must not abort draft-write-gate
mkdir -p "$ROOT/.claude/state/learning" 2>/dev/null
printf 'GARBAGE_NONNUM' > "$ROOT/.claude/state/learning/draftgate-aborttest.count"
DP=$(j --arg c '# Summary
x
## PoC
y
## Impact
z' '{cwd:"'"$ROOT"'",session_id:"aborttest",tool_input:{file_path:"'"$ROOT"'/reports/drafts/x/t.md",content:$c}}')
err=$(printf '%s' "$DP" | bash "$HK/draft-write-gate.sh" 2>&1 >/dev/null); rc=$?
echo "$err" | grep -qiE 'unbound variable|arithmetic|syntax error' \
  && bad "draft-write-gate aborted on corrupt counter: $(echo "$err"|head -1)" \
  || ok "draft-write-gate survives corrupt counter (exit $rc)"
rm -f "$ROOT/.claude/state/learning/draftgate-aborttest.count"

echo "== 4. loop-safety: stop hooks honor stop_hook_active (no infinite block) =="
for h in runtime-complete-gate refusal-monitor never-surrender timebox-gate subagent-floor-gate; do
  rc=$(j '{cwd:"'"$ROOT"'",session_id:"loopt",stop_hook_active:true}' | bash "$HK/$h.sh" >/dev/null 2>&1; echo $?)
  ae "$rc" 0 "$h stop_hook_active=true -> allow-stop"
done

echo "== 5. dedup-gate join-null (Agent with null prompt+description -> clean exit 0, no output) =="
out=$(j '{cwd:"'"$ROOT"'",tool_name:"Agent",tool_input:{}}' | bash "$HK/dedup-gate.sh" 2>/dev/null); rc=$?
{ [ "$rc" = 0 ] && [ -z "$out" ]; } && ok "dedup-gate null-fields exit 0, silent" || bad "dedup-gate null-fields rc=$rc out='$out'"

echo "== 6. scope-gate scheme-less bare host (fix) =="
SCOPE_SAMPLE=$(for f in targets/*/SCOPE.txt; do
  host=$(sed -n '1,30p' "$f" 2>/dev/null | grep -oiE '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}' | grep -viE 'example\.com|github\.com|immunefi\.com|\.md$' | head -1)
  [ -n "$host" ] && { printf '%s\t%s\n' "$(basename "$(dirname "$f")")" "$host"; break; }
done)
SCOPE_PROG=${SCOPE_SAMPLE%%$'\t'*}; INSCOPE=${SCOPE_SAMPLE#*$'\t'}
if [ -n "$INSCOPE" ] && [ "$INSCOPE" != "$SCOPE_SAMPLE" ]; then
  rc=$(HUNT_TARGET="$SCOPE_PROG" j '{cwd:"'"$ROOT"'",tool_name:"Bash",tool_input:{command:"curl '"$INSCOPE"'/x"}}' | HUNT_TARGET="$SCOPE_PROG" bash "$HK/scope-gate.sh" >/dev/null 2>&1; echo $?); ae "$rc" 0 "run-bound in-scope BARE host passes ($SCOPE_PROG/$INSCOPE)"
else ok "(no in-scope host sample; skipped positive)"; fi
rc=$(HUNT_TARGET= j '{cwd:"'"$ROOT"'",session_id:"no-such-session",tool_name:"Bash",tool_input:{command:"curl '"${INSCOPE:-totally-oos-xyz123.com}"'/x"}}' | HUNT_TARGET= bash "$HK/scope-gate.sh" >/dev/null 2>&1; echo $?); ae "$rc" 2 "root-run host without target binding blocks"
rc=$(j '{cwd:"'"$ROOT"'",tool_name:"Bash",tool_input:{command:"curl totally-oos-xyz123.com/x"}}' | bash "$HK/scope-gate.sh" >/dev/null 2>&1; echo $?); ae "$rc" 2 "OOS BARE host blocks"
rc=$(j '{cwd:"'"$ROOT"'",tool_name:"Bash",tool_input:{command:"python3 poc.py"}}' | bash "$HK/scope-gate.sh" >/dev/null 2>&1; echo $?); ae "$rc" 0 "non-network (no host) fail-open"

echo "== 7. submit-guard (fix: body-embedded platform URL not blocked; real submit blocked) =="
# STATE-SAFE (2026-11-04): a human's fresh approval sentinel would correctly ALLOW the first probe,
# and the one-shot hook would then consume it. Move it aside for these two probes, restore exactly.
SENT="$ROOT/.claude/state/GREYNOC-APPROVED-SUBMIT"; SENT_BAK=""
[ -f "$SENT" ] && { SENT_BAK="$SENT.test-hooks.$$"; mv "$SENT" "$SENT_BAK"; }
rc=$(j '{tool_input:{command:"curl -X POST https://hackerone.com/reports/1 -d @r"}}' | bash "$HK/submit-guard.sh" >/dev/null 2>&1; echo $?); ae "$rc" 2 "real submit blocked"
rc=$(j '{tool_input:{command:"curl -X POST https://app.example-inscope.com/cb -d '"'"'u=https://hackerone.com/reports/1'"'"'"}}' | bash "$HK/submit-guard.sh" >/dev/null 2>&1; echo $?); ae "$rc" 0 "platform URL in -d body NOT blocked"
[ -n "$SENT_BAK" ] && mv "$SENT_BAK" "$SENT"

echo "== 8. hunt-trigger (fix: short handle needs hunt context) =="
out=$(j '{cwd:"'"$ROOT"'",prompt:"give me a ring when done"}' | bash "$HK/hunt-trigger.sh" 2>/dev/null)
echo "$out" | grep -q 'HUNT-LOOP TRIGGER' && bad "short word 'ring' falsely triggered loop" || ok "benign 'ring' does NOT trigger loop"

echo "== 9. learning-inject (fix: meta prompt under any state -> no 6KB inject) =="
out=$(j '{cwd:"'"$ROOT"'",session_id:"m",prompt:"git status"}' | bash "$HK/learning-inject.sh" 2>/dev/null)
[ -z "$out" ] && ok "meta prompt -> no injection" || bad "meta prompt still injected LESSONS"

echo "== 10. per-session LOCK resolver (fix) =="
. scripts/hunt-loop/lock-lib.sh
hl_lock_set kayak _thtA; hl_lock_set sony _thtB
[ "$(hl_lock_target _thtA)" = kayak ] && ok "session A -> kayak" || bad "session A wrong"
[ "$(hl_lock_target _thtB)" = sony ]  && ok "session B -> sony"  || bad "session B wrong"
[ "$(HUNT_TARGET=zzz hl_lock_target _thtA)" = zzz ] && ok "HUNT_TARGET wins" || bad "HUNT_TARGET precedence broken"
rm -f "$ROOT/.claude/state/hunt-loop/LOCK._thtA" "$ROOT/.claude/state/hunt-loop/LOCK._thtB"

echo "== 11. timebox-set duration clamp (fix: >24h capped) [state-safe: backup+restore until] =="
UF="$ROOT/.claude/state/hunt-loop/until"
if [ -f "$UF" ]; then cp "$UF" /tmp/th.until.bak; else rm -f /tmp/th.until.bak; fi
out=$(j '{cwd:"'"$ROOT"'",prompt:"hunt for 100000 hours"}' | bash "$HK/timebox-set.sh" 2>/dev/null)
echo "$out" | grep -q 'capped to 24h' && ok "runaway duration clamped to 24h" || bad "duration NOT clamped: $(echo "$out"|head -1)"
if [ -f /tmp/th.until.bak ]; then cp /tmp/th.until.bak "$UF"; rm -f /tmp/th.until.bak; else rm -f "$UF"; fi

echo "== 12. draft-write-gate selfcheck (Denial 0 + Denial 3) =="
if bash "$HK/draft-write-gate.selfcheck.sh" >/tmp/th.sc 2>&1; then
  ok "selfcheck all green ($(grep -oE '[0-9]+ passed' /tmp/th.sc | head -1))"
else bad "selfcheck failed:"; sed 's/^/      /' /tmp/th.sc; fi

echo "== 13. state hygiene: harness left no timebox pin / per-session lock behind =="
UNTIL_POST=$(cat "$ROOT/.claude/state/hunt-loop/until" 2>/dev/null || echo __none__)
[ "$UNTIL_PRE" = "$UNTIL_POST" ] && ok "timebox 'until' unchanged by the harness" || bad "harness MUTATED timebox state ($UNTIL_PRE -> $UNTIL_POST)"
ls "$ROOT"/.claude/state/hunt-loop/LOCK._tht* >/dev/null 2>&1 && bad "leaked per-session lock file" || ok "no per-session lock leaked"

echo "---------------------------------------------"
echo "HOOK-TESTS: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
