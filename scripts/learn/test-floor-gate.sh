#!/usr/bin/env bash
# test-floor-gate.sh - 5-case synthetic harness for subagent-floor-gate.sh
# Each case builds a minimal transcript JSONL, pipes the hook input, and asserts
# on the presence or absence of {"decision":"block"} in stdout.
set -u

HOOK="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/hooks/subagent-floor-gate.sh"
TMPDIR_BASE=$(mktemp -d /tmp/floor-gate-test-XXXXXX)
CWD="${GNOC_WORKSPACE:-$HOME/.gnoc}"
PASS=0
FAIL=0
SID="test-session-$(date +%s)"

cleanup() { rm -rf "$TMPDIR_BASE"; }
trap cleanup EXIT

# Helper: build a transcript JSONL file.
# Arguments: path, array of tool names (space-separated) for probe lines, last-text
make_transcript() {
  local path="$1"
  local tools="$2"   # space-separated tool names (empty = no probes)
  local last_text="$3"
  local first_user_msg="${4:-hunt this target}"
  > "$path"
  # User turn (task message)
  printf '%s\n' "$(jq -nc --arg m "$first_user_msg" '{type:"user",message:{content:[{type:"text",text:$m}]}}')" >> "$path"
  # Assistant turn with tool_uses for each tool name
  if [ -n "$tools" ]; then
    local content_parts='[]'
    for t in $tools; do
      content_parts=$(printf '%s' "$content_parts" | jq -c --arg n "$t" --arg cmd "curl https://example.com/test" \
        '. + [{type:"tool_use",name:$n,input:{command:$cmd}}]')
    done
    printf '%s\n' "$(jq -nc --argjson c "$content_parts" '{type:"assistant",message:{content:$c}}')" >> "$path"
  fi
  # Final assistant turn with text digest
  printf '%s\n' "$(jq -nc --arg t "$last_text" '{type:"assistant",message:{content:[{type:"text",text:$t}]}}')" >> "$path"
}

# Helper: run the hook and capture stdout
run_hook() {
  local transcript="$1"
  local sid="$2"
  jq -nc --arg cwd "$CWD" --arg tp "$transcript" --arg sid "$sid" \
    '{cwd:$cwd,transcript_path:$tp,session_id:$sid,stop_hook_active:false}' \
  | bash "$HOOK"
}

# Helper: assert outcome
assert() {
  local case_num="$1"
  local desc="$2"
  local output="$3"
  local expect_block="$4"   # "block" or "pass"
  local has_block
  has_block=$(printf '%s' "$output" | grep -c '"decision":"block"' || true)
  if [ "$expect_block" = "block" ] && [ "$has_block" -ge 1 ]; then
    printf 'CASE %s PASS  (%s) -> BLOCKED as expected\n' "$case_num" "$desc"
    PASS=$((PASS+1))
  elif [ "$expect_block" = "pass" ] && [ "$has_block" -eq 0 ]; then
    printf 'CASE %s PASS  (%s) -> PASSED as expected\n' "$case_num" "$desc"
    PASS=$((PASS+1))
  else
    printf 'CASE %s FAIL  (%s) -> expected %s, got output: %s\n' "$case_num" "$desc" "$expect_block" "$output"
    FAIL=$((FAIL+1))
  fi
}

# ---------------------------------------------------------------------------
# CASE 1: probed (curl x3) + last text "ceiling reached, hardened surface, pivoting" + no receipt
#   EXPECT: block
# ---------------------------------------------------------------------------
T1="$TMPDIR_BASE/case1.jsonl"
make_transcript "$T1" "Bash Bash Bash" \
  "I tried a few things but this is ceiling reached, hardened surface, pivoting to another vector." \
  "exploit this IDOR hunter target"
OUT1=$(run_hook "$T1" "${SID}-1")
assert 1 "probed+ceiling/hardened+no-receipt" "$OUT1" "block"

# ---------------------------------------------------------------------------
# CASE 2: recon-scout - tools = subfinder/katana only (no exploit tool), last text map result
#   EXPECT: pass (EXPLOIT_PROBED=false -> exit 0)
# ---------------------------------------------------------------------------
T2="$TMPDIR_BASE/case2.jsonl"
> "$T2"
# user turn with recon-scout framing
printf '%s\n' "$(jq -nc '{type:"user",message:{content:[{type:"text",text:"map the subdomains and enumerate the attack surface, do not probe or exploit"}]}}')" >> "$T2"
# assistant turn with subfinder + katana (recon only, not in EXPLOIT regex)
printf '%s\n' "$(jq -nc '{type:"assistant",message:{content:[
  {type:"tool_use",name:"Bash",input:{command:"subfinder -d example.com -o /tmp/subs.txt"}},
  {type:"tool_use",name:"Bash",input:{command:"katana -u https://example.com -o /tmp/urls.txt"}}
]}}')" >> "$T2"
printf '%s\n' "$(jq -nc '{type:"assistant",message:{content:[{type:"text",text:"mapped 40 subdomains and catalogued 120 endpoints for review."}]}}')" >> "$T2"
OUT2=$(run_hook "$T2" "${SID}-2")
assert 2 "recon-scout-no-exploit-tools" "$OUT2" "pass"

# ---------------------------------------------------------------------------
# CASE 3: WIN - probed + last text confirms report drafted + cross-tenant
#   EXPECT: pass (is_win=true -> exit 0)
# ---------------------------------------------------------------------------
T3="$TMPDIR_BASE/case3.jsonl"
make_transcript "$T3" "Bash Bash Bash Bash Bash Bash Bash Bash Bash" \
  "Report saved to reports/drafts/acme/idor.md. Confirmed cross-tenant read of victim object. Terminal receipt captured. DEAD: fired 9 probes / 6 variants / burst=true / pos+neg control." \
  "hunter exploit idor bola"
OUT3=$(run_hook "$T3" "${SID}-3")
assert 3 "WIN-drafted-report" "$OUT3" "pass"

# ---------------------------------------------------------------------------
# CASE 4: floored LEAD - 9 curl tool_uses + burst loop in transcript + receipt line
#   EXPECT: pass (EMPIRICAL_OK=true, has_receipt=true -> exit 0)
# ---------------------------------------------------------------------------
T4="$TMPDIR_BASE/case4.jsonl"
> "$T4"
printf '%s\n' "$(jq -nc '{type:"user",message:{content:[{type:"text",text:"hunter exploit ssrf"}]}}')" >> "$T4"
# 9 curl tool-uses
CONTENT_PARTS='[]'
for i in $(seq 1 9); do
  CONTENT_PARTS=$(printf '%s' "$CONTENT_PARTS" | jq -c --argjson i "$i" \
    '. + [{type:"tool_use",name:"Bash",input:{command:("curl https://example.com/probe?n="+($i|tostring))}}]')
done
# add burst loop tool-use
CONTENT_PARTS=$(printf '%s' "$CONTENT_PARTS" | jq -c \
  '. + [{type:"tool_use",name:"Bash",input:{command:"for i in $(seq 1 20); do curl -s https://example.com/race & done; wait"}}]')
printf '%s\n' "$(jq -nc --argjson c "$CONTENT_PARTS" '{type:"assistant",message:{content:$c}}')" >> "$T4"
printf '%s\n' "$(jq -nc '{type:"assistant",message:{content:[{type:"text",text:"DEAD: fired 9 probes / 6 variants / burst=true / pos+neg control. Returning LEAD - no new capability confirmed but primitive is visible."}]}}')" >> "$T4"
OUT4=$(run_hook "$T4" "${SID}-4")
assert 4 "floored-LEAD-9probes-burst-receipt" "$OUT4" "pass"

# ---------------------------------------------------------------------------
# CASE 5: unverifiable - last text "this is dead" but transcript has NO assistant tool_use lines
#   while first user message frames it as an exploit hunt -> EXPECT block (PROBE_UNVERIFIABLE)
# ---------------------------------------------------------------------------
T5="$TMPDIR_BASE/case5.jsonl"
> "$T5"
# user turn with exploit framing (so IS_HUNTER=true for the zero-probe block too)
printf '%s\n' "$(jq -nc '{type:"user",message:{content:[{type:"text",text:"hunter exploit idor bola ssrf target. Fire crafted probes and return a receipt."}]}}')" >> "$T5"
# assistant turn with ONLY a text message, zero tool_use (simulates truncated/empty transcript for ALL_CMDS)
# BUT we need EXPLOIT_PROBED=true so the case reaches the unverifiable block rather than the zero-probe block.
# We force this by having the RECENT_TOOLS scan see a send_http name in a tool_use in an early assistant turn,
# while ALL_CMDS (which uses tac + full scan) still sees nothing useful because we put the probe text in the
# tool name field which RECENT_TOOLS catches but ALL_CMDS input.command path misses.
# Cleaner: put a real tool_use that fires send_http (so EXPLOIT_PROBED=true) but whose command is empty,
# making ALL_CMDS output non-empty but PROBE_COUNT=0 -> PROBE_UNVERIFIABLE stays false via ALL_CMDS non-empty.
# The spec says "transcript has NO assistant tool_use lines" for truly unverifiable.
# To hit the PROBE_UNVERIFIABLE branch we need EXPLOIT_PROBED=true AND ALL_CMDS empty.
# We achieve this by having a tool_use whose NAME matches EXPLOIT regex but input.command is null/empty,
# so RECENT_TOOLS grep matches (sets EXPLOIT_PROBED) but ALL_CMDS jq extracts empty string (ALL_CMDS empty -> PROBE_UNVERIFIABLE).
printf '%s\n' "$(jq -nc '{type:"assistant",message:{content:[
  {type:"tool_use",name:"mcp__burp__send_http",input:{url:"https://example.com"}}
]}}')" >> "$T5"
printf '%s\n' "$(jq -nc '{type:"assistant",message:{content:[{type:"text",text:"this is dead, I cannot proceed further."}]}}')" >> "$T5"
OUT5=$(run_hook "$T5" "${SID}-5")
assert 5 "unverifiable-empty-transcript" "$OUT5" "block"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: $PASS passed, $FAIL failed out of 5 cases."
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
