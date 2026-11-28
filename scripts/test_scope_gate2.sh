#!/bin/bash
# The ACTUAL command shapes that scope-gate.sh hard-blocked on 2026-10-28, plus the must-block set.
HOOK=${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/hooks/scope-gate.sh
pass=0; fail=0
run() {
  local expect="$1" label="$2" cmd="$3" rc out
  out=$(printf '%s' "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$(python3 -c '
import json,sys; print(json.dumps(sys.argv[1]))' "$cmd")}}" | HUNT_TARGET=program-62 bash "$HOOK" 2>&1)
  rc=$?
  if [ "$expect" = block ]; then
    if [ $rc -ne 0 ]; then echo "  ok   BLOCKED  $label"; pass=$((pass+1));
    else echo "  FAIL not blocked: $label"; fail=$((fail+1)); fi
  else
    if [ $rc -eq 0 ]; then echo "  ok   allowed  $label"; pass=$((pass+1));
    else echo "  FAIL blocked:    $label -> $(printf '%s' "$out"|head -1|cut -c1-96)"; fail=$((fail+1)); fi
  fi
}

echo "== MUST BLOCK =="
run block "curl to an out-of-scope URL"   'curl -sS https://www.evil-not-in-scope.com/a'
run block "bare host after curl"          'curl -sS www.evil-not-in-scope.com'
run block "host(1) in command position"   'host www.evil-not-in-scope.com'
run block "dig after a pipe"              'echo x | dig www.evil-not-in-scope.com'
run block "a probe hidden in a long doc write" 'cat > /tmp/z.md <<EOF
some long prose about a finding
EOF
curl -sS https://www.evil-not-in-scope.com/exfil'

echo
echo "== MUST PASS: the four real 2026-10-28 blocks =="
run pass "handoff prose: Go filename + the word host" 'cat >> /tmp/z.md <<EOF
currentWorktree() at main.go:1857 returns the readlink target verbatim, and SyncRepo reaches
os.RemoveAll at main.go:2006. A captcha bypass on a non-production host has no room above informative.
EOF'
run pass "manual entry naming a temp dir"  'cat >> /tmp/z.md <<EOF
the draft quoted remote hash b4230d32 and tmpdir /var/tmp/tmp.umng7VZz1g from a run never saved
EOF'
run pass "ledger write naming os.RemoveAll" 'echo "{\"vector\":\"widget-sync path check trusts a link -> a delete outside the root\"}" | python3 scripts/hunt-state.py append-outcome'
run pass "report body: a PoC curl AND a citation URL" 'cat > /tmp/z.md <<EOF
Google documents the pair at developers.google.com/recaptcha/docs/faq verbatim.

curl -sS -A "$UA" -X POST "$B/request_account.html" -d "g-recaptcha-sitekey=$TESTKEY"
EOF'

echo
echo "pass=$pass fail=$fail"
[ $fail -eq 0 ]
