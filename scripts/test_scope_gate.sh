#!/bin/bash
# Regression battery for .claude/hooks/scope-gate.sh after the 2026-10-28 prose fix.
# MUST-BLOCK cases prove enforcement is intact. MUST-PASS cases are the false positives that were fixed.
HOOK=${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/hooks/scope-gate.sh
pass=0; fail=0

run() { # <expect block|pass> <label> <command text>
  local expect="$1" label="$2" cmd="$3" out rc
  out=$(printf '%s' "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":$(python3 -c '
import json,sys; print(json.dumps(sys.argv[1]))' "$cmd")}}" \
        | HUNT_TARGET=program-62 bash "$HOOK" 2>&1)
  rc=$?
  if [ "$expect" = block ]; then
    if [ $rc -ne 0 ]; then echo "  ok   BLOCKED  $label"; pass=$((pass+1));
    else echo "  FAIL not blocked: $label"; fail=$((fail+1)); fi
  else
    if [ $rc -eq 0 ]; then echo "  ok   allowed  $label"; pass=$((pass+1));
    else echo "  FAIL blocked:    $label  -> $(printf '%s' "$out" | head -1)"; fail=$((fail+1)); fi
  fi
}

echo "== MUST BLOCK (enforcement must be intact) =="
run block "explicit out-of-scope URL"        'curl -sS https://www.evil-not-in-scope.com/a'
run block "out-of-scope URL in a pipeline"   'curl -sS https://api.notinscope-evil.com/v1 | head'
run block "bare host after curl"             'curl -sS www.evil-not-in-scope.com'
run block "host(1) tool in command position" 'host www.evil-not-in-scope.com'
run block "dig in command position"          'dig www.evil-not-in-scope.com'
run block "nc in command position"           'nc www.evil-not-in-scope.com 443'
run block "tool after a pipe"                'echo x | host www.evil-not-in-scope.com'
run block "tool after a semicolon"           'cd /tmp ; dig www.evil-not-in-scope.com'

echo
echo "== MUST PASS (the prose false positives this fix targets) =="
run pass  "prose containing the word host"   'echo "a captcha bypass on a non-production host has no room above informative"'
run pass  "Go method name in prose"          'echo "SyncRepo then reaches os.RemoveAll at line 2006"'
run pass  "Go source filename"               'echo "currentWorktree() at main.go:1857 returns the target"'
run pass  "doc URL quoted in a report body"  'cat > /tmp/zz.md <<EOF
See the reCAPTCHA FAQ at developers.google.com/recaptcha/docs/faq for the test keys.
EOF'
run pass  "prose with dig/ping as English"   'echo "one more dig at this and we ping the result back"'
run pass  "jsonl ledger filename"            'echo "appended to outcomes.jsonl and trajectories.jsonl"'

echo
echo "pass=$pass fail=$fail"
[ $fail -eq 0 ]
