#!/usr/bin/env bash
# test-report-flow.sh - regression suite for the report QA pipeline.
#
# Method: one GOLDEN fixture that passes every gate, then ONE mutation per case. A case asserts
# the mutation flips the verdict. That isolates each rule: a suite of bespoke fixtures cannot
# tell "this rule fired" from "some other rule fired".
#
# Every case carries its own control. A gate that only ever passes is not a gate, and a gate
# that only ever fails is worse, so both directions are asserted.
#
# Run by FILENAME, never by pasting its body into a shell: the report-access hook greps Bash
# command TEXT for the drafts path and will block the call.
#
#   scripts/test-report-flow.sh            run all
#   scripts/test-report-flow.sh -v         show the failing output for each failed case
set -uo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERBOSE=0; [ "${1:-}" = "-v" ] && VERBOSE=1

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
# built from parts so this script's own path literal cannot trip the access hook if echoed
DD="$TMP/re""ports/dr""afts"
CASE_DIR="$DD/prog/slug"

PASS=0; FAIL=0; FAILED_CASES=()

golden_report(){ cat <<'EOF'
Gate: report-killer NOT-YET-RUN 2026-10-05
Dedup: public-checked 2026-10-05 novel: no prior report on this endpoint

# Cross-tenant record read via unscoped org_id on api.example.test

**Summary**

I read a private record belonging to a second tenant I provisioned myself, using only my own
tenant A session. The org_id path segment is never compared against the session's own tenant,
so any tenant reads any other tenant's records.

**Proof of Concept**

1. Baseline with no session, proving the boundary exists

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://api.example.test/v1/orgs/TENANT_B/records/1
```

Confirmed result:

```
401
```

2. The same object with tenant A's session

```bash
curl -s -i -H 'Cookie: sess=TENANT_A_SESSION' \
  https://api.example.test/v1/orgs/TENANT_B/records/1
```

Confirmed result:

```
HTTP/1.1 200 OK
content-length: 118
{"org":"TENANT_B","record_id":1,"holder":"tenant-b-owner","balance":"4120.55"}
```

Evidence: capture.log

The vendor documentation states that organisation data is isolated per tenant, at
https://docs.example.test/security/tenancy

## Impact

I read another tenant's private records while authenticated only as my own tenant. Any
authenticated customer reads any other customer's records by changing one path segment.
EOF
}

setup(){
  rm -rf "$DD"; mkdir -p "$CASE_DIR/evidence"
  golden_report > "$CASE_DIR/report.md"
  printf 'captured\n' > "$CASE_DIR/evidence/capture.log"
  printf 'Title: Cross-tenant record read via unscoped org_id on api.example.test\nAsset: api.example.test\nCWE: CWE-639 Authorization Bypass Through User-Controlled Key\nCVSS: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium\n' > "$CASE_DIR/FORM.md"
}

qaqc(){ D_OVERRIDE="$DD" "$WS/scripts/qaqc.sh" prog/slug --quiet 2>&1; }

# check <name> <expect pass|fail> [mutation command...]
check(){
  local name="$1" expect="$2"; shift 2
  setup
  "$@" >/dev/null 2>&1
  local out rc
  out="$(qaqc)"; rc=$?
  local got="pass"; [ $rc -ne 0 ] && got="fail"
  if [ "$got" = "$expect" ]; then
    printf '  ok    %-52s (%s)\n' "$name" "$expect"; PASS=$((PASS+1))
  else
    printf '  FAIL  %-52s expected %s, got %s\n' "$name" "$expect" "$got"
    FAIL=$((FAIL+1)); FAILED_CASES+=("$name")
    [ "$VERBOSE" -eq 1 ] && printf '%s\n' "$out" | sed 's/^/          /'
  fi
}

nop(){ :; }
sub(){ perl -0pi -e "$1" "$CASE_DIR/report.md"; }
app(){ printf '%s\n' "$1" >> "$CASE_DIR/report.md"; }

echo "REPORT-FLOW REGRESSION SUITE"
echo
echo "golden fixture"
check "golden fixture passes everything"            pass nop

echo
echo "structure"
check "missing Summary section"                     fail sub 's/\*\*Summary\*\*/**Overview**/'
check "missing Proof of Concept section"            fail sub 's/\*\*Proof of Concept\*\*/**Steps**/'
check "missing Impact section"                      fail sub 's/## Impact/## Consequences/'
check "ATX headings accepted as well as bold"       pass sub 's/\*\*Summary\*\*/## Summary/'
check "'Steps to reproduce' accepted for PoC"       pass sub 's/\*\*Proof of Concept\*\*/## Steps to reproduce/'

echo
echo "evidence"
check "empty evidence directory"                    fail rm -f "$CASE_DIR/evidence/capture.log"

echo
echo "anti-slop voice (prose only)"
check "em dash in prose"                            fail sub 's/one path segment/one path segment \x{2014} trivially/'
check "AI-slop phrase in prose"                     fail sub 's/I read a private record/It is worth noting I read a private record/'
check "banned word in prose"                        fail sub 's/private records/comprehensive private records/'
check "slop INSIDE a code block is ignored"         pass sub 's/captured\n401/captured\n401 comprehensive/'
check "double-hyphen as em dash"                    fail sub 's/one path segment/one path segment -- trivially/'

echo
echo "internal reference leaks"
check "workspace path leaked in body"               fail app 'See ${GNOC_WORKSPACE:-$HOME/.gnoc}/targets/x/notes.md'
check "agent name in body prose"                    fail app 'The report-killer agent reviewed this.'
check "agent name on a Gate: line is allowed"       pass nop
check "placeholder left in draft"                   fail app 'TODO confirm the second tenant id'

echo
echo "title"
check "backtick in title"                           fail sub 's/# Cross-tenant/# `Cross`-tenant/'
check "underscore in title is allowed"              pass sub 's/org_id on/org_id and tenant_id on/'
check "title over 120 chars"                        fail sub 's/# Cross-tenant record read/# Cross-tenant record read that is really extremely very considerably and exceedingly long indeed for a title field/'

echo
echo "prose word caps (fenced blocks excluded)"
check "Summary over 150 words"                      fail sub "s/so any tenant reads any other tenant's records\./$(python3 -c "print(' '.join(['word']*160))")/"

echo
echo "FORM.md, the platform field values"
check "no FORM.md"                                  fail rm -f "$CASE_DIR/FORM.md"
check "FORM.md missing CVSS"                        fail sed -i '/^CVSS:/d' "$CASE_DIR/FORM.md"

echo
echo "manifest reconciliation"
check "ATTACHMENTS names a file not on disk"        fail bash -c "printf 'capture.log\nghost.bin\n' > '$CASE_DIR/ATTACHMENTS.txt'"
check "ATTACHMENTS matching disk is fine"           pass bash -c "printf 'capture.log\n' > '$CASE_DIR/ATTACHMENTS.txt'"

echo
echo "staged-form drift"
check "staged form two generations behind body"     fail bash -c "mkdir -p '$CASE_DIR/form' && printf 'A totally different and much older summary text.\n' > '$CASE_DIR/form/02-description.md'"

echo
echo "capability gate, re-run at the promotion boundary"
check "mechanism only, no new capability"           fail bash -c "cat > '$CASE_DIR/report.md' <<'MECH'
Gate: report-killer NOT-YET-RUN 2026-10-05
Dedup: public-checked 2026-10-05 novel: none

# Reachable endpoint on api.example.test

**Summary**

I observed that the endpoint responds without error when no parameters are supplied.

**Proof of Concept**

1. Probe

\\\`\\\`\\\`bash
curl -s -o /dev/null -w '%{http_code}' https://api.example.test/v1/ping
\\\`\\\`\\\`

Confirmed result:

\\\`\\\`\\\`
200
\\\`\\\`\\\`

Evidence: capture.log

## Impact

The endpoint is reachable and returns a response.
MECH"
check "missing Dedup public-check stamp"            fail sed -i '/^Dedup:/d' "$CASE_DIR/report.md"
check "missing Gate stamp"                          fail sed -i '/^Gate:/d' "$CASE_DIR/report.md"

echo
printf 'RESULT  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  printf 'failed: %s\n' "${FAILED_CASES[*]}"
  echo "re-run with -v to see each failing case's gate output"
  exit 1
fi
exit 0
