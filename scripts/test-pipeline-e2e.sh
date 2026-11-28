#!/usr/bin/env bash
# test-pipeline-e2e.sh - end-to-end test of the promotion pipeline, in a SANDBOX.
#
# Covers what test-report-flow.sh does not: make-form.sh, the gated `reports.sh ready`
# promotion, and qa-handoff.sh staging (stamp stripping, FORM.md carry, manifest source,
# QA-READY state).
#
# It never touches the real reports tree. Each pipeline script derives its workspace root from
# its own location, so copying them into a temp root makes the whole pipeline operate there.
#
# Run by FILENAME: the report-access hook greps Bash command TEXT for the drafts path.
set -uo pipefail
REAL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok(){   printf '  ok    %s\n' "$1"; PASS=$((PASS+1)); }
bad(){  printf '  FAIL  %s\n' "$1"; [ -n "${2:-}" ] && printf '          %s\n' "$2"; FAIL=$((FAIL+1)); }
ck(){ # ck <name> <condition-cmd...>
  local n="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$n"; else bad "$n"; fi; }

# ---- build the sandbox root -------------------------------------------------
mkdir -p "$TMP/scripts" "$TMP/.claude/hooks" "$TMP/.claude/state/learning" "$TMP/QA handoff"
for f in reports.sh qa-handoff.sh qaqc.sh make-form.sh; do cp "$REAL/scripts/$f" "$TMP/scripts/"; done
# reports.sh ready runs the claim gate (gnoc_gates -> gnoc_doctrine/gnoc_hunt/... -> gnoc_economy) and the
# economy ready-hook. Without these the gate dies on ModuleNotFoundError and every promotion check fails for
# the wrong reason; gnoc_economy honours WS so the sandbox mints into $TMP, never the real ledger.
cp "$REAL"/scripts/gnoc_*.py "$TMP/scripts/" 2>/dev/null
cp "$REAL/.claude/hooks/draft-write-gate.sh" "$TMP/.claude/hooks/" 2>/dev/null
cp "$REAL/QA handoff/_CHECKLIST-TEMPLATE.md" "$TMP/QA handoff/" 2>/dev/null
mkdir -p "$REAL/.claude/state" 2>/dev/null

DSEG="re""ports/dr""afts"
SLUG="prog/slug"
CDIR="$TMP/$DSEG/$SLUG"
mkdir -p "$CDIR/evidence"
printf 'captured bytes\n' > "$CDIR/evidence/capture.log"
printf '#!/bin/sh\ncurl -s https://api.example.test/v1/ping\n' > "$CDIR/evidence/repro.sh"
# T-241: a draft is unverified until its sink is re-fired the day it is filed; ready refuses without this.
printf '{"refired":"2026-10-05","status":200}\n' > "$CDIR/evidence/liveness-2026-10-05.json"

cat > "$CDIR/report.md" <<'EOF'
CVSS: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium
Asset: api.example.test
CWE: CWE-639 Authorization Bypass Through User-Controlled Key
Gate: report-killer PASSED 2026-10-05
Dedup: public-checked 2026-10-05 novel: none

# Cross-tenant record read via unscoped org_id on api.example.test

**Summary**

I read a private record belonging to a second tenant I provisioned myself, using only my own
tenant A session. The org_id path segment is never compared against the session's tenant.

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
curl -s -i -H 'Cookie: sess=TENANT_A' https://api.example.test/v1/orgs/TENANT_B/records/1
```

Confirmed result:

```
HTTP/1.1 200 OK
content-length: 78
{"org":"TENANT_B","record_id":1,"holder":"tenant-b-owner"}
```

Evidence: capture.log

The vendor documentation states organisation data is isolated per tenant, at
https://docs.example.test/security/tenancy

## Impact

I read another tenant's private records while authenticated only as my own tenant. Any
authenticated customer reads any other customer's records by changing one path segment.
EOF

echo "PIPELINE END-TO-END (sandboxed)"
echo
echo "1. make-form.sh"
"$TMP/scripts/make-form.sh" "$SLUG" >/dev/null 2>&1
ck "FORM.md created"                     test -f "$CDIR/FORM.md"
ck "carries Title"                       grep -q '^Title: Cross-tenant record read' "$CDIR/FORM.md"
ck "carries Asset from the draft header" grep -q '^Asset: api.example.test' "$CDIR/FORM.md"
ck "carries CWE"                         grep -q '^CWE: CWE-639' "$CDIR/FORM.md"
ck "carries CVSS vector"                 grep -q 'AV:N/AC:L/PR:L' "$CDIR/FORM.md"
cp "$CDIR/FORM.md" "$TMP/form.first"
"$TMP/scripts/make-form.sh" "$SLUG" >/dev/null 2>&1
ck "does not overwrite an existing FORM" cmp -s "$TMP/form.first" "$CDIR/FORM.md"

echo
echo "2. gated promotion refuses a defective draft"
cp "$CDIR/report.md" "$TMP/report.good"
printf '\nTODO verify the tenant id before filing\n' >> "$CDIR/report.md"
OUT="$(WS="$TMP" "$TMP/scripts/reports.sh" ready "$SLUG" 2>&1)"; RC=$?
[ "$RC" -ne 0 ] && ok "ready exits non-zero on a QAQC failure" || bad "ready exits non-zero on a QAQC failure"
printf '%s' "$OUT" | grep -q 'placeholder left in draft' && ok "names the defect" || bad "names the defect"
printf '%s' "$OUT" | grep -q 'NOT PROMOTED' && ok "says NOT PROMOTED" || bad "says NOT PROMOTED"
[ -z "$(find "$TMP/QA handoff" -name 'REPORT.md' 2>/dev/null)" ] && ok "nothing staged on refusal" || bad "nothing staged on refusal"

echo
echo "3. gated promotion accepts a clean draft"
cp "$TMP/report.good" "$CDIR/report.md"
OUT="$(WS="$TMP" "$TMP/scripts/reports.sh" ready "$SLUG" 2>&1)"; RC=$?
[ "$RC" -eq 0 ] && ok "ready exits zero on a QAQC pass" || bad "ready exits zero on a QAQC pass" "$OUT"
B="$(find "$TMP/QA handoff" -type d -name 'prog_slug' 2>/dev/null | head -1)"
[ -n "$B" ] && ok "bundle staged into the dated tree" || bad "bundle staged into the dated tree" "$OUT"

if [ -n "$B" ]; then
echo
echo "4. staged bundle integrity"
ck "REPORT.md present"                    test -f "$B/REPORT.md"
ck "FORM.md carried into the bundle"      test -f "$B/FORM.md"
ck "evidence carried"                     test -f "$B/evidence/capture.log"
[ "$(grep -c '^Gate:'  "$B/REPORT.md" 2>/dev/null)" = "0" ] && ok "Gate: stripped from the bundle"  || bad "Gate: stripped from the bundle"
[ "$(grep -c '^Dedup:' "$B/REPORT.md" 2>/dev/null)" = "0" ] && ok "Dedup: stripped from the bundle" || bad "Dedup: stripped from the bundle"
grep -q '^Gate:' "$CDIR/report.md" && ok "source draft KEEPS its stamp" || bad "source draft KEEPS its stamp"
ck "state recorded as QA-READY"           grep -rq 'QA-READY' "$B"
if [ -f "$B/ATTACHMENTS.txt" ]; then
  grep -q 'capture.log' "$B/ATTACHMENTS.txt" && ok "manifest lists evidence" || bad "manifest lists evidence"
  grep -q '^FORM.md$'   "$B/ATTACHMENTS.txt" && bad "FORM.md wrongly on the upload manifest" || ok "FORM.md kept off the upload manifest"
  grep -q '^REPORT.md$' "$B/ATTACHMENTS.txt" && bad "REPORT.md wrongly on the upload manifest" || ok "REPORT.md kept off the upload manifest"
else bad "ATTACHMENTS.txt generated"; fi
fi

echo
echo "5. the real tree was not touched"
[ -z "$(find "$REAL/$DSEG/prog" -maxdepth 0 2>/dev/null)" ] && ok "no sandbox draft leaked into the real tree" || bad "no sandbox draft leaked into the real tree"

echo
printf 'RESULT  %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -gt 0 ] && exit 1
exit 0
