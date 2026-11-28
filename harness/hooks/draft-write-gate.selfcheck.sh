#!/usr/bin/env bash
# Self-check for draft-write-gate.sh: Denial 0 (ATTRIBUTION) + Denial 3 (LENGTH 35-word cap).
# Proves: a report targeting a cloud-provider host with NO ownership artifact is BLOCKED
# (exit 2); adding an OWNERSHIP line or a vendor-disclosure route PASSES; a report with no
# cloud host is not attribution-blocked. Run: bash draft-write-gate.selfcheck.sh
set -u
HOOK="${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/hooks/draft-write-gate.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq absent"; exit 0; }
# reset this fixture session's safety-valve counter so repeated runs stay deterministic
# (>15 gated writes/session trips the valve and would let a length fixture pass spuriously).
rm -f "${GNOC_WORKSPACE:-$HOME/.gnoc}/.claude/state/learning/draftgate-attrib-selftest.count" 2>/dev/null

mk(){ jq -nc --arg c "$1" '{cwd:"${GNOC_WORKSPACE:-$HOME/.gnoc}",tool_name:"Write",tool_input:{file_path:"${GNOC_WORKSPACE:-$HOME/.gnoc}/reports/drafts/program-19/selftest.md",content:$c},session_id:"attrib-selftest"}'; }
run(){ printf '%s' "$(mk "$1")" | bash "$HOOK" >/tmp/ag.err 2>&1; echo $?; }

STAMP='Gate: report-killer PASS 2026-07-10'   # satisfies denial 2 stamp
EVID='HTTP/1.1 200 OK'                          # satisfies denial 2 evidence
CAP='cross-tenant mailbox read'                 # satisfies denial 1 (has capability)
DEDUP='Dedup: public-checked 2026-07-10 (none)'  # satisfies denial 2 public-dedup stamp

# Canonical shape (GreyNOC 2026-07-23): the Dedup/Gate stamps live in the header block ABOVE the
# # title, never in the body. The hygiene denial (3b) blocks a stamp below the title.
BAD="$DEDUP
$STAMP
# t
## Summary
A cross-tenant read.
## PoC
curl -X POST https://abcde12345.execute-api.us-east-1.amazonaws.com/dev/outlookGetToken -H 'X-Api-Key: X'
$EVID
## Impact
$CAP"

GOOD_OWN="$BAD
OWNERSHIP: TLS cert SAN on this host, issuer org=Massive Technologies (captured 2026-07-10)"

GOOD_VD="$BAD
This is routed as coordinated vendor-disclosure to the operator."

NO_CLOUD="$DEDUP
$STAMP
# t
## Summary
A cross-tenant read.
## PoC
curl https://app.example.com/api/x
$EVID
## Impact
$CAP"

# Denial 3b (HYGIENE) fixtures - a Gate:/Dedup: stamp BELOW the title, or a confession section,
# is blocked; the same draft with stamps in the header block passes hygiene.
HYG_STAMP_BODY="$DEDUP
$STAMP
# t
## Summary
A cross-tenant read.
## PoC
curl https://app.example.com/api/x
$EVID
$STAMP
## Impact
$CAP"
HYG_CONFESS="$DEDUP
$STAMP
# t
## Summary
A cross-tenant read.
## PoC
curl https://app.example.com/api/x
$EVID
## Impact
$CAP

## What Was NOT Confirmed
I did not reach money movement."

# Denial 3 (LENGTH) fixtures - need a CVSS: header line (an Immunefi form has none and is exempt).
HDR='CVSS: CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N 6.5 Medium
Asset: app.example.com
CWE: CWE-639'
LEN_BAD="$HDR
# t
## Summary
one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour twentyfive twentysix twentyseven twentyeight twentynine thirty thirtyone thirtytwo thirtythree thirtyfour thirtyfive thirtysix thirtyseven
## PoC
curl https://app.example.com/x
$EVID
## Impact
$CAP"
LEN_OK="$HDR
# t
## Summary
I read another tenant order, a cross-tenant IDOR exposing private PII with no authz check on the object id.
## PoC
curl https://app.example.com/x
$EVID
$STAMP
$DEDUP
Evidence: capture.log
## Impact
$CAP"

pass=0; fail=0
chk(){ if [ "$1" = "$2" ]; then echo "ok:   $3 (exit $1)"; pass=$((pass+1));
       else echo "FAIL: $3 (exit $1, want $2)"; sed 's/^/      | /' /tmp/ag.err; fail=$((fail+1)); fi; }

chk "$(run "$BAD")"      2 "cloud host + no ownership -> BLOCK"
chk "$(run "$GOOD_OWN")" 0 "cloud host + OWNERSHIP artifact -> PASS"
chk "$(run "$GOOD_VD")"  0 "cloud host + vendor-disclosure -> PASS"
chk "$(run "$NO_CLOUD")" 0 "no cloud host -> PASS (attribution not triggered)"

# Denial 3 (LENGTH): a CVSS-header draft with a 37-word Summary is BLOCKED on LENGTH; a <=35-word
# Summary does NOT trip the LENGTH denial (it may still exit 2 on another denial, but not LENGTH).
errhas(){ grep -q "$1" /tmp/ag.err && echo yes || echo no; }

# Denial 3b (HYGIENE): a stamp below the title, or a confession section, is blocked as HYGIENE.
r=$(run "$HYG_STAMP_BODY"); chk "$r" 2 "HYGIENE: Gate: stamp below title -> BLOCK"; chk "$(errhas 'HYGIENE')" yes "  ...and the block is the HYGIENE denial"
r=$(run "$HYG_CONFESS");    chk "$r" 2 "HYGIENE: confession section -> BLOCK"; chk "$(errhas 'HYGIENE')" yes "  ...and the block is the HYGIENE denial"
r=$(run "$LEN_BAD"); chk "$r" 2 "CVSS header + 37-word Summary -> BLOCK"; chk "$(errhas 'LENGTH')" yes "  ...and the block is the LENGTH denial"
run "$LEN_OK" >/dev/null 2>&1; chk "$(errhas 'LENGTH')" no "CVSS header + <=35-word Summary -> no LENGTH block"

echo "---- $pass passed, $fail failed ----"
[ "$fail" -eq 0 ]
