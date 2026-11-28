#!/usr/bin/env bash
# Ground-truth H1 API token check. Run BEFORE ever claiming the token is "wiped".
# Prints VALID / MISSING / REVOKED without leaking the value. No args.
# ponytail: 6 lines, no deps beyond curl; that is the whole feature.
set -u
SECRETS="$HOME/.config/gnoc/secrets.env"
[ -f "$SECRETS" ] || { echo "MISSING: no secrets file at $SECRETS"; exit 2; }
# shellcheck disable=SC1090
. "$SECRETS"
[ -n "${HACKERONE_API_TOKEN:-}" ] || { echo "MISSING: HACKERONE_API_TOKEN empty in $SECRETS"; exit 2; }
# NOTE (2026-09-30): this used to read ${HACKERONE_HANDLE:-researcher}, which silently
# authenticated as a DIFFERENT account whenever secrets.env failed to load or the var
# was unset. The operator is greynoc. Fail loud rather than guess an identity.
[ -n "${HACKERONE_HANDLE:-}" ] || { echo "MISSING: HACKERONE_HANDLE empty in $SECRETS"; exit 2; }
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
  -u "$HACKERONE_HANDLE:$HACKERONE_API_TOKEN" \
  'https://api.hackerone.com/v1/hackers/me/reports?page%5Bsize%5D=1' -H 'Accept: application/json')
case "$code" in
  200) echo "VALID: token works (HTTP 200), len=${#HACKERONE_API_TOKEN}, handle=$HACKERONE_HANDLE"; exit 0;;
  401) echo "REVOKED: token present but rejected (HTTP 401). Regenerate at hackerone.com/settings/api_token"; exit 1;;
  000) echo "NETWORK: no response (egress/scope block) - validity inconclusive"; exit 3;;
  *)   echo "UNEXPECTED: HTTP $code"; exit 3;;
esac
