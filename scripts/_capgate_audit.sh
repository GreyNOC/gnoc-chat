#!/usr/bin/env bash
# _capgate_audit.sh - is the CAPABILITY+TERMINAL refusal substantive, or a WORDING miss?
# Prints each refused draft's Impact text so a human can judge whether the finding really
# lacks a new capability or merely fails the gate's keyword regex.
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAP='cross-tenant|cross-user|other (user|account|tenant)|another (user|account)|state chang|deleted|modif|exfiltrat|private (body|data|record)|foreign (id|account|object)|\bRCE\b|command exec|money|payout'
for n in "$@"; do
  f="$WS/reports/drafts/$n/report.md"
  [ -f "$f" ] || { echo "-- $n : MISSING"; continue; }
  echo "=============================================================="
  echo "-- $n"
  echo "   CAP-regex hits in whole body: $(grep -ioE "$CAP" "$f" | sort -u | tr '\n' ' ')"
  echo "   --- Impact section as written ---"
  awk '/^(## [Ii]mpact|\*\*[Ii]mpact\*\*)/{on=1;next} on&&/^(## |\*\*[A-Z])/{exit} on' "$f" \
    | sed '/^$/d' | head -8 | sed 's/^/   /'
done
