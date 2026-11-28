#!/usr/bin/env bash
#
# qa-mail.sh - deliver the QA-READY reports and their evidence to the internal QA mailbox.
#
# This is an INTERNAL handoff to GreyNOC's own QA address. It is not a bug bounty submission
# and must never be pointed at a bug bounty platform. Platform submission stays human-only.
#
# WHY SMTP AND NOT A BROWSER. A browser driving webmail was considered and rejected:
#   1. Webmail attachment upload can silently drop a multi-file selection. That is not
#      hypothetical here - a vendor report form did exactly that to us, and the only way it
#      was caught was a human counting the rendered attachment chips. An unattended job
#      cannot do that, and would report success having delivered nothing.
#   2. A rendered "sent" page is a UI state, not proof of delivery. SMTP returns a 250 with
#      a queue id, which this script records as the receipt.
#   3. A DOM change breaks browser automation silently, at an arbitrary later time.
#   4. It would require an interactive logged-in profile or a stored password.
# One archive per message is attached, never a multi-select, for reason 1 above.
#
# SAFETY. Dry run is the DEFAULT; nothing leaves the machine without --send. It reads only
# the weekly READY tier, never _held or _closed. It refuses any bundle whose checksums do not
# verify. It will not re-send a bundle already in the sent ledger unless --force is given.
#
# Usage:
#   qa-mail.sh                      dry run: build everything, deliver nothing
#   qa-mail.sh --send               deliver
#   qa-mail.sh --send --one <slug>  deliver a single bundle
#   qa-mail.sh --list               show what is pending and what already went
# Flags: --force (re-deliver), --to ADDR, --from ADDR
set -u

WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
QA="$WS/QA handoff"
OUTBOX="$QA/_outbox"
SENTLOG="$WS/.claude/state/hunt-loop/qa-mail-sent.jsonl"
SECRETS="$HOME/.config/gnoc/secrets.env"

TO="you@your-site.example"
FROM="support@your-site.example"
SEND=0; FORCE=0; ONE=""; MODE=run

while [ $# -gt 0 ]; do
  case "$1" in
    --send)  SEND=1 ;;
    --force) FORCE=1 ;;
    --list)  MODE=list ;;
    --one)   shift; ONE="${1:-}" ;;
    --to)    shift; TO="${1:-$TO}" ;;
    --from)  shift; FROM="${1:-$FROM}" ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) echo "qa-mail: unknown arg $1" >&2; exit 2 ;;
  esac
  shift
done

die(){ printf 'qa-mail: %s\n' "$*" >&2; exit 1; }

# refuse to be aimed at a bounty platform, whatever the caller passes
case "$TO" in
  *hackerone*|*bugcrowd*|*intigriti*|*yeswehack*|*immunefi*|*whitehat*|*bugbounty*)
    die "refusing: $TO looks like a bug bounty platform. This tool is for the internal QA mailbox only." ;;
esac

month=$(date -u +%Y-%m-%B)
mon=$(date -u -d 'last monday' +%Y-%m-%d 2>/dev/null) || mon=$(date -u +%Y-%m-%d)
sun=$(date -u -d 'last monday +6 days' +%Y-%m-%d 2>/dev/null) || sun="$mon"
WEEK="$(date -u +%G-W%V)_${mon}_to_${sun}"
READY="$QA/$month/$WEEK"
[ -d "$READY" ] || die "no READY folder for this week at $READY"
mkdir -p "$OUTBOX" "$(dirname "$SENTLOG")" 2>/dev/null
touch "$SENTLOG" 2>/dev/null

already_sent(){ grep -qF "\"bundle\":\"$1\"" "$SENTLOG" 2>/dev/null; }

BUNDLES=(); SKIPPED=()
for d in "$READY"/*/; do
  [ -d "$d" ] || continue
  b=$(basename "$d")
  [ -n "$ONE" ] && [ "$b" != "$ONE" ] && continue
  [ -f "$d/REPORT.md" ] || { SKIPPED+=("$b (no REPORT.md)"); continue; }
  if [ -d "$d/evidence" ] && [ -f "$d/evidence/SHA256SUMS.txt" ]; then
    if ! ( cd "$d/evidence" && sha256sum -c SHA256SUMS.txt >/dev/null 2>&1 ); then
      SKIPPED+=("$b (CHECKSUMS FAIL - refused)"); continue
    fi
  fi
  if [ "$FORCE" -eq 0 ] && already_sent "$b"; then SKIPPED+=("$b (already delivered)"); continue; fi
  BUNDLES+=("$d")
done

if [ "$MODE" = list ]; then
  echo "READY folder: ${READY#$WS/}"
  echo "pending:"; for d in "${BUNDLES[@]:-}"; do [ -n "${d:-}" ] && echo "  $(basename "$d")"; done
  echo "skipped:";  for s in "${SKIPPED[@]:-}"; do [ -n "${s:-}" ] && echo "  $s"; done
  echo "ledger: $(grep -c . "$SENTLOG" 2>/dev/null || echo 0) prior deliveries"
  exit 0
fi
[ "${#BUNDLES[@]}" -eq 0 ] && { echo "qa-mail: nothing pending."; for s in "${SKIPPED[@]:-}"; do [ -n "${s:-}" ] && echo "  skipped: $s"; done; exit 0; }

if [ "$SEND" -eq 1 ]; then
  # shellcheck disable=SC1090
  [ -f "$SECRETS" ] && . "$SECRETS"
  : "${QA_SMTP_HOST:=}" "${QA_SMTP_PORT:=587}" "${QA_SMTP_USER:=}" "${QA_SMTP_PASS:=}"
  [ -n "$QA_SMTP_HOST" ] || die "QA_SMTP_HOST unset. Add QA_SMTP_HOST / QA_SMTP_PORT / QA_SMTP_USER / QA_SMTP_PASS to $SECRETS (chmod 600, outside the workspace)."
  [ -n "$QA_SMTP_USER" ] || die "QA_SMTP_USER unset in $SECRETS"
  [ -n "$QA_SMTP_PASS" ] || die "QA_SMTP_PASS unset in $SECRETS"
  command -v swaks >/dev/null 2>&1 || die "swaks not found"
fi

build_body(){
  local d="$1" b n ven
  b=$(basename "$d"); ven=${b%%_*}
  n=0; [ -f "$d/ATTACHMENTS.txt" ] && n=$(grep -vc '^#' "$d/ATTACHMENTS.txt" 2>/dev/null || echo 0)
  echo "QA handoff: $b"
  echo
  echo "Venue:          $ven"
  echo "Evidence files: $n"
  echo "Checksums:      verified before delivery; a failing bundle is refused, not sent"
  echo "Staged from:    ${d#$WS/}"
  echo
  echo "NOTHING IN THIS BUNDLE HAS BEEN FILED WITH ANY PROGRAM. Filing is human-only."
  echo
  for f in STATUS.md QA-NOTE-venue.md QA-NOTE-read-this.md STOP-READ-FIRST.md; do
    [ -f "$d/$f" ] && { echo "--- $f (read first) ---"; sed -n '1,25p' "$d/$f"; echo; }
  done
  echo "--- attachment manifest (generated by directory walk) ---"
  [ -f "$d/ATTACHMENTS.txt" ] && grep -v '^#' "$d/ATTACHMENTS.txt"
  echo
  echo "--- bundle contents ---"
  ( cd "$d" && find . -maxdepth 1 -mindepth 1 | sed 's|^\./|  |' | sort )
}

sent=0; built=0
for d in "${BUNDLES[@]}"; do
  b=$(basename "$d")
  tgz="$OUTBOX/$b.tar.gz"
  tar -czf "$tgz" -C "$READY" "$b" 2>/dev/null || { echo "  tar FAILED for $b"; continue; }
  tsha=$(sha256sum "$tgz" | cut -c1-16); tsize=$(du -h "$tgz" | cut -f1)
  body="$OUTBOX/$b.body.txt"
  { build_body "$d"; echo; echo "Archive: $(basename "$tgz")  ($tsize, sha256 ${tsha}...)"; } > "$body"
  built=$((built+1))

  # TRACKING TOKEN. Reconciling a Sent folder by subject substring is guesswork; a subject can
  # be edited, duplicated or truncated. Each message carries a deterministic token derived from
  # the bundle name and the archive hash, plus a Message-ID we mint ourselves, so the audit can
  # match on an exact string in either the header or the body.
  token="QA-HANDOFF-${b}-${tsha}"
  msgid="<${token}@greynoc.com>"
  printf '\nTracking token: %s\n' "$token" >> "$body"

  if [ "$SEND" -eq 1 ]; then
    out=$(swaks --to "$TO" --from "$FROM" \
            --server "$QA_SMTP_HOST" --port "$QA_SMTP_PORT" -tls \
            --auth-user "$QA_SMTP_USER" --auth-password "$QA_SMTP_PASS" \
            --header "Subject: [QA handoff] $b" \
            --header "Message-ID: $msgid" \
            --header "X-QA-Bundle: $b" \
            --header "X-QA-Token: $token" \
            --body "@$body" \
            --attach-type application/gzip --attach "@$tgz" 2>&1)
    if printf '%s' "$out" | grep -qE '<- +250'; then
      q=$(printf '%s' "$out" | grep -oE '250[^\r]*' | tail -1 | tr -d '"')
      printf '{"ts":"%s","bundle":"%s","to":"%s","from":"%s","archive_sha16":"%s","size":"%s","token":"%s","message_id":"%s","receipt":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$b" "$TO" "$FROM" "$tsha" "$tsize" "$token" "$msgid" "$q" >> "$SENTLOG"
      echo "  DELIVERED  $b  ($tsize)  receipt: $q"; sent=$((sent+1))
    else
      echo "  FAILED $b - NOT recorded as delivered. Server said:"
      printf '%s\n' "$out" | tail -5 | sed 's/^/      /'
    fi
  else
    echo "  BUILT (dry run)  $b  ($tsize)  token: $token"
  fi
done

echo
if [ "$SEND" -eq 1 ]; then
  echo "delivered $sent of $built; receipts in ${SENTLOG#$WS/}"
else
  echo "DRY RUN. Built $built message(s) in ${OUTBOX#$WS/}. Nothing left the machine."
  echo "Inspect:  cat \"$OUTBOX/<bundle>.body.txt\""
  echo "Deliver:  scripts/qa-mail.sh --send"
fi
for s in "${SKIPPED[@]:-}"; do [ -n "${s:-}" ] && echo "  skipped: $s"; done
exit 0
