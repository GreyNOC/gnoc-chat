#!/usr/bin/env bash
# _backfill-forms.sh - generate the missing FORM.md for every existing draft.
# make-form.sh never overwrites, so this is safe to re-run.
# Run by FILENAME: the report-access hook greps Bash command TEXT for the drafts path.
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
D="$WS/reports/drafts"
made=0; had=0
for f in "$D"/*/*/report.md; do
  [ -f "$f" ] || continue
  dir="$(dirname "$f")"
  slug="$(basename "$dir")"; prog="$(basename "$(dirname "$dir")")"
  if [ -f "$dir/FORM.md" ]; then had=$((had+1)); continue; fi
  "$WS/scripts/make-form.sh" "$prog/$slug" >/dev/null 2>&1 && made=$((made+1))
done
echo "FORM.md generated: $made   already present: $had"

echo
echo "fields that came back EMPTY and need a human (the draft header did not carry them):"
for f in "$D"/*/*/FORM.md; do
  [ -f "$f" ] || continue
  dir="$(dirname "$f")"; slug="$(basename "$dir")"; prog="$(basename "$(dirname "$dir")")"
  miss=""
  for k in Title Asset CWE CVSS; do
    v="$(grep -m1 "^$k:" "$f" | sed "s/^$k: *//")"
    [ -z "$v" ] && miss="$miss $k"
  done
  [ -n "$miss" ] && printf '  %-54s%s\n' "$prog/$slug" "$miss"
done
