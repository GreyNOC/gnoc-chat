#!/usr/bin/env bash
# make-form.sh <program>/<slug> - generate FORM.md, the platform's own field values.
# The report BODY is what gets pasted into the description field and carries no metadata
# header (reports/STYLE.md section 1). The structured values the form asks for live here.
set -euo pipefail
WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="${1:?usage: make-form.sh <program>/<slug>}"
DIR="$WS/reports/drafts/${T%%/*}/${T#*/}"; R="$DIR/report.md"
[ -f "$R" ] || { echo "no such draft: $R" >&2; exit 1; }
[ -f "$DIR/FORM.md" ] && { echo "FORM.md already exists, not overwriting: $DIR/FORM.md"; exit 0; }
g(){ grep -m1 -iE "^\\*{0,2}$1:?\\*{0,2}:? " "$R" 2>/dev/null | sed -E "s/^\\*{0,2}$1:?\\*{0,2}:? *//; s/^\\*+//; s/\\*+$//" | tr -d '`' | head -c 300; }
TITLE="$(grep -m1 '^# ' "$R" | sed 's/^# //')"
printf 'Title: %s\n' "${TITLE:-UNSET - fill in}"
{
printf 'Title: %s\n' "${TITLE:-UNSET - fill in}"
printf 'Asset: %s\n' "$(g Asset)"
printf 'CWE: %s\n' "$(g CWE)"
printf 'CVSS: %s\n' "$(g 'CVSS[^:]*')"
printf 'Venue: %s\n' "${T%%/*}"
printf '\n# Generated from the draft header by scripts/make-form.sh. VERIFY every line against\n'
printf '# the programme policy before filing. An empty value means the draft did not carry it.\n'
} > "$DIR/FORM.md"
echo "wrote $DIR/FORM.md"; cat "$DIR/FORM.md"
