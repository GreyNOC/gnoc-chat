#!/usr/bin/env bash
# Live H1 triager-feedback sync + reconsolidate. Sources the H1 token from secrets.env
# (never printed), pulls all reports + activities, refreshes triager_analysis.latest.json
# and TRIAGER-PATTERN.latest.md, then rebuilds LESSONS.md. Run ad hoc, or cron it
# (e.g. daily) to keep the feedback loop fed with fresh triager verdicts.
set -u
SEC="$HOME/.config/gnoc/secrets.env"
[ -f "$SEC" ] || { echo "no secrets.env at $SEC" >&2; exit 1; }
set -a; . "$SEC"; set +a
export H1_TOKEN="${HACKERONE_API_TOKEN:-}" H1_USER="${HACKERONE_HANDLE:?set HACKERONE_HANDLE in ~/.config/gnoc/secrets.env}"
[ -n "$H1_TOKEN" ] || { echo "HACKERONE_API_TOKEN not set in secrets.env" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
python3 "$HERE/sync_h1.py" || { echo "sync_h1 failed" >&2; exit 1; }
python3 ${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts/learn/consolidate.py || true
# ECON: settle the proof market on the fresh triage states (never fails the sync)
python3 -c 'import sys; sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts"); import gnoc_economy as E; print(E.settle_triage())' || true
echo "H1 sync + consolidate done."
