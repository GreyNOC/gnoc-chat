#!/usr/bin/env bash
# intake.sh - single front door for PROGRAM INTAKE.
#
# Dispatches to the existing platform-specific scope-fetch script (REUSED, never
# reimplemented), then verifies the result is a usable, non-empty SCOPE.txt and
# creates the standard targets/<handle>/ research subdirs.
#
# Usage:
#   scripts/intake.sh hackerone <handle>                 # alias: h1
#   scripts/intake.sh yeswehack <slug>                   # alias: ywh
#   scripts/intake.sh immunefi  <slug> [program-url] [--refresh]
#   scripts/intake.sh bugcrowd  <engagement-code> [--refresh]
#   scripts/intake.sh intigriti <company/program | program> [--refresh]
#   scripts/intake.sh hackenproof <program-slug> [--refresh]
#   scripts/intake.sh verify <handle>                    # re-run just the safety check
#   scripts/intake.sh list-platforms
#
# Idempotent: re-running with the same handle re-invokes the underlying platform
# script. h1-scope.sh / ywh-scope.sh / bugcrowd-scope.sh / intigriti-scope.sh never
# clobber an existing non-empty SCOPE.txt (they write SCOPE.txt.new instead, for a hand
# diff/merge; the last two also accept --refresh to overwrite in place); immunefi-scope.sh
# leaves an existing SCOPE.txt untouched unless --refresh is passed. Subdir creation is a
# plain `mkdir -p`, safe to repeat.
#
# HANDLE NORMALIZATION: bugcrowd and intigriti handles arrive in several shapes (a pasted
# brief/app URL, "engagements/<code>", "<company>/<program>"). The target directory is
# always ONE path segment - targets/<program>/ - so this script reduces the argument to
# that segment before verifying, exactly as the two platform scripts do internally.
# Without this, `intake.sh intigriti digitalocean/digitalocean` would look for
# targets/digitalocean/digitalocean/SCOPE.txt and refuse a perfectly good intake.
#
# SAFETY (see targets/README.md "empty-SCOPE.txt hazard"): a zero-entry SCOPE.txt is
# never a safe thing to leave on disk. As of 2026-09-30 the live scope gate
# (.claude/hooks/scope-gate.sh) FAILS CLOSED on a readable-but-empty allowlist, so such a
# file BLOCKS every probe from that program's directory and silently wedges the target;
# before that change the same file made the gate allow EVERY host. Either way it is wrong.
# This script therefore refuses to leave a zero-entry SCOPE.txt in place: it moves it
# aside and exits non-zero instead. The platform scope-fetch scripts (h1, ywh, immunefi,
# bugcrowd, intigriti) are the first line of defense - bugcrowd-scope.sh and
# intigriti-scope.sh refuse to write the file at all on a zero-host pull - and this is
# the backstop for a hand-edited or legacy file.
#
# The emptiness check imports scripts/bbtools/lib_scope.py's parse_scope() directly
# (the same parser the live hook's logic mirrors) rather than re-implementing scope
# line-counting, so this can never drift from what the gate actually enforces.
set -u

ROOT="${GNOC_WORKSPACE:-$HOME/.gnoc}"
SCRIPTS="$ROOT/scripts"

usage() {
  cat >&2 <<'EOF'
usage: intake.sh <platform> <handle> [platform-script args...]
       intake.sh verify <handle>
       intake.sh list-platforms

platform: hackerone|h1   yeswehack|ywh   immunefi   bugcrowd   intigriti   hackenproof

  intake.sh bugcrowd  program-25
  intake.sh intigriti digitalocean/digitalocean     (or just: intigriti digitalocean)
  intake.sh hackenproof zmo-exchange
EOF
}

PLATFORM="${1:-}"
HANDLE="${2:-}"
[ -z "$PLATFORM" ] && { usage; exit 1; }

if [ "$PLATFORM" = "list-platforms" ]; then
  cat <<'EOF'
hackerone (h1)   scripts/h1-scope.sh        needs HACKERONE_HANDLE + HACKERONE_API_TOKEN in
                                             ~/.config/gnoc/secrets.env
yeswehack (ywh)  scripts/ywh-scope.sh       public programs: no token. private/secured:
                                             YWH_API_TOKEN (or YWH_EMAIL/YWH_PASSWORD/YWH_TOTP)
immunefi         scripts/immunefi-scope.sh  zero auth (public RSC-embedded program data)
bugcrowd         scripts/bugcrowd-scope.sh  zero auth (public engagement-brief changelog JSON
                                             on bugcrowd.com). Arg = the engagement code,
                                             i.e. the last segment of the brief URL.
                                             Rank first:  scripts/bugcrowd-rank-programs.sh
intigriti        scripts/intigriti-scope.sh zero auth for confidentialityLevel=4 (fully
                                             public) programs via the public program API on
                                             app.intigriti.com. Arg = <company>/<program>,
                                             or just <program> (company is resolved from the
                                             public program list). Restricted/private
                                             programs answer HTTP 403 and need
                                             INTIGRITI_API_TOKEN in
                                             ~/.config/gnoc/secrets.env - see
                                             scripts/INTIGRITI.md for the honest limits.
                                             Rank first:  scripts/intigriti-rank-programs.sh
hackenproof      scripts/hackenproof-scope.sh zero auth (no public JSON API exists -
                                             decodes the Nuxt __NUXT_DATA__ devalue blob
                                             embedded in the public program page). Arg =
                                             the program slug, i.e. the last segment of
                                             the program page URL. Web3/crypto-focused
                                             platform: a program whose scope is entirely
                                             Smart Contract / Protocol references yields
                                             zero web hosts by design (on-chain lane, not
                                             this script). See scripts/HACKENPROOF.md.
                                             Rank first:  scripts/hackenproof-rank-programs.sh
EOF
  exit 0
fi

# --- emptiness check: reuses the CANONICAL parser, never reimplements it ----------------
scope_has_entries() {  # $1 = path to a SCOPE.txt ; exit 0 if it has >=1 in-scope host line
  python3 - "$1" <<'PY' 2>/dev/null
import sys
sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts")
from bbtools.lib_scope import parse_scope
sys.exit(0 if parse_scope(sys.argv[1]) else 1)
PY
}

scope_entry_count() {  # $1 = path to a SCOPE.txt ; prints the in-scope host-line count
  python3 - "$1" <<'PY' 2>/dev/null
import sys
sys.path.insert(0, "${GNOC_WORKSPACE:-$HOME/.gnoc}/scripts")
from bbtools.lib_scope import parse_scope
print(len(parse_scope(sys.argv[1])))
PY
}

verify_scope() {  # $1 = handle. Refuses (quarantines SCOPE.txt) if it has zero usable entries.
  local h="$1" dir sf
  dir="$ROOT/targets/$h"
  sf="$dir/SCOPE.txt"
  if [ ! -f "$sf" ]; then
    echo "REFUSE: $sf does not exist - nothing to onboard (check the platform-script output above)." >&2
    return 1
  fi
  if scope_has_entries "$sf"; then
    echo "OK: $sf has $(scope_entry_count "$sf") in-scope host line(s)."
    return 0
  fi
  # Zero usable entries. Never leave it in place: an absent SCOPE.txt keeps the program
  # UN-onboarded (invisible to loop-select-target.sh); an EMPTY one present would make the
  # live scope-gate hook fail OPEN and allow every host (see targets/README.md).
  local quarantine="$dir/SCOPE.txt.EMPTY-REFUSED.$(date +%s)"
  mv -f "$sf" "$quarantine"
  cat >&2 <<EOF
REFUSE: $sf parsed to ZERO in-scope host lines (comments / placeholders only).
  An empty SCOPE.txt is a hazard in BOTH directions, so it is never left in place:
  the live scope-gate hook now FAILS CLOSED on a readable-but-empty allowlist (changed
  2026-09-30) and would BLOCK every probe from targets/$h/, while a comments-only file
  that still parses to some token would instead hit the hook's fail-OPEN warn branch.
  Refusing to leave it in place. Moved aside to: $quarantine
  Fix: hand-fill real in-scope host lines (format: targets/README.md), or re-run intake
  with a working egress / valid token, then:  scripts/intake.sh verify $h
EOF
  return 2
}

make_subdirs() {  # $1 = handle. The standard research subdirs (never report drafts - those
                   # live only under reports/drafts/<program>/, per CLAUDE.md / ARCHITECTURE.md).
  mkdir -p "$ROOT/targets/$1"/recon "$ROOT/targets/$1"/poc "$ROOT/targets/$1"/evidence "$ROOT/targets/$1"/hunts
}

if [ "$PLATFORM" = "verify" ]; then
  [ -z "$HANDLE" ] && { usage; exit 1; }
  verify_scope "$HANDLE"
  exit $?
fi

[ -z "$HANDLE" ] && { usage; exit 1; }
shift 2 || true   # remaining "$@" (if any) passes through to the platform script untouched

case "$PLATFORM" in
  hackerone|h1)
    "$SCRIPTS/h1-scope.sh" "$HANDLE" "$@"
    rc=$?
    ;;
  yeswehack|ywh)
    "$SCRIPTS/ywh-scope.sh" "$HANDLE" "$@"
    rc=$?
    ;;
  immunefi)
    "$SCRIPTS/immunefi-scope.sh" "$HANDLE" "$@"
    rc=$?
    ;;
  bugcrowd)
    "$SCRIPTS/bugcrowd-scope.sh" "$HANDLE" "$@"
    rc=$?
    # targets/<code>/ - reduce a pasted brief URL / "engagements/<code>" to the bare code,
    # matching what bugcrowd-scope.sh did internally, so verify_scope looks in the right dir.
    HANDLE=$(printf '%s' "$HANDLE" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^engagements/##; s#[/?#].*$##')
    ;;
  intigriti)
    "$SCRIPTS/intigriti-scope.sh" "$HANDLE" "$@"
    rc=$?
    # targets/<program>/ - an Intigriti handle is "<company>/<program>"; the target dir is
    # the PROGRAM segment only, matching what intigriti-scope.sh did internally.
    HANDLE=$(printf '%s' "$HANDLE" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^programs/##; s#/detail/?$##; s#[?#].*$##; s#/+$##')
    HANDLE=${HANDLE##*/}
    ;;
  hackenproof)
    "$SCRIPTS/hackenproof-scope.sh" "$HANDLE" "$@"
    rc=$?
    # targets/<slug>/ - already a single segment; reduce a pasted program URL /
    # "programs/<slug>" the same way hackenproof-scope.sh did internally.
    HANDLE=$(printf '%s' "$HANDLE" | sed -E 's#^https?://[^/]+/##; s#^/+##; s#^programs/##; s#[/?#].*$##')
    ;;
  *)
    echo "unknown platform: $PLATFORM" >&2
    usage
    exit 1
    ;;
esac

if [ "$rc" -ne 0 ]; then
  echo "platform script exited $rc - not proceeding to subdir creation / verification." >&2
  exit "$rc"
fi

make_subdirs "$HANDLE"

if ! verify_scope "$HANDLE"; then
  exit 4
fi

echo "intake OK: targets/$HANDLE/ ready (SCOPE.txt verified non-empty; recon/ poc/ evidence/ hunts/ present)."
