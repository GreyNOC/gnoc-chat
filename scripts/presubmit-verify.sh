#!/usr/bin/env bash
# presubmit-verify.sh <finding-dir-name>
#
# Mechanical pre-submission check. Exists because on 2026-09-30 a report was filed to
# Meta missing one evidence file: the upload was verified against the form's OWN manifest
# (form/07-attachments.txt), which was itself the thing that was short. Checking a list
# against itself can only ever pass. This checks against the EVIDENCE DIRECTORY, which is
# the only source of truth, and against SHA256SUMS.txt, because shipping a manifest that
# names a file you did not upload makes the whole bundle fail verification for the triager.
set -u
PROG="${2:-meta-bbp}"
R="${GNOC_WORKSPACE:-$HOME/.gnoc}/reports/drafts/${PROG}/${1:-}"
[ -d "$R" ] || { echo "usage: presubmit-verify.sh <finding-dir> [program]"; exit 2; }
fail=0
say(){ printf '%-52s %s\n' "$1" "$2"; }

ev="$R/evidence"; lst="$R/form/07-attachments.txt"
[ -f "$lst" ] || { say "attachment list" "ABSENT - cannot submit"; exit 1; }

# SHA256SUMS.txt is the integrity manifest, not evidence, and some platforms refuse a .txt
# upload outright. Drop it from BOTH sides so the comparison stays evidence-vs-list.
nomanifest(){ grep -vx "SHA256SUMS.txt"; }

# The evidence dir can be a TREE (determinism runs under boot1/ boot2/), and a bundle too
# large to upload file-by-file can travel as an archive under <finding>/upload/. Compare
# RELATIVE PATHS over the whole tree, not basenames at one level: flattening collapses
# boot1/audit.log and boot2/audit.log into one name and silently hides an omission.
ondisk=$(cd "$ev" 2>/dev/null && find . -type f -printf '%P\n' | nomanifest | sort -u)
listedset=$(sed 's#^.*/evidence/##' "$lst" | grep . | nomanifest | sort -u)

# A listed archive carries its members: they count as uploaded, by their path inside it.
inarchive=$(for a in "$R"/upload/*.tar.gz "$R"/upload/*.tgz "$R"/upload/*.zip; do
  [ -f "$a" ] || continue
  case "$a" in
    *.zip) unzip -Z1 "$a" 2>/dev/null ;;
    *)     tar -tzf "$a" 2>/dev/null ;;
  esac
done | grep -v '/$' | grep . | sort -u)
# effective upload set = individually listed files + every archive member
uploadset=$(printf '%s\n%s\n' "$listedset" "$inarchive" | grep . | sort -u)
listed=$(printf '%s\n' "$listedset" | grep -c . )
miss=$(comm -13 <(printf '%s\n' "$uploadset") <(printf '%s\n' "$ondisk"))
extra=$(comm -23 <(printf '%s\n' "$uploadset") <(printf '%s\n' "$ondisk"))

say "evidence files on disk" "$(printf '%s\n' "$ondisk" | grep -c .)"
say "files reaching the form (incl. archive members)" "$(printf '%s\n' "$uploadset" | grep -c .)"
[ -n "$miss" ]  && { say "ON DISK BUT NOT BEING UPLOADED" "$(echo $miss)"; fail=1; } || say "nothing omitted" "ok"
[ -n "$extra" ] && { say "LISTED BUT NOT ON DISK" "$(echo $extra)"; fail=1; } || say "no phantom entries" "ok"

# every path in the list must resolve
while read -r p; do [ -z "$p" ] && continue; [ -f "$p" ] || { say "UNRESOLVABLE PATH" "$p"; fail=1; }; done < "$lst"

# the manifest must not name anything we are not sending
if [ -f "$ev/SHA256SUMS.txt" ]; then
  man=$(grep -v '^#' "$ev/SHA256SUMS.txt" | awk '{print $2}' | sed 's#.*/##' | sort -u)
  sentbase=$(printf '%s\n' "$uploadset" | sed 's#.*/##' | sort -u)
  notsent=$(comm -13 <(printf '%s\n' "$sentbase") <(printf '%s\n' "$man" | nomanifest | sort -u))
  [ -n "$notsent" ] && { say "MANIFEST NAMES FILES NOT BEING SENT" "$(echo $notsent)"; fail=1; } || say "manifest matches upload set" "ok"
  (cd "$ev" && sha256sum -c SHA256SUMS.txt >/dev/null 2>&1) && say "sha256sum -c" "ok" || { say "sha256sum -c" "FAILED"; fail=1; }
fi

for f in 01-title.txt 02-description.md 03-impact.md 06-reproduction-steps.md; do
  [ -s "$R/form/$f" ] || { say "required field $f" "MISSING OR EMPTY"; fail=1; }
done
t=$(wc -c < "$R/form/01-title.txt" 2>/dev/null || echo 999)
[ "$t" -le 120 ] && say "title length ($t)" "ok" || { say "title length ($t)" "OVER 120"; fail=1; }

echo
[ "$fail" -eq 0 ] && echo "PASS - mechanically ready. STILL REQUIRES HUMAN REVIEW BEFORE SUBMIT." || echo "FAIL - do not submit"
exit $fail
