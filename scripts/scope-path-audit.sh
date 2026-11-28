#!/usr/bin/env bash
#
# scope-path-audit.sh - list every host that is in scope ONLY at specific PATHS.
#
# WHY. The scope gate matches on HOSTNAME. It cannot enforce a path, so a program asset
# written as `URL https://host/v1/` becomes, to the gate, the bare host `host` - and a probe
# at `/mobile/` on that host sails through. On 2026-10-03 that produced a QA-READY report
# whose second affected host was in scope only at /v1/ and /v2/ while the PoC demonstrated
# /mobile/. A triager would have closed it "asset not in scope, N/A".
#
# Run this BEFORE probing a new host and BEFORE any report names a second affected asset.
# A host listed here is a trap: in scope, but only on the paths shown.
#
# Usage: scope-path-audit.sh [program ...]      no args = every program under targets/
set -u
WS="${GNOC_WORKSPACE:-$HOME/.gnoc}"
progs=("$@")
if [ "${#progs[@]}" -eq 0 ]; then
  mapfile -t progs < <(ls -d "$WS"/targets/*/ 2>/dev/null | sed 's#.*/targets/##; s#/$##' | sort)
fi

any=0
for p in "${progs[@]}"; do
  f="$WS/targets/$p/SCOPE.txt"
  [ -f "$f" ] || continue
  out=$(python3 - "$f" <<'PY'
import re, sys, collections
pathed = collections.defaultdict(list)   # host -> [paths]
bare = set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    s = line.strip()
    if not s or s.startswith("#"):
        continue
    s_line = s
    parts = s.split()
    # FIX 2026-10-10 (a): the type filter was hard-coded to URL/WILDCARD/CIDR/OTHER, which DROPPED
    # every API-typed row - and that is exactly how this audit missed the one programme where a real
    # out-of-scope probe actually happened. Accept any leading all-caps asset-type keyword instead of
    # an allowlist of four.
    if len(parts) < 2 or not re.fullmatch(r"[A-Z][A-Z_]*", parts[0]):
        continue
    asset = parts[1].lstrip("=")
    m = re.match(r"^https?://([^/]+)(/.*)$", asset)
    # a trailing /* is the whole host, not a path restriction
    if m and m.group(2) not in ("", "/", "/*"):
        pathed[m.group(1)].append(m.group(2))
        continue
    host_only = re.sub(r"^https?://", "", asset).rstrip("/")
    # FIX 2026-10-10 (b): a path restriction is ALSO written as a trailing annotation rather than as a
    # scheme'd URL, e.g. a PATH-ONLY note in the row's bracketed comment. The old code only detected
    # the URL form, so 22 annotated rows across 6 programmes were invisible. Read the whole row.
    ann = re.search(r"PATH[- ]?ONLY\s*:?\s*([^\]\n]+)", s_line, re.I)
    if ann:
        pathed[host_only].extend(ann.group(1).replace(",", " ").split())
    else:
        bare.add(host_only)
# a host is a TRAP only if every one of its entries carries a path, and no bare entry,
# no covering wildcard, exists for it
for host, paths in sorted(pathed.items()):
    if host in bare:
        continue
    covered = any(b.startswith("*") and host.endswith(b.lstrip("*").lstrip(".")) for b in bare)
    if covered:
        continue
    print(f"  {host}\tIN SCOPE ONLY AT: {' '.join(sorted(set(paths)))}")
PY
)
  if [ -n "$out" ]; then
    any=1
    printf '%s\n%s\n' "$p" "$out"
  fi
done

if [ "$any" -eq 0 ]; then
  echo "No path-restricted hosts in the programs checked."
else
cat <<'EOF'

The scope gate cannot enforce these paths. Probing any other path on a host above is out of
scope, and a report that demonstrates one will be closed N/A however good the finding is.
EOF
fi

# ---------- bare-domain trap ----------
# A programme that writes `*.example.com` for the estates it means to cover, and plain
# `example.com` elsewhere, means the plain ones EXACTLY. The gate matches hostnames and will
# happily let a worker probe a subdomain of a bare-domain asset that is not in scope at all.
# This cost a Umbrella lead on 2026-10-03: poc-static.paypalobjects.com looked in scope because
# paypalobjects.com is listed, but the asset is bare while every intended-wildcard line is `*.x`.
echo
echo "== bare-domain assets: subdomains are NOT in scope unless a wildcard line also exists =="
for p in "${progs[@]}"; do
  f="$WS/targets/$p/SCOPE.txt"
  [ -f "$f" ] || continue
  out=$(python3 - "$f" <<'PY'
import re, sys
bare, wild = set(), set()
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    s = line.strip()
    if not s or s.startswith("#"): continue
    parts = s.split()
    if len(parts) < 2: continue
    a = re.sub(r"^https?://", "", parts[1].lstrip("=")).split("/")[0]
    if a.startswith("*"): wild.add(a.lstrip("*."))
    elif a.count(".") == 1: bare.add(a)
trap = sorted(b for b in bare if b not in wild)
if trap and wild:
    for b in trap:
        print(f"  {b}	EXACT host only. A subdomain of it is OUT of scope.")
PY
)
  [ -n "$out" ] && printf '%s
%s
' "$p" "$out"
done
