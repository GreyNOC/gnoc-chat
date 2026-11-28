#!/usr/bin/env python3
"""gnoc_reqhash.py - add --hash lines to the release's pinned requirements, from PyPI's JSON API.

    python3 scripts/tools/gnoc_reqhash.py scripts/gnoc_release_files/requirements.txt

Every `name==version` line gets the SHA-256 of every file PyPI lists for that exact release (all wheels and the
sdist), so `pip install --require-hashes` installs exactly the bytes this release was built against: a file the
maintainer adds to the same version later has no listed hash and is never chosen. Comments and blank lines are
kept; an existing --hash block for a line is replaced. Needs network access to pypi.org.
"""
import json
import re
import sys
import urllib.request

PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)")


def hashes(name, version):
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "gnoc-release-reqhash"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    out = sorted({f["digests"]["sha256"] for f in data.get("urls") or [] if f.get("digests", {}).get("sha256")})
    if not out:
        raise SystemExit(f"{name}=={version}: PyPI lists no files")
    return out


def main(path):
    lines = open(path, encoding="utf-8").read().split("\n")
    out, i = [], 0
    while i < len(lines):
        ln = lines[i]
        m = PIN.match(ln)
        if not m:
            out.append(ln)
            i += 1
            continue
        head = ln.split("\\")[0].rstrip()
        i += 1
        while i < len(lines) and lines[i].strip().startswith("--hash="):   # drop the old hash block
            i += 1
        hs = hashes(m.group(1), m.group(2))
        out.append(head + " \\")
        out += [f"    --hash=sha256:{h}" + (" \\" if k < len(hs) - 1 else "") for k, h in enumerate(hs)]
        print(f"{m.group(1)}=={m.group(2)}: {len(hs)} file(s)", file=sys.stderr)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1])
