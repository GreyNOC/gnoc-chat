#!/usr/bin/env python3
"""One-off: quote the `description:` scalar in skills whose frontmatter fails YAML parse
(an unquoted internal colon like `CVEs:` / `AC:H` makes YAML read it as a nested mapping).
Only touches files that currently FAIL to parse; re-verifies each after; leaves body untouched.
Usage: fix-skill-frontmatter.py [--apply]   (default = dry run)."""
import glob, os, re, sys, yaml

APPLY = "--apply" in sys.argv
SKILLS = os.path.join(os.path.dirname(__file__), "..", ".claude", "skills")


def parses(fm_text):
    try:
        d = yaml.safe_load(fm_text)
        return isinstance(d, dict) and d.get("name") and d.get("description")
    except Exception:
        return False


def fix(path):
    text = open(path).read()
    lines = text.split("\n")
    if lines[0].strip() != "---":
        return "no-frontmatter"
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return "no-frontmatter-close"
    fm = lines[1:end]
    if parses("\n".join(fm)):
        return "already-ok"
    di = next((i for i, l in enumerate(fm) if l.startswith("description:")), None)
    if di is None:
        return "no-description"
    # description spans from di until the next top-level `key:` line or a blank line
    dj = di + 1
    while dj < len(fm) and not re.match(r"^[A-Za-z0-9_-]+:\s", fm[dj]) and fm[dj].strip() != "":
        dj += 1
    val = fm[di][len("description:"):].strip()
    for k in range(di + 1, dj):
        val += " " + fm[k].strip()
    val = val.strip().strip('"').strip("'").strip()          # drop any half-quoting already present
    esc = val.replace("\\", "\\\\").replace('"', '\\"')
    newfm = fm[:di] + ['description: "' + esc + '"'] + fm[dj:]
    if not parses("\n".join(newfm)):
        return "STILL-FAILS-after-fix"
    d = yaml.safe_load("\n".join(newfm))
    if d.get("description") != val:                          # meaning must be preserved exactly
        return "MEANING-CHANGED"
    newtext = "\n".join(lines[:1] + newfm + lines[end:])
    if APPLY:
        open(path, "w").write(newtext)
    return f"fixed ({'applied' if APPLY else 'dry'}) desc_len={len(val)}"


rows = [(os.path.basename(os.path.dirname(p)), fix(p)) for p in sorted(glob.glob(SKILLS + "/*/SKILL.md"))]
for name, r in rows:
    if r not in ("already-ok",):
        print(f"{name:28} {r}")
print("---")
print("touched:", sum(1 for _, r in rows if r.startswith("fixed")),
      " problems:", [n for n, r in rows if r.startswith(("STILL", "MEANING", "no-"))])
