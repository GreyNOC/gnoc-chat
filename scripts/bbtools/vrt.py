#!/usr/bin/env /usr/bin/python3
"""vrt.py - resolve a Bugcrowd VRT id to its PRIORITY, and enforce the P3 submission floor.

WHY THIS EXISTS, and the receipt is specific. The user, 2026-11-05: "from now on, use p5 and p4 to
get the p3 and above. only submit p3 and above to bugcrowd" - set after our first Bugcrowd filing
came back "youre a rookie try harder".

The filing was a world-readable admin OAuth client secret on an in-scope host. I chose the VRT
category by NAME MATCH - `sensitive_data_exposure.sensitive_data_hardcoded.oauth_secret`, because the
finding was literally an OAuth secret. **That leaf is P5, the lowest tier.** Meanwhile
`sensitive_data_exposure.disclosure_of_secrets.for_publicly_accessible_asset` - which is what the
finding actually WAS, a secret disclosed on a publicly accessible asset - is **P1**. The same bytes,
four priority levels apart, decided by which leaf you pick.

So this module exists to make two mistakes impossible:
  1. filing below P3 at all, and
  2. picking a leaf by how its NAME reads instead of by what the finding IS and what the leaf PAYS.

Usage:
    vrt.py <vrt-id>                 resolve one id: priority + the P3 verdict
    vrt.py --search <text>          every leaf whose path or name matches, WITH priorities, best first
    vrt.py --check <vrt-id>         exit 0 if P1-P3, exit 2 if P4/P5, exit 3 if varies/unknown
    vrt.py --levels                 leaf counts per priority

Data: scripts/bbtools/data/vrt.json (bugcrowd/vulnerability-rating-taxonomy, release 2026-07-08).
Refresh it from
https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master/vulnerability-rating-taxonomy.json

CAVEAT the file cannot express: a programme brief may DOWNGRADE a VRT priority for likelihood or
impact (scripts/BUGCROWD.md line 254). The taxonomy priority is a CEILING, not a promise, so read the
brief too. And 86 leaves carry priority null, meaning Bugcrowd sets it per submission - those are
NOT automatically P3+, so --check returns 3 for them and a human decides.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "vrt.json")


def load():
    if not os.path.exists(DATA):
        sys.exit("missing %s - refresh it from the taxonomy repo (see this file's docstring)" % DATA)
    with open(DATA) as fh:
        return json.load(fh)


def walk(nodes, path=""):
    """Yield (dotted_id, name, priority, is_leaf) for every node."""
    for n in nodes or []:
        nid = n.get("id") or ""
        p = (path + "." + nid) if path else nid
        kids = n.get("children")
        yield p, n.get("name") or "", n.get("priority"), not kids
        if kids:
            for row in walk(kids, p):
                yield row


def table():
    doc = load()
    return list(walk(doc.get("content") or []))


def resolve(vrt_id):
    for p, name, prio, leaf in table():
        if p == vrt_id:
            return {"id": p, "name": name, "priority": prio, "leaf": leaf}
    return None


def verdict(prio):
    if prio in (1, 2, 3):
        return "FILABLE on Bugcrowd (P%d)" % prio
    if prio in (4, 5):
        return ("DO NOT FILE (P%d). Below the P3 floor - this is raw material. Escalate it, or park "
                "it in reports/leads/ with an ESCALATION TARGET line." % prio)
    return ("VARIES (priority null) - Bugcrowd sets this per submission, so it is NOT automatically "
            "P3+. Decide by the captured impact and say so in the report.")


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)

    if args[0] == "--levels":
        from collections import Counter
        c = Counter(prio for _, _, prio, leaf in table() if leaf)
        for k in (1, 2, 3, 4, 5, None):
            print("  P%-5s %d leaves" % (k if k else "varies", c.get(k, 0)))
        return 0

    if args[0] == "--search":
        q = " ".join(args[1:]).lower()
        if not q:
            sys.exit("usage: vrt.py --search <text>")
        hits = [(p, n, pr) for p, n, pr, leaf in table()
                if leaf and (q in p.lower() or q in (n or "").lower())]
        # best first: P1 before P5, varies last
        hits.sort(key=lambda r: (r[2] if isinstance(r[2], int) else 99))
        if not hits:
            print("no leaf matches %r" % q)
            return 1
        print("%d leaf match(es), HIGHEST PRIORITY FIRST - pick by what the finding IS, not by name:\n" % len(hits))
        for p, n, pr in hits[:40]:
            flag = "FILABLE" if pr in (1, 2, 3) else ("sub-floor" if pr in (4, 5) else "varies")
            print("  P%-6s %-9s %s\n           %s" % (pr if pr else "?", flag, n, p))
        return 0

    check = args[0] == "--check"
    vrt_id = args[1] if check else args[0]
    r = resolve(vrt_id)
    if not r:
        print("UNKNOWN VRT id: %s" % vrt_id)
        print("try: vrt.py --search <keywords>")
        return 3
    print("id       : %s" % r["id"])
    print("name     : %s" % r["name"])
    print("priority : %s" % ("P%d" % r["priority"] if isinstance(r["priority"], int) else "varies (null)"))
    print("leaf     : %s" % r["leaf"])
    print("verdict  : %s" % verdict(r["priority"]))
    if not r["leaf"]:
        print("NOTE     : this is a PARENT node. Bugcrowd wants a leaf - run --search and pick one.")
    if check:
        if r["priority"] in (1, 2, 3):
            return 0
        return 2 if r["priority"] in (4, 5) else 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
