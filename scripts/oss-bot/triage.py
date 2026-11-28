#!/usr/bin/env python3
"""oss-bot lead triage - cull the open-lead pile, rank what survives into a worklist. Deterministic, no LLM.

    triage.py                 dry run: what would be culled, top of the worklist
    triage.py --apply         apply the culls, write worklist.json + triage.json, re-render every SEEDS.md
    triage.py --apply --quiet one JSON summary line (what orch-bot calls)
    triage.py --undo          restore every auto-culled lead to open (manual marks are never touched)
    triage.py --selftest      offline: path rules, cluster, flood (captures exempt), network-first ranking

Why (2026-10-21): 1079 open leads, 1001 of them gitleaks hits in vandelay source clones, 967 in
tests/data/hpke-vectors and parser fixtures. Nobody can work that pile, so the few real seeds drown.

Culls set `suppressed` (the column every open-lead query already excludes) and mark_note 'auto-triage <ts> <why>'.
`state` stays LEAD and the score is kept, so --undo is exact:
  1 path context  secret hit in a test / fixture / vector / example / doc / vendored path (ingest.path_context)
  2 file cluster  more than CLUSTER hits of one rule in ONE file: keep the top-scored one open
  3 rule flood    more than FLOOD open hits of a LOW_PRECISION rule in one program: keep the top KEEP open
                  (never applied to our own captures of target responses: hunts/*/raw, evidence/)
Survivors go to worklist.json, network leads first (a host: the orch brain may follow_up_lane them, GET-only and
scope-gated), then secret leads (a file to read in context; never use a found credential without the user).
Every row stays a LEAD: a scanner hit is never a finding and scanner silence is never a negative.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from bbtools import lib_scope  # noqa: E402
import ingest  # noqa: E402

ROOT = lib_scope.WS_ROOT
SD = ingest.state_dir(ROOT)
WORKLIST = os.path.join(SD, "worklist.json")
TRIAGE_STATE = os.path.join(SD, "triage.json")
CLUSTER = 5
FLOOD = 25
KEEP = 10
LOW_PRECISION = {"generic-api-key", "generic", "high-entropy", "URI"}


def _write(path, text):
    """Atomic write inside the oss-bot state dir only (the same place ingest.guard allows for state files)."""
    rp = os.path.realpath(path)
    if not rp.startswith(os.path.realpath(SD) + os.sep):
        raise SystemExit(f"refusing to write outside {SD}: {path}")
    with open(rp + ".tmp", "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(rp + ".tmp", rp)


def plan(rows):
    """rows: (fp, program, tool, rule, severity, host, url, score, first_seen). -> (cull {fp: why}, survivors)."""
    cull = {}
    for fp, p, tool, rule, sev, host, url, sc, fs in rows:
        ctx = ingest.path_context(url) if tool in ingest.SECRET_TOOLS else None
        if ctx:
            cull[fp] = ctx
    left = [r for r in rows if r[0] not in cull]
    groups = {}
    for r in left:
        if r[2] in ingest.SECRET_TOOLS:
            groups.setdefault((r[1], r[2], r[3], str(r[6] or "").split(":")[0]), []).append(r)
    for (p, tool, rule, f), g in groups.items():
        if len(g) > CLUSTER:
            for r in sorted(g, key=lambda x: -(x[7] or 0))[1:]:
                cull[r[0]] = f"cluster {len(g)} x {rule} in {f[-80:]}"
    left = [r for r in rows if r[0] not in cull]
    flood = {}
    for r in left:
        # a hit inside a response WE captured from the target (hunts/*/raw, evidence/) is where a real leak shows up:
        # never bulk-cull it (the 2026-10-21 dry run would have culled program-76 actuator /env captures at random)
        if r[3] in LOW_PRECISION and not ("/hunts/" in str(r[6]) or "/evidence/" in str(r[6])):
            flood.setdefault((r[1], r[3]), []).append(r)
    for (p, rule), g in flood.items():
        if len(g) > FLOOD:
            for r in sorted(g, key=lambda x: (-(x[7] or 0), -(x[8] or 0)))[KEEP:]:
                cull[r[0]] = f"rule-flood {len(g)} x {rule}"
    return cull, [r for r in rows if r[0] not in cull]


def worklist(left):
    work = sorted(left, key=lambda r: (0 if r[5] else 1, -(r[7] or 0), -(r[8] or 0)))
    return [{"fp": r[0], "program": r[1], "tool": r[2], "rule": r[3], "severity": r[4], "host": r[5], "url": r[6],
             "score": r[7], "kind": "network" if r[5] else "secret",
             "work": (f"follow_up_lane: GET-verify {r[6]} by hand (scanner LEAD, never a finding)" if r[5] else
                      f"read {r[6]} in its file context: a live credential of {r[1]} or a placeholder? then "
                      "`bot.py mark <fp> fp|dupe|verified-elsewhere`; never use a found credential without the user")}
            for r in work]


def selftest():
    pc = ingest.path_context
    cases = {"tests/data/hpke-vectors/v.json": "test-path", "internal/utils/fixtures/parser/x.json": "test-path",
             "a/conftest.py": "test-path", "README.md": "doc-path", "node_modules/x/y.js": "vendored",
             "src/config/prod.env": None, "app/settings.py": None, "keys.txt": None, "src/latest.js": None,
             "targets/p/hunts/lane/raw/x.resp": None, "targets/p/hunts/tests/raw/x.resp": None,
             "src/arc-node/Cargo.lock": "lockfile", "x/uv.lock": "lockfile", "b/CMakeFiles/c.dir/a.cpp.o": "build-artifact",
             "r/.git/objects/pack/p.promisor": "build-artifact", "targets/p/recon/js/app.js.map": None,
             "targets/p/recon/js/dist/app.js": None,
             "targets/p/hunts/auto-exposure/raw/github.com-act-env.resp": "third-party-capture",
             "targets/p/hunts/auto-exposure/raw/greynocresearchabbp.1password.com-js5.js": "own-account",
             "targets/p/hunts/auto-exposure/raw/status.arc.io-ctl-root.resp": None,
             "targets/v/hunts/auto-exposure/raw/gnoc-a-victim-grey-noc.vercel.app-boot1-env.resp": "own-account",
             "targets/c/hunts/auto-exposure/raw/app-sandbox.circle.com-act.resp": None,
             "targets/c/hunts/auto-exposure/raw/raw.githubusercontent.com-x.resp": "third-party-capture"}
    for path, want in cases.items():
        assert pc(path) == want, (path, pc(path), want)

    def row(i, rule, url, sc=4.0, tool="gitleaks", host=""):
        return (f"f{i}", "p", tool, rule, "medium", host, url, sc, i)

    rows = [row(i, "generic-api-key", "tests/v.json") for i in range(3)]                  # path context
    rows += [row(10 + i, "aws-access-token", "src/a.py", sc=4.0 + i) for i in range(8)]   # one-file cluster of 8
    rows += [row(100 + i, "generic-api-key", f"src/f{i}.py") for i in range(30)]          # rule flood of 30
    rows += [row(200 + i, "generic-api-key", f"targets/p/hunts/l/raw/{i}.resp") for i in range(30)]  # captures: exempt
    rows += [row(300, "exposed-env", "scheme://selftest-host/.env", 9.0, "nuclei", "selftest-host")]  # network lead
    cull, left = plan(rows)
    assert all(cull[f"f{i}"] == "test-path" for i in range(3))
    assert "f17" not in cull and all(cull[f"f{10 + i}"].startswith("cluster") for i in range(7)), "cluster keeps the top"
    assert sum(1 for i in range(30) if f"f{100 + i}" not in cull) == KEEP, "flood keeps KEEP"
    assert not any(f"f{200 + i}" in cull for i in range(30)), "captured responses never flood-culled"
    wl = worklist(left)
    assert wl[0]["kind"] == "network" and wl[0]["fp"] == "f300", "network leads first"
    print(f"triage selftest: PASS ({len(cases)} path cases, cull {len(cull)} of {len(rows)}, network first)")
    return 0


def main(a):
    if "-h" in a or "--help" in a:
        print(__doc__)
        return 0
    if "--selftest" in a:
        return selftest()
    con = ingest.db_connect(ROOT)
    if "--undo" in a:
        n = con.execute("UPDATE leads SET suppressed=NULL, mark_note=NULL WHERE mark_note LIKE 'auto-triage %'").rowcount
        con.commit()
        for (p,) in con.execute("SELECT DISTINCT program FROM leads").fetchall():
            ingest.render_seeds(p, ROOT, con)
        con.close()
        print(f"triage undo: {n} leads restored to open")
        return 0
    rows = con.execute("SELECT fp,program,tool,rule,severity,host,url,score,first_seen FROM leads WHERE state='LEAD' "
                       "AND (suppressed IS NULL OR suppressed='')").fetchall()
    cull, left = plan(rows)
    wl = worklist(left)
    why = {}
    for v in cull.values():
        why[v.split(" ")[0]] = why.get(v.split(" ")[0], 0) + 1
    by_prog = {}
    for w in wl:
        by_prog[w["program"]] = by_prog.get(w["program"], 0) + 1
    apply = "--apply" in a
    summary = {"ts": ingest._iso(), "applied": apply, "open_before": len(rows), "culled": len(cull), "by_reason": why,
               "open_after": len(left), "network_open": sum(1 for w in wl if w["kind"] == "network"),
               "secret_open": sum(1 for w in wl if w["kind"] == "secret"), "by_program": by_prog}
    if apply:
        stamp = summary["ts"]
        con.executemany("UPDATE leads SET suppressed=?, mark_note=? WHERE fp=? AND state='LEAD' "
                        "AND (suppressed IS NULL OR suppressed='')",
                        [(v.split(" ")[0][:40], f"auto-triage {stamp} {v}"[:300], fp) for fp, v in cull.items()])
        con.commit()
        for p in sorted({r[1] for r in rows}):
            ingest.render_seeds(p, ROOT, con)
        _write(WORKLIST, json.dumps({"ts": stamp, "items": wl[:500]}, indent=1) + "\n")
        _write(TRIAGE_STATE, json.dumps(summary, indent=1) + "\n")
    con.close()
    if "--quiet" in a:
        print(json.dumps(summary))
        return 0
    print(f"triage {'APPLIED' if apply else 'DRY (add --apply)'}: open {len(rows)} -> {len(left)}, culled {len(cull)} "
          f"{json.dumps(why)}; worklist {summary['network_open']} network + {summary['secret_open']} secret")
    for w in wl[:15]:
        print(f"  {w['score']:>5}  {w['program']:<18} {w['tool']:<10} {w['rule'][:24]:<24} {(w['host'] or w['url'])[:70]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
