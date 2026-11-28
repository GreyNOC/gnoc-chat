#!/usr/bin/env python3
"""ship-pipeline.py - run a draft through every pre-filing gate without an orchestrator.

  ship-pipeline.py <draft-dir> [--llm] [--force] [--model-killer opus] [--model-repro sonnet]
  ship-pipeline.py <draft-dir> --fix [--llm] [--rounds 2] [--model-writer sonnet]
                                          on failure, a headless report-writer repairs the text
                                          (no new probes) and the gates re-run, up to N rounds
  ship-pipeline.py --all [--llm] [--live]          drafts changed in the last 48h (not HELD)
  ship-pipeline.py --watch [secs] [--llm] [--live] loop --all forever (default every 300s)
  Batch and watch modes NEVER run a draft's live repro.sh unless --live is given: they run
  outside the scope-gate hook, and old drafts point at programs whose scope may have changed.

Stages, in order. The LOCAL stages cost no model tokens; the LLM stages run only with --llm,
only after every local stage passes, and only when the draft bytes changed since their last
verdict (each stage is cached on a hash of the files it reads):

  0 selfdup   scripts/h1-selfdup.py: did WE already file this? (H1 API read-only, fails closed)
  1 qaqc      scripts/qaqc.sh <program>/<slug>                         (local)
  2 slop      scripts/slop-gate.py report.md --evidence evidence/      (local)
  3 notes     scripts/submit-qaqc.py report.md  (severity-only refusal is advisory, 5b floor) (local)
  4 repro     run repro.sh once as shipped -> REPRO-RUN-auto.txt       (local, live GETs)
  5 panels    panels/BURP-INDEX.txt plus >= 2 PNGs                     (local)
  6 killer    headless report-killer -> KILLPASS-auto.txt, needs PASS  (LLM)
  7 reprochk  headless report-repro-checker -> REPRO-CHECK-auto.txt, needs REPRODUCES (LLM)
  8 dryrun    scripts/h1-submit-report.py <program> report.md --dry-run (local, H1 API read-only)

Output: <draft>/PIPELINE.md (one line per stage + the blockers) and <draft>/.pipeline.json
(the cache). Exit 0 only when every stage passed: the draft is READY TO FILE. Nothing here
ever files a report; filing stays `gnoc submit <dir> --send`, by hand.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
import paid_budget  # noqa: E402
import gnoc_finding  # noqa: E402  (T1.5/T1.6: layer verdicts in finding.json, the evidence manifest)
DRAFTS = os.path.join(WS, "reports/drafts")
LOCAL = ["selfdup", "qaqc", "slop", "notes", "repro", "panels"]
LLM = ["killer", "reprochk"]
ORDER = LOCAL + LLM + ["dryrun"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(paths):
    h = hashlib.sha256()
    for p in paths:
        if os.path.isdir(p):
            for dp, dn, fn in sorted(os.walk(p)):
                dn.sort()
                for f in sorted(fn):
                    fp = os.path.join(dp, f)
                    h.update(fp.encode())
                    h.update(str(os.path.getsize(fp)).encode())
                    h.update(str(int(os.path.getmtime(fp))).encode())
        elif os.path.isfile(p):
            h.update(p.encode())
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()[:16]


def run(cmd, cwd=WS, timeout=600, env=None):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, **(env or {})), stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return 127, str(e)


def tail(text, n=6):
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return " | ".join(l.strip()[:160] for l in lines[-n:])


class Draft:
    def __init__(self, path):
        self.dir = os.path.abspath(path)
        rel = os.path.relpath(self.dir, DRAFTS).split(os.sep)
        if len(rel) != 2 or rel[0] == "..":
            sys.exit(f"not a draft dir (reports/drafts/<program>/<slug>): {path}")
        self.program, self.slug = rel
        self.report = os.path.join(self.dir, "report.md")
        if not os.path.isfile(self.report):
            sys.exit(f"no report.md in {self.dir}")
        self.cache_path = os.path.join(self.dir, ".pipeline.json")
        try:
            self.cache = json.load(open(self.cache_path))
        except (OSError, ValueError):
            self.cache = {}

    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def inputs(self, stage):
        core = [self.report, self.p("repro.sh"), self.p("capture.log")]
        return {
            "selfdup": [self.report, self.p("SELF-DUP-OK.txt"), os.path.join(WS, ".claude/state/h1-self/my-reports.json")],
            "qaqc": core + [self.p("FORM.md"), self.p("GATES.md")],
            "slop": core + [self.p("evidence")],
            "notes": [self.report],
            "repro": [self.p("repro.sh")],
            "panels": [self.p("panels")],
            "killer": [self.report],
            "reprochk": core + [self.p("evidence")],
            "dryrun": [self.report],
        }[stage]

    def save(self):
        with open(self.cache_path, "w") as f:
            json.dump(self.cache, f, indent=1)


# ---------- stages: each returns (ok, note) ----------

def st_selfdup(d):
    # our own filed reports on this program, via the H1 Hacker API (read-only); fail closed if unreadable
    rc, out = run([sys.executable, os.path.join(WS, "scripts/h1-selfdup.py"), d.dir, "--program", d.program], timeout=180)
    first = out.strip().splitlines()[0] if out.strip() else f"rc={rc}"
    ids = re.findall(r"#(\d{6,})", out)
    return rc == 0, first[:120] + (f"  matches: {', '.join(sorted(set(ids)))}" if ids else "")


def st_qaqc(d):
    rc, out = run([os.path.join(WS, "scripts/qaqc.sh"), f"{d.program}/{d.slug}"])
    fails = [l.strip() for l in out.splitlines() if l.strip().startswith("FAIL")]
    return rc == 0, "; ".join(fails)[:400] or tail(out, 2)


def st_slop(d):
    cmd = [sys.executable, os.path.join(WS, "scripts/slop-gate.py"), d.report, "--program", d.program]
    if os.path.isdir(d.p("evidence")):
        cmd += ["--evidence", d.p("evidence")]
    rc, out = run(cmd)
    return rc == 0, tail(out, 4)


STRIP_RE = re.compile(r"^\s*(Gate:|Dedup:|ESCALATION TARGET:|\*\*Unlock:)")


def st_notes(d):
    # check what the submitter actually sends: it strips Gate:/Dedup:/escalation lines first
    clean = d.p(".report.submitted-view.md")
    with open(d.report) as f, open(clean, "w") as g:
        g.writelines(l for l in f if not STRIP_RE.match(l))
    rc, out = run([sys.executable, os.path.join(WS, "scripts/submit-qaqc.py"), clean])
    if rc == 0:
        return True, "clean"
    blockers = [l for l in out.splitlines() if re.search(r"FAIL|INTERNAL|SLOP", l)
                and not l.strip().startswith("BLOCKED:")]  # the summary line is not a blocker of its own
    severity_only = blockers and all(re.search(r"severity|cvss|7\.0|HIGH or CRITICAL", l, re.I) for l in blockers)
    if severity_only:  # GreyNOC 2026-10-19: Mediums with CIA impact are filable; the dry run passes --skip-qaqc-severity-only
        return True, "severity-only refusal (advisory under the 2026-10-19 floor)"
    return False, tail(out, 4)


def st_repro(d):
    rs = d.p("repro.sh")
    if not os.path.isfile(rs):
        return False, "no repro.sh"
    rc, out = run(["bash", rs], cwd=d.dir, timeout=900, env={"HUNT_TARGET": d.program})
    with open(d.p("REPRO-RUN-auto.txt"), "w") as f:
        f.write(f"# repro.sh run as shipped {now()} rc={rc}\n{out}")
    bad = re.search(r"MISMATCH|NOT FOUND|FAIL|Traceback", out)
    return rc == 0 and not bad, f"rc={rc} " + tail(out, 3)


def st_panels(d):
    """Raw Burp panels are mandatory on every filing (the user 2026-10-19, SPINE 5): BURP-INDEX.txt present, at least two
    PNGs, every PNG the index names exists on disk, and the report's Attachments section names the panels."""
    pdir = d.p("panels")
    pngs = {f for dp, dn, fn in os.walk(pdir) for f in fn if f.lower().endswith(".png")} if os.path.isdir(pdir) else set()
    idx_path = os.path.join(pdir, "BURP-INDEX.txt")
    idx = open(idx_path, encoding="utf-8", errors="replace").read() if os.path.isfile(idx_path) else ""
    named = set(re.findall(r"[\w.-]+\.png", idx))
    missing = sorted(named - pngs)
    rep = open(d.report, encoding="utf-8", errors="replace").read()
    att = rep[rep.lower().rfind("attachment"):] if "attachment" in rep.lower() else ""
    cited = bool(re.search(r"burp[\w.-]*\.png|burp panel", att, re.I))
    ok = bool(idx) and len(pngs) >= 2 and not missing and cited
    why = [f"BURP-INDEX={'yes' if idx else 'NO'}", f"pngs={len(pngs)}"]
    if missing:
        why.append(f"index names missing PNGs: {', '.join(missing[:4])}")
    if not cited:
        why.append("Attachments does not name the Burp panels")
    # T1.6: the evidence manifest (distinct, real PNGs in request+response pairs; bytes unchanged since the snapshot).
    # advisory (default): the problems ride on the note, the verdict is unchanged. enforce: any problem fails.
    mode = gnoc_finding.gate_mode()
    if mode != "off":
        try:
            probs = gnoc_finding.manifest_check(d.dir)
        except Exception as e:  # noqa: BLE001
            probs = [f"manifest check failed: {type(e).__name__}: {e}"]
        if probs:
            why.append(f"manifest[{mode}] {len(probs)}: {probs[0][:160]}")
            if mode == "enforce":
                ok = False
    return ok, " ".join(why)


def record_layer(d, stage, ok, note, h, model=None):
    """T1.5: append this stage's verdict to finding.json (append-only). Only when the stage actually RAN, so a
    cached verdict is not re-recorded every watch tick. Never breaks the pipeline."""
    try:
        verdict = "pass" if ok else ("skip" if "PAID-CAP" in str(note) else "reject")
        by = model or "code:ship-pipeline"
        gnoc_finding.append_layer(d.dir, stage, verdict, str(note)[:300], by=by,
                                  family=gnoc_finding.family_of(by), input_sha256=h)
    except Exception:  # noqa: BLE001
        pass


def headless(agent, model, prompt, out_file, d):
    # per-run caps: 25 turns, 15 min wall-clock; monthly paid-run ceiling counted before dispatch
    cmd = ["claude", "-p", prompt, "--agent", agent, "--model", model,
           "--permission-mode", "bypassPermissions", "--output-format", "text", "--max-turns", "25"]
    okb, _runs, bcap = paid_budget.reserve(WS, f"{agent} {d.program}/{d.slug}")
    if not okb:
        return 125, f"PAID-CAP: monthly paid-run cap {bcap} reached, {agent} not run"
    rc, out = run(cmd, timeout=900, env={"HUNT_TARGET": d.program})
    if rc == 124:
        paid_budget.inbox(WS, "PAID-CAPPED", f"{agent} on {d.program}/{d.slug} hit its 15m wall-clock cap")
    with open(out_file, "w") as f:
        f.write(f"# {agent} ({model}) {now()} rc={rc}\n{out}")
    return rc, out


def st_killer(d, model):
    view = d.p(".report.submitted-view.md")  # what H1 would actually receive (Gate:/Dedup: lines stripped)
    if not os.path.isfile(view):
        st_notes(d)
    prompt = (f"Kill pass on {view} (the exact text HackerOne will receive; internal header lines were already "
              "stripped by the submitter). You receive ONLY that file, targets/{d.program}/SCOPE.txt and "
              f"targets/{d.program}/PROGRAM.md. Do not read hunt STATUS files or transcripts. Run your rounds and end "
              "with exactly one line 'VERDICT: PASS' or 'VERDICT: KILL' or 'VERDICT: KILL-PENDING' followed by the "
              "required edits. Do not edit any file.")
    rc, out = headless("report-killer", model, prompt, d.p("KILLPASS-auto.txt"), d)
    m = re.findall(r"VERDICT:\s*(KILL-PENDING|KILL|PASS)", out)
    v = m[-1] if m else "NO-VERDICT"
    if rc == 125:
        return False, out  # PAID-CAP: not cached, retried next tick
    return v == "PASS", f"{v} (KILLPASS-auto.txt)"


def st_reprochk(d, model):
    prompt = (f"Post-write repro gate for {d.dir}. Read report.md as a zero-context triager per "
              "reports/REPORT-FORMAT.md, extract-and-diff every quoted byte against capture.log and evidence/. "
              "Do not run repro.sh (it was just run; its output is REPRO-RUN-auto.txt in that dir). Do not edit "
              "report.md. End with exactly one line 'VERDICT: REPRODUCES' or 'VERDICT: NOT-REPRODUCES' and the gaps.")
    rc, out = headless("report-repro-checker", model, prompt, d.p("REPRO-CHECK-auto.txt"), d)
    m = re.findall(r"VERDICT:\s*(NOT-REPRODUCES|REPRODUCES)", out)
    v = m[-1] if m else "NO-VERDICT"
    if rc == 125:
        return False, out
    return v == "REPRODUCES", f"{v} (REPRO-CHECK-auto.txt)"


def st_dryrun(d):
    rc, out = run([sys.executable, os.path.join(WS, "scripts/h1-submit-report.py"), d.program, d.report,
                   "--dry-run", "--skip-qaqc-severity-only"], timeout=120)
    with open(d.p("DRYRUN-auto.txt"), "w") as f:
        f.write(f"# h1 dry run {now()} rc={rc}\n{out}")
    refuse = re.search(r"QAQC would REFUSE|ABORT", out)
    keep = [l for l in out.splitlines() if l.startswith("== ") and not l.startswith("== DRY RUN payload")]
    return rc == 0 and not refuse, " | ".join(k[3:90] for k in keep[-3:]) or tail(out, 2)


# ---------- driver ----------

def pipeline(path, llm=False, force=False, mk="opus", mr="sonnet", quiet=False, live=True):
    d = Draft(path)
    results = {}
    blocked = False
    for stage in ORDER:
        if stage in LLM and not llm:
            prev = d.cache.get(stage)
            if prev and prev.get("ok") and prev.get("hash") == digest(d.inputs(stage) + [os.path.abspath(__file__)]):
                results[stage] = ("PASS", prev["note"] + " (cached LLM verdict, bytes unchanged)")
            else:
                results[stage] = ("SKIP", "LLM gates off (add --llm); no cached PASS on these bytes")
            continue
        if stage == "repro" and not live:
            results[stage] = ("SKIP", "live repro off in batch/watch mode (add --live)")
            continue
        if blocked and stage in LLM + ["dryrun"]:
            results[stage] = ("WAIT", "an earlier stage failed")
            continue
        h = digest(d.inputs(stage) + [os.path.abspath(__file__)])  # a gate change re-runs its stage
        prev = d.cache.get(stage)
        if prev and prev.get("hash") == h and not force and stage != "repro":
            ok, note = prev["ok"], prev["note"] + " (cached)"
        elif prev and stage == "repro" and prev.get("hash") == h and not force \
                and time.time() - prev.get("at", 0) < 6 * 3600:
            ok, note = prev["ok"], prev["note"] + " (cached <6h)"  # live leg: re-fire at most every 6h
        else:
            if not quiet:
                print(f"  .. {stage}", flush=True)
            fn = globals()["st_" + stage]
            ok, note = fn(d, mk) if stage == "killer" else fn(d, mr) if stage == "reprochk" else fn(d)
            if "PAID-CAP" not in str(note):
                d.cache[stage] = {"hash": h, "ok": ok, "note": note, "at": time.time()}
                d.save()
            record_layer(d, stage, ok, note, h, mk if stage == "killer" else mr if stage == "reprochk" else None)
        results[stage] = ("PASS" if ok else "FAIL", note)
        if not ok and stage not in ("panels",):  # panels are captured separately; they never block the text gates
            blocked = True
    ready = all(results[s][0] == "PASS" for s in ORDER if not (s == "repro" and not live)) and live
    lines = [f"# PIPELINE {d.program}/{d.slug}", f"run {now()}  verdict: "
             + ("READY TO FILE (file by hand: gnoc submit <dir> --send)" if ready else
                "NOT READY" if any(v[0] == "FAIL" for v in results.values()) else "LOCAL GATES PASS, LLM GATES PENDING"), ""]
    for s in ORDER:
        st, note = results[s]
        lines.append(f"- {st:<4} {s:<9} {note}")
    if ready:  # a READY draft always has its vendor-facing zip next to it
        rc, out = run([sys.executable, os.path.join(WS, "scripts/bundle-report.py"), d.dir])
        lines.append(f"- bundle   {(out.strip().splitlines() or ['?'])[0]}")
    with open(d.p("PIPELINE.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    if not quiet:
        print("\n".join(lines))
    return ready


FIXABLE = {"qaqc", "slop", "notes", "killer", "reprochk", "dryrun"}


def autofix(path, model):
    """Hand the current blockers to a headless report-writer: text edits from captured bytes only."""
    d = Draft(path)
    blockers = open(d.p("PIPELINE.md")).read()
    side = [f for f in ("KILLPASS-auto.txt", "REPRO-CHECK-auto.txt", "REPRO-RUN-auto.txt", "DRYRUN-auto.txt")
            if os.path.isfile(d.p(f))]
    prompt = (f"Repair the draft in {d.dir} so it passes the pre-filing gates. The gate results are below; the "
              f"side files {side} in that dir hold the details. Rules: TEXT EDITS ONLY to report.md, capture.log, "
              "FORM.md, GATES.md and repro.sh; every quoted byte must come verbatim from a file in evidence/ or the "
              "hunt raw/ dir it was copied from (copy any newly cited file into evidence/); never invent, retype or "
              "edit a captured byte; fire NO new network requests; keep Summary and Impact <=35 words; no em dash; "
              "keep the Dedup:/Gate: header lines; if FORM.md is missing create it with Title, Asset, CWE, CVSS taken "
              "from the report header. If the CAPABILITY+TERMINAL gate refuses, name the capability the evidence "
              "actually captured in the Impact text in plain words; never overstate it. Do not touch panels/. "
              "Finish with a 5-line summary of what you changed and anything you could not fix.\n\n" + blockers)
    rc, out = headless("report-writer-agent", model, prompt, d.p("AUTOFIX-auto.txt"), d)
    return rc == 0


def changed_drafts(max_age_h=48):
    out = []
    cutoff = time.time() - max_age_h * 3600
    for prog in sorted(os.listdir(DRAFTS)):
        pd = os.path.join(DRAFTS, prog)
        if not os.path.isdir(pd):
            continue
        for slug in sorted(os.listdir(pd)):
            dd = os.path.join(pd, slug)
            rep = os.path.join(dd, "report.md")
            if not os.path.isfile(rep) or os.path.isfile(os.path.join(dd, "HELD-REASON.md")):
                continue
            if os.path.getmtime(rep) < cutoff:  # old drafts are not re-gated (and never re-fired) by a sweep
                continue
            pl = os.path.join(dd, "PIPELINE.md")
            if not os.path.isfile(pl) or os.path.getmtime(rep) > os.path.getmtime(pl):
                out.append(dd)
    return out


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    llm = "--llm" in argv
    force = "--force" in argv
    mk = argv[argv.index("--model-killer") + 1] if "--model-killer" in argv else "opus"
    mr = argv[argv.index("--model-repro") + 1] if "--model-repro" in argv else "sonnet"
    live = "--live" in argv  # batch and watch never fire a draft's live repro.sh unless asked
    if argv[0] == "--all":
        todo = changed_drafts()
        print(f"{len(todo)} changed draft(s) touched in the last 48h")
        for dd in todo:
            pipeline(dd, llm, force, mk, mr, live=live)
        return 0
    if argv[0] == "--watch":
        secs = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 300
        while True:
            for dd in changed_drafts():
                print(f"[{now()}] {os.path.relpath(dd, DRAFTS)}", flush=True)
                pipeline(dd, llm, force, mk, mr, quiet=True, live=live)
            time.sleep(secs)
    if "--fix" in argv:
        rounds = int(argv[argv.index("--rounds") + 1]) if "--rounds" in argv else 2
        mw = argv[argv.index("--model-writer") + 1] if "--model-writer" in argv else "sonnet"
        for i in range(rounds + 1):
            if pipeline(argv[0], llm, force, mk, mr):
                return 0
            res = json.load(open(os.path.join(os.path.abspath(argv[0]), ".pipeline.json")))
            failing = {k for k, v in res.items() if not v.get("ok")}
            if i == rounds or not (failing & FIXABLE):
                print(f"stopping: failing stages {sorted(failing)} " +
                      ("need a human or a capture worker" if not failing & FIXABLE else f"after {rounds} fix rounds"))
                return 1
            print(f"== autofix round {i + 1}/{rounds} ({mw}) for {sorted(failing & FIXABLE)}", flush=True)
            autofix(argv[0], mw)
        return 1
    return 0 if pipeline(argv[0], llm, force, mk, mr) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
