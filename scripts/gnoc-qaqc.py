#!/usr/bin/env python3
"""gnoc-qaqc - one-command QA/QC battery for the gnoc chat harness (scripts/gnoc + scripts/gnoc_*.py).

    scripts/gnoc-qaqc.py            run everything, exit 1 on any hard failure
    scripts/gnoc-qaqc.py --quick    skip the unit tests (parse + lint + import + registry audit only)
    scripts/gnoc-qaqc.py --json     machine-readable summary on stdout

Stages (each independent, all reported):
  parse     every gnoc module compiles (a half-saved edit from another session shows up here first)
  lint      pyflakes: undefined names are HARD failures, unused imports are warnings (pyflakes optional)
  import    every gnoc_*.py imports cleanly (import-time side effects / missing deps)
  registry  gnoc_agent.TOOLS: schema <-> function signature agreement (a mismatch is a TypeError at
            call time that the model sees as "bad arguments"), required params exposed, approval slot present,
            WORKER_TOOLS subset of TOOLS, lead-only tools never in WORKER_TOOLS
  tests     scripts/test_gnoc_agent.py (+ the other test_gnoc_*.py), stdlib unittest
  functional (--functional only, ~30s) CALL every registered tool with safe arguments and judge the answer.
            The stages above never call a tool, so a tool can be registered, documented and broken with every
            one of them green: that is how four real defects survived a PASS on 2026-10-31.

Run it after pulling another session's changes, before committing, and whenever `gnoc chat` misbehaves.
"""
import argparse
import ast
import glob
import importlib
import inspect
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

LEAD_ONLY = ("set_program", "pick_target", "write_file", "edit_file", "bash", "desktop", "scan", "claude_worker",
             "fan_out", "delegate", "ship_chain", "draft_outgoing")


def modules():
    files = [os.path.join(HERE, "gnoc")] + sorted(glob.glob(os.path.join(HERE, "gnoc_*.py")))
    return [f for f in files if os.path.isfile(f) and not f.endswith(".bak")]


def stage_parse(rep):
    bad = []
    for f in modules():
        try:
            with open(f, encoding="utf-8") as fh:
                ast.parse(fh.read(), filename=f)
        except SyntaxError as e:
            bad.append(f"{os.path.basename(f)}:{e.lineno}: {e.msg}")
    rep["parse"] = {"ok": not bad, "errors": bad, "n": len(modules())}


def stage_lint(rep):
    try:
        import pyflakes.api  # noqa: F401
    except ImportError:
        rep["lint"] = {"ok": True, "skipped": "pyflakes not installed (pip install pyflakes --break-system-packages)"}
        return
    r = subprocess.run([sys.executable, "-m", "pyflakes"] + modules(), capture_output=True, text=True)
    hard, soft = [], []
    for ln in (r.stdout + r.stderr).splitlines():
        ln = ln.replace(HERE + os.sep, "")
        if "undefined name" in ln or "invalid syntax" in ln or "f-string" in ln:
            hard.append(ln)
        elif ln.strip():
            soft.append(ln)
    rep["lint"] = {"ok": not hard, "hard": hard, "warnings": soft}


def stage_import(rep):
    bad = []
    for f in modules():
        name = os.path.basename(f)
        if name == "gnoc":
            continue  # the CLI runs main() at import; the modules are what gnoc chat imports
        mod = name[:-3]
        try:
            importlib.import_module(mod)
        except Exception as e:  # noqa: BLE001 - any import-time failure is the finding
            bad.append(f"{name}: {type(e).__name__}: {e}")
    rep["import"] = {"ok": not bad, "errors": bad}


def stage_registry(rep):
    problems = []
    try:
        import gnoc_agent as G
    except Exception as e:  # noqa: BLE001
        rep["registry"] = {"ok": False, "problems": [f"cannot import gnoc_agent: {e}"]}
        return
    for name, entry in G.TOOLS.items():
        if len(entry) < 3:
            problems.append(f"{name}: tuple has no approval slot")
        impl, schema = entry[0], entry[1]
        fn = schema.get("function", schema)
        params = fn.get("parameters") or {}
        props = set((params.get("properties") or {}).keys())
        required = list(params.get("required") or [])
        sig = inspect.signature(impl)
        kw = any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values())
        fnames = [p for p in sig.parameters if p != "ctx"]
        req_fn = [p for p, v in sig.parameters.items() if p != "ctx" and v.default is inspect._empty
                  and v.kind in (v.POSITIONAL_OR_KEYWORD, v.KEYWORD_ONLY)]
        if fn.get("name") != name:
            problems.append(f"{name}: schema name is {fn.get('name')!r}")
        if "ctx" not in sig.parameters:
            problems.append(f"{name}: {impl.__name__} has no ctx parameter")
        for p in props:
            if p not in fnames and not kw:
                problems.append(f"{name}: schema param {p!r} not accepted by {impl.__name__}{sig}")
        for r in required:
            if r not in props:
                problems.append(f"{name}: required {r!r} missing from properties")
        for r in req_fn:
            if r not in props:
                problems.append(f"{name}: function requires {r!r} but the schema never exposes it")
            elif r not in required:
                problems.append(f"{name}: function requires {r!r} but the schema marks it optional")
    for w in G.WORKER_TOOLS:
        if w not in G.TOOLS:
            problems.append(f"WORKER_TOOLS names unknown tool {w!r}")
    for t in LEAD_ONLY:
        if t in G.TOOLS and t in G.WORKER_TOOLS:
            problems.append(f"lead-only tool {t!r} is exposed to workers")
    rep["registry"] = {"ok": not problems, "problems": problems, "tools": len(G.TOOLS), "worker_tools": len(G.WORKER_TOOLS)}


def stage_learning(rep):
    """The recursive-learning loop: every outcome ledger an agent writes must be READ by the
    consolidator that builds the steering block. A ledger nobody reads is learning thrown away -
    exactly the split-brain found on 2026-10-22, where 890 agent outcomes fed nothing."""
    problems, info = [], {}
    ws = os.path.dirname(HERE)
    cons = os.path.join(HERE, "learn", "consolidate.py")
    ledgers = {
        "hunt-loop/outcomes.jsonl": os.path.join(ws, ".claude/state/hunt-loop/outcomes.jsonl"),
        "learning/outcomes.jsonl": os.path.join(ws, ".claude/state/learning/outcomes.jsonl"),
        "hunt-loop/ships.jsonl": os.path.join(ws, ".claude/state/hunt-loop/ships.jsonl"),
    }
    src = ""
    if os.path.isfile(cons):
        with open(cons, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
    else:
        problems.append("scripts/learn/consolidate.py missing: nothing builds the LESSONS steering block")
    now = time.time()
    for label, p in ledgers.items():
        if not os.path.isfile(p):
            info[label] = "absent"
            continue
        with open(p, encoding="utf-8", errors="replace") as fh:
            rows = [ln for ln in fh if ln.strip()]
        age_h = (now - os.path.getmtime(p)) / 3600.0
        info[label] = f"{len(rows)} rows, {age_h:.1f}h old"
        if src and label.split("/")[0] not in src and label not in src:
            problems.append(f"{label} ({len(rows)} rows) is written but consolidate.py never reads it "
                            f"-> that learning is discarded")
    # the ledgers must share one verdict vocabulary, or counts silently bucket as 'other'
    hl = ledgers["hunt-loop/outcomes.jsonl"]
    if os.path.isfile(hl):
        vs = set()
        with open(hl, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    v = json.loads(ln).get("verdict")
                except ValueError:
                    continue
                if isinstance(v, str) and len(v) < 40:
                    vs.add(v.strip().lower().split(",")[0])
        odd = sorted(v for v in vs if v and not any(
            v.startswith(k) for k in ("dead", "lead", "unfired", "needs", "win", "other",
                                      "critical-candidate", "medium-candidate", "finding-candidate",
                                      "candidate", "alive", "uncertain", "keep")))
        if odd:
            # historical rows predate the enum and cannot be rewritten, so this is a WARNING: the
            # hard gate against new ones is validate_outcome() in scripts/hunt-state.py
            info["off-vocabulary verdicts (historical)"] = f"{len(odd)} distinct, e.g. {odd[:3]}"
    rep["learning"] = {"ok": not problems, "problems": problems, "ledgers": info}


def stage_tests(rep):
    out = {}
    ok = True
    # the scope gate guards every shell probe gnoc chat makes; its false blocks and true blocks are pinned too
    for t in sorted(glob.glob(os.path.join(HERE, "test_gnoc_*.py"))) + [os.path.join(HERE, "test_scope_gate.py")]:
        t0 = time.time()
        r = subprocess.run([sys.executable, "-W", "ignore::ResourceWarning", t], capture_output=True, text=True,
                           cwd=HERE, timeout=900)
        tail = (r.stderr or r.stdout).strip().splitlines()
        summary = next((ln for ln in reversed(tail) if ln.startswith(("OK", "FAILED", "Ran "))), tail[-1] if tail else "")
        ran = next((ln for ln in tail if ln.startswith("Ran ")), "")
        fails = [ln for ln in tail if ln.startswith(("FAIL:", "ERROR:"))]
        passed = r.returncode == 0
        ok &= passed
        out[os.path.basename(t)] = {"ok": passed, "ran": ran, "summary": summary, "failures": fails[:20],
                                    "secs": round(time.time() - t0, 1)}
    rep["tests"] = {"ok": ok, "files": out}


def stage_functional(rep):
    """CALL every tool with safe arguments and judge the answer. Parse/lint/import/registry never execute a
    tool, so a tool can be registered, documented and broken (a crash on ordinary input, a guard that does not
    guard) with every other stage green. See scripts/gnoc_qaqc_func.py."""
    out = {"ok": True}
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import gnoc_qaqc_func
        rows, missing = gnoc_qaqc_func.run(verbose=False)
    except Exception as e:  # noqa: BLE001
        rep["functional"] = {"ok": False, "errors": [f"the functional battery itself failed: {type(e).__name__}: {e}"]}
        return
    bad = [r for r in rows if r["verdict"] in ("CRASH", "GUARD-HOLE", "EMPTY")]
    out["ok"] = not bad
    out["problems"] = [f"{r['verdict']} {r['tool']}: {r['detail'][:120]}" for r in bad]
    out["warnings"] = ([f"no functional case yet: {', '.join(missing)}"] if missing else []) + \
        [f"slow: {r['tool']} {r['s']}s" for r in rows if r["s"] >= gnoc_qaqc_func.SLOW_S]
    out["ledgers"] = {"tool calls": f"{len(rows)} made, {len(rows) - len(bad)} good"}
    rep["functional"] = out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--functional", action="store_true", help="also CALL every tool (slower, finds real breakage)")
    a = ap.parse_args()
    rep = {}
    stage_parse(rep)
    stage_lint(rep)
    stage_import(rep)
    stage_registry(rep)
    stage_learning(rep)
    if a.functional:
        stage_functional(rep)
    else:
        rep["functional"] = {"ok": True, "skipped": "no tool was CALLED. Run with --functional (about 30s) to "
                             "drive every tool for real: parse/lint/import/registry cannot see a tool that is "
                             "registered and broken."}
    if not a.quick:
        stage_tests(rep)
    ok = all(v.get("ok", True) for v in rep.values())
    if a.json:
        print(json.dumps({"ok": ok, **rep}, indent=1))
        return 0 if ok else 1
    for stage, v in rep.items():
        flag = "ok " if v.get("ok", True) else "FAIL"
        print(f"[{flag}] {stage}")
        if v.get("skipped"):
            print(f"       skipped: {v['skipped']}")
        for k in ("errors", "hard", "problems"):
            for ln in v.get(k) or []:
                print(f"       ! {ln}")
        for ln in (v.get("warnings") or [])[:8]:
            print(f"       ~ {ln}")
        for k, d in (v.get("ledgers") or {}).items():
            print(f"       · {k}: {d}")
        if stage == "tests":
            for f, t in v["files"].items():
                print(f"       {'ok ' if t['ok'] else 'FAIL'} {f}: {t['ran']} {t['summary']} ({t['secs']}s)")
                for ln in t["failures"]:
                    print(f"            ! {ln}")
    tail = "" if a.functional else "  (no tool was called: add --functional)"
    print("QAQC", ("PASS" if ok else "FAIL") + tail)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
