#!/usr/bin/env python3
"""final-gate.py - who runs the two final gates (kill pass + repro check): Claude, or the user's own QAQC.

  final-gate.py                         current mode and the drafts waiting at the final gate
  final-gate.py mode claude|human       claude: orch-bot runs ship-pipeline --llm (opus kill pass, sonnet repro check)
                                        on drafts whose local gates pass. human: nothing calls Claude; drafts queue for you.
  final-gate.py queue                   drafts whose LOCAL gates all pass and whose final gates are still pending
  final-gate.py pass <draft-dir> [note] record YOUR QAQC pass for both final gates
  final-gate.py fail <draft-dir> <why>  record a fail (the draft goes back for repair)

A human verdict is written into the draft's .pipeline.json exactly like Claude's, bound to the SAME byte hash
ship-pipeline computes, so any later edit to report.md, repro.sh, capture.log or evidence/ voids it automatically.
Each verdict is also kept as QAQC-HUMAN.md in the draft dir. Works in either mode: you can always QA a draft yourself.
"""
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODE = os.path.join(WS, ".claude/state/orch/FINAL-GATE")
DRAFTS = os.path.join(WS, "reports/drafts")


def sp():
    spec = importlib.util.spec_from_file_location("ship_pipeline", os.path.join(WS, "scripts/ship-pipeline.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def mode():
    try:
        m = open(MODE).read().strip()
    except OSError:
        return "claude"
    return m if m in ("claude", "human") else "claude"


def queue():
    out = []
    for prog in sorted(os.listdir(DRAFTS)):
        for slug in sorted(os.listdir(os.path.join(DRAFTS, prog))) if os.path.isdir(os.path.join(DRAFTS, prog)) else []:
            d = os.path.join(DRAFTS, prog, slug)
            pl = os.path.join(d, "PIPELINE.md")
            if os.path.isfile(os.path.join(d, "HELD-REASON.md")) or not os.path.isfile(pl):
                continue
            if "LLM GATES PENDING" in open(pl).read():
                out.append(d)
    return out


def record(d, ok, note):
    m = sp()
    draft = m.Draft(d)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for stage in m.LLM:
        h = m.digest(draft.inputs(stage) + [os.path.abspath(m.__file__)])
        draft.cache[stage] = {"hash": h, "ok": ok, "at": __import__("time").time(),
                              "note": f"{'PASS' if ok else 'FAIL'} by the user QAQC {stamp}: {note[:160]}"}
    draft.save()
    # T1.5: GreyNOC's QA verdict, appended to finding.json. This RECORDS a QA verdict only; it is NOT the submission
    # approval, which stays his explicit instruction in the chat turn for that exact item (CLAUDE.md, 2026-10-21).
    try:
        sys.path.insert(0, os.path.join(WS, "scripts"))
        import gnoc_finding
        gnoc_finding.append_layer(d, "human-qaqc", "pass" if ok else "reject", (note or "")[:300], by="The user",
                                  family="human", input_sha256=m.digest(draft.inputs("killer")))
    except Exception as e:  # noqa: BLE001 - the pipeline cache above is still the verdict of record
        print(f"  (finding.json layer not recorded: {type(e).__name__}: {e})")
    with open(os.path.join(d, "QAQC-HUMAN.md"), "a") as f:
        f.write(f"- {stamp} {'PASS' if ok else 'FAIL'} (kill pass + repro check, bound to the current bytes): {note}\n")
    rc, out = m.run([sys.executable, os.path.join(WS, "scripts/ship-pipeline.py"), d])
    verdict = next((l for l in out.splitlines() if "verdict:" in l), "").split("verdict:")[-1].strip()
    print(f"{'PASS' if ok else 'FAIL'} recorded for {os.path.relpath(d, WS)}; pipeline now: {verdict or '?'}")
    if ok and "READY TO FILE" in out:
        print(f"  file it: python3 scripts/vdp-autosubmit.py --approve {os.path.relpath(d, WS)}")


def main(a):
    if a[:1] in (["-h"], ["--help"], ["help"]):
        print(__doc__)
        return 0
    if not a:
        print(f"final gate: {mode()}  ({'Claude runs kill pass + repro check' if mode() == 'claude' else 'you QAQC; Claude is never called'})")
        for d in queue():
            print(f"  waiting: {os.path.relpath(d, WS)}")
        return 0
    if a[0] == "mode" and len(a) == 2 and a[1] in ("claude", "human"):
        os.makedirs(os.path.dirname(MODE), exist_ok=True)
        open(MODE, "w").write(a[1] + "\n")
        print(f"final gate -> {a[1]}")
        return 0
    if a[0] == "queue":
        for d in queue():
            print(os.path.relpath(d, WS))
        return 0
    if a[0] in ("pass", "fail") and len(a) >= 2:
        d = os.path.abspath(a[1])
        if not os.path.isfile(os.path.join(d, "report.md")) or not d.startswith(DRAFTS + os.sep):
            sys.exit(f"not a draft dir under reports/drafts: {a[1]}")
        note = " ".join(a[2:]).strip()
        if a[0] == "fail" and not note:
            sys.exit("fail needs a reason (it goes back to the writer)")
        record(d, a[0] == "pass", note or "reviewed")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
