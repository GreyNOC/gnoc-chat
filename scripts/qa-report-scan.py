#!/usr/bin/env python3
"""
qa-report-scan.py - the single source of truth for "what is a report in this workspace".

WHY THIS EXISTS. The old sweep walked only targets/ and reports/, keyed on a narrow content
shape (a CVSS header, or a Summary+Impact pair) and pruned hard. It therefore reported 2
artifacts inside targets/ when there were 11: every hunt-authored FINDINGS.txt / FINDING.md /
lead.md was invisible because those files carry no CVSS line and no "## Impact" heading.
A finding that no index can see is a finding that never gets filed.

WHAT IT DOES. Walks the WHOLE workspace once, excluding only the QA pipeline itself and
machine-generated noise, and classifies every .md / .txt into one class. Emits JSON for
other scripts and a markdown digest for a human.

  REPORT        submittable shape: a CVSS/Asset/CWE header, or a Summary+Impact section pair,
                or the canonical report.md / <slug>.md under reports/.
  FINDING-NOTE  a hunt-authored finding record under targets/: FINDING(S)*, lead.md,
                CLOSING-PACKAGE, CANDIDATE*. Real work, not yet in report shape.
  SUPPORT       belongs to a report but is not one: venue form fields, triager replies,
                gate logs, status files, checklists, attachment manifests, recapture plans.
  TEMPLATE      the format spec and the exemplars. Never a finding, never staged.
  RESEARCH      everything else under targets/: scope, policy, target model, recon notes.

EXCLUSIONS, each for a stated reason, all overridable:
  QA handoff/       the pipeline itself. Scanning it would make every staged report its own
                    orphan. Excluded unconditionally (--include-qa to audit it anyway).
  patterns/         the mechanism-card library, 1758 cards. Cards carry PoC sections by
  bb-hunt-system/   design, so they flood any content-shape test. Doctrine, not findings.
  .claude/          agent and skill definitions. They quote report format and CVSS vectors
  scripts/          as instructions to follow, not findings. (--include-infra to see them.)
  salvage/          read-only pull from the old system, per CLAUDE.md never edited.
  oss/ node_modules/ .git/ jadx_out/ *_out/smali*/ bodies/ profiles*/ site-packages/ ...
                    cloned upstream source, decompiled apps and captured response bodies.
                    mailco alone contributes 70+ files named Draft*.smali.

Usage:
  qa-report-scan.py                 markdown digest to stdout
  qa-report-scan.py --json          machine-readable, for qa-sweep.sh
  qa-report-scan.py --orphans       only reports and finding-notes the pipeline cannot see
  qa-report-scan.py --program <p>   restrict to one targets/<p>
  qa-report-scan.py --include-infra also scan .claude/ and scripts/
  qa-report-scan.py --include-qa    also scan the QA handoff tree
"""
import os, re, sys, json, argparse

WS = os.environ.get("BB_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
QA = "QA handoff"
ACK = os.path.join(WS, ".claude/state/hunt-loop/qa-orphan-ack.txt")
# Three states, not two. "Is it in the pipeline" was the wrong question: a hunt note can be
# COVERED by a report filed under a different slug, it can be a real LEAD that is correctly
# not a report yet, or it can be research that will never be one. A binary flag made the
# first look like a gap and the third look like work owed.
LEDGER = os.path.join(WS, ".claude/state/hunt-loop/qa-artifact-ledger.tsv")


def read_ledger():
    """path<TAB>state<TAB>note. state: covered | to-draft | lead | not-a-report."""
    out = {}
    if not os.path.exists(LEDGER):
        return out
    for line in open(LEDGER):
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            out[parts[0].strip()] = (parts[1].strip(), parts[2].strip() if len(parts) > 2 else "")
    return out

# roots excluded from the report search, with the reason kept beside the rule
EXCLUDE_ROOTS_ALWAYS = [QA]
EXCLUDE_ROOTS_LIBRARY = ["patterns", "bb-hunt-system", "salvage", "prompts"]
EXCLUDE_ROOTS_INFRA   = [".claude", "scripts"]

# directory names pruned anywhere: generated, cloned or captured bytes
PRUNE_DIRS = {
    ".git", "node_modules", "__pycache__", "site-packages", ".venv", "venv",
    ".mypy_cache", ".pytest_cache", ".next", "dist", "build", "vendor",
    "oss", "bodies", "profiles", "profiles2", "jadx_out", "at_out", "apktool_out",
    "node", "target", "coverage", "htmlcov", ".ruff_cache",
}
# generated shortlists and scan output, not findings
PRUNE_RELS = {"intake/out", "scripts/learn/out", "scripts/h1-feedback/out"}
# A side investigation extracts a third party's artifact (a pulled image, a decompiled app)
# into app/ and keeps recovered credentials in private/. Both are evidence, neither is ours
# to index, and private/ holds live secrets. Prune them wherever a SIDE INVEST case sits.
PRUNE_SIDE_INVEST = re.compile(r"^SIDE INVEST/[^/]+/(app|private)(/|$)")
PRUNE_DIR_RE = re.compile(r"^(smali(_classes\d*)?|res|assets|lib|META-INF|kotlin)$")

MAX_BYTES = 400_000           # a report is prose; anything larger is a dump
EXTS = (".md", ".txt")

# ---------- content signals ----------
RE_CVSS_HDR = re.compile(r"^(CVSS:|\*\*CVSS)", re.M)
RE_META_HDR = re.compile(r"^(Asset|CWE):", re.M)
def _head(text, word):
    return re.search(r"^#{1,4}\s*(\d+[\.\)]\s*)?" + word, text, re.M | re.I)

# ---------- filename signals ----------
RE_FINDING_NAME = re.compile(
    r"^(FINDING|FINDINGS|FINDINGS-.*|FINDING-.*|LEAD|lead|CLOSING-PACKAGE|VERDICT|"
    r"CANDIDATES?-.*)\.(md|txt)$", re.I)
# a finding record only counts inside a program tree, never in a generated shortlist
RE_PROGRAM_TREE = re.compile(r"^(targets|reports/(drafts|submitted|leads))/[^/]+/")
RE_SUPPORT_NAME = re.compile(
    r"^(GATES|STATUS|QA-CHECKLIST|ATTACHMENTS|SHA256SUMS|HELD-REASON|FORM-STAGED|"
    r"RECAPTURE-PLAN|PASTE-REPLY|REOPEN-REQUEST|PRESEND-AUDIT.*|_INVENTORY|_QUEUE|"
    r"_SWEEP|_WATCH|README|\d\d-.*)\.(md|txt)$", re.I)
RE_SUPPORT_PATH = re.compile(r"/(form|attachments|triage-reply-[^/]*)/")
# evidence/ means two different things: under reports/ it holds a staged report's attachments,
# under targets/ it is where a hunt keeps its lead.md. Only the first is support.
RE_SUPPORT_EVIDENCE = re.compile(r"^reports/.*/evidence/")
RE_TEMPLATE_PATH = re.compile(
    r"^reports/(REPORT-FORMAT\.md|EVIDENCE-INTEGRITY\.md|exemplars/)|_CHECKLIST-TEMPLATE\.md$")
RE_SUPERSEDED = re.compile(r"(superseded|do-not-send|\.bak)", re.I)


def classify(rel, name, text):
    """Return (class, why). Order matters: template, support, report, finding, research."""
    if RE_TEMPLATE_PATH.search(rel):
        return "TEMPLATE", "format spec or exemplar"

    has_cvss = bool(RE_CVSS_HDR.search(text))
    has_meta = bool(RE_META_HDR.search(text))
    has_sum, has_imp = bool(_head(text, "Summary")), bool(_head(text, "Impact"))
    has_poc = bool(_head(text, r"(Proof[ -]of[ -]Concept|PoC|Steps to Repro|Reproduction)"))
    report_shape = has_cvss or (has_sum and has_imp)

    # a venue body (submission.txt / 05-*-description.md) carries the report text but the
    # canonical report.md beside it is the artifact of record
    if (RE_SUPPORT_NAME.match(name) or RE_SUPPORT_PATH.search("/" + rel)
            or RE_SUPPORT_EVIDENCE.match(rel)):
        if report_shape and name.lower() in ("submission.txt",):
            return "SUPPORT", "venue body beside a canonical report"
        return "SUPPORT", "report support file"
    if name.lower() == "submission.txt":
        return "SUPPORT", "venue body beside a canonical report"
    if RE_SUPERSEDED.search(name):
        return "SUPPORT", "superseded or backup"

    if rel.startswith("targets/") and report_shape and not (has_cvss and has_sum and has_imp):
        # a research doc that quotes a vector is not a report; fall through to the name tests
        report_shape = False
    if report_shape:
        why = []
        if has_cvss: why.append("CVSS header")
        if has_meta: why.append("Asset/CWE header")
        if has_sum and has_imp: why.append("Summary+Impact")
        if has_poc: why.append("PoC section")
        return "REPORT", ", ".join(why)
    if name.lower() == "report.md" and rel.startswith("reports/"):
        return "REPORT", "canonical report.md under reports/"

    sig = [s for s, ok in (("PoC", has_poc), ("Impact", has_imp),
                           ("Summary", has_sum), ("Asset/CWE", has_meta),
                           ("CVSS", has_cvss)) if ok]
    if RE_FINDING_NAME.match(name) and RE_PROGRAM_TREE.match(rel):
        return "FINDING-NOTE", "hunt finding record" + (" (" + ", ".join(sig) + ")" if sig else "")
    # name-blind catch: a file in a program tree that reproduces a defect and states its
    # effect is a finding record whatever it is called. A note titled NOTES.md has been a
    # real finding before, and naming is not a contract anyone enforces.
    if RE_PROGRAM_TREE.match(rel) and has_poc and (has_imp or has_cvss or has_meta):
        return "FINDING-NOTE", "finding shape, non-standard name (" + ", ".join(sig) + ")"
    return "RESEARCH", "no report or finding shape"


def pipeline_index():
    """Basenames and program_slug tokens the QA pipeline already represents."""
    seen_names, seen_tokens = set(), set()
    for root, dirs, files in os.walk(os.path.join(WS, "reports")):
        for f in files:
            if f.endswith(EXTS):
                seen_names.add(f)
    qa = os.path.join(WS, QA)
    for root, dirs, files in os.walk(qa):
        depth = root[len(qa):].count(os.sep)
        if depth > 4:
            dirs[:] = []
        for d in dirs:
            seen_tokens.add(d)
            seen_names.add(d)
    return seen_names, seen_tokens


def walk(include_infra=False, include_qa=False):
    excl = set(EXCLUDE_ROOTS_LIBRARY)
    if not include_qa:
        excl |= set(EXCLUDE_ROOTS_ALWAYS)
    if not include_infra:
        excl |= set(EXCLUDE_ROOTS_INFRA)
    pruned = 0
    for root, dirs, files in os.walk(WS, topdown=True):
        rel_root = os.path.relpath(root, WS)
        top = rel_root.split(os.sep)[0]
        if rel_root != "." and top in excl:
            dirs[:] = []
            continue
        if any(rel_root == r or rel_root.startswith(r + os.sep) for r in PRUNE_RELS):
            dirs[:] = []
            continue
        if PRUNE_SIDE_INVEST.match(rel_root):
            dirs[:] = []
            continue
        keep = []
        for d in dirs:
            if d in PRUNE_DIRS or PRUNE_DIR_RE.match(d) or d.startswith("."):
                pruned += 1
                continue
            if rel_root == "." and d in excl:
                continue
            keep.append(d)
        dirs[:] = keep
        for f in files:
            if not f.endswith(EXTS):
                continue
            p = os.path.join(root, f)
            rel = os.path.relpath(p, WS)
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            yield rel, f, text
    globals()["_PRUNED"] = pruned


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--orphans", action="store_true")
    ap.add_argument("--program")
    ap.add_argument("--include-infra", action="store_true")
    ap.add_argument("--include-qa", action="store_true")
    a = ap.parse_args()

    ack = set()
    if os.path.exists(ACK):
        ack = {l.strip() for l in open(ACK) if l.strip() and not l.startswith("#")}
    seen_names, seen_tokens = pipeline_index()
    ledger = read_ledger()

    rows = []
    for rel, name, text in walk(a.include_infra, a.include_qa):
        if a.program and not rel.startswith(f"targets/{a.program}/"):
            continue
        cls, why = classify(rel, name, text)
        if cls == "RESEARCH":
            continue
        prog = None
        m = re.match(r"(targets|reports/drafts|reports/submitted|reports/leads)/([^/]+)/", rel)
        if m:
            prog = m.group(2)
        # per ARTIFACT, never per program: a staged report does not cover its siblings.
        # Match on this artifact's own slug - its filename, or its containing hunt dir.
        own = {name, os.path.splitext(name)[0], os.path.basename(os.path.dirname(rel))}
        state, note = ledger.get(rel, ("", ""))
        represented = (
            state in ("covered", "to-draft", "lead", "not-a-report")
            or rel in ack
            or bool(own & seen_names)
            or any(any(f"_{prog}_{o}" == t or t.endswith(f"_{o}") for o in own if o)
                   for t in seen_tokens if prog)
        )
        rows.append(dict(path=rel, name=name, cls=cls, why=why, program=prog,
                         state=state or ("staged" if represented else "UNRESOLVED"),
                         note=note, represented=bool(represented), bytes=len(text)))

    if a.orphans:
        rows = [r for r in rows if r["cls"] in ("REPORT", "FINDING-NOTE") and not r["represented"]]

    if a.json:
        print(json.dumps(dict(rows=rows, pruned=globals().get("_PRUNED", 0)), indent=1))
        return

    order = {"REPORT": 0, "FINDING-NOTE": 1, "SUPPORT": 2, "TEMPLATE": 3}
    rows.sort(key=lambda r: (order[r["cls"]], r["path"]))
    counts = {}
    for r in rows:
        counts[r["cls"]] = counts.get(r["cls"], 0) + 1
    print("# Report scan\n")
    st_counts = {}
    for r in rows:
        if r["cls"] in ("REPORT", "FINDING-NOTE"):
            st_counts[r["state"]] = st_counts.get(r["state"], 0) + 1
    print("| class | count |\n|---|---|")
    for k in ("REPORT", "FINDING-NOTE", "SUPPORT", "TEMPLATE"):
        print(f"| {k} | {counts.get(k,0)} |")
    print("\n| triage state | count |\n|---|---|")
    for k in ("staged", "covered", "to-draft", "lead", "not-a-report", "UNRESOLVED"):
        if st_counts.get(k):
            print(f"| {k} | {st_counts[k]} |")
    for cls in ("REPORT", "FINDING-NOTE"):
        sel = [r for r in rows if r["cls"] == cls]
        if not sel:
            continue
        print(f"\n## {cls}\n")
        print("| state | program | path | why / note |\n|---|---|---|---|")
        for r in sel:
            st = r["state"] if r["represented"] else "**UNRESOLVED**"
            print(f"| {st} | {r['program'] or '-'} | `{r['path']}` "
                  f"| {r['note'] or r['why']} |")
    # every program under targets/, including the ones with nothing
    progs = sorted(d for d in os.listdir(os.path.join(WS, "targets"))
                   if os.path.isdir(os.path.join(WS, "targets", d)))
    print(f"\n## Per-program, all {len(progs)} under targets/\n")
    print("| program | reports | finding-notes | to-draft | lead | unresolved |\n"
          "|---|---|---|---|---|---|")
    for p in progs:
        sel = [r for r in rows if r["path"].startswith(f"targets/{p}/")]
        nr = sum(1 for r in sel if r["cls"] == "REPORT")
        nf = sum(1 for r in sel if r["cls"] == "FINDING-NOTE")
        nd = sum(1 for r in sel if r["state"] == "to-draft")
        nl = sum(1 for r in sel if r["state"] == "lead")
        no = sum(1 for r in sel if r["cls"] in ("REPORT", "FINDING-NOTE") and not r["represented"])
        if nr or nf:
            print(f"| {p} | {nr} | {nf} | {nd} | {nl} | {no} |")
    todraft = [r for r in rows if r["state"] == "to-draft"]
    if todraft:
        print("\n## ACTION - report-grade with no draft on disk\n")
        for r in todraft:
            print(f"- `{r['path']}` ({r['program']}) - {r['note']}")
    quiet = [p for p in progs
             if not any(r["path"].startswith(f"targets/{p}/") for r in rows)]
    print(f"\n{len(quiet)} of {len(progs)} programs hold no report or finding note: "
          + ", ".join(f"`{p}`" for p in quiet))


if __name__ == "__main__":
    main()
