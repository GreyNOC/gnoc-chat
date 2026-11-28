#!/usr/bin/env python3
"""gnoc_finding.py - one machine-readable record per draft (finding.json) and an evidence manifest.

WHY (spec .claude/state/hunt-loop/SPEC-0security-alignment-20261109.md, T1.5 and T1.6):
  A draft was report.md + GATES.md + FORM.md prose. Nothing recorded the VRT id and its priority, who judged
  each gate (and on which model family), or whether the evidence a gate judged is still the evidence on disk.
  Receipts: the Bugcrowd P3 floor (2026-11-05) lived in scripts/bbtools/vrt.py and no gnoc_*.py called
  it; three byte-identical control PNGs under three names (program-28, 2026-11-08) passed a "len(pngs) >= 2"
  gate; a liveness json outside evidence/ and a stray "# " in SUBMIT-TITLE.txt went unnoticed.

  Ideas from 0sec-labs/0 (MIT OR Apache-2.0), reimplemented here, no code copied:
    packages/shared/src/types.ts               Finding, LayerVerdict (append-only), PocStep, publishability
    packages/core/src/agent/finding-validator.ts  shape checks at the save boundary, path containment, NO auto-correct
    packages/core/src/stages/hunt-evidence-ledger.ts  observation (needs a locator) vs assumption
    packages/core/src/verify/reproduction-bundle.ts  per-file {sha256, size, mode} snapshot before judging

WHAT IT NEVER DOES: approve, stage, file or submit anything. A `human-qaqc` layer RECORDS the user's QA verdict; the
submission approval stays their explicit instruction in the chat turn (CLAUDE.md hard rules, 2026-10-21). No validator
rule fixes a value; every rule reports.

Pure stdlib at import time (gnoc_report, gnoc_oracle, gnoc_pay and vrt.py are imported lazily, inside the call that
needs them), so gnoc_line.py and ship-pipeline.py import this without the 15k-line chat module.

CLI:
  gnoc_finding.py validate <draft>       validator errors (exit 1 when any)
  gnoc_finding.py backfill <draft>       write a minimal finding.json when none exists (touches no other file)
  gnoc_finding.py show <draft>           print finding.json
  gnoc_finding.py manifest <draft>       (re)build evidence/MANIFEST.json from the bytes on disk now
  gnoc_finding.py check <draft>          validator errors plus the evidence-manifest refusals

Gate switch, read at call time by gnoc_line.gate_qa and ship-pipeline.py:
  GNOC_FINDING_GATE=advisory  (DEFAULT for the first week, spec 3.1) errors are appended to the verdict text,
                              the gate result is unchanged and the old PNG-count rule still decides
  GNOC_FINDING_GATE=enforce   any error refuses QA; the request+response panel-pair check replaces the PNG count
  GNOC_FINDING_GATE=off       neither runs; the old PNG-count path only
"""
import fnmatch
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_z as _now

HERE = os.path.dirname(os.path.abspath(__file__))
WS = os.path.dirname(HERE)
FILE = "finding.json"
MANIFEST_REL = os.path.join("evidence", "MANIFEST.json")
MANIFEST_DIRS = ("evidence", "panels")      # the bytes a gate judges and a triager receives
MAX_READ = 50 * 1024 * 1024

GATE_ENV = "GNOC_FINDING_GATE"
GATE_MODES = ("advisory", "enforce", "off")

VENUES = ("hackerone", "bugcrowd", "intigriti", "yeswehack", "immunefi", "self-hosted", "unknown")
STATUSES = ("draft", "held", "ready", "staged", "submitted", "archived")
WORKFLOW = {"draft": "agent_review", "held": "blocked", "ready": "human_review", "staged": "human_review",
            "submitted": "done", "archived": "cancelled"}
LAYERS = ("build", "format", "selfdup", "qaqc", "slop", "notes", "repro", "panels", "killer", "reprochk", "dryrun",
          "liveness", "qa-gate", "human-qaqc")
VERDICTS = ("pass", "reject", "downgrade", "skip", "error")
FAMILIES = ("code", "anthropic", "deepseek", "ollama", "human", "unknown")
PUBLISHABILITY = ("in_scope", "by_design", "duplicate", "fixed", "unreachable", "fix_bypass", "needs_verify")
STANCES = ("observation", "assumption")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

_CWE = re.compile(r"^CWE-[0-9]{1,4}$")
_CVSS = re.compile(r"^CVSS:(3\.[01])/AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])$")
# panel names: gnoc_panels.capture writes burp-req-<stem>.png / burp-resp-<stem>.png; hand captures use -req/-resp
# or REQUEST/RESPONSE. The token must stand alone between separators so "request" inside a word never matches.
_REQ_TOK = re.compile(r"(^|[-_.])(req|request)([-_.]|$)", re.I)
_RESP_TOK = re.compile(r"(^|[-_.])(resp|response)([-_.]|$)", re.I)
_CAPTURE_EXT = (".json", ".hdr", ".body", ".req", ".resp", ".txt", ".log", ".har", ".http", ".sig")




def gate_mode():
    v = str(os.environ.get(GATE_ENV) or "advisory").strip().lower()
    return v if v in GATE_MODES else "advisory"


def family_of(by):
    """The model FAMILY behind a verdict, so a finder and a refuter on the same family is visible
    (idea: 0sec-labs/0 packages/core/src/stages/hunt-cross-family.ts; reimplemented, no code copied)."""
    b = str(by or "").strip().lower()
    if not b or b == "code" or b.startswith("code:"):
        return "code"
    if b in ("greynoc", "human"):
        return "human"
    if any(k in b for k in ("claude", "opus", "sonnet", "haiku", "anthropic")):
        return "anthropic"
    if "deepseek" in b:
        return "deepseek"
    if ":" in b or any(k in b for k in ("qwen", "llama", "hermes", "gemma", "mistral", "phi", "ollama", "hf.co/")):
        return "ollama"
    return "unknown"


# ------------------------------------------------------------------ VRT (scripts/bbtools/vrt.py, imported by path)

_VRT = {"mod": None, "index": None}


def _vrt_mod():
    if _VRT["mod"] is None:
        spec = importlib.util.spec_from_file_location("gnoc_finding_vrt", os.path.join(HERE, "bbtools", "vrt.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _VRT["mod"] = mod
    return _VRT["mod"]


def _vrt_index():
    if _VRT["index"] is None:
        try:
            _VRT["index"] = {p: {"id": p, "name": n, "priority": pr, "leaf": leaf}
                             for p, n, pr, leaf in _vrt_mod().table()}
        except (SystemExit, OSError, ValueError):
            _VRT["index"] = {}
    return _VRT["index"]


def vrt_resolve(vrt_id):
    """vrt.resolve semantics over a cached index (vrt.resolve reloads the JSON per call)."""
    return _vrt_index().get(str(vrt_id or "").strip())


def vrt_source():
    try:
        with open(os.path.join(HERE, "bbtools", "data", "vrt.json")) as fh:
            rel = (json.load(fh).get("metadata") or {}).get("release_date") or "?"
    except (OSError, ValueError):
        rel = "?"
    return f"scripts/bbtools/data/vrt.json@{str(rel)[:10]}"


def vrt_check(rec):
    """(ok, why). Bugcrowd needs a VRT leaf that resolves at P1-P3 (the user 2026-11-05: "only submit p3 and above to
    bugcrowd"). Other venues pass. A null priority is NOT P3+: vrt.py --check exits 3 and a human decides."""
    if str((rec or {}).get("venue") or "").lower() != "bugcrowd":
        return True, "not a Bugcrowd draft: the VRT floor does not apply"
    v = (rec or {}).get("vrt") or {}
    vid = str(v.get("id") or "").strip()
    if not vid:
        return False, ("Bugcrowd draft has no VRT id: resolve the leaf BEFORE filing "
                       "(python3 scripts/bbtools/vrt.py --search <class>), then build_report vrt=<leaf id>")
    r = vrt_resolve(vid)
    if not r:
        return False, f"VRT id {vid} does not resolve in {vrt_source()}: pick a leaf with vrt.py --search <class>"
    prio = r["priority"]
    if prio in (1, 2, 3):
        if v.get("priority") not in (None, prio):
            return False, f"VRT {vid} is P{prio} in the taxonomy but the record says P{v.get('priority')}"
        if not r["leaf"]:
            return False, f"VRT {vid} is a parent node; Bugcrowd wants a leaf (vrt.py --search)"
        return True, f"VRT {vid} P{prio}: at or above the Bugcrowd P3 floor"
    if prio in (4, 5):
        return False, (f"VRT {vid} is P{prio}, below the Bugcrowd P3 floor: write it, hold it, escalate to a P3+ leaf "
                       "(vrt.py --search <class>)")
    return False, (f"VRT {vid} priority varies (null): not automatically P3+, the user decides by the captured impact "
                   "(vrt.py --check exits 3)")


# ------------------------------------------------------------------ record io

def _path(draft):
    return os.path.join(draft, FILE)


def load(draft):
    try:
        with open(_path(draft)) as fh:
            rec = json.load(fh)
        return rec if isinstance(rec, dict) else None
    except (OSError, ValueError):
        return None


def _layers_prefix_error(old, new):
    old_l = (old or {}).get("layers") or []
    new_l = (new or {}).get("layers") or []
    if len(new_l) < len(old_l) or new_l[:len(old_l)] != old_l:
        return ("layers are append-only: an earlier layer verdict was changed or removed "
                f"({len(old_l)} on disk, the first {min(len(old_l), len(new_l))} of the new record must match)")
    return None


def write(draft, rec):
    """Atomic tmp+rename. Refuses (ValueError) a record that rewrites or drops an earlier layer row."""
    why = _layers_prefix_error(load(draft), rec)
    if why:
        raise ValueError(why)
    tmp = _path(draft) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(rec, fh, indent=1, sort_keys=False)
        fh.write("\n")
    os.replace(tmp, _path(draft))
    return _path(draft)


def append_layer(draft, layer, verdict, reason="", by="code", family=None, input_sha256=""):
    """Append ONE gate verdict row; never rewrites an earlier row. Creates a minimal record (backfill) if none."""
    if layer not in LAYERS:
        raise ValueError(f"layer is one of {', '.join(LAYERS)} (got {layer!r})")
    if verdict not in VERDICTS:
        raise ValueError(f"verdict is one of {', '.join(VERDICTS)} (got {verdict!r})")
    rec = load(draft) or backfill_record(draft)
    rec.setdefault("layers", []).append({
        "layer": layer, "verdict": verdict, "reason": str(reason or "")[:400], "by": str(by or "code"),
        "family": family or family_of(by), "input_sha256": str(input_sha256 or ""), "ts": _now()})
    write(draft, rec)
    return rec


# ------------------------------------------------------------------ backfill

def _where(draft):
    """(bucket, program, slug) from reports/<bucket>/<program>/<slug>; a fixture outside reports/ is a draft."""
    d = os.path.realpath(draft)
    rel = os.path.relpath(d, os.path.realpath(os.path.join(WS, "reports"))).split(os.sep)
    if len(rel) >= 3 and rel[0] != "..":
        return rel[0], rel[1], rel[2]
    return "drafts", os.path.basename(os.path.dirname(d)), os.path.basename(d)


def _read_text(p, n=400_000):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read(n)
    except OSError:
        return ""


def _venue(program):
    try:
        sys.path.insert(0, HERE) if HERE not in sys.path else None
        import gnoc_pay
        v = gnoc_pay._venue(program)
        return v if v in VENUES else "unknown"
    except Exception:  # noqa: BLE001 - an unknown venue is reported, never raised
        return "unknown"


def _find_vrt_id(draft):
    """A dotted VRT id written in the draft's own files (FORM.md, GATES.md, SUBMIT-*.txt, report.md), if one resolves."""
    names = ["FORM.md", "GATES.md", "report.md"] + sorted(f for f in os.listdir(draft) if f.startswith("SUBMIT-"))
    for n in names:
        for m in re.finditer(r"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,6}\b", _read_text(os.path.join(draft, n))):
            if vrt_resolve(m.group(0)):
                return m.group(0)
    return None


def cvss_block(vector, score=None):
    vector = str(vector or "").strip()
    rec = {"version": "", "vector": vector, "score": score, "recomputed": None}
    m = _CVSS.match(vector)
    if m:
        rec["version"] = m.group(1)
        rec["recomputed"] = _recompute(m)
    return rec


def _recompute(m):
    sys.path.insert(0, HERE) if HERE not in sys.path else None
    import gnoc_report
    _ver, av, ac, pr, ui, s, c, i, a = m.groups()
    return gnoc_report.cvss_score(av, ac, pr, ui, s, c, i, a)


def backfill_record(draft):
    """A minimal record from report.md's header block and the directory layout. claims are empty: a backfilled
    record never claims an observation it did not check."""
    bucket, program, slug = _where(draft)
    md = _read_text(os.path.join(draft, "report.md"))
    head = md.splitlines()[:40]
    vec, score, asset, cwe, title = "", None, "", "", ""
    for ln in head:
        m = re.match(r"^CVSS:\s*(CVSS:3\.[01]/\S+)(?:\s*=\s*([0-9]+(?:\.[0-9])?))?", ln)
        if m and not vec:
            vec, score = m.group(1), (float(m.group(2)) if m.group(2) else None)
        elif ln.startswith("Asset:") and not asset:
            asset = ln.split(":", 1)[1].strip()
        elif ln.startswith("CWE:") and not cwe:
            got = re.search(r"CWE-\d+", ln)
            cwe = got.group(0) if got else ln.split(":", 1)[1].strip()
        elif ln.startswith("# ") and not title:
            title = ln[2:].strip()
    status = {"submitted": "submitted", "archive": "archived"}.get(bucket) or (
        "held" if os.path.isfile(os.path.join(draft, "HELD-REASON.md")) else "draft")
    vid = _find_vrt_id(draft) if os.path.isdir(draft) else None
    vr = vrt_resolve(vid) if vid else None
    rec = {"schema": 1, "id": f"{program}/{slug}", "program": program, "venue": _venue(program),
           "asset": asset, "title": title, "cwe": cwe,
           "cvss": cvss_block(vec, score) if vec else {},
           "vrt": {"id": vid, "priority": vr["priority"] if vr else None, "source": vrt_source()} if vid else {},
           "status": status, "workflow": WORKFLOW[status], "chain": [], "poc_steps": [], "claims": [],
           "layers": [],
           "publishability": {"decision": "needs_verify", "reason": "backfilled from the draft files; not judged",
                              "refs": []},
           "decorrelation": {"finder_family": "unknown", "refuter_family": "unknown", "cross_family": False},
           "backfilled": _now()}
    return rec


def backfill(draft):
    """Write a minimal finding.json when none exists. Returns (record, written)."""
    rec = load(draft)
    if rec is not None:
        return rec, False
    rec = backfill_record(draft)
    write(draft, rec)
    return rec, True


# ------------------------------------------------------------------ validator

def _resolve_in(draft, program, rel):
    """(abs path or None, error or None). The file must exist and its REAL path must sit inside the draft dir or
    targets/<program>/; a symlink that points outside is refused (0 finding-validator: containment, no traversal)."""
    path = str(rel or "").split("#", 1)[0].strip()
    if not path:
        return None, "empty path"
    cands = [path] if os.path.isabs(path) else [os.path.join(draft, path), os.path.join(WS, path)]
    hit = next((c for c in cands if os.path.lexists(c)), None)
    if hit is None:
        return None, f"{path} does not exist"
    real = os.path.realpath(hit)
    roots = [os.path.realpath(draft), os.path.realpath(os.path.join(WS, "targets", program or "_none_"))]
    if not any(real == r or real.startswith(r + os.sep) for r in roots):
        kind = "a symlink pointing" if os.path.islink(hit) or real != os.path.abspath(hit) else "a file"
        return None, f"{path} is {kind} outside the draft dir and targets/{program}/ ({real})"
    return real, None


def _contains(path, needle):
    try:
        with open(path, "rb") as fh:
            blob = fh.read(MAX_READ)
    except OSError:
        return False
    n = needle.encode()
    forms = (blob, blob.replace(b'\\"', b'"').replace(b"\\/", b"/"))
    return any(n in f for f in forms)


def validate(draft, rec=None):
    """Errors as one-line strings (empty list = valid). Pure: reads the draft, never writes, never fixes."""
    on_disk = load(draft)
    if rec is None:
        rec = on_disk
    if rec is None:
        return [f"no {FILE}: python3 scripts/gnoc_finding.py backfill {_rel(draft)}"]
    errs = []
    program = rec.get("program") or _where(draft)[1]
    # 1 CWE shape
    if not _CWE.match(str(rec.get("cwe") or "")):
        errs.append(f"cwe {str(rec.get('cwe'))[:40]!r} is not CWE-<number>")
    # 2 CVSS vector parses and its arithmetic matches the stated score (3.0 vs 3.1 rounding: 0.1)
    cv = rec.get("cvss") or {}
    if cv.get("vector"):
        m = _CVSS.match(str(cv["vector"]))
        if not m:
            errs.append(f"cvss vector {str(cv['vector'])[:80]!r} does not parse (AV/AC/PR/UI/S/C/I/A in order)")
        else:
            try:
                got = _recompute(m)
                stated = float(cv.get("score"))
                if abs(got - stated) > 0.1:
                    errs.append(f"cvss score {stated} does not match the vector, which computes to {got}")
            except (TypeError, ValueError):
                errs.append(f"cvss score {cv.get('score')!r} is not a number")
    # 3 every capture and locator resolves inside the draft or targets/<program>/
    refs = [("chain capture", e.get("capture")) for e in rec.get("chain") or [] if e.get("capture")]
    refs += [("poc step capture", s.get("capture")) for s in rec.get("poc_steps") or [] if s.get("capture")]
    refs += [("claim locator", c.get("locator")) for c in rec.get("claims") or [] if c.get("locator")]
    for what, ref in refs:
        _p, why = _resolve_in(draft, program, ref)
        if why:
            errs.append(f"{what}: {why}")
    # 4 a READY / staged / submitted record names a byte for every edge, and rests on no assumption
    status = rec.get("status")
    if status in ("ready", "staged", "submitted"):
        claims = rec.get("claims") or []
        for c in claims:
            if c.get("load_bearing") and c.get("stance") == "assumption":
                errs.append(f"load-bearing claim is an assumption, not an observation: {str(c.get('statement'))[:80]}")

        def observed(c):
            if c.get("stance") != "observation" or "#" not in str(c.get("locator") or ""):
                return False
            p, why = _resolve_in(draft, program, c["locator"])
            needle = str(c["locator"]).split("#", 1)[1]
            return bool(p and not why and needle and _contains(p, needle))
        edges = [e for e in rec.get("chain") or [] if e.get("role") != "negative-control"]
        if edges:
            for e in edges:
                mine = [c for c in claims if c.get("edge") == e.get("edge")
                        or (e.get("capture") and str(c.get("locator") or "").split("#", 1)[0]
                            == os.path.basename(str(e.get("capture"))))]
                mine = mine or claims
                if not any(observed(c) for c in mine):
                    errs.append(f"{status} record: edge {e.get('edge')} has no observation claim whose locator file "
                                "contains its needle (a gate row must name a byte, T-268)")
        elif not any(observed(c) for c in claims):
            errs.append(f"{status} record has no observation claim whose locator file contains its needle (T-268)")
    # 5 the Bugcrowd P3 floor
    ok, why = vrt_check(rec)
    if not ok:
        errs.append(why)
    # 6 layers are append-only against the record on disk
    if rec is not on_disk and on_disk is not None:
        why = _layers_prefix_error(on_disk, rec)
        if why:
            errs.append(why)
    for row in rec.get("layers") or []:
        if row.get("verdict") not in VERDICTS or row.get("layer") not in LAYERS:
            errs.append(f"layer row {row.get('layer')!r}/{row.get('verdict')!r} is not in the schema")
            break
    if status not in STATUSES:
        errs.append(f"status {status!r} is not one of {', '.join(STATUSES)}")
    return errs


def _rel(p):
    try:
        r = os.path.relpath(p, WS)
        return p if r.startswith("..") else r
    except ValueError:
        return p


# ------------------------------------------------------------------ evidence manifest (T1.6)

def _manifest_path(draft):
    return os.path.join(draft, MANIFEST_REL)


def _covered(draft):
    out = []
    for top in MANIFEST_DIRS:
        base = os.path.join(draft, top)
        for dp, dn, fn in os.walk(base):
            dn.sort()
            for f in sorted(fn):
                full = os.path.join(dp, f)
                rel = os.path.relpath(full, draft)
                if rel == MANIFEST_REL or f.endswith(".tmp") or not os.path.isfile(full):
                    continue
                out.append(rel)
    return out


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pair_key(base, tok):
    return tok.sub(lambda m: f"{m.group(1)}@{m.group(3)}", base.lower(), count=1)


def _role(rel):
    base = os.path.basename(rel)
    low = base.lower()
    if fnmatch.fnmatch(low, "liveness-*.json"):
        return "liveness"
    if low.endswith(".png"):
        stem = low[:-4]
        if _RESP_TOK.search(stem):
            return "panel-response"
        if _REQ_TOK.search(stem):
            return "panel-request"
        return "panel-unpaired"
    if low in ("repro.sh", "attacker.py", "attacker.html") or low.endswith(".sh"):
        return "repro"
    if low.endswith(_CAPTURE_EXT):
        return "capture"
    return "other"


def _is_sealed(path):
    try:
        sys.path.insert(0, HERE) if HERE not in sys.path else None
        import gnoc_oracle
        return bool(gnoc_oracle.is_sealed(path))
    except Exception:  # noqa: BLE001 - no seal key or no oracle: unsealed, never an error
        return False


def _scan(draft, seal=False):
    files = {}
    for rel in _covered(draft):
        full = os.path.join(draft, rel)
        st = os.stat(full)
        files[rel] = {"sha256": _sha(full), "bytes": st.st_size, "mode": f"{st.st_mode & 0o777:04o}",
                      "sealed": _is_sealed(full) if seal else False, "role": _role(rel), "pairs_with": None}
    # pair request and response panels in the same directory by the name with the req/resp token blanked
    reqs = {(os.path.dirname(r), _pair_key(os.path.basename(r)[:-4], _REQ_TOK)): r
            for r, v in files.items() if v["role"] == "panel-request"}
    for r, v in files.items():
        if v["role"] != "panel-response":
            continue
        key = (os.path.dirname(r), _pair_key(os.path.basename(r)[:-4], _RESP_TOK))
        if key in reqs:
            v["pairs_with"] = reqs[key]
            files[reqs[key]]["pairs_with"] = r
    return files


def manifest(draft):
    """Write evidence/MANIFEST.json from the bytes on disk NOW and return it (0 reproduction-bundle: snapshot the
    evidence once, before any gate judges it)."""
    os.makedirs(os.path.join(draft, "evidence"), exist_ok=True)
    rec = {"schema": 1, "created": _now(), "files": _scan(draft, seal=True)}
    tmp = _manifest_path(draft) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, _manifest_path(draft))
    return rec


def load_manifest(draft):
    try:
        with open(_manifest_path(draft)) as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) and isinstance(m.get("files"), dict) else None
    except (OSError, ValueError):
        return None


def manifest_check(draft):
    """One-line refusals; an empty list means the evidence on disk is the evidence the manifest recorded, every
    panel is a real and distinct PNG with a request+response pair, and nothing sits where a gate cannot see it."""
    errs = []
    cur = _scan(draft)
    man = load_manifest(draft)
    if man is None:
        errs.append(f"no {MANIFEST_REL}: build it with python3 scripts/gnoc_finding.py manifest {_rel(draft)}")
    else:
        old = man["files"]
        drift = sorted(set(cur) ^ set(old)) + sorted(r for r in set(cur) & set(old)
                                                     if cur[r]["sha256"] != (old[r] or {}).get("sha256"))
        for r in drift[:5]:
            how = "added" if r not in old else "removed" if r not in cur else "changed"
            errs.append(f"evidence changed after the manifest: {r} ({how}); rebuild the manifest and re-run the gates")
        if len(drift) > 5:
            errs.append(f"evidence changed after the manifest: {len(drift) - 5} more file(s)")
    pngs = {r: v for r, v in cur.items() if r.lower().endswith(".png")}
    by_sha = {}
    for r, v in sorted(pngs.items()):
        by_sha.setdefault(v["sha256"], []).append(r)
    for same in by_sha.values():
        if len(same) > 1:
            errs.append(f"panels {same[0]} and {same[1]}"
                        + (f" (and {len(same) - 2} more)" if len(same) > 2 else "")
                        + " are byte-identical; each decisive leg needs its own capture")
    for r in sorted(pngs):
        try:
            with open(os.path.join(draft, r), "rb") as fh:
                head = fh.read(8)
        except OSError:
            head = b""
        if head != PNG_MAGIC:
            errs.append(f"{r} is named .png but carries no PNG signature; attach the real screenshot")
    if not any(v["role"] == "panel-request" and v["pairs_with"] for v in pngs.values()):
        errs.append("no request+response Burp panel pair: name them burp-req-<stem>.png and burp-resp-<stem>.png "
                    "(or <stem>-req/-resp, REQUEST/RESPONSE) in the same folder")
    for dp, dn, fn in os.walk(draft):
        relp = os.path.relpath(dp, draft)
        if relp == "evidence" or relp.startswith("evidence" + os.sep):
            continue
        for f in fn:
            if fnmatch.fnmatch(f.lower(), "liveness-*.json"):
                errs.append(f"{os.path.normpath(os.path.join(relp, f))} is a liveness receipt outside evidence/; "
                            "move it into evidence/ so the gates and the bundle see it")
    stems = {}
    for r, v in cur.items():
        stems.setdefault(os.path.splitext(r)[0], []).append(v["bytes"])
    for r, v in sorted(cur.items()):
        # an empty .body beside a non-empty .hdr of the same stem is a real empty response (a 302, a 403), not an
        # empty capture; only a capture with no non-empty sibling reads as a tested negative
        if v["bytes"] == 0 and not any(b > 0 for b in stems.get(os.path.splitext(r)[0], [])):
            errs.append(f"{r} is empty (0 bytes); an empty capture reads as a tested negative (T-41)")
    title = os.path.join(draft, "SUBMIT-TITLE.txt")
    if os.path.isfile(title) and _read_text(title, 64).startswith("# "):
        errs.append("SUBMIT-TITLE.txt starts with '# '; the platform title field takes the plain title")
    return errs


def check(draft):
    return validate(draft) + manifest_check(draft)


# ------------------------------------------------------------------ cli

def main(argv):
    if len(argv) < 2 or argv[0] not in ("validate", "backfill", "show", "manifest", "check"):
        print(__doc__)
        return 2
    cmd, draft = argv[0], os.path.abspath(argv[1])
    if not os.path.isdir(draft):
        print(f"not a directory: {argv[1]}", file=sys.stderr)
        return 2
    if cmd == "show":
        rec = load(draft)
        print(json.dumps(rec, indent=1) if rec else f"no {FILE} in {_rel(draft)}")
        return 0 if rec else 1
    if cmd == "backfill":
        rec, written = backfill(draft)
        errs = validate(draft)
        print(f"{'wrote' if written else 'kept existing'} {_rel(_path(draft))}; {len(errs)} validator error(s)")
        for e in errs:
            print(f"  - {e}")
        return 0
    if cmd == "manifest":
        m = manifest(draft)
        print(f"wrote {_rel(_manifest_path(draft))}: {len(m['files'])} file(s)")
        return 0
    errs = validate(draft) if cmd == "validate" else check(draft)
    for e in errs:
        print(f"- {e}")
    print(f"{len(errs)} error(s)" if errs else "valid")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
