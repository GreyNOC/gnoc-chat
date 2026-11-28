"""gnoc_report.py - build a report draft from a PROVEN chain in the ledger, byte-faithful by construction.

The model never retypes evidence. The PoC is assembled by code from the raw capture files the chain's edges
point at (the gnoc raw JSON that http_request / probe_matrix write: the exact request and response), each step
quoted with the bytes that prove it. The model writes only what needs judgment in words: the title, the
Summary and the Impact, which are checked by gnoc_gates.format_checks and sent back with the failures until they
pass (or replaced by a plain template). Output follows reports/REPORT-FORMAT.md:

    CVSS / Asset / CWE header, '# title', ## Summary (<=35 words), ## PoC, ## Impact (<=35 words)
    evidence/ holds copies of every capture the PoC quotes; CHAIN.md is written by ship_chain.
CVSS is a SUGGESTION derived from the chain (start node -> PR, victim interaction -> UI, crown -> C/I/A);
cvss-scorer or the user confirms it. Nothing is filed by this module.
"""
import json
import math
import os
import re
import shlex
import shutil
import urllib.parse

import subprocess
import sys
from datetime import datetime, timezone

import gnoc_gates
import gnoc_hunt
import gnoc_doctrine
import gnoc_modes
import gnoc_pay

WS = gnoc_hunt.WS
# crown -> (C, I, A, CWE)
CROWN_IMPACT = {
    "rce": ("H", "H", "H", "CWE-94 Improper Control of Generation of Code"),
    "ato": ("H", "H", "N", "CWE-640 Weak Password Recovery Mechanism for Forgotten Password"),
    "cross-tenant": ("H", "H", "N", "CWE-639 Authorization Bypass Through User-Controlled Key"),
    "money": ("N", "H", "N", "CWE-840 Business Logic Errors"),
    "mass-pii": ("H", "N", "N", "CWE-359 Exposure of Private Personal Information to an Unauthorized Actor"),
    "admin": ("H", "H", "N", "CWE-269 Improper Privilege Management"),
    "auth-bypass": ("H", "H", "N", "CWE-287 Improper Authentication"),
    "cross-user-write": ("N", "H", "N", "CWE-639 Authorization Bypass Through User-Controlled Key"),
    "cross-user-read": ("H", "N", "N", "CWE-639 Authorization Bypass Through User-Controlled Key"),
    "secret": ("H", "N", "N", "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor"),
}
_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62}, "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _roundup(x):
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss_score(av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N"):
    """CVSS 3.x base score (the spec formula; 3.0 and 3.1 agree on base scores except rounding edge cases)."""
    prw = {"N": 0.85, "L": 0.68 if s == "C" else 0.62, "H": 0.5 if s == "C" else 0.27}[pr]
    iss = 1 - (1 - _W["CIA"][c]) * (1 - _W["CIA"][i]) * (1 - _W["CIA"][a])
    imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if s == "C" else 6.42 * iss
    expl = 8.22 * _W["AV"][av] * _W["AC"][ac] * prw * _W["UI"][ui]
    if imp <= 0:
        return 0.0
    return _roundup(min(1.08 * (imp + expl), 10)) if s == "C" else _roundup(min(imp + expl, 10))


def severity(score):
    return "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


_RACE = re.compile(r"\brace\b|toctou|concurren|burst|timing|window", re.I)


def chain_text(chain):
    return " ".join(f"{e['frm']} {e['to']} {e['via']} {' '.join(e.get('requires') or [])}" for e in chain)


def suggest_cvss(chain, version="3.0"):
    """(vector, score, cwe, reasoning): every metric derived from the chain and ARGUED, so GATES.md can show the
    arithmetic and the contested calls (T-102 derive, T-103 score what was captured and record the alternatives,
    T-105 CWE of the weakness not the effect)."""
    crown = chain[-1]["to"]
    text = chain_text(chain)
    c, i, a, _ = CROWN_IMPACT.get(crown, ("L", "N", "N", ""))
    cwe = gnoc_doctrine.cwe_for(text, crown)
    why = []
    pr = "N" if chain[0]["frm"] == "unauth" else "L"
    why.append(f"PR:{pr} - the chain starts from {chain[0]['frm']}" + (
        " (a self-provisioned account is PR:L; PR:N only if the first edge needs no credential at all)" if pr == "L" else ""))
    ui = "R" if any(gnoc_hunt.INTERACTION.search(" ".join(e.get("requires") or []) + " " + e["via"]) for e in chain) else "N"
    why.append(f"UI:{ui} - " + ("an edge requires a victim action (click / visit); UI:N would be an overclaim"
                               if ui == "R" else "no edge needs the victim to act"))
    ac = "H" if any(_RACE.search(e["via"] + " " + " ".join(e.get("requires") or [])) for e in chain) else "L"
    why.append(f"AC:{ac} - " + ("a race / timing window is on the chain; AC:L on a race is the classic inflation call"
                               if ac == "H" else "no timing window or non-default condition on the chain"))
    scope = "C" if crown == "cross-tenant" or any(e["to"] == "browser-origin" for e in chain) else "U"
    why.append(f"S:{scope} - " + ("the impact lands in a security authority other than the vulnerable component "
                                  "(another tenant, or script in the user's browser)" if scope == "C"
                                  else "impact stays inside the vulnerable component's authority; argue S:C only with a captured crossing"))
    why.append(f"C:{c}/I:{i}/A:{a} - defaults for the {crown} crown; downgrade any axis the captured bytes do not show "
               "(a partial read is C:L, a single field write is I:L)")
    vec = f"CVSS:{version}/AV:N/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
    sc = cvss_score("N", ac, pr, ui, scope, c, i, a)
    alt = []
    for label, kw in (("AC flipped", dict(ac="L" if ac == "H" else "H")), ("PR flipped", dict(pr="L" if pr == "N" else "N")),
                      ("UI flipped", dict(ui="N" if ui == "R" else "R"))):
        args = dict(av="N", ac=ac, pr=pr, ui=ui, s=scope, c=c, i=i, a=a)
        args.update(kw)
        alt.append(f"{label}: {cvss_score(**args)}")
    why.append("alternatives a triager may argue: " + "; ".join(alt))
    return vec, sc, cwe, why


def _load_raw(path):
    p = path if os.path.isabs(path) else os.path.join(WS, path)
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return None, None
    try:
        j = json.loads(txt)
        if isinstance(j, dict) and "request" in j and "response" in j:
            return j, txt
    except ValueError:
        pass
    return None, txt


def curl_of(req):
    parts = ["curl", "-sS", "-i", "--path-as-is", "-X", req.get("method", "GET"), shlex.quote(req.get("url", ""))]
    for k, v in (req.get("headers") or {}).items():
        parts += ["-H", shlex.quote(f"{k}: {v}")]
    body = req.get("body")
    if body not in (None, ""):
        parts += ["--data-raw", shlex.quote(body if isinstance(body, str) else json.dumps(body))]
    return " ".join(parts)


def _window(text, needle, span=700):
    if needle and needle in text:
        i = text.index(needle)
        a, b = max(0, i - span // 2), min(len(text), i + len(needle) + span // 2)
        return ("[...]\n" if a else "") + text[a:b] + ("\n[...]" if b < len(text) else "")
    return text[:1500] + ("\n[...]" if len(text) > 1500 else "")


def response_excerpt(resp, needle=None):
    keep = ("content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin",
            "access-control-allow-credentials", "x-powered-by", "server")
    hdrs = "\n".join(f"{k}: {v}" for k, v in (resp.get("headers") or {}).items() if str(k).lower() in keep)
    body = resp.get("body") or ""
    body = body if isinstance(body, str) else json.dumps(body)
    return f"HTTP {resp.get('status')}\n{hdrs}\n\n{_window(body, needle)}".replace("\n\n\n", "\n\n")


def poc_steps(chain, evdir):
    """Markdown PoC: an optional negative control per edge, then the edge's own request/response, quoted from disk."""
    out, n, copied = [], 0, []
    for e in chain:
        for kind, path, needle in (("control", e.get("control"), None), ("edge", e.get("evidence"), e.get("must_contain"))):
            if not path:
                continue
            j, txt = _load_raw(path)
            if txt is None:
                continue
            n += 1
            dst = os.path.join(evdir, f"{n:02d}-{e['id']}-{kind}-{os.path.basename(path)}")
            shutil.copyfile(path if os.path.isabs(path) else os.path.join(WS, path), dst)
            copied.append(dst)
            title = (f"Step {n}: negative control for {e['frm']} -> {e['to']}" if kind == "control"
                     else f"Step {n}: {e['via']}  ({e['frm']} -> {e['to']})")
            out.append(f"**{title}**")
            if j:
                out.append("```bash\n" + curl_of(j["request"]) + "\n```")
                out.append("```http\n" + response_excerpt(j["response"], needle) + "\n```")
            else:
                out.append("```\n" + _window(txt, needle) + "\n```")
            if needle and kind == "edge":
                out.append(f"The response contains `{needle}`.")
    return "\n\n".join(out), copied


def hosts_of(chain):
    """Every host a proven edge's capture was taken on, terminal edge first (the crown's host is the asset)."""
    out = []
    for e in reversed(chain):
        j, _ = _load_raw(e.get("evidence") or "")
        if j:
            h = urllib.parse.urlsplit((j.get("request") or {}).get("url", "")).hostname or ""
            if h and h not in out:
                out.append(h)
    return out


def asset_of(chain):
    hs = hosts_of(chain)
    return hs[0] if hs else ""


def _dedup_stamp(program, host, today):
    """The Dedup: header line, TRUE to the public-dedup ledger: a verified verdict stamps 'public-checked', no
    verdict stamps NOT-YET-RUN with the exact command. Never a fabricated 'none' (the 2026-10-01 incident: a gate
    that only accepted good news manufactured good news)."""
    import gnoc_dedup
    res, row = gnoc_dedup.public_verdict(program, host)
    if res == "MATCH":
        return f"Dedup: public-checked {today} (dup{row.get('prior') or ''})", "MATCH", row
    if res == "NOVEL":
        return f"Dedup: public-checked {today} (novel:{row.get('angle') or ''})", "NOVEL", row
    if res is not None:
        return f"Dedup: public-checked {today} (none)", "none", row
    return (f"Dedup: NOT-YET-RUN {today} (scripts/learn/public-dedup.sh {program} {host or '<host>'} <class> "
            "<endpoint> --result none|MATCH:#N|NOVEL:<angle>)"), None, None


def _held(d, reasons, unlock):
    """HELD-REASON.md beside a draft that is written but must not be promoted: the floor rule's own shape
    (the user: the gates gate FILING, not WRITING - evidence is perishable, so the draft is written and held)."""
    lines = ["# HELD", "", "State: HELD, not QA-ready. Do not stage, do not promote to READY.", ""]
    lines += [f"- {r}" for r in reasons]
    lines += ["", f"**Unlock:** {unlock}", ""]
    with open(os.path.join(d, "HELD-REASON.md"), "w") as f:
        f.write("\n".join(lines))


def _ship_row(program, rel_report, title, score):
    """One `draft` row in ships.jsonl through the one sanctioned writer, so the office funnel, STATUS.md and
    the picker see a gnoc-built draft at all (they never did). Skipped for a program with no scope on disk (a unit
    fixture), and a refusal is reported, never raised."""
    if not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        return "ledger: skipped (no scope on disk)"
    row = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "program": program, "kind": "draft",
           "path": rel_report, "title": title, "severity": severity(score).lower()}
    try:
        r = subprocess.run([sys.executable, os.path.join(WS, "scripts/hunt-state.py"), "append-ship"],
                           input=json.dumps(row), capture_output=True, text=True, timeout=30, cwd=WS)
        return "ledger: draft row recorded" if r.returncode == 0 else f"ledger refused the row: {(r.stderr or r.stdout).strip()[:160]}"
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"ledger: not recorded ({type(e).__name__})"


WRITER = """You write the three prose fields of a bug bounty report from facts you are given. Return ONLY JSON:
{"title": "...", "summary": "...", "impact": "..."}
Rules: title under 120 characters, plain ASCII, no markdown, names the asset, the defect and the impact.
summary and impact are each at most 35 words, first person ("I"), plain prose, no hedging words (could, may,
might, possibly, potentially), no em dash, and claim nothing the facts do not show.
Write for a triager who decides on ONE read: the summary names the asset, the excluded actor, the single input and
what the attacker now holds; the impact names the new capability and whose data, money or account it reaches. If a
vendor promise is given, the summary says the runtime contradicts it. No taxonomy lecture, no "attacker could"."""


def write_gates(d, program, chain, vec, score, cwe, cvss_why, anchor, asset):
    """GATES.md beside the draft: the arithmetic and the judgment calls a reviewer or the user checks before filing.
    Nothing here goes into the report body (dedup stamp, footprint, probe counts stay out of the submission)."""
    import gnoc_dedup
    import gnoc_ident
    lines = [f"# GATES for this draft (program {program})", ""]
    lines += ["## CVSS derivation (T-102 / T-103)", f"Vector: {vec} = {score} {severity(score)}", ""]
    lines += [f"- {w}" for w in cvss_why]
    lines += ["", "## CWE (T-105: the weakness, not the effect)", f"{cwe}",
              "Neighbours to argue against: CWE-639 (owner key), CWE-862 (missing authz), CWE-287 (authn), "
              "CWE-200 (disclosure as an effect). Pick the one whose FIX removes the bug.", ""]
    lines += ["## Capability gate on the attacker's own premise (T-215)"]
    req = sorted({r for e in chain for r in (e.get("requires") or [])})
    ok, note = gnoc_doctrine.premise_gate(chain[0]["frm"], req, chain[-1]["to"])
    lines += [f"- start: {chain[0]['frm']}; preconditions: {', '.join(req) or 'none'}; {note}",
              f"- terminal {chain[-1]['to']}: {'OUTSIDE the premise' if ok else 'INSIDE the premise: ' + note}",
              "- still-a-bug test (T-216): if the maintainer agrees with every word, is it still a bug they must fix? "
              "Write the one-sentence answer here before filing: ", ""]
    kills = gnoc_doctrine.kill_match(open(os.path.join(d, "report.md"), encoding="utf-8", errors="replace").read())
    lines += ["## Pre-rejected shapes (our own closure history)"]
    lines += ([f"- READS LIKE: {n} ({snip!r}). The PoC must show the capability this shape lacks, or it closes Informative."
               for n, snip in kills] or ["- matches none of the 16 shapes"]) + [""]
    lines += ["## Negative controls per edge"]
    for e in chain:
        lines.append(f"- {e['id']} {e['frm']} -> {e['to']}: " + (f"control {e['control']}" if e.get("control") else
                                                                 f"no control ({e.get('control_na') or 'MISSING'})"))
    lok, lnote = gnoc_modes.prod_leg(chain, _load_raw)
    lines += ["", "## Production leg (RULE 6: 'only affects UAT, production is not impacted' closes N/A)",
              f"- {'OK' if lok else 'MISSING'}: {lnote}"]
    lines += ["", "## Vendor-doc anchor (SIG-2, I5)",
              (f"- {anchor}" if anchor else "- none recorded in the model. If the chain bypasses a documented control, "
                                           "web_fetch the live page, quote the sentence verbatim with its URL (T-207), "
                                           "put it in the Summary."), ""]
    try:
        n, dtext = gnoc_dedup.check(program, f"{asset} {chain[0]['via']} {chain[-1]['to']}")
    except Exception as ex:
        n, dtext = 0, f"dedup check failed: {type(ex).__name__}"
    lines += ["## Dedup stamp (stays here, never in the body)",
              f"- local verdict channels: {n} hit(s)", dtext if n else "",
              "- public channels have no discriminating power on an all-private program (T-213); say so, do not imply novelty.", ""]
    try:
        idents = gnoc_ident.listing(program)
    except Exception:
        idents = ""
    lines += ["## Footprint (T-113)",
              "- research accounts used: " + ("; ".join(l.split(":")[0] for l in idents.splitlines() if ":" in l and "headers" in l) or "none saved"),
              "- state created on the target that the vendor should know about (objects, orgs, deployments): ", ""]
    lines += ["## Raw Burp panels (MANDATORY on every decisive leg, Proxy history for any path-shape claim)"]
    pngs = [f for dp, _, fs in os.walk(d) for f in fs if f.lower().endswith(".png")]
    for e in chain:
        for kind in ("control", "edge"):
            path = e.get(kind == "edge" and "evidence" or "control")
            if path:
                stem = os.path.splitext(os.path.basename(path))[0]
                have = [f for f in pngs if stem[:12] in f]
                lines.append(f"- [{'x' if have else ' '}] {e['id']} {kind}: request + response panels for {path}"
                             + (f" ({len(have)} png)" if have else "  -> burp_panels(raw_path=...)"))
    lines.append("")
    with open(os.path.join(d, "GATES.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


def _prose(llm, facts, tries=3):
    feedback = ""
    for _ in range(tries):
        try:
            out = llm([{"role": "system", "content": WRITER},
                       {"role": "user", "content": facts + (f"\n\nYOUR LAST ATTEMPT FAILED THESE CHECKS, FIX THEM:\n{feedback}"
                                                             if feedback else "")}])
            import gnoc_learn
            objs = [o for o in gnoc_learn.json_objects(out) if "title" in o or "summary" in o]
            d = objs[0] if objs else {}
        except Exception as ex:
            d, feedback = {}, f"not valid JSON ({type(ex).__name__})"
            continue
        if not all(isinstance(d.get(k), str) and d[k].strip() for k in ("title", "summary", "impact")):
            feedback = "title, summary and impact must all be non-empty strings"
            continue
        probe = (f"CVSS: x\nAsset: x\nCWE: x\n\n# {d['title']}\n\n## Summary\n{d['summary']}\n\n## PoC\n```\nx\n```\n\n"
                 f"## Impact\n{d['impact']}\n")
        bad = [f"{name} ({detail})" for ok, name, detail in gnoc_gates.format_checks(probe)
               if not ok and not name.startswith("total")]
        if not bad:
            return d, None
        feedback = "; ".join(bad)
    return None, feedback


FATAL_ASSET = ("descoped", "not-submittable", "not-in-scope", "verify-only")


def family_slugs(program, slug):
    """The draft directories of one slug family: <fam>, <fam>-2, <fam>-5-2 ... where fam is the slug without its
    trailing -N suffixes."""
    fam = re.sub(r"(-\d+)+$", "", str(slug or ""))
    base = os.path.join(WS, "reports", "drafts", program)
    out = []
    try:
        for n in sorted(os.listdir(base)):
            if n == fam or (n.startswith(fam + "-") and re.fullmatch(r"\d+(-\d+)*", n[len(fam) + 1:])):
                out.append(n)
    except OSError:
        pass
    return out


def killed_family(program, slug):
    """(slug, first line of its newest GATE) for the newest gate-killed draft of the family, else None."""
    import glob as _glob
    for n in reversed(family_slugs(program, slug)):
        d = os.path.join(WS, "reports", "drafts", program, n)
        gates = sorted(_glob.glob(os.path.join(d, "GATE-*.md")), key=os.path.getmtime)
        for g in reversed(gates):
            try:
                first = open(g).read(400).strip().splitlines()[:1]
            except OSError:
                first = []
            if first:
                if first[0].strip().upper().startswith("KILL"):
                    return n, first[0].strip()
                break
    return None


def _finding_record(d, program, chain, copied, asset, prose, cwe, vec, score, venue, vrt_rec, held, dedup_res,
                    finder):
    """T1.5: the machine-readable twin of the draft (scripts/gnoc_finding.py schema 1). Identities are NAMES only;
    no header value, cookie or token enters the file, and request URLs pass through the secrets redactor."""
    import gnoc_finding as F
    try:
        import gnoc_oracle
        sealed = gnoc_oracle.is_sealed
    except Exception:  # noqa: BLE001
        def sealed(_p):
            return False
    try:
        from gnoc_secrets import redact
    except Exception:  # noqa: BLE001
        def redact(t):
            return t

    def absp(p):
        return p if os.path.isabs(p) else os.path.join(WS, p)
    rows, claims, steps = [], [], []
    for e in chain:
        if e.get("control"):
            rows.append({"edge": e["id"], "capture": e["control"], "sealed": sealed(absp(e["control"])),
                         "must_contain": "", "role": "negative-control"})
        rows.append({"edge": e["id"], "capture": e.get("evidence") or "", "sealed": sealed(absp(e.get("evidence") or "")),
                     "must_contain": e.get("must_contain") or "", "role": "sink-leg" if e is chain[-1] else "positive"})
    by_id = {e["id"]: e for e in chain}
    for k, dst in enumerate(copied, 1):
        base = os.path.basename(dst)
        m = re.match(r"\d+-(.+?)-(control|edge)-", base)
        e = by_id.get(m.group(1)) if m else None
        kind = m.group(2) if m else "edge"
        j, _ = _load_raw(dst)
        req, resp = (j or {}).get("request") or {}, (j or {}).get("response") or {}
        needle = (e or {}).get("must_contain") if kind == "edge" else None
        step = {"id": f"s{k}", "kind": "verify" if kind == "control" else "exploit",
                "action": {"type": "http", "method": req.get("method") or "GET", "url": redact(req.get("url") or "")},
                "capture": f"evidence/{base}",
                "expect": ({"type": "body-contains", "text": needle} if needle
                           else {"type": "http-status", "status": resp.get("status")})}
        steps.append(step)
        if needle and e:
            claims.append({"stance": "observation", "statement": f"{e['frm']} -> {e['to']} via {e['via']}"[:300],
                           "locator": f"evidence/{base}#{needle}", "source": "code:gnoc_report",
                           "load_bearing": True, "edge": e["id"]})
    status = "held" if held else "draft"
    cwe_id = re.search(r"CWE-\d+", cwe or "")
    ffam = F.family_of(finder) if finder else "unknown"
    return {"schema": 1, "id": f"{program}/{os.path.basename(d)}", "program": program, "venue": venue,
            "asset": asset, "title": prose["title"].strip(), "cwe": cwe_id.group(0) if cwe_id else (cwe or ""),
            "cvss": F.cvss_block(vec, score), "vrt": vrt_rec, "status": status, "workflow": F.WORKFLOW[status],
            "chain": rows, "poc_steps": steps, "claims": claims, "layers": [],
            "publishability": {"decision": "duplicate" if dedup_res == "MATCH" else "needs_verify",
                               "reason": ("public-dedup ledger MATCH" if dedup_res == "MATCH"
                                          else "not judged yet: report-killer by-design pass and dedup-scout decide"),
                               "refs": []},
            "decorrelation": {"finder_family": ffam, "refuter_family": "unknown", "cross_family": False},
            "finder": str(finder or "")}


def build(program, llm=None, slug=None, version="3.0", oracle_id=None, vrt=None, finder=None):
    """Write reports/drafts/<program>/<slug>/report.md + evidence/ from the best fully proven chain that can be
    FILED. Three outcomes, decided from facts on disk before a byte of draft is spent:
      refused  the asset can never be filed (a DESCOPED / not-submittable / out-of-scope row, or a slug naming one):
               no draft, the raw captures stay where they are, the message says what to record instead
      HELD     written in full with HELD-REASON.md: this account cannot file on the program today (T-254 signal),
               the terminal sits inside the attacker's premise (T-215), no production leg, or a confirmed public
               duplicate - evidence is perishable, so the draft exists, and it is never promoted
      written  with GATES.md, FORM.md, the two header stamps stated truthfully, a `draft` row in ships.jsonl and
               the instant code gate already run
    The 2026-10-19 inventory counted 8 drafts against assets that could not pay and one that closed duplicate in
    four minutes; every one of those is caught here now."""
    complete = [(sc, c) for sc, c in gnoc_hunt.chains(program, 10) if all(e["status"] == "proven" for e in c)]
    if not complete:
        return None, "refused: no fully proven chain in the ledger (hunt_chains shows what is missing)"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # the best chain whose asset can be filed; a fatal asset is named and skipped, never drafted
    skipped, chosen = [], None
    for sc, chain in complete:
        verdicts = [(h, *gnoc_pay.payability(program, h)) for h in hosts_of(chain)]
        fatal = [(h, v, why) for h, v, why, _ in verdicts if v in FATAL_ASSET]
        if fatal:
            skipped.append(f"chain to {chain[-1]['to']} (score {sc}): " + "; ".join(f"{v.upper()}: {why}" for _, v, why in fatal))
            continue
        chosen = (sc, chain, verdicts)
        break
    if chosen is None:
        return None, ("refused: every proven chain ends on an asset that can never be filed:\n  - "
                      + "\n  - ".join(skipped)
                      + "\nRecord it as a LEAD with the reason (record_outcome verdict=LEAD), or re-prove the chain on a "
                        "bounty row of the scope (pay_check shows them). A draft here would close Not Applicable.")
    sc, chain, verdicts = chosen
    crown = chain[-1]["to"]
    asset_host = verdicts[0][0] if verdicts else ""
    verdict, why, row = (verdicts[0][1], verdicts[0][2], verdicts[0][3]) if verdicts else ("unknown", "no capture host", None)
    asset = (row["asset"] if row else asset_host) or "(set the in-scope asset)"
    vec, score, cwe, cvss_why = suggest_cvss(chain, version)
    slug = re.sub(r"[^a-z0-9-]+", "-", (slug or f"{crown}-chain-{chain[0]['via'][:30]}").lower()).strip("-")[:60]
    named = gnoc_pay.name_match(program, slug + " " + chain_text(chain))
    if named:
        return None, ("refused: the slug / chain names an asset the program does not take reports on: "
                      + "; ".join(f"{r['asset']} [{'DESCOPED' if r['descoped'] else 'no-bounty / not submittable'}]" for r in named)
                      + ". Re-aim at a bounty row (pay_check), or record a LEAD.")
    # the judgment rows that need no draft: controls, premise, production leg; and the money rows
    pre = gnoc_gates.chain_checks_pre(program, chain)
    # venue dedup (API-less venues) needs real TITLE WORDS, not just the slug: the slug alone does not
    # overlap a filed title enough to catch a re-file, so hand it the slug plus the chain description.
    money = gnoc_gates.money_checks(program, asset_host, severity(score), slug,
                                    title=slug + " " + chain_text(chain))
    kills = gnoc_doctrine.kill_match(chain_text(chain))
    by = {name: (ok, detail) for ok, name, detail in pre + money}
    held, warns = [], []
    if not by["terminal outside the attacker's premise (T-215)"][0]:
        held.append("T-215: " + by["terminal outside the attacker's premise (T-215)"][1])
    if not by["production leg captured (RULE 6: staging-only closes N/A)"][0]:
        held.append("RULE 6: " + by["production leg captured (RULE 6: staging-only closes N/A)"][1])
    if not by["this account can file on the program (T-254)"][0]:
        held.append("FILING: " + by["this account can file on the program (T-254)"][1])
    import gnoc_oracle  # ORACLE: a deterministic-tier crown with no oracle PASS is HELD (Unlock: oracle PASS)
    oracle_id = oracle_id or gnoc_oracle.pick_oracle(program, crown, " ".join(  # ORACLE: the draft names ONE oracle
        f"{e.get('via')} {e.get('evidence')} {e.get('must_contain')}" for e in chain))
    oracle_hold = gnoc_oracle.draft_hold(program, crown, oracle_id)
    held += oracle_hold
    dedup_line, dedup_res, dedup_row = _dedup_stamp(program, asset_host, today)
    if dedup_res == "MATCH":
        held.append(f"PUBLIC DUPLICATE: prior {dedup_row.get('prior')} on {dedup_row.get('host')} {dedup_row.get('endpoint')} "
                    "(public-dedup ledger). 8 of our 12 H1 reports closed duplicate; this one needs a NOVEL angle")
    if not by["negative control on every edge"][0]:
        warns.append("no negative control on: " + by["negative control on every edge"][1])
    if not by["severity within the scope row's max"][0]:
        warns.append(by["severity within the scope row's max"][1])
    if verdict == "no-bounty":
        warns.append("asset is a no-bounty row: this is a VDP filing (it earns signal if resolved, never money)")
    elif verdict in ("unknown", "no-scope"):
        warns.append("payability unknown: " + why)
    if kills:
        warns.append("reads like a pre-rejected shape: " + "; ".join(n for n, _ in kills) + " (the PoC must show the capability)")
    if dedup_res is None:
        warns.append("public dedup NOT run for this host: run the command on the Dedup: line before READY")
    base = os.path.join(WS, "reports/drafts", program)
    d = os.path.join(base, slug)
    # D99 (cycle 26, 11:33Z): build_report minted gnoc-agent-20261025-h2-seam-race-5-2-2, the SEVENTH directory of a
    # chain whose earlier copies were gate-KILLED, and the lead declared it READY. A killed family is refused with
    # the kill in hand; an existing directory is edited, never copied.
    killed = killed_family(program, slug)
    if killed:
        return None, (f"refused: this chain's draft was gate-KILLED ({killed[0]}: {killed[1][:160]}). A new copy is "
                      "the same report. Fix what the kill names (re-prove the edge with a capture that sends the "
                      "input and a control that differs in one variable), then build under a NEW slug that names "
                      "the new mechanism.")
    if os.path.exists(d):
        return None, (f"refused: {os.path.relpath(d, WS)} exists; edit it in place (write_file) or pass a new slug. "
                      "No -N copies.")
    evdir = os.path.join(d, "evidence")
    os.makedirs(evdir)
    poc, copied = poc_steps(chain, evdir)
    promises = gnoc_hunt.load(program)["model"].get("promises") or []
    anchor = next((pm for pm in promises if gnoc_doctrine._terms(pm) & gnoc_doctrine._terms(chain_text(chain))), "")
    facts = (f"Asset: {asset}\nCrown capability reached: {crown}\nStarting point: {chain[0]['frm']}\nWeakness: {cwe}\n"
             f"Chain:\n" + "\n".join(f"- {e['frm']} -> {e['to']} via {e['via']} (proven by bytes: {e.get('must_contain') or 'see PoC'})"
                                      for e in chain)
             + (f"\nVendor's documented promise this violates (quote it in the summary, verbatim): {anchor}" if anchor else ""))
    prose, why_prose = _prose(llm, facts) if llm else (None, "no model")
    if not prose:
        prose = {"title": f"{crown.upper()} on {asset} via {chain[0]['via']}"[:118].encode("ascii", "ignore").decode(),
                 "summary": f"Starting as {chain[0]['frm']}, I reached {crown} on {asset} through a {len(chain)}-step "
                            f"chain; every step below is quoted from captured responses.",
                 "impact": f"I hold the {crown} capability on {asset} without any privilege the chain did not "
                           f"start from, as the final captured response shows."}
    header = (f"CVSS: {vec} = {score} {severity(score)}\nAsset: {asset}\nCWE: {cwe}\n"
              f"Gate: report-killer NOT-YET-RUN {today}\n{dedup_line}\n")
    text = (header + f"\n# {prose['title'].strip()}\n\n"
            f"## Summary\n{prose['summary'].strip()}\n\n## PoC\n{poc}\n\n## Impact\n{prose['impact'].strip()}\n")
    with open(os.path.join(d, "report.md"), "w") as f:
        f.write(text)
    with open(os.path.join(d, "FORM.md"), "w") as f:  # the platform's own fields, scripts/make-form.sh's shape
        f.write(f"Title: {prose['title'].strip()}\nAsset: {asset}\nCWE: {cwe}\nCVSS: {vec} {score} {severity(score)}\n"
                f"Venue: {program}\n\n# Generated by gnoc_report.build from the draft header. VERIFY every line against\n"
                "# the programme policy before filing.\n")
    write_gates(d, program, chain, vec, score, cwe, cvss_why, anchor, asset)
    with open(os.path.join(d, "GATES.md"), "a") as f:
        f.write("\n## Money and filing (gnoc_pay, decided before the draft was written)\n"
                + "\n".join(f"- [{'x' if ok else ' '}] {name}" + (f": {detail}" if detail else "") for ok, name, detail in money)
                + f"\n\nOracle: {oracle_id or 'none'}\n")  # ORACLE: draft_hold is keyed by this id
    # T1.5: the Bugcrowd P3 floor in code (GreyNOC 2026-11-05). SPINE 4: the floor gates FILING, not WRITING, so a
    # sub-P3 (or unresolved, or priority-null) Bugcrowd draft is written in full and HELD with an Unlock line.
    import gnoc_finding
    venue = gnoc_finding._venue(program)
    vrt_rec = {}
    if vrt:
        vr = gnoc_finding.vrt_resolve(vrt)
        vrt_rec = {"id": str(vrt), "priority": vr["priority"] if vr else None, "source": gnoc_finding.vrt_source()}
    vrt_ok, vrt_why = gnoc_finding.vrt_check({"venue": venue, "vrt": vrt_rec})
    if not vrt_ok:
        held.append("BUGCROWD P3 FLOOR: " + vrt_why)
    if held:
        _held(d, held, ("oracle PASS; then " if any(r.startswith("ORACLE") for r in oracle_hold) else "")  # ORACLE
              + ("escalate to a P3+ VRT leaf: scripts/bbtools/vrt.py --search <class>; then " if not vrt_ok else "")
              + "clear every line above; a HELD draft is never promoted to READY")
    rel = os.path.relpath(d, WS)
    ledger = _ship_row(program, os.path.join(rel, "report.md"), prose["title"].strip(), score)
    gate_verdict, nbad = gnoc_gates.write_format_gate(d, program)
    finding_note = ""
    try:   # T1.5 + T1.6: finding.json with its first two layer rows, then the evidence manifest (snapshot)
        gnoc_finding.write(d, _finding_record(d, program, chain, copied, asset, prose, cwe, vec, score, venue,
                                              vrt_rec, held, dedup_res, finder))
        gnoc_finding.append_layer(d, "build", "downgrade" if held else "pass",
                                  "HELD: " + "; ".join(held)[:300] if held else "draft written from a proven chain",
                                  by="code:gnoc_report", family="code")
        gnoc_finding.append_layer(d, "format", "pass" if not nbad else "reject", f"{gate_verdict} ({nbad} failing)",
                                  by="code:gnoc_gates", family="code")
        gnoc_finding.manifest(d)
        ferrs = gnoc_finding.validate(d)
        finding_note = (f" finding.json + evidence/MANIFEST.json written ({len(ferrs)} validator note(s)"
                        + (f": {ferrs[0][:120]}" if ferrs else "") + ").")
    except Exception as e:  # noqa: BLE001 - the record is additive; a failure is reported, the draft stands
        finding_note = f" finding.json NOT written ({type(e).__name__}: {str(e)[:120]})."
    note = "" if not why_prose else f" (model prose failed the format checks: {why_prose[:160]}; a plain template was used)"
    head = f"HELD draft {rel}/report.md" if held else f"draft {rel}/report.md"
    msg = [f"{head}: {crown} chain, prestige {sc}, suggested {vec} = {score} {severity(score)}, "
           f"{len(copied)} captures quoted into the PoC{note}. Asset row: {why}. {ledger}.{finding_note}"]
    if skipped:
        msg.append("skipped chains on assets that cannot be filed: " + " | ".join(skipped))
    if held:
        msg.append("HELD (see HELD-REASON.md; written because evidence is perishable, NOT filable as it stands):\n  - "
                   + "\n  - ".join(held))
    if warns:
        msg.append("fix before READY:\n  - " + "\n  - ".join(warns))
    msg.append(f"instant code gate: {gate_verdict} ({nbad} failing; {rel}/GATE-local-format.md). "
               + ("Do NOT call ship_chain on a HELD draft; clear the hold first." if held else
                  f"Next: fix the lines above, then ship_chain {rel}"))
    return rel, "\n".join(msg)
