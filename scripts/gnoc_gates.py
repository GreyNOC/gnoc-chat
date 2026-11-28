"""gnoc_gates.py - the ship gates run entirely on the user's own machine (offline mode, no cloud model).

Two layers, both written into the draft dir:
  1. CODE checks (deterministic, instant)  -> GATE-local-format.md
     the reports/REPORT-FORMAT.md shape: CVSS / Asset / CWE header, one '# ' title under 120 ASCII chars with no
     markdown, the three sections Summary / PoC / Impact, Summary and Impact each <= 35 words, total <= 1000
     words, no em dash, no hedging words ("could", "may", "might", "an attacker could"), fenced code in the PoC;
     plus every evidence path named in CHAIN.md re-checked on disk (exists, non-empty, holds its claimed bytes)
  2. LOCAL MODEL reviews, one per role, on the local GPUs  -> GATE-local-<role>.md
     reviewer (constructive, fix list), killer (hostile triager trying to close it), repro (reproduce the PoC
     from the report's own bytes). Each must start with PASS, FIXABLE or KILL.
These mirror the Claude gates (reviewer-agent, report-killer, report-repro-checker). They are weaker judges than
the cloud gates, so their verdict is advisory: nothing is filed either way, filing stays the user's call.
"""
import json
import os
import re
from datetime import datetime, timezone

import gnoc_doctrine
import gnoc_hunt
import gnoc_modes

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _read_strict as _read

HEDGE = re.compile(r"\b(could|might|may|possibly|potentially|an attacker could|it is possible)\b", re.I)
ROLES = {
    "reviewer": "You are a senior bug-bounty report reviewer. Check that every claim maps to a captured byte in the "
                "PoC, that the PoC is copy-paste complete and ends at the terminal action, that severity matches "
                "what was captured, and that the CWE names the weakness. Constructive: list exact fixes.",
    "killer": "You are a hostile triager whose job is to CLOSE this report: by design, duplicate-shaped, no new "
              "capability for the attacker, out of scope, broken PoC, a mechanism with no terminal impact, a chain "
              "with an unproven link. Price the PRECONDITIONS first: list what the attacker's own premise already "
              "grants (an account, a victim click, a leaked secret, script on an origin) and kill if the terminal sits "
              "inside it. Then the still-a-bug test: if the maintainer agrees with every word, must they still fix "
              "something? These shapes closed Informative on this very account, kill on sight unless the PoC shows the "
              "missing capability in bytes: " + "; ".join(n for n, _ in gnoc_doctrine.KILL_SHAPES) + ". "
              "Try every reason. If one holds, say KILL and quote the line that dies.",
    "repro": "You are a triager with zero context reproducing this report from its own text: walk each PoC step, "
             "check the request would produce the response shown, check the response bytes support every claim in "
             "Summary and Impact. Report the first step that does not reproduce.",
}
VERDICT = re.compile(r"^\W*(PASS|FIXABLE|KILL)\b", re.I | re.M)




def _section(text, name):
    m = re.search(rf"(?ims)^##\s*{name}\s*$(.*?)(?=^##\s|\Z)", text)
    return m.group(1).strip() if m else None


def _words(t):
    # fenced text counts too: a 120-word Summary wrapped in ``` once scored "1 words" against the 35 cap
    return len(re.findall(r"\S+", re.sub(r"```\w*", " ", t or "")))


def format_checks(report_text):
    """[(ok, check, detail)] for the REPORT-FORMAT shape."""
    t = report_text if isinstance(report_text, str) else ""
    out = []
    for h in ("CVSS:", "Asset:", "CWE:"):
        out.append((bool(re.search(rf"(?m)^{h}\s*\S", t)), f"header {h}", ""))
    # fenced blocks are stripped first: a '# comment' at column 0 in the PoC read as a second '# ' title
    titles = re.findall(r"(?m)^# (.+)$", re.sub(r"(?ms)^```.*?^```", "", t))
    title = titles[0] if titles else ""
    out.append((len(titles) == 1, "one '# ' title", f"{len(titles)} found"))
    out.append((bool(title) and len(title) < 120 and title.isascii() and not re.search(r"[`*|#]", title),
                "title < 120 ASCII chars, no markdown", title[:120]))
    for name, cap in (("Summary", 35), ("PoC", None), ("Impact", 35)):
        body = _section(t, name)
        out.append((body is not None, f"section {name}", ""))
        if body is not None and cap:
            n = _words(body)
            out.append((n <= cap, f"{name} <= {cap} words", f"{n} words"))
            hedges = sorted(set(m.group(0).lower() for m in HEDGE.finditer(body)))
            out.append((not hedges, f"{name} has no hedging", ", ".join(hedges)))
    poc = _section(t, "PoC") or ""
    out.append(("```" in poc, "PoC has fenced commands/responses", ""))
    total = _words(t)
    out.append((total <= 1000, "total <= 1000 words", f"{total} words"))
    out.append(("—" not in t, "no em dash", f"{t.count(chr(0x2014))} found"))
    return out


def sink_freshness(chain, load_raw, days=7):
    """T-76 as code: a draft is unverified until its SINK was re-fired on the day of filing. app.example.com hardened a
    surface between 2026-10-06 and 2026-10-22 and the draft would have closed not-reproducible. No gate checked a
    capture's AGE, so a three-week-old receipt shipped as if it were today's. This reports the age of the newest
    PROVEN edge capture and refuses one older than `days`; it cannot know the day of filing, so a stale chain asks
    for a re-fire rather than claiming freshness. An unreadable timestamp is stale: a capture I cannot date is one
    I cannot say is current."""
    if not chain:
        return True, "no chain to age"
    newest, oldest_proven = None, None
    for e in chain:
        if e.get("status") != "proven" or not e.get("evidence"):
            continue
        j, _ = load_raw(e["evidence"])
        ts = str((j or {}).get("ts") or "").strip()
        if not ts:
            oldest_proven = oldest_proven or f"edge {e['id']} has no capture timestamp"
            continue
        try:
            t = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            oldest_proven = oldest_proven or f"edge {e['id']} has an unreadable timestamp ({ts[:24]})"
            continue
        newest = t if newest is None or t > newest else newest
    if newest is None:
        return (False, oldest_proven or "no dated receipt on any proven edge; re-fire the sink before filing")
    age = (datetime.now(timezone.utc) - newest).days
    if age > days:
        return False, (f"newest proven-edge capture is {age} days old (T-76); re-fire the sink on the production host "
                       "before filing and point the edge at today's capture")
    return True, f"newest proven-edge capture is {age} day(s) old"


def chain_checks(draft_dir, program, load_raw=None):
    """Re-verify every evidence path of the proven chain on disk, and how old it is."""
    out = []
    complete = [c for _, c in gnoc_hunt.chains(program, 10) if all(e["status"] == "proven" for e in c)]
    if not complete:
        return [(True, "chain evidence", "no proven chain in the ledger; report judged on its own evidence")]
    for e in complete[0]:
        ok, why = gnoc_hunt.check_evidence(e["evidence"], e.get("must_contain"))
        out.append((ok, f"edge {e['id']} {e['frm']} -> {e['to']} evidence", why if not ok else e["evidence"]))
    ok, why = sink_freshness(complete[0], load_raw or _raw_json)
    out.append((ok, "sink re-fired recently (T-76, capture under 7 days old)", why))
    return out


INTERNAL = re.compile(r"(\btargets/[\w.-]+/|\breports/(drafts|submitted|leads|archive)/|\.claude/|\bT-\d{2,3}\b|"
                      r"\bSPINE\b|hunt-loop|report-killer|reviewer-agent|triage-validator|gnoc[ _-]?(chat|agent))")
_FENCE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
# A repro command is not always an HTTP one. A local / source-code finding (an OSS repo asset) reproduces with
# git, go, podman, kubectl or a shell builtin, and this regex only knew web tooling: on
# an OSS draft it reported "0 command line(s)" for a PoC with five, and the
# same lines then fell through to the quoted-bytes row and were demanded in a capture file (one bug, two failures).
_CMD = re.compile(r"^\s*(\$\s*)?(curl|python3?|bash|sh|node|wget|http|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
                  r"|git|go|cargo|npm|npx|yarn|make|docker|podman|kubectl|helm|setpriv|sudo|ln|cp|mv|rm|mkdir|chmod"
                  r"|chown|cd|export|echo|cat|openssl|ssh|nc|java|javac|gcc|mvn|gradle|pip3?|GITSYNC=)\b")


def _corpus(draft_dir):
    """Every capture the draft ships with or cites: files under the draft dir (not the report prose, not images)
    plus every workspace path the report names."""
    chunks = []
    for dp, _, fs in os.walk(draft_dir):
        for f in fs:
            # THE DRAFT IS NOT ITS OWN EVIDENCE (T-271). This skip used to be
            # f.startswith(("report", "GATE")), which a LEADING DOT defeats: `.report.submitted-view.md`
            # is a byte-identical copy of the report, so every line the report quoted was "found in a
            # capture" because the gate was reading the report back to itself. The row passed 16/16 on
            # an OSS repo while an independent extractor found 10 of those lines in NO capture at
            # all (2026-10-28). Strip leading dots before the test, and treat every markdown sidecar at
            # the draft root as prose: real captures live in evidence/, not in a .md next to report.md.
            name = f.lstrip(".")
            prose_md = name.endswith(".md") and (os.path.realpath(dp) == os.path.realpath(draft_dir)
                                                 or name.startswith(("report", "GATE")))
            if prose_md or f.lower().endswith((".png", ".jpg", ".pdf")):
                continue
            fp = os.path.join(dp, f)
            try:  # a dangling symlink or a file removed mid-walk is not a reason to abort the gate
                if os.path.getsize(fp) < 5_000_000:
                    chunks.append(_capture_text(fp))
            except OSError:
                continue
    text = _read(os.path.join(draft_dir, "report.md"))
    for rel in set(re.findall(r"\b((?:targets|reports)/[\w./@%+-]+)", text)):
        fp = os.path.join(gnoc_hunt.WS, rel)
        if os.path.isfile(fp) and os.path.getsize(fp) < 5_000_000:
            chunks.append(_capture_text(fp))
    return "\n".join(chunks)


def _capture_text(fp):
    """A capture file's text PLUS its decoded request / response bodies when it is a gnoc raw JSON capture: on
    disk a body byte like "x":"y" is stored escaped (\\"x\\":\\"y\\"), and the report quotes the decoded form."""
    raw = _read(fp)
    try:
        j = json.loads(raw)
    except ValueError:
        return raw
    extra = []
    if isinstance(j, dict):
        for side in ("request", "response"):
            b = (j.get(side) or {}).get("body") if isinstance(j.get(side), dict) else None
            if b:
                extra.append(b if isinstance(b, str) else json.dumps(b))
            h = (j.get(side) or {}).get("headers") if isinstance(j.get(side), dict) else None
            if isinstance(h, dict):
                extra += [f"{k}: {v}" for k, v in h.items()]
    return raw + "\n" + "\n".join(extra)


def _norm(t):
    return " ".join(t.split())


_HTTP_REQ = re.compile(r"^\s*(\$\s*)?(curl\b|wget\b|https?://|(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S)")
_HTTP_RESP = re.compile(r"\bHTTP/[0-9.]+\b|^\s*HTTP\s+[1-5][0-9][0-9]\b", re.M)


def _has_http_leg(poc):
    """True when this PoC actually talks HTTP: a request line (curl/wget/URL/method) or an HTTP status in a quoted
    block. Decides whether the Burp-panel row applies at all; a finding with no wire traffic cannot carry a panel."""
    for b in _FENCE.findall(poc or ""):
        if _HTTP_RESP.search(b):
            return True
        for ln in b.splitlines():
            if _HTTP_REQ.match(ln):
                return True
    return False


def repro_checks(draft_dir):
    """The post-write repro gate, in code: quoted response bytes exist in a capture, raw Burp panels are attached,
    the PoC is copy-paste commands, and the body carries no internal references."""
    text = _read(os.path.join(draft_dir, "report.md"))
    poc = _section(text, "PoC") or ""
    out = []
    blocks = _FENCE.findall(poc)
    cmds = [ln for b in blocks for ln in b.splitlines() if _CMD.match(ln)]
    out.append((bool(cmds), "PoC carries copy-paste commands", f"{len(cmds)} command line(s)"))
    quoted = [ln.strip() for b in blocks for ln in b.splitlines()
              if len(ln.strip()) >= 16 and not _CMD.match(ln) and not ln.strip().startswith(("#", "-H ", "--"))]
    corpus = _norm(_corpus(draft_dir))
    missing = [q for q in quoted if _norm(q) not in corpus]
    ok = not quoted or len(missing) <= max(0, len(quoted) // 10)
    out.append((ok, "quoted bytes found in a capture on disk",
                f"{len(quoted) - len(missing)}/{len(quoted)} lines matched"
                + (f"; first unmatched: {missing[0][:90]!r}" if missing else "")))
    pngs = [f for dp, _, fs in os.walk(draft_dir) for f in fs if f.lower().endswith(".png")]
    burp = [f for f in pngs if re.search(r"burp|panel|req|resp", f, re.I)]
    # Panels are mandatory on every HTTP leg (SPINE 5 EVIDENCE GRADE, T-248) and IMPOSSIBLE without one. A local
    # source-code finding sends no request, so there is no panel that could exist; demanding one there is a false
    # positive that teaches the next agent to ignore the row. The row is skipped ONLY when the PoC shows no HTTP leg
    # at all, so a web finding can never buy its way out of it.
    if not _has_http_leg(poc):
        out.append((True, "raw Burp request+response panels attached",
                    "no HTTP leg in this PoC (no request line, no HTTP status in any quoted block): panels are "
                    "structurally N/A, not skipped. State why in GATES.md"))
    else:
        out.append((len(burp) >= 2, "raw Burp request+response panels attached", f"{len(burp)} panel image(s)"))
    leaks = sorted(set(m.group(0) for m in INTERNAL.finditer(text)))
    out.append((not leaks, "no internal references in the report body", ", ".join(leaks[:6])))
    return out


# ---- claim checks (2026-10-26) ------------------------------------------------------------------------------
# Receipt: GreyNOC was handed `program-0/gnoc-agent-20261025-h2-seam-race-5-2-2` as a "Critical ATO 9.1, capability
# gate satisfied, dedup stamp present" and asked for it to be readied. Its whole PoC was
#   GET  /api/event_logging/v2/batch -> 405      ("negative control")
#   POST /api/event_logging/v2/batch -> 200 {"accepted_count":0,"rejected_count":0}
# a public telemetry route counting zero events, whose control varied the HTTP METHOD. Five sibling copies claimed
# cross-user-read off a `"concurrent":true` field with the SAME Next.js shell as both control and evidence (T-60).
# Every row in GATE-local-format.md was ticked, because each asks "is there a value here" and none asks "does this
# value name a byte that the control does NOT carry". These four do, from the report's own bytes.
_STAMP = re.compile(r"^(Gate|Dedup):\s*(.+)$", re.M)
_UNRUN = re.compile(r"NOT-YET-RUN", re.I)
_EXCUSED = re.compile(r"\s*\(")
_STATUS = re.compile(r"^\s*(?:HTTP/[\d.]+\s+)?HTTP\s+(\d{3})\b|^\s*HTTP/[\d.]+\s+(\d{3})\b", re.M)
_METHOD = re.compile(r"-X\s+([A-Z]+)\b")
_URL = re.compile(r"https?://[^\s'\"<>]+")


def _poc_steps(poc):
    """[(command_block, response_block)] in PoC order. A fence is a command block when its first matching line is a
    shell command, else it is the response to the command block before it."""
    steps, pending = [], None
    for b in _FENCE.findall(poc):
        if any(_CMD.match(ln) for ln in b.splitlines()):
            if pending is not None:
                steps.append((pending, ""))
            pending = b
        elif pending is not None:
            steps.append((pending, b))
            pending = None
    if pending is not None:
        steps.append((pending, ""))
    return steps


def _status_of(block):
    m = _STATUS.search(block or "")
    return int(m.group(1) or m.group(2)) if m else 0


def _body_of(block):
    """The response block minus its status line and headers: everything after the first blank line."""
    parts = (block or "").split("\n\n", 1)
    return _norm(parts[1] if len(parts) > 1 else parts[0])


def claim_checks(draft_dir):
    """Four checks a hollow draft cannot tick. A failure here is a KILL, not a FIXABLE: the prose is not the
    problem, the finding is not there."""
    text = _read(os.path.join(draft_dir, "report.md"))
    out = []

    # 1. the draft's OWN stamps. The agent's summary said the dedup stamp was present while the body read
    #    'Dedup: NOT-YET-RUN'; a stamp that says it never ran is the draft telling you it is not ready.
    #    A channel that did not run FOR A STATED REASON is fine, and the house writes that reason in brackets
    #    right after it ("GHSA/CVE:NOT-YET-RUN (hosted service, no packaged component)"), so an unrun marker
    #    followed immediately by '(' is excused. A usage hint after a date is not a reason.
    unrun = []
    for k, v in _STAMP.findall(text):
        for m in _UNRUN.finditer(v):
            if not _EXCUSED.match(v, m.end()):
                unrun.append(f"{k}: ...{v[max(0, m.start() - 40):m.end() + 12].strip()}")
    out.append((not unrun, "report-killer and public dedup have actually run", "; ".join(unrun[:3])))

    steps = _poc_steps(_section(text, "PoC") or "")
    ctl, edge = (steps[0] if steps else ("", "")), (steps[-1] if steps else ("", ""))

    # 2. the control must not be a 405 on the edge's own URL: that measures the route's method table, not a
    #    boundary (T-31, one security-relevant variable).
    same_url = bool(_URL.search(ctl[0] or "")) and (
        _URL.search(ctl[0] or "") and _URL.search(edge[0] or "")
        and _URL.search(ctl[0]).group(0) == _URL.search(edge[0]).group(0))
    cm = _METHOD.search(ctl[0] or "")
    em = _METHOD.search(edge[0] or "")
    method_only = len(steps) > 1 and same_url and cm and em and cm.group(1) != em.group(1)
    bad_405 = bool(method_only and _status_of(ctl[1]) in (404, 405))
    out.append((not bad_405, "the negative control is not a method-table answer",
                f"control is {cm.group(1) if cm else '?'} -> {_status_of(ctl[1])} on the same URL the edge "
                f"{em.group(1) if em else '?'}s; vary the credential or the owner key, not the HTTP method"
                if bad_405 else ""))

    # 3. control and edge must not be the same page (the SPA soft-200, T-60): an index.html served for every path
    #    is both arms of the comparison at once.
    cb, eb = _body_of(ctl[1]), _body_of(edge[1])
    big = min(len(cb), len(eb)) >= 400
    near = big and (cb == eb or abs(len(cb) - len(eb)) <= 0.02 * max(len(cb), len(eb)))
    html = eb.lstrip().lower().startswith(("<!doctype html", "<html"))
    same_page = bool(len(steps) > 1 and near and (html or cb[:200] == eb[:200]))
    out.append((not same_page, "control and terminal are not the same response body",
                f"both arms are {len(eb)} chars of the same {'HTML shell' if html else 'body'}; "
                "an SPA answers 200 + index.html for every path, so neither arm proves anything" if same_page else ""))

    # 4. a copy of a family another gate already killed (the seven h2-seam-race directories).
    stem = re.sub(r"(-\d+)+$", "", os.path.basename(os.path.realpath(draft_dir)))
    parent = os.path.dirname(os.path.realpath(draft_dir))
    killed = []
    if stem:
        for sib in sorted(os.listdir(parent) if os.path.isdir(parent) else []):
            sp = os.path.join(parent, sib)
            if sp == os.path.realpath(draft_dir) or not os.path.isdir(sp):
                continue
            if not (sib == stem or sib.startswith(stem + "-")):
                continue
            for f in sorted(os.listdir(sp)):
                if f.startswith("GATE") and f.endswith(".md") and _read(os.path.join(sp, f)).lstrip()[:4] == "KILL":
                    killed.append(f"{sib}/{f}")
                    break
    out.append((not killed, "no sibling copy of this slug was already killed", ", ".join(killed[:4])))
    return out


def draft_state(draft_dir):
    """'KILL' / 'HELD' / 'gated' / '' for one draft directory, from the files the gates leave behind.

    A plain directory listing says only which folder is newest, and the newest folder is routinely a
    gate-KILLED copy: asked for the newest draft, the agent named a KILLED h2-seam-race iteration as if it
    were live work (2026-10-26). Whoever lists drafts needs the verdict in the same breath as the name.
    """
    try:
        names = sorted(os.listdir(draft_dir))
    except OSError:
        return ""
    gates = [n for n in names if n.startswith("GATE") and n.endswith(".md")]
    for n in gates:
        if _read(os.path.join(draft_dir, n)).lstrip()[:4] == "KILL":
            return "KILL"
    if "HELD-REASON.md" in names:
        return "HELD"
    return "gated" if gates else ""


def _raw_json(path):
    p = path if os.path.isabs(path) else os.path.join(gnoc_hunt.WS, path)
    try:
        j = json.loads(_read(p))
        return (j if isinstance(j, dict) and "request" in j else None), ""
    except (OSError, ValueError):
        return None, ""


def chain_checks_pre(program, chain):
    """The judgment rows that need no draft on disk: a control per edge, the premise gate, the production leg.
    They used to run only AFTER a draft was written (expert_checks); a chain that fails them should never cost a
    draft, so gnoc_report.build asks here first."""
    out = []
    ok, missing = gnoc_hunt.ship_ready(chain)
    out.append((ok, "negative control on every edge", "; ".join(missing)))
    req = sorted({r for e in chain for r in (e.get("requires") or [])})
    pok, note = gnoc_doctrine.premise_gate(chain[0]["frm"], req, chain[-1]["to"])
    out.append((pok, "terminal outside the attacker's premise (T-215)", note if not pok else ""))
    lok, lnote = gnoc_modes.prod_leg(chain, _raw_json)
    out.append((lok, "production leg captured (RULE 6: staging-only closes N/A)", lnote))
    sok, snote = gnoc_modes.source_leg(chain, _raw_json)
    out.append((sok, "SOURCE state produced on the production path (RULE 1, second leg)", snote))
    return out


def money_checks(program, host, severity=None, slug="", title=""):
    """Can this finding PAY and can we FILE it (gnoc_pay)? Rows, not refusals: build() decides which are fatal.
    Every one of these is a fact already on disk; none needs the model's opinion."""
    import gnoc_pay
    out = []
    verdict, why, row = gnoc_pay.payability(program, host) if host else ("unknown", "no asset host on the chain", None)
    fatal = verdict in ("descoped", "not-submittable", "not-in-scope", "verify-only")
    out.append((not fatal, f"asset can be filed ({gnoc_pay.VERDICT_WORD.get(verdict, verdict)})", why))
    if verdict == "no-bounty":
        out.append((True, "asset pays", "no-bounty row: a VDP filing, counts for signal, pays nothing"))
    elif verdict in ("unknown", "no-scope"):
        out.append((True, "asset pays", why))
    else:
        out.append((verdict == "pays" or not fatal, "asset pays", why))
    hits = gnoc_pay.name_match(program, slug)
    out.append((not hits, "slug names no descoped / no-bounty asset",
                "; ".join(f"{r['asset']} [{'DESCOPED' if r['descoped'] else 'no-bounty'}]" for r in hits)))
    cap = gnoc_pay.severity_cap(row, severity) if row else None
    out.append((not cap, "severity within the scope row's max", cap or ""))
    # `title` matters on an API-less venue: our own filed-report list is the ONLY dedup channel there,
    # and the slug alone does not overlap a real title enough to catch a re-file (2026-10-28 receipt).
    fok, fwhy = gnoc_pay.filing_gate(program, title=title or slug)
    out.append((fok, "this account can file on the program (T-254)", fwhy))
    return out


def expert_checks(draft_dir, program):
    """The judgment gates in code: pre-rejected shape, premise gate, a control per edge, a GATES.md on disk."""
    text = _read(os.path.join(draft_dir, "report.md"))
    out = []
    kills = gnoc_doctrine.kill_match(text)
    out.append((not kills, "not a pre-rejected shape", "; ".join(n for n, _ in kills)))
    complete = [c for _, c in gnoc_hunt.chains(program, 10) if all(e["status"] == "proven" for e in c)]
    if complete:
        out += chain_checks_pre(program, complete[0])
    out.append((os.path.isfile(os.path.join(draft_dir, "GATES.md")), "GATES.md written (CVSS arithmetic, dedup, panels)", ""))
    return out


def write_format_gate(draft_dir, program):
    text = _read(os.path.join(draft_dir, "report.md"))
    claims = claim_checks(draft_dir)
    rows = (format_checks(text) + repro_checks(draft_dir) + claims + chain_checks(draft_dir, program)
            + expert_checks(draft_dir, program))
    bad = [r for r in rows if not r[0]]
    # a failed CLAIM check is never FIXABLE: editing the prose cannot put a capability in the capture
    fatal = [r for r in bad if r[1].startswith("edge") or r in claims]
    verdict = "PASS" if not bad else ("KILL" if fatal else "FIXABLE")
    lines = [verdict, "", "Local code checks (gnoc_gates.py, offline):", ""]
    lines += [f"- [{'x' if ok else ' '}] {name}" + (f": {d}" if d else "") for ok, name, d in rows]
    with open(os.path.join(draft_dir, "GATE-local-format.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    return verdict, len(bad)


def model_gate(llm, draft_dir, role):
    """One local-model gate. llm(messages) -> text. Writes GATE-local-<role>.md, returns the verdict."""
    report = _read(os.path.join(draft_dir, "report.md"))[:14000]
    chain = ""
    cp = os.path.join(draft_dir, "CHAIN.md")
    if os.path.isfile(cp):
        chain = _read(cp)[:4000]
    out = llm([{"role": "system", "content": ROLES[role] + " Answer in English. The FIRST line of your answer is "
                                                           "exactly one word: PASS, FIXABLE or KILL. Then the reasons, "
                                                           "each tied to a quoted line of the report."},
               {"role": "user", "content": f"REPORT:\n{report}\n\nCHAIN AND EVIDENCE PATHS:\n{chain or '(none)'}"}])
    m = VERDICT.search(out or "")
    verdict = m.group(1).upper() if m else "UNCLEAR"
    with open(os.path.join(draft_dir, f"GATE-local-{role}.md"), "w") as f:
        f.write((out or "(empty answer)").strip() + "\n")
    return verdict


def run_all(llm, draft_dir, program):
    """Code checks, then the three model roles. Returns {gate: verdict}."""
    res = {"format": write_format_gate(draft_dir, program)[0]}
    for role in ROLES:
        try:
            res[role] = model_gate(llm, draft_dir, role)
        except Exception as e:
            res[role] = f"ERROR {type(e).__name__}"
    with open(os.path.join(draft_dir, "GATES-local.md"), "w") as f:
        f.write("Local ship gates (offline, no cloud model). Advisory: filing stays the user's call.\n\n"
                + "\n".join(f"- {k}: {v}  (GATE-local-{k}.md)" for k, v in res.items()) + "\n")
    return res
