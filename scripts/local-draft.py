#!/usr/bin/env python3
"""local-draft.py - turn a TIER-3 escalation into a HELD report draft using only the local model. No cloud tokens.

  local-draft.py <escalation-dir>            write reports/drafts/<program>/auto-<slug>/ (refuses if it exists)
  local-draft.py --pending [program]         list TIER-3 escalations that have no draft yet

What the model writes: the title, the Summary and the Impact (35 words each, checked in code; one retry, then a
plain template). What the model never touches: the PoC. The PoC is assembled in code from the escalation's raw
capture files, quoted VERBATIM (T-106 never retype a byte): the nonsense-sibling control first, then the positive
rounds. The raw files are copied into evidence/.

Every draft is HELD (HELD-REASON.md with an **Unlock:** line): a free model's draft is a starting point for review,
not a filing. Still owed before READY: CVSS and CWE (cvss-scorer), public dedup, raw Burp panels, report-killer.
"""
import json
import os
import re
import shutil
import sys
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import llm_endpoints  # noqa: E402  the "writer" role (defaults to the brain's model and host)
DRAFTS = os.environ.get("LOCAL_DRAFT_ROOT", os.path.join(WS, "reports/drafts"))
EXCERPT = 1800  # bytes of each response quoted in the PoC; the whole file ships in evidence/


def _writer():
    return llm_endpoints.resolve("writer", default=llm_endpoints.roles().get("brain") or llm_endpoints.DEFAULT)


def model():
    return _writer()[1]


def words(s):
    return len(re.findall(r"\S+", s))


def ask(esc_text, feedback=""):
    schema = {"type": "object", "required": ["title", "summary", "impact"],
              "properties": {"title": {"type": "string"}, "summary": {"type": "string"}, "impact": {"type": "string"}}}
    sysmsg = ("You write bug bounty report fields from a verified escalation record. Plain English, no hedging "
              "words (could, may, might, potentially), no em dash, no markdown. title: under 110 characters, ASCII, names "
              "the host, the defect and what is exposed. summary: at most 35 words, what request returns what. impact: at "
              "most 35 words, what an unauthenticated attacker now has. Use ONLY facts that appear in the RECORD and the "
              "RESPONSE EXCERPT: never name an endpoint, data type, secret or technology that is not written there.")
    body = {"model": model(), "stream": False, "format": schema, "think": False,
            "messages": [{"role": "system", "content": sysmsg},
                         {"role": "user", "content": f"{feedback}RECORD:\n{esc_text[:6000]}\n/no_think"}],
            "options": {"num_ctx": 16384, "temperature": 0.2, "num_predict": 500}}
    req = urllib.request.Request(_writer()[0], data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=240) as r:
        c = json.loads(r.read().decode())["message"]["content"]
    return json.loads(re.search(r"\{.*\}", re.sub(r"<think>.*?</think>", "", c, flags=re.S), re.S).group(0))


GROUNDED = ("password", "secret", "token", "credential", "key", "heapdump", "env", "environment", "database", "pii",
            "email", "session", "cookie", "admin", "rce", "jwt", "aws", "config", "configuration", "threaddump",
            "thread", "metrics", "internal", "ssrf", "actuator", "swagger", "graphql", "git", "user", "customer")


def check(f, corpus):
    """corpus = the record, the decoded URL and the response excerpt; every sensitive noun and path must come from it."""
    bad = []
    blob_l = " ".join(f.get(k, "") for k in ("title", "summary", "impact")).lower()
    c = corpus.lower()
    invented = sorted({w for w in GROUNDED if re.search(rf"\b{w}s?\b", blob_l) and w not in c})
    invented += sorted({p for p in re.findall(r"/[a-z0-9_.-]{3,}", blob_l) if p not in c})
    if invented:
        bad.append(f"these are not in the record or response, remove them: {', '.join(invented[:8])}")
    if words(f.get("summary", "")) > 35 or words(f.get("summary", "")) < 8:
        bad.append(f"summary has {words(f.get('summary', ''))} words (8-35)")
    if words(f.get("impact", "")) > 35 or words(f.get("impact", "")) < 8:
        bad.append(f"impact has {words(f.get('impact', ''))} words (8-35)")
    norm = lambda x: re.sub(r"\W+", " ", x.lower()).strip()
    if norm(f.get("summary", "")) in (norm(f.get("title", "")), norm(f.get("impact", ""))):
        bad.append("title, summary and impact must each say something different; summary is a full sentence")
    t = f.get("title", "")
    if not t or len(t) > 119 or re.search(r"[#`*|]|[^\x20-\x7e]", t):
        bad.append("title must be ASCII, under 120 chars, no # ` * |")
    blob = " ".join(f.get(k, "") for k in ("title", "summary", "impact"))
    if re.search(r"\b(could|may|might|potentially)\b|—", blob, re.I):
        bad.append("remove hedges (could/may/might/potentially) and em dashes")
    return bad


def covered(program, url):
    """True when any draft of the program already names this host+path (a Claude or human draft counts)."""
    hp = re.sub(r"^https?://", "", url).split("?")[0]
    root = os.path.join(DRAFTS, program)
    for dp, _, fs in os.walk(root) if os.path.isdir(root) else []:
        if "report.md" in fs and hp in open(os.path.join(dp, "report.md"), errors="replace").read():
            return True
    return False


def pending(program=None):
    out = []
    for ln in open(os.path.join(ORCH, "escalations.jsonl"), encoding="utf-8", errors="replace"):
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        if e.get("tier") != 3 or (program and e.get("program") != program):
            continue
        if not covered(e["program"], e["url"]):
            out.append(e)
    return out


def build(esc_dir):
    esc_dir = os.path.abspath(esc_dir)
    md = open(os.path.join(esc_dir, "ESCALATION.md"), encoding="utf-8", errors="replace").read()
    if "TIER-3" not in md.splitlines()[0]:
        sys.exit("only TIER-3 escalations are drafted")
    program = re.search(r"^Program: (\S+)", md, re.M).group(1)
    url = re.search(r"^URL: (\S+)", md, re.M).group(1)
    slug = os.path.basename(esc_dir)
    out = os.path.join(DRAFTS, program, "auto-" + slug)
    if os.path.exists(out) or (DRAFTS.startswith(WS) and covered(program, url)):
        sys.exit(f"already drafted: {program} {url.split('?')[0]}")
    raw = os.path.join(esc_dir, "raw")
    from urllib.parse import unquote
    det = os.path.join(raw, "det0.resp")
    excerpt = open(det, "rb").read()[:1500].decode("utf-8", "replace") if os.path.isfile(det) else ""
    decoded = unquote(unquote(url))
    record = f"{md}\n\nDECODED URL: {decoded}\n\nRESPONSE EXCERPT (det0, first 1500 bytes):\n{excerpt}"
    f, fb = None, ""
    for _ in range(3):
        cand = ask(record, fb)
        bad = check(cand, record)
        if not bad:
            f = cand
            break
        fb = "PREVIOUS ANSWER REJECTED: " + "; ".join(bad) + f". Previous answer: {json.dumps(cand)[:500]}\n"
    if f is None:  # the model could not meet the caps twice: a plain template, clearly marked for rewrite
        host = re.match(r"https?://([^/]+)", url).group(1)
        f = {"title": f"Unauthenticated access on {host} returns internal data (draft title, rewrite)",
             "summary": f"An unauthenticated GET to {host} returns data that the escalation record classifies as sensitive. "
                        "Draft text written by template, rewrite before review.",
             "impact": "Any unauthenticated visitor receives the response shown in the PoC. Rewrite with the captured terminal."}
    os.makedirs(os.path.join(out, "evidence"))
    shutil.copytree(raw, os.path.join(out, "evidence/raw"))
    shutil.copy(os.path.join(esc_dir, "ESCALATION.md"), os.path.join(out, "evidence/ESCALATION.md"))
    order = [t for t in ("sibling-nonsense", "det0", "arm-bogus-bearer", "det1", "det2") if os.path.isfile(os.path.join(raw, t + ".resp"))]
    poc = []
    for i, tag in enumerate(order, 1):
        b = open(os.path.join(raw, tag + ".resp"), "rb").read()
        first = b.split(b"\n", 1)[0].decode("utf-8", "replace")
        target = first.split(" ", 1)[1] if " " in first else url
        label = "Negative control: a nonsense path on the same host" if tag == "sibling-nonsense" else \
            "Same request with a fabricated Bearer token" if tag == "arm-bogus-bearer" else f"Request (round {tag[-1]})"
        excerpt = b[:EXCERPT].decode("utf-8", "replace")
        poc.append(f"Step {i}. {label}.\n\n```\ncurl -s -i '{target}'\n```\n\n```\n{excerpt}\n```\n"
                   + (f"\n(Truncated at {EXCERPT} of {len(b)} bytes; the full response is evidence/raw/{tag}.resp.)\n"
                      if len(b) > EXCERPT else ""))
    report = (f"CVSS: TBD (cvss-scorer)\nAsset: TBD (exact scope row)\nCWE: TBD\n\n# {f['title']}\n\n## Summary\n{f['summary']}\n\n"
              f"## PoC\n" + "\n".join(poc) + f"\n## Impact\n{f['impact']}\n")
    open(os.path.join(out, "report.md"), "w").write(report)
    open(os.path.join(out, "HELD-REASON.md"), "w").write(
        f"# HELD - local-model draft ({model()}, {datetime.now(timezone.utc):%Y-%m-%d %H:%MZ})\n\n"
        "Written by scripts/local-draft.py from a TIER-3 auto-escalation. The PoC quotes the raw captures verbatim; the "
        "title, Summary and Impact were written by a local model and need a human or Claude read.\n\n"
        "**Unlock: CVSS + CWE + exact Asset row, public dedup, a captured TERMINAL (credential, PII record or internal "
        "secret, not only reach), raw Burp panels, then gnoc ship <this dir>.**\n")
    print(f"drafted (HELD): {os.path.relpath(out, WS)}")
    return out


def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if a[0] == "--pending":
        for e in pending(a[1] if len(a) > 1 else None):
            print(f"{e['program']:<16} {e['dir']}")
        return 0
    build(a[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
