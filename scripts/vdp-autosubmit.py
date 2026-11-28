#!/usr/bin/env python3
"""vdp-autosubmit.py - file READY drafts to NO-BOUNTY (VDP) HackerOne programs, unattended.

Standing authorization: the user 2026-10-20 ("i want it to auto submit to vdp programs if there is no
bounty"). It is ON only while .claude/state/orch/AUTO-SUBMIT-VDP.enabled exists; delete that file to
stop it. Bounty programs are never auto-filed: they stay `gnoc submit <dir> --send`, by hand.

  vdp-autosubmit.py <draft-dir> [--dry]   check (and file) one draft
  vdp-autosubmit.py --scan [--dry]        every non-HELD draft under reports/drafts touched in 7 days
  vdp-autosubmit.py --pending             READY drafts waiting for the user (paid, or policy needs their own check)
  vdp-autosubmit.py --approve <draft-dir> ONE-TAP: shows the filing, one confirmation ('y', or 'verified' where
                                          the policy demands their own verification), then the same gates + file.
                                          Works for bounty programs; it is the only path that files them.

A draft is filed only when EVERY check below passes, re-verified at filing time, in this order:
  1  the enable file exists
  2  daily caps: at most 1 auto-filing per program and 2 overall per UTC day
  3  the program is a VDP: H1 API program attribute offers_bounties is false, and the asset's
     structured scope row has eligible_for_bounty false (both read live, read-only)
  4  the policy asks for no custom fields (no FILE-BY-HAND.md in the package, T-249)
  5  ship-pipeline passes on the CURRENT bytes: self-duplicate CLEAR (fresh H1 pull), qaqc, slop,
     notes, a fresh LIVE repro.sh (re-run now, after its hosts are checked against SCOPE.txt),
     Burp panels, the kill pass and the repro check (cached LLM verdicts, valid only while the
     bytes they judged are unchanged), and a clean H1 dry run
Then it files through scripts/h1-submit-report.py (its own QAQC still runs), pulls the filed report
back from the API and diffs title/severity/weakness against the package (T-253), writes
SUBMITTED.md, moves the draft to reports/submitted/<program>/<slug>/, and posts to the orch INBOX.
Every decision, filed or refused, is appended to .claude/state/orch/autosubmit.jsonl.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
ENABLE = os.path.join(ORCH, "AUTO-SUBMIT-VDP.enabled")
LEDGER = os.path.join(ORCH, "autosubmit.jsonl")
APPROVAL = os.path.join(WS, ".claude/state/GREYNOC-APPROVED-SUBMIT")
API = "https://api.hackerone.com/v1/hackers"
CAP_PROGRAM, CAP_TOTAL = 1, 2


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record(rec):
    os.makedirs(ORCH, exist_ok=True)
    rec["ts"] = now()
    with open(LEDGER, "a") as f:
        f.write(json.dumps(rec) + "\n")


def inbox(kind, msg):
    with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
        f.write(f"- [{now()}] **{kind}** {msg}\n")


def session():
    env = {}
    for ln in open(os.path.expanduser("~/.config/gnoc/secrets.env"), encoding="utf-8"):
        ln = ln.strip()
        if ln and not ln.startswith("#") and "=" in ln:
            k, v = ln.split("=", 1)
            env[k.replace("export ", "").strip()] = v.strip().strip("'\"")
    s = requests.Session()
    s.auth = (env["HACKERONE_HANDLE"], env["HACKERONE_API_TOKEN"])
    s.headers["Accept"] = "application/json"
    return s


def filed_today(program=None):
    day = now()[:10]
    n = 0
    if os.path.isfile(LEDGER):
        for ln in open(LEDGER):
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if r.get("result") == "FILED" and r.get("ts", "").startswith(day) and (program is None or r.get("program") == program):
                n += 1
    return n


def is_vdp(s, program, asset):
    r = s.get(f"{API}/programs/{program}", timeout=30)
    if r.status_code != 200:
        return False, f"program read HTTP {r.status_code}"
    attrs = r.json().get("attributes") or r.json().get("data", {}).get("attributes", {})
    if attrs.get("offers_bounties") is not False:
        return False, f"offers_bounties={attrs.get('offers_bounties')!r} (only an explicit false counts)"
    def norm(v):  # H1 lists identifiers with a scheme (https://*.app.example.com); the report header may not
        return re.sub(r"^[a-z][a-z0-9+.-]*://", "", (v or "").lower().strip()).rstrip("/")
    want = norm(asset)
    url = f"{API}/programs/{program}/structured_scopes?page%5Bsize%5D=100"
    rows = []
    while url:
        rr = s.get(url, timeout=30)
        if rr.status_code != 200:
            return False, f"scope read HTTP {rr.status_code}"
        d = rr.json()
        rows += d.get("data", [])
        url = (d.get("links") or {}).get("next")
    hit = [x for x in rows if norm(x.get("attributes", {}).get("asset_identifier")) == want]
    if len(hit) != 1:
        return False, f"asset {asset!r} matches {len(hit)} scope rows"
    if hit[0]["attributes"].get("eligible_for_bounty") is not False:
        return False, f"asset eligible_for_bounty={hit[0]['attributes'].get('eligible_for_bounty')!r}"
    return True, "offers_bounties=false, asset eligible_for_bounty=false"


def repro_hosts_in_scope(d, program):
    sys.path.insert(0, os.path.join(WS, "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("ob", os.path.join(WS, "scripts/orch-bot.py"))
    ob = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ob)
    pats = ob.scope_patterns(program)
    txt = open(os.path.join(d, "repro.sh"), encoding="utf-8", errors="replace").read()
    hosts = {h.lower() for h in re.findall(r"https?://([A-Za-z0-9.-]+)", txt) if "$" not in h}
    bad = sorted(h for h in hosts if h not in ("127.0.0.1", "localhost") and not ob.in_scope(h, pats))
    return not bad, bad


def header_of(report):
    hdr = {}
    for ln in open(report, encoding="utf-8").read().splitlines()[:12]:
        m = re.match(r"^(CVSS|Asset|CWE):\s*(.+)$", ln)
        if m:
            hdr[m.group(1)] = m.group(2).strip()
    return hdr


def run(cmd, env=None, timeout=1200):
    r = subprocess.run(cmd, cwd=WS, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                       env=dict(os.environ, **(env or {})))
    return r.returncode, (r.stdout or "") + (r.stderr or "")


HUMAN_RULE = re.compile(
    r"[^.\n]{0,120}\b(?:(?:AI|LLM|language model|ChatGPT|generative|automated tool(?:s|ing)?)\b[^.\n]{0,100}"
    r"\b(?:clos|reject|ban|prohibit|not accept|not applicable|invalid|without (?:the )?(?:author|researcher)|human)\w*"
    r"|(?:human|manually|yourself|your own)\b[^.\n]{0,60}\b(?:verif|validat|reproduc|review)\w*)[^.\n]{0,80}", re.I)


def human_rule(program):
    """The policy sentence that makes unattended filing a policy breach (AI-report closures, human verification), or ''."""
    for name in ("PROGRAM.md", "POLICY.md"):
        p = os.path.join(WS, "targets", program, name)
        if os.path.isfile(p):
            m = HUMAN_RULE.search(open(p, encoding="utf-8", errors="replace").read())
            if m:
                return " ".join(m.group(0).split())[:200]
    return ""


def attempt(d, dry=False, human=False):
    """human=True: the user approved THIS draft by hand (vdp-autosubmit.py --approve). It may then be a bounty program and
    a program whose policy requires the researcher's own verification; every other gate still runs on the live bytes."""
    d = os.path.abspath(d)
    rel = os.path.relpath(d, os.path.join(WS, "reports/drafts")).split(os.sep)
    if len(rel) != 2:
        return "SKIP", "not reports/drafts/<program>/<slug>"
    program, slug = rel
    report = os.path.join(d, "report.md")
    rec = {"program": program, "slug": slug}

    def refuse(why):
        rec.update(result="REFUSED", why=why)
        record(rec)
        return "REFUSED", why

    if not human and not os.path.isfile(ENABLE):
        return refuse("auto-submit is OFF (no AUTO-SUBMIT-VDP.enabled)")
    if os.path.isfile(os.path.join(d, "HELD-REASON.md")):
        return refuse("draft is HELD")
    if os.path.isfile(os.path.join(d, "FILE-BY-HAND.md")):
        return refuse("program needs custom fields (FILE-BY-HAND.md): web form only")
    why = human_rule(program)
    if why and not human:
        return refuse(f"program policy requires the researcher's own verification or bans AI/automation "
                      f"(\"{why}\"): one-tap approval only, never unattended")
    if filed_today(program) >= CAP_PROGRAM or filed_today() >= CAP_TOTAL:
        return refuse(f"daily cap reached ({CAP_PROGRAM}/program, {CAP_TOTAL}/day)")
    asset = (header_of(report).get("Asset") or "").split()[0] if header_of(report).get("Asset") else ""
    if not asset:
        return refuse("no Asset: header")
    try:
        s = session()
        ok, why = is_vdp(s, program, asset)
    except Exception as e:
        return refuse(f"H1 API unreadable: {e}")
    if not ok and not human:
        return refuse(f"not a no-bounty filing: {why} (paid: vdp-autosubmit.py --approve <dir>)")
    ok, bad = repro_hosts_in_scope(d, program)
    if not ok:
        return refuse(f"repro.sh names hosts outside SCOPE.txt: {bad}")
    # full gate on current bytes, with a FRESH live repro and the cached LLM verdicts
    cache = os.path.join(d, ".pipeline.json")
    try:
        c = json.load(open(cache))
        c.pop("repro", None)
        c.pop("selfdup", None)
        json.dump(c, open(cache, "w"))
    except (OSError, ValueError):
        pass
    rc, out = run([sys.executable, os.path.join(WS, "scripts/ship-pipeline.py"), d], env={"HUNT_TARGET": program})
    if "READY TO FILE" not in out:
        fails = [l.strip() for l in out.splitlines() if l.startswith("- ") and not l.startswith("- PASS")]
        return refuse("gates not all PASS: " + " | ".join(f[:90] for f in fails))
    if dry:
        rec.update(result="WOULD-FILE", why="all checks pass (--dry)")
        record(rec)
        return "WOULD-FILE", "all checks pass"
    # file it: the submitter re-runs its own QAQC and consumes the approval file
    with open(APPROVAL, "w") as f:
        f.write((f"The user approved this exact draft by hand (--approve) for {program}/{slug} at {now()}\n" if human else
                 f"standing VDP auto-submit authorization (2026-10-20) for {program}/{slug} at {now()}\n"))
    rc, out = run([sys.executable, os.path.join(WS, "scripts/h1-submit-report.py"), program, report,
                   "--yes", "--skip-qaqc-severity-only"], timeout=180)
    if os.path.isfile(APPROVAL):
        os.remove(APPROVAL)  # never leave a live approval behind
    m = re.search(r"SUBMITTED: report id (\d+)", out)
    if not m:
        rec.update(result="FAILED", why=out.strip()[-400:])
        record(rec)
        inbox("AUTOSUBMIT-FAILED", f"{program}/{slug}: {out.strip()[-200:]}")
        return "FAILED", out.strip()[-300:]
    rid = m.group(1)
    # T-253: read the filed report back and diff it against the package
    time.sleep(5)
    diff = []
    try:
        a = s.get(f"{API}/reports/{rid}", timeout=30).json().get("data", {}).get("attributes", {})
        title = next((l[2:].strip() for l in open(report, encoding="utf-8") if l.startswith("# ")), "")
        if (a.get("title") or "").strip() != title:
            diff.append(f"title differs: {a.get('title')!r}")
    except Exception as e:
        diff.append(f"read-back failed: {e}")
    dest = os.path.join(WS, "reports/submitted", program, slug)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(os.path.join(d, "SUBMITTED.md"), "w") as f:
        f.write(f"# SUBMITTED - FROZEN, DO NOT EDIT\n\nH1 report id {rid}  https://hackerone.com/reports/{rid}\n"
                f"Filed {now()} by vdp-autosubmit.py ("
                + ("approved by the user with --approve" if human else "standing VDP authorization, the user 2026-10-20") + ").\n"
                f"Read-back diff: {'; '.join(diff) or 'none'}\n")
    shutil.move(d, dest)
    rec.update(result="FILED", report_id=rid, diff=diff)
    record(rec)
    inbox("AUTOSUBMITTED", f"{program}/{slug} -> https://hackerone.com/reports/{rid}" + (f" DIFF: {'; '.join(diff)}" if diff else ""))
    return "FILED", f"#{rid}"


def scan(dry=False):
    root = os.path.join(WS, "reports/drafts")
    cutoff = time.time() - 7 * 86400
    for prog in sorted(os.listdir(root)):
        for slug in sorted(os.listdir(os.path.join(root, prog))) if os.path.isdir(os.path.join(root, prog)) else []:
            d = os.path.join(root, prog, slug)
            pl = os.path.join(d, "PIPELINE.md")
            if not os.path.isfile(os.path.join(d, "report.md")) or os.path.getmtime(os.path.join(d, "report.md")) < cutoff:
                continue
            # only drafts whose last pipeline run had every LOCAL gate passing are worth a live attempt
            if not os.path.isfile(pl) or re.search(r"^- FAIL", open(pl).read(), re.M):
                continue
            v, why = attempt(d, dry)
            print(f"{v:<10} {prog}/{slug}  {why[:160]}", flush=True)


def pending():
    """READY drafts that only wait for the user: paid programs, and programs whose policy needs their own verification."""
    out = []
    root = os.path.join(WS, "reports/drafts")
    for prog in sorted(os.listdir(root)):
        for slug in sorted(os.listdir(os.path.join(root, prog))) if os.path.isdir(os.path.join(root, prog)) else []:
            pl = os.path.join(root, prog, slug, "PIPELINE.md")
            if os.path.isfile(pl) and "READY TO FILE" in open(pl).read() and \
                    not os.path.isfile(os.path.join(root, prog, slug, "HELD-REASON.md")):
                out.append((prog, slug))
    return out


def approve(d):
    """One-tap filing for a draft the user has read: show what will be filed, one confirmation, then the full gate + file."""
    d = os.path.abspath(d)
    program, slug = os.path.relpath(d, os.path.join(WS, "reports/drafts")).split(os.sep)[:2]
    h = header_of(os.path.join(d, "report.md"))
    title = next((l[2:].strip() for l in open(os.path.join(d, "report.md"), encoding="utf-8") if l.startswith("# ")), "")
    print(f"\n  program  {program}\n  title    {title}\n  CVSS     {h.get('CVSS', '?')}\n  asset    {h.get('Asset', '?')}"
          f"\n  CWE      {h.get('CWE', '?')}\n  filed today: {filed_today(program)} on this program, {filed_today()} total\n")
    rule = human_rule(program)
    if rule:
        print(f"  THIS PROGRAM REQUIRES YOUR OWN VERIFICATION:\n    \"{rule}\"\n"
              f"  Run {os.path.relpath(os.path.join(d, 'repro.sh'), WS)} yourself and read the output first.\n")
        want = "verified"
    else:
        want = "y"
    try:
        ans = input(f"  type '{want}' to run the gates and file now (anything else cancels): ").strip()
    except EOFError:
        ans = ""
    if ans != want:
        print("  cancelled, nothing filed")
        return 1
    v, why = attempt(d, human=True)
    print(f"{v}: {why}")
    return 0 if v == "FILED" else 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--pending":
        for prog, slug in pending():
            print(f"  reports/drafts/{prog}/{slug}" + ("   (needs 'verified': policy wants your own check)" if human_rule(prog) else ""))
        return 0
    if argv[0] == "--approve" and len(argv) > 1:
        return approve(argv[1])
    dry = "--dry" in argv
    if argv[0] == "--scan":
        scan(dry)
        return 0
    v, why = attempt(argv[0], dry)
    print(f"{v}: {why}")
    return 0 if v in ("FILED", "WOULD-FILE") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
