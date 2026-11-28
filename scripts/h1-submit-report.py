#!/usr/bin/env python3
"""HackerOne Hacker-API report submitter (contract: scripts/H1-SUBMIT.md).

usage: h1-submit-report.py <program> <report.md> [--asset ID] [--weakness-id N]
         [--severity none|low|medium|high|critical] [--dry-run] [--yes]
         [--skip-qaqc-severity-only] [--skip-dedup-check]

Pre-POST self-dedup gate (Manual T-244): before any send, our OWN H1 report list is pulled
FRESH (scripts/h1-selfdup.py, refresh) and compared on program + asset + weakness + paths +
title. Any open overlap, or an unreadable API, ABORTS a real send (fail closed). A novel angle
on a matched report (T-125/T-126) is cleared by the user's SELF-DUP-OK.txt in the draft dir or by
--skip-dedup-check (loud warning; human decision only).

Creds come from ~/.config/gnoc/secrets.env (HACKERONE_HANDLE, HACKERONE_API_TOKEN),
HTTP Basic. The token is never printed. A real send needs the file
.claude/state/GREYNOC-APPROVED-SUBMIT (deleted after one successful submit) and a
clean scripts/submit-qaqc.py run on the SANITIZED submitted content.
"""
import argparse, datetime, json, os, re, subprocess, sys, tempfile
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://api.hackerone.com/v1/hackers"
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
APPROVAL = os.path.join(ROOT, ".claude/state/GREYNOC-APPROVED-SUBMIT")
QAQC = os.path.join(ROOT, "scripts/submit-qaqc.py")
STRIP_RE = re.compile(r"^\s*(Gate:|Dedup:|ESCALATION TARGET:|\*\*Unlock:)")


def die(msg, code=1):
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(code)


def load_creds():
    env = {}
    try:
        for ln in open(SECRETS, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                env[k.replace("export ", "").strip()] = v.strip().strip("'\"")
    except OSError:
        die(f"cannot read {SECRETS}")
    h, t = env.get("HACKERONE_HANDLE"), env.get("HACKERONE_API_TOKEN")
    if not h or not t:
        die("HACKERONE_HANDLE / HACKERONE_API_TOKEN missing in secrets.env")
    return h, t


def parse_report(path):
    """Return dict(header, title, summary, poc, impact, clean_text, stripped)."""
    raw = open(path, encoding="utf-8").read()
    lines = raw.split("\n")
    header, stripped, kept = {}, [], []
    title, in_fence, cur = None, False, None
    secs = {}
    for ln in lines:
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
        if not in_fence and STRIP_RE.match(ln):
            stripped.append(ln)
            continue
        kept.append(ln)
        if in_fence:
            if cur:
                secs[cur].append(ln)
            continue
        if title is None:
            m = re.match(r"^#\s+(.+?)\s*$", ln)
            if m:
                title = m.group(1)
                continue
            m = re.match(r"^(CVSS|Asset|CWE):\s*(.*)$", ln)
            if m:
                header[m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"^##\s+(.+?)\s*$", ln)
        if m:
            cur = m.group(1).strip().lower().rstrip(".")
            secs.setdefault(cur, [])
            secs[cur].append(ln)  # keep the heading line in the section text
            continue
        if cur:
            secs[cur].append(ln)
    if not title:
        die("no '# title' line")
    for need in ("summary", "poc", "impact"):
        if need not in secs:
            die(f"no '## {need}' section")
    sec = {k: "\n".join(v).strip("\n") for k, v in secs.items()}
    impact_body = "\n".join(secs["impact"][1:]).strip("\n")
    summary_body = "\n".join(secs["summary"][1:]).strip("\n")
    return dict(header=header, title=title, summary=sec["summary"], poc=sec["poc"],
                impact=impact_body, summary_body=summary_body,
                clean_text="\n".join(kept), stripped=stripped)


def words(s):
    s = re.sub(r"```.*?```", "", s, flags=re.S)
    return len([w for w in s.split() if w])


class H1:
    def __init__(self, user, token):
        self.s = requests.Session()
        self.s.auth = (user, token)
        self.s.headers["Accept"] = "application/json"

    def get_all(self, url):
        out, url = [], url + ("&" if "?" in url else "?") + "page%5Bsize%5D=100"
        while url:
            r = self.s.get(url, timeout=30)
            if r.status_code != 200:
                die(f"GET {url} -> HTTP {r.status_code}\n{r.text[:1500]}")
            d = r.json()
            out += d.get("data", [])
            url = (d.get("links") or {}).get("next")
        return out


def norm_ident(s):
    s = s.strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    return s.rstrip("/")


def resolve_scope(scopes, asset):
    a = norm_ident(asset)
    # --asset is documented as an ID, but only the asset IDENTIFIER was ever matched, so the numeric
    # structured_scope id straight out of the API aborted the send (2026-10-28). Accept either: a bare
    # number is looked up as the scope row's own id first.
    if str(asset).strip().isdigit():
        by_id = [s for s in scopes if str(s.get("id")) == str(asset).strip()]
        if len(by_id) == 1:
            return by_id[0], "scope id"
        if len(by_id) > 1:
            die("ambiguous: multiple scope rows carry id " + str(asset))
    rows = [(s, norm_ident(s["attributes"].get("asset_identifier", ""))) for s in scopes]
    exact = [s for s, i in rows if i == a]
    if len(exact) > 1:
        die("ambiguous: multiple exact scope rows: " + ", ".join(s["id"] for s in exact))
    if exact:
        return exact[0], "exact"
    host = a.split("/")[0]
    cands = []
    for s, i in rows:
        if i.startswith("*."):
            base = i[2:].split("/")[0]
            if host == base or host.endswith("." + base):
                cands.append((len(base), s))
    if not cands:
        die(f"no structured scope row matches asset '{asset}'")
    cands.sort(key=lambda x: -x[0])
    if len(cands) > 1 and cands[0][0] == cands[1][0]:
        die("ambiguous wildcard rows: " + ", ".join(c[1]["attributes"]["asset_identifier"] for c in cands))
    return cands[0][1], ("wildcard (most specific of %d)" % len(cands))


def run_qaqc(clean_text, allow_sev_only):
    with tempfile.TemporaryDirectory() as td:
        d = os.path.join(td, "submitted")
        os.mkdir(d)
        p = os.path.join(d, "report.md")
        open(p, "w", encoding="utf-8").write(clean_text)
        r = subprocess.run([sys.executable, QAQC, p], capture_output=True, text=True, cwd=ROOT)
    print("---- submit-qaqc.py (run on the sanitized submitted content) ----")
    print(r.stdout.rstrip())
    if r.stderr.strip():
        print(r.stderr.rstrip())
    print("---- end qaqc (exit %d) ----" % r.returncode)
    if r.returncode == 0:
        return True, ""
    fails = [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("FAIL")]
    sev_only = bool(fails) and all("SEVERITY" in f for f in fails)
    if allow_sev_only and sev_only:
        print("!" * 70)
        print("!! LOUD NOTE: QAQC severity gate (<7.0) overridden by --skip-qaqc-severity-only")
        print("!! (the user authorized a sub-7.0 filing). All other QAQC checks passed.")
        print("!" * 70)
        return True, "severity-override"
    return False, ("only the severity line failed; pass --skip-qaqc-severity-only if authorized"
                   if sev_only else "QAQC failed")


def dedup_gate(path, program, asset_ident, cwe_ext):
    """T-244 as a pre-POST gate. Returns (ok, lines). Fails closed on ANY error."""
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location("h1_selfdup", os.path.join(ROOT, "scripts/h1-selfdup.py"))
        sd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sd)
        verdict, lines = sd.check(path, program, refresh=True)  # refresh: a stale list is the bug
        if verdict == "UNVERIFIED":
            return False, lines + ["  dedup check could not run: fail closed"]
        # structured twin: the RESOLVED scope row + weakness (covers --asset / --weakness-id overrides)
        reports, _ = sd.my_reports(False)  # just refreshed above
        okf = os.path.join(os.path.dirname(path), "SELF-DUP-OK.txt")
        ok_ids = set(re.findall(r"\b\d{6,}\b", open(okf).read())) if os.path.isfile(okf) else set()
        seen = {m for m in re.findall(r"#(\d{6,})", "\n".join(lines))}
        extra = []
        for r in reports:
            if (r["program"] == program.lower() and r["id"] not in seen and r["id"] not in ok_ids
                    and norm_ident(r.get("asset") or "") == norm_ident(asset_ident or "")
                    and cwe_ext and (r.get("cwe") or "") == cwe_ext.lower()):
                extra.append(f"  [structured] #{r['id']} {r['state']} {r['created_at'][:10]}: {r['title'][:80]}"
                             f"  (same scope row {asset_ident} + {cwe_ext})  https://hackerone.com/reports/{r['id']}")
        if extra:
            verdict = "POSSIBLE" if verdict == "CLEAR" else verdict
            lines = lines + extra
        return verdict == "CLEAR", lines
    except (Exception, SystemExit) as e:
        return False, [f"SELFDUP UNVERIFIED  {program}", f"  dedup check raised {type(e).__name__}: {str(e)[:300]}",
                       "  dedup check could not run: fail closed"]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("program")
    ap.add_argument("report")
    ap.add_argument("--asset")
    ap.add_argument("--weakness-id", type=int)
    ap.add_argument("--severity", choices=["none", "low", "medium", "high", "critical"])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--yes", action="store_true")
    ap.add_argument("--skip-qaqc-severity-only", action="store_true")
    ap.add_argument("--skip-signal-gate", action="store_true",
                    help="file although the program's signal gate (T-254) says it will refuse us (the user's call only)")
    ap.add_argument("--skip-dedup-check", action="store_true",
                    help="file despite a self-dedup overlap or an unreadable API (the user's call only)")
    a = ap.parse_args()

    path = os.path.abspath(a.report)
    if not os.path.isfile(path):
        die(f"no such file {path}")
    rep = parse_report(path)
    hdr = rep["header"]
    print("== stripped from submission:")
    for s in rep["stripped"]:
        print("   -", s[:110])
    print("== header kept as metadata only (not in body):", json.dumps(hdr)[:300])

    # severity
    sev = a.severity
    if not sev:
        m = re.search(r"([0-9]+(?:\.[0-9])?)\b", re.sub(r"CVSS:(?:3\.[01]|4\.0)/[A-Z:/]+", "", hdr.get("CVSS", "")))
        if not m:
            die("cannot derive severity from CVSS: header; pass --severity")
        sc = float(m.group(1))
        sev = "critical" if sc >= 9 else "high" if sc >= 7 else "medium" if sc >= 4 else "low"
    print("== severity_rating:", sev)
    # T-254: the program's filing flags, token-free, BEFORE a credential or a slot is spent. A granular-signal
    # program whose target our closed record does not meet answers the create with a bare 403 on every channel;
    # the 2026-10-20 WordCamp filing burned a repro run, a QAQC pass and two create calls finding that out.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import gnoc_pay
        team = gnoc_pay.h1_team(a.program, refresh=True) or {}
        sig, n, _ = gnoc_pay.own_signal()
        print(f"== team flags: submission_state={team.get('submission_state')} offers_bounties={team.get('offers_bounties')} "
              f"granular_signal={team.get('granular_signal')} target_signal={team.get('target_signal')} "
              f"identity_required={team.get('identity_required')}; our signal {sig} over {n} scored "
              f"(pull {gnoc_pay.SIGNAL_INFO.get('day')})")
        gate_ok, gate_why = gnoc_pay.filing_gate(a.program, offline=True)
    except Exception as e:  # noqa: BLE001 - the gate is a fact check; an unreadable platform never blocks by itself
        gate_ok, gate_why = True, f"signal gate not checked ({type(e).__name__}: {e})"
    print("== filing gate:", "ok -" if gate_ok else "BLOCKED -", gate_why)
    if not gate_ok:
        if a.skip_signal_gate:
            print("== --skip-signal-gate passed: filing despite the gate (the user's call)")
        elif a.dry_run:
            print("== signal gate would REFUSE a real submit (the platform will answer 403); clear with --skip-signal-gate")
        else:
            die("signal gate (T-254): " + gate_why + "; re-run with --skip-signal-gate only on the user's explicit call")

    # QAQC
    ok, why = run_qaqc(rep["clean_text"], a.skip_qaqc_severity_only)
    if not ok:
        if a.dry_run:
            print(f"== QAQC would REFUSE a real submit: {why}")
        else:
            die(f"QAQC gate: {why}")

    user, token = load_creds()
    h1 = H1(user, token)

    asset = a.asset or (hdr.get("Asset", "").split() or [""])[0]
    if not asset:
        die("no --asset and no Asset: header")
    scope, how = resolve_scope(h1.get_all(f"{API}/programs/{a.program}/structured_scopes"), asset)
    at = scope["attributes"]
    print(f"== structured_scope ({how}): id={scope['id']} asset_identifier={at.get('asset_identifier')} "
          f"type={at.get('asset_type')} eligible_for_submission={at.get('eligible_for_submission')} "
          f"eligible_for_bounty={at.get('eligible_for_bounty')} max_severity={at.get('max_severity')}")
    if at.get("eligible_for_submission") is False:
        die("scope row is not eligible_for_submission")

    wid = a.weakness_id
    weaknesses = h1.get_all(f"{API}/programs/{a.program}/weaknesses")
    if wid is None:
        m = re.search(r"CWE-(\d+)", hdr.get("CWE", ""), re.I)
        if not m:
            die("no --weakness-id and no CWE-<n> in CWE: header")
        want = f"cwe-{m.group(1)}"
        hit = [w for w in weaknesses if (w["attributes"].get("external_id") or "").lower() == want]
        if len(hit) != 1:
            die(f"{want} matches {len(hit)} weaknesses in program {a.program} (of {len(weaknesses)}); pass --weakness-id")
        w = hit[0]
    else:
        hit = [w for w in weaknesses if str(w["id"]) == str(wid)]
        if not hit:
            die(f"weakness id {wid} not in program {a.program} weaknesses")
        w = hit[0]
    print(f"== weakness: id={w['id']} external_id={w['attributes'].get('external_id')} name={w['attributes'].get('name')}")

    vuln_info = rep["summary"] + "\n\n" + rep["poc"]
    payload = {"data": {"type": "report", "attributes": {
        "team_handle": a.program, "title": rep["title"],
        "vulnerability_information": vuln_info, "impact": rep["impact"],
        "severity_rating": sev, "weakness_id": int(w["id"]), "structured_scope_id": int(scope["id"])}}}
    print(f"== words: Summary={words(rep['summary_body'])} Impact={words(rep['impact'])} "
          f"vulnerability_information={words(vuln_info)}")

    # self-dedup gate (T-244), before any POST; fails closed
    dok, dlines = dedup_gate(path, a.program, at.get("asset_identifier") or "", w["attributes"].get("external_id") or "")
    print("---- self-dedup gate (T-244, fresh H1 pull of our own reports) ----")
    print("\n".join(dlines))
    print("---- end self-dedup (%s) ----" % ("CLEAR" if dok else "NOT CLEAR"))
    if not dok:
        if a.skip_dedup_check:
            print("!" * 70)
            print("!! LOUD WARNING: SELF-DEDUP GATE NOT CLEAR AND OVERRIDDEN BY --skip-dedup-check")
            print("!! Matches or an unverified check are listed above. Filing anyway is the user's call")
            print("!! (T-125/T-126 novel mechanism / fix-bypass / untested subset). Record why.")
            print("!" * 70)
        elif a.dry_run:
            print("== DEDUP gate would REFUSE a real submit (clear with SELF-DUP-OK.txt or --skip-dedup-check)")
        else:
            die("self-dedup gate: overlap with our own H1 reports or check could not run (see above); "
                "re-run with --skip-dedup-check only on the user's explicit call")
    elif a.skip_dedup_check:
        print("== --skip-dedup-check passed but the gate was CLEAR; no override used")

    if a.dry_run:
        print("== DRY RUN payload (POST %s/reports):" % API)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("== dry run: nothing sent.")
        return 0

    if not os.path.isfile(APPROVAL):
        die(f"{APPROVAL} missing: the user approval is per-filing")
    if not a.yes:
        if not sys.stdin.isatty():
            die("no TTY and no --yes")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        if input(f"Submit to {a.program}? type 'submit': ").strip() != "submit":
            die("not confirmed")

    r = h1.s.post(f"{API}/reports", json=payload, headers={"Content-Type": "application/json"}, timeout=30)
    if r.status_code not in (200, 201):
        print(f"HTTP {r.status_code}\n{r.text[:3000]}", file=sys.stderr)
        die("submission failed; approval file left in place")
    rid = r.json()["data"]["id"]
    url = f"https://hackerone.com/reports/{rid}"
    print(f"SUBMITTED: report id {rid}  {url}  (HTTP {r.status_code})")
    try:
        os.remove(APPROVAL)
        print("approval file consumed.")
    except OSError as e:
        print(f"WARNING: could not delete approval file: {e}")

    row = {"ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "program": a.program, "kind": "draft", "status": "submitted", "path": path,
           "report_id": rid, "url": url, "title": rep["title"], "severity": sev}
    lr = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/hunt-state.py"), "append-ship"],
                        input=json.dumps(row), capture_output=True, text=True, cwd=ROOT)
    print("ledger: kind 'draft' + status 'submitted' (hunt-state rejects kind 'submitted'):",
          "ok" if lr.returncode == 0 else f"FAILED {lr.stderr.strip()}")
    slug = os.path.basename(os.path.dirname(path))
    print(f"NEXT (manual): mv reports/drafts/{a.program}/{slug} reports/submitted/{a.program}/{slug}")
    return 0


if __name__ == "__main__":
    # line-buffer stdout so a redirected run keeps stdout/stderr in order (the 2026-10-19 "silent exit" was an
    # HTTP 400 on stderr printed ABOVE the block-buffered stdout lines)
    sys.stdout.reconfigure(line_buffering=True)
    sys.exit(main())
