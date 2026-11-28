#!/usr/bin/env python3
"""Slice the harvested H1 corpus into readable per-report markdown bundles.

Each bundle carries: metadata header, the full vulnerability_information body,
and the ordered activity stream with the TRIAGE REPLIES (actor + typename + message).
Slices are grouped so a worker can read one directory and nothing else.
"""
import json, os, glob, sys, collections, re

ROOT = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "research/h1-accepted-365")
RAW = os.path.join(ROOT, "reports")
OUT = os.path.join(ROOT, "slices")

OSS = {"curl","mariadb","nextcloud","monero","nodejs","wonka","rails","torproject",
       "python","django","ruby","php","openssl","gitlab","internet-bug-bounty","ibb",
       "automattic","hackerone","nginx","apache","golang","rust","qt","kde","gnome",
       "libreoffice","vlc","ffmpeg","openvpn","wireguard","tor","sqlite","postgres","mysql",
       "git","svn","mercurial","jenkins","gradle","maven","npm","yarn","composer","pip",
       "nodejs-ecosystem","nvidia","u-boot","uboot","linux","kernel","systemd"}


def norm(s):
    return (s or "").strip()


def load():
    out = []
    for p in sorted(glob.glob(os.path.join(RAW, "*.json"))):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        rep = d.get("report") or {}
        if not rep.get("title"):
            continue
        out.append(d)
    return out


def bundle(d):
    rep = d["report"]
    team = ((rep.get("team") or {}) or {}).get("handle")
    sev = ((rep.get("severity") or {}) or {}).get("rating")
    wk = ((rep.get("weakness") or {}) or {}).get("name")
    sc = rep.get("structured_scope") or {}
    L = []
    L.append(f"# [{d['id']}] {rep.get('title')}")
    L.append("")
    L.append(f"- url: {rep.get('url')}")
    L.append(f"- program: {team}")
    L.append(f"- state: {rep.get('state')} / substate: {rep.get('substate')} / readable: {rep.get('readable_substate')}")
    L.append(f"- severity: {sev}  | hacktivity severity: {(d.get('hacktivity') or {}).get('severity_rating')}")
    L.append(f"- weakness (CWE label): {wk}")
    L.append(f"- has_bounty: {rep.get('has_bounty?')}")
    L.append(f"- cve_ids: {rep.get('cve_ids')}")
    L.append(f"- submitted_at: {rep.get('submitted_at')} | disclosed_at: {rep.get('disclosed_at')}")
    L.append(f"- asset: {sc.get('asset_identifier')} ({sc.get('asset_type')})")
    L.append("")
    L.append("## REPORT BODY")
    L.append("")
    L.append(norm(rep.get("vulnerability_information")) or "(empty)")
    L.append("")
    sm = rep.get("summaries") or []
    if sm:
        L.append("## PROGRAM SUMMARY (written by the team)")
        for s in sm:
            L.append(f"- [{s.get('category')}] {norm(s.get('content'))}")
        L.append("")
    L.append("## ACTIVITY STREAM (triage replies)")
    L.append("")
    acts = d.get("activities") or []
    if not acts:
        L.append("(no activities captured)")
    for a in acts:
        t = a.get("__typename", "?")
        who = (a.get("actor") or {})
        name = who.get("username") or who.get("handle") or "?"
        msg = norm(a.get("message"))
        tag = " [INTERNAL]" if a.get("internal") else ""
        L.append(f"### {t} - {name} @ {a.get('created_at')}{tag}")
        L.append(msg if msg else "(no message)")
        L.append("")
    return "\n".join(L)


def main():
    recs = load()
    os.makedirs(OUT, exist_ok=True)
    stats = collections.Counter()
    manifest = []
    for d in recs:
        rep = d["report"]
        team = (((rep.get("team") or {}) or {}).get("handle") or "unknown").lower()
        sub = rep.get("substate") or "unknown"
        accepted = sub in ("resolved",)
        # slice key: acceptance x venue-kind
        kind = "oss" if team in OSS else "commercial"
        if accepted:
            slice_name = f"accepted-{kind}"
        elif sub in ("informative", "not-applicable", "duplicate", "spam"):
            slice_name = f"rejected-{kind}"
        else:
            slice_name = f"other-{kind}"
        dd = os.path.join(OUT, slice_name)
        os.makedirs(dd, exist_ok=True)
        txt = bundle(d)
        fn = os.path.join(dd, f"{d['id']}.md")
        open(fn, "w").write(txt)
        stats[slice_name] += 1
        nmsg = sum(1 for a in (d.get("activities") or []) if norm(a.get("message")))
        manifest.append({"id": d["id"], "slice": slice_name, "team": team, "substate": sub,
                         "severity": ((rep.get("severity") or {}) or {}).get("rating"),
                         "weakness": ((rep.get("weakness") or {}) or {}).get("name"),
                         "has_bounty": rep.get("has_bounty?"),
                         "title": rep.get("title"), "triage_messages": nmsg,
                         "body_chars": len(norm(rep.get("vulnerability_information"))),
                         "path": fn})
    with open(os.path.join(ROOT, "manifest.jsonl"), "w") as f:
        for m in manifest:
            f.write(json.dumps(m) + "\n")
    print(json.dumps(dict(stats), indent=1))
    print("total", len(recs))


if __name__ == "__main__":
    main()
