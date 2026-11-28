#!/usr/bin/env python3
"""h1-replies.py - watch our HackerOne reports for triager messages and DRAFT replies. It never sends anything.

  h1-replies.py sync            pull activities for every report we filed; draft a reply to each new triager message
  h1-replies.py list            drafted replies not yet marked sent
  h1-replies.py show <n|id>     one draft: the triager message, the reply, and the report link
  h1-replies.py sent <n|id>     mark it sent after you posted it (or edited and posted it) on HackerOne
  h1-replies.py redo <n|id> [guidance]   redraft, optionally steering it ("argue the encoding is a different control")

the user 2026-10-21: "Draft everything, I send". The draft is written by the local chat model (models.json role "chat"),
grounded in the filed package under reports/submitted/<program>/<slug>/ (report.md, SUBMITTED.md, capture.log), and
checked: at most 120 words, no em dash, no hedges, no apology filler, and no path, host or technical noun that is not
in the package. A draft that cannot pass twice is saved with a NEEDS-REWRITE flag instead of being dressed up.
State: .claude/state/h1-replies/{seen.json, drafts/<report>-<activity>.json}; new drafts post a REPLY line to the orch inbox.
"""
import glob
import importlib.util
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ST = os.path.join(WS, ".claude/state/h1-replies")
DR = os.path.join(ST, "drafts")
ORCH = os.path.join(WS, ".claude/state/orch")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import llm_endpoints  # noqa: E402  the "chat" role (laptop or linked desktop)
TRIAGER_TYPES = {"activity-comment", "activity-bug-needs-more-info", "activity-bug-duplicate", "activity-bug-informative",
                 "activity-bug-not-applicable", "activity-bug-triaged", "activity-bug-resolved", "activity-bug-spam",
                 "activity-report-severity-updated", "activity-bounty-awarded"}
CLOSURES = {"activity-bug-duplicate", "activity-bug-informative", "activity-bug-not-applicable", "activity-bug-spam"}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def h1():
    spec = importlib.util.spec_from_file_location("vas", os.path.join(WS, "scripts/vdp-autosubmit.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.session(), m.API


def model():
    return llm_endpoints.resolve("chat")[1]


def package(rid):
    """The filed package dir whose SUBMITTED.md names this report id, and its text (the grounding corpus)."""
    for sub in glob.glob(os.path.join(WS, "reports/submitted/*/*/SUBMITTED.md")):
        if re.search(rf"\b{rid}\b", open(sub, errors="replace").read()):
            d = os.path.dirname(sub)
            text = ""
            for name in ("report.md", "SUBMITTED.md", "capture.log", "H1-FORM-BODY.md"):
                p = os.path.join(d, name)
                if os.path.isfile(p):
                    text += f"\n=== {name} ===\n" + open(p, errors="replace").read()[:9000]
            return d, text
    return None, ""


SYSTEM = ("You draft a reply from a security researcher to a HackerOne triager about the researcher's own report. "
          "Write like a busy expert: short, direct, polite, first person, plain text. At most 120 words. No em dash, no "
          "hedging words (could, may, might, potentially, perhaps), no apology filler, no thanking more than once, no "
          "markdown headings. Use ONLY facts from the REPORT PACKAGE: never invent a request, response, header, host, "
          "path, number or result. If the triager asks for something the package does not contain (a new video, a "
          "re-test, an account), say plainly what you will provide and leave a bracketed TODO like [TODO: attach re-run "
          "output] for the researcher. If the report was closed and the package gives no concrete, checkable reason the "
          "decision is wrong, reply with one short line acknowledging it, nothing more.")


def ask(msg, kind, corpus, guidance=""):
    user = (f"TRIAGER ACTION: {kind}\nTRIAGER MESSAGE:\n{msg[:3000]}\n\nREPORT PACKAGE:\n{corpus[:9000]}\n\n"
            + (f"RESEARCHER GUIDANCE: {guidance}\n\n" if guidance else "") + "Write the reply text only. /no_think")
    body = {"model": model(), "stream": False, "think": False,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            "options": {"num_ctx": 16384, "temperature": 0.4, "num_predict": 300, "repeat_penalty": 1.25,
                        "repeat_last_n": 256}}
    req = urllib.request.Request(llm_endpoints.resolve("chat")[0], data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        c = json.loads(r.read().decode())["message"]["content"]
    c = c.split("</think>")[-1]  # a thinking model may emit only the closing tag
    return re.sub(r"<think>.*", "", c, flags=re.S).strip().strip('"')


def check(reply, corpus, msg):
    bad = []
    n = len(reply.split())
    if n > 120 or n < 3:
        bad.append(f"{n} words (3-120)")
    if "—" in reply or "–" in reply:
        bad.append("contains an em or en dash")
    sents = [x.strip().lower() for x in re.split(r"(?<=[.!?])\s+", reply) if len(x.strip()) > 12]
    if len(sents) != len(set(sents)):
        bad.append("repeats a sentence")
    if re.search(r"\b(could|may|might|potentially|perhaps|I apologi[sz]e|as an AI|I hope this (email|message) finds)\b", reply, re.I):
        bad.append("hedge or filler words")
    src = (corpus + "\n" + msg).lower()
    loose = [t for t in re.findall(r"(?:https?://\S+|/[\w.%-]{3,}(?:/[\w.%-]+)*|\b[\w-]+\.(?:com|net|io|app|dev|org|cn)\b)",
                                   reply.lower()) if t.rstrip(".,)") not in src]
    if loose:
        bad.append(f"not in the package: {', '.join(loose[:4])}")
    return bad


def draft(rid, act, program, guidance=""):
    at = act["attributes"]
    msg = (at.get("message") or "").strip()
    pdir, corpus = package(rid)
    rec = {"report": rid, "activity": act["id"], "kind": act["type"], "program": program, "triager_message": msg,
           "at": at.get("created_at"), "drafted": now(), "package": os.path.relpath(pdir, WS) if pdir else None,
           "link": f"https://hackerone.com/reports/{rid}", "sent": False, "model": model()}
    if not corpus:
        rec.update(reply="", status="NEEDS-REWRITE", problems=["no filed package found under reports/submitted"])
    elif act["type"] in CLOSURES and not guidance:
        rec.update(reply="", status="NO-REPLY-SUGGESTED", problems=[],
                   advice="Closed. Arguing a closure without a concrete, checkable fact costs signal. If you have one, run: "
                          f"gnoc replies redo {rid}-{act['id']} \"<the fact, e.g. the encoded path is a different control>\"")
    else:
        fb, reply, bad = "", "", ["not drafted"]
        for _ in range(2):
            reply = ask(msg, act["type"], corpus, (guidance + " " + fb).strip())
            bad = check(reply, corpus, msg)
            if not bad:
                break
            fb = "Your previous draft was rejected: " + "; ".join(bad) + ". Fix exactly that."
        rec.update(reply=reply, status="READY" if not bad else "NEEDS-REWRITE", problems=bad)
    if act["type"] in CLOSURES and not rec.get("advice"):
        rec["advice"] = "Closure: reply only if the package holds a concrete, checkable reason the decision is wrong."
    os.makedirs(DR, exist_ok=True)
    json.dump(rec, open(os.path.join(DR, f"{rid}-{act['id']}.json"), "w"), indent=1)
    return rec


def sync():
    os.makedirs(ST, exist_ok=True)
    seen_p = os.path.join(ST, "seen.json")
    try:
        seen = set(json.load(open(seen_p)))
    except (OSError, ValueError):
        seen = set()
    first_run = not seen
    s, api = h1()
    try:
        mine = json.load(open(os.path.join(WS, ".claude/state/h1-self/my-reports.json")))["reports"]
    except (OSError, ValueError, KeyError):
        sys.exit("no .claude/state/h1-self/my-reports.json; run scripts/h1-selfdup.py --sync first")
    me = None
    try:
        me = s.get(f"{api}/me", timeout=20).json().get("data", {}).get("attributes", {}).get("username")
    except Exception:
        pass
    new = 0
    for r in mine:
        rid = str(r["id"])
        try:
            data = s.get(f"{api}/reports/{rid}", timeout=30).json()["data"]
        except Exception as e:
            print(f"  {rid}: read failed ({e})")
            continue
        for act in data.get("relationships", {}).get("activities", {}).get("data", []):
            key = f"{rid}-{act['id']}"
            if key in seen:
                continue
            seen.add(key)
            actor = act.get("relationships", {}).get("actor", {}).get("data", {})
            who = actor.get("attributes", {}).get("username")
            if act["type"] not in TRIAGER_TYPES or (me and who == me) or act["attributes"].get("internal"):
                continue
            if first_run:  # baseline: history before this tool existed is recorded, not drafted
                continue
            rec = draft(rid, act, r.get("program"))
            new += 1
            with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
                f.write(f"- [{now()}] **REPLY** #{rid} ({r.get('program')}) {act['type'].replace('activity-', '')}: "
                        f"draft {rec['status']} - read it with: python3 scripts/h1-replies.py show {key}\n")
    json.dump(sorted(seen), open(seen_p, "w"))
    print(f"sync: {len(mine)} reports, {new} new triager message(s) drafted" + (" (first run: baseline recorded)" if first_run else ""))


def drafts():
    out = []
    for p in sorted(glob.glob(os.path.join(DR, "*.json"))):
        out.append(json.load(open(p)))
    return out


def pick(sel):
    ds = [d for d in drafts() if not d.get("sent")]
    if sel.isdigit() and int(sel) <= len(ds):
        return ds[int(sel) - 1]
    for d in drafts():
        if f"{d['report']}-{d['activity']}" == sel or d["report"] == sel:
            return d
    sys.exit(f"no draft {sel!r} (h1-replies.py list)")


def main(a):
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    if a[0] == "sync":
        sync()
    elif a[0] == "list":
        ds = [d for d in drafts() if not d.get("sent")]
        for i, d in enumerate(ds, 1):
            print(f"  {i}. #{d['report']} {d['program']:<16} {d['kind'].replace('activity-', ''):<22} {d['status']}")
        if not ds:
            print("  no unsent drafts")
    elif a[0] == "show" and len(a) > 1:
        d = pick(a[1])
        print(f"#{d['report']} {d['program']}  {d['kind']}  {d['link']}\n\nTRIAGER:\n{d['triager_message']}\n\n"
              f"DRAFT ({d['status']}{': ' + '; '.join(d.get('problems') or []) if d.get('problems') else ''}):\n{d['reply']}\n"
              + (f"\nNOTE: {d['advice']}" if d.get("advice") else "")
              + f"\n\nPost it on {d['link']}, then: python3 scripts/h1-replies.py sent {d['report']}-{d['activity']}")
    elif a[0] == "sent" and len(a) > 1:
        d = pick(a[1])
        d["sent"], d["sent_at"] = True, now()
        json.dump(d, open(os.path.join(DR, f"{d['report']}-{d['activity']}.json"), "w"), indent=1)
        print("marked sent")
    elif a[0] == "redo" and len(a) > 1:
        d = pick(a[1])
        act = {"id": d["activity"], "type": d["kind"], "attributes": {"message": d["triager_message"], "created_at": d["at"]}}
        r = draft(d["report"], act, d["program"], " ".join(a[2:]))
        print(f"{r['status']}:\n{r['reply']}")
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
