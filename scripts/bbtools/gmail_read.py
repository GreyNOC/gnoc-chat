#!/usr/bin/env python3
"""Read the real Gmail inbox (GMAIL_USER, e.g. researcher@example.com) through
the operator's live logged-in Chrome over CDP. The premium provisioning channel for signup
flows that reject disposable/alias email.

HOW: talk raw CDP (Runtime.evaluate) to the ALREADY-OPEN mail.google.com tab and run
fetch('/feed/atom/') inside it. Same-origin, credentials ride the tab's cookies, which
never leave the browser. No playwright, no page driving (does not disturb their session),
no cookie dump, no IMAP password. Needs cdp-chrome.sh up + that Chrome logged into Gmail.

Any worker (Bash) calls:
    python3 scripts/bbtools/gmail_read.py                 # newest inbox entries
    python3 scripts/bbtools/gmail_read.py "Verify"        # subject-substring filter
    python3 scripts/bbtools/gmail_read.py "code" --wait 120   # poll until one arrives
    python3 scripts/bbtools/gmail_read.py selfcheck       # liveness

Returns JSON: [{from, subject, snippet, links[], codes[], link}]. Fire a signup, then
`gmail_read "<sender/subject word>" --wait 120` to grab the activation link or OTP.

ponytail CEILING: the Atom <summary> is a truncated snippet (~first few hundred chars),
so a long activation URL buried deep in the body may be cut. codes() (OTP) and short
links land fine. For guaranteed full-body reads add IMAP via a Gmail App Password
(GMAIL_APP_PASS in secrets.env, one operator step) - upgrade path, not built until needed.
"""
import os
import sys
import json
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_provision import links, codes   # noqa: E402

_ATOM = "https://mail.google.com/mail/u/0/feed/atom/"   # newest ~20; /UNREAD for unread-only


def _cdp_eval(expr, timeout=20):
    """Runtime.evaluate an awaited JS expression in the open mail.google.com tab, via the shared
    robust CDP primitive (literal-IP loopback + suppress_origin + safe framing; no hand-roll)."""
    from lib_browser import cdp_ws_call
    r = cdp_ws_call("Runtime.evaluate",
                    {"expression": expr, "awaitPromise": True, "returnByValue": True},
                    url_match="mail.google.com", timeout=timeout)
    return (r.get("result") or {}).get("value", "") or ""


def _atom():
    expr = "fetch(%s,{credentials:'include'}).then(r=>r.text())" % json.dumps(_ATOM)
    return _cdp_eval(expr)


def _entries(xml_text):
    """Namespace-agnostic Atom parse -> list of {title, summary, id, link, from_*}."""
    out = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out
    for e in root.iter():
        if e.tag.split("}")[-1] != "entry":
            continue
        d = {}
        for c in e:
            t = c.tag.split("}")[-1]
            if t == "link":
                d["link"] = c.get("href", "")
            elif t == "author":
                for a in c:
                    d["from_" + a.tag.split("}")[-1]] = (a.text or "")
            else:
                d[t] = (c.text or "")
        out.append(d)
    return out


def _shape(d):
    subj = d.get("title", "")
    body = d.get("summary", "")
    msg = {"text": subj + "\n" + body, "html": body}
    return {
        "from": d.get("from_email") or d.get("from_name", ""),
        "subject": subj,
        "snippet": body[:300],
        "links": links(msg),
        "codes": codes(msg),
        "link": d.get("link", ""),
    }


def read(subject=None):
    res = []
    for d in _entries(_atom()):
        if subject and subject.lower() not in d.get("title", "").lower():
            continue
        res.append(_shape(d))
    return res


def wait_for(subject, timeout=150, interval=5):
    end = time.time() + timeout
    while time.time() < end:
        r = read(subject)
        if r:
            return r
        time.sleep(interval)
    return []


def selfcheck():
    try:
        xml = _atom()
    except Exception as e:
        print("SELFCHECK SKIP (CDP down / no Gmail tab):", str(e)[:200])
        return
    if not xml.strip():
        print("SELFCHECK SKIP: empty feed (Chrome not logged into Gmail?)")
        return
    print("SELFCHECK PASS: Atom feed reachable, %d entries parsed" % len(_entries(xml)))


def _secret(key):
    p = os.path.expanduser("~/.config/gnoc/secrets.env")
    try:
        for line in open(p):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip("'\"")
    except FileNotFoundError:
        pass
    return ""


def gmail_alias(tag):
    """Plus-alias of GMAIL_USER (name+<tag>@gmail.com): routes to the base inbox, passes
    disposable-email blocklists. Unique tag per provision to disambiguate concurrent flows."""
    u = _secret("GMAIL_USER")
    name, _, dom = u.partition("@")
    return "%s+%s@%s" % (name, tag, dom) if u else ""


def gmail_confirm(subject_hint, want=None, timeout=180, interval=6):
    """Close the provisioning loop: poll for the signup mail, extract+unwrap the verify link,
    GET it to activate. want = substring the link must contain (target host/'confirm'/'oobCode').
    Returns {link,status,ok,subject,codes} or {error}. CEILING: rides the atom snippet, so a
    long verify URL past the snippet is missed - use gmail_imap (full body) when GMAIL_APP_PASS is set."""
    import urllib.request
    from lib_provision import unwrap as _unwrap
    end = time.time() + timeout
    while time.time() < end:
        for e in read(subject_hint):
            picks = []
            for l in e.get("links", []):
                u = l if (want and want in l) else _unwrap(l)
                if (not want) or (want in u):
                    picks.append(u)
            if picks:
                url = picks[0]
                try:
                    r = urllib.request.urlopen(url, timeout=20)
                    return {"link": url, "status": r.status, "ok": 200 <= r.status < 400,
                            "subject": e["subject"], "codes": e.get("codes", [])}
                except Exception as ex:
                    return {"link": url, "error": str(ex)[:140], "subject": e["subject"]}
        time.sleep(interval)
    return {"error": "no matching verify mail in %ss" % timeout}


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "selfcheck":
        selfcheck()
        sys.exit(0)
    if args and args[0] == "confirm":
        rest = args[1:]
        cw = None
        if "--wait" in rest:
            j = rest.index("--wait")
            cw = int(rest[j + 1])
            del rest[j:j + 2]
        subj = rest[0] if rest else ""
        want = rest[1] if len(rest) > 1 and not rest[1].startswith("--") else None
        print(json.dumps(gmail_confirm(subj, want, 180 if cw is None else cw)))
        sys.exit(0)
    wait = 0
    if "--wait" in args:
        i = args.index("--wait")
        wait = int(args[i + 1])
        del args[i:i + 2]
    subj = args[0] if args else None
    r = wait_for(subj, wait) if wait else read(subj)
    for e in r:
        e["links"] = e["links"][:40]
    print(json.dumps(r, indent=2))
    sys.exit(0 if (r or not subj) else 2)
