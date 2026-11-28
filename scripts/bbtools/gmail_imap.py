#!/usr/bin/env python3
"""Full-body Gmail read over IMAP (imap.gmail.com). Removes gmail_read's atom-snippet ceiling
and works headless (no Chrome, no CDP) - good for cron / background fleet agents.

NEEDS (one operator step): GMAIL_USER + GMAIL_APP_PASS in ~/.config/gnoc/secrets.env.
GMAIL_APP_PASS is a 16-char Google App Password (Account -> Security -> App passwords;
requires 2FA on the account). The real login password will NOT work - Google disabled
basic-auth IMAP in 2022. Until GMAIL_APP_PASS is set, selfcheck prints NEEDS and every
read raises a clear error.

    python3 scripts/bbtools/gmail_imap.py                 # newest unread, full body
    python3 scripts/bbtools/gmail_imap.py "Verify"        # subject filter
    python3 scripts/bbtools/gmail_imap.py "code" --wait 120
    python3 scripts/bbtools/gmail_imap.py selfcheck

Returns JSON [{from, subject, date, links[], codes[]}] parsed from the FULL body.
"""
import os
import sys
import ssl
import json
import time
import imaplib
import email
from email.header import decode_header

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lib_provision import links, codes   # noqa: E402


def _secret(key):
    p = os.path.expanduser("~/.config/gnoc/secrets.env")
    try:
        for line in open(p):
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip("'\"")
    except FileNotFoundError:
        pass
    return ""


def _dec(part):
    try:
        pl = part.get_payload(decode=True)
        return pl.decode(part.get_content_charset() or "utf-8", "replace") if pl else ""
    except Exception:
        return ""


def _body(msg):
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                text += _dec(part)
            elif ct == "text/html":
                html += _dec(part)
    else:
        text = _dec(msg)
    return {"text": text, "html": html}


def _hdr(v):
    if not v:
        return ""
    out = []
    for s, enc in decode_header(v):
        out.append(s.decode(enc or "utf-8", "replace") if isinstance(s, bytes) else s)
    return "".join(out)


def read(subject=None, unseen=True, limit=15):
    user, pw = _secret("GMAIL_USER"), _secret("GMAIL_APP_PASS")
    if not user or not pw:
        raise RuntimeError("GMAIL_APP_PASS missing in secrets.env - enable 2FA + make a 16-char "
                           "App Password (the real login password will NOT work for IMAP)")
    M = imaplib.IMAP4_SSL("imap.gmail.com", 993, ssl_context=ssl.create_default_context())
    M.login(user, pw)
    M.select("INBOX")
    crit = (["UNSEEN"] if unseen else []) + (["SUBJECT", subject] if subject else [])
    _typ, data = M.search(None, *(crit or ["ALL"]))
    ids = data[0].split()[-limit:]
    res = []
    for i in reversed(ids):
        _typ, d = M.fetch(i, "(BODY.PEEK[])")   # PEEK = do not mark the mail read
        msg = email.message_from_bytes(d[0][1])
        b = _body(msg)
        res.append({"from": _hdr(msg.get("From")), "subject": _hdr(msg.get("Subject")),
                    "date": msg.get("Date", ""), "links": links(b), "codes": codes(b)})
    M.logout()
    return res


def wait_for(subject, timeout=150, interval=6):
    end = time.time() + timeout
    while time.time() < end:
        r = read(subject)
        if r:
            return r
        time.sleep(interval)
    return []


def selfcheck():
    if not _secret("GMAIL_APP_PASS"):
        print("SELFCHECK NEEDS: set GMAIL_APP_PASS in secrets.env (2FA + 16-char App Password). "
              "Real password will NOT work for IMAP. Code is wired and waiting.")
        return
    try:
        r = read(limit=1)
        print("SELFCHECK PASS: IMAP login OK, %d msg sampled" % len(r))
    except Exception as e:
        print("SELFCHECK FAIL:", str(e)[:200])


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "selfcheck":
        selfcheck()
        sys.exit(0)
    wait = 0
    if "--wait" in args:
        i = args.index("--wait")
        wait = int(args[i + 1])
        del args[i:i + 2]
    subj = args[0] if args else None
    r = wait_for(subj, wait) if wait else read(subj)
    for e in r:                       # cap link spam; the verify link is always near the top
        e["links"] = e["links"][:40]
    print(json.dumps(r, indent=2))
    sys.exit(0 if (r or not subj) else 2)
