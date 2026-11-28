#!/usr/bin/env python3
"""
lib_emailnator.py - real-Gmail-alias inbox for signup flows that DOMAIN-BLOCK disposable
mailboxes (mail.tm, guerrillamail). Emailnator hands out dot/plus aliases of a real, rotating
Gmail mailbox; those aliases receive genuine inbound mail from strict senders (e.g. 2K/Okta OTP)
and are readable via its message-list API. Drop-in for bbtools TempInbox: same .addr / .wait_for
/ message-dict shape consumed by links()/codes().

Emailnator is a THIRD-PARTY MAILBOX PROVIDER (infrastructure), not a scope target. Same category
as mail.tm which bbtools already uses freely.

API (Laravel + XSRF double-submit):
  GET  /                         -> sets XSRF-TOKEN + gmailnator_session cookies
  POST /generate-email {email:[...]} -> {"email":["<alias>@gmail.com"]}
       email option list: dotGmail, plusGmail (real gmail aliases), googleMail, domain, ...
  POST /message-list {email}          -> {"messageData":[{messageID,from,subject,time}, ...]}
  POST /message-list {email,messageID}-> raw HTML of that message
Header X-XSRF-TOKEN must equal url-decoded XSRF-TOKEN cookie.
"""
import time, urllib.parse, re
from curl_cffi import requests as creq

BASE = "https://www.emailnator.com"
# ADSVPN / "AI TOOLS" welcome ad is pre-seeded in every fresh alias; ignore it as noise.
_AD_IDS = {"ADSVPN"}


class EmailnatorInbox:
    """Real-Gmail-alias inbox. .addr / .wait_for(pred, timeout) match bbtools TempInbox."""

    def __init__(self, kind=("dotGmail", "plusGmail"), session=None):
        self.s = session or creq.Session(impersonate="chrome124")
        self._boot()
        self.addr = self._generate(list(kind))
        self._seen = set(_AD_IDS)
        # snapshot any pre-existing ad/backlog IDs so ONLY mail arriving after this alias
        # was minted (i.e. the target's verification email) surfaces from messages().
        try:
            for meta in self._list():
                mid = meta.get("messageID")
                if mid:
                    self._seen.add(mid)
        except Exception:
            pass

    # ---- internals ----
    def _boot(self):
        self.s.get(BASE + "/", timeout=30)
        tok = self.s.cookies.get("XSRF-TOKEN")
        if not tok:
            raise RuntimeError("emailnator: no XSRF-TOKEN cookie (CF block?)")
        self._xsrf = urllib.parse.unquote(tok)

    def _hdrs(self):
        return {
            "X-XSRF-TOKEN": self._xsrf,
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": BASE + "/",
            "Origin": BASE,
            "Accept": "application/json, text/plain, */*",
        }

    def _generate(self, kind):
        for attempt in range(4):
            r = self.s.post(BASE + "/generate-email", headers=self._hdrs(),
                            json={"email": kind}, timeout=30)
            if r.status_code == 200:
                try:
                    e = r.json().get("email")
                except Exception:
                    e = None
                if e:
                    return e[0] if isinstance(e, list) else e
            # refresh XSRF and retry
            time.sleep(2 + attempt)
            self._boot()
        raise RuntimeError(f"emailnator generate-email failed: {r.status_code} {r.text[:160]}")

    def _list(self):
        r = self.s.post(BASE + "/message-list", headers=self._hdrs(),
                        json={"email": self.addr}, timeout=30)
        if r.status_code != 200:
            return []
        try:
            return r.json().get("messageData", []) or []
        except Exception:
            return []

    def _body(self, message_id):
        r = self.s.post(BASE + "/message-list", headers=self._hdrs(),
                        json={"email": self.addr, "messageID": message_id}, timeout=30)
        return r.text if r.status_code == 200 else ""

    # ---- bbtools-compatible message dict ----
    def _fetch_msg(self, meta):
        html = self._body(meta["messageID"])
        return {
            "id": meta["messageID"],
            "from": meta.get("from", ""),
            "subject": meta.get("subject", ""),
            # links()/codes() read .get("html") (list|str) and .get("text")
            "html": [html],
            "text": "",
            "_raw": html,
        }

    def messages(self):
        out = []
        for meta in self._list():
            mid = meta.get("messageID")
            if not mid or mid in self._seen:
                continue
            self._seen.add(mid)
            out.append(self._fetch_msg(meta))
        return out

    def poll(self, timeout=180, interval=5):
        end = time.time() + timeout
        while time.time() < end:
            for m in self.messages():
                yield m
            time.sleep(interval)

    def wait_for(self, pred, timeout=180):
        for msg in self.poll(timeout=timeout):
            if pred(msg):
                return msg
        return None


def selfcheck():
    ib = EmailnatorInbox()
    print("alias:", ib.addr)
    assert ib.addr.endswith("@gmail.com"), ib.addr
    lst = ib._list()
    print("initial message-list count:", len(lst))
    print("emailnator selfcheck OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selfcheck":
        selfcheck()
    else:
        ib = EmailnatorInbox()
        print(ib.addr)
