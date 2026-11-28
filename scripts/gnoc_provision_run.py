#!/usr/bin/env python3
"""gnoc_provision_run.py - the subprocess behind gnoc chat's `provision` tool (2026-10-23).

Reads ONE JSON object on stdin, runs the matching scripts/bbtools/lib_provision helper, prints ONE JSON object on
stdout. It runs out of process so a Playwright crash, a hung inbox poll or a bot-wall loop can never take the chat
turn down with it (run_tools abandons it on timeout). The chat never sees a password: the account JSON under
targets/<program>/accounts/<tag>.json and the ACCOUNTS.md row (both written by lib_provision.save_account) hold
them; this runner only reports status, email, state_path, verify fields and a note.

    {"action": "inbox",    "program": p, "tag": "A"}
    {"action": "wait",     "token": "<mail.tm token>", "seconds": 150}
    {"action": "register", "program": p, "signup_url": u, "tag": "A", "overrides": {...}, "verify": "auto",
                           "headless": true, "scope_file": "targets/p/SCOPE.txt"}
    {"action": "pair",     "program": p, "signup_url": u, "tags": ["A", "B"], "role_urls": [uA, uB] | null, ...}
    {"action": "simple",   "program": p, "register_url": u, "tag": "A", "extra": {...}, "as_form": false,
                           "email_field": "email", "password_field": "password", "verify": "auto"}
"""
import json
import os
import sys

WS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(WS, "scripts"))

PUBLIC = ("status", "email", "username", "state_path", "verify_link", "verify_status", "captcha", "note",
          "signup_url", "role", "tag", "verify_code")


def _public(d):
    """Only the fields the chat may see. Never the password, never the raw form fields."""
    if not isinstance(d, dict):
        return {"status": "error", "note": f"unexpected result {type(d).__name__}"}
    out = {k: d.get(k) for k in PUBLIC if d.get(k) is not None}
    rs = d.get("register_status")
    if isinstance(rs, int) and rs >= 400:
        # simple_register answered with the target's refusal: that is NOT an account (the chat saw "status=ok" for a
        # 400 "Invalid input" on program-101, 2026-10-23)
        out["status"] = "error"
        out["note"] = f"register POST answered {rs}: {str(d.get('register_body') or '')[:160]}"
    out.setdefault("status", "ok" if d.get("email") or d.get("state_path") else "unknown")
    if d.get("password"):
        out["password_stored"] = True
    return out


def _browser_proxy(p):
    """Chromium knows socks5://, not socks5h:// (Page.goto: net::ERR_NO_SUPPORTED_PROXIES, program-101 2026-10-23). The
    curl paths keep socks5h (remote DNS); the browser gets the plain scheme and resolves through the proxy anyway."""
    p = (p or "").strip()
    if p.lower().startswith("socks5h://"):
        return "socks5://" + p[len("socks5h://"):]
    return p or None


def main():
    a = json.load(sys.stdin)
    from bbtools import lib_provision as L
    act = a.get("action")
    if act == "inbox":
        ib = L.TempInbox()
        d = {"address": ib.addr, "token": ib.token}
        if a.get("program"):
            L.save_account(a["program"], f"inbox-{a.get('tag') or 'A'}",
                           {"email": ib.addr, "password": ib.password, "token": ib.token, "role": "inbox"})
        return d
    if act == "wait":
        ib = L.TempInbox.attach(a["token"])
        seen = []
        for m in ib.poll(timeout=int(a.get("seconds") or 150)):
            seen.append({"from": m.get("from"), "subject": m.get("subject"), "links": L.links(m)[:5],
                         "codes": L.codes(m)[:5]})
        return {"messages": seen, "status": "ok" if seen else "no-mail"}
    if act == "register":
        r = L.browser_register(a["signup_url"], handle=a["program"], tag=a.get("tag") or "A",
                               headless=a.get("headless", True), scope_file=a.get("scope_file"),
                               overrides=a.get("overrides") or None, verify=a.get("verify") or "auto",
                               proxy=_browser_proxy(a.get("proxy")))
        p = _public(r)
        p["tag"] = a.get("tag") or "A"
        return p
    if act == "pair":
        tags = tuple(a.get("tags") or ("A", "B"))
        kw = {"headless": a.get("headless", True), "scope_file": a.get("scope_file"),
              "overrides": a.get("overrides") or None, "verify": a.get("verify") or "auto", "proxy": _browser_proxy(a.get("proxy"))}
        A, B = L.provision_pair_browser(a["program"], a["signup_url"], tags=tags, roles=a.get("role_urls"), **kw)
        pa, pb = _public(A), _public(B)
        pa["tag"], pb["tag"] = tags[0], tags[1]
        return {"accounts": [pa, pb]}
    if act == "simple":
        r = L.simple_register(a["register_url"], extra=a.get("extra") or None, as_form=bool(a.get("as_form")),
                              verify=a.get("verify") or "auto", email_field=a.get("email_field") or "email",
                              password_field=a.get("password_field") or "password")
        if isinstance(r, dict) and a.get("program"):
            L.save_account(a["program"], a.get("tag") or "A", dict(r, role=a.get("role") or "simple"))
        p = _public(r if isinstance(r, dict) else {"note": str(r)[:300]})
        p["tag"] = a.get("tag") or "A"
        return p
    return {"status": "error", "note": f"unknown action {act!r}"}


if __name__ == "__main__":
    try:
        res = main()
    except Exception as e:  # noqa: BLE001 - the chat gets a status, never a traceback dump
        res = {"status": "error", "note": f"{type(e).__name__}: {str(e)[:300]}"}
    print(json.dumps(res))
