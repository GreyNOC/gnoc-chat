#!/usr/bin/env python3
"""
lib_unauth.py - the strip-auth diff + SPA-200 discipline as a tested tool.

Two things every unauth pass needs and keeps getting wrong by eyeball:
  - THE MOVE: fire every route with and without a session, diff STATUS and BODY.
  - THE #1 FALSE POSITIVE: an SPA returns 200 + index.html for EVERY path, so a bare
    unauth 200 is NOT a disclosure (H1 RULE-2 "reachable is not a finding" kills these).

classify() is pure logic (offline-testable), verdicts:
  PROTECTED          unauth 401/403
  REDIRECT           unauth 30x (usually a login bounce; inspect for open-redirect)
  ABSENT             unauth 404
  PUBLIC-SHELL       unauth 200 == the SPA shell (html, len ~= a nonsense-sibling that
                     also 200s) -> NOT a lead
  PRIVATE-BUT-OPEN   unauth 200 with a real private body (non-html, or len differs from
                     the shell and a nonsense-sibling 404s; if an authed probe is given,
                     the unauth body aligns with the authed one) -> THE LEAD
  PUBLIC-DATA        unauth 200 real data, by-design public (no authed delta)

CLI:
  lib_unauth.py diff <scope_file> <routes_file> [--authstate state.json]
  lib_unauth.py selfcheck
"""
import json, os, random, string, sys
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    from bbtools.lib_egress import make_session, OutOfScope  # scope-gated session
except Exception:                                            # pragma: no cover
    make_session = None

    class OutOfScope(Exception):
        pass

HTML_CT = ("text/html", "application/xhtml")


def nonsense_sibling(url):
    """Same path shape, last segment replaced with junk - the 404 control that tells a
    real route from an SPA shell (both may 200)."""
    p = urlparse(url)
    segs = p.path.rstrip("/").split("/")
    if segs and segs[-1]:
        segs[-1] = "zzz" + "".join(random.choice(string.ascii_lowercase) for _ in range(9))
    else:
        segs.append("zzz" + "".join(random.choice(string.ascii_lowercase) for _ in range(9)))
    return urlunparse(p._replace(path="/".join(segs)))


def resp_of(r):
    body = getattr(r, "text", "") or ""
    return {"status": r.status_code, "len": len(body),
            "ctype": (r.headers.get("content-type") or "").split(";")[0].strip().lower(),
            "body": body[:600]}


def probe(session, url, method="GET", **kw):
    kw.setdefault("timeout", 20)
    return resp_of(session.request(method, url, **kw))


def is_html(resp):
    return any(h in resp["ctype"] for h in HTML_CT)


def _aligns(a, b, tol=0.25):
    # same content-type and comparable length -> likely the same object shape
    return a["ctype"] == b["ctype"] and b["len"] and abs(a["len"] - b["len"]) <= tol * max(a["len"], b["len"], 1)


_AUTH_ERR = ("authentication required", "unauthenticated", "not authorized", "unauthorized",
             "access denied", "login required", "invalid token", "missing token", "must be logged in")


def _looks_auth_error(resp):
    b = (resp.get("body") or "").lower()
    return any(m in b for m in _AUTH_ERR)


def classify(unauth, sibling, authed=None, shell_len_tol=0.15):
    """SPA-200 discipline. unauth/sibling/authed are resp_of() dicts. Pure."""
    s = unauth["status"]
    if s in (401, 403):
        return "PROTECTED"
    if s in (301, 302, 303, 307, 308):
        return "REDIRECT"
    if s == 404:
        return "ABSENT"
    if s != 200:
        return f"STATUS-{s}"
    # 200: is it the SPA shell? (html, and ~= a nonsense-sibling that also 200s html)
    shell = sibling["status"] == 200 and is_html(unauth) and is_html(sibling)
    close = sibling["len"] and abs(unauth["len"] - sibling["len"]) <= shell_len_tol * max(unauth["len"], sibling["len"], 1)
    if shell and close:
        return "PUBLIC-SHELL"
    # a real 200 body
    if authed is not None and not is_html(unauth) and unauth["len"] > 0 and _aligns(unauth, authed):
        return "PRIVATE-BUT-OPEN"
    # data route, non-shell: a lead ONLY if it carries a real body and is not itself an auth-error
    if (not is_html(unauth) and unauth["len"] > 0 and sibling["status"] in (400, 404)
            and not (unauth["len"] < 200 and _looks_auth_error(unauth))):
        # suppress only a SHORT body dominated by an auth-error message; a large data body that
        # merely contains "unauthorized" incidentally is still the lead.
        return "PRIVATE-BUT-OPEN"
    return "PUBLIC-DATA"


_ORDER = {"PRIVATE-BUT-OPEN": 0, "PUBLIC-DATA": 1, "REDIRECT": 2, "PUBLIC-SHELL": 3,
          "PROTECTED": 4, "ABSENT": 5, "OOS": 6, "ERR": 7}


def strip_auth_diff(routes, unauth_session, authed_session=None, method="GET"):
    """Probe unauth + a nonsense-sibling control (+ authed if given) per route, classify.
    Returns rows sorted leads-first."""
    rows = []
    for url in routes:
        try:
            u = probe(unauth_session, url, method)
            sib = probe(unauth_session, nonsense_sibling(url), method)
            a = probe(authed_session, url, method) if authed_session else None
            v = classify(u, sib, a)
            rows.append({"url": url, "verdict": v, "unauth": u["status"], "len": u["len"],
                         "ctype": u["ctype"], "sibling": sib["status"],
                         "authed": (a["status"] if a else None)})
        except OutOfScope as e:
            rows.append({"url": url, "verdict": "OOS", "err": str(e)})
        except Exception as e:
            rows.append({"url": url, "verdict": "ERR", "err": str(e)[:120]})
    rows.sort(key=lambda r: _ORDER.get(r["verdict"], 3))
    return rows


def bypass_variants(url, header_ip="127.0.0.1"):
    """Generate the 403/401-bypass ladder: path-normalization, header-spoof, method-tamper
    variants of url. Returns [(label, method, url, headers)]. Pure - testable offline."""
    p = urlparse(url)
    path = p.path or "/"
    base = urlunparse(p._replace(path="", query="", fragment=""))   # scheme://host
    out = []
    for label, np in [("trailing-slash", path + "/"), ("trailing-dot", path + "/."),
                      ("double-slash", "//" + path.lstrip("/")), ("dot-slash", "/./" + path.lstrip("/")),
                      ("semicolon", path + ";"), ("encoded-slash", path + "%2f"),
                      ("space-suffix", path + "%20"), ("uppercase", path.upper()),
                      ("null-suffix", path + "%00"), ("dotdot-semi", path + "/..;/")]:
        out.append((f"path:{label}", "GET", base + np, {}))
    for label, hdr in [("x-original-url", {"X-Original-URL": path}),
                       ("x-rewrite-url", {"X-Rewrite-URL": path}),
                       ("x-forwarded-for", {"X-Forwarded-For": header_ip}),
                       ("x-forwarded-host", {"X-Forwarded-Host": "localhost"}),
                       ("x-real-ip", {"X-Real-IP": header_ip}),
                       ("x-originating-ip", {"X-Originating-IP": header_ip}),
                       ("x-custom-ip-auth", {"X-Custom-IP-Authorization": header_ip})]:
        out.append((f"hdr:{label}", "GET", url, hdr))
    for m in ("POST", "PUT", "PATCH", "HEAD", "OPTIONS", "TRACE"):
        out.append((f"method:{m}", m, url, {}))
    return out


def bypass_ladder(session, url, baseline_status=None, method="GET"):
    """Fire the 403/401-bypass ladder; return variants whose status differs from the baseline
    and is not a plain error - a 200 where a plain GET 403'd is the candidate bypass."""
    if baseline_status is None:
        baseline_status = probe(session, url, method)["status"]
    hits = []
    for label, m, u, hdr in bypass_variants(url):
        try:
            r = probe(session, u, m, headers=hdr) if hdr else probe(session, u, m)
            if r["status"] != baseline_status and r["status"] not in (400, 404, 405, 501):
                hits.append({"label": label, "status": r["status"], "len": r["len"],
                             "method": m, "url": u, "headers": hdr})
        except Exception:
            pass
    return {"baseline": baseline_status, "url": url, "hits": hits}


def _selfcheck():
    html = lambda n: {"status": 200, "len": n, "ctype": "text/html", "body": "<html>"}
    js = lambda n: {"status": 200, "len": n, "ctype": "application/json", "body": "{}"}
    r404 = {"status": 404, "len": 20, "ctype": "text/html", "body": ""}
    # SPA shell -> not a lead
    assert classify(html(5000), html(5050)) == "PUBLIC-SHELL", "shell"
    # data route, sibling 404 -> lead
    assert classify(js(800), r404) == "PRIVATE-BUT-OPEN", "data-lead"
    # protected
    assert classify({"status": 403, "len": 0, "ctype": "", "body": ""}, html(10)) == "PROTECTED"
    # authed-aligned open private
    assert classify(js(800), r404, authed=js(820)) == "PRIVATE-BUT-OPEN", "authed-align"
    # a real html page that is NOT the shell (sibling 404s) is not auto-shell
    assert classify(html(9000), r404) == "PUBLIC-DATA"
    # a 200 auth-error JSON body with a 404 sibling is NOT a lead (false-positive guard)
    autherr = {"status": 200, "len": 40, "ctype": "application/json", "body": '{"error":"authentication required"}'}
    assert classify(autherr, r404) == "PUBLIC-DATA", "auth-error must not be PRIVATE-BUT-OPEN"
    # a LARGE data body that merely contains 'unauthorized' incidentally is STILL a lead
    big = {"status": 200, "len": 300, "ctype": "application/json",
           "body": '{"logs":[{"user":"alice","action":"unauthorized_access_attempt","ssn":"x"}]}'}
    assert classify(big, r404) == "PRIVATE-BUT-OPEN", "large data body must stay a lead"
    # an empty-body 200 is not a lead
    assert classify({"status": 200, "len": 0, "ctype": "application/json", "body": ""}, r404) == "PUBLIC-DATA"
    # nonsense sibling mutates only the last segment
    assert nonsense_sibling("https://x.com/api/users/42").rsplit("/", 1)[0] == "https://x.com/api/users"
    # bypass ladder generates path + header + method variants
    v = bypass_variants("https://x.com/admin/panel")
    labels = [l for l, _, _, _ in v]
    assert any(l == "path:trailing-slash" for l in labels) and any(l == "method:PUT" for l in labels)
    xo = [h for l, m, u, h in v if l == "hdr:x-original-url"][0]
    assert xo["X-Original-URL"] == "/admin/panel"
    ts = [u for l, m, u, h in v if l == "path:trailing-slash"][0]
    assert ts.endswith("/admin/panel/"), ts
    ds = [u for l, m, u, h in v if l == "path:double-slash"][0]
    assert ds.endswith("//admin/panel"), ds  # real // bypass, not a trailing-slash dup
    print("SELFCHECK OK  SPA-200 discipline + 403-bypass ladder variants pass")


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    if argv[0] == "selfcheck":
        return _selfcheck()
    if argv[0] == "diff":
        if make_session is None:
            print("lib_egress unavailable; run from workspace root")
            return
        scope_file, routes_file = argv[1], argv[2]
        routes = [l.strip() for l in open(routes_file) if l.strip() and not l.startswith("#")]
        sess = make_session(scope_file)
        rows = strip_auth_diff(routes, sess)
        for r in rows:
            print(f"{r['verdict']:16} {r.get('unauth',''):>4} sib={r.get('sibling','')} "
                  f"len={r.get('len','')} {r.get('ctype','')}  {r['url']}")
        leads = [r for r in rows if r["verdict"] in ("PRIVATE-BUT-OPEN", "PUBLIC-DATA")]
        print(f"\n{len(leads)} lead(s) of {len(rows)} routes")
        return
    print("unknown cmd:", argv[0])
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
