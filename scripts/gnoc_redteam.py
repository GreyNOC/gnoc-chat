"""gnoc_redteam.py - actively TEST the user's own site, instead of trusting what it says about itself.

gnoc_site reads the posture scorecard; that scorecard is the site grading its own CONFIGURATION. "100/100
hardened" means every switch is set, not that anything was tried. This module tries them, and every check is
tied to a claim the site makes:

    claim                                   this module
    "admin authority is isolated"           every /api/dashboard/* route, unauthenticated, with a junk token,
                                            and with the READ-ONLY monitoring token - a 200 on any of them is
                                            the whole credential-separation claim falsified
    "CSP, HSTS, frame isolation active"     reads them off a real response and checks their VALUES
    "host allow-list enforcement"           asks for the site with somebody else's Host header
    "bounded per-IP request ceilings"       bursts one public route until it is told to stop (opt-in: loud)
    "learner data at rest"                  reads the store's own encryption flag back out of the overview
    (no claim)                              CORS reflection, cookie flags, path traversal on the static mount,
                                            stack traces in error bodies, origin/edge header drift

SAFETY, in code and not in a promise:
  - The target is fixed: the loopback port from the site's own .env, plus its PUBLIC_URL for the edge check.
    No argument of any kind reaches a URL, so this cannot be pointed at a third party.
  - Nothing can change state. Mutating verbs are sent ONLY unauthenticated AND with a deliberately
    unparseable body, so even a total authentication bypass could not carry a change through: the test for
    "is this route guarded" cannot itself write anything.
  - The loud check (the rate-limit burst) is off unless confirm=True, and is bounded.
  - Every request carries a distinctive User-Agent with the run id, so the events it leaves in their console are
    attributable to this drill and not to an attacker. GreyWatch never bans loopback (it is exempt) but it does
    RECORD, so the console will light up: the report says so in its first line, every time.
"""
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request

import gnoc_site

SEVERITY = ("critical", "high", "medium", "low", "info")
CHECKS = ("authz", "headers", "host", "cors", "cookies", "traversal", "errors", "store", "limits", "edge",
          "feed", "surface")
DEFAULT = ("authz", "headers", "host", "cors", "cookies", "traversal", "errors", "store", "surface")
# A named part of the site, so "QA/QC the campus live feed" tests THAT and not the whole service. An area the
# drill does not have is refused by name: claiming to have tested a subsystem it never touched is the one
# failure mode worse than finding nothing (2026-10-25: a QA/QC of the campus live feed was answered with a
# generic whole-site drill and reported "complete").
AREAS = {"site": DEFAULT, "campus-live-feed": ("feed",)}
BURST = 40          # requests in the rate-limit check, when it is confirmed
ROUTE_CAP = 60      # ops routes probed in one run
REPEAT_S = 30 * 60  # an identical drill inside this window is reported as a repeat, not as news


def _run_id():
    return "rt-" + secrets.token_hex(3)


def _headers(msg):
    """Header map that KEEPS duplicates: Set-Cookie arrives as several lines, and dict() kept only the last.

    Duplicates are joined with a newline. Only the cookie check depends on the separation; every other
    header the drill reads is single-valued, so a joined value is still that value."""
    out = {}
    for k, v in (msg or {}).items():
        k = k.lower()
        out[k] = out[k] + "\n" + v if k in out else v
    return out


def _req(method, url, headers=None, body=None, timeout=8):
    """One probe. Returns (status, headers, body_text, ms); status 0 means nothing answered."""
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, _headers(resp.headers), resp.read(200_000).decode("utf-8", "replace"), (time.time() - t0) * 1000
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every probe leaks one
            return e.code, _headers(e.headers), e.read(200_000).decode("utf-8", "replace"), (time.time() - t0) * 1000
    except (OSError, ValueError) as e:
        return 0, {}, f"{type(e).__name__}: {e}", (time.time() - t0) * 1000


_ROUTE_RE = r"""app\.(get|post|put|patch|delete)\(\s*(["'`])(/api/[^"'`]*)\2"""
PRIVILEGED_PREFIXES = ("/api/admin", "/api/ops", "/api/internal", "/api/security-events")


def _declared_routes(src):
    """[(method, path)] for every literal app.<verb>('/api/...') declaration, whatever its quote style."""
    return [(m, p) for m, _q, p in re.findall(_ROUTE_RE, src)]


def ops_routes(server_js=None):
    """Every /api/dashboard route the site registers, read out of its own source so a route added tomorrow is
    tested tomorrow. Returns [(method, path)] with :params filled with a harmless placeholder."""
    path = server_js or os.path.join(gnoc_site.SITE_DIR, "server.js")
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return []
    out, seen = [], set()
    for m, p in _declared_routes(src):
        if not p.startswith("/api/dashboard"):
            continue
        probe = re.sub(r":([A-Za-z_]+)", lambda mm: "0.0.0.0" if "key" in mm.group(1) else "zz-probe", p)
        if (m, probe) not in seen:
            seen.add((m, probe))
            out.append((m.upper(), probe))
    return out


def other_gated(server_js=None):
    """Privileged /api prefixes this drill does NOT sweep, counted from the site's own source.

    Read as UNTESTED surface, never as a finding: /api/admin is session-gated, so probing it with the ops
    token would prove nothing, but staying silent about it would let a /api/dashboard sweep read as
    whole-site coverage."""
    path = server_js or os.path.join(gnoc_site.SITE_DIR, "server.js")
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return {}
    counts = {}
    for _m, p in _declared_routes(src):
        for pre in PRIVILEGED_PREFIXES:
            if p == pre or p.startswith(pre + "/"):
                counts[pre] = counts.get(pre, 0) + 1
                break
    return counts


def base_headers(ua, host):
    """Loopback as the TUNNEL delivers it. Without the public Host (and the https hint) the host guard answers
    'Bad Host header.' before any route runs - the first version of this module probed 129 routes that way and
    reported a clean sweep it had not actually performed. Every check sends these except the host-spoof one."""
    h = {"User-Agent": ua}
    if host:
        h["Host"] = host
        h["X-Forwarded-Proto"] = "https"
    return h


def reached(code, text):
    """False when the answer came from the host guard rather than the route."""
    return not (code == 400 and "Bad Host header" in (text or ""))


def _finding(fid, title, severity, status, evidence, fix=""):
    return {"id": fid, "title": title, "severity": severity, "status": status, "evidence": evidence, "fix": fix}


def _hdr(headers, name):
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return None


# ------------------------------------------------------------------ the checks

def check_authz(base, env, ua, host, cap=ROUTE_CAP):
    """Every ops route, with no token / a junk token / the READ-ONLY monitoring token.

    A refusal here is 404 "Not found." (denyOps deliberately gives no route-existence oracle), and a route
    that does not exist answers 404 too - so "404" alone proves NOTHING. A route only counts as verified when
    the admin token makes it answer 2xx and the three unauthorized variants do not: that is the credential
    separation claim, tested. Routes whose probe path never resolves (a :param placeholder) are reported as
    not exercised rather than quietly counted as passing.

    GET routes get the admin control probe. Mutating routes never do - an admin-token POST could actually
    change something - so they are probed unauthenticated with an unparseable body only, and reported as the
    weaker evidence that they are."""
    out, all_routes = [], ops_routes()
    routes = all_routes[:cap]
    if not routes:
        return [_finding("authz.routes", "No ops routes found to test", "info", "skipped",
                         "server.js could not be read, so the sweep had nothing to sweep")]
    if len(all_routes) > cap:
        out.append(_finding("authz.capped", "Ops routes beyond the probe cap", "info", "warn",
                            f"{len(all_routes) - cap} of {len(all_routes)} route(s) were NOT probed: the sweep "
                            f"stops at {cap}. They are untested, not passing.",
                            "Raise ROUTE_CAP, or split the sweep: a capped sweep must never read as complete."))
    admin = env.get("OPS_ADMIN_TOKEN") or ""
    health_token = env.get("HEALTHZ_DETAIL_TOKEN") or ""
    variants = [("no token", {}), ("junk token", {"x-ops-token": "not-the-token"})]
    if health_token and health_token != admin:
        variants.append(("the read-only monitoring token", {"x-ops-token": health_token}))
    opened, verified, unreached, mutating, blocked, limited = [], [], [], [], 0, 0
    for method, path in routes:
        live = None
        if method == "GET" and admin:
            code, _, text, _ = _req("GET", base + path, dict(base_headers(ua, host), **{"x-ops-token": admin}))
            if not reached(code, text):
                blocked += 1
                continue
            live = 200 <= code < 300
        hit = False
        for label, extra in variants:
            code, _, text, _ = _req(method, base + path, dict(base_headers(ua, host), **extra),
                                    "{" if method != "GET" else None)
            if method != "GET":
                pass  # unauthenticated AND unparseable: even an unguarded route cannot be made to act
            if not reached(code, text):
                blocked += 1
                continue
            if code == 429:
                limited += 1
                continue
            if 200 <= code < 300:
                opened.append(f"{method} {path} answered {code} with {label} ({len(text)} bytes)")
                hit = True
        if hit:
            continue
        if live:
            verified.append(f"{method} {path}")
        elif method == "GET":
            unreached.append(f"{method} {path}")
        else:
            mutating.append(f"{method} {path}")
    if opened:
        out.append(_finding("authz.open", "An ops route answered without the admin token", "critical", "FAIL",
                            "; ".join(opened[:8]) + (f" (+{len(opened) - 8} more)" if len(opened) > 8 else ""),
                            "Every /api/dashboard route must call opsTokenOk() before anything else."))
    if verified:
        out.append(_finding("authz.verified", "Ops routes proven live and still refusing every other credential",
                            "info", "pass",
                            f"{len(verified)} route(s) answered 2xx for the admin token and refused no-token, a "
                            f"junk token and the read-only monitoring token: "
                            + ", ".join(p.split()[-1] for p in verified[:6])
                            + (f" +{len(verified) - 6} more" if len(verified) > 6 else "")))
    if mutating:
        out.append(_finding("authz.mutating", "Mutating ops routes refuse an unauthenticated call", "info", "pass",
                            f"{len(mutating)} POST/PUT/DELETE route(s) refused; they are NOT probed with the "
                            f"admin token (that could change something), so this is weaker evidence than the "
                            f"GET sweep: it shows refusal, not that the route is live"))
    if unreached:
        out.append(_finding("authz.unreached", "Ops routes the sweep could not exercise", "info", "warn",
                            f"{len(unreached)} GET route(s) answered non-2xx even WITH the admin token, so a "
                            f"refusal proves nothing about them (usually a :param the probe cannot guess): "
                            + ", ".join(p.split()[-1] for p in unreached[:5])
                            + (f" +{len(unreached) - 5} more" if len(unreached) > 5 else ""),
                            "Not necessarily a bug - but these are untested, not passing."))
    if blocked:
        out.append(_finding("authz.hostguard", "Probes stopped by the host guard", "info", "warn",
                            f"{blocked} probe(s) were answered by the host guard before the route ran"))
    if limited:
        out.append(_finding("authz.ratelimited", "Probes rate-limited", "info", "warn",
                            f"{limited} probe(s) got 429: inconclusive, re-run later"))
    return out


def _csp_weak(csp):
    """Directive-value analysis, not substring matching.

    https://*.example.com in img-src is a wildcard SUBDOMAIN, not the bare * that makes a policy meaningless.
    The first version searched the whole header for '*', so a legitimate CDN wildcard was reported as a weak
    policy (severity medium). Keyword sources are compared as tokens for the same reason."""
    weak = []
    for directive in csp.split(";"):
        parts = directive.split()
        if not parts:
            continue
        name, srcs = parts[0].lower(), {p.lower().strip("'\"") for p in parts[1:]}
        for kw in ("unsafe-inline", "unsafe-eval"):
            if kw in srcs:
                weak.append(kw)
        if "*" in srcs and name in ("default-src", "script-src", "script-src-elem", "object-src", "worker-src"):
            weak.append(f"{name} *")
    return sorted(set(weak))


def check_headers(base, host, ua):
    """The browser-isolation claim, read off a real response."""
    out = []
    code, h, _, _ = _req("GET", base + "/", base_headers(ua, host))
    if not code:
        return [_finding("headers.fetch", "Could not fetch a page to read headers", "info", "skipped", "no answer")]
    csp = _hdr(h, "content-security-policy")
    if not csp:
        out.append(_finding("headers.csp", "No Content-Security-Policy", "high", "FAIL", f"GET / -> {code}, no CSP",
                            "Restore the Helmet CSP middleware."))
    else:
        weak = _csp_weak(csp)
        frame = "frame-ancestors" in csp
        out.append(_finding("headers.csp", "Content-Security-Policy", "medium" if weak else "info",
                            "warn" if weak else "pass",
                            (f"contains {', '.join(weak)}; " if weak else "")
                            + ("frame-ancestors set" if frame else "NO frame-ancestors") + f"; {len(csp)} chars",
                            "Drop unsafe-inline/unsafe-eval where the page can use a nonce." if weak else ""))
    hsts = _hdr(h, "strict-transport-security")
    age = int(re.search(r"max-age=(\d+)", hsts).group(1)) if hsts and re.search(r"max-age=(\d+)", hsts) else 0
    out.append(_finding("headers.hsts", "HSTS", "medium" if age < 15552000 else "info",
                        "pass" if age >= 15552000 else ("warn" if age else "FAIL"),
                        hsts or "absent on the loopback response (the edge may add it: check section=edge)",
                        "Set max-age to at least 180 days with includeSubDomains." if age < 15552000 else ""))
    for name, want, sev in (("x-content-type-options", "nosniff", "low"),
                            ("referrer-policy", None, "low"),
                            ("permissions-policy", None, "low"),
                            ("cross-origin-opener-policy", None, "low")):
        got = _hdr(h, name)
        ok = bool(got) and (want is None or want in got.lower())
        out.append(_finding(f"headers.{name}", name, sev, "pass" if ok else "warn", got or "absent",
                            "" if ok else f"Set {name}."))
    return out


def check_host(base, ua):
    """The host allow-list claim: ask for the site as somebody else."""
    code, h, text, _ = _req("GET", base + "/", {"User-Agent": ua, "Host": "evil.example.com"})
    if code == 0:
        return [_finding("host.spoof", "Host header validation", "info", "skipped", "no answer")]
    ok = code in (400, 403, 404, 421) or 300 <= code < 400
    return [_finding("host.spoof", "Host header validation", "medium" if not ok else "info",
                     "pass" if ok else "FAIL",
                     f"GET / with Host: evil.example.com -> {code}"
                     + ("" if ok else f", {len(text)} bytes of the real page"),
                     "" if ok else "Set PUBLIC_URL or ALLOWED_HOSTS and enforce it in production.")]


def check_cors(base, ua, host):
    """An API route must not hand its answers to another origin."""
    out = []
    for path in ("/api/server-status", "/api/dashboard/overview"):
        code, h, _, _ = _req("GET", base + path,
                             dict(base_headers(ua, host), Origin="https://evil.example.com"))
        acao, acac = _hdr(h, "access-control-allow-origin"), _hdr(h, "access-control-allow-credentials")
        reflected, wildcard = acao == "https://evil.example.com", acao == "*"
        sensitive = path.startswith("/api/dashboard")
        # A bare * on a PUBLIC, credential-less route is how public data is meant to be shared; it is a
        # finding only when the route is sensitive or the answer carries credentials. Reflection is worse
        # than *, and reflection WITH credentials is the one that is actually exploitable.
        bad = (reflected or wildcard) and (bool(acac) or sensitive)
        out.append(_finding(f"cors{path.replace('/', '.')}", f"CORS on {path}",
                            "high" if (reflected and acac) else ("medium" if bad else "info"),
                            "FAIL" if bad else "pass",
                            f"{code}; Allow-Origin: {acao or 'absent'}, Allow-Credentials: {acac or 'absent'}",
                            "Do not reflect Origin on credentialed routes." if bad else ""))
    return out


def check_cookies(base, ua, host):
    code, h, _, _ = _req("GET", base + "/", base_headers(ua, host))
    setc = _hdr(h, "set-cookie")
    if not setc:
        return [_finding("cookies.flags", "Cookie flags", "info", "pass", "the page sets no cookie")]
    # Attribute names, not substrings of the whole line: a cookie NAMED secure_pref (or a value containing
    # "secure") must not satisfy the Secure flag, or a missing flag is reported as present. Every Set-Cookie
    # line is judged on its own: one hardened cookie must not launder an unhardened one next to it.
    lines = [ln for ln in setc.split("\n") if ln.strip()]
    bad = []
    for ln in lines:
        attrs = {p.split("=", 1)[0].strip().lower() for p in ln.split(";")[1:] if p.strip()}
        missing = [f for f in ("httponly", "secure", "samesite") if f not in attrs]
        if missing:
            name = ln.split("=", 1)[0].strip() or "(unnamed)"
            bad.append(f"{name} missing {', '.join(missing)}")
    return [_finding("cookies.flags", "Cookie flags", "medium" if bad else "info",
                     "FAIL" if bad else "pass",
                     (f"{len(lines)} cookie(s) set; " + "; ".join(bad[:5])
                      + (f" (+{len(bad) - 5} more)" if len(bad) > 5 else "")) if bad
                     else f"{len(lines)} cookie(s) set with HttpOnly, Secure and SameSite",
                     "Add the missing flags." if bad else "")]


def check_traversal(base, ua, host):
    """The static mount, asked for files above it."""
    probes = ["/../../../../etc/passwd", "/..%2f..%2f..%2fetc/passwd", "/static/../../../etc/passwd",
              "/%2e%2e/%2e%2e/etc/passwd", "/.env", "/server.js", "/data/store.json"]
    hits, answered = [], 0
    for p in probes:
        code, _, text, _ = _req("GET", base + p, base_headers(ua, host))
        if not code:
            continue
        answered += 1
        if 200 <= code < 300 and ("root:x:" in text or "OPS_ADMIN_TOKEN" in text or "require(" in text
                                  or '"pro"' in text):
            hits.append(f"{p} -> {code} ({len(text)} bytes, looks like the real file)")
    if hits:
        return [_finding("traversal.static", "Path traversal and source exposure", "critical", "FAIL",
                         "; ".join(hits), "Serve static from a fixed root and never resolve '..' into it.")]
    if answered < len(probes):
        return [_finding("traversal.static", "Path traversal and source exposure", "info", "skipped",
                         f"{answered} of {len(probes)} probes answered; the other {len(probes) - answered} got "
                         f"NO answer, which is not a refusal and is not counted as one")]
    return [_finding("traversal.static", "Path traversal and source exposure", "info", "pass",
                     f"{len(probes)} traversal and source probes all refused")]


def check_errors(base, ua, host):
    """A malformed body must not come back with a stack trace or an internal path."""
    code, _, text, _ = _req("POST", base + "/api/contact",
                            dict(base_headers(ua, host), **{"Content-Type": "application/json"}), "{not json")
    if not code:
        return [_finding("errors.stack", "Error bodies", "info", "skipped",
                         "POST /api/contact got no answer: there is no body to read, and no answer is not a pass")]
    leak = [m for m in ("at Object.", "node_modules", "/home/", "Error:", ".mjs:", "server.js:") if m in text]
    if not reached(code, text):
        return [_finding("errors.stack", "Error bodies", "info", "skipped",
                         "the host guard answered first; the route was not reached")]
    return [_finding("errors.stack", "Error bodies", "medium" if leak else "info", "FAIL" if leak else "pass",
                     f"POST /api/contact with a broken body -> {code}"
                     + (f", body leaks {', '.join(leak)}" if leak else f", {len(text)} bytes, no trace"),
                     "Return a plain message; log the trace server-side." if leak else "")]


def check_store(base, env, ua):
    """The 'learner data at rest' claim, read back from the site itself."""
    d = gnoc_site.read(force=True)
    db = d.get("database") or {}
    if not d.get("ok"):
        return [_finding("store.encrypted", "Store encryption", "info", "skipped", d.get("why", "unreadable"))]
    enc, ro = db.get("encrypted"), db.get("read_only")
    if enc is True:
        out = [_finding("store.encrypted", "Persistent store encryption", "info", "pass",
                        f"the store reports encrypted=True, {db.get('size_mb')} MB on disk")]
    elif enc is False:
        out = [_finding("store.encrypted", "Persistent store encryption", "high", "FAIL",
                        f"the store reports encrypted=False, {db.get('size_mb')} MB on disk",
                        "Set STORE_ENCRYPTION_KEY_FILE.")]
    else:
        # An absent flag is a site that does not report it, not a site that stores plaintext.
        out = [_finding("store.encrypted", "Persistent store encryption", "info", "skipped",
                        f"the store did not report an encryption flag (encrypted={enc!r}): "
                        f"that is unmeasured, not failed")]
    if ro:
        out.append(_finding("store.readonly", "Store is read-only", "high", "FAIL",
                            f"writes are disabled: {db.get('last_error') or 'no reason recorded'}",
                            "Fix the storage volume, then restart."))
    return out


def check_surface(server_js=None):
    """The privileged surface this drill does NOT prove. A coverage statement, never a vulnerability claim.

    /api/admin is session-gated, so probing it with the ops token would prove nothing - but silence about it
    would let a clean /api/dashboard sweep read as whole-site access control."""
    other = other_gated(server_js)
    if not other:
        return [_finding("surface.swept", "Privileged API prefixes", "info", "pass",
                         "no /api/admin, /api/ops, /api/internal or /api/security-events route is declared "
                         "outside the /api/dashboard sweep")]
    return [_finding("surface.untested", "Privileged routes outside this drill", "info", "warn",
                     "server.js also registers "
                     + ", ".join(f"{n} under {p}" for p, n in sorted(other.items()))
                     + " route(s). The sweep proves /api/dashboard only: these are UNTESTED, not passing.",
                     "Test them from an authenticated admin session, or extend the sweep deliberately.")]


def declared_ceiling(name, server_js=None):
    """The per-minute ceiling the site declares for a named route, read from its own apiRateLimit() call."""
    path = server_js or os.path.join(gnoc_site.SITE_DIR, "server.js")
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    m = re.search(r'apiRateLimit\(\s*"%s"\s*,\s*(?:positiveIntEnv\([^,]+,\s*)?(\d+)' % re.escape(name), src)
    return int(m.group(1)) if m else None


def check_limits(base, ua, host, confirm=False, n=BURST):
    """The abuse-limit claim. LOUD: it is a burst, and it is the one check that looks like an attack.

    A burst SMALLER than the declared ceiling proves nothing, and the first version of this reported "never
    rate-limited" as a FAILURE after 40 requests against a route that allows 120 a minute. So: read the
    ceiling the site declares, and if the burst cannot exceed it, say the result is inconclusive and why."""
    ceiling = declared_ceiling("server-status")
    if not confirm:
        return [_finding("limits.burst", "Rate limits", "info", "skipped",
                         "proving a ceiling needs a burst past it"
                         + (f" (/api/server-status declares {ceiling}/min)" if ceiling else "")
                         + "; it runs only when the user asks for the burst in their own words (then confirm=true). "
                           "Loopback is ban-exempt, but the burst WILL show in their console")]
    codes = []
    for _ in range(n):
        code, _, _, _ = _req("GET", base + "/api/server-status", base_headers(ua, host), timeout=4)
        codes.append(code)
        if code == 429:
            break
    if 429 in codes:
        return [_finding("limits.burst", "Rate limits", "info", "pass",
                         f"/api/server-status told us to stop (429) after {codes.index(429)} requests"
                         + (f"; it declares {ceiling}/min" if ceiling else ""))]
    if ceiling and n <= ceiling:
        return [_finding("limits.burst", "Rate limits", "info", "skipped",
                         f"{len(codes)} requests all answered, but /api/server-status declares {ceiling}/min: "
                         f"a burst of {n} CANNOT disprove that ceiling. Re-run with burst above {ceiling} to "
                         f"test it for real.")]
    return [_finding("limits.burst", "Rate limits", "medium", "FAIL",
                     f"{len(codes)} requests to /api/server-status were all answered"
                     + (f", past its declared {ceiling}/min" if ceiling else "") + ": no ceiling took effect",
                     "Give the public polling routes a per-IP ceiling that actually fires.")]


def check_edge(pub, ua, origin_hsts=None):
    """The public path - what a browser actually gets. The origin's headers are not the browser's headers:
    anything the edge rewrites happens HERE, and only here."""
    if not pub:
        return [_finding("edge.hsts", "Public edge", "info", "skipped", "no PUBLIC_URL in the site's .env")]
    code, h, _, ms = _req("GET", pub + "/", {"User-Agent": ua}, timeout=12)
    if not code:  # one retry: a cold DNS/TLS failure is not a statement about the edge
        c2, h2, _, ms2 = _req("GET", pub + "/", {"User-Agent": ua}, timeout=8)
        code, h, ms = c2, h2, ms + ms2
    if not code:
        # An unobserved edge is UNMEASURED. Reading hsts/csp off an empty header set invented a stripped
        # CSP and a missing HSTS pin from a response that never arrived (seen live 2026-11-24).
        return [_finding("edge.reachable", "Public edge", "info", "skipped",
                         f"GET {pub}/ got no answer in {ms:.0f} ms: the edge was not observed, so its HSTS, "
                         f"CSP and server fingerprint are unmeasured. That may be this host's egress, not the "
                         f"edge.")]
    out = [_finding("edge.reachable", "Public edge reachable", "high" if code != 200 else "info",
                    "pass" if code == 200 else "FAIL", f"GET {pub}/ -> {code} in {ms:.0f} ms")]
    hsts = _hdr(h, "strict-transport-security")
    age = int(re.search(r"max-age=(\d+)", hsts).group(1)) if hsts and re.search(r"max-age=(\d+)", hsts) else 0
    o_age = int(re.search(r"max-age=(\d+)", origin_hsts).group(1)) \
        if origin_hsts and re.search(r"max-age=(\d+)", origin_hsts) else 0
    if age >= 15552000:
        out.append(_finding("edge.hsts", "HSTS as the browser sees it", "info", "pass", hsts))
    else:
        drift = f" The ORIGIN sends max-age={o_age}, so this is the edge overriding it." if o_age >= 15552000 else ""
        out.append(_finding("edge.hsts", "HSTS as the browser sees it", "medium", "FAIL",
                            f"the edge sends {hsts or 'no HSTS header'} on {pub}/ — max-age=0 tells browsers to "
                            f"FORGET the HSTS pin, so the posture check that passes at the origin buys nothing "
                            f"in production.{drift}",
                            "Turn HSTS on at Cloudflare (SSL/TLS -> Edge Certificates -> HSTS); with it off, "
                            "Cloudflare emits max-age=0 and overwrites what the origin set."))
    csp = _hdr(h, "content-security-policy")
    out.append(_finding("edge.csp", "CSP survives the edge", "high" if not csp else "info",
                        "pass" if csp else "FAIL", (csp or "absent at the edge")[:120],
                        "" if csp else "The edge is stripping the CSP the origin sets."))
    srv = _hdr(h, "server")
    out.append(_finding("edge.fingerprint", "Origin fingerprint at the edge", "info", "pass",
                        f"Server: {srv or 'absent'}"))
    return out


# ------------------------------------------------------------------ the campus live feed

def _sio_read(base, ua, host, event, payload=None, timeout=5):
    """Connect to socket.io as an ANONYMOUS client and send one READ event. Returns (connected, frames, note).

    Engine.IO v4 over HTTP polling, by hand: handshake, namespace connect, one acked emit, one poll. It never
    sends a write event - not feed:post, not feed:like, nothing on the write allow-list - so this cannot put
    anything on their live feed. The frames come back as raw text and are only ever searched, never echoed."""
    q = f"/socket.io/?EIO=4&transport=polling&t={secrets.token_hex(4)}"
    code, _, body, _ = _req("GET", base + q, base_headers(ua, host), timeout=timeout)
    if code != 200 or not body.startswith("0"):
        return False, [], f"handshake answered {code}"
    try:
        sid = json.loads(body[1:body.index("}") + 1])["sid"]
    except (ValueError, KeyError):
        return False, [], "handshake carried no sid"
    sq = f"/socket.io/?EIO=4&transport=polling&sid={sid}"
    _req("POST", base + sq, dict(base_headers(ua, host), **{"Content-Type": "text/plain;charset=UTF-8"}), "40",
         timeout=timeout)
    code, _, body, _ = _req("GET", base + sq, base_headers(ua, host), timeout=timeout)
    if "40" not in body:
        return False, [body], "namespace connect refused"
    frames = [body]
    emit = "420" + json.dumps([event, payload or {}])
    _req("POST", base + sq, dict(base_headers(ua, host), **{"Content-Type": "text/plain;charset=UTF-8"}), emit,
         timeout=timeout)
    code, _, body, _ = _req("GET", base + sq, base_headers(ua, host), timeout=timeout + 3)
    frames.append(body)
    return True, frames, ""


FEED_SOURCE_FACTS = (("FEED_MAX", r"const FEED_MAX\s*=\s*(\d+)", "the in-memory ring is bounded"),
                     ("FEED_SLOWMODE_MS", r"FEED_SLOWMODE_MS\"?,\s*(\d+)\s*\*\s*SECOND", "per-user slow mode"))


def _source_fact(pattern, server_js=None):
    try:
        src = open(server_js or os.path.join(gnoc_site.SITE_DIR, "server.js"), encoding="utf-8",
                   errors="replace").read()
    except OSError:
        return None
    m = re.search(pattern, src)
    return m.group(1) if m else None


# Fields a stranger must never be handed. "pub" and "signerPub" are deliberately NOT here: they are public
# identity keys, they are how a public feed names an author, and they appear in profile-picture URLs. Flagging
# them printed a high-severity finding for the feed working as designed (2026-10-25).
LEAKY_KEYS = ("email", "mail", "ip", "ipaddress", "clientip", "addr", "address", "token", "secret",
              "password", "sessionid", "session", "privatekey", "apikey", "cookie")
SAFE_KEYS = ("pubroom", "published", "publishedat", "public", "emailenabled")


def _walk_keys(obj, found, depth=0):
    """Every key name in a payload, with the kind of value it holds. Structure is the signal: an address in a
    post's TEXT is something a person typed in public, an address in an author.email FIELD is a leak."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower().replace("_", "")
            if kl in LEAKY_KEYS and kl not in SAFE_KEYS and isinstance(v, (str, int)) and str(v).strip():
                found.append((str(k), str(v)))
            _walk_keys(v, found, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:200]:
            _walk_keys(v, found, depth + 1)


def _json_payloads(blob):
    """The JSON bodies inside socket.io frames (43[...] / 42[...]), best effort."""
    out = []
    for m in re.finditer(r"4[23]\d*(\[.*?\])(?=\x1e|4[23]|$)", blob, re.S):
        try:
            out.append(json.loads(m.group(1)))
        except ValueError:
            continue
    if not out:
        i = blob.find("[")
        if i >= 0:
            try:
                out.append(json.loads(blob[i:]))
            except ValueError:
                pass
    return out


def _feed_payload_findings(blob, host):
    """What came back to an unidentified socket, judged on structure.

    The first version regexed the raw frames for anything address-shaped and reported a leak. What it found
    was the user's own support address inside the TEXT of a post the user had published asking people to mail them:
    public content the user wrote, not a leak (2026-10-25). Free text is not the signal - field names are."""
    out, found = [], []
    for payload in _json_payloads(blob):
        _walk_keys(payload, found)
    # His own address is not a third party's. The site is your-site.example and his support mailbox is at
    # greynoc.com - the same name with the hyphen dropped - so compare on the letters, not the spelling.
    def _flat(d):
        return re.sub(r"[^a-z0-9.]", "", (d or "").lower())

    own = _flat(host).split(".", 1)[-1] if "." in _flat(host) else _flat(host)

    def _is_own(addr):
        # Boundary match: evilgreynoc.com is NOT greynoc.com, and must not be filtered out as if it were.
        dom = _flat(addr.split("@", 1)[-1])
        return bool(own) and (dom == own or dom.endswith("." + own))

    addrs = [a for a in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", blob) if own and not _is_own(a)]
    if found:
        shapes = sorted({k for k, _ in found})
        out.append(_finding("feed.socket.fields", "Feed rows carry identifying FIELDS", "high", "FAIL",
                            f"an unidentified socket got rows with {', '.join(shapes[:6])} on them",
                            "Project the feed down to what a stranger may see before it leaves the server."))
    else:
        out.append(_finding("feed.socket.fields", "Feed rows carry no identifying fields", "info", "pass",
                            f"an unidentified socket read the feed; no email / ip / token / session field on "
                            f"any row ({len(blob)} bytes of frames)"))
    if addrs:
        out.append(_finding("feed.socket.text", "Third-party addresses in post text", "low", "warn",
                            f"{len(addrs)} address(es) outside {own} appear in post BODIES (typed by whoever "
                            f"wrote the post, not a field the server added)",
                            "Nothing to fix server-side; moderate the post if it is somebody else's address."))
    size = len(blob)
    if size > 50_000:
        out.append(_finding("feed.socket.size", "feed:list ignores its limit", "low", "warn",
                            f"feed:list with limit=5 returned {size // 1024} KB to an anonymous socket "
                            f"(the whole ring, by the look of it)",
                            "Honour the limit argument: every anonymous connect pays this in bandwidth."))
    return out


def check_feed(base, ua, host, env):
    """QA/QC of the campus LIVE FEED: its public surface, its control surface, and what an anonymous socket
    can get out of it. What cannot be reached from here is listed as not covered, never as passing."""
    out = []
    # 1. the public snapshot: counts only, no-store, and a declared ceiling
    code, h, text, _ = _req("GET", base + "/api/campus/snapshot", base_headers(ua, host))
    if not reached(code, text):
        return [_finding("feed.snapshot", "Campus snapshot", "info", "skipped", "the host guard answered first")]
    ceiling = declared_ceiling("campus-snapshot")
    if code != 200:
        out.append(_finding("feed.snapshot", "Campus snapshot reachable", "high", "FAIL",
                            f"GET /api/campus/snapshot -> {code}"))
    else:
        try:
            j = json.loads(text)
        except ValueError:
            j = {}
        camp = (j.get("campus") or {}) if isinstance(j, dict) else {}
        leaky = [k for k in ("posts", "feedItems", "messages", "handles", "people", "roster")
                 if isinstance(camp.get(k), list) and camp.get(k)]
        bodies = re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", text)
        out.append(_finding("feed.snapshot", "Campus snapshot exposes counts, not content",
                            "high" if (leaky or bodies) else "info", "FAIL" if (leaky or bodies) else "pass",
                            (f"it carries {', '.join(leaky)}" if leaky else "")
                            + (f" and {len(bodies)} address-shaped string(s)" if bodies else "")
                            or f"activePeople={camp.get('activePeople')}, feedPosts={camp.get('feedPosts')}, "
                               f"{len(camp.get('publicRooms') or [])} room summaries, {len(text)} bytes",
                            "Publish counts, never post bodies or handles." if (leaky or bodies) else ""))
        cc = _hdr(h, "cache-control") or ""
        out.append(_finding("feed.snapshot.cache", "Snapshot is not cached", "low" if "no-store" not in cc
                            else "info", "pass" if "no-store" in cc else "warn", f"Cache-Control: {cc or 'absent'}",
                            "Set no-store: a cached snapshot shows stale presence." if "no-store" not in cc else ""))
        out.append(_finding("feed.snapshot.limit", "Snapshot has a declared ceiling",
                            "medium" if not ceiling else "info", "pass" if ceiling else "warn",
                            f"apiRateLimit declares {ceiling}/min" if ceiling
                            else "no apiRateLimit() found for campus-snapshot in server.js",
                            "" if ceiling else "Give the public snapshot a per-IP ceiling."))
    # 2. the feed's own control surface must be ops-gated
    admin = env.get("OPS_ADMIN_TOKEN") or ""
    for method, path in (("GET", "/api/dashboard/campus/reports"), ("POST", "/api/dashboard/campus/moderate"),
                         ("POST", "/api/dashboard/bb")):
        body = "{" if method != "GET" else None
        code, _, text, _ = _req(method, base + path, base_headers(ua, host), body)
        if not reached(code, text):
            continue
        open_ = 200 <= code < 300
        live = None
        if method == "GET" and admin:
            c2, _, t2, _ = _req("GET", base + path, dict(base_headers(ua, host), **{"x-ops-token": admin}))
            live = reached(c2, t2) and 200 <= c2 < 300
        out.append(_finding(f"feed.gate{path.replace('/', '.')}", f"{method} {path} is ops-gated",
                            "critical" if open_ else "info", "FAIL" if open_ else "pass",
                            f"unauthenticated -> {code}"
                            + ("" if live is None else (", and 2xx with the admin token (route proven live)"
                                                        if live else ", but the admin probe did not reach it "
                                                                     "either: refusal proves little")),
                            "Gate it with opsTokenOk()." if open_ else ""))
    # 3. what an anonymous socket can read
    connected, frames, note = _sio_read(base, ua, host, "feed:list", {"limit": 5})
    blob = " ".join(frames)
    if not connected:
        out.append(_finding("feed.socket", "Anonymous socket.io read", "info", "skipped",
                            f"could not complete an anonymous handshake ({note})"))
    else:
        out += _feed_payload_findings(blob, host)
    # 4. invariants read from the source (stated as read, not as exercised)
    fmax = _source_fact(r"const FEED_MAX\s*=\s*(\d+)")
    slow = _source_fact(r"FEED_SLOWMODE_MS\"?\s*,\s*(\d+)\s*\*\s*SECOND")
    out.append(_finding("feed.bounds", "Feed ring and slow mode (read from server.js, not exercised)",
                        "medium" if not fmax else "info", "pass" if fmax else "warn",
                        f"FEED_MAX={fmax or '?'} posts in the ring"
                        + (f", slow mode {slow}s per user" if slow else ", no per-user slow mode found"),
                        "" if fmax else "Bound the in-memory feed ring."))
    out.append(_finding("feed.notcovered", "What this drill did NOT test", "info", "warn",
                        "the write path (feed:post / like / delete and the other write events), post-body "
                        "sanitisation and XSS, moderation correctness, the BB bot's posting cadence, and "
                        "per-user slow mode in practice - all of them need an IDENTIFIED socket client, and "
                        "writing to their live campus feed is exactly what this tool refuses to do",
                        "Exercise those from a logged-in browser session or a dedicated test identity."))
    return out


# ------------------------------------------------------------------ the run

def run(checks=None, confirm=False, burst=BURST, area=None):
    """Run the drill and return (announcement, findings). area names a subsystem; an unknown one is refused."""
    env = gnoc_site._env()
    port = env.get("PORT") or "6969"
    pub = (env.get("PUBLIC_URL") or "").rstrip("/")
    host = re.sub(r"^https?://", "", pub).split("/")[0]
    base = f"http://127.0.0.1:{port}"
    rid = _run_id()
    ua = f"gnoc-redteam/{rid} (authorized self-test of their own site)"
    if area:
        key = str(area).strip().lower().replace("_", "-").replace(" ", "-")
        if key not in AREAS:
            return (f"There is no drill for {area!r}. The areas that exist are: "
                    + ", ".join(sorted(AREAS)) + ". Running the whole-site drill instead would NOT test it, "
                    "so nothing was run.", [])
        checks = checks or AREAS[key]
    want = [c for c in (checks or DEFAULT) if c in CHECKS] or list(DEFAULT)

    code, _, _, _ = _req("GET", base + "/healthz", base_headers(ua, host), timeout=5)
    if not code:
        return (f"{host or base} is not answering on loopback: nothing to test (the site process is down, or "
                f"PORT moved).", [])
    findings = []
    if "authz" in want:
        findings += check_authz(base, env, ua, host)
    origin_hsts = None
    if "headers" in want:
        hf = check_headers(base, host, ua)
        origin_hsts = next((f["evidence"] for f in hf if f["id"] == "headers.hsts"), None)
        findings += hf
    if "host" in want:
        findings += check_host(base, ua)
    if "cors" in want:
        findings += check_cors(base, ua, host)
    if "cookies" in want:
        findings += check_cookies(base, ua, host)
    if "traversal" in want:
        findings += check_traversal(base, ua, host)
    if "errors" in want:
        findings += check_errors(base, ua, host)
    if "store" in want:
        findings += check_store(base, env, ua)
    if "surface" in want:
        findings += check_surface()
    if "feed" in want:
        findings += check_feed(base, ua, host, env)
    if "limits" in want:
        findings += check_limits(base, ua, host, confirm=confirm, n=burst)
    if "edge" in want:
        if origin_hsts is None:
            _, oh, _, _ = _req("GET", base + "/", base_headers(ua, host))
            origin_hsts = _hdr(oh, "strict-transport-security")
        findings += check_edge(pub, ua, origin_hsts)
    ann = (f"DRILL {rid} ran against {host or base} just now. These were real requests to the live site: they "
           f"are in its security feed and on the console, tagged User-Agent {ua!r}. Loopback is ban-exempt, so "
           f"nothing was blocked. Nothing was changed: reads only, and the mutating probes were sent "
           f"unauthenticated with an unparseable body.")
    return ann, findings


def summary(checks=None, confirm=False, burst=BURST, area=None):
    """The drill as text for the model to answer from: what was tested, what failed, what to fix."""
    ann, findings = run(checks, confirm, burst, area)
    if not findings:
        return ann
    order = {s: i for i, s in enumerate(SEVERITY)}
    bad = [f for f in findings if f["status"] == "FAIL"]
    warn = [f for f in findings if f["status"] == "warn"]
    ok = [f for f in findings if f["status"] == "pass"]
    skip = [f for f in findings if f["status"] == "skipped"]
    # The verdict without per-run noise (timings, route counts, run id). "continue" re-ran this drill three times
    # in a row with nothing changed between them, and the lead re-announced each as news (2026-11-27).
    sig = sorted(f"{f['id']}:{f['status']}:{f['severity']}" for f in findings)
    key = f"{area or ''}|{','.join(sorted(checks or DEFAULT))}"
    prev = gnoc_site.last_drill()
    rid = re.search(r"DRILL (rt-[0-9a-f]+)", ann)
    gnoc_site.save_drill({"rid": rid.group(1) if rid else "", "ts": time.time(), "key": key, "sig": sig,
                          "failed": [{"title": f["title"], "severity": f["severity"], "fix": f["fix"]} for f in bad]})
    repeat = ""
    if prev and prev.get("key") == key and prev.get("sig") == sig and time.time() - float(prev["ts"]) < REPEAT_S:
        repeat = (f"SAME RESULT as drill {prev.get('rid')} {gnoc_site._mins(prev['ts'])}: every check landed where it "
                  "did then. Nothing on the site changed between the two runs, so this run is not news - say so, "
                  "and do not run it again until something changes"
                  + (" (the open FAILED items below need a change on their side first)." if bad else "."))
    L = [ann, ""] + ([repeat, ""] if repeat else []) + [
         f"TESTED {len(findings)} checks: {len(bad)} failed, {len(warn)} warning, {len(ok)} passed, "
         f"{len(skip)} skipped.", ""]
    if bad:
        # The answer the lead is asked for is "criticals, highs, mediums": count them here, once, so the
        # model reads the numbers instead of recounting a list and getting it wrong.
        sc = {s: sum(1 for f in bad if f["severity"] == s) for s in SEVERITY}
        L.append("FAILED BY SEVERITY: " + ", ".join(f"{sc[s]} {s}" for s in SEVERITY)
                 + " (failed checks only; warnings and skips are not vulnerabilities).")
    for label, rows in (("FAILED", sorted(bad, key=lambda f: order.get(f["severity"], 9))),
                        ("WARNINGS", sorted(warn, key=lambda f: order.get(f["severity"], 9)))):
        if rows:
            L.append(label + ":")
            for f in rows:
                L.append(f"  [{f['severity']}] {f['title']} — {f['evidence']}"
                         + (f"  FIX: {f['fix']}" if f["fix"] else ""))
            L.append("")
    if ok:
        L.append("PASSED: " + "; ".join(f"{f['title']} ({f['evidence'][:70]})" for f in ok))
    if skip:
        L.append("NOT RUN: " + "; ".join(f"{f['title']} — {f['evidence']}" for f in skip))
    L.append("")
    L.append("This is a configuration and access-control drill against their own service. It is not a full "
             "application pentest: it does not test business logic, authorization between USERS, the realtime "
             "layer or anything that needs a logged-in session.")
    return "\n".join(L)
