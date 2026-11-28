#!/usr/bin/env python3
"""auto-hunt.py - the no-model hunt engine behind `gnoc orch auto`. One host per run.

  auto-hunt.py <program> --next [N] [--workers K]   sweep the next N unswept hosts, K in parallel (max 6)
  auto-hunt.py <program> --host H    sweep one named host
  auto-hunt.py <program> --plan [--all]  print the host order (first 40, or all) and what is already swept

The sweep is a FIXED, read-only list of GET requests for the unauthenticated-exposure classes that
produced most of our shipped findings (Spring actuator incl. the double-encoded edge bypass, OpenAPI /
Swagger, GraphQL, .git, .env, server-status, debug endpoints), plus a JS SEED stage on HTML hosts: up to 6 in-scope
bundles are fetched, API routes / secrets / URL-taking proxy params are mined (routes saved to auto-exposure/routes/),
and up to 25 mined routes are fired GET-only after an API nonsense control; a JSON 200 with user-data keys that differs
from the control is a candidate HIT (AUTO_JS_SEED=0 turns the stage off). Every host gets two controls first
(a nonsense path and the root) so a soft-200 SPA cannot fake a hit (T-60). A row is a HIT only when the
response is 2xx, differs in length from the nonsense control, and its body carries the class's own
signature (e.g. "_links" + "actuator", "swagger"/"openapi", "[core]", KEY=value lines, "__schema").

Safety, enforced in code: every URL host is checked against targets/<program>/SCOPE.txt before it is
fired (refused rows are logged, never sent); the program's PROGRAM.md is grepped for an automation ban
and the run refuses if it finds one (T-156); X-HackerOne: <handle> is sent on every request; requests
are spaced (default 3s) and never redirected; GET only; at most ~24 requests per host; raw bytes saved.

Output: targets/<program>/hunts/auto-exposure/{commands.txt, raw/, STATUS.md (one "## Round <host>"
table per host)}, one outcome line via scripts/hunt-state.py, and swept hosts in
.claude/state/orch/auto-<program>.json. HITS also go to the orch INBOX as AUTO-HIT. It never drafts
or files: a hit is a LEAD for a human or Claude to verify and escalate.
"""
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
SPACING = float(os.environ.get("AUTO_SPACING", "3"))
# one shared scope + policy gate for every unattended caller (NOSCOPE, third-party, internal IP, T-156 ban)
sys.path.insert(0, os.path.join(WS, "scripts"))
from bbtools import lib_scope, lib_policy  # noqa: E402
# third-party platforms that appear in SCOPE.txt only so source code can be fetched; now lives in lib_scope
THIRD_PARTY = lib_scope.THIRD_PARTY
ROLE_ORDER = ["api-gateway", "internal-corporate", "nonprod", "owner-partner", "admin", "guest-booking/other"]

# (tag, path, signature regex that must appear in a 2xx body for a HIT)
PROBES = [
    ("act", "/actuator", r'"_links"\s*:\s*\{[^}]*"(self|health|env)"'),
    ("act-health", "/actuator/health", r'"status"\s*:\s*"(UP|DOWN)"'),
    ("act-env", "/actuator/env", r'"propertySources"|"activeProfiles"'),
    ("act-dbl", "/%2561ctuator", r'"_links"\s*:\s*\{'),
    ("act-dbl-env", "/%2561ctuator/%2565nv", r'"propertySources"|"activeProfiles"'),
    ("act-dbl-td", "/%2561ctuator/%2574hreaddump", r'"threadName"|"threads"\s*:'),
    ("boot1-env", "/env", r'"profiles"\s*:|"systemProperties"|"applicationConfig'),
    ("boot1-mappings", "/mappings", r'"dispatcherServlets"|"\{\[/'),
    ("swagger-v2", "/v2/api-docs", r'"swagger"\s*:\s*"2'),
    ("openapi-v3", "/v3/api-docs", r'"openapi"\s*:\s*"3'),
    ("openapi-json", "/openapi.json", r'"openapi"\s*:|"swagger"\s*:'),
    ("swagger-ui", "/swagger-ui/index.html", r"swagger-ui"),
    ("graphql", "/graphql?query=%7B__typename%7D", r'"data"\s*:\s*\{\s*"__typename"'),
    ("git-config", "/.git/config", r"\[core\]"),
    ("git-head", "/.git/HEAD", r"^ref: refs/"),
    ("dotenv", "/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=\S"),
    ("server-status", "/server-status", r"Apache Server Status"),
    ("debug-vars", "/debug/vars", r'"memstats"|"cmdline"'),
    ("debug-pprof", "/debug/pprof/", r"Types of profiles available"),
    ("heapdump-head", "/actuator/heapdump", r"^JAVA PROFILE|^\x1f\x8b"),
    ("jolokia", "/jolokia/version", r'"agent"\s*:|"protocol"\s*:'),
    ("phpinfo", "/phpinfo.php", r"PHP Version"),
]


# extra probes added only when the root response fingerprints the stack (header or body regex)
TECH = [
    ("spring", r"(?i)x-application-context|whitelabel error page|spring", [
        ("sp-act-mappings", "/actuator/mappings", r'"dispatcherServlets"|"contexts"'),
        ("sp-act-configprops", "/actuator/configprops", r'"beans"\s*:|"contexts"'),
        ("sp-act-loggers", "/actuator/loggers", r'"levels"\s*:'),
        ("sp-dbl-mappings", "/%2561ctuator/%256dappings", r'"dispatcherServlets"|"contexts"'),
        ("sp-h2", "/h2-console/", r"H2 Console"),
    ]),
    ("php", r"(?i)x-powered-by: php|phpsessid|laravel_session|wonka|wp-content", [
        ("php-info", "/info.php", r"PHP Version"),
        ("lv-ignition", "/_ignition/health-check", r'"can_execute_commands"'),
        ("lv-telescope", "/telescope/requests", r"Telescope"),
        ("wp-users", "/wp-json/wp/v2/users", r'"slug"\s*:\s*"[^"]+"[^]]*"link"'),
        ("wp-debuglog", "/wp-content/debug.log", r"PHP (Notice|Warning|Fatal)"),
    ]),
    ("node", r"(?i)x-powered-by: express|_next/static|__next_data__|connect\.sid", [
        ("next-build-manifest", "/_next/static/development/_buildManifest.js", r"self\.__BUILD_MANIFEST"),
        ("node-env-js", "/env.js", r"(?i)(api[_-]?key|secret|token)\s*[:=]"),
        ("node-config-json", "/config.json", r"(?i)\"(api[_-]?key|secret|token|password)\"\s*:"),
    ]),
    ("observability", r"(?i)grafana|kibana|prometheus|jenkins|x-jenkins", [
        ("grafana-health", "/api/health", r'"database"\s*:\s*"ok"'),
        ("grafana-snapshots", "/api/snapshots", r'"key"\s*:'),
        ("kibana-status", "/api/status", r'"version"\s*:\s*\{'),
        ("prom-targets", "/api/v1/targets", r'"activeTargets"'),
        ("jenkins-api", "/api/json", r'"_class"\s*:\s*"hudson'),
    ]),
]
# weak signals worth a human or Claude look later (never a finding on their own)
LEAD_RES = [
    ("dir-listing", r"<title>Index of /"),
    ("stack-trace", r"(?i)(java\.lang\.\w+Exception|Traceback \(most recent call last\)|at [a-z]+\.[a-z]+\.[A-Za-z]+\(\w+\.java:\d+\)|Fatal error</b>:|Whitelabel Error Page|ORA-\d{5}|SQLSTATE\[)"),
    ("source-map", r"sourceMappingURL=[^\s'\"]+\.map"),
    ("debug-mode", r"(?i)(DEBUG\s*=\s*True|django\.core\.exceptions|Werkzeug Debugger|laravel.*whoops)"),
    ("internal-host", r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"),
]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scope_ok_fn(program):
    return lambda h: lib_scope.program_allows(h, program)[0]


def automation_banned(program):
    # harmony 2.1: network_ok also refuses Immunefi venues (status ALLOWED but no web sweeping)
    return not lib_policy.policy(program)["network_ok"]


def handle():
    return lib_policy.handle()


def hosts(program):
    """Answering hosts from the newest unauth map, priority by role; fall back to exact SCOPE hosts."""
    rdir = os.path.join(WS, "targets", program, "recon")
    maps = sorted((d for d in os.listdir(rdir) if d.startswith("unauth-map")), reverse=True) if os.path.isdir(rdir) else []
    out = []
    for m in maps:
        tsv = os.path.join(rdir, m, "hosts.tsv")
        if not os.path.isfile(tsv):
            continue
        rows = [l.rstrip("\n").split("\t") for l in open(tsv)][1:]
        for r in rows:
            if len(r) < 4 or r[1] == "no-answer" or not r[3].isdigit() or r[3] == "0":
                continue
            out.append((ROLE_ORDER.index(r[1]) if r[1] in ROLE_ORDER else len(ROLE_ORDER), r[0], r[2] or "https"))
        break
    if not out:
        for ln in open(os.path.join(WS, "targets", program, "SCOPE.txt")):
            if ln.startswith("# === OUT"):
                break
            m = re.search(r"\s=?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", ln.split("#")[0])
            if m and "*" not in ln.split("#")[0]:
                out.append((9, m.group(1), "https"))
    seen, uniq = set(), []
    for pri, h, sch in sorted(out):
        if THIRD_PARTY.search(h):
            continue
        if h not in seen:
            seen.add(h)
            uniq.append((h, sch))
    return uniq


def state_path(program):
    return os.path.join(ORCH, f"auto-{program}.json")


import threading
_STATE_LOCK = threading.Lock()


def load_state(program):
    try:
        return json.load(open(state_path(program)))
    except (OSError, ValueError):
        return {"swept": {}}


def fire(url, hdrs):
    from curl_cffi import requests
    r = requests.get(url, headers=hdrs, impersonate="chrome124", timeout=25, allow_redirects=False)
    return r.status_code, r.headers, r.content


# ---------------- JS seed mining (97% of our shipped findings opened from a seed, ~1% from cold enum) ----------------
SCRIPT_RE = re.compile(r"""<(?:script[^>]+src|link[^>]+rel=["']?(?:modulepreload|preload)[^>]+href)=["']([^"']+\.m?js[^"']*)["']""", re.I)
ROUTE_RE = re.compile(r"""["'`](/(?:api|apis|v[1-9]|rest|graphql|gql|internal|admin|user|users|account|accounts|profile|bff|"""
                      r"""gateway|service|services|svc|private|me|customer|customers|booking|bookings|order|orders)"""
                      r"""(?:/[A-Za-z0-9_.~-]*)*/?(?:\?[A-Za-z0-9_=&.-]*)?)["'`]""")
ABS_RE = re.compile(r"""["'`](https?://[A-Za-z0-9.-]+(?:/[A-Za-z0-9_.~-]+)*/(?:api|v[1-9]|rest|graphql|bff)[A-Za-z0-9_./~-]*)["'`]""")
PROXY_PARAM_RE = re.compile(r"[?&](url|uri|target|redirect|dest|destination|proxy|link|feed|image|imageurl|callback)=", re.I)
SECRET_RES = [
    ("aws-key", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("stripe-live", r"\b(sk|rk)_live_[0-9A-Za-z]{20,}"),
    ("slack-token", r"\bxox[abposr]-[0-9A-Za-z-]{10,}"),
    ("github-token", r"\bgh[pousr]_[0-9A-Za-z]{30,}"),
    ("private-key", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("sendgrid-key", r"\bSG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}"),
    ("twilio-key", r"\bSK[0-9a-f]{32}\b"),
]
PII_KEYS = re.compile(r'"(e-?mail|email_?address|phone|phone_?number|mobile|msisdn|address|street|dob|date_?of_?birth|'
                      r'passport|ssn|national_?id|first_?name|last_?name|full_?name|password|passwd|access_?token|'
                      r'refresh_?token|api_?key|secret|card_?number|iban|user_?id|customer_?id|guest)"\s*:\s*"[^"]{2,}"', re.I)
MAX_JS, MAX_ROUTES = 6, 25


def js_seed(program, host, scheme, root_html, hdrs, in_scope, raw, lane, safe, rows, hits, leads):
    from urllib.parse import urljoin
    base = f"{scheme}://{host}/"
    js = []
    for src in SCRIPT_RE.findall(root_html):
        u = urljoin(base, src)
        h = urlparse(u).hostname or ""
        if h and in_scope(h) and not THIRD_PARTY.search(h) and u not in js:
            js.append(u)
    routes, abs_routes, secrets, proxies = set(), set(), [], set()
    for i, u in enumerate(js[:MAX_JS]):
        tag = f"{safe}-js{i}"
        try:
            code, rh, body = fire(u, hdrs)
        except Exception:
            time.sleep(SPACING)
            continue
        rows.append((tag, u, code, len(body), "js-bundle"))
        if code == 200 and body:
            text = body[:4_000_000].decode("utf-8", "replace")
            with open(os.path.join(raw, tag + ".js"), "w", encoding="utf-8") as f:
                f.write(text)
            for r in ROUTE_RE.findall(text):
                if not re.search(r"[{}$:<>]|\.\.|//", r):
                    routes.add(r)
            for a in ABS_RE.findall(text):
                ah = urlparse(a).hostname or ""
                if ah and in_scope(ah) and not THIRD_PARTY.search(ah) and not re.search(r"[{}$<>]", a):
                    abs_routes.add(a)
            for name, rx in SECRET_RES:
                for m in re.findall(rx, text)[:3]:
                    val = m if isinstance(m, str) else "".join(m)
                    secrets.append((name, u))
                    break
            for m in re.finditer(r"""["'`]([^"'`]{0,120}[?&](?:url|uri|target|redirect|dest|proxy|link|feed|callback)=)""", text, re.I):
                lit = m.group(1).strip()
                if lit.startswith("http") or lit.startswith("//"):  # absolute: only an in-scope host counts
                    lh = urlparse(lit if lit.startswith("http") else "https:" + lit).hostname or ""
                    if not lh or not in_scope(lh) or THIRD_PARTY.search(lh):
                        continue  # share buttons (pinterest/linkedin/twitter ?url=) are not the program's endpoints
                proxies.add(lit[:140])
        time.sleep(SPACING)
    rdir = os.path.join(lane, "routes")
    os.makedirs(rdir, exist_ok=True)
    if routes or abs_routes or proxies:
        with open(os.path.join(rdir, f"{safe}.txt"), "w") as f:
            f.write(f"# routes mined from {len(js[:MAX_JS])} JS bundle(s) on {host} at {now()}\n")
            for r in sorted(routes):
                f.write(r + "\n")
            for a in sorted(abs_routes):
                f.write(a + "\n")
            for x in sorted(proxies):
                f.write("PROXY-PARAM " + x + "\n")
    # the same bundle is often served by hundreds of sibling hosts (e.g. every *.app.example.com portfolio):
    # a JS-derived lead is raised ONCE per program, keyed on what was found, not on the host it was found on
    seen_path = os.path.join(ORCH, f"js-seen-{program}.json")
    with _STATE_LOCK:
        try:
            seen = set(json.load(open(seen_path)))
        except (OSError, ValueError):
            seen = set()
        fresh = []
        for name, u in secrets:
            key = f"secret:{name}:{urlparse(u).path}"
            if key not in seen:
                seen.add(key)
                fresh.append(("secret-in-js:" + name, "js", u, 200))
        for x in sorted(proxies)[:5]:
            key = "proxy:" + re.sub(r"\s+", "", x)[-80:]
            if key not in seen:
                seen.add(key)
                fresh.append(("ssrf-candidate", "js", f"{base} :: {x}", 0))
        with open(seen_path, "w") as f:
            json.dump(sorted(seen), f)
    leads += fresh
    # probe the mined routes, GET only, after an API-level nonsense control (catch-all JSON 200s are common)
    targets = [urljoin(base, r.lstrip("/")) if not r.startswith("http") else r for r in sorted(routes)]
    targets += sorted(abs_routes)
    targets = [t for t in targets if not PROXY_PARAM_RE.search(t)][:MAX_ROUTES]  # never fire a URL-taking param blind
    if not targets:
        return
    jhdrs = dict(hdrs, Accept="application/json")
    ctl = f"{scheme}://{host}/api/gnoc-{random.randint(10**6, 10**7)}-nonexistent"
    try:
        c_code, c_rh, c_body = fire(ctl, jhdrs)
        rows.append((f"{safe}-api-ctl", ctl, c_code, len(c_body), "api nonsense control"))
    except Exception:
        c_code, c_body = 0, b""
    time.sleep(SPACING)
    for i, t in enumerate(targets):
        th = urlparse(t).hostname or ""
        if not in_scope(th) or THIRD_PARTY.search(th):
            continue
        tag = f"{safe}-rt{i:02d}"
        try:
            code, rh, body = fire(t, jhdrs)
        except Exception:
            time.sleep(SPACING)
            continue
        with open(os.path.join(raw, tag + ".resp"), "wb") as f:
            f.write(f"GET {t}\nHTTP {code}\n".encode() + "".join(f"{k}: {v}\n" for k, v in rh.items()).encode() + b"\n" + body)
        note = ""
        ctype = rh.get("content-type", "")
        if code == 200 and "json" in ctype and body:
            same_as_ctl = c_code == 200 and abs(len(body) - len(c_body)) <= max(32, 0.05 * max(1, len(c_body)))
            text = body[:300000].decode("utf-8", "replace")
            pii = PII_KEYS.findall(text)
            if not same_as_ctl and pii:
                note = "HIT unauth-data " + ",".join(sorted({k.lower() for k in pii})[:6])
                hits.append(("js-route-unauth-data", t, code, len(body)))
            elif not same_as_ctl and len(body) > 200:
                note = "unauth JSON (no user-data keys)"
                leads.append(("unauth-json-route", tag, t, code))
        rows.append((tag, t, code, len(body), note))
        time.sleep(SPACING)


def sweep(program, host, scheme="https", seen_fp=None):
    if THIRD_PARTY.search(host):  # belt and braces: refuse even a host passed by hand
        print(f"{host}: REFUSED third-party platform, never swept")
        return 0
    in_scope = scope_ok_fn(program)
    lane = os.path.join(WS, "targets", program, "hunts", "auto-exposure")
    raw = os.path.join(lane, "raw")
    os.makedirs(raw, exist_ok=True)
    safe = re.sub(r"[^a-z0-9.-]", "_", host.lower())
    hdrs = {"X-HackerOne": handle(), "Accept": "*/*"}
    t0 = time.time()
    rows, hits, leads, refused = [], [], [], []
    nonsense = f"/gnoc-{random.randint(10**7, 10**8)}-nonexistent"
    plan = [("ctl-nonsense", nonsense, None), ("ctl-root", "/", None)] + list(PROBES)
    base_len, root_blob, blocked, note_end = None, "", 0, ""
    root_html = ""
    i = 0
    while i < len(plan):
        tag, path, sig = plan[i]
        i += 1
        url = f"{scheme}://{host}{path}"
        if not in_scope(urlparse(url).hostname):
            refused.append(url)
            continue
        full = f"{safe}-{tag}"
        try:
            code, rh, body = fire(url, hdrs)
        except Exception as e:
            rows.append((full, url, 0, 0, f"error {type(e).__name__}"))
            time.sleep(SPACING)
            continue
        with open(os.path.join(raw, full + ".resp"), "wb") as f:
            f.write(f"GET {url}\nHTTP {code}\n".encode() + "".join(f"{k}: {v}\n" for k, v in rh.items()).encode() + b"\n" + body)
        with open(os.path.join(lane, "commands.txt"), "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} {full} GET {url} -> {code} {len(body)}b\n")
        text = body[:200000].decode("utf-8", "replace")
        hblob = "".join(f"{k}: {v}\n" for k, v in rh.items())
        note = ""
        # back off: rate limit or edge block three times in a row ends this host
        if code == 429 or (code == 403 and "Access Denied" in text and "akamai" in hblob.lower() + text.lower()):
            blocked += 1
            if blocked >= 3:
                note_end = f"stopped: {code} edge/rate-limit x3, backing off"
                rows.append((full, url, code, len(body), note_end))
                break
        else:
            blocked = 0
        if tag == "ctl-nonsense":
            base_len = len(body)
        if tag == "ctl-root":
            root_blob = hblob + text[:20000]
            root_html = text if (code == 200 and "html" in rh.get("content-type", "").lower()) else ""
            fp = (rows[0][2] if rows else 0, base_len, code, len(body), "")  # same key shape as fingerprints()
            if seen_fp is not None:
                seen_fp[fp] = seen_fp.get(fp, 0) + 1
                if seen_fp[fp] > 3:  # 4th host answering exactly like 3 others: a catch-all edge, skip the probes
                    note_end = "catch-all: identical controls to 3+ swept hosts, probes skipped"
                    rows.append((full, url, code, len(body), note_end))
                    break
            for name, rx, extra in TECH:
                if re.search(rx, root_blob):
                    plan += [(t, p_, sg) for t, p_, sg in extra]
                    note += f"tech:{name} "
        if sig and 200 <= code < 300:
            differs = base_len is None or abs(len(body) - base_len) > max(32, 0.05 * base_len)
            if differs and re.search(sig, text):
                note += "HIT"
                hits.append((tag, url, code, len(body)))
            elif not differs:
                note += "soft-200 (same length as nonsense control)"
        if 200 <= code < 600 and tag != "ctl-nonsense":
            for lname, lrx in LEAD_RES:
                if re.search(lrx, text):
                    leads.append((lname, tag, url, code))
            if code == 401 and "basic realm" in hblob.lower():
                leads.append(("basic-auth", tag, url, code))
        rows.append((full, url, code, len(body), note.strip()))
        time.sleep(SPACING)
    if root_html and not note_end and os.environ.get("AUTO_JS_SEED", "1") == "1":
        try:
            js_seed(program, host, scheme, root_html, hdrs, in_scope, raw, lane, safe, rows, hits, leads)
        except Exception as e:  # the seed stage must never cost the host its fixed-probe results
            rows.append((f"{safe}-js-error", "-", 0, 0, f"js-seed error {type(e).__name__}"))
    with open(os.path.join(lane, "STATUS.md"), "a") as f:
        f.write(f"\n## Round {host} (auto-hunt {now()})\n\n| tag | method | url | status | length |\n|---|---|---|---|---|\n")
        for full, url, code, ln, note in rows:
            f.write(f"| {full} | GET | {url} | {code} | {ln}b |{(' ' + note) if note else ''}\n")
        if refused:
            f.write(f"\nREFUSED (scope, never fired): {', '.join(refused)}\n")
    if leads:
        with open(os.path.join(lane, "LEADS.md"), "a") as f:
            for lname, tag, url, code in leads:
                ref = tag if tag.startswith(safe) else (f"{safe}-js*.js" if tag == "js" else f"{safe}-{tag}")
                f.write(f"- {now()} {lname:<13} {code} {url}  (raw/{ref}{'' if tag == 'js' else '.resp'})\n")
    with _STATE_LOCK:
        _save_swept(program, host, {"ts": now(), "fired": len(rows), "hits": len(hits), "leads": len(leads),
                         "secs": round(time.time() - t0), "note": note_end})
    # A SWEEP MAY NEVER WRITE A DEAD. It fires each URL once across many URLs: that is BREADTH, and the
    # floor is DEPTH - 8 crafted MUTATIONS of one vector plus a concurrent burst with its serial control
    # (SPINE 4). This lane cannot burst at all (burst is hardcoded False below), so a DEAD from here is a
    # verdict its own evidence cannot support, and T-266 says probes against routes that only ever refused
    # are ABSENT SURFACE, not a tested negative. Measured 2026-10-27: 371 of the 452 DEAD rows in the
    # ledger came from this lane, 368 of them burst-less, and they are what the steering blob then reads
    # back as "the surface is dead". RULE 3 records a stale dead suppressing a re-hunt that later paid two
    # massive criticals. So: hits -> LEAD, no hits -> UNFIRED. hunt-state.py rejects a bad DEAD anyway;
    # this makes the sweep incapable of proposing one in the first place.
    elapsed = time.time() - t0
    floor = "met" if len(rows) >= 8 and elapsed >= 1800 else "not-met"
    outcome = {"ts": now(), "lane": f"auto-exposure-{safe}", "target": program,
               "vector": f"auto-hunt unauth exposure sweep {host}", "verdict": "LEAD" if hits else "UNFIRED",
               "capability": ("candidate exposure, unverified: " + ", ".join(t for t, *_ in hits)) if hits else "none",
               "probes": len(rows), "burst": False, "minutes": round((time.time() - t0) / 60, 1), "floor": floor,
               "artifact": f"targets/{program}/hunts/auto-exposure/STATUS.md",
               "notes": "orch-bot auto-hunt; " + (note_end or "full sweep") + f"; weak leads {len(leads)}"
                        + ("" if hits else "; breadth sweep, one request per URL and no burst: this is "
                           "ABSENT SURFACE (UNFIRED), never a tested negative - a DEAD here needs a "
                           "class hunter to mutate ONE vector 8+ times plus a burst")}
    subprocess.run([sys.executable, os.path.join(WS, "scripts/hunt-state.py"), "append-outcome"],
                   input=json.dumps(outcome), text=True, cwd=WS, capture_output=True)
    if hits:
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **AUTO-HIT** {program} {host}: " + "; ".join(f"{t} {c} {n}b {u}" for t, u, c, n in hits)
                    + " -> bug signal only; auto-escalate.py tests it next (stability, credential arms, sensitivity) and "
                    "posts EXPLOIT-CANDIDATE only if it survives\n")
    if any(l[0] in ("dir-listing", "debug-mode", "stack-trace", "ssrf-candidate", "unauth-json-route")
           or l[0].startswith("secret-in-js") for l in leads):
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **AUTO-LEAD** {program} {host}: " + ", ".join(sorted({l[0] for l in leads}))
                    + f" (targets/{program}/hunts/auto-exposure/LEADS.md)\n")
    print(f"{host}: fired {len(rows)}, hits {len(hits)}, leads {len(leads)}, refused {len(refused)}"
          + (f", {note_end}" if note_end else ""))
    return len(hits)


def _save_swept(program, host, rec):
    st = load_state(program)
    st["swept"][host] = rec
    with open(state_path(program), "w") as f:
        json.dump(st, f, indent=1)


def fingerprints(program):
    """Control fingerprints of hosts already swept, rebuilt from STATUS.md so catch-all dedupe survives restarts."""
    fp = {}
    sp = os.path.join(WS, "targets", program, "hunts", "auto-exposure", "STATUS.md")
    if not os.path.isfile(sp):
        return fp
    for block in open(sp, encoding="utf-8", errors="replace").read().split("\n## Round ")[1:]:
        rows = re.findall(r"\| \S+-ctl-(nonsense|root) \| GET \| \S+ \| (\d+) \| (\d+)b", block)
        if len(rows) >= 2:
            key = (int(rows[0][1]), int(rows[0][2]), int(rows[1][1]), int(rows[1][2]))
            fp[key] = fp.get(key, 0) + 1
    return {(k[0], k[1], k[2], k[3], ""): v for k, v in fp.items()}


def main(argv):
    if len(argv) < 2 or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    program = argv[0]
    if not os.path.isfile(os.path.join(WS, "targets", program, "SCOPE.txt")):
        sys.exit(f"no SCOPE.txt for {program}")
    if automation_banned(program):
        pol = lib_policy.policy(program)
        sys.exit(f"REFUSED: {program}/PROGRAM.md appears to ban automated scanning (T-156); auto-hunt will not run"
                 f" [{pol['status']}] {pol['evidence']}")
    os.makedirs(ORCH, exist_ok=True)
    # HUNTING IS BOUND TO A LIVE gnoc chat (GreyNOC, 2026-11-02). Only the modes that actually fire
    # probes are gated; --plan and --report are read-only and stay available with no chat open.
    if argv[1] in ("--next", "--host"):
        sys.path.insert(0, os.path.join(WS, "scripts"))
        import gnoc_session
        ok, why = gnoc_session.require(f"auto-hunt on {program}")
        if not ok:
            sys.exit(why)
    if argv[1] == "--plan":
        st = load_state(program)["swept"]
        hs = hosts(program)
        print(f"{len(hs)} candidate hosts, {len(st)} swept")
        for h, sch in (hs if "--all" in argv else hs[:40]):
            print(f"  {'done' if h in st else 'todo'}  {sch}://{h}")
        return 0
    if argv[1] == "--report":
        st = load_state(program)
        sw = st.get("swept", {})
        total = len(hosts(program))
        secs = [v.get("secs") for v in sw.values() if v.get("secs")]
        avg = sum(secs) / len(secs) if secs else 0
        workers = int(os.environ.get("AUTO_WORKERS", "4"))
        left = max(0, total - len(sw))
        catch = sum(1 for v in sw.values() if str(v.get("note", "")).startswith("catch-all"))
        throttled = sum(1 for v in sw.values() if "rate-limit" in str(v.get("note", "")))
        flags = ("EXHAUSTED " if st.get("exhausted") else "") + ("PARKED" if st.get("parked") else "")
        print(f"{program:<20} swept {len(sw)}/{total}  hits {sum(v.get('hits', 0) for v in sw.values())}  "
              f"leads {sum(v.get('leads', 0) for v in sw.values())}  catch-all {catch}  backed-off {throttled}  "
              f"avg {avg:.0f}s/host  ETA {left * avg / max(1, workers) / 3600:.1f}h {flags}")
        return 0
    if argv[1] == "--host":
        sweep(program, argv[2])
        return 0
    if argv[1] == "--next":
        n = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 1
        workers = int(argv[argv.index("--workers") + 1]) if "--workers" in argv else 1
        st = load_state(program)["swept"]
        todo = [(h, sch) for h, sch in hosts(program) if h not in st][:n]
        if not todo:
            print(f"all hosts swept for {program}")
            return 3
        seen = fingerprints(program)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max(1, min(workers, 6))) as ex:  # parallel across HOSTS, never within one
            list(ex.map(lambda hs: sweep(program, hs[0], hs[1], seen), todo))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
