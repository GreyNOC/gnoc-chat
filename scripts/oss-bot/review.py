#!/usr/bin/env python3
"""oss-bot secret review - work the triaged secret leads instead of leaving them in a list.

    review.py run [--max N] [--quiet]   A rules pass (deterministic, auto-applied, undoable), then up to N leads
                                        (default 6) to the brain model ON THE DESKTOP for a suggested verdict,
                                        then one inbox line per lead the model calls possibly-live
    review.py show [--all]              the suggestions waiting for a human (--all: every recorded verdict)
    review.py accept [verdicts]         apply model suggestions as FP marks (default: placeholder,public-by-design,ours);
                                        possibly-live and unsure are never accepted in bulk
    review.py --selftest                offline: value location by hash, feature extraction, every public rule

Order of work for each open secret lead (state LEAD, not suppressed, no verdict yet):
  1 locate    the evidence is "<first4>...<last2> sha256:<12> at <file>:<line>"; the exact value is found in the
              local file by that hash, so nothing is guessed
  2 rules     public by design, applied automatically as suppressed='public:<kind>' with an 'auto-triage' note
              (so `triage.py --undo` restores them): reCAPTCHA site key, Cloudflare NEL beacon, EVM address,
              32-byte hex constant, pinned action SHA, SRI hash, a type name in a declaration, a placeholder
  3 model     whatever is left goes to the brain role's model, ONLY when that role is served by the desktop GPU
              (the laptop GPU is the hunter's; no fallback). The model never sees the value: it gets the detector,
              the file path, the surrounding lines with the value replaced by <VALUE>, and the value's shape
              (length, charset, entropy, 4-char prefix). Its answer is a SUGGESTION in review.json, never a mark.
  4 surface   possibly-live -> one OSS-REVIEW inbox line per lead (file:line, detector, why). A found credential is
              never used or tested against a live service; that call is the user's, per lead.
"""
from __future__ import annotations

import glob
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from bbtools import lib_scope  # noqa: E402
import ingest  # noqa: E402

ROOT = lib_scope.WS_ROOT
SD = ingest.state_dir(ROOT)
REVIEW = os.path.join(SD, "review.json")
VERDICTS = ("placeholder", "public-by-design", "ours", "possibly-live", "unsure")
EV_RE = re.compile(r"^(?P<pre>.{0,4})\.\.\.(?P<suf>.{0,2}) sha256:(?P<h>[0-9a-f]{12}) at (?P<file>.+):(?P<line>\d+)$")
PLACEHOLDER = re.compile(r"example|xxxx|your[_-]?|changeme|change_me|dummy|sample|placeholder|fake|<[^>]*>|\*\*\*|"
                         r"^(.)\1{7,}$|0{8,}|1234567|abcdef0123|insert[_-]?", re.I)


def _write(path, text):
    rp = os.path.realpath(path)
    if not rp.startswith(os.path.realpath(SD) + os.sep):
        raise SystemExit(f"refusing to write outside {SD}: {path}")
    with open(rp + ".tmp", "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(rp + ".tmp", rp)


def load_review():
    try:
        return json.load(open(REVIEW, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def evidence_map(program):
    out = {}
    for ln in open(os.path.join(ROOT, "targets", program, "recon/oss-bot/leads.jsonl"), encoding="utf-8",
                   errors="replace") if os.path.isfile(os.path.join(ROOT, "targets", program, "recon/oss-bot/leads.jsonl")) else []:
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if r.get("fp"):
            out[r["fp"]] = r.get("evidence") or ""
    return out


def find_file(program, rel):
    bases = [ROOT, os.path.join(ROOT, "targets", program)]
    for sub in ("recon/src", "recon/source"):
        bases.append(os.path.join(ROOT, "targets", program, sub))
        bases += glob.glob(os.path.join(ROOT, "targets", program, sub, "*"))
    for b in bases:
        p = os.path.join(b, rel)
        if os.path.isfile(p):
            return p
    return None


def _scan(s, pre, suf, want, maxlen=1024):
    """(start, end) of the substring of s that starts with pre, ends with suf and hashes to want, else None."""
    start = s.find(pre)
    while start != -1:
        for end in range(start + max(len(pre) + len(suf), 6), min(len(s), start + maxlen) + 1):
            if s.endswith(suf, start, end) and hashlib.sha256(s[start:end].encode()).hexdigest()[:12] == want:
                return start, end
        start = s.find(pre, start + 1)
    return None


def _b64(tok):
    import base64
    import binascii
    for f in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return f(tok + "=" * (-len(tok) % 4)).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            continue
    return ""


def keyname(before):
    """The config key a value is assigned to: '..."DATADOG_CLIENT_TOKEN":"' -> DATADOG_CLIENT_TOKEN."""
    m = re.search(r"[\"']?([A-Za-z_][A-Za-z0-9_.\-]{1,60})[\"']?\s*[:=]\s*[\"']?$", before[-160:])
    return m.group(1) if m else None


def locate(program, evidence):
    """-> dict(file, line, lines, idx, value, keyname, decoded, stale). The exact value is found by its hash: first in
    the raw lines around the reported line (it can sit mid-token, e.g. inside a 2.7 KB cookie), then inside base64
    tokens of those lines (raw or url-decoded), because gitleaks/trufflehog decode before matching: on 2026-10-21
    every program-46 hit sat in a base64 JSON front-end config cookie. value is None when nothing hashes to it."""
    m = EV_RE.match(evidence or "")
    if not m:
        return None
    path = find_file(program, m.group("file"))
    if not path:
        return {"file": m.group("file"), "line": int(m.group("line")), "lines": [], "idx": 0, "value": None}
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    ln = int(m.group("line"))
    pre, suf, want = m.group("pre"), m.group("suf"), m.group("h")
    window = sorted(range(max(0, ln - 3), min(len(lines), ln + 2)), key=lambda k: abs(k - (ln - 1)))
    out = {"file": os.path.relpath(path, ROOT), "line": ln, "lines": lines, "idx": min(max(ln - 1, 0), max(len(lines) - 1, 0)),
           "value": None, "keyname": None, "decoded": None}
    for i in window:
        hit = _scan(lines[i], pre, suf, want)
        if hit:
            out.update(line=i + 1, idx=i, value=lines[i][hit[0]:hit[1]], keyname=keyname(lines[i][:hit[0]]))
            return out
    import urllib.parse
    for i in window:  # url-decoded text itself (a value inside an encoded redirect or cookie)
        for layer in dict.fromkeys((urllib.parse.unquote(lines[i]), urllib.parse.unquote(urllib.parse.unquote(lines[i])))):
            if layer == lines[i]:
                continue
            hit = _scan(layer, pre, suf, want)
            if hit:
                out.update(line=i + 1, lines=[layer], idx=0, value=layer[hit[0]:hit[1]], keyname=keyname(layer[:hit[0]]),
                           decoded=f"url-decoded line {i + 1}")
                return out
    for i in window:
        for layer in dict.fromkeys((lines[i], urllib.parse.unquote(lines[i]))):
            for tok in re.findall(r"[A-Za-z0-9+/_\-]{24,}={0,2}", layer):
                d = _b64(tok)
                hit = _scan(d, pre, suf, want) if pre in d else None
                if hit:
                    segs = re.split(r"(?<=[,{}])", d)  # one JSON pair per pseudo-line for the context window
                    pos, k = 0, 0
                    for k, sgm in enumerate(segs):
                        if pos + len(sgm) > hit[0]:
                            break
                        pos += len(sgm)
                    out.update(line=i + 1, lines=segs, idx=k, value=d[hit[0]:hit[1]], keyname=keyname(d[:hit[0]]),
                               decoded=f"base64 token inside line {i + 1}")
                    return out
    out["stale"] = ln > len(lines)  # the file changed since the scan (line past its end)
    return out


def entropy(v):
    if not v:
        return 0.0
    c = {ch: v.count(ch) for ch in set(v)}
    return round(-sum(n / len(v) * math.log2(n / len(v)) for n in c.values()), 2)


def features(v):
    if v is None:
        return {"located": False}
    cls = "".join(k for k, rx in (("a", r"[a-z]"), ("A", r"[A-Z]"), ("9", r"[0-9]"), ("_", r"[_\-]"), ("+", r"[+/=]"),
                                  (".", r"[^A-Za-z0-9_\-+/=]")) if re.search(rx, v))
    return {"located": True, "len": len(v), "charset": cls, "entropy": entropy(v), "prefix": v[:4]}


PUBLIC_KEY = re.compile(r"site_?key|client_?token|publishable|public|_guid$|guid$|form_?id|app_?id$|client_?id$|"
                        r"measurement_?id|tracking_?id|dsn$|rum_|analytics|onetrust|consent|gtm|pixel|tag_?manager", re.I)
# per-response ids a server stamps on every reply (2026-10-21: 107 of 113 epicgames hits were x-amz-apigw-id)
RESPONSE_ID = re.compile(r"^(x-amz-apigw-id|x-amzn-requestid|x-amzn-trace-id|x-amz-request-id|x-amz-cf-id|x-amz-id-2|"
                         r"x-request-id|x-req-id|request-id|x-correlation-id|x-trace-id|traceparent|x-b3-traceid|cf-ray|"
                         r"x-cache-key|x-served-by|x-timer|x-github-request-id|x-runtime|etag|x-vercel-id|fly-request-id)$",
                         re.I)
# values minted per request FOR US (OAuth state, nonce, anti-CSRF): ours by construction, never a leaked credential
PER_REQUEST = re.compile(r"^(state|nonce|code_challenge|csrf|csrf_?token|_csrf|xsrf|xsrf_?token|_token|"
                         r"authenticity_token|__requestverificationtoken|request_?token|correlation_?id)$", re.I)
# client-side analytics / tagging SDKs whose key is designed to sit in the page (2026-10-21: Amplitude, Avo Inspector,
# AppsFlyer banners on wolt and 8x8). Matched on the key name or the 200 chars before the value, never on the value.
SDK_VENDOR = re.compile(r"amplitude|\bavo|avoinspector|appsflyer|\"AF\",\s*\"banners\"|mixpanel|segment\.(io|com)|"
                        r"analytics\.load|posthog|intercom|hotjar|fullstory|launchdarkly|clientsideid|optimizely|statsig|"
                        r"growthbook|heap\.load|braze|onesignal|branch\.init", re.I)
PRIVATE_KEY = re.compile(r"secret|private|passw|signing|webhook|_sk$|^sk_|admin|service_?role|refresh|session", re.I)


def _jwt_claims(v):
    """The payload of a JWT-shaped value (header must decode with an 'alg'), else None. Never verified, only read."""
    import base64
    parts = str(v).split(".")
    if len(parts) != 3 or not parts[0].startswith("eyJ"):
        return None
    try:
        dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))  # noqa: E731
        return dec(parts[1]) if "alg" in dec(parts[0]) else None
    except Exception:
        return None


def public_rule(v, line, ctx, key=None, decoded=None):
    """'public:<kind>' when the value is public by design or not a secret at all, else None. Conservative: every
    branch needs the value's own shape AND the surrounding text (or the config key it is assigned to) to agree."""
    if v is None:
        return None
    lo, cl = line.lower(), ctx.lower()
    if key and PER_REQUEST.match(key):
        return f"ours:per-request-{key.lower()[:30]}"
    jwt = _jwt_claims(v)
    if jwt is not None:
        role = str(jwt.get("role") or jwt.get("scope") or "").lower()
        if role in ("anon", "anonymous", "public", "guest"):
            return "public:jwt-anon-role"
        if isinstance(jwt.get("exp"), (int, float)) and jwt["exp"] < time.time() - 86400:
            return "dead:jwt-expired"
    if key and RESPONSE_ID.match(key) and re.match(r"\s*" + re.escape(key) + r"\s*:", line, re.I):
        return f"public:response-id-{key.lower()[:30]}"
    if key and PUBLIC_KEY.search(key) and not PRIVATE_KEY.search(key):
        return f"public:config-{key[:40]}"
    if re.fullmatch(r"pub[0-9a-f]{32}", v):
        return "public:datadog-client-token"
    if re.fullmatch(r"pk\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{10,}", v) and ("mapbox" in cl or (key and "mapbox" in key.lower())):
        return "public:mapbox-public-token"  # pk.* is the browser token by design; sk.* (secret) is not matched
    if (key and re.fullmatch(r"sentry_?(key|dsn|public_?key)", key, re.I)) or \
            re.search(r"https?://" + re.escape(v) + r"@[a-z0-9.-]*sentry\.io", line):
        return "public:sentry-dsn-key"  # the public half of a DSN, built to ship to browsers
    if (not decoded or str(decoded).startswith("url-decoded")) and lo.startswith("set-cookie") and v in line:
        i = line.find(v)  # the cookie (name=value up to ';' or ', next') that holds the value: set on OUR request
        seg = re.findall(r"([A-Za-z0-9_.\-]+)=[^;,]*$", line[:i] + v)
        if seg:
            return f"ours:set-cookie-{seg[-1][:30]}"
    pre = line[max(0, line.find(v) - 200):line.find(v)] if v in line else ""
    if re.search(r"nonce-$|nonce=[\"']?$", pre):
        return "ours:per-response-nonce"  # a CSP / script nonce: fresh in every response, issued to us
    if (key and SDK_VENDOR.search(key)) or SDK_VENDOR.search(pre):
        return "public:analytics-sdk-key"  # browser analytics / tagging SDK keys (Amplitude, Avo, AppsFlyer, ...)
    if key and re.fullmatch(r"(player|analytics|write|browser|rum)_?key", key, re.I):
        return f"public:browser-key-{key[:30]}"  # vendor keys built to ship in client-side JS (Bitmovin, Segment)
    if v.startswith("6L") and len(v) == 40 and ("sitekey" in cl or "recaptcha" in cl):
        return "public:recaptcha-sitekey"
    if "nel.cloudflare.com" in lo or ('"group":"cf-nel"' in lo and "report-to" in lo):
        return "public:cloudflare-nel"
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", v):
        return "public:evm-address"
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", v) and re.search(r"keccak|slot|hash|topic|selector|root", cl):
        return "public:hex-constant"
    if re.fullmatch(r"[0-9a-f]{40}", v) and re.search(r"uses:\s*\S+@" + re.escape(v), line):
        return "public:action-pin"
    if re.match(r"sha(256|384|512)-", v) or "integrity=" in lo:
        return "public:sri-hash"
    words = re.findall(r"[A-Z]?[a-z]{2,}", v)
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", v) and len(v) <= 40 and sum(ch.isdigit() for ch in v) <= 4 and \
            len([w for w in words if re.search(r"[aeiou]", w)]) >= 2 and \
            re.search(r"\btype\s+\w+\s*=|\bclass\s|\bstruct\s|\benum\s|::|key_type|\binterface\s", ctx):
        return "public:type-name"
    if PLACEHOLDER.search(v):
        return "public:placeholder"
    return None


SYSTEM = ("You review secret-scanner hits for an authorized bug-bounty researcher. You never see the secret itself, "
          "only its shape and the lines around it (the value is shown as <VALUE>). Classify the hit as exactly one of: "
          "placeholder (an example/test/dummy value), public-by-design (meant to be public: a publishable or site key, "
          "a public client id, an address, a hash, an id that is not a credential), ours (the file is a capture of the "
          "researcher's own account, so any credential in it belongs to the researcher), possibly-live (a credential "
          "that could grant access and does not look public or fake), unsure. Prefer possibly-live over a guess when "
          "a private credential is plausible. Answer in JSON.")
SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string", "enum": list(VERDICTS)},
                                           "why": {"type": "string"}}, "required": ["verdict", "why"]}


def masked_context(loc, v, n=3):
    out = []
    for i in range(max(0, loc["idx"] - n), min(len(loc["lines"]), loc["idx"] + n + 1)):
        s = loc["lines"][i]
        if v:
            s = s.replace(v, "<VALUE>")
        s = re.sub(r"[A-Za-z0-9_\-+/=]{20,}", lambda m: f"<TOKEN len={len(m.group(0))}>", s)  # any other long token
        out.append(f"{i + 1:>5}{'>' if i == loc['idx'] else ' '} {s[:220]}")
    return "\n".join(out)


ENDPOINT = None


def desktop_model():
    try:
        import llm_endpoints
        r = llm_endpoints.roles()
        if llm_endpoints.split(r.get("brain") or llm_endpoints.DEFAULT)[1] != "desktop":
            return None   # brain not served by the desktop GPU: model step stays off, as before
        got = llm_endpoints.failover("brain")   # desktop -> laptop -> phone by health; plain resolve() when desktop is up
        if not got:
            return None
        url, model, host = got
    except Exception:
        return None
    global ENDPOINT
    ENDPOINT = host
    return (url, model)


def _ctx_for_url(url):
    """The per-host context size every caller uses (D84, 2026-10-26): this review asked the desktop's 35B for a
    4096 window four times in 25 minutes and Ollama started a new runner each time, on the card the lead was on."""
    try:
        import llm_endpoints
        for host, addr in llm_endpoints.HOSTS.items():
            if addr and addr in str(url):
                return llm_endpoints.ctx_for_host(host)
    except Exception:  # noqa: BLE001
        pass
    return 16384


def ask(url, model, lead, loc, feats):
    user = (f"detector: {lead['tool']}/{lead['rule']}\nprogram: {lead['program']}\nfile: {loc['file']}\n"
            f"value shape: {json.dumps(feats)}\nassigned to key: {loc.get('keyname') or '(none found)'}\n"
            f"found: {loc.get('decoded') or 'raw in the file'}\ncontext:\n{masked_context(loc, loc.get('value'))}\n\n"
            "Classify. why = one sentence naming the context that decides it.")
    body = {"model": model, "stream": False, "format": SCHEMA,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            "options": {"temperature": 0.1, "num_ctx": _ctx_for_url(url), "num_predict": 200}, "keep_alive": "30m"}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        content = json.loads(r.read().decode()).get("message", {}).get("content", "")
    d = json.loads(re.search(r"\{.*\}", content, re.S).group(0))
    if d.get("verdict") not in VERDICTS:
        d["verdict"] = "unsure"
    return {"verdict": d["verdict"], "why": str(d.get("why", ""))[:240]}


def _inbox(line):
    with open(os.path.join(ROOT, ".claude/state/orch/INBOX.md"), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def cmd_run(max_n=6, quiet=False):
    con = ingest.db_connect(ROOT)
    rows = con.execute("SELECT fp,program,tool,rule,url FROM leads WHERE state='LEAD' AND (suppressed IS NULL OR "
                       "suppressed='') AND tool IN ('gitleaks','trufflehog') ORDER BY score DESC, first_seen DESC").fetchall()
    rev = load_review()
    evs, stats = {}, {"rules": 0, "model": 0, "surfaced": 0, "skipped_no_model": 0, "unlocated": 0}
    todo, applied = [], []
    for fp, prog, tool, rule, url in rows:
        if fp in rev:
            continue
        evs.setdefault(prog, evidence_map(prog))
        loc = locate(prog, evs[prog].get(fp, ""))
        lead = {"fp": fp, "program": prog, "tool": tool, "rule": rule, "url": url}
        if not loc or not loc["lines"]:
            stats["unlocated"] += 1
            rev[fp] = {"ts": ingest._iso(), "kind": "none", "verdict": "unsure", "why": "file or evidence not found", "file": url}
            continue
        v = loc.get("value")
        line = loc["lines"][loc["idx"]] if 0 <= loc["idx"] < len(loc["lines"]) else ""
        ctx = "\n".join(loc["lines"][max(0, loc["idx"] - 3):loc["idx"] + 4])
        pub = public_rule(v, line, ctx, loc.get("keyname"), loc.get("decoded"))
        if pub:
            applied.append((pub, f"auto-triage {ingest._iso()} {pub} (review.py rule)", fp))
            rev[fp] = {"ts": ingest._iso(), "kind": "rule", "why": pub,
                       "verdict": {"ours": "ours", "dead": "placeholder"}.get(pub.split(":")[0], "public-by-design"),
                       "file": f"{loc['file']}:{loc['line']}"}
            stats["rules"] += 1
            continue
        if v is None:  # the model must never judge a value nobody located (2026-10-21: 6 of 6 'possibly-live' were
            rev[fp] = {"ts": ingest._iso(), "kind": "unlocated", "verdict": "unsure",  # header lines with no value)
                       "why": "value not found in the file by its hash" + (" (file changed since the scan)" if loc.get("stale") else ""),
                       "file": f"{loc['file']}:{loc['line']}"}
            stats["unlocated"] += 1
            continue
        todo.append((lead, loc))
    if applied:
        con.executemany("UPDATE leads SET suppressed=?, mark_note=? WHERE fp=? AND state='LEAD'", applied)
        con.commit()
    mdl = desktop_model()
    told = 0
    for lead, loc in todo[:max_n]:
        if not mdl:
            stats["skipped_no_model"] = len(todo)
            break
        feats = features(loc.get("value"))
        try:
            ans = ask(mdl[0], mdl[1], lead, loc, feats)
        except Exception as e:  # a slow or absent desktop just leaves the lead for the next round
            stats.setdefault("errors", []).append(f"{lead['fp'][:12]}: {type(e).__name__}")
            try:
                import llm_endpoints
                llm_endpoints.record(ENDPOINT, False) if ENDPOINT else None
            except Exception:
                pass
            continue
        rec = {"ts": ingest._iso(), "kind": "model", "model": mdl[1], "file": f"{loc['file']}:{loc['line']}",
               "features": feats, **ans}
        stats["model"] += 1
        if ans["verdict"] == "possibly-live" and told < 10:
            _inbox(f"- [{ingest._iso()}] **OSS-REVIEW** {lead['program']}: {lead['tool']}/{lead['rule']} at "
                   f"{loc['file']}:{loc['line']} looks possibly live ({mdl[1]}: {ans['why'][:160]}). Read it; never use "
                   f"it without the user. Mark: python3 scripts/oss-bot/bot.py mark {lead['fp'][:16]} fp|verified-elsewhere \"<why>\"")
            rec["told"] = True
            told += 1
            stats["surfaced"] += 1
        rev[lead["fp"]] = rec
    _write(REVIEW, json.dumps(rev, indent=1) + "\n")
    for p in sorted({r[1] for r in rows}):
        ingest.render_seeds(p, ROOT, con)
    con.close()
    stats["waiting"] = max(0, len(todo) - stats["model"])
    stats["endpoint"] = ENDPOINT if mdl else None
    if quiet:
        print(json.dumps(stats))
    else:
        print(f"review: {stats['rules']} public-by-design by rule (auto-suppressed), {stats['model']} model suggestions, "
              f"{stats['surfaced']} surfaced as possibly-live, {stats['waiting']} still waiting"
              + (" (desktop model not available)" if stats["skipped_no_model"] else "")
              + (f", {stats['unlocated']} unlocated" if stats["unlocated"] else ""))
    return 0


def cmd_show(all_=False):
    rev = load_review()
    con = ingest.db_connect(ROOT)
    open_fps = {r[0] for r in con.execute("SELECT fp FROM leads WHERE state='LEAD' AND (suppressed IS NULL OR suppressed='')")}
    con.close()
    for fp, r in sorted(rev.items(), key=lambda kv: kv[1].get("verdict", "")):
        if all_ or (fp in open_fps and r.get("kind") == "model"):
            print(f"{fp[:16]}  {r.get('verdict', '?'):<16} {r.get('kind', ''):<5} {r.get('file', '')[:80]}\n"
                  f"                  {r.get('why', '')[:150]}")
    return 0


def cmd_accept(verdicts):
    rev = load_review()
    con = ingest.db_connect(ROOT)
    stamp, n = ingest._iso(), 0
    for fp, r in rev.items():
        if r.get("kind") == "model" and r.get("verdict") in verdicts and r.get("verdict") not in ("possibly-live", "unsure"):
            n += con.execute("UPDATE leads SET state='FP', mark_note=? WHERE fp=? AND state='LEAD' AND "
                             "(suppressed IS NULL OR suppressed='')",
                             (f"{stamp} review-accept {r.get('model')}: {r.get('verdict')}: {r.get('why', '')}"[:300], fp)).rowcount
    con.commit()
    for (p,) in con.execute("SELECT DISTINCT program FROM leads").fetchall():
        ingest.render_seeds(p, ROOT, con)
    con.close()
    print(f"accepted {n} model suggestions ({', '.join(verdicts)}) as FP")
    return 0


def selftest():
    v = "6LcZx" + "A" * 33 + "Op"
    assert public_rule(v, f"setAttribute('data-sitekey', '{v}')", "grecaptcha sitekey") == "public:recaptcha-sitekey"
    assert public_rule("0x" + "ab" * 20, "export const a = '0x...'", "") == "public:evm-address"
    assert public_rule("0x" + "cd" * 32, "const SLOT = '0x..'", "// keccak256(\"org.proxy\")") == "public:hex-constant"
    sha = "b45d" + "0" * 36
    assert public_rule(sha, f"  uses: docker/login-action@{sha} # v4", "") == "public:action-pin"
    assert public_rule("P256VerifyingKey", "type VerifyingKey = P256VerifyingKey;", "type VerifyingKey = x") == "public:type-name"
    assert public_rule("your_api_key_here", "API_KEY=your_api_key_here", "") == "public:placeholder"
    assert public_rule("Kp3x9QzLm2VbN8rT4wYa", "report-to: {\"group\":\"cf-nel\",\"endpoints\":[{\"url\":\"https://a.nel.cloudflare.com/r?s=Kp\"}]}",
                       "") == "public:cloudflare-nel"
    real = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
    assert public_rule(real, f"STRIPE_KEY={real}", "config") is None, "a live-looking key must reach the model"
    assert public_rule("AKIA" + "Q3EGRIOS7V5HJL2P", "aws_access_key_id = AKIA...", "[default]") is None
    assert public_rule("pub" + "0a" * 16, "", "", "DATADOG_CLIENT_TOKEN") == "public:config-DATADOG_CLIENT_TOKEN"
    assert public_rule("6LfR" + "x" * 36, "", "", "GOOGLE_RECAPTCHA_SITE_KEY").startswith("public:config-")
    assert public_rule(real, "", "", "STRIPE_SECRET_KEY") is None, "a secret-named key is never public"
    assert public_rule(real, "", "", "NEXT_PUBLIC_WEBHOOK_SECRET") is None
    assert keyname('{"a":1,"DATADOG_CLIENT_TOKEN":"') == "DATADOG_CLIENT_TOKEN" and keyname("API_KEY=") == "API_KEY"
    assert public_rule("x" * 36, "", "", "ONETRUST_TOKEN") == "public:config-ONETRUST_TOKEN"
    import base64
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    hdr = enc({"alg": "HS256", "typ": "JWT"})
    assert public_rule(f"{hdr}.{enc({'iss': 'x'})}.sig", "location: /?state=", "", "state") == "ours:per-request-state"
    assert public_rule(f"{hdr}.{enc({'role': 'anon'})}.sig", "key=", "", "apikey") == "public:jwt-anon-role"
    assert public_rule(f"{hdr}.{enc({'exp': 1000})}.sig", "t=", "", "token") == "dead:jwt-expired"
    assert public_rule(f"{hdr}.{enc({'role': 'service_role', 'exp': 4102444800})}.sig", "k=", "", "SUPABASE_KEY") is None
    assert public_rule("UXz2" + "q" * 12, "x-amz-apigw-id: UXz2qqqqqqqqqqqq=", "", "x-amz-apigw-id") == "public:response-id-x-amz-apigw-id"
    assert public_rule(real, f'{{"x-request-id": "{real}"}}', "", "x-request-id") is None, "only a real header line"
    ck = "Wkrm" + "Ab3" * 9 + "Zq"
    assert public_rule(ck, f"set-cookie: a=1; Path=/, __cf_bm={ck}.x; HttpOnly", "", "__cf_bm") == "ours:set-cookie-__cf_bm"
    assert public_rule(ck, f"set-cookie: cfg={ck}", "", "STRIPE_SECRET_KEY", "base64 token inside line 1") is None
    assert public_rule(ck, f"set-cookie: __cf_bm=Hq1x.3238957-1.0.1.1-e.{ck}.cod; HttpOnly", "", None) == "ours:set-cookie-__cf_bm"
    assert public_rule(ck, f"set-cookie: authentik_proxy_x={ck}; HttpOnly", "", None, "url-decoded line 6") == \
        "ours:set-cookie-authentik_proxy_x"
    assert public_rule("a" * 36, 'bitmovin:{player_key:"..."}', "", "player_key") == "public:browser-key-player_key"
    assert public_rule("pk.eyJ1Ijoid29sdCIsImEiOiJ4In0.Ab3dEf9hIjK2", "", "", "MAPBOX_TOKEN") == "public:mapbox-public-token"
    assert public_rule("sk.eyJ1Ijoid29sdCIsImEiOiJ4In0.Ab3dEf9hIjK2", "", "", "MAPBOX_TOKEN") is None, "a mapbox SECRET token"
    assert public_rule("9f3c1e7a2b5d4c8e0a6f1b3d5e7c9a2f", "", "", "sentry_key") == "public:sentry-dsn-key"
    nn = "Vs6x9f3c1e7a2b5d4c8e0a6f1b3d5e7c"
    assert public_rule(nn, f"content-security-policy: script-src 'nonce-{nn}' 'strict-dynamic'", "", None) == \
        "ours:per-response-nonce"
    amp = "d55a" + "9f3c1e7a2b5d4c8e0a6f1b3d5e7c"
    assert public_rule(amp, f'window.__AMPLITUDE__={{"apiKey":"{amp}"}}', "", "apiKey") == "public:analytics-sdk-key"
    assert public_rule("BIx9f3c1e7a2b5d4c8e0a", "", "", "AVO_API_KEY") == "public:analytics-sdk-key"
    assert public_rule("Uyf9f3c1e7a2b5d4c8e0a6f1b3d5e7c9a2f1234", '"GATEKEEPER_API_KEY":"x"', "", "GATEKEEPER_API_KEY") is None
    assert public_rule("9f3c1e7a2b5d4c8e0a6f1b3d5e7c9a2f", 'rollbar:{access_token:"..."}', "", "access_token") is None, \
        "a token key reaches the model"
    f = features(real)
    assert f["located"] and f["len"] == len(real) and f["prefix"] == "sk_l" and f["entropy"] > 3.5
    tmp = os.path.join(SD, "selftest-review")
    os.makedirs(tmp, exist_ok=True)
    p = os.path.join(tmp, "x.env")
    open(p, "w").write("a=1\nSTRIPE=" + real + "\nb=2\n")
    ev = f"{ingest.redact(real)} at {os.path.relpath(p, ROOT)}:2"
    loc = locate("px", ev)
    assert loc and loc["value"] == real and loc["line"] == 2, loc
    import base64
    blob = base64.b64encode(json.dumps({"ENV": "prod", "STRIPE_SECRET_KEY": real}).encode()).decode()
    open(p, "w").write("set-cookie: cfg=" + blob + "; Path=/\n")
    loc2 = locate("px", f"{ingest.redact(real)} at {os.path.relpath(p, ROOT)}:1")
    assert loc2["value"] == real and loc2["decoded"] and loc2["keyname"] == "STRIPE_SECRET_KEY", loc2.get("keyname")
    mc = masked_context(loc, real)
    assert real not in mc and "<VALUE>" in mc, "the model must never see the value"
    os.remove(p)
    os.rmdir(tmp)
    print("review selftest: PASS (32 public rules incl. 10 live-looking negatives, hash-exact location raw + base64 cookie, key names, value masked)")
    return 0


def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if a[0] == "--selftest":
        return selftest()
    if a[0] == "run":
        return cmd_run(int(a[a.index("--max") + 1]) if "--max" in a else 6, "--quiet" in a)
    if a[0] == "show":
        return cmd_show("--all" in a)
    if a[0] == "accept":
        vs = [v for v in (a[1].split(",") if len(a) > 1 else ["placeholder", "public-by-design", "ours"]) if v in VERDICTS]
        return cmd_accept(vs)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
