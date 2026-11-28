#!/usr/bin/env python3
"""auto-escalate.py - turn the auto-hunter's candidate HITs into EXPLOIT-CANDIDATES or demote them. No model.

  auto-escalate.py <program> [--all]     escalate every not-yet-escalated HIT row in auto-exposure/STATUS.md
  auto-escalate.py <program> --url U     escalate one URL by hand

Why: a matched signature is a BUG signal; programs pay for a demonstrated capability (SPINE gates 2-3, the dominant
kill in our own record is "mechanism without capability"). Every candidate goes through, GET only, same URL only:
  1 DETERMINISM   re-fired 3x, 5 s apart; must return the same status and a body that still matches  (T-61)
  2 UNAUTH ARMS   no auth header / fabricated Bearer / junk cookie must all return the data          (T-62, T-165)
  3 SIBLING CTL   a nonsense sibling path on the same host must NOT return the same body           (T-60)
  4 SENSITIVITY   the captured bytes are scored: credential/secret > personal data > internal config > public
  5 ID-KEYED      a numeric/uuid path segment or id-like param is noted as an IDOR-escalation candidate; other ids are
                  NEVER fetched here (that is a human or Claude step, one owned/minimal record, per policy)
Result per URL: targets/<p>/hunts/auto-exposure/escalations/<slug>/ESCALATION.md + raw/ bytes, and a tier:
  TIER-3 EXPLOIT-CANDIDATE  stable, credential-independent, and carries credentials, secrets or personal data
           or internal-network bytes returned through a URL-taking parameter (internal reach, SSRF)
  TIER-2 LEAD               stable and unauth, internal/config data or an id-keyed route (needs the partner bug)
  TIER-1 DEMOTED            unstable, catch-all, credential-dependent, structure-shifting, or public content
Only TIER-3 reaches the orch INBOX as EXPLOIT-CANDIDATE; the ESCALATION.md names the exact next steps that make it a
filable terminal (minimal real sample or owned-object proof, credential scope check, paired write).
"""
import hashlib
import json
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
SECRET = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}|(sk|rk)_live_[0-9A-Za-z]{20,}|xox[abposr]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{30,}"
                    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----|\"(password|passwd|secret|client_secret|api_?key|access_?token|"
                    r"refresh_?token|private_?key|aws_secret_access_key|db_?pass(word)?)\"\s*:\s*\"[^\"*]{6,}\"", re.I)
PII = re.compile(r"\"(e-?mail|email_?address|phone|phone_?number|mobile|msisdn|address|street|dob|date_?of_?birth|passport|"
                 r"ssn|national_?id|first_?name|last_?name|full_?name|card_?number|iban|guest_?name)\"\s*:\s*\"[^\"]{3,}\"", re.I)
INTERNAL = re.compile(r"\b(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b|internal\.|"
                      r"\"propertySources\"|jdbc:|redis://|mongodb(\+srv)?://|amqp://|zookeeper|\"activeProfiles\"", re.I)
ID_SEG = re.compile(r"/(\d{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24})(/|$)", re.I)
ID_PARAM = re.compile(r"[?&](id|user_?id|account_?id|customer_?id|order_?id|booking_?id|uid|profile_?id)=", re.I)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def handle():
    for ln in open(os.path.expanduser("~/.config/gnoc/secrets.env"), encoding="utf-8"):
        if ln.strip().startswith(("HACKERONE_HANDLE", "export HACKERONE_HANDLE")):
            return ln.split("=", 1)[1].strip().strip("'\"")
    return "greynoc"


def scope_fn(program):
    import importlib.util
    spec = importlib.util.spec_from_file_location("ah", os.path.join(WS, "scripts/auto-hunt.py"))
    ah = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ah)
    ok = ah.scope_ok_fn(program)
    return lambda h: ok(h) and not ah.THIRD_PARTY.search(h)


def get(url, extra=None):
    from curl_cffi import requests
    h = {"X-HackerOne": handle(), "Accept": "application/json, */*"}
    h.update(extra or {})
    r = requests.get(url, headers=h, impersonate="chrome124", timeout=25, allow_redirects=False)
    return r.status_code, dict(r.headers), r.content


def fingerprint(body):
    """Body identity that ignores volatile values (timestamps, ids, nonces) but keeps the structure and keys."""
    t = body[:200000].decode("utf-8", "replace")
    t = re.sub(r"\d{4,}", "N", t)
    t = re.sub(r"[0-9a-f]{16,}", "H", t, flags=re.I)
    return hashlib.sha1(t.encode()).hexdigest()[:16], len(body)


def shape(body):
    """Structural identity: top-level JSON keys (or the first element's keys); falls back to a length band.
    Thread dumps, metrics and listings change size on every request; their key structure does not."""
    try:
        d = json.loads(body[:2_000_000].decode("utf-8", "replace"))
        if isinstance(d, list):
            d = d[0] if d and isinstance(d[0], dict) else {}
        if isinstance(d, dict) and d:
            return ("keys", frozenset(d.keys()))
    except ValueError:
        pass
    return ("len", len(body) // max(1, len(body) // 2 or 1) if body else 0, len(body) > 0)


def same_shape_as(a, b):
    if a[0] == "keys" and b[0] == "keys":
        return len(a[1] & b[1]) >= 0.7 * max(1, len(a[1] | b[1]))
    return a == b


def score(text):
    sec = sorted({m.group(0)[:40] for m in SECRET.finditer(text)})
    pii = sorted({m.group(1).lower() for m in PII.finditer(text)})
    inte = sorted({m.group(0)[:30] for m in INTERNAL.finditer(text)})
    return sec, pii, inte


def escalate(program, url, origin="auto-hunt HIT"):
    in_scope = scope_fn(program)
    host = urlparse(url).hostname or ""
    if not in_scope(host):
        return "REFUSED", f"{host} not in scope"
    slug = re.sub(r"[^a-z0-9.-]+", "_", (host + urlparse(url).path).lower()).strip("_")[:90]
    edir = os.path.join(WS, "targets", program, "hunts", "auto-exposure", "escalations", slug)
    raw = os.path.join(edir, "raw")
    os.makedirs(raw, exist_ok=True)
    log = []

    def save(tag, code, rh, body, u):
        with open(os.path.join(raw, tag + ".resp"), "wb") as f:
            f.write(f"GET {u}\nHTTP {code}\n".encode() + "".join(f"{k}: {v}\n" for k, v in rh.items()).encode() + b"\n" + body)
        log.append(f"| {tag} | {u} | {code} | {len(body)}b |")

    # 1 determinism
    shots = []
    for i in range(3):
        try:
            code, rh, body = get(url)
        except Exception as e:
            log.append(f"| det{i} | {url} | error {type(e).__name__} | |")
            time.sleep(5)
            continue
        save(f"det{i}", code, rh, body, url)
        shots.append((code, shape(body), body))
        time.sleep(5)
    stable = len(shots) == 3 and len({s[0] for s in shots}) == 1 and shots[0][0] == 200
    same_shape = stable and all(same_shape_as(shots[0][1], s[1]) for s in shots[1:])
    body = shots[-1][2] if shots else b""
    text = body[:300000].decode("utf-8", "replace")
    # 2 unauth arms (all three must still return the data)
    arms = {}
    for name, extra in (("bogus-bearer", {"Authorization": "Bearer gnoc.invalid.token"}),
                        ("junk-cookie", {"Cookie": "session=gnocinvalid; token=gnocinvalid"})):
        try:
            code, rh, b = get(url, extra)
            save(f"arm-{name}", code, rh, b, url)
            arms[name] = (code, same_shape_as(shape(b), shape(body)))
        except Exception as e:
            arms[name] = (0, False)
        time.sleep(5)
    cred_independent = stable and all(c == 200 and same for c, same in arms.values())
    # 3 nonsense sibling on the same host and path depth
    p = urlparse(url)
    parent = p.path.rsplit("/", 1)[0] or ""
    sib = urlunparse((p.scheme, p.netloc, f"{parent}/gnoc-{random.randint(10**6, 10**7)}-nonexistent", "", "", ""))
    try:
        sc, srh, sb = get(sib)
        save("sibling-nonsense", sc, srh, sb, sib)
        catch_all = sc == 200 and fingerprint(sb)[0] == fingerprint(body)[0]
    except Exception:
        catch_all = False
    # 4 sensitivity, 5 id-keyed
    sec, pii, inte = score(text)
    id_keyed = bool(ID_SEG.search(p.path) or ID_PARAM.search("?" + (p.query or "")))
    # a URL-taking parameter that makes the server return internal-network bytes is internal reach (SSRF), a capability
    ssrf_reach = bool(re.search(r"[?&](url|uri|target|dest|destination|proxy|link|feed)=", "?" + (p.query or ""), re.I)) and bool(inte)
    solid = stable and same_shape and cred_independent and not catch_all
    if solid and (sec or pii or ssrf_reach):
        tier, verdict = 3, "TIER-3 EXPLOIT-CANDIDATE"
    elif solid and (inte or id_keyed):
        tier, verdict = 2, "TIER-2 LEAD"
    else:
        tier, verdict = 1, "TIER-1 DEMOTED"
    why = []
    if not stable:
        why.append("not stable over 3 spaced re-fires")
    if stable and not cred_independent:
        why.append("response changes with credential arms (likely auth-dependent or edge noise)")
    if catch_all:
        why.append("nonsense sibling returns the same body (catch-all)")
    if stable and not same_shape:
        why.append("the response structure changes between re-fires")
    if not (sec or pii or inte):
        why.append("no credential, personal or internal bytes in the body (public content)")
    nxt = []
    if sec:
        nxt.append("Credential/secret captured: determine its scope with the vendor's own read-only identity or "
                   "metadata call ONCE (no data access beyond identity), quote the policy line that allows it, stop there.")
    if pii:
        nxt.append("Personal data captured: keep ONE record as the minimal real sample (fields redacted in the report), "
                   "never enumerate; if the route is id-keyed, prove the crossing with two OWNED accounts instead.")
    if id_keyed:
        nxt.append("Route is id-keyed: IDOR escalation candidate. Provision account A and B, read and then write B's own "
                   "object from A (gold receipt). Do NOT fetch real users' ids from this script.")
    if ssrf_reach:
        nxt.append("Internal reach via a URL parameter: map which internal hosts and paths answer (allowlist, encodings), "
                   "then look for a credential-bearing internal endpoint (env, config, metadata) before writing up.")
    if inte and not (sec or pii or ssrf_reach):
        nxt.append("Internal/config only: find the partner bug (SSRF into the named internal host, or a credential in "
                   "the same family of endpoints) before this is a capability.")
    nxt.append("Then: public dedup, report-writer, gnoc ship <draft> --llm --fix.")
    with open(os.path.join(edir, "ESCALATION.md"), "w") as f:
        f.write(f"# {verdict}\n\nURL: {url}\nProgram: {program}\nOrigin: {origin}\nEscalated: {now()}\n\n"
                f"- stable 3/3 spaced: {stable} (same shape: {same_shape})\n"
                f"- credential-independent (no auth, bogus Bearer, junk cookie): {cred_independent} {arms}\n"
                f"- nonsense sibling catch-all: {catch_all}\n"
                f"- secrets/credentials: {sec or 'none'}\n- personal-data keys: {pii or 'none'}\n"
                f"- internal/config markers: {inte or 'none'}\n- id-keyed (IDOR candidate): {id_keyed}\n\n"
                + (("Why not tier 3: " + "; ".join(why) + "\n\n") if tier < 3 else "")
                + "## Next steps to a filable terminal\n" + "\n".join(f"{i + 1}. {n}" for i, n in enumerate(nxt))
                + "\n\n## Requests (raw bytes in raw/)\n| tag | url | status | length |\n|---|---|---|---|\n"
                + "\n".join(log) + "\n")
    rec = {"ts": now(), "program": program, "url": url, "tier": tier, "verdict": verdict,
           "secrets": len(sec), "pii": pii, "internal": len(inte), "id_keyed": id_keyed,
           "dir": os.path.relpath(edir, WS)}
    with open(os.path.join(ORCH, "escalations.jsonl"), "a") as f:
        f.write(json.dumps(rec) + "\n")
    if tier == 3:
        with open(os.path.join(ORCH, "INBOX.md"), "a") as f:
            f.write(f"- [{now()}] **EXPLOIT-CANDIDATE** {program} {url}: stable, credential-independent, carries "
                    f"{'secrets ' if sec else ''}{'personal data (' + ','.join(pii[:4]) + ')' if pii else ''}"
                    f"{'internal-network reach via URL param ' if ssrf_reach else ''}"
                    f"{' + id-keyed IDOR path' if id_keyed else ''} -> {os.path.relpath(edir, WS)}/ESCALATION.md\n")
    return verdict, os.path.relpath(edir, WS)


def pending_hits(program):
    """HIT rows from auto-exposure/STATUS.md not yet in escalations.jsonl."""
    sp = os.path.join(WS, "targets", program, "hunts", "auto-exposure", "STATUS.md")
    done = set()
    jl = os.path.join(ORCH, "escalations.jsonl")
    if os.path.isfile(jl):
        for ln in open(jl):
            try:
                done.add(json.loads(ln)["url"])
            except (ValueError, KeyError):
                pass
    urls = []
    if os.path.isfile(sp):
        for ln in open(sp, encoding="utf-8", errors="replace"):
            m = re.match(r"\| \S+ \| GET \| (\S+) \| 200 \| \d+b \|.*\bHIT\b", ln)
            if m and m.group(1) not in done and m.group(1) not in urls:
                urls.append(m.group(1))
    return urls


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    program = argv[0]
    os.makedirs(ORCH, exist_ok=True)
    if "--url" in argv:
        v, d = escalate(program, argv[argv.index("--url") + 1], "manual")
        print(f"{v}  {d}")
        return 0
    todo = pending_hits(program)
    if not todo:
        print(f"{program}: no un-escalated HITs")
        return 0
    for u in todo[: (len(todo) if "--all" in argv else 5)]:
        v, d = escalate(program, u)
        print(f"{v}  {u}  -> {d}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
