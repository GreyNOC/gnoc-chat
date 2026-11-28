#!/usr/bin/env python3
"""target_simhash - collapse clone / staging-twin hosts BEFORE modeling or probing (XBOW technique item 7).

We re-modelled the same target 24 times (one program) because nothing told the modeler that 30 hosts were
one app. This fingerprints each host's `/` once (through make_session, so scope applies) and clusters
hosts whose 64-bit SimHash is within Hamming distance 3. Model ONE representative per cluster.

    python3 scripts/bbtools/target_simhash.py dedup <program> [host ...]
    python3 scripts/bbtools/target_simhash.py selfcheck

    from bbtools.target_simhash import simhash, fingerprint_host, cluster
    simhash({"status": 200, "title": "Login", "content_type": "text/html", "body": html})  # int, 64 bit

Features: status, title, content-type, and 3-word shingles of the visible body text. Tags, script and
style bodies, digits, hex runs and long random-looking tokens (CSP nonces, csrf tokens, build hashes)
are stripped first, so two loads of the same page, or two staging twins, hash alike.
Clustering is single-link (union-find). Hosts that failed to fetch (status 0) are never merged.
Default host list: targets/<program>/recon/*hosts* (first token per line), else literal SCOPE.txt rows.
Output: targets/<program>/recon/simhash.json. Self-checks run offline (no network).
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from lib_scope import WS_ROOT, exact_hosts, extract_host, program_allows  # noqa: E402

BITS = 64
HAMMING = 3
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_DROP_BLOCKS = re.compile(r"<(script|style|noscript)\b.*?</\1\s*>", re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")
_HEX = re.compile(r"\b[0-9a-f]{6,}\b", re.I)
_DIGITS = re.compile(r"\d+")
_WORD = re.compile(r"[a-z][a-z'-]*")


def extract_title(body: str) -> str:
    m = _TITLE.search(body or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def normalize_words(body: str) -> list[str]:
    """Visible text words with nonces, hashes and numbers removed."""
    s = _DROP_BLOCKS.sub(" ", body or "")
    s = _TAGS.sub(" ", s)
    s = _HEX.sub(" ", s)
    s = _DIGITS.sub(" ", s)
    out = []
    for w in _WORD.findall(s.lower()):
        if len(w) >= 16 and not re.search(r"[aeiou]{1}.*[aeiou]", w):   # long vowel-poor token = random id
            continue
        out.append(w)
    return out


def _h64(s: str) -> int:
    return int.from_bytes(hashlib.md5(s.encode("utf-8", "replace")).digest()[:8], "big")


def simhash(resp: dict) -> int:
    """64-bit SimHash over (status, title, content-type, body 3-word shingles)."""
    body = resp.get("body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    title = resp.get("title")
    if title is None:
        title = extract_title(body)
    ctype = (resp.get("content_type") or "").split(";")[0].strip().lower()
    words = normalize_words(body)
    feats: list[tuple[str, int]] = [
        ("status:%s" % resp.get("status", 0), 4),
        ("title:%s" % " ".join(normalize_words(title)), 4),
        ("ctype:%s" % ctype, 2),
    ]
    if len(words) >= 3:
        feats += [("sh:" + " ".join(words[i:i + 3]), 1) for i in range(len(words) - 2)]
    else:
        feats += [("w:" + w, 1) for w in words]
    v = [0] * BITS
    for f, wt in feats:
        h = _h64(f)
        for i in range(BITS):
            v[i] += wt if (h >> i) & 1 else -wt
    return sum(1 << i for i in range(BITS) if v[i] > 0)


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def fingerprint_host(host: str, session, timeout: int = 15) -> dict:
    """Fetch `/` once through a scope-gated session. Never raises: failures give status 0."""
    url = "https://" + host + "/"
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        body = r.text if hasattr(r, "text") else (r.content or b"").decode("utf-8", "replace")
        ct = r.headers.get("content-type", "") if getattr(r, "headers", None) else ""
        resp = {"status": r.status_code, "content_type": ct, "body": body}
        return {"host": host, "status": r.status_code, "title": extract_title(body),
                "simhash": "%016x" % simhash(resp), "len": len(body)}
    except Exception as e:  # OutOfScope, DNS, TLS, timeout
        return {"host": host, "status": 0, "title": "", "simhash": None, "len": 0, "error": type(e).__name__}


def cluster(fps: list[dict], dist: int = HAMMING) -> list[list[dict]]:
    """Single-link clusters within Hamming `dist`. Failed fetches stay singletons."""
    n = len(fps)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    vals = [int(f["simhash"], 16) if f.get("simhash") else None for f in fps]
    for i in range(n):
        for j in range(i + 1, n):
            if vals[i] is not None and vals[j] is not None and hamming(vals[i], vals[j]) <= dist:
                parent[find(i)] = find(j)
    groups: dict[int, list[dict]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(fps[i])
    out = [sorted(g, key=lambda f: (len(f["host"]), f["host"])) for g in groups.values()]
    return sorted(out, key=lambda g: (-len(g), g[0]["host"]))


def default_hosts(program: str, root: str = WS_ROOT) -> list[str]:
    hosts: list[str] = []
    rd = os.path.join(root, "targets", program, "recon")
    if os.path.isdir(rd):
        for fn in sorted(os.listdir(rd)):
            if "hosts" in fn and os.path.isfile(os.path.join(rd, fn)) and not fn.endswith((".json", ".png")):
                for line in open(os.path.join(rd, fn), encoding="utf-8", errors="replace"):
                    t = line.strip().split()
                    h = extract_host(t[0]) if t and not t[0].startswith("#") else ""
                    if h and h not in hosts:
                        hosts.append(h)
    if not hosts:
        hosts = exact_hosts(program, root)
    return [h for h in hosts if program_allows(h, program, root=root)[0]]


def dedup(program: str, hosts: list[str] | None = None, root: str = WS_ROOT, session=None, workers: int = 8) -> dict:
    hosts = hosts or default_hosts(program, root)
    if session is None:
        from lib_egress import make_session
        session = make_session(os.path.join(root, "targets", program, "SCOPE.txt"))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fps = list(ex.map(lambda h: fingerprint_host(h, session), hosts))
    groups = cluster(fps)
    result = {"program": program, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "max_hamming": HAMMING,
              "hosts": len(fps), "clusters": [{"representative": g[0]["host"], "members": [f["host"] for f in g],
                                               "title": g[0]["title"], "status": g[0]["status"]} for g in groups],
              "fingerprints": fps}
    rd = os.path.join(root, "targets", program, "recon")
    os.makedirs(rd, exist_ok=True)
    with open(os.path.join(rd, "simhash.json"), "w") as fh:
        json.dump(result, fh, indent=1)
    return result


def selfcheck() -> None:
    import random
    def page(title, nonce, extra=""):
        return ("<html><head><title>%s</title><script nonce=\"%s\">var a=1;</script></head><body>"
                "<h1>Welcome to the partner portal</h1><p>Sign in with your corporate account to manage "
                "invoices, shipments and support tickets for your organisation across every region.</p>"
                "<form action=/login><input name=csrf value=\"%s\"></form><p>%s</p></body></html>" % (title, nonce, nonce, extra))
    a = {"status": 200, "content_type": "text/html; charset=utf-8", "body": page("Portal", "a1b2c3d4e5f60718")}
    b = {"status": 200, "content_type": "text/html", "body": page("Portal", "ffee00112233aabb99")}
    assert simhash(a) == simhash(b), "CSP-nonce variants must hash equal"
    c = {"status": 200, "content_type": "text/html", "body": page("Portal", "0123456789abcdef", "Staging environment build for internal testing only")}
    assert hamming(simhash(a), simhash(c)) <= HAMMING, "staging twin with a small diff must cluster"
    rnd = random.Random(7)
    vocab = "alpha river stone quantum ledger orbit willow garden cipher harbor maple engine falcon meadow signal pixel copper".split()
    docs = [{"status": 200, "content_type": "text/html", "body": "<title>Doc %d</title>" % k + " ".join(rnd.choice(vocab) for _ in range(120))}
            for k in range(6)]
    hs = [simhash(d) for d in docs]
    assert all(hamming(hs[i], hs[j]) > HAMMING for i in range(6) for j in range(i + 1, 6)), "distinct pages must not cluster"
    err = {"status": 404, "content_type": "text/html", "body": "<title>Not Found</title><p>nothing here</p>"}
    assert hamming(simhash(a), simhash(err)) > HAMMING, "app vs 404 must differ"
    fps = [{"host": "a.x.example", "simhash": "%016x" % simhash(a)}, {"host": "bb.x.example", "simhash": "%016x" % simhash(b)},
           {"host": "c.x.example", "simhash": "%016x" % simhash(err)}, {"host": "d.x.example", "simhash": None},
           {"host": "e.x.example", "simhash": None}]
    g = cluster(fps)
    assert [len(x) for x in g] == [2, 1, 1, 1] and g[0][0]["host"] == "a.x.example", g   # None never merges
    assert extract_title("<TITLE> A\n b </title>") == "A b"
    print("target_simhash SELFCHECK OK: nonce-strip + near-dup cluster + distinct-separate + failed-singleton ASSERTIONS PASS")


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "dedup":
        res = dedup(argv[1], argv[2:] or None)
        print("%s: %d hosts -> %d clusters (model ONE representative per cluster)" % (res["program"], res["hosts"], len(res["clusters"])))
        for c in res["clusters"]:
            print("  [%s] %s  (%s, %s)  +%d: %s" % (c["status"], c["representative"], c["title"][:40] or "no title",
                  len(c["members"]), len(c["members"]) - 1, ", ".join(c["members"][1:6])))
        print("written: targets/%s/recon/simhash.json" % res["program"])
        return 0
    if not argv or argv[0] == "selfcheck":
        selfcheck()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
