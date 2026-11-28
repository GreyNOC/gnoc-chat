"""gnoc_sec.py - the security toolbox gnoc chat drives: code review scanners, scoped recon, JS mining, decoding.

Every result is a LEAD to confirm, never a finding (Manual T-45: a static hit is not a finding until a live
request or a run proves it). Network-touching helpers take a `gate(url) -> (policy, error)` callable from the agent
(scope + program policy) and filter EVERY discovered host through it in code before anything is probed.

    sast(path)                 semgrep (security rulesets) + gitleaks (secrets) + npm audit when a lockfile exists
    recon(program, gate, ...)  subfinder (passive) -> in-scope filter -> httpx (rate-limited) [-> katana on 1 host]
    js_mine(url, scope_file)   endpoints, secret candidates, source maps from a page's JS bundles (lib_jsintel)
    decode(text)               JWT / base64 / base64url / URL / hex / HTML entities, JWT alg + claims + expiry
"""
import base64
import binascii
import html
import json
import os
import re
import shutil
import subprocess
import urllib.parse
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_stamp as _now

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GO = os.path.expanduser("~/go/bin")
SEMGREP_RULESETS = ("p/security-audit", "p/secrets", "p/owasp-top-ten")


def _bin(name):
    p = shutil.which(name) or os.path.join(GO, name)
    return p if os.path.isfile(p) else None




# ---------------------------------------------------------------- code review

def semgrep(path, timeout=900):
    exe = _bin("semgrep")
    if not exe:
        return None, "semgrep not installed"
    args = [exe, "scan", "--json", "--quiet", "--metrics=off", "--timeout", "30"]
    for r in SEMGREP_RULESETS:
        args += ["--config", r]
    pr = subprocess.run(args + [path], capture_output=True, text=True, timeout=timeout)
    try:
        d = json.loads(pr.stdout or "{}")
    except ValueError:
        return None, f"semgrep failed: {(pr.stderr or pr.stdout)[-300:]}"
    rows = []
    for r in d.get("results", []):
        ex = r.get("extra", {})
        if not ex.get("lines") or "requires login" in ex.get("lines", ""):
            try:  # the free CLI hides the matched line; read it from the file
                ln = r.get("start", {}).get("line") or 0
                with open(r.get("path"), encoding="utf-8", errors="replace") as fh:
                    ex["lines"] = fh.read().splitlines()[ln - 1]
            except (OSError, IndexError, TypeError):
                ex["lines"] = ""
        rows.append({"tool": "semgrep", "sev": ex.get("severity", "?"), "rule": r.get("check_id", "").split(".")[-1],
                     "file": r.get("path"), "line": r.get("start", {}).get("line"),
                     "msg": " ".join((ex.get("message") or "").split())[:200],
                     "code": " ".join((ex.get("lines") or "").split())[:160],
                     "cwe": ",".join((ex.get("metadata") or {}).get("cwe", []) or [])[:60]})
    return rows, ""


def gitleaks(path, timeout=600):
    exe = _bin("gitleaks")
    if not exe:
        return None, "gitleaks not installed"
    # a private directory, not a predictable /tmp name another local user could pre-create as a symlink (bandit B108)
    import shutil
    import tempfile
    tmpd = tempfile.mkdtemp(prefix="gnoc-gitleaks-")
    out = os.path.join(tmpd, "report.json")
    subprocess.run([exe, "detect", "--no-git", "--no-banner", "-s", path, "--report-format", "json",
                    "--report-path", out, "--redact"], capture_output=True, text=True, timeout=timeout)
    try:
        with open(out) as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        d = []
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)
    return [{"tool": "gitleaks", "sev": "SECRET", "rule": f.get("RuleID"), "file": f.get("File"),
             "line": f.get("StartLine"), "msg": f.get("Description", "")[:160], "code": "(value redacted)",
             "cwe": "CWE-798"} for f in d or []], ""


def npm_audit(path, timeout=300):
    if not (os.path.isfile(os.path.join(path, "package-lock.json")) and _bin("npm")):
        return [], ""
    pr = subprocess.run([_bin("npm"), "audit", "--json", "--omit=dev"], cwd=path, capture_output=True, text=True,
                        timeout=timeout)
    try:
        vulns = json.loads(pr.stdout or "{}").get("vulnerabilities", {})
    except ValueError:
        return [], "npm audit output unreadable"
    rows = []
    for name, v in vulns.items():
        via = [x for x in v.get("via", []) if isinstance(x, dict)]
        rows.append({"tool": "npm-audit", "sev": v.get("severity", "?").upper(), "rule": name,
                     "file": "package-lock.json", "line": None,
                     "msg": (via[0].get("title") if via else "vulnerable dependency")[:160],
                     "code": v.get("range", ""), "cwe": ",".join((via[0].get("cwe") or []) if via else [])})
    return rows, ""


SEV_RANK = {"SECRET": 0, "CRITICAL": 1, "ERROR": 2, "HIGH": 2, "WARNING": 3, "MODERATE": 3, "MEDIUM": 3,
            "INFO": 4, "LOW": 4}


def sast(path, which=("semgrep", "gitleaks", "npm")):
    rows, notes = [], []
    for name, fn in (("semgrep", semgrep), ("gitleaks", gitleaks), ("npm", npm_audit)):
        if name not in which:
            continue
        got, err = fn(path)
        if err:
            notes.append(err)
        rows += got or []
    rows.sort(key=lambda r: (SEV_RANK.get(str(r["sev"]).upper(), 5), r["file"] or "", r["line"] or 0))
    return rows, notes


def sast_text(rows, notes, root, limit=60):
    if not rows:
        return "no scanner hits" + (f" ({'; '.join(notes)})" if notes else "")
    by = {}
    for r in rows:
        by[r["tool"]] = by.get(r["tool"], 0) + 1
    out = [f"{len(rows)} scanner hits ({', '.join(f'{k} {v}' for k, v in by.items())}). Each is a LEAD: read the "
           "code path and prove reachability before calling it a bug."]
    for r in rows[:limit]:
        f = os.path.relpath(r["file"], root) if r["file"] and os.path.isabs(r["file"]) else r["file"]
        out.append(f"[{r['sev']}] {r['tool']}:{r['rule']}  {f}:{r['line'] or '-'}  {r['msg']}"
                   + (f"  ({r['cwe']})" if r.get("cwe") else "") + (f"\n      {r['code']}" if r.get("code") else ""))
    if len(rows) > limit:
        out.append(f"... {len(rows) - limit} more")
    return "\n".join(out + ([f"notes: {'; '.join(notes)}"] if notes else []))


# ---------------------------------------------------------------- recon (scope enforced in code)

def recon(program, gate, domain, crawl=None, rps=5, timeout=900):
    """Passive subdomains of `domain`, kept only where gate() allows, probed live with httpx at <= rps; optionally a
    shallow katana crawl of ONE allowed URL. Everything is written under targets/<program>/recon/gnoc-<ts>/."""
    out = os.path.join(WS, "targets", program, "recon", f"gnoc-{_now()}")
    os.makedirs(out, exist_ok=True)
    pol, err = gate(f"https://{domain}/")
    if err:
        return f"recon refused for {domain}: {err}"
    summary = []
    hosts = {domain}
    if _bin("subfinder"):
        pr = subprocess.run([_bin("subfinder"), "-d", domain, "-silent", "-all"], capture_output=True, text=True,
                            timeout=timeout)
        hosts |= {h.strip().lower() for h in pr.stdout.split() if h.strip()}
    allowed = sorted(h for h in hosts if not gate(f"https://{h}/")[1])
    dropped = len(hosts) - len(allowed)
    with open(os.path.join(out, "subdomains-all.txt"), "w") as fh:
        fh.write("\n".join(sorted(hosts)) + "\n")
    with open(os.path.join(out, "in-scope.txt"), "w") as fh:
        fh.write("\n".join(allowed) + "\n")
    summary.append(f"subfinder: {len(hosts)} names, {len(allowed)} in scope ({dropped} dropped by the scope/policy "
                   "gate)")
    live = []
    if allowed and _bin("httpx"):
        rate = max(1, min(int(rps or 5), int(float(pol.get("rps") or rps or 5))))
        pr = subprocess.run([_bin("httpx"), "-silent", "-json", "-rl", str(rate), "-t", "10", "-timeout", "8",
                             "-sc", "-title", "-td", "-cl", "-fr", "-no-color"],
                            input="\n".join(allowed), capture_output=True, text=True, timeout=timeout)
        for ln in pr.stdout.splitlines():
            try:
                live.append(json.loads(ln))
            except ValueError:
                pass
        with open(os.path.join(out, "httpx.jsonl"), "w") as f:
            f.write(pr.stdout)
        summary.append(f"httpx ({rate} req/s): {len(live)} live")
    for r in sorted(live, key=lambda r: (r.get("status_code") or 999, r.get("url") or ""))[:60]:
        tech = ",".join((r.get("tech") or [])[:4])
        summary.append(f"  {r.get('status_code')} {r.get('url')}  {str(r.get('title') or '')[:50]!r}  "
                       f"len={r.get('content_length')}{'  ' + tech if tech else ''}")
    if crawl:
        pol2, err2 = gate(crawl)
        if err2:
            summary.append(f"crawl refused: {err2}")
        elif _bin("katana"):
            host = urllib.parse.urlsplit(crawl).hostname
            pr = subprocess.run([_bin("katana"), "-u", crawl, "-d", "2", "-jc", "-silent", "-rl", "5", "-c", "5",
                                 "-fs", "fqdn", "-timeout", "10"], capture_output=True, text=True, timeout=timeout)
            urls = sorted({u for u in pr.stdout.split() if urllib.parse.urlsplit(u).hostname == host})
            open(os.path.join(out, "katana.txt"), "w").write("\n".join(urls) + "\n")
            interesting = [u for u in urls if re.search(r"(api|graphql|admin|internal|debug|v\d/|\.json|\.map|"
                                                        r"upload|export|token|oauth|callback|redirect|webhook)", u, re.I)]
            summary.append(f"katana depth 2 on {host}: {len(urls)} URLs, {len(interesting)} interesting:")
            summary += [f"  {u}" for u in interesting[:40]]
    summary.append(f"files: {os.path.relpath(out, WS)}/")
    return "\n".join(summary)


# ---------------------------------------------------------------- JS mining

def js_mine(url, scope_file):
    from bbtools import lib_jsintel
    d = lib_jsintel.jsintel(url, scope_file)
    out = [f"bundles fetched: {len(d.get('bundles_seen', []))}"]
    for key, label in (("secrets", "SECRET CANDIDATES (unconfirmed: prove the key works against a vendor API)"),
                       ("sourcemaps", "SOURCE MAPS"), ("envvars", "CONFIG / ENV"), ("endpoints", "ENDPOINTS")):
        rows = d.get(key) or []
        if rows:
            out.append(f"{label}: {len(rows)}")
            for r in rows[:40 if key == "endpoints" else 15]:
                # the endpoint row's key is "endpoint": before 2026-10-23 the listing printed "type=api_path source=..."
                # with NO path, so every mined route was invisible to the model (program-101 launches #18-#20)
                out.append("  " + " ".join(f"{k}={str(v)[:120]}" for k, v in r.items() if k in
                                           ("endpoint", "value", "kind", "type", "path", "url", "source", "match", "name"))[:240])
    if d.get("errors"):
        out.append("errors: " + "; ".join(d["errors"][:5]))
    return "\n".join(out)


# ---------------------------------------------------------------- decoding

def _b64(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    for fn in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return fn(s + pad)
        except (binascii.Error, ValueError):
            continue
    return None


def _show(b):
    try:
        t = b.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in t):
            try:
                return json.dumps(json.loads(t), indent=1)[:3000]
            except ValueError:
                return t[:3000]
    except UnicodeDecodeError:
        pass
    return "hex " + b.hex()[:400]


def decode(text):
    t = (text or "").strip()
    out = []
    m = re.fullmatch(r"(?:Bearer\s+)?([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)", t)
    if m:
        head, body = _b64(m.group(1)), _b64(m.group(2))
        if head and body:
            try:
                h, c = json.loads(head), json.loads(body)
                out.append("JWT header: " + json.dumps(h))
                out.append("JWT claims: " + json.dumps(c, indent=1)[:3000])
                for k in ("exp", "iat", "nbf"):
                    if isinstance(c.get(k), (int, float)):
                        out.append(f"  {k} = {datetime.fromtimestamp(c[k], timezone.utc).isoformat()}")
                if str(h.get("alg", "")).lower() in ("none", ""):
                    out.append("  ! alg none: check whether the server accepts an unsigned token")
                if not m.group(3):
                    out.append("  ! empty signature segment")
                if h.get("jku") or h.get("x5u") or h.get("kid"):
                    out.append("  ! header names its key (jku/x5u/kid): key-confusion / injection surface")
                return "\n".join(out)
            except ValueError:
                pass
    if "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
        u = urllib.parse.unquote(t)
        out.append("URL-decoded: " + u[:3000])
        if re.search(r"%[0-9A-Fa-f]{2}", u):
            out.append("URL-decoded twice: " + urllib.parse.unquote(u)[:3000])
    if "&" in t and re.search(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", t, re.I):
        out.append("HTML-unescaped: " + html.unescape(t)[:3000])
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", t) and len(t) % 2 == 0 and len(t) >= 8:
        out.append("hex: " + _show(bytes.fromhex(t[2:] if t.startswith("0x") else t)))
    if re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", t) and len(t) >= 8:
        b = _b64(t)
        if b:
            out.append("base64: " + _show(b))
    if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", t.lower()):
        out.append({32: "looks like MD5", 40: "looks like SHA-1", 64: "looks like SHA-256"}[len(t)]
                   + " (or a random hex token): a hash is not decodable")
    return "\n".join(out) or "no known encoding recognised"
