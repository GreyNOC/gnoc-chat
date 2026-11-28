#!/usr/bin/env python3
"""
lib_jsintel.py - Obfuscated JS secret/endpoint analysis helper for the the workspace workspace.

Public API:
    jsintel(url_or_host, scope_file, session=None) -> dict
        Scope-gate, fetch page + linked JS bundles, beautify/deobfuscate,
        extract and rank secrets / envvars / endpoints / sourcemaps.

    _selfcheck()
        Assert-based offline self-test. PASS with no network.

CLI:
    python3 lib_jsintel.py <url> --scope SCOPE.txt
    python3 lib_jsintel.py selfcheck

FALSIFIABLE RULE (baked in):
    Every secret hit is annotated LEAD-UNCONFIRMED.
    A static hit is NOT a finding until a live API call or runtime execution confirms it.

Authorized defensive research only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import os
from typing import Optional
from urllib.parse import urljoin, urlparse

# ---------------------------------------------------------------------------
# Optional heavy imports (graceful degradation)
# ---------------------------------------------------------------------------
try:
    import jsbeautifier as _jsb
    _HAS_JSBEAUTIFIER = True
except ImportError:
    _HAS_JSBEAUTIFIER = False

# ---------------------------------------------------------------------------
# Secret patterns (annotated LEAD-UNCONFIRMED by design)
# Each tuple: (label, compiled_regex)
# ---------------------------------------------------------------------------
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("google_api_key",      re.compile(r'AIza[0-9A-Za-z_\-]{35}')),
    ("aws_access_key",      re.compile(r'AKIA[0-9A-Z]{16}')),
    ("stripe_live_secret",  re.compile(r'sk_live_[0-9A-Za-z]{24,}')),
    ("stripe_live_pub",     re.compile(r'pk_live_[0-9A-Za-z]{24,}')),
    ("github_pat",          re.compile(r'gh[pousr]_[0-9A-Za-z]{36,}')),
    ("slack_token",         re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}')),
    ("jwt",                 re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+')),
    ("pem_private_key",     re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
    ("client_secret",       re.compile(r'(?i)client[_\-]?secret\s*[=:]\s*["\']([^"\']{8,})["\']')),
    ("api_key",             re.compile(r'(?i)api[_\-]?key\s*[=:]\s*["\']([^"\']{8,})["\']')),
    ("auth_bearer",         re.compile(r'(?i)authorization\s*[=:]\s*["\']bearer\s+([A-Za-z0-9\-._~+/]{20,})["\']')),
]

# ---------------------------------------------------------------------------
# Env/config patterns
# ---------------------------------------------------------------------------
_ENV_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("process_env",    re.compile(r'process\.env\.([A-Z_][A-Z0-9_]{2,})')),
    ("window_env",     re.compile(r'window\.__ENV__\s*[=\[{]')),
    ("next_data",      re.compile(r'__NEXT_DATA__')),
    ("nuxt_data",      re.compile(r'window\.__NUXT__')),
    ("inline_config",  re.compile(r'(?:window|globalThis)\.[a-zA-Z_$][a-zA-Z0-9_$]*Config\s*=\s*\{')),
    ("remix_context",  re.compile(r'window\.__remixContext')),
]

# ---------------------------------------------------------------------------
# Endpoint patterns
# ---------------------------------------------------------------------------
_ENDPOINT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("fetch_url",    re.compile(r'fetch\s*\(\s*["\'](\S+?)["\']')),
    ("axios_url",    re.compile(r'axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*["\'](\S+?)["\']')),
    ("xhr_open",     re.compile(r'\.open\s*\(\s*["\'][A-Z]+["\'],\s*["\'](\S+?)["\']')),
    ("api_path",     re.compile(r'["\`](/(?:api|v[0-9]+|graphql|gql|rest|internal|auth|oauth|admin)[^\s"\'`<>,;)]{1,100})["\`]')),
    ("graphql_ep",   re.compile(r'["\`]((?:https?://\S+)?/graphql(?:/\S*)?)["\`]')),
]

# ---------------------------------------------------------------------------
# Source-map pattern
# ---------------------------------------------------------------------------
_SOURCEMAP_RE = re.compile(r'//# sourceMappingURL=(\S+)')

# ---------------------------------------------------------------------------
# Common packer pattern (eval-based p,a,c,k,e,d)
# ---------------------------------------------------------------------------
_PACKER_RE = re.compile(
    r"eval\s*\(function\s*\(p,a,c,k,e,[dr]\)",
    re.IGNORECASE,
)


def _beautify(js_text: str) -> str:
    """Return beautified JS. Falls back to regex whitespace normalisation."""
    if _HAS_JSBEAUTIFIER:
        opts = _jsb.default_options()
        opts.indent_size = 2
        opts.max_preserve_newlines = 2
        return _jsb.beautify(js_text, opts)
    # Minimal regex unpacker for eval(function(p,a,c,k,e,d){...}) packer pattern
    if _PACKER_RE.search(js_text):
        # Cannot safely unpack without execution; mark it and return as-is
        return "/* LIB_JSINTEL: packed/eval packer detected - beautify manually */\n" + js_text
    # Basic whitespace normalisation so regex hits work across concat literals
    js_text = re.sub(r'([{};,])', r'\1\n', js_text)
    return js_text


def _extract_js_urls(html: str, base_url: str, limit: int = 40) -> list[str]:
    """Absolute bundle URLs: <script src=...> tags first, then every .js URL written in the page text (an SPA
    shell that injects its bundles from inline JS has NO script tags - ads/app.example.com, 2026-10-23)."""
    urls: list[str] = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
        urls.append(urljoin(base_url, m.group(1)))
    for m in re.finditer(r'(?:https?:)?//[A-Za-z0-9.-]+(?:/[^"\'\s<>()]*)?/[^"\'\s<>()/]+\.js(?=["\'\s<>()?]|$)', html):
        urls.append(urljoin(base_url, m.group(0)))
    out: list[str] = []
    for u in urls:
        if u not in out:
            out.append(u)
    return out[:limit]


def asset_hosts(scope_file: str) -> set[str]:
    """Hosts listed in ASSET-HOSTS.txt beside SCOPE.txt: the program's own static CDN (program-101: static.kwcdn.com,
    bstatic.kwcdn.com). A bundle referenced by an in-scope page may be READ (GET, .js only) from one of them; the
    file is the operator's switch, no code adds to it."""
    try:
        f = os.path.join(os.path.dirname(os.path.abspath(scope_file)), "ASSET-HOSTS.txt")
        with open(f, encoding="utf-8") as fh:
            return {ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def _extract_hits(js_text: str, source_label: str) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """
    Run all pattern sets against beautified JS text.
    Returns (secrets, envvars, endpoints, sourcemaps) each as list of dicts.
    """
    secrets: list[dict] = []
    envvars: list[dict] = []
    endpoints: list[dict] = []
    sourcemaps: list[dict] = []

    lines = js_text.splitlines()

    def _context(lineno: int) -> str:
        start = max(0, lineno - 1)
        end = min(len(lines), lineno + 2)
        return " | ".join(lines[start:end]).strip()[:200]

    # Secrets
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(js_text):
            lineno = js_text[:m.start()].count("\n")
            secrets.append({
                "type": label,
                "match": m.group(0)[:120],
                "source": source_label,
                "line": lineno + 1,
                "context": _context(lineno),
                "status": "LEAD-UNCONFIRMED",
                "note": "Static hit only. Confirm with a live API call before treating as a finding.",
            })

    # Envvars
    for label, pat in _ENV_PATTERNS:
        for m in pat.finditer(js_text):
            lineno = js_text[:m.start()].count("\n")
            envvars.append({
                "type": label,
                "match": m.group(0)[:120],
                "source": source_label,
                "line": lineno + 1,
                "context": _context(lineno),
            })

    # Endpoints
    seen_eps: set[str] = set()
    for label, pat in _ENDPOINT_PATTERNS:
        for m in pat.finditer(js_text):
            ep = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
            ep = ep[:200]
            if ep in seen_eps:
                continue
            seen_eps.add(ep)
            lineno = js_text[:m.start()].count("\n")
            endpoints.append({
                "type": label,
                "endpoint": ep,
                "source": source_label,
                "line": lineno + 1,
                "context": _context(lineno),
            })

    # Source maps
    for m in _SOURCEMAP_RE.finditer(js_text):
        lineno = js_text[:m.start()].count("\n")
        sourcemaps.append({
            "url": m.group(1),
            "source": source_label,
            "line": lineno + 1,
        })

    return secrets, envvars, endpoints, sourcemaps


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def jsintel(
    url_or_host: str,
    scope_file: str,
    session=None,
) -> dict:
    """
    Scope-gate, fetch page + linked JS bundles, beautify/deobfuscate, extract
    and rank secrets / envvars / endpoints / sourcemaps.

    Parameters
    ----------
    url_or_host : str
        A full URL (https://...) or bare hostname.
    scope_file : str
        Path to SCOPE.txt for this program.
    session : optional
        A pre-built ScopedSession (lib_egress.make_session). Created internally if None.

    Returns
    -------
    dict with keys:
        secrets      list[dict]   - LEAD-UNCONFIRMED hits
        envvars      list[dict]   - env/config blob hits
        endpoints    list[dict]   - extracted URL/path literals
        sourcemaps   list[dict]   - //# sourceMappingURL hits
        bundles_seen list[str]    - JS bundle URLs fetched
        errors       list[str]    - fetch errors, non-blocking
    """
    # Normalise to URL
    if not url_or_host.startswith("http"):
        url_or_host = "https://" + url_or_host

    # Scope-gate: import here to avoid hard dep if used as a library
    try:
        from lib_scope import in_scope
    except ImportError:
        from bbtools.lib_scope import in_scope  # type: ignore[no-redef]

    host = urlparse(url_or_host).netloc.split(":")[0]
    if not in_scope(host, scope_file):
        raise ValueError(f"OUT_OF_SCOPE: {host} not in {scope_file}")

    # Build session if not provided
    if session is None:
        try:
            from lib_egress import make_session
        except ImportError:
            from bbtools.lib_egress import make_session  # type: ignore[no-redef]
        session = make_session(scope_file)

    all_secrets: list[dict] = []
    all_envvars: list[dict] = []
    all_endpoints: list[dict] = []
    all_sourcemaps: list[dict] = []
    bundles_seen: list[str] = []
    errors: list[str] = []

    def _fetch(url: str) -> Optional[str]:
        try:
            r = session.get(url, timeout=15)
            if hasattr(r, "text"):
                return r.text
            if hasattr(r, "content"):
                return r.content.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"fetch {url}: {exc}")
        return None

    # Step 1: fetch the root page
    root_html = _fetch(url_or_host) or ""

    # Step 2: discover JS bundle URLs from <script src>
    js_urls = _extract_js_urls(root_html, url_or_host)

    # Step 3: scope-filter discovered bundle URLs; a listed asset host is read through an UNGATED session, GET only,
    # .js only (the gated session would refuse the host)
    scoped_js_urls: list[str] = []
    assets = asset_hosts(scope_file)
    asset_session = None
    for u in js_urls:
        h = urlparse(u).netloc.split(":")[0].lower()
        if in_scope(h, scope_file):
            scoped_js_urls.append(u)
        elif h in assets and urlparse(u).path.lower().endswith(".js"):
            scoped_js_urls.append(u)
            if asset_session is None:
                try:
                    from lib_egress import make_session as _ms
                except ImportError:
                    from bbtools.lib_egress import make_session as _ms  # type: ignore[no-redef]
                asset_session = _ms(None)
        else:
            errors.append(f"OUT_OF_SCOPE bundle skipped: {u} (add {h} to ASSET-HOSTS.txt beside SCOPE.txt if it is the "
                          "program's own static CDN)")

    # Step 4: also mine inline <script> blocks from the root page
    inline_blocks = re.findall(
        r'<script(?![^>]+src=)[^>]*>(.*?)</script>',
        root_html,
        re.DOTALL | re.IGNORECASE,
    )
    for idx, block in enumerate(inline_blocks):
        if len(block.strip()) < 20:
            continue
        beautified = _beautify(block)
        s, e, ep, sm = _extract_hits(beautified, f"inline-script-{idx}:{url_or_host}")
        all_secrets.extend(s)
        all_envvars.extend(e)
        all_endpoints.extend(ep)
        all_sourcemaps.extend(sm)

    # Step 5: fetch + analyse each in-scope (or listed-asset-host) JS bundle
    for js_url in scoped_js_urls:
        jh = urlparse(js_url).netloc.split(":")[0].lower()
        if asset_session is not None and jh in assets and not in_scope(jh, scope_file):
            try:
                r = asset_session.get(js_url, timeout=15)
                js_text = r.text if hasattr(r, "text") else r.content.decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"fetch {js_url}: {exc}")
                js_text = None
        else:
            js_text = _fetch(js_url)
        if not js_text:
            continue
        bundles_seen.append(js_url)
        beautified = _beautify(js_text)
        s, e, ep, sm = _extract_hits(beautified, js_url)
        all_secrets.extend(s)
        all_envvars.extend(e)
        all_endpoints.extend(ep)
        all_sourcemaps.extend(sm)

    # Step 6: de-duplicate endpoints by (type, endpoint)
    seen_ep_keys: set[tuple] = set()
    deduped_eps: list[dict] = []
    for ep in all_endpoints:
        key = (ep["type"], ep["endpoint"])
        if key not in seen_ep_keys:
            seen_ep_keys.add(key)
            deduped_eps.append(ep)

    return {
        "secrets":      all_secrets,
        "envvars":      all_envvars,
        "endpoints":    deduped_eps,
        "sourcemaps":   all_sourcemaps,
        "bundles_seen": bundles_seen,
        "errors":       errors,
    }


# ---------------------------------------------------------------------------
# Offline self-check (assert-based, no network)
# ---------------------------------------------------------------------------

def _selfcheck() -> None:
    """Assert-based offline self-check. PASS with no network required.

    Checks:
    1. Scope gate refuses an off-scope host.
    2. Beautify runs (with or without jsbeautifier).
    3. Secret extraction finds the planted AIza key and JWT.
    4. Endpoint extraction finds the planted fetch("/api/secret") URL.
    5. Sourcemap extraction finds the planted //# sourceMappingURL.
    6. Envvar extraction finds process.env.SECRET_KEY.
    7. LEAD-UNCONFIRMED annotation is present on every secret hit.
    8. Packed JS is detected and flagged (fallback path).
    """

    # ---- Plant the inline fake JS ----
    FAKE_JS = r"""
var apiKey = "AIza1234567890abcdefghijklmnopqrstuvwxyz";
var tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
fetch("/api/secret");
//# sourceMappingURL=app.js.map
process.env.SECRET_KEY;
""".strip()

    # ---- Scope fixture ----
    scope_content = "target.example.com\n*.target.example.com\n"
    fd, scope_path = tempfile.mkstemp(suffix="_SCOPE.txt")
    os.write(fd, scope_content.encode())
    os.close(fd)

    try:
        # 1. Scope gate refuses off-scope host
        try:
            from lib_scope import in_scope
        except ImportError:
            from bbtools.lib_scope import in_scope  # type: ignore[no-redef]

        assert not in_scope("evil.com", scope_path), \
            "FAIL: scope gate allowed evil.com"
        assert not in_scope("target.example.com.evil.com", scope_path), \
            "FAIL: scope gate allowed suffix-trick domain"
        assert in_scope("target.example.com", scope_path), \
            "FAIL: scope gate blocked in-scope host"
        assert in_scope("api.target.example.com", scope_path), \
            "FAIL: scope gate blocked wildcard subdomain"

        # 2. Beautify runs without error
        beautified = _beautify(FAKE_JS)
        assert isinstance(beautified, str) and len(beautified) > 0, \
            "FAIL: _beautify returned empty/non-string"

        # 3+4+5+6. Extract from planted JS
        secrets, envvars, endpoints, sourcemaps = _extract_hits(beautified, "selfcheck-inline")

        # Secret: AIza key
        aiza_hits = [s for s in secrets if s["type"] == "google_api_key"]
        assert aiza_hits, \
            f"FAIL: AIza key not found in secrets. Got: {[s['match'] for s in secrets]}"

        # Secret: JWT
        jwt_hits = [s for s in secrets if s["type"] == "jwt"]
        assert jwt_hits, \
            f"FAIL: JWT not found in secrets. Got: {[s['match'] for s in secrets]}"

        # All secret hits must be LEAD-UNCONFIRMED
        for s in secrets:
            assert s.get("status") == "LEAD-UNCONFIRMED", \
                f"FAIL: secret hit missing LEAD-UNCONFIRMED annotation: {s}"

        # Endpoint: /api/secret
        ep_values = [e["endpoint"] for e in endpoints]
        assert any("/api/secret" in ep for ep in ep_values), \
            f"FAIL: /api/secret endpoint not found. Got: {ep_values}"

        # Sourcemap
        sm_urls = [sm["url"] for sm in sourcemaps]
        assert any("app.js.map" in u for u in sm_urls), \
            f"FAIL: sourceMappingURL not found. Got: {sm_urls}"

        # Envvar
        env_types = [e["type"] for e in envvars]
        assert "process_env" in env_types, \
            f"FAIL: process.env not found in envvars. Got: {env_types}"

        # 7. Packed JS detection (fallback path, no jsbeautifier)
        packed_js = "eval(function(p,a,c,k,e,d){return 'packed'})"
        result = _beautify(packed_js)
        if not _HAS_JSBEAUTIFIER:
            assert "packed/eval packer detected" in result, \
                "FAIL: packed JS not flagged in fallback path"

        print("PASS: all selfcheck assertions passed")
        print(f"  jsbeautifier available: {_HAS_JSBEAUTIFIER}")
        print(f"  secrets found: {len(secrets)} (AIza + JWT both present)")
        print(f"  endpoints found: {len(endpoints)}")
        print(f"  sourcemaps found: {len(sourcemaps)}")
        print(f"  envvars found: {len(envvars)}")
        print("  scope gate: evil.com blocked, target.example.com allowed")

    finally:
        os.unlink(scope_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "selfcheck":
        _selfcheck()
        return

    parser = argparse.ArgumentParser(
        description="JS intelligence extractor. Scope-gated, beautify+deobfuscate, ranked secrets/endpoints."
    )
    parser.add_argument("url", help="Target URL or hostname (must be in scope)")
    parser.add_argument("--scope", required=True, metavar="SCOPE.txt",
                        help="Path to program SCOPE.txt")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of human summary")
    args = parser.parse_args()

    result = jsintel(args.url, args.scope)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\n=== jsintel: {args.url} ===")
    print(f"Bundles fetched : {len(result['bundles_seen'])}")
    for u in result["bundles_seen"]:
        print(f"  {u}")

    print(f"\nSecrets [{len(result['secrets'])}] (all LEAD-UNCONFIRMED - confirm with live call):")
    for s in result["secrets"]:
        print(f"  [{s['type']}] line {s['line']} in {s['source']}")
        print(f"    match   : {s['match'][:80]}")
        print(f"    context : {s['context'][:100]}")

    print(f"\nEnvvars / config [{len(result['envvars'])}]:")
    for e in result["envvars"]:
        print(f"  [{e['type']}] line {e['line']} in {e['source']}")
        print(f"    {e['match'][:100]}")

    print(f"\nEndpoints [{len(result['endpoints'])}]:")
    for ep in result["endpoints"]:
        print(f"  [{ep['type']}] {ep['endpoint']}")

    print(f"\nSource maps [{len(result['sourcemaps'])}]:")
    for sm in result["sourcemaps"]:
        print(f"  {sm['url']}  (in {sm['source']} line {sm['line']})")

    if result["errors"]:
        print(f"\nErrors [{len(result['errors'])}]:")
        for err in result["errors"]:
            print(f"  {err}")


if __name__ == "__main__":
    _cli_main()
