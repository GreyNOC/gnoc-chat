#!/usr/bin/env python3
"""lib_scope - one in-scope gate for every probe script.

Mirrors .claude/hooks/scope-gate.sh exactly (scope_inscope_hosts + host_in_scope)
so a script's in_scope() check and the live hook can never disagree. The retro
script-audit found ~160 ad-hoc scope parsers reimplementing this; import this instead.

    from bbtools.lib_scope import in_scope, extract_host
    if not in_scope(host, "targets/acme/SCOPE.txt"):
        print(f"OUT_OF_SCOPE {host}"); sys.exit(1)

ponytail: pure stdlib, no deps. The matching is security-relevant, so it carries a
demo() self-check (run `python3 lib_scope.py`) that fails loudly if the logic drifts.
"""
from __future__ import annotations
import ipaddress
import os
import re
from urllib.parse import urlparse

WS_ROOT = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Third-party platforms that appear in SCOPE.txt only so source code can be fetched (e.g. program-76 "Hosts
# needed to review them: github.com"). They are never the program's asset; no unattended caller may
# sweep them. Moved here from scripts/auto-hunt.py (2026-10-21) so every gate shares one copy.
THIRD_PARTY = re.compile(r"(^|\.)(github\.com|githubusercontent\.com|githubassets\.com|gitlab\.com|bitbucket\.org|"
                         r"npmjs\.(org|com)|pypi\.org|pythonhosted\.org|crates\.io|rubygems\.org|docker\.(io|com)|"
                         r"googleapis\.com|gstatic\.com|cloudfront\.net|amazonaws\.com|azureedge\.net|akamaihd\.net|"
                         r"cloudflare\.com|fastly\.net|jsdelivr\.net|unpkg\.com|hackerone\.com)$", re.I)

# Public suffixes / bare TLDs a scope entry must never be reduced to: matching a
# subdomain rule on these would fail-open every domain under the suffix. Mirror of
# the bash guard. Skipping them only removes ALLOW paths, so the failure is safe.
_PUBLIC_SUFFIX = {
    "app.example.com", "com.au", "com.co", "com.mx", "co.jp", "co.nz", "com.br", "co.in",
    "com.sg", "com.hk", "co.za", "com.tr", "gov.uk", "org.uk", "net.au", "org.au",
    "co.kr", "com.cn", "co.id", "com.ph", "com.my", "co.th", "com.tw", "ne.jp", "or.jp",
}

_OOS_RE = re.compile(
    r"^(out.?of.?scope|oos([^a-z0-9]|$)|exclud|ineligib|not\s+in\s+scope|do\s+not\s+test|forbidden|"
    r"not\s+eligible)",
    re.IGNORECASE,
)
_HOST_IN_LINE_RE = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}", re.IGNORECASE)
# a FILE NAME is not a host: the standard divider "# === OUT OF SCOPE (non-host asset types below; see PROGRAM.md) ==="
# read as an inline note naming a host, and every row after it was parsed as IN scope (QAQC r2: program-60, vandelay)
_FILE_NAME_RE = re.compile(r"\b[\w.-]+\.(md|txt|json|ya?ml|csv|pdf|html?|png|jpe?g|log|sh|py)\b", re.IGNORECASE)


def _names_a_host(line: str) -> bool:
    return bool(_HOST_IN_LINE_RE.search(_FILE_NAME_RE.sub(" ", line)))


def _strip_decor(s: str) -> str:
    """The text of a heading or note without its decoration: '#', '===', '**', '* ', '> ', '[ ]', ':'."""
    s = re.sub(r"^\s*#+\s*", "", s)
    s = re.sub(r"^[-=\s]+", "", s)
    s = re.sub(r"^(?:[>*\[\s]|\*\*)+", "", s)   # > quote, * bullet, ** bold, [ heading ]
    return s


def parse_scope(scope_file: str) -> list[str]:
    """In-scope host tokens: first token of each non-comment, non-blank line BEFORE
    the first genuine OUT-OF-SCOPE section divider (an OOS phrase line that does not
    itself name a host). Mirrors scope_inscope_hosts()."""
    out: list[str] = []
    try:
        with open(scope_file, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return out
    for raw in lines:
        is_comment = bool(re.match(r"^\s*#", raw))
        line = _strip_decor(raw)
        if _OOS_RE.match(line):
            if _names_a_host(line):
                continue  # inline OOS note that references a host -> not a divider
            break         # genuine divider -> ignore everything to EOF
        if is_comment or not raw.strip():
            continue
        cleaned = re.sub(r"\s*#.*$", "", raw).strip()
        if not cleaned:
            continue
        toks = re.split(r"\s+", cleaned)
        tok = toks[0]
        # H1 TABULAR FORMAT (fix 2026-10-02). Platform scope exports prefix each line with
        # the asset TYPE: "WILDCARD  *.foo.com\t[bounty; max=critical; added_16d_ago]".
        # Taking toks[0] yielded the keyword ("WILDCARD"), which has no dot and is refused
        # downstream, so EVERY host on a tabular scope file came back out-of-scope - the
        # python gate returned False for in-scope hosts and the bash hook blocked them.
        # An all-caps token with no dot can never be a hostname, so if toks[0] looks like an
        # asset-type keyword, the asset is the NEXT token. Enumerating no type list keeps this
        # correct for asset types the platforms add later.
        if len(toks) > 1 and re.fullmatch(r"[A-Z][A-Z0-9_]*", tok):
            atype, tok = tok, toks[1]
            if "://" in tok or "/" in tok:      # a URL-form asset -> reduce to its host
                tok = extract_host(tok) or tok
            # ASSET TYPE CARRIES THE SEMANTICS. Only WILDCARD authorises subdomains. A bare
            # domain on a URL/DOMAIN/API/IP row is EXACT-ONLY on HackerOne - treating it as an
            # apex would silently widen scope to every subdomain (caught by a regression test:
            # a URL-typed "furycloud.io" wrongly made "ci.furycloud.io" in-scope, and a worker
            # had correctly gate-refused exactly that host). Mark it exact-only with "=".
            if atype != "WILDCARD" and not tok.startswith("*"):
                tok = "=" + tok
        out.append(tok)
    return out


def host_in_scope(host: str, scope_file: str) -> bool:
    """True if host matches an in-scope entry. Mirrors host_in_scope():
    exact, subdomain (.suffix), wildcard-suffix (*foo.com), '=' exact-only marker;
    refuses bare-TLD / public-suffix-only entries."""
    if not host:
        return False
    lh = host.lower().strip().rstrip(".")
    for e in parse_scope(scope_file):
        e = e.lower().strip()
        if not e:
            continue
        exact_only = e.startswith("=")
        if exact_only:
            e = e[1:]
        ne = re.sub(r"^\*\.", "", e)
        ne = re.sub(r"^\*", "", ne)
        if not ne:
            continue
        if ne in _PUBLIC_SUFFIX:
            continue
        if "." not in ne:        # single label (bare TLD like "com"): refuse
            continue
        if lh == ne:
            return True
        if exact_only:
            continue
        if lh.endswith("." + ne):
            return True
        # WILDCARD FORM MATTERS (2026-09-30). Previously ANY '*' entry got a bare,
        # non-dot-bounded suffix match, so '*.target.example' also matched
        # 'eviltarget.example' / 'nottarget.example' - a DIFFERENT registrable domain,
        # possibly a third party's. '*.foo.com' is the most common scope line on every
        # platform, so that silently widened scope off-program. It is now dot-bounded
        # (handled by the lh == ne and lh.endswith("." + ne) cases above).
        # A bare '*foo.com' (no dot) keeps the loose suffix match: that form is a
        # deliberate glob for programs that write scope that way. Mirrors scope-gate.sh.
        if e.startswith("*") and not e.startswith("*.") and lh.endswith(ne):
            return True
    return False


def extract_host(url_or_host: str) -> str:
    """Best-effort host from a URL, host:port, or bare host."""
    s = (url_or_host or "").strip()
    # urlsplit SILENTLY DELETES \n, \r and \t from a URL (WHATWG), so "evil.test\nsub.good.example" became the
    # single host "evil.testsub.good.example" and matched a *.good.example row - while httpx, fed the same raw
    # string on stdin, read it as TWO lines and probed evil.test out of scope. Any embedded whitespace or
    # control byte means this is not one host: refuse it rather than guess which reader is right.
    if re.search(r"[\s\x00-\x1f\x7f]", s):
        return ""
    # a BARE IPv6 literal ("::1", "fe80::1%eth0") has no brackets: without this it became "" (no-host), and a
    # host already extracted once by a caller came back empty on the second pass.
    if "://" not in s and "/" not in s and s.count(":") >= 2 and not s.startswith("["):
        return _ipv6(s)
    if "://" not in s:
        # a protocol-relative URL is already two slashes; prefixing it again made the host vanish
        s = s if s.startswith("//") else "//" + s
    # urlparse RAISES ValueError on a bracketed non-IP ("[evil.test]") since Python 3.11; a raise inside a
    # mitmproxy hook let the flow CONTINUE (fail open, fix3 2026-10-23). A malformed host is "" (never matches).
    try:
        netloc = urlparse(s).netloc or ""
    except ValueError:
        return ""
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):              # IPv6 literal
        host, sep, rest = netloc[1:].partition("]")
        if not sep or (rest and not re.fullmatch(r":\d{0,5}", rest)):
            return ""
        return _ipv6(host)
    if "[" in netloc or "]" in netloc:
        return ""
    host = netloc.split(":", 1)[0].rstrip(".").lower()
    # a host is letters, digits, dots and hyphens, nothing else: "evil.test\nsub.good.example" once matched the
    # in-scope suffix after the newline, and a space / tab / CR did the same. Anything else is NOT a host,
    # and an empty host never matches a scope row.
    return host if re.fullmatch(r"[a-z0-9_.-]+", host) else ""


def _ipv6(h: str) -> str:
    """Compressed lowercase IPv6 (zone id dropped, %25 or %), or "" when it is not one."""
    h = re.split(r"%(25)?", h, maxsplit=1)[0]
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return ""
    return ip.compressed if ip.version == 6 else ""


def in_scope(host_or_url: str, scope_file: str) -> bool:
    """Public entry: accepts a bare host OR a URL."""
    h = host_or_url if ("://" not in host_or_url and "/" not in host_or_url) else extract_host(host_or_url)
    return host_in_scope(h, scope_file)


def _scope_paths(program: str, root: str) -> tuple[str, str]:
    d = os.path.join(root, "targets", program)
    return os.path.join(d, "SCOPE.txt"), os.path.join(d, "NOSCOPE.txt")


def program_allows(host_or_url: str, program: str, root: str = WS_ROOT) -> tuple[bool, str]:
    """The one gate for every UNATTENDED caller (auto-hunt, orch-bot, orch_brain, oss-bot).
    Decision order (fail closed): no-host -> internal-ip -> noscope -> (public IP: exact row only)
    -> third-party -> not-in-scope -> ok. NOSCOPE.txt uses the same host_in_scope semantics as the
    scope-gate hook (T-160), and is checked before any allow path."""
    host = extract_host(host_or_url or "").lower().rstrip(".")
    if not host:
        return False, "no-host"
    scope_f, noscope_f = _scope_paths(program, root)
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if ip is not None and getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped               # ::ffff:127.0.0.1 is 127.0.0.1
    if ip is not None and (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
                           or ip.is_multicast or ip.is_unspecified):
        return False, "internal-ip"
    if os.path.isfile(noscope_f) and host_in_scope(host, noscope_f):
        return False, "noscope"
    if ip is not None:
        rows = {e.lower().lstrip("=") for e in parse_scope(scope_f)}
        return (True, "ok") if host in rows else (False, "not-in-scope")
    if THIRD_PARTY.search(host):
        return False, "third-party"
    if not host_in_scope(host, scope_f):
        return False, "not-in-scope"
    return True, "ok"


def wildcard_apexes(program: str, root: str = WS_ROOT) -> list[str]:
    """Apex of each wildcard row (`*.x.y` / WILDCARD). Skips public suffixes, single labels and
    TLD-wildcards like `*.brand.*`. Used by passive enumeration only."""
    out: list[str] = []
    for e in parse_scope(_scope_paths(program, root)[0]):
        e = e.lower().strip()
        if not e.startswith("*"):
            continue
        apex = re.sub(r"^\*\.?", "", e)
        if not apex or "*" in apex or apex.endswith(".") or "." not in apex or apex in _PUBLIC_SUFFIX:
            continue
        if apex not in out:
            out.append(apex)
    return out


def exact_hosts(program: str, root: str = WS_ROOT) -> list[str]:
    """Non-wildcard host rows (the "=" exact-only marker stripped). A row list, NOT a gate: IP and
    third-party rows are returned too, so callers must filter through program_allows."""
    out: list[str] = []
    for e in parse_scope(_scope_paths(program, root)[0]):
        e = e.lower().strip().lstrip("=")
        if not e or e.startswith("*") or "." not in e or e in _PUBLIC_SUFFIX:
            continue
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", e):
            continue
        if e not in out:
            out.append(e)
    return out


def demo() -> None:
    import os, tempfile
    scope = """# program X
acmenft.io
api.acmenft.io
*.acmecdn.com
=acmefoods.com
# === OUT OF SCOPE ===
internal-corp.example
"""
    fd, path = tempfile.mkstemp(suffix="SCOPE.txt")
    os.write(fd, scope.encode()); os.close(fd)
    try:
        assert host_in_scope("acmenft.io", path)                      # exact
        assert host_in_scope("api.acmenft.io", path)                  # exact
        assert host_in_scope("sub.acmenft.io", path)                  # subdomain of apex
        assert host_in_scope("x.acmecdn.com", path)      # wildcard *.suffix
        assert host_in_scope("acmecdn.com", path)        # wildcard apex itself
        assert host_in_scope("acmefoods.com", path)                # = exact-only
        assert not host_in_scope("sub.acmefoods.com", path)        # = blocks subdomain
        assert not host_in_scope("internal-corp.example", path)   # distinct apex after OOS divider: not parsed
        assert host_in_scope("secret-internal.acmenft.io", path)      # NOTE: subdomain of in-scope apex matches even if OOS-listed (mirrors the hook)
        assert not host_in_scope("evil.com", path)                # not in scope
        assert not host_in_scope("notacmenft.io", path)               # suffix-trick must NOT match
        assert extract_host("https://user:pw@api.acmenft.io:443/x?y=1") == "api.acmenft.io"
    finally:
        os.unlink(path)

    # H1 TABULAR FORMAT self-check (regression guard for the 2026-10-02 fix).
    tab = ("# program Y\n"
           "URL            www.acmebook.com\t[bounty; max=critical; added_2478d_ago]\n"
           "WILDCARD       *.acmetravel.com\t[bounty; max=critical; added_16d_ago]\n"
           "APPLE_STORE_APP_ID com.foo.bar\t[bounty; max=critical]\n"
           "OTHER          Core Assets\t[bounty; max=critical]\n")
    fd, path = tempfile.mkstemp(suffix="SCOPE.txt")
    os.write(fd, tab.encode()); os.close(fd)
    try:
        assert host_in_scope("www.acmebook.com", path)      # URL-prefixed line
        assert host_in_scope("me.acmetravel.com", path)       # *.wildcard-prefixed line
        assert host_in_scope("acmetravel.com", path)          # wildcard apex
        assert not host_in_scope("evil.example", path)     # still refuses OOS
        assert not host_in_scope("notacmetravel.com", path)   # suffix-trick still refused
        assert not host_in_scope("WILDCARD", path)         # keyword never becomes an entry
        assert in_scope("https://me.acmetravel.com/me/gate.html", path)   # URL form on a tabular file
        assert not host_in_scope("sub.www.acmebook.com", path)   # URL-typed row is EXACT-ONLY
        assert host_in_scope("deep.sub.acmetravel.com", path)      # WILDCARD row allows subdomains
    finally:
        os.unlink(path)

    assert extract_host("api.acmenft.io") == "api.acmenft.io"
    assert extract_host("https://[::1]:8080/x") == "::1"
    # fix3 2026-10-23: malformed / bracketed hosts never raise, bare IPv6 survives a second pass
    assert extract_host("[evil.test]") == "" and extract_host("https://[evil.test]/x") == ""
    assert extract_host("[evil.test]:443") == "" and extract_host("api.acmenft.io]") == ""
    assert extract_host("[::ffff:127.0.0.1]") == "::ffff:127.0.0.1" and extract_host("::1") == "::1"
    assert extract_host("[fe80::1%25eth0]") == "fe80::1" and extract_host(extract_host("[2001:db8::1]")) == "2001:db8::1"

    # program_allows self-check (2026-10-21): NOSCOPE beats a wildcard allow, internal IPs refused even
    # when listed, third-party refused, public IP only on an exact row.
    root = tempfile.mkdtemp()
    try:
        d = os.path.join(root, "targets", "px")
        os.makedirs(d)
        with open(os.path.join(d, "SCOPE.txt"), "w") as fh:
            fh.write("WILDCARD *.acme.example\t[bounty]\n=www.acme.example\n10.1.2.3\n127.0.0.1\n"
                     "github.com\n203.0.113.9\n8.8.8.8\nWILDCARD *.app.example.com\nWILDCARD *.brand.*\nshop.other.example\n")
        with open(os.path.join(d, "NOSCOPE.txt"), "w") as fh:
            fh.write("=vpn.acme.example\n*.corp.acme.example\n")
        pa = lambda h: program_allows(h, "px", root=root)
        assert pa("[evil.test]") == (False, "no-host")
        assert pa("[::ffff:127.0.0.1]") == (False, "internal-ip") and pa("[fe80::1%25eth0]") == (False, "internal-ip")
        assert pa("api.acme.example") == (True, "ok")                       # wildcard allow
        assert pa("https://api.acme.example/x?y=1") == (True, "ok")         # URL form
        assert pa("vpn.acme.example") == (False, "noscope")                 # NOSCOPE beats the wildcard
        assert pa("x.corp.acme.example") == (False, "noscope")              # NOSCOPE wildcard deny
        assert pa("10.1.2.3") == (False, "internal-ip")                     # listed, still refused
        assert pa("127.0.0.1") == (False, "internal-ip")                    # listed, still refused
        assert pa("http://[::1]:8080/") == (False, "internal-ip")
        assert pa("169.254.169.254") == (False, "internal-ip")
        assert pa("github.com") == (False, "third-party")                   # listed, third-party
        assert pa("raw.githubusercontent.com") == (False, "third-party")
        assert pa("8.8.8.8") == (True, "ok")                                # public IP on an exact row
        assert pa("8.8.4.4") == (False, "not-in-scope")                     # public IP not listed
        assert pa("") == (False, "no-host")
        assert pa("evil.example") == (False, "not-in-scope")
        assert pa("notacme.example") == (False, "not-in-scope")
        assert program_allows("api.acme.example", "missing-prog", root=root) == (False, "not-in-scope")
        assert wildcard_apexes("px", root=root) == ["acme.example"]         # public suffix + TLD-wildcard skipped
        assert exact_hosts("px", root=root) == ["www.acme.example", "10.1.2.3", "127.0.0.1", "github.com",
                                                "203.0.113.9", "8.8.8.8", "shop.other.example"]
        # exact_hosts is a row list, not a gate: callers filter it through program_allows
        assert [h for h in exact_hosts("px", root=root) if pa(h)[0]] == [
            "www.acme.example", "8.8.8.8", "shop.other.example"]   # 203.0.113.9 = TEST-NET, internal-ip
        assert pa("203.0.113.9") == (False, "internal-ip")
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)
    print("lib_scope demo: ALL ASSERTIONS PASS")


if __name__ == "__main__":
    demo()
