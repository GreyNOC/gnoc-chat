#!/usr/bin/env python3
"""lib_egress - one scope-gated HTTP session for every probe script.

The retro script-audit found ~2087 curl_cffi rewrites + ~346 Cloudflare re-impls +
~1007 hardcoded sys.path.insert lines. This is the single helper they should all import.
The SCOPE GATE is baked into the session: every request is checked with lib_scope.in_scope
BEFORE the bytes leave, so an out-of-scope probe raises instead of silently happening
(the retro asked for the SPINE gates to be impossible to skip).

    from bbtools.lib_egress import make_session
    s = make_session("targets/acme/SCOPE.txt")          # chrome124 impersonation, scope-gated
    r = s.get("https://api.acmenft.io/graphql")               # OK (in scope)
    r = s.get("https://evil.com")                         # raises OutOfScope

    from bbtools.lib_egress import clear_cloudflare
    cookies = clear_cloudflare("acmenft.io")                  # Playwright managed-challenge solve

    # Route a worker's traffic THROUGH Burp's proxy so it lands in Burp proxy history +
    # scanner and the orchestrator can read it back via get_proxy_http_history (MCP).
    s = make_session("targets/x/SCOPE.txt", burp_proxy=True)          # -> 127.0.0.1:8080
    s = make_session("targets/x/SCOPE.txt", burp_proxy="http://127.0.0.1:8080")
    # env override (no code change): BURP_PROXY=http://127.0.0.1:8080 python3 probe.py
    # The SCOPE GATE still fires on every request when proxied (proxying does NOT bypass it).
    # JA3 TRADEOFF: routing through Burp uses Burp's TLS fingerprint, so the chrome124 JA3
    # match is LOST. JA3-walled targets (Akamai / DataDome) MUST stay on DIRECT curl_cffi
    # (burp_proxy off). Use Burp routing only where capture / scan visibility beats JA3.

ponytail: curl_cffi and playwright are imported LAZILY so this module loads (and its
scope-gate self-test runs) on a box without them; the network path just needs them present.
"""
from __future__ import annotations
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from lib_scope import in_scope, extract_host  # noqa: E402


class OutOfScope(Exception):
    """Raised when a request host is not in the session's SCOPE.txt."""


_DEFAULT_BURP_PROXY = "http://127.0.0.1:8080"   # last-resort fallback only


def _resolved_burp_default() -> str:
    """Proxy URL of the Burp that owns the MCP port, else the legacy default.

    burp_proxy=True means 'capture this in Burp so the orchestrator can read it back'.
    That is only true for the MCP-BOUND Burp: a second Burp squatting 8080 captures
    into a history no MCP call can reach (measured 2026-10-01). Resolve, do not guess.
    """
    try:
        import burp_resolve
        return burp_resolve.mcp_proxy_url() or _DEFAULT_BURP_PROXY
    except Exception:
        return _DEFAULT_BURP_PROXY


def _resolve_burp_proxy(burp_proxy) -> str | None:
    """Turn the burp_proxy arg + BURP_PROXY env into a concrete proxy URL or None.

    - burp_proxy is None/False (default): OFF unless BURP_PROXY is set in the env, in
      which case the env opts in (so a probe script gets Burp routing with no code edit).
    - burp_proxy is True: ON at the MCP-BOUND Burp's live listener, resolved at call
      time (env still overrides the URL). NOT a hardcoded 8080.
    - burp_proxy is a str: that exact proxy URL (env does NOT override an explicit arg).
    Returns the proxy URL string, or None when routing is OFF.
    """
    env = os.environ.get("BURP_PROXY")
    if isinstance(burp_proxy, str) and burp_proxy:
        return burp_proxy                      # explicit arg wins outright
    if burp_proxy is True:
        return env or _resolved_burp_default()  # opt-in, env may retarget the URL
    if burp_proxy in (None, False):
        return env or None                     # OFF unless the env opts in
    raise ValueError(f"burp_proxy must be bool|str|None, got {type(burp_proxy).__name__}")


_BURP_WARNED = False


def _warn_burp_unproxied(burp: str, scope_proxy: str) -> None:
    global _BURP_WARNED
    if not _BURP_WARNED:
        _BURP_WARNED = True
        import sys as _sys
        print(f"lib_egress WARNING: GNOC_SCOPE_PROXY is set but this session routes via Burp {burp}; Burp traffic is "
              f"NOT scope-proxied unless Burp's upstream proxy is {scope_proxy} (python scope gate still enforced)",
              file=_sys.stderr)


def _program_gate(url: str) -> None:
    """Fail-closed program gate for a session with no scope_file (resolved like scope_proxy / scope-gate.sh)."""
    try:
        from scope_proxy import resolve_program
        from lib_scope import program_allows
        prog = resolve_program()
        ok, why = program_allows(url, prog) if prog else (False, "no-program")
    except Exception as e:      # a conflict or any error is a refusal
        ok, why = False, f"scope decision error {type(e).__name__}"
    if not ok:
        raise OutOfScope(f"OUT_OF_SCOPE {extract_host(url) or url!r} ({why})")


class ScopedSession:
    """Wraps a curl_cffi Session and enforces the scope gate on every request.

    Fail-closed: with a scope_file set, an unparseable or out-of-scope host RAISES.
    With scope_file=None the gate is OFF (explicit opt-out for non-target use only).

    burp_proxy (default off) routes every request through Burp's proxy listener so the
    traffic lands in Burp proxy history + scanner (read it back with the MCP
    get_proxy_http_history tools). The scope gate still fires FIRST on every request, so
    proxying can NEVER bypass in_scope. Burp's CA intercepts TLS, so verification is
    disabled ONLY for the proxied session (documented tradeoff; alternatively trust Burp's
    CA). NOTE the JA3 cost: through Burp the TLS fingerprint is Burp's, not chrome124, so
    JA3-walled targets (Akamai / DataDome) must stay on DIRECT curl_cffi (burp_proxy off).
    """

    def __init__(self, scope_file: str | None, impersonate: str = "chrome124",
                 pin_ip: str | None = None, burp_proxy=None, egress=None, follow: bool = False):
        self.scope_file = scope_file
        self.pin_ip = pin_ip
        # Redirects are OFF by default: the gate below only sees the URL it is handed, so letting the
        # HTTP client follow a Location is a gate bypass with a body. See request().
        self.follow = bool(follow)
        self.burp_proxy = _resolve_burp_proxy(burp_proxy)   # concrete URL or None
        # PROGRAM EGRESS (2026-11-03): a host that the default route cannot reach (SNI hijack, geo wall)
        # gets a per-program proxy from .egress beside its SCOPE.txt. Lowest priority: an explicit arg
        # wins, then a proxy the caller already chose (Burp / scope proxy) keeps the route.
        self.egress = egress or egress_for_scope(scope_file)
        from curl_cffi import requests as creq  # lazy
        self._s = creq.Session(impersonate=impersonate)
        if self.burp_proxy:
            # Route through Burp AND stop trusting the upstream cert (Burp's CA re-signs).
            self._s.proxies = {"http": self.burp_proxy, "https": self.burp_proxy}
            self._s.verify = False
        # NETWORK SCOPE PROXY (2026-10-23): GNOC_SCOPE_PROXY=http://127.0.0.1:8084 routes through
        # scripts/scope-proxy.sh (bbtools/scope_proxy.py), which refuses out-of-scope hosts on the wire.
        # The python-side _gate() below still runs first (belt and braces). An explicit/env Burp proxy
        # wins the route (chain Burp -> scope proxy via Burp's upstream-proxy setting instead).
        self.scope_proxy = os.environ.get("GNOC_SCOPE_PROXY") or None
        # fix3 2026-10-23: the Burp route used to SKIP the scope proxy silently. Burp's upstream proxy is
        # GreyNOC's manual setting, so code cannot chain it; instead, on that route the python gate is made
        # MANDATORY (even with scope_file=None it checks the resolved program, fail closed) and one warning
        # line says Burp traffic is not proxied unless Burp's upstream proxy points at the scope proxy.
        self.burp_unproxied = bool(self.scope_proxy and self.burp_proxy)
        if self.burp_unproxied:
            _warn_burp_unproxied(self.burp_proxy, self.scope_proxy)
        if self.scope_proxy and not self.burp_proxy:
            self._s.proxies = {"http": self.scope_proxy, "https": self.scope_proxy}
            self._s.verify = False      # mitmproxy CA re-signs; upstream cert checks are not this layer's job
        # The program's own egress applies only when nothing above chose a route: a Burp capture or the
        # network scope proxy already answers "how do these bytes leave", so overriding it would silently
        # move traffic away from a layer the caller asked for. verify is NOT disabled here: an SSH/SOCKS
        # tunnel to the real host serves the real cert, unlike a TLS-terminating mitmproxy.
        if self.egress and not self.burp_proxy and not self.scope_proxy:
            self._s.proxies = {"http": self.egress, "https": self.egress}

    def _gate(self, url: str) -> None:
        if self.scope_file is None and self.__dict__.get("burp_unproxied", False):
            _program_gate(url)          # Burp route under GNOC_SCOPE_PROXY: never ungated
            return
        if self.scope_file is None:
            return
        host = extract_host(url)
        if not host:
            raise OutOfScope(f"could not parse host from {url!r}")
        if not in_scope(host, self.scope_file):
            raise OutOfScope(f"OUT_OF_SCOPE {host} (not in {self.scope_file})")

    def request(self, method: str, url: str, **kw):
        """One scope-gated request. Redirects are NOT followed unless this session or the call asks.

        WHY (2026-11-04, two loopback servers): curl_cffi follows redirects by default and _gate saw only
        the FIRST url. An in-scope host answering `302 Location: http://offscope/` was followed, the
        off-scope body came back to the caller as the in-scope response (status 200), and the second host
        was never checked. That is an out-of-scope request and a corrupted capture at the same time.
        Following is opt-in (`follow=True` on the session, or allow_redirects=True on the call) and every
        hop is gated BEFORE it is fetched, so an off-scope hop raises OutOfScope with no byte sent.
        """
        from urllib.parse import urljoin
        self._gate(url)
        if self.pin_ip:                       # IP-pin: force DNS to a chosen origin IP
            host = extract_host(url)
            port = 443 if url.lower().startswith("https") else 80
            kw.setdefault("resolve", [f"{host}:{port}:{self.pin_ip}"])
        want = kw.pop("allow_redirects", getattr(self, "follow", False))
        kw["allow_redirects"] = False         # the client must never follow on its own
        r = self._s.request(method, url, **kw)
        hops = 0
        while want and getattr(r, "status_code", 0) in (301, 302, 303, 307, 308) and hops < 5:
            loc = (getattr(r, "headers", None) or {}).get("location")
            if not loc:
                break
            nxt = urljoin(url, loc)
            self._gate(nxt)                   # raises BEFORE the next hop leaves the box
            hops += 1
            if r.status_code == 303 or (r.status_code in (301, 302) and method.upper() == "POST"):
                method = "GET"
                for k in ("data", "json", "body"):
                    kw.pop(k, None)
            url = nxt
            r = self._s.request(method, url, **kw)
        return r

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)

    def __getattr__(self, name):              # passthrough for cookies, headers, etc.
        return getattr(self._s, name)


def egress_for_scope(scope_file: str | None) -> str | None:
    """The program's configured egress proxy URL, or None for the default route.

    Why this exists (2026-11-03, program-63): that program's host is SNI-hijacked on the local network
    (TLS WRONG_VERSION_NUMBER from every direct client), so a gated `http_request` could not reach it at
    all and every probe had to be fired by hand through a side channel that bypassed the ledger. The
    route belongs to the PROGRAM, so it lives beside its SCOPE.txt as a one-line `.egress` file:

        socks5h://127.0.0.1:9050

    An explicit `egress=` argument wins over the file; the file is only read when the caller passed a
    scope_file (a session with no scope file has no program to ask). A missing/invalid file changes
    nothing. NOTE the JA3 cost: through a SOCKS proxy curl_cffi still sends chrome124's TLS hello, but
    the source IP and any proxy-side TLS are not the browser's, so a JA3/JA4-walled host must stay direct.
    """
    try:
        if not scope_file:
            return None          # no program -> no .egress to read (abspath(None) would raise)
        prog_dir = os.path.dirname(os.path.abspath(scope_file))
        path = os.path.join(prog_dir, ".egress")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line if re.match(r"^(socks5h?|http|https)://", line) else None
    except OSError:
        return None
    return None


def make_session(scope_file: str | None, impersonate: str = "chrome124",
                 pin_ip: str | None = None, burp_proxy=None, egress=None,
                 follow: bool = False) -> "ScopedSession":
    """The standard scope-gated, browser-impersonating session. scope_file=None disables the gate.

    burp_proxy (default None = OFF, so the signature/behavior is unchanged for every existing
    caller): True routes through Burp at 127.0.0.1:8080; a str routes through that proxy URL;
    the BURP_PROXY env var opts in / retargets. See ScopedSession for the JA3 tradeoff.

    egress (default None = no change): a concrete proxy URL for a program whose host is unreachable
    on the default route (an ISP/SNI hijack, a geo wall). Resolved from the program directory when
    the caller passes a scope_file, see egress_for_scope(). The scope gate still fires first, and a
    proxy ONLY changes the route: it never widens scope.

    follow (default False = a 30x is RETURNED, not followed): following is what makes a probe leave
    scope through an in-scope host's Location. Pass follow=True only when the answer really needs the
    landing page; every hop is re-gated either way.
    """
    return ScopedSession(scope_file, impersonate=impersonate, pin_ip=pin_ip, burp_proxy=burp_proxy,
                         egress=egress, follow=follow)


def clear_cloudflare(host: str, scope_file: str | None = None, timeout_s: int = 45) -> dict:
    """Solve a Cloudflare managed challenge with a real browser (Playwright) and return the
    cookies (incl cf_clearance) for reuse in a curl_cffi session. curl_cffi JA3-spoofing alone
    cannot solve a managed challenge (workspace lesson); a real browser can. Lazy-imports
    playwright. Scope-gated if scope_file is given."""
    if scope_file is not None and not in_scope(host, scope_file):
        raise OutOfScope(f"OUT_OF_SCOPE {host} (not in {scope_file})")
    from playwright.sync_api import sync_playwright  # lazy
    out: dict = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(f"https://{host}/", wait_until="networkidle", timeout=timeout_s * 1000)
        out = {c["name"]: c["value"] for c in ctx.cookies()}
        browser.close()
    return out


def demo() -> None:
    """Offline self-test of the SCOPE GATE (the security-critical path; no network needed).
    Stubs the curl_cffi layer so the gate logic is exercised without curl_cffi installed."""
    import os as _os, tempfile, types
    scope = "acmenft.io\napi.acmenft.io\n*.acmecdn.com\n"
    fd, path = tempfile.mkstemp(suffix="SCOPE.txt")
    _os.write(fd, scope.encode()); _os.close(fd)
    try:
        # build a ScopedSession without importing curl_cffi: bypass __init__, inject a fake inner.
        s = ScopedSession.__new__(ScopedSession)
        s.scope_file = path
        s.pin_ip = None
        calls = []
        fake = types.SimpleNamespace()
        fake.request = lambda m, u, **k: calls.append((m, u)) or "OK"
        s._s = fake
        assert s.request("GET", "https://api.acmenft.io/graphql") == "OK"     # in scope -> passes gate
        assert s.get("https://x.acmecdn.com/a") == "OK"           # wildcard in scope
        assert calls and calls[0][1].endswith("/graphql")
        for bad in ("https://evil.com/x", "https://attacker.acmenft.io.evil.com/"):
            try:
                s.get(bad); raise AssertionError(f"gate FAILED to block {bad}")
            except OutOfScope:
                pass
        # gate OFF when scope_file is None
        s2 = ScopedSession.__new__(ScopedSession); s2.scope_file = None; s2.pin_ip = None; s2._s = fake
        assert s2.get("https://anything.example/") == "OK"

        # --- burp_proxy: the scope gate MUST still fire when routed through Burp ---
        # (proxying must NOT bypass in_scope). Build a proxied-shaped session by hand.
        sp = ScopedSession.__new__(ScopedSession)
        sp.scope_file = path; sp.pin_ip = None; sp.burp_proxy = _DEFAULT_BURP_PROXY; sp._s = fake
        assert sp.get("https://api.acmenft.io/graphql") == "OK"          # in scope, proxied: passes
        for bad in ("https://evil.com/x", "https://attacker.acmenft.io.evil.com/"):
            try:
                sp.get(bad); raise AssertionError(f"proxied gate FAILED to block {bad}")
            except OutOfScope:
                pass

        # --- _resolve_burp_proxy precedence (arg vs env vs default) ---
        _saved = _os.environ.pop("BURP_PROXY", None)
        try:
            assert _resolve_burp_proxy(None) is None                 # default OFF
            assert _resolve_burp_proxy(False) is None
            # bool True -> the MCP-BOUND Burp's live listener (resolved), NOT a fixed
            # 8080. The old assertion here hardcoded 8080 and so enshrined the bug
            # where worker traffic was captured in a Burp the orchestrator cannot read.
            assert _resolve_burp_proxy(True) == _resolved_burp_default()
            # REGRESSION: True must never resolve to a FOREIGN Burp's proxy port.
            try:
                import burp_resolve as _br
                _d = _br.diagnose()
                _foreign = [f"http://127.0.0.1:{f['port']}" for f in
                            _d["foreign_burp_proxies"]]
                if _d["proxy_url"]:
                    assert _resolve_burp_proxy(True) not in _foreign, (
                        "burp_proxy=True resolved to a FOREIGN Burp: its captures are invisible over MCP"
                    )
            except ImportError:
                pass
            assert _resolve_burp_proxy("http://127.0.0.1:8081") == "http://127.0.0.1:8081"
            _os.environ["BURP_PROXY"] = "http://10.0.0.9:8080"
            assert _resolve_burp_proxy(None) == "http://10.0.0.9:8080"    # env opts in
            assert _resolve_burp_proxy(True) == "http://10.0.0.9:8080"    # env retargets True
            assert _resolve_burp_proxy("http://127.0.0.1:8081") == "http://127.0.0.1:8081"  # arg wins
        finally:
            _os.environ.pop("BURP_PROXY", None)
            if _saved is not None:
                _os.environ["BURP_PROXY"] = _saved
        # --- GNOC_SCOPE_PROXY routes through the scope proxy and the python gate still fires ---
        _saved_sp = _os.environ.get("GNOC_SCOPE_PROXY")
        _os.environ["GNOC_SCOPE_PROXY"] = "http://127.0.0.1:8084"
        try:
            try:
                ssp = ScopedSession(path)
                assert ssp.scope_proxy == "http://127.0.0.1:8084"
                assert ssp._s.proxies.get("https") == "http://127.0.0.1:8084"
                try:
                    ssp.get("https://offscope.example/x"); raise AssertionError("scope-proxy session gate FAILED")
                except OutOfScope:
                    pass
            except ImportError:
                pass                                              # curl_cffi absent on this box
            # fix3: GNOC_SCOPE_PROXY + Burp route -> python gate is mandatory, even with scope_file=None
            _os.environ["HUNT_TARGET"] = "__no_such_program__"
            try:
                sb = ScopedSession(None, burp_proxy="http://127.0.0.1:65530")
                assert sb.burp_unproxied and sb._s.proxies.get("https") == "http://127.0.0.1:65530"
                try:
                    sb.get("https://offscope.example/x"); raise AssertionError("burp+scope-proxy ungated")
                except OutOfScope:
                    pass
            except ImportError:
                pass
            finally:
                _os.environ.pop("HUNT_TARGET", None)
        finally:
            _os.environ.pop("GNOC_SCOPE_PROXY", None)
            if _saved_sp is not None:
                _os.environ["GNOC_SCOPE_PROXY"] = _saved_sp
        print("lib_egress SELFCHECK OK: scope-gate + burp_proxy-scope-gate + resolve ASSERTIONS PASS")
    finally:
        _os.unlink(path)


if __name__ == "__main__":
    # accept `lib_egress.py` or `lib_egress.py selfcheck`; the scope-gate + burp_proxy
    # assertions run offline (no browser / network), so this is CI-safe.
    demo()
