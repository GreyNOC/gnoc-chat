#!/usr/bin/env python3
"""bh - single front-door for target HTTP in hunter agents.

The measured problem: agents underuse Burp because it needs knowing two helpers
(lib_egress burp_proxy + burp_ext.py). This collapses them into one obvious module
with auto-detect so the common case needs zero ceremony.

WORKER USAGE (start here):
    from bbtools.bh import req, race, active_scan
    r = req("https://api.target.com/endpoint", scope_file="targets/x/SCOPE.txt")
    # -> auto-routes through Burp if 127.0.0.1:8080 is reachable, else direct curl_cffi.
    # r = {status, len, body, headers, via_used}

via modes:
    "auto"   (default) - socket-probe 127.0.0.1:8080; if up, route through Burp so the
             request lands in Burp history/scanner; if down, fall back to direct curl_cffi
             and print a one-line stderr note.
    "burp"   - force through Burp proxy; raise if proxy is unreachable.
    "direct" - force direct curl_cffi (use for JA3-walled targets: Akamai/DataDome where
             Burp TLS fingerprint breaks the chrome124 JA3 match).

Advanced Burp actions (thin passthroughs from burp_ext, workers may use these; the control
server on 127.0.0.1:9877 is NOT MCP-bound, so workers can reach it):
    race(reqs, host, ...)    - last-byte-synced burst + serial control (SIG-1 seam race)
    active_scan(req, host)   - start Burp active scan (Pro only)
    sitemap(host)            - Burp sitemap tree for a host
    macro(name)              - replay an auth/refresh request
    ping()                   - liveness check for the control extension

NOTE: Burp MCP (127.0.0.1:9876) is ORCHESTRATOR-ONLY. Workers must NOT use it (79% fail
rate measured 2026-07-07). Workers use this module instead: bh.req for plain HTTP (goes
through Burp's proxy), and bh.race/active_scan/sitemap/macro for advanced actions (go
through the control server on 9877).
"""
from __future__ import annotations

import os
import socket
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lib_egress import make_session, egress_for_scope, OutOfScope  # noqa: E402
from lib_scope import extract_host, in_scope  # noqa: E402
import burp_ext as _bext  # noqa: E402
import burp_resolve as _bres  # noqa: E402

# Re-export the OutOfScope exception so importers only need this one module.
__all__ = [
    "req", "status", "race", "active_scan", "sitemap", "macro", "ping",
    "BurpActionUnavailable",
    "OutOfScope", "_selfcheck",
]

# NOT authoritative any more: the proxy port is resolved from whichever Burp owns the
# MCP port, because routing into a second, non-MCP Burp captures bytes the orchestrator
# can never read back. See burp_resolve.py for the measured failure.
_BURP_PROXY_ADDR = ("127.0.0.1", 8080)   # legacy default, used only in messages
_BURP_CTRL_ADDR = ("127.0.0.1", 9877)
_BURP_MCP_PORT = 9876

# WAF block-detection patterns (used by the waf_evade auto-retry path only)
_WAF_BLOCK_STATUSES = frozenset({403, 406, 429})
_WAF_BLOCK_BODY_PATTERNS = (
    "Cloudflare Ray ID",
    "cdn-cgi/challenge-platform",
    "Access Denied - Sucuri",
    "Incapsula incident ID",
    "Not Acceptable!",
    "x-amzn-waf-action",
    "Request blocked",
    "Bot Verification",
    "Enable JavaScript",
)


def _is_waf_blocked(status: int, body: str) -> bool:
    """Return True if the response looks like a WAF block or challenge page."""
    if status in _WAF_BLOCK_STATUSES:
        return True
    body_lower = body.lower()
    return any(pat.lower() in body_lower for pat in _WAF_BLOCK_BODY_PATTERNS)


def _probe_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _burp_proxy_url() -> str | None:
    """Proxy URL of the MCP-BOUND Burp, or None if that Burp has no live listener.

    None means go DIRECT. Proxying into a foreign Burp would silently capture into a
    history the orchestrator cannot read, so direct is strictly better than wrong.
    """
    return _bres.mcp_proxy_url()


def _burp_proxy_up() -> bool:
    return _burp_proxy_url() is not None


def req(
    url: str,
    method: str = "GET",
    body: Any = None,
    headers: dict | None = None,
    scope_file: str | None = None,
    via: str = "auto",
    waf_evade: bool = False,
) -> dict:
    """Scope-gated HTTP request with automatic Burp routing.

    Scope gate fires FIRST (before any network): raises OutOfScope if the host is not
    in scope_file. Pass scope_file=None to disable the gate (non-target use only).

    Args:
        url:        Target URL.
        method:     HTTP method (default "GET").
        body:       Request body (dict/list serialized as JSON, string sent raw).
        headers:    Extra request headers.
        scope_file: Path to SCOPE.txt; raises OutOfScope if host not in scope.
        via:        Routing: "auto" (default), "burp" (force), "direct" (JA3-walled).
        waf_evade:  When True, if the response is 403/406/429 or a WAF challenge page,
                    automatically call lib_wafmutate.spray() to find a passing mutation
                    and return the first PASSING variant's response instead. The returned
                    dict gains a "via_used" value of "wafmutate:<label>" when a mutation
                    succeeded. Default False: existing callers are byte-for-byte unchanged.

    Returns: {status: int, len: int, body: str, headers: dict, via_used: str}
    Raises: OutOfScope if the host is not in scope.
    Raises: RuntimeError if via="burp" and the Burp proxy is not reachable.
    """
    if via not in ("auto", "burp", "direct"):
        raise ValueError(f"via must be 'auto', 'burp', or 'direct', got {via!r}")

    # Scope gate: check before deciding routing so an OOS request never touches the network.
    if scope_file is not None:
        host = extract_host(url)
        if not in_scope(host, scope_file):
            raise OutOfScope(f"OUT_OF_SCOPE {host} (not in {scope_file})")

    # Determine routing.
    burp_url = _burp_proxy_url()
    if via == "burp":
        if burp_url is None:
            raise RuntimeError(
                "via='burp' requested but the MCP-bound Burp has no running proxy "
                "listener. Run: python3 burp_resolve.py   (a second Burp squatting the "
                "port is the usual cause; its captures are invisible over MCP)"
            )
        use_burp = burp_url
    elif via == "direct":
        use_burp = False
    else:  # auto
        use_burp = burp_url or False
        if not use_burp:
            print(
                "bh: MCP-bound Burp has no running proxy listener;"
                " falling back to direct curl_cffi (JA3 fingerprint preserved)",
                file=sys.stderr,
            )

    # Build session. scope_file=None here because we already ran the gate above; passing it
    # again would double-check, which is harmless but wastes a file read on every request.
    # egress is resolved by hand for the same reason: the program's .egress route is needed exactly
    # when the default route cannot reach the host, and this call site is the one http_request uses.
    sess = make_session(None, burp_proxy=use_burp, egress=egress_for_scope(scope_file) if scope_file else None)
    # Belt and braces: with scope_file=None, ScopedSession cannot consult .egress itself (it has no program
    # to ask), so the route resolved above must be attached here or the program's own egress is lost.
    if not use_burp and getattr(sess, "egress", None) and not getattr(sess, "scope_proxy", None):
        inner = getattr(sess, "_s", None)
        if inner is not None:
            inner.proxies = {"http": sess.egress, "https": sess.egress}

    kw: dict = {}
    if headers:
        kw["headers"] = headers
    if body is not None:
        if isinstance(body, (dict, list)):
            import json
            kw["data"] = json.dumps(body)
            kw.setdefault("headers", {})
            kw["headers"].setdefault("Content-Type", "application/json")
        else:
            kw["data"] = body

    resp = sess.request(method.upper(), url, **kw)

    resp_body = ""
    try:
        resp_body = resp.text
    except Exception:
        try:
            resp_body = resp.content.decode("utf-8", errors="replace")
        except Exception:
            resp_body = ""

    resp_headers: dict = {}
    try:
        resp_headers = dict(resp.headers)
    except Exception:
        pass

    base_result = {
        "status": resp.status_code,
        "len": len(resp_body),
        "body": resp_body,
        "headers": resp_headers,
        "via_used": "burp" if use_burp else "direct",
    }

    # Optional WAF-evasion auto-retry (waf_evade=True only; default False).
    # When the response looks like a WAF block, import lib_wafmutate lazily and
    # spray mutations; return the first PASSING variant's response if found.
    # Existing callers with waf_evade=False (the default) reach none of this code.
    if waf_evade and _is_waf_blocked(resp.status_code, resp_body):
        try:
            import lib_wafmutate as _wm  # lazy import: no hard dependency
        except ImportError:
            print(
                "bh: waf_evade=True but lib_wafmutate is not importable; "
                "returning original blocked response",
                file=sys.stderr,
            )
            return base_result

        # Extract the param=value from the body or URL for mutation.
        # We re-send the full body string as the payload so mutations cover it.
        raw_payload = body if isinstance(body, str) and body else url
        # Determine the parameter name heuristically from the body or default to "q"
        param_name = "q"
        if isinstance(body, str) and "=" in body:
            param_name = body.split("=", 1)[0]

        try:
            spray_result = _wm.spray(
                sess, url, method, param_name, raw_payload,
                waf=None, scope_file=None  # scope already checked above
            )
        except Exception as spray_exc:
            print(f"bh: wafmutate.spray failed: {spray_exc}", file=sys.stderr)
            return base_result

        # Take the first passing mutation and re-execute it as a real request.
        for passing in spray_result.get("passed", []):
            label = passing.get("label", "?")
            variant = passing.get("variant", "")
            # Rebuild the request with the mutated param value.
            try:
                mut_kw: dict = {}
                if headers:
                    mut_kw["headers"] = headers
                if method.upper() == "GET":
                    sep = "&" if "?" in url else "?"
                    mut_url = f"{url}{sep}{param_name}={variant}"
                    mut_resp = sess.request(method.upper(), mut_url, **mut_kw)
                else:
                    mut_kw["data"] = {param_name: variant}
                    mut_resp = sess.request(method.upper(), url, **mut_kw)

                mut_body = ""
                try:
                    mut_body = mut_resp.text
                except Exception:
                    try:
                        mut_body = mut_resp.content.decode("utf-8", errors="replace")
                    except Exception:
                        mut_body = ""

                mut_headers: dict = {}
                try:
                    mut_headers = dict(mut_resp.headers)
                except Exception:
                    pass

                return {
                    "status": mut_resp.status_code,
                    "len": len(mut_body),
                    "body": mut_body,
                    "headers": mut_headers,
                    "via_used": f"wafmutate:{label}",
                }
            except Exception:
                continue  # try the next passing mutation

    return base_result


def status() -> None:
    """Print which Burp surfaces are up right now. Safe with no Burp running."""
    diag = _bres.diagnose()
    ctrl_up = _probe_port(_BURP_CTRL_ADDR[0], _BURP_CTRL_ADDR[1])

    if diag["proxy_url"]:
        print(
            f"Burp proxy   {diag['proxy_url']:<22} UP  (MCP-bound pid {diag['mcp_pid']};"
            f" captures ARE readable over MCP)"
        )
    else:
        print(
            "Burp proxy   (none)                DOWN - the MCP-bound Burp has no running"
            " listener; bh will go DIRECT"
        )
    for f in diag["foreign_burp_proxies"]:
        print(
            f"  WARNING  a FOREIGN Burp (pid {f['pid']}) holds 127.0.0.1:{f['port']}."
            f" Traffic sent there is INVISIBLE to MCP. Do not route to it."
        )

    ctrl_detail = ""
    if ctrl_up:
        result = _bext.ping()
        if "error" not in result:
            ctrl_detail = f"  burp={result.get('burp', '?')}"
        else:
            ctrl_detail = f"  (ping error: {result.get('error', '?')})"
    ctrl_label = f"UP{ctrl_detail} (workers: race/scan/sitemap/macro)" if ctrl_up else "DOWN"
    print(f"Burp control 127.0.0.1:9877  {ctrl_label}")

    print(
        f"Burp MCP     127.0.0.1:{_BURP_MCP_PORT}  ORCHESTRATOR-ONLY"
        f" (workers must not use MCP directly; use bh.req / bh.race instead)"
    )


# --- Advanced Burp actions ---------------------------------------------------
# These used to be blind passthroughs to the loopback control server on 9877.
# That server is provided by a `bbhunt-control` extension which does NOT exist on
# this box, so the calls returned a connection error shaped like a result. A worker
# reading that as 'ran, found nothing' would file a DEAD claim on an action that
# never fired. race() now falls back to the real race_burst primitive; the rest
# raise loudly.


class BurpActionUnavailable(RuntimeError):
    """A Burp action was requested that cannot run on this install."""


def _ctrl_up() -> bool:
    return _probe_port(_BURP_CTRL_ADDR[0], _BURP_CTRL_ADDR[1])



def race(reqs, host: str, port: int = 443, tls: bool = True, copies: int = 20,
         scope_file: str | None = None, timeout: int = 90) -> dict:
    """Concurrent burst + serial-replay control.

    Uses Burp's control server when present (last-byte sync), else falls back to the
    race_burst primitive over scope-gated curl_cffi. The serial control is what makes
    a burst result interpretable, so it is preserved on both paths.
    """
    if _ctrl_up():
        out = _bext.race(reqs, host=host, port=port, tls=tls, copies=copies,
                         scope_file=scope_file, timeout=timeout)
        if "error" not in out:
            out.setdefault("engine", "burp_ctrl")
            return out
    import race_burst as _rb
    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}" + ("" if port in (80, 443) else f":{port}")
    reqlist = reqs if isinstance(reqs, (list, tuple)) else [reqs]
    paths = []
    for r in reqlist:
        first = str(r).splitlines()[0] if str(r).strip() else "GET /"
        parts = first.split()
        paths.append(parts[1] if len(parts) > 1 else "/")
    sess = make_session(scope_file, burp_proxy=_burp_proxy_url() or False)
    def _fire(i):
        return sess.get(base + paths[i % len(paths)])
    burst_res = _rb.burst(_fire, n=copies)
    serial_res = _rb.serial_control(_fire, n=min(copies, 5))
    return {
        "engine": "race_burst",
        "note": ("Burp control server (9877) absent - the bbhunt-control extension is "
                 "not installed on this box. Ran the race_burst fallback instead."),
        "burst": burst_res,
        "serial_control": serial_res,
    }


def active_scan(request: str, host: str, port: int = 443, tls: bool = True,
                scope_file: str | None = None) -> dict:
    """Start a Burp active scan on one request. Requires Burp PRO + the control extension."""
    if not _ctrl_up():
        raise BurpActionUnavailable(
            "active_scan needs the Burp control extension on 127.0.0.1:9877, which is "
            "not installed here, AND Burp PRO (this install is COMMUNITY, which has no "
            "active scanner). Hunt the vector by hand - do NOT record a DEAD on this."
        )
    return _bext.active_scan(request, host=host, port=port, tls=tls, scope_file=scope_file)


def sitemap(host: str, scope_file: str | None = None) -> dict:
    """Read Burp sitemap + parameter analysis for host (needs the control extension)."""
    if not _ctrl_up():
        raise BurpActionUnavailable(
            "sitemap needs the Burp control extension on 127.0.0.1:9877, which is not "
            "installed here. The orchestrator can read the same traffic over MCP with "
            "get_proxy_http_history / get_proxy_http_history_regex instead."
        )
    return _bext.sitemap(host, scope_file=scope_file)


def macro(request: str, host: str, port: int = 443, tls: bool = True,
          token_header: str | None = None, cookie_name: str | None = None,
          scope_file: str | None = None) -> dict:
    """Replay an auth/refresh request and return the refreshed token."""
    if not _ctrl_up():
        raise BurpActionUnavailable(
            "macro needs the Burp control extension on 127.0.0.1:9877, which is not "
            "installed here. Replay the auth request directly with bh.req and read the "
            "refreshed token from the response."
        )
    return _bext.run_macro(request, host=host, port=port, tls=tls,
                           token_header=token_header, cookie_name=cookie_name,
                           scope_file=scope_file)


def ping() -> dict:
    """Liveness check for the Burp control extension. Passthrough to burp_ext.ping."""
    return _bext.ping()


# --- Offline self-check ---

def _selfcheck() -> None:
    """Assert-based offline self-check. MUST pass with NO Burp running.

    Checks:
    1. Scope gate refuses an off-scope URL before any network.
    2. via='auto' degrades to direct when 8080 is down (no exception thrown).
    3. status() runs clean with everything down (no exception, no throw).
    4. via='direct' bypasses Burp routing without error.
    5. via='burp' raises RuntimeError when proxy is down.
    """
    import tempfile

    scope = "api.target.com\n*.target.com\n"
    fd, scope_path = tempfile.mkstemp(suffix="SCOPE.txt")
    os.write(fd, scope.encode())
    os.close(fd)

    try:
        # 1. Scope gate blocks OOS before network.
        for bad_url in ("https://evil.com/x", "https://api.target.com.evil.com/x"):
            try:
                req(bad_url, scope_file=scope_path, via="direct")
                raise AssertionError(f"scope gate FAILED to block {bad_url}")
            except OutOfScope:
                pass

        # 2. via='auto' with NO MCP-bound listener -> falls back to direct, no exception.
        # The seam is _burp_proxy_url (returns None when the MCP-bound Burp has no live
        # listener). Patching it to None must build a DIRECT session even while some
        # other Burp is listening on 8080 - that foreign Burp must never attract traffic.
        import unittest.mock as _mock
        with _mock.patch(__name__ + "._burp_proxy_url", return_value=None):
            # Confirm the logic path: auto with proxy down should not raise, just print.
            # We mock make_session to avoid a real network call.
            captured: list = []

            def _fake_make_session(scope_f, burp_proxy=None, egress=None):
                captured.append({"scope_file": scope_f, "burp_proxy": burp_proxy, "egress": egress})
                # Return a minimal fake session object.
                class FakeResp:
                    status_code = 200
                    text = "ok"
                    content = b"ok"
                    headers = {}
                class FakeSess:
                    def request(self, m, u, **kw):
                        return FakeResp()
                return FakeSess()

            with _mock.patch(__name__ + ".make_session", _fake_make_session):
                r = req("https://api.target.com/x", scope_file=scope_path, via="auto")
                assert r["via_used"] == "direct", f"expected direct fallback, got {r['via_used']}"
                assert captured and captured[0]["burp_proxy"] is False, \
                    f"expected burp_proxy=False, got {captured}"

            # 2b. REGRESSION: a resolved listener must be passed through as the URL
            # STRING. Passing True here would re-introduce the 8080 hardcode and could
            # route captures into a foreign, MCP-invisible Burp.
            captured.clear()
            _fake_url = "http://127.0.0.1:65123"
            with _mock.patch(__name__ + "._burp_proxy_url", return_value=_fake_url), \
                 _mock.patch(__name__ + ".make_session", _fake_make_session):
                r = req("https://api.target.com/x", scope_file=scope_path, via="auto")
                assert r["via_used"] == "burp", f"expected burp, got {r['via_used']}"
                assert captured and captured[0]["burp_proxy"] == _fake_url, \
                    f"expected the resolved URL string, got {captured}"

        # 3. status() runs clean with everything down (no Burp present).
        import io
        buf = io.StringIO()
        _saved_stdout = sys.stdout
        sys.stdout = buf
        try:
            status()
        finally:
            sys.stdout = _saved_stdout
        out = buf.getvalue()
        # The proxy line must be PRESENT, but it deliberately does not name 8080 when no listener is
        # up: status() reports "Burp proxy (none) ... bh will go DIRECT". Asserting the literal
        # 127.0.0.1:8080 tested an older status() that hardcoded the port, and it fails with Burp down
        # (which is the state this selfcheck runs in).
        assert "Burp proxy" in out, "status() missing proxy line"
        assert "127.0.0.1:9877" in out, "status() missing control line"
        assert "9876" in out, "status() missing MCP note"

        # 4. via='direct' skips Burp even if proxy were up.
        with _mock.patch(__name__ + "._burp_proxy_up", return_value=True):
            captured2: list = []
            with _mock.patch(__name__ + ".make_session",
                             lambda sf, burp_proxy=None, egress=None: captured.append(burp_proxy) or
                             type("S", (), {"request": lambda s, m, u, **k:
                                           type("R", (), {"status_code": 200, "text": "",
                                                          "content": b"", "headers": {}})()})()
                             ):
                # Just confirm via='direct' passes burp_proxy=False.
                # We re-implement the test inline to avoid a real call.
                with _mock.patch(__name__ + ".make_session",
                                 lambda sf, burp_proxy=None, egress=None: (captured2.append(burp_proxy),
                                     type("S", (), {"request": lambda s, m, u, **k:
                                         type("R", (), {"status_code": 200, "text": "x",
                                                        "content": b"x", "headers": {}})()})())[1]
                                 ):
                    r2 = req("https://api.target.com/y", scope_file=scope_path, via="direct")
                    assert r2["via_used"] == "direct"
                    assert captured2 and captured2[0] is False, \
                        f"via='direct' should pass burp_proxy=False, got {captured2}"

        # 5. via='burp' raises RuntimeError when proxy is down.
        with _mock.patch(__name__ + "._burp_proxy_url", return_value=None):
            try:
                req("https://api.target.com/z", scope_file=scope_path, via="burp")
                raise AssertionError("via='burp' with proxy down should raise RuntimeError")
            except RuntimeError:
                pass

        print("bh SELFCHECK OK: scope-gate + auto-fallback + status + via-modes ASSERTIONS PASS")

    finally:
        os.unlink(scope_path)


# --- CLI ---

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="bh",
        description="Front-door target HTTP: auto-routes through Burp with direct fallback.",
    )
    sub = parser.add_subparsers(dest="cmd")

    # status
    sub.add_parser("status", help="Show which Burp surfaces are up")

    # selfcheck
    sub.add_parser("selfcheck", help="Offline self-check (PASS with no Burp running)")

    # get / post
    for verb in ("get", "post"):
        p = sub.add_parser(verb, help=f"HTTP {verb.upper()} <url>")
        p.add_argument("url")
        p.add_argument("--scope", dest="scope_file", default=None,
                       help="Path to SCOPE.txt (e.g. targets/x/SCOPE.txt)")
        p.add_argument("--body", default=None, help="Request body string")
        p.add_argument("--via", choices=["auto", "burp", "direct"], default="auto",
                       help="Routing: auto (default), burp (force), direct (JA3-walled targets)")

    # race (passthrough to burp_ext, minimal CLI)
    p_race = sub.add_parser("race", help="Scoped race burst (passthrough to burp_ext.race)")
    p_race.add_argument("host", help="Target host (e.g. api.target.com)")
    p_race.add_argument("--scope", dest="scope_file", default=None)
    p_race.add_argument("--copies", type=int, default=20)

    args = parser.parse_args()

    if args.cmd == "status":
        status()

    elif args.cmd == "selfcheck":
        _selfcheck()

    elif args.cmd in ("get", "post"):
        import json
        method = args.cmd.upper()
        try:
            result = req(
                args.url,
                method=method,
                body=args.body,
                scope_file=args.scope_file,
                via=args.via,
            )
        except OutOfScope as e:
            print(f"BLOCKED: {e}", file=sys.stderr)
            sys.exit(1)
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"HTTP {result['status']}  len={result['len']}  via={result['via_used']}")
        print(json.dumps(result["headers"], indent=2))
        print()
        print(result["body"][:4000])
        if result["len"] > 4000:
            print(f"... [{result['len'] - 4000} bytes truncated]")

    elif args.cmd == "race":
        import json
        scope_arg = getattr(args, "scope_file", None)
        r = race(
            ["GET / HTTP/1.1\r\nHost: " + args.host + "\r\n\r\n"],
            host=args.host,
            scope_file=scope_arg,
            copies=args.copies,
        )
        print(json.dumps(r, indent=2))

    else:
        parser.print_help()
        sys.exit(1)
