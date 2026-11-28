#!/usr/bin/env python3
"""burp_ext - thin worker-side client for the bbhunt companion Burp extension.

The Burp MCP plugin is bound to the ORCHESTRATOR session, so a WORKER's MCP call fails
~79% of the time. The companion extension (burp-ext/, load it into Burp once) runs a plain
loopback HTTP control server on 127.0.0.1:9877 with NO such binding, so any worker process
can drive Burp's advanced actions by calling it. This module is the uniform curl-style
wrapper agents import instead of hand-rolling requests to that port.

    from bbtools.burp_ext import race, run_macro, intruder_results, active_scan, sitemap

    # race: fire N last-byte-synced requests + a serial control (SIG-1 seam race)
    r = race([raw_request], host="api.target.com", copies=30, scope_file="targets/x/SCOPE.txt")
    print(r["by_status"], "serial:", r["serial_control"])

    # active scan one request, get a task id (read findings back via MCP get_scanner_issues)
    active_scan(raw_request, host="api.target.com", scope_file="targets/x/SCOPE.txt")

    # sitemap tree + parameter analysis for a host
    sitemap("api.target.com", scope_file="targets/x/SCOPE.txt")

SCOPE GATE: every call that names a target host is scope-gated with lib_scope.in_scope
BEFORE it reaches the control server (the control server itself is loopback and does not
re-check scope, mirroring how the MCP plugin trusts the orchestrator's scope discipline).
Pass scope_file to enforce; scope_file=None opts out (non-target / self-test only).

ponytail: the stdlib urllib is used so this loads on any box; requests is optional.
Two capabilities are Montoya-limited and return {"supported": false, ...} by design:
intruder_results (Montoya cannot read the Intruder table) and invoke_ext (no generic
invoke-another-extension API). race reports single_packet:false -- for TRUE single-packet
use the Turbo Intruder fallback documented in scripts/BURP-INTEGRATION.md.
"""
from __future__ import annotations
import json
import os
import sys
import urllib.request
import urllib.error

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from lib_scope import in_scope, extract_host  # noqa: E402

CONTROL = os.environ.get("BBHUNT_BURP_CTRL", "http://127.0.0.1:9877")


class OutOfScope(Exception):
    """Raised when a requested host is not in the given SCOPE.txt."""


def _gate(host_or_url: str | None, scope_file: str | None) -> None:
    if scope_file is None or not host_or_url:
        return
    host = extract_host(host_or_url) if ("/" in host_or_url or "://" in host_or_url) else host_or_url
    if not in_scope(host, scope_file):
        raise OutOfScope(f"OUT_OF_SCOPE {host} (not in {scope_file})")


def _post(path: str, payload: dict, timeout: int = 60) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(CONTROL + path, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    return _do(req, timeout)


def _get(path: str, timeout: int = 30) -> dict:
    req = urllib.request.Request(CONTROL + path, method="GET")
    return _do(req, timeout)


def _do(req, timeout: int) -> dict:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # the control server returns JSON error bodies (incl 501 for documented limitations)
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            try:
                return json.loads(e.read().decode())
            except Exception:
                return {"error": f"HTTP {e.code}", "http_status": e.code}
    except urllib.error.URLError as e:
        return {"error": f"cannot reach Burp control server at {CONTROL} ({e}); "
                         f"is Burp running with the bbhunt extension loaded?"}


def ping() -> dict:
    """Liveness: {ok, burp} if the extension is loaded, else an error hint."""
    return _get("/ping")


def race(reqs, host: str, port: int = 443, tls: bool = True, copies: int = 20,
         scope_file: str | None = None, timeout: int = 90) -> dict:
    """Fire a parallel last-byte-synchronized group + one serial control.

    reqs: list of raw HTTP request strings. If exactly one is given it is replicated
    `copies` times (the common race shape: same request x N). Returns per-request status,
    a by_status histogram, and the serial_control status/len for a same-vs-serial diff.
    single_packet is always false (Montoya limit) -- see BURP-INTEGRATION.md for the true
    single-packet Turbo Intruder fallback.
    """
    if isinstance(reqs, str):
        reqs = [reqs]
    _gate(host, scope_file)
    return _post("/race", {"reqs": reqs, "host": host, "port": port, "tls": tls, "copies": copies},
                 timeout=timeout)


def run_macro(request: str, host: str, port: int = 443, tls: bool = True,
              token_header: str | None = None, cookie_name: str | None = None,
              scope_file: str | None = None) -> dict:
    """Replay an auth/refresh request and return the refreshed token header + Set-Cookie.

    (Montoya cannot invoke a saved session-handling macro by name; this replays the request
    you pass and extracts the refreshed creds, which is the working equivalent for a long
    authed checkout walk.) Set token_header (e.g. "authorization") and/or cookie_name.
    """
    _gate(host, scope_file)
    return _post("/macro", {"request": request, "host": host, "port": port, "tls": tls,
                            "tokenHeader": token_header, "cookieName": cookie_name})


def intruder_results(attack_id: str | int = "") -> dict:
    """Read an Intruder attack results table.

    Montoya LIMITATION: it exposes no API to read the Intruder table back, so this returns
    {"supported": false, "reason": ...}. Use race() for race data or the MCP proxy-history /
    organizer tools for other captured evidence.
    """
    return _get(f"/intruder-results?id={attack_id}")


def invoke_ext(name: str, **kwargs) -> dict:
    """Invoke an installed extension action (Autorize / Param Miner / Hackvertor).

    Montoya LIMITATION: there is no generic invoke-another-extension API, so this returns
    {"supported": false, "reason": ...} with the practical routes. Kept for a uniform surface.
    """
    return _post("/invoke-ext", {"name": name, **kwargs})


def active_scan(request: str, host: str, port: int = 443, tls: bool = True,
                scope_file: str | None = None) -> dict:
    """Start an active scan (audit) on one request; returns {task_id, started}.

    Read the findings back with the MCP get_scanner_issues tool. NEEDS Burp Pro.
    """
    _gate(host, scope_file)
    return _post("/active-scan", {"request": request, "host": host, "port": port, "tls": tls})


def sitemap(host: str, scope_file: str | None = None) -> dict:
    """Read Burp's sitemap tree for `host` + per-request parameter analysis."""
    _gate(host, scope_file)
    return _get(f"/sitemap?host={urllib.request.quote(host)}")


def _selfcheck() -> None:
    """Offline self-check: the SCOPE GATE (security-critical) + client shapes. No Burp needed.

    Asserts the gate raises on an off-scope host and passes an in-scope host, and that the
    'cannot reach Burp' path returns a structured error (not an exception) when Burp is down.
    """
    import tempfile
    scope = "api.target.com\n*.target.com\n"
    fd, path = tempfile.mkstemp(suffix="SCOPE.txt")
    os.write(fd, scope.encode()); os.close(fd)
    try:
        # gate blocks off-scope BEFORE any network
        for bad in ("evil.com", "https://evil.com/x", "api.target.com.evil.com"):
            try:
                _gate(bad, path); raise AssertionError(f"gate FAILED to block {bad}")
            except OutOfScope:
                pass
        # gate passes in-scope
        _gate("api.target.com", path)
        _gate("https://sub.target.com/x", path)
        # gate OFF when scope_file is None
        _gate("anything.example", None)

        # point the client at a closed port: every fn must return a structured error, not throw
        global CONTROL
        saved = CONTROL
        CONTROL = "http://127.0.0.1:9"      # nothing listens
        try:
            r = ping()
            assert "error" in r, "expected a reach error when Burp is down"
            # a scoped race with a good host still hits the gate first (in-scope) then the reach error
            rr = race(["GET / HTTP/1.1\r\nHost: api.target.com\r\n\r\n"], host="api.target.com",
                      scope_file=path, timeout=2)
            assert "error" in rr, "expected reach error"
            # and an off-scope race raises BEFORE any network
            try:
                race(["x"], host="evil.com", scope_file=path); raise AssertionError("race did not gate")
            except OutOfScope:
                pass
            # documented-limitation helpers do not raise (they return supported:false when live;
            # offline they return a reach error -- either way, no exception)
            invoke_ext("Autorize")
            intruder_results("1")
        finally:
            CONTROL = saved
        print("burp_ext SELFCHECK OK: scope-gate + client-shape + down-server ASSERTIONS PASS")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "selfcheck":
        _selfcheck()
    elif len(sys.argv) > 1 and sys.argv[1] == "ping":
        print(json.dumps(ping(), indent=2))
    else:
        _selfcheck()
