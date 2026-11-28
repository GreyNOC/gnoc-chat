#!/usr/bin/env python3
"""burp_resolve - find the proxy listener of the MCP-BOUND Burp, not just "a" Burp.

WHY THIS EXISTS (measured 2026-10-01): two Burp instances were running. The
MCP-bound Burp (owner of 127.0.0.1:9876) had its 8080 listener configured but
NOT running, because a second, --disable-extensions Burp squatted 8080 first.
Burp's own project options said it plainly:

    request_listeners: [{port:8080, running:false}, {port:8081, running:true}]

Every worker routed to the hardcoded 8080 and so captured its traffic in the
Burp the orchestrator CANNOT read back over MCP, while `bh status` cheerfully
printed "UP (requests will be captured in Burp history)". Silent capture loss:
the worker proxies, the orchestrator reads an empty history, and the receipt
that was supposed to be captured never existed.

THE DISCRIMINATOR is process ownership, not a banner. Both Burps serve the same
"Burp Suite Community Edition" web-interface page on their proxy ports, so the
page proves nothing about WHICH Burp answered. The proxy listener we want is:

    a port owned by the SAME pid that owns the MCP port (9876),
    which serves Burp's web-interface page.

That is offline, needs no MCP call, and so a WORKER can run it too (Burp MCP is
orchestrator-bound; see SPINE 7).
"""
from __future__ import annotations

import os
import re
import socket
import subprocess

MCP_PORT = 9876
_BURP_PAGE = b"Burp Suite"
_TIMEOUT = 3.0


def _listeners() -> dict[int, int]:
    """{port: pid} for every loopback LISTEN socket we can attribute."""
    out: dict[int, int] = {}
    try:
        raw = subprocess.run(
            ["ss", "-ltnp"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return out
    for line in raw.splitlines():
        m_port = re.search(r":(\d+)\s", line)
        m_pid = re.search(r"pid=(\d+)", line)
        if m_port and m_pid:
            out[int(m_port.group(1))] = int(m_pid.group(1))
    return out


def _serves_burp_page(port: int) -> bool:
    """Burp's proxy listener serves its own web-interface page on a bare GET /."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=_TIMEOUT) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            buf = b""
            while len(buf) < 4096:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return _BURP_PAGE in buf
    except OSError:
        return False


def mcp_proxy_port() -> int | None:
    """Proxy port of the Burp that owns the MCP port, or None if there isn't one.

    None means: do NOT proxy. Routing elsewhere would capture into a Burp the
    orchestrator cannot read, which is worse than going direct.
    """
    env = os.environ.get("BURP_MCP_PROXY_PORT")
    if env and env.isdigit():
        return int(env)
    lst = _listeners()
    mcp_pid = lst.get(MCP_PORT)
    if mcp_pid is None:
        return None
    siblings = sorted(p for p, pid in lst.items() if pid == mcp_pid and p != MCP_PORT)
    for port in siblings:
        if _serves_burp_page(port):
            return port
    return None


def mcp_proxy_url() -> str | None:
    port = mcp_proxy_port()
    return f"http://127.0.0.1:{port}" if port else None


def diagnose() -> dict:
    """Full picture, including the foreign-Burp trap that motivated this module."""
    lst = _listeners()
    mcp_pid = lst.get(MCP_PORT)
    port = mcp_proxy_port()
    foreign = []
    if mcp_pid is not None:
        for p, pid in sorted(lst.items()):
            if pid != mcp_pid and p != port and _serves_burp_page(p):
                foreign.append({"port": p, "pid": pid})
    return {
        "mcp_port": MCP_PORT,
        "mcp_up": mcp_pid is not None,
        "mcp_pid": mcp_pid,
        "proxy_port": port,
        "proxy_url": mcp_proxy_url(),
        "foreign_burp_proxies": foreign,
    }


def _selfcheck() -> None:
    d = diagnose()
    assert isinstance(d["mcp_up"], bool)
    # A resolved proxy MUST belong to the MCP-bound pid: that is the whole point.
    if d["proxy_port"] is not None:
        assert _listeners().get(d["proxy_port"]) == d["mcp_pid"], \
            "resolved proxy port is not owned by the MCP-bound Burp"
    # And it must never silently return a foreign Burp's port.
    assert d["proxy_port"] not in [f["port"] for f in d["foreign_burp_proxies"]]
    for k, v in d.items():
        print(f"  {k}: {v}")
    # marker LAST: selfcheck-all.sh greps only the final 3 lines for it.
    print("burp_resolve SELFCHECK OK")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selfcheck":
        _selfcheck()
    else:
        import json
        print(json.dumps(diagnose(), indent=2))
