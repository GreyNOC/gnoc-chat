#!/usr/bin/env python3
"""scope_proxy - the per-job, deny-by-default, scope-enforcing HTTP/CONNECT proxy for oss-bot.

    scope_proxy.py --program P --port 0 --log D/egress.jsonl --rps R --max-conn-per-host 4 [--selftest]

Prints `PORT <n>` as stdout line 1, then serves on 127.0.0.1 until SIGTERM/SIGINT.

Every connection is decided here, independent of the tool's own scope flags (T-171):
  1. port must be in config proxy_ports
  2. lib_scope.program_allows(host, P) (NOSCOPE first, internal IP, third-party, SCOPE allowlist)
  3. the proxy resolves the host ITSELF; ANY resolved address that is not globally routable denies
  4. the proxy connects to the exact IP it resolved (no DNS-rebind TOCTOU)
Anything that is not a well-formed CONNECT or absolute-form http:// request is refused. One request
per plain-HTTP connection (Connection: close upstream), so a kept-alive client socket can never be
reused toward a second, undecided host. TLS inside CONNECT passes through untouched (no fingerprint
change). Per-host token bucket on NEW connections + a concurrent-tunnel cap (connection-level limiter;
the tool's own -rl is the request-level limiter). Every decision is one JSON log row.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import signal
import socket
import sys
import time
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from bbtools import lib_scope  # noqa: E402

WS_ROOT = lib_scope.WS_ROOT
CONFIG = os.path.join(HERE, "config.json")
HOP = {b"connection", b"proxy-connection", b"keep-alive", b"proxy-authorization", b"te", b"trailer",
       b"upgrade", b"host"}
IDLE_S = 120


def ip_blocked(ip_str: str) -> bool:
    """True for anything that is not a public unicast address (fail closed on parse errors)."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast
            or ip.is_unspecified or not ip.is_global)


class Proxy:
    def __init__(self, program, root=WS_ROOT, ports=(80, 443, 8080, 8443), rps=3.0, max_conn=4,
                 log_path=None, resolver=None):
        self.program, self.root = program, root
        self.ports = {int(p) for p in ports}
        self.rps = max(0.1, float(rps))
        self.max_conn = max(1, int(max_conn))
        self.resolver = resolver or self._resolve
        self._ip_blocked = ip_blocked
        self.buckets: dict[str, list[float]] = {}
        self.sems: dict[str, asyncio.Semaphore] = {}
        self.log_fh = open(log_path, "a", buffering=1, encoding="utf-8") if log_path else None
        self.rows: list[dict] = []

    async def _resolve(self, host, port):
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [i[4][0] for i in infos]

    def log(self, host, port, kind, allowed, reason, ip):
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host, "port": port,
               "kind": kind, "allowed": bool(allowed), "reason": reason, "ip": ip}
        self.rows.append(row)
        if self.log_fh:
            self.log_fh.write(json.dumps(row) + "\n")

    async def decide(self, host, port):
        """-> (allowed, reason, ip). Every path that is not the final return is a deny."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False, "no-host", None
        if not isinstance(port, int) or port not in self.ports:
            return False, "port", None
        ok, why = lib_scope.program_allows(host, self.program, self.root)
        if not ok:
            return False, why, None
        try:
            ips = await asyncio.wait_for(self.resolver(host, port), 10)
        except Exception:
            return False, "dns-fail", None
        if not ips:
            return False, "dns-fail", None
        for ip in ips:
            if self._ip_blocked(ip):
                return False, "resolved-internal", ip
        ip = next((i for i in ips if ":" not in i), ips[0])
        return True, "ok", ip

    async def throttle(self, host):
        b = self.buckets.setdefault(host, [max(1.0, self.rps), time.monotonic()])
        while True:
            now = time.monotonic()
            b[0] = min(max(1.0, self.rps), b[0] + (now - b[1]) * self.rps)
            b[1] = now
            if b[0] >= 1.0:
                b[0] -= 1.0
                return
            await asyncio.sleep((1.0 - b[0]) / self.rps)

    @staticmethod
    async def _reply(writer, status):
        """CONNECT failures only: a non-200 CONNECT reply is a failure to every client. A plain-HTTP failure
        must NOT get a status line (a tool would record the proxy's 403 as the target's response, which also
        fakes an audit row), so those paths use _drop()."""
        try:
            writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        except Exception:
            pass
        writer.close()

    @staticmethod
    async def _drop(writer):
        """Close with ZERO response bytes: the client sees a connection error, never a fake response."""
        try:
            writer.transport.abort()
        except Exception:
            writer.close()

    @staticmethod
    async def _pipe(r, w):
        try:
            while True:
                d = await asyncio.wait_for(r.read(65536), IDLE_S)
                if not d:
                    break
                w.write(d)
                await w.drain()
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except Exception:
            writer.close()
            return
        lines = head[:-4].split(b"\r\n")
        parts = lines[0].decode("latin-1").split(" ")
        if len(parts) != 3:
            self.log("", None, "BAD", False, "malformed", None)
            return await self._drop(writer)
        method, target, ver = parts
        hdrs = []
        for ln in lines[1:]:
            k, sep, v = ln.partition(b":")
            if not sep:
                self.log("", None, "BAD", False, "malformed", None)
                return await self._drop(writer)
            hdrs.append((k.strip(), v.strip()))
        if method.upper() == "CONNECT":
            kind = "CONNECT"
            if target.startswith("["):
                host, _, rest = target[1:].partition("]")
                pstr = rest[1:] if rest.startswith(":") else ""
            else:
                host, _, pstr = target.rpartition(":")
            port = int(pstr) if pstr.isdigit() else None
            path = None
        else:
            kind = "HTTP"
            if not target.lower().startswith("http://"):
                self.log("", None, kind, False, "not-absolute-http", None)
                return await self._drop(writer)
            try:
                u = urlsplit(target)
                host, port = u.hostname or "", u.port or 80
            except ValueError:
                self.log("", None, kind, False, "malformed", None)
                return await self._drop(writer)
            path = (u.path or "/") + (("?" + u.query) if u.query else "")
            authority = u.netloc.rsplit("@", 1)[-1]
        allowed, reason, ip = await self.decide(host, port)
        self.log((host or "").lower().rstrip("."), port, kind, allowed, reason, ip)

        async def fail(status):
            return await (self._reply(writer, status) if kind == "CONNECT" else self._drop(writer))
        if not allowed:
            return await fail("403 Forbidden")
        clen = 0
        if kind == "HTTP":
            for k, v in hdrs:
                if k.lower() == b"transfer-encoding":
                    return await fail("501 Not Implemented")
                if k.lower() == b"content-length":
                    if not v.isdigit():
                        return await fail("400 Bad Request")
                    clen = int(v)
        sem = self.sems.setdefault(host, asyncio.Semaphore(self.max_conn))
        async with sem:
            await self.throttle(host)
            try:
                up_r, up_w = await asyncio.wait_for(asyncio.open_connection(ip, port), 15)
            except Exception:
                return await fail("502 Bad Gateway")
            if kind == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                await asyncio.gather(self._pipe(reader, up_w), self._pipe(up_r, writer))
                return
            out = [f"{method} {path} {ver}".encode("latin-1"), b"Host: " + authority.encode("latin-1")]
            out += [k + b": " + v for k, v in hdrs if k.lower() not in HOP]
            out.append(b"Connection: close")
            up_w.write(b"\r\n".join(out) + b"\r\n\r\n")
            try:
                if clen:
                    up_w.write(await asyncio.wait_for(reader.readexactly(clen), 30))
                await up_w.drain()
            except Exception:
                up_w.close()
                return await self._drop(writer)
            await self._pipe(up_r, writer)   # client->upstream is NOT piped: one request per connection
            up_w.close()


def load_ports():
    try:
        with open(CONFIG, encoding="utf-8") as fh:
            return json.load(fh)["proxy_ports"]
    except Exception:
        return [80, 443, 8080, 8443]


async def serve(px: Proxy, port: int):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(s, stop.set)
    server = await asyncio.start_server(px.handle, "127.0.0.1", port, limit=65536)
    print(f"PORT {server.sockets[0].getsockname()[1]}", flush=True)
    await stop.wait()
    server.close()


# ------------------------------------------------------------------ selftest
async def _selftest():
    import tempfile
    root = tempfile.mkdtemp(prefix="scope-proxy-selftest-")
    pdir = os.path.join(root, "targets", "px")
    os.makedirs(pdir)
    with open(os.path.join(pdir, "SCOPE.txt"), "w") as fh:
        fh.write("*.inscope.example\nexact.example\ngithub.com\n=93.184.216.34\n")
    with open(os.path.join(pdir, "NOSCOPE.txt"), "w") as fh:
        fh.write("deny.inscope.example\n")
    calls = []
    table = {"a.inscope.example": ["93.184.216.34"], "rebind.inscope.example": ["127.0.0.1"],
             "mixed.inscope.example": ["93.184.216.34", "10.0.0.5"], "v6.inscope.example": ["::1"],
             "mapped.inscope.example": ["::ffff:127.0.0.1"], "meta.inscope.example": ["169.254.169.254"],
             "cgnat.inscope.example": ["100.64.1.1"], "pos.inscope.example": ["127.0.0.1"],
             "exact.example": ["93.184.216.35"], "93.184.216.34": ["93.184.216.34"]}

    async def fake(host, port):
        calls.append(host)
        if host not in table:
            raise socket.gaierror("nx")
        return table[host]

    px = Proxy("px", root, log_path=os.path.join(root, "egress.jsonl"), resolver=fake)
    want = [
        (("a.inscope.example", 443), (True, "ok")), (("exact.example", 80), (True, "ok")),
        (("93.184.216.34", 443), (True, "ok")),
        (("a.inscope.example", 22), (False, "port")), (("deny.inscope.example", 443), (False, "noscope")),
        (("other.example", 443), (False, "not-in-scope")), (("oos-canary.invalid", 443), (False, "not-in-scope")),
        (("github.com", 443), (False, "third-party")), (("127.0.0.1", 443), (False, "internal-ip")),
        (("10.1.2.3", 80), (False, "internal-ip")), (("169.254.169.254", 80), (False, "internal-ip")),
        (("93.184.216.99", 443), (False, "not-in-scope")),
        (("rebind.inscope.example", 443), (False, "resolved-internal")),
        (("mixed.inscope.example", 443), (False, "resolved-internal")),
        (("v6.inscope.example", 443), (False, "resolved-internal")),
        (("mapped.inscope.example", 443), (False, "resolved-internal")),
        (("meta.inscope.example", 443), (False, "resolved-internal")),
        (("cgnat.inscope.example", 443), (False, "resolved-internal")),
        (("nx.inscope.example", 443), (False, "dns-fail")), (("", 443), (False, "no-host")),
        (("a.inscope.example", None), (False, "port")),
    ]
    for (h, p), exp in want:
        got = await px.decide(h, p)
        assert got[:2] == exp, f"decide({h},{p}) = {got}, want {exp}"
    for h in ("other.example", "oos-canary.invalid", "deny.inscope.example", "github.com"):
        assert h not in calls, f"resolver called for a scope-denied host {h}"
    assert (await px.decide("a.inscope.example", 443))[2] == "93.184.216.34"

    # integration: a local listener that counts every accepted socket
    seen = {"n": 0, "data": b""}

    async def listener(r, w):
        seen["n"] += 1
        try:
            d = await asyncio.wait_for(r.read(4096), 2)
            seen["data"] += d
            w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
            await w.drain()
        except Exception:
            pass
        w.close()
    lsrv = await asyncio.start_server(listener, "127.0.0.1", 0)
    lport = lsrv.sockets[0].getsockname()[1]

    async def send(pport, raw):
        r, w = await asyncio.open_connection("127.0.0.1", pport)
        w.write(raw)
        await w.drain()
        try:
            data = await asyncio.wait_for(r.read(4096), 3)
        except Exception:
            data = b""
        w.close()
        return data

    # POSITIVE CONTROL (T-32): a test-only instance whose internal-IP check is replaced, so the harness
    # proves it CAN observe an upstream connection through the proxy. Production code has no such switch.
    pos = Proxy("px", root, ports=(lport,), resolver=fake)
    pos._ip_blocked = lambda ip: False
    psrv = await asyncio.start_server(pos.handle, "127.0.0.1", 0)
    pport = psrv.sockets[0].getsockname()[1]
    r = await send(pport, f"CONNECT pos.inscope.example:{lport} HTTP/1.1\r\n\r\nPING".encode())
    await asyncio.sleep(0.3)
    assert r.startswith(b"HTTP/1.1 200 Connection Established"), r
    assert seen["n"] == 1 and b"PING" in seen["data"], seen
    r = await send(pport, f"GET http://pos.inscope.example:{lport}/x?q=1 HTTP/1.1\r\nHost: evil.example\r\n"
                          "Proxy-Connection: keep-alive\r\n\r\n".encode())
    await asyncio.sleep(0.3)
    assert seen["n"] == 2 and b"GET /x?q=1 HTTP/1.1" in seen["data"], seen
    assert f"Host: pos.inscope.example:{lport}".encode() in seen["data"] and b"evil.example" not in seen["data"]
    assert b"Connection: close" in seen["data"] and b"Proxy-Connection" not in seen["data"]
    psrv.close()

    # NEGATIVES with the REAL internal-IP check: the listener must see ZERO new sockets
    neg = Proxy("px", root, ports=(lport, 443, 22), log_path=os.path.join(root, "neg.jsonl"), resolver=fake)
    nsrv = await asyncio.start_server(neg.handle, "127.0.0.1", 0)
    nport = nsrv.sockets[0].getsockname()[1]
    base = seen["n"]
    bad = [f"CONNECT 127.0.0.1:{lport} HTTP/1.1\r\n\r\n",
           f"CONNECT rebind.inscope.example:{lport} HTTP/1.1\r\n\r\n",
           f"CONNECT pos.inscope.example:{lport} HTTP/1.1\r\n\r\n",
           f"CONNECT [::1]:{lport} HTTP/1.1\r\n\r\n",
           f"CONNECT localhost:{lport} HTTP/1.1\r\n\r\n",
           "CONNECT oos-canary.invalid:443 HTTP/1.1\r\n\r\n",
           f"GET http://rebind.inscope.example:{lport}/ HTTP/1.1\r\n\r\n",
           f"GET http://127.0.0.1:{lport}/ HTTP/1.1\r\n\r\n",
           f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{lport}\r\n\r\n",
           f"GET https://pos.inscope.example:{lport}/ HTTP/1.1\r\n\r\n",
           "garbage\r\n\r\n"]
    for raw in bad:
        resp = await send(nport, raw.encode())
        if raw.startswith("CONNECT"):
            assert resp.startswith(b"HTTP/1.1 403"), (raw, resp)
        else:   # a plain-HTTP deny must carry ZERO bytes, never a status a tool could record as the target's
            assert resp == b"", (raw, resp)
    await asyncio.sleep(0.5)
    assert seen["n"] == base, f"a DENIED request opened an upstream socket ({seen['n'] - base})"
    nsrv.close()
    lsrv.close()
    neg.log_fh.flush()
    with open(os.path.join(root, "neg.jsonl")) as fh:
        txt = fh.read()
    rows = [json.loads(x) for x in txt.splitlines()]
    assert len(rows) == len(bad) and all(not x["allowed"] for x in rows), rows
    assert '"allowed": false' in txt
    print(f"scope_proxy selftest: PASS ({len(want)} decision fixtures, positive control 2 upstream "
          f"sockets, {len(bad)} denied requests -> 0 upstream sockets)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--program")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--log")
    ap.add_argument("--rps", type=float, default=3.0)
    ap.add_argument("--max-conn-per-host", type=int, default=4)
    ap.add_argument("--root", default=WS_ROOT)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        asyncio.run(_selftest())
        return 0
    if not a.program or not a.log:
        ap.error("--program and --log are required")
    if not os.path.isfile(os.path.join(a.root, "targets", a.program, "SCOPE.txt")):
        print(f"no SCOPE.txt for {a.program}", file=sys.stderr)
        return 2
    px = Proxy(a.program, a.root, load_ports(), a.rps, a.max_conn_per_host, a.log)
    asyncio.run(serve(px, a.port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
