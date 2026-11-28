#!/usr/bin/env python3
"""burp-mcp-cli.py - talk to Burp Suite's MCP Server extension directly over its SSE
transport, without needing a Claude Code session restart.

The extension (PortSwigger official, net.portswigger.mcp) serves ONE MCP endpoint:
    SSE stream :  GET  http://127.0.0.1:9876/          (Accept: text/event-stream)
    messages   :  POST http://127.0.0.1:9876/?sessionId=<id>
Both are registered at the routing ROOT - there is no /sse or /mcp path. The server
does NOT expose streamable-HTTP (the extension calls the SDK's SSE `mcp()` overload).

Usage:
  burp-mcp-cli.py tools
  burp-mcp-cli.py call <tool_name> '<json-arguments>'
  burp-mcp-cli.py repeater <url> [method] [tab_name]

Examples:
  burp-mcp-cli.py tools
  burp-mcp-cli.py call create_repeater_tab '{"content":"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n","targetHostname":"example.com","targetPort":443,"usesHttps":true,"tabName":"t1"}'
  burp-mcp-cli.py repeater https://example.com/ GET my-tab
"""
import json, os, queue, sys, threading, time
from urllib.parse import urlparse
import requests

BASE = os.environ.get("BURP_MCP", "http://127.0.0.1:9876").rstrip("/")


class McpDown(ConnectionError):
    """Burp's MCP server is not reachable (Burp not running, or the extension is off)."""


class Mcp:
    def __init__(self, base=BASE):
        self.base = base
        self.events = queue.Queue()
        self._ep = queue.Queue()
        self._id = 0
        threading.Thread(target=self._sse, daemon=True).start()
        try:
            path = self._ep.get(timeout=20)
        except queue.Empty:
            path = None
        if not path:   # D97: a dead MCP is one clean error, not a thread stack dump plus a 20 s wait
            raise McpDown(f"Burp MCP not reachable at {self.base} (start Burp with the MCP extension: scripts/burp-start.sh)")
        self.post_url = path if path.startswith("http") else self.base + path
        self.request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "burp-mcp-cli", "version": "1.0"}})
        self.request("notifications/initialized", {}, notify=True)

    def _sse(self):
        try:
            r = requests.get(self.base + "/", headers={"Accept": "text/event-stream"},
                             stream=True, timeout=(5, 600))
        except requests.RequestException:
            self._ep.put(None)   # D97: wake __init__ at once with "no endpoint"
            return
        ev, data = None, []
        for raw in r.iter_lines(decode_unicode=True):
            if raw is None:
                continue
            if raw == "":
                if ev or data:
                    p = "\n".join(data)
                    if ev == "endpoint":
                        self._ep.put(p)
                    else:
                        self.events.put(p)
                    ev, data = None, []
                continue
            if raw.startswith("event:"):
                ev = raw[6:].strip()
            elif raw.startswith("data:"):
                data.append(raw[5:].lstrip())

    def request(self, method, params=None, notify=False, timeout=120):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        requests.post(self.post_url, json=msg, timeout=30)
        if notify:
            return None
        dl = time.time() + timeout
        while time.time() < dl:
            try:
                payload = self.events.get(timeout=max(dl - time.time(), 0.1))
            except queue.Empty:
                break
            obj = json.loads(payload)
            if obj.get("id") == msg["id"]:
                return obj
        raise TimeoutError("no MCP response for " + method)

    def call(self, name, args):
        return self.request("tools/call", {"name": name, "arguments": args})


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    m = Mcp()

    if cmd == "tools":
        res = m.request("tools/list", {})
        for t in res["result"]["tools"]:
            print("%-34s %s" % (t["name"], t.get("description", "")[:100]))
        print("\n%d tools" % len(res["result"]["tools"]))

    elif cmd == "call":
        args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
        print(json.dumps(m.call(sys.argv[2], args), indent=2))

    elif cmd == "repeater":
        url = sys.argv[2]
        method = sys.argv[3] if len(sys.argv) > 3 else "GET"
        tab = sys.argv[4] if len(sys.argv) > 4 else None
        u = urlparse(url)
        https = u.scheme == "https"
        port = u.port or (443 if https else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        req = ("%s %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n"
               % (method, path, u.hostname))
        a = {"content": req, "targetHostname": u.hostname, "targetPort": port,
             "usesHttps": https}
        if tab:
            a["tabName"] = tab
        print(json.dumps(m.call("create_repeater_tab", a), indent=2))

    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
