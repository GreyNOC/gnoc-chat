#!/usr/bin/env python3
"""Tests for the MCP client layer (scripts/gnoc_mcp.py).

    python3 scripts/test_gnoc_mcp.py [-v]

No network and no installed MCP server: the stdio server is a tiny script written into a temp
directory, and the HTTP server is a local http.server thread on 127.0.0.1.
"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_mcp as M  # noqa: E402

FAKE_SERVER = r'''
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    mid, method = msg.get("id"), msg.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        out = {"jsonrpc": "2.0", "id": mid,
               "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                          "serverInfo": {"name": "fake", "version": "1"}}}
    elif method == "tools/list":
        out = {"jsonrpc": "2.0", "id": mid,
               "result": {"tools": [{"name": "echo", "description": "Echo the text back",
                                     "inputSchema": {"type": "object",
                                                     "properties": {"text": {"type": "string"}},
                                                     "required": ["text"]}}]}}
    elif method == "tools/call":
        params = msg.get("params") or {}
        args = params.get("arguments") or {}
        if params.get("name") != "echo":
            out = {"jsonrpc": "2.0", "id": mid,
                   "error": {"code": -32602, "message": "unknown tool " + str(params.get("name"))}}
        else:
            out = {"jsonrpc": "2.0", "id": mid,
                   "result": {"content": [{"type": "text", "text": "echo: " + str(args.get("text", ""))}],
                              "isError": False}}
    else:
        out = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    print(json.dumps(out), flush=True)
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-mcp-test-")
        self.saved = (M.WS,)
        M.WS = self.tmp
        self.server_path = os.path.join(self.tmp, "fake_mcp.py")
        with open(self.server_path, "w", encoding="utf-8") as fh:
            fh.write(FAKE_SERVER)
        self.spec = {"transport": "stdio", "command": sys.executable,
                     "args": [self.server_path]}

    def tearDown(self):
        M.WS = self.saved[0]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_config(self, servers):
        M.save_config({"servers": servers})


class Config(Base):
    def test_add_list_remove_round_trip(self):
        M.add_server("fake", self.spec)
        conf = M.load_config()
        self.assertIn("fake", conf["servers"])
        self.assertEqual(conf["servers"]["fake"]["command"], sys.executable)
        self.assertTrue(os.path.isfile(M.config_path()))
        self.assertTrue(M.remove_server("fake"))
        self.assertEqual(M.servers(), {})

    def test_bad_server_name_is_refused(self):
        with self.assertRaises(ValueError):
            M.add_server("bad name!", self.spec)

    def test_cli_add_and_remove(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = M._main(["add", "fake", "--stdio", sys.executable, self.server_path, "--env", "X=1"])
        self.assertEqual(rc, 0)
        conf = M.load_config()["servers"]["fake"]
        self.assertEqual(conf["args"], [self.server_path])
        self.assertEqual(conf["env"], {"X": "1"})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = M._main(["remove", "fake"])
        self.assertEqual(rc, 0)
        self.assertIn("removed", out.getvalue())


class Stdio(Base):
    def test_tools_list_and_call(self):
        tools = M.list_tools(self.spec)
        self.assertEqual([t["name"] for t in tools], ["echo"])
        self.assertEqual(tools[0]["required"], ["text"])
        result = M.call_tool(self.spec, "echo", {"text": "hi"})
        self.assertEqual(result["text"], "echo: hi")
        self.assertFalse(result["isError"])

    def test_text_views(self):
        self._write_config({"fake": self.spec})
        listing = M.servers_text(probe_live=True)
        self.assertIn("MCP SERVERS", listing)
        self.assertIn("tools=1", listing)
        tools = M.tools_text("fake")
        self.assertIn("MCP TOOLS - fake (1)", tools)
        self.assertIn("required: text", tools)
        called = M.call_text("fake", "echo", {"text": "yo"})
        self.assertIn("MCP CALL fake/echo", called)
        self.assertIn("echo: yo", called)

    def test_unknown_server_and_offline_probe(self):
        self.assertIn("no MCP server", M.tools_text("nope"))
        broken = {"transport": "stdio", "command": "/nonexistent/binary"}
        p = M.probe(broken, timeout=2)
        self.assertFalse(p["ok"])
        self.assertTrue(p["error"])
        self._write_config({"broken": broken})
        self.assertIn("OFFLINE", M.servers_text(probe_live=True))

    def test_a_method_error_is_raised_not_swallowed(self):
        with self.assertRaises(M.McpError):
            M.call_tool(self.spec, "no-such-tool", {})

    def test_cli_call(self):
        self._write_config({"fake": self.spec})
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = M._main(["call", "fake", "echo", '{"text": "cli"}'])
        self.assertEqual(rc, 0)
        self.assertIn("echo: cli", out.getvalue())


class Http(Base):
    def setUp(self):
        super().setUp()
        captured = self.requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length") or 0)
                msg = json.loads(self.rfile.read(length) or b"{}")
                captured.append(msg)
                method, mid = msg.get("method"), msg.get("id")
                if method == "initialize":
                    result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                              "serverInfo": {"name": "httpfake", "version": "1"}}
                elif method == "tools/list":
                    result = {"tools": [{"name": "ping", "description": "ping",
                                         "inputSchema": {"type": "object"}}]}
                elif method == "tools/call":
                    result = {"content": [{"type": "text", "text": "pong"}], "isError": False}
                else:
                    result = None
                body = json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                return None

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def test_http_transport_lists_and_calls(self):
        spec = {"transport": "http", "url": f"http://127.0.0.1:{self.port}/mcp"}
        tools = M.list_tools(spec, timeout=5)
        self.assertEqual([t["name"] for t in tools], ["ping"])
        result = M.call_tool(spec, "ping", {}, timeout=5)
        self.assertEqual(result["text"], "pong")
        self.assertEqual(self.requests[0]["method"], "initialize")
        self.assertEqual(self.requests[-1]["method"], "tools/call")


class AgentTool(Base):
    def test_agent_tool_is_registered_and_gated(self):
        import gnoc_agent as A
        self.assertIn("mcp", A.TOOLS)
        self.assertEqual(A.TOOLS["mcp"][2], "unless_auto")
        self.assertIn("mcp", A.HUNT_TOOLS)
        self.assertIn("mcp", A.CODE_TOOLS)

    def test_agent_tool_lists_and_calls(self):
        import gnoc_agent as A
        self._write_config({"fake": self.spec})
        saved = A.WS
        A.WS = self.tmp
        try:
            ctx = A.Ctx({"program": "prog", "sid": "mcp-test"})
            self.assertIn("MCP SERVERS", A.t_mcp(ctx, action="servers"))
            self.assertIn("echo", A.t_mcp(ctx, action="tools", server="fake"))
            called = A.t_mcp(ctx, action="call", server="fake", tool="echo",
                             arguments={"text": "agent"})
            self.assertIn("echo: agent", called)
            self.assertIn("bad arguments", A.t_mcp(ctx, action="tools"))
        finally:
            A.WS = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
