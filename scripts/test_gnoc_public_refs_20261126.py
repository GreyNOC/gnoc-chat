#!/usr/bin/env python3
"""Phase 0, missing references (2026-11-26): every place the public build ran, imported or opened a file that only
the operator's workspace has. Each class pins one replacement or one degrade, with its negative cases. Stdlib
unittest, temp dirs and loopback servers only, no model, no outside network.

    python3 -m pytest -q scripts/test_gnoc_public_refs_20261126.py
"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
import queue
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_mcp  # noqa: E402
import gnoc_missing  # noqa: E402
import gnoc_web  # noqa: E402

_spec = importlib.util.spec_from_file_location("gnoc_models_publicrefs", os.path.join(HERE, "gnoc-models.py"))
assert _spec is not None and _spec.loader is not None
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)

TOOLS = [{"name": "echo", "description": "say it back",
          "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}},
         {"name": "get_proxy_http_history_regex", "description": "burp history",
          "inputSchema": {"type": "object", "properties": {"regex": {"type": "string"}}}}]


class FakeSse:
    """A legacy HTTP+SSE MCP server on loopback. mode: ok | silent (no endpoint) | foreign (endpoint on another
    origin) | plain (not an event stream) | mute (accepts messages, never answers) | inline (answers in the POST)."""

    def __init__(self, mode="ok", history=""):
        self.mode, self.history = mode, history
        self.sessions: dict = {}
        self.seen: list = []
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if fake.mode == "plain":
                    body = b'{"jsonrpc": "2.0"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                sid = str(len(fake.sessions) + 1)
                box: queue.Queue = queue.Queue()
                fake.sessions[sid] = box
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                self.wfile.write(b": keep-alive comment\n\n")
                if fake.mode == "foreign":
                    self.wfile.write(b"event: endpoint\ndata: http://evil.invalid:9/messages\n\n")
                elif fake.mode != "silent":
                    self.wfile.write(f"event: endpoint\ndata: /messages?sessionId={sid}\n\n".encode())
                self.wfile.flush()
                deadline = time.time() + 10
                while time.time() < deadline:
                    try:
                        msg = box.get(timeout=0.2)
                    except queue.Empty:
                        continue
                    if msg is None:
                        return
                    self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
                    self.wfile.flush()

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                msg = json.loads(self.rfile.read(n) or b"{}")
                fake.seen.append(msg)
                reply = fake.reply(msg)
                if fake.mode == "inline" and reply is not None:
                    body = json.dumps(reply).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                box = fake.sessions[self.path.rsplit("sessionId=", 1)[-1]]
                if reply is not None and fake.mode != "mute":
                    if msg.get("method") == "tools/list":
                        # a server REQUEST carrying the same id as ours must not be taken for our reply
                        box.put({"jsonrpc": "2.0", "id": msg["id"], "method": "ping"})
                    box.put(reply)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def reply(self, msg):
        if "id" not in msg or "method" not in msg:
            return None   # a notification, or our answer to the server's ping
        m, rid = msg["method"], msg["id"]
        if m == "initialize":
            res = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                   "serverInfo": {"name": "fake", "version": "1"}}
        elif m == "tools/list":
            res = {"tools": TOOLS}
        elif m == "tools/call":
            name, args = msg["params"]["name"], msg["params"].get("arguments") or {}
            if name == "echo":
                res = {"content": [{"type": "text", "text": args.get("text", "")}]}
            elif name == "get_proxy_http_history_regex":
                res = {"content": [{"type": "text", "text": self.history}]}
            else:
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": f"no tool {name}"}}
        else:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "nope"}}
        return {"jsonrpc": "2.0", "id": rid, "result": res}

    def close(self):
        for box in list(self.sessions.values()):
            box.put(None)
        self.httpd.shutdown()
        self.httpd.server_close()


@contextlib.contextmanager
def absent(path):
    """Make one file read as missing for the duration. These tests pin how the PUBLIC build behaves without an
    operator-only file, and the operator's workspace has that file: hiding it here makes each test establish its own
    premise, so it checks the same behaviour in both editions instead of passing only where the file is gone."""
    import builtins
    import importlib.util as iu
    real_exists, real_isfile, real_open, real_spec = os.path.exists, os.path.isfile, builtins.open, iu.spec_from_file_location
    gone = os.path.realpath(path)

    def hit(p):
        try:
            return os.path.realpath(os.fspath(p)) == gone
        except TypeError:
            return False

    def fake_open(p, *a, **k):
        if hit(p):
            raise FileNotFoundError(2, "No such file or directory", os.fspath(p))
        return real_open(p, *a, **k)

    def fake_spec(name, location=None, *a, **k):
        if location is not None and hit(location):
            return None
        return real_spec(name, location, *a, **k)

    with mock.patch("os.path.exists", lambda p: False if hit(p) else real_exists(p)), \
            mock.patch("os.path.isfile", lambda p: False if hit(p) else real_isfile(p)), \
            mock.patch("builtins.open", fake_open), mock.patch("importlib.util.spec_from_file_location", fake_spec):
        yield


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class SseFixture(unittest.TestCase):
    mode = "ok"

    def setUp(self):
        self.srv = FakeSse(self.mode)
        self.spec = {"transport": "sse", "url": self.srv.url}

    def tearDown(self):
        self.srv.close()


class TheSseTransportSpeaksMcp(SseFixture):
    def test_initialize_and_tools_list(self):
        tools = gnoc_mcp.list_tools(self.spec, timeout=5)
        self.assertEqual([t["name"] for t in tools], ["echo", "get_proxy_http_history_regex"])
        self.assertEqual(tools[0]["required"], ["text"])
        methods = [m.get("method") for m in self.srv.seen]
        self.assertEqual(methods[:3], ["initialize", "notifications/initialized", "tools/list"])
        # the server's same-id ping was answered (from a side thread, so allow it a moment), and not mistaken for
        # the tools/list result, which arrived after it
        deadline = time.time() + 3
        while time.time() < deadline and not any(m.get("result") == {} and "method" not in m for m in self.srv.seen):
            time.sleep(0.05)
        self.assertTrue(any(m.get("result") == {} and "method" not in m for m in self.srv.seen))

    def test_tools_call_round_trip(self):
        out = gnoc_mcp.call_tool(self.spec, "echo", {"text": "hello"}, timeout=5)
        self.assertEqual(out["text"], "hello")
        self.assertFalse(out["isError"])

    def test_a_server_error_is_an_McpError(self):
        with self.assertRaisesRegex(gnoc_mcp.McpError, "no tool nope"):
            gnoc_mcp.call_tool(self.spec, "nope", {}, timeout=5)

    def test_the_operator_script_is_not_needed(self):
        with absent(os.path.join(HERE, "burp-mcp-cli.py")):
            self.assertFalse(os.path.exists(os.path.join(HERE, "burp-mcp-cli.py")))
            self.assertTrue(gnoc_mcp.probe(self.spec, timeout=5)["ok"])


class AnInlineReplyIsAccepted(SseFixture):
    mode = "inline"

    def test(self):
        self.assertEqual(len(gnoc_mcp.list_tools(self.spec, timeout=5)), 2)


class NoEndpointTimesOut(SseFixture):
    mode = "silent"

    def test(self):
        t = time.time()
        with self.assertRaisesRegex(gnoc_mcp.McpError, "no `endpoint` event within"):
            gnoc_mcp.list_tools(self.spec, timeout=1)
        self.assertLess(time.time() - t, 5)


class AForeignEndpointIsRefused(SseFixture):
    mode = "foreign"

    def test(self):
        with self.assertRaisesRegex(gnoc_mcp.McpError, "refused the server's message endpoint"):
            gnoc_mcp.list_tools(self.spec, timeout=3)
        self.assertEqual(self.srv.seen, [])   # nothing was POSTed anywhere

    def test_same_origin_rules(self):
        base = "http://127.0.0.1:9876/"
        self.assertEqual(gnoc_mcp._same_origin(base, "/m?s=1"), "http://127.0.0.1:9876/m?s=1")
        self.assertEqual(gnoc_mcp._same_origin("https://h.example/sse", "https://h.example:443/m"),
                         "https://h.example:443/m")
        for bad in ("http://127.0.0.1:9877/m", "https://127.0.0.1:9876/m", "//other.example/m", ""):
            with self.assertRaises(gnoc_mcp.McpError, msg=bad):
                gnoc_mcp._same_origin(base, bad)


class NotAnEventStream(SseFixture):
    mode = "plain"

    def test(self):
        with self.assertRaisesRegex(gnoc_mcp.McpError, "not an SSE stream.*--transport http"):
            gnoc_mcp.list_tools(self.spec, timeout=3)


class AMuteServerTimesOutPerCall(SseFixture):
    mode = "mute"

    def test(self):
        t = time.time()
        with self.assertRaisesRegex(gnoc_mcp.McpError, "no reply to initialize within 1s"):
            gnoc_mcp.list_tools(self.spec, timeout=1)
        self.assertLess(time.time() - t, 5)


class AnUnreachableServer(unittest.TestCase):
    def test_closed_port(self):
        spec = {"transport": "sse", "url": f"http://127.0.0.1:{free_port()}/"}
        with self.assertRaisesRegex(gnoc_mcp.McpError, "SSE stream unreachable"):
            gnoc_mcp.list_tools(spec, timeout=2)
        self.assertFalse(gnoc_mcp.probe(spec, timeout=2)["ok"])

    def test_bad_url(self):
        with self.assertRaisesRegex(gnoc_mcp.McpError, "must be http"):
            gnoc_mcp.list_tools({"transport": "sse", "url": "ftp://x/"}, timeout=2)


class BurpHistoryUsesTheSseClient(unittest.TestCase):
    def test_found(self):
        srv = FakeSse(history="GET /a?b=1 HTTP/1.1\r\nHost: t.example\r\n\r\n")
        try:
            with mock.patch.object(gnoc_web, "BURP_MCP", srv.url.rstrip("/")):
                self.assertEqual(gnoc_web.burp_history("GET", "https://t.example/a?b=1"), (True, "in Proxy history"))
                self.assertEqual(gnoc_web.burp_history("GET", "https://t.example/zzz")[0], False)
        finally:
            srv.close()

    def test_burp_down_is_a_clear_answer_not_a_crash(self):
        with mock.patch.object(gnoc_web, "BURP_MCP", f"http://127.0.0.1:{free_port()}"):
            found, detail = gnoc_web.burp_history("GET", "https://t.example/")
        self.assertIsNone(found)
        self.assertIn("Burp MCP unreachable at http://127.0.0.1:", detail)
        self.assertNotIn("FileNotFoundError", detail)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-publicrefs-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, rel, body):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)
        return p


class TheBashScopeGateWithoutItsHook(Tmp):
    def setUp(self):
        super().setUp()
        self.put("targets/p/SCOPE.txt", "*.in.example\n")

    def gate(self, cmd, program="p"):
        with mock.patch.object(G, "WS", self.tmp):
            return G._scope_gate_bash(cmd, program)

    def test_out_of_scope_url_is_blocked(self):
        why = self.gate("curl -s https://evil.example/x")
        self.assertIn("evil.example is not allowed by targets/p/SCOPE.txt", why)
        self.assertIn("scope-gate hook is not installed", why)

    def test_one_bad_host_among_good_ones_blocks(self):
        self.assertIsNotNone(self.gate("curl https://a.in.example/ https://evil.example/"))

    def test_in_scope_and_loopback_pass(self):
        self.assertIsNone(self.gate("curl -s https://a.in.example/x"))
        self.assertIsNone(self.gate("curl http://127.0.0.1:8080/ && curl http://localhost:3000/"))

    def test_private_and_noscope_hosts_are_blocked(self):
        self.put("targets/p/NOSCOPE.txt", "admin.in.example\n")
        self.assertIn("internal-ip", self.gate("curl http://10.0.0.5/"))
        self.assertIn("noscope", self.gate("curl https://admin.in.example/"))

    def test_a_client_with_no_url_errs_closed(self):
        self.assertIn("no scheme://host URL", self.gate("curl evil.example"))

    def test_local_work_and_no_programme_pass(self):
        self.assertIsNone(self.gate("ls -la && grep -r https://evil.example ."))
        self.assertIsNone(self.gate("curl https://evil.example/", program=""))

    def test_the_hook_still_wins_when_present(self):
        self.put(".claude/hooks/scope-gate.sh", "exit 0\n")
        self.assertIsNone(self.gate("curl https://evil.example/"))


class HuntSearchWithoutTheIndex(Tmp):
    def test(self):
        ctx = G.Ctx({"sid": "publicrefs"})
        with mock.patch.object(G, "WS", self.tmp):
            out = G.t_hunt_search(ctx, "api.in.example")
        self.assertIn("hunt_search needs the hunt index (scripts/hq), which this edition does not ship", out)
        self.assertIn("grep", out)


class IntelRecallWithoutTheIntelPackage(unittest.TestCase):
    def test(self):
        import gnoc_learn
        # the operator's workspace ships scripts/intel/; a None in sys.modules makes `import intel` raise the same
        # ModuleNotFoundError(name="intel") a release without the package raises
        with mock.patch.dict(sys.modules, {"intel": None, "intel.intake": None}):
            self.assertEqual(gnoc_learn.intel_recall("p", "xss"), [])
            self.assertEqual(gnoc_learn.intel_block("p", "xss"), "")

    def test_the_premise_is_the_missing_package_not_an_empty_book(self):
        import importlib

        import gnoc_learn
        with mock.patch.dict(sys.modules, {"intel": None, "intel.intake": None}):
            self.assertIsNone(gnoc_learn._intel_intake(importlib))

    def test_a_broken_import_inside_the_package_still_raises(self):
        import gnoc_learn
        err = ModuleNotFoundError("No module named 'yaml'", name="yaml")
        fake = mock.Mock(import_module=mock.Mock(side_effect=err))
        with self.assertRaises(ModuleNotFoundError):
            gnoc_learn._intel_intake(fake)


class OperatorOnlyEntryPoints(Tmp):
    # one edition (2026-11-27): the Discord bot and the company run on every install; neither reads the build stamp
    def test_discord_runs_in_every_edition(self):
        import inspect
        import gnoc_discord
        self.assertNotIn("PUBLIC", inspect.getsource(gnoc_discord.main))
        self.assertNotIn("not part of this edition", inspect.getsource(gnoc_discord.main))

    def test_discord_scrubber_fails_closed_with_a_reason(self):
        import gnoc_discord
        with mock.patch.object(gnoc_discord, "WS", self.tmp):
            with self.assertRaisesRegex(RuntimeError, "refuses to send anything it cannot scrub"):
                gnoc_discord.load_scrubber()

    def test_company_runs_in_every_edition(self):
        import inspect
        import gnoc_company
        self.assertNotIn("PUBLIC", inspect.getsource(gnoc_company.main))
        self.assertNotIn("not part of this edition", inspect.getsource(gnoc_company.main))

    def test_note_wording(self):
        self.assertEqual(gnoc_missing.note("x", "y"), "x needs y, which this edition does not ship.")
        self.assertEqual(gnoc_missing.note("x", "y", " do z "), "x needs y, which this edition does not ship. do z")


class FakeOllama:
    def __init__(self, answer):
        self.answer = answer

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(h):
                n = int(h.headers.get("Content-Length") or 0)
                body = json.loads(h.rfile.read(n) or b"{}")
                q = body["messages"][0]["content"]
                a, b = [int(w) for w in q.replace("?", " ").split() if w.isdigit()][:2]
                out = json.dumps({"message": {"role": "assistant", "content": self.answer(a, b)}}).encode()
                h.send_response(200)
                h.send_header("Content-Type", "application/json")
                h.send_header("Content-Length", str(len(out)))
                h.end_headers()
                h.wfile.write(out)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.host = f"127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ModelsTestWithoutTheLab(unittest.TestCase):
    def run_smoke(self, answer=None, host=None, n=2):
        srv = FakeOllama(answer) if answer else None
        out = io.StringIO()
        try:
            with mock.patch.object(M, "HOST", host or srv.host), contextlib.redirect_stdout(out):
                rc = M.cmd_test_smoke("m", n, timeout=5)
        finally:
            if srv:
                srv.close()
        return rc, out.getvalue()

    def test_a_good_model_passes(self):
        rc, out = self.run_smoke(lambda a, b: json.dumps({"sum": a + b}))
        self.assertEqual(rc, 0)
        self.assertIn("json 2/2, correct 2/2", out)
        self.assertIn("score 100/100", out)

    def test_a_wrong_sum_and_prose_fail(self):
        rc, out = self.run_smoke(lambda a, b: json.dumps({"sum": a + b + 1}))
        self.assertEqual(rc, 1)
        self.assertIn("WRONG", out)
        rc, out = self.run_smoke(lambda a, b: "the answer is 5")
        self.assertEqual(rc, 1)
        self.assertIn("NOT JSON", out)

    def test_a_dead_server_is_a_result_not_a_crash(self):
        rc, out = self.run_smoke(host=f"127.0.0.1:{free_port()}")
        self.assertEqual(rc, 1)
        self.assertIn("FAILED (URLError", out)

    def test_cmd_test_routes_to_the_smoke_test(self):
        # neither the Model Lab nor orch_brain ships in a release; the operator's workspace has both, so take them
        # away here rather than rely on where the test happens to run
        import importlib.util as iu
        real_find = iu.find_spec
        with mock.patch.object(M, "LAB", os.path.join(HERE, "no-such-model-lab", "lab.py")), \
                mock.patch("importlib.util.find_spec",
                           lambda name, *a: None if name == "orch_brain" else real_find(name, *a)), \
                mock.patch.object(M, "resolve", lambda m: m), \
                mock.patch.object(M, "cmd_test_smoke", return_value=7) as smoke, \
                mock.patch.object(M, "cmd_test_legacy", side_effect=AssertionError("needs orch_brain")):
            self.assertEqual(M.cmd_test("m", 3), 7)
        smoke.assert_called_once_with("m", 3)


if __name__ == "__main__":
    unittest.main()
