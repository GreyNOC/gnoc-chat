#!/usr/bin/env python3
"""Phase 1 (2026-11-26): provider adapters, prompt caching and real usage.

Every adapter (the OpenAI-compatible wire that existed before, and the new native Anthropic Messages and Gemini
wires) is driven through the real call path, llm_chat -> _llm_chat_once -> _cloud_call -> _wire_chat, against an
in-process HTTP server on 127.0.0.1 that serves the fixtures in scripts/fixtures/providers/. The fixtures are
HAND-BUILT to the shapes in each provider's public API documentation, not captured from a live account: no test
here calls a real provider or uses a real key. Each adapter is covered for text, a tool call, the tool-result round
trip, stream cancel, 429 then retry, context overflow and malformed tool JSON; then redaction, the privacy switch,
the usage-billing regression and the provider config.

    cd scripts && python3 -m pytest -q test_gnoc_phase1_providers.py
"""
import contextlib
import http.server
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_cloud  # noqa: E402
import gnoc_monitor  # noqa: E402
import gnoc_privacy  # noqa: E402
import gnoc_secrets  # noqa: E402
from gnoc_core import llmwire  # noqa: E402
from gnoc_core import providers as P  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "providers")
SECRET = "phase1-" + "s3cr3t" * 4          # registered for redaction in setUpModule; never a real credential
KEY = "test-key-not-a-real-" + "0" * 12     # the fake provider's API key
TOOLS = [{"type": "function", "function": {
    "name": "list_dir", "description": "List a directory.",
    "parameters": {"type": "object", "additionalProperties": False,
                   "properties": {"path": {"type": ["string", "null"], "description": "dir"}}, "required": ["path"]}}}]


def setUpModule():
    gnoc_secrets.register_extra("phase1-test", SECRET)


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


class FakeProvider:
    """A loopback HTTP server that answers each POST with the next scripted response and records every request.
    A response is (status, headers, body) where body is bytes, or a list of byte lines sent one by one with a
    pause between them (a slow stream)."""

    def __init__(self):
        self.script, self.requests = [], []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n)
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                       "body": body})
                status, hdrs, payload, pause = outer.script.pop(0) if outer.script else (500, {}, b"no script", 0)
                self.send_response(status)
                ctype = "text/event-stream" if status == 200 else "application/json"
                self.send_header("Content-Type", hdrs.pop("Content-Type", ctype))
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Connection", "close")
                self.end_headers()
                with contextlib.suppress(OSError):   # the client hung up on a cancelled stream
                    for line in (payload if isinstance(payload, list) else [payload]):
                        self.wfile.write(line)
                        self.wfile.flush()
                        if pause:
                            time.sleep(pause)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def add(self, status=200, body=b"", headers=None, pause=0):
        self.script.append((status, dict(headers or {}), body, pause))

    def body(self, i=-1):
        return json.loads(self.requests[i]["body"])

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ProviderCase(unittest.TestCase):
    """A temp config dir with one custom provider registered on the fake server, the privacy switch open, the
    economy and the retry log captured instead of written to the operator's files."""
    WIRE = "openai"
    MODEL = "deepseek-chat"
    NAME = "fakeopenai"
    PREFIX = "openai"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-phase1-")
        self.srv = FakeProvider()
        self.econ, self.waits = [], []
        self.stack = contextlib.ExitStack()
        st = self.stack
        st.enter_context(mock.patch.object(gnoc_cloud, "CUSTOM", os.path.join(self.tmp, "cloud-providers.json")))
        st.enter_context(mock.patch.object(gnoc_cloud, "SECRETS", os.path.join(self.tmp, "secrets.env")))
        st.enter_context(mock.patch.object(gnoc_privacy, "why_not", return_value=""))
        st.enter_context(mock.patch.object(G, "_econ_llm", lambda m, t: self.econ.append((m, t))))
        st.enter_context(mock.patch.object(G, "_note_retry", lambda *a: None))
        st.enter_context(mock.patch.object(G, "_cloud_wait", lambda s: self.waits.append(s) or False))
        ok, msg = gnoc_cloud.add_provider(self.NAME, self.srv.base, self.MODEL, api_key=KEY, wire=self.WIRE)
        self.assertTrue(ok, msg)
        G.INTERRUPT.clear()

    def tearDown(self):
        G.INTERRUPT.clear()
        self.stack.close()
        self.srv.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def chat(self, messages=None, tools=None, on_text=None, **kw):
        msgs = messages or [{"role": "system", "content": "You are gnoc."}, {"role": "user", "content": "hello"}]
        return G.llm_chat(self.MODEL, self.NAME, msgs, tools=tools, on_text=on_text, retry=False, **kw)

    def serve(self, name, **kw):
        self.srv.add(200, fixture(f"{self.PREFIX}_{name}.sse"), **kw)

    def raw(self, i=-1):
        return self.srv.requests[i]["body"].decode()

    def slow_stream(self):
        """A long stream, one event per 20 ms, so a cancel lands mid-stream."""
        raise NotImplementedError


class AdapterContract:
    """The seven behaviours every adapter must have; mixed into one TestCase per wire."""
    TEXT = ""
    CACHED = 0

    # -- text
    def test_text_streams_and_bills_real_usage(self):
        self.serve("text")
        seen = []
        out = self.chat(on_text=seen.append, think=True)
        self.assertEqual(out["content"], self.TEXT)
        self.assertEqual("".join(s for s in seen if s), self.TEXT)
        self.assertNotIn("usage", out)                       # taken off: it never joins a saved history
        u = G.last_usage()
        self.assertEqual(u["cached_tokens"], self.CACHED)
        self.assertGreater(u["input_tokens"], u["cached_tokens"] - 1)
        self.assertEqual(self.econ, [(f"{self.MODEL}@{self.NAME}", P.usage_tokens(u))])

    # -- tool call, then the tool result round trip
    def test_tool_call_and_result_round_trip(self):
        self.serve("tool")
        first = self.chat(tools=TOOLS)
        calls = first.get("tool_calls") or []
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["function"]["name"], "list_dir")
        self.assertEqual(calls[0]["function"]["arguments"], {"path": "."})
        history = [{"role": "system", "content": "You are gnoc."}, {"role": "user", "content": "what is here?"},
                   first, {"role": "tool", "tool_name": "list_dir", "content": "a.py\nb.py"}]
        self.serve("tool_followup")
        second = self.chat(messages=history, tools=TOOLS)
        self.assertEqual(second["content"], "The directory has 2 files.")
        self.assert_result_paired(self.srv.body(-1), calls[0])

    # -- cancel mid-stream
    def test_stream_cancel_returns_promptly(self):
        self.srv.add(200, self.slow_stream(), pause=0.02)
        seen = []

        def on_text(t):
            if t:
                seen.append(t)
                G.INTERRUPT.set()   # Ctrl-C after the first token
        t0 = time.time()
        out = self.chat(on_text=on_text)
        self.assertLess(time.time() - t0, 3.0, "a cancelled stream must not be read to its end (400 events)")
        self.assertEqual(seen, ["w0 "])
        self.assertEqual(out["content"], "w0")

    # -- 429 honoured, then retried
    def test_429_waits_as_asked_then_retries(self):
        self.srv.add(429, fixture(f"{self.PREFIX}_429.json"), headers=self.RATE_HEADERS)
        self.serve("text")
        out = self.chat()
        self.assertEqual(out["content"], self.TEXT)
        self.assertEqual(len(self.srv.requests), 2)
        self.assertEqual(self.waits, [7.0], "the wait the server asked for, not the 2 s backoff")

    # -- context overflow: one request, a clear error, never retried
    def test_context_overflow_is_reported_not_retried(self):
        self.srv.add(400, fixture(f"{self.PREFIX}_overflow.json"))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.chat()
        self.assertEqual(cm.exception.code, 400)
        self.assertRegex(str(cm.exception), self.OVERFLOW_TEXT)
        self.assertEqual(len(self.srv.requests), 1)
        self.assertEqual(self.waits, [])

    # -- malformed tool JSON reaches run_tools as the marker
    def test_malformed_tool_json_is_marked(self):
        self.serve("malformed")
        out = self.chat(tools=TOOLS)
        args = out["tool_calls"][0]["function"]["arguments"]
        self.assertIn(G.MALFORMED_ARGS, args)
        self.assertEqual(out["tool_calls"][0]["function"]["name"], "read_file")
        self.assertIn("src/", args[G.MALFORMED_ARGS])

    # -- a secret in the conversation never reaches the provider
    def test_a_secret_never_reaches_the_request_body(self):
        self.serve("text")
        history = [{"role": "system", "content": f"system knows {SECRET}"},
                   {"role": "user", "content": f"my token is {SECRET}"},
                   {"role": "assistant", "content": "",
                    "tool_calls": [{"id": "call_1", "function": {"name": "list_dir", "arguments": {"path": SECRET}}}]},
                   {"role": "tool", "tool_name": "list_dir", "content": f"found {SECRET}"},
                   {"role": "user", "content": "go on"}]
        self.chat(messages=history, tools=TOOLS)
        self.assertNotIn(SECRET, self.raw())
        self.assertIn("REDACTED", self.raw())

    # -- the privacy switch stops the call before any byte leaves
    def test_the_privacy_switch_sends_nothing(self):
        self.serve("text")
        with mock.patch.object(gnoc_privacy, "why_not", return_value="cloud is switched off in /privacy"):
            with self.assertRaises(RuntimeError) as cm:
                self.chat()
        self.assertIn("not sent", str(cm.exception))
        self.assertEqual(self.srv.requests, [])

    def test_the_key_travels_in_a_header_never_the_url(self):
        self.serve("text")
        self.chat()
        req = self.srv.requests[0]
        self.assertNotIn(KEY, req["path"])
        self.assertNotIn(KEY, self.raw())
        self.assertIn(KEY, " ".join(req["headers"].values()))


def _sse_lines(events):
    return [e.encode() for e in events]


class OpenAIWire(ProviderCase, AdapterContract):
    TEXT = "Hello from the OpenAI wire."
    CACHED = 2048
    RATE_HEADERS = {"Retry-After": "7"}
    OVERFLOW_TEXT = "maximum context length"

    def slow_stream(self):
        ev = [f'data: {{"choices":[{{"index":0,"delta":{{"content":"w{i} "}}}}]}}\n\n' for i in range(400)]
        return _sse_lines(ev + ["data: [DONE]\n\n"])

    def assert_result_paired(self, body, call):
        msgs = body["messages"]
        asst = next(m for m in msgs if m["role"] == "assistant")
        tool = next(m for m in msgs if m["role"] == "tool")
        self.assertEqual(asst["tool_calls"][0]["id"], call["id"])
        self.assertEqual(tool["tool_call_id"], call["id"])
        self.assertEqual(tool["content"], "a.py\nb.py")

    def test_the_request_is_what_it_was_before_adapters(self):
        self.serve("text")
        self.chat(tools=TOOLS)
        req = self.srv.requests[0]
        self.assertEqual(req["path"], "/v1/chat/completions")
        self.assertEqual(req["headers"]["authorization"], "Bearer " + KEY)
        body = self.srv.body(0)
        self.assertEqual(body["temperature"], 0.3)
        self.assertEqual(body["stream_options"], {"include_usage": True})
        self.assertEqual(body["tools"], TOOLS)


class AnthropicWire(ProviderCase, AdapterContract):
    WIRE = "anthropic"
    MODEL = "claude-sonnet-5-5"
    NAME = "fakeanthropic"
    PREFIX = "anthropic"
    TEXT = "Hello from Claude."
    CACHED = 2048
    RATE_HEADERS = {"retry-after": "7"}
    OVERFLOW_TEXT = "prompt is too long"

    def slow_stream(self):
        ev = ['event: message_start\ndata: {"type":"message_start","message":{"usage":{"input_tokens":5,'
              '"output_tokens":1}}}\n\n',
              'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
              '"content_block":{"type":"text","text":""}}\n\n']
        ev += [f'event: content_block_delta\ndata: {{"type":"content_block_delta","index":0,'
               f'"delta":{{"type":"text_delta","text":"w{i} "}}}}\n\n' for i in range(400)]
        return _sse_lines(ev + ['event: message_stop\ndata: {"type":"message_stop"}\n\n'])

    def assert_result_paired(self, body, call):
        msgs = body["messages"]
        asst = next(m for m in msgs if m["role"] == "assistant")
        kinds = [b["type"] for b in asst["content"]]
        # the signed thinking block goes back first and unchanged, then the text, then the call
        self.assertEqual(kinds, ["thinking", "text", "tool_use"])
        self.assertEqual(asst["content"][0]["signature"], "fixture-signature-tool-turn")
        self.assertEqual(asst["content"][2]["id"], call["id"])
        self.assertEqual(asst["content"][2]["input"], {"path": "."})
        last = msgs[-1]
        self.assertEqual(last["role"], "user")
        res = last["content"][0]
        self.assertEqual((res["type"], res["tool_use_id"], res["content"]), ("tool_result", call["id"], "a.py\nb.py"))
        # the second request reads the prefix the first one wrote
        self.assertEqual(G.last_usage()["cached_tokens"], 1530)

    def test_thinking_streams_and_the_signed_block_is_kept(self):
        self.serve("text")
        thoughts = []
        out = self.chat(think="high", on_think=thoughts.append)
        self.assertEqual("".join(thoughts), "The user greets me; a short hello is enough.")
        self.assertEqual(out[P.THINKING_KEY][0]["signature"], "fixture-signature-text-turn")
        body = self.srv.body(0)
        self.assertEqual(body["thinking"], {"type": "adaptive", "display": "summarized"})
        self.assertEqual(body["output_config"], {"effort": "high"})

    def test_thinking_off_asks_for_none(self):
        self.serve("text")
        self.chat(think=False)
        self.assertNotIn("thinking", self.srv.body(0))

    def test_cache_breakpoints_and_wire_shape(self):
        self.serve("text")
        history = [{"role": "system", "content": "You are gnoc."}, {"role": "user", "content": "first"},
                   {"role": "assistant", "content": "ok"}, {"role": "user", "content": "second"}]
        self.chat(messages=history, tools=TOOLS)
        req = self.srv.requests[0]
        self.assertEqual(req["path"], "/v1/messages")
        self.assertEqual(req["headers"]["x-api-key"], KEY)
        self.assertEqual(req["headers"]["anthropic-version"], P.ANTHROPIC_VERSION)
        body = self.srv.body(0)
        eph = {"type": "ephemeral"}
        self.assertEqual(body["tools"][-1]["cache_control"], eph)            # the tool schemas
        self.assertEqual(body["tools"][0]["input_schema"]["required"], ["path"])
        self.assertEqual(body["system"][-1], {"type": "text", "text": "You are gnoc.", "cache_control": eph})
        users = [m for m in body["messages"] if m["role"] == "user"]
        self.assertEqual(users[-1]["content"][-1]["cache_control"], eph)     # the newest message
        self.assertEqual(users[-2]["content"][-1]["cache_control"], eph)     # and the one before it
        marks = json.dumps(body).count('"cache_control"')
        self.assertLessEqual(marks, 4, "the API allows four breakpoints")
        self.assertNotIn("temperature", body)       # 2026-10-21 refuses sampling parameters
        self.assertEqual(body["max_tokens"], P.DEFAULT_MAX_TOKENS)

    def test_usage_counts_cache_reads_and_writes_as_input(self):
        u = P.normalize_usage("anthropic", {"input_tokens": 30, "cache_creation_input_tokens": 1500,
                                            "cache_read_input_tokens": 200, "output_tokens": 40})
        self.assertEqual((u["input_tokens"], u["cached_tokens"], u["cache_write_tokens"], u["output_tokens"]),
                         (1730, 200, 1500, 40))

    def test_a_mid_stream_error_event_is_an_error_not_a_short_answer(self):
        self.srv.add(200, b'event: message_start\ndata: {"type":"message_start","message":{"usage":{}}}\n\n'
                          b'event: error\ndata: {"type":"error","error":{"type":"overloaded_error",'
                          b'"message":"Overloaded"}}\n\n')
        self.serve("text")
        out = self.chat()   # overloaded before any text: transient, so the same request is sent again
        self.assertEqual(out["content"], self.TEXT)
        self.assertEqual(len(self.srv.requests), 2)

    def test_an_unanswered_tool_use_gets_a_not_run_result(self):
        _, msgs = P.anthropic_messages([
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "", "tool_calls": [{"id": "call.1", "function": {"name": "x",
                                                                                            "arguments": "{}"}}]},
            {"role": "user", "content": "never mind"}])
        res = msgs[2]["content"][0]
        self.assertEqual((res["type"], res["tool_use_id"], res["is_error"]), ("tool_result", "call_1", True))
        self.assertEqual(msgs[2]["content"][1]["text"], "never mind")


class GeminiWire(ProviderCase, AdapterContract):
    WIRE = "gemini"
    MODEL = "gemini-2.5-flash"
    NAME = "fakegemini"
    PREFIX = "gemini"
    TEXT = "Hello from Gemini."
    CACHED = 2048
    RATE_HEADERS: dict = {}      # Gemini says how long in the body (RetryInfo.retryDelay "7s"), not in a header
    OVERFLOW_TEXT = "(?s)context length exceeded.*input token count"

    def slow_stream(self):
        ev = [f'data: {{"candidates":[{{"content":{{"parts":[{{"text":"w{i} "}}],"role":"model"}}}}]}}\n\n'
              for i in range(400)]
        return _sse_lines(ev)

    def assert_result_paired(self, body, call):
        contents = body["contents"]
        model = next(c for c in contents if c["role"] == "model")
        fc = model["parts"][0]
        self.assertEqual(fc["functionCall"], {"name": "list_dir", "args": {"path": "."}})
        self.assertEqual(fc["thoughtSignature"], "fixture-thought-signature-list-dir")   # returned on its part
        resp = contents[-1]["parts"][0]["functionResponse"]
        self.assertEqual(resp, {"name": "list_dir", "response": {"result": "a.py\nb.py"}})
        self.assertEqual(G.last_usage()["cached_tokens"], 896)

    def test_thoughts_stream_and_usage_counts_them_as_output(self):
        self.serve("text")
        thoughts = []
        self.chat(think=True, on_think=thoughts.append)
        self.assertIn("a short reply fits", "".join(thoughts))
        u = G.last_usage()
        self.assertEqual((u["input_tokens"], u["cached_tokens"], u["output_tokens"], u["reasoning_tokens"]),
                         (2100, 2048, 36, 30))
        cfg = self.srv.body(0)["generationConfig"]
        self.assertEqual(cfg["thinkingConfig"], {"includeThoughts": True, "thinkingBudget": -1})

    def test_wire_shape_and_schema_subset(self):
        self.serve("text")
        self.chat(tools=TOOLS)
        req = self.srv.requests[0]
        self.assertEqual(req["path"], "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse")
        self.assertEqual(req["headers"]["x-goog-api-key"], KEY)
        body = self.srv.body(0)
        self.assertEqual(body["systemInstruction"], {"parts": [{"text": "You are gnoc."}]})
        decl = body["tools"][0]["functionDeclarations"][0]
        self.assertNotIn("additionalProperties", json.dumps(decl))   # outside Gemini's schema subset
        self.assertEqual(decl["parameters"]["properties"]["path"], {"nullable": True, "type": "STRING",
                                                                    "description": "dir"})


class UsageIsBilledNotEstimated(unittest.TestCase):
    """REGRESSION (Phase-0 audit): _openai_chat read the usage block but never returned it, so the economy billed
    every cloud and split call at characters/4. These fail on the old code: the debit was _approx_tokens(...)."""

    def setUp(self):
        self.srv = FakeProvider()
        self.econ = []
        self.p = [mock.patch.object(G, "_econ_llm", lambda m, t: self.econ.append((m, t))),
                  mock.patch.object(G, "SPLIT_URL", self.srv.base)]
        for p in self.p:
            p.start()
        G.INTERRUPT.clear()

    def tearDown(self):
        for p in self.p:
            p.stop()
        self.srv.close()

    def test_the_openai_result_carries_usage(self):
        self.srv.add(200, fixture("openai_text.sse"))
        out = G._openai_chat([{"role": "user", "content": "x"}], None, None, None, url=self.srv.base + "/v1/x")
        self.assertEqual(out["usage"]["prompt_tokens"], 2100)
        self.assertEqual(out["usage"]["cached_tokens"], 2048)

    def test_a_split_call_bills_the_real_tokens(self):
        self.srv.add(200, fixture("openai_text.sse"))
        msgs = [{"role": "user", "content": "hello"}]
        G.llm_chat("split", "split", msgs, retry=False)
        self.assertEqual(self.econ, [("split", 2109)])
        self.assertNotEqual(2109, G._approx_tokens(msgs, "Hello from the OpenAI wire."))

    def test_no_usage_block_falls_back_to_the_estimate(self):
        self.srv.add(200, b'data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n\n')
        msgs = [{"role": "user", "content": "hello there, " * 40}]
        G.llm_chat("split", "split", msgs, retry=False)
        self.assertEqual(self.econ, [("split", G._approx_tokens(msgs, "hi"))])

    def test_the_session_tally_keeps_cached_tokens(self):
        gnoc_monitor.reset_session()
        gnoc_monitor.record("m", "h", 100, 5, 0.1, cached=80)
        self.assertEqual(gnoc_monitor.session_usage()["cached"], 80)


class ProviderConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-phase1-cfg-")
        self.custom = os.path.join(self.tmp, "cloud-providers.json")
        self.p = [mock.patch.object(gnoc_cloud, "CUSTOM", self.custom),
                  mock.patch.object(gnoc_cloud, "SECRETS", os.path.join(self.tmp, "secrets.env"))]
        for p in self.p:
            p.start()

    def tearDown(self):
        for p in self.p:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_an_existing_config_without_a_wire_is_openai(self):
        with open(self.custom, "w") as f:
            json.dump({"oldone": {"base_url": "http://127.0.0.1:9/v1", "default": "m", "api_key": KEY}}, f)
        self.assertEqual(gnoc_cloud.wire_for("oldone"), "openai")
        url, mdl, hdrs = gnoc_cloud.endpoint("oldone")
        self.assertEqual(url, "http://127.0.0.1:9/v1/v1/chat/completions")   # the path rule it always had
        self.assertEqual(hdrs["Authorization"], "Bearer " + KEY)

    def test_an_openai_entry_is_written_as_before(self):
        ok, _ = gnoc_cloud.add_provider("plain", "http://127.0.0.1:9", "m", api_key=KEY)
        self.assertTrue(ok)
        with open(self.custom) as f:
            self.assertNotIn("wire", json.load(f)["plain"])
        self.assertEqual(oct(os.stat(self.custom).st_mode & 0o777), "0o600")

    def test_an_unknown_wire_is_refused_and_a_bad_stored_one_skipped(self):
        ok, msg = gnoc_cloud.add_provider("x", "http://127.0.0.1:9", "m", api_key=KEY, wire="cohere")
        self.assertFalse(ok)
        self.assertIn("wire", msg)
        with open(self.custom, "w") as f:
            json.dump({"odd": {"base_url": "http://127.0.0.1:9", "default": "m", "wire": "cohere"}}, f)
        self.assertNotIn("odd", gnoc_cloud.providers())

    def test_builtins_and_their_keys_use_the_same_store(self):
        self.assertEqual(gnoc_cloud.wire_for("anthropic"), "anthropic")
        self.assertEqual(gnoc_cloud.wire_for("gemini"), "gemini")
        self.assertEqual(gnoc_cloud.wire_for("deepseek"), "openai")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            ok, _ = gnoc_cloud.save_key("anthropic", KEY)
            self.assertTrue(ok)
            with open(gnoc_cloud.SECRETS) as f:
                self.assertIn("ANTHROPIC_API_KEY=" + KEY, f.read())
            self.assertEqual(oct(os.stat(gnoc_cloud.SECRETS).st_mode & 0o777), "0o600")
            url, mdl, hdrs = gnoc_cloud.endpoint("anthropic")
            os.environ.pop("ANTHROPIC_API_KEY", None)
        self.assertTrue(url.endswith("/v1/messages"))
        self.assertEqual(hdrs["x-api-key"], KEY)
        self.assertNotIn("Authorization", hdrs)

    def test_no_key_no_request(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GEMINI_API_KEY", None)
            with self.assertRaises(RuntimeError) as cm:
                gnoc_cloud.endpoint("gemini")
        self.assertIn("/gemini api", str(cm.exception))   # a built-in provider has its own /<name> command

    def test_check_speaks_each_wire(self):
        srv = FakeProvider()
        try:
            for wire, body, want in (
                    ("anthropic", b'{"content":[{"type":"text","text":"OK"}]}', "/v1/messages"),
                    ("gemini", b'{"candidates":[{"content":{"parts":[{"text":"OK"}]}}]}',
                     "/v1beta/models/m:generateContent"),
                    ("openai", b'{"choices":[{"message":{"content":"OK"}}]}', "/v1/chat/completions")):
                gnoc_cloud.add_provider("chk" + wire, srv.base, "m", api_key=KEY, wire=wire)
                srv.add(200, body, headers={"Content-Type": "application/json"})
                ok, msg = gnoc_cloud.check("chk" + wire)
                self.assertTrue(ok, msg)
                self.assertIn("'OK'", msg)
                self.assertEqual(srv.requests[-1]["path"], want)
        finally:
            srv.close()

    def test_cloud_add_takes_a_wire(self):
        out = []
        agent = mock.Mock()
        with mock.patch.object(G, "say", lambda t: out.append(str(t))), \
                mock.patch.object(gnoc_cloud, "check", return_value=(False, "offline")):
            G.handle_slash(agent, "/cloud add myproxy http://127.0.0.1:9 claude-haiku-5-5 - wire=anthropic", {})
        self.assertEqual(gnoc_cloud.wire_for("myproxy"), "anthropic")
        self.assertTrue(any("anthropic wire" in o for o in out), out)


class TransientErrors(unittest.TestCase):
    def _http(self, code, body=""):
        import io
        return urllib.error.HTTPError("http://x", code, f"x: {body}", {}, io.BytesIO(b""))

    def test_rate_limit_and_overload_are_transient_a_spend_cap_is_not(self):
        self.assertTrue(llmwire._transient_cloud_error(self._http(429)))
        self.assertTrue(llmwire._transient_cloud_error(self._http(529)))
        self.assertFalse(llmwire._transient_cloud_error(self._http(429, '"error_code":"enforced_spend_limit_reached"')))
        self.assertFalse(llmwire._transient_cloud_error(self._http(400, "prompt is too long")))

    def test_retry_after_is_capped(self):
        e = urllib.error.HTTPError("http://x", 429, "x", {"Retry-After": "3600"}, None)
        self.assertEqual(P.retry_after(e), P.RETRY_AFTER_CAP)
        self.assertIsNone(P.retry_after(urllib.error.HTTPError("http://x", 429, "x", {}, None)))

    def test_a_long_retry_wait_is_cut_short_by_ctrl_c(self):
        G.INTERRUPT.clear()
        threading.Timer(0.1, G.INTERRUPT.set).start()
        t0 = time.time()
        self.assertTrue(G._cloud_wait(10))
        self.assertLess(time.time() - t0, 2)
        G.INTERRUPT.clear()


class MalformedStreams(unittest.TestCase):
    def test_a_garbage_chunk_is_an_error(self):
        srv = FakeProvider()
        try:
            srv.add(200, b"data: {not json\n\n")
            with self.assertRaises(RuntimeError) as cm:
                P.ADAPTERS["gemini"].chat([{"role": "user", "content": "x"}], None, url=srv.base + "/g",
                                          model="m", headers={}, timeout=5)
            self.assertIn("malformed stream chunk", str(cm.exception))
        finally:
            srv.close()

    def test_a_silent_server_times_out(self):
        srv = FakeProvider()
        try:
            srv.add(200, [b"", b'data: {"candidates":[]}\n\n'], pause=2.0)
            with self.assertRaises(OSError):
                P.ADAPTERS["gemini"].chat([{"role": "user", "content": "x"}], None, url=srv.base + "/g",
                                          model="m", headers={}, timeout=0.5)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
