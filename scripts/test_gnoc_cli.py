"""The `gnoc` CLI script itself: the surface the agent tells people to use, and the simple chat path.

Both defects below were found by driving the CLI during the 2026-10-25 soak, not by reading it.
"""
import importlib.util
import io
import json
import os
import sys
import unittest
from unittest import mock

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# the CLI has no .py extension, so spec_from_file_location needs the loader named explicitly
import importlib.machinery  # noqa: E402
_path = os.path.join(WS, "scripts/gnoc")
_spec = importlib.util.spec_from_loader("gnoc_cli", importlib.machinery.SourceFileLoader("gnoc_cli", _path))
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SimpleChat(unittest.TestCase):
    """gnoc chat --simple printed a bare "bot>" every time: a qwen3.5 build with thinking on puts its
    whole answer in the thinking field, and chat_once_routed never asked for no-thinking."""

    def _reply(self, payload):
        return lambda req, timeout=None: _Resp(json.dumps(payload).encode())

    def test_it_asks_for_no_thinking(self):
        seen = {}

        def capture(req, timeout=None):
            seen["body"] = json.loads(req.data.decode())
            return _Resp(json.dumps({"message": {"content": "an answer"}}).encode())
        with mock.patch("urllib.request.urlopen", capture):
            ans, _ = C.chat_once_routed("q", [], "http://x/api/chat", "m")
        self.assertEqual(ans, "an answer")
        self.assertIs(seen["body"].get("think"), False, "simple chat must ask for no thinking")

    def test_an_answer_that_arrives_as_reasoning_is_still_shown(self):
        with mock.patch("urllib.request.urlopen",
                        self._reply({"message": {"content": "", "thinking": "the real answer"}})):
            ans, _ = C.chat_once_routed("q", [], "http://x/api/chat", "m")
        self.assertEqual(ans, "the real answer", "an empty content must fall back to the reasoning text")

    def test_think_tags_are_still_stripped_from_content(self):
        with mock.patch("urllib.request.urlopen",
                        self._reply({"message": {"content": "<think>hmm</think>  visible"}})):
            ans, _ = C.chat_once_routed("q", [], "http://x/api/chat", "m")
        self.assertEqual(ans, "visible")


class CommandSurface(unittest.TestCase):
    def test_commands_the_agent_advises_are_dispatchable(self):
        """gnoc gpus was advised by the agent in three places and did not exist (2026-10-25)."""
        src = open(os.path.join(WS, "scripts/gnoc"), encoding="utf-8").read()
        for cmd in ("gpus", "soak"):
            self.assertIn(f'"{cmd}": lambda', src, f"gnoc {cmd} is not in the dispatch table")
            self.assertIn(f"  gnoc {cmd}", src, f"gnoc {cmd} is not documented in help")

    def test_do_gpus_runs_without_a_live_host(self):
        out = io.StringIO()
        with mock.patch.object(C, "_chat_url_for", lambda h: "http://127.0.0.1:1/api/chat"), \
             mock.patch("sys.stdout", out):
            rc = C.do_gpus([])
        self.assertEqual(rc, 0)
        body = out.getvalue()
        self.assertIn("ROLES", body)
        self.assertIn("HOSTS", body)


class DeepcodeFlags(unittest.TestCase):
    """gnoc chat speaks deepcode's flag dialect (-p/-x/-r/-f/-l/-v) without sending those flags to the model."""

    def test_prompt_and_exec(self):
        self.assertEqual(C._parse_chat_flags(["-p", "hi"])["prompt"], "hi")
        f = C._parse_chat_flags(["-x", "-p", "hi"])
        self.assertTrue(f["exec"] and f["prompt"] == "hi")
        self.assertTrue(C._parse_chat_flags(["-x", "hi"])["exec"])
        self.assertFalse(C._parse_chat_flags(["hi"])["exec"])  # a plain message is still a one-shot

    def test_resume_fork_last(self):
        self.assertEqual(C._parse_chat_flags(["-r", "abc123"])["resume"], "abc123")
        self.assertEqual(C._parse_chat_flags(["-r"])["resume"], "", "bare -r means the session picker")
        self.assertEqual(C._parse_chat_flags(["-f"])["fork"], "last", "bare -f forks the most recent")
        self.assertEqual(C._parse_chat_flags(["-f", "abc123"])["fork"], "abc123")
        self.assertEqual(C._parse_chat_flags(["-l"])["resume"], "last")
        self.assertEqual(C._parse_chat_flags(["-c"])["resume"], "last")

    def test_bad_combinations_exit(self):
        for bad in (["-x"], ["-p"], ["-p", "hi", "extra"], ["-r", "abc123", "-f", "last"], ["-r", "-r"]):
            with self.assertRaises(SystemExit, msg=f"{bad!r} must be a usage error"):
                C._parse_chat_flags(bad)

    def test_piped_stdin_rides_along_as_context(self):
        old = sys.stdin
        sys.stdin = io.StringIO("  log line one\nlog line two\n")
        try:
            out = C._stdin_context("explain this")
        finally:
            sys.stdin = old
        self.assertTrue(out.startswith("explain this"))
        self.assertIn("<context from stdin>", out)
        self.assertIn("log line one", out)
        self.assertEqual(C._stdin_context("explain this"), "explain this")  # empty stdin adds nothing


if __name__ == "__main__":
    unittest.main()
