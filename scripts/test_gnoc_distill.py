"""Tests for gnoc_distill (corpus building, redaction) and gnoc_opus_eval (scoring, voting). No model, no network."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_distill as D  # noqa: E402
import gnoc_opus_eval as E  # noqa: E402


def _line(**kw):
    return json.dumps(kw) + "\n"


class MapCall(unittest.TestCase):
    def test_tools_map_to_gnoc_names_and_args(self):
        self.assertEqual(D.map_call("Bash", {"command": "ls", "timeout": 30000}),
                         ("bash", {"command": "ls", "timeout": 30}))
        self.assertEqual(D.map_call("Read", {"file_path": D.WS + "/SPINE.md", "offset": 5}),
                         ("read_file", {"path": "SPINE.md", "offset": 5}))
        self.assertEqual(D.map_call("Edit", {"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}),
                         ("edit_file", {"path": "/tmp/x", "old": "a", "new": "b"}))
        self.assertEqual(D.map_call("Agent", {"prompt": "go"}), ("delegate", {"task": "go"}))
        self.assertIsNone(D.map_call("SendMessage", {}))

    def test_every_mapped_name_is_a_declared_tool(self):
        for n in ("Bash", "Read", "Write", "Edit", "Grep", "WebSearch", "WebFetch", "Agent"):
            self.assertIn(D.map_call(n, {})[0], D.TOOL_NAMES)


class Redact(unittest.TestCase):
    def test_tokens_headers_and_cookies(self):
        s = ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123 ghp_" + "a" * 30 +
             " eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." "abcdefghijklmn" +
             "\nCookie: session=0123456789abcdefghij; other=1")
        out = D.redact(s)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz0123", out)
        self.assertNotIn("ghp_aaaa", out)
        self.assertNotIn("eyJzdWIi", out)
        self.assertNotIn("0123456789abcdefghij", out)
        self.assertIn("Authorization: Bearer <REDACTED>", out)

    def test_plain_text_untouched(self):
        self.assertEqual(D.redact("git status && ls -la"), "git status && ls -la")


class Session(unittest.TestCase):
    def _session(self, rows, sub=False):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "subagents" if sub else "", "s.jsonl")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.writelines(rows)
        return p

    def rows(self, side=False):
        u = lambda c: _line(type="user", isSidechain=side, message={"role": "user", "content": c})  # noqa: E731
        a = lambda mid, c: _line(type="assistant", isSidechain=side,  # noqa: E731
                                 message={"role": "assistant", "id": mid, "content": c})
        return [u("fix the bug"),
                a("m1", [{"type": "text", "text": "Looking."}]),
                a("m1", [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}]),
                u([{"type": "tool_result", "tool_use_id": "t1", "content": "a.py"}]),
                a("m2", [{"type": "tool_use", "id": "t2", "name": "Bash", "input": {"command": "rm x"}}]),
                u([{"type": "tool_result", "tool_use_id": "t2", "content": "PreToolUse:Bash hook error: blocked"}]),
                a("m3", [{"type": "tool_use", "id": "t3", "name": "Read", "input": {"file_path": "a.py"}}]),
                u([{"type": "tool_result", "tool_use_id": "t3", "content": "print(1)"}])]

    def test_merges_one_message_and_drops_blocked_calls(self):
        msgs = D.session_messages(self._session(self.rows()))
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant", "tool", "assistant", "tool"])
        self.assertEqual(msgs[1]["content"], "Looking.")
        self.assertEqual(msgs[1]["tool_calls"][0]["function"]["name"], "bash")
        self.assertNotIn("rm x", json.dumps(msgs))      # the hook-refused call and its result are gone
        self.assertEqual(msgs[3]["tool_calls"][0]["function"]["name"], "read_file")

    def test_subagent_sidechain_rows_are_kept(self):
        self.assertTrue(D.session_messages(self._session(self.rows(side=True), sub=True)))
        self.assertFalse(D.session_messages(self._session(self.rows(side=True))))

    def test_windows_keep_the_task_and_never_split_a_call_from_its_result(self):
        msgs = D.session_messages(self._session(self.rows()))
        ws = D.windows(msgs, 1)   # force a cut at every assistant turn
        for w in ws:
            self.assertEqual(w[0]["role"], "user")
            self.assertIn("fix the bug", w[0]["content"])
            self.assertEqual(w[1]["role"], "assistant")


class Scoring(unittest.TestCase):
    def test_exact_and_wrong_tool(self):
        t = {"name": "read_file", "arguments": {"path": "SPINE.md"}}
        self.assertEqual(E.score(t, t)["item"], 1.0)
        self.assertEqual(E.score({"name": "bash", "arguments": {"command": "cat SPINE.md"}}, t)["item"], 0.2)
        self.assertEqual(E.score(None, t)["item"], 0.0)

    def test_bash_program_counts(self):
        self.assertEqual(E._prog("cd /x && FOO=1 timeout 5 python3 a.py | head"), "python3")
        hi = E.arg_sim("bash", {"command": "git status"}, {"command": "git status --short"})
        lo = E.arg_sim("bash", {"command": "ls"}, {"command": "git status --short"})
        self.assertGreater(hi, lo)

    def test_vote_picks_the_majority(self):
        a = {"name": "bash", "arguments": {"command": "git status"}}
        b = {"name": "bash", "arguments": {"command": "git status -s"}}
        c = {"name": "read_file", "arguments": {"path": "x"}}
        self.assertEqual(E.pick([c, a, b])["name"], "bash")
        self.assertEqual(E.pick([None, None, a]), None)

    def test_model_for_unknown_host(self):
        self.assertEqual(E.model_for("phone", E.TWINS["desktop"]), E.TWINS["desktop"])


if __name__ == "__main__":
    unittest.main()
