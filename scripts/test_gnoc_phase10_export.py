#!/usr/bin/env python3
"""Phase 10 (2026-11-26): `gnoc export trajectories` and the headless batch runner. Each class pins one promise of
the export (the schema each line obeys, the redaction applied by default, the refusals) or of the batch (a held
action is held and never touches disk; the pool is bounded; a timeout and a Ctrl-C kill the run). Stdlib unittest,
temp dirs only, a scripted model, no network.

    python3 -m pytest -q scripts/test_gnoc_phase10_export.py
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_learn as L  # noqa: E402
import gnoc_secrets  # noqa: E402
import gnoc_trajectories as T  # noqa: E402

SECRET = "zq9-Pk3vX7mL2nB8wR4tY6uE"   # registered as a known secret value for the test, nothing real


def call(name, **args):
    return {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": name, "arguments": args}}]}


def record(ts="2026-11-25T10:00:00+00:00", program=None, messages=None, outcome=None, **extra):
    r = {"ts": ts, "program": program, "outcome": outcome or {"ok": 1, "failed": 0, "verdict": False,
                                                                "receipt": False, "good": True},
         "messages": messages if messages is not None else [
             {"role": "user", "content": f"fetch https://api.acmecorp-test.com/v1 with key {SECRET} from "
                                         "/home/alice/proj/notes.md"},
             call("http", url="https://api.acmecorp-test.com/v1", headers={"Authorization": "Bearer " + SECRET}),
             {"role": "tool", "content": "200 OK from 10.20.30.40 (api.acmecorp-test.com)", "tool_name": "http"},
             {"role": "assistant", "content": "Done: api.acmecorp-test.com answered from 10.20.30.40; see "
                                              "gnoc_learn.py:817 and logger.info."}]}
    r.update(extra)
    return r


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p10-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.saved_env = {k: os.environ.get(k) for k in ("HOME",)}
        os.environ["HOME"] = self.home
        gnoc_secrets.register_extra("TEST_KEY", SECRET)

    def tearDown(self):
        gnoc_secrets._EXTRA.pop(SECRET, None)
        gnoc_secrets._EXTRA_VER[0] += 1
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, records, name="traj.jsonl", raw_lines=()):
        p = os.path.join(self.tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
            for ln in raw_lines:
                f.write(ln + "\n")
        return p

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        code = T.cmd_trajectories(argv, out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def export(self, records, fmt, **kw):
        kw.setdefault("home", "/home/alice")
        kw.setdefault("user", "alice")
        return T.export(self.write(records), fmt, **kw)


class TheExportSchemaIsValid(Base):
    def test_openai_lines_are_chat_finetune_lines_with_paired_ids(self):
        lines, counts = self.export([record()], "openai")
        self.assertEqual(counts["exported"], 1)
        rec = json.loads(lines[0])
        T.validate_openai(rec)
        self.assertEqual(list(rec), ["messages"])
        msgs = rec["messages"]
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant", "tool", "assistant"])
        tc = msgs[1]["tool_calls"][0]
        self.assertEqual(tc["type"], "function")
        self.assertIsInstance(tc["function"]["arguments"], str)
        self.assertIsInstance(json.loads(tc["function"]["arguments"]), dict)
        self.assertEqual(msgs[2]["tool_call_id"], tc["id"])

    def test_sharegpt_lines_pair_function_calls_with_observations(self):
        lines, _ = self.export([record(held=[{"tool": "write_file", "args": "{\"path\": \"x\"}"}])], "sharegpt")
        rec = json.loads(lines[0])
        T.validate_sharegpt(rec)
        self.assertEqual([t["from"] for t in rec["conversations"]], ["human", "function_call", "observation", "gpt"])
        fc = json.loads(rec["conversations"][1]["value"])
        self.assertEqual(fc["name"], "http")
        self.assertIsInstance(fc["arguments"], dict)
        self.assertEqual(rec["held"], [{"tool": "write_file", "args": "{\"path\": \"x\"}"}])
        self.assertTrue(rec["outcome"]["good"])

    def test_string_and_malformed_arguments_still_make_valid_json(self):
        msgs = [{"role": "user", "content": "go"},
                {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "bash", "arguments": "{\"command\": \"ls\"}"}},
                    {"function": {"name": "bash", "arguments": "not json at all"}}]},
                {"role": "tool", "content": "a"}, {"role": "tool", "content": "b"},
                {"role": "assistant", "content": "ok"}]
        lines, counts = self.export([record(messages=msgs)], "openai")
        self.assertEqual(counts["exported"], 1)
        calls = json.loads(lines[0])["messages"][1]["tool_calls"]
        self.assertEqual(json.loads(calls[0]["function"]["arguments"]), {"command": "ls"})
        self.assertEqual(json.loads(calls[1]["function"]["arguments"]), {"_raw": "not json at all"})

    def test_a_broken_structure_is_skipped_not_emitted(self):
        orphan = [{"role": "user", "content": "x"}, {"role": "tool", "content": "who called me"},
                  {"role": "assistant", "content": "y"}]
        unanswered = [{"role": "user", "content": "x"}, call("bash", command="ls")]
        for fmt in T.FORMATS:
            lines, counts = self.export([record(messages=orphan), record(messages=unanswered), record()], fmt)
            self.assertEqual(counts["invalid"], 2, fmt)
            self.assertEqual(len(lines), 1, fmt)

    def test_validators_refuse_bad_lines(self):
        good = json.loads(self.export([record()], "openai")[0][0])
        bad_id = json.loads(json.dumps(good))
        bad_id["messages"][2]["tool_call_id"] = "call_999"
        bad_args = json.loads(json.dumps(good))
        bad_args["messages"][1]["tool_calls"][0]["function"]["arguments"] = "{not json"
        extra = dict(good, metadata={"x": 1})
        for rec in (bad_id, bad_args, extra, {"messages": []}):
            with self.assertRaises(T.Invalid):
                T.validate_openai(rec)
        with self.assertRaises(T.Invalid):
            T.validate_sharegpt({"conversations": [{"from": "bot", "value": "hi"}]})
        with self.assertRaises(T.Invalid):
            T.validate_sharegpt({"conversations": [{"from": "human", "value": "hi"},
                                                   {"from": "observation", "value": "nobody asked"}]})

    def test_unreadable_lines_and_empty_records_are_counted(self):
        p = self.write([record(), record(messages=[])], raw_lines=["{not json", "[1, 2]"])
        lines, counts = T.export(p, "openai")
        self.assertEqual((len(lines), counts["unreadable"], counts["empty"]), (1, 2, 1))

    def test_a_logged_trajectory_exports_from_the_default_source(self):
        """log_trajectory and the exporter share one schema: what the chat logs is what the export reads."""
        with L.isolated(os.path.join(self.tmp, "book")):
            os.makedirs(L.DIR, exist_ok=True)
            msgs = record()["messages"]
            L.log_trajectory(msgs, None, L.turn_outcome(msgs))
            code, out, err = self.run_cli(["--format", "openai"])
        self.assertEqual(code, 0, err)
        T.validate_openai(json.loads(out.splitlines()[0]))
        self.assertIn("exported 1 trajectories (openai, redaction on)", err)

    def test_trajectory_record_keeps_the_logged_shape(self):
        msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "u" * 5000}]
        rec = L.trajectory_record(msgs, "p", {"good": True})
        self.assertEqual(set(rec), {"ts", "program", "outcome", "messages"})
        self.assertEqual([m["role"] for m in rec["messages"]], ["user"])
        self.assertEqual(len(rec["messages"][0]["content"]), 4000)


class RedactionIsAppliedByDefault(Base):
    def everything(self, line):
        return json.dumps(json.loads(line))

    def test_secrets_hosts_ips_and_home_paths_are_gone_from_content_and_arguments(self):
        for fmt in T.FORMATS:
            lines, _ = self.export([record()], fmt)
            blob = lines[0]
            for leak in (SECRET, "acmecorp-test.com", "10.20.30.40", "/home/alice", "alice"):
                self.assertNotIn(leak, blob, f"{fmt}: {leak} leaked")
            self.assertIn("host-1.invalid", blob)
            self.assertIn("198.51.100.1", blob)
            self.assertIn("~/proj/notes.md", blob)

    def test_one_host_gets_one_placeholder_and_two_hosts_get_two(self):
        msgs = [{"role": "user", "content": "compare one.acmecorp-test.com, two.acmecorp-test.com and "
                                            "one.acmecorp-test.com"},
                {"role": "assistant", "content": "done"}]
        lines, _ = self.export([record(messages=msgs)], "openai")
        text = json.loads(lines[0])["messages"][0]["content"]
        self.assertEqual(text, "compare host-1.invalid, host-2.invalid and host-1.invalid")

    def test_the_placeholder_is_stable_across_lines_of_one_export(self):
        lines, _ = self.export([record(), record()], "openai")
        self.assertEqual(lines[0], lines[1])

    def test_tool_call_arguments_are_redacted_including_secret_named_keys(self):
        msgs = [{"role": "user", "content": "log in"},
                call("http", url="https://login.acmecorp-test.com/", password="hunter2hunter2",
                     headers={"Cookie": "sid=abcdef"}, data={"note": "from 192.168.7.9"}),
                {"role": "tool", "content": "ok"}, {"role": "assistant", "content": "in"}]
        lines, _ = self.export([record(messages=msgs)], "openai")
        args = json.loads(json.loads(lines[0])["messages"][1]["tool_calls"][0]["function"]["arguments"])
        self.assertEqual(args["password"], "[REDACTED]")
        self.assertEqual(args["headers"]["Cookie"], "[REDACTED]")
        self.assertEqual(args["url"], "https://host-1.invalid/")
        self.assertEqual(args["data"]["note"], "from 198.51.100.1")

    def test_secret_shapes_are_redacted_without_being_known(self):
        # fake secrets built from pieces: the release leak scan flags the literal shapes in shipped code
        aws = "AK" + "IAABCDEFGHIJKLMNOP"
        pk = "PRIVATE " + "KEY-----"
        msgs = [{"role": "user", "content": aws + " and ghp_" + "a" * 36 + " and "
                                            "-----BEGIN " + pk + "\nMIIabc\n-----END " + pk},
                {"role": "assistant", "content": "ok"}]
        lines, _ = self.export([record(messages=msgs)], "openai")
        text = json.loads(lines[0])["messages"][0]["content"]
        self.assertNotIn(aws, text)
        self.assertNotIn("ghp_aaaa", text)
        self.assertNotIn("MIIabc", text)

    def test_code_is_not_mistaken_for_hosts_or_addresses(self):
        msgs = [{"role": "user", "content": "gnoc_learn.py:817, logger.info, self.app, x[::2], x[1::2], 12:30:45, "
                                            "README.md, localhost:8080, 127.0.0.1, example.com"},
                {"role": "assistant", "content": "ok"}]
        lines, _ = self.export([record(messages=msgs)], "openai")
        self.assertEqual(json.loads(lines[0])["messages"][0]["content"], msgs[0]["content"])

    def test_ipv6_and_email_and_url_userinfo(self):
        msgs = [{"role": "user", "content": "2606:4700:4700::1111 then ::1, mail bob@acmecorp-test.com, "
                                            "https://bob:pw@acmecorp-test.com/x"},
                {"role": "assistant", "content": "ok"}]
        lines, _ = self.export([record(messages=msgs)], "openai")
        text = json.loads(lines[0])["messages"][0]["content"]
        self.assertEqual(text, "2001:db8::1 then ::1, mail user-1@host-1.invalid, https://[REDACTED]@host-1.invalid/x")

    def test_the_program_handle_is_replaced_everywhere(self):
        msgs = [{"role": "user", "content": "hunt acmeprog: targets/acmeprog/SCOPE.txt"},
                {"role": "assistant", "content": "acmeprog has no scope file"}]
        lines, _ = self.export([record(program="acmeprog", messages=msgs)], "sharegpt")
        self.assertNotIn("acmeprog", lines[0])
        rec = json.loads(lines[0])
        self.assertEqual(rec["program"], "program-1")
        self.assertIn("targets/program-1/SCOPE.txt", rec["conversations"][0]["value"])

    def test_the_allowlist_file_and_allow_flag_keep_a_host(self):
        os.makedirs(os.path.join(self.home, ".gnoc"))
        with open(os.path.join(self.home, ".gnoc", "export-allowlist.txt"), "w") as f:
            f.write("# my own hosts\nacmecorp-test.com\n10.20.30.0/24\n")
        p = self.write([record()])
        code, out, err = self.run_cli(["--format", "openai", "--from", p])
        self.assertEqual(code, 0, err)
        self.assertIn("api.acmecorp-test.com", out)   # a subdomain of an allowed host is allowed
        self.assertIn("10.20.30.40", out)
        self.assertNotIn(SECRET, out)                  # the allowlist never lets a secret through
        os.remove(os.path.join(self.home, ".gnoc", "export-allowlist.txt"))
        code, out, _ = self.run_cli(["--format", "openai", "--from", p, "--allow", "other.example,acmecorp-test.com"])
        self.assertIn("api.acmecorp-test.com", out)
        self.assertNotIn("10.20.30.40", out)

    def test_redact_is_a_no_op_alias_and_no_redact_warns(self):
        p = self.write([record()])
        _, plain, _ = self.run_cli(["--format", "openai", "--from", p])
        _, alias, _ = self.run_cli(["--format", "openai", "--from", p, "--redact"])
        self.assertEqual(plain, alias)
        code, raw, err = self.run_cli(["--format", "openai", "--from", p, "--no-redact"])
        self.assertEqual(code, 0)
        self.assertIn("WARNING: --no-redact", err)
        self.assertIn("redaction OFF", err)
        self.assertIn("acmecorp-test.com", raw)
        code, _, err = self.run_cli(["--format", "openai", "--from", p, "--redact", "--no-redact"])
        self.assertEqual(code, 2)

    def test_existing_redaction_is_untouched(self):
        """gnoc_secrets and gnoc_distill keep their own behaviour: this phase only reads them."""
        self.assertEqual(gnoc_secrets.redact(f"k={SECRET}"), "k=[REDACTED:TEST_KEY]")
        import gnoc_distill
        self.assertEqual(gnoc_distill.redact("AK" + "IAABCDEFGHIJKLMNOP"), "<REDACTED>")


class TheCommandLine(Base):
    def test_since_filters_and_malformed_since_is_refused(self):
        p = self.write([record(ts="2026-11-01T09:00:00+00:00"), record(ts="2026-11-20T09:00:00Z"),
                        record(ts="not a time")])
        code, out, err = self.run_cli(["--format", "sharegpt", "--from", p, "--since", "2026-11-10"])
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("2 before since", err)
        for bad in ("2026-13-01", "yesterday", "2026/11/01", "2026-11-1", "2026-02-30"):
            code, out, err = self.run_cli(["--format", "openai", "--from", p, "--since", bad])
            self.assertEqual(code, 2, bad)
            self.assertEqual(out, "", bad)
            self.assertIn("--since", err)

    def test_out_writes_a_private_file_and_nothing_to_stdout(self):
        p = self.write([record()])
        dest = os.path.join(self.tmp, "sub", "export.jsonl")
        code, out, err = self.run_cli(["--format", "openai", "--from", p, "--out", dest])
        self.assertEqual((code, out), (0, ""))
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)
        with open(dest) as f:
            T.validate_openai(json.loads(f.readline()))
        self.assertIn(dest, err)

    def test_good_only_and_missing_source_and_bad_format(self):
        p = self.write([record(), record(outcome={"ok": 0, "failed": 2, "good": False})])
        code, out, err = self.run_cli(["--format", "openai", "--from", p, "--good-only"])
        self.assertEqual(len(out.splitlines()), 1)
        self.assertIn("1 not good", err)
        code, _, err = self.run_cli(["--format", "openai", "--from", os.path.join(self.tmp, "nope.jsonl")])
        self.assertEqual(code, 1)
        self.assertIn("no trajectories yet", err)
        self.assertEqual(self.run_cli(["--format", "csv", "--from", p])[0], 2)

    def test_the_gnoc_command_dispatches_export(self):
        env = dict(os.environ, HOME=self.home, GNOC_NO_UPDATE_CHECK="1")
        p = self.write([record()])
        r = subprocess.run([sys.executable, os.path.join(HERE, "gnoc"), "export", "trajectories", "--format",
                            "openai", "--from", p], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        T.validate_openai(json.loads(r.stdout.splitlines()[0]))
        r = subprocess.run([sys.executable, os.path.join(HERE, "gnoc"), "export", "trajectories", "--format",
                            "openai", "--from", p, "--since", "soon"], capture_output=True, text=True, env=env,
                           timeout=120)
        self.assertEqual(r.returncode, 2)


class HeldActionsAreHeld(Base):
    """A batch prompt runs in a fresh non-interactive agent: a write the model asks for is recorded as held and the
    file never appears."""

    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.tmp, "repo")
        os.makedirs(self.root)
        with open(os.path.join(self.root, "notes.txt"), "w") as f:
            f.write("hello\n")
        self.saved_g = (G._ACTIVE_ROOT[0], G.resolve, G.llm_chat, G.say, G.SKIP_PERMS[0], G._approve,
                        G.AGENT_DIR, G.SESSIONS_DIR)
        G._ACTIVE_ROOT[0] = self.root
        G.resolve = lambda role, quiet=False: ("smoke-model", "local")
        G.say = lambda *a, **k: None

    def tearDown(self):
        (G._ACTIVE_ROOT[0], G.resolve, G.llm_chat, G.say, G.SKIP_PERMS[0], G._approve, _, _) = self.saved_g
        super().tearDown()

    def script(self, steps):
        steps = list(steps)
        G.llm_chat = lambda model, host, msgs, *a, **k: (steps.pop(0) if steps else
                                                         {"role": "assistant", "content": "DONE (exhausted)"})

    def test_a_held_write_is_recorded_and_never_touches_disk(self):
        self.script([call("read_file", path="notes.txt"),
                     call("write_file", path="held.txt", content="should never exist\n"),
                     {"role": "assistant", "content": "DONE: the write needs your approval."}])
        rec = T.run_one({"id": "w1", "prompt": "create held.txt containing a greeting"}, steps=8)
        self.assertFalse(os.path.exists(os.path.join(self.root, "held.txt")), "a held write ran")
        self.assertEqual([h["tool"] for h in rec["held"]], ["write_file"])
        self.assertIn("held.txt", rec["held"][0]["args"])
        self.assertEqual(rec["id"], "w1")
        self.assertTrue({"ts", "program", "outcome", "messages", "held"} <= set(rec))
        tools = [m for m in rec["messages"] if m["role"] == "tool"]
        self.assertIn("hello", tools[0]["content"])                 # the read ran
        self.assertIn("needs the user's approval", tools[1]["content"])   # the write did not
        # and the export carries it as held
        lines, counts = T.export(self.write([rec]), "sharegpt")
        self.assertEqual(counts["exported"], 1, counts)
        out = json.loads(lines[0])
        T.validate_sharegpt(out)
        self.assertEqual(out["held"][0]["tool"], "write_file")
        olines, _ = T.export(self.write([rec], name="b.jsonl"), "openai")
        T.validate_openai(json.loads(olines[0]))
        self.assertIn("needs the user's approval", olines[0])

    def test_the_child_entry_runs_in_the_folder_it_was_started_in(self):
        """`_batch-one` (what each pool child runs) works in its cwd and writes a private record."""
        self.script([call("write_file", path="child.txt", content="x\n"), {"role": "assistant", "content": "DONE"}])
        inp, out = os.path.join(self.tmp, "in.json"), os.path.join(self.tmp, "rec.json")
        with open(inp, "w") as f:
            json.dump({"id": "c1", "prompt": "create child.txt with an x"}, f)
        here = os.getcwd()
        G._ACTIVE_ROOT[0] = self.tmp   # the child must replace this with its cwd
        os.chdir(self.root)
        try:
            self.assertEqual(T.main(["_batch-one", inp, out, "4"]), 0)
        finally:
            os.chdir(here)
        self.assertEqual(G._ACTIVE_ROOT[0], self.root)
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o600)
        with open(out) as f:
            rec = json.load(f)
        self.assertEqual((rec["id"], [h["tool"] for h in rec["held"]]), ("c1", ["write_file"]))
        self.assertFalse(os.path.exists(os.path.join(self.root, "child.txt")))

    def test_skip_perms_is_forced_off_for_the_batch_and_restored(self):
        G.SKIP_PERMS[0] = True
        before = G._approve
        self.script([call("write_file", path="held2.txt", content="x\n"),
                     {"role": "assistant", "content": "DONE"}])
        rec = T.run_one({"id": "w2", "prompt": "create held2.txt with an x"}, steps=4)
        self.assertFalse(os.path.exists(os.path.join(self.root, "held2.txt")))
        self.assertEqual([h["tool"] for h in rec["held"]], ["write_file"])
        self.assertTrue(G.SKIP_PERMS[0], "the caller's setting is put back")
        self.assertIs(G._approve, before)
        self.assertEqual(G.AGENT_DIR, self.saved_g[6], "the private session dir is undone")


class LoadPrompts(Base):
    def lines(self, *rows):
        p = os.path.join(self.tmp, "prompts.jsonl")
        with open(p, "w") as f:
            f.write("\n".join(rows) + "\n")
        return p

    def test_good_file(self):
        items = T.load_prompts(self.lines('{"prompt": "a"}', "", '{"prompt": "b", "id": 7}'))
        self.assertEqual(items, [{"id": "p1", "prompt": "a"}, {"id": "7", "prompt": "b"}])

    def test_bad_lines_refuse_the_batch_with_the_line_number(self):
        cases = {"line 2: not JSON": ('{"prompt": "a"}', "{oops"),
                 "line 1: \"prompt\"": ('{"id": "x"}',),
                 "line 1: each line is an object": ('["a"]',),
                 "duplicate id": ('{"prompt": "a", "id": "x"}', '{"prompt": "b", "id": "x"}'),
                 "\"id\" must be": ('{"prompt": "a", "id": true}',),
                 "no prompts": ("",)}
        for want, rows in cases.items():
            with self.assertRaises(ValueError) as cm:
                T.load_prompts(self.lines(*rows))
            self.assertIn(want, str(cm.exception))

    def test_cmd_batch_refuses_before_making_the_out_folder(self):
        out = os.path.join(self.tmp, "batch-out")
        err = io.StringIO()
        self.assertEqual(T.cmd_batch([self.lines("{oops"), "--out", out], err=err), 2)
        self.assertFalse(os.path.exists(out))
        self.assertIn("refused", err.getvalue())
        self.assertEqual(T.cmd_batch([self.lines('{"prompt": "a"}'), "--out", out, "--workers", "99"], err=err), 2)
        self.assertFalse(os.path.exists(out))


# a stand-in for the child process: it reads its prompt and does what the prompt says
FAKE_CHILD = r'''
import json, os, subprocess, sys, time
inp, out = sys.argv[1], sys.argv[2]
item = json.load(open(inp))
cmd, _, arg = item["prompt"].partition(":")
open(out + ".pid", "w").write(str(os.getpid()))
if cmd == "sleep":
    g = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    open(out + ".gpid", "w").write(str(g.pid))
    time.sleep(float(arg))
elif cmd == "noout":
    sys.exit(3)
elif cmd == "count":
    mine = os.path.join(arg, str(os.getpid()))
    open(mine, "w").close()
    n = len(os.listdir(arg))
    time.sleep(0.4)
    os.remove(mine)
    json.dump({"id": item["id"], "messages": [], "held": [], "running": n}, open(out, "w"))
    sys.exit(0)
json.dump({"id": item["id"], "messages": [{"role": "user", "content": item["prompt"]}], "held": []}, open(out, "w"))
'''


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:   # a zombie still answers kill 0: read its state
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


@unittest.skipUnless(os.name == "posix", "process groups are POSIX")
class TheBatchPool(Base):
    def setUp(self):
        super().setUp()
        self.child = os.path.join(self.tmp, "child.py")
        with open(self.child, "w") as f:
            f.write(FAKE_CHILD)
        self.out = os.path.join(self.tmp, "out")
        self.err = io.StringIO()

    def cmd(self, i, o):
        return [sys.executable, self.child, i, o]

    def items(self, *prompts):
        return [{"id": f"p{n}", "prompt": p} for n, p in enumerate(prompts, 1)]

    def results(self):
        with open(os.path.join(self.out, "trajectories.jsonl")) as f:
            return [json.loads(ln) for ln in f]

    def wait_dead(self, pid, secs=5.0):
        end = time.time() + secs
        while time.time() < end and alive(pid):
            time.sleep(0.05)
        return not alive(pid)

    def test_the_pool_is_bounded_and_keeps_input_order(self):
        cnt = os.path.join(self.tmp, "running")
        os.makedirs(cnt)
        items = self.items(*[f"count:{cnt}"] * 5)
        code, summary = T.run_batch(items, self.out, workers=2, timeout=30, cmd_for=self.cmd, err=self.err)
        self.assertEqual(code, 0)
        res = self.results()
        self.assertEqual([r["id"] for r in res], [f"p{n}" for n in range(1, 6)])
        self.assertTrue(all(1 <= r["running"] <= 2 for r in res), [r["running"] for r in res])
        self.assertEqual(summary["ok"], 5)
        self.assertEqual(os.stat(os.path.join(self.out, "trajectories.jsonl")).st_mode & 0o777, 0o600)

    def test_a_timeout_kills_the_child_and_its_children(self):
        t0 = time.time()
        code, summary = T.run_batch(self.items("sleep:60", "ok"), self.out, workers=2, timeout=1.0,
                                    cmd_for=self.cmd, err=self.err)
        self.assertLess(time.time() - t0, 20)
        res = self.results()
        self.assertIn("timed out", res[0]["error"])
        self.assertTrue(res[0]["outcome"]["timeout"])
        self.assertEqual(res[1]["messages"][0]["content"], "ok")
        base = os.path.join(self.out, "items", "00000.json")
        for suffix in (".pid", ".gpid"):
            with open(base + suffix) as f:
                self.assertTrue(self.wait_dead(int(f.read())), suffix + " still running")
        self.assertEqual(summary["failed"], 1)

    def test_a_child_that_writes_nothing_is_an_error_line(self):
        T.run_batch(self.items("noout"), self.out, workers=1, timeout=30, cmd_for=self.cmd, err=self.err)
        res = self.results()
        self.assertIn("without a trajectory", res[0]["error"])
        self.assertEqual(res[0]["messages"], [])

    def test_ctrl_c_stops_every_child(self):
        ticks = [0]

        def tick(s):
            ticks[0] += 1
            if ticks[0] == 5:
                raise KeyboardInterrupt
            time.sleep(s)

        code, summary = T.run_batch(self.items("sleep:30", "sleep:30", "sleep:30"), self.out, workers=2,
                                    timeout=60, cmd_for=self.cmd, tick=tick, err=self.err)
        self.assertEqual(code, 130)
        res = self.results()
        self.assertEqual([r["error"].split(" (")[0] for r in res],
                         ["interrupted", "interrupted", "not run"])
        for n in (0, 1):
            with open(os.path.join(self.out, "items", f"{n:05d}.json.pid")) as f:
                self.assertTrue(self.wait_dead(int(f.read())))
        self.assertIn("interrupted", self.err.getvalue())

    def test_refusals(self):
        with self.assertRaises(ValueError):
            T.run_batch(self.items("ok"), self.out, workers=0, cmd_for=self.cmd, err=self.err)
        with self.assertRaises(ValueError):
            T.run_batch(self.items("ok"), self.out, workers=T.MAX_WORKERS + 1, cmd_for=self.cmd, err=self.err)
        with self.assertRaises(ValueError):
            T.run_batch(self.items("ok"), self.out, steps=0, cmd_for=self.cmd, err=self.err)
        T.run_batch(self.items("ok"), self.out, workers=1, cmd_for=self.cmd, err=self.err)
        with self.assertRaises(ValueError) as cm:   # never overwrites an earlier batch's output
            T.run_batch(self.items("ok"), self.out, workers=1, cmd_for=self.cmd, err=self.err)
        self.assertIn("already exists", str(cm.exception))

    def test_the_real_child_command_is_the_batch_one_entry(self):
        cmd = T._child_cmd("in.json", "out.json", 7)
        self.assertEqual(cmd[1:], [os.path.abspath(T.__file__), "_batch-one", "in.json", "out.json", "7"])


if __name__ == "__main__":
    unittest.main()
