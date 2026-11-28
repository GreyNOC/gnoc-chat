#!/usr/bin/env python3
"""Regression tests for the second 2026-11-19 QA/QC (whole shipped product, after the refactor): secrets, scope,
the defender, the SWE tools and the release. One test per confirmed defect, named after what went wrong.
Stdlib unittest, temp dirs only, no model, no network (DNS answers are mocked).

    python3 -m pytest -q scripts/test_gnoc_qaqc_20261119_r2.py
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_bg  # noqa: E402
import gnoc_cloud  # noqa: E402
import gnoc_comms  # noqa: E402
import gnoc_defend  # noqa: E402
import gnoc_defender  # noqa: E402
import gnoc_hooks  # noqa: E402
import gnoc_lsp  # noqa: E402
import gnoc_monitor  # noqa: E402
import gnoc_scan  # noqa: E402
import gnoc_secrets as S  # noqa: E402
import gnoc_session  # noqa: E402
import gnoc_worktree  # noqa: E402
from bbtools import lib_policy, lib_scope  # noqa: E402
from gnoc_core import cli as CLI  # noqa: E402
from gnoc_core import promptline as PL  # noqa: E402
from gnoc_core import terms as TERMS  # noqa: E402

SECRET = "qaqc-r2-" + "s3cr3t" * 4
# key armor, assembled at run time: the release leak scan refuses a literal marker in any shipped file
PK = "PRIVATE" + " KEY"   # registered for redaction in setUpModule; never a real credential


def setUpModule():
    S.register_extra("qaqc-r2-test", SECRET)


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-qaqc-r2-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", newline="") as f:
            f.write(text)
        return p


class Repo(Tmp):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.saved = (G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0])
        G.AGENT_DIR = os.path.join(self.tmp, "agent")
        G._ACTIVE_ROOT[0] = self.repo
        G.SKIP_PERMS[0] = False
        self.env = mock.patch.dict(os.environ, {"GNOC_HOME": os.path.join(self.tmp, "home"),
                                                "GNOC_BG_DIR": os.path.join(self.tmp, "bg")})
        self.env.start()
        for k in gnoc_worktree.GIT_LOCATION_VARS:
            os.environ.pop(k, None)
        self.ctx = G.Ctx({"sid": "qaqc-r2"})

    def tearDown(self):
        self.env.stop()
        G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0] = self.saved
        super().tearDown()

    def write(self, rel, text):
        return self.put(os.path.join("repo", rel), text)

    def raw(self, rel):
        with open(os.path.join(self.repo, rel), "rb") as f:
            return f.read()


# ============================================================================================ secrets
class TheShellSecretGateSeesThroughSpellings(Tmp):
    def test_globs_escapes_and_home_forms_are_resolved(self):
        self.put("store/secrets.env", "X_TOKEN=abc\n")
        st = os.path.join(self.tmp, "store")
        for c in [f"cat {self.tmp}/st[o]re/*.e*", f"base64 -w0 {st}/secr\\ets.env", f"xxd '{st}'/\"secrets.env\"",
                  "cat ~/.git-cred*", "cat .ne?rc", "cat secr*.env"]:
            self.assertTrue(S.shell_reads_secret(c, cwd=self.tmp), c)

    def test_environment_dumps(self):
        for c in ["cat /proc/$PPID/env*", "ps eww -p 1", "ps -E", "declare -p", "typeset -px", "compgen -e",
                  "python3 -c \"import os; print(os.environ)\"", "perl -e 'print %ENV'"]:
            self.assertTrue(S.shell_reads_secret(c), c)

    def test_ordinary_commands_pass(self):
        for c in ["ls -la", "cat README.md", "ps aux", "ps -ef", "cat *.py", "ls src/*", "grep -rn foo scripts",
                  "python3 -c 'print(1)'", "ls -la ~"]:
            self.assertFalse(S.shell_reads_secret(c, cwd=self.tmp), c)

    def test_a_recursive_read_of_a_folder_holding_a_store_is_caught(self):
        parent = os.path.dirname(S.CONF)
        self.assertTrue(S.shell_reads_secret(f"grep -rh token {parent}"))
        self.assertFalse(S.shell_reads_secret(f"ls {parent}"))


class HomeDotfilesAreNeverReadOnly(unittest.TestCase):
    def test(self):
        for c in ["cat ~/.netrc", "cat $HOME/.aws/credentials", "head ${HOME}/.x", "cat /root/.bashrc"]:
            self.assertFalse(G._bash_readonly(c), c)
        self.assertTrue(G._bash_readonly("cat ~/notes.txt"))


class KeyMaterialIsRecognised(Tmp):
    def test_pgp_putty_and_lowercase_markers(self):
        for name, text in [("a.asc", "-----BEGIN PGP " + PK + " BLOCK-----\nxx\n"),
                           ("b.txt", "-----begin rsa " + PK.lower() + "-----\nxx\n"),
                           ("c.dat", "PuTTY-User-Key-File-3: ssh-ed25519\n")]:
            self.assertTrue(S.is_secret_path(self.put(name, text)), name)
        self.assertTrue(S.is_secret_path(self.put("k.ppk", "x")))

    def test_source_that_mentions_the_marker_is_not_a_key(self):
        self.assertFalse(S.is_secret_path(self.put("m.py", 'MARK = "-----BEGIN RSA ' + PK + '-----"\n')))


class TheStoreIsReadWhole(Tmp):
    def setUp(self):
        super().setUp()
        self.p = mock.patch.object(S, "CONF", self.tmp)
        self.p.start()
        self.x = mock.patch.object(S, "EXTRA_SECRET_FILES", ())
        self.x.start()
        S._cache["sig"] = None

    def tearDown(self):
        self.p.stop()
        self.x.stop()
        S._cache["sig"] = None
        super().tearDown()

    def test_webhook_urls_escaped_quotes_subfolders_and_hidden_files(self):
        self.put("secrets.env", 'DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1/abcdefghijk\n'
                                'DB_PASSWORD="pa\\"ss-word-1234"\nGH_PAT=ghp_aaaaaaaaaaaaaaaaaaaa\n')
        self.put("sub/deep.env", "DEEP_TOKEN=deep-token-value-123456\n")
        self.put(".hidden", "HIDDEN_SECRET=hidden-secret-value-1234\n")
        vals = {v for _, v in S.values()}
        for v in ("https://discord.com/api/webhooks/1/abcdefghijk", 'pa"ss-word-1234', "ghp_aaaaaaaaaaaaaaaaaaaa",
                  "deep-token-value-123456", "hidden-secret-value-1234"):
            self.assertIn(v, vals)

    def test_a_public_url_is_still_not_a_secret(self):
        self.put("secrets.env", "INBOX_URL=https://mail.example.com/inbox\n")
        self.assertNotIn("https://mail.example.com/inbox", {v for _, v in S.values()})


class ChildProcessesGetNoCredentials(unittest.TestCase):
    def test_dropped_and_kept(self):
        env = {"SMTP_PASS": "x", "GH_PAT": "x", "DATABASE_URL": "x", "MYSQL_PWD": "x", "JWT": "x",
               "DISCORD_WEBHOOK_URL": "x", "SIGNING_KEY": "x", "GH_AUTH": "x", "PWD": "/w", "OLDPWD": "/v",
               "XAUTHORITY": "/x", "DBUS_SESSION_BUS_ADDRESS": "unix:x", "XDG_SESSION_TYPE": "x11", "PATH": "/bin"}
        with mock.patch.dict(os.environ, env, clear=True):
            got = S.child_env({})
        for k in ("SMTP_PASS", "GH_PAT", "DATABASE_URL", "MYSQL_PWD", "JWT", "DISCORD_WEBHOOK_URL", "SIGNING_KEY",
                  "GH_AUTH"):
            self.assertNotIn(k, got)
        for k in ("PWD", "OLDPWD", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE", "PATH"):
            self.assertIn(k, got)

    def test_repo_code_runs_get_the_scrubbed_environment(self):
        import inspect
        from gnoc_tools import fs
        src = inspect.getsource(fs)
        # user_env (gnoc's private venv off PATH, 2026-11-20) is child_env underneath: still scrubbed
        self.assertGreaterEqual(src.count('env=bind("gnoc_secrets")[0].child_env({})')
                                + src.count('env=bind("gnoc_secrets")[0].user_env({})'), 4)
        import gnoc_secrets
        self.assertIn("env = child_env(extra, allow)", inspect.getsource(gnoc_secrets.user_env))


class GrepContextLinesNeverLeakAKey(Repo):
    def test(self):
        self.write("deploy/id_ed25519", "-----BEGIN OPENSSH " + PK + "-----\nAAAAkeybodyline\n"
                                        "-----END OPENSSH " + PK + "-----\n")
        self.write("a.txt", "x\nBEGIN\ny\n")
        out = G._exec("grep", {"pattern": "BEGIN", "path": ".", "context": 2}, self.ctx)
        self.assertNotIn("keybody", out)
        self.assertIn("a.txt:2:BEGIN", out)


class SecretsStayOutOfWhatLeaves(Repo):
    def test_export_is_redacted(self):
        agent = types.SimpleNamespace(s={"sid": "r2", "history": [{"role": "user", "content": f"key {SECRET}"}]},
                                      ctx=types.SimpleNamespace(program=None))
        target, err = PL.export_transcript(agent, "out/x.md")
        self.assertIsNone(err)
        with open(target) as f:
            self.assertNotIn(SECRET, f.read())

    def test_cloud_requests_redact_tool_call_arguments(self):
        msgs = [{"role": "assistant", "content": "",
                 "tool_calls": [{"id": "1", "function": {"name": "bash",
                                                         "arguments": json.dumps({"command": f"echo {SECRET}"})}},
                                {"id": "2", "function": {"name": "bash", "arguments": {"command": SECRET}}}]}]
        self.assertNotIn(SECRET, json.dumps(gnoc_cloud.redact_messages(msgs)))
        self.assertIn(SECRET, json.dumps(msgs))   # the caller's copy is untouched

    def test_an_at_mention_of_a_secrets_file_is_not_attached(self):
        self.write(".env", f"API_TOKEN={SECRET}\n")
        out = PL.expand_mentions("look at @.env")
        self.assertNotIn(SECRET, out)
        self.assertIn("secrets file", out)

    def test_long_output_is_redacted_before_it_is_cut(self):
        out = G._spill(("x" * 50 + SECRET + "\n") * 4000, "r2")
        self.assertNotIn(SECRET, out)
        self.assertNotIn(SECRET[:12] + SECRET[12:20], out.replace("[REDACTED", ""))

    def test_subagent_logs_are_redacted(self):
        with mock.patch.object(gnoc_monitor, "DIR", os.path.join(self.tmp, "mon")):
            sid = gnoc_monitor.start("worker", task=f"use {SECRET}")
            gnoc_monitor.append(sid, f"step {SECRET}")
            log = gnoc_monitor._mem[sid]["log"]
            with open(log) as f:
                self.assertNotIn(SECRET, f.read())


class ReadlineHistoryKeepsNoKeys(unittest.TestCase):
    def test(self):
        hist = ["/deepseek api sk-abc", "/cloud add x key zzz", f"echo {SECRET}", "hello", "/help"]

        class RL:
            def get_current_history_length(self):
                return len(hist)

            def get_history_item(self, i):
                return hist[i - 1]

            def remove_history_item(self, i):
                del hist[i]
        CLI._scrub_history(RL())
        self.assertEqual(hist, ["hello", "/help"])


class SendSendsWhatWasShown(unittest.TestCase):
    def test_a_draft_changed_after_approval_is_refused(self):
        d = {"id": "O1", "status": "draft", "channel": "email", "to": "a@example.com", "subject": "s", "text": "hi"}
        shown = gnoc_comms.fingerprint(d)
        changed = dict(d, to="b@example.com")
        with mock.patch.object(gnoc_comms, "load", return_value=changed), \
                mock.patch.object(gnoc_comms, "_send_email", side_effect=AssertionError("must not send")):
            ok, msg = gnoc_comms.send("O1", approved=shown)
        self.assertFalse(ok)
        self.assertIn("changed after you approved", msg)

    def test_the_outbox_is_write_protected(self):
        self.assertTrue(G.WRITE_DENY.search(".claude/state/orch/outbox/O1.json"))


class LanesRegisteredTogetherAreAllKept(Tmp):
    def test(self):
        p = self.put("s.json", json.dumps({"pid": os.getpid(), "lanes": []}))
        with mock.patch.object(gnoc_session, "_MINE", [p]):
            ts = [threading.Thread(target=gnoc_session.register_lane, args=(10000 + i, f"l{i}", 1)) for i in range(16)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        with open(p) as f:
            self.assertEqual(len(json.load(f)["lanes"]), 16)


# ============================================================================================ scope
class OutOfScopeDividersEndTheInScopeList(Tmp):
    def test_every_divider_form(self):
        for div in ["# === OUT OF SCOPE (non-host asset types below; see PROGRAM.md) ===", "**Out of scope**",
                    "* Out of scope:", "[Out of Scope]", "Not eligible:", "> Out of scope"]:
            p = self.put("S.txt", f"WILDCARD *.in.example\n{div}\nWILDCARD *.oos.example\n")
            self.assertFalse(lib_scope.host_in_scope("www.oos.example", p), div)
            self.assertTrue(lib_scope.host_in_scope("a.in.example", p), div)

    def test_an_inline_note_naming_a_host_is_not_a_divider(self):
        p = self.put("S.txt", "out of scope: admin.in.example\n*.in.example\n")
        self.assertTrue(lib_scope.host_in_scope("a.in.example", p))


class TheBashScopeGateFailsClosed(Tmp):
    def gate(self, body):
        self.put(".claude/hooks/scope-gate.sh", body)
        with mock.patch.object(G, "WS", self.tmp):
            return G._scope_gate_bash("curl https://x.example/", "p")

    def test(self):
        self.assertIsNone(self.gate("exit 0\n"))
        self.assertIn("nope", self.gate("echo nope >&2; exit 2\n"))
        self.assertIn("scope gate failed", self.gate("echo $UNSET_VAR_X; set -u; echo $UNSET_VAR_Y\n"))


@unittest.skipUnless(os.path.isfile(os.path.join(os.path.dirname(HERE), ".claude/hooks/scope-gate.sh")) and
                     os.path.isdir(os.path.join(os.path.dirname(HERE), "targets", "gatewayco")),
                     "the workspace scope hook and a program are needed")
class TheScopeHookIsNotFooledByLookalikes(unittest.TestCase):
    def run_hook(self, cmd):
        ws = os.path.dirname(HERE)
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"HUNT_TARGET=gatewayco {cmd}"}, "cwd": ws})
        return subprocess.run(["bash", os.path.join(ws, ".claude/hooks/scope-gate.sh")], input=payload, text=True,
                              capture_output=True, cwd=ws, timeout=30).returncode

    def test(self):
        for c in ["curl https://127.evil.com/", "curl https://10.attacker.net/", "curl -o /tmp/x-e https://evil.com/"]:
            self.assertEqual(self.run_hook(c), 2, c)
        for c in ["curl http://127.0.0.1:8080/", "curl http://10.0.0.5/"]:
            self.assertEqual(self.run_hook(c), 0, c)


class NamesThatResolveInsideAreRefused(unittest.TestCase):
    def setUp(self):
        G._RESOLVE_CACHE.clear() if hasattr(G, "_RESOLVE_CACHE") else None
        from gnoc_tools import net
        net._RESOLVE_CACHE.clear()

    def test(self):
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
            self.assertEqual(G._resolves_internal("rebind.example"), "10.0.0.5")
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))]):
            self.assertEqual(G._resolves_internal("public.example"), "")
        self.assertEqual(G._resolves_internal("127.0.0.1"), "127.0.0.1")


class TheHostHeaderIsInScopeToo(unittest.TestCase):
    def test(self):
        allow = lambda u, p, ws: (".in.example" in u, "not-in-scope")
        with mock.patch.object(lib_scope, "program_allows", side_effect=allow):
            self.assertIn("OUT_OF_SCOPE", G._host_header_refusal("p", "https://a.in.example/", {"Host": "evil.com"}))
            self.assertIsNone(G._host_header_refusal("p", "https://a.in.example/", {"host": "b.in.example"}))
            self.assertIsNone(G._host_header_refusal("p", "https://a.in.example/", {}))


class WebFetchHonoursNoscope(Tmp):
    def test(self):
        self.put("targets/p/SCOPE.txt", "*.in.example\n")
        self.put("targets/p/NOSCOPE.txt", "=vpn.in.example\n")
        with mock.patch.object(G, "WS", self.tmp):
            out = G._exec("web_fetch", {"url": "https://vpn.in.example/"}, G.Ctx({"program": "p"}))
        self.assertIn("OUT of scope", out)


class ScannersStayOnTheHost(Tmp):
    def test_ffuf_never_fuzzes_the_host(self):
        with mock.patch.object(gnoc_scan, "_bin", return_value="/bin/true"):
            self.assertIn("refused", gnoc_scan.ffuf("p", {}, "https://FUZZ.in.example/"))

    def test_nuclei_follows_no_redirect(self):
        seen = []
        with mock.patch.object(gnoc_scan, "_bin", return_value="/bin/true"), \
                mock.patch.object(gnoc_scan, "_out", return_value=self.tmp), \
                mock.patch.object(gnoc_scan, "_run", side_effect=lambda argv, *a, **k: seen.append(argv) or ""):
            gnoc_scan.nuclei("p", {"rps": 1}, "https://a.in.example/")
        self.assertIn("-dr", seen[0])


class AiAgentBansAreRead(unittest.TestCase):
    def test(self):
        for t in ["Do not use AI agents to test our systems.", "AI tools may not be used for testing.",
                  "The use of artificial intelligence is strictly prohibited.", "No AI agents.",
                  "Autonomous agents are not permitted."]:
            self.assertTrue(lib_policy.agent_ban_line(t), t)
        for t in ["Prompt injection against our LLM is in scope.", "We use AI to triage reports."]:
            self.assertFalse(lib_policy.agent_ban_line(t), t)


class TheBrowserToolHasItsBackend(unittest.TestCase):
    def test(self):
        import gnoc_browser
        self.assertTrue(callable(getattr(gnoc_browser, "visit", None)))
        out = gnoc_browser.summary({"status": 200, "final_url": "https://a/", "title": "t", "dialogs": [],
                                    "postmessages": [], "blocked_navigations": ["https://evil/"],
                                    "console_errors": [], "record": "r.json"})
        self.assertIn("blocked out-of-scope navigations: https://evil/", out)


# ============================================================================================ defender
class TheDefenderTrustsOnlyWhatHeSaid(unittest.TestCase):
    def test_admin_sources_must_be_narrow(self):
        self.assertIsNone(gnoc_defender._valid_source("128.0.0.0/1")[0])
        self.assertIsNone(gnoc_defender._valid_source("2001::/16")[0])
        self.assertEqual(gnoc_defender._valid_source("203.0.113.0/24")[0], "203.0.113.0/24")

    def test_yes_means_yes(self):
        self.assertTrue(gnoc_defender._said_yes("yes"))
        self.assertFalse(gnoc_defender._said_yes("yes, but do not disable it"))

    def test_undo_and_muting_ask(self):
        for a in ({"action": "undo"}, {"action": "alerts", "op": "suppress"},
                  {"action": "triage", "op": "false_positive"}):
            self.assertTrue(gnoc_defender.needs_approval({}, a), a)

    def test_unisolate_needs_the_isolation_token(self):
        rows = [{"id": "d1", "ok": True, "undo": {"kind": "endpoint_unisolate", "dest": "h1", "token": "ab" * 16}}]
        with mock.patch.object(gnoc_defender, "journal", return_value=rows):
            self.assertEqual(gnoc_defender.isolation_token("h1"), "ab" * 16)
            self.assertEqual(gnoc_defender.isolation_token("h2"), "")


class AProtectedNameFromTmpIsNotProtected(unittest.TestCase):
    def test(self):
        self.assertFalse(gnoc_defend.is_protected_proc("sshd", "/tmp/.x/sshd"))
        self.assertTrue(gnoc_defend.is_protected_proc("sshd", "/usr/sbin/sshd"))

    def test_only_input_hook_drops_count_as_a_firewall(self):
        docker = "table ip filter {\n chain FORWARD {\n  type filter hook forward priority 0; policy drop;\n }\n}\n"
        inp = "table inet fw {\n chain input {\n  type filter hook input priority 0; policy drop;\n }\n}\n"
        self.assertEqual(gnoc_defend._input_drop_chains(docker), 0)
        self.assertEqual(gnoc_defend._input_drop_chains(inp), 1)


# ============================================================================================ SWE tools
class EditsKeepTheFilesBytes(Repo):
    def test_crlf_survives_an_edit(self):
        self.write("w.txt", "a\r\nb\r\nc\r\n")
        G._exec("edit_file", {"path": "w.txt", "old": "b", "new": "B"}, self.ctx)
        self.assertEqual(self.raw("w.txt"), b"a\r\nB\r\nc\r\n")


class AChangedFileIsNotHiddenByTheReadCache(Repo):
    def test_an_edit_that_keeps_the_line_count_is_visible_on_the_next_read(self):
        self.write("w.txt", "one\ntwo\n")
        first = G._exec("read_file", {"path": "w.txt"}, self.ctx)
        self.assertIn("one", first)
        self.write("w.txt", "red\nblue\n")
        second = G._exec("read_file", {"path": "w.txt"}, self.ctx)
        self.assertIn("red", second)
        self.assertIn("blue", second)
        self.assertNotIn("already shown in full", second)
        # An unchanged file still gets the dedup guard.
        third = G._exec("read_file", {"path": "w.txt"}, self.ctx)
        self.assertIn("already shown in full", third)


class PatchRenamesAreChecked(Repo):
    def test_a_rename_onto_a_hook_is_refused(self):
        self.write(".claude/hooks/h.sh", "h\n")
        self.write("x", "a\n")
        p = ("diff --git a/x b/.claude/hooks/h.sh\nsimilarity index 100%\nrename from x\n"
             "rename to .claude/hooks/h.sh\n")
        out = G._exec("apply_patch", {"patch": p}, self.ctx)
        self.assertIn("protected", out)
        self.assertEqual(self.raw(".claude/hooks/h.sh"), b"h\n")


class HookFileMatchingUsesRealPaths(Tmp):
    def test(self):
        repo = os.path.join(self.tmp, "r")
        os.makedirs(os.path.join(repo, "migrations"))
        got = gnoc_hooks._rel_paths(repo, ["./migrations/1.py", os.path.join(repo, "migrations/2.py")])
        self.assertIn("migrations/1.py", got)
        self.assertIn("migrations/2.py", got)
        names = gnoc_hooks.touched_files("apply_patch", {"patch": 'rename from a.py\nrename to "migrations/x y.py"\n'
                                                                  "--- \"q/z.py\"\n"})
        self.assertIn("a.py", names)


class StoppingABackgroundJobStopsItsChildren(unittest.TestCase):
    def test_a_leader_that_already_exited(self):
        p = subprocess.Popen(["sh", "-c", "sleep 30 & echo started"], stdout=subprocess.PIPE, start_new_session=True)
        p.stdout.readline()
        p.wait(5)
        self.assertTrue(gnoc_bg._group_alive(p.pid))
        gnoc_bg._kill({"proc": p}, grace=1.0)
        deadline = time.time() + 5
        while gnoc_bg._group_alive(p.pid) and time.time() < deadline:
            time.sleep(0.05)
        self.assertFalse(gnoc_bg._group_alive(p.pid))
        p.stdout.close()


class SudoInsideAHeredocIsText(unittest.TestCase):
    def test(self):
        from gnoc_tools import proc
        lines = proc._command_lines("cat <<'EOF' > INSTALL.md\nsudo apt install x\nEOF\nls")
        self.assertNotIn("sudo", lines)
        self.assertIn("sudo", proc._command_lines("ls\nsudo reboot"))


class NavigationFindsTheWholeName(unittest.TestCase):
    def test(self):
        self.assertEqual(gnoc_lsp._column("x = reload_all(load)", "load", None), 15)


# ============================================================================================ display
class APlainTruncatedLineCarriesNoEscapeCode(unittest.TestCase):
    def test_the_ellipsis_line_is_plain_when_there_was_no_colour(self):
        self.assertEqual(TERMS._fit_width("abcdef", 3), "abc")
        self.assertEqual(TERMS._fit_width("\x1b[31mabcdef", 3), "\x1b[31mabc\x1b[0m")


# ============================================================================================ models
class AStockModelIsNamedAsStock(unittest.TestCase):
    # 2026-11-27: the uncensored-only rule is gone and the picker hides nothing, so a model that is not on the host is
    # simply not installed, stock or not
    def test_a_missing_stock_model_is_reported_as_not_installed(self):
        out = []
        with mock.patch.object(G, "model_rows", return_value=[("local", "other", 1)]), \
                mock.patch.object(G.llm_endpoints, "stock", return_value=True), \
                mock.patch.object(G, "say", lambda text: out.append(str(text))):
            self.assertFalse(G._role_set("lead", "qwen2.5-coder:7b"))
        text = "\n".join(out)
        self.assertIn("not installed", text)
        self.assertNotIn("censored", text)


# ============================================================================================ approval wording
class AnOrderBeforeJustIsAnOrder(unittest.TestCase):
    def test(self):
        self.assertIsNone(G._hold_phrase("run the suite and just tell me the count"))
        self.assertIsNotNone(G._hold_phrase("just tell me what it does, I'll go run it myself later"))
        self.assertIsNone(G._hold_phrase("don't run it yet. ok go ahead"))

    def test_go_ahead_and_act_lifts_but_go_ahead_and_read_does_not(self):
        self.assertIsNone(G._hold_phrase("do not run it blindly: go ahead and run it with the serial control"))
        self.assertIsNotNone(G._hold_phrase("don't run it. go ahead and read the file"))
        self.assertIsNotNone(G._hold_phrase("don't run it, proceed with the analysis only"))


if __name__ == "__main__":
    unittest.main()
