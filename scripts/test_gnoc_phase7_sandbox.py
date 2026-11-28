"""Phase 7 (2026-11-26): execution backends - local, docker, ssh (gnoc_sandbox.py).

Nothing here needs docker, podman or an ssh server: the container runtime and ssh are replaced by a fake runner
(control commands) and a fake Popen (the command itself), and the tests assert the exact argv each would have
run. One integration class at the bottom drives a real container; it is skipped unless GNOC_TEST_DOCKER=1 and a
runtime with the image is on the machine.

What is pinned: a denied command is denied on every backend before the backend is reached, approval asks the same
question everywhere, the undo checkpoint is taken before a destructive command on docker (and on ssh, through the
backend), file tools refuse a path whose realpath leaves the mount (symlink included), bash refuses a cwd outside
the mount, the container has no network unless the user typed --network, Ctrl-C and a timeout kill the command
INSIDE the sandbox, and only a typed /sandbox changes the backend.
"""
import base64
import contextlib
import io
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_bg  # noqa: E402
import gnoc_sandbox as SB  # noqa: E402

try:
    with open("/proc/sys/kernel/pid_max") as _f:
        DEAD_PID = int(_f.read().strip()) + 1000   # above pid_max: no process can have it, so a stray killpg is a no-op
except (OSError, ValueError):
    DEAD_PID = 2 ** 22 + 1000


class FakeRunner:
    """Stands in for `docker ...` / `ssh ...` control commands: records argv, answers from a table."""

    def __init__(self, missing_image=False, version="Docker version 27.0.0", remote=None):
        self.calls = []
        self.missing_image = missing_image
        self.version = version
        self.remote = remote          # FakeRemote for the ssh tests

    def __call__(self, argv, timeout=30, input=None):
        self.calls.append(list(argv))
        out, rc = "", 0
        if len(argv) > 2 and argv[1] == "image" and argv[2] == "inspect":
            rc = 1 if self.missing_image else 0
            out = "" if self.missing_image else "sha256:abc\n"
        elif len(argv) > 1 and argv[1] == "--version":
            out = self.version
        elif argv and argv[0] == "ssh" and self.remote is not None:
            out, rc = self.remote.control(argv[-1], input)
        return subprocess.CompletedProcess(argv, rc, out, "")

    def named(self, verb):
        return [c for c in self.calls if len(c) > 1 and c[1] == verb]


class FakeProc:
    def __init__(self, argv, kw, out="ok\n", hang=False, effect=None):
        self.argv, self.kw, self.out, self.hang = argv, kw, out, hang
        self.pid = DEAD_PID
        self.returncode = None
        self.killed = False
        self.stdout = io.BytesIO(b"")
        self.stdin = io.BytesIO()
        if effect:
            effect(argv)

    def communicate(self, timeout=None, input=None):
        if self.hang and not self.killed:
            time.sleep(min(timeout or 0.05, 0.05))
            raise subprocess.TimeoutExpired(self.argv, timeout)
        self.returncode = -9 if self.killed else 0
        return ("" if self.killed else self.out), ""

    def poll(self):
        return self.returncode if (self.returncode is not None or not self.killed) else -9

    def kill(self):
        self.killed = True


class FakePopen:
    def __init__(self, hang=False, effect=None):
        self.calls, self.hang, self.effect = [], hang, effect

    def __call__(self, argv, **kw):
        p = FakeProc(argv, kw, hang=self.hang, effect=self.effect)
        self.calls.append(p)
        return p


class HostKills:
    def __init__(self):
        self.procs = []

    def __call__(self, p):
        self.procs.append(p)
        p.killed = True


class Base(unittest.TestCase):
    """A temp repo as the active root, a separate temp workspace (reachable by the file tools on the host, but
    OUTSIDE the mount), agent state and GNOC_HOME in temp dirs."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="gnoc-p7-"))
        self.repo = os.path.join(self.tmp, "repo")
        self.ws = os.path.join(self.tmp, "ws")
        self.home = os.path.join(self.tmp, "gnochome")
        for d in (self.repo, self.ws, self.home):
            os.makedirs(d)
        self.saved = (G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0], G.WS)
        G.AGENT_DIR = os.path.join(self.tmp, "agent")
        G._ACTIVE_ROOT[0] = self.repo
        G.SKIP_PERMS[0] = False
        G.WS = self.ws
        self.env = mock.patch.dict(os.environ, {"GNOC_HOME": self.home, "GNOC_BG_DIR": os.path.join(self.tmp, "bg")})
        self.env.start()
        self.ctx = G.Ctx({"sid": "p7-test"})
        self.runner, self.popen, self.kills = FakeRunner(), FakePopen(), HostKills()

    def tearDown(self):
        SB.detach(self.ctx.s)
        gnoc_bg.stop_all()
        gnoc_bg._PROCS.clear()
        G.INTERRUPT.clear()
        self.env.stop()
        G.AGENT_DIR, G._ACTIVE_ROOT[0], G.SKIP_PERMS[0], G.WS = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def docker(self, **kw):
        be = SB.DockerBackend(self.repo, kw.pop("image", "img:1"), runtime="docker", flavor=kw.pop("flavor", "docker"),
                              sid="p7-test", runner=self.runner, popen=self.popen, host_kill=self.kills, uid=1000,
                              gid=1000, **kw)
        return SB.attach(self.ctx.s, be)

    def ssh(self, remote=None):
        self.runner.remote = remote
        be = SB.SshBackend("dev@box", "/srv/w", runner=self.runner, popen=self.popen, host_kill=self.kills)
        return SB.attach(self.ctx.s, be)

    def write(self, rel, text, base=None):
        p = os.path.join(base or self.repo, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p


# ---------------------------------------------------------------------------------------------- the container
class DockerContainerArgv(Base):
    def test_run_argv_is_exactly_the_safe_one(self):
        be = self.docker()
        m = self.repo
        self.assertEqual(be.run_argv(), [
            "docker", "run", "-d", "--rm", "--name", be.name, "--label", "gnoc.sandbox=1",
            "--network", "none", "--user", "1000:1000", "--read-only",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,mode=1777,size=1g", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "1024", "-e", "HOME=/tmp",
            "-v", f"{m}:{m}", "-w", m, "img:1", "sleep", "infinity"])

    def test_no_other_host_mount_ever(self):
        argv = " ".join(self.docker(network=True).run_argv())
        self.assertEqual(argv.count(" -v "), 1)
        for bad in ("docker.sock", "podman.sock", os.path.expanduser("~") + ":", ".config/gnoc", "--privileged"):
            self.assertNotIn(bad, argv)

    def test_network_is_off_by_default_and_only_the_typed_flag_turns_it_on(self):
        self.assertIn("none", self.docker().run_argv())
        SB.detach(self.ctx.s)
        on = self.docker(network=True).run_argv()
        self.assertNotIn("--network", on)

    def test_podman_keeps_the_users_id_on_the_mount(self):
        self.assertIn("--userns=keep-id", self.docker(flavor="podman").run_argv())
        SB.detach(self.ctx.s)
        self.assertNotIn("--userns=keep-id", self.docker(flavor="docker").run_argv())

    def test_flavor_is_read_from_the_runtime_when_not_given(self):
        self.runner.version = "podman version 5.4.2"
        be = SB.DockerBackend(self.repo, "img:1", runtime="docker", runner=self.runner, popen=self.popen)
        self.assertEqual(be.prepare(self.repo), "")
        self.assertIn("--userns=keep-id", self.runner.named("run")[0])

    def test_a_missing_image_is_reported_with_the_pull_command_never_pulled(self):
        self.runner.missing_image = True
        be = self.docker()
        why = be.prepare(self.repo)
        self.assertIn("docker pull img:1", why)
        self.assertEqual(self.runner.named("pull"), [])
        self.assertEqual(self.runner.named("run"), [])

    def test_exec_passes_only_the_listed_variables(self):
        be = self.docker()
        argv, where, token = be.exec_argv("echo hi", self.repo, {"GNOC_PLAIN": "1", "GITHUB_TOKEN": "ghp_x",
                                                                 "PATH": "/usr/bin"})
        self.assertEqual(argv, ["docker", "exec", "-i", "-w", self.repo, "-e", "GNOC_PLAIN=1", be.name, "sh", "-c",
                                SB.WRAP, "gnoc-sbx", token, "echo hi"])
        self.assertTrue(token.startswith("/tmp/.gnoc-run-"))

    def test_mount_refuses_home_root_and_gnoc_config(self):
        self.assertTrue(SB.mount_refusal("/"))
        self.assertTrue(SB.mount_refusal(os.path.expanduser("~")))
        self.assertTrue(SB.mount_refusal(os.path.dirname(os.path.expanduser("~"))))
        self.assertTrue(SB.mount_refusal(self.home))          # GNOC_HOME
        self.assertTrue(SB.mount_refusal(os.path.join(self.tmp, "no-such-dir")))
        self.assertEqual(SB.mount_refusal(self.repo), "")     # negative control

    def test_new_conversation_keeps_the_setting_and_removes_the_old_container(self):
        be = self.docker()
        G.t_bash(self.ctx, "true")
        self.ctx.s["sid"] = "p7-next"               # what /new does: same settings, a new sid
        nxt = SB.for_session(self.ctx.s)
        self.assertEqual(nxt.kind, "docker")         # still sandboxed: never silently back on the host
        self.assertIsNot(nxt, be)
        self.assertIn(["docker", "rm", "-f", be.name], self.runner.calls)

    def test_a_hand_edited_setting_fails_closed(self):
        self.ctx.s["sandbox"] = {"kind": "docker", "mount": "/", "image": "x"}
        out = G.t_bash(self.ctx, "echo hi")
        self.assertIn("Nothing ran on this machine instead", out)
        self.ctx.s["sandbox"] = {"kind": "warp"}
        self.assertIn("not usable", G.t_bash(self.ctx, "echo hi"))


# ---------------------------------------------------------------------------------------------- the gates
class GatesAreTheSameOnEveryBackend(Base):
    DENIED = ("rm -rf /", "git push origin main", "cat ~/.config/gnoc/secrets.env")

    def _assert_denied_and_never_run(self):
        for cmd in self.DENIED:
            out = G.t_bash(self.ctx, cmd)
            self.assertRegex(out, r"refused|BLOCKED", cmd)
        self.assertEqual(self.popen.calls, [])
        self.assertEqual([c for c in self.runner.calls if "exec" in c or c[0] == "ssh"], [])

    def test_denied_on_docker(self):
        self.docker()
        self._assert_denied_and_never_run()

    def test_denied_on_ssh(self):
        self.ssh()
        self._assert_denied_and_never_run()

    def test_denied_in_bg_too(self):
        self.docker()
        self.assertIn("refused", G.t_bg(self.ctx, "start", name="x", command="git push origin main"))
        self.assertEqual(self.popen.calls, [])

    def test_approval_asks_the_same_question_on_every_backend(self):
        cmd = {"command": "touch made.txt"}
        # a fresh conversation per backend: the refusal text counts the approvals asked earlier in the turn
        local = G._plan_call("bash", dict(cmd), G.Ctx({"sid": "p7-test"}), False, None)[2]
        self.ctx = G.Ctx({"sid": "p7-test"})
        self.docker()
        dock = G._plan_call("bash", dict(cmd), self.ctx, False, None)[2]
        SB.detach(self.ctx.s)
        self.ctx = G.Ctx({"sid": "p7-test"})
        self.ssh()
        remote = G._plan_call("bash", dict(cmd), self.ctx, False, None)[2]
        self.assertTrue(local)              # non-interactive and not /auto: it is not approved
        self.assertEqual(local, dock)
        self.assertEqual(local, remote)
        self.assertEqual(self.popen.calls, [])

    def test_bash_runs_through_docker_exec_after_the_gates(self):
        self.docker()
        out = G.t_bash(self.ctx, "echo hi")
        self.assertTrue(out.startswith("exit 0"), out)
        self.assertEqual(self.popen.calls[0].argv[:3], ["docker", "exec", "-i"])
        self.assertEqual(len(self.runner.named("run")), 1)     # the container started once, on first use
        G.t_bash(self.ctx, "echo again")
        self.assertEqual(len(self.runner.named("run")), 1)

    def test_undo_checkpoint_before_a_destructive_command_on_docker(self):
        self.docker()
        self.write("notes.txt", "keep me\n")
        target = os.path.join(self.repo, "notes.txt")
        # the container deletes it through the bind mount: the host sees the same file vanish
        self.popen.effect = lambda argv: os.remove(target) if argv[0] == "docker" else None
        out = G.t_bash(self.ctx, "rm notes.txt")
        self.assertTrue(out.startswith("exit 0"), out)
        self.assertFalse(os.path.exists(target))
        self.assertEqual(self.popen.calls[0].argv[:2], ["docker", "exec"])
        self.assertIn("restored", " ".join(G.undo(self.ctx)))
        with open(target) as f:
            self.assertEqual(f.read(), "keep me\n")

    def test_bash_cwd_must_be_inside_the_mount(self):
        self.docker()
        G._ACTIVE_ROOT[0] = self.ws
        out = G.t_bash(self.ctx, "ls")
        self.assertIn("outside it", out)
        self.assertEqual(self.popen.calls, [])

    def test_bg_runs_in_the_sandbox_and_stop_kills_it_there(self):
        be = self.docker()
        out = G.t_bg(self.ctx, "start", name="srv", command="python3 -m http.server")
        self.assertIn("started srv", out)
        argv = self.popen.calls[0].argv
        self.assertEqual(argv[:3], ["docker", "exec", "-i"])
        token = argv[-2]
        G.t_bg(self.ctx, "stop", name="srv")
        self.assertIn(["docker", "exec", be.name, "sh", "-c", SB.KILL, "gnoc-kill", token], self.runner.calls)


class ModelCannotMoveTheExecutor(Base):
    def test_a_tool_naming_sandbox_is_refused(self):
        for name, args in (("bash", {"command": "gnoc chat -c '/sandbox local'"}),
                           ("bg", {"command": "gnoc chat \"/sandbox docker --network\""}),
                           ("bash", {"command": "echo '/sandbox ssh evil-host' | gnoc chat -c"})):
            pre = G._plan_call(name, args, self.ctx, False, None)[2]
            self.assertIn("only the user switches where commands run", str(pre), name)
        self.docker()
        pre = G._plan_call("bash", {"command": "gnoc chat -c '/sandbox local'"}, self.ctx, False, None)[2]
        self.assertIn("only the user switches", str(pre))

    def test_a_folder_named_sandbox_is_not_that(self):
        pre = G._plan_call("bash", {"command": "ls ./sandbox/ tests/sandbox"}, self.ctx, False, None)[2]
        self.assertNotIn("only the user switches", str(pre))

    def test_host_tools_are_refused_while_a_sandbox_is_on(self):
        for name in ("run_tests", "lint", "typecheck", "git", "gnoc"):
            self.assertEqual(SB.host_tool_refusal(self.ctx.s, name), "")   # local: untouched
        self.docker()
        for name, args in (("run_tests", {}), ("git", {"action": "status"}), ("lint", {}),
                           ("delegate", {"task": "x", "isolated": True})):
            pre = G._plan_call(name, args, self.ctx, False, None)[2]
            self.assertIn("outside the docker sandbox", str(pre), name)
        self.assertEqual(SB.host_tool_refusal(self.ctx.s, "delegate", {"task": "x"}), "")

    def _slash(self, line, typed):
        agent = mock.Mock()
        agent.s, agent.ctx, agent._slash_capturing = self.ctx.s, self.ctx, False
        agent._typed_line = line if typed else None
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            G.handle_slash(agent, line, {})
        return buf.getvalue()

    def test_only_a_typed_line_changes_the_backend(self):
        self.docker()
        G.t_bash(self.ctx, "true")                 # the container is up, so going local has one to remove
        copy = "".join(["/sandbox ", "local"])     # equal text, a different object: not what the keyboard gave
        out = self._slash(copy, typed=False)
        self.assertIn("typed at the prompt", out)
        self.assertEqual(self.ctx.s["sandbox"]["kind"], "docker")
        out = self._slash("/sandbox local", typed=True)
        self.assertNotIn("sandbox", self.ctx.s)
        self.assertTrue(any(c[1:3] == ["rm", "-f"] for c in self.runner.calls))

    def test_status_needs_no_typing(self):
        out = self._slash("/sandbox", typed=False)
        self.assertIn("sandbox: local", out)

    def test_docker_switch_and_typed_network(self):
        which = {"docker": "/usr/bin/docker"}.get
        msg, changed = SB.command(self.ctx.s, "docker", True, self.repo, runner=self.runner, which=which,
                                  popen=self.popen)
        self.assertTrue(changed, msg)
        self.assertEqual(self.ctx.s["sandbox"]["kind"], "docker")
        self.assertFalse(self.ctx.s["sandbox"]["network"])
        self.assertIn("none", self.runner.named("run")[-1])
        msg, changed = SB.command(self.ctx.s, "docker --network", False, self.repo, runner=self.runner, which=which)
        self.assertFalse(changed)
        self.assertFalse(self.ctx.s["sandbox"]["network"])
        msg, changed = SB.command(self.ctx.s, "docker --network", True, self.repo, runner=self.runner, which=which)
        self.assertTrue(changed, msg)
        self.assertTrue(self.ctx.s["sandbox"]["network"])
        self.assertNotIn("--network", self.runner.named("run")[-1])
        self.assertIn("NETWORK IS ON", msg)

    def test_docker_switch_refusals(self):
        msg, changed = SB.command(self.ctx.s, "docker", True, self.repo, runner=self.runner, which=lambda n: None)
        self.assertFalse(changed)
        self.assertIn("neither docker nor podman", msg)
        self.runner.missing_image = True
        msg, changed = SB.command(self.ctx.s, "docker --image busybox:1", True, self.repo, runner=self.runner,
                                  which={"podman": "/usr/bin/podman"}.get)
        self.assertFalse(changed)
        self.assertIn("podman pull busybox:1", msg)
        msg, changed = SB.command(self.ctx.s, "docker --image -evil", True, self.repo, runner=self.runner,
                                  which={"docker": "x"}.get)
        self.assertFalse(changed)
        self.assertNotIn("sandbox", self.ctx.s)

    def test_auto_recommends_docker_and_never_switches(self):
        self.assertIn("/sandbox docker", SB.auto_tip(self.ctx.s, which={"podman": "/usr/bin/podman"}.get))
        self.assertEqual(SB.auto_tip(self.ctx.s, which=lambda n: None), "")
        with mock.patch.object(SB, "detect_runtime", return_value="docker"):
            out = self._slash("/auto on", typed=True)
        self.assertIn("/sandbox docker", out)
        self.assertNotIn("sandbox", self.ctx.s)
        self.docker()
        self.assertEqual(SB.auto_tip(self.ctx.s, which={"docker": "x"}.get), "")


# ---------------------------------------------------------------------------------------------- the file tools
class PathEscapeOutOfTheMount(Base):
    def setUp(self):
        super().setUp()
        self.outside = self.write("secret-notes.txt", "outside the mount\n", base=self.ws)
        os.symlink(self.outside, os.path.join(self.repo, "link.txt"))
        os.symlink(self.ws, os.path.join(self.repo, "linkdir"))
        self.write("inside.txt", "inside\n")

    def test_local_backend_still_follows_the_link(self):
        # positive control: the host-side tools reach the workspace today; only the sandbox narrows them
        self.assertIn("outside the mount", G.t_read_file(self.ctx, "link.txt"))

    def test_docker_refuses_every_file_tool_through_the_symlink(self):
        self.docker()
        calls = (
            ("read_file", lambda: G.t_read_file(self.ctx, "link.txt")),
            ("read_file abs", lambda: G.t_read_file(self.ctx, self.outside)),
            ("read_file ..", lambda: G.t_read_file(self.ctx, "../ws/secret-notes.txt")),
            ("list_dir", lambda: G.t_list_dir(self.ctx, "linkdir")),
            ("grep", lambda: G.t_grep(self.ctx, "outside", path="linkdir")),
            ("find_file", lambda: G.t_find_file(self.ctx, "secret", path="linkdir")),
            ("write_file", lambda: G.t_write_file(self.ctx, "link.txt", "overwritten\n")),
            ("write_file new", lambda: G.t_write_file(self.ctx, "linkdir/new.txt", "x\n")),
            ("edit_file", lambda: G.t_edit_file(self.ctx, "link.txt", old="outside", new="pwned")),
            ("apply_patch", lambda: G.t_apply_patch(
                self.ctx, "--- a/link.txt\n+++ b/link.txt\n@@ -1 +1 @@\n-outside the mount\n+pwned\n")),
        )
        for label, call in calls:
            self.assertIn("outside", str(call()).lower(), label)
            self.assertIn("refused", str(call()).lower(), label)
        with open(self.outside) as f:
            self.assertEqual(f.read(), "outside the mount\n")
        self.assertFalse(os.path.exists(os.path.join(self.ws, "new.txt")))

    def test_docker_keeps_paths_inside_the_mount_working(self):
        self.docker()
        self.assertIn("inside", G.t_read_file(self.ctx, "inside.txt"))
        self.assertNotIn("refused", G.t_write_file(self.ctx, "made.txt", "ok\n"))

    def test_ssh_turns_the_file_tools_off(self):
        self.ssh()
        for out in (G.t_read_file(self.ctx, "inside.txt"), G.t_write_file(self.ctx, "made.txt", "x"),
                    G.t_list_dir(self.ctx, "."), G.t_grep(self.ctx, "x")):
            self.assertIn("file tools are off", out)
        self.assertFalse(os.path.exists(os.path.join(self.repo, "made.txt")))


# ---------------------------------------------------------------------------------------------- Ctrl-C
class CtrlCKillsInsideTheSandbox(Base):
    def _run_and_cancel(self, via_interrupt=False, timeout=120):
        box = {}
        ev = threading.Event()

        def work():
            with G._cancel_scope(ev):
                box["out"] = G.t_bash(self.ctx, "sleep 60", timeout=timeout)
        th = threading.Thread(target=work, daemon=True)
        th.start()
        time.sleep(0.4)
        (G.INTERRUPT if via_interrupt else ev).set()
        th.join(10)
        self.assertFalse(th.is_alive())
        return box["out"]

    def test_cancel_kills_the_process_in_the_container(self):
        be = self.docker()
        self.popen.hang = True
        out = self._run_and_cancel()
        self.assertIn("INTERRUPTED", out)
        token = self.popen.calls[0].argv[-2]
        self.assertIn(["docker", "exec", be.name, "sh", "-c", SB.KILL, "gnoc-kill", token], self.runner.calls)
        self.assertEqual(self.kills.procs, [self.popen.calls[0]])   # and the local client

    def test_ctrl_c_interrupt_kills_it_too(self):
        be = self.docker()
        self.popen.hang = True
        out = self._run_and_cancel(via_interrupt=True)
        self.assertIn("INTERRUPTED", out)
        self.assertTrue(any(c[:3] == ["docker", "exec", be.name] and SB.KILL in c for c in self.runner.calls))

    def test_timeout_kills_inside_as_well(self):
        be = self.docker()
        self.popen.hang = True
        out = G.t_bash(self.ctx, "sleep 60", timeout=1)
        self.assertIn("TIMED OUT", out)
        self.assertTrue(any(c[:3] == ["docker", "exec", be.name] and SB.KILL in c for c in self.runner.calls))

    def test_ssh_kill_goes_over_ssh(self):
        self.ssh()
        self.popen.hang = True
        out = self._run_and_cancel()
        self.assertIn("INTERRUPTED", out)
        token = self.popen.calls[0].argv[-1].split()[-2]
        kill = [c for c in self.runner.calls if c[0] == "ssh" and "gnoc-kill" in c[-1]]
        self.assertTrue(kill)
        self.assertIn(token.strip("'"), kill[0][-1])

    def test_local_ctrl_c_now_reaches_a_real_command(self):
        if os.name == "nt":
            self.skipTest("POSIX shell")
        t0 = time.monotonic()
        box, ev = {}, threading.Event()

        def work():
            with G._cancel_scope(ev):
                box["out"] = G.t_bash(self.ctx, "sleep 30")
        th = threading.Thread(target=work, daemon=True)
        th.start()
        time.sleep(0.5)
        ev.set()
        th.join(10)
        self.assertIn("INTERRUPTED", box.get("out", ""))
        self.assertLess(time.monotonic() - t0, 8)


# ---------------------------------------------------------------------------------------------- ssh
class FakeRemote:
    """A remote filesystem the fake ssh runner answers for (read helper, restore helper, rm)."""

    def __init__(self, files):
        self.files = dict(files)

    def control(self, remote_cmd, stdin):
        words = shlex.split(remote_cmd)
        if "gnoc-read" in words:
            paths = words[words.index("gnoc-read") + 1:]
            out = "".join(f"F {p}\n{base64.b64encode(self.files[p].encode()).decode()}\n"
                          for p in paths if p in self.files)
            return out, 0
        if "gnoc-restore" in words:
            self.files[words[-1]] = base64.b64decode(stdin).decode()
            return "", 0
        if words[:3] == ["rm", "-f", "--"]:
            self.files.pop(words[3], None)
            return "", 0
        if words[-1] == "-P" or remote_cmd.endswith("pwd -P"):
            return "/srv/w\n", 0
        return "", 0


class SshBackendShape(Base):
    def test_host_validation_blocks_option_injection(self):
        for bad in ("-oProxyCommand=sh", "host;rm -rf ~", "a b", "", "`id`@x", "x@-y", "$(id)"):
            self.assertFalse(SB.valid_host(bad), bad)
            with self.assertRaises(ValueError):
                SB.SshBackend(bad, "/srv/w")
        self.assertTrue(SB.valid_host("dev@build-01.lan"))
        msg, changed = SB.command(self.ctx.s, "ssh -oProxyCommand=x", True, self.repo, runner=self.runner)
        self.assertFalse(changed)
        self.assertEqual(self.runner.calls, [])

    def test_key_only_and_known_hosts_only(self):
        argv = SB.SshBackend("dev@box", "/srv/w").ssh_argv("true")
        joined = " ".join(argv)
        for opt in ("BatchMode=yes", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                    "StrictHostKeyChecking=yes", "ConnectTimeout=10", "ForwardAgent=no"):
            self.assertIn(opt, joined)
        self.assertNotIn("accept-new", joined)
        self.assertEqual(argv[-3:], ["--", "dev@box", "true"])

    def test_switch_checks_the_login_first(self):
        self.runner.remote = FakeRemote({})
        msg, changed = SB.command(self.ctx.s, "ssh dev@box /srv/w", True, self.repo, runner=self.runner)
        self.assertTrue(changed, msg)
        self.assertEqual(self.ctx.s["sandbox"], {"kind": "ssh", "host": "dev@box", "dir": "/srv/w"})
        SB.detach(self.ctx.s)

        def unknown_host(argv, timeout=30, input=None):   # StrictHostKeyChecking=yes on a host not in known_hosts
            return subprocess.CompletedProcess(argv, 255, "", "Host key verification failed.")
        msg, changed = SB.command(self.ctx.s, "ssh dev@box", True, self.repo, runner=unknown_host)
        self.assertFalse(changed)
        self.assertIn("Host key verification failed", msg)
        self.assertNotIn("sandbox", self.ctx.s)

    def test_exec_runs_in_the_remote_dir_without_host_env(self):
        be = self.ssh()
        argv, _, token = be.exec_argv("ls -la", self.repo, {"GNOC_PLAIN": "1", "AWS_SECRET_ACCESS_KEY": "x"})
        remote = argv[-1]
        self.assertTrue(remote.startswith("cd /srv/w && env GNOC_PLAIN=1 sh -c "), remote)
        self.assertNotIn("AWS_SECRET", remote)
        self.assertEqual(shlex.split(remote)[-1], "ls -la")
        self.assertEqual(shlex.split(remote)[-2], token)

    def test_undo_on_ssh_restores_the_remote_file(self):
        remote = FakeRemote({"/srv/w/notes.txt": "remote text\n"})
        self.ssh(remote)
        self.popen.effect = lambda argv: remote.files.pop("/srv/w/notes.txt", None)
        out = G.t_bash(self.ctx, "rm notes.txt")
        self.assertTrue(out.startswith("exit 0"), out)
        self.assertNotIn("/srv/w/notes.txt", remote.files)
        self.assertIn("restored ssh://dev@box/srv/w/notes.txt", " ".join(G.undo(self.ctx)))
        self.assertEqual(remote.files["/srv/w/notes.txt"], "remote text\n")

    def test_undo_of_a_remote_row_needs_that_host(self):
        remote = FakeRemote({"/srv/w/notes.txt": "remote text\n"})
        self.ssh(remote)
        self.popen.effect = lambda argv: remote.files.pop("/srv/w/notes.txt", None)
        G.t_bash(self.ctx, "rm notes.txt")
        SB.detach(self.ctx.s)
        self.assertIn("/sandbox ssh dev@box first", " ".join(G.undo(self.ctx)))
        self.assertNotIn("/srv/w/notes.txt", remote.files)


# ---------------------------------------------------------------------------------------------- real container
def _runtime_with_image():
    if os.environ.get("GNOC_TEST_DOCKER") != "1":
        return "", ""
    rt = SB.detect_runtime()
    image = os.environ.get("GNOC_TEST_DOCKER_IMAGE", SB.DEFAULT_IMAGE)
    if rt and SB.default_runner([rt, "image", "inspect", image], timeout=30).returncode == 0:
        return rt, image
    return "", ""


@unittest.skipUnless(_runtime_with_image()[0], "set GNOC_TEST_DOCKER=1 with docker/podman and the image present")
class RealContainer(Base):
    def setUp(self):
        super().setUp()
        rt, image = _runtime_with_image()
        self.be = SB.attach(self.ctx.s, SB.DockerBackend(self.repo, image, runtime=rt, sid="p7-real"))

    def _procs(self):
        r = SB.default_runner([self.be.runtime, "exec", self.be.name, "sh", "-c",
                               "for p in /proc/[0-9]*; do tr '\\0' ' ' <$p/cmdline; echo; done"], timeout=30)
        return r.stdout

    def test_end_to_end(self):
        out = G.t_bash(self.ctx, "echo hello > made.txt; id -u")
        self.assertTrue(out.startswith("exit 0"), out)
        self.assertIn(str(os.getuid()), out)
        made = os.path.join(self.repo, "made.txt")
        self.assertEqual(os.stat(made).st_uid, os.getuid())    # the user's own file on the host, not root's
        # network is off by default
        net = G.t_bash(self.ctx, "python3 -c \"import socket; socket.create_connection(('1.1.1.1', 53), 3)\"")
        self.assertNotIn("exit 0", net.splitlines()[0])
        # the root filesystem is read-only, /tmp is writable
        self.assertNotIn("exit 0", G.t_bash(self.ctx, "touch /etc/gnoc-x").splitlines()[0])
        self.assertTrue(G.t_bash(self.ctx, "touch /tmp/ok").startswith("exit 0"))

    def test_ctrl_c_really_kills_sleep_60(self):
        box, ev = {}, threading.Event()

        def work():
            with G._cancel_scope(ev):
                box["out"] = G.t_bash(self.ctx, "sleep 60 & sleep 61")
        th = threading.Thread(target=work, daemon=True)
        th.start()
        deadline = time.monotonic() + 30
        while "sleep 61" not in self._procs() and time.monotonic() < deadline:
            time.sleep(0.3)
        self.assertIn("sleep 61", self._procs())
        ev.set()
        th.join(30)
        self.assertIn("INTERRUPTED", box.get("out", ""))
        time.sleep(0.5)
        procs = self._procs()
        self.assertNotIn("sleep 60", procs)
        self.assertNotIn("sleep 61", procs)

    def test_symlink_out_of_the_mount_is_refused_in_the_real_container(self):
        outside = self.write("x.txt", "outside\n", base=self.ws)
        self.assertTrue(G.t_bash(self.ctx, f"ln -s {outside} link.txt").startswith("exit 0"))
        self.assertIn("refused", G.t_read_file(self.ctx, "link.txt"))


if __name__ == "__main__":
    unittest.main()
