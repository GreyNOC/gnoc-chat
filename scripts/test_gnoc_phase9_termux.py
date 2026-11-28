#!/usr/bin/env python3
"""Phase 9: gnoc inside Termux on Android. The detector, the installer (dry runs in a faked Termux and a plain
Linux, plus a real sandboxed Linux run that pins the old behaviour), the doctor, the setup's model choices, and
the defender's reduced read-only checks and crond schedule. Nothing here needs a phone: every Termux is faked
with TERMUX_VERSION / PREFIX in a temp directory, and every subprocess that would touch the machine is a fake.

    python3 -m pytest -q scripts/test_gnoc_phase9_termux.py
"""
import contextlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
# a release ships install.sh at its root; the operator's workspace keeps it as a release template under
# scripts/gnoc_release_files/ (the same convention test_gnoc_update.py follows for gnoc_update.py)
# a default, never an import-time StopIteration: the release smoke test imports every module from a copy of
# scripts/ alone, where neither path exists (the Installer tests then skip, they do not crash the import)
INSTALL_SH = next((p for p in (os.path.join(HERE, "gnoc_release_files", "install.sh"), os.path.join(APP, "install.sh"))
                   if os.path.isfile(p)), os.path.join(APP, "install.sh"))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402,F401 - the suite's convention: the facade loads first
import gnoc_platform as P  # noqa: E402
import gnoc_termux as T  # noqa: E402


def _old_on_android():
    """gnoc_engine.on_android() as it was before this phase, verbatim: the delegate must agree with it."""
    return hasattr(sys, "getandroidapilevel") or bool(os.environ.get("TERMUX_VERSION")) \
        or os.path.isdir("/data/data/com.termux/files/usr")


@contextlib.contextmanager
def plain_env(**extra):
    """No Termux markers at all, whatever the machine running the tests has."""
    real_isdir = os.path.isdir
    with mock.patch.dict(os.environ, extra):
        for k in ("TERMUX_VERSION", "PREFIX"):
            os.environ.pop(k, None)   # patch.dict restores them on exit
        with mock.patch("os.path.isdir", lambda p: False if p == P.TERMUX_USR else real_isdir(p)):
            yield


@contextlib.contextmanager
def termux_env(root, version="0.118"):
    """A faked Termux: TERMUX_VERSION, PREFIX and HOME under root. -> the prefix."""
    prefix = os.path.join(root, "data", "data", "com.termux", "files", "usr")
    home = os.path.join(root, "home")
    os.makedirs(os.path.join(prefix, "bin"), exist_ok=True)
    os.makedirs(home, exist_ok=True)
    env = {"PREFIX": prefix, "HOME": home}
    if version:
        env["TERMUX_VERSION"] = version
    with mock.patch.dict(os.environ, env):
        if not version:
            os.environ.pop("TERMUX_VERSION", None)
        yield prefix


# ---------------------------------------------------------------- the detector
class Detector(unittest.TestCase):
    def test_termux_version_marks_termux(self):
        self.assertTrue(P.is_termux({"TERMUX_VERSION": "0.118"}, lambda p: False))

    def test_prefix_alone_marks_termux(self):
        self.assertTrue(P.is_termux({"PREFIX": "/data/data/com.termux/files/usr"}, lambda p: False))
        self.assertTrue(P.is_termux({"PREFIX": "/tmp/x/data/data/com.termux/files/usr/"}, lambda p: False))

    def test_install_root_on_disk_marks_termux(self):
        self.assertTrue(P.is_termux({}, lambda p: p == P.TERMUX_USR))

    def test_plain_linux_is_not_termux(self):
        for env in ({}, {"PREFIX": "/usr"}, {"PREFIX": "/data/data/com.termux.evil/files/usr"},
                    {"PREFIX": "/data/data/com.termux/files/usr/lib"}, {"TERMUX_VERSION": ""}):
            self.assertFalse(P.is_termux(env, lambda p: False), env)

    def test_termux_prefix(self):
        self.assertEqual(P.termux_prefix({"PREFIX": "/t/data/data/com.termux/files/usr/"}, lambda p: False),
                         "/t/data/data/com.termux/files/usr")
        self.assertEqual(P.termux_prefix({"TERMUX_VERSION": "1"}, lambda p: False), P.TERMUX_USR)
        self.assertEqual(P.termux_prefix({"PREFIX": "/usr"}, lambda p: False), "")

    def test_on_android_matches_the_old_engine_test_exactly(self):
        sys_with = types.SimpleNamespace(getandroidapilevel=lambda: 34)
        sys_without = types.SimpleNamespace()
        for env in ({}, {"TERMUX_VERSION": "0.118"}, {"PREFIX": "/data/data/com.termux/files/usr"},
                    {"TERMUX_VERSION": ""}):
            for dir_there in (False, True):
                for sm in (sys_with, sys_without):
                    def isdir(p, there=dir_there):
                        return there and p == P.TERMUX_USR
                    with mock.patch.dict(os.environ, env, clear=True), \
                            mock.patch.object(sys, "getandroidapilevel", sm.getandroidapilevel, create=True) \
                            if hasattr(sm, "getandroidapilevel") else contextlib.nullcontext(), \
                            mock.patch("os.path.isdir", isdir):
                        if not hasattr(sm, "getandroidapilevel") and hasattr(sys, "getandroidapilevel"):
                            continue   # a real Android Python running the suite: cannot fake its absence
                        self.assertEqual(P.on_android(), _old_on_android(), (env, dir_there, sm))

    def test_engine_delegates_and_falls_back_without_the_module(self):
        import gnoc_engine as E
        with mock.patch.dict(os.environ, {"TERMUX_VERSION": "0.118"}):
            self.assertTrue(E.on_android())
            self.assertEqual(E.pick_variant(), "android-arm64")
            # the phone gets gnoc_engine.py alone: no gnoc_platform to import there
            with mock.patch.dict(sys.modules, {"gnoc_platform": None}):
                self.assertTrue(E.on_android())
        with plain_env(), mock.patch("os.path.isdir", lambda p: False):
            if not hasattr(sys, "getandroidapilevel"):
                self.assertFalse(E.on_android())
                with mock.patch.dict(sys.modules, {"gnoc_platform": None}):
                    self.assertFalse(E.on_android())

    def test_kind(self):
        no = lambda p: False  # noqa: E731
        self.assertEqual(P.kind({"TERMUX_VERSION": "1"}, no), "termux")
        self.assertEqual(P.kind({}, no, "Linux", "5.15.0-microsoft-standard-WSL2"), "wsl")
        self.assertEqual(P.kind({}, no, "Darwin", "23.0"), "darwin")
        self.assertEqual(P.kind({}, no, "Linux", "6.8.0"), "linux")

    def test_pkg_hint_and_unavailable(self):
        self.assertEqual(P.pkg_hint("python", "git", env={"TERMUX_VERSION": "1"}, isdir=lambda p: False),
                         "pkg install python git")
        self.assertEqual(P.pkg_hint("git", env={}, isdir=lambda p: False), "")
        self.assertEqual(P.pkg_hint(env={"TERMUX_VERSION": "1"}, isdir=lambda p: False), "")
        msg = P.unavailable("the firewall")
        self.assertIn("needs root or systemd, not available on Termux", msg)
        self.assertNotIn("sudo", msg)

    def test_crond_state(self):
        env = {"TERMUX_VERSION": "1", "PREFIX": "/t/data/data/com.termux/files/usr"}
        sv = "/t/data/data/com.termux/files/usr/var/service/crond"
        self.assertEqual(P.crond_state({}, lambda p: False, lambda n: "/x"), "")
        self.assertEqual(P.crond_state(env, lambda p: False, lambda n: None), "no-crontab")
        self.assertEqual(P.crond_state(env, lambda p: False, lambda n: "/x", lambda p: False), "no-service")
        # installed but not enabled: termux-services keeps a `down` file until sv-enable
        self.assertEqual(P.crond_state(env, lambda p: p == sv, lambda n: "/x", lambda p: p.endswith("/down")),
                         "no-service")
        self.assertEqual(P.crond_state(env, lambda p: p == sv, lambda n: "/x", lambda p: False), "ok")

    def test_doctor_and_defender_agree_on_the_schedule_mark(self):
        import gnoc_defender
        import gnoc_doctor
        self.assertEqual(gnoc_doctor.SCHEDULE_MARK, gnoc_defender.SCHEDULE_MARK)


# ---------------------------------------------------------------- install.sh
@unittest.skipUnless(shutil.which("bash"), "install.sh needs bash")
@unittest.skipUnless(os.path.isfile(INSTALL_SH), "install.sh is not beside this copy of scripts/")
class Installer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p9-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(self.app, "scripts"))
        shutil.copy(INSTALL_SH, self.app)
        with open(os.path.join(self.app, "VERSION"), "w") as fh:
            fh.write("9.9.9\n")
        self.log = os.path.join(self.tmp, "launcher.log")
        self._stub("gnoc-launcher", f'#!/bin/sh\necho "launcher $* PYTHON=$PYTHON" >> "{self.log}"\nexit 0\n')
        self._stub(os.path.join("scripts", "gnoc"), "#!/bin/sh\n")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.py_dir = os.path.dirname(os.path.realpath(sys.executable))

    def _stub(self, rel, text):
        p = os.path.join(self.app, rel)
        with open(p, "w") as fh:
            fh.write(text)
        os.chmod(p, 0o644)   # install.sh makes it executable (in a real run)

    def run_install(self, env, path_extra=()):
        base = {"HOME": self.home, "SHELL": "/bin/bash",
                "PATH": os.pathsep.join([*path_extra, self.py_dir, "/usr/bin", "/bin"]), "PYTHON": sys.executable}
        base.update(env)
        r = subprocess.run(["bash", os.path.join(self.app, "install.sh")], env=base, capture_output=True,
                           text=True, timeout=60, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout + r.stderr

    def _termux(self, version="0.118"):
        prefix = os.path.join(self.tmp, "data", "data", "com.termux", "files", "usr")
        os.makedirs(os.path.join(prefix, "bin"), exist_ok=True)
        env = {"PREFIX": prefix}
        if version:
            env["TERMUX_VERSION"] = version
        return prefix, env

    def _created(self):
        out = []
        for root, dirs, files in os.walk(self.tmp):
            for n in dirs + files:
                out.append(os.path.relpath(os.path.join(root, n), self.tmp))
        return sorted(out)

    def test_termux_dry_run_uses_pkg_and_termux_paths_and_changes_nothing(self):
        prefix, env = self._termux()
        before = self._created()
        rc, out = self.run_install({**env, "GNOC_INSTALL_DRY_RUN": "1"}, path_extra=[os.path.join(prefix, "bin")])
        self.assertEqual(rc, 0, out)
        self.assertIn("Termux on Android", out)
        self.assertIn("pkg install cronie termux-services", out)
        self.assertNotIn("sudo", out)
        self.assertNotRegex(out, r"\bapt\b")
        self.assertNotIn("/usr/local", out)
        self.assertNotIn("/opt", out)
        actions = [ln.split("[dry run] ", 1)[1] for ln in out.splitlines() if "[dry run] " in ln]
        self.assertTrue(any(a.startswith("ln -sf ") and a.endswith(os.path.join(prefix, "bin", "gnoc"))
                            for a in actions), actions)
        for a in actions:
            for word in a.split():
                if word.startswith("/"):
                    self.assertTrue(word.startswith((prefix, self.home, self.app)), (word, a))
        # $PREFIX/bin is on Termux's PATH, so no shell file is edited
        self.assertFalse(any(a.startswith("append to") for a in actions), actions)
        self.assertEqual(self._created(), before, "a dry run must not create or change anything")
        self.assertFalse(os.path.exists(self.log), "a dry run must not build the Python environment")

    def test_termux_detected_from_prefix_alone(self):
        prefix, env = self._termux(version="")
        rc, out = self.run_install({**env, "GNOC_INSTALL_DRY_RUN": "1"}, path_extra=[os.path.join(prefix, "bin")])
        self.assertEqual(rc, 0, out)
        self.assertIn("Termux on Android", out)
        self.assertIn(os.path.join(prefix, "bin", "gnoc"), out)

    def test_termux_real_run_links_into_prefix_bin(self):
        prefix, env = self._termux()
        rc, out = self.run_install(env, path_extra=[os.path.join(prefix, "bin")])
        self.assertEqual(rc, 0, out)
        link = os.path.join(prefix, "bin", "gnoc")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), os.path.join(self.app, "gnoc-launcher"))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".local", "bin", "gnoc")))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".bashrc")))
        with open(self.log) as fh:
            self.assertIn("launcher help", fh.read())

    def test_termux_missing_python_says_pkg_not_sudo(self):
        _prefix, env = self._termux()
        rc, out = self.run_install({**env, "PYTHON": "gnoc-no-such-python"})
        self.assertEqual(rc, 1)
        self.assertIn("pkg install python git", out)
        self.assertNotIn("sudo", out)
        self.assertNotRegex(out, r"\bapt\b")

    def test_termux_environment_failure_says_pkg(self):
        prefix, env = self._termux()
        self._stub("gnoc-launcher", "#!/bin/sh\nexit 3\n")
        rc, out = self.run_install(env, path_extra=[os.path.join(prefix, "bin")])
        self.assertEqual(rc, 1)
        self.assertIn("pkg install python git clang", out)
        self.assertNotIn("sudo", out)

    def test_linux_dry_run_lists_the_desktop_actions_and_changes_nothing(self):
        before = self._created()
        rc, out = self.run_install({"GNOC_INSTALL_DRY_RUN": "1"})
        self.assertEqual(rc, 0, out)
        self.assertNotIn("Termux", out)
        self.assertNotIn("pkg install", out)
        actions = [ln.split("[dry run] ", 1)[1] for ln in out.splitlines() if "[dry run] " in ln]
        bin_dst = os.path.join(self.home, ".local", "bin")
        self.assertIn(f"mkdir -p {bin_dst}", actions)
        self.assertIn(f"ln -sf {os.path.join(self.app, 'gnoc-launcher')} {os.path.join(bin_dst, 'gnoc')}", actions)
        self.assertTrue(any(a.startswith(f"append to {os.path.join(self.home, '.bashrc')}: export PATH=")
                            for a in actions), actions)
        self.assertEqual(self._created(), before)

    def test_linux_real_run_is_the_pre_termux_behaviour(self):
        """What the installer did before this phase (checked against the old script in a sandbox): the launcher
        builds the environment with PYTHON set, the command is linked into ~/.local/bin, and one PATH line goes
        into ~/.bashrc under the installer's comment. The desktop closing text is unchanged."""
        rc, out = self.run_install({})
        self.assertEqual(rc, 0, out)
        bin_dst = os.path.join(self.home, ".local", "bin")
        self.assertEqual(os.readlink(os.path.join(bin_dst, "gnoc")), os.path.join(self.app, "gnoc-launcher"))
        with open(os.path.join(self.home, ".bashrc")) as fh:
            self.assertEqual(fh.read(), f'\n# added by the gnoc chat installer\nexport PATH="{bin_dst}:$PATH"\n')
        with open(self.log) as fh:
            self.assertEqual(fh.read(), f"launcher help PYTHON={sys.executable}\n")
        self.assertTrue(os.stat(os.path.join(self.app, "gnoc-launcher")).st_mode & stat.S_IXUSR)
        self.assertIn("gnoc engine install && gnoc engine start", out)
        self.assertNotIn("Termux", out)
        # a second run adds no second PATH line
        rc, _ = self.run_install({})
        with open(os.path.join(self.home, ".bashrc")) as fh:
            self.assertEqual(fh.read().count("export PATH="), 1)

    def test_linux_missing_python_keeps_the_desktop_hint(self):
        rc, out = self.run_install({"PYTHON": "gnoc-no-such-python"})
        self.assertEqual(rc, 1)
        self.assertNotIn("pkg install", out)
        if os.uname().sysname != "Darwin":
            self.assertIn("sudo apt install python3 python3-venv", out)


# ---------------------------------------------------------------- gnoc doctor
class Doctor(unittest.TestCase):
    def setUp(self):
        import gnoc_doctor
        self.D = gnoc_doctor
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p9d-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_platform_rows_inside_termux(self):
        with termux_env(self.tmp), mock.patch.object(self.D, "_crontab_has_gnoc", return_value=False), \
                mock.patch("shutil.which", return_value=None):
            rows = []
            self.D.check_platform(rows)
        labels = [r["label"] for r in rows]
        self.assertIn("platform", labels)
        self.assertIn("root and systemd features", labels)
        self.assertTrue(all(r["status"] == self.D.OK for r in rows), rows)
        text = " ".join(r["detail"] + r["fix"] for r in rows)
        self.assertIn("not available on Termux", text)
        self.assertIn("sv-enable crond", text)
        self.assertNotIn("sudo", text)

    def test_schedule_without_crond_is_a_warning(self):
        with termux_env(self.tmp), mock.patch.object(self.D, "_crontab_has_gnoc", return_value=True), \
                mock.patch("shutil.which", return_value="/x/crontab"):
            rows = []
            self.D.check_platform(rows)
        row = next(r for r in rows if r["label"] == "scheduled sweeps")
        self.assertEqual(row["status"], self.D.WARN)
        self.assertIn("sv-enable crond", row["fix"])

    def test_no_platform_rows_off_termux(self):
        with plain_env():
            rows = []
            self.D.check_platform(rows)
            self.D.check_termux_models(rows)
        self.assertEqual(rows, [])

    def test_git_and_workspace_fixes_inside_termux_never_say_sudo(self):
        ws = os.path.join(self.tmp, "ws")
        os.makedirs(ws)
        with termux_env(self.tmp), mock.patch.dict(os.environ, {"GNOC_WORKSPACE": ws}), \
                mock.patch.object(self.D.shutil, "which", return_value=None), \
                mock.patch.object(self.D.os, "access", return_value=False):
            rows = []
            self.D.check_install(rows)
            with mock.patch.dict(sys.modules, {"llm_endpoints": None}):
                self.D.check_workspace(rows)
        git = next(r for r in rows if r["label"] == "git")
        self.assertEqual(git["fix"], "pkg install git")
        wsrow = next(r for r in rows if r["label"] == "workspace")
        self.assertNotIn("sudo", wsrow["fix"])
        self.assertNotIn("sudo", " ".join(r["fix"] for r in rows))

    def test_workspace_fix_off_termux_is_unchanged(self):
        ws = os.path.join(self.tmp, "ws")
        os.makedirs(ws)
        with plain_env(GNOC_WORKSPACE=ws), mock.patch.object(self.D.os, "access", return_value=False), \
                mock.patch.dict(sys.modules, {"llm_endpoints": None}):
            rows = []
            self.D.check_workspace(rows)
        self.assertEqual(rows[0]["fix"], f"fix its owner: sudo chown -R $USER {ws}")

    def test_model_choices_shown_only_when_the_lead_fails(self):
        with termux_env(self.tmp):
            rows = [{"status": self.D.FAIL, "label": "lead model", "detail": "", "fix": ""}]
            self.D.check_termux_models(rows)
            self.assertEqual(rows[-1]["label"], "a model for this phone")
            self.assertIn("desktop", rows[-1]["detail"])
            self.assertIn("cloud", rows[-1]["detail"])
            self.assertIn("small model on this phone", rows[-1]["detail"])
            ok = [{"status": self.D.OK, "label": "lead model", "detail": "", "fix": ""}]
            self.D.check_termux_models(ok)
            self.assertEqual(len(ok), 1)


# ---------------------------------------------------------------- gnoc setup
class Setup(unittest.TestCase):
    def setUp(self):
        import gnoc_setup
        import llm_endpoints
        self.S, self.L = gnoc_setup, llm_endpoints
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p9s-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        p = mock.patch.object(gnoc_setup, "STATE", os.path.join(self.tmp, "setup.json"))
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(llm_endpoints, "allow_stock", return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def io(self, answers):
        said, asked = [], []
        it = iter(answers)

        def ask(prompt):
            asked.append(prompt)
            return next(it)
        return self.S.Io(ask=ask, say=said.append, secret=lambda p: ""), said, asked

    def test_machine_inside_termux(self):
        with termux_env(self.tmp):
            m = self.S.machine()
        self.assertEqual(m["os"], "termux")
        self.assertTrue(m["termux"])
        self.assertEqual(m["vram_gb"], 0.0)

    def test_phone_sized_models_never_desktop_ones(self):
        rec = self.S.recommend
        base = {"os": "termux", "vram_gb": 0.0, "apple": False, "termux": True}
        self.assertEqual(rec({**base, "ram_gb": 11.0})[0], "qwen3:4b")
        self.assertEqual(rec({**base, "ram_gb": 7.5})[0], "qwen3:1.7b")
        self.assertEqual(rec({**base, "ram_gb": 3.0})[0], "qwen3:0.6b")
        self.assertEqual(rec({**base, "ram_gb": 0.0})[0], "qwen3:0.6b")
        # even a phone that reports a lot of memory never gets an 8B or a 14B
        self.assertNotIn(rec({**base, "ram_gb": 24.0})[0], {t[0] for t in self.S.TIERS[:2]})

    def test_termux_menu_offers_three_ways_and_defaults_to_the_cloud_when_unpaired(self):
        with termux_env(self.tmp), mock.patch.dict(self.L.HOSTS, {"desktop": ""}), \
                mock.patch.object(self.S, "machine", return_value={"os": "termux", "ram_gb": 8.0, "vram_gb": 0.0,
                                                                   "apple": False, "termux": True}):
            io, said, asked = self.io(["4"])
            self.assertFalse(self.S.run(lambda r, s: None, io))
        text = "\n".join(said)
        self.assertIn("desktop", text)
        self.assertIn("cloud model", text)
        self.assertIn("small model on this phone (qwen3:1.7b", text)
        self.assertNotIn("a model on this computer: free and private (recommended)", text)
        self.assertIn("[2]", asked[0])

    def test_termux_menu_defaults_to_a_paired_desktop(self):
        with termux_env(self.tmp), mock.patch.dict(self.L.HOSTS, {"desktop": "192.168.1.20:11434"}):
            io, said, asked = self.io(["4"])
            self.S.run(lambda r, s: None, io)
        self.assertIn("[1]", asked[0])
        self.assertIn("already paired", "\n".join(said))

    def test_termux_choices_route_to_the_existing_paths(self):
        for answer, chosen in (("1", "_remote_path"), ("2", "_cloud_path"), ("3", "_local_path")):
            calls = []
            fakes = {n: (lambda io, sr, n=n: calls.append(n) or True)
                     for n in ("_remote_path", "_cloud_path", "_local_path")}
            with termux_env(self.tmp), mock.patch.multiple(self.S, **fakes):
                io, _said, _asked = self.io([answer])
                self.assertTrue(self.S.run(lambda r, s: None, io))
            self.assertEqual(calls, [chosen])

    def test_termux_first_run_shows_the_menu_instead_of_installing(self):
        with termux_env(self.tmp), mock.patch.object(self.S, "auto", side_effect=AssertionError("auto ran")):
            io, said, _asked = self.io(["q"])
            self.assertFalse(self.S.first_run(lambda r, s: None, io))
        self.assertIn("small model on this phone", "\n".join(said))

    def test_desktop_menu_is_unchanged(self):
        with plain_env():
            io, said, asked = self.io(["4"])
            self.S.run(lambda r, s: None, io)
        self.assertIn("    1) a model on this computer: free and private (recommended)", said)
        self.assertIn("[1]", asked[0])
        self.assertNotIn("phone", "\n".join(said))


# ---------------------------------------------------------------- the defender
TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F56 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid}        0 1 1
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid}        0 2 1
   2: 0100007F:1F90 0100007F:9C40 01 00000000:00000000 00:00000000 00000000 {uid}        0 3 1
   3: garbage line
   4: ZZZZZZZZ:1F56 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid}        0 4 1
"""
TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 5 1
"""  # noqa: E501


class TermuxChecks(unittest.TestCase):
    def test_parse_proc_net(self):
        rows = T.parse_proc_net(TCP.format(uid=os.getuid()), "tcp")
        self.assertEqual([(r["addr"], r["port"], r["bind"]) for r in rows],
                         [("0.0.0.0", 8022, "all"), ("127.0.0.1", 8080, "loopback")])
        six = T.parse_proc_net(TCP6, "tcp6")
        self.assertEqual((six[0]["addr"], six[0]["port"], six[0]["bind"], six[0]["proto"]), ("::", 80, "all", "tcp"))
        self.assertEqual(T.parse_proc_net("", "udp"), [])

    def test_hidden_socket_table_reads_as_not_checked(self):
        def deny(path):
            raise PermissionError(path)
        self.assertIsNone(T.listening(deny))
        rows, notes = T.host_checks("/p", "/h", read=deny, run=lambda a: (1, ""), isdir=lambda p: False,
                                    which=lambda n: None)
        self.assertEqual(rows, [])
        self.assertTrue(any("not checked" in n for n in notes))
        self.assertIn(T.HIDDEN, notes)

    def test_sshd_settings(self):
        self.assertEqual(T.sshd_settings(""), {"port": [8022], "password": "yes"})
        self.assertEqual(T.sshd_settings("PasswordAuthentication no\nPort 2222\n")["password"], "no")
        self.assertEqual(T.sshd_settings("PasswordAuthentication yes\nPasswordAuthentication no\n")["password"],
                         "yes")
        self.assertEqual(T.sshd_settings("# PasswordAuthentication no\n")["password"], "yes")
        self.assertEqual(T.sshd_settings("Match User x\n  PasswordAuthentication no\n")["password"], "yes")

    def test_host_checks_on_a_faked_phone(self):
        files = {"/proc/net/tcp": TCP.format(uid=os.getuid()), "/proc/net/tcp6": TCP6,
                 "/p/etc/ssh/sshd_config": "PrintMotd yes\n"}

        def read(path):
            if path in files:
                return files[path]
            raise FileNotFoundError(path)

        def run(argv):
            self.assertEqual(argv, ["apt", "list", "--upgradable"])
            return 0, ("Listing...\nopenssl/stable 3.3 aarch64 [upgradable from: 3.2]\n"
                       "curl/stable 8.9 aarch64 [upgradable from: 8.8]\n")
        rows, notes = T.host_checks("/p", "/h", read=read, run=run, isdir=lambda p: p == "/h/storage",
                                    which=lambda n: "/p/bin/apt")
        by = {r[0]: r for r in rows}
        self.assertEqual(by["ssh:password"][1], "high")   # password login AND listening on 8022
        self.assertIn("8022", by["ssh:password"][3])
        self.assertIn("port:tcp:8022", by)
        self.assertIn("another app, uid 10123", by["port:tcp:80"][3])
        self.assertNotIn("port:tcp:8080", by)   # loopback only
        self.assertEqual(by["storage:shared"][1], "info")
        self.assertIn("2 Termux package", by["pkg:upgrades"][3])
        self.assertEqual(by["pkg:upgrades"][4], "pkg upgrade")
        for r in rows:
            self.assertNotIn("sudo", r[4])
        self.assertIn(T.HIDDEN, notes)

    def test_unreadable_package_lists(self):
        self.assertIsNone(T.pending_upgrades(lambda a: (100, "E: lock")))
        rows, notes = T.host_checks("/p", "/h", read=lambda p: (_ for _ in ()).throw(OSError(p)),
                                    run=lambda a: (100, ""), isdir=lambda p: False, which=lambda n: "/x")
        self.assertTrue(any("package lists were not readable" in n for n in notes))


class DefenderOnTermux(unittest.TestCase):
    def setUp(self):
        import gnoc_defender
        self.F = gnoc_defender
        self.tmp = tempfile.mkdtemp(prefix="gnoc-p9f-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_local_sweep_is_the_reduced_set_and_never_reads_ss(self):
        fake = ([("ssh:password", "warn", "ssh", "fact", "fix")], ["note"])
        with termux_env(self.tmp) as prefix, \
                mock.patch.object(self.F.D, "listening", side_effect=AssertionError("ss ran")), \
                mock.patch("gnoc_termux.host_checks", return_value=fake) as hc:
            out, notes = self.F.sweep(None, profile={})
        self.assertEqual([f["id"] for f in out], ["ssh:password"])
        self.assertIsNone(out[0]["act"])
        self.assertEqual(notes, ["note"])
        self.assertEqual(hc.call_args[0][0], prefix)

    def test_a_named_remote_host_still_gets_the_full_sweep(self):
        class Reached(Exception):
            pass
        with termux_env(self.tmp), mock.patch.object(self.F.D, "listening", side_effect=Reached), \
                mock.patch.object(self.F, "termux_sweep", side_effect=AssertionError("reduced set for a remote")):
            with self.assertRaises(Reached):
                self.F.sweep("admin@server", profile={})

    def test_root_helper_refuses_in_one_line_without_running_sudo(self):
        with termux_env(self.tmp), mock.patch.object(self.F.D, "_run", side_effect=AssertionError("sudo ran")):
            ok, msg = self.F.helper(["block", "203.0.113.9", 60])
            ok2, msg2, _undo = self.F.execute({"kind": "block_ip", "ip": "8.8.8.8"})
        self.assertFalse(ok)
        self.assertFalse(ok2)
        self.assertIn("not available on Termux", msg)
        self.assertIn("not available on Termux", msg2)
        self.assertNotIn("sudo", msg)

    def test_install_hint_inside_termux(self):
        with termux_env(self.tmp):
            text = self.F.install_hint({}, None, None)
        self.assertIn("not available on Termux", text)
        self.assertNotIn("sudo", text)
        with plain_env():
            self.assertIn("sudo install", self.F.install_hint({}, None, None))

    def test_schedule_without_crontab_names_cronie_and_runs_nothing(self):
        with termux_env(self.tmp), mock.patch("shutil.which", return_value=None), \
                mock.patch.object(self.F.subprocess, "run", side_effect=AssertionError("ran")):
            msg = self.F.schedule("every 30m")
        self.assertIn("nothing was scheduled", msg)
        self.assertIn("pkg install cronie termux-services", msg)
        self.assertNotIn("sudo", msg)

    def test_schedule_uses_crontab_and_warns_when_crond_is_off(self):
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw.get("input")))
            if argv == ["crontab", "-l"]:
                return types.SimpleNamespace(returncode=1, stdout="", stderr="no crontab for u0_a123")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with termux_env(self.tmp), \
                mock.patch("shutil.which", side_effect=lambda n: "/x/" + n if n in ("crontab", "gnoc") else None), \
                mock.patch.object(self.F.subprocess, "run", side_effect=run), \
                mock.patch.object(self.F, "SCHEDULE_LOG", os.path.join(self.tmp, "log", "cron.log")):
            msg = self.F.schedule("every 30m")
        self.assertIn("scheduled", msg)
        self.assertIn("sv-enable crond", msg)
        written = [inp for argv, inp in calls if argv == ["crontab", "-"]][0]
        self.assertIn("*/30 * * * *", written)
        self.assertIn(self.F.SCHEDULE_MARK, written)

    def test_schedule_off_termux_has_no_crond_note(self):
        def run(argv, **kw):
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with plain_env(), mock.patch("shutil.which", side_effect=lambda n: "/x/" + n), \
                mock.patch.object(self.F.subprocess, "run", side_effect=run), \
                mock.patch.object(self.F, "SCHEDULE_LOG", os.path.join(self.tmp, "log", "cron.log")):
            msg = self.F.schedule("hourly")
        self.assertNotIn("crond", msg)

    def test_vulnwatch_timer_is_unavailable_and_writes_no_units(self):
        import gnoc_vulnwatch as V
        with termux_env(self.tmp), mock.patch.object(V.subprocess, "run", side_effect=AssertionError("ran")), \
                mock.patch.object(V, "_unit_dir", return_value=os.path.join(self.tmp, "units")):
            for op in ("on", "off", "status"):
                msg = V.timer(op)
                self.assertIn("not available on Termux", msg)
                self.assertIn("/defender schedule", msg)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "units")))

    def test_engine_boot_autostart_explains_termux_boot(self):
        import gnoc_engine as E
        with termux_env(self.tmp), mock.patch.object(E.subprocess, "run", side_effect=AssertionError("ran")):
            ok, how = E.boot_autostart(True)
        self.assertFalse(ok)
        self.assertIn("Termux:Boot", how)


if __name__ == "__main__":
    unittest.main()
