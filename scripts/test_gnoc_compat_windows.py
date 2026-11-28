#!/usr/bin/env python3
"""Native Windows support (gnoc_compat, the Windows launcher, the PowerShell shell). The Windows half runs on a real
Windows machine (the windows CI job); on Linux/macOS it checks that the compat layer changes nothing.

    python -m pytest -q scripts/test_gnoc_compat_windows.py
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_compat  # noqa: E402

gnoc_compat.install()
WIN = os.name == "nt"


@unittest.skipUnless(WIN, "native Windows only")
class OnWindows(unittest.TestCase):
    def test_fcntl_is_there_and_locks(self):
        import fcntl
        fd, path = tempfile.mkstemp()
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            fd2 = os.open(path, os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)   # held by fd: a second holder is refused
                fcntl.flock(fd, fcntl.LOCK_UN)
                fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)       # free again
                fcntl.flock(fd2, fcntl.LOCK_UN)
            finally:
                os.close(fd2)
        finally:
            os.close(fd)
            os.remove(path)

    def test_signals_and_process_groups_exist(self):
        import signal
        for name in ("SIGKILL", "SIGHUP", "SIGQUIT", "SIGTERM"):
            self.assertTrue(hasattr(signal, name), name)
        self.assertTrue(hasattr(os, "killpg") and hasattr(os, "getpgid"))

    def test_the_shell_is_powershell_and_runs(self):
        argv = gnoc_compat.shell_argv("Write-Output ('gnoc' + 'ok'); $PSVersionTable.PSVersion.Major")
        self.assertIn(os.path.basename(argv[0]).lower(), ("powershell.exe", "pwsh.exe", "powershell", "pwsh"))
        out = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("gnocok", out.stdout)

    def test_kill_tree_ends_the_children(self):
        argv = gnoc_compat.shell_argv("Start-Process -NoNewWindow ping -ArgumentList '-n','60','127.0.0.1'; Start-Sleep 60")
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(4)
        gnoc_compat.kill_tree(p.pid)
        p.wait(timeout=30)
        self.assertIsNotNone(p.returncode)

    def test_the_launcher_makes_a_junction(self):
        import importlib.util
        launcher = os.path.join(os.path.dirname(HERE), "gnoc-launcher.py")
        if not os.path.isfile(launcher):
            self.skipTest("gnoc-launcher.py ships in the Windows package")
        spec = importlib.util.spec_from_file_location("gnoc_launcher_win", launcher)
        L = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(L)
        base = tempfile.mkdtemp()
        target = os.path.join(base, "target")
        os.makedirs(os.path.join(target, "inner"))
        link = os.path.join(base, "link")
        L._junction(link, target)
        self.assertTrue(os.path.isdir(os.path.join(link, "inner")))
        L._junction(link, target)   # again: a no-op, never an error


class Everywhere(unittest.TestCase):
    def test_shell_argv(self):
        argv = gnoc_compat.shell_argv("echo hi")
        if WIN:
            self.assertEqual(argv[-2:], ["-Command", "echo hi"])
        else:
            self.assertEqual(argv, ["bash", "-c", "echo hi"])
            self.assertEqual(gnoc_compat.shell_argv("x", login=True), ["bash", "-lc", "x"])

    def test_install_changes_nothing_off_windows(self):
        if WIN:
            self.skipTest("Windows has its own checks")
        import fcntl
        self.assertNotEqual(getattr(fcntl, "__file__", None) or "builtin", None)
        self.assertFalse(hasattr(gnoc_compat, "_fcntl_shim_installed"))
        self.assertIs(sys.modules["fcntl"], fcntl)


class PowerShellReadsRunWithoutAsking(unittest.TestCase):
    """On Windows the agent's shell is PowerShell: its read-only commands run at once, everything else asks."""

    def test_reads_and_writes(self):
        from unittest import mock
        import gnoc_agent as G
        with mock.patch.object(os, "name", "nt"):
            for c in ("Get-ChildItem -Recurse", "Get-Content README.md | Select-String TODO", "git status",
                      "Test-Path .venv", "Get-Process python"):
                self.assertTrue(G._bash_readonly(c), c)
            for c in ("Remove-Item x", "Get-ChildItem | Remove-Item", "Get-ChildItem | ForEach-Object { Remove-Item $_ }",
                      "Sort-Object { rm x }", "git push", "Get-Content a.txt > b.txt", "Set-Content a.txt x"):
                self.assertFalse(G._bash_readonly(c), c)


class TheProjectsPythonOnWindows(unittest.TestCase):
    def test_a_windows_venv_and_never_the_store_stub(self):
        from unittest import mock
        from gnoc_core import testing as T
        tmp = tempfile.mkdtemp()
        win_py = os.path.join(tmp, ".venv", "Scripts", "python.exe")
        os.makedirs(os.path.dirname(win_py))
        open(win_py, "w").close()
        os.chmod(win_py, 0o755)
        with mock.patch.object(os, "name", "nt"):
            self.assertEqual(T.project_python(tmp), win_py)
            bare = tempfile.mkdtemp()
            stub = r"C:\Users\u\AppData\Local\Microsoft\WindowsApps\python3.exe"
            with mock.patch("shutil.which", side_effect=lambda n, path=None: stub if n == "python3" else None):
                self.assertEqual(T.project_python(bare), sys.executable)


if __name__ == "__main__":
    unittest.main()
