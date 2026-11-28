"""gnoc_compat.py - what gnoc needs from the operating system, on native Windows too.

gnoc chat was written for Linux and macOS. On Windows it used to run inside WSL; it now runs natively (PowerShell,
cmd, Windows Terminal). This module is the one place that knows the difference. `install()` runs before anything
else imports (scripts/gnoc and gnoc_agent call it first) and does nothing at all on Linux or macOS.

On Windows it:
  - provides an `fcntl` module whose flock() is msvcrt.locking on byte 0 of the lock file (every gnoc lock is a
    dedicated lock file, so locking one byte of it is the whole lock), with LOCK_NB raising BlockingIOError exactly
    as fcntl does. ioctl() raises OSError (only the Linux desktop-input driver uses it, and that is off here).
  - gives `signal` the termination signals Windows lacks (SIGKILL, SIGHUP, SIGQUIT) as SIGTERM, which on Windows
    already means TerminateProcess. Stop/continue signals are NOT faked: code that pauses a process must check.
  - provides os.killpg / os.getpgid: a "process group" is the process and its children, ended with
    `taskkill /T /F` (subprocess ignores start_new_session on Windows, so the group id is the leader's pid).
  - turns on ANSI colour handling in the console (VT processing) and makes stdout/stderr UTF-8 with replacement,
    so a box-drawing character never crashes a turn on a code-page console or a pipe.

Helpers everyone may use, on every platform: IS_WINDOWS, shell_argv(command) (the shell the agent's commands run
in: bash on Linux/macOS, PowerShell on Windows), shell_name(), kill_tree(pid).
"""
from __future__ import annotations

import os
import subprocess
import sys
import types

IS_WINDOWS = os.name == "nt"
_INSTALLED = [False]


# ------------------------------------------------------------------ the shell the agent runs commands in
def powershell():
    """pwsh (PowerShell 7) when installed, else Windows PowerShell 5.1, which every Windows 10/11 has."""
    import shutil
    return shutil.which("pwsh") or shutil.which("powershell") or "powershell.exe"


def shell_name():
    return "PowerShell" if IS_WINDOWS else "bash"


def shell_argv(command, login=False):
    """argv that runs `command` in the agent's shell: bash on Linux/macOS (-lc for a login shell when asked),
    PowerShell on Windows (no profile, non-interactive, so a user's profile can never hang or change a command)."""
    if IS_WINDOWS:
        return [powershell(), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-Command", command]
    return ["bash", "-lc" if login else "-c", command]


def kill_tree(pid):
    """End a process and everything it started. POSIX: its process group (it was started in a new session);
    Windows: taskkill /T /F."""
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(int(pid))], capture_output=True)
        return
    import signal
    try:
        os.killpg(int(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ------------------------------------------------------------------ Windows stand-ins
def _fcntl_module():
    m = types.ModuleType("fcntl")
    m.LOCK_SH, m.LOCK_EX, m.LOCK_NB, m.LOCK_UN = 1, 2, 4, 8
    m.F_GETFL, m.F_SETFL, m.F_GETFD, m.F_SETFD = 3, 4, 1, 2

    def _fd(f):
        return f if isinstance(f, int) else f.fileno()

    def flock(f, op):
        import msvcrt
        import time
        fd = _fd(f)
        pos = os.lseek(fd, 0, os.SEEK_CUR)
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            if op & m.LOCK_UN:
                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass   # unlocking a region that is not locked is not an error for flock
                return
            if op & m.LOCK_NB:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as e:
                    raise BlockingIOError(11, "Resource temporarily unavailable") from e
                return
            while True:   # LK_LOCK gives up after ~10 s; flock waits as long as it takes
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    return
                except OSError:
                    time.sleep(0.05)
        finally:
            os.lseek(fd, pos, os.SEEK_SET)

    def lockf(f, op, *_a):
        return flock(f, op)

    def ioctl(*_a, **_k):
        raise OSError("ioctl is not available on Windows")

    def fcntl(*_a, **_k):
        return 0

    m.flock, m.lockf, m.ioctl, m.fcntl = flock, lockf, ioctl, fcntl
    return m


def _console_vt():
    """ANSI escape handling for the classic console (Windows Terminal has it already)."""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        for std in (-11, -12):   # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            h = k32.GetStdHandle(std)
            mode = ctypes.c_uint32()
            if k32.GetConsoleMode(h, ctypes.byref(mode)):
                k32.SetConsoleMode(h, mode.value | 0x0004)   # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        k32.SetConsoleOutputCP(65001)
    except Exception:  # noqa: BLE001 - colours are a nicety, never a reason to fail
        pass


def install():
    """Make the Windows process look enough like POSIX for gnoc. A no-op anywhere else, and idempotent."""
    if not IS_WINDOWS or _INSTALLED[0]:
        return
    _INSTALLED[0] = True
    sys.modules.setdefault("fcntl", _fcntl_module())
    import signal
    for name in ("SIGKILL", "SIGHUP", "SIGQUIT"):
        if not hasattr(signal, name):
            setattr(signal, name, signal.SIGTERM)
    if not hasattr(os, "killpg"):
        os.killpg = lambda pgid, sig: kill_tree(pgid)   # noqa: E731 - every gnoc "group" is a process tree
    if not hasattr(os, "getpgid"):
        os.getpgid = lambda pid: pid   # noqa: E731
    if not hasattr(os, "getuid"):
        os.getuid = lambda: 1000   # noqa: E731 - "not root": nothing on Windows runs as uid 0
    os.environ.setdefault("PYTHONUTF8", "1")      # children (hooks, tests) print UTF-8 too
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    _console_vt()
