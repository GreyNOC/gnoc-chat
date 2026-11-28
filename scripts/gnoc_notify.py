"""A desktop notification when a long turn finishes or stops for his approval.

From the Hermes Agent review (2026-11-23): finish and approval-wait notifications were among the most asked-for
harness features, and a local model's answer can take minutes. gnoc only printed to the terminal, so a long answer
or an "? allow bash" prompt sat unseen while he was in another window.

Quiet by design: only in an interactive terminal, only for a turn longer than GNOC_NOTIFY_AFTER seconds (default
60), never for the drive or a one-shot run, and /notify off turns it off for the session. Linux uses notify-send,
WSL a Windows toast through PowerShell, a Mac osascript; with none of them, nothing happens.
"""
import os
import shutil
import subprocess
import sys

OFF = [False]
TURN_START = [None]   # set by the chat loop when his turn starts


def after_seconds():
    try:
        return max(5, int(os.environ.get("GNOC_NOTIFY_AFTER", "60")))
    except ValueError:
        return 60


def _on_wsl():
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _argv(title, body):
    if sys.platform == "darwin" and shutil.which("osascript"):
        esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')   # noqa: E731
        return ["osascript", "-e", f'display notification "{esc(body)}" with title "{esc(title)}"']
    if _on_wsl() and shutil.which("powershell.exe"):
        q = lambda s: s.replace("'", "''")   # noqa: E731
        ps = ("[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType=WindowsRuntime]"
              " > $null; $t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
              "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); $x = $t.GetElementsByTagName('text'); "
              f"$x.Item(0).AppendChild($t.CreateTextNode('{q(title)}')) > $null; "
              f"$x.Item(1).AppendChild($t.CreateTextNode('{q(body)}')) > $null; "
              "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('gnoc').Show("
              "[Windows.UI.Notifications.ToastNotification]::new($t))")
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps]
    if shutil.which("notify-send"):
        return ["notify-send", "-a", "gnoc", "-i", "dialog-information", title, body]
    return None


def notify(title, body, force=False):
    """Show one notification, detached and silent. -> True when one was sent."""
    if OFF[0] or os.environ.get("GNOC_NOTIFY") == "0":
        return False
    if not force and not (sys.stdin.isatty() and sys.stdout.isatty()):
        return False
    argv = _argv(str(title)[:80], str(body)[:200])
    if not argv:
        return False
    try:
        subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                         start_new_session=True, cwd="/mnt/c" if _on_wsl() and os.path.isdir("/mnt/c") else None)
        return True
    except OSError:
        return False


def turn_done(seconds, answer=""):
    """After a turn: notify when it ran long enough that he may have looked away."""
    if seconds < after_seconds():
        return False
    first = " ".join(str(answer or "").split())[:140] or "the answer is ready"
    mins = f"{int(seconds // 60)}m{int(seconds % 60):02d}s" if seconds >= 60 else f"{int(seconds)}s"
    return notify(f"gnoc answered ({mins})", first)


def waiting(name, started_at=None):
    """Before an approval prompt: notify when the turn has already run long (he may not be watching)."""
    import time
    started_at = started_at if started_at is not None else TURN_START[0]
    if started_at is None or time.time() - started_at < min(30, after_seconds()):
        return False
    return notify("gnoc is waiting for your yes", f"allow {name}?")
