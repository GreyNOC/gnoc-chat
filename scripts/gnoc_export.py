"""Files gnoc made in this chat: list them, export (copy) them to Downloads, open one in its app.

The user, 2026-11-23, after a chat wrote "The Girl Next Door Shop.html" to their Desktop: "can we give it the capability
to download the file from chat? i want to export attachments straight from chat". A terminal has no download
button, so the chat gets three commands:

    /files                 what this chat made (numbered, newest first)
    /download [n|all|name] [folder] copy them to Downloads (Windows' Downloads under WSL), never overwriting
    /open [n]              open one in its default app (the browser for .html, the image viewer for .png)

The list comes from what the chat itself recorded: every write_file/edit_file (the /undo checkpoints) and every
picture generate_image saved. Shell-made files are not tracked.
"""
import contextlib
import os
import shutil
import subprocess
import sys


def on_wsl():
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    with contextlib.suppress(OSError):
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    return False


def made_files(ctx):
    """Files this conversation wrote or drew that still exist, newest first."""
    seen, out = set(), []
    rows = []
    with contextlib.suppress(Exception):
        from gnoc_core.session import _checkpoints
        rows = [r.get("path") for r in _checkpoints(ctx) if r.get("path")]
    rows += list((getattr(ctx, "s", None) or {}).get("_images_made") or [])
    for p in reversed(rows):
        rp = os.path.realpath(os.path.expanduser(str(p)))
        if rp in seen or not os.path.isfile(rp):
            continue
        seen.add(rp)
        out.append(rp)
    return out


def _windows_home():
    """The Windows user folder seen from WSL (/mnt/c/Users/<name>), or ''."""
    with contextlib.suppress(Exception):
        r = subprocess.run(["cmd.exe", "/c", "echo %USERPROFILE%"], capture_output=True, text=True, timeout=8,
                           cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
        win = (r.stdout or "").strip().splitlines()[-1].strip()
        if win and "%" not in win:
            u = subprocess.run(["wslpath", "-u", win], capture_output=True, text=True, timeout=5).stdout.strip()
            if u and os.path.isdir(u):
                return u
    return ""


def downloads_dir():
    """Where an export goes: Windows' Downloads under WSL, else the desktop's Downloads (xdg), else ~/Downloads."""
    if on_wsl():
        wh = _windows_home()
        if wh and os.path.isdir(os.path.join(wh, "Downloads")):
            return os.path.join(wh, "Downloads")
    with contextlib.suppress(Exception):
        d = subprocess.run(["xdg-user-dir", "DOWNLOAD"], capture_output=True, text=True, timeout=5).stdout.strip()
        if d and os.path.isdir(d) and os.path.realpath(d) != os.path.realpath(os.path.expanduser("~")):
            return d
    return os.path.expanduser("~/Downloads")


def _free_name(folder, name):
    base, ext = os.path.splitext(name)
    cand, n = os.path.join(folder, name), 1
    while os.path.exists(cand):
        cand = os.path.join(folder, f"{base} ({n}){ext}")
        n += 1
    return cand


def pick(files, which):
    """The files /export or /open means: '' or 'last' = newest, a number from /files, 'all', or part of a name."""
    w = str(which or "").strip().lower()
    if not files:
        return []
    if w in ("", "last", "it", "latest", "newest"):
        return files[:1]
    if w == "all":
        return list(files)
    if w.isdigit():
        i = int(w)
        return [files[i - 1]] if 1 <= i <= len(files) else []
    return [p for p in files if w in os.path.basename(p).lower()]


def export(paths, folder=None):
    """Copy each file into folder (Downloads by default), never over an existing file. -> [(src, dest)]"""
    folder = os.path.expanduser(folder) if folder else downloads_dir()
    os.makedirs(folder, exist_ok=True)
    done = []
    for p in paths:
        dest = _free_name(folder, os.path.basename(p))
        shutil.copy2(p, dest)
        done.append((p, dest))
    return done


def open_file(path):
    """Open a file in its default app, detached. -> how, or raises."""
    if on_wsl():
        if shutil.which("wslview"):
            argv = ["wslview", path]
        else:
            win = subprocess.run(["wslpath", "-w", path], capture_output=True, text=True, timeout=5).stdout.strip()
            argv = ["cmd.exe", "/c", "start", "", win]
    elif sys.platform == "darwin":
        argv = ["open", path]
    elif shutil.which("xdg-open"):
        argv = ["xdg-open", path]
    else:
        raise RuntimeError("no program here opens files (install xdg-utils)")
    subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                     start_new_session=True, cwd="/mnt/c" if on_wsl() and os.path.isdir("/mnt/c") else None)
    return os.path.basename(argv[0])


def _gui():
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def save_dialog(default_path):
    """Ask where to save with the system's own Save As window; the chosen path, '' when the user cancelled, or None when
    no window can be shown here (no desktop session, no dialog program)."""
    name = os.path.basename(default_path)
    start = os.path.join(downloads_dir(), name)
    try:
        if on_wsl() and shutil.which("powershell.exe"):
            win_dir = subprocess.run(["wslpath", "-w", os.path.dirname(start)], capture_output=True, text=True,
                                     timeout=5).stdout.strip()
            q = lambda s: s.replace("'", "''")   # noqa: E731
            ps = ("Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.SaveFileDialog; "
                  f"$d.FileName = '{q(name)}'; $d.InitialDirectory = '{q(win_dir)}'; $d.OverwritePrompt = $true; "
                  "$d.Filter = 'All files (*.*)|*.*'; if ($d.ShowDialog() -eq 'OK') { $d.FileName }")
            r = subprocess.run(["powershell.exe", "-NoProfile", "-STA", "-Command", ps], capture_output=True,
                               text=True, timeout=600, cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
            win = (r.stdout or "").strip().splitlines()[-1].strip() if (r.stdout or "").strip() else ""
            if not win:
                return ""
            return subprocess.run(["wslpath", "-u", win], capture_output=True, text=True, timeout=5).stdout.strip()
        if sys.platform == "darwin" and shutil.which("osascript"):
            r = subprocess.run(["osascript", "-e", f'POSIX path of (choose file name with prompt "Save {name} as" '
                                f'default name "{name}" default location (path to downloads folder))'],
                               capture_output=True, text=True, timeout=600)
            return (r.stdout or "").strip()
        if _gui() and shutil.which("kdialog"):
            r = subprocess.run(["kdialog", "--getsavefilename", start], capture_output=True, text=True, timeout=600)
            return (r.stdout or "").strip()
        if _gui() and shutil.which("zenity"):
            r = subprocess.run(["zenity", "--file-selection", "--save", "--confirm-overwrite", f"--filename={start}"],
                               capture_output=True, text=True, timeout=600)
            return (r.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        return None
    return None


def save_as(src, dest):
    """Copy src to the path the user chose (a folder keeps the file's name). -> the written path."""
    dest = os.path.expanduser(dest)
    if os.path.isdir(dest) or dest.endswith(("/", os.sep)):   # a folder, even one to be made, keeps the name
        dest = os.path.join(dest, os.path.basename(src))
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def listing(files):
    if not files:
        return "this chat has not made any file yet (files written with write_file/edit_file and pictures count)"
    lines = ["files this chat made (newest first):  /save [n] (choose where) · /download [n|all] [folder] · /open [n]"]
    for i, p in enumerate(files, 1):
        with contextlib.suppress(OSError):
            kb = os.path.getsize(p) / 1024
            lines.append(f"  {i}. {p}  ({kb:.0f} KB)" if kb >= 1 else f"  {i}. {p}  ({os.path.getsize(p)} bytes)")
    return "\n".join(lines)
