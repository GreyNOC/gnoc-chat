"""Computer use: gnoc sees the screen and works the mouse and keyboard, on the user's own machine.

The user, 2026-11-23: "can we develop and engineer computer use for the harness?"

    capture(path)                 -> (path, width, height)   a screenshot of the whole screen
    locate(shot, target)          -> (x, y, box) or None     a local vision model points at "the OK button"
    click(x, y, button, double)   type_text(text)   key(combo)   scroll(direction, amount)
    look(shot)                    -> what is on screen, in words (visible text transcribed)

Backends, picked for this computer (GNOC_COMPUTER_X11=:N forces X11 on display :N, used by the nested test desktop):
    screen: KDE Wayland spectacle · wlroots grim · X11 import · WSL/Windows PowerShell · macOS screencapture
    input:  X11 xdotool (the nested test desktop) · Wayland/X11 desktops gnoc_input's uinput · WSL/Windows PowerShell

Seeing uses a local vision model through gnoc's own engine or Ollama (GNOC_VISION_MODEL picks one; Qwen2.5-VL points
at things best: it answers a bounding box in the image's own pixels). Nothing leaves the computer.

The safety rules live with the tool (gnoc_tools.computer): every action needs their yes unless the user turned a session on
with /computer on, a password or payment screen stops it, and every step is logged with its screenshot.
"""
import base64
import contextlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

PATCH = 28            # Qwen2.5-VL's vision patch: an image whose sides are multiples of it is read without rescaling
MAX_W = 1288          # 46 patches: large enough to read a 1080p screen's text, small enough for an 8 GB card


# ---------------------------------------------------------------- where we are

def _wsl():
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    with contextlib.suppress(OSError):
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    return False


def platform():
    """'x11:<display>' (forced) | 'kde-wayland' | 'wayland' | 'x11' | 'wsl' | 'windows' | 'mac' | 'none'."""
    forced = os.environ.get("GNOC_COMPUTER_X11")
    if forced:
        return "x11:" + forced
    if sys.platform == "darwin":
        return "mac"
    if os.name == "nt":
        return "windows"
    if _wsl() and shutil.which("powershell.exe"):
        return "wsl"
    if os.environ.get("WAYLAND_DISPLAY"):
        kde = "KDE" in os.environ.get("XDG_CURRENT_DESKTOP", "") or shutil.which("spectacle")
        return "kde-wayland" if kde else "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "none"


def _x11_display():
    p = platform()
    return p.split(":", 1)[1] if p.startswith("x11:") else os.environ.get("DISPLAY", ":0")


def _run(argv, timeout=30, env=None, **kw):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, **(env or {})), **kw)


def _ps(script, timeout=60):
    """Run PowerShell on the Windows side (WSL or Windows) and return its stdout."""
    exe = shutil.which("powershell.exe") or shutil.which("powershell")
    if not exe:
        raise RuntimeError("PowerShell is not reachable from here")
    r = _run([exe, "-NoProfile", "-NonInteractive", "-STA", "-Command", script], timeout=timeout,
             cwd="/mnt/c" if os.path.isdir("/mnt/c") else None)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout or "PowerShell failed").strip()[:300])
    return r.stdout


def _png_size(path):
    with open(path, "rb") as f:
        head = f.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    return struct.unpack(">II", head[16:24])


# ---------------------------------------------------------------- seeing the screen

def capture(path=None):
    """A screenshot of the whole screen as PNG. -> (path, width, height)"""
    path = path or tempfile.mktemp(prefix="gnoc-screen-", suffix=".png")
    p = platform()
    if p.startswith("x11:") or p == "x11":
        r = _run(["import", "-window", "root", "-display", _x11_display(), path])
        if r.returncode != 0 and shutil.which("xwd"):
            r = _run(["sh", "-c", f"xwd -root -silent -display {_x11_display()} | convert xwd:- {path}"])
    elif p == "kde-wayland":
        r = _run(["spectacle", "-b", "-n", "-f", "-o", path], timeout=30)
    elif p == "wayland":
        r = _run(["grim", path]) if shutil.which("grim") else None
        if r is None:
            raise RuntimeError("no screenshot program for this Wayland desktop (install grim)")
    elif p in ("wsl", "windows"):
        win = path if p == "windows" else _run(["wslpath", "-w", path]).stdout.strip()
        _ps("Add-Type -AssemblyName System.Windows.Forms,System.Drawing; "
            "$b = [System.Windows.Forms.SystemInformation]::VirtualScreen; "
            "$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height; "
            "$g = [System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size); "
            f"$bmp.Save('{win}', [System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()")
        r = None
    elif p == "mac":
        r = _run(["screencapture", "-x", path])
    else:
        raise RuntimeError("no screen here (no desktop session): computer use needs a desktop")
    if r is not None and r.returncode != 0:
        raise RuntimeError(f"screenshot failed: {(r.stderr or r.stdout).strip()[:200]}")
    if not os.path.isfile(path):
        raise RuntimeError("screenshot failed: no file was written")
    w, h = _png_size(path)
    _OFFSET[:] = [0, 0]
    if p.startswith("x11") or p == "x11":
        _OFFSET[:] = _x11_root_offset(w, h)
    return path, w, h


_OFFSET = [0, 0]   # where the screenshot's top-left sits on the screen (a rootless XWayland root is cropped)


def _x11_root_offset(w, h):
    """A rootless XWayland 'root' screenshot is only the windows' area, not the screen: clicks then need the
    windows' top-left added (nested test desktop, 2026-11-23). A normal X11 root is the whole screen: (0, 0)."""
    exe = shutil.which("xdotool")
    if not exe:
        return [0, 0]
    env = {"DISPLAY": _x11_display()}
    g = _run([exe, "getdisplaygeometry"], env=env).stdout.split()
    if len(g) == 2 and (int(g[0]), int(g[1])) == (w, h):
        return [0, 0]
    xs, ys = [], []
    for wid in _run([exe, "search", "--onlyvisible", "--name", "."], env=env).stdout.split():
        m = re.search(r"Position:\s*(-?\d+),(-?\d+)", _run([exe, "getwindowgeometry", wid], env=env).stdout)
        if m:
            xs.append(int(m.group(1)))
            ys.append(int(m.group(2)))
    return [min(xs), min(ys)] if xs else [0, 0]


def _model_input(path):
    """The screenshot as the vision model should get it: sides a multiple of 28, at most MAX_W wide.
    -> (base64 PNG, width, height) of what the model sees."""
    w, h = _png_size(path)
    # always the same width, small screens scaled UP as well: a 522x375 shot sent as 504x364 came back with every
    # box about 30 px low; the full-size test was exact (the model re-scales small images internally)
    scale = MAX_W / w
    tw = max(PATCH, int(w * scale) // PATCH * PATCH)
    th = max(PATCH, int(h * scale) // PATCH * PATCH)
    out = tempfile.mktemp(suffix=".png")
    conv = shutil.which("magick") or shutil.which("convert")
    data = None
    if conv:
        r = _run([conv, path, "-resize", f"{tw}x{th}!", out])
        if r.returncode == 0 and os.path.isfile(out):
            with open(out, "rb") as f:
                data = f.read()
            os.remove(out)
    if data is None:
        with contextlib.suppress(Exception):
            from PIL import Image
            import io
            with Image.open(path) as im:
                buf = io.BytesIO()
                im.convert("RGB").resize((tw, th)).save(buf, "PNG")
                data = buf.getvalue()
    if data is None:   # no resizer at all: send it as it is and scale by its own size
        with open(path, "rb") as f:
            data = f.read()
        tw, th = w, h
    return base64.b64encode(data).decode(), tw, th


def vision_model():
    """(model, 'host:port') for seeing, or None. GNOC_VISION_MODEL wins; else a Qwen-VL, else any vision model."""
    try:
        import llm_endpoints as ep
    except Exception:  # noqa: BLE001
        return None
    pin = os.environ.get("GNOC_VISION_MODEL", "")
    for host in ("local", "desktop"):
        addr = ep.HOSTS.get(host)
        if not addr:
            continue
        try:
            with urllib.request.urlopen(f"http://{addr}/api/tags", timeout=4) as r:
                names = [m.get("name", "") for m in json.loads(r.read()).get("models") or []]
        except Exception:  # noqa: BLE001
            continue
        if pin and pin.split("@")[0] in names:
            return pin.split("@")[0], addr
        for pref in (r"qwen2\.5-?vl|qwen3-?vl|qwen-?vl", r"vl\b|vision|llava|minicpm-?v|gemma3|moondream"):
            hit = [n for n in names if re.search(pref, n, re.I)]
            if hit:
                return hit[0], addr
    return None


def _ask_vision(prompt, b64, timeout=240):
    got = vision_model()
    if not got:
        raise RuntimeError("no vision model is installed: pull one, e.g. gnoc engine pull qwen2.5vl:7b")
    model, addr = got
    body = {"model": model, "stream": False, "options": {"temperature": 0, "num_predict": 400},
            "messages": [{"role": "user", "content": prompt, "images": [b64]}]}
    req = urllib.request.Request(f"http://{addr}/api/chat", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return model, json.loads(r.read()).get("message", {}).get("content", "")


def locate(shot, target):
    """Where on the screen is `target` ("the OK button", "the Name field")? -> (x, y, (x1, y1, x2, y2)) in SCREEN
    pixels, or None when the model does not find it."""
    w, h = _png_size(shot)
    b64, tw, th = _model_input(shot)
    _m, text = _ask_vision(f"Locate {target} in this screenshot and output its bbox coordinates in JSON format: "
                           '{"bbox_2d": [x1, y1, x2, y2], "label": "..."}. If it is not on the screen, output '
                           '{"bbox_2d": null}.', b64)
    m = re.search(r'"bbox_2d"\s*:\s*\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*'
                  r'(-?\d+(?:\.\d+)?)\s*\]', text)
    if not m:
        return None
    x1, y1, x2, y2 = (float(v) for v in m.groups())
    sx, sy = w / tw, h / th
    box = (int(x1 * sx), int(y1 * sy), int(x2 * sx), int(y2 * sy))
    if box[2] <= box[0] or box[3] <= box[1] or box[0] < 0 or box[1] < 0 or box[2] > w + 2 or box[3] > h + 2:
        return None
    return (box[0] + box[2]) // 2, (box[1] + box[3]) // 2, box


def look(shot, question=""):
    """What is on the screen, in words: every visible piece of text, the windows, and what has focus."""
    b64, _tw, _th = _model_input(shot)
    model, text = _ask_vision(
        (question.strip() + "\n\n" if question.strip() else "") +
        "Describe this screenshot for someone who cannot see it: which windows and dialogs are open, every piece "
        "of visible text exactly (titles, labels, buttons, fields and what they contain, messages), and which "
        "field or window has focus. Under 200 words. End with one line exactly 'SENSITIVE: yes' if the screen "
        "shows a password or PIN field, a login form, a payment or card form, or an admin/sudo/UAC prompt, else "
        "'SENSITIVE: no'.", b64)
    return model, text.strip()


def sensitive(described):
    """True when look()'s answer says the screen shows a password/login/payment/admin prompt. The model's own
    flag line decides: a regex over the description fired on "there is no password field" (2026-11-23)."""
    m = re.search(r"(?im)^\W*SENSITIVE\s*:\s*(yes|no)\b", str(described or ""))
    if m:
        return m.group(1).lower() == "yes"
    return bool(re.search(r"(?i)\b(?:enter|type)\s+(?:your\s+)?(?:password|pin|passphrase)|\b(?:card\s+number|cvv|"
                          r"authentication\s+required|user\s+account\s+control)\b", str(described or "")))


SENSITIVE = re.compile(r"(?i)\b(?:password|passphrase|pass\s*code|pin\s*code|2fa|one[- ]time\s+code|credit\s+card|"
                       r"card\s+number|cvv|cvc|payment|checkout|bank\s+login|sign\s*in\s+to\s+your\s+bank|sudo|"
                       r"authentication\s+required|administrator|user\s+account\s+control|keychain|polkit)\b")


# ---------------------------------------------------------------- acting

_KEYS = {"enter": "Return", "return": "Return", "esc": "Escape", "escape": "Escape", "tab": "Tab",
         "backspace": "BackSpace", "delete": "Delete", "del": "Delete", "space": "space", "up": "Up", "down": "Down",
         "left": "Left", "right": "Right", "home": "Home", "end": "End", "pageup": "Prior", "pagedown": "Next",
         "ctrl": "ctrl", "control": "ctrl", "alt": "alt", "shift": "shift", "super": "super", "win": "super",
         "meta": "super", "cmd": "super"}


def _xdo(*args):
    exe = shutil.which("xdotool")
    if not exe:
        raise RuntimeError("xdotool is not installed (it drives X11 windows)")
    r = _run([exe] + [str(a) for a in args], env={"DISPLAY": _x11_display()})
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "xdotool failed").strip()[:200])


def _x11_combo(combo):
    parts = [p.strip() for p in str(combo).replace(" ", "").split("+") if p.strip()]
    return "+".join(_KEYS.get(p.lower(), p if len(p) > 1 else p.lower()) for p in parts)


def _win_click_ps(x, y, button="left", double=False):
    down, up = {"left": (0x0002, 0x0004), "right": (0x0008, 0x0010), "middle": (0x0020, 0x0040)}[button]
    clicks = 2 if double else 1
    return ("Add-Type @'\nusing System; using System.Runtime.InteropServices;\npublic class GnocIn {\n"
            "[DllImport(\"user32.dll\")] public static extern bool SetCursorPos(int x, int y);\n"
            "[DllImport(\"user32.dll\")] public static extern void mouse_event(uint f, uint x, uint y, uint d, IntPtr e);\n}\n'@; "
            f"[GnocIn]::SetCursorPos({int(x)}, {int(y)}) | Out-Null; Start-Sleep -Milliseconds 60; "
            + "".join(f"[GnocIn]::mouse_event({down}, 0, 0, 0, [IntPtr]::Zero); [GnocIn]::mouse_event({up}, 0, 0, 0, "
                      "[IntPtr]::Zero); Start-Sleep -Milliseconds 90; " for _ in range(clicks)))


def _sendkeys_escape(text):
    return "".join("{" + c + "}" if c in "+^%~(){}[]" else c for c in text).replace("'", "''").replace("\n", "{ENTER}")


def move(x, y):
    p = platform()
    if p.startswith("x11") or p == "x11":
        _xdo("mousemove", "--sync", int(x) + _OFFSET[0], int(y) + _OFFSET[1])
    elif p in ("wsl", "windows"):
        _ps("Add-Type @'\nusing System; using System.Runtime.InteropServices;\npublic class GnocMv {\n"
            "[DllImport(\"user32.dll\")] public static extern bool SetCursorPos(int x, int y);\n}\n'@; "
            f"[GnocMv]::SetCursorPos({int(x)}, {int(y)}) | Out-Null")
    elif p in ("kde-wayland", "wayland"):
        _desktop_ops([{"op": "move", "x": int(x), "y": int(y)}])
    else:
        raise RuntimeError(f"no pointer on this desktop ({p})")


def click(x, y, button="left", double=False):
    p = platform()
    if p.startswith("x11") or p == "x11":
        _xdo("mousemove", "--sync", int(x) + _OFFSET[0], int(y) + _OFFSET[1])
        _xdo("click", "--repeat", 2 if double else 1, {"left": 1, "middle": 2, "right": 3}[button])
    elif p in ("wsl", "windows"):
        _ps(_win_click_ps(x, y, button, double))
    elif p in ("kde-wayland", "wayland"):
        _desktop_ops([{"op": "click", "x": int(x), "y": int(y), "button": button, "double": bool(double)}])
    else:
        raise RuntimeError(f"no way to click on this desktop ({p})")


def type_text(text):
    text = str(text)
    p = platform()
    if p.startswith("x11") or p == "x11":
        _xdo("type", "--delay", 25, "--", text)
    elif p in ("wsl", "windows"):
        _ps("Add-Type -AssemblyName System.Windows.Forms; "
            f"[System.Windows.Forms.SendKeys]::SendWait('{_sendkeys_escape(text)}')")
    elif p in ("kde-wayland", "wayland"):
        _desktop_ops([{"op": "type", "text": text}])
    else:
        raise RuntimeError(f"no way to type on this desktop ({p})")


def key(combo):
    p = platform()
    if p.startswith("x11") or p == "x11":
        _xdo("key", _x11_combo(combo))
    elif p in ("wsl", "windows"):
        mods = {"ctrl": "^", "control": "^", "alt": "%", "shift": "+"}
        names = {"enter": "{ENTER}", "return": "{ENTER}", "esc": "{ESC}", "escape": "{ESC}", "tab": "{TAB}",
                 "backspace": "{BACKSPACE}", "delete": "{DELETE}", "up": "{UP}", "down": "{DOWN}", "left": "{LEFT}",
                 "right": "{RIGHT}", "home": "{HOME}", "end": "{END}", "pageup": "{PGUP}", "pagedown": "{PGDN}",
                 "space": " "}
        parts = [q for q in str(combo).lower().replace(" ", "").split("+") if q]
        seq = "".join(mods.get(q, "") for q in parts[:-1]) + names.get(parts[-1], parts[-1])
        _ps(f"Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{seq}')")
    elif p in ("kde-wayland", "wayland"):
        _desktop_ops([{"op": "key", "combo": str(combo)}])
    else:
        raise RuntimeError(f"no keyboard on this desktop ({p})")


def scroll(direction="down", amount=3):
    p = platform()
    n = max(1, min(20, int(amount)))
    if p.startswith("x11") or p == "x11":
        _xdo("click", "--repeat", n, {"up": 4, "down": 5, "left": 6, "right": 7}[direction])
    elif p in ("wsl", "windows"):
        delta = 120 * n * (1 if direction == "up" else -1)
        _ps("Add-Type @'\nusing System; using System.Runtime.InteropServices;\npublic class GnocWh {\n"
            "[DllImport(\"user32.dll\")] public static extern void mouse_event(uint f, uint x, uint y, int d, IntPtr e);\n}\n'@; "
            f"[GnocWh]::mouse_event(0x0800, 0, 0, {delta}, [IntPtr]::Zero)")
    elif p in ("kde-wayland", "wayland"):
        _desktop_ops([{"op": "scroll", "dy": n if direction == "up" else -n}])
    else:
        raise RuntimeError(f"no way to scroll on this desktop ({p})")


# ---------------------------------------------------------------- Wayland / X11 desktops: gnoc_input's uinput

def _desktop_ops(ops):
    """Linux desktops (Wayland or X11) use gnoc_desktop's uinput helper, the one linked machines use too."""
    import gnoc_desktop
    res = gnoc_desktop.act("local", ops)
    if not res.get("ok", True):
        raise RuntimeError(res.get("error") or "input failed")
    return res


# ---------------------------------------------------------------- one step, logged

def log_dir(sid):
    base = os.path.join(os.environ.get("GNOC_WORKSPACE") or os.path.expanduser("~/.gnoc"), ".claude", "state",
                        "orch", "computer", str(sid or "nosid"))
    os.makedirs(base, exist_ok=True)
    return base


def log_step(sid, action, detail, shot=None):
    d = log_dir(sid)
    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "action": action, "detail": detail, "shot": shot}
    with open(os.path.join(d, "steps.jsonl"), "a") as f:
        f.write(json.dumps(row) + "\n")
    return d
