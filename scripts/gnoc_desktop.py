"""gnoc_desktop.py - see and drive a desktop (this machine, or a machine linked with `gnoc link`).

    shot(target)            screenshot -> (local png path, (w, h)); saved under .claude/state/orch/desktop/
    read(png)               OCR -> [{"text", "x", "y", "w", "h"}] per text line (tesseract), x/y = centre
    act(target, ops)        mouse/keyboard ops (gnoc_input.py: move/click/drag/scroll/type/key/sleep)
    find_text(lines, text)  the OCR line that holds the text, for click_text

Gating lives in gnoc_agent (the bot must ask the user, the grant ends with the task); this module only does the
work. The model is text-only, so "seeing" the screen means OCR text with coordinates; the PNG is kept on disk for
the user (and for evidence).
"""
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(WS, ".claude/state/orch/desktop")
# beside this file, not under the workspace: a workspace without the launcher's scripts/ link had no input script
_HERE = os.path.dirname(os.path.abspath(__file__))
INPUT = os.path.join(_HERE, "gnoc_input.py")
sys.path.insert(0, _HERE)
import gnoc_link  # noqa: E402

MAX_OPS = 200          # one `do` call: at most this many ops ...
MAX_SLEEP_MS = 30_000  # ... and this much sleeping in total
KEEP_SHOTS = 60        # screenshots kept on disk (they hold whatever was on the screen)
SHOT_CMDS = {  # tool -> command writing a PNG to "$f"
    "spectacle": 'spectacle -b -n -f -o "$f"',
    "grim": 'grim "$f"',
    "gnome-screenshot": 'gnome-screenshot -f "$f"',
    "import": 'import -window root "$f"',
    "scrot": 'scrot -o "$f"',
}
_sizes = {}


def _env_prefix(probe):
    """The desktop session's environment. DISPLAY / XAUTHORITY are the ones the probe read from the session's own
    process (GDM: /run/user/<uid>/gdm/Xauthority, often :1; SDDM: /tmp/xauth_*); spectacle is forced onto Wayland
    only in a Wayland session (it was forced always, and failed on X11)."""
    import shlex
    wl = probe.get("wayland") or ""
    dp = probe.get("display") or ""
    xa = probe.get("xauth") or ""
    env = ('u=$(id -u); export XDG_RUNTIME_DIR=/run/user/$u DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$u/bus '
           f'WAYLAND_DISPLAY={wl or "wayland-0"} '
           + (f"DISPLAY={shlex.quote(dp)} " if dp else "DISPLAY=${DISPLAY:-:0} ")
           + (f"XAUTHORITY={shlex.quote(xa)}" if xa else "XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority}"))
    if probe.get("session") == "wayland":
        env += " QT_QPA_PLATFORM=wayland"
    return env + "; "


def _png_size(data):
    """(width, height) from a PNG's IHDR. Pillow was imported for this alone and the public release does not ship
    it, so every screenshot there failed with ModuleNotFoundError (QAQC 2026-11-19)."""
    import struct
    if len(data) < 24 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RuntimeError("not a PNG image")
    return struct.unpack(">II", data[16:24])


def _keep_recent(d, keep=KEEP_SHOTS):
    try:
        shots = sorted((os.path.join(d, f) for f in os.listdir(d) if f.endswith(".png")), key=os.path.getmtime)
    except OSError:
        return
    for f in shots[:-keep]:
        try:
            os.remove(f)
        except OSError:
            pass


def _probe(target):
    if target == "local":
        out = subprocess.run(["bash", "-s"], input=gnoc_link.PROBE, capture_output=True, text=True).stdout
        return json.loads(out.strip().splitlines()[-1])
    link = gnoc_link.load().get(target)
    if not link:
        raise KeyError(f"no linked machine {target!r} (gnoc link list)")
    return link.get("probe") or {}


def _shot_cmd(probe):
    tools = (probe.get("shot") or "").split()
    order = ["spectacle", "grim", "gnome-screenshot", "import", "scrot"] if probe.get("session") == "wayland" \
        else ["import", "scrot", "spectacle", "gnome-screenshot", "grim"]
    for t in order:
        if t in tools:
            return t, SHOT_CMDS[t]
    return None, None


def _computer_local(target):
    """True when this machine's screen is reached through gnoc_computer (WSL and Windows by PowerShell, macOS,
    or a forced X11 display such as the nested test desktop) instead of the shell tools and uinput."""
    if target != "local":
        return False
    try:
        import gnoc_computer
        p = gnoc_computer.platform()
    except Exception:  # noqa: BLE001
        return False
    return p in ("wsl", "windows", "mac") or p.startswith("x11:")


def shot(target="local"):
    if _computer_local(target):
        import gnoc_computer
        os.makedirs(OUT, mode=0o700, exist_ok=True)
        path = os.path.join(OUT, f"{target}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.png")
        path, w, h = gnoc_computer.capture(path)
        _keep_recent(OUT)
        _sizes[target] = (w, h)
        return path, (w, h)
    probe = _probe(target)
    tool, cmd = _shot_cmd(probe)
    if not tool:
        raise RuntimeError(f"{target}: no screenshot tool (spectacle / grim / gnome-screenshot / imagemagick)")
    script = _env_prefix(probe) + f'f=$(mktemp --suffix=.png); {cmd} >/dev/null 2>&1 && cat "$f"; rm -f "$f"'
    err = b""
    if target == "local":
        r = subprocess.run(["bash", "-c", script], capture_output=True, timeout=40)
        data, code = r.stdout, r.returncode
    else:
        code, data, err = gnoc_link.run(gnoc_link.load()[target], "bash -s", stdin=script.encode(), timeout=60,
                                        binary=True)
    if not data or not data.startswith(b"\x89PNG"):
        if target != "local" and code not in (0, 1):
            e = err.decode("utf-8", "replace") if isinstance(err, bytes) else str(err)
            raise RuntimeError(f"{target}: ssh failed ({e.strip()[:200]}) -> {gnoc_link.ssh_hint(e)}")
        raise RuntimeError(f"{target}: {tool} returned no image (is a desktop session logged in? "
                           + ("gnoc link test " + target + " re-checks the session)" if target != "local" else ")"))
    size = _png_size(data)   # checked before anything is written: a bad image leaves no file behind
    os.makedirs(OUT, mode=0o700, exist_ok=True)
    path = os.path.join(OUT, f"{target}-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.png")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # a screenshot shows whatever was on screen
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    _keep_recent(OUT)
    _sizes[target] = size
    return path, size


def ocr_available():
    return shutil.which("tesseract") is not None


def read(png):
    """OCR lines with centre coordinates. [] when tesseract is missing (see ocr_available)."""
    if not ocr_available():
        return []
    r = subprocess.run(["tesseract", png, "stdout", "--psm", "11", "tsv"], capture_output=True, text=True,
                       timeout=90)
    lines = {}
    for ln in r.stdout.splitlines()[1:]:
        p = ln.split("\t")
        if len(p) < 12 or not p[11].strip() or float(p[10] or -1) < 40:
            continue
        key = (p[2], p[3], p[4])  # block, paragraph, line
        x, y, w, h = (int(v) for v in p[6:10])
        cur = lines.setdefault(key, {"words": [], "x0": x, "y0": y, "x1": x + w, "y1": y + h})
        cur["words"].append((x, y, w, h, p[11]))
        cur["x0"], cur["y0"] = min(cur["x0"], x), min(cur["y0"], y)
        cur["x1"], cur["y1"] = max(cur["x1"], x + w), max(cur["y1"], y + h)
    out = []
    for v in lines.values():
        out.append({"text": " ".join(w[4] for w in v["words"]), "x": (v["x0"] + v["x1"]) // 2,
                    "y": (v["y0"] + v["y1"]) // 2, "w": v["x1"] - v["x0"], "h": v["y1"] - v["y0"],
                    "words": v["words"]})
    return sorted(out, key=lambda l: (l["y"] // 12, l["x"]))


def find_text(lines, text, occurrence=1):
    """Centre of the occurrence-th match of text (case-insensitive) - the matching WORDS' box, not the whole line."""
    t = text.lower().split()
    hits = []
    for ln in lines:
        words = ln["words"]
        low = [w[4].lower() for w in words]
        for i in range(len(low) - len(t) + 1):
            if all(t[j] in low[i + j] for j in range(len(t))):
                seg = words[i:i + len(t)]
                x0, y0 = min(w[0] for w in seg), min(w[1] for w in seg)
                x1, y1 = max(w[0] + w[2] for w in seg), max(w[1] + w[3] for w in seg)
                hits.append(((x0 + x1) // 2, (y0 + y1) // 2, ln["text"]))
    return hits[occurrence - 1] if 0 < occurrence <= len(hits) else None


def check_ops(ops):
    """'' or why these ops are refused: too many, or too much sleeping, for one call."""
    if len(ops) > MAX_OPS:
        return f"at most {MAX_OPS} ops per call"
    slept = sum(int(o.get("ms", 0) or 0) for o in ops if isinstance(o, dict) and o.get("op") == "sleep")
    if slept > MAX_SLEEP_MS:
        return f"at most {MAX_SLEEP_MS // 1000} s of sleep per call"
    return ""


def act(target, ops, size=None):
    why = check_ops(ops)
    if why:
        return {"ok": False, "error": why}
    size = size or _sizes.get(target)
    if not size:
        _, size = shot(target)
    if _computer_local(target):
        return _computer_ops(ops)
    arg = json.dumps(ops)
    wh = f"{int(size[0])}x{int(size[1])}"
    # the ops (which can hold typed text) travel on stdin, never the command line, where every user of either
    # machine could read them in the process list
    if target == "local":
        r = subprocess.run([sys.executable, INPUT, "-", wh], input=arg, capture_output=True, text=True, timeout=120)
        out = r.stdout.strip() or r.stderr.strip()
    else:
        with open(INPUT) as fh:
            script = fh.read()
        boot = f"import sys\nsys.argv = ['gnoc_input', '-', {wh!r}]\nsys.stdin_ops = {arg!r}\n"
        # `timeout` there too: killing the local ssh did not stop the typing on the other machine
        code, out, err = gnoc_link.run(gnoc_link.load()[target], "timeout 110 python3 -",
                                       stdin=boot + script, timeout=120)
        out = (out or err).strip()
    try:
        return json.loads(out.splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "error": out[:300] or "no output"}


def _computer_ops(ops):
    import time as _t
    import gnoc_computer as C
    done = 0
    try:
        for o in ops:
            k = o.get("op")
            if k == "click":
                C.click(o["x"], o["y"], o.get("button", "left"), bool(o.get("double")))
            elif k == "move":
                C.move(o["x"], o["y"])
            elif k == "type":
                C.type_text(o.get("text", ""))
            elif k == "key":
                C.key(o.get("combo", ""))
            elif k == "scroll":
                dy = int(o.get("dy", -3))
                C.scroll("up" if dy > 0 else "down", abs(dy) or 3)
            elif k == "sleep":
                _t.sleep(min(30, int(o.get("ms", 300)) / 1000))
            elif k == "drag":
                return {"ok": False, "done": done, "error": "drag is not supported on this desktop yet"}
            done += 1
    except (KeyError, RuntimeError, OSError, ValueError) as e:
        return {"ok": False, "done": done, "error": f"{type(e).__name__}: {e}"}
    return {"ok": True, "done": done}


def _q(s):
    import shlex
    return shlex.quote(s)


def windows(target="local"):
    """Window list where the desktop can tell us (KDE via KWin scripting on this machine)."""
    if target != "local":
        return []
    try:
        import gnoc_kwin
        return gnoc_kwin.windows()
    except Exception:
        return []


def summary(target, png, size, lines, wins, limit=120):
    out = [f"{target} screen {size[0]}x{size[1]}  image {os.path.relpath(png, WS)}"]
    if wins:
        out.append("windows: " + " | ".join(f"{'*' if w['active'] else ''}{w['caption'][:50]} @({w['x']},{w['y']} "
                                            f"{w['w']}x{w['h']})" for w in wins[:12]))
    if not ocr_available():
        out.append("screen text: OCR not installed (sudo apt install tesseract-ocr); only the window list is known")
    elif not lines:
        out.append("screen text: none recognised")
    else:
        out.append("screen text (x,y = centre; click there):")
        out += [f"  ({l['x']},{l['y']}) {l['text'][:100]}" for l in lines[:limit]]
        if len(lines) > limit:
            out.append(f"  ... {len(lines) - limit} more lines")
    return "\n".join(out)
