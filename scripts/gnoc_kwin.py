"""gnoc_kwin.py - ask KDE's KWin (Plasma 6, Wayland) about the desktop: cursor position, window list, activate a
window by caption. Uses KWin's own scripting D-Bus API; the script's print() output is read back from the
user journal by a unique marker. Local machine only (a linked machine runs the same via ssh if it is KDE).
"""
import json
import os
import subprocess
import tempfile
import time
import uuid

ENV = dict(os.environ, XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}",
           DBUS_SESSION_BUS_ADDRESS=f"unix:path=/run/user/{os.getuid()}/bus")


def _gdbus(*args):
    r = subprocess.run(["gdbus", "call", "--session", "--dest", "org.kde.KWin"] + list(args),
                       capture_output=True, text=True, timeout=15, env=ENV)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[:300])
    return r.stdout.strip()


def run_script(body, wait=0.6):
    """Run a KWin JS snippet; every print() line it makes is returned (in order)."""
    mark = "GNOCKW" + uuid.uuid4().hex[:10]
    js = body.replace("OUT(", f"print('{mark} ' + ")
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(js)
        path = f.name
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1))
    try:
        sid = _gdbus("--object-path", "/Scripting", "--method", "org.kde.kwin.Scripting.loadScript", path, mark)
        num = sid.strip("()").split(",")[0].strip()
        _gdbus("--object-path", f"/Scripting/Script{num}", "--method", "org.kde.kwin.Script.run")
        time.sleep(wait)
        _gdbus("--object-path", "/Scripting", "--method", "org.kde.kwin.Scripting.unloadScript", mark)
    finally:
        os.unlink(path)
    log = subprocess.run(["journalctl", "--user", "--since", since, "-o", "cat", "--no-pager"],
                         capture_output=True, text=True, timeout=15, env=ENV).stdout
    return [ln.split(mark + " ", 1)[1] for ln in log.splitlines() if mark + " " in ln]


def cursor():
    out = run_script("OUT(JSON.stringify({x: workspace.cursorPos.x, y: workspace.cursorPos.y}));")
    return json.loads(out[0]) if out else None


def windows():
    out = run_script("""
var ws = workspace.windowList();
for (var i = 0; i < ws.length; i++) { var w = ws[i];
  if (!w.normalWindow) continue;
  OUT(JSON.stringify({caption: w.caption, cls: w.resourceClass, active: w === workspace.activeWindow,
       x: w.frameGeometry.x, y: w.frameGeometry.y, w: w.frameGeometry.width, h: w.frameGeometry.height,
       minimized: w.minimized})); }""")
    return [json.loads(x) for x in out]


def activate(caption_part):
    """Bring the first normal window whose caption contains caption_part to the front. Returns its geometry."""
    needle = json.dumps(caption_part.lower())
    out = run_script(f"""
var ws = workspace.windowList(); var hit = null;
for (var i = 0; i < ws.length; i++) {{ var w = ws[i];
  if (w.normalWindow && w.caption.toLowerCase().indexOf({needle}) >= 0) {{ hit = w; break; }} }}
if (hit) {{ hit.minimized = false; workspace.activeWindow = hit;
  OUT(JSON.stringify({{caption: hit.caption, x: hit.frameGeometry.x, y: hit.frameGeometry.y,
                       w: hit.frameGeometry.width, h: hit.frameGeometry.height}})); }}
else {{ OUT("null"); }}""")
    return json.loads(out[0]) if out else None
