"""gnoc_panels.py - raw Burp REQUEST and RESPONSE panels for a decisive leg, taken from Proxy > HTTP history.

House rule (SPINE 5): every decisive leg of a filing carries real Burp panel screenshots; for any path-shape,
encoding or header-grammar claim they must come from Proxy history (Repeater normalises the path), with the
request sent by `curl --path-as-is --proxy <the MCP-bound Burp listener>`.

    resend(raw_path)            replay a gnoc raw capture byte-exact through Burp's proxy -> it is the newest
                                row of Proxy history
    capture(raw_path, dest)     drive Burp (this machine, KDE/Wayland): focus it, Proxy tab, HTTP history, select
                                the newest row, screenshot, crop the Request and Response panels; OCR checks the
                                crops show this request's line before anything is saved as a panel
The desktop grant is the agent's job (gnoc_agent asks the user first); this module assumes it was given.
Nothing here edits a byte: crops come from the screenshot as-is.
"""
import contextlib
import json
import os
import subprocess
import sys
import time
import urllib.parse

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))


def burp_proxy():
    from bbtools import burp_resolve
    return burp_resolve.mcp_proxy_url()


def load_raw(raw_path):
    with open(raw_path) as f:
        d = json.load(f)
    return d["request"]


def curl_argv(req, proxy):
    argv = ["curl", "-sS", "-k", "-i", "--path-as-is", "--proxy", proxy, "-X", req["method"], "--max-time", "40"]
    for k, v in (req.get("headers") or {}).items():
        argv += ["-H", f"{k}: {v}"]
    body = req.get("body")
    if body not in (None, ""):
        argv += ["--data-binary", body if isinstance(body, str) else json.dumps(body)]
    return argv + [req["url"]]


def resend(raw_path):
    """(ok, status line or error). The caller has already scope-gated the URL."""
    proxy = burp_proxy()
    if not proxy:
        return False, "no Burp proxy listener owned by the MCP-bound Burp (is Burp running?)"
    req = load_raw(raw_path)
    r = subprocess.run(curl_argv(req, proxy), capture_output=True, timeout=60)
    first = (r.stdout.split(b"\r\n", 1)[0] or r.stderr[:200]).decode("latin-1")
    return r.returncode == 0, first


def request_line(req):
    u = urllib.parse.urlsplit(req["url"])
    return f"{req['method']} {u.path or '/'}" + (f"?{u.query}" if u.query else "")


def panel_boxes(lines, win):
    """Request / response panel rectangles from OCR lines of the Burp window. Burp labels its two message editors
    'Request' and 'Response'; side by side (default) or stacked. Returns {'request': box, 'response': box} or {}."""
    x0, y0, w, h = win["x"], win["y"], win["w"], win["h"]
    req = [l for l in lines if l["text"].strip().lower() == "request" and l["y"] > y0 + h * 0.25]
    resp = [l for l in lines if l["text"].strip().lower() == "response" and l["y"] > y0 + h * 0.25]
    if not req or not resp:
        return {}
    a, b = req[-1], resp[-1]
    if abs(a["y"] - b["y"]) < 20:  # side by side: split at the response label's left edge
        top = min(a["y"], b["y"]) - a["h"]
        split = b["x"] - b["w"] // 2 - 12
        return {"request": (x0, top, split, y0 + h), "response": (split, top, x0 + w, y0 + h)}
    top_a = a["y"] - a["h"]
    top_b = b["y"] - b["h"]
    return {"request": (x0, top_a, x0 + w, top_b - 4), "response": (x0, top_b, x0 + w, y0 + h)}


@contextlib.contextmanager
def desktop_exclusive():
    """Own the GUI for the duration of a panel capture.

    RECEIPT (2026-11-08): a lane looping browser launches put 237 Chromium instances
    through one boot while panels were being taken for the program-28 Vault filing.
    No OOM fired; kwin_wayland_drm's main thread hung for 44 minutes and the desktop
    needed a hard reboot mid-filing. A capture drives the real Burp window with
    xdotool and screen-reads it, so anything else fighting for the compositor can both
    wedge the box AND silently corrupt a crop by stealing focus or repainting.

    Holding this lock drops the lane browser budget to zero for HEADED browsers (a
    headless one cannot touch the GUI) and clears any that are already running. It is
    advisory by design: if the budget tool is missing the capture still proceeds,
    because refusing to take evidence is worse than taking it unprotected.
    """
    budget = os.path.join(WS, "scripts/browser-budget.py")
    lock = os.path.join(WS, ".claude/state/browser-budget/desktop.lock")
    held = False
    if os.path.exists(budget):
        try:
            os.makedirs(os.path.dirname(lock), exist_ok=True)
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, f"{os.getpid()} gnoc_panels capture\n".encode())
            os.close(fd)
            held = True
            subprocess.run([sys.executable, budget, "reap"], capture_output=True, timeout=90)
        except FileExistsError:
            pass   # another capture owns it; do not steal a lock we did not take
        except (OSError, subprocess.SubprocessError):
            pass
    try:
        yield
    finally:
        if held:
            try:
                os.unlink(lock)
            except OSError:
                pass


def capture(raw_path, dest_dir, stem=None):
    """Drive Burp and save burp-req-<stem>.png / burp-resp-<stem>.png. Returns (ok, text).

    Runs under desktop_exclusive(): a browser swarm must not fight the capture for the
    compositor (it froze the desktop once, 2026-11-08)."""
    with desktop_exclusive():
        return _capture(raw_path, dest_dir, stem)


def _capture(raw_path, dest_dir, stem=None):
    import gnoc_desktop
    import gnoc_kwin
    from PIL import Image
    if not gnoc_desktop.ocr_available():
        return False, ("panels need OCR to find and verify the rows: sudo apt install tesseract-ocr (once). The "
                       "request is already in Proxy history if resend ran; take the panels by hand meanwhile")
    req = load_raw(raw_path)
    line = request_line(req)
    host = urllib.parse.urlsplit(req["url"]).hostname
    win = gnoc_kwin.activate("Burp Suite")
    if not win:
        return False, "no Burp Suite window found"
    time.sleep(0.6)
    act = lambda ops: gnoc_desktop.act("local", ops)
    act([{"op": "key", "combo": "ctrl+shift+p"}, {"op": "sleep", "ms": 700}])  # Burp hotkey: switch to Proxy
    png, size = gnoc_desktop.shot("local")
    lines = gnoc_desktop.read(png)
    hit = gnoc_desktop.find_text(lines, "HTTP history")
    if hit:
        act([{"op": "click", "x": hit[0], "y": hit[1]}, {"op": "sleep", "ms": 700}])
        png, size = gnoc_desktop.shot("local")
        lines = gnoc_desktop.read(png)
    # select the newest history row: click a row under the table header, then ctrl+end
    head = gnoc_desktop.find_text(lines, "Method") or gnoc_desktop.find_text(lines, "Host")
    if not head:
        return False, f"could not find the HTTP history table on screen (screenshot {os.path.relpath(png, WS)})"
    act([{"op": "click", "x": head[0], "y": head[1] + 28}, {"op": "key", "combo": "ctrl+end"},
         {"op": "sleep", "ms": 900}])
    png, size = gnoc_desktop.shot("local")
    lines = gnoc_desktop.read(png)
    boxes = panel_boxes(lines, win)
    if not boxes:
        return False, f"could not locate the Request/Response editors (screenshot {os.path.relpath(png, WS)})"
    os.makedirs(dest_dir, exist_ok=True)
    stem = stem or os.path.splitext(os.path.basename(raw_path))[0]
    im = Image.open(png)
    out, problems = [], []
    for kind, box in (("req", boxes["request"]), ("resp", boxes["response"])):
        path = os.path.join(dest_dir, f"burp-{kind}-{stem}.png")
        crop = im.crop(tuple(int(v) for v in box))
        crop.save(path)
        text = " ".join(l["text"] for l in gnoc_desktop.read(path))
        if kind == "req":
            path_part = line.split(" ", 1)[1][:40]
            if path_part.lower() not in text.lower() or (host or "").lower() not in text.lower():
                problems.append(f"request panel does not show {line[:60]!r} for {host}: wrong row selected?")
        elif "HTTP/" not in text:
            problems.append("response panel shows no HTTP status line (response not loaded?)")
        out.append(os.path.relpath(path, WS))
    if problems:
        for p in out:
            os.replace(os.path.join(WS, p), os.path.join(WS, p) + ".UNVERIFIED")
        return False, "; ".join(problems) + f" (kept as .UNVERIFIED; full screenshot {os.path.relpath(png, WS)})"
    return True, "panels: " + ", ".join(out) + f"  (verified by OCR: {line[:60]} on {host})"
