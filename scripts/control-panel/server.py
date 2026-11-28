#!/usr/bin/env python3
"""server.py - desktop rig control panel: a local dashboard for the linked Windows desktop GPU.

Shows live traffic between the laptop and the desktop (read from the instrumenting proxy's log,
scripts/desktop-link/traffic_proxy.py) and lets you change role assignments, the desktop's
recorded VRAM, and type raw `gnoc` commands, all from a browser instead of a terminal. It is a
thin wrapper: every control action shells out to the real scripts/gnoc-models.py and scripts/gnoc
so there is exactly one source of truth for what a role is set to.

Binds 127.0.0.1 only; not reachable from the network. Run via pm2 (name: control-panel) or
directly: python3 server.py, then open http://127.0.0.1:8787
"""
import hmac
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request

from flask import Flask, Response, jsonify, request

_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(s):
    return _ANSI.sub("", s or "")

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MODELS_PY = os.path.join(WS, "scripts", "gnoc-models.py")
# the real, current CLI is the installed ~/.local/bin/gnoc (dispatches models/lab/sandbox/...);
# scripts/gnoc in the repo is an older, partial copy - never shell out to that one.
GNOC = os.path.expanduser("~/.local/bin/gnoc")
TRAFFIC_LOG = os.path.join(WS, ".claude/state/orch/desktop-traffic.jsonl")
# same default as scripts/llm_endpoints.py / scripts/gnoc-models.py: the instrumenting proxy, so a
# chat sent here shows up in the traffic card too, not a bypass of it.
DESKTOP_HOST = os.environ.get("GNOC_DESKTOP_OLLAMA", "")

app = Flask(__name__)

# --- local-RCE hardening: per-process token + Host/Origin/Fetch-Metadata checks on every /api/* ---
PANEL_TOKEN = secrets.token_hex(32)
TOKEN_FILE = os.path.expanduser("~/.config/gnoc/control-panel.token")
ALLOWED_HOSTS = {"127.0.0.1:8787", "localhost:8787"}
ALLOWED_ORIGINS = {"http://127.0.0.1:8787", "http://localhost:8787"}
CMD_RE = re.compile(r"^[A-Za-z0-9 ._:/@=,+-]{1,400}$")


def write_token_file(path=TOKEN_FILE):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(PANEL_TOKEN + "\n")
    os.chmod(path, 0o600)
    return path


def _deny(msg, code=403):
    return jsonify({"ok": False, "err": msg}), code


@app.before_request
def guard_api():
    if not request.path.startswith("/api/"):
        return None
    h = request.headers
    if h.get("Host") not in ALLOWED_HOSTS:
        return _deny("forbidden host")
    origin = h.get("Origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        return _deny("forbidden origin")
    if h.get("Sec-Fetch-Site") in ("cross-site", "same-site"):
        return _deny("forbidden fetch site")
    if not hmac.compare_digest(h.get("X-Panel-Token", "").encode(), PANEL_TOKEN.encode()):
        return _deny("missing or invalid panel token")
    if request.method == "POST" and request.mimetype != "application/json":
        return _deny("Content-Type must be application/json", 415)
    return None


def _body():
    d = request.get_json(silent=True)
    return d if isinstance(d, dict) else {}


def page_may_get_token():
    h = request.headers
    origin = h.get("Origin")
    return ((origin is None or origin == "http://127.0.0.1:8787")
            and h.get("Host") in ALLOWED_HOSTS
            and h.get("Sec-Fetch-Site") in (None, "none", "same-origin"))


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, cwd=WS, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, FORCE_COLOR="0", NO_COLOR="1", GNOC_FORCE_COLOR="0"))
        return {"ok": p.returncode == 0, "code": p.returncode, "out": strip_ansi(p.stdout), "err": strip_ansi(p.stderr)}
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": -1, "out": "", "err": f"timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"ok": False, "code": -1, "out": "", "err": str(e)}


def host_status(host):
    r = run([sys.executable, MODELS_PY, "json"] + ([] if host == "local" else ["--on", "desktop"]), timeout=10)
    try:
        return json.loads(r["out"])
    except ValueError:
        return {"linked": False, "error": (r["out"] + r["err"]).strip()[-400:] or "no response"}


@app.get("/")
def index():
    html = PAGE
    if page_may_get_token():
        html = html.replace("<head>", f'<head>\n<meta name="panel-token" content="{PANEL_TOKEN}">', 1)
    resp = Response(html, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


@app.get("/api/ping")
def ping():
    return jsonify({"ok": True})


@app.get("/api/status")
def status():
    return jsonify({"local": host_status("local"), "desktop": host_status("desktop"), "ts": time.time()})


TRAFFIC_MAX_READ = 4 * 1024 * 1024  # bound the work per poll by BYTES, not by a line count that a busy
                                    # minute overruns (the old [-6000:] cut the 300 s window short under load)


def traffic_rows(window, now, path=None, maxbytes=TRAFFIC_MAX_READ):
    """The log rows inside the last `window` seconds, read from the end of the file only."""
    path = path or TRAFFIC_LOG
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - maxbytes))
            data = f.read()
    except OSError:
        return []
    lines = data.decode("utf-8", "replace").splitlines()
    if size > maxbytes and lines:
        lines = lines[1:]  # the seek landed mid-row
    rows = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if now - e.get("ts", 0) <= window:
            rows.append(e)
    return rows


@app.get("/api/traffic")
def traffic():
    window = float(request.args.get("seconds", 300))
    bucket = max(1.0, float(request.args.get("bucket", 5)))
    now = time.time()
    rows = traffic_rows(window, now)
    buckets = {}
    for e in rows:
        b = int((now - e["ts"]) // bucket)
        d = buckets.setdefault(b, {"bytes_in": 0, "bytes_out": 0, "n": 0})
        d["bytes_in"] += e.get("bytes_in", 0)
        d["bytes_out"] += e.get("bytes_out", 0)
        d["n"] += 1
    n_buckets = int(window // bucket)
    series = [{"t": -k * bucket, **buckets.get(k, {"bytes_in": 0, "bytes_out": 0, "n": 0})}
              for k in range(n_buckets, -1, -1)]
    recent = sorted(rows, key=lambda e: -e["ts"])[:40]
    totals = {"bytes_in": sum(e.get("bytes_in", 0) for e in rows),
              "bytes_out": sum(e.get("bytes_out", 0) for e in rows), "n": len(rows)}
    return jsonify({"series": series, "recent": recent, "bucket_seconds": bucket, "totals": totals})


@app.post("/api/role")
def set_role():
    d = _body()
    role, model, on = d.get("role"), d.get("model"), d.get("on", "local")
    if role not in ("brain", "chat", "hunter") or not model:
        return jsonify({"ok": False, "out": "", "err": "role must be brain, chat or hunter; model is required"})
    cmd = [sys.executable, MODELS_PY, "use", role, model]
    if on == "desktop":
        cmd += ["--on", "desktop"]
    return jsonify(run(cmd))


@app.post("/api/vram")
def set_vram():
    gb = _body().get("gb")
    try:
        float(gb)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "out": "", "err": "gb must be a number"})
    return jsonify(run([sys.executable, MODELS_PY, "desktop", "vram", str(gb)]))


@app.post("/api/chat")
def chat():
    d = _body()
    model = (d.get("model") or "").strip()
    messages = d.get("messages") or []
    if not model or not messages:
        return jsonify({"ok": False, "err": "model and messages are required"})
    body = json.dumps({"model": model, "messages": messages, "stream": False}).encode()
    req = urllib.request.Request(f"http://{DESKTOP_HOST}/api/chat", data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            resp = json.loads(r.read().decode())
        return jsonify({"ok": True, "message": resp.get("message") or {}})
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            return jsonify({"ok": False,
                            "err": f"desktop Ollama returned {e.code}: {e.read().decode()[:300]}"})
    except Exception as e:
        return jsonify({"ok": False, "err": f"desktop unreachable: {e}"[:300]})


@app.post("/api/exec")
def exec_cmd():
    line = _body().get("cmd") or ""
    line = line.strip() if isinstance(line, str) else ""
    if not line:
        return jsonify({"ok": False, "out": "", "err": "empty command"})
    if line.startswith("!"):
        if os.environ.get("CONTROL_PANEL_ALLOW_SHELL") != "1":
            return jsonify({"ok": False, "out": "", "err": "shell escape disabled (set CONTROL_PANEL_ALLOW_SHELL=1)"}), 403
        cmd = ["bash", "-lc", line[1:]]
    else:
        if not CMD_RE.match(line):
            return jsonify({"ok": False, "out": "", "err": "command contains disallowed characters or is too long"}), 400
        try:
            cmd = [GNOC] + shlex.split(line)
        except ValueError as e:
            return jsonify({"ok": False, "out": "", "err": f"bad command: {e}"}), 400
    return jsonify(run(cmd, timeout=120))


PAGE = open(os.path.join(os.path.dirname(__file__), "index.html")).read()


if __name__ == "__main__":
    print(f"control-panel token file: {write_token_file()}", flush=True)
    app.run(host="127.0.0.1", port=8787)
