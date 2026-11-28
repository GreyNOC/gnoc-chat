#!/usr/bin/env python3
"""traffic_proxy.py - sits between every role that calls the desktop Ollama and the reverse SSH
tunnel, so the control panel can show what is actually moving between the laptop and the desktop.

Laptop role resolution (scripts/llm_endpoints.py, scripts/gnoc-models.py) points "desktop" at
this proxy's port; this proxy forwards byte-for-byte to the real tunnel (scripts/desktop-link/
link-desktop.ps1, 127.0.0.1:11436) and appends one JSON line per request to
.claude/state/orch/desktop-traffic.jsonl (capped, oldest trimmed). It changes no behavior: a dead
upstream surfaces the same connection-refused the caller would see talking to the tunnel
directly, so the existing fallback-to-laptop logic in llm_endpoints.resolve() is untouched.

Each row also names its CALLER (which laptop process opened the socket: gnoc-chat, orch-bot, hunter,
office, control-panel, watch, ...; resolved once per connection from /proc) and an id. While a model
call is open it is listed in .claude/state/orch/desktop-inflight.json (id -> ts, model, caller), so a
viewer can show the request leaving when it really leaves, not when its log line lands at the end.

Run via pm2 (name: desktop-proxy) or directly: python3 traffic_proxy.py. Binds 127.0.0.1 only.
"""
import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.request

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
LISTEN = ("127.0.0.1", int(os.environ.get("GNOC_PROXY_PORT", "11440")))  # override only to test a second copy
UPSTREAM = os.environ.get("GNOC_DESKTOP_UPSTREAM", "")
_STATE = os.environ.get("GNOC_PROXY_STATE", os.path.join(WS, ".claude/state/orch"))
LOG = os.path.join(_STATE, "desktop-traffic.jsonl")
INFLIGHT = os.path.join(_STATE, "desktop-inflight.json")
ALLOWED_PATHS = {"/api/chat", "/api/generate", "/api/tags", "/api/show", "/api/embed",
                 "/api/embeddings", "/api/version", "/api/ps"}
# The log is read by three live viewers (control panel /api/traffic, gnoc-office's UPLINK panel, gnoc dash),
# so trimming it is what starves them: every rewrite shrinks the file and a tailing viewer has to resync.
# Keep the cap large enough that the viewers' 300 s window always fits even at full request rate, and rewrite
# at most once a TRIM_EVERY, not every 50 requests.
MAX_LINES = 20000           # ~4 MB at the ~215 bytes a row costs
TRIM_EVERY = 120.0          # seconds between rewrites
CHUNK = 65536

_count = 0
_open = {}  # id -> {"ts", "model", "caller", "path"}: model calls that have not answered yet
_open_lock = threading.Lock()
_log_lock = threading.Lock()  # every request thread appends to the one log file, and a trim rewrites it
_last_trim = [0.0]
_recent_pids = []  # callers seen lately: their fds are checked first, so most lookups skip the /proc scan


def _publish_open():
    tmp = INFLIGHT + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"ts": time.time(), "open": _open}, f)
        os.replace(tmp, INFLIGHT)
    except OSError:
        pass


def _socket_inode(port):
    """The inode of the laptop-side socket bound to 127.0.0.1:<port> (the caller's end of this connection)."""
    want = f":{port:04X}"
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = open(table).read().splitlines()[1:]
        except OSError:
            continue
        for ln in rows:
            f = ln.split()
            if len(f) > 9 and f[1].endswith(want) and f[2].endswith(f":{LISTEN[1]:04X}"):
                return f[9]
    return None


def _pid_of(inode):
    tag = f"socket:[{inode}]"
    pids = _recent_pids + [p for p in os.listdir("/proc") if p.isdigit() and p not in _recent_pids]
    for pid in pids:
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") == tag:
                    if pid in _recent_pids:
                        _recent_pids.remove(pid)
                    _recent_pids.insert(0, pid)
                    del _recent_pids[8:]
                    return int(pid)
        except OSError:
            continue
    return None


def _argv(pid):
    try:
        return [a.decode(errors="replace") for a in open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0") if a]
    except OSError:
        return []


def _ppid(pid):
    try:
        return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[1])
    except (OSError, IndexError, ValueError):
        return 0


def _classify(argv):
    """One argv -> a desk-level caller name, or None when this process says nothing (python, bash, ...)."""
    names = [os.path.basename(a) for a in argv[:4]]
    if "gnoc" in names or "gnoc.py" in names:
        i = names.index("gnoc") if "gnoc" in names else names.index("gnoc.py")
        sub = argv[i + 1] if i + 1 < len(argv) else ""
        return {"chat": "gnoc-chat", "watch": "watch", "dchat": "gnoc-chat"}.get(sub, "gnoc")
    for script, who in (("auto-hunt.py", "hunter"), ("opencode-lane.sh", "hunter"), ("orch-bot.py", "orch-bot"),
                        ("gnoc-office.py", "office"), ("gnoc-office", "office"), ("office-stream.py", "office"), ("server.py", "control-panel"),
                        ("gnoc_agent.py", "gnoc-chat"), ("gnoc_agents_ui.py", "gnoc-chat"),
                        ("pipeline-sweep.py", "pipeline-sweep"), ("bot.py", "oss-bot")):
        if script in names:
            return who
    return None


def _caller(port):
    """(caller, pid) for the laptop process on the other end of this connection: the nearest process in its
    ancestry that names a known role (a hunter spawned by orch-bot is the hunter, not the brain)."""
    inode = _socket_inode(port)
    pid = _pid_of(inode) if inode else None
    cur, seen = pid, 0
    while cur and cur > 1 and seen < 6:
        who = _classify(_argv(cur))
        if who:
            return who, pid
        cur, seen = _ppid(cur), seen + 1
    argv = _argv(pid) if pid else []
    if not argv:
        return "unknown", pid
    # an unknown process: its script (python3 foo.py -> foo.py), else the program itself (curl, python3 -c)
    script = argv[1] if len(argv) > 1 and not argv[1].startswith("-") else argv[0]
    return os.path.basename(script), pid


def _log(entry):
    """Append one row, and trim the file rarely and atomically.

    Both halves run under one lock: the trim used to read the file, truncate it in place and write the tail
    back, so a concurrent append was lost, a viewer could read a half-written file, and - because it fired
    every 50 requests - the file shrank constantly, which makes every tailing viewer resync and drop whatever
    it had not read yet. That is why the dashboards go blank under load.
    """
    global _count
    line = json.dumps(entry) + "\n"
    with _log_lock:
        _count += 1
        try:
            os.makedirs(os.path.dirname(LOG), exist_ok=True)
            # one write syscall on an O_APPEND fd: a viewer polling the file sees the whole row or none of
            # it, where a buffered text write let it read a row torn in half and throw the line away
            fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
        except OSError:
            return
        now = time.time()
        if now - _last_trim[0] < TRIM_EVERY:
            return
        _last_trim[0] = now
        try:
            with open(LOG) as f:
                lines = f.readlines()
            if len(lines) > MAX_LINES:
                tmp = LOG + ".tmp"
                with open(tmp, "w") as f:
                    f.writelines(lines[-MAX_LINES:])
                os.replace(tmp, LOG)  # one atomic swap: a reader sees the old file or the new one, never a stub
        except OSError:
            pass


# DNS-rebinding guard: a page in a local browser can point its own hostname at
# 127.0.0.1 and then talk to this port as "same origin". Every real caller names
# the loopback address, so a request for any other Host is refused before it is
# read. (Ollama applies the same rule itself; this service strips Host before
# forwarding, which would otherwise launder a rebound request past it.)
LOOPBACK_HOSTNAMES = {"127.0.0.1", "localhost", "[::1]"}


def host_is_loopback(host):
    host = (host or "").strip().lower()
    name = host if host.endswith("]") else host.rsplit(":", 1)[0]
    return name in LOOPBACK_HOSTNAMES



class _Cut(Exception):
    """An upstream failure after the response headers were sent: the connection is closed, not answered twice."""

class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _forward(self):
        t0 = time.time()
        if not host_is_loopback(self.headers.get("Host")):
            return self._refuse(403, "forbidden host")
        # allow-list: only GET/POST to known Ollama inference/read endpoints; never DELETE/PUT/copy/pull/etc.
        if self.command not in ("GET", "POST"):
            return self._refuse(405, "method not allowed")
        if self.path.split("?", 1)[0] not in ALLOWED_PATHS:
            return self._refuse(404, "path not allowed")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        model, num_ctx = None, None
        if body:
            try:
                _j = json.loads(body)
                model = _j.get("model")
                num_ctx = (_j.get("options") or {}).get("num_ctx")   # D74: which runner this request asks for
            except Exception:
                pass
        if not hasattr(self, "_who"):  # once per connection: a keep-alive client keeps its socket and its pid
            try:
                self._who = _caller(self.client_address[1])
            except Exception:
                self._who = ("unknown", None)
        caller, pid = self._who
        rid = f"{time.time_ns():x}"
        if model:
            with _open_lock:
                _open[rid] = {"ts": t0, "model": model, "caller": caller, "path": self.path}
                _publish_open()
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        req = urllib.request.Request(f"http://{UPSTREAM}{self.path}", data=body or None,
                                      headers=headers, method=self.command)
        bytes_out = 0
        status = 0
        err = None
        sent_headers = False
        try:
            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    status = resp.status
                    resp_headers = resp.getheaders()
                    has_cl = any(k.lower() == "content-length" for k, _ in resp_headers)
                    self.send_response(status)
                    for k, v in resp_headers:
                        if k.lower() not in ("transfer-encoding", "connection"):
                            self.send_header(k, v)
                    if not has_cl:
                        self.close_connection = True
                    self.end_headers()
                    sent_headers = True
                    while True:
                        # read1: whatever has arrived, now. read(CHUNK) waited for 64 KB or the end, so a streamed
                        # answer reached the chat all at once at the end (QAQC 2026-11-19: tokens 0.5 s apart
                        # upstream all arrived together after 3 s through the proxy)
                        chunk = resp.read1(CHUNK) if hasattr(resp, "read1") else resp.read(CHUNK)
                        if not chunk:
                            break
                        bytes_out += len(chunk)
                        try:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break
            except urllib.error.HTTPError as e:
                with e:  # the error response is a live socket: close it, or every failed call leaks one
                    status, payload = e.code, e.read()
                bytes_out = len(payload)
                self.send_response(status)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                if sent_headers:
                    # the 200 and part of the body are already out: a second status line written now landed
                    # INSIDE the body (the client read "HTTP/1.1 502 ..." as a stream chunk). End the connection
                    # instead; the client sees a cut stream, which it already handles.
                    err = f"upstream failed mid-stream: {str(e)[:180]}"
                    status = 599
                    self.close_connection = True
                    raise _Cut() from e
                # A 502 MUST carry a length, or the client hangs on it. This branch used to send a bare
                # status line with no Content-Length on an HTTP/1.1 keep-alive connection, so a client had
                # no way to know the (empty) body had ended: a dead desktop tunnel failed here in 2 s and
                # the caller then sat for its whole timeout. That is what made `gnoc chat` look hung on
                # 2026-10-26 - curl waited over 20 s for a reply the proxy had already finished sending.
                err = str(e)[:200]
                status = 502
                payload = json.dumps({"error": f"upstream {UPSTREAM}: {err}"}).encode()
                bytes_out = len(payload)
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
        except _Cut:
            pass
        finally:  # a client that hung up mid-reply must not leave its call listed as open
            if model:
                with _open_lock:  # one writer at a time: every thread shares the one .tmp file
                    _open.pop(rid, None)
                    _publish_open()
        _log({
            "ts": time.time(), "method": self.command, "path": self.path,
            "model": model, "bytes_in": length, "bytes_out": bytes_out,
            "ms": round((time.time() - t0) * 1000), "status": status, "err": err,
            "id": rid, "caller": caller, "pid": pid, "num_ctx": num_ctx,
        })

    def _refuse(self, code, msg):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)  # drain so a keep-alive connection stays in sync
        payload = json.dumps({"error": msg}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if code == 405:
            self.send_header("Allow", "GET, POST")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        _log({"ts": time.time(), "method": self.command, "path": self.path, "model": None,
              "bytes_in": n, "bytes_out": len(payload), "ms": 0, "status": code,
              "err": "blocked: " + msg, "id": f"{time.time_ns():x}", "caller": "blocked", "pid": None})

    def do_GET(self):
        self._forward()

    def do_POST(self):
        self._forward()

    # DELETE/PUT go through _forward only to get a logged 405: the proxy must never relay model deletion
    # (`gnoc models rm --on desktop` now fails loudly instead of deleting). Hardening 2026-10-24.
    def do_DELETE(self):
        self._forward()

    def do_PUT(self):
        self._forward()

    def log_message(self, fmt, *args):
        pass  # the JSONL line is the log


if __name__ == "__main__":
    _publish_open()  # a restart forgets every open call: clear what the previous process left behind
    with http.server.ThreadingHTTPServer(LISTEN, Proxy) as httpd:
        httpd.daemon_threads = True
        print(f"desktop traffic proxy: {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM}, logging to {LOG}", flush=True)
        httpd.serve_forever()
