#!/usr/bin/env python3
"""gnoc_mcp.py - the MCP client layer for gnoc chat.

ARTEX ships a configured MCP server list and calls their tools; gnoc chat had MCP *scripts* in the operator's
workspace but no first-class way to use a server.

    gnoc mcp list                       configured servers, transport, reachability
    gnoc mcp tools <server>             that server's tool list (name, description, required args)
    gnoc mcp call <server> <tool> '<json arguments>'
    gnoc mcp add <name> --stdio CMD [args...] [--env K=V]
    gnoc mcp add <name> --url http://host:port   [--transport http|sse]
    gnoc mcp remove <name>

Config lives in .claude/state/mcp.json (workspace) or ~/.gnoc/mcp.json:

    {"servers": {
        "burp": {"transport": "sse", "url": "http://127.0.0.1:9876"},
        "fs":   {"transport": "stdio", "command": "python3", "args": ["fs_server.py"], "env": {}}
    }}

Transports:
  stdio  JSON-RPC over the child's stdin/stdout, one JSON object per line (the MCP stdio transport).
  http   JSON-RPC POSTed to the URL (streamable HTTP); a JSON or SSE-framed response is accepted.
  sse    the legacy HTTP+SSE transport (Burp's MCP extension speaks it): GET the stream, POST to its endpoint.

Nothing here installs, downloads or starts a server on its own: a stdio server is only spawned when a
tool on it is listed or called, and every child is terminated with the call that spawned it.
"""
from __future__ import annotations

import http.client
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

WS = os.path.abspath(os.environ.get("GNOC_WS") or
                     os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONFIG_NAME = "mcp.json"
PROTOCOL = "2024-11-05"
CLIENT_INFO = {"name": "gnoc", "version": "1"}
DEFAULT_TIMEOUT = 20.0


# ------------------------------------------------------------------ config
def config_path(ws: str | None = None) -> str:
    return os.path.join(ws or WS, ".claude/state", CONFIG_NAME)


def load_config(ws: str | None = None) -> dict:
    path = config_path(ws)
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {"servers": {}}
    if not isinstance(data, dict):
        return {"servers": {}}
    servers = data.get("servers")
    if not isinstance(servers, dict):
        data["servers"] = {}
    return data


def save_config(data: dict, ws: str | None = None) -> str:
    path = config_path(ws)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    return path


def servers(ws: str | None = None) -> dict:
    return load_config(ws).get("servers") or {}


def add_server(name: str, spec: dict, ws: str | None = None) -> dict:
    name = _server_name(name)
    data = load_config(ws)
    data.setdefault("servers", {})[name] = spec
    save_config(data, ws)
    return spec


def remove_server(name: str, ws: str | None = None) -> bool:
    name = _server_name(name)
    data = load_config(ws)
    if name in (data.get("servers") or {}):
        del data["servers"][name]
        save_config(data, ws)
        return True
    return False


def _server_name(name: str) -> str:
    name = str(name or "").strip()
    if not name or not all(c.isalnum() or c in "._-" for c in name):
        raise ValueError(f"invalid MCP server name: {name!r}")
    return name


# ------------------------------------------------------------------ transports
class McpError(RuntimeError):
    pass


class _StdioTransport:
    """One child process speaking newline-delimited JSON-RPC, spawned for the life of one command."""

    def __init__(self, command: str, args=None, env: dict | None = None):
        cmd = [command, *[str(a) for a in (args or [])]]
        # the server gets the environment MINUS credential-shaped names (like every child gnoc starts), plus what
        # its own config gives it explicitly (QAQC r2: it inherited every key, the cloud API key included)
        try:
            import gnoc_secrets
            child_env = gnoc_secrets.child_env({})
        except Exception:  # noqa: BLE001 - standalone use without the harness on the path
            child_env = dict(os.environ)
        child_env.update({str(k): str(v) for k, v in (env or {}).items()})
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True, bufsize=1, env=child_env)
        self.responses: dict[int, queue.Queue] = {}
        self.lock = threading.Lock()
        self.next_id = 0
        self.closed = False
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if not isinstance(msg, dict):
                continue
            rid = msg.get("id")
            if "method" in msg:
                # a REQUEST from the server (ping, sampling, roots...), never our reply, even when its id equals a
                # pending one (QAQC r2: an error reply was lost under a server ping with the same id)
                if rid is not None:
                    self._answer(rid, msg.get("method"))
                continue
            if rid is not None and rid in self.responses:
                self.responses[rid].put(msg)

    def _answer(self, rid, method):
        reply = {"jsonrpc": "2.0", "id": rid}
        if method == "ping":
            reply["result"] = {}
        else:
            reply["error"] = {"code": -32601, "message": f"gnoc does not offer {method}"}
        try:
            with self.lock:
                self.proc.stdin.write(json.dumps(reply) + "\n")
                self.proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            pass

    def request(self, method: str, params: dict | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
        with self.lock:
            self.next_id += 1
            rid = self.next_id
            box: queue.Queue = queue.Queue()
            self.responses[rid] = box
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            with self.lock:
                self.proc.stdin.write(json.dumps(msg) + "\n")
                self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise McpError(f"server closed the pipe: {e}") from e
        try:
            reply = box.get(timeout=timeout)
        except queue.Empty:
            raise McpError(f"no reply to {method} within {timeout:.0f}s") from None
        finally:
            self.responses.pop(rid, None)
        if "error" in reply:
            err = reply["error"] or {}
            raise McpError(str(err.get("message") or err))
        return reply.get("result") or {}

    def notify(self, method: str, params: dict | None = None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def close(self):
        self.closed = True
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.proc.kill()
            except OSError:
                pass
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass


class _HttpTransport:
    """Streamable HTTP: POST one JSON-RPC message, accept a JSON or SSE-framed answer."""

    def __init__(self, url: str, headers: dict | None = None):
        self.url = url
        self.headers = {"content-type": "application/json",
                        "accept": "application/json, text/event-stream"}
        self.headers.update(headers or {})
        self.next_id = 0

    def request(self, method: str, params: dict | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        req = urllib.request.Request(self.url, data=json.dumps(msg).encode(), headers=self.headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                ctype = resp.headers.get("content-type", "")
        except (urllib.error.URLError, OSError) as e:
            raise McpError(f"MCP endpoint unreachable: {e}") from e
        return _parse_body(raw, ctype, self.next_id)

    def notify(self, method: str, params: dict | None = None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            req = urllib.request.Request(self.url, data=json.dumps(msg).encode(),
                                         headers=self.headers, method="POST")
            urllib.request.urlopen(req, timeout=5).close()
        except Exception:  # noqa: BLE001 - a notification failing is not a call failure
            pass

    def close(self):
        return None


def _parse_body(raw: str, ctype: str, rid: int) -> dict:
    raw = raw.strip()
    if "text/event-stream" in (ctype or "") or raw.startswith("event:"):
        for block in raw.replace("\r\n", "\n").split("\n\n"):
            data = [ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")]
            if not data:
                continue
            try:
                msg = json.loads("\n".join(data))
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("id") == rid:
                if "error" in msg:
                    err = msg["error"] or {}
                    raise McpError(str(err.get("message") or err))
                return msg.get("result") or {}
        raise McpError("SSE response carried no JSON-RPC result")
    try:
        msg = json.loads(raw or "{}")
    except ValueError as e:
        raise McpError(f"non-JSON reply: {raw[:120]!r}") from e
    if isinstance(msg, dict) and "error" in msg:
        err = msg["error"] or {}
        raise McpError(str(err.get("message") or err))
    return (msg.get("result") if isinstance(msg, dict) else None) or {}


class _SseTransport:
    """Legacy HTTP+SSE (MCP 2024-11-05): GET the event stream, wait for its `endpoint` event, POST each JSON-RPC
    message to that endpoint and read the replies off the stream.

    This used to load scripts/burp-mcp-cli.py, which the public build does not ship (and which needed `requests`),
    so every `--transport sse` server failed with "needs scripts/burp-mcp-cli.py". SSE is the MCP transport, not a
    Burp feature, and it is small enough to speak with the standard library. The stream leg goes through
    http.client rather than urlopen so the CONNECT can be bounded by the call's timeout while the idle wait on an
    open stream gets its own, longer bound: one urlopen timeout would either hang 5 minutes on a dead host or kill
    a healthy stream that simply had nothing to say for 20 s."""

    STREAM_IDLE = 300.0          # longest silence on an open stream before the reader gives up
    MAX_LINE = 32 * 1024 * 1024  # one SSE data line (a tool result) is bounded, so a runaway server cannot OOM us

    def __init__(self, url: str, headers: dict | None = None, timeout: float = DEFAULT_TIMEOUT):
        self.url = url
        self.headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self.next_id = 0
        self.lock = threading.Lock()
        self.responses: dict[int, queue.Queue] = {}
        self.endpoint: queue.Queue = queue.Queue(maxsize=1)
        self.post_url = ""
        self.closed = False
        # both legs ignore *_proxy: the stream cannot go through urlopen's proxy handling, and a POST taking a
        # different route than its stream would reach a different server session than the one it belongs to
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise McpError(f"sse server url must be http(s)://host[:port][/path], got {url!r}")
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        self.conn = cls(u.hostname, u.port, timeout=timeout)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        self.sock: socket.socket | None = None
        try:
            self.conn.request("GET", path, headers={**self.headers, "Accept": "text/event-stream",
                                                    "Cache-Control": "no-cache"})
            # kept before getresponse(): for a stream that ends at connection close (no length, HTTP/1.0) the
            # connection hands the socket to the response and forgets it, and the idle timeout and close() need it
            self.sock = self.conn.sock
            self.stream = self.conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            self.conn.close()
            raise McpError(f"SSE stream unreachable at {url}: {type(e).__name__}: {e}") from e
        ctype = self.stream.getheader("content-type") or ""
        if self.stream.status != 200 or "text/event-stream" not in ctype:
            status = self.stream.status
            self.conn.close()
            raise McpError(f"{url} answered HTTP {status} ({ctype or 'no content-type'}), not an SSE stream; "
                           "a streamable-HTTP server takes --transport http")
        if self.sock is not None:
            self.sock.settimeout(self.STREAM_IDLE)
        threading.Thread(target=self._read, daemon=True, name="gnoc-mcp-sse").start()
        try:
            endpoint = self.endpoint.get(timeout=timeout)
        except queue.Empty:
            self.close()
            raise McpError(f"{url} sent no `endpoint` event within {timeout:.0f}s") from None
        if endpoint is None:
            self.close()
            raise McpError(f"{url} closed its SSE stream before naming a message endpoint")
        try:
            self.post_url = _same_origin(url, endpoint)
        except McpError:
            self.close()
            raise

    # -- the stream
    def _read(self):
        event = ""
        data: list[str] = []
        try:
            while not self.closed:
                raw = self.stream.readline(self.MAX_LINE)
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line == "":
                    if data:
                        self._dispatch(event or "message", "\n".join(data))
                    event, data = "", []
                elif line.startswith(":"):
                    continue          # an SSE comment: servers send these as keep-alives
                else:
                    field, _, value = line.partition(":")
                    value = value[1:] if value.startswith(" ") else value
                    if field == "event":
                        event = value
                    elif field == "data":
                        data.append(value)
        except (OSError, ValueError, http.client.HTTPException, AttributeError):
            # a closed or timed-out stream ends the session; pending calls are woken below. AttributeError is
            # close() racing this readline: http.client drops the response's file object under it
            pass
        finally:
            self.closed = True
            try:
                self.endpoint.put_nowait(None)
            except queue.Full:
                pass
            with self.lock:
                boxes = list(self.responses.values())
            for box in boxes:
                box.put(None)

    def _dispatch(self, event: str, payload: str):
        if event == "endpoint":
            try:
                self.endpoint.put_nowait(payload.strip())
            except queue.Full:
                pass   # only the first endpoint counts; a later one cannot re-point a live session
            return
        try:
            msg = json.loads(payload)
        except ValueError:
            return
        if not isinstance(msg, dict):
            return
        rid = msg.get("id")
        if "method" in msg:
            # a REQUEST from the server (ping, sampling, roots): never our reply, even when its id equals a pending
            # one (the same rule as the stdio transport)
            if rid is not None and self.post_url:
                threading.Thread(target=self._answer, args=(rid, msg.get("method")), daemon=True).start()
            return
        with self.lock:
            box = self.responses.get(rid) if isinstance(rid, int) else None
        if box is not None:
            box.put(msg)

    def _answer(self, rid, method):
        reply: dict = {"jsonrpc": "2.0", "id": rid}
        if method == "ping":
            reply["result"] = {}
        else:
            reply["error"] = {"code": -32601, "message": f"gnoc does not offer {method}"}
        try:
            self._post(reply, 5.0)
        except McpError:
            pass

    # -- the message leg
    def _post(self, msg: dict, timeout: float) -> dict | None:
        """POST one message. Returns a JSON-RPC reply when the server put it in the POST body instead of on the
        stream (some do), else None."""
        req = urllib.request.Request(self.post_url, data=json.dumps(msg).encode(), method="POST",
                                     headers={**self.headers, "Content-Type": "application/json",
                                              "Accept": "application/json, text/event-stream"})
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                body = resp.read(self.MAX_LINE).decode("utf-8", "replace").strip()
        except urllib.error.HTTPError as e:
            raise McpError(f"the server refused the {msg.get('method') or 'reply'} message: HTTP {e.code}") from e
        except (urllib.error.URLError, OSError) as e:
            raise McpError(f"MCP message endpoint unreachable: {e}") from e
        if body.startswith("{"):
            try:
                got = json.loads(body)
            except ValueError:
                return None
            if isinstance(got, dict) and "method" not in got and got.get("id") == msg.get("id"):
                return got
        return None

    def request(self, method: str, params: dict | None = None, timeout: float = DEFAULT_TIMEOUT) -> dict:
        if self.closed:
            raise McpError("the SSE stream is closed")
        with self.lock:
            self.next_id += 1
            rid = self.next_id
            box: queue.Queue = queue.Queue()
            self.responses[rid] = box
        msg: dict = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        try:
            inline = self._post(msg, timeout)
            reply = inline if inline is not None else box.get(timeout=timeout)
        except queue.Empty:
            raise McpError(f"no reply to {method} within {timeout:.0f}s") from None
        finally:
            with self.lock:
                self.responses.pop(rid, None)
        if reply is None:
            raise McpError(f"the SSE stream closed before the reply to {method}")
        if "error" in reply:
            err = reply["error"] or {}
            raise McpError(str(err.get("message") if isinstance(err, dict) else err))
        return reply.get("result") or {}

    def notify(self, method: str, params: dict | None = None):
        msg: dict = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        try:
            self._post(msg, 5.0)
        except McpError:
            pass   # a notification failing is not a call failure

    def close(self):
        self.closed = True
        sock = self.sock
        if sock is not None:
            # shutdown, not just close: the reader is blocked in recv() on this socket and close() alone does not
            # wake it, so the thread (and the server's session) would linger until the idle timeout
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for part in (getattr(self, "stream", None), self.conn):   # no stream yet when the handshake failed
            try:
                if part is not None:
                    part.close()
            except OSError:
                pass


def _same_origin(base: str, endpoint: str) -> str:
    """The endpoint URL resolved against the stream URL, refused unless it is on the same scheme, host and port.
    The endpoint is chosen by the server: honouring a foreign one would let it point every message (and the headers
    configured for it, an Authorization among them) at a third host."""
    full = urllib.parse.urljoin(base, endpoint)
    a, b = urllib.parse.urlsplit(base), urllib.parse.urlsplit(full)
    default = {"http": 80, "https": 443}

    def origin(u):
        return u.scheme, (u.hostname or "").lower(), u.port or default.get(u.scheme)

    if not endpoint or origin(a) != origin(b):
        raise McpError(f"refused the server's message endpoint {endpoint!r}: it is not on {a.scheme}://{a.netloc}")
    return full


def _transport(spec: dict, ws: str | None = None, timeout: float = DEFAULT_TIMEOUT):
    transport = str(spec.get("transport") or "stdio").lower()
    if transport == "stdio":
        command = spec.get("command")
        if not command:
            raise McpError("stdio server has no command")
        return _StdioTransport(str(command), spec.get("args") or [], spec.get("env") or {})
    if transport in ("http", "streamable-http", "streamable"):
        url = spec.get("url")
        if not url:
            raise McpError("http server has no url")
        return _HttpTransport(str(url), spec.get("headers") or {})
    if transport == "sse":
        url = spec.get("url")
        if not url:
            raise McpError("sse server has no url")
        return _SseTransport(str(url), spec.get("headers") or {}, timeout=timeout)
    raise McpError(f"unknown transport {transport!r} (stdio, http, sse)")


def _session(spec: dict, ws: str | None = None, timeout: float = DEFAULT_TIMEOUT):
    """Handshake + initialized notification, returning the live transport. A failed handshake closes the child:
    it used to leak one server process per failed probe (QAQC r2)."""
    t = _transport(spec, ws, timeout)
    try:
        t.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                 "clientInfo": CLIENT_INFO}, timeout=timeout)
        t.notify("notifications/initialized")
    except BaseException:
        t.close()
        raise
    return t


# ------------------------------------------------------------------ the commands
def list_tools_full(spec: dict, ws: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    """Every tool with its whole input schema: what the harness needs to offer the tool to the model natively."""
    t = _session(spec, ws, timeout)
    try:
        result = t.request("tools/list", {}, timeout=timeout)
    finally:
        t.close()
    tools = result.get("tools") if isinstance(result, dict) else None
    out = []
    for tool in tools if isinstance(tools, list) else []:
        if isinstance(tool, dict) and tool.get("name"):
            schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            schema = {k: v for k, v in schema.items() if k not in ("$schema", "$id")}
            schema.setdefault("type", "object")
            schema.setdefault("properties", {})
            out.append({"name": str(tool["name"]), "description": str(tool.get("description") or ""),
                        "inputSchema": schema})
    return out


def list_tools(spec: dict, ws: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    t = _session(spec, ws, timeout)
    try:
        result = t.request("tools/list", {}, timeout=timeout)
    finally:
        t.close()
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return []
    out = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
        out.append({"name": str(tool.get("name") or ""),
                    "description": str(tool.get("description") or ""),
                    "required": list(schema.get("required") or []),
                    "properties": sorted((schema.get("properties") or {}).keys())})
    return out


def call_tool(spec: dict, tool: str, arguments: dict | None = None, ws: str | None = None,
              timeout: float = 60.0) -> dict:
    t = _session(spec, ws)
    try:
        result = t.request("tools/call", {"name": str(tool), "arguments": arguments or {}},
                           timeout=timeout)
    finally:
        t.close()
    texts = []
    if isinstance(result, dict):
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(str(item.get("text") or ""))
    return {"tool": tool, "isError": bool(result.get("isError")) if isinstance(result, dict) else False,
            "text": "\n".join(texts), "structured": result.get("structuredContent") if isinstance(result, dict) else None,
            "raw": result}


def list_resources(spec: dict, ws: str | None = None, timeout: float = DEFAULT_TIMEOUT) -> list[dict]:
    t = _session(spec, ws)
    try:
        result = t.request("resources/list", {}, timeout=timeout)
    finally:
        t.close()
    rows = result.get("resources") if isinstance(result, dict) else None
    return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []


def read_resource(spec: dict, uri: str, ws: str | None = None, timeout: float = 60.0) -> str:
    t = _session(spec, ws)
    try:
        result = t.request("resources/read", {"uri": str(uri)}, timeout=timeout)
    finally:
        t.close()
    parts = []
    for c in (result.get("contents") if isinstance(result, dict) else None) or []:
        if isinstance(c, dict):
            if "text" in c:
                parts.append(str(c["text"]))
            elif "blob" in c:
                parts.append(f"[binary {c.get('mimeType') or 'content'}, {len(str(c['blob'])) * 3 // 4} bytes]")
    return "\n".join(parts)


# ------------------------------------------------------------------ the tool cache (native tools)
# Offering a server's tools to the model as real tools needs their schemas at the START of a chat, and spawning
# every configured server then would make each launch wait on all of them. So the schemas are cached on disk
# whenever a server's tools are listed (mcp action=tools / servers, /mcp refresh) and the chat reads the cache.
CACHE_NAME = "mcp-tools-cache.json"


def cache_path(ws: str | None = None) -> str:
    return os.path.join(ws or WS, ".claude/state", CACHE_NAME)


def _spec_key(spec: dict) -> str:
    import hashlib
    return hashlib.sha256(json.dumps(spec, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _load_cache(ws=None) -> dict:
    try:
        with open(cache_path(ws), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(d: dict, ws=None):
    p = cache_path(ws)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = f"{p}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=1)
    os.replace(tmp, p)


def refresh_cache(server: str | None = None, ws: str | None = None) -> dict:
    """List the tools of one server (or every enabled one) and cache them. Returns {server: count | 'error ...'}."""
    conf = servers(ws)
    names = [_server_name(server)] if server else [n for n, sp in conf.items() if sp.get("enabled", True)]
    cache = _load_cache(ws)
    out = {}
    for n in names:
        if n not in conf:
            out[n] = "error: not configured"
            continue
        try:
            tools = list_tools_full(conf[n], ws)
            cache[n] = {"key": _spec_key(conf[n]), "tools": tools}
            out[n] = len(tools)
        except Exception as e:  # noqa: BLE001 - one dead server must not stop the others
            out[n] = f"error: {type(e).__name__}: {str(e)[:120]}"
    for n in list(cache):
        if n not in conf:
            del cache[n]
    _save_cache(cache, ws)
    return out


def cached_tools(ws: str | None = None) -> dict:
    """{server: [tool, ...]} from the cache, for enabled servers whose config has not changed since."""
    conf = servers(ws)
    out = {}
    for n, row in _load_cache(ws).items():
        sp = conf.get(n)
        if sp and sp.get("enabled", True) and isinstance(row, dict) and row.get("key") == _spec_key(sp):
            out[n] = [t for t in row.get("tools") or [] if isinstance(t, dict) and t.get("name")]
    return out


def probe(spec: dict, ws: str | None = None, timeout: float = 6.0) -> dict:
    """Reachability + tool count without raising."""
    try:
        tools = list_tools(spec, ws, timeout=timeout)
        return {"ok": True, "tools": len(tools), "error": ""}
    except Exception as e:  # noqa: BLE001 - a probe reports, never raises
        return {"ok": False, "tools": 0, "error": f"{type(e).__name__}: {e}"}


# ------------------------------------------------------------------ text views
def servers_text(ws: str | None = None, probe_live: bool = True) -> str:
    conf = servers(ws)
    if not conf:
        return ("no MCP servers configured\n  add one: gnoc mcp add burp --url http://127.0.0.1:9876 "
                "--transport sse\n          gnoc mcp add fs --stdio npx -y @modelcontextprotocol/server-filesystem /tmp")
    lines = ["MCP SERVERS"]
    for name, spec in sorted(conf.items()):
        transport = str(spec.get("transport") or "stdio")
        target = spec.get("url") or " ".join([str(spec.get("command") or ""), *[str(a) for a in spec.get("args") or []]])
        state = ""
        if probe_live:
            p = probe(spec, ws, timeout=5.0)
            state = f"  tools={p['tools']}" if p["ok"] else f"  OFFLINE ({p['error'][:80]})"
        enabled = "" if spec.get("enabled", True) else "  [disabled]"
        lines.append(f"  {name:<12} {transport:<6} {target}{enabled}{state}")
    return "\n".join(lines)


def tools_text(server: str, ws: str | None = None) -> str:
    name = _server_name(server)
    conf = servers(ws)
    if name not in conf:
        return f"no MCP server {name!r} (gnoc mcp list)"
    tools = list_tools(conf[name], ws)
    if not tools:
        return f"{name}: no tools advertised"
    lines = [f"MCP TOOLS - {name} ({len(tools)})"]
    for t in tools:
        req = f"  required: {', '.join(t['required'])}" if t["required"] else ""
        lines.append(f"  {t['name']}")
        if t["description"]:
            lines.append(f"      {_short(t['description'], 150)}")
        if req:
            lines.append(f"     {req}")
    return "\n".join(lines)


def call_text(server: str, tool: str, arguments: dict | None = None, ws: str | None = None) -> str:
    name = _server_name(server)
    conf = servers(ws)
    if name not in conf:
        return f"no MCP server {name!r} (gnoc mcp list)"
    result = call_tool(conf[name], tool, arguments, ws)
    head = f"MCP CALL {name}/{tool}" + ("  (isError)" if result["isError"] else "")
    body = result["text"] or json.dumps(result["structured"] or result["raw"], indent=2)[:4000]
    return f"{head}\n{body}"


def _short(text, n=150):
    s = " ".join(str(text or "").split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


# ------------------------------------------------------------------ CLI
def _main(argv: list[str]) -> int:
    action = (argv[0].lower() if argv else "list")
    rest = argv[1:]
    if action in ("list", "servers", "status"):
        print(servers_text())
        return 0
    if action in ("tools", "ls"):
        if not rest:
            print("usage: gnoc mcp tools <server>")
            return 2
        try:
            print(tools_text(rest[0]))
        except Exception as e:  # noqa: BLE001
            print(f"mcp tools failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action == "call":
        if len(rest) < 2:
            print("usage: gnoc mcp call <server> <tool> ['<json arguments>']")
            return 2
        arguments = {}
        if len(rest) > 2 and str(rest[2]).strip():
            try:
                arguments = json.loads(rest[2])
            except ValueError as e:
                print(f"the arguments must be a JSON object: {e}")
                return 2
            if not isinstance(arguments, dict):
                print("the arguments must be a JSON object")
                return 2
        try:
            print(call_text(rest[0], rest[1], arguments))
        except Exception as e:  # noqa: BLE001
            print(f"mcp call failed: {type(e).__name__}: {e}")
            return 1
        return 0
    if action == "add":
        if len(rest) < 2:
            print("usage: gnoc mcp add <name> --stdio CMD [args...] | --url URL [--transport http|sse]")
            return 2
        name, words = rest[0], rest[1:]
        spec: dict = {}
        env: dict = {}
        headers: dict = {}
        command = None
        cmd_args: list[str] = []
        i = 0
        while i < len(words):
            w = words[i]
            if w == "--url" and i + 1 < len(words):
                spec["url"] = words[i + 1]
                i += 2
                continue
            if w == "--transport" and i + 1 < len(words):
                spec["transport"] = words[i + 1].lower()
                i += 2
                continue
            if w == "--env" and i + 1 < len(words):
                k, _, v = words[i + 1].partition("=")
                env[k] = v
                i += 2
                continue
            if w == "--header" and i + 1 < len(words):
                k, _, v = words[i + 1].partition(":")
                headers[k.strip()] = v.strip()
                i += 2
                continue
            if w == "--stdio":
                spec["transport"] = "stdio"
                if i + 1 < len(words):
                    command = words[i + 1]
                    i += 2
                    continue
                i += 1
                continue
            if command is not None:
                cmd_args.append(w)
            i += 1
        if command is not None:
            spec["command"] = command
            spec["args"] = cmd_args
        if env:
            spec["env"] = env
        if headers:
            spec["headers"] = headers
        spec.setdefault("transport", "sse" if "url" in spec else "stdio")
        if spec["transport"] == "stdio" and not spec.get("command"):
            print("a stdio server needs --stdio CMD")
            return 2
        if spec["transport"] in ("http", "sse") and not spec.get("url"):
            print("an http/sse server needs --url URL")
            return 2
        try:
            add_server(name, spec)
        except Exception as e:  # noqa: BLE001
            print(f"mcp add failed: {type(e).__name__}: {e}")
            return 1
        print(f"added MCP server {name} ({spec['transport']})")
        print(servers_text(probe_live=True))
        return 0
    if action in ("remove", "rm", "delete"):
        if not rest:
            print("usage: gnoc mcp remove <name>")
            return 2
        try:
            ok = remove_server(rest[0])
        except Exception as e:  # noqa: BLE001
            print(f"mcp remove failed: {type(e).__name__}: {e}")
            return 1
        print(f"removed MCP server {rest[0]}" if ok else f"no MCP server {rest[0]!r}")
        return 0 if ok else 1
    if action in ("help", "-h", "--help"):
        print(__doc__)
        return 0
    print(f"unknown mcp action: {action} (list|tools|call|add|remove)")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
