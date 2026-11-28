"""A minimal RFC 6455 WebSocket client on the standard library (Slack Socket Mode needs one; gnoc adds no
third-party package for it).

What it does: the HTTP/1.1 upgrade with Sec-WebSocket-Key/Accept checked, TLS through `ssl` with certificate and
hostname verification, client-to-server masking, fragmented messages, ping answered with pong, close answered and
reported, and a cap on frame and message size so a hostile or broken server cannot make it allocate gigabytes.
What it does not do: extensions (no permessage-deflate is offered, so none can be negotiated), subprotocols,
proxies. Plain ws:// is accepted only to this machine (the tests' fake server); everything else must be wss://.
"""
import base64
import hashlib
import os
import select
import socket
import ssl
import struct
import urllib.parse

from .net import is_loopback

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_MESSAGE = 8 * 1024 * 1024
OP_CONT, OP_TEXT, OP_BIN, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WebSocketError(Exception):
    pass


class WebSocket:
    def __init__(self, sock, leftover=b""):
        self.sock = sock
        self.buf = bytearray(leftover)
        self.closed = False
        self.close_code = None

    # ---- connect

    @classmethod
    def connect(cls, url, timeout=30.0, headers=None, ssl_context=None):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("ws", "wss") or not p.hostname:
            raise WebSocketError("not a ws:// or wss:// URL")
        if p.scheme == "ws" and not is_loopback(p.hostname):
            raise WebSocketError("plain ws:// is allowed only to this machine; use wss://")
        port = p.port or (443 if p.scheme == "wss" else 80)
        raw = socket.create_connection((p.hostname, port), timeout=timeout)
        try:
            sock = raw
            if p.scheme == "wss":
                ctx = ssl_context or ssl.create_default_context()   # verifies the certificate and the hostname
                sock = ctx.wrap_socket(raw, server_hostname=p.hostname)
            key = base64.b64encode(os.urandom(16)).decode()
            path = (p.path or "/") + (f"?{p.query}" if p.query else "")
            host = p.hostname if p.port is None else f"{p.hostname}:{p.port}"
            lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade",
                     f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
            lines += [f"{k}: {v}" for k, v in (headers or {}).items() if "\r" not in f"{k}{v}" and "\n" not in f"{k}{v}"]
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            head, rest = _read_head(sock)
            status, hdrs = _parse_head(head)
            if status != 101:
                raise WebSocketError(f"the server answered {status}, not 101 Switching Protocols")
            want = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
            if hdrs.get("sec-websocket-accept") != want:
                raise WebSocketError("Sec-WebSocket-Accept does not match the key: not a WebSocket server")
            if hdrs.get("upgrade", "").lower() != "websocket":
                raise WebSocketError("the server did not upgrade to websocket")
            if hdrs.get("sec-websocket-extensions"):
                raise WebSocketError("the server negotiated an extension that was never offered")
            ws = cls(sock, rest)
            sock.settimeout(timeout)
            return ws
        except BaseException:
            raw.close()
            raise

    # ---- frames

    def _frame(self, op, payload=b"", fin=True):
        if self.closed and op != OP_CLOSE:
            raise WebSocketError("the connection is closed")
        mask = os.urandom(4)
        n = len(payload)
        head = bytes([(0x80 if fin else 0) | op])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(head + mask + masked)

    def send_text(self, text):
        self._frame(OP_TEXT, text.encode("utf-8"))

    def send_bytes(self, data):
        self._frame(OP_BIN, bytes(data))

    def ping(self, data=b""):
        self._frame(OP_PING, bytes(data)[:125])

    def close(self, code=1000, reason=""):
        if not self.closed:
            try:
                self._frame(OP_CLOSE, struct.pack("!H", code) + reason.encode()[:120])
            except OSError:
                pass
            self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass

    def _need(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise WebSocketError("the connection dropped")
            self.buf += chunk
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def _read_frame(self):
        b0, b1 = self._need(2)
        fin, op = bool(b0 & 0x80), b0 & 0x0F
        if b0 & 0x70:
            self._fail(1002, "reserved bits set (no extension was negotiated)")
        if b1 & 0x80:
            self._fail(1002, "the server masked a frame")       # RFC 6455 5.1: a client must close on this
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack("!H", self._need(2))[0]
        elif n == 127:
            n = struct.unpack("!Q", self._need(8))[0]
        if op >= 0x8 and (n > 125 or not fin):
            self._fail(1002, "a control frame that is long or fragmented")
        if n > MAX_MESSAGE:
            self._fail(1009, "a frame over the size cap")
        return fin, op, self._need(n)

    def _fail(self, code, why):
        self.close(code, why[:100])
        raise WebSocketError(why)

    def readable(self, timeout):
        """True when a frame has started arriving within `timeout` seconds. TLS can hold decrypted bytes the
        socket's file descriptor no longer shows, so pending() is asked before select()."""
        if self.buf:
            return True
        pending = getattr(self.sock, "pending", None)
        if pending is not None and pending():
            return True
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        return bool(r)

    def recv(self, timeout=None):
        """The next text (str) or binary (bytes) message; None once the connection is closed.

        With `timeout`, TimeoutError when no frame starts in that time; the connection is still good. A timeout
        in the MIDDLE of a frame is fatal instead: half a frame cannot be put back, so the stream is closed."""
        if timeout is not None and not self.closed and not self.readable(timeout):
            raise TimeoutError("no message")
        parts, kind, size = [], None, 0
        while True:
            if self.closed:
                return None
            try:
                fin, op, data = self._read_frame()
            except (socket.timeout, TimeoutError):
                self.close(1001, "timeout mid-frame")
                raise WebSocketError("the server stalled in the middle of a frame") from None
            if op == OP_PING:
                self._frame(OP_PONG, data)
                continue
            if op == OP_PONG:
                continue
            if op == OP_CLOSE:
                self.close_code = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 1005
                self.close(self.close_code if self.close_code not in (1005, 1006, 1015) else 1000)
                return None
            if op in (OP_TEXT, OP_BIN):
                if kind is not None:
                    self._fail(1002, "a new message started inside a fragmented one")
                kind = op
            elif op == OP_CONT:
                if kind is None:
                    self._fail(1002, "a continuation frame with nothing to continue")
            else:
                self._fail(1002, f"unknown opcode {op}")
            parts.append(data)
            size += len(data)
            if size > MAX_MESSAGE:
                self._fail(1009, "a message over the size cap")
            if fin:
                payload = b"".join(parts)
                if kind == OP_BIN:
                    return payload
                try:
                    return payload.decode("utf-8")
                except UnicodeDecodeError:
                    self._fail(1007, "a text message that is not UTF-8")


def _read_head(sock, cap=16384):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise WebSocketError("the connection closed during the handshake")
        data += chunk
        if len(data) > cap:
            raise WebSocketError("the handshake response is too long")
    head, rest = data.split(b"\r\n\r\n", 1)
    return head.decode("iso-8859-1"), rest


def _parse_head(head):
    lines = head.split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise WebSocketError("not an HTTP response") from None
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return status, hdrs
