"""Signal through a local signal-cli daemon (`signal-cli -a +NUMBER daemon --tcp 127.0.0.1:7583`), JSON-RPC.

signal-cli does the Signal protocol and verifies who sent each message; gnoc reads its "receive" notifications
and calls its "send" method. Its socket has no authentication of its own, so the gateway refuses to talk to one
that is not on this machine: anything that can reach that port can send as the account. Identity is the sender's
Signal UUID or phone number as signal-cli reports it; a group needs its id in GNOC_SIGNAL_GROUPS. Signal has no
buttons, so approvals are answered by replying `yes <id>` or `no <id>`.
"""
import itertools
import json
import queue
import socket
import threading

from .core import Adapter, Inbound
from .net import NetError, is_loopback

LIMIT = 4000


class Signal(Adapter):
    name = "signal"
    max_len = LIMIT
    can_edit = False
    buttons = False

    def __init__(self, account, rpc="127.0.0.1:7583", owners=(), log=None, connect=socket.create_connection):
        host, _, port = (rpc or "").rpartition(":")
        host = host.strip("[]")
        if not host or not port.isdigit():
            raise ValueError("GNOC_SIGNAL_RPC must be host:port of signal-cli's --tcp socket")
        if not is_loopback(host):
            raise ValueError("signal-cli's JSON-RPC socket has no authentication: it must listen on this machine "
                             "(127.0.0.1)")
        self.account, self.addr = account, (host, int(port))
        self.owners = frozenset(owners)
        self.log = log or (lambda *a: None)
        self.connect = connect
        self.sock = None
        self._ids = itertools.count(1)
        self._waiters = {}
        self._wlock = threading.Lock()
        self._inbox: "queue.Queue" = queue.Queue()

    # ---- JSON-RPC

    def request(self, method, params, timeout=30.0):
        sock = self.sock
        if sock is None:
            raise NetError("signal-cli is not connected")
        rid = next(self._ids)
        box = {"event": threading.Event()}
        self._waiters[rid] = box
        try:
            line = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": rid}) + "\n"
            with self._wlock:
                sock.sendall(line.encode())
            if not box["event"].wait(timeout):
                raise NetError(f"signal-cli did not answer {method} in {int(timeout)}s")
        finally:
            self._waiters.pop(rid, None)
        if box.get("error"):
            raise NetError(f"signal-cli {method}: {str((box['error'] or {}).get('message') or 'error')[:120]}")
        return box.get("result")

    def _on_line(self, raw):
        try:
            obj = json.loads(raw)
        except ValueError:
            return
        if not isinstance(obj, dict):
            return
        if "id" in obj and ("result" in obj or "error" in obj):
            box = self._waiters.get(obj["id"])
            if box is not None:
                box["result"], box["error"] = obj.get("result"), obj.get("error")
                box["event"].set()
        elif obj.get("method") == "receive" and isinstance(obj.get("params"), dict):
            # handled on another thread: gw.handle may send a reply, and that reply's answer arrives on THIS
            # reading thread, which must not be the one waiting for it
            self._inbox.put(obj["params"])

    # ---- outbound

    def send(self, chat_id, text, reply_to=None):
        chat_id = str(chat_id)
        params = {"account": self.account, "message": text[:LIMIT]}
        if chat_id.startswith("group:"):
            params["groupId"] = chat_id[len("group:"):]
        else:
            params["recipient"] = [chat_id]
        res = self.request("send", params) or {}
        return str(res.get("timestamp") or "") or None

    # ---- inbound

    def parse(self, params):
        env = params.get("envelope") or {}
        dm = env.get("dataMessage") or {}
        if not isinstance(dm, dict) or (dm.get("message") is None and not dm.get("attachments")):
            return None           # receipts, typing, a note sent from his own linked device: not prompts
        uuid, number = env.get("sourceUuid"), env.get("sourceNumber") or env.get("source")
        sender = next((x for x in (uuid, number) if x and str(x) in self.owners), uuid or number)
        if not sender:
            return None
        gid = (dm.get("groupInfo") or {}).get("groupId")
        inb = Inbound("signal", f"group:{gid}" if gid else str(sender), str(sender), text=str(dm.get("message") or ""),
                      message_id=str(dm.get("timestamp") or env.get("timestamp") or ""), private=not gid)
        q = dm.get("quote") or {}
        if isinstance(q, dict) and q.get("text"):
            inb.untrusted.append(("quoted message", q["text"]))
        if dm.get("attachments"):
            inb.notes.append("an attachment was sent; gnoc does not open attachments sent over the gateway")
        return inb

    def _dispatch(self, gw, stop):
        while not stop.is_set():
            try:
                params = self._inbox.get(timeout=0.5)
            except queue.Empty:
                continue
            inb = self.parse(params)
            if inb is not None:
                gw.handle(inb)

    def run(self, gw, stop):
        threading.Thread(target=self._dispatch, args=(gw, stop), name="gnoc-gateway-signal-dispatch",
                         daemon=True).start()
        backoff = 1.0
        while not stop.is_set():
            try:
                sock = self.connect(self.addr, timeout=10)
                sock.settimeout(1.0)
                self.sock = sock
                backoff = 1.0
                buf = b""
                while not stop.is_set():
                    try:
                        chunk = sock.recv(65536)
                    except (socket.timeout, TimeoutError):
                        continue
                    if not chunk:
                        raise NetError("signal-cli closed the connection")
                    buf += chunk
                    if len(buf) > 8 * 1024 * 1024:
                        raise NetError("signal-cli sent an over-long line")
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if line.strip():
                            self._on_line(line.decode("utf-8", "replace"))
            except (NetError, OSError) as e:
                self.log(f"signal: {type(e).__name__}: {str(e)[:120]}; retrying in {backoff:.0f}s")
                stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)
            finally:
                s, self.sock = self.sock, None
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def from_conf(conf, log=None):
    from .config import ids
    from .core import Allowlist
    account = conf("GNOC_SIGNAL_ACCOUNT") or ""
    ident = r"\+\d{6,15}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    owners = ids(conf("GNOC_SIGNAL_OWNERS"), ident)
    groups = {f"group:{g}" for g in ids(conf("GNOC_SIGNAL_GROUPS"), r"[A-Za-z0-9+/=_-]{8,}")}
    problems = []
    if not account:
        problems.append("GNOC_SIGNAL_ACCOUNT is not set (the number signal-cli is registered with)")
    if not owners:
        problems.append("GNOC_SIGNAL_OWNERS is empty: gnoc would answer nobody (Signal UUIDs or +numbers)")
    if problems:
        return None, None, problems
    try:
        ad = Signal(account, rpc=conf("GNOC_SIGNAL_RPC") or "127.0.0.1:7583", owners=owners, log=log)
    except ValueError as e:
        return None, None, [str(e)]
    return ad, Allowlist(owners, groups), []
