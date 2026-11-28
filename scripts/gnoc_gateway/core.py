"""The gateway core: every safety decision the adapters share, made in one place.

An adapter turns a messenger's wire format into an Inbound and sends text back; it decides nothing else. The
core decides:

- WHO. An Allowlist of stable ids (a Telegram numeric user id, a Slack user id, a Signal UUID), checked on every
  message and on every approval answer. A display name or @username is never an identity: its owner can change
  it to yours. An unknown sender gets no reply at all, so the bot does not even confirm it exists.
- WHERE. A reply goes to `inbound.chat_id` and nowhere else. The runner returns TEXT; there is no field, argument
  or marker through which the model can name another destination (gnoc_comms' rule: the model never chooses a
  recipient). The one tool whose argument is a recipient (draft_outgoing) is removed from gateway sessions.
- WHAT LEAVES. Every outbound string (answers, streamed progress, approval prompts, errors) is redacted as one
  piece BEFORE it is split, so a secret cannot straddle two chunks and slip past. A redactor that raises
  withholds the message: nothing is ever sent unredacted (the Phase-0 rule for the Discord scrubber, kept here).
- WHICH APPROVALS COUNT. The agent's approval engine asks the broker; the broker puts a yes/no in the origin
  chat and counts only the allowlisted owner of that chat answering that request id. Another sender, another
  chat, a wrong or replayed id, a malformed answer, or no answer before the timeout is NO. There is no "approve
  all" here: the engine's auto mode cannot be switched on from a messenger.
- WHAT STAYS LOCAL. Slash commands (/file, /send, /skills trust, /auto, /approve ...) act on the identity of a
  line typed at gnoc's own keyboard. A messenger line is not that, so every slash command except the gateway's
  own four (/help, /start, /new, /stop) is refused before the agent sees it.
- WHAT IS DATA. The owner's own words are the user's turn. A forwarded message, the message it replies to, a
  quote and an attachment's caption are someone else's text: they reach the model fenced by gnoc_comms.untrusted
  (with its injection and invisible-character scan), and the turn is marked tainted so acting tools ask first.
"""
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

WITHHELD = "(a reply was withheld: redacting it failed, so it was not sent. The gateway log has the reason.)"
MAX_PARTS = 8                 # a long answer is truncated rather than flooding a phone with 40 messages
OWN_COMMANDS = ("/help", "/start", "/new", "/stop")
HELP = ("gnoc gateway. Send a message and gnoc answers here, as `gnoc chat` would.\n"
        "Actions that need your approval show up here as a yes/no; no answer in time means no.\n"
        "/new starts a fresh conversation, /stop cuts the current answer short, /help shows this.\n"
        "Other slash commands are typed in `gnoc chat` on the computer itself.")

_ANSWER = re.compile(r"^\s*(yes|y|approve|allow|no|n|deny)\s+#?([0-9a-f]{8})\s*[.!]?\s*$", re.I)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[@-Z\\-_]")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _log_default(*a):
    # stderr, never stdout: the runner captures stdout to stream the agent's own output, and a log line must not
    # land in someone's chat. Content is never logged, only ids and sizes.
    print(time.strftime("%H:%M:%S"), "gateway:", *a, file=sys.__stderr__, flush=True)


# ----------------------------------------------------------------- data

@dataclass
class Inbound:
    """One message, as the core sees it. Built by the adapter from the messenger's event and nothing else."""
    adapter: str
    chat_id: str                  # where it came from: the only place a reply can go
    sender_id: str                # a stable id, never a display name
    text: str = ""                # the sender's own words
    message_id: str = ""
    private: bool = False         # a 1:1 chat with exactly this sender
    untrusted: List[Tuple[str, str]] = field(default_factory=list)   # (label, text): forwarded / quoted / caption
    notes: List[str] = field(default_factory=list)   # gateway-written facts ("a photo was attached, not read")


class Allowlist:
    """Owners by stable id, plus the group chats they may use gnoc in. Empty owners = gnoc answers nobody."""

    def __init__(self, owners=(), chats=(), private_ok=True):
        self.owners = frozenset(str(o).strip() for o in owners if str(o).strip())
        self.chats = frozenset(str(c).strip() for c in chats if str(c).strip())
        self.private_ok = private_ok

    def owner(self, sender_id, chat_id, private=False):
        s, c = str(sender_id or "").strip(), str(chat_id or "").strip()
        if not s or s not in self.owners:
            return False
        if c and c in self.chats:
            return True
        return bool(self.private_ok and private)


class Adapter:
    """A transport. Subclasses send text to a chat id they were handed; they never pick one."""
    name = "base"
    max_len = 4000
    can_edit = False
    buttons = False               # approval prompts carry yes/no buttons (else: reply `yes <id>`)

    def send(self, chat_id, text, reply_to=None):   # -> message id or None
        raise NotImplementedError

    def edit(self, chat_id, message_id, text):      # -> bool
        return False

    def ask(self, chat_id, approval_id, text):      # an approval prompt -> message id or None
        return self.send(chat_id, text)

    def settle(self, chat_id, message_id, text):    # the prompt after it was answered or expired
        if self.can_edit and message_id:
            self.edit(chat_id, message_id, text)


class RedactionError(Exception):
    pass


def clean(text):
    """Terminal output as plain text: colours, cursor moves and spinner carriage returns removed."""
    t = _ANSI.sub("", str(text or ""))
    t = "\n".join(seg.split("\r")[-1] for seg in t.split("\n"))   # a spinner redraws its line with \r
    return _CTRL.sub("", t)


class Redactor:
    """Secrets out, then the adapter's own tokens, then an optional extra scrubber (Discord's name substitution).

    Fails closed: any stage raising, or returning something that is not text, raises RedactionError and the
    caller withholds the message.
    """

    def __init__(self, tokens=(), extra=None, secrets_redact=None):
        forms = set()
        for t in tokens:
            if t and len(str(t)) >= 8:
                forms.add(str(t))
                try:   # the same token URL-encoded or JSON-escaped must not slip past either
                    import gnoc_secrets
                    forms.update(f for f in gnoc_secrets.encodings(str(t)) if len(f) >= 8)
                except Exception:  # noqa: BLE001 - the raw form is still replaced
                    pass
        self.tokens = sorted(forms, key=len, reverse=True)
        self.extra = extra
        self._secrets = secrets_redact

    def __call__(self, text):
        try:
            t = clean(text)
            red = self._secrets
            if red is None:
                import gnoc_secrets
                red = gnoc_secrets.redact
            t = red(t)
            if not isinstance(t, str):
                raise TypeError("secret redaction returned no text")
            for tok in self.tokens:
                t = t.replace(tok, "[REDACTED:gateway-token]")
            if self.extra is not None:
                t = self.extra(t)
                if not isinstance(t, str):
                    raise TypeError("the extra scrubber returned no text")
            return t
        except Exception as e:  # noqa: BLE001 - every failure is the same answer: do not send
            raise RedactionError(f"{type(e).__name__}: {e}"[:200]) from e


def split_text(text, limit, max_parts=MAX_PARTS):
    """Messages of at most `limit` characters, split on line boundaries, in order, with a truncation note."""
    text = (text or "").rstrip()
    if not text:
        return ["(no answer)"]
    room = max(40, limit - 120)          # the truncation note lands on the last part
    blocks, buf, size = [], [], 0
    for line in text.split("\n"):
        while len(line) > room:          # one over-long line: a URL or a wide table row
            if buf:
                blocks.append("\n".join(buf))
                buf, size = [], 0
            blocks.append(line[:room])
            line = line[room:]
        if size + len(line) + 1 > room and buf:
            blocks.append("\n".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += len(line) + 1
    if buf:
        blocks.append("\n".join(buf))
    out = blocks[:max_parts]
    if len(blocks) > max_parts:
        out[-1] += f"\n... truncated: {len(blocks) - max_parts} more part(s). The full answer is in gnoc chat."
    return [b[:limit] for b in out]


def _tail(text, n):
    text = text.rstrip()
    return text if len(text) <= n else "..." + text[-(n - 3):]


# ----------------------------------------------------------------- approvals

class _Pending:
    def __init__(self, pid, adapter, chat_id, allow):
        self.id, self.adapter, self.chat_id, self.allow = pid, adapter, str(chat_id), allow
        self.event = threading.Event()
        self.result: Optional[bool] = None
        self.message_id = None


class ApprovalBroker:
    """One yes/no per request id, answerable only by an allowlisted owner in the chat it was asked in."""

    def __init__(self, redact, log=_log_default, clock=time.monotonic):
        self.redact = redact
        self.log = log
        self.clock = clock
        self._lock = threading.Lock()
        self._pending: Dict[str, _Pending] = {}

    def pending_in(self, adapter_name, chat_id):
        with self._lock:
            return [p.id for p in self._pending.values() if p.adapter == adapter_name and p.chat_id == str(chat_id)]

    def request(self, adapter, chat_id, allow, tool, detail, timeout):
        """True only for an owner's yes before the timeout. Called from the turn's thread; blocks until then."""
        pid = secrets.token_hex(4)
        how = ("Tap Yes or No." if adapter.buttons else f"Reply `yes {pid}` or `no {pid}`.")
        text = (f"gnoc asks to run {tool}: {str(detail)[:1500]}\n"
                f"Approve? {how} No answer in {int(timeout)}s counts as no. (request {pid})")
        try:
            text = self.redact(text)
        except RedactionError as e:
            # the owner cannot judge a prompt we cannot show: no prompt, no yes
            self.log(f"approval {pid} for {tool} denied unasked: the prompt could not be redacted ({e})")
            return False
        p = _Pending(pid, adapter.name, chat_id, allow)
        with self._lock:
            self._pending[pid] = p
        try:
            try:
                p.message_id = adapter.ask(str(chat_id), pid, text)
            except Exception as e:  # noqa: BLE001 - an unsent prompt is an unanswered one
                self.log(f"approval {pid}: sending the prompt failed ({type(e).__name__}); denied")
                return False
            p.event.wait(max(0.0, float(timeout)))
        finally:
            with self._lock:
                self._pending.pop(pid, None)
        ok = p.result is True
        if p.result is None:
            p.result = False   # a late answer after this point finds nothing to set
            verdict = f"no answer in {int(timeout)}s: denied, not run."
        else:
            verdict = "approved." if ok else "denied, not run."
        self.log(f"approval {pid} for {tool}: {'yes' if ok else 'no'}")
        try:
            adapter.settle(str(chat_id), p.message_id, self.redact(f"{tool}: {verdict} (request {pid})"))
        except Exception:  # noqa: BLE001 - the answer stands even if the prompt cannot be updated
            pass
        return ok

    def answer(self, adapter_name, chat_id, sender_id, pid, yes, private=False):
        """True when this answer was accepted. Everything else is ignored, silently."""
        with self._lock:
            p = self._pending.get(str(pid or ""))
            if p is None or p.adapter != adapter_name or p.chat_id != str(chat_id):
                return False
            if not p.allow.owner(sender_id, chat_id, private):
                return False
            if p.result is not None:
                return False           # first answer wins; a second tap changes nothing
            p.result = bool(yes)
        p.event.set()
        return True

    def cancel(self, adapter_name, chat_id):
        """/stop: every open question in this chat is answered no."""
        with self._lock:
            hits = [p for p in self._pending.values() if p.adapter == adapter_name and p.chat_id == str(chat_id)]
            for p in hits:
                if p.result is None:
                    p.result = False
        for p in hits:
            p.event.set()
        return len(hits)


# ----------------------------------------------------------------- the gateway

class _Stream:
    """Progress shown by editing one placeholder message, throttled; the final answer replaces it."""

    def __init__(self, gw, adapter, inbound):
        self.gw, self.adapter, self.inbound = gw, adapter, inbound
        self.msg_id = None
        self.last = 0.0
        self.done = False
        self.lock = threading.Lock()

    def update(self, so_far):
        if not self.adapter.can_edit or self.done:
            return
        now = self.gw.clock()
        if now - self.last < self.gw.stream_interval:
            return
        with self.lock:
            if self.done or now - self.last < self.gw.stream_interval:
                return
            self.last = now
            tail = _tail(clean(so_far), min(1500, self.adapter.max_len - 200))
            if not tail.strip():
                return
            try:
                body = self.gw.redact("working ...\n" + tail)
            except RedactionError:
                return             # nothing streamed is better than something unredacted
            try:
                if self.msg_id is None:
                    self.msg_id = self.adapter.send(self.inbound.chat_id, body, reply_to=self.inbound.message_id)
                else:
                    self.adapter.edit(self.inbound.chat_id, self.msg_id, body)
            except Exception as e:  # noqa: BLE001 - progress is a convenience
                self.gw.log(f"progress update failed: {type(e).__name__}")

    def finish(self, answer):
        with self.lock:
            self.done = True
            parts = self.gw.outbound(answer, self.adapter.max_len)
            first = 0
            if self.msg_id is not None and self.adapter.can_edit:
                try:
                    if self.adapter.edit(self.inbound.chat_id, self.msg_id, parts[0]):
                        first = 1
                except Exception:  # noqa: BLE001 - fall back to a fresh message
                    first = 0
            for p in parts[first:]:
                self.adapter.send(self.inbound.chat_id, p, reply_to=self.inbound.message_id)


class Gateway:
    """Adapters in, one agent turn at a time, text out to the chat each message came from."""

    def __init__(self, runner_factory, redact=None, approval_timeout=300.0, stream_interval=2.0,
                 log=_log_default, clock=time.monotonic, interrupt=None, busy=None):
        self.runner_factory = runner_factory          # key -> runner with .turn(...)
        self.redact = redact or Redactor()
        self.approval_timeout = float(approval_timeout)
        self.stream_interval = float(stream_interval)
        self.log = log
        self.clock = clock
        self.interrupt = interrupt                    # /stop: callable that cuts the running turn short
        self.broker = ApprovalBroker(self.redact, log=log, clock=clock)
        self.adapters: Dict[str, Tuple[Adapter, Allowlist]] = {}
        self.sessions: Dict[tuple, object] = {}
        # One turn at a time across every chat: the agent's state (stdout capture, working directory, the
        # facade's globals) is process-wide, so two turns would interleave. A second message is told to wait.
        # (busy: a host that runs another agent in this process, like the Discord bot's read-only !ask, passes
        # its lock so the two never overlap either)
        self._busy = busy if busy is not None else threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._current: Optional[tuple] = None

    def add(self, adapter, allow):
        self.adapters[adapter.name] = (adapter, allow)

    # ---- inbound

    def handle(self, inbound: Inbound):
        """Called by an adapter for every message. Never raises, never blocks on a model turn."""
        try:
            self._handle(inbound)
        except Exception as e:  # noqa: BLE001 - one bad message must not stop the poll loop
            self.log(f"{inbound.adapter}: handling a message failed: {type(e).__name__}")

    def _handle(self, inbound):
        got = self.adapters.get(inbound.adapter)
        if got is None:
            return
        adapter, allow = got
        if not allow.owner(inbound.sender_id, inbound.chat_id, inbound.private):
            self.log(f"{inbound.adapter}: ignored sender {inbound.sender_id} in chat {inbound.chat_id}")
            return          # silent: an unknown sender learns nothing, not even that this is gnoc
        own = _visible(inbound.text).strip()
        # only the owner's OWN words can answer: a forwarded "yes <id>" lands in inbound.untrusted, never in `own`,
        # while replying to the prompt itself (which quotes it) still answers it
        m = _ANSWER.match(own)
        if m:
            ok = self.broker.answer(inbound.adapter, inbound.chat_id, inbound.sender_id, m.group(2).lower(),
                                    m.group(1).lower() in ("yes", "y", "approve", "allow"), inbound.private)
            if not ok:
                self.reply(adapter, inbound, f"no open request {m.group(2).lower()} here (it expired, was "
                                             "answered, or belongs to another chat). Nothing was approved.")
            return
        if own.startswith("/"):
            self._command(adapter, inbound, own)
            return
        if not own and not inbound.untrusted and not inbound.notes:
            return
        if not self._busy.acquire(blocking=False):
            waiting = self.broker.pending_in(inbound.adapter, inbound.chat_id)
            if waiting:
                self.reply(adapter, inbound, f"waiting for your answer to request {waiting[0]} first"
                           + ("" if adapter.buttons else f": reply `yes {waiting[0]}` or `no {waiting[0]}`") + ".")
            else:
                self.reply(adapter, inbound, "still working on the last message; /stop cuts it short.")
            return
        try:
            key = (inbound.adapter, str(inbound.chat_id), str(inbound.sender_id))
            self._current = key
            t = threading.Thread(target=self._turn, args=(adapter, allow, inbound, own, key),
                                 name="gnoc-gateway-turn", daemon=True)
            self._thread = t
            t.start()
        except BaseException:
            self._current = None
            self._busy.release()
            raise

    def _command(self, adapter, inbound, own):
        cmd = own.split()[0].lower().split("@", 1)[0]   # Telegram groups send /new@SomeBot
        if cmd in ("/help", "/start"):
            self.reply(adapter, inbound, HELP)
        elif cmd == "/new":
            key = (inbound.adapter, str(inbound.chat_id), str(inbound.sender_id))
            if self._current == key:
                self.reply(adapter, inbound, "still answering; /stop first, then /new.")
            else:
                self.sessions.pop(key, None)
                self.reply(adapter, inbound, "a fresh conversation starts with your next message.")
        elif cmd == "/stop":
            n = self.broker.cancel(inbound.adapter, inbound.chat_id)
            if self._current and self._current[:2] == (inbound.adapter, str(inbound.chat_id)) and self.interrupt:
                try:
                    self.interrupt()
                except Exception:  # noqa: BLE001
                    pass
                self.reply(adapter, inbound, "stopping" + (f"; {n} open request(s) denied." if n else "."))
            else:
                self.reply(adapter, inbound, "nothing is running here.")
        else:
            self.log(f"{inbound.adapter}: refused slash command {cmd[:24]!r} from {inbound.sender_id}")
            self.reply(adapter, inbound,
                       f"{cmd[:40]} is not available from a messenger. Slash commands act on a line typed at gnoc's "
                       "own keyboard (/file, /send, /skills trust, /auto, /approve ...), and a message sent here is not "
                       "that. Type it in `gnoc chat` on the computer, or say what you want in plain words.")

    def _turn(self, adapter, allow, inbound, own, key):
        stream = _Stream(self, adapter, inbound)
        answer = ""
        try:
            runner = self.sessions.get(key)
            if runner is None:
                runner = self.runner_factory(key)
                self.sessions[key] = runner
            model_text, untrusted = compose(own, inbound)

            def approver(tool, detail):
                # bound to THIS chat: the prompt goes to the message's own chat and only its owner can answer
                return self.broker.request(adapter, inbound.chat_id, allow, tool, detail, self.approval_timeout)

            answer = runner.turn(model_text, typed=own, untrusted=untrusted, approver=approver,
                                 on_progress=stream.update)
        except Exception as e:  # noqa: BLE001 - say it failed, without the exception text (it may quote data)
            self.log(f"{inbound.adapter}: the turn failed: {type(e).__name__}")
            answer = f"the turn failed ({type(e).__name__}). The gateway log has more."
        finally:
            self._current = None
            self._busy.release()
        try:
            stream.finish(str(answer or "").strip() or "(no answer)")
        except Exception as e:  # noqa: BLE001
            self.log(f"{inbound.adapter}: sending the answer failed: {type(e).__name__}")

    def wait_idle(self, timeout=30.0):
        t = self._thread
        if t is not None:
            t.join(timeout)
        return not (t and t.is_alive())

    # ---- outbound

    def outbound(self, text, limit):
        """Redact the WHOLE text, then split. Redacting chunk by chunk would miss a secret cut in two."""
        try:
            return split_text(self.redact(text), limit)
        except RedactionError as e:
            self.log(f"withheld a message: {e}")
            return [WITHHELD]

    def reply(self, adapter, inbound, text):
        """A short gateway message to the chat the inbound came from (and only there)."""
        for part in self.outbound(text, adapter.max_len):
            try:
                adapter.send(inbound.chat_id, part, reply_to=inbound.message_id)
            except Exception as e:  # noqa: BLE001
                self.log(f"{inbound.adapter}: send failed: {type(e).__name__}")

    def answer(self, adapter_name, chat_id, sender_id, pid, yes, private=False):
        """For button adapters: a callback carrying (pid, yes). The broker checks owner, chat and id."""
        return self.broker.answer(adapter_name, chat_id, sender_id, pid, yes, private)


def _visible(text):
    """The owner's text without invisible characters, so a zero-width prefix cannot disguise a slash command."""
    try:
        import gnoc_comms
        return gnoc_comms.injection_signs(text)[0]
    except Exception:  # noqa: BLE001
        return re.sub(r"[​-‏‪-‮⁠-⁤﻿]", "", str(text or ""))


def compose(own, inbound):
    """(the text the model reads, the untrusted texts). The owner's words first; everything else fenced."""
    import gnoc_comms
    parts = [own] if own else []
    parts += [f"[{n}]" for n in inbound.notes]
    raw = []
    for label, text in inbound.untrusted:
        if str(text or "").strip():
            parts.append(gnoc_comms.untrusted(f"{inbound.adapter} {label}", str(text)))
            raw.append(str(text))
    if not own and raw:
        parts.insert(0, "(the user sent this without a comment of their own)")
    return "\n\n".join(parts), raw


RunnerFactory = Callable[[tuple], object]
