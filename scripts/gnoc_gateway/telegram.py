"""Telegram: the Bot API by long polling (getUpdates), so no public port, webhook or certificate is needed.

Identity is Telegram's numeric user id (`from.id`) plus the chat id, never the @username, which its owner can
change. A private chat counts only when its id equals the sender's (that is how Telegram numbers 1:1 chats);
a group needs its chat id in GNOC_TELEGRAM_CHATS as well. Approvals are inline Yes/No buttons; a button press
counts only from an allowlisted owner in the chat the question was asked in (callback_query.from.id is checked,
so another member of a group tapping Yes changes nothing).
"""
import re
import time

from .core import Adapter, Inbound
from .net import NetError, check_base, post_json

LIMIT = 4096
_CB = re.compile(r"gw:([yn]):([0-9a-f]{8})")
_ATTACHED = ("photo", "document", "voice", "audio", "video", "video_note", "animation", "sticker", "contact",
             "location", "venue", "poll", "dice")
_FORWARD = ("forward_origin", "forward_from", "forward_from_chat", "forward_sender_name", "forward_date")


def _cid(chat_id):
    s = str(chat_id)
    return int(s) if re.fullmatch(r"-?\d+", s) else s


class Telegram(Adapter):
    name = "telegram"
    max_len = LIMIT
    can_edit = True
    buttons = True

    def __init__(self, token, base="https://api.telegram.org", poll_timeout=50, max_age=600, log=None,
                 clock=time.time):
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN is not set")
        self.token = token
        self.base = check_base(base, "GNOC_TELEGRAM_API")
        self.poll_timeout = int(poll_timeout)
        self.max_age = max_age          # a queued message older than this (s) is not run: see poll_once
        self.offset = None
        self.log = log or (lambda *a: None)
        self.clock = clock
        self.started = clock()

    # ---- wire

    def call(self, method, params, timeout=30.0):
        got = post_json(f"{self.base}/bot{self.token}/{method}", params, timeout=timeout)
        if not got.get("ok"):
            desc = str(got.get("description") or "error")[:200].replace(self.token, "[token]")
            retry = (got.get("parameters") or {}).get("retry_after")
            raise NetError(f"telegram {method}: {desc}", status=got.get("error_code"), retry_after=retry)
        return got.get("result")

    # ---- outbound (chat ids always come from an Inbound, through the core)

    def send(self, chat_id, text, reply_to=None):
        p = {"chat_id": _cid(chat_id), "text": text[:LIMIT], "link_preview_options": {"is_disabled": True}}
        if reply_to and str(reply_to).isdigit():
            p["reply_parameters"] = {"message_id": int(reply_to), "allow_sending_without_reply": True}
        res = self.call("sendMessage", p)
        return str((res or {}).get("message_id") or "") or None

    def edit(self, chat_id, message_id, text, markup=None):
        p = {"chat_id": _cid(chat_id), "message_id": int(message_id), "text": text[:LIMIT],
             "link_preview_options": {"is_disabled": True}}
        if markup is not None:
            p["reply_markup"] = markup
        try:
            self.call("editMessageText", p)
        except NetError as e:
            if "not modified" in str(e):   # the same text again: Telegram says so, and that is fine
                return True
            raise
        return True

    def ask(self, chat_id, approval_id, text):
        p = {"chat_id": _cid(chat_id), "text": text[:LIMIT], "link_preview_options": {"is_disabled": True},
             "reply_markup": {"inline_keyboard": [[{"text": "Yes", "callback_data": f"gw:y:{approval_id}"},
                                                   {"text": "No", "callback_data": f"gw:n:{approval_id}"}]]}}
        res = self.call("sendMessage", p)
        return str((res or {}).get("message_id") or "") or None

    def settle(self, chat_id, message_id, text):
        if message_id:
            self.edit(chat_id, message_id, text, markup={"inline_keyboard": []})   # the buttons go away

    # ---- inbound

    def parse(self, msg):
        """An Inbound from a Telegram message, or None for one gnoc never answers (a bot, no sender)."""
        frm, chat = msg.get("from") or {}, msg.get("chat") or {}
        if frm.get("is_bot") or frm.get("id") is None or chat.get("id") is None:
            return None
        sender, chat_id = str(frm["id"]), str(chat["id"])
        inb = Inbound("telegram", chat_id, sender, message_id=str(msg.get("message_id") or ""),
                      private=(chat.get("type") == "private" and chat_id == sender))
        body = msg.get("text") or msg.get("caption") or ""
        if any(k in msg for k in _FORWARD):
            # someone else's message, passed on: data, however trusted the person who forwarded it
            inb.untrusted.append(("forwarded message", body))
        else:
            inb.text = body
        rep = msg.get("reply_to_message") or {}
        if rep.get("text") or rep.get("caption"):
            inb.untrusted.append(("message this replies to", rep.get("text") or rep.get("caption")))
        ext = msg.get("external_reply") or {}
        if isinstance(ext, dict) and (ext.get("text") or ext.get("caption")):
            inb.untrusted.append(("message this replies to", ext.get("text") or ext.get("caption")))
        q = msg.get("quote") or {}
        if isinstance(q, dict) and q.get("text"):
            inb.untrusted.append(("quoted part", q["text"]))
        for kind in _ATTACHED:
            if kind in msg:
                inb.notes.append(f"a {kind} was attached; gnoc does not open attachments sent over the gateway")
        return inb

    def on_update(self, u, gw):
        if "message" in u:
            msg = u["message"]
            date = msg.get("date")
            if isinstance(date, (int, float)) and self.max_age and date < self.started - self.max_age:
                # queued while the gateway was down: running "delete the build dir" hours after it was sent,
                # with nobody watching, is not what the sender meant. Logged, not run.
                self.log(f"telegram: skipped a message from {int(self.started - date)}s before start")
                return
            inb = self.parse(msg)
            if inb is not None:
                gw.handle(inb)
        elif "callback_query" in u:
            cq = u["callback_query"]
            frm = cq.get("from") or {}
            chat = (cq.get("message") or {}).get("chat") or {}
            m = _CB.fullmatch(str(cq.get("data") or ""))
            ok = False
            if m and frm.get("id") is not None and chat.get("id") is not None:
                private = chat.get("type") == "private" and str(chat["id"]) == str(frm["id"])
                ok = gw.answer("telegram", str(chat["id"]), str(frm["id"]), m.group(2), m.group(1) == "y", private)
            if not ok:
                self.log(f"telegram: ignored a button press from {frm.get('id')}")
            try:   # always answered, so the button stops spinning; an ignored press gets no text at all
                self.call("answerCallbackQuery", {"callback_query_id": str(cq.get("id") or ""),
                                                  **({"text": "recorded"} if ok else {})}, timeout=15)
            except NetError:
                pass

    def poll_once(self, gw):
        params = {"timeout": self.poll_timeout, "allowed_updates": ["message", "callback_query"]}
        if self.offset is not None:
            params["offset"] = self.offset
        # the socket waits a little longer than the server-side long poll, so a quiet chat is not a timeout
        updates = self.call("getUpdates", params, timeout=self.poll_timeout + 10) or []
        for u in updates:
            uid = u.get("update_id")
            if isinstance(uid, int):
                # advance first: an update that breaks the handler must not be delivered again forever
                self.offset = max(self.offset or 0, uid + 1)
            try:
                self.on_update(u, gw)
            except Exception as e:  # noqa: BLE001
                self.log(f"telegram: an update failed: {type(e).__name__}")
        return len(updates)

    def run(self, gw, stop):
        backoff = 1.0
        while not stop.is_set():
            try:
                self.poll_once(gw)
                backoff = 1.0
            except NetError as e:
                wait = float(e.retry_after or backoff)
                self.log(f"telegram: {e}; retrying in {wait:.0f}s")
                stop.wait(wait)
                backoff = min(backoff * 2, 60.0)


def from_conf(conf, log=None):
    """(adapter, allowlist, problems) from secrets.env / the environment."""
    from .core import Allowlist
    from .config import ids
    token = conf("TELEGRAM_BOT_TOKEN") or ""
    owners = ids(conf("GNOC_TELEGRAM_OWNERS"), r"\d+")
    chats = ids(conf("GNOC_TELEGRAM_CHATS"), r"-?\d+")
    problems = []
    if not token:
        problems.append("TELEGRAM_BOT_TOKEN is not set")
    if not owners:
        problems.append("GNOC_TELEGRAM_OWNERS is empty: gnoc would answer nobody (your numeric Telegram user id)")
    if problems:
        return None, None, problems
    try:
        ad = Telegram(token, base=conf("GNOC_TELEGRAM_API") or "https://api.telegram.org", log=log)
    except ValueError as e:
        return None, None, [str(e)]
    return ad, Allowlist(owners, chats), []
