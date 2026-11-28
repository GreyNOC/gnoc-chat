"""Discord on the gateway core, for OWNERS only (gnoc_discord.py hosts it beside its read-only bot).

gnoc_discord.py keeps its read-only `!hunt` / `!ask` behaviour for every allowlisted member exactly as it was.
An owner (GNOC_DISCORD_OWNERS, Discord user ids) additionally gets the full agent through this core: in a DM
with the bot any line, in an allowlisted channel a line starting `!gnoc `, plus `yes <id>` / `no <id>` to answer
an approval. The full agent is never offered in "any channel the bot can see": only DMs and GNOC_DISCORD_CHANNELS.
Replies go to the channel id of the triggering event, never one named by the model; mentions are disabled on
every post so an answer cannot ping @everyone.
"""
import re

from .core import _ANSWER, Adapter, Inbound

LIMIT = 2000
PREFIX = "!gnoc"


class Discord(Adapter):
    name = "discord"
    max_len = LIMIT
    can_edit = True
    buttons = False

    def __init__(self, rest):
        self.rest = rest          # (method, path, body) -> decoded JSON; gnoc_comms._discord in the real bot

    def send(self, chat_id, text, reply_to=None):
        body = {"content": text[:LIMIT], "allowed_mentions": {"parse": []}}
        if reply_to:
            body["message_reference"] = {"message_id": str(reply_to), "fail_if_not_exists": False}
        got = self.rest("POST", f"/channels/{_snow(chat_id)}/messages", body) or {}
        return str(got.get("id") or "") or None

    def edit(self, chat_id, message_id, text):
        self.rest("PATCH", f"/channels/{_snow(chat_id)}/messages/{_snow(message_id)}",
                  {"content": text[:LIMIT], "allowed_mentions": {"parse": []}})
        return True


def _snow(v):
    s = str(v)
    if not re.fullmatch(r"\d{1,25}", s):   # a path segment built from anything else could walk the REST API
        raise ValueError("not a Discord id")
    return s


def parse(d, me=None):
    """An Inbound for a message addressed to the full agent, or None (the read-only bot then decides)."""
    author = d.get("author") or {}
    if author.get("bot") or not author.get("id") or (me and author.get("id") == me):
        return None
    content = str(d.get("content") or "")
    low = content.strip().lower()
    if low.startswith(("!hunt", "!ask")):
        return None                                   # the read-only commands keep their own path, for everyone
    private = not d.get("guild_id")                   # a DM has no guild
    if low.startswith(PREFIX + " ") or low == PREFIX:
        text = content.strip()[len(PREFIX):].strip()
    elif private or _ANSWER.match(content.strip()):
        text = content.strip()
    else:
        return None
    inb = Inbound("discord", str(d.get("channel_id") or ""), str(author["id"]), text=text,
                  message_id=str(d.get("id") or ""), private=private)
    ref = d.get("referenced_message") or {}
    if isinstance(ref, dict) and ref.get("content"):
        inb.untrusted.append(("message this replies to", ref["content"]))
    if d.get("attachments"):
        inb.notes.append("an attachment was sent; gnoc does not open attachments sent over the gateway")
    return inb
