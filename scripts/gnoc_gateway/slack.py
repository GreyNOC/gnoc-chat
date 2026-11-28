"""Slack: Socket Mode (an outbound WebSocket, so no public URL) for events, the Web API for replies.

Two tokens: the app-level token (xapp-, scope connections:write) opens the socket; the bot token (xoxb-, scopes
chat:write, im:history, channels:history) posts. Identity is the Slack user id (U.../W...), never a display name.
In a direct message every line is for gnoc; in an allowlisted channel only a line that mentions the bot is,
so gnoc does not answer every remark the owner makes in a shared channel. Approvals are Block Kit buttons; a
press counts only from an owner in the channel the question was asked in. Every envelope is acknowledged first,
as Socket Mode requires, so Slack does not redeliver it.
"""
import json
import re

from .core import Adapter, Inbound
from .net import NetError, check_base, post_json
from .ws import WebSocket, WebSocketError

LIMIT = 3900          # Slack truncates a message's text well past this; 3900 keeps a chunk readable on a phone


class Slack(Adapter):
    name = "slack"
    max_len = LIMIT
    can_edit = True
    buttons = True

    def __init__(self, app_token, bot_token, api="https://slack.com/api", log=None, connect=WebSocket.connect,
                 idle=10.0):
        if not app_token or not bot_token:
            raise ValueError("SLACK_APP_TOKEN and SLACK_BOT_TOKEN are both needed")
        self.app_token, self.bot_token = app_token, bot_token
        self.api = check_base(api, "GNOC_SLACK_API")
        self.log = log or (lambda *a: None)
        self.connect = connect
        self.idle = idle
        self.bot_user = None

    def call(self, method, body, token=None, timeout=30.0):
        got = post_json(f"{self.api}/{method}", body, timeout=timeout,
                        headers={"Authorization": f"Bearer {token or self.bot_token}"})
        if not got.get("ok"):
            raise NetError(f"slack {method}: {str(got.get('error') or 'error')[:120]}")
        return got

    # ---- outbound

    def send(self, chat_id, text, reply_to=None):
        got = self.call("chat.postMessage", {"channel": str(chat_id), "text": text[:LIMIT], "unfurl_links": False,
                                             "unfurl_media": False})
        return got.get("ts")

    def edit(self, chat_id, message_id, text, blocks=None):
        body = {"channel": str(chat_id), "ts": str(message_id), "text": text[:LIMIT]}
        if blocks is not None:
            body["blocks"] = blocks
        self.call("chat.update", body)
        return True

    def ask(self, chat_id, approval_id, text):
        blocks = [{"type": "section", "text": {"type": "plain_text", "text": text[:2900]}},
                  {"type": "actions", "elements": [
                      {"type": "button", "action_id": "gw_yes", "value": approval_id, "style": "primary",
                       "text": {"type": "plain_text", "text": "Yes"}},
                      {"type": "button", "action_id": "gw_no", "value": approval_id, "style": "danger",
                       "text": {"type": "plain_text", "text": "No"}}]}]
        got = self.call("chat.postMessage", {"channel": str(chat_id), "text": text[:LIMIT], "blocks": blocks})
        return got.get("ts")

    def settle(self, chat_id, message_id, text):
        if message_id:
            self.edit(chat_id, message_id, text, blocks=[])   # the buttons go away

    # ---- inbound

    def parse(self, ev):
        """An Inbound from a message event, or None for one gnoc does not answer."""
        if ev.get("type") != "message" or ev.get("subtype") or ev.get("bot_id") or not ev.get("user"):
            return None          # edits, joins, bot posts (its own replies included) are not prompts
        chat, user = str(ev.get("channel") or ""), str(ev["user"])
        private = ev.get("channel_type") == "im"
        text = str(ev.get("text") or "")
        if not private:
            tag = f"<@{self.bot_user}>" if self.bot_user else None
            if not tag or tag not in text:
                return None
            text = text.replace(tag, " ").strip()
        inb = Inbound("slack", chat, user, text=text, message_id=str(ev.get("ts") or ""), private=private)
        for att in ev.get("attachments") or []:
            if isinstance(att, dict) and (att.get("text") or att.get("fallback")):
                # a shared (forwarded) message or an unfurl: someone else's words
                inb.untrusted.append(("shared message", att.get("text") or att.get("fallback")))
        if ev.get("files"):
            inb.notes.append("a file was attached; gnoc does not open attachments sent over the gateway")
        return inb

    def on_envelope(self, env, gw, ws):
        """Returns "reconnect" when Slack asks for a new socket."""
        if env.get("envelope_id"):
            ws.send_text(json.dumps({"envelope_id": env["envelope_id"]}))   # ack first, or Slack redelivers
        kind = env.get("type")
        if kind == "disconnect":
            return "reconnect"
        payload = env.get("payload") or {}
        if kind == "events_api":
            inb = self.parse(payload.get("event") or {})
            if inb is not None:
                gw.handle(inb)
        elif kind == "interactive" and payload.get("type") == "block_actions":
            user = str((payload.get("user") or {}).get("id") or "")
            chat = str((payload.get("channel") or {}).get("id") or (payload.get("container") or {}).get("channel_id")
                       or "")
            for act in payload.get("actions") or []:
                aid, pid = act.get("action_id"), str(act.get("value") or "")
                if aid in ("gw_yes", "gw_no") and re.fullmatch(r"[0-9a-f]{8}", pid) and user and chat:
                    if not gw.answer("slack", chat, user, pid, aid == "gw_yes", private=chat.startswith("D")):
                        self.log(f"slack: ignored a button press from {user}")
        return None

    def run(self, gw, stop):
        backoff = 1.0
        while not stop.is_set():
            ws = None
            try:
                if self.bot_user is None:
                    self.bot_user = self.call("auth.test", {}).get("user_id")
                url = self.call("apps.connections.open", {}, token=self.app_token).get("url") or ""
                ws = self.connect(url, timeout=30.0)
                backoff = 1.0
                while not stop.is_set():
                    try:
                        msg = ws.recv(timeout=self.idle)
                    except TimeoutError:
                        continue
                    if msg is None:
                        break
                    try:
                        env = json.loads(msg)
                    except ValueError:
                        continue
                    if isinstance(env, dict) and self.on_envelope(env, gw, ws) == "reconnect":
                        break
            except (NetError, WebSocketError, OSError) as e:
                self.log(f"slack: {type(e).__name__}: {str(e)[:120]}; retrying in {backoff:.0f}s")
                stop.wait(backoff)
                backoff = min(backoff * 2, 60.0)
            finally:
                if ws is not None:
                    ws.close()


def from_conf(conf, log=None):
    from .config import ids
    from .core import Allowlist
    app, bot = conf("SLACK_APP_TOKEN") or "", conf("SLACK_BOT_TOKEN") or ""
    owners = ids(conf("GNOC_SLACK_OWNERS"), r"[UW][A-Z0-9]{2,}")
    chans = ids(conf("GNOC_SLACK_CHANNELS"), r"[CGD][A-Z0-9]{2,}")
    problems = []
    if not app.startswith("xapp-"):
        problems.append("SLACK_APP_TOKEN must be the app-level token (xapp-..., scope connections:write)")
    if not bot.startswith("xoxb-"):
        problems.append("SLACK_BOT_TOKEN must be the bot token (xoxb-...)")
    if not owners:
        problems.append("GNOC_SLACK_OWNERS is empty: gnoc would answer nobody (Slack user ids, U...)")
    if problems:
        return None, None, problems
    try:
        ad = Slack(app, bot, api=conf("GNOC_SLACK_API") or "https://slack.com/api", log=log)
    except ValueError as e:
        return None, None, [str(e)]
    return ad, Allowlist(owners, chans), []
