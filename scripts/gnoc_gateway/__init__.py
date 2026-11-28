"""gnoc_gateway - drive gnoc chat from a messenger (Telegram, Slack, Signal, email; Discord through gnoc_discord).

The core (core.py) makes every safety decision once, for every adapter: who may talk to gnoc (stable sender and
chat ids, never a display name), where a reply goes (always the chat the message came from, bound from the
inbound event, never from model output), what leaves the machine (secret redaction that fails closed), which
approvals count (the allowlisted owner of that chat, answering that request id, before the timeout), and which
local commands stay local (every typed-only slash command). Adapters are transports and nothing else.
"""
from .core import (  # noqa: F401
    Adapter, Allowlist, ApprovalBroker, Gateway, Inbound, RedactionError, Redactor, split_text,
)
