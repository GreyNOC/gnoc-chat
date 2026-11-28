# gnoc gateway: driving gnoc chat from a messenger

`scripts/gnoc_gateway/`. One core and thin adapters. Run it with `gnoc gateway run`, check the setup with
`gnoc gateway check`, write a service file with `gnoc gateway install`.

## Layout

| file | what it is |
| --- | --- |
| `core.py` | every safety decision: allowlist, reply target, redaction, approvals, slash commands, untrusted text |
| `runner.py` | the real agent behind it: one `Agent` per (messenger, chat, sender), approvals bound to that chat |
| `telegram.py` | Bot API long polling (`getUpdates`), inline Yes/No buttons |
| `ws.py` | a minimal RFC 6455 WebSocket client on the standard library |
| `slack.py` | Socket Mode for events, the Web API for replies, Block Kit buttons |
| `signal_cli.py` | JSON-RPC to a local `signal-cli daemon --tcp` |
| `email_imap.py` | IMAP poll, SMTP reply, DMARC/DKIM required |
| `discord_gw.py` | the owners' path inside `gnoc discord` (operator edition) |
| `service.py`, `cli.py` | `gnoc gateway run / check / install / status` |

## The rules the core enforces

**Who.** Each adapter has an `Allowlist` of stable ids: Telegram numeric user ids, Slack `U...` ids, Signal UUIDs
or numbers, email addresses (plus the mail server's verdict, below). A 1:1 chat counts only when it is with that
very sender; a group or channel needs its own id listed too. Ids that do not look like ids are dropped when the
settings are read, so `@name` typed by mistake allows nobody. A sender who is not listed gets no reply at all.

**Where.** A reply goes to `inbound.chat_id`, taken from the messenger's event. The runner returns text only; it has
no parameter for a destination, and the one agent tool whose argument is a recipient (`draft_outgoing`) is removed
from gateway sessions (refused in dispatch and hidden from the model's tool list). `/send` is a slash command, so it
is refused like the others.

**What leaves.** Answers, streamed progress, approval prompts and errors all go through one `Redactor`: the
`gnoc_secrets` store, then every adapter token from `secrets.env` and its URL/JSON-encoded forms, then an optional
extra scrubber (the Discord bot's name substitution). The whole text is redacted before it is split into messages,
so a secret cut across two messages is still caught. If any stage raises, the message is replaced by a fixed
notice and nothing else is sent.

**Approvals.** The agent's approval engine (`gnoc_core/approval.py` `_approve`) takes an optional `approver`, which
dispatch reads from `ctx.remote_approver`. For a gateway turn it is the broker: a prompt in the origin chat with a
random 8-hex request id, then a wait. Only an allowlisted owner, in that chat, answering that id, before the timeout,
counts; the first answer wins. The approver's answer becomes `y` only when it is exactly `True`; it is never `a`
(auto), so one yes is one action. Everything the engine refuses before asking (deny rules, hard-blocked commands such
as `git push` through bash) is still refused after a yes. A no is reported to the model as the user's no.

**What stays local.** Every slash command except `/help`, `/start`, `/new` and `/stop` is refused before the agent
sees the message: `/file`, `/send`, `/skills trust`, `/auto`, `/approve` and the rest act on a line typed at gnoc's
own keyboard. A zero-width character in front of the slash does not get one past.

**What is data.** Forwarded messages, the message being replied to, quotes and quoted mail reach the model inside
`gnoc_comms.untrusted` fences (with its injection and invisible-character scan), the turn is marked tainted (acting
tools ask first), and text copied out of them into a tool argument asks every time. Attachments are not opened; the
model is told one was sent.

**One turn at a time.** The agent's state is process-wide, so the core runs one turn at a time across all chats.
A second message gets "still working", or a reminder of the open approval.

## Per messenger

- **Telegram**: `TELEGRAM_BOT_TOKEN`, `GNOC_TELEGRAM_OWNERS`, optional `GNOC_TELEGRAM_CHATS` (group ids, negative).
  A message queued more than ten minutes before the gateway started is skipped, not run late. Link previews are off.
- **Slack**: an app with Socket Mode on; `SLACK_APP_TOKEN` (xapp-, `connections:write`), `SLACK_BOT_TOKEN` (xoxb-,
  `chat:write`, `im:history`, `channels:history`), `GNOC_SLACK_OWNERS`, optional `GNOC_SLACK_CHANNELS`. In a channel
  only a message that mentions the bot is a prompt. Every envelope is acknowledged before it is handled.
- **Signal**: `signal-cli -a +NUMBER daemon --tcp 127.0.0.1:7583`; `GNOC_SIGNAL_ACCOUNT`, `GNOC_SIGNAL_OWNERS`,
  optional `GNOC_SIGNAL_GROUPS`, `GNOC_SIGNAL_RPC`. That socket has no authentication, so a non-loopback address is
  refused.
- **Email**: `GNOC_EMAIL_USER`, `GNOC_EMAIL_PASS`, `GNOC_EMAIL_IMAP_HOST`, `GNOC_EMAIL_SMTP_HOST` (`host:port`; 587
  means STARTTLS), `GNOC_EMAIL_OWNERS`, `GNOC_EMAIL_AUTHSERV`. A message counts only when the first
  `Authentication-Results` header from that server shows `dmarc=pass` for the From domain or `dkim=pass` signed by
  it. The reply goes to the From address, never to Reply-To. This is as strong as your provider's checks: use an
  address at a domain that publishes DMARC.
- **Discord** (operator edition, `gnoc discord`): `GNOC_DISCORD_OWNERS` get the full agent in DMs and in
  `GNOC_DISCORD_CHANNELS` (with `!gnoc `). Everyone else, and `!hunt` / `!ask`, keep the read-only bot unchanged.

## Service

`gnoc gateway install` writes `~/.config/systemd/user/gnoc-gateway.service` (or, when `TERMUX_VERSION` is set,
`~/.termux/boot/gnoc-gateway` with a wake lock) and prints the command that enables it. It never runs `systemctl`
itself, and it will not replace a file it did not write unless given `--force`. No token is written into either file.

## Limits

- The conversation per chat lives in memory: a restart starts fresh conversations.
- Progress is the tail of what `gnoc chat` would print, redacted, edited into one message at most every two seconds.
- Discord is not hosted by `gnoc gateway run`; it stays inside `gnoc discord`, which needs the operator workspace.
- Approval timeouts are wall-clock; a phone that is asleep for five minutes means no.

## Rollback

Delete `scripts/gnoc_gateway/`, the `gateway` entry in `scripts/gnoc`, and revert the three short hunks in
`gnoc_core/approval.py`, `gnoc_core/dispatch.py` and `gnoc_core/rails.py` (each is inert when no ctx carries a
`remote_approver` or `remote_denied`). For Discord, unset `GNOC_DISCORD_OWNERS`: the bot is read-only again.
