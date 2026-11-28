# Phase 5: messaging gateway

- One stdlib core (`scripts/gnoc_gateway/core.py`) owns every safety decision: an allowlist keyed on stable
  sender and chat ids, the reply target bound from the inbound event, redaction (secrets + the adapter's own
  tokens + an optional extra scrubber, failing closed), typed-only slash commands refused, quoted/forwarded text
  fenced as untrusted, one turn at a time, and the approval broker.
- Approvals: the agent's own approval engine gains an optional `approver` taken from the session's ctx
  (`ctx.remote_approver`). For a gateway session it becomes a yes/no in the origin chat; only the allowlisted
  owner of that chat answering that request id counts; anything else, and a timeout, is no. It never answers
  "auto", and every hard refusal still runs before it.
- Adapters in the brief's order, each a thin transport over the core: Telegram (Bot API long polling, inline
  keyboard), Slack (Socket Mode over a minimal RFC 6455 client), Signal (signal-cli JSON-RPC over TCP), email
  (IMAP poll + SMTP reply, DMARC/DKIM result required). Discord moves onto the core: non-owners keep the
  read-only bot exactly; allowlisted owners get the full agent.
- `gnoc gateway run|install|status|check`: `install` writes a systemd user unit, or on Termux a
  `~/.termux/boot/` script; it never enables or starts anything.
- Tests in `scripts/test_gnoc_phase5_gateway.py` against in-process fakes only (fake Bot API http.server, fake
  WebSocket server, fake signal-cli socket, fake IMAP/SMTP objects).

## What was built

- `scripts/gnoc_gateway/core.py`: `Inbound`, `Allowlist`, `Redactor`, `ApprovalBroker`, `Gateway`, `split_text`.
  Unknown senders get no reply; replies go only to `inbound.chat_id`; outbound text (answers, progress, prompts,
  errors) is redacted whole before splitting and withheld if redaction fails; slash commands other than
  `/help /start /new /stop` are refused; quoted/forwarded/caption text is fenced with `gnoc_comms.untrusted`; one
  turn at a time; `/stop` interrupts and denies open questions.
- Engine wiring (three short hunks): `approval._approve(..., approver=None)` and `_remote_answer` (only exactly
  `True` is `y`, never `a`); `dispatch._plan_call` passes `ctx.remote_approver`, reports a remote no as the user's
  no, and refuses tools in `ctx.remote_denied`; `rails._live_tools` hides them. All inert without those attributes.
- `runner.py`: the real agent per (adapter, chat, sender) in `~/.gnoc/gateway/agent`, skip-perms forced off and
  re-checked each turn, auto forced off, `draft_outgoing` removed, owner's words as `_typed`, untrusted parts taint
  the turn.
- Adapters: Telegram (long polling, socket timeout above the poll timeout, offset advanced before handling,
  4096-char chunks, throttled `editMessageText` streaming, inline buttons with `callback_query.from.id` checked,
  stale backlog skipped); Slack Socket Mode on a new stdlib RFC 6455 client (`ws.py`: verified handshake, TLS,
  masking, ping/pong, fragments, close, size caps, idle timeout) with Block Kit buttons and acks; Signal via
  signal-cli JSON-RPC over loopback TCP; email via IMAP/SMTP requiring the provider's DMARC/DKIM verdict.
- Discord: `gnoc_discord.py` routes `GNOC_DISCORD_OWNERS` to the core (DMs, or `!gnoc` in allowlisted channels);
  everyone else and every `!hunt` / `!ask` keep the read-only path unchanged; owner replies get the core's
  redaction plus the bot's scrubber, failing closed.
- `gnoc gateway check|run|install|status` (public command); `install` writes a systemd user unit or a Termux:Boot
  script and never starts it.
- Tests: `scripts/test_gnoc_phase5_gateway.py`, 93 tests against in-process fakes (Bot API http.server, WebSocket
  server, Slack Web API, signal-cli socket, IMAP/SMTP objects) and the real agent through dispatch.

## Security impact

A new remote surface that reaches the full agent. It goes through every existing gate: approvals (now answerable
from the origin chat by an allowlisted owner only, never as auto), redaction, injection fencing and taint, typed-only
slash commands, and the recipient rule (no destination parameter; `draft_outgoing` removed; `/send` refused).
Hard refusals still run before any question. Residual risks: a compromised messenger account of the owner is the
owner; email is only as strong as the provider's DMARC/DKIM checks; everything shown to the owner (redacted) is
stored by the messenger's servers.

## Rollback

Revert the feature commits, or operationally: do not set any gateway token (every adapter is off by default) and
unset `GNOC_DISCORD_OWNERS`. The engine hunks are inert when no ctx carries `remote_approver` / `remote_denied`.

## What is left

- Conversations are in memory only (a restart starts fresh); no resume of a gateway session.
- `gnoc gateway run` does not host Discord (it stays in the operator-edition `gnoc discord`, which still uses the
  `websockets` package for its connection; the stdlib `ws.py` could replace it later).
- Discord approvals are text replies, not buttons (buttons need the interactions endpoint).
- Slack, Signal and email were tested only against in-process fakes of their protocols, not the live services.

## Release note

gnoc can now be driven from a phone. `gnoc gateway` connects gnoc chat to Telegram, Slack, Signal or email: only
the account ids you list are answered, replies go only to the chat a message came from, anything that needs your
approval is asked in that same chat as a yes/no that only you can answer (no answer in five minutes means no), and
everything sent is redacted. `gnoc gateway install` writes a systemd user service or a Termux:Boot script for you
to switch on. On Discord, owners named in `GNOC_DISCORD_OWNERS` get the full agent under the same rules, while the
read-only bot is unchanged for everyone else. Development: GreyNOC (Brad), with Claude (Anthropic) as a development
contributor.
