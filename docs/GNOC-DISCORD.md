# gnoc discord — the hunt workspace, queryable from a Discord channel

`scripts/gnoc_discord.py`. A read-only bot so the team can ask the workspace things from chat
instead of over your shoulder. Run it with `gnoc discord`; `gnoc discord --check` verifies the
setup and self-tests the redaction; `gnoc discord --once <query>` renders one answer locally,
exactly as a channel would receive it.

## What the team types

| in Discord | what it runs |
| --- | --- |
| `!hunt` or `!hunt status` | `gnoc` (the status screen) |
| `!hunt needs` | `gnoc needs` |
| `!hunt reports` | `gnoc reports` |
| `!hunt lanes` / `outcomes` / `handoff` | the matching read-only section |
| `!hunt line` / `company` / `econ` / `oracle` | `… status` (`oracle classes`) |
| `!hunt gpus` | `gnoc gpus` |
| `!ask <question>` | one turn of the real `gnoc chat` agent |
| `!hunt help` | the list above |

A message that does not begin `!hunt` or `!ask` is ignored and never logged.

## Setup

Three values in `~/.config/gnoc/secrets.env` (read through `gnoc_comms.conf`, which keeps them
out of every model prompt):

```
DISCORD_BOT_TOKEN=...          # the bot token
GNOC_DISCORD_USERS=1234,5678   # REQUIRED: Discord USER IDS that may use it
GNOC_DISCORD_CHANNELS=9999     # optional: restrict to these channel ids
```

In the Discord developer portal the application needs the **message content** privileged intent,
and the bot needs `View Channel`, `Send Messages` and `Read Message History` in the channel. The
bot dials out to Discord's gateway, so there is no inbound port and no tunnel — nothing for Mullvad
to break the way it breaks cloudflared.

Run it under pm2 alongside the control panel:

```
pm2 start /usr/bin/python3 --name gnoc-discord -- ~/.gnoc/scripts/gnoc_discord.py
pm2 save
```

It refuses to start without a token and at least one allowlisted user id, so a misconfigured bot is
a dead process rather than an open one.

## The three things that keep it safe

Each is a promise in the module docstring and a section of
`python3 scripts/test_gnoc_discord.py`. Run that before leaving the bot up.

**1. It cannot hunt.** GreyNOC's rule of 2026-11-02 is that hunting lives inside a live `gnoc chat`
session and dies with it; orch-bot and oss-bot were retired to end unattended hunting. A chat bot
that could start a hunt would be that hunter again under a worse trigger — anyone typing in a
channel, with nobody watching. So the bot never calls `gnoc_session.open_session()`. It holds no
session file, so `hunting_allowed()` can never be true *because of it*, and every automated probe
engine (`opencode-lane.sh`, `auto-hunt.py`, `auto-target --pick`) refuses behind it. The agent is
also built `interactive=False`, which is what makes every approval-gated action refuse — the same
mechanism `gnoc_train.py` relies on — and it runs against an **isolated** session, history and
goal, because a standing `/goal` of yours ("hunt meta until RCE", the 2026-10-22 bug) otherwise
steers an innocent question into live probes.

**2. It cannot write, and it cannot compose a command.** `COMMANDS` is a table of exact argv
vectors. A word typed in Discord *selects a row*; it never becomes part of a command line, so
there is no quoting or injection surface. Everything that writes, submits, starts, kills, pauses or
sends is simply absent — including `lane` (`do_lane` can start one), `submit`, `approve`, `gate`,
`start`, `stop`, `pivot`, `orch` and `chat`. The test asserts each absence by name.

**3. It cannot name a client.** The workspace holds unresolved findings against named programs, and
H1/Bugcrowd terms generally bar sharing those with a third party before a fix — Discord stores
channel content, every member can read it, and it stays searchable. So every byte out goes through
the dashboard's demo `Scrubber` (`gnoc-dashboard.py`), the same substitution `gnoc dash --demo`
uses for shareable screenshots: stable fake program names, hosts, report slugs, lane names, URLs,
e-mails, IPs and anything secret-shaped.

It is **tightened** here, because a channel is permanent and multi-reader where a screenshot is one
frame. The dashboard builds its deny set by splitting a program directory on `[-_.]`, so a
one-word directory like `program-55` contributes only `program-55` and the brand `Acme` survives in
prose. `harden_scrubber()` adds the alphabetic runs of every **program** name and their prefixes
(+125 tokens, measured), which catches that. It deliberately does **not** do the same for hunt
slugs: a slug is a description (`merchant-account-takeover`), and denying its words scrubs ordinary
English out of every answer — measured, and the test pins both halves ("a brand that is only a
prefix is caught" **and** "ordinary English survives").

Over-scrubbing is the safe failure, and you will see it: a script filename or a column header
sometimes becomes a codename. That is the right direction. It is a strong filter, **not a proof** —
read `--check`'s self-test, which re-derives the real `gnoc needs` output and reports any program
directory name it can still find in the scrubbed text, before you trust a channel with this.

`GNOC_DISCORD_NO_SCRUB=1` sends real names. It is refused unless a user allowlist is set, it is
announced in `--check` and in the start-up log, and it is for a private single-operator server
only.

## Two more properties worth knowing

- **It cannot choose a recipient.** `gnoc_comms.py`'s rule is that the model may only draft and you
  type `/send`. A bot that answers in a channel is an autonomous send, so it gets its own narrow
  path rather than a loosening of that one: the destination is always the `channel_id` of the
  message that triggered it, read from the Discord event and never from model output. No text the
  model produces can address a message anywhere, and it never posts unprompted or cross-posts.
- **One question at a time.** The agent is one conversation with one history, so two overlapping
  turns would interleave. A second `!ask` while one is running is told to wait rather than queued,
  so nobody's answer arrives twenty minutes late against a context they have forgotten.

## If you later want it to drive hunts

Don't widen `COMMANDS`. The gate is the thing: a Discord-triggered hunt needs a live `gnoc chat`
session to belong to, or it is the unattended hunter again. The honest shape is for the bot to
*refuse* and say which operator's open session it would need — not to call `open_session()` itself,
which would make a chat channel the owner of a hunt that outlives everyone's attention.

## Owners: the full agent, through the gateway core (2026-11-26)

`GNOC_DISCORD_OWNERS` (Discord user ids) gives those people the full `gnoc chat` agent, built on the same core as
`gnoc gateway` (`scripts/gnoc_gateway/`, see `docs/GNOC-GATEWAY.md`). An owner talks to it in a DM with the bot (any
line) or in a `GNOC_DISCORD_CHANNELS` channel with `!gnoc <text>`; it is never offered in "any channel the bot can
see". Actions that need approval ask in that channel, and only an owner's `yes <id>` counts; no answer within
`GNOC_GATEWAY_APPROVAL_TIMEOUT` seconds (300) is no. Slash commands (`/file`, `/send`, ...) are refused. Replies to
owners get the gateway's secret redaction and then this bot's name scrubbing; if the scrubber cannot load, nothing
is sent. Owner turns and members' `!ask` share one lock, so they never overlap.

Nothing changes for anyone else: a member who is not an owner, and every `!hunt` / `!ask` (owners' included), take
the read-only path above exactly as before. The full agent still never opens a hunt session.
