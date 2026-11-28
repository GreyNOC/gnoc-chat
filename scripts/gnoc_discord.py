#!/usr/bin/env python3
"""gnoc_discord.py - a READ-ONLY Discord bot for the hunt workspace, so the team can query it from chat.

    python3 scripts/gnoc_discord.py            run the bot (pm2 name: gnoc-discord)
    python3 scripts/gnoc_discord.py --check     config, allowlists and a scrub self-test, then exit
    python3 scripts/gnoc_discord.py --once "needs"   render one command locally, exactly as Discord would see it

In a channel (or a DM), an allowlisted member types:

    !hunt status | needs | reports | lanes | outcomes | handoff | line | company | econ | gpus | oracle
    !ask <question>      one turn of the real gnoc chat agent
    !hunt help

WHY IT CANNOT HUNT. The user's rule of 2026-11-02 is that hunting lives inside a live `gnoc chat`
session and stops when that session closes; orch-bot and oss-bot were retired to end unattended
hunting. This bot therefore never calls gnoc_session.open_session(), so `hunting_allowed()` stays
False for its whole life and every automated probe engine (opencode-lane.sh, auto-hunt.py,
auto-target --pick) refuses to start behind it. That is structural, not a convention: the bot holds
no session file, so there is nothing for it to prop open. It also builds its Agent with
interactive=False, which is what makes every approval-gated action refuse (same mechanism
scripts/gnoc_train.py relies on), and it runs that Agent against an ISOLATED session, history and
goal, because a standing /goal of the user's own ("hunt meta until RCE", 2026-10-22) otherwise
steers an innocent question into live probes.

WHY IT CANNOT CHOOSE A RECIPIENT. gnoc_comms.py's rule is that the model may only draft and
the user types /send. A bot that answers in a channel is an autonomous send, so it gets its own
narrow path rather than a loosening of that one: the destination is always the channel id of the
message that triggered it, read from the Discord event and never from model output, so no text the
model produces can address a message anywhere. It never posts unprompted, and never cross-posts.

WHAT LEAVES THE MACHINE IS SCRUBBED. The workspace holds unresolved findings against named
programs, and H1/Bugcrowd terms generally bar sharing those with third parties before a fix -
Discord stores channel content, every member can read it and it stays searchable. So every byte
this bot sends is put through the dashboard's demo Scrubber (scripts/gnoc-dashboard.py), the same
substitution `gnoc dash --demo` uses for shareable screenshots: stable fake program names, hosts,
report slugs, lane names, URLs, e-mails, IPs, and anything shaped like a secret. It is tightened
here (see harden_scrubber) because a channel is permanent and multi-reader, where a screenshot is
one frame: program names contribute their alphabetic sub-words to the deny set, so a brand that
appears in prose rather than as a directory name ("Acme Pay" against the program-55 program) is
caught too. Over-scrubbing is the safe failure. It is a strong filter, NOT a proof: read --check's
self-test before trusting a channel with this.

Secrets, in ~/.config/gnoc/secrets.env (read via gnoc_comms.conf, which keeps values out of
every model prompt):
    DISCORD_BOT_TOKEN        the bot token (already this file's channel in gnoc_comms)
    GNOC_DISCORD_USERS       REQUIRED. Comma-separated Discord user ids that may use the bot.
                             Empty or missing = the bot answers nobody. Ids, not usernames: a
                             username can be changed by its owner.
    GNOC_DISCORD_CHANNELS    optional. Comma-separated channel ids it will answer in; empty = any
                             channel it can see (the user allowlist still applies).
    GNOC_DISCORD_NO_SCRUB    optional. "1" sends real names. Refused unless GNOC_DISCORD_USERS is
                             set; it exists for a private single-operator server and is announced
                             in --check, never silent.
    GNOC_DISCORD_OWNERS      optional. Comma-separated Discord user ids that get the FULL agent through
                             the messaging gateway core (scripts/gnoc_gateway): in a DM with the bot any
                             line, in a GNOC_DISCORD_CHANNELS channel a line starting `!gnoc `. Actions
                             that need approval ask in the same channel; only an owner's `yes <id>`
                             counts, and no answer in GNOC_GATEWAY_APPROVAL_TIMEOUT seconds (300) is no.
                             Everyone else, owners' `!hunt` / `!ask` included, keeps the read-only bot
                             below exactly as it was. Answers to owners get the gateway's secret
                             redaction AND this file's name scrubbing; if the scrubber cannot load,
                             nothing is sent.
"""
import asyncio
import contextlib
import importlib.util
import io
import json
import os
import random
import re
import subprocess
import sys
import threading
import time

WS = os.environ.get("GNOC_WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))

import gnoc_comms  # noqa: E402  (conf() + the Discord REST helpers already live there)

GNOC = os.path.expanduser("~/.local/bin/gnoc")  # the real CLI; scripts/gnoc is an older partial copy
GATEWAY = "wss://gateway.discord.gg/?v=10&encoding=json"
# GUILDS | GUILD_MESSAGES | DIRECT_MESSAGES | MESSAGE_CONTENT
INTENTS = (1 << 0) | (1 << 9) | (1 << 12) | (1 << 15)
DISCORD_LIMIT = 2000
MAX_MESSAGES = 3           # a long answer is truncated rather than flooding a channel
CMD_TIMEOUT = 90           # seconds for a gnoc read-only command
ASK_TIMEOUT = 300          # seconds for one agent turn (a cold model on the desktop is slow)

# Read-only commands, as EXACT argv vectors. Not a prefix match and not user-composable: a word
# typed in Discord selects a row here, it never becomes part of a command line. Everything that
# writes, submits, starts, kills, pauses or sends is simply absent - including `lane` (do_lane can
# start one), `submit`, `approve`, `gate`, `start`, `stop`, `pivot`, `orch` and `chat`.
COMMANDS = {
    "status":   [],
    "needs":    ["needs"],
    "reports":  ["reports"],
    "lanes":    ["lanes"],
    "outcomes": ["outcomes"],
    "handoff":  ["handoff"],
    "line":     ["line", "status"],
    "company":  ["company", "status"],
    "econ":     ["econ", "status"],
    "oracle":   ["oracle", "classes"],
    "gpus":     ["gpus"],
}
HELP = ("**read-only hunt queries** - `!hunt " + " | ".join(sorted(COMMANDS)) + "`\n"
        "**ask the agent** - `!ask <question>` (one turn, no approvals, cannot hunt)\n"
        "Names are substituted for sharing; this bot cannot start, stop or submit anything.")


# ----------------------------------------------------------------- config

def _ids(name):
    raw = gnoc_comms.conf(name) or ""
    return {p.strip() for p in re.split(r"[,\s]+", raw) if p.strip().isdigit()}


class Conf:
    def __init__(self):
        self.token = gnoc_comms.conf("DISCORD_BOT_TOKEN")
        self.users = _ids("GNOC_DISCORD_USERS")
        self.channels = _ids("GNOC_DISCORD_CHANNELS")
        self.no_scrub = (gnoc_comms.conf("GNOC_DISCORD_NO_SCRUB") or "") == "1" and bool(self.users)
        self.owners = _ids("GNOC_DISCORD_OWNERS")   # the full agent, through gnoc_gateway; see the docstring

    def problems(self):
        out = []
        if not self.token:
            out.append("DISCORD_BOT_TOKEN is not set in ~/.config/gnoc/secrets.env")
        if not self.users:
            out.append("GNOC_DISCORD_USERS is empty: the bot would answer nobody. Add Discord user ids.")
        return out

    def may(self, user_id, channel_id):
        if str(user_id) not in self.users:
            return False
        return not self.channels or str(channel_id) in self.channels


# ----------------------------------------------------------------- scrubbing

def load_scrubber():
    """The dashboard's demo Scrubber, imported from its hyphenated filename."""
    path = os.path.join(WS, "scripts", "gnoc-dashboard.py")
    if not os.path.isfile(path):
        # fail closed with a reason: exec_module raised a bare FileNotFoundError, and nothing may be sent unscrubbed
        import gnoc_missing
        raise RuntimeError(gnoc_missing.note("the Discord bot's redaction", "scripts/gnoc-dashboard.py (its Scrubber)",
                                             "The bot refuses to send anything it cannot scrub."))
    spec = importlib.util.spec_from_file_location("gnoc_dashboard_for_discord", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return harden_scrubber(mod.Scrubber(ws=WS), mod)


def harden_scrubber(sc, mod):
    """Deny the alphabetic sub-words of every program name and in-scope host label too.

    The dashboard builds `deny` by splitting a program directory on [-_.], so a one-word directory
    like `program-55` contributes only `program-55` and the brand `Acme` survives in prose - fine
    for one screenshot, wrong for a channel that keeps everything. Splitting each name into its
    alphabetic runs of 4+ characters catches the brand as well. `deny` is checked before `safe` in
    _part_bad, so this also overrides a tech-vocabulary word that happens to be a program name.
    """
    extra = set()
    # programs only: a program directory is a BRAND, whereas a hunt slug is a description
    # ("merchant-account-takeover"), and denying its words scrubs ordinary English out of every
    # answer. The base scrubber already renames a slug it recognises, by exact match.
    for name in set(sc.programs):
        for run in re.findall(r"[a-z]{4,}", str(name).lower()):
            if run not in mod.GENERIC_PARTS:
                extra.add(run)
                # a brand is usually the head of the directory name: program-55 -> acme
                for cut in (run[:-3], run[:-4], run[:-5]):
                    if len(cut) >= 5 and cut not in mod.GENERIC_PARTS:
                        extra.add(cut)
    sc.deny.update(extra)
    sc._memo.clear()
    return sc


class Redactor:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self._sc = None
        self._lock = threading.Lock()

    @property
    def scrubber(self):
        with self._lock:
            if self._sc is None:
                self._sc = load_scrubber()
            return self._sc

    def __call__(self, text):
        if not self.enabled:
            return text
        return self.scrubber.text(text or "")


# ----------------------------------------------------------------- read-only gnoc commands

def run_command(key):
    argv = COMMANDS[key]
    env = dict(os.environ, GNOC_PLAIN="1", NO_COLOR="1", FORCE_COLOR="0", GNOC_FORCE_COLOR="0",
               GNOC_ASCII="1")
    try:
        p = subprocess.run([GNOC] + argv, cwd=WS, capture_output=True, text=True,
                           timeout=CMD_TIMEOUT, env=env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return f"`gnoc {' '.join(argv) or 'status'}` timed out after {CMD_TIMEOUT}s"
    except OSError as e:
        return f"could not run gnoc: {e}"
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr.strip() else "")
    return strip_ansi(out).strip() or "(no output)"


_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def strip_ansi(s):
    return _ANSI.sub("", s or "")


# ----------------------------------------------------------------- the agent, isolated and gateless

class Ask:
    """One gnoc chat agent, built so it cannot hunt and cannot approve anything.

    Serialised by a lock: the agent is one conversation with one history, and two overlapping turns
    would interleave into it. A second question while one is running is told to wait rather than
    queued, so nobody's answer arrives twenty minutes late against a context they have forgotten.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._agent = None
        self._G = None
        self._dir = None

    def _build(self):
        import tempfile
        import gnoc_agent as G
        import gnoc_goal
        d = tempfile.mkdtemp(prefix="gnoc-discord-")
        agent_dir = os.path.join(d, "agent")
        os.makedirs(agent_dir, exist_ok=True)
        for k, v in {"AGENT_DIR": agent_dir,
                     "SESSION": os.path.join(agent_dir, "session.json"),
                     "OUT_DIR": os.path.join(agent_dir, "out"),
                     "JOBS_DIR": os.path.join(agent_dir, "jobs"),
                     "SESSIONS_DIR": os.path.join(agent_dir, "sessions")}.items():
            setattr(G, k, v)
        gnoc_goal.PATH = os.path.join(agent_dir, "goal.json")
        # interactive=False is the gate: every action needing approval refuses. No open_session()
        # call anywhere here, so the hunt gate stays shut for this process's whole life.
        self._G, self._agent, self._dir = G, G.Agent(interactive=False), d

    def busy(self):
        return self._lock.locked()

    def turn(self, text):
        if not self._lock.acquire(blocking=False):
            return "busy: the agent is already answering someone. Try again in a moment."
        try:
            if self._agent is None:
                self._build()
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                answer = self._agent.turn(text)
            if not (answer or "").strip():
                answer = next((m.get("content") or "" for m in reversed(self._agent.s.get("history") or [])
                               if m.get("role") == "assistant" and (m.get("content") or "").strip()), "")
            return (answer or "").strip() or "the agent returned no answer"
        except Exception as e:  # noqa: BLE001 - a bad turn must not take the bot down
            return f"the agent failed: {type(e).__name__}: {e}"[:600]
        finally:
            self._lock.release()


# ----------------------------------------------------------------- formatting

def chunks(text, fence=True):
    """Discord messages, <= DISCORD_LIMIT each, split on line boundaries and in order."""
    text = (text or "").rstrip()
    if not text:
        return ["(no output)"]
    # reserve the fence (```\n ... \n```) and the full truncation note, which lands on the last message
    room = DISCORD_LIMIT - (8 if fence else 0) - 120
    blocks, buf, size = [], [], 0

    def flush():
        nonlocal buf, size
        if buf:
            blocks.append("\n".join(buf))
            buf, size = [], 0

    for line in text.split("\n"):
        while len(line) > room:          # one over-long line: a URL or a wide table row
            flush()                      # keep output in order
            blocks.append(line[:room])
            line = line[room:]
        if size + len(line) + 1 > room:
            flush()
        buf.append(line)
        size += len(line) + 1
    flush()
    msgs = [f"```\n{b}\n```" if fence else b for b in blocks[:MAX_MESSAGES]]
    if len(blocks) > MAX_MESSAGES:
        msgs[-1] += (f"\n_... truncated: {len(blocks) - MAX_MESSAGES} more block(s). "
                     f"Run it on the laptop for the rest._")
    return [m[:DISCORD_LIMIT] for m in msgs]


# ----------------------------------------------------------------- Discord REST (send) + gateway

def post(channel_id, text, reply_to=None):
    """Send one message. channel_id comes from the triggering event, never from model output."""
    body = {"content": text[:DISCORD_LIMIT], "allowed_mentions": {"parse": []}}
    if reply_to:
        body["message_reference"] = {"message_id": str(reply_to), "fail_if_not_exists": False}
    return gnoc_comms._discord("POST", f"/channels/{channel_id}/messages", body)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


class Bot:
    def __init__(self, conf):
        self.conf = conf
        self.redact = Redactor(enabled=not conf.no_scrub)
        self.ask = Ask()
        self.seq = None
        self.session_id = None
        self.resume_url = None
        self.me = None
        self._gw = None
        self._gw_lock = threading.Lock()

    # ---- owners: the full agent through the gateway core

    def gateway(self):
        """The gateway core for owners, built on first use. It shares Ask's lock: one agent turn at a time in
        this process, whether it is a member's read-only !ask or an owner's full turn."""
        with self._gw_lock:
            if self._gw is None:
                import gnoc_agent as G
                from gnoc_gateway import Allowlist, Gateway, Redactor as GwRedactor, config, discord_gw, runner
                state = os.path.join(config.state_dir(), "discord")
                runner.configure(G, state)
                try:
                    timeout = float(gnoc_comms.conf("GNOC_GATEWAY_APPROVAL_TIMEOUT") or 300)
                except ValueError:
                    timeout = 300.0
                # secrets first (the core), then this bot's name scrubbing on top; either failing withholds
                red = GwRedactor(tokens=[self.conf.token or ""], extra=self.redact if self.redact.enabled else None)
                gw = Gateway(lambda key: runner.AgentRunner(G, state_dir=state), redact=red, approval_timeout=timeout,
                             log=lambda *a: log("gateway:", *a), interrupt=G.INTERRUPT.set, busy=self.ask._lock)
                gw.add(discord_gw.Discord(gnoc_comms._discord), Allowlist(self.conf.owners, self.conf.channels))
                self._gw = gw
            return self._gw

    def owner_message(self, d):
        """True when this message went to the full agent (an owner, addressed to it, in a DM or an allowlisted
        channel). Everything else returns False and takes the read-only path unchanged."""
        if not self.conf.owners:
            return False
        author = d.get("author") or {}
        if str(author.get("id") or "") not in self.conf.owners:
            return False
        from gnoc_gateway import discord_gw
        inb = discord_gw.parse(d, self.me)
        if inb is None:
            return False
        gw = self.gateway()
        if not gw.adapters["discord"][1].owner(inb.sender_id, inb.chat_id, inb.private):
            return False
        gw.handle(inb)
        return True

    # ---- one message

    def handle_text(self, content):
        """Returns (text, fenced) for a command, or None when the message is not for us."""
        body = content.strip()
        low = body.lower()
        if low.startswith("!ask"):
            q = body[4:].strip()
            if not q:
                return ("`!ask <question>` - ask the agent something.", False)
            return (self.redact(self.ask.turn(q)), False)
        if low.startswith("!hunt"):
            arg = body[5:].strip().split()
            key = (arg[0].lower() if arg else "status")
            if key in ("help", "-h", "--help", "?"):
                return (HELP, False)
            if key not in COMMANDS:
                return (f"no such query: `{key}`\n\n" + HELP, False)
            return (self.redact(run_command(key)), True)
        return None

    def on_message(self, d):
        author = d.get("author") or {}
        if author.get("bot") or (self.me and author.get("id") == self.me):
            return
        try:
            if self.owner_message(d):
                return
        except Exception as e:  # noqa: BLE001 - never let one message kill the bot
            log(f"owner path failed: {type(e).__name__}: {e}")
            return
        channel_id, user_id = d.get("channel_id"), author.get("id")
        content = d.get("content") or ""
        if not content.strip().lower().startswith(("!hunt", "!ask")):
            return                                   # not addressed to us: no reply, no log of content
        who = f"{author.get('username', '?')}/{user_id}"
        if not self.conf.may(user_id, channel_id):
            log(f"ignored {who} in {channel_id} (not allowlisted)")
            return                                   # silent: an unlisted user learns nothing
        log(f"{who} in {channel_id}: {content[:80]!r}")
        try:
            got = self.handle_text(content)
            if got is None:
                return
            text, fenced = got
            for part in chunks(text, fence=fenced):
                post(channel_id, part, reply_to=d.get("id"))
        except Exception as e:  # noqa: BLE001 - never let one message kill the bot
            log(f"handler failed: {type(e).__name__}: {e}")
            with contextlib.suppress(Exception):
                post(channel_id, f"that failed: `{type(e).__name__}`. It is in the bot log.",
                     reply_to=d.get("id"))

    # ---- gateway

    async def run(self):
        from websockets.asyncio.client import connect
        backoff = 1
        while True:
            url = self.resume_url or GATEWAY
            try:
                async with connect(url, max_size=None, open_timeout=30) as ws:
                    backoff = 1
                    await self.session(ws)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log(f"gateway: {type(e).__name__}: {e}")
            delay = min(backoff, 60) * (1 + random.random() * 0.3)
            log(f"reconnecting in {delay:.0f}s")
            await asyncio.sleep(delay)
            backoff = min(backoff * 2, 60)

    async def session(self, ws):
        hello = json.loads(await ws.recv())
        interval = hello["d"]["heartbeat_interval"] / 1000.0
        hb = asyncio.create_task(self.heartbeat(ws, interval))
        try:
            if self.session_id and self.seq is not None:
                await ws.send(json.dumps({"op": 6, "d": {"token": self.conf.token,
                                                         "session_id": self.session_id, "seq": self.seq}}))
                log("resuming")
            else:
                await ws.send(json.dumps({
                    "op": 2, "d": {"token": self.conf.token, "intents": INTENTS,
                                   "properties": {"os": "linux", "browser": "gnoc", "device": "gnoc"}}}))
                log("identifying")
            async for raw in ws:
                msg = json.loads(raw)
                op, t, d = msg.get("op"), msg.get("t"), msg.get("d")
                if msg.get("s") is not None:
                    self.seq = msg["s"]
                if op == 0:
                    if t == "READY":
                        self.me = (d.get("user") or {}).get("id")
                        self.session_id = d.get("session_id")
                        base = d.get("resume_gateway_url")
                        self.resume_url = f"{base}/?v=10&encoding=json" if base else None
                        log(f"ready as {(d.get('user') or {}).get('username')} "
                            f"({len(self.conf.users)} allowlisted user(s), "
                            f"{'scrubbed' if self.redact.enabled else 'RAW NAMES'})")
                    elif t == "RESUMED":
                        log("resumed")
                    elif t == "MESSAGE_CREATE":
                        # blocking work (subprocess, model turn) off the event loop
                        asyncio.get_running_loop().run_in_executor(None, self.on_message, d)
                elif op == 7:
                    log("gateway asked us to reconnect")
                    return
                elif op == 9:
                    log("session invalid; starting a new one")
                    self.session_id = self.seq = self.resume_url = None
                    await asyncio.sleep(1 + random.random() * 4)
                    return
        finally:
            hb.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await hb

    async def heartbeat(self, ws, interval):
        await asyncio.sleep(interval * random.random())
        while True:
            with contextlib.suppress(Exception):
                await ws.send(json.dumps({"op": 1, "d": self.seq}))
            await asyncio.sleep(interval)


# ----------------------------------------------------------------- entry points

def check():
    conf = Conf()
    print("gnoc_discord --check\n")
    print(f"  token               {'set' if conf.token else 'MISSING'}")
    print(f"  allowlisted users   {len(conf.users)}" + ("" if conf.users else "   <- answers nobody"))
    print(f"  channels            {len(conf.channels) or 'any it can see'}")
    print(f"  scrubbing           {'OFF - REAL NAMES WILL BE SENT' if conf.no_scrub else 'on (demo substitution)'}")
    print(f"  read-only queries   {', '.join(sorted(COMMANDS))}")
    print(f"  owners (full agent) {len(conf.owners)}" + ("  DMs and allowlisted channels only; approvals ask in chat"
                                                         if conf.owners else "  (none: read-only for everyone)"))
    try:
        import gnoc_session
        live = gnoc_session.live_sessions()
        mine = [s for s in live if str(s.get("pid")) == str(os.getpid())]
        state = "OPEN" if gnoc_session.hunting_allowed() else "shut"
        print(f"  hunt gate           {state} - {len(live)} live chat session(s), "
              f"{len(mine)} of them this bot's")
        print("                      the gate follows the user's own open `gnoc chat`, not this bot;")
        print("                      this process registers none, so it can never hold it open.")
    except Exception as e:  # noqa: BLE001
        print(f"  hunt gate           could not read: {e}")
    print("\n  scrub self-test (real -> sent):")
    red = Redactor(enabled=True)
    sample = run_command("needs")[:1200]
    leaked = []
    sc = red.scrubber
    out = red(sample)
    for name in sorted(sc.programs):
        if len(name) >= 5 and re.search(rf"\b{re.escape(name)}\b", out, re.I):
            leaked.append(name)
    for ln in out.strip().split("\n")[:6]:
        print("    " + ln[:150])
    print(f"\n  program names found in scrubbed output: {', '.join(leaked) if leaked else 'none'}")
    for p in conf.problems():
        print(f"\n  PROBLEM: {p}")
    return 1 if conf.problems() else 0


def once(arg):
    key = (arg or "status").strip().lower()
    if key not in COMMANDS:
        print(f"no such query: {key}\navailable: {', '.join(sorted(COMMANDS))}")
        return 2
    print(Redactor(enabled=True)(run_command(key)))
    return 0


def main(argv):
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv and argv[0] == "--check":
        return check()
    if argv and argv[0] == "--once":
        return once(argv[1] if len(argv) > 1 else "status")
    conf = Conf()
    problems = conf.problems()
    if problems:
        for p in problems:
            print(f"refusing to start: {p}", file=sys.stderr)
        return 2
    if conf.no_scrub:
        log("WARNING: GNOC_DISCORD_NO_SCRUB=1 - real program and host names will be sent to Discord")
    log(f"starting; {len(conf.users)} allowlisted user(s)")
    try:
        asyncio.run(Bot(conf).run())
    except KeyboardInterrupt:
        log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
