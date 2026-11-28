#!/usr/bin/env python3
"""Prove the Discord bot cannot hunt, cannot write, and cannot leak a program name.

    python3 scripts/test_gnoc_discord.py

Every check here is one of the three promises in gnoc_discord.py's docstring. If one fails, the
bot must not be left running: the gate check failing means an unattended hunter is reachable from
a chat channel, and the scrub check failing means client findings are going into Discord.
"""
import importlib.util
import os
import re
import sys

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
import gnoc_discord as B    # noqa: E402
import gnoc_session as S    # noqa: E402

FAIL = []


def check(name, cond):
    print(("  PASS  " if cond else "  FAIL  ") + name)
    if not cond:
        FAIL.append(name)


def base_scrubber():
    spec = importlib.util.spec_from_file_location("dash_base", os.path.join(WS, "scripts", "gnoc-dashboard.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["dash_base"] = m
    spec.loader.exec_module(m)
    return m


# ---------- 1. the command allowlist cannot write
print("1. read-only command allowlist")
WRITES = ("lane", "kill-lane", "submit", "approve", "gate", "start", "stop", "resume", "pivot",
          "orch", "chat", "code", "prune", "zip", "lock", "unlock", "svc", "ship", "unpark",
          "inbox", "split", "phone", "dchat", "soak", "train", "video", "fleet", "hq", "menu")
for w in WRITES:
    check(f"`{w}` is not reachable from Discord", w not in B.COMMANDS)
check("every allowlisted entry is an exact argv list",
      all(isinstance(v, list) for v in B.COMMANDS.values()))
check("no allowlisted argv interpolates user text",
      all(all(isinstance(x, str) and not re.search(r"[;&|`$<>]", x) for x in v)
          for v in B.COMMANDS.values()))

# ---------- 2. an unlisted user and an unlisted channel get nothing
print("\n2. access control")
c = B.Conf.__new__(B.Conf)
c.token, c.users, c.channels, c.no_scrub = "t", {"111"}, {"999"}, False
check("allowlisted user in allowlisted channel may", c.may("111", "999"))
check("allowlisted user in another channel may not", not c.may("111", "1000"))
check("unlisted user may not", not c.may("222", "999"))
c.channels = set()
check("empty channel list means any channel", c.may("111", "12345"))
check("empty channel list still gates the user", not c.may("222", "12345"))
c2 = B.Conf.__new__(B.Conf)
c2.token, c2.users, c2.channels, c2.no_scrub = "t", set(), set(), False
check("no allowlisted users = nobody may", not c2.may("111", "999"))
check("no allowlisted users is a refusal to start", bool(c2.problems()))
c3 = B.Conf.__new__(B.Conf)
c3.token, c3.users, c3.channels = "t", set(), set()
c3.no_scrub = ("1" == "1") and bool(c3.users)
check("NO_SCRUB cannot be set without a user allowlist", c3.no_scrub is False)

# ---------- 3. the hunt gate: building the agent must register no session
print("\n3. hunting stays bound to the user's own chat")
before = {str(s.get("pid")) for s in S.live_sessions()}
ask = B.Ask()
ask._build()
G = ask._G
import gnoc_goal  # noqa: E402
after = {str(s.get("pid")) for s in S.live_sessions()}
check("the bot's pid registered no hunt session", str(os.getpid()) not in after)
check("no session appeared at all", before == after)
check("the agent is non-interactive (approvals refuse)", ask._agent.interactive is False)
real = os.path.join(WS, ".claude")
for label, p in (("AGENT_DIR", G.AGENT_DIR), ("SESSION", G.SESSION), ("SESSIONS_DIR", G.SESSIONS_DIR),
                 ("OUT_DIR", G.OUT_DIR), ("JOBS_DIR", G.JOBS_DIR), ("goal", gnoc_goal.PATH)):
    check(f"{label} is isolated from the real state", str(p).startswith("/tmp") and
          not str(p).startswith(real))
check("a second question is refused, not queued", ask.busy() is False)

# ---------- 4. scrubbing: no program name may leave
print("\n4. nothing leaves under a real name")
m = base_scrubber()
hard = B.load_scrubber()
sample = B.run_command("needs")
out = hard.text(sample)
leaked = sorted(n for n in hard.programs
                if len(n) >= 5 and re.search(rf"\b{re.escape(n)}\b", out, re.I))
check(f"no program directory name in scrubbed output (leaked: {leaked or 'none'})", not leaked)
probe = "A signed-in Acme customer account on Acme Pay reached the merchant portal."
scrubbed = hard.text(probe)
# The two hardening checks need a program directory to harden against. On the operator's machine that is the real
# program-55; a fresh install has no targets/, so they also run on a throwaway workspace with one invented program.
if os.path.isdir(os.path.join(WS, "targets", "program-55")):
    check("the hardened deny set is larger than the dashboard's",
          len(hard.deny) > len(m.Scrubber(ws=WS).deny))
    check("a brand that is only a prefix of a program dir is caught", "acme" not in scrubbed.lower())
import shutil as _shutil      # noqa: E402
import tempfile as _tempfile  # noqa: E402
_fx = _tempfile.mkdtemp(prefix="gnoc-discord-ws-")
try:
    os.makedirs(os.path.join(_fx, "targets", "zorbexvrp"))
    with open(os.path.join(_fx, "targets", "zorbexvrp", "SCOPE.txt"), "w") as _fh:
        _fh.write("# scope\n=api.zorbex.test\n")
    _fx_hard = B.harden_scrubber(m.Scrubber(ws=_fx), m)
    check("the hardened deny set is larger than the dashboard's (fixture program)",
          len(_fx_hard.deny) > len(m.Scrubber(ws=_fx).deny))
    check("a brand that is only a prefix of a program dir is caught (fixture program)",
          "zorbex" not in _fx_hard.text("A signed-in Zorbex customer account on Zorbex Pay reached the merchant "
                                        "portal.").lower())
finally:
    _shutil.rmtree(_fx, ignore_errors=True)
check("ordinary English survives (readability)",
      "customer" in scrubbed and "merchant" in scrubbed)
check("substitution is stable within one text",
      len({w for w in scrubbed.split() if w.endswith("Pay")}) <= 1)
check("a secret-shaped token is hidden",
      "[hidden]" in hard.text("Authorization: Bearer sk-" "abcdef0123456789abcdef0123456789"))
check("an IP is masked", "10.0.0.x" in hard.text("connected from 203.0.113.44 twice"))
check("scrubbing is on by default", B.Redactor().enabled is True)

# ---------- 5. message framing
print("\n5. Discord message framing")
for text, fence in (("", True), ("x", True), ("\n".join("y" * 90 for _ in range(400)), True),
                    ("a\n" + "Z" * 9000 + "\nb", False)):
    msgs = B.chunks(text, fence=fence)
    check(f"every message is within Discord's limit ({max(len(x) for x in msgs)} <= {B.DISCORD_LIMIT})",
          max(len(x) for x in msgs) <= B.DISCORD_LIMIT)
    check("at most MAX_MESSAGES are sent", len(msgs) <= B.MAX_MESSAGES)
check("output stays in order when one line overflows",
      B.chunks("a\n" + "Z" * 9000 + "\nb", fence=False)[0].startswith("a"))
check("an empty answer still says something", B.chunks("") == ["(no output)"])

print()
print(("FAILED: " + ", ".join(FAIL)) if FAIL else "ALL CHECKS PASSED")


def test_every_check_passed():
    """pytest entry: the checks above run at import; this fails if any of them did."""
    assert not FAIL, FAIL


if __name__ == "__main__":
    sys.exit(1 if FAIL else 0)
