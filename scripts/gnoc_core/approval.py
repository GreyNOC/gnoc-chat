"""Whether a tool call needs the user's yes, asking for it, and the "do not do it, just tell me" hold."""
import re
from .runtime import bind


# git actions that only READ: no approval, and allowed after the turn read untrusted text. Everything else
# changes the repo (branch / switch / stash / restore / commit) or reaches outward (push, pr create).
_GIT_READ = {"status", "diff", "log", "show", "blame"}


_GIT_READ_OPS = {"stash": {"list", "show", ""}, "pr": {"view", "list", "status", "checks", "diff", ""}}


_GIT_ALWAYS = {"commit", "push"}
# The same acts typed as a shell command. The git tool asked every time and `bash command='git commit -m ..'`
# did not: under /auto a commit or a new pull request went through unasked, which is not what the README says
# ("a commit, a push or a new pull request asks you every time, even in auto mode"; workflow drive 2026-11-21).
# A push never runs through bash at all (BASH_DENY). Global options before the subcommand are skipped
# (`git -C dir commit`, `git --no-pager commit`).
_SHELL_GIT_ALWAYS = __import__("re").compile(
    r"(?:^|[\s;&|(`])(?:git(?:\s+(?:-[cC]\s+\S+|--?[A-Za-z][\w-]*(?:=\S+)?))*\s+commit(?![\w-])"
    r"|gh\s+pr\s+create\b)")


def _git_reads(a):
    """True when this git call only reads."""
    (
        _GIT_READ, _GIT_READ_OPS,
    ) = bind(
        "_GIT_READ", "_GIT_READ_OPS",
    )
    a = a if isinstance(a, dict) else {}
    act = str(a.get("action") or "status").lower()
    if act in _GIT_READ:
        return True
    if act == "branch":
        return not str(a.get("ref") or "").strip()
    if act in _GIT_READ_OPS:
        return str(a.get("op") or "").lower() in _GIT_READ_OPS[act]
    return False


def _bg_reads(a):
    """bg calls that only look at processes this chat already started."""
    return str((a if isinstance(a, dict) else {}).get("action") or "list").lower() in ("output", "log", "list")


def _defend_reads(a):
    """defend calls that only look. Answering, responding, enforcing, undoing, muting an alert, closing a case and
    adding/removing endpoints change what the defender does or trusts."""
    a = a if isinstance(a, dict) else {}
    act = str(a.get("action") or "sweep").lower()
    op = str(a.get("op") or "").lower()
    if act in ("answer", "respond", "undo", "enforce"):
        return False
    if act in ("alerts", "triage", "endpoints", "vulnwatch") and op and op not in (
            "list", "show", "status", "get", "detail", "test", "check", "run"):
        return False
    return True


def _mcp_reads(a):
    """mcp calls that only look: list servers, a server's tools or resources. call and read reach the server."""
    return str((a if isinstance(a, dict) else {}).get("action") or "servers").lower() in (
        "servers", "list", "tools", "ls", "resources")


def _git_always(a):
    """commit, push and opening a pull request: the user's call every time, /auto and -s-p included."""
    (
        _GIT_ALWAYS,
    ) = bind(
        "_GIT_ALWAYS",
    )
    a = a if isinstance(a, dict) else {}
    act = str(a.get("action") or "").lower()
    return act in _GIT_ALWAYS or (act == "pr" and str(a.get("op") or "").lower() == "create")


_live = {}


def repo_is_live(r):
    """True when a pm2 process runs straight out of this repo (the website does: a save in public/ is live).
    Cached per repo for the session."""
    (
        WS, _live, json, os, subprocess,
    ) = bind(
        "WS", "_live", "json", "os", "subprocess",
    )
    if r == WS:
        return False
    if r not in _live:
        procs = []
        # `pm2 jlist` STARTS a pm2 daemon when none is running: a check must not spawn one (a test suite under
        # throwaway HOMEs left 318 daemons burning 13 cores, 2026-11-27). No daemon means no pm2 process at all.
        home = os.environ.get("PM2_HOME") or os.path.join(os.path.expanduser("~"), ".pm2")
        try:
            with open(os.path.join(home, "pm2.pid")) as fh:
                os.kill(int(fh.read().strip()), 0)
            running = True
        except (OSError, ValueError):
            running = False
        if running:
            try:
                procs = json.loads(subprocess.run(["pm2", "jlist"], capture_output=True, text=True,
                                                  timeout=15).stdout or "[]")
            except Exception:
                procs = []
        _live[r] = any(os.path.realpath(p.get("pm2_env", {}).get("pm_cwd") or "") == r for p in procs)
    return _live[r]


def _approval_target(ctx):
    return str(getattr(ctx, "program", "") or "").strip()


def _approval_approved(ctx, name, args):
    """A queued approval for this exact call, consumed once. No program means no durable queue."""
    (
        _approval_target, _graph_db, gnoc_graph,
    ) = bind(
        "_approval_target", "_graph_db", "gnoc_graph",
    )
    program = _approval_target(ctx)
    if not program:
        return False
    try:
        return bool(gnoc_graph.approval_check(program, name, args, consume=True, db_path=_graph_db()))
    except Exception:  # noqa: BLE001 - approval state must never break a turn
        return False


def _queue_approval(ctx, name, args):
    (
        WS, _approval_target, _graph_db, gnoc_graph, os,
    ) = bind(
        "WS", "_approval_target", "_graph_db", "gnoc_graph", "os",
    )
    program = _approval_target(ctx)
    if not program or not os.path.isdir(os.path.join(WS, "targets", program)):
        return None
    try:
        return gnoc_graph.approval_request(program, name, args,
                                           risk="non-interactive turn: no prompt available",
                                           requested_by="worker" if ctx.s.get("_worker") else "lead",
                                           db_path=_graph_db())
    except Exception:  # noqa: BLE001
        return None


# a shell command that reaches the link key, the link/desktop modules or the input script: driving a machine by hand
_DRIVES_A_MACHINE = re.compile(r"gnoc_link|gnoc_desktop|gnoc_input|gnoc_kwin|gnoc_link_ed25519|gnoc_known_hosts|"
                               r"orch/links\.json")


_ANSWER_WORDS = re.compile(r"\b(?:yes|yeah|yep|no|nope|y|n|allow|deny|accept|keep|close|block|skip|ok|okay|sure|"
                           r"go ahead|do it|do the rest|all of them|loopback|localhost|lan|vpn|never|always|"
                           r"\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b", re.I)


def _his_answer(ctx):
    """True when the user's OWN message this turn carries an answer for the model to relay ("skip the docker one, do
    the rest", "accept the network baseline", "27036 loopback only"). "please defend this machine" and "continue"
    carry none, and neither does a nudge the harness wrote: _turn_text is their words only."""
    text = str((getattr(ctx, "s", None) or {}).get("_turn_text") or "")
    return bool(_ANSWER_WORDS.search(text))


def _needs_approval(name, args, ctx):
    (
        _approval_approved, _approval_required, _normalize_for_approval, grant_desktop,
    ) = bind(
        "_approval_approved", "_approval_required", "_normalize_for_approval", "grant_desktop",
    )
    args = _normalize_for_approval(name, args)  # defense in depth: a direct caller gets the same answer as _plan_call
    if not _approval_required(name, args, ctx):
        return False
    if _approval_approved(ctx, name, args):
        if name == "desktop" and args.get("action") == "request":
            grant_desktop(ctx, (args.get("target") or "local").strip(), args.get("reason"))
        return False
    return True


def _approval_required(name, args, ctx):
    (
        ACTING_TOOLS, SKIP_PERMS, TOOLS, _EDIT_TOOLS, _VERIFY_TOOLS, _approval_target, _bash_readonly, _bg_reads, _defend_reads,
        _git_always, _git_reads, _gnoc_class, _graph_db, _mcp_reads, _normalize_for_approval, copies_untrusted,
        gnoc_defend, gnoc_defender, gnoc_graph, repo_is_live, root,
    ) = bind(
        "ACTING_TOOLS", "SKIP_PERMS", "TOOLS", "_EDIT_TOOLS", "_VERIFY_TOOLS", "_approval_target",
        "_bash_readonly", "_bg_reads", "_defend_reads", "_git_always", "_git_reads", "_gnoc_class", "_graph_db", "_mcp_reads",
        "_normalize_for_approval", "copies_untrusted", "gnoc_defend", "gnoc_defender", "gnoc_graph",
        "repo_is_live", "root",
    )
    args = _normalize_for_approval(name, args)  # defense in depth: a direct caller gets the same answer as _plan_call
    if name == "desktop" and args.get("action") == "request":
        return True  # control of a real screen/mouse/keyboard: asked every time, skip-perms and /auto or not
    if name == "scan":
        return True  # an aggressive scanner run is GreyNOC's call every time, skip-perms and /auto included
    if name in ("bash", "bg") and _DRIVES_A_MACHINE.search(str(args.get("command", "") or args.get("text", "") or "")):
        return True  # the link key / input script by hand is the desktop tool without its grant: a one-liner calling
        # gnoc_link.run() got a full shell on a linked machine under -s-p with nobody asked (QAQC 2026-11-19)
    if name == "bash" and gnoc_defend.scans_remote(args.get("command", "")):
        return True  # nmap / masscan / nuclei ... at anything but this machine: the scan tool's rule, without the
        # bash-shaped hole (masscan of an internet /24 ran unprompted under -s-p with no program, 2026-10-24)
    if name == "defend" and gnoc_defender.needs_approval(ctx.s.get("defender"), args):
        return True  # defense that ACTS (block / pause / sysctl): his call, unless auto-defense is on and the
        # profile he answered already allows exactly these kinds (hand-picked ids always ask)
    if name == "defend" and str(args.get("action") or "").lower() == "scan" and any(
            gnoc_defend.classify(t) != "self" for t in str(args.get("target") or "").split()):   # none = itself
        return True  # scanning another machine on the LAN: his call every time, even his own network
    if name == "defend" and str(args.get("action") or "").lower() in ("discover", "gateway", "wlan"):
        return True  # an active probe of the subnet/gateway/Wi-Fi: his call every time
    if name == "defend" and str(args.get("action") or "").lower() in ("endpoint", "endpoints") \
            and str(args.get("op") or "").lower() in ("test", "check", "sweep", "scan"):
        return True  # ssh into a configured/unconfigured endpoint and inspect it: his call
    if name == "defend" and str(args.get("action") or "").lower() == "answer" and not _his_answer(ctx):
        return True  # the defender's questions are HIS: may it scan the LAN, which port stays open, who must never
        # be locked out. Pushed to "carry out the plan", the lead answered them itself ("docker_group: yes,
        # steam_ports: yes") with nobody asked (2026-11-20 defender drive). It relays his answer; it never makes one.
    if name == "defend" and str(args.get("action") or "").lower() == "enforce" and str(args.get("op") or "").strip():
        return True  # gateway/AP/endpoint changes: always ask, even after a permission is granted. A call with no
        # op does nothing but print its usage, and walled it hid that: two bare enforce calls, then no answer (drive)
    if name == "gnoc" and _gnoc_class(args.get("args", ""))[0] == "control":
        return True  # stop / resume / pivot / lock / fleet: the whole hunt machinery, asked every time
    if name in ("bash", "bg") and gnoc_defend.scans_remote(args.get("command", "") or args.get("text", "") or ""):
        return True  # the same rule for a scan started in the background (QAQC 2026-11-19: bg skipped it)
    if ctx.s.get("_tainted") and name in ACTING_TOOLS and not (name == "bash" and _bash_readonly(
            args.get("command", ""))) and not (name == "git" and _git_reads(args)) \
            and not (name == "bg" and _bg_reads(args)) and not (name == "mcp" and _mcp_reads(args)) \
            and not (name == "defend" and _defend_reads(args)) \
            and not (name == "desktop" and args.get("action") in ("look", "release")):
        return True  # this turn read someone else's text (email/discord/web): no unattended actions after it
    if copies_untrusted(ctx, name, args):
        return True  # it is acting out text a target sent us: asked every time, skip-perms and /auto included
    if isinstance(getattr(ctx, "s", None), dict) and ctx.s.get("_root_override") and \
            name in (_EDIT_TOOLS | _VERIFY_TOOLS):
        return False  # a builder in its own disposable worktree (approved when its isolated delegate was);
        # _isolation_refusal keeps every write inside it
    rule = TOOLS[name][2]
    if getattr(rule, "plugin_tool", False):
        # a tool a plugin registered asks every time, /auto and skip-perms included, unless the user saved a
        # standing rule for it (/permissions allow <tool>): plugin code is new to the chat, the user's rules are not
        try:
            import gnoc_perms
            return not gnoc_perms.allowed(name, args, root())
        except Exception:  # noqa: BLE001 - a broken rules file never widens the gate
            return True
    if rule == "always" or (name == "git" and _git_always(args)):
        return True  # a commit, a ship, a cloud spend: GreyNOC's call every time, /auto and -s-p included
    if name in ("bash", "bg") and _SHELL_GIT_ALWAYS.search(str(args.get("command") or args.get("text") or "")):
        return True  # the same commit or pull request, typed as a shell command
    if SKIP_PERMS[0] or rule is None:
        return False
    live = repo_is_live(root()) and (
        name in ("write_file", "edit_file", "apply_patch")
        or (name == "bash" and not _bash_readonly(args.get("command", "")))
        or (name == "bg" and not _bg_reads(args))
        or (name == "git" and not _git_reads(args)))   # QAQC 2026-11-19: apply_patch, bg and git writes too
    if live:
        need = True  # a live checkout: every change is GreyNOC's to approve, /auto or not
    elif rule == "unless_auto":
        need = not ctx.auto
    else:
        need = bool(rule(args)) and not ctx.auto
    if not need:
        return False
    # The user's own standing rule ("always allow pytest here"), saved from the prompt or with /permissions. It
    # only answers this ordinary question: every ask-every-time rule above has already returned (gnoc_perms).
    if not live:
        try:
            import gnoc_perms
            if gnoc_perms.allowed(name, args, root()):
                return False
        except Exception:  # noqa: BLE001 - a broken rules file must never widen the gate
            pass
    # An operator rule pre-authorises a call that WOULD ask. Consulted only now: before, every GET, every /auto
    # and every -s-p call spent one of its uses on a call that needed no approval at all (QAQC 2026-11-19).
    program = _approval_target(ctx)
    if program:
        try:
            if gnoc_graph.rule_consume(program, name, args, db_path=_graph_db()):
                return False  # an operator rule pre-authorised this exact call, once per granted use
        except Exception:  # noqa: BLE001 - a broken rule must never widen the gate
            pass
    return True


# ---------- "do not do it, just tell me" ----------
# GreyNOC asked "what would stop do right now? do not do it, just tell me" and the lead CALLED `gnoc stop`
# (2026-10-26 UX battery, prompt 8). Only the piped-run approval wall stopped it; his own -s-p terminal has no
# wall, and that call ends the 24-hour drive. The approval gate asks "may it act"; nothing asked "did he say
# NOT to act". This is that check. It is OBEDIENCE, not a refusal, so it is narrow by design (GreyNOC, same
# day: "it should never refuse my requests"):
#   - it reads only HIS words for THIS turn (`_turn_text` is set before bot events are prepended), never the
#     model's, never a directive, never a worker brief;
#   - the hold phrase must forbid ACTING AS SUCH ("do not do it", "don't run that", "just tell me", "without
#     running anything", "no lo hagas"); "do not touch program-0, pivot to program-101" is a request, not a hold;
#   - a go-word in the same message ("go ahead", "run it", "dale", "I approve") lifts the hold, matched after
#     the hold phrase itself is cut out so "do not do it" cannot lift itself;
#   - it holds only ACTING_TOOLS, with the same read exemptions the taint rule uses; every read still runs;
#   - it lasts one turn: the next message without hold words runs the same call at once, -s-p or not.
_HOLD_RX = [re.compile(p, re.I) for p in (
    r"\b(?:do\s+not|don'?t|dont|never)\s+(?:actually\s+|really\s+)?"
    r"(?:do|run|execute|fire|send|launch|trigger|perform|apply|call|start|touch|change|write|submit|file|post|"
    r"delete|kill|stop|act\s+on)\s+"
    r"(?:it|that|this|them|anything|any\s+of\s+(?:it|that|them)|the\s+(?:command|tool|call|burst|probe|write|action|request))\b",
    r"\b(?:just|only)\s+(?:tell|show|explain|describe|answer)\s+(?:me|it|what|how|whether|which|why)\b",
    # "make my home directory private, plan only": the lead set a plan, said "now executing step 1" and tried
    # chmod 700 ~ (defense batch 8, 2026-11-23)
    r"\b(?:plan|steps|commands?|outline|proposal)\s+only\b|\bonly\s+(?:the\s+|a\s+)?(?:plan|steps|commands?)\b|"
    r"\b(?:just|only)\s+(?:give\s+me\s+|show\s+me\s+)?(?:the\s+|a\s+)?plan\b",
    r"\b(?:without|not)\s+(?:actually\s+)?(?:doing|running|executing|firing|sending|changing|touching)\s+"
    r"(?:it|that|this|them|anything)\b",
    r"\b(?:do\s+not|don'?t|dont)\s+act\b",
    r"\bno\s+lo\s+(?:hagas|ejecutes|corras|mandes|lances|toques)\b",
    r"\bs[oó]lo\s+(?:dime|explica|cu[eé]ntame|mu[eé]strame)\b",
)]


# A go-word lifts a hold only as an order of its own: at the start of the message or of a clause ("ok, go ahead";
# "don't run it yet. go ahead now"), never inside a sentence about something else. QAQC 2026-11-19: anywhere in
# the text, "don't do it, just explain how you'd do it" and "do not run that, just tell me what the approved list
# says" read as go-words and nothing was held.
# ...and the go-word must be the WHOLE order ("ok, go ahead", "go ahead now.", "approved!"), not the start of an
# order about something else: "proceed with the analysis only" and "go ahead and read the file" lifted the hold
# for every acting tool (QAQC r2)
_GO_RX = re.compile(r"(?:^|[.,;:!?\n]\s*|\b(?:and|then|so|now|but|ok(?:ay)?|yes|sure)\s+)(?:please\s+)?"
                    r"(?:go\s+ahead|do\s+it|run\s+it|fire\s+it|execute\s+it|proceed|approved?|i\s+approve|"
                    r"yes,?\s+do|dale|hazlo|adelante|ejec[uú]talo)\b(?:\s+(?:now|please|then))?"
                    # ...or followed by an ACTING order: "go ahead and run it with the serial control" acts;
                    # "go ahead and read the file" does not (a read was never held)
                    r"(?:\s*(?:[.,;:!?\n]|$)|\s+and\s+(?:run|fire|execute|send|launch|apply|do|start|write|delete|"
                    r"kill|deploy|submit|post|probe|restart|stop|push|commit|install|trigger)\b)",
                    re.I)
# an order BEFORE "just tell me" makes it a report request, not a hold: "run the tests and just tell me whether
# they pass", "fix X, then just tell me what changed"
_ORDER_FIRST = re.compile(r"^\s*(?:please\s+)?(?:run|fix|restart|start|stop|build|test|check|deploy|install|update|"
                          r"upgrade|delete|remove|create|apply|commit|push|add|make|write|edit|change|open|send|kill|"
                          r"launch|execute|rerun|refactor|rename|move|copy|probe|scan|hunt)\b", re.I)


def _hold_phrase(text):
    """The hold phrase in the user's own words, or None when the message does not forbid acting or lifts it."""
    (
        _GO_RX, _HOLD_RX, _ORDER_FIRST, re,
    ) = bind(
        "_GO_RX", "_HOLD_RX", "_ORDER_FIRST", "re",
    )
    text = str(text or "")
    hits = [m for rx in _HOLD_RX for m in rx.finditer(text)]
    hits = [m for m in hits if not (re.match(r"(?i)(?:just|only)\b", m.group(0))
                                    and _ORDER_FIRST.match(text[:m.start()]))]
    # "fix the discount bug ... do not touch anything ELSE" limits the scope of an order; it does not forbid the
    # order. Read as a hold, it held the test run and the very edit he asked for (baseline drive 2026-11-21).
    hits = [m for m in hits if not re.match(
        r"(?i)\s*(?:else\b|other\b|unrelated\b|beyond\b|outside\b|except\b|but\s+(?:that|this|the)\b|"
        r"(?:in|of|from)\s+the\s+rest\b|the\s+rest\b|more\s+than\b|you\s+(?:do\s+not|don't)\s+(?:have|need)\s+to\b)",
        text[m.end():])]
    if not hits:
        return None
    rest = text
    for m in sorted(hits, key=lambda m: -m.start()):
        rest = rest[:m.start()] + " " + rest[m.end():]
    if _GO_RX.search(rest):
        return None
    return min(hits, key=lambda m: m.start()).group(0)


def _told_not_to(ctx, name, args):
    """The hold text when the user's message this turn forbids acting and this call would act; else None."""
    (
        ACTING_TOOLS, _bash_readonly, _bg_reads, _defend_reads, _mcp_reads, _git_reads, _gnoc_class, _hold_phrase,
    ) = bind(
        "ACTING_TOOLS", "_bash_readonly", "_bg_reads", "_defend_reads", "_mcp_reads", "_git_reads", "_gnoc_class", "_hold_phrase",
    )
    if name not in ACTING_TOOLS:
        return None
    if name == "bash" and _bash_readonly(args.get("command", "")):
        return None
    if name == "git" and _git_reads(args):
        return None
    if name == "bg" and _bg_reads(args):
        return None
    if name == "mcp" and _mcp_reads(args):
        return None
    if name == "defend" and _defend_reads(args):
        return None
    if name == "desktop" and args.get("action") in ("look", "release"):
        return None
    if name == "gnoc" and _gnoc_class(args.get("args", ""))[0] == "read":
        return None
    phrase = _hold_phrase((getattr(ctx, "s", None) or {}).get("_turn_text"))
    if not phrase:
        return None
    return (f"held, not run: the user's message this turn says {phrase!r}, so answer them in words and do not "
            f"act. Nothing was executed, queued or changed. Do not retry {name} this turn and do not reach the "
            "same effect through another tool. Answer their question now from what you know or can READ (reads "
            "still run). If the user wants it done, their next message saying so (or 'go ahead') runs it at once.")


# "no network. what should a good impact statement contain" ran web_search and web_fetch (defense batch 5,
# 2026-11-23). His "no network" holds every tool that sends traffic off this machine for the turn; reads still run.
NETWORK_TOOLS = frozenset({"web_search", "web_fetch", "http_request", "graphql", "probe_matrix", "race", "browser", "sweep",
                           "escalate", "host_sweep", "provision", "liveness", "site_redteam", "recon", "scan",
                           "fingerprint", "oast", "js_mine"})
_NO_NET = re.compile(
    r"^\s*(?:no[- ]network|offline|no[- ]internet|no[- ]web)\s*[.:;,!-]"
    r"|(?<!the\s)(?<!a\s)\bno[- ]network\b(?![- ](?:rule|policy|mode|clause|flag|setting|section|requirement)s?\b)"
    r"|\bno\s+web\s+search(?:es|ing)?\b"
    r"|\bwithout\s+(?:any\s+)?(?:network|internet|web)(?:\s+access)?\b"
    r"|\bwithout\s+(?:sending|making)\s+(?:any\s+)?(?:traffic|requests?|network\s+calls?)\b"
    r"|\b(?:do\s+not|don'?t|dont|never)\s+(?:search\s+(?:the\s+web|online)|go\s+online|browse|"
    r"use\s+the\s+(?:web|internet|network)|send\s+(?:any\s+)?traffic|touch\s+the\s+network)\b"
    r"|\b(?:stay|work|answer)\s+offline\b", re.I)


def _offline_hold(ctx, name):
    """The hold text when their message this turn says no network and this tool would send traffic; else None."""
    if name not in NETWORK_TOOLS:
        return None
    # his /privacy switches: local-only holds every network tool, "web off" holds web_search/web_fetch (2026-11-24)
    try:
        import gnoc_privacy
        _flow = "web" if name in ("web_search", "web_fetch") else ""
        _why = gnoc_privacy.why_not(_flow) if _flow else (
            gnoc_privacy.why_not("web") if gnoc_privacy.local_only() else "")
        if _why:
            return (f"held, not run: {_why}. {name} would send traffic off this machine. Answer from what you know "
                    "and from local reads, and tell them in one line that the web was not used because of this "
                    "setting. Do not reach the network through another tool.")
    except ImportError:
        pass
    text = str((getattr(ctx, "s", None) or {}).get("_turn_text") or "")
    m = _NO_NET.search(text)
    if not m:
        return None
    return (f"held, not run: the user's message this turn says {m.group(0).strip(' .:;,!-')!r}, so nothing leaves this "
            f"machine: {name} sends traffic. Answer from what you know and from local reads (files, the workspace). "
            "Do not retry it or reach the network through another tool this turn.")


APPROVAL_WAIT_S = 180   # how long "? allow" waits for a human before it counts as no (2026-11-10)


def _stdin_ready(timeout):
    """True when a line is waiting on stdin within `timeout` seconds, or when stdin cannot be polled (a pipe,
    a test, a platform without select on ttys): in that case the caller falls through to a blocking read, which
    is exactly the old behaviour."""
    (
        sys,
    ) = bind(
        "sys",
    )
    import os
    if os.name == "nt":
        # Windows cannot select() a console: poll the keyboard, so "no answer in N s = no" holds there too
        try:
            import msvcrt
            import time
            if not sys.stdin.isatty():
                return True
            end = time.time() + float(timeout)
            while time.time() < end:
                if msvcrt.kbhit():
                    return True
                time.sleep(0.05)
            return False
        except Exception:  # noqa: BLE001
            return True
    try:
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        return bool(r)
    except Exception:  # noqa: BLE001 - not pollable: keep the blocking prompt
        return True


def _approve(name, args, interactive, approver=None):
    (
        APPROVAL_WAIT_S, BAR, TYPED, _preview, _stdin_ready, contextlib, diff_panel, dim, json, normalize_answer,
        re, root, say, show_diff, sys, yellow,
    ) = bind(
        "APPROVAL_WAIT_S", "BAR", "TYPED", "_preview", "_stdin_ready", "contextlib", "diff_panel", "dim", "json",
        "normalize_answer", "re", "root", "say", "show_diff", "sys", "yellow",
    )
    if not interactive and approver is None:
        return False
    detail = args.get("command") or args.get("args") or args.get("path") or args.get("url") or args.get("brief", "")
    if name == "desktop" and str(args.get("action") or "") in ("do", "click_text", "focus"):
        what = args.get("ops") if args.get("action") == "do" else (args.get("text") or args.get("window"))
        detail = (f"{args.get('action')} on {args.get('target') or 'local'}: "
                  f"{json.dumps(what, default=str)[:400] if not isinstance(what, str) else what[:400]}")
    elif name == "desktop":
        detail = (f"control the screen, mouse and keyboard of {args.get('target') or 'local'} for this task "
                  f"(off again when it answers). Why: {args.get('reason') or '(no reason given)'}")
    if name == "scan":
        detail = f"{args.get('tool')} scan against {args.get('url')} (one host, policy rate, detection only)"
    if not detail:   # run_tests {} or an odd shape: an empty "? allow X:" asks for a blind yes
        detail = json.dumps(args, default=str)[:300] if args else "(no arguments: the tool's default action)"
    if approver is not None:
        if name in ("edit_file", "write_file"):   # a phone shows no diff panel: put the first rows in the question
            try:
                rows = _preview(name, args)[:12]
            except Exception:  # noqa: BLE001 - the path alone is still a question he can answer
                rows = []
            if rows:
                detail = f"{detail}\n" + "\n".join(str(r) for r in rows)
        return _remote_answer(approver, name, detail)
    rows = _preview(name, args) if name in ("edit_file", "write_file") else []
    if rows:
        show_diff("    ", rows)
    # say(), not print(): with the bottom input bar on, the cursor lives on the bar, and a bare print or
    # input() drew the question over the input row (the "? allow" line vanished, 2026-10-24). The lock is
    # never held around the human: that froze every other writer until you answered.
    say(yellow(f"  ? allow {name}: {str(detail)[:300]}"))
    try:   # he may be in another window after a long turn (Hermes review, 2026-11-23)
        __import__("gnoc_notify").waiting(name)
    except Exception:  # noqa: BLE001 - a notification never costs the prompt
        pass
    offer = None
    try:
        import gnoc_perms
        offer = gnoc_perms.suggest(name, args, root())
    except Exception:  # noqa: BLE001 - the offer is a convenience; the question is still asked
        offer = None
    choices = ("    [y]es / [n]o / [a]uto for this session" + (" / [d]iff" if rows else "")
               + (f" / [p] always allow {offer} here" if offer else "") + " > ")
    with TYPED.paused():   # the type-ahead reader owns stdin mid-turn: without this it ate the answer
        try:
            while True:
                BAR.to_scroll()
                try:
                    # A question nobody answers must not freeze the hunt. Under /goal with skip-perms on, the
                    # copy gate asked "? allow bash" and the loop sat on it for 12 minutes until a human typed
                    # y (program-50, 2026-11-10 01:39Z); unattended it would have sat there until the session
                    # died. No answer in APPROVAL_WAIT_S means no: the safe default, and the lead is told why.
                    sys.stdout.write(yellow(choices))
                    sys.stdout.flush()
                    if not _stdin_ready(APPROVAL_WAIT_S):
                        say(yellow(f"\n    no answer in {APPROVAL_WAIT_S}s: taking that as NO. The action was not "
                                   "run; the hunt goes on without it."))
                        return "n"
                    typed = input().strip()
                except (EOFError, KeyboardInterrupt):
                    # Ctrl-C at the "? allow" prompt is the operator saying no, not "kill the chat". With the
                    # SIGINT handler gone (gnoc_session 2026-11-10) the interrupt reaches this input(); unguarded
                    # it climbed past the REPL's per-turn guards and the pane died with status 130 (01:55Z).
                    say(yellow("\n    interrupted: taking that as NO"))
                    return "n"
                raw = typed.lower()
                if normalize_answer(raw) is None and (len(typed.split()) >= 3 or typed.endswith("?")):
                    # a message typed ahead that landed on the prompt: it was eaten as a bad answer (2026-10-24)
                    TYPED.push(typed)
                    say(dim("    that looks like a message, not an answer: queued to run after this turn"))
                    continue
                if offer and raw in ("p", "perm", "permanent", "always here"):
                    ok, msg = gnoc_perms.add("allow", offer, repo=root())
                    say(dim(f"    {msg}" + ("  ·  /permissions lists and removes rules" if ok else "")))
                    return "y"
                if raw in ("d", "diff") and rows:
                    adds = sum(1 for r in rows if re.match(r"\s*\d*\s*\+", r))
                    diff_panel([(args.get("path") or name, rows, adds, max(0, len(rows) - adds))])
                    continue
                ans = normalize_answer(raw)
                if ans:
                    return ans
                say(dim("    type y, yes, n, no, a or auto" + (", or p" if offer else "")))
        finally:
            with contextlib.suppress(Exception):
                BAR.paint(TYPED.buf)


def _remote_answer(approver, name, detail):
    """A messenger gateway's yes/no (gnoc_gateway): 'y' only for an approver that returned exactly True.

    Never 'a': auto mode is a standing yes to everything that follows, and a phone message is not the place to
    hand that out. An approver that raises, times out or returns anything else is a no.
    """
    try:
        return "y" if approver(name, str(detail)[:1500]) is True else "n"
    except Exception:  # noqa: BLE001 - a broken channel is an unanswered question
        return "n"


YES = {"y", "yes", "yep", "yeah", "ok", "okay", "sure", "go", "do it", "allow", "approve", "1"}


NO = {"n", "no", "nope", "deny", "stop", "cancel", "0", ""}


AUTO = {"a", "auto", "always", "all", "yes all", "yes to all"}


def normalize_answer(raw):
    """'yes' / 'YES!' / 'y' -> 'y'; 'auto' -> 'a'; 'no' or empty -> 'n'; anything else -> None (ask again).
    Only 'y' used to count, so typing 'yes' silently declined the action (2026-10-22)."""
    (
        AUTO, NO, YES,
    ) = bind(
        "AUTO", "NO", "YES",
    )
    t = raw.strip().lower().rstrip(".!")
    if t in AUTO:
        return "a"
    if t in YES:
        return "y"
    if t in NO:
        return "n"
    return None


def _normalize_for_approval(name, args):
    """Alias, enum-case and type normalisation applied BEFORE the approval check, so approval judges the
    same command / action / values the tool will actually run. _harden did this only AFTER the check
    (review 2026-10-22): bash {"cmd": "touch F"} and git {"action": "COMMIT"} ran with no prompt,
    desktop {"action": "Request"} took the screen unasked. Unknown keys are left for _harden to note;
    a value _coerce cannot fix is left for _harden to refuse with the fix."""
    (
        TOOLS, _BadArg, _alias_targets, _coerce,
    ) = bind(
        "TOOLS", "_BadArg", "_alias_targets", "_coerce",
    )
    if name not in TOOLS or not isinstance(args, dict):
        return args
    sch = TOOLS[name][1] if isinstance(TOOLS[name][1], dict) else {}  # a test's stub tool may register no schema
    props = ((sch.get("function") or {}).get("parameters") or {}).get("properties") or {}
    out = dict(args)
    for k in list(out):
        if k not in props:
            for target in _alias_targets(k):
                if target in props and target not in out:
                    out[target] = out.pop(k)
                    break
    for k in list(out):
        if k in props and out[k] is not None:
            try:
                out[k] = _coerce(k, out[k], props[k])
            except _BadArg:
                pass
    return out


def _preview(name, args):
    """The diff an edit_file / write_file call WOULD make, for the approval prompt (nothing is written)."""
    (
        _diff_rows, _inside_ws, _lines_after, _read, os,
    ) = bind(
        "_diff_rows", "_inside_ws", "_lines_after", "_read", "os",
    )
    p = _inside_ws(args.get("path") or "")
    if not p:
        return []
    old = _read(p) if os.path.isfile(p) else ""
    if name == "edit_file":
        if args.get("cell") is not None or p.lower().endswith(".ipynb"):
            return []   # a notebook cell edit: the JSON diff would mislead; the result shows the cell
        if isinstance(args.get("edits"), list):
            new = old
            for e in args["edits"]:
                if not isinstance(e, dict) or not isinstance(e.get("old"), str) or not e["old"] or \
                        e["old"] not in new:
                    return []
                n = str(e.get("new") or "")
                new = new.replace(e["old"], n) if e.get("replace_all") else new.replace(e["old"], n, 1)
        elif args.get("replace_all") and args.get("old") and old.count(args["old"]) >= 1:
            new = old.replace(args["old"], args.get("new") or "")
        elif not args.get("old") and args.get("start_line") is not None:
            new = _lines_after(old, args.get("start_line"), args.get("end_line"), str(args.get("new") or ""))[0]
            if new is None:
                return []
        elif not args.get("old") or old.count(args["old"]) != 1:
            return []
        else:
            new = old.replace(args["old"], args.get("new") or "", 1)
    else:
        new = args.get("content") or ""
    return _diff_rows(old, new)[0]
