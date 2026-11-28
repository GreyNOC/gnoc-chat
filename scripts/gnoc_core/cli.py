"""The command line around the chat: /help, launching in a repo, copying and paging answers, the defender command, and the REPL."""
import re

import gnoc_repo
from .runtime import bind
from .state import STATE


AGENT_HELP = """  just talk: ask questions, tell it to hunt a program, read a report, run a probe, fix a script
  /hunt [program|dir] [goal]   hunt continuously (turn after turn) until Ctrl-C, STOP, NEEDS: or READY:;
                           loose names work (META), a dir moves there first
  /bot [summary|inbox|log|brain|leads]   what the background hunt bot is doing (it also shows up by itself
                           as BOT EVENTS in your next message)
  /offline [on|off]        nothing leaves this computer this run: no web, picture lookups, cloud models or update check
  /privacy [flow on|off]   what can leave this computer and each switch (local-only, web, image-lookup, updates, cloud)
                           (also gnoc chat --offline, GNOC_OFFLINE=1, or automatic without the claude CLI)
  /plain [on|off]          just talk - a plain assistant, no hunt program/scope/doctrine (also gnoc chat --plain)
  /collab [status|refresh|import <dir|file>]   the collaborator engagement: the partner's initial handoff
                           document IS the scope (no bounty program needed). status = handoff, hosts,
                           paperwork; refresh = re-import after the handoff changed; import <dir|file> =
                           add that project, or read one specific document the partner sent
  /graph [overview|stats|assets|coverage|nodes|todos|traces|traffic|evidence|findings|retest|retests|rules|snapshot|snapshots|diff|path|lineage|draft|export] [query]
                           the dual graph: assets, coverage/untested, exploration nodes, leased todos,
                           traces, evidence, findings; snapshot/diff show the attack surface moving;
                           path/lineage walk how a finding was reached; traffic lists/searches/shows captured exchanges; stats is the
dashboard; retest/retests schedule and close re-tests; rules lists the operator approval rules; export writes the self-contained
                           visual cockpit page and opens it; draft <finding_id> assembles a REPORT-FORMAT
                           report draft from a confirmed finding (files nothing)
  /approvals [state]       the intercept approval queue: calls that needed your yes but had no prompt
  /approve <id> [reason]   approve one queued call (single use; the model must retry the exact call)
  /deny <id> [reason]      deny one queued call
  /gpu1 <request>          ask the worker model on the second GPU directly (it answers, no tools); typed WHILE
                           it works it fires in the background and the lead keeps thinking, like /btw
  /skipperms [on|off]      this session: run writes/shell/non-GET HTTP without asking (commit, ship, scan still ask)
  /notify [on|off|test]    a desktop notification when a long answer finishes or it waits for your yes
  /save [n] [path]         save a file this chat made where you choose (the system's Save As window)
  /files                   the files this chat made (written files and pictures), numbered
  /download [n|all] [folder]  copy them to Downloads (Windows' Downloads under WSL); /open [n] opens one in its app
  /recall <words>          search your past chats (a local index of the saved sessions; the original messages)
  /lessons [query]         the lesson book it writes for itself (recalled into every turn); /forget L# retires one
  /learn [on|off|now]      recursive learning: after each working turn the worker GPU adds, reinforces, revises or
                           retires lessons; your corrections ("no, ...", "don't ...") become standing preferences
  /skills [show|review|rm|trust]   saved procedures (~/.gnoc/skills/<name>/SKILL.md, and the repo's
                           .gnoc/skills once trusted); the agent proposes one, /skills review shows the diff to approve
  /btw <note>              while it works: hand the RUNNING turn a side note (it reads it at its next step).
                           A plain line waits for the next turn; a line starting with ! kills this one instead
  ↓ / ↑                    while it works: watch a running sub-agent live, then back to the main chain
  /agents                  arrow-key picker: select a sub-agent (fan-out bot, worker, gate...), Enter, then c = its
                           whole chat, l = its log, live (/agents list = the plain table; gnoc agents from a 2nd
                           terminal while a hunt runs)
  /agents list [n]         every sub-agent (workers, fan_out bots, reflection, gates, Claude jobs): status, model,
                           steps, tokens, seconds since its last sign of life (⚠ = quiet > 90 s)
  /agent <id> [n|follow]   that sub-agent's log; follow tails it live. Also from another terminal: gnoc chat /agents
  /bench [lead|worker|both|<model>] [quick]   grade local models on gnoc chat's own jobs (tool choice, acting
                           not explaining, hypothesis/reflection JSON, report prose, refusals, prompt-injection
                           resistance, speed); synthetic cases, graded by code. /bench recommend | apply
  /econ [audit]            the proof market: wealth, Brier, open markets, bounties, chain integrity (audit replays)
  /pay [program] [host]    can it pay, can we file: bounty / no-bounty / descoped rows, the program's filing flags
                           and signal gate (T-254, read live), our own signal and how many resolved closures lift it
  /report [program]        build the draft for the best fully proven chain (PoC quoted from the raw captures,
                           suggested CVSS, title/Summary/Impact checked), show it; then the bot runs ship_chain
  /ledger [program]        the hunt ledger: hypotheses (status, probes, evidence) and capability edges
  /chains [program]        bug chains from unauth/own-account to a crown, ranked by prestige, with the next edge
  /brief [program]         what the workspace already knows (scope, policy, model, drafts, seeds, ledger)
  /copy [n|all|answer]     put the last answer's code on the clipboard, exact (last block by default; n = block
                           n, all = every block, answer = the whole answer as Markdown). Code lines on screen
                           carry no borders either, so a mouse selection of them pastes clean
  /top [n] · /bottom [n]   open the last answer (n = n back) in a pager at its top or its end; q comes back.
                           PgUp / PgDn at the prompt do the same
  /goal <what you want achieved>   set a standing objective and START ON IT NOW ("achieve zero click ato on
                           gatewayco"): it parses the crown and the acceptance criteria (zero-click, unauth, production),
                           seeds milestones from the attack tree, switches to the program named in it, then works
                           toward it turn after turn UNTIL IT IS ACHIEVED. It hands back only for Ctrl-C (held until you
                           say "continue" or /goal resume), NEEDS: (answer it and it resumes by itself), or six turns
                           with no progress; typing interjects. GNOC_GOAL_TURNS sets an optional turn budget. Every parsed constraint becomes an acceptance
                           criterion, so the goal refuses to close while it is unproven. --accept "a; b" adds your
                           own definition of done, --milestone "step" seeds one, --no-start sets it without starting
  /goal show|note <progress>|milestone <text>|accept <criterion>|pause|resume|done <receipt>|clear|help
                           progress; record a note (--artifact PATH); close a milestone/criterion with --receipt PATH
                           (--open re-opens one); pause keeps progress without steering; done refuses while anything
                           is open; clear drops it (--force drops another conversation's goal)
  /tasks [list|add <text>|done <T-id>|note <T-id> <text>|reopen <T-id>]   the tasks ledger (/todo too); plan steps sync
                           here automatically, so a finished plan does not leave stale open rows
  /mode [auto|swe|design|review|hunt|chain|prod|defender]   pin the job (software engineering, website design, code review
                           that proves its findings, bug hunting, exploit chains, live production testing); auto
                           picks per request. A new chat is a GENERAL assistant and coding agent; it turns into a
                           hunt only on an order (hunt <program>, keep hunting, /hunt, /mode hunt), and
                           /mode auto (or general) or "stop hunting" turns it back
  /mode defender [auto]    blue team for a machine and its subnet/LAN/WLAN: sweeps ports, firewall, settings,
                           packets, pids, connections, logins, neighbour ARP, gateway MAC/admin ports and Wi-Fi,
                           asks for gateways/subnets and who must never be locked out. AUTO-DEFENSE IS ON BY
                           DEFAULT for local reversible actions; an active intrusion opens a numbered triage
                           case. Gateway/AP/endpoint enforcement (block IP/MAC, deauth, isolate, pause/kill) is
                           proposed and ALWAYS waits for your explicit yes.
  /defender [...]          status · sweep · setup · network · gateway [add|rm <ip>|ssh|platform|api|test] ·
                           subnet [add|rm <cidr>] · baseline accept [network|host] · vulnwatch [run|on|off] · wlan · endpoint [list|add|rm|test|sweep] ·
                           enforce block-ip|block-mac|deauth|isolate|pause|kill · alerts · triage · auto|watch on|off [secs] ·
                           target local|<user@host> · allow|deny · admin · undo · journal · install
  /schedule add "<cron>" <prompt> [--deliver telegram|desktop|file]   run a prompt unattended on a cron schedule
                           (a systemd user timer, else crontab). It runs with the scope, folder, permission rules,
                           effort and models in force now; anything needing approval is held and listed in the
                           report, never run. list (what each was saved with) · rm <id> · run <id> (now)
  /mode design            the website-designer loop: see the page first, learn the design system, plan, build,
                           verify in the browser (mobile too), review. The team tool is its analysis arm:
  team(brief=..., members=[designer, frontend, reviewer]) runs specialist bots in parallel and merges
                           their digests - you stay the lead and do the edits. Roles: architect, backend,
                           frontend, designer, reviewer, tester, security, researcher, docs.
  /plan [request]          deepcode-style plan mode: the lead proposes plan(action=set, steps=[{action, verify,
                           why}...]) which shows as a PLAN panel, then you choose: enter = implement,
                           e = edit the plan, q = keep it for later. /plan on pins plan mode for every message,
                           /plan show|status|next inspects it and the next step, /plan done N [proof] or
                           /plan doing|skip N updates a step (done needs the proof when verify= is set),
                           /plan go works it across turns with the /work loop, /plan clear drops it. An active
                           plan rides the prompt bar (▣ 2/5 …) and every turn's system prompt; its steps stay
                           in sync with the tasks ledger.
  /setup                  the guided model setup: Ollama on this computer, or a cloud API key (also `gnoc setup`)
  /init [project <name>    workspace setup, Claude-Code-strong. On first entry into a repo gnoc chat offers to
    [node|python|web]]      write GNOC.md (stack, build/test/lint/run commands, layout, rules) + a gchat.md
                           session - never overwriting a repo's own GNOC/CLAUDE/AGENTS.md. /init project <name>
                           scaffolds a NEW project: dir, git init, starter files, GNOC.md, then enters it.
  /work <task>             long-horizon autonomous task completion: it sets the standing goal, plans with
                           plan(action=set), then works the plan step by step ACROSS TURNS without asking -
                           running each verification and marking plan(action=update, evidence=...) - until done,
                           NEEDS: you, or six turns without progress (no default budget; GNOC_WORK_TURNS sets one). On completion it writes a
                           completion receipt, meets the plan-completion criterion and closes the goal; open
                           --accept criteria keep the goal open. /work alone continues the active plan; /work
                           status shows the goal+plan; --turns N caps this run; --no-goal plans without a
                           standing goal; --force replaces an unrelated active goal. Ctrl-C hands control back.
  /thoughts [on|off]       the lead's reasoning, live (default OFF: hidden; on is kept for later chats): the status line
                           shows the live glyph, model@gpu, step n/N, elapsed, tokens, tok/s and a stalled
                           warning after 25 s of silence, with the thinking as a tail ticker, and the whole
                           reasoning stays on screen as a block above the answer or the actions it led to.
                           off only hides it: the model still reasons (/reasoning sets how hard)
  /reasoning [low|med|high|ultra]   how hard it thinks: model reasoning depth, steps per turn and how many
                           worker bots it may run in parallel (1/2/3/6). ultra also fans big requests out to
                           parallel bots on BOTH GPUs and merges their findings. Remembered for the session
  /effort [low|medium|high|max]   the same knob under its older names (max = high + both GPUs every message)
  /effort steps <n>        override just the lead's per-turn tool budget (0 = unlimited, off = back to the
                           preset). Remembered for the session. A /hunt loop is already uncapped: the step
                           limit ends a TURN, never the hunt
  /deep <request>          both GPUs work the request in parallel, the lead merges the answers
  /gpus                    which model runs where, and what each GPU has loaded
  /tools [words]           which tools are loaded for the next turn, and which were left out
                           (the list is fitted to the model's context; [words] previews the pick)
  /lead <model[@desktop]>  set the lead model     /worker <model[@desktop]>  set the worker model
  /cd or /dir <dir|program> [task]  move the working directory (keeps the conversation), start a gchat.md session;
                           the bot can do this itself when you name a folder (change_dir)
  /repo <path|url|owner/repo|off>   work in any repo: a folder on disk, or a public remote cloned once
                           (shallow, into ~/.gnoc/repos) and opened here; reads its GNOC.md/CLAUDE.md, edits,
                           runs its tests (gnoc chat --repo <path|url> starts there; off = back to the hunt workspace)
  /program [handle]        set the active hunt program (scope + raw-capture folder); alone, it says which one and
                           where it came from (this folder, an earlier session, /program, /goal)
  /program clear           clear the program (no active program; leaves its folder)
  /auto [on|off]           auto-approve writes, shell and non-GET HTTP (Claude workers always ask)
  /sandbox [local|docker [--network] [--image X]|ssh <host> [dir]]   where bash runs: this machine, a container
                           for this conversation (no network, only this repo mounted) or another host (key login).
                           Typed by you only; the model can never switch it
  /jobs                    background Claude workers
  /stophunt                kill all hunting so the chat gets the whole machine (sets the global STOP; the
                           lead and worker models stay loaded)
  /resumehunt              clear the global STOP so hunting can run again (asking the bot to "resume the hunt"
                           does the same, with a prompt); it names any hunt process /stophunt left stopped, which
                           gnoc start auto hunt restarts
  /stop [on|off]           /stop off = /resumehunt, /stop on = /stophunt; alone it says whether STOP is set
  /new (/reset, /clear)    start a new conversation; every launch of gnoc chat is a new one too, and each new
                           conversation starts clean: program clear, unlimited steps (/effort steps 0), mode auto
  /changes [short]         every file the agent wrote in this conversation, as a diff (/diff too)
  /review [paths]          the worker GPU code-reviews the uncommitted diff of the active repo
  /undo [n] [force]        revert the agent's last n file writes (never over an edit made after it)
  /bg [list|output|stop]   the background processes the agent started (dev servers, watchers); /bg stop <name>
  /hooks [trust|untrust]   your pre/post tool hooks (~/.gnoc/hooks.json, and the repo's .gnoc/hooks.json once
                           trusted): e.g. format every edited file, block writes to a folder
  /plugins [enable|disable <name>]   your Python plugins in ~/.gnoc/plugins (events around tools and model
                           calls, extra tools and commands); each runs only after you type /plugins enable
  /permissions [allow|deny <rule>|rm <#>]   standing rules: allow bash(pytest *) in this repo without asking,
                           deny bash(rm -rf *) everywhere even under /auto; p at an approval prompt saves one
  /doctor                  check this install: Python, its environment, the model, updates, your config files
  /commands                your own slash commands: ~/.gnoc/commands/<name>.md or <repo>/.gnoc/commands/<name>.md
                           (or .claude/commands/) become /<name> [args]; $ARGUMENTS in the file is replaced
  /mcp refresh             list every MCP server's tools again and offer them as native tools
  /file <program/slug> [--dry-run] [--token-env NAME] [--allow-missing-panels]   file ONE draft to HackerOne:
                           filability and pre-filing gates, the exact payload, then it files only when you type
                           FILE <slug>. Typed by you only; the model can never run it
  /outbox [id|all]         drafts the bot wrote (email, Discord, Facebook, LinkedIn, X); nothing leaves without you
  /send <id>               send that exact draft (asks yes once more)   /edit <id>  /discard <id>
  /comms                   which channels are set up and what secrets.env still needs
  /sessions [n]            saved conversations, newest first
  /resume [n|last|id]      bring one back (gnoc chat -c or -l resumes the last at launch, -r <id> resumes one,
                           bare -r shows the picker)
  /fork [n|last|id]        copy a conversation into a NEW one and keep talking (bare = this one; the source is
                           never modified; gnoc chat -f <id> forks at launch)
  /continue                this conversation if it has history, else resume the most recent saved one
  /raw                     toggle the reasoning display: the live status-line ticker AND the ✻ thinking block
                           kept above each answer/action (same knob as /thoughts)
  /simple <q>              the old read-only status Q&A
  /hf clone <owner/repo|url>[:QUANT] [--worker|--both] [--on desktop]   clone a Hugging Face model and talk to
                           it here (it becomes the lead unless you say otherwise); /hf search|files|list|use|room
                           at most 3 cloned bots per GPU: the least-used one without a role is removed for a new one
  /model                   pick a model on either machine OR a registered cloud provider with the arrow keys
                           (enter = lead, w = worker)
  /model <name>[@desktop]  set the lead directly · /worker <name> · /route laptop|desktop
  /model <provider>        a bare cloud provider name (anthropic, openai, ... or one /cloud add registered) sets
                           its default model as the lead · <model>@<provider> picks a specific one
  /claude api <key>        use Claude (Anthropic's API) as the lead. api <key> saves it to
                           ~/.config/gnoc/secrets.env (chmod 600) and tests it live; then
                           /claude on [model] · /claude off · /claude models · /claude clear.
                           The same for every frontier lab: /gpt /gemini /grok /llama /mistral /deepseek /kimi /qwen
                           (also by provider name: /anthropic /openai /chatgpt /google /xai /meta /moonshot /alibaba).
                           CLOUD: the conversation leaves this machine (secrets scrubbed first).
  /cloud <provider> ...    the same thing for any registered provider, e.g. /cloud anthropic on
  /cloud add <name> <base-url> <model> [api-key|-]   register ANY OpenAI-compatible endpoint
                           (OpenAI, OpenRouter, Groq, Together, vLLM, llama.cpp server, a proxy ...);
                           no api-key, or '-' as the key, marks it keyless. Then /cloud <name> check,
                           /cloud <name> on [model] · off · api <key> · models · rm. /cloud list shows
                           them all; model names are free-form (the listed ones are advisory).
  /clone <repo-url|owner/repo>   clone a bot/agent repo into scripts/bots-ingested/ for review (inspects only,
                           never installs or runs it); a Hugging Face model goes to /hf clone instead
  /bots                    the repos /clone ingested
  /compact                 fold older turns into session notes to free the context window (automatic too)
  /usage                   tokens, calls and time per model this session, plus how full the context is
  /export [name.md]        write this conversation to Markdown (default out/chat-<sid>.md under the repo)
  @path                    attach a file's content to your next message - Tab completes after @, and several
                           @paths ride along at once (each capped at 8k chars, 24k per message). Ctrl-O at the
                           prompt asks which file to attach; Ctrl-O while a turn runs completes the @path you
                           are typing. Long turns ring the terminal bell when they finish (GNOC_TURN_ALERT_SECS)
  /help (/?)               this list
  q / quit / exit / /exit  leave (Ctrl-D and Ctrl-C at the prompt too)"""

# Slash commands that drive the hunt harness's own services (the bot, the economy, the outbox, filing). Every
# install has them (one edition, 2026-11-27); the set only tells the slash dispatcher these names are built in.
OPERATOR_COMMANDS = frozenset({"bot", "econ", "resumehunt", "stop", "outbox", "send", "clone", "bots", "route", "file"})


HELP_SECTIONS = (
    ("START HERE", "plain English works; common starts: /work, /plan, /hunt, /model", ()),
    ("LONG TASKS & CODE", "set an objective, plan it, work it, prove it",
     ("goal", "plan", "work", "tasks", "schedule", "init", "cd", "repo", "auto", "changes", "review", "undo", "bg",
      "hooks", "commands", "mcp")),
    ("HUNTING", "run and inspect a hunt; scope and evidence stay in code",
     ("hunt", "bot", "stophunt", "resumehunt", "stop", "program", "brief", "ledger", "chains", "report", "pay", "econ",
      "graph", "collab")),
    ("MODES & SAFETY", "choose the job, approvals and permissions",
     ("mode", "defender", "permissions", "approvals", "approve", "deny", "skipperms", "plain", "privacy", "sandbox")),
    ("MODELS & REASONING", "which model answers, how hard it thinks, what it can load",
     ("model", "lead", "deepseek", "cloud", "hf", "offline", "gpus", "deep", "gpu1", "reasoning", "effort",
      "thoughts", "raw", "tools", "bench")),
    ("WHILE IT WORKS", "watch, steer or cut into a running turn",
     ("btw", "agents", "agent", "jobs", "keys")),
    ("LEARNING", "lessons the worker writes for itself, and the procedures you approve",
     ("lessons", "learn", "skills")),
    ("SESSIONS & OUTPUT", "resume, export, copy and paginate",
     ("new", "sessions", "resume", "fork", "continue", "compact", "usage", "export", "copy", "top", "simple")),
    ("MESSAGES, FILES & OTHER", "outbox, attachments and imported repos",
     ("outbox", "send", "file", "comms", "@path", "clone", "bots")),
    ("HELP & EXIT", "this list, a health check, and how to leave", ("help", "doctor", "quit")),
)


_HELP_SECTION_BY_KEY = {key: title for title, _, keys in HELP_SECTIONS for key in keys}


def _agent_help_blocks():
    """Split AGENT_HELP into (intro, blocks) without changing the plain text that the tab completer reads.
    A block starts at a command line; its continuation lines keep their own indentation after wrapping."""
    (
        AGENT_HELP, re,
    ) = bind(
        "AGENT_HELP", "re",
    )
    intro, blocks, cur = [], [], None
    for raw in AGENT_HELP.splitlines():
        line = raw.rstrip()
        m = re.match(r"^  (/[a-z0-9]+)\b", line)
        if m:
            cur = {"key": m.group(1)[1:], "lines": [line]}
            blocks.append(cur)
            continue
        m = re.match(r"^  (↓ / ↑|@path|q / quit)", line)
        if m:
            key = "keys" if line.lstrip().startswith("↓") else ("@path" if line.lstrip().startswith("@path")
                                                                  else "quit")
            cur = {"key": key, "lines": [line]}
            blocks.append(cur)
            continue
        if cur is None:
            if line.strip():
                intro.append(line)
            continue
        if line.strip() and not line.startswith(" "):
            line = "      " + line   # a few old continuation lines started at column 0
        cur["lines"].append(line)
    for block in blocks:
        while block["lines"] and not block["lines"][-1].strip():
            block["lines"].pop()
    return intro, blocks


def _help_wrap(text, width, initial="", subsequent=""):
    (
        textwrap,
    ) = bind(
        "textwrap",
    )
    text = " ".join(str(text or "").split())
    if not text:
        return [initial.rstrip()]
    return textwrap.wrap(text, width=max(40, width), initial_indent=initial, subsequent_indent=subsequent,
                         break_long_words=False, break_on_hyphens=False) or [initial.rstrip()]


def _help_block_lines(block, width):
    """Color one command block and wrap it to the terminal. All of a block's original lines are joined first:
    the old help was manually wrapped, and re-wrapping each short line produced ragged three-word rows."""
    (
        T, _help_wrap, re,
    ) = bind(
        "T", "_help_wrap", "re",
    )
    text = " ".join(line.strip() for line in block["lines"] if line.strip())
    text = re.sub(r"\s*\|\s*", " | ", text)   # let the wrapper break long usage alternatives
    parts = _help_wrap(text, width, initial="  ", subsequent=" " * 27)
    out = []
    if parts:
        m = re.match(r"^(  (?:/\S+|↓ / ↑|@path|q / [a-z]+))(.*)$", parts[0])
        if m:
            out.append(T.bblue(m.group(1)) + T.dim(m.group(2)))
            out += [T.dim(p) for p in parts[1:]]
        else:
            out += [T.dim(p) for p in parts]
    return out


def help_text(width=None):
    """The /help screen: the same command documentation, grouped by the job instead of one long list."""
    (
        HELP_SECTIONS, T, _HELP_SECTION_BY_KEY, _agent_help_blocks, _help_block_lines, _help_wrap, shutil,
    ) = bind(
        "HELP_SECTIONS", "T", "_HELP_SECTION_BY_KEY", "_agent_help_blocks", "_help_block_lines", "_help_wrap",
        "shutil",
    )
    intro, blocks = _agent_help_blocks()
    if width is None:
        try:
            width = min(112, max(60, shutil.get_terminal_size((100, 24)).columns - 2))
        except Exception:  # noqa: BLE001 - a size lookup never breaks help
            width = 98
    grouped = {}
    for block in blocks:
        grouped.setdefault(_HELP_SECTION_BY_KEY.get(block["key"], "OTHER"), []).append(block)
    out = [T.byellow("GNOC CHAT · HELP"),
           T.dim("  Type plain English.")]
    titles = [title for title, _, _ in HELP_SECTIONS if title == "START HERE" or grouped.get(title)]
    if grouped.get("OTHER"):
        titles.append("OTHER")
    for line in _help_wrap("Sections: " + ", ".join(titles[1:]), width, initial="  ", subsequent="  "):
        out.append(T.dim(line))
    for title, blurb, keys in HELP_SECTIONS:
        items = grouped.pop(title, [])
        if title != "START HERE" and not items:
            continue
        order = {key: i for i, key in enumerate(keys)}
        items.sort(key=lambda b: order.get(b["key"], len(keys)))
        out.append("")
        head = f"── {title} "
        out.append(T.byellow(head) + T.dim("─" * max(4, width - len(head))))
        out.append(T.dim("  " + blurb))
        if title == "START HERE":
            for line in intro:
                out += [T.dim(p) for p in _help_wrap(line.strip(), width, initial="  ", subsequent="  ")]
        for block in items:
            out += _help_block_lines(block, width)
    for title, items in grouped.items():
        out.append("")
        head = f"── {title} "
        out.append(T.byellow(head) + T.dim("─" * max(4, width - len(head))))
        for block in items:
            out += _help_block_lines(block, width)
    out.append("")
    out.append(T.dim("  Tab completes /commands and @paths · q / Ctrl-D leaves"))
    return "\n".join(out)


def set_repo(agent, spec):
    """Point the agent at a repo (a folder, or a public remote cloned once) or back at the hunt workspace.

    A new repo starts a new conversation. The clone happens here, in the user-typed path only: a remote is
    shallow, cached under ~/.gnoc/repos, and reused only when its origin is the same repo.
    """
    (
        PLAIN, REPO_ALIASES, WS, _ACTIVE_ROOT, _rel_home, _repo_instructions, _system_root, attach_collab, dim,
        gnoc_goal, green, os, red, repo_is_live, root, say, white, yellow,
    ) = bind(
        "PLAIN", "REPO_ALIASES", "WS", "_ACTIVE_ROOT", "_rel_home", "_repo_instructions", "_system_root",
        "attach_collab", "dim", "gnoc_goal", "green", "os", "red", "repo_is_live", "root", "say", "white",
        "yellow",
    )
    spec = str(spec or "").strip()
    if not spec:
        say(red("  usage: /repo <path|url|owner/repo|off>"))
        return False
    alias = REPO_ALIASES.get(spec.lower(), spec)

    def _local_path(value):
        """A folder, resolved the way a person means it in a chat.

        An absolute/~ path is itself. A relative one is tried against the shell's cwd first (normal CLI
        semantics), then against the repo that is already open: `/repo src` in a chat launched from home must
        find the active repo's src/, not ~/src.
        """
        p = os.path.realpath(os.path.expanduser(value))
        if os.path.isdir(p) or os.path.isabs(os.path.expanduser(value)):
            return p
        alt = os.path.realpath(os.path.join(root(), value))
        return alt if os.path.isdir(alt) else p

    remote = None
    local = _local_path(alias)
    if gnoc_repo.looks_remote(alias):
        try:
            remote = gnoc_repo.parse_remote(alias)
        except gnoc_repo.RepoError as e:
            say(red(f"  {e}"))
            return False
        if remote is not None and os.path.isdir(local) and not re.match(r"^(?:[a-z][a-z0-9+.-]*://|git@)", alias, re.I):
            # a real folder literally named owner/repo (the active repo's src/pkg, say) is a FOLDER: the
            # relative-path widening above must not turn it into a GitHub clone.
            remote = None
    if spec.lower() == "off":
        path = WS
    elif remote is None:
        path = local
    else:
        if STATE.offline[0] and remote.network:
            say(red("  offline mode: cloning a public repo needs the internet. "
                    "/offline off (or gnoc chat without --offline) lets it clone."))
            return False
        what = f"{remote.owner}/{remote.name}" + (f" branch {remote.branch}" if remote.branch else "")
        say(dim(f"  cloning {what} from {remote.host} (shallow, into {_rel_home(gnoc_repo.cache_root())}) ..."))
        try:
            path, note = gnoc_repo.obtain(alias)
        except gnoc_repo.RepoError as e:
            say(red(f"  {e}"))
            return False
        if note:
            say(dim(f"  {note}"))
    if not os.path.isdir(path):
        say(red(f"  no such directory: {spec}"))
        return False
    if _system_root(path):
        say(red("  pick a project directory, not / or a system dir"))
        return False
    changed = path != root()
    _ACTIVE_ROOT[0] = path
    agent.s["repo"] = path
    gnoc_goal.scope_to(path)  # a different repo has its own goal, not the one from the repo we were just in
    if changed:
        agent.s["history"] = []
    if not PLAIN[0]:
        old_collab = agent.s.get("collab") or {}
        agent.s.pop("collab", None)
        if old_collab and agent.ctx.program == old_collab.get("program"):
            agent.s.pop("program", None)
            agent.s.pop("program_src", None)
        if attach_collab(agent, path):
            agent.save()
    agent.save()
    ifile, _ = _repo_instructions(path) if path != WS else ("SPINE.md / CLAUDE.md", "")
    say(green("● ") + white("repo ") + _rel_home(path)
        + dim(f"  ·  {gnoc_repo.summary(path)}  ·  instructions: {ifile}"
              + ("  ·  new conversation" if changed else "")))
    if repo_is_live(path):
        say(yellow("  ⎿  this checkout is served live by pm2: every edit and shell change asks you first"))
    return True


def launch_dir(cwd=None):
    """Where a bare `gnoc chat` should open: the directory it was LAUNCHED in, like any CLI coding agent.
    Returns (root, program, why). Inside the hunt workspace the root stays the workspace (that IS the project
    there), and launching inside targets/<program>/ also selects that program. Anywhere else, INCLUDING ~, opens
    right there (the user 2026-11-06: "just like a normal cli coding agent ... without it wanting to change the
    dir to the workspace"); the secret guards, not the root, keep credential stores out. A system root (/, /etc,
    /usr, ...) is never a working dir, so it opens in ~ instead. Only a vanished cwd returns None."""
    (
        WS, _system_root, gnoc_collab, os, resolve_program,
    ) = bind(
        "WS", "_system_root", "gnoc_collab", "os", "resolve_program",
    )
    try:
        cwd = os.path.realpath(cwd or os.getcwd())
    except OSError:  # the launch dir was deleted under the shell
        return None, None, ""
    if cwd == WS or cwd.startswith(WS + os.sep):
        prog = resolve_program(cwd)
        if prog:
            return WS, prog, f"launched in targets/{prog}"
        if cwd != WS and not cwd.startswith(os.path.join(WS, "targets") + os.sep):
            handoff = gnoc_collab.find_handoff(cwd)
            if handoff:
                return cwd, None, f"collaborator handoff {os.path.basename(handoff)}"
        return WS, prog, "launched in the hunt workspace"
    if not os.path.isdir(cwd):
        return None, None, ""
    home = os.path.realpath(os.path.expanduser("~"))
    if _system_root(cwd):
        return home, None, f"launched in {cwd}, a system dir: opened in ~"
    handoff = gnoc_collab.find_handoff(cwd)
    if handoff:
        return cwd, None, f"collaborator handoff {os.path.basename(handoff)}"
    return cwd, None, "launched here"


_SYSTEM_ROOTS = ("/etc", "/usr", "/var", "/opt", "/proc", "/sys", "/dev", "/root", "/boot", "/bin", "/sbin", "/lib")


def _system_root(d):
    """/, /home and the OS trees: never a working dir (read/write/bash are contained to it)."""
    (
        _SYSTEM_ROOTS, os,
    ) = bind(
        "_SYSTEM_ROOTS", "os",
    )
    rd = os.path.realpath(d)
    return rd in ("/", "/home") or any(rd == r or rd.startswith(r + os.sep) for r in _SYSTEM_ROOTS)


def resolve_launch_root(here, here_prog, resume, saved_repo):
    """Where a chat with NO explicit --repo should open. Returns (root, repo_to_save, program_or_None).

    The launch directory ALWAYS wins (`cd ~/code/thing && gnoc chat` works, and launching in the hunt
    workspace drops any stale pin). A saved repo is reopened ONLY when continuing a prior conversation (-c):
    a fresh launch must never resurrect whatever repo the last chat left pinned (that showed a stale scratch
    dir when the user opened a new chat from their home, 2026-10-23). A fresh launch from a non-project dir
    (home, /) used to fall back to the workspace; it now opens in ~ like any CLI coding agent. Continuing (-c)
    from ~ still reopens the repo that conversation was in. Only a vanished launch dir falls back to the workspace."""
    (
        WS, os,
    ) = bind(
        "WS", "os",
    )
    home = os.path.realpath(os.path.expanduser("~"))
    if here and not (here == home and resume and saved_repo and os.path.isdir(saved_repo)):
        return here, (None if here == WS else here), here_prog
    if resume and saved_repo and os.path.isdir(saved_repo):
        return saved_repo, saved_repo, None
    return WS, None, None


def copy_cmd(agent, arg):
    """/copy [n|all|answer]: put the last answer's code (or the whole answer) on the clipboard, byte-exact."""
    (
        T, dim, green, last_answer, red, white, yellow,
    ) = bind(
        "T", "dim", "green", "last_answer", "red", "white", "yellow",
    )
    ans = last_answer(agent)
    if not ans:
        return red("  nothing to copy yet")
    blocks = T.code_blocks(ans)
    if arg in ("answer", "a", "text"):
        text, what = ans, "the whole answer (raw Markdown)"
    elif not blocks:
        return yellow("  the last answer has no code block; /copy answer copies the whole answer")
    elif arg == "all":
        text, what = "\n\n".join(c for _, c in blocks), f"all {len(blocks)} code blocks"
    elif arg.isdigit():
        n = int(arg)
        if not 1 <= n <= len(blocks):
            return red(f"  the last answer has {len(blocks)} code block(s): /copy 1..{len(blocks)}")
        text, what = blocks[n - 1][1], f"code block {n} ({blocks[n - 1][0] or 'code'})"
    elif not arg:
        text, what = blocks[-1][1], f"the last code block ({blocks[-1][0] or 'code'})"
    else:
        return red("  usage: /copy [n|all|answer]")
    how = T.copy_to_clipboard(text)
    return green("● ") + white("copied ") + what + dim(f"  ·  {len(text.splitlines())} lines via {how}")


def nth_answer(agent, n=1):
    """The nth most recent assistant answer (1 = the last), from the conversation history itself."""
    for m in reversed(agent.s.get("history") or []):
        if m.get("role") == "assistant" and (m.get("content") or "").strip():
            n -= 1
            if n == 0:
                return m["content"]
    return ""


def page_answer(agent, arg, end=False):
    """/top [n] and /bottom [n] (PgUp / PgDn at the prompt): a long answer streams past, so open it in
    `less -R` at its top or its end. Not a terminal, or no less: print it (the bottom prints its tail).
    Returns the text to print, or None when the pager showed it."""
    (
        T, contextlib, dim, nth_answer, red, shutil, subprocess, sys,
    ) = bind(
        "T", "contextlib", "dim", "nth_answer", "red", "shutil", "subprocess", "sys",
    )
    arg = (arg or "").strip()
    if arg and (not arg.isdigit() or int(arg) < 1):
        return red(f"  usage: /{'bottom' if end else 'top'} [n]   (n = how many answers back, 1 = the last)")
    n = int(arg or 1)
    ans = nth_answer(agent, n)
    if not ans:
        return dim("  no answer yet in this conversation" if n == 1 else f"  there is no answer {n} back")
    text = T.render_markdown(ans)
    less = shutil.which("less")
    if less and sys.stdin.isatty() and sys.stdout.isatty():
        with contextlib.suppress(OSError):
            subprocess.run([less, "-R"] + (["+G"] if end else []), input=text, text=True)
            return None
    which = "the last answer" if n == 1 else f"answer {n} back"
    if end:
        return dim(f"── bottom of {which} ──") + "\n" + "\n".join(text.splitlines()[-25:])
    return dim(f"── top of {which} ──") + "\n" + text


def note_program_source(agent, how):
    """Record where the active program came from. It persists across launches, and a prompt showing [globex]
    gave no hint whether that was this folder, an old session or an explicit /program."""
    agent.s["program_src"] = {"program": agent.ctx.program, "how": how, "sid": agent.s.get("sid")}


def _ask_collab(preview):
    """The yes/no before a handoff document becomes an engagement: which file, and exactly which hosts it would
    put in scope. Default no."""
    (
        T, dim, say, sys, yellow,
    ) = bind(
        "T", "dim", "say", "sys", "yellow",
    )
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None
    hosts = preview.get("hosts") or []
    say(yellow("  a partner handoff document is here: ") + T.byellow(preview["handoff"]))
    say(dim("  importing it makes it an authorized engagement: these hosts would be IN SCOPE for probes"))
    for h in hosts[:20]:
        say("    " + h)
    if len(hosts) > 20:
        say(dim(f"    ... {len(hosts) - 20} more"))
    if not hosts:
        say(dim("    (none parsed: nothing would pass the scope gate until the document has a scope section)"))
    if preview.get("out"):
        say(dim("  out of scope: " + ", ".join(preview["out"][:10])))
    try:
        ans = input(yellow("  Is this a real engagement you are authorized to test? [y/N] > ")).strip().lower()
    except (EOFError, OSError):
        return False
    return ans in ("y", "yes")


def attach_collab(agent, project=None, handoff_path=None, explicit=False):
    """Make a project's partner handoff the active engagement, if it has one.

    `handoff_path` imports a specific document the partner sent (its parent becomes the project).
    Never enters the hunt stance: opening the folder is not an order to hunt. A handoff that was
    found but could not be imported is said out loud (usually a scanned PDF with no text layer).
    """
    (
        WS, _graph_import_scope, dim, gnoc_collab, os, root, say, sys, yellow,
    ) = bind(
        "WS", "_graph_import_scope", "dim", "gnoc_collab", "os", "root", "say", "sys", "yellow",
    )
    if handoff_path:
        project = os.path.dirname(os.path.realpath(os.path.expanduser(str(handoff_path))))
    else:
        project = os.path.realpath(project or root())
    if project == WS or project.startswith(os.path.join(WS, "targets") + os.sep):
        return None
    try:
        ask = None if explicit else (lambda pv: bool(_ask_collab(pv)))
        if not explicit and not (sys.stdin.isatty() and sys.stdout.isatty()):
            ask = None   # no human to ask: attach() imports nothing and says it is pending
        got = gnoc_collab.attach(agent.ctx, project, handoff_path=handoff_path, approve=ask, explicit=explicit)
    except Exception as e:  # noqa: BLE001 - a broken handoff must never block the chat from opening
        say(yellow("  collaborator handoff could not be imported: ") + dim(f"{type(e).__name__}: {e}"))
        return None
    if not got:
        return None
    if not got.get("ok"):
        say(yellow("  collaborator handoff " + ("scope revoked: " if got.get("revoked") else "not imported: "))
            + dim(str(got.get("reason"))[:200]))
        return None
    _graph_import_scope(agent.ctx.program)
    return got


def program_origin(agent):
    """'launched in targets/gatewayco', 'set with /program', 'saved from an earlier session (...)', ..."""
    prog = agent.ctx.program
    if not prog:
        return ""
    src = agent.s.get("program_src") or {}
    if src.get("program") != prog:
        return "set by the agent this session (a tool, /hunt or a folder change)"
    if src.get("sid") != agent.s.get("sid"):
        return f"saved from an earlier session: {src.get('how') or 'origin not recorded'}; /program clear drops it"
    return src.get("how") or "origin not recorded"


DEFENDER_USAGE = ("usage: /defender [status|sweep|respond|setup] · network · gateway [add|rm <ip>|ssh <dst>|"
                  "platform <name>|iface <name>|api <url>|test] · subnet [add|rm <cidr>] · baseline accept [network|host] · vulnwatch [run|on|off] · wlan · "
                  "endpoint [list|add|rm|test|sweep <user@host>] · enforce block-ip|block-mac|deauth <ip|mac> | "
                  "isolate <dst> | pause|kill <dst> <pid> · alerts [ack|resolve|suppress <id>] · "
                  "triage [<IR-id>|contain|close|note] · auto on|off [secs] · watch on|off [secs] · "
                  "target local|<user@host> · allow|deny block|contain|sysctl|quarantine|scan|auto · "
                  "level critical|high|medium|low|info · notify on|off · "
                  "schedule every 30m|hourly|daily 03:00|show|off (a headless sweep from cron, no model) · "
                  "summary [days] (what it did and found, default 7) · "
                  "admin <ip/cidr> · undo [last|all|d3] · journal · install")


def defender_cmd(agent, rest):
    """/defender: everything the user types to control the defender. Typed by them, so this is where the
    remote target, network scope and auto-defense permissions can be set without the model's say-so."""
    (
        defender_command, dim, hang, say,
    ) = bind(
        "defender_command", "dim", "hang", "say",
    )
    text = defender_command(agent, rest)
    if text:
        # each line wrapped to the terminal with a hanging indent: the usage line ran 400+ columns and the
        # terminal broke it at column 0, under the prompt's own margin (2026-11-18 QA/QC)
        if str(text).count("\n") > 2:
            say("\n".join(dim(hang("  " + line, indent=4)) for line in str(text).split("\n")))
        else:
            say(str(text))
    return text


_KEY_COMMAND = re.compile(r"(?i)^\s*/(cloud|hf|claude|anthropic|openai|gpt|chatgpt|gemini|google|xai|grok|meta|llama|"
                          r"mistral|deepseek|moonshot|kimi|qwen|alibaba)\b.*\b(api|key|token|add)\b")


def _model_ready(one_shot, boot=None):
    """True when a configured model can answer. A fresh install has none: an interactive chat runs the guided
    setup (gnoc_setup) right here, a one-shot says what to do in one line. It used to be eight seconds of
    "Retrying" and then `URLError: Connection refused` (2026-11-19). GNOC_NO_SETUP=1 skips the check."""
    (
        dim, os, role_spec, say, set_role, sys, yellow,
    ) = bind(
        "dim", "os", "role_spec", "say", "set_role", "sys", "yellow",
    )
    if os.environ.get("GNOC_NO_SETUP") == "1":
        return True
    import gnoc_setup
    ok, why = gnoc_setup.usable(role_spec("lead"), role_spec("worker"))
    _MODEL_READY[0] = ok
    if ok:
        return True
    interactive = not one_shot and sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        say(yellow("  gnoc has no working model yet: ") + dim(f"{why}.  Run  gnoc setup  to set one up."))
        return False
    if gnoc_setup.skipped_recently():
        say(yellow("  no model is set up yet, so messages cannot be answered") + dim("  ·  /setup when you are ready"))
        return True
    if boot is not None:
        boot.done()   # the "starting..." notice must not print into the middle of the walk-through
    _MODEL_READY[0] = gnoc_setup.first_run(set_role, reason=why)   # automatic first; a no opens the menu
    return True


_MODEL_READY = [True]   # False after a start that found no working model and set none up: the banner says so


def _scrub_history(readline):
    """Drop every history line that carries a credential: `/deepseek api <key>`, `/cloud add ... <key>`, or any line
    holding a known secret value. The history file is plain text the agent can read_file (QAQC r2)."""
    import gnoc_secrets
    try:
        n = readline.get_current_history_length()
        lines = [readline.get_history_item(i) or "" for i in range(1, n + 1)]
        whole = "\n".join(lines)
        if not any(_KEY_COMMAND.search(x) for x in lines) and gnoc_secrets.redact(whole) == whole:
            return   # the usual case: one pass over the whole history, not one redact() per line at every start
        for i in range(n, 0, -1):
            line = readline.get_history_item(i) or ""
            # redact(), not find(): find() leaves out the research identities (they may be SENT), but none of
            # them belongs in a plain-text history file either
            if _KEY_COMMAND.search(line) or gnoc_secrets.redact(line) != line:
                readline.remove_history_item(i - 1)
    except Exception:  # noqa: BLE001 - history is a convenience; never break the prompt over it
        pass


def _plugins_session(agent, phase):
    """Phase 8 plugins: at the start, register the enabled plugins' tools and fire session_start; at the end, fire
    session_end. Observe-only events: a broken plugin layer never stops the chat from opening or closing."""
    import gnoc_agent
    import gnoc_plugins
    sid = (getattr(agent, "s", None) or {}).get("sid")
    try:
        if phase == "start":
            gnoc_plugins.sync_tools(gnoc_agent.TOOLS, gnoc_agent.CODE_TOOLS, gnoc_agent.ACTING_TOOLS)
            gnoc_plugins.session_start(sid)
        else:
            gnoc_plugins.session_end(sid)
    except Exception:  # noqa: BLE001
        pass


def repl(legacy, one_shot=None, repo=None, skip_perms=False, offline_mode=False, resume=None, plain=False,
         fork=None, staged_prompt=None):
    (
        AGENT_DIR, Agent, BAR, EFFORT, EFFORTS, INTERRUPT, MON, NEXT_SUGGESTION, OFFLINE, PLAIN, SKIP_PERMS, SPIN,
        SPLIT_FLAG, STEPS_OVERRIDE, T, TYPED, WS, _ACTIVE_ROOT, _BootNotice, _CHAT_SID, _GOAL_SEEN, _file_marker,
        _goal_field, _goal_reenter, _graph_import_scope, _guard_tty, _last_answer, _owl_static, _plan_field,
        _plan_request, _read, _rel_home, _repo_instructions, _restore_tty, _set_title, _setup_completion,
        _short_model, _title_of, _title_text, _tool_tokens, attach_collab, auto_hunt_request, contextlib, dim,
        echo_prompt, effort, expand_mentions, gnoc_goal, gnoc_plan, gnoc_session, gnoc_ws, goal_after_turn,
        goal_before_stop, green, handle_slash, hang, launch_dir, note_program_source, offline, os, program_origin,
        prompt_ctx_pct, readline, red, resolve, resolve_launch_root, root, say, set_repo, shutil, split_up,
        suggest_next_prompt, sys, turn_tools, wait_reflection, white, yellow,
    ) = bind(
        "AGENT_DIR", "Agent", "BAR", "EFFORT", "EFFORTS", "INTERRUPT", "MON", "NEXT_SUGGESTION", "OFFLINE",
        "PLAIN", "SKIP_PERMS", "SPIN", "SPLIT_FLAG", "STEPS_OVERRIDE", "T", "TYPED", "WS", "_ACTIVE_ROOT",
        "_BootNotice", "_CHAT_SID", "_GOAL_SEEN", "_file_marker", "_goal_field", "_goal_reenter",
        "_graph_import_scope", "_guard_tty", "_last_answer", "_owl_static", "_plan_field", "_plan_request",
        "_read", "_rel_home", "_repo_instructions", "_restore_tty", "_set_title", "_setup_completion",
        "_short_model", "_title_of", "_title_text", "_tool_tokens", "attach_collab", "auto_hunt_request",
        "contextlib", "dim", "echo_prompt", "effort", "expand_mentions", "gnoc_goal", "gnoc_plan", "gnoc_session",
        "gnoc_ws", "goal_after_turn", "goal_before_stop", "green", "handle_slash", "hang", "launch_dir",
        "note_program_source", "offline", "os", "program_origin", "prompt_ctx_pct", "readline", "red", "resolve",
        "resolve_launch_root", "root", "say", "set_repo", "shutil", "split_up", "suggest_next_prompt", "sys",
        "turn_tools", "wait_reflection", "white", "yellow",
    )
    SKIP_PERMS[0] = bool(skip_perms)
    interactive = sys.stdin.isatty()
    import gnoc_bg   # headless browsers an earlier chat left running are closed; SIGHUP/SIGTERM exit cleanly
    gnoc_bg.chat_started(say=lambda m: say(dim(m)))
    MON.reset_session()   # /usage describes THIS launch, not every launch before it
    _boot = _BootNotice(interactive and not one_shot and not plain)
    agent = Agent(interactive=interactive, resume=resume)
    if resume and getattr(agent, "resume_failed", False):
        if resume not in ("last",):
            # an id or a number that matches nothing is a mistake to report, not a reason to start somewhere else
            if not getattr(agent, "resume_blocked", None):
                say(red(f"  no saved conversation matches {resume!r}")
                    + dim("  ·  /sessions lists them; gnoc chat -r alone shows the picker"))
            sys.exit(1)
        if not getattr(agent, "resume_blocked", None):
            say(dim("  no saved conversation to continue: this is a new one"))
        resume = None   # a new conversation opens where it was launched, never in the last chat's repo
    if fork:
        got = agent.fork(fork)
        if got:
            say(green("● ") + f"forked: {got['title']}" + dim(f"  ({got['n']} messages, new conversation)"))
        else:
            say(red("  no saved conversation to fork (/sessions lists them)"))
    _CHAT_SID[0] = agent.s.get("sid")  # the goal is owned by THIS conversation; a fresh chat shows none
    # HUNTING IS BOUND TO THIS CHAT (GreyNOC, 2026-11-02): registering here is what opens the gate for
    # the probe engines, and the teardown armed inside kills every lane this chat started when it exits.
    gnoc_session.open_session(sid=agent.s.get("sid"), program=agent.ctx.program)
    if agent.s.get("effort") in EFFORTS:
        EFFORT[0] = agent.s["effort"]
    if isinstance(agent.s.get("steps_override"), int):
        STEPS_OVERRIDE[0] = agent.s["steps_override"]
    if offline_mode or agent.s.get("offline"):
        OFFLINE[0] = True
        __import__("gnoc_privacy").SESSION_LOCAL[0] = True   # --offline / a resumed /offline chat: local-only
    if plain or agent.s.get("plain"):
        PLAIN[0] = True
    here, here_prog, why = launch_dir()
    was_prog = agent.ctx.program
    if was_prog and (agent.s.get("program_src") or {}).get("program") != was_prog:
        agent.s["program_src"] = {"program": was_prog, "how": "origin not recorded", "sid": None}
    if repo:
        if not set_repo(agent, repo):
            sys.exit(1)   # `gnoc chat --repo /no/such/dir` said "no such directory" and exited 0 (entry-point drive)
    else:
        new_root, new_repo, prog = resolve_launch_root(here, here_prog, resume, agent.s.get("repo"))
        _ACTIVE_ROOT[0] = new_root
        dirty = agent.s.get("repo") != new_repo
        agent.s["repo"] = new_repo
        if prog:
            # the folder wins over a program saved by an earlier session: launched in targets/gatewayco means gatewayco
            agent.s["program"] = prog
            agent.s["stance"] = "hunt"   # launching inside targets/<program>/ is itself the order to hunt it
            note_program_source(agent, f"launched in targets/{prog}"
                                + (f", replacing {was_prog} from an earlier session"
                                   if was_prog and was_prog != prog else ""))
            dirty = True
        if dirty:
            agent.save()
    if not PLAIN[0]:
        _graph_import_scope(agent.ctx.program)   # a target launched with/inside its folder gets its assets
        collab_now = attach_collab(agent)
        if collab_now:
            agent.save()   # program + collab scope are session settings: the next turn reads them
    gnoc_goal.scope_to(root())  # the goal is per-repo: a goal set in another project never leaks into this chat
    # FIRST OPEN in a repo: Claude-Code-strong workspace setup. An instruction file means the repo already
    # knows itself; none means gnoc chat offers to write GNOC.md (stack, commands, layout) + gchat.md once,
    # interactively, and only ever into the repo it just opened. One-shots stay silent.
    # Since 2026-11-06 this is a one-line hint, never a blocking [Y/n] question: a normal CLI coding agent opens
    # straight to the prompt, and ~ (now a valid launch dir) must never get a GNOC.md written into it by Enter.
    if root() != WS and root() != os.path.realpath(os.path.expanduser("~")) and gnoc_ws.first_open(root()) \
            and not one_shot and sys.stdin.isatty() and sys.stdout.isatty():
        say(dim(f"  first time in {_rel_home(root())}  ·  /init sets up the workspace (GNOC.md + gchat.md), "
                "/init project <name> scaffolds a new project"))
    if not one_shot or not one_shot.startswith("/"):
        if not _model_ready(one_shot, _boot):
            return
    _plugins_session(agent, "start")
    if one_shot:
        agent.s["_one_shot"] = True   # this process answers once and exits: what bg starts does not outlive it
        _guard_tty()  # a one-shot turn runs the typeahead too: Ctrl-C mid-turn must not leave the shell echo-off
        try:
            if one_shot.startswith("/"):
                # typed-only marker: this exact string object is what he typed on the command line. /file checks
                # the IDENTITY of its line against it, so no other path (model text, a tool, a goal) can pass it.
                agent._typed_line = one_shot
                try:
                    handle_slash(agent, one_shot, legacy)
                finally:
                    agent._typed_line = None
            elif auto_hunt_request(one_shot):
                prog, goal = auto_hunt_request(one_shot)
                agent.hunt(prog or agent.ctx.program, goal)
            else:
                typed = expand_mentions(one_shot)
                agent.s["_typed"] = typed     # HIS words this turn (the question gate tells them from gnoc's prompts)
                agent.turn(typed)
        except KeyboardInterrupt:
            SPIN.stop()
            say(yellow("\n  interrupted"))
        finally:
            _restore_tty()
            _plugins_session(agent, "end")
        wait_reflection()
        return
    hist = os.path.join(AGENT_DIR, "readline-history")
    with contextlib.suppress(OSError):
        readline.read_history_file(hist)
    _scrub_history(readline)   # an old file may still hold a key typed at /deepseek api (QAQC r2)
    with contextlib.suppress(Exception):  # GNU readline only; libedit just lacks the shortcut
        # PgUp / PgDn at the prompt: jump to the top / bottom of the last answer. Up/Down stay history (and
        # sub-agent focus mid-turn, where the typeahead swallows PgUp/PgDn); Home/End stay cursor moves.
        # \C-a\C-k first: the line is cut (Ctrl-Y brings it back) instead of being submitted with "/top" glued
        # on, which sent a half-typed message to the model as a turn (QAQC 2026-11-19)
        readline.parse_and_bind(r'"\e[5~": "\C-a\C-k/top\n"')
        readline.parse_and_bind(r'"\e[6~": "\C-a\C-k/bottom\n"')
    with contextlib.suppress(Exception):
        # The input line is pinned to the last two rows, OUTSIDE the scroll region. A typed line longer than
        # the window wrapped onto a third row that does not exist: the text folded back over the prompt's own
        # rows and Ctrl-U left the debris behind (2026-10-24, 120 columns). Horizontal scrolling keeps the edit
        # line on one row and slides it under the caret instead, like a shell with the same setting.
        readline.parse_and_bind("set horizontal-scroll-mode on")
    lead, lh = resolve("lead")
    worker, wh = resolve("worker")
    _boot.done()   # the probe is over: the real banner takes it from here
    roles = (f"lead and worker {_short_model(lead)}@{lh}" if (lead, lh) == (worker, wh)
             else f"lead {_short_model(lead)}@{lh}  ·  worker {_short_model(worker)}@{wh}")
    if not _MODEL_READY[0]:
        roles = "no model ready yet  ·  /setup"
    say(hang(_owl_static(1.0) + " " + T.byellow("gnoc") + dim("  local agent on your GPUs  ·  ") + T.blue(roles),
             indent=2))
    if os.path.exists(SPLIT_FLAG) and not split_up():
        # the flag says "run everything on the split model"; the server is not answering, so these roles are
        # NOT what was asked for. Saying nothing here is how a session silently runs on the small model.
        want = (_read(SPLIT_FLAG).split(maxsplit=1) + ["?"])[1].strip()
        say(hang(T.bred("  ⚠ split requested but NOT serving: ") + red(f"you are not on {_short_model(want)[:60]}")
                 + dim(f"  (running {_short_model(lead)}@{lh}; gnoc split status says why, gnoc split down clears "
                       "the flag)"), indent=4))
    elif lh == "split":
        # Split trades latency for model size, and a tool-driven turn is the worst case for it: the system prompt
        # plus the tool schemas are ~14k tokens, and processing that across the RPC link took over 10 minutes per
        # call (measured 2026-10-22). Thinking on top of that returns an EMPTY answer when the budget runs out.
        # Say so up front: a silent 10-minute turn is indistinguishable from a hang.
        say(hang(T.byellow("  ⚠ on the split model: ") + yellow("one tool-driven turn costs minutes, not seconds")
                 + dim(f"  (~{_tool_tokens(turn_tools(False, False)) // 1000}k tokens of tool schemas go over the "
                       "RPC link every call)"), indent=4))
        if effort()["qwen_think"]:
            say(hang(dim("     thinking is ON at this effort, which can spend the whole budget and answer EMPTY: ")
                     + T.byellow("/effort medium") + dim(" turns it off, or ") + T.byellow("gnoc split down")
                     + dim(" goes back to the two separate GPUs"), indent=5))
    if not one_shot:
        with contextlib.suppress(Exception):
            _hint = __import__("gnoc_setup").engine_hint()
            if _hint:
                say(hang(T.byellow("  ◇ engine: ") + dim(_hint), indent=4))
    if offline():
        say(hang(T.byellow("  ⦸ offline: ") + yellow("local GPUs only, no cloud models")
                 + dim("  (gates run locally; /offline off to allow cloud workers)"), indent=4))
    if SKIP_PERMS[0]:
        say(hang(T.bred("  ⚠ skip-permissions ON: ") + red("writes, shell, non-GET HTTP, cloud workers and live-repo "
                                                          "edits run without asking") + dim("  (scope gate and deny "
                                                                                         "lists still enforced)"), indent=4))
    if here and here != WS and not repo:
        ifile, _ = _repo_instructions(here)
        say(hang(dim("  ") + white("repo ") + _rel_home(here) + dim(f"  ·  instructions: {ifile}  ·  {why}"
                                                                     "  ·  /repo off for the hunt workspace"), indent=4))
    # every banner row goes through hang(): at 80 columns these two folded at column 0 (2026-10-24)
    say(hang(dim(f"  dir {_rel_home(root())}  ·  "
                 + (f"program {agent.ctx.program}  ·  " if agent.ctx.program else "") + f"effort {EFFORT[0]}  ·  "
                 f"auto-approve {'ON' if agent.ctx.auto else 'off'}  ·  /help  ·  q to leave"), indent=4))
    if agent.ctx.program:
        say(hang(dim(f"  program {agent.ctx.program}: {program_origin(agent)}"), indent=4))
    collab_now = agent.s.get("collab") or {}
    if collab_now:
        n_hosts = len(collab_now.get("hosts") or [])
        scope_row = (f"  collab handoff {collab_now.get('handoff_rel') or collab_now.get('handoff')}"
                     f"  ·  {n_hosts} in scope")
        say(hang((dim(scope_row) if n_hosts else yellow(scope_row + " - NONE PARSED, probes will refuse"))
                 + dim("   /collab for detail"), indent=4))
    goal_now = gnoc_goal.one_line(shutil.get_terminal_size((100, 24)).columns - 12, owner=agent.s.get("sid"))
    if goal_now:  # it steers every turn from inside the system prompt: show it where he can see it
        say(hang(T.blue("  ◎ goal  ") + T.white(goal_now) + dim("   /goal for detail, /goal clear to drop it"), indent=4))
        _GOAL_SEEN[0] = gnoc_goal.fingerprint(owner=agent.s.get("sid"))
    plan_now = gnoc_plan.load(agent.s.get("sid"))
    if plan_now:  # the plan shows in the banner AND rides the prompt bar; /plan reprints the panel
        d, n = gnoc_plan.progress(plan_now)
        say(hang(T.blue("  ▣ plan  ") + T.white(f"{d}/{n} · " + " ".join(str(plan_now.get('goal') or '').split())[:70])
                 + dim("   /plan for the full plan, /plan go implements it"), indent=4))
    if agent.s.get("plan_mode"):
        say(hang(T.bblue("  💡 plan mode ") + dim("every message proposes a plan first; /plan off to unpin"), indent=4))
    if agent.s["history"]:
        say(hang(dim(f"  resumed: {_title_of(agent.s['history'])}  ({len(agent.s['history'])} messages)"), indent=4))
    else:
        say(hang(dim("  new conversation  ·  /resume brings back the last one, /sessions lists them"), indent=4))
    _guard_tty()
    _setup_completion()
    _set_title(_title_text(agent))

    def prompt_for():
        pct = prompt_ctx_pct(agent)
        ctx = f"ctx {pct}%⚠" if pct >= 88 else f"ctx {pct}%"
        # no bug bounty program active: the field is simply not there. "no program" on every prompt of a coding
        # or everyday chat read as something missing (GreyNOC 2026-11-21).
        return T.prompt(agent.ctx.program or None, _rel_home(root()),
                        "skip-perms" if SKIP_PERMS[0] else None, _goal_field(), _plan_field(), ctx)
    if os.environ.get("GNOC_BOTTOM_BAR", "1") != "0":
        BAR.prompt_fn = prompt_for
        BAR.enable()   # GNOC_BOTTOM_BAR=0 keeps the old scrolling prompt
    if staged_prompt:
        # gnoc chat -p <prompt>: staged for the first turn, the REPL stays open. raw=True: a prompt that
        # begins with /btw, /gpu1 or ! is still a prompt, not a typeahead side note.
        TYPED.push(staged_prompt, raw=True)
    while True:
        try:
            say("")
            staged = TYPED.pop()
            if staged is not None:
                # A STAGED LINE IS ECHOED THE SAME WAY A TYPED ONE IS. read_line() strips readline's
                # \001..\002 width markers and echoes only the prompt's LAST row; this path did neither,
                # so every typeahead line (and gnoc chat -p) printed 22 pairs of control bytes and
                # repeated the whole two-row ┌─[gnoc] box - the chrome-doubling already fixed for the
                # typed echo on 2026-10-24. Measured in a pty 2026-11-03: staged carried 22 \001 + 22
                # \002 over 2 rows, typed 0 over 1. .strip() too: without it a staged " q" missed the
                # leave check and a staged " /goal ..." was sent to the model as prose.
                line = staged.strip()
                say(echo_prompt(prompt_for(), line))
            else:
                line = BAR.read_line(prompt_for()).strip()
        except (EOFError, KeyboardInterrupt):
            say("")
            with contextlib.suppress(Exception):
                closing = goal_before_stop("leaving the chat")
                if closing:
                    say(closing)
            break
        if line in ("q", "quit", "exit"):
            with contextlib.suppress(Exception):
                closing = goal_before_stop("leaving the chat")
                if closing:
                    say(closing)
            break
        if not line:
            continue
        if line.strip().lower() in ("clear", "cls"):
            # a shell habit, not a message: "clear" went to the model, which cleared its plan (GreyNOC's desktop,
            # 2026-11-23). Clear the screen; /new starts a new conversation.
            sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
            sys.stdout.flush()
            continue
        # Ctrl-O: the message typed so far stays, a file picker asks what to attach, and the pick becomes
        # an @path mention that the expansion below turns into the file's content.
        rest_before_file = _file_marker(line)
        if rest_before_file is not None:
            NEXT_SUGGESTION[0] = "@"
            pick = ""   # Ctrl-D at the first attach left `pick` unbound; Ctrl-C here killed the chat (QAQC 2026-11-19)
            with contextlib.suppress(EOFError, KeyboardInterrupt):
                pick = BAR.read_line(T.prompt("attach file")).strip()
            if not pick or pick == "@":
                say(dim("  nothing attached"))
                continue
            line = (rest_before_file + " " if rest_before_file else "") \
                + (pick if pick.startswith("@") else "@" + pick)
        # @-mentions attach file content to GreyNOC's own message; slash commands never get expanded.
        if not line.startswith("/"):
            line = expand_mentions(line)
        # Nothing a command does may kill the chat: a Ctrl-C that lands outside turn()'s own handler (the
        # ultra planner's first model call, /review, /report, /hf ...) comes back to the prompt, and any
        # other error is printed. Only q / Ctrl-D / Ctrl-C at the prompt itself end the session.
        try:
            if line.startswith("/"):
                agent._typed_line = line   # read from the keyboard: the typed-only marker /file checks (identity)
                try:
                    slash_rv = handle_slash(agent, line, legacy)
                finally:
                    agent._typed_line = None
                if slash_rv == "exit":  # /exit: the same leave as q
                    with contextlib.suppress(Exception):
                        closing = goal_before_stop("leaving the chat")
                        if closing:
                            say(closing)
                    break
                _CHAT_SID[0] = agent.s.get("sid")  # /resume or /reset may have switched the conversation
            elif auto_hunt_request(line):
                prog, goal = auto_hunt_request(line)
                agent.hunt(prog or agent.ctx.program, goal)
            elif agent.s.get("plan_mode"):
                _plan_request(agent, line)   # plan mode: propose first, GreyNOC decides, then implement
            else:
                agent.s["_typed"] = line      # HIS words this turn (the question gate tells them from gnoc's prompts)
                import gnoc_notify
                import time as _time
                gnoc_notify.TURN_START[0] = _t0 = _time.time()
                agent.turn(line)
                with contextlib.suppress(Exception):   # a long answer while he looked away (Hermes review)
                    gnoc_notify.turn_done(_time.time() - _t0, _last_answer(agent))
                gnoc_notify.TURN_START[0] = None
                _goal_reenter(agent)   # F9: a goal turn killed by a transient lead error resumes instead of idling
                goal_after_turn(agent, line)   # a live goal does not wait at the prompt after his message
                with contextlib.suppress(Exception):
                    NEXT_SUGGESTION[0] = suggest_next_prompt(agent, _last_answer(agent))
            _goal_reenter(agent)   # F9: a goal turn killed by a transient lead error resumes instead of idling
        except KeyboardInterrupt:
            INTERRUPT.set()
            SPIN.stop()
            agent.interrupted = True
            from gnoc_core.agent import _stop_claude_workers
            _n_claude = _stop_claude_workers()   # phase 4: a Ctrl-C between turns stops them too
            say(yellow("\n  interrupted") + (f"  (stopped {_n_claude} claude worker(s))" if _n_claude else ""))
        except Exception as e:  # noqa: BLE001 - the REPL survives; the error is the message
            SPIN.stop()
            say(red(f"  error: {type(e).__name__}: {e}"))
            say(dim("  (the chat is still here; gnoc qaqc checks the harness if this keeps happening)"))
        finally:
            # turn() restores the tty only on its NORMAL exit. After a Ctrl-C the typeahead was left
            # running: echo off, and its thread still reading stdin, eating the next prompt's keys.
            with contextlib.suppress(Exception):
                TYPED.stop()
            with contextlib.suppress(Exception):
                BAR.paint(TYPED.buf)   # the input line is back the moment the turn ends, never blank
            with contextlib.suppress(Exception):
                agent.save()
            _set_title(_title_text(agent))   # /cd or /program moves the tab title with the work
    _restore_tty()
    _plugins_session(agent, "end")
    _scrub_history(readline)
    with contextlib.suppress(OSError):
        readline.write_history_file(hist)
    wait_reflection()
    with contextlib.suppress(Exception):
        __import__("gnoc_core.llm", fromlist=["release_local_models"]).release_local_models()   # free the RAM
