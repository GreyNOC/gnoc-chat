# gnoc chat

gnoc chat is an AI agent that lives in your terminal. You talk to it in plain English and it does the
work on your machine: it reads and edits files, runs commands, browses the web and finds its way
around a codebase. It runs on a model on your own computer (gnoc's built-in model engine), on the API of any
frontier lab (Claude first: Anthropic, OpenAI, Google Gemini, xAI, Meta Llama, Mistral, DeepSeek, Moonshot
Kimi, Alibaba Qwen), or on any OpenAI-compatible service you already have a key for. It ships the whole hunt
harness too (scope gate, hunt ledger, platform intake, report pipeline), and everything runs on one machine.

It was built for security research, so it is careful by default:

- **It asks before it acts.** Writing a file or running a command that changes something waits
  for your yes, unless you turn on auto mode. The check looks at the action itself, not at how the
  request was worded.
- **It stays in scope.** Its testing tools refuse any host outside the scope you set. Reading
  public web pages and searching the web are always allowed.
- **It keeps your secrets.** Keys in your secrets file are removed from everything a model sees
  and from every transcript.
- **It cleans up after itself.** Commands it starts have a time limit and stop when you press
  Ctrl-C or quit.

Version: see the `VERSION` file. Released under the MIT license.

---

## What you need

- **Linux or macOS** with **Python 3.10 or newer**, or **Windows 10/11**, where gnoc runs inside WSL
  (Microsoft's built-in Linux). The Windows installer sets WSL up for you.
- **A model.** Either one on your computer (free and private; gnoc downloads and runs it itself), or
  an API key from a frontier lab (Anthropic Claude, OpenAI, Google, xAI, Meta, Mistral, DeepSeek, Moonshot,
  Alibaba) or any OpenAI-compatible service such as OpenRouter or Groq.
- About 200 MB of disk for gnoc and its Python packages (plus whatever your model needs).

## Install

**One command (Linux, WSL and macOS).** Open a terminal (on Windows, your WSL Ubuntu) and run:

```bash
curl -fsSL https://chat.grey-noc.com/install.sh | bash
```

It checks the release's signature against the gnoc chat release key and the package's SHA-256
before it installs anything. On Debian, Ubuntu and WSL it installs the .deb with apt (sudo asks for
your password); elsewhere it installs the tarball into your home folder. To skip root on an apt
system, run `curl -fsSL https://chat.grey-noc.com/install.sh | bash -s -- --user`. To read the
script first, open https://chat.grey-noc.com/install.sh.

**Or pick the file for your computer.** All of them contain the same program; they only differ in how
they install it.

**Linux (any distribution)**: `gnoc-chat-<version>-linux.tar.gz`

```bash
tar xzf gnoc-chat-*-linux.tar.gz
cd gnoc-chat-*/
./install.sh
```

**Debian, Ubuntu, Mint, Pop!_OS, Kali, Parrot**: `gnoc-chat_<version>_all.deb`

```bash
sudo apt install ./gnoc-chat_*_all.deb
gnoc help        # the first run sets up its Python packages (about a minute)
```

**macOS**: `gnoc-chat-<version>-macos.zip`

Double-click the zip to unpack it, open the folder, and double-click **Install gnoc chat.command**.
If macOS says the file "cannot be opened because it is from an unidentified developer", right-click
it and choose **Open**, then **Open** again. You can also open Terminal in the folder and run
`bash install.sh`.

**Windows 10 and 11**: `gnoc-chat-<version>-windows.zip`

Right-click the zip and choose **Extract All**, open the folder, and double-click
**install-windows.cmd**.

- If you have never used WSL, the installer turns it on and installs Ubuntu. Windows asks for
  administrator permission. **Restart** when it finishes, open **Ubuntu** from the Start menu once
  to pick a Linux username and password, then double-click **install-windows.cmd** again.
- The second run copies gnoc into Ubuntu, installs it, adds a **gnoc chat** shortcut to your Start
  menu, and adds a `gnoc` command to Windows terminals.

**Any system, by hand**: `gnoc-chat-<version>-source.zip` holds every file. Unpack it and run
`./install.sh` on Linux or macOS. Mac users who prefer Terminal can use
`gnoc-chat-<version>-macos.tar.gz` the same way as the Linux tarball.

Except for the .deb, which installs to `/opt/gnoc-chat`, nothing goes in system folders. gnoc's
Python packages go in a private environment
(`~/.local/share/gnoc-chat/venv`), the `gnoc` command goes in `~/.local/bin`, and your settings,
notes and history live in your workspace, `~/.gnoc`.

## Pick a model

gnoc needs one model to think with, and **it works out of the box**: the first time you start
`gnoc chat`, it looks at this computer and asks one question (Enter means yes). If an Ollama is already
running, gnoc uses it and a model it already has. If not, gnoc sets up its own model engine: llama.cpp for
this computer (the CUDA build on an NVIDIA card, Vulkan on others, Metal on a Mac), started and kept
starting, then a model sized to your GPU and memory (qwen3:14b with 12 GB or more of GPU memory, qwen3:8b
with less, qwen3:4b with no graphics card), downloaded and tested. Answer no for the other choices:
another computer's GPU, or a cloud API key. `gnoc setup --yes` does the same with no question (for
scripts), and `gnoc setup` (or `/setup` in the chat) runs it again or switches models.

To do it by hand instead:

**A model on your own computer.** gnoc has its own model engine: it keeps a store of GGUF models and
runs them with [llama.cpp](https://github.com/ggml-org/llama.cpp). No other program is needed.

```bash
gnoc engine install                # llama.cpp for this computer, about 40 MB, checksum verified
gnoc engine start
gnoc engine pull qwen3:8b          # about 5 GB; qwen3:14b is better if you have 16 GB of RAM or a GPU
gnoc models use lead qwen3:8b
```

`gnoc engine pull` takes any GGUF model:

```bash
gnoc engine pull bartowski/Qwen_Qwen3-8B-GGUF:Q5_K_M          # a Hugging Face repo and a quantisation
gnoc engine pull https://huggingface.co/owner/repo            # its page address works too (Q4_K_M by default)
gnoc engine pull https://example.com/files/model.gguf         # a direct link to a .gguf file
gnoc engine pull ~/Downloads/model.gguf --as mymodel          # a file you already have (no second copy)
```

With no quantisation named, the pull takes one that fits this computer's GPU or memory and says which.
`gnoc engine search <words>` finds GGUF repos on Hugging Face and `gnoc engine files <owner/repo>` lists a
repo's quantisations and which of them fit. In the chat, `/hf clone <owner/repo>` does the same as a pull
and gives the model a role. `gnoc engine list`
shows what you have, `gnoc engine rm <model>` removes one, `gnoc engine run <model>` talks to one in the
terminal without the agent, and plain `gnoc engine` shows what is running. `gnoc engine ps` lists loaded
models, `gnoc engine unload <model>` frees one's memory, `gnoc engine logs` shows the server's log, and
`gnoc engine update` moves to the newest llama.cpp build. The engine also makes embeddings (`/api/embed`,
`/v1/embeddings`), from an embedding model or from a chat model.
A gated Hugging Face repo needs `HF_TOKEN` set.

**Already use Ollama?** The first start uses it as it is. `/setup` (a model on this computer) offers
gnoc's engine beside it:
the engine starts at `127.0.0.1:11439`, adopts the models Ollama already downloaded (hard links, no
second copy), and gnoc uses it from then on. Ollama keeps running for anything else that uses it. Say
no and gnoc uses the Ollama as it is.

**Memory.** A model stays loaded 10 minutes after the last message (`GNOC_KEEP_ALIVE` changes it), and
closing your last `gnoc chat` unloads it at once, so the engine holds no model memory while gnoc is not in
use. On WSL, Windows gets that memory back only when WSL hands it over: add this to
`%UserProfile%\.wslconfig` and run `wsl --shutdown` once, and it is returned as soon as it is freed:

```ini
[experimental]
autoMemoryReclaim=dropcache
```

The engine listens at `127.0.0.1:11434` (at `127.0.0.1:11439` when it runs beside an Ollama). To move
it, set `GNOC_LOCAL_OLLAMA=host:port` before starting gnoc and the engine.

**A cloud model.** Every frontier lab is built in, Claude first. Start `gnoc chat` and type:

```
/claude api sk-ant-your-key
/claude on
```

The same two lines work for each of them. The key is checked with one live call and saved outside the
install (`~/.config/gnoc/secrets.env`, readable only by you):

| Command | Provider | Default model | Key variable |
|---|---|---|---|
| `/claude` | Anthropic | `claude-opus-5-5` | `ANTHROPIC_API_KEY` |
| `/gpt` | OpenAI | `gpt-5` | `OPENAI_API_KEY` |
| `/gemini` | Google | `gemini-2.5-pro` | `GEMINI_API_KEY` |
| `/grok` | xAI | `grok-4` | `XAI_API_KEY` |
| `/llama` | Meta | `Llama-4-Maverick-17B-128E-Instruct-FP8` | `LLAMA_API_KEY` |
| `/mistral` | Mistral | `mistral-large-latest` | `MISTRAL_API_KEY` |
| `/deepseek` | DeepSeek | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `/kimi` | Moonshot | `kimi-k2-turbo-preview` | `MOONSHOT_API_KEY` |
| `/qwen` | Alibaba | `qwen-max` | `DASHSCOPE_API_KEY` |

`/claude on claude-sonnet-5-5` (or any model name the provider serves) picks a model; `/claude off` goes
back to the local model. `/cloud <provider> ...` is the long form of every one of these commands.

For any other OpenAI-compatible service:

```
/cloud add openrouter https://openrouter.ai/api/v1 openai/gpt-4o-mini sk-your-key
/cloud openrouter on
```

Anthropic (Claude) and Google Gemini are spoken natively, not through an OpenAI-compatible shim:

```
/claude api sk-ant-your-key
/claude on claude-sonnet-5-5
/gemini api your-gemini-key
/gemini on gemini-2.5-flash
```

The native wires stream text and reasoning, run tool calls, and use each provider's prompt cache:
Claude gets cache breakpoints on the tool list, the system prompt and the newest message; Gemini's
automatic cache is used as it is. A gateway or proxy in front of either API is added with
`wire=anthropic` or `wire=gemini` at the end of `/cloud add`. `/usage` shows the tokens each provider
reported, including the part served from its cache, and that real count (not an estimate) is what
the usage accounting records. A provider that answers 429 is retried after the wait it asks for.

Keys are saved in `~/.config/gnoc/` with owner-only permissions, never in your workspace. Note that
with a cloud model, what you type and the files the agent reads are sent to that service. Known
secrets are removed from every message before it is sent, on every provider, and `/privacy cloud off`
stops all of them before anything is sent.

## Use it

```bash
gnoc chat
```

Type what you want done. gnoc answers in Markdown, shows each action it takes, and asks before it
writes a file or runs a command that changes something. Useful commands inside the chat:

| Command | What it does |
|---|---|
| `/help` | everything you can type |
| `/model` | pick or switch the model |
| `/cloud` | add or switch a cloud model service |
| `/goal <objective>` | work toward an objective until it is achieved: it keeps going turn after turn, stops only when it needs you (`NEEDS:`), when you press Ctrl-C (say "continue" to go on), or after six turns with no progress, and picks itself back up after you answer |
| `/work <task>` | plan a task and carry the plan out step by step, verifying each one, until it is done |
| `/bg` | the background processes it started (a dev server, a test watcher); `/bg stop <name>` ends one |
| `/hooks` | your own rules around its actions, such as "format every file it edits" (see below) |
| `/commands` | your own slash commands, written as Markdown prompt files |
| `/skills` | saved procedures it loads when a task needs one; `/skills review` approves the ones it proposes (see below) |
| `/plugins` | your own Python plugins: list them, `/plugins enable <name>`, `/plugins disable <name>` (see below) |
| `/permissions` | your standing rules: commands it may run here without asking, and ones it must never run (see below) |
| `/doctor` | check that everything gnoc needs works, and what to do when something does not |
| Ctrl-C | stop the current step (press again at the prompt to quit) |

Outside the chat, `gnoc help` lists every command.

### Long chats

When a chat gets close to the model's window, gnoc folds the oldest turns into notes at the top of the
conversation. Nothing is thrown away: before a turn is folded, its original messages are saved next to the
chat (`sessions/segments/<chat>/`), and `/recall <words>` (or the model's own recall tool) searches them,
telling you which segment and turn a hit came from. So "what was the flag I gave you at the start of this
chat?" can still be answered with your exact words.

In an ordinary (non-hunt) chat, your worker model then rewrites the notes from those saved originals. Before
the notes are used, gnoc checks them and adds back, word for word, any file path or instruction of yours
("don't touch the migrations", "only use the standard library") that the summary left out. If the worker is
not reachable, errors or times out, the plain notes are kept. Secrets are redacted before the text goes to
the worker, and a summary that looks like it is trying to give instructions is discarded. `/compact` does
the same on demand; `GNOC_COMPACT_SUMMARY=0` turns the worker step off. Details: `docs/GNOC-COMPACTION.md`.

### Working on code

Ask for the change in plain English. gnoc reads the code first, makes the edit, then runs the tests
that cover it, along with your project's type checker and linter. It can:

- **run one test or the failures**: by name (`pytest -k`, `go test -run`, jest and vitest `-t`), or
  re-run only what failed last time. It runs Python, JavaScript/TypeScript, Go, Rust and shell tests.
- **type-check**: `tsc --noEmit`, mypy or pyright, `go vet` or `cargo check`, whichever your project
  uses.
- **keep a server running**: it starts a dev server or a watcher in the background, reads its new
  output, types into it, and stops it. Everything it started stops when you quit.
- **find the exact definition or callers** of a name with Python's `jedi` or a language server if you
  have one installed (`pyright-langserver`, `typescript-language-server`, `gopls`, `rust-analyzer`,
  `clangd`). Otherwise it searches the text.
- **use git**: blame, branches, stash and restore. A commit, a push or a new pull request (through
  the `gh` CLI) asks you every time, even in auto mode, and a push is never forced.
- **open a public repo**: `gnoc chat --repo https://github.com/owner/repo` (or `/repo owner/repo` in a
  chat) shallow-clones it once into `~/.gnoc/repos/<host>/<owner>/<repo>` and opens it there; a second
  open reuses that checkout, and a local folder works exactly the same. Only a URL you typed is cloned,
  a URL carrying a username/password is refused (git would write it into `.git/config`), and an existing
  directory with another origin is never overwritten.
- **map an untrusted clone safely**: `repo_map` skips a symlink that resolves outside the repo instead of
  reading the file it points at, does not read a very large generated file, and cannot be taken down by
  one `.py` file the parser rejects. A `find_symbol` search that times out says the search did not finish
  instead of reporting the name as absent.
- **edit Jupyter notebooks** cell by cell, and **look at screenshots** if you have a vision model
  (a GGUF repo that ships an `mmproj` file: `gnoc engine pull` fetches it along with the weights).
- **build in parallel without collisions**: an isolated helper works in its own copy of the repo (a
  git worktree) and hands back a patch for you to review before it is applied.

**Hooks.** Put rules in `~/.gnoc/hooks.json` and gnoc runs them around its actions:

```json
{"pre_tool":  [{"tools": "edit_file|write_file", "files": "migrations/*",
                "command": "echo 'migrations are generated' >&2; exit 2"}],
 "post_tool": [{"tools": "edit_file|write_file|apply_patch", "files": "*.py",
                "command": "ruff format $GNOC_FILES"}]}
```

A `pre_tool` hook that exits with status 2 blocks the action, and the model reads its message. A
`post_tool` hook's output is added to what the model sees. A repo can ship its own
`.gnoc/hooks.json`, but it only runs after you type `/hooks trust` in that repo, and it stops
running if the file changes.

**Plugins.** For rules a shell command cannot express, write a Python plugin:
`~/.gnoc/plugins/<name>.py` (or `<name>/plugin.py`) with a `register(api)` function.

```python
def register(api):
    def no_terraform_apply(ev):                 # ev = {"event": "pre_tool", "tool": ..., "args": {...}}
        if ev["tool"] == "bash" and "terraform apply" in ev["args"].get("command", ""):
            return {"block": "terraform apply is typed by hand"}
    api.on("pre_tool", no_terraform_apply)
    api.command("hello", lambda rest: f"hello {rest}", "say hello")
```

Handlers run on `pre_tool`, `post_tool`, `pre_llm`, `post_llm`, `approval_request`,
`approval_response`, `session_start` and `session_end`, and return nothing (pass), `{"block": ...}`
or `{"rewrite": {...}}`. A plugin can also add tools and slash commands. Nothing runs until you type
`/plugins enable <name>`; if a plugin file changes afterwards it stops running until you enable it
again. Plugins load only from `~/.gnoc/plugins`, never from a repo, and gnoc refuses a plugin file
other users can write to.

A plugin can make gnoc stricter, never looser. A rewritten action is checked again from scratch and
still asks for your approval if the original needed it. A plugin cannot approve anything. A message
a plugin rewrites still has its secrets removed before it reaches a cloud model, and the privacy
switch still applies. A plugin's own tools ask every time, even in auto mode, until you allow one
with `/permissions allow <tool>`. The agent's file and shell tools refuse to write into
`~/.gnoc/plugins`. Shell hooks keep working as before. The full API is in
[docs/GNOC-PLUGINS.md](docs/GNOC-PLUGINS.md).

**Permission rules.** When gnoc asks before running something, `p` saves the rule it offers, such
as "always allow `pytest *` in this repo", so the same kind of command stops asking. You can also
write them yourself:

```
/permissions allow bash(npm run test *)     # this repo; --global for every repo
/permissions allow edit(src/*)              # file edits under src/ without asking
/permissions deny bash(rm -rf *)            # never, anywhere (--here for this repo only)
/permissions rm 2                           # remove rule #2 (/permissions lists them)
```

An allow rule covers one plain command: never a chain such as `pytest; curl … | sh`, a pipe or a
`$(…)`. It never covers what always asks: a commit or a push, a scan of another machine, control of
a desktop, or anything after gnoc has read text from the web or an email in that turn. A deny rule
blocks the action even in auto mode. Rules live in `~/.gnoc/permissions.json`, never in a repo, so a
repo cannot grant itself anything.

**Your own commands.** A file `~/.gnoc/commands/fix-issue.md` (or `.gnoc/commands/` in a repo)
becomes `/fix-issue 42`, with `$ARGUMENTS` in the file replaced by `42`.

**Skills.** A skill is a procedure gnoc keeps for next time: a folder with a `SKILL.md` and, if you
like, scripts and reference files.

```
~/.gnoc/skills/release-notes/SKILL.md
---
name: release-notes
description: Write the release notes from the pull requests merged since the last tag
triggers: [release notes, changelog]
---
1. git describe --tags --abbrev=0 ...
```

Only the name and description go into the model's instructions; it reads the rest with `load_skill`
when a request needs it. After a long task that worked, gnoc may propose a skill (or you can say "save
that as a skill"). Nothing is saved until you type `/skills review`, read the diff and type `yes`. A
proposal is refused in a turn where gnoc read a web page, an email, a chat message or an MCP tool's
output, when it copies text from a response, when it reads like instructions aimed at an AI, or when
it holds a secret. gnoc cannot write into a skills folder with its file tools.

A repo can ship skills in `.gnoc/skills/`. They load only after you type `/skills trust` in that repo,
and stop loading if any file under that folder changes or is a symlink. If you have a skill with the
same name, yours is used. `/skills` lists them, `/skills show <name>` prints one, `/skills rm <name>`
deletes one of yours. More in [docs/skills.md](docs/skills.md).

**MCP servers.** After `gnoc mcp add`, each server's tools show up to the model as tools of their
own. Type `/mcp refresh` after you change a server.

### Helpers that work in parallel

Ask for several independent jobs at once ("read these four modules and tell me what each one exports") and
gnoc hands them to helper workers with `delegate`. Each helper starts with a fresh conversation, can read and
search but not change files, and ends with a short report: what it found, the evidence, the files it looked at,
and what it left open.

- **At most 3 run at once** by default; the rest wait their turn. Change it with `GNOC_DELEGATE_CAP` or
  `{"delegate": {"cap": 4}}` in `~/.gnoc/settings.json`. A repo cannot change it.
- **Each helper has its own time and token budget**, and its tokens count toward the turn you see in the footer.
- **A helper never approves anything**, never starts another helper, never sets a schedule and never moves to
  another folder or program. Something it needed approval for comes back to gnoc as a request, and gnoc asks you.
- **Ctrl-C stops every helper**, the waiting ones included, and any background Claude Code worker this chat
  started.
- An **isolated** helper edits and tests in its own copy of the repo (a git worktree) and returns a patch for
  you to review.

The background Claude Code worker (`claude_worker`) is optional. Without the `claude` command installed gnoc
does not offer it and says how to install it if asked. Details: `docs/GNOC-SUBAGENTS.md`.
### Scheduled tasks

Run a prompt on a schedule, with no chat open:

```text
/schedule add "0 9 * * 1-5" summarise yesterday's failing tests --deliver desktop
/schedule list                # what is scheduled, and what each one was saved with
/schedule run 3f2a9c1e        # run one now, in the background
/schedule rm 3f2a9c1e         # remove its timer and its record
```

The schedule is standard five-field cron (`minute hour day-of-month month weekday`, or `@daily`,
`@hourly` ...). gnoc installs it as a systemd user timer, or as one marked crontab line where systemd
is missing (on Termux, a crontab line for crond: `pkg install cronie termux-services`, then
`sv-enable crond`). Your other crontab lines are never touched. A cron line systemd cannot express
exactly, such as one that names both a day of the month and a weekday, is refused with the reason.

- **Only you set a schedule.** `/schedule add`, `rm` and `run` work only from a line you type at the
  prompt in a terminal. The model cannot create, change or run one: a tool call that tries
  (`/schedule`, `gnoc schedule`, crontab, a systemd timer, `at`, a Termux boot file) is refused, even
  in auto mode or with skip-perms. The hourly vulnerability watch timer follows the same rule.
- **Nothing that needs approval runs.** A scheduled run has nobody to ask, so every action that would
  ask is held, listed in the report as "held for approval", and not run.
- **It runs as you set it up.** The folder, the permission rules, the effort and the models in force
  when you add a schedule are saved with it and used for every run, even if you change them later.
  `/schedule list` shows them. A deny rule you add later still applies.
- **Where the report goes.** Every run writes `~/.gnoc/schedules/out/<id>/<time>.md` (readable only
  by you). `--deliver desktop` also shows a notification; `--deliver telegram` also sends it to your
  own chat, set in `~/.config/gnoc/secrets.env` as `TELEGRAM_BOT_TOKEN` and
  `TELEGRAM_OWNER_CHAT_ID` (the chat is fixed when you add the schedule; the model never picks it, and
  the token is removed from the text). A run stops after 15 minutes or about 200,000 tokens.

Outside the chat, `gnoc schedule list` shows the same list. `gnoc schedule run <id>` is what the timer
runs. Details: [docs/GNOC-SCHEDULE.md](docs/GNOC-SCHEDULE.md).
**Where commands run (`/sandbox`).** By default bash runs on this computer. You can move it:

```
/sandbox                         # where commands run now
/sandbox docker                  # a container for this conversation (docker or podman)
/sandbox docker --network        # the same, with network access
/sandbox docker --image node:22  # another image you already have
/sandbox ssh dev@build-box ~/work   # another computer, key login only
/sandbox local                   # back to this computer
```

The container mounts only the repo you are in, at the same path, and nothing else of this machine:
no network unless you typed `--network`, your own user id (not root), a read-only system with `/tmp`
in memory, and no extra privileges. If the image is not on your machine, gnoc tells you the
`docker pull` line and does not download it itself. The ssh backend needs a host that is already in
`~/.ssh/known_hosts` and accepts your key without a password.

The same rules apply on every backend: the deny list, the secret check, approvals and `/undo`
checkpoints before a destructive command. On docker the file tools refuse any path that
leaves the mount, symlinks included. On ssh they are switched off (they would act on this computer),
so the model reads and writes files with bash on that host. While a sandbox is on, the tools that
would run the repo's own code on this computer (run_tests, lint, typecheck, git) are refused and
bash does those jobs inside. Ctrl-C stops the command inside the container or on the other host
too. Only you can switch: the model cannot type `/sandbox`, and `/auto on` only suggests docker when
it is installed. The choice stays for new conversations (`/new`) until `/sandbox local`. The
image and the default remote folder can be set in `~/.gnoc/sandbox.json`
(`{"image": "python:3.12-slim", "ssh_dir": "~/work"}`). Details: `docs/GNOC-SANDBOX.md`.

## Defend your machine and network

gnoc also works as a blue team for computers you own: this machine, a Linux box you can reach
over SSH, and the LAN or Wi-Fi around them. It finds what is exposed or wrong, raises alerts, opens
an incident when the evidence shows a real intrusion, and can take small defensive actions that
undo themselves. **Use it only on machines and networks you own or administer.**

### Turn it on

```text
gnoc chat
/mode defender            # or just ask: "is this laptop compromised?" / "lock this box down"
/defender sweep
```

A sweep runs read-only checks and reports each finding with the exact fix:

- **Exposure:** listening ports and containers, firewall state, SSH settings and authorized keys.
- **Processes and connections:** reverse shells, miners, programs running from temp folders or
  deleted files, connections to suspicious ports.
- **Logins:** SSH brute force, and a login that **succeeded** after failures.
- **Persistence:** systemd units, cron, shell start-up files, desktop autostart, `rc.local` and
  `/etc/ld.so.preload`. It flags anything that runs a reverse shell, downloads and runs code,
  runs from `/tmp`, sets `LD_PRELOAD` or aliases `sudo`.
- **Settings:** kernel hardening (sysctl), extra root accounts, world-writable files in `/etc`,
  setuid programs in odd places.
- **Network:** the default gateway's MAC address (ARP spoofing), devices that change MAC, new
  devices, rogue DHCP servers, Wi-Fi changes (another access point, weaker security, an open
  twin) and DNS changes.
- **Packets:** a short capture that spots port scans and SYN floods.

The first sweep records two **baselines**: one for the network and one for this host (its
persistence files, SSH keys and listening ports). Later sweeps report what changed, such as a new
SSH key, an edited unit or cron file, a new network port or a new gateway MAC. Drift stays on the
list until you confirm it was you: `/defender baseline accept` (or `... accept host` / `... accept network`).

### Set it up (about five minutes)

1. **Say who must never be locked out.** Add your admin machine or your whole LAN:
   `/defender admin 192.168.1.0/24`. The defender never blocks those addresses, your live SSH or
   remote-desktop session, the gateway, your DNS servers or the machine itself.
2. **Name what you want watched** (optional; the default gateway and the local subnets are found on
   their own): `/defender gateway add 192.168.1.1`, `/defender subnet add 192.168.1.0/24`.
3. **Answer its questions.** After a sweep it asks what it cannot know: what the box is for, which
   open ports are meant to be open, which Wi-Fi network it should be on. Answers change the verdicts.
4. **Let it read the logs and the network** (recommended; log out and back in afterwards):
   ```bash
   sudo usermod -aG systemd-journal $USER   # see SSH brute force in the system journal
   sudo usermod -aG wireshark $USER         # capture packets (with Wireshark/tshark installed)
   ```
5. **Install the root helper** (only if you want it to act, not just report). Type
   `/defender install`. It lays out five numbered steps, each with its command and what you
   should see, and checks the machine first, so steps you have already done show as `[done]`.
   Run the rest yourself (prefix a line with `!` to run it in the chat). While you work, it keeps
   checking and tells you as each step completes, then says **ROOT HELPER READY**. The steps install a
   small root-owned program and one sudoers line. gnoc never runs `sudo` for you, and the helper
   refuses anything outside its short list, including the admin addresses you list in
   `/etc/gnoc-defender/protect`.

### Keep watch

```text
/defender watch on 60     # re-sweep every 60 s and alert, never act
/defender auto on 60      # re-sweep every 60 s and defend automatically
/defender watch off
```

The watcher runs while the chat is open. If you answer yes to its desktop-notification question,
alerts also pop up as desktop notifications.

**What auto-defense does by itself.** It takes only four kinds of action. Each one undoes itself
or can be undone, and each is written to a journal:

| Action | When |
|---|---|
| Block one public IP for an hour | a brute-force source or a port scanner |
| Pause (SIGSTOP, not kill) one process | a reverse shell or miner, or a suspicious process talking to the internet |
| Set one hardening sysctl | a weak kernel setting from a short allowlist |
| Quarantine one LAN device on this machine for 30 minutes | an ARP spoof or rogue DHCP server |

Closing a port, changing `sshd_config` or the firewall policy, and disabling a service or unit are
always **proposals** with the exact command for you to run. Control it with
`/defender auto off`, `/defender deny block|contain|sysctl|quarantine`, `/defender journal` and
`/defender undo` (or `undo all`, or `undo d3`).

### Hourly vulnerability watch

```text
/defender vulnwatch on        # check every hour, even with no chat open (a systemd user timer)
/defender vulnwatch run       # one pass now; its report prints in the chat when done
/defender vulnwatch           # status: last pass, next run, what is watched
/defender vulnwatch report    # the last full report
```

`on` and `off` install and remove a timer, so like `/schedule` they work only from a line you type;
gnoc can tell you the line, but cannot turn the watch on or off itself.

Every hour it pulls newly announced vulnerabilities (CISA's list of actively exploited ones, and new
CVEs scoring 7.0 or higher on NVD) and checks them against what this machine actually runs: installed
packages, the kernel, programs such as Chrome, ollama and node, and the services listening on the
network. A match counts only with version evidence. Debian's own fixed version decides whether your
package is already patched, so a backported fix is never reported. A match without a version stays
quiet until there is evidence. One outdated program is one alert, however many CVEs it has, and it
stays on the list each hour until you update.

It also checks that you are keeping up: security updates waiting to be installed, package lists that
have not refreshed, and whether automatic security updates are on. Each finding comes with the exact
command to fix it. A new high or critical finding also raises a desktop notification. Patching needs
root, so gnoc never installs anything itself.

To also check your projects' dependencies, name them, and their package names and versions are sent
to [OSV](https://osv.dev): `/defender vulnwatch npm add ~/my-site` (a folder with
`package-lock.json`) and `/defender vulnwatch pip add /usr/bin/python3` (for a system Python, only
packages you installed with `pip --user`). The vulnerability feeds themselves are downloads: nothing
about your machine is sent to them. The timer runs while you are logged in; `loginctl enable-linger`
keeps it running after you log out.

### Alerts and incidents

```text
/defender alerts                    # the open alert queue, worst first
/defender alerts ack <id>           # also: resolve, suppress
/defender triage                    # open incidents with priority, confidence and SLA clock
/defender triage <IR-id> contain    # then eradicate, recover, close (or false_positive)
```

An incident opens only on evidence of an active intrusion, for example malware running with a
connection out, a gateway impersonation, a rogue DHCP server, an evil-twin access point, a login
after brute force, or a reverse shell or rootkit hook installed to start again. Exposure alone is
never called an intrusion. Each incident comes with a verify → contain → eradicate → recover →
review playbook.

### Other machines, routers and access points

- **Another Linux machine:** `/defender target user@host` points every check at it over SSH (key
  login only); `/defender target local` points it back.
- **Routers, access points and endpoints:** `/defender setup` walks you through an SSH key, the
  gateway (`/defender gateway ssh|platform|iface|api ...` for OpenWrt/Linux nft, pfSense/OPNsense,
  hostapd or a UniFi controller) and Linux endpoints (`/defender endpoint add user@host`). gnoc then
  offers to block an IP or MAC at the gateway, disconnect a Wi-Fi client, or isolate an endpoint
  and pause or kill a process on it. **These always wait for your explicit yes**, even with
  auto-defense on.

`/defender` on its own shows the status and every subcommand; `docs/GNOC-DEFENDER.md` has the full
guide.

## A phone on a USB cable

An Android phone plugged into this computer can run models too. `gnoc phone setup` walks through it:
it checks `adb` and the phone, has you install Termux (from F-Droid), copies gnoc's engine onto the
phone, and offers a model sized to the phone's memory. The engine listens on the phone's own loopback
address and this computer reaches it through the cable (`adb forward`), so nothing is opened on Wi-Fi
and pulling the cable ends it.

```bash
gnoc phone setup               # once
gnoc phone                     # the phone, its battery and heat, whether its engine answers, its models
gnoc phone pull qwen3:1.7b     # download a model onto the phone (over the phone's own connection)
```

A model on the phone is `<model>@phone`: in the chat, `/model worker qwen3:4b@phone` makes it gnoc's
helper. A phone runs models on its CPU (a recent flagship does a 4B model at roughly 7 tokens a second)
and gets hot under long load, so it suits short side jobs, not the lead model. Under Windows, gnoc runs
in WSL, which only sees a USB phone after it is attached with
[usbipd](https://learn.microsoft.com/windows/wsl/connect-usb).

## gnoc inside Termux (Android)

gnoc also runs on the phone itself, inside [Termux](https://f-droid.org/packages/com.termux/). Unpack the
Linux tarball or the source zip in Termux and run the same installer:

```bash
pkg install python git
./install.sh                         # GNOC_INSTALL_DRY_RUN=1 ./install.sh lists what it would do, changes nothing
```

The installer sees Termux, puts the `gnoc` command in `$PREFIX/bin` (always on Termux's PATH) and the rest in
your home folder, and never suggests sudo or apt. `gnoc doctor` and `gnoc setup` know Termux too. A phone has
no GPU for big models, so the setup offers three ways and defaults to the desktop once it is paired:

- the model server on your desktop: run `gnoc-engine share on` there and `gnoc pair <line it prints>` here;
- a cloud model with an API key;
- a small model on the phone itself (gnoc's engine, Android build), sized to the phone's memory.

Root and systemd do not exist in Termux, so those features say so in one line instead of trying: the
defender's root helper (firewall blocks, process pause, sysctl) and the hourly vulnerability timer.
`/defender sweep` runs a reduced read-only set there (reachable listening sockets when Android lets
Termux see them, Termux's sshd password login, shared-storage access, waiting package upgrades) and says
what Android hides. `/defender schedule` uses crond:
`pkg install cronie termux-services`, restart Termux, `sv-enable crond`. Details: [docs/termux.md](docs/termux.md).

## A second computer

**Use its GPU.** A desktop with a bigger graphics card can run the model while you work on this
computer. The other computer needs only gnoc's engine, no Ollama: install gnoc chat there or just
the `gnoc-engine` download, then run

```bash
gnoc-engine install     # llama.cpp for its GPU (the CUDA build on an NVIDIA card)
gnoc-engine share on    # serve other computers behind a key, start with the computer, stay current
```

It prints one line, `gnoc pair <address> <key>`. Type that line on this computer (or paste it into
`gnoc setup`, *a model server on another computer*), then pick one of its models with `/model`, or
download one onto it from here with `gnoc models pull Qwen/Qwen3-8B-GGUF:Q4_K_M --on desktop`. The key is saved owner-only
and sent on every request to that computer; without it the engine answers nothing from the network.
`gnoc update` here also brings that engine to the newest signed release, and a shared engine checks
once a day by itself. If that computer is off, gnoc falls back to a model on this one. Let its
firewall accept the port (11434) from this computer only. An Ollama there still works: make it
listen on the network and leave the key empty.

**See and drive its desktop (Linux).** `gnoc link` shows a block to paste on the other Linux
computer. That block installs an ssh server, trusts one key from your local network only, and gives
the desktop user mouse and keyboard access. Then `gnoc link add <name> user@address` registers it.
The chat asks you every time before it touches that screen, and control ends with the task.
`gnoc link remove <name>` prints the block that undoes everything on the other computer.

## Messaging: gnoc from your phone

`gnoc gateway` lets you talk to gnoc from Telegram (the simplest: no public port, no webhook), Slack,
Signal or email, and answers as `gnoc chat` would. Put the bot's token and **your own numeric account
id** in `~/.config/gnoc/secrets.env`, check it, then run it:

```bash
# ~/.config/gnoc/secrets.env  (Telegram: make a bot with @BotFather; your id is a number, not @name)
TELEGRAM_BOT_TOKEN=123456:ABC...
GNOC_TELEGRAM_OWNERS=123456789

gnoc gateway check        # which messengers are set up and what is missing
gnoc gateway run          # answer in the foreground
gnoc gateway install      # write a systemd user unit (or, in Termux, a Termux:Boot script); it prints the
                          # one command that turns it on, and never starts anything itself
```

What it will and will not do:

- Only the account ids you list are answered; anyone else gets no reply at all. A username is never
  enough, because its owner can change it.
- A reply goes only to the chat your message came from. Nothing gnoc writes can send it anywhere else.
- When gnoc wants to do something that needs your yes (a write, a command), it asks in the same chat:
  Yes/No buttons on Telegram and Slack, `yes <id>` / `no <id>` on Signal and email. Only you can
  answer, and no answer within 5 minutes (`GNOC_GATEWAY_APPROVAL_TIMEOUT`) counts as no. There is no
  "yes to all" from a phone.
- Secrets are redacted from everything it sends; if redaction fails, the message is not sent.
- Slash commands (`/file`, `/send`, `/auto`, ...) stay on the computer's own keyboard and are refused
  from a messenger. `/new`, `/stop` and `/help` are the gateway's own.
- A forwarded message, the message you reply to and quoted mail are treated as someone else's text,
  never as your instructions.

Slack uses Socket Mode (`SLACK_APP_TOKEN`, `SLACK_BOT_TOKEN`, `GNOC_SLACK_OWNERS`), Signal a local
`signal-cli daemon --tcp 127.0.0.1:7583` (`GNOC_SIGNAL_ACCOUNT`, `GNOC_SIGNAL_OWNERS`), and email IMAP
and SMTP, answering only mail your provider marks DMARC- or DKIM-verified (`GNOC_EMAIL_AUTHSERV`).
`gnoc gateway --help` lists every setting; [docs/GNOC-GATEWAY.md](docs/GNOC-GATEWAY.md) has the details.
## Export trajectories (training data)

Every chat turn that used tools is logged on this computer with its measured outcome. To turn that
log into a fine-tuning file:

```bash
gnoc export trajectories --format sharegpt --since 2026-11-01 --out traj.jsonl
gnoc export trajectories --format openai --good-only > traj-openai.jsonl
```

`sharegpt` writes `{"conversations": [{"from": "human|gpt|function_call|observation", ...}]}` lines;
`openai` writes the chat fine-tuning shape, with each tool call's id paired with its tool message.
Every line is checked against that shape before it is written, and a turn that does not fit is
skipped and counted. `--since` takes a date (UTC). `--out` writes a file only you can read.

**Redaction is on by default.** Known secrets, token and key shapes, values under keys such as
`password` or `cookie`, your home folder (written as `~`), your user name in paths, IP addresses and
hostnames are replaced. Each host gets one placeholder for the whole export (`host-1.invalid`,
`198.51.100.1`), so a trajectory keeps its shape. Hosts and networks you list in
`~/.gnoc/export-allowlist.txt` (one per line), or pass with `--allow`, are kept, along with their
subdomains. `--no-redact` turns all of this off and prints a warning. Nothing is uploaded anywhere.

To make more trajectories, run a file of prompts headless:

```bash
gnoc export batch prompts.jsonl --out batch-run --workers 2 --timeout 600 --steps 24
```

Each line of `prompts.jsonl` is `{"prompt": "...", "id": "optional"}`. Each prompt runs in its own
process with a time limit and a step limit, at most `--workers` at once (up to 8). Nothing can answer
an approval in a batch, so every action that needs your approval is **held**: listed under `held` in
that prompt's trajectory and never run. Rules you saved with `/permissions` still apply. Ctrl-C stops
every running prompt. Export the result with `--from batch-run/trajectories.jsonl`.

## Settings

Every setting below is an environment variable. To keep one for this machine, put it in
`~/.gnoc/.claude/state/orch/machine.json` (an environment variable that is already set wins):

```
{"env": {"GNOC_DESKTOP_OLLAMA": "192.168.1.20:11434", "GNOC_KEEP_ALIVE": "30m", "GNOC_DEFAULT_COMMAND": "chat"}}
```

There is one edition: this copy has every command and tool the author's own copy has, and the only
differences between two machines are settings like these.

| Variable | What it changes | Default |
|---|---|---|
| `GNOC_WORKSPACE` | where your settings, notes and history are kept | `~/.gnoc` |
| `GNOC_LOCAL_OLLAMA` | the address of the model server on this computer (gnoc's engine, or an Ollama) | `127.0.0.1:11434` (`:11439` beside an Ollama) |
| `GNOC_DESKTOP_OLLAMA` | another computer's model server (`host:port`); `gnoc setup` saves one for you | unset |
| `GNOC_MODELS_DIR` | where the engine keeps downloaded models | `~/.local/share/gnoc-chat/models` |
| `GNOC_ENGINE_ARGS` | extra `llama-server` arguments for every model, for example `-ngl 99` | unset |
| `GNOC_ENGINE_KEEP_ALIVE` | how long an idle model stays in memory | `5m` (the chat asks for 30 minutes) |
| `GNOC_ENGINE_MAX_LOADED` | models kept loaded at the same time | `1` |
| `GNOC_ENGINE_KEY` | a key that callers on other computers must send (`Authorization: Bearer ...`); set it whenever the engine listens on a network address | unset |
| `HACKERONE_HANDLE` | your researcher handle, for the identification header a bug-bounty program asks for (also read from `secrets.env`) | unset: no identification header is sent |
| `GNOC_NO_SETUP` | `1` skips the model check (and the guided setup) when a chat starts | unset |
| `GNOC_VENV` | where the private Python environment lives | `~/.local/share/gnoc-chat/venv` |
| `GNOC_NO_UPDATE_CHECK` | `1` turns off the daily check for a new version | unset |
| `GNOC_DELEGATE_CAP` | how many helper workers run at once (also `"delegate": {"cap": N}` in `~/.gnoc/settings.json`) | `3` |
| `GNOC_CHILD_TOKENS` | each helper's token budget | `150000` |
| `GNOC_CHILD_SECONDS` | each helper's time limit, in seconds (isolated helpers: 900) | `210` |

API tokens the built-in tools use go in `~/.config/gnoc/secrets.env`, one `NAME=value` per line.
That file is never shown to a model.

## Update

gnoc looks for a new version once a day, when you start it. When there is one, it asks
`Install it now? [Y/n/a]`: Enter installs it and the chat opens on the new version, `a` does the same
and installs every later release by itself too. Nobody answering in 30 seconds counts as no.
A .deb install says so in one line instead, because only `sudo apt` can replace it. Or:

```bash
gnoc update              # download, check and install the newest release
gnoc update --check      # only say whether there is one
gnoc update --auto on    # install new releases by themselves when gnoc starts (off turns it off)
```

`gnoc update` downloads the package for your system from https://chat.grey-noc.com/gnoc-chat ,
checks its signature and SHA-256 (below), and unpacks it beside the old version in
`~/.local/share/gnoc-chat/releases/`, then runs its installer, which points the `gnoc` command at
it. A chat that is already open keeps running until you restart it. With the .deb, it downloads
the new .deb and asks before running `sudo apt install`.

The daily check reads the download page's `manifest.json` and its signature, and sends no identifier
with them. Set `GNOC_NO_UPDATE_CHECK=1` to turn it off. You can always update by hand instead: download
the new version and install it the same way.

Either way your workspace (`~/.gnoc`) and your keys (`~/.config/gnoc`) are kept, and the first run
after an update refreshes the Python packages if they changed.

**Something not working?** `gnoc doctor` (or `/doctor` in the chat) checks Python and gnoc's own
environment, the `gnoc` command, your workspace, whether the models gnoc is set to use answer,
updates, and your config files, and says what to do about each problem. It changes nothing.

## Uninstall

```bash
rm -f ~/.local/bin/gnoc
rm -rf ~/.local/share/gnoc-chat          # the Python environment and updated copies
rm -rf <the folder you unpacked>          # the program
# optional: your data and keys
rm -rf ~/.gnoc ~/.config/gnoc
```

With the .deb: `sudo apt remove gnoc-chat`. On Windows, also delete the **gnoc chat** Start menu
shortcut and the folder `%LOCALAPPDATA%\gnoc-chat`, and run the lines above inside Ubuntu.

## Check your download

Each release ships a `SHA256SUMS.txt`. Compare it with your file:

```bash
sha256sum gnoc-chat-*-linux.tar.gz          # Linux
shasum -a 256 gnoc-chat-*-macos.zip         # macOS
Get-FileHash gnoc-chat-*-windows.zip        # Windows PowerShell
```

Every release is also signed with the GreyNOC release key (Ed25519), and `gnoc update` installs
nothing that key did not sign. The signature (`manifest.json.sig`) covers `manifest.json`, which
lists every file's SHA-256. The key's public half, built into this copy of gnoc:

```
8a983eb6c416a99d923943f04ca20195c95c3c2d99cd895c00e838dfdf2ce0b9
```

To check that every module is intact after unpacking:

```bash
python3 -m py_compile scripts/gnoc scripts/*.py scripts/bbtools/*.py
```

## What is not included

The code is complete: every command, tool and harness script ships. What does not ship is research DATA:
the author's hunt notes, technique manual and pattern library, report drafts and captures, and anything
naming a real program's unreported findings. A fresh install starts with an empty workspace
(`targets/`, `reports/`, the hunt ledger) that you fill with your own programs.

## Use it responsibly

Only point gnoc at systems you own or have written permission to test. The approval and scope checks
help you stay inside those limits. They do not set them for you.

## License

MIT. See [LICENSE](LICENSE). Contributors are listed in [CREDITS.md](CREDITS.md).
