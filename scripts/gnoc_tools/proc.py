"""Shell execution and host process helpers."""
from gnoc_core.runtime import bind


def _session_hint(ctx):
    """F6 2026-11-09: a secrets refusal names the SANCTIONED way to a session (identities action=login, or ACCOUNTS.md
    when it really holds the values), else the lead retried the same read three times."""
    (
        gnoc_ident,
    ) = bind(
        "gnoc_ident",
    )
    try:
        prog = getattr(ctx, "program", None)
        return ("\n  Session path: " + gnoc_ident.session_path_hint(prog)) if prog else ""
    except Exception:  # noqa: BLE001 - a hint never breaks a refusal
        return ""


def _sudo_needs_password():
    (
        _SUDO_OK, subprocess,
    ) = bind(
        "_SUDO_OK", "subprocess",
    )
    if not _SUDO_OK:
        try:
            r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
            _SUDO_OK.append(r.returncode == 0)
        except (OSError, subprocess.TimeoutExpired):
            _SUDO_OK.append(False)
    return not _SUDO_OK[0]


def _command_lines(command):
    """The command with heredoc bodies and quoted spans blanked, so a newline only separates REAL commands: sudo
    in an INSTALL.md heredoc or a multi-line commit message is text (QAQC r2). Heredocs first (their markers may be
    quoted), then quotes."""
    import re
    text = str(command or "")
    start = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
    pos = 0
    while True:
        m = start.search(text, pos)
        if not m:
            break
        end = re.compile(r"(?m)^\s*" + re.escape(m.group(1)) + r"\s*$").search(text, m.end())
        stop = end.end() if end else len(text)
        text = text[:m.end()] + re.sub(r"[^\n]", " ", text[m.end():stop]) + text[stop:]
        pos = stop
    out, quote, i = [], None, 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(text):
                out.append("  ")
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(c if c in "'\"" else " ")
        else:
            if c in "'\"":
                quote = c
            out.append(c)
        i += 1
    return "".join(out)


def _sudo_gate(command):
    """sudo in a tool call can only fail when it needs a password: the shell has no terminal to ask on. The user
    2026-11-18, `defend`: the lead ran `sudo sysctl ...` (exit 1, "a terminal is required"), then the same with
    `2>/dev/null || echo` (exit 0, which it read as progress), then `sudo sysctl -a | grep` three times over, each
    an empty exit 0. Say it once, plainly, with what to do instead."""
    (
        _SUDO, _sudo_needs_password,
    ) = bind(
        "_SUDO", "_sudo_needs_password",
    )
    if not _SUDO.search(_command_lines(command)) or not _sudo_needs_password():
        return ""
    return ("refused: sudo needs the user's password and this shell has no terminal to ask on, so it can only fail "
            "(and `2>/dev/null` turns that failure into an empty exit 0). Do the part that needs no root yourself; "
            "for the root part, give the user the exact command in a code block and tell them what it changes. "
            "Settings the defender owns (sysctl, firewall, blocks) go through defend, which has its own helper.")


# reads that only root can do: without sudo they fail or show nothing, so the sudo is left for the gate to explain
_ROOT_ONLY_READS = {"ufw", "nft", "iptables", "ip6tables", "cat", "less", "head", "tail", "ls", "find", "grep", "lsof",
                    "ss", "netstat", "dmesg", "journalctl", "nmap"}


def output_note(command, out, rc):
    """One line under a command's output for the two readings a model gets backwards (scored defense batch
    2026-11-22): nothing printed, and `ip link`'s UP flag next to `state DOWN`.

    `swapon -s` printed nothing (there is no swap) and the answer was "Yes, swap is enabled ... listed in the
    output". `ip link show eno1` printed <NO-CARRIER,BROADCAST,MULTICAST,UP> ... state DOWN and the answer was "up"."""
    re = __import__("re")
    cmd, text = str(command or ""), str(out or "")
    if not text.strip():
        os_ = __import__("os")
        missing = [w for w in re.findall(r"(?<![\w=])(/(?:var|etc|home|root|opt|srv|usr|tmp|run|proc|sys)/[^\s'\"|;&<>()*?]+)", cmd)
                   if not os_.path.exists(w)]
        if missing:
            # "I see failed ssh logins from 45.155.205.233 in auth.log": `grep ... /var/log/auth.log 2>/dev/null`
            # printed nothing because the file does not exist (this box logs to the journal), and the answer was
            # "the IP is NOT in auth.log" (defense drive 2026-11-22)
            return (f"\n[note] the command printed NOTHING, and {', '.join(missing[:4])} "
                    f"{'does' if len(missing) == 1 else 'do'} NOT EXIST on this machine: the empty output proves "
                    "nothing about what you searched for. Say the file is not there"
                    + (" (this system logs to the journal: `journalctl` reads it, and other users' entries need "
                       "group adm or systemd-journal)" if any(m.startswith("/var/log/") for m in missing) else "")
                    + ".")
        if rc == 0 and re.search(r"\b(?:swapon|grep|egrep|rg|pgrep|lsof|ss|netstat|find|ls|who|last|lastb|docker|podman|"
                                 r"crontab|systemctl|dpkg|rpm|ip|iw|nmcli|mount|findmnt|lsblk|journalctl|awk|sed|cat)\b",
                                 cmd):
            return ("\n[note] the command printed NOTHING. For a listing or a search that means there is nothing "
                    "of that kind (no swap device, no match, no such entry): report it as none, never as present.")
        return ""
    if re.search(r"\$3\s*>=?\s*1000", cmd) and "65534" not in cmd and re.search(r"passwd", cmd):
        # "how many regular user accounts": `$3>=1000` counted `nobody` (65534) and the answer was 2 (it is 1)
        return ("\n[note] this filter also counts `nobody` (uid 65534), a placeholder account and not a person. "
                "Leave it out: add `&& $3<65534`.")
    gm = re.search(r"\bps\b[^|]*\|\s*(?:e?grep|rg)\s+(?:-\w+\s+)*['\"]?([\w.@:/-]+)", cmd)
    if gm:
        rows = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("exit ", "[stderr]"))]
        real = [ln for ln in rows if not re.search(r"\b(?:e?grep|rg)\b", ln) and "ps -" not in ln
                and "bash -c" not in ln and "sh -c" not in ln]
        if rows and not real:
            # "is docker running": `ps -ef | grep docker` printed its own grep, and the answer was "Yes, Docker
            # is running ... PID 1016771" (scored defense batch 2026-11-22)
            return (f"\n[note] every line above is this search itself (the grep and the shell that ran it), not a "
                    f"{gm.group(1)} process: NOTHING named {gm.group(1)} is running. `pgrep -a {gm.group(1)}` or "
                    f"`systemctl is-active {gm.group(1)}` asks without matching itself.")
    modes = re.findall(r"(?m)^([-dlbcps])([rwxsStT-]{9})[.+@]?\s+\d+\s+(\S+)\s+(\S+)\s.*?(\S+)(?:\s+->\s+\S+)?\s*$",
                       text)
    if modes and len(modes) <= 8 and re.search(r"\bls\b", cmd):
        # "permissions on /etc/shadow": -rw-r----- was read as "others: read only (r--)" (defense drive 2026-11-22)
        def words(tri, who):
            got = [w for c, w in zip(tri, ("read", "write", "execute")) if c not in "-ST"]
            return f"{who} {tri} = " + ("/".join(got) if got else "NO access")
        rows = []
        for kind, perm, owner, group, path in modes:
            if kind == "l":
                # /var/run/docker.sock -> /run/podman/podman.sock was read as "0777 permissions" (drive 2026-11-22)
                rows.append(f"{path}: a SYMLINK. Its lrwxrwxrwx bits mean nothing; what counts is the target's "
                            f"mode (`ls -lL` or `stat -L` shows it)")
                continue
            octal = "".join(str(sum(v for c, v in zip(perm[i:i + 3], (4, 2, 1)) if c not in "-ST")) for i in (0, 3, 6))
            special = [w for c, w in ((perm[2], "SETUID"), (perm[5], "SETGID"), (perm[8], "sticky")) if c in "sStT"]
            octal = str((perm[2] in "sS") * 4 + (perm[5] in "sS") * 2 + (perm[8] in "tT")) + octal
            rows.append(f"{path}: mode {octal}" + (f" ({', '.join(special)})" if special else "") + ": " + ", ".join(
                (words(perm[0:3], f"owner {owner}"), words(perm[3:6], f"group {group}"), words(perm[6:9], "others"))))
        return "\n[note] the permission columns, spelled out:\n  " + "\n  ".join(rows)
    if re.search(r"\bip\s+(?:-\S+\s+)*(?:link|addr|address|a|l)\b", cmd) and re.search(r"NO-CARRIER|state DOWN", text):
        down = sorted(set(re.findall(r"^\d+:\s*([\w.@-]+):\s*<[^>]*>[^\n]*\bstate DOWN", text, re.M)))
        return ("\n[note] in this output UP inside <...> only means the interface is switched on. `state DOWN` or "
                "NO-CARRIER means it has NO link (nothing plugged in or associated): that interface is down"
                + (": " + ", ".join(d.split("@")[0] for d in down[:6]) if down else "") + ".")
    return ""


def sudo_not_needed(command):
    """The command without its sudo, when it is ONE read-only command of a kind that works unprivileged
    (systemctl status / is-active, which, id, uname, loginctl, timedatectl, mokutil ...). Else ''."""
    re = __import__("re")
    m = re.match(r"\s*sudo\s+(?:-n\s+)?(?!-)(\S+)(.*)$", str(command or ""), re.S)
    if not m or re.search(r"[;&|`$<>]|\bsudo\b", m.group(2)):
        return ""
    if m.group(1) in _ROOT_ONLY_READS:
        return ""
    rest = (m.group(1) + m.group(2)).strip()
    try:
        ok = __import__("gnoc_core.shellsafe", fromlist=["_bash_readonly"])._bash_readonly(rest)
    except Exception:  # noqa: BLE001
        ok = False
    return rest if ok else ""


def t_bash(ctx, command, timeout=120):
    (gnoc_secrets,) = bind("gnoc_secrets")
    command = str(command or "")
    if not command.strip():
        return "bad arguments: bash needs command=<a shell command>"
    plain = sudo_not_needed(command)
    if plain:
        # `sudo systemctl status fail2ban`: the read needs no root, the sudo could only be refused, and with its
        # one call refused the lead answered "fail2ban is not installed" (it is) (defense drive 2026-11-22).
        return "(ran without sudo: this read needs no root)\n" + t_bash(ctx, plain, timeout)
    why = _bash_gates(ctx, command)
    if why:
        return why
    srv = _foreground_server(command)
    if srv:
        # SWE batch 1: "bad json crashes the server" -> `python3 server.py` in the foreground twice, 120 s each,
        # while the repo's own test_server.py answered in under a second
        return (f"not run: `{srv}` starts a server that never exits, so this call would hang until its timeout. "
                f"To run it, use bg action=start command='{srv}' and read it with bg action=output (bg "
                f"action=stop ends it). To check a change, run the repo's tests (run_tests) instead.")
    env = gnoc_secrets.user_env(dict(GNOC_PLAIN="1", **({"HUNT_TARGET": ctx.program} if ctx.program else {})))  # T1.7
    before = _shell_snapshot(ctx, command)
    out = _bash_run(ctx, command, timeout, env)
    _shell_checkpoint(ctx, before)
    return out


_SERVER_CMD = __import__("re").compile(
    r"(?:\bpython3?\s+(?:-u\s+)?(?:\S*/)?server\.py\b|\bpython3?\s+(?:\S*/)?manage\.py\s+runserver\b|"
    r"\bpython3?\s+-m\s+(?:http\.server|flask\s+run|uvicorn|gunicorn)\b|\b(?:flask\s+run|uvicorn|gunicorn)\b|"
    r"\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:start|dev|serve)\b|\bnode\s+(?:\S*/)?server\.js\b|\bphp\s+-S\b|"
    r"\brails\s+s(?:erver)?\b)[^;&|]*$")


def _foreground_server(command):
    """The server command this shell line runs in the FOREGROUND as its last step (so it never returns), or one it
    starts with `&` inside this call (it keeps the output pipe open, so the call still hangs to its timeout, and
    it outlives the call: SWE batch 1, `python3 -c "...serve(port=8099)" & sleep 1; curl ...`), or ''."""
    c = str(command or "").strip()
    _re = __import__("re")
    bgd = _re.search(r"((?:" + _SERVER_CMD.pattern.replace("[^;&|]*$", "") + r"|\bpython3?\s+-c\s+[\"'][^\"']*\b(?:serve|"
                     r"serve_forever)\s*\()[^;&|\n]*)&(?!&)", c)
    if bgd and not _re.search(r">\s*\S+\s+2>&1\s*&|&>\s*\S+\s*&|\bnohup\b|\bsetsid\b", c):
        return bgd.group(1).strip()
    if not c or c.endswith("&") or _re.search(r"\b(?:timeout|nohup|setsid)\s", c) or "--help" in c:
        return ""
    last = __import__("re").split(r"&&|\|\||;|\n", c)[-1].strip()
    m = _SERVER_CMD.search(last)
    return last if m and "&" not in last else ""


# Files a shell command is about to delete or rewrite: rm, sed -i, truncate, "> file", mv onto a file. /undo only
# knew write_file/edit_file, so `rm notes.txt` or `sed -i` through bash could not be taken back (the Hermes Agent
# review: checkpoints before destructive commands, 2026-11-23). Small text files inside the active repo only.
import os  # noqa: E402 - the shell-checkpoint helpers below; the module otherwise binds per function
import re  # noqa: E402
_SHELL_TARGETS = (
    re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?rm\s+((?:-[a-zA-Z]+\s+)*)([^;&|<>]+)"),
    re.compile(r"(?:^|[;&|]\s*)(?:sudo\s+)?sed\s+(?:-\w*\s+|-e\s+\S+\s+|'[^']*'\s+|\"[^\"]*\"\s+)*-i\S*\s+"
               r"(?:-\w+\s+)*(?:'[^']*'|\"[^\"]*\"|\S+)\s+([^;&|<>]+)"),
    re.compile(r"(?:^|[;&|]\s*)truncate\s+(?:-\w+\s+\S+\s+)*([^;&|<>]+)"),
    re.compile(r"(?<![>&2])>(?!>|&)\s*([^\s;&|<>]+)"),
    re.compile(r"(?:^|[;&|]\s*)mv\s+(?:-\w+\s+)*\S+\s+([^\s;&|<>]+)\s*(?:$|[;&|])"),
)


def _shell_target_words(command):
    """The file names a shell command may delete or rewrite (rm without -r, sed -i, truncate, > file, mv onto)."""
    import shlex
    for rx in _SHELL_TARGETS:
        for m in rx.finditer(command):
            if rx is _SHELL_TARGETS[0] and "r" in (m.group(1) or "").lower():
                continue   # a recursive delete is a directory: too much to keep, and it is asked for by name
            try:
                words = shlex.split(m.group(m.lastindex))
            except ValueError:
                words = m.group(m.lastindex).split()
            for w in words[:20]:
                if not w.startswith("-"):
                    yield w


def _shell_snapshot(ctx, command):
    """{path: text} for the small text files inside the repo this command may delete or rewrite. On the docker
    sandbox the repo is bind-mounted at the same path, so this host-side read sees exactly what the command will
    change; on ssh the files are on the other host and are read through the backend."""
    import gnoc_sandbox
    (_inside_ws, root) = bind("_inside_ws", "root")
    out = {}
    be = gnoc_sandbox.for_session(getattr(ctx, "s", None))
    if be.kind == "ssh":
        words = list(_shell_target_words(command))
        if not words:
            return out
        try:
            return {"ssh://" + be.host + p: t for p, t in be.snapshot(words).items()}
        except Exception:  # noqa: BLE001 - a failed snapshot never blocks the command; it just cannot be undone
            return out
    try:
        base = root()
    except Exception:  # noqa: BLE001
        return out
    for w in _shell_target_words(command):
        p = os.path.realpath(os.path.join(base, os.path.expanduser(w)))
        if p in out or not os.path.isfile(p) or os.path.getsize(p) > 2_000_000 or _inside_ws(p) != p:
            continue
        try:
            with open(p, encoding="utf-8") as f:
                out[p] = f.read()
        except (OSError, UnicodeDecodeError):
            continue   # binary: not checkpointed
    return out


def _ssh_split(key):
    """'ssh://host/abs/path' -> ('host', '/abs/path')."""
    rest = key[len("ssh://"):]
    host, _, path = rest.partition("/")
    return host, "/" + path


def _shell_checkpoint(ctx, before):
    """After the command: one /undo checkpoint per snapshotted file that it changed or removed."""
    if not before:
        return
    (_checkpoint,) = bind("_checkpoint")
    remote = [p for p in before if p.startswith("ssh://")]
    now_remote = {}
    if remote:
        import gnoc_sandbox
        be = gnoc_sandbox.for_session(getattr(ctx, "s", None))
        try:
            got = be.read_many([_ssh_split(p)[1] for p in remote])
            now_remote = {"ssh://" + be.host + k: v for k, v in got.items()}
        except Exception:  # noqa: BLE001 - the command already ran; without a second read there is no checkpoint
            return
    for p, old in before.items():
        if p.startswith("ssh://"):
            now, gone = now_remote.get(p, ""), p not in now_remote
        else:
            try:
                with open(p, encoding="utf-8") as f:
                    now = f.read()
            except FileNotFoundError:
                now = ""
            except (OSError, UnicodeDecodeError):
                continue
            gone = not os.path.exists(p)
        if now != old or gone:
            try:
                _checkpoint(ctx, p, old, True, now)
            except Exception:  # noqa: BLE001 - a checkpoint never costs the command's output
                pass


def _bash_gates(ctx, command):
    """Every refusal bash applies before a command runs (deny list, secrets, sudo, scope gate, target probes).
    Shared with bg, so a background process cannot be the way around them."""
    (
        BASH_DENY, _bash_target_probe, _scope_gate_bash, _session_hint, _sudo_gate, gnoc_secrets,
    ) = bind(
        "BASH_DENY", "_bash_target_probe", "_scope_gate_bash", "_session_hint", "_sudo_gate", "gnoc_secrets",
    )
    if BASH_DENY.search(command):
        return "refused: that command is on the agent's deny list"
    if gnoc_secrets.shell_reads_secret(command, cwd=bind("root")[0]()):
        return ("refused: that command reads a credential store or dumps the environment. Secrets never enter the "
                "chat; refer to a credential by its name and let the tool that needs it read it."
                + _session_hint(ctx))
    why = _sudo_gate(command)
    if why:
        return why
    why = _scope_gate_bash(command, ctx.program)
    if why:
        return f"BLOCKED by scope-gate: {why}"
    why = _bash_target_probe(command, ctx.program)
    if why:
        return why
    return None


def _bash_run(ctx, command, timeout, env):
    """Run one command that already passed _bash_gates (and, before them, dispatch's refusals and approval). The
    BACKEND (gnoc_sandbox: this machine, the session's container, an ssh host) only decides where it runs."""
    (
        INTERRUPT, WS, _ANSI, _cancelled, _rel_home, _spill, os, root, subprocess,
    ) = bind(
        "INTERRUPT", "WS", "_ANSI", "_cancelled", "_rel_home", "_spill", "os", "root", "subprocess",
    )
    import time
    import gnoc_sandbox
    be = gnoc_sandbox.for_session(getattr(ctx, "s", None))
    limit = max(1, min(int(timeout or 120), 900))
    why = be.prepare(root())
    if why:
        return why
    argv, where, token = be.exec_argv(command, root(), env)
    # its own process group: on a timeout subprocess.run killed only bash, and every child (a curl loop, a
    # pipeline stage) kept running after we told the model it "was killed" (reproduced 2026-10-22: sleep | cat)
    # errors="replace": a capture from a .cn host is GBK, a binary blob is anything. With the default strict decode
    # the whole tool call died ("bash failed: UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe8", program-50
    # 2026-11-10 01:32Z) and the lead lost the turn's work; a replacement character in one line loses nothing.
    p = be.popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                 errors="replace", stdin=subprocess.DEVNULL, start_new_session=True, **where)
    # Ctrl-C used to stop only the turn: tools run on worker threads, the KeyboardInterrupt lands on the main
    # thread, and the command (in its own session, so the terminal's SIGINT never reached it) ran on to its
    # timeout. Polling INTERRUPT and this work's cancel events lets the kill reach it - and on a sandbox the kill
    # has to be exec'd inside the container or on the remote, because killing the local client does not stop it.
    was_interrupted = INTERRUPT.is_set()
    deadline = time.monotonic() + limit
    try:
        while True:
            try:
                so, se = p.communicate(timeout=max(0.05, min(0.25, deadline - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                stop = (INTERRUPT.is_set() and not was_interrupted) or _cancelled()
                if not stop and time.monotonic() < deadline:
                    continue
                be.kill(p, token)
                try:
                    got, _ = p.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    got = ""
                if stop:
                    return _spill("INTERRUPTED (Ctrl-C, or this work was cancelled): the command was killed with its "
                                  "whole process group" + (f" inside the {be.kind} sandbox" if be.kind != "local"
                                                           else "") + f". Output so far:\n{_ANSI.sub('', got or '')}",
                                  "bash")
                return _spill(f"TIMED OUT after {limit}s and was killed with its whole process group (timeout= caps "
                              f"at 900). For a server, a watcher or a long job use bg action=start (it keeps running; "
                              f"read it with bg action=output). "
                              + ("A `find /` walks every mounted filesystem: add -xdev (root filesystem only) and "
                                 "2>/dev/null, or start from the folder that matters. "
                                 if __import__("re").search(r"\bfind\s+/(?:\s|$)(?!.*-xdev)", str(command or ""))
                                 else "")
                              + f"Output so far:\n"
                              f"{_ANSI.sub('', got or '')}", "bash")
    except BaseException:
        be.kill(p, token)   # a Ctrl-C or an abandoned turn must not leave the command running either
        raise
    out = _ANSI.sub("", (so or "") + (("\n[stderr]\n" + se) if (se or "").strip() else ""))
    if be.kind == "local" and "No such file or directory" in out and os.path.realpath(root()) != os.path.realpath(WS):
        out += (f"\n[note] this shell runs in {_rel_home(root())}. Workspace paths (reports/..., targets/<other>/..., "
                f"SPINE.md) live under {_rel_home(WS)}: use that prefix, or read_file / list_dir, which resolve both.")
    if be.kind != "local" and be.lost(se):
        out += "\n[note] the sandbox container had stopped; the next command starts a new one."
    if be.kind == "local":
        out += output_note(command, out, p.returncode)
    return _spill(f"exit {p.returncode}\n{out}", "bash")


def _kill_group(p):
    (
        contextlib, os,
    ) = bind(
        "contextlib", "os",
    )
    import signal
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(p.pid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        p.kill()


def _run_group(argv, timeout=None, input=None, capture_output=False, **kw):
    """subprocess.run for a command that spawns children (test runners, npm, gnoc, a shell): same result and the
    same TimeoutExpired, but a timeout kills the whole process group instead of leaving the children running."""
    (
        _kill_group, contextlib, subprocess,
    ) = bind(
        "_kill_group", "contextlib", "subprocess",
    )
    if capture_output:
        kw.setdefault("stdout", subprocess.PIPE)
        kw.setdefault("stderr", subprocess.PIPE)
    if input is not None:
        kw.setdefault("stdin", subprocess.PIPE)
    p = subprocess.Popen(argv, start_new_session=True, **kw)
    try:
        out, err = p.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(p)
        with contextlib.suppress(subprocess.TimeoutExpired):
            p.communicate(timeout=5)
        raise
    except BaseException:
        _kill_group(p)
        raise
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def t_bg(ctx, action="list", name="", command="", text="", tail=60, wait=0, tty=False):
    """Background processes: a dev server, a file watcher, a REPL. start keeps it running past this call; output
    reads what it printed since the last look; send types a line into it; stop ends it (whole process group)."""
    (
        gnoc_bg, gnoc_secrets, root, _spill,
    ) = bind(
        "gnoc_bg", "gnoc_secrets", "root", "_spill",
    )
    action = str(action or "list").lower()
    if action == "list":
        return gnoc_bg.listing()
    if action == "start":
        command = str(command or "")
        if not command.strip():
            return "bad arguments: bg action=start needs name=<short name> and command=<the shell command>"
        why = _bash_gates(ctx, command)
        if why:
            return why
        env = gnoc_secrets.user_env(dict(GNOC_PLAIN="1", **({"HUNT_TARGET": ctx.program} if ctx.program else {})))
        import gnoc_sandbox
        be = gnoc_sandbox.for_session(getattr(ctx, "s", None))
        if be.kind == "local":
            ok, msg = gnoc_bg.start(name, command, root(), env=env, tty=bool(tty))
        else:
            # the same gates ran above; only the executor differs. stop must reach the process INSIDE the sandbox.
            why = be.prepare(root())
            if why:
                return why
            argv, where, token = be.exec_argv(command, root(), env, tty=bool(tty))
            ok, msg = gnoc_bg.start(name, command, root(), env=env, tty=bool(tty), argv=argv,
                                    killer=lambda: be.kill_inside(token), popen=be.popen)
        if not ok:
            return f"refused: {msg}"
        got_ok, first = gnoc_bg.output(name, tail=40, new=True, wait=min(float(wait or 3), 30))
        if isinstance(getattr(ctx, "s", None), dict) and ctx.s.get("_one_shot"):
            # `gnoc chat "start a server ..."` answers once and exits, and everything bg started stops with it. The
            # tool said "It keeps running", the lead said "The server is ready", and the next command found
            # nothing on the port (server drive 2026-11-21).
            return msg + ("\n" + first if got_ok else "") + (
                f"\nIt is running NOW, but this is a one-shot run (gnoc chat \"...\"): everything it started is "
                "stopped when this answer is finished, so it will NOT be up afterwards. Say that plainly. For a "
                "server that stays up the user starts it in an interactive `gnoc chat` (it lives as long as that chat), "
                f"or runs the command themselves: {command}")
        return msg + ("\n" + first if got_ok else "") + (
            f"\nIt keeps running. bg action=output name={name} reads new output; action=stop name={name} ends it.")
    if action == "output":
        ok, out = gnoc_bg.output(name, tail=tail, new=True, wait=wait)
        return _spill(out, "bg") if ok else out
    if action == "log":
        ok, out = gnoc_bg.output(name, tail=tail, new=False)
        return _spill(out, "bg") if ok else out
    if action == "send":
        # typed into a shell or REPL it IS a command: bash's deny list, secrets, sudo and scope gates apply
        # (QAQC 2026-11-19: `bg start command=bash` then send "git push" walked past all of them)
        why = _bash_gates(ctx, str(text or ""))
        if why:
            return why
        ok, out = gnoc_bg.send(name, text)
        return out
    if action == "stop":
        ok, out = gnoc_bg.stop(name)
        return out
    return "action is start, output, log, send, stop or list"
