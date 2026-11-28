"""Which shell commands only read (they run without approval), the bash deny list, and the scope gates a command passes before it runs."""
import os
import re
from .runtime import bind


BASH_READONLY = {"cd", "sed", "rg", "ls", "cat", "head", "tail", "wc", "grep", "find", "file", "stat", "du", "df", "pwd", "echo",
                 "git", "jq", "sort", "uniq", "cut", "awk", "diff", "date", "ps", "free", "uptime", "which",
                 "sha256sum", "md5sum", "base64", "xxd", "strings", "dig", "host", "nslookup", "whois",
                 "whoami", "groups"}     # who am I: `whoami` was held for approval on "who can sudo here"


GIT_READONLY = {"status", "log", "diff", "show", "branch", "ls-files", "blame", "rev-parse"}

# Native Windows: the agent's shell is PowerShell (gnoc_compat.shell_argv), and these only read. Matched like the bash
# words above (each segment's first word, case-insensitive on Windows); a redirect, `$(`, a backtick or a write flag
# still makes the whole command ask.
POWERSHELL_READONLY = {"get-childitem", "gci", "dir", "ls", "get-content", "gc", "type", "cat", "select-string", "sls",
                       "get-location", "gl", "pwd", "get-item", "gi", "get-itemproperty", "test-path", "resolve-path",
                       "split-path", "join-path", "get-process", "gps", "get-service", "get-command", "gcm", "where.exe",
                       "get-date", "write-output", "echo", "write-host", "measure-object", "measure", "sort-object",
                       "sort", "select-object", "select", "where-object", "where", "format-table", "ft", "format-list",
                       "fl", "out-string", "get-filehash", "get-help", "get-netipaddress", "get-nettcpconnection",
                       "get-computerinfo", "hostname", "whoami", "ipconfig", "systeminfo", "tasklist", "netstat",
                       "findstr", "git", "cd", "set-location", "sl", "group-object"}
# (ForEach-Object, %, Where-Object and any `{ ... }` script block can run anything: never read-only)


# Host inspection for defensive questions (what listens, who logged in, the firewall, the services). Read-only ONLY
# in the argument shapes _host_ro() allows; the write forms (ip addr add, ufw allow, iptables -A, systemctl stop,
# hostname NAME, ss -K) fall through to approval. Asked "what is exposed on this machine", the agent had `ss`
# refused and then reported services that do not exist here (driven 2026-10-24).
HOST_READONLY = {"ss", "netstat", "lsof", "who", "w", "last", "id", "uname", "getent", "lsblk", "lscpu", "nproc",
                 "lsmod", "ip", "systemctl", "ufw", "nft", "iptables", "ip6tables", "journalctl", "hostname",
                 "hostnamectl", "arp", "route", "nmap",
                 # status reads a defender question needs ("is secure boot on", "is bluetooth on", "is the clock
                 # right"): each only in the shapes _host_ro() allows below
                 "mokutil", "nmcli", "timedatectl", "bluetoothctl", "sestatus", "findmnt", "lsusb", "lspci", "loginctl",
                 # "is fail2ban installed": what the package manager KNOWS, never what it would change
                 "dpkg", "dpkg-query", "apt", "apt-cache", "rpm", "pacman", "snap", "flatpak", "swapon",
                 "sysctl", "crontab",
                 # "what distribution is this" / "is docker running" / "what is my umask": held for approval, they
                 # were answered from memory as Ubuntu 22.04, yes and 022 (Parrot 7.4, no, 0002) (2026-11-22)
                 "lsb_release", "pgrep", "umask"}


_IP_OBJECTS = {"addr", "address", "a", "link", "l", "route", "r", "ro", "neigh", "neighbor", "neighbour", "n",
               "rule", "ru", "maddr", "m"}


_SYSTEMCTL_READ = {"status", "list-units", "list-unit-files", "list-sockets", "list-timers", "list-dependencies",
                   "is-active", "is-enabled", "is-failed", "show", "cat"}


_IPTABLES_WRITE = {"-A", "-I", "-D", "-R", "-F", "-Z", "-N", "-X", "-P", "-E", "--append", "--insert", "--delete",
                   "--replace", "--flush", "--zero", "--new-chain", "--delete-chain", "--policy", "--rename-chain"}


_NMAP_UNSAFE = ("-o", "--script", "-iL", "-iR", "--resume", "--datadir", "--servicedb", "--versiondb", "-sI", "-b",
                "--proxies", "--stylesheet", "--append-output",
                # --exclude-file / --script-args-file read a FILE the agent can write, so a "self scan" could
                # be pointed at any host list or Lua args (audit A-01 follow-up, 2026-10-28)
                "--exclude-file", "--excludefile", "--script-args-file",
                # --privileged is not a write, but it is the one flag that turns a loopback scan into raw
                # sockets and OS detection: a self-check never needs it, so it asks (2026-10-28)
                "--privileged")


def _host_ro(w, shorts):
    """One segment whose first word is in HOST_READONLY: True when THIS argument shape only reads."""
    (
        _IPTABLES_WRITE, _IP_OBJECTS, _NMAP_UNSAFE, _SYSTEMCTL_READ, gnoc_defend, re,
    ) = bind(
        "_IPTABLES_WRITE", "_IP_OBJECTS", "_NMAP_UNSAFE", "_SYSTEMCTL_READ", "gnoc_defend", "re",
    )
    tool, args = w[0], w[1:]
    pos = [x for x in args if not x.startswith("-")]
    if tool == "ss":
        return "K" not in shorts and "--kill" not in args   # ss -K closes the sockets it lists
    if tool == "ip":
        obj = next((x for x in args if not x.startswith("-")), None)
        verbs = [x for x in pos[1:] if not re.fullmatch(r"[\w.:/%-]+", x) or x in (
            "add", "del", "delete", "set", "flush", "change", "replace", "append", "prepend", "save", "restore",
            "exec", "monitor")]
        return (obj is None or obj in _IP_OBJECTS) and not verbs and (len(pos) < 2 or pos[1] in (
            "show", "list", "lst", "sh", "s", "get", "dev"))
    if tool == "systemctl":
        return bool(pos) and pos[0] in _SYSTEMCTL_READ
    if tool == "ufw":
        return bool(pos) and (pos[0] == "status" or pos[0] == "show" or pos[:2] == ["app", "list"])
    if tool == "nft":
        return bool(pos) and pos[0] == "list"
    if tool in ("iptables", "ip6tables"):
        return not (_IPTABLES_WRITE & set(args)) and any(x in ("-L", "-S", "--list", "--list-rules") or (
            re.fullmatch(r"-[A-Za-z]+", x) and set(x[1:]) & set("LS")) for x in args) and not (
            set(shorts) & set("AIDRFZNXPE"))
    if tool == "journalctl":
        return not any(x.startswith(("--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--smart-relinquish",
                                     "--setup-keys", "--update-catalog")) for x in args)
    if tool == "hostname":
        return not pos and not ({"-F", "--file", "-b", "--boot"} & set(args))
    if tool == "hostnamectl":
        return not pos or pos == ["status"]
    if tool == "arp":
        return not ({"-s", "-d", "--set", "--delete", "-f", "--file"} & set(args))
    if tool == "route":
        return not ({"add", "del", "delete", "flush"} & set(pos))
    if tool == "nmap":
        # a self-check (loopback or this host's own addresses) with no output files, scripts or target lists;
        # anything aimed elsewhere is a scan and asks every time (_needs_approval)
        return not any(x.startswith(_NMAP_UNSAFE) for x in args) and gnoc_defend.scans_only_self(" ".join(w))
    if tool == "sysctl":
        # reading keys: `sysctl KEY ...`, -n, -a. Never -w, KEY=VALUE, -p / --system / --load (those apply settings)
        return not any("=" in x for x in w[1:]) and not ({"-w", "--write", "-p", "--load", "--system"} & set(args)) \
            and not any(x.startswith(("-p", "--load=")) for x in args)
    if tool == "crontab":
        return args == ["-l"] and not pos
    if tool == "swapon":
        return not pos and (not args or set(args) <= {"--show", "-s", "--summary", "--noheadings", "--bytes", "--raw"})
    if tool == "dpkg":
        return bool(args) and args[0] in ("-l", "-s", "-L", "-S", "-p", "--list", "--status", "--listfiles",
                                          "--search", "--print-avail", "--get-selections", "--audit", "-C")
    if tool == "dpkg-query":
        return True
    if tool == "apt":
        return pos[:1] in (["list"], ["show"], ["policy"], ["search"], ["depends"], ["rdepends"])
    if tool == "apt-cache":
        return pos[:1] in (["policy"], ["show"], ["search"], ["depends"], ["rdepends"], ["showpkg"], ["madison"],
                           ["pkgnames"], ["stats"])
    if tool == "rpm":
        return bool(args) and re.fullmatch(r"-q[a-zA-Z]*|--query", args[0]) is not None
    if tool == "pacman":
        return bool(args) and re.fullmatch(r"-Q[a-z]*", args[0]) is not None
    if tool in ("snap", "flatpak"):
        return pos[:1] in (["list"], ["info"], ["find"], ["search"], ["version"])
    if tool == "mokutil":
        return args in (["--sb-state"], ["--list-enrolled"], ["-l"])
    if tool == "umask":
        return args in ([], ["-S"], ["-p"])        # `umask 077` sets it
    if tool == "pgrep":
        return True                                # it only lists; pkill is a different program
    if tool == "nmcli":
        # what the connection IS, never its secrets and never a fresh Wi-Fi scan (`device wifi show` prints the
        # password; `device wifi list` rescans unless told not to)
        if {"-s", "--show-secrets", "-a", "--ask", "-w", "--wait"} & set(args):
            return False
        pos, skip = [], False
        for x in args:               # -f/-g/-m/-c/-e take a value; --rescan's is checked below
            if skip:
                skip = False
            elif x in ("-f", "--fields", "-g", "--get-values", "-m", "--mode", "-c", "--colors", "-e", "--escape",
                       "--rescan"):
                skip = True
            elif not x.startswith("-"):
                pos.append(x)
        p0 = {"g": "general", "d": "device", "dev": "device", "c": "connection", "con": "connection",
              "n": "networking", "r": "radio"}.get(pos[0] if pos else "", pos[0] if pos else "")
        if p0 == "general":
            return pos[1:2] in ([], ["status"], ["hostname"], ["permissions"]) and len(pos) <= 2
        if p0 == "device":
            if pos[1:2] == ["wifi"]:
                return pos[2:3] in ([], ["list"]) and "--rescan" in args \
                    and args[args.index("--rescan") + 1:args.index("--rescan") + 2] == ["no"]
            return pos[1:2] in ([], ["status"], ["show"])
        if p0 == "connection":
            return pos[1:2] in ([], ["show"])
        if p0 in ("radio", "networking"):
            return len(pos) == 1 or pos[1:] in (["all"], ["wifi"], ["wwan"], ["connectivity"])
        return not pos
    if tool == "timedatectl":
        return not pos or pos[:1] in (["status"], ["show"], ["timesync-status"], ["show-timesync"])
    if tool == "bluetoothctl":
        return pos[:1] in (["show"], ["devices"], ["list"], ["paired-devices"], ["paired"], ["info"]) and len(pos) <= 2
    if tool == "loginctl":
        return not pos or pos[:1] in (["list-sessions"], ["list-users"], ["list-seats"], ["show-user"],
                                      ["show-session"], ["user-status"], ["session-status"])
    if tool == "findmnt":
        return not any(x.startswith(("--fstab-", "-o=")) for x in args) and not ({"--verify", "-x"} & set(args))
    return True   # netstat, lsof, who, w, last, id, uname, getent, lsblk, lscpu, nproc, lsmod, sestatus, lsusb, lspci


BASH_DENY = re.compile(r"(\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)(\s|$)|\bgit\s+push\b|\bpm2\s+(delete|kill)\b|"
                       # QAQC 2026-11-19: `rm -rf /*`, `~/`, `$HOME/`, `${HOME}`, `--no-preserve-root`, and
                       # `git -C . push` / `git --no-pager push` all walked past the two spellings above
                       r"\brm\s+(?:-\S+\s+)*(?:--no-preserve-root\b|(?:/\*?|~/?\*?|\$\{?HOME\}?/?\*?)(?=\s|$|[;&|]))|"
                       # any ARGUMENT of a recursive rm that is the root or home, quoted or not, anywhere in the
                       # list: `rm -rf x /`, `rm -rf /.`, `rm -rf //`, `rm -rf "$HOME"` (QAQC r2)
                       r"\brm\b(?=[^|;&\n]*\s-(?:[a-zA-Z]*[rR]|-recursive))[^|;&\n]*?\s[\"']?"
                       r"(?:/+\.?|/\*|~/?\*?|\$\{?HOME\}?/?\*?)[\"']?/?(?=\s|$|[;&|])|"
                       r"\bgit(?:\s+(?:-[Cc]\s*\S+|--[\w-]+(?:=\S+)?|-[A-Za-z]+))+\s+push\b|"
                       r"\bmkfs\b|\bdd\s+if=|(?<![.\w])shutdown\b(?!\s*\()|(?<![.\w])reboot\b(?!\s*\()|:\(\)\s*\{|\bchmod\s+-R\s+777\s+/|"
                       r"hackerone\.com/v1/hackers/reports|\bgnoc\s+(ship|submit)\b|\bcurl\b[^|]*\|\s*(ba)?sh|"
                       # The scripts that actually POST to a platform. "no submit tool" is stated as a
                       # hard limit that survives -s-p, but BASH_DENY only knew the `gnoc submit` spelling
                       # and the raw API URL, so `python3 scripts/h1-submit-report.py --send` walked
                       # straight through it (soak batch18 2026-10-25). Filing, and every comment or reply
                       # headed to a platform, is GreyNOC's own shell, never the agent's bash.
                       r"\b(h1-submit-report|h1-comment|vdp-autosubmit)(\.py)?\b|"
                       # gnoc_file.py is chat's typed-only /file: a shell that runs or imports it is the model
                       # filing (2026-11-25). Reading it (cat, grep) and running its tests stay allowed.
                       r"\bpython[\w.]*\b[^|;&\n]*\bgnoc_file\b|\b(?:import|from)\s+gnoc_file\b|"
                       r"(?:^|[;&|]\s*)[^\s;&|]*gnoc_file\.py\b|"
                       # a shell write onto a hunt ledger: it must go through hunt-state.py, which validates.
                       # Reads stay free; only a redirect/tee/sed -i whose TARGET is the ledger is denied.
                       r">>?[^|;&<>]*(outcomes|ships)\.jsonl|"
                       r"\b(tee|truncate|dd)\b[^|;&]*(outcomes|ships)\.jsonl|"
                       r"\bsed\b[^|;&]*-i[^|;&]*(outcomes|ships)\.jsonl)")


GNOC_READONLY = {"status", "inbox", "reports", "needs", "outcomes", "lanes", "models", "help", "handoff", "hq",
                 "qaqc"}


GNOC_SUB_READONLY = {("orch", "report"), ("orch", "status"), ("orch", "queue"), ("orch", "log"),
                     ("oss", "status"), ("oss", "leads"), ("oss", "plan"), ("leads", "--once"),
                     ("video", "list"), ("video", "outputs"), ("video", "help"), ("video", "projects"),
                     ("video", "show"), ("video", "tutorials"), ("video", "clips"),  # renders and edits stay 'write' (they write ~/Downloads)
                     # status readers (QAQC 2026-10-24: a one-shot `gnoc chat` could not answer "is the phone up")
                     ("phone", "status"), ("company", "status"), ("company", "journal"), ("line", "status"),
                     ("line", "show"), ("line", "current"), ("line", "trap"), ("econ", "status"), ("econ", "audit"),
                     ("intel", "status"), ("oracle", "status"), ("oracle", "classes"), ("oracle", "banner"),
                     ("lab", "list"), ("droid", "status"), ("sandbox", "ls")}


# a read-only verb followed by one of these is a write (`models rm`, `reports archive`, `leads --fix`)
GNOC_MUTATING = {"rm", "use", "pull", "set", "clear", "archive", "ready", "new", "add", "remove", "delete", "kill",
                 "--fix", "--force", "--delete", "reindex", "--refresh"}


# fleet / loop controls: GreyNOC's call EVERY time, -s-p and /auto included (a greeting once got `stop` + `resume`
# run against the whole hunt fleet by a fallback model under skip-perms)
GNOC_CONTROL = {"stop", "resume", "pivot", "lock", "unlock", "lane", "kill-lane", "start", "fleet", "orch", "oss",
                "svc", "split", "droid", "lab", "sandbox", "zip", "bundle", "mine"}


GNOC_DENY = {"ship", "submit", "chat", "dchat", "watch", "dash", "chair", "menu", "code", "prune", "replies",
             "schedule"}   # only the user sets or runs a schedule (gnoc_schedule.model_refusal says why)


_SED_SAFE_CMD = set("pPdDqQ=nNlhHxGg")
_SED_LONG = ("in-place", "file", "expression", "quiet", "silent", "debug", "posix", "regexp-extended", "separate",
             "sandbox", "unbuffered", "null-data", "zero-terminated", "line-length", "follow-symlinks", "binary",
             "help", "version")   # print, delete, quit, line number, next, list, hold-space moves


def _sed_script_ro(script):
    """True only for a sed SCRIPT that cannot write a file.

    sed writes without any shell redirect: the `w FILE` and `W FILE` commands, and the `w` flag on
    `s///w FILE`, all open a file themselves. A substring test cannot tell those from a `w` inside a
    regex address (`/word/p`), so the script is walked: addresses are skipped, and the command
    character that follows one has to be in the print/delete/quit set. Anything else - `s`, `w`, `W`,
    `r`, `R`, `e`, `a`, `i`, `c`, `y`, a `{` block or a `b`/`t` branch - returns False. Refusing all
    of `s///` is deliberate over-refusal: a plain substitution only prints, but `s///w` does not, and
    the approval prompt is the safe failure.
    """
    (
        _SED_SAFE_CMD,
    ) = bind(
        "_SED_SAFE_CMD",
    )
    s, i, n = str(script or ""), 0, len(str(script or ""))
    while i < n:
        c = s[i]
        if c in " \t;":
            i += 1
        elif c in "0123456789$,+~!":          # line numbers, last line, ranges, step, negation
            i += 1
        elif c == "/":                        # /regex/ address: skip to the unescaped closing slash
            i += 1
            while i < n and s[i] != "/":
                i += 2 if s[i] == "\\" else 1
            if i >= n:
                return False                  # unterminated address: do not guess
            i += 1
            while i < n and s[i] in "IM":     # GNU address flags
                i += 1
        elif c in _SED_SAFE_CMD:
            i += 1
        else:
            return False
    return True


def _sed_readonly(w):
    """True only for a `sed` invocation that cannot write: no in-place flag in any position, no script
    read from a file (its bytes are unknown here), and every script it is given print-only."""
    (
        _sed_script_ro,
    ) = bind(
        "_sed_script_ro",
    )
    # _bash_readonly splits a segment with a plain .split(), so an argument still carries the shell
    # quotes it was written with: the script arrives as "'1,5p'", not 1,5p. Strip one matched pair.
    def unquote(x):
        x = str(x)
        return x[1:-1] if len(x) >= 2 and x[0] == x[-1] and x[0] in "'\"" else x

    args, scripts, want_script, saw_e = [unquote(x) for x in w[1:]], [], False, False
    for a in args:
        if want_script:                       # the value of a preceding -e
            scripts.append(a)
            want_script = False
            continue
        if a.startswith("--"):
            # GNU getopt accepts any unambiguous prefix: `--in` is --in-place, `--fi=x` is --file, `--e=` is
            # --expression (QAQC 2026-11-19: all three slipped past the startswith tests that were here).
            name = a[2:].split("=", 1)[0]
            hits = [o for o in _SED_LONG if o.startswith(name)] if name else []
            if not hits or any(o in ("in-place", "file") for o in hits):
                return False                  # unknown, ambiguous with in-place/file, or one of them
            if hits == ["expression"] or name == "expression":
                if "=" in a:
                    scripts.append(unquote(a.split("=", 1)[1]))   # the quotes sit after the =, not around it
                    saw_e = True
                else:
                    want_script, saw_e = True, True
            continue
        if a.startswith("-") and len(a) > 1:
            body = a[1:]
            if "i" in body or "f" in body:
                return False                  # -i / -ni / -i.bak, and -f script.sed
            if "e" in body:
                want_script, saw_e = True, True
            continue
        scripts.append(a) if not saw_e and not scripts else None   # bare script only when no -e
    if want_script or not scripts:
        return False                          # a dangling -e, or no script at all
    return all(_sed_script_ro(x) for x in scripts)


# Wrappers in front of the real command: {word: (flags that take a value, flags that take none)}. Anything else
# after the wrapper word is an unknown flag and the command is not judged read-only.
_TIMEOUT_FLAGS = frozenset({"-s", "-k", "--signal", "--kill-after"})
_WRAPPERS = {
    "sudo": (frozenset({"-u", "-g", "--user", "--group"}), frozenset({"-n", "--non-interactive"})),
    "env": (frozenset({"-u", "--unset"}), frozenset({"-i", "--ignore-environment"})),
    "nohup": (frozenset(), frozenset()),
    "timeout": (_TIMEOUT_FLAGS, frozenset({"--preserve-status", "--foreground", "-v", "--verbose"})),
    "nice": (frozenset({"-n", "--adjustment"}), frozenset()),
    "time": (frozenset(), frozenset({"-p", "--portability", "-v", "--verbose"})),
}
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
# variables that change WHAT runs or what a reader loads: a loader preload, the search path, git's external
# diff/pager/config, an interpreter's startup or module path, a pager or editor, a tool's own config file
# (RIPGREP_CONFIG_PATH can carry --pre), less's input preprocessor. Any other assignment (FOO=1, LC_ALL=C) only
# changes how output looks and stays read-only.
_RISKY_ENV = re.compile(r"^(?:LD_\w*|DYLD_\w*|GIT_\w*|PATH|IFS|ENV|BASH_ENV|BASH_FUNC_\w*|ZDOTDIR|SHELL|SHELLOPTS|"
                        r"BASHOPTS|PROMPT_COMMAND|CDPATH|HOME|TMPDIR|XDG_\w*|PAGER|\w*_PAGER|MANPAGER|EDITOR|VISUAL|"
                        r"PYTHON\w*|PERL\w*|RUBY\w*|NODE_\w*|JAVA_TOOL_OPTIONS|AWKPATH|RIPGREP_CONFIG_PATH|LESS\w*|"
                        r"GCONV_PATH|GLIBC_TUNABLES|MALLOC_\w*|OPENSSL_\w*|SSL_\w*|CURL_\w*|WGETRC)$")


def _abbrev(longs, names, minlen):
    """True when any --option in `longs` is a getopt_long abbreviation (or the full spelling) of one of `names`."""
    for x in longs:
        n = x[2:].split("=", 1)[0]
        if len(n) >= min(minlen, max(len(t) for t in names)) and any(t.startswith(n) for t in names):
            return True
    return False


def _git_branch_creates(rest):
    """`git branch NAME [START]` creates a ref; the listing forms take a name only after --list/-l or as the
    value of --contains / --merged / --no-merged / --points-at / --sort / --format."""
    valued = {"--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--sort", "--format",
              "--column"}
    listing = any(x in ("--list", "-l") or (x.startswith("-") and not x.startswith("--") and "l" in x[1:])
                  for x in rest)
    skip = False
    for x in rest:
        if skip:
            skip = False
            continue
        if x in valued:
            skip = True
            continue
        if not x.startswith("-") and not listing:
            return True
    return False


_VERSION_TOOLS = frozenset({"python", "python3", "node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "go", "cargo",
                            "rustc", "java", "javac", "gcc", "g++", "clang", "make", "cmake", "pip", "pip3", "ruby",
                            "perl", "php", "dotnet", "tsc", "pytest", "ruff", "mypy", "flake8", "black", "eslint",
                            "docker", "kubectl", "terraform", "gh", "uv", "poetry", "ollama"})


def _mask_quotes(cmd):
    """`cmd` with the CONTENTS of '...' and of plain "..." replaced by '_' (same length), so a | ; & > inside quotes
    is not read as a separator or a redirect. None when the quoting is not plain: unbalanced, or a "..." holding $ `
    or \\ that the shell would expand - then the raw text is judged, which only ever asks more often."""
    out, i, n, q = [], 0, len(cmd), None
    while i < n:
        c = cmd[i]
        if q is None:
            if c == "\\":                 # an escaped char outside quotes: literal, and never opens a quote
                out.append(cmd[i:i + 2])
                i += 2
                continue
            if c in "'\"":
                q = c
            out.append(c)
            i += 1
            continue
        if q == "'":
            out.append(c if c == "'" else "_")
            q = None if c == "'" else q
            i += 1
            continue
        if c in "$`\\":
            return None
        out.append(c if c == '"' else "_")
        q = None if c == '"' else q
        i += 1
    return None if q else "".join(out)


# tools where an ARGUMENT can be a flag that writes or runs (find -delete, sort -o, rg --pre, git --output): an
# unquoted glob there expands to whatever file names the directory holds, and a repo can ship a file named -delete
_FLAG_TOOLS = {"find", "sort", "rg", "git", "sed", "awk", "gawk", "mawk", "uniq", "date", "diff", "xxd", "jq"}


def _bash_readonly(cmd):
    """True only for a command that cannot change anything: every segment's first word is a read-only tool
    and no segment carries a write-shaped flag. Used to skip the approval prompt (and the taint gate), so a
    false True here is an unattended write: a newline, a single '&' and a process substitution '<(...)'
    are command separators too and were missed once."""
    (
        BASH_READONLY, GIT_READONLY, HOST_READONLY, _host_ro, _sed_readonly, re,
    ) = bind(
        "BASH_READONLY", "GIT_READONLY", "HOST_READONLY", "_host_ro", "_sed_readonly", "re",
    )
    cmd = str(cmd or "")
    # `bash -lc 'cat /proc/swaps'` is `cat /proc/swaps`: gpt-oss wraps every command this way and each one asked
    # (scored defense batch 2026-11-22). Only the plain shapes: one single-quoted string with no quote in it, or one
    # double-quoted string with nothing the shell would expand or unescape. The inner command is judged as usual.
    if re.fullmatch(r"\s*[A-Za-z][\w.+-]*\s+(?:--version|-V)\s*", cmd):
        return True     # `git --version`, `python3 --version`: a program on PATH saying which one it is
    wrapped = re.fullmatch(r"\s*(?:ba)?sh\s+-l?c\s+(?:'([^']*)'|\"([^\"\\$`!]*)\")\s*", cmd, re.S)
    if wrapped:
        return _bash_readonly(wrapped.group(1) if wrapped.group(1) is not None else wrapped.group(2))
    # 2>/dev/null, >/dev/null, &>/dev/null and 2>&1 discard or merge output and write nothing; every other
    # redirect is a write. Stripped first so the common `ss -tulpn 2>/dev/null | grep LISTEN` still reads.
    cmd = re.sub(r"(?:(?<=\s)|^)(?:[012]?>|&>)\s*/dev/null(?=\s|$|[|;&])|(?:(?<=\s)|^)2>&1(?=\s|$|[|;&])", " ", cmd)
    # The shell runs the argv it BUILDS - quotes removed, escapes resolved, words expanded - so that is what is judged.
    # Judging the raw text let `find . '-delete'`, `find . -\delete`, `rg '--pre' rm x .`, `git diff '--output=F'`,
    # `X=-delete; find . $X`, `find . ${X:--delete}` and `find . -{delete,print}` all run unasked, while
    # `grep -n 'a|b' f` and a quoted git --format asked (2026-11-20 SWE drive / audit).
    if "$'" in cmd or '$"' in cmd:
        return False   # ANSI-C and locale quoting resolve escapes this parser does not model
    masked = _mask_quotes(cmd) if os.name != "nt" else None
    scan = masked if masked is not None else cmd
    if re.search(r"[>]", scan) or re.search(r"\btee\b|\bsed\s+-i|\$\(|`|<\(|[\n\r]", cmd):
        return False
    if re.search(r"\$\{[^}]*[^\w}]", scan):
        return False   # ${X:-...} ${X:=...} ${X/a/b}: an operator makes the value up on the spot
    if "$" in scan and re.search(r"(?:^\s*|[;&|({]\s*)(?:(?:export|declare|local|readonly|typeset)\s+(?:-\w+\s+)*)?"
                                 r"[A-Za-z_]\w*=|\b(?:read|mapfile|readarray)\b|\bprintf\s+-v\b", scan):
        return False   # a value set in the command and expanded in it: X=-delete; find . $X
    if re.search(r"(?<!\$)\{[^{}\s]*(?:,|\.\.)[^{}\s]*\}", scan):
        return False   # brace expansion: -{delete,print} is two flags
    # a read of hidden files in a home folder (where credentials live) always asks: the secret gate is a text
    # filter, and a glob or an encoding it does not foresee must not also skip the approval (QAQC r2)
    if re.search(r"(^|[\s'\"=])(~|\$\{?HOME\}?|/home/[^/\s]+|/root)/[\"']?\.", cmd):
        return False
    import shlex
    cuts, last = [], 0
    for m in re.finditer(r"\|\||&&|;|\||&", scan):   # separators OUTSIDE quotes only
        cuts.append((last, m.start()))
        last = m.end()
    cuts.append((last, len(scan)))
    for a, b in cuts:
        seg, seg_scan = cmd[a:b], scan[a:b]
        try:
            w = shlex.split(seg)              # the argv the shell builds: quotes and escapes resolved
        except ValueError:
            return False
        if not w:
            continue
        # A leading assignment or wrapper is not the command: `FOO=1 ls` and `timeout 5 ls` were refused
        # as unknown words, while `nmap --privileged ...` reached _host_ro with the flag in w[0] and skipped
        # every nmap rule (audit A-01 follow-up, 2026-10-28). Strip them so the real tool is judged.
        # QAQC 2026-11-19: this used to treat every wrapper flag alike, so `time -p rm -rf ls x` and `sudo -n rm
        # ...` lost the real command as a flag "value" and were judged by `ls`; and ANY assignment was skipped,
        # so `GIT_EXTERNAL_DIFF=rm git diff`, `LD_PRELOAD=x ls` and `PATH=/tmp ls` ran unasked. Now each wrapper
        # knows exactly which of its flags take a value, an unknown flag means "not judged here" (False, so it
        # asks), and only assignments that cannot change what runs are skipped.
        while w and (_ASSIGN.fullmatch(w[0]) or w[0] in _WRAPPERS):
            if _ASSIGN.fullmatch(w[0]):
                if _RISKY_ENV.match(w[0].split("=", 1)[0]):
                    return False
                w = w[1:]
                continue
            takes, bare = _WRAPPERS[w[0]]
            w = w[1:]
            while w and w[0].startswith("-") and w[0] != "-":
                f = w[0]
                if f == "--":
                    w = w[1:]
                    break
                if f in bare or (f.startswith("--") and "=" in f and f.split("=", 1)[0] in takes):
                    w = w[1:]
                elif f in takes and len(w) > 1:
                    w = w[2:]
                else:
                    return False   # a wrapper flag this table does not know (sudo -s, env -S, time -o FILE)
            if takes is _TIMEOUT_FLAGS and w and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", w[0]):   # timeout 30
                w = w[1:]
        if not w:
            continue
        if w[0] in _FLAG_TOOLS and re.search(r"[*?\[]", seg_scan.strip().partition(" ")[2]):
            return False   # an unquoted glob: the directory's file names become arguments (a file named -delete)
        if w[0] in HOST_READONLY:
            if not _host_ro(w, "".join(x[1:] for x in w[1:] if re.fullmatch(r"-[A-Za-z]+", x))):
                return False
            continue
        if w[0] in ("gnoc", "gnoc-engine") and [x for x in w[1:] if not x.startswith("-")] in (
                ["engine", "ps"], ["engine", "status"], ["engine", "version"], ["gpus"], ["ps"], ["status"],
                ["version"], ["models"], ["engine", "list"], ["list"]):
            continue   # gnoc's own status reads: "is my model on the GPU" held `gnoc engine ps` for approval (batch 15)
        if len(w) == 2 and w[0] in _VERSION_TOOLS and w[1] in ("--version", "-V", "version"):
            continue   # `python3 --version`, `node --version`: asked for approval 4 times in one SWE drive batch
            # (2026-11-20). Known tools by NAME only (never a path like ./x), and the version flag alone.
        # A syntax / validity CHECK of one named file: it parses the file and prints, and writes nothing.
        # "is config.json valid JSON?" had no way to check without approval (json drive 2026-11-21).
        #   python3 -m json.tool FILE      (one file: a second path would be the OUTPUT file)
        #   node --check FILE, bash -n FILE, sh -n FILE
        # The file is data to the checker, never run. Names only (no ./python3), no other flag.
        _plain = lambda x: bool(re.fullmatch(r"[\w./-]+", x)) and not x.startswith("-")   # noqa: E731
        if (len(w) == 4 and w[0] in ("python", "python3") and w[1:3] == ["-m", "json.tool"] and _plain(w[3])) \
                or (len(w) == 3 and w[0] == "node" and w[1] == "--check" and _plain(w[2])) \
                or (len(w) == 3 and w[0] in ("bash", "sh") and w[1] == "-n" and _plain(w[2])):
            continue
        if os.name == "nt" and "{" in seg:
            return False   # a PowerShell script block runs whatever is inside it
        if w[0] not in BASH_READONLY and not (os.name == "nt" and w[0].lower() in POWERSHELL_READONLY):
            return False
        if w[0] == "git" and (len(w) < 2 or w[1] not in GIT_READONLY):
            return False
        if w[0] == "sed" and not _sed_readonly(w):
            return False  # sed's own `w`/`W` commands write a file with no redirect (see _sed_readonly)
        if w[0] == "date" and any(x in ("-s", "--set") or re.fullmatch(r"-[A-Za-z]*s\S*", x)
                                  or x.startswith("--set=") for x in w[1:]):
            return False  # `date -s 2020-01-01` sets the system clock (audit A-01 follow-up, 2026-10-28)
        if w[0] == "find" and any(x in ("-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls")
                                  or x.startswith(("-fprint", "-fprintf")) for x in w):
            return False  # -fprint*/-fls write a file, the rest run or remove
        if w[0] in ("awk", "gawk", "mawk") and ("system" in seg or "inplace" in seg or "@" in seg
                                                or any(x in ("-i", "--in-place") for x in w)
                                                # a program read from a FILE (-f/-E), an extension (-l) or an
                                                # include (-i) is code nobody read here, as sed -f is
                                                or any(re.fullmatch(r"-[fEil]\S*", x) or x.startswith(
                                                    ("--f", "--e", "--l", "--i")) for x in w[1:])
                                                # awk's own print/printf redirection writes a file, and
                                                # `"cmd" | getline` / `print | "cmd"` runs a command. These need
                                                # no shell redirect, so the scan above cannot see them (drive
                                                # 2026-11-22: `awk 'BEGIN{print 1 > "/tmp/x"}'` was read-only).
                                                or re.search(r"\b(?:print|printf)\b[\s\S]*?(?:>>?|\|)", seg)
                                                or ("getline" in seg and "|" in seg)):
            return False  # system() runs anything; -i inplace rewrites the file it reads; gawk's @f() indirect
            # call reaches system with the name assembled at run time ("sys" "tem", audit A-01, still open
            # 2026-10-24), and @include / @load pull in code
        # A WRITE FLAG on a "read" command. These were the real holes (audit A-01, each reproduced
        # 2026-10-22): `sort -uo F` hid -o inside a COMBINED short flag, `git diff --output=F` and
        # `git branch -D x` were waved through because only the subcommand was checked, and `uniq IN OUT`
        # takes its output file as a bare second argument with no flag at all.
        shorts = "".join(x[1:] for x in w[1:] if re.fullmatch(r"-[A-Za-z]+", x))
        longs = [x for x in w[1:] if x.startswith("--")]
        if w[0] == "git" and len(w) > 1 and w[1] in ("diff", "show", "log", "blame") and (
                _abbrev(longs, ("ext-diff",), 3) or _abbrev(longs, ("textconv",), 3)):
            return False  # these run a command from the repo's config (diff.external / textconv), not a read
        if w[0] == "rg" and any(x.startswith("--pre") for x in longs):
            return False  # rg --pre CMD runs CMD on every file it searches (QAQC 2026-11-19: `rg --pre rm x d`)
        if w[0] == "sort" and _abbrev(longs, ("compress-program",), 2):   # `--co=` is enough for GNU sort
            return False  # sort --compress-program=sh runs a program on its temp files
        if w[0] == "file" and ("C" in shorts or _abbrev(longs, ("compile",), 3)):
            return False  # file -C compiles a magic file: it writes <name>.mgc
        if w[0] in ("sort", "uniq", "comm", "join", "cut", "base64", "xxd", "strings") and "o" in shorts:
            return False
        if any(x.startswith(("--output", "--out-file", "--write-out", "--result-file")) for x in longs) or \
                _abbrev(longs, ("output", "out-file", "write-out", "result-file"), 1):   # `--o=F` too (QAQC r2)
            return False  # getopt_long takes an unambiguous prefix: `sort --outp=F` is --output
        if w[0] in ("uniq", "xxd") and len([x for x in w[1:] if not x.startswith("-")]) > 1:
            return False  # `uniq INPUT OUTPUT` / `xxd [-r] INPUT OUTPUT` write OUTPUT without any flag
        if w[0] == "git" and len(w) > 1:
            if w[1] == "branch" and (set("dDmMfcCut") & set(shorts)
                                     or any(x.startswith(("--delete", "--move", "--copy", "--force", "--set-upstream",
                                                          "--unset-upstream", "--track", "--no-track",
                                                          "--edit-description", "--create-reflog")) for x in longs)
                                     or _git_branch_creates(w[2:])):
                return False  # git branch -D / -M deletes or renames a ref; `git branch NAME` / -u write too
            if w[1] in ("diff", "show", "log", "blame") and "o" in shorts:
                return False
    return True


def _scope_gate_bash(cmd, program):
    """Run the workspace's real scope-gate hook on the command. Returns None or the block reason."""
    (
        WS, gnoc_secrets, json, os, subprocess,
    ) = bind(
        "WS", "gnoc_secrets", "json", "os", "subprocess",
    )
    hook = os.path.join(WS, ".claude/hooks/scope-gate.sh")
    if not os.path.isfile(hook):
        # a public install has no hook: this used to return None, so bash went unchecked with a programme active
        if not program:
            return None
        import gnoc_missing
        try:
            from bbtools import lib_scope
        except Exception as e:  # noqa: BLE001 - no scope parser, no way to say yes
            return (f"blocked: the scope parser did not load ({type(e).__name__}); "
                    "a command it cannot check does not run")
        return gnoc_missing.bash_scope_check(cmd, program, WS, _BASH_HTTP_CLIENT, lib_scope.program_allows,
                                             lib_scope.extract_host)
    pinned = f"HUNT_TARGET={program} {cmd}" if program else cmd
    payload = {"tool_name": "Bash", "tool_input": {"command": pinned}, "cwd": WS, "session_id": "gnoc-agent"}
    env = gnoc_secrets.child_env({"HUNT_TARGET": program} if program else {})   # T1.7
    try:
        r = subprocess.run(["bash", hook], input=json.dumps(payload), capture_output=True, text=True,
                           timeout=20, cwd=WS, env=env)
    except (subprocess.TimeoutExpired, OSError) as e:
        return f"blocked: the scope gate did not answer ({type(e).__name__}); a command it cannot check does not run"
    if r.returncode == 2:
        return r.stderr.strip() or "blocked by scope-gate"
    if r.returncode != 0:
        # the hook exists but crashed (an unbound variable under set -u exits 1): fail CLOSED here, the agent has no
        # second gate behind it (QAQC r2: any non-2 exit counted as "allowed")
        return (f"blocked: the scope gate failed (exit {r.returncode}): {(r.stderr or '').strip()[:200]}; "
                "a command it cannot check does not run")
    return None


# A client WORD: at a command position or after a path (/usr/bin/curl), and followed by an argument, so a URL's
# scheme ("http://...") inside a grep pattern is not a client (QAQC 2026-11-19: the path form slipped through,
# and every local grep of an in-scope URL was refused).
_BASH_HTTP_CLIENT = re.compile(r"(?<![\w.-])(curl|wget|httpx|http|xh|nc|ncat|openssl\s+s_client|ab|wrk|hey|ffuf|"
                               r"feroxbuster|gobuster|dirb|nikto|nuclei|sqlmap)(?=\s|$)|requests\.(get|post|put|"
                               r"patch|delete|head|options|request|Session)|urllib\.request|aiohttp\.|httpx\.|"
                               r"curl_cffi|urlopen\(", re.I)


def _bash_target_probe(cmd, program):
    """A bash command that drives an HTTP client at an IN-SCOPE host is a probe, and probes go through
    http_request / probe_matrix / sweep: those add the programme's identification header, honour its rate, save
    the raw exchange beside a signature, consult the dedup and the route walls, and count toward the floor. A
    raw `curl` carries none of that: plain curl's TLS fingerprint fakes 403/429 negatives (T-153), nothing is
    captured, and nothing is counted. Measured 2026-11-10 00:38Z on program-58: the lead's first three probes were
    bash curl (no X-HackerOne-Research header, deepwiki 429 x2 read as a wall, app.example.com fetched with no
    capture) and it stayed on bash until the 60-call cap. Loopback and out-of-scope hosts are not this gate's
    business (the scope gate owns the latter), and a command with no HTTP client (grep, cat, python parsing) is
    local work and passes."""
    (
        WS, _BASH_HTTP_CLIENT, re,
    ) = bind(
        "WS", "_BASH_HTTP_CLIENT", "re",
    )
    text = str(cmd or "")
    if not program or not _BASH_HTTP_CLIENT.search(text):
        return None
    try:
        # the same parser the http_request gate uses, so the exact rows AND the wildcard zones count
        # (gnoc_hunt.scope_hosts returns URL rows only: 50 of program-50's 234 usable rows, measured 2026-11-10)
        from bbtools import lib_scope
        hosts = [h.lower() for h in lib_scope.exact_hosts(program, WS)]
        wild = [a.lower() for a in lib_scope.wildcard_apexes(program, WS)]
    except Exception:  # noqa: BLE001 - no scope, nothing to protect
        return None
    low = text.lower()
    hit = next((h for h in hosts if re.search(r"(?<![a-z0-9.-])" + re.escape(h) + r"(?![a-z0-9-])", low)), None)
    if not hit:
        for apex in wild:
            m = re.search(r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*" + re.escape(apex) + r"(?![a-z0-9-])", low)
            if m:
                hit = m.group(0)
                break
    if not hit:
        return None
    return (f"refused: that bash command drives an HTTP client at {hit}, an in-scope host of {program}. A probe "
            "goes through http_request (one request, raw capture + identification header + rate + walls), "
            "probe_matrix (variants of one request) or sweep (one path list on one host); JS bundles go through "
            "js_mine. bash is for local work: parsing captures, grep, files. Re-issue this request with the tool "
            "that fits.")
