"""gnoc_sandbox.py - where the agent's shell runs: this machine, a per-session container, or another host.

Every tool used to run on the host (Hermes gap 7, docs/plans/hermes-gap-audit.md). A backend here is only an
EXECUTOR. It is reached from two places, `_bash_run` and `bg action=start` (gnoc_tools/proc.py), and both run
after `_bash_gates` (deny list, secrets, sudo, scope gate, target probes), which itself runs after `_plan_call`'s
refusals and the approval engine. So a command is judged exactly the same way whichever backend runs it; the
backend decides only WHERE it runs.

    local   today's behaviour: bash on this machine, in the active repo
    docker  one container per conversation (docker or podman): the active repo bind-mounted at the SAME path (so
            paths in messages stay valid and the host-side /undo snapshot still works), no network unless the
            user typed --network, the user's uid:gid, read-only root filesystem, /tmp in memory, every capability
            dropped, no-new-privileges. Nothing else of the host is mounted: never the docker socket, never $HOME,
            never ~/.config/gnoc or ~/.gnoc.
    ssh     an existing host, key login only (BatchMode, no password or keyboard-interactive), its host key
            checked against known_hosts and never auto-accepted, commands run in a configured remote directory.

Only the user switches backend (/sandbox, typed at the prompt). The session keeps the choice in s["sandbox"];
a model call that names /sandbox is refused in dispatch, the same way a schedule is.
"""
from __future__ import annotations

import atexit
import base64
import contextlib
import json
import os
import posixpath
import re
import shlex
import shutil
import signal
import subprocess
import threading
import uuid

KINDS = ("local", "docker", "ssh")
DEFAULT_IMAGE = "python:3.12-slim"   # small, and it has python3 + bash, so tests and scripts run as on the host
SSH_CONNECT_TIMEOUT = 10
KILL_TIMEOUT = 15

# the only variables that cross into the sandbox. user_env() is the host's environment minus gnoc's secrets; it
# still holds the user's own tokens and paths, which a container or another host has no business seeing.
ENV_PASS = ("GNOC_PLAIN", "HUNT_TARGET", "PYTHONDONTWRITEBYTECODE", "LANG", "LC_ALL", "TZ")

# Tools that would run repo-controlled code or config ON THE HOST. With the repo bind-mounted, code in the container
# can write conftest.py, an eslint config or .git/config (core.fsmonitor, a clean filter, a hook path); the host
# then executes it the moment run_tests, lint, typecheck or git touches the repo. On a sandbox they are refused
# and bash (which runs in the sandbox) is the way.
HOST_TOOLS = frozenset({"run_tests", "lint", "typecheck", "git", "code_review", "gnoc", "claude_worker"})

_HOST = re.compile(r"^(?:[A-Za-z0-9._][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")
_REMOTE_DIR = re.compile(r"^(?:~|~/[^\x00\n\r]*|/[^\x00\n\r]*)$")
_SAFE = re.compile(r"[^A-Za-z0-9_.-]")

# Runs inside the sandbox around every command. The pid goes to a file first, so a Ctrl-C can find the command:
# `docker exec` does not forward signals reliably, and killing the local client leaves the command running in the
# container (measured on podman 5.4: the client exited, `sleep 61 & sleep 62` kept going). Not exec'd, so the
# pidfile is removed when the command ends.
WRAP = ('echo $$ >"$1" || exit 125; '
        'if command -v bash >/dev/null 2>&1; then bash -c "$2"; else sh -c "$2"; fi; '
        'r=$?; rm -f "$1"; exit $r')

# Kills the process GROUP of the recorded pid by walking /proc (pgrp is field 5 of /proc/<pid>/stat; the text after
# the last ") " starts at field 3, so a command name with spaces cannot shift it). Not `kill -- -PGID`: dash, the
# /bin/sh of Debian images, rejects that form ("Illegal number: -"), measured. In docker the exec'd shell is a session
# leader (runc/crun setsid), so its group is the command; over ssh the group is the channel's own session. Our own
# group and group 1 are never touched. It waits up to 2 s for a pidfile a just-started command has not written yet.
KILL = r'''f=$1; i=0
while [ ! -s "$f" ] && [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done
p=$(cat "$f" 2>/dev/null); rm -f "$f"
case "$p" in ''|*[!0-9]*) exit 0;; esac
me=; st=$(cat /proc/$$/stat 2>/dev/null) && { set -- ${st##*') '}; me=$3; }
g=; st=$(cat /proc/$p/stat 2>/dev/null) && { set -- ${st##*') '}; g=$3; }
case "$g" in ''|0|1|"$me") g=$p;; esac
kill -KILL -- -"$g" 2>/dev/null
for pass in 1 2; do
  for s in /proc/[0-9]*/stat; do
    st=$(cat "$s" 2>/dev/null) || continue
    q=${s#/proc/}; set -- ${st##*') '}
    [ "$3" = "$g" ] && kill -KILL "${q%/stat}" 2>/dev/null
  done
done
kill -KILL "$p" 2>/dev/null
exit 0'''


# ------------------------------------------------------------------ defaults (each one injectable)
def default_runner(argv, timeout=30, input=None):
    """Run a short control command (inspect, start, kill, rm): never raises, a timeout is exit 124."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input,
                              stdin=None if input is not None else subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"no answer in {timeout}s")
    except OSError as e:
        return subprocess.CompletedProcess(argv, 127, "", str(e))


def default_host_kill(p):
    """The local process group (start_new_session) of a client or command, then the process itself."""
    with contextlib.suppress(Exception):
        os.killpg(p.pid, signal.SIGKILL)
    with contextlib.suppress(Exception):
        p.kill()


def detect_runtime(which=shutil.which):
    """'docker' or 'podman' when one is on PATH (docker first), else ''."""
    for name in ("docker", "podman"):
        if which(name):
            return name
    return ""


def _home():
    return os.environ.get("GNOC_HOME") or os.path.join(os.path.expanduser("~"), ".gnoc")


def settings():
    """~/.gnoc/sandbox.json: {"image": "...", "ssh_dir": "..."}. A bad value is ignored, never trusted."""
    out = {"image": DEFAULT_IMAGE, "ssh_dir": "~"}
    try:
        with open(os.path.join(_home(), "sandbox.json")) as f:
            got = json.load(f)
    except (OSError, ValueError):
        return out
    if isinstance(got, dict):
        if isinstance(got.get("image"), str) and _IMAGE.match(got["image"]):
            out["image"] = got["image"]
        if isinstance(got.get("ssh_dir"), str) and _REMOTE_DIR.match(got["ssh_dir"]):
            out["ssh_dir"] = got["ssh_dir"]
    return out


def _inside(p, base):
    return p == base or p.startswith(base.rstrip(os.sep) + os.sep)


def mount_refusal(path):
    """Why `path` must not be bind-mounted into the container, or ''. The mount is the whole reach of the container,
    so it may not be (or contain) the home folder, gnoc's own config, ssh keys or a runtime socket."""
    m = os.path.realpath(str(path or ""))
    if not os.path.isdir(m):
        return f"{m} is not a folder"
    if any(c in m for c in ":,\n\r"):
        return f"{m} has a ':' or ',' in it, which a bind mount cannot carry"
    home = os.path.realpath(os.path.expanduser("~"))
    if m == "/" or _inside(home, m):
        return f"{m} is (or holds) your home folder; change_dir into the project folder first"
    guarded = [os.path.join(home, ".config"), os.path.join(home, ".gnoc"), os.path.join(home, ".ssh"), _home(),
               "/run", "/var/run", "/etc", "/proc", "/sys", "/dev", "/boot", "/usr"]
    for g in guarded:
        g = os.path.realpath(g)
        if _inside(m, g) or _inside(g, m):
            return f"{m} is (or holds) {g}, which never goes into a sandbox"
    return ""


def valid_host(host):
    """An ssh destination we will pass: [user@]name, no leading '-', no spaces, quotes or shell characters."""
    h = str(host or "")
    return bool(h) and not h.startswith("-") and bool(_HOST.match(h))


def _rq(path):
    """A remote directory for the remote shell: '~' stays unquoted so it expands, the rest is quoted."""
    if path == "~":
        return "~"
    if path.startswith("~/"):
        return "~/" + shlex.quote(path[2:])
    return shlex.quote(path)


def _token():
    return f"/tmp/.gnoc-run-{uuid.uuid4().hex}.pid"


# ------------------------------------------------------------------ backends
class _Spawn:
    _popen = None

    def popen(self, argv, **kw):
        # looked up at call time, not bound at import: a test that patches subprocess.Popen still sees its patch
        return (self._popen or subprocess.Popen)(argv, **kw)


class LocalBackend(_Spawn):
    """This machine: exactly what _bash_run did before backends existed."""
    kind = "local"

    def __init__(self, popen=None, host_kill=None):
        self._popen = popen
        self._host_kill = host_kill or default_host_kill

    def config(self):
        return {"kind": "local"}

    def describe(self):
        return "local: commands and file tools run on this machine (no sandbox)"

    def prepare(self, cwd):
        return ""

    def exec_argv(self, command, cwd, env, tty=False):
        import gnoc_compat   # bash on Linux/macOS, PowerShell on native Windows
        return gnoc_compat.shell_argv(command), {"cwd": cwd, "env": env}, None

    def kill(self, p, token=None):
        self._host_kill(p)

    def file_refusal(self, tool, real):
        return ""

    def close(self):
        pass


class DockerBackend(_Spawn):
    """One container per conversation; commands are `docker exec`s into it."""
    kind = "docker"

    def __init__(self, mount, image=DEFAULT_IMAGE, network=False, runtime="docker", flavor=None, sid=None,
                 runner=None, popen=None, host_kill=None, uid=None, gid=None):
        self.mount = os.path.realpath(str(mount))
        self.image = str(image or DEFAULT_IMAGE)
        self.network = bool(network)
        self.runtime = str(runtime or "docker")
        self.flavor = flavor          # "docker" | "podman" | None (asked from `<runtime> --version` on start)
        self.uid = os.getuid() if uid is None and hasattr(os, "getuid") else (uid or 0)
        self.gid = os.getgid() if gid is None and hasattr(os, "getgid") else (gid or 0)
        # unique per backend, not just per conversation: switching docker -> docker (adding --network) starts the new
        # container before the old one is removed, and two containers cannot share a name
        self.name = f"gnoc-sbx-{_SAFE.sub('-', str(sid or 'nosid'))[:40]}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self._run = runner or default_runner
        self._popen = popen
        self._host_kill = host_kill or default_host_kill
        self._up = False
        self._lock = threading.Lock()

    def config(self):
        return {"kind": "docker", "mount": self.mount, "image": self.image, "network": self.network,
                "runtime": self.runtime}

    def describe(self):
        return (f"docker ({self.flavor or self.runtime}): container {self.name}, image {self.image}; "
                f"{self.mount} mounted at the same path; network {'ON (you typed --network)' if self.network else 'OFF'};"
                f" user {self.uid}:{self.gid}; read-only root, /tmp in memory, no capabilities; "
                f"{'running' if self._up else 'starts with the next command'}")

    def run_argv(self):
        """The exact `docker run` that creates the container. Tests pin it: every flag here is a safety property."""
        argv = [self.runtime, "run", "-d", "--rm", "--name", self.name, "--label", "gnoc.sandbox=1"]
        if not self.network:
            argv += ["--network", "none"]
        argv += ["--user", f"{self.uid}:{self.gid}"]
        if self.flavor == "podman":
            # rootless podman maps the host uid to root in its namespace; without keep-id, uid 1000 inside is a
            # sub-uid outside and cannot write the user's own repo
            argv += ["--userns=keep-id"]
        argv += ["--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,mode=1777,size=1g",
                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "1024",
                 "-e", "HOME=/tmp", "-v", f"{self.mount}:{self.mount}", "-w", self.mount,
                 self.image, "sleep", "infinity"]
        return argv

    def prepare(self, cwd):
        """'' when a command can run in `cwd`; else the refusal. Starts the container on first use."""
        real = os.path.realpath(str(cwd or ""))
        if not _inside(real, self.mount):
            return (f"not run: the docker sandbox reaches only {self.mount} (the bind mount), and the working "
                    f"directory {real} is outside it. change_dir back into it, or the user types /sandbox local.")
        with self._lock:
            if self._up:
                return ""
            why = mount_refusal(self.mount)
            if why:
                return f"not run: the docker sandbox cannot mount this folder: {why}"
            if not _IMAGE.match(self.image):
                return f"not run: {self.image!r} is not an image name"
            r = self._run([self.runtime, "image", "inspect", "--format", "{{.Id}}", self.image], timeout=30)
            if r.returncode != 0:
                # never a silent pull in the middle of a turn: it is a download of code the user did not choose now
                return (f"not run: the sandbox image {self.image} is not on this machine, and gnoc never pulls one "
                        f"during a turn. Pull it yourself:  {self.runtime} pull {self.image}   (or /sandbox docker "
                        f"--image <one you have>)")
            if self.flavor is None:
                v = self._run([self.runtime, "--version"], timeout=15)
                self.flavor = "podman" if "podman" in ((v.stdout or "") + (v.stderr or "")).lower() else "docker"
            self._reap()
            r = self._run(self.run_argv(), timeout=120)
            if r.returncode != 0:
                return f"not run: the sandbox container did not start: {((r.stderr or r.stdout) or '').strip()[:400]}"
            self._up = True
        return ""

    def _reap(self):
        """Remove gnoc sandbox containers whose gnoc process is gone (a crash or a kill -9 skips atexit)."""
        r = self._run([self.runtime, "ps", "-a", "--filter", "label=gnoc.sandbox=1", "--format", "{{.Names}}"],
                      timeout=20)
        for name in (r.stdout or "").split():
            m = re.match(r"^gnoc-sbx-.*-(\d+)-[0-9a-f]{6}$", name)
            if not m or int(m.group(1)) == os.getpid():
                continue
            try:
                os.kill(int(m.group(1)), 0)
                continue          # that gnoc is still running
            except PermissionError:
                continue          # someone else's process: alive, not ours to judge
            except OSError:
                pass
            self._run([self.runtime, "rm", "-f", name], timeout=30)

    def exec_argv(self, command, cwd, env, tty=False):
        token = _token()
        argv = [self.runtime, "exec", "-i"] + (["-t"] if tty else []) + ["-w", os.path.realpath(cwd)]
        for k in ENV_PASS:
            if (env or {}).get(k):
                argv += ["-e", f"{k}={env[k]}"]
        argv += [self.name, "sh", "-c", WRAP, "gnoc-sbx", token, command]
        return argv, {"cwd": cwd if os.path.isdir(str(cwd)) else None, "env": env}, token

    def kill_inside(self, token):
        if token:
            self._run([self.runtime, "exec", self.name, "sh", "-c", KILL, "gnoc-kill", token], timeout=KILL_TIMEOUT)

    def kill(self, p, token=None):
        self.kill_inside(token)    # first, while the pidfile still names the command
        self._host_kill(p)

    def lost(self, text):
        """The container disappeared under us (removed by hand, the runtime restarted): start a new one next time."""
        if re.search(r"(?i)no such container|no container with name|is not running", str(text or "")):
            self._up = False
            return True
        return False

    def file_refusal(self, tool, real):
        if _inside(os.path.realpath(str(real or "")), self.mount):
            return ""
        return (f"refused: the docker sandbox reaches only {self.mount}, and that path resolves to {real}, outside "
                f"the mount (an absolute path, a '..' or a symlink pointing out). Work inside {self.mount}; the user "
                "types /sandbox local to work on the rest of this machine.")

    def close(self):
        with self._lock:
            if self._up:
                self._run([self.runtime, "rm", "-f", self.name], timeout=30)
            self._up = False


class SshBackend(_Spawn):
    """Commands on another host, in a fixed remote directory."""
    kind = "ssh"

    def __init__(self, host, remote_dir="~", runner=None, popen=None, host_kill=None,
                 connect_timeout=SSH_CONNECT_TIMEOUT):
        if not valid_host(host):
            raise ValueError(f"not an ssh host: {host!r}")
        if not _REMOTE_DIR.match(str(remote_dir or "")):
            raise ValueError(f"not a remote directory: {remote_dir!r} (absolute, or ~/...)")
        self.host, self.dir = str(host), str(remote_dir)
        self.connect_timeout = int(connect_timeout)
        self._run = runner or default_runner
        self._popen = popen
        self._host_kill = host_kill or default_host_kill

    def config(self):
        return {"kind": "ssh", "host": self.host, "dir": self.dir}

    def describe(self):
        return (f"ssh: {self.host}, in {self.dir}; key login only, host key checked against known_hosts. bash and bg "
                "run there; the file tools are off (PARTIAL: they would act on this machine), use bash on the host")

    def ssh_argv(self, remote_cmd):
        # BatchMode + no password/keyboard-interactive: a key or nothing, and never a prompt that hangs a turn.
        # StrictHostKeyChecking=yes: an unknown or changed host key is a refusal, never an auto-accept.
        # '--' before the host: whatever the host string is, ssh reads it as a destination, never an option.
        return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes",
                "-o", f"ConnectTimeout={self.connect_timeout}", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no", "--", self.host, remote_cmd]

    def check(self):
        """(ok, absolute remote dir | error text): log in and enter the directory once."""
        r = self._run(self.ssh_argv(f"cd {_rq(self.dir)} && pwd -P"), timeout=self.connect_timeout + 20)
        out = (r.stdout or "").strip().splitlines()
        if r.returncode == 0 and out and out[-1].startswith("/"):
            return True, out[-1]
        return False, ((r.stderr or r.stdout) or f"ssh exit {r.returncode}").strip()[:400]

    def prepare(self, cwd):
        return ""

    def exec_argv(self, command, cwd, env, tty=False):
        token = _token()
        envs = " ".join(shlex.quote(f"{k}={env[k]}") for k in ENV_PASS if (env or {}).get(k))
        remote = (f"cd {_rq(self.dir)} && " + (f"env {envs} " if envs else "")
                  + f"sh -c {shlex.quote(WRAP)} gnoc-sbx {shlex.quote(token)} {shlex.quote(command)}")
        argv = self.ssh_argv(remote)
        if tty:
            argv[1] = "-tt"
        return argv, {"cwd": cwd if os.path.isdir(str(cwd)) else None, "env": env}, token

    def kill_inside(self, token):
        if token:
            self._run(self.ssh_argv(f"sh -c {shlex.quote(KILL)} gnoc-kill {shlex.quote(token)}"),
                      timeout=self.connect_timeout + KILL_TIMEOUT)

    def kill(self, p, token=None):
        self.kill_inside(token)
        self._host_kill(p)

    def lost(self, text):
        return False

    def file_refusal(self, tool, real):
        return (f"refused: {tool} acts on THIS machine, and the shell runs on {self.host} (the ssh sandbox), so the "
                f"two would disagree. On ssh the file tools are off: use bash there, in {self.dir}: `cat -n FILE`, "
                "`sed -n '10,40p' FILE`, `grep -rn PATTERN .`, and a heredoc to write. Every bash call still goes "
                "through the deny list, the scope gate and approval.")

    # ---- /undo on the remote: the snapshot and the restore go through the same ssh, small text files only
    def _remote_paths(self, words):
        base = self.dir
        out = []
        for w in words:
            if w.startswith("~"):
                continue                       # not resolvable here; it is not inside the directory by name anyway
            p = posixpath.normpath(posixpath.join(base, w))
            if base.startswith("/") and (p == base or not p.startswith(base.rstrip("/") + "/")):
                continue
            if p not in out:
                out.append(p)
        return out[:20]

    def read_many(self, paths, limit=2_000_000):
        """{remote path: text} for the regular, non-symlink files among `paths` (missing ones are left out)."""
        paths = [p for p in paths if p.startswith("/")]
        if not paths:
            return {}
        script = ('for f in "$@"; do [ -f "$f" ] && [ ! -L "$f" ] || continue; '
                  f'n=$(wc -c <"$f"); [ "$n" -le {int(limit)} ] || continue; '
                  'printf "F %s\\n" "$f"; base64 <"$f" | tr -d "\\n"; echo; done')
        r = self._run(self.ssh_argv(f"sh -c {shlex.quote(script)} gnoc-read "
                                    + " ".join(shlex.quote(p) for p in paths)), timeout=self.connect_timeout + 30)
        got, lines = {}, (r.stdout or "").split("\n")
        for i in range(0, len(lines) - 1):
            if lines[i].startswith("F ") and lines[i][2:] in paths:
                try:
                    got[lines[i][2:]] = base64.b64decode(lines[i + 1]).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    continue           # binary: not checkpointed, as on the host
        return got

    def snapshot(self, words):
        return self.read_many(self._remote_paths(words))

    def inside_dir(self, path):
        return self.dir.startswith("/") and str(path).startswith(self.dir.rstrip("/") + "/")

    def restore(self, path, text, existed):
        """Put a checkpointed remote file back (or remove one the agent created). (ok, message)."""
        if not self.inside_dir(path):
            return False, f"{path} is outside {self.dir}"
        if existed:
            script = 'f=$1; [ -L "$f" ] && exit 3; base64 -d >"$f"'
            r = self._run(self.ssh_argv(f"sh -c {shlex.quote(script)} gnoc-restore {shlex.quote(path)}"),
                          timeout=self.connect_timeout + 30,
                          input=base64.b64encode(text.encode("utf-8")).decode("ascii") + "\n")
        else:
            r = self._run(self.ssh_argv(f"rm -f -- {shlex.quote(path)}"), timeout=self.connect_timeout + 15)
        return r.returncode == 0, ((r.stderr or "").strip()[:200] or f"exit {r.returncode}")

    def close(self):
        pass


class BrokenBackend(_Spawn):
    """A session whose sandbox setting does not validate (edited by hand, an old format). It fails CLOSED: running
    the command on the host instead would be the opposite of what the user chose."""
    kind = "broken"

    def __init__(self, why):
        self.why = why
        self._popen = None

    def config(self):
        return {"kind": "broken"}

    def describe(self):
        return f"not usable: {self.why}"

    def prepare(self, cwd):
        return (f"not run: this conversation's sandbox setting is not usable ({self.why}). Nothing ran on this "
                "machine instead. The user types /sandbox docker, /sandbox ssh <host> or /sandbox local.")

    def exec_argv(self, command, cwd, env, tty=False):
        raise RuntimeError(self.why)

    def kill(self, p, token=None):
        default_host_kill(p)

    def lost(self, text):
        return False

    def file_refusal(self, tool, real):
        return self.prepare(None).replace("not run", "refused", 1)

    def close(self):
        pass


LOCAL = LocalBackend()
_LIVE: dict = {}
_LIVE_LOCK = threading.Lock()


def _cfg(s):
    cfg = s.get("sandbox") if isinstance(s, dict) else None
    return cfg if isinstance(cfg, dict) and cfg.get("kind") in ("docker", "ssh") else None


def active(s):
    """True when this session runs commands somewhere other than this machine."""
    return _cfg(s) is not None


def _key(s, cfg):
    return str(s.get("sid") or "nosid") + "|" + json.dumps(cfg, sort_keys=True, default=str)


def build(cfg, sid=None):
    """A backend from a stored setting, every field validated again (the session file is data, not an order)."""
    try:
        if cfg.get("kind") == "docker":
            why = mount_refusal(cfg.get("mount"))
            if why:
                return BrokenBackend(why)
            if not _IMAGE.match(str(cfg.get("image") or "")):
                return BrokenBackend(f"bad image name {cfg.get('image')!r}")
            rt = cfg.get("runtime") if cfg.get("runtime") in ("docker", "podman") else detect_runtime()
            if not rt:
                return BrokenBackend("neither docker nor podman is installed")
            return DockerBackend(cfg["mount"], cfg["image"], bool(cfg.get("network")), runtime=rt, sid=sid)
        if cfg.get("kind") == "ssh":
            return SshBackend(cfg.get("host"), cfg.get("dir"))
    except (ValueError, KeyError, TypeError) as e:
        return BrokenBackend(str(e))
    return BrokenBackend(f"unknown kind {cfg.get('kind')!r}")


def for_session(s):
    """The backend this session's commands run on (LOCAL when none was chosen)."""
    cfg = _cfg(s)
    if cfg is None:
        if isinstance(s, dict) and isinstance(s.get("sandbox"), dict) and s["sandbox"].get("kind") not in (None, "local"):
            return BrokenBackend(f"unknown kind {s['sandbox'].get('kind')!r}")
        return LOCAL
    k = _key(s, cfg)
    stale = []
    with _LIVE_LOCK:
        be = _LIVE.get(k)
        if be is None:
            be = _LIVE[k] = build(cfg, s.get("sid"))
            # /new keeps the setting (it is not per-chat) but mints a new sid: the last conversation's container
            # with the same setting would otherwise idle until gnoc exits
            same = "|" + k.split("|", 1)[1]
            stale = [_LIVE.pop(x) for x in list(_LIVE) if x != k and x.endswith(same)]
    for old in stale:
        with contextlib.suppress(Exception):
            old.close()
    return be


def attach(s, backend):
    """Make `backend` this session's (the /sandbox command, and tests with a fake runner)."""
    s["sandbox"] = backend.config()
    with _LIVE_LOCK:
        _LIVE[_key(s, s["sandbox"])] = backend
    return backend


def detach(s):
    """Back to local: the session's container (if any) is removed."""
    cfg = _cfg(s)
    if cfg is not None:
        with _LIVE_LOCK:
            be = _LIVE.pop(_key(s, cfg), None)
        if be is not None:
            with contextlib.suppress(Exception):
                be.close()
    if isinstance(s, dict):
        s.pop("sandbox", None)


def close_all():
    with _LIVE_LOCK:
        live = list(_LIVE.values())
        _LIVE.clear()
    for be in live:
        with contextlib.suppress(Exception):
            be.close()


atexit.register(close_all)


def file_refusal(s, tool, real):
    """Why a file tool may not touch `real` (a resolved path) on this session's backend, or ''."""
    if not isinstance(s, dict) or "sandbox" not in s:
        return ""
    return for_session(s).file_refusal(tool, real)


def host_tool_refusal(s, name, args=None):
    """Why a tool that runs on the host is refused while a sandbox is on, or ''."""
    if not isinstance(s, dict) or "sandbox" not in s:
        return ""
    be = for_session(s)
    if be.kind == "local":
        return ""
    if name in HOST_TOOLS or (name == "delegate" and isinstance(args, dict) and args.get("isolated")):
        return (f"refused: {name} runs on this machine, outside the {be.kind} sandbox the user chose for this "
                "conversation, and it would execute the repo's own code or config there. Use bash instead (it runs "
                "in the sandbox): e.g. `python3 -m pytest -q`, `ruff check .`, `git status`.")
    return ""


def auto_tip(s, which=shutil.which):
    """The one line /auto prints when it turns auto-approve on while commands still run on this machine."""
    if active(s):
        return ""
    rt = detect_runtime(which)
    if not rt:
        return ""
    return (f"tip: {rt} is installed. /sandbox docker runs the shell in a container with no network that can reach "
            "only this repo, so auto-approved commands cannot touch the rest of this machine (gnoc never switches "
            "it for you).")


USAGE = ("usage: /sandbox                      show where commands run\n"
         "       /sandbox local                back to this machine\n"
         "       /sandbox docker [--network] [--image NAME]   a container for this conversation (network off "
         "unless --network)\n"
         "       /sandbox ssh <[user@]host> [remote-dir]       another host, key login only")


def command(s, rest, typed, root_dir, runner=None, which=shutil.which, popen=None):
    """The /sandbox command. Returns (message, changed). `typed` is True only for a line read from the user's
    keyboard (the same identity marker /file checks); every change needs it, a status read does not."""
    try:
        words = shlex.split(str(rest or ""))
    except ValueError:
        return USAGE, False
    current = for_session(s)
    if not words or words[0].lower() in ("show", "status"):
        lines = [f"sandbox: {current.describe()}"]
        if current.kind == "local":
            rt = detect_runtime(which)
            lines.append(f"{rt} is installed: /sandbox docker runs commands in a container" if rt
                         else "no docker or podman here: /sandbox ssh <host> runs commands on another machine")
        return "\n".join(lines), False
    verb = words[0].lower()
    if verb not in ("local", "off", "docker", "ssh"):
        return USAGE, False
    if not typed:
        return ("/sandbox changes only from a line you typed at the prompt: refused, the backend is unchanged "
                f"({current.kind})"), False
    if verb in ("local", "off"):
        detach(s)
        return "sandbox: local. Commands and file tools run on this machine again.", True
    if verb == "docker":
        network, image, i = False, settings()["image"], 1
        while i < len(words):
            if words[i] == "--network":
                network = True
            elif words[i] == "--image" and i + 1 < len(words):
                image, i = words[i + 1], i + 1
            else:
                return USAGE, False
            i += 1
        if not _IMAGE.match(image):
            return f"not switched: {image!r} is not an image name", False
        rt = detect_runtime(which)
        if not rt:
            return "not switched: neither docker nor podman is installed here (/sandbox ssh <host> is the other way)", False
        why = mount_refusal(root_dir)
        if why:
            return f"not switched: {why}", False
        be = DockerBackend(root_dir, image, network, runtime=rt, sid=s.get("sid"), runner=runner, popen=popen)
        why = be.prepare(root_dir)
        if why:
            return "not switched: " + why.replace("not run: ", "", 1), False
        detach(s)
        attach(s, be)
        return ("sandbox: " + be.describe() + ".\n  bash and bg run in it; file tools stay inside the mount; run_tests, "
                "lint, typecheck, git and gnoc are off (bash does them inside). /sandbox local switches back."
                + ("\n  NETWORK IS ON: commands in the container can reach the internet and your network." if network
                   else "")), True
    if len(words) < 2 or len(words) > 3:
        return USAGE, False
    host, rdir = words[1], (words[2] if len(words) == 3 else settings()["ssh_dir"])
    if not valid_host(host):
        return f"not switched: {host!r} is not an ssh host ([user@]name; no leading '-', spaces or quotes)", False
    if not _REMOTE_DIR.match(rdir):
        return f"not switched: {rdir!r} is not a remote directory (absolute, or ~/...)", False
    be = SshBackend(host, rdir, runner=runner, popen=popen)
    ok, got = be.check()
    if not ok:
        return (f"not switched: {got}\n  key login only: the host must already be in ~/.ssh/known_hosts (connect "
                "once yourself with ssh) and accept your key without a password prompt; the directory must exist"), False
    be.dir = got
    detach(s)
    attach(s, be)
    return "sandbox: " + be.describe() + ". /sandbox local switches back.", True
