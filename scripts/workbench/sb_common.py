#!/usr/bin/env python3
"""sb_common - shared helpers for the emulated-surface sandbox (scripts/workbench/sandbox.py).

Every lab lives in targets/<program>/labs/<name>/ and carries a lab.json state file. `sandbox ls`
and `sandbox down` work only from those files, so a lab is never orphaned by a crashed session.

Invariants enforced here (not by convention):
  * every listener a lab opens is bound to 127.0.0.1 (free_port, assert_loopback_bindings)
  * every process a lab starts runs in its own session so `down` kills the whole group
  * every remote host the workbench itself contacts is checked against the program's SCOPE.txt
    and NOSCOPE.txt first (T-160, T-171) - the Bash scope hook cannot see a subprocess.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

WS = Path(__file__).resolve().parents[2]            # ~/.gnoc
TARGETS = WS / "targets"
WB = Path.home() / ".local/opt/gnoc-workbench"      # toolchain prefix (foundry, asar, electron)
WB_BIN = WB / "bin"
NPM_PREFIX = WB / "npm"
ELECTRON_BIN = NPM_PREFIX / "node_modules/electron/dist/electron"
ASAR_JS = NPM_PREFIX / "node_modules/@electron/asar/bin/asar.mjs"
CHROME = Path.home() / ".local/bin/google-chrome"
MITM_CA = Path.home() / ".mitmproxy/mitmproxy-ca-cert.pem"
# /usr/bin/mitmdump crashes when the user site-packages (cryptography 50) shadow the distro
# pyOpenSSL; `python3 -s` drops the user site and it runs. Measured 2026-10-20.
MITMDUMP = ["/usr/bin/python3", "-s", "/usr/bin/mitmdump"]
CONTAINER = "podman"                                  # docker on this host is the podman shim

sys.path.insert(0, str(WS / "scripts"))
try:
    from bbtools.lib_scope import in_scope as _lib_in_scope, extract_host  # noqa: E402
except Exception:  # pragma: no cover - lib_scope is part of the workspace
    _lib_in_scope = None

    def extract_host(u: str) -> str:
        from urllib.parse import urlparse
        return (urlparse(u if "://" in u else "http://" + u).hostname or "").lower()


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def die(msg: str, code: int = 2):
    print(f"sandbox: {msg}", file=sys.stderr)
    sys.exit(code)


# ---------------------------------------------------------------- scope -----------------------
def program_dir(program: str, create: bool = False) -> Path:
    if not program or "/" in program or program.startswith("."):
        die(f"bad program handle {program!r}")
    d = TARGETS / program
    if not d.is_dir():
        if create:
            d.mkdir(parents=True)
        else:
            die(f"no targets/{program}/ (run the platform scope fetch first)")
    return d


def scope_file(program: str) -> Path:
    return TARGETS / program / "SCOPE.txt"


def _noscope_hit(host: str, program: str) -> bool:
    f = TARGETS / program / "NOSCOPE.txt"
    if not f.exists():
        return False
    for line in f.read_text(errors="replace").splitlines():
        t = line.split("#", 1)[0].strip().lower()
        if not t:
            continue
        t = extract_host(t.split()[0]) if "/" in t else t.split()[0]
        if host == t or (t.startswith("*.") and host.endswith(t[1:])) or host.endswith("." + t):
            return True
    return False


def LOOPBACK(host: str) -> bool:
    return host in ("localhost", "::1") or host.startswith("127.")


def host_in_scope(host_or_url: str, program: str) -> bool:
    host = extract_host(host_or_url)
    if not host:
        return False
    if LOOPBACK(host):
        return True
    if _noscope_hit(host, program):
        return False
    sf = scope_file(program)
    if not sf.exists() or _lib_in_scope is None:
        return False
    try:
        return bool(_lib_in_scope(host, str(sf)))
    except Exception:
        return False


def require_scope(host_or_url: str, program: str, what: str):
    host = extract_host(host_or_url)
    if not host_in_scope(host_or_url, program):
        die(f"OUT_OF_SCOPE {host} ({what}) is not in targets/{program}/SCOPE.txt "
            f"(or is in NOSCOPE.txt). Add the row only if the program lists it.", 3)


def scope_text_mentions(needle: str, program: str) -> bool:
    sf = scope_file(program)
    return sf.exists() and needle.lower() in sf.read_text(errors="replace").lower()


# ---------------------------------------------------------------- ports / procs ---------------
def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port: int, timeout: float = 30.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def spawn(cmd: list[str], log: Path, env: dict | None = None, cwd: Path | None = None) -> int:
    """Start a detached process group, stdout+stderr to log. Returns the pid (== pgid)."""
    log.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log, "ab", buffering=0)
    fh.write(f"\n=== {now()} {' '.join(cmd)}\n".encode())
    p = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                         env=env, cwd=str(cwd) if cwd else None, start_new_session=True)
    return p.pid


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:  # a zombie answers kill(0); read its state
        st = Path(f"/proc/{pid}/stat").read_text().split(")")[-1].split()[0]
        return st != "Z"
    except OSError:
        return False


def kill_group(pid: int | None, grace: float = 4.0):
    if not pid:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            return
        except PermissionError:
            try:
                os.kill(pid, sig)
            except OSError:
                return
        end = time.time() + grace
        while time.time() < end:
            if not alive(pid):
                return
            time.sleep(0.2)


def listening_sockets_of(pid: int) -> list[str]:
    """Every LISTEN socket owned by the process group of pid, as 'addr:port' (via ss)."""
    try:
        out = subprocess.run(["ss", "-ltnpH"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return []
    pids = {str(pid)}
    try:
        for p in Path("/proc").iterdir():
            if p.name.isdigit():
                try:
                    if os.getpgid(int(p.name)) == pid:
                        pids.add(p.name)
                except OSError:
                    pass
    except OSError:
        pass
    res = []
    for line in out.splitlines():
        if any(f"pid={x}," in line for x in pids):
            parts = line.split()
            if len(parts) >= 4:
                res.append(parts[3])
    return res


def assert_loopback_listeners(pid: int) -> list[str]:
    """Return the non-loopback listeners of a lab process group (empty list = clean)."""
    bad = []
    for a in listening_sockets_of(pid):
        host = a.rsplit(":", 1)[0].strip("[]")
        if not (host.startswith("127.") or host == "::1"):
            bad.append(a)
    return bad


# ---------------------------------------------------------------- display ---------------------
def gui_env(base: dict | None = None) -> dict:
    """Fill DISPLAY/XAUTHORITY like ~/.local/bin/google-chrome does (agent shells have neither)."""
    env = dict(base or os.environ)
    env.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    if not env.get("DISPLAY"):
        xs = sorted(Path("/tmp/.X11-unix").glob("X*"))
        if xs:
            env["DISPLAY"] = ":" + xs[0].name[1:]
    if not env.get("XAUTHORITY"):
        cands = sorted(Path(env["XDG_RUNTIME_DIR"]).glob("xauth_*")) + [Path.home() / ".Xauthority"]
        for c in cands:
            if c.is_file():
                env["XAUTHORITY"] = str(c)
                break
    return env


# ---------------------------------------------------------------- lab state -------------------
def lab_dir(program: str, name: str) -> Path:
    return TARGETS / program / "labs" / name


def save_state(d: Path, st: dict):
    d.mkdir(parents=True, exist_ok=True)
    st["updated"] = now()
    tmp = d / "lab.json.tmp"
    tmp.write_text(json.dumps(st, indent=2, sort_keys=True) + "\n")
    tmp.replace(d / "lab.json")


def load_state(d: Path) -> dict | None:
    f = d / "lab.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except json.JSONDecodeError:
        return None


def all_labs() -> list[tuple[Path, dict]]:
    out = []
    for f in sorted(TARGETS.glob("*/labs/*/lab.json")):
        st = load_state(f.parent)
        if st:
            out.append((f.parent, st))
    return out


def container_running(name: str) -> bool:
    r = subprocess.run([CONTAINER, "inspect", "-f", "{{.State.Running}}", name],
                       capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "true"


def lab_live(st: dict) -> bool:
    if st.get("status") == "down":
        return False
    if any(alive(p) for p in (st.get("pids") or {}).values()):
        return True
    return any(container_running(c) for c in st.get("containers", []))


# ---------------------------------------------------------------- mitm ------------------------
def start_mitm(d: Path, program: str, block_oos: bool = False, extra: list[str] | None = None
               ) -> tuple[int, int]:
    """mitmdump on 127.0.0.1:<port> writing flows.jsonl (with in_scope flags) and flows.mitm."""
    port = free_port()
    addon = Path(__file__).resolve().parent / "sb_flowlog.py"
    cmd = MITMDUMP + ["--listen-host", "127.0.0.1", "-p", str(port), "-q",
                      "-s", str(addon),
                      "--set", f"flowlog_out={d / 'flows.jsonl'}",
                      "--set", f"flowlog_program={program}",
                      "--set", f"flowlog_block_oos={'true' if block_oos else 'false'}",
                      "-w", str(d / "flows.mitm")] + (extra or [])
    pid = spawn(cmd, d / "mitmdump.log")
    if not wait_port(port, 20):
        kill_group(pid)
        die(f"mitmdump did not come up, see {d / 'mitmdump.log'}")
    return pid, port
