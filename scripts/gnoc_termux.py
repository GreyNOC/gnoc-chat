"""gnoc_termux.py - the defender's host checks inside Termux: a reduced, read-only set that works without root.

The desktop sweep (gnoc_defender.sweep) reads `ss`, the journal, the firewall, sysctl and packets, and acts
through a root helper. Inside Termux none of that exists: there is no root, no systemd journal, no firewall an
app may read, and Android hides other apps' processes and (from Android 10) the socket table. Running the
desktop sweep there produced errors and desktop advice (sudo ufw ...) that cannot be followed on a phone.

What an unprivileged Termux CAN see, and checks here:
  - listening sockets in /proc/net/{tcp,tcp6,udp,udp6} when Android lets the app read them
  - Termux's own sshd configuration ($PREFIX/etc/ssh/sshd_config): password login on a reachable port
  - shared-storage access (~/storage, made by termux-setup-storage)
  - package upgrades waiting in Termux's package lists

Every reader is injectable so the tests can fake a phone. Nothing here changes anything.
"""
from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from typing import Callable, List, Optional, Tuple

Row = Tuple[str, str, str, str, str]   # (id, sev, area, fact, fix), the shape gnoc_defender._f() takes
Reader = Callable[[str], str]
Runner = Callable[[List[str]], Tuple[int, str]]

# what the desktop sweep checks and a phone cannot, said once so a short report is not read as a clean one
HIDDEN = ("Android hides other apps' processes, system logs, the firewall and packet capture from Termux, so "
          "failed logins, firewall rules, packets, kernel settings and other apps' processes are not checked "
          "here (they need root or systemd, not available on Termux)")
TCP_LISTEN, UDP_UNCONN = "0A", "07"


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _run(argv: List[str]) -> Tuple[int, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError) as e:
        return 127, str(e)


def _hex_addr(h: str) -> str:
    """/proc/net's address column: IPv4 as one little-endian 32-bit word, IPv6 as four of them."""
    raw = bytes.fromhex(h)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))))
    raise ValueError(h)


def parse_proc_net(text: str, proto: str) -> List[dict]:
    """[{proto, addr, port, uid, bind}] for the listening rows of one /proc/net table. A malformed line is skipped,
    never fatal: the file is the kernel's, but a test (or an odd kernel) can hand anything."""
    want = TCP_LISTEN if proto.startswith("tcp") else UDP_UNCONN
    out = []
    for ln in text.splitlines()[1:]:
        f = ln.split()
        if len(f) < 8 or f[3].upper() != want or ":" not in f[1]:
            continue
        addr_h, _, port_h = f[1].partition(":")
        try:
            addr, port = _hex_addr(addr_h), int(port_h, 16)
            uid = int(f[7])
        except ValueError:
            continue
        if not port:
            continue
        ip = ipaddress.ip_address(addr)
        bind = "all" if ip.is_unspecified else "loopback" if ip.is_loopback else "lan"
        out.append({"proto": proto[:3], "addr": addr, "port": port, "uid": uid, "bind": bind})
    return out


def listening(read: Reader = _read) -> Optional[List[dict]]:
    """Every listening socket the app may see, or None when Android refuses the socket table (Android 10+ for apps
    that target it), which must read as 'not checked', not as 'nothing listens'."""
    rows: List[dict] = []
    readable = False
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        try:
            text = read(f"/proc/net/{proto}")
        except OSError:
            continue
        readable = True
        rows += parse_proc_net(text, proto)
    return rows if readable else None


def sshd_settings(text: str) -> dict:
    """{'port': [..], 'password': 'yes'|'no'} from an sshd_config. OpenSSH's defaults when unset: port 22 upstream,
    but Termux's package sets 8022 (no app may bind below 1024), and password login on."""
    ports: List[int] = []
    password = ""
    for ln in text.splitlines():
        ln = ln.split("#", 1)[0].strip()
        if re.match(r"(?i)match\s", ln):
            break   # a Match block only applies to some connections; the global settings end here
        m = re.fullmatch(r"(?i)port\s+(\d{1,5})", ln)
        if m:
            ports.append(int(m.group(1)))
        m = re.fullmatch(r"(?i)passwordauthentication\s+(\S+)", ln)
        if m and not password:
            password = m.group(1).lower()   # sshd keeps the FIRST value it reads for a keyword
    return {"port": ports or [8022], "password": password or "yes"}


def pending_upgrades(run: Runner = _run) -> Optional[int]:
    """How many installed packages have a newer version in Termux's package lists, or None when that cannot be
    read. `apt list --upgradable` because pkg has no read-only form of it (pkg is a wrapper around Termux's own
    apt, which lives in $PREFIX and needs no root); it reads the cached lists and never touches the network."""
    rc, out = run(["apt", "list", "--upgradable"])
    if rc != 0:
        return None
    return sum(1 for ln in out.splitlines() if "upgradable from" in ln)


def host_checks(prefix: str, home: str, read: Reader = _read, run: Runner = _run,
                isdir: Callable[[str], bool] = os.path.isdir,
                which: Optional[Callable[[str], Optional[str]]] = None) -> Tuple[List[Row], List[str]]:
    """(rows, notes): the Termux sweep. rows carry no action: every finding here is advice, because the actions
    the desktop sweep can take (block an IP, pause a process, set a sysctl) need root."""
    import shutil
    which = shutil.which if which is None else which
    rows: List[Row] = []
    notes: List[str] = [HIDDEN]
    socks = listening(read)
    if socks is None:
        notes.append("listening ports: Android hides the socket table from apps here (Android 10 and newer), so "
                     "they were not checked")
        socks = []
    seen = set()
    for s in socks:
        key = (s["proto"], s["port"])
        if s["bind"] == "loopback" or key in seen:
            continue
        seen.add(key)
        mine = s["uid"] == os.getuid()
        rows.append((f"port:{s['proto']}:{s['port']}", "warn", "port",
                     f"{s['proto']} {s['addr']}:{s['port']} is reachable from the network "
                     + ("(a program inside Termux)" if mine else f"(another app, uid {s['uid']})"),
                     "stop it, or make it listen on 127.0.0.1 only, when this phone is on a network you do not trust"
                     if mine else "check which app opened it in Android Settings > Apps"))
    cfg_path = os.path.join(prefix, "etc", "ssh", "sshd_config")
    try:
        cfg = sshd_settings(read(cfg_path))
    except OSError:
        cfg = None
    if cfg is not None and cfg["password"] != "no":
        open_ports = {s["port"] for s in socks if s["bind"] != "loopback" and s["proto"] == "tcp"}
        live = sorted(open_ports & set(cfg["port"]))
        rows.append(("ssh:password", "high" if live else "warn", "ssh",
                     "Termux's sshd allows password login" + (f" and is listening on port {live[0]}" if live else
                                                             " (it is not listening now)"),
                     f"put your public key in {os.path.join(home, '.ssh', 'authorized_keys')}, then set "
                     f"PasswordAuthentication no in {cfg_path} and restart sshd (pkill sshd; sshd)"))
    if isdir(os.path.join(home, "storage")):
        rows.append(("storage:shared", "info", "storage",
                     "Termux has shared-storage access (~/storage): every command gnoc runs can read and change "
                     "your Downloads, photos and documents",
                     "revoke it in Android Settings > Apps > Termux > Permissions when you do not need it"))
    if which("apt"):
        n = pending_upgrades(run)
        if n is None:
            notes.append("package upgrades: Termux's package lists were not readable")
        elif n:
            rows.append(("pkg:upgrades", "warn", "packages", f"{n} Termux package(s) have a newer version waiting "
                         "(as of the last pkg update)", "pkg upgrade"))
    return rows, notes
