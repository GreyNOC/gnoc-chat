"""gnoc_defend.py - blue-team checks on the user's OWN machine, LAN/WLAN and gateway: what is exposed, who is
there, what changed, who logged in, what runs.

Every answer is built from command output on this host, never from what a model expects to find. Driven
2026-10-24: asked "what is exposed on this machine", the agent got its `ss` refused, then reported Redis and
MongoDB that do not exist here and set about editing systemd units to close them. The fences, in code:
  - exposure / logins / services / audit / the network reads only READ local state (ss, ip, iw/nmcli,
    /etc/resolv.conf, journalctl, systemctl)
  - scan / discover run nmap without root and only at this machine or a private-range address (RFC 1918,
    link-local, IPv6 ULA); a public host or subnet is refused here, because public hosts belong to a
    program's scope (the scan tool). gnoc_agent asks before any target that is not this machine
  - the gateway check is a connect probe of the private gateway the user named (or the default route), never
    the internet, and the DHCP watch is passive (it only listens to OFFER/ACK)
  - scanners_remote() is the same judgement for a scanner run through bash
"""
import base64
import binascii
import hashlib
import ipaddress
import json
import glob
import os
import re
import shutil
import shlex
import signal
import socket
import subprocess
import threading
import time
import contextlib

_CTRL_RE = re.compile("\x1b\\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def _clean_text(value, limit=600):
    """One terminal-safe line for a process name, argv, SSID or command output field."""
    s = _CTRL_RE.sub("", str(value or ""))
    return re.sub(r"\s+", " ", s).strip()[:limit]


# Every scanner that sends traffic to the hosts it is given. A bash call to one of these is a scan, whatever the
# tool: the scan tool's "asked every time" promise must not have a bash-shaped hole (masscan of an internet /24
# ran unprompted under -s-p, 2026-10-24).
SCANNERS = {"nmap", "masscan", "rustscan", "zmap", "naabu", "unicornscan", "hping3", "nuclei", "ffuf", "gobuster",
            "feroxbuster", "dirb", "dirsearch", "nikto", "sqlmap", "hydra", "medusa", "ncrack", "wpscan", "katana",
            "httpx", "whatweb", "wfuzz", "arjun", "testssl", "sslscan", "enum4linux", "smbmap", "crackmapexec", "nxc"}

# What an exposed port usually means. "crit" = a remote attacker gets code execution or full control with no
# credential at all; "high" = data or a login surface that should never face a network; "info" = expected.
PORT_NOTES = {
    22: ("info", "SSH: fine exposed IF password login is off (defend action=logins shows it)"),
    23: ("high", "telnet: cleartext logins"),
    25: ("info", "SMTP"),
    53: ("info", "DNS resolver"),
    123: ("info", "NTP time sync"),
    111: ("high", "rpcbind: maps NFS/RPC services for anyone who asks"),
    139: ("high", "SMB/NetBIOS file sharing"),
    445: ("high", "SMB file sharing"),
    631: ("info", "CUPS printing"),
    2375: ("crit", "Docker API without TLS: anyone who reaches it is root on this host"),
    2376: ("high", "Docker API (TLS)"),
    3306: ("high", "MySQL/MariaDB"),
    3389: ("high", "RDP remote desktop"),
    5432: ("high", "PostgreSQL"),
    5900: ("high", "VNC remote desktop"),
    6379: ("crit", "Redis: no auth by default; writes files, often a shell"),
    8001: ("high", "datasette (hq-web): the whole hunt index, no login"),
    8080: ("high", "HTTP proxy / dev server (Burp listens here): lets others proxy through you"),
    8787: ("high", "GreyNOC control panel"),
    9050: ("high", "Tor SOCKS: lets others egress through you"),
    9222: ("crit", "Chrome DevTools: full control of the browser and every logged-in session in it"),
    11434: ("crit", "Ollama API: no auth; anyone can run, pull and delete models"),
    11435: ("crit", "Ollama API (ollama-oc): no auth; anyone can run, pull and delete models"),
    11450: ("high", "llama-server (split): unauthenticated model API"),
    27017: ("crit", "MongoDB: often no auth"),
    27036: ("", "Steam Remote Play / in-home streaming discovery"),
    50052: ("crit", "llama.cpp RPC: unauthenticated remote memory read/write on the GPU host"),
    50053: ("crit", "llama.cpp RPC (phone): unauthenticated remote memory read/write"),
}
_RANK = {"crit": 0, "high": 1, "info": 2, "": 3}
# A published container port shows up as the runtime's forwarder (rootlessport, docker-proxy ...), not as the
# service behind it: "rootlessport 18021" was really gateway-rp's unauthenticated Admin API on 0.0.0.0 (2026-10-24).
FORWARDERS = {"rootlessport", "rootlesskit", "docker-proxy", "conmon", "slirp4netns", "pasta", "pasta.avx2"}
# (image substring, CONTAINER port) -> what that port is inside the container
CONTAINER_NOTES = {
    ("kong", 8001): ("crit", "Kong Admin API (HTTP): unauthenticated control of the gateway: routes, plugins, and "
                             "serverless plugins that run code"),
    ("kong", 8444): ("crit", "Kong Admin API (HTTPS): unauthenticated control of the gateway"),
    ("kong", 8002): ("high", "Kong Manager GUI"), ("kong", 8445): ("high", "Kong Manager GUI (HTTPS)"),
    ("kong", 8000): ("info", "Kong proxy (the gateway's public side)"), ("kong", 8443): ("info", "Kong proxy (HTTPS)"),
    ("redis", 6379): ("crit", "Redis: no auth by default"), ("mongo", 27017): ("crit", "MongoDB"),
    ("postgres", 5432): ("high", "PostgreSQL"), ("mysql", 3306): ("high", "MySQL"), ("mariadb", 3306): ("high", "MariaDB"),
    ("elasticsearch", 9200): ("crit", "Elasticsearch REST API: no auth by default"),
    ("jenkins", 8080): ("high", "Jenkins (script console = code execution once logged in)"),
}
# UDP sockets a client opens for itself: they answer only the peer they talk to, they are not a service to close
UDP_CLIENT = {68: "DHCP client", 546: "DHCPv6 client", 5353: "mDNS discovery (local network names)",
              1900: "SSDP/UPnP discovery"}
_ADDR_CACHE = {}   # {target key: (time, {ifname: [addr]})}

# WHICH MACHINE the read checks run on (2026-11-18, /mode defender). None = this machine. An ssh destination
# ("alice@203.0.113.10") runs the SAME read-only argv there over `ssh -o BatchMode=yes`, so a remote box is judged
# from its own command output, never from this one's. Thread-local: the defender watcher thread and the chat turn
# may look at different hosts at the same moment. Only /defender target (GreyNOC typing it) sets a remote host.
_TL = threading.local()


def target():
    """The ssh destination the checks run on, or None for this machine."""
    return getattr(_TL, "dest", None)


@contextlib.contextmanager
def on_host(dest):
    prev = getattr(_TL, "dest", None)
    _TL.dest = dest or None
    try:
        yield
    finally:
        _TL.dest = prev


SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ServerAliveInterval=10", "-T"]


def _read(path):
    """A file's text on the target machine, or None. '~/' is the target user's home."""
    dest = target()
    if not dest:
        try:
            with open(os.path.expanduser(path), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None
    q = '"$HOME"/' + shlex.quote(path[2:]) if path.startswith("~/") else shlex.quote(path)
    rc, txt = _run(["sh", "-c", f"cat {q} 2>/dev/null || exit 3"], 20)
    return txt if rc == 0 else None


def _ls(d):
    dest = target()
    if not dest:
        try:
            return sorted(os.listdir(d))
        except OSError:
            return []
    rc, txt = _run(["ls", "-1", d], 15)
    return sorted(x for x in txt.splitlines() if x and rc == 0)


def _run(argv, timeout=60):
    """(returncode, stdout+stderr). A timeout kills the process group; a missing binary is rc 127.
    On a remote target (on_host) the same argv runs there over ssh; rc 255 is ssh itself failing."""
    dest = target()
    if dest:
        if not shutil.which("ssh"):
            return 127, "ssh is not installed"
        argv = ["ssh", *SSH_OPTS, dest, "--", "LC_ALL=C " + shlex.join(argv)]
    elif not shutil.which(argv[0]):
        return 127, f"{argv[0]} is not installed"
    # The C locale locally too (the remote path already sets it): ufw, journalctl and friends translate the
    # strings these parsers match ("Status: active" is "Status: aktiv" in Swedish -> read as inactive).
    env = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             text=True, encoding="utf-8", errors="replace", start_new_session=True, env=env)
    except OSError as e:
        return 126, str(e)
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            out = p.communicate(timeout=1)[0] or ""
        except subprocess.TimeoutExpired:
            # a descendant left the process group (setsid, an ssh ControlPersist master) and still holds the
            # pipe: stop reading rather than wait for it, or the "timeout" is however long that child lives
            with contextlib.suppress(OSError):
                p.kill()
            with contextlib.suppress(Exception):
                p.stdout.close()
            out = ""
        return 124, out + f"\n(timed out after {timeout}s)"
    return p.returncode, out or ""


# ---------------------------------------------------------------- which addresses are "this machine"

def interfaces():
    """{interface: [address, ...]} from `ip -j addr`, cached for a minute."""
    key = target() or ""
    hit = _ADDR_CACHE.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    out = {}
    rc, txt = _run(["ip", "-j", "addr"], 10)
    if rc == 0:
        try:
            for i in json.loads(txt):
                out[i.get("ifname", "?")] = [a.get("local") for a in i.get("addr_info") or [] if a.get("local")]
        except ValueError:
            pass
    _ADDR_CACHE[key] = (time.time(), out)
    return out


def own_addrs():
    return {ipaddress.ip_address(a.split("%")[0]) for addrs in interfaces().values() for a in addrs
            if _is_ip(a.split("%")[0])}


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _host_of(tok):
    """'http://127.0.0.1:8080/x' / '[::1]:22' / '10.0.0.5:80' / 'host.lan' -> the bare host."""
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", tok.strip(), flags=re.I).split("/", 1)[0]
    t = t.rsplit("@", 1)[-1]
    if t.startswith("["):
        return t[1:].split("]", 1)[0]
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


def classify(target):
    """'self' (this machine), 'private' (LAN / VPN / link-local / ULA), 'public', or 'unknown'.
    A CIDR is classified by its network: 10.0.0.0/24 is 'private' (other hosts), never 'self'."""
    t = _host_of(str(target or ""))
    if not t:
        return "unknown"
    if t.lower() in ("localhost", "localhost.localdomain", "ip6-localhost", socket.gethostname().lower()):
        return "self"
    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            if net.num_addresses == 1:
                t = str(net.network_address)
            else:
                return "self" if net.is_loopback else ("private" if net.is_private or net.is_link_local else "public")
        ip = ipaddress.ip_address(t)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.getaddrinfo(t, None)[0][4][0].split("%")[0])
        except (OSError, ValueError, IndexError):
            return "unknown"
    if ip.is_loopback or ip.is_unspecified or ip in own_addrs():
        return "self"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


_HOSTLIKE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?(?:\[?[0-9a-f:]*:[0-9a-f:.]+\]?|\d{1,3}(?:\.\d{1,3}){3}"
                       r"(?:/\d{1,2})?|localhost|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?::\d+)?(?:/\S*)?$", re.I)


# a wordlist or output file name (-w common.txt) matches the hostname shape; these extensions are not TLDs
_FILELIKE = re.compile(r"\.(txt|lst|list|json|xml|csv|ya?ml|g?nmap|log|out|conf|wordlist|dic|db)$", re.I)


def scanner_targets(cmd):
    """[(scanner, [target tokens], has_target_file)] for every scanner a shell command runs."""
    out = []
    for seg in re.split(r"\|\||&&|;|\||&|\n", str(cmd or "")):
        w = seg.strip().split()
        while w and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", w[0]) or w[0] in ("sudo", "env", "nohup",
                                                                                  "timeout", "nice", "proxychains",
                                                                                  "proxychains4", "time")):
            w = w[1:]
            while w and w[0].startswith("-"):   # sudo -n, timeout -s KILL ...
                w = w[1:]
            if w and re.fullmatch(r"\d+[smhd]?", w[0]):   # timeout 30
                w = w[1:]
        if not w:
            continue
        name = os.path.basename(w[0])
        if name not in SCANNERS:
            continue
        files = any(x in ("-iL", "-iR", "-l", "-list", "--list", "-u-list", "--input-file", "-L", "-M",
                          "--target-file") or x.startswith(("--input", "-iL")) for x in w[1:])
        out.append((name, [x for x in w[1:] if not x.startswith("-") and _HOSTLIKE.match(x)
                           and not _FILELIKE.search(x)], files))
    return out


def scans_remote(cmd):
    """True when a shell command runs a scanner at anything that is not this machine (or at targets it cannot
    see: a target file, random targets, none parsed). Loopback and this host's own addresses are a self-check."""
    for _name, targets, files in scanner_targets(cmd):
        if files or not targets or any(classify(t) != "self" for t in targets):
            return True
    return False


def scans_only_self(cmd):
    """Every scanner in the command aims only at this machine."""
    runs = scanner_targets(cmd)
    return bool(runs) and not scans_remote(cmd)


# ---------------------------------------------------------------- what is listening

def listening():
    """[{proto, addr, port, proc, pid, bind}] from `ss -H -tulpn`. bind: loopback | all | lan | vpn | <ifname>."""
    rc, txt = _run(["ss", "-H", "-tulpn"], 20)
    rows, by_ip = [], {}
    for ifn, addrs in interfaces().items():
        for a in addrs:
            by_ip[a] = ifn
    for ln in txt.splitlines():
        f = ln.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        if f[0] == "tcp" and f[1] != "LISTEN":
            continue
        local = f[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%")[0].strip("[]")   # ss prints [fe80::1]%wlp6s0:546
        if not port.isdigit():
            continue
        m = re.search(r'users:\(\("(.*?)",pid=(\d+)', ln)   # a comm may itself contain a quote
        if addr in ("*", "0.0.0.0", "::"):
            bind = "all"
        elif _is_ip(addr) and ipaddress.ip_address(addr).is_loopback:
            bind = "loopback"
        else:
            ifn = by_ip.get(addr, "")
            bind = ("vpn" if re.match(r"(wg|tun|tap|tailscale|zt)", ifn) else
                    "docker" if re.match(r"(docker|br-|veth|virbr)", ifn) else "lan") if ifn else "lan"
        rows.append({"proto": f[0], "addr": _clean_text(addr, 64), "port": int(port),
                     "proc": _clean_text(m.group(1), 80) if m else "?",
                     "pid": int(m.group(2)) if m else None, "bind": bind})
    return rows


def containers():
    """{host_port: {name, image, cport, proto}} for every published container port (podman, then docker)."""
    out = {}
    rc, txt = _run(["podman", "ps", "--format", "json"], 20)
    rows = []
    if rc == 0:
        try:
            rows = json.loads(txt[txt.index("["):]) if "[" in txt else []
        except ValueError:
            rows = []
    for c in rows:
        for p in c.get("Ports") or []:
            for i in range(int(p.get("range") or 1)):
                out[int(p["host_port"]) + i] = {"name": (c.get("Names") or ["?"])[0], "image": c.get("Image", ""),
                                                "cport": int(p["container_port"]) + i,
                                                "proto": p.get("protocol", "tcp"), "host_ip": p.get("host_ip") or "*"}
    if not out and shutil.which("docker"):
        rc, txt = _run(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"], 20)
        for ln in txt.splitlines() if rc == 0 else []:
            f = ln.split("\t")
            if len(f) < 3:
                continue
            for m in re.finditer(r"(?:([\d.:\[\]a-f]+):)?(\d+)(?:-(\d+))?->(\d+)(?:-\d+)?/(\w+)", f[2]):
                lo, hi, cp = int(m.group(2)), int(m.group(3) or m.group(2)), int(m.group(4))
                for i in range(hi - lo + 1):
                    out[lo + i] = {"name": f[0], "image": f[1], "cport": cp + i, "proto": m.group(5),
                                   "host_ip": m.group(1) or "*"}
    return out


def _input_drop_chains(ruleset):
    """How many INPUT-hook chains drop by default (policy drop/reject, or a final drop/reject rule), outside
    gnoc's own tables. Any drop rule anywhere used to count, so Docker's forward chains or the defender's own
    block set made an open host read as firewalled (QAQC 2026-11-19)."""
    n = 0
    for tm in re.finditer(r"(?ms)^table\s+\S+\s+(\S+)\s*\{(.*?)^\}", ruleset or ""):
        if tm.group(1) in ("gnoc_defender", "gnoc_isolate"):
            continue
        for cm in re.finditer(r"(?ms)chain\s+\S+\s*\{(.*?)\n\s*\}", tm.group(2)):
            body = cm.group(1)
            if not re.search(r"hook\s+input\b", body):
                continue
            rules = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith("type ")]
            if re.search(r"policy\s+(drop|reject)", body) or (rules and re.search(r"\b(drop|reject)\s*$", rules[-1])):
                n += 1
    return n


def is_protected_proc(comm, exe="", args=""):
    """A protected NAME that is really the system's program: protected only when it runs from a system path
    (or, unreadable exe, when its argv[0] is not a temp path). A miner renamed "sshd" in /tmp was never
    paused or killed (QAQC 2026-11-19)."""
    if comm in GNOC_PROCS or (str(comm or "").startswith("python") and _GNOC_ARGS.search(str(args or ""))):
        # gnoc's OWN model server and chat: "pause whatever process is using the most cpu if it's not mine" picked
        # llama-server (the engine answering that very question) and tried to pause it (batch 8, 2026-11-23).
        # Protected only where gnoc puts it: a renamed miner in /tmp is still caught.
        where = str(exe or "").replace(" (deleted)", "") or (str(args or "").split() or [""])[0]
        if comm.startswith("python"):
            where = next((w for w in str(args or "").split() if _GNOC_ARGS.search(w)), where)
        return not TMP_EXE.match(where) and (not where.startswith("/") or where.startswith(_GNOC_HOMES))
    if comm not in PROTECTED_PROCS:
        return False
    exe = str(exe or "").replace(" (deleted)", "")
    if exe:
        return exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib/", "/opt/")) and not TMP_EXE.match(exe)
    arg0 = (str(args or "").split() or [""])[0]
    return not (arg0.startswith("/") and TMP_EXE.match(arg0))


def firewall():
    """(state, detail): state 'active' | 'inactive' | 'unknown'. Reads without root first; `sudo -n` never
    prompts, so it only answers where the user already allowed it."""
    for argv in (["ufw", "status", "verbose"], ["sudo", "-n", "ufw", "status", "verbose"]):
        rc, txt = _run(argv, 15)
        if rc == 0 and "Status:" in txt:
            return ("active" if "Status: active" in txt else "inactive"), txt.strip()
    for argv in (["nft", "list", "ruleset"], ["sudo", "-n", "nft", "list", "ruleset"]):
        rc, txt = _run(argv, 15)
        if rc == 0:
            n = _input_drop_chains(txt)
            return ("active" if n else "inactive"), (f"nftables: {len(txt.splitlines())} lines, {n} input chain(s) "
                                                     "that drop by default")
    known = firewall_known()
    return "unknown", ("the RULES need root to read here" + (f" (read without root: {'; '.join(known)})" if known else "")
                       + ": run `sudo ufw status verbose` (or `sudo nft list ruleset`)")


def firewall_known():
    """What IS readable about the firewall without root: unit states and ufw.conf. With only "unknown" the
    exposure view said "with no active firewall, every row above is reachable" on a box whose ufw was active,
    and the lead repeated it (defense drive 2026-11-22)."""
    known = []
    for unit in ("ufw", "nftables", "firewalld"):
        _, act = _run(["systemctl", "is-active", unit], 5)
        _, enb = _run(["systemctl", "is-enabled", unit], 5)
        act, enb = (act or "").strip().splitlines()[:1], (enb or "").strip().splitlines()[:1]
        if act and act[0] in ("active", "inactive", "failed") and not (act[0] == "inactive" and enb
                                                                      and enb[0] not in ("enabled", "disabled")):
            known.append(f"{unit} service: {act[0]}" + (f", {enb[0]} at boot" if enb else ""))
    try:
        with open("/etc/ufw/ufw.conf", encoding="utf-8", errors="replace") as fh:
            m = re.search(r"(?m)^\s*ENABLED\s*=\s*(\w+)", fh.read())
        if m:
            known.append(f"/etc/ufw/ufw.conf says ENABLED={m.group(1)}")
    except OSError:
        pass
    if any(k.startswith("ufw service: active") for k in known) and any(k.startswith("nftables service: inactive")
                                                                     for k in known):
        # NORMAL: ufw writes its own rules into the kernel; the separate nftables SERVICE stays off beside it.
        # A lead read "nftables disabled at boot" as the most serious finding and told him to run `systemctl enable
        # --now nftables`, which loads /etc/nftables.conf (often a flush) over ufw's rules (defense batch 17).
        known.append("(the nftables service being off is NORMAL with ufw active: ufw manages the kernel's rules "
                     "itself; never enable nftables.service beside ufw, it can wipe ufw's rules)")
    return known


def _note(row, ctr=None):
    """(severity, what it is) for one listening row; a published container port is judged by the port INSIDE."""
    c = (ctr or {}).get(row["port"]) if row["proc"] in FORWARDERS or row["proc"] == "?" else None
    if c:
        img = c["image"].lower()
        sev, what = next((v for (sub, cp), v in CONTAINER_NOTES.items() if sub in img and cp == c["cport"]),
                         PORT_NOTES.get(c["cport"], ("", "")))
        where = f"container {c['name']} ({c['image'].split('/')[-1].split('@')[0][:40]}) port {c['cport']}"
        return sev, where + (f": {what}" if what else "")
    if row["proto"] == "udp" and row["port"] in UDP_CLIENT:
        return "info", UDP_CLIENT[row["port"]]
    return PORT_NOTES.get(row["port"], ("", ""))


def _is_client_udp(row):
    """An unconnected UDP socket on an ephemeral port: a program's own outbound socket (QUIC, DNS lookups,
    discovery replies), reachable only by the peers it is talking to. Not a service, nothing to 'close'."""
    return row["proto"] == "udp" and row["port"] >= 32768 and row["port"] not in PORT_NOTES


def _recreate_hint(c, hport):
    """How to actually close a published container port, with this container's own run command.

    A published port is fixed when the container is CREATED. Told to bind one to loopback, the agent
    produced `podman stop gateway-rp && podman start gateway-rp --publish 127.0.0.1:...` - `podman start`
    takes no --publish, so it failed twice and the port stayed open (2026-10-25). Hand over the real
    command instead of advice it has to translate."""
    out = [f"fix: the published port is fixed at CREATE time, so `podman start --publish` does NOT work: "
           f"the container has to be recreated (or just stop it: podman stop {c['name']})."]
    rc, txt = _run(["podman", "inspect", c["name"], "--format",
                    "{{range .Config.CreateCommand}}{{.}}\x1f{{end}}"], 20)
    argv = [a for a in txt.strip().split("\x1f") if a] if rc == 0 else []
    if not argv:
        out.append(f"     recreate it with  -p 127.0.0.1:{hport}:{c['cport']}  in place of  -p {hport}:{c['cport']}")
        return out
    patched, vols = [], []
    for a in argv:
        if a == f"{hport}:{c['cport']}":
            a = f"127.0.0.1:{hport}:{c['cport']}"
        patched.append(a)
    for i, a in enumerate(argv):
        if a == "-v" and i + 1 < len(argv):
            src = argv[i + 1].split(":")[0]
            if src.startswith("/tmp/"):
                vols.append(src)
    cmd = (f"#!/bin/bash\n# close {c['name']}'s published port {hport}: bind it to loopback.\n"
           f"# Written by gnoc defend. The image digest, the volumes and every -e flag are copied from the\n"
           f"# container's own create command, so nothing is lost in the retyping.\nset -euo pipefail\n"
           f"podman stop {c['name']} && podman rm {c['name']}\n"
           + " ".join(shlex.quote(a) for a in patched) + "\n")
    path = ""
    try:
        ws = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        d = os.path.join(ws, ".claude/state/orch/fixes")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"close-{re.sub(r'[^A-Za-z0-9_.-]', '_', c['name'])}-{hport}.sh")
        with open(path, "w") as fh:
            fh.write(cmd)
        os.chmod(path, 0o755)
    except OSError:
        path = ""
    if path:
        # Do NOT make the model carry the command. Asked to close this port it retyped the run line and
        # got the sha256 digest wrong, dropped the -v that carries the declarative config, and changed
        # KONG_ADMIN_LISTEN to 127.0.0.1 - which would have left the admin API unreachable even through
        # the new mapping, because the container's loopback is not the host's (2026-10-25). A long
        # literal belongs in a file, not in a model's output buffer.
        out.append("     the exact command is SAVED and ready to run: "
                   + os.path.relpath(path, ws))
        out.append("     give the user that path and let them run it. Do NOT retype the command into chat: "
                   "the digest, the volumes and the -e flags all have to survive exactly, and they do "
                   "not survive being copied by hand.")
    else:
        out.append(f"     podman stop {c['name']} && podman rm {c['name']}")
        out.append("     " + " ".join(shlex.quote(a) for a in patched))
    for v in vols:
        out.append(f"     WARNING: this container's config comes from {v}, which is under /tmp and will "
                   "not survive a reboot. Copy it somewhere durable before recreating.")
    return out


def exposure():
    rows = listening()
    if not rows:
        return "no listening sockets found (or `ss` is unavailable)"
    fw, fwd = firewall()
    ctr = containers()
    netw = [r for r in rows if r["bind"] in ("all", "lan")]
    clients = [r for r in netw if _is_client_udp(r)]
    reach = [r for r in netw if not _is_client_udp(r)]
    vpn = [r for r in rows if r["bind"] in ("vpn", "docker")]
    local = [r for r in rows if r["bind"] == "loopback"]
    lines = [f"LISTENING SOCKETS on {hostname()}: {len(rows)} total; {len(reach)} services reachable from "
             f"the network, {len(clients)} outbound UDP client sockets, {len(vpn)} on VPN/container interfaces, "
             f"{len(local)} loopback-only.",
             f"FIREWALL: {fw}" + ("" if fw == "active" else f"  ({fwd.splitlines()[0][:300]})")]
    if reach:
        lines.append("\nSERVICES REACHABLE FROM THE NETWORK (bound to all interfaces or a LAN address):")
        seen = set()
        for r in sorted(reach, key=lambda r: (_RANK[_note(r, ctr)[0]], r["port"])):
            key = (r["proto"], r["port"], r["proc"])
            if key in seen:
                continue
            seen.add(key)
            sev, what = _note(r, ctr)
            tag = {"crit": "CRITICAL", "high": "HIGH", "info": "ok"}.get(sev, "review")
            lines.append(f"  [{tag:8}] {r['proto']} {r['addr'] or '*'}:{r['port']:<5} {r['proc']}"
                         + (f" (pid {r['pid']})" if r["pid"] else "") + (f"  - {what}" if what else ""))
            c = ctr.get(r["port"]) if r["proc"] in FORWARDERS or r["proc"] == "?" else None
            if c and sev in ("crit", "high"):
                lines += ["             " + x for x in _recreate_hint(c, r["port"])]
        if fw == "inactive":
            lines.append("  With no active firewall, every row above is reachable by anything on the same network.")
        elif fw == "unknown":
            lines.append("  The firewall RULES could not be read, so whether a rule filters these rows is UNKNOWN: "
                         "do not call the firewall off or on beyond what the FIREWALL line says.")
    if clients:
        names = sorted({r["proc"] for r in clients})
        lines.append(f"\nOUTBOUND UDP CLIENT SOCKETS ({len(clients)}, not services; nothing to close): "
                     f"ephemeral ports opened by {', '.join(names)} for their own connections (QUIC, DNS).")
    if vpn:
        lines.append("\nVPN / CONTAINER INTERFACES ONLY:")
        lines += [f"  {r['proto']} {r['addr']}:{r['port']} {r['proc']}" for r in vpn]
    if local:
        names = sorted({f"{r['port']}/{r['proc']}" for r in local}, key=lambda s: int(s.split("/")[0]))
        lines.append(f"\nLOOPBACK ONLY (not reachable from other machines): {', '.join(names[:40])}"
                     + (f" ... +{len(names) - 40}" if len(names) > 40 else ""))
    if any(r["proc"] == "?" for r in rows):
        lines.append("\n(process names show as ? for sockets owned by other users; `sudo ss -tulpn` shows them)")
    return "\n".join(lines)


# ---------------------------------------------------------------- active self-check

def scan(target="", ports=""):
    """nmap connect scan of this machine (default: its LAN addresses) or a private-range host. Public refused."""
    if not target:
        lan = [a for ifn, addrs in interfaces().items() if not ifn.startswith(("lo", "docker", "br-", "veth", "virbr"))
               for a in addrs if _is_ip(a) and ipaddress.ip_address(a).version == 4]
        target = " ".join(lan) or "127.0.0.1"
    targets = target.split()
    kinds = {t: classify(t) for t in targets}
    bad = [t for t, k in kinds.items() if k in ("public", "unknown")]
    if bad:
        return (f"refused: {', '.join(bad)} is not this machine or a private-network address. defend scans only "
                "your own machine and LAN; a public host belongs to a bug-bounty program's scope (the scan tool).")
    if ports and not re.fullmatch(r"[0-9,\-]{1,200}", str(ports)):
        return "refused: ports takes a list like 22,80,8000-8100"
    argv = ["nmap", "-sT", "-Pn", "-T4", "--open", "-n"] + (["-p", str(ports)] if ports else ["--top-ports", "1000"])
    rc, txt = _run(argv + ["-oG", "-"] + targets, 600)
    if rc == 127:
        return txt
    found = []
    for ln in txt.splitlines():
        m = re.match(r"Host: (\S+).*Ports: (.*)", ln)
        if not m:
            continue
        for p in m.group(2).split(","):
            f = p.strip().split("/")
            if len(f) > 4 and f[1] == "open":
                found.append((m.group(1), int(f[0]), f[2], f[4] or "?"))
    if not found:
        return f"nmap -sT top {'ports ' + ports if ports else '1000 ports'} on {target}: no open TCP ports" + (
            "" if rc == 0 else f" (nmap exit {rc}: {txt.strip()[-200:]})")
    loop = all(_is_ip(h) and ipaddress.ip_address(h).is_loopback for h, *_ in found)
    lines = [f"nmap -sT on {target} ({'ports ' + ports if ports else 'top 1000'}): {len(found)} open port(s)"
             + (" on LOOPBACK: only programs on this machine can connect to these, nothing on the network can "
                "(scan the LAN address, the default, to see what the network sees)" if loop else
                ", as another machine on the network sees them:")]
    for host, port, proto, svc in found:
        sev, what = PORT_NOTES.get(port, ("", ""))
        if loop or sev not in ("crit", "high"):   # a loopback-only port is not an exposure: no alarm label
            lines.append(f"  {host}:{port}/{proto} {svc}" + (f"  ({what})" if what else ""))
        else:
            lines.append(f"  {host}:{port}/{proto} {svc}  [{sev.upper()}] {what}")
    return "\n".join(lines)


# ---------------------------------------------------------------- who got in, what runs

_SSHD_DEFAULTS = {"passwordauthentication": "yes (OpenSSH default)", "permitrootlogin": "prohibit-password (default)",
                  "pubkeyauthentication": "yes (default)", "port": "22 (default)",
                  "kbdinteractiveauthentication": "yes (OpenSSH default)", "listenaddress": "all interfaces (default)"}


def sshd_settings():
    """Effective-ish sshd settings from sshd_config + sshd_config.d (first value wins, as sshd reads them)."""
    d = "/etc/ssh/sshd_config.d"
    files = [os.path.join(d, f) for f in _ls(d) if f.endswith(".conf")] + ["/etc/ssh/sshd_config"]
    seen, have = {}, False
    for p in files:
        txt = _read(p)
        if txt is None:
            continue
        have = have or p == "/etc/ssh/sshd_config"
        for ln in txt.splitlines():
            m = re.match(r"\s*(\w+)(?:\s*=\s*|\s+)(.+?)\s*$", ln)   # sshd takes `Key value` and `Key=value`
            if m and not ln.lstrip().startswith("#") and m.group(1).lower() in _SSHD_DEFAULTS:
                seen.setdefault(m.group(1).lower(), m.group(2))
            if re.match(r"\s*Match\b", ln, re.I):
                break   # Match blocks are conditional: only the global section counts here
    return {k: seen.get(k, v) for k, v in _SSHD_DEFAULTS.items()}, have


def logins():
    lines = []
    rc, txt = _run(["who"], 10)
    lines.append("LOGGED IN NOW:\n" + ("\n".join("  " + x for x in txt.strip().splitlines()) or "  nobody"))
    rc, txt = _run(["last", "-n", "15", "-a", "-w"], 15)
    lines.append("RECENT LOGINS (last 15):\n" + "\n".join("  " + x for x in txt.strip().splitlines()
                                                         if x.strip() and not x.startswith("wtmp")))
    rc, txt = _run(["journalctl", "-q", "--no-pager", "--since", "-7d", "-u", "ssh", "-u", "sshd",
                    "-g", "Failed password|Invalid user|authentication failure"], 30)
    if rc == 0 and txt.strip() and "No journal files" not in txt:
        fails = txt.strip().splitlines()
        ips = {}
        for x in fails:
            m = re.search(r"from (\S+)", x)
            if m:
                ip = _clean_text(m.group(1), 64)
                ips[ip] = ips.get(ip, 0) + 1
        top = sorted(ips.items(), key=lambda kv: -kv[1])[:8]
        lines.append(f"FAILED SSH LOGINS (7 days): {len(fails)}" + (
            "; top sources: " + ", ".join(f"{ip} x{n}" for ip, n in top) if top else ""))
    elif rc == 0:
        lines.append("FAILED SSH LOGINS (7 days): none in the journal")
    else:
        lines.append("FAILED SSH LOGINS: the journal is not readable by this user (add it to group adm or "
                     "systemd-journal, or run `sudo journalctl -u ssh -g 'Failed password'`)")
    cfg, have = sshd_settings()
    if have:
        lines.append("SSHD SETTINGS (global section of /etc/ssh/sshd_config + sshd_config.d):")
        lines += [f"  {k}: {v}" for k, v in cfg.items()]
        # the two a question is about, in words: "permitrootlogin: no" was answered "this means root login is
        # enabled ... you can log in as root via SSH" (defense drive 2026-11-22)
        prl = str(cfg.get("permitrootlogin") or "").lower()
        lines.append("  in words: root login over SSH is "
                     + ("NOT allowed" if prl.startswith("no") else
                        "allowed with a key only, never a password" if prl.startswith(("prohibit", "without"))
                        else "allowed only for forced commands" if prl.startswith("forced")
                        else "ALLOWED, password included" if prl.startswith("yes") else f"set to {prl}")
                     + "; password login is "
                     + ("OFF (keys only)" if str(cfg.get("passwordauthentication") or "").lower().startswith("no")
                        else "ON") + ".")
    else:
        lines.append("SSHD: no /etc/ssh/sshd_config (OpenSSH server not installed)")
    return "\n".join(lines)


def services():
    lines = []
    rc, txt = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend",
                    "--plain"], 20)
    run = [x.split()[0] for x in txt.splitlines() if x.strip()]
    lines.append(f"RUNNING SERVICES ({len(run)}): " + ", ".join(run))
    rc, txt = _run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-pager",
                    "--no-legend", "--plain"], 20)
    en = [x.split()[0] for x in txt.splitlines() if x.strip()]
    lines.append(f"ENABLED AT BOOT ({len(en)}): " + ", ".join(en))
    if shutil.which("pm2"):
        rc, txt = _run(["pm2", "jlist"], 20)
        try:
            procs = json.loads(txt[txt.index("["):]) if "[" in txt else []
            lines.append("PM2: " + ", ".join(f"{p.get('name')} ({p.get('pm2_env', {}).get('status')})"
                                             for p in procs))
        except ValueError:
            pass
    return "\n".join(lines)


# ---------- TOR HIDDEN SERVICES ----------
# Asked "check on the onion port and make sure it is secure", the agent read the socket list, saw `tor`
# next to 9152 and 9153, and reported those loopback-bound SOCKS/proxy ports as "the onion port, secure"
# (2026-10-25). They belonged to an UNRELATED throwaway tor started from a session scratchpad, and the
# real hidden service was never looked at. Nothing was wrong with the model's reasoning: `exposure` is a
# socket list, and a hidden service HAS NO LISTENING SOCKET - that is the entire point of it. Tor dials
# out to the network and forwards inbound streams to a local port. So no socket-shaped tool can find one,
# and the only honest answer the agent could have given was "I cannot see onion services".
#
# What actually decides whether an onion service is safe, none of which is a listening port:
#   1. the BACKEND the service forwards to. If 127.0.0.1:6969 is also bound on 0.0.0.0, the same content
#      is served in the clear and anyone scanning the internet can tie the two together: the anonymity is
#      gone even though tor is configured perfectly.
#   2. the SECRET KEY file. hs_ed25519_secret_key IS the service's identity. Readable by another local
#      account means that account can move the address to a server it controls.
#   3. the CONTROL PORT. An open, unauthenticated ControlPort is full control of tor: enumerate every
#      hidden service, read its keys, add new ones. Far worse than any proxy port.
#   4. the SOCKS PORT, which is the thing the agent DID check, and the least important of the four: it is
#      an open proxy if exposed, which is bad, but it is not the onion service.
_HS_KEY = "hs_ed25519_secret_key"


def _torrcs():
    """Every torrc this machine is actually running, as {path: [lines]}, from the live processes.

    Read from /proc, not from /etc: the tor that matters may be started by pm2, by a user unit or out of a
    temp dir with -f, and /etc/tor/torrc can be a file nothing uses."""
    found = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(pid_dir)
        try:
            with open(f"{pid_dir}/cmdline", "rb") as fh:
                argv = fh.read().decode("utf8", "replace").split("\0")
        except OSError:
            continue
        if not argv or os.path.basename(argv[0] or "") != "tor":
            continue
        path = ""
        for i, a in enumerate(argv):
            if a == "-f" and i + 1 < len(argv):
                path = argv[i + 1]
        path = path or "/etc/tor/torrc"
        try:
            with open(path, errors="replace") as fh:
                found[path] = [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]
        except OSError:
            found.setdefault(path, [])
        found[path + "\0pid"] = [pid]   # keep the pid beside it without changing the value shape
    return found


def _torrc_value(lines, key):
    for ln in lines:
        k, _, v = ln.partition(" ")
        if k.lower() == key.lower():
            return v.strip()
    return ""


def _proc_age(pid):
    rc, txt = _run(["ps", "-o", "etime=", "-p", str(pid)], 10)
    return txt.strip() if rc == 0 else ""


def _controlport_verdict(ctrl, lines):
    """How bad is this ControlPort. Authentication is the question, not which address it is bound to.

    A control connection can SETCONF, ADD_ONION and read the data directory: it is tor itself, not a
    proxy. Bound to loopback with no auth it is still every local process on the box; tor ships
    CookieAuthentication for exactly this, and `CookieAuthentication 0` turns it off."""
    if not ctrl:
        return "ControlPort (not set)  PASS"
    if ctrl.split()[0] == "0":
        return "ControlPort 0  PASS (disabled)"
    cookie = _torrc_value(lines, "CookieAuthentication")
    hashed = _torrc_value(lines, "HashedControlPassword")
    loopback = ctrl.startswith("127.") or ctrl.startswith("[::1]") or ctrl.startswith("localhost")
    if hashed or cookie == "1":
        return f"ControlPort {ctrl}  PASS (authenticated: " + ("password" if hashed else "cookie") + ")"
    where = ("every local process and user on this host can drive tor" if loopback else
             "ANYONE WHO CAN REACH THIS ADDRESS can drive tor")
    return (f"ControlPort {ctrl}  FAIL: no authentication"
            + (" (CookieAuthentication 0)" if cookie == "0" else " (no CookieAuthentication, no "
               "HashedControlPassword)")
            + f", so {where}: read every hidden service key, publish new services, change the exit path.")


def onion(rows=None):
    """Every tor hidden service on this host, and the four things that decide whether it is safe."""
    if target():
        # _torrcs reads THIS machine's /proc; mixing it with a remote box's sockets would describe neither
        return (f"the onion check reads tor's live config from /proc and runs on the local host only; "
                f"run it from a gnoc chat on {target()} (or /defender target local)")
    rows = rows if rows is not None else listening()
    # a backend is only private if NOTHING serves that port on a non-loopback address
    wide = {r["port"] for r in rows if r["bind"] in ("all", "lan")}
    out, confs = [], _torrcs()
    paths = [p for p in confs if not p.endswith("\0pid")]
    if not paths:
        return "no tor process is running on this host, so there are no onion services to check."
    for path in paths:
        lines = confs[path]
        pid = (confs.get(path + "\0pid") or ["?"])[0]
        socks, ctrl = _torrc_value(lines, "SocksPort"), _torrc_value(lines, "ControlPort")
        dirs = [v.split()[0] for ln in lines if ln.lower().startswith("hiddenservicedir")
                for v in [ln.partition(" ")[2].strip()] if v]
        ports = [ln.partition(" ")[2].strip() for ln in lines if ln.lower().startswith("hiddenserviceport")]
        age = _proc_age(pid)
        orphan = "/scratchpad/" in path or "/tmp/" in path
        out.append(f"tor pid {pid}  config {path}" + (f"  (running {age})" if age else ""))
        if orphan:
            out.append("  ORPHAN: this config lives in a temp/scratch directory, so the session that "
                       "started it has probably ended. That makes anything wrong with it WORSE, not "
                       "milder: nobody is watching it, nobody will fix it, and it keeps running with "
                       "whatever settings it has until the box reboots. Judge it on its settings below, "
                       "and say it should be killed if it is no longer needed: kill " + str(pid))
        if not dirs:
            out.append("  NO hidden service in this config: it is a plain tor client/proxy, not an onion "
                       "service. Its SocksPort is an egress proxy, nothing is published through it.")
        out.append(f"  SocksPort {socks or '(default 9050)'}" + ("  [0 = disabled, good]" if socks == "0" else ""))
        out.append("  " + _controlport_verdict(ctrl, lines))
        for d in dirs:
            host = ""
            try:
                with open(os.path.join(d, "hostname")) as fh:
                    host = fh.read().strip()
            except OSError:
                pass
            # the address itself is the service's identity: show enough to tell them apart, never all of it
            shown = (host[:8] + "..." + host[-6:]) if len(host) > 20 else (host or "(not created yet)")
            out.append(f"  service {d}")
            out.append(f"    address {shown}")
            for f, want, why in ((d, 0o700, "the service directory"), (os.path.join(d, _HS_KEY), 0o600,
                                                                       "the SECRET KEY: it IS this address")):
                try:
                    mode = os.stat(f).st_mode & 0o777
                except OSError:
                    out.append(f"    MISSING {os.path.basename(f)}")
                    continue
                ok = mode <= want
                out.append(f"    {'PASS' if ok else 'FAIL'}  {oct(mode)} {why}"
                           + ("" if ok else f" - must be {oct(want)}; another local account can take this "
                                            "service over"))
        for hp in ports:
            # "80 127.0.0.1:6969"  ->  virtual port, backend
            part = hp.split()
            vport, backend = (part[0] if part else "?"), (part[1] if len(part) > 1 else "")
            bp = backend.rpartition(":")[2]
            bp = int(bp) if bp.isdigit() else None
            if bp is None:
                out.append(f"    port {vport} -> {backend or '?'} (unix socket or unparsed)")
            elif bp in wide:
                out.append(f"    FAIL  onion port {vport} -> {backend}, but port {bp} is ALSO bound to the "
                           "network. The same content is reachable in the clear, so the onion address can "
                           "be tied to this host: the anonymity is defeated even though tor is fine.")
            else:
                out.append(f"    PASS  onion port {vport} -> {backend}, and nothing else serves {bp} off "
                           "loopback")
    out.append("")
    out.append("A hidden service has NO listening socket, so `defend action=exposure` cannot see one and "
               "a loopback-bound SocksPort says nothing about whether it is safe.")
    return "ONION SERVICES on " + socket.gethostname() + "\n" + "\n".join("  " + x if x else "" for x in out)


def audit():
    """The short verdict list: each line PASS / WARN / FAIL with the fact behind it."""
    out = []
    rows = listening()
    fw, fwd = firewall()
    ctr = containers()
    reach = [r for r in rows if r["bind"] in ("all", "lan") and not _is_client_udp(r)]
    crit = sorted({(r["port"], _note(r, ctr)[1]) for r in reach if _note(r, ctr)[0] == "crit"})
    high = sorted({(r["port"], _note(r, ctr)[1]) for r in reach if _note(r, ctr)[0] == "high"})
    out.append(("PASS" if fw == "active" else "WARN" if fw == "unknown" else "FAIL",
                f"firewall {fw}" + ("" if fw == "active" else f": {fwd.splitlines()[0][:140]}")))
    out.append(("FAIL" if crit else "PASS", "critical services reachable from the network: "
                + ("; ".join(f"port {p}: {w.split(':')[0]}" for p, w in crit) or "none")))
    out.append(("WARN" if high else "PASS", "sensitive services reachable from the network: "
                + ("; ".join(f"port {p}: {w.split(':')[0]}" for p, w in high) or "none")))
    cfg, have = sshd_settings()
    if have:
        pw = cfg["passwordauthentication"].lower().startswith("yes")
        ssh_open = any(r["port"] == int(re.match(r"\d+", cfg["port"]).group()) for r in reach) if re.match(
            r"\d+", cfg["port"]) else False
        out.append(("FAIL" if pw and ssh_open else "WARN" if pw else "PASS",
                    f"SSH password login: {cfg['passwordauthentication']}"
                    + ("  (sshd is reachable from the network)" if ssh_open else "")))
        out.append(("WARN" if cfg["permitrootlogin"].lower().startswith("yes") else "PASS",
                    f"SSH root login: {cfg['permitrootlogin']}"))
    # hidden services: no socket, so nothing above can see them (read from THIS machine's /proc: local only)
    torrcs = {} if target() else _torrcs()
    for path, lines in torrcs.items():
        if path.endswith("\0pid"):
            continue
        ctrl = _torrc_value(lines, "ControlPort")
        if ctrl and ctrl.split()[0] != "0" and not (_torrc_value(lines, "HashedControlPassword")
                                                    or _torrc_value(lines, "CookieAuthentication") == "1"):
            out.append(("FAIL", f"tor ControlPort {ctrl} with no authentication ({os.path.basename(path)}): "
                                "any local process can drive tor and read hidden service keys "
                                "(defend action=onion)"))
    wide = {r["port"] for r in rows if r["bind"] in ("all", "lan")}
    for path, lines in torrcs.items():
        for ln in lines:
            if not ln.lower().startswith("hiddenserviceport"):
                continue
            part = ln.partition(" ")[2].split()
            bp = part[1].rpartition(":")[2] if len(part) > 1 else ""
            if bp.isdigit() and int(bp) in wide:
                out.append(("FAIL", f"onion service backend port {bp} is also reachable from the network: "
                                    "the same content is served in the clear (defend action=onion)"))
    upg = "1" in (_read("/etc/apt/apt.conf.d/20auto-upgrades") or "")
    out.append(("PASS" if upg else "WARN", "automatic security updates " + ("on" if upg else "off (unattended-upgrades)")))
    order = {"FAIL": 0, "WARN": 1, "PASS": 2}
    out.sort(key=lambda x: order[x[0]])
    bad = sum(1 for s, _ in out if s != "PASS")
    # The count, in words, before the rows. Asked for "my top 3 security problems", a gpt-oss lead had one WARN and
    # five PASS rows and filled the list with two of the PASS rows, reworded as faults ("SSH password login is not
    # yet reachable - authentication is missing") (defense drive 2026-11-22).
    verdict = (f"{bad} thing(s) to look at, {len(out) - bad} check(s) passed. A PASS row is good news, not a "
               "problem: never list one as a problem, and if the user asks for more problems than there are, say how "
               "many there are.")
    return "HOST AUDIT " + hostname() + "\n" + verdict + "\n" + "\n".join(f"  {s:4}  {t}" for s, t in out) + \
        "\n\n(defend action=exposure lists every socket; action=logins and action=services show the detail)"


def hostname():
    """The target machine's hostname (this machine's when no remote target is set)."""
    if not target():
        return _clean_text(socket.gethostname(), 120)
    rc, txt = _run(["hostname"], 10)
    return (_clean_text((txt.splitlines() or ["?"])[0], 120) if rc == 0
            else _clean_text(f"{target()} (unreachable: {txt[:80]})", 200))


# ---------------------------------------------------------------- processes (pids)
# Names of miners, botnets and their usual disguises. A match is a strong signal, never a verdict on its own:
# the finding carries the exe path and the args so GreyNOC sees what was matched.
MALWARE_NAMES = re.compile(r"^(xmrig|xmr-stak\w*|kdevtmpfsi|kinsing|minerd|cpuminer\w*|ccminer|t-rex|nbminer|"
                           r"lolminer|phoenixminer|teamredminer|nanominer|kthreaddi|kworkerds|dbused|sysupdate|"
                           r"watchbog|tsunami|mirai|gafgyt|xorddos|pnscan)$", re.I)
REVERSE_SHELL = re.compile(r"/dev/tcp/|/dev/udp/|\bnc(?:at)?\b[^|;]*\s-[ec]\s|\bsocat\b[^|;]*\bexec:|"
                           r"\bbash\s+-i\b[^|;]*>&|python[23]?\s+-c\s+.*socket.*(?:connect|pty)|"
                           r"perl\s+-e\s+.*socket|\bmkfifo\b.*\bnc\b|stratum\+(?:tcp|ssl)://|"
                           r"(?:curl|wget)\s[^|;]*\|\s*(?:ba)?sh\b|base64\s+-d[^|;]*\|\s*(?:ba)?sh\b", re.I)
TMP_EXE = re.compile(r"^(?:/tmp/|/dev/shm/|/var/tmp/|/run/user/\d+/)")
# Processes the defender never pauses or kills, whatever they look like: the ones that keep GreyNOC connected to
# this box (he drives it remotely) and the ones the system cannot live without.
GNOC_PROCS = {"llama-server", "ollama", "ollama_llama_se", "ollama-runner", "rpc-server", "ggml-rpc-server",
              "llama-rpc-server"}
_GNOC_ARGS = re.compile(r"gnoc_engine\.py|gnoc-launcher(?:\.py)?|/gnoc$|/gnoc\s|gnoc_agent\.py")
_GNOC_HOMES = tuple(os.path.expanduser(p) for p in ("~/.local/share/gnoc-chat/", "~/.local/bin/", "~/.ollama/")) + (
    "/usr/", "/opt/", "/bin/", "/snap/",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep)   # this gnoc's own install, wherever it is
PROTECTED_PROCS = {"systemd", "init", "sshd", "sshd-session", "sshd-auth", "dbus-daemon", "dbus-broker", "polkitd",
                   "NetworkManager", "wpa_supplicant", "systemd-logind", "systemd-journald", "systemd-resolved",
                   "systemd-networkd", "login", "agetty", "Xorg", "Xwayland", "gnome-shell", "kwin_x11",
                   "kwin_wayland", "plasmashell", "gdm", "gdm3", "sddm", "lightdm", "xrdp", "xrdp-sesman",
                   "x11vnc", "Xvnc", "vncserver", "rustdesk", "anydesk", "teamviewerd", "tmux", "screen",
                   "tailscaled", "openvpn", "wireguard", "cron", "rsyslogd", "systemd-udevd", "udevd"}


def _exe_map():
    """{pid: exe link target} for every process whose /proc/<pid>/exe this user can read."""
    rc, txt = _run(["find", "/proc", "-mindepth", "2", "-maxdepth", "2", "-name", "exe", "-printf", r"%h\t%l\n"],
                   30)
    out = {}
    for ln in txt.splitlines():
        h, _, link = ln.partition("\t")
        m = re.fullmatch(r"/proc/(\d+)", h)
        if m and link:
            out[int(m.group(1))] = link
    return out


def process_rows():
    """[{pid, ppid, user, cpu, mem, secs, comm, args, exe, flags:[(sev, why)]}] from `ps` plus /proc/*/exe."""
    rc, txt = _run(["ps", "-eo", "pid=,ppid=,user:32=,pcpu=,pmem=,etimes=,args="], 20)
    exes = _exe_map()
    rows = []
    for ln in txt.splitlines():
        f = ln.split(None, 6)
        if len(f) < 7 or not f[0].isdigit():
            continue
        pid, ppid = int(f[0]), int(f[1])
        args = f[6]
        if ppid == 2 or pid == 2 or (args.startswith("[") and args.endswith("]")):
            continue   # kernel threads
        exe = exes.get(pid, "")
        comm = os.path.basename((exe.replace(" (deleted)", "") or args.split()[0]).rstrip(":"))
        if re.fullmatch(r"[\d.]+", comm) and args.split():
            comm = os.path.basename(args.split()[0]) or comm   # a versioned binary (.../versions/2.1.330): its name
        comm, args, exe = _clean_text(comm, 80), _clean_text(args, 300), _clean_text(exe, 300)
        try:
            cpu, mem = float(f[3] or 0), float(f[4] or 0)
        except ValueError:
            cpu, mem = 0.0, 0.0
        r = {"pid": pid, "ppid": ppid, "user": _clean_text(f[2], 80), "cpu": cpu, "mem": mem,
             "secs": int(f[5]) if f[5].isdigit() else 0, "comm": comm, "args": args, "exe": exe, "flags": []}
        arg0 = os.path.basename((args.split() or [""])[0])
        if MALWARE_NAMES.match(comm) or MALWARE_NAMES.match(arg0):
            r["flags"].append(("crit", f"name matches known miner/botnet malware ({comm})"))
        if REVERSE_SHELL.search(args):
            r["flags"].append(("crit", "command line looks like a reverse shell / download-and-run / miner pool"))
        if exe and TMP_EXE.match(exe):
            r["flags"].append(("high", f"runs from a temp directory ({exe})"))
        if exe.endswith(" (deleted)"):
            if re.match(r"^/(usr|opt|snap|lib|bin|sbin)/", exe):
                r["flags"].append(("info", "binary was replaced by an upgrade; restart it to run the patched one"))
            else:
                r["flags"].append(("high", f"binary was deleted after it started ({exe})"))
        rows.append(r)
    return rows


def processes():
    rows = process_rows()
    if not rows:
        return "could not list processes (`ps` failed)"
    flagged = [r for r in rows if any(s in ("crit", "high") for s, _ in r["flags"])]
    upgraded = [r for r in rows if any(s == "info" for s, _ in r["flags"])]
    conns = {}
    for c in connection_rows():
        if c["pid"]:
            conns.setdefault(c["pid"], []).append(c)
    lines = [f"PROCESSES on {hostname()}: {len(rows)} (kernel threads left out); "
             f"{len(flagged)} suspicious, {len(upgraded)} running a binary an upgrade replaced."]
    if flagged:
        lines.append("\nSUSPICIOUS:")
        for r in sorted(flagged, key=lambda r: min(_RANK[s] for s, _ in r["flags"])):
            pub = [c for c in conns.get(r["pid"], []) if c["peer_kind"] == "public"]
            lines.append(f"  pid {r['pid']} ({r['comm']}, user {r['user']}, up {r['secs']}s, cpu {r['cpu']}%)"
                         f"  exe={r['exe'] or '?'}")
            lines += [f"      [{s.upper()}] {w}" for s, w in r["flags"] if s != "info"]
            if pub:
                lines.append("      talks to: " + ", ".join(sorted({f"{c['peer']}:{c['peer_port']}" for c in pub})[:6]))
            lines.append(f"      args: {r['args'][:200]}")
    # the OWNER goes with every pid: "kill every process owned by root that has a network socket" was answered
    # with rclone, adb, tor and the operator's own Claude session, all his, called "owned by root" (drive
    # 2026-11-22). Protected processes are marked: the defender never pauses them.
    def who(r):
        prot = is_protected_proc(r["comm"], r.get("exe"), r.get("args"))
        # gnoc's own processes say so in words: with a bare "PROTECTED" the lead read "user gn, not the gnoc user"
        # and handed him `kill -STOP` for the llama-server answering him (batch 9, 2026-11-23)
        own = prot and (r["comm"] in GNOC_PROCS or str(r["comm"]).startswith("python"))
        tag = ", GNOC'S OWN model server/chat: never pause or kill it" if own else (", PROTECTED" if prot else "")
        return f"{r['comm']}(pid {r['pid']}, user {r['user']}" + tag + ")"
    top = sorted(rows, key=lambda r: -r["cpu"])[:6]
    lines.append("\nTOP CPU: " + ", ".join(f"{who(r)} {r['cpu']}%" for r in top))
    netp = sorted((r for r in rows if r["pid"] in conns), key=lambda r: r["pid"])
    lines.append(f"PROCESSES WITH ESTABLISHED CONNECTIONS ({len(netp)}): "
                 + ", ".join(who(r) for r in netp[:30]) + (" ..." if len(netp) > 30 else ""))
    owners = sorted({r["user"] for r in netp})
    if netp:
        lines.append("  owners of those: " + ", ".join(f"{u} x{sum(1 for r in netp if r['user'] == u)}"
                                                       for u in owners))
    if upgraded:
        lines.append("RESTART PENDING (upgraded binary still running): "
                     + ", ".join(sorted({r["comm"] for r in upgraded}))[:400])
    if not any(r["exe"] for r in rows):
        lines.append("(exe paths are unreadable here; other users' processes need root: `sudo ls -l /proc/*/exe`)")
    return "\n".join(lines)


# ---------------------------------------------------------------- connections
SUSPECT_PORTS = {3333: "mining pool (stratum)", 4444: "metasploit default", 5555: "common RAT / adb",
                 6666: "IRC botnet / RAT", 6667: "IRC (botnet C2)", 7777: "common RAT", 14444: "mining pool (xmr)",
                 14433: "mining pool (xmr tls)", 45700: "mining pool", 1337: "common backdoor",
                 31337: "common backdoor"}


def _peer_kind(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_unspecified or a.is_multicast:
        return "unknown"
    # CGNAT (100.64/10), ULA and link-local are not public even though ipaddress does not call them private.
    if not a.is_global:
        return "private"
    return "public"


def connection_rows():
    """[{proto, local, lport, peer, peer_port, peer_kind, dir, proc, pid}] for established TCP connections."""
    rc, txt = _run(["ss", "-H", "-tnp", "state", "established"], 20)
    listen = {r["port"] for r in listening() if r["proto"] == "tcp"}
    rows = []
    for ln in txt.splitlines():
        f = ln.split()
        if len(f) < 4:
            continue
        loc, peer = f[2], f[3]
        la, _, lp = loc.rpartition(":")
        pa, _, pp = peer.rpartition(":")
        if not (lp.isdigit() and pp.isdigit()):
            continue
        pa = pa.split("%")[0].strip("[]")       # [fe80::1]%wlan0: drop the zone first, then the brackets
        pa = pa[7:] if pa.startswith("::ffff:") else pa
        m = re.search(r'users:\(\("(.*?)",pid=(\d+)', ln)   # a comm may itself contain a quote
        peer = _clean_text(pa, 64)
        rows.append({"proto": "tcp", "local": _clean_text(la.split("%")[0].strip("[]"), 64), "lport": int(lp), "peer": peer,
                     "peer_port": int(pp), "peer_kind": _peer_kind(peer),
                     "dir": "in" if int(lp) in listen else "out",
                     "proc": _clean_text(m.group(1), 80) if m else "?",
                     "pid": int(m.group(2)) if m else None})
    return rows


def connections():
    rows = connection_rows()
    ext = [r for r in rows if r["peer_kind"] in ("public", "private")]
    inbound = [r for r in ext if r["dir"] == "in"]
    out = [r for r in ext if r["dir"] == "out"]
    lines = [f"ESTABLISHED TCP on {hostname()}: {len(rows)} total, {len(inbound)} inbound from other machines, "
             f"{len(out)} outbound to other machines, {len(rows) - len(ext)} loopback."]
    if inbound:
        lines.append("\nINBOUND (someone connected to a service here):")
        agg = {}
        for r in inbound:
            k = (r["peer"], r["lport"], r["proc"])
            agg[k] = agg.get(k, 0) + 1
        for (ip, lp, proc), n in sorted(agg.items(), key=lambda kv: -kv[1])[:25]:
            lines.append(f"  {ip:<40} -> port {lp:<5} {proc}  x{n}  ({_peer_kind(ip)})")
    sus = [r for r in out if r["peer_port"] in SUSPECT_PORTS]
    if sus:
        lines.append("\nOUTBOUND TO SUSPICIOUS PORTS:")
        lines += [f"  [HIGH] {r['proc']}({r['pid']}) -> {r['peer']}:{r['peer_port']}  {SUSPECT_PORTS[r['peer_port']]}"
                  for r in sus]
    if out:
        per = {}
        for r in out:
            per.setdefault(r["proc"], set()).add(r["peer"])
        lines.append("\nOUTBOUND BY PROCESS (distinct remote hosts): "
                     + ", ".join(f"{p} {len(v)}" for p, v in sorted(per.items(), key=lambda kv: -len(kv[1]))[:20]))
        # the addresses themselves: "I see outbound connections to an IP in a country I don't know" got a count,
        # then three `sudo ss` that waited on approval to the 420 s cap (batch 9, 2026-11-23)
        seen, shown = set(), 0
        lines.append("OUTBOUND CONNECTIONS (program(pid) -> remote:port):")
        for r in sorted(out, key=lambda r: (r["proc"], r["peer"])):
            k = (r["proc"], r["pid"], r["peer"], r["peer_port"])
            if k in seen:
                continue
            seen.add(k)
            if shown >= 30:
                lines.append(f"  ... {len(out) - shown} more")
                break
            host = f"[{r['peer']}]" if ":" in str(r["peer"]) else r["peer"]
            lines.append(f"  {r['proc']}({r['pid']}) -> {host}:{r['peer_port']}  ({_peer_kind(r['peer'])})")
            shown += 1
        fan = [(p, len(v)) for p, v in per.items() if len(v) >= 40 and p not in BROWSERS]
        if fan:
            lines.append("  [WARN] high fan-out (scanner/bot-like unless you started it): "
                         + ", ".join(f"{p} -> {n} hosts" for p, n in fan))
    if any(r["proc"] == "?" for r in rows):
        lines.append("\n(? = owned by another user; `sudo ss -tnp state established` names them)")
    return "\n".join(lines)


BROWSERS = {"chrome", "chromium", "firefox", "firefox-esr", "brave", "librewolf", "opera", "msedge"}


# ---------------------------------------------------------------- packets
def _proc_counters():
    """({name: value} from /proc/net/snmp + /proc/net/netstat, {iface: (rxB, rxP, txB, txP)} from /proc/net/dev).
    Readable by any user, so this is the no-root packet view."""
    c = {}
    for path in ("/proc/net/snmp", "/proc/net/netstat"):
        lines = (_read(path) or "").splitlines()
        for a, b in zip(lines[0::2], lines[1::2]):
            ka, kb = a.split(), b.split()
            if ka and kb and ka[0] == kb[0]:
                pre = ka[0].rstrip(":")
                for k, v in zip(ka[1:], kb[1:]):
                    if v.lstrip("-").isdigit():
                        c[pre + "." + k] = int(v)
    dev = {}
    for ln in (_read("/proc/net/dev") or "").splitlines()[2:]:
        name, _, rest = ln.partition(":")
        f = rest.split()
        if len(f) >= 10:
            dev[name.strip()] = (int(f[0]), int(f[1]), int(f[8]), int(f[9]))
    return c, dev


_TS_FIELDS = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport",
              "udp.dstport", "tcp.flags.syn", "tcp.flags.ack", "_ws.col.Protocol", "frame.len"]
_TD_LINE = re.compile(r"\bIP6?\s+(\S+?)\.(\d+)\s+>\s+(\S+?)\.(\d+):\s*(tcp|UDP|Flags \[([^\]]*)\])?[^\n]*?"
                      r"(?:length:? (\d+))?$")


def parse_tshark(txt):
    pk = []
    for ln in txt.splitlines():
        # tunnelled/ICMP-quoted packets carry several values per field ("10.0.0.1,10.0.0.9"): the outer one
        f = [x.split(",")[0] for x in ln.split("\t")]
        if len(f) < len(_TS_FIELDS):
            continue
        src, dst = f[0] or f[1], f[2] or f[3]
        if not src:
            continue
        tcp = bool(f[4])
        sp, dp = (f[4], f[5]) if tcp else (f[6], f[7])
        syn = f[8] in ("1", "True") and f[9] in ("0", "False")
        pk.append((src, int(sp) if sp.isdigit() else 0, dst, int(dp) if dp.isdigit() else 0,
                   "tcp" if tcp else (f[10] or "udp").lower(), syn, int(f[11]) if f[11].isdigit() else 0))
    return pk


def parse_tcpdump(txt):
    pk = []
    for ln in txt.splitlines():
        m = _TD_LINE.search(ln)
        if m:
            kind = m.group(5) or ""
            proto = "udp" if kind == "UDP" else "tcp" if kind else "ip"
            pk.append((m.group(1), int(m.group(2)), m.group(3), int(m.group(4)), proto, (m.group(6) or "") == "S",
                       int(m.group(7) or 0)))
    return pk


def _capture(seconds, count):
    """([(src, sport, dst, dport, proto, syn_only, length)], how) or (None, why). tshark first (works for the
    wireshark group: dumpcap carries the capture capability), then a passwordless `sudo -n tcpdump`."""
    errs = []
    argv = ["tshark", "-i", "any", "-n", "-q", "-l", "-a", f"duration:{seconds}", "-c", str(count),
            "-T", "fields", "-E", "separator=\t"]
    for f in _TS_FIELDS:
        argv += ["-e", f]
    rc, txt = _run(argv, seconds + 20)
    pk = parse_tshark(txt)
    if pk:
        return pk, "tshark"
    errs.append("tshark: " + (txt.strip().splitlines() or ["no packets"])[-1][:160])
    # not -q: quiet mode drops the TCP flags, and SYN-only packets are what the port-scan check counts
    rc, txt = _run(["timeout", str(seconds), "sudo", "-n", "tcpdump", "-i", "any", "-nn", "-l", "-t",
                    "-c", str(count)], seconds + 15)
    pk = parse_tcpdump(txt)
    if pk:
        return pk, "tcpdump"
    errs.append("tcpdump: " + (txt.strip().splitlines() or ["no packets"])[-1][:160])
    return None, "; ".join(errs)


def summarize_packets(pk, own, seconds, how=""):
    """The text verdict over captured packets. own = this machine's addresses (as strings)."""
    tot = sum(p[6] for p in pk)
    lines = [f"PACKETS on {hostname()} ({how}, {len(pk)} packets / {tot} bytes in up to {seconds}s):"]
    protos = {}
    for p in pk:
        protos[p[4]] = protos.get(p[4], 0) + 1
    lines.append("  protocols: " + ", ".join(f"{k} {v}" for k, v in sorted(protos.items(), key=lambda kv: -kv[1])))
    talk = {}
    for s, sp, d, dp, pr, syn, ln in pk:
        talk[(s, d, dp)] = talk.get((s, d, dp), 0) + max(ln, 1)
    lines.append("  top flows (src -> dst:port, bytes):")
    lines += [f"    {s} -> {d}:{dp}  {b}" for (s, d, dp), b in sorted(talk.items(), key=lambda kv: -kv[1])[:10]]
    syn_in = {}
    for s, sp, d, dp, pr, syn, ln in pk:
        if syn and d in own and s not in own:
            syn_in.setdefault(s, set()).add(dp)
    if syn_in:
        lines.append("  inbound connection attempts (SYN) by source: "
                     + ", ".join(f"{s} -> {len(ps)} port(s)" for s, ps in sorted(syn_in.items(),
                                                                                 key=lambda kv: -len(kv[1]))[:10]))
    for s, ps in syn_in.items():
        if len(ps) >= 12:
            lines.append(f"  [HIGH] port scan: {s} tried {len(ps)} distinct ports in {seconds}s "
                         f"({_peer_kind(s)}): {', '.join(map(str, sorted(ps)[:15]))}")
    odd = sorted({(d, dp) for s, sp, d, dp, pr, syn, ln in pk if dp in SUSPECT_PORTS and s in own})
    for d, dp in odd[:10]:
        lines.append(f"  [HIGH] outbound to {d}:{dp} ({SUSPECT_PORTS[dp]})")
    return "\n".join(lines)


def packets(seconds=8, count=600):
    """A short look at the traffic itself: who talks to whom, inbound SYNs, port scans, odd ports. Falls back to
    the kernel's own counters (no root) when nothing here may capture."""
    try:
        seconds = max(3, min(30, int(seconds or 8)))
    except (TypeError, ValueError):
        seconds = 8
    own = {a.split("%")[0] for v in interfaces().values() for a in v}
    pk, how = _capture(seconds, max(50, min(5000, int(count or 600))))
    if pk:
        return summarize_packets(pk, own, seconds, how)
    c0, d0 = _proc_counters()
    time.sleep(seconds)
    c1, d1 = _proc_counters()
    dc = {k: c1.get(k, 0) - v for k, v in c0.items()}
    lines = [f"PACKET VIEW on {hostname()}: no capture rights here ({how}).",
             f"Kernel counters over {seconds}s instead (no root needed):"]
    for ifn in sorted(d1):
        if ifn in d0 and ifn != "lo":
            rb, rp, tb, tp = (d1[ifn][i] - d0[ifn][i] for i in range(4))
            if rp or tp:
                lines.append(f"  {ifn}: in {rp} pkts / {rb} B, out {tp} pkts / {tb} B")
    for k, label in (("Tcp.PassiveOpens", "inbound connections accepted"),
                     ("Tcp.ActiveOpens", "outbound connections opened"),
                     ("Tcp.AttemptFails", "failed connection attempts"), ("Tcp.OutRsts", "resets sent (closed-port hits)"),
                     ("Tcp.InErrs", "bad TCP segments"), ("TcpExt.ListenDrops", "accept-queue drops"),
                     ("TcpExt.SyncookiesSent", "SYN cookies sent (SYN flood)"), ("Udp.NoPorts", "UDP to closed ports")):
        if k in dc:
            lines.append(f"  {label}: {dc[k]}")
    lines += counter_alarms(dc)
    lines.append("For per-packet detail: `sudo usermod -aG wireshark $USER` (dumpcap already has the capture "
                 "capability), log in again, and re-run this.")
    return "\n".join(lines)


def counter_alarms(dc):
    out = []
    if dc.get("Tcp.OutRsts", 0) > 40 and dc.get("Tcp.OutRsts", 0) > 4 * max(1, dc.get("Tcp.PassiveOpens", 0)):
        out.append("  [HIGH] many resets to few accepted connections: something is hitting closed ports (a scan)")
    if dc.get("TcpExt.SyncookiesSent", 0) > 0:
        out.append("  [HIGH] SYN cookies were sent: a SYN flood is filling the listen queue")
    return out


# ---------------------------------------------------------------- kernel / OS settings
# key -> (accepted values, value to set, what it protects). The defender helper changes ONLY these keys.
SYSCTL_CHECKS = {
    "net.ipv4.tcp_syncookies": ({"1"}, "1", "SYN flood resistance"),
    "net.ipv4.conf.all.rp_filter": ({"1", "2"}, "2", "drops spoofed source addresses"),
    "net.ipv4.conf.all.accept_redirects": ({"0"}, "0", "ICMP redirects can reroute your traffic"),
    "net.ipv4.conf.default.accept_redirects": ({"0"}, "0", "ICMP redirects on new interfaces"),
    "net.ipv6.conf.all.accept_redirects": ({"0"}, "0", "IPv6 ICMP redirects"),
    "net.ipv4.conf.all.send_redirects": ({"0"}, "0", "a non-router should not send redirects"),
    "net.ipv4.conf.all.accept_source_route": ({"0"}, "0", "source-routed packets bypass routing policy"),
    "net.ipv4.icmp_echo_ignore_broadcasts": ({"1"}, "1", "smurf amplification"),
    "net.ipv4.conf.all.log_martians": ({"1"}, "1", "logs impossible source addresses"),
    "kernel.randomize_va_space": ({"2"}, "2", "full ASLR"),
    "kernel.kptr_restrict": ({"1", "2"}, "1", "hides kernel pointers from users"),
    "kernel.dmesg_restrict": ({"1"}, "1", "kernel log readable only by root"),
    "kernel.yama.ptrace_scope": ({"1", "2", "3"}, "1", "stops a process reading another's memory"),
    "kernel.unprivileged_bpf_disabled": ({"1", "2"}, "2", "unprivileged eBPF is a common kernel exploit path"),
    "fs.protected_symlinks": ({"1"}, "1", "symlink attacks in /tmp"),
    "fs.protected_hardlinks": ({"1"}, "1", "hardlink attacks"),
    "fs.protected_fifos": ({"1", "2"}, "1", "FIFO spoofing in sticky dirs"),
    "fs.protected_regular": ({"1", "2"}, "2", "file spoofing in sticky dirs"),
    "fs.suid_dumpable": ({"0"}, "0", "setuid programs dumping memory to disk"),
}
ROOT_GROUPS = {"docker": "the docker socket is root without a password", "lxd": "lxd containers are root on the host",
               "disk": "raw disk access reads any file", "libvirt": "VM definitions can mount host files"}


def docker_socket_usable():
    """True when a docker API socket this user can read AND write exists (the symlink followed)."""
    for p in ("/var/run/docker.sock", "/run/docker.sock"):
        try:
            if os.path.exists(p) and os.access(p, os.R_OK | os.W_OK):
                return True
        except OSError:
            continue
    return False


def setting_rows():
    """[(sev, area, key, fact, fix)] for kernel, account, group, cron and file-permission hardening."""
    out = []
    rc, txt = _run(["sysctl", "net.ipv4.ip_forward", *SYSCTL_CHECKS], 20)
    vals = {}
    for ln in txt.splitlines():
        k, _, v = ln.partition(" = ")
        if v:
            vals[k.strip()] = v.strip()
    for k, (ok, want, why) in SYSCTL_CHECKS.items():
        if k in vals and vals[k] not in ok:
            out.append(("warn", "sysctl", k, f"{k} = {vals[k]} ({why})", f"sysctl -w {k}={want}"))
    if vals.get("net.ipv4.ip_forward") == "1":
        out.append(("info", "sysctl", "net.ipv4.ip_forward", "IP forwarding is on (normal with containers or a VPN)",
                    ""))
    for ln in (_read("/etc/passwd") or "").splitlines():
        f = ln.split(":")
        if len(f) > 3 and f[2] == "0" and f[0] != "root":
            out.append(("crit", "accounts", "uid0:" + f[0], f"account {f[0]} has uid 0 (a second root)",
                        f"usermod -u <new uid> {f[0]}  (or remove the account)"))
    rc, gtxt = _run(["id", "-Gn"], 10)
    for g in gtxt.split() if rc == 0 else []:
        if g == "docker" and not docker_socket_usable():
            # docker not installed, the socket a symlink to a podman socket this user cannot open: "the docker
            # socket is root without a password" made the lead rank it the one thing to fix (drive 2026-11-22)
            out.append(("info", "groups", "group:docker", "this user is in group docker, but no docker socket "
                        "this user can open exists right now (docker not running, or the socket is not reachable): "
                        "no root path TODAY; it becomes one the moment a docker daemon starts",
                        "sudo gpasswd -d $USER docker  (only if you do not use docker)"))
        elif g in ROOT_GROUPS:
            out.append(("warn", "groups", "group:" + g, f"this user is in group {g}: {ROOT_GROUPS[g]}",
                        f"sudo gpasswd -d $USER {g}  (only if you do not need it)"))
    keys = [k for k in (_read("~/.ssh/authorized_keys") or "").splitlines() if k.strip() and not k.startswith("#")]
    if keys:
        out.append(("info", "ssh", "authorized_keys", f"{len(keys)} key(s) in ~/.ssh/authorized_keys may log in as "
                    "this user: " + "; ".join(k.split()[-1][:40] for k in keys[:8]), ""))
        weak = [k for k in keys if "ssh-dss" in k or re.search(r"ssh-rsa\s+(\S{1,360})(\s|$)", k)]
        if weak:
            out.append(("warn", "ssh", "weakkey", f"{len(weak)} authorized key(s) are DSA or RSA under 2048 bits",
                        "replace them with ed25519 keys"))
    rc, txt = _run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], 30)
    ww = [x for x in txt.splitlines() if x.startswith("/etc/")]
    if ww:
        out.append(("high", "files", "etc-world-writable", f"{len(ww)} world-writable file(s) in /etc: "
                    + ", ".join(ww[:6]), "sudo chmod o-w " + " ".join(shlex.quote(x) for x in ww[:6])))
    rc, txt = _run(["find", "/usr/local", "/opt", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-type", "f",
                    "-perm", "-4000"], 30)
    suid = [x for x in txt.splitlines() if x.startswith("/")]
    if suid:
        sev = "crit" if any(x.startswith(("/tmp", "/var/tmp", "/dev/shm")) for x in suid) else "warn"
        out.append((sev, "files", "suid-odd", "setuid binaries outside the system dirs: " + ", ".join(suid[:8]),
                    "sudo chmod u-s <file>  after checking what installed it"))
    rc, txt = _run(["crontab", "-l"], 10)
    for ln in txt.splitlines() if rc == 0 else []:
        if ln.strip() and not ln.lstrip().startswith("#") and (
                REVERSE_SHELL.search(ln) or re.search(r"\s/(?:tmp|dev/shm|var/tmp)/", ln)):
            out.append(("high", "cron", "cron:" + ln.strip()[:40], f"crontab runs: {ln.strip()[:160]}", "crontab -e"))
    return out


def settings():
    rows = setting_rows()
    order = {"crit": 0, "high": 1, "warn": 2, "info": 3}
    lines = [f"SETTINGS on {hostname()}: {sum(1 for r in rows if r[0] != 'info')} to fix"]
    for sev, area, key, fact, fix in sorted(rows, key=lambda r: order[r[0]]):
        lines.append(f"  [{sev.upper():4}] {area}: {fact}" + (f"\n         fix: {fix}" if fix else ""))
    return "\n".join(lines)


# ---------------------------------------------------------------- persistence: what survives a reboot
# Where an intruder who already ran code makes it run AGAIN: system/user systemd units, cron, shell start-up
# files, desktop autostart, rc.local, and the loader's preload list. Admin-owned locations only: /lib and /usr/lib
# units are package-managed (hundreds of files) and their drift is the package manager's business.
PERSIST_FILES = ("/etc/ld.so.preload", "/etc/rc.local", "/etc/crontab", "/etc/profile", "/etc/bash.bashrc",
                 "/etc/zsh/zshrc", "~/.bashrc", "~/.profile", "~/.bash_profile", "~/.bash_login", "~/.bash_logout",
                 "~/.zshrc", "~/.zprofile", "~/.xprofile", "~/.xsessionrc")
PERSIST_DIRS = ("/etc/systemd/system", "/etc/systemd/user", "~/.config/systemd/user", "/etc/cron.d",
                "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/profile.d",
                "/etc/xdg/autostart", "~/.config/autostart", "/etc/init.d")
PERSIST_MAX_FILES = 400
PERSIST_MAX_BYTES = 65536
_PERSIST_MARK = "@@GNOC-PERSIST@@ "
# The parts of REVERSE_SHELL that mean "fetch and run": high on their own, not proof of a live shell.
_FETCH_RUN = re.compile(r"(?:curl|wget)\s[^|;]*\|\s*(?:ba)?sh\b|base64\s+-d[^|;]*\|\s*(?:ba)?sh\b", re.I)
_TMP_RUN = re.compile(r"(?:^|[;&|(`]\s*|\$\(\s*|\b(?:sh|bash|dash|zsh|python[23]?|perl|ruby|php|node|exec|nohup|"
                      r"setsid|env|nice|chmod\s+\+x)\s+)/(?:tmp|dev/shm|var/tmp)/\S")
_CRON_LINE = re.compile(r"^\s*(?:@\w+\s+|(?:\S+\s+){5})(\S+)\s+(.*)$")
_EXEC_LINE = re.compile(r"^\s*(?:Exec(?:Start|StartPre|StartPost|Stop|Reload)?)\s*=\s*(.+)$", re.I)
_RC_HOOKS = (
    (re.compile(r"^\s*(?:export\s+)?LD_PRELOAD\s*=", re.I), "high",
     "sets LD_PRELOAD: every program started from this shell loads that library first"),
    (re.compile(r"^\s*alias\s+(?:sudo|su|ssh|passwd)\s*=", re.I), "high",
     "aliases a credential-handling command: the classic way to capture a typed password"),
)


def _persist_script(mark=_PERSIST_MARK):
    """One POSIX-sh pass that prints every persistence file, bounded, each after a marker line. Runs the same
    locally and over ssh (one round trip, not one per file)."""
    def word(p):
        return '"$HOME"/' + shlex.quote(p[2:]) if p.startswith("~/") else shlex.quote(p)
    files = " ".join(word(p) for p in PERSIST_FILES)
    dirs = " ".join(word(p) for p in PERSIST_DIRS)
    return ("{ for f in " + files + "; do [ -f \"$f\" ] && printf '%s\\n' \"$f\"; done; "
            "find " + dirs + " -maxdepth 1 -type f 2>/dev/null; } | head -n " + str(PERSIST_MAX_FILES) +
            " | while IFS= read -r f; do printf '\\n" + mark + "%s\\n' \"$f\"; "
            "head -c " + str(PERSIST_MAX_BYTES) + " \"$f\" 2>/dev/null; done; exit 0")


def parse_persist_dump(txt, mark=_PERSIST_MARK):
    """{path: text} from _persist_script output. A path line is only ever the marker's own line. The live sweep
    uses a RANDOM marker per run: with the fixed one, a line `@@GNOC-PERSIST@@ /etc/init.d/cron` appended to
    ~/.bashrc filed the lines after it under another file and hid them from drift (QAQC 2026-11-19)."""
    out = {}
    cur = None
    buf = []
    for ln in (txt or "").split("\n"):
        if ln.startswith(mark):
            if cur is not None:
                out[cur] = "\n".join(buf).strip("\n")
            cur, buf = ln[len(mark):].strip(), []
        elif cur is not None:
            buf.append(ln)
    if cur is not None:
        out[cur] = "\n".join(buf).strip("\n")
    return {k: v for k, v in out.items() if k.startswith("/")}


def persistence_files():
    """{path: text} of every persistence file this user can read on the target, or None when the read itself
    failed (ssh down, timeout) - which callers must not mistake for "no persistence files"."""
    mark = f"@@GNOC-PERSIST-{os.urandom(12).hex()}@@ "
    rc, txt = _run(["sh", "-c", _persist_script(mark)], 30)
    return parse_persist_dump(txt, mark) if rc == 0 else None


def _exec_flags(cmd):
    """(sev, why) for one command line that something will run on its own, or None."""
    if REVERSE_SHELL.search(cmd):
        if _FETCH_RUN.search(cmd) and not REVERSE_SHELL.search(_FETCH_RUN.sub(" ", cmd)):
            return "high", "downloads and runs code"
        return "crit", "reverse shell / miner signature"
    words = cmd.strip().lstrip("-@+!:").split()
    first = words[0] if words else ""   # systemd prefixes alone ("ExecStart=-") leave nothing to run
    # EXECUTED from a temp dir (command position, or handed to an interpreter), not merely mentioned:
    # init scripts routinely `mktemp /tmp/...`, which is not persistence
    if TMP_EXE.match(first) or _TMP_RUN.search(cmd):
        return "high", "runs a program from a world-writable temp directory"
    if re.search(r"/home/[^/\s]+/\.[^/\s]+/\S*|~/\.[^/\s]+/\S*|\$HOME/\.[^/\s]+/\S*", first):
        if not re.search(r"/\.(?:local|cargo|nvm|pyenv|rbenv|sdkman|bun|deno|volta)/", first):
            return "warn", "runs a program from a hidden directory in a home folder"
    return None


def persistence_rows(files=None):
    """[(sev, area, key, fact, fix)] for persistence entries that run something they should not."""
    files = (persistence_files() or {}) if files is None else files
    out = []
    seen = set()

    def add(sev, key, fact, fix):
        if key not in seen:
            seen.add(key)
            out.append((sev, "persistence", key, fact, fix))
    for path, text in sorted(files.items()):
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        if path == "/etc/ld.so.preload":
            libs = [x for ln in lines for x in ln.split()]
            if libs:
                odd = [x for x in libs if not re.match(r"^/(?:usr/)?lib(?:32|64|x32)?/", x)]
                add("crit" if odd else "high", "preload",
                    "/etc/ld.so.preload force-loads " + ", ".join(libs[:4]) + " into EVERY process"
                    + (" from outside the system library dirs" if odd else "")
                    + ": the standard user-land rootkit hook",
                    "check which package owns it (dpkg -S / rpm -qf); if none, empty /etc/ld.so.preload as root "
                    "and treat the host as compromised")
            continue
        is_unit = path.endswith((".service", ".timer", ".socket", ".path", ".desktop"))
        is_rc = not is_unit and ("/profile" in path or os.path.basename(path).startswith(".")
                                 or path.endswith(("bashrc", "zshrc")))
        is_crontab = path == "/etc/crontab" or path.startswith("/etc/cron.d/")
        for ln in lines:
            cmd = ln
            if is_unit:
                m = _EXEC_LINE.match(ln)
                if not m:
                    continue
                cmd = m.group(1)
            elif is_crontab:
                if re.match(r"^\s*[A-Za-z_]\w*\s*=", ln):     # SHELL=, PATH=, MAILTO=
                    continue
                m = _CRON_LINE.match(ln)
                if not m:
                    continue
                cmd = m.group(2)                              # minus the schedule and the user field
            hit = _exec_flags(cmd)
            if hit:
                sev, why = hit
                add(sev, f"{path}:{cmd.strip()[:40]}", f"{path} {why}: {cmd.strip()[:160]}",
                    (f"systemctl {'--user ' if '/.config/' in path or '/user/' in path else ''}disable --now "
                     f"{shlex.quote(os.path.basename(path))} after saving a copy for the incident"
                     if path.endswith(".service") else f"save a copy, then remove that line from {path}"))
            if is_rc:
                for rx, sev, why in _RC_HOOKS:
                    if rx.search(ln):
                        add(sev, f"{path}:{ln.strip()[:40]}", f"{path} {why}: {ln.strip()[:160]}",
                            f"remove that line from {path} unless you put it there")
    return out


def persistence():
    rows = persistence_rows()
    order = {"crit": 0, "high": 1, "warn": 2, "info": 3}
    lines = [f"PERSISTENCE on {hostname()}: {len(rows)} suspicious entr{'y' if len(rows) == 1 else 'ies'}"]
    for sev, area, key, fact, fix in sorted(rows, key=lambda r: order[r[0]]):
        lines.append(f"  [{sev.upper():4}] {fact}" + (f"\n         fix: {fix}" if fix else ""))
    if not rows:
        lines.append("  nothing in systemd/cron/shell start-up/autostart/preload runs a known-bad pattern")
    return "\n".join(lines)


def authorized_key_prints(text=None):
    """{sha256 fingerprint of the key blob: comment} for ~/.ssh/authorized_keys on the target."""
    text = _read("~/.ssh/authorized_keys") if text is None else text
    out = {}
    for ln in (text or "").splitlines():
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        try:
            parts = shlex.split(ln, posix=True) if '"' in ln else ln.split()
        except ValueError:          # unbalanced quote in an options field: fall back to whitespace
            parts = ln.split()
        blob_i = next((i for i, p in enumerate(parts) if re.match(r"^(?:ssh-|ecdsa-|sk-)", p)), None)
        if blob_i is None or blob_i + 1 >= len(parts):
            continue
        try:
            raw = base64.b64decode(parts[blob_i + 1], validate=True)
        except (binascii.Error, ValueError):
            continue
        # the same string `ssh-keygen -lf` prints, so the operator can match it by eye
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        out[fp] = (" ".join(parts[blob_i + 2:])[:80] or parts[blob_i])
    return out


def firewall_detail():
    """The whole ruleset as far as this user can read it."""
    lines = [f"FIREWALL on {hostname()}:"]
    seen = set()
    for name, argv in (("ufw", ["ufw", "status", "verbose"]), ("ufw", ["sudo", "-n", "ufw", "status", "verbose"]),
                       ("nftables", ["nft", "list", "ruleset"]), ("nftables", ["sudo", "-n", "nft", "list", "ruleset"]),
                       ("iptables", ["sudo", "-n", "iptables", "-S"])):
        if name in seen:
            continue
        rc, txt = _run(argv, 15)
        good = rc == 0 and txt.strip() and ("Status:" in txt if name == "ufw" else True)
        if not good:
            continue
        seen.add(name)
        body = txt.strip().splitlines()
        lines.append(f"\n{name} ({' '.join(argv[:4])}):")
        lines += ["  " + x for x in body[:120]]
        if len(body) > 120:
            lines.append(f"  ... {len(body) - 120} more lines")
    if not seen:
        # what IS readable without root, so the answer has a fact to stand on. With only "nothing readable",
        # a gpt-oss lead printed a whole invented `ufw status verbose` table and an nft ruleset (2026-11-22).
        known = firewall_known()
        if known:
            lines.append("  read without root: " + "; ".join(known))
        lines.append("  the RULES are not readable without root, so which ports are allowed or denied is UNKNOWN "
                     "here: say that, and show no rule table or command output that was not read. For the rules, "
                     "run (and paste back): `sudo ufw status verbose; sudo nft list ruleset | head -150`")
    if any("gnoc_defender" in x for x in lines):
        lines.append("\n(table inet gnoc_defender holds the defender's temporary IP blocks; each one expires)")
    return "\n".join(lines)


# ---------------------------------------------------------------- the network around this machine
# A host check cannot see the LAN or the WLAN. These reads answer the questions the user actually asks:
# which subnets am I on, which gateway carries them, which wireless network am I attached to, which
# neighbours have I seen, and (only when asked) which addresses answer on the subnet. Every parser is
# pure and testable; every command is the non-root form of the same read.
_LINK_CACHE = {}
_WIFI_CACHE = {}
_GATEWAY_PORTS = {
    22: ("medium", "SSH admin"),
    23: ("high", "TELNET: cleartext admin"),
    # the router answering name lookups for the LAN is its job, not an exposure: graded medium, the sweep's "one
    # thing that matters most" became "disable DNS on the router", which breaks the network (defense batch 11)
    53: ("info", "DNS resolver: normal, the router answers the LAN's name lookups"),
    80: ("info", "HTTP admin page"),
    443: ("info", "HTTPS admin page"),
    7547: ("high", "TR-069/CWMP: ISP remote management"),
    8080: ("medium", "alternate HTTP admin"),
    8443: ("medium", "alternate HTTPS admin"),
    5000: ("medium", "UPnP HTTP admin"),
}


def _if_kind(name, link_type=""):
    """Classify an interface by its own name, then by the kernel's link type."""
    n = (name or "").lower()
    if n == "lo" or link_type == "loopback":
        return "loopback"
    if re.match(r"^(wl|wlan|wlp|wlo|wifi|ath|ra\d)", n):
        return "wlan"
    if re.match(r"^(wg|tun|tap|tailscale|zt|ppp|ipsec|vti)", n):
        return "vpn"
    if re.match(r"^(docker|br-|veth|virbr|podman|cni|flannel|cali|kube)", n):
        return "container"
    if re.match(r"^(en|eth|eno|ens|enp|em\d|bond|team|ib)", n):
        return "ethernet"
    return "other"


def wireless_interfaces():
    """Interface names that are currently wireless, from iw/nmcli/sysfs (cached 60 s)."""
    key = target() or ""
    hit = _WIFI_CACHE.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    names = set()
    if not target():
        names |= {os.path.basename(os.path.dirname(os.path.dirname(p)))
                  for p in glob.glob("/sys/class/net/*/wireless")}
    rc, txt = _run(["iw", "dev"], 10)
    if rc == 0:
        names |= set(re.findall(r"^\s*Interface\s+(\S+)", txt, re.M))
    if not names:
        rc, txt = _run(["nmcli", "-t", "-f", "DEVICE,TYPE", "dev", "status"], 10)
        if rc == 0:
            for ln in txt.splitlines():
                f = ln.split(":")
                if len(f) >= 2 and f[1].strip().lower() in ("wifi", "802-11-wireless"):
                    names.add(f[0].strip())
    _WIFI_CACHE[key] = (time.time(), names)
    return names


def parse_ip_addr_json(txt):
    """`ip -j addr` -> [{name, mac, state, mtu, kind, addrs:[...], subnets:[...]}]. Pure."""
    try:
        data = json.loads(txt)
    except (TypeError, ValueError):
        return []
    out = []
    for item in data if isinstance(data, list) else []:
        name = item.get("ifname") or "?"
        addrs, nets = [], []
        for a in item.get("addr_info") or []:
            local, plen = a.get("local"), a.get("prefixlen")
            if not local:
                continue
            row = {"family": a.get("family", ""), "address": local, "prefixlen": plen,
                   "scope": a.get("scope", "")}
            addrs.append(row)
            if isinstance(plen, int):
                try:
                    net = ipaddress.ip_network(f"{local}/{plen}", strict=False)
                    nets.append(str(net))
                except ValueError:
                    pass
        out.append({"name": name, "mac": (item.get("address") or "").lower(),
                    "state": item.get("operstate", ""), "mtu": item.get("mtu"),
                    "link_type": item.get("link_type", ""), "kind": _if_kind(name, item.get("link_type")),
                    "addrs": addrs, "subnets": sorted(set(nets))})
    return out


def network_interfaces():
    """Live interface details, cached for a minute; `ip -j addr`, with an `ip -o addr` fallback."""
    key = target() or ""
    hit = _LINK_CACHE.get(key)
    if hit and time.time() - hit[0] < 60:
        return hit[1]
    rc, txt = _run(["ip", "-j", "addr"], 10)
    rows = parse_ip_addr_json(txt) if rc == 0 else []
    if not rows:
        rc, txt = _run(["ip", "-o", "addr", "show"], 10)
        if rc == 0:
            by = {}
            for ln in txt.splitlines():
                m = re.match(r"\d+:\s+(\S+)\s+(inet6?)\s+([0-9a-fA-F:.]+)/(\d+)", ln)
                if not m:
                    continue
                name, fam, addr, plen = m.group(1), m.group(2), m.group(3), int(m.group(4))
                r = by.setdefault(name, {"name": name, "mac": "", "state": "", "mtu": None, "link_type": "",
                                         "kind": _if_kind(name), "addrs": [], "subnets": []})
                r["addrs"].append({"family": "inet6" if fam == "inet6" else "inet", "address": addr,
                                   "prefixlen": plen, "scope": ""})
                try:
                    r["subnets"].append(str(ipaddress.ip_network(f"{addr}/{plen}", strict=False)))
                except ValueError:
                    pass
            rows = list(by.values())
    wl = wireless_interfaces()
    for r in rows:
        if r["name"] in wl:
            r["kind"] = "wlan"
        r["subnets"] = sorted(set(r["subnets"]))
    _LINK_CACHE[key] = (time.time(), rows)
    return rows


def parse_routes(txt, family="ipv4"):
    """`ip -j route` (JSON) or `ip route` text -> [{gateway, dev, family, metric, protocol, src}]. Pure."""
    rows = []
    try:
        data = json.loads(txt)
    except (TypeError, ValueError):
        data = None
    if isinstance(data, list):
        for r in data:
            rows.append({"gateway": r.get("gateway") or "", "dev": r.get("dev") or "",
                         "family": family, "metric": r.get("metric"), "protocol": r.get("protocol") or "",
                         "src": r.get("prefsrc") or ""})
    elif isinstance(txt, str):
        for ln in txt.splitlines():
            if not ln.strip().startswith("default"):
                continue
            gw = re.search(r"\bvia\s+(\S+)", ln)
            dev = re.search(r"\bdev\s+(\S+)", ln)
            metric = re.search(r"\bmetric\s+(\d+)", ln)
            proto = re.search(r"\bproto\s+(\S+)", ln)
            rows.append({"gateway": gw.group(1) if gw else "", "dev": dev.group(1) if dev else "",
                         "family": family, "metric": int(metric.group(1)) if metric else None,
                         "protocol": proto.group(1) if proto else "", "src": ""})
    uniq = {}
    for r in rows:
        uniq[(r["gateway"], r["dev"], r["family"])] = r
    return list(uniq.values())


def default_routes():
    """Every default route, IPv4 and IPv6, newest preferred first."""
    out = []
    for family, argv in (("ipv4", ["ip", "-j", "route", "show", "default"]),
                         ("ipv6", ["ip", "-j", "-6", "route", "show", "default"])):
        rc, txt = _run(argv, 10)
        if rc == 0:
            out += parse_routes(txt, family)
    out.sort(key=lambda r: (r.get("metric") is None, r.get("metric") or 0))
    return out


def parse_neigh_json(txt):
    """`ip -j neigh` -> [{ip, mac, dev, state, family}], real entries only. Pure."""
    try:
        data = json.loads(txt)
    except (TypeError, ValueError):
        return []
    out = []
    for r in data if isinstance(data, list) else []:
        ip = r.get("dst") or ""
        mac = (r.get("lladdr") or "").lower()
        if not ip or not mac:
            continue
        state = r.get("state") or []
        if isinstance(state, list):
            state = ",".join(state)
        if any(x in state.upper() for x in ("FAILED", "INCOMPLETE")):
            continue
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        if a.is_multicast or a.is_unspecified:
            continue
        out.append({"ip": ip.split("%")[0], "mac": mac, "dev": r.get("dev") or "",
                    "state": state, "family": "inet6" if a.version == 6 else "inet"})
    return out


def parse_neigh_text(txt):
    """`ip neigh` text -> the same rows as parse_neigh_json. Pure."""
    out = []
    for ln in txt.splitlines():
        f = ln.split()
        if len(f) < 5 or "lladdr" not in f:
            continue
        ip, mac = f[0], f[f.index("lladdr") + 1]
        dev = f[f.index("dev") + 1] if "dev" in f and f.index("dev") + 1 < len(f) else ""
        state = f[-1]
        if state.upper() in ("FAILED", "INCOMPLETE"):
            continue
        try:
            a = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            continue
        out.append({"ip": ip.split("%")[0], "mac": mac.lower(), "dev": dev, "state": state,
                    "family": "inet6" if a.version == 6 else "inet"})
    return out


def neighbors():
    """The kernel's current neighbour table (ARP/NDP), real entries only."""
    rc, txt = _run(["ip", "-j", "neigh", "show"], 10)
    rows = parse_neigh_json(txt) if rc == 0 else []
    if not rows:
        rc, txt = _run(["ip", "neigh", "show"], 10)
        rows = parse_neigh_text(txt) if rc == 0 else []
    if not rows:
        rc, txt = _run(["arp", "-an"], 10)
        if rc == 0:
            for ln in txt.splitlines():
                m = re.search(r"\(([^)]+)\)\s+at\s+([0-9a-fA-F:]{17})", ln)
                if m:
                    rows.append({"ip": m.group(1), "mac": m.group(2).lower(), "dev": "",
                                 "state": "REACHABLE", "family": "inet"})
    uniq = {}
    for r in rows:
        uniq[(r["ip"], r["mac"])] = r
    return list(uniq.values())


def dns_servers():
    """Nameservers in /etc/resolv.conf, in order, without comments or duplicates."""
    out = []
    for ln in (_read("/etc/resolv.conf") or "").splitlines():
        m = re.match(r"\s*nameserver\s+(\S+)", ln)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def parse_iw_link(txt, iface=""):
    """`iw dev <if> link` -> {iface, connected, ssid, bssid, freq, signal, tx_bitrate}. Pure."""
    row = {"iface": iface, "connected": False, "ssid": "", "bssid": "", "freq": "", "signal": "",
           "tx_bitrate": "", "security": ""}
    m = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", txt or "")
    if not m:
        return row
    row["connected"], row["bssid"] = True, m.group(1).lower()
    for key, pat in (("ssid", r"^\s*SSID:\s*(.+?)\s*$"), ("freq", r"^\s*freq:\s*(\S+)"),
                     ("signal", r"^\s*signal:\s*(\S+)"), ("tx_bitrate", r"^\s*tx bitrate:\s*(.+?)\s*$")):
        m = re.search(pat, txt or "", re.M)
        if m:
            row[key] = _clean_text(m.group(1), 128)
    return row


def parse_nmcli_wifi(txt):
    """`nmcli -t -f IN-USE,SSID,BSSID,SECURITY,SIGNAL dev wifi list` -> rows. Pure.

    nmcli escapes the colons inside a BSSID as \\:; splitting on the first colon would turn one BSSID
    into five fields, so the escaped separators are protected before the split.
    """
    def parts(line):
        # nmcli -t escapes ':' and '\\' with a backslash. Walk it: a backslash takes the next character
        # literally, so an SSID ending in a backslash ("my\\\\:AA\\:...") does not swallow the separator.
        out, cur, esc = [], [], False
        for ch in line:
            if esc:
                cur.append(ch)
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == ":":
                out.append("".join(cur))
                cur = []
            else:
                cur.append(ch)
        out.append("".join(cur))
        return out

    out = []
    for ln in (txt or "").splitlines():
        f = parts(ln)
        if len(f) < 4:
            continue
        if len(f) >= 5 and f[0].strip() in ("", "*", "yes", "no"):
            in_use, ssid, bssid, security, signal = f[0].strip(), f[1], f[2], f[3], f[4]
        else:
            in_use, ssid, bssid, security, signal = "", f[0], f[1], f[2], f[3]
        if not bssid:
            continue
        out.append({"in_use": in_use == "*" or in_use.lower() == "yes",
                    "ssid": _clean_text(ssid, 64) or "<hidden>", "bssid": _clean_text(bssid, 32).lower(),
                    "security": _clean_text(security, 80), "signal": _clean_text(signal, 20)})
    return out


def wifi_link():
    """The current Wi-Fi association(s), from iw first, enriched with nmcli's security string."""
    rows = []
    for ifn in sorted(wireless_interfaces()):
        rc, txt = _run(["iw", "dev", ifn, "link"], 10)
        if rc == 0:
            row = parse_iw_link(txt, ifn)
            if row["connected"]:
                rows.append(row)
    if rows:
        rc, txt = _run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list"], 15)
        by_bssid = {r["bssid"]: r for r in parse_nmcli_wifi(txt) if rc == 0}
        for row in rows:
            match = by_bssid.get(row["bssid"])
            if match:
                row["security"] = match.get("security", "")
                row["signal"] = row.get("signal") or match.get("signal", "")
        return rows
    rc, txt = _run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list"], 15)
    for r in parse_nmcli_wifi(txt) if rc == 0 else []:
        if r["in_use"]:
            rows.append({"iface": "", "connected": True, "ssid": r["ssid"], "bssid": r["bssid"],
                         "freq": "", "signal": r["signal"], "tx_bitrate": "", "security": r["security"]})
    return rows


def wifi_scan():
    """Nearby Wi-Fi BSSIDs from nmcli (no root, no monitor mode). [] with no NetworkManager."""
    rc, txt = _run(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi", "list"], 20)
    return parse_nmcli_wifi(txt) if rc == 0 else []


def ping_host(host, timeout=1, dev=""):
    """(reachable, rtt text) with a one-packet ICMP ping; never a scan. A link-local IPv6 target needs its
    interface zone, or the kernel has no route for it."""
    if not _is_ip(host):
        return False, ""
    ip = ipaddress.ip_address(host)
    fam = "-6" if ip.version == 6 else "-4"
    target = f"{host}%{dev}" if ip.version == 6 and ip.is_link_local and dev else host
    rc, txt = _run(["ping", fam, "-c", "1", "-W", str(max(1, int(timeout))), target],
                   max(3, int(timeout) + 3))
    m = re.search(r"time[=<]([\d.]+)\s*ms", txt)
    return rc == 0, (m.group(1) + " ms" if m else "")


def tcp_probe(host, ports, timeout=0.7):
    """[open ports] via a plain TCP connect; bounded, threaded, and never privileged."""
    ports = [int(p) for p in (ports or []) if str(p).isdigit() and 0 < int(p) < 65536][:64]
    if not ports or not _is_ip(host):
        return []
    if target():
        # The defended box is remote: probe FROM it. A socket opened here would test this machine's LAN,
        # where the same gateway address may be a different router. host is a validated IP, ports are ints.
        h = shlex.quote(str(ipaddress.ip_address(host)))
        script = (f"h={h}; for p in {' '.join(map(str, ports))}; do ( if command -v nc >/dev/null 2>&1; then "
                  "nc -z -w1 \"$h\" \"$p\" >/dev/null 2>&1; else timeout 1 bash -c \"exec 3<>/dev/tcp/$h/$p\" "
                  ">/dev/null 2>&1; fi && echo \"open $p\" ) & done; wait")
        rc, txt = _run(["sh", "-c", script], 20)
        return sorted({int(m) for m in re.findall(r"^open (\d+)$", txt, re.M) if int(m) in ports})
    fam = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET

    def one(port):
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(max(0.15, float(timeout)))
        try:
            return port if s.connect_ex((host, port)) == 0 else None
        except OSError:
            return None
        finally:
            s.close()

    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(ports))) as ex:
            return sorted({p for p in ex.map(one, ports) if p})
    except Exception:  # noqa: BLE001 - a probe failure is not an answer about the host
        return []


def _private_net(text):
    """A CIDR the defender may touch: private/link-local/loopback, never public."""
    try:
        net = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        return None
    if net.is_global or net.prefixlen == 0 or net.network_address.is_unspecified or net.is_multicast \
            or net.is_unspecified or net.is_reserved:
        return None
    return net


def subnet_targets(target=""):
    """CIDRs to discover: the explicit private target, else this host's LAN/WLAN subnets."""
    if target:
        return [str(_private_net(x)) for x in str(target).replace(",", " ").split() if _private_net(x)]
    out = []
    for r in network_interfaces():
        if r.get("kind") not in ("ethernet", "wlan", "other") or r.get("kind") == "loopback":
            continue
        for a in r.get("addrs") or []:
            if a.get("family") != "inet" or not a.get("prefixlen"):
                continue
            try:
                net = ipaddress.ip_network(f"{a['address']}/{a['prefixlen']}", strict=False)
            except ValueError:
                continue
            if net.prefixlen <= 30 and (net.is_private or net.is_link_local):
                out.append(str(net))
    return sorted(set(out))


def discover_hosts(target=""):
    """(hosts, cidrs) from `nmap -sn`; raises ValueError for a public or oversized target."""
    cidrs = subnet_targets(target)
    if not cidrs:
        raise ValueError("no private subnet found (give a CIDR such as 192.168.1.0/24)")
    total = 0
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        total += net.num_addresses
    if total > 4096:
        raise ValueError(f"refused: {total} addresses is too large for one discovery; narrow the CIDR "
                         "(at most 4096 addresses)")
    rc, txt = _run(["nmap", "-sn", "-n", "--max-retries", "1", "--host-timeout", "12s", *cidrs], 300)
    if rc == 127:
        raise ValueError(txt)
    hosts = []
    for ln in txt.splitlines():
        m = re.match(r"Nmap scan report for (?:(\S+) \()?([0-9a-fA-F:.]+)\)?\s*$", ln)
        if m:
            hosts.append({"ip": m.group(2), "name": m.group(1) or ""})
    return hosts, cidrs


def discover(target=""):
    """A ping-sweep inventory of this host's own subnets, or a private CIDR the user named."""
    try:
        hosts, cidrs = discover_hosts(target)
    except ValueError as e:
        return f"refused: {e}"
    lines = [f"SUBNET DISCOVERY ({'nmap -sn'}) on {', '.join(cidrs)}: {len(hosts)} host(s) answered"]
    for h in sorted(hosts, key=lambda x: ipaddress.ip_address(x["ip"])):
        lines.append(f"  {h['ip']:<40} {h['name'] or ''}".rstrip())
    if not hosts:
        lines.append("  no host answered (the network may block ICMP; the neighbour table still shows ARP peers)")
    return "\n".join(lines)


def gateway_open_ports(host, ports=None, timeout=0.7):
    """{port: note} for open TCP admin ports on one gateway, all connect probes only."""
    return {p: _GATEWAY_PORTS.get(p, ("info", "open")) for p in tcp_probe(host, ports or sorted(_GATEWAY_PORTS), timeout)}


def gateway_check(gateways=None, timeout=1):
    """Read-only-ish probe of the gateways: reachability, MAC, and admin ports. Public refused."""
    gates = [g for g in (gateways or []) if _is_ip(g)]
    if not gates:
        gates = sorted({r["gateway"] for r in default_routes() if r.get("gateway")})
    if not gates:
        return "no default gateway found (ip route show default returned nothing)"
    neigh = {r["ip"]: r for r in neighbors()}
    own = {str(a) for a in own_addrs()}
    route_dev = {r["gateway"]: r.get("dev", "") for r in default_routes() if r.get("gateway")}
    lines = [f"GATEWAY MONITOR on {hostname()}"]
    for g in gates:
        try:
            a = ipaddress.ip_address(g)
        except ValueError:
            lines.append(f"  {g}: not an IP address")
            continue
        if a.is_global:
            lines.append(f"  {g}: refused (public address; a gateway on your LAN is private)")
            continue
        up, rtt = ping_host(g, timeout, dev=route_dev.get(g, ""))
        mac = (neigh.get(g) or {}).get("mac", "")
        if a.is_link_local and not up and mac:
            up = True   # a link-local gateway often does not answer ICMP through the zone; ARP/NDP is proof
        ports = {} if a.is_link_local else gateway_open_ports(g, timeout=timeout)
        lines.append(f"  {g}: {'reachable' if up else 'NO ICMP REPLY'}" + (f" ({rtt})" if rtt else "")
                     + (f"  MAC {mac}" if mac else "  (no ARP entry)"))
        if g in own:
            lines.append("    this is one of this host's own addresses, not a remote gateway")
        if not ports:
            lines.append("    no common admin TCP port answered")
        for p, (sev, note) in sorted(ports.items()):
            lines.append(f"    [{sev.upper():6}] tcp/{p}: {note}")
    lines.append("  A gateway is not a host to attack: this list is for the router's own admin page and "
                 "for deciding whether remote management (TR-069/Telnet) should be off.")
    return "\n".join(lines)


def parse_dhcp_fields(txt):
    """tshark bootp fields -> [{ip, mac, type}]. Fields: ip.src, eth.src, bootp.option.dhcp. Pure."""
    out = []
    for ln in (txt or "").splitlines():
        f = ln.split("\t")
        if len(f) < 3 or not f[0]:
            continue
        typ = f[2].strip()
        # 2 = OFFER, 5 = ACK: only servers that hand out addresses matter here.
        if typ not in ("2", "5"):
            continue
        out.append({"ip": f[0].strip(), "mac": (f[1] or "").strip().lower(), "type": "OFFER" if typ == "2" else "ACK"})
    return out


def parse_tcpdump_dhcp(txt):
    """`tcpdump -v -e` DHCP output -> [{ip, mac, type}] for every OFFER/ACK. A packet is a header line naming
    `<ip>.67 > <ip>.68` followed by indented option lines; the server is its Server-ID option, else the source.
    Pure."""
    out, cur, link_mac = [], None, ""

    def flush():
        if cur and cur.get("type") in ("OFFER", "ACK"):
            # the SENDER, not the Server-ID option: that option is written by whoever sends the offer, so a rogue
            # claiming the gateway's address read as the gateway (QAQC 2026-11-19); the claim rides beside it
            out.append({"ip": cur["src"], "server_id": cur.get("server", ""), "mac": cur.get("mac", ""),
                        "type": cur["type"]})
    for ln in (txt or "").splitlines():
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\.(?:67|bootps)\s+>\s+\S+\.(?:68|bootpc):", ln)
        if m:
            flush()
            mac = re.search(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", ln, re.I)
            cur = {"src": m.group(1), "mac": mac.group(1).lower() if mac else link_mac}
            continue
        if re.match(r"^\S", ln):
            # a link-level header line (-e) opens the next packet; its MAC is the sender's
            flush()
            cur = None
            mac = re.search(r"\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b", ln, re.I)
            link_mac = mac.group(1).lower() if mac else ""
            continue
        if cur is None:
            continue
        t = re.search(r"DHCP-Message[^:]*:\s*(Offer|ACK)\b", ln, re.I)
        if t:
            cur["type"] = t.group(1).upper()
        sid = re.search(r"Server-ID[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})", ln)
        if sid:
            cur["server"] = sid.group(1)
    flush()
    return out


def dhcp_servers(seconds=4):
    """(servers, how) seen answering DHCP in a short passive capture; (None, why) without capture rights."""
    seconds = max(2, min(30, int(seconds or 4)))
    for typ, field in (("dhcp", "dhcp.option.dhcp"), ("bootp", "bootp.option.dhcp")):
        argv = ["tshark", "-i", "any", "-n", "-q", "-l", "-a", f"duration:{seconds}", "-c", "300",
                "-Y", typ, "-T", "fields", "-E", "separator=\t", "-e", "ip.src", "-e", "eth.src", "-e", field]
        rc, txt = _run(argv, seconds + 15)
        rows = parse_dhcp_fields(txt)
        if rows:
            return rows, "tshark"
        if rc == 0 and "Capturing" in txt:
            return [], "tshark"
    # -v prints the DHCP options (Server-ID, message type) on continuation lines; -e the source MAC.
    # `timeout` exits 124 when the window ends before 100 packets, which is the normal case, not a failure.
    rc, txt = _run(["timeout", str(seconds), "sudo", "-n", "tcpdump", "-i", "any", "-nn", "-l", "-v", "-e",
                    "-c", "100", "udp", "and", "(port", "67", "or", "port", "68)"], seconds + 12)
    if rc in (0, 124) and ("BOOTP" in txt or "DHCP" in txt or "listening on" in txt):
        return parse_tcpdump_dhcp(txt), "tcpdump"
    return None, ((txt.strip().splitlines() or ["no capture rights"])[-1][:180] if txt else "no capture rights")


def dhcp_report(seconds=4):
    servers, how = dhcp_servers(seconds)
    if servers is None:
        return f"DHCP WATCH: could not capture ({how}). Add the user to the wireshark group or run tcpdump as root."
    if not servers:
        return f"DHCP WATCH ({how}, {seconds}s): no OFFER/ACK seen. A rogue server only shows up when a client asks."
    gates = {r["gateway"] for r in default_routes() if r.get("gateway")}
    lines = [f"DHCP SERVERS seen answering in {seconds}s ({how}):"]
    for s in servers:
        ok = s["ip"] in gates
        lines.append(f"  {s['ip']:<20} {s['mac'] or '?':<18} {s['type']:<5} "
                     + ("known gateway" if ok else "NOT the default gateway: verify this server"))
    return "\n".join(lines)


ACTIONS = {"exposure": exposure, "logins": logins, "services": services, "audit": audit,
           "onion": onion, "processes": processes, "connections": connections, "settings": settings,
           "firewall": firewall_detail, "discover": discover, "gateway": gateway_check, "dhcp": dhcp_report,
           "persistence": persistence}
