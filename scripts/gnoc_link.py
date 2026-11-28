#!/usr/bin/env python3
"""gnoc_link.py - link another Linux machine on the same LAN so gnoc chat can see and drive it.

    gnoc link                      the guided setup: what to paste on the other machine, then what to run here
    gnoc link add <name> <user@ip> register it (tests ssh, probes its desktop, saves .claude/state/orch/links.json)
    gnoc link test <name>          re-probe: ssh, desktop session, screenshot tool, uinput access, python3
    gnoc link list | remove <name>

How it works: one dedicated ssh key (~/.ssh/gnoc_link_ed25519) that the other machine accepts ONLY from this
LAN's subnet (from="..." in its authorized_keys). Mouse and keyboard there go through the same stdlib uinput
script as here (gnoc_input.py, piped over ssh, nothing installed); a udev rule gives the logged-in desktop user
access to /dev/uinput. Unlink = delete the gnoc-link line from the other machine's ~/.ssh/authorized_keys.
"""
import ipaddress
import json
import os
import platform
import re
import subprocess
import sys

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _now_iso as _now

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KEY = os.path.expanduser("~/.ssh/gnoc_link_ed25519")
KNOWN = os.path.expanduser("~/.ssh/gnoc_known_hosts")
STORE = os.path.join(WS, ".claude/state/orch/links.json")
NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
RESERVED = {"local", "desktop", "phone", "split"}   # this machine, and the names of model hosts
# a link record is re-checked on every load: its fields go into an ssh command line and a remote shell script, and
# a record edited to user="-oProxyCommand=..." ran that command HERE (QAQC 2026-11-19)
_USER = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
_HOST = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[?[0-9A-Fa-f:.]{2,45}\]?)$")
_WAYLAND = re.compile(r"^(?:wayland-\d{1,3})?$")
_DISPLAY = re.compile(r"^(?::\d{1,3}(?:\.\d)?)?$")

# run on the linked machine: where its desktop session lives and what can screenshot it. DISPLAY and XAUTHORITY come
# from the user's own desktop process: GDM keeps the auth file under /run/user/<uid>/gdm and often uses :1, and SDDM
# uses /tmp/xauth_*, so ":0" + ~/.Xauthority failed on common setups
PROBE = r'''
u=$(id -u); rt=/run/user/$u
wl=$(ls $rt 2>/dev/null | grep -E '^wayland-[0-9]+$' | head -1)
st=x11; [ -n "$wl" ] && st=wayland
de=$( (ps -u "$u" -o comm= | grep -E -m1 'kwin_wayland|kwin_x11|gnome-shell|sway|Hyprland|xfwm4|cinnamon|mate-session|lxqt-session|weston|labwc|xfce4-session|plasmashell') 2>/dev/null)
dp=""; xa=""
if [ -n "$de" ]; then
  pid=$(pgrep -u "$u" -n -x "$de" 2>/dev/null)
  if [ -n "$pid" ] && [ -r /proc/$pid/environ ]; then
    dp=$(tr '\0' '\n' < /proc/$pid/environ | sed -n 's/^DISPLAY=//p' | head -1)
    xa=$(tr '\0' '\n' < /proc/$pid/environ | sed -n 's/^XAUTHORITY=//p' | head -1)
  fi
fi
shot=""
for t in spectacle grim gnome-screenshot import scrot; do command -v $t >/dev/null 2>&1 && shot="$shot $t"; done
ui=no; [ -w /dev/uinput ] && ui=yes
py=$(command -v python3 || true)
printf '{"user":"%s","host":"%s","uid":"%s","session":"%s","wayland":"%s","desktop":"%s","shot":"%s","uinput":"%s","python3":"%s","display":"%s","xauth":"%s"}\n' \
  "$(whoami)" "$(hostname)" "$u" "$st" "$wl" "$de" "${shot# }" "$ui" "$py" "$dp" "$xa"
'''




def valid(link):
    """'' when a link record is safe to put on an ssh command line and into a remote script, else why not."""
    if not isinstance(link, dict):
        return "not a record"
    if not _USER.match(str(link.get("user", ""))):
        return f"bad user {link.get('user')!r}"
    if not _HOST.match(str(link.get("host", ""))) or str(link.get("host", "")).startswith("-"):
        return f"bad host {link.get('host')!r}"
    try:
        if not 1 <= int(link.get("port", 22)) <= 65535:
            return "bad port"
    except (TypeError, ValueError):
        return "bad port"
    p = link.get("probe") or {}
    if not _WAYLAND.match(str(p.get("wayland") or "")) or not _DISPLAY.match(str(p.get("display") or "")):
        return "bad probe (wayland/display)"
    xa = str(p.get("xauth") or "")
    if xa and not re.match(r"^/[\w./-]{1,200}$", xa):
        return "bad probe (xauth)"
    return ""


def load():
    """The linked machines whose records pass valid(); an invalid one is left out, never run."""
    try:
        with open(STORE) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    return {n: l for n, l in (d.items() if isinstance(d, dict) else ()) if NAME.match(n) and not valid(l)}


def _save(d):
    os.makedirs(os.path.dirname(STORE), exist_ok=True)
    tmp = f"{STORE}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, STORE)


def ensure_key():
    if not os.path.isfile(KEY):
        os.makedirs(os.path.dirname(KEY), mode=0o700, exist_ok=True)   # a machine that never used ssh has no ~/.ssh
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "gnoc-link@" + platform.node(),
                        "-f", KEY], check=True, capture_output=True)
    with open(KEY + ".pub") as f:
        return f.read().strip()


_SKIP_DEV = re.compile(r"^(lo|wg|tun|tap|docker|br-|veth|virbr|podman|tailscale|zt|proton|nordlynx|utun|cni|flannel)")


def lan():
    """(this machine's LAN ip, its subnet): the interface the DEFAULT ROUTE leaves by, never a VPN tunnel or a
    link-local address (the first private interface won before, so a 169.254 address or tailscale0 could become
    the only network allowed to use the key)."""
    try:
        route = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True,
                               timeout=5).stdout
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None, None
    m = re.search(r"\bdev\s+(\S+).*?\bsrc\s+(\S+)", route)
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 4:
            continue
        dev, cidr = parts[1], parts[3]
        if _SKIP_DEV.match(dev) or (m and dev != m.group(1)):
            continue
        net = ipaddress.ip_interface(cidr)
        if net.ip.is_private and not net.ip.is_link_local and not net.ip.is_loopback:
            return str(net.ip), str(net.network)
    return None, None


def setup_block():
    """The text the user pastes into a terminal on the other machine. Refused without a LAN subnet: the key used to
    be trusted from ANY address then, with the firewall opened to the world."""
    pub = ensure_key()
    _, subnet = lan()
    if not subnet:
        raise RuntimeError("could not tell which local network this machine is on (no private IPv4 address on the "
                           "default-route interface). Connect to the same Wi-Fi/LAN as the other machine and run "
                           "gnoc link again.")
    # restrict: no port/agent/X11 forwarding and no pty; from=: only this LAN may use the key
    opt = f'restrict,from="{subnet}" '
    comment = pub.split()[-1]
    return f"""bash -s <<'GNOC_LINK'
set -e
echo "[gnoc] installing ssh server + python3 (asks for your sudo password once)"
if command -v apt-get >/dev/null; then sudo apt-get update -qq && sudo apt-get install -y -qq openssh-server python3
elif command -v dnf >/dev/null; then sudo dnf install -y -q openssh-server python3
elif command -v pacman >/dev/null; then sudo pacman -S --needed --noconfirm openssh python
elif command -v zypper >/dev/null; then sudo zypper -n -q install openssh python3
fi
sudo systemctl enable --now ssh 2>/dev/null || sudo systemctl enable --now sshd
echo "[gnoc] trusting this one key, only from {subnet}"
mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
# replace this controller's earlier key (same comment) with the current one; other keys are untouched
grep -v ' {comment}$' ~/.ssh/authorized_keys > ~/.ssh/.gnoc-ak || true
echo '{opt}{pub}' >> ~/.ssh/.gnoc-ak && chmod 600 ~/.ssh/.gnoc-ak && mv ~/.ssh/.gnoc-ak ~/.ssh/authorized_keys
echo "[gnoc] mouse/keyboard access for the logged-in desktop user (/dev/uinput)"
echo 'KERNEL=="uinput", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uinput"' | sudo tee /etc/udev/rules.d/60-gnoc-uinput.rules >/dev/null
echo uinput | sudo tee /etc/modules-load.d/gnoc-uinput.conf >/dev/null
sudo modprobe uinput; sudo udevadm control --reload; sudo udevadm trigger --name-match=uinput || true
if command -v ufw >/dev/null && sudo ufw status | grep -q active; then sudo ufw allow from {subnet} to any port 22 proto tcp; fi
echo
ip=$(python3 -c 'import ipaddress,re,subprocess,sys
net=ipaddress.ip_network(sys.argv[1])
try:
    ips=subprocess.run(["hostname","-I"],capture_output=True,text=True).stdout.split()
except OSError:
    ips=[]
if not ips:
    out=subprocess.run(["ip","-4","-o","addr"],capture_output=True,text=True).stdout
    ips=re.findall(r"inet ([0-9.]+)/",out)
hit=[a for a in ips if ":" not in a and ipaddress.ip_address(a) in net]
print((hit or ips or ["?"])[0])' '{subnet}')
echo "GNOC-LINK $(whoami)@$ip"
echo "[gnoc] done. Copy the GNOC-LINK line above back to gnoc."
GNOC_LINK"""


def guide():
    ip, subnet = lan()
    return f"""LINK ANOTHER LINUX MACHINE (same Wi-Fi/LAN)

This machine: {ip or '?'} on {subnet or '?'}. The other machine must be on the same network.

1) On the OTHER machine, log in to its desktop, open a terminal and paste this whole block
   (it asks for that machine's sudo password once):

{setup_block()}

2) It ends by printing a line like   GNOC-LINK alice@10.0.0.57
   Back HERE, register it with a short name:

     gnoc link add <name> alice@10.0.0.57

3) That tests the connection and checks the desktop. If it lists anything missing it prints the fix.
   Then gnoc chat can use it: the bot asks you before it touches that machine's mouse/keyboard/screen,
   and control switches off again when the task ends.

What the block changes there: it installs and starts the ssh server (with that machine's default settings,
which on most distributions allow PASSWORD logins from your network: to turn those off, add
"PasswordAuthentication no" to /etc/ssh/sshd_config.d/50-gnoc.conf there and restart ssh), adds this one key
(usable only from {subnet or '?'}, no forwarding), a udev rule for /dev/uinput, and a firewall rule for port 22
when ufw is on. `gnoc link remove <name>` prints the block that undoes all of it.
Note: a machine you reboot into the login screen has no desktop session yet; log in first."""


def unlink_block():
    """What to paste on the linked machine to undo everything the setup block did there."""
    pub = ensure_key()
    comment = pub.split()[-1]
    _, subnet = lan()
    return f"""bash -s <<'GNOC_UNLINK'
grep -v ' {comment}$' ~/.ssh/authorized_keys > ~/.ssh/.gnoc-ak; mv ~/.ssh/.gnoc-ak ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
sudo rm -f /etc/udev/rules.d/60-gnoc-uinput.rules /etc/modules-load.d/gnoc-uinput.conf
sudo udevadm control --reload || true
if command -v ufw >/dev/null; then sudo ufw delete allow from {subnet or 'any'} to any port 22 proto tcp || true; fi
echo "[gnoc] unlinked. The ssh server is still installed; to stop it:  sudo systemctl disable --now ssh"
GNOC_UNLINK"""


def ssh_base(link):
    why = valid(link)
    if why:
        raise ValueError(f"refused: link record is not valid ({why}); gnoc link remove it and add it again")
    return ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={KNOWN}",
            "-p", str(int(link.get("port", 22))), "--", f"{link['user']}@{link['host']}"]


def run(link, remote_cmd, stdin=None, timeout=60, binary=False):
    try:
        r = subprocess.run(ssh_base(link) + [remote_cmd], input=stdin, capture_output=True, timeout=timeout,
                           text=not binary)
    except subprocess.TimeoutExpired:
        return 124, (b"" if binary else ""), f"no answer in {timeout}s (is the machine on and on this network?)"
    return r.returncode, r.stdout, r.stderr


def ssh_hint(err):
    """What to do about an ssh failure, from its own words."""
    e = str(err or "")
    if "REMOTE HOST IDENTIFICATION HAS CHANGED" in e or "Host key verification failed" in e:
        return f"the machine's identity changed (reinstalled?): ssh-keygen -R <ip> -f {KNOWN}, then gnoc link test"
    if "Permission denied" in e:
        return "the key was not accepted: run the gnoc link setup block on that machine again"
    if "No route to host" in e or "timed out" in e or "no answer" in e or "Connection refused" in e:
        return ("cannot reach it: same network? is it on? its address may have changed (give it a fixed address in "
                "your router), then gnoc link add <name> <user@new-ip>")
    return "gnoc link test <name> checks the connection and the desktop again"


def probe(link):
    code, out, err = run(link, "bash -s", stdin=PROBE, timeout=30)
    if code:
        e = (err or out or f"ssh exit {code}").strip()[:400]
        return None, f"{e}\n  -> {ssh_hint(e)}"
    try:
        return json.loads(out.strip().splitlines()[-1]), ""
    except (ValueError, IndexError):
        return None, f"unexpected probe output: {out[:300]}"


def readiness(p):
    """[(ok, item, fix)] for a probe result."""
    rows = [(bool(p.get("python3")), "python3 (runs the input script)", "install python3 on it"),
            (p.get("uinput") == "yes", "mouse/keyboard (/dev/uinput writable)",
             "re-run the setup block, then log out and back in on that machine (the udev 'uaccess' tag applies "
             "to the logged-in desktop user)"),
            (bool(p.get("shot")), "screenshot tool",
             "KDE: spectacle; GNOME: gnome-screenshot; sway/Hyprland: grim; X11: imagemagick (import)"),
            (bool(p.get("desktop")), "a logged-in desktop session",
             "log in to the desktop on that machine")]
    if "gnome-shell" in (p.get("desktop") or "") and p.get("session") == "wayland" and "grim" not in p.get("shot", ""):
        rows.append((False, "GNOME Wayland screenshots",
                     "GNOME blocks silent screenshots on Wayland; pick 'GNOME on Xorg' at login, or the screen "
                     "cannot be read (mouse/keyboard still work)"))
    return rows


def add(name, target, port=22):
    if not NAME.match(name or "") or name in RESERVED:
        return False, ("name: lowercase letters, digits, dashes (e.g. office-pc, lab-box); "
                       f"not {', '.join(sorted(RESERVED))}")
    m = re.match(r"^(?:GNOC-LINK\s+)?([a-z_][\w.-]*)@([\w.:-]+)$", (target or "").strip())
    if not m:
        return False, "target looks like user@10.0.0.57 (paste the GNOC-LINK line)"
    ensure_key()
    link = {"user": m.group(1), "host": m.group(2), "port": int(port), "added": _now()}
    why = valid(link)
    if why:
        return False, f"refused: {why}"
    p, err = probe(link)
    if not p:
        return False, (f"cannot reach {target} over ssh: {err}\nCheck: same network, the setup block finished "
                       "without errors, and `ping " + link["host"] + "` works from here.")
    link["probe"], link["probed"] = p, _now()
    if valid(link):
        return False, f"the probe of {target} returned something unexpected: {valid(link)}"
    d = load()
    d[name] = link
    _save(d)
    return True, report(name, link)


def report(name, link):
    p = link.get("probe") or {}
    lines = [f"link {name}: {link['user']}@{link['host']}  ({p.get('host')}, {p.get('session')}, "
             f"{p.get('desktop') or 'no desktop seen'})"]
    for ok, item, fix in readiness(p):
        lines.append(f"  [{'x' if ok else ' '}] {item}" + ("" if ok else f"  -> {fix}"))
    return "\n".join(lines)


def test(name):
    d = load()
    if name not in d:
        return False, f"no link {name} (gnoc link list)"
    p, err = probe(d[name])
    if not p:
        return False, f"{name}: ssh failed: {err}"
    if valid(dict(d[name], probe=p)):
        return False, f"{name}: the probe returned something unexpected"
    d[name]["probe"], d[name]["probed"] = p, _now()
    _save(d)
    return True, report(name, d[name])


def remove(name):
    d = load()
    link = d.pop(name, None)
    if link is None:
        return f"no link {name}"
    _save(d)
    subprocess.run(["ssh-keygen", "-R", str(link.get("host")), "-f", KNOWN], capture_output=True)
    return (f"link {name} removed here. To revoke it on that machine too, paste this there:\n\n"
            + unlink_block())


def listing():
    d = load()
    if not d:
        return "no linked machines (gnoc link for the guided setup)"
    return "\n".join(f"{n}: {l['user']}@{l['host']}  {(l.get('probe') or {}).get('session', '?')} "
                     f"{(l.get('probe') or {}).get('desktop', '')}  probed {l.get('probed', '-')}"
                     for n, l in sorted(d.items()))


def main(argv):
    if not sys.platform.startswith("linux"):
        print("gnoc link connects Linux machines (ssh + uinput); this computer is not running Linux.")
        return 1
    try:
        return _main(argv)
    except (RuntimeError, subprocess.CalledProcessError, OSError) as e:
        print(f"gnoc link: {e}")
        return 1


def _main(argv):
    if not argv or argv[0] in ("guide", "help", "-h", "--help"):
        print(guide())
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "add" and len(rest) >= 2:
        ok, msg = add(rest[0], " ".join(rest[1:]).replace("GNOC-LINK", "").strip())
    elif cmd == "test" and rest:
        ok, msg = test(rest[0])
    elif cmd == "remove" and rest:
        ok, msg = True, remove(rest[0])
    elif cmd == "list":
        ok, msg = True, listing()
    elif cmd == "setup":
        ok, msg = True, setup_block()
    else:
        ok, msg = False, "usage: gnoc link [add <name> <user@ip> | test <name> | list | remove <name> | setup]"
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
