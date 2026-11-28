"""gnoc_defender.py - /mode defender: defend a machine and the LAN/WLAN around it, alert, triage, undo.

The user 2026-11-18: "make defender and or defend mode able to defend my entire subnet, lan, and wlan. I should be
able to enter gateway addresses to monitor for intrusion ... Implement an alert system thats professional and if
they bot determins there is an active intrusion there should be a triage" and "defend should have the bot auto
defend the computer".

The parts, and the fence on each one (the fences are code, not prompt):
  scope      the live interfaces, private subnets, default/entered gateway addresses, Wi-Fi association and
             DNS. The user can add gateways/subnets/Wi-Fi expectations; a public network is refused.
  sweep      every read check in gnoc_defend (sockets, containers, firewall, sshd, processes, connections,
             failed logins, kernel and file settings, a short packet look) plus the network checks (neighbour
             ARP changes, duplicate MACs, gateway MAC changes, rogue DHCP, Wi-Fi twins, DNS changes) folded
             into FINDINGS with stable ids. Runs here, or on a box the user named with /defender target over ssh.
  questions  what the scan cannot know: who must never be locked out, what the box is for, which subnets and
             gateways to monitor, the expected Wi-Fi SSID, which exposed ports are intended, whether active
             subnet discovery is allowed. Answers live in a per-host PROFILE and change both verdicts and policy.
  defend     every finding maps to a fix. AUTO-DEFENSE IS ON BY DEFAULT (2026-11-18) for four reversible
             HOST kinds: block one PUBLIC ip (nft timeout), pause one process (SIGSTOP), set an allowlisted
             sysctl at runtime, quarantine one LAN ARP/DHCP rogue on THIS host (nft timeout). Closing a port,
             a service, sshd_config or ufw policy is a PROPOSAL with the exact command.
  enforce    the next ring, from gnoc_enforce.py: gateway/AP over SSH (nft IP/MAC block, hostapd deauth,
             pfSense table) or controller API, and Linux endpoints over SSH (helper isolate/pause/kill/block).
             EVERY gateway/endpoint action is an ASK and runs only after the user's explicit yes; setup is
             guided by defend(action=setup).
  alerts     a persistent, deduplicated queue (open -> ack -> resolved/suppressed) with a professional
             renderer, severity, evidence, count, first/last seen and history.
  triage     deterministic scoring; when execution, C2, gateway impersonation, ARP spoof, rogue DHCP, an evil
             twin or a brute-force success is found, a numbered incident opens with P1..P4, confidence, assets,
             evidence, an SLA clock and a verify/contain/eradicate/recover/review playbook.
  watcher    lives and dies with the chat: re-sweeps every N seconds, alerts, opens triage and (when auto is
             on) applies the allowed kinds, journalled, without asking.
  undo       every applied action is in the journal with its inverse; /defender undo reverts one or all.

Anti-lockout is enforced twice: here (admin sources, the live ssh/remote-desktop peers, the default gateway and
this host are never blocked/quarantined; protected processes are never paused) and inside the root helper.
"""
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import signal
import threading
import time
import urllib.parse

import gnoc_defend as D
import gnoc_platform
import gnoc_alerts as A
import gnoc_triage as T
import gnoc_enforce as E

_WS = os.environ.get("GNOC_WS") or (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STATE = os.path.join(_WS, ".claude/state/defender")
HELPER = "/usr/local/sbin/gnoc-defender-helper"
HELPER_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gnoc-defender-helper")
KINDS = ("block_ip", "pause_pid", "sysctl", "quarantine_lan") + tuple(sorted(E.KINDS))
PERMISSION = {"block_ip": "allow_block_ips", "pause_pid": "allow_contain", "sysctl": "allow_sysctl",
              "quarantine_lan": "allow_quarantine", "gateway_block_ip": "allow_gateway_enforce",
              "gateway_block_mac": "allow_gateway_enforce", "gateway_deauth": "allow_gateway_enforce",
              "endpoint_isolate": "allow_endpoint_enforce", "endpoint_kill": "allow_endpoint_enforce",
              "endpoint_block_ip": "allow_endpoint_enforce"}
# Gateway and endpoint actions always ask, even if a permission is on: the operator explicitly asked to be
# consulted when the bot detects an intrusion.
ALWAYS_ASK = set(E.KINDS)
SEV_ORDER = {"crit": 0, "high": 1, "warn": 2, "info": 3}
BLOCK_TTL = 3600
NET_TTL = 1800
ALERT_SEVERITY = {"crit": "critical", "high": "high", "warn": "medium", "info": "info", "low": "low"}
MAX_FINDINGS = 800  # worst-first cap: a pathological host cannot flood the console, alerts or triage
# One auto-action key -> last time it was applied. The watcher and a manual sweep can see the same finding
# seconds apart; running `nft add element` twice or SIGSTOP twice is noise, not more defence.
_LAST_ACTION = {}
_LAST_LOCK = threading.Lock()
_STATE_LOCK = threading.RLock()   # profile/baseline/journal: a watcher pass and a chat sweep share them

# Terminal-safe, one-line text for anything that came from a process, a network peer or a remote command.
# A malicious process can put ANSI escapes, bidi overrides or newlines in argv; the defender must not let
# that rewrite the operator's terminal or forge a second finding line.
_CTRL_RE = re.compile("\x1b\\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
_ONE_LINE = re.compile(r"\s+")


def _safe_text(value, limit=600):
    s = _CTRL_RE.sub("", str(value or ""))
    return _ONE_LINE.sub(" ", s).strip()[:limit]


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value, limit=128):
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()][:limit]
    return []


def _as_bool(value, default=False):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on", "y"):
            return True
        if v in ("0", "false", "no", "off", "n"):
            return False
    return default


def _as_int(value, default=0, low=None, high=None):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if low is not None:
        n = max(low, n)
    if high is not None:
        n = min(high, n)
    return n


def _secure_state():
    """The profile names admin sources and enforcement targets; the alert/triage files hold evidence.
    Keep the directory and its files private to the operator, including on an existing checkout."""
    try:
        os.makedirs(STATE, mode=0o700, exist_ok=True)
        os.chmod(STATE, 0o700)
        for name in os.listdir(STATE):
            p = os.path.join(STATE, name)
            if os.path.isfile(p) and not os.path.islink(p):
                os.chmod(p, 0o600)
    except OSError:
        pass


def sync_stores():
    """Keep the alert and triage files inside the defender's state dir. A test (or a /defender target)
    that moves STATE must not leave the two queues pointed at the previous host's files."""
    A.STATE = STATE
    A.STORE = os.path.join(STATE, "alerts.jsonl")
    T.STATE = STATE
    T.STORE = os.path.join(STATE, "triage.jsonl")
    _secure_state()


PROTECT_FILE = "/etc/gnoc-defender/protect"
INSTALL_STEPS = 5


def _covers(entries, addr):
    """True when one of the IP/CIDR entries contains addr (itself an IP or a CIDR)."""
    try:
        want = ipaddress.ip_network(str(addr).strip(), strict=False)
    except ValueError:
        return False
    for e in entries:
        try:
            net = ipaddress.ip_network(str(e).strip(), strict=False)
        except ValueError:
            continue
        if net.version == want.version and want.subnet_of(net):
            return True
    return False


def install_check(profile=None, dest=None):
    """{step: (done, detail)} for the helper install, read from the target as it is NOW. Read-only, never
    prompts: `sudo -n` only, and only once the helper itself is in place (so a half-done install does not
    write a password failure to the auth log on every check). done is True, False, or None (not checkable
    yet because an earlier step is missing)."""
    out = {}
    try:
        with open(HELPER_SRC, "rb") as fh:
            src_hash = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        src_hash = ""
    with D.on_host(dest):
        rc, txt = D._run(["stat", "-c", "%u %a", HELPER], 10)
        rc2, h = D._run(["sha256sum", HELPER], 10)
        installed = rc == 0 and len(txt.split()) >= 2
        if not installed:
            out[1] = (False, f"{HELPER} is not there yet")
        else:
            uid, mode = txt.split()[:2]
            m = int(mode, 8) if re.fullmatch(r"[0-7]{3,4}", mode) else 0
            if uid != "0":
                out[1] = (False, f"{HELPER} is not owned by root (uid {uid})")
            elif m & 0o022:
                out[1] = (False, f"{HELPER} is writable by group/others (mode {mode})")
            elif not m & 0o100:
                out[1] = (False, f"{HELPER} is not executable (mode {mode})")
            elif src_hash and rc2 == 0 and h.split()[:1] != [src_hash]:
                out[1] = (False, f"{HELPER} is an OLDER copy than this gnoc's helper: run step 1 again")
            else:
                out[1] = (True, f"{HELPER} root-owned, mode {mode}, matches this gnoc's copy")
        if out[1][0]:
            rc, txt = D._run(["sudo", "-n", HELPER, "status"], 20)
            sudo_ok = rc == 0 and "helper v" in txt
            why = (txt.strip().splitlines() or [""])[0][:120]
        else:
            sudo_ok, why = None, ""
        ptxt = D._read(PROTECT_FILE)
    if sudo_ok:
        out[2] = (True, "the sudoers rule lets this user run the helper without a password")
        out[3] = (True, "sudo accepted the rule file")
    elif sudo_ok is None:
        out[2] = out[3] = (None, "checked once step 1 is done")
    else:
        out[2] = (False, f"sudo -n refused the helper ({why})")
        out[3] = (False, "not verified yet: sudo has to accept the rule from step 2")
    entries = [x for x in (ptxt or "").split() if not x.startswith("#")]
    valid = [x for x in entries if _covers([x], x)]
    admins = [str(a) for a in ((profile or {}).get("admin_sources") or []) if str(a).strip()]
    missing = [a for a in admins if not _covers(valid, a)]
    if ptxt is None:
        out[4] = (False, f"{PROTECT_FILE} does not exist yet")
    elif not valid:
        out[4] = (False, f"{PROTECT_FILE} has no valid IP or CIDR")
    elif missing:
        out[4] = (False, f"{PROTECT_FILE} does not cover your admin source(s): {', '.join(missing[:6])}")
    else:
        out[4] = (True, f"{PROTECT_FILE} protects {', '.join(valid[:6])}")
    out[5] = ((True, "the chat reaches the helper without a password") if sudo_ok else
              (None, "checked once step 1 is done") if sudo_ok is None else
              (False, "sudo -n " + HELPER + " status does not answer yet"))
    return out


def install_done(status):
    return bool(status) and all(status.get(i, (False,))[0] is True for i in range(1, INSTALL_STEPS + 1))


def install_hint(profile=None, status=None, dest=None):
    """The helper install, laid out like the reproduction steps of a report: one numbered step at a time, the
    command alone on its own line, what you should see after it, and - when `status` is given (install_check)
    - whether that step is ALREADY done on the target, so the operator only runs what is left. `profile` fills
    step 4 with the admin sources already recorded."""
    if not dest and gnoc_platform.is_termux():
        # every step below is sudo; printing them inside Termux sends the user to commands that cannot exist there
        return ("ROOT HELPER INSTALL\n\n" + gnoc_platform.unavailable("the defender's root helper") + ". The sweep "
                "still runs its read-only checks here; to protect a Linux server, name it: /defender install <host>")
    src = shlex.quote(HELPER_SRC)
    admins = [str(a) for a in ((profile or {}).get("admin_sources") or []) if str(a).strip()][:8]
    protect = admins or ["192.168.1.0/24"]
    first = ([f"scp {src} {shlex.quote(dest)}:/tmp/gnoc-defender-helper",
              f"ssh -t {shlex.quote(dest)}",
              f"sudo install -o root -g root -m 0755 /tmp/gnoc-defender-helper {HELPER}"] if dest else
             [f"sudo install -o root -g root -m 0755 {src} {HELPER}"])
    steps = [
        ("Install the helper as a root-owned copy (the chat cannot edit it afterwards):", first,
         f"nothing is printed; `ls -l {HELPER}` shows root root -rwxr-xr-x"),
        ("Let your user run that one program, and nothing else, without a password:",
         [f'echo "$USER ALL=(root) NOPASSWD: {HELPER}" | sudo tee /etc/sudoers.d/gnoc-defender'],
         "the line you just wrote is echoed back"),
        ("Lock the sudoers file down and check its syntax:",
         ["sudo chmod 0440 /etc/sudoers.d/gnoc-defender",
          "sudo visudo -cf /etc/sudoers.d/gnoc-defender"],
         "/etc/sudoers.d/gnoc-defender: parsed OK   (anything else: remove the file and redo step 2)"),
        ("List your admin machines, one IP or CIDR per line. The helper refuses to block or quarantine them "
         "even when no session from them is live" + ("" if admins else " (replace the example with yours)") + ":",
         ["sudo install -d -m 0755 /etc/gnoc-defender",
          "printf '%s\\n' " + " ".join(shlex.quote(a) for a in protect) + " | sudo tee " + PROTECT_FILE],
         "your addresses are echoed back"),
        ("Check that the chat can reach it without a password:",
         [f"sudo -n {HELPER} status"],
         "helper v<n>, then: no defender table (nothing blocked)"),
    ]
    out = ["ROOT HELPER INSTALL" + (f" on {dest}" if dest else ""), ""]
    if status:
        n = sum(1 for i in range(1, INSTALL_STEPS + 1) if status.get(i, (False,))[0] is True)
        nxt = next((i for i in range(1, INSTALL_STEPS + 1) if status.get(i, (False,))[0] is not True), None)
        out.append(f"PROGRESS {n}/{INSTALL_STEPS} done" + (f" · next: step {nxt}" if nxt else " · READY"))
        out.append("")
        if not nxt:
            out += ["The helper is installed and answering. Auto-defense can act now: /defender sweep", ""]
            for i in range(1, INSTALL_STEPS + 1):
                out.append(f"  [done] step {i}: {status[i][1]}")
            return "\n".join(out)
    out += ["Run these yourself, one step at a time (here, prefix each line with ! to run it in this chat).",
            "The chat never runs sudo for you." + (f" Steps 2-5 run ON {dest}, in the ssh session from step 1."
                                                    if dest else ""), ""]
    for i, (what, cmds, expect) in enumerate(steps, 1):
        st = (status or {}).get(i)
        mark = "" if not st else "[done] " if st[0] is True else "[todo] " if st[0] is False else "[wait] "
        out.append(f"{mark}Step {i}. {what}")
        out.append("")
        if st and st[0] is True:
            out.append(f"    done: {st[1]}")
        else:
            out += ["    " + c for c in cmds]
            out.append("")
            out.append(f"    expected: {expect}")
            if st:
                out.append(f"    now:      {st[1]}")
        out.append("")
    out += ["What the helper accepts, and nothing more: block/unblock a PUBLIC ip with a timeout, quarantine/",
            "release a LAN ip with a timeout, pause/resume/kill a pid, isolate/unisolate this endpoint, set an",
            "allowlisted sysctl, show status, flush its own tables. Every call is logged.", "",
            "Then: /defender sweep"]
    return "\n".join(out)


class InstallWatch:
    """While the operator works through the install, re-check the target every few seconds and announce each
    step the moment it completes, then READY. Lives and dies with the chat; stops when done, on stop(), or
    after `limit` seconds. Checks are read-only (install_check)."""

    def __init__(self, say=print):
        self.say = say
        self.th, self.ev = None, threading.Event()

    def running(self):
        return bool(self.th and self.th.is_alive())

    def start(self, profile=None, dest=None, interval=6, limit=900, status=None):
        self.stop()
        ev = threading.Event()
        self.ev = ev
        self.th = threading.Thread(target=self._loop, args=(ev, profile, dest, max(2, interval), limit, status),
                                   daemon=True, name="gnoc-defender-install")
        self.th.start()

    def stop(self):
        if self.th:
            self.ev.set()
            self.th = None

    def _loop(self, ev, profile, dest, interval, limit, prev):
        prev = prev or install_check(profile, dest)
        deadline = time.time() + limit
        while not ev.wait(interval):
            if time.time() > deadline:
                self.say("install check stopped after 15 minutes; /defender install shows where it stands")
                return
            try:
                cur = install_check(profile, dest)
            except Exception as e:  # noqa: BLE001 - a failed check is not a reason to stop watching
                self.say(f"install check failed ({type(e).__name__}); still watching")
                continue
            if ev.is_set():
                return
            for i in range(1, INSTALL_STEPS + 1):
                was, now = (prev.get(i) or (None, ""))[0], cur.get(i, (None, ""))
                if now[0] is True and was is not True:
                    self.say(f"[done] step {i}: {now[1]}")
                elif now[0] is False and was is True:
                    self.say(f"[todo] step {i} is no longer done: {now[1]}")
            if install_done(cur):
                self.say("ROOT HELPER READY: all 5 steps done. Auto-defense can act now: /defender sweep")
                return
            nxt = next(i for i in range(1, INSTALL_STEPS + 1) if cur.get(i, (False,))[0] is not True)
            if any(cur.get(i, (None,))[0] != (prev.get(i) or (None,))[0] for i in cur):
                self.say(f"next: step {nxt}  ({cur[nxt][1]})")
            prev = cur


# ---------------------------------------------------------------- per-host profile (the answers)

def host_key(dest):
    return "local" if not dest else re.sub(r"[^A-Za-z0-9_.@-]", "_", dest)[:80]


def _path(kind, dest):
    return os.path.join(STATE, f"{kind}-{host_key(dest)}.json")


def load_profile(dest=None):
    """Read one host profile. A hand-edited or truncated file must not take the defender down: every
    container and scalar is re-typed here, and invalid scope values are dropped rather than trusted."""
    _secure_state()
    try:
        with open(_path("profile", dest)) as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    p = raw if isinstance(raw, dict) else {}
    exposed = {}
    for port, value in _as_dict(p.get("exposed")).items():
        port = str(port)
        if port.isdigit() and str(value).strip().lower() in EXPOSED_VALUES:
            exposed[port] = str(value).strip().lower()
    p["exposed"] = exposed
    p["admin_sources"] = [x for x in _as_list(p.get("admin_sources"), 64) if _valid_source(x)[0]]
    p["subnets"] = [s for s in _as_list(p.get("subnets"), 32) if _valid_net(s)[0]]
    p["gateways"] = [g for g in _as_list(p.get("gateways"), 32) if _valid_gateway(g)[0]]
    p["gateway_macs"] = {str(k): str(v).strip().lower() for k, v in _as_dict(p.get("gateway_macs")).items()
                         if _valid_mac(v)}
    p["trusted_macs"] = [m for m in _as_list(p.get("trusted_macs"), 128) if _valid_mac(m)]
    p["dhcp_servers"] = [x for x in _as_list(p.get("dhcp_servers"), 32) if _valid_gateway(x)[0]]
    p["wlan_ssid"] = _safe_text(p.get("wlan_ssid"), 64)
    p["wlan_bssid"] = str(p.get("wlan_bssid") or "").strip().lower() if _valid_mac(p.get("wlan_bssid")) else ""
    # allow_net_scan is deliberately NOT defaulted: an absent key is the unanswered question, and the
    # questions()/record_answers() contract is "ask once, then honour the answer". Its absence means off.
    p["allow_quarantine"] = _as_bool(p.get("allow_quarantine"), True)
    # GreyNOC, 2026-11-18: "defend should have the bot auto defend the computer." Auto-defense is the
    # default for the four reversible, allowlisted actions. A profile that already says false stays false;
    # /defender auto off and /defender deny <kind> turn it off for a host.
    for key in ("auto_defense", "allow_block_ips", "allow_contain", "allow_sysctl"):
        p[key] = _as_bool(p.get(key), True)
    p["endpoints"] = [x for x in _as_list(p.get("endpoints"), 64) if E.valid_dest(x)]
    p["gateway_ssh"] = str(p.get("gateway_ssh") or "").strip() if E.valid_dest(p.get("gateway_ssh")) else ""
    p["gateway_platform"] = (str(p.get("gateway_platform") or "generic").strip().lower()
                             if str(p.get("gateway_platform") or "generic").strip().lower() in
                             ("generic", "linux", "openwrt", "pfsense", "opnsense", "pf", "hostapd", "ap", "unifi")
                             else "generic")
    p["gateway_wifi_iface"] = (str(p.get("gateway_wifi_iface") or "").strip()
                               if re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", str(p.get("gateway_wifi_iface") or ""))
                               else "")
    p["gateway_api"] = _sanitize_api(p.get("gateway_api"))
    for key in ("allow_gateway_enforce", "allow_endpoint_enforce", "allow_endpoint_kill"):
        p[key] = _as_bool(p.get(key), False)
    p["alert_min_severity"] = (A.severity(p.get("alert_min_severity"))
                               if str(p.get("alert_min_severity") or "").lower() in A._ALIASES else "high")
    if "fail_threshold" in p:
        p["fail_threshold"] = _as_int(p.get("fail_threshold"), 10, 3, 1000)
    for key in ("role", "remote_access", "expected_services", "notes"):
        if key in p:
            p[key] = _safe_text(p.get(key), 300)
    if "notify" in p:
        p["notify"] = _as_bool(p.get("notify"), False)
    if "allow_net_scan" in p:
        p["allow_net_scan"] = _as_bool(p.get("allow_net_scan"), False)
    p["updated"] = _safe_text(p.get("updated"), 40)
    return p


def _sanitize_api(value):
    """Keep the controller configuration JSON-safe, private, and free of stored credentials."""
    raw = dict(_as_dict(value))
    meta = {"url", "kind", "site", "token_env", "allow_public", "headers"}
    if not raw or (not _safe_text(raw.get("url"), 500)
                   and not any(str(k).lower() not in meta for k in raw)):
        return {}
    api = raw
    for key in list(api):
        if str(key).lower() in ("token", "password", "secret", "api_key", "apikey", "authorization"):
            api.pop(key, None)
    api["url"] = _safe_text(api.get("url"), 500)
    if api["url"]:
        try:
            parsed = urllib.parse.urlparse(api["url"])
        except ValueError:
            return {}
        if (parsed.username or parsed.password or parsed.scheme not in ("http", "https")
                or not parsed.hostname):
            return {}
        if any(re.search(r"token|key|secret|passw|auth", k, re.I)
               for k, _v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)):
            return {}
    api["kind"] = (str(api.get("kind") or "generic").strip().lower()
                   if str(api.get("kind") or "generic").strip().lower() in ("generic", "unifi") else "generic")
    api["site"] = _safe_text(api.get("site"), 80)
    api["token_env"] = (str(api.get("token_env") or "").strip()
                        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,80}", str(api.get("token_env") or "")) else "")
    if "allow_public" in api:
        api["allow_public"] = _as_bool(api.get("allow_public"), False)
    headers = {}
    for k, v in _as_dict(api.get("headers")).items():
        if str(k).lower() in ("authorization", "x-api-key", "cookie", "proxy-authorization"):
            continue
        headers[str(k)[:80]] = _safe_text(v, 300)
    if headers:
        api["headers"] = headers
    else:
        api.pop("headers", None)
    return api


def _atomic_json(path, obj):
    """Write one JSON file atomically, private to the operator. The temp name carries pid+thread so a
    watcher pass and a chat sweep cannot write the same half-written temp file."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh, indent=1, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def save_profile(p, dest=None):
    with _STATE_LOCK:
        _atomic_json(_path("profile", dest), p)


EXPOSED_VALUES = {"no", "lan", "all", "vpn"}
_YES = re.compile(r"\b(yes|yeah|yep|yup|sure|ok(?:ay)?|allow(?:ed)?|enable[d]?|go ahead|do it|approved?|y)\b", re.I)
# a yes beside a negation is not a yes: "No, don't allow that" and "I'm not sure" matched _YES (QAQC 2026-11-19)
_NEGATED = re.compile(r"\b(no|not|nope|nah|never|don'?t|do\s+not|deny|disable|refuse|stop)\b", re.I)


def _said_yes(text):
    return bool(_YES.search(str(text or ""))) and not _NEGATED.search(str(text or ""))


# answers that change what the defender TRUSTS or where it SENDS a credential: the model relays them, so each
# value must appear in GreyNOC's own message (QAQC 2026-11-19: a model could record its own MAC as the gateway's,
# exempt 128.0.0.0/1 as an "admin source", or point gateway_api at a URL with token_env=ANTHROPIC_API_KEY)
_BASELINE_KEYS = {"admin_sources", "trusted_macs", "trusted_devices", "dhcp_servers", "wlan_bssid", "bssid",
                  "gateway_macs", "gateway_api", "gateway_api_url", "gateway_api_token_env", "gateway_ssh",
                  "endpoints", "endpoint"}


def _mentions_all(text, items):
    low = str(text or "").lower()
    items = [str(x).strip().lower() for x in items if str(x).strip()]
    return bool(items) and all(x in low for x in items)


def _url_host(url):
    import urllib.parse
    try:
        return urllib.parse.urlsplit(str(url)).hostname or ""
    except ValueError:
        return ""
_NO = re.compile(r"^\s*(no|nope|nah|n|never|don'?t|deny|disable)\b", re.I)


def _answer_items(value):
    """A comma/space separated answer, or a JSON list, as clean strings."""
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x for x in re.split(r"[,\s]+", str(value or "").strip()) if x]


def _valid_mac(value):
    return bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", str(value or "").strip()))


def _valid_net(value):
    """(cidr or None, error): a private/link-local network, never public, multicast or the whole internet."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None, f"{value!r} is not an IP or CIDR"
    if net.is_global:
        return None, f"{value} is a public network; the defender only defends your own LAN, WLAN and VPN"
    if net.is_loopback:
        return None, f"{value} is loopback, not a network with other hosts"
    if net.prefixlen == 0 or net.network_address.is_unspecified or net.is_multicast or net.is_unspecified \
            or net.is_reserved:
        return None, f"{value} is not a LAN/WLAN/VPN network"
    return str(net), ""


def _valid_gateway(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None, f"{value!r} is not an IP address"
    if ip.is_global:
        return None, f"{value} is a public address; a LAN/WLAN gateway is private"
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return None, f"{value} is not a LAN/WLAN gateway"
    return str(ip), ""


def _valid_source(value):
    """An admin source may be public (remote operator), but it must be a real unicast network."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None, f"{value!r} is not an IP or CIDR"
    if net.prefixlen == 0 or net.network_address.is_unspecified or net.is_multicast or net.is_unspecified:
        return None, f"{value} is not an admin source"
    if net.prefixlen < (16 if net.version == 4 else 48):   # 128.0.0.0/1 would exempt half the internet
        return None, f"{value} is too broad for an admin source (at most a /16, or /48 for IPv6)"
    return str(net), ""


def _mentions(text, items):
    low = str(text or "").lower()
    return any(str(x).lower() in low for x in items)


def record_answers(answers, user_text, dest=None, asked=()):
    """Write the user's answers into the host profile. -> (recorded, refused) lists of strings.

    The model relays the answers, so the PERMISSION keys (what auto-defense may do unasked) are only accepted
    when their own message this turn says yes and the question was actually put to them: the model cannot grant
    itself power by answering its own question. Turning a permission OFF is always accepted. Network scope
    (subnets and gateways) is accepted only when the values appear in their own message, or the user says "auto"."""
    p = load_profile(dest)
    ok, bad = [], []
    text = str(user_text or "")
    asked = {asked} if isinstance(asked, str) else set(asked or ())
    for k, v in (answers or {}).items():
        k = str(k).strip().lower()
        sv = str(v).strip()
        if k in _BASELINE_KEYS or k.startswith(("gateway_mac.", "gateway-mac.")):
            if isinstance(v, dict):
                need = ([_url_host(v.get("url"))] if v.get("url") else []) + \
                    ([str(v["token_env"])] if v.get("token_env") else []) if k == "gateway_api" else \
                    [str(x) for kv in v.items() for x in kv]
                if need and not _mentions_all(text, need):
                    bad.append(f"{k}: the user's own message must name {', '.join(need)}; nothing was recorded")
                    continue
            else:
                items = _answer_items(v) + ([k.split(".", 1)[1]] if "." in k else [])
                if k == "gateway_api_url":
                    items = [_url_host(sv)] if _url_host(sv) else items
                low = text.lower()
                named = [x for x in items if str(x).strip().lower() in low]
                for x in items:
                    if x not in named:
                        bad.append(f"{k}: {x} is not named in the user's own message; not recorded")
                if not named:
                    continue
                if k not in ("gateway_api_url",) and not k.startswith(("gateway_mac.", "gateway-mac.")):
                    v = named
                    sv = ", ".join(named)
        if k in set(PERMISSION.values()) | {"allow_net_scan", "allow_quarantine", "allow_endpoint_kill"}:
            want = sv.lower() in ("true", "yes", "y", "1", "on", "allow")
            if want and not (_said_yes(text) and k in asked):
                bad.append(f"{k}: needs the user's own yes to the question this turn (or /defender allow ...)")
                continue
            p[k] = want
            ok.append(f"{k} = {want}")
        elif k == "admin_sources":
            items = _answer_items(v)
            good = []
            for x in items:
                net, err = _valid_source(x)
                if net:
                    good.append(x if "/" not in x else net)
                else:
                    bad.append("admin_sources: " + err)
            if good:
                p["admin_sources"] = sorted(set(p.get("admin_sources", [])) | set(good))
                ok.append(f"admin_sources = {', '.join(p['admin_sources'])}")
            elif not items:
                bad.append("admin_sources: no IP or CIDR given")
        elif k in ("subnets", "networks", "lan_subnets"):
            items = _answer_items(v)
            auto = any(x.lower() in ("auto", "detect", "all") for x in items)
            if auto:
                with D.on_host(dest):
                    items = D.subnet_targets()
            elif not _mentions(text, items):
                bad.append(f"{k}: the user's message does not name these networks (or answer 'auto')")
                continue
            good = []
            for x in items:
                net, err = _valid_net(x)
                if net:
                    good.append(net)
                else:
                    bad.append(f"{k}: {err}")
            if good:
                p["subnets"] = sorted(set(p.get("subnets", [])) | set(good))
                ok.append(f"subnets = {', '.join(p['subnets']) or '(none)'}")
            elif not items:
                bad.append(f"{k}: no subnet given")
        elif k in ("gateways", "gateway", "gateway_addresses"):
            items = _answer_items(v)
            auto = any(x.lower() in ("auto", "detect", "default") for x in items)
            if auto:
                with D.on_host(dest):
                    items = sorted({r["gateway"] for r in D.default_routes() if r.get("gateway")})
            elif not _mentions(text, items):
                bad.append(f"{k}: the user's message does not name these addresses (or answer 'auto')")
                continue
            good = []
            for x in items:
                ip, err = _valid_gateway(x)
                if ip:
                    good.append(ip)
                else:
                    bad.append(f"{k}: {err}")
            if good:
                p["gateways"] = sorted(set(p.get("gateways", [])) | set(good))
                ok.append(f"gateways = {', '.join(p['gateways']) or '(none)'}")
            elif not items:
                bad.append(f"{k}: no gateway given")
        elif k in ("endpoints", "endpoint"):
            items = _answer_items(v)
            if not items:
                bad.append(f"{k}: no SSH destination given")
                continue
            if not _mentions(text, items) and not _YES.search(text):
                bad.append(f"{k}: the user's message does not name these SSH destinations")
                continue
            good = []
            for x in items:
                if E.valid_dest(x):
                    good.append(x)
                else:
                    bad.append(f"{k}: {x!r} is not an ssh destination such as alice@10.0.0.20")
            if good:
                p["endpoints"] = sorted(set(p.get("endpoints", [])) | set(good))
                ok.append(f"endpoints = {', '.join(p['endpoints'])}")
        elif k == "gateway_ssh":
            if not E.valid_dest(sv):
                bad.append("gateway_ssh: an ssh destination such as root@10.0.0.1")
                continue
            if not _mentions(text, [sv]) and not _YES.search(text):
                bad.append("gateway_ssh: the user's message does not name this destination")
                continue
            p["gateway_ssh"] = sv
            ok.append(f"gateway_ssh = {sv}")
        elif k == "gateway_platform":
            if sv.lower() not in ("generic", "linux", "openwrt", "pfsense", "opnsense", "pf", "hostapd", "ap",
                                   "unifi"):
                bad.append("gateway_platform: generic|linux|openwrt|pfsense|opnsense|hostapd|unifi")
                continue
            p["gateway_platform"] = sv.lower()
            ok.append(f"gateway_platform = {sv.lower()}")
        elif k in ("gateway_wifi_iface", "gateway_iface"):
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", sv):
                bad.append("gateway_wifi_iface: an interface name such as wlan0")
                continue
            p["gateway_wifi_iface"] = sv
            ok.append(f"gateway_wifi_iface = {sv}")
        elif k == "gateway_api" and isinstance(v, dict):
            api = dict(v)
            if api.get("kind") and str(api["kind"]).lower() not in ("generic", "unifi"):
                bad.append("gateway_api: kind must be generic or unifi")
                continue
            secret_keys = {"token", "password", "secret", "api_key", "apikey", "authorization"}
            if secret_keys & {str(x).lower() for x in api} or any(
                    str(h).lower() in ("authorization", "x-api-key", "cookie", "proxy-authorization")
                    for h in (api.get("headers") or {})):
                bad.append("gateway_api: never store a credential; put it in token_env and export it")
                continue
            if api.get("url") and not E._api_url_ok(api["url"], api):
                bad.append("gateway_api: url is not an allowed private controller URL "
                           "(or set allow_public with HTTPS explicitly)")
                continue
            if api:
                clean = _sanitize_api(api)
                if not clean:
                    bad.append("gateway_api: put credentials in token_env; the URL must be a plain http(s) "
                               "controller URL with no userinfo or token query")
                    continue
                p["gateway_api"] = clean
                ok.append("gateway_api configured (token is read from its token_env, never stored)")
        elif k == "gateway_api_url":
            cur = dict(p.get("gateway_api") or {})
            cur["url"] = sv
            if not E._api_url_ok(sv, cur):
                bad.append("gateway_api_url: not an allowed private controller URL "
                           "(or set allow_public with HTTPS explicitly)")
                continue
            clean = _sanitize_api(cur)
            if not clean:
                bad.append("gateway_api_url: put credentials in token_env; no userinfo or token query")
                continue
            p["gateway_api"] = clean
            ok.append(f"gateway_api url = {clean['url']}")
        elif k == "gateway_api_kind":
            if sv.lower() not in ("generic", "unifi"):
                bad.append("gateway_api_kind: generic or unifi")
                continue
            p.setdefault("gateway_api", {})["kind"] = sv.lower()
            ok.append(f"gateway_api kind = {sv.lower()}")
        elif k == "gateway_api_site":
            p.setdefault("gateway_api", {})["site"] = sv[:80]
            ok.append(f"gateway_api site = {sv[:80]}")
        elif k == "gateway_api_token_env":
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{1,80}", sv):
                bad.append("gateway_api_token_env: an environment variable name")
                continue
            p.setdefault("gateway_api", {})["token_env"] = sv
            ok.append(f"gateway_api token_env = {sv}")
        elif k.startswith("gateway_mac.") or k.startswith("gateway-mac."):
            ip = k.split(".", 1)[1] if "." in k else k.split("-", 2)[-1]
            good_ip, err = _valid_gateway(ip)
            if not good_ip:
                bad.append(f"{k}: {err}")
                continue
            if not _valid_mac(sv):
                bad.append(f"{k}: {sv!r} is not a MAC address")
                continue
            p.setdefault("gateway_macs", {})[good_ip] = sv.lower()
            ok.append(f"gateway {good_ip} expected MAC = {sv.lower()}")
        elif k == "gateway_macs" and isinstance(v, dict):
            recorded = 0
            for ip, mac in v.items():
                good_ip, err = _valid_gateway(ip)
                if not good_ip or not _valid_mac(mac):
                    bad.append(f"gateway_macs: {ip} -> {mac} is not a valid gateway/MAC pair")
                    continue
                p.setdefault("gateway_macs", {})[good_ip] = str(mac).lower()
                recorded += 1
            if recorded:
                ok.append("gateway MACs recorded")
        elif k in ("trusted_macs", "trusted_devices"):
            good = []
            for x in _answer_items(v):
                if _valid_mac(x):
                    good.append(x.lower())
                else:
                    bad.append(f"{k}: {x!r} is not a MAC address")
            if good:
                p["trusted_macs"] = sorted(set(p.get("trusted_macs", [])) | set(good))
                ok.append(f"trusted_macs = {', '.join(p['trusted_macs']) or '(none)'}")
        elif k == "dhcp_servers":
            good = []
            for x in _answer_items(v):
                ip, err = _valid_gateway(x)
                if ip:
                    good.append(ip)
                else:
                    bad.append(f"dhcp_servers: {err}")
            if good:
                p["dhcp_servers"] = sorted(set(p.get("dhcp_servers", [])) | set(good))
                ok.append(f"dhcp_servers = {', '.join(p['dhcp_servers']) or '(none)'}")
        elif k in ("wlan_ssid", "ssid"):
            if 0 < len(sv) <= 64:
                p["wlan_ssid"] = sv
                ok.append(f"wlan_ssid = {sv}")
            else:
                bad.append("wlan_ssid: one SSID, at most 64 characters")
        elif k in ("wlan_bssid", "bssid"):
            if _valid_mac(sv):
                p["wlan_bssid"] = sv.lower()
                ok.append(f"wlan_bssid = {sv.lower()}")
            else:
                bad.append("wlan_bssid: a MAC address such as aa:bb:cc:dd:ee:ff")
        elif k.startswith("exposed.") or k.startswith("port"):
            port = re.sub(r"\D", "", k)
            if not port or sv.lower() not in EXPOSED_VALUES:
                bad.append(f"{k}: answer one of {sorted(EXPOSED_VALUES)} for a port number")
                continue
            if port not in text and not (_YES.search(text) or _NO.search(text)):
                bad.append(f"{k}: the user's message does not answer it")
                continue
            p["exposed"][port] = sv.lower()
            ok.append(f"port {port} expected exposure = {sv.lower()}")
        elif k in ("role", "remote_access", "expected_services", "notes"):
            p[k] = sv[:300]
            ok.append(f"{k} = {sv[:80]}")
        # The VALUE must be his, not the model's: "set the alert minimum to medium" was relayed as low and recorded
        # as low (batch 6, 2026-11-23). His message has to carry the value (or a yes/no for notify).
        elif k == "notify":
            want = sv.lower() in ("true", "yes", "y", "1", "on")
            said = (re.search(r"(?i)\b(?:on|enable\w*|start|want)\b", text) or _said_yes(text)) if want else \
                re.search(r"(?i)\b(?:off|no|disable\w*|stop|mute|never|don'?t)\b", text)
            if not said:
                bad.append(f"notify: the user's own message does not say {'on' if want else 'off'}; not recorded")
                continue
            p[k] = want
            ok.append(f"notify = {p[k]}")
        elif k == "alert_min_severity":
            sev = A.severity(sv)
            if sv.strip().lower() not in A._ALIASES:
                bad.append(f"alert_min_severity: one of {', '.join(A.SEVERITIES)}")
            elif not any(re.search(rf"(?i)\b{re.escape(w)}\b", text) for w, s in A._ALIASES.items() if s == sev):
                bad.append(f"alert_min_severity: the user's own message does not name {sev}; not recorded")
            else:
                p[k] = sev
                ok.append(f"alert_min_severity = {sev}")
        elif k == "fail_threshold":
            if not (sv.isdigit() and 3 <= int(sv) <= 1000):
                bad.append("fail_threshold: a number 3..1000")
            elif not re.search(rf"(?<!\d){int(sv)}(?!\d)", text):
                bad.append(f"fail_threshold: {sv} is not in the user's own message; not recorded")
            else:
                p[k] = int(sv)
                ok.append(f"fail_threshold = {sv}")
        else:
            bad.append(f"{k}: not a profile key")
    p["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    save_profile(p, dest)
    return ok, bad


# ---------------------------------------------------------------- who must never be cut off

def protected_ips(profile, dest=None):
    """Addresses the defender never blocks: their admin sources, every live ssh/remote-desktop peer, logged-in
    remote users, the default gateway and the box itself."""
    out = set()
    for x in profile.get("admin_sources", []):
        out.add(x.split("/")[0])
    if not dest:
        for var in ("SSH_CONNECTION", "SSH_CLIENT"):
            v = os.environ.get(var, "").split()
            if v:
                out.add(v[0])
    with D.on_host(dest):
        rc, txt = D._run(["who"], 10)
        out |= set(re.findall(r"\(([0-9a-fA-F.:]+)\)", txt))
        rc, txt = D._run(["ip", "route", "show", "default"], 10)
        out |= set(re.findall(r"\bvia (\S+)", txt))
        out |= {a.split("%")[0] for v in D.interfaces().values() for a in v}
        # the resolvers this box uses: blocking one takes name resolution (and the chat's model API) down
        with contextlib.suppress(Exception):
            out |= {str(x).split("%")[0] for x in D.dns_servers() or []}
            # systemd-resolved: resolv.conf says 127.0.0.53; the upstreams it really uses are listed here
            out |= set(re.findall(r"(?m)^\s*nameserver\s+(\S+)",
                                  D._read("/run/systemd/resolve/resolv.conf") or ""))
        for c in D.connection_rows():
            if c["dir"] == "in" and (c["lport"] in (22, 3389, 5900, 5901, 21118) or c["proc"] in D.PROTECTED_PROCS):
                out.add(c["peer"])
    return out


def in_admin_net(ip, profile):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in profile.get("admin_sources", []):
        try:
            if a in ipaddress.ip_network(net, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------- the sweep

def _safe_obj(value, depth=0):
    """Recursively make a finding action JSON/terminal-safe without changing its numeric types."""
    if depth > 4:
        return None
    if isinstance(value, str):
        return _safe_text(value, 600)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {_safe_text(k, 80): _safe_obj(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_obj(v, depth + 1) for v in value][:64]
    return _safe_text(value, 200)


def _f(fid, sev, area, fact, fix="", act=None):
    sev = sev if sev in SEV_ORDER else "info"
    return {"id": _safe_text(fid, 300), "sev": sev, "area": _safe_text(area, 40),
            "fact": _safe_text(fact, 2000), "fix": _safe_text(fix, 1200), "act": _safe_obj(act)}


# ---------------------------------------------------------------- LAN / WLAN / gateway scope

def _baseline_path(dest=None):
    return _path("network", dest)


def load_baseline(dest=None):
    """The first-seen state used to notice change: gateways, neighbours, Wi-Fi, DNS, DHCP. Re-typed on
    read so a truncated or hand-edited baseline cannot crash a sweep halfway through."""
    _secure_state()
    try:
        with open(_baseline_path(dest)) as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    b = raw if isinstance(raw, dict) else {}
    b["initialized"] = bool(b.get("initialized"))
    for key, limit in (("gateways", 64), ("neighbors", 4096), ("wifi", 32)):
        rows = {str(k): v for k, v in _as_dict(b.get(key)).items() if isinstance(v, dict)}
        # every value a sweep calls .lower()/.split() on is a string, whatever a hand edit put there:
        # one {"mac": 5} row used to fail every watcher pass until someone reset the baseline by hand
        for row in rows.values():
            for f, v in list(row.items()):
                if v is not None and not isinstance(v, (str, bool, list, dict)):
                    row[f] = str(v)
                elif v is None:
                    row[f] = ""
        b[key] = dict(list(rows.items())[:limit])
    b["dns"] = _as_list(b.get("dns"), 32)
    b["dhcp_servers"] = _as_list(b.get("dhcp_servers"), 64)
    b["subnets"] = [s for s in _as_list(b.get("subnets"), 32) if _valid_net(s)[0]]
    return b


def _trim_baseline(b):
    """Keep the first-seen database bounded: a long-lived LAN must not grow the state file forever."""
    for key, limit in (("neighbors", 4096), ("gateways", 64), ("wifi", 32)):
        rows = _as_dict(b.get(key))
        if len(rows) > limit:
            rows = dict(sorted(rows.items(), key=lambda kv: str(
                kv[1].get("last_seen") if isinstance(kv[1], dict) else ""), reverse=True)[:limit])
            b[key] = rows
    b["dns"] = _as_list(b.get("dns"), 32)
    b["dhcp_servers"] = _as_list(b.get("dhcp_servers"), 64)[-64:]
    b["subnets"] = _as_list(b.get("subnets"), 32)
    return b


def save_baseline(b, dest=None):
    with _STATE_LOCK:
        _atomic_json(_baseline_path(dest), _trim_baseline(b))


_BASELINE_EPOCH = {}   # host key -> resets so far; a sweep that loaded before a reset must not save over it


def reset_baseline(dest=None):
    """Operator-requested re-baseline after a verified device/gateway change. Never automatic."""
    with _STATE_LOCK:
        _BASELINE_EPOCH[host_key(dest)] = _BASELINE_EPOCH.get(host_key(dest), 0) + 1
        try:
            os.unlink(_baseline_path(dest))
        except FileNotFoundError:
            return "network baseline was already empty"
        except OSError as e:
            return f"could not clear the network baseline: {type(e).__name__}"
    return "network baseline cleared; the next sweep records the current gateway and device MACs"


# ---------------------------------------------------------------- host drift: what changed on THIS box
# Its own file, not a key in the network baseline: network_sweep loads that file, works for seconds and saves
# it whole, so a host section written in between would be overwritten by a stale copy - and a lost host
# baseline silently re-records whatever is on disk NOW, accepting an implant as normal.
HOST_LIMITS = {"files": 2000, "keys": 512, "ports": 512}


def _host_baseline_path(dest=None):
    return _path("host", dest)


def load_host_baseline(dest=None):
    _secure_state()
    try:
        with open(_host_baseline_path(dest)) as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        raw = {}
    b = raw if isinstance(raw, dict) else {}
    files = {str(k): str(v) for k, v in _as_dict(b.get("files")).items() if isinstance(v, str)}
    keys = {str(k): _safe_text(v, 80) for k, v in _as_dict(b.get("keys")).items()}
    ports = {str(k): _safe_text(v, 60) for k, v in _as_dict(b.get("ports")).items()}
    return {"initialized": bool(b.get("initialized")),
            "files": dict(list(files.items())[:HOST_LIMITS["files"]]),
            "keys": dict(list(keys.items())[:HOST_LIMITS["keys"]]),
            "ports": dict(list(ports.items())[:HOST_LIMITS["ports"]]),
            "recorded": _safe_text(b.get("recorded"), 40)}


def host_snapshot(files, keys, reach):
    """The comparable state: persistence file hashes, authorised-key fingerprints, network-reachable ports.
    `files` None means the read failed, which is NOT the same as "no files" and must never re-baseline."""
    snap = {"keys": dict(keys or {}),
            "ports": {f"{r['proto']}:{r['port']}": _safe_text(r.get("proc"), 60) for r in reach or []}}
    snap["files"] = None if files is None else {p: _host_digest(t) for p, t in files.items()}
    return snap


def _host_digest(text):
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:24]


def _as_swept(text):
    """A file's text the way the sweep reads it back (D.persistence_files: `head -c PERSIST_MAX_BYTES`, then
    parse_persist_dump strips the surrounding newlines), so a vouched hash is the hash the next sweep computes."""
    raw = str(text).encode("utf-8", "replace")[:D.PERSIST_MAX_BYTES]
    return raw.decode("utf-8", "replace").strip("\n")


def vouch_host_files(texts, dest=None):
    """gnoc wrote these persistence files itself (path -> the exact text written): record THOSE paths, at THOSE
    hashes, in the host baseline, and nothing else. The user 2026-11-18: the sweep flagged the defender's own
    gnoc-vulnwatch.service and .timer as "new since the host baseline", which taught them to wave drift through.
    Only the bytes gnoc wrote are vouched for: an edit by anything else changes the hash and is drift again.
    Returns how many paths were recorded (0 before the first sweep, which records everything anyway)."""
    texts = {str(p): t for p, t in (texts or {}).items() if isinstance(t, str)}
    if not texts:
        return 0
    with _STATE_LOCK:
        b = load_host_baseline(dest)
        if not b["initialized"]:
            return 0
        b["files"].update({p: _host_digest(_as_swept(t)) for p, t in texts.items()})
        _atomic_json(_host_baseline_path(dest), {
            "initialized": True, "files": b["files"], "keys": b["keys"], "ports": b["ports"],
            "recorded": b["recorded"] or time.strftime("%Y-%m-%d %H:%M:%S")})
    return len(texts)


def host_drift(snap, dest=None, save=True):
    """([finding], [note]) for host change since the recorded baseline. The first readable pass records it.
    Drift is NOT folded back in automatically: a changed unit stays a finding until the operator accepts it
    (/defender baseline accept), so an implant cannot become "normal" by surviving one watcher pass."""
    out, notes = [], []
    with _STATE_LOCK:
        b = load_host_baseline(dest)
        if not b["initialized"]:
            if snap.get("files") is None:
                return out, ["host baseline: persistence files not readable on this pass, not recorded yet"]
            if save:
                _atomic_json(_host_baseline_path(dest), {
                    "initialized": True, "files": snap["files"], "keys": snap["keys"], "ports": snap["ports"],
                    "recorded": time.strftime("%Y-%m-%d %H:%M:%S")})
            return out, [f"host baseline recorded: {len(snap['files'])} persistence file(s), "
                         f"{len(snap['keys'])} SSH key(s), {len(snap['ports'])} network port(s)"]
    files = snap.get("files")
    if files is not None:
        for path, digest in sorted(files.items()):
            old = b["files"].get(path)
            if old == digest:
                continue
            preload = path == "/etc/ld.so.preload"
            sev = "crit" if preload else "warn"
            what = "is new" if old is None else "changed"
            out.append(_f(f"drift:file:{path}", sev, "drift",
                          f"{path} {what} since the host baseline ({b['recorded'] or 'first sweep'})"
                          + (": the loader now force-loads something into every process" if preload else ""),
                          f"read it (cat {shlex.quote(path)}); if you made this change, /defender baseline accept"))
    for fp, comment in sorted(snap.get("keys", {}).items()):
        if fp not in b["keys"]:
            out.append(_f(f"drift:key:{fp}", "high", "drift",
                          f"a NEW SSH key may log in as this user since the baseline: {comment} ({fp})",
                          "if you did not add it: remove that line from ~/.ssh/authorized_keys, then find out how "
                          "it got there; if you did, /defender baseline accept"))
    known_procs = set(b["ports"].values())
    for key, proc in sorted(snap.get("ports", {}).items()):
        if key in b["ports"]:
            continue
        port = _as_int(key.rpartition(":")[2], 0)
        if port >= 32768 and proc in known_procs:
            continue   # a known program re-listening on a fresh ephemeral port is not a new service
        out.append(_f(f"drift:port:{key}", "warn", "drift",
                      f"{key.replace(':', ' port ', 1)} ({proc or 'unknown process'}) became reachable from the "
                      "network since the baseline",
                      "if it is yours, /defender baseline accept; otherwise find what started it"))
    return out, notes


# ---- scheduled sweeps (2026-11-23): the "automate cyber defense" goal, and Hermes Agent's most-liked automation.
# GreyNOC types /defender schedule ...; the model can never create or change a schedule (a job that makes jobs was a
# Hermes/OpenClaw lesson). One marked crontab line runs a headless sweep: no model, auto-defense by the profile's
# rules, alerts to the queue, a bounded log.
import shutil  # noqa: E402 - the schedule helpers only
import subprocess  # noqa: E402
SCHEDULE_MARK = "# gnoc-defender-schedule"
SCHEDULE_LOG = os.path.expanduser("~/.local/share/gnoc-chat/defender-cron.log")


def schedule_spec(words):
    """(cron fields, words) for 'every 30m' / 'every 2h' / 'hourly' / 'daily 03:00' / five cron fields, or (None,
    why)."""
    w = " ".join(str(words or "").split()).lower()
    m = re.fullmatch(r"(?:every\s+)?(\d{1,3})\s*(?:m|min|mins|minutes?)", w)
    if m and 5 <= int(m.group(1)) <= 59:
        return f"*/{int(m.group(1))} * * * *", f"every {int(m.group(1))} minutes"
    m = re.fullmatch(r"(?:every\s+)?(\d{1,2})\s*(?:h|hr|hrs|hours?)", w)
    if m and 1 <= int(m.group(1)) <= 23:
        n = int(m.group(1))
        return (f"0 */{n} * * *" if n > 1 else "0 * * * *"), (f"every {n} hours" if n > 1 else "every hour")
    if w in ("hourly", "every hour"):
        return "0 * * * *", "every hour"
    m = re.fullmatch(r"(?:daily|every\s+day|nightly)(?:\s+(?:at\s+)?(\d{1,2})(?::(\d{2}))?)?", w)
    if m:
        hh, mm = int(m.group(1) or 3), int(m.group(2) or 0)
        if hh < 24 and mm < 60:
            return f"{mm} {hh} * * *", f"every day at {hh:02d}:{mm:02d}"
    f = w.split()
    if len(f) == 5 and all(re.fullmatch(r"[\d*/,-]+", x) for x in f):
        return w, f"cron '{w}'"
    return None, "say how often: every 30m (5-59 minutes), every 2h, hourly, daily 03:00, or five cron fields"


def schedule_line(fields, gnoc_path=None):
    gp = gnoc_path or (os.path.expanduser("~/.local/bin/gnoc") if os.path.exists(os.path.expanduser("~/.local/bin/gnoc"))
                       else (shutil.which("gnoc") or os.path.expanduser("~/.local/bin/gnoc")))
    log = SCHEDULE_LOG
    return (f"{fields} GNOC_NO_UPDATE_CHECK=1 GNOC_DEFENDER_SCHEDULED=1 {shlex.quote(gp)} chat \"/defender sweep\" "
            f">> {shlex.quote(log)} 2>&1; tail -n 4000 {shlex.quote(log)} > {shlex.quote(log)}.tmp 2>/dev/null && "
            f"mv -f {shlex.quote(log)}.tmp {shlex.quote(log)} {SCHEDULE_MARK}")


def merge_crontab(existing, line):
    """Their crontab with gnoc's one marked line replaced (line) or removed (line None); every other line kept as is."""
    kept = [ln for ln in str(existing or "").splitlines() if SCHEDULE_MARK not in ln]
    while kept and not kept[-1].strip():
        kept.pop()
    if line:
        kept.append(line)
    return ("\n".join(kept) + "\n") if kept else ""


def _crontab_read():
    r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    if r.returncode != 0 and "no crontab" not in (r.stderr or "").lower():
        raise RuntimeError((r.stderr or "crontab -l failed").strip()[:200])
    return r.stdout if r.returncode == 0 else ""


def _termux_cron_note():
    """'' outside Termux or when crond runs; otherwise the one line that keeps a schedule from silently never
    firing (Android has no init to start crond: termux-services does, once enabled)."""
    st = gnoc_platform.crond_state()
    return "" if st in ("", "ok") else (" Inside Termux crond does not start by itself: "
                                        + gnoc_platform.CROND_HELP + ".")


def schedule(words):
    """/defender schedule <how often> | show | off. -> text for them."""
    if not shutil.which("crontab"):
        if gnoc_platform.is_termux():
            return "no crontab inside Termux - nothing was scheduled. " + gnoc_platform.CROND_HELP
        return "no crontab on this computer (install cron) - nothing was scheduled"
    w = " ".join(str(words or "").split()).lower()
    cur = _crontab_read()
    mine = [ln for ln in cur.splitlines() if SCHEDULE_MARK in ln]
    if w in ("", "show", "status", "list"):
        if not mine:
            return ("no scheduled sweep. Set one: /defender schedule every 30m | hourly | daily 03:00 "
                    f"(a headless sweep with no model; its log: {SCHEDULE_LOG})")
        return ("scheduled sweep: " + mine[0].split(" GNOC_NO_UPDATE_CHECK")[0] + f"  (log: {SCHEDULE_LOG})"
                + _termux_cron_note())
    if w in ("off", "stop", "remove", "none", "clear"):
        if not mine:
            return "no scheduled sweep to remove"
        new = merge_crontab(cur, None)
    else:
        fields, said = schedule_spec(w)
        if not fields:
            return "not scheduled: " + said
        new = merge_crontab(cur, schedule_line(fields))
    os.makedirs(os.path.dirname(SCHEDULE_LOG), exist_ok=True)
    r = subprocess.run(["crontab", "-"], input=new, capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return "not scheduled: crontab refused it: " + (r.stderr or "").strip()[:200]
    if w in ("off", "stop", "remove", "none", "clear"):
        return "scheduled sweep removed (your other crontab lines are unchanged)"
    return (f"scheduled: a headless defender sweep {said} (no model; auto-defense acts by this profile's rules; new "
            f"findings go to /defender alerts; log {SCHEDULE_LOG}). /defender schedule off removes it; your other "
            "crontab lines are unchanged." + _termux_cron_note())


def baseline_summary(dest=None):
    """What the defender has learned as normal for this machine, in words: the host baseline (persistence files,
    authorized SSH keys, network-reachable ports) and the network baseline (gateways, DNS, neighbours, Wi-Fi). For
    "what has the defender learned as normal" (defense batch 12 answered from a grep of the home folder)."""
    h, n = load_host_baseline(dest) or {}, load_baseline(dest) or {}
    lines = ["WHAT THE DEFENDER TREATS AS NORMAL HERE (its baseline; drift from it is reported on the next sweep):"]
    if not h.get("initialized") and not n.get("initialized"):
        return "no baseline yet: the first /defender sweep records one"
    files = sorted(h.get("files") or {})
    lines.append(f"  persistence files hashed: {len(files)} (cron, systemd units, shell start-up files, ld.so.preload"
                 f"...), e.g. {', '.join(files[:4])}")
    lines.append(f"  authorized SSH keys: {len(h.get('keys') or [])} fingerprint(s): "
                 + ", ".join(list(h.get("keys") or [])[:4]))
    lines.append(f"  ports reachable from the network: {', '.join(sorted(h.get('ports') or [])) or 'none'}")
    if n.get("initialized"):
        gw = n.get("gateways") or {}
        lines.append(f"  gateways: {', '.join(list(gw)[:3]) or 'none'};  DNS: {', '.join(list(n.get('dns') or [])[:4])}")
        lines.append(f"  LAN neighbours known: {len(n.get('neighbors') or {})};  subnets: "
                     f"{', '.join(list(n.get('subnets') or [])[:3])}")
    lines.append("  A change you made yourself is accepted with /defender baseline accept host|network; drift is never "
                 "folded in by itself.")
    return "\n".join(lines)


def accept_host_drift(dest=None):
    """Operator-requested: fold the current host state into the baseline (after reviewing the drift)."""
    with D.on_host(dest):
        files = D.persistence_files()
        keys = D.authorized_key_prints()
        reach = [r for r in D.listening() if r["bind"] in ("all", "lan") and not D._is_client_udp(r)]
    snap = host_snapshot(files, keys, reach)
    if snap["files"] is None:
        return "host baseline NOT updated: the persistence files were not readable on this pass"
    with _STATE_LOCK:
        _atomic_json(_host_baseline_path(dest), {
            "initialized": True, "files": snap["files"], "keys": snap["keys"], "ports": snap["ports"],
            "recorded": time.strftime("%Y-%m-%d %H:%M:%S")})
    return (f"host baseline accepted: {len(snap['files'])} persistence file(s), {len(snap['keys'])} SSH key(s), "
            f"{len(snap['ports'])} network port(s); earlier drift is now the reference")


def effective_scope(profile=None, dest=None, full=False, snapshot=None):
    """What the defender is responsible for: the live LAN/WLAN, plus anything the user entered."""
    profile = profile or load_profile(dest)
    if snapshot is not None:
        scope = dict(snapshot)
    else:
        with D.on_host(dest):
            scope = {"host": D.hostname(), "links": D.network_interfaces(), "routes": D.default_routes(),
                     "neighbors": D.neighbors(), "wifi": D.wifi_link(), "dns": D.dns_servers(),
                     "wifi_scan": [], "dhcp": None, "gateway_ports": {}}
    discovered = []
    for r in scope.get("links") or []:
        if r.get("kind") not in ("ethernet", "wlan", "other"):
            continue
        for a in r.get("addrs") or []:
            if a.get("family") != "inet" or not a.get("prefixlen"):
                continue
            try:
                net = ipaddress.ip_network(f"{a['address']}/{a['prefixlen']}", strict=False)
            except ValueError:
                continue
            if net.prefixlen <= 30 and not net.is_global and not net.is_loopback:
                discovered.append(str(net))
    configured = list(profile.get("subnets") or [])
    scope["subnets"] = sorted(set(configured) | set(discovered))
    scope["configured_subnets"] = configured
    gates = list(profile.get("gateways") or [])
    for r in scope.get("routes") or []:
        g = r.get("gateway")
        if g and g not in gates:
            gates.append(g)
    scope["gateways"] = [g for g in gates if _is_ipv4_or_v6(g)]
    scope["configured_gateways"] = list(profile.get("gateways") or [])
    scope["profile"] = profile
    scope.setdefault("host", "")
    scope.setdefault("wifi_scan", [])
    scope.setdefault("dhcp", None)
    scope.setdefault("dhcp_error", "")
    scope.setdefault("gateway_ports", {})
    if full and snapshot is None:
        with D.on_host(dest):
            scope["wifi_scan"] = D.wifi_scan()
            servers, how = D.dhcp_servers(4)
            scope["dhcp"] = servers
            if servers is None:
                scope["dhcp_error"] = how
            if profile.get("allow_net_scan"):
                probes = {}
                for g in scope["gateways"]:
                    try:
                        if not ipaddress.ip_address(g).is_global:
                            probes[g] = D.gateway_open_ports(g)
                    except ValueError:
                        continue
                scope["gateway_ports"] = probes
    return scope


def _is_ipv4_or_v6(value):
    try:
        ipaddress.ip_address(str(value).split("%")[0])
        return True
    except ValueError:
        return False


def _iface_label(scope):
    for r in scope.get("links") or []:
        if r.get("kind") in ("wlan", "ethernet") and r.get("addrs"):
            return f"{r.get('name')} ({r.get('kind')})"
    return "?"


# Who runs a well-known public resolver. Without this the lead NAMED the operator from memory: 75.75.75.75 was
# "OpenDNS" (it is Comcast Xfinity's), drive 2026-11-22. A resolver not in the table says so instead of a guess.
_DNS_OPERATORS = (
    (("75.75.75.75", "75.75.76.76", "2001:558:feed::"), "Comcast Xfinity"),
    (("8.8.8.8", "8.8.4.4", "2001:4860:4860::"), "Google Public DNS"),
    (("1.1.1.1", "1.0.0.1", "2606:4700:4700::"), "Cloudflare"),
    (("9.9.9.9", "149.112.112.112", "2620:fe::"), "Quad9"),
    (("208.67.222.222", "208.67.220.220", "2620:119:35::", "2620:119:53::"), "Cisco OpenDNS"),
    (("94.140.14.14", "94.140.15.15", "2a10:50c0::"), "AdGuard DNS"),
    (("4.2.2.1", "4.2.2.2", "4.2.2.3", "4.2.2.4"), "Lumen (Level 3)"),
    (("68.94.156.1", "68.94.157.1"), "AT&T"),
    (("194.242.2.2", "2a07:e340::"), "Mullvad DNS"),
)


def dns_operator(addr):
    """'Comcast Xfinity' / 'on your network (...)' / 'operator not in gnoc's table' for one resolver address."""
    a = str(addr or "").split("%")[0].strip().lower()
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "operator not known"
    if ip.is_loopback:
        return "a resolver on this machine"
    if ip.is_private or ip.is_link_local:
        return "on your own network: the router or a local resolver"
    for addrs, who in _DNS_OPERATORS:
        for x in addrs:
            if a == x or (x.endswith("::") and ip.version == 6 and a.startswith(x[:-1])):
                return who
    return "public; operator not in gnoc's table, look it up, do not guess"


def _dns_text(servers):
    return ", ".join(f"{s} ({dns_operator(s)})" for s in servers or []) or "none"


def _scope_line(scope):
    links = []
    for r in scope.get("links") or []:
        if r.get("kind") not in ("wlan", "ethernet", "other") or not r.get("addrs"):
            continue
        nets = [n for n in r.get("subnets") or [] if n and ":" not in n]
        # THIS machine's own address on the link, then the subnet it sits in. With only the subnet shown, "my
        # local ip?" was answered "10.0.0.0/24" (scored defense batch 2026-11-22).
        own = [str(a.get("address")) for a in r.get("addrs") or []
               if isinstance(a, dict) and a.get("family") == "inet" and a.get("address")]
        links.append(f"{r.get('name')} ({r.get('kind')}) "
                     + (f"this machine is {', '.join(own[:2])} in " if own else "") + ", ".join(nets[:3]))
    wifi = scope.get("wifi") or []
    wifi = [wifi] if isinstance(wifi, dict) else wifi
    wtxt = "; ".join(f"{w.get('ssid') or '?'} [{w.get('bssid') or '?'}] on {w.get('iface') or '?'}"
                     for w in wifi if isinstance(w, dict) and w.get("connected")) or "not on Wi-Fi"
    return (f"  interfaces: {'; '.join(links) or 'none'}\n"
            f"  subnets:    {', '.join(scope.get('subnets') or []) or 'none discovered'}\n"
            f"  gateways:   {', '.join(scope.get('gateways') or []) or 'none discovered'}\n"
            f"  wi-fi:      {wtxt}\n"
            f"  dns:        {_dns_text(scope.get('dns'))}")


def network_report(profile=None, dest=None, full=False):
    """Human-readable scope: what is defended, what is monitored, and what the baseline knows."""
    profile = profile or load_profile(dest)
    scope = effective_scope(profile, dest, full=full)
    b = load_baseline(dest)
    lines = [f"NETWORK DEFENSE SCOPE on {scope.get('host') or 'this machine'}",
             _scope_line(scope)]
    if scope.get("configured_subnets"):
        lines.append("  user-entered subnets: " + ", ".join(scope["configured_subnets"]))
    if scope.get("configured_gateways"):
        lines.append("  user-entered gateways: " + ", ".join(scope["configured_gateways"]))
    expected = profile.get("gateway_macs") or {}
    if expected:
        lines.append("  pinned gateway MACs: " + ", ".join(f"{k}={v}" for k, v in sorted(expected.items())))
    lines.append(f"  baseline: {'recorded' if b.get('initialized') else 'not recorded yet'}  "
                 f"({len(b.get('neighbors') or {})} devices, {len(b.get('gateways') or {})} gateways)")
    if b.get("wifi"):
        lines.append("  last Wi-Fi: " + ", ".join(f"{k}={v.get('ssid') or ''}/{v.get('bssid') or ''}"
                                                  for k, v in sorted(b["wifi"].items())))
    return "\n".join(lines)


def wlan_report(profile=None, dest=None, full=True):
    """Current Wi-Fi link, nearby BSSIDs, and whether the expected SSID/BSSID/security still holds."""
    profile = profile or load_profile(dest)
    with D.on_host(dest):
        current = D.wifi_link()
        scan = D.wifi_scan() if full else []
        links = D.network_interfaces()
        host = D.hostname()
    lines = [f"WLAN MONITOR on {host}"]
    if not current:
        lines.append("  no active Wi-Fi association found (iw/nmcli)")
    for w in current:
        lines.append(f"  {w.get('iface') or '?'}: {w.get('ssid') or '?'}  bssid {w.get('bssid') or '?'}  "
                     f"security {w.get('security') or '?'}  freq {w.get('freq') or '?'}  "
                     f"signal {w.get('signal') or '?'} dBm")
    if profile.get("wlan_ssid"):
        ok = any(w.get("ssid") == profile["wlan_ssid"] for w in current)
        lines.append(f"  expected SSID {profile['wlan_ssid']!r}: {'MATCH' if ok else 'MISMATCH'}")
    if profile.get("wlan_bssid"):
        ok = any(w.get("bssid", "").lower() == profile["wlan_bssid"].lower() for w in current)
        lines.append(f"  expected BSSID {profile['wlan_bssid']!r}: {'MATCH' if ok else 'MISMATCH'}")
    if scan:
        by_ssid = {}
        for r in scan:
            by_ssid.setdefault(r["ssid"], []).append(r)
        watched = {w.get("ssid") for w in current if w.get("connected")}
        if profile.get("wlan_ssid"):
            watched.add(profile["wlan_ssid"])
        twin = {s: rs for s, rs in by_ssid.items() if s in watched
                and len({r["bssid"] for r in rs}) > 1 and any(not r["security"] or r["security"] == "--" for r in rs)}
        lines.append(f"  nearby BSSIDs: {len(scan)}; your SSID with an open twin: {', '.join(twin) or 'none'}")
    elif full:
        lines.append("  nearby scan unavailable (nmcli/iw scan needs NetworkManager or root)")
    for r in links:
        if r.get("kind") == "wlan":
            lines.append(f"  radio {r.get('name')}: {r.get('state') or '?'}  mac {r.get('mac') or '?'}")
    return "\n".join(lines)


def gateway_report(profile=None, dest=None, targets=None, full=True):
    """Check the entered gateways (or the default ones), and show the MAC/port baseline."""
    profile = profile or load_profile(dest)
    gates = targets or profile.get("gateways") or []
    with D.on_host(dest):
        if not gates:
            gates = sorted({r["gateway"] for r in D.default_routes() if r.get("gateway")})
        text = D.gateway_check(gates, timeout=1)
        up = {r["ip"]: r for r in D.neighbors()}
    b = load_baseline(dest)
    lines = [text]
    if gates:
        lines.append("  baseline and expectations:")
    for g in gates:
        entry = (b.get("gateways") or {}).get(g) or {}
        exp = (profile.get("gateway_macs") or {}).get(g) or entry.get("mac") or ""
        cur = (up.get(g) or {}).get("mac", "")
        lines.append(f"    {g}: baseline MAC {entry.get('mac') or '(none)'}  expected {exp or '(unpinned)'}  "
                     f"current {cur or '(no ARP entry)'}")
    return "\n".join(lines)


def add_gateways(values, dest=None):
    """Add gateway addresses to the profile (the /defender and defend answers use this too)."""
    p = load_profile(dest)
    good, bad = [], []
    for x in _answer_items(values):
        ip, err = _valid_gateway(x)
        if ip:
            good.append(ip)
        else:
            bad.append(err)
    p["gateways"] = sorted(set(p.get("gateways", [])) | set(good))
    save_profile(p, dest)
    return good, bad


def remove_gateways(values, dest=None):
    p = load_profile(dest)
    drop = {str(x).strip() for x in _answer_items(values)}
    p["gateways"] = [g for g in p.get("gateways", []) if g not in drop]
    save_profile(p, dest)
    return sorted(drop)


def add_subnets(values, dest=None):
    p = load_profile(dest)
    good, bad = [], []
    for x in _answer_items(values):
        net, err = _valid_net(x)
        if net:
            good.append(net)
        else:
            bad.append(err)
    p["subnets"] = sorted(set(p.get("subnets", [])) | set(good))
    save_profile(p, dest)
    return good, bad


def remove_subnets(values, dest=None):
    p = load_profile(dest)
    drop = {str(x).strip() for x in _answer_items(values)}
    p["subnets"] = [n for n in p.get("subnets", []) if n not in drop]
    save_profile(p, dest)
    return sorted(drop)


def _asset_of(f):
    fid = str(f.get("id") or "")
    m = re.search(r"((?:\d{1,3}\.){3}\d{1,3})", fid + " " + str(f.get("fact") or ""))
    if m:
        return m.group(1)
    m = re.search(r"((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", fid + " " + str(f.get("fact") or ""))
    return m.group(1).lower() if m else fid.split(":")[0]


def _wifi_security(scope, wifi):
    """Best-effort security string for the current BSSID, from the link itself then the nearby scan."""
    if not isinstance(wifi, dict):
        wifi = {}
    if wifi.get("security"):
        return wifi["security"]
    bssid = str(wifi.get("bssid") or "").lower()
    for r in scope.get("wifi_scan") or []:
        if isinstance(r, dict) and str(r.get("bssid") or "").lower() == bssid:
            return str(r.get("security") or "")
    return ""


def network_sweep(profile=None, dest=None, snapshot=None, baseline=None, full=False, save=True, host=None):
    """[finding] for the LAN/WLAN/gateways, plus notes. First run records a baseline; later runs report change.

    Light mode is read-only: neighbour table, routes, Wi-Fi association, DNS and one gateway ICMP test.
    Full mode additionally probes the gateways' admin ports (only with allow_net_scan), lists nearby BSSIDs,
    and listens for DHCP OFFER/ACK. Nothing here is ever run against a public address.
    """
    profile = profile if isinstance(profile, dict) else load_profile(dest)
    scope = effective_scope(profile, dest, full=full, snapshot=snapshot)
    epoch = _BASELINE_EPOCH.get(host_key(dest), 0)
    b = baseline if baseline is not None else load_baseline(dest)
    first = not b.get("initialized")
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    out, notes = [], []
    own = {str(a).split("%")[0] for a in D.own_addrs()} if snapshot is None else set(scope.get("own_addrs") or [])
    neighbors = [n for n in (scope.get("neighbors") or [])
                 if isinstance(n, dict) and n.get("ip") and n.get("mac") and n.get("ip") not in own
                 and not (str(n.get("ip", "")).startswith("fe80:"))]
    by_ip = {}
    for n in neighbors:
        by_ip.setdefault(n["ip"], n)
    trusted = {m.lower() for m in (profile.get("trusted_macs") or []) if _valid_mac(m)}
    # Baselines per NETWORK: a laptop in a cafe met a router at the same address as home (10.0.0.1) with another MAC
    # (a CRITICAL "gateway changed" and an intrusion case) and every stranger's phone as a "new device". The home
    # network keeps the plain-address keys (old baselines need no migration); any other Wi-Fi gets "<ip>@<ssid>"
    # entries, and its first visit is learned quietly (2026-11-23).
    _wl = scope.get("wifi") or []
    _wl = [_wl] if isinstance(_wl, dict) else _wl
    cur_ssid = next((str(w.get("ssid") or "") for w in _wl if isinstance(w, dict) and w.get("connected")), "")
    home = str(b.get("home_ssid") or next((str(v.get("ssid") or "") for v in (b.get("wifi") or {}).values()
                                           if isinstance(v, dict) and v.get("ssid")), "") or cur_ssid)
    if home:
        b["home_ssid"] = home
    away = bool(cur_ssid and home and cur_ssid != home)
    nkey = (lambda ip: f"{ip}@{cur_ssid}") if away else (lambda ip: ip)   # noqa: E731
    net_first = first or (away and not any(str(k).endswith("@" + cur_ssid) for k in (b.get("neighbors") or {})))
    gateways = [g for g in (scope.get("gateways") or []) if _is_ipv4_or_v6(g)]
    gateway_set = set(gateways)
    gateway_macs = {str(k): str(v).lower() for k, v in (profile.get("gateway_macs") or {}).items()}

    # --- gateways: MAC change, reachability, and (opt-in) exposed admin ports
    for g in gateways:
        try:
            a = ipaddress.ip_address(g)
        except ValueError:
            continue
        if a.is_global:
            notes.append(f"gateway {g}: refused (public address)")
            continue
        entry = (b.get("gateways") or {}).get(nkey(g)) or {}
        cur = by_ip.get(g) or {}
        cur_mac = (cur.get("mac") or "").lower()
        expected = gateway_macs.get(g) or (entry.get("mac") or "").lower()
        gateway_changed = False
        if expected and cur_mac and expected != cur_mac:
            gateway_changed = True
            out.append(_f(f"net:gw:{g}:mac", "crit", "gateway",
                          f"gateway {g} changed MAC from {expected} to {cur_mac} on {cur.get('dev') or '?'}: "
                          "possible ARP spoof or man-in-the-middle. Do not trust traffic through it until you "
                          "verify the router itself.",
                          "verify the gateway MAC on the router's own admin page; power-cycle/isolate the suspect "
                          "device; check the switch/AP client list"))
        elif expected and not cur_mac and not first:
            dev = cur.get("dev") or entry.get("dev") or ""
            if a.is_link_local and not dev:
                reachable = True  # no zone/interface: a failed probe would be our own missing route, not evidence
            else:
                try:
                    reachable = (D.ping_host(g, 1, dev=dev)[0] if snapshot is None
                                 else bool(scope.get("gateway_up", {}).get(g)))
                except Exception:  # noqa: BLE001 - a failed probe is not an answer
                    reachable = True
            if not reachable:
                out.append(_f(f"net:gw:{g}:down", "high", "gateway",
                              f"gateway {g} is not answering ARP or ICMP; the LAN may be down or the gateway "
                              "may have been replaced", "check the router and the uplink before trusting the LAN"))
        b.setdefault("gateways", {})[nkey(g)] = {"mac": expected if gateway_changed else (cur_mac or expected),
                                           "dev": cur.get("dev") or "",
                                           "first_seen": entry.get("first_seen") or now,
                                           "last_seen": now, "expected": expected}
        if full and profile.get("allow_net_scan"):
            ports = ((scope.get("gateway_ports") or {}).get(g)
                     if snapshot is not None else D.gateway_open_ports(g))
            for p, (sev, what) in sorted((ports or {}).items()):
                if int(p) == 53:
                    continue   # DNS on the gateway is the LAN's resolver: expected, never a finding to "disable"
                out.append(_f(f"net:gw:{g}:port:{p}", "high" if sev == "high" else
                              "warn" if sev == "medium" else "info", "gateway",
                              f"gateway {g} has tcp/{p} open ({what}); a LAN gateway should expose only the "
                              "admin surface you use", f"disable {what} on the router if you do not use it"))
    if full and not profile.get("allow_net_scan") and gateways:
        notes.append("gateway port audit skipped: answer allow_net_scan yes to permit it")

    # --- neighbours: a changed MAC, a duplicate MAC, or a new device
    seen_mac = {}
    for n in neighbors:
        mac = n["mac"].lower()
        # ARP is IPv4. A phone or laptop holds an IPv4 address plus SLAAC/privacy IPv6 addresses on one MAC;
        # counting those made every dual-stack device "one MAC claiming several IPs" and auto-quarantined it.
        if ":" not in str(n["ip"]):
            seen_mac.setdefault(mac, []).append(n["ip"])
        entry = (b.get("neighbors") or {}).get(nkey(n["ip"])) or {}
        old_mac = (entry.get("mac") or "").lower()
        mac_changed = bool(old_mac and old_mac != mac and n["ip"] not in gateway_set)
        if mac_changed:
            out.append(_f(f"net:arp:{n['ip']}:mac", "high", "arp",
                          f"{n['ip']} changed MAC from {old_mac} to {mac} on {n.get('dev') or '?'}: an ARP spoof "
                          "or an IP conflict", "verify the device and quarantine the offending MAC"))
        if not entry and not net_first and mac not in trusted:
            random_mac = bool(int(mac[:2], 16) & 0x2) if re.match(r"^[0-9a-f]{2}", mac) else False
            out.append(_f(f"net:host:new:{n['ip']}", "info", "host",
                          f"new device on {n.get('dev') or 'the LAN'}: {n['ip']} ({mac})"
                          + (" with a randomized MAC" if random_mac else ""),
                          "confirm it is yours; if not, find its switch/AP port and quarantine it"))
        if mac_changed:
            # Keep the FIRST-SEEN MAC as the expectation. Updating it would let one spoofed ARP reply
            # permanently bless the attacker's MAC for every later sweep.
            entry["last_seen"] = now
            b.setdefault("neighbors", {})[nkey(n["ip"])] = entry
        else:
            b.setdefault("neighbors", {})[nkey(n["ip"])] = {"mac": mac, "dev": n.get("dev") or "",
                                                       "first_seen": entry.get("first_seen") or now,
                                                       "last_seen": now}
    gateway_mac_set = {str((b.get("gateways") or {}).get(nkey(g), {}).get("mac") or "").lower() for g in gateway_set}
    gateway_mac_set |= {str(m).lower() for m in gateway_macs.values()}
    for mac, ips in seen_mac.items():
        if len(ips) <= 1 or mac in trusted:
            continue
        # a router answering for several of its own addresses (aliases, proxy ARP) is reported, never
        # auto-quarantined: cutting the gateway's MAC off this host takes the whole uplink with it
        act = None if mac in gateway_mac_set or set(ips) & set(gateway_set) else \
            {"kind": "quarantine_lan", "ip": sorted(ips)[0], "mac": mac, "ttl": NET_TTL, "spoofable": True}
        out.append(_f(f"net:arp:mac:{mac}:dup", "high", "arp",
                      f"one MAC ({mac}) is claiming {len(ips)} IPv4 addresses: {', '.join(sorted(ips)[:8])}: "
                      "ARP spoof or a misconfigured bridge", "find the port serving this MAC and quarantine it",
                      act))

    # --- Wi-Fi: SSID/BSSID change, an open twin, or a security downgrade
    wifi = scope.get("wifi") or []
    wifi = [wifi] if isinstance(wifi, dict) else wifi
    for w in wifi:
        if not isinstance(w, dict) or not w.get("connected"):
            continue
        key = w.get("iface") or w.get("ssid") or "wlan"
        entry = (b.get("wifi") or {}).get(key) or {}
        ssid, bssid = w.get("ssid") or "", (w.get("bssid") or "").lower()
        if profile.get("wlan_ssid") and ssid != profile["wlan_ssid"]:
            out.append(_f(f"net:wlan:ssid:{key}", "high", "wlan",
                          f"Wi-Fi is on SSID {ssid!r}, not the expected {profile['wlan_ssid']!r}: you may be on a "
                          "different or rogue access point", "disconnect and verify the network before doing sensitive work"))
        if profile.get("wlan_bssid") and bssid != profile["wlan_bssid"].lower():
            out.append(_f(f"net:wlan:bssid:{key}", "warn", "wlan",
                          f"Wi-Fi BSSID is {bssid or '?'}, not the expected {profile['wlan_bssid']}: a roam is "
                          "normal, a new BSSID on a one-AP network is not", "verify the access point"))
        if entry.get("ssid") and ssid != entry["ssid"]:
            out.append(_f(f"net:wlan:ssid:{key}:change", "high", "wlan",
                          f"Wi-Fi SSID changed from {entry['ssid']!r} to {ssid!r}", "verify the network"))
        if entry.get("bssid") and bssid and bssid != entry["bssid"]:
            out.append(_f(f"net:wlan:bssid:{key}:change", "warn", "wlan",
                          f"Wi-Fi BSSID changed from {entry['bssid']} to {bssid}", "verify the access point"))
        scan = [r for r in (scope.get("wifi_scan") or []) if isinstance(r, dict)]
        sec = _wifi_security(scope, w)
        if entry.get("security") and sec and entry["security"] != sec and not sec.strip(" -"):
            out.append(_f(f"net:wlan:security:{key}", "high", "wlan",
                          f"Wi-Fi security changed from {entry['security']} to open/none", "do not use this network"))
        b.setdefault("wifi", {})[key] = {"ssid": ssid, "bssid": bssid, "security": sec or entry.get("security", ""),
                                         "last_seen": now}
        by_ssid = {}
        for r in scan:
            by_ssid.setdefault(r.get("ssid"), []).append(r)
        # ONLY the network this host is on (or the one GreyNOC named). A public hotspot such as
        # xfinitywifi is advertised by many BSSIDs and is open by design; alerting on it is noise.
        watched = {ssid} | ({profile["wlan_ssid"]} if profile.get("wlan_ssid") else set())
        for name, rs in by_ssid.items():
            if name not in watched:
                continue
            bs = {r.get("bssid") for r in rs}
            if len(bs) > 1 and any(not r.get("security") or r.get("security") == "--" for r in rs):
                out.append(_f(f"net:wlan:evil-twin:{name}", "high", "wlan",
                              f"SSID {name!r} is advertised by {len(bs)} BSSIDs and at least one is open: a "
                              "possible evil twin", "use the secured BSSID only; check the AP client list"))
    if full and not wifi:
        notes.append("Wi-Fi: no active association found")

    # --- DNS: a resolver change is a common router/DHCP hijack symptom
    dns = list(scope.get("dns") or [])
    old_dns = list(b.get("dns") or [])
    if old_dns and dns and sorted(old_dns) != sorted(dns):
        out.append(_f("net:dns:changed", "warn", "dns",
                      f"DNS resolvers changed from {', '.join(old_dns)} to {', '.join(dns)}: verify the router and "
                      "DHCP lease", "set DNS manually or fix the DHCP server"))
    if dns:
        b["dns"] = dns

    # --- DHCP: a server that is not the gateway is a rogue DHCP server
    dhcp = scope.get("dhcp")
    if full and dhcp is None and scope.get("dhcp_error"):
        notes.append("DHCP watch: " + str(scope["dhcp_error"]))
    if dhcp is not None:
        # Only the gateway and servers GreyNOC explicitly approved are trusted. A server merely SEEN before
        # is not promoted into the allow-list: otherwise one rogue DHCP lease would make it invisible forever.
        allowed = set(gateways) | set(profile.get("dhcp_servers") or [])
        for s in dhcp:
            ip = s.get("ip", "")
            if not ip:
                continue
            sid = s.get("server_id") or ""
            if sid and sid != ip and sid in allowed:
                out.append(_f(f"net:dhcp:forged-id:{ip}", "high", "dhcp",
                              f"DHCP {s.get('type') or 'OFFER'} sent by {ip} ({s.get('mac') or '?'}) claims to be "
                              f"{sid}, an approved server: a rogue DHCP server impersonating it",
                              "find the device serving DHCP on the switch/AP, disable that port, then renew leases",
                              {"kind": "quarantine_lan", "ip": ip, "ttl": NET_TTL, "spoofable": True}))
            if ip not in allowed:
                out.append(_f(f"net:dhcp:rogue:{ip}", "high", "dhcp",
                              f"DHCP {s.get('type') or 'OFFER'} from {ip} ({s.get('mac') or '?'}) is not the "
                              "configured gateway: a rogue DHCP server can hand out a hostile gateway/DNS",
                              "find the device serving DHCP on the switch/AP, disable that port, then renew leases",
                              {"kind": "quarantine_lan", "ip": ip, "ttl": NET_TTL, "spoofable": True}))
            b["dhcp_servers"] = sorted(set(b.get("dhcp_servers") or []) | {ip})[-64:]

    if scope.get("subnets"):
        b["subnets"] = sorted(set(b.get("subnets") or []) | set(scope["subnets"]))
    b["initialized"] = True
    b["updated"] = now
    if save:
        with _STATE_LOCK:
            # an operator reset that landed while this pass ran wins: writing our pre-reset copy back would
            # silently undo it
            if _BASELINE_EPOCH.get(host_key(dest), 0) == epoch:
                save_baseline(b, dest)
    if first:
        notes.append(f"network baseline recorded: {len(b.get('neighbors') or {})} device(s), "
                     f"{len(b.get('gateways') or {})} gateway(s), {len(wifi)} Wi-Fi link(s)")
    out.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["id"]))
    if len(out) > MAX_FINDINGS:
        notes.append(f"findings capped at {MAX_FINDINGS} (worst first); {len(out) - MAX_FINDINGS} lower-priority "
                     "finding(s) not shown")
        out = out[:MAX_FINDINGS]
    return out, notes


def publish(findings, dest=None, profile=None, host=None):
    """Turn findings into alerts and, when the evidence is an active intrusion, open a triage case.

    -> (alerts, assessment, case, new_case). The alert store deduplicates, so calling this on every sweep
    is safe: a repeat increments the same alert instead of stacking a new one.
    """
    profile = profile if isinstance(profile, dict) else load_profile(dest)
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    sync_stores()
    if host is None:
        with D.on_host(dest):
            host = D.hostname()
    minimum = profile.get("alert_min_severity") or "high"
    rows, created = [], 0
    for f in findings:
        sev = ALERT_SEVERITY.get(f.get("sev"), "info")
        if str(f.get("id") or "").startswith("net:host:new:") and profile.get("alert_new_devices", True):
            # "watch for new devices on my wifi and alert me": the finding was info and never reached the
            # queue or the watcher's announcement (defense drive 2026-11-22). Reported, never acted on alone.
            sev = "medium" if not A.at_least(sev, "medium") else sev
        elif not A.at_least(sev, minimum):
            continue
        alert, is_new = A.raise_alert(
            host=host, severity_=sev, category=f.get("area") or "defender",
            title=f"{str(f.get('area') or 'finding').upper()}: {str(f.get('fact') or '')[:150]}",
            summary=f.get("fact") or "", asset=_asset_of(f), evidence=[f.get("id")],
            dedup=str(f.get("id") or ""), source="defender")
        rows.append(alert)
        created += int(is_new)
    assessment = T.assess(findings, profile=profile)
    case = None
    new_case = False
    if assessment.get("active"):
        alert_ids = [a.get("id") for a in rows if a.get("id")]
        containment = [f.get("id") for f in findings if f.get("area") == "enforcement" and f.get("id")]
        case, new_case = T.open_case(host, findings, assessment, alert_ids=alert_ids, profile=profile,
                                     containment=containment)
        if case:
            alert, _ = A.raise_alert(
                host=host, severity_="critical", category="intrusion",
                title=f"ACTIVE INTRUSION - {case.get('id')}: {case.get('title', '')[:120]}",
                summary=" ".join(assessment.get("reasons") or [])[:1200], asset=host,
                evidence=case.get("evidence") or [], dedup="triage:" + str(case.get("id")),
                source="triage", confidence=assessment.get("confidence"))
            rows.append(alert)
    return rows, assessment, case, new_case


def alerts_report(op="list", alert_id=None, note="", ttl=3600, minimum=None):
    """The alert queue: list, show one, or change its state. Acknowledge does not hide it."""
    sync_stores()
    op = str(op or "list").lower()
    aid = str(alert_id or "").strip().upper()
    if op in ("ack", "acknowledge") and aid:
        a = A.ack(aid, note=note)
        return A.render_detail(a) if a else f"no alert {aid}"
    if op in ("resolve", "resolved", "close") and aid:
        a = A.resolve(aid, note=note)
        return A.render_detail(a) if a else f"no alert {aid}"
    if op in ("reopen",) and aid:
        a = A.reopen(aid, note=note)
        return A.render_detail(a) if a else f"no alert {aid}"
    if op in ("suppress", "mute") and aid:
        a = A.suppress(aid, reason=note, ttl=ttl)
        return A.render_detail(a) if a else f"no alert {aid}"
    if aid:
        a = A.get(aid)
        return A.render_detail(a) if a else f"no alert {aid}"
    return A.render(limit=50, status="open", minimum=minimum or "info")


def triage_report(case_id=None, op=None, note="", step=""):
    """The incident queue: list, show one, or advance it (ack/contain/eradicate/recover/close/step/note)."""
    sync_stores()
    cid = str(case_id or "").strip().upper()
    if cid and op:
        before = T.get_case(cid)
        if before and before.get("status") in T.CLOSED_STATES and str(op).lower() != "note":
            return (f"{cid} is CLOSED ({before.get('status')}): record a note or open a new incident; "
                    "a closed case is not silently reopened")
        case = T.update_case(cid, op=op, note=note, step=step)
        return T.render_case(case) if case else (f"no incident {cid}, unknown op/step {op!r}, or {op!r} would move "
                                                  "the case backwards (contained -> triage is refused)")
    if cid:
        case = T.get_case(cid)
        return T.render_case(case) if case else f"no incident {cid}"
    return T.render_list()


def status_scope(profile=None, dest=None):
    """One compact line for /defender status: the subnets and gateways currently in scope."""
    sync_stores()
    profile = profile or load_profile(dest)
    try:
        scope = effective_scope(profile, dest)
    except Exception as e:  # noqa: BLE001 - status must never fail because a network read did
        return f"network scope: unavailable ({type(e).__name__})"
    return (f"network: {', '.join(scope.get('subnets') or []) or 'none'}  ·  "
            f"gateways: {', '.join(scope.get('gateways') or []) or 'none'}  ·  "
            f"wifi: {', '.join(w.get('ssid') or '?' for w in scope.get('wifi') or []) or 'wired/none'}"
            f"\nenforcement: " + _enforcement_line(profile))


def _enforcement_line(profile):
    caps = E.capabilities(profile)
    eps = E.endpoints(profile)
    gw = E.gateway_dest(profile) or ("controller API" if E.gateway_api(profile) else "")
    if not caps:
        return "not configured (/defender setup guides you; containment stays manual)"
    return (f"gateway {gw or '(none)'} [{E.gateway_platform(profile)}], endpoints "
            f"{', '.join(eps) or '(none)'}, {len(caps)} action(s) ready (always asks)")


def failed_logins(since="-24h"):
    """{ip: count} of failed SSH logins from the journal on the current target, or None when this user cannot
    read the system journal (journalctl then shows only the user's own journal: an empty result, not a zero)."""
    rc, hint = D._run(["journalctl", "--no-pager", "-n", "0"], 15)
    if rc != 0 or "not seeing messages from other users" in hint:
        return None
    rc, txt = D._run(["journalctl", "-q", "--no-pager", "--since", since, "-u", "ssh", "-u", "sshd",
                      "-g", "Failed password|Invalid user|authentication failure|Connection closed by authenticating"],
                     30)
    if rc not in (0, 1):   # -g exits 1 when nothing matched
        return None
    return _count_sources(txt)


def _log_source(ln):
    """The peer address sshd logged for one line, or None. The USERNAME in these lines is attacker-chosen:
    `ssh 'from 1.1.1.1'@box` logs "Invalid user from 1.1.1.1 from 203.0.113.7 port 4242", and the first
    "from" would block the operator's DNS resolver. sshd always appends the real peer LAST, so take the last
    `<addr> port <n>` (or the last rhost=), and only if it parses as an IP address."""
    hits = re.findall(r"(\S+) port \d+", ln) or re.findall(r"rhost=(\S+)", ln)
    if not hits:
        return None
    cand = hits[-1].strip("[]")
    cand = cand[7:] if cand.lower().startswith("::ffff:") else cand
    try:
        return str(ipaddress.ip_address(cand.split("%")[0]))
    except ValueError:
        return None


def _count_sources(txt):
    ips = {}
    for ln in (txt or "").splitlines():
        ip = _log_source(ln)
        if ip:
            ips[ip] = ips.get(ip, 0) + 1
    return ips


def _peer_kind(ip, profile):
    try:
        a = ipaddress.ip_address(str(ip).split("%")[0])
    except ValueError:
        return "not an address"
    if in_admin_net(str(a), profile):
        return "an ADMIN SOURCE you named: the defender never blocks or quarantines it"
    if a.is_loopback:
        return "this machine"
    if a.is_private or a.is_link_local:
        return ("on your own network: never blocked as a public address; a LAN device is quarantined only on "
                "ARP/DHCP-rogue evidence")
    return "a public address"


def login_verdict(dest=None, profile=None):
    """What the login reads PROVE, as the last block of defend(action=logins). Told "someone is brute forcing ssh
    right now", the lead found the journal unreadable, saw the operator's own key sessions from their desktop,
    and answered "SSH brute-force activity detected ... key-based", offering to block their own LAN address with
    "no approval needed" (defense drive 2026-11-22). The facts and their limits, in words."""
    profile = profile if isinstance(profile, dict) else load_profile(dest)
    with D.on_host(dest):
        failed = failed_logins()
        _, who = D._run(["who"], 10)
        _, est = D._run(["ss", "-Htn", "state", "established", "(", "sport", "=", ":22", ")"], 10)
        rc_syn, syn = D._run(["ss", "-Htn", "state", "syn-recv", "(", "sport", "=", ":22", ")"], 10)
    peers = {}
    for ip in re.findall(r"\(([0-9a-fA-F.:]+)\)", who or ""):
        peers.setdefault(ip, set()).add("logged in")
    for ln in (est or "").splitlines():
        cols = ln.split()
        if len(cols) >= 4:
            ip = cols[-1].rsplit(":", 1)[0].strip("[]")
            ip = ip[7:] if ip.lower().startswith("::ffff:") else ip
            peers.setdefault(ip, set()).add("connected to port 22 now")
    lines = ["VERDICT (what the reads above prove; say no more than this):"]
    if failed is None:
        lines.append("  failed SSH logins: NOT READABLE as this user, so this read shows NO evidence of a brute "
                     "force, and none against one. Do not say one is happening or was detected; say it could not "
                     "be checked and how to check it.")
    elif failed:
        top = sorted(failed.items(), key=lambda kv: -kv[1])[:6]
        lines.append("  failed SSH logins (24h): " + "; ".join(f"{ip} x{n} ({_peer_kind(ip, profile)})"
                                                            for ip, n in top))
    else:
        lines.append("  failed SSH logins (24h): none in the journal: no brute force in the last day.")
    if rc_syn == 0:
        n = len([x for x in (syn or "").splitlines() if x.strip()])
        lines.append(f"  half-open connections to port 22 right now: {n}" + (" (a flood would show many)" if n < 20
                                                                            else " (MANY: a possible SYN flood)"))
    for ip, how in sorted(peers.items()):
        lines.append(f"  ssh peer {ip} ({', '.join(sorted(how))}): {_peer_kind(ip, profile)}")
    if not peers:
        lines.append("  no remote ssh sessions or connections right now")
    return "\n".join(lines)


def accepted_logins(since="-24h"):
    """{ip: count} of accepted SSH logins, or None when the journal is not readable here."""
    rc, hint = D._run(["journalctl", "--no-pager", "-n", "0"], 15)
    if rc != 0 or "not seeing messages from other users" in hint:
        return None
    rc, txt = D._run(["journalctl", "-q", "--no-pager", "--since", since, "-u", "ssh", "-u", "sshd",
                      "-g", "Accepted (password|publickey|keyboard-interactive)|session opened for user"], 30)
    if rc not in (0, 1):
        return None
    return _count_sources(txt)


def _own_ancestors():
    out, pid = set(), os.getpid()
    for _ in range(64):
        out.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as fh:
                pid = int(fh.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
        if pid <= 1:
            break
    return out


def sweep(dest=None, light=False, profile=None, packet_secs=5, net=True):
    """[finding] for the target. light=True is the watcher's cheap pass (sockets, processes, recent failed
    logins, suspicious connections, LAN/WLAN/gateway state); the full pass adds kernel/file settings, a short
    packet look, the gateway admin-port audit (if allow_net_scan), the Wi-Fi neighbourhood list and a DHCP
    listen. `net=False` keeps a caller to host checks only (tests and an explicit host question)."""
    profile = profile if isinstance(profile, dict) else load_profile(dest)
    if not dest and gnoc_platform.is_termux():
        return termux_sweep()
    out = []
    notes = []
    with D.on_host(dest):
        rows = D.listening()
        ctr = D.containers()
        reach = [r for r in rows if r["bind"] in ("all", "lan") and not D._is_client_udp(r)]
        seen = set()
        for r in reach:
            key = (r["proto"], r["port"])
            if key in seen:
                continue
            seen.add(key)
            sev, what = D._note(r, ctr)
            sev = {"crit": "crit", "high": "high", "info": "info"}.get(sev, "warn")
            want = _as_dict(profile.get("exposed")).get(str(r["port"]))
            fact = f"{r['proto']} {r['addr'] or '*'}:{r['port']} {r['proc']} is reachable from the network" + (
                f" - {what}" if what else " - unknown service")
            if want in ("lan", "all", "vpn"):
                sev, fact = "info", fact + f" (expected: you said {want})"
            fix = (f"bind it to 127.0.0.1 in its own config, or: sudo ufw deny {r['port']}/{r['proto']}"
                   if sev != "info" else "")
            out.append(_f(f"port:{r['proto']}:{r['port']}", sev, "port", fact, fix))
        # Persistence and host drift run on the light pass too: one bounded read (one ssh round trip on a
        # remote target), and an implanted unit or a new authorised key is exactly what the watcher is for.
        pfiles = D.persistence_files()
        for psev, parea, pkey, pfact, pfix in D.persistence_rows(pfiles or {}):
            out.append(_f(f"persist:{pkey}", psev, parea, pfact, pfix))
        if pfiles is None and not light:
            notes.append("persistence: the start-up files were not readable on this pass")
        drift, dnotes = host_drift(host_snapshot(pfiles, D.authorized_key_prints(), reach), dest)
        out += drift
        notes += dnotes
        if not light:
            fw, fwd = D.firewall()
            if fw == "inactive":
                out.append(_f("fw:inactive", "high", "firewall", "no active firewall: every reachable port above is "
                              "open to the whole network", "sudo ufw default deny incoming && sudo ufw allow from "
                              "<admin source> to any port 22 && sudo ufw enable"))
            elif fw == "unknown":
                out.append(_f("fw:unknown", "warn", "firewall", "the firewall rules are not readable without root"
                              + (f" ({'; '.join(D.firewall_known())})" if D.firewall_known() else ""),
                              "sudo ufw status verbose  (paste it back)"))
            cfg, have = D.sshd_settings()
            ssh_open = any(r["port"] == 22 for r in reach)
            if have and cfg["passwordauthentication"].lower().startswith("yes"):
                out.append(_f("ssh:password", "high" if ssh_open else "warn", "ssh",
                              f"SSH password login is on ({cfg['passwordauthentication']})",
                              "PasswordAuthentication no in /etc/ssh/sshd_config.d/00-hardening.conf, then "
                              "sudo systemctl reload ssh (keep this session open while you test a new one)"))
            if have and cfg["permitrootlogin"].lower().startswith("yes"):
                out.append(_f("ssh:root", "warn", "ssh", f"SSH root login: {cfg['permitrootlogin']}",
                              "PermitRootLogin no"))
        mine = _own_ancestors() if not dest else set()
        conns = D.connection_rows()
        by_pid = {}
        for c in conns:
            if c["pid"]:
                by_pid.setdefault(c["pid"], []).append(c)
        for r in D.process_rows():
            bad = [(s, w) for s, w in r["flags"] if s in ("crit", "high")]
            if not bad:
                continue
            pub = [c for c in by_pid.get(r["pid"], []) if c["peer_kind"] == "public"]
            sev = "crit" if any(s == "crit" for s, _ in bad) or pub else "high"
            act = None
            # AUTO-defense pauses only the unambiguous cases: a crit signature (miner, reverse shell) or a
            # high finding talking to a public peer. A binary merely living in /tmp or being deleted after an
            # upgrade is a manual-review finding; pausing it unasked would break a legitimate process.
            auto_flag = any(s == "crit" for s, _ in bad) or bool(pub)
            if auto_flag and not D.is_protected_proc(r["comm"], r.get("exe"), r.get("args")) \
                    and r["pid"] not in mine and r["pid"] > 1:
                act = {"kind": "pause_pid", "pid": r["pid"], "comm": r["comm"], "exe": r.get("exe") or ""}
            fact = (f"pid {r['pid']} {r['comm']} (user {r['user']}): " + "; ".join(w for _, w in bad)
                    + (f"; talks to {', '.join(sorted({c['peer'] + ':' + str(c['peer_port']) for c in pub})[:3])}"
                       if pub else "") + f"; args: {r['args'][:120]}")
            out.append(_f(f"proc:{r['comm']}:{r['exe'] or r['args'][:60]}", sev, "process", fact,
                          f"inspect: ls -l /proc/{r['pid']}/exe; cat /proc/{r['pid']}/cmdline | tr '\\0' ' '; "
                          f"then kill {r['pid']} and remove its file and whatever started it", act))
        for c in conns:
            if c["dir"] == "out" and c["peer_port"] in D.SUSPECT_PORTS and c["peer_kind"] == "public":
                out.append(_f(f"conn:{c['proc']}:{c['peer']}:{c['peer_port']}", "high", "connection",
                              f"{c['proc']} (pid {c['pid']}) is connected to {c['peer']}:{c['peer_port']} "
                              f"({D.SUSPECT_PORTS[c['peer_port']]})", "find out what started it before trusting it"))
        thr = _as_int(profile.get("fail_threshold"), 10, 3, 1000)
        fails = failed_logins("-30min" if light else "-24h")
        if fails is None:
            if not light:
                notes.append("failed logins: the journal is not readable here (`sudo usermod -aG "
                             "systemd-journal $USER` lets the defender see SSH brute force)")
        else:
            for ip, n in sorted(fails.items(), key=lambda kv: -kv[1]):
                if n < thr:
                    continue
                kind = D._peer_kind(ip)
                act = {"kind": "block_ip", "ip": ip, "ttl": BLOCK_TTL} if kind == "public" else None
                out.append(_f(f"brute:{ip}", "high", "logins", f"{n} failed SSH logins from {ip} ({kind}) "
                              f"in the last {'30 minutes' if light else '24 hours'}",
                              "block it (auto-defense can, for an hour) and keep password login off", act))
            # A failure count is reconnaissance. A success from the SAME source after failures is the
            # intrusion: that is the finding triage must see as active, not just "someone is brute forcing".
            accepted = accepted_logins("-30min" if light else "-24h")
            for ip, n in sorted((accepted or {}).items(), key=lambda kv: -kv[1]):
                if fails.get(ip, 0) < thr:
                    continue
                kind = D._peer_kind(ip)
                act = {"kind": "block_ip", "ip": ip, "ttl": BLOCK_TTL} if kind == "public" else None
                out.append(_f(f"logins:success:{ip}", "high", "logins",
                              f"{fails[ip]} failed SSH logins and then {n} ACCEPTED login(s) from {ip} ({kind}) "
                              f"in the last {'30 minutes' if light else '24 hours'}: possible brute-force success",
                              "review every session and authorised key for this source, then block it and rotate "
                              "the credentials that were used", act))
        if not light:
            for sev, area, key, fact, fix in D.setting_rows():
                act = None
                if area == "sysctl" and key in D.SYSCTL_CHECKS:
                    act = {"kind": "sysctl", "key": key, "value": D.SYSCTL_CHECKS[key][1]}
                out.append(_f(f"{area}:{key}", sev, area, fact, fix, act))
            if packet_secs:
                pk, how = D._capture(int(packet_secs), 800)
                own = {a.split("%")[0] for v in D.interfaces().values() for a in v}
                if pk:
                    syn_in = {}
                    for s, sp, d, dp, pr, syn, ln in pk:
                        if syn and d in own and s not in own:
                            syn_in.setdefault(s, set()).add(dp)
                    for s, ps in syn_in.items():
                        if len(ps) >= 12:
                            kind = D._peer_kind(s)
                            out.append(_f(f"scan:{s}", "high", "packets", f"{s} ({kind}) probed {len(ps)} ports in "
                                          f"{packet_secs}s: a port scan", "block it",
                                          {"kind": "block_ip", "ip": s, "ttl": BLOCK_TTL, "spoofable": True}
                                          if kind == "public" else None))
                    notes.append(f"packets: {len(pk)} captured in {packet_secs}s via {how}")
                else:
                    notes.append("packets: no capture rights here, kernel counters only (defend action=packets); "
                                 "`sudo usermod -aG wireshark $USER` gives per-packet detail")
    if net:
        # The LAN/WLAN/gateway checks live in the same pass: a finding from the network and a finding from
        # this host have to reach triage together, or a gateway spoof plus a malicious process reads as two
        # unrelated notes instead of one incident. Keep the target thread-local around the whole pass: the
        # neighbour/routes/own-address reads inside network_sweep must run on the SAME machine as the host
        # checks, not on the local laptop just because this call is outside the earlier with-block.
        with D.on_host(dest):
            nf, nn = network_sweep(profile, dest, full=not light, save=True)
        out += nf
        notes += nn
    with D.on_host(dest):
        host = D.hostname()
    for f in out:
        f.setdefault("dest", dest)
    proposals = E.proposals(out, profile, host, source_dest=dest)
    if proposals:
        for f in proposals:
            f["dest"] = (f.get("act") or {}).get("dest")
        out += proposals
        notes.append(f"enforcement: {len(proposals)} containment option(s) ready; operator approval required")
    out.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["id"]))
    if len(out) > MAX_FINDINGS:
        notes.append(f"findings capped at {MAX_FINDINGS} (worst first); {len(out) - MAX_FINDINGS} lower-priority "
                     "finding(s) not shown")
        out = out[:MAX_FINDINGS]
    return out, notes


def termux_sweep():
    """The sweep of THIS phone inside Termux: gnoc_termux's reduced read-only set, as findings with no action
    (every desktop action needs root). A remote target named with dest still gets the full sweep over ssh."""
    import gnoc_termux
    rows, notes = gnoc_termux.host_checks(gnoc_platform.termux_prefix(), os.path.expanduser("~"))
    out = [_f(fid, sev, area, fact, fix) for fid, sev, area, fact, fix in rows]
    for f in out:
        f.setdefault("dest", None)
    out.sort(key=lambda f: (SEV_ORDER[f["sev"]], f["id"]))
    return out[:MAX_FINDINGS], notes


# ---------------------------------------------------------------- the questions

def questions(profile, findings, asked=(), dest=None):
    """[(key, question)] still unanswered, most important first, at most 6 per round. Once a key is in
    `asked` it is not asked again, even when every question has been asked."""
    q = []
    profile = profile if isinstance(profile, dict) else {}
    asked = {asked} if isinstance(asked, str) else set(asked or ())
    if not profile.get("admin_sources"):
        guess = os.environ.get("SSH_CONNECTION", "").split()[:1]
        q.append(("admin_sources", "Which IPs or networks must ALWAYS keep admin access, so defense can never lock "
                  "you out?" + (f" (you are connected from {guess[0]} right now; e.g. answer "
                                f"{'.'.join(guess[0].split('.')[:3])}.0/24)" if guess else "")))
    if not profile.get("role"):
        q.append(("role", "What is this machine for: workstation, server (which services), hunting box, or "
                  "something else? It decides which ports are normal."))
    # Network scope is asked before individual ports: the whole point of defender mode is the LAN/WLAN,
    # and a user who does not name a gateway should still get the detected one offered back to them.
    scope = {}
    try:
        scope = effective_scope(profile, dest)
    except Exception:  # noqa: BLE001 - a discovery failure must not block the questions
        scope = {}
    if not profile.get("subnets"):
        detected = scope.get("subnets") or []
        q.append(("subnets", "Which subnets are yours to defend (LAN/WLAN/VPN)? Answer the CIDRs, or 'auto'"
                  + (f" for the detected {', '.join(_safe_text(x, 80) for x in detected)}" if detected else "")))
    if not profile.get("gateways"):
        detected = scope.get("gateways") or []
        q.append(("gateways", "Which gateway addresses should the defender monitor for intrusion? Answer the "
                  "addresses, or 'auto'" + (f" for the detected {', '.join(_safe_text(x, 80) for x in detected)}"
                                             if detected else "")))
    wifi_raw = scope.get("wifi") or []
    wifi_raw = [wifi_raw] if isinstance(wifi_raw, dict) else wifi_raw
    wifi = [w for w in wifi_raw if isinstance(w, dict) and w.get("connected")]
    if wifi and not profile.get("wlan_ssid"):
        w = wifi[0]
        q.append(("wlan_ssid", f"Which Wi-Fi network is yours? Right now you are on {_safe_text(w.get('ssid'), 64)!r} "
                  f"(BSSID {_safe_text(w.get('bssid'), 32)!r}). Answer the SSID so a rogue AP with another name "
                  "is noticed."))
    if "allow_net_scan" not in profile and (scope.get("gateways") or scope.get("subnets")):
        q.append(("allow_net_scan", "May the defender probe your gateways' admin ports and inventory devices on "
                  "these subnets (connect scans only, private ranges only, never the internet)?"))
    for f in findings:
        if f.get("area") == "port" and f.get("sev") != "info":
            m = re.search(r":(\d{1,5})$", str(f.get("id") or ""))
            port = m.group(1) if m else ""
            if port and port not in _as_dict(profile.get("exposed")):
                q.append((f"exposed.{port}", f"{_safe_text(f.get('fact'), 300)}. Should port {port} be reachable: "
                          "no (loopback only), lan, vpn, or all?"))
    acts = {str((f.get("act") or {}).get("kind")) for f in findings if isinstance(f.get("act"), dict)}
    for kind, key, text in (
            ("block_ip", "allow_block_ips", "May auto-defense block a PUBLIC IP that brute-forces SSH or "
             "port-scans this box, for one hour (it expires by itself; LAN and your admin IPs are never blocked)?"),
            ("pause_pid", "allow_contain", "May auto-defense PAUSE (not kill; resumable with /defender undo) a "
             "process that matches a malware or reverse-shell signature?"),
            ("sysctl", "allow_sysctl", "May auto-defense apply the kernel network hardening it lists (runtime "
             "only, gone at reboot, undoable)?")):
        if key not in profile and (kind in acts or kind == "block_ip"):
            q.append((key, text))
    if "notify" not in profile:
        q.append(("notify", "Desktop notification when the watcher finds something new (yes/no)?"))
    uniq, seen = [], set()
    for k, t in q:
        if k not in seen:
            seen.add(k)
            uniq.append((k, t))
    return [x for x in uniq if x[0] not in asked][:6]


# ---------------------------------------------------------------- respond: plan, apply, undo

def plan(findings, profile, dest=None, ids=None):
    """[(finding, verdict, why)] verdict: 'allowed' (the profile permits it unasked), 'ask' (executable, but only
    with their yes), 'refused' (anti-lockout or protected), 'manual' (a command for them; never executed here)."""
    prot = None
    prot_dest = object()
    profile = profile if isinstance(profile, dict) else {}
    out = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = str(f.get("id") or "")
        if ids and fid not in ids:
            continue
        row_dest = f.get("dest") if f.get("dest") is not None else dest
        a = f.get("act")
        if not isinstance(a, dict):
            if str(f.get("sev")) != "info" and f.get("fix"):
                out.append((f, "manual", _safe_text(f.get("fix"), 1200)))
            continue
        kind = str(a.get("kind") or "")
        if kind in E.KINDS:
            ok, why = E.check(a, profile)
            out.append((f, "ask" if ok else "refused", why))
            continue
        if kind == "block_ip":
            ip = str(a.get("ip") or "")
            if prot is None or prot_dest != row_dest:
                prot, prot_dest = protected_ips(profile, row_dest), row_dest
            if not ip or ip in prot or in_admin_net(ip, profile) or D._peer_kind(ip) != "public":
                out.append((f, "refused", f"{ip or '(missing IP)'} is an admin source, a live admin session, "
                            "this box, the gateway or not public: never blocked"))
                continue
        if kind == "pause_pid":
            pid = _as_int(a.get("pid"), 0, 0)
            if D.is_protected_proc(a.get("comm"), a.get("exe"), a.get("args")):
                out.append((f, "refused", f"{a['comm']} is protected"))
                continue
            if pid <= 1:
                out.append((f, "refused", "pid must be above 1"))
                continue
        if kind == "quarantine_lan":
            if prot is None or prot_dest != row_dest:
                prot, prot_dest = protected_ips(profile, row_dest), row_dest
            ip = str(a.get("ip") or "")
            if not ip or ip in prot or ip in set(profile.get("gateways") or []) or in_admin_net(ip, profile) \
                    or D._peer_kind(ip) != "private":
                out.append((f, "refused", f"{ip or '(missing IP)'} is the gateway, an admin/live session, this "
                            "host, or not a private LAN address: never quarantined"))
                continue
        perm = PERMISSION.get(kind)
        if not perm:
            out.append((f, "refused", f"{kind!r} is not an executable defender action"))
            continue
        if a.get("spoofable"):
            # the evidence (a packet's source, an ARP reply, a DHCP offer) can be forged by anyone on the path,
            # so acting on it unasked lets an attacker aim the block at a victim (QAQC 2026-11-19)
            out.append((f, "ask", "the evidence can be spoofed: needs your yes"))
            continue
        out.append((f, "allowed" if profile.get(perm) else "ask",
                    "permitted by the profile" if profile.get(perm) else f"needs your yes ({perm} is off)"))
    return out


def _journal_path():
    return os.path.join(STATE, "journal.jsonl")


def journal(limit=50):
    rows = []
    try:
        with open(_journal_path()) as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and row.get("id"):
                    rows.append(row)
    except OSError:
        pass
    return rows[-max(1, int(limit or 50)):]


def _boot_time():
    try:
        with open("/proc/stat") as fh:
            for ln in fh:
                if ln.startswith("btime "):
                    return float(ln.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def summary(days=7, dest=None):
    """What the defender did and found over the last N days, in words: actions taken (auto or asked, and what is
    still in place), alerts raised and still open, scheduled sweeps run. Read-only. The user (defense batch 15):
    "can I get a weekly summary of what the defender did" was 18 calls searching ~ for a summary file."""
    import time as _t
    days = max(1, min(90, int(days or 7)))
    since = _t.time() - days * 86400
    since_iso = _t.strftime("%Y-%m-%dT%H:%M:%S", _t.localtime(since))

    def _when(r):
        return str(r.get("ts") or r.get("at") or r.get("time") or r.get("first_seen") or "")

    acts = [r for r in journal(5000) if _when(r) >= since_iso]
    ok = [r for r in acts if r.get("ok")]
    auto = [r for r in ok if r.get("auto")]
    kinds = {}
    for r in ok:
        k = str((r.get("act") or {}).get("kind") or "action")
        kinds[k] = kinds.get(k, 0) + 1
    lines = [f"DEFENDER SUMMARY, last {days} day(s) (since {since_iso[:10]}):"]
    lines.append(f"  actions: {len(ok)} done ({len(auto)} on its own, {len(ok) - len(auto)} that you approved)"
                 + (", " + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) if kinds else "")
                 + (f"; {len(acts) - len(ok)} failed" if len(acts) > len(ok) else ""))
    for r in ok[-6:]:
        lines.append(f"    {_when(r)[:16]}  {str(r.get('out') or r.get('finding') or '')[:90]}  ({r.get('id')})")
    try:
        import gnoc_alerts
        raised = [a for a in gnoc_alerts._replay().values()
                  if str(a.get("first_seen") or "") >= since_iso or str(a.get("last_seen") or "") >= since_iso]
    except Exception:  # noqa: BLE001
        raised = []
    still = [a for a in raised if a.get("status") == "open"]
    lines.append(f"  alerts: {len(raised)} seen in this period, {len(still)} still open")
    for a in still[:6]:
        lines.append(f"    [{str(a.get('severity')).upper()}] {str(a.get('summary') or a.get('title') or '')[:90]} "
                     f"({a.get('id')})")
    runs = 0
    with contextlib.suppress(OSError):
        with open(SCHEDULE_LOG, errors="replace") as fh:
            runs = sum(1 for ln in fh if "DEFENDER SWEEP" in ln)
    lines.append(f"  scheduled sweeps logged: {runs}" + ("" if runs else " (none: /defender schedule every 30m sets one)"))
    lines.append("  /defender journal lists every action with its undo; /defender alerts the queue.")
    return "\n".join(lines)


def journal_lines(limit=30):
    """The journal as lines that say what each entry LEFT BEHIND and whether it can be undone. With bare
    "sysctl fs.suid_dumpable FAILED (auto)" rows the lead told the user a FAILED entry was "still active" and that
    runtime sysctls had "expired" (defense drive 2026-11-22). The facts are here so they are read, not guessed."""
    import datetime
    rows = journal(100000)
    undone = {r.get("undo_of"): r.get("id") for r in rows if r.get("undo_of") and r.get("ok")}
    now = time.time()
    out, live = [], []
    for r in rows[-max(1, int(limit or 30)):]:
        a = r.get("act") if isinstance(r.get("act"), dict) else {}
        kind = _safe_text(a.get("kind"), 40)
        what = _safe_text(a.get("ip") or a.get("mac") or a.get("pid") or a.get("key") or a.get("dest") or "", 80)
        val = f" = {_safe_text(a.get('value'), 40)}" if kind == "sysctl" and a.get("value") is not None else ""
        head = (f"{_safe_text(r.get('id'), 12)} {_safe_text(r.get('ts'), 25)} "
                + (f"UNDO of {_safe_text(r.get('undo_of'), 12)}: " if r.get("undo_of") else "")
                + f"{kind} {what}{val} {'ok' if r.get('ok') else 'FAILED'}{' (auto)' if r.get('auto') else ''}")
        if r.get("undo_of"):
            state = "this reverted that entry" if r.get("ok") else "the revert failed: that entry still stands"
        elif not r.get("ok"):
            state = "nothing was changed, so there is nothing to undo"
        elif r.get("id") in undone:
            state = f"already undone by {undone[r['id']]}"
        else:
            ttl = a.get("ttl")
            try:
                start = datetime.datetime.fromisoformat(str(r.get("ts"))).timestamp()
            except ValueError:
                start = None
            if kind in ("block_ip", "quarantine_lan") and ttl and start:
                end = start + _as_int(ttl, BLOCK_TTL, 60, 86400)
                stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(end))
                if end <= now:
                    state = f"expired by itself at {stamp}: nothing left to undo"
                else:
                    state = f"in force until {stamp}, then expires by itself; undo lifts it now"
                    live.append(r.get("id"))
            elif kind == "sysctl" and start and _boot_time() and start < _boot_time() and not r.get("dest"):
                state = (f"lapsed at the reboot on {time.strftime('%Y-%m-%d %H:%M', time.localtime(_boot_time()))}: "
                         "a runtime sysctl does not survive one; nothing left to undo")
            elif kind == "sysctl":
                back = (r.get("undo") or {}).get("value") if isinstance(r.get("undo"), dict) else None
                state = ("set at runtime: it stays until undone or until the next reboot (it never expires); undo "
                         f"sets it back to {_safe_text(back, 40)}" if back is not None else
                         "set at runtime until the next reboot")
                live.append(r.get("id"))
            elif kind == "pause_pid":
                state = "the process stays STOPPED until undone (undo resumes it) or until it is killed"
                live.append(r.get("id"))
            else:
                state = "in force until undone" if r.get("undo") else "no undo recorded"
                if r.get("undo"):
                    live.append(r.get("id"))
        out.append(f"{head}  -> {state}")
    if not out:
        return ["journal empty"]
    out.append("undoable now: " + (", ".join(live) + "  (/defender undo <id>, or undo all)" if live else "none"))
    return out


@contextlib.contextmanager
def _journal_lock():
    os.makedirs(STATE, mode=0o700, exist_ok=True)
    with open(os.path.join(STATE, ".journal.lock"), "a+") as fh:
        try:
            os.chmod(fh.name, 0o600)
        except OSError:
            pass
        try:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        try:
            yield
        finally:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_UN)
            except (ImportError, OSError):
                pass


def _journal_add(row):
    with _STATE_LOCK, _journal_lock():
        os.makedirs(STATE, mode=0o700, exist_ok=True)
        try:
            os.chmod(STATE, 0o700)
        except OSError:
            pass
        rows = journal(100000)
        nums = []
        for r in rows:
            rid = str(r.get("id") or "")
            if rid.startswith("d") and rid[1:].isdigit():
                nums.append(int(rid[1:]))
        row["id"] = "d" + str(1 + max(nums or [0]))
        row["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        fd = os.open(_journal_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(_journal_path(), 0o600)
        except OSError:
            pass
        return row["id"]


def helper(argv, dest=None):
    """(ok, output) from the root helper via `sudo -n` (never prompts)."""
    if not dest and gnoc_platform.is_termux():
        # no sudo and no root inside Termux: say so instead of an install hint for a sudoers file
        return False, gnoc_platform.unavailable("the defender's root helper (firewall blocks, process pause, sysctl)")
    with D.on_host(dest):
        rc, txt = D._run(["sudo", "-n", HELPER, *map(str, argv)], 40)
    # Only sudo's OWN refusal means "not installed": an nft error such as "No such file or directory" (a
    # missing set) is an ordinary failure of one action and must not abort the rest of the batch.
    sudo_lines = [ln for ln in txt.splitlines() if ln.startswith("sudo:")]
    if rc != 0 and (rc == 127 or any(k in ln for ln in sudo_lines for k in (
            "password is required", "command not found", "No such file", "not allowed", "not in the sudoers"))):
        return False, "the defender helper is not installed for passwordless use on this host.\n" + install_hint()
    return rc == 0, txt.strip()


def execute(act, dest=None):
    """(ok, output, undo_act) for one executable action. Re-validates its own input: an approved action
    must never crash the turn or reach a helper with a malformed value."""
    act = act if isinstance(act, dict) else {}
    k = str(act.get("kind") or "")
    if k in E.KINDS:
        return E.run(act)
    if k == "block_ip":
        ip = str(act.get("ip") or "")
        if not D._is_ip(ip) or D._peer_kind(ip) != "public":
            return False, f"{ip or '(missing IP)'} is not a public IP", None
        ttl = _as_int(act.get("ttl"), BLOCK_TTL, 60, 86400)
        ok, out = helper(["block", ip, ttl], dest)
        return ok, out, {"kind": "unblock_ip", "ip": ip}
    if k == "quarantine_lan":
        ip = str(act.get("ip") or "")
        if not D._is_ip(ip) or D._peer_kind(ip) != "private":
            return False, f"{ip or '(missing IP)'} is not a private LAN IP", None
        ttl = _as_int(act.get("ttl"), NET_TTL, 60, 86400)
        mac = str(act.get("mac") or "")
        ok, out = helper(["quarantine", ip, ttl, mac], dest)
        return ok, out, {"kind": "release_lan", "ip": ip}
    if k == "pause_pid":
        pid = _as_int(act.get("pid"), 0, 0)
        if pid <= 1:
            return False, "pid must be above 1", None
        if not dest:
            try:
                os.kill(pid, signal.SIGSTOP)
                return True, f"paused {pid} ({_safe_text(act.get('comm'), 80) or '?'})", \
                    {"kind": "resume_pid", "pid": pid}
            except PermissionError:
                pass
            except ProcessLookupError:
                return False, f"no process {pid}", None
            except OSError as e:
                return False, f"cannot pause {pid}: {type(e).__name__}: {str(e)[:120]}", None
        else:
            with D.on_host(dest):
                rc, txt = D._run(["kill", "-STOP", str(pid)], 15)
            if rc == 0:
                return True, f"paused {pid}", {"kind": "resume_pid", "pid": pid}
        ok, out = helper(["pause", pid], dest)
        return ok, out, {"kind": "resume_pid", "pid": pid}
    if k == "sysctl":
        key = str(act.get("key") or "")
        value = str(act.get("value") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", key) or not value:
            return False, "sysctl needs a key and a value", None
        ok, out = helper(["sysctl", key, value], dest)
        # the undo restores what the HELPER recorded (root-only) before it hardened the key; it never re-sends a
        # weaker value, which the helper now refuses (QAQC 2026-11-19)
        return ok, out, ({"kind": "sysctl_undo", "key": key} if ok else None)
    if k == "sysctl_undo":
        key = str(act.get("key") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", key):
            return False, "sysctl_undo needs a key", None
        ok, out = helper(["sysctl-undo", key], dest)
        return ok, out, None
    if k == "unblock_ip":
        ip = str(act.get("ip") or "")
        if not D._is_ip(ip):
            return False, f"{ip!r} is not an IP address", None
        ok, out = helper(["unblock", ip], dest)
        return ok, out, None
    if k == "release_lan":
        ip = str(act.get("ip") or "")
        if not D._is_ip(ip):
            return False, f"{ip!r} is not an IP address", None
        ok, out = helper(["release", ip], dest)
        return ok, out, None
    if k == "resume_pid":
        pid = _as_int(act.get("pid"), 0, 0)
        if pid <= 1:
            return False, "pid must be above 1", None
        if not dest:
            try:
                os.kill(pid, signal.SIGCONT)
                return True, f"resumed {pid}", None
            except PermissionError:
                pass
            except ProcessLookupError:
                return False, f"no process {pid} (it exited)", None
            except OSError as e:
                return False, f"cannot resume {pid}: {type(e).__name__}: {str(e)[:120]}", None
        ok, out = helper(["resume", pid], dest)
        return ok, out, None
    return False, f"unknown action {k}", None


def _act_key(act):
    value = act.get("ip") or act.get("mac") or act.get("pid") or act.get("key") or act.get("dest")
    return f"{act.get('kind')}:{value}:{act.get('value', '')}"


def apply(items, dest=None, auto=False):
    """Run every (finding, verdict) whose verdict the CALLER already decided may run. -> [line]

    In auto mode the same action is not repeated inside two minutes: the watcher and a manual sweep can see
    the same finding seconds apart, and a second nft element or a second SIGSTOP is noise, not more defence."""
    lines = []
    for f, verdict, _why in items:
        if not isinstance(f, dict) or not isinstance(f.get("act"), dict):
            continue
        act = f["act"]
        row_dest = f.get("dest") if f.get("dest") is not None else dest
        key = _act_key(act)
        now = time.time()
        if auto:
            with _LAST_LOCK:
                last = _LAST_ACTION.get(key, 0)
                if now - last < 120:
                    lines.append(f"  SKIPPED  {_safe_text(act.get('kind'), 40)} "
                                 f"{_safe_text(key.split(':', 1)[1], 80)} (already applied "
                                 f"{int(now - last)}s ago)")
                    continue
        ok, out, undo = execute(act, row_dest)
        out = str(out or "")
        if ok and auto:
            with _LAST_LOCK:
                _LAST_ACTION[key] = now
        jid = _journal_add({"host": host_key(row_dest), "dest": row_dest, "finding": str(f.get("id") or ""),
                            "act": act, "ok": ok, "out": _safe_text(out, 300), "undo": undo, "auto": auto})
        lines.append(f"  {'APPLIED' if ok else 'FAILED '} [{jid}] {_safe_text(act.get('kind'), 40)} "
                     f"{_safe_text(act.get('ip') or act.get('mac') or act.get('pid') or act.get('key') or act.get('dest'), 100)}: "
                     f"{_safe_text((out.splitlines() or [''])[0], 160)}")
        if not ok and "helper is not installed" in out:
            lines.append("")
            lines.append("  " + install_hint().replace("\n", "\n  "))
            break
    return lines


def isolation_token(dest):
    """The token of the newest live isolation of `dest`, from this machine's journal, or ''."""
    rows = journal(100000)
    done = {r.get("undo_of") for r in rows if r.get("undo_of") and r.get("ok")}
    for r in reversed(rows):
        u = r.get("undo") if isinstance(r.get("undo"), dict) else {}
        if r.get("ok") and r["id"] not in done and u.get("kind") == "endpoint_unisolate" and u.get("dest") == dest:
            return str(u.get("token") or "")
    return ""


def undo(which="last"):
    """Revert journal entries: 'last', 'all', or ids ('d3 d5'). -> [line]"""
    rows = journal(100000)
    # only a SUCCESSFUL undo retires an action: a failed one (ssh timeout resuming a paused pid) must stay
    # retryable, or the process stays stopped with every later undo saying "nothing to undo"
    done = {r.get("undo_of") for r in rows if r.get("undo_of") and r.get("ok")}
    live = [r for r in rows if r.get("ok") and r.get("undo") and r["id"] not in done and not r.get("undo_of")]
    if which in ("", "last"):
        pick = live[-1:]
    elif which == "all":
        pick = list(reversed(live))
    else:
        want = set(re.findall(r"d\d+", which))
        pick = [r for r in reversed(live) if r["id"] in want]
    if not pick:
        return ["  nothing to undo"]
    lines = []
    for r in pick:
        undo_act = r.get("undo") if isinstance(r.get("undo"), dict) else None
        if not undo_act:
            continue
        ok, out, _ = execute(undo_act, r.get("dest"))
        out = str(out or "")
        _journal_add({"host": r.get("host"), "dest": r.get("dest"), "undo_of": r.get("id"), "act": undo_act,
                      "ok": ok, "out": _safe_text(out, 300)})
        kind = _safe_text((r.get("act") or {}).get("kind"), 40)
        lines.append(f"  {'UNDONE' if ok else 'FAILED'} {_safe_text(r.get('id'), 20)} ({kind}): "
                     f"{_safe_text((out.splitlines() or [''])[0], 140)}")
    return lines


# ---------------------------------------------------------------- rendering

def render(findings, notes, qs, plan_rows, dest=None, profile=None, alerts=None, assessment=None, case=None):
    profile = profile if isinstance(profile, dict) else {}
    head = f"DEFENDER SWEEP of {'this machine' if not dest else dest}"
    with D.on_host(dest):
        head += f" ({D.hostname()})"
    lines = [head, ""]
    findings = [f for f in findings or [] if isinstance(f, dict)]
    counts = {s: sum(1 for f in findings if f.get("sev") == s) for s in SEV_ORDER}
    lines.append("  " + ", ".join(f"{n} {s}" for s, n in counts.items() if n) if findings else "  nothing found")
    for f in findings:
        if f.get("sev") == "info":
            continue
        lines.append(f"  [{_safe_text(f.get('sev'), 4).upper():4}] {_safe_text(f.get('id'), 120)}: "
                     f"{_safe_text(f.get('fact'), 1800)}")
    info = [f for f in findings if f.get("sev") == "info"]
    if info:
        lines.append("  ok/expected: " + "; ".join(_safe_text(f.get("fact"), 90) for f in info[:8]))
    if notes:
        lines += ["", "  notes: " + " | ".join(_safe_text(n, 400) for n in notes)]
    if alerts:
        lines += ["", f"ALERTS RAISED/UPDATED: {len(alerts)}"]
        lines += [f"  {_safe_text(a.get('id'), 20)} [{A.severity(a.get('severity')).upper()}] "
                  f"{_safe_text(a.get('title'), 160)}" for a in alerts[:8] if isinstance(a, dict)]
        if len(alerts) > 8:
            lines.append(f"  ... and {len(alerts) - 8} more (defend action=alerts)")
    if assessment and assessment.get("active"):
        lines += ["", f"ACTIVE INTRUSION ASSESSMENT: {_safe_text(assessment.get('priority'), 4)}  "
                      f"confidence {assessment.get('confidence')}%"]
        lines += [f"  - {_safe_text(r, 300)}" for r in (assessment.get("reasons") or [])[:6]]
    if case:
        lines += ["", f"TRIAGE {_safe_text(case.get('id'), 20)} [{_safe_text(case.get('status'), 20).upper()}] "
                      f"{_safe_text(case.get('priority'), 4)}"]
        lines.append(f"  {_safe_text(case.get('title'), 300)}")
        lines.append("  playbook: " + ", ".join(f"{_safe_text(s.get('step'), 20)}={_safe_text(s.get('status'), 20)}"
                                                 for s in (case.get("playbook") or []) if isinstance(s, dict)))
        lines.append("  defend(action=triage, id=" + _safe_text(case.get("id"), 20) + ") shows the full case")
    if plan_rows:
        lines += ["", "RESPONSE PLAN:"]
        for f, verdict, why in plan_rows:
            if not isinstance(f, dict):
                continue
            tag = {"allowed": "AUTO-OK", "ask": "ASK", "refused": "NEVER", "manual": "MANUAL"}.get(verdict, "?")
            act = f.get("act") if isinstance(f.get("act"), dict) else {}
            what = (f"{_safe_text(act.get('kind'), 40)} "
                    f"{_safe_text(act.get('ip') or act.get('mac') or act.get('pid') or act.get('key') or act.get('dest'), 100)}"
                    if act else _safe_text(why, 400))
            lines.append(f"  [{tag:7}] {_safe_text(f.get('id'), 120)}: {what}"
                         + (f"  ({_safe_text(why, 300)})" if act else ""))
        if any(isinstance(f, dict) and f.get("area") == "enforcement" for f, _v, _w in plan_rows):
            lines.append("  ENFORCEMENT: gateway/endpoint changes always wait for the user's explicit yes.")
    always_ask = {"allow_gateway_enforce", "allow_endpoint_enforce", "allow_endpoint_kill"}
    perms = [k for k in PERMISSION.values() if k not in always_ask and profile.get(k)]
    if profile.get("allow_net_scan"):
        perms.append("allow_net_scan")
    lines += ["", "AUTO-DEFENSE MAY: " + (", ".join(sorted(set(perms))) if perms else "nothing yet (it only alerts)")]
    if qs:
        lines += ["", "QUESTIONS FOR GREYNOC - ask them these in ONE message, numbered, and END YOUR TURN there. "
                      "Only their reply answers them: never answer them yourself. When the user answers, record each with "
                      "defend(action=answer, answers={key: value}):"]
        lines += [f"  {i}. [{_safe_text(k, 40)}] {_safe_text(t, 500)}" for i, (k, t) in enumerate(qs, 1)]
    return "\n".join(lines)


# ---------------------------------------------------------------- the watcher (auto mode)

class Watcher:
    """Re-sweeps the target every `interval` seconds while the chat is open. New findings are announced;
    with auto=True the kinds the profile allows are applied at once and journalled. It never outlives the
    chat (daemon thread) and never runs anything plan() does not mark allowed."""

    def __init__(self, say=print, notify=None):
        self.say, self.notify = say, notify
        self.th, self.stop_ev = None, threading.Event()
        self.dest, self.interval, self.auto = None, 60, True
        self.seen, self.prev_ids = set(), set()
        self.prev_counters, self.last, self.runs, self.alerts = None, None, 0, 0

    def running(self):
        return bool(self.th and self.th.is_alive())

    def start(self, dest=None, interval=60, auto=None):
        self.stop()
        self.dest, self.interval = dest, _as_int(interval, 60, 20, 86400)
        self.auto = auto_defense_on(load_profile(dest), {"auto": auto}) if auto is not None else \
            auto_defense_on(load_profile(dest))
        self.seen, self.prev_ids, self.prev_counters, self.runs = set(), set(), None, 0
        # Each worker owns ITS event. _loop used to re-read self.stop_ev every pass, so a worker still inside
        # a slow sweep when stop() gave up joining picked up the NEW, unset event and kept running beside the
        # new worker: duplicate alerts and duplicate auto-actions on every restart.
        ev = threading.Event()
        self.stop_ev = ev
        self.th = threading.Thread(target=self._loop, args=(ev,), daemon=True, name="gnoc-defender")
        self.th.start()

    def stop(self):
        """Stop and join the old worker before a new one starts: two overlapping sweeps would double every
        alert and race the journal."""
        th = self.th
        if th:
            self.stop_ev.set()
            self.th = None
            if th is not threading.current_thread():
                th.join(timeout=5)

    def status(self):
        if not self.running():
            return "watcher off"
        return (f"watcher on: {'AUTO-DEFENSE' if self.auto else 'alert only'}, every {self.interval}s on "
                f"{self.dest or 'this machine'}, {self.runs} sweep(s), {self.alerts} alert(s)"
                + (f", last {self.last}" if self.last else ""))

    def tick(self, ev=None):
        """One watcher pass; returns the lines it announced (tests drive this directly). `ev` is the calling
        worker's stop event: a pass that outlived its stop() is discarded before it touches state or acts."""
        prof = load_profile(self.dest)
        findings, _ = sweep(self.dest, light=True, profile=prof)
        with D.on_host(self.dest):
            c, _dev = D._proc_counters()
        if ev is not None and ev.is_set():
            return []
        said = []
        if self.prev_counters is not None:
            dc = {k: c.get(k, 0) - v for k, v in self.prev_counters.items()}
            for ln in D.counter_alarms(dc):
                raw = str(ln or "")
                m = re.search(r"\[([^\]]{1,40})\]\s*(.*)", raw)
                fid = "counter:" + _safe_text(m.group(1) if m else raw, 40)
                if fid not in self.seen:
                    findings.append(_f(fid, "high", "packets",
                                       _safe_text(m.group(2) if m else raw, 400)))
        self.prev_counters = c
        first = self.runs == 0
        # `prev_ids` is the PREVIOUS PASS, not everything ever seen: a finding that clears and comes back must
        # raise a new alert instead of staying silent forever because its id was once in a set.
        new = [f for f in findings if f["id"] not in self.prev_ids and (
            f["sev"] in ("crit", "high") or (f["area"] == "port" and not first)
            or (not first and str(f["id"]).startswith("net:host:new:") and prof.get("alert_new_devices", True)))]
        if first:
            new = [f for f in new if f["sev"] == "crit" or f["area"] == "process"]
        self.prev_ids = {f["id"] for f in findings}
        self.seen |= {f["id"] for f in findings if str(f["id"]).startswith("counter:")}
        self.runs += 1
        self.last = time.strftime("%H:%M:%S")
        # The alert queue and triage see the whole finding set on the first pass (and whenever something
        # new appears), not just the subset the console chooses to announce. A gateway MAC change plus a
        # malicious process must land in one incident, even if only one of them is "new" this minute.
        if new or first:
            alerts, assessment, case, new_case = publish(findings, self.dest, prof)
        else:
            alerts, assessment, case, new_case = [], T.assess(findings, profile=prof), None, False
        if not new and not new_case:
            for ln in [f"  {a.get('id')} [{A.severity(a.get('severity')).upper()}] {a.get('title')}"
                       for a in alerts[:4]]:
                self.say(ln)
            return said
        self.alerts += max(len(new), len(alerts))
        said.append(f"DEFENDER ALERT ({self.last}, {self.dest or 'this machine'}): {len(new)} new finding(s), "
                    f"{len(alerts)} alert(s)")
        said += [f"  [{f['sev'].upper()}] {f['fact'][:220]}" for f in new]
        for a in alerts[:6]:
            said.append(f"  ALERT {a.get('id')} [{A.severity(a.get('severity')).upper()}] {a.get('title')}")
        if assessment.get("active"):
            said.append(f"  TRIAGE: ACTIVE INTRUSION, {assessment.get('priority')}, "
                        f"confidence {assessment.get('confidence')}%")
        if new_case and case:
            said.append(f"  TRIAGE OPENED {case.get('id')} on {case.get('host')}: {case.get('title')}")
            said.append(f"  next: defend(action=triage, id={case.get('id')}) for the playbook")
        auto_rows = plan(findings if first else new, prof, self.dest)
        if ev is not None and ev.is_set():
            return []      # stopped while publishing: never apply from a retired worker
        if self.auto:
            ok_rows = [r for r in auto_rows if r[1] == "allowed"]
            if ok_rows:
                said += apply(ok_rows, self.dest, auto=True)
            asks = [r for r in auto_rows if r[1] == "ask"]
            if asks:
                said.append("  needs your yes: " + "; ".join(f"{r[0]['act']['kind']} for {r[0]['id']}" for r in asks)
                            + "  (defend action=respond, or /defender allow ...)")
        else:
            acts = [r for r in auto_rows if r[1] in ("allowed", "ask")]
            if acts:
                said.append("  auto-defense is off; to act: /defender respond  (or turn it on: /defender auto on)")
        enforcement = [r for r in auto_rows if r[1] == "ask" and r[0].get("area") == "enforcement"]
        if enforcement:
            said.append("  ENFORCEMENT READY (waiting for your yes): "
                        + "; ".join(f"{r[0]['act']['kind']} for {r[0]['id']}" for r in enforcement)
                        + "  (/defender enforce ...)")
        for ln in said:
            self.say(ln)
        if self.notify and prof.get("notify"):
            with contextlib.suppress(Exception):
                self.notify("defender alert", said[0] + "\n" + "\n".join(x.strip() for x in said[1:4]))
        return said

    def _loop(self, ev):
        while not ev.is_set():
            try:
                self.tick(ev)
            except Exception as e:  # noqa: BLE001 - a failed pass is reported, the watch goes on
                if not ev.is_set():
                    self.say(f"defender watcher: pass failed ({type(e).__name__}: {str(e)[:120]})")
            ev.wait(self.interval)


def auto_rules(profile=None, watching=""):
    """The exact rules auto-defense acts on, from the code below (sweep/plan/apply), for defend(action=status).
    Without them the lead invented behaviour: a new listener on port 4444 would be "blocked from public access,
    paused and quarantined" (it is only alerted), it promised a timed "auto off" that does not exist, and it went
    looking in ~/.config for where alerts go (defense drive 2026-11-22)."""
    p = profile if isinstance(profile, dict) else {}
    on = lambda k: "allowed" if p.get(k) else "asks first (switched off in the profile)"   # noqa: E731
    thr = _as_int(p.get("fail_threshold"), 10, 3, 1000)
    return "\n".join([
        "AUTO-DEFENSE RULES (exactly what runs with nobody asked, and only on a sweep or a watcher pass):",
        f"  pause a process [{on('allow_contain')}]: a CRITICAL signature (crypto miner, reverse shell) or a HIGH "
        "process finding that talks to a public address. SIGSTOP, never a kill; protected system processes and "
        "gnoc itself are never paused; undo resumes it.",
        f"  block a PUBLIC address for {BLOCK_TTL // 60} min [{on('allow_block_ips')}]: {thr}+ failed SSH logins "
        "from it (24 h on a sweep, 30 min on a watcher pass), or failures then an accepted login. Expires by "
        "itself. Never: a LAN address, an admin source, a live ssh peer, the gateway, a DNS resolver, this host.",
        f"  set a kernel setting [{on('allow_sysctl')}]: an allowlisted sysctl off its safe value, at runtime "
        "(until undone or the next reboot).",
        "  ASKS FIRST, always: anything whose evidence can be forged (a port scan's packet source, an ARP or DHCP "
        f"reply: LAN quarantine for {NET_TTL // 60} min), every gateway/AP/endpoint action, hand-picked ids.",
        "  ONLY REPORTED, never acted on: a new listening port (e.g. 4444) unless its PROCESS matches a rule "
        "above; a new device on the LAN (a medium alert); changed persistence files, keys, DNS, Wi-Fi; pending "
        "updates and vulnerable packages. Closing a port or service, sshd_config and ufw policy are proposals "
        "with the exact command.",
        "  WHERE ALERTS GO: the alert queue (/defender alerts), the chat's screen while it is open, and a desktop "
        f"notification when the profile's notify is on (now: {'on' if p.get('notify') else 'off'}).",
        f"  WHEN: a sweep on request, or every N s while the watcher runs ({watching or 'watcher off'}). The watcher "
        "lives and dies with this chat: nothing sweeps while no gnoc chat is open.",
        "  SWITCHES (the user types these; no tool call sets them): /defender auto on [secs] (watch AND act), "
        "/defender watch on [secs] (alert only), /defender watch off, /defender auto off (this chat stops "
        "acting; there is NO timed off: turn it back on with /defender auto on), /defender allow|deny "
        "block|contain|sysctl|quarantine (per kind), /defender alerts ack|resolve <id>.",
    ])


def slash_for(args):
    """The /defender command the user types for a defend call that waits on their yes, or ''. At the approval wall the
    lead told them to "run gnoc chat -s-p" to acknowledge one alert, and wrote that it was acknowledged (defense
    drive 2026-11-22)."""
    a = args if isinstance(args, dict) else {}
    act = str(a.get("action") or "").lower()
    op = str(a.get("op") or "").lower()
    one = re.sub(r"[^A-Za-z0-9_.:-]", "", str(a.get("id") or ""))[:40]
    if act == "alerts" and op in ("ack", "acknowledge", "resolve", "suppress", "mute", "reopen") and one:
        return f"/defender alerts {'ack' if op == 'acknowledge' else op} {one}"
    if act == "undo":
        ids = a.get("ids")
        ids = " ".join(re.findall(r"d\d+", " ".join(map(str, ids)) if isinstance(ids, (list, tuple)) else str(ids or "")))
        return f"/defender undo {ids or 'last'}"
    if act == "triage" and op and one:
        return f"/defender triage {one} {op}"
    if act == "auto" and op in ("on", "off"):
        return f"/defender auto {op}"
    ids = a.get("ids")
    ids = [str(x) for x in ids] if isinstance(ids, (list, tuple)) else re.findall(r"[\w:/.\-]+", str(ids or ""))
    if act == "respond" and ids and all(i.startswith(("drift:", "net:")) for i in ids):
        # a change he made himself is ACCEPTED into the baseline, not "applied" (drive 2026-11-23)
        return "/defender baseline accept " + ("network" if all(i.startswith("net:") for i in ids)
                                               else "host" if all(i.startswith("drift:") for i in ids) else "")
    return ""


def auto_defense_on(profile, state=None):
    """Auto-defense is ON by default. This chat's explicit /defender auto on/off overrides the host
    profile; with no explicit choice, the profile's auto_defense decides."""
    mark = (state or {}).get("auto")
    if mark is True:
        return True
    if mark is False:
        return False
    return bool((profile or {}).get("auto_defense", True))


def needs_approval(state, args):
    """The chat's approval rule for defend(action=respond, apply=true). AUTO-DEFENSE is the default
    (2026-11-18), so a plan made only of kinds the profile already allows runs unasked. Naming
    ids is always their call; switching auto off always asks."""
    act = str(args.get("action") or "").lower()
    op = str(args.get("op") or "").lower()
    # reversing containment or muting an alert is as consequential as acting: an injected instruction could
    # unblock an attacker or close the incident (QAQC 2026-11-19)
    if act == "undo" or (act == "alerts" and op in ("suppress", "mute", "ack", "clear")) or \
            (act == "triage" and op in ("close", "false_positive", "false-positive", "dismiss", "resolve")):
        return True
    if act == "auto":
        return True   # switching auto-defense on or off is his decision, every time
    if act != "respond":
        return False
    ap = args.get("apply")
    if not (ap is True or str(ap).strip().lower() in ("true", "yes", "1", "on")):
        return False
    if args.get("ids"):
        return True   # hand-picked findings may include kinds the profile does not allow: his call, every time
    if str(args.get("target") or "").strip() and str(args.get("op") or "").strip().lower().replace("_", "-") in (
            "block", "block-ip"):
        # an address named in the call is an order, not evidence: his yes, every time. One the anti-lockout rules
        # refuse anyway is not asked about: the refusal itself is the answer ("203.0.113.9 is not public" was hidden
        # behind the approval wall, and the lead told him it was "actively scanning" him; drive 2026-11-22).
        try:
            ip = str(args.get("target")).strip().split("/")[0]
            f = _f(f"operator:block:{ip}", "high", "operator", "", "", {"kind": "block_ip", "ip": ip, "ttl": BLOCK_TTL})
            rows = plan([f], load_profile((state or {}).get("target")), (state or {}).get("target"))
            if rows and rows[0][1] == "refused":
                return False
        except Exception:  # noqa: BLE001 - when unsure, ask
            pass
        return True
    prof = load_profile((state or {}).get("target"))
    return not auto_defense_on(prof, state)
