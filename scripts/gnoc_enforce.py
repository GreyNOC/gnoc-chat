"""gnoc_enforce.py - enforcement on LAN/WLAN endpoints and on the gateway or AP.

The defender can already quarantine a LAN offender on THIS host. This module is the next ring: act on the
device itself (Linux endpoint over SSH, with the root helper installed there) or at the shared control point
(gateway/AP over SSH, or the controller's HTTP API). Every operation returns an undo where an undo is
possible, and every operation is selected by the user; `proposals()` only proposes, it never runs anything.

Supported backends, chosen from the per-host profile:
  gateway_ssh       key-based ssh destination, platform = generic|linux|openwrt|pfsense|opnsense|hostapd
  gateway_platform  the adapter used by gateway_ssh
  gateway_wifi_iface  hostapd interface for deauth/deny_acl on an AP
  gateway_api       {"kind": "unifi"|"generic", ...}; see api_call()
  endpoints         ["user@host", ...] Linux endpoints with the defender helper installed

No credentials are stored here. An API token is read from the environment variable named by
`gateway_api.token_env`; SSH uses the user's existing key (BatchMode, never a password prompt).
"""
import ipaddress
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

import gnoc_defend as D

DEFAULT_TTL = 1800
NFT_TABLE = "gnoc_enforce"
ENDPOINT_HELPER = "/usr/local/sbin/gnoc-defender-helper"

GATEWAY_KINDS = {"gateway_block_ip", "gateway_block_mac", "gateway_deauth",
                 "gateway_unblock_ip", "gateway_unblock_mac"}
ENDPOINT_KINDS = {"endpoint_isolate", "endpoint_unisolate", "endpoint_kill", "endpoint_pause",
                  "endpoint_resume", "endpoint_block_ip", "endpoint_release"}
KINDS = GATEWAY_KINDS | ENDPOINT_KINDS

# Gateway and endpoint changes are the operator's decision every time. They are never auto-applied by the
# watcher, even when the profile has a permission set; the user asked to be asked on an active intrusion.
ALWAYS_ASK = KINDS

_NFT_SCRIPT = """table inet %s {
  set blocked4 { type ipv4_addr; flags timeout; }
  set blocked6 { type ipv6_addr; flags timeout; }
  set blocked_macs { type ether_addr; flags timeout; }
  chain input { type filter hook input priority -10; policy accept;
    ip saddr @blocked4 counter drop
    ip6 saddr @blocked6 counter drop
    ether saddr @blocked_macs counter drop
  }
  chain forward { type filter hook forward priority -10; policy accept;
    ip saddr @blocked4 counter drop
    ip6 saddr @blocked6 counter drop
    ether saddr @blocked_macs counter drop
  }
}
""" % NFT_TABLE


def cfg(profile):
    return (profile or {}).get("enforcement") or {}


def endpoints(profile):
    """The configured Linux endpoints, as ssh destinations."""
    return [str(e).strip() for e in (profile or {}).get("endpoints") or [] if str(e).strip()]


def gateway_dest(profile):
    return str((profile or {}).get("gateway_ssh") or cfg(profile).get("ssh") or "").strip()


def gateway_platform(profile):
    return str((profile or {}).get("gateway_platform") or cfg(profile).get("platform") or "generic").lower()


def gateway_iface(profile):
    return str((profile or {}).get("gateway_wifi_iface") or cfg(profile).get("wifi_iface") or "").strip()


def gateway_api(profile):
    api = (profile or {}).get("gateway_api") or cfg(profile).get("api") or {}
    return api if isinstance(api, dict) else {}


def valid_dest(value):
    """An ssh destination (user@host or host[:port]), never one that ssh would parse as an option."""
    s = str(value or "").strip()
    if not s or s.startswith("-"):
        return False
    if any(part.startswith("-") for part in s.split("@")):
        return False
    return bool(re.fullmatch(r"(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9._:\[\]-]+", s))


def valid_mac(value):
    """A unicast Ethernet MAC. Broadcast/multicast MACs are not a device identity to block."""
    s = str(value or "").strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", s):
        return False
    return not (int(s[:2], 16) & 0x1)


def _ip(value):
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def _blockable_ip(value):
    """A unicast, non-loopback, non-unspecified address is worth sending to a firewall."""
    ip = _ip(value)
    return bool(ip and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_reserved))


def _ttl(value, default=DEFAULT_TTL):
    try:
        n = int(value)
    except (TypeError, ValueError):
        n = int(default)
    return max(60, min(86400, n))


def _brief(value, limit=300):
    s = re.sub("\x1b\\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]",
               "", str(value or ""))
    return re.sub(r"\s+", " ", s).strip()[:limit]


def _api_supports(api, op):
    """Whether the configured controller API can do `op` (block_ip, unblock_ip, block_mac, deauth ...)."""
    if not api:
        return False
    if str((api or {}).get("kind") or "").lower() == "unifi":
        return op in ("block_mac", "unblock_mac", "deauth")
    return True


def expires(kind, platform="", api=None):
    """True when the enforcement point drops the block by itself after its ttl (nft sets with timeouts).
    pf tables, hostapd deny_acl and controller APIs keep it until it is undone."""
    platform = str(platform or "").lower()
    if kind == "gateway_block_ip":
        return not (platform in ("pfsense", "opnsense", "pf") or _api_supports(api, "block_ip"))
    if kind == "gateway_block_mac":
        return not (platform in ("hostapd", "ap") or _api_supports(api, "block_mac"))
    return kind in ("endpoint_isolate", "endpoint_block_ip")


def _for(kind, platform="", api=None):
    return f"for {DEFAULT_TTL}s" if expires(kind, platform, api) else "until /defender undo (no expiry on this platform)"


def capabilities(profile):
    """{op: reason} for what this profile can actually enforce right now."""
    out = {}
    dest, platform = gateway_dest(profile), gateway_platform(profile)
    api = gateway_api(profile)
    if api:
        if str(api.get("kind") or "").lower() == "unifi":
            out["gateway_block_mac"] = out["gateway_deauth"] = "UniFi controller API"
        else:
            out["gateway_block_ip"] = out["gateway_block_mac"] = out["gateway_deauth"] = "controller API"
    if dest:
        if platform in ("pfsense", "opnsense", "pf"):
            out["gateway_block_ip"] = "pfctl table"
        elif platform in ("hostapd", "ap"):
            out["gateway_block_mac"] = out["gateway_deauth"] = "hostapd_cli"
        else:
            out["gateway_block_ip"] = out["gateway_block_mac"] = "nft table"
            if gateway_iface(profile):
                out["gateway_deauth"] = "hostapd_cli"
    if endpoints(profile):
        for op in ("endpoint_isolate", "endpoint_unisolate", "endpoint_kill", "endpoint_pause",
                   "endpoint_resume", "endpoint_block_ip", "endpoint_release"):
            out[op] = "endpoint helper over SSH"
    return out


def _own_or_gateway(value, profile, dest=None):
    v = str(value or "").strip().lower()
    if v in {str(g).lower() for g in (profile or {}).get("gateways") or []}:
        return True
    if v in {str(m).lower() for m in ((profile or {}).get("gateway_macs") or {}).values()}:
        return True
    try:
        addr = ipaddress.ip_address(v)
        for net in (profile or {}).get("admin_sources") or []:
            try:
                if addr in ipaddress.ip_network(str(net), strict=False):
                    return True
            except ValueError:
                continue
        with D.on_host(dest):
            own = {str(a) for a in D.own_addrs()}
        if str(addr) in own:
            return True
    except ValueError:
        pass
    return False


def check(act, profile):
    """(ok, why) before an enforcement action; anti-lockout is enforced here as well as in the helper."""
    act = act if isinstance(act, dict) else {}
    k = str(act.get("kind") or "")
    if k not in KINDS:
        return False, f"unknown enforcement kind {k!r}"
    caps = capabilities(profile)
    if k.startswith("gateway_"):
        base = k.replace("unblock", "block", 1)
        if base not in caps:
            return False, f"{base} is not supported by the configured gateway/AP backend"
    if k in ("gateway_block_mac", "gateway_deauth") and gateway_platform(profile) in ("hostapd", "ap") \
            and not act.get("iface") and not act.get("api"):
        return False, "no gateway_wifi_iface configured for hostapd"
    if k.startswith("gateway_block_ip") or k == "endpoint_block_ip" or k in ("gateway_block_mac", "gateway_deauth"):
        value = act.get("ip") or act.get("mac") or ""
        source = str(act.get("dest") or "") if k.startswith("endpoint_") else None
        if _own_or_gateway(value, profile, source):
            return False, f"{value} is the gateway, a gateway MAC, or the target host: never blocked"
        if k.endswith("block_ip") and not _blockable_ip(value):
            return False, f"{value!r} is not a blockable IP address"
        if not k.endswith("block_ip") and not valid_mac(value):
            return False, f"{value!r} is not a unicast MAC address"
    if k in ("gateway_unblock_ip", "endpoint_release") and not _ip(act.get("ip")):
        return False, f"{act.get('ip')!r} is not an IP address"
    if k.startswith("endpoint_"):
        dest = str(act.get("dest") or "").strip()
        if not dest:
            return False, "no endpoint SSH destination configured for this action"
        if dest not in endpoints(profile):
            return False, f"{dest} is not a configured endpoint; add it first (/defender endpoint add {dest})"
        if k in ("endpoint_kill", "endpoint_pause"):
            try:
                pid = int(act.get("pid") or 0)
            except (TypeError, ValueError):
                pid = 0
            if pid <= 1:
                return False, "pid must be above 1"
    return True, "operator approval required"


# ---------------------------------------------------------------- gateway SSH / nft / pf / hostapd

def _ssh(dest, argv, timeout=40):
    with D.on_host(dest):
        return D._run(argv, timeout)


def _ssh_script(dest, script, timeout=60):
    with D.on_host(dest):
        return D._run(["sh", "-c", script], timeout)


def _ensure_nft(dest):
    rc, _ = _ssh(dest, ["nft", "list", "table", "inet", NFT_TABLE], 15)
    if rc == 0:
        return True, ""
    rc, out = _ssh_script(dest, "nft -f - <<'GNOC_EOF'\n" + _NFT_SCRIPT + "GNOC_EOF\n", 30)
    return rc == 0, out   # (ok, out): _gateway_nft reads a bool, not a return code


def _nft_element(dest, setname, value, ttl=None, delete=False):
    action = "delete" if delete else "add"
    expr = f"{{ {value} }}" if delete or not ttl else f"{{ {value} timeout {int(ttl)}s }}"
    rc, out = _ssh(dest, ["nft", action, "element", "inet", NFT_TABLE, setname, expr], 20)
    if not delete and rc and "exists" in out.lower():
        _ssh(dest, ["nft", "delete", "element", "inet", NFT_TABLE, setname, f"{{ {value} }}"], 20)
        rc, out = _ssh(dest, ["nft", "add", "element", "inet", NFT_TABLE, setname, expr], 20)
    return rc == 0, out.strip()


def _gateway_nft(dest):
    ok, out = _ensure_nft(dest)
    return ok, ("nft table ready" if ok else "nft table failed: " + out[:200])


def _hostapd(dest, iface, argv):
    if not iface:
        return False, "no gateway_wifi_iface configured for hostapd"
    rc, txt = _ssh(dest, ["hostapd_cli", "-i", iface, *argv], 20)
    return rc == 0, txt


def _pf(dest, add, value):
    return _ssh(dest, ["pfctl", "-t", "gnoc_block", "-T", "add" if add else "delete", str(value)], 20)


# ---------------------------------------------------------------- endpoint helper

def _endpoint_helper(dest, argv):
    with D.on_host(dest):
        return D._run(["sudo", "-n", ENDPOINT_HELPER, *map(str, argv)], 45)


def _endpoint_result(dest, argv):
    rc, out = _endpoint_helper(dest, argv)
    if rc != 0:
        return False, out.strip()[:300]
    return True, out.strip()


# ---------------------------------------------------------------- HTTP API

def _api_headers(api):
    headers = {str(k): str(v) for k, v in (api.get("headers") or {}).items()}
    token_env = str(api.get("token_env") or "").strip()
    token = os.environ.get(token_env, "") if token_env else ""
    if token:
        if str(api.get("kind") or "").lower() == "unifi":
            headers.setdefault("X-API-KEY", token)
        else:
            headers.setdefault("Authorization", "Bearer " + token)
    return headers


def _api_url_ok(url, api):
    try:
        p = urllib.parse.urlparse(str(url))
    except ValueError:
        return False
    if p.scheme not in ("http", "https") or not p.hostname:
        return False
    if p.username or p.password:
        return False  # credentials belong in the controller's env/token, never in a saved URL
    if any(re.search(r"token|key|secret|passw|auth", k, re.I)
           for k, _v in urllib.parse.parse_qsl(p.query, keep_blank_values=True)):
        return False
    metadata = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata",
                "metadata.google.internal"}
    if str(p.hostname).lower() in metadata:
        return False
    allow_public = bool(api.get("allow_public"))
    try:
        ip = ipaddress.ip_address(p.hostname)
        if ip.is_global and not allow_public:
            return False
    except ValueError:
        # Resolve the name and judge the addresses, not the suffix: a .local name can still resolve public.
        host = str(p.hostname).lower()
        private_name = host.endswith((".local", ".lan", ".home", ".internal", ".localdomain")) or "." not in host
        try:
            addrs = {info[4][0].split("%")[0] for info in socket.getaddrinfo(p.hostname, None)}
        except OSError:
            if not (private_name or allow_public):
                return False
            addrs = set()
        for addr in addrs:
            try:
                if ipaddress.ip_address(addr).is_global and not allow_public:
                    return False
            except ValueError:
                return False
        if not addrs and not (private_name or allow_public):
            return False
    if p.scheme == "http" and allow_public:
        return False
    return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A controller must not be able to bounce the approved call to a different host or scheme."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_API_OPENER = urllib.request.build_opener(_NoRedirect)


def _api_call(api, op, value="", ttl=DEFAULT_TTL):
    kind = str(api.get("kind") or "generic").lower()
    base = str(api.get("url") or "").rstrip("/")
    if not base or not _api_url_ok(base, api):
        return False, "gateway API url is missing or not allowed (private/loopback, or allow_public with HTTPS)"
    headers = _api_headers(api)
    site = str(api.get("site") or "default")
    if kind == "unifi":
        # UniFi Network application: block/unblock/kick a station by MAC.
        cmd = {"block_mac": "block-sta", "unblock_mac": "unblock-sta", "deauth": "kick-sta"}.get(op)
        if not cmd:
            return False, f"unifi API does not support {op} (only MAC block/unblock/deauth)"
        url = f"{base}/api/s/{urllib.parse.quote(site)}/cmd/stamgr"
        body = {"cmd": cmd, "mac": str(value).lower()}
        headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers=headers)
    else:
        template = api.get(op) or api.get(op.replace("_", "-")) or {}
        if not template:
            return False, f"gateway API has no {op} template"
        if isinstance(template, str):
            template = {"url": base + template, "method": "POST", "body": "{}"}
        url = str(template.get("url") or base)
        body = template.get("body")
        if isinstance(body, str):
            try:
                body = body.format(ip=value, mac=str(value).lower(), ttl=int(ttl), op=op)
            except (KeyError, IndexError, ValueError) as e:
                return False, f"gateway API template has a bad placeholder: {type(e).__name__}: {e}"
            try:
                body = json.loads(body)
            except ValueError:
                pass
        try:
            data = body.encode() if isinstance(body, str) else (json.dumps(body).encode() if body is not None else None)
        except (TypeError, ValueError) as e:
            return False, f"gateway API body is not JSON-safe: {type(e).__name__}"
        headers.update({str(k): str(v) for k, v in (template.get("headers") or {}).items()})
        if data is not None:
            headers.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(url, data=data, method=str(template.get("method") or "POST").upper(),
                                     headers=headers)
    if not _api_url_ok(req.full_url, api):
        return False, "refused: API target is not allowed"
    try:
        with _API_OPENER.open(req, timeout=15) as resp:
            text = resp.read(300).decode("utf-8", "replace")
            return 200 <= resp.status < 300, f"HTTP {resp.status}: {text}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read(200).decode('utf-8', 'replace')}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"API call failed: {type(e).__name__}: {str(e)[:200]}"


def _api_ping(api):
    """A read-only controller check: GET, never a kick or a block."""
    base = str(api.get("url") or "").rstrip("/")
    kind = str(api.get("kind") or "generic").lower()
    url = (f"{base}/api/s/{urllib.parse.quote(str(api.get('site') or 'default'))}/stat/health"
           if kind == "unifi" else base)
    if not _api_url_ok(url, api):
        return False, "API url is missing or not allowed"
    req = urllib.request.Request(url, method="GET", headers=_api_headers(api))
    try:
        with _API_OPENER.open(req, timeout=15) as resp:
            return 200 <= resp.status < 300, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


# ---------------------------------------------------------------- run / undo

def run(act):
    """(ok, output, undo_act) for one enforcement action. No action is taken without an already-approved call."""
    act = act if isinstance(act, dict) else {}
    k = str(act.get("kind") or "")
    ttl = _ttl(act.get("ttl"))
    dest = str(act.get("dest") or "").strip()
    value = act.get("ip") or act.get("mac") or act.get("pid")
    platform = str(act.get("platform") or "").lower()
    if k in ("gateway_block_ip", "endpoint_block_ip") and not _blockable_ip(value):
        return False, f"{value!r} is not a blockable IP address", None
    if k in ("gateway_block_mac", "gateway_deauth", "gateway_unblock_mac") and not valid_mac(value):
        return False, f"{value!r} is not a unicast MAC address", None
    if k in ("gateway_unblock_ip", "endpoint_release") and not _ip(value):
        return False, f"{value!r} is not an IP address", None
    if k in ("endpoint_kill", "endpoint_pause", "endpoint_resume"):
        try:
            pid = int(act.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        if pid <= 1:
            return False, "pid must be above 1", None
    if k.startswith("gateway_") and not dest and not act.get("api"):
        return False, "no gateway SSH destination configured for this action", None
    if dest and not valid_dest(dest):
        return False, f"{dest!r} is not a safe ssh destination", None
    if k.startswith("endpoint_") and not dest:
        return False, "no endpoint SSH destination configured for this action", None
    if k == "gateway_block_ip":
        if platform in ("pfsense", "opnsense", "pf"):
            rc, out = _pf(dest, True, value)
            return rc == 0, out, {"kind": "gateway_unblock_ip", "ip": value, "dest": dest,
                                  "platform": platform}
        if _api_supports(act.get("api"), "block_ip"):
            ok, out = _api_call(act["api"], "block_ip", value, ttl)
        elif not dest:
            return False, "the controller API cannot block an IP and no gateway SSH destination is set", None
        else:
            ok0, out0 = _gateway_nft(dest)
            if not ok0:
                return False, out0, None
            ip = _ip(value)
            ok, out = _nft_element(dest, "blocked6" if ip.version == 6 else "blocked4", value, ttl)
        return ok, out, {"kind": "gateway_unblock_ip", "ip": value, "dest": dest, "platform": platform,
                         "api": act.get("api")}
    if k == "gateway_block_mac":
        if platform in ("hostapd", "ap"):
            ok, out = _hostapd(dest, gateway_iface({"gateway_wifi_iface": act.get("iface")}), ["deny_acl", "add", value])
        elif act.get("api"):
            ok, out = _api_call(act["api"], "block_mac", value, ttl)
        else:
            ok0, out0 = _gateway_nft(dest)
            if not ok0:
                return False, out0, None
            ok, out = _nft_element(dest, "blocked_macs", value, ttl)
        return ok, out, {"kind": "gateway_unblock_mac", "mac": value, "dest": dest, "platform": platform,
                         "iface": act.get("iface"), "api": act.get("api")}
    if k == "gateway_unblock_ip":
        ip = _ip(value)
        if not ip:
            return False, f"{value!r} is not an IP address", None
        if platform in ("pfsense", "opnsense", "pf"):
            rc, out = _pf(dest, False, value)
            return rc == 0, out, None
        if _api_supports(act.get("api"), "unblock_ip"):
            return (*_api_call(act["api"], "unblock_ip", value, ttl), None)
        ok, out = _nft_element(dest, "blocked6" if ip.version == 6 else "blocked4", value, delete=True)
        return ok, out, None
    if k == "gateway_unblock_mac":
        if platform in ("hostapd", "ap"):
            ok, out = _hostapd(dest, act.get("iface") or "", ["deny_acl", "del", value])
        elif act.get("api"):
            return (*_api_call(act["api"], "unblock_mac", value, ttl), None)
        else:
            ok, out = _nft_element(dest, "blocked_macs", value, delete=True)
        return ok, out, None
    if k == "gateway_deauth":
        if act.get("api"):
            return (*_api_call(act["api"], "deauth", value, ttl), None)
        ok, out = _hostapd(dest, act.get("iface") or "", ["deauthenticate", value])
        return ok, out, None
    if k == "endpoint_isolate":
        ok, out = _endpoint_result(dest, ["isolate", ttl])
        # the helper prints a one-time token; only its holder (this journal, on GreyNOC's machine) can lift the
        # isolation early, so the contained account cannot lift its own (QAQC 2026-11-19)
        m = re.search(r"(?m)^token=([0-9a-f]{32})$", out or "")
        out = re.sub(r"(?m)^token=[0-9a-f]{32}\n?", "", out or "").strip()
        return ok, out, ({"kind": "endpoint_unisolate", "dest": dest, "token": m.group(1)} if ok and m else None)
    if k == "endpoint_unisolate":
        token = str(act.get("token") or "")
        if not re.fullmatch(r"[0-9a-f]{32}", token):
            return False, ("unisolate needs the token from the isolation (it is in the defender journal: "
                           "/defender undo lifts it); the isolation also ends by itself at its TTL"), None
        ok, out = _endpoint_result(dest, ["unisolate", token])
        return ok, out, None
    if k in ("endpoint_pause", "endpoint_kill", "endpoint_resume"):
        verb = {"endpoint_pause": "pause", "endpoint_kill": "kill", "endpoint_resume": "resume"}[k]
        ok, out = _endpoint_result(dest, [verb, int(act.get("pid") or 0)])
        undo = {"kind": "endpoint_resume", "dest": dest, "pid": int(act.get("pid") or 0)} \
            if k == "endpoint_pause" else None
        return ok, out, undo
    if k == "endpoint_block_ip":
        ip = _ip(value)
        if not ip:
            return False, f"{value!r} is not an IP", None
        verb = "block" if ip.is_global else "quarantine"
        ok, out = _endpoint_result(dest, [verb, value, ttl])
        return ok, out, {"kind": "endpoint_release", "dest": dest, "ip": value}
    if k == "endpoint_release":
        ip = _ip(value)
        verb = "unblock" if ip and ip.is_global else "release"
        ok, out = _endpoint_result(dest, [verb, value])
        return ok, out, None
    return False, f"unknown enforcement kind {k!r}", None


# ---------------------------------------------------------------- proposals

def _targets(findings):
    out = []
    for f in findings or []:
        if not isinstance(f, dict) or str(f.get("sev")) not in ("crit", "high"):
            continue
        text = f"{f.get('id', '')} {f.get('fact', '')}"
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if _blockable_ip(m):
                out.append(("ip", m, f))
        for m in re.findall(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", text):
            if valid_mac(m):
                out.append(("mac", m.lower(), f))
        if len(out) >= 256:
            break
    return out


def proposals(findings, profile, host="this machine", limit=8, source_dest=None):
    """[finding] containment options for an active/high finding. These are always ASK, never auto-run."""
    caps = capabilities(profile)
    if not caps:
        return []
    dest, platform = gateway_dest(profile), gateway_platform(profile)
    iface = gateway_iface(profile)
    api = gateway_api(profile)
    out, seen = [], set()
    for kind, value, src in _targets(findings):
        if _own_or_gateway(value, profile, source_dest):
            continue
        if kind == "ip" and f"gateway_block_ip:{value}" not in seen and "gateway_block_ip" in caps:
            seen.add(f"gateway_block_ip:{value}")
            out.append({"id": f"enforce:gateway-block-ip:{value}", "sev": "info", "area": "enforcement",
                        "fact": f"containment option: block {value} at the gateway/AP "
                                f"{_for('gateway_block_ip', platform, api)}",
                        "fix": f"/defender enforce block-ip {value}",
                        "act": {"kind": "gateway_block_ip", "ip": value, "ttl": DEFAULT_TTL, "dest": dest,
                                "platform": platform, "api": api}})
        if kind == "mac" and f"gateway_block_mac:{value}" not in seen and "gateway_block_mac" in caps:
            seen.add(f"gateway_block_mac:{value}")
            out.append({"id": f"enforce:gateway-block-mac:{value}", "sev": "info", "area": "enforcement",
                        "fact": f"containment option: deny MAC {value} at the gateway/AP "
                                f"{_for('gateway_block_mac', platform, api)}",
                        "fix": f"/defender enforce block-mac {value}",
                        "act": {"kind": "gateway_block_mac", "mac": value, "ttl": DEFAULT_TTL, "dest": dest,
                                "platform": platform, "iface": iface, "api": api}})
        if kind == "mac" and f"gateway_deauth:{value}" not in seen and "gateway_deauth" in caps:
            seen.add(f"gateway_deauth:{value}")
            out.append({"id": f"enforce:gateway-deauth:{value}", "sev": "info", "area": "enforcement",
                        "fact": f"containment option: deauthenticate Wi-Fi client {value}",
                        "fix": f"/defender enforce deauth {value}",
                        "act": {"kind": "gateway_deauth", "mac": value, "dest": dest, "platform": platform,
                                "iface": iface, "api": api}})
    # Endpoint options: an endpoint that matches the host, an offender IP, or the source of a high finding.
    for dest in endpoints(profile):
        source_hit = any(str(f.get("dest") or "") == dest and str(f.get("sev")) in ("crit", "high")
                         for f in findings or [])
        hit = source_hit or host in dest or any(str(dest).split("@")[-1] == value
                                                for _k, value, _s in _targets(findings))
        if not hit or f"endpoint_isolate:{dest}" in seen:
            continue
        seen.add(f"endpoint_isolate:{dest}")
        out.append({"id": f"enforce:endpoint-isolate:{dest}", "sev": "info", "area": "enforcement",
                    "fact": f"containment option: isolate endpoint {dest} for {DEFAULT_TTL}s (keeps the admin SSH path)",
                    "fix": f"/defender enforce isolate {dest}",
                    "act": {"kind": "endpoint_isolate", "dest": dest, "ttl": DEFAULT_TTL}})
    # A malicious pid can be killed only on the endpoint where the sweep actually saw it. Never carry a
    # local PID to an arbitrary endpoint: PIDs are host-local and the wrong one kills the wrong process.
    for f in findings or []:
        act = f.get("act") or {}
        if act.get("kind") != "pause_pid" or not act.get("pid"):
            continue
        source = str(f.get("dest") or source_dest or "")
        if source not in endpoints(profile):
            continue
        key = f"endpoint_kill:{source}:{act['pid']}"
        if key in seen:
            continue
        seen.add(key)
        out.append({"id": f"enforce:endpoint-kill:{source}:{act['pid']}", "sev": "info", "area": "enforcement",
                    "fact": f"containment option: kill pid {act['pid']} ({act.get('comm', '?')}) on {source}",
                    "fix": f"/defender enforce kill {source} {act['pid']}",
                    "act": {"kind": "endpoint_kill", "dest": source, "pid": int(act["pid"])}})
        if len(out) >= limit:
            break
    return out[:limit]


# ---------------------------------------------------------------- setup and tests

def setup_steps(profile, scope=None):
    """The guided setup the chat shows the user. It never runs these commands itself."""
    dest, platform = gateway_dest(profile), gateway_platform(profile)
    eps = endpoints(profile)
    # "Setup Complete. The endpoint quarantine is now configured." after only this checklist was read (batch 6,
    # 2026-11-23): nothing here changes anything, and the header says so.
    lines = ["ENDPOINT / GATEWAY ENFORCEMENT SETUP",
             "NOTHING WAS SET UP: these are the steps the user runs themselves, in order. Until the user has, no endpoint or "
             "gateway is configured; /defender endpoint list shows what is.", ""]
    lines.append("1. SSH KEY (one key, no passwords). Run this yourself on this machine:")
    lines.append("   ssh-keygen -t ed25519 -f ~/.ssh/gnoc-defender -N ''")
    lines.append("   Then copy the public key to each control point:")
    lines.append("   ssh-copy-id -i ~/.ssh/gnoc-defender.pub <user@host>")
    lines.append("   Test it with BatchMode (this is exactly how the defender connects):")
    lines.append("   ssh -i ~/.ssh/gnoc-defender -o BatchMode=yes <user@host> hostname")
    lines.append("")
    lines.append("2. GATEWAY / AP (block IP, deny MAC, deauth a Wi-Fi client):")
    lines.append("   /defender gateway ssh <user@gateway>")
    lines.append("   /defender gateway platform generic|openwrt|pfsense|opnsense|hostapd|unifi")
    lines.append("   /defender gateway iface <wifi-interface>   (hostapd/AP only)")
    lines.append("   /defender gateway test")
    lines.append("   OpenWrt/generic Linux needs nft; pfSense needs a persistent table named gnoc_block;")
    lines.append("   hostapd needs hostapd_cli and macaddr_acl/deny_mac_file enabled.")
    lines.append("")
    lines.append("3. LINUX ENDPOINTS (isolate, pause/kill a process, block an IP locally):")
    lines.append("   Copy the helper to each endpoint and install it root-owned:")
    lines.append("   scp scripts/gnoc-defender-helper <user@endpoint>:/tmp/gnoc-defender-helper")
    lines.append("   ssh <user@endpoint> 'sudo install -o root -g root -m 0755 "
                 "/tmp/gnoc-defender-helper /usr/local/sbin/gnoc-defender-helper'")
    lines.append("   ssh <user@endpoint> 'echo \"$USER ALL=(root) NOPASSWD: /usr/local/sbin/gnoc-defender-helper\" "
                 "| sudo tee /etc/sudoers.d/gnoc-defender && sudo chmod 0440 /etc/sudoers.d/gnoc-defender'")
    lines.append("   /defender endpoint add <user@endpoint>")
    lines.append("   /defender endpoint test <user@endpoint>")
    lines.append("")
    lines.append("4. CONTROLLER API (UniFi first; generic HTTP is configurable):")
    lines.append("   Put the token in an environment variable, never in a message:")
    lines.append("   export GNOC_GATEWAY_TOKEN=...        (UniFi: X-API-KEY)")
    lines.append("   /defender gateway api https://controller:8443")
    lines.append("   /defender gateway api-kind unifi")
    lines.append("   /defender gateway api-site default")
    lines.append("   /defender gateway api-token-env GNOC_GATEWAY_TOKEN")
    lines.append("   /defender gateway test")
    lines.append("")
    lines.append("Current configuration:")
    lines.append(f"   gateway ssh: {dest or '(not set)'}   platform: {platform}")
    lines.append(f"   gateway api: {'configured' if gateway_api(profile) else '(not set)'}")
    lines.append(f"   endpoints:   {', '.join(eps) or '(none)'}")
    lines.append("")
    lines.append("Nothing here runs automatically. When an intrusion is confirmed the bot proposes the exact")
    lines.append("action and waits for your yes before it touches a gateway or an endpoint.")
    return "\n".join(lines)


def gateway_test(profile):
    """Test every configured control path, not just the first one: an API can be up while the SSH fallback
    is dead, and the operator needs to know before an incident."""
    parts = []
    api = gateway_api(profile)
    if api:
        ok, out = _api_ping(api)
        parts.append(f"gateway API: {'reachable' if ok else 'FAILED'}: {_brief(out, 300)}")
    dest = gateway_dest(profile)
    if dest:
        rc, out = _ssh(dest, ["hostname"], 20)
        if rc != 0:
            parts.append(f"gateway SSH {dest}: FAILED: {_brief(out, 300)}")
        else:
            platform = gateway_platform(profile)
            probe = (["pfctl", "-s", "info"] if platform in ("pfsense", "opnsense", "pf")
                     else (["hostapd_cli", "-v"] if platform in ("hostapd", "ap") else ["nft", "--version"]))
            rc2, out2 = _ssh(dest, probe, 20)
            parts.append(f"gateway SSH {dest} reachable as {_brief(out, 80)}; {platform}: "
                         f"{'ready' if rc2 == 0 else 'NOT ready: ' + _brief(out2, 160)}")
    return "\n".join(parts) if parts else "gateway enforcement is not configured (run /defender setup)"


def endpoint_test(dest):
    dest = str(dest or "").strip()
    if not valid_dest(dest):
        return f"{dest!r}: not an ssh destination (user@host)"
    rc, out = _ssh(dest, ["hostname"], 20)
    if rc != 0:
        return f"{dest}: SSH failed: {_brief(out, 300)}"
    rc2, out2 = _endpoint_helper(dest, ["status"])
    return (f"{dest}: SSH ok ({_brief(out, 80)}); helper "
            f"{'ready' if rc2 == 0 else 'NOT installed/usable: ' + _brief(out2, 160)}")
