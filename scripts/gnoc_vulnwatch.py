#!/usr/bin/env python3
"""gnoc_vulnwatch.py - every hour: what vulnerabilities were newly announced, do they hit what this machine
runs, and is it defended against them.

    python3 scripts/gnoc_vulnwatch.py run [--quiet]      one pass: fetch, match, verify, alert, report
    python3 scripts/gnoc_vulnwatch.py status             the last pass and the timer
    python3 scripts/gnoc_vulnwatch.py timer on|off       the hourly systemd user timer
    python3 scripts/gnoc_vulnwatch.py npm add|rm <dir>   watch a project's package-lock.json
    python3 scripts/gnoc_vulnwatch.py pip add|rm <python> watch a Python environment's packages

In the chat: /defender vulnwatch [run|status|on|off|npm add <dir>|pip add <python>].

Each source is used for what it is precise at:
  announcements  CISA KEV (actively exploited, every entry checked every pass) and NVD (CVEs PUBLISHED since
                 the last pass, CVSS >= 7). Downloads only: nothing about this machine is sent.
  matching       the installed dpkg packages (binary + source names), the running kernel, the processes that
                 listen on the network, and a few non-dpkg binaries (ollama, node, docker, chrome, code).
  verification   a matched CVE is checked against Debian's own fixed version (OSV record DEBIAN-<CVE>, asked
                 by CVE id only) and the installed source version, so a backported fix reads as patched.
  dependencies   npm lockfiles and pip environments you name go to OSV's batch API (package name + version),
                 which is exact for those ecosystems.
  defended?      apt's pending security updates (local, exact), whether automatic security updates are on,
                 and whether the vulnerable package backs a network-facing service.

Every result is a defender finding (area "vuln"): it lands in the alert queue, deduplicated, and a new
high/critical one also raises a desktop notification. Patching needs root, so fixes are PROPOSALS with the
exact command: the chat and this job never run sudo.
"""
import contextlib
import datetime as _dt
import functools
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_defend as D  # noqa: E402
import gnoc_defender as G  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
UA = "gnoc-vulnwatch/1.0"
NVD_MIN_CVSS = 7.0
NVD_RECENT_DAYS = 7              # announced CVEs kept and RE-MATCHED every pass: software installed after an
                                 # announcement is still checked against it
NVD_MAX_WINDOW_H = NVD_RECENT_DAYS * 24   # first pass (or after a long gap): backfill the whole window
DEB_CACHE_TTL = 6 * 3600
DETAIL_CAP = 250                 # OSV lookups per pass (Debian records are cached, so only the first pass is heavy)
NVD_LOOKUP_CAP = 10              # per-CVE NVD lookups per pass, 6.5 s apart (NVD allows 5 per 30 s without a key)
APT_STALE_H = 48
TIMER = "gnoc-vulnwatch"
_LOCK = threading.Lock()

# CPE/KEV product -> the dpkg source/binary names (or extra binaries) that ship it. Anything not listed is
# tried as itself ("git" -> git). Keys are normalized: lowercase, runs of non-alphanumerics -> "_".
ALIASES = {
    "linux_kernel": ["@kernel"], "linux:kernel": ["@kernel"],
    "openssh": ["openssh"], "openbsd:openssh": ["openssh"],
    "glibc": ["glibc"], "gnu_c_library": ["glibc"], "c_library": ["glibc"],
    "chrome": ["chromium", "@google-chrome"], "chromium": ["chromium"], "chromium_v8": ["chromium", "@google-chrome"],
    "chromium_mojo": ["chromium", "@google-chrome"], "skia": ["chromium", "@google-chrome"],
    "firefox": ["firefox", "firefox-esr"], "firefox_esr": ["firefox-esr"], "thunderbird": ["thunderbird"],
    "node_js": ["nodejs", "@node"], "nodejs": ["nodejs", "@node"],
    "http_server": ["apache2"], "apache:http_server": ["apache2"], "nginx": ["nginx"],
    "polkit": ["policykit-1", "polkit"], "xz": ["xz-utils"], "xz_utils": ["xz-utils"],
    "libcurl": ["curl"], "curl": ["curl"], "openssl": ["openssl"], "gnutls": ["gnutls28"],
    "sudo": ["sudo"], "bash": ["bash"], "systemd": ["systemd"], "samba": ["samba"], "cups": ["cups"],
    "python": ["python3.13", "python3"], "cpython": ["python3.13", "python3"],
    "docker": ["docker.io", "@docker"], "docker_engine": ["docker.io", "@docker"], "runc": ["runc"],
    "containerd": ["containerd"], "ollama": ["@ollama"], "visual_studio_code": ["@code"],
    "vim": ["vim"], "git": ["git"], "exim": ["exim4"], "postgresql": ["postgresql-17"], "redis": ["redis"],
    "wireshark": ["wireshark"], "libxml2": ["libxml2"], "zlib": ["zlib"], "expat": ["expat"],
    "libwebp": ["libwebp"], "freetype": ["freetype"], "ghostscript": ["ghostscript"], "imagemagick": ["imagemagick"],
    "libreoffice": ["libreoffice"], "avahi": ["avahi"], "chrony": ["chrony"], "ntp": ["ntpsec", "ntp"],
    "wpa_supplicant": ["wpa"], "hostapd": ["wpa"], "networkmanager": ["network-manager"], "bluez": ["bluez"],
}
# names too generic to match on their own: "linux", "windows", "server", "kernel" from a non-Linux vendor ...
GENERIC_PRODUCTS = {"linux", "server", "client", "windows", "kernel", "firmware", "os", "router", "app",
                    "core", "library", "framework", "platform", "plugin", "api", "web", "admin", "manager"}
EXTRA_BINARIES = {"ollama": ["ollama", "--version"], "node": ["node", "--version"],
                  "docker": ["docker", "--version"], "google-chrome": ["google-chrome", "--version"],
                  "code": ["code", "--version"]}
# non-dpkg binaries whose upstream versions Debian tracks under another source package: Debian's fixed
# version is the version evidence (Google Chrome and Debian's chromium share the version scheme)
BINARY_DEBSRC = {"google-chrome": "chromium", "node": "nodejs", "@kernel": "linux"}
EXTRA_PATHS = [os.path.expanduser("~/.local/bin"), "/opt/google/chrome", "/snap/bin",
               os.path.expanduser("~/.nvm/current/bin"), "/usr/share/code/bin"]
# a listening process whose owner the kernel hides from this user: the usual package behind the port
PORT_PKG = {22: "openssh", 25: "exim4", 53: "bind9", 80: "nginx", 443: "nginx", 631: "cups", 5353: "avahi",
            123: "chrony", 3306: "mariadb", 5432: "postgresql-17", 6379: "redis", 139: "samba", 445: "samba",
            11434: "@ollama", 2375: "docker.io", 2376: "docker.io"}


# ---------------------------------------------------------------- state and config

def _path(name):
    return os.path.join(G.STATE, name)


def _load(name, default):
    try:
        with open(_path(name)) as fh:
            v = json.load(fh)
        return v if isinstance(v, type(default)) else default
    except (OSError, ValueError):
        return default


def _save(name, obj):
    G._atomic_json(_path(name), obj)


def config():
    c = _load("vulnwatch-config.json", {})
    c["npm"] = [str(x) for x in c.get("npm") or [] if isinstance(x, str)][:20]
    c["pip"] = [str(x) for x in c.get("pip") or [] if isinstance(x, str)][:10]
    c["min_cvss"] = float(c.get("min_cvss") or NVD_MIN_CVSS)
    return c


def set_config(kind, op, value):
    """npm|pip add|rm <value> -> message."""
    if kind not in ("npm", "pip") or op not in ("add", "rm"):
        return "usage: npm|pip add|rm <dir|python>"
    c = config()
    value = os.path.abspath(os.path.expanduser(str(value or "").strip()))
    if op == "add":
        if kind == "npm" and not os.path.isfile(os.path.join(value, "package-lock.json")):
            return f"refused: {value} has no package-lock.json"
        if kind == "pip" and not (os.path.isfile(value) and os.access(value, os.X_OK)):
            return f"refused: {value} is not an executable python"
        if value not in c[kind]:
            c[kind].append(value)
    else:
        c[kind] = [x for x in c[kind] if x != value]
    _save("vulnwatch-config.json", c)
    return f"vulnwatch {kind}: " + (", ".join(c[kind]) or "(none)")


# ---------------------------------------------------------------- network (bounded, never follows a target)

def http_json(url, data=None, timeout=40, etag=None):
    """(status, json or None, etag). 304 -> (304, None, etag). Errors -> (0, None, why)."""
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(64 * 1024 * 1024)
            return r.status, json.loads(raw.decode("utf-8", "replace")), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, None, etag
        return e.code, None, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return 0, None, f"{type(e).__name__}: {str(e)[:120]}"


# ---------------------------------------------------------------- versions

def upstream(v):
    """Debian version -> the upstream part: '1:10.3p1-1~bpo13+1' -> '10.3p1', '6.12.5-1' -> '6.12.5'."""
    v = str(v or "").split(":", 1)[-1]
    v = v.rsplit("-", 1)[0] if "-" in v else v
    return re.split(r"[+~]", v)[0]


@functools.lru_cache(maxsize=8192)
def vcmp(a, op, b):
    """dpkg version comparison (lt, le, eq, ge, gt), local and pure. False when either side is empty."""
    if not a or not b or not shutil.which("dpkg"):
        return False
    try:
        return subprocess.run(["dpkg", "--compare-versions", str(a), op, str(b)], timeout=5,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def norm(s):
    return re.sub(r"[^a-z0-9]+", "_", str(s or "").lower()).strip("_")


# ---------------------------------------------------------------- inventory

def inventory(dest=None):
    """What runs on the target: dpkg binaries/sources, kernel, extra binaries, network services, apt state."""
    inv = {"bins": {}, "srcs": {}, "src_bins": {}, "extra": {}, "services": [], "kernel": "", "notes": []}
    with D.on_host(dest):
        rc, txt = D._run(["dpkg-query", "-W", "-f",
                          "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n"], 60)
        if rc != 0:
            inv["notes"].append("dpkg-query is not available: package matching skipped")
        for ln in txt.splitlines():
            f = ln.split("\t")
            if len(f) < 5 or not f[0].startswith("ii"):
                continue
            name, ver, src, sver = f[1].split(":")[0], f[2], f[3] or f[1].split(":")[0], f[4] or f[2]
            inv["bins"][name] = ver
            inv["srcs"].setdefault(src, sver)
            inv["src_bins"].setdefault(src, []).append(name)
        rc, k = D._run(["uname", "-r"], 10)
        inv["kernel"] = re.split(r"[-+]", k.strip())[0] if rc == 0 else ""
        for name, argv in EXTRA_BINARIES.items():
            if not dest:
                # a timer's PATH is systemd's, not the login shell's: ~/.local/bin and vendor dirs are not on it
                exe = shutil.which(argv[0], path=os.pathsep.join([os.environ.get("PATH", ""), *EXTRA_PATHS]))
                if not exe:
                    continue
                argv = [exe, *argv[1:]]
            rc, out = D._run(argv, 10)
            m = re.search(r"(\d+\.\d+(?:\.\d+)*)", out) if rc == 0 else None
            if name == "docker" and "podman" in out.lower():
                m = None          # podman's docker shim reports podman's version, not Docker's
            if m:
                inv["extra"][name] = m.group(1)
        for r in D.listening():
            if r.get("bind") not in ("all", "lan") or D._is_client_udp(r):
                continue
            pkg = ""
            if r.get("proc") and r["proc"] != "?":
                rc, path = D._run(["sh", "-c", "command -v " + shlex.quote(r["proc"])], 5)
                if rc == 0 and path.strip():
                    rc, own = D._run(["dpkg", "-S", path.strip()], 10)
                    if rc == 0 and ":" in own:
                        pkg = own.split(":", 1)[0].strip()
            if not pkg and (r.get("proc") or "?") == "?":
                pkg = PORT_PKG.get(r["port"], "")   # only when the kernel hides who listens
            inv["services"].append({"port": r["port"], "proto": r["proto"], "proc": r.get("proc") or "?", "pkg": pkg})
        inv["apt"] = apt_state()
    return inv


def apt_state():
    """Pending security updates, how old the package lists are, and whether automatic updates are on."""
    st = {"security": [], "other": 0, "lists_age_h": None, "auto": False}
    rc, txt = D._run(["apt", "list", "--upgradable"], 60)
    for ln in txt.splitlines():
        m = re.match(r"^([^/\s]+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", ln)
        if not m:
            continue
        name, origin, new, old = m.groups()
        if "security" in origin or re.search(r"[+~]deb\d+u\d+", new):
            st["security"].append({"pkg": name, "from": old, "to": new})
        else:
            st["other"] += 1
    rc, age = D._run(["sh", "-c", "ls -t /var/lib/apt/lists/*Release 2>/dev/null | head -1 | xargs -r stat -c %Y"], 10)
    if rc == 0 and age.strip().isdigit():
        st["lists_age_h"] = round((time.time() - int(age.strip())) / 3600, 1)
    rc, txt = D._run(["sh", "-c", "dpkg-query -W -f '${db:Status-Abbrev}' unattended-upgrades 2>/dev/null; echo; "
                      "apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null"], 10)
    st["auto"] = txt.startswith("ii") and bool(re.search(r'Unattended-Upgrade "1"', txt))
    return st


def candidates(product, vendor=""):
    """The installed things a CPE/KEV product could be: [(kind, name, version, src)]."""
    p, v = norm(product), norm(vendor)
    names = ALIASES.get(f"{v}:{p}") or ALIASES.get(p)
    if names is None:
        if p in GENERIC_PRODUCTS or len(p) < 3:
            return []
        names = [p, p.replace("_", "-")]
    return names


def installed(names, inv):
    out = []
    for n in names:
        if n == "@kernel":
            if inv.get("kernel"):
                out.append(("kernel", "linux", inv["kernel"], "linux"))
        elif n.startswith("@"):
            if n[1:] in inv["extra"]:
                out.append(("binary", n[1:], inv["extra"][n[1:]], ""))
        elif n in inv["srcs"]:
            out.append(("dpkg", n, inv["srcs"][n], n))
        elif n in inv["bins"]:
            src = next((s for s, bs in inv["src_bins"].items() if n in bs), n)
            out.append(("dpkg", n, inv["bins"][n], src))
    seen, uniq = set(), []
    for x in out:
        if (x[0], x[1]) not in seen:
            seen.add((x[0], x[1]))
            uniq.append(x)
    return uniq


def exposed_srcs(inv):
    """Source packages that back a network-facing service on the target."""
    out = {}
    for s in inv.get("services") or []:
        pkg = s.get("pkg") or ""
        if pkg.startswith("@"):
            out[pkg[1:]] = s
            continue
        src = next((src for src, bs in inv["src_bins"].items() if pkg in bs), pkg)
        if src:
            out[src] = s
    return out


# ---------------------------------------------------------------- announcements

def fetch_kev(state):
    status, data, etag = http_json(KEV_URL, etag=state.get("kev_etag"))
    if status == 304:
        return _load("vulnwatch-kev.json", {}).get("vulnerabilities") or [], "unchanged"
    if status != 200 or not isinstance(data, dict):
        cached = _load("vulnwatch-kev.json", {}).get("vulnerabilities") or []
        return cached, f"KEV fetch failed ({etag}); using the cached copy ({len(cached)} entries)"
    vulns = [v for v in data.get("vulnerabilities") or [] if isinstance(v, dict) and v.get("cveID")]
    _save("vulnwatch-kev.json", {"vulnerabilities": vulns})
    state["kev_etag"] = etag
    return vulns, f"{len(vulns)} entries"


_NVD_LAST = [0.0]


def _nvd_window(kind, start, end, out):
    """Append every CVE NVD lists for one window (kind 'pub' or 'lastMod'). -> None, or why it failed."""
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    idx = 0
    while True:
        url = (f"{NVD_URL}?{kind}StartDate={start.strftime(fmt)}&{kind}EndDate={end.strftime(fmt)}"
               f"&resultsPerPage=2000&startIndex={idx}")
        wait = 6.5 - (time.time() - _NVD_LAST[0])
        if wait > 0:
            time.sleep(wait)    # NVD without a key: 5 requests per 30 s
        status, data, why = http_json(url, timeout=90)
        _NVD_LAST[0] = time.time()
        if status != 200 or not isinstance(data, dict):
            return why
        for item in data.get("vulnerabilities") or []:
            c = (item or {}).get("cve") or {}
            score = 0.0
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                for m in (c.get("metrics") or {}).get(key) or []:
                    score = max(score, float(((m or {}).get("cvssData") or {}).get("baseScore") or 0))
            desc = next((d.get("value") for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")
            cpes = []
            for conf in c.get("configurations") or []:
                for node in conf.get("nodes") or []:
                    cpes += [m for m in node.get("cpeMatch") or [] if m.get("vulnerable")]
            if c.get("id"):
                out[c["id"]] = {"id": c["id"], "cvss": score, "desc": desc or "", "cpes": cpes}
        total = int(data.get("totalResults") or 0)
        idx += int(data.get("resultsPerPage") or 0) or 2000
        if idx >= total:
            return None


def fetch_nvd(state):
    """CVEs PUBLISHED since the last pass, plus CVEs MODIFIED since then: NVD usually adds the CVSS score and
    the affected-product (CPE) data days after publishing, so a CVE first seen bare is picked up once it is
    analysed. -> ([{id, cvss, desc, cpes}], note). The first pass backfills NVD_RECENT_DAYS of publications."""
    now = _dt.datetime.now(_dt.timezone.utc)
    last = state.get("nvd_until")
    try:
        start = _dt.datetime.fromisoformat(last) if last else None
    except ValueError:
        start = None
    backfill = start is None or not _load("vulnwatch-nvd.json", {}).get("cves")
    floor = now - _dt.timedelta(hours=NVD_MAX_WINDOW_H)
    start = floor if backfill else max(start - _dt.timedelta(minutes=10), floor)
    out = {}
    why = _nvd_window("pub", start, now, out)
    if why is None and not backfill:
        why = _nvd_window("lastMod", start, now, out)
    if why is not None:
        return list(out.values()), f"NVD fetch failed ({why}); the window is kept for the next pass"
    state["nvd_until"] = now.isoformat()
    return list(out.values()), (f"{len(out)} CVE(s) published or updated since {start.strftime('%Y-%m-%d %H:%M')}Z"
                                + (" (backfill)" if backfill else ""))


def cpe_hits(cve, inv):
    """[(kind, name, version, src, in_range)] for the installed products a CVE's CPE matches name."""
    hits = []
    for m in cve.get("cpes") or []:
        parts = str(m.get("criteria") or "").split(":")
        if len(parts) < 6:
            continue
        part, vendor, product, ver = parts[2], parts[3], parts[4], parts[5]
        if part == "o" and norm(product) not in ("linux_kernel",):
            continue    # operating systems other than the Linux kernel are not what dpkg ships
        for kind, name, inst, src in installed(candidates(product, vendor), inv):
            have = upstream(inst) if kind == "dpkg" else inst
            in_range = None
            lo_i, lo_e = m.get("versionStartIncluding"), m.get("versionStartExcluding")
            hi_i, hi_e = m.get("versionEndIncluding"), m.get("versionEndExcluding")
            if any((lo_i, lo_e, hi_i, hi_e)):
                in_range = ((not lo_i or vcmp(have, "ge", lo_i)) and (not lo_e or vcmp(have, "gt", lo_e))
                            and (not hi_i or vcmp(have, "le", hi_i)) and (not hi_e or vcmp(have, "lt", hi_e)))
            elif ver not in ("*", "-", ""):
                in_range = vcmp(have, "eq", ver)
            hint = hi_e or (f"a release after {hi_i}" if hi_i else "")
            hits.append((kind, name, inst, src, in_range, hint))
    return hits


def nvd_cpes(cve_id, state):
    """The vulnerable CPE matches NVD lists for one CVE, cached for a week; None when not resolved this pass
    (the per-pass cap, or NVD unavailable) - the caller defers instead of guessing."""
    cache = state.setdefault("nvd_cpe_cache", {})
    hit = cache.get(cve_id)
    if hit and time.time() - hit.get("ts", 0) < 7 * 86400:
        return hit.get("cpes") or []
    if state.get("_nvd_calls", 0) >= NVD_LOOKUP_CAP:
        return None
    state["_nvd_calls"] = state.get("_nvd_calls", 0) + 1
    wait = 6.5 - (time.time() - _NVD_LAST[0])
    if wait > 0:
        time.sleep(wait)
    status, data, _ = http_json(f"{NVD_URL}?cveId={cve_id}", timeout=40)
    _NVD_LAST[0] = time.time()
    if status != 200 or not isinstance(data, dict):
        return None
    cpes = []
    for item in data.get("vulnerabilities") or []:
        for conf in ((item or {}).get("cve") or {}).get("configurations") or []:
            for node in conf.get("nodes") or []:
                cpes += [m for m in node.get("cpeMatch") or [] if m.get("vulnerable")]
    cache[cve_id] = {"ts": time.time(), "cpes": cpes}
    return cpes


def debian_verdict(cve_id, src, installed_ver, state, strict_urgency=True):
    """'patched' | 'fix-available' | 'unfixed' | 'not-affected' | 'unknown' for one CVE on one source package,
    from Debian's own record (OSV DEBIAN-<CVE>). Asks OSV by CVE id only; cached for DEB_CACHE_TTL."""
    cache = state.setdefault("deb_cache", {})
    hit = cache.get(cve_id)
    if not hit or time.time() - hit.get("ts", 0) > DEB_CACHE_TTL:
        if state.get("_details", 0) >= DETAIL_CAP:
            return "unknown", ""
        state["_details"] = state.get("_details", 0) + 1
        status, data, _ = http_json(OSV_VULN + "DEBIAN-" + cve_id, timeout=20)
        rec = {}
        if status == 200 and isinstance(data, dict):
            for a in data.get("affected") or []:
                pkg = (a or {}).get("package") or {}
                if pkg.get("ecosystem") != f"Debian:{debian_major()}":
                    continue
                fixed = None
                for r in a.get("ranges") or []:
                    for e in r.get("events") or []:
                        if e.get("fixed"):
                            fixed = e["fixed"]
                urg = ((a.get("ecosystem_specific") or {}).get("urgency") or "")
                rec[pkg.get("name")] = {"fixed": fixed, "urgency": urg}
        hit = {"ts": time.time(), "status": status, "rec": rec}
        cache[cve_id] = hit
    rec = (hit.get("rec") or {}).get(src)
    if hit.get("status") == 404 or rec is None:
        return "unknown", ""
    if strict_urgency and str(rec.get("urgency")).startswith("unimportant"):
        return "not-affected", "Debian rates it unimportant for its builds"
    if not rec.get("fixed"):
        return "unfixed", "no fixed version in Debian yet"
    if vcmp(installed_ver, "ge", rec["fixed"]):
        return "patched", f"installed {installed_ver} >= fixed {rec['fixed']}"
    return "fix-available", f"fixed in {rec['fixed']}, installed {installed_ver}"


_DEB_MAJOR = []


def debian_major():
    if not _DEB_MAJOR:
        try:
            with open("/etc/debian_version") as fh:
                _DEB_MAJOR.append(fh.read().strip().split(".")[0] or "13")
        except OSError:
            _DEB_MAJOR.append("13")
    return _DEB_MAJOR[0]


# ---------------------------------------------------------------- dependencies (OSV batch)

def npm_packages(d):
    try:
        with open(os.path.join(d, "package-lock.json")) as fh:
            lock = json.load(fh)
    except (OSError, ValueError):
        return []
    out = set()
    for key, meta in (lock.get("packages") or {}).items():
        if not key or not isinstance(meta, dict) or not meta.get("version") or meta.get("link"):
            continue
        out.add((key.rsplit("node_modules/", 1)[-1], meta["version"]))
    for name, meta in (lock.get("dependencies") or {}).items():          # lockfile v1
        if isinstance(meta, dict) and meta.get("version"):
            out.add((name, meta["version"]))
    return sorted(out)


def pip_packages(python):
    """name/version pairs pip installed for this interpreter. A system interpreter lists only --user
    packages: its dist-packages belong to apt, and OSV's PyPI ranges would misread Debian's patched builds."""
    try:
        venv = subprocess.run([python, "-c", "import sys; print(sys.prefix != sys.base_prefix)"],
                              capture_output=True, text=True, timeout=20).stdout.strip() == "True"
        p = subprocess.run([python, "-m", "pip", "list", "--format=json", "--disable-pip-version-check"]
                           + ([] if venv else ["--user"]),
                           capture_output=True, text=True, timeout=60)
        return sorted((x["name"], x["version"]) for x in json.loads(p.stdout or "[]") if x.get("name"))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError):
        return []


def osv_batch(ecosystem, pkgs):
    """{(name, version): [vuln id]} via OSV querybatch, 1000 per request."""
    out = {}
    for i in range(0, len(pkgs), 1000):
        chunk = pkgs[i:i + 1000]
        q = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in chunk]}
        status, data, _ = http_json(OSV_BATCH, q, timeout=60)
        if status != 200 or not isinstance(data, dict):
            return None
        for (n, v), res in zip(chunk, data.get("results") or []):
            ids = [x.get("id") for x in (res or {}).get("vulns") or [] if x.get("id")]
            if ids:
                out[(n, v)] = ids
    return out


def osv_detail(vid, state):
    cache = state.setdefault("osv_cache", {})
    if vid in cache:
        return cache[vid]
    if state.get("_details", 0) >= DETAIL_CAP:
        return None
    state["_details"] = state.get("_details", 0) + 1
    status, data, _ = http_json(OSV_VULN + vid, timeout=20)
    if status != 200 or not isinstance(data, dict):
        return None
    sev = str(((data.get("database_specific") or {}).get("severity")) or "").upper()
    fixed = {}
    for a in data.get("affected") or []:
        name = ((a or {}).get("package") or {}).get("name")
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                if e.get("fixed"):
                    fixed.setdefault(name, []).append(e["fixed"])
    d = {"sev": sev, "summary": str(data.get("summary") or data.get("details") or "")[:200],
         "aliases": [x for x in data.get("aliases") or [] if str(x).startswith("CVE-")][:3], "fixed": fixed}
    cache[vid] = d
    return d


# ---------------------------------------------------------------- the pass

def _upgrade_cmd(src, inv):
    bins = [b for b in inv["src_bins"].get(src, []) if b in inv["bins"]][:12] or [src]
    return "sudo apt update && sudo apt install --only-upgrade " + " ".join(bins)


def run(dest=None, save=True):
    """One pass. -> (findings, notes, summary). Findings are defender findings (area 'vuln')."""
    with _LOCK:
        state = _load("vulnwatch.json", {})
        state["_details"] = 0
        cfg = config()
        notes, out = [], []
        inv = inventory(dest)
        notes += inv["notes"]
        exposed = exposed_srcs(inv)
        summary = {"kev_hits": 0, "nvd_new": 0, "nvd_hits": 0, "patched": 0, "deps": 0, "deferred": 0,
                   "security_updates": len(inv["apt"]["security"])}

        def add(fid, sev, fact, fix):
            out.append(G._f(fid, sev, "vuln", fact, fix))

        def judge(cve_id, title, kind, name, ver, src, kev, cvss, in_range, hint=""):
            """One CVE on one installed thing -> a record, or None when it is patched / not affected /
            not provably in range. Never guesses: no version evidence means deferred, not reported."""
            verdict, why = ("unknown", "")
            if kind == "dpkg":
                verdict, why = debian_verdict(cve_id, src, ver, state)
            elif BINARY_DEBSRC.get("@kernel" if kind == "kernel" else name):
                # Debian's fixed version of the same upstream is the evidence; "unimportant" there means
                # Debian does not support its own build, not that the upstream bug is harmless
                verdict, why = debian_verdict(cve_id, BINARY_DEBSRC["@kernel" if kind == "kernel" else name],
                                              ver, state, strict_urgency=False)
                if verdict == "fix-available":
                    verdict, why = "outdated", why.replace("installed", "this machine has")
                elif verdict == "unfixed":
                    verdict = "unknown"     # Debian has no fix yet; the upstream range below decides
            if verdict in ("patched", "not-affected"):
                summary["patched"] += 1
                return None
            if verdict == "unknown" and in_range is None:
                cpes = nvd_cpes(cve_id, state)
                if cpes is None:
                    summary["deferred"] += 1
                    return None       # no version evidence yet: resolved on a later pass, never guessed
                rng = [h for h in cpe_hits({"cpes": cpes}, inv) if h[1] == name]
                in_range = True if any(h[4] for h in rng) else (False if rng else None)
                hint = hint or next((h[5] for h in rng if h[4] and h[5]), "")
            if verdict == "unknown" and not in_range:
                if in_range is None:
                    summary["deferred"] += 1
                return None           # the published affected range does not include what is installed
            if verdict == "unknown":
                verdict, why = (("outdated", f"fixed upstream in {hint}") if hint and kind != "dpkg" else
                                ("unknown", f"fixed upstream in {hint}" if hint else
                                 "the published affected range includes what is installed"))
            facing = exposed.get(src) or exposed.get(name)
            sev = ("crit" if kev and (facing or verdict in ("fix-available", "outdated")) else
                   "high" if kev or cvss >= 9 or facing else "warn")
            return {"cve": cve_id, "title": title, "kind": kind, "name": name, "ver": ver, "src": src, "kev": kev,
                    "cvss": cvss, "verdict": verdict, "why": why, "facing": facing, "sev": sev, "hint": hint}

        records = []

        # 1. CISA KEV, every entry, every pass (actively exploited matters whatever its age)
        kev, kev_note = fetch_kev(state)
        notes.append("CISA KEV: " + kev_note)
        known = set(state.get("kev_seen") or [])
        new_kev = [v for v in kev if v["cveID"] not in known]
        for v in kev:
            for kind, name, ver, src in installed(candidates(v.get("product"), v.get("vendorProject")), inv):
                summary["kev_hits"] += 1
                records.append(judge(v["cveID"], f"{v.get('vendorProject')} {v.get('product')}: "
                                     f"{v.get('vulnerabilityName')}", kind, name, ver, src, True, 0.0, None))
        if known:
            notes.append(f"CISA KEV: {len(new_kev)} newly added since the last pass")
        state["kev_seen"] = sorted({v["cveID"] for v in kev})

        # 2. NVD: what was published since the last pass joins the TRACKED set when it names something
        # installed; every tracked CVE is re-judged each pass until the installed version is out of range
        # or patched, so an unpatched hit does not vanish just because it is no longer "new"
        nvd, nvd_note = fetch_nvd(state)
        notes.append("NVD: " + nvd_note)
        kev_ids = {v["cveID"] for v in kev}
        tracked = state.get("tracked") if isinstance(state.get("tracked"), dict) else {}
        keep = ("criteria", "vulnerable", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                "versionEndExcluding")
        recent = _load("vulnwatch-nvd.json", {}).get("cves") or {}
        today = time.strftime("%Y-%m-%d")
        for c in nvd:
            if c["cvss"] >= cfg["min_cvss"] and c["cpes"]:
                summary["nvd_new"] += 1
                recent[c["id"]] = {"cvss": c["cvss"], "desc": c["desc"][:300], "seen": today,
                                   "cpes": [{k: m[k] for k in keep if k in m} for m in c["cpes"][:60]]}
        cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - NVD_RECENT_DAYS * 86400))
        recent = {k: v for k, v in recent.items() if str(v.get("seen") or "") >= cutoff}
        if save:
            _save("vulnwatch-nvd.json", {"cves": recent})
        # every recent announcement is matched against the CURRENT inventory, not only this hour's batch
        for cid, c in recent.items():
            if cid in kev_ids:
                continue
            c = dict(c, id=cid)
            if cpe_hits(c, inv):
                tracked[cid] = {"title": c["desc"][:300], "cvss": c["cvss"], "cpes": c["cpes"][:60],
                                "added": (tracked.get(cid) or {}).get("added") or today}
        for cid in list(tracked):
            t = tracked[cid]
            hits = cpe_hits(t, inv)
            live = []
            for kind, name, ver, src, in_range, hint in hits:
                summary["nvd_hits"] += 1
                r = judge(cid, t.get("title") or "", kind, name, ver, src, False, float(t.get("cvss") or 0),
                          in_range, hint)
                records.append(r)
                live.append(r)
            if not hits or not any(live):
                tracked.pop(cid, None)      # uninstalled, out of range or patched: stop tracking
        state["tracked"] = dict(list(tracked.items())[-2000:])

        # one finding per installed package: an outdated browser is ONE thing to fix, not 35 alerts
        groups = {}
        for r in records:
            if r:
                groups.setdefault((r["kind"], r["name"], r["ver"]), []).append(r)
        order = {"crit": 0, "high": 1, "warn": 2, "info": 3}
        prev_sets = state.get("group_cves") if isinstance(state.get("group_cves"), dict) else {}
        grown, group_cves = set(), {}
        for (kind, name, ver), rs in sorted(groups.items()):
            rs.sort(key=lambda r: (order[r["sev"]], -r["kev"], -r["cvss"], r["cve"]))
            worst = rs[0]
            fid = f"vuln:{kind}:{name}:{ver}"
            group_cves[fid] = sorted({r["cve"] for r in rs})
            if set(group_cves[fid]) - set(prev_sets.get(fid) or []):
                grown.add(fid)
            kevs = sorted({r["cve"] for r in rs if r["kev"]})
            top = ", ".join(r["cve"] + (f" ({r['cvss']:.1f})" if r["cvss"] else "") for r in rs[:4])
            hints = sorted({r["hint"] for r in rs if r["hint"]}, key=lambda h: [int(x) if x.isdigit() else 0
                                                                                 for x in re.split(r"[.]", h)])
            what = {"fix-available": "NOT PATCHED: a fixed package exists", "unfixed": "UNPATCHED: no fix shipped yet",
                    "outdated": "OUTDATED", "unknown": "affected"}.get(worst["verdict"], worst["verdict"])
            facing = worst["facing"]
            fact = (f"{name} {ver} ({kind}) is affected by {len(rs)} vulnerabilit{'y' if len(rs) == 1 else 'ies'}"
                    + (f", {len(kevs)} ACTIVELY EXPLOITED (CISA KEV: {', '.join(kevs[:3])})" if kevs else "")
                    + f": {top}{' ...' if len(rs) > 4 else ''}. {what}"
                    + (f"; fixed upstream in {hints[-1]}" if hints else f" ({worst['why']})" if worst["why"] else "")
                    + (f". It backs a network-facing service (port {facing['port']}/{facing['proto']})"
                       if facing else "") + f". Worst: {worst['title'][:160]}")
            src = worst["src"]
            if any(r["verdict"] == "fix-available" for r in rs) or (kind == "dpkg" and any(
                    u["pkg"] in inv["src_bins"].get(src, []) for u in inv["apt"]["security"])):
                fix = _upgrade_cmd(src, inv) + ", then restart what uses it (reboot for a kernel or libc)"
            elif kind == "kernel":
                fix = ("install the distribution's next kernel as soon as it ships (sudo apt update && "
                       "sudo apt upgrade), then reboot")
            elif kind == "binary":
                fix = (f"update {name} to {hints[-1]} or newer from its vendor (it is not a dpkg package)"
                       + ("; for Chrome: open chrome://settings/help, or sudo apt update && sudo apt install "
                          "--only-upgrade google-chrome-stable" if name == "google-chrome" else "")
                       if hints else f"update {name} from its vendor (it is not a dpkg package)")
            else:
                fix = ("no patched package yet: limit exposure (bind the service to 127.0.0.1, or sudo ufw deny "
                       f"{facing['port']}/{facing['proto']}); vulnwatch re-checks every hour"
                       if facing else "no patched package yet: vulnwatch re-checks every hour and says when it ships")
            add(fid, worst["sev"], fact, fix)
        state["group_cves"] = group_cves

        # 3. dependencies you named: npm lockfiles and pip environments, exact through OSV
        for eco, items in (("npm", [(d, npm_packages(d)) for d in cfg["npm"]]),
                           ("PyPI", [(p, pip_packages(p)) for p in cfg["pip"]])):
            for where, pkgs in items:
                if not pkgs:
                    notes.append(f"{eco} {where}: nothing to check (no lockfile / pip list failed)")
                    continue
                res = osv_batch(eco, pkgs)
                if res is None:
                    notes.append(f"{eco} {where}: OSV query failed; kept the last result")
                    continue
                for (n, v), ids in sorted(res.items()):
                    for vid in ids[:8]:
                        d = osv_detail(vid, state) or {}
                        sev_word = d.get("sev") or ""
                        if sev_word == "LOW":
                            continue
                        summary["deps"] += 1
                        sev = "high" if sev_word in ("CRITICAL", "HIGH") else "warn"
                        fixed = sorted(set(d.get("fixed", {}).get(n) or []))
                        fx = (f"cd {shlex.quote(where)} && npm install {n}@{fixed[-1]}" if eco == "npm" and fixed else
                              f"cd {shlex.quote(where)} && npm audit fix" if eco == "npm" else
                              f"{shlex.quote(where)} -m pip install -U '{n}>={fixed[-1]}'" if fixed else
                              f"{shlex.quote(where)} -m pip install -U {n}")
                        tag = "/".join(d.get("aliases") or [vid])
                        add(f"vuln:{eco}:{hashlib.sha1(where.encode()).hexdigest()[:8]}:{n}:{vid}", sev,
                            f"{tag} ({sev_word.lower() or 'unrated'}) in {eco} {n} {v} under {where}: "
                            f"{d.get('summary') or 'see ' + vid}", fx)

        # 4. are we keeping up: pending security updates, stale lists, automatic updates
        apt = inv["apt"]
        if apt["security"]:
            names = ", ".join(u["pkg"] for u in apt["security"][:10])
            add("vuln:apt:security-updates", "high",
                f"{len(apt['security'])} security update(s) are waiting to be installed: {names}"
                + (" ..." if len(apt["security"]) > 10 else ""),
                "sudo apt update && sudo apt upgrade   (then restart the services that use them, or reboot for "
                "libc/kernel)")
        if apt["lists_age_h"] is not None and apt["lists_age_h"] > APT_STALE_H:
            add("vuln:apt:stale-lists", "warn",
                f"the package lists are {apt['lists_age_h']:.0f} h old: new fixes are invisible until apt refreshes",
                "sudo apt update")
        if not apt["auto"] and inv["bins"]:
            add("vuln:apt:no-auto-security", "warn",
                "automatic security updates are off: a fix that ships overnight waits for someone to run apt",
                "sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")

        out.sort(key=lambda f: (G.SEV_ORDER[f["sev"]], f["id"]))
        state.pop("_details", None)
        state.pop("_nvd_calls", None)
        if summary["deferred"]:
            notes.append(f"{summary['deferred']} match(es) wait for version evidence (NVD lookups are rate-limited); "
                         "the next passes resolve them")
        state["last_run"] = time.strftime("%Y-%m-%d %H:%M:%S")
        state["last_summary"] = summary
        prev = set(state.get("last_ids") or [])
        state["last_ids"] = [f["id"] for f in out]
        state["new_ids"] = [f["id"] for f in out if f["id"] not in prev or f["id"] in grown]
        # bound the caches: the KEV list and a day of verifications are plenty
        for k in ("deb_cache", "osv_cache"):
            c = state.get(k) or {}
            if len(c) > 3000:
                state[k] = dict(list(c.items())[-3000:])
        if save:
            _save("vulnwatch.json", state)
        return out, notes, dict(summary, new=state["new_ids"])


def render(findings, notes, summary):
    lines = [f"VULNWATCH {time.strftime('%Y-%m-%d %H:%M')}: {len(findings)} finding(s), "
             f"{len(summary.get('new') or [])} new",
             f"  announced: KEV matches {summary['kev_hits']}, NVD new CVSS>=7 {summary['nvd_new']} "
             f"(matched {summary['nvd_hits']}); already patched {summary['patched']}; "
             f"dependency advisories {summary['deps']}; security updates waiting {summary['security_updates']}"
             + (f"; awaiting evidence {summary['deferred']}" if summary.get("deferred") else ""), ""]
    for f in findings:
        lines.append(f"  [{f['sev'].upper():4}] {f['fact']}")
        if f.get("fix"):
            lines.append(f"         fix: {f['fix']}")
        lines.append("")
    if not findings:
        lines += ["  nothing announced affects what this machine runs, and no security update is waiting", ""]
    lines += ["  " + n for n in notes]
    return "\n".join(lines)


def run_and_publish(dest=None, notify=True):
    """run() + the alert queue + the report file + a desktop notification for new high/critical findings."""
    if dest is None:
        vouch_own_units()   # this machine's own units only; a remote host's baseline is not ours to touch
    findings, notes, summary = run(dest)
    alerts = []
    with contextlib.suppress(Exception):
        alerts, _a, _c, _n = G.publish(findings, dest, G.load_profile(dest))
    text = render(findings, notes, summary)
    with contextlib.suppress(OSError):
        with open(_path("vulnwatch-latest.txt"), "w") as fh:
            fh.write(text + "\n")
    new_bad = [f for f in findings if f["id"] in set(summary.get("new") or []) and f["sev"] in ("crit", "high")]
    if notify and new_bad and shutil.which("notify-send"):
        with contextlib.suppress(Exception):
            subprocess.Popen(["notify-send", "-a", "gnoc-defender", "-u", "critical",
                              f"vulnwatch: {len(new_bad)} new vulnerability finding(s)",
                              "\n".join(f["fact"][:160] for f in new_bad[:3])],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return text, findings, alerts


# ---------------------------------------------------------------- the hourly timer (systemd --user)

def _unit_dir():
    return os.path.expanduser("~/.config/systemd/user")


def _unit_path():
    parts = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p and '"' not in p and "\n" not in p]
    for extra in EXTRA_PATHS[:1] + ["/usr/local/bin", "/usr/bin", "/bin"]:
        if extra not in parts:
            parts.append(extra)
    return os.pathsep.join(parts)


def _unit_files():
    return os.path.join(_unit_dir(), TIMER + ".service"), os.path.join(_unit_dir(), TIMER + ".timer")


def _service_text(path_env=None):
    ws = G._WS
    return ("[Unit]\nDescription=gnoc defender: check newly announced vulnerabilities against this machine\n"
            "After=network-online.target\n\n[Service]\nType=oneshot\n"
            f"Environment=GNOC_WS={ws}\nEnvironment=GNOC_WORKSPACE={ws}\n"
            # the login PATH, so programs in ~/.local/bin and the like are found from the timer too
            f"Environment=\"PATH={path_env if path_env is not None else _unit_path()}\"\n"
            f"ExecStart={shlex.quote(sys.executable)} {shlex.quote(os.path.abspath(__file__))} run --quiet\n"
            "Nice=10\nTimeoutStartSec=15min\n")


def _timer_text():
    return ("[Unit]\nDescription=gnoc defender vulnerability watch, hourly\n\n[Timer]\n"
            "OnBootSec=5min\nOnCalendar=hourly\nRandomizedDelaySec=300\nPersistent=true\n\n"
            "[Install]\nWantedBy=timers.target\n")


_PATH_LINE = re.compile(r'^Environment="PATH=([^"\n]*)"$', re.M)


def vouch_own_units():
    """Units installed before the defender knew to vouch for them (or by an older gnoc) are flagged as drift.
    Vouch for one only when it is EXACTLY what timer("on") writes - the PATH line is the one part that differs
    between the shell that installed it and the timer that runs it, so it is read back from the file, never
    ignored: any other line added or changed (an ExecStartPre, a different ExecStart) leaves it drift."""
    svc, tmr = _unit_files()
    texts = {}
    with contextlib.suppress(OSError):
        with open(svc) as fh:
            got = fh.read()
        m = _PATH_LINE.search(got)
        if m and got == _service_text(m.group(1)):
            texts[svc] = got
    with contextlib.suppress(OSError):
        with open(tmr) as fh:
            got = fh.read()
        if got == _timer_text():
            texts[tmr] = got
    with contextlib.suppress(Exception):
        return G.vouch_host_files(texts)
    return 0


def timer(op="status"):
    """on | off | status for the hourly systemd user timer. No root needed."""
    import gnoc_platform
    if gnoc_platform.is_termux():
        # Android has no systemd; the message names the user-set crond path instead of writing units nobody runs.
        # Deliberately NOT a crontab line from here: a model can reach this through defend(action=vulnwatch), and
        # only the user sets a schedule (the defender's own /defender schedule is typed-only).
        return (gnoc_platform.unavailable("the hourly vulnerability timer") + ". Run a pass by hand with "
                "/defender vulnwatch run, or type /defender schedule to have crond sweep this phone")
    if not shutil.which("systemctl"):
        return "systemd is not available: run `python3 scripts/gnoc_vulnwatch.py run` from cron instead"
    svc, tmr = _unit_files()
    if op == "on":
        os.makedirs(_unit_dir(), exist_ok=True)
        texts = {svc: _service_text(), tmr: _timer_text()}
        for path, text in texts.items():
            with open(path, "w") as fh:
                fh.write(text)
        with contextlib.suppress(Exception):
            G.vouch_host_files(texts)   # the defender's own units are not drift (only these exact bytes)
        for argv in (["systemctl", "--user", "daemon-reload"],
                     ["systemctl", "--user", "enable", "--now", TIMER + ".timer"]):
            p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            if p.returncode:
                return f"could not start the timer: {(p.stderr or p.stdout).strip()[:200]}"
        return "hourly vulnerability watch ON (systemd user timer). " + timer("status")
    if op == "off":
        subprocess.run(["systemctl", "--user", "disable", "--now", TIMER + ".timer"], capture_output=True, timeout=30)
        for p in (svc, tmr):
            with contextlib.suppress(OSError):
                os.unlink(p)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=30)
        return "hourly vulnerability watch OFF"
    p = subprocess.run(["systemctl", "--user", "show", TIMER + ".timer", "-p", "ActiveState",
                        "-p", "NextElapseUSecRealtime", "-p", "LastTriggerUSec"], capture_output=True, text=True,
                       timeout=15)
    props = dict(ln.split("=", 1) for ln in p.stdout.splitlines() if "=" in ln)
    if props.get("ActiveState") != "active":
        return "timer: off  (/defender vulnwatch on starts the hourly watch)"
    row = (f"next {props.get('NextElapseUSecRealtime') or '?'}, last {props.get('LastTriggerUSec') or 'never'}")
    linger = subprocess.run(["loginctl", "show-user", os.environ.get("USER", ""), "-p", "Linger"],
                            capture_output=True, text=True, timeout=10).stdout.strip()
    return ("timer: on, hourly: " + row
            + ("" if linger.endswith("yes") else
               "\n  note: it runs while you are logged in; `loginctl enable-linger` keeps it running after logout"))


def status():
    vouch_own_units()
    st = _load("vulnwatch.json", {})
    s = st.get("last_summary") or {}
    lines = [f"VULNWATCH: last pass {st.get('last_run') or 'never'}"
             + (f": {len(st.get('last_ids') or [])} finding(s), {s.get('security_updates', 0)} security update(s) "
                f"waiting, {s.get('patched', 0)} announced CVE(s) already patched" if st.get("last_run") else ""),
             "  " + timer("status").replace("\n", "\n  "),
             f"  watching npm: {', '.join(config()['npm']) or '(none)'}   pip: {', '.join(config()['pip']) or '(none)'}",
             f"  report: {_path('vulnwatch-latest.txt')}"]
    return "\n".join(lines)


def main(argv):
    cmd = argv[0] if argv else "run"
    if cmd == "run":
        text, findings, _ = run_and_publish()
        if "--quiet" not in argv:
            print(text)
        else:
            print(text.splitlines()[0])
        return 0
    if cmd == "status":
        print(status())
        return 0
    if cmd == "timer" and len(argv) > 1:
        print(timer(argv[1]))
        return 0
    if cmd in ("npm", "pip") and len(argv) > 2:
        print(set_config(cmd, argv[1], argv[2]))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
