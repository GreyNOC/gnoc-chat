"""gnoc_oast.py - out-of-band callbacks for blind SSRF / XXE / RCE / SSTI, without Burp Pro.

Burp Collaborator is Pro-only (absent from this Burp's MCP tools), so this runs interactsh-client in the
background, one listener per program:
    targets/<program>/hunts/gnoc-oast/{payload.txt, interactions.jsonl, client.log, state.json}
new_tag(program) -> a unique sub-label + full callback host for ONE probe (code-side correlation: an interaction
counts for a probe only when its full id carries that probe's tag). poll(program, tag) -> the interactions seen.
A callback is a receipt of REACH (DNS/HTTP from the target's infrastructure), not of impact: record the remote
address and whether it was DNS only or a full HTTP fetch.
"""
import json
import os
import re
import secrets
import signal
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _alive

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLIENT = os.path.expanduser("~/go/bin/interactsh-client")
OOB_ENV = os.path.expanduser("~/.config/gnoc/gnoc-oob.env")
DEFAULT_BASE = "https://your-site.example"
SITE_UA = "gnoc-oast/1"  # never the urllib default: Cloudflare 1010-blocks it (see _site_hits)
_ALNUM = string.ascii_letters + string.digits
_site_disabled = False  # set on a 401: no retries for the rest of the process


def _site_cfg():
    """(base, secret) from the env file, or None when the site backend is off. Never logs the secret."""
    if _site_disabled:
        return None
    vals = {}
    try:
        with open(OOB_ENV) as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    vals[k.strip()] = v.strip().strip("'\"")
    except OSError:
        return None
    secret = vals.get("GNOC_OOB_SECRET", "")
    if not secret:
        return None
    return (vals.get("GNOC_OOB_BASE") or DEFAULT_BASE).rstrip("/"), secret


def _mint_token():
    return "g" + "".join(secrets.choice(_ALNUM) for _ in range(24))


def _log(program, msg):
    try:
        os.makedirs(_dir(program), exist_ok=True)
        with open(os.path.join(_dir(program), "client.log"), "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} gnoc-oast site: {msg}\n")
    except OSError:
        pass


def _site_hits(program, token):
    """Hits the site recorded for token, as interactsh-shaped rows tagged source=site. [] on any failure."""
    global _site_disabled
    cfg = _site_cfg()
    if not cfg or not re.match(r"^[A-Za-z0-9]{6,64}$", token or ""):
        return []
    base, secret = cfg
    # The poll NAMES ITSELF. Cloudflare fronts the site and answers the default Python-urllib
    # User-Agent with its own error 1010 (HTTP 403) before the app ever sees the request, so the
    # poll silently returned zero hits while the receiver recorded them fine. Verified 2026-10-24:
    # UA "Python-urllib/3.13" -> 403, any other UA -> 200. Keep a UA on every request to the site.
    req = urllib.request.Request(f"{base}/api/oob/{token}",
                                 headers={"Authorization": f"Bearer {secret}", "User-Agent": SITE_UA})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            if e.code == 401:
                _site_disabled = True
                _log(program, "poll answered 401 (bad OOB secret); site backend disabled for this process")
            return []
    except (OSError, ValueError):
        return []
    rows = []
    for h in (data.get("hits") or []) if isinstance(data, dict) else []:
        hd = h.get("headers") or {}
        raw = f"{h.get('method', '')} {h.get('path', '')} HTTP/1.1\n" + \
            "".join(f"{k}: {v}\n" for k, v in hd.items()) + "\n" + (h.get("body") or "")
        rows.append({"protocol": "http", "full-id": token, "unique-id": token,
                     "remote-address": h.get("ip", ""), "raw-request": raw,
                     "timestamp": h.get("at", ""), "source": "site"})
    return rows


def _dir(program):
    return os.path.join(WS, "targets", program, "hunts", "gnoc-oast")


def _state(program):
    try:
        with open(os.path.join(_dir(program), "state.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}




def _save_state(program, st, d=None):
    """Atomic state write: this file maps every OAST tag to the probe that minted it, so a torn write loses
    the correlation for callbacks already in flight - the proof of a blind finding, unrecoverable."""
    d = d or _dir(program)
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, f"state.json.{os.getpid()}.tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, os.path.join(d, "state.json"))
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _domain(program):
    try:
        with open(os.path.join(_dir(program), "payload.txt")) as f:
            return f.read().split()[0].strip()
    except (OSError, IndexError):
        return ""


def start(program, wait=20):
    """Start (or reuse) the program's listener. Returns (domain, note)."""
    st = _state(program)
    if st.get("pid") and _alive(st["pid"]) and _domain(program):
        return _domain(program), "listener already running"
    if not os.path.isfile(CLIENT):
        return "", f"interactsh-client not found at {CLIENT}"
    d = _dir(program)
    os.makedirs(d, exist_ok=True)
    for f in ("payload.txt",):
        try:
            os.remove(os.path.join(d, f))
        except OSError:
            pass
    log = open(os.path.join(d, "client.log"), "a")
    p = subprocess.Popen([CLIENT, "-json", "-o", os.path.join(d, "interactions.jsonl"), "-ps",
                          "-psf", os.path.join(d, "payload.txt")],
                         stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    _save_state(program, {"pid": p.pid, "started": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          "tags": {}}, d)
    t0 = time.time()
    while time.time() - t0 < wait:
        if _domain(program):
            return _domain(program), "listener started"
        if p.poll() is not None:
            return "", f"interactsh-client exited ({p.returncode}); see {os.path.relpath(d, WS)}/client.log"
        time.sleep(0.5)
    return "", "listener did not register in time; see client.log"


def stop(program):
    st = _state(program)
    if st.get("pid") and _alive(st["pid"]):
        try:
            os.killpg(os.getpgid(int(st["pid"])), signal.SIGTERM)
        except OSError:
            pass
        return "listener stopped"
    return "no listener running"


def new_tag(program, label=""):
    """A fresh correlation tag for one probe and the callback host to put in it."""
    dom, note = start(program)
    if not dom:
        return None, None, note
    tag = "g" + secrets.token_hex(4)
    st = _state(program)
    st.setdefault("tags", {})[tag] = {"label": (label or "")[:120],
                                      "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    _save_state(program, st)
    return tag, f"{tag}.{dom}", note


def new_probe(program, label=""):
    """{"tag","dns_host","http_url","note"}: dns_host is the interactsh host (or None), http_url the site URL (or None).
    Use http_url in URL-shaped sinks and dns_host in DNS-shaped ones. tag is None only if neither backend works."""
    tag, host, note = new_tag(program, label)
    cfg = _site_cfg()
    url = None
    if cfg:
        if not tag:
            tag = "g" + secrets.token_hex(4)
            st = _state(program)
            st.setdefault("tags", {})[tag] = {"label": (label or "")[:120],
                                              "ts": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        token = _mint_token()
        st = _state(program)
        st.setdefault("tags", {}).setdefault(tag, {})["site_token"] = token
        _save_state(program, st)
        url = f"{cfg[0]}/oob/{token}/{tag}"
        note = (note + "; " if note else "") + "site http backend on"
    return {"tag": tag, "dns_host": host, "http_url": url, "note": note}


def interactions(program):
    rows = []
    try:
        with open(os.path.join(_dir(program), "interactions.jsonl")) as f:
            for ln in f:
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return rows


def poll(program, tag=None):
    """Interactions for one tag (or every tag this listener handed out). Returns text."""
    st = _state(program)
    tags = st.get("tags", {})
    rows = interactions(program)
    want = [tag] if tag else list(tags)
    out = []
    for t in want:
        hits = [r for r in rows if t.lower() in (r.get("full-id") or r.get("unique-id") or "").lower()
                or t.lower() in (r.get("raw-request") or "").lower()]
        stok = tags.get(t, {}).get("site_token")
        if stok:
            hits = hits + _site_hits(program, stok)
        label = tags.get(t, {}).get("label", "")
        if not hits:
            out.append(f"{t} ({label}): no callback yet")
            continue
        kinds = sorted({(r.get("protocol") or "?").upper() for r in hits})
        out.append(f"{t} ({label}): {len(hits)} callback(s) {'/'.join(kinds)}")
        for r in hits[:5]:
            first = (r.get("raw-request") or "").splitlines()[:1]
            out.append(f"   {r.get('timestamp', '')[:19]} {r.get('protocol')}{' [site]' if r.get('source') == 'site' else ''} "
                       f"from {r.get('remote-address')} "
                       f"{first[0][:120] if first else ''}")
    alive = st.get("pid") and _alive(st["pid"])
    return ("\n".join(out) or "no tags handed out yet (oast action=new)") + \
        ("" if alive else "\n(listener is not running: oast action=new restarts it; callbacks while it was down "
                          "are lost)") + f"\nraw: {os.path.relpath(_dir(program), WS)}/interactions.jsonl"


def _selftest():
    cfg = _site_cfg()
    if not cfg:
        print("site backend not configured")
        return 0
    prog = "_oast_selftest"
    tag = "gselftest"
    token = _mint_token()
    url = f"{cfg[0]}/oob/{token}/{tag}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": SITE_UA}),
                                    timeout=10) as r:
            r.read(16)
    except (OSError, ValueError) as e:
        print(f"FAIL: could not hit own receiver ({type(e).__name__})")
        return 1
    rows = _site_hits(prog, token)
    if _site_disabled:
        print("FAIL: poll rejected (401), check GNOC_OOB_SECRET")
        return 1
    ok = any(tag in r["raw-request"] for r in rows)
    print("OK" if ok else "FAIL: no hit seen by poll")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    print("usage: gnoc_oast.py --selftest")
