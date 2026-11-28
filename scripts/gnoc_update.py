#!/usr/bin/env python3
"""gnoc update - keep gnoc chat current, from the GreyNOC download page.

    gnoc update            download the newest release, check it, install it
    gnoc update --check    only say whether there is a newer release
    gnoc update --yes      do not ask before installing
    gnoc update --auto on  install each new release by itself when gnoc starts (off turns it off;
                           --auto alone says which it is)

Once a day, when you start gnoc, the launcher asks this script (`notice`) whether a newer release
is out. If one is, it asks "Install it now? [Y/n/a]" (a = always, the same as --auto on), or with
auto-update on it installs it before the chat opens. The check itself runs in the background, so
starting gnoc never waits on the network when there is nothing new. Set GNOC_NO_UPDATE_CHECK=1 to
turn all of it off.

What it trusts. Every release is signed with the GreyNOC release key (Ed25519). The key's public
half is built into this file, and nothing is installed unless manifest.json carries that key's
signature and the package matches the SHA-256 the manifest gives it. So a release can come only
from the machine that holds the key: not from the download server, and not from anyone between you
and it. A release older than (or the same as) the one installed is never taken, so an old signed
release cannot be replayed to roll you back.

What it changes. A new version is unpacked beside the old one, in
~/.local/share/gnoc-chat/releases/, and its own install.sh points the `gnoc` command at it. The
folder you installed from is never touched, a chat that is already open keeps running, and your
workspace (~/.gnoc) and keys (~/.config/gnoc) are left alone. With the .deb, it downloads the new
.deb and asks before running `sudo apt install`.

Only the Python standard library, so it works before the private environment exists.
"""
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = (os.environ.get("GNOC_UPDATE_URL") or "https://chat.grey-noc.com/downloads/gnoc-chat/").rstrip("/") + "/"
PAGE = "https://chat.grey-noc.com/gnoc-chat"
# The release key's public half, written in by the release builder. A copy built without one never updates.
RELEASE_KEY = "8a983eb6c416a99d923943f04ca20195c95c3c2d99cd895c00e838dfdf2ce0b9"
HOME_DIR = os.environ.get("GNOC_UPDATE_HOME") or (
    os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "gnoc-chat") if os.name == "nt"
    else os.path.join(os.path.expanduser("~"), ".local", "share", "gnoc-chat"))
STATE = os.path.join(HOME_DIR, "update-check.json")
RELEASES = os.path.join(HOME_DIR, "releases")
DOWNLOADS = os.path.join(HOME_DIR, "updates")
CHECK_EVERY = 20 * 3600     # a background check at most this often
NOTICE_EVERY = 20 * 3600    # the "a new version is out" line at most this often
RETRY_AFTER = 3600          # after a failed check
PROMPT_WAIT = 30            # the "Install it now?" question at start-up: no answer in this long = not now
MANIFEST_MAX = 64 * 1024
PACKAGE_MAX = 512 * 1024 * 1024
UA = "gnoc-chat-updater"


# --------------------------------------------------------------------------- Ed25519 (RFC 8032)
# The reference algorithm from RFC 8032, section 6, in plain Python: the standard library has no
# Ed25519, and the updater must not depend on a package it may be about to replace. Verification is
# the RFC's (decode both points, require S < L, check [S]B = R + [k]A). sign() is here for the
# release builder, which runs it on the operator's own machine; it is not constant-time.
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)
_ZERO = (0, 1, 1, 0)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = _ZERO
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _h(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    return _compress(_mul(_expand(seed)[0], _G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    pub = _compress(_mul(a, _G))
    r = _h(prefix, msg) % _L
    big_r = _compress(_mul(r, _G))
    s = (r + _h(big_r, pub, msg) % _L * a) % _L
    return big_r + s.to_bytes(32, "little")


def verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decompress(pub)
    r = _decompress(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = _h(sig[:32], pub, msg) % _L
    return _equal(_mul(s, _G), _add(r, _mul(k, a)))


# --------------------------------------------------------------------------- versions and state
def _vtuple(v):
    try:
        parts = tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return None
    if not 3 <= len(parts) <= 4 or parts[0] < 2000:
        return None
    return parts + (0,) * (4 - len(parts))


def newer(a, b):
    """Is release version a newer than b? Anything unreadable is never newer."""
    ta, tb = _vtuple(a), _vtuple(b)
    return bool(ta and tb and ta > tb)


def installed_version():
    try:
        with open(os.path.join(APP, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _key():
    try:
        k = bytes.fromhex(RELEASE_KEY)
    except ValueError:
        return None
    return k if len(k) == 32 else None


def _read_state():
    try:
        with open(STATE, encoding="utf-8") as fh:
            st = json.load(fh)
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_state(st):
    os.makedirs(HOME_DIR, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh)
    os.replace(tmp, STATE)


# --------------------------------------------------------------------------- the release
class UpdateError(Exception):
    pass


def _get(url, limit, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(limit + 1)
    if len(body) > limit:
        raise UpdateError(f"{url} is larger than expected")
    return body


def latest_release(timeout=15):
    """The newest signed release on the download page, as its manifest (a dict). Raises UpdateError
    when it cannot be fetched or its signature does not check out."""
    key = _key()
    if not key:
        raise UpdateError("this copy of gnoc chat was built without the release key, so it cannot update itself")
    last = None
    for _ in range(2):  # a publish can land between the two reads: read both again once
        try:
            raw = _get(BASE + "manifest.json", MANIFEST_MAX, timeout)
            sig_text = _get(BASE + "manifest.json.sig", 1024, timeout).decode("ascii", "replace").strip()
        except UpdateError:
            raise
        except Exception as e:  # network, DNS, TLS, HTTP errors
            raise UpdateError(f"could not reach the download page ({e.__class__.__name__}: {e})")
        try:
            import base64
            sig = base64.b64decode(sig_text, validate=True)
        except ValueError:
            sig = b""
        if verify(key, raw, sig):
            try:
                manifest = json.loads(raw.decode("utf-8"))
            except ValueError:
                raise UpdateError("the release manifest is signed but is not JSON")
            if not isinstance(manifest, dict) or manifest.get("name") != "gnoc-chat" or not _vtuple(manifest.get("version")):
                raise UpdateError("the release manifest is signed but is not a gnoc chat release")
            return manifest
        last = "the release on the download page is not signed with the GreyNOC release key"
        time.sleep(1)
    raise UpdateError(last + "; nothing was downloaded")


STALE_DAYS = 120   # a newest release older than this is worth a word: the download server may be serving old files


def _age_days(manifest):
    """Days since the signed manifest was built, or None when it carries no readable time."""
    import calendar
    try:   # "built" is UTC ("...Z"): timegm, never mktime, which would read it as local time
        t = calendar.timegm(time.strptime(str(manifest.get("built") or ""), "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, OverflowError):
        return None
    return max(0.0, (time.time() - t) / 86400)


def _remember(st, m):
    """Record a verified manifest. The highest version ever seen is never lowered: a server that later offers
    an OLDER signed manifest (a stale mirror, or one replayed to hide a fix) is noticed, not believed."""
    v = m["version"]
    seen = st.get("highest_seen")
    if not seen or newer(v, seen):
        st["highest_seen"] = v
    st.update(latest=v, notes=str(m.get("notes") or "")[:600], ok=True, built=m.get("built"))
    st["held_back"] = bool(st.get("highest_seen") and newer(st["highest_seen"], v))


def _prompt(question, wait=PROMPT_WAIT):
    """One line from the terminal, or None when nobody answers within `wait` seconds (an unattended start must
    not sit on a question forever, and silence is never taken as a yes)."""
    sys.stderr.write(question)
    sys.stderr.flush()
    try:
        if os.name == "nt":   # a Windows console cannot be select()ed: poll the keyboard
            import msvcrt
            end = time.time() + wait
            while not msvcrt.kbhit():
                if time.time() >= end:
                    sys.stderr.write("\n")
                    return None
                time.sleep(0.05)
        else:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], wait)
            if not ready:
                sys.stderr.write("\n")
                return None
        line = sys.stdin.readline()
    except (OSError, ValueError, ImportError):
        return None
    return line.strip().lower() if line else None


def _set_auto(on):
    st = _read_state()
    st["auto"] = bool(on)
    st.pop("auto_failed_at", None)
    _write_state(st)


_LAST_INSTALLED = [None]   # where update() just put a new release, for the launcher to start it


def _launch_install(mine):
    """Install the newest release before the chat opens. On success print the new launcher's path on stdout: the
    launcher starts that one instead. Never raises; a failure is one line, the chat opens on the old version,
    and an automatic attempt waits CHECK_EVERY before it tries again."""
    out = sys.stdout
    rc = 1
    try:
        with contextlib.redirect_stdout(sys.stderr):
            rc = update(["--yes"], quiet=True)
    except Exception as e:  # noqa: BLE001 - nothing here may stop gnoc from starting
        sys.stderr.write(f"gnoc update: {e.__class__.__name__}: {e}\n")
    new = _LAST_INSTALLED[0]
    launcher = "gnoc-launcher.py" if os.name == "nt" else "gnoc-launcher"   # Windows: the Python launcher
    if rc == 0 and new and os.path.isfile(os.path.join(new, launcher)):
        out.write(os.path.join(new, launcher) + "\n")
        out.flush()
        return True
    if rc != 0:
        try:
            st = _read_state()
            st["auto_failed_at"] = time.time()
            _write_state(st)
        except OSError:
            pass
        sys.stderr.write(f"  the update did not install; starting {mine}. `gnoc update` tries again.\n")
    return False


def refresh():
    """The background check: remember what the newest release is. Never prints."""
    st = _read_state()
    st["checked_at"] = time.time()
    try:
        _remember(st, latest_release(timeout=10))
    except UpdateError:
        st["ok"] = False
    _write_state(st)


def _interactive():
    return sys.stdin.isatty() and sys.stderr.isatty()


def notice():
    """Called by the launcher on every start; must be quick. Prints the one line at most once a day
    and starts a background check when the last one is old."""
    if os.environ.get("GNOC_NO_UPDATE_CHECK") == "1" or not _key() or not installed_version() or not _interactive():
        return
    try:   # his /privacy switch (updates off, or local-only) stops the automatic check (2026-11-24)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import gnoc_privacy
        if not gnoc_privacy.allowed("updates"):
            return
    except ImportError:
        pass
    st = _read_state()
    now = time.time()
    mine = installed_version()
    latest = st.get("latest")
    due = now - float(st.get("noticed_at") or 0) > NOTICE_EVERY
    if st.get("held_back") and due:
        sys.stderr.write(f"\033[33mgnoc chat: the download page went back to {latest} after offering "
                         f"{st.get('highest_seen')}; updates may be held back. Check {PAGE}\033[0m\n")
        st["noticed_at"] = now
        try:
            _write_state(st)
        except OSError:
            pass
    elif latest and newer(latest, mine) and not os.environ.get("GNOC_JUST_UPDATED"):
        # the launcher reads this script's stdout for the path of a freshly installed launcher; everything a
        # person reads goes to stderr
        if st.get("auto") and not _is_deb_install():
            if now - float(st.get("auto_failed_at") or 0) > CHECK_EVERY:
                sys.stderr.write(f"\033[33mgnoc chat {latest} is out (you have {mine}): installing it "
                                 "(auto-update; gnoc update --auto off turns it off)\033[0m\n")
                _launch_install(mine)
        elif due:
            note = st.get("notes") or ""
            line = f"gnoc chat {latest} is out (you have {mine})."
            if note:
                line += f" New: {note[:140]}"
            st["noticed_at"] = now
            try:
                _write_state(st)
            except OSError:
                pass
            if _is_deb_install():
                sys.stderr.write(f"\033[33m{line}\033[0m Run: gnoc update\n")
            else:
                sys.stderr.write(f"\033[33m{line}\033[0m\n")
                ans = _prompt(f"Install it now? [Y/n/a] (a = always, from now on) ")
                if ans in ("a", "always"):
                    _set_auto(True)
                    sys.stderr.write("  auto-update is on: new releases install when gnoc starts "
                                     "(gnoc update --auto off turns it off)\n")
                    _launch_install(mine)
                elif ans in ("", "y", "yes"):
                    _launch_install(mine)
                else:
                    sys.stderr.write("  not now. Run `gnoc update` when you want it.\n")
    age = now - float(st.get("checked_at") or 0)
    if age > CHECK_EVERY or (st.get("ok") is False and age > RETRY_AFTER):
        try:
            subprocess.Popen([sys.executable, os.path.abspath(__file__), "refresh"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, close_fds=True)
        except OSError:
            pass


def _download(meta, dest_dir):
    """Fetch one package the signed manifest names; check size and SHA-256 while it streams."""
    name = str(meta.get("file") or "")
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise UpdateError("the manifest names a package with an unsafe file name")
    size, want = meta.get("bytes"), str(meta.get("sha256") or "")
    if not isinstance(size, int) or not 0 < size <= PACKAGE_MAX or len(want) != 64:
        raise UpdateError("the manifest's size or hash for the package is not usable")
    os.makedirs(dest_dir, exist_ok=True)
    final = os.path.join(dest_dir, name)
    part = final + ".part"
    h, got = hashlib.sha256(), 0
    req = urllib.request.Request(BASE + urllib.request.quote(name), headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30) as r, open(part, "wb") as out:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                got += len(chunk)
                if got > size:
                    raise UpdateError(f"{name} is larger than the release says")
                h.update(chunk)
                out.write(chunk)
                if sys.stderr.isatty():
                    sys.stderr.write(f"\r  downloading {name}  {got * 100 // size:3d}%")
        if sys.stderr.isatty():
            sys.stderr.write("\n")
    except UpdateError:
        _rm(part)
        raise
    except Exception as e:
        _rm(part)
        raise UpdateError(f"downloading {name} failed ({e.__class__.__name__}: {e})")
    if got != size or h.hexdigest() != want:
        _rm(part)
        raise UpdateError(f"{name} does not match the signed release (size or SHA-256); it was deleted")
    os.replace(part, final)
    return final


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _unpack(tar_path, version):
    """Unpack the release tarball into RELEASES/gnoc-chat-<version>. Only plain files and folders under
    that one top-level folder are accepted; a link, a device or a path that climbs out is refused."""
    prefix = f"gnoc-chat-{version}"
    os.makedirs(RELEASES, exist_ok=True)
    dest = os.path.join(RELEASES, prefix)
    stage = tempfile.mkdtemp(prefix=f".{prefix}-", dir=RELEASES)
    try:
        with tarfile.open(tar_path, "r:gz") as tf:
            for m in tf.getmembers():
                parts = m.name.split("/")
                if parts[0] != prefix or m.name.startswith("/") or ".." in parts or "\\" in m.name:
                    raise UpdateError(f"the package holds an unexpected path ({m.name[:80]})")
                target = os.path.join(stage, *parts)
                if m.isdir():
                    os.makedirs(target, exist_ok=True)
                elif m.isfile():
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    src = tf.extractfile(m)
                    with open(target, "wb") as out:
                        shutil.copyfileobj(src, out)
                    os.chmod(target, 0o755 if m.mode & 0o100 else 0o644)
                else:
                    raise UpdateError(f"the package holds something that is not a file ({m.name[:80]})")
        unpacked = os.path.join(stage, prefix)
        if not os.path.isfile(os.path.join(unpacked, "install.sh")):
            raise UpdateError("the package has no install.sh")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.replace(unpacked, dest)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return dest


def _command_dir():
    """Where the `gnoc` command that points at this copy lives, so the new install.sh replaces that
    one (install.sh's default is ~/.local/bin)."""
    for d in os.environ.get("PATH", "").split(os.pathsep):
        link = os.path.join(d, "gnoc")
        if os.path.islink(link) and os.path.realpath(link) == os.path.realpath(os.path.join(APP, "gnoc-launcher")):
            return d
    return os.environ.get("GNOC_BIN") or os.path.join(os.path.expanduser("~"), ".local", "bin")


def _prune(keep):
    """Keep the release just installed, the one running now and one more; remove older ones."""
    try:
        names = [n for n in os.listdir(RELEASES) if n.startswith("gnoc-chat-") and _vtuple(n[len("gnoc-chat-"):])]
    except OSError:
        return
    names.sort(key=lambda n: _vtuple(n[len("gnoc-chat-"):]), reverse=True)
    running = os.path.realpath(APP)
    spare = 1
    for n in names:
        p = os.path.join(RELEASES, n)
        if os.path.realpath(p) in (running, os.path.realpath(keep)):
            continue
        if spare:
            spare -= 1
            continue
        shutil.rmtree(p, ignore_errors=True)


def _ask(question, default_yes):
    if not sys.stdin.isatty():
        return default_yes
    hint = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"{question} {hint} ").strip().lower()
    except EOFError:
        return default_yes
    return default_yes if not answer else answer in ("y", "yes")


DEB_MARKER = ".installed-by-deb"   # only the .deb ships this file, so a tarball unpacked under /opt is not a .deb


def _is_deb_install():
    return os.path.isfile(os.path.join(APP, DEB_MARKER))


def auto_command(value):
    """gnoc update --auto [on|off]"""
    value = (value or "").strip().lower()
    if value not in ("", "on", "off", "status"):
        print("gnoc update: --auto takes on or off")
        return 2
    if value in ("on", "off"):
        try:
            _set_auto(value == "on")
        except OSError as e:
            print(f"gnoc update: could not save the setting ({e})")
            return 1
    on = bool(_read_state().get("auto"))
    if on:
        print("auto-update is on: when gnoc starts and a newer signed release is out, it installs it first "
              "(gnoc update --auto off turns it off).")
        if _is_deb_install():
            print("  This copy came from the .deb, which only apt can replace: gnoc says when a release is out, and "
                  "`gnoc update` installs it with sudo.")
    else:
        print("auto-update is off: gnoc asks when a newer release is out (gnoc update --auto on installs them by "
              "itself).")
    return 0


def _chat_open_besides_me():
    """True when a gnoc chat runs on this computer other than this process and the ones that started it (the chat
    whose start-up runs this update, and its launcher). Linux /proc; elsewhere: assume none."""
    mine, p = {os.getpid()}, os.getpid()
    for _ in range(8):   # this process's ancestors
        try:
            with open(f"/proc/{p}/stat") as f:
                p = int(f.read().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            break
        if p <= 1:
            break
        mine.add(p)
    try:
        pids = [int(x) for x in os.listdir("/proc") if x.isdigit()]
    except OSError:
        return False
    for pid in pids:
        if pid in mine:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
        except OSError:
            continue
        if any(os.path.basename(a) in ("gnoc", "gnoc-launcher.py") for a in argv[:3]) and "chat" in argv[1:4]:
            return True
    return False


def _engine_release(addr, key="", timeout=4):
    """{'release', 'standalone', ...} that the engine at addr reports, or None when it does not answer as gnoc's."""
    hdr = {"User-Agent": UA}
    if key:
        hdr["Authorization"] = f"Bearer {key}"
    try:
        with urllib.request.urlopen(urllib.request.Request(f"http://{addr}/api/version", headers=hdr),
                                    timeout=timeout) as r:
            d = json.load(r)
    except Exception:  # noqa: BLE001
        return None
    return d if isinstance(d, dict) and d.get("engine") == "gnoc" else None


def restart_local_engine(app_dir, say=print, want=""):
    """Restart this computer's gnoc engine on the release in app_dir, when one is running an older one: the engine
    is its own process and kept serving the old code after every update (2026-11-23). Never while another gnoc chat
    is open here: that would cut its answer off.
    -> 'restarted' | 'current' | 'not-running' | 'chat-open' | 'failed' | 'no-engine'."""
    eng = os.path.join(app_dir, "scripts", "gnoc_engine.py")
    if not os.path.isfile(eng):
        return "no-engine"
    try:
        probe = subprocess.run([sys.executable, "-c", "import json,sys; sys.path.insert(0, sys.argv[1]); "
                                "import gnoc_engine as E; print(json.dumps(E.running() or {}))", os.path.dirname(eng)],
                               capture_output=True, text=True, timeout=30)
        d = json.loads((probe.stdout.strip().splitlines() or ["{}"])[-1])
    except (OSError, ValueError, subprocess.SubprocessError):
        d = {}
    if not d.get("addr"):
        return "not-running"
    host, _, port = str(d["addr"]).rpartition(":")
    at = f"{'127.0.0.1' if host in ('0.0.0.0', '::', '', '[::]') else host}:{port}"
    have = str((_engine_release(at) or {}).get("release") or "")
    if want and have == want:
        return "current"
    if _chat_open_besides_me():
        say(f"  the engine here still runs {have or 'the previous release'}: a gnoc chat is open and a restart would "
            "cut its answer off. It restarts with  gnoc engine restart  (or the next update).")
        return "chat-open"
    try:
        r = subprocess.run([sys.executable, eng, "restart"], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        say(f"  the engine here did not restart ({e.__class__.__name__}): gnoc engine restart")
        return "failed"
    if r.returncode != 0:
        say("  the engine here did not restart: " + ((r.stdout + r.stderr).strip().splitlines() or ["?"])[-1])
        return "failed"
    say(f"  the engine here restarted on {want or 'the new release'}")
    return "restarted"


def _paired_engines():
    """[(address, key)] for the gnoc engines on other computers this install is paired with (gnoc pair)."""
    try:
        sys.path.insert(0, os.path.join(APP, "scripts"))
        import llm_endpoints
        return sorted(llm_endpoints.host_keys().items())
    except Exception:  # noqa: BLE001 - an install without the module has nothing paired
        return []


def update_paired(latest, say=print, apply=True, wait=360):
    """Bring the paired engines to `latest` too: each is asked its release with its key; a standalone engine is
    told to install the newest signed release itself (it checks the signature and the SHA-256 on its side), one
    that is part of gnoc chat there installs the newest gnoc chat (signed, checked there) and restarts its engine on
    it; this waits up to `wait` seconds for it to come back and says what each one runs now. One computer's update
    keeps the others current, with no Ollama anywhere."""
    for addr, key in _paired_engines():
        hdr = {"Authorization": f"Bearer {key}", "User-Agent": UA, "Content-Type": "application/json"}
        try:
            with urllib.request.urlopen(urllib.request.Request(f"http://{addr}/api/version", headers=hdr),
                                        timeout=4) as r:
                d = json.load(r)
        except Exception:  # noqa: BLE001
            say(f"  the engine at {addr} did not answer (it updates itself once a day when it is on)")
            continue
        if d.get("engine") != "gnoc":
            continue
        have = str(d.get("release") or "")
        if have and not newer(latest, have):
            say(f"  the engine at {addr} is current ({have})")
            continue
        if not apply:
            say(f"  the engine at {addr} has {have or 'an older release'}; `gnoc update` updates it too")
            continue
        try:
            req = urllib.request.Request(f"http://{addr}/api/gnoc/update", b"{}", hdr, method="POST")
            with urllib.request.urlopen(req, timeout=300) as r:
                res = json.load(r)
        except Exception as e:  # noqa: BLE001
            say(f"  the engine at {addr} could not update ({e.__class__.__name__}: {e})")
            continue
        if res.get("updating"):
            # a whole gnoc chat there installs in the background and restarts its engine on it: wait for it to come
            # back on the new release (GreyNOC 2026-11-23: "it should communicate with all the attached machines
            # about the restart and update")
            say(f"  the engine at {addr}: {res.get('note') or 'installing the newest gnoc chat there'}")
            if not wait:
                continue
            end, now_have = time.time() + wait, ""
            while time.time() < end:
                time.sleep(5)
                now_have = str((_engine_release(addr, key) or {}).get("release") or "")
                if now_have and not newer(latest, now_have):
                    break
            say(f"  the engine at {addr}: " + (f"updated to {now_have} and restarted" if now_have and not
                                               newer(latest, now_have) else
                                               f"still on {now_have or 'its old release'} after {int(wait)} s "
                                               "(a chat open there waits; `gnoc engine` there shows it)"))
        else:
            say(f"  the engine at {addr}: " + (f"updated to {res.get('latest')}, restarting" if res.get("updated")
                                                else str(res.get("note") or "unchanged")))


def update(args, quiet=False, paired=True, restart=True):
    """quiet=True is the start-up install: the release notes and the installer's own output are left out (the
    installer's is shown when it fails)."""
    _LAST_INSTALLED[0] = None
    check_only = "--check" in args
    assume_yes = "--yes" in args or "-y" in args
    if "-h" in args or "--help" in args:
        print(__doc__.split("\n\n")[1] if "\n\n" in __doc__ else __doc__)
        return 0
    if "--auto" in args:
        i = args.index("--auto")
        return auto_command(args[i + 1] if i + 1 < len(args) else "")
    say = (lambda *a, **k: None) if quiet else print
    mine = installed_version()
    if not mine:
        print("gnoc update: this copy has no VERSION file, so it is not a release install (a source checkout?).")
        return 1
    try:
        m = latest_release()
    except UpdateError as e:
        print(f"gnoc update: {e}.")
        return 1
    v = m["version"]
    st = _read_state()
    st["checked_at"] = time.time()
    _remember(st, m)
    try:
        _write_state(st)
    except OSError:
        pass
    if st.get("held_back"):
        print(f"gnoc update: the download page now offers {v}, older than {st['highest_seen']}, which it offered "
              "before. That is a stale or tampered mirror: nothing was installed. Check " + PAGE)
        return 1
    age = _age_days(m)
    if not newer(v, mine):
        print(f"gnoc chat {mine} is the newest release.")
        if restart and not check_only:
            restart_local_engine(APP, print, mine)   # an earlier update that never restarted the engine
        if paired:
            update_paired(v, say, apply=not check_only, wait=0 if quiet else 360)
        if age is not None and age > STALE_DAYS:
            print(f"  (the newest release on the download page was built {int(age)} days ago; if you expected a "
                  f"newer one, check {PAGE})")
        return 0
    say(f"gnoc chat {v} is out (you have {mine}).")
    if m.get("notes"):
        say(f"  New: {m['notes']}")
    if check_only:
        if paired:
            update_paired(v, say, apply=False)
        print("  Run `gnoc update` to install it.")
        return 0
    files = m.get("files") or {}

    if _is_deb_install():
        meta = files.get("deb")
        if not meta:
            print(f"gnoc update: this release has no .deb. Download it from {PAGE}")
            return 1
        try:
            path = _download(meta, DOWNLOADS)
        except UpdateError as e:
            print(f"gnoc update: {e}.")
            return 1
        print(f"  Signed and checked: {path}")
        print(f"  Install it with:   sudo apt install {path}")
        if _ask("  Run that now?", False):
            sys.stdout.flush()
            # The file sits in a folder this user can write, and the prompt can wait: anything running as the user
            # could swap it before apt runs as root. So root copies it somewhere only root can write and checks
            # the signed SHA-256 THERE, then installs that copy.
            script = ('set -eu; d=$(mktemp -d); trap \'rm -rf "$d"\' EXIT; cp -- "$1" "$d/gnoc-chat.deb"; '
                      'echo "$2  $d/gnoc-chat.deb" | sha256sum -c --quiet -; apt install "$d/gnoc-chat.deb"')
            rc = subprocess.call(["sudo", "sh", "-c", script, "gnoc-update", path, str(meta.get("sha256") or "x")])
            if rc == 0:   # apt replaced the app in place: its engine restarts on it, then the paired computers
                _after_install(APP, v, say, quiet, paired, restart)
            return rc
        return 0

    if os.name == "nt":
        return _update_windows(files, v, mine, assume_yes, quiet, say, paired, restart)
    kind = "macos_tar" if sys.platform == "darwin" else "linux"
    meta = files.get(kind) or files.get("linux")
    if not meta:
        print(f"gnoc update: this release has no package for this system. Download it from {PAGE}")
        return 1
    if not assume_yes and not _ask(f"Install gnoc chat {v} now?", True):
        print("  Nothing was changed.")
        return 0
    try:
        tar_path = _download(meta, DOWNLOADS)
        dest = _unpack(tar_path, v)
    except (UpdateError, tarfile.TarError, OSError) as e:
        print(f"gnoc update: {e}. Nothing was changed.")
        return 1
    env = dict(os.environ, GNOC_BIN=_command_dir())
    say(f"  Installing into {dest}", flush=True)
    if quiet:
        done = subprocess.run(["bash", os.path.join(dest, "install.sh")], cwd=dest, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
        rc = done.returncode
        if rc != 0:
            print("\n".join((done.stdout + done.stderr).strip().splitlines()[-15:]))
    else:
        rc = subprocess.call(["bash", os.path.join(dest, "install.sh")], cwd=dest, env=env)
    if rc != 0:
        print(f"gnoc update: the new version's installer failed (exit {rc}). The gnoc command may still point at {mine}; "
              f"run `bash {os.path.join(dest, 'install.sh')}` to try again.")
        return rc
    _rm(tar_path)
    _prune(dest)
    _LAST_INSTALLED[0] = dest
    if quiet:
        print(f"  gnoc chat {v} is installed.")
    else:
        print(f"\ngnoc chat {v} is installed. A chat that is already open keeps running {mine} until you restart it.")
        if _read_state().get("auto") is None:
            print("  gnoc update --auto on installs the next ones by themselves when gnoc starts.")
    _after_install(dest, v, say, quiet, paired, restart)
    return 0


def _after_install(dest, v, say, quiet, paired, restart):
    """A clean install: this computer's engine restarts on it, then every paired computer is brought to it too."""
    if restart:
        restart_local_engine(dest, print, v)
    if paired:
        update_paired(v, say, apply=True, wait=0 if quiet else 360)


def _unpack_zip(zip_path, version):
    """The Windows package: the same refusals as _unpack (one top-level folder, no absolute path, no `..`, no link)."""
    import zipfile
    prefix = f"gnoc-chat-{version}"
    os.makedirs(RELEASES, exist_ok=True)
    dest = os.path.join(RELEASES, prefix)
    stage = tempfile.mkdtemp(prefix=f".{prefix}-", dir=RELEASES)
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for info in zf.infolist():
                name = info.filename
                parts = [x for x in name.split("/") if x]
                if (not parts or parts[0] != prefix or name.startswith("/") or ".." in parts or "\\" in name
                        or ":" in name):
                    raise UpdateError(f"the package holds an unexpected path ({name[:80]})")
                if ((info.external_attr >> 16) & 0o170000) == 0o120000:
                    raise UpdateError(f"the package holds a link ({name[:80]})")
                target = os.path.join(stage, *parts)
                if name.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        unpacked = os.path.join(stage, prefix)
        if not os.path.isfile(os.path.join(unpacked, "install-windows.ps1")):
            raise UpdateError("the package has no install-windows.ps1")
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.replace(unpacked, dest)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    return dest


def _update_windows(files, v, mine, assume_yes, quiet, say, paired=True, restart=True):
    """Native Windows: download the signed windows zip, unpack it, and run ITS installer (-Quiet). The installer copies
    the release into %LOCALAPPDATA%\\gnoc-chat\\app\\<version> and points the gnoc command at it."""
    import zipfile
    meta = files.get("windows")
    if not meta:
        print(f"gnoc update: this release has no Windows package. Download it from {PAGE}")
        return 1
    if not assume_yes and not _ask(f"Install gnoc chat {v} now?", True):
        print("  Nothing was changed.")
        return 0
    try:
        zip_path = _download(meta, DOWNLOADS)
        dest = _unpack_zip(zip_path, v)
    except (UpdateError, zipfile.BadZipFile, OSError) as e:
        print(f"gnoc update: {e}. Nothing was changed.")
        return 1
    ps = shutil.which("powershell") or "powershell.exe"
    argv = [ps, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
            os.path.join(dest, "install-windows.ps1"), "-Quiet"]
    say(f"  Installing gnoc chat {v}", flush=True)
    if quiet:
        done = subprocess.run(argv, cwd=dest, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace")
        rc = done.returncode
        if rc != 0:
            print("\n".join((done.stdout + done.stderr).strip().splitlines()[-15:]))
    else:
        rc = subprocess.call(argv, cwd=dest)
    if rc != 0:
        print(f"gnoc update: the new version's installer failed (exit {rc}); gnoc still runs {mine}. To try again, "
              f"run {os.path.join(dest, 'install-windows.cmd')}")
        return rc
    _rm(zip_path)
    shutil.rmtree(dest, ignore_errors=True)   # the installer copied it into app\\<version>
    _LAST_INSTALLED[0] = os.path.join(HOME_DIR, "app", v)
    if quiet:
        print(f"  gnoc chat {v} is installed.")
    else:
        print(f"\ngnoc chat {v} is installed. A chat that is already open keeps running {mine} until you restart it.")
    _after_install(_LAST_INSTALLED[0], v, say, quiet, paired, restart)
    return 0


def main(argv):
    cmd, rest = (argv[0], argv[1:]) if argv else ("update", [])
    if cmd == "notice":
        try:
            notice()
        except Exception:  # never let the check stop gnoc from starting
            pass
        return 0
    if cmd == "refresh":
        try:
            refresh()
        except Exception:
            pass
        return 0
    if cmd == "update":
        return update(rest)
    if cmd in ("--check", "--yes", "-y", "-h", "--help", "--auto"):
        return update(argv)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
