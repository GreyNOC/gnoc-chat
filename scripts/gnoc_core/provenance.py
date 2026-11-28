"""Which programme a URL path came from: another programme's material never becomes a route on this one.

Why (initech replay, 2026-11-25 20:21Z): bot 6 ran hunt_search sourceId, which searches EVERY programme. A stayco
capture (targets/stayco/hunts/rate-credit/raw/003-B0-B0_hotels.txt) came back; the bot read it, tried its path on
booking.cheapcaribbean.com (refused OUT_OF_SCOPE for initech), then put the same path on www.initech.com, which the
scope gate passed because the HOST was in scope. The scope gate checks hosts; nothing checked where the PATH came
from. This module remembers the paths seen in other programmes' files during this process, fences that output
with a banner, and the programme gate refuses a request whose path was only ever seen in foreign material.

Stdlib only; gnoc_core never imports gnoc_agent.
"""
import os
import re
import subprocess
import threading
from urllib.parse import unquote, urlsplit



def _ws():
    """The workspace whose targets/ dirs name the programmes. Read at call time from the runtime state, the same
    root gnoc_agent.WS reports: GNOC_WORKSPACE moves it, and so does a test or a chat that rebinds WS. A copy
    fixed to this file's install dir (the 2026.11.26 code) found no targets/ in a packaged install, so the fence
    and the transplant refusal never engaged there."""
    from .state import STATE
    return STATE.ws
_LOCK = threading.Lock()
_FOREIGN: dict[str, str] = {}          # path -> the programme whose material showed it
_MAX = 20000
_OWN_CACHE: dict[tuple[str, str], bool] = {}        # (program, path) -> bool

# a programme dir in a path or a grep hit line: targets/<handle>/...
_TARGET_DIR = re.compile(r"(?:^|[\s\"'(=:])(?:\S*/)?targets/([A-Za-z0-9_.-]+)/")
# a URL path of two or more segments, from a full URL or standing alone
_URL = re.compile(r"https?://[^\s/\"'<>]+(/[^\s\"'<>?#)]*)", re.I)
_BARE = re.compile(r"(?<![\w.~%/-])(/(?:[A-Za-z0-9_.~%-]+/)+[A-Za-z0-9_.~%-]+)")
# filesystem paths are not routes; skip them so the table stays small
_FS = re.compile(r"^/(?:home|tmp|usr|etc|var|opt|proc|dev|mnt|root|srv|bin|lib|run|snap|sys)/")
# a path this generic is a convention every API shares, not something one programme's notes can own
_GENERIC = {"/api/v1", "/api/v2", "/api/graphql", "/graphql", "/.well-known/openid-configuration"}


def _norm(p):
    p = unquote(str(p or "")).rstrip("/")
    return p.lower()


def _keep(p):
    if not p or _FS.match(p) or p.count("/") < 2 or len(p) < 8:
        return False
    return _norm(p) not in _GENERIC


def paths_in(text):
    """The route-shaped paths a piece of text names (normalised, de-duplicated)."""
    out = []
    t = str(text or "")
    for m in _URL.finditer(t):
        if _keep(m.group(1)):
            out.append(_norm(m.group(1)))
    for m in _BARE.finditer(_URL.sub(" ", t)):
        if _keep(m.group(1)):
            out.append(_norm(m.group(1)))
    return list(dict.fromkeys(out))


def _program_of(path):
    m = _TARGET_DIR.search(" " + str(path or ""))
    if not m:
        return ""
    h = m.group(1)
    return h if os.path.isfile(os.path.join(_ws(), "targets", h, "SCOPE.txt")) or \
        os.path.isdir(os.path.join(_ws(), "targets", h)) else ""


def remember(text, program):
    """Record every route-shaped path in text as seen in programme `program`'s material."""
    if not program:
        return 0
    n = 0
    with _LOCK:
        for p in paths_in(text):
            if p not in _FOREIGN and len(_FOREIGN) < _MAX:
                _FOREIGN[p] = program
                n += 1
    return n


def active(ctx=None):
    """The programme this process or chat works: the HUNT_TARGET pin wins, then the chat's set_program."""
    pin = str(os.environ.get("HUNT_TARGET") or "").strip()
    if pin:
        return pin
    return str(getattr(ctx, "program", "") or "").strip()


def _banner(other, mine):
    return (f"[OTHER PROGRAMME: this is {other} material. Its hosts and paths are NOT routes on {mine}; do not "
            f"port them to a {mine} host. A request whose path was only ever seen in another programme's files is "
            f"refused (harness, not the model).]\n")


def fence(ctx, name, args, result):
    """read_file / grep output that comes from another programme's targets dir gets a banner, and its paths are
    remembered as foreign. Output from this programme, or with no programme active, is returned unchanged."""
    mine = active(ctx)
    if not mine or name not in ("read_file", "grep") or not isinstance(args, dict):
        return result
    res = str(result)
    if name == "read_file":
        other = _program_of(args.get("path"))
        if other and other != mine:
            remember(res, other)
            return _banner(other, mine) + res
        return result
    # grep: the hit lines name their file; attribute each line to its programme
    others = set()
    src = _program_of(args.get("path"))
    for line in res.splitlines():
        other = _program_of(line) or src
        if other and other != mine:
            others.add(other)
            remember(line, other)
    if others:
        return _banner(", ".join(sorted(others)), mine) + res
    return result


def _own_has(program, path):
    """True when this programme's own files (not gnoc's own probe captures) name the path. A capture of a request
    we sent proves only that we sent it. Fails open (True) when the search cannot finish."""
    key = (program, path)
    if key in _OWN_CACHE:
        return _OWN_CACHE[key]
    base = os.path.join(_ws(), "targets", program)
    if not os.path.isdir(base):
        return True
    found = True
    try:
        r = subprocess.run(["grep", "-rqiF", "--exclude-dir=gnoc-agent-*", "-e", path, "-e", path.replace("|", "%7c"),
                            base], capture_output=True, timeout=8, stdin=subprocess.DEVNULL)
        found = r.returncode != 1
    except (subprocess.TimeoutExpired, OSError):
        found = True
    with _LOCK:
        _OWN_CACHE[key] = found
    return found


def transplant(program, url):
    """The refusal text when url's path was seen only in another programme's material this process, else ''."""
    try:
        p = _norm(urlsplit(str(url or "")).path)
    except ValueError:
        return ""
    with _LOCK:
        other = _FOREIGN.get(p)
    if not other or other == program or not _keep(p):
        return ""
    if _own_has(program, p):
        return ""
    return (f"refused: the path {p} was seen only in {other}'s files this session, never in {program}'s recon, "
            f"notes or captures. A route from another programme is not a route here; nothing was sent. Pick a path "
            f"from {program}'s own material (hunt_brief, js_mine, known routes) or the vendor's docs.")


def reset():
    with _LOCK:
        _FOREIGN.clear()
        _OWN_CACHE.clear()
