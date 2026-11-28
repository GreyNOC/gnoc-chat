"""llm_endpoints.py - which Ollama server and model a role uses (laptop or the linked Windows desktop).

Roles live in .claude/state/orch/models.json, set with `gnoc models use <role> <model> [--on desktop]`:
    "brain": "qwen3-14b-oc"                    laptop Ollama (ollama-oc, 127.0.0.1:11434)
    "brain": "qwen3.6-35b-a3b-oc@desktop"      the desktop's Ollama through its reverse SSH tunnel (127.0.0.1:11436,
                                               set up by scripts/desktop-link/link-desktop.ps1)
A desktop role whose tunnel is down falls back to the laptop: the role's "<role>_fallback" entry if set, else
qwen3-14b-oc. The health check is cached for 30 s so a dead desktop costs one 2 s probe, not one per call.
"""
import contextlib
import json
import re
import os
import threading
import time
import urllib.error
import urllib.request

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROLES = os.path.join(WS, ".claude/state/orch/models.json")
try:   # importing gnoc_edition also loads this machine's settings (.claude/state/orch/machine.json) into os.environ
    from gnoc_edition import DEFAULT_MODEL as _START_MODEL
except Exception:  # noqa: BLE001
    _START_MODEL = "qwen3:8b"
HOSTS = {# GNOC_LOCAL_OLLAMA moves it (the public build already patched this in; the private one ignored the variable,
         # so a massive hunt meant for a tuned engine on 11471 ran on the 16K one at 11435 and overflowed, 2026-11-25)
         "local": os.environ.get("GNOC_LOCAL_OLLAMA") or "127.0.0.1:11434",
         # 11440 = scripts/desktop-link/traffic_proxy.py (forwards to the real tunnel on 11436,
         # logs every request for the control panel); set GNOC_DESKTOP_OLLAMA to bypass it.
         # A second computer or a phone exists only when its variable is set (machine.json, `gnoc setup`, `gnoc pair`);
         # an empty address fails at once, like a refused port.
         "desktop": os.environ.get("GNOC_DESKTOP_OLLAMA", ""),
         # COMPANY: the USB phone's Ollama (adb forward kept by phone_link.py; it unloads models when hot or flat).
         # Qwen3 there MUST get "think": false or a short num_predict returns an empty reply.
         "phone": os.environ.get("GNOC_PHONE_OLLAMA", "")}


def _hostport(v):
    """host:port from what a user may write: "http://192.168.1.20:11434/" worked nowhere (every URL here is built as
    http://{addr}/..., so it became http://http://...) and the second machine read as always down."""
    v = str(v or "").strip()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v, flags=re.I)
    return v.split("/", 1)[0]


HOSTS = {k: _hostport(v) for k, v in HOSTS.items()}
# a second machine saved by `gnoc setup` (another computer's Ollama on the network). An environment variable wins.
SAVED_HOSTS = os.path.join(WS, ".claude/state/orch/hosts.json")


def _saved_hosts():
    try:
        with open(SAVED_HOSTS) as f:
            d = json.load(f)
        return {k: _hostport(v) for k, v in d.items() if k in ("desktop", "phone", "local") and isinstance(v, str)} \
            if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


for _k, _v in _saved_hosts().items():
    # "local" is saved when setup runs gnoc's engine beside an Ollama that already holds the default port
    if not os.environ.get({"desktop": "GNOC_DESKTOP_OLLAMA", "phone": "GNOC_PHONE_OLLAMA",
                           "local": "GNOC_LOCAL_OLLAMA"}[_k]) and _v:
        HOSTS[_k] = _v
# where gnoc's engine listens when an Ollama already holds 11434 on this computer
ENGINE_BESIDE_OLLAMA = "127.0.0.1:11439"


# The keys of paired gnoc engines on other computers (gnoc pair <address> <key>), by host:port. Owner-only file.
# GNOC_DESKTOP_KEY wins for the desktop's address. Every urllib request this process makes to one of those addresses
# carries "Authorization: Bearer <key>" (a urllib handler below), so no call site has to remember it.
HOST_KEYS = os.path.join(WS, ".claude/state/orch/host-keys.json")


def host_keys():
    try:
        with open(HOST_KEYS) as f:
            d = json.load(f)
        keys = {_hostport(k): str(v) for k, v in d.items() if isinstance(v, str) and v} if isinstance(d, dict) else {}
    except (OSError, ValueError):
        keys = {}
    env = os.environ.get("GNOC_DESKTOP_KEY", "").strip()
    if env and HOSTS.get("desktop"):
        keys[HOSTS["desktop"]] = env
    return keys


def save_host_key(addr, key):
    """Remember a paired engine's key (owner-only file). An empty key forgets it."""
    try:
        with open(HOST_KEYS) as f:
            d = json.load(f)
        d = d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        d = {}
    a = _hostport(addr)
    if key:
        d[a] = str(key).strip()
    else:
        d.pop(a, None)
    os.makedirs(os.path.dirname(HOST_KEYS), exist_ok=True)
    tmp = HOST_KEYS + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, HOST_KEYS)
    with contextlib.suppress(OSError):
        os.chmod(HOST_KEYS, 0o600)


class _HostKeyHandler(urllib.request.BaseHandler):
    """Adds a paired engine's key to plain-HTTP requests for its address (never to any other host, never on a
    redirect: the header is unredirected)."""
    handler_order = 400

    def http_request(self, req):
        with contextlib.suppress(Exception):
            key = host_keys().get(_hostport(req.host))
            if key and not req.has_header("Authorization"):
                req.add_unredirected_header("Authorization", f"Bearer {key}")
        return req


urllib.request.install_opener(urllib.request.build_opener(_HostKeyHandler()))


def save_host(key, addr):
    """Remember another machine's Ollama address (host:port) for every later start."""
    d = _saved_hosts()
    d[key] = _hostport(addr)
    _write_json(SAVED_HOSTS, d)
    HOSTS[key] = d[key]
    _health.pop(key, None)
# CLOUD providers (gnoc_cloud.py) are hosts too, so "deepseek-chat@deepseek" resolves like any other role.
# They are NOT in HOSTS: HOSTS values are host:port for a plain-HTTP Ollama, and a cloud provider is an
# https OpenAI-compatible endpoint with a key. up() and stock() special-case them below.
try:
    from gnoc_cloud import PROVIDERS as CLOUD_PROVIDERS
except Exception:  # noqa: BLE001 - the module is optional; without it nothing cloud exists
    CLOUD_PROVIDERS = {}
DEFAULT = os.environ.get("GNOC_DEFAULT_MODEL") or _START_MODEL   # the role default when models.json names none
_health = {}

# REMOVED 2026-11-27 (allow_stock() is always True); kept as history: UNCENSORED ONLY (GreyNOC 2026-10-22). A stock
# model refuses or waters down security work mid-hunt, and the
# desktop carries stock builds (qwen3.6, qwen2.5, gpt-oss:20b) plus a CLOUD model (kimi-k3:cloud) that would
# send the conversation off the machine. A model counts as uncensored by its name, or - for a local wrapper
# like qwen3-14b-oc - by its weights: the wrapper's FROM blob is the blob of a model whose name says so.
UNCENSORED = re.compile(r"abliterat|uncensor|heretic|hauhau|huihui|dolphin", re.I)
_stock_cache = {}
_stock_unknown = {}   # (host, name) -> when a verdict could not be had (host down): retried after 30 s


def is_cloud(host):
    # The merged provider table (builtins + ~/.config/gnoc/cloud-providers.json) is re-read every call,
    # so `/cloud add localai ...` is recognized by this running process without a restart.
    try:
        import gnoc_cloud
        return gnoc_cloud.is_cloud(host)
    except Exception:  # noqa: BLE001 - without the module nothing cloud exists
        return str(host or "").lower() in CLOUD_PROVIDERS


def allow_stock():
    """Always True: any model may fill any role (the user 2026-11-27, "remove the uncensored model requirement"). The
    function stays so older callers and plugins keep working; stock() still says what a model is. A public install refused its own default (qwen3:8b) and the user's qwen3:14b, hid them from /model and
    re-routed every turn to a model that was not pulled, so "hello" hung (the user 2026-11-22, a WSL install).
    GNOC_ALLOW_STOCK is no longer read."""
    return True


def _post(host, path, body, timeout=4):
    req = urllib.request.Request(f"http://{HOSTS[host]}{path}", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


_blob_cache = {}
_marked_cache = {}
# Verdicts survive restarts, keyed by the model's content digest (same digest = same weights = same verdict).
# The first /model of every process used to make ~76 HTTP calls, several through the desktop tunnel, and froze
# for seconds whenever the desktop was busy (GreyNOC: "/model is buggy and doesnt load sometimes", 2026-10-22).
STOCK_DISK = os.path.join(os.path.dirname(ROLES), "stock-verdicts.json")


def _from_blob(host, name):
    """The sha256 blob a model is built FROM ('' when it names none). Raises when the host does not answer."""
    key = (host, name)
    if key not in _blob_cache:
        mf = (_post(host, "/api/show", {"model": name}) or {}).get("modelfile") or ""
        m = re.search(r"^FROM\s+\S*?(sha256[-:][0-9a-f]{12,})", mf, re.M)
        _blob_cache[key] = m.group(1).replace(":", "-") if m else ""
    return _blob_cache[key] or None


def _tags(host, timeout=4):
    with urllib.request.urlopen(f"http://{HOSTS[host]}/api/tags", timeout=timeout) as r:
        return {m.get("name"): m.get("digest") or "" for m in json.load(r).get("models") or [] if m.get("name")}


def _disk_verdicts():
    try:
        with open(STOCK_DISK) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _remember_verdict(host, name, digest, verdict):
    if not digest:
        return
    with _ledger_locked(STOCK_DISK):
        d = _disk_verdicts()
        d[f"{host}|{name}|{digest}"] = verdict
        _write_json(STOCK_DISK, d)


def stock(name, host="local", tags=None):
    """True when (name, host) is a STOCK model, False when uncensored, None when it cannot be told (the host is
    unreachable): callers must not take a working route down on a None. Cached per process and on disk by digest.
    tags: the host's {name: digest} when the caller already fetched it (model_rows does)."""
    if not name or host == "split" or UNCENSORED.search(name):
        return False
    if is_cloud(host):
        # Asked for BY NAME via /deepseek on, with the cloud warning shown at that moment. The
        # local-uncensored rule exists to stop a stock model being picked silently; this one never is.
        return False
    if name.endswith(":cloud") or "-cloud" in name:
        return True   # a cloud model is never uncensored and never local
    key = (host, name)
    if key in _stock_cache:
        return _stock_cache[key]
    if host not in HOSTS or not HOSTS.get(host):
        return None
    miss = _stock_unknown.get(key)
    if miss and time.time() - miss < 30:
        return None   # asked in the last 30 s and the host did not answer: do not pay its timeout again
    if is_down(host) or (host in _health and not _health[host][0] and time.time() - _health[host][1] < 30):
        return None   # a host already known to be down is "unknown", at no cost (it cost 4 s on EVERY resolve)
    try:
        tags = tags if tags is not None else _tags(host)
        digest = tags.get(name) or tags.get(name + ":latest") or ""
        disk = _disk_verdicts().get(f"{host}|{name}|{digest}") if digest else None
        if isinstance(disk, bool):
            _stock_cache[key] = disk
            return disk
        mine = _from_blob(host, name)
        if host not in _marked_cache:   # the uncensored blobs on a host, looked up once, not once per model
            _marked_cache[host] = {_from_blob(host, n) for n in tags if UNCENSORED.search(n)}
        verdict = not (mine and mine in _marked_cache[host])
    except Exception:   # noqa: BLE001 - an unreachable host is "unknown", never "stock"
        _stock_unknown[key] = time.time()
        return None
    _stock_cache[key] = verdict
    _remember_verdict(host, name, digest, verdict)
    return verdict


def _version_url(host_key):
    return "http://" + HOSTS[host_key] + "/api/version"


def up(host_key):
    """True when that Ollama answers /api/version (cached 30 s). Never raises.

    A BLACK-HOLED host is the expensive case, and the one that made `gnoc chat` look hung (2026-10-26): a dead
    reverse tunnel ACCEPTS the connection and then never answers, so the patient 2 s + 6 s ladder below burned
    4.1 s per call, twice per role through gnoc_agent._host_up, before the repl printed its first line.
    record()/is_down() already knew the host was benched; up() just never asked them. So while a host sits in
    its down window it gets ONE 0.6 s recovery sniff instead of the ladder (a healthy tunnel answers
    /api/version in milliseconds), and every probe now feeds the trip ledger that sets the window.
    """
    now = time.time()
    if host_key in HOSTS and not HOSTS[host_key]:
        return False   # a machine this install does not have: not probed, and never written to the ledger
    if host_key in _health and now - _health[host_key][1] < 30:
        return _health[host_key][0]
    ok = False
    # A TIMEOUT gets one more, patient try: one slow /api/version (the desktop loading a 10 GB model, or busy with
    # another chat) used to mark it down for 30 s and drop the lead onto the laptop's 16k window, where a full turn
    # overflowed (2026-10-22). Any other failure (refused, no route, unknown host key) is final at once.
    for limit in ((0.6,) if is_down(host_key, now) else (2, 6)):
        try:
            with urllib.request.urlopen(f"http://{HOSTS[host_key]}/api/version", timeout=limit) as r:
                ok = r.status == 200
            break
        except Exception as e:
            if not isinstance(getattr(e, "reason", e), TimeoutError):
                break
    if host_key in HOSTS:
        record(host_key, ok, now)   # a success clears the bench, three failures set the next one
    _health[host_key] = (ok, now)
    return ok


def sniff(host_key, timeout=0.6):
    """One SHORT /api/version probe that neither reads nor writes the 30 s cache. A healthy host answers in
    milliseconds, so this is the cheap way to ask "was that failure a blip?" without paying up()'s patient
    2 s + 6 s ladder a second time. Never raises."""
    try:
        with urllib.request.urlopen(_version_url(host_key), timeout=timeout) as r:
            return r.status == 200
    except Exception:   # noqa: BLE001
        return False


def roles():
    try:
        with open(ROLES) as fh:   # called on every resolve(): do not leak the fd
            d = json.load(fh)
    except (OSError, ValueError):
        d = {}
    d = d if isinstance(d, dict) else {}   # a list / string on disk broke every .get() caller
    # GNOC_ROLE_LEAD=<model[@host]> (or _WORKER, _CHAT ...) sets a role for THIS run only, the saved roles untouched:
    # a test drive or a one-off chat on another model without changing his setting (2026-11-23)
    for k, v in os.environ.items():
        if k.startswith("GNOC_ROLE_") and v.strip():
            d = dict(d, **{k[len("GNOC_ROLE_"):].lower(): v.strip()})
    return d


def multi_machine():
    """True when a second machine is set up (the operator's linked desktop, or one saved by `gnoc setup`)."""
    return bool(HOSTS.get("desktop"))


def host_label(host):
    """What a person calls a host. A public install with one computer said "the laptop model list did not
    arrive" and "loading models from both machines" (the user 2026-11-22: "if we dont set up another computer
    ... it should run without laptop labeling"). The operator's own two-machine rig keeps laptop / desktop."""
    local = os.environ.get("GNOC_LOCAL_NAME", "").strip()
    other = os.environ.get("GNOC_DESKTOP_NAME", "").strip()
    if host == "local":
        return local if (local and multi_machine()) else "this computer"
    if host == "desktop":
        return other or "the other computer"
    if host == "split":
        return f"{other}+{local}" if (local and other) else "both computers"
    return str(host)


def split(spec):
    """'name@desktop' -> ('name', 'desktop'); 'name' -> ('name', 'local')."""
    spec = spec.strip() if isinstance(spec, str) else ""   # a number / dict in models.json raised here
    # CLOUD providers are hosts for routing but deliberately absent from HOSTS (they are not host:port Ollamas).
    # Omitting them here made "deepseek-chat@deepseek" split to ("deepseek-chat@deepseek", "local"): the suffix
    # stayed in the MODEL NAME and the call went to the local Ollama, which answered
    # `HTTP 400 {"error":"invalid model name"}` (GreyNOC, 2026-10-28, first real /deepseek on).
    if "@" in spec and (spec.rsplit("@", 1)[1] in HOSTS or is_cloud(spec.rsplit("@", 1)[1])):
        name, host = spec.rsplit("@", 1)
        if host not in HOSTS:   # a provider alias ("opus@claude") routes as its provider ("anthropic")
            try:
                import gnoc_cloud
                host = gnoc_cloud.canonical(host)
            except Exception:  # noqa: BLE001
                pass
        return name, host
    return spec, "local"


def resolve(role, default=DEFAULT):
    """(chat_url, model, host_key) for a role, falling back to the laptop when the desktop is unreachable."""
    r = roles()
    name, host = split(r.get(role) or default)
    if is_cloud(host):
        try:
            import gnoc_cloud
            if gnoc_cloud.key_for(host) or gnoc_cloud.keyless(host):
                return f"cloud://{host}", name, host     # _llm_chat_once routes on the host key
        except Exception:  # noqa: BLE001
            pass
        name, host = split(default)[0], "local"          # no key: silently local, never a dead role
    if host != "local" and not is_cloud(host) and not up(host):
        # ONE fallback, and it is always the laptop: a fallback naming a remote host is not probed (a second
        # dead host would cost a second timeout, and it may be the very host that just failed)
        name, host = split(r.get(f"{role}_fallback") or default)
        if host != "local":
            name, host = split(default)[0], "local"
    if not name:   # 'x@desktop' with no model name, or an empty entry: never send model=""
        name = split(default)[0] or DEFAULT
    if not allow_stock() and stock(name, host):   # uncensored only: a stock role answers from the default
        name, host = DEFAULT, "local"
    return f"http://{HOSTS[host]}/api/chat", name, host


# ---- per-endpoint health with failover (2026-10-24) ----------------------------------------------------------
# State in .claude/state/orch/llm-health.json {host: {"fails": n, "trips": n, "down_until": epoch}}. Three consecutive
# failures mark a host down for 10 min, doubling per repeat trip up to 60 min; a success resets it. pick() probes
# /api/tags with a 2 s timeout before choosing, in order desktop -> laptop (local, 11434) -> phone.
HEALTH_FILE = os.path.join(WS, ".claude/state/orch/llm-health.json")
FAIL_LIMIT, DOWN_BASE, DOWN_MAX = 3, 600, 3600
ORDER = ("desktop", "local", "phone")


def _health_load():
    try:
        with open(HEALTH_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _health_save(d):
    _write_json(HEALTH_FILE, d)


def _write_json(path, d):
    """Atomic, with one temp file per writer: threads of one process shared "<file>.<pid>.tmp" and 8 threads
    recording at once gave 688 corrupt reads and lost a host's bench (QAQC 2026-11-19)."""
    import tempfile
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix="." + os.path.basename(path) + ".")
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
        os.replace(tmp, path)
    except OSError:
        pass


_LEDGER_LOCK = threading.Lock()


@contextlib.contextmanager
def _ledger_locked(path):
    """This process's threads and other processes: a read-modify-write of a shared state file is one step."""
    import fcntl
    with _LEDGER_LOCK:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            lk = open(path + ".lock", "a")
        except OSError:
            yield
            return
        with lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lk, fcntl.LOCK_UN)


def record(host, ok, now=None):
    """Note one success/failure for a host. Returns True when this call tripped it to 'down'."""
    now = time.time() if now is None else now
    with _ledger_locked(HEALTH_FILE):
        return _record(host, ok, now)


def _record(host, ok, now):
    d = _health_load()
    h = d.get(host) if isinstance(d.get(host), dict) else {}
    tripped = False
    if ok:
        h = {"fails": 0, "trips": 0, "down_until": 0}
    else:
        h["fails"] = int(h.get("fails", 0)) + 1
        if h["fails"] >= FAIL_LIMIT:
            h["trips"] = int(h.get("trips", 0)) + 1
            h["down_until"] = now + min(DOWN_BASE * 2 ** (h["trips"] - 1), DOWN_MAX)
            h["fails"] = 0
            tripped = True
    d[host] = h
    _health_save(d)
    return tripped


def is_down(host, now=None):
    now = time.time() if now is None else now
    h = _health_load().get(host)
    return bool(isinstance(h, dict) and float(h.get("down_until", 0)) > now)


def probe(host, timeout=2):
    """Quick /api/tags check; records the outcome. Never raises."""
    try:
        with urllib.request.urlopen(f"http://{HOSTS[host]}/api/tags", timeout=timeout) as r:
            ok = r.status == 200
    except Exception:   # noqa: BLE001
        ok = False
    record(host, ok)
    return ok


def pick(order=ORDER, start=None):
    """First healthy host in order (starting at `start` when given), or None. A host in its down window is skipped
    without a probe; otherwise it is probed (2 s) and a failure counts toward its trip."""
    order = list(order)
    if start in order:
        order = order[order.index(start):]
    for h in order:
        if h not in HOSTS or not HOSTS[h]:
            continue
        if is_down(h):
            if sniff(h, 0.6):   # benched, but answering again: one cheap probe, not 10-60 min away
                record(h, True)
                return h
            continue
        if probe(h):
            return h
    return None


def failover(role, default=DEFAULT):
    """(chat_url, model, host_key) like resolve(), but a role configured on the desktop walks desktop -> laptop -> phone
    by health. Roles not on the desktop, and a healthy desktop, behave exactly as resolve(). None when nothing is up."""
    r = roles()
    name, host = split(r.get(role) or default)
    if host != "desktop":
        return resolve(role, default)
    got = pick(ORDER)
    if got is None:
        return None
    if got == "desktop":
        return resolve(role, default)
    if got == "local":
        n2, h2 = split(r.get(f"{role}_fallback") or default)
        n2 = n2 if h2 == "local" and n2 else split(default)[0] or DEFAULT
    else:   # phone: only with a model named for it, role key "<role>_phone"
        n2, h2 = split(r.get(f"{role}_phone") or "")
        if not n2:
            return None
    if not allow_stock() and stock(n2, got):
        if got != "local":
            return None
        n2 = DEFAULT
    return f"http://{HOSTS[got]}/api/chat", n2, got


# D67 (2026-10-26 08:43Z): the per-host num_ctx EVERY caller sends. The lead sent 32768 to the desktop and the
# orch-bot brain 16384 for the same 35B; Ollama starts a new runner when num_ctx changes, so the model unloaded and
# reloaded 14 times in five minutes (08:35Z-08:40Z) while the two alternated, and two of the lead's calls got a 500
# that read as "cannot start". One table, imported by gnoc_agent.CTX and orch_brain.
CTX = {"local": 16384, "desktop": 32768, "split": 16384}


def ctx_for_host(host):
    return CTX.get(host, 16384)

# D74 (2026-10-26 09:36Z): the overflow handler in gnoc_agent.llm_chat answered an exceed_context_size 400 by asking
# for a bigger window (prompt + 2048, up to 65536). On the desktop's 16 GB card the 35B at 32768 already holds ~14 GB;
# the bigger runner died at start ("exit status 0xc0000409 ... CUDA error: shared object initialization failed"),
# the lead read it as "cannot start" and fell to the 9B. Past this ceiling the prompt is trimmed, not the window grown.
CTX_MAX = {"local": 16384, "desktop": 32768, "split": 16384}


def ctx_max(host):
    return CTX_MAX.get(host, 65536)
