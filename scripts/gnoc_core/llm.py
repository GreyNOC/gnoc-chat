"""Models and the LLM client: role resolution and routing, broken/down hosts, the OpenAI-compatible and Ollama chat calls with retries, context percentages."""
import http.client
import contextlib
import os

import gnoc_edition
import re
import threading

from . import providers as _providers
from .runtime import bind


def role_spec(role):
    (
        DEFAULT_LEAD, DEFAULT_WORKER, llm_endpoints,
    ) = bind(
        "DEFAULT_LEAD", "DEFAULT_WORKER", "llm_endpoints",
    )
    default = DEFAULT_LEAD if role == "lead" else DEFAULT_WORKER
    return llm_endpoints.roles().get(role) or default


# the both-GPU split server spans two machines: it exists only when GNOC_SPLIT_URL says so (machine.json)
SPLIT_URL = os.environ.get("GNOC_SPLIT_URL", "")


_split_health = [None, 0.0]


def split_up():
    """True when the both-GPU llama-server (gnoc split up) answers /health (cached 20 s)."""
    (
        SPLIT_URL, _split_health, time, urllib,
    ) = bind(
        "SPLIT_URL", "_split_health", "time", "urllib",
    )
    if time.time() - _split_health[1] < 20:
        return _split_health[0]
    try:
        with urllib.request.urlopen(SPLIT_URL + "/health", timeout=2) as r:
            ok = b"ok" in r.read()
    except Exception:
        ok = False
    _split_health[:] = [ok, time.time()]
    return ok


# Measured 2026-10-22: the laptop is an RX 7700S (8 GB, Vulkan), the desktop an RTX 5060 Ti (16283 MiB).
# Used only to label a row "fits GPU" / "partly offloaded", so being approximate is fine.
_VRAM_GB = {"local": 8.0, "desktop": 16.0}


def _fit_note(size_bytes, host):
    (
        _VRAM_GB,
    ) = bind(
        "_VRAM_GB",
    )
    g, v = (size_bytes or 0) / 1e9, _VRAM_GB.get(host, 8.0)
    if not g:
        return ""
    return "fits GPU" if g <= v - 1.2 else ("partly offloaded" if g <= v * 1.5 else "too big")


def model_rows():
    """[(host, name, size_bytes)] for every model on both Ollamas, laptop first. Both lists are fetched at once (a
    busy desktop used to hold the laptop's list hostage) and a host that did not answer is named in
    MODEL_ROWS_MISSING instead of silently vanishing from the picker."""
    (
        MODEL_ROWS_MISSING, _parallel, json, llm_endpoints,
    ) = bind(
        "MODEL_ROWS_MISSING", "_parallel", "json", "llm_endpoints",
    )
    import urllib.request

    def fetch(host):
        addr = llm_endpoints.HOSTS.get(host)
        if not addr:
            return None
        for limit in (4, 8):   # a busy desktop gets one patient retry, like up()
            try:
                with urllib.request.urlopen(f"http://{addr}/api/tags", timeout=limit) as r:
                    return json.loads(r.read().decode()).get("models") or []
            except Exception as e:  # noqa: BLE001
                if not isinstance(getattr(e, "reason", e), TimeoutError):
                    return None
        return None
    got = _parallel([lambda h=h: fetch(h) for h in ("local", "desktop")], max_workers=2, timeouts=[14, 14])
    del MODEL_ROWS_MISSING[:]
    rows = []
    for host, models in zip(("local", "desktop"), got):
        if not isinstance(models, list):
            if llm_endpoints.HOSTS.get(host):
                MODEL_ROWS_MISSING.append(host)
            continue
        tags = {m.get("name"): m.get("digest") or "" for m in models if m.get("name")}
        for m in models:
            name = m.get("name", "?")
            if not llm_endpoints.allow_stock() and llm_endpoints.stock(name, host, tags=tags):
                continue   # uncensored only: a stock or cloud model is not offered
            rows.append((host, name, m.get("size") or 0))
    return rows


def _read_key(fd):
    """One keypress: 'up', 'down', 'enter', 'quit', or the literal character."""
    (
        os,
    ) = bind(
        "os",
    )
    ch = os.read(fd, 1).decode("utf-8", "ignore")
    if ch == "\x1b":
        # A BARE Esc sends one byte and nothing else: reading 2 more blocked until the next keypress, so
        # Esc hung the panel and the model picker (measured 2026-10-22). Wait briefly for a sequence.
        import select
        if not select.select([fd], [], [], 0.05)[0]:
            return "quit"
        rest = os.read(fd, 2).decode("utf-8", "ignore")
        if rest in ("[5", "[6"):              # PgUp / PgDn send ESC [ 5 ~ and ESC [ 6 ~
            if select.select([fd], [], [], 0.05)[0]:
                os.read(fd, 1)
            return "pgup" if rest == "[5" else "pgdn"
        return {"[A": "up", "[B": "down", "[H": "g", "[F": "G"}.get(rest, "quit")
    if ch in ("\r", "\n"):
        return "enter"
    if ch in ("q", "\x03", "\x04"):
        return "quit"
    return ch


def _cloud_model_rows():
    """[(provider, default_model, 0)] for every registered cloud provider, so the /model picker offers a
    cloud model as the lead too, not just the Ollama rows (2026-10-29: the picker was local-only)."""
    out = []
    try:
        import gnoc_cloud
        for p in gnoc_cloud.providers():   # table order: Claude first
            base, env, default, models = gnoc_cloud.providers()[p]
            if default:
                out.append((p, default, 0))
    except Exception:  # noqa: BLE001 - no gnoc_cloud module, no cloud rows
        pass
    return out


def _cloud_state(provider):
    """One word for the picker row: 'key set' / 'keyless' / 'NO KEY' for a registered cloud provider."""
    try:
        import gnoc_cloud
        if gnoc_cloud.keyless(provider):
            return "keyless"
        return "key set" if gnoc_cloud.key_for(provider) else "NO KEY"
    except Exception:  # noqa: BLE001
        return ""


def pick_model(current_lead=None, current_worker=None):
    """Arrow-key picker over both machines and the registered cloud providers. Returns (role, spec) or None
    if cancelled."""
    (
        MODEL_ROWS_MISSING, T, _cloud_model_rows, _cloud_state, _fit_note, _read_key, dim, model_rows, red, say,
        shutil, sys, termios, tty, yellow,
    ) = bind(
        "MODEL_ROWS_MISSING", "T", "_cloud_model_rows", "_cloud_state", "_fit_note", "_read_key", "dim",
        "model_rows", "red", "say", "shutil", "sys", "termios", "tty", "yellow",
    )
    _ep = __import__("llm_endpoints")
    say(dim("  loading models from both machines..." if _ep.multi_machine() else "  loading models..."))
    rows = model_rows() + _cloud_model_rows()
    for host in MODEL_ROWS_MISSING:
        say(yellow(f"  the model list from {_ep.host_label(host)} did not arrive (busy or not running); showing "
                   "what answered") + dim("  (gnoc models desktop checks the link)" if host == "desktop" else
                                         "  (is Ollama running? `ollama list` checks it)"))
    if not rows:
        say(red("  no models to pick: neither Ollama is reachable and no cloud provider is registered")
            + dim("  (start Ollama, or run gnoc setup; /cloud add registers an OpenAI-compatible endpoint)"))
        return None
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return None  # not a terminal: the caller prints the plain listing instead

    def spec_of(i):
        host, name, _ = rows[i]
        return name if host == "local" else f"{name}@{host}"   # desktop and cloud hosts both ride the @suffix

    sel = next((i for i in range(len(rows)) if spec_of(i) == current_lead), 0)
    view = min(len(rows), max(6, shutil.get_terminal_size((100, 24)).lines - 8))
    top = max(0, min(sel - view // 2, len(rows) - view))
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    drawn = 0

    def draw():
        nonlocal drawn, top
        if sel < top:
            top = sel
        elif sel >= top + view:
            top = sel - view + 1
        out = []
        last_host = None
        # every line fits the terminal: a 97-column row wrapped on a narrower WSL window, the redraw moved up by
        # the unwrapped count, and every key press printed the list again (GreyNOC's desktop, 2026-11-23)
        cols = max(40, shutil.get_terminal_size((100, 24)).columns)
        for i in range(top, min(top + view, len(rows))):
            host, name, size = rows[i]
            if host != last_host:
                last_host = host
                out.append(dim(("  " + (_ep.host_label(host) if host in ("local", "desktop")
                                        else "cloud " + host))[:cols - 1]))
            spec = spec_of(i)
            mark = " ←lead" if spec == current_lead else (" ←worker" if spec == current_worker else "")
            tail = (f" {size / 1e9:5.1f} GB  {_fit_note(size, host)}" if host in ("local", "desktop")
                    else f" {'cloud':>9}  {_cloud_state(host)}")   # a cloud provider row: the key state matters
            namew = max(12, min(58, cols - 1 - 4 - len(tail) - len(mark)))
            nm = name if len(name) <= namew else name[:namew - 1] + "…"
            label = (f"{nm:<{namew}}" + tail)[:max(8, cols - 1 - 4 - len(mark))]
            out.append((T.byellow("  ▸ " + label) if i == sel else dim("    " + label)) + T.blue(mark))
        hint = "  ↑↓ move · enter = lead · w = worker · q = cancel"
        if top > 0 or top + view < len(rows):
            hint += f"   [{sel + 1}/{len(rows)}]"
        out.append(dim(hint[:cols - 1]))
        if drawn:
            sys.stdout.write(f"\x1b[{drawn}A")
        for line in out:
            sys.stdout.write("\x1b[2K" + line + "\n")
        sys.stdout.flush()
        drawn = len(out)

    try:
        tty.setcbreak(fd)
        while True:
            draw()
            k = _read_key(fd)
            if k == "up":
                sel = (sel - 1) % len(rows)
            elif k == "down":
                sel = (sel + 1) % len(rows)
            elif k == "enter":
                return "lead", spec_of(sel)
            elif k == "w":
                return "worker", spec_of(sel)
            elif k == "quit":
                return None
    except (OSError, termios.error) as e:
        # a real terminal problem: say so rather than looking like the user pressed q
        say(dim(f"  picker unavailable ({type(e).__name__}); use /model <name>[@desktop]"))
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\x1b[0m")
        sys.stdout.flush()


def _split_flags(text, value=(), boolean=()):
    """(words, {flag: [values]}, {flags}), error. Shell-quoted, so --accept "a; b" is one value. Unknown
    --flags stay in the words: a task may legitimately contain them, and swallowing them silently is worse
    than letting the goal/task text keep them. `--` ends flag parsing."""
    (
        shlex,
    ) = bind(
        "shlex",
    )
    try:
        toks = shlex.split(text or "")
    except ValueError:
        toks = (text or "").split()
    vals = {k: [] for k in value}
    flags = set()
    words = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "--":
            words.extend(toks[i + 1:])
            break
        key, eq, inline = t.partition("=")
        if key in boolean:
            if eq:
                return None, f"{key} does not take a value"
            flags.add(key)
            i += 1
            continue
        if key in value:
            if eq:
                vals[key].append(inline)
                i += 1
                continue
            if i + 1 >= len(toks):
                return None, f"{key} needs a value"
            vals[key].append(toks[i + 1])
            i += 2
            continue
        words.append(t)
        i += 1
    return (words, vals, flags), None


def routing_text():
    """What the agent is really talking to right now, split state included.

    /model with no argument used to print the legacy simple-chat's model, which is not what answers you."""
    (
        SPLIT_FLAG, SPLIT_GRACE_S, dim, green, llm_endpoints, os, red, resolve, role_spec, split_up, time,
    ) = bind(
        "SPLIT_FLAG", "SPLIT_GRACE_S", "dim", "green", "llm_endpoints", "os", "red", "resolve", "role_spec",
        "split_up", "time",
    )
    out = []
    flagged = os.path.exists(SPLIT_FLAG)
    if flagged and split_up():
        out.append(green("  split: ON") + f"  both roles answer from the both-GPU split server ({SPLIT_URL})")
    elif flagged:
        age = (time.time() - os.path.getmtime(SPLIT_FLAG)) / 60
        out.append(red("  split: ENABLED BUT NOT SERVING") + dim(f"  (set {age:.0f} min ago; "
                   + ("roles are forced to the laptop until it comes up" if age * 60 < SPLIT_GRACE_S
                      else "ignored now, your roles below are in force")
                   + ")  gnoc split status | gnoc split down"))
    for role in ("lead", "worker"):
        want = role_spec(role)
        name, host = resolve(role, quiet=True)  # this text already shows any fallback, in red
        line = f"  {role:<7} {want}"
        if (name, host) != llm_endpoints.split(want):
            line += red(f"   -> actually {name}@{host}")
        out.append(line)
    return "\n".join(out)


def _cloud_text():
    """The cloud providers /model lists under the roles: one line each, with key state, so a custom
    OpenAI-compatible endpoint registered with /cloud add is visible in the same place as the local ones."""
    (
        dim,
    ) = bind(
        "dim",
    )
    try:
        import gnoc_cloud
        names = list(gnoc_cloud.providers())
    except Exception:  # noqa: BLE001 - no gnoc_cloud module, no cloud lines
        return ""
    lines = []
    for n in names:
        base, env, default, models = gnoc_cloud.providers()[n]
        k = gnoc_cloud.key_for(n)
        state = "keyless" if gnoc_cloud.keyless(n) else ("key set" if k else "no key")
        models_txt = ", ".join(models) if len(models) > 1 else default
        lines.append(dim(f"  cloud  {n}: {models_txt}  ({state}, {base})   /cloud {n} on"))
    return ("\n" + "\n".join(lines)) if lines else ""


def _host_up(host):
    """llm_endpoints.up, but one failed 2 s /api/version probe is not an outage: ask once more before
    calling the host down. Without this a single blip cached "down" for 30 s and the lead flapped to the
    laptop model and back. A host mark_down() benched on purpose (timestamp in the future) is not re-asked."""
    (
        llm_endpoints, time,
    ) = bind(
        "llm_endpoints", "time",
    )
    if llm_endpoints.up(host):
        return True
    h = llm_endpoints._health.get(host)
    if h and h[1] > time.time():
        return False
    # ONE short re-sniff, never a second full ladder. up() already retries a timeout patiently (2 s then 6 s),
    # so popping the cache and re-asking paid that ladder TWICE: against a BLACK-HOLED tunnel (connect accepted,
    # nothing ever answered) that was 16.5 s of blank screen before the banner's first byte, which reads as a
    # hang and leaves Ctrl-C as the only move (GreyNOC, 2026-10-27: "it wasn't starting at all and I had to
    # ctrl C to exit"). A host that is merely blipping answers /api/version in milliseconds, so the anti-flap
    # intent survives at 0.6 s instead of 8 s.
    if not llm_endpoints.sniff(host):
        return False
    llm_endpoints._health.pop(host, None)
    return llm_endpoints.up(host)


def resolve(role, quiet=False):
    """(model, host) for a role (see _resolve). A role answering from something other than what the user
    configured is announced LOUDLY once per change, and again when it comes back: a silent drop of the
    lead to the small laptop model was the worst bug this chat had."""
    (
        SPLIT_FLAG, SPLIT_GRACE_S, T, _BROKEN_MODEL, _ROUTE_SEEN, _resolve, _short_model, dim, green, hang,
        is_broken, llm_endpoints, os, red, role_spec, say, split_up, time, yellow,
    ) = bind(
        "SPLIT_FLAG", "SPLIT_GRACE_S", "T", "_BROKEN_MODEL", "_ROUTE_SEEN", "_resolve", "_short_model", "dim",
        "green", "hang", "is_broken", "llm_endpoints", "os", "red", "role_spec", "say", "split_up", "time",
        "yellow",
    )
    if os.environ.get("GNOC_ECONOMY_ROUTING") == "1":  # ECON: a broke role hands its seat on (default OFF)
        try:
            import gnoc_economy
            role = gnoc_economy.route_role(role)
        except Exception:
            pass
    got = _resolve(role)
    if quiet:
        return got
    want = llm_endpoints.split(role_spec(role))
    prev = _ROUTE_SEEN.get(role)
    _ROUTE_SEEN[role] = got
    if got == prev or got == ("split", "split"):
        return got
    if got != want and not llm_endpoints.roles().get(role) and want[1] not in ("local", "split"):
        pass   # the built-in default names a machine this user never set up (a desktop link): no alarm about it
    elif got != want:
        why = ("split mode is still loading" if os.path.exists(SPLIT_FLAG) and not split_up()
               and time.time() - os.path.getmtime(SPLIT_FLAG) < SPLIT_GRACE_S
               else f"{want[0]} is a stock (censored) model, gnoc runs uncensored only"
               if "stock (censored)" in _BROKEN_MODEL.get(f"{want[0]}@{want[1]}", "")
               else f"{want[0]} cannot start on {want[1]}" if is_broken(*want)
               else f"no {want[1]} machine is set up" if want[1] in llm_endpoints.HOSTS
               and not llm_endpoints.HOSTS[want[1]]
               else f"{want[1]} is unreachable")
        say(hang(red("  ⎿  ") + T.byellow(f"{role} is NOT on {_short_model(want[0])}@{want[1]}: {why}")
                 + yellow(f"; answering from {_short_model(got[0])}@{got[1]}")
                 + dim("  (gnoc gpus to check, /model to switch)"), indent=5))
    elif prev is not None and prev != ("split", "split"):
        say(hang(dim("  ⎿  ") + green(f"{role} is back on {_short_model(want[0])}@{want[1]}"), indent=5))
    return got


def _resolve(role):
    """(model, host) for a role. Order: the both-GPU split model when it is up (it serves lead AND worker
    from two slots), else the role's own model, and a dead desktop falls back to the laptop worker model.
    While split mode is ON but still loading, the desktop GPU belongs to the RPC server: nothing here may
    load a model into the desktop's Ollama (that crashed the RPC server mid-load on 2026-10-21), so every
    role answers from the laptop until the split is ready."""
    (
        DEFAULT_WORKER, SPLIT_FLAG, SPLIT_GRACE_S, _host_up, _split_warned, dim, is_broken, llm_endpoints,
        mark_broken, os, role_spec, say, split_up, time, yellow,
    ) = bind(
        "DEFAULT_WORKER", "SPLIT_FLAG", "SPLIT_GRACE_S", "_host_up", "_split_warned", "dim", "is_broken",
        "llm_endpoints", "mark_broken", "os", "role_spec", "say", "split_up", "time", "yellow",
    )
    cname, chost = llm_endpoints.split(role_spec(role))
    if llm_endpoints.is_cloud(chost):
        # An EXPLICIT cloud role outranks split mode and skips every local check: _host_up() would look
        # "deepseek" up in HOSTS (it is deliberately not there), fail, and silently demote the role to the
        # small local worker - which is how /deepseek on produced `HTTP 400 invalid model name` instead.
        try:
            import gnoc_cloud
            if gnoc_cloud.key_for(chost) or gnoc_cloud.keyless(chost):
                return cname, chost
        except Exception:  # noqa: BLE001
            pass
        return DEFAULT_WORKER, "local"      # no key: local, never a dead role
    if os.environ.get("GNOC_NO_SPLIT") != "1":
        if split_up():
            return "split", "split"
        if os.path.exists(SPLIT_FLAG):
            # While a split is LOADING the desktop GPU belongs to the RPC server, so every role answers from
            # the laptop. That grace is bounded: with no expiry, a split that never came up pinned every role
            # to the small worker model FOREVER, silently, while a healthy desktop lead sat unused.
            if time.time() - os.path.getmtime(SPLIT_FLAG) < SPLIT_GRACE_S:
                wname, whost = llm_endpoints.split(role_spec("worker"))
                return (wname if whost == "local" else DEFAULT_WORKER), "local"
            if not _split_warned[0]:
                _split_warned[0] = True
                say(yellow(f"  split mode has not come up in {SPLIT_GRACE_S // 60} min; ignoring it so your "
                           "configured models work") + dim("  (gnoc split down to clear, gnoc split up to retry)"))
    name, host = llm_endpoints.split(role_spec(role))
    down = host != "local" and not _host_up(host)   # FIRST: stock() on a dead host cost 4 s on every resolve
    if not down and not llm_endpoints.allow_stock() and llm_endpoints.stock(name, host):
        mark_broken(name, host, "a stock (censored) model; gnoc runs uncensored models only (GNOC_ALLOW_STOCK=1)")
    if down or is_broken(name, host):
        # the same model on this machine first, as a mid-turn failover does (_fallback_target): the session
        # switched to the small worker on the NEXT turn of the same outage
        if down and _local_has(name) and not is_broken(name, "local"):
            return name, "local"
        wname, whost = llm_endpoints.split(role_spec("worker"))
        if is_broken(wname, whost):
            return DEFAULT_WORKER, "local"
        if whost == "local" or not _host_up(whost):
            return (wname if whost == "local" else DEFAULT_WORKER), "local"
        return wname, whost
    return name, host


# A runner that cannot START is not a transient: retrying it costs ~20-30s of dead wait EVERY turn and then
# silently demotes the whole session to the small worker model. Remember it for the process, per MODEL, and
# leave the HOST alone - a GPU that cannot run one architecture still serves its other models fine.
# The HOST rejected what the MODEL emitted (Ollama cannot turn its tool call into the API shape). Retrying
# the identical request reproduces it; the model has to be told to try again differently.
_TOOLCALL_PARSE_FAIL = re.compile(r"error parsing|parse error|invalid tool call|tool_call|unmarshal|"
                                  r"invalid character|cannot unmarshal|json: ", re.I)


_PERMANENT_FAIL = re.compile(r"llama-server process has terminated|CUDA error|shared object initialization|"
                             r"failed to load model|unsupported model|unknown model architecture|no such model|"
                             r"out of memory|insufficient memory|requires more system memory|"
                             r"exit status 0xc", re.I)


SPLIT_GRACE_S = 1200  # a split still not serving after 20 min is not loading any more, it is broken


_split_warned = [False]


BROKEN_TTL = 600   # D54: a "cannot start" mark expires; a runner that crashed once is retried after ten minutes


def mark_broken(model, host, why):
    (
        BROKEN_LOG, _BROKEN_AT, _BROKEN_MODEL, _now, _release_dead_runner, json, os, time,
    ) = bind(
        "BROKEN_LOG", "_BROKEN_AT", "_BROKEN_MODEL", "_now", "_release_dead_runner", "json", "os", "time",
    )
    _BROKEN_MODEL[f"{model}@{host}"] = str(why)[:300]
    _BROKEN_AT[f"{model}@{host}"] = time.time()
    try:   # D66 (drive cycle 22): the chat prints 70 chars of the reason, which was the model's own name; the
        #   diagnosis needed the proxy log and a guess. Persist what the server actually said.
        os.makedirs(os.path.dirname(BROKEN_LOG), exist_ok=True)
        with open(BROKEN_LOG, "a") as f:
            f.write(json.dumps({"ts": _now().isoformat(), "model": model, "host": host, "why": str(why)[:600],
                                "pid": os.getpid()}) + "\n")
    except Exception:  # noqa: BLE001
        pass
    _release_dead_runner(model, host, why)


def _desktop_ollama():
    """The second machine's Ollama URL for runner clean-up: the operator's direct tunnel port, or for anyone else the
    GNOC_DESKTOP_OLLAMA address the roles use (it was the operator's port only, so nobody else got the clean-up)."""
    import gnoc_image
    import llm_endpoints as _le
    if getattr(gnoc_image, "DESKTOP_OLLAMA", ""):
        return gnoc_image.DESKTOP_OLLAMA
    return ("http://" + _le.HOSTS["desktop"]) if _le.HOSTS.get("desktop") else ""


def _release_dead_runner(model, host, why):
    """A desktop model whose runner CRASHED still holds its VRAM until it is unloaded BY NAME.

    Ollama keeps the registry entry for a llama-server that died, and `/api/ps` goes on reporting the
    model as loaded with its full size. Nothing reclaims that: the card stays short for every later
    session, not just this one, so the next launch hits the same load failure and poisons it again.
    Measured 2026-10-25 after an SDXL render took the card: the dead 14 GB entry held VRAM at 8.3 of
    15.9 GB free, every `gnoc chat` turn sat silent for minutes, and one unload-by-name took it back to
    14.7 GB and the model loaded in 16 s. _BROKEN_MODEL only remembers it for THIS process; this frees
    the machine. Best effort and bounded: never raises, never blocks a turn for long.
    """
    (
        contextlib, re,
    ) = bind(
        "contextlib", "re",
    )
    if host != "desktop" or not re.search(r"terminated|CUDA|cannot load|failed to load|out of memory|"
                                          r"insufficient memory|exit status", str(why), re.I):
        return
    with contextlib.suppress(Exception):
        import gnoc_image
        gnoc_image._req("POST", _desktop_ollama() + "/api/generate",
                        {"model": model, "keep_alive": 0}, timeout=20)


def _other_chats_open():
    """True when another gnoc chat process runs on this computer (Linux /proc; elsewhere: assume none)."""
    me, n = os.getpid(), 0
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return False
    for p in pids:
        if int(p) == me:
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as fh:
                argv = [a.decode("utf-8", "replace") for a in fh.read().split(b"\0") if a]
        except OSError:
            continue
        if any(os.path.basename(a) in ("gnoc", "gnoc-launcher.py") for a in argv[:3]) and "chat" in argv[1:4]:
            n += 1
    return n > 0


def release_local_models():
    """When the last interactive chat closes, unload its models from THIS computer's model server, so the memory
    is free while gnoc is not in use (the user 2026-11-23: "the gnoc engine seems to use up the ram even when the
    bot isnt running"). Not when another gnoc chat is open, nor when GNOC_KEEP_ALIVE was set by hand. Quiet."""
    if os.environ.get("GNOC_KEEP_ALIVE") or _other_chats_open():
        return 0
    import json
    import urllib.request
    ep = __import__("llm_endpoints")
    done = 0
    for role in ("lead", "worker"):
        try:
            name, host = ep.split(__import__("gnoc_agent").role_spec(role))
            if host != "local" or not ep.HOSTS.get("local"):
                continue
            req = urllib.request.Request(f"http://{ep.HOSTS['local']}/api/generate",
                                         json.dumps({"model": name, "keep_alive": 0}).encode(),
                                         {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5):
                done += 1
        except Exception:  # noqa: BLE001 - not loaded, server gone: nothing to free
            continue
    return done


def is_broken(model, host):
    """True while the mark is fresh. Drive cycle 20 (2026-10-26 06:5xZ): the desktop 35B was marked "cannot start"
    once (a runner crash under three concurrent bots) and, with no expiry, the lead sat on the 9B and the fan-out
    on one GPU for the rest of the cycle while /api/ps showed the model loaded again within a minute."""
    (
        BROKEN_TTL, _BROKEN_AT, _BROKEN_MODEL, time,
    ) = bind(
        "BROKEN_TTL", "_BROKEN_AT", "_BROKEN_MODEL", "time",
    )
    key = f"{model}@{host}"
    if key not in _BROKEN_MODEL:
        return False
    if time.time() - _BROKEN_AT.get(key, 0) > BROKEN_TTL:
        _BROKEN_MODEL.pop(key, None); _BROKEN_AT.pop(key, None)
        return False
    return True


def mark_down(host, secs=120):
    """Treat a host as down for a while after a hard failure (resolve() then falls back for every role)."""
    (
        _split_health, llm_endpoints, time,
    ) = bind(
        "_split_health", "llm_endpoints", "time",
    )
    if host == "split":
        _split_health[:] = [False, time.time() + secs - 20]
    elif host in llm_endpoints.HOSTS:
        llm_endpoints._health[host] = (False, time.time() + secs - 30)


def set_role(role, spec):
    (
        ORCH, json, llm_endpoints, os,
    ) = bind(
        "ORCH", "json", "llm_endpoints", "os",
    )
    name, host = llm_endpoints.split(spec)
    if not llm_endpoints.allow_stock() and llm_endpoints.stock(name, host):
        return (f"{name} is a stock (censored) model: {role} unchanged. gnoc runs uncensored models only "
                "(pick an abliterated/uncensored build, or set GNOC_ALLOW_STOCK=1)")
    r = llm_endpoints.roles()
    r[role] = spec
    os.makedirs(os.path.dirname(llm_endpoints.ROLES) or ORCH, exist_ok=True)
    # orch-bot and every chat re-read this file on each call: a plain "w" open let them read it half-written
    tmp = f"{llm_endpoints.ROLES}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, llm_endpoints.ROLES)


def _role_set(role, spec):
    """The checks /model, /lead and /worker share before a role is written: a cloud provider needs its key
    (or be registered keyless), a remote Ollama must answer, and a named local model must exist. Says the
    outcome and returns True when the role file was actually changed."""
    (
        SPLIT_FLAG, dim, green, llm_endpoints, model_rows, os, red, say, set_role, yellow,
    ) = bind(
        "SPLIT_FLAG", "dim", "green", "llm_endpoints", "model_rows", "os", "red", "say", "set_role", "yellow",
    )
    name, host = llm_endpoints.split(spec)
    if llm_endpoints.is_cloud(host):
        import gnoc_cloud
        if not gnoc_cloud.key_for(host) and not gnoc_cloud.keyless(host):
            say(red(f"  no {host} API key") + dim(f"   set one with  /{host} api <key>"))
            return False
        err = set_role(role, spec)
        say(red("  " + err) if err else green(f"  {role} -> {spec}") + dim(
            "   (CLOUD: the conversation leaves this machine; secrets are scrubbed first)"))
        return not err
    if host in llm_endpoints.HOSTS and not llm_endpoints.HOSTS[host]:
        var = {"desktop": "GNOC_DESKTOP_OLLAMA", "phone": "GNOC_PHONE_OLLAMA"}.get(host, "")
        say(red(f"  no {host} machine is set up: {role} unchanged")
            + dim(f"  (to use another computer's Ollama, start gnoc with {var}=<its address>:11434)"))
        return False
    if host != "local" and not llm_endpoints.up(host):
        say(red(f"  the {host} Ollama is not reachable") + dim(
            "  (is it on, and is Ollama there listening on the network? gnoc gpus shows every host)"))
    have = {n for h, n, _ in model_rows() if h == host}
    if have and name not in have and name + ":latest" not in have:
        # a typo used to become the role and break every later turn; only an unreachable host is trusted
        say(red(f"  {name} is not installed on {__import__('llm_endpoints').host_label(host)}'s Ollama: "
                f"{role} unchanged") + dim("  (/model lists them; gnoc models pull <owner/repo>)"))
        return False
    err = set_role(role, spec)
    if err:
        say(red("  " + err))
        return False
    say(green(f"  {role} -> {spec}"))
    if os.path.exists(SPLIT_FLAG):
        say(yellow("  note: split mode is enabled, and it overrides both roles while it is up")
            + dim("  (gnoc split status; gnoc split down to clear)"))
    return True


# a public install keeps an idle model 10 minutes, not 30: on one computer that memory is the user's whole machine
KEEP_ALIVE = os.environ.get("GNOC_KEEP_ALIVE") or "10m"   # D84: Ollama's 5-minute default unloaded the 35B between


def _think_opt(model):
    (
        effort,
    ) = bind(
        "effort",
    )
    m = model.lower()
    if "gpt-oss" in m:
        t = effort()["think"]
        if "abliterated" in m:  # it reasons 2-4x longer than stock at the same level (23-35 s an answer at medium)
            t = {"high": "medium", "medium": "low"}.get(t, t)
        return t
    if "qwen3" in m:
        return effort()["qwen_think"]
    return None


_CPU_ONLY = {}   # model -> (checked_at, True/False/None)


def runs_on_cpu(model):
    """True when the lead's Ollama reports this model loaded with nothing in GPU memory (size_vram 0): every
    token, reasoning included, is CPU time there. None when it cannot tell (not loaded yet, no size_vram field)."""
    import json
    import time
    import urllib.request
    hit = _CPU_ONLY.get(model)
    if hit and time.time() - hit[0] < 120:
        return hit[1]
    ep = __import__("llm_endpoints")
    host = ep.split(__import__("gnoc_agent").role_spec("lead"))[1]
    addr = ep.HOSTS.get(host) if host in ("local", "desktop") else None
    verdict = None
    if addr:
        try:
            with urllib.request.urlopen(f"http://{addr}/api/ps", timeout=2) as r:
                for row in json.loads(r.read().decode()).get("models") or []:
                    if row.get("name") == model or row.get("model") == model:
                        if "size_vram" in row and int(row.get("size") or 0) > 0:
                            verdict = int(row.get("size_vram") or 0) == 0
        except Exception:  # noqa: BLE001 - unknown is not CPU
            verdict = None
    _CPU_ONLY[model] = (time.time(), verdict)
    return verdict


def lead_gpu_note(model):
    """One line for them when the lead model answers (partly) from the CPU because the GPU was full, else ''. An
    Ollama beside gnoc's engine held 6 GB, the engine's 9B loaded 0/33 layers on the GPU, and every answer came at
    7 tok/s instead of 39 with nothing said (engine QAQC 2026-11-23)."""
    import json
    import urllib.request
    ep = __import__("llm_endpoints")
    host = ep.split(__import__("gnoc_agent").role_spec("lead"))[1]
    addr = ep.HOSTS.get(host) if host in ("local", "desktop") else None
    if not addr:
        return ""
    try:
        with urllib.request.urlopen(f"http://{addr}/api/ps", timeout=2) as r:
            rows = json.loads(r.read().decode()).get("models") or []
    except Exception:  # noqa: BLE001 - unknown is not a warning
        return ""
    for row in rows:
        if row.get("name") == model or row.get("model") == model:
            if row.get("gpu_note"):
                return f"{model.split('/')[-1]} is {row['gpu_note']}"
            size, vram = int(row.get("size") or 0), int(row.get("size_vram") or 0)
            if size and "size_vram" in row and vram < size * 0.9:
                return (f"{model.split('/')[-1]} is {'wholly' if not vram else 'partly'} on the CPU (slow): another "
                        "program may be holding the GPU's memory")
    return ""


def _lead_think(model):
    """What the LEAD asks the model for, given the reasoning display is on or off."""
    (
        THINK_UI, _think_opt, effort,
    ) = bind(
        "THINK_UI", "_think_opt", "effort",
    )
    if not THINK_UI[0]:
        return False
    m = model.lower()
    if "qwen3" in m and os.environ.get("GNOC_THINK_ON_CPU") != "1" and runs_on_cpu(model) is True:
        # a computer with no GPU for the model: qwen3's reasoning pass made "hello" wait past 30 s (GreyNOC
        # 2026-11-22, a public install under WSL). It answers directly; GNOC_THINK_ON_CPU=1 keeps reasoning on.
        return False
    if "gpt-oss" in m:
        return effort()["think"]      # a depth word, exactly as before
    if "qwen3" in m:
        return True                   # the stream itself, whatever the dial says
    return _think_opt(model)          # any other family: unchanged


REASONS_IN_CONTENT_FILE = "reasons-in-content.json"   # under AGENT_DIR: models seen reasoning in their content


def _reasons_path():
    (
        AGENT_DIR,
    ) = bind(
        "AGENT_DIR",
    )
    return os.path.join(AGENT_DIR, REASONS_IN_CONTENT_FILE)


def _reasons_seen():
    import json
    try:
        with open(_reasons_path()) as f:
            got = json.load(f)
        return set(got if isinstance(got, list) else [])
    except (OSError, ValueError):
        return set()


def reasons_in_content(model):
    """True when this model was seen writing an untagged reasoning preamble into its CONTENT on a call sent with
    thinking off (llmwire.split_untagged_reasoning). Remembered on disk, per model, across restarts."""
    return bool(model) and str(model) in _reasons_seen()


def note_reasons_in_content(model):
    """Remember that this model reasons in its content when told not to think. Returns True the first time."""
    (
        _atomic_json,
    ) = bind(
        "_atomic_json",
    )
    if not model:
        return False
    seen = _reasons_seen()
    if str(model) in seen:
        return False
    seen.add(str(model))
    with contextlib.suppress(OSError):
        os.makedirs(os.path.dirname(_reasons_path()), exist_ok=True)
        _atomic_json(_reasons_path(), sorted(seen))
    return True


def _chat_think(model, small_talk=False):
    """The think value a chat step sends. Small talk gets no reasoning pass (qwen3 thinking made "hello" wait past
    30 s, the user 2026-11-22). A model that reasons ANYWAY, in its content, with no tag (the Opus-distilled
    Huihui Qwen3.5 lead: "The user has sent a simple greeting. I need to respond..." above "Hello!", 2026-11-25)
    gets thinking ON, small talk included: its reasoning then arrives on the thinking channel, which /thoughts off
    hides, instead of in the answer. Only models seen doing it are flipped; every other model is unchanged."""
    (
        _lead_think,
    ) = bind(
        "_lead_think",
    )
    if reasons_in_content(model):
        t = _lead_think(model)
        return t if t not in (False, None) else True
    return False if small_talk else _lead_think(model)


MALFORMED_ARGS = "_malformed_json"  # a tool call whose arguments did not parse carries its raw text under this key


# what a model call can raise when the server or the socket misbehaves (IncompleteRead is not an OSError)
_STREAM_ERRORS = (RuntimeError, OSError, ValueError, http.client.HTTPException)


def _openai_chat(messages, tools, on_text, num_predict, on_think=None, timeout=None,
                 url=None, model="split", headers=None, think=None, mon_as=("split", "split")):
    # url/model/headers let the same streaming client serve a CLOUD provider (gnoc_cloud) as well as the
    # local split llama-server. Defaults are unchanged, so every existing caller behaves identically.
    # mon_as is the (model, host) pair this call is BOOKED AGAINST in the usage tally. It used to be the
    # literal "split", "split" for every caller, so a cloud lead's tokens showed up in the turn footer and
    # in /usage as `split@split` - a model that was not running. The economy ledger beside it already
    # recorded the real name, so the two disagreed (GreyNOC, 2026-11-01, first deepseek-reasoner lead).
    (
        INTERRUPT, LLM_READ_TIMEOUT, MALFORMED_ARGS, MON, SPLIT_URL, _cancelled, _to_openai, effort, json, time,
        urllib,
    ) = bind(
        "INTERRUPT", "LLM_READ_TIMEOUT", "MALFORMED_ARGS", "MON", "SPLIT_URL", "_cancelled", "_to_openai",
        "effort", "json", "time", "urllib",
    )
    body = {"model": model, "messages": _to_openai(messages), "stream": True, "temperature": 0.3,
            "stream_options": {"include_usage": True}}
    if model == "split":
        # the SECOND gate on the same thing: the split llama-server takes the Qwen template kwarg, and it
        # read the effort dial too, so a lead on `gnoc split` stayed silent at medium however _lead_think
        # answered. None (every worker) keeps the dial; an explicit think from the lead wins.
        body["chat_template_kwargs"] = {"enable_thinking": effort()["qwen_think"] if think is None
                                        else bool(think)}
    if tools:
        body["tools"] = tools
    if num_predict:
        body["max_tokens"] = num_predict
    if url:   # a cloud host's documented departures (gnoc_core.providers.OPENAI_HOST_QUIRKS)
        from gnoc_core import providers as _wires
        body = _wires.openai_fixups(url, body)
    req = urllib.request.Request(url or (SPLIT_URL + "/v1/chat/completions"), json.dumps(body).encode(),
                                 headers or {"Content-Type": "application/json"})
    content, calls, thinking = [], {}, False
    t0, usage = time.time(), {}
    try:
        resp = urllib.request.urlopen(req, timeout=float(timeout or LLM_READ_TIMEOUT))
    except urllib.error.HTTPError as e:
        # read and close the error body: the server's REASON ("context length exceeded", "invalid tool schema")
        # was dropped and the socket left open until GC, on every retry (QAQC 2026-11-19). Same exception type and
        # "HTTP Error <code>" text, so the callers' retry/permanent-failure tests read it as before.
        with e:
            detail = e.read(800).decode("utf-8", "replace").strip()
        raise urllib.error.HTTPError(e.url, e.code, f"{e.reason}: {detail}" if detail else e.reason, e.headers,
                                     None) from None
    with resp:
        for raw in resp:
            if INTERRUPT.is_set() or _cancelled():  # Ctrl-C, or this worker alone was cancelled (B-01/B-02)
                break
            line = raw.decode(errors="replace").strip()
            if line.startswith("error:"):   # llama.cpp's server reports a failure on its own line
                raise RuntimeError(f"split: the model server reported an error: {line[6:].strip()[:300]}")
            if not line.startswith("data:") or line == "data: [DONE]":
                continue
            try:
                ch = json.loads(line[5:])
            except ValueError:
                raise RuntimeError(f"split: the model server sent a malformed stream chunk: {line[:80]!r}")
            if isinstance(ch, dict) and ch.get("error"):
                # OpenAI / OpenRouter report a mid-stream failure as a data event; returning the partial text as a
                # success skipped every retry and failover (QAQC r2)
                err = ch["error"]
                msg = err.get("message") if isinstance(err, dict) else err
                raise RuntimeError(f"the model server reported an error mid-stream: {str(msg)[:300]}")
            usage = ch.get("usage") or usage
            if ch.get("choices"):
                MON.tick()
            for choice in ch.get("choices") or []:
                d = choice.get("delta") or {}
                # DeepSeek calls it reasoning_content; OpenRouter and several OpenAI-compatible gateways
                # call the same field reasoning. Reading only the first shape left a cloud lead's thinking
                # invisible on half the providers we can point at.
                reasoning = d.get("reasoning_content") or d.get("reasoning")
                if reasoning and isinstance(reasoning, str):
                    if not thinking and on_text:
                        thinking = True
                        on_text(None)
                    if on_think:
                        on_think(reasoning)
                if d.get("content"):
                    content.append(d["content"])
                    if on_text:
                        on_text(d["content"])
                for tc in d.get("tool_calls") or []:
                    slot = calls.setdefault(tc.get("index", 0), {"id": None, "name": "", "args": ""})
                    slot["id"] = tc.get("id") or slot["id"]
                    fn = tc.get("function") or {}
                    slot["name"] += fn.get("name") or ""
                    slot["args"] += fn.get("arguments") or ""
    # The usage block is RETURNED as well as tallied. It used to reach MON.record only, so the caller's
    # out.get("usage") was always empty and the economy billed every cloud and split call at characters/4
    # (Phase-0 audit, 2026-11-26). Normalized, so the cached part of the prompt is kept too.
    real = _providers.normalize_usage("openai", usage)
    MON.record(mon_as[0], mon_as[1], usage.get("prompt_tokens"), usage.get("completion_tokens"),
               time.time() - t0, cached=real.get("cached_tokens", 0))
    out = {"role": "assistant", "content": "".join(content)}
    if calls:
        out["tool_calls"] = []
        for k in sorted(calls):
            try:
                args = json.loads(calls[k]["args"] or "{}")
            except ValueError:
                # keep a dict (Ollama rejects string arguments on replay) but do not hide the defect:
                # run_tools sees the marker and tells the model its JSON was malformed
                args = {MALFORMED_ARGS: calls[k]["args"][:300]}
            out["tool_calls"].append({"id": calls[k]["id"], "function": {"name": calls[k]["name"],
                                                                         "arguments": args}})
    out["usage"] = real
    return out


def _save_failed_shape(model, host, code, detail, body):
    """What the model server refused, as a shape (roles, content types, heads; never whole bodies): a server-side
    template error says nothing about which message tripped it, and the request is gone once the turn moves on."""
    (
        AGENT_DIR, _atomic_json, _now, contextlib, os,
    ) = bind(
        "AGENT_DIR", "_atomic_json", "_now", "contextlib", "os",
    )
    with contextlib.suppress(Exception):
        shape = [{"role": m.get("role"), "type": type(m.get("content")).__name__,
                  "head": str(m.get("content") or "")[:80], "tool_calls": len(m.get("tool_calls") or [])}
                 for m in body.get("messages") or []]
        _atomic_json(os.path.join(AGENT_DIR, "last-model-error.json"),
                     {"ts": _now().isoformat(), "model": model, "host": host, "status": code, "detail": detail[:600],
                      "tools": len(body.get("tools") or []), "messages": shape})


def ctx_pct_of(history, host, model=None):
    """How full the window is after this history, as a whole percent. The same
    characters/4 estimate compaction budgets with, so the number a human sees is
    the number the harness acts on - never two different truths."""
    (
        _approx_tokens, ctx_for,
    ) = bind(
        "_approx_tokens", "ctx_for",
    )
    try:
        return min(999, round(100.0 * _approx_tokens(history or []) / max(1, ctx_for(host, model))))
    except Exception:  # noqa: BLE001 - a percentage is advisory, never a crash
        return 0


def prompt_ctx_pct(agent):
    """ctx% for the prompt bar, cached ~2 s: the bar repaints on every keystroke
    and must never pay a probe or a history walk for that."""
    (
        _CTX_PCT, ctx_pct_of, resolve, root, time,
    ) = bind(
        "_CTX_PCT", "ctx_pct_of", "resolve", "root", "time",
    )
    key = (agent.s.get("sid"), root())
    now = time.time()
    if _CTX_PCT[2] == key and now - _CTX_PCT[1] < 2.0:
        return _CTX_PCT[0]
    try:
        _, host = resolve("lead", quiet=True)
        pct = ctx_pct_of(agent.s.get("history"), host)
    except Exception:  # noqa: BLE001 - keep the last honest number
        pct = _CTX_PCT[0] if _CTX_PCT[2] == key else 0
    _CTX_PCT[:] = [pct, time.time(), key]
    return pct


def _lead_host():
    (
        resolve,
    ) = bind(
        "resolve",
    )
    try:
        return resolve("lead", quiet=True)[1]
    except Exception:  # noqa: BLE001
        return "local"


def _econ_llm(model, tokens):  # ECON: one LLM turn debits the acting bot; never raises into the chat
    try:
        import gnoc_economy
        gnoc_economy.debit_llm(gnoc_economy.current_bot("lead"), model, int(tokens or 0))
    except Exception:  # noqa: BLE001 - a busy or broken economy never costs a model turn
        pass


def _note_retry(model, host, err):
    """One line per retried model call. Silent retries hide a GPU that is going: this is where a run of them
    shows up (`tail ~/.../agent/model-retries.log`), and it must never be what fails a call."""
    (
        AGENT_DIR, _now, contextlib, os,
    ) = bind(
        "AGENT_DIR", "_now", "contextlib", "os",
    )
    with contextlib.suppress(Exception):
        os.makedirs(AGENT_DIR, exist_ok=True)
        with open(os.path.join(AGENT_DIR, "model-retries.log"), "a", encoding="utf-8", errors="replace") as f:
            f.write(f"{_now().isoformat()} {model}@{host} {type(err).__name__}: {str(err)[:200]}\n")


_REFUSED = ("Connection refused", "Errno 111", "ECONNREFUSED")


def _wait_for_endpoint(host, seconds=8.0, step=1.0):
    """True once a TCP connect to the host's endpoint succeeds, polling for up to `seconds`. Drive D42 (2026-10-26
    04:03Z): `pm2 restart all` bounced desktop-proxy (127.0.0.1:11440) for about two seconds; the lead's call was
    refused, the immediate retry was refused again, and the chat failed over to the 9B for the rest of the cycle."""
    (
        llm_endpoints, time,
    ) = bind(
        "llm_endpoints", "time",
    )
    import socket
    try:
        addr = llm_endpoints.HOSTS.get(host) or ""
        h, _, port = addr.rpartition(":")
        port = int(port)
    except Exception:  # noqa: BLE001 - an unknown host shape: nothing to wait for
        return False
    deadline = time.time() + float(seconds)
    while True:
        try:
            with socket.create_connection((h or "127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            if time.time() >= deadline:
                return False
            time.sleep(step)


def llm_chat(model, host, messages, tools=None, on_text=None, num_predict=None, think=None, on_think=None,
             retry=True, timeout=None, fmt=None):
    """One chat call, with ONE retry when it fails before producing anything (see _llm_chat_once for the call).

    Every model call in this file goes through here, and a dropped socket is routine: Ollama closes the
    connection while it swaps a model in or out, a tunnel re-dials, a server returns one 502. The chat loop
    has always retried (and failed over); the other ~13 callers - summaries, sub-agents, /gpu1, the worker
    loop, planners - did not, so one blip cost a whole delegated task ("worker failed: Connection reset").
    The retry is here so every caller gets it, under two rules that keep it safe:
      - nothing may have reached the user yet: a call that already streamed text is never repeated, or the
        answer would appear twice;
      - the failure must not be permanent (a model that cannot load, OOM): retrying that only doubles the wait.
    The chat loop passes retry=False - it has richer handling of its own (tool-call parse failures, benching
    the host, falling back to another model) and must not retry twice over.
    """
    (
        INTERRUPT, _PERMANENT_FAIL, _STREAM_ERRORS, _cancelled, _llm_chat_once, _note_retry, llm_endpoints,
    ) = bind(
        "INTERRUPT", "_PERMANENT_FAIL", "_STREAM_ERRORS", "_cancelled", "_llm_chat_once", "_note_retry",
        "llm_endpoints",
    )
    # PLUGINS (phase 8): pre_llm runs HERE, before _llm_chat_once applies the privacy switch and the secret
    # redaction, so a rewritten message is refused or scrubbed exactly like the original. A block raises
    # gnoc_plugins.PluginBlocked, which is not a stream error: the chat must not fail over and resend it elsewhere.
    import gnoc_plugins
    messages = gnoc_plugins.pre_llm(model, host, messages)
    emitted = [False]
    sink = on_text
    if on_text is not None:
        def _sink(delta):
            if delta:
                emitted[0] = True
            return on_text(delta)
        sink = _sink
    for attempt in (0, 1):
        try:
            # fmt: a JSON schema the answer must fit (Ollama `format`); only passed on when a caller set it
            out = _llm_chat_once(model, host, messages, tools, sink, num_predict, think, on_think, timeout,
                                 **({"fmt": fmt} if fmt else {}))
            # post_llm may rewrite the TEXT (what is kept and what later steps read; streamed words stay on
            # screen). The model's tool calls are untouched and still go through every dispatch gate.
            return gnoc_plugins.post_llm(model, host, out)
        except _STREAM_ERRORS as e:
            if (not retry or attempt or emitted[0] or INTERRUPT.is_set() or _cancelled()
                    or _PERMANENT_FAIL.search(str(e)) or llm_endpoints.is_cloud(host)):   # F9: retried inside
                raise
            _note_retry(model, host, e)


# A model call's own socket wall. It is a SILENCE wall, not a total: urllib applies it to each read, and a
# streaming answer delivers a token every few seconds, so a long answer never trips it. What it bounds is
# the quiet before the first byte - the model load plus the prompt eval - and after a render, with the
# desktop card held by someone else's job, that quiet was 19 minutes of a dead socket at 900 s before the
# process was killed from outside (image test 5, 2026-10-25). 360 s covers a cold 35B load (~60 s) plus a
# 20k-token prompt eval with room to spare; the CPU fallback's eval of a 12k prompt fits too. Workers inside
# a turn are shorter still: their step wall is only checked BETWEEN steps (soak 2026-10-25), so callers
# with a deadline pass their remaining seconds.
LLM_READ_TIMEOUT = float(os.environ.get("GNOC_LLM_TIMEOUT") or 360)


# A model call made BY A TOOL, inside a turn, gets a much shorter wall than the lead writing its answer:
# those tools already sit behind a 1200 s tool timeout, so an unbounded call could hold an interactive
# turn for a quarter of an hour. Measured 2026-10-25: second_opinion ran past six minutes on one call.
TOOL_LLM_TIMEOUT = float(os.environ.get("GNOC_TOOL_LLM_TIMEOUT") or 300)


# A proposer in the hypothesis tournament gets a WALL-CLOCK wall on top of that per-read silence wall,
# because _propose may make two calls and because /goal runs the tournament with the operator waiting at
# the prompt. Two proposers run in parallel, so this is roughly the worst case a goal pays before the
# hunt starts; whoever answers in time is what the tournament scores.
HYPO_PROPOSER_WALL = float(os.environ.get("GNOC_HYPO_WALL") or 240)


# F9 2026-11-09: one DeepSeek `RemoteDisconnected` mid-turn ended the goal turn and dropped the REPL to the prompt.
# For a CLOUD lead a dropped socket, a reset, a 502/503/504 or a timeout is transient: the SAME request is retried
# with this backoff (seconds) before the error surfaces, as long as nothing has streamed to the screen yet.
CLOUD_RETRY_BACKOFF = (2, 5, 10)


def _cloud_wait(seconds):
    """Sleep between cloud retries; True when a Ctrl-C arrived meanwhile (then the error surfaces at once)."""
    (
        INTERRUPT,
    ) = bind(
        "INTERRUPT",
    )
    return INTERRUPT.wait(seconds)


def _cloud_call(fn, on_text, model, host):
    """Run fn(sink) and retry it on a transient cloud error per CLOUD_RETRY_BACKOFF (F9). A call that already put
    text on screen is never repeated (the answer would appear twice); the chat loop handles that one."""
    (
        CLOUD_RETRY_BACKOFF, INTERRUPT, _cancelled, _cloud_wait, _note_retry, _transient_cloud_error,
    ) = bind(
        "CLOUD_RETRY_BACKOFF", "INTERRUPT", "_cancelled", "_cloud_wait", "_note_retry", "_transient_cloud_error",
    )
    emitted = [False]
    sink = on_text
    if on_text is not None:
        def tracked(delta):
            if delta:
                emitted[0] = True
            return on_text(delta)
        sink = tracked
    for attempt in range(len(CLOUD_RETRY_BACKOFF) + 1):
        try:
            return fn(sink)
        except Exception as e:  # noqa: BLE001 - classified below; anything not transient is re-raised as it was
            if (attempt >= len(CLOUD_RETRY_BACKOFF) or emitted[0] or not _transient_cloud_error(e)
                    or INTERRUPT.is_set() or _cancelled()):
                raise
            _note_retry(model, host, e)
            # a 429 says how long to wait (Retry-After, or Gemini's retryDelay): retrying sooner only spends the
            # attempt on a second 429. Never shorter than the backoff, never longer than providers.RETRY_AFTER_CAP.
            asked = _providers.retry_after(e)
            wait = CLOUD_RETRY_BACKOFF[attempt] if asked is None else max(CLOUD_RETRY_BACKOFF[attempt], asked)
            if _cloud_wait(wait):
                raise


_LAST_USAGE = threading.local()


def last_usage():
    """The normalized usage (providers.normalize_usage) of the newest model call made on THIS thread; {} when the
    provider sent none. It is taken off the returned message (_take_usage), so it never joins a saved history."""
    return dict(getattr(_LAST_USAGE, "u", None) or {})


def _take_usage(out):
    u = out.pop("usage", None) if isinstance(out, dict) else None
    u = u if isinstance(u, dict) else {}
    _LAST_USAGE.u = u
    return u


def _wire_chat(wire, messages, tools, *, model, host, url=None, headers=None, on_text=None, on_think=None,
               num_predict=None, think=None, timeout=None, style="adaptive"):
    """THE ADAPTER SEAM for a cloud provider: one internal message and tool-call format in (gnoc_core.providers),
    the provider's wire out. "openai" is _openai_chat exactly as it was called before adapters existed (no think,
    the provider's URL, model and headers, booked under model@host); "anthropic" and "gemini" are the native
    adapters. Redaction and the privacy switch have already run in _llm_chat_once: nothing here may skip them."""
    (
        INTERRUPT, LLM_READ_TIMEOUT, MON, _cancelled, _openai_chat, time,
    ) = bind(
        "INTERRUPT", "LLM_READ_TIMEOUT", "MON", "_cancelled", "_openai_chat", "time",
    )
    if wire in ("openai", "", None):
        return _openai_chat(messages, tools, on_text, num_predict, on_think, timeout, url=url, model=model,
                            headers=headers, mon_as=(model, host))
    adapter = _providers.ADAPTERS.get(wire)
    if adapter is None:
        raise RuntimeError(f"{model}@{host}: unknown provider wire {wire!r} (one of {', '.join(_providers.WIRES)})")
    t0 = time.time()
    out = adapter.chat(messages, tools, url=url, model=model, headers=headers, on_text=on_text, on_think=on_think,
                       num_predict=num_predict, think=think, timeout=float(timeout or LLM_READ_TIMEOUT),
                       cancelled=lambda: INTERRUPT.is_set() or _cancelled(),   # Ctrl-C, or this worker alone
                       tick=MON.tick, style=style)
    u = out.get("usage") or {}
    MON.record(model, host, u.get("input_tokens"), u.get("output_tokens"), time.time() - t0,
               cached=u.get("cached_tokens", 0))
    return out


def _llm_chat_once(model, host, messages, tools=None, on_text=None, num_predict=None, think=None, on_think=None,
                   timeout=None, fmt=None):
    """One chat call (streamed): a cloud provider through its wire adapter (_wire_chat), the split llama-server's
    OpenAI API, or Ollama /api/chat (_ollama_chat). Returns the assistant message dict in Ollama shape. on_think(delta)
    receives the model's reasoning stream. The provider's usage block is taken off the message (last_usage() has it)
    and billed to the economy; characters/4 only when the provider sent none."""
    (
        _approx_tokens, _cloud_call, _econ_llm, _ensure_user_turn, _openai_chat, effort, llm_endpoints, re,
    ) = bind(
        "_approx_tokens", "_cloud_call", "_econ_llm", "_ensure_user_turn", "_openai_chat", "effort",
        "llm_endpoints", "re",
    )
    messages = _ensure_user_turn(messages)
    if llm_endpoints.is_cloud(host) or str(model or "").endswith(":cloud") or "-cloud:" in str(model or ""):
        # his /privacy switch: with cloud off or local-only on, nothing goes to a cloud model (2026-11-24). An Ollama
        # ":cloud" model looks local but Ollama forwards the chat to ollama.com.
        import gnoc_privacy
        _off = gnoc_privacy.why_not("cloud")
        if _off:
            raise RuntimeError(f"not sent: {model} is a cloud model and {_off}. Pick a local model with /model.")
        # A CLOUD LEAD. Secrets are scrubbed from every message before it leaves the machine; the rest of
        # the conversation does go, which is why this is opt-in and announced (gnoc_cloud's docstring). Both
        # steps run before the wire is chosen, so every adapter sends only the redacted copy.
        import gnoc_cloud
        url, mdl, hdrs = gnoc_cloud.endpoint(host, model)
        wire = gnoc_cloud.wire_for(host)
        red_msgs = gnoc_cloud.redact_messages(messages)
        # A native wire thinks per the effort dial when the caller left it open (a worker; a lead whose family
        # _lead_think does not know); an explicit False (small talk, /thoughts off) keeps the reasoning pass off.
        nthink = (effort()["think"] if think is None else think) if wire != "openai" else None
        style = gnoc_cloud.thinking_style(host)
        out = _cloud_call(lambda sink: _wire_chat(wire, red_msgs, tools, model=mdl, host=host, url=url,
                                                  headers=hdrs, on_text=sink, on_think=on_think,
                                                  num_predict=num_predict, think=nthink, timeout=timeout,
                                                  style=style),
                          on_text, mdl, host)   # F9: a transient cloud error is retried, not the end of the turn
        u = _take_usage(out)
        _econ_llm(f"{mdl}@{host}", _providers.usage_tokens(u) or _approx_tokens(messages, out.get("content") or ""))
        text = re.sub(r"<think>.*?</think>", "", out.get("content") or "", flags=re.S)
        out["content"] = (text.rsplit("</think>", 1)[1] if "</think>" in text else text).strip()
        return out
    if host == "split":
        out = _openai_chat(messages, tools, on_text, num_predict, on_think, timeout, think=think)
        u = _take_usage(out)   # ECON: usage when present, else len/4
        _econ_llm(model, _providers.usage_tokens(u) or _approx_tokens(messages, out.get("content") or ""))
        text = re.sub(r"<think>.*?</think>", "", out["content"], flags=re.S)
        if "</think>" in text:
            out["_reasoning"] = text.rsplit("</think>", 1)[0]   # for stalled_call; popped before history
        out["content"] = (text.rsplit("</think>", 1)[1] if "</think>" in text else text).strip()
        return out
    out = _ollama_chat(model, host, messages, tools, on_text, num_predict, think, on_think, timeout, fmt)
    _take_usage(out)
    return out


def _ollama_chat(model, host, messages, tools=None, on_text=None, num_predict=None, think=None, on_think=None,
                 timeout=None, fmt=None):
    """The Ollama /api/chat wire (Ollama and gnoc's engine), moved here verbatim from _llm_chat_once so it is one
    adapter among the others. messages have already been through _ensure_user_turn."""
    (
        INTERRUPT, KEEP_ALIVE, LLM_READ_TIMEOUT, MON, _approx_tokens, _cancelled, _ctx_overflow_fix,
        _degenerate, _econ_llm, _save_failed_shape, _think_opt, ctx_for, json,
        llm_endpoints, re, time, urllib,
    ) = bind(
        "INTERRUPT", "KEEP_ALIVE", "LLM_READ_TIMEOUT", "MON", "_approx_tokens", "_cancelled", "_ctx_overflow_fix",
        "_degenerate", "_econ_llm", "_save_failed_shape", "_think_opt", "ctx_for", "json",
        "llm_endpoints", "re", "time", "urllib",
    )
    _ctx_live = bind("_CTX_LIVE")[0]
    body = {"model": model, "messages": messages, "stream": True, "keep_alive": KEEP_ALIVE,
            "options": {"num_ctx": ctx_for(host, model), "temperature": 0.3}}
    if _ctx_live.get("engine:%s|%s" % (host, model)):
        # gnoc's engine told us its window: let it keep the one it fitted to the GPU (a num_ctx from here would only
        # pin a size it chose better, and a stale one after a restart would make it reload the model)
        body["options"].pop("num_ctx")
    if num_predict:
        body["options"]["num_predict"] = num_predict
    if tools:
        body["tools"] = tools
    if fmt and not tools:
        # the answer is constrained to this JSON schema by the server's grammar, so a model that "thinks out
        # loud" with thinking off cannot spend the whole budget on prose (code review, 2026-11-21). Ollama
        # only: the cloud and split paths above return before this and rely on the prompt.
        body["format"] = fmt
    if think is None:
        think = _think_opt(model)
    elif not isinstance(think, bool) and "gpt-oss" not in model.lower():
        # a gpt-oss reasoning-DEPTH word ("low"/"medium"/"high") means nothing to another family: off
        think = False
    # An explicit True/False from the caller is honoured for every family. Without this, _lead_think()
    # could not turn a Qwen's reasoning stream ON, so the ticker and the thinking block had nothing to
    # show at any effort below high and the UX read as a silent bot (GreyNOC 2026-10-31).
    if think is not None:
        body["think"] = think
    url = f"http://{llm_endpoints.HOSTS[host]}/api/chat"
    fixes = set()  # each server-side complaint is repaired once, then the call is retried once
    while True:
        req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        try:
            resp = urllib.request.urlopen(req, timeout=float(timeout or LLM_READ_TIMEOUT))
            break
        except urllib.error.HTTPError as e:
            with e:  # the error response is a live socket: close it, or every failed call leaks one
                detail = e.read().decode(errors="replace")[:300]
            if "think" not in fixes and "think" in body and "think" in detail.lower():
                fixes.add("think")
                body.pop("think")
                continue
            if "ctx" not in fixes and "exceed_context_size" in detail:
                # Ollama 0.40 refuses (HTTP 400) instead of truncating when the prompt is over num_ctx, and
                # it says how many tokens it saw. Ask for that window once, rounded up with reply room; the
                # server reloads the runner with it. Measured 2026-10-25: 20,4xx tokens against 16,384 on the
                # laptop fallback killed every turn of five test runs. A slower answer beats none.
                got = re.search(r"n_prompt_tokens[^0-9]*(\d+)", detail) or re.search(r"request \((\d+) tokens\)", detail)
                if got:
                    fixes.add("ctx")
                    if _ctx_overflow_fix(host, body, int(got.group(1))):   # D74: bump within the ceiling, else trim
                        continue
            _ctx_tries = sum(1 for f in fixes if str(f).startswith("ctx2"))
            if _ctx_tries < 3 and "exceed_context_size" in detail:
                # the bigger window was asked for and the server refused at the SAME size: it cannot grow (gnoc's
                # engine loads a model at one n_ctx). Trim the history to the window it reports, then try once more.
                got = re.search(r"n_prompt_tokens[^0-9]*(\d+)", detail) or re.search(r"request \((\d+) tokens\)", detail)
                n_ctx = re.search(r"n_ctx[^0-9]*(\d+)", detail) or re.search(r"context size \((\d+) tokens\)", detail)
                if got and n_ctx:
                    fixes.add(f"ctx2-{_ctx_tries}")
                    # each pass cuts deeper: a trimmed request came back at 16,385 against 16,384 (SWE batch 2),
                    # the 3.2-characters-a-token estimate is a little short on code and JSON
                    if _ctx_overflow_fix(host, body, int(got.group(1)) + 1536 * _ctx_tries, cap=int(n_ctx.group(1))):
                        continue
            if "user" not in fixes and "no user query found" in detail.lower():
                # The request DID carry a user turn (_ensure_user_turn): Ollama truncated the prompt to num_ctx
                # oldest-first on its side and dropped it, and the Qwen3.5 Jinja then found only assistant/tool
                # messages (a 27-message, 17-tool worker loop, 2026-10-22). A neutral user turn at the END survives
                # any front truncation; the saved history is untouched (body holds a copy).
                fixes.add("user")
                body["messages"] = list(body["messages"]) + [{"role": "user", "content": "Continue the current task."}]
                continue
            _save_failed_shape(model, host, e.code, detail, body)
            raise RuntimeError(f"{model}@{host}: HTTP {e.code} {detail}")
    content, calls, thinking, thought = [], [], False, []
    degenerate = False
    think_tail, think_n, think_loop = "", 0, False
    _think_loop = __import__("gnoc_core.llmwire", fromlist=["_think_loop"])._think_loop
    t0, tin, tout = time.time(), 0, 0
    with resp:
        for line in resp:
            if INTERRUPT.is_set() or _cancelled():  # Ctrl-C, or this worker alone was cancelled (B-01/B-02)
                break
            if not line.strip():
                continue
            try:
                chunk = json.loads(line)
            except ValueError:
                raise RuntimeError(f"{model}@{host}: malformed stream chunk from Ollama: {line[:80]!r}")
            if chunk.get("error"):
                raise RuntimeError(f"{model}@{host}: {chunk['error']}")
            if chunk.get("done"):
                tin, tout = chunk.get("prompt_eval_count") or 0, chunk.get("eval_count") or 0
                try:
                    if int(chunk.get("context_length") or 0) >= 2048:   # gnoc's engine: the window it loaded with
                        _ctx_live["engine:%s|%s" % (host, model)] = int(chunk["context_length"])   # per model
                except (TypeError, ValueError):
                    pass
            else:
                MON.tick()
            msg = chunk.get("message") or {}
            if msg.get("thinking"):
                if not thinking and on_text:
                    thinking = True
                    on_text(None)
                # kept, not just forwarded: a lead that reasons "let me call site_status" and then emits
                # NOTHING is a stalled call, and stalled_call() can only recover it from these words. It used
                # to be recoverable only when the reasoning LEAKED into content (the </think> path below);
                # with think on, it comes down this channel instead and the whole turn came back empty.
                if len(thought) < 400:
                    thought.append(msg["thinking"])
                if on_think:
                    on_think(msg["thinking"])
                think_tail = (think_tail + msg["thinking"])[-2000:]
                think_n += 1
                if think_n % 24 == 0 and not content and not calls and _think_loop(think_tail):
                    # Its reasoning is one sentence on repeat and will run to the token limit with no answer
                    # behind it: stop reading. The caller sees an empty answer and asks again with thinking off.
                    think_loop = True
                    break
            if msg.get("content"):
                content.append(msg["content"])
                if on_text:
                    on_text(msg["content"])
                if _degenerate(content):
                    # It is repeating one short string and will not stop on its own: reading more of the
                    # stream only buys more of it. Breaking here returns what it said up to this point.
                    degenerate = True
                    break
            calls += [c for c in msg.get("tool_calls") or [] if isinstance(c, dict)]  # junk entries crash .get later
    MON.record(model, host, tin, tout, time.time() - t0)
    _econ_llm(model, (tin + tout) or _approx_tokens(messages, "".join(content)))  # ECON: usage, else len/4
    text = re.sub(r"<think>.*?</think>", "", "".join(content), flags=re.S)
    leaked = None
    if "</think>" in text:  # reasoning leaked without its opening tag: keep only what follows it
        leaked, text = text.rsplit("</think>", 1)
    text = text.strip()
    if not leaked and not text and not calls and thought:
        leaked = "".join(thought)   # nothing said, nothing called: the reasoning is all there is to go on
    if degenerate:
        # Say it in the answer itself. Silently truncating looks like a complete reply that happens to end
        # mid-sentence, and the model's next turn would read its own garbage back as context.
        text = (text[:2000].rstrip()
                + "\n\n[cut: the model started repeating itself and was not going to stop. Everything after "
                  "the cut was that repetition. If a long literal belongs here - a hash, a key, a digest - "
                  "read it from the file or the tool output instead of retyping it.]")
    out = {"role": "assistant", "content": text}
    if think_loop:
        out["_think_loop"] = True
    if leaked:
        out["_reasoning"] = leaked   # for stalled_call; popped before the message joins the history
    if calls:
        out["tool_calls"] = calls
    _trace(model, host, body, content, thought, calls, out)
    out["usage"] = _providers.normalize_usage("ollama", {"prompt_eval_count": tin, "eval_count": tout})
    return out


def _trace(model, host, body, content, thought, calls, out):
    """GNOC_LLM_TRACE=<file>: one JSON line per local model call with what the model REALLY sent back (raw content,
    its reasoning stream, the tool calls) beside what the harness made of it. Off unless set. Driving gnoc chat on
    2026-11-20, turns died "without an answer" and nothing on disk said whether the model had said nothing, said it
    in its reasoning, or said it in a shape the parser dropped. Secrets: the trace holds what the model saw and
    said, which the scrubber already cleaned; it is a file you asked for, in a place you chose."""
    path = os.environ.get("GNOC_LLM_TRACE")
    if not path:
        return
    try:
        import json as _json
        import time as _time
        row = {"t": round(_time.time(), 3), "model": model, "host": host, "think": body.get("think"),
               "n_msgs": len(body.get("messages") or []), "n_tools": len(body.get("tools") or []),
               "last_user": next((str(m.get("content"))[-300:] for m in reversed(body.get("messages") or [])
                                  if m.get("role") == "user"), ""),
               "raw_content": "".join(content)[-4000:], "thinking": "".join(thought)[-3000:],
               "raw_calls": calls, "out_content": out.get("content", "")[-1000:],
               "out_reasoning": str(out.get("_reasoning") or "")[-1000:]}
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(_json.dumps(row, default=str) + "\n")
    except Exception:  # noqa: BLE001 - a trace must never fail a call
        pass


# `gnoc chat -s-p` / --skip-permissions: no approval prompts at all for this launch (never persisted). The hard
# limits are code, not prompts, and stay on: scope gate, BASH_DENY, WRITE_DENY, the secret guard, no submit tool.
NEXT_SUGGESTION = [""]  # a next-prompt suggestion pre-filled into the input field when a turn ends (GNOC_SUGGEST=0 off)


SPLIT_TOOL_TURN_OK = os.environ.get("GNOC_SPLIT_TOOL_TURNS") == "1"


_SPLIT_ROUTE_SAID = []


def _route_turn(model, host):
    """Where a TOOL-DRIVEN turn actually runs.

    The split server holds a far bigger model but every call ships the whole prompt across the RPC link, and a
    real turn is ~14k tokens of system prompt plus tool schemas. Measured 2026-10-22: 540 s with no answer
    (thinking off), and the connection dropped at 226 s once the tools were attached, so the turn produced
    nothing at all. Split stays the right place for a small-prompt question (/deep, /simple), so the flag and
    the server are left alone; only the tool-driven turn is routed back to the configured per-GPU lead.
    GNOC_SPLIT_TOOL_TURNS=1 restores the old behaviour."""
    (
        SPLIT_TOOL_TURN_OK, T, _SPLIT_ROUTE_SAID, dim, llm_endpoints, role_spec, say, yellow,
    ) = bind(
        "SPLIT_TOOL_TURN_OK", "T", "_SPLIT_ROUTE_SAID", "dim", "llm_endpoints", "role_spec", "say", "yellow",
    )
    if host != "split" or SPLIT_TOOL_TURN_OK:
        return model, host
    want, whost = llm_endpoints.split(role_spec("lead"))
    if whost == "split" or not want:        # the lead IS configured as split: nothing better to fall back to
        return model, host
    if whost != "local" and not llm_endpoints.up(whost):
        return model, host
    if whost == "desktop":
        # the split server holds the desktop's GPU: loading the lead there as well fights it for the VRAM
        if _local_has(want):
            whost = "local"
        else:
            want, whost = llm_endpoints.split(role_spec("worker"))
            if whost != "local":
                return model, host
    if not _SPLIT_ROUTE_SAID:
        _SPLIT_ROUTE_SAID.append(1)
        say(T.byellow("  ⚠ tool turns are not running on the split model: ")
            + yellow(f"using {want}@{whost} instead")
            + dim("  (a ~14k-token tool prompt over the RPC link took >540s and returned nothing; split still "
                  "serves /deep and small-prompt questions. GNOC_SPLIT_TOOL_TURNS=1 forces it back)"))
    return want, whost


_LOCAL_TAGS = [set(), 0.0]


def _local_has(model):
    """True when the laptop's own Ollama serves `model` (tags cached 60 s). The user 2026-10-26: the laptop has
    32 GB of RAM and an 8 GB card, the desktop 16 GB that the video renders need; the lead model is pulled to
    both, so a busy or dead desktop falls back to the SAME model on the laptop, not to the small worker.
    GNOC_LEAD_LOCAL_FALLBACK=0 turns this off."""
    (
        _LOCAL_TAGS, json, llm_endpoints, os, time,
    ) = bind(
        "_LOCAL_TAGS", "json", "llm_endpoints", "os", "time",
    )
    if os.environ.get("GNOC_LEAD_LOCAL_FALLBACK", "1") == "0" or not model:
        return False
    if time.time() - _LOCAL_TAGS[1] > 60:
        try:
            import urllib.request
            addr = llm_endpoints.HOSTS["local"]
            with urllib.request.urlopen("http://" + addr + "/api/tags", timeout=4) as r:
                _LOCAL_TAGS[0] = {m.get("name") for m in json.loads(r.read().decode()).get("models") or []}
        except Exception:  # noqa: BLE001
            _LOCAL_TAGS[0] = set()
        _LOCAL_TAGS[1] = time.time()
    return model in _LOCAL_TAGS[0]


def _avoid_busy_card(model, host):
    """Do not load the 13 GB lead onto the desktop card while someone else's ComfyUI job is on it.

    Measured 2026-10-25 (photo 12): a Wan clip started on the card between my render and my next call; the
    turn loaded the lead anyway, WDDM paged it into system RAM, the desktop fell to 0.03 GB free and the
    turn took 12 minutes before falling back. A lead that is ALREADY resident costs nothing more and is
    kept; a lead that would have to load waits on the laptop model for this turn instead."""
    (
        _fallback_target, _local_has, _short_model, dim, is_broken, json, orange, say,
    ) = bind(
        "_fallback_target", "_local_has", "_short_model", "dim", "is_broken", "json", "orange", "say",
    )
    if host != "desktop":
        return model, host
    try:
        import gnoc_image
        busy = gnoc_image.comfy_busy()
        if not busy:
            return model, host
        loaded = [m.get("name") for m in json.loads(gnoc_image._req("GET", _desktop_ollama() + "/api/ps",
                                                                     timeout=5)).get("models", [])]
    except Exception:
        return model, host
    if model in loaded:
        return model, host
    if _local_has(model) and not is_broken(model, "local"):
        alt_model, alt_host = model, "local"
    else:
        alt_model, alt_host = _fallback_target(model, host)
    if (alt_model, alt_host) == (model, host) or alt_host == host:
        return model, host
    say(dim("  ⎿  ") + orange("✻ ") + dim(f"the desktop card is busy with {busy} ComfyUI job(s) (a video render?): "
                                          f"this turn runs on {_short_model(alt_model)}@{alt_host} rather than "
                                          "loading the lead into the desktop's RAM"))
    return alt_model, alt_host


def _fallback_target(dead_model, dead_host, need_tokens=0):
    """(model, host) to continue on after `dead_model@dead_host` failed.

    The LEAD'S OWN configured model first, when it is not the thing that just died and its host answers:
    the split server dying does not make the desktop unhealthy, and dropping a chat to the small laptop
    model while the configured lead sits loaded on a working GPU is the worst of both (2026-10-22).

    need_tokens: the conversation's approximate size. The SAME model moved to a host whose window for it is
    smaller than that gives way to the configured worker there when the worker's window is bigger: the 35B
    lead moved desktop -> laptop loaded at 16,384 under a 24,220-token prompt and the turn died (2026-11-25)."""
    (
        DEFAULT_WORKER, _local_has, ctx_for, is_broken, llm_endpoints, resolve, role_spec,
    ) = bind(
        "DEFAULT_WORKER", "_local_has", "ctx_for", "is_broken", "llm_endpoints", "resolve", "role_spec",
    )

    def _fits(model, host):
        if not need_tokens or model != dead_model or host == dead_host:
            return model, host
        try:
            have = ctx_for(host, model)
            if have >= need_tokens:
                return model, host
            w_name, _w_host = llm_endpoints.split(role_spec("worker"))
            if not w_name or w_name == model or is_broken(w_name, host):
                return model, host
            if host == "local" and not _local_has(w_name):
                return model, host
            if ctx_for(host, w_name) > have:
                return w_name, host
        except Exception:  # noqa: BLE001 - the choice is advisory; the old target stands
            pass
        return model, host

    want_name, want_host = llm_endpoints.split(role_spec("lead"))
    if (want_name, want_host) != (dead_model, dead_host) and want_host != dead_host:
        if want_host == "local" or llm_endpoints.up(want_host):
            if not is_broken(want_name, want_host):
                return _fits(want_name, want_host)
    if dead_host != "local" and _local_has(dead_model) and not is_broken(dead_model, "local"):
        return _fits(dead_model, "local")   # the same lead on the laptop's 32 GB beats the small worker
    model, host = resolve("worker", quiet=True)
    if host in ("desktop", "split") and host == dead_host:
        model, host = llm_endpoints.split(DEFAULT_WORKER)[0], "local"
    return model, host


def _list(host):
    (
        json, llm_endpoints, urllib,
    ) = bind(
        "json", "llm_endpoints", "urllib",
    )
    try:
        with urllib.request.urlopen(f"http://{llm_endpoints.HOSTS[host]}/api/ps", timeout=3) as r:
            loaded = [m["name"] for m in json.loads(r.read()).get("models", [])]
        return True, loaded
    except Exception:
        return False, []


def cmd_gpus():
    (
        SPLIT_FLAG, SPLIT_URL, _list, green, llm_endpoints, os, red, resolve, role_spec, say, split_up, yellow,
    ) = bind(
        "SPLIT_FLAG", "SPLIT_URL", "_list", "green", "llm_endpoints", "os", "red", "resolve", "role_spec", "say",
        "split_up", "yellow",
    )
    state = (green("UP") + f" at {SPLIT_URL}, serving lead + worker") if split_up() else \
        (yellow("LOADING") + " (laptop answers meanwhile; the desktop GPU is reserved for it)"
         if os.path.exists(SPLIT_FLAG) else "off  (gnoc split up)")
    if SPLIT_URL:   # an install without a split server has nothing to say about one
        say("  split (one model on both GPUs): " + state)
    for role in ("lead", "worker"):
        spec = role_spec(role)
        model, host = resolve(role)
        # A cloud host is not in this table and KeyError'd the whole command (GreyNOC, 2026-10-28:
        # /gpus right after /deepseek on). It is also the one row that needs saying out loud.
        where = (__import__("llm_endpoints").host_label(host) if host in ("desktop", "local", "split")
                 else f"{host} CLOUD - leaves this machine")
        note = "" if host == "split" or llm_endpoints.split(spec) == (model, host) else \
            yellow(f"  (configured {spec}, fell back)")
        say(f"  {role:<7} {model} @ {where}{note}")
    _ep = __import__("llm_endpoints")
    for host in (("desktop", "local") if _ep.multi_machine() else ("local",)):   # one computer: one row
        label = _ep.host_label(host)
        up, loaded = _list(host)
        say(f"  {label:<12} {'up' if up else red('down')}  loaded: {', '.join(loaded) or '-'}")
