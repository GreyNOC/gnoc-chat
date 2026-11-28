"""gnoc_hf.py - clone a Hugging Face model repo into the local model server (gnoc's engine, or an Ollama) and make it
a bot you talk to in `gnoc chat`.

    /hf clone <owner/repo | https://huggingface.co/owner/repo>[:QUANT] [--as NAME] [--role lead|worker|both|none]
              [--on desktop]
    /hf search <words>      GGUF repos, most downloaded first
    /hf files <owner/repo>  the quantisations a repo carries, with sizes and whether they fit the GPU
    /hf list                models cloned through gnoc chat: uses, the role each holds
    /hf room                evict least-used cloned bots now so one more fits under the cap (GNOC_HF_MAX_BOTS, default 3)
    /hf use <model> [lead|worker] [--on desktop]
    (/clone <huggingface url> routes here too)

How a repo becomes a bot:
  1. the repo carries .gguf files   -> pull the quant you asked for, else the best one that fits the GPU
                                       (Q4_K_M first), through scripts/gnoc-models.py (POST /api/pull hf.co/...)
  2. no GGUF, but a GGUF build of it exists on the Hub (bartowski, unsloth, ...) -> use the most downloaded one
  3. only safetensors               -> on an Ollama host only: download them to ~/.cache/gnoc-hf/ and
                                       `ollama create --quantize q4_K_M`. gnoc's engine loads GGUF and says so.
Room is made first: at most GNOC_HF_MAX_BOTS (default 3) cloned bots per GPU host, and enough free disk for
the download. When either is short, the LEAST-USED cloned bot is removed from the model server and noted in
the registry. A bot that holds a role (lead, worker, chat, brain, hunter) is never removed, nor is any model that
was not cloned through gnoc chat. Usage is counted every time gnoc chat talks to a model (touch()).
Then the model is smoke-tested, its capabilities read from the server (/api/show), and it takes the role you
asked for (default lead = the model you talk to). A model without tool calling cannot drive the agent, so it
gets the /simple chat role instead and the agent says so. Gated repos need HF_TOKEN in
~/.config/gnoc/secrets.env (read, never printed).
"""
import importlib.util
import contextlib
import json
import os
import re
import subprocess
import threading
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(WS, "scripts"))
import gnoc_theme as T  # noqa: E402
import llm_endpoints  # noqa: E402
import gnoc_engine  # noqa: E402

MODELS_PY = os.path.join(WS, "scripts", "gnoc-models.py")
REGISTRY = os.path.join(WS, ".claude/state/orch/agent/hf-models.json")
CACHE = os.path.expanduser("~/.cache/gnoc-hf")
MAX_BOTS = int(os.environ.get("GNOC_HF_MAX_BOTS", "3"))
MODELS_DIR = os.environ.get("OLLAMA_MODELS") or os.path.expanduser("~/.ollama/models")
QUANT_PREF = ["Q4_K_M", "Q4_K_S", "IQ4_XS", "Q4_0", "Q5_K_M", "Q3_K_M", "IQ3_M", "Q3_K_S", "Q6_K", "Q8_0", "Q2_K"]
SAFE_FILES = re.compile(r"(\.safetensors|^config\.json|^generation_config\.json|^tokenizer[^/]*|"
                        r"^special_tokens_map\.json|^vocab\.(json|txt)|^merges\.txt|\.model|\.tiktoken)$")


def _models_mod():
    spec = importlib.util.spec_from_file_location("gnoc_models", MODELS_PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _token():
    tok = os.environ.get("HF_TOKEN")
    if tok:
        return tok
    try:
        for ln in open(os.path.expanduser("~/.config/gnoc/secrets.env")):
            m = re.match(r"\s*(?:export\s+)?HF_TOKEN\s*=\s*['\"]?([^'\"\s#]+)", ln)
            if m:
                return m.group(1)
    except OSError:
        pass
    return None


def hub(path, timeout=30):
    h = {"User-Agent": "gnoc-chat"}
    if _token():
        h["Authorization"] = f"Bearer {_token()}"
    with urllib.request.urlopen(urllib.request.Request("https://huggingface.co" + path, headers=h),
                                timeout=timeout) as r:
        return json.loads(r.read())


def parse_spec(spec):
    """'https://huggingface.co/owner/repo/tree/main:Q5_K_M' | 'hf.co/owner/repo' | 'owner/repo:Q4_K_M'
    -> ('owner/repo', 'Q5_K_M' | None)."""
    s = re.sub(r"^(https?://)?(www\.)?(huggingface\.co|hf\.co)/", "", spec.strip())
    s = re.sub(r"^models/", "", s)
    quant = None
    if ":" in s:
        s, quant = s.rsplit(":", 1)
        quant = quant.upper() or None
    parts = s.strip("/").split("/")
    if len(parts) < 2 or not all(re.fullmatch(r"[\w.-]+", p) for p in parts[:2]):
        raise ValueError(f"not a Hugging Face repo: {spec!r} (want owner/repo or a huggingface.co URL)")
    return f"{parts[0]}/{parts[1]}", quant


def is_hf(spec):
    return bool(re.match(r"^(https?://)?(www\.)?(huggingface\.co|hf\.co)/", spec.strip()))


def _host(on):
    return llm_endpoints.HOSTS[on]


def _api(on, path, body=None, timeout=60):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{_host(on)}{path}", data, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def capabilities(name, on="local"):
    try:
        return _api(on, "/api/show", {"model": name}).get("capabilities") or []
    except Exception:
        return []


def smoke(name, on="local"):
    t0 = time.time()
    r = _api(on, "/api/chat", {"model": name, "stream": False, "messages": [
        {"role": "user", "content": "Reply with exactly: ready"}], "options": {"num_predict": 24}}, timeout=600)
    return (r.get("message") or {}).get("content", "").strip()[:80], time.time() - t0


def _registry():
    try:
        with open(REGISTRY) as fh:   # called by touch() on every turn: do not leak the fd
            return json.load(fh)
    except (OSError, ValueError):
        return []


def _save_registry(rows):
    """Atomic, like every other state file here: touch() rewrites this on EVERY answer, from every chat at
    once, so a Ctrl-C or a second writer mid-dump used to leave a torn file that _registry() then read as []
    - every clone's usage count silently gone. Per-pid/thread tmp so two writers cannot steal each other's."""
    os.makedirs(os.path.dirname(REGISTRY), exist_ok=True)
    tmp = f"{REGISTRY}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(rows, f, indent=1)
        os.replace(tmp, REGISTRY)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def touch(name, on="local"):
    """Count one use of a cloned bot (gnoc chat calls this per answer); models it did not clone are ignored."""
    rows = _registry()
    for x in rows:
        if x.get("name") == name and x.get("on") == on and not x.get("removed"):
            x["uses"] = int(x.get("uses") or 0) + 1
            x["last_used"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            _save_registry(rows)
            return


def _role_holders():
    return {llm_endpoints.split(v)[0] for k, v in llm_endpoints.roles().items() if isinstance(v, str)}


def _free(on):
    if on != "local":
        return None  # the desktop's disk is not visible from here: only the count cap applies there
    import shutil
    return shutil.disk_usage(MODELS_DIR if os.path.isdir(MODELS_DIR) else os.path.expanduser("~")).free


def make_room(on, need_bytes, keep=None):
    """Evict least-used cloned bots on this host until (a) one more fits under MAX_BOTS and (b) need_bytes of
    disk is free (plus 5 GB headroom). Role holders and models not cloned here are never touched."""
    rows = _registry()
    live = [x for x in rows if x.get("on") == on and not x.get("removed") and x.get("name") != keep]
    try:
        installed = {m["name"].removesuffix(":latest") for m in _api(on, "/api/tags").get("models", [])}
    except Exception:
        installed = None
    if installed is not None:  # removed by hand outside gnoc: drop from the count
        for x in live:
            if x["name"] not in installed:
                x["removed"] = "missing from the model server"
        live = [x for x in live if not x.get("removed")]
    held = _role_holders()
    victims = sorted((x for x in live if x["name"] not in held),
                     key=lambda x: (int(x.get("uses") or 0), x.get("last_used") or x.get("cloned_at") or ""))
    free = _free(on)
    short = lambda: len(live) >= MAX_BOTS or (free is not None and free < need_bytes + 5e9)
    while short() and victims:
        v = victims.pop(0)
        # over HTTP with a timeout (a wedged server used to hang make_room, and the clone that called it, for ever);
        # the same call removes a model from gnoc's engine and from an Ollama
        try:
            gnoc_engine.remote_delete(_host(on), v["name"])
        except gnoc_engine.EngineError as e:
            print(T.red(f"  could not remove {v['name']}: {str(e)[-200:]}"))
            continue
        # pulling hf.co/... leaves its own tag holding the weights: drop it too, unless a role or another
        # cloned bot still points at it, or the disk is not actually freed
        src = v.get("src_tag")
        if src and src not in held and not any(x.get("src_tag") == src for x in live if x is not v):
            with contextlib.suppress(gnoc_engine.EngineError):
                gnoc_engine.remote_delete(_host(on), src)
        v["removed"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        live.remove(v)
        print(T.yellow("  ✗ removed least-used bot ") + T.red(v["name"])
              + T.dim(f"  ({int(v.get('uses') or 0)} uses, last {v.get('last_used') or 'never'})"))
        free = _free(on)
    _save_registry(rows)
    if short():
        why = (f"{len(live)} cloned bots already (max {MAX_BOTS}) and every one holds a role"
               if len(live) >= MAX_BOTS else f"only {free / 1e9:.0f} GB free for a {need_bytes / 1e9:.0f} GB model")
        raise RuntimeError(f"no room: {why}. Free a role (/hf use) or raise GNOC_HF_MAX_BOTS.")


def _pick_quant(gm, quants, want):
    qs = {q: s for q, s, _ in quants}
    if want:
        if want not in qs:
            raise ValueError(f"no {want} in this repo; it has: {', '.join(sorted(qs)) or 'none'}")
        return want
    budget = gm.vram() * 1.25 * 1e9  # a little spill to system RAM is fine; more than that crawls
    for q in QUANT_PREF:
        if q in qs and qs[q] <= budget:
            return q
    fitting = sorted((s, q) for q, s in qs.items() if s <= budget)
    if fitting:
        return fitting[-1][1]
    return min(qs, key=qs.get) if qs else None


def _gguf_mirror(repo):
    base = repo.split("/")[1]
    q = urllib.parse.urlencode({"search": base, "filter": "gguf", "sort": "downloads", "limit": 20})
    for m in hub(f"/api/models?{q}"):
        if base.lower() in m["id"].lower() and m["id"].lower() != repo.lower():
            return m["id"]
    return None


def _download(repo, files, dest):
    os.makedirs(dest, exist_ok=True)
    h = {"User-Agent": "gnoc-chat"}
    if _token():
        h["Authorization"] = f"Bearer {_token()}"
    for f in files:
        out = os.path.join(dest, f["path"])
        if os.path.exists(out) and os.path.getsize(out) == f.get("size"):
            continue
        os.makedirs(os.path.dirname(out), exist_ok=True)
        url = f"https://huggingface.co/{repo}/resolve/main/{urllib.parse.quote(f['path'])}"
        size, done, t0 = f.get("size") or 0, 0, time.time()
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=120) as r, \
                open(out + ".part", "wb") as fh:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if sys.stdout.isatty():
                    pct = f"{100 * done / size:5.1f}%" if size else ""
                    sys.stdout.write(f"\r  {T.blue(f['path'][:48]):<60} {pct} "
                                     + T.dim(f"{done / 1e9:.2f} GB  {done / 1e6 / max(time.time() - t0, .1):.0f} MB/s"))
                    sys.stdout.flush()
        os.replace(out + ".part", out)
        if sys.stdout.isatty():
            sys.stdout.write("\r\x1b[2K")
        print(T.green("  ✓ ") + f["path"])


def _create_from_safetensors(repo, name, on):
    if gnoc_engine.who(_host(on)) != "ollama" or not __import__("shutil").which("ollama"):
        # converting raw safetensors is the one thing here that still needs Ollama's own importer
        raise RuntimeError(f"{repo} has no GGUF build anywhere on the Hub, and gnoc's engine loads GGUF only. "
                           f"Look for one with /hf search {repo.split('/')[1]}, or convert it with llama.cpp's "
                           "convert_hf_to_gguf.py and then: gnoc engine pull <file.gguf>")
    tree = hub(f"/api/models/{repo}/tree/main?recursive=true")
    files = [f for f in tree if f.get("type") == "file" and SAFE_FILES.search(f["path"].split("/")[-1])
             and "/" not in f["path"]]
    if not any(f["path"].endswith(".safetensors") for f in files):
        raise RuntimeError(f"{repo} has neither GGUF nor top-level safetensors weights; nothing Ollama can load")
    total = sum(f.get("size") or 0 for f in files)
    make_room(on, total * 1.4, keep=name)  # the safetensors plus the quantised copy Ollama builds from them
    print(T.yellow(f"  no GGUF anywhere for {repo}: downloading {total / 1e9:.1f} GB of safetensors to convert"))
    dest = os.path.join(CACHE, repo.replace("/", "__"))
    _download(repo, files, dest)
    with tempfile.NamedTemporaryFile("w", suffix=".Modelfile", delete=False) as tf:
        tf.write(f"FROM {dest}\nPARAMETER num_ctx 16384\nPARAMETER temperature 0.2\n")
    try:
        print(T.dim(f"  ollama create {name} --quantize q4_K_M (a few minutes) ..."), flush=True)
        # a real quantize runs for minutes; an hour means it is wedged, not working
        p = subprocess.run(["ollama", "create", name, "--quantize", "q4_K_M", "-f", tf.name], text=True,
                           capture_output=True, timeout=3600, env=dict(os.environ, OLLAMA_HOST=_host(on)))
    finally:
        os.unlink(tf.name)
    if p.returncode != 0:
        raise RuntimeError(f"ollama could not import {repo}: {p.stderr.strip()[-300:]} (an architecture Ollama "
                           f"cannot convert; look for a GGUF build with /hf search {repo.split('/')[1]})")


def clone(spec, alias=None, role="lead", on="local", set_role=None):
    """Clone a Hugging Face repo into Ollama and hand it a gnoc chat role. Returns the Ollama model name."""
    repo, want = parse_spec(spec)
    gm = _models_mod()
    gm.ON, gm.HOST = on, _host(on)
    try:
        info = hub(f"/api/models/{repo}")
    except urllib.error.HTTPError as e:
        with e:  # the error response is a live socket: close it, or every failed call leaks one
            hint = (" (gated or private: put HF_TOKEN in ~/.config/gnoc/secrets.env)"
                    if e.code in (401, 403) else "")
            raise RuntimeError(f"Hugging Face says {e.code} for {repo}{hint}")
    print(T.green("● ") + T.white("hf ") + T.blue(repo) + T.dim(
        f"  ·  {info.get('pipeline_tag') or 'model'}  ·  {info.get('downloads', 0):,} downloads"
        + ("  ·  gated" if info.get("gated") else "")))
    src_repo, how = repo, "gguf"
    quants = gm.quants(repo)
    if not quants:
        mirror = _gguf_mirror(repo)
        if mirror:
            print(T.yellow(f"  {repo} ships no GGUF; using the GGUF build {mirror}"))
            src_repo, quants, how = mirror, gm.quants(mirror), "gguf-mirror"
    name = alias or re.sub(r"(?i)[-_]?gguf$", "", repo.split("/")[1]).lower() + "-oc"
    if quants:
        quant = _pick_quant(gm, quants, want)
        size = dict((q, s) for q, s, _ in quants)[quant]
        print(T.dim(f"  quant {quant} ({gm.gb(size)}, {gm.fit(size)})"))
        make_room(on, size, keep=name)
        sys.stdout.flush()
        rc = subprocess.call([sys.executable, MODELS_PY, "pull", f"{src_repo}:{quant}", "--as", name]
                             + (["--on", on] if on != "local" else []))
        if rc != 0:
            raise RuntimeError(f"pull failed (exit {rc})")
    else:
        quant, how = "q4_K_M", "safetensors"
        _create_from_safetensors(repo, name, on)
    caps = capabilities(name, on)
    try:
        reply, secs = smoke(name, on)
        print(T.green("  ✓ ") + f"answers: {reply!r}" + T.dim(f"  ({secs:.0f}s cold start)"))
    except Exception as e:
        print(T.red(f"  ✗ loaded but did not answer: {e}"))
    spec_name = name if on == "local" else f"{name}@{on}"
    tools_ok = "tools" in caps
    given = []
    if role in ("lead", "worker", "both") and not tools_ok:
        print(T.yellow(f"  {name} has no tool calling ({', '.join(caps) or 'capabilities unknown'}): it cannot "
                       "drive the agent, so it becomes the /simple chat model instead"))
        role = "chat"
    for r in (("lead", "worker") if role == "both" else (role,) if role not in ("none", "") else ()):
        if set_role:
            set_role(r, spec_name)
        given.append(r)
    old = next((x for x in _registry() if x.get("name") == name and x.get("on") == on), {})
    rows = [x for x in _registry() if x.get("name") != name or x.get("on") != on] + [{
        "uses": 0 if old.get("removed") else int(old.get("uses") or 0), "last_used": old.get("last_used"),
        "name": name, "on": on, "repo": repo, "source": src_repo, "quant": quant, "how": how, "caps": caps,
        "src_tag": f"hf.co/{src_repo}:{quant}" if how != "safetensors" else None,
        "roles": given, "cloned_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}]
    _save_registry(rows)
    print(T.green("● ") + T.white(f"{spec_name} ready") + (T.dim("  ·  role: ") + T.yellow(", ".join(given))
                                                           if given else T.dim("  ·  no role (/hf use)")))
    if "chat" in given:
        print(T.dim("  talk to it: /simple <question>"))
    elif given:
        print(T.dim("  it answers your next message; /gpus shows where it runs"))
    return name


def cmd(args, set_role=None):
    """Entry point for /hf and `/clone <hf url>`."""
    a = list(args)
    on, alias, role = "local", None, "lead"
    for flag in ("--on", "--as", "--role"):
        if flag in a:
            i = a.index(flag)
            val = a[i + 1] if i + 1 < len(a) else ""
            del a[i:i + 2]
            on, alias, role = (val, alias, role) if flag == "--on" else (on, val, role) if flag == "--as" else \
                (on, alias, val)
    for f in ("--lead", "--worker", "--both"):
        if f in a:
            a.remove(f)
            role = f[2:]
    if on not in llm_endpoints.HOSTS:
        return print(T.red(f"--on takes one of: {', '.join(llm_endpoints.HOSTS)}"))
    if on != "local" and not llm_endpoints.up(on):
        return print(T.red(f"the {on} model server is not reachable (gnoc models desktop)"))
    sub, rest = (a[0].lower(), a[1:]) if a else ("help", [])
    if is_hf(sub) or re.fullmatch(r"[\w.-]+/[\w.-]+(:[\w.]+)?", sub):
        sub, rest = "clone", a
    try:
        if sub == "clone" and rest:
            clone(rest[0], alias, role, on, set_role)
        elif sub == "search" and rest:
            q = urllib.parse.urlencode({"search": " ".join(rest), "filter": "gguf", "sort": "downloads", "limit": 15})
            for m in hub(f"/api/models?{q}"):
                print(f"  {T.blue(m['id']):<80} " + T.dim(f"{m.get('downloads', 0):>10,} downloads"))
            print(T.dim("  next: /hf files <owner/repo>   or   /hf clone <owner/repo>"))
        elif sub == "files" and rest:
            gm = _models_mod()
            gm.ON, gm.HOST = on, _host(on)
            repo, _ = parse_spec(rest[0])
            for q, s, p in sorted(gm.quants(repo), key=lambda x: x[1]):
                print(f"  {T.yellow(f'{q:<10}')} {gm.gb(s):>8}  {gm.fit(s):<26} " + T.dim(p))
            print(T.dim(f"  next: /hf clone {repo}:Q4_K_M"))
        elif sub == "room":
            make_room(on, 0)
            print(T.green(f"  room ok: room for one more cloned bot on {on} (cap {MAX_BOTS})"))
        elif sub in ("list", "ls"):
            rows = [x for x in _registry() if not x.get("removed")]
            if not rows:
                print(T.dim("  nothing cloned through gnoc chat yet: /hf clone <owner/repo>"))
            for x in rows:
                print(f"  {T.green(x['name'])}{T.dim('@' + x['on'] if x['on'] != 'local' else '')}  "
                      f"{T.blue(x['repo'])} {T.dim(x['quant'] + ' via ' + x['how'])}  "
                      f"{T.dim(str(x.get('uses') or 0) + ' uses')}  roles: "
                      f"{T.yellow(', '.join(x.get('roles') or []) or '-')}  tools: "
                      + (T.green("yes") if "tools" in (x.get("caps") or []) else T.red("no")))
        elif sub == "use" and rest:
            name, r = rest[0], (rest[1] if len(rest) > 1 else "lead")
            if r not in ("lead", "worker", "chat"):
                return print(T.red("role: lead | worker | chat"))
            if r != "chat" and "tools" not in capabilities(name, on):
                print(T.yellow(f"  warning: {name} does not report tool calling; the agent needs it"))
            if set_role:
                set_role(r, name if on == "local" else f"{name}@{on}")
            print(T.green(f"  {r} -> {name}" + ("" if on == "local" else f"@{on}")))
            rows = _registry()
            for x in rows:
                if x.get("name") == name and x.get("on") == on:
                    x["roles"] = sorted(set(x.get("roles") or []) | {r})
            _save_registry(rows)
        else:
            print(T.dim(__doc__.split("How a repo")[0].split("\n", 1)[1]))
    except (ValueError, RuntimeError, urllib.error.URLError) as e:
        print(T.red(f"  {e}"))
    except KeyboardInterrupt:
        print(T.yellow("\n  interrupted (a partial download resumes next time)"))
    except SystemExit as e:  # gnoc-models helpers exit with a message on bad input
        print(T.red(f"  {e}"))
