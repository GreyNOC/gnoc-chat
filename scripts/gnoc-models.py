#!/usr/bin/env python3
"""gnoc-models.py - clone Hugging Face models into the hunt Ollama (127.0.0.1:11434) and give them jobs.

  gnoc models                          installed models, which role uses each, and whether it fits the GPU
  gnoc models search <words>           Hugging Face GGUF repos, most downloaded first (e.g. "qwen3 abliterated")
  gnoc models files <owner/repo>       the quantisations in a repo with sizes (Q4_K_M is the usual 8 GB choice)
  gnoc models pull <owner/repo>[:QUANT] [--as NAME]
                                       download into ollama-oc and build a 16k-context NAME (default <repo>-oc)
  gnoc models use <role> <model>       roles: brain (orch-bot decisions), chat (gnoc chat), hunter (OpenCode lanes)
  gnoc models test <model> [n]         the Model Lab QUICK suite (scripts/model-lab/lab.py bench <model> --suite quick):
                                       orch decisions (live + frozen snapshots), JSON, grounded report fields, security
                                       triage, house-rule following, refusal, plus latency/tok-s/VRAM, scored 0..100.
                                       Run it before giving a new model a role; compare with gnoc lab list / compare.
                                       Without model-lab: n dry-run orch decisions (operator) or n JSON arithmetic
                                       rounds scored for format, correctness and latency (public edition).
  gnoc models rm <model>               remove (refused while a role uses it)
  gnoc models desktop                  the linked Windows desktop: tunnel up?, its models, what is loaded
  gnoc models desktop vram <GB>        tell the rig the desktop GPU size (for the fits-GPU column)

  gnoc models machines                 every computer hooked up to this one: is it answering, its GPU and memory,
                                       free disk, how many models it holds
  gnoc models where <owner/repo>[:QUANT]
                                       where that model would go: per machine, the quantisation it would get, whether
                                       it fits, whether it is already there - and which machine a pull would choose

  pull with more than one machine answering ASKS where to download (Enter takes the best fit). Say it up front with
  --on <machine>, --on desktop,phone (several), --on all, or --on best. Without a terminal it downloads here.

  --on desktop   add to list, files, pull, use, test, rm to act on the DESKTOP's Ollama (reverse SSH tunnel at
                 127.0.0.1:11436, set up once with scripts/desktop-link/link-desktop.ps1). A desktop role is stored as
                 model@desktop and falls back to the laptop model whenever the desktop is off (scripts/llm_endpoints.py).

Roles live in .claude/state/orch/models.json; orch_brain.py and gnoc chat read it on every call, the hunter role is
written into .opencode/agent/hunter.md and ~/.config/opencode/opencode.json. Works from the gnoc watch command box.
The GPU has 8 GB: a Q4_K_M up to ~14B runs (partly offloaded, slower); 7-8B is fully on the GPU.
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ORCH = os.path.join(WS, ".claude/state/orch")
ROLES = os.path.join(ORCH, "models.json")
CHANGES_LOG = os.path.join(ORCH, "changes.jsonl")


def _log_change(kind, **fields):
    """Same global change log gnoc's own do_stop/do_lock/etc. append to; the OUTCOMES panel in
    gnoc watch merges it with outcomes.jsonl and ships.jsonl into one activity feed."""
    try:
        os.makedirs(ORCH, exist_ok=True)
        row = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind, **fields}
        with open(CHANGES_LOG, "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass
import gnoc_edition  # noqa: E402
import gnoc_engine  # noqa: E402  (pull/create/rm go over HTTP: the same calls work on gnoc's engine and on an Ollama)

HOSTS = {"local": os.environ.get("GNOC_LOCAL_OLLAMA", "127.0.0.1:11434"),
         # 11440 = scripts/desktop-link/traffic_proxy.py, which forwards to the real tunnel on
         # 11436 and logs every request for the control panel; set GNOC_DESKTOP_OLLAMA to bypass it.
         "desktop": os.environ.get("GNOC_DESKTOP_OLLAMA", "")}
try:   # a phone on USB (gnoc phone setup) is a host too: --on phone
    import llm_endpoints as _hosts
    if _hosts.HOSTS.get("phone"):
        HOSTS["phone"] = _hosts.HOSTS["phone"]
    if not HOSTS.get("desktop") and _hosts.HOSTS.get("desktop"):
        HOSTS["desktop"] = _hosts.HOSTS["desktop"]     # a second computer saved by gnoc setup
except Exception:  # noqa: BLE001
    pass
ON = "local"           # set by --on desktop in main()
HOST = HOSTS[ON]
DESKTOP_CFG = os.path.join(ORCH, "desktop.json")
OC_CFG = os.path.expanduser("~/.config/opencode/opencode.json")
HUNTER_MD = os.path.join(WS, ".opencode/agent/hunter.md")
VRAM_GB = float(os.environ.get("GNOC_VRAM_GB", "8"))


def _cfg_vram(name):
    """GB of GPU memory recorded for a machine that cannot say for itself (an Ollama): gnoc models desktop vram N."""
    try:
        with open(os.path.join(ORCH, f"{name}.json")) as f:
            return float(json.load(f).get("vram_gb") or 0)
    except (OSError, ValueError, AttributeError, TypeError):
        return 0.0


def vram():
    if ON != "local":
        return _cfg_vram(ON) or VRAM_GB
    return VRAM_GB


# ------------------------------------------------------------------ the machines a model can be downloaded to
def machines(timeout=2):
    """One row per configured machine: {name, addr, kind ('gnoc'|'ollama'|''), gpu, vram, ram, free, models}.
    Sizes in bytes, 0 = not known. A gnoc engine says all of it (GET /api/machine); an Ollama says nothing about
    its hardware, so its GPU size is the one recorded with `gnoc models <machine> vram <GB>`."""
    rows = []
    for name, addr in HOSTS.items():
        if not addr:
            continue
        row = {"name": name, "addr": addr, "kind": gnoc_engine.who(addr, timeout), "gpu": "", "vram": 0, "ram": 0,
               "free": 0, "models": None, "have": []}
        if row["kind"]:
            info = {}
            if row["kind"] == "gnoc":
                try:
                    info = gnoc_engine.api(addr, "/api/machine", timeout=timeout + 1)
                except Exception:  # noqa: BLE001 - an engine older than 1.3 has no such page
                    info = {}
            if not info and name == "local" and row["kind"] == "gnoc":
                info = gnoc_engine.machine()      # the same computer: read it here
            row.update(gpu=info.get("gpu") or "", vram=int(info.get("vram") or 0), ram=int(info.get("ram") or 0),
                       free=int(info.get("disk_free") or 0))
            if not row["vram"]:
                row["vram"] = int((_cfg_vram(name) or (VRAM_GB if name == "local" else 0)) * 2 ** 30)
            try:
                row["have"] = [m["name"] for m in gnoc_engine.api(addr, "/api/tags", timeout=timeout + 2)
                               .get("models") or []]
                row["models"] = len(row["have"])
            except Exception:  # noqa: BLE001
                pass
        rows.append(row)
    return rows


def _budget(row):
    if not row["vram"] and not row["ram"]:
        return None
    return gnoc_engine.budget_for(row["gpu"], row["vram"], row["ram"])


def placement(row, by, quant=None, src_repo=""):
    """Where a model would land on one machine: {quant, size, rank, word, there}. rank: 0 fits, 1 runs slower,
    2 too big, 3 not known, 8 no room on the disk, 9 the machine is not answering. by: {QUANT: (QUANT, bytes)}."""
    if not row["kind"]:
        return {"quant": quant or "", "size": 0, "rank": 9, "word": "not answering", "there": False}
    budget = _budget(row)
    q = quant or (gnoc_engine.pick_quant(by, budget)[0] if budget else
                  next((x for x in gnoc_engine.QUANT_PREF if x in by), min(by, key=lambda x: by[x][1])))
    size = by[q][1]
    there = any(n.lower() in (f"hf.co/{src_repo}:{q}".lower(), f"{src_repo}:{q}".lower()) for n in row["have"])
    if row["free"] and not there and row["free"] < size + (1 << 30):
        return {"quant": q, "size": size, "rank": 8, "there": there,
                "word": f"no room: {row['free'] / 1e9:.1f} GB free"}
    if not budget:
        return {"quant": q, "size": size, "rank": 3, "there": there,
                "word": f"GPU size not known (gnoc models {row['name']} vram <GB>)"}
    well, at_all, what = budget
    if size <= well:
        rank, word = 0, "fits"
    elif size <= at_all and row["ram"]:
        rank, word = 1, "runs partly on the CPU (slower)"
    elif not row["ram"] and size <= row["vram"] * 2.5:
        rank, word = 1, f"bigger than {what}: partly on the CPU (slower)"
    else:
        rank, word = 2, f"too big for {what}"
    return {"quant": q, "size": size, "rank": rank, "word": word, "there": there}


def best_machine(rows, places):
    """The machine a pull takes when nobody chose: the best fit; among equals the bigger GPU; then this computer."""
    live = [r for r in rows if places[r["name"]]["rank"] < 8]
    if not live:
        return None
    return min(live, key=lambda r: (places[r["name"]]["rank"], -r["vram"], r["name"] != "local"))["name"]


def _machine_line(i, r, pl=None, mark=""):
    hw = (f"{r['vram'] / 2 ** 30:.0f} GB GPU" if r["vram"] else "GPU ?") + \
         (f", {r['ram'] / 2 ** 30:.0f} GB memory" if r["ram"] else "") + \
         (f", {r['free'] / 1e9:.0f} GB free" if r["free"] else "")
    if not r["kind"]:
        return f"  {i}  {r['name']:<8} {r['addr']:<22} not answering"
    tail = (f"{pl['quant']:<8} {gb(pl['size']):>8}  {pl['word']}" + ("  (already there)" if pl["there"] else "")
            ) if pl else f"{r['models'] if r['models'] is not None else '?'} models"
    return (f"  {i}  {r['name']:<8} {('gnoc engine' if r['kind'] == 'gnoc' else 'Ollama'):<12} {hw:<38} {tail}"
            + (f"  {mark}" if mark else ""))


def cmd_machines():
    rows = machines()
    for i, r in enumerate(rows, 1):
        print(_machine_line(i, r))
    if sum(1 for r in rows if r["kind"]) < 2:
        print("one machine answers. Add another: gnoc setup (a second computer), gnoc phone setup (a phone on USB)")
    return 0


def _repo_quants(spec):
    repo, _, quant = spec.partition(":")
    repo = re.sub(r"^(?:https?://)?(?:huggingface\.co|hf\.co)/", "", repo).strip("/")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        sys.exit("usage: gnoc models pull <owner/repo>[:QUANT]")
    try:
        by = {}
        for q, size, _p in quants(repo):
            by[q] = (q, by.get(q, (q, 0))[1] + size)       # a quantisation split over several files is one model
    except Exception as e:
        sys.exit(f"cannot read {repo} on Hugging Face ({e})")
    if not by:
        sys.exit(f"no .gguf files in {repo}; only GGUF repos can be pulled (search with gnoc models search)")
    quant = quant.upper() or None
    if quant and quant not in by:
        sys.exit(f"{repo} has no {quant}; available: {', '.join(sorted(by)) or 'none'}")
    return repo, quant, by


def _table(repo, quant, by):
    rows = machines()
    places = {r["name"]: placement(r, by, quant, repo) for r in rows}
    best = best_machine(rows, places)
    for i, r in enumerate(rows, 1):
        print(_machine_line(i, r, places[r["name"]], "<- best fit" if r["name"] == best else ""))
    return rows, places, best


def cmd_where(spec):
    repo, quant, by = _repo_quants(spec)
    print(f"{repo}" + (f":{quant}" if quant else "") + ": where it would go")
    rows, places, best = _table(repo, quant, by)
    if best:
        print(f"next: gnoc models pull {repo}:{places[best]['quant']} --on {best}")
    else:
        print("no machine can take it: none answers, or none has the disk space")
    return 0 if best else 1


def choose_machines(spec, on=None, ask=None, tty=None):
    """The machines a pull goes to, and what each gets: [(name, quant)]. on: None (not said), a name, several
    with commas, 'all', 'best' or 'ask'. With nothing said and a terminal, two or more answering machines are a
    question; without a terminal it is this computer, as it always was."""
    repo, quant, by = _repo_quants(spec)
    tty = sys.stdin.isatty() and sys.stdout.isatty() if tty is None else tty
    names = [n for n, a in HOSTS.items() if a]
    if on and on not in ("all", "best", "ask"):
        want = [w.strip() for w in on.split(",") if w.strip()]
        bad = [w for w in want if w not in names]
        if bad:
            sys.exit(f"--on takes one of: {', '.join(names)}, all, best, ask  (not {', '.join(bad)})")
        if len(want) == 1 and not quant and want[0] == "local":
            return repo, by, [("local", None)]
    rows = machines()
    places = {r["name"]: placement(r, by, quant, repo) for r in rows}
    best = best_machine(rows, places)
    up = [r["name"] for r in rows if r["kind"]]
    if on and on not in ("all", "best", "ask"):
        down = [w for w in want if w not in up]
        if down:
            sys.exit(f"{', '.join(down)} is not answering (gnoc models machines)")
        picked = want
    elif on == "all":
        picked = [n for n in up if places[n]["rank"] < 8]
    elif on == "best":
        picked = [best] if best else []
    elif len(up) < 2 or (on is None and not tty):
        picked = ["local"] if "local" in up or on is None else up[:1]
        if on is None and len(up) > 1:
            print("downloading to this computer (other machines answer too: --on " + " | --on ".join(
                n for n in up if n != "local") + " | --on best)")
    else:
        print(f"{repo}" + (f":{quant}" if quant else "") + ": where should it go?")
        for i, r in enumerate(rows, 1):
            print(_machine_line(i, r, places[r["name"]], "<- best fit" if r["name"] == best else ""))
        default = best or "local"
        said = (ask or input)(f"download to [{default}]  (a number or name, several with commas, all, q to stop): "
                              ).strip().lower()
        if said in ("q", "quit", "n", "no"):
            sys.exit("nothing downloaded")
        picked = []
        for w in ([default] if not said else up if said == "all" else [x.strip() for x in said.split(",")]):
            w = rows[int(w) - 1]["name"] if w.isdigit() and 0 < int(w) <= len(rows) else w
            if w not in up:
                sys.exit(f"{w!r} is not a machine that answers; nothing downloaded")
            if w not in picked:
                picked.append(w)
    if not picked:
        sys.exit("no machine can take it: none answers, or none has the disk space (gnoc models machines)")
    for n in picked:
        if places[n]["rank"] == 8:
            sys.exit(f"{n} has {places[n]['word']} and {repo}:{places[n]['quant']} is {gb(places[n]['size'])}; "
                     "nothing downloaded")
    return repo, by, [(n, places[n]["quant"]) for n in picked]
DEFAULT_ROLES = {"brain": "qwen3:8b", "chat": "qwen3:8b", "hunter": "qwen3:8b",
                 "lead": "qwen3:8b",
                 "worker": "qwen3:8b"}


def roles():
    try:
        return dict(DEFAULT_ROLES, **json.load(open(ROLES)))
    except (OSError, ValueError):
        return dict(DEFAULT_ROLES)


def _file_roles():
    try:
        with open(ROLES) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_roles(r):
    """Atomic (chats re-read models.json on every call and a plain "w" open let them read it half-written), and only
    what was set: writing every DEFAULT_ROLES entry made defaults look configured."""
    os.makedirs(ORCH, exist_ok=True)
    tmp = f"{ROLES}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(r, f, indent=1)
    os.replace(tmp, ROLES)


def api(path, body=None, timeout=30):
    req = urllib.request.Request(f"http://{HOST}{path}", data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def installed():
    return {m["name"]: m for m in api("/api/tags").get("models", [])}


def hf(path):
    req = urllib.request.Request("https://huggingface.co" + path, headers={"User-Agent": "gnoc-models"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def gb(n):
    return f"{n / 1e9:.1f} GB"


def fit(size):
    g, v = size / 1e9, vram()
    return "fits GPU" if g <= v - 1.2 else ("partly offloaded (slower)" if g <= v * 1.5 else "too big (very slow)")


def cmd_list():
    try:
        ms = installed()
    except Exception as e:
        sys.exit(f"the model server on {HOST} is not answering ({e}); gnoc engine start  (or gnoc svc restart ollama-oc)")
    r = roles()
    print(f"models on the {ON} model server ({HOST}), GPU {vram():.0f} GB")
    tag = "" if ON == "local" else "@" + ON
    for name, m in sorted(ms.items()):
        uses = [k for k, v in r.items() if v in (name + tag, name.removesuffix(":latest") + tag)]
        print(f"  {name:<62} {gb(m['size']):>8}  {fit(m['size']):<26} {'<- ' + ', '.join(uses) if uses else ''}")
    for k, v in r.items():
        name, host = v.rsplit("@", 1) if "@" in v else (v, "local")
        if host == ON and name not in ms and name + ":latest" not in ms:
            print(f"  WARNING role {k} points at {v}, which is not installed")
    _other_machines_line()


def _other_machines_line():
    """Under the list: the other machines hooked up, and the commands that say more. Asked "which machines can
    run models, and what is on each?", the chat ran `gnoc models`, saw one machine, and answered for one
    (drive 2026-11-21)."""
    others = [n for n, a in HOSTS.items() if a and n != ON]
    if not others:
        return
    said = []
    for n in others:
        kind = gnoc_engine.who(HOSTS[n], 1)
        said.append(f"{n} ({'answering' if kind else 'not answering'})")
    print(f"other machines: {', '.join(said)}.  All of them: gnoc models machines   one of them: gnoc models --on "
          f"{others[0]}   where a model would go: gnoc models where <owner/repo>")


def cmd_search(words):
    q = urllib.parse.urlencode({"search": " ".join(words), "filter": "gguf", "sort": "downloads", "limit": 20})
    for m in hf(f"/api/models?{q}"):
        print(f"  {m['id']:<70} downloads {m.get('downloads', 0):>9}")
    print("next: gnoc models files <owner/repo>")


def quants(repo):
    out = []
    for f in hf(f"/api/models/{repo}/tree/main?recursive=true"):
        p = f.get("path", "")
        if p.endswith(".gguf") and "mmproj" not in p:
            m = re.search(r"((?:I?Q\d[_A-Z0-9]*)|F16|BF16|F32)(?:-\d+-of-\d+)?\.gguf$", p, re.I)
            out.append((m.group(1).upper() if m else p, f.get("size", 0), p))
    return out


def cmd_files(repo):
    qs = quants(repo)
    if not qs:
        sys.exit(f"no .gguf files in {repo}; only GGUF repos can be pulled (search with gnoc models search)")
    for q, size, p in sorted(qs, key=lambda x: x[1]):
        print(f"  {q:<10} {gb(size):>8}  {fit(size):<26} {p}")
    print(f"next: gnoc models pull {repo}:Q4_K_M")


def cmd_pull(spec, alias=None, on=None, ask=None):
    """Download to the machine(s) chosen by --on, by the question, or (one machine, or no terminal) to this one."""
    global ON, HOST
    repo, by, targets = choose_machines(spec, on, ask)
    failed = []
    for name, quant in targets:
        ON, HOST = name, HOSTS[name]
        quant = quant or ("Q4_K_M" if "Q4_K_M" in by else min(by, key=lambda q: by[q][1]))
        try:
            _pull_one(repo, quant, by[quant][1], alias)
        except SystemExit as e:
            if len(targets) == 1:
                raise
            failed.append(name)
            print(f"  {name}: {e}")
    if failed:
        sys.exit(f"downloaded to {len(targets) - len(failed)} of {len(targets)} machines; failed on: "
                 + ", ".join(failed))


def _pull_one(repo, quant, size, alias=None):
    print(f"pulling hf.co/{repo}:{quant} ({gb(size)}, {fit(size)}) into the {ON} model server ({HOST}) ...",
          flush=True)
    src = f"hf.co/{repo}:{quant}"
    try:
        gnoc_engine.remote_pull(HOST, src)
    except gnoc_engine.EngineError as e:
        sys.exit(f"pull failed: {e}")
    name = alias or re.sub(r"(?i)[-_]?gguf$", "", repo.split("/")[1]).lower() + "-oc"
    # 16k context, one slot: the same shape as qwen3-14b-oc so a lane prompt is never silently truncated
    try:
        gnoc_engine.remote_create(HOST, name, src, {"num_ctx": 16384, "temperature": 0.2})
    except gnoc_engine.EngineError as e:
        sys.exit(f"pulled {src}, but creating {name} failed: {e}")
    on = "" if ON == "local" else f" --on {ON}"
    print(f"ready: {name}" + ("" if ON == "local" else f"@{ON}")
          + f"\nnext: gnoc models test {name}{on}   then   gnoc models use brain {name}{on}")


def resolve(model):
    # "name@desktop" is the form every role file and `gnoc models` listing shows, so it is the form people type;
    # it used to be looked up verbatim and rejected as not installed while `--on desktop` worked (2026-10-22).
    name, _, host = str(model or "").partition("@")
    if host and host != ON:
        sys.exit(f"{name} is on {host}, but this command is acting on {ON}: add --on {host}")
    model = name
    ms = installed()
    for cand in (model, model + ":latest"):
        if cand in ms:
            return cand.removesuffix(":latest") if cand.endswith(":latest") else cand
    sys.exit(f"{model} is not installed on {ON} (gnoc models{'' if ON == 'local' else ' --on ' + ON})")


def cmd_use(role, model):
    if role not in DEFAULT_ROLES:
        sys.exit(f"role must be one of {', '.join(DEFAULT_ROLES)}")
    model = resolve(model)
    try:
        import llm_endpoints as _le
        if not _le.allow_stock() and _le.stock(model, ON):
            sys.exit(f"{model} is a stock (censored) model: {role} unchanged (pick an abliterated/uncensored build, "
                     "or set GNOC_ALLOW_STOCK=1)")
    except ImportError:
        pass
    r = _file_roles()
    r[role] = model if ON == "local" else f"{model}@{ON}"
    save_roles(r)
    if role == "hunter" and os.path.isfile(HUNTER_MD):
        pname = "ollamaoc" if ON == "local" else "ollamadesk"
        md = open(HUNTER_MD).read()
        open(HUNTER_MD, "w").write(re.sub(r"(?m)^model: .*$", f"model: {pname}/{model}", md, count=1))
        cfg = json.load(open(OC_CFG))
        provs = cfg.setdefault("provider", {})
        if pname not in provs:  # the desktop provider = a copy of the laptop one pointed at the tunnel
            base = json.loads(json.dumps(provs.get("ollamaoc", {"npm": "@ai-sdk/openai-compatible", "options": {}})))
            base["name"] = "Desktop Ollama (reverse SSH tunnel)"
            base.setdefault("options", {})["baseURL"] = "http://" + HOST + "/v1"
            base["models"] = {}
            provs[pname] = base
        prov = provs[pname].setdefault("models", {})
        prov.setdefault(model, {"name": f"{model} (added by gnoc models)", "limit": {"context": 16384, "output": 4096}})
        with open(OC_CFG, "w") as f:
            json.dump(cfg, f, indent=2)
    _log_change("role", detail=f"{role} -> {r[role]}")
    print(f"{role} -> {r[role]}" + ("  (next orch-bot tick)" if role == "brain" else "")
          + ("  (falls back to the laptop model while the desktop is off)" if ON != "local" else ""))


LAB = os.path.join(WS, "scripts", "model-lab", "lab.py")


def cmd_test(model, n=3):
    model = resolve(model)
    if os.path.isfile(LAB):
        return subprocess.call([sys.executable, LAB, "bench", model, "--suite", "quick"]
                               + ([] if ON == "local" else ["--tag", ON]), env=dict(os.environ, LAB_OLLAMA=HOST))
    sys.path.insert(0, os.path.join(WS, "scripts"))
    import importlib.util
    if importlib.util.find_spec("orch_brain") is None:
        # neither the Model Lab nor orch-bot's brain ships in the public edition: `gnoc models test` died on
        # "No module named 'orch_brain'". The smoke test below needs only the model server it is testing.
        return cmd_test_smoke(model, n)
    return cmd_test_legacy(model, n)


def cmd_test_smoke(model, n=3, timeout=180):
    """n arithmetic questions answered as JSON: does the model load, follow a JSON-only instruction, get a sum right,
    and how long does a short answer take. Scored, like the lab, so two models can be compared on one machine."""
    ok_json = ok_math = 0
    secs = []
    print(f"{model}: quick smoke test on {HOST} ({n} rounds; the full Model Lab is not part of this edition)")
    for i in range(max(1, int(n))):
        a, b = 17 + 13 * i, 29 + 7 * i
        body = {"model": model, "stream": False, "format": "json", "options": {"temperature": 0},
                "messages": [{"role": "user", "content": f'What is {a} + {b}? Reply with only the JSON object '
                                                         f'{{"sum": <the number>}} and nothing else.'}]}
        t = time.time()
        try:
            reply = api("/api/chat", body, timeout=timeout)
            text = str((reply.get("message") or {}).get("content") or "")
            got = json.loads(text)
            ok_json += 1
            right = isinstance(got, dict) and str(got.get("sum")).strip() == str(a + b)
            ok_math += right
            verdict = "PASS" if right else f"WRONG ({text.strip()[:60]})"
        except ValueError as e:
            verdict = f"NOT JSON ({str(e)[:60]})"
        except Exception as e:  # noqa: BLE001 - a dead server or a timeout is a result, not a crash
            verdict = f"FAILED ({type(e).__name__}: {str(e)[:80]})"
        secs.append(time.time() - t)
        print(f"  {i + 1}: {secs[-1]:5.1f}s  {verdict}")
    rounds = len(secs)
    score = round(100 * (ok_json + ok_math) / (2 * rounds))
    print(f"{model}: json {ok_json}/{rounds}, correct {ok_math}/{rounds}, {sum(secs) / rounds:.1f}s per answer, "
          f"score {score}/100")
    return 0 if ok_json == rounds and ok_math == rounds else 1


def cmd_test_legacy(model, n=3):
    sys.path.insert(0, os.path.join(WS, "scripts"))
    import orch_brain as b
    b.MODEL = model
    snap, prog = b.snapshot({})
    ok_json = ok_pre = 0
    secs = []
    for i in range(n):
        t = time.time()
        try:
            d = b.ask(snap)
            ok_json += 1
            err = b.precheck(d, prog)
            ok_pre += not err
            print(f"  {i + 1}: {time.time() - t:5.0f}s  {d.get('action')!s:<15} {'PASS' if not err else 'REJECT ' + err[:80]}")
            print(f"       why: {str(d.get('reason', ''))[:160]}")
        except Exception as e:
            print(f"  {i + 1}: {time.time() - t:5.0f}s  INVALID ({str(e)[:100]})")
        secs.append(time.time() - t)
    print(f"{model}: json {ok_json}/{n}, precheck {ok_pre}/{n}, {sum(secs) / len(secs):.0f}s per decision"
          + ("" if prog else "   (no focus program, so sweep choices were not exercised)"))
    print("good enough for the brain: json n/n and precheck at least n-1, under ~120 s")


def cmd_rm(model):
    model = resolve(model)
    used = [k for k, v in roles().items() if v == (model if ON == "local" else f"{model}@{ON}")]
    if used:
        sys.exit(f"{model} is the {', '.join(used)} model; gnoc models use <role> <other> first")
    why = ""
    try:
        gnoc_engine.remote_delete(HOST, model)
    except gnoc_engine.EngineError as e:
        why = str(e)
    ms = installed()
    if why or model in ms or model + ":latest" in ms:   # a failed rm used to exit 0 silently and leave the model
        sys.exit(f"{model} was NOT removed ({why or 'the server still lists it'})")
    print(f"removed {model}")


def cmd_json():
    """structured status for the control panel (scripts/control-panel/server.py): one JSON object."""
    out = {"host": ON, "addr": HOST, "vram_gb": vram()}
    if ON == "desktop":
        try:
            out["version"] = api("/api/version", timeout=3).get("version")
            out["loaded"] = [{"name": m["name"], "size_vram_gb": round(m.get("size_vram", 0) / 1e9, 2)}
                              for m in api("/api/ps").get("models", [])]
            out["linked"] = True
        except Exception as e:
            out.update(linked=False, error=str(e)[:200])
            print(json.dumps(out))
            return 0
    else:
        out["linked"] = True
    try:
        ms = installed()
    except Exception as e:
        out["error"] = str(e)[:200]
        print(json.dumps(out))
        return 1
    r = roles()
    tag = "" if ON == "local" else "@" + ON
    out["models"] = [{"name": name, "size_gb": round(m["size"] / 1e9, 2), "fit": fit(m["size"]),
                       "roles": [k for k, v in r.items() if v in (name + tag, name.removesuffix(":latest") + tag)]}
                      for name, m in sorted(ms.items())]
    out["roles"] = r
    print(json.dumps(out))
    return 0


def cmd_desktop(rest):
    if rest[:1] == ["vram"] and len(rest) == 2:
        json.dump({"vram_gb": float(rest[1])}, open(DESKTOP_CFG, "w"))
        _log_change("vram", detail=f"desktop GPU recorded as {float(rest[1]):.0f} GB")
        print(f"desktop GPU recorded as {float(rest[1]):.0f} GB")
        return 0
    global ON, HOST
    ON, HOST = "desktop", HOSTS["desktop"]
    if not HOST:
        print("no second machine is set up. To use another computer's GPU: install Ollama there, make it listen on the "
              "network (OLLAMA_HOST=0.0.0.0, then restart Ollama), and start gnoc here with\n"
              "  GNOC_DESKTOP_OLLAMA=<that computer's address>:11434 gnoc\n"
              "Then: /model <model>@desktop in the chat, or gnoc models --on desktop use lead <model>.")
        return 1
    try:
        v = api("/api/version", timeout=3).get("version")
    except Exception:
        script = os.path.join(WS, "scripts/desktop-link/link-desktop.ps1")
        print(f"desktop NOT linked: nothing answers on {HOST}."
              + (f"\n  On the desktop run (PowerShell): powershell -ExecutionPolicy Bypass -File link-desktop.ps1 "
                 f"-Laptop <this laptop's LAN IP>\n  The script is {script}" if os.path.isfile(script) else
                 "\n  Check that the other computer is on, Ollama is running there and listening on the network "
                 "(OLLAMA_HOST=0.0.0.0), and that its firewall allows port 11434 from this computer."))
        return 1
    print(f"desktop LINKED: Ollama {v} via {HOST}")
    for m in api("/api/ps").get("models", []):
        print(f"  loaded {m['name']}  {gb(m.get('size', 0))} total, {gb(m.get('size_vram', 0))} in VRAM")
    cmd_list()
    return 0


def main(a):
    global ON, HOST
    pull_on = None
    if "--on" in a:
        i = a.index("--on")
        want = a[i + 1] if i + 1 < len(a) else ""
        a = a[:i] + a[i + 2:]
        if a[:1] == ["pull"]:
            pull_on, want = want, "local"      # pull takes several machines, all, best, ask: it resolves them
        if want not in HOSTS or not HOSTS[want]:
            sys.exit(f"--on takes one of: {', '.join(k for k, v in HOSTS.items() if v)}")
        ON, HOST = want, HOSTS[want]
        if ON != "local":
            try:
                api("/api/version", timeout=3)
            except Exception:
                sys.exit(f"the {ON} Ollama is not reachable on {HOST} (gnoc models desktop explains how to link it)")
    if a[:1] == ["desktop"]:
        return cmd_desktop(a[1:])
    if not a or a[0] in ("list", "ls"):
        return cmd_list()
    c, rest = a[0], a[1:]
    if c in ("-h", "--help", "help"):
        print(__doc__)
    elif c == "json":
        return cmd_json()
    elif c == "search" and rest:
        cmd_search(rest)
    elif c == "files" and rest:
        cmd_files(rest[0])
    elif c == "pull" and rest:
        cmd_pull(rest[0], rest[rest.index("--as") + 1] if "--as" in rest and rest.index("--as") + 1 < len(rest) else None,
                 on=pull_on)
    elif c == "machines":
        return cmd_machines()
    elif c == "where" and rest:
        return cmd_where(rest[0])
    elif c == "use" and len(rest) == 2:
        cmd_use(*rest)
    elif c == "test" and rest:
        return cmd_test(rest[0], int(rest[1]) if len(rest) > 1 and rest[1].isdigit() else 3)
    elif c == "rm" and rest:
        cmd_rm(rest[0])
    else:
        print(__doc__)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
