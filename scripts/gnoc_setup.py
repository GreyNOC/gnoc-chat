"""gnoc_setup.py - the guided first-run setup: get gnoc a model it can talk to.

gnoc needs one working model. A fresh install has none, and used to say so only as a raw
`URLError: Connection refused` after eight seconds of retries. This module answers two questions:

    usable(lead_spec, worker_spec)   -> (True, how) when a configured role can answer right now
    run(...)                         the interactive walk-through, step by step, each step checked

The walk-through offers a model on this computer (gnoc's own engine, scripts/gnoc_engine.py: fetch llama.cpp,
start it, pick or download a model sized to this machine, test it; an Ollama that is already running is used as
it is) or a cloud model (paste an API key, checked with one live call), or "not now". It runs
automatically at the start of an interactive chat ONLY when no configured model works, and again any time with
`/setup` in the chat or `gnoc setup` in a shell. Nothing is installed, started or downloaded without a yes.
"""
from __future__ import annotations

import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import gnoc_engine
import gnoc_platform
import llm_endpoints

STATE = os.path.join(llm_endpoints.WS, ".claude/state/orch/setup.json")
ROLES = ("lead", "worker")

# (model, download size) by machine size. qwen3 models handle tool calls, which gnoc's agent needs.
TIERS = (("qwen3:14b", "9.3 GB", "a GPU with 12 GB or more, or a Mac with 24 GB or more"),
         ("qwen3:8b", "5.2 GB", "8 GB of memory or more"),
         ("qwen3:4b", "2.6 GB", "a smaller machine"))


# ------------------------------------------------------------------ what works now
def _tags(host, timeout=3):
    try:
        with urllib.request.urlopen(f"http://{llm_endpoints.HOSTS[host]}/api/tags", timeout=timeout) as r:
            return [m.get("name") for m in json.load(r).get("models") or [] if m.get("name")]
    except Exception:  # noqa: BLE001 - an unreachable host has no models
        return []


def _has(models, name):
    return name in models or f"{name}:latest" in models


def _wake_engine():
    """Start gnoc's engine when this install uses it and it is not running (after a reboot, say). True when it
    answers afterwards."""
    if not gnoc_engine.ensure():
        return False
    llm_endpoints._health.pop("local", None)
    return llm_endpoints.up("local")


def _phone_link():
    """Put the USB link to a set-up phone back (a replug or a reboot drops it). In the background: a chat never
    waits for a phone."""
    try:
        import gnoc_phone
        gnoc_phone.ensure()
    except Exception:  # noqa: BLE001 - no phone support in this copy, or no adb: nothing to restore
        pass


def usable(lead_spec, worker_spec):
    """(True, 'lead qwen3:8b on this computer') when a role can answer now, else (False, why) in words a new user
    understands. Cheap: a refused port answers at once, and up() caches its verdict. A role nobody configured
    (the built-in default) is tried but never named in the reason: a new user has no "desktop" to fix."""
    configured = llm_endpoints.roles()
    _phone_link()
    why = []
    for role, spec in zip(ROLES, (lead_spec, worker_spec)):
        name, host = llm_endpoints.split(spec)
        mine = bool(configured.get(role))
        if llm_endpoints.is_cloud(host):
            try:
                import gnoc_cloud
                if gnoc_cloud.key_for(host) or gnoc_cloud.keyless(host):
                    return True, f"{role} {name} on {host}"
            except Exception:  # noqa: BLE001
                pass
            why.append(f"there is no {host} API key")
            continue
        if host not in llm_endpoints.HOSTS:
            if mine:
                why.append(f"the {role} is set to an unknown machine ({host})")
            continue
        if not llm_endpoints.up(host) and not (host == "local" and _wake_engine()):
            if host == "local":
                why.append("no model server is running on this computer (gnoc looks for one at "
                           f"{llm_endpoints.HOSTS[host]})")
            elif mine:
                why.append(f"the {role}'s machine ({host}, {llm_endpoints.HOSTS[host]}) does not answer")
            continue
        if _has(_tags(host), name):
            return True, f"{role} {name} on {'this computer' if host == 'local' else host}"
        if host == "local" or mine:
            why.append(f"the model gnoc is set to use ({name}) is not downloaded"
                       + ("" if host == "local" else f" on {host}"))
    return False, "; ".join(dict.fromkeys(why)) or "no model is set up"


def skipped_recently(days=1.0):
    try:
        with open(STATE) as f:
            return time.time() - float(json.load(f).get("skipped", 0)) < days * 86400
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def engine_hint():
    """One line, shown at most three times, for a PUBLIC install whose models run on an Ollama: gnoc's own engine
    is there, and /setup moves this install to it with its models. '' otherwise (and always on the operator's
    build). Costs one local request, only when the local server answers at all."""
    try:   # an NVIDIA card driven by the Vulkan build: on WSL that ran on the CPU (llvmpipe) at 0% GPU
        if gnoc_engine.enabled() and "vulkan" in str(gnoc_engine.build_info().get("variant") or "") \
                and sys.platform.startswith("linux") and gnoc_engine.gpu()[0] == "nvidia":
            return ("your NVIDIA card is not used by the engine's Vulkan build. Switch to the CUDA build (about 800 "
                    "MB, once):  gnoc engine install --variant cuda-12.8  then  gnoc engine restart")
    except Exception:  # noqa: BLE001
        pass
    try:
        if os.environ.get("GNOC_ENGINE_HINT", "").strip() == "0":   # a machine that runs Ollama on purpose
            return ""
        with open(STATE) as f:
            d = json.load(f)
        shown = int((d if isinstance(d, dict) else {}).get("engine_hint", 0))
    except (OSError, ValueError, TypeError, ImportError):
        shown = 0
    if shown >= 3 or not llm_endpoints.sniff("local", 0.4):
        return ""
    try:
        if gnoc_engine.who(llm_endpoints.HOSTS["local"], timeout=1) != "ollama":
            return ""
    except Exception:  # noqa: BLE001
        return ""
    _remember(engine_hint=shown + 1)
    return ("models run on Ollama here; gnoc's own engine is faster to set up and sized by gnoc: /setup moves "
            "this install to it (Ollama's models come along, no second copy)")


def _remember(**kv):
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        try:
            with open(STATE) as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        d = d if isinstance(d, dict) else {}
        d.update(kv)
        with open(STATE + ".tmp", "w") as f:
            json.dump(d, f)
        os.replace(STATE + ".tmp", STATE)
    except OSError:
        pass


# ------------------------------------------------------------------ the hunt harness's workspace
# The folders the harness scripts expect to exist (hunt-state.py, gnoc_line.py, intake.sh, reports.sh, the scope-gate
# hook, the hunt-loop lock). Each creates what it writes, but a reader (reports.sh status, scope-gate's program lookup,
# the line's ledgers) on a fresh install found nothing and said so confusingly. The launcher runs the same steps in
# sh on every start; `gnoc setup` runs this.
SKELETON = ("targets", "reports/drafts", "reports/submitted", "reports/archive", "reports/leads",
            ".claude/state/hunt-loop", ".claude/state/do-not-rehunt", ".claude/state/learning",
            ".claude/state/economy", ".claude/state/orch")


HOOKS_MARKER = ".gnoc-shipped"   # inside a .claude/hooks this module filled: "<app folder> <release version>"


def _shipped_stamp(app):
    try:
        with open(os.path.join(app, "VERSION"), encoding="utf-8") as fh:
            version = fh.read().strip()
    except OSError:
        version = "unversioned"
    return f"{app} {version}"


def ensure_workspace(ws=None, app=None, have_jq=None):
    """Create the hunt harness's folders in the workspace and install its hooks. Idempotent; returns what it did.

    The hooks a release ships (<app>/harness/hooks) are COPIED into <ws>/.claude/hooks, with a marker file naming the
    release they came from, and refreshed when that release changes (`gnoc update`). Never a symlink: the agent's
    write guard refuses .claude/hooks/ by path, and a link made a write there land in harness/hooks, which it did not
    refuse (release test run, 2026-11-27). A .claude/hooks without the marker (the operator's own) is never touched.
    The scope-gate hook needs jq: it exits 0 (allow) without it, while gnoc's own fallback for a workspace with no hook
    refuses what it cannot check. So the hooks are installed only when jq is on PATH, and removed again (ours only)
    when jq is gone, never loosening the gate."""
    ws = os.path.abspath(ws or os.environ.get("GNOC_WORKSPACE") or llm_endpoints.WS)
    app = os.path.abspath(app or os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    have_jq = bool(shutil.which("jq")) if have_jq is None else have_jq
    done = []
    for d in SKELETON:
        p = os.path.join(ws, d)
        if not os.path.isdir(p):
            try:
                os.makedirs(p, exist_ok=True)
                done.append(f"made {d}/")
            except OSError as e:
                done.append(f"could not make {d}/ ({e.strerror})")
    src = os.path.join(app, "harness", "hooks")
    dst = os.path.join(ws, ".claude", "hooks")
    marker = os.path.join(dst, HOOKS_MARKER)
    if not os.path.isdir(src):
        return done
    try:
        if os.path.islink(dst):
            if not os.readlink(dst).replace("\\", "/").rstrip("/").endswith("harness/hooks"):
                return done                  # a link of the user's own
            os.unlink(dst)                   # the layout of an earlier build of this function
        ours = os.path.isfile(marker)
        if os.path.exists(dst) and not ours:
            return done                      # a real hooks folder that is not ours
        if not have_jq:
            if ours:
                shutil.rmtree(dst)
                done.append("removed .claude/hooks (jq is missing; gnoc checks bash scope itself)")
            return done
        stamp = _shipped_stamp(app)
        if ours:
            with open(marker, encoding="utf-8") as fh:
                if fh.read().strip() == stamp:
                    return done
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(stamp + "\n")
        done.append(f"installed .claude/hooks from {src}")
    except OSError as e:
        done.append(f"could not install .claude/hooks ({e.strerror})")
    return done


# ------------------------------------------------------------------ this machine
def machine():
    """{'os', 'ram_gb', 'vram_gb', 'apple'}: enough to pick a model that fits."""
    ram = 0.0
    try:
        ram = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2 ** 30
    except (ValueError, OSError, AttributeError):
        pass
    vram = 0.0
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                                 capture_output=True, text=True, timeout=10).stdout
            vram = max((float(x) for x in out.split() if x.replace(".", "", 1).isdigit()), default=0.0) / 1024
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
    if not vram:
        # an AMD or Intel card (no nvidia-smi): the engine reads it from sysfs, and it decides the build anyway
        try:
            vram = round(float(gnoc_engine.gpu()[1] or 0) / 2 ** 30, 1)
        except Exception:  # noqa: BLE001
            vram = 0.0
    if gnoc_platform.is_termux():
        # a phone: llama.cpp's Android build runs on the CPU only, so whatever GPU sysfs reports is not usable
        return {"os": "termux", "ram_gb": round(ram, 1), "vram_gb": 0.0, "apple": False, "termux": True}
    system = platform.system()
    wsl = system == "Linux" and "microsoft" in platform.release().lower()
    return {"os": "wsl" if wsl else system.lower(), "ram_gb": round(ram, 1), "vram_gb": round(vram, 1),
            "apple": system == "Darwin" and platform.machine() == "arm64"}


def phone_tier(ram_gb):
    """(model, size, why) for a phone of this much memory: gnoc_phone's tiers, the sizes measured on a real phone
    (a 4B at about 7 tokens a second on 11 GB). Never a desktop tier: an 8B on a phone CPU takes minutes per
    answer and Android kills Termux when memory runs out."""
    import gnoc_phone
    for least, model, size in gnoc_phone.TIERS:
        if ram_gb >= least:
            return model, size, f"a phone with {ram_gb:g} GB of memory (it runs on the phone's CPU)"
    least, model, size = gnoc_phone.TIERS[-1]
    return model, size, "a phone (it runs on the phone's CPU)"


def recommend(m):
    """(model, size, why) for this machine. A private build that runs uncensored models only gets the default
    uncensored worker instead."""
    if not llm_endpoints.allow_stock():
        return ("hf.co/bartowski/mlabonne_Qwen3-8B-abliterated-GGUF:Q4_K_M", "5.0 GB",
                "this build runs uncensored models only")
    if m.get("termux"):
        return phone_tier(m["ram_gb"])
    if m["vram_gb"] >= 12 or (m["apple"] and m["ram_gb"] >= 24):
        return TIERS[0]
    if not m["vram_gb"] and not m["apple"] and m["ram_gb"]:
        # no GPU: every token is CPU time, and the 4B answers in seconds where the 8B takes a minute
        return (TIERS[2][0], TIERS[2][1], "a computer with no graphics card (it answers fastest on the CPU)")
    if m["ram_gb"] >= 8 or m["vram_gb"] >= 6 or not m["ram_gb"]:
        return TIERS[1]
    return TIERS[2]


_NOT_CHAT = re.compile(r"(?i)embed|nomic|bge-|minilm|llava|vl[:\d]|-vl\b|vision|moondream|whisper")
_BIG = re.compile(r"(?i)\b(?:3[0-9]|[4-9][0-9]|[1-9][0-9]{2})b\b|-(?:3[0-9]|[4-9][0-9])b-")


# ------------------------------------------------------------------ the walk-through
class Io:
    """Terminal I/O, swappable in tests."""

    def __init__(self, ask=input, say=print, secret=getpass.getpass, run=subprocess.run, popen=subprocess.Popen,
                 sleep=time.sleep, engine=gnoc_engine):
        self.ask, self.say, self.secret, self.run, self.popen, self.sleep = ask, say, secret, run, popen, sleep
        self.engine = engine   # the local model server's install/start/pull calls

    def choose(self, prompt, n, default=1):
        while True:
            try:
                a = self.ask(f"{prompt} [{default}] > ").strip()
            except (EOFError, OSError):   # no terminal to read from: stop, never crash
                return None
            if not a:
                return default
            if a.isdigit() and 1 <= int(a) <= n:
                return int(a)
            if a.lower() in ("q", "quit", "exit", "n", "no"):
                return None
            self.say(f"  type a number from 1 to {n}, or q to stop")

    def yes(self, prompt, default=True):
        try:
            a = self.ask(f"{prompt} [{'Y/n' if default else 'y/N'}] > ").strip().lower()
        except (EOFError, OSError):   # no terminal to read from: stop, never crash
            return False
        return default if not a else a in ("y", "yes")


def _step(io, n, total, text):
    io.say(f"\n  step {n} of {total}: {text}")


def _wait_up(io, seconds=20):
    llm_endpoints._health.pop("local", None)
    for _ in range(int(seconds * 2)):
        if llm_endpoints.sniff("local", 0.5):
            llm_endpoints._health.pop("local", None)
            return True
        io.sleep(0.5)
    return False


def _get_llama(io):
    """llama.cpp's server program, downloaded after a yes when it is missing. True when it is there."""
    E = io.engine
    if E.server_path():
        return True
    cuda = getattr(E, "pick_variant", lambda: "")() == getattr(E, "CUDA_VARIANT", None)
    io.say(f"  It needs llama.cpp's server program from github.com/{E.LLAMA_REPO}, checked against its published "
           f"checksum and kept in {E.HOME}: " + ("the CUDA build for your NVIDIA card, about 800 MB with its CUDA "
                                                  "libraries (a one-time download)." if cuda else "about 40 MB."))
    if not io.yes("  Download it now?", default=True):
        io.say("  Get it any time with  gnoc engine install  and run /setup again.")
        return False
    try:
        got = E.install()
    except E.EngineError as e:
        io.say(f"  The download did not finish ({e}). Try  gnoc engine install  yourself, then /setup again.")
        return False
    io.say(f"  ✓ llama.cpp {got['tag']} is installed")
    return True


def _engine_beside_ollama(io):
    """An Ollama already holds the default address: run gnoc's engine on its own port, adopt the models Ollama
    downloaded (hard links, no second copy) and point gnoc at the engine. The user 2026-11-22: "make sure the new
    installs are using the gnoc model engine" (a WSL install with Ollama stalled on a stock-model rule). Any
    failure leaves gnoc on the Ollama that already works."""
    E = io.engine
    old = llm_endpoints.HOSTS["local"]
    if not _get_llama(io):
        return False
    llm_endpoints.HOSTS["local"] = llm_endpoints.ENGINE_BESIDE_OLLAMA
    st, detail = E.start()
    if st not in ("started", "running") or not _wait_up(io):
        llm_endpoints.HOSTS["local"] = old
        io.say(f"  The engine did not come up at {llm_endpoints.ENGINE_BESIDE_OLLAMA}"
               + (f": {detail}" if st == "failed" else "") + f". gnoc stays on Ollama ({old}).")
        return False
    got = []
    try:
        got = E.import_ollama(progress=lambda d: io.say("    " + str(d.get("status") or ""))) or []
    except Exception as e:  # noqa: BLE001 - a model that will not come over is pulled fresh in the next step
        io.say(f"  Ollama's models did not come over ({type(e).__name__}); the next step downloads one.")
    llm_endpoints.save_host("local", llm_endpoints.ENGINE_BESIDE_OLLAMA)
    E.enable(True)   # from now on gnoc starts it by itself whenever it is not running
    io.say(f"  ✓ gnoc's engine is running ({llm_endpoints.ENGINE_BESIDE_OLLAMA})"
           + (f", with {len(got)} model(s) from Ollama" if got else "")
           + f". Ollama keeps running on {old} for anything else that uses it.")
    return True


def _start_engine(io):
    """Step 1: something to run a model on this computer: gnoc's own engine. One that already answers is used; an
    Ollama on the default address is offered the engine beside it (yes by default, its models come along); with
    nothing running, the engine is fetched and started. Each step after a yes."""
    E, at = io.engine, llm_endpoints.HOSTS["local"]
    if llm_endpoints.sniff("local", 0.6):
        if E.who(at) != "ollama":
            io.say(f"  ✓ the engine is running ({at})")
            return True
        io.say(f"  An Ollama is running here ({at}). gnoc runs best on its own engine (llama.cpp underneath): the "
               "same models, started and sized by gnoc, nothing you type leaves this machine.")
        if io.yes("  Set up gnoc's engine beside Ollama and bring over the models Ollama already downloaded "
                  "(no second copy)?", default=True) and _engine_beside_ollama(io):
            return True
        io.say(f"  ✓ using Ollama ({llm_endpoints.HOSTS['local']})")
        return True
    io.say("  gnoc runs models on this computer with its own engine (llama.cpp underneath). It is free, needs no "
           "administrator password, and nothing you type leaves this machine.")
    if not _get_llama(io):
        return False
    if not io.yes("  Start the engine now in the background?", default=True):
        io.say("  Start it yourself with  gnoc engine start  and run /setup again.")
        return False
    st, detail = E.start()
    if st in ("started", "running") and _wait_up(io):
        E.enable(True)   # from now on gnoc starts it by itself whenever it is not running
        io.say(f"  ✓ the engine is running ({at})")
        return True
    io.say(f"  The engine did not come up at {at}" + (f": {detail}" if st == "failed" else "")
           + ". If your model server is elsewhere, set GNOC_LOCAL_OLLAMA=host:port and start gnoc again.")
    return False


def _pick_model(io, m):
    have = _tags("local")
    rec, size, why = recommend(m)
    io.say(f"  This computer: {m['ram_gb']:g} GB memory" + (f", a {m['vram_gb']:g} GB GPU" if m["vram_gb"] else "")
           + (", Apple silicon" if m["apple"] else ""))
    have = [n for n in have if not _NOT_CHAT.search(n)][:12]   # embedding and vision-only models cannot drive it
    if have:
        io.say("  Models already downloaded:")
        for i, n in enumerate(have, 1):
            io.say(f"    {i}) {n}")
        io.say(f"    {len(have) + 1}) download {rec} instead ({size}, suggested for {why})")
        # the default: an installed Qwen3 (they handle tool calls) or the suggested download, never a 35B by accident
        default = next((i for i, n in enumerate(have, 1) if n.split(":")[0] == rec.split(":")[0]), None) or \
            next((i for i, n in enumerate(have, 1) if "qwen3" in n.lower() and not _BIG.search(n)), len(have) + 1)
        c = io.choose("  Which one should gnoc use?", len(have) + 1, default)
        if c is None:
            return None
        if c <= len(have):
            return have[c - 1]
    else:
        io.say(f"  Suggested for {why}: {rec} ({size} download).")
    if not io.yes(f"  Download {rec} now ({size}; it shows progress and can take a while)?", default=True):
        io.say(f"  Download it yourself with  gnoc engine pull {rec}  and run /setup again.")
        return None
    err = ""
    try:   # one HTTP call that the engine and an Ollama both answer: either downloads the model itself
        io.engine.remote_pull(llm_endpoints.HOSTS["local"], rec)
    except io.engine.EngineError as e:
        err = f" ({e})"
    if err or not _has(_tags("local"), rec):
        io.say(f"  The download did not finish{err}. Run /setup again to resume it where it stopped.")
        return None
    io.say(f"  ✓ {rec} is downloaded")
    return rec


def _test_local(io, model):
    io.say(f"  Loading {model} for a first test (the first load takes the longest)...")
    body = json.dumps({"model": model, "stream": False, "think": False, "options": {"num_predict": 8},
                       "messages": [{"role": "user", "content": "Reply with the single word: ready"}]}).encode()
    try:
        req = urllib.request.Request(f"http://{llm_endpoints.HOSTS['local']}/api/chat", body,
                                     {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            ok = r.status == 200
    except Exception as e:  # noqa: BLE001
        io.say(f"  The test call failed ({type(e).__name__}: {str(e)[:120]}). gnoc is set to use {model}; if the "
               "next message fails too, check that this computer has enough memory for it.")
        return False
    io.say("  ✓ the model answered" if ok else "  the model did not answer cleanly")
    return ok


def _local_path(io, set_role):
    m = machine()
    total = 3
    _step(io, 1, total, "the model engine")
    if not _start_engine(io):
        return False
    _step(io, 2, total, "pick a model")
    model = _pick_model(io, m)
    if not model:
        return False
    _step(io, 3, total, "use it and test it")
    for role in ROLES:
        err = set_role(role, model)
        if err:
            io.say(f"  could not set {role}: {err}")
            return False
    io.say(f"  ✓ gnoc's lead and worker now use {model} on this computer")
    _test_local(io, model)
    return True


REMOTE_HELP = ("  On the other computer, gnoc's engine is all it needs (no Ollama): install gnoc chat there, or only the\n"
               "  engine (the gnoc-engine download), then run\n"
               "      gnoc-engine install      llama.cpp for its GPU (the CUDA build on an NVIDIA card)\n"
               "      gnoc-engine share on     serve this computer behind a key, start at boot, stay current\n"
               "  It prints a line like  gnoc pair 192.168.1.20:11434 <key>: paste that line here, or type the\n"
               "  address and then the key. Let its port through its firewall from this computer only.\n"
               "  (An Ollama there works too: make it listen on the network and leave the key empty.)")


def _remote_version(addr, timeout=4):
    """(kind, version) of the model server at addr: ('gnoc' | 'ollama' | 'locked' | '', text)."""
    try:
        with urllib.request.urlopen(f"http://{addr}/api/version", timeout=timeout) as r:
            d = json.load(r)
        return ("gnoc" if d.get("engine") == "gnoc" else "ollama"), str(d.get("version") or "?")
    except urllib.error.HTTPError as e:
        return ("locked" if e.code in (401, 403) else ""), ""
    except Exception:  # noqa: BLE001
        return "", ""


def _norm_addr(addr):
    addr = llm_endpoints._hostport(addr)
    if not re.fullmatch(r"[A-Za-z0-9.\-\[\]:]{1,100}", addr or ""):
        return ""
    if ":" not in addr.strip("[]") or addr.endswith("]"):
        addr += ":11434"
    return addr


def pair(addr, key=""):
    """Pair this gnoc with a model server on another computer: save its key (owner-only) and its address as the
    other computer, check it answers. -> (ok, message, [its chat models])."""
    addr = _norm_addr(addr)
    if not addr:
        return False, "that does not look like an address (e.g. 192.168.1.20:11434)", []
    llm_endpoints.save_host_key(addr, key or "")
    kind, v = _remote_version(addr)
    if kind == "locked":
        return False, f"{addr} answers but refused the key: copy the line gnoc-engine share on printed there", []
    if not kind:
        return False, (f"nothing answers at {addr}: is that computer on, is `gnoc-engine share on` done there, and "
                       "does its firewall let this computer through on that port?"), []
    llm_endpoints.save_host("desktop", addr)
    try:
        with urllib.request.urlopen(f"http://{addr}/api/tags", timeout=6) as r:
            have = [m.get("name") for m in json.load(r).get("models") or [] if m.get("name")]
    except Exception:  # noqa: BLE001
        have = []
    have = [n for n in have if not _NOT_CHAT.search(n)]
    what = "gnoc's engine" if kind == "gnoc" else "Ollama"
    return True, f"paired with {what} ({v}) at {addr}" + ("" if key or kind != "gnoc" else " (it has no key set)"), have


def _remote_path(io, set_role):
    """Another computer's model server on the network (gnoc's engine, or an Ollama): pair, pick one of ITS models,
    saved for every start."""
    _step(io, 1, 3, "the other computer")
    io.say(REMOTE_HELP)
    for _ in range(3):
        try:
            line = io.ask("  Its pairing line, or its address (e.g. 192.168.1.20; :11434 is added) > ").strip()
        except (EOFError, OSError):
            return False
        if not line or line.lower() in ("q", "quit"):
            return False
        bits = line.split()
        if bits[:2] == ["gnoc", "pair"]:
            bits = bits[2:]
        addr, key = bits[0], (bits[1] if len(bits) > 1 else "")
        if not key:
            try:
                key = (io.secret("  Its key (Enter when it has none) > ") or "").strip()
            except (EOFError, OSError):
                key = ""
        ok, msg, have = pair(addr, key)
        io.say(("  ✓ " if ok else "  ") + msg)
        if ok:
            addr = _norm_addr(addr)
            break
    else:
        return False
    _step(io, 2, 3, "pick one of its models")
    have = have[:12]
    if not have:
        io.say(f"  it has no chat model yet. Download one onto it from here:  gnoc models pull Qwen/Qwen3-8B-GGUF:Q4_K_M --on desktop  "
               f"(or on that computer: gnoc-engine pull {TIERS[1][0]}), then /setup again.")
        return False
    for i, n in enumerate(have, 1):
        io.say(f"    {i}) {n}")
    c = io.choose("  Which one should gnoc use?", len(have))
    if c is None:
        return False
    model = have[c - 1]
    _step(io, 3, 3, "save it")
    for role in ROLES:
        err = set_role(role, f"{model}@desktop")
        if err:
            io.say(f"  could not set {role}: {err}")
            return False
    io.say(f"  ✓ gnoc's lead and worker now use {model} on {addr} (saved; GNOC_DESKTOP_OLLAMA overrides it). "
           "When that computer is off, gnoc falls back to a model on this one if it has one.")
    return True


def pair_main(argv):
    """gnoc pair <address> [key]: the line `gnoc-engine share on` printed on the other computer."""
    if not argv:
        print("usage: gnoc pair <address[:port]> [key]   (the line gnoc-engine share on printed on the other computer)")
        return 2
    ok, msg, have = pair(argv[0], argv[1] if len(argv) > 1 else "")
    print(("✓ " if ok else "") + msg)
    if ok:
        print(("  its models: " + ", ".join(have[:12])) if have else
              "  it has no chat model yet:  gnoc models pull Qwen/Qwen3-8B-GGUF:Q4_K_M --on desktop")
        print("  use one:  gnoc models use lead <model>@desktop   (or /model in the chat)")
    return 0 if ok else 1


def _cloud_path(io, set_role):
    import gnoc_cloud
    provs = list(gnoc_cloud.providers().items())   # the table's order: Claude first
    _step(io, 1, 2, "pick a provider")
    io.say("  A cloud model is fast and needs no GPU, but your conversation (code, file contents, commands) is sent "
           "to that company on every turn. Known secrets are scrubbed first.")
    for i, (name, row) in enumerate(provs, 1):
        io.say(f"    {i}) {name}  ({row[0]}, model {row[2]})")
    io.say("  Any other OpenAI-compatible service: stop here and use  /cloud add <name> <base-url> <model>  in the chat.")
    c = io.choose("  Which provider?", len(provs))
    if c is None:
        return False
    name, row = provs[c - 1]
    _step(io, 2, 2, f"your {name} API key")
    io.say(f"  Create a key in your {name} account, then paste it here (it is not shown as you type, and it is "
           "stored only on this computer, readable by you alone).")
    for _ in range(3):
        try:
            key = io.secret("  API key > ").strip()
        except (EOFError, OSError):   # no terminal to read from: stop, never crash
            return False
        if not key:
            return False
        ok, msg = gnoc_cloud.save_key(name, key)
        if not ok:
            io.say("  " + msg)
            continue
        io.say("  checking the key with one tiny request...")
        ok, msg = gnoc_cloud.check(name)
        io.say(("  ✓ " if ok else "  ✗ ") + msg)
        if ok:
            for role in ROLES:
                err = set_role(role, f"{row[2]}@{name}")
                if err:
                    io.say(f"  could not set {role}: {err}")
                    return False
            io.say(f"  ✓ gnoc's lead and worker now use {row[2]} on {name}")
            return True
    return False


def _pick_installed(have, rec):
    """The installed chat model to use: the suggested one, else a qwen3 that is not huge, else the first."""
    have = [n for n in have if not _NOT_CHAT.search(n)]
    for n in have:
        if n.split(":")[0] == rec.split(":")[0] and n.split(":")[-1] == rec.split(":")[-1]:
            return n
    return next((n for n in have if "qwen3" in n.lower() and not _BIG.search(n)), None) or \
        next((n for n in have if not _BIG.search(n)), None)


def auto(io, set_role, assume_yes=False):
    """Out of the box (the user 2026-11-23: "detect if ollama is present, if not it should install gnoc engine. We
    want this working out of the box"). Whatever already serves models here is used: an Ollama, or gnoc's engine.
    With nothing, gnoc's engine is set up: llama.cpp for this computer (the CUDA build on an NVIDIA card), started
    and kept starting. Then a model this computer can run is chosen (an installed one first) or downloaded, set
    for both roles and tested. ONE question, yes by default (assume_yes skips it). True when a model answers."""
    E, at = io.engine, llm_endpoints.HOSTS["local"]
    m = machine()
    rec, size, why = recommend(m)
    kind = E.who(at) if llm_endpoints.sniff("local", 0.6) else ""
    if not kind and getattr(E, "enabled", lambda: False)() and E.server_path():
        st, _ = E.start()            # installed before and simply not running (after a reboot)
        kind = "gnoc" if st in ("started", "running") and _wait_up(io) else ""
    have = [n for n in (_tags("local") if kind else []) if not _NOT_CHAT.search(n)]
    pick = _pick_installed(have, rec) if have else None
    need_llama = not kind and not E.server_path()
    cuda = need_llama and getattr(E, "pick_variant", lambda: "")() == getattr(E, "CUDA_VARIANT", None)
    steps = []
    if kind == "ollama":
        io.say(f"  ✓ Ollama is running on this computer ({at}): gnoc uses it.")
    elif kind:
        io.say(f"  ✓ gnoc's engine is running on this computer ({at}).")
    else:
        steps.append("gnoc's own model engine (llama.cpp " + ("CUDA build for your NVIDIA card, about 800 MB"
                                                           if cuda else "for this computer, about 40 MB")
                     + ")" if need_llama else "gnoc's own model engine (already downloaded)")
    if pick:
        io.say(f"  ✓ using {pick}, already on this computer")
    else:
        steps.append(f"the model {rec} ({size}, suited to {why})")
    if steps:
        # (it said "Nothing you type ever leaves this computer", which web search and picture reference lookups
        # contradicted; privacy audit 2026-11-24)
        io.say("  To work out of the box, gnoc will set up: " + "; and ".join(steps) + ". The model runs on this "
               "computer and there is no telemetry; web search and picture lookups are the only things that go "
               "online, and `gnoc privacy local-only on` turns them off too.")
        if not assume_yes and not io.yes("  Go ahead?", default=True):
            return False
    if not kind:
        if need_llama:
            io.say("  downloading llama.cpp...")
            try:
                got = E.install()
            except E.EngineError as e:
                io.say(f"  The download did not finish ({e}). Try again with /setup, or  gnoc engine install.")
                return False
            io.say(f"  ✓ llama.cpp {got['tag']} ({got.get('variant', '')})")
        st, detail = E.start()
        if st not in ("started", "running") or not _wait_up(io):
            io.say(f"  The engine did not come up at {at}" + (f": {detail}" if st == "failed" else "")
                   + ". gnoc engine logs shows why; /setup tries again.")
            return False
        E.enable(True)   # gnoc starts it by itself from now on
        io.say(f"  ✓ gnoc's engine is running ({at}) and starts with gnoc from now on")
    if not pick:
        io.say(f"  downloading {rec} ({size}): this is the long part, and it resumes if it stops...")
        try:
            E.remote_pull(at, rec)
        except E.EngineError as e:
            io.say(f"  The download did not finish ({e}). /setup resumes it where it stopped.")
            return False
        if not _has(_tags("local"), rec):
            io.say("  The model is not there after the download. /setup tries again.")
            return False
        pick = rec
        io.say(f"  ✓ {rec} is downloaded")
    for role in ROLES:
        err = set_role(role, pick)
        if err:
            io.say(f"  could not set {role}: {err}")
            return False
    _test_local(io, pick)
    _remember(done=time.time(), skipped=0, auto=True)
    io.say(f"\n  ✓ ready: gnoc answers with {pick} on this computer. Just type what you want done (/help lists "
           "the commands; /setup picks another model, another computer or a cloud model).\n")
    return True


def first_run(set_role, io=None, reason=""):
    """A chat that starts with no working model: the automatic setup first; a no opens the full menu."""
    io = io or Io()
    if gnoc_platform.is_termux():
        # a phone: the automatic path downloads an engine and a model onto it without showing the desktop and
        # cloud choices, which are the better ones on a phone; show all three instead
        return run(set_role, io, reason=reason)
    io.say("\n  ── gnoc setup ─────────────────────────────────────────────")
    io.say("  gnoc needs an AI model to talk to, and none is ready yet." + (f"\n  ({reason})" if reason else ""))
    try:
        if auto(io, set_role):
            return True
    except KeyboardInterrupt:
        io.say("\n  setup stopped")
        return False
    return run(set_role, io, reason=reason)


def _paired():
    """True when a model server on another computer is already saved (gnoc pair, or GNOC_DESKTOP_OLLAMA)."""
    return bool(llm_endpoints.HOSTS.get("desktop"))


def termux_menu(io, current=""):
    """The choices on a phone, in the order that suits one: no GPU for big models, a CPU that heats up, a battery.
    -> (paths, default choice). The desktop is the default once it is paired (private and fast), the cloud
    otherwise; the on-phone model is offered last and sized by the phone tiers, never a desktop size."""
    rec, size, _why = recommend(machine())
    io.say("    This is Termux on a phone. A phone runs only small models, slowly, so:")
    io.say("    1) the model server on your desktop or another computer (gnoc's engine or Ollama): private, uses "
           "its GPU" + ("  (already paired)" if _paired() else ""))
    io.say("    2) a cloud model with an API key: fast, needs an account, your conversation leaves this phone")
    io.say(f"    3) a small model on this phone ({rec}, {size}): private, slow, and the phone gets warm")
    io.say("    4) " + ("keep the current model" if current else
                        "not now (type /setup in the chat, or run  gnoc setup, any time)"))
    return (_remote_path, _cloud_path, _local_path), (1 if _paired() else 2)


def run(set_role, io=None, reason="", current=""):
    """The walk-through. Returns True when a model was set up. set_role(role, spec) -> error text or None.
    current: what already works ("lead qwen3:8b on this computer"), when /setup is run to change it."""
    io = io or Io()
    io.say("\n  ── gnoc setup ─────────────────────────────────────────────")
    if current:
        io.say(f"  gnoc already has a working model: {current}. This picks a different one.")
    else:
        io.say("  gnoc needs an AI model to talk to, and none is ready yet." + (f"\n  ({reason})" if reason else ""))
        io.say("  This takes a few minutes, once. Nothing is installed or downloaded without asking you.")
    io.say("")
    if gnoc_platform.is_termux():
        paths, default = termux_menu(io, current)
    else:
        io.say("    1) a model on this computer: free and private (recommended)")
        io.say("    2) a model server on ANOTHER computer on your network (a desktop with a bigger GPU; gnoc's engine "
               "or Ollama): private, uses its GPU")
        io.say("    3) a cloud model with an API key: fast, needs an account, your conversation leaves this machine")
        io.say("    4) " + ("keep the current model" if current else
                            "not now (type /setup in the chat, or run  gnoc setup, any time)"))
        paths, default = (_local_path, _remote_path, _cloud_path), 1
    c = io.choose("  Choose", len(paths) + 1, default)
    done = False
    try:
        if c and c <= len(paths):
            done = paths[c - 1](io, set_role)
    except KeyboardInterrupt:
        io.say("\n  setup stopped")
    if done:
        _remember(done=time.time(), skipped=0)
        io.say("\n  ✓ setup finished. Just type what you want done, or /help to see the commands.\n")
    elif current:
        io.say(f"\n  nothing changed: gnoc keeps using {current}\n")
    else:
        _remember(skipped=time.time())
        io.say("\n  No model is set up yet, so messages cannot be answered. Type /setup when you are ready.\n")
    return done


def main(argv=None):
    """`gnoc setup`: the same walk-through from a shell."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    args = list(argv if argv is not None else sys.argv[1:])
    for line in ensure_workspace():
        print(f"  workspace: {line}")
    if "--workspace" in args:   # only the folders and the hooks link, no model check
        return 0
    import gnoc_agent as G
    ok, how = usable(G.role_spec("lead"), G.role_spec("worker"))
    if ok and "--force" not in args:
        print(f"  gnoc is ready: {how}.  (gnoc setup --force picks a different model)")
        return 0
    if "--auto" in args or "--yes" in args or "-y" in args:
        # the installers' last step and scripted installs: no menu; --yes also skips the one question
        return 0 if auto(Io(), G.set_role, assume_yes="--yes" in args or "-y" in args) else 1
    return 0 if run(G.set_role, reason="" if ok else how, current=how if ok else "") else 1


if __name__ == "__main__":
    sys.exit(main())
