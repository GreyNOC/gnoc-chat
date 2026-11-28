"""gnoc_image.py - text-to-image on the desktop GPU through ComfyUI (set up with desktop-link/comfyui-desktop.ps1).

The laptop reaches the desktop's ComfyUI at 127.0.0.1:18188 over the reverse SSH tunnel. The 16 GB card is shared
with the desktop's Ollama, so generate() first unloads every Ollama model there (keep_alive 0), runs one SDXL
workflow, downloads the PNG, and asks ComfyUI to free its VRAM; the chat model reloads on the next message.
    generate(prompt, negative="", width=1024, height=1024, steps=28, cfg=6.5, seed=None, out_dir=None) -> path
Settings: GNOC_COMFY_URL (default http://127.0.0.1:18188), GNOC_COMFY_CKPT (default sd_xl_base_1.0.safetensors).
"""
import contextlib
import json
import os
import random
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

import gnoc_edition  # noqa: F401,E402  (loads this machine's settings before the env reads below)

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
COMFY = os.environ.get("GNOC_COMFY_URL", "http://127.0.0.1:18188")
CKPT = os.environ.get("GNOC_COMFY_CKPT", "sd_xl_base_1.0.safetensors")
DESKTOP_OLLAMA = os.environ.get("GNOC_DESKTOP_DIRECT", "")   # the second machine's Ollama, unproxied (machine.json)
OUT = os.path.join(WS, ".claude/state/orch/images")   # sidecar JSON (prompt, seed, timing): an intermediate
# The picture itself is a deliverable: GreyNOC looks in ~/Downloads, not in a state folder inside the repo
# (his rule of 2026-10-24: every file he asks for lands there by default). The first test run of 2026-10-25
# had the lead inventing out_dir=~/Desktop, then ~/.gnoc, and the PNG landed in the
# repo root. out_dir still overrides.
DELIVER = os.path.expanduser("~/Downloads")
SIZE_MIN, SIZE_MAX = 512, 1536


def clamp_dims(width, height):
    """The size SDXL will really render: 512-1536 a side, multiples of 64. The caller checks the file
    against THIS, not against what was asked for - 1920x1080 renders at 1536x1024 and the sanity check
    used to fail the picture for it (first test run, 2026-10-25)."""
    return tuple(max(SIZE_MIN, min(int(v), SIZE_MAX)) // 64 * 64 for v in (width, height))


def _req(method, url, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        return resp.read()


def up():
    try:
        _req("GET", COMFY + "/system_stats", timeout=5)
        return True
    except Exception:
        return False


def workflow(prompt, negative, width, height, steps, cfg, seed):
    """ComfyUI API-format SDXL graph: checkpoint -> two text encodes -> KSampler -> VAE decode -> save."""
    return {
        "4": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": CKPT}},
        "5": {"class_type": "EmptyLatentImage", "inputs": {"width": width, "height": height, "batch_size": 1}},
        "6": {"class_type": "CLIPTextEncode", "inputs": {"text": prompt, "clip": ["4", 1]}},
        "7": {"class_type": "CLIPTextEncode", "inputs": {"text": negative, "clip": ["4", 1]}},
        "3": {"class_type": "KSampler", "inputs": {"seed": seed, "steps": steps, "cfg": cfg, "sampler_name": "dpmpp_2m",
                                                   "scheduler": "karras", "denoise": 1.0, "model": ["4", 0],
                                                   "positive": ["6", 0], "negative": ["7", 0],
                                                   "latent_image": ["5", 0]}},
        "8": {"class_type": "VAEDecode", "inputs": {"samples": ["3", 0], "vae": ["4", 2]}},
        "9": {"class_type": "SaveImage", "inputs": {"filename_prefix": "gnoc", "images": ["8", 0]}},
    }


LAST_GPU_NOTE = [""]   # what restore_gpu() saw, so the caller can relay it without changing generate()'s shape
# Below this the 14 GB lead model cannot come back to the desktop card and Ollama falls to CPU offload,
# which then fails its pinned-host allocation on a 16 GB machine. Measured 2026-10-25, see restore_gpu.
MIN_FREE_VRAM_GB = 12.0


def _desktop_free():
    """(vram_free_gb, ram_free_gb) from ComfyUI's view of the desktop, or (None, None)."""
    try:
        d = json.loads(_req("GET", COMFY + "/system_stats", timeout=10))
        return (d["devices"][0]["vram_free"] / 2 ** 30, d["system"]["ram_free"] / 2 ** 30)
    except Exception:
        return (None, None)


def _unload_by_name(name, timeout=60):
    _req("POST", DESKTOP_OLLAMA + "/api/generate", {"model": name, "keep_alive": 0}, timeout=timeout)


SITE_REPO = os.path.expanduser("~/gnoc-site")
LOW_DESKTOP_RAM_GB = 5.0


def free_orphan_runners(timeout=120):
    """Stop Ollama runners the desktop's Ollama has forgotten, through the video render worker's task channel
    (your-site.example/scripts/video/desktop/task.mjs free-orphan-runners). Returns a one-line note, or "".

    Measured 2026-10-25: a llama-server with 13.27 GB of commit and nothing listed in /api/ps sat on the
    15.7 GB desktop after a lead load failed under another job; unload-by-name cannot reach a runner Ollama
    no longer lists, so the box ran at 4 GB free until the process was stopped. The task stops every runner
    when Ollama lists nothing loaded, and only parent-less ones otherwise, so a live chat is never cut."""
    import subprocess
    script = os.path.join(SITE_REPO, "scripts/video/desktop/task.mjs")
    if not os.path.exists(script):
        return ""
    try:
        r = subprocess.run(["node", script, "free-orphan-runners"], cwd=SITE_REPO, capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
    except Exception as e:
        return f"orphan-runner sweep failed: {type(e).__name__}"
    try:
        d = json.loads(r.stdout.strip() or "{}")
        if not isinstance(d, dict) or d.get("kind") != "free-orphan-runners":
            raise ValueError("no task result")  # the channel printed nothing usable: say what it did say
        n = len(d.get("stopped") or [])
        return (f"desktop runner sweep: stopped {n} forgotten runner(s), RAM free {d.get('freeBeforeGb')} -> "
                f"{d.get('freeAfterGb')} GB") if n else f"desktop runner sweep: nothing to stop (RAM free {d.get('freeAfterGb')} GB)"
    except ValueError:
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or [""]
        return f"orphan-runner sweep: {tail[0][:140]}"


def comfy_busy():
    """How many ComfyUI jobs are running or queued right now (another operator's video render, say), or None
    when ComfyUI does not answer. The card and the desktop's RAM are shared: a 5B video clip plus a reload
    of the 13 GB chat model took the desktop to 0.02 GB of free RAM and both sides crawled for 20 minutes
    (image test 5, 2026-10-25, two agents on one card)."""
    try:
        d = json.loads(_req("GET", COMFY + "/queue", timeout=10))
        return len(d.get("queue_running") or []) + len(d.get("queue_pending") or [])
    except Exception:
        return None


def wait_comfy_idle(wait=300):
    """Block until ComfyUI has no job of anyone's, or `wait` seconds pass. Returns the last count."""
    t0 = time.time()
    while True:
        n = comfy_busy()
        if not n or time.time() - t0 >= wait:
            return n or 0
        time.sleep(5)


def _wait_vram(target, wait):
    """Poll the desktop card until `target` GB are free or `wait` seconds pass. Returns (vram, ram)."""
    t0 = time.time()
    while True:
        vram, ram = _desktop_free()
        if vram is None or vram >= target or time.time() - t0 >= wait:
            return vram, ram
        time.sleep(3)


def warm_lead(name, tries=3):
    """Load the chat model back onto the desktop card NOW, with a retry, instead of leaving it to the next
    turn. Returns a one-line note.

    Measured 2026-10-25 (first image test run): restore_gpu reported 14.7 GB free, the next turn's load of
    the 13.4 GB lead failed anyway ("cudaMalloc failed: out of memory"), the dead runner was NOT listed in
    /api/ps yet held 8.2 GB (5.9 GB free with nothing loaded), and the chat dropped to the laptop model.
    Unloading that model BY NAME freed the 8 GB and the same load then took 16 s. So: load here, and if it
    fails, unload by name, wait for the card, load once more. The failure is then a message in the tool
    result instead of a silent stall on the next turn."""
    if not name:
        return ""
    short = name.split("/")[-1][:40]
    for attempt in range(1, tries + 1):
        t0 = time.time()
        try:
            _req("POST", DESKTOP_OLLAMA + "/api/generate", {"model": name, "prompt": "", "keep_alive": "30m"},
                 timeout=300)
            return f"chat model {short} back on the desktop card in {time.time() - t0:.0f} s"
        except Exception as e:
            why = str(e)[:120]
            body = getattr(e, "read", None)
            if body:
                with contextlib.suppress(Exception):
                    why += " " + body().decode(errors="replace")[:160]
            try:
                _unload_by_name(name)
            except Exception:
                pass
            # Ollama answered 500 twice in a row straight after a render and the turn's own call loaded the
            # same model fine seconds later (test 9, 2026-10-25): the card is given back a little after
            # /free and the unload return. Give it a moment, then ask for more than the floor.
            time.sleep(8)
            _wait_vram(MIN_FREE_VRAM_GB + 2, 40)
            if attempt == tries:
                swept = free_orphan_runners()  # a failed load is exactly what leaves a forgotten runner behind
                return (f"WARNING: chat model {short} did not load back on the desktop ({type(e).__name__}: "
                        f"{why}); the next turn will fall back to the laptop model. Say this to the user."
                        + (f" ({swept})" if swept else ""))


def restore_gpu(wait=90, lead=None):
    """Hand the desktop GPU back after a render. Returns a one-line note.

    ComfyUI's /free returns its own torch allocations, but two things it does not do bite the NEXT chat
    turn, because the lead model lives on the same 16 GB card:

      1. Ollama keeps the registry entry for a model whose llama-server DIED while the card was busy,
         and that dead entry still holds its VRAM until the model is unloaded BY NAME.
      2. /free returns before the driver has actually given the memory back.

    Measured 2026-10-25, straight after one SDXL run: 8.3 of 15.9 GB VRAM free and 4.0 of 15.7 GB RAM
    free; the 14 GB lead model could not load ("CUDA error: shared object initialization failed", then a
    failed 2.7 GB pinned-host allocation), Ollama cached the dead runner, and `gnoc chat` sat silent for
    minutes on every turn until the entry was unloaded by hand. Clearing it took VRAM 8.3 -> 14.7 GB and
    RAM 4.0 -> 7.9 GB, and the model loaded in 16 s.
    """
    cleared = []
    try:
        _req("POST", COMFY + "/free", {"unload_models": True, "free_memory": True}, timeout=15)
    except Exception:
        pass
    # A crashed runner may be listed in /api/ps, or NOT listed and still holding its VRAM (2026-10-25: ps
    # empty, 8.2 GB gone, unload-by-name of the lead gave it back). So unload what ps lists AND the lead.
    names = []
    try:
        names = [m["name"] for m in json.loads(_req("GET", DESKTOP_OLLAMA + "/api/ps", timeout=5)).get("models", [])]
    except Exception:
        pass
    if lead and lead not in names:
        names.append(lead)
    for n in names:
        try:
            _unload_by_name(n)
            cleared.append(n)
        except Exception:
            pass
    # read it once, then keep looking: the driver gives it back a moment after /free returns
    vram, ram = _wait_vram(MIN_FREE_VRAM_GB, wait)
    swept = ""
    if ram is not None and ram < LOW_DESKTOP_RAM_GB:
        # Nothing of ours is loaded and the box is still short of RAM: the usual cause is a runner Ollama
        # forgot (see free_orphan_runners). Sweep, then read the card again.
        swept = free_orphan_runners()
        if swept.startswith("desktop runner sweep: stopped"):
            vram, ram = _wait_vram(MIN_FREE_VRAM_GB, 20)
    if vram is None:
        note = "desktop GPU state unknown (ComfyUI did not answer /system_stats)"
    else:
        note = f"desktop GPU handed back: {vram:.1f} GB VRAM free, {ram:.1f} GB RAM free"
        if cleared:
            note += " (unloaded " + ", ".join(c.split("/")[-1][:40] for c in cleared) + ")"
        if vram < MIN_FREE_VRAM_GB:
            note += (f" - WARNING: under {MIN_FREE_VRAM_GB:.0f} GB, so the chat model may fail to load on "
                     "the desktop and the next turn can stall. Say this to the user.")
    if swept:
        note += "; " + swept
    busy = comfy_busy() if lead else 0
    if busy:
        note += (f"; NOT reloading the chat model: ComfyUI has {busy} other job(s) on the card (a video render?), "
                 "and the two together exhaust the desktop. The next turn falls back to the laptop model until it clears.")
        warmed = ""
    else:
        warmed = warm_lead(lead) if lead else ""
    if warmed:
        note += "; " + warmed
    LAST_GPU_NOTE[0] = note
    return note


def unload_ollama():
    """Free the desktop GPU for the image: every loaded Ollama model is unloaded (it reloads on demand)."""
    try:
        loaded = json.loads(_req("GET", DESKTOP_OLLAMA + "/api/ps", timeout=5)).get("models", [])
    except Exception:
        return []
    for m in loaded:
        try:
            _unload_by_name(m["name"], timeout=30)
        except Exception:
            pass
    if loaded:
        # keep_alive 0 returns before the runner has released the card; SDXL then starts while the chat
        # model's 13 GB are still leaving, and the two overlap on a 16 GB card. Wait for the memory.
        _wait_vram(MIN_FREE_VRAM_GB, 45)
    return [m["name"] for m in loaded]


def comfy_configured():
    """A ComfyUI is part of this setup: GNOC_COMFY_URL is set (environment or machine.json)."""
    return bool(os.environ.get("GNOC_COMFY_URL"))


def _engine_hosts():
    """Where gnoc's engine can draw, best card first: a paired computer's engine, then this one's."""
    out = []
    try:
        import llm_endpoints
        for key in ("desktop", "local"):
            addr = (llm_endpoints.HOSTS.get(key) or "").strip()
            if addr and addr not in [a for _k, a in out]:
                out.append((key, addr))
    except Exception:  # noqa: BLE001
        pass
    return out


def _engine_image(addr, body, timeout, say):
    """POST /api/gnoc/image to the engine at addr; -> (png bytes, info) or raises."""
    import base64
    r = urllib.request.Request(f"http://{addr}/api/gnoc/image", json.dumps(dict(body, stream=True)).encode(),
                               method="POST", headers={"Content-Type": "application/json"})
    last = {}
    with urllib.request.urlopen(r, timeout=timeout) as resp:
        for line in resp:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("error"):
                raise RuntimeError(row["error"])
            if row.get("image"):
                last = row
            elif row.get("status") and row["status"] != "success":
                say(str(row["status"]))
    if not last:
        raise RuntimeError("the engine sent no image")
    return base64.b64decode(last.pop("image")), last


def engine_generate(prompt, negative="", width=None, height=None, steps=None, seed=None, out_dir=None, timeout=3600,
                    say=None):
    """An image from gnoc's own engine (stable-diffusion.cpp): a paired computer's card first, then this one's, and
    when no engine runs here (an Ollama install), the engine code itself in this process. -> (path, seed, seconds).
    A clean install makes pictures with nothing else set up (2026-11-23)."""
    say = say or (lambda s: None)
    body = {"prompt": prompt, "negative": negative or "blurry, low quality, watermark, text artifacts",
            "width": width, "height": height, "steps": steps,
            # a real seed, never -1: "seed -1" was reported with "same seed + prompt reproduces it" (image drive)
            "seed": int(seed) if seed is not None and str(seed).lstrip("-").isdigit() and int(seed) >= 0
            else random.randint(1, 2**31 - 1)}
    t0 = time.time()
    png, info, errors = None, {}, []
    for key, addr in _engine_hosts():
        try:
            with urllib.request.urlopen(f"http://{addr}/api/version", timeout=4) as r:
                v = json.load(r)
        except Exception:  # noqa: BLE001
            continue
        if v.get("engine") != "gnoc" or not v.get("images"):
            continue
        try:
            png, info = _engine_image(addr, body, timeout, say)
            info["where"] = "this computer" if key == "local" else "the paired computer"
            break
        except Exception as e:  # noqa: BLE001
            errors.append(f"{key}: {str(e)[:160]}")
    if png is None:
        import gnoc_engine
        png, info = gnoc_engine.make_image(prompt, body["negative"], width, height, steps, body["seed"],
                                           progress=lambda row: row.get("status") and say(str(row["status"])))
        info["where"] = "this computer"
    d = out_dir or DELIVER
    os.makedirs(d, exist_ok=True)
    stem = f"gnoc-image-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{info.get('seed', 0)}"
    path = os.path.join(d, stem + ".png")
    with open(path, "wb") as f:
        f.write(png)
    LAST_ENGINE_INFO[0] = info
    return path, info.get("seed"), round(time.time() - t0, 1)


LAST_ENGINE_INFO = [{}]


def generate(prompt, negative="", width=1024, height=1024, steps=28, cfg=6.5, seed=None, out_dir=None,
             timeout=600, lead=None):
    """lead: the chat model's name on the desktop, if it lives there - unloaded before the render, loaded
    back (with a retry) after it, see warm_lead. With no ComfyUI in this setup (a clean install) or none
    reachable, gnoc's own engine draws it (engine_generate)."""
    LAST_ENGINE_INFO[0] = {}
    if not comfy_configured() or not up():
        return engine_generate(prompt, negative, width, height, None, seed, out_dir)
    width, height = clamp_dims(width, height)
    steps = max(4, min(int(steps), 60))
    seed = int(seed) if seed is not None else random.randint(1, 2**31 - 1)
    # Someone else's job first: do not take the chat model off the card to queue behind a video render.
    still = wait_comfy_idle(300)
    if still:
        raise RuntimeError(f"ComfyUI is busy with {still} other job(s) on the desktop card (a video render?) and did "
                           "not clear in 5 minutes; try again when it is free (gnoc gpus shows the card)")
    freed = unload_ollama()
    t0 = time.time()
    img = None
    # The unload above has ALREADY taken the chat model off the card, so everything from here on has to
    # reach the restore in the finally - including a /prompt that is refused (a bad checkpoint name, a
    # ComfyUI that died between up() and now). It used to sit outside the try, so that path left the
    # desktop with no chat model and nothing to put it back.
    try:
        cid = uuid.uuid4().hex
        pid = json.loads(_req("POST", COMFY + "/prompt",
                              {"prompt": workflow(prompt, negative or "blurry, low quality, watermark, "
                                                  "text artifacts", width, height, steps, float(cfg), seed),
                               "client_id": cid}))["prompt_id"]
        while time.time() - t0 < timeout:
            hist = json.loads(_req("GET", f"{COMFY}/history/{pid}") or b"{}")
            if pid in hist:
                st = hist[pid].get("status", {})
                if st.get("status_str") == "error":
                    raise RuntimeError("ComfyUI error: " + json.dumps(st.get("messages", []))[:400])
                for node in hist[pid].get("outputs", {}).values():
                    for im in node.get("images", []):
                        img = im
                if img:
                    break
            time.sleep(1.5)
        if not img:
            raise RuntimeError(f"no image after {timeout}s")
        q = urllib.parse.urlencode({"filename": img["filename"], "subfolder": img.get("subfolder", ""),
                                    "type": img.get("type", "output")})
        data = _req("GET", f"{COMFY}/view?{q}", timeout=60)
    finally:
        # Not just /free: the card has to be usable by the chat model again before the next turn.
        try:
            restore_gpu(lead=lead)
        except Exception as e:
            LAST_GPU_NOTE[0] = f"could not check the desktop GPU after the render: {type(e).__name__}"
    d = out_dir or DELIVER
    os.makedirs(d, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    stem = f"gnoc-image-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{seed}"
    path = os.path.join(d, stem + ".png")
    with open(path, "wb") as f:
        f.write(data)
    with open(os.path.join(OUT, stem + ".json"), "w") as f:
        json.dump({"prompt": prompt, "negative": negative, "width": width, "height": height, "steps": steps,
                   "cfg": cfg, "seed": seed, "ckpt": CKPT, "seconds": round(time.time() - t0, 1),
                   "unloaded": freed, "path": path}, f, indent=1)
    return path, seed, round(time.time() - t0, 1)
