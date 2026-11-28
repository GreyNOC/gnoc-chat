#!/usr/bin/env python3
"""gnoc_engine.py - gnoc's own local model server: what gnoc used Ollama for, and nothing else.

It keeps a store of GGUF models, starts llama.cpp's `llama-server` for the model a request names, and answers
the part of the Ollama HTTP API that gnoc calls, on the address gnoc already talks to. Nothing else in gnoc
has to know which of the two is listening.

    gnoc engine                       status: the server, the llama.cpp build, loaded and stored models
    gnoc engine install [--variant vulkan|cpu|cuda-12.8|...] [--tag bNNNN]
                                      download llama.cpp's llama-server for this computer (checksum verified)
    gnoc engine start | stop | serve  run the server in the background / stop it / run it in this terminal
    gnoc engine pull <source> [--as NAME] [--ctx N]
                                      owner/repo[:QUANT] or a huggingface.co URL, a direct https://...gguf URL,
                                      a .gguf file on disk, or a library name such as qwen3:8b
    gnoc engine search <words> | files <owner/repo>
                                      find GGUF models on Hugging Face; the quantisations a repo has, and which fit
    gnoc engine list | show <model> | rm <model>
    gnoc engine ps | unload <model> | logs [model] | restart
                                      what is loaded, free its memory, read the server's (or a model's) log
    gnoc engine context [auto | N] [--gpu NAME | --gpu all]
                                      the context window for each GPU: auto (the default) is the biggest window that
                                      keeps the whole model on that GPU; N fixes it (tokens, e.g. 32768 or 64k)
    gnoc engine update                the newest llama.cpp build, when there is one (older builds are removed)
    gnoc engine run <model> ["question"]
                                      talk to a model in this terminal (starts the server if it is not running)
    gnoc engine share [on [--port N] | off]
                                      serve OTHER computers on your network behind a key, start with this computer,
                                      and print the line to pair it (gnoc pair <address> <key>)
    gnoc engine self-update [--llama] the newest signed engine release (a standalone engine does this daily when
                                      shared); --llama also the newest llama.cpp build
    gnoc engine import-ollama [name ...]
                                      adopt models an Ollama on this computer already downloaded (hard links:
                                      no second copy, and Ollama keeps working)

HTTP (the subset gnoc uses):
    GET  /api/version /api/tags /api/ps          POST /api/show /api/chat /api/generate
    POST /api/pull /api/create                   DELETE /api/delete
    POST /api/embed /api/embeddings /v1/embeddings          (embedding models, and chat models on request)
    POST /v1/chat/completions /v1/completions    GET /v1/models      (passed straight to llama-server)
Chat supports streaming, tools, think, format (JSON / a JSON schema), images, options (num_ctx, num_predict,
temperature, top_p, top_k, seed, stop, repeat_penalty) and keep_alive, with Ollama's response shapes.

Not here, on purpose: Modelfile templates and adapters, safetensors conversion, pushing models, several models
loaded at once by default (GNOC_ENGINE_MAX_LOADED raises it).

Settings (environment):
    GNOC_ENGINE_ADDR         host:port to listen on (default: the address gnoc uses for its local model server)
    GNOC_MODELS_DIR          the model store (default ~/.local/share/gnoc-chat/models)
    GNOC_ENGINE_HOME         llama.cpp builds, logs, pid file (default ~/.local/share/gnoc-chat/engine)
    GNOC_LLAMA_SERVER        use this llama-server binary instead of an installed build
    GNOC_ENGINE_ARGS         extra llama-server arguments, e.g. "-ngl 99 -ctk q8_0 -ctv q8_0"
    GNOC_ENGINE_CTX          context window for every GPU: a number, or auto (default: what `gnoc engine context`
                             set for this GPU, else auto; 16384 on the CPU)
    GNOC_ENGINE_FIT_MARGIN   MiB of GPU memory auto leaves free for the desktop and other programs (default 1024)
    GNOC_ENGINE_AUTO_MAX     the largest window auto picks (default 131072)
    GNOC_ENGINE_SPEC         speculative decoding: ngram-mod (default; drafts from text already in the prompt, about
                             1.9x faster when an answer repeats code it was shown), another --spec-type, or none
    GNOC_ENGINE_KEEP_ALIVE   how long an idle model stays loaded (default 5m)
    GNOC_ENGINE_MAX_LOADED   models kept loaded at once (default 1)
    GNOC_ENGINE_KEY          a key callers on OTHER computers must send (Authorization: Bearer ...); set it
                             whenever GNOC_ENGINE_ADDR opens the server to a network
    HF_TOKEN                 for gated Hugging Face repos (also read from ~/.config/gnoc/secrets.env)
"""
import collections
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import platform
import re
import shlex
import shutil
import signal
import secrets
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.4.0"   # 1.4.0: CUDA build for NVIDIA on Linux and WSL, llvmpipe warning
HOME = os.environ.get("GNOC_ENGINE_HOME") or os.path.expanduser("~/.local/share/gnoc-chat/engine")
MODELS = os.environ.get("GNOC_MODELS_DIR") or os.path.expanduser("~/.local/share/gnoc-chat/models")
BLOBS = os.path.join(MODELS, "blobs")
MANIFESTS = os.path.join(MODELS, "manifests")
PIDFILE = os.path.join(HOME, "engine.pid")
LOG = os.path.join(HOME, "engine.log")
DEFAULT_CTX = 16384   # the CPU, an embedding runner, or a llama.cpp too old to fit the window to the GPU
with contextlib.suppress(ValueError):
    DEFAULT_CTX = max(2048, int(os.environ.get("GNOC_ENGINE_CTX", "16384")))
# CONTEXT PER GPU (GreyNOC 2026-11-25: "can we have the harness assign context allotments based on the user's
# hardware? or give the user the choice of how much context on each gpu"). "auto", the default, starts llama-server
# with -c 0 and llama.cpp's own fit: the biggest window that keeps EVERY layer on the GPU with FIT_MARGIN MiB left
# free. Measured on an RX 7700S (8 GB) with the 9B Qwen3.5 and its vision projector: 61,696 tokens with 1 GiB free,
# where the fixed 16,384 left most of the card idle, and a fixed 131,072 silently put 8 of 33 layers on the CPU.
# `gnoc engine context` sets a fixed window per GPU instead (context.json, keyed by the GPU's name).
FIT_MARGIN = int(os.environ.get("GNOC_ENGINE_FIT_MARGIN", "1024") or 1024)
AUTO_MIN = 16384      # auto never goes below this: under it llama.cpp keeps the window and moves layers instead
AUTO_MAX = int(os.environ.get("GNOC_ENGINE_AUTO_MAX", "131072") or 131072)
# Speculative decoding from n-grams already in the prompt: no draft model, no extra memory. An answer that repeats
# code it was shown (an edit, a patch) came out 1.9x faster (40.1 -> 75.5 tok/s, 228 of 250 drafts accepted) and
# new prose ran at the same speed (39.8 vs 39.7), RX 7700S 2026-11-25.
SPEC = (os.environ.get("GNOC_ENGINE_SPEC", "ngram-mod") or "none").strip()
MAX_LOADED = max(1, int(os.environ.get("GNOC_ENGINE_MAX_LOADED", "1")))
LOAD_TIMEOUT = float(os.environ.get("GNOC_ENGINE_LOAD_TIMEOUT", "900"))
LLAMA_REPO = "ggml-org/llama.cpp"
UA = "gnoc-engine"
QUANT_PREF = ["Q4_K_M", "Q4_K_S", "IQ4_XS", "Q4_0", "Q5_K_M", "Q3_K_M", "IQ3_M", "Q3_K_S", "Q6_K", "Q8_0", "Q2_K"]
QUANT_RE = re.compile(r"((?:I?Q\d[_A-Z0-9]*)|F16|BF16|F32)(?:-\d+-of-\d+)?\.gguf$", re.I)
SPLIT_RE = re.compile(r"-(\d{5})-of-(\d{5})\.gguf$")
# Library names gnoc's own setup and docs use, served from the publisher's GGUF repo on Hugging Face. Any other
# bare name (llama3.1:8b) is fetched from the Ollama registry, which is a plain file server and needs no Ollama.
LIBRARY = {"qwen3:1.7b": "Qwen/Qwen3-1.7B-GGUF:Q8_0", "qwen3:4b": "Qwen/Qwen3-4B-GGUF:Q4_K_M", "qwen3:8b": "Qwen/Qwen3-8B-GGUF:Q4_K_M",
           "qwen3:14b": "Qwen/Qwen3-14B-GGUF:Q4_K_M", "qwen3:0.6b": "Qwen/Qwen3-0.6B-GGUF:Q8_0"}
REGISTRY = "https://registry.ollama.ai"
OLLAMA_STORES = [os.environ.get("OLLAMA_MODELS") or "", os.path.expanduser("~/.ollama/models"),
                 "/usr/share/ollama/.ollama/models", "/var/lib/ollama/.ollama/models"]


# the command as the user types it: "gnoc engine" inside gnoc chat, "gnoc-engine" for the download on its own
PROG = os.environ.get("GNOC_ENGINE_PROG") or "gnoc engine"


def _say(text):
    """Help and hints, with the command spelled the way this install runs it. A text that already names the
    command is left alone: an error can pass through here on the server and again in the terminal."""
    if PROG == "gnoc engine" or PROG in text:
        return text
    return text.replace("gnoc engine", PROG)


class EngineError(Exception):
    def __init__(self, msg, status=500):
        super().__init__(msg)
        self.status = status


def addr():
    """host:port the engine listens on: GNOC_ENGINE_ADDR, else the address gnoc uses for its local model server."""
    a = os.environ.get("GNOC_ENGINE_ADDR", "") or str(share_conf().get("addr") or "")
    if not a:
        try:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import llm_endpoints
            a = llm_endpoints.HOSTS.get("local") or ""
        except Exception:  # noqa: BLE001 - the engine also runs alone, without the rest of gnoc
            a = ""
    a = re.sub(r"^[a-z]+://", "", a or "127.0.0.1:11434").split("/", 1)[0]
    host, _, port = a.rpartition(":")
    return (host or "127.0.0.1"), int(port or 11434)


def _now():
    return datetime.now(timezone.utc).astimezone()


def _write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=1)
    os.replace(tmp, path)


def hf_token():
    tok = os.environ.get("HF_TOKEN")
    if tok:
        return tok
    try:
        with open(os.path.expanduser("~/.config/gnoc/secrets.env")) as f:
            for ln in f:
                m = re.match(r"\s*(?:export\s+)?HF_TOKEN\s*=\s*['\"]?([^'\"\s#]+)", ln)
                if m:
                    return m.group(1)
    except OSError:
        pass
    return None


# ------------------------------------------------------------------ GGUF metadata
_GG_FIXED = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
_FILE_TYPES = {0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K", 11: "Q3_K_S",
               12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M", 18: "Q6_K",
               19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S", 22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S", 25: "IQ4_NL",
               26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S", 29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M", 32: "BF16"}


def gguf_meta(path, limit=4000):
    """The scalar and string metadata of a GGUF file (arrays are skipped: the vocabulary is not wanted here).
    Raises ValueError when the file is not GGUF."""
    out = {}
    with open(path, "rb") as f:
        if f.read(4) != b"GGUF":
            raise ValueError(f"{os.path.basename(path)} is not a GGUF file")
        ver, = struct.unpack("<I", f.read(4))
        if ver < 2:
            raise ValueError(f"GGUF version {ver} is too old (re-download a current build of this model)")
        _tensors, n_kv = struct.unpack("<QQ", f.read(16))

        def rstr():
            n, = struct.unpack("<Q", f.read(8))
            if n > 64 << 20:
                raise ValueError("corrupt GGUF: a string longer than 64 MB")
            return f.read(n)

        def rval(t, keep=True):
            if t in _GG_FIXED:
                fmt = "<" + _GG_FIXED[t]
                return struct.unpack(fmt, f.read(struct.calcsize(fmt)))[0]
            if t == 8:
                s = rstr()
                return s.decode("utf-8", "replace") if keep else None
            if t == 9:
                it, n = struct.unpack("<IQ", f.read(12))
                if it in _GG_FIXED:
                    f.seek(n * struct.calcsize("<" + _GG_FIXED[it]), 1)
                else:
                    for _ in range(n):
                        rval(it, keep=False)
                return None
            raise ValueError(f"corrupt GGUF: unknown value type {t}")

        for _ in range(min(n_kv, limit)):
            key = rstr().decode("utf-8", "replace")
            t, = struct.unpack("<I", f.read(4))
            v = rval(t)
            if v is not None:
                out[key] = v
    return out


def describe(model_path, mmproj=None):
    """What /api/show reports about a model file: family, size label, quantisation, trained context, capabilities."""
    try:
        md = gguf_meta(model_path)
    except (OSError, ValueError, struct.error):
        md = {}
    arch = str(md.get("general.architecture") or "")
    tpl = str(md.get("tokenizer.chat_template") or "")
    # an embedding model says how its vectors are pooled, and has no conversation to template
    embedder = md.get(arch + ".pooling_type") is not None and not tpl
    caps = ["embedding"] if embedder else ["completion"]
    if re.search(r"\btools\b|tool_call", tpl):
        caps.append("tools")
    if re.search(r"enable_thinking|<think>|reasoning_content|reasoning_effort|<\|channel\|>", tpl):
        caps.append("thinking")
    if mmproj:
        caps.append("vision")
    quant = _FILE_TYPES.get(md.get("general.file_type"), "")
    return {"family": arch, "parameter_size": str(md.get("general.size_label") or ""),
            "quantization_level": quant or "unknown", "context_length": int(md.get(arch + ".context_length") or 0),
            "name": str(md.get("general.name") or ""), "capabilities": caps, "has_template": bool(tpl)}


# ------------------------------------------------------------------ the store
def canon(name):
    """One spelling per model: 'qwen3-oc:latest' == 'qwen3-oc'; a huggingface.co URL == its hf.co/ name."""
    n = str(name or "").strip()
    n = re.sub(r"^(https?://)?(www\.)?huggingface\.co/", "hf.co/", n)
    return n[:-7] if n.endswith(":latest") else n


def shown(name):
    """The name as Ollama lists it: an untagged model carries :latest."""
    return name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"


def _mpath(name):
    return os.path.join(MANIFESTS, urllib.parse.quote(canon(name), safe="") + ".json")


def get(name):
    try:
        with open(_mpath(name)) as f:
            m = json.load(f)
        return m if isinstance(m, dict) and m.get("model") else None
    except (OSError, ValueError):
        return None


def need(name):
    m = get(name)
    if not m:
        raise EngineError(f"model '{name}' not found", 404)
    return m


def models():
    out = []
    try:
        names = sorted(os.listdir(MANIFESTS))
    except OSError:
        return out
    for fn in names:
        if fn.endswith(".json"):
            m = get(urllib.parse.unquote(fn[:-5]))
            if m:
                out.append(m)
    return out


def blob_path(rel):
    return os.path.join(MODELS, rel)


def _save(name, model_rel, mmproj_rel=None, params=None, source="", digest=""):
    full = blob_path(model_rel)
    size = _set_size(full) + (os.path.getsize(blob_path(mmproj_rel)) if mmproj_rel else 0)
    info = describe(full, mmproj_rel)
    params = {k: v for k, v in (params or {}).items() if v is not None}
    body = {"name": canon(name), "model": model_rel, "mmproj": mmproj_rel, "params": params, "source": source,
            "size": size, "blob": digest, "info": info, "modified_at": _now().isoformat()}
    # like Ollama: the digest names the model AS CONFIGURED, so an alias with other parameters has its own
    body["digest"] = hashlib.sha256(json.dumps([digest, mmproj_rel, params], sort_keys=True).encode()).hexdigest()
    _write_json(_mpath(name), body)
    return body


def _set_size(first):
    """Bytes of a model file, counting every part of a split GGUF."""
    m = SPLIT_RE.search(first)
    if not m:
        return os.path.getsize(first)
    d = os.path.dirname(first)
    stem = os.path.basename(first)[:m.start() - len(first)]
    return sum(os.path.getsize(os.path.join(d, f)) for f in os.listdir(d) if f.startswith(stem))


def create(name, src, params=None):
    """A second name for a stored model, with its own parameters (num_ctx, temperature): Ollama's `create FROM`."""
    base = need(src)
    if not re.fullmatch(r"[\w.:/@+-]{1,200}", canon(name) or ""):
        raise EngineError(f"invalid model name {name!r}", 400)
    return _save(name, base["model"], base.get("mmproj"), dict(base.get("params") or {}, **(params or {})),
                 base.get("source") or canon(src), base.get("blob") or "")


def delete(name):
    m = need(name)
    os.remove(_mpath(name))
    left = {x["model"] for x in models()} | {x["mmproj"] for x in models() if x.get("mmproj")}
    for rel in (m["model"], m.get("mmproj")):
        if rel and rel not in left:
            top = os.path.join(BLOBS, os.path.relpath(blob_path(rel), BLOBS).split(os.sep)[0])
            # only ever inside the store's blobs directory
            if os.path.realpath(top).startswith(os.path.realpath(BLOBS) + os.sep):
                if os.path.isdir(top):
                    shutil.rmtree(top, ignore_errors=True)
                else:
                    with contextlib.suppress(OSError):
                        os.remove(top)
    return m


# ------------------------------------------------------------------ downloads
class _Redirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never carry the Authorization header to another host (Hugging Face and the
    registries redirect weights to a CDN with a signed URL; the token is for the first host only)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != urllib.parse.urlsplit(req.full_url).hostname:
            for h in list(new.headers):
                if h.lower() == "authorization":
                    del new.headers[h]
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_opener = urllib.request.build_opener(_Redirect())


def _headers(url, extra=None):
    h = {"User-Agent": UA}
    if urllib.parse.urlsplit(url).hostname in ("huggingface.co", "hf.co") and hf_token():
        h["Authorization"] = f"Bearer {hf_token()}"
    h.update(extra or {})
    return h


def _open(url, extra=None, timeout=60):
    if urllib.parse.urlsplit(url).scheme not in ("https", "http"):
        raise EngineError(f"not a web address: {url}", 400)
    return _opener.open(urllib.request.Request(url, headers=_headers(url, extra)), timeout=timeout)


def _json(url, extra=None, timeout=30):
    try:
        with _open(url, extra, timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            host = urllib.parse.urlsplit(url).hostname
            hint = " (gated or private: set HF_TOKEN)" if e.code in (401, 403) and "huggingface" in host else ""
            raise EngineError(f"{host} answered {e.code} for {urllib.parse.urlsplit(url).path}{hint}",
                              404 if e.code == 404 else 502)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise EngineError(f"cannot reach {urllib.parse.urlsplit(url).hostname}: {getattr(e, 'reason', e)}", 502)


class Cancelled(EngineError):
    """The caller of a pull went away: stop downloading (the partial file stays, so a later pull resumes)."""


@contextlib.contextmanager
def _one_download(part, label=""):
    """Only one download writes a partial file at a time, across the server and a `pull` in a terminal: two would
    interleave their bytes. The lock is held on an open file, so it dies with its process and a crashed pull
    never blocks the next one. Only the holder removes the lock file, when its work is over: a refused pull that
    removed it would let a third lock a fresh file beside the one still held."""
    os.makedirs(os.path.dirname(part), exist_ok=True)
    fh = open(part + ".lock", "a+b")
    held = False
    try:
        try:
            if os.name == "nt":
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = True
        except OSError:
            raise EngineError(f"{label or os.path.basename(part)} is already being downloaded by another pull: "
                              "wait for it, or stop it first", 409)
        yield
    finally:
        if held:
            with contextlib.suppress(OSError):
                os.remove(part + ".lock")
        fh.close()


def _room_for(dest, need_bytes, label):
    """Refuse a download the disk cannot hold, before the first byte instead of at the last."""
    try:
        free = shutil.disk_usage(os.path.dirname(dest)).free
    except OSError:
        return
    if need_bytes > 0 and free < need_bytes + (1 << 30):
        raise EngineError(f"not enough disk space for {label}: it needs {need_bytes / 1e9:.1f} GB more and "
                          f"{free / 1e9:.1f} GB is free in {os.path.dirname(dest)} (1 GB is kept spare)", 507)


def fetch(url, dest, size=0, sha256=None, progress=None, label=""):
    """Download url to dest, resuming a partial file, verifying sha256 when it is known. Returns the sha256.
    progress(row) may raise Cancelled to stop it."""
    if os.path.exists(dest) and (not size or os.path.getsize(dest) == size):
        if sha256 is None or not size:
            return sha256 or _sha(dest)
        return sha256
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    with _one_download(part, label or os.path.basename(dest)):
        _room_for(dest, size - (os.path.getsize(part) if os.path.exists(part) else 0), label or os.path.basename(dest))
        return _fetch(url, dest, part, size, sha256, progress, label)


def _fetch(url, dest, part, size, sha256, progress, label):
    for attempt in range(5):
        have = os.path.getsize(part) if os.path.exists(part) else 0
        h = hashlib.sha256()
        if have:
            with open(part, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 22), b""):
                    h.update(chunk)
        try:
            with _open(url, {"Range": f"bytes={have}-"} if have else None, timeout=120) as r:
                if have and r.status != 206:
                    have, h = 0, hashlib.sha256()   # the server ignored the range: start again
                total = size or (have + int(r.headers.get("Content-Length") or 0))
                last = 0.0
                with open(part, "ab" if have else "wb") as f:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
                        h.update(chunk)
                        have += len(chunk)
                        if progress and time.time() - last > 0.25:
                            last = time.time()
                            progress({"status": f"pulling {label or os.path.basename(dest)}", "total": total,
                                      "completed": have})
            if size and have < size:
                raise OSError(f"connection closed at {have} of {size} bytes")
            break
        except urllib.error.HTTPError as e:
            with e:
                if e.code == 416 and have:      # the partial file is already everything: verify it below
                    break
                raise EngineError(f"download failed: HTTP {e.code} for {label or url}", 502)
        except (urllib.error.URLError, OSError) as e:
            if attempt == 4:
                raise EngineError(f"download failed after 5 tries: {getattr(e, 'reason', e)} "
                                  "(run the same pull again: it resumes)", 502)
            time.sleep(2 + 3 * attempt)
    got = h.hexdigest()
    if sha256 and got != sha256:
        os.remove(part)
        raise EngineError(f"{label or os.path.basename(dest)}: checksum mismatch (got {got[:12]}, expected "
                          f"{sha256[:12]}); the partial file was removed, pull again", 502)
    if progress:
        progress({"status": f"pulling {label or os.path.basename(dest)}", "total": have, "completed": have})
    os.replace(part, dest)
    return got


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def _link(src, dest):
    """Put src in the store without a second copy when the filesystem allows it."""
    if os.path.exists(dest):
        return
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        os.link(src, dest)
    except OSError:
        shutil.copyfile(src, dest + ".part")
        os.replace(dest + ".part", dest)


# ------------------------------------------------------------------ where a model comes from
def hf_files(repo):
    """[(quant, bytes, path, sha256, [every part])] for the GGUF weights in a Hugging Face repo, and its mmproj."""
    tree = _json(f"https://huggingface.co/api/models/{repo}/tree/main?recursive=true")
    ggufs = [f for f in tree if f.get("type") == "file" and str(f.get("path", "")).lower().endswith(".gguf")]
    oid = lambda f: (f.get("lfs") or {}).get("oid") or None   # noqa: E731
    mm = sorted((f for f in ggufs if "mmproj" in f["path"].lower()),
                key=lambda f: (0 if re.search(r"(?i)f16|q8", f["path"]) else 1, f.get("size") or 0))
    rows = []
    for f in ggufs:
        p = f["path"]
        if "mmproj" in p.lower():
            continue
        sp = SPLIT_RE.search(p)
        if sp and sp.group(1) != "00001":
            continue
        parts = [f]
        if sp:
            stem = p[:sp.start()]
            parts = sorted((g for g in ggufs if g["path"].startswith(stem + "-") and SPLIT_RE.search(g["path"])),
                           key=lambda g: g["path"])
        q = QUANT_RE.search(p)
        rows.append((q.group(1).upper() if q else os.path.basename(p), sum(g.get("size") or 0 for g in parts), p,
                     oid(f), [(g["path"], g.get("size") or 0, oid(g)) for g in parts]))
    return rows, ((mm[0]["path"], mm[0].get("size") or 0, oid(mm[0])) if mm else None)


def parse_hf(spec):
    """'hf.co/owner/repo:Q4_K_M' | a huggingface.co URL | 'owner/repo'
    -> ('owner/repo', 'Q4_K_M' | None, file | None)."""
    s = re.sub(r"^(https?://)?(www\.)?(huggingface\.co|hf\.co)/", "", spec.strip())
    s = re.sub(r"^models/", "", s)
    m = re.match(r"^([\w.-]+/[\w.-]+)/(?:resolve|blob)/[^/]+/(.+\.gguf)(?:\?.*)?$", s)
    if m:
        return m.group(1), None, urllib.parse.unquote(m.group(2))
    quant = None
    q = re.search(r":([\w.-]*)$", s)
    if q:
        s, quant = s[:q.start()], q.group(1).upper() or None
    s = re.sub(r"/(tree|resolve|blob)/.*$", "", s)
    parts = s.strip("/").split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[\w.-]+", p) for p in parts):
        raise EngineError(f"not a Hugging Face repo: {spec!r} (want owner/repo[:QUANT])", 400)
    return "/".join(parts), quant, None


def fit_budget():
    """(bytes that run well, bytes that run at all, what the first is measured against). A model file up to the
    first figure sits on the GPU (with a little spill); up to the second it runs split between the GPU and RAM,
    or wholly in RAM, slower. (inf, inf, '') when this computer's memory cannot be read."""
    kind, vram = gpu()
    return budget_for(kind, vram, ram_bytes())


def ram_bytes():
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        pass
    if os.name == "nt":
        with contextlib.suppress(Exception):
            import ctypes

            class _M(ctypes.Structure):
                _fields_ = [("n", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                    (k, ctypes.c_ulonglong) for k in ("total", "avail", "tp", "ap", "tv", "av", "ext")]
            m = _M()
            m.n = ctypes.sizeof(_M)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
                return int(m.total)
    return 0


def budget_for(kind, vram, ram):
    """fit_budget() for any machine whose GPU and memory are known: this one, or another one that told us
    (GET /api/machine)."""
    if not vram and not ram:
        return float("inf"), float("inf"), ""
    if kind == "apple":     # one pool of memory, shared with the GPU
        return ram * 0.7, ram * 0.7, f"{ram / 2 ** 30:.0f} GB of memory"
    if vram:
        return vram * 1.25, max(vram * 1.25, vram + ram * 0.5), f"the {vram / 2 ** 30:.0f} GB GPU"
    return ram * 0.6, ram * 0.6, f"{ram / 2 ** 30:.0f} GB of memory"


def fit_word(size, budget=None):
    well, at_all, what = budget or fit_budget()
    return "fits" if size <= well else ("runs partly on the CPU (slower)" if size <= at_all else f"too big for {what}")


def pick_quant(by, budget=None):
    """The quantisation to take when none was asked for: the usual order of preference (Q4_K_M first) among those
    that run well on this computer; failing that, the same order among those that run at all; failing that, the
    smallest. by: {quant: (quant, bytes, ...)}. Returns (quant, note or '')."""
    well, at_all, what = budget or fit_budget()
    gb = lambda q: f"{q} ({by[q][1] / 1e9:.1f} GB)"   # noqa: E731
    first = next((q for q in QUANT_PREF if q in by), None) or min(by, key=lambda q: by[q][1])
    for limit, slow in ((well, False), (at_all, True)):
        fits = [q for q in by if by[q][1] <= limit]
        pick = next((q for q in QUANT_PREF if q in fits), None) or (max(fits, key=lambda q: by[q][1]) if fits else None)
        if pick:
            if slow:
                return pick, (f"nothing in this repo fits {what}; taking {gb(pick)}, which runs partly on the CPU "
                              "(slower)")
            return pick, ("" if pick == first else f"taking {gb(pick)}: {gb(first)} is too big for {what}")
    pick = min(by, key=lambda q: by[q][1])
    return pick, f"nothing in this repo fits this computer; taking the smallest, {gb(pick)}: expect it to be very slow"


# What every kind of source hands back to pull(): the name the model came from, where its weights (and the part
# that reads images, if any) now sit in the store, the parameters the source set, and the weights' checksum.
Pulled = collections.namedtuple("Pulled", "source model mmproj params digest")


def _rel(sha):
    """Where the store keeps a single file with this checksum, relative to the store."""
    return os.path.join("blobs", "sha256-" + sha)


def _fetch_blob(url, size, sha, progress, label, key=None):
    """Download one file into the store under its checksum; nothing is downloaded when the store already has
    the whole file (a copy of the wrong size is fetched again). key names the partial file while the checksum is
    not known yet (or to keep an older partial resumable). Returns (path relative to the store, sha256)."""
    final = blob_path(_rel(sha)) if sha else None
    tmp = os.path.join(BLOBS, "incoming-" + (key or hashlib.sha256(url.encode()).hexdigest()[:24]))
    if final and os.path.exists(final) and (not size or os.path.getsize(final) == size):
        with contextlib.suppress(OSError):
            os.remove(tmp)          # a finished download an earlier pull left beside it
        return _rel(sha), sha
    if final and key is None:
        fetch(url, final, size, sha, progress, label)
        return _rel(sha), sha
    sha = fetch(url, tmp, size, sha, progress, label)
    os.replace(tmp, blob_path(_rel(sha)))
    return _rel(sha), sha


def _by_quant(rows):
    """{quant: row} for hf_files() rows, the first file of each quantisation winning."""
    by = {}
    for r in rows:
        by.setdefault(r[0], r)
    return by


def _choose_hf_row(repo, rows, quant, want_file, progress):
    """The repo file to take: the one named, the quantisation asked for, or the one that fits this computer.
    Returns (row, quant or None)."""
    if want_file:
        row = next((r for r in rows if r[2] == want_file), None)
        if not row:
            raise EngineError(f"{repo} has no file {want_file}", 404)
        return row, quant
    by = _by_quant(rows)
    pick, note = (quant, "") if quant else pick_quant(by)
    if note and progress:
        progress({"status": note})
    if pick not in by:
        raise EngineError(f"{repo} has no {pick}; it has: {', '.join(sorted(by))}", 404)
    return by[pick], pick


def _pull_hf(spec, progress):
    repo, quant, want_file = parse_hf(spec)
    rows, mm = hf_files(repo)
    if not rows:
        raise EngineError(f"{repo} has no .gguf files (search Hugging Face for a GGUF build of it)", 404)
    (_q, _size, path, sha, parts), quant = _choose_hf_row(repo, rows, quant, want_file, progress)
    base = f"https://huggingface.co/{repo}/resolve/main/"
    name_key = hashlib.sha256((repo + path).encode()).hexdigest()
    if len(parts) == 1:
        rel, sha = _fetch_blob(base + urllib.parse.quote(path), parts[0][1], sha, progress, os.path.basename(path),
                               key=name_key[:24])
    else:
        # a split GGUF: llama.cpp finds the other parts by their file names, so the set keeps them, in one directory
        sha = sha or name_key
        d = os.path.join(BLOBS, f"sha256-{sha}.d")
        for part, size, part_sha in parts:
            fetch(base + urllib.parse.quote(part), os.path.join(d, os.path.basename(part)), size, part_sha, progress,
                  os.path.basename(part))
        rel = os.path.join("blobs", f"sha256-{sha}.d", os.path.basename(path))
    mm_rel = None
    if mm:
        mm_path, mm_size, mm_sha = mm
        mm_rel, _ = _fetch_blob(base + urllib.parse.quote(mm_path), mm_size, mm_sha, progress,
                                os.path.basename(mm_path), key="mm-" + (mm_sha or "x")[:24])
    return Pulled(f"hf.co/{repo}:{quant}" if quant else f"hf.co/{repo}/{path}", rel, mm_rel, {}, sha)


def _manifest_layers(man):
    """(model layer, projector layer, params dict loader input) from an Ollama/OCI manifest."""
    layers = {}
    for ly in man.get("layers") or []:
        kind = str(ly.get("mediaType") or "").rsplit(".", 1)[-1]
        layers.setdefault(kind, ly)
    return layers


def _layer_sha(layer):
    return layer["digest"].split(":", 1)[1]


def _params_of(raw):
    try:
        p = json.loads(raw)
    except ValueError:
        return {}
    return {k: p[k] for k in ("num_ctx", "temperature", "top_p", "top_k", "repeat_penalty", "stop") if k in p}


def _pull_registry(name, progress):
    n = canon(name)
    path, _, tag = n.partition(":")
    if "/" not in path:
        path = "library/" + path
    blobs = f"{REGISTRY}/v2/{path}/blobs/"
    man = _json(f"{REGISTRY}/v2/{path}/manifests/{tag or 'latest'}",
                {"Accept": "application/vnd.docker.distribution.manifest.v2+json"})
    layers = _manifest_layers(man)
    if "model" not in layers:
        raise EngineError(f"{name}: the registry has no model file under that name", 404)
    rels = {}
    for kind in ("model", "projector"):
        ly = layers.get(kind)
        if ly:
            rels[kind], _ = _fetch_blob(blobs + ly["digest"], ly.get("size") or 0, _layer_sha(ly), progress,
                                        f"{n} ({kind})")
    params = {}
    if "params" in layers:
        with contextlib.suppress(EngineError, OSError):
            with _open(blobs + layers["params"]["digest"]) as r:
                params = _params_of(r.read())
    return Pulled(n, rels["model"], rels.get("projector"), params, _layer_sha(layers["model"]))


def _pull_url(url, progress):
    label = os.path.basename(urllib.parse.urlsplit(url).path) or "model.gguf"
    tmp = os.path.join(BLOBS, "incoming-" + hashlib.sha256(url.encode()).hexdigest()[:24])
    sha = fetch(url, tmp, 0, None, progress, label)
    gguf_meta(tmp, limit=1)        # refuse a page or an archive before it is filed as a model
    os.replace(tmp, blob_path(_rel(sha)))
    return Pulled(url, _rel(sha), None, {}, sha)


def _pull_file(path, progress):
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        raise EngineError(f"no such file: {path}", 404)
    gguf_meta(path, limit=1)
    if progress:
        progress({"status": f"reading {os.path.basename(path)}"})
    folder, base = os.path.split(path)
    split = SPLIT_RE.search(base)
    if split:
        sha = hashlib.sha256(path.encode()).hexdigest()
        d = os.path.join(BLOBS, f"sha256-{sha}.d")
        stem = base[:split.start()]
        for f in os.listdir(folder):
            if f.startswith(stem + "-") and SPLIT_RE.search(f):
                _link(os.path.join(folder, f), os.path.join(d, f))
        return Pulled(path, os.path.join("blobs", f"sha256-{sha}.d", base), None, {}, sha)
    sha = _sha(path)
    _link(path, blob_path(_rel(sha)))
    return Pulled(path, _rel(sha), None, {}, sha)


def _default_name(source):
    s = canon(source)
    if s.startswith("hf.co/") or re.fullmatch(r"[\w.-]+(:[\w.-]+)?", s):
        return s
    base = os.path.basename(urllib.parse.urlsplit(s).path if "://" in s else s)
    return re.sub(r"[^\w.-]+", "-", re.sub(r"(?i)\.gguf$", "", SPLIT_RE.sub(".gguf", base))).strip("-").lower()


_HF_ADDRESS = re.compile(r"^(https?://)?(www\.)?(huggingface\.co|hf\.co)/")


def _is_path(src):
    return src.startswith(("/", "~", "./", "../")) or (src.lower().endswith(".gguf") and os.path.exists(src)) \
        or bool(re.match(r"^[A-Za-z]:[\\/]", src))


def _pull_source(src, progress, local_ok):
    """Fetch src with the function for its kind of source. Returns a Pulled."""
    if _HF_ADDRESS.match(src):
        return _pull_hf(src, progress)
    if re.match(r"^https?://", src):
        return _pull_url(src, progress)
    if _is_path(src):
        if not local_ok:
            raise EngineError("a file path can only be pulled from this computer itself", 403)
        return _pull_file(src, progress)
    if canon(src) in LIBRARY:       # stored under the name asked for, fetched from the publisher's repo
        return _pull_hf(LIBRARY[canon(src)], progress)._replace(source=canon(src))
    if re.fullmatch(r"[\w.-]+/[\w.-]+(:[\w.-]+)?", src) and not get(src):
        return _pull_hf(src, progress)
    return _pull_registry(src, progress)


def pull(source, name=None, params=None, progress=None, local_ok=True):
    """Bring a model into the store. source: owner/repo[:QUANT] or a huggingface.co URL; an https URL of a .gguf;
    a .gguf path on this computer; or a library name (qwen3:8b). Returns the manifest."""
    src = str(source or "").strip()
    if not src:
        raise EngineError("pull needs a model", 400)
    os.makedirs(BLOBS, exist_ok=True)
    try:
        got = _pull_source(src, progress, local_ok)
    except ValueError as e:
        raise EngineError(str(e), 400)
    if progress:
        progress({"status": "writing manifest"})
    man = _save(name or _default_name(got.source), got.model, got.mmproj, dict(got.params, **(params or {})),
                got.source, got.digest)
    if not man["info"].get("has_template") and progress:
        progress({"status": "note: this file carries no chat template, so llama.cpp will use ChatML"})
    return man


def _ollama_manifests():
    """(store, model name, manifest file) for every model in the Ollama stores on this computer. Ollama 0.40
    keeps the names it made itself (`create`) under manifests-v2/ollama.com; older ones are in manifests/."""
    seen = set()
    for store, sub in [(st, sub) for st in OLLAMA_STORES for sub in ("manifests", "manifests-v2")]:
        root = os.path.join(store, sub) if store else ""
        if not root or not os.path.isdir(root) or os.path.realpath(root) in seen:
            continue
        seen.add(os.path.realpath(root))
        for d, _dirs, files in os.walk(root):
            for fn in files:
                rel = os.path.relpath(os.path.join(d, fn), root).split(os.sep)
                if len(rel) < 3:
                    continue
                path = re.sub(r"^(registry\.ollama\.ai|ollama\.com)/(library/)?", "", "/".join(rel[:-1]))
                yield store, canon(f"{path}:{rel[-1]}"), os.path.join(d, fn)


def _adopt(store, name, manifest_file):
    """Link one Ollama model's files into the store and write its manifest. None when it has no model file."""
    with open(manifest_file) as f:
        layers = _manifest_layers(json.load(f))
    rels = {}
    for kind in ("model", "projector"):
        if kind in layers:
            sha = _layer_sha(layers[kind])
            src = os.path.join(store, "blobs", "sha256-" + sha)
            gguf_meta(src, limit=1)
            _link(src, blob_path(_rel(sha)))
            rels[kind] = _rel(sha)
    if "model" not in rels:
        return None
    params = {}
    if "params" in layers:
        with contextlib.suppress(OSError):
            with open(os.path.join(store, "blobs", layers["params"]["digest"].replace(":", "-"))) as f:
                params = _params_of(f.read())
    return _save(name, rels["model"], rels.get("projector"), params, "ollama:" + name, _layer_sha(layers["model"]))


def import_ollama(names=None, progress=None):
    """Adopt models from an Ollama store on this computer by hard link. Returns the manifests made."""
    made, done = [], set()
    wanted = {canon(n) for n in names} if names else None
    for store, name, manifest_file in _ollama_manifests():
        if wanted is not None and name not in wanted:
            continue
        try:
            man = _adopt(store, name, manifest_file)
        except (OSError, ValueError, KeyError, struct.error) as e:
            if progress:
                progress({"status": f"skipped {name}: {e}"})
            continue
        if man and name not in done:     # the same name can sit in both of Ollama's manifest directories
            done.add(name)
            made.append(man)
            if progress:
                progress({"status": f"imported {name}"})
    return made


# ------------------------------------------------------------------ the llama.cpp build
def _exe(name="llama-server"):
    return name + (".exe" if os.name == "nt" else "")


def server_path():
    """The llama-server to run: GNOC_LLAMA_SERVER, the installed build, or one on PATH. None when there is none."""
    env = os.environ.get("GNOC_LLAMA_SERVER")
    if env:
        return env if os.path.isfile(env) else None
    try:
        with open(os.path.join(HOME, "current.json")) as f:
            p = json.load(f).get("server")
        if p and os.path.isfile(p):
            return p
    except (OSError, ValueError):
        pass
    return shutil.which("llama-server")


def build_info():
    try:
        with open(os.path.join(HOME, "current.json")) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def gpu():
    """('nvidia'|'amd'|'intel'|'apple'|'', vram bytes) - a best guess, for choosing a build and for size_vram."""
    if sys.platform == "darwin":
        return "apple", 0
    if shutil.which("nvidia-smi"):
        with contextlib.suppress(Exception):
            out = subprocess.run(["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                                 capture_output=True, text=True, timeout=5).stdout
            return "nvidia", max(int(x) for x in out.split()) * (1 << 20)
    best = 0
    try:
        for card in os.listdir("/sys/class/drm"):
            with contextlib.suppress(OSError, ValueError):
                with open(f"/sys/class/drm/{card}/device/mem_info_vram_total") as f:
                    best = max(best, int(f.read()))
    except OSError:
        pass
    return ("amd" if best else ""), best


def free_vram_mib():
    """Free GPU memory now, in MiB (the largest card), or None when it cannot be read."""
    if shutil.which("nvidia-smi"):
        with contextlib.suppress(Exception):
            out = subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                                 capture_output=True, text=True, timeout=5).stdout
            return max(int(x) for x in out.split())
    best = None
    with contextlib.suppress(OSError):
        for card in os.listdir("/sys/class/drm"):
            base = f"/sys/class/drm/{card}/device/"
            with contextlib.suppress(OSError, ValueError):
                with open(base + "mem_info_vram_total") as f:
                    tot = int(f.read())
                with open(base + "mem_info_vram_used") as f:
                    used = int(f.read())
                if best is None or tot > best[0]:
                    best = (tot, (tot - used) >> 20)
    return best[1] if best else None


_HELP = {}
_GPU_NAME = {}


def _server_env(exe):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = os.pathsep.join(_lib_dirs(exe) + ([env["LD_LIBRARY_PATH"]]
                                                           if env.get("LD_LIBRARY_PATH") else []))
    return env


def server_supports(exe, flag):
    """True when this llama-server build knows `flag` (or, for a value such as 'ngram-mod', lists it). Builds add,
    rename and drop flags, and an unknown flag makes llama-server exit before it loads anything."""
    if not exe:
        return False
    if exe not in _HELP:
        txt = ""
        with contextlib.suppress(Exception):
            txt = subprocess.run([exe, "--help"], capture_output=True, text=True, errors="replace", timeout=20,
                                 env=_server_env(exe), stdin=subprocess.DEVNULL).stdout
        _HELP[exe] = txt
    return bool(re.search(r"(?:^|[\s,{])" + re.escape(flag) + r"(?=[\s,}]|$)", _HELP[exe], re.M))


def gpu_name():
    """The name of the GPU llama-server runs on ('AMD Radeon RX 7700S'): the --device GNOC_ENGINE_ARGS names, else
    the first real one (llvmpipe is the CPU). '' when there is none, or the build cannot list them."""
    exe = server_path()
    if not exe:
        return ""
    if exe not in _GPU_NAME:
        out = ""
        with contextlib.suppress(Exception):
            out = subprocess.run([exe, "--list-devices"], capture_output=True, text=True, errors="replace",
                                 timeout=20, env=_server_env(exe), stdin=subprocess.DEVNULL).stdout
        devs = re.findall(r"(?m)^\s*(\w+): (.+?)(?: \(\d+ MiB, \d+ MiB free\))?\s*$", out)
        devs = [(i, d) for i, d in devs if "llvmpipe" not in d.lower()]
        args = shlex.split(os.environ.get("GNOC_ENGINE_ARGS", ""))
        want = next((args[i + 1] for i, a in enumerate(args[:-1]) if a in ("--device", "-dev")), "")
        pick = next((d for i, d in devs if i == want), devs[0][1] if devs else "")
        _GPU_NAME[exe] = re.sub(r"\s*\([^()]*\)$", "", pick).strip()
    return _GPU_NAME[exe]


def _ctx_file():
    return os.path.join(HOME, "context.json")


def ctx_settings():
    """{gpu name or '*': 'auto' | tokens}, what `gnoc engine context` saved."""
    try:
        with open(_ctx_file()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def parse_ctx(v):
    """'auto', or a window in tokens from '32768', '32k', '64K'. None when it is neither."""
    t = str(v or "").strip().lower().replace(",", "").replace("_", "")
    if t in ("auto", "default"):
        return "auto"
    m = re.fullmatch(r"(\d+)(k?)", t)
    if not m:
        return None
    n = int(m.group(1)) * (1024 if m.group(2) else 1)
    return n if n >= 2048 else None


def ctx_choice(name=None):
    """'auto' or a window in tokens for this GPU: GNOC_ENGINE_CTX, else what `gnoc engine context` saved for this
    GPU, else for every GPU ('*'), else 'auto'."""
    env = parse_ctx(os.environ.get("GNOC_ENGINE_CTX", ""))
    if env:
        return env
    d = ctx_settings()
    name = gpu_name() if name is None else name
    v = parse_ctx(d.get(name)) if name else None
    return v or parse_ctx(d.get("*")) or "auto"


def can_fit_ctx():
    """True when the window can be fitted to a real GPU: one is there, and this llama.cpp has --fit-ctx."""
    if soft_gpu_marked() or "none" in shlex.split(os.environ.get("GNOC_ENGINE_ARGS", "")):
        return False
    if not (gpu()[1] or sys.platform == "darwin"):
        return False
    return server_supports(server_path(), "--fit-ctx")


def _soft_gpu_path():
    return os.path.join(HOME, "vulkan-is-software.json")


def soft_gpu_marked():
    """True once a runner here found only llvmpipe, for this llama.cpp build (a new build or driver re-checks)."""
    if os.environ.get("GNOC_ENGINE_CPU") == "1":
        return True
    try:
        with open(_soft_gpu_path()) as f:
            d = json.load(f)
        return d.get("server") == server_path() and not os.environ.get("GNOC_ENGINE_RECHECK_GPU")
    except (OSError, ValueError):
        return False


def mark_soft_gpu(log=""):
    with contextlib.suppress(OSError):
        os.makedirs(HOME, exist_ok=True)
        with open(_soft_gpu_path(), "w") as f:
            json.dump({"server": server_path(), "at": time.time(), "log": log}, f)


def gpu_holders():
    """Who else holds GPU memory, in words, for 'your model is on the CPU' (an Ollama beside gnoc's engine held
    qwen3:8b, and the engine's 9B loaded 0/33 layers on the GPU: 7 tok/s instead of 39, engine QAQC 2026-11-23)."""
    out = []
    own = os.environ.get("GNOC_ENGINE_ADDR", "127.0.0.1:11434").rsplit(":", 1)[-1]
    for port in ("11434", "11435", "11439"):
        if port == own:
            continue
        with contextlib.suppress(Exception):
            import urllib.request
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/ps", timeout=2) as r:
                rows = [m for m in (json.loads(r.read()).get("models") or []) if int(m.get("size_vram") or 0) > 0]
            if rows:
                out.append(f"the model server on port {port} (an Ollama, or another engine) holds "
                           + ", ".join(f"{m.get('name')} ({int(m.get('size_vram') or 0) >> 30} GB)" for m in rows))
    return "; ".join(out)


def on_android():
    """True inside Termux (or any Python on Android). gnoc_platform owns the test now (one detector for the
    installer, doctor, setup and defender); the inline copy stays because this file is pushed ALONE onto a phone
    (gnoc_phone.PHONE_SETUP copies only gnoc_engine.py), where there is no gnoc_platform to import."""
    try:
        import gnoc_platform
    except ImportError:
        return hasattr(sys, "getandroidapilevel") or bool(os.environ.get("TERMUX_VERSION")) \
            or os.path.isdir("/data/data/com.termux/files/usr")
    return gnoc_platform.on_android()


def pick_variant():
    """The llama.cpp release build for this computer. Vulkan runs on NVIDIA, AMD and Intel cards with a normal
    driver and falls back to the CPU without one, so it is the default wherever a GPU might exist."""
    import platform
    mach = platform.machine().lower()
    arm = mach in ("arm64", "aarch64")
    if on_android():        # Termux on a phone: Android's own C library, so only the Android build runs
        return "android-arm64"
    if sys.platform == "darwin":
        return "macos-arm64" if arm else "macos-x64"
    if os.name == "nt":
        if not arm and gpu()[0] == "nvidia":
            # native Windows with an NVIDIA card: the CUDA build, faster than Vulkan on the same card (GreyNOC
            # 2026-11-25, an RTX 5060 Ti); its runtime DLLs are unpacked beside llama-server.exe
            return WIN_CUDA_VARIANT
        return "win-vulkan-arm64" if arm else "win-vulkan-x64"
    if not arm and gpu()[0] == "nvidia":
        # an NVIDIA card on Linux or WSL: llama.cpp's CUDA build (and its runtime, fetched beside it). Under WSL the
        # Vulkan build found no Vulkan driver for the card and ran on llvmpipe, a software rasteriser on the CPU:
        # "hello" stalled past a minute with the GPU at 1% (GreyNOC 2026-11-23, an RTX 5060 under WSL).
        return CUDA_VARIANT
    return "ubuntu-vulkan-arm64" if arm else "ubuntu-vulkan-x64"


CUDA_VARIANT = "ubuntu-cuda-12.8-x64"   # 12.8 runs every card from Maxwell to Blackwell (RTX 50) on current drivers
# the --variant a user is told to install for an NVIDIA card: Windows has no 12.8 build (its CUDA builds are 12.4,
# too old for Blackwell, and 13.5), so the hint there names 13.5
CUDA_HINT = "cuda-13.5" if os.name == "nt" else "cuda-12.8"
# llama.cpp's Windows CUDA builds are 12.4 and 13.x only; 12.4 predates Blackwell (sm_120 needs CUDA 12.8 or newer),
# so 13.5. CUDA 13 needs an NVIDIA driver of 580 or newer and a Turing (RTX 20) or newer card; an older card takes
# --variant vulkan (asset names read from release b12728, 2026-11-25).
WIN_CUDA_VARIANT = "win-cuda-13.5-x64"


def _cudart_re(tag, variant):
    """The CUDA runtime archive beside a CUDA build. The Linux one carries the tag
    (cudart-llama-b12728-bin-ubuntu-cuda-12.8-x64.tar.gz), the Windows one does not
    (cudart-llama-bin-win-cuda-13.5-x64.zip)."""
    return re.compile(rf"^cudart-llama-(?:{re.escape(tag)}-)?bin-{re.escape(variant)}\.(tar\.gz|zip)$")


def _lib_dirs(exe):
    """Where llama-server's shared libraries are: its own folder, the CUDA runtime unpacked beside the build, and
    WSL's driver folder (libcuda lives there)."""
    out = [os.path.dirname(exe)]
    root = os.path.dirname(exe)
    base = os.path.join(HOME, "llama.cpp")
    while os.path.dirname(root) not in (base, root) and len(root) > len(base):
        root = os.path.dirname(root)
    for d, _s, fs in os.walk(root):
        if d not in out and any(f.startswith(("libcudart.so", "libcublas")) for f in fs):
            out.append(d)
    if os.path.isdir("/usr/lib/wsl/lib"):
        out.append("/usr/lib/wsl/lib")
    return out


def software_vulkan():
    """True when the newest runner log shows Vulkan running on llvmpipe (a CPU software driver), so the model is
    on the CPU at its slowest whatever the GPU column says."""
    d = os.path.join(HOME, "runners")
    try:
        logs = sorted((os.path.join(d, f) for f in os.listdir(d) if f.endswith(".log")), key=os.path.getmtime)
    except OSError:
        return False
    for path in reversed(logs[-3:]):
        try:
            with open(path, "rb") as fh:
                head = fh.read(200_000).decode("utf-8", "replace").lower()
        except OSError:
            continue
        if "ggml_vulkan" in head or "vulkan" in head:
            return "llvmpipe" in head
    return False


def _releases(tag=None):
    """llama.cpp's releases, newest first (or the one release with this tag)."""
    api_url = f"https://api.github.com/repos/{LLAMA_REPO}/releases"
    return [_json(f"{api_url}/tags/{tag}")] if tag else _json(f"{api_url}?per_page=10")


def _find_build(rels, variant):
    """(release, asset) for the newest release that carries a build for variant; (None, None) when none does."""
    for rel in rels:
        want = re.compile(rf"^llama-{re.escape(rel.get('tag_name') or '')}-bin-{re.escape(variant)}\.(tar\.gz|zip)$")
        asset = next((a for a in rel.get("assets") or [] if want.match(a.get("name") or "")), None)
        if asset:
            return rel, asset
    return None, None


def _unpack(arc, dest, label):
    """Extract a release archive into dest, refusing one that would write anywhere else."""
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    root = os.path.realpath(dest) + os.sep
    inside = lambda *parts: os.path.realpath(os.path.join(dest, *parts)).startswith(root)   # noqa: E731
    if arc.endswith(".zip"):
        with zipfile.ZipFile(arc) as z:
            for n in z.namelist():
                if not inside(n):
                    raise EngineError(f"refusing {label}: it writes outside its directory ({n})", 502)
            z.extractall(dest)
        return
    with tarfile.open(arc) as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:   # Python before the extraction filters: check the names by hand
            for m in t.getmembers():
                if not inside(m.name) or m.issym() and not inside(os.path.dirname(m.name), m.linkname):
                    raise EngineError(f"refusing {label}: it writes outside its directory", 502)
            t.extractall(dest)


def install(variant=None, tag=None, progress=None):
    """Download a llama.cpp release build into GNOC_ENGINE_HOME and make it the one the engine runs."""
    variant = variant or pick_variant()
    if not re.match(r"^(ubuntu|win|macos|linux)", variant):
        variant = ("win-" if os.name == "nt" else "ubuntu-") + variant + ("-x64" if not variant.endswith("64") else "")
    rels = _releases(tag)
    rel, asset = _find_build(rels, variant)
    if not asset:
        have = sorted({re.sub(r"^llama-[^-]+-bin-|\.(tar\.gz|zip)$", "", a["name"]) for r in rels
                       for a in r.get("assets") or [] if a["name"].startswith("llama-") and "-bin-" in a["name"]})
        raise EngineError(f"no llama.cpp build named {variant!r}; there are: {', '.join(have) or 'none'}", 404)
    tag = rel["tag_name"]
    dest = os.path.join(HOME, "llama.cpp", f"{tag}-{variant}")
    arc = os.path.join(HOME, "llama.cpp", asset["name"])
    sha = (asset.get("digest") or "").partition("sha256:")[2] or None
    fetch(asset["browser_download_url"], arc, asset.get("size") or 0, sha, progress, asset["name"])
    _unpack(arc, dest, asset["name"])
    os.remove(arc)
    exe = next((os.path.join(d, f) for d, _s, fs in os.walk(dest) for f in fs if f == _exe()), None)
    if not exe:
        raise EngineError(f"{asset['name']} has no {_exe()} in it", 502)
    os.chmod(exe, 0o755)
    if "cuda" in variant:
        # the CUDA build needs the CUDA runtime and cuBLAS; llama.cpp publishes them as a second archive
        want = _cudart_re(tag, variant)
        rt = next((a for a in rel.get("assets") or [] if want.match(a.get("name") or "")), None)
        if not rt:
            raise EngineError(f"llama.cpp {tag} has no CUDA runtime archive for {variant}", 404)
        rt_arc = os.path.join(HOME, "llama.cpp", rt["name"])
        fetch(rt["browser_download_url"], rt_arc, rt.get("size") or 0,
              (rt.get("digest") or "").partition("sha256:")[2] or None, progress, rt["name"])
        _unpack(rt_arc, os.path.join(dest, "cudart"), rt["name"])
        os.remove(rt_arc)
        if variant.startswith("win-"):
            # Windows loads a DLL from the exe's own folder or PATH, never from LD_LIBRARY_PATH: put the runtime
            # (cudart64_13.dll, cublas64_13.dll, cublasLt64_13.dll) beside llama-server.exe
            for d, _s, fs in os.walk(os.path.join(dest, "cudart")):
                for f in fs:
                    if f.lower().endswith(".dll"):
                        os.replace(os.path.join(d, f), os.path.join(os.path.dirname(exe), f))
    _write_json(os.path.join(HOME, "current.json"), {"server": exe, "tag": tag, "variant": variant,
                                                     "installed_at": _now().isoformat()})
    return {"server": exe, "tag": tag, "variant": variant}


def update(progress=None):
    """Install the newest llama.cpp build when it is newer than the one in use, and remove the older ones.
    Returns {'tag', 'was', 'changed'}."""
    cur = build_info()
    variant = cur.get("variant") or pick_variant()
    rel, _asset = _find_build(_releases(), variant)
    if not rel:
        raise EngineError(f"no llama.cpp build for {variant} in the newest releases", 404)
    newest = rel["tag_name"]
    if newest == cur.get("tag") and server_path():
        return {"tag": newest, "was": newest, "changed": False}
    install(variant, newest, progress)
    root = os.path.join(HOME, "llama.cpp")
    for d in os.listdir(root):
        if d != f"{newest}-{variant}" and os.path.isdir(os.path.join(root, d)):
            shutil.rmtree(os.path.join(root, d), ignore_errors=True)   # a build still running keeps its files open
    return {"tag": newest, "was": cur.get("tag") or "", "changed": True}


# ------------------------------------------------------------------ images
# Text-to-image with stable-diffusion.cpp (the image counterpart of llama.cpp), so a clean install makes pictures with
# nothing else set up (GreyNOC 2026-11-23: "for a clean install ... even the image gen should work"). The model is
# sized to the card, permissive licences only: SDXL base (CreativeML OpenRAIL++-M) where a GPU has 10 GB or more,
# Stable Diffusion 1.5 (CreativeML OpenRAIL-M) everywhere else, both as Q8_0 GGUF.
SD_REPO = "leejet/stable-diffusion.cpp"
SD_HOME = os.path.join(HOME, "sd.cpp")
IMAGE_DIR = os.path.join(MODELS, "image")
IMAGE_MODELS = {
    "sd15": {"label": "Stable Diffusion 1.5", "licence": "CreativeML OpenRAIL-M",
             "repo": "second-state/stable-diffusion-v1-5-GGUF", "file": "stable-diffusion-v1-5-pruned-emaonly-Q8_0.gguf",
             "width": 512, "height": 512, "steps": 20, "cfg": 7.0},
    "sdxl": {"label": "Stable Diffusion XL", "licence": "CreativeML OpenRAIL++-M",
             "repo": "gpustack/stable-diffusion-xl-base-1.0-GGUF", "file": "stable-diffusion-xl-base-1.0-Q8_0.gguf",
             # the fp16-safe VAE (MIT): SDXL's own decodes to black at fp16 on many cards
             "vae": ("madebyollin/sdxl-vae-fp16-fix", "sdxl_vae.safetensors"),
             "width": 1024, "height": 1024, "steps": 25, "cfg": 6.0},
}
# the glibc an Ubuntu release ships: a Linux build made on a newer Ubuntu does not start on an older system
_UBUNTU_GLIBC = {"20.04": (2, 31), "22.04": (2, 35), "24.04": (2, 39), "25.04": (2, 41), "25.10": (2, 42),
                 "26.04": (2, 43)}


def pick_image_model():
    """'sdxl' on a GPU with 10 GB or more that the image build can use, 'sd15' otherwise (GNOC_IMAGE_MODEL wins)."""
    want = os.environ.get("GNOC_IMAGE_MODEL", "").strip().lower()
    if want in IMAGE_MODELS:
        return want
    kind, vram = gpu()
    if sys.platform == "darwin":
        return "sdxl" if ram_bytes() >= 24 * (1 << 30) else "sd15"
    if kind and vram >= 10 * (1 << 30) and not on_wsl():   # WSL runs the CPU build: SDXL there takes minutes
        return "sdxl"
    return "sd15"


def _glibc():
    import platform
    with contextlib.suppress(Exception):
        lib, ver = platform.libc_ver()
        if lib == "glibc" and ver:
            return tuple(int(x) for x in ver.split(".")[:2])
    return (0, 0)


def _sd_wanted():
    """A regex for the stable-diffusion.cpp build this computer runs (Vulkan where a GPU driver is there, the CPU
    build under WSL, where Vulkan is a software rasteriser on an NVIDIA card)."""
    import platform
    if sys.platform == "darwin":
        return r"Darwin-macOS-[\d.]+-arm64" if platform.machine().lower() in ("arm64", "aarch64") else r"Darwin-.*-x86_64"
    kind = gpu()[0]
    if os.name == "nt":
        return r"win-vulkan-x64" if kind else r"win-cpu-x64"
    if kind and not on_wsl():
        return r"Linux-Ubuntu-(\d+\.\d+)-x86_64-vulkan"
    return r"Linux-Ubuntu-(\d+\.\d+)-x86_64"


def _sd_find(rels, wanted):
    """(release, asset) for the newest release with a build this computer can run, or (None, None)."""
    mine = _glibc()
    for rel in rels:
        for a in rel.get("assets") or []:
            m = re.match(rf"^sd-.+-bin-{wanted}\.zip$", a.get("name") or "")
            if not m:
                continue
            if m.groups() and sys.platform.startswith("linux"):
                need = _UBUNTU_GLIBC.get(m.group(1), (9, 99))
                if mine < need:
                    continue      # built against a newer glibc than this system has: it would not start
            return rel, a
    return None, None


def sd_path():
    """The stable-diffusion.cpp command line program, or None when it is not installed."""
    try:
        with open(os.path.join(SD_HOME, "current.json")) as f:
            p = json.load(f).get("exe")
        return p if p and os.path.isfile(p) else None
    except (OSError, ValueError):
        return None


def install_sd(progress=None):
    """Download the stable-diffusion.cpp build for this computer, checked against GitHub's published checksum."""
    wanted = _sd_wanted()
    rels = _json(f"https://api.github.com/repos/{SD_REPO}/releases?per_page=60")
    rel, asset = _sd_find(rels if isinstance(rels, list) else [], wanted)
    if not asset:
        why = (f" (this system has glibc {'.'.join(map(str, _glibc()))}; the builds need a newer one)"
               if sys.platform.startswith("linux") else "")
        raise EngineError(f"no stable-diffusion.cpp build for this computer{why}", 404)
    tag = rel["tag_name"]
    dest = os.path.join(SD_HOME, tag)
    arc = os.path.join(SD_HOME, asset["name"])
    sha = (asset.get("digest") or "").partition("sha256:")[2] or None
    fetch(asset["browser_download_url"], arc, asset.get("size") or 0, sha, progress, asset["name"])
    _unpack(arc, dest, asset["name"])
    os.remove(arc)
    names = ("sd-cli.exe", "sd.exe") if os.name == "nt" else ("sd-cli", "sd")
    exe = next((os.path.join(d, f) for name in names for d, _s, fs in os.walk(dest) for f in fs if f == name), None)
    if not exe:
        raise EngineError(f"{asset['name']} has no {names[0]} in it", 502)
    os.chmod(exe, 0o755)
    _write_json(os.path.join(SD_HOME, "current.json"), {"exe": exe, "tag": tag, "asset": asset["name"],
                                                        "installed_at": _now().isoformat()})
    return {"exe": exe, "tag": tag}


def _hf_file(repo, path):
    """(url, size, sha256) of one file in a Hugging Face repo, from its tree listing."""
    rows = _json(f"https://huggingface.co/api/models/{repo}/tree/main")
    row = next((r for r in rows or [] if isinstance(r, dict) and r.get("path") == path), None)
    if not row:
        raise EngineError(f"{repo} has no {path}", 404)
    return (f"https://huggingface.co/{repo}/resolve/main/{urllib.parse.quote(path)}", int(row.get("size") or 0),
            (row.get("lfs") or {}).get("oid") or None)


def image_files(name):
    m = IMAGE_MODELS[name]
    out = {"model": os.path.join(IMAGE_DIR, m["file"])}
    if m.get("vae"):
        out["vae"] = os.path.join(IMAGE_DIR, m["vae"][1])
    return out


def image_ready(name=None):
    return bool(sd_path()) and all(os.path.isfile(p) for p in image_files(name or pick_image_model()).values())


def pull_image_model(name, progress=None):
    m = IMAGE_MODELS[name]
    wanted = [(m["repo"], m["file"])] + ([m["vae"]] if m.get("vae") else [])
    for repo, path in wanted:
        url, size, sha = _hf_file(repo, path)
        fetch(url, os.path.join(IMAGE_DIR, os.path.basename(path)), size, sha, progress, os.path.basename(path))
    return image_files(name)


def _free_gpu():
    """Unload the idle chat models so the image model has the card (the next chat message loads them again)."""
    with contextlib.suppress(Exception):
        with POOL.cv:
            for k, r in list(POOL.runners.items()):
                if r.active == 0:
                    POOL.runners.pop(k).stop()
            POOL.cv.notify_all()


def _dims(v, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(256, min(1536, (v // 64) * 64))


def make_image(prompt, negative="", width=None, height=None, steps=None, seed=-1, model=None, progress=None):
    """One PNG for prompt. Installs stable-diffusion.cpp and the image model on first use. -> (png bytes, info)."""
    prompt = str(prompt or "").strip()
    if not prompt:
        raise EngineError("an image needs a prompt", 400)
    name = model if model in IMAGE_MODELS else pick_image_model()
    m = IMAGE_MODELS[name]
    say = progress or (lambda row: None)
    if not sd_path():
        say({"status": "installing stable-diffusion.cpp (once)"})
        install_sd(progress)
    files = image_files(name)
    if not all(os.path.isfile(p) for p in files.values()):
        say({"status": f"downloading {m['label']} ({m['licence']}), once"})
        files = pull_image_model(name, progress)
    _free_gpu()
    w, h = _dims(width, m["width"]), _dims(height, m["height"])
    try:
        # the shape he asked for, before the 1536 cap: 1920x1080 capped to 1536x1024 is 3:2, and a 16:9 desktop
        # wallpaper came back 768x512 (image drive batch 4). Scale the asked shape; cap the size after.
        rw, rh = max(64, int(width)), max(64, int(height))
        if max(rw, rh) > 1536:
            k0 = 1536 / max(rw, rh)
            w, h = _dims(rw * k0, w), _dims(rh * k0, h)
    except (TypeError, ValueError):
        pass
    if name == "sd15" and max(w, h) / min(w, h) < 1.3:
        if max(w, h) > 768:   # near-square: 768 a side drew well in the image drive
            k = 768 / max(w, h)
            w, h = _dims(w * k, 512), _dims(h * k, 512)
    elif name == "sd15" and min(w, h) > 512:
        # SD 1.5 is trained at 512: a short side much over that draws its subject twice. Same shape, short side 512,
        # long side at most 1024 (a landscape was 768x384 when the LONG side was held to 768: image drive).
        k = 512 / min(w, h)
        w, h = _dims(w * k, 512), _dims(h * k, 512)
        if max(w, h) > 1024:
            k2 = 1024 / max(w, h)
            w, h = _dims(w * k2, 512), _dims(h * k2, 512)
    n = max(1, min(60, int(steps or m["steps"])))
    try:
        s = int(seed)
    except (TypeError, ValueError):
        s = -1
    out = os.path.join(SD_HOME, f"out-{os.getpid()}-{threading.get_ident()}.png")
    exe = sd_path()
    base = [exe, "-m", files["model"], "-p", prompt, "-n", str(negative or ""), "-W", str(w), "-H", str(h),
            "--steps", str(n), "--cfg-scale", str(m["cfg"]), "-s", str(s), "-o", out]
    if files.get("vae"):
        base += ["--vae", files["vae"]]
    env = dict(os.environ)
    if not os.name == "nt":
        d = os.path.dirname(exe)
        env["LD_LIBRARY_PATH"] = d + (os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    say({"status": f"drawing {w}x{h} with {m['label']}, {n} steps"})
    t0 = time.time()
    tail = ""
    for extra in ([], ["--vae-tiling", "--offload-to-cpu"]):   # a card too small: weights in RAM, the VAE in tiles
        with contextlib.suppress(OSError):
            os.remove(out)
        r = subprocess.run(base + extra, capture_output=True, text=True, errors="replace", env=env,
                           timeout=float(os.environ.get("GNOC_IMAGE_TIMEOUT", "1800")))
        tail = (r.stdout + r.stderr)[-600:]
        if r.returncode == 0 and os.path.isfile(out) and os.path.getsize(out) > 0:
            break
    else:
        raise EngineError("stable-diffusion.cpp made no image: " + tail.strip().splitlines()[-1:][0]
                          if tail.strip() else "stable-diffusion.cpp made no image", 500)
    with open(out, "rb") as f:
        png = f.read()
    with contextlib.suppress(OSError):
        os.remove(out)
    return png, {"model": name, "label": m["label"], "width": w, "height": h, "steps": n, "seed": s,
                 "seconds": round(time.time() - t0, 1)}


# ------------------------------------------------------------------ runners
def keep_alive_secs(v, default=None):
    """Ollama's keep_alive: seconds as a number, or '30m' / '1h30m' / '45s'; negative = for ever."""
    if v is None or v == "":
        return keep_alive_secs(os.environ.get("GNOC_ENGINE_KEEP_ALIVE", "5m"), 300) if default is None else default
    if isinstance(v, bool):
        return 300
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().lower()
    with contextlib.suppress(ValueError):
        return float(s)
    total, hit = 0.0, False
    for num, unit in re.findall(r"(-?\d+(?:\.\d+)?)(ms|h|m|s)", s):
        total += float(num) * {"h": 3600, "m": 60, "s": 1, "ms": .001}[unit]
        hit = True
    return total if hit else (300 if default is None else default)


def is_embedder(man):
    return "embedding" in ((man.get("info") or {}).get("capabilities") or [])


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Runner:
    """One llama-server process serving one model at one context size."""

    def __init__(self, man, ctx, embed=False, auto=False):
        self.name, self.man, self.ctx, self.embed = man["name"], man, ctx, embed
        self.auto = auto   # the window is llama.cpp's fit to the GPU (-c 0); self.ctx is learned once it loads
        self.digest = man.get("digest")
        self.port = _free_port()
        self.active = 0
        self.used = time.time()
        self.expires = time.time() + 300
        self.loaded_in = 0.0
        self.log = os.path.join(HOME, "runners", re.sub(r"[^\w.-]+", "_", self.name)[-80:] + ".log")
        self.proc = None

    def _command(self, exe):
        """The llama-server command line for this model: one slot with the whole window, no web page, no network."""
        win = (["-c", "0", "--fit-target", str(FIT_MARGIN), "--fit-ctx", str(AUTO_MIN)]
               if getattr(self, "auto", False) else ["-c", str(self.ctx)])
        cmd = [exe, "-m", blob_path(self.man["model"]), "--host", "127.0.0.1", "--port", str(self.port),
               *win, "-np", "1", "--no-webui", "--offline", "--jinja", "-lv", "4",
               # prompt batch 512, as Ollama runs it: 2048 was ~2-4% slower on long prompts on an RX 7700S (Vulkan),
               # and 1024/2048 micro-batches slower still (engine QAQC against Ollama, 2026-11-23)
               "-b", os.environ.get("GNOC_ENGINE_BATCH", "512")]
        if self.man.get("mmproj"):
            cmd += ["--mmproj", blob_path(self.man["mmproj"])]
        if SPEC.lower() not in ("", "none", "off", "0") and not getattr(self, "embed", False) \
                and server_supports(exe, "--spec-type") and server_supports(exe, SPEC):
            cmd += ["--spec-type", SPEC]
        if self.embed:
            # llama-server gives vectors only when started for it. A chat model started this way still chats,
            # and needs to be told how to pool; an embedding model carries its own pooling.
            cmd += ["--embeddings"] + ([] if is_embedder(self.man) else ["--pooling", "mean"])
        if getattr(self, "cpu_only", False) or soft_gpu_marked():
            # Vulkan's only device here is llvmpipe, a software rasteriser on the CPU: llama.cpp's own CPU backend is
            # far faster than "offloading" to it (GreyNOC 2026-11-23: "the models are automatically using cpu instead
            # of gpu on user computers")
            cmd += ["--device", "none"]
        return cmd + shlex.split(os.environ.get("GNOC_ENGINE_ARGS", ""))

    def _healthy(self):
        with contextlib.suppress(OSError, http.client.HTTPException):
            c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
            try:
                c.request("GET", "/health")
                return c.getresponse().status == 200
            finally:
                c.close()
        return False

    def start(self):
        """Start llama-server and wait until the model is loaded. Raises when it exits or takes too long."""
        exe = server_path()
        if not exe:
            raise EngineError("llama.cpp is not installed: run  gnoc engine install", 503)
        cmd = self._command(exe)
        os.makedirs(os.path.dirname(self.log), exist_ok=True)
        t0 = time.time()
        env = dict(os.environ)
        env["LD_LIBRARY_PATH"] = os.pathsep.join(_lib_dirs(exe) + ([env["LD_LIBRARY_PATH"]]
                                                               if env.get("LD_LIBRARY_PATH") else []))
        with open(self.log, "wb") as lf:
            lf.write((" ".join(shlex.quote(c) for c in cmd) + "\n").encode())
            lf.flush()
            self.proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
        with contextlib.suppress(OSError):
            with open(self.log + ".pid", "w") as pf:     # for stop_orphans(), should this server be killed
                json.dump({"pid": self.proc.pid, "port": self.port}, pf)
        while True:
            if self.proc.poll() is not None:
                raise EngineError(f"llama-server exited while loading {self.name}: {self.log_tail()}"
                                  + self._format_hint(), 500)
            if self._healthy():
                break
            if time.time() - t0 > LOAD_TIMEOUT:
                self.stop()
                raise EngineError(f"{self.name} did not finish loading in {LOAD_TIMEOUT:.0f}s: {self.log_tail()}", 504)
            time.sleep(0.15)
        self.loaded_in = time.time() - t0
        if not getattr(self, "cpu_only", False) and self.on_llvmpipe():
            print(f"gnoc-engine: {self.name}: Vulkan has no GPU driver here (llvmpipe, a CPU software driver); "
                  "restarting it on llama.cpp's faster CPU backend", flush=True)
            mark_soft_gpu(self.log)
            self.stop()
            self.cpu_only = True
            self.auto = False
            self.ctx = max(self.ctx, DEFAULT_CTX)
            self.port = _free_port()
            return self.start()
        if getattr(self, "auto", False):
            got = self.live_ctx()
            if got:
                self.ctx = got
            if self.ctx > AUTO_MAX:
                # a big card fits more than any prompt here needs: a fixed window keeps the rest of it free
                self.stop()
                self.auto, self.ctx, self.port = False, AUTO_MAX, _free_port()
                return self.start()
        return self

    def live_ctx(self):
        """The window llama-server really has (with -c 0 its fit chose it): /props, else its log. 0 if unknown."""
        with contextlib.suppress(OSError, ValueError, http.client.HTTPException, TypeError):
            c = self.conn(5)
            try:
                c.request("GET", "/props")
                d = json.loads(c.getresponse().read())
            finally:
                c.close()
            n = int((d.get("default_generation_settings") or {}).get("n_ctx") or d.get("n_ctx") or 0)
            if n:
                return n
        m = re.findall(r"n_ctx_seq\s+=\s+(\d+)", self._log_head()) or re.findall(r"n_ctx\s+=\s+(\d+)", self._log_head())
        return int(m[-1]) if m else 0

    def _format_hint(self):
        """A model from Ollama's own library can be in a format only Ollama reads (qwen2.5vl:7b was): say what to
        do instead of leaving a bare 'failed to load model'."""
        src = str(self.man.get("source") or "")
        if src.startswith("ollama:") or not src.startswith(("hf.co/", "http", "/")):
            return _say("  (this copy came from Ollama's library, and some of those are in a format only Ollama "
                        "reads: pull a GGUF build of the model from Hugging Face instead, gnoc engine pull "
                        "<owner/repo>)")
        return ""

    def log_tail(self, n=3):
        try:
            with open(self.log, errors="replace") as f:
                lines = [ln.strip() for ln in f.read()[-4000:].splitlines() if ln.strip()]
            bad = [ln for ln in lines if re.search(r"(?i)error|failed|unable|cannot|invalid", ln)]
            return " | ".join((bad or lines)[-n:])[:500]
        except OSError:
            return ""

    def _log_head(self):
        try:
            with open(self.log, errors="replace") as f:
                return f.read(300000)
        except OSError:
            return ""

    def on_llvmpipe(self):
        """True when this runner's Vulkan device is llvmpipe (the model 'offloaded' to a CPU software driver)."""
        head = self._log_head().lower()
        return "llvmpipe" in head and "using device" in head and "vulkan" in head

    def gpu_device(self):
        """The GPU this runner really uses ('AMD Radeon RX 7700S'), or '' when it found none. llama.cpp logs
        'offloaded 33/33 layers to GPU' even when Vulkan said 'No devices found' and every layer is on the CPU, so
        the layer count alone reported a CPU-only model as all on the GPU (engine QAQC, 2026-11-23)."""
        import re as _re
        head = self._log_head()
        m = _re.search(r"using device \S+ \(([^)]*)\)", head)
        if m and "llvmpipe" not in m.group(1).lower():
            return m.group(1)
        return ""

    def on_cpu(self):
        """True when no real GPU serves this runner (no device found, llvmpipe, or --device none)."""
        if getattr(self, "cpu_only", False):
            return True
        head = self._log_head()
        if not head or "load_tensors" not in head:
            return False   # still loading: unknown is not CPU
        low = head.lower()
        if self.on_llvmpipe():
            return True
        # explicit signs only: an older build may not log "using device", and silence is not the CPU
        no_dev = any(s in low for s in ("ggml_vulkan: no devices found", "no cuda-capable device",
                                        "ggml_cuda_init: failed", "cuda driver version is insufficient"))
        return no_dev and not self.gpu_device()

    def gpu_short(self):
        """MiB of GPU memory this runner wanted when it loaded with layers left on the CPU for lack of room, else 0
        (a model that does not fit the card at all, or a CPU-only build, is not 'short': nothing frees up for it)."""
        try:
            with open(self.log, errors="replace") as f:
                head = f.read(400000)
        except OSError:
            return 0
        off = re.findall(r"offloaded (\d+)/(\d+) layers to GPU", head)
        want = re.findall(r"projected to use (\d+) MiB of device memory vs\. (\d+) MiB of free device memory", head)
        if not off or not want or int(off[-1][0]) >= int(off[-1][1]):
            return 0
        need, free = int(want[0][0]), int(want[0][1])
        total = (gpu()[1] >> 20) or 0
        return need if free < need and (not total or need < total - 512) else 0

    def size_vram(self):
        """Bytes of the model on the GPU, from the layer split llama-server logged ('offloaded 29/29 layers').
        llvmpipe and --device none are the CPU: 0, whatever the layer count says."""
        if self.on_cpu():
            return 0
        try:
            with open(self.log, errors="replace") as f:
                m = re.findall(r"offloaded (\d+)/(\d+) layers to GPU", f.read(200000))
        except OSError:
            m = []
        if not m or not int(m[-1][1]):
            return 0
        return int(self.man.get("size", 0) * int(m[-1][0]) / int(m[-1][1]))

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        with contextlib.suppress(OSError):
            os.remove(self.log + ".pid")

    def conn(self, timeout=None):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)


def stop_orphans():
    """End llama-servers a previous engine left behind (it was killed, or the machine slept through its exit): a
    forgotten runner keeps its model in GPU memory. Only a process that still answers as llama-server on the
    port its pid file names is touched."""
    d = os.path.join(HOME, "runners")
    try:
        files = [f for f in os.listdir(d) if f.endswith(".pid")]
    except OSError:
        return 0
    n = 0
    for fn in files:
        path = os.path.join(d, fn)
        try:
            with open(path) as f:
                row = json.load(f)
            c = http.client.HTTPConnection("127.0.0.1", int(row["port"]), timeout=2)
            try:
                c.request("GET", "/health")
                is_runner = "llama" in (c.getresponse().getheader("Server") or "").lower()
            finally:
                c.close()
            if is_runner:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/F", "/PID", str(int(row["pid"]))], capture_output=True)
                else:
                    os.kill(int(row["pid"]), signal.SIGTERM)
                n += 1
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            pass
        with contextlib.suppress(OSError):
            os.remove(path)
    return n


class Pool:
    """The loaded models. A request takes a runner (loading it, and unloading idle ones to make room), and gives
    it back when its answer is complete; a runner in use is never unloaded under the request using it."""

    def __init__(self):
        self.cv = threading.Condition()
        self.runners = {}
        self.loading = set()
        self.closed = False

    @staticmethod
    def _serves(r, man, want, embed):
        """True when loaded runner r can answer this request as it is: the same build of the model, at least the
        window asked for (a bigger one serves a smaller request: reloading to shrink it only threw away the prompt
        cache), and vectors if vectors are wanted."""
        return not ((want and want > r.ctx) or r.digest != man.get("digest") or (embed and not r.embed))

    def _make_room(self):
        """Unload idle models, least recently used first, until one more may load. True when there is room.
        Call with the lock held."""
        idle = sorted((x for x in self.runners.values() if x.active == 0), key=lambda x: x.used)
        while len(self.runners) + len(self.loading) >= MAX_LOADED and idle:
            self.runners.pop(idle.pop(0).name).stop()
        return len(self.runners) + len(self.loading) < MAX_LOADED

    def take(self, name, ctx=None, keep_alive=None, embed=False):
        """The runner for this model, loaded if need be; the caller must give() it back. ctx: the window the
        request asks for (never more than the model was trained with)."""
        man = need(name)
        key = man["name"]
        embed = embed or is_embedder(man)
        trained = (man.get("info") or {}).get("context_length") or 0
        want = int(ctx or 0)
        if want and trained:
            want = min(want, trained)
        deadline = time.time() + LOAD_TIMEOUT
        with self.cv:
            while True:
                if self.closed:
                    raise EngineError("the engine is shutting down", 503)
                r = self.runners.get(key)
                if r and not r.alive():
                    self.runners.pop(key, None)
                    r = None
                if r and self._serves(r, man, want, embed) and r.active == 0 and \
                        time.time() - getattr(r, "gpu_checked", 0) > 20:
                    # loaded with layers on the CPU because another program held the GPU (an Ollama beside gnoc's
                    # engine): once that memory is free again, reload it on the GPU before this request, not
                    # keep answering at CPU speed for as long as he chats (engine QAQC 2026-11-23)
                    r.gpu_checked = time.time()
                    _need = r.gpu_short()
                    _free = free_vram_mib() if _need else None
                    if _need and _free is not None and _free + (r.size_vram() >> 20) >= _need + 256:
                        print(f"gnoc-engine: {key}: GPU memory is free again; reloading it on the GPU", flush=True)
                        self.runners.pop(key).stop()
                        r = None
                if r and self._serves(r, man, want, embed):
                    r.active += 1
                    r.used = time.time()
                    return r
                if key not in self.loading:     # else another request is loading it: wait for that one
                    if r and r.active == 0:     # loaded, but not as this request needs it: reload
                        self.runners.pop(key).stop()
                        r = None
                    if not r and self._make_room():
                        break
                if not self.cv.wait(timeout=max(0.1, min(5, deadline - time.time()))) and time.time() > deadline:
                    raise EngineError(f"timed out waiting for room to load {key}", 503)
            self.loading.add(key)
        try:
            r = self._load(man, want, trained, embed)
        except BaseException:
            with self.cv:
                self.loading.discard(key)
                self.cv.notify_all()
            raise
        with self.cv:
            self.loading.discard(key)
            r.active = 1
            r.expires = time.time() + max(keep_alive_secs(keep_alive), 1)
            self.runners[key] = r
            self.cv.notify_all()
        return r

    @staticmethod
    def _load(man, want, trained, embed):
        """Start a runner for this request. The window: the model's own num_ctx or the one `gnoc engine context`
        fixed for this GPU, else auto (fitted to the GPU), else DEFAULT_CTX; never under what the request asked."""
        def cap(n):
            return min(n, trained) if trained else n
        fixed = int((man.get("params") or {}).get("num_ctx") or 0)
        choice = ctx_choice()
        if not fixed and isinstance(choice, int):
            fixed = choice
        if fixed:
            return Runner(man, cap(max(fixed, want)), embed).start()
        if embed or not can_fit_ctx():
            return Runner(man, cap(max(DEFAULT_CTX, want)), embed).start()
        r = Runner(man, cap(max(AUTO_MIN, want)), embed, auto=True).start()
        if want and r.ctx < want:
            # the request needs more than the GPU holds: give it that window, as Ollama would (layers go to the CPU)
            r.stop()
            r = Runner(man, cap(want), embed).start()
        return r

    def give(self, r, keep_alive=None):
        with self.cv:
            r.active = max(0, r.active - 1)
            r.used = time.time()
            secs = keep_alive_secs(keep_alive)
            r.expires = float("inf") if secs < 0 else time.time() + secs
            if secs == 0 and r.active == 0 and self.runners.get(r.name) is r:
                self.runners.pop(r.name).stop()
            self.cv.notify_all()

    def unload(self, name):
        key = canon(name)
        with self.cv:
            r = self.runners.get(key)
            if r and r.active == 0:
                self.runners.pop(key).stop()
            elif r:
                r.expires = 0   # in use: goes as soon as the request holding it ends
            self.cv.notify_all()

    def reap(self):
        with self.cv:
            for k, r in list(self.runners.items()):
                if not r.alive() or (r.active == 0 and time.time() >= r.expires):
                    self.runners.pop(k).stop()
            self.cv.notify_all()

    def close(self):
        with self.cv:
            self.closed = True
            for r in self.runners.values():
                r.stop()
            self.runners.clear()
            self.cv.notify_all()

    def ps(self):
        with self.cv:
            return list(self.runners.values())


POOL = Pool()


# ------------------------------------------------------------------ Ollama <-> llama-server
_OPT = {"temperature": "temperature", "top_p": "top_p", "top_k": "top_k", "min_p": "min_p", "seed": "seed",
        "stop": "stop", "repeat_penalty": "repeat_penalty", "presence_penalty": "presence_penalty",
        "frequency_penalty": "frequency_penalty", "repeat_last_n": "repeat_last_n"}


# "think": false on a model whose chat template has no enable_thinking switch but always opens <think> (the
# Claude-4.6-Opus distills of Qwen3.5): the template ignored the switch, the model thought 100-200 tokens anyway, the
# thinking was dropped and a short reply came back EMPTY (desktop 35B, 2026-11-23). An already-closed think block as the
# start of the reply turns it off: 4 tokens instead of 112 for "laptop ok", tool calls still parsed.
THINK_OFF_PREFILL = "<think>\n\n</think>\n\n"
_FORCED_THINK = {}


def forced_think(man):
    """True for a model whose template opens <think> at every reply and has no enable_thinking switch."""
    path = blob_path(str((man or {}).get("model") or ""))
    if path not in _FORCED_THINK:
        try:
            tpl = str(gguf_meta(path).get("tokenizer.chat_template") or "")
        except (OSError, ValueError, struct.error):
            tpl = ""
        _FORCED_THINK[path] = "enable_thinking" not in tpl and bool(
            re.search(r"add_generation_prompt[\s\S]{0,300}<think>", tpl))
    return _FORCED_THINK[path]


def think_prefill(body, man):
    """The closed think block to start the reply with, or ''."""
    msgs = body.get("messages") or []
    if body.get("think") is not False or not msgs or (msgs[-1] or {}).get("role") == "assistant":
        return ""
    return THINK_OFF_PREFILL if forced_think(man) else ""


def to_openai(body, man):
    """An Ollama /api/chat body as a llama-server /v1/chat/completions body."""
    msgs = []
    for i, m in enumerate(body.get("messages") or []):
        if not isinstance(m, dict):
            continue
        role, content = m.get("role") or "user", m.get("content")
        content = "" if content is None else content
        out = {"role": role, "content": content}
        if m.get("images") and role == "user":
            parts = [{"type": "text", "text": content}] if content else []
            for im in m["images"]:
                url = im if str(im).startswith("data:") else "data:image/jpeg;base64," + str(im)
                parts.append({"type": "image_url", "image_url": {"url": url}})
            out["content"] = parts
        if role == "assistant" and m.get("tool_calls"):
            calls = []
            for j, c in enumerate(m["tool_calls"]):
                fn = (c or {}).get("function") or {}
                args = fn.get("arguments")
                calls.append({"id": c.get("id") or f"call_{i}_{j}", "type": "function",
                              "function": {"name": fn.get("name") or "",
                                           "arguments": args if isinstance(args, str) else json.dumps(args or {})}})
            out["tool_calls"] = calls
        if role == "tool":
            out["tool_call_id"] = m.get("tool_call_id") or _last_call_id(msgs)
            if not isinstance(content, str):
                out["content"] = json.dumps(content)
        msgs.append(out)
    pre = think_prefill(body, man)
    if pre:
        msgs.append({"role": "assistant", "content": pre})
    opts = dict(man.get("params") or {}, **(body.get("options") or {}))
    req = {"messages": msgs, "stream": True, "stream_options": {"include_usage": True}, "cache_prompt": True}
    for k, v in opts.items():
        if k in _OPT and v is not None:
            req[_OPT[k]] = v
    n = opts.get("num_predict")
    if isinstance(n, (int, float)) and n > 0:
        req["max_tokens"] = int(n)
    if body.get("tools"):
        req["tools"] = body["tools"]
    fmt = body.get("format")
    if fmt == "json":
        req["response_format"] = {"type": "json_object"}
    elif isinstance(fmt, dict) and fmt:
        req["response_format"] = {"type": "json_schema", "json_schema": {"name": "answer", "schema": fmt}}
    think = body.get("think")
    if isinstance(think, bool):
        req["chat_template_kwargs"] = {"enable_thinking": think}
    elif isinstance(think, str) and think:
        req["chat_template_kwargs"] = {"enable_thinking": True, "reasoning_effort": think}
        req["reasoning_effort"] = think
    return req


def _last_call_id(msgs):
    answered = {m.get("tool_call_id") for m in msgs if m.get("role") == "tool"}
    for m in reversed(msgs):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            for c in m["tool_calls"]:
                if c["id"] not in answered:
                    return c["id"]
            return m["tool_calls"][-1]["id"]
    return "call_0"


def _upstream_error(status, raw):
    """llama-server's error as Ollama would relay it: the text keeps the type and the token counts gnoc reads
    (exceed_context_size, n_prompt_tokens)."""
    try:
        e = json.loads(raw).get("error")
    except (ValueError, AttributeError):
        e = None
    text = json.dumps(e) if isinstance(e, dict) else (str(e) if e else raw.decode(errors="replace")[:600])
    return EngineError(text, status if 400 <= status < 600 else 500)


_UPSTREAM_LOST = (http.client.HTTPException, ConnectionError, TimeoutError)


def _dropped(r, e):
    """llama-server went away (or stopped answering) under a request: an error the caller can read, in place of
    a connection that just closes."""
    return EngineError(f"llama-server stopped answering for {shown(r.name)} ({type(e).__name__})"
                       + (f": {r.log_tail(2)}" if not r.alive() else ""), 502)


def chat_stream(r, body, man):
    """Yield Ollama /api/chat chunks (dicts) for one request against runner r."""
    req = to_openai(body, man)
    think = body.get("think")
    pre = think_prefill(body, man)   # a prefilled closed think block comes back at the start of the content: cut it
    held = [""] if pre else None
    t0 = time.time()
    c = r.conn(timeout=float(os.environ.get("GNOC_ENGINE_READ_TIMEOUT", "1800")))
    try:
        c.request("POST", "/v1/chat/completions", json.dumps(req).encode(), {"Content-Type": "application/json"})
        resp = c.getresponse()
        if resp.status != 200:
            raise _upstream_error(resp.status, resp.read())
        calls, usage, timings, finish = {}, {}, {}, "stop"

        def chunk(**msg):
            return {"model": shown(man["name"]), "created_at": _now().isoformat(),
                    "message": dict({"role": "assistant", "content": ""}, **msg), "done": False}

        for raw in resp:
            line = raw.strip()
            if not line.startswith(b"data:"):
                if line.startswith(b"{") and b'"error"' in line:
                    raise _upstream_error(500, line)
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                break
            try:
                d = json.loads(data)
            except ValueError:
                continue
            if d.get("error"):
                raise _upstream_error(500, data)
            usage = d.get("usage") or usage
            timings = d.get("timings") or timings
            for ch in d.get("choices") or []:
                delta = ch.get("delta") or {}
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
                if delta.get("reasoning_content") and think is not False:
                    yield chunk(thinking=delta["reasoning_content"])
                text = delta.get("content")
                if text and held is not None:
                    held[0] += text
                    if held[0].startswith(pre):
                        text, held = held[0][len(pre):], None
                    elif pre.startswith(held[0]):
                        text = ""            # still a piece of the prefill
                    else:
                        text, held = held[0], None
                if text:
                    yield chunk(content=text)
                for tc in delta.get("tool_calls") or []:
                    slot = calls.setdefault(tc.get("index", len(calls)), {"id": "", "name": "", "args": ""})
                    fn = tc.get("function") or {}
                    slot["id"] = tc.get("id") or slot["id"]
                    slot["name"] += fn.get("name") or ""
                    slot["args"] += fn.get("arguments") or ""
        if calls:
            out = []
            for i in sorted(calls):
                s = calls[i]
                args = repair_json_args(s["args"])
                out.append({"id": s["id"] or f"call_{i}",
                            "function": {"index": i, "name": s["name"], "arguments": args if isinstance(args, dict)
                                         else {"_raw": args}}})
            yield chunk(tool_calls=out)
        ns = lambda ms: int(float(ms or 0) * 1e6)   # noqa: E731
        yield {"model": shown(man["name"]), "created_at": _now().isoformat(),
               "message": {"role": "assistant", "content": ""}, "done": True,
               "done_reason": "length" if finish == "length" else "stop",
               "total_duration": int((time.time() - t0) * 1e9), "load_duration": int(r.loaded_in * 1e9),
               "prompt_eval_count": int(usage.get("prompt_tokens") or timings.get("prompt_n") or 0),
               "prompt_eval_duration": ns(timings.get("prompt_ms")),
               "eval_count": int(usage.get("completion_tokens") or timings.get("predicted_n") or 0),
               "eval_duration": ns(timings.get("predicted_ms")),
               # not Ollama's: the window this model is loaded with, so gnoc budgets its prompt to the real window
               # (fitted to the GPU) instead of a fixed 16k table. Ollama clients ignore a field they do not know.
               "context_length": int(getattr(r, "ctx", 0) or 0)}
    except _UPSTREAM_LOST as e:
        raise _dropped(r, e)
    finally:
        c.close()


def collect(chunks):
    """A stream of chat chunks folded into the one object a stream:false caller gets."""
    content, thinking, calls, last = [], [], [], {}
    for ch in chunks:
        m = ch.get("message") or {}
        content.append(m.get("content") or "")
        thinking.append(m.get("thinking") or "")
        calls += m.get("tool_calls") or []
        last = ch
    msg = {"role": "assistant", "content": "".join(content)}
    if "".join(thinking):
        msg["thinking"] = "".join(thinking)
    if calls:
        msg["tool_calls"] = calls
    return dict(last, message=msg)


def embed(r, texts, man):
    """Vectors for texts from runner r (llama-server's /v1/embeddings). Returns (vectors, prompt tokens)."""
    c = r.conn(timeout=600)
    try:
        c.request("POST", "/v1/embeddings", json.dumps({"input": texts}).encode(),
                  {"Content-Type": "application/json"})
        resp = c.getresponse()
        raw = resp.read()
        if resp.status != 200:
            raise _upstream_error(resp.status, raw)
        d = json.loads(raw)
        rows = sorted(d.get("data") or [], key=lambda x: x.get("index", 0))
        return [x.get("embedding") or [] for x in rows], int((d.get("usage") or {}).get("prompt_tokens") or 0)
    except _UPSTREAM_LOST as e:
        raise _dropped(r, e)
    finally:
        c.close()


def show(name):
    man = need(name)
    info = man.get("info") or {}
    params = man.get("params") or {}
    lines = [f"FROM {blob_path(man['model'])}"] + [f"PARAMETER {k} {v}" for k, v in params.items()
                                                    if not isinstance(v, (list, dict))]
    return {"modelfile": "\n".join(lines) + "\n", "parameters": "\n".join(f"{k} {v}" for k, v in params.items()),
            "template": "", "details": _details(man), "capabilities": info.get("capabilities") or ["completion"],
            "model_info": {"general.architecture": info.get("family"), "general.name": info.get("name"),
                           f"{info.get('family')}.context_length": info.get("context_length")},
            "modified_at": man.get("modified_at"), "source": man.get("source")}


def _details(man):
    info = man.get("info") or {}
    return {"parent_model": "", "format": "gguf", "family": info.get("family") or "",
            "families": [info.get("family") or ""], "parameter_size": info.get("parameter_size") or "",
            "quantization_level": info.get("quantization_level") or "unknown"}


def tags():
    return {"models": [{"name": shown(m["name"]), "model": shown(m["name"]), "modified_at": m.get("modified_at"),
                        "size": m.get("size") or 0, "digest": m.get("digest") or "", "details": _details(m)}
                       for m in models()]}


def ps():
    out = []
    for r in POOL.ps():
        exp = _now() + timedelta(seconds=min(max(r.expires - time.time(), 0), 3650 * 86400))
        out.append({"name": shown(r.name), "model": shown(r.name), "size": r.man.get("size") or 0,
                    "digest": r.man.get("digest") or "", "details": _details(r.man),
                    "expires_at": exp.isoformat(), "size_vram": r.size_vram(), "context_length": r.ctx,
                    "context_auto": bool(getattr(r, "auto", False)), "runner": "llamacpp"})
        k = gpu()[0] if r.on_cpu() else ""
        if k:   # a card exists and the model is not on it (no card at all: nothing to fix, nothing said)
            cuda = "cuda" in str((build_info() or {}).get("variant") or "")
            out[-1]["gpu_note"] = ("on the CPU (slow): llama.cpp found no GPU it can use here (no driver for the "
                                   "card, or only llvmpipe, a software one). " + (
                                       "Fix: the NVIDIA driver (nvidia-smi must work; under WSL, the Windows driver), "
                                       "then gnoc engine restart." if k == "nvidia" and cuda else
                                       f"Fix: gnoc engine install --variant {CUDA_HINT}, then gnoc engine restart."
                                       if k == "nvidia" else "Fix: install the graphics card's Vulkan driver (on "
                                       "Ubuntu/Debian: mesa-vulkan-drivers; under WSL use gnoc's Windows engine "
                                       "instead), then GNOC_ENGINE_RECHECK_GPU=1 gnoc engine restart."))
        elif r.gpu_short():
            # said where he sees it: 0/33 layers on the GPU answers at a fifth of the speed, with no word why
            out[-1]["gpu_note"] = ("partly or wholly on the CPU (slow): the GPU was full when it loaded"
                                   + (": " + gpu_holders() if gpu_holders() else "")
                                   + ". It moves back to the GPU by itself once that memory is free.")
    return {"models": out}


def repair_json_args(text):
    """Tool-call arguments as a dict: the JSON as sent, or repaired when a small model cut it short (an open string,
    braces never closed: `{"command": "wc -l targets/x/scope.txt &&` from a 9B lead, drive 2026-11-23); else
    {"_raw": text}, which the caller reports as malformed."""
    s = str(text or "").strip()
    if not s:
        return {}
    try:
        v = json.loads(s)
        return v if isinstance(v, dict) else {"_raw": s}
    except ValueError:
        pass
    if s.startswith("{"):
        quotes = len(re.findall(r'(?<!\\)"', s))
        fixed = s + ('"' if quotes % 2 else "")
        fixed += "}" * max(0, fixed.count("{") - fixed.count("}"))
        for cand in (fixed, fixed.rstrip(",") + ("}" if not fixed.endswith("}") else "")):
            try:
                v = json.loads(cand)
                if isinstance(v, dict):
                    return v
            except ValueError:
                continue
    return {"_raw": s}


def version():
    return {"version": f"gnoc-engine {VERSION}", "engine": "gnoc", "llama_cpp": build_info().get("tag") or "",
            "release": _release_version(), "standalone": standalone(), "variant": build_info().get("variant") or "",
            "images": True, "image_model": pick_image_model(), "image_ready": image_ready()}


def machine():
    """What this computer can hold and run, for a gnoc on another computer that is choosing where a model should
    be downloaded (gnoc models pull, GET /api/machine). Sizes in bytes; 0 means not known."""
    kind, vram = gpu()
    free = 0
    with contextlib.suppress(OSError):
        os.makedirs(MODELS, exist_ok=True)
        free = shutil.disk_usage(MODELS).free
    return {"engine": "gnoc", "version": VERSION, "name": platform.node(), "os": sys.platform,
            "android": bool(on_android()), "gpu": kind, "vram": int(vram or 0), "ram": int(ram_bytes()),
            "disk_free": int(free), "llama_cpp": bool(server_path()), "models": len(models())}


# ------------------------------------------------------------------ HTTP
_LOCAL_NAMES = {"127.0.0.1", "localhost", "::1", "[::1]"}


def _is_local(ip):
    """True for a caller on this computer itself."""
    return ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gnoc-engine/" + VERSION

    def log_message(self, fmt, *args):   # noqa: D401 - one line per request in the engine log
        sys.stderr.write(f"{time.strftime('%H:%M:%S')} {self.address_string()} {fmt % args}\n")

    # a web page must not be able to drive the engine through the visitor's browser: no cross-site origins, and
    # the Host header has to be this server (a DNS-rebinding page reaches 127.0.0.1 under its own host name)
    def _keyed(self):
        """With GNOC_ENGINE_KEY set, a caller on another computer must send it. Callers on this computer need
        none, so gnoc itself and local tools keep working unchanged."""
        key = engine_key()
        if not key or _is_local(self.client_address[0]):
            return True
        sent = self.headers.get("Authorization") or ""
        return sent.startswith("Bearer ") and hmac.compare_digest(sent[7:].strip().encode(), key.encode())

    def _allowed(self):
        origin = self.headers.get("Origin")
        if origin and urllib.parse.urlsplit(origin).hostname not in _LOCAL_NAMES:
            return False
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        bound = self.server.server_address[0]
        if bound in ("127.0.0.1", "::1", "localhost"):
            return host in ("127.0.0.1", "localhost", "::1", "")
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 256 << 20:
            raise EngineError("request too large", 413)
        raw = self.rfile.read(n) if n else b""
        if not raw.strip():
            return {}
        try:
            d = json.loads(raw)
        except ValueError:
            raise EngineError("invalid JSON body", 400)
        if not isinstance(d, dict):
            raise EngineError("the body must be a JSON object", 400)
        return d

    def _send(self, obj, status=200):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _stream(self, items, ctype="application/x-ndjson"):
        """Send dicts as NDJSON with chunked encoding. An error after the first byte goes out as an error line."""
        started = False
        try:
            for item in items:
                if not started:
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    started = True
                data = json.dumps(item).encode() + b"\n"
                self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                self.wfile.flush()
        except EngineError as e:
            if not started:
                raise
            data = json.dumps({"error": _say(str(e))}).encode() + b"\n"
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        if not started:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def _route(self, method):
        path = urllib.parse.urlsplit(self.path).path.rstrip("/") or "/"
        try:
            if not self._allowed():
                raise EngineError("forbidden", 403)
            if not self._keyed():
                raise EngineError("this server needs its key: send Authorization: Bearer <GNOC_ENGINE_KEY>", 401)
            fn = ROUTES.get((method, path))
            if not fn:
                raise EngineError(f"no such endpoint: {method} {path}", 404)
            fn(self)
        except EngineError as e:
            self.close_connection = True   # the request body may be unread: do not reuse this connection
            with contextlib.suppress(OSError):
                self._send({"error": _say(str(e))}, e.status)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:  # noqa: BLE001 - one bad request must not take the server down
            with contextlib.suppress(OSError):
                self._send({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_GET(self):
        self._route("GET")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._route("POST")

    def do_DELETE(self):
        self._route("DELETE")

    # ---- endpoints
    def h_gnoc_update(self):
        """POST /api/gnoc/update: install the newest signed engine release now (the paired gnoc chat's `gnoc update`
        asks for it). From another computer only when this engine has a key; then the key was already checked."""
        if not _is_local(self.client_address[0]) and not engine_key():
            raise EngineError("updating this engine from another computer needs its key: gnoc-engine share on", 403)
        if not standalone():
            self._send(_update_whole_app())
            return
        res = self_update()
        if res.get("updated"):
            _restart_soon()
        self._send(res)

    def h_gnoc_image(self):
        """POST /api/gnoc/image {prompt, negative?, width?, height?, steps?, seed?, model?}: a PNG (base64) in the
        last streamed row; the rows before say what is being installed or drawn. A paired computer uses this card."""
        b = self._body()

        def work(prog):
            png, info = make_image(b.get("prompt"), b.get("negative") or "", b.get("width"), b.get("height"),
                                   b.get("steps"), b.get("seed", -1), b.get("model"), prog)
            import base64
            prog(dict(info, status="image", image=base64.b64encode(png).decode()))
        self._progress_stream(b, work)

    def h_root(self):
        data = b"gnoc engine is running"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    @contextlib.contextmanager
    def _runner(self, body, name, embed=False):
        """The loaded model for this request: taken with the request's window and keep_alive, given back when the
        answer is complete (or the caller is gone)."""
        ka = body.get("keep_alive")
        r = POOL.take(name, (body.get("options") or {}).get("num_ctx"), ka, embed=embed)
        try:
            yield r
        finally:
            POOL.give(r, ka)

    def _answer(self, body, chunks, shape=lambda ch: ch):
        """Send chat chunks as the caller asked: one object for stream:false, else a line per chunk."""
        if body.get("stream") is False:
            self._send(shape(collect(chunks)))
        else:
            self._stream(shape(ch) for ch in chunks)

    @staticmethod
    def _refuse_embedder(man, instead, verb):
        raise EngineError(f"{shown(man['name'])} is an embedding model: it makes vectors{instead}, it does not "
                          f"{verb}", 400)

    def h_chat(self):
        body = self._body()
        name = body.get("model") or ""
        man = need(name)
        if not body.get("messages"):
            return self._load_only(name, body, "message")
        if is_embedder(man):
            self._refuse_embedder(man, " (/api/embed)", "chat")
        with self._runner(body, name) as r:
            self._answer(body, chat_stream(r, body, man))

    def _load_only(self, name, body, field):
        """No prompt: keep_alive 0 unloads the model, anything else loads it (how gnoc frees and warms a card)."""
        ka = body.get("keep_alive")
        base = {"model": shown(canon(name)), "created_at": _now().isoformat(), "done": True}
        base[field] = {"role": "assistant", "content": ""} if field == "message" else ""
        if ka is not None and keep_alive_secs(ka) == 0:
            POOL.unload(name)
            return self._send(dict(base, done_reason="unload"))
        with self._runner(body, name):
            pass
        self._send(dict(base, done_reason="load"))

    def _embed(self, body, texts):
        """Shared by /api/embed and /api/embeddings: (vectors, prompt tokens, seconds, runner load seconds, the
        model), or None when there was nothing to embed and the call only loaded or unloaded the model."""
        name = body.get("model") or ""
        man = need(name)
        if not texts:
            self._load_only(name, body, "response")
            return None
        if not all(isinstance(t, str) for t in texts):
            raise EngineError("input must be a string or a list of strings", 400)
        t0 = time.time()
        with self._runner(body, name, embed=True) as r:
            vecs, n = embed(r, texts, man)
        return vecs, n, time.time() - t0, r.loaded_in, man

    def h_embed(self):
        b = self._body()
        inp = b.get("input")
        got = self._embed(b, [inp] if isinstance(inp, str) else list(inp or []))
        if got:
            vecs, n, secs, load, man = got
            self._send({"model": shown(man["name"]), "embeddings": vecs, "total_duration": int(secs * 1e9),
                        "load_duration": int(load * 1e9), "prompt_eval_count": n})

    def h_embeddings(self):
        """The older single-text call some clients still make."""
        b = self._body()
        got = self._embed(b, [b["prompt"]] if b.get("prompt") else [])
        if got:
            self._send({"embedding": got[0][0] if got[0] else []})

    def h_generate(self):
        body = self._body()
        name = body.get("model") or ""
        man = need(name)
        if not body.get("prompt") and not body.get("images"):
            return self._load_only(name, body, "response")
        if is_embedder(man):
            self._refuse_embedder(man, " (/api/embed)", "write")
        msgs = ([{"role": "system", "content": body["system"]}] if body.get("system") else []) + [
            {"role": "user", "content": body.get("prompt") or "", "images": body.get("images") or []}]

        def as_generate(ch):
            m = ch.pop("message", {})
            ch["response"] = m.get("content") or ""
            if m.get("thinking"):
                ch["thinking"] = m["thinking"]
            return ch
        with self._runner(body, name) as r:
            self._answer(body, chat_stream(r, dict(body, messages=msgs), man), as_generate)

    def h_show(self):
        b = self._body()
        self._send(show(b.get("model") or b.get("name") or ""))

    def _progress_stream(self, body, work):
        """Run work(progress) on a thread; its progress dicts are the response stream (or only the end, unstreamed).
        When the caller hangs up, the next progress report stops the work: nobody is left to want the download."""
        import queue
        q = queue.Queue()
        gone = threading.Event()

        def report(row):
            if gone.is_set():
                raise Cancelled("the caller went away", 499)
            q.put(row)

        def run():
            try:
                work(report)
                q.put({"status": "success"})
            except EngineError as e:
                q.put({"error": _say(str(e)), "_status": e.status})
            except Exception as e:  # noqa: BLE001
                q.put({"error": f"{type(e).__name__}: {e}", "_status": 500})
            q.put(None)

        threading.Thread(target=run, daemon=True).start()

        def items():
            while True:
                it = q.get()
                if it is None:
                    return
                yield it
        if body.get("stream") is False:
            last = {}
            for it in items():
                last = it
            status = last.pop("_status", 200) if "error" in last else 200
            return self._send(last, status)
        try:
            self._stream({k: v for k, v in it.items() if k != "_status"} for it in items())
        except OSError:
            gone.set()
            raise

    def h_pull(self):
        b = self._body()
        src = b.get("model") or b.get("name") or ""
        local = _is_local(self.client_address[0])
        self._progress_stream(b, lambda prog: pull(src, b.get("as") or None, b.get("parameters"), prog, local))

    def h_create(self):
        b = self._body()
        name, src = b.get("model") or b.get("name") or "", b.get("from") or ""
        if not name or not src:
            raise EngineError("create needs model and from", 400)

        def work(prog):
            prog({"status": f"using existing layer {src}"})
            create(name, src, b.get("parameters"))
        self._progress_stream(b, work)

    def h_delete(self):
        b = self._body()
        name = b.get("model") or b.get("name") or ""
        need(name)
        POOL.unload(name)
        delete(name)
        self._send({})

    def h_v1_models(self):
        self._send({"object": "list", "data": [{"id": shown(m["name"]), "object": "model", "owned_by": "gnoc",
                                                 "created": 0} for m in models()]})

    def h_v1(self):
        """The OpenAI-compatible endpoints go to llama-server as they are, once the model they name is loaded."""
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            name = json.loads(raw).get("model") or ""
        except (ValueError, AttributeError):
            raise EngineError("invalid JSON body", 400)
        man = need(name)
        path = urllib.parse.urlsplit(self.path).path
        vectors = path.endswith("/embeddings")
        if is_embedder(man) and not vectors:
            self._refuse_embedder(man, "", "chat")
        with self._runner({}, name, embed=vectors) as r:
            c = r.conn(timeout=1800)
            try:
                try:
                    c.request("POST", path, raw, {"Content-Type": "application/json"})
                    resp = c.getresponse()
                except _UPSTREAM_LOST as e:
                    raise _dropped(r, e)
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.getheader("Content-Type") or "application/json")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                while True:
                    data = resp.read1(65536)
                    if not data:
                        break
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
            finally:
                c.close()


ROUTES = {("GET", "/"): Handler.h_root,
          ("GET", "/api/version"): lambda h: h._send(version()),
          ("POST", "/api/gnoc/update"): Handler.h_gnoc_update,
          ("POST", "/api/gnoc/image"): Handler.h_gnoc_image,
          ("GET", "/api/tags"): lambda h: h._send(tags()),
          ("GET", "/api/machine"): lambda h: h._send(machine()),
          ("GET", "/api/ps"): lambda h: h._send(ps()),
          ("POST", "/api/show"): Handler.h_show,
          ("POST", "/api/chat"): Handler.h_chat,
          ("POST", "/api/generate"): Handler.h_generate,
          ("POST", "/api/embed"): Handler.h_embed,
          ("POST", "/api/embeddings"): Handler.h_embeddings,
          ("POST", "/api/pull"): Handler.h_pull,
          ("POST", "/api/create"): Handler.h_create,
          ("DELETE", "/api/delete"): Handler.h_delete,
          ("GET", "/v1/models"): Handler.h_v1_models,
          ("POST", "/v1/chat/completions"): Handler.h_v1,
          ("POST", "/v1/completions"): Handler.h_v1,
          ("POST", "/v1/embeddings"): Handler.h_v1}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64


def serve(host=None, port=None):
    h, p = addr()
    host, port = host or h, port or p
    os.makedirs(HOME, exist_ok=True)
    srv = _Server((host, port), Handler)
    stop_orphans()
    with open(PIDFILE, "w") as f:
        json.dump({"pid": os.getpid(), "addr": f"{host}:{port}"}, f)

    def reaper():
        while not POOL.closed:
            time.sleep(2)
            POOL.reap()

    threading.Thread(target=reaper, daemon=True).start()

    def bye(*_a):
        threading.Thread(target=srv.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, bye)
    if share_conf().get("auto_update") and standalone():
        threading.Thread(target=_auto_update_loop, daemon=True, name="gnoc-engine-self-update").start()
    if host not in ("127.0.0.1", "::1", "localhost") and not engine_key():
        sys.stderr.write(f"WARNING: listening on {host} with no key: anyone who can reach this address can use and "
                         "change your models. Set GNOC_ENGINE_KEY, or only do this on a network you trust.\n")
    sys.stderr.write(f"gnoc engine {VERSION} listening on {host}:{port}  models: {MODELS}  "
                     f"llama-server: {server_path() or 'NOT INSTALLED (gnoc engine install)'}\n")
    try:
        srv.serve_forever()
    finally:
        POOL.close()
        srv.server_close()
        with contextlib.suppress(OSError):
            os.remove(PIDFILE)


# ------------------------------------------------------------------ talking to a server (the engine or an Ollama)
def _client_headers():
    key = os.environ.get("GNOC_ENGINE_KEY")
    return dict({"Content-Type": "application/json"}, **({"Authorization": f"Bearer {key}"} if key else {}))


def api(host, path, body=None, method=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://{host}{path}", data, _client_headers(),
                                 method=method or ("POST" if data is not None else "GET"))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def who(host, timeout=2):
    """'gnoc' when gnoc's engine answers at host, 'ollama' when an Ollama does, '' when nothing does."""
    try:
        v = api(host, "/api/version", timeout=timeout)
    except Exception:  # noqa: BLE001
        return ""
    return "gnoc" if v.get("engine") == "gnoc" else ("ollama" if v.get("version") else "")


def _bar(row, state):
    if not sys.stdout.isatty():
        if row.get("status") != state.get("last"):
            state["last"] = row.get("status")
            print("  " + str(row.get("status")), flush=True)
        return
    total, done = row.get("total") or 0, row.get("completed") or 0
    if total:
        t0 = state.setdefault(("t", row.get("status")), (time.time(), done))
        rate = (done - t0[1]) / max(time.time() - t0[0], .5) / 1e6
        sys.stdout.write(f"\r\x1b[2K  {str(row.get('status'))[:56]:<56} {100 * done / total:5.1f}%  "
                         f"{done / 1e9:.2f}/{total / 1e9:.2f} GB  {rate:.0f} MB/s")
    else:
        sys.stdout.write(f"\r\x1b[2K  {row.get('status')}\n")
    sys.stdout.flush()


def _error_text(raw):
    """The message in a server's error body: its JSON "error" when it has one, else the body as it is."""
    try:
        return str(json.loads(raw).get("error") or raw)
    except (ValueError, AttributeError):
        return str(raw)


@contextlib.contextmanager
def _rows(host, path, body, timeout, lost, limit=400, method="POST"):
    """POST body and hand back the response's JSON lines, one dict at a time. Every way the call can fail
    becomes an EngineError here: an error line in the stream, an HTTP error (with the server's own message), a
    dropped connection (`lost` says whose)."""
    req = urllib.request.Request(f"http://{host}{path}", json.dumps(body).encode(), _client_headers(), method=method)

    def rows(resp):
        for line in resp:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as e:
                raise EngineError(f"{lost}: {e}", 502)
            if row.get("error"):
                raise EngineError(str(row["error"]))
            yield row
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            yield rows(resp)
    except urllib.error.HTTPError as e:
        with e:
            raw = e.read().decode(errors="replace")
        raise EngineError(_error_text(raw)[:limit], e.code)
    except (urllib.error.URLError, OSError) as e:
        raise EngineError(f"{lost}: {getattr(e, 'reason', e)}", 502)


def _streamed(host, path, body, show=True, method="POST", timeout=None):
    """POST and follow a progress stream (/api/pull, /api/create) on the engine or an Ollama. Raises EngineError."""
    state = {}
    try:
        with _rows(host, path, body, timeout or 86400, f"the model server at {host} did not finish",
                   method=method) as rows:
            for row in rows:
                if show:
                    _bar(row, state)
    finally:
        if show and sys.stdout.isatty():
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()


def remote_pull(host, source, show=True):
    _streamed(host, "/api/pull", {"model": source, "stream": True}, show)


def remote_create(host, name, source, params=None, show=False):
    _streamed(host, "/api/create", {"model": name, "from": source, "parameters": params or {}, "stream": True}, show)


def remote_delete(host, name):
    try:
        api(host, "/api/delete", {"model": name}, method="DELETE", timeout=180)
    except urllib.error.HTTPError as e:
        with e:
            raise EngineError(e.read().decode(errors="replace")[:300] or f"HTTP {e.code}", e.code)
    except (urllib.error.URLError, OSError) as e:
        raise EngineError(f"the model server at {host} did not answer: {getattr(e, 'reason', e)}", 502)


# ------------------------------------------------------------------ running it in the background
def running():
    """{'pid', 'addr'} of the background engine when it is alive, else None."""
    try:
        with open(PIDFILE) as f:
            d = json.load(f)
        int(d["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    # asked over HTTP, not with a signal: os.kill(pid, 0) ENDS the process on Windows, and a pid can be reused
    return d if who(str(d.get("addr") or ""), 1) == "gnoc" else None


def start(wait=15):
    """Start the engine in the background unless something already answers on its address. Returns
    ('started'|'running'|'ollama'|'no-llama'|'failed', detail)."""
    host, port = addr()
    at = f"{'127.0.0.1' if host in ('0.0.0.0', '::', '') else host}:{port}"   # a shared engine is asked locally
    kind = who(at, 1)
    if kind == "gnoc":
        return "running", at
    if kind == "ollama":
        return "ollama", at
    if not server_path():
        return "no-llama", at
    os.makedirs(HOME, exist_ok=True)
    kw = {"creationflags": 0x00000008 | 0x00000200} if os.name == "nt" else {"start_new_session": True}
    with open(LOG, "ab") as lf:
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "serve"], stdout=lf, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, **kw)
    end = time.time() + wait
    while time.time() < end:
        if who(at, 1) == "gnoc":
            return "started", at
        time.sleep(0.2)
    return "failed", f"nothing answered at {at} in {wait}s (see {LOG})"


def stop():
    d = running()
    if not d:
        return False
    if os.name == "nt":   # no SIGTERM handler there: end the server and the llama-server under it
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(int(d["pid"]))], capture_output=True)
    else:
        os.kill(int(d["pid"]), signal.SIGTERM)
    for _ in range(100):
        if not running():
            break
        time.sleep(0.1)
    return True


def enabled():
    """True when this install uses gnoc's engine as its local model server (set by setup, or `gnoc engine start`)."""
    return os.path.exists(os.path.join(HOME, "enabled"))


def enable(on=True):
    os.makedirs(HOME, exist_ok=True)
    p = os.path.join(HOME, "enabled")
    if on:
        open(p, "w").close()
    else:
        with contextlib.suppress(OSError):
            os.remove(p)


def ensure():
    """Called when gnoc starts: bring the engine up if this install uses it and nothing is listening. Quiet, and
    never raises."""
    try:
        if enabled() and server_path():
            return start(wait=10)[0] in ("started", "running")
    except Exception:  # noqa: BLE001
        pass
    return False


# ------------------------------------------------------------------ a chat in the terminal
def _ask(at, model, messages, out=sys.stdout):
    """Stream one answer to the terminal; returns its text. The model's reasoning is not printed."""
    body = {"model": model, "messages": messages, "stream": True, "keep_alive": "30m"}
    said, thinking = [], False
    with _rows(at, "/api/chat", body, 1800, f"the engine at {at} stopped answering", limit=500) as rows:
        for row in rows:
            msg = row.get("message") or {}
            if msg.get("thinking") and not thinking and not said:
                thinking = True
                out.write("(thinking...)\r")
                out.flush()
            if msg.get("content"):
                if thinking:
                    out.write("              \r")
                    thinking = False
                said.append(msg["content"])
                out.write(msg["content"])
                out.flush()
    out.write("\n")
    return "".join(said)


def run_chat(model, prompt=None, ask=input, out=sys.stdout):
    """`run <model>`: a plain conversation with a stored model. One question when prompt is given."""
    need(model)
    st, detail = start()
    if st == "ollama":
        raise EngineError(f"an Ollama is listening on {detail}, not the engine: stop it, or set GNOC_ENGINE_ADDR")
    if st == "no-llama":
        raise EngineError(_say("llama.cpp is not installed yet: gnoc engine install"), 503)
    if st == "failed":
        raise EngineError(detail)
    at = "%s:%d" % addr()
    messages = []
    if prompt:
        _ask(at, model, [{"role": "user", "content": prompt}], out)
        return 0
    out.write(f"{shown(canon(model))}  ·  /bye to leave, /clear to start over (the first answer waits for the "
              "model to load)\n")
    while True:
        try:
            line = ask(">>> ").strip()
        except (EOFError, KeyboardInterrupt):
            out.write("\n")
            return 0
        if not line:
            continue
        if line in ("/bye", "/exit", "/quit"):
            return 0
        if line == "/clear":
            messages = []
            continue
        messages.append({"role": "user", "content": line})
        try:
            messages.append({"role": "assistant", "content": _ask(at, model, messages, out)})
        except KeyboardInterrupt:
            messages.pop()
            out.write("\n(stopped)\n")
        except EngineError as e:
            messages.pop()
            out.write(f"\n{e}\n")


# ------------------------------------------------------------------ command line
def _gb(n):
    return f"{(n or 0) / 1e9:.1f} GB"


def _status():
    host, port = addr()
    at = f"{host}:{port}"
    kind = who(at, 1)
    b = build_info()
    print(f"gnoc engine {VERSION}")
    print(f"  server      {at}  " + {"gnoc": "running", "ollama": "an Ollama is listening here, not the engine",
                                     "": _say("not running  (gnoc engine start)")}[kind])
    sp = server_path()
    print(f"  llama.cpp   {(b.get('tag', '') + ' ' + b.get('variant', '')).strip() or 'on PATH' if sp else ''}"
          + (f"  {sp}" if sp else _say("not installed  (gnoc engine install)")))
    kind_gpu, vram = gpu()
    print(f"  gpu         {kind_gpu or 'none found'}" + (f"  {_gb(vram)}" if vram else ""))
    _im = pick_image_model()
    print(f"  images      {IMAGE_MODELS[_im]['label']} ({IMAGE_MODELS[_im]['licence']}): "
          + ("ready" if image_ready(_im) else "installed on the first picture request (stable-diffusion.cpp and the "
             "model, " + ("about 5.4 GB" if _im == "sdxl" else "about 1.8 GB") + ")"))
    if software_vulkan():
        print(_say("  ⚠ Vulkan is running on llvmpipe, a software driver on the CPU: the GPU is not used and every "
                   "answer is slow.") + (f"  Fix: gnoc engine install --variant {CUDA_HINT}  then  gnoc engine restart"
                                         if kind_gpu == "nvidia" else "  Install the card's Vulkan driver, or: "
                                         "gnoc engine install --variant cpu"))
    elif kind_gpu == "nvidia" and "vulkan" in str(b.get("variant") or "") and os.path.isdir("/usr/lib/wsl/lib"):
        print("  tip         an NVIDIA card under WSL runs best on the CUDA build: gnoc engine install --variant "
              "cuda-12.8  then  gnoc engine restart")
    print(f"  store       {MODELS}  ({len(models())} models)")
    if kind == "gnoc":
        for m in api(at, "/api/ps", timeout=5).get("models") or []:
            print(f"  loaded      {m['name']}  ctx {m.get('context_length')}  {_gb(m.get('size_vram'))} on the GPU "
                  f"of {_gb(m.get('size'))}")
    return 0


def _at():
    return "%s:%d" % addr()


def _cmd_help(rest, opt):
    print(_say(__doc__))


def _cmd_run(rest, opt):
    return run_chat(rest[0], " ".join(rest[1:]) or None)


def _cmd_serve(rest, opt):
    serve()


def _cmd_start(rest, opt):
    st, detail = start()
    enable(st in ("started", "running"))
    print({"started": f"engine started on {detail}", "running": f"engine already running on {detail}",
           "ollama": f"an Ollama is already listening on {detail}: stop it first, or give the engine its own "
                     f"address with GNOC_ENGINE_ADDR=127.0.0.1:11439 (and point gnoc at the same address)",
           "no-llama": _say("llama.cpp is not installed yet: gnoc engine install"),
           "failed": detail}[st])
    return 0 if st in ("started", "running") else 1


def _cmd_stop(rest, opt):
    enable(False)
    print("engine stopped" if stop() else "the engine was not running")


def _cmd_restart(rest, opt):
    stop()
    st, detail = start()
    print(f"engine restarted on {detail}" if st == "started" else _say(
        {"ollama": f"an Ollama is listening on {detail}", "no-llama": "llama.cpp is not installed yet: "
         "gnoc engine install", "running": f"something is still answering on {detail}"}.get(st, detail)))
    return 0 if st == "started" else 1


def _cmd_update(rest, opt):
    state = {}
    got = update(lambda r: _bar(r, state))
    print(f"\r\x1b[2Kllama.cpp {got['tag']} installed (was {got['was'] or 'none'}); models load with it from now on"
          if got["changed"] else f"llama.cpp {got['tag']} is the newest build")


def _cmd_install(rest, opt):
    state = {}
    got = install(opt("--variant"), opt("--tag"), lambda r: _bar(r, state))
    print(f"\r\x1b[2Kllama.cpp {got['tag']} ({got['variant']}) installed: {got['server']}")


def _cmd_ps(rest, opt):
    if who(_at(), 1) != "gnoc":
        print(_say("the engine is not running  (gnoc engine start)"))
        return 1
    rows = api(_at(), "/api/ps", timeout=5).get("models") or []
    for m in rows:
        print(f"  {m['name']:<60} ctx {m.get('context_length')}  {_gb(m.get('size_vram'))} on the GPU of "
              f"{_gb(m.get('size'))}  until {str(m.get('expires_at'))[11:19]}")
        if m.get("gpu_note"):
            print(f"    {m['gpu_note']}")
    if not rows:
        print("  nothing is loaded")


def _ctx_words(v):
    return ("auto: the biggest window that keeps the whole model on the GPU" if v == "auto"
            else f"{int(v):,} tokens")


def _cmd_context(rest, opt):
    """gnoc engine context [auto | N] [--gpu NAME | --gpu all]: show or set the window for each GPU."""
    target = opt("--gpu")
    d = ctx_settings()
    here = gpu_name()
    up = who(_at(), 1) == "gnoc"
    rows = (api(_at(), "/api/ps", timeout=5).get("models") or []) if up else []
    if not rest:
        none = (f"none found: models run on the CPU at {DEFAULT_CTX:,} tokens" if server_path()
                else "not known until llama.cpp is installed (gnoc engine install)")
        print(f"  GPU        {here or none}")
        print(f"  context    {_ctx_words(ctx_choice(here))}"
              + ("   (set by GNOC_ENGINE_CTX)" if parse_ctx(os.environ.get("GNOC_ENGINE_CTX", "")) else ""))
        for k, v in sorted(d.items()):
            if k != here:
                print(f"  saved      {'every GPU' if k == '*' else k}: {_ctx_words(parse_ctx(v) or 'auto')}")
        for m in rows:
            print(f"  loaded     {m['name']}  {int(m.get('context_length') or 0):,} tokens"
                  + ("  (fitted to the GPU)" if m.get("context_auto") else ""))
        print(_say("  change it: gnoc engine context auto | 32k | 65536   (--gpu all: every GPU)"))
        return 0
    v = parse_ctx(rest[0])
    if not v:
        print(_say("usage: gnoc engine context [auto | N]  [--gpu NAME | --gpu all]   (N in tokens, at least 2048, "
                   "or with k: 32k, 64k)"))
        return 2
    key = "*" if (target or "").lower() == "all" else (target or here or "*")
    d[key] = v
    os.makedirs(HOME, exist_ok=True)
    tmp = _ctx_file() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, _ctx_file())
    print(f"context for {'every GPU' if key == '*' else key}: {_ctx_words(v)}")
    if key == "*" and here and here in d and here != key:
        print(_say(f"  ({here} has its own setting, which wins: gnoc engine context {v} --gpu \"{here}\")"))
    for m in rows:   # the window is set when a model loads: free the loaded one so its next request uses the new one
        with contextlib.suppress(Exception):
            api(_at(), "/api/generate", {"model": m["name"], "keep_alive": 0}, timeout=60)
            print(f"  unloaded {m['name']}: it loads with the new window on its next request")
    if isinstance(v, int) and v > 32768:
        print(_say("  a fixed window bigger than the GPU holds moves model layers to the CPU, which is much slower: "
                   "auto never does"))
    return 0


def _cmd_unload(rest, opt):
    api(_at(), "/api/generate", {"model": rest[0], "keep_alive": 0}, timeout=60)
    print(f"unloaded {rest[0]}")


def _cmd_logs(rest, opt):
    n = int(opt("-n", "40"))
    path = LOG if not rest else os.path.join(HOME, "runners", re.sub(r"[^\w.-]+", "_", canon(rest[0]))[-80:] + ".log")
    try:
        with open(path, errors="replace") as f:
            print("".join(f.readlines()[-n:]), end="")
    except OSError:
        print(f"no log yet at {path}")
        return 1


def _cmd_search(rest, opt):
    q = urllib.parse.urlencode({"search": " ".join(rest), "filter": "gguf", "sort": "downloads", "limit": 20})
    for m in _json(f"https://huggingface.co/api/models?{q}"):
        print(f"  {m['id']:<72} {m.get('downloads', 0):>10,} downloads")
    print(_say("next: gnoc engine files <owner/repo>"))


def _cmd_files(rest, opt):
    repo = parse_hf(rest[0])[0]
    rows, mm = hf_files(repo)
    if not rows:
        raise EngineError(f"{repo} has no .gguf files", 404)
    budget = fit_budget()
    by = _by_quant(rows)
    best = pick_quant(by, budget)[0]
    for r in sorted(by.values(), key=lambda r: r[1]):
        print(f"  {r[0]:<10} {_gb(r[1]):>9}  {fit_word(r[1], budget):<32}"
              + ("  <- the one a plain pull takes" if r[0] == best else ""))
    if mm:
        print(f"  + {os.path.basename(mm[0])} ({_gb(mm[1])}): the part that lets it see images, fetched with it")
    print(_say(f"next: gnoc engine pull {repo}:{best}"))


def _cmd_pull(rest, opt):
    name, ctx = opt("--as"), opt("--ctx")
    state = {}
    m = pull(rest[0], name, {"num_ctx": int(ctx)} if ctx else None, lambda r: _bar(r, state))
    if sys.stdout.isatty():
        sys.stdout.write("\r\x1b[2K")
    info = m["info"]
    print(f"ready: {shown(m['name'])}  {_gb(m['size'])}  {info.get('parameter_size')} "
          f"{info.get('quantization_level')}  can: {', '.join(info.get('capabilities') or [])}")


def _cmd_list(rest, opt):
    have = models()
    for m in have:
        i = m.get("info") or {}
        print(f"  {shown(m['name']):<64} {_gb(m.get('size')):>9}  {i.get('parameter_size') or '':<6} "
              f"{i.get('quantization_level') or '':<8} {','.join(i.get('capabilities') or [])}")
    if not have:
        print(_say("  no models yet: gnoc engine pull <owner/repo[:QUANT]>"))


def _cmd_show(rest, opt):
    print(json.dumps(dict(show(rest[0]), manifest=need(rest[0])), indent=1))


def _cmd_rm(rest, opt):
    if who(_at(), 1) == "gnoc":     # a running server also has to let go of the loaded model
        remote_delete(_at(), rest[0])
    else:
        delete(rest[0])
    print(f"removed {rest[0]}")


def _cmd_import_ollama(rest, opt):
    made = import_ollama(rest or None, lambda r: print("  " + r["status"]))
    print(f"{len(made)} model(s) adopted from Ollama's store" if made else
          "nothing to adopt (no Ollama store found here, or no model by that name)")


# command -> (what runs it, whether it needs an argument). A command given without the argument it needs, and
# anything not listed, prints the help and exits 2.
# ------------------------------------------------------------------ serving other computers, and staying current
# GreyNOC 2026-11-23: "i dont want to have to install ollama on the external machines". A second computer runs only
# this engine, shared on the network behind a key; the computer with gnoc chat pairs with it (gnoc pair) and keeps it
# current. A standalone engine also checks for a new signed release once a day by itself.

def _share_path():
    return os.path.join(HOME, "share.json")


def share_conf():
    """{"addr", "port", "key", "auto_update"} when this engine serves other computers, else {}."""
    try:
        with open(_share_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def engine_key():
    """The key callers on other computers must send: GNOC_ENGINE_KEY, else the one `share on` made."""
    return os.environ.get("GNOC_ENGINE_KEY") or str(share_conf().get("key") or "")


def lan_addresses():
    """This computer's address on its network (the one a route to the internet would use), for the pairing line."""
    out = []
    with contextlib.suppress(OSError):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))   # a documentation address: nothing is sent, the route picks the interface
            out.append(s.getsockname()[0])
        finally:
            s.close()
    return [a for a in out if a and not a.startswith("127.")]


def on_wsl():
    """True inside Windows' Subsystem for Linux."""
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    with contextlib.suppress(OSError):
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    return False


def wsl_networking():
    """'mirrored' (WSL shares Windows' own network address), 'nat' (WSL sits behind Windows on a 172.x address no
    other computer reaches), or '' when this is not WSL."""
    if not on_wsl():
        return ""
    with contextlib.suppress(Exception):
        r = subprocess.run(["wslinfo", "--networking-mode"], capture_output=True, text=True, timeout=5)
        mode = (r.stdout or "").strip().lower()
        if mode in ("nat", "mirrored", "virtioproxy", "none"):
            return mode
    ips = lan_addresses()
    return "nat" if any(re.match(r"172\.(1[6-9]|2\d|3[01])\.", a) for a in ips) else "mirrored"


def wsl_share_steps(port):
    """What Windows needs once so another computer reaches a shared engine inside WSL (NAT mode). The user 2026-11-23:
    "it should be able to set up the desktop using the engine" - their desktop runs gnoc in WSL, where share on
    listened on a 172.x address nothing else could reach."""
    return [
        "This engine runs in WSL behind Windows (NAT): its address is inside this PC and no other computer reaches",
        "it. Once, in Windows (Windows 11 22H2 or newer):",
        "  1. Add to %UserProfile%\\.wslconfig (create it if missing):",
        "         [wsl2]",
        "         networkingMode=mirrored",
        "  2. In PowerShell:  wsl --shutdown     then open WSL again and run:  gnoc engine share on",
        "  3. In PowerShell as administrator (lets ONLY this port into WSL):",
        "         New-NetFirewallHyperVRule -Name gnoc-engine -DisplayName \"gnoc engine\" -Direction Inbound "
        f"-VMCreatorId '{{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}}' -Protocol TCP -LocalPorts {port}",
        "The pairing line then shows this PC's own address. WSL starts the engine when WSL starts, not when Windows",
        "does: open WSL once after a reboot (or add `wsl -e true` to Windows' startup).",
    ]


_AUTOSTART_TAG = "# gnoc-engine autostart"


def boot_autostart(on=True):
    """Start the engine when this computer starts (a crontab @reboot line; at logon on Windows). No administrator
    rights. -> (ok, how)."""
    me = os.path.abspath(__file__)
    if os.name == "nt":
        if on:
            r = subprocess.run(["schtasks", "/create", "/f", "/sc", "onlogon", "/tn", "gnoc-engine", "/tr",
                                f'"{sys.executable}" "{me}" start'], capture_output=True, text=True)
        else:
            r = subprocess.run(["schtasks", "/delete", "/f", "/tn", "gnoc-engine"], capture_output=True, text=True)
        return r.returncode == 0, "a Windows scheduled task at logon (gnoc-engine)"
    if on and on_android():
        # Termux's crond starts with Termux, never at boot, so an @reboot line there never fires; the Termux:Boot
        # app runs ~/.termux/boot/ at boot instead (gnoc phone setup writes that script)
        return False, ("Android never runs a crontab @reboot line: install the Termux:Boot app and put  gnoc-engine "
                       "start  in a script under ~/.termux/boot/ (gnoc phone setup does this for you)")
    if not shutil.which("crontab"):
        return False, "no crontab on this computer: start it after a reboot with  gnoc-engine start"
    cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    lines = [ln for ln in (cur.stdout.splitlines() if cur.returncode == 0 else []) if _AUTOSTART_TAG not in ln]
    if on:
        lines.append(f"@reboot {shlex.quote(sys.executable)} {shlex.quote(me)} start >/dev/null 2>&1 {_AUTOSTART_TAG}")
    r = subprocess.run(["crontab", "-"], input="\n".join(lines) + ("\n" if lines else ""), capture_output=True,
                       text=True)
    return r.returncode == 0, "a crontab @reboot line (crontab -l shows it)"


def share(on=True, port=None):
    """Serve other computers (on) or only this one (off). On: listen on every interface at `port` (11434 by default)
    behind a key made here, start at boot, and keep the engine current by itself. -> the share settings."""
    path = _share_path()
    if not on:
        with contextlib.suppress(OSError):
            os.remove(path)
        boot_autostart(False)
        return {}
    conf = share_conf()
    p = int(port or conf.get("port") or 11434)
    conf.update(key=conf.get("key") or secrets.token_urlsafe(24), addr=f"0.0.0.0:{p}", port=p,
                auto_update=conf.get("auto_update", True))
    os.makedirs(HOME, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(conf, f)
    os.replace(tmp, path)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    enable(True)
    return conf


def _release_version():
    """The release this engine came in: the VERSION file beside it (the standalone package), or gnoc chat's."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in (os.path.join(here, "VERSION"), os.path.join(os.path.dirname(here), "VERSION")):
        with contextlib.suppress(OSError):
            with open(p) as f:
                v = f.read().strip()
            if v:
                return v
    return ""


def standalone():
    """True for the gnoc-engine package on its own (it may replace its own files); False inside gnoc chat, whose
    whole release `gnoc update` installs."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.basename(here) == "gnoc-engine" or os.environ.get("GNOC_ENGINE_PROG") == "gnoc-engine"


_UPDATE_LOCK = threading.Lock()


def self_update(apply=True, llama=False):
    """Bring this engine to the newest SIGNED release: the manifest must carry the release key's signature and the
    package its SHA-256 (gnoc_update, beside this file, checks both); never an older or equal release. A standalone
    engine replaces its own files; one inside gnoc chat only reports (gnoc update installs the whole app). The
    llama.cpp build only with llama=True: llama.cpp publishes almost daily, and the CUDA build is ~800 MB.
    -> {"have", "latest", "updated", "llama", "note"}."""
    out = {"have": _release_version(), "latest": "", "updated": False, "llama": "", "note": ""}
    if not _UPDATE_LOCK.acquire(blocking=False):
        out["note"] = "an update is already running"
        return out
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        try:
            import gnoc_update as U
        except ImportError:
            out["note"] = "gnoc_update.py is not beside the engine: install the engine package once more"
            return out
        try:
            m = U.latest_release()
        except Exception as e:  # noqa: BLE001 - U.UpdateError and the rest: say why, change nothing
            out["note"] = f"no signed release could be read ({e})"
            return out
        out["latest"] = str(m.get("version") or "")
        if not U.newer(out["latest"], out["have"]):
            out["note"] = "already the newest release"
        elif not standalone():
            out["note"] = f"{out['latest']} is out: this engine is part of gnoc chat here, so run  gnoc update  on it"
        elif apply:
            meta = (m.get("files") or {}).get("engine_zip" if os.name == "nt" else "engine")
            if not isinstance(meta, dict):
                out["note"] = "the release has no engine package"
                return out
            tmp = tempfile.mkdtemp(prefix="gnoc-engine-update-")
            try:
                arc = U._download(meta, tmp)
                stage = os.path.join(tmp, "x")
                _unpack(arc, stage, os.path.basename(arc))
                top = next((os.path.join(stage, d) for d in os.listdir(stage)
                            if os.path.isdir(os.path.join(stage, d))), stage)
                for fn in ("gnoc_engine.py", "gnoc_update.py", "VERSION", "README.md"):
                    src = os.path.join(top, fn)
                    if os.path.isfile(src):
                        shutil.copy2(src, os.path.join(here, fn + ".new"))
                        os.replace(os.path.join(here, fn + ".new"), os.path.join(here, fn))
                out["updated"] = True
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        with contextlib.suppress(Exception):
            if llama and server_path() and build_info().get("tag"):
                r = update()
                out["llama"] = r.get("tag", "") if r.get("changed") else ""
        return out
    finally:
        _UPDATE_LOCK.release()


_APP_UPDATE = {"running": False}


def _update_whole_app():
    """A paired computer's `gnoc update` asked this engine, which is part of a gnoc chat install here, to update: the
    whole app installs in the background (the signed release, checked here by gnoc_update) and this engine restarts on
    the new folder's copy. Not while a gnoc chat is open here (a restart would cut its answer); this computer's own
    paired machines are left alone (no update ping-pong). The user 2026-11-23: "it should communicate with all the
    attached machines about the restart and update"."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        import gnoc_update as U
    except Exception as e:  # noqa: BLE001
        return {"updating": False, "note": f"no updater beside this engine ({e.__class__.__name__}): gnoc update there"}
    if _APP_UPDATE["running"]:
        return {"updating": True, "note": "an update is already installing there"}
    _APP_UPDATE["running"] = True

    def job():
        try:
            rc = U.update(["--yes"], quiet=True, paired=False, restart=False)
            # the folder now installed: the new one, or (nothing newer) the current one, which an earlier update put
            # there while this engine kept running an older folder's copy
            new = os.path.join(U._LAST_INSTALLED[0] or U.APP, "scripts", "gnoc_engine.py")
            moved = os.path.realpath(new) != os.path.realpath(os.path.abspath(__file__))
            if rc == 0 and os.path.isfile(new) and (U._LAST_INSTALLED[0] or moved) and not U._chat_open_besides_me():
                _restart_soon(path=new)
        except Exception:  # noqa: BLE001 - a failed update leaves the running engine as it was
            pass
        finally:
            _APP_UPDATE["running"] = False
    threading.Thread(target=job, daemon=True, name="gnoc-app-update").start()
    return {"updating": True, "note": "installing the newest gnoc chat there; its engine restarts on it when done"}


def _restart_soon(delay=2.0, path=None):
    """Re-run this server from the (possibly new) file, after the current answer has gone out. `path`: the engine of
    a newly installed gnoc chat (each release has its own folder, so this file is the OLD one)."""
    def go():
        time.sleep(delay)
        with contextlib.suppress(Exception):
            POOL.close()
        os.execv(sys.executable, [sys.executable, os.path.abspath(path or __file__), "serve"])
    threading.Thread(target=go, daemon=True).start()


def _auto_update_loop():
    """A shared standalone engine checks once a day by itself and restarts on what it installed."""
    stamp = os.path.join(HOME, "self-update.json")
    time.sleep(300)
    while True:
        try:
            with open(stamp) as f:
                last = float(json.load(f).get("checked", 0))
        except (OSError, ValueError, TypeError, AttributeError):
            last = 0.0
        _priv_ok = True
        with contextlib.suppress(Exception):   # his /privacy switch (updates off / local-only), 2026-11-24
            import gnoc_privacy
            _priv_ok = gnoc_privacy.allowed("updates")
        if _priv_ok and time.time() - last > 20 * 3600:
            res = self_update()
            with contextlib.suppress(OSError):
                with open(stamp, "w") as f:
                    json.dump(dict(res, checked=time.time()), f)
            if res.get("updated") or res.get("llama"):
                sys.stderr.write(f"self-update: {res}\n")
                _restart_soon(1.0)
                return
        time.sleep(6 * 3600)


def _cmd_share(rest, opt):
    """gnoc engine share [on [--port N] | off]: serve other computers behind a key (the pairing line to type on the
    computer with gnoc chat), or stop."""
    port = opt("--port")
    what = (rest[0] if rest else "show").lower()
    if what in ("off", "stop", "no"):
        share(False)
        stop()
        start()
        print("  this engine serves only this computer again (and does not start at boot any more)")
        return 0
    if what in ("on", "start", "yes"):
        conf = share(True, port)
        ok, how = boot_autostart(True)
        stop()
        st, detail = start()
        print(f"  shared on port {conf['port']}: {st}" + ("" if st in ("started", "running") else f" ({detail})"))
        print(f"  starts with this computer: {'yes, ' + how if ok else 'no (' + how + ')'}")
        print(f"  updates itself once a day from signed releases: {'yes' if standalone() else 'no (gnoc update does)'}")
        if not server_path():
            print("  llama.cpp is not installed yet:  gnoc-engine install")
    conf = share_conf()
    if not conf:
        print("  not shared: only this computer can use it  (gnoc-engine share on)")
        return 0
    mode = wsl_networking()
    if mode and mode != "mirrored":
        print()
        for ln in wsl_share_steps(conf["port"]):
            print("  " + ln)
        return 0
    ips = lan_addresses() or ["<this computer's address>"]
    print("\n  On the computer with gnoc chat, type:\n")
    for ip in ips:
        print(f"    gnoc pair {ip}:{conf['port']} {conf['key']}")
    print("\n  Let port %s through this computer's firewall from that computer only. The key is the password: "
          "anyone with it can use and change these models." % conf["port"])
    return 0


def _cmd_image(rest, opt):
    """gnoc engine image "<prompt>" [-o file.png] [--model sd15|sdxl] [--size WxH]: through the running engine when
    there is one (it holds the card and frees it), else here."""
    prompt = " ".join(x for x in rest if not x.startswith("-")) if rest else ""
    out = opt("-o") or opt("--output") or os.path.join(os.getcwd(), "gnoc-image-%d.png" % int(time.time()))
    w = h = None
    if opt("--size") and "x" in opt("--size"):
        w, h = opt("--size").lower().split("x", 1)
    body = {"prompt": prompt, "model": opt("--model"), "width": w, "height": h, "stream": True}
    import base64
    if running():
        host, port = addr()
        at = f"{'127.0.0.1' if host in ('0.0.0.0', '::', '') else host}:{port}"
        req = urllib.request.Request(f"http://{at}/api/gnoc/image", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"}, method="POST")
        last = {}
        with urllib.request.urlopen(req, timeout=3600) as r:
            for line in r:
                row = json.loads(line or b"{}")
                if row.get("error"):
                    print("  " + row["error"])
                    return 1
                if row.get("image"):
                    last = row
                elif row.get("status") and row.get("status") != "success":
                    print("  " + str(row["status"]))
        png = base64.b64decode(last.get("image") or b"")
    else:
        png, last = make_image(prompt, "", w, h, None, -1, opt("--model"),
                               lambda row: row.get("status") and print("  " + str(row["status"])))
    if not png:
        print("  no image came back")
        return 1
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    with open(out, "wb") as f:
        f.write(png)
    print(f"  saved {out}  ({last.get('label', '')}, {last.get('width')}x{last.get('height')}, {last.get('seconds')} s)")
    return 0


def _cmd_image_install(rest, opt):
    name = opt("--model") or pick_image_model()
    st = {}
    if not sd_path():
        print("  " + str(install_sd(lambda r: _bar(r, st))["tag"]))
    pull_image_model(name, lambda r: _bar(r, st))
    print(f"\r\x1b[2K  image generation ready: {IMAGE_MODELS[name]['label']} ({IMAGE_MODELS[name]['licence']})")
    return 0


def _cmd_self_update(rest, opt):
    res = self_update(llama="--llama" in rest)
    print(f"  release {res['have'] or '?'} -> newest {res['latest'] or '?'}: "
          + ("UPDATED (restart: gnoc-engine restart)" if res["updated"] else res["note"] or "unchanged")
          + (f"; llama.cpp {res['llama']}" if res["llama"] else ""))
    return 0


COMMANDS = {"help": (_cmd_help, False), "-h": (_cmd_help, False), "--help": (_cmd_help, False),
            "status": (lambda rest, opt: _status(), False), "serve": (_cmd_serve, False),
            "start": (_cmd_start, False), "stop": (_cmd_stop, False), "restart": (_cmd_restart, False),
            "install": (_cmd_install, False), "update": (_cmd_update, False),
            "pull": (_cmd_pull, True), "list": (_cmd_list, False), "ls": (_cmd_list, False),
            "show": (_cmd_show, True), "rm": (_cmd_rm, True), "import-ollama": (_cmd_import_ollama, False),
            "run": (_cmd_run, True), "ps": (_cmd_ps, False), "unload": (_cmd_unload, True),
            "logs": (_cmd_logs, False), "search": (_cmd_search, True), "files": (_cmd_files, True),
            "share": (_cmd_share, False), "self-update": (_cmd_self_update, False),
            "image": (_cmd_image, True), "image-install": (_cmd_image_install, False),
            "context": (_cmd_context, False)}


def main(a=None):
    a = list(sys.argv[1:] if a is None else a)
    cmd, rest = (a[0], a[1:]) if a else ("status", [])

    def opt(flag, default=None):
        """The value after flag, taken out of the arguments."""
        if flag in rest:
            i = rest.index(flag)
            v = rest[i + 1] if i + 1 < len(rest) else default
            del rest[i:i + 2]
            return v
        return default

    run, needs_arg = COMMANDS.get(cmd, (None, False))
    try:
        if run is None or (needs_arg and not rest):
            print(_say(__doc__))
            return 2
        return run(rest, opt) or 0
    except EngineError as e:
        print(f"{PROG}: {_say(str(e))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted (a pull resumes where it stopped)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
