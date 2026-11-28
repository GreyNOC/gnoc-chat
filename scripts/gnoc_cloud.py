"""gnoc_cloud.py - OpenAI-compatible CLOUD model providers for gnoc chat.

Built in, every frontier lab's own API, Claude first: anthropic (Claude), openai, gemini, xai (Grok), meta (Llama),
mistral, deepseek, moonshot (Kimi), qwen. /claude, /gpt, /gemini, /grok, /llama, /mistral, /deepseek, /kimi and /qwen
are short for /cloud <provider>:
    /claude api sk-ant-...    save the key (goes to ~/.config/gnoc/secrets.env, chmod 600, never the repo)
    /claude                   status: key present?, which model, is it the current lead?
    /claude on [model]        make Claude the lead role (default claude-opus-5-5)
    /claude off               hand the lead back to the local model
    /claude models            the model names this provider serves

Any OpenAI-compatible endpoint (model agnostic):
    /cloud add <name> <base-url> <default-model> [api-key|-]   register ANY provider that speaks
                            POST /v1/chat/completions (OpenAI, OpenRouter, Groq, Together, vLLM,
                            llama.cpp's server, a proxy...). No api-key, or '-' as the key, marks it
                            keyless (self-hosted). Stored in ~/.config/gnoc/cloud-providers.json
                            (chmod 600, outside the repo; keys live there or in GNOC_CLOUD_<NAME>_API_KEY).
    /cloud rm <name>        remove a custom provider (a removed override restores the builtin of that name)
    /cloud list             every provider, custom and built in
    /cloud <name> on [model]   make one of them the lead (model name is free-form; the listed models are
                            advisory, not a gate)
    /cloud <name> off       back to the local model
    /cloud <name> api <key>    set the key of a custom provider (builtins keep their secrets.env entry)

WHY THIS FILE EXISTS AND WHAT IT COSTS, stated once, here, so nobody has to rediscover it:

A cloud model sends the conversation off the machine. A hunt turn carries captured bytes,
hostnames, provisioned account names, draft findings, and sometimes credentials. Sending that to a
third-party API is a real disclosure, it is irreversible, and for an unfiled finding it can also be a
disclosure to the vendor's competitors or to the vendor itself.

So this is OPT-IN and NEVER a default:
  - no key, no provider: nothing changes and nothing is sent anywhere
  - the key lives outside the workspace (secrets.env or cloud-providers.json, both chmod 600)
  - every outgoing message is run through gnoc_secrets.redact() first, so a token that leaked into the
    transcript does not leave the machine in the prompt
  - the lead only becomes a cloud model when asked for by name, and `gnoc gpus` shows it
  - a program whose policy bans AI agents (lib_policy AGENT-BANNED) is refused outright

Any model may be the lead (2026-11-27: the uncensored-only rule is gone). If a model declines a task, that is the
model, not the harness: pick another with /model or /cloud <name> off.
"""
import json
import os
import re
import urllib.error
import urllib.request

SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
# Custom providers: name -> {base_url, default, models, api_key, keyless}. Same directory as secrets.env,
# outside the workspace, chmod 600 like every other credential file. GNOC_CLOUD_PROVIDERS overrides the
# path (tests and disposable setups).
CUSTOM = os.environ.get("GNOC_CLOUD_PROVIDERS") or os.path.join(os.path.dirname(SECRETS), "cloud-providers.json")

# name -> (base_url, env var holding the key, default model, the models it serves)
# The frontier labs' own APIs (2026-11-27: "open it up to api from all the frontier labs, put claude first"). Order is
# the order every list shows them in (/cloud list, /model, gnoc setup), so Claude is first. Same opt-in rule for all:
# no key, nothing is sent; a key alone does not make a provider the lead, only /cloud <name> on (or /claude on) does.
# Model names are advisory: any model the provider serves is accepted, so a new release needs no gnoc update.
PROVIDERS = {
    "anthropic": ("https://api.anthropic.com", "ANTHROPIC_API_KEY", "claude-opus-5-5",
                  ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2")),
    "openai": ("https://app.example.com", "OPENAI_API_KEY", "gpt-5",
               ("gpt-5", "gpt-5-mini", "gpt-5-nano")),
    "gemini": ("https://generativelanguage.googleapis.com", "GEMINI_API_KEY", "gemini-2.5-pro",
               ("gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite")),
    "xai": ("https://api.x.ai", "XAI_API_KEY", "grok-4", ("grok-4", "grok-3", "grok-3-mini")),
    "meta": ("https://api.llama.com/compat/v1/chat/completions", "LLAMA_API_KEY",
             "Llama-4-Maverick-17B-128E-Instruct-FP8",
             ("Llama-4-Maverick-17B-128E-Instruct-FP8", "Llama-4-Scout-17B-16E-Instruct-FP8")),
    "mistral": ("https://api.mistral.ai", "MISTRAL_API_KEY", "mistral-large-latest",
                ("mistral-large-latest", "mistral-medium-latest", "codestral-latest")),
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat",
                 ("deepseek-chat", "deepseek-reasoner")),
    "moonshot": ("https://api.moonshot.ai", "MOONSHOT_API_KEY", "kimi-k2-turbo-preview",
                 ("kimi-k2-turbo-preview", "kimi-k2-0905-preview")),
    "qwen": ("https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions", "DASHSCOPE_API_KEY",
             "qwen-max", ("qwen-max", "qwen-plus", "qwen-turbo")),
}
# what people call them: /claude, /gpt, /grok ... are the same command as /cloud <provider>
ALIASES = {"claude": "anthropic", "gpt": "openai", "chatgpt": "openai", "google": "gemini", "grok": "xai",
           "llama": "meta", "kimi": "moonshot", "alibaba": "qwen"}


def canonical(name):
    """The provider a name or alias means ('claude' -> 'anthropic'); the name itself when it is not an alias."""
    n = str(name or "").strip().lower()
    return ALIASES.get(n, n)
# The wire a provider speaks (gnoc_core.providers): "openai" (POST /v1/chat/completions) unless named here. A custom
# provider carries its own "wire" in cloud-providers.json; an entry without one is "openai", so every config written
# before wires existed means exactly what it meant.
WIRES = ("openai", "anthropic", "gemini")
PROVIDER_WIRES = {"anthropic": "anthropic", "gemini": "gemini"}
# How a native wire asks for reasoning: "adaptive" (Claude 4.6+, Gemini 2.5), "budget" (older Claude models that take
# budget_tokens), "off" (never ask). Custom providers may set "thinking" in cloud-providers.json.
THINKING_STYLES = ("adaptive", "budget", "off")
KEY_SHAPE = re.compile(r"^[A-Za-z0-9_\-]{16,200}$")
# A custom provider name is a host suffix in "model@name", so it must stay DNS-ish; the words the
# /cloud handler treats as subcommands are reserved, or `/cloud add ...` could never be typed.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
RESERVED = {"add", "rm", "remove", "list", "api", "key", "set", "on", "use", "off", "models",
            "clear", "forget", "check", "test"}


def providers():
    """Merged provider table, name -> (base_url, env, default, models). A custom entry of the same name
    OVERRIDES a builtin (re-pointing deepseek at a proxy is a legitimate move), and remove_provider()
    restores the builtin. The custom file is re-read on every call, so `/cloud add` is live immediately
    (the same contract roles() has for models.json)."""
    d = {name: tuple(row) for name, row in PROVIDERS.items()}   # insertion order: Claude first
    d.update({name: (c["base"], c["env"], c["default"], c["models"]) for name, c in _custom_read().items()})
    return d


def is_cloud(host):
    return canonical(host) in providers()


def _custom_read():
    """The custom provider file as a dict of cfg dicts; {} when it is absent or unreadable. Entries with
    a missing base_url or default model are skipped, so one bad line never breaks every provider."""
    out = {}
    try:
        with open(CUSTOM, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return out
    if not isinstance(d, dict):
        return out
    for name, cfg in d.items():
        name = str(name).lower()
        if not NAME_RE.match(name) or not isinstance(cfg, dict):
            continue
        base = str(cfg.get("base_url") or "").strip().rstrip("/")
        default = str(cfg.get("default") or cfg.get("model") or "").strip()
        if not re.match(r"^https?://", base) or not default:
            continue
        models = tuple(str(m).strip() for m in (cfg.get("models") or ()) if str(m).strip())
        if not models:
            models = (default,)
        env = f"GNOC_CLOUD_{re.sub(r'[^A-Za-z0-9]', '_', name).upper()}_API_KEY"
        wire = str(cfg.get("wire") or "openai").strip().lower()
        if wire not in WIRES:
            continue   # a wire this build cannot speak: skipped like any other bad entry, never sent the wrong shape
        thinking = str(cfg.get("thinking") or "adaptive").strip().lower()
        out[name] = {"base": base, "env": env, "default": default, "models": models,
                     "api_key": str(cfg.get("api_key") or "").strip(),
                     "keyless": bool(cfg.get("keyless")), "wire": wire,
                     "thinking": thinking if thinking in THINKING_STYLES else "adaptive"}
    return out


def wire_for(provider):
    """The wire this provider speaks: its custom entry's "wire", else the builtin's, else "openai"."""
    p = str(provider or "").lower()
    c = _custom_read().get(p)
    if c:
        return c["wire"]
    return PROVIDER_WIRES.get(p, "openai")


def thinking_style(provider):
    """How a native wire asks this provider for reasoning (THINKING_STYLES); "adaptive" unless configured."""
    c = _custom_read().get(str(provider or "").lower())
    return c["thinking"] if c else "adaptive"


def keyless(provider):
    """True when this provider was explicitly registered as keyless (a self-hosted OpenAI-compatible
    server). A builtin never is: DeepSeek without a key stays refused, not silently unauthenticated."""
    return bool(_custom_read().get(str(provider or "").lower(), {}).get("keyless"))


def key_for(provider):
    """The API key, inline custom config first, then the environment, then secrets.env. Never returned
    to a model or a log."""
    p = str(provider or "").lower()
    inline = _custom_read().get(p, {}).get("api_key") or ""
    if inline:
        return inline
    cfg = providers().get(p)
    if not cfg:
        return ""
    _, env, _, _ = cfg
    return (os.environ.get(env) or _read_env().get(env) or "").strip()


def _read_env():
    out = {}
    try:
        with open(SECRETS, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def _write_custom(d, chmod=0o600):
    os.makedirs(os.path.dirname(CUSTOM), exist_ok=True)
    tmp = CUSTOM + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=1)
    os.chmod(tmp, chmod)
    os.replace(tmp, CUSTOM)
    os.chmod(CUSTOM, chmod)


def add_provider(name, base_url, default, models=(), api_key=None, wire=None):
    """Register a custom provider. Returns (ok, message).
    api_key: a key string to store inline, '-' or None for a KEYLESS endpoint (self-hosted).
    wire: "openai" (the default, any OpenAI-compatible endpoint), "anthropic" or "gemini" (a proxy or gateway in
    front of those APIs). A name that overrides a builtin keeps the builtin's wire unless one is given."""
    name = (name or "").strip().lower()
    if not NAME_RE.match(name):
        return False, f"provider name {name!r} is not valid (lowercase letters, digits, . _ -, up to 32 chars)"
    if name in RESERVED:
        return False, f"{name!r} is a reserved /cloud word; pick another name"
    wire = str(wire or PROVIDER_WIRES.get(name, "openai")).strip().lower()
    if wire not in WIRES:
        return False, f"wire {wire!r} is not one gnoc speaks ({', '.join(WIRES)})"
    base = (base_url or "").strip().rstrip("/")
    if not re.match(r"^https?://", base):
        return False, f"base URL must start with http:// or https:// (got {base_url!r})"
    default = (default or "").strip()
    if not default:
        return False, "a default model name is required: /cloud add <name> <base-url> <model> [api-key|-]"
    models = tuple(str(m).strip() for m in (models or ()) if str(m).strip())
    if not models:
        models = (default,)
    d = _custom_read()
    entry = {"base_url": base, "default": default}
    if len(models) > 1 or models[0] != default:
        entry["models"] = list(models)
    if wire != "openai":
        entry["wire"] = wire   # written only when it is not the default, so an openai entry is byte-for-byte as before
    if api_key in (None, "", "-"):
        entry["keyless"] = True
        entry["api_key"] = ""
    else:
        entry["keyless"] = False
        entry["api_key"] = api_key.strip()
        if len(entry["api_key"]) < 8:
            return False, "that does not look like an API key (8+ characters); use '-' instead for a keyless endpoint"
    d[name] = entry
    _write_custom(d)
    what = "keyless" if entry["keyless"] else f"key stored inline ({len(entry['api_key'])} chars)"
    if wire != "openai":
        what += f", {wire} wire"
    return True, (f"provider {name} -> {base} (default {default}, {what}). "
                  f"Try it with /cloud {name} check, then /cloud {name} on.")


def remove_provider(name):
    """Remove a CUSTOM provider. Removing a name that overrode a builtin restores the builtin."""
    name = str(name or "").strip().lower()
    d = _custom_read()
    if name not in d:
        return False, f"no custom provider {name!r} (/cloud list shows them)"
    del d[name]
    _write_custom(d)
    return True, (f"{name} removed" + (f"; the builtin {name} is back in force" if name in PROVIDERS else ""))


def save_key(provider, key):
    """Write the key: builtins keep their secrets.env entry; custom providers store it inline in
    cloud-providers.json. Returns (ok, message)."""
    provider = str(provider or "").strip().lower()
    if provider not in providers():
        return False, f"unknown provider {provider!r}; known: {', '.join(list(providers()))} " \
                      f"(register one with /cloud add <name> <base-url> <model>)"
    key = (key or "").strip().strip('"').strip("'")
    if provider in _custom_read():
        if len(key) < 8:
            return False, "that does not look like an API key (8+ characters). Nothing was written."
        d = _custom_read()
        d[provider]["api_key"] = key
        d[provider]["keyless"] = False
        _write_custom(d)
        return True, f"{provider} key stored inline in {CUSTOM} ({len(key)} chars, ending {key[-4:]})."
    if not key:
        return False, f"no key given. Usage: /{provider} api sk-..."
    if not KEY_SHAPE.match(key):
        return False, ("that does not look like an API key (expected 16+ characters, letters, digits, "
                       "- and _). Nothing was written.")
    _, env, _, _ = providers()[provider]
    os.makedirs(os.path.dirname(SECRETS), exist_ok=True)
    lines, found = [], False
    try:
        with open(SECRETS, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                if ln.strip().startswith(env + "=") or ln.strip().startswith("export " + env + "="):
                    lines.append(f"{env}={key}\n")
                    found = True
                else:
                    lines.append(ln)
    except OSError:
        pass
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(f"# {provider} cloud model for gnoc chat (added by /{provider} api)\n")
        lines.append(f"{env}={key}\n")
    tmp = SECRETS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRETS)
    os.chmod(SECRETS, 0o600)
    os.environ[env] = key                       # live for this process, no restart needed
    return True, (f"{provider} key saved to {SECRETS} (chmod 600, outside the repo). "
                  f"{len(key)} chars, ending {key[-4:]}.")


def clear_key(provider):
    provider = str(provider or "").strip().lower()
    if provider in _custom_read():
        d = _custom_read()
        d[provider]["api_key"] = ""
        d[provider]["keyless"] = False
        _write_custom(d)
        return True, f"{provider} key removed from {CUSTOM}"
    if provider not in providers():
        return False, f"unknown provider {provider!r}"
    _, env, _, _ = providers()[provider]
    out, removed = [], False
    try:
        with open(SECRETS, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                if ln.strip().startswith(env + "=") or ln.strip().startswith("export " + env + "="):
                    removed = True
                    continue
                out.append(ln)
    except OSError:
        return False, "no secrets.env to clear"
    tmp = SECRETS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.writelines(out)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SECRETS)
    os.environ.pop(env, None)
    return removed, ("key removed" if removed else "no key was set")


def _chat_url(base, wire="openai", model=""):
    base = base.rstrip("/")
    if wire == "anthropic":
        if base.endswith("/v1/messages"):
            return base
        return base + ("/messages" if base.endswith("/v1") else "/v1/messages")
    if wire == "gemini":
        from gnoc_core import providers as wires
        return wires.gemini_url(base, model, stream=True)
    # a base URL may already point at the completions path (some gateways document it that way)
    return base if base.endswith("/chat/completions") else base + "/v1/chat/completions"


def endpoint(provider, model=None):
    """(url, model, headers) for a chat completion, or raises if the key is missing / provider unknown."""
    provider = canonical(provider)
    cfg = providers().get(provider)
    if not cfg:
        raise RuntimeError(f"unknown provider {provider!r}; known: {', '.join(providers())} "
                           f"(register one with /cloud add <name> <base-url> <model>)")
    base, env, default, _ = cfg
    k = key_for(provider)
    if not k and not keyless(provider):
        # /<name> api only exists for deepseek; every other provider's key is set through /cloud <name> api
        hint = f"/{provider} api <key>" if provider in PROVIDERS else f"/cloud {provider} api <key>"
        raise RuntimeError(f"no {provider} API key. Set one with:  {hint}   "
                           f"(or put {env}= in {SECRETS}; a self-hosted endpoint is registered keyless "
                           f"with /cloud add {provider} <base-url> <model> -)")
    wire = wire_for(provider)
    mdl = model or default
    hdrs = {"Content-Type": "application/json"}
    # each wire's own auth header; the key is never put in the URL (Gemini also accepts ?key=, which would land in
    # every proxy and error log that prints a URL)
    if wire == "anthropic":
        from gnoc_core import providers as wires
        hdrs["anthropic-version"] = wires.ANTHROPIC_VERSION
        if k:
            hdrs["x-api-key"] = k
    elif wire == "gemini":
        if k:
            hdrs["x-goog-api-key"] = k
    elif k:
        hdrs["Authorization"] = "Bearer " + k
    return (_chat_url(base, wire, mdl), mdl, hdrs)


def check(provider, model=None, timeout=20):
    """One tiny live call. (ok, message) - used by /cloud <name> api to prove the key works before it is trusted."""
    try:
        url, mdl, hdrs = endpoint(provider, model)
    except RuntimeError as e:
        return False, str(e)
    from gnoc_core import providers as wires
    wire = wire_for(provider)
    url, body = wires.check_request(wire, url, mdl)
    try:
        req = urllib.request.Request(url, json.dumps(body).encode(), hdrs)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
        txt = wires.check_text(wire, d)
        return True, f"{provider}/{mdl} answered: {txt[:40]!r}"
    except urllib.error.HTTPError as e:
        with e:
            detail = e.read().decode(errors="replace")[:200]
        if e.code in (401, 403):
            return False, f"{provider} rejected the key (HTTP {e.code}). Check it and run /{provider} api again."
        if e.code == 402:
            return False, f"{provider} says the account has no credit (HTTP 402): {detail}"
        return False, f"{provider} HTTP {e.code}: {detail}"
    except Exception as e:  # noqa: BLE001
        return False, f"{provider} unreachable: {str(e)[:160]}"


def redact_messages(messages):
    """Every outgoing message through the secret scrubber. A cloud provider is OFF the machine: a token
    that leaked into the transcript must not leave in the prompt."""
    try:
        import gnoc_secrets
    except Exception:  # noqa: BLE001 - never block a call because the scrubber is missing
        return messages
    out = []
    for m in messages or []:
        if isinstance(m, dict) and isinstance(m.get("content"), str):
            m = dict(m)
            m["content"] = gnoc_secrets.redact(m["content"])
        if isinstance(m, dict) and m.get("tool_calls"):
            # the ARGUMENTS of earlier tool calls go out too: a token typed into a bash command left in the request
            # body (QAQC r2)
            m = dict(m)
            calls = []
            for c in m["tool_calls"]:
                c = dict(c) if isinstance(c, dict) else c
                fn = dict(c.get("function") or {}) if isinstance(c, dict) else None
                if fn is not None:
                    a = fn.get("arguments")
                    if isinstance(a, str):
                        fn["arguments"] = gnoc_secrets.redact(a)
                    elif isinstance(a, dict):
                        import json as _json
                        fn["arguments"] = _json.loads(gnoc_secrets.redact(_json.dumps(a)))
                    c["function"] = fn
                calls.append(c)
            m["tool_calls"] = calls
        out.append(m)
    return out


def status(provider="deepseek"):
    cfg = providers().get(str(provider).lower())
    if not cfg:
        return f"unknown provider {provider!r}  (/cloud list shows them)"
    base, env, default, models = cfg
    k = key_for(provider)
    kl = keyless(provider)
    if kl:
        kline = "KEYLESS (self-hosted: no Authorization header is sent)"
    elif k:
        kline = f"set ({len(k)} chars, ending {k[-4:]})"
    else:
        kline = "NOT SET"
    wire = wire_for(provider)
    lines = [f"{provider}: {base}" + (f"   ({wire} wire)" if wire != "openai" else ""),
             f"  key    : {kline}",
             f"  key env: {env} in {SECRETS}",
             f"  models : {', '.join(models)}   (default {default}; any model name is accepted on /on)",
             f"  use    : /{provider} on [model]   then /{provider} off to go back local"]
    if not k and not kl:
        lines.append(f"  set it : /{provider} api <key>")
    if provider in PROVIDERS:
        lines.append("  NOTE   : this is a CLOUD model. The hunt conversation (captured bytes, hostnames, "
                     "account names, draft findings) leaves this machine when it is the lead. Secrets are "
                     "scrubbed from every message first, but the rest still goes.")
    else:
        lines.append("  NOTE   : cloud/off-machine unless the base_url is a loopback or LAN address you "
                     "control. The same warning and secret scrubber apply.")
    return "\n".join(lines)
