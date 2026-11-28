"""What gnoc sends off this computer, and the switches that stop it.

The user, 2026-11-24: "can we please make sure that privacy is important still and that we have settings and options
to turn off any telem or file sharing". An audit of the shipped app found no telemetry and no crash reporting, but
several flows that send data without a clear off switch (picture reference lookups searched the first words of every
picture request on DuckDuckGo; web_search/web_fetch ran whenever the model chose; /offline only stopped the claude
worker). Every such flow now asks this module first.

    /privacy                      what leaves this computer, and each switch (also `gnoc privacy`)
    /privacy local-only on|off    one switch: nothing leaves this computer (web, picture lookups, cloud models,
                                  update checks, the shared engine's self-update, hunt traffic)
    /privacy <flow> on|off        one flow: web, image-lookup, updates, cloud

Settings live in ~/.local/share/gnoc-chat/privacy.json (kept across releases). GNOC_OFFLINE=1 or /offline on
means local-only for that run. A command the user types themselves (`gnoc update`, `gnoc models pull`, /hf) still runs:
it is their explicit request, not something gnoc does on its own.
"""
import json
import os

FLOWS = (
    ("web", "web search and page fetches by the model (queries go to DuckDuckGo; pages are fetched directly)"),
    ("image-lookup", "picture reference lookup (the first words of a picture request are searched on DuckDuckGo "
                     "and a few pages read, to describe the subject)"),
    ("updates", "update checks (your IP address and the user agent 'gnoc-chat-updater' go to your-site.example, at "
                "most once every 20 hours; no ID and nothing you typed) and a shared engine's daily self-update"),
    ("cloud", "cloud models (DeepSeek or a custom provider, Ollama ':cloud' models, the claude worker): the "
              "conversation, with secrets removed, goes to that provider; only used once you choose one"),
)
DEFAULTS = {"local_only": False, "web": True, "image-lookup": True, "updates": True, "cloud": True}
SESSION_LOCAL = [False]   # /offline on, for this run


def path():
    return os.environ.get("GNOC_PRIVACY_FILE") or os.path.expanduser("~/.local/share/gnoc-chat/privacy.json")


def load():
    d = dict(DEFAULTS)
    try:
        with open(path()) as f:
            got = json.load(f)
        if isinstance(got, dict):
            d.update({k: bool(v) for k, v in got.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return d


def save(d):
    p = path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump({k: bool(d.get(k, v)) for k, v in DEFAULTS.items()}, f, indent=1)
    os.replace(tmp, p)


def local_only():
    return bool(SESSION_LOCAL[0] or os.environ.get("GNOC_OFFLINE") == "1" or load().get("local_only"))


def allowed(flow):
    """True when this flow may send data off the computer now."""
    if local_only():
        return False
    if flow == "updates" and os.environ.get("GNOC_NO_UPDATE_CHECK") == "1":
        return False
    return bool(load().get(flow, True))


def why_not(flow):
    """The one line that says why a flow is off and how to turn it on, or '' when it is allowed."""
    if allowed(flow):
        return ""
    if local_only():
        how = ("/offline off" if SESSION_LOCAL[0] else "unset GNOC_OFFLINE" if os.environ.get("GNOC_OFFLINE") == "1"
               else "/privacy local-only off")
        return f"local-only mode is on, so nothing leaves this computer ({how} to change it)"
    if flow == "updates" and os.environ.get("GNOC_NO_UPDATE_CHECK") == "1":
        return "update checks are off (GNOC_NO_UPDATE_CHECK=1)"
    return f"{flow} is switched off in /privacy (/privacy {flow} on to allow it)"


def report():
    d = load()
    lo = local_only()
    lines = ["PRIVACY: what can leave this computer, and the switch for each. There is no telemetry, no usage "
             "reporting and no crash reporting.",
             f"  local-only: {'ON - nothing below leaves this computer' if lo else 'off'}"
             + ("  (this run: /offline on)" if SESSION_LOCAL[0] else "  (GNOC_OFFLINE=1)"
                if os.environ.get("GNOC_OFFLINE") == "1" else "") + "   /privacy local-only on|off"]
    for name, what in FLOWS:
        state = "allowed" if allowed(name) else ("OFF (local-only)" if lo and d.get(name, True) else "OFF")
        lines.append(f"  {name:<13} {state:<17} {what}   /privacy {name} on|off")
    lines += ["  Always local: chats and the past-chat index (~/.gnoc), the lesson book, the defender's alerts and "
              "journal, desktop notifications, pictures (saved to Downloads).",
              "  Only when you ask: model downloads (`gnoc models pull`, /hf), `gnoc update`, MCP servers you add, "
              "pairing another computer (`gnoc pair`), sharing this computer's engine (`gnoc-engine share on`)."]
    return "\n".join(lines)


def command(rest):
    """The /privacy and `gnoc privacy` command: report, or set one switch. -> the text to show."""
    words = str(rest or "").lower().replace("_", "-").split()
    if not words or words[0] in ("show", "status", "list"):
        return report()
    names = {"local-only": "local_only", "local": "local_only", "offline": "local_only", "web": "web",
             "image-lookup": "image-lookup", "images": "image-lookup", "image": "image-lookup",
             "lookup": "image-lookup", "updates": "updates", "update": "updates", "cloud": "cloud"}
    if len(words) != 2 or words[0] not in names or words[1] not in ("on", "off"):
        return ("usage: /privacy  |  /privacy local-only on|off  |  /privacy web|image-lookup|updates|cloud on|off")
    d = load()
    d[names[words[0]]] = words[1] == "on"
    save(d)
    return report()


if __name__ == "__main__":
    import sys
    print(command(" ".join(sys.argv[1:])))
