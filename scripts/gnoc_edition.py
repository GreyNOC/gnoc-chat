"""gnoc_edition.py - one edition, and this machine's own settings.

There is ONE gnoc (the user 2026-11-27: "make the two editions the same"). The operator's workspace and every release
run the same commands, tools and hunt harness. What differs between two machines is a SETTING, not an edition: a
linked desktop or phone, the both-GPU split server, a ComfyUI, uncensored-only models, how long a model stays loaded,
the starting models, the names the machines go by. Those come from environment variables, and an install keeps its
own in <workspace>/.claude/state/orch/machine.json:

    {"env": {"GNOC_DESKTOP_OLLAMA": "192.168.1.20:11434", "GNOC_ALLOW_STOCK": "0", "GNOC_KEEP_ALIVE": "30m"}}

An environment variable that is already set wins over the file. The file is per machine and never ships, so a fresh
install starts on ONE computer with the model `gnoc setup` picks; a second machine is `gnoc setup` or `gnoc pair`.

PUBLIC is only the build stamp: gnoc_release.py flips it in every release and refuses a build where the flip did not
happen. No feature reads it (test_gnoc_one_edition.py fails a change that branches on it).
"""
import json
import os

PUBLIC = True

# the model an install starts from when nothing is configured (gnoc_setup picks and downloads a size that fits)
DEFAULT_MODEL = "qwen3:8b"

WS = os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MACHINE = os.path.join(WS, ".claude", "state", "orch", "machine.json")


def machine_env(path=MACHINE):
    """The {"VAR": "value"} settings this machine saved, {} when there are none or the file is unreadable."""
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return {}
    env = d.get("env") if isinstance(d, dict) else None
    if not isinstance(env, dict):
        return {}
    return {str(k): str(v) for k, v in env.items() if str(k).startswith("GNOC_") and v is not None}


def apply(path=MACHINE):
    """Put this machine's settings into os.environ without overriding a variable that is already set."""
    for k, v in machine_env(path).items():
        os.environ.setdefault(k, v)


def setting(name, default=""):
    return os.environ.get(name, default)


apply()
