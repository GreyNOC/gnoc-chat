"""Gateway settings: the environment first, then ~/.config/gnoc/secrets.env (the file gnoc keeps out of prompts)."""
import os
import re

SECRETS = "~/.config/gnoc/secrets.env"

# Every credential an adapter holds. The Redactor replaces each value (and its encoded forms) in every outbound
# message, on top of gnoc_secrets' own store, so a token reaching a reply through an error string is still caught.
TOKEN_NAMES = ("TELEGRAM_BOT_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "DISCORD_BOT_TOKEN", "GNOC_EMAIL_PASS")

_LINE = re.compile(r"\s*(?:export\s+)?([A-Za-z_]\w*)\s*=\s*(.*?)\s*$")


def reader(path=None, env=None):
    """conf(name) -> str or None. Values are never logged and never reach a model."""
    path = os.path.expanduser(path or SECRETS)
    env = os.environ if env is None else env

    def conf(name):
        if env.get(name):
            return env[name]
        try:
            with open(path, encoding="utf-8") as fh:
                for ln in fh:
                    m = _LINE.match(ln)
                    if m and m.group(1) == name:
                        return m.group(2).strip().strip("'\"")
        except OSError:
            return None
        return None
    return conf


def ids(raw, pattern):
    """The comma/space separated ids in `raw` that fully match `pattern`; anything else is dropped, so a
    username typed where an id belongs allows nobody rather than whoever holds that name today."""
    return {p.strip() for p in re.split(r"[,\s]+", raw or "") if p.strip() and re.fullmatch(pattern, p.strip())}


def tokens(conf):
    return [v for v in (conf(n) for n in TOKEN_NAMES) if v]


def state_dir():
    return os.path.expanduser(os.environ.get("GNOC_GATEWAY_HOME") or "~/.gnoc/gateway")
