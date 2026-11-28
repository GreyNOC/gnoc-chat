"""Running the gateway as a service: a systemd user unit, or a Termux:Boot script on Android.

`install` only WRITES a file and prints the one command that turns it on. It never enables, starts or restarts
anything: a service that answers a messenger is the user's to switch on, the same rule as the schedule (only
the user sets one). Tokens are never written into the unit or the script; the gateway reads secrets.env at start.
"""
import os
import shlex
import subprocess
import sys

UNIT_NAME = "gnoc-gateway.service"
MARK = "# written by `gnoc gateway install`"


def on_termux(env=None):
    env = os.environ if env is None else env
    return bool(env.get("TERMUX_VERSION")) or "com.termux" in (env.get("PREFIX") or "")


def scripts_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def unit_text(python=None, scripts=None):
    python, scripts = python or sys.executable, scripts or scripts_dir()
    return (f"{MARK}. Turn it on with: systemctl --user enable --now gnoc-gateway\n"
            "[Unit]\n"
            "Description=gnoc messaging gateway (drive gnoc chat from Telegram, Slack, Signal or email)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            # systemd splits ExecStart itself; quote each word the way it unquotes (double quotes)
            f"ExecStart={_sd_quote(python)} -m gnoc_gateway run\n"
            f"Environment={_sd_quote('PYTHONPATH=' + scripts)}\n"
            "Environment=PYTHONUNBUFFERED=1\n"
            "WorkingDirectory=%h\n"
            "Restart=on-failure\n"
            "RestartSec=15\n"
            "NoNewPrivileges=yes\n"
            "\n"
            "[Install]\n"
            "WantedBy=default.target\n")


def _sd_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def boot_text(python=None, scripts=None, prefix=None, log=None):
    python, scripts = python or sys.executable, scripts or scripts_dir()
    prefix = prefix or os.environ.get("PREFIX") or "/data/data/com.termux/files/usr"
    log = log or os.path.expanduser("~/.gnoc/gateway/gateway.log")
    return (f"#!{prefix}/bin/sh\n"
            f"{MARK}. Termux:Boot runs it at boot; remove the file to stop that.\n"
            "# a wake lock, or Android dozes the phone and the long poll stops answering\n"
            "command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock\n"
            f"mkdir -p {shlex.quote(os.path.dirname(log))}\n"
            f"export PYTHONPATH={shlex.quote(scripts)}\n"
            f"exec {shlex.quote(python)} -m gnoc_gateway run >> {shlex.quote(log)} 2>&1\n")


def target_path(env=None, home=None):
    home = home or os.path.expanduser("~")
    if on_termux(env):
        return os.path.join(home, ".termux", "boot", "gnoc-gateway")
    return os.path.join(home, ".config", "systemd", "user", UNIT_NAME)


def install(env=None, home=None, force=False):
    """(ok, message). Writes the unit or boot script; refuses to replace a file it did not write."""
    termux = on_termux(env)
    path = target_path(env, home)
    text = boot_text() if termux else unit_text()
    if os.path.exists(path) and not force:
        try:
            with open(path, encoding="utf-8") as fh:
                old = fh.read()
        except OSError as e:
            return False, f"cannot read {path}: {e}"
        if MARK not in old:
            return False, f"{path} exists and was not written by gnoc; move it aside or pass --force"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o700 if termux else 0o644)
    os.replace(tmp, path)
    if termux:
        return True, (f"wrote {path}. Install the Termux:Boot app and open it once; the gateway then starts at "
                      "boot. Start it now with: sh " + shlex.quote(path))
    return True, (f"wrote {path}. Nothing is running yet. Turn it on with:\n"
                  "  systemctl --user daemon-reload && systemctl --user enable --now gnoc-gateway\n"
                  "To keep it running while you are logged out: loginctl enable-linger $USER")


def service_state(env=None, run=subprocess.run):
    """A one-line state of the installed service. Read-only."""
    path = target_path(env)
    if not os.path.exists(path):
        return f"not installed ({path} does not exist; `gnoc gateway install` writes it)"
    if on_termux(env):
        return f"installed for Termux:Boot ({path})"
    try:
        p = run(["systemctl", "--user", "is-active", UNIT_NAME], capture_output=True, text=True, timeout=10)
        state = (p.stdout or "").strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        state = "unknown (systemctl did not answer)"
    return f"installed ({path}); systemd says: {state}"
