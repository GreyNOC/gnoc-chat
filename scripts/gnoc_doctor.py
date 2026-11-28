"""gnoc_doctor.py - `gnoc doctor` / `/doctor`: is this install healthy, and if not, what to do about it.

One screen, one line per check, each with the fix when it is not fine:

    ✓  fine     !  works, but worth a look     ✗  something gnoc needs is broken

It reads only: nothing is installed, started, downloaded or changed. The model checks talk to the Ollama (or
cloud) endpoints gnoc is set to use, with short time limits, so a dead host costs a few seconds, not minutes.
Exit status 1 when anything is ✗, so a script can run `gnoc doctor` before a job.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import subprocess
import sys

import gnoc_platform

HERE = os.path.dirname(os.path.realpath(__file__))
APP = os.path.dirname(HERE)
OK, WARN, FAIL = "ok", "warn", "fail"
# import name -> requirements.txt name, for the packages gnoc cannot start without
NEEDED = (("prompt_toolkit", "prompt_toolkit"), ("requests", "requests"), ("bs4", "beautifulsoup4"),
          ("markdown", "Markdown"), ("pygments", "Pygments"), ("curl_cffi", "curl_cffi"))


def _check(rows, status, label, detail="", fix=""):
    rows.append({"status": status, "label": label, "detail": detail, "fix": fix})


def _updater():
    """The shipped updater module, or None in a source checkout."""
    p = os.path.join(HERE, "gnoc_update.py")
    if not os.path.isfile(p):
        return None
    try:
        spec = importlib.util.spec_from_file_location("gnoc_update_for_doctor", p)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


def _version():
    try:
        with open(os.path.join(APP, "VERSION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _termux():
    return gnoc_platform.is_termux()


def check_platform(rows):
    """Inside Termux: say so, and say what Android and Termux leave out, before any check gives desktop advice."""
    if not _termux():
        return
    _check(rows, OK, "platform", "Termux on Android" + (f" {os.environ['TERMUX_VERSION']}"
                                                      if os.environ.get("TERMUX_VERSION") else "")
           + f" (programs in {gnoc_platform.termux_prefix()}, packages from pkg)")
    _check(rows, OK, "root and systemd features",
           "off here: the defender's firewall, packet and process actions and the systemd vulnerability timer "
           "need root or systemd, not available on Termux; /defender sweep runs a reduced read-only set")
    st = gnoc_platform.crond_state()
    if st == "ok":
        _check(rows, OK, "scheduled sweeps", "crond runs under termux-services")
    elif _crontab_has_gnoc():
        # a schedule nobody reads is the real failure: the user thinks sweeps run and none do
        _check(rows, WARN, "scheduled sweeps", "a /defender schedule is set, but crond is not running, so it never "
               "fires", gnoc_platform.CROND_HELP)
    else:
        _check(rows, OK, "scheduled sweeps", "crond is not set up (only /defender schedule needs it: "
               + gnoc_platform.CROND_HELP + ")")
    if os.path.isdir(os.path.join(os.path.expanduser("~"), "storage")):
        _check(rows, OK, "shared storage", "Termux can read and write your shared storage (~/storage), and so can "
               "every command gnoc runs")
    else:
        _check(rows, OK, "shared storage", "not granted (termux-setup-storage grants it when you want files from "
               "Downloads or the camera)")


# gnoc_defender.SCHEDULE_MARK, spelled out: importing the defender pulls in the whole host-check stack for one
# string (the phase-9 test pins the two together)
SCHEDULE_MARK = "# gnoc-defender-schedule"


def _crontab_has_gnoc():
    mark = SCHEDULE_MARK
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0 and mark in r.stdout


def check_install(rows):
    v = _version()
    _check(rows, OK, f"gnoc chat {v}" if v else "gnoc chat (a source checkout: no VERSION file)", APP)
    py = sys.version_info
    if py < (3, 10):
        _check(rows, FAIL, f"Python {py[0]}.{py[1]}", "gnoc chat needs 3.10 or newer",
               "pkg upgrade python, then run install.sh again" if _termux() else
               "install a newer Python, then run install.sh again")
    else:
        _check(rows, OK, f"Python {py[0]}.{py[1]}.{py[2]}", sys.executable)
    missing = [req for mod, req in NEEDED if importlib.util.find_spec(mod) is None]
    venv = os.environ.get("GNOC_VENV") or os.path.join(os.path.expanduser("~"), ".local", "share", "gnoc-chat", "venv")
    if missing:
        _check(rows, FAIL, "Python packages", "missing: " + ", ".join(missing),
               f"remove {venv} and start gnoc again: it rebuilds its environment")
    else:
        _check(rows, OK, "Python packages", "everything gnoc needs is installed")
    launcher = os.path.join(APP, "gnoc-launcher")
    if os.path.isfile(launcher):
        found = shutil.which("gnoc")
        if not found:
            _check(rows, WARN, "the gnoc command", "not on your PATH",
                   "run install.sh again: inside Termux it puts gnoc in $PREFIX/bin, which is always on PATH"
                   if _termux() else
                   "open a new terminal, or add ~/.local/bin to PATH (install.sh prints the line)")
        elif os.path.realpath(found) != os.path.realpath(launcher):
            _check(rows, WARN, "the gnoc command", f"{found} runs {os.path.realpath(found)}, not this copy",
                   "fine right after an update (the old copy is the one checking); otherwise run install.sh "
                   "in the copy you want")
        else:
            _check(rows, OK, "the gnoc command", found)
    if not shutil.which("git"):
        _check(rows, WARN, "git", "not installed: diffs, /undo across commits and worktree helpers need it",
               gnoc_platform.pkg_hint("git") or "install git with your package manager")


def check_workspace(rows):
    try:
        import llm_endpoints
        ws = llm_endpoints.WS
    except Exception:  # noqa: BLE001
        ws = os.environ.get("GNOC_WORKSPACE") or os.path.join(os.path.expanduser("~"), ".gnoc")
    if not os.path.isdir(ws):
        _check(rows, FAIL, "workspace", f"{ws} does not exist", "start gnoc once: the launcher creates it")
        return
    if not os.access(ws, os.W_OK):
        # Termux has no sudo, and every file in its home belongs to the one app user anyway
        _check(rows, FAIL, "workspace", f"{ws} is not writable",
               f"check it with  ls -ld {ws}  and give yourself write access (chmod u+w), or move it aside and "
               "start gnoc again" if _termux() else f"fix its owner: sudo chown -R $USER {ws}")
        return
    try:
        free = shutil.disk_usage(ws).free / 2 ** 30
    except OSError:
        free = None
    if free is not None and free < 2:
        _check(rows, WARN, "disk space", f"{free:.1f} GB free where your workspace is",
               "free some space: sessions and logs stop being saved when the disk fills")
    else:
        _check(rows, OK, "workspace", ws + (f"  ({free:.0f} GB free)" if free is not None else ""))


def _role_spec_default(role):
    import llm_endpoints
    return llm_endpoints.roles().get(role) or llm_endpoints.DEFAULT


def check_models(rows, role_spec=None):
    try:
        import llm_endpoints
        import gnoc_setup
    except Exception as e:  # noqa: BLE001
        _check(rows, FAIL, "models", f"could not load the model settings ({e.__class__.__name__}: {e})")
        return
    role_spec = role_spec or _role_spec_default
    seen = {}
    for role in ("lead", "worker"):
        try:
            spec = role_spec(role)
        except Exception:  # noqa: BLE001
            spec = _role_spec_default(role)
        name, host = llm_endpoints.split(spec)
        bad = FAIL if role == "lead" else WARN
        if (name, host) in seen:
            _check(rows, seen[(name, host)], f"{role} model", f"{name} (same as the lead)")
            continue
        label = f"{role} model"
        if llm_endpoints.is_cloud(host):
            try:
                import gnoc_cloud
                has = bool(gnoc_cloud.key_for(host) or gnoc_cloud.keyless(host))
            except Exception:  # noqa: BLE001
                has = False
            st = OK if has else bad
            _check(rows, st, label, f"{name} on {host} (cloud)" + ("" if has else ": no API key"),
                   "" if has else f"/cloud {host} api <key> in the chat, or gnoc setup")
        elif host not in llm_endpoints.HOSTS or not llm_endpoints.HOSTS.get(host):
            st = bad
            _check(rows, st, label, f"{name} on {host}: this install does not know that machine",
                   "gnoc setup picks a model again")
        elif not llm_endpoints.up(host):
            st = bad
            where = "this computer" if host == "local" else f"{host} ({llm_endpoints.HOSTS[host]})"
            _check(rows, st, label, f"{name}: the model server on {where} does not answer at {llm_endpoints.HOSTS[host]}",
                   "gnoc engine start   (or start your Ollama), or run gnoc setup"
                   if host == "local" else "is that computer on, and is its model server listening on the network? "
                                           "gnoc setup")
        else:
            tags = gnoc_setup._tags(host)
            if gnoc_setup._has(tags, name):
                st = OK
                _check(rows, st, label, f"{name} on {'this computer' if host == 'local' else host}")
            else:
                st = bad
                _check(rows, st, label, f"{name} is not downloaded on {'this computer' if host == 'local' else host}",
                       f"gnoc engine pull {name}   (or gnoc setup to pick one you have)")
        seen[(name, host)] = st


def check_termux_models(rows):
    """Inside Termux, when the lead has no working model: the three ways a phone gets one. A phone's CPU runs a
    1.7B-4B model at a few tokens a second and heats up, so the big local models a desktop setup offers are the
    wrong advice here."""
    if not _termux():
        return
    lead = next((r for r in rows if r["label"] == "lead model"), None)
    if lead is None or lead["status"] == OK:
        return
    _check(rows, WARN, "a model for this phone", "pick one of three: the model server on your desktop (private, "
           "its GPU), a cloud model with an API key, or a small model on this phone (slow, warm)",
           "gnoc setup  (it walks through all three)")


def check_updates(rows):
    if os.environ.get("GNOC_NO_UPDATE_CHECK") == "1":
        _check(rows, WARN, "updates", "the daily check is off (GNOC_NO_UPDATE_CHECK=1)",
               "gnoc update --check looks by hand")
    U = _updater()
    if U is None:
        return
    mine = _version()
    if not U._key():
        _check(rows, WARN, "updates", "this copy was built without the release key, so it cannot update itself",
               f"download the newest release from {U.PAGE}")
        return
    st = U._read_state()
    auto = "auto-update on" if st.get("auto") else "auto-update off (gnoc update --auto on)"
    latest = st.get("latest")
    if st.get("held_back"):
        _check(rows, FAIL, "updates", f"the download page went back to {latest} after offering {st.get('highest_seen')}",
               f"a stale or tampered mirror: check {U.PAGE}")
    elif latest and mine and U.newer(latest, mine):
        _check(rows, WARN, "updates", f"{latest} is out (you have {mine}); {auto}", "gnoc update")
    elif st.get("ok") is False:
        _check(rows, WARN, "updates", f"the last check could not reach the download page; {auto}",
               "gnoc update --check tries again and says why")
    elif not st.get("checked_at"):
        _check(rows, OK, "updates", f"not checked yet; {auto}")
    else:
        _check(rows, OK, "updates", f"up to date; {auto}")


def check_config(rows):
    problems = []
    try:
        import gnoc_hooks
        p = gnoc_hooks.user_hooks_path()
        if os.path.isfile(p):
            try:
                gnoc_hooks._load(p)
            except (OSError, ValueError) as e:
                problems.append(f"{p}: {e}")
    except Exception:  # noqa: BLE001
        pass
    try:
        import gnoc_perms
        problems += gnoc_perms.problems()
    except Exception:  # noqa: BLE001
        pass
    if problems:
        for p in problems:
            _check(rows, WARN, "config file", p, "fix the JSON; until then that file's rules are ignored")
    else:
        _check(rows, OK, "config files", "hooks and permission rules read cleanly")
    try:
        import gnoc_secrets
        sec = os.path.join(gnoc_secrets.CONF, "secrets.env")
    except Exception:  # noqa: BLE001
        sec = ""
    if sec and os.path.isfile(sec):
        mode = stat.S_IMODE(os.stat(sec).st_mode)
        if mode & 0o077:
            _check(rows, WARN, "secrets file", f"{sec} can be read by other users (mode {mode:o})", f"chmod 600 {sec}")
        else:
            _check(rows, OK, "secrets file", f"{sec} is private")


def run_checks(role_spec=None):
    rows = []
    for fn in (check_platform, check_install, check_workspace, lambda r: check_models(r, role_spec),
               check_termux_models, check_updates, check_config):
        try:
            fn(rows)
        except Exception as e:  # noqa: BLE001 - one broken check must not hide the others
            _check(rows, WARN, "a check failed to run", f"{e.__class__.__name__}: {e}")
    return rows


def report(rows, color=None):
    color = sys.stdout.isatty() if color is None else color
    mark = {OK: ("✓", "32"), WARN: ("!", "33"), FAIL: ("✗", "31")}
    out = []
    for r in rows:
        sym, code = mark[r["status"]]
        sym = f"\033[{code}m{sym}\033[0m" if color else sym
        line = f"  {sym} {r['label']}" + (f": {r['detail']}" if r["detail"] else "")
        out.append(line)
        if r["fix"] and r["status"] != OK:
            out.append(f"      → {r['fix']}")
    fails = sum(r["status"] == FAIL for r in rows)
    warns = sum(r["status"] == WARN for r in rows)
    if not fails and not warns:
        out.append("  everything checks out.")
    else:
        out.append("  " + ", ".join(x for x in (f"{fails} problem{'s' * (fails != 1)}" if fails else "",
                                               f"{warns} to look at" if warns else "") if x) + ".")
    return "\n".join(out)


def main(argv=None):
    role_spec = None
    try:
        sys.path.insert(0, HERE)
        import gnoc_agent as G
        role_spec = G.role_spec
    except Exception:  # noqa: BLE001 - the doctor must run even when the agent cannot load
        pass
    rows = run_checks(role_spec)
    print(report(rows))
    return 1 if any(r["status"] == FAIL for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
