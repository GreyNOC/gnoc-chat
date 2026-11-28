"""gnoc_platform.py - which kind of computer gnoc is running on, Termux on Android above all.

ONE detector for every part of gnoc that has to behave differently inside Termux (the installer's Python step,
`gnoc doctor`, `gnoc setup`, the engine, the defender, the scheduler). Before this module the only check was
gnoc_engine.on_android(), and install.sh, the doctor and the setup each assumed a desktop with sudo and apt.

Standard library only and no gnoc imports: gnoc_engine.py is copied ALONE onto a phone, and anything it imports
must be optional there. Every function takes its environment and filesystem as arguments so a test can fake a
Termux without one.
"""
from __future__ import annotations

import os
import platform
import sys
from typing import Callable, Mapping, Optional

# Termux's fixed install root. Android gives every app /data/data/<package>, and Termux builds every package
# with this prefix compiled in, so it does not move (a fork with another package name is not Termux to us).
TERMUX_USR = "/data/data/com.termux/files/usr"
_SUFFIX = "/com.termux/files/usr"
# termux-services keeps one directory per service here; crond is one of them once cronie is installed
_SV_DIR = "var/service"

Env = Mapping[str, str]
IsDir = Callable[[str], bool]


def _env(env: Optional[Env]) -> Env:
    return os.environ if env is None else env


def _isdir(isdir: Optional[IsDir]) -> IsDir:
    return os.path.isdir if isdir is None else isdir


def is_termux(env: Optional[Env] = None, isdir: Optional[IsDir] = None) -> bool:
    """True inside Termux. TERMUX_VERSION is set by the Termux app for every shell it opens; $PREFIX ending in
    /com.termux/files/usr also counts, because a `su`, a `proot` or a cron job can keep PREFIX and drop
    TERMUX_VERSION; the install root on disk is the last word."""
    e = _env(env)
    if e.get("TERMUX_VERSION"):
        return True
    if str(e.get("PREFIX") or "").rstrip("/").endswith(_SUFFIX):
        return True
    return _isdir(isdir)(TERMUX_USR)


def termux_prefix(env: Optional[Env] = None, isdir: Optional[IsDir] = None) -> str:
    """Termux's $PREFIX (where pkg puts programs: <prefix>/bin is always on PATH), or '' outside Termux.
    The live $PREFIX wins when it is a Termux one, so a test (or a relocated Termux) gets its own."""
    e = _env(env)
    pre = str(e.get("PREFIX") or "").rstrip("/")
    if pre.endswith(_SUFFIX):
        return pre
    return TERMUX_USR if is_termux(e, isdir) else ""


def on_android(env: Optional[Env] = None, isdir: Optional[IsDir] = None, sysmod: object = None) -> bool:
    """True inside Termux or any Python on Android. Exactly gnoc_engine.on_android()'s old test (it picks the
    llama.cpp build, so a change here changes what a phone downloads): Android's own Python has
    sys.getandroidapilevel, Termux sets TERMUX_VERSION, and Termux's install root exists."""
    s = sys if sysmod is None else sysmod
    return hasattr(s, "getandroidapilevel") or bool(_env(env).get("TERMUX_VERSION")) \
        or _isdir(isdir)(TERMUX_USR)


def kind(env: Optional[Env] = None, isdir: Optional[IsDir] = None, system: Optional[str] = None,
         release: Optional[str] = None) -> str:
    """'termux' | 'wsl' | 'darwin' | 'windows' | 'linux' (or another platform.system(), lowercased)."""
    if is_termux(env, isdir):
        return "termux"
    system = platform.system() if system is None else system
    release = platform.release() if release is None else release
    if system == "Linux" and "microsoft" in release.lower():
        return "wsl"
    return system.lower() or "unknown"


def pkg_hint(*packages: str, env: Optional[Env] = None, isdir: Optional[IsDir] = None) -> str:
    """'pkg install <packages>' inside Termux, '' elsewhere. Termux has no sudo and no root: a hint naming sudo or
    apt sends the user down a path that cannot work there (Termux's apt does run, but pkg also picks a working
    mirror first, which is the advice Termux itself gives)."""
    if not packages or not is_termux(env, isdir):
        return ""
    return "pkg install " + " ".join(packages)


def unavailable(feature: str) -> str:
    """The one line every root- or systemd-only feature prints inside Termux instead of trying."""
    return f"{feature} needs root or systemd, not available on Termux"


def crond_state(env: Optional[Env] = None, isdir: Optional[IsDir] = None,
                which: Optional[Callable[[str], Optional[str]]] = None,
                exists: Optional[Callable[[str], bool]] = None) -> str:
    """For a Termux schedule: 'no-crontab' (cronie is not installed), 'no-service' (crontab exists but
    termux-services does not run crond), 'ok', or '' outside Termux. Android has no init that starts crond, so a
    crontab line that nobody reads is the failure to name. termux-services keeps a service directory per daemon
    and marks a disabled one with a `down` file, which `sv-enable` removes."""
    if not is_termux(env, isdir):
        return ""
    import shutil
    w = shutil.which if which is None else which
    ex = os.path.exists if exists is None else exists
    if not w("crontab"):
        return "no-crontab"
    sv = os.path.join(termux_prefix(env, isdir), _SV_DIR, "crond")
    return "ok" if _isdir(isdir)(sv) and not ex(os.path.join(sv, "down")) else "no-service"


CROND_HELP = ("pkg install cronie termux-services, restart Termux, then sv-enable crond "
              "(termux-services starts crond whenever Termux runs)")
