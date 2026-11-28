"""gnoc_missing.py - what a public install does where the operator's workspace has a file this edition does not ship.

The release is cut from the operator's live workspace, and some code there runs, imports or opens files that stay
behind (the hunt index CLI, the workspace scope-gate hook, the dashboard's scrubber, the office collectors). Each
such call site either got a public replacement or says, in one line, what is missing and what to do instead; the
wording lives here so every one of those lines reads the same way. Dependencies are passed in, never looked up:
this module imports nothing from the harness.
"""
from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable


def note(feature: str, missing: str, instead: str = "") -> str:
    """'<feature> needs <missing>, which this edition does not ship. <instead>' - one line, no trailing space."""
    text = f"{feature} needs {missing}, which this edition does not ship."
    return f"{text} {instead.strip()}" if instead.strip() else text


def present(ws: str, rel: str) -> bool:
    return os.path.isfile(os.path.join(ws, rel))


# ------------------------------------------------------------------ the bash scope gate without its hook
# A URL with a scheme: the only host form the fallback reads. Quotes, angle brackets and shell metacharacters end it.
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>|;&()`]+", re.I)


def _loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def bash_scope_check(cmd: str, program: str, ws: str, client_re: re.Pattern,
                     allows: Callable[[str, str, str], tuple[bool, str]],
                     extract_host: Callable[[str], str]) -> str | None:
    """The bash scope gate for an install without .claude/hooks/scope-gate.sh. None = may run, else the reason.

    Without the hook the gate used to return None for every command, so with a programme active `curl
    https://not-in-scope.example/` ran unchecked: the only scope check on bash was a file only the operator has.
    This is narrower than the hook and errs closed: a command that drives an HTTP client (client_re) must name
    every host as a URL with a scheme, and every such host must pass `allows` (lib_scope.program_allows: NOSCOPE,
    internal addresses, third-party hosts, SCOPE.txt). Loopback stays open, because a local dev server or the
    researcher's own proxy is not a target. A command with no HTTP client is local work and passes, as it does
    under the hook."""
    if not program:
        return None
    text = str(cmd or "")
    if not client_re.search(text):
        return None
    hosts = []
    for m in _URL.finditer(text):
        h = (extract_host(m.group(0)) or "").lower().rstrip(".")
        if h and h not in hosts:
            hosts.append(h)
    where = f"targets/{program}/SCOPE.txt"
    tail = " (this edition checks bash against SCOPE.txt itself; the workspace scope-gate hook is not installed)"
    if not hosts:
        return (f"an HTTP client with no scheme://host URL in the command, so its host cannot be checked against "
                f"{where}; write the full URL, or use http_request" + tail)
    for h in hosts:
        if _loopback(h):
            continue
        ok, why = allows(h, program, ws)
        if not ok:
            return f"{h} is not allowed by {where} ({why})" + tail
    return None
