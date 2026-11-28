#!/usr/bin/env python3
"""scope_proxy - mitmproxy addon that enforces program scope on the NETWORK, not on command text.

XBOW enforces scope with a proxy; our scope-gate hook greps the Bash command text, which T-171
records as bypassable (a host list inside a heredoc). This addon refuses any host that
lib_scope.program_allows() says is out of scope, at the wire, for any client that uses the proxy.

  program     same order as scope-gate.sh / lock-lib.sh: env HUNT_TARGET, then the per-session
              .claude/state/hunt-loop/LOCK.<session_id> (this session's sid when CLAUDE_CODE_SESSION_ID /
              CLAUDE_SESSION_ID / HUNT_SID is set, else every LOCK.<sid> present: if they name DIFFERENT
              programs the proxy refuses to start, ProgramConflict), then the global LOCK. No program
              resolved -> everything is refused (fail closed).
  fail closed ANY exception inside a decision refuses the flow ("scope decision error"); mitmproxy
              logs an addon exception and lets the flow continue, so a raise would be fail OPEN.
  STRICT      SCOPE_PROXY_STRICT=1 (the default) drops github.io and storage.googleapis.com from the
              toolchain allowlist: anyone can publish there, so on the wire they are exfil/C2 sinks.
              The hook keeps them (parity); SCOPE_PROXY_STRICT=0 restores the hook's exact list.
  rules       targets/<program>/SCOPE.txt + NOSCOPE.txt through lib_scope (the one parser).
  allowlist   TOOLCHAIN_RE is read from .claude/hooks/scope-gate.sh at startup (never re-typed).
  refusal     synthetic 403, body "OUT_OF_SCOPE <host> (<program>)", NO upstream socket opened
              (run with --set connection_strategy=lazy), one JSON line appended to
              .claude/state/hunt-loop/SCOPE-INCIDENTS.jsonl {ts, program, host, url, client_pid}.
  in scope    passes through UNTOUCHED. This addon never re-issues a request; that is
              ja3_forward_proxy's job. The two chain: client -> scope_proxy:8084 -> (upstream
              mode) ja3_forward_proxy:8083 -> origin, e.g.
              mitmdump -s scope_proxy.py -p 8084 --mode upstream:http://127.0.0.1:8083 ...

Run via scripts/scope-proxy.sh start|stop|status [program]. Offline tests: test_scope_proxy.py
(decide() is pure; the hooks are thin wrappers).
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
from lib_scope import program_allows, extract_host, WS_ROOT  # noqa: E402

HOOK = os.path.join(WS_ROOT, ".claude", "hooks", "scope-gate.sh")
STATE = os.path.join(WS_ROOT, ".claude", "state", "hunt-loop")
INCIDENTS = os.environ.get("GNOC_SCOPE_INCIDENTS") or os.path.join(STATE, "SCOPE-INCIDENTS.jsonl")
# publicly writable hosts: anyone can publish a page or a bucket object there (fix3 2026-10-23)
STRICT_DROP = (r"github\.io", r"storage\.googleapis\.com")


class ProgramConflict(RuntimeError):
    """Several per-session LOCK files name different programs and no session id picks one."""


def strict_default() -> bool:
    return (os.environ.get("SCOPE_PROXY_STRICT", "1").strip() or "1") != "0"


def load_toolchain_re(hook: str = HOOK, strict: bool | None = None):
    """Extract TOOLCHAIN_RE from scope-gate.sh and wrap it the way the hook does: (^|\\.)(RE)$.
    strict (default SCOPE_PROXY_STRICT, on) removes the STRICT_DROP alternatives."""
    try:
        with open(hook, encoding="utf-8", errors="replace") as fh:
            m = re.search(r"^TOOLCHAIN_RE='([^']+)'", fh.read(), re.M)
    except OSError:
        return None
    if not m:
        return None
    alts = m.group(1).split("|")
    if strict_default() if strict is None else strict:
        alts = [a for a in alts if a not in STRICT_DROP]
    return re.compile(r"(^|\.)(" + "|".join(alts) + r")$", re.I) if alts else None


def _first_token(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line.split()[0]
    except OSError:
        pass
    return ""


def _sid() -> str:
    raw = os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or os.environ.get("HUNT_SID") or ""
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)[:80]


def resolve_program(root: str = WS_ROOT) -> str:
    """HUNT_TARGET -> LOCK.<sid> (this session, else every one present; conflicting -> ProgramConflict)
    -> global LOCK -> "". Mirrors scope-gate.sh + scripts/hunt-loop/lock-lib.sh hl_lock_target."""
    p = (os.environ.get("HUNT_TARGET") or "").strip()
    if p:
        return p
    st = os.path.join(root, ".claude", "state", "hunt-loop")
    sid = _sid()
    if sid and sid != "_":
        mine = _first_token(os.path.join(st, "LOCK." + sid))
        if mine:
            return mine
    found = {}
    try:
        names = sorted(os.listdir(st))
    except OSError:
        names = []
    for n in names:
        if re.fullmatch(r"LOCK\.[A-Za-z0-9_.-]{1,80}", n) and ".bak" not in n:
            t = _first_token(os.path.join(st, n))
            if t:
                found.setdefault(t, []).append(n)
    if len(found) > 1:
        raise ProgramConflict("per-session LOCK files name different programs: "
                              + "; ".join(f"{t} ({', '.join(v)})" for t, v in sorted(found.items()))
                              + ". Set HUNT_TARGET=<program> (or CLAUDE_CODE_SESSION_ID) to pick one.")
    if found:
        return next(iter(found))
    return _first_token(os.path.join(st, "LOCK"))


def decide(host: str, program: str, root: str = WS_ROOT, toolchain=None) -> tuple[bool, str]:
    """(allowed, reason). NOSCOPE beats everything, including the toolchain allowlist."""
    h = extract_host(host or "")
    if not program:
        return False, "no-program"
    if not h:
        return False, "no-host"
    ok, why = program_allows(h, program, root=root)
    if why == "noscope":
        return False, why
    if toolchain is not None and toolchain.search(h):
        return True, "toolchain"
    return ok, why


def refusal_body(host: str, program: str) -> bytes:
    return f"OUT_OF_SCOPE {host} ({program})".encode()


def client_pid(peer) -> int | None:
    """Best effort: pid owning the client end of a loopback connection (ss -tnp)."""
    try:
        port = int(peer[1])
        out = subprocess.run(["ss", "-Htnp", f"sport = :{port}"], capture_output=True, text=True, timeout=1).stdout
        m = re.search(r"pid=(\d+)", out)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def log_incident(program: str, host: str, url: str, pid=None, reason: str = "", path: str | None = None) -> None:
    path = path or INCIDENTS
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "program": program, "host": host,
           "url": url, "client_pid": pid, "reason": reason}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


class ScopeProxy:
    def __init__(self, program: str | None = None, root: str = WS_ROOT, incidents: str | None = None):
        self.error = ""
        if program is None:
            try:
                program = resolve_program(root)
            except ProgramConflict as e:   # never raise at load: mitmdump would run WITHOUT the addon (fail open)
                self.error, program = str(e), ""
                print(f"scope_proxy: REFUSING ALL TRAFFIC: {e}", file=sys.stderr)
        if program and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", program):
            self.error, program = f"bad program handle {program[:80]!r}", ""
        self.program = program
        self.root = root
        self.incidents = incidents
        self.toolchain = load_toolchain_re()

    def check(self, hosts, url: str, peer=None):
        """Return None if every host passes, else a refusal tuple (status, body, headers).
        FAIL CLOSED: any exception while deciding is a refusal, never a pass."""
        try:
            return self._check(hosts, url, peer)
        except Exception as e:   # noqa: BLE001 - the whole point is that nothing escapes
            host = str(next((h for h in hosts if h), ""))[:200]
            log_incident(self.program, host, str(url)[:500], None, f"decision-error {type(e).__name__}",
                         self.incidents)
            return 403, f"OUT_OF_SCOPE {host!r} (scope decision error)".encode(), {"content-type": "text/plain"}

    def _check(self, hosts, url: str, peer=None):
        for h in hosts:
            if not h:
                continue
            ok, why = decide(h, self.program, self.root, self.toolchain)
            if not ok:
                log_incident(self.program, extract_host(h) or h, url,
                             client_pid(peer) if peer else None, why, self.incidents)
                return 403, refusal_body(extract_host(h) or h, self.program), {"content-type": "text/plain"}
        return None

    # --- mitmproxy hooks ---
    def _refuse(self, flow, hosts_fn, url_fn):
        """hosts_fn / url_fn are evaluated INSIDE the guard: reading a malformed flow can raise too."""
        try:
            hosts, url = hosts_fn(), url_fn()
            r = self.check(hosts, url, getattr(flow.client_conn, "peername", None))
        except Exception as e:   # noqa: BLE001
            log_incident(self.program, "", "", None, f"decision-error {type(e).__name__}", self.incidents)
            r = 403, b"OUT_OF_SCOPE (scope decision error)", {"content-type": "text/plain"}
        if r:
            from mitmproxy import http
            flow.response = http.Response.make(*r)
        return r

    def http_connect(self, flow):
        self._refuse(flow, lambda: [flow.request.host or "-"],
                     lambda: f"CONNECT {flow.request.host}:{flow.request.port}")

    def request(self, flow):
        if flow.response is not None:
            return
        # the RAW Host header goes to extract_host: ".split(':')[0]" turned "[::1]:443" into "[" and
        # "[evil.test]" into a ValueError. An absent Host header is fine; a present-but-unparseable one refuses.
        self._refuse(flow, lambda: [flow.request.host or "-"] + _host_header(flow), lambda: flow.request.pretty_url)

    def tls_clienthello(self, data):
        try:
            sni = getattr(data.client_hello, "sni", None)
            if not sni:
                return
            ok, why = decide(sni, self.program, self.root, self.toolchain)
        except Exception as e:   # noqa: BLE001
            sni, ok, why = locals().get("sni") or "", False, f"decision-error {type(e).__name__}"
        if not ok:
            log_incident(self.program, str(sni)[:200], f"tls://{str(sni)[:200]}", None, why, self.incidents)
            data.context.server.address = ("scope-refused.invalid", 443)   # upstream can never open


def _host_header(flow) -> list:
    """Every name the request claims besides the connection host: the HTTP/1 Host header AND the HTTP/2
    :authority (flow.request.authority; HTTP/2 has no Host header, so a header-only check let a forged
    authority through on the live check, fix3 2026-10-23) AND mitmproxy's host_header view."""
    out = []
    rq = flow.request
    for v in (rq.headers.get("host", ""), getattr(rq, "authority", ""), getattr(rq, "host_header", "")):
        v = "" if v is None else str(v)
        if v.strip():
            out.append(v)
    return out


addons = [ScopeProxy()] if "mitmproxy" in sys.modules or os.environ.get("SCOPE_PROXY_ACTIVE") else []


if __name__ == "__main__":
    # `scope_proxy.py resolve` -> the program the proxy would enforce (exit 2 on conflict / none), used by
    # scripts/scope-proxy.sh start so a conflicting LOCK set refuses to START with a clear message.
    if sys.argv[1:2] == ["resolve"]:
        try:
            prog = resolve_program()
        except ProgramConflict as e:
            print(f"REFUSED: {e}", file=sys.stderr)
            sys.exit(2)
        print(prog)
        sys.exit(0 if prog else 2)
    print("usage: scope_proxy.py resolve   (as an addon: mitmdump -s scope_proxy.py)")
