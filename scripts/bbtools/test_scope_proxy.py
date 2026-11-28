#!/usr/bin/env python3
"""Offline tests for scope_proxy: pure decision + fake flow objects. No mitmproxy process, no network."""
import json, os, shutil, sys, tempfile, types
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scope_proxy as sp

# offline stand-in for mitmproxy.http.Response.make (installed only if the real one is absent)
_stub = types.ModuleType("mitm_stub")
if "mitmproxy" not in sys.modules:
    _m, _h = types.ModuleType("mitmproxy"), types.ModuleType("mitmproxy.http")
    _h.Response = types.SimpleNamespace(make=lambda *a: ("RESP", a))
    _m.http = _h
    sys.modules["mitmproxy"], sys.modules["mitmproxy.http"] = _m, _h
sys.modules["mitm_stub"] = _stub


def _w(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def _r(path):
    with open(path) as fh:
        return fh.read()


class Hdr(dict):
    def get(self, k, d=None):
        return super().get(k.lower(), d)


def flow(host, hdr_host=None, peer=("127.0.0.1", 1)):
    rq = types.SimpleNamespace(host=host, port=443, headers=Hdr(host=hdr_host or host),
                               pretty_url="https://" + host + "/x")
    return types.SimpleNamespace(request=rq, response=None, client_conn=types.SimpleNamespace(peername=peer))


def main():
    root = tempfile.mkdtemp()
    inc = os.path.join(root, "inc.jsonl")
    try:
        d = os.path.join(root, "targets", "px"); os.makedirs(d)
        _w(os.path.join(d, "SCOPE.txt"), "WILDCARD *.acme.example\t[bounty]\n=www.other.example\n")
        _w(os.path.join(d, "NOSCOPE.txt"), "=vpn.acme.example\n")
        tc = sp.load_toolchain_re()
        assert tc is not None, "TOOLCHAIN_RE not extracted from scope-gate.sh"
        assert tc.search("pkg.go.dev") and tc.search("deb.debian.org") and not tc.search("acme.example")
        # STRICT (default): publicly writable hosts are NOT allowlisted on the wire; STRICT=0 = the hook's list
        assert not tc.search("sub.github.io") and not tc.search("storage.googleapis.com"), "STRICT must drop them"
        loose = sp.load_toolchain_re(strict=False)
        assert loose.search("sub.github.io") and loose.search("storage.googleapis.com")
        assert not loose.search("notgithub.io.attacker.example")
        saved_strict = os.environ.get("SCOPE_PROXY_STRICT")
        os.environ["SCOPE_PROXY_STRICT"] = "0"
        assert sp.load_toolchain_re().search("x.github.io")
        os.environ["SCOPE_PROXY_STRICT"] = "1"
        assert not sp.load_toolchain_re().search("x.github.io")
        if saved_strict is None:
            os.environ.pop("SCOPE_PROXY_STRICT")
        else:
            os.environ["SCOPE_PROXY_STRICT"] = saved_strict
        P = sp.ScopeProxy(program="px", root=root, incidents=inc)
        P.toolchain = tc

        assert sp.decide("api.acme.example", "px", root, tc) == (True, "ok")             # in scope
        assert sp.decide("pkg.go.dev", "px", root, tc) == (True, "toolchain")           # allowlist
        assert sp.decide("vpn.acme.example", "px", root, tc) == (False, "noscope")      # NOSCOPE wins over SCOPE
        assert sp.decide("pkg.go.dev", "px", root, None) == (False, "not-in-scope")     # no allowlist -> refused
        assert sp.decide("anything.example", "", root, tc) == (False, "no-program")     # fail closed
        assert sp.decide("", "px", root, tc) == (False, "no-host")

        f = flow("api.acme.example"); P.request(f)
        assert f.response is None, "in-scope request must pass untouched"
        assert not os.path.exists(inc), "no incident for in-scope traffic"

        r = P.check(["offscope.example"], "https://offscope.example/x")
        assert r[0] == 403 and r[1] == b"OUT_OF_SCOPE offscope.example (px)", r
        rec = json.loads(_r(inc).splitlines()[-1])
        assert rec["program"] == "px" and rec["host"] == "offscope.example" and rec["url"] == "https://offscope.example/x"
        assert {"ts", "client_pid"} <= set(rec)

        assert P.check(["vpn.acme.example"], "https://vpn.acme.example/")[0] == 403      # NOSCOPE via check
        assert P.check(["pkg.go.dev"], "https://pkg.go.dev/") is None                   # toolchain via check
        # Host-header fronting: URL host in scope, Host header out of scope -> refused
        assert P.check(["api.acme.example", "offscope.example"], "https://api.acme.example/")[0] == 403
        n = len(_r(inc).splitlines())
        assert n == 3, n

        # --- fix3 2026-10-23 attacks (reviewer /tmp/rv_attack/sp*.py): every one must REFUSE, fail closed ---
        import mitm_stub  # noqa: F401  (fake mitmproxy.http so _refuse can build a response offline)
        for h in ("[evil.test]", "[::ffff:127.0.0.1]", "[fe80::1%25eth0]", "api.acme.example@evil.test",
                  "evil.test#.api.acme.example", "api.acme.example.evil.test", "0x7f000001", "2130706433",
                  "attacker.github.io", "storage.googleapis.com", "api.acme.examp\u043ee"):
            assert sp.decide(h, "px", root, tc)[0] is False, h
        for host, hh in [("api.acme.example", "evil.test"), ("api.acme.example", "evil.test "),
                         ("api.acme.example", "[evil.test]"), ("api.acme.example", "evil.test:x:y"),
                         ("[evil.test]", "api.acme.example"), ("evil.test", "api.acme.example"),
                         ("api.acme.example", "[::1]:443")]:
            f = flow(host, hh); P.request(f)
            assert f.response is not None, ("must refuse", host, hh)
        f = flow("api.acme.example", "api.acme.example:443"); P.request(f)
        assert f.response is None, "Host header with a port must still pass"
        # HTTP/2: no Host header, the forged name rides in :authority (found on the live check)
        f = flow("api.acme.example"); f.request.headers = Hdr(); f.request.authority = "[evil.test]"
        P.request(f); assert f.response is not None, "forged :authority must refuse"
        f = flow("api.acme.example"); f.request.headers = Hdr(); f.request.authority = "evil.test:443"
        P.request(f); assert f.response is not None
        f = flow("api.acme.example"); f.request.headers = Hdr(); f.request.authority = "api.acme.example:443"
        P.request(f); assert f.response is None, "a matching :authority passes"
        # an exception anywhere in the decision is a refusal, never a pass (mitmproxy continues on a raise)
        real = sp.decide
        sp.decide = lambda *a, **k: (_ for _ in ()).throw(ValueError("boom"))
        try:
            f = flow("api.acme.example"); P.request(f)
            assert f.response is not None and b"scope decision error" in f.response[1][1], f.response
            r = P.check(["api.acme.example"], "u")
            assert r[0] == 403 and b"scope decision error" in r[1]
            hello = types.SimpleNamespace(client_hello=types.SimpleNamespace(sni="api.acme.example"),
                                          context=types.SimpleNamespace(server=types.SimpleNamespace(address=None)))
            P.tls_clienthello(hello)
            assert hello.context.server.address == ("scope-refused.invalid", 443)
        finally:
            sp.decide = real
        broken = types.SimpleNamespace(request=None, response=None, client_conn=None)
        P.request(broken)
        assert broken.response is not None, "a malformed flow object must refuse"
        # program resolution: fail closed, env, session LOCK.<sid>, conflict refusal, global LOCK fallback
        keys = ("HUNT_TARGET", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "HUNT_SID")
        saved = {k: os.environ.pop(k, None) for k in keys}
        try:
            st = os.path.join(root, ".claude/state/hunt-loop")
            assert sp.resolve_program(root) == ""
            os.environ["HUNT_TARGET"] = "px"; assert sp.resolve_program(root) == "px"; os.environ.pop("HUNT_TARGET")
            os.makedirs(st)
            _w(os.path.join(st, "LOCK"), "px\n")
            assert sp.resolve_program(root) == "px"
            _w(os.path.join(st, "LOCK.sid-a"), "# pinned\nqq\n")
            assert sp.resolve_program(root) == "qq", "a session LOCK beats the global LOCK"
            _w(os.path.join(st, "LOCK.sid-b"), "qq\n")
            assert sp.resolve_program(root) == "qq", "agreeing session LOCKs resolve"
            _w(os.path.join(st, "LOCK.sid-c"), "zz\n")
            try:
                sp.resolve_program(root); raise AssertionError("conflicting session LOCKs must refuse")
            except sp.ProgramConflict as e:
                assert "qq" in str(e) and "zz" in str(e)
            Pc = sp.ScopeProxy(root=root, incidents=inc)
            assert Pc.program == "" and Pc.error and Pc.check(["api.acme.example"], "u")[0] == 403
            os.environ["CLAUDE_CODE_SESSION_ID"] = "sid-c"
            assert sp.resolve_program(root) == "zz", "this session's own LOCK wins (lock-lib.sh order)"
            os.environ["HUNT_TARGET"] = "px"
            assert sp.resolve_program(root) == "px", "HUNT_TARGET beats every LOCK"
            assert sp.ScopeProxy(program="../px", root=root).program == "", "bad handle -> fail closed"
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None)
                if v is not None:
                    os.environ[k] = v
        print("test_scope_proxy: ALL ASSERTIONS PASS")
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
