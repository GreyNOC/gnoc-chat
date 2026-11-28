#!/usr/bin/env python3
"""Regression tests for the 2026-11-19 QA/QC of the multi-machine wiring: collaborator handoffs (what may become
scope), linked machines (pairing, records, approval), the desktop tool, and model routing across machines (fallback,
health ledger, the traffic proxy). Temp dirs, mocks and loopback test servers only: no real machine is contacted.

    python3 -m pytest -q scripts/test_gnoc_multimachine.py
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_agent as G  # noqa: E402
import gnoc_collab as C  # noqa: E402
import gnoc_desktop as D  # noqa: E402
import gnoc_link as L  # noqa: E402
import llm_endpoints as E  # noqa: E402


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-mm-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def put(self, rel, text):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p


# ============================================================================================ collaborator handoffs
HANDOFF = "# Handoff\nAuthorized engagement.\n## In scope\n- app.acme.test\n## Out of scope\n- admin.acme.test\n"


class Collab(Tmp):
    def setUp(self):
        super().setUp()
        self.ws = os.path.join(self.tmp, "ws")
        os.makedirs(os.path.join(self.ws, "targets"))
        self.proj = os.path.join(self.tmp, "proj")
        os.makedirs(self.proj)

    def ctx(self):
        return types.SimpleNamespace(s={})


class NothingBecomesScopeWithoutAYes(Collab):
    def test_an_ordinary_onboarding_doc_is_not_a_handoff(self):
        self.put("proj/docs/ONBOARDING.md", "# Developer onboarding\nIn scope for this sprint: https://api.thirdparty.test\n")
        self.assertIsNone(C.find_handoff(self.proj))

    def test_no_human_no_import(self):
        self.put("proj/HANDOFF.md", HANDOFF)
        got = C.attach(self.ctx(), self.proj, self.ws)
        self.assertTrue(got["pending"])
        self.assertEqual([d for d in os.listdir(os.path.join(self.ws, "targets")) if not d.startswith(".")], [])

    def test_a_no_is_remembered_and_a_yes_imports(self):
        self.put("proj/HANDOFF.md", HANDOFF)
        self.assertIsNone(C.attach(self.ctx(), self.proj, self.ws, approve=lambda pv: False))
        self.assertIsNone(C.attach(self.ctx(), self.proj, self.ws, approve=lambda pv: self.fail("asked twice")))
        ctx = self.ctx()
        got = C.attach(ctx, self.proj, self.ws, explicit=True)
        self.assertEqual(got["hosts"], ["app.acme.test"])
        self.assertEqual(ctx.s["program"], got["program"])

    def test_the_question_shows_the_hosts(self):
        self.put("proj/HANDOFF.md", HANDOFF)
        seen = []
        C.attach(self.ctx(), self.proj, self.ws, approve=lambda pv: seen.append(pv) or True)
        self.assertEqual(seen[0]["hosts"], ["app.acme.test"])


class HandoffFilesAreSafe(Collab):
    def test_symlinks_and_secret_files_are_never_read(self):
        self.put("proj/HANDOFF.md", HANDOFF)
        secret = self.put("elsewhere/creds.txt", "SECRET_VALUE_42\n")
        os.symlink(secret, os.path.join(self.proj, "contract.md"))
        got = C.attach(self.ctx(), self.proj, self.ws, explicit=True)
        pdir = os.path.join(self.ws, "targets", got["program"])
        with open(os.path.join(pdir, "PROGRAM.md")) as f:
            self.assertNotIn("SECRET_VALUE_42", f.read())
        self.assertEqual(oct(os.stat(pdir).st_mode & 0o777), "0o700")
        self.assertEqual(oct(os.stat(os.path.join(pdir, "PROGRAM.md")).st_mode & 0o777), "0o600")

    def test_a_deleted_handoff_revokes_its_scope(self):
        from bbtools import lib_scope
        h = self.put("proj/HANDOFF.md", HANDOFF)
        ctx = self.ctx()
        got = C.attach(ctx, self.proj, self.ws, explicit=True)
        self.assertTrue(lib_scope.program_allows("app.acme.test", got["program"], self.ws)[0])
        os.remove(h)
        r = C.attach(ctx, self.proj, self.ws)
        self.assertTrue(r["revoked"])
        self.assertNotIn("program", ctx.s)
        self.assertFalse(lib_scope.program_allows("app.acme.test", got["program"], self.ws)[0])

    def test_only_an_approved_handoff_rides_the_prompt(self):
        self.put("proj/HANDOFF.md", HANDOFF)
        self.assertIsNone(C.active_handoff(self.proj, self.ws))
        C.attach(self.ctx(), self.proj, self.ws, explicit=True)
        self.assertIn("Authorized engagement", C.active_handoff(self.proj, self.ws)[1])


class TheScopeParserNeverWidens(unittest.TestCase):
    def test(self):
        p = C.parse_scope("""# Handoff
## In scope
- app.acme.com
## Out of scope
- Third-party assets: cdn.vendor.net
- payments.acme.com
Never attack these production targets: prod.acme.com
### Partner systems (do not test)
- partner.acme.com
| Host | In scope | Notes |
|---|---|---|
| admin.acme.com | No | allowed only after written approval |
""")
        self.assertEqual(p["in"], ["app.acme.com"])
        for h in ("cdn.vendor.net", "payments.acme.com", "prod.acme.com", "partner.acme.com", "admin.acme.com"):
            self.assertIn(h, p["out"])

    def test_a_url_in_prose_is_not_authorization(self):
        self.assertEqual(C.parse_scope("Our old vendor https://shop.othercorp.test was breached.")["in"], [])


# ============================================================================================ linked machines
class LinkRecords(Tmp):
    def test_a_record_that_could_inject_ssh_options_is_never_used(self):
        bad = {"user": "-oProxyCommand=touch /tmp/x", "host": "10.0.0.5", "port": 22}
        self.assertTrue(L.valid(bad))
        self.assertTrue(L.valid({"user": "alice", "host": "-oX", "port": 22}))
        self.assertTrue(L.valid({"user": "alice", "host": "10.0.0.5", "port": 22, "probe": {"wayland": "x; rm"}}))
        with self.assertRaises(ValueError):
            L.ssh_base(bad)
        store = self.put("links.json", json.dumps({"lab": bad, "ok": {"user": "alice", "host": "10.0.0.5"}}))
        with mock.patch.object(L, "STORE", store):
            self.assertEqual(list(L.load()), ["ok"])

    def test_the_destination_follows_double_dash(self):
        argv = L.ssh_base({"user": "alice", "host": "10.0.0.5", "port": 22})
        self.assertEqual(argv[-2:], ["--", "alice@10.0.0.5"])

    def test_reserved_names(self):
        self.assertFalse(L.add("desktop", "alice@10.0.0.5")[0])
        self.assertFalse(L.add("local", "alice@10.0.0.5")[0])


class Pairing(Tmp):
    def test_no_subnet_no_setup_block(self):
        with mock.patch.object(L, "ensure_key", return_value="ssh-ed25519 AAAA gnoc-link@here"), \
                mock.patch.object(L, "lan", return_value=(None, None)):
            with self.assertRaises(RuntimeError):
                L.setup_block()

    def test_the_key_is_restricted_and_replaces_this_controllers_old_one(self):
        with mock.patch.object(L, "ensure_key", return_value="ssh-ed25519 AAAANEW gnoc-link@here"), \
                mock.patch.object(L, "lan", return_value=("10.0.0.2", "10.0.0.0/24")):
            block = L.setup_block()
        self.assertIn('restrict,from="10.0.0.0/24" ssh-ed25519 AAAANEW', block)
        home = os.path.join(self.tmp, "home")
        os.makedirs(os.path.join(home, ".ssh"))
        ak = os.path.join(home, ".ssh", "authorized_keys")
        with open(ak, "w") as f:
            f.write("ssh-ed25519 OTHER someone@else\nfrom=\"10.0.0.0/24\" ssh-ed25519 AAAAOLD gnoc-link@here\n")
        # run just the key lines of the block against a temp HOME
        lines = [ln for ln in block.splitlines() if "authorized_keys" in ln or ".gnoc-ak" in ln]
        subprocess.run(["bash", "-c", "\n".join(lines)], env=dict(os.environ, HOME=home), check=True)
        with open(ak) as f:
            text = f.read()
        self.assertIn("OTHER someone@else", text)
        self.assertNotIn("AAAAOLD", text)
        self.assertIn("AAAANEW", text)

    def test_the_default_route_interface_wins(self):
        route = "1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.50 uid 1000\n"
        addrs = ("2: eth9 inet 169.254.3.4/16 scope link eth9\n"
                 "3: tailscale0 inet 100.64.0.2/32 scope global tailscale0\n"
                 "4: wlan0 inet 192.168.1.50/24 brd 192.168.1.255 scope global wlan0\n")
        outs = iter([types.SimpleNamespace(stdout=route), types.SimpleNamespace(stdout=addrs)])
        with mock.patch("subprocess.run", side_effect=lambda *a, **k: next(outs)):
            self.assertEqual(L.lan(), ("192.168.1.50", "192.168.1.0/24"))

    def test_no_desktop_process_is_not_a_session(self):
        rows = dict((item, ok) for ok, item, _ in L.readiness({"session": "x11", "desktop": "", "python3": "/usr/bin/python3"}))
        self.assertFalse(rows["a logged-in desktop session"])


class DriveAMachineOnlyWithApproval(unittest.TestCase):
    def test_link_by_hand_asks_even_under_skip_perms(self):
        saved = G.SKIP_PERMS[0]
        G.SKIP_PERMS[0] = True
        try:
            c = G.Ctx({})
            self.assertTrue(G._approval_required(
                "bash", {"command": "python3 -c \"import gnoc_link as L; L.run(L.load()['lab'], 'id')\""}, c))
            self.assertTrue(G._approval_required("bash", {"command": "ssh -i ~/.ssh/gnoc_link_ed25519 a@b"}, c))
            self.assertFalse(G._approval_required("bash", {"command": "ls"}, c))
        finally:
            G.SKIP_PERMS[0] = saved

    def test_the_links_file_is_write_protected(self):
        self.assertTrue(G.WRITE_DENY.search(".claude/state/orch/links.json"))


class TheDesktopTool(Tmp):
    def test_png_size_without_pillow(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (1280).to_bytes(4, "big") + (800).to_bytes(4, "big")
        self.assertEqual(D._png_size(png), (1280, 800))

    def test_ops_are_capped(self):
        self.assertTrue(D.check_ops([{"op": "sleep", "ms": 1}] * (D.MAX_OPS + 1)))
        self.assertTrue(D.check_ops([{"op": "sleep", "ms": D.MAX_SLEEP_MS + 1}]))
        self.assertEqual(D.act("local", [{"op": "sleep", "ms": D.MAX_SLEEP_MS + 1}], size=(10, 10))["ok"], False)

    def test_typed_text_travels_on_stdin_not_argv(self):
        seen = {}

        def run(argv, **kw):
            seen.update(argv=argv, input=kw.get("input"))
            return types.SimpleNamespace(stdout='{"ok": true, "done": ["type"]}', stderr="", returncode=0)
        with mock.patch("subprocess.run", side_effect=run):
            D.act("local", [{"op": "type", "text": "hunter2-not-a-secret"}], size=(10, 10))
        self.assertNotIn("hunter2-not-a-secret", " ".join(seen["argv"]))
        self.assertIn("hunter2-not-a-secret", seen["input"])

    def test_remote_input_is_bounded_on_the_other_machine(self):
        seen = {}
        link = {"user": "alice", "host": "10.0.0.5", "port": 22}
        with mock.patch.object(L, "load", return_value={"lab": link}), \
                mock.patch.object(L, "run", side_effect=lambda l, cmd, stdin=None, **k: seen.update(cmd=cmd, stdin=stdin)
                                  or (0, '{"ok": true, "done": []}', "")):
            D.act("lab", [{"op": "type", "text": "abc"}], size=(10, 10))
        self.assertTrue(seen["cmd"].startswith("timeout "))
        self.assertNotIn("abc", seen["cmd"])

    def test_the_x_session_environment_comes_from_the_probe(self):
        env = D._env_prefix({"session": "x11", "display": ":1", "xauth": "/run/user/1000/gdm/Xauthority"})
        self.assertIn("DISPLAY=:1", env)
        self.assertIn("XAUTHORITY=/run/user/1000/gdm/Xauthority", env)
        self.assertNotIn("QT_QPA_PLATFORM", env)


# ============================================================================================ model routing
class Routing(Tmp):
    def test_addresses_are_normalised(self):
        self.assertEqual(E._hostport("http://192.168.1.20:11434/"), "192.168.1.20:11434")
        self.assertEqual(E._hostport("desk.local:11434"), "desk.local:11434")

    def test_an_unset_machine_is_never_probed_or_recorded(self):
        with mock.patch.dict(E.HOSTS, {"phone": ""}), mock.patch.object(E, "record",
                                                                       side_effect=AssertionError("recorded")):
            self.assertFalse(E.up("phone"))
            self.assertIsNone(E.stock("some-model", "phone"))

    def test_a_down_host_costs_no_stock_timeout(self):
        E._stock_unknown.clear()
        with mock.patch.object(E, "is_down", return_value=True), \
                mock.patch.object(E, "_tags", side_effect=AssertionError("asked a down host")):
            t = time.time()
            self.assertIsNone(E.stock("x-model", "desktop"))
            self.assertLess(time.time() - t, 0.5)

    def test_the_ledger_survives_concurrent_writers(self):
        with mock.patch.object(E, "HEALTH_FILE", os.path.join(self.tmp, "llm-health.json")):
            E._health_save({"desktop": {"fails": 0, "trips": 3, "down_until": 9e12}})
            bad = []

            def worker(i):
                for _ in range(100):
                    E.record("local" if i % 2 else "phone", bool(i % 3))
                    try:
                        with open(E.HEALTH_FILE) as f:
                            if "desktop" not in json.load(f):
                                bad.append("lost")
                    except ValueError:
                        bad.append("corrupt")
            ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            self.assertEqual(bad, [])
            self.assertTrue(E.is_down("desktop"))

    def test_a_dead_desktop_falls_back_to_the_same_model_here(self):
        with mock.patch("gnoc_agent.role_spec", side_effect=lambda r: "big:20b@desktop" if r == "lead" else "small:4b"), \
                mock.patch("gnoc_agent._host_up", return_value=False), \
                mock.patch("gnoc_agent._local_has", side_effect=lambda m: m == "big:20b"), \
                mock.patch("gnoc_agent.split_up", return_value=False), \
                mock.patch.dict(os.environ, {"GNOC_NO_SPLIT": "1"}):
            self.assertEqual(G._resolve("lead"), ("big:20b", "local"))

    def test_a_role_on_a_machine_that_is_not_set_up_is_refused(self):
        said = []
        with mock.patch.dict(E.HOSTS, {"desktop": ""}), mock.patch("gnoc_agent.say", side_effect=said.append), \
                mock.patch("gnoc_agent.set_role", side_effect=AssertionError("must not write")):
            self.assertFalse(G._role_set("lead", "qwen3:8b@desktop"))
        self.assertIn("GNOC_DESKTOP_OLLAMA", " ".join(map(str, said)))


PROXY = os.path.join(HERE, "desktop-link", "traffic_proxy.py")


@unittest.skipUnless(os.path.isfile(PROXY), "the traffic proxy is the operator's own desktop link")
class TheTrafficProxyStreams(Tmp):
    def serve(self, drop):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                for i in range(4):
                    if drop and i == 2:
                        self.wfile.flush()
                        self.connection.shutdown(2)
                        return
                    self.wfile.write(json.dumps({"i": i}).encode() + b"\n")
                    self.wfile.flush()
                    time.sleep(0.4)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def proxy(self, up_port):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        env = dict(os.environ, GNOC_PROXY_PORT=str(port), GNOC_DESKTOP_UPSTREAM=f"127.0.0.1:{up_port}",
                   GNOC_PROXY_STATE=self.tmp)
        p = subprocess.Popen([sys.executable, PROXY], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (p.kill(), p.wait()))
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/version", timeout=0.2)
            except Exception as e:  # noqa: BLE001
                if "Connection refused" not in str(e):
                    break
            time.sleep(0.1)
        return port

    def stream(self, port):
        req = urllib.request.Request(f"http://127.0.0.1:{port}/api/chat", b'{"model": "m"}',
                                     {"Content-Type": "application/json"})
        t0, got = time.time(), []
        with urllib.request.urlopen(req, timeout=10) as r:
            try:
                for line in r:
                    got.append((round(time.time() - t0, 2), line))
            except Exception:  # noqa: BLE001
                pass
        return got

    def test_tokens_arrive_as_they_are_made(self):
        got = self.stream(self.proxy(self.serve(drop=False)))
        self.assertEqual(len(got), 4)
        self.assertLess(got[0][0], 0.35)   # the first token did not wait for the whole answer

    def test_a_mid_stream_failure_is_a_cut_not_a_second_response(self):
        got = self.stream(self.proxy(self.serve(drop=True)))
        self.assertFalse(any(b"HTTP/1.1" in line for _, line in got))


if __name__ == "__main__":
    unittest.main()


class ComputerUse20261123(unittest.TestCase):
    """Computer use: a local vision model sees the screen and points at things; Windows/WSL, macOS and a forced X11
    display go through gnoc_computer; a sensitive screen stops typing and clicking."""

    def test_the_sensitive_flag_is_the_models_line(self):
        import gnoc_computer as C
        self.assertFalse(C.sensitive("A dialog. There is no password field.\nSENSITIVE: no"))
        self.assertTrue(C.sensitive("A bank login form.\nSENSITIVE: yes"))

    def test_locate_scales_the_models_box_back_to_the_screen(self):
        import gnoc_computer as C
        from unittest import mock
        tmp = tempfile.mkdtemp()
        shot = os.path.join(tmp, "s.png")
        import gnoc_draw
        gnoc_draw.shape("a red rectangle, exactly, 644x392", shot)
        # the model sees the screen at 1288 wide (x2): its box at 200..400 x 100..140 is 100..200 x 50..70 here.
        # What it sees is pinned (Phase 0, 2026-11-26): the resize needs ImageMagick or Pillow, and a machine with
        # neither sends the shot at its own size, so this test failed in a clean container for a correct reason.
        with mock.patch.object(C, "_model_input", return_value=("", 1288, 784)), \
                mock.patch.object(C, "_ask_vision", return_value=("m", '{"bbox_2d": [200, 100, 400, 140]}')):
            x, y, box = C.locate(shot, "the button")
        self.assertEqual(box, (100, 50, 200, 70))
        self.assertEqual((x, y), (150, 60))
        # no resizer at all: the model saw the shot at its own size, so its box needs no scaling
        with mock.patch.object(C.shutil, "which", return_value=None), \
                mock.patch.dict(sys.modules, {"PIL": None}), \
                mock.patch.object(C, "_ask_vision", return_value=("m", '{"bbox_2d": [100, 50, 200, 70]}')):
            self.assertEqual(C._model_input(shot)[1:], (644, 392))
            self.assertEqual(C.locate(shot, "the button")[2], (100, 50, 200, 70))
        with mock.patch.object(C, "_ask_vision", return_value=("m", '{"bbox_2d": null}')):
            self.assertIsNone(C.locate(shot, "a missing thing"))
        shutil.rmtree(tmp, ignore_errors=True)

    def test_routing_and_refusals(self):
        import gnoc_desktop
        import gnoc_agent as G
        from unittest import mock
        from gnoc_tools import net
        with mock.patch.dict(os.environ, {"GNOC_COMPUTER_X11": ":9"}):
            self.assertTrue(gnoc_desktop._computer_local("local"))
            self.assertFalse(gnoc_desktop._computer_local("desktop"))
        ctx = G.Ctx({"sid": "cu-unit"})
        G.grant_desktop(ctx, "local", "test")
        ctx.s["_screen_sensitive"] = True
        self.assertIn("password, login, payment or admin", net.t_desktop(ctx, action="click_target", text="OK"))
        self.assertIn("password, login, payment or admin",
                      net.t_desktop(ctx, action="do", ops=[{"op": "type", "text": "hi"}]))


class WindowsSecurity20261123(unittest.TestCase):
    """the user's desktop (WSL): "are the windows defender settings correct on this machine?" ran `powershell`
    (exit 127) six times. defend(action=windows) reads Windows Security; a bare Windows program gets its .exe."""

    def test_findings(self):
        import gnoc_winsec as W
        bad = {"status": {"AntivirusEnabled": True, "RealTimeProtectionEnabled": False, "IsTamperProtected": False,
                          "AntivirusSignatureAge": 20, "AMRunningMode": "Normal"},
               "prefs": {"DisableRealtimeMonitoring": True, "ExclusionPath": ["C:\\\\Temp"]},
               "firewall": [{"Name": "Public", "Enabled": False}, {"Name": "Private", "Enabled": True}]}
        text = W.render(bad, W.findings(bad))
        for want in ("real-time protection is OFF", "tamper protection is off", "20 days old", "Public profile",
                     "excluded from scanning"):
            self.assertIn(want, text)
        good = {"status": {"AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "IsTamperProtected": True,
                           "AntivirusSignatureAge": 0, "QuickScanAge": 1, "AMRunningMode": "Normal"},
                "prefs": {}, "firewall": [{"Name": "Public", "Enabled": True}]}
        self.assertEqual(W.findings(good), [])

    def test_a_bare_windows_program_gets_its_exe(self):
        import gnoc_agent as G
        from unittest import mock
        ctx = G.Ctx({"sid": "w"})
        ctx.s["_turn_text"] = "are the windows defender settings correct"
        with mock.patch("shutil.which", side_effect=lambda n: "/mnt/c/x/" + n if n.endswith(".exe") else None):
            _n, args, _pre = G._plan_call("bash", {"command": 'powershell -NoProfile -Command "Get-MpPreference"'},
                                          ctx, False, None)
        self.assertTrue(args["command"].startswith("powershell.exe -NoProfile"))
