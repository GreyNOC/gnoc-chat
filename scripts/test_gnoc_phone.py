"""gnoc_phone: an Android phone on USB as a model host. A stand-in `adb` (a script that keeps its state in a
file) plays the phone, so every step of the link and the walk-through runs without one."""
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_engine  # noqa: E402
import gnoc_phone as P  # noqa: E402
import llm_endpoints  # noqa: E402

FAKE_ADB = r'''#!/usr/bin/env python3
import json, os, sys
state_file = os.environ["FAKE_ADB_STATE"]
st = json.load(open(state_file))
a = sys.argv[1:]
st.setdefault("calls", []).append(a)
serial = None
if a[:1] == ["-s"]:
    serial, a = a[1], a[2:]
def done(out="", rc=0, err=""):
    json.dump(st, open(state_file, "w"))
    sys.stdout.write(out); sys.stderr.write(err); sys.exit(rc)
if a[:1] == ["devices"]:
    done("List of devices attached\n" + "".join(f"{d['serial']}  {d['state']} usb:1-1 product:x model:{d.get('model','')} device:y\n" for d in st["devices"]))
if a[:2] == ["forward", "--list"]:
    done("".join(f"{s} {l} {r}\n" for s, l, r in st.get("forwards", [])))
if a[:2] == ["forward", "--remove"]:
    st["forwards"] = [f for f in st.get("forwards", []) if f[1] != a[2]]; done()
if a[:1] == ["forward"]:
    if st.get("forward_fails"): done(rc=1, err="error: cannot bind listener")
    st.setdefault("forwards", []).append([serial, a[1], a[2]]); done()
if a[:1] == ["push"]:
    st.setdefault("pushed", []).append(a[2]); done("1 file pushed\n")
if a[:1] == ["shell"]:
    cmd = a[1]
    dev = next(d for d in st["devices"] if d["serial"] == serial)
    if cmd.startswith("cat /proc/meminfo"): done(f"MemTotal:       {int(dev.get('ram_gb', 8) * 2 ** 20)} kB\n")
    if cmd.startswith("dumpsys battery"): done(f"  AC powered: false\n  USB powered: {'true' if dev.get('charging', True) else 'false'}\n  level: {dev.get('battery', 77)}\n  temperature: {dev.get('temp', 301)}\n")
    if "ro.product.model" in cmd: done(dev.get("model", "") + "\n")
    if "ro.build.version.release" in cmd: done("14\n")
    if cmd.startswith("pm list packages"): done("package:com.termux\n" if dev.get("termux") else "package:com.termux.api\n")
    done()
done(rc=1, err="unknown adb command")
'''


@unittest.skipIf(os.name == "nt", "the stand-in adb is a #! script")
class Phone(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-phone-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.adb = os.path.join(self.tmp, "adb")
        with open(self.adb, "w") as f:
            f.write(FAKE_ADB)
        os.chmod(self.adb, os.stat(self.adb).st_mode | stat.S_IEXEC)
        self.state = os.path.join(self.tmp, "adb.json")
        self.world(devices=[{"serial": "R58", "state": "device", "model": "SM_S908", "ram_gb": 11.2, "termux": True}])
        self.hosts = {}
        ps = [mock.patch.dict(os.environ, {"FAKE_ADB_STATE": self.state}),
              mock.patch.object(P, "adb_path", lambda: self.adb),
              mock.patch.object(llm_endpoints, "SAVED_HOSTS", os.path.join(self.tmp, "hosts.json")),
              mock.patch.object(llm_endpoints, "save_host", lambda k, v: self.hosts.__setitem__(k, v)),
              mock.patch.dict(llm_endpoints.HOSTS, {"phone": ""}),
              mock.patch.object(P, "answering", lambda timeout=3: self.engine_up)]
        self.engine_up = False
        for p in ps:
            p.start()
            self.addCleanup(p.stop)

    def world(self, **kw):
        with open(self.state, "w") as f:
            json.dump(kw, f)

    def seen(self):
        with open(self.state) as f:
            return json.load(f)

    def io(self, answers):
        answers, out = list(answers), []

        def ask(prompt):
            out.append(prompt)
            if not answers:
                raise EOFError
            return answers.pop(0)
        return P.Io(ask=ask, say=out.append, sleep=lambda s: None), out


class TheLink(Phone):
    def test_the_phone_is_read_from_adb(self):
        self.assertEqual(P.devices(), [{"serial": "R58", "state": "device", "model": "SM_S908"}])
        f = P.facts("R58")
        self.assertEqual((f["model"], f["android"], f["ram_gb"], f["battery"], f["temp_c"], f["charging"], f["termux"]),
                         ("SM_S908", "14", 11.2, 77, 30.1, True, True))

    def test_another_termux_package_is_not_termux(self):
        self.world(devices=[{"serial": "R58", "state": "device", "termux": False}])
        self.assertFalse(P.facts("R58")["termux"])

    def test_up_forwards_this_computers_port_to_the_phones_engine_and_remembers_it(self):
        dev = P.up()
        self.assertEqual(dev["serial"], "R58")
        self.assertEqual(self.seen()["forwards"], [["R58", f"tcp:{P.LOCAL_PORT}", f"tcp:{P.PHONE_PORT}"]])
        self.assertEqual(self.hosts, {"phone": P.ADDR})
        self.assertTrue(P.forwarded("R58"))
        self.assertTrue(P.linked())
        P.down()
        self.assertFalse(P.forwarded())

    def test_an_install_whose_phone_address_is_already_this_cable_keeps_its_settings_file(self):
        with mock.patch.dict(llm_endpoints.HOSTS, {"phone": P.ADDR}):
            P.up()
        self.assertEqual(self.hosts, {})                 # nothing rewritten
        self.assertTrue(P.forwarded("R58"))

    def test_each_reason_there_is_no_phone_says_what_to_do(self):
        for devices, words in (([], "no phone is plugged in"),
                               ([{"serial": "R58", "state": "unauthorized"}], "tap Allow"),
                               ([{"serial": "R58", "state": "no permissions"}], "adb kill-server"),
                               ([{"serial": "A", "state": "device"}, {"serial": "B", "state": "device"}],
                                "more than one phone")):
            self.world(devices=devices)
            with self.assertRaises(P.PhoneError) as c:
                P.up()
            self.assertIn(words, str(c.exception))
        self.assertEqual(self.hosts, {})

    def test_two_phones_and_a_serial_picks_that_one(self):
        self.world(devices=[{"serial": "A", "state": "device"}, {"serial": "B", "state": "device"}])
        self.assertEqual(P.up("B")["serial"], "B")
        self.assertEqual(P.pick()["serial"], "B")        # and it is the remembered one from now on

    def test_no_adb_is_said_plainly(self):
        with mock.patch.object(P, "adb_path", lambda: None):
            with self.assertRaises(P.PhoneError) as c:
                P.up()
            self.assertIn("adb is not installed", str(c.exception))
            self.assertEqual(P.adb("devices")[0], 127)
            self.assertEqual(P.print_status(), 1)

    def test_a_chat_start_restores_a_dropped_link_only_for_a_phone_that_was_set_up(self):
        self.assertIsNone(P.ensure())                    # never set up: adb is not even asked
        self.assertNotIn("calls", self.seen())
        P.up()
        self.world(devices=self.seen()["devices"])       # the cable was pulled and put back: the forward is gone
        P.ensure(wait=True)
        self.assertEqual(len(self.seen()["forwards"]), 1)
        calls = len(self.seen()["calls"])
        P.ensure(wait=True)                              # in place already: not added twice
        self.assertEqual(len(self.seen()["forwards"]), 1)
        self.world(devices=[])                           # unplugged: nothing happens, nothing raises
        P.ensure(wait=True)
        self.assertGreater(calls, 0)

    def test_a_forward_alone_is_not_an_engine(self):
        P.up()
        st = P.status()
        self.assertEqual((st["forwarded"], st["engine"]), (True, False))
        self.assertEqual(P.print_status(st), 1)
        self.engine_up = True
        with mock.patch.object(gnoc_engine, "api", side_effect=lambda at, path, **k: {
                "models": [{"name": "qwen3:4b"}] if path == "/api/tags" else []}):
            st = P.status()
        self.assertEqual((st["engine"], st["models"]), (True, ["qwen3:4b"]))
        self.assertEqual(P.print_status(st), 0)

    def test_a_hot_phone_is_called_out(self):
        self.world(devices=[{"serial": "R58", "state": "device", "temp": 431, "termux": True}])
        lines = []
        with mock.patch("builtins.print", lambda *a, **k: lines.append(" ".join(map(str, a)))):
            P.print_status()
        self.assertIn("43 C (HOT: let it rest)", "\n".join(lines))

    def test_a_model_is_sized_to_the_phones_memory(self):
        self.assertEqual([P.recommend(g)[0] for g in (16, 11.2, 8, 6, 4, 0)],
                         ["qwen3:4b", "qwen3:4b", "qwen3:1.7b", "qwen3:1.7b", "qwen3:0.6b", "qwen3:0.6b"])
        for _least, model, _size in P.TIERS:
            self.assertIn(model, gnoc_engine.LIBRARY)   # each one is a name the phone's engine can pull


class TheWalkThrough(Phone):
    def run_setup(self, answers, tags=(), pull=None, set_role=None):
        io, out = self.io(answers)
        pulled = []

        def remote_pull(addr, model, show=True):
            pulled.append((addr, model))
            if pull:
                raise gnoc_engine.EngineError(pull)
        with mock.patch.object(gnoc_engine, "api", return_value={"models": [{"name": t} for t in tags]}), \
                mock.patch.object(gnoc_engine, "remote_pull", remote_pull):
            ok = P.setup(io, set_role)
        return ok, "\n".join(map(str, out)), pulled

    def test_a_fresh_phone_gets_the_engine_pushed_and_a_model_that_fits(self):
        roles = {}
        io_answers = ["", "", "", "y"]          # copy files? / ran the two lines / download model? / worker?
        real = P.Io.enter

        def enter(self_io, prompt):
            got = real(self_io, prompt)
            if "Run them on the phone" in prompt:
                self.engine_up = True           # the script finished on the phone
            return got
        with mock.patch.object(P.Io, "enter", enter):
            ok, text, pulled = self.run_setup(io_answers, set_role=lambda r, s: roles.__setitem__(r, s))
        self.assertTrue(ok)
        self.assertEqual(sorted(os.path.basename(p) for p in self.seen()["pushed"]),
                         ["gnoc-phone-setup.sh", "gnoc_engine.py"])
        self.assertIn("bash ~/storage/downloads/gnoc/gnoc-phone-setup.sh", text)
        self.assertEqual(pulled, [(P.ADDR, "qwen3:4b")])            # 11.2 GB of memory
        self.assertEqual(roles, {"worker": "qwen3:4b@phone"})
        self.assertEqual(self.hosts, {"phone": P.ADDR})
        self.assertIn("put it on Wi-Fi first", text)

    def test_nothing_is_copied_or_downloaded_without_a_yes(self):
        ok, text, pulled = self.run_setup(["n"])
        self.assertFalse(ok)
        self.assertNotIn("pushed", self.seen())
        self.assertEqual(pulled, [])
        self.engine_up = True
        ok, text, pulled = self.run_setup(["n", "n"], set_role=lambda r, s: self.fail("no role without a yes"))
        self.assertTrue(ok)                                          # the phone is linked; the model is for later
        self.assertEqual(pulled, [])
        self.assertIn("gnoc phone pull qwen3:4b", text)

    def test_a_phone_that_is_already_set_up_is_not_set_up_again(self):
        self.engine_up = True
        ok, text, pulled = self.run_setup([""], tags=["qwen3:1.7b"])
        self.assertTrue(ok)
        self.assertNotIn("pushed", self.seen())
        self.assertEqual(pulled, [])
        self.assertIn("/model worker qwen3:1.7b@phone", text)

    def test_no_termux_points_at_f_droid_and_stops_when_asked(self):
        self.world(devices=[{"serial": "R58", "state": "device", "termux": False}])
        ok, text, _ = self.run_setup(["q"])
        self.assertFalse(ok)
        self.assertIn(P.TERMUX_URL, text)
        self.assertNotIn("pushed", self.seen())

    def test_an_unaccepted_prompt_is_explained_and_no_terminal_never_crashes(self):
        self.world(devices=[{"serial": "R58", "state": "unauthorized"}])
        ok, text, _ = self.run_setup([])                             # no terminal to read from
        self.assertFalse(ok)
        self.assertIn("tap Allow", text)

    def test_an_engine_that_never_answers_says_what_to_check(self):
        ok, text, pulled = self.run_setup(["", ""])
        self.assertFalse(ok)
        self.assertIn("does not answer through the cable yet", text)
        self.assertEqual((pulled, self.hosts), ([], {}))

    def test_a_failed_download_says_how_to_resume(self):
        self.engine_up = True
        ok, text, pulled = self.run_setup([""], pull="connection closed at 1 of 2 bytes")
        self.assertTrue(ok)
        self.assertIn("gnoc phone pull qwen3:4b  to resume", text)


class ThePhoneSide(unittest.TestCase):
    def test_the_script_is_valid_shell_and_binds_the_phones_loopback_only(self):
        self.assertIn(f"127.0.0.1:{P.PHONE_PORT}", P.PHONE_SETUP)
        self.assertNotIn("0.0.0.0", P.PHONE_SETUP)
        self.assertNotIn("@PHONE_PORT@", P.PHONE_SETUP)
        if shutil.which("bash"):
            import subprocess
            r = subprocess.run(["bash", "-n"], input=P.PHONE_SETUP, text=True, capture_output=True)
            self.assertEqual((r.returncode, r.stderr), (0, ""))

    def test_inside_termux_the_engine_asks_for_the_android_build(self):
        with mock.patch.object(gnoc_engine, "on_android", return_value=True):
            self.assertEqual(gnoc_engine.pick_variant(), "android-arm64")
        with mock.patch.object(gnoc_engine, "on_android", return_value=False), \
                mock.patch.object(sys, "platform", "linux"), mock.patch("platform.machine", return_value="x86_64"):
            self.assertEqual(gnoc_engine.pick_variant(), "ubuntu-vulkan-x64")


if __name__ == "__main__":
    unittest.main()
