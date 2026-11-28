#!/usr/bin/env python3
"""Tests for the self-updater (gnoc_update.py): the Ed25519 code against RFC 8032, what a signed manifest must be,
rollback and freeze detection, the package download checks, and the tarball unpacker's refusals. The updater is
the one path that installs new code on a user's machine, so every trust decision it makes is pinned here.
Stdlib unittest, temp dirs only, no network.

    python3 -m pytest -q scripts/test_gnoc_update.py
"""
import base64
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
# the live tree keeps the template under gnoc_release_files/; the release ships it as scripts/gnoc_update.py
SRC = next(p for p in (os.path.join(HERE, "gnoc_release_files", "scripts", "gnoc_update.py"),
                       os.path.join(HERE, "gnoc_update.py")) if os.path.isfile(p))

# RFC 8032 section 7.1, TEST 1
RFC_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
RFC_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_SIG = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b4"
                        "6bd25bf5f0595bbe24655141438e7a100b")


def load(home):
    spec = importlib.util.spec_from_file_location(f"gnoc_update_under_test_{id(home)}", SRC)
    U = importlib.util.module_from_spec(spec)
    with mock.patch.dict(os.environ, {"GNOC_UPDATE_HOME": home}):
        spec.loader.exec_module(U)
    U.RELEASE_KEY = U.public_key(RFC_SEED).hex()
    return U


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-update-test-")
        self.U = load(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def manifest(self, version="2026.11.19.9", built=None, **extra):
        m = {"name": "gnoc-chat", "version": version,
             "built": built or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "files": {}}
        m.update(extra)
        raw = json.dumps(m).encode()
        return raw, base64.b64encode(self.U.sign(RFC_SEED, raw))

    def serve(self, raw, sig):
        def fake_get(url, limit, timeout=15):
            return raw if url.endswith("manifest.json") else sig
        return mock.patch.object(self.U, "_get", fake_get)


class Ed25519(Base):
    def test_rfc8032_vector_1(self):
        self.assertEqual(self.U.public_key(RFC_SEED), RFC_PUB)
        self.assertEqual(self.U.sign(RFC_SEED, b""), RFC_SIG)
        self.assertTrue(self.U.verify(RFC_PUB, b"", RFC_SIG))

    def test_tampering_is_refused(self):
        self.assertFalse(self.U.verify(RFC_PUB, b"x", RFC_SIG))
        bad = bytearray(RFC_SIG)
        bad[5] ^= 1
        self.assertFalse(self.U.verify(RFC_PUB, b"", bytes(bad)))
        # malleability: S + L is the same point but must be refused (RFC 8032 requires S < L)
        s = int.from_bytes(RFC_SIG[32:], "little") + self.U._L
        if s < 2 ** 256:
            self.assertFalse(self.U.verify(RFC_PUB, b"", RFC_SIG[:32] + s.to_bytes(32, "little")))
        self.assertFalse(self.U.verify(RFC_PUB, b"", b""))


class TheManifest(Base):
    def test_a_signed_gnoc_manifest_is_accepted(self):
        raw, sig = self.manifest()
        with self.serve(raw, sig):
            self.assertEqual(self.U.latest_release()["version"], "2026.11.19.9")

    def test_unsigned_or_foreign_manifests_are_refused(self):
        raw, sig = self.manifest()
        with self.serve(raw + b" ", sig), mock.patch("time.sleep"):
            with self.assertRaises(self.U.UpdateError):
                self.U.latest_release()
        foreign = json.dumps({"name": "other", "version": "1.0"}).encode()
        with self.serve(foreign, base64.b64encode(self.U.sign(RFC_SEED, foreign))):
            with self.assertRaises(self.U.UpdateError):
                self.U.latest_release()
        with self.serve(raw, b"not base64!!"), mock.patch("time.sleep"):
            with self.assertRaises(self.U.UpdateError):
                self.U.latest_release()

    def test_no_key_no_update(self):
        self.U.RELEASE_KEY = "@RELEASE_PUBKEY@"
        with self.assertRaises(self.U.UpdateError):
            self.U.latest_release()

    def test_older_or_equal_is_never_newer(self):
        self.assertTrue(self.U.newer("2026.11.19.2", "2026.11.18.15"))
        self.assertFalse(self.U.newer("2026.11.18.15", "2026.11.19.2"))
        self.assertFalse(self.U.newer("2026.11.19.2", "2026.11.19.2"))


class FreezeAndRollback(Base):
    def test_a_server_that_goes_back_is_noticed_not_believed(self):
        st = {}
        self.U._remember(st, {"version": "2026.11.19.5"})
        self.U._remember(st, {"version": "2026.11.19.2"})
        self.assertEqual(st["highest_seen"], "2026.11.19.5")
        self.assertTrue(st["held_back"])
        self.U._remember(st, {"version": "2026.11.20.1"})
        self.assertFalse(st["held_back"])

    def test_update_refuses_a_held_back_release(self):
        self.U._write_state({"highest_seen": "2026.12.01.1"})
        raw, sig = self.manifest(version="2026.11.19.9")
        with self.serve(raw, sig), mock.patch.object(self.U, "installed_version", return_value="2026.11.01.1"), \
                mock.patch("builtins.print") as pr:
            self.assertEqual(self.U.update([]), 1)
        self.assertIn("stale or tampered mirror", " ".join(str(c) for c in pr.call_args_list))

    def test_build_age_is_read_as_utc(self):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.assertLess(self.U._age_days({"built": now}), 0.01)
        self.assertIsNone(self.U._age_days({"built": "yesterday"}))


class Download(Base):
    def test_unsafe_names_and_bad_sizes_are_refused_before_any_request(self):
        for meta in ({"file": "../x.tar.gz", "bytes": 3, "sha256": "0" * 64},
                     {"file": "a/b.tar.gz", "bytes": 3, "sha256": "0" * 64},
                     {"file": ".hidden", "bytes": 3, "sha256": "0" * 64},
                     {"file": "ok.tar.gz", "bytes": 0, "sha256": "0" * 64},
                     {"file": "ok.tar.gz", "bytes": 3, "sha256": "short"}):
            with mock.patch("urllib.request.urlopen", side_effect=AssertionError("no request")):
                with self.assertRaises(self.U.UpdateError):
                    self.U._download(meta, self.tmp)

    def test_a_hash_mismatch_deletes_the_file(self):
        body = b"abc"

        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        meta = {"file": "ok.tar.gz", "bytes": 3, "sha256": hashlib.sha256(b"xyz").hexdigest()}
        with mock.patch("urllib.request.urlopen", return_value=R(body)):
            with self.assertRaises(self.U.UpdateError):
                self.U._download(meta, self.tmp)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("ok")], [])
        meta["sha256"] = hashlib.sha256(body).hexdigest()
        with mock.patch("urllib.request.urlopen", return_value=R(body)):
            self.assertTrue(os.path.isfile(self.U._download(meta, self.tmp)))


class Unpack(Base):
    def tarball(self, members):
        p = os.path.join(self.tmp, "pkg.tar.gz")
        with tarfile.open(p, "w:gz") as tf:
            for name, kind, data in members:
                ti = tarfile.TarInfo(name)
                if kind == "file":
                    ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data))
                elif kind == "sym":
                    ti.type, ti.linkname = tarfile.SYMTYPE, data
                    tf.addfile(ti)
                elif kind == "dir":
                    ti.type = tarfile.DIRTYPE
                    tf.addfile(ti)
        return p

    def test_a_good_tarball_unpacks(self):
        v = "2026.11.19.9"
        p = self.tarball([(f"gnoc-chat-{v}", "dir", None), (f"gnoc-chat-{v}/install.sh", "file", b"#!/bin/sh\n")])
        self.assertTrue(os.path.isfile(os.path.join(self.U._unpack(p, v), "install.sh")))

    def test_climbing_absolute_foreign_and_link_members_are_refused(self):
        v = "2026.11.19.9"
        for bad in ((f"gnoc-chat-{v}/../evil", "file", b"x"), ("/etc/evil", "file", b"x"),
                    ("other-dir/install.sh", "file", b"x"), (f"gnoc-chat-{v}/link", "sym", "/etc/passwd")):
            p = self.tarball([(f"gnoc-chat-{v}/install.sh", "file", b"#!/bin/sh\n"), bad])
            with self.assertRaises(self.U.UpdateError, msg=bad[0]):
                self.U._unpack(p, v)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "evil")))


class DebInstall(Base):
    def test_only_the_debs_marker_makes_it_a_deb_install(self):
        app = tempfile.mkdtemp(dir=self.tmp)
        self.U.APP = app
        self.assertFalse(self.U._is_deb_install())
        open(os.path.join(app, self.U.DEB_MARKER), "w").close()
        self.assertTrue(self.U._is_deb_install())


class AutoUpdate(Base):
    """Getting people onto the new release: the start-up question, `--auto on`, and the hand-over to the newly
    installed launcher. Silence is never a yes, a .deb is never auto-installed, and a failed install never stops
    gnoc from starting."""

    def notice_with(self, state, answer=None, deb=False, env=None):
        self.U._write_state(state)
        calls = []
        with mock.patch.object(self.U, "installed_version", return_value="2026.11.19.1"), \
                mock.patch.object(self.U, "_interactive", return_value=True), \
                mock.patch.object(self.U, "_is_deb_install", return_value=deb), \
                mock.patch.object(self.U, "_prompt", return_value=answer) as asked, \
                mock.patch.object(self.U, "_launch_install", side_effect=lambda mine: calls.append(mine)), \
                mock.patch.object(self.U.subprocess, "Popen"), \
                mock.patch.dict(os.environ, env or {}, clear=False), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            os.environ.pop("GNOC_NO_UPDATE_CHECK", None)
            if not env:
                os.environ.pop("GNOC_JUST_UPDATED", None)
            self.U.notice()
        return calls, asked, err.getvalue()

    NEW = {"latest": "2026.11.19.9", "checked_at": time.time()}

    def test_auto_on_and_off_are_saved(self):
        with mock.patch("builtins.print"):
            self.assertEqual(self.U.update(["--auto", "on"]), 0)
            self.assertTrue(self.U._read_state()["auto"])
            self.assertEqual(self.U.main(["--auto", "off"]), 0)
            self.assertFalse(self.U._read_state()["auto"])
            self.assertEqual(self.U.update(["--auto", "sometimes"]), 2)

    def test_a_new_release_asks_and_yes_installs(self):
        calls, asked, _ = self.notice_with(dict(self.NEW), answer="")
        self.assertTrue(asked.called)
        self.assertEqual(calls, ["2026.11.19.1"])

    def test_always_turns_auto_on_and_installs(self):
        calls, _, err = self.notice_with(dict(self.NEW), answer="a")
        self.assertEqual(len(calls), 1)
        self.assertTrue(self.U._read_state()["auto"])
        self.assertIn("auto-update is on", err)

    def test_no_or_silence_installs_nothing(self):
        for answer in ("n", None, "what is this"):
            calls, _, _ = self.notice_with(dict(self.NEW), answer=answer)
            self.assertEqual(calls, [], answer)

    def test_the_question_is_asked_at_most_once_a_day(self):
        calls, asked, _ = self.notice_with(dict(self.NEW, noticed_at=time.time()), answer="y")
        self.assertFalse(asked.called)
        self.assertEqual(calls, [])

    def test_auto_installs_without_asking(self):
        calls, asked, _ = self.notice_with(dict(self.NEW, auto=True, noticed_at=time.time()))
        self.assertFalse(asked.called)
        self.assertEqual(len(calls), 1)

    def test_auto_waits_after_a_failed_install(self):
        calls, _, _ = self.notice_with(dict(self.NEW, auto=True, auto_failed_at=time.time()))
        self.assertEqual(calls, [])

    def test_a_deb_is_never_installed_at_start_up(self):
        for st in (dict(self.NEW, auto=True), dict(self.NEW)):
            calls, asked, err = self.notice_with(st, answer="y", deb=True)
            self.assertEqual(calls, [])
            self.assertFalse(asked.called)
        self.assertIn("gnoc update", err)

    def test_the_handed_over_launcher_does_not_install_again(self):
        calls, asked, _ = self.notice_with(dict(self.NEW, auto=True), env={"GNOC_JUST_UPDATED": "1"})
        self.assertEqual(calls, [])
        self.assertFalse(asked.called)

    def test_launch_install_prints_only_the_new_launcher_on_stdout(self):
        new = os.path.join(self.tmp, "releases", "gnoc-chat-2026.11.19.9")
        os.makedirs(new)
        open(os.path.join(new, "gnoc-launcher"), "w").close()

        def fake_update(args, quiet=False):
            self.assertTrue(quiet)
            self.assertIn("--yes", args)
            print("chatter that must not reach the launcher")
            self.U._LAST_INSTALLED[0] = new
            return 0
        with mock.patch.object(self.U, "update", fake_update), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            self.assertTrue(self.U._launch_install("2026.11.19.1"))
        self.assertEqual(out.getvalue(), os.path.join(new, "gnoc-launcher") + "\n")
        self.assertIn("chatter", err.getvalue())

    def test_a_failed_launch_install_is_remembered_and_never_raises(self):
        with mock.patch.object(self.U, "update", side_effect=RuntimeError("boom")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertFalse(self.U._launch_install("2026.11.19.1"))
        self.assertEqual(out.getvalue(), "")
        self.assertIn("auto_failed_at", self.U._read_state())

    def test_prompt_times_out_to_none(self):
        r, w = os.pipe()
        try:
            with os.fdopen(r) as rf, mock.patch("sys.stdin", rf), mock.patch("sys.stderr", new_callable=io.StringIO):
                self.assertIsNone(self.U._prompt("? ", wait=0.05))
                os.write(w, b"A\n")
                self.assertEqual(self.U._prompt("? ", wait=1), "a")
        finally:
            os.close(w)


class WindowsZip(Base):
    """Native Windows updates unpack the signed windows zip: the same refusals as the tarball."""

    def zip_with(self, entries, prefix="gnoc-chat-2026.11.19.9"):
        import zipfile
        path = os.path.join(self.tmp, "pkg.zip")
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in entries:
                zf.writestr(name if name.startswith(("/", "..")) or "\\" in name else name, data)
        return path

    def test_a_good_zip_unpacks(self):
        p = self.zip_with([("gnoc-chat-2026.11.19.9/install-windows.ps1", "x"),
                           ("gnoc-chat-2026.11.19.9/scripts/gnoc", "y")])
        dest = self.U._unpack_zip(p, "2026.11.19.9")
        self.assertTrue(os.path.isfile(os.path.join(dest, "install-windows.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(dest, "scripts", "gnoc")))

    def test_climbing_or_foreign_paths_are_refused(self):
        for bad in ("gnoc-chat-2026.11.19.9/../evil.txt", "/abs/evil.txt", "other-folder/x.txt",
                    "gnoc-chat-2026.11.19.9/C:/evil.txt"):
            p = self.zip_with([("gnoc-chat-2026.11.19.9/install-windows.ps1", "x"), (bad, "boom")])
            with self.assertRaises(self.U.UpdateError, msg=bad):
                self.U._unpack_zip(p, "2026.11.19.9")

    def test_a_link_is_refused(self):
        import zipfile
        path = os.path.join(self.tmp, "link.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("gnoc-chat-2026.11.19.9/install-windows.ps1", "x")
            info = zipfile.ZipInfo("gnoc-chat-2026.11.19.9/evil-link")
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
        with self.assertRaises(self.U.UpdateError):
            self.U._unpack_zip(path, "2026.11.19.9")

    def test_no_installer_no_install(self):
        p = self.zip_with([("gnoc-chat-2026.11.19.9/scripts/gnoc", "y")])
        with self.assertRaises(self.U.UpdateError):
            self.U._unpack_zip(p, "2026.11.19.9")


class PairedEnginesUpdate(Base):
    @staticmethod
    def _resp(body):
        import io as _io

        class R(_io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return R(json.dumps(body).encode())

    def test_gnoc_update_brings_every_paired_engine_along_and_reports_each(self):
        """the user 2026-11-23: "it should communicate with all the attached machines about the restart and update".
        A standalone engine updates itself; one that is part of gnoc chat there installs the whole app and restarts
        its engine on it, and this waits for it to come back on the new release."""
        U = load(self.tmp)
        posted, said, polls = [], [], {"n": 0}

        def fake_open(req, timeout=0):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            self.assertEqual(req.get_header("Authorization"), "Bearer K")
            if url.endswith("/api/version"):
                if "10.0.0.6" in url:
                    polls["n"] += 1
                    rel = "2026.11.23.1" if polls["n"] == 1 else "2026.11.23.2"   # back on the new release
                    return self._resp({"engine": "gnoc", "release": rel, "standalone": False})
                return self._resp({"engine": "gnoc", "release": "2026.11.23.1", "standalone": True})
            posted.append(url)
            if "10.0.0.6" in url:
                return self._resp({"updating": True, "note": "installing the newest gnoc chat there"})
            return self._resp({"updated": True, "latest": "2026.11.23.2"})
        with mock.patch.object(U, "_paired_engines", return_value=[("10.0.0.5:11434", "K"), ("10.0.0.6:11434", "K")]), \
                mock.patch("urllib.request.urlopen", side_effect=fake_open), mock.patch.object(U.time, "sleep"):
            U.update_paired("2026.11.23.2", said.append, wait=60)
            self.assertEqual(posted, ["http://10.0.0.5:11434/api/gnoc/update", "http://10.0.0.6:11434/api/gnoc/update"])
            polls["n"] = 0
            U.update_paired("2026.11.23.2", said.append, apply=False)
        self.assertTrue(any("10.0.0.5" in s and "updated to 2026.11.23.2" in s for s in said), said)
        self.assertTrue(any("10.0.0.6" in s and "updated to 2026.11.23.2 and restarted" in s for s in said), said)
        self.assertEqual(len(posted), 2, "--check only reports")


class LocalEngineRestart(Base):
    """the user 2026-11-23: "I have to restart the gnoc engine every time i update right now"."""

    def _app(self):
        app = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(app, "scripts"), exist_ok=True)
        open(os.path.join(app, "scripts", "gnoc_engine.py"), "w").close()
        return app

    def _run(self, U, running, release, chat_open=False):
        calls = []

        def fake_run(argv, **kw):
            calls.append(argv)
            out = json.dumps(running) if argv[1] == "-c" else "engine restarted"
            return mock.Mock(returncode=0, stdout=out, stderr="")
        said = []
        with mock.patch.object(U.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(U, "_engine_release", return_value={"release": release} if release else None), \
                mock.patch.object(U, "_chat_open_besides_me", return_value=chat_open):
            st = U.restart_local_engine(self._app(), said.append, "2026.11.23.6")
        return st, [c for c in calls if c[-1] == "restart"], said

    def test_an_engine_on_the_old_release_restarts_after_a_clean_update(self):
        U = load(self.tmp)
        st, restarts, said = self._run(U, {"pid": 5, "addr": "127.0.0.1:11434"}, "2026.11.23.5")
        self.assertEqual(st, "restarted")
        self.assertEqual(len(restarts), 1)
        self.assertTrue(restarts[0][1].endswith(os.path.join("app", "scripts", "gnoc_engine.py")))
        self.assertTrue(any("restarted on 2026.11.23.6" in s for s in said))

    def test_no_restart_while_a_chat_is_open_or_when_nothing_changed_or_nothing_runs(self):
        U = load(self.tmp)
        st, restarts, said = self._run(U, {"pid": 5, "addr": "0.0.0.0:11434"}, "2026.11.23.5", chat_open=True)
        self.assertEqual((st, restarts), ("chat-open", []))
        self.assertTrue(any("gnoc engine restart" in s for s in said))
        self.assertEqual(self._run(U, {"pid": 5, "addr": "127.0.0.1:11434"}, "2026.11.23.6")[:2], ("current", []))
        self.assertEqual(self._run(U, {}, "")[:2], ("not-running", []))


if __name__ == "__main__":
    unittest.main()
