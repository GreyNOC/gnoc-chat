#!/usr/bin/env python3
"""Tests for the guided first-run setup (gnoc_setup.py): when it runs, what it tells a new user, and each path
(Ollama already there, a download, an install the user declines, a cloud key). The terminal, subprocesses and
model hosts are all fakes: nothing is installed, started, downloaded or sent anywhere.

    python3 -m pytest -q scripts/test_gnoc_setup.py
"""
import inspect
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_setup as S  # noqa: E402
import llm_endpoints  # noqa: E402


class FakeEngine:
    """Stands in for gnoc_engine: records what setup asked it to do."""
    EngineError = S.gnoc_engine.EngineError
    LLAMA_REPO, HOME = "ggml-org/llama.cpp", "/tmp/engine-home"

    def __init__(self, installed=True, kind="gnoc", pull_fails=""):
        self.installed, self.kind, self.pull_fails, self.did, self.on_pull = installed, kind, pull_fails, [], None

    def who(self, at, timeout=2):
        return self.kind

    def server_path(self):
        return "/x/llama-server" if self.installed else None

    def install(self, **kw):
        self.did.append("install")
        self.installed = True
        return {"tag": "b1", "variant": "v", "server": "/x/llama-server"}

    def start(self, wait=15):
        self.did.append("start")
        return "started", "127.0.0.1:1"

    def enable(self, on=True):
        self.did.append("enable")

    def import_ollama(self, names=None, progress=None):
        self.did.append("import")
        return [{"name": "qwen3:8b"}]

    def remote_pull(self, host, src, show=True):
        self.did.append(("pull", src))
        if self.pull_fails:
            raise self.EngineError(self.pull_fails)
        if self.on_pull:
            self.on_pull(src)


class FakeIo(S.Io):
    def __init__(self, answers, secrets=(), engine=None):
        self.answers, self.secrets, self.out, self.ran, self.started = list(answers), list(secrets), [], [], []
        super().__init__(ask=self._ask, say=self.out.append, secret=self._secret, run=self._run, popen=self._popen,
                         sleep=lambda s: None, engine=engine or FakeEngine())

    def _ask(self, prompt):
        self.out.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def _secret(self, prompt):
        if not self.secrets:
            raise EOFError
        return self.secrets.pop(0)

    def _run(self, argv, **kw):
        self.ran.append(argv)
        return types.SimpleNamespace(returncode=0)

    def _popen(self, argv, **kw):
        self.started.append(argv)

    def text(self):
        return "\n".join(map(str, self.out))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-setup-test-")
        self.p = [mock.patch.object(S, "STATE", os.path.join(self.tmp, "setup.json")),
                  mock.patch.object(llm_endpoints, "roles", return_value={}),
                  mock.patch.object(S, "machine", return_value={"os": "linux", "ram_gb": 16.0, "vram_gb": 8.0,
                                                                "apple": False}),
                  mock.patch.object(llm_endpoints, "allow_stock", return_value=True),
                  mock.patch.object(S, "_wake_engine", return_value=False),   # never start a real engine
                  mock.patch.object(S, "_phone_link")]                        # nor reach for a real phone
        for p in self.p:
            p.start()
        self.roles = {}

    def tearDown(self):
        for p in self.p:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def set_role(self, role, spec):
        self.roles[role] = spec


class WhenSetupIsNeeded(Base):
    def test_no_ollama_is_said_plainly_and_an_unconfigured_desktop_is_not_mentioned(self):
        with mock.patch.object(llm_endpoints, "up", return_value=False):
            ok, why = S.usable("gpt-oss:20b@desktop", "qwen3:8b")
        self.assertFalse(ok)
        self.assertIn("no model server is running on this computer", why)
        self.assertNotIn("desktop", why)

    def test_a_downloaded_model_is_ready(self):
        with mock.patch.object(llm_endpoints, "up", return_value=True), \
                mock.patch.object(S, "_tags", return_value=["qwen3:8b"]):
            self.assertEqual(S.usable("gpt-oss:20b@desktop", "qwen3:8b"), (True, "worker qwen3:8b on this computer"))

    def test_a_missing_model_is_named(self):
        with mock.patch.object(llm_endpoints, "up", return_value=True), \
                mock.patch.object(S, "_tags", return_value=["llama3:8b"]):
            ok, why = S.usable("qwen3:8b", "qwen3:8b")
        self.assertFalse(ok)
        self.assertIn("(qwen3:8b) is not downloaded", why)

    def test_a_cloud_role_with_a_key_is_ready(self):
        import gnoc_cloud
        with mock.patch.object(gnoc_cloud, "key_for", return_value="k"), \
                mock.patch.object(llm_endpoints, "up", return_value=False):
            self.assertTrue(S.usable("deepseek-chat@deepseek", "qwen3:8b")[0])

    def test_not_now_is_remembered_for_a_day(self):
        self.assertFalse(S.skipped_recently())
        io = FakeIo(["4"])
        self.assertFalse(S.run(self.set_role, io))
        self.assertTrue(S.skipped_recently())
        self.assertEqual(self.roles, {})


class ThisMachinesModel(unittest.TestCase):
    def test_sizes(self):
        with mock.patch.object(llm_endpoints, "allow_stock", return_value=True):
            self.assertEqual(S.recommend({"ram_gb": 64, "vram_gb": 16, "apple": False})[0], "qwen3:14b")
            self.assertEqual(S.recommend({"ram_gb": 32, "vram_gb": 0, "apple": True})[0], "qwen3:14b")
            self.assertEqual(S.recommend({"ram_gb": 16, "vram_gb": 8, "apple": False})[0], "qwen3:8b")
            # no graphics card: the 4B answers in seconds on a CPU where the 8B takes a minute (out of the box)
            self.assertEqual(S.recommend({"ram_gb": 16, "vram_gb": 0, "apple": False})[0], "qwen3:4b")
            self.assertEqual(S.recommend({"ram_gb": 4, "vram_gb": 0, "apple": False})[0], "qwen3:4b")

    def test_an_uncensored_only_build_suggests_an_uncensored_model(self):
        with mock.patch.object(llm_endpoints, "allow_stock", return_value=False):
            self.assertIn("abliterated", S.recommend({"ram_gb": 16, "vram_gb": 0, "apple": False})[0])


class TheLocalPath(Base):
    def env(self, tags, ollama=True, running=True):
        return [mock.patch("shutil.which", side_effect=lambda b: "/usr/bin/" + b if (b != "ollama" or ollama) else None),
                mock.patch.object(llm_endpoints, "sniff", return_value=running),
                mock.patch.object(S, "_tags", side_effect=lambda h, timeout=3: list(tags)),
                mock.patch.object(S, "_test_local", return_value=True)]

    def run_with(self, patches, io):
        for p in patches:
            p.start()
        try:
            return S.run(self.set_role, io)
        finally:
            for p in patches:
                p.stop()

    def test_an_installed_model_is_chosen_and_both_roles_use_it(self):
        io = FakeIo(["1", "2"])
        self.assertTrue(self.run_with(self.env(["nomic-embed-text:latest", "llama3:8b", "qwen3:8b"]), io))
        self.assertEqual(self.roles, {"lead": "qwen3:8b", "worker": "qwen3:8b"})
        self.assertNotIn("nomic-embed", io.text())       # embedding models are not offered
        self.assertEqual(io.ran, [])                      # nothing downloaded
        self.assertIn("Which one should gnoc use? [2]", io.text())   # the installed qwen3 is the default

    def test_no_model_downloads_the_suggested_one_after_a_yes(self):
        tags = []
        io = FakeIo(["1", ""])
        io.engine.on_pull = tags.append
        self.assertTrue(self.run_with(self.env(tags), io))
        self.assertEqual(io.engine.did, [("pull", "qwen3:8b")])
        self.assertEqual(io.ran, [])                      # no outside program is run for a download
        self.assertEqual(self.roles["lead"], "qwen3:8b")

    def test_a_failed_download_says_why_and_sets_nothing(self):
        io = FakeIo(["1", ""], engine=FakeEngine(pull_fails="huggingface.co answered 503"))
        self.assertFalse(self.run_with(self.env([]), io))
        self.assertEqual(self.roles, {})
        self.assertIn("huggingface.co answered 503", io.text())

    def test_a_declined_download_changes_nothing(self):
        io = FakeIo(["1", "n"])
        self.assertFalse(self.run_with(self.env([]), io))
        self.assertEqual((io.ran, io.engine.did, self.roles), ([], [], {}))
        self.assertIn("gnoc engine pull qwen3:8b", io.text())

    def test_no_engine_yet_downloads_nothing_without_a_yes(self):
        io = FakeIo(["1", "n"], engine=FakeEngine(installed=False))
        self.assertFalse(self.run_with(self.env([], running=False), io))
        self.assertIn("gnoc engine install", io.text())
        self.assertEqual((io.ran, io.engine.did), ([], []))

    def test_a_fresh_computer_gets_the_engine_installed_started_and_kept(self):
        states = iter([False, True, True])
        patches = self.env(["qwen3:8b"])
        patches[1] = mock.patch.object(llm_endpoints, "sniff", side_effect=lambda *a, **k: next(states, True))
        io = FakeIo(["1", "", "", "1"], engine=FakeEngine(installed=False))
        self.assertTrue(self.run_with(patches, io))
        self.assertEqual(io.engine.did, ["install", "start", "enable"])
        self.assertEqual((io.ran, io.started), ([], []))  # no Ollama installer, no `ollama serve`
        self.assertEqual(self.roles["lead"], "qwen3:8b")

    def test_a_running_ollama_is_kept_when_he_says_no(self):
        io = FakeIo(["1", "n", "1"], engine=FakeEngine(kind="ollama"))
        self.assertTrue(self.run_with(self.env(["qwen3:8b"]), io))
        self.assertIn("An Ollama is running here", io.text())
        self.assertIn("using Ollama", io.text())
        self.assertEqual(io.engine.did, [])

    def test_a_new_install_beside_ollama_gets_gnocs_engine(self):
        """the user 2026-11-22: "make sure the new installs are using the gnoc model engine"."""
        old = llm_endpoints.HOSTS["local"]
        io = FakeIo(["1", "", "1"], engine=FakeEngine(kind="ollama"))
        try:
            with mock.patch.object(llm_endpoints, "save_host") as save:
                self.assertTrue(self.run_with(self.env(["qwen3:8b"]), io))
            save.assert_called_once_with("local", llm_endpoints.ENGINE_BESIDE_OLLAMA)
            self.assertEqual(io.engine.did, ["start", "import", "enable"])
            self.assertIn("gnoc's engine is running (127.0.0.1:11439), with 1 model(s) from Ollama", io.text())
        finally:
            llm_endpoints.HOSTS["local"] = old


class TheEngineHint(Base):
    def test_a_public_install_on_ollama_hears_about_the_engine_three_times(self):
        with mock.patch.dict(os.environ, {"GNOC_ENGINE_HINT": ""}), \
                mock.patch.object(llm_endpoints, "sniff", return_value=True), \
                mock.patch.object(S.gnoc_engine, "who", return_value="ollama"), \
                mock.patch.object(S, "STATE", os.path.join(self.tmp, "setup.json")):
            got = [S.engine_hint() for _ in range(4)]
        self.assertTrue(all("/setup moves this install" in g for g in got[:3]))
        self.assertEqual(got[3], "")
        # a machine that runs Ollama on purpose turns it off in its machine.json
        with mock.patch.dict(os.environ, {"GNOC_ENGINE_HINT": "0"}):
            self.assertEqual(S.engine_hint(), "")


class OutOfTheBox(Base):
    """2026-11-23: "detect if ollama is present, if not it should install gnoc engine. We want this working out of
    the box." One question at most, yes by default."""

    def test_an_ollama_with_a_model_is_used_with_no_question(self):
        io = FakeIo([], engine=FakeEngine(kind="ollama"))
        with mock.patch.object(llm_endpoints, "sniff", return_value=True), \
                mock.patch.object(S, "_tags", return_value=["qwen3:8b", "nomic-embed-text:latest"]), \
                mock.patch.object(S, "_test_local", return_value=True):
            self.assertTrue(S.auto(io, self.set_role))
        self.assertEqual(self.roles, {"lead": "qwen3:8b", "worker": "qwen3:8b"})
        self.assertEqual(io.engine.did, [])
        self.assertNotIn("Go ahead?", io.text())
        self.assertIn("Ollama is running on this computer", io.text())

    def test_nothing_here_gets_gnocs_engine_and_a_model_after_one_yes(self):
        tags = []
        eng = FakeEngine(installed=False, kind="")
        eng.on_pull = tags.append
        io = FakeIo([""], engine=eng)
        up = []
        with mock.patch.object(llm_endpoints, "sniff", side_effect=lambda *a, **k: bool(up)), \
                mock.patch.object(S, "_tags", side_effect=lambda h, timeout=3: list(tags)), \
                mock.patch.object(S, "_test_local", return_value=True), \
                mock.patch.object(S, "_wait_up", side_effect=lambda io, seconds=20: up.append(1) or True):
            self.assertTrue(S.auto(io, self.set_role))
        self.assertEqual(io.engine.did, ["install", "start", "enable", ("pull", "qwen3:8b")])
        self.assertEqual(self.roles, {"lead": "qwen3:8b", "worker": "qwen3:8b"})
        self.assertEqual(io.text().count("Go ahead?"), 1)

    def test_a_no_changes_nothing_and_assume_yes_asks_nothing(self):
        io = FakeIo(["n"], engine=FakeEngine(installed=False, kind=""))
        with mock.patch.object(llm_endpoints, "sniff", return_value=False), mock.patch.object(S, "_tags", return_value=[]):
            self.assertFalse(S.auto(io, self.set_role))
        self.assertEqual(io.engine.did, [])
        self.assertEqual(self.roles, {})
        eng = FakeEngine(installed=True, kind="")
        eng.on_pull = lambda src: None
        io = FakeIo([], engine=eng)
        with mock.patch.object(llm_endpoints, "sniff", return_value=False), \
                mock.patch.object(S, "_tags", return_value=[]), mock.patch.object(S, "_wait_up", return_value=True):
            S.auto(io, self.set_role, assume_yes=True)
        self.assertNotIn("Go ahead?", io.text())
        self.assertIn("start", eng.did)

    def test_the_first_chat_runs_it_and_a_no_opens_the_menu(self):
        io = FakeIo(["n", "4"], engine=FakeEngine(installed=False, kind=""))
        with mock.patch.object(llm_endpoints, "sniff", return_value=False), mock.patch.object(S, "_tags", return_value=[]):
            self.assertFalse(S.first_run(self.set_role, io))
        self.assertIn("a model server on ANOTHER computer", io.text())
        import gnoc_agent  # noqa: F401
        from gnoc_core import cli
        self.assertIn("gnoc_setup.first_run(set_role", inspect.getsource(cli._model_ready))


class NvidiaOnVulkanHint(Base):
    def test_an_nvidia_card_on_the_vulkan_build_is_told_how_to_switch(self):
        with mock.patch.object(S.gnoc_engine, "enabled", return_value=True), \
                mock.patch.object(S.gnoc_engine, "build_info", return_value={"variant": "ubuntu-vulkan-x64"}), \
                mock.patch.object(S.gnoc_engine, "gpu", return_value=("nvidia", 16 << 30)), \
                mock.patch.object(S.sys, "platform", "linux"):
            self.assertIn("--variant cuda-12.8", S.engine_hint())
        with mock.patch.object(S.gnoc_engine, "enabled", return_value=True), \
                mock.patch.object(S.gnoc_engine, "build_info", return_value={"variant": "ubuntu-cuda-12.8-x64"}), \
                mock.patch.object(S.gnoc_engine, "gpu", return_value=("nvidia", 16 << 30)), \
                mock.patch.object(S.llm_endpoints, "sniff", return_value=False):
            self.assertNotIn("cuda", S.engine_hint())


class TheCloudPath(Base):
    def test_a_checked_key_sets_both_roles(self):
        import gnoc_cloud
        prov = {"deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat", ("deepseek-chat",))}
        with mock.patch.object(gnoc_cloud, "providers", return_value=prov), \
                mock.patch.object(gnoc_cloud, "save_key", return_value=(True, "saved")) as save, \
                mock.patch.object(gnoc_cloud, "check", return_value=(True, "answered")):
            io = FakeIo(["3", "1"], secrets=["sk-test-not-real-0000000000"])
            self.assertTrue(S.run(self.set_role, io))
        save.assert_called_once_with("deepseek", "sk-test-not-real-0000000000")
        self.assertEqual(self.roles, {"lead": "deepseek-chat@deepseek", "worker": "deepseek-chat@deepseek"})
        self.assertIn("leaves this machine", io.text())

    def test_a_rejected_key_sets_nothing(self):
        import gnoc_cloud
        prov = {"deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY", "deepseek-chat", ("deepseek-chat",))}
        with mock.patch.object(gnoc_cloud, "providers", return_value=prov), \
                mock.patch.object(gnoc_cloud, "save_key", return_value=(True, "saved")), \
                mock.patch.object(gnoc_cloud, "check", return_value=(False, "rejected the key")):
            io = FakeIo(["3", "1"], secrets=["bad-key-000000000000"])
            self.assertFalse(S.run(self.set_role, io))
        self.assertEqual(self.roles, {})


class AnotherComputersEngine(Base):
    """2026-11-23: a second computer runs gnoc's engine only (no Ollama), shared behind a key, paired from here."""

    def _tags(self, names):
        import io as _io

        class Tags(_io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Tags(json.dumps({"models": [{"name": n} for n in names]}).encode())

    def test_a_pasted_pairing_line_saves_the_key_and_the_address_and_uses_its_model(self):
        saved, keys = {}, {}
        with mock.patch.object(S, "_remote_version", side_effect=lambda a, timeout=4: ("gnoc", "gnoc-engine 1.4.0")
                               if a == "192.168.1.20:11434" else ("", "")), \
                mock.patch("urllib.request.urlopen", return_value=self._tags(["nomic-embed-text:latest", "qwen3:14b"])), \
                mock.patch.object(llm_endpoints, "save_host", side_effect=lambda k, a: saved.update({k: a})), \
                mock.patch.object(llm_endpoints, "save_host_key", side_effect=lambda a, k: keys.update({a: k})):
            io = FakeIo(["2", "gnoc pair 192.168.1.20:11434 K3Y-not-real", "1"])
            self.assertTrue(S.run(self.set_role, io))
        self.assertEqual(saved, {"desktop": "192.168.1.20:11434"})
        self.assertEqual(keys, {"192.168.1.20:11434": "K3Y-not-real"})
        self.assertEqual(self.roles, {"lead": "qwen3:14b@desktop", "worker": "qwen3:14b@desktop"})
        self.assertIn("gnoc-engine share on", io.text())
        self.assertNotIn("install Ollama", io.text())

    def test_an_ollama_without_a_key_still_pairs(self):
        saved = {}
        with mock.patch.object(S, "_remote_version", return_value=("ollama", "0.9")), \
                mock.patch("urllib.request.urlopen", return_value=self._tags(["qwen3:8b"])), \
                mock.patch.object(llm_endpoints, "save_host", side_effect=lambda k, a: saved.update({k: a})), \
                mock.patch.object(llm_endpoints, "save_host_key"):
            io = FakeIo(["2", "http://192.168.1.20/", "1"])
            self.assertTrue(S.run(self.set_role, io))
        self.assertEqual(saved, {"desktop": "192.168.1.20:11434"})

    def test_nothing_answering_or_a_wrong_key_saves_no_host(self):
        for answer in (("", ""), ("locked", "")):
            with mock.patch.object(S, "_remote_version", return_value=answer), \
                    mock.patch.object(llm_endpoints, "save_host_key"), \
                    mock.patch.object(llm_endpoints, "save_host", side_effect=AssertionError("must not save")):
                io = FakeIo(["2", "10.0.0.9 k", "10.0.0.9 k", "10.0.0.9 k"])
                self.assertFalse(S.run(self.set_role, io))
        self.assertEqual(self.roles, {})

    def test_gnoc_pair_from_a_shell(self):
        with mock.patch.object(S, "_remote_version", return_value=("gnoc", "gnoc-engine 1.4.0")), \
                mock.patch("urllib.request.urlopen", return_value=self._tags(["qwen3:8b"])), \
                mock.patch.object(llm_endpoints, "save_host"), mock.patch.object(llm_endpoints, "save_host_key"), \
                mock.patch("builtins.print") as out:
            self.assertEqual(S.pair_main(["192.168.1.20", "K3Y"]), 0)
        self.assertIn("paired with gnoc's engine", str(out.call_args_list))
        self.assertEqual(S.pair_main([]), 2)


class ChangingAWorkingSetup(Base):
    def test_keep_the_current_model(self):
        io = FakeIo(["4"])
        self.assertFalse(S.run(self.set_role, io, current="worker qwen3:8b on this computer"))
        self.assertIn("nothing changed", io.text())
        self.assertFalse(S.skipped_recently())


class TheChatStartsTheSetup(unittest.TestCase):
    def test_a_one_shot_with_no_model_says_what_to_do_and_does_not_call_a_model(self):
        import gnoc_agent  # noqa: F401 - binds the facade
        from gnoc_core import cli
        said = []
        with mock.patch.object(S, "usable", return_value=(False, "Ollama is not running on this computer")), \
                mock.patch("gnoc_agent.say", side_effect=lambda x: said.append(str(x))), \
                mock.patch.dict(os.environ, {"GNOC_NO_SETUP": ""}):
            self.assertFalse(cli._model_ready("hi"))
        self.assertIn("gnoc setup", " ".join(said))

    def test_a_working_model_skips_it(self):
        import gnoc_agent  # noqa: F401
        from gnoc_core import cli
        with mock.patch.object(S, "usable", return_value=(True, "worker qwen3:8b")), \
                mock.patch.object(S, "run", side_effect=AssertionError("must not run")):
            self.assertTrue(cli._model_ready(None))



class EnsureWorkspace(unittest.TestCase):
    """The hunt harness's folders and the hooks a fresh install needs (gnoc_setup.ensure_workspace)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-ws-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ws, self.app = os.path.join(self.tmp, "ws"), os.path.join(self.tmp, "app")
        self.ship(self.app, "2026.11.27")
        self.hooks = os.path.join(self.ws, ".claude", "hooks")

    @staticmethod
    def ship(app, version, body="exit 2\n"):
        os.makedirs(os.path.join(app, "harness", "hooks"), exist_ok=True)
        with open(os.path.join(app, "harness", "hooks", "scope-gate.sh"), "w") as fh:
            fh.write(body)
        with open(os.path.join(app, "VERSION"), "w") as fh:
            fh.write(version + "\n")

    def run_it(self, jq=True, app=None):
        return S.ensure_workspace(self.ws, app or self.app, have_jq=jq)

    def gate(self):
        with open(os.path.join(self.hooks, "scope-gate.sh")) as fh:
            return fh.read()

    def test_fresh_workspace_gets_every_folder_and_a_real_copy_of_the_hooks(self):
        did = self.run_it()
        for d in S.SKELETON:
            self.assertTrue(os.path.isdir(os.path.join(self.ws, d)), d)
        # a copy, never a link: the write guard refuses .claude/hooks/ by path, and a link sent writes elsewhere
        self.assertFalse(os.path.islink(self.hooks))
        self.assertEqual(self.gate(), "exit 2\n")
        self.assertTrue(os.path.isfile(os.path.join(self.hooks, S.HOOKS_MARKER)))
        self.assertTrue(any("installed .claude/hooks" in x for x in did))

    def test_second_run_changes_nothing(self):
        self.run_it()
        self.assertEqual(self.run_it(), [])

    def test_a_real_hooks_folder_is_never_touched(self):
        os.makedirs(self.hooks)
        with open(os.path.join(self.hooks, "mine.sh"), "w") as fh:
            fh.write("exit 0\n")
        self.run_it()
        self.run_it(jq=False)
        self.assertEqual(os.listdir(self.hooks), ["mine.sh"])

    def test_no_jq_means_no_hook_because_the_hook_allows_everything_without_it(self):
        self.run_it(jq=False)
        self.assertFalse(os.path.lexists(self.hooks))
        self.run_it()
        self.assertTrue(os.path.isdir(self.hooks))
        did = self.run_it(jq=False)                      # jq removed later: ours goes, gnoc's own check returns
        self.assertFalse(os.path.lexists(self.hooks))
        self.assertTrue(any("removed" in x for x in did))

    def test_a_new_release_refreshes_the_copy(self):
        self.run_it()
        new_app = os.path.join(self.tmp, "app2")
        self.ship(new_app, "2026.11.28", body="exit 2  # newer\n")
        self.run_it(app=new_app)
        self.assertEqual(self.gate(), "exit 2  # newer\n")

    def test_a_link_from_an_earlier_build_is_replaced_by_a_copy(self):
        os.makedirs(os.path.dirname(self.hooks))
        os.symlink(os.path.join(self.app, "harness", "hooks"), self.hooks)
        self.run_it()
        self.assertFalse(os.path.islink(self.hooks))
        self.assertEqual(self.gate(), "exit 2\n")

    def test_a_link_of_the_users_own_is_left_alone(self):
        mine = os.path.join(self.tmp, "my-hooks")
        os.makedirs(mine)
        os.makedirs(os.path.dirname(self.hooks))
        os.symlink(mine, self.hooks)
        self.run_it()
        self.run_it(jq=False)
        self.assertEqual(os.readlink(self.hooks), mine)

    def test_an_install_without_shipped_hooks_only_makes_folders(self):
        shutil.rmtree(os.path.join(self.app, "harness"))
        self.run_it()
        self.assertFalse(os.path.lexists(self.hooks))
        self.assertTrue(os.path.isdir(os.path.join(self.ws, "reports", "drafts")))

    def test_the_write_guard_refuses_the_installed_hooks_and_their_source(self):
        from gnoc_core import paths
        self.assertTrue(paths.WRITE_DENY.search(".claude/hooks/scope-gate.sh"))
        self.assertTrue(paths.WRITE_DENY.search("harness/hooks/scope-gate.sh"))

    def test_gnoc_setup_workspace_flag_stops_before_the_model_check(self):
        with mock.patch.object(S, "ensure_workspace", return_value=["made targets/"]) as ew, \
                mock.patch("sys.stdout"):
            self.assertEqual(S.main(["--workspace"]), 0)
        ew.assert_called_once_with()

if __name__ == "__main__":
    unittest.main()
