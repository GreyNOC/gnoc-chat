"""The render and the chat model share one 16 GB card, so handing it back is part of rendering.

2026-10-25: one SDXL run left the desktop with 8.3 of 15.9 GB VRAM free and 4.0 of 15.7 GB RAM free.
The 14 GB lead model could not load after it ("CUDA error: shared object initialization failed", then
a failed 2.7 GB pinned-host allocation), Ollama kept the dead runner in its registry still holding the
VRAM, and `gnoc chat` sat silent for minutes on every turn until that entry was unloaded by name.
"""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_image as I  # noqa: E402


class RestoreGpu(unittest.TestCase):
    def _req(self, vram, ram=8.0, loaded=(), fail=()):
        """Stub gnoc_image._req. Records the calls it was given."""
        calls = []

        def req(method, url, body=None, timeout=30):
            calls.append((method, url.rsplit("/", 1)[-1].split("?")[0], (body or {}).get("model")))
            if any(f in url for f in fail):
                raise OSError("unreachable")
            if url.endswith("/system_stats"):
                return json.dumps({"system": {"ram_free": int(ram * 2 ** 30)},
                                   "devices": [{"vram_free": int(vram * 2 ** 30)}]}).encode()
            if url.endswith("/api/ps"):
                return json.dumps({"models": [{"name": n} for n in loaded]}).encode()
            return b"{}"
        saved = I._req
        I._req = req
        self.addCleanup(setattr, I, "_req", saved)
        self.addCleanup(lambda: I.LAST_GPU_NOTE.__setitem__(0, ""))
        return calls

    def test_it_unloads_the_dead_runner_that_is_holding_the_vram(self):
        calls = self._req(vram=14.7, loaded=["hf.co/mradermacher/Huihui-Qwen3.5-35B:IQ3_XXS"])
        note = I.restore_gpu()
        self.assertIn(("POST", "generate", "hf.co/mradermacher/Huihui-Qwen3.5-35B:IQ3_XXS"), calls)
        self.assertIn("unloaded", note)
        self.assertIn("14.7 GB VRAM free", note)
        self.assertNotIn("WARNING", note)

    def test_it_frees_comfyui_first(self):
        calls = self._req(vram=14.7)
        I.restore_gpu()
        self.assertEqual(calls[0][:2], ("POST", "free"))

    def test_a_card_still_too_full_is_a_warning_the_agent_must_relay(self):
        self._req(vram=8.3, ram=4.0)
        note = I.restore_gpu(wait=0)
        self.assertIn("WARNING", note)
        self.assertIn("may fail to load", note)
        self.assertIn("Say this to the user", note)
        self.assertIn("8.3 GB VRAM free", note)
        self.assertIn("4.0 GB RAM free", note)

    def test_the_note_is_left_where_the_caller_reads_it(self):
        self._req(vram=14.7)
        self.assertEqual(I.restore_gpu(), I.LAST_GPU_NOTE[0])

    def test_an_unreachable_desktop_is_not_an_exception(self):
        self._req(vram=14.7, fail=("system_stats",))
        self.assertIn("state unknown", I.restore_gpu())

    def test_one_unload_that_fails_does_not_stop_the_others(self):
        calls = self._req(vram=14.7, loaded=["a", "b"])
        saved = I._req

        def req(method, url, body=None, timeout=30):
            if url.endswith("/api/generate") and (body or {}).get("model") == "a":
                raise OSError("boom")
            return saved(method, url, body, timeout)
        I._req = req
        note = I.restore_gpu()
        self.assertIn(("POST", "generate", "b"), calls)
        self.assertIn("unloaded b", note)

    def test_generate_hands_the_card_back_even_when_the_render_fails(self):
        self._req(vram=14.7)
        I.LAST_GPU_NOTE[0] = ""
        saved_up, saved_restore = I.up, I.restore_gpu
        seen = []
        I.up = lambda: True
        I.restore_gpu = lambda *a, **k: seen.append(1)
        # the ComfyUI path is taken only where one is set up (GNOC_COMFY_URL, machine.json); a fresh install draws
        # with the engine instead and never reaches this finally
        env = mock.patch.dict(os.environ, {"GNOC_COMFY_URL": "http://comfy.invalid:18188"})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(setattr, I, "up", saved_up)
        self.addCleanup(setattr, I, "restore_gpu", saved_restore)
        with self.assertRaises(Exception):
            I.generate("x", timeout=0)   # no ComfyUI behind the stub: it fails inside the try
        self.assertEqual(seen, [1], "the finally must still hand the card back")


if __name__ == "__main__":
    unittest.main()


class DeadRunnerIsReleased(unittest.TestCase):
    """A crashed desktop runner holds its VRAM until it is unloaded by name, and that outlives the
    process that saw the crash. _BROKEN_MODEL remembers it for one session; the card needs freeing."""

    def setUp(self):
        import gnoc_agent
        self.G = gnoc_agent
        self.sent = []
        saved = I._req
        I._req = lambda method, url, body=None, timeout=30: (
            self.sent.append((method, url, (body or {}).get("model"), (body or {}).get("keep_alive"))), b"{}")[1]
        self.addCleanup(setattr, I, "_req", saved)
        self.addCleanup(self.G._BROKEN_MODEL.clear)

    def test_a_crashed_desktop_runner_is_unloaded_by_name(self):
        self.G.mark_broken("big:IQ3_XXS", "desktop",
                           "llama-server process has terminated: CUDA error: shared object init failed")
        self.assertEqual([(m, mod, k) for m, _u, mod, k in self.sent], [("POST", "big:IQ3_XXS", 0)])
        self.assertTrue(self.G.is_broken("big:IQ3_XXS", "desktop"))

    def test_the_laptop_is_left_alone(self):
        self.G.mark_broken("small", "local", "llama-server process has terminated: CUDA error")
        self.assertEqual(self.sent, [])

    def test_a_failure_that_is_not_a_dead_runner_unloads_nothing(self):
        self.G.mark_broken("big", "desktop", "context length exceeded")
        self.assertEqual(self.sent, [])

    def test_an_unreachable_desktop_does_not_break_marking_it_broken(self):
        I._req = lambda *a, **k: (_ for _ in ()).throw(OSError("tunnel down"))
        self.G.mark_broken("big", "desktop", "CUDA error")
        self.assertTrue(self.G.is_broken("big", "desktop"))
