"""Reels driver 2026-10-26: two defects seen while driving one chat turn per reel.
1. read_file refused the storyboard template as 'already shown' in a FRESH launch: the _whole_files tracker lived in
   the part of session.json that carries over between launches. It is per chat now.
2. The 9B fallback wrote its bash call as Hermes XML text; text_tool_calls now parses that shape."""
import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_agent as A  # noqa: E402


def _agent_source():
    import importlib
    import inspect
    import pkgutil
    import gnoc_core
    import gnoc_tools
    # every module of both packages, found rather than listed: a later split's modules are read too
    names = sorted(f"{pkg.__name__}.{m.name}" for pkg in (gnoc_core, gnoc_tools)
                   for m in pkgutil.iter_modules(pkg.__path__))
    return "\n".join(inspect.getsource(m) for m in [A] + [importlib.import_module(n) for n in names])

XML = ('The storyboard is written. Now the clip.\n<tool_call>\n<function=bash>\n<parameter=command>\n'
       'gnoc video clip "dark terminal" --seconds 4 --name reel-01\n</parameter>\n</function>\n</tool_call>\n')


class ReelsFixes(unittest.TestCase):
    def test_whole_files_is_per_chat(self):
        self.assertIn("_whole_files", A.PER_CHAT)

    def test_xml_function_text_call_is_salvaged(self):
        calls = A.text_tool_calls(XML)
        self.assertEqual(calls, [("bash", {"command": 'gnoc video clip "dark terminal" --seconds 4 --name reel-01'})])

    def test_xml_unknown_tool_ignored(self):
        self.assertEqual(A.text_tool_calls("<function=nosuchtool><parameter=x>1</parameter></function>"), [])

    def test_fenced_json_still_parsed(self):
        out = A.text_tool_calls('```json\n{"name": "bash", "arguments": {"command": "ls"}}\n```')
        self.assertEqual(out, [("bash", {"command": "ls"})])


class LocalLeadFallback(unittest.TestCase):
    """the user 2026-10-26: a busy or dead desktop falls back to the SAME lead on the laptop when it is there."""

    def setUp(self):
        import gnoc_image
        self._saved = (A._local_has, A.is_broken, A._fallback_target, gnoc_image.comfy_busy, gnoc_image._req, A.say)
        A.say = lambda *a, **k: None

    def tearDown(self):
        import gnoc_image
        A._local_has, A.is_broken, A._fallback_target, gnoc_image.comfy_busy, gnoc_image._req, A.say = self._saved

    def test_busy_card_prefers_same_model_on_local(self):
        import gnoc_image
        gnoc_image.comfy_busy = lambda: 1
        gnoc_image._req = lambda *a, **k: '{"models": []}'
        A._local_has = lambda m: m == "lead-35b"
        A.is_broken = lambda m, h: False
        A._fallback_target = lambda m, h: ("worker-9b", "local")
        self.assertEqual(A._avoid_busy_card("lead-35b", "desktop"), ("lead-35b", "local"))

    def test_busy_card_without_local_copy_uses_worker(self):
        import gnoc_image
        gnoc_image.comfy_busy = lambda: 1
        gnoc_image._req = lambda *a, **k: '{"models": []}'
        A._local_has = lambda m: False
        A.is_broken = lambda m, h: False
        A._fallback_target = lambda m, h: ("worker-9b", "local")
        self.assertEqual(A._avoid_busy_card("lead-35b", "desktop"), ("worker-9b", "local"))

    def test_resident_lead_is_kept(self):
        import gnoc_image
        gnoc_image.comfy_busy = lambda: 1
        gnoc_image._req = lambda *a, **k: '{"models": [{"name": "lead-35b"}]}'
        A._local_has = lambda m: True
        self.assertEqual(A._avoid_busy_card("lead-35b", "desktop"), ("lead-35b", "desktop"))

    def test_env_switch_off(self):
        os.environ["GNOC_LEAD_LOCAL_FALLBACK"] = "0"
        try:
            self.assertFalse(A._local_has("anything"))
        finally:
            del os.environ["GNOC_LEAD_LOCAL_FALLBACK"]


class SaidNothingRetry(unittest.TestCase):
    """R4: the said-nothing retry must ask for the next tool call, not forbid tool calls."""

    def test_retry_allows_tool_calls(self):
        src = _agent_source()
        i = src.index("You produced no answer.")
        msg = src[i:i + 500]
        self.assertIn("make the next tool call", msg)
        self.assertNotIn("no tool calls", msg)
        self.assertIn("never claim a file or result you did not produce", msg)


if __name__ == "__main__":
    unittest.main()
