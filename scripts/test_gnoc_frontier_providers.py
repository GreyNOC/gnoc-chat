"""Every frontier lab's API is a built-in provider, Claude first (2026-11-27)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import gnoc_cloud  # noqa: E402
from gnoc_core import providers as wires  # noqa: E402

LABS = ("anthropic", "openai", "gemini", "xai", "meta", "mistral", "deepseek", "moonshot", "qwen")


class TheTable(unittest.TestCase):
    def test_every_lab_is_built_in_and_claude_is_first(self):
        names = list(gnoc_cloud.PROVIDERS)
        self.assertEqual(names[0], "anthropic")
        for lab in LABS:
            self.assertIn(lab, names)
        self.assertEqual(list(gnoc_cloud.providers())[0], "anthropic")
        self.assertTrue(gnoc_cloud.PROVIDERS["anthropic"][2].startswith("claude-"))

    def test_each_row_is_well_formed(self):
        for name, (base, env, default, models) in gnoc_cloud.PROVIDERS.items():
            self.assertTrue(base.startswith("https://"), name)
            self.assertRegex(env, r"^[A-Z_]+_API_KEY$", name)
            self.assertIn(default, models, name)

    def test_aliases_name_providers(self):
        self.assertEqual(gnoc_cloud.canonical("Claude"), "anthropic")
        self.assertEqual(gnoc_cloud.canonical("grok"), "xai")
        self.assertEqual(gnoc_cloud.canonical("deepseek"), "deepseek")
        for alias, name in gnoc_cloud.ALIASES.items():
            self.assertIn(name, gnoc_cloud.PROVIDERS, alias)
        self.assertTrue(gnoc_cloud.is_cloud("claude"))

    def test_urls_land_on_each_labs_chat_endpoint(self):
        want = {"anthropic": "https://api.anthropic.com/v1/messages",
                "openai": "https://app.example.com/v1/chat/completions",
                "xai": "https://api.x.ai/v1/chat/completions",
                "meta": "https://api.llama.com/compat/v1/chat/completions",
                "mistral": "https://api.mistral.ai/v1/chat/completions",
                "deepseek": "https://api.deepseek.com/v1/chat/completions",
                "moonshot": "https://api.moonshot.ai/v1/chat/completions",
                "qwen": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"}
        for name, url in want.items():
            base = gnoc_cloud.PROVIDERS[name][0]
            self.assertEqual(gnoc_cloud._chat_url(base, gnoc_cloud.wire_for(name)), url, name)


class HostQuirks(unittest.TestCase):
    def test_openai_takes_max_completion_tokens_and_no_temperature(self):
        body = {"model": "gpt-5", "temperature": 0.3, "max_tokens": 100, "messages": []}
        got = wires.openai_fixups("https://app.example.com/v1/chat/completions", body)
        self.assertEqual(got.get("max_completion_tokens"), 100)
        self.assertNotIn("max_tokens", got)
        self.assertNotIn("temperature", got)
        self.assertIn("temperature", body)   # the caller's dict is not changed

    def test_mistral_drops_stream_options(self):
        got = wires.openai_fixups("https://api.mistral.ai/v1/chat/completions",
                                  {"stream_options": {"include_usage": True}, "max_tokens": 5})
        self.assertEqual(got, {"max_tokens": 5})

    def test_other_hosts_are_untouched(self):
        body = {"temperature": 0.3, "max_tokens": 5, "stream_options": {}}
        self.assertEqual(wires.openai_fixups("https://api.deepseek.com/v1/chat/completions", body), body)
        self.assertEqual(wires.openai_fixups("http://127.0.0.1:8080/v1/chat/completions", body), body)

    def test_the_key_check_uses_the_fixups(self):
        _, body = wires.check_request("openai", "https://app.example.com/v1/chat/completions", "gpt-5")
        self.assertIn("max_completion_tokens", body)
        self.assertNotIn("max_tokens", body)


class KeysStayOutOfHistory(unittest.TestCase):
    def test_every_provider_command_with_a_key_is_scrubbed(self):
        from gnoc_core import cli
        for cmd in ("claude", "anthropic", "gpt", "openai", "grok", "xai", "gemini", "mistral", "llama", "kimi",
                    "qwen", "deepseek", "cloud"):
            self.assertTrue(cli._KEY_COMMAND.search(f"/{cmd} api sk-" "test0123456789abcdef"), cmd)
        self.assertFalse(cli._KEY_COMMAND.search("/claude on"))


if __name__ == "__main__":
    unittest.main()
