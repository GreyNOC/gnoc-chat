"""The /privacy switches (the user 2026-11-24: "make sure that privacy is important still and that we have settings
and options to turn off any telem or file sharing"). Each flow that can send data off the computer asks
gnoc_privacy first; these tests pin the switches and the hooks."""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_agent  # noqa: E402,F401
import gnoc_privacy as P  # noqa: E402


class PrivacySwitches(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.env = {k: os.environ.get(k) for k in ("GNOC_PRIVACY_FILE", "GNOC_OFFLINE", "GNOC_NO_UPDATE_CHECK")}
        os.environ["GNOC_PRIVACY_FILE"] = os.path.join(self.d, "privacy.json")
        os.environ.pop("GNOC_OFFLINE", None)
        os.environ.pop("GNOC_NO_UPDATE_CHECK", None)
        P.SESSION_LOCAL[0] = False

    def tearDown(self):
        for k, v in self.env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        P.SESSION_LOCAL[0] = False

    def test_defaults_allow_and_report_says_no_telemetry(self):
        for f in ("web", "image-lookup", "updates", "cloud"):
            self.assertTrue(P.allowed(f), f)
        self.assertIn("no telemetry", P.report())

    def test_one_switch_and_local_only(self):
        P.command("web off")
        self.assertFalse(P.allowed("web"))
        self.assertTrue(P.allowed("image-lookup"))
        P.command("web on")
        P.command("local-only on")
        for f in ("web", "image-lookup", "updates", "cloud"):
            self.assertFalse(P.allowed(f), f)
            self.assertIn("local-only", P.why_not(f))
        P.command("local-only off")
        self.assertTrue(P.allowed("web"))

    def test_offline_env_and_session_and_update_env(self):
        os.environ["GNOC_OFFLINE"] = "1"
        self.assertFalse(P.allowed("web"))
        os.environ.pop("GNOC_OFFLINE")
        P.SESSION_LOCAL[0] = True
        self.assertIn("/offline off", P.why_not("cloud"))
        P.SESSION_LOCAL[0] = False
        os.environ["GNOC_NO_UPDATE_CHECK"] = "1"
        self.assertFalse(P.allowed("updates"))
        self.assertTrue(P.allowed("web"))

    def test_bad_usage(self):
        self.assertIn("usage", P.command("web maybe"))

    def test_web_tools_are_held(self):
        from gnoc_core.approval import _offline_hold

        class C:
            s = {"_turn_text": "what is the capital of peru"}
        self.assertIsNone(_offline_hold(C(), "web_search"))
        P.command("web off")
        self.assertIn("switched off in /privacy", _offline_hold(C(), "web_search"))
        self.assertIsNone(_offline_hold(C(), "read_file"))
        P.command("web on")
        P.command("local-only on")
        self.assertIn("local-only", _offline_hold(C(), "recon"))

    def test_picture_lookup_is_skipped(self):
        from gnoc_tools import media
        P.command("image-lookup off")
        urls, lines = media._seek_references(None, "a red fox in snow")
        self.assertEqual(urls, [])
        self.assertIn("no reference lookup", " ".join(lines))
        ok, why = media._read_reference(None, "https://example.com/fox")
        self.assertFalse(ok)
        self.assertIn("not opened", why)
        src = open(media.__file__).read()
        self.assertIn('why_not("image-lookup")', src)

    def test_cloud_hooks(self):
        P.command("cloud off")
        import gnoc_agent as G
        self.assertTrue(G.offline())   # the claude worker is not offered
        llm = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "gnoc_core", "llm.py")).read()
        self.assertIn('gnoc_privacy.why_not("cloud")', llm)
        self.assertIn('endswith(":cloud")', llm)

    def test_update_check_and_engine_obey(self):
        here = os.path.dirname(os.path.abspath(__file__))
        upd = open(os.path.join(here, "gnoc_release_files", "scripts", "gnoc_update.py")).read() \
            if os.path.exists(os.path.join(here, "gnoc_release_files")) else open(os.path.join(here, "gnoc_update.py")).read()
        self.assertIn('gnoc_privacy.allowed("updates")', upd)
        self.assertIn('gnoc_privacy.allowed("updates")', open(os.path.join(here, "gnoc_engine.py")).read())


if __name__ == "__main__":
    unittest.main()


class PrivacyInHisWords(unittest.TestCase):
    """Defense batch 24: "does gnoc send anything I type to the internet" ran 7 minutes of tools and timed out."""

    def test_phrases(self):
        from gnoc_core.agent import _privacy_intent as P
        for q, want in (("does gnoc send anything I type to the internet", "show"), ("turn off web search", "web off"),
                        ("make gnoc fully offline", "local-only on"), ("does gnoc have telemetry", "show"),
                        ("stop checking for updates automatically", "updates off"), ("go back online", "local-only off"),
                        ("never use a cloud model", "cloud off"), ("privacy settings", "show")):
            self.assertEqual(P(q), want, q)
        for q in ("how do I make my instagram private", "can you make my instagram private",
                  "stop automatic updates on windows", "what is telemetry", "does my smart tv send data to the internet",
                  "is my private key safe", "how do I disable auto updates for apt", "what is a privacy policy"):
            self.assertEqual(P(q), "", q)
