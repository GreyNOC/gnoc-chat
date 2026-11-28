#!/usr/bin/env python3
"""Tests for the support modules gnoc chat imports on every turn. Stdlib unittest, temp dirs only, no network, no
model calls.

    python3 -W error::ResourceWarning scripts/test_gnoc_modules.py [-v]

Covers gnoc_secrets (redact / find / is_secret_path), gnoc_monitor (usage, the sub-agent registry, prune),
llm_endpoints (roles / split / resolve fallback), gnoc_goal (set / note / milestone / done round trip and gates),
gnoc_typeahead (feed on every control byte, cut-in, the reader's UTF-8 decoding), gnoc_learn (correction capture,
the book on malformed or unwritable disk), gnoc_modes, gnoc_dedup, gnoc_doctrine, gnoc_gates and gnoc_theme.
Every module's state PATH constants are pointed at a temp dir in setUp and restored in tearDown.
"""
import gc
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest
import warnings
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_dedup as D  # noqa: E402
import gnoc_doctrine as DOC  # noqa: E402
import gnoc_gates as GT  # noqa: E402
import gnoc_goal as GOAL  # noqa: E402
import gnoc_learn as L  # noqa: E402
import gnoc_modes as MODES  # noqa: E402
import gnoc_monitor as MON  # noqa: E402
import gnoc_secrets as S  # noqa: E402
import gnoc_theme as TH  # noqa: E402
import gnoc_typeahead as TA  # noqa: E402
import llm_endpoints as LE  # noqa: E402
import gnoc_hf as HF  # noqa: E402
import gnoc_oast as OAST  # noqa: E402
import gnoc_plan as PLAN  # noqa: E402
import gnoc_ws as WS  # noqa: E402

ROOT = os.geteuid() == 0  # chmod does not stop root, so the "not writable" cases are skipped there


def _readonly(path):
    os.chmod(path, stat.S_IRUSR | stat.S_IXUSR)


def _writable(path):
    os.chmod(path, stat.S_IRWXU)


class Tmp(unittest.TestCase):
    """A temp dir per test, with the module attributes a test redirects restored afterwards."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-modtest-")
        self._saved = []

    def redirect(self, mod, **attrs):
        for k, v in attrs.items():
            self._saved.append((mod, k, getattr(mod, k)))
            setattr(mod, k, v)

    def tearDown(self):
        for mod, k, v in reversed(self._saved):
            setattr(mod, k, v)
        for dp, dirs, _ in os.walk(self.tmp):
            for d in dirs:
                try:
                    _writable(os.path.join(dp, d))
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)


# ====================================================================== gnoc_secrets

AWS_ID = "AKIA" "IOSFODNN7EXAMPLE"
AWS_SECRET = "/wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # base64 secrets start with '/' one time in 64
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
H1_TOKEN = "Zk3pQ9vT2mXw8LrB5nYcH1dGa7sEu4Jo"
BEARER = "sk_live_" "51Hq8TwQbq7vZx2KpLm"
COOKIE_SID = "s%3Aab12cd34ef56gh78ij90"
COOKIE_CSRF = "c5f0a1e2d3b4c5d6e7f8"
HASH_TOKEN = "abc#defghijklmnop"
SECRETS_ENV = f"""# bb-hunt secrets
H1_API_TOKEN={H1_TOKEN}
H1_USER=greynoc-research
export AWS_ACCESS_KEY_ID="{AWS_ID}"
AWS_SECRET_ACCESS_KEY='{AWS_SECRET}'
VENDOR_AUTH_HEADER="Bearer {BEARER}"
TARGET_COOKIE="sid={COOKIE_SID}; csrftoken={COOKIE_CSRF}"
SESSION_JWT={JWT}   # the dashboard session
ODD_TOKEN={HASH_TOKEN}
CACHE_DIR=/tmp
DEBUG_TOKEN=true
"""


class Secrets(Tmp):
    def setUp(self):
        super().setUp()
        conf = os.path.join(self.tmp, "bb-hunt")
        os.makedirs(conf)
        with open(os.path.join(conf, "secrets.env"), "w") as f:
            f.write(SECRETS_ENV)
        self.redirect(S, CONF=conf, _cache={"sig": None, "vals": []}, _EXTRA={})
        # the test process's own sensitive env vars must not leak into (or out of) the store under test
        clean = {k: v for k, v in os.environ.items() if not S.SENSITIVE_NAME.search(k)}
        self._env = mock.patch.dict(os.environ, clean, clear=True)
        self._env.start()

    def tearDown(self):
        self._env.stop()
        super().tearDown()

    def test_each_credential_shape_is_redacted(self):
        text = (f"Authorization: Bearer {BEARER}\nX-Api: {H1_TOKEN}\nCookie: sid={COOKIE_SID}; csrftoken={COOKIE_CSRF}\n"
                f"aws {AWS_ID} {AWS_SECRET}\njwt={JWT}\nodd={HASH_TOKEN}\n")
        out = S.redact(text)
        for v in (BEARER, H1_TOKEN, COOKIE_SID, COOKIE_CSRF, AWS_ID, AWS_SECRET, JWT, HASH_TOKEN):
            self.assertNotIn(v, out, v)
        self.assertIn("[REDACTED:H1_API_TOKEN]", out)
        self.assertIn("[REDACTED:AWS_ACCESS_KEY_ID]", out)
        self.assertIn("Authorization: [REDACTED:VENDOR_AUTH_HEADER]", out)   # the stored header value, whole

    def test_one_cookie_of_a_stored_jar_is_caught_alone(self):
        self.assertNotIn(COOKIE_CSRF, S.redact(f"csrftoken={COOKIE_CSRF}"))
        self.assertIn("TARGET_COOKIE", S.find(f"X-CSRF: {COOKIE_CSRF}"))

    def test_bearer_token_without_its_scheme_is_caught(self):
        self.assertIn("VENDOR_AUTH_HEADER", S.find(f'{{"key": "{BEARER}"}}'))

    def test_hash_inside_token_is_part_of_it_comment_after_space_is_not(self):
        vals = dict((v, n) for n, v in S.values())
        self.assertEqual(vals.get(HASH_TOKEN), "ODD_TOKEN")
        self.assertEqual(vals.get(JWT), "SESSION_JWT")   # the trailing ' # comment' is not part of the value
        self.assertFalse(any("dashboard" in v for v in vals))

    def test_encoded_forms_are_caught(self):
        import base64
        import urllib.parse
        for form in (urllib.parse.quote(AWS_SECRET, safe=""), base64.b64encode(H1_TOKEN.encode()).decode(),
                     base64.b64encode(f"api:{H1_TOKEN}".encode()).decode()):
            self.assertTrue(S.find(f"x={form}"), form)
            self.assertNotIn(form, S.redact(f"x={form}"))

    def test_ordinary_text_urls_and_settings_survive(self):
        text = ("GET https://api.example.com/v1/users?page=2 HTTP/1.1 returned 200; the token endpoint is "
                "/oauth/token and the cache lives in /tmp. greynoc-research filed it. true\n")
        self.assertEqual(S.redact(text), text)
        self.assertEqual(S.find(text), [])
        names = {n for n, _ in S.values()}
        self.assertNotIn("H1_USER", names)       # not a sensitive name
        self.assertNotIn("CACHE_DIR", names)
        self.assertNotIn("DEBUG_TOKEN", names)   # 'true' is not a secret

    def test_existing_path_value_is_not_a_secret(self):
        with open(os.path.join(S.CONF, "secrets.env"), "a") as f:
            f.write(f"GOOGLE_APPLICATION_CREDENTIALS={self.tmp}/bb-hunt/secrets.env\n")
        S._cache["sig"] = None
        self.assertNotIn(f"{self.tmp}/bb-hunt/secrets.env", [v for _, v in S.values()])

    def test_never_raises_on_none_bytes_or_objects(self):
        self.assertIsNone(S.redact(None))
        self.assertEqual(S.redact(""), "")
        self.assertEqual(S.redact(b""), b"")
        self.assertEqual(S.find(None), [])
        self.assertEqual(S.find(b""), [])
        out = S.redact(f"tok={H1_TOKEN}\xff".encode("latin-1"))
        self.assertIsInstance(out, bytes)
        self.assertNotIn(H1_TOKEN.encode(), out)
        self.assertTrue(out.endswith(b"\xff"))   # an undecodable byte survives the round trip
        self.assertEqual(S.find(H1_TOKEN.encode()), ["H1_API_TOKEN"])
        self.assertEqual(S.redact(12345), "12345")
        self.assertIn("[REDACTED:H1_API_TOKEN]", S.redact({"t": H1_TOKEN}))

    def test_unicode_text_is_untouched_and_secret_still_found(self):
        text = f"résumé ✓ 日本語 {H1_TOKEN} ünïcode"
        self.assertEqual(S.redact(text), "résumé ✓ 日本語 [REDACTED:H1_API_TOKEN] ünïcode")

    def test_private_key_block_and_unterminated_begin(self):
        pk = "-----BEGIN RSA PRIVATE" " KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----"
        self.assertEqual(S.redact(f"a {pk} b"), "a [REDACTED:PRIVATE-KEY] b")
        self.assertEqual(S.redact("x -----BEGIN PRIVATE" " KEY-----\nAAAA"), "x [REDACTED:PRIVATE-KEY]")
        self.assertIn("PRIVATE-KEY", S.find(pk))
        t0 = time.time()
        S.redact("-----BEGIN PRIVATE" " KEY-----" * 2000)
        self.assertLess(time.time() - t0, 2.0)

    def test_store_change_is_picked_up_and_cache_reused(self):
        self.assertTrue(S.find(H1_TOKEN))
        first = S.values()
        self.assertIs(S.values(), first)   # unchanged store: cached
        p = os.path.join(S.CONF, "new.token")
        with open(p, "w") as f:
            f.write("Q8r3NewTokenValueZZZ9\n")
        self.assertEqual(S.find("x Q8r3NewTokenValueZZZ9"), ["new.token"])

    def test_malformed_json_store_and_unreadable_file_do_not_raise(self):
        with open(os.path.join(S.CONF, "broken.json"), "w") as f:
            f.write("{not json")
        with open(os.path.join(S.CONF, "session.json"), "w") as f:
            json.dump({"cookies": [{"name": "sid", "value": "j9Kq2Lw8Mx3Nv7Bc"}]}, f)
        S._cache["sig"] = None
        self.assertIn("session.json:value", S.find("j9Kq2Lw8Mx3Nv7Bc"))

    def test_extra_identity_values_redacted_but_not_reported(self):
        S.register_extra("ident:b", "IdentCookieValue77")
        self.assertIn("[REDACTED:ident:b]", S.redact("c=IdentCookieValue77"))
        self.assertEqual(S.find("c=IdentCookieValue77"), [])

    def test_is_secret_path(self):
        self.assertTrue(S.is_secret_path("~/.ssh/id_ed25519"))
        self.assertTrue(S.is_secret_path("/x/y/.env"))
        self.assertTrue(S.is_secret_path("/x/y/secrets.env"))
        self.assertFalse(S.is_secret_path(os.path.join(self.tmp, "notes.md")))
        self.assertFalse(S.is_secret_path(None))
        p = os.path.join(self.tmp, "blob.bin")
        with open(p, "w") as f:
            f.write("junk\n-----BEGIN OPENSSH PRIVATE" " KEY-----\n")
        self.assertTrue(S.is_secret_path(p))

    def test_shell_reads_secret(self):
        self.assertTrue(S.shell_reads_secret("cat ~/.config/gnoc/secrets.env"))
        self.assertTrue(S.shell_reads_secret("env | grep TOKEN"))
        self.assertTrue(S.shell_reads_secret("printenv"))
        self.assertFalse(S.shell_reads_secret("ls -la scripts"))
        self.assertFalse(S.shell_reads_secret(None))

    def test_repeated_concurrent_redaction_is_stable(self):
        text = f"Bearer {BEARER}"
        outs, errs = [], []

        def run():
            try:
                for _ in range(20):
                    outs.append(S.redact(text))
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(len(set(outs)), 1)


# ====================================================================== gnoc_monitor

class Monitor(Tmp):
    def setUp(self):
        super().setUp()
        self.redirect(MON, DIR=os.path.join(self.tmp, "subagents"), _mem={})
        MON.reset_turn()

    def tearDown(self):
        MON.unbind()
        MON.reset_turn()
        super().tearDown()

    def test_usage_accounting(self):
        MON.record("m", "local", 1500, 20, 1.5)
        MON.record("m", "local", None, "3", None)
        MON.tick(5)
        self.assertEqual(MON.live_tokens(), 5)
        s = MON.turn_summary()
        self.assertIn("m@local  2 calls  1.5k in / 23 out", s)
        s = MON.turn_summary(ctx_pct=42)
        self.assertIn("ctx 42%", s)
        self.assertEqual(MON.fmt_s(75), "1m15s")
        self.assertEqual(MON.fmt_n(999), "999")

    def test_session_usage_accumulates_across_turns_and_resets(self):
        MON.reset_session()
        MON.record("a", "local", 1000, 100, 2.0)
        MON.record("b", "desktop", 500, 50, 1.0)
        u = MON.session_usage()
        self.assertEqual(u["calls"], 2)
        self.assertEqual(u["in"], 1500)
        self.assertEqual(u["out"], 150)
        self.assertEqual([k for k, _ in u["models"]], ["a@local", "b@desktop"])  # sorted by out, most first
        self.assertEqual(u["models"][0][1]["secs"], 2.0)
        MON.reset_session()
        u = MON.session_usage()
        self.assertEqual(u["calls"], 0)
        self.assertEqual(u["models"], [])

    def test_start_append_finish_round_trip(self):
        sid = MON.start("worker:x", "qwen", "local", "probe the seam ✓")
        MON.bind(sid)
        MON.tick(3)
        MON.append(sid, "step one", step=True)
        r = MON.find(sid)
        self.assertEqual(r["status"], "running")
        self.assertEqual(r["tokens"], 3)
        MON.finish(sid, "done", "all good")
        r = MON.find(sid)
        self.assertEqual((r["status"], r["summary"], r["steps"]), ("done", "all good", 1))
        _, lines = MON.tail(sid)
        self.assertTrue(any("step one" in ln for ln in lines))
        self.assertEqual(MON.running(), [])

    def test_none_task_and_summary_do_not_raise(self):
        sid = MON.start("worker", task=None)
        MON.finish(sid, "failed", None)
        self.assertEqual(MON.find(sid)["status"], "failed")

    def test_ids_are_unique_for_back_to_back_external_starts(self):
        ids = [MON.start("claude:hunter", pid=os.getpid()) for _ in range(5)]
        self.assertEqual(len(set(ids)), 5)
        self.assertEqual(len([f for f in os.listdir(MON.DIR) if f.endswith(".json")]), 5)

    def test_load_all_skips_malformed_records(self):
        os.makedirs(MON.DIR)
        for name, body in (("a.json", "[1, 2]"), ("b.json", "{}"), ("c.json", "{oops"),
                           ("d.json", json.dumps({"id": "d", "status": "done"}))):
            with open(os.path.join(MON.DIR, name), "w") as f:
                f.write(body)
        rows = MON.load_all()
        self.assertEqual([r["id"] for r in rows], ["d"])
        self.assertEqual(MON.spinner_note(), "")

    def test_dead_pid_is_orphaned_and_external_dead_is_done(self):
        os.makedirs(MON.DIR)
        dead = 2 ** 22 + 12345
        for sid, ext in (("int-1", False), ("ext-1", True)):
            with open(os.path.join(MON.DIR, f"{sid}.json"), "w") as f:
                json.dump({"id": sid, "status": "running", "pid": dead, "external": ext, "started": "2026-10-22T00:00:00",
                           "log": os.path.join(MON.DIR, f"{sid}.log")}, f)
        st = {r["id"]: r["status"] for r in MON.load_all()}
        self.assertEqual(st, {"int-1": "orphaned", "ext-1": "done"})

    def test_prune_never_deletes_a_running_record(self):
        live = MON.start("worker", task="still working")
        done_ids = []
        for i in range(4):
            s = MON.start("worker", task=f"t{i}")
            MON.save_chat(s, [{"role": "user", "content": "hi"}])
            MON.finish(s, "done", "ok")
            done_ids.append(s)
        ext = MON.start("claude:x", pid=os.getpid())  # an external worker that is alive
        MON.prune(keep=0)
        left = {r["id"] for r in MON.load_all()}
        self.assertIn(live, left)
        self.assertIn(ext, left)
        self.assertFalse(left & set(done_ids))
        self.assertFalse([f for f in os.listdir(MON.DIR) if f.endswith(".chat")])   # transcripts go too
        self.assertTrue(os.path.exists(MON._path(live, "log")))

    def test_prune_skips_in_memory_record_even_if_disk_says_done(self):
        sid = MON.start("worker", task="x")
        rec = dict(MON._mem[sid], status="done")
        MON._write(rec)          # a stale or foreign writer marked it done on disk
        MON.prune(keep=0)
        self.assertTrue(os.path.exists(MON._path(sid, "json")))

    @unittest.skipIf(ROOT, "root ignores file modes")
    def test_unwritable_registry_never_raises(self):
        os.makedirs(MON.DIR)
        _readonly(MON.DIR)
        sid = MON.start("worker", task="x")
        MON.append(sid, "line", step=True)
        MON.save_chat(sid, [{"role": "user", "content": "x"}])
        MON.finish(sid, "done", "ok")
        self.assertEqual(MON.load_all(), [])

    def test_concurrent_writers_of_one_record(self):
        sid = MON.start("worker", task="x")
        errs = []

        def run():
            try:
                for i in range(30):
                    MON.append(sid, f"line {i}", step=True)
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(MON.find(sid)["steps"], 120)
        self.assertFalse([f for f in os.listdir(MON.DIR) if f.endswith(".tmp")])

    def test_save_chat_redacts_and_reads_back(self):
        sid = MON.start("worker", task="x")
        MON.save_chat(sid, [{"role": "assistant", "content": "ok", "tool_calls": [
            {"function": {"name": "http_request", "arguments": {"url": "https://a.example.com"}}}]}])
        rows = MON.chat(sid)
        self.assertEqual(rows[0]["calls"][0]["name"], "http_request")
        self.assertEqual(MON.chat("nope"), [])


# ====================================================================== llm_endpoints

class Endpoints(Tmp):
    def setUp(self):
        super().setUp()
        # HEALTH_FILE must be redirected too, or these tests read the MACHINE'S live state. up() chooses
        # its probe ladder from is_down(), which reads that file off disk: whenever the real desktop
        # happened to be benched, test_a_timeout_gets_one_patient_retry saw the cheap single 0.6 s
        # recovery sniff instead of the patient 2 s + 6 s ladder it asserts, and failed for a reason that
        # had nothing to do with the code under test. Measured 2026-10-27: that one test failed in two
        # full-suite runs and passed in three, purely with the bench flipping as the desktop came and
        # went. A flaky test is worse than a missing one now that a pre-commit gate runs the suite - a
        # gate that fails at random teaches people to pass SKIP_SUITE=1.
        self.redirect(LE, ROLES=os.path.join(self.tmp, "models.json"), _health={},
                      HEALTH_FILE=os.path.join(self.tmp, "llm-health.json"),
                      HOSTS={"local": "127.0.0.1:1", "desktop": "127.0.0.1:2"})
        self.probed = []

    def roles(self, d):
        with open(LE.ROLES, "w") as f:
            f.write(d if isinstance(d, str) else json.dumps(d))

    def fake_up(self, alive):
        def up(host):
            self.probed.append(host)
            return host in alive
        self.redirect(LE, up=up)

    def test_a_dead_host_is_not_laddered_twice_before_the_banner(self):
        """_host_up must not re-run up()'s patient 2 s + 6 s ladder on a failure.

        A black-holed tunnel (connect accepted, nothing answered) paid that ladder TWICE, which put 16.5 s of
        BLANK screen in front of the first banner byte and read as a hang (2026-10-27). up() already
        retries a timeout internally, so the second ask must be the cheap sniff.
        """
        import gnoc_agent
        calls = {"up": 0, "sniff": 0}

        def up(host):
            calls["up"] += 1
            return False

        def sniff(host, timeout=0.6):
            calls["sniff"] += 1
            return False

        self.redirect(LE, up=up, sniff=sniff, _health={})
        self.assertFalse(gnoc_agent._host_up("desktop"))
        self.assertEqual(calls["up"], 1, "up() ran its full ladder twice on one dead host")
        self.assertEqual(calls["sniff"], 1, "the cheap re-sniff never ran")

    def test_a_blipping_host_still_gets_its_second_chance(self):
        """The anti-flap intent survives: when the short sniff answers, up() is asked again properly."""
        import gnoc_agent
        seq, calls = [False, True], {"sniff": 0}

        def up(host):
            return seq.pop(0)

        def sniff(host, timeout=0.6):
            calls["sniff"] += 1
            return True

        self.redirect(LE, up=up, sniff=sniff, _health={})
        self.assertTrue(gnoc_agent._host_up("desktop"))
        self.assertEqual(calls["sniff"], 1)

    def test_split(self):
        self.assertEqual(LE.split("m@desktop"), ("m", "desktop"))
        self.assertEqual(LE.split("m@nowhere"), ("m@nowhere", "local"))
        self.assertEqual(LE.split(None), ("", "local"))
        self.assertEqual(LE.split(42), ("", "local"))

    def test_roles_missing_malformed_or_not_a_dict(self):
        self.assertEqual(LE.roles(), {})
        self.roles("{nope")
        self.assertEqual(LE.roles(), {})
        self.roles("[1, 2]")
        self.assertEqual(LE.roles(), {})
        self.assertEqual(LE.resolve("brain")[1:], (LE.DEFAULT, "local"))

    def test_desktop_up_is_used(self):
        self.roles({"brain": "big@desktop"})
        self.fake_up({"desktop"})
        self.assertEqual(LE.resolve("brain"), ("http://127.0.0.1:2/api/chat", "big", "desktop"))

    def test_desktop_down_falls_back_once_to_role_fallback(self):
        self.roles({"brain": "big@desktop", "brain_fallback": "small"})
        self.fake_up(set())
        self.assertEqual(LE.resolve("brain"), ("http://127.0.0.1:1/api/chat", "small", "local"))
        self.assertEqual(self.probed, ["desktop"])

    def test_fallback_on_the_failed_host_is_never_used(self):
        self.roles({"brain": "big@desktop", "brain_fallback": "other@desktop"})
        self.fake_up(set())
        url, name, host = LE.resolve("brain")
        self.assertEqual((name, host), (LE.DEFAULT, "local"))
        self.assertEqual(self.probed, ["desktop"])   # exactly one probe, the dead host is not retried

    def test_remote_default_on_dead_desktop_still_lands_local(self):
        self.roles({"brain": "big@desktop"})
        self.fake_up(set())
        self.assertEqual(LE.resolve("brain", default="mid@desktop")[1:], ("mid", "local"))

    def test_empty_model_name_and_non_string_entries(self):
        self.roles({"brain": "@desktop", "w": 7, "x": {"a": 1}})
        self.fake_up({"desktop"})
        self.assertEqual(LE.resolve("brain")[1:], (LE.DEFAULT, "desktop"))
        self.assertEqual(LE.resolve("w")[1:], (LE.DEFAULT, "local"))
        self.assertEqual(LE.resolve("x")[1:], (LE.DEFAULT, "local"))

    def test_up_is_cached_and_never_raises(self):
        calls = []

        def boom(*a, **k):
            calls.append(1)
            raise OSError("refused")
        with mock.patch.object(LE.urllib.request, "urlopen", boom):
            self.assertFalse(LE.up("desktop"))
            self.assertFalse(LE.up("desktop"))
            self.assertFalse(LE.up("no-such-host-key"))
        self.assertEqual(len(calls), 1)

    def test_stock_verdict_is_remembered_by_digest_across_processes(self):
        # the first /model of every process made ~76 HTTP calls (2026-10-22); a known digest now costs none
        d = tempfile.mkdtemp()
        saved = (LE.STOCK_DISK, dict(LE._stock_cache))
        try:
            LE.STOCK_DISK = os.path.join(d, "v.json")
            LE._stock_cache.clear()
            LE._remember_verdict("local", "plain:7b", "sha256:abc", True)

            def boom(*a, **k):
                raise AssertionError("no HTTP for a remembered digest")
            with mock.patch.object(LE, "_post", boom):
                self.assertTrue(LE.stock("plain:7b", "local", tags={"plain:7b": "sha256:abc"}))
            LE._stock_cache.clear()   # a different digest (new weights) is NOT taken from the cache
            with mock.patch.object(LE, "_post", side_effect=OSError("down")):
                self.assertIsNone(LE.stock("plain:7b", "local", tags={"plain:7b": "sha256:def"}))
        finally:
            LE.STOCK_DISK = saved[0]
            LE._stock_cache.clear()
            LE._stock_cache.update(saved[1])
            shutil.rmtree(d, ignore_errors=True)

    def test_a_timeout_gets_one_patient_retry(self):
        # one slow /api/version dropped the lead to the laptop for 30 s (2026-10-22); a refusal stays one try
        timeouts = []

        def slow(*a, **k):
            timeouts.append(k.get("timeout"))
            raise TimeoutError("timed out")
        LE._health.clear()
        with mock.patch.object(LE.urllib.request, "urlopen", slow):
            self.assertFalse(LE.up("desktop"))
        self.assertEqual(timeouts, [2, 6])
        LE._health.clear()

    def test_roles_does_not_leak_fd(self):
        self.roles({"brain": "x"})
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            for _ in range(50):
                LE.roles()
            gc.collect()


# ====================================================================== gnoc_goal

class Goal(Tmp):
    def setUp(self):
        super().setUp()
        self.redirect(GOAL, PATH=os.path.join(self.tmp, "orch", "goal.json"), RECEIPT_BASE=self.tmp)
        # receipt fixtures the existence gate resolves against the tmp repo root
        for rel in ("r", "targets/x/raw/2.json", "targets/gatewayco/raw/a.json", "reports/drafts/x/rce"):
            full = os.path.join(self.tmp, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write("receipt\n")
        os.makedirs(os.path.join(self.tmp, "reports/drafts/x"), exist_ok=True)

    def test_set_parses_crown_and_constraints_and_round_trips(self):
        d, err = GOAL.set_goal("achieve zero click   ato on gatewayco production", program="gatewayco")
        self.assertIsNone(err)
        self.assertEqual((d["crown"], sorted(d["constraints"])), ("ato", ["production", "zero-click"]))
        self.assertEqual(GOAL.load(), d)
        self.assertIn("STANDING GOAL", GOAL.block())
        self.assertIn("CONSTRAINT zero-click", GOAL.block())

    def test_too_short_goal_is_refused(self):
        d, err = GOAL.set_goal("ato")
        self.assertIsNone(d)
        self.assertTrue(err)
        self.assertEqual(GOAL.load(), {})

    def test_note_milestone_done_round_trip(self):
        GOAL.set_goal("achieve rce on the build runner", milestones=["hold file-write"])
        self.assertIn("refused", GOAL.note("cites a file that is not there", "targets/x/raw/1.json"))
        self.assertIn("1 notes", GOAL.note("mapped the upload route ✓"))
        self.assertTrue(GOAL.milestone("file-write", "done", "targets/x/raw/2.json").startswith("milestone done"))
        self.assertEqual(GOAL.load()["milestones"][0]["receipt"], "targets/x/raw/2.json")
        self.assertTrue(GOAL.done("reports/drafts/x/rce").startswith("goal ACHIEVED"))
        d = GOAL.load()
        self.assertEqual((d["status"], d["receipt"]), ("achieved", "reports/drafts/x/rce"))
        self.assertIn("not active", GOAL.note("late"))   # "the goal is achieved, not active"
        self.assertIn("already achieved", GOAL.done("again"))

    def test_done_refuses_without_receipt_and_with_open_milestones(self):
        GOAL.set_goal("achieve rce on the build runner", milestones=["hold file-write"])
        self.assertTrue(GOAL.done().startswith("refused"))
        self.assertTrue(GOAL.done("   ").startswith("refused"))
        self.assertIn("still open", GOAL.done("reports/drafts/x"))
        self.assertEqual(GOAL.load()["status"], "active")
        self.assertTrue(GOAL.done("", force=True).startswith("goal ACHIEVED"))

    def test_milestone_needs_receipt_and_valid_status(self):
        GOAL.set_goal("achieve rce on the build runner", milestones=["hold file-write"])
        self.assertTrue(GOAL.milestone("file-write", "done").startswith("refused"))
        self.assertTrue(GOAL.milestone("file-write", "done", "  ").startswith("refused"))
        self.assertTrue(GOAL.milestone("file-write", "skipped").startswith("refused"))
        self.assertTrue(GOAL.milestone("brand new", "done").startswith("refused"))
        self.assertIn("still open", GOAL.done("reports/drafts/x"))
        self.assertTrue(GOAL.milestone("", "done", "r").startswith("refused"))

    def test_acceptance_criteria_gate_a_general_goal(self):
        # a non-hunt goal: no crown, no constraints parsed, but an explicit definition of done
        d, err = GOAL.set_goal("refactor the plan module across many turns",
                               acceptance=["all tests pass", "no public API change"])
        self.assertIsNone(err)
        self.assertEqual([a["text"] for a in d["acceptance"]], ["all tests pass", "no public API change"])
        self.assertIn("Definition of done", GOAL.block())
        # done is refused while a criterion is open, even with a valid receipt and no milestones
        self.assertIn("acceptance criterion", GOAL.done("r"))
        self.assertEqual(GOAL.load()["status"], "active")
        # a criterion marked met needs a receipt that exists on disk
        self.assertTrue(GOAL.accept("all tests pass", "met").startswith("refused"))          # no receipt
        self.assertTrue(GOAL.accept("all tests pass", "met", "/nope/x").startswith("refused"))  # not on disk
        self.assertIn("criterion met", GOAL.accept("tests pass", "met", "r"))   # containment match resolves it
        self.assertEqual(GOAL.load()["acceptance"][0]["status"], "met")
        # still one criterion open, so done is still refused
        self.assertIn("acceptance criterion", GOAL.done("r"))
        self.assertIn("criterion met", GOAL.accept("no public API change", "met", "targets/x/raw/2.json"))
        self.assertTrue(GOAL.done("reports/drafts/x/rce").startswith("goal ACHIEVED"))

    def test_acceptance_add_open_then_force_and_malformed(self):
        GOAL.set_goal("migrate the build system")
        self.assertIn("No definition of done yet", GOAL.block())   # crownless, no ms/constraints -> prompts
        self.assertIn("criterion added (open)", GOAL.accept("ci is green", "open"))
        self.assertTrue(GOAL.accept("ci is green", "sideways").startswith("refused"))   # bad status
        self.assertTrue(GOAL.accept("", "open").startswith("refused"))                  # empty text
        self.assertIn("acceptance criterion", GOAL.done("r"))                           # open -> refused
        self.assertTrue(GOAL.done("r", force=True).startswith("goal ACHIEVED"))         # force overrides
        # a hand-edited file with a junk acceptance list must not break the block or the gate
        GOAL.set_goal("another task", acceptance=["x"])
        import json as _json
        with open(GOAL.PATH, "w") as fh:
            fh.write(_json.dumps({"text": "another task", "status": "active",
                                  "acceptance": ["ok", {"bad": 1}, 7, {"text": "y", "status": "nope"}]}))
        GOAL.block(); GOAL.status_text()
        kept = GOAL.load()["acceptance"]
        self.assertEqual([a["text"] for a in kept], ["ok", "y"])
        self.assertEqual(kept[1]["status"], "open")   # unknown status defaults to open (counts as unmet)

    def test_no_goal_paths(self):
        self.assertEqual(GOAL.note("x"), "no active goal")
        self.assertEqual(GOAL.accept("x", "met", "r"), "no active goal")
        self.assertEqual(GOAL.milestone("x", "done", "r"), "no active goal")
        self.assertEqual(GOAL.done("r"), "no goal set")
        self.assertEqual(GOAL.clear(), "no goal set")
        self.assertIn("NO STANDING GOAL", GOAL.block())
        self.assertIn("no goal set", GOAL.status_text())

    def test_malformed_files_never_break_block(self):
        os.makedirs(os.path.dirname(GOAL.PATH))
        bad = ["{nope", "[]", '"x"', "{}", json.dumps({"status": "active"}),
               json.dumps({"text": "achieve ato on gatewayco", "status": "active", "milestones": ["a", {"x": 1}, 5],
                           "log": ["s", {"text": "n"}], "constraints": ["zero-click", "bogus"]}),
               json.dumps({"text": "achieve ato", "status": "active", "milestones": {"a": 1}, "log": "x",
                           "created": None, "constraints": "zero-click"})]
        for body in bad:
            with open(GOAL.PATH, "w") as f:
                f.write(body)
            GOAL.block()
            GOAL.status_text()
            GOAL.done("r")
        with open(GOAL.PATH, "w") as f:
            f.write(bad[5])
        d = GOAL.load()
        self.assertEqual([m["text"] for m in d["milestones"]], ["a"])
        self.assertEqual(d["constraints"], ["zero-click"])
        self.assertIn("still open", GOAL.done("r"))   # a status-less milestone counts as OPEN, not closed

    def test_unicode_and_clear(self):
        GOAL.set_goal("achieve ato on gatewayco — über ✓")
        self.assertIn("über ✓", GOAL.block())
        self.assertTrue(GOAL.clear().startswith("goal cleared"))
        self.assertEqual(GOAL.load(), {})

    def test_log_is_capped(self):
        GOAL.set_goal("achieve ato on gatewayco")
        for i in range(60):
            GOAL.note(f"step {i}")
        log = GOAL.load()["log"]
        self.assertEqual(len(log), 40)
        self.assertEqual(log[-1]["text"], "step 59")
        self.assertLessEqual(len(GOAL.block(cap=500)), 500 + 30)

    def test_concurrent_notes_never_raise(self):
        GOAL.set_goal("achieve ato on gatewayco")
        errs = []

        def run():
            try:
                for i in range(15):
                    GOAL.note(f"n{i}")
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(GOAL.load()["text"], "achieve ato on gatewayco")

    @unittest.skipIf(ROOT, "root ignores file modes")
    def test_unwritable_goal_dir_reports_instead_of_raising(self):
        GOAL.set_goal("achieve ato on gatewayco")
        _readonly(os.path.dirname(GOAL.PATH))
        self.assertTrue(GOAL.note("x").startswith("NOT recorded"))
        self.assertTrue(GOAL.done("r").startswith("NOT recorded"))
        self.assertEqual(GOAL.load()["status"], "active")   # the refusal left the goal as it was
        _writable(os.path.dirname(GOAL.PATH))
        _readonly(os.path.dirname(GOAL.PATH))
        d, err = GOAL.set_goal("another goal entirely")
        self.assertIsNone(d)
        self.assertIn("could not be saved", err)

    def test_zero_click_written_as_0_click_is_a_constraint(self):
        d, err = GOAL.set_goal("hunt meta until we achieve an RCE or 0 click ato")
        self.assertIsNone(err)
        self.assertIn("zero-click", d["constraints"])

    def test_a_milestone_matches_whatever_verb_names_it(self):
        GOAL.set_goal("achieve ato on gatewayco", milestones=["prove oauth-code (unlocks ato)"])
        GOAL.milestone("hold oauth-code", "done", receipt="targets/gatewayco/raw/a.json")
        ms = GOAL.load()["milestones"]
        self.assertEqual(len(ms), 1)
        self.assertEqual(ms[0]["status"], "done")

    def test_seed_milestones(self):
        d, _ = GOAL.set_goal("achieve ato on gatewayco")
        GOAL.seed_milestones(d, ["oauth-code", "open-redirect"])
        self.assertEqual([m["text"] for m in GOAL.load()["milestones"]], ["hold oauth-code", "hold open-redirect"])
        GOAL.seed_milestones(GOAL.load(), ["other"])
        self.assertEqual(len(GOAL.load()["milestones"]), 2)


# ====================================================================== gnoc_typeahead

class TypeAhead(unittest.TestCase):
    def test_every_control_byte_and_more_never_raises(self):
        t = TA.TypeAhead()
        for i in range(256):
            t.feed(chr(i))
        for ch in ("", None, 5, b"x", "ab", "\x1b[A", "é", "日", "\U0001F600"):
            t.feed(ch)
        t.feed("\n")
        t.drain()
        self.assertEqual(t.buf, "")

    def test_staging_backspace_ctrl_u_ctrl_w(self):
        t = TA.TypeAhead()
        for ch in "hello wurld\x7f\x7f\x7f\x7forld\n":
            t.feed(ch)
        self.assertEqual(t.pop(), "hello world")
        for ch in "one two three\x17\x17":
            t.feed(ch)
        self.assertEqual(t.buf, "one")
        t.feed("\x15")
        self.assertEqual(t.buf, "")
        for ch in "   \r":
            t.feed(ch)
        self.assertEqual(t.pending(), 0)

    def test_arrow_sequences_are_swallowed_and_switch_on_empty_line(self):
        seen = []
        t = TA.TypeAhead(on_arrow=seen.append)
        for ch in "\x1b[B\x1bOA":
            t.feed(ch)
        self.assertEqual(seen, ["down", "up"])
        for ch in "ab\x1b[Ac\x1b[1;5D":
            t.feed(ch)
        self.assertEqual(t.buf, "abc")
        self.assertEqual(seen, ["down", "up"])

    def test_cut_in_and_a_raising_callback(self):
        cut = []
        t = TA.TypeAhead(on_cut_in=cut.append)
        for ch in "! stop now\n":
            t.feed(ch)
        self.assertEqual((cut, t.pop()), (["stop now"], "stop now"))
        t2 = TA.TypeAhead(on_cut_in=lambda x: 1 / 0, on_arrow=lambda x: 1 / 0)
        for ch in "!go\n\x1b[A":
            t2.feed(ch)
        self.assertEqual(t2.pop(), "go")
        t2.feed("!")
        t2.feed("\n")
        self.assertEqual(t2.pending(), 0)   # a bare '!' is nothing

    def test_hint(self):
        t = TA.TypeAhead()
        self.assertEqual(t.hint(), "")
        for ch in "x\nabcdefghijklmnopqrstuvwxyz":
            t.feed(ch)
        h = t.hint(30)
        self.assertTrue(h.startswith("1 staged"))
        self.assertIn("…", h)

    def test_ctrl_o_asks_the_harness_to_complete_the_path(self):
        t = TA.TypeAhead(on_ctrl_o=lambda buf: buf + "@x")
        for ch in "fix @sr":
            t.feed(ch)
        t.feed("\x0f")
        self.assertEqual(t.buf, "fix @sr@x")
        t2 = TA.TypeAhead(on_ctrl_o=lambda buf: 1 / 0)
        for ch in "ok\x0f!":
            t2.feed(ch)
        self.assertEqual(t2.buf, "ok!")   # a raising callback is not a dead reader

    def test_start_is_noop_without_a_tty(self):
        t = TA.TypeAhead()
        with mock.patch.object(sys, "stdin", mock.Mock(isatty=lambda: False)):
            self.assertFalse(t.start())
        self.assertEqual(t.stop(), "")

    def test_reader_survives_multibyte_utf8(self):
        r, w = os.pipe()
        try:
            t = TA.TypeAhead()
            t._fd, t._on = r, True
            os.write(w, "café ✓\nnext\n".encode())
            os.close(w)
            w = None
            t._run()   # returns at EOF; it used to return at the first byte of 'é'
            self.assertEqual(t.drain(), ["café ✓", "next"])
        finally:
            os.close(r)
            if w is not None:
                os.close(w)


# ====================================================================== gnoc_learn

class Learn(Tmp):
    def setUp(self):
        super().setUp()
        self._iso = L.isolated(os.path.join(self.tmp, "lessons"))
        self._iso.__enter__()

    def tearDown(self):
        self._iso.__exit__(None, None, None)
        super().tearDown()

    def test_ordinary_sentences_are_not_corrections(self):
        for t in ("Never mind, show me the scope file", "No problem, thanks", "No idea why this fails, can you look?",
                  "Don't know what this function does, explain it", "Always the same error when I run it?",
                  "Don't you think the gatewayco lane is dead?", "Nothing new on the board today", "Nobody filed it yet",
                  "Note the time and continue", "Now run the tests", "Instructions are in AGENTS.md",
                  "how do I stop the bot", "Is it wrong to file this one?", "noted, thanks", ""):
            self.assertIsNone(L.capture_correction(t), t)
        self.assertEqual(L.load(), [])

    def test_real_corrections_are_captured(self):
        for t in ("No, use curl_cffi for every target request", "Don't ask me before writing the draft",
                  "Stop asking for confirmation on dispatches", "Never put the handle in the User-Agent",
                  "I told you to keep replies short", "From now on read HANDOFF-CURRENT first",
                  "Don't do that, why did you delete the evidence?"):
            got = L.capture_correction(t)
            self.assertTrue(got and got[0], t)
        self.assertTrue(all(r["kind"] == "pref" for r in L.load()))

    def test_correction_on_unwritable_book_does_not_raise(self):
        if ROOT:
            self.skipTest("root ignores file modes")
        os.makedirs(L.DIR, exist_ok=True)
        _readonly(L.DIR)
        self.assertIsNone(L.capture_correction("Never put the handle in the User-Agent header"))

    def test_malformed_lines_never_break_recall(self):
        os.makedirs(L.DIR, exist_ok=True)
        with open(L.LIVE, "w") as f:
            f.write('"a string"\n[1]\n{"no": "id"}\n{"id": 5, "text": "x"}\n{bad json\n'
                    + json.dumps({"id": "L1", "kind": "rule", "text": "probe gatewayco admin twin first", "why": "x" * 20})
                    + "\n")
        self.assertEqual([r["id"] for r in L.load()], ["L1"])
        self.assertIn("L1", L.recall_block("gatewayco admin", "gatewayco"))
        self.assertEqual(L.add("a new technique about gatewayco admin routes", "it held twice in the receipts")[1], "added")
        self.assertTrue(L.reinforce("L1"))
        self.assertTrue(L.retire("L1", "test"))

    @unittest.skipIf(ROOT, "root ignores file modes")
    def test_recall_on_unwritable_book_still_returns(self):
        L.add("Always fire the serial control before the burst", "the user said so", "pref", "*", "greynoc")
        _readonly(L.DIR)
        self.assertTrue(L.recall("burst"))

    def test_add_dedups_and_redacts(self):
        a = L.add("Use curl_cffi chrome124 against akamai hosts", "plain curl 403'd on 5 probes")
        b = L.add("use curl_cffi chrome124 against akamai hosts!", "again")
        self.assertEqual((a[0], b[1]), (b[0], "reinforced"))
        self.assertEqual(L.add("short"), (None, "too short"))

    def test_unicode_lesson(self):
        lid, how = L.add("Le WAF rejette les requêtes avec é dans le chemin ✓", "observed on 3 probes today")
        self.assertEqual(how, "added")
        self.assertIn("é", L.load()[0]["text"])


# ====================================================================== gnoc_modes

class Modes(Tmp):
    def test_detect_and_block(self):
        self.assertEqual(MODES.detect("please review this diff"), "review")
        self.assertEqual(MODES.detect("refactor the parser"), "swe")
        self.assertIsNone(MODES.detect(None))
        self.assertEqual(MODES.block(None), "")
        self.assertEqual(MODES.block(["x"]), "")
        self.assertTrue(MODES.block("swe").startswith("MODE: SOFTWARE"))

    def test_leaving_hunt_allows_a_qualifier(self):
        # "please stop all hunting" is how GreyNOC actually says it. It set the STOP flag and left the chat's
        # hunt stance on, so the greeting after it ran with the hunt prompt and hunt tools (2026-11-17).
        for t in ("stop hunting", "stop the hunt", "please stop all hunting", "stop all hunting",
                  "done with the hunt", "pause hunting", "end the hunt now"):
            self.assertTrue(MODES.leaves_hunt(t), t)
        for t in ("keep hunting", "hunt gatewayco", "resume the hunt", "stop", "stop the fleet"):
            self.assertFalse(MODES.leaves_hunt(t), t)
        self.assertTrue(MODES.wants_hunt("keep hunting"))
        self.assertFalse(MODES.wants_hunt("stop all hunting"))

    def test_design_mode_detects_and_has_a_loop(self):
        self.assertEqual(MODES.detect("redesign the landing page"), "design")
        self.assertEqual(MODES.detect("fix the css and layout on the homepage"), "design")
        self.assertEqual(MODES.detect("make the site prettier"), "design")
        self.assertEqual(MODES.detect("responsive mobile view for the settings page"), "design")
        self.assertTrue(MODES.block("design").startswith("MODE: WEBSITE DESIGN"))
        self.assertIn("team(", MODES.block("swe"), "the swe loop must name the team tool for big work")

    def test_env_of(self):
        self.assertEqual(MODES.env_of("https://api.staging.kong.com/x"), ("nonprod", "staging"))
        self.assertEqual(MODES.env_of("developer.acmehq.com"), ("prod", ""))
        self.assertEqual(MODES.env_of(None), ("prod", ""))
        self.assertEqual(MODES.env_of("http://[::1"), ("prod", ""))

    def test_check_verdict_and_normalize(self):
        self.assertEqual(MODES.check_verdict(1, "AssertionError: FAIL")[0], "confirmed")
        self.assertEqual(MODES.check_verdict(127, "")[0], "not-run")
        self.assertEqual(MODES.check_verdict(1, "ModuleNotFoundError: x")[0], "not-run")
        self.assertEqual(MODES.check_verdict(0, None)[0], "clean")
        self.assertTrue(MODES.normalize_check("assert f(1)==2", ("m",)).startswith("python3 -c 'from m import *"))
        self.assertEqual(MODES.normalize_check("pytest -q"), "pytest -q")

    def test_verify_findings_no_fd_leak_and_missing_fields(self):
        p = os.path.join(self.tmp, "mod.py")
        with open(p, "w") as f:
            f.write("def f(x):\n    return x + 1  # off by one\n")
        rows = [{"file": "mod.py", "line": 2, "snippet": "return x + 1", "confidence": "4"},
                {"file": "../etc/passwd", "line": 1, "snippet": "root:x"},
                {"file": "mod.py", "line": 99, "snippet": "return x + 1"},
                {"file": "mod.py", "line": 2, "snippet": "invented text"}, "junk"]
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            kept, dropped = MODES.verify_findings(self.tmp, rows, lambda c: (1, "AssertionError"))
            gc.collect()
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(dropped), 3)
        txt = MODES.review_text(kept, dropped, "mod.py")
        self.assertIn("(no claim given)", txt)

    def test_prod_leg(self):
        chain = [{"id": "E1", "status": "proven", "evidence": "a"}]
        ok, _ = MODES.prod_leg(chain, lambda p: ({"request": {"url": "https://uat.x.com/"}}, ""))
        self.assertFalse(ok)
        ok, _ = MODES.prod_leg(chain, lambda p: ({"request": {"url": "https://x.com/"}}, ""))
        self.assertTrue(ok)

    def test_env_of_sees_numbered_and_hyphenated_env_labels(self):
        # 2026-11-04: the bare-token regex read uat1/stg2 as production, so a UAT receipt ticked RULE 6.
        D = "target." + "com"
        for sub in ("uat1.", "stg2.", "uat.", "staging.", "qa1.", "dev2.", "stage3.", "preprod.", "demo.",
                    "sandbox-prod.", "beta.", "canary.", "preview."):
            self.assertEqual(MODES.env_of(f"https://{sub}{D}/")[0], "nonprod", sub)
        self.assertEqual(MODES.env_of(f"https://{D}.staging-mirror.net/")[0], "nonprod", "glued label across the dot")
        # the path is not the host: a production host serving a /staging/admin route stays production
        self.assertEqual(MODES.env_of(f"https://{D}/staging/panel")[0], "prod")
        self.assertEqual(MODES.env_of(f"https://www.{D}/")[0], "prod")

    def test_prod_leg_refuses_a_capture_with_no_readable_host(self):
        # a capture whose request carries no URL used to fall through env_of("") -> prod and satisfy RULE 6
        chain = [{"id": "E1", "status": "proven", "evidence": "a"}]
        for j in ({"request": {"url": ""}}, {"request": {}}, {"request": None}):
            ok, note = MODES.prod_leg(chain, lambda p, j=j: (j, ""))
            self.assertFalse(ok, j)
            self.assertIn("no readable request", note)
        ok, note = MODES.prod_leg(chain, lambda p: (None, ""))
        self.assertTrue(ok, "a receipt that will not parse is not a prod claim either way")


# ====================================================================== gnoc_plan

class Plan(Tmp):
    def setUp(self):
        super().setUp()
        self.redirect(PLAN, PLAN_DIR=os.path.join(self.tmp, "plans"))
        self.good = {"goal": "make the website load faster for everyone",
                     "steps": [{"action": "compress the hero images", "verify": "lighthouse LCP under 2s", "why": "images are the LCP"},
                               {"action": "lazy-load below-the-fold media", "verify": "network panel shows deferred loads"}],
                     "risks": "regression in gallery", "not_doing": "framework rewrite"}

    def test_validate_normalize_and_progress(self):
        ok, err = PLAN.validate(self.good)
        self.assertTrue(ok, err)
        self.assertFalse(PLAN.validate({"goal": "short"})[0])
        self.assertFalse(PLAN.validate({"goal": "a real goal here", "steps": []})[0])
        self.assertFalse(PLAN.validate({"goal": "a real goal here", "steps": [{"action": "x"}]})[0],
                         "an action of one char is not a step")
        self.assertFalse(PLAN.validate({"goal": "a real goal here",
                                         "steps": [{"action": "do it", "status": "wat"}]})[0])
        self.assertFalse(PLAN.validate({"goal": "a real goal here",
                                         "steps": [{"action": f"step {i}"} for i in range(9)]})[0],
                         "more than 8 steps is a task list, not a plan")
        p = PLAN.normalize(self.good)
        self.assertEqual(p["steps"][0]["status"], "pending")
        d, n = PLAN.progress(p)
        self.assertEqual((d, n), (0, 2))

    def test_save_load_one_line_next_block(self):
        p = PLAN.normalize(self.good)
        PLAN.save("sid-1", p)
        self.assertEqual(PLAN.load("sid-1")["goal"], p["goal"])
        self.assertIsNone(PLAN.load("nope"))
        self.assertIn("▣ 0/2", PLAN.one_line(p))
        i, s = PLAN.next_step(p)
        self.assertEqual((i, s["action"]), (1, "compress the hero images"))
        p["steps"][0]["status"] = "done"
        PLAN.save("sid-1", p)
        i, s = PLAN.next_step(PLAN.load("sid-1"))
        self.assertEqual(i, 2)
        b = PLAN.block(p)
        self.assertIn("ACTIVE PLAN (1/2 steps done)", b)
        self.assertIn("NEXT: step 2", b)
        self.assertIn("lazy-load below-the-fold media", b)

    def test_panel_and_tasks_rows(self):
        p = PLAN.normalize(self.good)
        text = PLAN.panel(p)
        self.assertIn("PLAN 0/2 steps", text)
        self.assertIn("compress the hero images", text)
        self.assertIn("verify: lighthouse LCP under 2s", text)
        self.assertIn("NOT", text)
        rows = PLAN.tasks_rows(p)
        self.assertEqual(rows[0], ("plan: compress the hero images", "plan"))

    def test_clear(self):
        PLAN.save("sid-2", PLAN.normalize(self.good))
        PLAN.clear("sid-2")
        self.assertIsNone(PLAN.load("sid-2"))


# ====================================================================== gnoc_ws

class Workspace(Tmp):
    """gnoc_ws: the Claude-Code-strong workspace setup - sniff, first_open, GNOC.md + gchat.md init (never
    overwriting a repo's own instructions), and new-project scaffolding."""

    def _tree(self, files):
        for name in files:
            with open(os.path.join(self.tmp, name), "w") as fh:
                fh.write("# hello\n\nA sample project.\n")

    def test_sniff_node_and_python(self):
        self._tree(["package.json"])
        with open(os.path.join(self.tmp, "package.json"), "w") as fh:
            fh.write('{"scripts": {"start": "node i.js", "build": "vite build", "test": "node --test", "lint": "eslint ."}}')
        s = WS.sniff(self.tmp)
        self.assertEqual((s["stack"], s["run"], s["build"], s["test"], s["lint"]),
                         ("node", "node i.js", "vite build", "node --test", "eslint ."))
        os.remove(os.path.join(self.tmp, "package.json"))
        self._tree(["pyproject.toml"])
        s = WS.sniff(self.tmp)
        self.assertEqual(s["stack"], "python")
        self.assertIn("pytest", s["test"])

    def test_first_open_then_init_writes_and_respects_instructions(self):
        self._tree(["package.json", "README.md"])
        with open(os.path.join(self.tmp, "package.json"), "w") as fh:
            fh.write('{"scripts": {"test": "node --test"}}')
        self.assertTrue(WS.first_open(self.tmp))
        lines = WS.init_workspace(self.tmp, program="prog", task="wire it")
        self.assertFalse(WS.first_open(self.tmp))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "GNOC.md")))
        self.assertTrue(os.path.isfile(os.path.join(self.tmp, "gchat.md")))
        self.assertEqual(len(lines), 2)
        with open(os.path.join(self.tmp, "GNOC.md")) as fh:
            text = fh.read()
        self.assertIn("node --test", text)
        self.assertIn("Rules", text)
        with open(os.path.join(self.tmp, "CLAUDE.md"), "w") as fh:
            fh.write("do not touch\n")
        os.remove(os.path.join(self.tmp, "GNOC.md"))
        lines = WS.init_workspace(self.tmp)
        self.assertTrue(any("kept CLAUDE.md" in l for l in lines))
        with open(os.path.join(self.tmp, "CLAUDE.md")) as fh:
            self.assertEqual(fh.read().strip(), "do not touch", "a repo's own instructions are never overwritten")
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "GNOC.md")),
                         "CLAUDE.md already exists: no GNOC.md is written beside it")

    def test_scaffold_new_project(self):
        path, lines = WS.scaffold_project(self.tmp, "cool-web", "web")
        self.assertTrue(path and os.path.isdir(path))
        self.assertTrue(any("created" in l for l in lines))
        for f in ("README.md", ".gitignore", "index.html", "GNOC.md", "gchat.md"):
            self.assertTrue(os.path.isfile(os.path.join(path, f)), f)
        self.assertTrue(os.path.isdir(os.path.join(path, ".git")), "git init ran")
        self.assertEqual(WS.sniff(path)["stack"], "web")
        p2, lines2 = WS.scaffold_project(self.tmp, "cool-web", "web")
        self.assertIsNone(p2)
        self.assertTrue(any("already exists" in l for l in lines2))
        bad = WS.scaffold_project(self.tmp, "x", "fortran")
        self.assertIsNone(bad[0])
        self.assertTrue(any("node, python or web" in l for l in bad[1]))


# ====================================================================== gnoc_dedup

class Dedup(Tmp):
    def setUp(self):
        super().setUp()
        self.redirect(D, WS=self.tmp)
        rep = os.path.join(self.tmp, "reports", "submitted", "gatewayco", "idor-x")
        os.makedirs(rep)
        with open(os.path.join(rep, "report.md"), "w") as f:
            f.write("# IDOR on api.kong.com orders\nbody api.kong.com /orders\n")
        os.makedirs(os.path.join(self.tmp, ".claude/state/hunt-loop"))
        with open(os.path.join(self.tmp, ".claude/state/hunt-loop/outcomes.jsonl"), "w") as f:
            f.write('["gatewayco"]\n"gatewayco"\n{bad "gatewayco"\n' + json.dumps({"target": "gatewayco", "vector": "api.kong.com orders",
                                                                    "verdict": "DEAD", "ts": None}) + "\n")
        os.makedirs(os.path.join(self.tmp, "targets/gatewayco/hunts/gnoc"))
        with open(os.path.join(self.tmp, "targets/gatewayco/hunts/gnoc/ledger.json"), "w") as f:
            json.dump({"hypotheses": ["str", {"title": "api.kong.com orders idor", "status": "open"}]}, f)

    def test_check_finds_each_source_and_survives_malformed_rows(self):
        n, text = D.check("gatewayco", "api.kong.com orders")
        self.assertEqual(n, 3)
        self.assertIn("FILED, never refile", text)
        self.assertIn("RECORDED VERDICTS", text)
        self.assertIn("? [open]", text)

    def test_bad_terms_and_program(self):
        self.assertEqual(D.check("gatewayco", None)[0], 0)
        self.assertEqual(D.check("gatewayco", ["ab", None, 3])[0], 0)
        self.assertEqual(D.check("", "x.com")[0], 0)
        self.assertEqual(D.check("../..", "etc passwd")[0], 0)
        self.assertIn("not a program handle", D.program_summary("../x"))

    def test_ledger_not_a_dict(self):
        with open(os.path.join(self.tmp, "targets/gatewayco/hunts/gnoc/ledger.json"), "w") as f:
            f.write("[1, 2]")
        self.assertEqual(D.ledger("gatewayco", ["orders"]), [])

    def test_program_summary(self):
        s = D.program_summary("gatewayco")
        self.assertIn("1 submitted", s)
        self.assertIn("FILED (never refile): IDOR on api.kong.com orders", s)
        self.assertIn("no reports", D.program_summary("nothing-here"))


# ====================================================================== gnoc_doctrine

class Doctrine(Tmp):
    def setUp(self):
        super().setUp()
        doc = os.path.join(self.tmp, "DOCTRINE.md")
        with open(doc, "w") as f:
            f.write("## A. hypo\n\nA1. Model what the developer trusted about the redirect.\n\n"
                    "## EV-RANKED OPENER\nstart with the seam\n\n### M1. a move\n\nI1. paid win on oauth redirect.\n")
        idx = os.path.join(self.tmp, "INDEX.md")
        with open(idx, "w") as f:
            f.write("| id | class | sev | bounty | triggers | fp |\n|--|\n"
                    "| oauth-redirect-x | oauth | high | 1k | redirect_uri oauth | callback |\n")
        man = os.path.join(self.tmp, "M.md")
        with open(man, "w") as f:
            f.write("## T-215 premise\n**Rule.** price the premise.\n**Why.** kills.\n")
        self.redirect(DOC, DOCTRINE=doc, INDEX=idx, MANUALS=[man], WS=self.tmp, _doc_cache={}, _idx_cache=[])

    def test_retrieval_without_fd_leaks(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            self.assertIn("A1", dict(DOC.moves("A", "redirect")))
            self.assertIn("start with the seam", DOC.opener())
            self.assertEqual(DOC.cards("oauth redirect_uri")[0][0], "oauth-redirect-x")
            self.assertIn("Rule: price the premise.", DOC.manual("T-215"))
            self.assertIn("no Manual entry", DOC.manual("zzz"))
            self.assertIn("PATTERN CARDS", DOC.pack("hypothesize", "oauth redirect"))
            gc.collect()

    def test_card_rejects_paths_and_globs(self):
        for cid in ("../../etc/passwd", "*", "", None, "a/b"):
            self.assertTrue(DOC.card(cid).startswith("no card"), cid)

    def test_pure_functions(self):
        self.assertEqual(DOC.canon("SSRF to metadata"), "internal-reach")
        self.assertEqual(DOC.canon(None), "")
        self.assertTrue(DOC.next_hops("open redirect")[1])
        self.assertIn("CONCRETE NEXT HOPS", DOC.escalation_plan("ssrf"))
        self.assertTrue(DOC.kill_match("the host resolves to a private IP 10.0.0.1"))
        self.assertEqual(DOC.kill_match(None), [])
        ok, _ = DOC.premise_gate("unauth", ["victim session"], "ato")
        self.assertFalse(ok)
        self.assertIn("LEAVES TO PROVE", DOC.attack_tree("ato"))
        self.assertTrue(DOC.cwe_for("", "rce").startswith("CWE-94"))

    def test_fingerprint_tolerates_odd_captures(self):
        DOC.fingerprint([{"response": {"headers": ["x"], "body": b"y"}}, {"request": "s", "response": None}, None, 5])


# ====================================================================== gnoc_gates

REPORT = """CVSS: 8.1 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
Asset: api.example.com
CWE: CWE-639

# IDOR on orders lets any user read another user's order

## Summary
I read account B's order with account A's session.

## PoC
```
curl -s https://api.example.com/orders/2 -H 'Authorization: Bearer A'
{"id": 2, "owner": "account-b", "total": 10}
```

## Impact
Any user reads any order, including address and phone of the buyer.
"""


class Gates(Tmp):
    def test_format_checks_pass_and_fail(self):
        bad = [r for r in GT.format_checks(REPORT) if not r[0]]
        self.assertEqual(bad, [])
        broken = REPORT.replace("## Impact", "## Effect") + "\nIt could — maybe."
        names = {r[1] for r in GT.format_checks(broken) if not r[0]}
        self.assertIn("section Impact", names)
        self.assertIn("no em dash", names)
        GT.format_checks(None)

    def test_write_format_gate_no_fd_leak(self):
        d = os.path.join(self.tmp, "draft")
        os.makedirs(os.path.join(d, "evidence"))
        with open(os.path.join(d, "report.md"), "w") as f:
            f.write(REPORT)
        with open(os.path.join(d, "evidence", "cap.json"), "w") as f:
            json.dump({"request": {"url": "https://api.example.com/orders/2"},
                       "response": {"body": '{"id": 2, "owner": "account-b", "total": 10}'}}, f)
        os.symlink(os.path.join(d, "missing"), os.path.join(d, "evidence", "dangling.txt"))
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            verdict, nbad = GT.write_format_gate(d, "zz-no-such-program-test")
            gc.collect()
        self.assertEqual(verdict, "FIXABLE")   # no Burp panels and no GATES.md
        with open(os.path.join(d, "GATE-local-format.md")) as f:
            text = f.read()
        self.assertIn("[x] quoted bytes found in a capture on disk", text)
        self.assertIn("[ ] raw Burp request+response panels attached", text)


# ====================================================================== gnoc_theme

class Theme(unittest.TestCase):
    def test_plain_mode_passes_text_through(self):
        with mock.patch.object(TH, "TTY", False):
            self.assertEqual(TH.red("x"), "x")
            self.assertEqual(TH.render_markdown("# t\n**b** é\n"), "# t\n**b** é\n")
            self.assertEqual(TH.prompt("a"), "> ")

    def test_tty_rendering_never_raises(self):
        text = ("# h\n- [x] done\n- [ ] todo\n- b\n1. one\n> q\n| a | b |\n|---|---|\n---\n"
                "```python\ndef f():\n    return 1\n```\n```nolang\nx\n```\n```\nunclosed")
        with mock.patch.object(TH, "TTY", True):
            out = []
            md = TH.MarkdownStream(out.append)
            for i in range(0, len(text), 3):
                md.feed(text[i:i + 3])
            md.close()
            self.assertIn("☑", "".join(out))
            TH.diff_line("  12 - removed")
            TH.diff_line("garbage")
        self.assertEqual(TH.vis_len("\x1b[91m日本\x1b[0m"), 4)

    def test_code_blocks(self):
        self.assertEqual(TH.code_blocks("a\n```py\nx=1\n```\nb\n```sh\nls"), [("py", "x=1"), ("sh", "ls")])
        self.assertEqual(TH.code_blocks(None), [])


class GroundedLearning(unittest.TestCase):
    """Recursive learning grounded in OUTCOMES (2026-10-22). The live book's most-reinforced lesson was
    "qaqc functional battery ran", reinforced 27 times: lessons were reinforced because they RECURRED,
    not because following them WORKED."""

    def setUp(self):
        import gnoc_learn
        self.L = gnoc_learn
        self.iso = gnoc_learn.isolated()
        self.iso.__enter__()

    def tearDown(self):
        self.iso.__exit__(None, None, None)

    WORKED = [{"role": "tool", "content": "     1  # SPINE"},
              {"role": "tool", "content": "HTTP 200 len=812 raw=targets/x/raw/1.json"}]
    FAILED = [{"role": "tool", "content": "refused: outside the repo"},
              {"role": "tool", "content": "bad arguments: edit_file needs old"}]

    def test_status_and_log_lines_are_not_lessons(self):
        for junk in ("qaqc functional battery ran", "The Burp MCP is operational", "the probe failed"):
            self.assertFalse(self.L.worth_keeping(junk, "evidence in raw/x.json", "rule", "reflection")[0], junk)

    def test_a_conditional_fact_is_kept(self):
        self.assertTrue(self.L.worth_keeping("the WAF is operational on /api but not on /v1",
                                             "evidence in raw/x.json", "fact", "reflection")[0])

    def test_outcome_is_measured_from_tool_results(self):
        self.assertTrue(self.L.turn_outcome(self.WORKED)["good"])
        self.assertFalse(self.L.turn_outcome(self.FAILED)["good"])
        self.assertIsNone(self.L.turn_outcome([{"role": "user", "content": "hi"}])["good"],
                          "a turn with no tool results has no measured outcome")

    def test_a_recorded_verdict_counts_as_a_good_outcome(self):
        msgs = [{"role": "assistant", "tool_calls": [{"function": {"name": "record_outcome",
                                                                   "arguments": '{"verdict": "LEAD"}'}}]}] + self.FAILED
        self.assertTrue(self.L.turn_outcome(msgs)["good"])

    def _new(self, text="Burp proxy history is the source for path-shape panels, never Repeater"):
        self.L.add(text, "Repeater normalises paths, measured", "rule", "*", "reflection")
        return self.L.load()[-1]["id"]

    def _r(self, lid):
        return next(r for r in self.L.load() if r["id"] == lid)

    def test_a_worked_turn_reinforces(self):
        lid = self._new()
        n = self.L.apply_ops({"reinforce": [lid]}, None, {lid}, outcome=self.L.turn_outcome(self.WORKED))
        self.assertEqual(n["reinforced"], 1)

    def test_a_failed_turn_cannot_reinforce_and_weakens_what_it_was_given(self):
        lid = self._new()
        self.L.apply_ops({"reinforce": [lid]}, None, {lid}, outcome=self.L.turn_outcome(self.WORKED))
        before = self._r(lid).get("reinforced", 0)
        n = self.L.apply_ops({"reinforce": [lid]}, None, {lid}, outcome=self.L.turn_outcome(self.FAILED))
        self.assertEqual(n["reinforced"], 0, "a measured failure must not reinforce")
        self.assertEqual(n["weakened"], 1)
        self.assertEqual(self._r(lid)["reinforced"], before - 1)

    def test_no_outcome_keeps_the_old_behaviour(self):
        lid = self._new()
        self.assertEqual(self.L.apply_ops({"reinforce": [lid]}, None, {lid}, outcome=None)["reinforced"], 1)

    def test_greynocs_corrections_are_never_weakened(self):
        self.L.add("Never edit captured bytes", "their rule", "pref", "*", "greynoc")
        gid = [r for r in self.L.load() if r.get("source") == "greynoc"][0]["id"]
        self.L.apply_ops({}, None, {gid}, outcome=self.L.turn_outcome(self.FAILED))
        self.assertFalse(self._r(gid).get("weakened"))

    def test_the_reflecting_model_is_shown_the_measured_outcome(self):
        txt = self.L.outcome_text(self.L.turn_outcome(self.FAILED))
        self.assertIn("measured by code", txt)
        self.assertIn("FAILED", txt)
        self.assertIn("Do NOT reinforce", txt)


class LearningV2(unittest.TestCase):
    """Learning v2 (2026-10-22): a replayed real turn showed the reflector cut off mid-JSON, ungrounded lessons
    ("adjust snippet to make it unique") passing the gate, and 894 measured hunt verdicts never recalled."""

    TURN = [{"role": "user", "content": "always read the artifact before re-firing a lane on neon"},
            {"role": "assistant", "content": "", "tool_calls": [{"function": {"name": "http_request",
                                                                              "arguments": {"url": "x"}}}]},
            {"role": "tool", "content": "HTTP 401 len=40 console.initech.tech/api/v2/projects"}]

    def setUp(self):
        import gnoc_learn
        self.L = gnoc_learn
        self.iso = gnoc_learn.isolated()
        self.d = self.iso.__enter__()

    def tearDown(self):
        self.iso.__exit__(None, None, None)

    def _add(self, text, kind="fact"):
        return self.L.apply_ops({"add": [{"kind": kind, "text": text, "why": "the tool result shows HTTP 401"}]},
                                "program-65", (), outcome=self.L.turn_outcome(self.TURN), turn=self.TURN)

    def test_a_lesson_anchored_in_the_turn_is_kept(self):
        self.assertEqual(self._add("console.initech.tech /api/v2/projects answers 401 without a Bearer")["added"], 1)

    def test_generic_advice_with_no_anchor_is_refused(self):
        n = self._add("adjust the snippet to make it unique", "rule")
        self.assertEqual((n["added"], n["rejected"]), (0, 1))
        self.assertIn("generic advice", self.L.LAST_REJECTS[0])

    def test_an_anchor_that_is_not_in_the_turn_is_refused(self):
        self.assertEqual(self._add("api.vercel.com /v9/projects leaks env values")["rejected"], 1)

    def test_a_pref_comes_only_from_greynocs_own_correction(self):
        # a reflection can no longer create a pref, even in his words: the check counted harness-injected
        # user messages as his and let an invented pref in (audit 2026-10-22)
        self.assertEqual(self._add("prefer short replies with tables", "pref")["rejected"], 1)
        self.assertEqual(self._add("always read the artifact before re-firing a lane", "pref")["rejected"], 1)
        self.assertEqual(self.L.capture_correction("always read the artifact before re-firing a lane")[1], "added")

    def test_a_revision_is_grounded_too(self):
        self._add("console.initech.tech /api/v2/projects answers 401 without a Bearer")
        lid = self.L.load()[-1]["id"]
        n = self.L.apply_ops({"revise": [{"id": lid, "text": "Adjusted snippet for uniqueness in the file"}]},
                             "program-65", {lid}, turn=self.TURN)
        self.assertEqual(n["revised"], 0)

    def test_narration_and_bare_absence_are_not_lessons(self):
        for junk in ("ledger.jsonl updated with unique entry for 2026-10-22T16:27:00Z",
                     "The path targets/x/ledger.jsonl was successfully created with a single entry",
                     "The GET request to /api was successful with status 200",
                     "No identity 'A' found for some-program"):
            self.assertFalse(self.L.worth_keeping(junk, "the tool result shows it", "fact", "reflection")[0], junk)
        self.assertTrue(self.L.worth_keeping("no /graphql route on api.x after 40 probes", "probes in raw/",
                                             "fact", "reflection")[0], "an absence with its count is a negative")

    def _outcomes(self, *rows):
        import json
        with open(self.L.OUTCOMES, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

    def test_the_measured_hunt_history_is_recalled_for_its_program_only(self):
        self._outcomes(
            {"ts": "2026-10-11T00:00:00Z", "target": "program-65", "vector": "KC ROPC on public client",
             "verdict": "LEAD", "probes": 118, "capability": "ROPC enabled"},
            {"ts": "2026-10-22T00:00:00Z", "target": "program-65", "vector": "KC ROPC on public client",
             "verdict": "NEEDS", "probes": 195, "burst": True, "capability": "none new", "artifact": "t/n/R.md"},
            {"ts": "2026-10-22T00:00:00Z", "target": "globex", "vector": "firewall dot-segment", "verdict": "LEAD"})
        self.assertEqual(self.L.rebuild_ground(force=True), 2, "one row per (program, vector)")
        txt = self.L.recall_block("keycloak ROPC", "program-65")
        self.assertIn("MEASURED HUNT HISTORY for program-65", txt)
        self.assertIn("NEEDS", txt, "the newest verdict wins")
        self.assertIn("195 probes, burst", txt)
        self.assertNotIn("dot-segment", txt)
        self.assertEqual(self.L.recall_block("anything", None), "", "no program, no hunt history")

    def test_the_ground_store_rebuilds_when_the_ledger_grows(self):
        import os
        import time
        self._outcomes({"ts": "1", "target": "p", "vector": "v1", "verdict": "DEAD"})
        self.assertEqual(self.L.rebuild_ground(), 1)
        time.sleep(0.01)
        self._outcomes({"ts": "1", "target": "p", "vector": "v1", "verdict": "DEAD"},
                       {"ts": "2", "target": "p", "vector": "v2", "verdict": "LEAD"})
        os.utime(self.L.OUTCOMES, (time.time() + 5, time.time() + 5))
        self.assertEqual(len(self.L.recall_ground("", "p")), 2)

    def test_a_tool_turn_is_logged_as_a_trajectory_and_a_chat_turn_is_not(self):
        import json
        self.L.reflect(lambda m: "{}", self.TURN, "program-65")
        self.L.reflect(lambda m: "{}", [{"role": "user", "content": "hi"}], "program-65")
        with open(self.L.TRAJ) as f:
            rows = [json.loads(x) for x in f]
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["outcome"]["good"])


class UncensoredOnly(unittest.TestCase):
    """the user 2026-10-22: "make sure we are using uncensored models please"."""

    def setUp(self):
        import llm_endpoints
        self.E = llm_endpoints
        self.saved = dict(llm_endpoints._stock_cache)
        self.saved_env = os.environ.get("GNOC_ALLOW_STOCK")
        os.environ["GNOC_ALLOW_STOCK"] = "0"   # these tests are about a machine set to uncensored-only

    def tearDown(self):
        self.E._stock_cache.clear()
        self.E._stock_cache.update(self.saved)
        if self.saved_env is None:
            os.environ.pop("GNOC_ALLOW_STOCK", None)
        else:
            os.environ["GNOC_ALLOW_STOCK"] = self.saved_env

    def test_names_that_say_uncensored_pass_without_a_network_call(self):
        for n in ("huihui_ai/gpt-oss-abliterated:20b", "hf.co/HauhauCS/Qwen3.5-9B-Uncensored-HauhauCS-Aggressive:Q4_K_M",
                  "x/Qwen3.5-9B-Ultra-Uncensored-Heretic-GGUF"):
            self.assertIs(self.E.stock(n, "nohost"), False, n)

    def test_a_cloud_model_is_always_stock(self):
        self.assertIs(self.E.stock("kimi-k3:cloud", "desktop"), True)

    def test_an_unreachable_host_is_unknown_not_stock(self):
        self.assertIsNone(self.E.stock("gpt-oss:20b", "nohost"))

    def test_a_stock_role_is_used_as_configured(self):
        # 2026-11-27: the uncensored-only rule is gone, and GNOC_ALLOW_STOCK=0 (setUp) no longer brings it back
        from unittest import mock
        self.E._stock_cache[("local", "plainmodel:7b")] = True
        with mock.patch.object(self.E, "roles", return_value={"brain": "plainmodel:7b"}):
            self.assertEqual(self.E.resolve("brain")[1:], ("plainmodel:7b", "local"))


# ====================================================================== state files are written atomically


class AtomicStateWrites(Tmp):
    """Every state file gnoc chat rewrites while it runs must survive a crash mid-write: the reader sees the
    OLD file, never a torn one, and no .tmp litter is left behind. llm_endpoints, gnoc_learn, gnoc_hunt and
    gnoc_monitor already did this; the model registry and the OAST tag map did not."""

    def _torn(self, write, read, path, good, bad):
        write(good)
        self.assertEqual(read(), good)
        boom = io.StringIO  # a sentinel that is never reached if json.dump raises first
        with mock.patch("json.dump", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write(bad)
        self.assertEqual(read(), good, "the half-written file replaced the good one")
        d = os.path.dirname(path)
        self.assertEqual([f for f in os.listdir(d) if ".tmp" in f], [], "a tmp file was left behind")
        del boom

    def test_model_registry_survives_a_crash_mid_write(self):
        reg = os.path.join(self.tmp, "hf", "registry.json")
        self.redirect(HF, REGISTRY=reg)
        good = [{"name": "a:9b", "uses": 3}]
        self._torn(HF._save_registry, HF._registry, reg, good, [{"name": "b:4b", "uses": 1}])

    def test_registry_write_is_visible_whole_to_a_concurrent_reader(self):
        """touch() runs on every answer, and two chats answer at once."""
        reg = os.path.join(self.tmp, "hf2", "registry.json")
        self.redirect(HF, REGISTRY=reg)
        HF._save_registry([{"name": "a:9b", "uses": 0}])
        stop, seen = threading.Event(), []

        def reader():
            while not stop.is_set():
                seen.append(HF._registry())
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        for i in range(200):
            HF._save_registry([{"name": "a:9b", "uses": i}] * 40)
        stop.set()
        t.join(5)
        self.assertTrue(seen)
        self.assertTrue(all(isinstance(r, list) and r for r in seen), "a reader saw a torn registry")

    def test_oast_tag_map_survives_a_crash_mid_write(self):
        d = os.path.join(self.tmp, "oast", "prog")
        os.makedirs(d)
        self.redirect(OAST, _dir=lambda program: d)
        path = os.path.join(d, "state.json")

        def read():
            with open(path) as f:
                return json.load(f)
        good = {"pid": 1, "tags": {"gaaaa": {"label": "ssrf probe"}}}
        self._torn(lambda st: OAST._save_state("prog", st), read, path, good, {"tags": {}})


def setUpModule():  # noqa: N802 - unittest hook: no test may write the live agent state or lesson book
    import gnoc_testenv
    gnoc_testenv.start()


def tearDownModule():  # noqa: N802
    import gnoc_testenv
    gnoc_testenv.stop()


if __name__ == "__main__":
    unittest.main()
