"""gnoc_site: the user's own site, answered from its own telemetry - and the visitor data that must never
reach a model while doing it.

The bug this exists for (2026-10-24): "how is the cyber security of the site looking?" was answered with the
program-32 BOUNTY PROGRAM's trust model. Their site and a program the user hunts are different subjects.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# never read or write his REAL last-drill record (~/.local/share/gnoc-chat/redteam-last.json)
os.environ["GNOC_REDTEAM_LAST"] = os.path.join(tempfile.mkdtemp(prefix="gnoc-rtlast-"), "last.json")
import gnoc_site as SITE  # noqa: E402
import gnoc_agent as G  # noqa: E402

# One live address, one private message body, one ban row: the payload really does carry these.
VISITOR_IP = "203.0.113.77"
PRIVATE_MSG = "my password reset link never arrived, my email is learner@example.com"
BAN_REASON = "sqli probe burst from 198.51.100.9"

OVERVIEW = {
    "ok": True,
    "server": {"version": "1.5.0", "build": "abc123", "uptime": 14400, "runtime": "Android PM2", "lastWipe": None},
    "security": {
        "enabled": True,
        "stats": {"activeBans": 2},
        "summary": {"last15m": {"events": 0}, "last1h": {"events": 3}, "last24h": {"events": 6, "uniqueIps": 3}},
        "posture": {"score": 85, "grade": "guarded", "failing": 1, "warnings": 1, "checks": [
            {"key": "intrusion-watch", "label": "Intrusion detection & blocking", "status": "pass", "detail": "on"},
            {"key": "store-encryption", "label": "Learner data at rest", "status": "fail",
             "detail": "The persistent store is plaintext.", "remediation": "Configure STORE_ENCRYPTION_KEY_FILE."},
            {"key": "secure-transport", "label": "HTTPS enforcement", "status": "warn",
             "detail": "HTTPS enforcement is inactive.", "remediation": "Run with NODE_ENV=production."},
        ]},
        "events": [{"ip": VISITOR_IP, "sig": "sqli", "path": "/api/login"}],
        "bans": [{"key": VISITOR_IP, "reason": BAN_REASON}],
        "watchlist": [{"key": VISITOR_IP, "score": 40}],
    },
    "community": {"onlineVisible": 4, "socketsConnected": 7, "publicRooms": 2, "p2pRooms": 1,
                  "pro": {"total": 9, "stripeActive": 7, "stripeToday": 1}, "certsIssued": 3, "courseVaults": 11},
    "inbox": {"open": 2, "emergencies": 1, "next": {"sender": "a learner", "message": PRIVATE_MSG}},
    "sessions": [{"ip": VISITOR_IP, "ua": "curl/8"}, {"ip": "198.51.100.9", "ua": "Firefox"}],
    "presence": [{"handle": "someone", "ip": VISITOR_IP}],
    "controls": {"maintenance": False},
    "metrics": {
        "http": {"lifetime": 2206, "oneMinute": {"requests": 9, "status4xx": 1, "status5xx": 2},
                 "fiveMinutes": {"requests": 51}},
        "realtime": {"events1m": 3},
        "process": {"cpuPercent": 0.48855, "rssBytes": 192_900_000, "heapUsedBytes": 91_800_000,
                    "heapLimitBytes": 4_345_300_000, "eventLoopLagAvgMs": 0.15021, "eventLoopLagPeakMs": 0,
                    "loadAverage1m": 0.8523},
        "store": {"encrypted": False, "readOnly": True, "writePending": False, "fileBytes": 300_000,
                  "diskFreeBytes": 826_000_000, "diskTotalBytes": 2_048_000_000, "lastPersistDurationMs": 101.25,
                  "lastPersistAt": 1792895278786, "lastPersistError": "EACCES: permission denied",
                  "lastPersistErrorAt": 1792895278786},
    },
    "alerts": [{"level": "critical", "title": "Profile store is read-only", "detail": "Writes are disabled."}],
}


class Reader(unittest.TestCase):
    def setUp(self):
        SITE._CACHE.update(ts=0, data=None)
        self.tmp = tempfile.mkdtemp(prefix="gnoc-site-")
        env = os.path.join(self.tmp, ".env")
        with open(env, "w") as f:
            f.write("PORT=6969\nPUBLIC_URL=https://your-site.example\nOPS_ADMIN_TOKEN=tok-ops\n"
                    "HEALTHZ_DETAIL_TOKEN=tok-health\n")
        self._saved = (SITE.SITE_DIR, SITE.SITE_ENV)
        SITE.SITE_DIR, SITE.SITE_ENV = self.tmp, env
        self.addCleanup(lambda: setattr(SITE, "SITE_ENV", self._saved[1]))
        self.addCleanup(lambda: setattr(SITE, "SITE_DIR", self._saved[0]))
        self.addCleanup(lambda: SITE._CACHE.update(ts=0, data=None))

    def _serve(self, overview=OVERVIEW, health=None, edge_ok=True):
        health = health if health is not None else {"ok": True, "version": "1.5.0", "uptime": 14400}
        calls = []

        def get(url, headers, timeout=6):
            calls.append((url, headers))
            if url.endswith("/healthz") and url.startswith("http://127.0.0.1"):
                return 200, health, 3.0
            if "/api/dashboard/overview" in url:
                return 200, overview, 7.0
            return (200, {"ok": True}, 300.0) if edge_ok else (502, None, 300.0)
        p = mock.patch.object(SITE, "_get", side_effect=get)
        p.start()
        self.addCleanup(p.stop)
        return calls

    # ---- the numbers he asked for
    def test_security_section_reports_the_sites_own_scorecard_and_what_is_failing(self):
        self._serve()
        out = SITE.summary("security")
        self.assertIn("85/100", out)
        self.assertIn("guarded", out)
        self.assertIn("Learner data at rest", out)      # the failing check, by name
        self.assertIn("STORE_ENCRYPTION_KEY_FILE", out)  # and its fix
        self.assertIn("HTTPS enforcement", out)          # the warning too
        self.assertIn("2 active bans", out)

    def test_users_database_and_traffic_sections_answer_their_own_question(self):
        self._serve()
        users = SITE.summary("users")
        self.assertIn("4 visible online", users)
        self.assertIn("9 active Pro", users)
        db = SITE.summary("database")
        self.assertIn("READ-ONLY", db)                  # the thing he would need to know
        self.assertIn("PLAINTEXT", db)
        self.assertIn("EACCES", db)                     # the last write failed, and why
        traffic = SITE.summary("traffic")
        self.assertIn("9 req/min", traffic)
        self.assertIn("2 5xx", traffic)
        self.assertIn("0.5%", traffic)                  # cpu rounded, not 0.48855...

    def test_overview_covers_every_section(self):
        self._serve()
        out = SITE.summary()
        for mark in ("SECURITY:", "USERS:", "DATABASE", "TRAFFIC:", "PROCESS:", "ALERTS:"):
            self.assertIn(mark, out)

    # ---- what must never reach a model
    def test_no_visitor_address_session_or_message_body_reaches_the_answer(self):
        self._serve()
        for section in SITE.SECTIONS:
            out = SITE.summary(section, force=True)
            for leak in (VISITOR_IP, "198.51.100.9", PRIVATE_MSG, BAN_REASON, "learner@example.com", "curl/8"):
                self.assertNotIn(leak, out, f"{leak!r} leaked into the {section} answer")
        data = SITE.read(force=True)
        blob = json.dumps(data)
        for leak in (VISITOR_IP, PRIVATE_MSG, BAN_REASON):
            self.assertNotIn(leak, blob, f"{leak!r} survived into the returned data")
        self.assertEqual(data["users"]["sessions"], 2)      # counted, not read
        self.assertEqual(data["security"]["watchlist"], 1)

    def test_the_ops_token_is_sent_to_loopback_only_and_never_printed(self):
        calls = self._serve()
        out = SITE.summary("overview")
        self.assertNotIn("tok-ops", out)
        self.assertNotIn("tok-health", out)
        for url, headers in calls:
            if any("tok-" in str(v) for v in (headers or {}).values()):
                self.assertTrue(url.startswith("http://127.0.0.1:"), f"a token went to {url}")

    # ---- a site that is down is an answer, not an error
    def test_a_site_that_does_not_answer_says_so_plainly(self):
        with mock.patch.object(SITE, "_get", return_value=(0, None, 1.0)):
            out = SITE.summary("overview", force=True)
        self.assertIn("IS NOT ANSWERING", out)
        self.assertIn("not running", out)

    def test_an_ops_console_that_refuses_still_reports_healthz(self):
        def get(url, headers, timeout=6):
            if url.endswith("/healthz") and url.startswith("http://127.0.0.1"):
                return 200, {"ok": True, "version": "1.5.0"}, 3.0
            return 403, None, 2.0
        with mock.patch.object(SITE, "_get", side_effect=get):
            out = SITE.summary("security", force=True)
        self.assertIn("/healthz says ok", out)
        self.assertIn("403", out)

    def test_an_unknown_section_lists_the_real_ones(self):
        self.assertIn("overview", SITE.summary("wizardry"))

    def test_sections_have_aliases_for_the_words_he_actually_uses(self):
        self._serve()
        for alias, mark in (("db", "DATABASE"), ("store", "DATABASE"), ("stats", "TRAFFIC:"),
                            ("posture", "SECURITY:"), ("sec", "SECURITY:")):
            self.assertIn(mark, SITE.summary(alias, force=True), f"alias {alias} did not resolve")


class Routing(unittest.TestCase):
    """The model has to CHOOSE this tool: the description and the system prompt are what teach it."""

    def test_the_tool_is_registered_and_readable_by_a_worker(self):
        self.assertIn("site_status", G.TOOLS)
        self.assertIn("site_status", G.WORKER_TOOLS)

    def test_its_description_names_the_questions_he_asks(self):
        desc = G.TOOLS["site_status"][1]["function"]["description"].lower()
        for phrase in ("how is the site", "is the site secure", "users online", "database", "website stats",
                       "posture"):
            self.assertIn(phrase, desc)
        self.assertIn("never hunt_brief", desc)

    def test_the_system_prompt_separates_his_site_from_a_bounty_program(self):
        # the rule names the configured site, so it exists only where a site's .env names a PUBLIC_URL (a fresh
        # install has none): build it for one, and check the prompt carries whatever this machine's rules are
        from gnoc_core import prompts
        import gnoc_site
        with mock.patch.object(gnoc_site, "_env", return_value={"PUBLIC_URL": "https://your-site.example"}):
            sysp = prompts._site_rules().lower()
        self.assertIn("their site is not a program", sysp)
        self.assertIn("site_status", sysp)
        self.assertIn("your-site.example", sysp)
        self.assertIn(prompts._site_rules(), G.SYSTEM)

    def test_hunt_brief_still_describes_itself_as_the_program_tool(self):
        self.assertIn("program", G.TOOLS["hunt_brief"][1]["function"]["description"].lower())

    def test_the_tool_answers_without_a_program_set(self):
        """The original failure needed a program; this question must work with none."""
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        with mock.patch.object(SITE, "summary", return_value="SECURITY: posture 85/100"):
            out = G.TOOLS["site_status"][0](ctx, section="security")
        self.assertIn("85/100", out)

    def test_a_site_read_that_raises_does_not_kill_the_turn(self):
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        with mock.patch.object(SITE, "summary", side_effect=RuntimeError("boom")):
            out = G.TOOLS["site_status"][0](ctx, section="overview")
        self.assertIn("could not read the site", out)


if __name__ == "__main__":
    unittest.main()
