"""gnoc_redteam: the drill must be honest in BOTH directions - no missed finding, and no clean report it did
not earn.

Two real bugs from the day it was written, both now regression-tested:
  - every probe was answered by the HOST GUARD before the route ran, and the sweep reported 129 clean probes
    it had never actually performed;
  - a 40-request burst against a route that allows 120/min was reported as "no rate limit".
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# never read or write his REAL last-drill record (~/.local/share/gnoc-chat/redteam-last.json)
os.environ["GNOC_REDTEAM_LAST"] = os.path.join(tempfile.mkdtemp(prefix="gnoc-rtlast-"), "last.json")
import gnoc_redteam as R  # noqa: E402
import gnoc_site  # noqa: E402
import gnoc_agent as G  # noqa: E402

SERVER_JS = '''
app.get("/api/dashboard/overview", dashboardOverviewRateLimit, async (req, res) => {});
app.get("/api/dashboard/users/:pub", (req, res) => {});
app.post("/api/dashboard/ban", (req, res) => {});
app.get("/api/server-status", apiRateLimit("server-status", 120), (req, res) => {});
app.get("/api/public/thing", (req, res) => {});
'''
HOST_GUARD = (400, {}, "Bad Host header.\\n", 1.0)
NOT_FOUND = (404, {}, "Not found.\\n", 1.0)
OK = (200, {"content-type": "application/json"}, '{"ok":true}', 1.0)


class Routes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-rt-")
        self.js = os.path.join(self.tmp, "server.js")
        with open(self.js, "w") as f:
            f.write(SERVER_JS)

    def test_ops_routes_come_from_the_sites_own_source(self):
        got = R.ops_routes(self.js)
        self.assertIn(("GET", "/api/dashboard/overview"), got)
        self.assertIn(("POST", "/api/dashboard/ban"), got)
        self.assertTrue(any(m == "GET" and p.startswith("/api/dashboard/users/") for m, p in got))
        self.assertNotIn(("GET", "/api/server-status"), got)   # not an ops route
        self.assertNotIn(("GET", "/api/public/thing"), got)

    def test_the_declared_ceiling_is_read_from_the_site(self):
        self.assertEqual(R.declared_ceiling("server-status", self.js), 120)
        self.assertIsNone(R.declared_ceiling("no-such-route", self.js))


class Authz(unittest.TestCase):
    """The sweep must only call a route guarded when it PROVED the route was live."""

    def setUp(self):
        self.env = {"OPS_ADMIN_TOKEN": "admin-tok", "HEALTHZ_DETAIL_TOKEN": "health-tok"}
        self.routes = [("GET", "/api/dashboard/overview")]
        p = mock.patch.object(R, "ops_routes", return_value=self.routes)
        p.start()
        self.addCleanup(p.stop)

    def _sweep(self, responder):
        with mock.patch.object(R, "_req", side_effect=responder) as m:
            return R.check_authz("http://127.0.0.1:6969", self.env, "ua", "your-site.example"), m

    def test_a_guarded_route_is_verified_only_via_the_admin_control_probe(self):
        def resp(method, url, headers=None, body=None, timeout=8):
            return OK if (headers or {}).get("x-ops-token") == "admin-tok" else NOT_FOUND
        out, _ = self._sweep(resp)
        ids = {f["id"]: f for f in out}
        self.assertEqual(ids["authz.verified"]["status"], "pass")
        self.assertNotIn("authz.open", ids)

    def test_host_guard_answers_are_never_counted_as_refusals(self):
        """THE regression: 'Bad Host header' is not the auth guard saying no."""
        out, _ = self._sweep(lambda *a, **k: HOST_GUARD)
        ids = {f["id"]: f for f in out}
        self.assertNotIn("authz.verified", ids, "a host-guard answer was counted as a passing route")
        self.assertIn("authz.hostguard", ids)
        self.assertEqual(ids["authz.hostguard"]["status"], "warn")

    def test_every_probe_carries_the_public_host_so_it_reaches_the_route(self):
        _, m = self._sweep(lambda *a, **k: NOT_FOUND)
        self.assertTrue(m.call_args_list)
        for call in m.call_args_list:
            headers = call.args[2] if len(call.args) > 2 else call.kwargs.get("headers")
            self.assertEqual((headers or {}).get("Host"), "your-site.example")

    def test_an_unguarded_route_is_a_critical_finding(self):
        out, _ = self._sweep(lambda *a, **k: OK)
        ids = {f["id"]: f for f in out}
        self.assertEqual(ids["authz.open"]["severity"], "critical")
        self.assertEqual(ids["authz.open"]["status"], "FAIL")

    def test_a_route_that_never_resolves_is_untested_not_passing(self):
        out, _ = self._sweep(lambda *a, **k: NOT_FOUND)
        ids = {f["id"]: f for f in out}
        self.assertIn("authz.unreached", ids)
        self.assertEqual(ids["authz.unreached"]["status"], "warn")
        self.assertNotIn("authz.verified", ids)

    def test_mutating_routes_are_probed_unauthenticated_and_unparseable_only(self):
        """A test for 'is this guarded' must not be able to change anything."""
        self.routes[:] = [("POST", "/api/dashboard/ban")]
        sent = []

        def resp(method, url, headers=None, body=None, timeout=8):
            sent.append((method, dict(headers or {}), body))
            return NOT_FOUND
        with mock.patch.object(R, "_req", side_effect=resp):
            out = R.check_authz("http://127.0.0.1:6969", self.env, "ua", "your-site.example")
        self.assertTrue(sent)
        for method, headers, body in sent:
            self.assertEqual(method, "POST")
            self.assertNotEqual(headers.get("x-ops-token"), "admin-tok", "a mutating probe carried the admin token")
            self.assertEqual(body, "{", "a mutating probe sent a parseable body")
        ids = {f["id"]: f for f in out}
        self.assertEqual(ids["authz.mutating"]["status"], "pass")
        self.assertIn("weaker evidence", ids["authz.mutating"]["evidence"])


class Limits(unittest.TestCase):
    def _run(self, codes, n, ceiling):
        it = iter(codes)
        with mock.patch.object(R, "declared_ceiling", return_value=ceiling), \
             mock.patch.object(R, "_req", side_effect=lambda *a, **k: (next(it, 200), {}, "", 1.0)):
            return R.check_limits("http://127.0.0.1:6969", "ua", "h", confirm=True, n=n)[0]

    def test_a_burst_under_the_declared_ceiling_is_inconclusive_not_a_failure(self):
        f = self._run([200] * 40, 40, 120)
        self.assertEqual(f["status"], "skipped")
        self.assertIn("CANNOT disprove", f["evidence"])

    def test_a_burst_past_the_ceiling_with_no_429_is_a_real_failure(self):
        f = self._run([200] * 130, 130, 120)
        self.assertEqual(f["status"], "FAIL")

    def test_a_429_is_a_pass(self):
        f = self._run([200] * 5 + [429], 130, 120)
        self.assertEqual(f["status"], "pass")
        self.assertIn("429", f["evidence"])

    def test_it_does_not_run_without_confirmation(self):
        with mock.patch.object(R, "declared_ceiling", return_value=120), \
             mock.patch.object(R, "_req", side_effect=AssertionError("fired without confirm")):
            f = R.check_limits("http://127.0.0.1:6969", "ua", "h", confirm=False)[0]
        self.assertEqual(f["status"], "skipped")


class Edge(unittest.TestCase):
    def _edge(self, hsts, origin_hsts="max-age=15552000; includeSubDomains"):
        h = {"strict-transport-security": hsts, "content-security-policy": "default-src 'self'"} if hsts \
            else {"content-security-policy": "default-src 'self'"}
        with mock.patch.object(R, "_req", return_value=(200, h, "", 10.0)):
            return {f["id"]: f for f in R.check_edge("https://your-site.example", "ua", origin_hsts)}

    def test_max_age_zero_at_the_edge_is_a_finding_even_when_the_origin_is_strong(self):
        f = self._edge("max-age=0")["edge.hsts"]
        self.assertEqual(f["status"], "FAIL")
        self.assertIn("FORGET", f["evidence"])
        self.assertIn("edge overriding it", f["evidence"])
        self.assertIn("Cloudflare", f["fix"])

    def test_a_real_hsts_at_the_edge_passes(self):
        self.assertEqual(self._edge("max-age=31536000; includeSubDomains")["edge.hsts"]["status"], "pass")

    def test_a_stripped_csp_at_the_edge_is_a_finding(self):
        with mock.patch.object(R, "_req", return_value=(200, {"strict-transport-security": "max-age=31536000"}, "", 9.0)):
            ids = {f["id"]: f for f in R.check_edge("https://your-site.example", "ua", None)}
        self.assertEqual(ids["edge.csp"]["status"], "FAIL")


class Traversal(unittest.TestCase):
    def test_a_served_passwd_file_is_critical(self):
        with mock.patch.object(R, "_req", return_value=(200, {}, "root:x:0:0:root:/root:/bin/bash\n", 1.0)):
            f = R.check_traversal("http://127.0.0.1:6969", "ua", "h")[0]
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["status"], "FAIL")

    def test_refusals_pass(self):
        with mock.patch.object(R, "_req", return_value=NOT_FOUND):
            self.assertEqual(R.check_traversal("http://127.0.0.1:6969", "ua", "h")[0]["status"], "pass")


class Areas(unittest.TestCase):
    """A named subsystem is tested, or honestly refused - never silently swapped for the whole-site drill."""

    def test_an_unknown_area_runs_nothing_and_says_so(self):
        with mock.patch.object(R, "_req", side_effect=AssertionError("probed on an unknown area")):
            text = R.summary(area="the moon")
        self.assertIn("no drill for", text)
        self.assertIn("campus-live-feed", text)
        self.assertIn("nothing was run", text)

    def test_a_known_area_runs_only_its_own_checks(self):
        called = []
        with mock.patch.object(R, "check_feed", side_effect=lambda *a: called.append("feed") or []),              mock.patch.object(R, "check_authz", side_effect=AssertionError("ran the whole-site sweep")),              mock.patch.object(R, "_req", return_value=(200, {}, "{}", 1.0)),              mock.patch.object(R.gnoc_site, "_env", return_value={"PORT": "6969"}):
            R.run(area="campus_live_feed")
        self.assertEqual(called, ["feed"])

    def test_the_feed_drill_always_states_what_it_did_not_cover(self):
        with mock.patch.object(R, "_req", return_value=(200, {}, '{"ok":true,"campus":{}}', 1.0)),              mock.patch.object(R, "_sio_read", return_value=(False, [], "no handshake")),              mock.patch.object(R, "_source_fact", return_value="150"):
            out = R.check_feed("http://127.0.0.1:6969", "ua", "h", {})
        nc = [f for f in out if f["id"] == "feed.notcovered"]
        self.assertTrue(nc)
        self.assertIn("write path", nc[0]["evidence"])


class FeedPayload(unittest.TestCase):
    """Judged on structure: a field the server added, not a word a person typed."""

    def test_a_public_identity_key_is_not_a_leak(self):
        blob = '42["feed:list",[{"id":"1","pub":"abc","signerPub":"def","user":"someone","text":"hi"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertEqual(ids["feed.socket.fields"]["status"], "pass")

    def test_his_own_support_address_in_a_post_body_is_not_a_finding(self):
        """Measured 2026-10-25: the first version flagged a post the user wrote asking people to mail them."""
        blob = '42["feed:list",[{"id":"1","text":"email me support@your-site.example for a code"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertEqual(ids["feed.socket.fields"]["status"], "pass")
        self.assertNotIn("feed.socket.text", ids)

    def test_an_email_FIELD_on_a_row_is_a_real_finding(self):
        blob = '42["feed:list",[{"id":"1","author":{"email":"learner@example.com"},"text":"hi"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertEqual(ids["feed.socket.fields"]["status"], "FAIL")
        self.assertEqual(ids["feed.socket.fields"]["severity"], "high")

    def test_a_client_ip_field_is_a_real_finding(self):
        blob = '42["feed:list",[{"id":"1","clientIp":"203.0.113.9"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertEqual(ids["feed.socket.fields"]["status"], "FAIL")

    def test_an_oversized_answer_to_a_small_limit_is_noted(self):
        blob = '42["feed:list",[' + '{"id":"x","text":"' + "a" * 60000 + '"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertIn("feed.socket.size", ids)

    def test_the_socket_probe_never_sends_a_write_event(self):
        sent = []

        def resp(method, url, headers=None, body=None, timeout=5):
            sent.append(body)
            if "sid=" not in url:
                return 200, {}, '0{"sid":"abc"}', 1.0
            return 200, {}, '40{"sid":"abc"}', 1.0
        with mock.patch.object(R, "_req", side_effect=resp):
            R._sio_read("http://127.0.0.1:6969", "ua", "h", "feed:list", {"limit": 5})
        writes = [b for b in sent if b and any(w in str(b) for w in
                  ("feed:post", "feed:like", "feed:delete", "feed:report", "drop:post"))]
        self.assertEqual(writes, [], "the socket probe emitted a write event")


class LoudGate(unittest.TestCase):
    """confirm must come from the user, not from the model deciding on their behalf."""

    def _call(self, turn_text, confirm="True"):
        import types
        ctx = types.SimpleNamespace(program=None, s={"_turn_text": turn_text})
        seen = {}
        with mock.patch.object(R, "summary",
                               side_effect=lambda c, confirm, area: seen.update(loud=confirm) or "report"):
            out = G.TOOLS["site_redteam"][0](ctx, confirm=confirm)
        return seen.get("loud"), out

    def test_the_model_cannot_fire_the_burst_on_its_own_initiative(self):
        loud, out = self._call("please orchistrate a qaqc of the Live feed on the campus on the website")
        self.assertIs(loud, False)
        self.assertIn("loud burst was NOT run", out)

    def test_his_own_words_do_fire_it(self):
        for text in ("burst it", "test the rate limits for real", "go ahead", "hit it hard"):
            loud, _ = self._call(text)
            self.assertIs(loud, True, f"{text!r} should have authorised the burst")

    def test_no_turn_text_means_no_burst(self):
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        seen = {}
        with mock.patch.object(R, "summary",
                               side_effect=lambda c, confirm, area: seen.update(loud=confirm) or "r"):
            G.TOOLS["site_redteam"][0](ctx, confirm=True)
        self.assertIs(seen["loud"], False)

    def test_the_appended_hint_that_says_never_burst_does_not_fire_it(self):
        """_turn_text carries a [gnoc: ...] hint that itself says "never the loud 'limits' burst"; matching
        that text authorised the very burst the hint forbids (1000-turn drive 2026-11-24)."""
        text = ("red team the site\n\n[gnoc: this tests their OWN site: call site_redteam() once and answer "
                "from its lines (FAILED BY SEVERITY counts, warnings and skipped are not findings). "
                "http_request is for bounty programs only; never the loud 'limits' burst unless the user asks "
                "for it.]")
        loud, out = self._call(text)
        self.assertIs(loud, False)
        self.assertIn("loud burst was NOT run", out)


class ToolWiring(unittest.TestCase):
    def test_the_tool_is_registered_and_asks_before_it_fires(self):
        self.assertIn("site_redteam", G.TOOLS)
        self.assertEqual(G.TOOLS["site_redteam"][2], "unless_auto")

    def test_its_description_tells_the_model_when_to_reach_for_it(self):
        d = G.TOOLS["site_redteam"][1]["function"]["description"].lower()
        for phrase in ("red team", "pentest the site", "prove it", "read-only", "loud burst", "area"):
            self.assertIn(phrase, d)

    def test_the_prompt_separates_a_posture_score_from_a_test(self):
        # the site rules exist only where a site is configured (its .env names a PUBLIC_URL), so build them for one,
        # and check the prompt carries whatever this machine's own site rules are
        from gnoc_core import prompts
        import gnoc_site
        with mock.patch.object(gnoc_site, "_env", return_value={"PUBLIC_URL": "https://site.example"}):
            p = prompts._site_rules().lower()
        self.assertIn("tested, not assumed", p)
        self.assertIn("site_redteam", p)
        self.assertIn(prompts._site_rules(), G.SYSTEM)

    def test_an_unknown_check_is_refused_without_probing_anything(self):
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        with mock.patch.object(R, "summary", side_effect=AssertionError("probed on a bad argument")):
            out = G.TOOLS["site_redteam"][0](ctx, checks="authz,wizardry")
        self.assertIn("wizardry", out)

    def test_an_alias_mixed_with_a_real_check_keeps_the_real_check(self):
        """'all,headers' was refused as "unknown check(s) all" (1000-turn drive 2026-11-24)."""
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        seen = {}
        with mock.patch.object(R, "summary",
                               side_effect=lambda c, confirm, area=None: seen.update(checks=c) or "ok"):
            out = G.TOOLS["site_redteam"][0](ctx, checks="all,headers")
        self.assertNotIn("unknown check", out)
        self.assertEqual(seen["checks"], ["headers"])

    def test_a_string_false_from_the_model_does_not_fire_the_loud_check(self):
        """Measured 2026-10-25: the lead sends confirm='True' as a STRING. bool('false') is True, so a plain
        bool() would have turned a refusal to confirm into a burst against the live site."""
        import types
        # his words DO authorise a burst here, so only the string coercion decides the outcome
        ctx = types.SimpleNamespace(program=None, s={"_turn_text": "go ahead and burst it"})
        seen = {}
        with mock.patch.object(R, "summary", side_effect=lambda c, confirm, area=None: seen.update(confirm=confirm) or "ok"):
            G.TOOLS["site_redteam"][0](ctx, confirm="false")
            self.assertIs(seen["confirm"], False)
            G.TOOLS["site_redteam"][0](ctx, confirm="True")
            self.assertIs(seen["confirm"], True)
            G.TOOLS["site_redteam"][0](ctx, confirm="no")
            self.assertIs(seen["confirm"], False)

    def test_checks_may_arrive_as_one_string(self):
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        seen = {}
        with mock.patch.object(R, "summary", side_effect=lambda c, confirm, area=None: seen.update(checks=c) or "ok"):
            G.TOOLS["site_redteam"][0](ctx, checks="authz headers")
        self.assertEqual(seen["checks"], ["authz", "headers"])

    def test_a_drill_that_raises_does_not_kill_the_turn(self):
        import types
        ctx = types.SimpleNamespace(program=None, s={})
        with mock.patch.object(R, "summary", side_effect=RuntimeError("boom")):
            self.assertIn("could not run", G.TOOLS["site_redteam"][0](ctx))

    def test_the_target_cannot_be_redirected_by_any_argument(self):
        """There is no url/host parameter anywhere in the tool's schema."""
        props = G.TOOLS["site_redteam"][1]["function"]["parameters"]["properties"]
        self.assertEqual(set(props), {"checks", "area", "confirm"})

    def test_the_report_always_announces_that_it_touched_the_live_site(self):
        with mock.patch.object(R, "_req", return_value=(200, {}, '{"ok":true}', 1.0)), \
             mock.patch.object(gnoc_site, "_env", return_value={"PORT": "6969",
                                                                "PUBLIC_URL": "https://your-site.example"}), \
             mock.patch.object(R, "ops_routes", return_value=[]):
            text = R.summary(["authz"])
        self.assertIn("security feed", text)
        self.assertIn("gnoc-redteam/", text)
        self.assertIn("Nothing was changed", text)


class DrillHonesty20261124(unittest.TestCase):
    """Each test encodes a bug measured on 2026-11-24: the drill reported a verdict it had not earned."""

    def test_a_cookie_name_does_not_satisfy_the_secure_flag(self):
        h = {"set-cookie": "secure_pref=1; HttpOnly; SameSite=Lax"}
        with mock.patch.object(R, "_req", return_value=(200, h, "", 1.0)):
            f = R.check_cookies("http://127.0.0.1:6969", "ua", "h")[0]
        self.assertEqual(f["status"], "FAIL")

    def test_a_wildcard_subdomain_is_not_a_wildcard_csp(self):
        h = {"content-security-policy": "default-src 'self'; img-src https://*.example.com",
             "strict-transport-security": "max-age=15552000"}
        with mock.patch.object(R, "_req", return_value=(200, h, "", 1.0)):
            f = {x["id"]: x for x in R.check_headers("http://127.0.0.1:6969", "h", "ua")}["headers.csp"]
        self.assertEqual(f["status"], "pass")

    def test_an_absent_encryption_flag_is_unmeasured(self):
        with mock.patch.object(R.gnoc_site, "read", return_value={"ok": True, "database": {"size_mb": 1.0}}):
            f = R.check_store("http://127.0.0.1:6969", {}, "ua")[0]
        self.assertEqual(f["status"], "skipped")

    def test_no_answer_is_not_a_clean_error_body_or_a_refusal(self):
        with mock.patch.object(R, "_req", return_value=(0, {}, "timed out", 1.0)):
            self.assertEqual(R.check_errors("http://127.0.0.1:6969", "ua", "h")[0]["status"], "skipped")
            self.assertEqual(R.check_traversal("http://127.0.0.1:6969", "ua", "h")[0]["status"], "skipped")

    def test_a_lookalike_domain_is_not_the_sites_own(self):
        blob = '42["feed:list",[{"text":"mail attacker@evilgreynoc.com"}]]'
        ids = {f["id"]: f for f in R._feed_payload_findings(blob, "your-site.example")}
        self.assertIn("feed.socket.text", ids)

    def test_an_unobserved_edge_is_not_three_findings(self):
        with mock.patch.object(R, "_req", return_value=(0, {}, "timed out", 12000.0)):
            out = R.check_edge("https://your-site.example", "ua")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["status"], "skipped")

    def test_single_quoted_routes_are_swept(self):
        tmp = tempfile.mkdtemp(prefix="gnoc-rt-")
        js = os.path.join(tmp, "server.js")
        with open(js, "w") as fh:
            fh.write("app.get('/api/dashboard/one', h);\n")
        self.assertIn(("GET", "/api/dashboard/one"), R.ops_routes(js))

    def test_a_capped_sweep_says_what_it_did_not_probe(self):
        routes = [("GET", "/api/dashboard/r%d" % i) for i in range(5)]
        with mock.patch.object(R, "ops_routes", return_value=routes), \
             mock.patch.object(R, "_req", return_value=(404, {}, "Not found.", 1.0)):
            out = R.check_authz("http://127.0.0.1:6969", {"OPS_ADMIN_TOKEN": "a"}, "ua", "h", cap=3)
        self.assertIn("authz.capped", {f["id"]: f for f in out})

    def test_the_summary_counts_failed_checks_by_severity(self):
        findings = [R._finding("a", "A", "high", "FAIL", "x"),
                    R._finding("b", "B", "medium", "FAIL", "y"),
                    R._finding("c", "C", "info", "pass", "z")]
        with mock.patch.object(R, "run", return_value=("ann", findings)):
            text = R.summary()
        self.assertIn("FAILED BY SEVERITY: 0 critical, 1 high, 1 medium, 0 low, 0 info", text)

    def test_every_set_cookie_line_is_checked(self):
        h = {"set-cookie": "good=1; HttpOnly; Secure; SameSite=Lax\nbad=2; HttpOnly; SameSite=Lax"}
        with mock.patch.object(R, "_req", return_value=(200, h, "", 1.0)):
            f = R.check_cookies("http://127.0.0.1:6969", "ua", "h")[0]
        self.assertEqual(f["status"], "FAIL")
        self.assertIn("bad missing secure", f["evidence"])

    def test_duplicate_set_cookie_headers_are_not_collapsed(self):
        from email.message import Message
        m = Message()
        m["Set-Cookie"] = "a=1; Secure"
        m["Set-Cookie"] = "b=2"
        self.assertEqual(R._headers(m)["set-cookie"].split("\n"), ["a=1; Secure", "b=2"])

    def test_the_drill_names_privileged_prefixes_it_does_not_sweep(self):
        tmp = tempfile.mkdtemp(prefix="gnoc-rt-")
        js = os.path.join(tmp, "server.js")
        with open(js, "w") as fh:
            fh.write('app.get("/api/dashboard/a", h);\napp.get("/api/admin/whoami", h);\n')
        ids = {x["id"]: x for x in R.check_surface(js)}
        self.assertIn("surface.untested", ids)
        self.assertIn("/api/admin", ids["surface.untested"]["evidence"])
        self.assertEqual(ids["surface.untested"]["status"], "warn")

    def test_a_dashboard_only_source_has_no_uncovered_prefix(self):
        tmp = tempfile.mkdtemp(prefix="gnoc-rt-")
        js = os.path.join(tmp, "server.js")
        with open(js, "w") as fh:
            fh.write('app.get("/api/dashboard/a", h);\n')
        self.assertEqual(R.check_surface(js)[0]["status"], "pass")


if __name__ == "__main__":
    unittest.main()


class AllMeansTheDefaultDrill20261124(unittest.TestCase):
    """Defense batch 25: the 9B called site_redteam(checks='all'), which was refused as an unknown check."""

    def test_all_is_not_refused(self):
        import inspect
        from gnoc_tools import hunt
        src = inspect.getsource(hunt.t_site_redteam)
        self.assertIn('{"all", "everything", "full", "default", "drill"}', src)
