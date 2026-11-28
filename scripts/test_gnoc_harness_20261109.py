"""Harness corrections from the 2026-11-09 gnoc chat program-59 session (stdlib unittest, temp dirs, no network).

Spec: .claude/state/hunt-loop/SPEC-harness-fixes-20261109.md. One class per item:
  F1 goal crown parser (gnoc_goal.parse)            F2 captured-route harvester (gnoc_hunt.existing_paths)
  F3 root-path request + refusal example             F4 identity-premise refusal + invented-id advisory
  F5 lead hands-on probe advisory                    F6 secrets refusal names the session path; honest listing
  F7 identities action=login via LOGIN.py            F9 cloud retry with backoff + goal re-entry
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as A  # noqa: E402
import gnoc_doctrine as D  # noqa: E402
import gnoc_goal as G  # noqa: E402
import gnoc_hunt as H  # noqa: E402
import gnoc_ident as I  # noqa: E402

PROG = "zz-harness1109"
GOAL_TEXT = ("chain the P3 vault session fixation into a P1 (one-click victim token theft or victim "
             "bank-credential exfil)")
SSRF_TRIO = {"open-redirect", "internal-hostname", "internal-reach"}


class _TmpWS(unittest.TestCase):
    """A throwaway workspace: gnoc_hunt, gnoc_ident and the env WS all point at it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-h1109-")
        self.saved = (H.path, H.WS, I.WS, os.environ.get("WS"))
        H.WS = self.tmp
        I.WS = self.tmp
        os.environ["WS"] = self.tmp
        H.path = lambda program: os.path.join(self.tmp, "targets", program, "hunts", "gnoc", "ledger.json")
        H._HARVEST.clear()
        self.tdir = os.path.join(self.tmp, "targets", PROG)
        os.makedirs(os.path.join(self.tdir, "hunts", "gnoc"), exist_ok=True)

    def tearDown(self):
        H.path, H.WS, I.WS, env = self.saved
        if env is None:
            os.environ.pop("WS", None)
        else:
            os.environ["WS"] = env
        H._HARVEST.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def raw(self, lane="lane1", sub=""):
        d = os.path.join(self.tdir, "hunts", lane, "raw", sub)
        os.makedirs(d, exist_ok=True)
        return d

    def pair(self, name, line, status, lane="lane1", ext=".hdr"):
        d = self.raw(lane)
        with open(os.path.join(d, name + ".req"), "w") as f:
            f.write(line + "\n{\"timeout\": 30}\n")
        with open(os.path.join(d, name + ext), "w") as f:
            f.write(status + "\ncontent-type: text/html\n")

    def jcap(self, name, url, status, lane="lane2"):
        with open(os.path.join(self.raw(lane), name + ".json"), "w") as f:
            json.dump({"request": {"method": "GET", "url": url}, "response": {"status": status, "body": "x"}}, f)

    def write(self, rel, text):
        p = os.path.join(self.tdir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
        return p


class F1GoalCrown(unittest.TestCase):
    def test_victim_token_theft_goal_is_ato_not_secret(self):
        crown, _ = G.parse(GOAL_TEXT)
        self.assertIn(crown, ("ato", "cross-user-read"), crown)

    def test_its_milestones_are_not_the_ssrf_trio(self):
        crown, _ = G.parse(GOAL_TEXT)
        tree = D.attack_tree(crown, [], 2)
        leaves = {x.strip() for x in tree.split("LEAVES TO PROVE", 1)[1].split(":", 1)[1].splitlines()[0].split(",")}
        self.assertNotEqual(leaves, SSRF_TRIO, leaves)
        self.assertFalse({"internal-hostname", "internal-reach"} & leaves, leaves)

    def test_victim_credential_exfil_alone_is_a_cross_user_read(self):
        self.assertEqual(G.parse("victim bank-credential exfil")[0], "cross-user-read")

    def test_secret_still_means_a_leaked_key(self):
        self.assertEqual(G.parse("find a leaked api key in the bundle")[0], "secret")
        self.assertEqual(G.parse("read the secret from the config")[0], "secret")

    def test_existing_parses_unchanged(self):
        self.assertEqual(G.parse("achieve zero click ato"), ("ato", ["zero-click"]))
        self.assertEqual(G.parse("fix the login page"), (None, []))


class F2CapturedRoutes(_TmpWS):
    def test_two_raw_captures_both_become_existing_paths(self):
        self.pair("1-a", "GET https://app.zz.test/v8/api/accounts/1234567/transactions.json HTTP/1.1", "200")
        self.jcap("2-b", "https://app.zz.test/guests/login?x=1", 302)
        got = H.existing_paths(PROG)
        self.assertIn("/v8/api/accounts/{id}/transactions.json", got)
        self.assertIn("/guests/login", got)

    def test_a_404_capture_and_an_unknown_status_are_not_routes(self):
        self.pair("1-a", "GET https://app.zz.test/real/route HTTP/1.1", "HTTP/1.1 200 OK", ext=".resp")
        self.pair("1-c", "GET https://app.zz.test/ghost/route HTTP/1.1", "404")
        self.pair("1-d", "GET https://app.zz.test/nostatus/route HTTP/1.1", "content-type: x")
        got = H.existing_paths(PROG)
        self.assertIn("/real/route", got)
        self.assertNotIn("/ghost/route", got)
        self.assertNotIn("/nostatus/route", got)

    def test_nested_raw_dirs_are_harvested(self):
        d = self.raw(sub="flows")
        with open(os.path.join(d, "9.req"), "w") as f:
            f.write("POST https://app.zz.test/oauth/token.json\n")
        with open(os.path.join(d, "9.resp"), "w") as f:
            f.write("HTTP/1.1 401 Unauthorized\n")
        self.assertIn("/oauth/token.json", H.existing_paths(PROG))

    def test_a_captured_route_admits_the_violation_with_another_id(self):
        self.write("hunts/gnoc/known-paths.txt", "/saml/login\n")
        self.pair("1-a", "GET https://app.zz.test/v8/api/accounts/1234567/transactions.json", "200")
        self.assertIsNone(H.unknown_route_refusal(PROG, "GET /v8/api/accounts/999/transactions.json as A"))
        self.assertIsNotNone(H.unknown_route_refusal(PROG, "GET /v8/api/invented/thing?x=1"))

    def test_the_cache_refreshes_when_a_capture_lands(self):
        self.pair("1-a", "GET https://app.zz.test/first/route", "200")
        self.assertIn("/first/route", H.existing_paths(PROG))
        d = self.raw()
        os.utime(d, ns=(1, 1))   # force a distinct mtime signature even on coarse filesystems
        self.pair("1-b", "GET https://app.zz.test/second/route", "302")
        self.assertIn("/second/route", H.existing_paths(PROG))


class F3RootPathAndExample(_TmpWS):
    def test_root_path_with_a_method_is_concrete(self):
        self.assertTrue(H.concrete_input("GET /?locale=ja"))
        self.assertTrue(H.concrete_input("GET https://myaccount.zz.test/?locale=ja as D"))

    def test_root_path_with_a_parameter_is_concrete(self):
        self.assertTrue(H.concrete_input("/?locale=ja with the victim cookie"))

    def test_a_bare_slash_in_prose_is_still_refused(self):
        self.assertFalse(H.concrete_input("the / page is insecure"))

    def test_third_identical_refusal_carries_an_accepted_example(self):
        self.pair("1-a", "GET https://app.zz.test/api/orders/12", "200")
        ctx = A.Ctx({"_turn_user": "hunt", "program": PROG})
        bad = "refused: the violation names no concrete request. Write the ONE crafted request."
        outs = [A._add_refusal_example(ctx, PROG, "add", bad) for _ in range(3)]
        self.assertEqual(outs[0], bad)
        self.assertEqual(outs[1], bad)
        self.assertIn("violation='GET /api/orders", outs[2])
        ex = outs[2].split("violation='", 1)[1].split("'", 1)[0]
        self.assertTrue(H.concrete_input(ex))
        self.assertIsNone(H.unknown_route_refusal(PROG, ex))

    def test_an_accepted_add_is_not_counted(self):
        ctx = A.Ctx({"_turn_user": "hunt"})
        for _ in range(4):
            self.assertEqual(A._add_refusal_example(ctx, PROG, "add", "added H1: x"), "added H1: x")


class F4IdentityPremise(_TmpWS):
    def add(self, assumption, violation):
        out = H.hypothesis(PROG, "add", title="vault fixation", crown="ato", assumption=assumption,
                           violation=violation, prediction="302 to the vault callback carrying a code for D",
                           kill_byte="code=D-owned")
        self.assertTrue(out.startswith("added"), out)
        return H.load(PROG)["hypotheses"][-1]["id"]

    def test_logged_in_victim_premise_without_identity_is_refused(self):
        hid = self.add("the logged-in victim D (cookie session only) is bound to the attacker's flow",
                       "GET /oauth/authorize?client_id=abc123 as D")
        out = A._identity_premise_refusal(PROG, hid, {})
        self.assertIn("needs an identity", out)
        self.assertIn("identities action=list", out)
        self.assertLessEqual(out.count("\n"), 2)

    def test_a_cookie_header_or_named_identity_passes(self):
        hid = self.add("the logged-in victim D", "GET /oauth/authorize?client_id=abc123 as D")
        self.assertEqual(A._identity_premise_refusal(PROG, hid, {"Cookie": "_session=x"}), "")
        self.assertEqual(A._identity_premise_refusal(PROG, hid, {}, named="D"), "")

    def test_an_unauth_premise_is_not_refused(self):
        hid = self.add("the discovery document is public", "GET /.well-known/openid-configuration?x=1")
        self.assertEqual(A._identity_premise_refusal(PROG, hid, {}), "")

    def test_http_request_refuses_before_the_wire_and_counts_nothing(self):
        hid = self.add("the logged-in victim D (cookie session only)", "GET /oauth/authorize?client_id=abc123 as D")
        sent = []
        saved = (A._program_gate, A._send)
        A._program_gate = lambda program, url: ({}, None)
        A._send = lambda *a, **k: sent.append(a) or (_ for _ in ()).throw(AssertionError("sent"))
        try:
            out = A.t_http_request(A.Ctx({"program": PROG}), "https://app.zz.test/oauth/authorize?client_id=abc123",
                                   program=PROG, hypothesis=hid)
        finally:
            A._program_gate, A._send = saved
        self.assertIn("needs an identity", out)
        self.assertEqual(sent, [])
        self.assertEqual(H._find_hyp(H.load(PROG)["hypotheses"], hid)["probes"], 0)

    def test_anon_marks_a_deliberate_unauth_arm(self):
        hid = self.add("the logged-in victim D (cookie session only)", "GET /oauth/authorize?client_id=abc123 as D")
        sent = []
        saved = (A._program_gate, A._send)
        A._program_gate = lambda program, url: ({}, None)

        def fake_send(*a, **k):
            sent.append(a)
            raise RuntimeError("stop here")
        A._send = fake_send
        try:
            A.t_http_request(A.Ctx({"program": PROG}), "https://app.zz.test/oauth/authorize?client_id=abc123",
                             program=PROG, hypothesis=hid, as_identity="anon")
        finally:
            A._program_gate, A._send = saved
        self.assertEqual(len(sent), 1, "as_identity=anon must reach the wire")

    def test_invented_identifier_advisory(self):
        self.write("hunts/lane/NOTES.md", "vault client c88fb2a60f02ded818d436110b20afb1a956b7d3d6c9fbd7a0cef53dd4391694\n")
        saved = A.WS
        A.WS = self.tmp
        A._SEEN_ID_CACHE.clear()
        try:
            real = A._invented_id_note(PROG, "https://x.test/oauth/authorize?client_id="
                                       "c88fb2a60f02ded818d436110b20afb1a956b7d3d6c9fbd7a0cef53dd4391694")
            fake = A._invented_id_note(PROG, "https://x.test/oauth/authorize?client_id="
                                       "c88fb2a6c1e0e0e0e0e0e0e0e0e0e0e0")
        finally:
            A.WS = saved
            A._SEEN_ID_CACHE.clear()
        self.assertEqual(real, "")
        self.assertIn("not seen anywhere on disk", fake)


class F5LeadProbeAdvisory(unittest.TestCase):
    def test_sixth_direct_probe_advises_dispatch(self):
        ctx = A.Ctx({"_turn_user": "go"})
        notes = [A._lead_probe_note(ctx, PROG, "H2") for _ in range(6)]
        self.assertTrue(all(n == "" for n in notes[:5]), notes)
        self.assertIn("dispatch probe_briefs()/claude_worker", notes[5])

    def test_counter_is_per_hypothesis(self):
        ctx = A.Ctx({"_turn_user": "go"})
        for _ in range(5):
            A._lead_probe_note(ctx, PROG, "H2")
        self.assertEqual(A._lead_probe_note(ctx, PROG, "H3"), "")

    def test_a_worker_is_never_advised(self):
        ctx = A.Ctx({"_turn_user": "go", "_worker": True})
        self.assertEqual([A._lead_probe_note(ctx, PROG, "H2") for _ in range(9)], [""] * 9)


class F6SessionPath(_TmpWS):
    POINTER = "# accounts\nPasswords are NOT stored here.\n## C\n- email: c@x.test\n- password: in ~/.config/gnoc/x.env\n"
    HELD = "## A\n- email: a@x.test\n- password: hunter2-fixture\n"

    def test_listing_does_not_promise_passwords_it_has_not_seen(self):
        self.write("ACCOUNTS.md", self.POINTER)
        out = I.listing(PROG)
        self.assertNotIn("for the passwords", out)
        self.assertIn("NOT in ACCOUNTS.md", out)

    def test_listing_points_at_read_file_when_the_file_holds_them(self):
        self.write("ACCOUNTS.md", self.HELD)
        self.assertIn("for the passwords", I.listing(PROG))
        self.assertNotIn("hunter2-fixture", I.listing(PROG))

    def test_listing_prefers_login_when_login_py_exists(self):
        self.write("ACCOUNTS.md", self.POINTER)
        self.write("LOGIN.py", "LOGIN_URL = 'https://app.zz.test/login'\n")
        self.assertIn("identities action=login", I.listing(PROG))

    def test_bash_secret_refusal_names_the_sanctioned_path(self):
        self.write("LOGIN.py", "LOGIN_URL = 'https://app.zz.test/login'\n")
        out = A.t_bash(A.Ctx({"program": PROG}), "cat ~/.config/gnoc/moneytree-staging-accounts.env")
        self.assertTrue(out.startswith("refused"), out)
        self.assertIn("identities action=login", out)
        self.assertLessEqual(out.count("\n"), 2)


FIXTURE_LOGIN = """import json, sys, os
LOGIN_URL = "https://app.zz.test/guests/login"
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ran.marker"), "w").write(sys.argv[-1])
print("noise line")
print(json.dumps({"headers": {"Cookie": "_mt_session=FIXTURE-SESSION-VALUE"}, "source": LOGIN_URL,
                  "note": "fixture login"}))
"""


class F7Login(_TmpWS):
    def test_login_runs_the_script_and_saves_without_echoing_values(self):
        self.write("LOGIN.py", FIXTURE_LOGIN)
        out = I.login(PROG, "D", scope_check=lambda u, p, r: True)
        self.assertTrue(out.startswith("identity D saved"), out)
        self.assertNotIn("FIXTURE-SESSION-VALUE", out)
        self.assertEqual(I.load(PROG)["D"]["headers"]["Cookie"], "_mt_session=FIXTURE-SESSION-VALUE")
        self.assertEqual(I.load(PROG)["D"]["origin"], "app.zz.test")

    def test_out_of_scope_login_url_is_never_run(self):
        self.write("LOGIN.py", FIXTURE_LOGIN)
        out = I.login(PROG, "D", scope_check=lambda u, p, r: False)
        self.assertIn("not in", out)
        self.assertFalse(os.path.exists(os.path.join(self.tdir, "ran.marker")))

    def test_missing_login_url_is_refused(self):
        self.write("LOGIN.py", "print('{}')\n")
        self.assertIn("LOGIN_URL", I.login(PROG, "D", scope_check=lambda u, p, r: True))

    def test_error_json_and_stderr_never_leak(self):
        self.write("LOGIN.py", "import sys\nLOGIN_URL = 'https://app.zz.test/x'\n"
                               "sys.stderr.write('ValueError: password=SECRET-FIXTURE\\n')\nsys.exit(3)\n")
        out = I.login(PROG, "D", scope_check=lambda u, p, r: True)
        self.assertIn("exit 3", out)
        self.assertNotIn("SECRET-FIXTURE", out)

    def test_no_script_says_how(self):
        self.assertIn("no targets/", I.login(PROG, "D", scope_check=lambda u, p, r: True))

    def test_identities_tool_wires_action_login(self):
        self.write("LOGIN.py", FIXTURE_LOGIN)
        saved = I._in_scope
        I._in_scope = lambda u, p, r: True
        try:
            out = A.t_identities(A.Ctx({"program": PROG}), action="login", name="E")
        finally:
            I._in_scope = saved
        self.assertTrue(out.startswith("identity E saved"), out)
        self.assertIn("login", A.TOOLS["identities"][1]["function"]["parameters"]["properties"]["action"]["enum"])


class F9CloudRetry(unittest.TestCase):
    def setUp(self):
        import gnoc_cloud
        self.gc = gnoc_cloud
        self.saved = (A._openai_chat, A._cloud_wait, A._econ_llm, gnoc_cloud.endpoint, A._note_retry)
        gnoc_cloud.endpoint = lambda host, model: ("http://fake.invalid/v1/chat/completions", "fake-model", {})
        A._econ_llm = lambda *a, **k: None
        A._note_retry = lambda *a, **k: None
        self.waits = []
        A._cloud_wait = lambda s: self.waits.append(s) or False
        A.INTERRUPT.clear()

    def tearDown(self):
        A._openai_chat, A._cloud_wait, A._econ_llm, self.gc.endpoint, A._note_retry = self.saved

    def transport(self, errors):
        calls = []

        def fake(messages, tools, on_text, *a, **k):
            calls.append(1)
            if errors:
                raise errors.pop(0)
            return {"content": "ok", "usage": {}}
        A._openai_chat = fake
        return calls

    def test_fails_twice_then_succeeds(self):
        calls = self.transport([http.client.RemoteDisconnected("Remote end closed connection without response"),
                                ConnectionResetError("reset")])
        out = A._llm_chat_once("deepseek-chat", "deepseek", [{"role": "user", "content": "hi"}])
        self.assertEqual(out["content"], "ok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.waits, [2, 5])

    def test_gives_up_after_three_retries(self):
        calls = self.transport([TimeoutError("t")] * 5)
        with self.assertRaises(TimeoutError):
            A._llm_chat_once("deepseek-chat", "deepseek", [{"role": "user", "content": "hi"}])
        self.assertEqual(len(calls), 4)
        self.assertEqual(self.waits, [2, 5, 10])

    def test_502_is_transient_but_400_is_not(self):
        self.assertTrue(A._transient_cloud_error(urllib.error.HTTPError("u", 502, "bad gateway", {}, None)))
        self.assertFalse(A._transient_cloud_error(urllib.error.HTTPError("u", 400, "bad", {}, None)))
        calls = self.transport([ValueError("bad request shape")])
        with self.assertRaises(ValueError):
            A._llm_chat_once("deepseek-chat", "deepseek", [{"role": "user", "content": "hi"}])
        self.assertEqual(len(calls), 1)

    def test_no_retry_after_text_reached_the_screen(self):
        def fake(messages, tools, on_text, *a, **k):
            on_text("partial")
            raise ConnectionResetError("mid-stream")
        A._openai_chat = fake
        with self.assertRaises(ConnectionResetError):
            A._llm_chat_once("deepseek-chat", "deepseek", [{"role": "user", "content": "hi"}], on_text=lambda d: None)
        self.assertEqual(self.waits, [])


class F9GoalReentry(unittest.TestCase):
    class Agent:
        def __init__(self, transient_times):
            self.s = {"sid": "sidX", "_lead_transient": True}
            self.ctx = A.Ctx(self.s)
            self.interrupted = False
            self.left = transient_times
            self.hunts = []

        def hunt(self, prog, text):
            self.hunts.append(prog)
            self.left -= 1
            if self.left > 0:
                self.s["_lead_transient"] = True

        def turn(self, text):
            self.hunts.append(None)

    def setUp(self):
        self.saved = (G.load, A.say, A.WS)
        A.say = lambda *a, **k: None
        # _goal_reenter yields to the LIVE workspace's STOP file. Read the real one and this suite
        # goes red the moment GreyNOC stops a hunt by hand - a real stop, not a code defect.
        self.ws = tempfile.mkdtemp(prefix="gnoc-f9-test-")
        A.WS = self.ws

    def tearDown(self):
        G.load, A.say, A.WS = self.saved
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_reenters_the_goal_loop_after_a_transient_death(self):
        G.load = lambda: {"status": "active", "sid": "sidX", "text": "goal", "program": PROG}
        ag = self.Agent(1)
        self.assertEqual(A._goal_reenter(ag), 1)
        self.assertEqual(ag.hunts, [PROG])

    def test_bounded(self):
        G.load = lambda: {"status": "active", "sid": "sidX", "text": "goal", "program": PROG}
        ag = self.Agent(99)
        self.assertEqual(A._goal_reenter(ag), A.GOAL_REENTRY_MAX)

    def test_no_goal_or_foreign_goal_means_no_reentry(self):
        G.load = lambda: {"status": "active", "sid": "someoneElse", "text": "goal", "program": PROG}
        ag = self.Agent(1)
        self.assertEqual(A._goal_reenter(ag), 0)
        self.assertEqual(ag.hunts, [])

    def test_no_transient_flag_means_no_reentry(self):
        G.load = lambda: {"status": "active", "sid": "sidX", "text": "goal", "program": PROG}
        ag = self.Agent(1)
        ag.s.pop("_lead_transient")
        self.assertEqual(A._goal_reenter(ag), 0)


if __name__ == "__main__":
    unittest.main(verbosity=1)
