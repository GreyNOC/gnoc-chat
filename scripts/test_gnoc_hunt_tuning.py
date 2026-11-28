"""Hunt tuning of 2026-10-25 (stdlib unittest, a throwaway ledger, no network).

Measured on the three richest gnoc ledgers before the change: program-101 spent 40 of 84 probes on an invented route
(app.example.com/api/v1/admin/twin, 403 len=35 every time), two hypotheses PREDICTED that 403, program-0 "proved"
unauth -> cross-user-read on the prober's own ownerId, three titles were "H5: ..." hops on other hypotheses, and a
violation of "malformed token accepted" was accepted. These tests pin the gates that refuse each shape and the two
directive phases (SURFACE, VERDICT) that stop a walled or verdict-owed hypothesis from eating turns."""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_hunt as H  # noqa: E402

PROG = "zz-hunttune"


class _Ledger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-hunttune-")
        self.saved = (H.path, H.WS)
        H.WS = self.tmp
        H.path = lambda program: os.path.join(self.tmp, "targets", program, "hunts", "gnoc", "ledger.json")
        os.makedirs(os.path.dirname(H.path(PROG)), exist_ok=True)
        H.model(PROG, "add", boundaries="B1: orders are readable only by their owner; excludes other customers")

    def tearDown(self):
        H.path, H.WS = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def add(self, **kw):
        base = dict(title="order read by a stranger", crown="cross-user-read", boundary="B1", assumption="a",
                    violation="GET /api/orders/{B's id} as A", prediction="200 with B's address in the body",
                    kill_byte="B-street-42")
        base.update(kw)
        return H.hypothesis(PROG, "add", **base)

    def capture(self, name, url, status, body="x" * 35):
        d = os.path.join(self.tmp, "targets", PROG, "hunts", "lane", "raw")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name + ".json")
        with open(p, "w") as f:
            json.dump({"request": {"method": "GET", "url": url}, "response": {"status": status, "body": body}}, f)
        return p


class HypothesisGates(_Ledger):
    def test_a_good_hypothesis_is_added(self):
        self.assertTrue(self.add().startswith("added H1"))

    def test_a_violation_with_no_concrete_input_is_refused(self):
        for v in ("malformed token accepted", "Concurrent race on the single-use/check-then-act request",
                  "Send a crafted state token that passes validation",
                  # D93: H44 (cycle 25) was admitted on the bare word "body"
                  "Drifted sibling endpoint returns private body (positive control) while enforcing sibling returns 403",
                  "the header is replayed to the sibling", "mutate the field or parameter the developer trusted",
                  # D101: a method with no path is not a request (H49, cycle 28)
                  "POST body with state pointing to a different session than the session_id",
                  "replay header X-Session on the sibling", "field dest_id set to B's id"):
            out = self.add(violation=v)
            self.assertIn("names no concrete request", out, v)
        for v in ("POST /api/v1/transfer dest_id=B", "method=GET path=/me", "replay the X-Session header on /xy",
                  "GET /api/session bucket=13", "set the cookie to A's then PATCH /profile",
                  "replay header X-Session on /api/sibling", "field dest_id set to B's id on /api/transfer",
                  "param redirect_uri as B on /oauth/authorize", "cookie sessionId from A on /api/me",
                  "json key event_source mutated in POST /api/event_logging/v2/batch"):
            self.assertTrue(H.concrete_input(v), v)
        self.assertEqual(H.load(PROG)["hypotheses"], [])

    def test_a_prediction_that_is_the_refusal_is_refused(self):
        out = self.add(prediction="HTTP 403 len=35 with error_code:40003 on admin twin, confirming the LEAD state")
        self.assertIn("describes a refusal", out)
        out = self.add(prediction="200 for the owner, 403 for the stranger: the 200 leaks B's address")
        self.assertTrue(out.startswith("added"), out)          # names the grant too: fine
        out = self.add(title="kb", prediction="200 with B's address", kill_byte="error_code:40003")
        self.assertIn("error marker", out)

    def test_a_self_read_is_not_a_crossing(self):
        out = self.add(prediction="Response contains owner's PII fields (email, name) in both concurrent responses",
                       kill_byte='"ownerId":"<own-id>" AND "email":"<own-email>"')
        self.assertIn("OWN data", out)
        self.assertIn("T-43", out)
        # the same words aimed at the other party pass
        out = self.add(prediction="A's response carries the other user's ownerId and email", kill_byte='"ownerId":"B"')
        self.assertTrue(out.startswith("added"), out)
        # and a non-crossing crown is not judged by this rule
        out = self.add(title="rce", crown="rce", prediction="my own id echoed by the template engine as 49",
                       kill_byte="49")
        self.assertTrue(out.startswith("added"), out)

    def test_a_title_that_is_a_hop_on_another_hypothesis_is_refused(self):
        self.add()
        for t in ("H5: websocket drift on admin twin", "H2-escalate: same defect on the staff host", "h1 - paired write"):
            out = self.add(title=t, violation="POST /api/v1/admin/twin type=drift")
            self.assertIn("escalation HOP", out, t)
        self.assertEqual(len(H.load(PROG)["hypotheses"]), 1)

    def test_score_hypothesis_applies_the_same_gates(self):
        good = {"title": "t", "crown": "cross-user-read", "assumption": "a", "violation": "GET /orders/{B} as A",
                "prediction": "200 with B's address", "kill_byte": "B-street"}
        self.assertGreater(H.score_hypothesis(good)[0], 0)
        self.assertEqual(H.score_hypothesis(dict(good, prediction="403 error_code 40003"))[0], -1)
        self.assertEqual(H.score_hypothesis(dict(good, prediction="my own email back", kill_byte="<own-email>"))[0], -1)
        self.assertEqual(H.score_hypothesis(dict(good, violation="malformed token accepted"))[0], -1)


class RouteWalls(_Ledger):
    def _wall(self, n=6, hyp="H1"):
        for i in range(n):
            H.log_probe(PROG, hyp, self.capture(f"w{i}", "https://www.t.example/api/v1/admin/twin?x=1", 403))

    def test_probes_on_a_route_that_only_refuses_do_not_count(self):
        self.add()
        self._wall(6)
        H.log_probe(PROG, "H1", self.capture("ok", "https://www.t.example/api/orders/1", 200, "real body"))
        h = H.load(PROG)["hypotheses"][0]
        self.assertEqual(h["probes"], 7)
        self.assertEqual(H.walled_routes(h), [("www.t.example/api/v1/admin/twin", "403:35", 6)])
        self.assertEqual(H.counted_probes(h), 1)
        self.assertEqual(H.floor_status(PROG, "H1"), (7, 0))
        self.assertEqual(H.floor_status(PROG, "H1", counted=True), (1, 0))
        self.assertIn("only 1 of 7 probes count toward the floor of 8", H.hypothesis(PROG, "list"))

    def test_a_route_that_answered_once_is_not_a_wall(self):
        self.add()
        self._wall(6)
        H.log_probe(PROG, "H1", self.capture("ok", "https://www.t.example/api/v1/admin/twin", 200, "it exists"))
        h = H.load(PROG)["hypotheses"][0]
        self.assertEqual(H.walled_routes(h), [])
        self.assertEqual(H.counted_probes(h), 7)

    def test_mixed_refusals_on_a_route_are_not_one_wall(self):
        """A route that answers 400, 401, 403 and 405 to different inputs is being parsed: that is a surface."""
        self.add()
        for i, st in enumerate((400, 401, 403, 405, 400, 403)):
            H.log_probe(PROG, "H1", self.capture(f"m{i}", "https://www.t.example/api/x", st, "e" * (10 + i)))
        self.assertEqual(H.walled_routes(H.load(PROG)["hypotheses"][0]), [])

    def test_dead_on_a_wall_is_unfired_with_the_fix(self):
        self.add()
        self._wall(9)
        out = H.hypothesis(PROG, "update", id="H1", status="dead", notes="not single-use: plain read")
        self.assertIn("refused DEAD", out)
        self.assertIn("ROUTE WALL", out)
        self.assertIn("T-49", out)
        self.assertIn("positive control", out)
        self.assertEqual(H.load(PROG)["hypotheses"][0]["status"], "unfired")

    def test_dead_past_the_floor_on_a_real_route_still_works(self):
        self.add()
        for i in range(8):
            H.log_probe(PROG, "H1", self.capture(f"r{i}", f"https://www.t.example/api/orders/{i}", 200, "own order"))
        out = H.hypothesis(PROG, "update", id="H1", status="dead", notes="not single-use: a plain read, no one-shot")
        self.assertIn("-> dead", out)

    def test_non_capture_evidence_records_no_route(self):
        self.add()
        H.log_probe(PROG, "H1", "")
        H.log_probe(PROG, "H1", os.path.join(self.tmp, "missing.json"))
        h = H.load(PROG)["hypotheses"][0]
        self.assertEqual(h["probes"], 2)
        self.assertNotIn("routes", h)


class DirectivePhases(_Ledger):
    def _brief(self):
        H.brief(PROG)

    def test_surface_phase_then_parked_unfired(self):
        self.add()
        for i in range(6):
            H.log_probe(PROG, "H1", self.capture(f"w{i}", "https://www.t.example/api/v1/admin/twin", 403))
        d1 = H.directive(PROG, briefed=True)
        self.assertIn("PHASE SURFACE H1", d1)
        self.assertIn("ROUTE WALL", d1)
        self.assertIn("turn 1 of 2", d1)
        d2 = H.directive(PROG, briefed=True)
        self.assertIn("turn 2 of 2", d2)
        d3 = H.directive(PROG, briefed=True)
        self.assertIn("PHASE SURFACE PARKED H1", d3)
        h = H.load(PROG)["hypotheses"][0]
        self.assertEqual(h["status"], "unfired")
        self.assertIn("parked UNFIRED", h["notes"])
        self.assertNotIn("SURFACE", H.directive(PROG, briefed=True))   # off the live list; the loop moves on

    def test_a_positive_control_releases_the_surface_phase(self):
        self.add()
        for i in range(6):
            H.log_probe(PROG, "H1", self.capture(f"w{i}", "https://www.t.example/api/v1/admin/twin", 403))
        self.assertIn("PHASE SURFACE", H.directive(PROG, briefed=True))
        for i in range(8):
            H.log_probe(PROG, "H1", self.capture(f"ok{i}", f"https://www.t.example/api/orders/{i}", 200, "real"))
        d = H.directive(PROG, briefed=True)
        self.assertNotIn("PHASE SURFACE", d)                            # 8 counted probes on a real route: released
        self.assertIn("6 hit a route that never answered", H.hypothesis(PROG, "list"))   # still on the record

    def test_verdict_phase_then_parked(self):
        self.add()
        for i in range(H.VERDICT_AT):
            H.log_probe(PROG, "H1", self.capture(f"r{i}", f"https://www.t.example/api/orders/{i}", 200, "own"))
        d1 = H.directive(PROG, briefed=True)
        self.assertIn("PHASE VERDICT H1", d1)
        self.assertIn("NO burst yet", d1)
        self.assertIn("race(hypothesis='H1')", d1)
        H.directive(PROG, briefed=True)
        d3 = H.directive(PROG, briefed=True)
        self.assertIn("PHASE VERDICT PARKED H1", d3)
        self.assertEqual(H.load(PROG)["hypotheses"][0]["status"], "unfired")

    def test_a_verdict_given_in_time_ends_the_phase(self):
        self.add()
        for i in range(H.VERDICT_AT):
            H.log_probe(PROG, "H1", self.capture(f"r{i}", f"https://www.t.example/api/orders/{i}", 200, "own"))
        self.assertIn("PHASE VERDICT", H.directive(PROG, briefed=True))
        H.hypothesis(PROG, "update", id="H1", status="dead", notes="not single-use: plain owner read")
        d = H.directive(PROG, briefed=True)
        self.assertNotIn("VERDICT", d)
        self.assertIn("PHASE HYPOTHESIZE", d)

    def test_probe_phase_prefers_the_hypothesis_with_fewest_counted_probes(self):
        self.add(title="a", crown="ato", violation="GET /alpha/1")
        self.add(title="b", crown="ato", violation="GET /bravo/1")
        self.add(title="c", crown="ato", violation="GET /charlie/1")
        for i in range(5):   # H1 looks the busiest (13 probes) but 5 of them are wall: 8 count
            H.log_probe(PROG, "H1", self.capture(f"w{i}", "https://www.t.example/ghost", 404, "nf"))
        for i in range(8):
            H.log_probe(PROG, "H1", self.capture(f"a{i}", f"https://www.t.example/a/{i}", 200, "real"))
        for i in range(9):
            H.log_probe(PROG, "H2", self.capture(f"b{i}", f"https://www.t.example/b/{i}", 200, "real"))
        for i in range(10):
            H.log_probe(PROG, "H3", self.capture(f"c{i}", f"https://www.t.example/c/{i}", 200, "real"))
        d = H.directive(PROG, briefed=True)
        self.assertIn("PHASE PROBE H1", d)          # fewest COUNTED probes (a raw sort would have picked H2)
        self.assertIn("8 probes count", d)
        self.assertIn("ROUTE WALL", d)
        self.assertEqual([b[0] for b in H.probe_briefs(PROG, 3)], ["H1", "H2", "H3"])
        self.assertIn("ROUTE WALL", H.probe_briefs(PROG, 1)[0][1])      # a worker is told not to re-probe it



class ProofIntegrity(_Ledger):
    """2026-10-25: program-0 E1 'proved' unauth -> cross-user-read with two copies of an 85 KB SPA shell (evidence 200
    text/html, control 200 within 1% of its length, no claimed byte) and program-101 H2-escalate 'proved' unauth -> ato with a
    403 error_code 40003 as both evidence and control. _proof_shape refuses each shape; heal_proofs re-judges stored
    proofs with today's gates."""
    SHELL = "<!DOCTYPE html><html><head><title>app</title></head><body><div id=root></div>" + "s" * 4000 + "</body></html>"

    def proven(self, ev, to="cross-user-read", mc=None, ctl=None, via="GET /api/orders/{B id} as A"):
        return H.edge(PROG, "add", frm="own-account", to=to, via=via, status="proven", evidence=ev,
                      must_contain=mc, control=ctl)

    def status(self):
        return H.load(PROG)["edges"][-1]["status"]

    def test_a_crown_proof_without_a_terminal_byte_is_not_proven(self):
        ev = self.capture("pos", "https://t/api/orders/2", 200, '{"id":2,"email":"b@x.com"}')
        out = self.proven(ev)
        self.assertNotIn("[proven]", out)
        # the proof gate drops it to lead, and the existing crown lead gate (a crown lead names its byte) one more
        self.assertEqual(self.status(), "hypothesized")
        ok, why = H._proof_shape(ev, None, "", "cross-user-read")
        self.assertFalse(ok)
        self.assertIn("must_contain", why)
        # a non-crown hop needs no byte from this gate
        self.assertTrue(H._proof_shape(ev, None, "", "ws-access")[0])

    def test_an_html_shell_is_not_even_a_lead(self):
        # drive cycle 10 (2026-10-26): generic markup as must_contain ('<div id=root>') is in every page the host
        # serves; the proof gate drops the offer and the lead gate refuses the markup, so the edge stays hypothesized
        ev = self.capture("shell", "https://t/oauth/callback", 200, self.SHELL)
        out = self.proven(ev, mc="<div id=root>")
        self.assertNotIn("[proven]", out)
        self.assertIn("generic markup", out)
        self.assertEqual(self.status(), "hypothesized")

    def test_a_control_that_answers_the_same_is_stored_as_lead(self):
        body = '{"id":2,"email":"b@x.com","orders":[' + "1," * 200 + '1]}'
        ev = self.capture("pos", "https://t/api/orders/2", 200, body)
        ctl = self.capture("neg", "https://t/api/orders/2?as=anon", 200, body.replace("b@x.com", "c@x.com"))
        out = self.proven(ev, mc='"email":"b@x.com"', ctl=ctl)
        self.assertIn("stored as LEAD, not proven", out)
        self.assertIn("shows no boundary", out)
        self.assertEqual(self.status(), "lead")

    def test_a_real_proof_is_stored_proven(self):
        ev = self.capture("pos", "https://t/api/orders/2", 200, '{"id":2,"email":"b@x.com","street":"B-street-42"}')
        ctl = self.capture("neg", "https://t/api/orders/2", 403, '{"error":"forbidden"}')
        out = self.proven(ev, mc='"email":"b@x.com"', ctl=ctl)
        self.assertIn("[proven]", out)
        self.assertNotIn("no negative control", out)
        self.assertEqual(self.status(), "proven")
        # a hand-written note is not a capture: a proven edge needs a raw JSON request+response (the gate tightened
        # in the 2026-11-22 bug-bounty drive; this used to pass on check_evidence alone)
        txt = os.path.join(self.tmp, "targets", PROG, "hunts", "lane", "raw", "notes.txt")
        with open(txt, "w") as f:
            f.write("email b@x.com")
        ok, why = H._proof_shape(txt, None, "b@x.com", "cross-user-read")
        self.assertFalse(ok)
        self.assertIn("not a raw JSON ca", why)

    def test_heal_proofs_demotes_a_planted_bogus_proof_and_keeps_a_good_one(self):
        good = self.capture("pos", "https://t/api/orders/2", 200, '{"id":2,"email":"b@x.com"}')
        gctl = self.capture("neg", "https://t/api/orders/2", 403, '{"error":"forbidden"}')
        shell = self.capture("shell", "https://t/oauth/callback", 200, self.SHELL)
        sctl = self.capture("shell2", "https://t/oauth/callback", 200, self.SHELL[:-20] + "</body></html>")
        r403 = self.capture("r403", "https://t/api/v1/admin/twin", 403, '{"error_msg":"","error_code":40003}')

        def plant(d):
            base = {"frm": "unauth", "requires": [], "ts": H._now(), "control_na": "", "via": "planted"}
            d["edges"] += [dict(base, id="E1", to="cross-user-read", status="proven", evidence=shell,
                                must_contain="", control=sctl),
                           dict(base, id="E2", to="cross-user-read", status="proven", evidence=good,
                                must_contain='"email":"b@x.com"', control=gctl),
                           dict(base, id="E3", to="ato", status="proven", evidence=r403, must_contain="",
                                control=r403),
                           dict(base, id="E4", to="ws-access", status="proven", evidence=shell + ".gone",
                                must_contain="", control="")]
        H.modify(PROG, plant)
        out = {i: (s, w) for i, s, w in H.heal_proofs(PROG)}
        self.assertEqual(set(out), {"E1", "E3", "E4"})
        self.assertEqual(out["E1"][0], "hypothesized")        # crown with no byte fails the lead gate too
        self.assertEqual(out["E3"][0], "hypothesized")        # a 403 is not even a mechanism
        self.assertEqual(out["E4"][0], "hypothesized")        # check_evidence fails: the file is gone
        self.assertIn("does not exist", out["E4"][1])
        E = {e["id"]: e for e in H.load(PROG)["edges"]}
        self.assertEqual(E["E2"]["status"], "proven")
        self.assertNotIn("note", E["E2"])
        self.assertIn("[demoted from proven: ", E["E1"]["note"])
        self.assertEqual(H.heal_proofs(PROG), [])               # idempotent: nothing left to demote
        self.assertEqual(H.heal_proofs("zz-no-such-ledger"), [])
        self.assertFalse(os.path.exists(H.path("zz-no-such-ledger")))

    def test_heal_demotes_to_lead_when_the_lead_gate_holds(self):
        ev = self.capture("shell", "https://t/oauth/callback", 200, self.SHELL)
        H.modify(PROG, lambda d: d["edges"].append(
            {"id": "E1", "frm": "unauth", "to": "cross-user-read", "via": "planted", "status": "proven",
             "evidence": ev, "must_contain": "<div id=root>", "requires": [], "ts": H._now(), "control": "",
             "control_na": ""}))
        [(eid, new, why)] = H.heal_proofs(PROG)
        self.assertEqual((eid, new), ("E1", "lead"))
        self.assertIn("T-60", why)


class LeadMustSendTheViolationInput(unittest.TestCase):
    """D96: a lead capture whose request never carries the violation's input is the baseline."""

    def test_violation_inputs_are_extracted(self):
        self.assertEqual(H.violation_inputs("POST /api/event_logging/v2/batch with X-Partner-Token header"), {"x-partner-token"})
        self.assertEqual(H.violation_inputs("POST /api/v1/transfer dest_id=B as A"), {"dest_id"})
        self.assertEqual(H.violation_inputs("replay the X-Session header on /x; field redirect_uri as B"),
                         {"x-session", "redirect_uri"})
        self.assertEqual(H.violation_inputs("GET /v1/models"), set())

    def test_capture_sends_reads_the_request(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "c.json")
            json.dump({"request": {"method": "POST", "url": "https://h/api/batch", "headers": {"X-HackerOne-Handle": "x"},
                                   "body": None}, "response": {"status": 200, "body": "{\"accepted_count\":0}"}}, open(fp, "w"))
            with __import__("unittest.mock", fromlist=["mock"]).patch.object(H, "WS", td):
                self.assertEqual(H.capture_sends("c.json", {"x-partner-token"}), ([], ["x-partner-token"]))
            json.dump({"request": {"method": "POST", "url": "https://h/api/batch",
                                   "headers": {"X-Partner-Token": "abc"}, "body": "{}"}, "response": {"status": 200, "body": "{}"}},
                      open(fp, "w"))
            with __import__("unittest.mock", fromlist=["mock"]).patch.object(H, "WS", td):
                self.assertEqual(H.capture_sends("c.json", {"x-partner-token"}), (["x-partner-token"], []))
            self.assertEqual(H.capture_sends("c.json", set()), ([], []))

    def test_the_gate_names_the_missing_input(self):
        src = open(H.__file__).read()
        self.assertIn("present, missing = capture_sends(ev, names)", src)
        self.assertIn("never sends the violation's own input", src)


class ProofSendsTheInputAndControlsOneVariable(unittest.TestCase):
    """D98: the H47-edge shape (plain POST 200 vs GET 404, hypothesis names a header) is not a proof."""

    def _cap(self, td, name, method, body_resp, status, headers=None, url="https://h/api/batch"):
        import json
        fp = os.path.join(td, name)
        json.dump({"request": {"method": method, "url": url, "headers": headers or {"X-HackerOne-Handle": "g"}, "body": None},
                   "response": {"status": status, "headers": {"content-type": "application/json"}, "body": body_resp}}, open(fp, "w"))
        return name

    def test_the_h47_shape_is_refused_and_the_real_shape_passes(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            ev = self._cap(td, "ev.json", "POST", '{"accepted_count":0,"rejected_count":0}', 200)
            ct = self._cap(td, "ct.json", "GET", '{"type":"error"}', 404)
            hyp = {"id": "H47", "violation": "POST /api/batch with X-Partner-Token header"}
            with mock.patch.object(H, "WS", td), mock.patch.object(H, "load", return_value={"hypotheses": [hyp]}):
                ok, why = H._proof_shape(ev, ct, "accepted_count", "ato", "p", "H47-edge")
                self.assertFalse(ok); self.assertIn("never sends H47's own input (x-partner-token)", why)
                ev2 = self._cap(td, "ev2.json", "POST", '{"accepted_count":1,"user":"b"}', 200,
                                headers={"X-HackerOne-Handle": "g", "X-Partner-Token": "abc"})
                ct2 = self._cap(td, "ct2.json", "POST", '{"type":"error"}', 401)
                ok, why = H._proof_shape(ev2, ct2, '"user":"b"', "ato", "p", "H47-edge")
                self.assertTrue(ok, why)

    def test_a_byte_the_control_also_carries_is_the_baseline(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ev = self._cap(td, "ev.json", "POST", '{"accepted_count":0}', 200)
            ct = self._cap(td, "ct.json", "POST", '{"accepted_count":0}', 200, url="https://h/api/batch?x=1")
            from unittest import mock
            with mock.patch.object(H, "WS", td):
                ok, why = H._proof_shape(ev, ct, "accepted_count", "ato")
            self.assertFalse(ok); self.assertIn("CONTROL's body as well", why)

    def test_a_control_that_differs_in_two_variables_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ev = self._cap(td, "ev.json", "POST", '{"user":"b"}', 200, headers={"X-HackerOne-Handle": "g", "X-T": "1"})
            ct = self._cap(td, "ct.json", "GET", '{"type":"error"}', 404)
            from unittest import mock
            with mock.patch.object(H, "WS", td):
                ok, why = H._proof_shape(ev, ct, '"user":"b"', "ato")
            self.assertFalse(ok); self.assertIn("2 variables", why)


class EdgeLeadSendsTheInput(unittest.TestCase):
    def test_rejudge_drops_a_baseline_lead_to_hypothesized(self):
        import json, tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            json.dump({"request": {"method": "POST", "url": "https://h/api/batch", "headers": {"X-HackerOne-Handle": "g"}, "body": None},
                       "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": '{"accepted_count":0}'}},
                      open(os.path.join(td, "ev.json"), "w"))
            json.dump({"request": {"method": "GET", "url": "https://h/api/batch", "headers": {}, "body": None},
                       "response": {"status": 404, "headers": {}, "body": '{"type":"error"}'}}, open(os.path.join(td, "ct.json"), "w"))
            hyp = {"id": "H47", "violation": "POST /api/batch with X-Partner-Token header"}
            e = {"id": "H47-edge", "frm": "unauth", "to": "ato", "status": "proven", "evidence": "ev.json",
                 "control": "ct.json", "must_contain": "accepted_count"}
            with mock.patch.object(H, "WS", td), mock.patch.object(H, "load", return_value={"hypotheses": [hyp]}):
                new, why = H._rejudge_proven(e, "p")
            self.assertEqual(new, "hypothesized"); self.assertIn("never sends H47's own input", why)


class DeepDiveDossier(unittest.TestCase):
    def test_the_dossier_lays_out_crown_chains_with_their_requests_walls_and_precondition(self):
        import tempfile
        from unittest import mock
        with tempfile.TemporaryDirectory() as td:
            ledger = {"hypotheses": [{"id": "H7", "status": "unfired", "title": "OAuth vault state drift", "assumption": "state is bound",
                                      "violation": "GET /oauth/vault/callback state=<B's state> as A", "kill_byte": '"user_id"',
                                      "prediction": "200 carrying B's user_id", "routes": {"h/oauth/vault/callback": {"404:117": 6}}}],
                      "edges": [{"id": "H7-edge", "frm": "unauth", "to": "ato", "status": "hypothesized", "via": "oauth-vault", "ts": "t"},
                                {"id": "E9", "frm": "unauth", "to": "info", "status": "hypothesized", "via": "x", "ts": "t"}]}
            with mock.patch.object(H, "WS", td), mock.patch.object(H, "load", return_value=ledger), \
                    mock.patch.object(H, "program_walls", return_value={"h/oauth/vault/callback": ("404:117", 6)}), \
                    mock.patch.object(H, "surface_exhausted", return_value=([], 10, [])):
                path, summary = H.deep_dive("p")
                self.assertFalse(H.deep_dive_due("p"))
            text = open(path).read()
            self.assertIn("H7-edge: unauth -> ato", text)
            self.assertIn("the request: GET /oauth/vault/callback state=<B's state> as A", text)
            self.assertIn("(WALL)", text); self.assertIn("Without an identity this chain cannot advance", text)
            self.assertNotIn("E9", text)                       # not crown-bound
            self.assertIn("1 crown chains laid out", summary)


if __name__ == "__main__":
    unittest.main()


class ClassPrecisionNote(unittest.TestCase):
    """The measured class-EV table must reach the moment a hypothesis is written.

    Receipt (2026-10-27): our own adjudicated record is IDOR 6% positive over 16 reports with 69%
    duplicates and Information Disclosure 12% over 26 - the two classes we hunt hardest - against
    Business Logic at 83% (5/6), barely hunted. That table lived only in an injected prose blob which
    was itself over the auto-load ceiling and being silently truncated, so it never reached the
    decision. It warns, it never refuses: the class is INFERRED from wording and a guess must not
    block real work.
    """

    def setUp(self):
        # The ledger is the operator's adjudicated record (research/ never ships). A fresh install gets the same
        # rows, so the note is still tested where the real ledger is absent.
        import gnoc_hunt
        if os.path.isfile(gnoc_hunt._PRECISION_LEDGER):
            return
        d = tempfile.mkdtemp(prefix="gnoc-precision-")
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "PRECISION-LEDGER.json")
        rows = {"Insecure Direct Object Reference (IDOR)": {"n": 16, "positive": 1, "precision_pct": 6,
                                                            "duplicates": 11, "dupe_pct": 69},
                "Information Disclosure": {"n": 26, "positive": 3, "precision_pct": 12, "duplicates": 6,
                                           "dupe_pct": 23},
                "Business Logic": {"n": 6, "positive": 5, "precision_pct": 83, "duplicates": 0, "dupe_pct": 0}}
        with open(path, "w") as fh:
            json.dump({"by_class": rows}, fh)
        saved = gnoc_hunt._PRECISION_LEDGER
        gnoc_hunt._PRECISION_LEDGER = path
        self.addCleanup(setattr, gnoc_hunt, "_PRECISION_LEDGER", saved)

    def test_a_trap_class_hypothesis_gets_the_numbers(self):
        import gnoc_hunt
        note = gnoc_hunt.class_precision_note(
            "cross-user order read via object reference", "GET /api/v1/orders/1002 id=<B order>", "200")
        self.assertIn("CLASS WARNING", note)
        self.assertIn("IDOR", note)
        self.assertIn("Business Logic 83%", note)

    def test_information_disclosure_is_also_a_trap(self):
        import gnoc_hunt
        self.assertIn("CLASS WARNING",
                      gnoc_hunt.class_precision_note("information disclosure on the status route", "GET /x", "200"))

    def test_a_good_converter_is_left_alone(self):
        import gnoc_hunt
        self.assertEqual("", gnoc_hunt.class_precision_note(
            "spend cap debited on success not commit", "POST /api/v1/charge amount=100", "200"))

    def test_a_missing_ledger_is_not_an_error(self):
        import gnoc_hunt
        saved = gnoc_hunt._PRECISION_LEDGER
        try:
            gnoc_hunt._PRECISION_LEDGER = "/nonexistent/precision.json"
            self.assertEqual("", gnoc_hunt.class_precision_note("idor on orders", "GET /x", "200"))
        finally:
            gnoc_hunt._PRECISION_LEDGER = saved


class SourceLane(_Ledger):
    """2026-11-02: a repo-asset program (SOURCE_CODE) is probed by building the code and running the
    extracted sink, so its violation names a file:line and a crafted value, not a url. The proven
    node-problem-detector health-checker exec was refused twice for having no route: the input gate demanded a
    known-paths route and the ghost-route gate read '/usr/bin/touch' out of the payload as an HTTP path."""

    SRC = ("SINK pkg/healthchecker/health_checker_linux.go:90 checkForPattern() passes service, logStartTime and "
           "logPattern into /bin/sh -c; INPUT --log-pattern 'nomatch\"; touch gnoc_pwn; #'")

    def test_a_source_violation_with_a_location_and_a_value_is_admitted(self):
        out = self.add(violation=self.SRC, title="health checker shell injection")
        self.assertTrue(out.startswith("added H1"), out)

    def test_a_source_violation_with_no_crafted_value_is_still_refused(self):
        out = self.add(violation="SINK pkg/healthchecker/health_checker_linux.go:90 checkForPattern is unsafe")
        self.assertIn("names no concrete request", out, out)

    def test_a_pathless_violation_with_no_location_is_still_refused(self):
        out = self.add(violation="the health checker is insecure when given a crafted value")
        self.assertIn("names no concrete request", out, out)

    def test_a_source_path_is_not_treated_as_a_ghost_route(self):
        self.assertIsNone(H.unknown_route_refusal(PROG, self.SRC))

    def test_a_real_ghost_route_is_still_refused(self):
        # the fixture's known-paths has no file, so a 404 route needs a mined one first
        d = os.path.dirname(H.path(PROG))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "known-paths.txt"), "w") as f:
            f.write("/api/v1/orders\n")
        out = H.unknown_route_refusal(PROG, "GET /api/v1/admin/twin?x=1")
        self.assertIsNotNone(out)
        self.assertIn("does not exist on", out)
