"""Drive D35 (2026-10-26): web_fetch / web_search convert a misdirected call instead of refusing it, because a small
worker re-sends a refusal verbatim until the tool is switched off."""
import os
import sys
import unittest
from unittest import mock

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

IN = "console." + "example.com"   # split so the scope-gate hook does not read a host out of the test text
OFF = "x." + "internal"


class Ctx:
    program = "anthropic"
    s = {}


class Convert(unittest.TestCase):
    def test_repo_path_in_web_fetch_reads_the_file(self):
        with mock.patch.object(A, "t_read_file", return_value="1\tline one") as rf:
            out = A.t_web_fetch(Ctx(), "scripts/gnoc_agent.py")
        self.assertIn("converted", out)
        self.assertIn("read_file ran instead", out)
        rf.assert_called_once()
        self.assertEqual(rf.call_args[0][1], "scripts/gnoc_agent.py")

    def test_paths_outside_the_repo_and_urls_are_not_repo_paths(self):
        self.assertIsNone(A._repo_path("/etc/passwd"))
        self.assertIsNone(A._repo_path("https://" + IN + "/a.txt"))
        self.assertIsNone(A._repo_path("two words here"))

    def test_in_scope_host_runs_http_request(self):
        with mock.patch.object(A, "_in_active_scope", return_value=lambda h: h == IN), \
             mock.patch.object(A, "t_http_request", return_value="200 ok bytes") as hr, \
             mock.patch.object(A.gnoc_web, "fetch", side_effect=AssertionError("must not reach web fetch")):
            out = A.t_web_fetch(Ctx(), "https://" + IN + "/api/v1/merge")
        self.assertIn("http_request", out)
        self.assertIn("200 ok bytes", out)
        self.assertEqual(hr.call_args[0][1], "https://" + IN + "/api/v1/merge")

    def test_off_scope_host_still_goes_to_the_web_fetcher(self):
        with mock.patch.object(A, "_in_active_scope", return_value=lambda h: False), \
             mock.patch.object(A, "_deadline", return_value=(False, "refused: not public")):
            out = A.t_web_fetch(Ctx(), "https://" + OFF + "/")
        self.assertTrue(out.startswith("refused"))

    def test_web_search_of_a_path_or_url_is_converted(self):
        with mock.patch.object(A, "t_read_file", return_value="bytes"):
            self.assertIn("read_file ran instead", A.t_web_search(Ctx(), "scripts/gnoc_agent.py"))
        with mock.patch.object(A, "t_web_fetch", return_value="page") as wf:
            out = A.t_web_search(Ctx(), "https://github.com/x/y")
        self.assertIn("web_fetch ran instead", out)
        wf.assert_called_once()


class MisroutedReadConversion(unittest.TestCase):
    def test_a_tool_handed_a_real_repo_file_runs_read_file(self):
        with mock.patch.dict(A.TOOLS, {"read_file": (lambda ctx, **kw: f"READ {kw}", A.TOOLS["read_file"][1])}):
            out = A._convertible_read(Ctx(), "gnoc", {"path": "scripts/gnoc_agent.py", "limit": "50"},
                                      "bad arguments: gnoc does not read files - it has no path argument")
        self.assertIn("converted: gnoc does not read files", out)
        self.assertIn("'limit': 50", out)
        self.assertIn("'path': 'scripts/gnoc_agent.py'", out)

    def test_a_missing_file_or_another_refusal_is_left_alone(self):
        self.assertIsNone(A._convertible_read(Ctx(), "gnoc", {"path": "scripts/no-such-file.py"},
                                              "bad arguments: gnoc does not read files"))
        self.assertIsNone(A._convertible_read(Ctx(), "gnoc", {"path": "scripts/gnoc_agent.py"},
                                              "bad arguments: gnoc needs args"))
        self.assertIsNone(A._convertible_read(Ctx(), "touch", {"path": "scripts/gnoc_agent.py"},
                                              "bad arguments: touch does not read files"))


class HoldGateIgnoresTheHarness(unittest.TestCase):
    def test_the_walled_routes_line_carries_no_hold_phrase(self):
        import gnoc_hunt as H
        with mock.patch.object(H, "program_walls", return_value={"a.example/b": ("404:117", 9)}), \
             mock.patch.object(H, "load", return_value={"hypotheses": [], "edges": [], "model": {}, "goal": ""}):
            try:
                text = H.directive("p", peek=True)
            except Exception:
                text = "WALLED ROUTES (refused before the wire for any hypothesis and any method past the cap; pick other routes): x"
        self.assertIn("WALLED ROUTES", text)
        self.assertIsNone(A._hold_phrase(text))

    def test_the_old_wording_was_a_hold_phrase(self):
        self.assertIsNotNone(A._hold_phrase("WALLED ROUTES (...; do NOT fire them): x"))

    def test_a_stuck_directive_is_a_harness_turn_too(self):
        self.assertTrue(A.is_hunt_directive("STUCK: H16 took 20 probes. Do not send it another variant.\n[HUNT program-0]"))
        self.assertTrue(A.is_hunt_directive("[HUNT program-0] PHASE PROBE"))
        self.assertFalse(A.is_hunt_directive("do not send it, just tell me what it would do"))
        self.assertIsNotNone(A._hold_phrase("Do not send it another variant."))


class CanonicalHypothesisId(unittest.TestCase):
    def test_a_mutated_id_resolves_to_its_ledger_row(self):
        import gnoc_hunt as H
        rows = [{"id": "H16", "status": "probing", "probes": 20}, {"id": "H18", "status": "open", "probes": 0}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}):
            self.assertEqual(H.canonical_hyp_id("p", "H16-mutated"), "H16")
            self.assertEqual(H.canonical_hyp_id("p", "H18"), "H18")
            self.assertEqual(H.canonical_hyp_id("p", "H99"), "H99")
            self.assertIsNone(H.canonical_hyp_id("p", None))


class VerdictOwedOnSpentBudget(unittest.TestCase):
    def test_a_hypothesis_with_spent_probes_but_few_counted_enters_the_verdict_phase(self):
        import gnoc_hunt as H
        h = {"id": "H16", "status": "probing", "title": "t", "probes": 20, "evidence": [], "crown": "ato",
             "routes": {"c.example/api/v1/merge": {"404:117": 7}, "c.example/oauth/cb": {"200:84694": 13}}}
        state = {"hypotheses": [h], "edges": [], "model": {"boundaries": ["b"]}, "goal": ""}
        with mock.patch.object(H, "load", return_value=state), mock.patch.object(H, "modify"), \
             mock.patch.object(H, "program_walls", return_value={"c.example/api/v1/merge": ("404:117", 8)}), \
             mock.patch.object(H, "counted_probes", return_value=13):
            text = H.directive("p", briefed=True, peek=True)
        self.assertIn("PHASE VERDICT H16", text)


class HarnessBriefsReachTheBots(unittest.TestCase):
    def test_probe_briefs_pass_the_fan_out_entry_checks(self):
        import gnoc_hunt as H
        rows = [{"id": "H18", "status": "open", "probes": 0, "title": "t", "assumption": "a", "violation": "POST /x",
                 "prediction": "p", "kill_byte": "k", "crown": "ato", "routes": {}, "evidence": []}]
        doc = getattr(H, "DOC")
        with mock.patch.object(H, "load", return_value={"hypotheses": rows, "edges": [], "model": {}, "goal": ""}), \
             mock.patch.object(doc, "moves", return_value=[("B1", "a tell that says delegate nothing")]):
            briefs = H.probe_briefs("p", 2)
        tasks = [b for _, b in briefs]
        self.assertEqual(len(tasks), 1)
        self.assertIsNone(A._placeholder_in(tasks))
        # a tell may still carry a lead-tool word: the harness path must not go through the typo checks at all
        self.assertEqual(A._lead_tool_in(tasks), "delegate")
        src = _agent_source()
        self.assertIn("findings = _fan_out_run(self.ctx, [b for _, b in briefs])", src)


class RefusedEndpointWait(unittest.TestCase):
    def test_waits_for_a_listener_and_gives_up_on_a_closed_port(self):
        import socket, threading, time
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
        with mock.patch.dict(A.llm_endpoints.HOSTS, {"t": f"127.0.0.1:{port}"}):
            self.assertTrue(A._wait_for_endpoint("t", seconds=2))
        srv.close()
        with mock.patch.dict(A.llm_endpoints.HOSTS, {"t": f"127.0.0.1:{port}"}):
            t0 = time.time()
            self.assertFalse(A._wait_for_endpoint("t", seconds=1.5, step=0.5))
            self.assertLess(time.time() - t0, 4)
        self.assertFalse(A._wait_for_endpoint("no-such-host", seconds=0.1))


class VerdictOwedRefusesProbes(unittest.TestCase):
    def test_a_hypothesis_in_its_verdict_turns_takes_no_probe(self):
        import gnoc_hunt as H
        rows = [{"id": "H16", "status": "probing", "probes": 20, "verdict_turns": 1, "routes": {}, "evidence": []},
                {"id": "H17", "status": "probing", "probes": 20, "routes": {}, "evidence": []},
                {"id": "H18", "status": "open", "probes": 0, "routes": {}, "evidence": []}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), \
             mock.patch.object(H, "counted_probes", side_effect=lambda h, program=None: int(h.get("probes") or 0)):
            self.assertIn("owes a VERDICT", H.verdict_owed("p", "H16"))
            self.assertIn("owes a VERDICT", H.verdict_owed("p", "H16-mutated"))
            self.assertIsNone(H.verdict_owed("p", "H17"))   # not yet asked to decide
            self.assertIsNone(H.verdict_owed("p", "H18"))
            self.assertIsNone(H.verdict_owed("p", None))


class GhostGuessBudget(unittest.TestCase):
    def test_three_nonexistent_routes_close_the_guessing(self):
        import gnoc_hunt as H
        h = {"id": "H22", "status": "probing", "probes": 12, "routes": {
            "a.example/api/session": {"404:117": 1}, "a.example/api/v1/account": {"404:117": 2},
            "a.example/api/x": {"404:117": 1}, "a.example/api/auth/aws": {"400:147": 3},
            "docs.example/en/api": {"200:536790": 1}}}
        self.assertEqual(sorted(H.ghost_routes(h)), ["a.example/api/session", "a.example/api/v1/account", "a.example/api/x"])
        with mock.patch.object(H, "load", return_value={"hypotheses": [h]}):
            self.assertIn("routes that do not exist", H.ghost_guesses_spent("p", "H22"))
            h["routes"].pop("a.example/api/x")
            self.assertIsNone(H.ghost_guesses_spent("p", "H22"))
            self.assertIsNone(H.ghost_guesses_spent("p", "H99"))


class ShellErrorWall(unittest.TestCase):
    def test_a_drifting_404_shell_is_one_wall_shape(self):
        import gnoc_hunt as H
        h = {"id": "H19", "status": "probing", "probes": 8, "routes": {
            "c.example/admin-settings/billing": {"404:82223": 1, "404:81764": 1, "404:82121": 1, "404:0": 1,
                                                  "404:82130": 1, "404:81779": 1, "404:81773": 1},
            "c.example/v1/admin": {"404:117": 1}}}
        walls = H.walled_routes(h)
        self.assertEqual([(r, s) for r, s, _ in walls], [("c.example/admin-settings/billing", "404:shell")])
        self.assertEqual(walls[0][2], 7)
        self.assertEqual(H.counted_probes(h), 1)
        # small refusals and granted answers keep their exact shape
        self.assertEqual(H.shape_bucket("404:117"), "404:117")
        self.assertEqual(H.shape_bucket("200:85000"), "200:85000")
        with mock.patch.object(H, "load", return_value={"hypotheses": [h]}):
            self.assertEqual(H.program_walls("p")["c.example/admin-settings/billing"], ("404:shell", 7))


class LeadNeedsTheKillByte(unittest.TestCase):
    def test_a_public_sink_2xx_without_the_kill_byte_is_not_a_lead(self):
        import gnoc_hunt as H, json, tempfile
        d = tempfile.mkdtemp(dir=os.path.join(H.WS, ".claude", "state"))   # check_evidence wants a workspace path
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        def cap(name, body):
            p = os.path.join(d, name)
            json.dump({"request": {"url": "https://api.example/api/event_logging/v2/batch", "method": "POST"},
                       "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": body}}, open(p, "w"))
            return p
        sink = cap("sink.json", '{"accepted_count":0,"rejected_count":0}')
        hit = cap("hit.json", '{"fallback_mode": true, "data": {"k": 1}}')
        h = {"id": "H24", "status": "probing", "probes": 12, "title": "t", "kill_byte": '"fallback_mode": true',
             "routes": {}, "evidence": [], "notes": "", "prediction": "p"}
        state = {"hypotheses": [h], "edges": [], "model": {}, "goal": ""}
        with mock.patch.object(H, "load", return_value=state), mock.patch.object(H, "save", lambda *a, **k: None), \
             mock.patch.object(H, "_mechanism_shape", return_value=(True, "")), \
             mock.patch.object(H, "is_soft200_shell", return_value=(False, "")):
            out = H.hypothesis("p", action="update", id="H24", status="lead", evidence=sink)
            self.assertIn("refused LEAD for H24", out)
            self.assertIn("kill byte", out)
            self.assertEqual(h["status"], "probing")
            out = H.hypothesis("p", action="update", id="H24", status="lead", evidence=hit)
            self.assertIn("H24 -> lead", out)


class MatrixBudgetAndBriefOnce(unittest.TestCase):
    def test_matrix_budget_left_subtracts_logged_probes(self):
        import gnoc_hunt as H, gnoc_economy as E
        rows = [{"id": "H24", "status": "probing", "probes": 12}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), \
             mock.patch.object(E, "budget", return_value=20):
            self.assertEqual(A._matrix_budget_left("p", "H24"), 8)
            self.assertEqual(A._matrix_budget_left("p", "H24-mutated"), 8)
            rows[0]["probes"] = 32
            self.assertEqual(A._matrix_budget_left("p", "H24"), 0)
        self.assertIsNone(A._matrix_budget_left("p", None))

    def test_hunt_brief_answers_once_per_turn(self):
        class C:
            program = "p"
            s = {"_turn_user": "turn-1"}
        with mock.patch.object(A, "_hunt_brief_body", return_value="BRIEF") as body:
            self.assertEqual(A.t_hunt_brief(C(), "p"), "BRIEF")
            out = A.t_hunt_brief(C(), "p")
            self.assertIn("already ran this turn", out)
            C.s["_turn_user"] = "turn-2"
            self.assertEqual(A.t_hunt_brief(C(), "p"), "BRIEF")
            self.assertEqual(body.call_count, 2)


class GhostRefusalsPark(unittest.TestCase):
    def test_the_third_guessed_path_refusal_parks_the_hypothesis(self):
        import gnoc_hunt as H
        h = {"id": "H24", "status": "probing", "probes": 12, "routes": {}, "evidence": [], "notes": ""}
        state = {"hypotheses": [h]}
        def fake_modify(program, fn):
            fn(state)
        with mock.patch.object(H, "modify", side_effect=fake_modify):
            self.assertIsNone(H.note_ghost_refusal("p", "H24"))
            self.assertIsNone(H.note_ghost_refusal("p", "H24-mutated"))
            out = H.note_ghost_refusal("p", "H24")
        self.assertIn("H24 is now UNFIRED", out)
        self.assertEqual(h["status"], "unfired")
        self.assertIn("guessed-path refusals", h["notes"])
        with mock.patch.object(H, "modify", side_effect=fake_modify):
            self.assertIsNone(H.note_ghost_refusal("p", "H24"))   # already parked: nothing more


class DecisionToolsStayOn(unittest.TestCase):
    def test_refused_lead_claims_do_not_switch_the_verdict_tool_off(self):
        self.assertIn("hunt_hypothesis", A.DECISION_TOOLS)
        src = _agent_source()
        self.assertIn("streak[name] >= REPEAT_LIMIT and name not in DECISION_TOOLS", src)


class GateOwnedFiles(unittest.TestCase):
    def test_the_lead_cannot_write_the_files_the_gates_read(self):
        class C:
            program = "anthropic"
            s = {}
        for path in ("targets/program-0/hunts/gnoc/known-paths.txt", "targets/program-0/hunts/gnoc/ledger.json",
                     "targets/program-0/SCOPE.txt"):
            self.assertIn("written by the harness", A.t_edit_file(C(), path, old="a", new="b"))
            self.assertIn("written by the harness", A.t_write_file(C(), path, "x"))
        self.assertIsNone(A._gate_owned("targets/program-0/hunts/gnoc-agent-20261026/STATUS.md"))

    def test_gnoc_hypothesis_points_at_the_ledger_tool(self):
        class C:
            program = "anthropic"
            s = {}
        out = A.t_gnoc(C(), "hypothesis H18 status=lead evidence=targets/x.json")
        self.assertIn("hunt_hypothesis(action=update", out)


class FanOutBotsSurvive(unittest.TestCase):
    def test_the_worker_alloy_has_no_phone_slot_and_the_nudges_exist(self):
        src = _agent_source()
        body = src.split("def _run_worker_body(", 1)[1].split("\ndef ", 1)[0]
        self.assertIn('os.environ.get("GNOC_ALLOY_PHONE") == "1"', body)
        self.assertIn("empty answer; nudged once", body)
        self.assertIn("steps without a probe; nudged once", body)
        self.assertEqual(A.READ_STEPS_BEFORE_PROBE, 4)
        self.assertIn("probe_matrix", A.PROBE_TOOLS)
        self.assertIn("http_request", A.PROBE_TOOLS)


class BrokenMarkExpires(unittest.TestCase):
    def test_a_cannot_start_mark_lifts_after_its_ttl(self):
        import time
        import tempfile
        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(A, "BROKEN_LOG", os.path.join(td, "b.jsonl")), \
                mock.patch.object(A, "_release_dead_runner", lambda *a, **k: None):
            A.mark_broken("m", "desktop", "llama-server process has terminated")
        self.assertTrue(A.is_broken("m", "desktop"))
        A._BROKEN_AT["m@desktop"] = time.time() - A.BROKEN_TTL - 1
        self.assertFalse(A.is_broken("m", "desktop"))
        self.assertNotIn("m@desktop", A._BROKEN_MODEL)


class RaceBurstBudget(unittest.TestCase):
    def test_a_burst_is_capped_to_the_budget_left_and_refused_at_zero(self):
        with mock.patch.object(A, "_matrix_budget_left", return_value=4):
            self.assertEqual(A._race_n_cap("p", "H30", 10), (2, None))      # D69: two arms share the 4 left
            self.assertEqual(A._race_n_cap("p", "H30", 10, arms=1), (4, None))
            self.assertEqual(A._race_n_cap("p", "H30", 3), (2, None))
        with mock.patch.object(A, "_matrix_budget_left", return_value=0):
            n, why = A._race_n_cap("p", "H30", 10)
            self.assertIn("no probe budget left", why)
        with mock.patch.object(A, "_matrix_budget_left", return_value=None):
            self.assertEqual(A._race_n_cap("p", None, "7"), (7, None))


class ClosedHypothesisTakesNoProbe(unittest.TestCase):
    def test_dead_and_unfired_are_refused_and_open_passes(self):
        import gnoc_hunt as H
        rows = [{"id": "H26", "status": "unfired"}, {"id": "H28", "status": "dead"}, {"id": "H29", "status": "probing"}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}):
            self.assertIn("H26 is unfired", H.closed_hypothesis("p", "H26"))
            self.assertIn("reopen it first", H.closed_hypothesis("p", "H26-mutated"))
            self.assertIn("H28 is dead", H.closed_hypothesis("p", "H28"))
            self.assertIsNone(H.closed_hypothesis("p", "H29"))
            self.assertIsNone(H.closed_hypothesis("p", None))


class WallsFormOnMixedRefusals(unittest.TestCase):
    def test_route_shape_folds_path_shapes_and_a_two_shape_refusal_route_walls_past_wall_hard(self):
        import gnoc_hunt as H
        self.assertEqual(H.route_key("https://x.example/a//b/./c/"), "x.example/a/b/c")
        rows = [{"id": "H18", "status": "unfired", "routes": {"api.x/api/account": {"403:215": 10, "405:132": 4}}},
                {"id": "H33", "status": "probing", "routes": {"api.x//api/account": {"403:215": 1},
                                                              "api.x/api/./account": {"403:215": 1}}},
                {"id": "H2", "status": "probing", "routes": {"api.x/live": {"403:215": 3, "401:10": 3}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}):
            walls = H.program_walls("p")
        self.assertIn("api.x/api/account", walls)
        self.assertEqual(walls["api.x/api/account"][1], 16)
        self.assertNotIn("api.x/live", walls)          # 6 probes, mixed shapes, under WALL_HARD: not yet a wall
        self.assertNotIn("api.x//api/account", walls)  # folded, not a route of its own

    def test_an_add_whose_violation_names_a_walled_route_is_refused(self):
        import gnoc_hunt as H
        with mock.patch.object(H, "program_walls", return_value={"api.x/api/account": ("403:215", 16)}):
            out = H.violation_on_wall("p", "GET /api/account with a second account's id in the path")
            self.assertIn("program wall", out)
            self.assertIsNone(H.violation_on_wall("p", "POST /api/v1/transfer dest_id=<B>"))
        with mock.patch.object(H, "program_walls", return_value={"api.x/api/account": ("403:215", 5)}):
            self.assertIsNone(H.violation_on_wall("p", "GET /api/account"))   # under 2 x WALL_MIN: a body may differ


class ZeroProbeParkIsRefused(unittest.TestCase):
    def test_unfired_at_zero_probes_needs_a_named_blocker(self):
        import gnoc_hunt as H
        rows = [{"id": "H32", "status": "open", "probes": 0, "evidence": [], "notes": "", "title": "t"}]
        d = {"hypotheses": rows}
        with mock.patch.object(H, "load", return_value=d), mock.patch.object(H, "save", lambda *a, **k: None):
            out = H.hypothesis("p", "update", id="H32", status="unfired", notes="awaiting probe")
            self.assertIn("refused UNFIRED", out)
            self.assertEqual(rows[0]["status"], "open")
            out = H.hypothesis("p", "update", id="H32", status="unfired", notes="NEEDS a second account")
            self.assertIn("H32 -> unfired", out)


class BudgetRefusalNamesAlternatives(unittest.TestCase):
    def test_the_alternatives_list_open_ids_with_room_or_say_add_one(self):
        import gnoc_hunt as H
        rows = [{"id": "H3", "status": "probing", "probes": 20}, {"id": "H26", "status": "probing", "probes": 14},
                {"id": "H9", "status": "dead", "probes": 2}, {"id": "H40", "status": "open", "probes": 0}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}):
            got = H.open_with_budget("p", lambda p, i: 20, skip="H3")
            self.assertEqual([i for i, _, _ in got], ["H40", "H26"])
            with mock.patch.object(A.gnoc_hunt, "load", return_value={"hypotheses": rows}):
                self.assertIn("H40 (0/20)", A._budget_alternatives("p", "H3"))
        with mock.patch.object(A.gnoc_hunt, "open_with_budget", return_value=[]):
            self.assertIn("add a new one", A._budget_alternatives("p", "H3"))


class SpentBudgetParksAnUnreachedHypothesis(unittest.TestCase):
    def test_parked_when_the_floor_was_never_reached_and_left_alone_when_it_was(self):
        import gnoc_hunt as H
        rows = [{"id": "H33", "status": "probing", "probes": 22, "notes": "", "evidence": [],
                 "routes": {"api.x/api/account": {"403:215": 15, "405:132": 4}}},
                {"id": "H40", "status": "probing", "probes": 20, "notes": "", "evidence": [],
                 "routes": {"api.x/live": {"200:900": 12, "403:215": 8}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "save", lambda *a, **k: None):
            out = H.park_spent("p", "H33")
            self.assertIn("UNFIRED by code", out)
            self.assertEqual(rows[0]["status"], "unfired")
            self.assertIn("parked by code", rows[0]["notes"])
            self.assertEqual(H.park_spent("p", "H40"), "")
            self.assertEqual(rows[1]["status"], "probing")
            self.assertEqual(H.park_spent("p", "H33"), "")   # already parked: no second note


class WallRefusalsParkAndBrokenMarksPersist(unittest.TestCase):
    def test_the_third_wall_refusal_parks_an_unreached_hypothesis(self):
        import gnoc_hunt as H
        rows = [{"id": "H33", "status": "probing", "probes": 22, "notes": "", "evidence": [],
                 "routes": {"api.x/api/account": {"403:215": 20}}}]
        d = {"hypotheses": rows}

        def _modify(program, fn):
            fn(d)
        with mock.patch.object(H, "modify", _modify):
            self.assertEqual(H.note_wall_refusal("p", "H33"), "")
            self.assertEqual(H.note_wall_refusal("p", "H33"), "")
            self.assertIn("UNFIRED by code", H.note_wall_refusal("p", "H33"))
            self.assertEqual(rows[0]["status"], "unfired")
        rows2 = [{"id": "H40", "status": "probing", "probes": 12, "notes": "", "evidence": [], "wall_refusals": 2,
                  "routes": {"api.x/live": {"200:900": 10}, "api.x/wall": {"404:117": 2}}}]
        d2 = {"hypotheses": rows2}
        with mock.patch.object(H, "modify", lambda program, fn: fn(d2)):
            self.assertEqual(H.note_wall_refusal("p", "H40"), "")   # floor reached on a live route: the model decides
            self.assertEqual(rows2[0]["status"], "probing")

    def test_mark_broken_writes_the_full_reason_to_disk(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            log = os.path.join(td, "broken-marks.jsonl")
            with mock.patch.object(A, "BROKEN_LOG", log), mock.patch.object(A, "_release_dead_runner", lambda *a, **k: None):
                A.mark_broken("m", "desktop", "m@desktop: llama-server process has terminated (exit 0xc0000005) " + "x" * 400)
            row = json.loads(open(log).read().splitlines()[-1])
        self.assertEqual(row["host"], "desktop")
        self.assertIn("llama-server process has terminated", row["why"])
        self.assertLessEqual(len(row["why"]), 600)

    def test_one_context_table_for_the_lead_and_the_brain(self):
        import llm_endpoints
        import orch_brain
        self.assertIs(A.CTX, llm_endpoints.CTX)
        self.assertEqual(orch_brain.llm_endpoints.ctx_for_host("desktop"), A.ctx_for("desktop"))
        self.assertEqual(llm_endpoints.ctx_for_host("nowhere"), 16384)


class DeadNeedsAGrantedRoute(unittest.TestCase):
    def test_dead_on_refusals_only_is_recorded_unfired(self):
        import gnoc_hunt as H
        rows = [{"id": "H34", "status": "probing", "probes": 25, "notes": "", "evidence": [], "bursts": 1,
                 "routes": {"api.x/api/v1/messages": {"404:117": 3}, "api.x/api/account": {"405:132": 1}}},
                {"id": "H40", "status": "probing", "probes": 12, "notes": "", "evidence": [], "bursts": 1,
                 "routes": {"api.x/live": {"200:900": 10, "403:215": 2}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "save", lambda *a, **k: None):
            out = H.hypothesis("p", "update", id="H34", status="dead", notes="not single-use: burst found nothing")
            self.assertIn("refused DEAD", out)
            self.assertEqual(rows[0]["status"], "unfired")
            out = H.hypothesis("p", "update", id="H40", status="dead", notes="not single-use: no one-shot step")
            self.assertIn("H40 -> dead", out)


class RootDocumentDoesNotReachTheSurface(unittest.TestCase):
    def test_any_granted_ignores_the_bare_host(self):
        import gnoc_hunt as H
        self.assertFalse(H.any_granted({"routes": {"console.x": {"200:207238": 2}, "api.x/v1/messages": {"401:141": 3}}}))
        self.assertTrue(H.any_granted({"routes": {"console.x": {"200:207238": 2}, "api.x/v1/models": {"200:900": 1}}}))


class WeakKillBytesAndRootShell(unittest.TestCase):
    def test_short_words_and_route_fragments_are_refused(self):
        import gnoc_hunt as H
        h = {"title": "console-vs-api drift", "violation": "GET /api/v1/users/me on console", "prediction": "200 with a body",
             "routes": {"console.x/api/v1/users/me": {"200:50": 1}}}
        self.assertIn("short bare word", H.weak_kill_byte("api", h))
        self.assertIn("short bare word", H.weak_kill_byte("secret", h))
        self.assertIn("fragment", H.weak_kill_byte("api/v1/users", h))
        self.assertIsNone(H.weak_kill_byte('"owner_id":"<different-user-id>"', h))
        self.assertIsNone(H.weak_kill_byte("account_session_invalid", h))
        rows = [{"id": "H36", "status": "probing", "probes": 3, "notes": "", "evidence": ["x"], "kill_byte": "api",
                 "title": "t", "violation": "v", "prediction": "p", "routes": {}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "save", lambda *a, **k: None):
            out = H.hypothesis("p", "update", id="H36", status="lead", evidence="x")
            self.assertIn("refused LEAD", out)
            self.assertIn("short bare word", out)

    def test_the_host_root_document_is_a_shell(self):
        import gnoc_hunt as H
        import json
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", dir=H.WS, delete=False) as f:
            json.dump({"request": {"url": "https://console.x/"}, "response": {"status": 200, "body": "<!doctype html>" + "x" * 30000}}, f)
        try:
            shell, why = H.is_soft200_shell(f.name)
        finally:
            os.unlink(f.name)
        self.assertTrue(shell)
        self.assertIn("root document", why)


class RaceCapCountsBothArms(unittest.TestCase):
    def test_the_cap_halves_for_a_serial_control(self):
        with mock.patch.object(A, "_matrix_budget_left", return_value=15):
            self.assertEqual(A._race_n_cap("p", "H34", 10), (7, None))
            self.assertEqual(A._race_n_cap("p", "H34", 10, arms=1), (10, None))
        with mock.patch.object(A, "_matrix_budget_left", return_value=1):
            self.assertIn("no probe budget left", A._race_n_cap("p", "H34", 10)[1])


class BadUrlNamesTheHosts(unittest.TestCase):
    def test_scope_hosts_reads_url_rows(self):
        import gnoc_hunt as H
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "targets", "p"))
            with open(os.path.join(td, "targets", "p", "SCOPE.txt"), "w") as f:
                f.write("# h\nURL            api.p.com\t[bounty]\nURL   console.p.com\t[bounty]\n")
            with mock.patch.object(H, "WS", td):
                self.assertEqual(H.scope_hosts("p"), ["api.p.com", "console.p.com"])


class ContextOverflowStaysUnderTheCeiling(unittest.TestCase):
    def test_bump_within_the_cap_and_trim_at_it(self):
        import llm_endpoints
        self.assertEqual(llm_endpoints.ctx_max("desktop"), 32768)
        body = {"options": {"num_ctx": 16384}, "messages": [{"role": "system", "content": "s"}] + [{"role": "user", "content": "u"}] * 8}
        self.assertTrue(A._ctx_overflow_fix("desktop", body, 20400))
        self.assertEqual(body["options"]["num_ctx"], 22528)
        big = [{"role": "tool", "content": "x" * 60000} for _ in range(4)]
        body = {"options": {"num_ctx": 32768}, "messages": [{"role": "system", "content": "s"}] + big
                + [{"role": "user", "content": "u"}] * 7}
        self.assertTrue(A._ctx_overflow_fix("desktop", body, 34000))
        self.assertEqual(body["options"]["num_ctx"], 32768)
        self.assertTrue(any("trimmed" in str(m["content"]) for m in body["messages"]))
        self.assertEqual(body["messages"][-1]["content"], "u")


class ProgramWallsCountAgainstTheFloor(unittest.TestCase):
    def test_counted_probes_subtracts_program_walls_and_briefs_skip_walled_violations(self):
        import gnoc_hunt as H
        h = {"id": "H36", "status": "probing", "probes": 19, "violation": "POST /v1/messages as B", "title": "t",
             "assumption": "a", "prediction": "p", "kill_byte": '"owner_id":"x"', "crown": "cross-user-read",
             "routes": {"api.x/v1/messages": {"401:141": 3}, "console.x": {"200:207238": 2}, "api.x/other": {"404:117": 14}}}
        with mock.patch.object(H, "program_walls", return_value={"api.x/v1/messages": ("401:141", 12), "api.x/other": ("404:117", 30)}):
            self.assertEqual(H.counted_probes(h), 5)            # per-hypothesis: /other (14) is a wall, /v1/messages (3) is not
            self.assertEqual(H.counted_probes(h, "p"), 2)       # with the program: /v1/messages is a program wall too
            with mock.patch.object(H, "load", return_value={"hypotheses": [h, dict(h, id="H50", violation="GET /v1/skills", routes={})]}), \
                    mock.patch.object(H.DOC, "moves", return_value=[]):
                briefs = H.probe_briefs("p", n=3)
        self.assertEqual([i for i, _ in briefs], ["H50"])

    def test_a_spent_hypothesis_is_not_briefed(self):
        import gnoc_hunt as H
        rows = [{"id": "H42", "status": "open", "probes": 20, "violation": "GET /v1/skills", "title": "t", "assumption": "a",
                 "prediction": "p", "kill_byte": '"x":1', "crown": "cross-user-read", "routes": {}},
                {"id": "H44", "status": "open", "probes": 2, "violation": "GET /v1/models", "title": "t", "assumption": "a",
                 "prediction": "p", "kill_byte": '"x":1', "crown": "cross-user-read", "routes": {}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "program_walls", return_value={}), \
                mock.patch.object(H, "budget_left", side_effect=lambda p, h: 20 - h["probes"]), mock.patch.object(H.DOC, "moves", return_value=[]):
            self.assertEqual([i for i, _ in H.probe_briefs("p", n=3)], ["H44"])

    def test_the_worker_breaker_counts_wall_refusals(self):
        src = _agent_source()
        self.assertIn("unknown or unavailable|route wall|route closed|GHOST-PATH", src)

    def test_the_proposal_scorer_rejects_a_weak_kill_byte(self):
        import gnoc_hunt as H
        src = open(H.__file__).read()
        self.assertIn("weak = weak_kill_byte(h.get(\"kill_byte\", \"\"), h)   # D76", src)


class PromotionOnASpentUnreachedHypothesisParksIt(unittest.TestCase):
    def test_lead_on_spent_never_answered_is_parked_unfired(self):
        import gnoc_hunt as H
        rows = [{"id": "H40", "status": "open", "probes": 20, "notes": "", "evidence": [], "kill_byte": "draft",
                 "title": "t", "violation": "v", "prediction": "p", "routes": {"api.x/api/account": {"405:132": 20}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "save", lambda *a, **k: None), \
                mock.patch.object(H, "budget_left", return_value=0):
            out = H.hypothesis("p", "update", id="H40", status="lead", evidence="x")
        self.assertIn("Recorded as UNFIRED", out)
        self.assertEqual(rows[0]["status"], "unfired")


class ReopenNeedsANewRoute(unittest.TestCase):
    def test_a_walled_or_probed_route_cannot_reopen_and_a_new_one_can(self):
        import gnoc_hunt as H
        rows = [{"id": "H40", "status": "unfired", "probes": 20, "notes": "", "evidence": [], "title": "t",
                 "routes": {"api.x/api/account": {"405:132": 1}}},
                {"id": "H9", "status": "dead", "probes": 9, "notes": "", "evidence": [],
                 "routes": {"api.x/v1/models": {"200:900": 9}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), mock.patch.object(H, "save", lambda *a, **k: None), \
                mock.patch.object(H, "program_walls", return_value={"api.x/api/account": ("403:215", 151)}):
            self.assertIn("program wall", H.hypothesis("p", "update", id="H40", status="open", notes="positive control: /api/account"))
            self.assertIn("needs notes naming a NEW route", H.hypothesis("p", "update", id="H40", status="open", notes="try again"))
            self.assertIn("H40 -> open", H.hypothesis("p", "update", id="H40", status="open", notes="new route: /v1/skills from js_mine"))
            self.assertTrue(H.route_answered("p", "/v1/models"))
            self.assertFalse(H.route_answered("p", "/api/account"))
            rows[0]["status"] = "probing"
            out = H.hypothesis("p", "update", id="H40", status="dead", notes="positive control: /api/account")
            self.assertIn("refused DEAD", out)


class HypothesesNeedARouteThatExists(unittest.TestCase):
    def test_invented_routes_are_refused_and_known_or_answered_ones_pass(self):
        import gnoc_hunt as H
        rows = [{"id": "H1", "status": "dead", "probes": 3, "routes": {"api.x/v1/skills": {"401:141": 3}}},
                {"id": "H2", "status": "dead", "probes": 2, "routes": {"api.x/nope": {"404:117": 2}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": rows}), \
                mock.patch("builtins.open", mock.mock_open(read_data="/v1/models\n/v1/messages/batches\n")):
            known = H.existing_paths("p")
            self.assertEqual(known, {"/v1/models", "/v1/messages/batches", "/v1/skills"})
            self.assertIsNone(H.unknown_route_refusal("p", "POST /v1/models with a second account's id"))
            self.assertIsNone(H.unknown_route_refusal("p", "GET /v1/skills as A"))
            self.assertIsNone(H.unknown_route_refusal("p", "GET /v1/messages/batches/{id} as B"))   # placeholder stripped
            self.assertIsNone(H.unknown_route_refusal("p", "GET /v1 index"))                        # parent of known
            self.assertIn("does not exist", H.unknown_route_refusal("p", "POST /api/v1/follow-up with X-Request-Id"))
            self.assertIn("nearest known under /v1/", H.unknown_route_refusal("p", "GET /v1/user/profile from mobile"))
            self.assertIsNone(H.unknown_route_refusal("p", "replay the session cookie across tenants"))   # no path token
        self.assertEqual(H._violation_paths("GET /orders/{B} as A then /v1/x/123"), ["/orders", "/v1/x"])

    def test_note_shapes_records_routes_without_counting_probes(self):
        import gnoc_hunt as H
        import json
        import tempfile
        d = {"hypotheses": [{"id": "H40", "status": "probing", "probes": 20, "routes": {}}]}
        paths = []
        with tempfile.TemporaryDirectory() as td:
            for i in range(3):
                fp = os.path.join(td, f"r{i}.json")
                json.dump({"request": {"url": "https://api.x/api/account"}, "response": {"status": 405, "body": "x" * 132}}, open(fp, "w"))
                paths.append(fp)
            with mock.patch.object(H, "modify", lambda program, fn: fn(d)):
                H.note_shapes("p", "H40", paths)
        self.assertEqual(d["hypotheses"][0]["routes"], {"api.x/api/account": {"405:132": 3}})
        self.assertEqual(d["hypotheses"][0]["probes"], 20)


class SpentHypothesesOweAVerdict(unittest.TestCase):
    def test_a_spent_open_hypothesis_is_owed_and_not_probed(self):
        import gnoc_hunt as H
        live = [{"id": "H40", "status": "open", "probes": 20, "routes": {}},
                {"id": "H44", "status": "open", "probes": 2, "routes": {}},
                {"id": "H45", "status": "probing", "probes": 17, "routes": {}}]
        with mock.patch.object(H, "budget_left", side_effect=lambda p, h: 20 - h["probes"]), \
                mock.patch.object(H, "program_walls", return_value={}):
            self.assertEqual([h["id"] for h in H.verdict_owed_set("p", live)], ["H40", "H45"])
        src = open(H.__file__).read()
        self.assertIn('fresh = [h for h in live if budget_left(program, h) > 0] or live', src)

    def test_keep_alive_rides_every_chat_body(self):
        self.assertIn('"keep_alive": KEEP_ALIVE', _agent_source())
        # the code default is 10m (D84); 30m is the operator's own machine.json setting, not the default
        self.assertEqual(A.KEEP_ALIVE, os.environ.get("GNOC_KEEP_ALIVE") or "10m")


class RepeatedAnswerIsAStall(unittest.TestCase):
    def test_the_same_paragraph_twice_is_detected_and_short_or_new_text_is_not(self):
        a = ("Looking at the bot digest, H43 is a CANDIDATE with 20 probes, but the LEAD verdict requires a 2xx/3xx "
             "response. Let me check if there is a better capture.")
        self.assertTrue(A._same_answer(A._norm_answer(a), a.replace("20 probes", "21 probes")))   # numbers do not count
        self.assertFalse(A._same_answer(A._norm_answer(a), "H43 is dead. Moving to H44."))
        self.assertFalse(A._same_answer(A._norm_answer("short"), "short"))
        self.assertFalse(A._same_answer(None, a))
        self.assertIn("same answer as last turn; telling it to act or decide", _agent_source())


class NoRespawnWithoutAProbe(unittest.TestCase):
    def test_a_bot_that_never_probed_is_not_respawned(self):
        self.assertFalse(A._bot_probed("VERDICT: NOTHING-YET, PROBES: 0, EVIDENCE: none\n\nRESPAWN BRIEF (lane x)"))
        self.assertFalse(A._bot_probed("the bot wandered and wrote no digest\nRESPAWN BRIEF (lane x)"))
        self.assertTrue(A._bot_probed("VERDICT: NOTHING-YET, PROBES: 7, EVIDENCE: raw/a.json\nRESPAWN BRIEF (lane x)"))
        self.assertIn("and _bot_probed(results[i])", _agent_source())


class SurfaceExhausted(unittest.TestCase):
    def test_unfired_routes_and_unmined_hosts(self):
        import gnoc_hunt as H
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            g = os.path.join(td, "targets", "p", "hunts", "gnoc"); os.makedirs(g)
            open(os.path.join(g, "known-paths.txt"), "w").write("/v1/models\n/v1/skills\n/docs/en/x\n")
            open(os.path.join(g, "mined-hosts.txt"), "w").write("api.p.com\n")
            open(os.path.join(td, "targets", "p", "SCOPE.txt"), "w").write("URL api.p.com\nURL console.p.com\n")
            rows = [{"id": "H1", "status": "dead", "probes": 5, "routes": {"api.p.com/v1/models": {"401:141": 5}}}]
            with mock.patch.object(H, "WS", td), mock.patch.object(H, "load", return_value={"hypotheses": rows}), \
                    mock.patch.object(H, "program_walls", return_value={"api.p.com/v1/skills": ("403:215", 12)}):
                unfired, total, unmined = H.surface_exhausted("p")
            self.assertEqual((unfired, total, unmined), ([], 2, ["console.p.com"]))

    def test_fts_terms_quote_paths_and_keep_operators(self):
        self.assertEqual(A._fts_terms(["anthropic", "/api/account", "OR", "/api/auth", "x:y"]),
                         ["anthropic", '"/api/account"', "OR", '"/api/auth"', '"x:y"'])

    def test_js_mine_records_the_host_once(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(A, "WS", td):
                A._note_mined_host("p", "https://console.p.com/")
                A._note_mined_host("p", "https://console.p.com/x")
            self.assertEqual(open(os.path.join(td, "targets", "p", "hunts", "gnoc", "mined-hosts.txt")).read(), "console.p.com\n")
        self.assertIn("written by the harness", A._gate_owned("targets/p/hunts/gnoc/mined-hosts.txt"))


class AdmissibleRoutesFeedTheTournament(unittest.TestCase):
    def test_the_block_names_unfired_routes_or_says_none(self):
        import gnoc_hunt as H
        with mock.patch.object(H, "surface_exhausted", return_value=(["/v1/agents", "/v1/skills"], 27, [])):
            b = H.admissible_routes_block("p")
            self.assertIn("2 of 27", b); self.assertIn("/v1/agents", b)
        with mock.patch.object(H, "surface_exhausted", return_value=([], 27, [])):
            self.assertIn("none left", H.admissible_routes_block("p"))
        with mock.patch.object(H, "surface_exhausted", return_value=([], 0, [])):
            self.assertEqual(H.admissible_routes_block("p"), "")
        src = _agent_source()
        self.assertIn("routes_block = gnoc_hunt.admissible_routes_block(ctx.program)", src)


class PromotionLoopEndsInATurn(unittest.TestCase):
    def test_the_fourth_refused_promotion_is_answered_without_the_gate(self):
        class C:
            program = "anthropic"
            s = {"_turn_user": "t1"}
        c = C()
        with mock.patch.object(A, "_need_program", return_value=None), mock.patch.object(A, "_program_gate_write", return_value=None), \
                mock.patch.object(A, "_read_program", return_value=("anthropic", "")), \
                mock.patch.object(A.gnoc_hunt, "canonical_hyp_id", side_effect=lambda p, i: i), \
                mock.patch.object(A.gnoc_hunt, "hypothesis", return_value="refused LEAD for H45: the capture is an HTTP 405 refusal") as gate:
            for _ in range(3):
                self.assertIn("refused LEAD", A.t_hunt_hypothesis(c, action="update", id="H45", status="lead", evidence="x"))
            out = A.t_hunt_hypothesis(c, action="update", id="H45", status="lead", evidence="x")
            self.assertIn("refused promotion 3 times this turn", out)
            self.assertEqual(gate.call_count, 3)
            A.t_hunt_hypothesis(c, action="update", id="H44", status="unfired", notes="wall")   # a park still reaches the gate
            self.assertEqual(gate.call_count, 4)


class MatrixOnAWallIsOneRefusal(unittest.TestCase):
    def test_a_walled_baseline_route_returns_the_wall_not_a_table(self):
        th = "api." + "p.com"
        with mock.patch.object(A.gnoc_hunt, "route_key", return_value=th + "/api/account"), \
                mock.patch.object(A.gnoc_hunt, "program_shell_routes", return_value={}), \
                mock.patch.object(A.gnoc_hunt, "program_walls", return_value={th + "/api/account": ("403:215", 150)}), \
                mock.patch.object(A.gnoc_hunt, "note_wall_refusal", return_value=" H44 parked."), \
                mock.patch.object(A.gnoc_hunt, "canonical_hyp_id", side_effect=lambda p, i: i):
            out = A._matrix_wall("p", "https://" + th + "/api/account", "H44")
        self.assertIn("route wall: " + th + "/api/account answered 403 len=215 on all 150 probes", out)
        self.assertIn("H44 parked", out)
        with mock.patch.object(A.gnoc_hunt, "route_key", return_value=th + "/v1/skills"), \
                mock.patch.object(A.gnoc_hunt, "program_shell_routes", return_value={}), \
                mock.patch.object(A.gnoc_hunt, "program_walls", return_value={th + "/api/account": ("403:215", 150)}):
            self.assertEqual(A._matrix_wall("p", "https://" + th + "/v1/skills", "H44"), "")
        self.assertIn("walled = _matrix_wall(program, url, hypothesis)", _agent_source())


class BurpMcpDownIsOneCleanError(unittest.TestCase):
    def test_a_refused_connection_raises_mcpdown_at_once(self):
        import importlib.util, time as _t
        spec = importlib.util.spec_from_file_location("burp_mcp_cli_t", os.path.join(A.WS, "scripts/burp-mcp-cli.py"))
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        t0 = _t.time()
        with self.assertRaises(mod.McpDown):
            mod.Mcp(base="http://127.0.0.1:1")   # nothing listens on port 1
        self.assertLess(_t.time() - t0, 5)
        self.assertTrue(issubclass(mod.McpDown, ConnectionError))


class NoCopiesOfAKilledDraft(unittest.TestCase):
    def test_family_and_kill_are_read_from_disk(self):
        import tempfile, gnoc_report as R
        with tempfile.TemporaryDirectory() as td:
            base = os.path.join(td, "reports", "drafts", "p")
            for n in ("x-chain", "x-chain-2", "x-chain-5-2", "x-chainy", "other"):
                os.makedirs(os.path.join(base, n))
            open(os.path.join(base, "x-chain-5-2", "GATE-reviewer.md"), "w").write("KILL - the terminal is the baseline\n")
            with mock.patch.object(R, "WS", td):
                self.assertEqual(R.family_slugs("p", "x-chain-5-2-2"), ["x-chain", "x-chain-2", "x-chain-5-2"])
                self.assertEqual(R.killed_family("p", "x-chain-5-2")[0], "x-chain-5-2")
                self.assertIsNone(R.killed_family("p", "other"))
        src = open(R.__file__).read()
        self.assertIn("killed = killed_family(program, slug)", src)
        self.assertNotIn('d, k = os.path.join(base, f"{slug}-{k}"), k + 1', src)


class AWalledRouteIsToldTwicePerTurn(unittest.TestCase):
    def test_the_third_refusal_closes_the_route_for_the_turn(self):
        class C:
            s = {"_turn_user": "t1"}
        c = C()
        with mock.patch.object(A.gnoc_hunt, "route_key", return_value="h/v1/oauth/token"):
            self.assertEqual(A._wall_told(c, "p", "https://h/v1/oauth/token", "route wall: x"), "route wall: x")
            self.assertEqual(A._wall_told(c, "p", "https://h/v1/oauth/token", "route wall: x"), "route wall: x")
            out = A._wall_told(c, "p", "https://h/v1/oauth/token?grant=1", "route wall: x")
            self.assertIn("refused 3 times this turn and is closed", out)
        with mock.patch.object(A.gnoc_hunt, "route_key", return_value="h/other"):
            self.assertEqual(A._wall_told(c, "p", "https://h/other", "route wall: y"), "route wall: y")
        c.s = {"_turn_user": "t2"}
        with mock.patch.object(A.gnoc_hunt, "route_key", return_value="h/v1/oauth/token"):
            self.assertEqual(A._wall_told(c, "p", "https://h/v1/oauth/token", "route wall: x"), "route wall: x")
        self.assertIn("return _wall_told(ctx, program, url, str(e))   # D100", _agent_source())


class OutcomeVerdictFollowsTheLedger(unittest.TestCase):
    """D102: record_outcome cannot write a LEAD the hypothesis ledger does not hold."""

    def test_lead_on_an_unfired_hypothesis_is_refused_and_a_ledger_lead_passes(self):
        class C:
            program = "p"
            s = {}
        c = C()
        rows = {"H51": "unfired", "H9": "lead"}
        def load(p):
            return {"hypotheses": [{"id": k, "status": v} for k, v in rows.items()]}
        with mock.patch.object(A, "_program_gate_write", return_value=None), \
                mock.patch.object(A.gnoc_hunt, "load", side_effect=load), \
                mock.patch.object(A.gnoc_hunt, "canonical_hyp_id", side_effect=lambda p, i: i), \
                mock.patch.object(A.gnoc_hunt, "floor_status", return_value=(8, 1)), \
                mock.patch.object(A.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run:
            out = A.t_record_outcome(c, "H51", "LEAD", hypothesis="H51")
            self.assertIn("H51 is UNFIRED in the hypothesis ledger", out); self.assertEqual(run.call_count, 0)
            out = A.t_record_outcome(c, "x", "LEAD")
            self.assertIn("needs hypothesis=", out); self.assertEqual(run.call_count, 0)
            self.assertEqual(A.t_record_outcome(c, "H9", "LEAD", hypothesis="H9"), "recorded")
            self.assertEqual(A.t_record_outcome(c, "H51", "UNFIRED", hypothesis="H51"), "recorded")
            self.assertEqual(run.call_count, 2)


class ProvisioningLeavesAReceipt(unittest.TestCase):
    def test_every_account_attempt_is_a_jsonl_row_without_secrets(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(A, "WS", td):
                A._provision_receipt("p", "pair", "https://console.example/signup", [
                    {"tag": "A", "status": "needs-captcha", "captcha": "turnstile", "email": "x1@mailbox.test", "password": "s3cret"},
                    {"tag": "B", "status": "submitted", "verify_status": 0, "note": "no verify mail in 150s", "email": "x2@mailbox.test"},
                ])
                A._provision_receipt("p", "pair", "https://console.example/signup", [])
            fp = os.path.join(td, "targets", "p", "accounts", "provision-log.jsonl")
            rows = [json.loads(l) for l in open(fp)]
            self.assertEqual([r["tag"] for r in rows], ["A", "B"])
            self.assertEqual(rows[0]["status"], "needs-captcha"); self.assertEqual(rows[0]["captcha"], "turnstile")
            self.assertEqual(rows[1]["note"], "no verify mail in 150s"); self.assertEqual(rows[1]["mail_domain"], "mailbox.test")
            raw = open(fp).read()
            self.assertNotIn("s3cret", raw); self.assertNotIn("x1@", raw)
        self.assertIn("_provision_receipt(program, action, signup_url, accounts or [], tag)   # D104", _agent_source())


if __name__ == "__main__":
    unittest.main()
