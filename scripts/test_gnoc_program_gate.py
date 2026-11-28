"""The cross-program gate, the counted-probe floor and hunt_phase (stdlib unittest, no network, no live writes).

Measured 2026-10-25 by driving the live `gnoc chat` with five prompts that each named a program: every one ran
against the STICKY program instead. "On program-101, add this hypothesis" wrote it into program-64's ledger; "On program-0,
is edge E1 proven?" was answered from program-64's E1 and reported as program-0's; "mark program-101 H6 dead" read
program-64's H6 and recorded an outcome row for program-64. The model never passes program= to the ledger tools and
nothing in the tool layer looked at the program the turn named."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_hunt as H  # noqa: E402


class _Two(unittest.TestCase):
    """Two intaken programs, 'alpha' active and 'bravo' named in the turn."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-proggate-")
        self.saved = (H.path, H.WS, G.WS)
        H.WS = G.WS = self.tmp
        H.path = lambda program: os.path.join(self.tmp, "targets", program, "hunts", "gnoc", "ledger.json")
        for p in ("alpha", "bravo"):
            os.makedirs(os.path.join(self.tmp, "targets", p, "hunts", "gnoc"), exist_ok=True)
            with open(os.path.join(self.tmp, "targets", p, "SCOPE.txt"), "w") as f:
                f.write(f"www.{p}-t.com\n")
            H.model(p, "add", boundaries=f"B1: {p} orders readable only by their owner; excludes other customers")
        self.ctx = G.Ctx({"program": "alpha"})

    def tearDown(self):
        H.path, H.WS, G.WS = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def turn(self, text):
        self.ctx.s["_turn_user"] = text

    def hyp(self, **kw):
        base = dict(action="add", title="order read by a stranger", crown="cross-user-read", boundary="B1",
                    assumption="a", violation="GET /api/orders/{B} as A", prediction="200 with B's address",
                    kill_byte="B-street")
        base.update(kw)
        return G.t_hunt_hypothesis(self.ctx, **base)


class TurnProgram(_Two):
    def test_it_finds_the_one_named_program(self):
        for text in ("On bravo, add this hypothesis", "mark the bravo H6 dead", "is edge E1 proven for bravo?",
                     "probe bravo now", "what about program bravo"):
            self.turn(text)
            self.assertEqual(G._turn_program(self.ctx), "bravo", text)

    def test_it_is_silent_when_the_turn_names_the_active_program_or_none(self):
        for text in ("On alpha, add this hypothesis", "add this hypothesis", "", "what phase are we in"):
            self.turn(text)
            self.assertIsNone(G._turn_program(self.ctx), text)

    def test_it_is_silent_when_two_programs_are_named(self):
        self.turn("compare bravo and alpha, then on bravo add it")   # ambiguous: the gate must not pick one
        self.assertIsNone(G._turn_program(self.ctx))

    def test_english_words_do_not_resolve_to_a_program(self):
        """resolve_program's substring tier turns English into a target ("all" -> program-53), so the gate is
        strict. A false positive here would refuse every write on an unrelated sentence."""
        for text in ("make all the tests pass", "read the ledger", "on the floor, what counts",
                     "for the record, probe it", "in the brief it says 8 probes"):
            self.turn(text)
            self.assertIsNone(G._turn_program(self.ctx), text)


class NoStickyProgramStillResolvesTheTurnsProgram(_Two):
    """QAQC 2026-11-03. `_need_program` tested only the sticky `ctx.program`, while `_read_program`
    in the very next line of each caller already resolves the program the TURN names. On a resumed
    program-63 conversation that carried no sticky program, both hypotheses the turn asked for by name
    were refused with "no active program" and the lane fired nothing for two turns. The companion
    half: `_program_gate_write` then claimed the write "would land on the wrong target's ledger"
    when the active program was None - a refusal naming no real risk."""

    def setUp(self):
        super().setUp()
        self.ctx = G.Ctx({})          # a conversation with NO sticky program
        self.turn("hunt bravo for a cross-user read")

    def test_a_read_is_not_refused(self):
        out = G.t_hunt_hypothesis(self.ctx, action="list")
        self.assertNotIn("no active program", out, out)

    def test_a_write_lands_in_the_named_programs_ledger(self):
        out = self.hyp()
        self.assertNotIn("no active program", out, out)
        self.assertNotIn("wrong target", out, out)
        self.assertTrue(H.load("bravo").get("hypotheses"), "the hypothesis must land in bravo's ledger")
        self.assertFalse(H.load("alpha").get("hypotheses"), "and never in alpha's")

    def test_the_model_and_edge_tools_agree(self):
        self.assertNotIn("no active program", G.t_hunt_model(self.ctx, action="show"))
        self.assertNotIn("no active program", G.t_hunt_edge(self.ctx, action="list"))

    def test_with_nothing_named_and_nothing_sticky_it_still_refuses(self):
        """The refusal must survive for the case it was written for."""
        ctx = G.Ctx({})
        ctx.s["_turn_user"] = "what should I look at today"
        self.assertIn("no active program", G.t_hunt_hypothesis(ctx, action="list"))

    def test_the_mis_filing_guard_still_fires_when_a_program_IS_active(self):
        """The 2026-10-25 receipt (a program-101 hypothesis written into program-64) must stay caught."""
        ctx = G.Ctx({"program": "alpha"})
        ctx.s["_turn_user"] = "hunt bravo for a cross-user read"
        base = dict(action="add", title="t", crown="cross-user-read", boundary="B1", assumption="a",
                    violation="v", prediction="p", kill_byte="k")
        self.assertIn("wrong target", G.t_hunt_hypothesis(ctx, **base))


class WritesAreRefused(_Two):
    def test_a_hypothesis_for_another_program_is_refused_not_misfiled(self):
        self.turn("On bravo, add this hypothesis about order reads")
        out = self.hyp()
        self.assertIn("refused", out)
        self.assertIn("set_program(program='bravo')", out)
        self.assertEqual(H.load("bravo")["hypotheses"], [])
        self.assertEqual(H.load("alpha")["hypotheses"], [])

    def test_the_same_call_lands_once_the_program_is_active(self):
        self.turn("On bravo, add this hypothesis about order reads")
        self.assertIn("refused", self.hyp())
        G.t_set_program(self.ctx, "bravo")
        self.assertTrue(self.hyp().startswith("added H1"))
        self.assertEqual(len(H.load("bravo")["hypotheses"]), 1)
        self.assertEqual(H.load("alpha")["hypotheses"], [])

    def test_an_edge_and_a_model_item_are_refused_the_same_way(self):
        self.turn("for bravo, record the hop")
        out = G.t_hunt_edge(self.ctx, "add", frm="unauth", to="ato", via="POST /x")
        self.assertIn("refused", out)
        self.assertIn("bravo", out)
        self.assertEqual(H.load("bravo")["edges"], [])
        out = G.t_hunt_model(self.ctx, "add", catastrophes="full account takeover of any bravo customer")
        self.assertIn("refused", out)

    def test_an_update_is_a_write_too(self):
        self.hyp()                                   # H1 on alpha, no program named
        self.turn("on bravo, mark H1 dead")
        out = G.t_hunt_hypothesis(self.ctx, "update", id="H1", status="dead")
        self.assertIn("refused", out)
        self.assertEqual(H.load("alpha")["hypotheses"][0]["status"], "open")


class ReadsResolve(_Two):
    def test_a_read_answers_for_the_named_program_and_says_so(self):
        G.t_set_program(self.ctx, "bravo")
        self.hyp(title="bravo only hypothesis")
        G.t_set_program(self.ctx, "alpha")
        self.turn("On bravo, list the hypotheses")
        out = G.t_hunt_hypothesis(self.ctx, "list")
        self.assertIn("this turn names bravo", out)
        self.assertIn("bravo only hypothesis", out)

    def test_a_read_with_no_other_program_named_is_unchanged(self):
        self.hyp(title="alpha hypothesis")
        self.turn("list the hypotheses")
        out = G.t_hunt_hypothesis(self.ctx, "list")
        self.assertNotIn("this turn names", out)
        self.assertIn("alpha hypothesis", out)


class CountedFloor(_Two):
    def capture(self, name, url, status, body="x" * 35):
        import json
        d = os.path.join(self.tmp, "targets", "alpha", "hunts", "lane", "raw")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name + ".json")
        with open(p, "w") as f:
            json.dump({"request": {"method": "GET", "url": url}, "response": {"status": status, "body": body}}, f)
        return p

    def test_a_walled_hypothesis_cannot_reach_the_dead_floor_through_record_outcome(self):
        self.hyp()
        for i in range(10):      # 10 probes, all of them one refusal shape on one route
            H.log_probe("alpha", "H1", self.capture(f"w{i}", "https://www.alpha-t.com/api/v1/ghost", 403))
        why = G.floor_check("alpha", "H1", "not single-use: a plain read")
        self.assertIn("0 counted probes", why)
        self.assertIn("never answered 2xx", why)
        out = G.t_record_outcome(self.ctx, "ghost route", "DEAD", hypothesis="H1",
                                 not_single_use="not single-use: a plain read, no one-shot step")
        self.assertIn("refused", out)

    def test_a_real_floor_still_passes(self):
        self.hyp()
        for i in range(8):
            H.log_probe("alpha", "H1", self.capture(f"r{i}", f"https://www.alpha-t.com/api/orders/{i}", 200, "own"))
        H.mark_burst("alpha", "H1", 10)
        self.assertIsNone(G.floor_check("alpha", "H1"))


class BulkAndOutcomeWrites(_Two):
    """QA run 1, 2026-10-25: the refused hypothesis add was recovered correctly (the model called set_program
    itself), but it then called hypothesize three times in one turn and wrote five unprobed hypotheses before the
    360 s cap killed the turn. hypothesize and record_outcome are ledger WRITES and were both ungated."""

    def test_generated_hypotheses_are_refused_for_another_program(self):
        self.turn("On bravo, hypothesize three crown-aimed ideas")
        out = G.t_hypothesize(self.ctx, n=3)
        self.assertIn("refused", out)
        self.assertIn("set_program(program='bravo')", out)
        self.assertEqual(H.load("bravo")["hypotheses"], [])

    def test_hypothesize_runs_once_a_turn(self):
        calls = []
        saved = (H.tournament, G._propose, G.resolve)
        H.tournament = lambda prog, props, n: (None, f"added H1 ({len(calls)})") if calls.append(prog) is None else None
        G.resolve = lambda role, quiet=False: ("m", "local")        # no GPU in a unit test
        G._propose = lambda model, host, msgs: [{"title": "t", "crown": "ato"}]
        try:
            self.turn("hypothesize for this program")
            out1 = G.t_hypothesize(self.ctx, n=3)
            out2 = G.t_hypothesize(self.ctx, n=3)
        finally:
            H.tournament, G._propose, G.resolve = saved
        self.assertNotIn("refused", out1)
        self.assertIn("already ran hypothesize this turn", out2)
        self.assertEqual(len(calls), 1)

    def test_an_outcome_row_for_another_program_is_refused(self):
        self.turn("record the bravo lane as a LEAD")
        out = G.t_record_outcome(self.ctx, "GET /x", "LEAD")
        self.assertIn("refused", out)
        self.assertIn("bravo", out)

    def test_an_unknown_hypothesis_id_says_so_instead_of_zero_probes(self):
        """"0 counted probes" for an id that is not on this ledger reads as "your 20 probes do not count", and
        the live lead twice explained it with an invented "mutation threshold"."""
        self.hyp()
        why = G.floor_check("alpha", "H9")
        self.assertIn("no hypothesis H9 on alpha", why)
        self.assertIn("H1", why)
        self.assertNotIn("counted probes", why)


class HuntPhase(_Two):
    def test_it_names_the_phase_without_starting_a_hunt(self):
        out = G.t_hunt_phase(self.ctx)
        self.assertIn("alpha: PHASE COMPREHEND", out)     # a model but no hypotheses, and not briefed yet
        self.assertIn("read-only", out)
        self.hyp()
        self.ctx.s["briefed"] = {"alpha": True}
        # one hypothesis is fewer than the three the loop wants live, so it asks for more before probing
        self.assertIn("alpha: PHASE HYPOTHESIZE", G.t_hunt_phase(self.ctx))
        # distinct enough to clear the near-duplicate guard: _sim drops tokens under three characters, so
        # "b seam" and "c seam" are one title to it
        for t in ("coupon race", "merge owner key drift"):
            self.hyp(title=t, violation=f"POST /{t.split()[0]}/1")
        self.assertIn("alpha: PHASE PROBE", G.t_hunt_phase(self.ctx))

    def test_it_answers_for_the_program_the_turn_names(self):
        self.turn("what phase is bravo in and why not PROBE")
        self.assertIn("bravo: PHASE", G.t_hunt_phase(self.ctx))
        self.assertIn("bravo: PHASE", G.t_hunt_phase(self.ctx, program="bravo"))

    def test_reading_the_phase_does_not_spend_the_hunts_budget(self):
        """directive() ticks the escalation and parking counters by design; a phase QUERY must not, or asking
        what phase we are in parks a hypothesis (it did, on three live ledgers, 2026-10-25)."""
        self.hyp()
        H.hypothesis("alpha", "update", id="H1", status="lead",
                     evidence=self._lead_capture())
        before = H.load("alpha")["hypotheses"][0].copy()
        for _ in range(5):
            G.t_hunt_phase(self.ctx)
        self.assertEqual(H.load("alpha")["hypotheses"][0], before)

    def _lead_capture(self):
        import json
        d = os.path.join(self.tmp, "targets", "alpha", "hunts", "lane", "raw")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "lead.json")
        with open(p, "w") as f:
            json.dump({"request": {"method": "GET", "url": "https://www.alpha-t.com/api/orders/1"},
                       "response": {"status": 200, "body": '{"owner":"A"}'}}, f)
        return p


class GoalTextBecomesTheTurnText(_Two):
    """2026-11-10 00:36Z and 00:46Z, live chat: a slash command never refreshes `_turn_user`, so at /goal time the
    cross-program gate read the PREVIOUS turn's program out of it and refused every goal-seeded hypothesis
    ("this turn is about program-58, but the active program is program-50"). The goal started with none."""

    class _Agent:
        def __init__(self, ctx):
            self.ctx = ctx
            self.s = ctx.s

    def test_stale_turn_text_refuses_and_the_goal_text_clears_it(self):
        self.turn("achieve zero click ato on bravo")          # the previous turn named bravo
        self.ctx.s["program"] = "alpha"                        # the goal switched the program to alpha
        self.assertIsNotNone(G._program_gate_write(self.ctx, "a hypothesis"))
        G._goal_turn_text(self._Agent(self.ctx), {"text": "achieve unauthenticated ato on alpha, production"})
        self.assertEqual(self.ctx.s["_turn_user"], "achieve unauthenticated ato on alpha, production")
        self.assertIsNone(G._program_gate_write(self.ctx, "a hypothesis"))

    def test_a_goal_naming_no_program_still_clears_the_stale_text(self):
        self.turn("probe bravo now")
        G._goal_turn_text(self._Agent(self.ctx), {"text": "reach rce"})
        self.assertIsNone(G._program_gate_write(self.ctx, "a hypothesis"))


if __name__ == "__main__":
    unittest.main()
