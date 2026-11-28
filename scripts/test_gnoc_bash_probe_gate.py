#!/usr/bin/env python3
"""The bash tool refuses an HTTP client aimed at an IN-SCOPE host and points at http_request (stdlib unittest, no
network). Measured 2026-11-10 00:38Z on the live chat: the lead's first three program-58 probes were raw `curl`
through bash (no identification header, no raw capture, plain-curl JA3; two deepwiki 429s read as a wall) and it
stayed on bash until the 60-call cap. The scope gate only knows out-of-scope; in-scope curl walked straight through."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402
import gnoc_hunt as H  # noqa: E402


class BashProbeGate(unittest.TestCase):
    def setUp(self):
        from bbtools import lib_scope
        self.L = lib_scope
        self.saved = (lib_scope.exact_hosts, lib_scope.wildcard_apexes)
        lib_scope.exact_hosts = lambda program, root=None: ["www.alpha-t.com", "api.alpha-t.com"] if program == "alpha" else []
        lib_scope.wildcard_apexes = lambda program, root=None: ["alpha-wild.cn"] if program == "alpha" else []

    def tearDown(self):
        self.L.exact_hosts, self.L.wildcard_apexes = self.saved

    def test_curl_at_an_in_scope_host_is_refused_toward_http_request(self):
        why = G._bash_target_probe("curl -m 8 -s -o /tmp/x https://www.alpha-t.com/login", "alpha")
        self.assertIsNotNone(why)
        self.assertIn("www.alpha-t.com", why)
        self.assertIn("http_request", why)

    def test_wildcard_scope_rows_are_matched_on_the_suffix(self):
        why = G._bash_target_probe("wget -qO- https://deep.api.alpha-wild.cn/v1/x", "alpha")
        self.assertIsNotNone(why)
        self.assertIn("deep.api.alpha-wild.cn", why)

    def test_python_requests_at_the_host_counts_as_a_client(self):
        why = G._bash_target_probe("python3 -c \"import requests; print(requests.get('https://api.alpha-t.com/').status_code)\"", "alpha")
        self.assertIsNotNone(why)

    def test_local_work_on_captures_that_mention_the_host_passes(self):
        for cmd in ("grep -o 'api.alpha-t.com[^\"]*' recon/urls.jsonl | sort -u",
                    "cat hunts/gnoc-agent/raw/www.alpha-t.com-root.resp | head",
                    "python3 - <<'EOF'\nimport json\nprint(json.load(open('x.json'))['url'])\nEOF"):
            self.assertIsNone(G._bash_target_probe(cmd, "alpha"), cmd)

    def test_a_client_at_a_host_outside_scope_is_not_this_gates_business(self):
        self.assertIsNone(G._bash_target_probe("curl -s https://example.org/", "alpha"))
        self.assertIsNone(G._bash_target_probe("curl -s http://127.0.0.1:9222/json", "alpha"))

    def test_no_program_means_no_gate(self):
        self.assertIsNone(G._bash_target_probe("curl -s https://www.alpha-t.com/", None))

    def test_the_tool_itself_returns_the_refusal(self):
        ctx = G.Ctx({"program": "alpha"})
        saved_gate = G._scope_gate_bash
        G._scope_gate_bash = lambda cmd, program: None
        try:
            out = G.t_bash(ctx, "curl -s https://www.alpha-t.com/")
        finally:
            G._scope_gate_bash = saved_gate
        self.assertTrue(str(out).startswith("refused: that bash command drives an HTTP client"), out)


class BashNonUtf8Output(unittest.TestCase):
    """2026-11-10 01:32Z, program-50: a GBK capture from a .cn host killed the whole bash call with
    UnicodeDecodeError. Bytes that are not UTF-8 are replaced, never raised."""

    def test_invalid_utf8_bytes_come_back_as_text(self):
        # another suite may leave the agent's working directory pointing into its deleted tempdir; pin it
        saved = list(G._ACTIVE_ROOT)
        G._ACTIVE_ROOT[0] = G.WS
        self.addCleanup(lambda: G._ACTIVE_ROOT.__setitem__(0, saved[0]))
        ctx = G.Ctx({"program": None})
        out = G.t_bash(ctx, "printf 'ok \\xe8\\xa8 tail\\n'")
        self.assertNotIn("UnicodeDecodeError", str(out))
        self.assertIn("ok", str(out))
        self.assertIn("tail", str(out))


class IdenticalHypothesisAddIsALoop(unittest.TestCase):
    """2026-11-10 01:36Z: one refused hunt_hypothesis add re-sent byte-identical 7 times. The ledger tool is exempt
    from the exact-repeat guard for list/show/update; an identical `add` now trips it like bash or http_request."""

    def test_fourth_identical_add_is_refused_and_update_stays_exempt(self):
        ctx = G.Ctx({"program": "alpha"})
        args = {"action": "add", "title": "x", "violation": "GET /api/nope"}
        notes = [G._repeat_note(ctx, "hunt_hypothesis", dict(args)) for _ in range(4)]
        self.assertTrue(all(n is None for n in notes[:3]), notes)
        self.assertIsNotNone(notes[3])
        self.assertIn("already made this exact hunt_hypothesis call", notes[3])
        for _ in range(6):
            self.assertIsNone(G._repeat_note(ctx, "hunt_hypothesis", {"action": "list"}))


class DelegateRefusesAFileAWorkerCannotIngest(unittest.TestCase):
    """2026-11-10 03:35Z program-50: a 1.5 MB minified-bundle capture was delegated to the local 9B worker, which
    timed out after 420 s while the lead waited. A brief naming a file above DELEGATE_FILE_CAP is refused before
    any worker starts, and the refusal names js_mine and the byte-window grep; a small file still goes through."""

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()
        self.big = os.path.join(self.d, "022350524378-get.json")
        with open(self.big, "wb") as f:
            f.write(b"x" * (G.DELEGATE_FILE_CAP + 1))
        self.small = os.path.join(self.d, "small.json")
        with open(self.small, "wb") as f:
            f.write(b"{}")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_a_brief_naming_a_big_file_is_refused_with_the_right_tools(self):
        ctx = G.Ctx({"program": "alpha"})
        out = G.t_delegate(ctx, f"Read the file {self.big} (a JSON capture) and list every /api route in response.body")
        self.assertTrue(out.startswith("refused:"), out)
        self.assertIn("js_mine", out)
        self.assertIn("around=", out)
        self.assertIn(self.big, out)

    def test_fan_out_applies_the_same_cap(self):
        ctx = G.Ctx({"program": "alpha"})
        out = G.t_fan_out(ctx, [f"grep {self.small} for x", f"read {self.big} and extract routes"])
        self.assertTrue(out.startswith("refused:"), out)
        self.assertIn(self.big, out)

    def test_a_small_file_does_not_trip_the_cap(self):
        self.assertIsNone(G._oversized_file_in([f"read {self.small} and report the keys"]))
        self.assertIsNone(G._oversized_file_in(["probe https://example.invalid/ and report the status"]))


class HuntingTurnCapsTheDevTools(unittest.TestCase):
    """2026-11-10 03:04-03:40Z program-50: one 224-call turn wrote a bundle miner plus its test suite (37 run_tests,
    32 edit_file, 14 write_file) and fired 6 probes. While /hunt runs, edit_file, write_file and run_tests carry a
    small per-turn cap with a hunt-specific refusal; outside a hunt the same tools keep the default cap."""

    def test_run_tests_is_cut_in_a_hunting_turn_with_the_hunt_refusal(self):
        ctx = G.Ctx({"program": "alpha"})
        ctx.s["_hunting"] = True
        cap = G._HUNT_DEV_CAP["run_tests"]
        notes = [G._turn_volume_note(ctx, "run_tests") for _ in range(cap + 1)]
        self.assertTrue(all(n is None for n in notes[:cap]), notes)
        self.assertIsNotNone(notes[cap])
        self.assertIn("hunting, not developing", notes[cap])
        self.assertIn("run_tests", ctx.s.get("_turn_off", []))

    def test_edit_file_keeps_the_default_cap_outside_a_hunt(self):
        ctx = G.Ctx({"program": "alpha"})
        cap = G._HUNT_DEV_CAP["edit_file"]
        notes = [G._turn_volume_note(ctx, "edit_file") for _ in range(cap + 5)]
        self.assertTrue(all(n is None for n in notes), notes)

    def test_the_cap_function_only_answers_the_dev_caps_when_hunting(self):
        self.assertEqual(G._turn_call_cap("write_file", hunting=True), G._HUNT_DEV_CAP["write_file"])
        self.assertNotEqual(G._turn_call_cap("write_file"), G._HUNT_DEV_CAP["write_file"])
        self.assertEqual(G._turn_call_cap("hunt_hypothesis", hunting=True), G._TURN_CALL_CAP["hunt_hypothesis"])


class ARefusedVerdictResentIsALoop(unittest.TestCase):
    """2026-11-10 04:07Z program-50: 266 `hunt_hypothesis update status=dead` calls in one process, each refused by
    the probe floor and re-sent with new notes. Verdict writes still pass the per-turn cap (a verdict is never a
    loop), but the same (id, status) only VERDICT_RETRIES times; after that the tool is off for the turn."""

    def _spend_cap(self, ctx):
        for _ in range(G._TURN_CALL_CAP["hunt_hypothesis"]):
            G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "list"})

    def test_the_same_refused_verdict_is_cut_after_the_retries(self):
        ctx = G.Ctx({"program": "alpha"})
        self._spend_cap(ctx)
        args = {"action": "update", "id": "H13", "status": "dead", "notes": "x"}
        notes = [G._turn_volume_note(ctx, "hunt_hypothesis", dict(args, notes=f"try {i}"))
                 for i in range(G.VERDICT_RETRIES + 1)]
        self.assertTrue(all(n is None for n in notes[:G.VERDICT_RETRIES]), notes)
        self.assertIsNotNone(notes[G.VERDICT_RETRIES])
        self.assertIn("H13:dead", notes[G.VERDICT_RETRIES])
        self.assertIn("hunt_hypothesis", ctx.s.get("_turn_off", []))

    def test_a_different_hypothesis_verdict_still_passes(self):
        ctx = G.Ctx({"program": "alpha"})
        self._spend_cap(ctx)
        for i in range(G.VERDICT_RETRIES + 1):
            G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "update", "id": "H13", "status": "dead"})
        # H13 is cut; H14's first verdict of the turn is not a repeat, but the tool is off now, which _live_tools
        # enforces; the note itself is None because the retry counter is per (id, status)
        self.assertIsNone(G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "update", "id": "H14", "status": "lead"}))


class EveryActingHuntToolIsOfferedOnAHuntTurn(unittest.TestCase):
    """2026-11-10 04:10Z: host_sweep existed in TOOLS and ACTING_TOOLS but not in HUNT_TOOLS, so two hunt sessions
    were briefed to call it and never could. A tool registered as a hunt-time probe must be in the hunt toolset."""

    def test_host_sweep_is_in_the_hunt_toolset(self):
        self.assertIn("host_sweep", G.HUNT_TOOLS)
        self.assertIn("host_sweep", G.TOOLS)

    def test_the_probe_tools_the_floor_relies_on_are_all_offered(self):
        for name in ("http_request", "probe_matrix", "race", "sweep", "host_sweep", "js_mine"):
            self.assertIn(name, G.HUNT_TOOLS, name)
            self.assertIn(name, G.TOOLS, name)


class PolicyHeaderWins(unittest.TestCase):
    """2026-11-10 01:40Z program-50: three probes went out as X-HackerOne-Research: gnoc-research, a handle the lead
    typed. The programme's carrier value from the policy overwrites a hand-typed one; a matching value is kept."""

    def test_hand_typed_handle_is_replaced_by_the_policy_value(self):
        pol = {"header": ("X-HackerOne-Research", "greynoc")}
        out = G._apply_carrier({"Accept": "application/json", "x-hackerone-research": "gnoc-research"}, pol, handle="greynoc")
        vals = [v for k, v in out.items() if k.lower() == "x-hackerone-research"]
        self.assertEqual(vals, ["greynoc"], out)

    def test_a_correct_value_is_left_alone(self):
        pol = {"header": ("X-HackerOne-Research", "greynoc")}
        out = G._apply_carrier({"X-HackerOne-Research": "greynoc"}, pol, handle="greynoc")
        self.assertEqual(out.get("X-HackerOne-Research"), "greynoc")

    def test_an_unrequested_identification_header_is_dropped(self):
        # program-19 2026-11-25: the lead typed X-HackerOne: greynoc; the policy asks for no header
        out = G._apply_carrier({"X-HackerOne": "greynoc", "Accept": "*/*"}, {}, handle="greynoc")
        self.assertEqual(out, {"Accept": "*/*"})

    def test_only_the_policy_named_header_survives(self):
        pol = {"header": ("X-HackerOne-Handle", "greynoc")}
        out = G._apply_carrier({"X-HackerOne": "greynoc", "X-Bugcrowd-Research": "x"}, pol, handle="greynoc")
        self.assertEqual(out, {"X-HackerOne-Handle": "greynoc"})


class ApprovalPromptDoesNotStallForever(unittest.TestCase):
    """2026-11-10 01:39Z: a copy-gate "? allow bash" under /goal with skip-perms on sat unanswered for 12 minutes.
    With nothing on stdin inside APPROVAL_WAIT_S the answer is no and the loop moves on."""

    def test_no_answer_within_the_wait_is_no(self):
        saved = (G._stdin_ready, G.say)
        G._stdin_ready = lambda timeout: False
        G.say = lambda *a, **k: None
        try:
            self.assertEqual(G._approve("bash", {"command": "echo hi"}, True), "n")
        finally:
            G._stdin_ready, G.say = saved


class FanOutSlotsNeedAnAnsweringModel(unittest.TestCase):
    """2026-11-10 02:04Z: three fan-out bots sat on a cold local model until "model error: timed out" while the lead
    waited. A slot that does not answer a short warm-up is dropped; with none left the lead's model takes the bots."""

    def setUp(self):
        self.saved = (G.resolve, G._slot_answers, G.say)
        G.resolve = lambda role, quiet=False: ("worker-9b", "local") if role == "worker" else ("deepseek-chat", "deepseek")
        G.say = lambda *a, **k: None

    def tearDown(self):
        G.resolve, G._slot_answers, G.say = self.saved

    def test_dead_worker_slot_falls_back_to_the_lead(self):
        G._slot_answers = lambda m, h, **k: False
        self.assertEqual(G._bot_slots(), [("deepseek-chat", "deepseek")])

    def test_live_worker_slot_is_kept(self):
        G._slot_answers = lambda m, h, **k: True
        self.assertEqual(G._bot_slots(), [("worker-9b", "local")])


class VerdictWritesPassThePerTurnCap(unittest.TestCase):
    """2026-11-10 02:24Z: the hunt_hypothesis per-turn cap was spent on adds and reads and the lead could not record
    H7's verdict ("blocked on H7's decision"). A status update passes the cap; an add past the cap is still refused."""

    def test_status_update_passes_after_the_cap_is_spent(self):
        ctx = G.Ctx({"program": "alpha"})
        cap = G._turn_call_cap("hunt_hypothesis") or 10
        for _ in range(cap):
            G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "add"})
        self.assertIsNotNone(G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "add"}))
        self.assertIsNone(G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "update", "id": "H7", "status": "dead"}))
        self.assertIsNotNone(G._turn_volume_note(ctx, "hunt_hypothesis", {"action": "list"}))


class HostSweepTriagesManyHosts(unittest.TestCase):
    """2026-11-10 02:50Z program-50: 187 wildcard zones, bash refuses a $h loop at an in-scope host, sweep is one host
    many paths, so liveness went one http_request per host. host_sweep sends one gated GET per host and reports a
    line each; out-of-scope hosts are refused by the gate, not sent."""

    def setUp(self):
        self.saved = (G._program_gate, G._send, G.gnoc_hunt.log_probe)
        G._program_gate = lambda program, url: (({"rps": 1}, None) if "good" in url else (None, "refused: OUT_OF_SCOPE"))
        G._send = lambda program, pol, u, m, h, b, hypothesis=None: (f"HTTP 200 len=12 via=direct {u}", {"url": u})
        G.gnoc_hunt.log_probe = lambda *a, **k: None

    def tearDown(self):
        G._program_gate, G._send, G.gnoc_hunt.log_probe = self.saved

    def test_one_line_per_host_and_gate_refusals_are_not_sent(self):
        ctx = G.Ctx({"program": "alpha"})
        out = G.t_host_sweep(ctx, ["good-a.test", "https://good-b.test/", "other.test"], path="/admin/")
        self.assertIn("2 host(s) answered", out)
        self.assertIn("1 refused", out)
        self.assertIn("good-a.test", out)
        self.assertIn("good-b.test", out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("via=direct https://other", out)

    def test_bad_hosts_argument_is_refused(self):
        ctx = G.Ctx({"program": "alpha"})
        self.assertTrue(G.t_host_sweep(ctx, ["https://x/{{H}}", "$h"]).startswith("bad arguments"))


class DeadOriginIsWalledAfterTwoTimeouts(unittest.TestCase):
    """2026-11-10 03:00Z program-50: the admin SPA's API origin black-holed every connection; the lead paid 30 s per
    probe, four times in seven minutes, with four hypotheses parked on that host. Two connect timeouts wall the host
    for 15 minutes and the sender refuses before the wire with a message that says what to record."""

    def setUp(self):
        G._HOST_DOWN.clear()

    def tearDown(self):
        G._HOST_DOWN.clear()

    def test_two_timeouts_wall_the_host_and_a_non_timeout_does_not_count(self):
        u = "https://dead-origin.test/mongodb/currentOps"
        self.assertIsNone(G._host_down_note(u))
        G._mark_host_down(u, TimeoutError("Connection timed out after 30001 milliseconds"))
        self.assertIsNone(G._host_down_note(u), "one timeout is a retry, not a wall")
        G._mark_host_down(u, RuntimeError("HTTP 500"))
        self.assertIsNone(G._host_down_note(u), "a non-timeout failure does not count")
        G._mark_host_down("https://dead-origin.test/other", TimeoutError("timed out"))
        note = G._host_down_note(u)
        self.assertIsNotNone(note)
        self.assertIn("HOST UNREACHABLE", note)
        self.assertIn("UNFIRED", note)
        self.assertIsNone(G._host_down_note("https://alive.test/"), "another host is untouched")

    def test_the_sender_refuses_a_walled_host_before_the_wire(self):
        u = "https://dead-origin.test/x"
        for _ in range(2):
            G._mark_host_down(u, TimeoutError("timed out"))
        with self.assertRaises(G.HostUnreachable):
            G._send("alpha", {}, u)


if __name__ == "__main__":
    unittest.main()
