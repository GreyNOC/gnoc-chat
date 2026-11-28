"""Gates added 2026-10-25 after watching orch-bot live: churn / ping-pong refusal, line-work ownership, queued lanes
first, SALES skipping gate-killed drafts and collapsing slug-N copies, the standing-goal steer."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orch_brain as B  # noqa: E402
import gnoc_company as C  # noqa: E402


def _dec(action, status="ok", detail="", started=False):
    return {"ts": "t", "action": action, "status": status, "detail": detail, "started_job": started}


class Churn(unittest.TestCase):
    def test_two_moves_and_the_programs_left(self):
        rows = [_dec("pivot", detail="acmeprog: pivot: (none) -> acmeprog"),
                _dec("pivot", detail="program-60: pivot: acmeprog -> program-60"),
                _dec("pick_target", detail="pivot: parked program-60; auto-target picks the next program")]
        with mock.patch.object(B, "last_decisions", return_value=rows):
            moved, left = B.churn()
        self.assertEqual(moved, 3)
        self.assertEqual(left, {"acmeprog", "program-60"})

    def test_a_started_job_resets_the_count(self):
        rows = [_dec("pivot", detail="a: pivot: (none) -> a"), _dec("sweep_host", started=True),
                _dec("pivot", detail="b: pivot: a -> b")]
        with mock.patch.object(B, "last_decisions", return_value=rows):
            moved, left = B.churn()
        self.assertEqual(moved, 1)
        self.assertIn("a", left)

    def test_rejected_moves_do_not_count(self):
        rows = [_dec("pivot", status="rejected", detail="x"), _dec("pivot", status="rejected", detail="y")]
        with mock.patch.object(B, "last_decisions", return_value=rows):
            self.assertEqual(B.churn()[0], 0)


class MoveGates(unittest.TestCase):
    def setUp(self):
        self.known = mock.patch.object(B, "known_program", return_value=True)
        self.known.start()
        self.policy = mock.patch.object(B, "policy_refusal", return_value="")
        self.policy.start()
        self.lock = mock.patch.object(B, "locked_program", return_value="")
        self.lock.start()

    def tearDown(self):
        self.known.stop()
        self.policy.stop()
        self.lock.stop()

    def test_queued_lane_forces_run_queue(self):
        with mock.patch.object(B, "line_work", return_value=([], ["acmeprog|lane|b|p"])):
            err = B.precheck({"action": "pivot", "program": "program-60", "reason": "x" * 40}, "acmeprog")
        self.assertIn("run_queue", err)

    def test_open_work_order_owns_the_program(self):
        with mock.patch.object(B, "line_work", return_value=(["acmeprog WO-1 at 0 SALES"], [])):
            err = B.precheck({"action": "pick_target", "reason": "x" * 40}, "acmeprog")
        self.assertIn("work order", err)

    def test_third_move_is_churn(self):
        with mock.patch.object(B, "line_work", return_value=([], [])), \
             mock.patch.object(B, "churn", return_value=(2, {"a"})):
            err = B.precheck({"action": "pivot", "program": "zzz", "reason": "x" * 40}, "acmeprog")
        self.assertIn("churn", err)

    def test_pivot_back_is_ping_pong(self):
        with mock.patch.object(B, "line_work", return_value=([], [])), \
             mock.patch.object(B, "churn", return_value=(1, {"program-60"})):
            err = B.precheck({"action": "pivot", "program": "program-60", "reason": "x" * 40}, "acmeprog")
        self.assertIn("ping-pong", err)

    def test_a_clean_pivot_still_passes_the_move_gates(self):
        with mock.patch.object(B, "line_work", return_value=([], [])), \
             mock.patch.object(B, "churn", return_value=(0, set())):
            err = B.precheck({"action": "pivot", "program": "program-60", "reason": "x" * 40}, "acmeprog")
        self.assertEqual(err, "")

    def test_work_actions_are_not_gated(self):
        with mock.patch.object(B, "line_work", side_effect=AssertionError("must not be called")):
            err = B.precheck({"action": "wait", "minutes": 5, "reason": "x" * 40}, "acmeprog")
        self.assertEqual(err, "")


class Sales(unittest.TestCase):
    def test_gate_killed_reads_the_newest_gate(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(C, "WS", td):
            d = os.path.join(td, "reports", "drafts", "p", "s")
            os.makedirs(d)
            open(os.path.join(d, "GATE-reviewer-agent.md"), "w").write("KILL\n\nVerdict: KILL\n")
            self.assertTrue(C.gate_killed("p", "s"))
            os.utime(os.path.join(d, "GATE-reviewer-agent.md"), (1, 1))
            open(os.path.join(d, "GATE-report-killer.md"), "w").write("PASS\n")
            self.assertFalse(C.gate_killed("p", "s"))
            self.assertFalse(C.gate_killed("p", "nope"))

    def test_goal_steer_doubles_the_crown_classes(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(C, "ORCH", td):
            self.assertEqual(C.goal_steer(), {})
            open(os.path.join(td, "GOAL.md"), "w").write("# goal\nCROWN: rce, ato\n")
            st = C.goal_steer()
        self.assertEqual(st.get("rce"), 2.0)
        self.assertEqual(st.get("improper-auth"), 2.0)
        self.assertNotIn("info-disclosure", st)

    def test_slug_copies_collapse_and_killed_drafts_are_skipped(self):
        board = ("| draft:p/thing-2 | ACTIVE | x | 0 |\n| draft:p/thing-3 | ACTIVE | x | 0 |\n"
                 "| draft:p/dead-1 | ACTIVE | x | 0 |\n")
        with mock.patch.object(C, "_read", side_effect=lambda f, *a: board if "RESCUE" in str(f) else ""), \
             mock.patch.object(C, "_jsonl", return_value=[]), mock.patch.object(C, "_autohunt", return_value=""), \
             mock.patch.object(C, "_scope_ok", return_value=True), mock.patch.object(C, "_lane_hosts", return_value=["h"]), \
             mock.patch.object(C, "_filing_ok", return_value=(True, "")), \
             mock.patch.object(C, "gate_killed", side_effect=lambda p, s: s.startswith("dead")), \
             mock.patch.object(C, "goal_steer", return_value={}):
            out = C.candidates({})
        crowns = [o["crown"] for o in out]
        self.assertEqual(len(out), 1, crowns)
        self.assertTrue(crowns[0].endswith(": thing"), crowns)


class Depth(unittest.TestCase):
    LEADS = ("- 2026-10-23T14:55:35Z ssrf-candidate 0 https://m.example.com/ :: /user/login?redirect=  (raw/m-js.js)\n"
             "- 2026-10-23T14:56:00Z unauth-json-route 200 https://api.example.com/api/pwa/homepage  (raw/x.resp)\n"
             "- 2026-10-23T14:57:00Z banner 200 https://www.example.com/robots.txt  (raw/y.resp)\n")

    def _ws(self, td, probes=""):
        os.makedirs(os.path.join(td, "targets", "p", "hunts", "auto-exposure"))
        open(os.path.join(td, "targets", "p", "hunts", "auto-exposure", "LEADS.md"), "w").write(self.LEADS)
        if probes:
            os.makedirs(os.path.join(td, "targets", "p", "hunts", "brain-x"))
            open(os.path.join(td, "targets", "p", "hunts", "brain-x", "PROBES.txt"), "w").write(probes)

    def test_unfollowed_chain_leads_rank_first(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(B, "WS", td), mock.patch.object(B, "ORCH", td):
            self._ws(td)
            leads = B.chain_leads("p")
        self.assertEqual([l["chain"] for l in leads], [True, True, False])
        self.assertIn("m.example.com", leads[0]["url"])

    def test_a_probed_url_counts_as_followed(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(B, "WS", td), mock.patch.object(B, "ORCH", td):
            self._ws(td, "b00|p.py b00 GET 'https://m.example.com/user/login?redirect=https://m.example.com/'\n"
                         "b01|p.py b01 GET 'https://api.example.com/api/pwa/homepage'\n")
            leads = B.chain_leads("p")
        self.assertEqual([l["url"] for l in leads], ["https://www.example.com/robots.txt"])

    def test_sweep_is_refused_while_a_chain_lead_waits(self):
        lead = {"kind": "ssrf-candidate", "url": "https://m.example.com/", "detail": "/user/login?redirect=", "chain": True}
        with mock.patch.object(B, "chain_leads", return_value=[lead]):
            err = B.precheck({"action": "sweep_next", "reason": "x" * 40}, "p")
            self.assertIn("depth before breadth", err)
            err = B.precheck({"action": "follow_up_lane", "urls": ["a", "b"], "brief": "x" * 50, "reason": "x" * 40}, "p")
        self.assertNotIn("depth before breadth", err)

    def test_no_chain_lead_no_gate(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(B, "WS", td), \
             mock.patch.object(B, "chain_leads", return_value=[{"kind": "banner", "url": "u", "detail": "", "chain": False}]), \
             mock.patch.object(B, "plan", return_value=([], ["h1"])), mock.patch.object(B, "resolve_host", return_value="h1"):
            os.makedirs(os.path.join(td, "targets", "p"))
            open(os.path.join(td, "targets", "p", "SCOPE.txt"), "w").close()
            err = B.precheck({"action": "sweep_host", "host": "h1", "reason": "x" * 40}, "p")
        self.assertEqual(err, "")


class LockPin(unittest.TestCase):
    def test_locked_program_reads_the_lock_when_it_has_a_scope(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(B, "WS", td), \
             mock.patch.object(B, "LOCK_FILE", os.path.join(td, "LOCK")):
            open(os.path.join(td, "LOCK"), "w").write("acmeprog\n")
            self.assertEqual(B.locked_program(), "")
            os.makedirs(os.path.join(td, "targets", "acmeprog"))
            open(os.path.join(td, "targets", "acmeprog", "SCOPE.txt"), "w").close()
            self.assertEqual(B.locked_program(), "acmeprog")

    def test_a_move_off_the_locked_program_is_refused(self):
        with mock.patch.object(B, "locked_program", return_value="acmeprog"), \
             mock.patch.object(B, "line_work", side_effect=AssertionError("refused before line_work")):
            err = B.precheck({"action": "pick_target", "reason": "x" * 40}, "acmeprog")
        self.assertIn("LOCKED", err)


class SweptProgram(unittest.TestCase):
    def test_a_sweep_on_a_fully_swept_program_is_refused(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.object(B, "WS", td), \
             mock.patch.object(B, "chain_leads", return_value=[]), mock.patch.object(B, "plan", return_value=(["h1"], [])):
            os.makedirs(os.path.join(td, "targets", "p"))
            open(os.path.join(td, "targets", "p", "SCOPE.txt"), "w").close()
            err = B.precheck({"action": "sweep_next", "reason": "x" * 40}, "p")
        self.assertIn("no unswept hosts", err)
        self.assertIn("follow_up_lane", err)


class RepeatedLanes(unittest.TestCase):
    """D61 (2026-10-26): a finished lane re-queued a minute later, 18 times in seven hours."""

    def test_the_program_name_is_stripped_from_a_copied_lane_name(self):
        self.assertEqual(B.lane_slug("brain-acmeprog-brain-api-auth-console-10260759", "acmeprog"), "api-auth-console")
        self.assertEqual(B.lane_slug("acmeprog/brain-api-auth-console-10260746", "acmeprog"), "api-auth-console")
        self.assertEqual(B.lane_slug("brain-brain-x-10211646"), "x")

    def test_a_slug_finished_twice_needs_mostly_new_urls(self):
        rows = [json.dumps({"ts": "2026-10-26T07:30:11Z", "program": "acmeprog", "lane": "brain-api-auth-console-10260716",
                            "flags": []}),
                json.dumps({"ts": "2026-10-26T08:06:35Z", "program": "acmeprog",
                            "lane": "brain-acmeprog-brain-api-auth-console-10260759", "flags": []}),
                json.dumps({"ts": "2026-10-26T08:06:35Z", "program": "other", "lane": "brain-api-auth-console-1", "flags": []})]
        fired = {"https://api.acmeprog.com/api/account", "https://api.acmeprog.com/api/auth/aws_refresh_creds"}
        d = {"lane": "api-auth-console", "urls": sorted(fired) + ["https://api.acmeprog.com/api/new-route"]}
        with mock.patch.object(B, "read", side_effect=lambda p, default="": "\n".join(rows) if p.endswith("done.jsonl") else ""), \
                mock.patch.object(B, "_lane_urls", return_value=set(fired)), \
                mock.patch.object(B.time, "time", return_value=1792972800.0 + 8 * 3600), \
                mock.patch.dict(B._ST, {"current": {}}, clear=True):
            self.assertEqual(len(B.finished_lanes("acmeprog", "api-auth-console")), 2)
            why = B.duplicate_lane(d, "acmeprog")
            self.assertIn("finished 2 times", why)
            self.assertIn("2 of 3 routes already fired", why)
            fresh = {"lane": "api-auth-console", "urls": ["https://api.acmeprog.com/a", "https://api.acmeprog.com/b",
                                                         "https://api.acmeprog.com/api/account"]}
            self.assertEqual(B.duplicate_lane(fresh, "acmeprog"), "")
            self.assertEqual(B.duplicate_lane({"lane": "billing-twin", "urls": sorted(fired)}, "acmeprog"), "")

    def test_query_string_variants_of_a_fired_route_are_the_same_route(self):
        rows = [json.dumps({"ts": "2026-10-26T08:06:35Z", "program": "acmeprog", "lane": "brain-api-auth-console-10260806", "flags": []}),
                json.dumps({"ts": "2026-10-26T08:20:13Z", "program": "acmeprog", "lane": "brain-api-auth-console-10260820", "flags": []})]
        fired = {f"https://api.acmeprog.com/api/auth/console?session=b{i:02d}" for i in range(20)}
        d = {"lane": "api-auth-console", "urls": ["https://api.acmeprog.com/api/auth/console",
                                                  "https://api.acmeprog.com/api/auth/console?nonsense=true",
                                                  "https://api.acmeprog.com/api/auth/console?debug=true"]}
        with mock.patch.object(B, "read", side_effect=lambda p, default="": "\n".join(rows) if p.endswith("done.jsonl") else ""), \
                mock.patch.object(B, "_lane_urls", return_value=set(fired)), \
                mock.patch.object(B.time, "time", return_value=1792972800.0 + 8.5 * 3600), \
                mock.patch.dict(B._ST, {"current": {}}, clear=True):
            why = B.duplicate_lane(d, "acmeprog")
            self.assertIn("1 of 1 routes already fired", why)

    def test_walled_urls_come_from_the_hunt_ledger(self):
        import gnoc_hunt
        with mock.patch.object(gnoc_hunt, "program_walls",
                               return_value={"api.acmeprog.com/api/account": ("403:215", 150)}):
            got = B.walled_urls("acmeprog", ["https://api.acmeprog.com/api/account?x=1",
                                              "https://api.acmeprog.com/api/other"])
        self.assertEqual(got, ["https://api.acmeprog.com/api/account?x=1"])


class UnfiredKnownRoutes(unittest.TestCase):
    """D65 (2026-10-26 08:43Z): the brain's material is the routes no lane fired, not the file's first 24 lines."""

    def test_fired_and_walled_routes_drop_out_and_the_hosts_are_listed(self):
        import gnoc_hunt
        kp = "/admin-settings/billing\n/api/account\n/api/auth/console\n/api/new/one\n/api/new/two\n"
        scope = "=api.acmeprog.com\n=console.acmeprog.com\n# comment\nclaude.ai  # host row\n"
        done = json.dumps({"ts": "2026-10-26T08:06:35Z", "program": "acmeprog", "lane": "brain-api-auth-console-10260806"})

        def _read(p, default=""):
            if p.endswith("known-paths.txt"):
                return kp
            if p.endswith("SCOPE.txt"):
                return scope
            if p.endswith("done.jsonl"):
                return done
            return ""
        with mock.patch.object(B, "read", side_effect=_read), \
                mock.patch("bbtools.lib_scope.parse_scope", side_effect=RuntimeError("no parser")), \
                mock.patch.object(B, "_lane_urls", return_value={"https://api.acmeprog.com/api/auth/console?session=b00"}), \
                mock.patch.object(gnoc_hunt, "program_walls", return_value={"api.acmeprog.com/api/account": ("403:215", 150)}):
            routes, total, fired = B.unfired_known_routes("acmeprog")
            hosts = B.scope_hosts("acmeprog")
        self.assertEqual(routes, ["/admin-settings/billing", "/api/new/one", "/api/new/two"])
        self.assertEqual((total, fired), (5, 2))   # D75: totals count API-shaped routes only (none are docs here)
        self.assertEqual(hosts, ["api.acmeprog.com", "console.acmeprog.com", "claude.ai"])

    def test_parse_scope_rows_lose_their_equals_prefix(self):
        with mock.patch("bbtools.lib_scope.parse_scope", return_value=["=api.acmeprog.com", "=claude.ai", "*.x.com"]):
            self.assertEqual(B.scope_hosts("acmeprog"), ["api.acmeprog.com", "claude.ai"])

    def test_scope_hosts_reads_the_url_row_shape_and_docs_sort_last(self):
        scope = ("# header\nURL            api.acmeprog.com\t[bounty; max=critical]\n"
                 "URL            claude.ai\t[bounty; max=critical]\n")
        kp = "/docs/en/a\n/docs/en/b\n/api/live\n"
        with mock.patch.object(B, "read", side_effect=lambda p, default="": scope if p.endswith("SCOPE.txt") else (kp if p.endswith("known-paths.txt") else "")), \
                mock.patch("bbtools.lib_scope.parse_scope", side_effect=RuntimeError("no parser")):
            self.assertEqual(B.scope_hosts("acmeprog"), ["api.acmeprog.com", "claude.ai"])
            routes, total, fired = B.unfired_known_routes("acmeprog")
        self.assertEqual(routes, ["/api/live"])   # D75: docs pages are not lane material at all
        self.assertEqual(total, 1)
        self.assertTrue(B._api_shaped("/api/live") and not B._api_shaped("/docs/en/a"))


class BarePathsResolve(unittest.TestCase):
    def test_lane_host_prefers_the_fired_host_then_api(self):
        done = json.dumps({"ts": "t", "program": "acmeprog", "lane": "brain-x-10260853"})
        with mock.patch.object(B, "read", side_effect=lambda p, default="": done if p.endswith("done.jsonl") else ""), \
                mock.patch.object(B, "_lane_urls", return_value={"https://api.acmeprog.com/a", "https://api.acmeprog.com/b"}), \
                mock.patch.object(B, "scope_hosts", return_value=["claude.ai", "api.acmeprog.com"]):
            self.assertEqual(B.lane_host("acmeprog"), "api.acmeprog.com")
        with mock.patch.object(B, "read", return_value=""), \
                mock.patch.object(B, "scope_hosts", return_value=["claude.ai", "api.acmeprog.com"]):
            self.assertEqual(B.lane_host("acmeprog"), "api.acmeprog.com")
        with mock.patch.object(B, "read", return_value=""), mock.patch.object(B, "scope_hosts", return_value=["claude.ai"]):
            self.assertEqual(B.lane_host("acmeprog"), "claude.ai")


class GuessedRoutesAreNotLaneMaterial(unittest.TestCase):
    def test_unmined_paths_drop_and_one_control_stays(self):
        kp = "/v1/models\n/v1/sessions\n"
        status = "| b00 | GET | https://api.acmeprog.com/v1/skills | 401 | 141b |\n| b01 | GET | https://api.acmeprog.com/nope | 404 | 0b |\n"
        done = json.dumps({"ts": "t", "program": "acmeprog", "lane": "brain-x-10260923"})

        def _read(p, default=""):
            if p.endswith("known-paths.txt"):
                return kp
            if p.endswith("done.jsonl"):
                return done
            if p.endswith("STATUS.md"):
                return status
            return ""
        urls = ["https://api.acmeprog.com/v1/models", "https://api.acmeprog.com/v1/skills",
                "https://api.acmeprog.com/v1/auth/credentials", "https://api.acmeprog.com/v1/internal/service",
                "https://api.acmeprog.com/nope", "https://api.acmeprog.com/fake-nonsense-path-xyz"]
        with mock.patch.object(B, "read", side_effect=_read):
            self.assertEqual(sorted(B.known_paths("acmeprog")), ["/v1/models", "/v1/sessions", "/v1/skills"])
            got = B.guessed_urls("acmeprog", urls)
        self.assertEqual(got, ["https://api.acmeprog.com/v1/auth/credentials",
                               "https://api.acmeprog.com/v1/internal/service", "https://api.acmeprog.com/nope"])


class RejectStreakAndMineRoutes(unittest.TestCase):
    def test_six_rejections_cool_the_brain_down(self):
        st = {"brain_rejects": 6}
        rows = []
        with mock.patch.object(B, "journal", rows.append):
            self.assertTrue(B.decide(st, lambda *a, **k: None, lambda: None))
        self.assertGreater(st["brain_wait_until"], B.time.time() + 600)
        self.assertEqual(st["brain_rejects"], 0)
        self.assertEqual(rows[-1]["action"], "cooldown")

    def test_mine_routes_is_gated_on_scope_and_recency(self):
        self.assertIn("mine_routes", B.ACTIONS)
        with mock.patch.object(B, "scope_ok", return_value=False), mock.patch.object(B, "scope_hosts", return_value=["api.x"]):
            self.assertIn("not in", B.mine_refusal("p", "evil.example"))
        recent = json.dumps({"ts": B.now(), "action": "mine_routes", "status": "ok", "detail": "mine_routes api.x: 3 new route(s)"})
        with mock.patch.object(B, "scope_ok", return_value=True), mock.patch.object(B, "read", return_value=recent):
            self.assertIn("once per host", B.mine_refusal("p", "api.x"))
        with mock.patch.object(B, "scope_ok", return_value=True), mock.patch.object(B, "read", return_value=""):
            self.assertEqual(B.mine_refusal("p", "api.x"), "")
        self.assertIn("mine_routes needs host", B.mine_refusal("p", ""))


class LegalMoves(unittest.TestCase):
    """D95: the move set is computed by code before the model is asked."""

    def _env(self, **kw):
        base = dict(queue="", unswept=[], leads=[], routes=([], 27, 27), esc="nothing to escalate",
                    osint_age=3600, hosts=["one.example", "two.example"], mined={"one.example": "mined", "two.example": "mined"})
        base.update(kw)
        st = {"osint": {"p": B.time.time() - base["osint_age"]}}
        patches = [
            mock.patch.object(B, "read", side_effect=lambda path, default="": base["queue"] if path.endswith("queue.txt") else ""),
            mock.patch.object(B, "plan", return_value=([], base["unswept"])),
            mock.patch.object(B, "chain_leads", return_value=base["leads"]),
            mock.patch.object(B, "unfired_known_routes", return_value=base["routes"]),
            mock.patch.object(B, "escalate_noop", return_value=base["esc"]),
            mock.patch.object(B, "scope_hosts", return_value=base["hosts"]),
            mock.patch.object(B, "mine_refusal", side_effect=lambda p, h: base["mined"].get(h, "")),
        ]
        import gnoc_hunt
        patches.append(mock.patch.object(gnoc_hunt, "deep_dive_due", return_value=False))   # D105: no dossier move here
        return st, patches

    def test_an_empty_set_means_parked(self):
        st, patches = self._env()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            self.assertEqual(B.legal_moves(st, "p"), [])
        self.assertIsNone(B.code_pick([]))

    def test_only_mining_left_is_taken_by_code(self):
        st, patches = self._env(mined={"one.example": "mined", "two.example": ""})
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            moves = B.legal_moves(st, "p")
        self.assertEqual(moves, [("mine_routes", {"host": "two.example"})])
        self.assertEqual(B.code_pick(moves), ("mine_routes", {"host": "two.example"}))
        self.assertIn("mine_routes (two.example)", B.legal_block(moves))

    def test_a_chain_lead_or_a_route_list_still_goes_to_the_model(self):
        st, patches = self._env(leads=[{"chain": True, "url": "https://one.example/x", "kind": "k", "detail": ""}],
                                routes=(["/v1/agents", "/v1/skills"], 27, 25))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            moves = B.legal_moves(st, "p")
        self.assertEqual([a for a, _ in moves], ["follow_up_lane", "follow_up_lane"])
        self.assertIsNone(B.code_pick(moves))
        self.assertIn("1 chain lead(s)", B.legal_block(moves)); self.assertIn("2 unfired mined route(s)", B.legal_block(moves))

    def test_decide_parks_and_code_picks(self):
        src = open(B.__file__).read()
        self.assertIn("moves = legal_moves(st, prog)   # D95", src)
        self.assertIn('"action": "parked", "status": "wait"', src)
        self.assertIn("d = ask(snap + legal_block(moves), feedback)", src)


class DeepDiveMove(unittest.TestCase):
    def test_deep_dive_is_offered_only_when_the_live_moves_are_spent_and_the_dossier_is_stale(self):
        import gnoc_hunt
        st = {"osint": {"p": B.time.time() - 3600}}
        base = [mock.patch.object(B, "read", side_effect=lambda path, default="": ""),
                mock.patch.object(B, "plan", return_value=([], [])),
                mock.patch.object(B, "chain_leads", return_value=[]),
                mock.patch.object(B, "unfired_known_routes", return_value=([], 27, 27)),
                mock.patch.object(B, "escalate_noop", return_value="nothing"),
                mock.patch.object(B, "scope_hosts", return_value=["one.example"]),
                mock.patch.object(B, "mine_refusal", side_effect=lambda p, h: "mined")]
        with base[0], base[1], base[2], base[3], base[4], base[5], base[6], \
                mock.patch.object(gnoc_hunt, "deep_dive_due", return_value=True):
            self.assertEqual(B.legal_moves(st, "p"), [("deep_dive", {})])
            self.assertEqual(B.code_pick([("deep_dive", {})]), ("deep_dive", {}))
        with base[0], base[1], base[2], base[3], base[4], base[5], base[6], \
                mock.patch.object(gnoc_hunt, "deep_dive_due", return_value=False):
            self.assertEqual(B.legal_moves(st, "p"), [])
        self.assertIn("deep_dive", B.ACTIONS); self.assertIn("deep_dive", B.CODE_FILLABLE)


if __name__ == "__main__":
    unittest.main()


class ReadyGate(unittest.TestCase):
    def test_ready_without_a_draft_is_not_ready(self):
        import gnoc_agent as A
        self.assertFalse(A.ready_with_draft("**READY:** the hunt is live on the seam"))
        self.assertFalse(A.ready_with_draft("READY: reports/drafts/zz/no-such-draft"))
        self.assertFalse(A.ready_with_draft("NEEDS: a phone"))
