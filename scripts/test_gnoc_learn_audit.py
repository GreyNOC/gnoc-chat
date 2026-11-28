"""Lesson-book hygiene of 2026-10-25 (stdlib unittest, an isolated book, no network).

The live book held 25+ lessons about program-101's INVENTED /api/v1/admin/twin route ("the admin twin endpoint requires a
JSON body with pid, device_class and action to trigger the terminal capability"), six of them filed under "*" and so
recalled on program-32 and program-0, where both hunts then aimed at an "admin twin". Across 1,802 captures the
words never appeared in a response, only in our own request bodies. These tests pin the gates and the audit."""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_learn as L  # noqa: E402

WHY = "seen on 2026-10-25 in the capture file, three times"


class _Book(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gnoc-learn-audit-")
        self._iso = L.isolated(os.path.join(self.tmp, "book"))
        self._iso.__enter__()
        self.saved_ws = L.WS
        L.WS = self.tmp

    def tearDown(self):
        L.WS = self.saved_ws
        self._iso.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def program(self, name, scope_hosts=(), known=(), captures=()):
        t = os.path.join(self.tmp, "targets", name)
        os.makedirs(os.path.join(t, "hunts", "gnoc"), exist_ok=True)
        with open(os.path.join(t, "SCOPE.txt"), "w") as f:
            f.write("\n".join(scope_hosts) + "\n")
        with open(os.path.join(t, "hunts", "gnoc", "known-paths.txt"), "w") as f:
            f.write("\n".join(known) + "\n")
        raw = os.path.join(t, "hunts", "lane", "raw")
        os.makedirs(raw, exist_ok=True)
        for i, (url, status) in enumerate(captures):
            with open(os.path.join(raw, f"c{i}.json"), "w") as f:
                json.dump({"request": {"url": url}, "response": {"status": status, "body": "b"}}, f)


class Gates(_Book):
    def test_doctrine_echo_is_refused(self):
        for t in ("The 'SAME DEFECT, HIGHER-VALUE ASSET' move targets the admin twin to elevate a LEAD",
                  "The 'via' parameter in the hunt_edge tool call is 'websocket drift / admin twin'",
                  "The 'ato' state is the terminal capability reached by the drift mechanism",
                  "The 'unauth' state on the H2-edge is gated by a 403 with error_code 40003"):
            ok, why = L.worth_keeping(t, WHY, "rule")
            self.assertFalse(ok, t)
            self.assertIn("doctrine", why)

    def test_a_target_fact_with_the_same_words_elsewhere_is_kept(self):
        ok, why = L.worth_keeping("seller.temu-t.com/api/orders answers 401 unauth and 200 as identity A, 12 probes",
                                  WHY, "fact")
        self.assertTrue(ok, why)

    def test_hunt_bound_lessons_cannot_be_universal(self):
        lid, how = L.add("The /api/v1/admin/twin endpoint requires pid and action to trigger the terminal capability",
                         WHY, "rule", "*", "reflection")
        self.assertIsNone(lid)
        self.assertIn("program-bound", how)
        lid, how = L.add("The /api/v1/admin/twin endpoint requires pid and action to trigger the terminal capability",
                         WHY, "rule", "program-101", "reflection")
        self.assertEqual(how, "added")

    def test_a_site_or_infra_fact_naming_a_host_stays_universal(self):
        """your-site.example is the user's own site, not a program; its facts must stay learnable under "*"."""
        lid, how = L.add("The host chat.greysite.com is served by pm2 app greynoc from ~/Desktop/site; a save under "
                         "public/ is live to the next visitor", WHY, "fact", "*", "reflection")
        self.assertEqual(how, "added")

    def test_greynoc_may_file_anything_universal(self):
        lid, how = L.add("Always fire /healthz on loopback, never the public edge", "the user said so", "rule", "*",
                         "greynoc")
        self.assertEqual(how, "added")

    def test_apply_ops_binds_a_route_lesson_to_the_turns_program(self):
        ops = {"add": [{"kind": "rule", "program": "*", "why": WHY,
                        "text": "POST /api/v1/orders with control:true answers 403 error_code 40003 as identity A"}]}
        turn = [{"role": "user", "content": "probe it"},
                {"role": "tool", "content": "HTTP 403 len=35 /api/v1/orders error_code 40003 control:true identity A"}]
        n = L.apply_ops(ops, program="program-101", turn=turn)
        self.assertEqual(n["added"], 1)
        self.assertEqual(L.load()[0]["program"], "program-101")

    def test_a_refused_add_is_counted_as_rejected(self):
        ops = {"add": [{"kind": "rule", "program": "*", "why": WHY,
                        "text": "The /api/v1/admin/twin endpoint requires pid to reach the terminal"}]}
        turn = [{"role": "tool", "content": "HTTP 200 /api/v1/admin/twin pid=1 terminal"}]
        n = L.apply_ops(ops, program=None, turn=turn)
        self.assertEqual((n["added"], n["rejected"]), (0, 1))
        self.assertTrue(any("program-bound" in r for r in L.LAST_REJECTS))


class Grounding(_Book):
    def test_a_ghost_path_lesson_is_refused(self):
        turn = "GHOST-PATH: /api/v1/admin/twin never appeared in any captured body for this program"
        ok, why = L.grounded("The /api/v1/admin/twin endpoint requires a pid field", "fact", turn, "")
        self.assertFalse(ok)
        self.assertIn("GHOST-PATH", why)

    def test_a_route_that_only_refused_cannot_teach_what_it_requires(self):
        turn = "\n".join(["http_request https://w.temu-t.com/api/v1/admin/twin -> HTTP 403 len=35 via=burp"] * 6)
        ok, why = L.grounded("The /api/v1/admin/twin endpoint requires admin_twin:true to trigger the terminal state",
                             "fact", turn, "")
        self.assertFalse(ok)
        self.assertIn("refusal", why)
        # the same route with a 200 somewhere in the turn, or a lesson that claims nothing about what it grants, passes
        ok, _ = L.grounded("The /api/v1/admin/twin endpoint requires admin_twin:true to trigger the terminal state",
                           "fact", turn + "\nHTTP 200 len=702 /api/v1/admin/twin", "")
        self.assertTrue(ok)
        ok, _ = L.grounded("/api/v1/admin/twin answers 403 len=35 to every method, 6 probes", "fact", turn, "")
        self.assertTrue(ok)

    def test_route_statuses_reads_the_three_output_shapes(self):
        turn = 'a /x HTTP 403 len=35\nb "status": 200 /x\nc 404 len=9 /x\nd /y HTTP 500'
        self.assertEqual(L.route_statuses("/x", turn), {403, 200, 404})


class Audit(_Book):
    def seed(self):
        self.program("program-101", scope_hosts=["www.temu-t.com", "seller.temu-t.com"], known=["/api/orders"],
                     captures=[("https://www.temu-t.com/api/v1/admin/twin", 403)] * 5
                     + [("https://www.temu-t.com/api/orders", 200)])
        rows = [
            ("L1", "rule", "*", "The 'SAME DEFECT, HIGHER-VALUE ASSET' move targets the admin twin"),
            ("L2", "rule", "*", "The 'admin twin' endpoint requires pid and action fields to trigger the terminal capability"),
            ("L3", "fact", "program-101", "The /api/v1/admin/twin endpoint requires admin_twin:true to reach the terminal state"),
            ("L4", "fact", "program-101", "/api/orders answers 200 as identity A with 702 bytes, 401 unauth"),
            ("L5", "rule", "*", "On www.temu-t.com a plain-curl 403 is the TLS fingerprint; use curl_cffi, 12 probes"),
            ("L6", "fact", "*", "The host chat.greysite.com is served by pm2 app greynoc; public/ is live at once"),
            ("L7", "rule", "*", "A 403 with error_code 40003 on the admin twin is a LEAD needing admin_twin:true"),
        ]
        os.makedirs(L.DIR, exist_ok=True)
        with open(L.LIVE, "w") as f:
            for lid, kind, prog, text in rows:
                f.write(json.dumps({"id": lid, "kind": kind, "program": prog, "text": text, "why": WHY,
                                    "source": "reflection", "reinforced": 0, "uses": 0}) + "\n")
            f.write(json.dumps({"id": "L8", "kind": "rule", "program": "*", "source": "greynoc", "reinforced": 0,
                                "uses": 0, "why": "their words",
                                "text": "The admin twin /api/v1/admin/twin is where the user says to look first"}) + "\n")

    def test_dry_run_names_every_action_and_changes_nothing(self):
        self.seed()
        acts = {lid: (act, why) for lid, act, why in L.audit(apply=False)}
        self.assertEqual(acts["L1"][0], "retire")                       # doctrine echo
        self.assertEqual(acts["L2"][0], "retire")                       # hunt-bound, no owner, universal
        self.assertEqual(acts["L3"][0], "retire")                       # route only ever 403 on disk
        self.assertIn("never answered 2xx", acts["L3"][1])
        self.assertNotIn("L4", acts)                                    # a real fact about a real route
        self.assertEqual(acts["L5"][0], "bind:program-101")                    # host owned by program-101's scope
        self.assertNotIn("L6", acts)                                    # GreyNOC's site: no program, stays "*"
        self.assertEqual(acts["L7"][0], "retire")
        self.assertNotIn("L8", acts)                                    # GreyNOC's own lesson is never touched
        self.assertEqual(len(L.load()), 8)

    def test_apply_retires_binds_and_keeps_the_reasons(self):
        self.seed()
        L.audit(apply=True)
        live = {r["id"]: r for r in L.load()}
        self.assertEqual(sorted(live), ["L4", "L5", "L6", "L8"])
        self.assertEqual(live["L5"]["program"], "program-101")
        retired = {r["id"]: r for r in L.load(L.RETIRED)}
        self.assertEqual(sorted(retired), ["L1", "L2", "L3", "L7"])
        self.assertTrue(all(r["reason"].startswith("audit: ") for r in retired.values()))

    def test_grep_retires_named_fiction_but_not_greynocs(self):
        self.seed()
        acts = {lid: act for lid, act, _ in L.audit(apply=False, grep="admin[ _]twin")}
        self.assertEqual({lid for lid, act in acts.items() if act == "retire"}, {"L1", "L2", "L3", "L7"})
        self.assertNotIn("L8", acts)


if __name__ == "__main__":
    unittest.main()
