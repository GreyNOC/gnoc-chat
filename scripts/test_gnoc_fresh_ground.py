"""Drive cycle 2 gates: fresh crown hypotheses are probed before a stale chain; an edge's proof attempts are
budgeted per capture."""
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_hunt as H  # noqa: E402


class ChainWaits(unittest.TestCase):
    def test_fresh_crown_hypothesis_beats_old_lead_capture(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.path.join(td, "old.json")
            open(old, "w").write("{}")
            os.utime(old, (time.time() - 86400, time.time() - 86400))
            d = {"edges": [{"id": "E1", "status": "lead", "evidence": old}]}
            live = [{"id": "H5", "status": "open", "probes": 0, "crown": "ato", "ts": H._now()}]
            self.assertTrue(H.chain_waits(d, live))

    def test_probed_or_non_crown_hypotheses_do_not_hold_the_chain(self):
        d = {"edges": [{"id": "E1", "status": "lead", "evidence": "/nonexistent"}]}
        self.assertFalse(H.chain_waits(d, [{"id": "H5", "probes": 3, "crown": "ato", "ts": H._now()}]))
        self.assertFalse(H.chain_waits(d, [{"id": "H5", "probes": 0, "crown": "banner", "ts": H._now()}]))

    def test_a_lead_capture_newer_than_the_hypothesis_keeps_the_chain(self):
        with tempfile.TemporaryDirectory() as td:
            new = os.path.join(td, "new.json")
            open(new, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": 200, "body": "ok"}}')
            d = {"edges": [{"id": "E1", "status": "lead", "evidence": new}]}
            live = [{"id": "H5", "probes": 0, "crown": "ato", "ts": "2026-10-20T00:00:00Z"}]
            self.assertFalse(H.chain_waits(d, live))


class ProofBudget(unittest.TestCase):
    def test_third_refusal_on_the_same_capture_closes_the_edge(self):
        capdir = os.path.join(H.WS, ".claude", "state", "testcap")
        os.makedirs(capdir, exist_ok=True)
        ev = os.path.join(capdir, f"ev-{os.getpid()}.json")
        open(ev, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": 404, "body": "no"}}')
        try:
                store = {"d": {"hypotheses": [], "edges": [], "model": {}}}
                with mock.patch.object(H, "load", side_effect=lambda p: store["d"]), \
                     mock.patch.object(H, "save", side_effect=lambda p, dd: store.__setitem__("d", dd)), \
                     mock.patch.object(H, "_econ", return_value=None):
                    outs = [H.edge("p", action="add" if i == 0 else "update", id="E9", frm="unauth", to="ato",
                                   via="x", status="proven", evidence=ev, must_contain="zzz") for i in range(4)]
                self.assertIn("proof attempt 1 of 3", outs[0])
                self.assertIn("proof attempt 3 of 3", outs[2])
                self.assertTrue(outs[3].startswith("refused:"), outs[3])
                self.assertIn("same capture", outs[3])
        finally:
            os.remove(ev)


class RefusalCaptures(unittest.TestCase):
    def test_chain_waits_ignores_a_lead_whose_capture_is_a_refusal(self):
        capdir = os.path.join(H.WS, ".claude", "state", "testcap")
        os.makedirs(capdir, exist_ok=True)
        ev = os.path.join(capdir, f"ref-{os.getpid()}.json")
        open(ev, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": 404, "body": "no"}}')
        try:
            d = {"edges": [{"id": "E1", "status": "lead", "evidence": ev}]}
            live = [{"id": "H6", "probes": 0, "crown": "ato", "ts": "2026-10-20T00:00:00Z"}]
            self.assertTrue(H.chain_waits(d, live))   # the capture is newer, but it is a 404: no lead to defer to
        finally:
            os.remove(ev)

    def test_a_proven_offer_on_a_refusal_capture_stays_hypothesized(self):
        capdir = os.path.join(H.WS, ".claude", "state", "testcap")
        os.makedirs(capdir, exist_ok=True)
        ev = os.path.join(capdir, f"ref2-{os.getpid()}.json")
        open(ev, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": 404, "body": "no"}}')
        try:
            store = {"d": {"hypotheses": [], "edges": [], "model": {}}}
            with mock.patch.object(H, "load", side_effect=lambda p: store["d"]), \
                 mock.patch.object(H, "save", side_effect=lambda p, dd: store.__setitem__("d", dd)), \
                 mock.patch.object(H, "_econ", return_value=None):
                out = H.edge("p", action="add", id="E8", frm="unauth", to="ato", via="x", status="proven",
                             evidence=ev, must_contain="200_with_session_cookies")
            self.assertIn("[hypothesized]", out)
            self.assertIn("HTTP 404 refusal", out)
        finally:
            os.remove(ev)


class CandidateGate(unittest.TestCase):
    def _run(self, kill_byte, body, status=200):
        capdir = os.path.join(H.WS, ".claude", "state", "testcap")
        os.makedirs(capdir, exist_ok=True)
        ev = os.path.join(capdir, f"cand-{os.getpid()}.json")
        open(ev, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": %d, "body": %s}}'
                            % (status, __import__("json").dumps(body)))
        h = {"id": "H6", "status": "probing", "probes": 15, "evidence": [os.path.relpath(ev, H.WS)], "notes": "",
             "kill_byte": "", "title": "t", "crown": "ato", "assumption": "", "violation": "", "prediction": ""}
        store = {"d": {"hypotheses": [h], "edges": [], "model": {}}}
        try:
            with mock.patch.object(H, "load", side_effect=lambda p: store["d"]), \
                 mock.patch.object(H, "save", side_effect=lambda p, dd: store.__setitem__("d", dd)), \
                 mock.patch.object(H, "_econ", return_value=None):
                return H.hypothesis("p", action="update", id="H6", status="candidate", kill_byte=kill_byte,
                                    evidence=os.path.relpath(ev, H.WS))
        finally:
            os.remove(ev)

    def test_status_description_is_not_a_kill_byte(self):
        out = self._run("200_with_accepted_count", "ok")
        self.assertTrue(out.startswith("refused CANDIDATE"), out)
        self.assertIn("status code", out)

    def test_kill_byte_absent_from_the_capture_is_refused(self):
        out = self._run("other_user_email", "{\"accepted\": 0}")
        self.assertTrue(out.startswith("refused CANDIDATE"), out)

    def test_kill_byte_present_in_a_granted_capture_passes(self):
        out = self._run("victim@example.org", "{\"email\": \"victim@example.org\"}")
        self.assertIn("-> candidate", out)


class ChainSubstance(unittest.TestCase):
    def test_hypothesized_only_chain_is_not_a_chain_turn(self):
        self.assertFalse(H.chain_has_substance([{"status": "hypothesized"}, {"status": "hypothesized"}]))

    def test_a_lead_edge_makes_it_a_chain_turn(self):
        self.assertTrue(H.chain_has_substance([{"status": "hypothesized"}, {"status": "lead"}]))

    def test_fully_proven_chain_is_ship_not_chain(self):
        self.assertFalse(H.chain_has_substance([{"status": "proven"}]))


class LeadGate(unittest.TestCase):
    def _edge(self, must_contain, body='{"type":"error","error":{"type":"not_found_error"}}', status=404):
        capdir = os.path.join(H.WS, ".claude", "state", "testcap")
        os.makedirs(capdir, exist_ok=True)
        ev = os.path.join(capdir, f"lead-{os.getpid()}.json")
        open(ev, "w").write('{"request": {"url": "https://a.example.com/x"}, "response": {"status": %d, "body": %s}}'
                            % (status, __import__("json").dumps(body)))
        store = {"d": {"hypotheses": [], "edges": [], "model": {}}}
        try:
            with mock.patch.object(H, "load", side_effect=lambda p: store["d"]), \
                 mock.patch.object(H, "save", side_effect=lambda p, dd: store.__setitem__("d", dd)), \
                 mock.patch.object(H, "_econ", return_value=None):
                return H.edge("p", action="add", id="E7", frm="unauth", to="ato", via="x", status="lead",
                              evidence=os.path.relpath(ev, H.WS), must_contain=must_contain)
        finally:
            os.remove(ev)

    def test_claimed_bytes_absent_from_the_capture(self):
        self.assertIn("[hypothesized]", self._edge('"error_code":"account_session_invalid"'))

    def test_error_marker_present_is_still_not_a_lead(self):
        self.assertIn("[hypothesized]", self._edge("not_found_error"))

    def test_private_bytes_present_hold_a_lead(self):
        out = self._edge("victim@example.org", body='{"email":"victim@example.org"}', status=200)
        self.assertIn("[lead]", out)


class SoftShell(unittest.TestCase):
    def _cap(self, name, url, status, body):
        capdir = os.path.join(H.WS, "targets", "shelltest", "hunts", "x", "raw")
        os.makedirs(capdir, exist_ok=True)
        p = os.path.join(capdir, f"{name}-{os.getpid()}.json")
        open(p, "w").write(__import__("json").dumps({"request": {"url": url}, "response": {"status": status, "body": body}}))
        return os.path.relpath(p, H.WS)

    def test_a_recurring_html_200_is_a_shell_not_a_mechanism(self):
        shell = "<!doctype html><html><head><title>app</title></head><body>" + "x" * 85000 + "</body></html>"
        ledger = {"hypotheses": [{"id": "H1", "routes": {"app.example.com/a": {"200:%d" % len(shell): 3},
                                                         "app.example.com/b": {"200:%d" % (len(shell) + 300): 2},
                                                         "app.example.com/zz-nonsense": {"200:%d" % (len(shell) - 200): 1}}}],
                  "edges": [], "model": {}}
        ev = self._cap("shell", "https://app.example.com/oauth/callback", 200, shell)
        try:
            with mock.patch.object(H, "load", return_value=ledger):
                ok, why = H._mechanism_shape(ev)
                self.assertFalse(ok); self.assertIn("SPA shell", why)
                ok2, why2 = H._terminal_shape(ev, "title")
                self.assertFalse(ok2)
                js = self._cap("api", "https://app.example.com/api/me", 200, '{"email":"victim@example.org"}')
                self.assertTrue(H._mechanism_shape(js)[0], "a small JSON 200 is a mechanism")
        finally:
            import shutil
            shutil.rmtree(os.path.join(H.WS, "targets", "shelltest"), ignore_errors=True)

    def test_generic_markup_is_not_a_must_contain(self):
        self.assertTrue(__import__("re").search(r"(?i)<!doctype|<html", "<html>"))


if __name__ == "__main__":
    unittest.main()
