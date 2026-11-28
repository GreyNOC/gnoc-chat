"""Program-wide route wall (drive cycle 1, 2026-10-25): a route that only ever refused across every hypothesis is
refused at the sender before the wire, under any hypothesis id; POST or a body is a new shape and passes."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_hunt as H  # noqa: E402


def _ledger(hyps):
    return {"hypotheses": hyps, "edges": []}


class Walls(unittest.TestCase):
    def test_route_key_normalizes(self):
        self.assertEqual(H.route_key("https://a.example.com/x/y/?q=1#f"), "a.example.com/x/y")
        self.assertEqual(H.route_key("https://a.example.com//x/./y"), "a.example.com/x/y")
        self.assertEqual(H.route_key("http://a.example.com"), "a.example.com")
        self.assertEqual(H.route_key(""), "/")

    def test_wall_is_merged_across_hypotheses(self):
        hyps = [{"id": "H3", "routes": {"a.example.com/dead": {"404:117": 2}}},
                {"id": "E1", "routes": {"a.example.com/dead": {"404:117": 2}}},
                {"id": "H4", "routes": {"a.example.com/live": {"404:117": 3, "200:900": 1}}}]
        with mock.patch.object(H, "load", return_value=_ledger(hyps)):
            w = H.program_walls("p")
        self.assertEqual(w, {"a.example.com/dead": ("404:117", 4)})

    def test_below_min_is_not_a_wall(self):
        hyps = [{"id": "H3", "routes": {"a.example.com/dead": {"404:117": 3}}}]
        with mock.patch.object(H, "load", return_value=_ledger(hyps)):
            self.assertEqual(H.program_walls("p"), {})

    def test_mixed_shapes_below_share_is_not_a_wall(self):
        hyps = [{"id": "H3", "routes": {"a.example.com/x": {"404:117": 2, "403:50": 2}}}]
        with mock.patch.object(H, "load", return_value=_ledger(hyps)):
            self.assertEqual(H.program_walls("p"), {})


class Sender(unittest.TestCase):
    def test_send_refuses_a_walled_get_and_allows_a_post(self):
        import gnoc_agent as A
        with mock.patch.object(H, "program_walls", return_value={"a.example.com/dead": ("404:117", 6)}), \
             mock.patch.object(A, "_econ_budget", side_effect=AssertionError("must not reach the budget check")):
            with self.assertRaises(H.RouteWalled) as cm:
                A._send("p", {}, "https://a.example.com/dead/?v=2", "GET", None, None, hypothesis="H9")
            self.assertIn("route wall", str(cm.exception))
        with mock.patch.object(H, "program_walls", return_value={"a.example.com/dead": ("404:117", 6)}), \
             mock.patch.object(A, "_econ_budget", side_effect=RuntimeError("reached the budget check")):
            with self.assertRaises(RuntimeError):
                A._send("p", {}, "https://a.example.com/dead", "POST", None, {"a": 1}, hypothesis="H9")


class WallAllMethods(unittest.TestCase):
    def test_non_get_is_refused_once_the_route_has_twice_the_minimum(self):
        import gnoc_agent as A
        with mock.patch.object(H, "program_walls", return_value={"a.example.com/dead": ("404:117", 2 * H.WALL_MIN)}), \
             mock.patch.object(A, "_econ_budget", side_effect=AssertionError("must not reach the budget check")):
            with self.assertRaises(H.RouteWalled):
                A._send("p", {}, "https://a.example.com/dead", "POST", None, {"a": 1}, hypothesis="H9")


class ShellRoutes(unittest.TestCase):
    def test_a_route_that_only_ever_served_the_shell_is_closed(self):
        hyps = [{"id": "H12", "routes": {"app.example.com/cb": {"200:85000": 10, "404:82000": 2}}},
                {"id": "H13", "routes": {"app.example.com/cb": {"200:84700": 9}}},
                {"id": "H14", "routes": {"app.example.com/api/me": {"200:120": 3, "403:200": 20}}}]
        with mock.patch.object(H, "load", return_value={"hypotheses": hyps, "edges": []}):
            closed = H.program_shell_routes("p")
        self.assertEqual(closed, {"app.example.com/cb": 21})

    def test_send_refuses_a_closed_route_for_any_method(self):
        import gnoc_agent as A
        with mock.patch.object(H, "program_walls", return_value={}), \
             mock.patch.object(H, "program_shell_routes", return_value={"app.example.com/cb": 40}), \
             mock.patch.object(A, "_econ_budget", side_effect=AssertionError("must not reach the budget check")):
            for method, body in (("GET", None), ("POST", {"a": 1})):
                with self.assertRaises(H.RouteWalled):
                    A._send("p", {}, "https://app.example.com/cb?x=1", method, None, body, hypothesis="H20")


class Degeneration(unittest.TestCase):
    def test_numbered_line_repeats_are_degenerate(self):
        import gnoc_agent as A
        line = "The seam /cb returned 200 with 84718 bytes, but the response is within 15% of the shell."
        chunks = [f"{i}. {line}\n" for i in range(20, 40)]
        self.assertTrue(A._degenerate(chunks))
        prose = [f"{i}. point number {i} says something different about item {i * 7}\n" for i in range(1, 12)]
        self.assertFalse(A._degenerate(prose))


if __name__ == "__main__":
    unittest.main()
