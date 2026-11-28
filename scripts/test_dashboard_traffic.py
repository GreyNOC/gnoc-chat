"""Tests for the uplink traffic log under load: the dashboards must keep receiving rows while the proxy is busy.

The bug these cover: traffic_proxy._log trimmed the log every 50 requests by reading it, truncating it in place
and writing the tail back. Under real request rates that fired constantly, so (a) appends racing the rewrite
were lost, (b) a viewer could read a half-written file, and (c) every tailing viewer saw the file shrink and
resynced at the new end of file, dropping whatever it had not read yet. The dashboards emptied out exactly when
there was the most to show.

    python3 scripts/test_dashboard_traffic.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest

WS = os.environ.get("GNOC_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, os.path.join(WS, path))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def row(i, ts=None):
    return {"ts": ts if ts is not None else time.time(), "method": "POST", "path": "/api/chat",
            "model": "m", "bytes_in": 10, "bytes_out": 20, "ms": 1, "status": 200, "err": None,
            "id": f"r{i:06d}", "caller": "hunter", "pid": 1}


class ProxyLog(unittest.TestCase):
    """traffic_proxy._log: lossless under concurrency, and the trim is rare, capped and atomic."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proxy = load("traffic_proxy_under_test", "scripts/desktop-link/traffic_proxy.py")
        self.proxy.LOG = os.path.join(self.tmp.name, "desktop-traffic.jsonl")
        self.proxy._last_trim[0] = time.time()  # as after a fresh start: no trim due yet

    def tearDown(self):
        self.tmp.cleanup()

    def lines(self):
        with open(self.proxy.LOG) as f:
            return [ln for ln in f.read().splitlines() if ln]

    def test_concurrent_appends_lose_nothing(self):
        n_threads, per = 12, 200
        def work(t):
            for i in range(per):
                self.proxy._log(row(t * per + i))
        threads = [threading.Thread(target=work, args=(t,)) for t in range(n_threads)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        lines = self.lines()
        self.assertEqual(len(lines), n_threads * per)
        ids = {json.loads(ln)["id"] for ln in lines}          # every line parses and every row is there
        self.assertEqual(len(ids), n_threads * per)

    def test_trim_is_time_bounded_not_every_50_requests(self):
        for i in range(500):
            self.proxy._log(row(i))
        self.assertEqual(len(self.lines()), 500)              # nothing rewritten inside the window
        self.assertEqual(os.path.getsize(self.proxy.LOG + ".tmp") if
                         os.path.exists(self.proxy.LOG + ".tmp") else 0, 0)

    def test_trim_caps_the_file_and_keeps_the_newest(self):
        self.proxy.MAX_LINES = 100
        for i in range(250):
            self.proxy._log(row(i))
        self.proxy._last_trim[0] = 0.0                        # a trim is now due
        self.proxy._log(row(250))
        lines = self.lines()
        self.assertEqual(len(lines), 100)
        self.assertEqual(json.loads(lines[-1])["id"], "r000250")
        self.assertFalse(os.path.exists(self.proxy.LOG + ".tmp"))

    def test_a_reader_never_sees_a_stub_file(self):
        """Readers poll while a trim rewrites: every snapshot must be the whole log, never a half-written stub.

        A reader can always catch the newest row torn in half (a write to a regular file is not atomic against
        a concurrent read, which is why every reader here parses line by line and ignores a bad tail). What it
        must never see is the file itself emptied out: that is what the in-place truncate-and-rewrite did.
        """
        self.proxy.MAX_LINES = 500
        for i in range(500):
            self.proxy._log(row(i))
        stop, counts, torn = threading.Event(), [], []
        def reader():
            while not stop.is_set():
                try:
                    with open(self.proxy.LOG) as f:
                        lines = [ln for ln in f.read().splitlines() if ln]
                except OSError:
                    continue
                counts.append(len(lines))
                for n, ln in enumerate(lines):
                    try:
                        json.loads(ln)
                    except ValueError:
                        torn.append(n == len(lines) - 1)  # only the last row may be caught mid-write
        r = threading.Thread(target=reader, daemon=True)
        r.start()
        for i in range(500, 2500):
            if i % 25 == 0:
                self.proxy._last_trim[0] = 0.0  # force a trim, far more often than in production
            self.proxy._log(row(i))
        stop.set()
        r.join(5)
        self.assertTrue(counts)
        self.assertGreaterEqual(min(counts), self.proxy.MAX_LINES,
                                "a trim left the log a stub: the viewers lose everything they had not read")
        self.assertTrue(all(torn), "a row other than the newest came out malformed")
        self.assertFalse(os.path.exists(self.proxy.LOG + ".tmp"))

    def test_the_old_in_place_trim_would_fail_that(self):
        """The regression itself: rewriting the file in place does empty it out under a polling reader."""
        self.proxy.MAX_LINES = 500
        for i in range(500):
            self.proxy._log(row(i))
        stop, counts = threading.Event(), []
        def reader():
            while not stop.is_set():
                try:
                    with open(self.proxy.LOG) as f:
                        counts.append(len([ln for ln in f.read().splitlines() if ln]))
                except OSError:
                    continue
        r = threading.Thread(target=reader, daemon=True)
        r.start()
        for _ in range(300):  # the pre-fix trim: read all, truncate, write the tail back
            with open(self.proxy.LOG) as f:
                lines = f.readlines()
            with open(self.proxy.LOG, "w") as f:
                f.writelines(lines[-self.proxy.MAX_LINES:])
        stop.set()
        r.join(5)
        self.assertTrue(counts)
        self.assertLess(min(counts), self.proxy.MAX_LINES,
                        "expected the in-place rewrite to be observable as a stub")


class OfficeTailer(unittest.TestCase):
    """gnoc-office d_traffic: a trim must not cost the panel the rows it had not read yet."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.office = load("gnoc_office_under_test", "scripts/gnoc-office.py")
        self.office.TRAFFIC_FILE = os.path.join(self.tmp.name, "desktop-traffic.jsonl")
        self.office.INFLIGHT_FILE = os.path.join(self.tmp.name, "desktop-inflight.json")
        self.office._LAST_SEEN.clear()
        self.office.TRAFFIC.clear()
        open(self.office.TRAFFIC_FILE, "w").close()

    def tearDown(self):
        self.tmp.cleanup()

    def append(self, ids):
        with open(self.office.TRAFFIC_FILE, "a") as f:
            for i in ids:
                f.write(json.dumps(row(i)) + "\n")

    def rewrite_keeping_last(self, n):
        with open(self.office.TRAFFIC_FILE) as f:
            lines = f.read().splitlines(keepends=True)
        tmp = self.office.TRAFFIC_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.writelines(lines[-n:])
        os.replace(tmp, self.office.TRAFFIC_FILE)

    def test_first_poll_does_not_replay_history(self):
        self.append(range(50))
        self.assertEqual(self.office.d_traffic()["n"], 0)
        self.append([99])
        self.assertEqual(self.office.d_traffic()["n"], 1)

    def test_rows_written_across_a_trim_still_arrive(self):
        self.append(range(300))
        self.office.d_traffic()                    # primed at EOF
        self.append(range(300, 340))               # 40 new rows the panel has not read
        self.rewrite_keeping_last(200)             # the proxy trims: the file shrinks below our offset
        got = self.office.d_traffic()
        ids = [r["id"] for r in self.office.TRAFFIC]
        self.assertEqual(got["n"], 40, "the rows written since the last poll were dropped by the resync")
        self.assertEqual(ids[-1], "r000339")
        self.assertEqual(len(set(ids)), len(ids), "a resync must not re-deliver rows already drawn")

    def test_a_trim_does_not_redeliver_old_rows(self):
        self.append(range(300))
        self.office.d_traffic()
        self.append(range(300, 310))
        self.office.d_traffic()
        self.office.TRAFFIC.clear()
        self.rewrite_keeping_last(200)             # trim with nothing new to read
        self.assertEqual(self.office.d_traffic()["n"], 0)
        self.assertEqual(len(self.office.TRAFFIC), 0)

    def test_busy_log_keeps_flowing_across_repeated_trims(self):
        self.append(range(100))
        self.office.d_traffic()
        delivered, nxt = [], 100
        for _ in range(20):                        # 20 polls, a burst and a trim between each
            self.append(range(nxt, nxt + 30))
            nxt += 30
            self.rewrite_keeping_last(150)
            self.office.TRAFFIC.clear()
            self.office.d_traffic()
            delivered += [r["id"] for r in self.office.TRAFFIC]
        self.assertEqual(len(delivered), 20 * 30)
        self.assertEqual(len(set(delivered)), 20 * 30)


class PanelWindow(unittest.TestCase):
    """control panel /api/traffic: the asked-for window must come back whole, however busy the minute was."""

    def setUp(self):
        sys.path.insert(0, os.path.join(WS, "scripts/control-panel"))
        self.server = load("control_panel_under_test", "scripts/control-panel/server.py")
        self.tmp = tempfile.TemporaryDirectory()
        self.log = os.path.join(self.tmp.name, "desktop-traffic.jsonl")

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, n, span):
        now = time.time()
        with open(self.log, "w") as f:
            for i in range(n):
                f.write(json.dumps(row(i, ts=now - span * (1 - i / n))) + "\n")
        return now

    def test_window_is_not_cut_short_by_a_line_count(self):
        now = self.write(9000, 300)                # a busy 5 minutes: 9000 rows inside the 300 s window
        rows = self.server.traffic_rows(300, now, path=self.log)
        self.assertEqual(len(rows), 9000)

    def test_only_the_tail_is_read(self):
        now = self.write(9000, 300)
        rows = self.server.traffic_rows(300, now, path=self.log, maxbytes=20000)
        self.assertTrue(0 < len(rows) < 9000)      # bounded work
        for r in rows:                             # and no half-row ever reaches the page
            self.assertIn("id", r)

    def test_rows_outside_the_window_are_dropped(self):
        now = self.write(1000, 1200)
        rows = self.server.traffic_rows(300, now, path=self.log)
        self.assertTrue(all(now - r["ts"] <= 300 for r in rows))
        self.assertTrue(0 < len(rows) < 1000)

    def test_missing_log_is_empty_not_an_error(self):
        self.assertEqual(self.server.traffic_rows(300, time.time(), path=self.log + ".nope"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
