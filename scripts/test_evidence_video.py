import warnings; warnings.simplefilter("ignore", ResourceWarning)
import contextlib, hashlib, importlib.util, io, json, os, shutil, subprocess, sys, tempfile, threading, time, unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("evidence_video", os.path.join(HERE, "evidence-video.py"))
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)


def seg(text, fg=252, bg=0, attr=0):
    return [text, fg, bg, attr]


def frame(rows, full=False, w=10, h=3):
    return {"w": w, "h": h, "full": full, "rows": {str(y): s for y, s in rows.items()}}


def synth_cast(path):
    lines = [
        dict(t=0.0, **frame({0: [seg("hello ", 46), seg("bold", 196, 17, 1)], 1: [seg("dim", 250, 0, 2)],
                             2: [seg("rev ", 16, 226, 16), seg("u", 252, 0, 8), seg("█▒", 33)]}, True)),
        dict(t=1.0, **frame({1: [seg("changed", 82, 0, 4)]})),
        dict(t=2.0, **frame({0: [seg("later", 201)]})),
    ]
    with open(path, "w") as f:
        for ln in lines:
            f.write(json.dumps(ln) + "\n")


def probe(path):
    r = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                        "stream=width,height,codec_name,pix_fmt:format=duration", "-of", "json", path],
                       capture_output=True, text=True)
    j = json.loads(r.stdout)
    return j["streams"][0], float(j["format"]["duration"])


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = E.main(argv)
    return rc, out.getvalue(), err.getvalue()


class FakeSSE(BaseHTTPRequestHandler):
    frames = []

    def log_message(self, *a): pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        w = self.wfile
        try:
            w.write(b": keepalive\n\n"); w.flush()
            for i, body in enumerate(self.frames):
                data = b"event: frame\ndata: " + body + b"\n\n"
                if i == 1:  # split chunk mid-event
                    w.write(data[:9]); w.flush(); time.sleep(0.05)
                    w.write(data[9:]); w.flush()
                else:
                    w.write(data); w.flush()
                if i == 0:
                    w.write(b"event: frame\ndata: {not json\n\n"); w.flush()
                time.sleep(0.1)
            time.sleep(1.5)
        except OSError:
            pass


@contextlib.contextmanager
def sse_server(frames):
    FakeSSE.frames = frames
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeSSE)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/stream" % srv.server_address[1]
    finally:
        srv.shutdown()


def jf(**kw):
    return json.dumps(kw, separators=(",", ":")).encode()


class T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="evv-test-")
        self.cast = os.path.join(self.tmp, "s.cast")
        synth_cast(self.cast)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- render
    def test_render_plays_with_requested_size_and_duration(self):
        out = os.path.join(self.tmp, "a.mp4")
        rc, o, e = run(["render", "--cast", self.cast, "--out", out, "--fps", "5", "--size", "160x96"])
        self.assertEqual(rc, 0, e)
        st, dur = probe(out)
        self.assertEqual((st["width"], st["height"]), (160, 96))
        self.assertEqual(st["codec_name"], "h264"); self.assertEqual(st["pix_fmt"], "yuv420p")
        self.assertAlmostEqual(dur, 2.2, delta=0.25)
        out2 = os.path.join(self.tmp, "fast.mp4")
        self.assertEqual(run(["render", "--cast", self.cast, "--out", out2, "--fps", "5", "--speed", "2"])[0], 0)
        st, dur = probe(out2)
        self.assertEqual((st["width"], st["height"]), (80, 48))  # native 10x3 cells of 8x16
        self.assertAlmostEqual(dur, 1.2, delta=0.25)

    def test_faststart(self):
        out = os.path.join(self.tmp, "a.mp4")
        run(["render", "--cast", self.cast, "--out", out, "--fps", "5"])
        head = open(out, "rb").read()
        self.assertLess(head.find(b"moov"), head.find(b"mdat"))

    def test_render_is_byte_identical(self):
        a, b = os.path.join(self.tmp, "a.mp4"), os.path.join(self.tmp, "b.mp4")
        for o in (a, b):
            self.assertEqual(run(["render", "--cast", self.cast, "--out", o, "--fps", "5"])[0], 0)
        self.assertEqual(open(a, "rb").read(), open(b, "rb").read())

    def test_sidecar_hashes_match_files(self):
        out = os.path.join(self.tmp, "a.mp4")
        run(["render", "--cast", self.cast, "--out", out, "--fps", "5"])
        s = json.load(open(out + ".json"))
        self.assertEqual(s["mp4_sha256"], hashlib.sha256(open(out, "rb").read()).hexdigest())
        self.assertEqual(s["cast_sha256"], hashlib.sha256(open(self.cast, "rb").read()).hexdigest())
        for k in ("subcommand", "args", "started_utc", "ended_utc", "frame_count", "fps", "duration_s", "tools", "reproduce"):
            self.assertIn(k, s)
        self.assertIn("ffmpeg", s["tools"]["ffmpeg"].lower())

    # ---- parser and grid
    def test_sse_split_keepalive_and_malformed(self):
        p = E.SSEParser()
        ev = p.feed(b": keepalive\n\nevent: fra")
        self.assertEqual(ev, [])
        ev = p.feed(b'me\r\ndata: {"a":1}\r\n\r\nevent: frame\ndata: {bad\n\n')
        self.assertEqual(ev[0], ("frame", '{"a":1}'))
        self.assertEqual(len(ev), 2)
        self.assertFalse(E.valid_frame({"w": 1}))
        self.assertFalse(E.valid_frame(json.loads('{"w":5,"h":2,"rows":{"0":[["a",1]]}}')))
        self.assertTrue(E.valid_frame(frame({0: [seg("x")]}, True)))
        # a multi-byte char split across chunks survives
        p = E.SSEParser(); raw = "data: █\n\n".encode()
        self.assertEqual(p.feed(raw[:7]) + p.feed(raw[7:]), [("message", "█")])

    def test_delta_rows_apply_onto_full_frame(self):
        g = E.Grid()
        g.apply(frame({0: [seg("aaa")], 1: [seg("bbb")], 2: [seg("ccc")]}, True))
        ch = g.apply(frame({1: [seg("XXX")]}))
        self.assertEqual(ch, {1})
        self.assertEqual([g.row_text(y) for y in range(3)], ["aaa", "XXX", "ccc"])
        self.assertEqual(g.apply(frame({1: [seg("XXX")]})), set())
        g.apply(frame({0: [seg("n")]}, True))
        self.assertEqual(g.row_text(1), "")

    # ---- capture-office
    def good_frames(self):
        return [jf(**frame({0: [seg("hello")], 1: [seg("world")]}, True)),
                jf(**frame({1: [seg("again")]})), jf(**frame({0: [seg("third")]}))]

    def test_capture_survives_noise_and_writes_valid_cast(self):
        out = os.path.join(self.tmp, "o.cast")
        with sse_server(self.good_frames()) as url:
            rc, o, e = run(["capture-office", "--seconds", "1", "--url", url, "--out", out])
        self.assertEqual(rc, 0, e)
        lines = [json.loads(l) for l in open(out)]
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0]["full"])
        ts = [l["t"] for l in lines]
        self.assertEqual(ts, sorted(ts))
        s = json.load(open(out + ".json"))
        self.assertEqual(s["redaction"]["mode"], "redact-check")
        self.assertEqual(s["redaction"]["malformed_frames"], 1)
        self.assertEqual(s["cast_sha256"], hashlib.sha256(open(out, "rb").read()).hexdigest())

    def test_redaction_catches_secret_and_ip_and_refuses(self):
        fake_key = "sk-" + "A1b2C3d4" * 4
        for planted, shape in ((fake_key, "vendor-key-prefix"), ("peer 10.20.30.40 up", "ipv4"),
                               ("host admin.example.com", "hostname")):
            out = os.path.join(self.tmp, "r.cast")
            fr = [jf(**frame({0: [seg("ok")], 1: [seg(planted)]}, True))]
            with sse_server(fr) as url:
                rc, o, e = run(["capture-office", "--seconds", "1", "--url", url, "--out", out])
            self.assertEqual(rc, 3)
            self.assertFalse(os.path.exists(out))
            self.assertIn("row 1", e); self.assertIn(shape, e)
            self.assertNotIn(fake_key, e + o); self.assertNotIn("10.20.30.40", e + o)
            self.assertNotIn("admin.example.com", e + o)
        # override records its mode
        with sse_server([jf(**frame({0: [seg("peer 10.20.30.40")]}, True))]) as url:
            rc, o, e = run(["capture-office", "--seconds", "1", "--url", url, "--out", out, "--allow-unredacted"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(out + ".json"))["redaction"]["mode"], "allow-unredacted")

    def test_scan_shapes(self):
        S = E.scan_text
        self.assertIn("jwt", S("eyJhbGciOiJI.eyJzdWIiOiIx.abc"))
        self.assertIn("pem-header", S("-----BEGIN PRIVATE" " KEY-----"))
        self.assertIn("credential-assignment", S("password=hunter22"))
        self.assertIn("bearer", S("Authorization: Bearer abcdef123456"))
        self.assertIn("uuid", S("id 123e4567-e89b-12d3-a456-426614174000"))
        self.assertIn("long-hex", S("0123456789abcdef0123456789abcdef"))
        self.assertIn("ipv6", S("addr 2001:db8::1 here"))
        self.assertIn("high-entropy-blob", S("Zk3fQ9xLp2Vb7NcR4tYw8HsJ1aMd"))
        self.assertEqual(S("10/10 online  Sat 11:44:46 EDT  pace 5/5 ~20s ▒▒▒ token: ▒▒"), [])

    def test_non_loopback_stream_refused(self):
        for u in ("http://example.com/stream", "http://192.0.2.7:8791/stream", "http://10.0.0.1/stream"):
            rc, o, e = run(["capture-office", "--seconds", "1", "--url", u, "--out", os.path.join(self.tmp, "x.cast")])
            self.assertEqual(rc, 2)
        self.assertTrue(E.is_loopback_host("127.0.0.1") and E.is_loopback_host("::1") and E.is_loopback_host("localhost"))
        self.assertFalse(E.is_loopback_host("127.0.0.1.evil.com"))

    # ---- browser policy
    def test_browser_scope_gate(self):
        scope = os.path.join(self.tmp, "SCOPE.txt")
        open(scope, "w").write("# c\nURL   app.good.test\t[bounty]\nWILDCARD *.wild.test\n"
                               "# === OUT OF SCOPE (x) ===\nURL   below.good.test\n")
        rc, o, e = run(["capture-browser", "--url", "https://evil.test/x", "--seconds", "1"])
        self.assertEqual(rc, 2); self.assertIn("OUT_OF_SCOPE evil.test", o)
        rc, o, e = run(["capture-browser", "--url", "https://below.good.test/", "--seconds", "1", "--scope", scope])
        self.assertEqual(rc, 2); self.assertIn("OUT_OF_SCOPE below.good.test", o)
        self.assertTrue(E.check_browser_url("https://app.good.test/a", scope)[0])
        self.assertTrue(E.check_browser_url("https://x.wild.test/", scope)[0])
        self.assertFalse(E.check_browser_url("https://notwild.test/", scope)[0])
        self.assertTrue(E.check_browser_url("http://127.0.0.1:9/", None)[0])

    @unittest.skipUnless(E.find_chrome(), "Chrome not installed")
    def test_browser_captures_loopback_page(self):
        from http.server import SimpleHTTPRequestHandler
        d = os.path.join(self.tmp, "www"); os.makedirs(d)
        open(os.path.join(d, "index.html"), "w").write("<h1 id=a>hi</h1><button onclick=\"a.textContent='clicked'\">b</button>")

        class H(SimpleHTTPRequestHandler):
            def __init__(s, *a, **k): super().__init__(*a, directory=d, **k)
            def log_message(s, *a): pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        acts = os.path.join(self.tmp, "acts.json")
        json.dump([{"type": "wait", "ms": 200}, {"type": "click", "selector": "button"}, {"type": "scroll", "y": 10}], open(acts, "w"))
        out = os.path.join(self.tmp, "b.mp4")
        try:
            rc, o, e = run(["capture-browser", "--url", "http://127.0.0.1:%d/" % srv.server_address[1], "--seconds", "2",
                            "--fps", "2", "--size", "320x240", "--out", out, "--actions", acts])
        finally:
            srv.shutdown()
        self.assertEqual(rc, 0, e)
        st, dur = probe(out)
        self.assertEqual((st["width"], st["height"]), (320, 240))
        s = json.load(open(out + ".json"))
        self.assertEqual(s["mp4_sha256"], hashlib.sha256(open(out, "rb").read()).hexdigest())
        self.assertTrue(s["scope"]["loopback"])

    # ---- default output location (operator rule: requested files land in ~/Downloads)
    def test_default_out_lands_in_downloads_and_honours_home(self):
        fake_home = os.path.join(self.tmp, "home")
        os.makedirs(fake_home)
        with unittest.mock.patch.dict(os.environ, {"HOME": fake_home}):
            out = E.default_out("office", "cast")
        self.assertEqual(os.path.dirname(out), os.path.join(fake_home, "Downloads"))
        self.assertTrue(os.path.isdir(os.path.dirname(out)), "the Downloads folder is created if missing")
        self.assertRegex(os.path.basename(out), r"^office-\d{8}-\d{6}\.cast$")
        self.assertNotIn(E.WS_DIR, out, "nothing lands inside the repo by default")
        # the real default resolves under the operator's own home
        self.assertEqual(os.path.dirname(E.default_out("browser", "mp4")), os.path.expanduser("~/Downloads"))

    def test_scratch_default_is_not_a_dead_session_path(self):
        self.assertNotIn("/scratchpad", E.SCRATCH)
        self.assertTrue(E.SCRATCH.startswith(tempfile.gettempdir()) or os.environ.get("EVIDENCE_SCRATCH"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
