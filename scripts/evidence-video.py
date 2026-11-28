#!/usr/bin/env python3
"""evidence-video - turn a hunt session, an Office view or a PoC into an MP4 receipt.

    evidence-video.py capture-office  --seconds N [--out FILE] [--url http://127.0.0.1:8791/stream]
                                      [--redact-check | --no-redact-check] [--allow-unredacted]
    evidence-video.py render          --cast FILE [--out FILE] [--fps N] [--speed X] [--size WxH]
    evidence-video.py capture-browser --url URL --seconds N [--out FILE] [--actions FILE]
                                      [--scope targets/<program>/SCOPE.txt] [--fps N] [--size WxH]

CAST FORMAT (one JSON object per line):
    {"t": <monotonic seconds since capture start>, "w": cols, "h": rows, "full": bool,
     "rows": {"<y>": [[text, fg, bg, attr], ...]}}
The first line is a full frame; later lines carry only the rows that changed. Replaying the lines in order
onto a grid (a full frame resets it) reproduces every screen. 256-colour indices, attr bits 1 bold, 2 dim,
4 italic, 8 underline, 16 reverse (the office-stream.py format).

Without --out, every output lands in ~/Downloads as <subcommand>-<UTC timestamp>.<ext> (the operator's
standing rule: requested files arrive in Downloads). Copy only the final clip into a draft's evidence/
folder; that folder is committed to git.

Every output FILE gets a sidecar FILE.json: subcommand, arguments, UTC start/end, frame count, fps,
duration, SHA-256 of the MP4 and of the cast, ffmpeg/Chrome versions, redaction mode, and for a render the
exact renderer parameters, font hashes and a reproduce command. Rendering is deterministic: the same cast,
arguments, ffmpeg build and fonts give a byte-identical MP4 (no clock, no randomness in the render path).

Exit codes: 0 ok, 2 refused by policy (non-loopback stream, OUT_OF_SCOPE host), 3 redaction check
refused the cast, 4 nothing captured / failure.
"""
import argparse
import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

WS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Intermediate frames only (never deliverables). The default used to be one session's scratchpad,
# which stopped existing when that session ended; fall back to the system temp dir instead.
SCRATCH = os.environ.get("EVIDENCE_SCRATCH", os.path.join(tempfile.gettempdir(), "evidence-video-scratch"))
CHROME_CANDIDATES = ["~/.local/opt/chrome-for-testing/current/chrome-linux64/chrome"]
CELL_W, CELL_H = 8, 16
FONT_DIR = "/usr/share/fonts/truetype/dejavu/"
FONTS = {(0, 0): "DejaVuSansMono.ttf", (1, 0): "DejaVuSansMono-Bold.ttf",
         (0, 1): "DejaVuSansMono-Oblique.ttf", (1, 1): "DejaVuSansMono-BoldOblique.ttf"}
EXIT_POLICY, EXIT_REDACT, EXIT_FAIL = 2, 3, 4


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def tool_version(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
        return out.splitlines()[0].strip() if out else None
    except (OSError, subprocess.SubprocessError):
        return None


def ffmpeg_version():
    return tool_version(["ffmpeg", "-version"])


def find_chrome():
    for c in CHROME_CANDIDATES + [shutil.which("google-chrome") or ""]:
        if c and os.path.exists(c):
            return c
    return None


def write_sidecar(out, data):
    path = out + ".json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    return path


# ---------------------------------------------------------------- loopback policy

def is_loopback_host(host):
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- SSE parsing and the grid

class SSEParser:
    """Incremental text/event-stream parser. feed(bytes) -> list of (event, data) tuples.
    Handles chunks split anywhere (even inside a UTF-8 sequence), CRLF, ': keepalive' comments."""

    def __init__(self):
        self.buf = b""
        self.event = "message"
        self.data = []

    def feed(self, chunk):
        out = []
        self.buf += chunk
        while True:
            nl = self.buf.find(b"\n")
            if nl < 0:
                break
            line, self.buf = self.buf[:nl], self.buf[nl + 1:]
            line = line.rstrip(b"\r").decode("utf-8", "replace")
            if line == "":
                if self.data:
                    out.append((self.event, "\n".join(self.data)))
                self.event, self.data = "message", []
            elif line.startswith(":"):
                continue
            else:
                k, _, v = line.partition(":")
                v = v[1:] if v.startswith(" ") else v
                if k == "event":
                    self.event = v
                elif k == "data":
                    self.data.append(v)
        if len(self.buf) > 8 << 20:  # runaway line without newline: drop it
            self.buf = b""
        return out


def valid_frame(o):
    if not isinstance(o, dict) or not isinstance(o.get("rows"), dict):
        return False
    for k in ("w", "h"):
        if not isinstance(o.get(k), int) or isinstance(o.get(k), bool) or not 0 < o[k] <= 1000:
            return False
    for y, segs in o["rows"].items():
        if not str(y).isdigit() or not isinstance(segs, list):
            return False
        for s in segs:
            if not (isinstance(s, list) and len(s) == 4 and isinstance(s[0], str)):
                return False
    return True


class Grid:
    """Terminal grid; apply() merges a frame (full resets, otherwise row deltas)."""

    def __init__(self):
        self.w = self.h = 0
        self.rows = {}

    def apply(self, fr):
        """Apply a validated frame. Returns the set of row numbers whose content changed."""
        changed = set()
        if fr.get("full") or fr["w"] != self.w or fr["h"] != self.h:
            changed.update(self.rows)
            self.rows = {}
            self.w, self.h = fr["w"], fr["h"]
        for y, segs in fr["rows"].items():
            y = int(y)
            if y >= self.h:
                continue
            segs = [list(s) for s in segs]
            if self.rows.get(y) != segs:
                self.rows[y] = segs
                changed.add(y)
        return {y for y in changed if y < self.h}

    def row_text(self, y):
        return "".join(s[0] for s in self.rows.get(y, []))


# ---------------------------------------------------------------- redaction check

_TLDS = ("com net org io dev app ai co us uk de fr ru cn jp br in eu info biz xyz me tv cc gg cloud online "
         "site tech store shop live pro one top link ws to nl se no fi it es pl ca au nz za mx kr tw").split()
SHAPES = [
    ("vendor-key-prefix", re.compile(
        r"\b(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{8,}|pk_(?:live|test)_[A-Za-z0-9]{8,}|"
        r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
        r"xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|"
        r"npm_[A-Za-z0-9]{20,}|SG\.[A-Za-z0-9_-]{16,}|shp(?:at|ca|pa)_[a-f0-9]{16,}|ya29\.[A-Za-z0-9_-]{20,}|"
        r"sntrys_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{8,})")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?")),
    ("pem-header", re.compile(r"-----BEGIN [A-Z ]*(?:KEY|CERTIFICATE)[A-Z ]*-----")),
    ("credential-assignment", re.compile(
        r"(?i)\b(?:pass(?:word|wd|phrase)?|secret|api[_-]?key|access[_-]?key|auth|token|cookie)\b"
        r"\s*[=:]\s*(?![\s▒*x.\-]*$)\S")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")),
    ("long-hex", re.compile(r"\b[0-9a-fA-F]{24,}\b")),
    ("uuid", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("ipv4", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.]*\d)")),
    ("hostname", re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + "|".join(_TLDS) + r")\b")),
]
_B64 = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_V6 = re.compile(r"[0-9A-Fa-f:.]{3,}")


def _entropy(s):
    n = len(s)
    return -sum((s.count(c) / n) * math.log2(s.count(c) / n) for c in set(s))


def scan_text(text):
    """Return the sorted list of secret/address shape NAMES found in text. Never returns the matches."""
    found = set()
    for name, rx in SHAPES:
        if rx.search(text):
            found.add(name)
    for m in _B64.finditer(text):
        t = m.group(0)
        if any(c.isdigit() for c in t) and any(c.isalpha() for c in t) and _entropy(t) >= 3.6:
            found.add("high-entropy-blob")
            break
    for m in _V6.finditer(text):
        t = m.group(0).strip(".")
        if t.count(":") >= 2 and ("::" in t or t.count(":") >= 7):
            try:
                ipaddress.IPv6Address(t)
                found.add("ipv6")
                break
            except ValueError:
                pass
    return sorted(found)


# ---------------------------------------------------------------- capture-office

def capture_frames(url, seconds, deadline_hook=None, clock=time.monotonic, log=print):
    """Subscribe and return (cast_lines, stats). cast_lines: list of dicts. Always returns what it has."""
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    grid, parser = Grid(), SSEParser()
    lines, stats = [], {"malformed": 0, "keepalive_bytes": 0, "events": 0, "findings": {}}
    t0 = clock()
    conn = (http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection)(
        host, port, timeout=1.0)
    try:
        conn.request("GET", path, headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise OSError("stream returned HTTP %d" % resp.status)
        stats["start_wall"] = utcnow()
        t0 = clock()
        while clock() - t0 < seconds:
            try:
                chunk = resp.read1(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                break
            for ev, data in parser.feed(chunk):
                if ev != "frame":
                    continue
                stats["events"] += 1
                try:
                    fr = json.loads(data)
                except ValueError:
                    fr = None
                if not valid_frame(fr):
                    stats["malformed"] += 1
                    continue
                now = clock() - t0
                if now > seconds:
                    break
                changed = grid.apply(fr)
                first = not lines
                if not changed and not first:
                    continue
                rows = {str(y): grid.rows[y] for y in sorted(changed) if y in grid.rows}
                if first or fr.get("full"):
                    rows = {str(y): grid.rows[y] for y in sorted(grid.rows)}
                for y in changed:  # redaction scan of every row that appears in the cast
                    for shape in scan_text(grid.row_text(y)):
                        stats["findings"].setdefault((y, shape), 0)
                        stats["findings"][(y, shape)] += 1
                t = round(max(now, lines[-1]["t"] if lines else 0.0), 3)  # monotonic
                lines.append({"t": t, "w": grid.w, "h": grid.h, "full": bool(first or fr.get("full")), "rows": rows})
    except KeyboardInterrupt:
        log("interrupted; finalising cast")
    finally:
        try:
            conn.close()
        except Exception:
            pass
    stats["elapsed"] = clock() - t0
    return lines, stats


def write_cast(path, lines):
    tmp = path + ".part"
    with open(tmp, "w") as f:
        for ln in lines:
            f.write(json.dumps(ln, ensure_ascii=False, separators=(",", ":")) + "\n")
    os.replace(tmp, path)


def default_out(prefix, ext):
    """Deliverables land in the operator's Downloads folder unless --out says otherwise.

    The user, 2026-10-24: every file the operator asks for arrives in ~/Downloads, not buried in a
    repo directory. The sidecar JSON is written beside whatever path this returns. Re-read HOME on
    every call so a test (or a sandbox) can redirect it."""
    d = os.path.expanduser("~/Downloads")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "%s-%s.%s" % (prefix, time.strftime("%Y%m%d-%H%M%S", time.gmtime()), ext))


def cmd_capture_office(a):
    host = urlsplit(a.url).hostname
    if urlsplit(a.url).scheme not in ("http", "https") or not is_loopback_host(host):
        print("REFUSED non-loopback stream URL (loopback only): %s" % (host or "?"), file=sys.stderr)
        return EXIT_POLICY
    out = a.out or default_out("office", "cast")
    start = utcnow()
    try:
        lines, stats = capture_frames(a.url, a.seconds)
    except (OSError, http.client.HTTPException) as e:
        lines, stats = [], {"findings": {}, "malformed": 0, "elapsed": 0.0}
        print("capture error: %s" % type(e).__name__, file=sys.stderr)
    end = utcnow()
    findings = stats["findings"]
    mode = "allow-unredacted" if a.allow_unredacted else ("redact-check" if a.redact_check else "unchecked")
    if findings and a.redact_check and not a.allow_unredacted:
        for (y, shape), n in sorted(findings.items()):
            print("REDACT_FAIL row %d shape %s (x%d); matched value withheld" % (y, shape, n), file=sys.stderr)
        print("cast NOT written (use --allow-unredacted only for a local-only recording)", file=sys.stderr)
        return EXIT_REDACT
    write_cast(out, lines)
    dur = lines[-1]["t"] if lines else 0.0
    side = {
        "subcommand": "capture-office", "args": vars(a), "started_utc": start, "ended_utc": end,
        "frame_count": len(lines), "fps": round(len(lines) / dur, 3) if dur else 0.0, "duration_s": dur,
        "mp4_sha256": None, "cast_sha256": sha256_file(out), "cast": os.path.abspath(out),
        "tools": {"ffmpeg": None, "chrome": None, "python": sys.version.split()[0]},
        "redaction": {"mode": mode, "findings": len(findings), "malformed_frames": stats["malformed"],
                      "shapes": sorted({s for _, s in findings})},
    }
    write_sidecar(out, side)
    print("cast %s frames=%d duration=%.1fs redaction=%s findings=%d" % (out, len(lines), dur, mode, len(findings)))
    return 0 if lines else EXIT_FAIL


# ---------------------------------------------------------------- render

def xterm_palette():
    p = [(0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0), (0, 0, 238), (205, 0, 205), (0, 205, 205),
         (229, 229, 229), (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0), (92, 92, 255),
         (255, 0, 255), (0, 255, 255), (255, 255, 255)]
    lv = [0, 95, 135, 175, 215, 255]
    for r in lv:
        for g in lv:
            for b in lv:
                p.append((r, g, b))
    p += [(8 + 10 * i,) * 3 for i in range(24)]
    return p


PALETTE = xterm_palette()
DEF_FG, DEF_BG = (229, 229, 229), (0, 0, 0)


def color(idx, default):
    if isinstance(idx, int) and not isinstance(idx, bool) and 0 <= idx < 256:
        return PALETTE[idx]
    return default


def block_mask(ch):
    """Procedural coverage (rows of 8 alphas) for block-element characters, or None."""
    o = ord(ch)
    W, H = CELL_W, CELL_H

    def rect(x0, y0, x1, y1, v=255):
        return [[v if (x0 <= x < x1 and y0 <= y < y1) else 0 for x in range(W)] for y in range(H)]
    if o == 0x2588:
        return rect(0, 0, W, H)
    if 0x2581 <= o <= 0x2587:
        n = o - 0x2580
        return rect(0, H - H * n // 8, W, H)
    if o == 0x2580:
        return rect(0, 0, W, H // 2)
    if o == 0x2584:
        return rect(0, H // 2, W, H)
    if 0x2589 <= o <= 0x258F:
        return rect(0, 0, W * (0x2590 - o) // 8, H)
    if o == 0x258C:
        return rect(0, 0, W // 2, H)
    if o == 0x2590:
        return rect(W // 2, 0, W, H)
    if o in (0x2591, 0x2592, 0x2593):
        return rect(0, 0, W, H, {0x2591: 64, 0x2592: 128, 0x2593: 192}[o])
    if 0x2596 <= o <= 0x259F:  # quadrants
        q = {0x2596: "3", 0x2597: "4", 0x2598: "1", 0x2599: "134", 0x259A: "14", 0x259B: "123",
             0x259C: "124", 0x259D: "2", 0x259E: "23", 0x259F: "234"}[o]
        m = rect(0, 0, 0, 0)
        for c in q:
            x0, y0 = (0, 0) if c == "1" else (W // 2, 0) if c == "2" else (0, H // 2) if c == "3" else (W // 2, H // 2)
            for y in range(y0, y0 + H // 2):
                for x in range(x0, x0 + W // 2):
                    m[y][x] = 255
        return m
    return None


class GlyphSet:
    """Coverage masks for every (char, bold, italic) used. Block elements are procedural; the rest are
    rasterised once through ffmpeg's drawtext (DejaVu Sans Mono) into a single strip per style."""

    def __init__(self, needed):
        self.masks = {}
        self.degraded = False
        by_style = {}
        for ch, b, i in sorted(needed):
            m = block_mask(ch)
            if m is not None:
                self.masks[(ch, b, i)] = m
            elif ch.isspace() or ord(ch) < 32:
                self.masks[(ch, b, i)] = None
            else:
                by_style.setdefault((b, i), []).append(ch)
        for style, chars in by_style.items():
            for s in range(0, len(chars), 400):
                self._raster(style, chars[s:s + 400])

    def _raster(self, style, chars):
        font = FONT_DIR + FONTS[style]
        tmp = tempfile.mkdtemp(prefix="evv-glyph-")
        try:
            if not os.path.exists(font):
                raise OSError("font missing")
            filt = []
            for n, ch in enumerate(chars):
                tf = os.path.join(tmp, "g%d" % n)
                with open(tf, "w", encoding="utf-8") as f:
                    f.write(ch)
                filt.append("drawtext=fontfile=%s:textfile=%s:expansion=none:fontsize=13:fontcolor=white:"
                            "x=%d+(%d-text_w)/2:y=(%d-text_h)/2" % (font, tf, n * CELL_W, CELL_W, CELL_H))
            script = os.path.join(tmp, "f.txt")
            with open(script, "w") as f:
                f.write("format=gray,\n" + ",\n".join(filt))
            r = subprocess.run(
                ["ffmpeg", "-v", "error", "-threads", "1", "-f", "lavfi", "-i",
                 "color=c=black:s=%dx%d:d=1" % (CELL_W * len(chars), CELL_H), "-filter_script:v", script,
                 "-frames:v", "1", "-pix_fmt", "gray", "-f", "rawvideo", "-"],
                capture_output=True, timeout=120)
            width = CELL_W * len(chars)
            if r.returncode != 0 or len(r.stdout) != width * CELL_H:
                raise OSError("drawtext failed")
            for n, ch in enumerate(chars):
                self.masks[(ch, style[0], style[1])] = [
                    list(r.stdout[y * width + n * CELL_W: y * width + (n + 1) * CELL_W]) for y in range(CELL_H)]
        except (OSError, subprocess.SubprocessError):
            self.degraded = True
            for ch in chars:  # fallback: a filled box so content is at least visible
                self.masks[(ch, style[0], style[1])] = [
                    [200 if 1 <= x < CELL_W - 1 and 3 <= y < CELL_H - 3 else 0 for x in range(CELL_W)]
                    for y in range(CELL_H)]
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def cell_attrs(seg_fg, seg_bg, attr):
    attr = attr if isinstance(attr, int) and not isinstance(attr, bool) else 0
    fg, bg = color(seg_fg, DEF_FG), color(seg_bg, DEF_BG)
    if attr & 16:
        fg, bg = bg, fg
    if attr & 2:
        fg = tuple((f * 6 + b * 4) // 10 for f, b in zip(fg, bg))
    return fg, bg, bool(attr & 1), bool(attr & 4), bool(attr & 8)


def expand_row(segs, w):
    cells = []
    for s in segs:
        fg, bg, b, i, u = cell_attrs(s[1], s[2], s[3])
        for ch in s[0]:
            cells.append((ch, fg, bg, b, i, u))
    cells = cells[:w]
    cells += [(" ", DEF_FG, DEF_BG, False, False, False)] * (w - len(cells))
    return tuple(cells)


class Rasteriser:
    def __init__(self, w, h, glyphs):
        self.w, self.h, self.g = w, h, glyphs
        self.tables, self.cells, self.rows = {}, {}, {}
        self.blank_row = None

    def _table(self, fg, bg):
        t = self.tables.get((fg, bg))
        if t is None:
            t = [bytes(((f * a + b * (255 - a)) // 255) for f, b in zip(fg, bg)) for a in range(256)]
            self.tables[(fg, bg)] = t
        return t

    def _cell(self, cell):
        c = self.cells.get(cell)
        if c is None:
            ch, fg, bg, b, i, u = cell
            m = self.g.masks.get((ch, int(b), int(i)))
            t = self._table(fg, bg)
            if m is None:
                scan = [t[0] * CELL_W] * CELL_H
            else:
                scan = [b"".join(t[a] for a in row) for row in m]
            if u:
                scan[CELL_H - 2] = t[255] * CELL_W
            c = self.cells[cell] = scan
        return c

    def row_bytes(self, cells):
        r = self.rows.get(cells)
        if r is None:
            if len(self.rows) > 800:
                self.rows.clear()
            cs = [self._cell(c) for c in cells]
            r = self.rows[cells] = b"".join(b"".join(c[s] for c in cs) for s in range(CELL_H))
        return r

    def frame(self, grid_rows):
        blank = expand_row([], self.w)
        return b"".join(self.row_bytes(expand_row(grid_rows[y], self.w) if y in grid_rows else blank)
                        for y in range(self.h))


def load_cast(path):
    frames, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                o = json.loads(ln)
            except ValueError:
                bad += 1
                continue
            if not valid_frame(o) or not isinstance(o.get("t"), (int, float)):
                bad += 1
                continue
            frames.append(o)
    return frames, bad


MP4_ARGS = ["-c:v", "libx264", "-preset", "medium", "-crf", "20", "-pix_fmt", "yuv420p", "-threads", "1",
            "-x264-params", "threads=1:lookahead-threads=1:sliced-threads=0", "-movflags", "+faststart",
            "-fflags", "+bitexact", "-flags:v", "+bitexact", "-map_metadata", "-1", "-an"]


def parse_size(s):
    m = re.fullmatch(r"(\d{2,5})x(\d{2,5})", s or "")
    if not m:
        raise ValueError("size must be WxH")
    return int(m.group(1)), int(m.group(2))


def size_filter(w, h):
    """Scale to fit inside w x h (even), pad with black: deterministic, no clock."""
    w, h = w - w % 2, h - h % 2
    return ("scale=%d:%d:force_original_aspect_ratio=decrease:flags=lanczos,"
            "pad=%d:%d:(ow-iw)/2:(oh-ih)/2:black,setsar=1" % (w, h, w, h)), (w, h)


def render_cast(cast, out, fps=10, speed=1.0, size=None):
    """Rasterise cast -> MP4. Returns a dict of facts for the sidecar."""
    frames, bad = load_cast(cast)
    if not frames:
        raise ValueError("cast has no valid frames")
    frames.sort(key=lambda f: f["t"])  # stable; guards a hand-edited cast
    grid = Grid()
    grid.apply(dict(frames[0], full=True))
    w, h = grid.w, grid.h
    needed = set()
    g2 = Grid()
    for fr in frames:
        g2.apply(fr)
        w, h = max(w, g2.w), max(h, g2.h)
        for segs in g2.rows.values():
            for s in segs:
                a = s[3] if isinstance(s[3], int) else 0
                for ch in s[0]:
                    needed.add((ch, int(bool(a & 1)), int(bool(a & 4))))
    needed.add((" ", 0, 0))
    glyphs = GlyphSet(needed)
    ras = Rasteriser(w, h, glyphs)
    native = (w * CELL_W, h * CELL_H)
    T = frames[-1]["t"] / speed
    n = int(math.floor(T * fps + 1e-9)) + 1
    vf, (ow, oh) = size_filter(*(parse_size(size) if size else (native[0], native[1])))
    cmd = ["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", "%dx%d" % native,
           "-framerate", str(fps), "-i", "-", "-vf", vf] + MP4_ARGS + [out]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
    grid = Grid()
    idx, last, last_idx = 0, None, -1
    try:
        for k in range(n):
            tk = k / fps * speed
            while idx < len(frames) and frames[idx]["t"] <= tk + 1e-9:
                grid.apply(frames[idx])
                idx += 1
            if idx != last_idx:
                last = ras.frame(grid.rows)
                last_idx = idx
            p.stdin.write(last)
        p.stdin.close()
        err = p.stderr.read().decode("utf-8", "replace")
        if p.wait() != 0:
            raise RuntimeError("ffmpeg failed: " + err[-300:])
    finally:
        if p.poll() is None:
            p.kill()
    fonts = {}
    for st, name in FONTS.items():
        if os.path.exists(FONT_DIR + name):
            fonts[name] = sha256_file(FONT_DIR + name)
    return {"frame_count": n, "fps": fps, "duration_s": round(n / fps, 3), "grid": [w, h], "cell": [CELL_W, CELL_H],
            "video_size": [ow, oh], "cast_frames": len(frames), "cast_bad_lines": bad,
            "glyph_rasteriser": "ffmpeg-drawtext-degraded" if glyphs.degraded else "ffmpeg-drawtext",
            "fonts_sha256": fonts, "ffmpeg_args": cmd[:-1][-len(MP4_ARGS) - 2:], "palette": "xterm-256"}


def cmd_render(a):
    if not os.path.isfile(a.cast):
        print("cast not found", file=sys.stderr)
        return EXIT_FAIL
    if a.fps <= 0 or a.speed <= 0:
        print("fps and speed must be positive", file=sys.stderr)
        return EXIT_FAIL
    out = a.out or os.path.splitext(a.cast)[0] + ".mp4"
    start = utcnow()
    try:
        facts = render_cast(a.cast, out, a.fps, a.speed, a.size)
    except (ValueError, RuntimeError, OSError) as e:
        print("render failed: %s" % e, file=sys.stderr)
        return EXIT_FAIL
    cast_rel = a.cast
    side = {
        "subcommand": "render", "args": vars(a), "started_utc": start, "ended_utc": utcnow(),
        "frame_count": facts["frame_count"], "fps": a.fps, "duration_s": facts["duration_s"],
        "mp4_sha256": sha256_file(out), "cast_sha256": sha256_file(a.cast), "mp4": os.path.abspath(out),
        "cast": os.path.abspath(a.cast),
        "tools": {"ffmpeg": ffmpeg_version(), "chrome": None, "python": sys.version.split()[0]},
        "render": facts, "script_sha256": sha256_file(os.path.abspath(__file__)),
        "reproduce": "python3 scripts/evidence-video.py render --cast %s --out <new.mp4> --fps %s --speed %s%s"
                     % (cast_rel, a.fps, a.speed, " --size " + a.size if a.size else ""),
        "reproduce_note": "Verify cast_sha256 first; with the same ffmpeg build, fonts_sha256 and script the "
                          "new MP4 sha256 equals mp4_sha256 (deterministic render).",
    }
    write_sidecar(out, side)
    print("mp4 %s frames=%d fps=%s duration=%.2fs size=%dx%d" % (
        out, facts["frame_count"], a.fps, facts["duration_s"], *facts["video_size"]))
    return 0


# ---------------------------------------------------------------- scope gate + browser

def parse_scope(path):
    """Hosts in the IN-SCOPE part of a SCOPE.txt (everything above the OUT OF SCOPE divider)."""
    hosts = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            if re.match(r"\s*#\s*=+\s*OUT OF SCOPE", ln):
                break
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            tok = ln.split()
            cand = tok[1] if len(tok) > 1 and tok[0].isupper() else tok[0]
            cand = re.sub(r"^[a-z]+://", "", cand.lower()).split("/")[0].split(":")[0].strip()
            if cand:
                hosts.append(cand)
    return hosts


def host_in_scope(host, scope_hosts):
    host = host.lower().rstrip(".")
    for s in scope_hosts:
        if s.startswith("*."):
            if host == s[2:] or host.endswith(s[1:]):
                return True
        elif host == s:
            return True
    return False


def check_browser_url(url, scope_file):
    """Return (ok, host, message). Loopback always passes; others need an in-scope scope-file line."""
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        return False, host or "?", "unsupported URL"
    if is_loopback_host(host):
        return True, host, ""
    if scope_file and os.path.isfile(scope_file) and host_in_scope(host, parse_scope(scope_file)):
        return True, host, ""
    return False, host, "OUT_OF_SCOPE %s" % host


class MiniWS:
    """Just enough RFC 6455 client for Chrome DevTools (text frames, no TLS)."""

    def __init__(self, host, port, path, timeout=30):
        self.s = socket.create_connection((host, port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall(("GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = self.s.recv(4096)
            if not d:
                raise OSError("ws handshake closed")
            buf += d
        if b" 101 " not in buf.split(b"\r\n")[0]:
            raise OSError("ws handshake refused")
        self.rest = buf.split(b"\r\n\r\n", 1)[1]
        self.id = 0
        self.events = []

    def _read(self, n):
        while len(self.rest) < n:
            d = self.s.recv(1 << 20)
            if not d:
                raise OSError("ws closed")
            self.rest += d
        out, self.rest = self.rest[:n], self.rest[n:]
        return out

    def send(self, obj):
        data = json.dumps(obj).encode()
        mask = os.urandom(4)
        n = len(data)
        hdr = b"\x81" + (bytes([0x80 | n]) if n < 126 else b"\xfe" + struct.pack(">H", n) if n < 65536
                         else b"\xff" + struct.pack(">Q", n))
        self.s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        msg = b""
        while True:
            b0, b1 = self._read(2)
            n = b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            payload = self._read(n)
            op = b0 & 0x0F
            if op == 8:
                raise OSError("ws closed by peer")
            if op in (9, 10):
                continue
            msg += payload
            if b0 & 0x80:
                return json.loads(msg.decode("utf-8", "replace"))

    def call(self, method, params=None):
        self.id += 1
        mid = self.id
        self.send({"id": mid, "method": method, "params": params or {}})
        while True:
            m = self.recv()
            if m.get("id") == mid:
                if "error" in m:
                    raise RuntimeError("%s: %s" % (method, m["error"].get("message", "error")))
                return m.get("result", {})
            self.events.append(m)

    def wait_event(self, name, timeout):
        end = time.monotonic() + timeout
        self.s.settimeout(1.0)
        while time.monotonic() < end:
            for e in self.events:
                if e.get("method") == name:
                    self.events.remove(e)
                    return True
            try:
                self.events.append(self.recv())
            except (socket.timeout, TimeoutError):
                pass
        return False

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def run_action(ws, act, wait_state):
    kind = act.get("type")
    if kind == "wait":
        wait_state["until"] = time.monotonic() + float(act.get("ms", 500)) / 1000.0
    elif kind == "scroll":
        ws.call("Runtime.evaluate", {"expression": "window.scrollBy(%d,%d)" % (int(act.get("x", 0)), int(act.get("y", 400)))})
    elif kind in ("click", "type"):
        sel = act.get("selector")
        if sel:
            r = ws.call("Runtime.evaluate", {"returnByValue": True, "expression":
                        "(()=>{const e=document.querySelector(%s);if(!e)return null;e.scrollIntoView({block:'center'});"
                        "const r=e.getBoundingClientRect();if(%s)e.focus();return [r.x+r.width/2,r.y+r.height/2]})()"
                        % (json.dumps(sel), "true" if kind == "type" else "false")})
            pos = r.get("result", {}).get("value")
        else:
            pos = [act.get("x", 0), act.get("y", 0)]
        if kind == "click" and pos:
            for t in ("mousePressed", "mouseReleased"):
                ws.call("Input.dispatchMouseEvent", {"type": t, "x": pos[0], "y": pos[1], "button": "left", "clickCount": 1})
        elif kind == "type":
            ws.call("Input.insertText", {"text": str(act.get("text", ""))})


def cmd_capture_browser(a):
    ok, host, msg = check_browser_url(a.url, a.scope)
    if not ok:
        print(msg, file=sys.stderr)
        print(msg)
        return EXIT_POLICY
    chrome = find_chrome()
    if not chrome:
        print("Chrome not found", file=sys.stderr)
        return EXIT_FAIL
    actions = []
    if a.actions:
        with open(a.actions) as f:
            actions = json.load(f)
        if not isinstance(actions, list):
            print("--actions must be a JSON list", file=sys.stderr)
            return EXIT_FAIL
    try:
        vw, vh = parse_size(a.size)
    except ValueError as e:
        print(e, file=sys.stderr)
        return EXIT_FAIL
    out = a.out or default_out("browser", "mp4")
    base = SCRATCH if os.path.isdir(SCRATCH) else tempfile.gettempdir()
    work = tempfile.mkdtemp(prefix="evv-browser-", dir=base)
    # WHY A NEW CHROME: the operator's live Chrome (remote-debugging-port 9222) holds his real hunt profile
    # with logged-in sessions. Attaching to it, or reusing its profile, would put his real session cookies
    # and tokens on screen and into an evidence video. So we always launch a NEW headless Chrome with a
    # throwaway --user-data-dir under the scratchpad and an ephemeral debugging port (never 9222).
    profile = os.path.join(work, "profile")
    rules = "MAP * ~NOTFOUND, EXCLUDE localhost, EXCLUDE 127.0.0.1"
    if not is_loopback_host(host):  # scope gate extends to every subresource and redirect: only this host resolves
        rules += ", EXCLUDE %s" % host
    cmd = [chrome, "--headless=new", "--remote-debugging-port=0", "--remote-allow-origins=*",
           "--user-data-dir=" + profile, "--no-first-run", "--no-default-browser-check", "--disable-gpu",
           "--disable-extensions", "--disable-sync", "--hide-scrollbars", "--mute-audio",
           "--window-size=%d,%d" % (vw, vh), "--host-resolver-rules=" + rules, "about:blank"]
    if os.geteuid() == 0:
        cmd.insert(1, "--no-sandbox")
    start = utcnow()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ws = None
    shots = []
    try:
        pf = os.path.join(profile, "DevToolsActivePort")
        for _ in range(150):
            if os.path.exists(pf) and len(open(pf).read().split()) >= 2:
                break
            if proc.poll() is not None:
                raise RuntimeError("chrome exited early")
            time.sleep(0.1)
        port = int(open(pf).read().split()[0])
        if port == 9222:
            raise RuntimeError("refusing to use port 9222")
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", "/json/list")
        pages = [p for p in json.loads(c.getresponse().read()) if p.get("type") == "page"]
        c.close()
        wsu = urlsplit(pages[0]["webSocketDebuggerUrl"])
        ws = MiniWS("127.0.0.1", port, wsu.path)
        ws.call("Page.enable")
        ws.call("Emulation.setDeviceMetricsOverride", {"width": vw, "height": vh, "deviceScaleFactor": 1, "mobile": False})
        ws.call("Page.navigate", {"url": a.url})
        ws.wait_event("Page.loadEventFired", 15)
        n = max(1, int(a.seconds * a.fps))
        step, wait_state, ai = 1.0 / a.fps, {"until": 0.0}, 0
        t0 = time.monotonic()
        for k in range(n):
            data = ws.call("Page.captureScreenshot", {"format": "png"})["data"]
            fp = os.path.join(work, "f%05d.png" % k)
            with open(fp, "wb") as f:
                f.write(base64.b64decode(data))
            shots.append(fp)
            if ai < len(actions) and time.monotonic() >= wait_state["until"]:
                try:
                    run_action(ws, actions[ai], wait_state)
                except (RuntimeError, OSError, ValueError, TypeError, AttributeError) as e:
                    print("action %d skipped: %s" % (ai, type(e).__name__), file=sys.stderr)
                ai += 1
            left = t0 + (k + 1) * step - time.monotonic()
            if left > 0:
                time.sleep(left)
    except KeyboardInterrupt:
        print("interrupted; muxing what was captured", file=sys.stderr)
    except (RuntimeError, OSError, KeyError, IndexError, ValueError) as e:
        print("browser capture error: %s" % e, file=sys.stderr)
    finally:
        if ws:
            ws.close()
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    end = utcnow()
    rc = EXIT_FAIL
    if shots:
        vf, (ow, oh) = size_filter(vw, vh)
        r = subprocess.run(["ffmpeg", "-v", "error", "-y", "-framerate", str(a.fps), "-i",
                            os.path.join(work, "f%05d.png"), "-vf", vf] + MP4_ARGS + [out],
                           capture_output=True, timeout=600)
        if r.returncode == 0:
            fh = sha256_bytes("".join(sha256_file(s) for s in shots).encode())
            side = {
                "subcommand": "capture-browser", "args": vars(a), "started_utc": start, "ended_utc": end,
                "frame_count": len(shots), "fps": a.fps, "duration_s": round(len(shots) / a.fps, 3),
                "mp4_sha256": sha256_file(out), "cast_sha256": None, "mp4": os.path.abspath(out),
                "frames_sha256": fh, "frames_note": "sha256 over the concatenated per-frame PNG sha256 hex; "
                                                    "browser captures have no cast, the PNG set is the source",
                "tools": {"ffmpeg": ffmpeg_version(), "chrome": tool_version([chrome, "--version"]),
                          "python": sys.version.split()[0]},
                "scope": {"host": host, "loopback": is_loopback_host(host), "scope_file": a.scope},
                "isolation": "new headless chrome, throwaway profile, ephemeral debug port; operator profile untouched",
                "redaction": {"mode": "not-applicable", "findings": 0},
            }
            write_sidecar(out, side)
            print("mp4 %s frames=%d fps=%s size=%dx%d" % (out, len(shots), a.fps, ow, oh))
            rc = 0
        else:
            print("ffmpeg failed: %s" % r.stderr.decode("utf-8", "replace")[-300:], file=sys.stderr)
    shutil.rmtree(work, ignore_errors=True)  # throwaway profile and frames
    return rc


# ---------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(prog="evidence-video", description=__doc__.split("\n")[0])
    sp = p.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("capture-office", help="record the loopback Office SSE stream to a cast file")
    c.add_argument("--seconds", type=float, required=True)
    c.add_argument("--out")
    c.add_argument("--url", default="http://127.0.0.1:8791/stream")
    c.add_argument("--redact-check", dest="redact_check", action="store_true", default=True)
    c.add_argument("--no-redact-check", dest="redact_check", action="store_false")
    c.add_argument("--allow-unredacted", action="store_true", help="write the cast despite findings (local only)")
    r = sp.add_parser("render", help="rasterise a cast to MP4 (deterministic)")
    r.add_argument("--cast", required=True)
    r.add_argument("--out")
    r.add_argument("--fps", type=int, default=10)
    r.add_argument("--speed", type=float, default=1.0)
    r.add_argument("--size", help="output WxH in pixels (default: native grid size)")
    b = sp.add_parser("capture-browser", help="record a NEW headless Chrome to MP4")
    b.add_argument("--url", required=True)
    b.add_argument("--seconds", type=float, required=True)
    b.add_argument("--out")
    b.add_argument("--actions", help="JSON list of {type: click|type|wait|scroll, ...}")
    b.add_argument("--scope", help="targets/<program>/SCOPE.txt; required for any non-loopback host")
    b.add_argument("--fps", type=int, default=2)
    b.add_argument("--size", default="1280x720")
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    return {"capture-office": cmd_capture_office, "render": cmd_render,
            "capture-browser": cmd_capture_browser}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
