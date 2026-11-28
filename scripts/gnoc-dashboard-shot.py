#!/usr/bin/env python3
"""gnoc-dashboard-shot - run a TUI in a REAL pty, drive it with keys, render the final screen to a PNG.

    gnoc-dashboard-shot.py --size 120x40 --out shot.png [--keys 'v' --keys '\\x04' ...] [--wait 4] -- <cmd...>

How it works: pty.fork() gives the command a real controlling terminal of the requested size (TIOCSWINSZ),
so isatty(), termios cbreak mode, select() on stdin and the terminal size all behave exactly as in a
terminal emulator. Everything the program writes is fed into a pyte virtual screen (a VT100/xterm
emulator: cursor moves, alt screen, SGR 256-colour and truecolour). Keys are written to the pty master
after --wait seconds, one --keys entry per --step seconds. The final pyte screen is painted with PIL in
DejaVu Sans Mono, cell by cell (fg, bg, bold, reverse), and also dumped as plain text (<out>.txt) so a
test can grep it. Nothing here touches the network.
"""
import argparse
import codecs
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FALLBACK = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"  # the mono face has no Braille block (U+2800)
BASE16 = {"black": "000000", "red": "cd3131", "green": "0dbc79", "brown": "e5e510", "yellow": "e5e510",
          "blue": "2472c8", "magenta": "bc3fbc", "cyan": "11a8cd", "white": "e5e5e5", "brightblack": "666666",
          "brightred": "f14c4c", "brightgreen": "23d18b", "brightyellow": "f5f543", "brightblue": "3b8eea",
          "brightmagenta": "d670d6", "brightcyan": "29b8db", "brightwhite": "ffffff"}
DEF_FG, DEF_BG = "d4d4d4", "0b0f17"


def run(cmd, cols, rows, keys, wait, step, settle, env_extra):
    import pyte
    screen = pyte.Screen(cols, rows)
    stream = pyte.ByteStream(screen)
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ, TERM="xterm-256color", COLUMNS=str(cols), LINES=str(rows), **env_extra)
        os.execvpe(cmd[0], cmd, env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    os.kill(pid, signal.SIGWINCH)
    t0 = time.time()
    plan = [(wait + i * step, k) for i, k in enumerate(keys)]
    end = wait + len(keys) * step + settle
    raw = bytearray()
    # stop on a frame boundary: past the end time, keep reading until the stream ends with the
    # synchronized-update close (ESC[?2026l) that every gnoc frame ends with, so the screen is never a
    # half-drawn frame (pyte does not implement mode 2026 itself). Gives up 2 s later for other programs.
    while time.time() - t0 < end or (raw and not raw.rstrip().endswith(b"\x1b[?2026l") and time.time() - t0 < end + 2):
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                break
            if not data:
                break
            raw += data
            stream.feed(data)
        while plan and time.time() - t0 >= plan[0][0]:
            os.write(fd, plan.pop(0)[1].encode())
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(0.2)
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    return screen, bytes(raw)


def colour(c, default):
    if c in (None, "default"):
        return default
    if c in BASE16:
        return BASE16[c]
    if len(c) == 6:
        return c
    return default


def paint(screen, path, size=15):
    from PIL import Image, ImageDraw, ImageFont
    f, fb = ImageFont.truetype(FONT, size), ImageFont.truetype(FONT_B, size)
    ff = ImageFont.truetype(FALLBACK, size)
    try:
        from fontTools.ttLib import TTFont
        have = set(TTFont(FONT).getBestCmap())
    except Exception:
        have = None
    cw = int(round(f.getlength("M")))
    ch = int(size * 1.25)
    img = Image.new("RGB", (cw * screen.columns + 16, ch * screen.lines + 16), "#" + DEF_BG)
    d = ImageDraw.Draw(img)
    for y in range(screen.lines):
        line = screen.buffer[y]
        for x in range(screen.columns):
            cell = line[x]
            fg, bg = colour(cell.fg, DEF_FG), colour(cell.bg, DEF_BG)
            if cell.reverse:
                fg, bg = bg, fg
            px, py = 8 + x * cw, 8 + y * ch
            if bg != DEF_BG:
                d.rectangle([px, py, px + cw - 1, py + ch - 1], fill="#" + bg)
            if cell.data and cell.data != " ":
                missing = have is not None and any(ord(c) not in have for c in cell.data)
                d.text((px, py), cell.data, font=ff if missing else (fb if cell.bold else f), fill="#" + fg)
    img.save(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", default="120x40")
    ap.add_argument("--out", required=True)
    ap.add_argument("--keys", action="append", default=[])
    ap.add_argument("--wait", type=float, default=4.0)
    ap.add_argument("--step", type=float, default=1.2)
    ap.add_argument("--settle", type=float, default=1.5)
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE for the child")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    cols, rows = (int(v) for v in a.size.lower().split("x"))
    keys = [codecs.decode(k, "unicode_escape") for k in a.keys]
    env = dict(kv.split("=", 1) for kv in a.env)
    screen, raw = run(cmd, cols, rows, keys, a.wait, a.step, a.settle, env)
    paint(screen, a.out)
    with open(a.out + ".txt", "w") as fh:
        fh.write("\n".join(screen.display) + "\n")
    with open(a.out + ".raw", "wb") as fh:
        fh.write(raw)
    print(a.out)


if __name__ == "__main__":
    sys.exit(main())
