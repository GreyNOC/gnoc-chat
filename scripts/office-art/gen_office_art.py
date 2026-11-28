#!/usr/bin/env python3
"""gen_office_art.py - the GNOC office as a tonal ASCII-art poster (luminance-ramp render, dark background).

    python3 gen_office_art.py [--cols 130] [--out DIR] [--no-png] [--stego "/greypath"]

Writes into DIR (default: this script's folder):
    office.txt          plain ASCII, no color, copy-pastes anywhere
    office_ansi.txt     the same characters with 256-color ANSI foreground codes
    office.png          office.txt rendered back (white on black, monospace) for checking
    office_ansi.png     office_ansi.txt rendered back in color
    office_source.png   the procedural source image the characters were sampled from
    office_stego.txt    office.txt plus an invisible zero-width payload (only with --stego; decode: zw_decode.py)

Method: 1) draw a clean source image procedurally (shapes + gradients + blurred glow layers; no screenshot, so no UI
text or report names can leak in), 2) sample it per character cell with the terminal aspect (a cell is ~2x taller
than wide), apply contrast + gamma, map to the ramp RAMP, 3) stamp crisp ASCII labels and faces on top (text drawn
into the image would only turn into noise), 4) render the result back to PNG to look at it.
"""
from __future__ import annotations

import argparse
import os
import re

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

RAMP = " .:;ri7Z2SXW8MB@"          # dark -> bright (empty space is the dark background)
FONT_MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
CELL_W, CELL_H = 8, 16              # source pixels per character cell (aspect ~0.5)
TITLE_BAND = 0.135                  # top fraction of the poster that holds the GNOC OFFICE banner
GAMMA, BLACK, WHITE = 0.95, 0.068, 0.82  # tuned by measuring: wall/floor base stays space

# moods for the 10 desks along the back wall (index -> face); everyone else is idle/neutral
# ASCII only, so the happy agent is (^_^) rather than a Unicode-bullet face; exactly one asleep, one dead
FACES = {0: "(o_o)", 1: "(o.o)", 2: "(o_o)", 3: "(-_-)", 4: "(._.)", 5: "(o_o)", 6: "(x_x)", 7: "(o.o)",
         8: "(^_^)", 9: "(o_o)"}
ASLEEP, DEAD, HAPPY = 3, 6, 8


# ------------------------------------------------------------------ source image
def build_source(cols, rows):
    W, H = cols * CELL_W, rows * CELL_H
    X = lambda u: int(u * W)  # noqa: E731
    Y = lambda v: int(v * H)  # noqa: E731
    yy, xx = np.mgrid[0:H, 0:W].astype(np.float32)
    img = np.zeros((H, W, 3), np.float32)

    horizon = 0.53
    # back wall: very dark, slightly lighter towards the centre (spill from the light cone)
    wall = (yy < Y(horizon)) & (yy > Y(0.135))
    wl = 0.05 + 0.05 * np.exp(-((xx - W / 2) / (0.35 * W)) ** 2)
    img[wall] = (wl[wall, None] * np.array([0.85, 0.9, 1.0]))
    # floor: shadowed, darker at the far edges, faint perspective grid towards a vanishing point
    floor = yy >= Y(horizon)
    fl = 0.060 + 0.035 * ((yy - Y(horizon)) / (H - Y(horizon)))
    img[floor] = fl[floor, None] * np.array([0.9, 0.85, 0.8])
    vx, vy = W / 2, Y(0.30)
    ang = np.arctan2(yy - vy, xx - vx)
    rays = (np.abs(np.sin(ang * 22)) < 0.16) & floor  # wide enough to survive the per-cell average
    img[rays] += 0.095
    for k in range(1, 9):  # horizontal floor seams, closer together near the horizon
        t = (k / 9) ** 1.8
        yl = int(Y(horizon) + t * (H - Y(horizon)))
        img[max(0, yl - CELL_H // 4):yl + CELL_H // 4, :, :] += 0.08
    # wall panel seams: sparse vertical texture
    for k in range(1, 16):
        xs = int(k * W / 16)
        img[Y(0.15):Y(horizon), xs:xs + CELL_W, :] += 0.085
    # baseboard line where wall meets floor
    img[Y(horizon) - 2:Y(horizon) + 1, :, :] = 0.16

    glow = Image.new("RGB", (W, H))
    gd = ImageDraw.Draw(glow)
    solid = Image.new("RGB", (W, H))
    sd = ImageDraw.Draw(solid)
    mask = Image.new("L", (W, H))  # where `solid` replaces the scene
    md = ImageDraw.Draw(mask)

    def rect(d, box, fill, m=True):
        d.rectangle([X(box[0]), Y(box[1]), X(box[2]), Y(box[3])], fill=fill)
        if m and d is sd:
            md.rectangle([X(box[0]), Y(box[1]), X(box[2]), Y(box[3])], fill=255)

    def ell(d, box, fill, m=True):
        d.ellipse([X(box[0]), Y(box[1]), X(box[2]), Y(box[3])], fill=fill)
        if m and d is sd:
            md.ellipse([X(box[0]), Y(box[1]), X(box[2]), Y(box[3])], fill=255)

    # --- light cone from a ceiling lamp, top centre, widening onto the floor
    cone = Image.new("L", (W, H))
    cd = ImageDraw.Draw(cone)
    cd.polygon([(X(0.47), Y(0.135)), (X(0.53), Y(0.135)), (X(0.74), Y(0.97)), (X(0.26), Y(0.97))], fill=34)
    cd.ellipse([X(0.30), Y(0.84), X(0.70), Y(1.00)], fill=40)  # the pool of light on the floor
    cone = cone.filter(ImageFilter.GaussianBlur(W * 0.035))
    c = np.asarray(cone, np.float32)[..., None] / 255.0
    img += c * np.array([1.0, 0.92, 0.75]) * 0.75

    # --- whiteboard, centred at the top of the wall, lit
    wb = (0.355, 0.165, 0.645, 0.335)
    rect(gd, (wb[0] - 0.01, wb[1] - 0.01, wb[2] + 0.01, wb[3] + 0.01), (150, 150, 140))
    rect(sd, (wb[0] - 0.006, wb[1] - 0.008, wb[2] + 0.006, wb[3] + 0.008), (95, 95, 100))  # frame
    rect(sd, wb, (235, 235, 225))
    rect(sd, (wb[0] + 0.03, wb[3] + 0.008, wb[2] - 0.03, wb[3] + 0.016), (70, 70, 75))  # marker tray

    # --- 10 desks along the back wall: monitor (glowing), seated agent, desk slab
    slots = []
    x0, x1 = 0.035, 0.965
    sw = (x1 - x0) / 10
    for i in range(10):
        cx = x0 + sw * (i + 0.5)
        slots.append(cx)
        mon = (cx - 0.023, 0.395, cx + 0.017, 0.445)
        dead = i == DEAD
        mc = (60, 20, 20) if dead else ((90, 120, 150) if i == ASLEEP else (130, 200, 255))
        if not dead:
            rect(gd, (mon[0] - 0.012, mon[1] - 0.02, mon[2] + 0.012, mon[3] + 0.02),
                 (40, 60, 90) if i == ASLEEP else (70, 120, 170))
        rect(sd, (mon[0] - 0.003, mon[1] - 0.005, mon[2] + 0.003, mon[3] + 0.004), (55, 55, 60))  # bezel
        rect(sd, mon, mc)
        if dead:  # a cracked, dead screen: a few broken bright scan lines
            for k in range(3):
                yl = mon[1] + (k + 1) * (mon[3] - mon[1]) / 4
                rect(sd, (mon[0] + 0.004 * k, yl, mon[2] - 0.006 * (2 - k), yl + 0.003), (220, 70, 60))
        rect(sd, (cx - 0.006, 0.445, cx - 0.002, 0.458), (60, 60, 65))  # stand
        # seated agent beside the monitor: head + shoulders, lit by the screen on one side
        hx = cx + 0.030
        tone = (70, 70, 75) if dead else (150, 145, 140)
        ell(sd, (hx - 0.020, 0.432, hx + 0.020, 0.475), tuple(int(t * 0.8) for t in tone))      # shoulders
        ell(sd, (hx - 0.011, 0.403, hx + 0.011, 0.438), tone)                                  # head
        rect(sd, (cx - 0.036, 0.458, cx + 0.052, 0.472), (115, 100, 85))                       # desk top
        rect(sd, (cx - 0.034, 0.472, cx + 0.050, 0.478), (55, 48, 40))                         # desk edge shadow
        for lx in (cx - 0.030, cx + 0.044):
            rect(sd, (lx, 0.478, lx + 0.004, 0.528), (45, 40, 35))                             # legs
        ell(gd, (cx - 0.04, 0.522, cx + 0.06, 0.540), (0, 0, 0))

    # --- water cooler, far left on the floor
    wc = 0.085
    ell(sd, (wc - 0.050, 0.835, wc + 0.050, 0.865), (10, 10, 12), m=True)                     # shadow
    rect(sd, (wc - 0.030, 0.68, wc + 0.030, 0.85), (85, 90, 100))                              # body
    rect(sd, (wc - 0.030, 0.68, wc + 0.030, 0.69), (120, 125, 135))
    rect(sd, (wc - 0.010, 0.73, wc + 0.010, 0.75), (40, 40, 45))                               # tap recess
    ell(gd, (wc - 0.05, 0.55, wc + 0.05, 0.70), (40, 90, 140))
    ell(sd, (wc - 0.028, 0.575, wc + 0.028, 0.690), (120, 185, 235))                           # water jug
    rect(sd, (wc - 0.010, 0.565, wc + 0.010, 0.585), (150, 200, 240))
    ell(sd, (wc - 0.015, 0.595, wc - 0.004, 0.640), (200, 235, 255))                           # highlight

    # --- two agents loitering on the open floor (standing, chatting)
    def standing(cx, base, tone):
        ell(sd, (cx - 0.035, base - 0.012, cx + 0.035, base + 0.012), (8, 8, 10))              # floor shadow
        rect(sd, (cx - 0.012, base - 0.085, cx - 0.003, base), tuple(int(t * 0.6) for t in tone))  # legs
        rect(sd, (cx + 0.003, base - 0.085, cx + 0.012, base), tuple(int(t * 0.6) for t in tone))
        ell(sd, (cx - 0.022, base - 0.175, cx + 0.022, base - 0.075), tuple(int(t * 0.85) for t in tone))  # torso
        ell(sd, (cx - 0.013, base - 0.215, cx + 0.013, base - 0.168), tone)                    # head
    standing(0.255, 0.86, (215, 205, 190))
    standing(0.335, 0.87, (200, 195, 210))

    # --- LEAD TRIAGE: IN tray + SHRED bin, centre-right
    tx = 0.585
    ell(sd, (tx - 0.02, 0.825, tx + 0.17, 0.850), (8, 8, 10))
    rect(sd, (tx, 0.745, tx + 0.065, 0.835), (95, 90, 80))                                     # IN tray stand
    rect(sd, (tx - 0.004, 0.735, tx + 0.069, 0.748), (140, 130, 110))                          # tray lip
    for k in range(4):                                                                         # paper stack
        rect(sd, (tx + 0.006 + 0.002 * k, 0.712 + 0.006 * k, tx + 0.060 - 0.002 * k, 0.716 + 0.006 * k), (230, 225, 210))
    sx = tx + 0.095
    rect(sd, (sx, 0.735, sx + 0.065, 0.835), (80, 85, 80))                                     # shredder bin
    rect(sd, (sx - 0.004, 0.720, sx + 0.069, 0.738), (120, 125, 120))                          # cutter head
    rect(gd, (sx + 0.01, 0.722, sx + 0.055, 0.735), (60, 160, 80))                             # status glow
    for k in range(6):                                                                         # shreds
        rect(sd, (sx + 0.008 + 0.009 * k, 0.742, sx + 0.011 + 0.009 * k, 0.775 + 0.006 * (k % 3)), (200, 200, 190))

    # --- filing cabinet, far right
    fx = 0.875
    ell(sd, (fx - 0.02, 0.845, fx + 0.095, 0.870), (8, 8, 10))
    rect(sd, (fx, 0.56, fx + 0.075, 0.855), (120, 118, 112))
    for k in range(3):
        y0 = 0.575 + k * 0.093
        rect(sd, (fx + 0.006, y0, fx + 0.069, y0 + 0.080), (150, 148, 140))
        rect(sd, (fx + 0.026, y0 + 0.030, fx + 0.049, y0 + 0.040), (60, 60, 62))              # handle
    rect(sd, (fx + 0.068, 0.56, fx + 0.075, 0.855), (70, 68, 64))                              # side shade

    # --- title band: big block lettering with a soft glow
    title = "GNOC OFFICE"
    size = int(H * 0.15)
    font = ImageFont.truetype(FONT_BOLD, size)
    tw = gd.textlength(title, font=font)
    if tw > 0.92 * W:  # fit the banner to 92% of the width, whatever --cols is
        size = int(size * 0.92 * W / tw)
        font = ImageFont.truetype(FONT_BOLD, size)
        tw = gd.textlength(title, font=font)
    tx0, ty0 = (W - tw) / 2, Y(0.005)
    gd.text((tx0, ty0), title, font=font, fill=(45, 45, 55))
    sd.text((tx0, ty0), title, font=font, fill=(255, 255, 255))
    md.text((tx0, ty0), title, font=font, fill=255)

    g = np.asarray(glow.filter(ImageFilter.GaussianBlur(W * 0.012)), np.float32) / 255.0
    img += g * 0.9
    s = np.asarray(solid, np.float32) / 255.0
    m = np.asarray(mask.filter(ImageFilter.GaussianBlur(0.6)), np.float32)[..., None] / 255.0
    img = img * (1 - m) + s * m
    # add the light cone ON TOP of solids too (things in the cone are lit), gently
    img += c * np.array([1.0, 0.92, 0.75]) * 0.15 * m
    # vignette: the room falls off into darkness at the edges and the bottom (the title band is exempt)
    r2 = ((xx - W / 2) / (0.62 * W)) ** 2 + ((yy - 0.42 * H) / (0.70 * H)) ** 2
    vig = np.clip(1.0 - 0.35 * r2, 0.45, 1.0)
    vig[yy < Y(0.135)] = 1.0
    img *= vig[..., None]
    img = np.clip(img, 0, 1)
    return img, slots


# ------------------------------------------------------------------ convert
def to_ascii(img, cols, rows):
    H, W, _ = img.shape
    cells = img[: rows * CELL_H, : cols * CELL_W].reshape(rows, CELL_H, cols, CELL_W, 3).mean(axis=(1, 3))
    lum = cells @ np.array([0.2126, 0.7152, 0.0722])
    lum = np.clip((lum - BLACK) / (WHITE - BLACK), 0, 1) ** GAMMA
    idx = np.minimum((lum * len(RAMP)).astype(int), len(RAMP) - 1)
    grid = [[RAMP[i] for i in row] for row in idx]
    # the title band gets its own crisp 4-step ramp so the banner reads as block lettering, not texture
    for r in range(int(rows * TITLE_BAND)):
        for c in range(cols):
            v = lum[r, c]
            grid[r][c] = " " if v < 0.22 else ":" if v < 0.42 else "8" if v < 0.66 else "@"
    return grid, cells


def stamp(grid, colors, row, col, text, rgb=None, pad=True):
    """Write crisp text into the character grid; pad=True clears one cell either side so it reads on a dense area."""
    rows, cols = len(grid), len(grid[0])
    if pad:
        text = f" {text} "
        col -= 1
    for i, ch in enumerate(text):
        c = col + i
        if 0 <= row < rows and 0 <= c < cols:
            grid[row][c] = ch
            if rgb is not None:
                colors[row][c] = rgb


def label_scene(grid, colors, slots, cols, rows):
    R = lambda v: int(round(v * rows))  # noqa: E731
    C = lambda u: int(round(u * cols))  # noqa: E731
    # 'dark' = whiteboard marker: plain ASCII reads it by contrast with the lit board; in colour it is marker blue
    dark, warm, cyan, red, yellow, green = (95, 135, 255), (255, 220, 150), (140, 210, 255), (255, 90, 80), (255, 230, 120), (120, 230, 140)
    # whiteboard content: neutral placeholders only (dark text on the lit board)
    wb_c0 = C(0.355) + 3
    stamp(grid, colors, R(0.190), wb_c0, "REPORTS", dark)
    stamp(grid, colors, R(0.225), wb_c0, "[ ]  ----------", dark)
    stamp(grid, colors, R(0.255), wb_c0, "[ ]  -------", dark)
    stamp(grid, colors, R(0.300), wb_c0, "QUEST: sweep_host", dark)
    # faces on the seated agents
    for i, cx in enumerate(slots):
        face = FACES[i]
        hr, hc = R(0.418), C(cx + 0.030) - 2
        col_rgb = red if i == DEAD else (yellow if i == HAPPY else ((150, 150, 170) if i == ASLEEP else warm))
        stamp(grid, colors, hr, hc, face, col_rgb, pad=False)
        if i == ASLEEP:
            # padded: the ramp itself contains Z, so an unpadded snore dissolves into the texture
            stamp(grid, colors, hr - 2, hc + 4, "zZ", (170, 170, 200))
            stamp(grid, colors, hr - 3, hc + 7, "z", (130, 130, 160))
        if i == DEAD:
            stamp(grid, colors, hr - 2, hc + 1, "!!!", red, pad=False)
    # loitering agents: faces + a speech fragment
    for cx, base, face in ((0.255, 0.86, "(o_o)"), (0.335, 0.87, "(._.)")):
        stamp(grid, colors, R(base - 0.195), C(cx) - 2, face, warm, pad=False)
    stamp(grid, colors, R(0.615), C(0.235), "...so the PoC", (200, 200, 200), pad=False)
    stamp(grid, colors, R(0.640), C(0.300), "repro.sh or bust", (200, 200, 200), pad=False)
    # fixtures
    stamp(grid, colors, R(0.885), C(0.085) - 6, "WATER COOLER", cyan)
    stamp(grid, colors, R(0.672), C(0.585) + 2, "LEAD TRIAGE", green)
    stamp(grid, colors, R(0.872), C(0.585) + 2, "IN", warm)
    stamp(grid, colors, R(0.872), C(0.680) + 1, "SHRED", warm)
    stamp(grid, colors, R(0.890), C(0.875) + 1, "FILING", warm)
    # footer
    foot = "reproducible or it didn't happen."
    stamp(grid, colors, rows - 1, (cols - len(foot)) // 2, foot, (170, 170, 170), pad=False)


def trim(grid, colors):
    """Drop fully blank rows at the top/bottom and blank columns at both edges."""
    keep = [i for i, r in enumerate(grid) if "".join(r).strip()]
    if not keep:
        return grid, colors
    grid, colors = grid[keep[0]:keep[-1] + 1], colors[keep[0]:keep[-1] + 1]
    used = [j for j in range(len(grid[0])) if any(r[j] != " " for r in grid)]
    a, b = used[0], used[-1] + 1
    return [r[a:b] for r in grid], [r[a:b] for r in colors]


# ------------------------------------------------------------------ outputs
def rgb256(r, g, b):
    """Nearest xterm-256 color for an RGB triple (6x6x6 cube or the 24-step gray ramp)."""
    def q(v):
        return 0 if v < 48 else 1 if v < 115 else (v - 35) // 40
    ci = 16 + 36 * q(r) + 6 * q(g) + q(b)
    cube = [0, 95, 135, 175, 215, 255]
    cr = (cube[q(r)], cube[q(g)], cube[q(b)])
    gray = max(0, min(23, round(((r + g + b) / 3 - 8) / 10)))
    gv = 8 + 10 * gray
    d = lambda a: sum((x - y) ** 2 for x, y in zip(a, (r, g, b)))  # noqa: E731
    return ci if d(cr) <= d((gv, gv, gv)) else 232 + gray


def ansi_text(grid, colors):
    out = []
    for row, crow in zip(grid, colors):
        line, cur = [], None
        for ch, rgb in zip(row, crow):
            if ch == " ":
                line.append(ch)
                continue
            if max(rgb) <= 1.0:  # a sampled scene colour: boost saturation, lift brightness so dim cells still read
                m_ = sum(rgb) / 3
                sat = [m_ + (v - m_) * 2.4 for v in rgb]
                peak = max(max(sat), 1e-6)
                scale = (0.38 + 0.62 * min(1.0, peak * 1.25)) / peak
                r, g, b = [max(0, min(255, int(v * scale * 255))) for v in sat]
            else:  # an explicit label colour
                r, g, b = [int(v) for v in rgb]
            code = rgb256(r, g, b)
            if code != cur:
                line.append(f"\x1b[38;5;{code}m")
                cur = code
            line.append(ch)
        out.append("".join(line) + ("\x1b[0m" if cur is not None else ""))
    return "\n".join(out) + "\n"


XTERM = None


def xterm_rgb(n):
    if n < 16:
        base = [(0, 0, 0), (128, 0, 0), (0, 128, 0), (128, 128, 0), (0, 0, 128), (128, 0, 128), (0, 128, 128),
                (192, 192, 192), (128, 128, 128), (255, 0, 0), (0, 255, 0), (255, 255, 0), (0, 0, 255),
                (255, 0, 255), (0, 255, 255), (255, 255, 255)]
        return base[n]
    if n < 232:
        n -= 16
        cube = [0, 95, 135, 175, 215, 255]
        return cube[n // 36], cube[(n // 6) % 6], cube[n % 6]
    v = 8 + 10 * (n - 232)
    return v, v, v


def render_png(text, path, color=False, size=13):
    """Render text (optionally with 38;5;N codes) back to an image, white/colour on black, to LOOK at the result."""
    font = ImageFont.truetype(FONT_MONO, size)
    cw = font.getbbox("M")[2]
    ch = int(size * 1.18)
    lines = text.rstrip("\n").split("\n")
    plain = [re.sub(r"\x1b\[[0-9;]*m", "", ln) for ln in lines]
    W, H = max(len(p) for p in plain) * cw + 20, len(lines) * ch + 20
    im = Image.new("RGB", (W, H), (0, 0, 0))
    d = ImageDraw.Draw(im)
    for y, ln in enumerate(lines):
        x, fg = 0, (235, 235, 235)
        for tok in re.split(r"(\x1b\[[0-9;]*m)", ln):
            m = re.fullmatch(r"\x1b\[([0-9;]*)m", tok)
            if m:
                parts = m.group(1).split(";")
                fg = xterm_rgb(int(parts[2])) if color and len(parts) == 3 and parts[:2] == ["38", "5"] else (235, 235, 235)
                continue
            for chh in tok:
                if chh != " ":
                    d.text((10 + x * cw, 10 + y * ch), chh, font=font, fill=fg)
                x += 1
    im.save(path)


ZW0, ZW1, ZWF = "​", "‌", "⁠"


def zw_encode(msg):
    bits = "".join(f"{b:08b}" for b in msg.encode("utf-8"))
    return ZWF + "".join(ZW1 if bit == "1" else ZW0 for bit in bits) + ZWF


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cols", type=int, default=130)
    ap.add_argument("--rows", type=int, default=0, help="default: 0.55 x cols")
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--no-png", action="store_true")
    ap.add_argument("--stego", default="", help="hide this string with zero-width characters in office_stego.txt")
    a = ap.parse_args()
    cols = a.cols
    rows = a.rows or round(cols * 0.62)
    img, slots = build_source(cols, rows)
    grid, cells = to_ascii(img, cols, rows)
    colors = [[tuple(px) for px in row] for row in cells]
    label_scene(grid, colors, slots, cols, rows)
    for r in range(int(rows * TITLE_BAND)):  # colour file only: the banner in a cyan -> violet gradient
        for c in range(cols):
            t = c / max(1, cols - 1)
            colors[r][c] = (int(80 + 120 * t), int(220 - 120 * t), 255)
    grid, colors = trim(grid, colors)
    txt = "\n".join("".join(r).rstrip() for r in grid) + "\n"
    assert all(ord(ch) < 128 for ch in txt), "office.txt must be plain ASCII"
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, "office.txt"), "w", encoding="ascii").write(txt)
    ansi = ansi_text(grid, colors)
    open(os.path.join(a.out, "office_ansi.txt"), "w", encoding="ascii").write(ansi)
    if a.stego:
        lines = txt.rstrip("\n").split("\n")
        lines[-1] = lines[-1] + zw_encode(a.stego)  # invisible, after the footer
        open(os.path.join(a.out, "office_stego.txt"), "w", encoding="utf-8").write("\n".join(lines) + "\n")
    if not a.no_png:
        Image.fromarray((img * 255).astype(np.uint8)).save(os.path.join(a.out, "office_source.png"))
        render_png(txt, os.path.join(a.out, "office.png"))
        render_png(ansi, os.path.join(a.out, "office_ansi.png"), color=True)
    print(f"wrote {a.out}/office.txt ({len(grid[0])}x{len(grid)}), office_ansi.txt" + (", office_stego.txt" if a.stego else "")
          + ("" if a.no_png else ", office.png, office_ansi.png, office_source.png"))


if __name__ == "__main__":
    main()
