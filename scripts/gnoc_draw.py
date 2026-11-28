"""gnoc_draw.py - exact pictures with no image model and no extra Python packages: a bar chart from the numbers in a
sentence, or a plain shape in named colours. Stable Diffusion cannot draw either: "a black circle centred on a white
square, exactly, 512x512" came back 768x384 with no circle, and a 9B lead's hand-written SVG chart drew Thursday's 8
below an axis that stopped at 6 (image drive, 2026-11-23).

    chart(text, path)  -> (path, note)   bars from "mon 3, tue 5, wed 2" (SVG; PNG through rsvg-convert/ImageMagick)
    shape(text, path)  -> (path, note)   "a black circle on a white square, 512x512" (SVG, or PNG written here)
    plan(text)         -> 'chart' | 'shape' | ''
"""
import os
import re
import shutil
import struct
import subprocess
import zlib

COLOURS = {
    "black": (0, 0, 0), "white": (255, 255, 255), "red": (220, 38, 38), "green": (22, 163, 74),
    "blue": (37, 99, 235), "yellow": (234, 179, 8), "orange": (234, 88, 12), "purple": (147, 51, 234),
    "pink": (236, 72, 153), "grey": (107, 114, 128), "gray": (107, 114, 128), "brown": (120, 72, 36),
    "cyan": (6, 182, 212), "teal": (13, 148, 136), "navy": (30, 58, 138), "gold": (202, 138, 4),
}
SHAPES = ("circle", "square", "rectangle", "triangle")

_PAIR = re.compile(r"([A-Za-z][\w .'-]{0,24}?)\s*[:=]?\s+(-?\d+(?:\.\d+)?)\b")


def pairs(text):
    """[(label, value)] from "mon 3, tue 5, wed 2" or "apples: 4, pears: 7" (at least two)."""
    body = str(text or "")
    m = re.search(r"(?i)(?:numbers?|data|values?)\s*[:\-]\s*(.+)", body)
    body = m.group(1) if m else body
    out = []
    for part in re.split(r"[,;\n]+", body):
        pm = _PAIR.search(part.strip())
        if pm and not re.match(r"(?i)^(?:save|put|width|height|size)\b", pm.group(1).strip()):
            out.append((pm.group(1).strip(), float(pm.group(2))))
    return out if len(out) >= 2 else []


_WORDS_ON = re.compile(r"(?i)\b(?:write|put|spell|print|type)\s+(?:out\s+)?(?:the\s+)?(?:words?|text|letters?|name|title)?"
                       r"\s*[\"'\u201c]?([A-Za-z0-9][\w !?.,&'/-]{0,40}?)[\"'\u201d]?\s+(?:in\s+(?:big|large|bold|huge)|"
                       r"on\s+(?:an?\s+|the\s+)?(?:image|picture|png|background))|\b(?:image|picture|png|sign|banner|poster|flyer|"
                       r"card|label|header|thumbnail|cover)\b[^.\"\u201c]{0,50}?\b(?:that\s+|which\s+)?(?:says|saying|reads|with\s+"
                       r"the\s+(?:words?|text))\s+[\"'\u201c]?([\w !?.,&'/-]{1,40}?)[\"'\u201d]?(?:[,.]|$)")

# words that describe the words themselves, not a scene: "write HELLO in big white letters on a black image"
_PLAIN_WORDS = {"make", "made", "write", "put", "draw", "create", "generate", "give", "me", "a", "an", "the", "my", "our",
                "image", "picture", "png", "sign", "banner", "poster", "flyer", "card", "label", "that", "says", "saying",
                "reads", "reading", "with", "words", "word", "text", "letters", "letter", "in", "on", "of", "for", "big",
                "large", "bold", "huge", "small", "white", "black", "red", "blue", "green", "yellow", "orange", "purple",
                "pink", "gold", "teal", "background", "plain", "simple", "and", "to", "it", "please", "an", "font",
                "landscape", "portrait", "square", "wide", "tall", "no", "only", "just", "exactly", "centered", "centred"}


def scene_with_words(text):
    """The words to lay over a PICTURE ("a banner for my bakery that says FRESH BREAD, warm colours"), or ''
    when the request is only the words (then they are drawn on a plain background). Image batch 6, 2026-11-24."""
    words = words_to_draw(text)
    if not words:
        return ""
    rest = re.sub(re.escape(words), " ", str(text or ""), flags=re.I)
    scene = [w for w in re.findall(r"[a-z]{3,}", rest.lower()) if w not in _PLAIN_WORDS]
    return words if len(scene) >= 2 else ""


def overlay_words(png, words):
    """The exact words, big and centred, over a picture (white with a dark outline, readable on any scene).
    -> True when written, False when no ImageMagick/GraphicsMagick is installed (the picture is left as it is).
    Only options both programs share (-draw text, a font file): this laptop's `convert` is GraphicsMagick."""
    conv = shutil.which("magick") or shutil.which("convert") or shutil.which("gm")
    if not conv:
        return False
    try:
        with open(png, "rb") as f:
            head = f.read(24)
        w, h = struct.unpack(">II", head[16:24])
    except (OSError, struct.error):
        return False
    size = max(14, min(int(h * 0.22), int(w * 0.85 / (0.62 * max(1, len(words))))))
    font = next((f for f in ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                             "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf",
                             "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
                             "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
                             "C:/Windows/Fonts/arialbd.ttf") if os.path.isfile(f)), "")
    safe = words.replace("\\", "").replace("'", "\u2019")
    argv = ([conv, "convert"] if os.path.basename(conv) == "gm" else [conv]) + [png, "-gravity", "center"]
    argv += (["-font", font] if font else []) + ["-pointsize", str(size)]
    argv += ["-stroke", "#000000", "-strokewidth", str(max(2, size // 14)), "-fill", "#ffffff",
             "-draw", f"text 0,0 '{safe}'", "-stroke", "none", "-fill", "#ffffff", "-draw", f"text 0,0 '{safe}'", png]
    try:
        r = subprocess.run(argv, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


# logo/sign/shop ...: "a logo for my coffee shop called Bean There" was drawn as "CIFEE ill SUFE" (image batch 9)
_TITLED = re.compile(r"(?i)\b(?:cover|poster|book|novel|album|banner|flyer|thumbnail|game|podcast|channel|logo|sign|label|"
                     r"shop|caf[eé]|bakery|store|restaurant|bar|business|company|brand|team|club|band|card|mug|shirt|"
                     r"t-shirt|sticker|badge|menu|app|website)\b[^.]{0,60}?"
                     r"\b(?:called|titled|named|entitled)\s+[\"'\u201c]?([A-Z0-9][\w !?.,&'/-]{1,40}?)[\"'\u201d]?"
                     r"(?:\s*[,.]|\s*$|\s+(?:in|with|for|and)\b)")


def words_to_draw(text):
    """The exact words he wants drawn ("write the word HELLO in big letters on an image" -> "HELLO"; a book cover
    "called THE LAST DOOR" -> its title, image batch 7), or ''."""
    m = _WORDS_ON.search(str(text or ""))
    if not m:
        tm = _TITLED.search(str(text or ""))
        return tm.group(1).strip(" .,") if tm else ""
    w = (m.group(1) or m.group(2) or "").strip(" .,")
    return "" if w.lower() in ("a", "an", "the", "it", "something", "some") else w


# ---- flat icons, drawn exactly. "an icon of a shield with a check mark, flat, square, white background" went to
# Stable Diffusion three times and came back as a brochure mockup with fake text (image batch 9). Simple original
# geometry on a 100x100 grid, one colour on white (or transparent).
def _star(cx=50, cy=52, r1=42, r2=18):
    import math
    pts = []
    for i in range(10):
        a = math.pi / 2 + i * math.pi / 5
        r = r1 if i % 2 == 0 else r2
        pts.append(f"{cx + r * math.cos(a):.1f},{cy - r * math.sin(a):.1f}")
    return f'<polygon points="{" ".join(pts)}" fill="{{c}}"/>'


ICONS = {
    "shield": '<path d="M50 6 L88 20 V46 C88 72 71 87 50 95 C29 87 12 72 12 46 V20 Z" fill="{c}"/>',
    "lock": ('<path d="M33 44 V32 a17 17 0 0 1 34 0 V44" fill="none" stroke="{c}" stroke-width="9"/>'
             '<rect x="20" y="44" width="60" height="46" rx="8" fill="{c}"/>'),
    "star": _star(),
    "heart": ('<path d="M50 88 C20 66 7 50 7 33 C7 19 18 9 31 9 C40 9 46 14 50 21 C54 14 60 9 69 9 C82 9 93 19 93 33 '
              'C93 50 80 66 50 88 Z" fill="{c}"/>'),
    "house": '<polygon points="50,10 92,48 80,48 80,90 20,90 20,48 8,48" fill="{c}"/>',
    "bell": ('<path d="M50 10 C67 10 75 25 75 42 V62 L86 76 H14 L25 62 V42 C25 25 33 10 50 10 Z" fill="{c}"/>'
             '<circle cx="50" cy="85" r="8" fill="{c}"/>'),
    "bolt": '<polygon points="58,4 20,56 46,56 38,96 80,40 54,40" fill="{c}"/>',
    "envelope": '<rect x="8" y="22" width="84" height="56" rx="7" fill="{c}"/>',
    "search": ('<circle cx="42" cy="42" r="25" fill="none" stroke="{c}" stroke-width="10"/>'
               '<line x1="61" y1="61" x2="88" y2="88" stroke="{c}" stroke-width="13" stroke-linecap="round"/>'),
    "user": ('<circle cx="50" cy="31" r="19" fill="{c}"/>'
             '<path d="M14 92 C14 68 30 56 50 56 C70 56 86 68 86 92 Z" fill="{c}"/>'),
    "cloud": ('<circle cx="34" cy="60" r="20" fill="{c}"/><circle cx="56" cy="46" r="26" fill="{c}"/>'
              '<circle cx="74" cy="62" r="18" fill="{c}"/><rect x="34" y="60" width="40" height="20" fill="{c}"/>'),
    "wifi": ('<path d="M10 40 a56 56 0 0 1 80 0" fill="none" stroke="{c}" stroke-width="9" stroke-linecap="round"/>'
             '<path d="M24 55 a36 36 0 0 1 52 0" fill="none" stroke="{c}" stroke-width="9" stroke-linecap="round"/>'
             '<path d="M37 69 a17 17 0 0 1 26 0" fill="none" stroke="{c}" stroke-width="9" stroke-linecap="round"/>'
             '<circle cx="50" cy="82" r="7" fill="{c}"/>'),
    "check": ('<polyline points="16,54 40,78 86,26" fill="none" stroke="{c}" stroke-width="13" '
              'stroke-linecap="round" stroke-linejoin="round"/>'),
}
_ICON_WORDS = {"shield": r"shield", "lock": r"lock|padlock", "star": r"star", "heart": r"heart",
               "house": r"house|home", "bell": r"bell|notification", "bolt": r"bolt|lightning|flash",
               "envelope": r"envelope|mail|email", "search": r"search|magnifying\s+glass|magnifier",
               "user": r"user|person|profile|account|avatar", "cloud": r"cloud", "wifi": r"wi-?fi|wireless",
               "check": r"check\s*-?mark|checkmark|tick"}
# what sits inside a symbol, in white: "a shield with a check mark", "an envelope" (its flap), "a lock" (keyhole)
_INNER = {"check": ('<polyline points="32,50 45,64 70,36" fill="none" stroke="#ffffff" stroke-width="9" '
                    'stroke-linecap="round" stroke-linejoin="round"/>'),
          "envelope": '<polyline points="10,26 50,56 90,26" fill="none" stroke="#ffffff" stroke-width="6"/>',
          "lock": '<circle cx="50" cy="63" r="7" fill="#ffffff"/><rect x="47" y="64" width="6" height="14" fill="#ffffff"/>',
          "house": '<rect x="42" y="62" width="16" height="28" fill="#ffffff"/>',
          "star": ('<polyline points="34,52 46,64 68,40" fill="none" stroke="#ffffff" stroke-width="7" '
                   'stroke-linecap="round" stroke-linejoin="round"/>')}


def icon_kind(text):
    """(symbol, with_check) for an ICON request naming a symbol gnoc can draw exactly, else None."""
    t = str(text or "")
    if not re.search(r"(?i)\b(?:icon|icons|glyph|symbol|favicon|app\s+icon)\b", t) or re.search(
            r"(?i)\b(?:photo\w*|realistic|3d|painting|watercolou?r|scene|landscape\s+of)\b", t):
        return None
    found = [k for k, rx in _ICON_WORDS.items() if re.search(rf"(?i)\b(?:{rx})s?\b", t)]
    if not found:
        return None
    main = next((k for k in found if k != "check"), "check")
    return main, ("check" in found and main != "check")


def icon_svg(text, w=512, h=512):
    kind = icon_kind(text)
    if not kind:
        return ""
    main, with_check = kind
    t = str(text or "").lower()
    names = re.findall(r"\b(" + "|".join(COLOURS) + r")\b", t)
    names = [n for n in names if not re.search(rf"\b{n}\s+background\b", t)]
    col = "#%02x%02x%02x" % (COLOURS[names[0]] if names else (37, 99, 235))
    bgm = re.search(r"\b(" + "|".join(COLOURS) + r")\s+background\b", t)
    bg = "" if re.search(r"\btransparent\b", t) else (
        '<rect width="100" height="100" fill="#%02x%02x%02x"/>' % (COLOURS[bgm.group(1)] if bgm else (255, 255, 255)))
    body = ICONS[main].replace("{c}", col)
    inner = _INNER["check"] if with_check else (_INNER.get(main, "") if main != "star" else "")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 100 100">'
            f'{bg}<g transform="translate(6 6) scale(0.88)">{body}{inner}</g></svg>')


def icon(text, path):
    w, h = _size(text, (512, 512))
    side = min(w, h)
    svg = icon_svg(text, side, side)
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    main, with_check = icon_kind(text)
    what = main + (" with a check mark" if with_check else "")
    svg_path = os.path.splitext(path)[0] + ".svg"
    with open(svg_path, "w") as f:
        f.write(svg)
    if path.lower().endswith(".svg"):
        return svg_path, f"{what} icon drawn exactly ({side}x{side}, SVG)"
    png = os.path.splitext(path)[0] + ".png"
    if _svg_to_png(svg_path, png):
        with __import__("contextlib").suppress(OSError):
            os.remove(svg_path)
        return png, f"{what} icon drawn exactly ({side}x{side}, PNG)"
    return svg_path, f"{what} icon drawn exactly as SVG ({side}x{side}; no SVG-to-PNG converter here)"


def plan(text):
    t = str(text or "")
    if icon_kind(t):
        return "icon"
    if words_to_draw(t):
        return "text"
    if re.search(r"(?i)\b(?:chart|graph|plot|visuali[sz]e)\w*\b", t) and pairs(t):
        return "chart"
    if re.search(r"(?i)\b(?:" + "|".join(SHAPES) + r")\b", t) and re.search(r"(?i)\b(?:exact\w*|precise\w*|test\s+"
                                                                          r"(?:image|pattern)|svg|simple)\b", t):
        return "shape"
    return ""


def _size(text, default=(512, 512)):
    m = re.search(r"\b(\d{2,4})\s*[x×]\s*(\d{2,4})\b", str(text or ""))
    if not m:
        return default
    return max(16, min(4096, int(m.group(1)))), max(16, min(4096, int(m.group(2))))


def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def chart_svg(data, w=640, h=360, title=""):
    top, bottom, left, right = (44 if title else 28), 36, 44, 16
    pw, ph = w - left - right, h - top - bottom
    hi = max(0.0, max(v for _l, v in data))
    lo = min(0.0, min(v for _l, v in data))
    span = (hi - lo) or 1.0
    # a round top for the axis: the highest bar always fits under it (the 9B's axis stopped at 6 under an 8)
    step = 10 ** max(0, len(str(int(span))) - 1)
    top_v = (int(hi / step) + (1 if hi % step else 0)) * step if hi > 0 else 0
    span = (top_v - lo) or 1.0

    def y(v):
        return top + ph - (v - lo) / span * ph
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">',
           f'<rect width="{w}" height="{h}" fill="#ffffff"/>']
    if title:
        out.append(f'<text x="{w / 2}" y="24" text-anchor="middle" font-family="sans-serif" font-size="16">'
                   f'{_esc(title)}</text>')
    for i in range(5):   # gridlines and their values
        v = lo + span * i / 4
        out.append(f'<line x1="{left}" y1="{y(v):.1f}" x2="{w - right}" y2="{y(v):.1f}" stroke="#e5e7eb"/>')
        out.append(f'<text x="{left - 6}" y="{y(v) + 4:.1f}" text-anchor="end" font-family="sans-serif" '
                   f'font-size="11" fill="#6b7280">{v:g}</text>')
    slot = pw / len(data)
    for i, (label, v) in enumerate(data):
        x = left + i * slot + slot * 0.15
        bw = slot * 0.7
        y0, y1 = sorted((y(0), y(v)))
        out.append(f'<rect x="{x:.1f}" y="{y0:.1f}" width="{bw:.1f}" height="{max(1.0, y1 - y0):.1f}" fill="#2563eb"/>')
        out.append(f'<text x="{x + bw / 2:.1f}" y="{y0 - 5:.1f}" text-anchor="middle" font-family="sans-serif" '
                   f'font-size="12">{v:g}</text>')
        out.append(f'<text x="{x + bw / 2:.1f}" y="{h - 14}" text-anchor="middle" font-family="sans-serif" '
                   f'font-size="12">{_esc(label)}</text>')
    out.append(f'<line x1="{left}" y1="{y(0):.1f}" x2="{w - right}" y2="{y(0):.1f}" stroke="#111827"/>')
    out.append("</svg>")
    return "\n".join(out)


def _svg_to_png(svg_path, png_path):
    """A PNG from an SVG through whatever converter this computer has; False when it has none."""
    for argv in (["rsvg-convert", "-o", png_path, svg_path], ["magick", svg_path, png_path],
                 ["convert", svg_path, png_path], ["inkscape", svg_path, "--export-filename", png_path]):
        if shutil.which(argv[0]):
            try:
                if subprocess.run(argv, capture_output=True, timeout=60).returncode == 0 and os.path.isfile(png_path):
                    return True
            except (OSError, subprocess.SubprocessError):
                continue
    return False


_PIE_COLOURS = ("#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f", "#edc948", "#b07aa1", "#ff9da7", "#9c755f",
                "#bab0ac")


def pie_svg(data, w=640, h=400, title="", donut=False):
    """A pie with a legend: each slice's share is its value over the total (negative values are refused)."""
    import math
    if any(v < 0 for _l, v in data):
        raise ValueError("a pie chart cannot show negative values")
    total = sum(v for _l, v in data) or 1.0
    top = 40 if title else 16
    r = max(20, min(h - top - 16, int(w * 0.55)) // 2)
    cx, cy = 16 + r, top + r
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
           f'font-family="DejaVu Sans, Arial, sans-serif"><rect width="{w}" height="{h}" fill="#ffffff"/>']
    if title:
        out.append(f'<text x="{w // 2}" y="26" font-size="18" text-anchor="middle" fill="#222">{_esc(title)}</text>')
    a0 = -math.pi / 2
    for i, (label, v) in enumerate(data):
        col = _PIE_COLOURS[i % len(_PIE_COLOURS)]
        frac = v / total
        if frac >= 0.9999:
            out.append(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{col}"/>')
        elif frac > 0:
            a1 = a0 + frac * 2 * math.pi
            x0, y0 = cx + r * math.cos(a0), cy + r * math.sin(a0)
            x1, y1 = cx + r * math.cos(a1), cy + r * math.sin(a1)
            big = 1 if frac > 0.5 else 0
            out.append(f'<path d="M{cx},{cy} L{x0:.2f},{y0:.2f} A{r},{r} 0 {big} 1 {x1:.2f},{y1:.2f} Z" fill="{col}" '
                       f'stroke="#ffffff" stroke-width="2"/>')
            a0 = a1
        ly = top + 8 + i * 26   # legend row
        out.append(f'<rect x="{cx + r + 28}" y="{ly}" width="16" height="16" fill="{col}"/>')
        num = int(v) if float(v).is_integer() else round(v, 2)
        out.append(f'<text x="{cx + r + 52}" y="{ly + 13}" font-size="15" fill="#222">{_esc(label)}: {num} '
                   f'({frac * 100:.1f}%)</text>')
    if donut:   # a donut is a pie with its middle cut out
        out.append(f'<circle cx="{cx}" cy="{cy}" r="{int(r * 0.55)}" fill="#ffffff"/>')
    out.append("</svg>")
    return "\n".join(out)


def line_svg(data, w=640, h=360, title=""):
    """A line through the values in order, with a dot and its number at each point. The axis spans the data (not
    from 0), so a change from 82 to 78 shows; the range is padded by a tenth so no point sits on the edge."""
    top, bottom, left, right = (44 if title else 28), 40, 48, 20
    pw, ph = w - left - right, h - top - bottom
    vals = [v for _l, v in data]
    lo, hi = min(vals), max(vals)
    pad = (hi - lo) * 0.1 or (abs(hi) * 0.1 or 1.0)
    lo, hi = lo - pad, hi + pad
    inset = 24   # the first and last labels sit inside the picture, not cut by its edge
    xs = [left + inset + ((pw - 2 * inset) * i / max(1, len(data) - 1) if len(data) > 1 else (pw - 2 * inset) / 2)
          for i in range(len(data))]
    ys = [top + ph - (v - lo) / (hi - lo) * ph for v in vals]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
           f'font-family="DejaVu Sans, Arial, sans-serif"><rect width="{w}" height="{h}" fill="#ffffff"/>']
    if title:
        out.append(f'<text x="{w // 2}" y="26" font-size="18" text-anchor="middle" fill="#222">{_esc(title)}</text>')
    for k in range(5):   # horizontal guides with their values
        gy = top + ph * k / 4
        gv = hi - (hi - lo) * k / 4
        out.append(f'<line x1="{left}" y1="{gy:.1f}" x2="{w - right}" y2="{gy:.1f}" stroke="#e5e5e5"/>')
        out.append(f'<text x="{left - 6}" y="{gy + 4:.1f}" font-size="11" text-anchor="end" fill="#666">'
                   f'{round(gv, 1) if abs(gv) < 100 else int(gv)}</text>')
    pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in zip(xs, ys))
    out.append(f'<polyline points="{pts}" fill="none" stroke="#4e79a7" stroke-width="3"/>')
    for (label, v), x, y in zip(data, xs, ys):
        num = int(v) if float(v).is_integer() else round(v, 2)
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="#4e79a7"/>')
        out.append(f'<text x="{x:.1f}" y="{y - 10:.1f}" font-size="13" text-anchor="middle" fill="#222">{num}</text>')
        out.append(f'<text x="{x:.1f}" y="{h - bottom + 20}" font-size="13" text-anchor="middle" fill="#444">'
                   f'{_esc(label)}</text>')
    out.append("</svg>")
    return "\n".join(out)


def chart(text, path, title=""):
    data = pairs(text)
    if not data:
        raise ValueError("no label/number pairs in the request (e.g. 'mon 3, tue 5, wed 2')")
    pie = bool(re.search(r"(?i)\b(?:pie|donut|doughnut)\b", str(text or "")))
    line = not pie and bool(re.search(r"(?i)\b(?:line|trend|over\s+time|progress)\b", str(text or "")))
    w, h = _size(text, (640, 400) if pie else (640, 360))
    donut = pie and bool(re.search(r"(?i)\b(?:donut|doughnut|ring)\b", str(text or "")))
    svg = pie_svg(data, w, h, title, donut) if pie else line_svg(data, w, h, title) if line else chart_svg(data, w, h,
                                                                                                         title)
    kind = "donut chart" if donut else "pie chart" if pie else "line chart" if line else "bar chart"
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if path.lower().endswith(".svg"):
        with open(path, "w") as f:
            f.write(svg)
        return path, f"{kind} of {len(data)} values, drawn exactly (SVG)"
    base = os.path.splitext(path)[0]
    with open(base + ".svg", "w") as f:
        f.write(svg)
    if _svg_to_png(base + ".svg", base + ".png"):
        os.remove(base + ".svg")
        return base + ".png", f"{kind} of {len(data)} values, drawn exactly"
    return base + ".svg", (f"{kind} of {len(data)} values, drawn exactly as an SVG (no SVG-to-PNG converter on "
                           "this computer: install librsvg2-bin or ImageMagick for a PNG)")


def text(request, path):
    """Exact words, big and centred (Stable Diffusion cannot spell: "HELLO" came out as letters it made up)."""
    words = words_to_draw(request)
    if not words:
        raise ValueError("no words to draw")
    w, h = _size(request, (1024, 512))
    dark = re.search(r"(?i)\b(?:dark|black)\s+background|\bon\s+black\b|white\s+(?:text|letters)", request)
    fg, bg = ("#ffffff", "#111111") if dark else ("#111111", "#ffffff")
    cm = re.search(r"(?i)\b(red|blue|green|orange|purple|yellow|pink|gold|teal)\s+(?:text|letters|words)", request)
    if cm:
        fg = {"gold": "#c9a227", "teal": "#14857a"}.get(cm.group(1).lower(), cm.group(1).lower())
    size = max(12, min(int(h * 0.5), int(w * 0.85 / (0.7 * max(1, len(words))))))   # bold sans ~0.7em a letter
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
           f'<rect width="{w}" height="{h}" fill="{bg}"/><text x="{w // 2}" y="{h // 2 + int(size * 0.36)}" fill="{fg}" '
           f'font-family="DejaVu Sans, Liberation Sans, Arial, sans-serif" font-weight="bold" font-size="{size}" '
           f'text-anchor="middle">{_esc(words)}</text></svg>')
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    base = os.path.splitext(path)[0]
    with open(base + ".svg", "w") as f:
        f.write(svg)
    if not path.lower().endswith(".svg") and _svg_to_png(base + ".svg", base + ".png"):
        os.remove(base + ".svg")
        return base + ".png", f'the words "{words}" drawn exactly ({w}x{h})'
    return base + ".svg", (f'the words "{words}" drawn exactly as an SVG ({w}x{h}' + ("" if path.lower().endswith(
        ".svg") else "; no SVG-to-PNG converter here: install librsvg2-bin or ImageMagick for a PNG") + ")")


def _png(w, h, pixel):
    """A PNG written by hand (no Pillow): pixel(x, y) -> (r, g, b)."""
    raw = bytearray()
    for yy in range(h):
        raw.append(0)
        for xx in range(w):
            raw.extend(pixel(xx, yy))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


def _scene(text):
    t = str(text or "").lower()
    kind = next((s for s in SHAPES if re.search(rf"\b{s}\b", t)), "circle")
    # "a black circle on a white square": the FIRST shape named is the subject, a later "square" is the canvas
    names = [c for c in re.findall(r"\b(" + "|".join(COLOURS) + r")\b", t)]
    fg = COLOURS[names[0]] if names else (0, 0, 0)
    bg = COLOURS[names[1]] if len(names) > 1 else ((255, 255, 255) if fg != (255, 255, 255) else (0, 0, 0))
    return kind, fg, bg


def shape(text, path):
    w, h = _size(text, (512, 512))
    kind, fg, bg = _scene(text)
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    cx, cy, r = w / 2, h / 2, min(w, h) * 0.35
    if path.lower().endswith(".svg"):
        col = "#%02x%02x%02x" % fg
        body = {"circle": f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{col}"/>',
                "square": f'<rect x="{cx - r}" y="{cy - r}" width="{2 * r}" height="{2 * r}" fill="{col}"/>',
                "rectangle": f'<rect x="{w * 0.15}" y="{h * 0.3}" width="{w * 0.7}" height="{h * 0.4}" fill="{col}"/>',
                "triangle": f'<polygon points="{cx},{cy - r} {cx - r * 0.866},{cy + r / 2} {cx + r * 0.866},{cy + r / 2}" '
                            f'fill="{col}"/>'}[kind]
        with open(path, "w") as f:
            f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">'
                    f'<rect width="{w}" height="{h}" fill="#%02x%02x%02x"/>{body}</svg>' % bg)
        return path, f"{kind} drawn exactly ({w}x{h}, SVG)"

    def inside(x, y):
        x, y = x + 0.5, y + 0.5
        if kind == "circle":
            return (x - cx) ** 2 + (y - cy) ** 2 <= r * r
        if kind == "square":
            return abs(x - cx) <= r and abs(y - cy) <= r
        if kind == "rectangle":
            return w * 0.15 <= x <= w * 0.85 and h * 0.3 <= y <= h * 0.7
        # triangle: apex up, base below the centre
        top, base = cy - r, cy + r / 2
        if not top <= y <= base:
            return False
        half = (y - top) / (base - top) * r * 0.866
        return abs(x - cx) <= half
    if not path.lower().endswith(".png"):
        path = os.path.splitext(path)[0] + ".png"
    with open(path, "wb") as f:
        f.write(_png(w, h, lambda x, y: fg if inside(x, y) else bg))
    return path, f"{kind} drawn exactly ({w}x{h}, PNG)"


def target(text, stem, folder=None):
    """Where the drawing goes: the file he named (~/x/y.png or .svg), else the folder he named (Desktop, Downloads,
    Pictures, ~/path) or ~/Downloads, as stem-<n>.png (.svg when he asked for an SVG)."""
    import time
    t = str(text or "")
    m = re.search(r"(~/[\w./ -]*?\.(?:png|svg))\b", t)
    if m:
        return os.path.expanduser(m.group(1))
    if not folder:
        m = re.search(r"(?i)\b(?:on|to|into|in|at)\s+(?:my\s+|the\s+)?(desktop|downloads|pictures|documents)\b"
                      r"|\b(?:to|into|in|at)\s+(~/[\w./-]+)", t)
        folder = (m.group(2) or "~/" + m.group(1).capitalize()) if m else "~/Downloads"
    ext = ".svg" if re.search(r"(?i)\bsvg\b", t) else ".png"
    return os.path.join(os.path.expanduser(folder), f"{stem}-{time.strftime('%Y%m%d-%H%M%S')}{ext}")


# ---- edits of a picture that already exists ("make ~/Downloads/cocoa.png black and white" drew a NEW, different
# picture, image drive 2026-11-23): the file itself is changed, through ImageMagick where it is installed, otherwise
# in pure Python for an 8-bit PNG.
EDIT_OPS = (("grayscale", r"black\s*(?:and|&|n)\s*white|grey\s*scale|gray\s*scale|greyscale|grayscale|monochrome|b\s*&\s*w"),
            ("square", r"crop\w*[^.]{0,60}\bsquare\b|\bsquare\s+crop"),
            ("rotate", r"\brotat\w*|\bturn\s+it\b"),
            ("flip", r"\bflip\w*|\bmirror\w*"),
            ("resize", r"\bresiz\w*|\bscale\b|\bsmaller\b|\bbigger\b|\b\d{2,4}\s*[x×]\s*\d{2,4}\b"),
            # image batch 7: "make it a little brighter" drew a NEW picture instead of brightening this one
            ("brighter", r"\bbrighter\b|\blighter\b|\bbrighten\b|\bmore\s+light\b"),
            ("darker", r"\bdarker\b|\bdarken\b|\bdimmer\b|\bless\s+bright\b"),
            ("contrast", r"\bmore\s+contrast\b|\bcontrast\w*\b|\bpunchier\b"),
            ("blur", r"\bblur\w*\b|\bsofter\b|\bsoften\b"),
            ("sharpen", r"\bsharpen\w*\b|\bsharper\b|\bcrisper\b"),
            # image batch 10: "make it warmer" drew a NEW picture (299 s) instead of tinting this one
            ("warmer", r"\bwarmer\b|\bwarm\s+(?:it|tones?|colou?rs?)\b|\bmore\s+(?:orange|golden|warm)\b"),
            ("cooler", r"\bcooler\b|\bcolder\b|\bcool\s+(?:it|tones?|colou?rs?)\b|\bmore\s+(?:blue|cool)\b"))


def edit_plan(text):
    """'grayscale' | 'square' | 'rotate' | 'flip' | 'resize' for an edit of an existing picture, else ''."""
    t = str(text or "")
    if not re.search(r"(?i)\b(?:make|turn|convert|crop|rotate|flip|mirror|resize|scale|shrink|change|brighten|darken|"
                     r"blur|sharpen|soften)\b", t):
        return ""
    if re.search(r"(?i)\b(?:a|an|another|new)\s+(?:[\w-]+\s+){0,4}(?:picture|photo|image|drawing|illustration|painting|"
                 r"logo|icon|wallpaper|poster|sticker|sketch)s?\b", t) and not re.search(r"(?i)~/|\.(?:png|jpe?g|webp)\b", t):
        return ""   # "make a black and white picture of a cat" is a NEW picture, not an edit of the last one
    for op, rx in EDIT_OPS:
        if re.search(rx, t, re.I):
            return op
    return ""


def _read_png(path):
    """(w, h, rows of (r, g, b)) for an 8-bit RGB/RGBA non-interlaced PNG, or None."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos, idat, w = 8, b"", 0
    while pos < len(data):
        n = struct.unpack(">I", data[pos:pos + 4])[0]
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
        if kind == b"IHDR":
            w, h, depth, ctype, _c, _f, inter = struct.unpack(">IIBBBBB", body)
            if depth != 8 or ctype not in (0, 2, 4, 6) or inter:
                return None
            bpp = {0: 1, 2: 3, 4: 2, 6: 4}[ctype]
        elif kind == b"IDAT":
            idat += body
        pos += 12 + n
    raw, stride, prev, rows, i = zlib.decompress(idat), w * bpp, bytearray(w * bpp), [], 0
    for _y in range(h):
        ft, line = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        i += 1 + stride
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b, c = prev[x], (prev[x - bpp] if x >= bpp else 0)
            if ft == 1:
                line[x] = (line[x] + a) & 255
            elif ft == 2:
                line[x] = (line[x] + b) & 255
            elif ft == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append([tuple(line[x * bpp:x * bpp + 3]) if bpp >= 3 else (line[x * bpp],) * 3 for x in range(w)])
        prev = line
    return w, h, rows


def edit(path, op, text=""):
    """Change the picture at path in place (a copy is kept as <name>-original). -> (path, note)."""
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        raise ValueError(f"there is no {path}")
    keep = os.path.splitext(path)[0] + "-original" + os.path.splitext(path)[1]
    if not os.path.exists(keep):
        shutil.copy2(path, keep)
    size = _size(text, (0, 0))
    tool = shutil.which("magick") or shutil.which("convert")
    if tool:
        args = {"grayscale": ["-colorspace", "Gray"], "square": ["-gravity", "center", "-crop", "1:1", "+repage"],
                "rotate": ["-rotate", "90"], "flip": ["-flop"],
                "resize": ["-resize", f"{size[0]}x{size[1]}" if size[0] else "50%"],
                "brighter": ["-modulate", "118"], "darker": ["-modulate", "82"], "contrast": ["-contrast"],
                "blur": ["-blur", "0x2"], "sharpen": ["-sharpen", "0x1"],
                # a light colour wash: -fill/-colorize works in ImageMagick and GraphicsMagick alike (a three-value
                # -gamma barely showed under GraphicsMagick)
                "warmer": ["-fill", "#ff9a3c", "-colorize", "12"], "cooler": ["-fill", "#2f7dff", "-colorize", "14"]}[op]
        if op == "square":
            # 1:1 crop needs IM7's aspect geometry; the portable way is the smaller side, centred
            args = ["-gravity", "center", "-extent", "%[fx:min(w,h)]x%[fx:min(w,h)]"]
        r = subprocess.run([tool, path] + args + [path], capture_output=True, timeout=120)
        if r.returncode == 0:
            return path, f"{op} applied to the file itself (the original is kept as {os.path.basename(keep)})"
    img = _read_png(path) if path.lower().endswith(".png") else None
    if not img:
        raise ValueError("this edit needs ImageMagick for this file (install imagemagick), or an 8-bit PNG")
    w, h, rows = img
    if op == "grayscale":
        rows = [[(lambda v: (v, v, v))(int(0.299 * r + 0.587 * g + 0.114 * b)) for r, g, b in row] for row in rows]
    elif op == "square":
        s = min(w, h)
        x0, y0 = (w - s) // 2, (h - s) // 2
        rows, w, h = [row[x0:x0 + s] for row in rows[y0:y0 + s]], s, s
    elif op == "flip":
        rows = [row[::-1] for row in rows]
    elif op == "rotate":
        rows, w, h = [[rows[h - 1 - y][x] for y in range(h)] for x in range(w)], h, w
    elif op in ("brighter", "darker"):
        k = 1.18 if op == "brighter" else 0.82
        rows = [[tuple(max(0, min(255, int(c * k))) for c in px) for px in row] for row in rows]
    elif op in ("warmer", "cooler"):
        kr, kb = (1.1, 0.9) if op == "warmer" else (0.9, 1.1)
        rows = [[(max(0, min(255, int(r * kr))), g, max(0, min(255, int(b * kb)))) for r, g, b in row] for row in rows]
    elif op in ("contrast", "blur", "sharpen"):
        raise ValueError(f"{op} needs ImageMagick or GraphicsMagick installed")
    elif op == "resize":
        nw, nh = size if size[0] else (w // 2, h // 2)
        rows, w, h = [[rows[y * h // nh][x * w // nw] for x in range(nw)] for y in range(nh)], nw, nh
    with open(path, "wb") as f:
        f.write(_png(w, h, lambda x, y: rows[y][x]))
    return path, f"{op} applied to the file itself (the original is kept as {os.path.basename(keep)})"
