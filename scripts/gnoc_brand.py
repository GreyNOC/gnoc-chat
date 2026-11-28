"""gnoc_brand.py - what the user actually looks like, for anything that makes a picture.

The user has TWO faces and they are not alike. Getting this wrong is the commonest way a generated
brand image comes out wrong, and it looks deliberate rather than mistaken:

    company   the public site at your-site.example - DEEP NAVY and ELECTRIC BLUE, a lit stone
              pyramid, a heavy serif GREYNOC wordmark, one red C.E.R.T. accent.
    academy   the campus behind it - near-black with a green cast, LIME GREEN signal, IBM Plex
              Sans and Mono, flat panels, square geometry.

Every colour here is READ FROM THE REAL STYLESHEET at call time (public/landing.css and
public/signal-command.css in the website repo), so the palette cannot drift from the site the way a
copied hex does. FALLBACK holds the values as of 2026-10-24 for when the repo is not on this disk;
test_gnoc_agent.py asserts the two agree, so a site retheme fails the suite instead of silently
shipping last year's blue.

THE RULE THAT MATTERS MOST: a diffusion model CANNOT draw the GreyNOC owl. Asked for "the GreyNOC
owl" SDXL invents a different owl every time, and a nearly-right logo is worse than none - it reads
as a counterfeit of your own brand. The real marks are PNGs with alpha in the website repo. So the
model generates the SCENE and compose() lays the REAL mark on top. Same for the wordmark: diffusion
models garble lettering, so NEGATIVE pushes text out of the frame and any wordmark is composited or
set in HTML, never generated.
"""
import os
import re

WEBSITE = os.environ.get("GNOC_WEBSITE_REPO", os.path.expanduser("~/gnoc-site"))
ICONS = os.path.join(WEBSITE, "public", "icons")

FACES = ("company", "academy")

# (css file, token -> role). The token names are the site's own.
_SOURCES = {
    "company": ("public/landing.css", {"navy": "canvas", "blue": "signal", "ice": "light", "white": "ink"}),
    "academy": ("public/signal-command.css", {"sc-canvas": "canvas", "sc-green": "signal", "sc-ink": "ink",
                                              "sc-sub": "sub", "sc-surface": "surface", "sc-rule": "rule"}),
}
# Read 2026-10-24. Kept so a machine without the website repo still gets the brand right, and so the
# test can prove the stylesheets still say this.
FALLBACK = {
    "company": {"canvas": "#050c20", "signal": "#4597e5", "light": "#b9e6ff", "ink": "#f6f9ff",
                "alert": "#ff3b3b", "deep": "#03091b"},
    "academy": {"canvas": "#090d0b", "signal": "#9de66b", "ink": "#f2f0e8", "sub": "#a8b0aa",
                "surface": "#0f1411", "rule": "#2b342e"},
}

# The marks, by what they are FOR. Every one is a PNG with alpha.
MARKS = {
    "owl-light": "owl-512.png",          # white owl, for a dark frame - the default
    "owl-dark": "owl-ink-1024.png",      # navy owl, for a light frame
    "owl-badge": "owl-badge-512.png",    # the owl in its dark disc, when the frame is busy
    "orb": "orb-512.png",
}


def _read_css(rel):
    try:
        with open(os.path.join(WEBSITE, rel), encoding="utf-8") as fh:
            return fh.read()
    except Exception:
        return ""


def palette(face="company"):
    """The face's colours, read from the site. Falls back to the pinned values off-disk."""
    face = face if face in FACES else "company"
    out = dict(FALLBACK[face])
    rel, roles = _SOURCES[face]
    css = _read_css(rel)
    for token, role in roles.items():
        m = re.search(r"--" + re.escape(token) + r"\s*:\s*(#[0-9a-fA-F]{3,8})", css)
        if m:
            out[role] = m.group(1).lower()
    return out


def mark_path(name="owl-light"):
    """The file for a named mark, or None. A name that is not in MARKS is NOT quietly turned into the
    default: a typo'd mark would then stamp a different logo than the one asked for and nothing would
    say so (found by its own test, 2026-10-24)."""
    rel = MARKS.get(name)
    if not rel:
        return None
    p = os.path.join(ICONS, rel)
    return p if os.path.isfile(p) else None


# What the picture should LOOK like, per face. Written as a prompt fragment, in the plain visual
# vocabulary a diffusion model answers to - no brand nouns it cannot know.
def style_prompt(face="company"):
    c = palette(face)
    if face == "academy":
        # The word "green" alone floods the frame: the first academy test came back as a saturated
        # neon-green computer lab, which llava passed as OK (2026-10-24). The campus is almost
        # entirely BLACK with green as a small accent, so say that in proportions, not adjectives.
        return (f"a very dark almost black scene {c['canvas']}, most of the frame in deep shadow, lit "
                f"only by one small lime-green {c['signal']} accent light and the faint glow it throws, "
                "the rest of the picture unlit and nearly black, flat matte surfaces, square hard-edged "
                "geometry, thin precise lines, very high contrast, restrained, cool technical mood, "
                "clean negative space, no clutter")
    return (f"deep navy {c['canvas']} background, electric blue {c['signal']} rim light and volumetric "
            f"glow, pale ice-blue {c['light']} highlights, dark cut stone and brushed metal, dramatic "
            "low-key lighting, mist, cinematic wide composition, clean negative space, no clutter")


# Diffusion models garble lettering and hallucinate logos. Both are fatal on a brand image, so they
# are pushed out of the frame by default and the real mark is composited afterwards.
_NEGATIVE_BASE = ("text, words, letters, typography, watermark, signature, logo, emblem, brand mark, owl, "
                  "bird, mascot, ui mockup, website screenshot, people, faces, hands, lowres, blurry, "
                  "jpeg artifacts, oversaturated, cluttered")
# Both faces are COLD. The first company test came back with an orange sunset on the horizon, which
# passed every numeric check and still read as off-brand at a glance, so warmth is pushed out
# explicitly rather than left to the palette words to win on their own (2026-10-24).
_NEGATIVE_WARM = "sunset, sunrise, golden hour, orange sky, warm light, amber glow, fire, candlelight, sepia"
# A colour name in the prompt becomes a colour CAST over the whole frame unless it is pushed back.
_NEGATIVE_FLOOD = ("neon, saturated colour, colour flood, monochrome colour wash, everything one colour, "
                   "glowing room, rave lighting, overexposed")
NEGATIVE = _NEGATIVE_BASE + ", " + _NEGATIVE_WARM + ", " + _NEGATIVE_FLOOD


def brief_hint(face="company"):
    """One line the agent can show the user so the user knows which face it is about to use."""
    c = palette(face)
    where = "the public site (your-site.example)" if face == "company" else "the Academy campus"
    return f"{face}: {where}, canvas {c['canvas']}, signal {c['signal']}"


def compose(image_path, mark="owl-light", corner="bottom-right", scale=0.16, pad=0.04, out=None):
    """Lay the REAL mark onto a generated image. Returns (out_path, note) or (None, why).

    This is the step that makes a brand image honest: the scene is generated, the mark is the
    file the site serves. Nothing here redraws it.
    """
    src = mark_path(mark)
    if not src:
        return None, f"no mark named {mark!r} under {ICONS}"
    try:
        from PIL import Image
    except Exception as e:
        return None, f"PIL is needed to composite the mark: {type(e).__name__}"
    try:
        with Image.open(image_path) as base_im:
            base = base_im.convert("RGBA")
        with Image.open(src) as m_im:
            m = m_im.convert("RGBA")
    except Exception as e:
        return None, f"could not open the image or the mark: {type(e).__name__}: {str(e)[:120]}"
    w, h = base.size
    side = max(24, int(min(w, h) * float(scale)))
    m = m.resize((side, side), Image.LANCZOS)
    off = int(min(w, h) * float(pad))
    spots = {"bottom-right": (w - side - off, h - side - off), "bottom-left": (off, h - side - off),
             "top-right": (w - side - off, off), "top-left": (off, off),
             "center": ((w - side) // 2, (h - side) // 2)}
    base.alpha_composite(m, spots.get(corner, spots["bottom-right"]))
    out = out or (os.path.splitext(image_path)[0] + "-marked.png")
    base.convert("RGB").save(out)
    return out, f"{os.path.basename(src)} at {side}px, {corner}"
