"""Terminal text primitives: width measurement, safe rows, wrapping, colour, the live owl."""
import math
import os
import re
import shutil
import sys

import gnoc_theme as T


_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


_SGR = re.compile(r"\x1b\[[0-9;:]*m")


_ESC_ANY = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")


def _char_cols(ch):
    """Terminal columns one printable character takes: 0 for combining marks and zero-width format characters,
    2 for East Asian wide/fullwidth, 1 otherwise."""
    import unicodedata
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _text_cols(s):
    """Printable columns of s: escape sequences cost nothing, control characters cost nothing (_row_text has
    already expanded or dropped them in anything that is printed)."""
    return sum(_char_cols(ch) for ch in _ESC_ANY.sub("", s or "") if ch >= " " and not ("\x7f" <= ch < "\xa0"))


def _row_text(s, col0=0):
    """Make s safe to print as ONE row starting at terminal column col0 (0-based): colour codes are kept, every
    other escape sequence (cursor moves, erase, OSC titles/links) is dropped, a TAB becomes the spaces the
    terminal would have advanced to its next 8-column stop, a newline becomes a space and every other control
    character is dropped. Tool output reaches the transcript through this, so a stray \r, \x1b[2K or tab can
    no longer move the cursor or widen a row behind the width check's back."""
    s = str(s if s is not None else "")
    out, col, i = [], col0, 0
    while i < len(s):
        ch = s[i]
        if ch == "\x1b":
            m = _SGR.match(s, i)
            if m:
                out.append(m.group(0))
                i = m.end()
                continue
            m = _ESC_ANY.match(s, i)
            i = m.end() if m else i + 1
            continue
        if ch == "\t":
            n = 8 - (col % 8)
            out.append(" " * n)
            col += n
        elif ch == "\n":
            out.append(" ")
            col += 1
        elif ch < " " or "\x7f" <= ch < "\xa0":
            pass
        else:
            out.append(ch)
            col += _char_cols(ch)
        i += 1
    return "".join(out)


def _term_cols(default=100):
    """The live window width. shutil.get_terminal_size() believes a COLUMNS variable over the terminal, so a
    COLUMNS exported by a parent shell or a multiplexer goes stale on the first resize; when one is set and
    stdout is a real terminal, ask the terminal (BottomBar._size does the same for the input line)."""
    if os.environ.get("COLUMNS"):
        try:
            if sys.stdout.isatty():
                c = os.get_terminal_size(sys.stdout.fileno()).columns
                if c:
                    return c
        except (OSError, ValueError, AttributeError):
            pass
    return shutil.get_terminal_size((default, 24)).columns


def _split_cols(s, n):
    """Split s after n printable columns; escape sequences stay with the head and an attribute open at the cut
    carries over into the tail, as it does on the terminal."""
    used, i = 0, 0
    while i < len(s):
        m = _ESC_ANY.match(s, i)
        if m:
            i = m.end()
            continue
        w = _char_cols(s[i])
        if used + w > n:
            break
        used += w
        i += 1
    if i == 0 and s:          # n smaller than one wide glyph: still make progress
        i = 1
    return s[:i], s[i:]


def hang(text, indent=2, width=None):
    """Word-wrap a (possibly coloured) line to the live terminal width with a hanging indent, so a long
    status line reads as one paragraph instead of a line that snaps at the right edge and continues at
    column 0 (the start-up banner did exactly that at 120 columns, 2026-10-24). Colour codes ride inside
    their words and cost no columns; an attribute that spans a break carries over, as the terminal does.
    Every row is at most width-1 columns: a word longer than the row (a URL, a model id) is broken hard,
    tabs and control characters are made safe first, and the line's own leading spaces are kept."""
    cols = max(30, width or _term_cols()) - 1
    return "\n".join(r for para in str(text if text is not None else "").split("\n")
                     for r in _hang_rows(_row_text(para), indent, cols))


def _hang_rows(para, indent, cols):
    if _text_cols(para) <= cols:
        return [para]
    plain = _ESC_ANY.sub("", para)
    lead = len(plain) - len(plain.lstrip(" "))
    pad = " " * min(max(indent, lead), cols // 2)
    rows, cur, used, has = [], "", 0, False
    for i, w in enumerate(para.split(" ")):
        vw = _text_cols(w)
        sep = 0 if i == 0 else 1
        if rows and not has:
            if not vw:               # a colour code or a doubled space right after a break: no stray column
                cur += w
                continue
            sep = 0
        if has and used + sep + vw > cols:
            rows.append(cur.rstrip(" "))
            cur, used, has, sep = pad, len(pad), False, 0
        while vw and used + sep + vw > cols:   # still too wide for a whole row: break the word itself
            head, w = _split_cols(w, max(1, cols - used - sep))
            rows.append(cur + " " * sep + head)
            cur, used, has, sep = pad, len(pad), False, 0
            vw = _text_cols(w)
        cur += " " * sep + w
        used += sep + vw
        has = has or bool(_ESC_ANY.sub("", w).strip())
    rows.append(cur)
    return rows


def _fit_width(s, cols):
    """Cut s to at most `cols` printable columns. Escape sequences are copied whole and cost nothing, so a cut
    never lands inside one; wide glyphs count 2 (the same rule as _text_cols); a coloured cut line ends with a
    reset, and a plain one does not (piped output used to carry a stray ESC[0m)."""
    out, used, i = [], 0, 0
    while i < len(s):
        m = _ANSI.match(s, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        ch = s[i]
        w = _char_cols(ch)
        if used + w > max(0, cols):
            fragment = "".join(out)
            return fragment + ("\x1b[0m" if "\x1b[" in fragment else "")
        out.append(ch)
        used += w
        i += 1
    return s


_ACCENT_256 = ("256color" in os.environ.get("TERM", "").lower()
               or os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit"))


OWL_COLS = 3
OWL_BREATH_S = 2.8


_GLOW_RAMP = ("38;5;24", "38;5;31", "38;5;38", "38;5;45", "38;5;81", "38;5;123", "38;5;159", "38;5;195")


_GLOW_ANSI = ("2;96", "96", "1;96")


_SHINE_RAMP = ("38;5;248", "38;5;251", "38;5;254", "1;38;5;231")


_SHINE_ANSI = ("37", "37", "97", "1;97")


_SPARK = "▁▂▃▄▅▆▇█"


_OWL_LOOK = ((0.0, "◉"), (2.2, "◐"), (2.6, "◉"), (3.0, "◑"), (3.4, "◉"), (5.55, "─"), (5.7, "◉"))


_OWL_LOOK_S = 6.0


_OWL_SCAN = ("◐", "◉", "◑", "◉")


def _sgr(code, text):
    return f"\x1b[{code}m{text}\x1b[0m" if T.TTY else str(text)


def _pick(r256, r16, level):
    ramp = r256 if _ACCENT_256 else r16
    return ramp[max(0, min(len(ramp) - 1, int(round(max(0.0, min(1.0, level)) * (len(ramp) - 1)))))]


def _glow(text, level=1.0):
    """The eye glow at a brightness from 0.0 (embers) to 1.0 (white-hot ice)."""
    return _sgr(_pick(_GLOW_RAMP, _GLOW_ANSI, level), text)


def _owl_static(level=0.85):
    """The eyes at rest, for one-off lines (startup, the reasoning block header): two columns, no padding."""
    return _glow("◉◉", level)


def _owl(kind, elapsed, frame, stalled=False):
    """One frame of the live eyes, exactly OWL_COLS columns (trailing space included)."""
    if stalled:
        return T.bred("◉◉") + " "
    if kind == "tool":
        return _glow(_OWL_SCAN[(frame // 2) % len(_OWL_SCAN)] * 2, 0.9) + " "
    if kind == "wait":
        return T.dim("──") + " "
    t = elapsed % _OWL_LOOK_S
    eye = [g for at, g in _OWL_LOOK if t >= at][-1]
    breath = 0.5 - 0.5 * math.cos(2 * math.pi * ((elapsed % OWL_BREATH_S) / OWL_BREATH_S))
    return _glow(eye * 2, 0.35 + 0.65 * breath) + " "


def _shine(label, frame, live=True):
    """The label with a light sweeping through it, one character per frame, a pause between passes."""
    if not T.TTY or not live:
        return T.white(label) if live else T.dim(label)
    n = len(label)
    head = frame % (n + 12) - 2
    out = []
    for j, ch in enumerate(label):
        d = abs(j - head)
        out.append(_sgr(_pick(_SHINE_RAMP, _SHINE_ANSI, (3 - min(d, 3)) / 3), ch))
    return "".join(out)


def _sparkline(rates, width=8):
    """The last few tok/s samples as rising blocks, each lit by its own height. Re-opens dim afterwards, so it
    can sit inside a dim() run without ending it."""
    vals = [r for r in rates[-width:] if r is not None]
    top = max(vals or [0])
    if len(vals) < 3 or top <= 0:
        return ""
    # scaled between the slowest and fastest sample, so a steady stream shows its wobble instead of a flat
    # block of full bars; lit low, so it never outshines the owl
    lo = min(vals)
    span = top - lo
    out = ""
    for v in vals:
        h = (v - lo) / span if span > 0.05 * top else 0.5
        out += _glow(_SPARK[max(0, min(len(_SPARK) - 1, int(round(h * (len(_SPARK) - 1)))))], 0.05 + 0.25 * h)
    return out + ("\x1b[2m" if T.TTY else "") + " "


def _short_model(model):
    """A compact label for a model id in status lines: drop the hf.co/owner/ prefix and the -GGUF:QUANT
    packaging, keep the distinctive name. Full ids stay where they are identity keys (broken map, errors)."""
    m = str(model or "").split("/")[-1]
    m = re.sub(r"-i1-GGUF|-GGUF", "", m, flags=re.I)
    m = re.sub(r":[A-Za-z0-9_.]+$", "", m)
    return m or str(model)


def _strip_rl(t):
    """Drop readline's \001..\002 width markers: they are for readline's own column counting, and
    writing them to the terminal shows control characters."""
    return (t or "").replace("\001", "").replace("\002", "")


def _vis_len(t):
    """Printable columns in a string that carries colour codes."""
    return len(re.sub(r"\x1b\[[0-9;]*m", "", t or ""))


def _fit_cols(t, cols):
    """Trim to `cols` PRINTABLE columns, never cutting inside an escape sequence."""
    out, width, i = [], 0, 0
    while i < len(t) and width < cols:
        m = re.match(r"\x1b\[[0-9;]*m", t[i:])
        if m:
            out.append(m.group(0))
            i += m.end()
            continue
        out.append(t[i])
        width += 1
        i += 1
    return "".join(out) + ("\x1b[0m" if "\x1b[" in "".join(out) else "")
