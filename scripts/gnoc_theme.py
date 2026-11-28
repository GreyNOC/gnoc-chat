"""gnoc_theme.py - the Parrot OS terminal look for gnoc, and a streaming Markdown renderer for gnoc chat.

Two palettes, kept apart on purpose so code never blends into the interface:
    APP   (the interface)  red, blue, green, yellow - the Parrot prompt colours (bright ANSI 91/94/92/93)
    CODE  (code blocks)    a 256-colour set: pink keywords, orange strings, violet numbers, cyan functions,
                           teal builtins, grey comments, on a dark grey panel
Both fall back to plain text when stdout is not a TTY or NO_COLOR is set, so pipes and logs stay clean.

    import gnoc_theme as T
    T.red("x"); T.prompt("program", "repo")          # the ┌─[gnoc]─[...] / └──╼ $ prompt (readline-safe)
    md = T.MarkdownStream(write); md.feed(tok); md.close()   # render model output as it streams
    T.render_markdown(text)                           # whole-text version
"""
import os
import re
import shutil
import sys
import unicodedata

TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
RESET = "\x1b[0m"


def _c(code, s):
    return f"\x1b[{code}m{s}{RESET}" if TTY else str(s)


# ---------------------------------------------------------------- APP palette (Parrot OS)
def red(s): return _c("91", s)
def blue(s): return _c("94", s)
def green(s): return _c("92", s)
def yellow(s): return _c("93", s)
def bred(s): return _c("1;91", s)
def bblue(s): return _c("1;94", s)
def bgreen(s): return _c("1;92", s)
def byellow(s): return _c("1;93", s)
def bold(s): return _c("1", s)
def dim(s): return _c("2", s)
def white(s): return _c("97", s)
def italic(s): return _c("3", s)


# ---------------------------------------------------------------- CODE palette (distinct from the app)
CODE_BG = "48;5;235"
CODE = {
    "text": "38;5;252", "keyword": "38;5;205", "string": "38;5;215", "number": "38;5;141",
    "function": "38;5;117", "class": "38;5;117;1", "builtin": "38;5;80", "comment": "38;5;244;3",
    "operator": "38;5;211", "decorator": "38;5;177", "variable": "38;5;223", "tag": "38;5;205",
    "attr": "38;5;80", "error": "38;5;196", "inline": "38;5;213",
}


def _code(kind, s):
    return f"\x1b[{CODE[kind]};{CODE_BG}m{s}" if TTY else s


def prompt(*fields):
    """The Parrot two-line prompt. Escape codes are wrapped in \\001..\\002 so readline counts the width right."""
    if not TTY:
        return "> "
    w = lambda code, s: f"\001\x1b[{code}m\002{s}\001{RESET}\002"
    parts = [w("91", "┌─[") + w("1;93", "gnoc")]
    for i, f in enumerate(x for x in fields if x):
        # the program (first field, when there is one) is blue; with no program the folder comes first and keeps
        # its own green
        colour = "1;91" if f == "skip-perms" else "96" if str(f).startswith("◎") else \
            "94" if i == 0 and fields and fields[0] else "92"
        parts.append(w("91", "]─[") + w(colour, f))
    return "".join(parts) + w("91", "]") + "\n" + w("91", "└──╼ ") + w("1;93", "$ ")


# ---------------------------------------------------------------- syntax highlighting
try:
    from pygments import lex
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.token import (Comment, Error, Keyword, Name, Number, Operator, String, Literal, Generic,
                                Punctuation)
    from pygments.util import ClassNotFound
    _PYG = True
except ImportError:  # still renders, just without per-token colour
    _PYG = False

_ALIAS = {"sh": "bash", "shell": "bash", "zsh": "bash", "console": "bash", "py": "python", "js": "javascript",
          "ts": "typescript", "yml": "yaml", "ps1": "powershell", "http": "http", "": "text"}


def _kind(tt):
    if tt in Comment or tt in Comment.Single:
        return "comment"
    if tt in Keyword:
        return "keyword"
    if tt in String or tt in Literal.String:
        return "string"
    if tt in Number or tt in Literal.Number:
        return "number"
    if tt in Name.Function or tt in Name.Function.Magic:
        return "function"
    if tt in Name.Class or tt in Name.Namespace:
        return "class"
    if tt in Name.Builtin or tt in Name.Builtin.Pseudo:
        return "builtin"
    if tt in Name.Decorator:
        return "decorator"
    if tt in Name.Variable:
        return "variable"
    if tt in Name.Tag:
        return "tag"
    if tt in Name.Attribute:
        return "attr"
    if tt in Operator or tt in Punctuation:
        return "operator"
    if tt in Error or tt in Generic.Error:
        return "error"
    if tt in Generic.Inserted:
        return "string"
    if tt in Generic.Deleted:
        return "keyword"
    return "text"


def _lexer(lang, sample=""):
    if not _PYG:
        return None
    lang = (lang or "").strip().lower()
    try:
        return get_lexer_by_name(_ALIAS.get(lang, lang), stripnl=False, ensurenl=False)
    except ClassNotFound:
        try:
            return guess_lexer(sample) if sample.strip() else None
        except ClassNotFound:
            return None


def highlight_lines(code, lang):
    """Highlight a whole block; returns one coloured string per source line (no trailing reset)."""
    lines = code.split("\n")
    lx = _lexer(lang, code)
    if not TTY or lx is None:
        return [_code("text", l) for l in lines]
    out, cur = [], []
    for tt, val in lex(code, lx):
        kind = _kind(tt)
        parts = val.split("\n")
        for j, p in enumerate(parts):
            if j:
                out.append("".join(cur))
                cur = []
            if p:
                cur.append(_code(kind, p))
    out.append("".join(cur))
    return out[:len(lines)] + [""] * (len(lines) - len(out))


# ---------------------------------------------------------------- markdown (prose lines)
def width():
    return max(40, shutil.get_terminal_size((100, 24)).columns)


def vis_len(s):
    """Printed width of a string: ANSI stripped, wide (CJK/emoji) characters count 2."""
    s = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|[\001\002]", "", s)
    return sum(2 if unicodedata.east_asian_width(ch) in "WF" else 0 if unicodedata.combining(ch) else 1 for ch in s)


_INLINE = re.compile(r"(`[^`\n]+`)|(\*\*[^*\n]+\*\*|__[^_\n]+__)|(\*[^*\s][^*\n]*\*|(?<!\w)_[^_\s][^_\n]*_(?!\w))|"
                     r"(\[[^\]\n]+\]\([^)\s]+\))")


def inline(s):
    if not TTY:
        return s

    def sub(m):
        t = m.group(0)
        if m.group(1):
            return f"\x1b[{CODE['inline']};{CODE_BG}m{t[1:-1]}{RESET}"
        if m.group(2):
            return f"\x1b[1;97m{t[2:-2]}{RESET}"
        if m.group(3):
            return f"\x1b[3m{t[1:-1]}{RESET}"
        txt, url = re.match(r"\[([^\]]+)\]\(([^)]+)\)", t).groups()
        return f"\x1b[4;94m{txt}{RESET}" + dim(f" ({url})")
    return _INLINE.sub(sub, s)


def prose_line(line):
    if not TTY:
        return line
    m = re.match(r"^(#{1,6})\s+(.*)$", line)
    if m:
        lvl, txt = len(m.group(1)), m.group(2)
        # strip emphasis/code MARKERS only: deleting every underscore showed "### `test_calc.py`" as "testcalc.py"
        txt = re.sub(r"\*+|`|(?<![A-Za-z0-9])_+|_+(?![A-Za-z0-9])", "", txt)
        return {1: bred, 2: byellow}.get(lvl, bblue)(("" if lvl > 2 else "▍") + txt)
    if re.match(r"^\s*([-*_])(\s*\1){2,}\s*$", line):
        return dim("─" * min(60, width() - 2))
    m = re.match(r"^(\s*)[-*+]\s+(\[[ xX]\]\s+)?(.*)$", line)
    if m:
        box = m.group(2)
        mark = (green("☑ ") if box.strip()[1] in "xX" else yellow("☐ ")) if box else green("• ")
        return wrap_prose(inline(m.group(3)), first=PROSE_INDENT + m.group(1) + mark, rest=PROSE_INDENT + m.group(1) + "  ")
    m = re.match(r"^(\s*)(\d+)[.)]\s+(.*)$", line)
    if m:
        num = yellow(m.group(2) + ".") + " "
        return wrap_prose(inline(m.group(3)), first=PROSE_INDENT + m.group(1) + num,
                          rest=PROSE_INDENT + m.group(1) + " " * (len(m.group(2)) + 2))
    m = re.match(r"^\s*>\s?(.*)$", line)
    if m:
        return blue("▌ ") + italic(inline(m.group(1)))
    if re.match(r"^\s*\|.*\|\s*$", line):
        if re.match(r"^\s*\|[\s:|-]+\|\s*$", line):
            return blue(re.sub(r"[^|]", "─", line.strip()).replace("|", "┼"))
        cells = line.strip().strip("|").split("|")
        return blue("│") + blue("│").join(" " + inline(c.strip()) + " " for c in cells) + blue("│")
    if not line.strip():
        return line
    return wrap_prose(inline(line), first=PROSE_INDENT, rest=PROSE_INDENT)


# Prose is indented two columns and wrapped at the window, like a chat transcript, instead of running
# edge to edge and snapping mid-word wherever the terminal folds it (2026-10-24). Code, tables, rules and
# headings keep their own layout; a word longer than the room is cut rather than looped on.
PROSE_INDENT = "  "


def wrap_prose(text, first="", rest="", cols=None):
    cols = (cols or width()) - 1
    words = text.split(" ")
    out, cur, pre = [], "", first
    for w in words:
        if not w and cur:
            continue
        vw = vis_len(w)
        if cur and vis_len(cur) + 1 + vw > cols:
            out.append(cur)
            cur, pre = rest + w, rest
        elif not cur:
            cur = pre + w
        else:
            cur += " " + w
    out.append(cur if cur else pre.rstrip())
    return "\n".join(out)


FENCE = re.compile(r"^\s*(```|~~~)\s*([\w+#.-]*)\s*$")


# A code line carries ONLY the code: no gutter or side border, so a mouse selection of the code lines pastes
# clean. The panel is a background colour (\x1b[K fills it to the edge without writing characters, so nothing
# extra is copied); the label and closing rules sit on their own lines, outside the selection.
def _code_top(lang):
    w = min(width() - 2, 100)
    label = f" {lang or 'code'} "
    return dim("──") + yellow(label) + dim("─" * max(2, w - len(label) - 2))


def _code_bottom():
    return dim("─" * min(width() - 2, 100))


def _code_row(colored):
    return colored + (f"\x1b[{CODE_BG}m\x1b[K{RESET}" if TTY else "")


# ---------------------------------------------------------------- diffs (Claude Code style)
DIFF_ROW = re.compile(r"^\s*(\d*) ([-+ ]) (.*)$")


def diff_line(row, numw=4):
    """One numbered diff row '  12 - text' -> gutter number, then the line on a red (removed) or green (added)
    background filled to the edge; context lines dim. Hunk gaps ('⋯') stay dim."""
    m = DIFF_ROW.match(row)
    if not m:
        return dim(row)
    num, sign, text = m.groups()
    text = text.expandtabs(4)
    if not TTY:
        return f"{num:>{numw}} {sign} {text}"
    gutter = f"\x1b[2m{num:>{numw}}\x1b[0m "
    if sign == "-":
        return gutter + f"\x1b[48;5;52m\x1b[1;91m- \x1b[22;38;5;224m{text}\x1b[K{RESET}"
    if sign == "+":
        return gutter + f"\x1b[48;5;22m\x1b[1;92m+ \x1b[22;38;5;194m{text}\x1b[K{RESET}"
    return gutter + dim("  " + text)


FENCED = re.compile(r"^[ \t]*(```|~~~)[ \t]*([\w+#.-]*)[ \t]*\n(.*?)^[ \t]*\1[ \t]*$", re.S | re.M)


def code_blocks(text):
    """[(lang, code), ...] for every fenced block in a Markdown answer (an unclosed last block counts)."""
    out = [(m.group(2), m.group(3).rstrip("\n")) for m in FENCED.finditer(text or "")]
    tail = (text or "")[max((m.end() for m in FENCED.finditer(text or "")), default=0):]
    m = re.search(r"^[ \t]*(```|~~~)[ \t]*([\w+#.-]*)[ \t]*\n(.*)$", tail, re.S | re.M)
    if m:
        out.append((m.group(2), m.group(3).rstrip("\n")))
    return out


def copy_to_clipboard(text):
    """System clipboard via xclip / xsel / wl-copy; else OSC 52 (the terminal sets the clipboard itself, which also
    works over SSH in most terminals). Returns how it was copied."""
    import base64
    import subprocess
    for cmd in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
        if shutil.which(cmd[0]) and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            try:
                subprocess.run(cmd, input=text, text=True, timeout=5, check=True)
                return cmd[0]
            except Exception:
                continue
    sys.stdout.write("\x1b]52;c;" + base64.b64encode(text.encode()).decode() + "\a")
    sys.stdout.flush()
    return "terminal (OSC 52)"


def render_markdown(text):
    """Whole-text render (for one-shot answers, notes, history replay)."""
    out = []
    MarkdownStream(out.append).feed(text).close()
    return "".join(out)


class MarkdownStream:
    """Renders streamed model text as Markdown, line by line.

    A partial line is shown raw the moment its tokens arrive (so the answer still streams); when its newline
    lands, that line is erased and redrawn rendered. Code-fence lines are highlighted against the whole block
    so far, which keeps multi-line strings and comments correct."""

    def __init__(self, write):
        self.write = write
        self.buf = ""
        self.shown = ""        # raw partial text already on screen for the current line
        self.code = None       # None, or [lang, [lines]]

    def _erase_partial(self):
        if not self.shown or not TTY:
            self.shown = ""
            return
        cols = vis_len(self.shown)
        rows = max(1, -(-cols // width()))
        self.write("\r" + (f"\x1b[{rows - 1}A" if rows > 1 else "") + "\x1b[J")
        self.shown = ""

    def _emit_line(self, line):
        m = FENCE.match(line)
        if self.code is None and m:
            self.code = [m.group(2), []]
            self.write(_code_top(m.group(2)) + "\n")
        elif self.code is not None and m and not m.group(2):
            self.code = None
            self.write(_code_bottom() + "\n")
        elif self.code is not None:
            self.code[1].append(line)
            hl = highlight_lines("\n".join(self.code[1]), self.code[0])
            self.write(_code_row(hl[-1] if hl else "") + "\n")
        else:
            self.write(prose_line(line) + "\n")

    def feed(self, tok):
        if not tok:
            return self
        if not TTY:
            self.write(tok)
            return self
        self.buf += tok
        while "\n" in self.buf:
            line, self.buf = self.buf.split("\n", 1)
            self._erase_partial()
            self._emit_line(line)
        if self.buf and len(self.buf) > len(self.shown):
            self.write(self.buf[len(self.shown):])
            self.shown = self.buf
        return self

    def close(self):
        if TTY and self.buf:
            self._erase_partial()
            self._emit_line(self.buf)
        self.buf = ""
        if TTY and self.code is not None:
            self.write(_code_bottom() + "\n")
            self.code = None
        return self


if __name__ == "__main__":  # demo: python3 scripts/gnoc_theme.py
    demo = ("# gnoc theme\n## Interface\nA **bold** word, an *italic* one, `inline code`, a [link](https://x.y).\n"
            "- bullet\n- [x] done\n1. first\n> a quote\n\n| col | val |\n|---|---|\n| a | 1 |\n\n"
            "```python\n@cache\ndef probe(url: str, n=3):\n    \"\"\"doc\"\"\"\n    # comment\n"
            "    return requests.get(url, timeout=n).status_code == 200\n```\n"
            "```bash\ncurl -s https://example.com | grep -c 'x'  # count\n```\n")
    md = MarkdownStream(sys.stdout.write)
    for i in range(0, len(demo), 7):
        md.feed(demo[i:i + 7])
    md.close()
    print(red("red ") + blue("blue ") + green("green ") + yellow("yellow"))
