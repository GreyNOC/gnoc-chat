"""gnoc_typeahead.py - type while it works: stage the next request, or cut into the one running.

The REPL reads a line, runs a whole turn, then reads again, so everything typed during a turn used to sit in the
terminal buffer unseen and then arrive mangled at the next prompt (the spinner repaints over it). This owns stdin
for exactly as long as a turn runs:

    plain text + Enter      STAGED: it runs as the next request the moment this turn ends, no retyping
    ! text      + Enter     CUTS IN: the turn is interrupted now and the text runs next
    Down / Up (empty line)  WATCH a running sub-agent live / back to the main chain
    Ctrl-C                  unchanged, the terminal still raises SIGINT (cbreak keeps ISIG on)

The spinner draws the buffer as you type, so characters are not eaten by its repaint. Not a tty (a pipe, a
one-shot, a test) -> start() is a no-op and nothing changes.
"""
import codecs
import contextlib
import os
import queue
import select
import sys
import threading

try:
    import termios
    import tty
except ImportError:  # not POSIX: type-ahead is simply off
    termios = tty = None

BACKSPACE = ("\x7f", "\b")
CUT_IN = "!"
# "/btw <text>" typed WHILE a turn runs: a side note the running turn reads at its next step. A plain line waits
# for the next turn and a "!" line kills this one; neither can add context to work already under way.
BTW = "/btw"
# "/gpu1 <text>" typed WHILE a turn runs: fire the worker model on the second GPU now, in the background, and
# print its answer when it lands. Like /btw it never waits for the next turn, but it bypasses the lead entirely
# instead of feeding the running turn - the lead keeps thinking on its own GPU.
GPU1 = "/gpu1"


class TypeAhead:
    """Reads stdin in a daemon thread while a turn runs. Lines land in a queue; the partial line is public so
    the status line can draw it."""

    def __init__(self, on_cut_in=None, enabled=True, on_arrow=None, on_change=None, on_btw=None, on_gpu1=None,
                 on_ctrl_o=None):
        self.q = queue.Queue()
        self.buf = ""
        self.on_cut_in = on_cut_in
        self.on_btw = on_btw       # called with the text of a "/btw ..." line
        self.on_gpu1 = on_gpu1     # called with the text of a "/gpu1 ..." line typed mid-turn
        self.on_arrow = on_arrow   # called with "up"/"down" when an arrow is pressed on an empty line
        self.on_change = on_change  # called with the buffer after every keystroke (redraws the input line)
        self.on_ctrl_o = on_ctrl_o  # called with the buffer on Ctrl-O: returns the new buffer (@path completion)
        self.enabled = enabled
        self._on = False
        self._saved = None
        self._th = None
        self._fd = None
        self._esc = 0  # 0 none, 1 saw ESC, 2 inside a CSI/SS3 sequence
        self._lock = threading.Lock()  # held across "still on? read one byte" so stop() never strands a key

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        if self._on or not self.enabled or termios is None:
            return False
        try:
            if not sys.stdin.isatty():
                return False
            self._fd = sys.stdin.fileno()
            self._saved = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)  # ICANON and ECHO off, ISIG ON so Ctrl-C still interrupts
        except Exception:
            self._saved = None
            return False
        self._on = True
        self._th = threading.Thread(target=self._run, daemon=True, name="gnoc-typeahead")
        self._th.start()
        return True

    def stop(self):
        """Restore the terminal. Returns the unfinished partial line (never lost: it is pushed back)."""
        if not self._on:
            return ""
        with self._lock:   # the reader is between reads: nothing it took can be dropped after this
            self._on = False
        th = self._th
        if th is not None and th is not threading.current_thread():
            th.join(0.5)   # let it finish feeding the byte it already read, then the buffer is complete
        if self._saved is not None:
            try:
                termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved)
            except Exception:
                pass
            self._saved = None
        partial, self.buf = self.buf, ""
        return partial

    @contextlib.contextmanager
    def paused(self):
        """Hand stdin back for a prompt INSIDE a turn (an approval, a confirm), then take it again. While the
        reader runs it owns every keystroke: the "y" answering an approval went into the type-ahead line and
        input() read the bare Enter as "no" (2026-10-24). The half-typed line survives the pause."""
        if not self._on:
            yield
            return
        keep = self.stop()
        try:
            yield
        finally:
            self.buf = keep
            self.start()

    # ---------------------------------------------------------------- reading
    def _run(self):
        # one byte at a time through an INCREMENTAL decoder: decoding each byte alone turned the first byte of any
        # non-ASCII character (é, ü, …) into "", which read as end-of-input and killed the reader for the turn
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        fd = self._fd
        while self._on:
            # Wait for a key WITHOUT reading it. A reader parked in a blocking os.read() outlived stop() and ate
            # the next key typed at the prompt that followed (the first letter of an approval answer).
            try:
                ready = select.select([fd], [], [], 0.05)[0]
            except Exception:
                return
            if not ready:
                continue
            with self._lock:
                if not self._on:
                    return
                try:
                    b = os.read(fd, 1)
                except Exception:
                    return
            if not b:
                return
            for ch in dec.decode(b):
                self.feed(ch)

    def feed(self, ch):
        """One character in. Separate from _run so a test can drive it without a terminal. Never raises: it runs
        in the reader thread, where an exception ends type-ahead for the rest of the turn."""
        if not isinstance(ch, str) or len(ch) != 1:
            for c in ch if isinstance(ch, str) else ():
                self.feed(c)
            return
        # an arrow key arrives as ESC [ A: dropping only the ESC leaves "[A" in the line, so swallow the
        # whole sequence (CSI/SS3 run until a byte in @..~)
        if self._esc == 1:
            self._esc = 2 if ch in "[O" else 0
            return
        if self._esc == 2:
            if "@" <= ch <= "~":
                self._esc = 0
                # Up/Down with an EMPTY buffer switch which stream you are watching (the main chain or a
                # running sub-agent). Mid-line they stay swallowed, as every arrow key was before.
                if not self.buf and self.on_arrow and ch in ("A", "B"):
                    try:
                        self.on_arrow("up" if ch == "A" else "down")
                    except Exception:
                        pass
            return
        if ch == "\x1b":
            self._esc = 1
            return
        if ch in ("\r", "\n"):
            line = self.buf.strip()
            self.buf = ""
            if line:
                self.push(line)
            return
        if ch in BACKSPACE:
            self.buf = self.buf[:-1]
            return
        if ch == "\x15":          # Ctrl-U clears the line, as in a shell
            self.buf = ""
            return
        if ch == "\x17":          # Ctrl-W deletes the last word
            self.buf = self.buf.rstrip().rsplit(" ", 1)[0] if " " in self.buf.rstrip() else ""
            return
        if ch == "\x0f":          # Ctrl-O: complete the @path under the cursor (the harness owns the paths)
            if self.on_ctrl_o:
                with contextlib.suppress(Exception):
                    self.buf = self.on_ctrl_o(self.buf) or self.buf
            if self.on_change:
                with contextlib.suppress(Exception):
                    self.on_change(self.buf)
            return
        if ch.isprintable():
            self.buf += ch
        if self.on_change:
            with contextlib.suppress(Exception):
                self.on_change(self.buf)   # redraw the input line on the keystroke, not a second later

    def push(self, line, raw=False):
        """Stage a finished line. A '!' prefix cuts into the running turn; a '/btw ' prefix hands it to the
        running turn as a side note; a '/gpu1 ' prefix fires the worker GPU now. None of the three is queued
        as its own turn. raw=True (gnoc chat -p <prompt> boot staging) queues the line as a plain turn:
        none of those prefixes are special there."""
        stripped = line.strip()
        if not raw:
            if stripped.lower().startswith(BTW + " ") or stripped.lower() == BTW:
                note = stripped[len(BTW):].strip()
                if note and self.on_btw:
                    with contextlib.suppress(Exception):
                        self.on_btw(note)
                return
            if stripped.lower().startswith(GPU1 + " "):
                ask = stripped[len(GPU1):].strip()
                if ask and self.on_gpu1:
                    with contextlib.suppress(Exception):
                        self.on_gpu1(ask)
                    return
        cut = (not raw) and line.startswith(CUT_IN)
        text = line[len(CUT_IN):].strip() if cut else line
        if not text:
            return
        self.q.put(text)
        if cut and self.on_cut_in:
            try:
                self.on_cut_in(text)
            except Exception:
                pass

    # ---------------------------------------------------------------- the queue
    def pending(self):
        return self.q.qsize()

    def pop(self):
        try:
            return self.q.get_nowait()
        except queue.Empty:
            return None

    def drain(self):
        out = []
        while True:
            x = self.pop()
            if x is None:
                return out
            out.append(x)

    def hint(self, width=0, text=True):
        """What the status line shows: how many lines are staged, and (when nothing else is showing it)
        the partial line being typed. With the bottom input line on, the text lives there instead."""
        n = self.pending()
        bits = []
        if n:
            bits.append(f"{n} staged")
        if self.buf and text:
            text = self.buf
            if width and len(text) + 12 > width:
                text = "…" + text[-(max(10, width - 13)):]
            bits.append("⏎ " + text)
        return "  ".join(bits)
