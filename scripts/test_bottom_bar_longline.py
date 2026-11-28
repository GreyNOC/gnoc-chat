"""The input line must survive text longer than the window.

Receipt (2026-10-27): "when I enter text and the characters pass the end of the input the cursor
starts from home and starts deleting text."

Cause, measured before the fix at 100 columns with typed=400: BottomBar.paint() rendered 99 columns of
the HEAD of the line and parked the caret at column 100, while readline - which runs in
horizontal-scroll-mode - was showing a window onto the END of the buffer with its own caret. Two writers,
two models, one row. say() repaints after any output and every spinner frame repaints too, so each one
replaced readline's view with the truncated head and moved the caret to the edge; the next keystroke
redrew against a screen that no longer matched, and characters appeared to be deleted from the start.

The buffer was never corrupted - a 425-character line submitted intact - so this was display only, which
is why it never showed up as lost data.

Two properties are pinned here:
  1. paint() HORIZONTAL-SCROLLS: past the window it shows the tail, so the newest text and the caret stay
     visible however long the entry gets.
  2. paint() REFUSES to draw while readline owns the row, so there is only ever one writer.
"""
import io
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gnoc_agent as G  # noqa: E402

COLS, LINES = 100, 24
PROMPT = "\x1b[91m┌─[\x1b[0mgnoc\x1b[91m]\x1b[0m\n\x1b[91m└──╼ \x1b[0m$ "   # 7 visible cols on the last row


def marked(n):
    """n chars where every 10th is its decade digit, so a window's position is identifiable."""
    return "".join(str((i // 10) % 10) if i % 10 == 0 else "x" for i in range(n))


class _Bar(unittest.TestCase):
    def setUp(self):
        self.bar = G.BottomBar()
        self.bar.on = True
        self.bar._size = lambda: (COLS, LINES)
        self.bar.prompt_fn = lambda: PROMPT

    def emit(self, typed):
        buf, real = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            self.bar.paint(typed)
        finally:
            sys.stdout = real
        return buf.getvalue()

    def input_row(self, out):
        """(visible text, caret column) for the last row."""
        plain = re.sub(r"\x1b\[[0-9;]*m", "", out)
        seg = plain.split(f"\x1b[{LINES};1H\x1b[2K")[-1]
        text = seg.split("\x1b[")[0]
        cols = re.findall(rf"\x1b\[{LINES};(\d+)H", plain)
        return text, (int(cols[-1]) if cols else None)


class ShortLine(_Bar):
    def test_a_short_line_is_shown_whole_with_the_caret_after_it(self):
        text, caret = self.input_row(self.emit(marked(20)))
        self.assertTrue(text.endswith(marked(20)), text)
        self.assertEqual(caret, 7 + 20 + 1)


class LongLine(_Bar):
    def test_it_shows_the_TAIL_not_the_head(self):
        typed = marked(400)
        text, _ = self.input_row(self.emit(typed))
        self.assertTrue(text.endswith(typed[-40:]),
                        f"the END of the typed text must be visible; got tail {text[-40:]!r}")
        self.assertNotIn(typed[:30], text, "showing the HEAD is the bug: the caret is not there")

    def test_the_row_never_exceeds_the_window(self):
        for n in (90, 99, 101, 200, 400, 4000):
            text, caret = self.input_row(self.emit(marked(n)))
            self.assertLessEqual(len(text), COLS - 1, f"n={n} overflowed the row")
            self.assertLessEqual(caret, COLS, f"n={n} parked the caret off-screen")

    def test_the_caret_sits_at_the_end_of_what_is_visible(self):
        text, caret = self.input_row(self.emit(marked(400)))
        self.assertEqual(caret, min(COLS, len(text) + 1))

    def test_a_very_narrow_window_still_leaves_room_to_type(self):
        self.bar._size = lambda: (20, LINES)
        text, caret = self.input_row(self.emit(marked(200)))
        self.assertLessEqual(len(text), 19)
        self.assertGreaterEqual(caret, 1)


class ReadlineOwnsTheRow(_Bar):
    def test_paint_refuses_to_draw_while_readline_is_reading(self):
        self.bar.reading = True
        self.assertEqual(self.emit(marked(50)), "", "paint() must not write while readline owns the row")

    def test_it_draws_again_once_reading_ends(self):
        self.bar.reading = True
        self.emit(marked(50))
        self.bar.reading = False
        self.assertNotEqual(self.emit(marked(50)), "")

    def test_rl_refresh_is_a_no_op_when_not_reading(self):
        buf, real = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            self.bar._rl_refresh()
        finally:
            sys.stdout = real
        self.assertEqual(buf.getvalue(), "")

    def test_say_hands_the_row_back_to_readline_mid_edit(self):
        """say() must NOT repaint while reading - that is what corrupted the line."""
        calls = {"paint": 0, "refresh": 0}
        saved = (G.BAR, G.SPIN.on)
        try:
            G.BAR = self.bar
            self.bar.reading = True
            self.bar.paint = lambda *a, **k: calls.__setitem__("paint", calls["paint"] + 1)
            self.bar._rl_refresh = lambda: calls.__setitem__("refresh", calls["refresh"] + 1)
            self.bar.to_scroll = lambda: None
            buf, real = io.StringIO(), sys.stdout
            sys.stdout = buf
            try:
                G.say("some output arriving while you type")
            finally:
                sys.stdout = real
        finally:
            G.BAR, G.SPIN.on = saved
        self.assertEqual(calls["paint"], 0, "repainting mid-edit is the defect")
        self.assertEqual(calls["refresh"], 1, "readline must be asked to redisplay instead")


if __name__ == "__main__":
    unittest.main()
