"""Terminal output: the spinner, the bottom input bar, sub-agent focus, thought blocks, diffs and result panels, tty handling."""
from gnoc_core.terms import OWL_BREATH_S
import os
import threading
from .runtime import bind


class Spinner:
    """The live status line while a model thinks or tools run. One line, redrawn in place, cleared before anything
    else prints (say() does that), so output never interleaves with it. It shows, left to right:
        the owl's eyes (_owl): glowing and looking around while it thinks, scanning while tools run,
        shut while it waits, red when it stalls
        the label with a light sweeping through it - the only bright word; model@gpu and step recede into dim
        elapsed, tokens, a sparkline of the last few seconds' throughput, and the live rate
        the model's own reasoning streams after a ⎿ rule, the same marker that opens its full block
    The ticker is the honest indicator: it is the model's actual thoughts, not an animation. thought() also
    accumulates the full stream, and _show_thoughts_block() prints it once per step as a persistent block
    above the answer or the labelled tool actions."""
    STALL_S = 25
    BREATH_S = OWL_BREATH_S

    def __init__(self):
        self.label, self.t0, self.on, self.th = "", 0.0, False, None
        self.who, self.step, self.kind = "", "", "think"
        self._thought, self._thought_t, self._toks = "", 0.0, (0, 0.0)
        self._token_t = 0.0   # when the live token count last MOVED (not when it was last sampled)
        self._full = ""   # the whole reasoning of the current phase, for the persistent block (take_thoughts)
        self._rates = []   # one tok/s sample a second, newest last, for the sparkline
        self._bar = False  # True while an answer streams: the indicator lives in the input bar, not the scroll area
        # hidden unless GreyNOC turns it on (/thoughts on): the model still reasons, only the display is off
        # (GreyNOC 2026-11-22: "can you make it hide the thoughts on default")
        self.show_thoughts = bool(__import__("os").environ.get("GNOC_SHOW_THOUGHTS"))
        self._gen = 0

    def start(self, label="Thinking", who="", step="", kind=None):
        (
            MON, sys, threading, time,
        ) = bind(
            "MON", "sys", "threading", "time",
        )
        now = time.time()
        self.label, self.t0, self.who, self.step = label, now, who, step
        self.kind = kind or ("tool" if label.startswith(("Running", "Building", "Planning")) else
                             "wait" if "waiting" in label.lower() else "think")
        try:
            toks = MON.live_tokens()
        except Exception:
            toks = 0
        self._thought, self._thought_t, self._toks = "", now, (toks, now)
        self._token_t, self._last_rate, self._rates = now, 0.0, []
        if self._bar:
            self._bar_off()
        if self.on or not sys.stdout.isatty():
            return
        self.on = True
        self._gen += 1
        self.th = threading.Thread(target=self._run, args=(self._gen,), daemon=True)
        self.th.start()

    def streaming(self, label="Writing"):
        """The answer has started streaming. Its raw text owns the scroll area, so the status line cannot stay
        there - but a long answer (or a runaway one) with NO indicator left the user unable to tell what was going
        on (2026-11-18: "make sure the indicator is present to let me know whats up"). It moves to the input bar's
        top row, drawn with the cursor saved and restored, so the streaming text is never disturbed. Elapsed time
        and the token counter carry on from the step."""
        (
            BAR, sys, threading,
        ) = bind(
            "BAR", "sys", "threading",
        )
        self.stop()
        if not (BAR.on and sys.stdout.isatty()):
            return
        self.label, self.kind, self._bar, self.on = label, "write", True, True
        self._gen += 1
        self.th = threading.Thread(target=self._run, args=(self._gen,), daemon=True)
        self.th.start()

    def _bar_status(self, i):
        """The compact indicator for the input bar: eyes, label, elapsed, tokens, rate."""
        (
            MON, T, _owl, dim, time,
        ) = bind(
            "MON", "T", "_owl", "dim", "time",
        )
        now = time.time()
        rate, toks = self._rate()
        quiet = now - max(self._thought_t, self._token_t)
        stalled = quiet > self.STALL_S
        bits = [f"{now - self.t0:.0f}s"]
        if toks:
            bits.append("↓ " + MON.fmt_n(toks))
        if rate >= 1 and not stalled:
            bits.append(f"{rate:.0f} tok/s")
        tail = T.red(f"  stalled {quiet:.0f}s") if stalled else ""
        return _owl(self.kind, now - self.t0, i, stalled) + T.white(self.label) + dim("  " + " · ".join(bits)) + tail

    def _bar_off(self):
        (
            BAR, TYPED, contextlib,
        ) = bind(
            "BAR", "TYPED", "contextlib",
        )
        self._bar = False
        if BAR.status:
            BAR.status = ""
            with contextlib.suppress(Exception):
                BAR.paint(TYPED.buf, park=False)

    def thought(self, text):
        """Feed a reasoning delta from the model; the ticker shows the tail of the current sentence."""
        (
            THOUGHT_FULL_MAX, re, time,
        ) = bind(
            "THOUGHT_FULL_MAX", "re", "time",
        )
        if not text:
            return
        t = (self._thought + text).replace("\n", " ")
        t = re.sub(r"\s+", " ", t)
        # keep the tail: the end of the last sentence boundary when the buffer is long
        if len(t) > 240:
            cut = max(t.rfind(". ", 0, len(t) - 60), t.rfind("; ", 0, len(t) - 60))
            t = t[cut + 2:] if cut > 0 else t[-200:]
        self._thought, self._thought_t = t, time.time()
        self._full = (self._full + str(text))[-THOUGHT_FULL_MAX:]

    def reset_thoughts(self):
        """Drop the accumulated reasoning: a new step starts its own persistent block."""
        self._full = ""

    def take_thoughts(self):
        """The whole reasoning streamed since the last take/reset, and clear it. The ticker keeps its own tail."""
        full, self._full = self._full, ""
        return full

    def _rate(self):
        (
            MON, time,
        ) = bind(
            "MON", "time",
        )
        toks, now = MON.live_tokens(), time.time()
        t0, at = self._toks
        if toks != t0:
            self._token_t = now
        if now - at >= 1.0:
            self._toks = (toks, now)
            raw, prev = (toks - t0) / (now - at), getattr(self, "_last_rate", 0.0)
            # A finishing sub-agent ticks its whole count into the same live counter in one lump ("407 tok/s"
            # between runs of 12): a sample far above the recent rate is a lump, not throughput, so skip it.
            # Otherwise an EMA, so the number follows the lead's own stream without jitter.
            # No baseline yet: take the sample (a filter here dropped the FIRST sample of any stream faster
            # than 200 tok/s, so a steady 260 showed 0 forever - review 2026-10-22). With a baseline, a
            # sample far above it is a lump, not throughput.
            if prev <= 0:
                self._last_rate = raw
            elif raw <= 8 * max(prev, 25.0):
                self._last_rate = 0.5 * prev + 0.5 * raw
            self._rates = (self._rates + [self._last_rate])[-12:]
        return getattr(self, "_last_rate", 0.0), toks

    def _run(self, gen=0):
        # gen: stop() then start() inside one 0.1 s sleep used to leave the OLD thread alive next to the new
        # one (both saw self.on True), two writers drawing alternate frames. Each thread now owns a generation.
        (
            BAR, MON, TYPED, _print_lock, contextlib, shutil, time,
        ) = bind(
            "BAR", "MON", "TYPED", "_print_lock", "contextlib", "shutil", "time",
        )
        i, note, note_t = 0, "", 0.0
        width = shutil.get_terminal_size((100, 24)).columns
        while self.on and self._gen == gen:
            # the WIDTH every frame (one ioctl): read once a second, a restore drew up to a second of frames
            # at the old width, they wrapped, and "\r\x1b[2K" cleared only the last wrapped row (2026-10-22)
            width = shutil.get_terminal_size((100, 24)).columns
            if time.time() - note_t > 1.0:  # the registry is on disk: read it once a second, not every frame
                try:
                    note = MON.spinner_note()
                except Exception:
                    note = ""
                if not self._bar:   # in bar mode a parking repaint would pull the streaming text onto the bar
                    with contextlib.suppress(Exception):   # the input line stays live while it works
                        BAR.paint(TYPED.buf)
                note_t = time.time()
                width = shutil.get_terminal_size((100, 24)).columns
            with _print_lock:
                if self.on and self._gen == gen:
                    try:
                        self._draw(i, note, width)
                    except Exception:  # one bad frame must not kill the thread while self.on stays True
                        pass
                else:
                    # Prevent indicator from disappearing prematurely
                    if not self.on:
                        # Keep spinner alive for a grace period after replies
                        time.sleep(0.05)
            i += 1
            time.sleep(0.1)

    @staticmethod
    def _tail_cols(text, cols):
        """The longest end of text that fits in cols printable columns, without splitting a wide glyph."""
        (
            _char_cols,
        ) = bind(
            "_char_cols",
        )
        used, i = 0, len(text)
        while i > 0:
            w = _char_cols(text[i - 1])
            if used + w > cols:
                break
            used += w
            i -= 1
        return text[i:]

    @classmethod
    def _ticker_text(cls, text, room):
        """The newest end of the reasoning that fits room columns, beginning at a word when possible."""
        tail = cls._tail_cols(text, max(0, room - 1))
        if len(tail) >= len(text):
            return tail
        cut = tail.find(" ")
        if 0 < cut <= 10:
            tail = tail[cut + 1:]
        return "…" + tail.lstrip()

    def _compose(self, i, note, width):
        """One frame's text, before any terminal I/O (kept separate so the layout can be inspected)."""
        (
            BAR, MON, T, TYPED, _owl, _shine, _sparkline, _text_cols, dim, time,
        ) = bind(
            "BAR", "MON", "T", "TYPED", "_owl", "_shine", "_sparkline", "_text_cols", "dim", "time",
        )
        now = time.time()
        rate, toks = self._rate()
        el = now - self.t0
        quiet = now - max(self._thought_t, self._token_t)
        stalled = self.kind == "think" and quiet > self.STALL_S

        # The eyes carry the phase; only a stall turns them red, so red still means something.
        owl = _owl(self.kind, el, i, stalled)
        base = "  " + owl + (T.white(self.label) if stalled else _shine(self.label, i, self.kind != "wait"))
        who = dim(" · " + self.who) if self.who else ""
        step = dim(" · step " + self.step) if self.step else ""

        # Stats shed their least useful field before the line drops a word, so a narrow terminal never
        # ends on a half-written number. Layouts stay in priority order: context first, then throughput,
        # then just elapsed time. The row that fits wins.
        elapsed = f"{el:.0f}s"
        short = elapsed + (f" · ↓ {MON.fmt_n(toks)}" if toks else "")
        full = short + (f" · {rate:.0f} tok/s" if toks and rate >= 1 else "")
        spark = _sparkline(self._rates) if toks and rate >= 1 else ""
        flash = short + f" · {spark}{rate:.0f} tok/s" if spark else full
        stat_opts = []
        for opt in (flash, full, short, elapsed):
            if opt not in stat_opts:
                stat_opts.append(opt)

        layouts = []
        if who and step:
            layouts += [who + step + dim("   " + st) for st in stat_opts[:2]]
        if who:
            layouts += [who + dim("   " + st) for st in stat_opts]
        if step:
            layouts += [step + dim("   " + st) for st in stat_opts]
        layouts += [dim("   " + st) for st in stat_opts]

        alert = ""
        if stalled:
            alert += T.red(f"   stalled {quiet:.0f}s") + dim(" · check gnoc gpus")
        if note:
            pre, mark, post = note.partition("⚠")
            alert += (dim(pre) + T.yellow("⚠ " + post.strip())) if mark else dim(note)

        head = next((base + lo + alert for lo in layouts
                     if _text_cols(base + lo + alert) <= width - 1), base + alert)

        line = head
        # only the COUNT staged behind this turn: the text itself is on the input line, and showing it
        # in both places was the duplicate GreyNOC reported (2026-10-22)
        typed = TYPED.hint(width, text=not BAR.on)
        if typed:
            line += "   " + T.blue(typed)
        elif self.show_thoughts and self._thought and self.kind == "think" and not stalled:
            # The live tail gets whatever room is left, but never a three-word sliver. It opens with the
            # same ⎿ as the persistent reasoning block, so the one-line ticker reads as its preview.
            room = width - _text_cols(head) - 8
            if room >= 16:
                line += dim("   ⎿  " + self._ticker_text(self._thought, room))
        elif self.kind != "think":
            # A shortcut hint is useful, but never at the price of a word cut in half at the edge.
            hint = "   ctrl-c to interrupt"
            if _text_cols(line + dim(hint)) <= width - 1:
                line += dim(hint)
            elif _text_cols(line + dim("   ctrl-c")) <= width - 1:
                line += dim("   ctrl-c")
        return line

    def _draw(self, i, note, width):
        """One frame. Called with _print_lock held."""
        (
            BAR, TYPED, _fit_width, sys,
        ) = bind(
            "BAR", "TYPED", "_fit_width", "sys",
        )
        if self._bar:
            BAR.status = self._bar_status(i)
            BAR.paint(TYPED.buf, park=False)   # cursor saved and restored: the answer keeps streaming where it was
            return
        line = self._compose(i, note, width)
        # A line that wraps by even one column defeats "\r\x1b[2K" (it clears only the last visual row) and
        # every 0.1 s frame then stacks a new copy down the screen. to_scroll() first: this writes AT THE
        # CURSOR, and the input line owns the cursor now, so without it the status line is painted over what
        # you are typing (GreyNOC 2026-10-22, "jargled").
        BAR.to_scroll()
        sys.stdout.write("\r\x1b[2K" + _fit_width(line, width - 1))
        sys.stdout.flush()
        BAR.paint(TYPED.buf)   # caret back to the input line

    def clear(self):
        (
            BAR, sys,
        ) = bind(
            "BAR", "sys",
        )
        if self._bar:
            return             # nothing of ours is in the scroll area: that row is the answer being written
        if sys.stdout.isatty():
            BAR.to_scroll()    # same reason: never erase the input line
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()

    def stop(self):
        (
            _print_lock,
        ) = bind(
            "_print_lock",
        )
        if not self.on:
            return
        self.on = False
        with _print_lock:
            if self._bar:
                self._bar_off()
            else:
                self.clear()


# Side notes handed to the turn that is ALREADY running (see gnoc_typeahead.BTW). Drained before each model
# step, so "btw the account is B" reaches the work in flight instead of waiting for the next turn.
_BTW = []


_BTW_LOCK = threading.Lock()


def _btw(text):
    """A '/btw ...' line typed mid-turn: queue it for the running turn's next step."""
    (
        T, _BTW, _BTW_LOCK, dim, say, white,
    ) = bind(
        "T", "_BTW", "_BTW_LOCK", "dim", "say", "white",
    )
    with _BTW_LOCK:
        _BTW.append(str(text or "").strip())
    say("\n" + T.bblue("  btw: ") + white(str(text)[:160]) + dim("  (the running turn reads it at its next step)"))


def take_btw():
    """Pop every pending side note, as one user message, or None."""
    (
        _BTW, _BTW_LOCK,
    ) = bind(
        "_BTW", "_BTW_LOCK",
    )
    with _BTW_LOCK:
        notes, _BTW[:] = list(_BTW), []
    notes = [n for n in notes if n]
    if not notes:
        return None
    return {"role": "user", "content": "The user added mid-turn, while you were working"
            + (" (take it into account from here on; it does not cancel what the user asked):\n- " if len(notes) == 1
               else " (take them into account from here on; they do not cancel what the user asked):\n- ")
            + "\n- ".join(notes)}


def _cut_in(text):
    """A '!' line typed mid-turn: stop what the model is doing now, the text runs next."""
    (
        INTERRUPT, T, TYPED, say, white,
    ) = bind(
        "INTERRUPT", "T", "TYPED", "say", "white",
    )
    INTERRUPT.set()
    TYPED.cutting = True
    say("\n" + T.bred("  ⎋ cutting in: ") + white(text[:120]))   # own line: it landed on a half-streamed row


class SubAgentFocus:
    """Which stream the terminal is watching: the main chain, or one running sub-agent.

    The sub-agent's steps are already being appended to a log on disk by gnoc_monitor, so following
    one is just tailing that file and printing what is new. Attaching prints the recent history
    first, so you see what it has been doing, not only what it does next."""

    POLL_S = 0.4
    HISTORY = 12

    def __init__(self):
        self.sid = None
        self._seen = 0
        self._th = None
        self._on = False
        # a follower thread runs only while its generation is current: re-attaching to the SAME sub-agent kept
        # the old thread alive (same sid, _on True again), so every Down added a poller (QAQC 2026-11-19)
        self._gen = 0

    def watching(self):
        return self.sid

    def _rows(self):
        (
            MON,
        ) = bind(
            "MON",
        )
        return MON.running()

    def next_agent(self):
        """Down: the first running sub-agent, or the one after the current (so Down cycles through them)."""
        rows = self._rows()
        if not rows:
            return None
        ids = [r["id"] for r in rows]
        if self.sid not in ids:
            return rows[0]
        return rows[(ids.index(self.sid) + 1) % len(ids)]

    def arrow(self, direction):
        """Silent when there is nothing to do.

        An arrow pressed at the PROMPT sits in the tty buffer and is read the moment a turn starts and
        typeahead takes stdin, so a chatty handler printed "no sub-agent is running" three times for
        keys pressed before the turn even began (reported 2026-10-22). The status line already says
        "(↓ watch)" only when there IS one to watch, so saying nothing here is the honest default."""
        if direction == "down":
            r = self.next_agent()
            if r:
                self.attach(r)
        elif self.sid:
            self.detach("back to the main chain")

    def attach(self, r):
        (
            MON, T, dim, say, threading,
        ) = bind(
            "MON", "T", "dim", "say", "threading",
        )
        self.detach(None)
        self.sid = r["id"]
        _, lines = MON.tail(self.sid, self.HISTORY)
        self._seen = len(MON.tail(self.sid, 10000)[1])
        head = f"↓ watching {r['id']}"
        for k in ("kind", "model", "task"):
            if r.get(k):
                head += f" · {r[k]}" if k != "task" else f" · {str(r[k])[:60]}"
        say(T.blue("● ") + T.white(head) + dim("   ↑ back to the main chain"))
        for ln in lines:
            say(dim("  │ " + ln[:200]))
        self._on = True
        self._gen += 1
        self._th = threading.Thread(target=self._follow, args=(self._gen,), daemon=True)
        self._th.start()

    def detach(self, note="back to the main chain"):
        (
            T, dim, say,
        ) = bind(
            "T", "dim", "say",
        )
        self._on = False
        self._gen += 1
        if self.sid and note:
            say(T.blue("● ") + dim(f"↑ {note} (was watching {self.sid})"))
        self.sid = None

    def _follow(self, gen=None):
        (
            MON, T, dim, say, time,
        ) = bind(
            "MON", "T", "dim", "say", "time",
        )
        sid = self.sid
        gen = self._gen if gen is None else gen
        while self._on and self.sid == sid and self._gen == gen:
            try:
                r, lines = MON.tail(sid, 10000)
                if r is None:
                    break
                if len(lines) > self._seen:
                    for ln in lines[self._seen:]:
                        say(dim("  │ " + ln[:200]))
                    self._seen = len(lines)
                if r.get("status") and r["status"] != "running":
                    say(T.blue("● ") + dim(f"{sid} finished ({r['status']}); back to the main chain"))
                    self.sid = None
                    break
            except Exception:
                break
            time.sleep(self.POLL_S)


# Ctrl-O at the PROMPT submits the line with this marker appended; the REPL sees it, asks for a file, and
# attaches it as an @path mention. In the TYPEAHEAD it completes the @path under the cursor directly.
FILE_MARKER = "@@FILE@@"


def _typeahead_ctrl_o(buf):
    """Ctrl-O while typing mid-turn: complete the @path under the cursor, or start one. The staged line
    goes through the same @-mention expansion as a prompt-line message, so the file content rides along."""
    (
        _mention_paths,
    ) = bind(
        "_mention_paths",
    )
    if not buf:
        return "@"
    # Only the LAST word is completed, and only when it is an @mention: completing the last word but splicing
    # it in after the last '@' anywhere threw away everything typed after an earlier mention
    # ("fix @a.py then run t" became "fix @tests/", QAQC 2026-11-19).
    head, sp, last = buf.rpartition(" ")
    if not last.startswith("@"):
        return buf + ("@" if buf.endswith(" ") else " @")
    hits = _mention_paths(last[1:])
    return (head + sp + "@" + hits[0]) if hits else buf


def _file_marker(line):
    """The text before a Ctrl-O marker, or None when the line does not carry one."""
    (
        FILE_MARKER,
    ) = bind(
        "FILE_MARKER",
    )
    if line and line.endswith(FILE_MARKER):
        return line[:-len(FILE_MARKER)].rstrip()
    return None


def say(*a, **k):
    (
        BAR, SPIN, TYPED, _print_lock, contextlib,
    ) = bind(
        "BAR", "SPIN", "TYPED", "_print_lock", "contextlib",
    )
    with _print_lock:
        if SPIN.on:
            SPIN.clear()
        BAR.to_scroll()          # output belongs above the input line, never on it
        print(*a, **k, flush=True)
        if k.get("file") is None:
            with contextlib.suppress(Exception):
                BAR.record(str(k.get("sep", " ")).join(str(x) for x in a) + str(k.get("end", "\n")))
        with contextlib.suppress(Exception):
            if BAR.reading:
                # mid-edit: readline owns the row, so IT redraws (prompt, its scrolled view, its caret).
                # Repainting here is what corrupted a long line, because this class and readline drew
                # two different views of the same row.
                BAR._rl_refresh()
            else:
                BAR.paint(TYPED.buf)  # and the caret goes straight back to where you are typing


# A turn longer than this ends with a terminal bell and (when notify-send exists) a desktop notification,
# so a long hunt or build never needs babysitting. GNOC_TURN_ALERT_SECS=0 disables the bell; GNOC_NOTIFY=0
# disables only the desktop part.
TURN_ALERT_SECS = float(os.environ.get("GNOC_TURN_ALERT_SECS", "60") or 0)


THOUGHT_FULL_MAX = 24000


def _show_thoughts_block():
    """The persistent reasoning block: the full thinking the model streamed since the last block, printed
    once per step, above the answer or the labelled tool actions it leads to (the status-line ticker is
    only the live tail; this is the record). /raw and /thoughts turn it off with the ticker; off the TTY
    it stays quiet so scripted output is unchanged."""
    (
        SPIN, THOUGHT_BLOCK_CHARS, _fit_width, _owl_static, _term_cols, dim, hang, re, say, sys, white,
    ) = bind(
        "SPIN", "THOUGHT_BLOCK_CHARS", "_fit_width", "_owl_static", "_term_cols", "dim", "hang", "re", "say",
        "sys", "white",
    )
    if not SPIN.show_thoughts or not sys.stdout.isatty():
        SPIN.reset_thoughts()
        return
    full = SPIN.take_thoughts()
    text = re.sub(r"\s+", " ", str(full or "")).strip()
    if not text:
        return
    note = ""
    if THOUGHT_BLOCK_CHARS and len(text) > THOUGHT_BLOCK_CHARS:
        cut = text[:THOUGHT_BLOCK_CHARS].rsplit(" ", 1)[0].rstrip()
        note = f"… (+{len(text) - len(cut)} more chars of reasoning not shown)"
        text = cut
    head = dim("  ⎿  ") + _owl_static() + dim(" thinking")
    if SPIN.who:
        head += dim(" · ") + white(SPIN.who)
    if SPIN.step:
        head += dim(" · step ") + SPIN.step
    say(head)
    for row in hang("    " + text, indent=4).split("\n"):
        say(_fit_width(dim(row), _term_cols() - 1))
    if note:
        say(_fit_width(dim("    " + note), _term_cols() - 1))


def _turn_done_alert(secs, answer):
    """Ring for a finished long turn. Everything is guarded: a missing bell, a missing notify-send or a
    dead notification daemon can never fail the turn it announces."""
    (
        TURN_ALERT_SECS, contextlib, os, shutil, subprocess, sys,
    ) = bind(
        "TURN_ALERT_SECS", "contextlib", "os", "shutil", "subprocess", "sys",
    )
    if TURN_ALERT_SECS <= 0 or secs < TURN_ALERT_SECS:
        return
    head = " ".join(str(answer or "").split())[:80]
    if sys.stdout.isatty():
        with contextlib.suppress(Exception):
            sys.stdout.write("\a")
            sys.stdout.flush()
    if os.environ.get("GNOC_NOTIFY", "1") == "0":
        return
    with contextlib.suppress(Exception):
        if shutil.which("notify-send"):
            subprocess.Popen(["notify-send", "-a", "gnoc chat", f"turn done · {secs:.0f}s",
                              head or "answer ready"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def show_result(prefix, name, args, res, announced=False):
    """'● tool(args)' with a green or red dot, then '⎿' and a one-line summary; edits show their diff.
    announced=True: run_tools already printed the action row when the tool STARTED, so only the result
    row is printed under it (the running label stays visible for the whole call)."""
    (
        T, _FAIL, _brief, _fit_width, _row_text, _term_cols, _text_cols, dim, green, re, red, say, show_diff,
    ) = bind(
        "T", "_FAIL", "_brief", "_fit_width", "_row_text", "_term_cols", "_text_cols", "dim", "green", "re", "red",
        "say", "show_diff",
    )
    lines = res.splitlines() or [""]
    bad = bool(_FAIL.match(lines[0])) or bool(re.match(r"exit [1-9]", lines[0]))
    say("")   # one blank line between actions: a long turn was an unreadable wall of ●/⎿ pairs (GreyNOC)
    # Each row is cut to the WINDOW, not to a fixed count: a 110-character summary behind a 6-column prefix
    # wrapped at 120 columns and left a single letter alone on the next row (2026-10-24). Both rows are measured
    # with the same width rule the cut uses and made one-row-safe first (tabs expanded, cursor codes dropped),
    # and each is cut to width-1 as a last guard, so neither can ever reach the right margin.
    cols = _term_cols() - 1
    if not announced:
        say(_fit_width(_row_text(prefix + (red("● ") if bad else green("● ")) + T.bblue(name)
                                 + dim(f"({_brief(args)})")), cols))
    more = dim(f"  (+{len(lines) - 1} lines)") if len(lines) > 1 and name not in ("edit_file", "write_file") else ""
    head = prefix + dim("  ⎿  ")
    hw = _text_cols(head)
    room = max(20, cols - hw - _text_cols(more))
    first = _row_text(lines[0], hw)
    if _text_cols(first) > room:
        first = _fit_width(first, room - 1) + "…"
    say(_fit_width(head + (red(first) if bad else first) + more, cols))
    if name in ("edit_file", "write_file") and not bad:
        show_diff(prefix + "     ", lines[1:])
    if not bad and (name == "write_file" and lines[0].startswith("created ")
                    or name == "generate_image" and lines[0].startswith(("image saved:", "image edited:"))):
        # the file is his to keep: say how, once under it (GreyNOC: "give me the html file in the chat so I can
        # choose where to save", 2026-11-23)
        say(_fit_width(prefix + dim("     /save keeps a copy where you choose · /open views it · /files lists "
                                    "this chat's files"), cols))


DIFF_SHOW = 24


def diff_panel(panes, start=0):
    """Show diffs full screen until the operator closes it. `panes` is [(label, rows, adds, dels)].

    The alternate screen buffer means nothing of the chat is overdrawn: on exit the terminal puts the
    transcript back exactly as it was, so this cannot damage a conversation in progress."""
    (
        BAR, T, TYPED, _fit_cols, _print_lock, _read_key, _vis_len, contextlib, dim, green, red, say, show_diff,
        shutil, sys, termios, tty,
    ) = bind(
        "BAR", "T", "TYPED", "_fit_cols", "_print_lock", "_read_key", "_vis_len", "contextlib", "dim", "green",
        "red", "say", "show_diff", "shutil", "sys", "termios", "tty",
    )
    panes = [p for p in panes if p[1]]
    if not panes:
        return "no changes to show"
    if not (sys.stdout.isatty() and sys.stdin.isatty()):
        for label, rows, adds, dels in panes:          # not a terminal: fall back to printing them
            say(f"  {T.byellow(label)} " + green(f"+{adds}") + " " + red(f"-{dels}"))
            show_diff("    ", rows)
        return ""

    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    i, top = max(0, min(start, len(panes) - 1)), 0

    def draw():
        cols, lines = shutil.get_terminal_size((100, 24))
        label, rows, adds, dels = panes[i]
        body_h = max(1, lines - 2)                      # one header row, one footer row
        view = rows[top:top + body_h]
        counts = green(f"+{adds}") + " " + red(f"-{dels}")
        where = f"  {i + 1}/{len(panes)}" if len(panes) > 1 else ""
        left = " " + T.byellow(label) + " " + counts + dim(where)
        # x hard against the right edge: the close button he asked for
        pad = max(1, cols - _vis_len(left) - 3)
        head = left + " " * pad + T.bred("x") + " "
        out = ["\x1b[H\x1b[2J", _fit_cols(head, cols), "\x1b[0m\r\n"]
        for r in view:
            out.append(_fit_cols(T.diff_line(r), cols) + "\x1b[0m\r\n")
        for _ in range(body_h - len(view)):
            out.append("\r\n")
        more = f"  {top + len(view)}/{len(rows)}"
        foot = dim("  ↑↓ scroll · PgUp/PgDn · g/G ends" + ("  · n/p file" if len(panes) > 1 else "")
                   + "  · x close" + more)
        out.append("\x1b[" + str(lines) + ";1H" + _fit_cols(foot, cols) + "\x1b[0m")
        with _print_lock:
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    with _print_lock:
        sys.stdout.write("\x1b[?1049h\x1b[r\x1b[?25l")   # alt screen, full region, hide the caret
        sys.stdout.flush()
    try:
        tty.setcbreak(fd)
        while True:
            draw()
            cols, lines = shutil.get_terminal_size((100, 24))
            page = max(1, lines - 4)
            rows = panes[i][1]
            k = _read_key(fd)
            if k in ("x", "q", "quit"):
                return ""
            if k == "up":
                top = max(0, top - 1)
            elif k == "down":
                top = min(max(0, len(rows) - 1), top + 1)
            elif k in ("k",):
                top = max(0, top - 1)
            elif k in ("j",):
                top = min(max(0, len(rows) - 1), top + 1)
            elif k == "pgup":
                top = max(0, top - page)
            elif k == "pgdn":
                top = min(max(0, len(rows) - 1), top + page)
            elif k == "g":
                top = 0
            elif k == "G":
                top = max(0, len(rows) - page)
            elif k == "n" and len(panes) > 1:
                i, top = (i + 1) % len(panes), 0
            elif k == "p" and len(panes) > 1:
                i, top = (i - 1) % len(panes), 0
            elif k == "enter":
                return ""
    except (OSError, termios.error) as e:
        return f"  diff panel unavailable ({type(e).__name__}); /diff short prints them instead"
    finally:
        with contextlib.suppress(Exception):
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        with _print_lock:
            sys.stdout.write("\x1b[?25h\x1b[?1049l")      # caret back, main screen back
            sys.stdout.flush()
        with contextlib.suppress(Exception):
            BAR.rearm()                                   # the panel's \x1b[r reset the scroll region
            BAR.paint(TYPED.buf)


def show_diff(indent, rows):
    """Render numbered diff rows: line numbers, red removed, green added, dim context."""
    (
        DIFF_SHOW, T, dim, say,
    ) = bind(
        "DIFF_SHOW", "T", "dim", "say",
    )
    for r in rows[:DIFF_SHOW]:
        say(indent + T.diff_line(r))
    if len(rows) > DIFF_SHOW:
        say(indent + dim(f"   ⋯ {len(rows) - DIFF_SHOW} more diff lines"))


def echo_prompt(prompt_text, line):
    """How a SUBMITTED line is written into the transcript: the prompt's LAST row plus the text.

    One implementation for both paths. The typed path had it right and the staged one (typeahead, and
    gnoc chat -p) concatenated the raw prompt instead, so it printed readline's \001..\002 width markers
    as control characters and repeated the whole two-row ┌─[gnoc] box - the chrome-doubling already fixed
    for the typed echo on 2026-10-24. Measured in a pty 2026-11-03: the raw concatenation carried 22
    \001 + 22 \002 over 2 rows; this returns 0 over 1."""
    (
        _strip_rl,
    ) = bind(
        "_strip_rl",
    )
    return _strip_rl(prompt_text).split("\n")[-1] + (line or "")


class BottomBar:
    """The input line pinned to the last rows of the terminal. No box: just the prompt and your text.

    ROWS rows are reserved (the prompt is two lines). Printing scrolls only the rows above them, so the
    input line survives a streaming answer, a tool result, or a worker's output arriving mid-sentence."""

    ROWS = 2

    def __init__(self):
        self.on = False
        self.rows = 0
        self._text = ""
        self.reading = False    # True while readline owns the input rows: paint() must not draw on them
        self.status = ""        # the live indicator while an answer streams (Spinner.streaming), right of the prompt
        self.prompt_fn = None   # set by repl(): returns the same prompt string readline draws
        # The last lines printed above the bar, kept so a resize can put them BACK (see _repaint_tail). The
        # terminal is not a safe place to keep the conversation: one that is minimized to a row or two pushes
        # every line into its scrollback, and many do not bring them back when the window returns.
        self._tail = __import__("collections").deque(maxlen=600)
        self._part = ""         # the line being printed now (a streaming answer has no newline yet)
        self._cols = 0          # the width the bar was last drawn for
        self._was_tiny = False  # a minimized (degenerate) size was seen since the last real one

    _NOT_TEXT = __import__("re").compile(r"\x1b\[[0-9;?]*[A-LN-Za-ln-z@`]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\\\)|\x1b[78=>]")

    def record(self, text):
        """Remember what was just printed above the bar: whole lines into _tail, the unfinished one in _part.
        Colours are kept (SGR); cursor moves, clears and title sequences are not conversation. A carriage
        return restarts the line, as it does on the screen."""
        if not text or not self.on:
            return
        s = self._part + self._NOT_TEXT.sub("", str(text))
        parts = s.split("\n")
        for ln in parts[:-1]:
            self._tail.append(ln.rsplit("\r", 1)[-1])
        self._part = parts[-1].rsplit("\r", 1)[-1]

    def _repaint_tail(self, cols, lines):
        """Draw the end of the conversation back into the rows above the bar, the unfinished line last.

        The user, 2026-11-21: "an issue during window minimizing and maximizing. doing either deletes the chat
        window". Their terminal reports a 1x1 window while minimized (test_minimize_then_restore_leaves_no_ghost_bar,
        from their 2026-10-22 report) and leaves the text at the top when the window grows. Shrunk to one row, such
        a terminal scrolls the whole conversation into its scrollback; grown again, it shows blank rows. No program
        can pull lines back out of a terminal's scrollback, so the bar holds its own copy and repaints.
        On a terminal that did keep the text (Konsole, VTE, tmux pull it back down) this rewrites the same
        lines in the same rows."""
        (
            _fit_cols, _print_lock, _vis_len, sys,
        ) = bind(
            "_fit_cols", "_print_lock", "_vis_len", "sys",
        )
        k = lines - self.rows                      # rows above the bar; the last of them is the line in progress
        if k < 2 or lines < self._MIN_LINES or cols < self._MIN_COLS:
            return
        body = list(self._tail)[-(k - 1):]
        out = []
        first = k - len(body)                      # bottom-aligned: the newest line sits just above the last row
        for r in range(1, k):
            i = r - first
            out.append(f"\x1b[{r};1H\x1b[2K" + (_fit_cols(body[i], cols - 1) + "\x1b[0m" if 0 <= i < len(body) else ""))
        part = _fit_cols(self._part, cols - 1) if self._part else ""
        out.append(f"\x1b[{k};1H\x1b[2K" + part)
        out.append(f"\x1b[{k};{min(cols, _vis_len(part) + 1)}H")   # where the next character of output goes
        with _print_lock:
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def _size(self):
        """The LIVE window size, read from the terminal itself. shutil.get_terminal_size() prefers the
        COLUMNS/LINES environment variables and falls back silently to a default when the ioctl fails -
        either way a resize handler can get a size that is not the window's, and then draws the input
        line on the wrong rows. The fd is the authority; shutil is only the last resort."""
        (
            os, shutil, sys,
        ) = bind(
            "os", "shutil", "sys",
        )
        try:
            first = sys.stdout.fileno()   # INSIDE a try: a redirected stdout (StringIO) raises right here
        except (OSError, ValueError, AttributeError):
            first = 1
        for fd in (first, 1, 0):
            try:
                sz = os.get_terminal_size(fd)
                # 0 means UNKNOWN (an unsized pty), not a zero-row window: fall back for that dimension only
                return (sz.columns or 100), (sz.lines or 24)
            except (OSError, ValueError):
                continue
        sz = shutil.get_terminal_size((100, 24))
        return sz.columns, sz.lines

    def enable(self):
        """Reserve the bottom rows. A no-op off a terminal, or when the window is too short to spare them."""
        (
            _print_lock, contextlib, signal, sys,
        ) = bind(
            "_print_lock", "contextlib", "signal", "sys",
        )
        if self.on or not (sys.stdout.isatty() and sys.stdin.isatty()):
            return False
        cols, lines = self._size()
        if lines < 8:
            return False
        self.rows = self.ROWS
        with _print_lock:
            # scroll region = everything above the reserved rows; park the cursor at its last line so the
            # next print lands there and scrolls normally
            sys.stdout.write(f"\x1b[1;{lines - self.rows}r\x1b[{lines - self.rows};1H")
            sys.stdout.flush()
        self._lines = lines          # so a resize knows where the bar WAS
        self._cols = cols
        self.on = True
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGWINCH, self._resized)
        self.paint("")
        return True

    def rearm(self):
        """Set the scroll region again after something full-screen (the diff panel, the /agents picker) reset
        it. enable() is a no-op while the bar is on, and calling only that left the region at the full window:
        every say() then landed on the same last row and overwrote the line before it (2026-10-24)."""
        if self.on:
            self.on = False
            return self.enable()
        return False

    def disable(self):
        """Give the whole window back. MUST run before the chat exits, or the shell inherits a terminal
        that only scrolls its top rows."""
        (
            _print_lock, contextlib, sys,
        ) = bind(
            "_print_lock", "contextlib", "sys",
        )
        if not self.on:
            return
        self.on = False
        with contextlib.suppress(Exception):
            cols, lines = self._size()
            top = max(1, lines - (self.rows or self.ROWS) + 1)
            with _print_lock:
                # full region, then wipe EVERY reserved row: clearing only the last one left the prompt's top row
                # ("┌─[gnoc]...") on screen above the shell prompt after q (2026-10-24, tmux 80x24). The cursor
                # lands on the top reserved row, so the shell prompt replaces the bar instead of sitting under it.
                sys.stdout.write("\x1b[r" + "".join(f"\x1b[{r};1H\x1b[2K" for r in range(top, lines + 1))
                                 + f"\x1b[{top};1H")
                sys.stdout.flush()

    _MIN_LINES, _MIN_COLS = 8, 20   # a minimized window reports less than this; its restore resends SIGWINCH

    def _resized(self, *_):
        """A resize invalidates the row numbers the region was set with: wipe the bar where it WAS, set the
        region for the new size, draw the bar where it now belongs."""
        (
            _print_lock, contextlib, sys,
        ) = bind(
            "_print_lock", "contextlib", "sys",
        )
        if not self.on:
            return
        with contextlib.suppress(Exception):
            cols, lines = self._size()
            if lines < self._MIN_LINES or cols < self._MIN_COLS:
                self._was_tiny = True
                return              # minimized: nothing sensible to draw; the restore brings a real size
            old = getattr(self, "_lines", lines)
            old_cols = self._cols or cols
            with _print_lock:
                out = []
                if self.reading:
                    # The old prompt, erased WHERE THE CURSOR IS, not at the rows it used to be on. Terminals
                    # differ in what a taller window does to the text: Konsole, VTE, kitty and tmux pull it DOWN
                    # (the prompt stays on the last rows), xterm leaves it at the top (the prompt is now
                    # mid-screen). Erasing rows old-1..old by number was right only for the second kind; on the
                    # first those rows hold the conversation by then, and every maximize ate two lines of it
                    # (measured in Konsole 25.04, 2026-11-21: 23 text rows before, 21 after). While readline
                    # owns the line the cursor IS on the prompt's last row, on every terminal.
                    out.append("\r\x1b[2K" + "\x1b[A\x1b[2K" * (self.rows - 1))
                # (while an answer streams the cursor is in the text, not on the bar, and the bar's old rows
                # are not known: nothing is erased. A terminal that left the text at the top may show the old
                # bar until it scrolls away; no terminal loses a line of the conversation.)
                out.append(f"\x1b[r\x1b[1;{lines - self.rows}r")   # full reset, then the new region
                sys.stdout.write("".join(out))
                sys.stdout.flush()
            self._lines, self._cols = lines, cols
            # Back from a minimize, or taller than before: the rows above the bar may be blank now (the text went
            # to the terminal's scrollback, or stayed at the top with a gap under it). Put the conversation back.
            # Not on a narrower window: there the terminal's own re-wrapping is better than lines cut to fit.
            was_tiny, self._was_tiny = self._was_tiny, False
            if was_tiny or (lines > old and cols >= old_cols):
                self._repaint_tail(cols, lines)
            # Setting the scroll region sends the cursor HOME (row 1, column 1). paint() puts it back, but
            # paint() draws nothing while readline owns the input row - which is whenever he is at the prompt, so
            # after ANY resize there (maximize, restore, or the same-size SIGWINCH a window manager sends on
            # minimize / restore) the cursor stayed at the top-left, the prompt was not redrawn, and the next key
            # he typed landed on row 1 over the conversation (GreyNOC 2026-11-21: "doing either deletes the chat
            # window"; reproduced in a pty with a terminal emulator).
            if self.reading:
                self._rl_redraw()
            else:
                self.paint(self._text)

    _rl_c = [None]   # libreadline through ctypes, looked up once ([False] when it cannot be had)

    def _rl_redraw(self):
        """Redraw the whole prompt on the reserved rows while READLINE owns them, at the window's NEW size.

        readline.redisplay() only repaints what it believes changed, and after a resize it believes nothing
        did. So the reserved rows are cleared, the cursor is put on the first of them, and readline is told
        the new size and that it is on a fresh line (rl_set_screen_size, rl_on_new_line), then asked for a
        full redraw (rl_forced_update_display): it prints its own prompt, both lines, and what is typed,
        exactly as input() did the first time. rl_resize_terminal() alone was not enough: it redraws only when
        the size CHANGED, and the SIGWINCH a window manager sends on minimize / restore usually carries the
        same size. Without libreadline (libedit, an odd build) this falls back to redisplay()."""
        (
            _print_lock, contextlib, readline, sys,
        ) = bind(
            "_print_lock", "contextlib", "readline", "sys",
        )
        cols, lines = self._size()
        if lines < self._MIN_LINES or cols < self._MIN_COLS:
            return
        with _print_lock:
            sys.stdout.write(f"\x1b[{lines - self.rows + 1};1H\x1b[J")
            sys.stdout.flush()
        if self._rl_c[0] is None:
            self._rl_c[0] = False
            with contextlib.suppress(Exception):
                import ctypes
                import ctypes.util
                name = ctypes.util.find_library("readline")
                lib = ctypes.CDLL(name) if name else None
                if lib is not None and all(hasattr(lib, f) for f in ("rl_set_screen_size", "rl_on_new_line",
                                                                     "rl_forced_update_display")):
                    self._rl_c[0] = lib
        done = False
        if self._rl_c[0]:
            with contextlib.suppress(Exception):
                lib = self._rl_c[0]
                lib.rl_set_screen_size(int(lines), int(cols))
                lib.rl_on_new_line()
                lib.rl_forced_update_display()
                done = True
        if not done:
            with contextlib.suppress(Exception):
                readline.redisplay()
        with contextlib.suppress(Exception):
            sys.stdout.flush()

    def paint(self, typed="", park=True):
        """Draw the input line: the same prompt you type on, plus whatever is typed so far.

        The cursor is saved and restored, so this can run from the spinner thread mid-output without
        disturbing what is being printed above."""
        (
            _fit_cols, _print_lock, _strip_rl, _vis_len, dim, sys,
        ) = bind(
            "_fit_cols", "_print_lock", "_strip_rl", "_vis_len", "dim", "sys",
        )
        if not self.on:
            return
        # WHILE READLINE OWNS THE LINE, DO NOT DRAW ON IT. Two writers with different models fought over
        # the input row and corrupted it the moment the text passed the window edge: readline (in
        # horizontal-scroll-mode) shows a window onto the END of the buffer and tracks its own caret,
        # while this method drew the TRUNCATED HEAD and clamped the caret to the last column. Every
        # repaint - and say() repaints after any output, as does every spinner frame - replaced
        # readline's view with the head and moved the caret to the edge, so the next keystroke redrew
        # against a screen that no longer matched and characters appeared to vanish from the start of
        # the line (GreyNOC 2026-10-27: "the cursor starts from home and starts deleting text").
        # Measured before the fix, at 100 columns: typed=400 rendered 99 columns of HEAD with the caret
        # parked at column 100. Readline repaints itself via _rl_refresh(), so the line is never stale.
        if self.reading:
            return
        self._text = typed
        cols, lines = self._size()
        if lines < self._MIN_LINES or cols < self._MIN_COLS:
            return   # minimized: `lines - rows + 1` is zero or negative there, and row 0 is the TOP of the screen
        rows = _strip_rl(self.prompt_fn() if self.prompt_fn else dim("› ")).split("\n")
        rows = rows[-self.rows:]                       # the prompt is two lines; keep its tail if longer
        if self.status and len(rows) > 1:
            # the live indicator rides on the prompt's top row, right-aligned when it fits
            gap = cols - 1 - _vis_len(rows[0]) - _vis_len(self.status)
            rows[0] = rows[0] + (" " * gap if gap >= 2 else "  ") + self.status
        # HORIZONTAL SCROLL, like a shell: when prompt+typed overflows the row, show the TAIL of what is
        # typed rather than the head, so the newest characters and the caret stay visible however long
        # the entry gets. Truncating the head instead put the caret where the text was not.
        avail = max(8, cols - 1 - _vis_len(rows[-1]))
        shown = typed if len(typed) <= avail else typed[-avail:]
        rows[-1] = rows[-1] + shown
        with _print_lock:
            out = []
            for n, row in enumerate(rows):
                out.append(f"\x1b[{lines - len(rows) + 1 + n};1H\x1b[2K" + _fit_cols(row, cols - 1))
            if park:
                # leave the caret at the end of what you have typed: this line is where typing goes, so
                # this is where the cursor belongs (GreyNOC 2026-10-22)
                out.append(f"\x1b[{lines};{min(cols, _vis_len(rows[-1]) + 1)}H")
            else:
                out.insert(0, "\x1b7")
                out.append("\x1b8")
            sys.stdout.write("".join(out))
            sys.stdout.flush()

    def _rl_refresh(self):
        """Hand the input rows back to READLINE after something printed above them.

        Readline moves the cursor RELATIVELY, so once anything else writes, its model of where the line
        sits is wrong and its next redraw lands in the wrong place - which is why this class used to
        repaint the line itself. Re-anchoring at the top reserved row and asking readline to redisplay
        keeps ONE writer: readline draws its own prompt and its own horizontally-scrolled view, with its
        own caret, so nothing can disagree about what is on the row."""
        (
            _print_lock, contextlib, readline, sys,
        ) = bind(
            "_print_lock", "contextlib", "readline", "sys",
        )
        if not (self.on and self.reading):
            return
        cols, lines = self._size()
        if lines < self._MIN_LINES or cols < self._MIN_COLS:
            # minimized. "\x1b[0;1H\x1b[J" is "go to the top-left and clear to the end of the screen": the
            # whole conversation, wiped by one refresh while the window was an icon (2026-11-21)
            return
        with contextlib.suppress(Exception):
            with _print_lock:
                sys.stdout.write(f"\x1b[{lines - self.rows + 1};1H\x1b[J")
                sys.stdout.flush()
            readline.redisplay()

    # kept for callers that only want the typed text updated
    def draw(self, text=""):
        self.paint(text)

    def to_scroll(self):
        """Move the cursor back into the scrolling area, so the next print lands there and not on the
        input line. Everything that writes output calls this first; the bar is repainted after."""
        (
            _print_lock, sys,
        ) = bind(
            "_print_lock", "sys",
        )
        if not self.on:
            return
        cols, lines = self._size()
        if lines < self._MIN_LINES or cols < self._MIN_COLS:
            return   # minimized: leave the cursor where it is
        with _print_lock:
            sys.stdout.write(f"\x1b[{lines - self.rows};1H")
            sys.stdout.flush()

    def read_line(self, prompt_text):
        """Read one line ON the reserved rows with readline fully intact (history, emacs keys, completion).

        input() draws wherever the cursor is, so the cursor is moved into the reserved rows first. The
        rows are OUTSIDE the scroll region, so nothing printed while you type can push the line away."""
        (
            FILE_MARKER, _prefilled_input, _print_lock, echo_prompt, say, sys,
        ) = bind(
            "FILE_MARKER", "_prefilled_input", "_print_lock", "echo_prompt", "say", "sys",
        )
        if not self.on:
            return _prefilled_input(prompt_text)
        cols, lines = self._size()
        with _print_lock:
            sys.stdout.write(f"\x1b[{lines - self.rows + 1};1H\x1b[J")   # top reserved row, clear downward
            sys.stdout.flush()
        line = None
        try:
            self.reading = True            # readline owns the rows from here: paint() stays off them
            line = _prefilled_input(prompt_text)
            return line
        finally:
            self.reading = False
            with _print_lock:   # wipe the editing rows and get back into the scrolling area
                sys.stdout.write(f"\x1b[{lines - self.rows + 1};1H\x1b[J\x1b[{lines - self.rows};1H")
                sys.stdout.flush()
            if line is not None:
                # the submitted line belongs in the transcript, like a sent message; then the input line
                # comes straight back, empty. Without this it stayed blank until the spinner's next frame.
                # Only the prompt's LAST row is echoed: repeating the whole two-row box for every message
                # doubled the transcript's chrome (2026-10-24). A Ctrl-O attach marker never echoes: the
                # REPL turns it into a file picker a moment later.
                shown = line[:-len(FILE_MARKER)] + "…" if line.endswith(FILE_MARKER) else line
                say(echo_prompt(prompt_text, shown))
            self.paint("")


_TTY_ORIG = [None]


def _restore_tty(*_):
    """Put the terminal back exactly as the shell gave it to us. Safe to call any number of times, from
    atexit or a signal handler: a chat that exits mid-turn must never leave the shell echo-off."""
    (
        BAR, TYPED, _TITLE, _TTY_ORIG, contextlib, sys, termios,
    ) = bind(
        "BAR", "TYPED", "_TITLE", "_TTY_ORIG", "contextlib", "sys", "termios",
    )
    with contextlib.suppress(Exception):
        TYPED.stop()
    with contextlib.suppress(Exception):
        BAR.disable()   # a scroll region left set gives the shell a window that only scrolls its top rows
    if _TITLE[0] is not None and sys.stdout.isatty():
        with contextlib.suppress(Exception):
            sys.stdout.write("\x1b]0;\x07")   # the tab title is ours, not the shell's to inherit
            sys.stdout.flush()
    fd_attrs = _TTY_ORIG[0]
    if fd_attrs:
        fd, attrs = fd_attrs
        with contextlib.suppress(Exception):
            termios.tcsetattr(fd, termios.TCSADRAIN, attrs)
    with contextlib.suppress(Exception):
        if sys.stdout.isatty():  # a pipe (gnoc chat < questions.txt | tee) must not end in escape bytes
            sys.stdout.write("\x1b[0m\x1b[?25h")   # reset colours, show the cursor
            sys.stdout.flush()


def _set_title(text):
    """The terminal tab title, Claude-Code-style: 'gnoc chat · gatewayco · gpt-oss'. Off when stdout is not a
    tty or GNOC_TITLE=0. Text goes through _row_text first, which drops every escape sequence, so a
    hostile program name or directory can never write its own OSC bytes."""
    (
        _TITLE, _print_lock, _row_text, os, sys,
    ) = bind(
        "_TITLE", "_print_lock", "_row_text", "os", "sys",
    )
    if os.environ.get("GNOC_TITLE", "1") == "0" or not sys.stdout.isatty():
        return
    t = (_row_text(str(text)) or "gnoc chat")[:200]
    if _TITLE[0] == t:
        return
    _TITLE[0] = t
    with _print_lock:
        sys.stdout.write("\x1b]0;" + t + "\x07")
        sys.stdout.flush()


def _title_text(agent):
    """What the tab says right now: the program or repo, and the model that will answer."""
    (
        WS, _short_model, os, resolve, root,
    ) = bind(
        "WS", "_short_model", "os", "resolve", "root",
    )
    try:
        model = _short_model(resolve("lead", quiet=True)[0])
    except Exception:  # noqa: BLE001 - a title is advisory
        model = ""
    where = agent.ctx.program or (os.path.basename(root()) if root() != WS else "hunt")
    return f"gnoc chat · {where}" + (f" · {model}" if model else "")


def _guard_tty():
    """Capture the shell's tty state once and make sure it is restored however we exit."""
    (
        _TTY_ORIG, _restore_tty, contextlib, os, sys, termios,
    ) = bind(
        "_TTY_ORIG", "_restore_tty", "contextlib", "os", "sys", "termios",
    )
    import atexit
    import signal
    if _TTY_ORIG[0] is not None or not sys.stdin.isatty():
        return
    with contextlib.suppress(Exception):
        fd = sys.stdin.fileno()
        _TTY_ORIG[0] = (fd, termios.tcgetattr(fd))
    atexit.register(_restore_tty)
    for sig in (signal.SIGHUP, signal.SIGTERM):
        # CHAIN to the handler already there: gnoc_session arms one that closes the session and reaps this chat's
        # hunt lanes. Replacing it left the lanes running after the terminal closed (QAQC 2026-11-19).
        prev = signal.getsignal(sig)

        def _bye(signum, frame, _sig=sig, _prev=prev):
            _restore_tty()
            if callable(_prev) and _prev not in (signal.SIG_DFL, signal.SIG_IGN):
                _prev(signum, frame)   # it re-raises the signal with the default action itself
                return
            signal.signal(_sig, signal.SIG_DFL)
            os.kill(os.getpid(), _sig)
        with contextlib.suppress(Exception):
            signal.signal(sig, _bye)


class _BootNotice:
    """The first thing on screen, before anything that can block.

    Every line of the banner below sits BEHIND the model-endpoint probe, so when a host is black-holed (the
    reverse tunnel accepts the connection and then never answers) the terminal stays completely blank while
    the probe ladder runs. A blank terminal is indistinguishable from a dead command, and the only move left
    is Ctrl-C (the user, 2026-10-27: "it wasn't starting at all and I had to ctrl C to exit"). So: say we are
    alive immediately, and if the probe is still running after a moment, name the host we are waiting on and
    how long it can take. Nothing here can raise into startup.
    """

    def __init__(self, show):
        (
            T, _owl_static, contextlib, dim, hang, say, threading,
        ) = bind(
            "T", "_owl_static", "contextlib", "dim", "hang", "say", "threading",
        )
        self.show, self.timer, self.warned = bool(show), None, False
        if self.show:
            with contextlib.suppress(Exception):
                say(hang(_owl_static(1.0) + " " + T.byellow("gnoc") + dim("  starting…"), indent=2))
                self.timer = threading.Timer(1.2, self._slow)
                self.timer.daemon = True
                self.timer.start()

    def _slow(self):
        (
            contextlib, dim, hang, llm_endpoints, say,
        ) = bind(
            "contextlib", "dim", "hang", "llm_endpoints", "say",
        )
        self.warned = True
        with contextlib.suppress(Exception):
            # only a host some role is set to use: a machine with no phone or desktop link was told it was
            # "waiting on phone" while the wait was something else entirely (2026-11-19)
            used = {llm_endpoints.split(str(v))[1] for v in llm_endpoints.roles().values()}
            slow = [h for h in ("desktop", "phone") if h in llm_endpoints.HOSTS and h in used
                    and not llm_endpoints.sniff(h, 0.3)]
            where = (" and ".join(slow) + f" ({llm_endpoints.HOSTS.get(slow[0])}): not answering, so") if slow \
                else "startup checks:"
            say(hang(dim(f"  … still starting, {where} this start can take a few seconds")
                     + dim("  (Ctrl-C to quit, gnoc gpus to check)"), indent=4))

    def done(self):
        (
            contextlib,
        ) = bind(
            "contextlib",
        )
        with contextlib.suppress(Exception):
            if self.timer:
                self.timer.cancel()
