#!/usr/bin/env python3
"""gnoc_agents_ui.py - pick a sub-agent with the arrow keys and read its log or its whole chat, live.

    gnoc agents            (or /agents inside gnoc chat; /agents list prints the old table)

List view    up/down (or k/j) select · Enter or right open · r refresh · q / Esc quit
Agent view   l = log, c = chat (the worker's full conversation: brief, every model turn, every tool call and
             result) · up/down/PgUp/PgDn scroll · End / f follow the bottom live · left / b / Esc back · q quit
Refreshes every second, so a running fan-out bot can be watched as it works. Read-only: nothing here changes an
agent. Text is redacted (the user's secrets never shown).
"""
import curses
import json
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_monitor as MON  # noqa: E402

try:
    import gnoc_secrets
    redact = gnoc_secrets.redact
except ImportError:
    redact = str


def status_attr(r):
    st = r.get("status", "?")
    if st == "done":
        return 2
    if st in ("failed", "orphaned"):
        return 1
    if st == "running":
        return 1 if MON.quiet_s(r) > MON.QUIET_S else 3
    return 0


def list_line(r, width):
    q = MON.quiet_s(r)
    warn = "  ! quiet" if r.get("status") == "running" and q > MON.QUIET_S else ""
    head = (f"{r.get('status', '?'):<9} {r['id']:<22} {r.get('kind', '')[:16]:<16} "
            f"{(r.get('model', '') or '')[:28]}@{r.get('host', '')}  steps {r.get('steps', 0)}  "
            f"last {MON.fmt_s(q)}{warn}")
    return head[:width - 1]


def chat_lines(rows, width):
    """A worker conversation as wrapped display lines."""
    out = []
    w = max(20, width - 4)
    for i, m in enumerate(rows):
        role = m.get("role") or "?"
        label = {"system": "BRIEF", "user": "TASK", "assistant": "MODEL", "tool": f"TOOL {m.get('tool') or ''}"}.get(
            role, role.upper())
        out.append(("head", f"── {i + 1}. {label} " + "─" * max(0, w - len(label) - 8)))
        text = redact(m.get("content") or "")
        for para in text.splitlines() or ([""] if not m.get("calls") else []):
            out += [("text", "  " + x) for x in (textwrap.wrap(para, w) or [""])]
        for c in m.get("calls") or []:
            args = c.get("args")
            args = json.dumps(args, default=str) if not isinstance(args, str) else args
            out += [("call", "  -> " + x) for x in textwrap.wrap(f"{c.get('name')}({redact(args)})", w)]
    return out or [("text", "(no chat saved for this agent: only fan-out / delegate workers save one)")]


def log_lines(sid, width):
    r, lines = MON.tail(sid, 2000)
    w = max(20, width - 4)
    out = []
    for ln in lines:
        out += [("text", x) for x in (textwrap.wrap(redact(ln), w, subsequent_indent="    ") or [""])]
    return out or [("text", "(empty log)")]


ARROWS = {"A": curses.KEY_UP, "B": curses.KEY_DOWN, "C": curses.KEY_RIGHT, "D": curses.KEY_LEFT,
          "H": curses.KEY_HOME, "F": curses.KEY_END, "5~": curses.KEY_PPAGE, "6~": curses.KEY_NPAGE,
          "1~": curses.KEY_HOME, "4~": curses.KEY_END}


def read_escape(stdscr):
    """An arrow key the terminfo did not decode (ESC [ B or ESC O B, as tmux and some terminals send) -> the curses
    key code; a lone Esc stays 27."""
    stdscr.nodelay(True)
    try:
        seq = ""
        for _ in range(4):
            c = stdscr.getch()
            if c == -1:
                break
            seq += chr(c)
            if seq[-1].isalpha() or seq[-1] == "~":
                break
    finally:
        stdscr.nodelay(False)
        stdscr.timeout(1000)
    if seq[:1] in ("[", "O"):
        return ARROWS.get(seq[1:], 27)
    return 27


def run(stdscr):
    curses.curs_set(0)
    curses.use_default_colors()
    for i, c in enumerate((curses.COLOR_RED, curses.COLOR_GREEN, curses.COLOR_YELLOW, curses.COLOR_CYAN), 1):
        curses.init_pair(i, c, -1)
    stdscr.timeout(1000)
    sel, top = 0, 0
    view, mode, scroll, follow = "list", "chat", 0, True
    while True:
        h, w = stdscr.getmaxyx()
        rows = MON.load_all()[:200]
        stdscr.erase()
        if view == "list":
            sel = max(0, min(sel, len(rows) - 1))
            stdscr.addnstr(0, 0, f" sub-agents ({len(rows)})   up/down select · Enter open · q quit", w - 1,
                           curses.A_REVERSE)
            if not rows:
                stdscr.addnstr(2, 2, "no sub-agents yet: fan-out bots, workers, reflection, gates and Claude jobs "
                                     "appear here", w - 3)
            body = h - 4
            top = min(top, sel) if sel < top else (sel - body + 1 if sel >= top + body else top)
            for i, r in enumerate(rows[top:top + body]):
                idx = top + i
                attr = curses.color_pair(status_attr(r)) | (curses.A_REVERSE if idx == sel else 0)
                stdscr.addnstr(1 + i, 0, list_line(r, w), w - 1, attr)
            if rows:
                stdscr.addnstr(h - 2, 0, ("task: " + rows[sel].get("task", ""))[:w - 1], w - 1, curses.A_DIM)
        else:
            r = rows[sel] if 0 <= sel < len(rows) else None
            if not r:
                view = "list"
                continue
            lines = chat_lines(MON.chat(r["id"]), w) if mode == "chat" else log_lines(r["id"], w)
            body = h - 2
            if follow:
                scroll = max(0, len(lines) - body)
            scroll = max(0, min(scroll, max(0, len(lines) - body)))
            tab = lambda name, key, mode=mode: f"[{key}] {name.upper() if mode == name else name}"
            stdscr.addnstr(0, 0, f" {r['id']} {r.get('status')} · {tab('chat', 'c')} {tab('log', 'l')} · "
                                 f"{'FOLLOWING' if follow else 'End = follow'} · left/Esc back", w - 1,
                           curses.A_REVERSE)
            colors = {"head": curses.color_pair(4) | curses.A_BOLD, "call": curses.color_pair(3), "text": 0}
            for i, (kind, text) in enumerate(lines[scroll:scroll + body]):
                stdscr.addnstr(1 + i, 0, text, w - 1, colors[kind])
            stdscr.addnstr(h - 1, 0, f" line {scroll + 1}-{min(len(lines), scroll + body)} of {len(lines)}", w - 1,
                           curses.A_DIM)
        stdscr.refresh()
        k = stdscr.getch()
        if k == -1:
            continue
        if k == 27:
            k = read_escape(stdscr)
        if os.environ.get("GNOC_UI_KEYLOG"):  # debugging aid: which code each key arrives as
            with open(os.environ["GNOC_UI_KEYLOG"], "a") as f:
                f.write(f"{view} {k}\n")
        if k in (ord("q"),):
            return
        if view == "list":
            if k in (curses.KEY_UP, ord("k")):
                sel -= 1
            elif k in (curses.KEY_DOWN, ord("j")):
                sel += 1
            elif k == curses.KEY_PPAGE:
                sel -= h - 4
            elif k == curses.KEY_NPAGE:
                sel += h - 4
            elif k in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT) and rows:
                view, follow, scroll = "agent", True, 0
                mode = "chat" if MON.chat(rows[sel]["id"]) else "log"
            elif k == 27:
                return
        else:
            if k in (curses.KEY_LEFT, ord("b"), 27):
                view = "list"
            elif k == ord("c"):
                mode, follow = "chat", True
            elif k == ord("l"):
                mode, follow = "log", True
            elif k in (curses.KEY_UP, ord("k")):
                scroll, follow = scroll - 1, False
            elif k in (curses.KEY_DOWN, ord("j")):
                scroll += 1
            elif k == curses.KEY_PPAGE:
                scroll, follow = scroll - (h - 3), False
            elif k == curses.KEY_NPAGE:
                scroll += h - 3
            elif k in (curses.KEY_HOME, ord("g")):
                scroll, follow = 0, False
            elif k in (curses.KEY_END, ord("f"), ord("G")):
                follow = True


def main():
    if not sys.stdout.isatty():
        print("gnoc agents needs a terminal (for a plain list: gnoc chat '/agents list')")
        return 1
    os.environ.setdefault("ESCDELAY", "25")
    curses.wrapper(run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
