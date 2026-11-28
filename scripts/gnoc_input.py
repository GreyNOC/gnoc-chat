#!/usr/bin/env python3
"""gnoc_input.py - mouse and keyboard through the kernel's uinput, stdlib only (works on Wayland and X11 alike).

Self-contained on purpose: gnoc pipes this file over ssh to a linked machine (`python3 - '<ops json>'`), so it
needs nothing installed there except python3 and write access to /dev/uinput (the guided link setup adds a udev
rule for that).

    gnoc_input.py '<json ops>' [WxH]
ops: [{"op": "move", "x": 10, "y": 20},
      {"op": "click", "x": 10, "y": 20, "button": "left|right|middle", "double": false},
      {"op": "drag", "x": 1, "y": 2, "x2": 300, "y2": 400},
      {"op": "scroll", "dy": -3},                 negative = down
      {"op": "type", "text": "hello"},             US layout, printable ASCII + \\n \\t
      {"op": "key", "combo": "ctrl+shift+p"},      names: ctrl shift alt meta enter tab esc backspace delete
                                                   home end pageup pagedown up down left right space f1..f12, a char
      {"op": "sleep", "ms": 300}]
WxH is the screen size the x/y refer to (the screenshot's size); absolute coordinates map onto it.
The virtual devices exist only while this process runs: when it exits, control is gone.
"""
import fcntl
import json
import os
import struct
import sys
import time

UI_SET_EVBIT, UI_SET_KEYBIT, UI_SET_RELBIT, UI_SET_ABSBIT = 0x40045564, 0x40045565, 0x40045566, 0x40045567
UI_DEV_CREATE, UI_DEV_DESTROY = 0x5501, 0x5502
EV_SYN, EV_KEY, EV_REL, EV_ABS = 0, 1, 2, 3
ABS_X, ABS_Y, REL_WHEEL = 0, 1, 8
BTN = {"left": 0x110, "right": 0x111, "middle": 0x112}

KEYS = {"esc": 1, "minus": 12, "equal": 13, "backspace": 14, "tab": 15, "enter": 28, "ctrl": 29, "shift": 42,
        "alt": 56, "space": 57, "capslock": 58, "home": 102, "up": 103, "pageup": 104, "left": 105, "right": 106,
        "end": 107, "down": 108, "pagedown": 109, "insert": 110, "delete": 111, "meta": 125, "super": 125}
KEYS.update({f"f{i}": 58 + i for i in range(1, 11)})
KEYS.update({"f11": 87, "f12": 88})
ROWS = {"1234567890": 2, "qwertyuiop": 16, "asdfghjkl": 30, "zxcvbnm": 44}
for row, start in ROWS.items():
    for i, ch in enumerate(row):
        KEYS[ch] = start + i
PLAIN = {"-": 12, "=": 13, "[": 26, "]": 27, ";": 39, "'": 40, "`": 41, "\\": 43, ",": 51, ".": 52, "/": 53,
         " ": 57, "\n": 28, "\t": 15}
SHIFTED = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9", ")": "0",
           "_": "-", "+": "=", "{": "[", "}": "]", ":": ";", '"': "'", "~": "`", "|": "\\", "<": ",", ">": ".",
           "?": "/"}


def char_key(ch):
    """(keycode, needs_shift) for one printable US-layout character, or None."""
    if ch in PLAIN:
        return PLAIN[ch], False
    if ch.isascii() and ch.isalpha():
        return KEYS[ch.lower()], ch.isupper()
    if ch.isdigit():
        return KEYS[ch], False
    if ch in SHIFTED:
        base = SHIFTED[ch]
        return (PLAIN.get(base) or KEYS[base]), True
    return None


class Dev:
    def __init__(self, name, keys=(), abs_size=None, wheel=False):
        self.fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
        fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_KEY)
        for k in keys:
            fcntl.ioctl(self.fd, UI_SET_KEYBIT, k)
        absmax = [0] * 64
        if abs_size:
            fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_ABS)
            for a in (ABS_X, ABS_Y):
                fcntl.ioctl(self.fd, UI_SET_ABSBIT, a)
            absmax[ABS_X], absmax[ABS_Y] = abs_size[0] - 1, abs_size[1] - 1
        if wheel:
            fcntl.ioctl(self.fd, UI_SET_EVBIT, EV_REL)
            fcntl.ioctl(self.fd, UI_SET_RELBIT, REL_WHEEL)
        user_dev = struct.pack("80sHHHHi", name.encode()[:79], 0x06, 0x1234, 0x5678, 1, 0) + \
            struct.pack("64i", *absmax) + struct.pack("64i", *([0] * 64)) * 3
        os.write(self.fd, user_dev)
        fcntl.ioctl(self.fd, UI_DEV_CREATE)

    def emit(self, typ, code, val):
        os.write(self.fd, struct.pack("llHHi", 0, 0, typ, code, val))

    def syn(self):
        self.emit(EV_SYN, 0, 0)

    def close(self):
        try:
            fcntl.ioctl(self.fd, UI_DEV_DESTROY)
        finally:
            os.close(self.fd)


def run(ops, size):
    w, h = size
    kbd = Dev("gnoc-keyboard", keys=sorted(set(KEYS.values()) | set(PLAIN.values())))
    ptr = Dev("gnoc-pointer", keys=BTN.values(), abs_size=(w, h), wheel=True)
    time.sleep(0.6)  # let the compositor pick the new devices up before the first event
    done = []
    try:
        def move(x, y):
            ptr.emit(EV_ABS, ABS_X, max(0, min(w - 1, int(x))))
            ptr.emit(EV_ABS, ABS_Y, max(0, min(h - 1, int(y))))
            ptr.syn()
            time.sleep(0.03)

        def press(dev, code, down):
            dev.emit(EV_KEY, code, 1 if down else 0)
            dev.syn()
            time.sleep(0.012)

        for op in ops:
            kind = op.get("op")
            if kind == "move":
                move(op["x"], op["y"])
            elif kind == "click":
                if "x" in op:
                    move(op["x"], op["y"])
                b = BTN[op.get("button", "left")]
                for _ in range(2 if op.get("double") else 1):
                    press(ptr, b, True)
                    press(ptr, b, False)
                    time.sleep(0.06)
            elif kind == "drag":
                move(op["x"], op["y"])
                press(ptr, BTN["left"], True)
                steps = 12
                for i in range(1, steps + 1):
                    move(op["x"] + (op["x2"] - op["x"]) * i / steps, op["y"] + (op["y2"] - op["y"]) * i / steps)
                press(ptr, BTN["left"], False)
            elif kind == "scroll":
                for _ in range(abs(int(op.get("dy", 0)))):
                    ptr.emit(EV_REL, REL_WHEEL, 1 if op["dy"] > 0 else -1)
                    ptr.syn()
                    time.sleep(0.02)
            elif kind == "type":
                bad = [c for c in op.get("text", "") if char_key(c) is None]
                if bad:
                    raise ValueError(f"cannot type {''.join(sorted(set(bad)))!r} (US-layout printable ASCII only)")
                for c in op["text"]:
                    code, shift = char_key(c)
                    if shift:
                        press(kbd, KEYS["shift"], True)
                    press(kbd, code, True)
                    press(kbd, code, False)
                    if shift:
                        press(kbd, KEYS["shift"], False)
            elif kind == "key":
                combo = op.get("combo") or op.get("keys") or ""   # "keys" is what the tool's own example said
                names = [n.strip().lower() for n in str(combo).split("+") if n.strip()]
                if not names:
                    raise ValueError('a key op needs "combo", e.g. {"op": "key", "combo": "ctrl+l"}')
                codes = []
                for n in names:
                    if n in KEYS:
                        codes.append(KEYS[n])
                    elif len(n) == 1 and char_key(n):
                        codes.append(char_key(n)[0])
                    else:
                        raise ValueError(f"unknown key {n!r}")
                for c in codes:
                    press(kbd, c, True)
                for c in reversed(codes):
                    press(kbd, c, False)
            elif kind == "sleep":
                time.sleep(min(int(op.get("ms", 0)), 10000) / 1000)
            else:
                raise ValueError(f"unknown op {kind!r}")
            done.append(kind)
        time.sleep(0.15)
    except (ValueError, KeyError) as e:
        e.done = list(done)
        raise
    finally:
        kbd.close()
        ptr.close()
    return done


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    # "-": the ops come on stdin (or, over ssh where stdin is this script, from the line before it), never argv
    ops = json.loads(getattr(sys, "stdin_ops", None) or sys.stdin.read()) if argv[1] == "-" else json.loads(argv[1])
    size = tuple(int(x) for x in (argv[2] if len(argv) > 2 else "1920x1080").lower().split("x"))
    try:
        done = run(ops if isinstance(ops, list) else [ops], size)
    except PermissionError:
        print(json.dumps({"ok": False, "error": "no write access to /dev/uinput (gnoc link setup adds the udev rule)"}))
        return 1
    except (ValueError, KeyError) as e:
        # what already ran is part of the answer: the screen has changed even though the call failed
        print(json.dumps({"ok": False, "error": str(e), "done": getattr(e, "done", [])}))
        return 1
    print(json.dumps({"ok": True, "done": done}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
