#!/usr/bin/env python3
"""zw_decode.py - find and decode the zero-width payload hidden in an office_stego.txt, and verify the round trip.

    python3 zw_decode.py office_stego.txt [--expect /greypath] [--clean office.txt]

Encoding (gen_office_art.py --stego): the UTF-8 bytes of the message, 8 bits each, most significant first,
written as U+200B (0) and U+200C (1), framed by U+2060 WORD JOINER on both sides. Invisible in a terminal.
Checks: exactly one framed payload; it decodes to --expect (when given); and the file with every zero-width
character removed is byte-identical to --clean (when given), i.e. the payload changed nothing visible.
Exit 0 only when every requested check passes.
"""
import re
import sys

ZW0, ZW1, ZWF = "​", "‌", "⁠"


def decode(text):
    found = re.findall(ZWF + "([" + ZW0 + ZW1 + "]+)" + ZWF, text)
    if len(found) != 1:
        raise SystemExit(f"FAIL: expected exactly one framed payload, found {len(found)}")
    bits = "".join("1" if ch == ZW1 else "0" for ch in found[0])
    if len(bits) % 8:
        raise SystemExit(f"FAIL: payload is {len(bits)} bits, not a whole number of bytes")
    # "replace": a corrupted payload must report a clean FAIL on --expect, not crash
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)).decode("utf-8", "replace")


def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    text = open(a[0], encoding="utf-8").read()
    msg = decode(text)
    print(f"payload: {msg!r}")
    ok = True
    if "--expect" in a:
        want = a[a.index("--expect") + 1]
        ok &= msg == want
        print(f"expect {want!r}: {'PASS' if msg == want else 'FAIL'}")
    if "--clean" in a:
        clean = open(a[a.index("--clean") + 1], encoding="utf-8").read()
        stripped = re.sub("[" + ZW0 + ZW1 + ZWF + "]", "", text)
        same = stripped == clean
        ok &= same
        print(f"visible text identical to {a[a.index('--clean') + 1]}: {'PASS' if same else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
