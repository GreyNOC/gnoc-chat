#!/usr/bin/env python3
"""
poe-capture.py - turn a captured probe into proof-of-exploit IMAGE evidence.

WHY. A triager reads faster than they replay. A report that carries the terminal response as a
picture of the actual bytes gets read; one that carries only a transcript gets queued. This
makes the image step one command so it stops being skipped, and it refuses to render anything
that would leak a credential into an attachment.

TWO MODES, and the distinction is kept honest in the image itself:

  --url   a GENUINE live page capture in a real browser. Use it for a page a human can visit:
          a public listing, a JSON endpoint, a rendered XSS, an admin panel reached as a second
          account. The image is what the browser actually showed.

  --log   a terminal transcript RENDERED from a captured log file. The title bar says so, with
          the source path, so the image can never be mistaken for a desktop screenshot. Use it
          for curl output, diffs, fingerprint matches, probe tables.

Never pass --url a page that only exists because you typed it. The whole point is that the
image shows the target's own bytes.

SIZE. The house attachment rule is 3 files under 50KB. --max-kb (default 50) downsamples and
quantises until the PNG fits, and reports the final size. An image nobody can attach is not
evidence.

SECRET GATE. Before rendering a log, every line is scanned for private-key blocks, AWS keys,
bearer and JWT material, Bitbucket ATCTT tokens, Telegram bot tokens, and common password
assignments. A hit ABORTS the render and names the line number. Redact at the capture step,
not here: a cropped image still has the bytes in the log it came from.

Usage:
  poe-capture.py --url https://host/path --out shot.png [--wait 5000] [--width 1500]
  poe-capture.py --log evidence/04.log --out shot.png --title "key matches live certificate"
  poe-capture.py --log evidence/04.log --out shot.png --allow-secret-scan-override   (refused)
"""
import argparse, asyncio, html, pathlib, re, sys

CHROME_CANDIDATES = [
    "~/.local/bin/google-chrome", "/usr/bin/google-chrome",
    "/usr/bin/chromium", "/usr/bin/chromium-browser",
]

SECRET_PATTERNS = [
    (r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY", "private key block"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bASIA[0-9A-Z]{16}\b", "AWS temporary key id"),
    (r"\bATCTT3[A-Za-z0-9._=-]{50,}", "Bitbucket access token"),
    (r"\b[0-9]{7,12}:[A-Za-z0-9_-]{30,}\b", "Telegram bot token"),
    (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT"),
    (r"(?i)\b(authorization|bearer)\s*[:=]\s*\S{20,}", "bearer credential"),
    (r"(?i)\b(password|passwd|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*\S{6,}", "secret assignment"),
    (r"\bsk_live_[A-Za-z0-9]{10,}", "Stripe live key"),
    (r"\bghp_[A-Za-z0-9]{20,}", "GitHub token"),
]

TERM_CSS = """
*{box-sizing:border-box} body{margin:0;background:#15161b;font-family:'DejaVu Sans Mono',monospace}
.win{margin:18px;border-radius:9px;overflow:hidden;box-shadow:0 10px 34px rgba(0,0,0,.6);border:1px solid #2c2e38}
.bar{background:#23252e;padding:9px 14px;display:flex;align-items:center;gap:9px;border-bottom:1px solid #2c2e38}
.dot{width:11px;height:11px;border-radius:50%}
.t{color:#aeb3c2;font-size:12.5px;margin-left:8px}
pre{margin:0;padding:16px 18px;color:#dfe3ec;font-size:12.6px;line-height:1.52;white-space:pre-wrap;word-break:break-word}
.ok{color:#5dd08a;font-weight:700}.bad{color:#ff7b72;font-weight:700}
.hd{color:#7fb5ff}.dim{color:#878d9c}.hl{color:#ffd166;font-weight:700}
"""

OK_MARKS = ("MATCH", "-> YES", "= YES", "HTTP 200", "200 OK", "CONFIRMED", "true")
BAD_MARKS = ("NO MATCH", "-> NO", "DENIED", "403", "401", "FAILED")


def scan_secrets(text):
    hits = []
    for n, line in enumerate(text.split("\n"), 1):
        for pat, label in SECRET_PATTERNS:
            if re.search(pat, line):
                hits.append((n, label, line.strip()[:60]))
                break
    return hits


def colorize(text):
    out = []
    for line in html.escape(text).split("\n"):
        plain = line
        if plain.startswith(("###", "==", "##")):
            out.append(f'<span class="hd">{line}</span>')
        elif any(m in plain for m in BAD_MARKS):
            out.append(f'<span class="bad">{line}</span>')
        elif any(m in plain for m in OK_MARKS):
            out.append(f'<span class="ok">{line}</span>')
        elif plain.strip().startswith("#"):
            out.append(f'<span class="dim">{line}</span>')
        else:
            out.append(line)
    return "\n".join(out)


def shrink(path, max_kb):
    """Downsample and quantise until the PNG fits the attachment rule."""
    try:
        from PIL import Image
    except ImportError:
        print(f"note: Pillow missing, cannot shrink {path}", file=sys.stderr)
        return
    p = pathlib.Path(path)
    for colors, scale in ((64, 1.0), (32, 1.0), (32, 0.75), (16, 0.75), (16, 0.5), (8, 0.5)):
        if p.stat().st_size <= max_kb * 1024:
            return
        im = Image.open(path)
        if scale != 1.0:
            im = im.resize((int(im.width * scale), int(im.height * scale)), Image.LANCZOS)
        im.convert("P", palette=Image.ADAPTIVE, colors=colors).save(path, optimize=True)


def find_chrome():
    for c in CHROME_CANDIDATES:
        if pathlib.Path(c).exists():
            return c
    return None


async def run(a):
    from playwright.async_api import async_playwright
    chrome = find_chrome()
    out = pathlib.Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as pw:
        kw = {"args": ["--no-sandbox"]}
        if chrome:
            kw["executable_path"] = chrome
        b = await pw.chromium.launch(**kw)

        if a.url:
            pg = await b.new_page(viewport={"width": a.width, "height": a.height})
            await pg.goto(a.url, wait_until="domcontentloaded", timeout=60000)
            await pg.wait_for_timeout(a.wait)
            await pg.screenshot(path=str(out), full_page=a.full_page)
            await pg.close()
            print(f"live capture: {out}")
        else:
            src = pathlib.Path(a.log)
            text = src.read_text(errors="replace").rstrip()
            hits = scan_secrets(text)
            if hits:
                print("REFUSED: the log contains credential material. Redact at the capture "
                      "step, then re-run.", file=sys.stderr)
                for n, label, frag in hits[:10]:
                    print(f"  line {n}: {label}: {frag}", file=sys.stderr)
                await b.close()
                sys.exit(2)
            caption = a.title or src.name
            doc = (f'<!doctype html><meta charset="utf-8"><style>{TERM_CSS}</style>'
                   f'<div class="win"><div class="bar">'
                   f'<span class="dot" style="background:#ff5f57"></span>'
                   f'<span class="dot" style="background:#febc2e"></span>'
                   f'<span class="dot" style="background:#28c840"></span>'
                   f'<span class="t">rendered from captured log {html.escape(str(src))}'
                   f' &mdash; {html.escape(caption)}</span></div>'
                   f'<pre>{colorize(text)}</pre></div>')
            tmp = out.with_suffix(".render.html")
            tmp.write_text(doc, encoding="utf-8")
            pg = await b.new_page(viewport={"width": a.width, "height": 800},
                                  device_scale_factor=a.scale)
            await pg.goto(tmp.as_uri(), wait_until="load")
            await pg.wait_for_timeout(200)
            await pg.screenshot(path=str(out), full_page=True)
            await pg.close()
            tmp.unlink(missing_ok=True)
            print(f"rendered transcript: {out}")
        await b.close()

    shrink(out, a.max_kb)
    kb = out.stat().st_size / 1024
    verdict = "fits the 3-files-under-50KB attachment rule" if kb <= a.max_kb else "OVER the cap"
    print(f"  {kb:.0f} KB, {verdict}")


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="live page to capture in a real browser")
    g.add_argument("--log", help="captured log file to render as a terminal transcript")
    ap.add_argument("--out", required=True)
    ap.add_argument("--title", help="one phrase saying what the image proves")
    ap.add_argument("--wait", type=int, default=4000, help="ms to settle before a live capture")
    ap.add_argument("--width", type=int, default=1180)
    ap.add_argument("--height", type=int, default=900)
    ap.add_argument("--scale", type=int, default=2, help="device scale for transcripts")
    ap.add_argument("--full-page", action="store_true")
    ap.add_argument("--max-kb", type=int, default=50)
    asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    main()
