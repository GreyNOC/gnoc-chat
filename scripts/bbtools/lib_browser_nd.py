#!/usr/bin/env python3
"""
lib_browser_nd.py - nodriver (undetected) backend for the browser walls Playwright can't beat.

Use when lib_browser.detect_wall() reports Kasada / DataDome / PerimeterX: they fingerprint
Playwright's CDP and block it even with JS stealth; nodriver patches the CDP leaks. This is
also the correct home for nodriver's async eval - its evaluate() returns None on an async IIFE
UNLESS await_promise=True is passed (the logged StockX gotcha), which nd_eval handles for you.

nodriver is async:
  async with nd_browser(headless=True) as b:
      page  = await b.get(url)
      v     = await nd_eval(page, '6*7')                    # sync expr
      v     = await nd_eval(page, 'async()=>{...}', is_async=True)   # awaits the promise
      title = await nd_clear_wall(page)
      cks   = await nd_cookies(b)                           # [{name,value,domain,path}] for curl

sync convenience:
  html, cookies = nd_fetch(url)                            # launch, clear the wall, return both

CLI: lib_browser_nd.py selfcheck   (launches headless, proves sync + async eval == 42)
"""
import sys, time
from contextlib import asynccontextmanager

try:
    import nodriver as uc
except ImportError:                                        # pragma: no cover
    uc = None

NDARGS = ["--no-sandbox", "--disable-dev-shm-usage"]
WALLS = ("just a moment", "checking your browser", "attention required", "challenge",
         "verifying you are human", "one more step")


@asynccontextmanager
async def nd_browser(headless=True, extra_args=None):
    b = await uc.start(headless=headless, browser_args=NDARGS + (extra_args or []))
    try:
        yield b
    finally:
        try:
            b.stop()
        except Exception:
            pass


async def nd_eval(page, expr, is_async=False):
    """Correct nodriver eval. is_async=True awaits the returned promise (await_promise) - the
    fix for evaluate() silently returning None on an async IIFE. An async arrow is auto-wrapped
    into a call: 'async()=>{...}' -> '(async()=>{...})()'."""
    if is_async:
        e = expr.strip()
        # wrap an async ARROW into a call, unless it is already invoked ( ...)() ). Keying on
        # "starts async + has =>" (not "doesn't end in )") is what makes a concise body ending
        # in ) - `async()=>fetch(x)` or `async()=>(6*7)` - get called instead of silently None.
        if e.startswith("async") and "=>" in e and not e.endswith(")()"):
            expr = f"({e})()"
        return await page.evaluate(expr, await_promise=True)
    return await page.evaluate(expr)


async def nd_clear_wall(page, timeout=45):
    """Load-time wait past a CF/DataDome/Kasada interstitial (the tab is already at the URL)."""
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        try:
            t = await page.evaluate("document.title")
            last = t or last
        except Exception:
            t = ""                                   # nav in flight; retry next loop
        if not any(w in (t or "").lower() for w in WALLS):
            break
        await page.sleep(1.5)
    try:
        return await page.evaluate("document.title")  # guard the final read too (nav race)
    except Exception:
        return last


async def nd_cookies(browser):
    """Cookies as plain dicts (a lib_browser storage_state 'cookies' list) for curl handoff."""
    out = []
    for c in await browser.cookies.get_all():
        out.append({"name": c.name, "value": c.value, "domain": getattr(c, "domain", None),
                    "path": getattr(c, "path", "/")})
    return out


def _quiet_loop():
    loop = uc.loop()
    loop.set_exception_handler(lambda l, c: None)   # swallow nodriver's teardown noise
    return loop


def nd_fetch(url, headless=True, clear=True):
    """Sync convenience: launch nodriver, clear the wall, return (page_html, cookies)."""
    async def _run():
        async with nd_browser(headless=headless) as b:
            page = await b.get(url)
            if clear:
                await nd_clear_wall(page)
            html = await page.evaluate("document.documentElement.outerHTML")
            return html, await nd_cookies(b)
    return _quiet_loop().run_until_complete(_run())


def _selfcheck():
    if uc is None:
        print("nodriver not installed - skip")
        return

    async def _t():
        async with nd_browser(headless=True) as b:
            p = await b.get("about:blank")
            assert await nd_eval(p, "6*7") == 42, "sync eval"
            r = await nd_eval(p, "async()=>{ await new Promise(r=>setTimeout(r,5)); return 6*7; }", is_async=True)
            assert r == 42, f"async eval returned {r!r} (the None gotcha)"
            # concise-body arrow ending in ) must also get called, not return None
            r2 = await nd_eval(p, "async()=>(6*7)", is_async=True)
            assert r2 == 42, f"concise-body async arrow returned {r2!r}"
        return True

    _quiet_loop().run_until_complete(_t())
    print("SELFCHECK OK  nodriver sync + async(await_promise) eval == 42")


def main(argv):
    if argv and argv[0] == "selfcheck":
        return _selfcheck()
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
