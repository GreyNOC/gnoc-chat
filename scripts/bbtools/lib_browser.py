#!/usr/bin/env python3
"""
lib_browser.py - hardened headless browser for bug-bounty runtime confirmation.

WHY: ~80% of hunt pain clusters in unauth + account + browser. curl is blind to
DOM-XSS/postMessage/CSR-forms; nodriver's evaluate() silently returns None on an
async IIFE; CF/DataDome interstitials block a cold Playwright; a cleared session is
thrown away instead of handed to curl. This centralizes the fixes:

  - browser()        stealth context, proxy-aware (routes through Burp for capture)
  - eval_async()     ACTUALLY returns an async result (the nodriver-None gotcha)
  - clear_wall()     load past a CF/DataDome JS interstitial, then reuse the cookies
  - fill_form()      drive a client-side-rendered form curl cannot see
  - in_page_fetch()  fetch from inside the cleared origin (past a JA3/CORS wall)
  - capture_xhr()    lift the token/response the page fetched
  - dump_state()     storage_state.json so curl/curl_cffi replays the cleared session

CDP BRIDGE (the operator's live authed Chrome - scope-gated cookie safety):
  - attach_cdp()     connect to the operator's running Chrome over CDP; reuse their session
  - cdp_fetch()      scope-gated in_page_fetch through the operator's live context
  - cdp_tabs()       list the operator's open tab URLs

SECURITY: cdp_fetch ALWAYS scope-gates the target URL before opening a page in
the operator's context. Their real Google/personal cookies NEVER reach an off-scope host.
The bridge NEVER closes the operator's browser or their existing tabs.

Browser egress on the hunt box goes through the proxy. Pass --proxy http://host:port
or set BB_PROXY; default is direct (real sessions have egress, the sandbox does not).

CLI:
  lib_browser.py open <url> [--head] [--state f.json]        clear wall, dump storage_state
  lib_browser.py fetch <url> --state f.json [--method POST] [--body '..']   in-page fetch
  lib_browser.py cdp-tabs [--cdp-url URL]                    list the operator's open tab URLs
  lib_browser.py cdp-fetch <url> --scope SCOPE.txt [--method M] [--body B] [--cdp-url URL]
  lib_browser.py selfcheck                                   offline logic check (no network)
"""
import json, os, sys, tempfile, time
from contextlib import contextmanager

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None  # CDP functions give a clear install hint at call time

_CDP_DEFAULT = "http://localhost:9222"  # localhost = v4+v6; cdp-chrome.sh Chrome binds [::1] only, 127.0.0.1 misses it

STEALTH_ARGS = ["--no-sandbox", "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled"]
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0.0.0 Safari/537.36")
# the well-known fingerprint evasions bot-walls (DataDome/Kasada/PerimeterX) check
STEALTH_JS = r"""
Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
Object.defineProperty(navigator,'languages',{get:()=>['en-US','en']});
Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});
window.chrome = window.chrome || {runtime:{}};
try {
  const q = navigator.permissions && navigator.permissions.query;
  if (q) navigator.permissions.query = (p) => (p && p.name === 'notifications')
      ? Promise.resolve({state: Notification.permission}) : q.call(navigator.permissions, p);
} catch (e) {}
"""


def _proxy(arg=None):
    p = arg or os.environ.get("BB_PROXY")
    return {"server": p} if p else None


# Schemes that are NOT a network request to a target host and therefore cannot be
# scope-gated: there is no host to match. `about:blank` is the neutral origin a fresh
# page opens on; `data:` is how an attacker-origin page is staged for postMessage and
# cross-origin tests (origin "null"); `blob:`/`chrome*:` are browser-internal.
# FIX 2026-10-03: cdp_session() pre-flighted `about:blank` through this gate, so it
# raised OUT_OF_SCOPE about:blank and died on open for EVERY caller. A worker hit that
# live and had to fall back to attach_cdp with its own gate. Exempting the scheme class
# fixes it without widening scope: these URLs reach no target, and every real URL inside
# the session is still gated individually by in_page_fetch(scope_file=...).
_NEUTRAL_SCHEMES = ("about:", "data:", "blob:", "chrome:", "chrome-extension:", "javascript:")


def _scope_ok(url, scope_file):
    """Gate a browser probe against SCOPE.txt (the workspace rule: scope-gate every network
    probe). No-op if scope_file is None. Raises ValueError('OUT_OF_SCOPE ...') otherwise.

    A neutral, non-network scheme (about:/data:/blob:/chrome:) is exempt because it names
    no host to check; the network requests such a page then makes are gated on their own.
    """
    if not scope_file:
        return
    u = (url or "").strip().lower()
    if u.startswith(_NEUTRAL_SCHEMES):
        return
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from bbtools.lib_scope import in_scope
    if not in_scope(url, scope_file):
        raise ValueError(f"OUT_OF_SCOPE {url}")


_SLOT_DIR = os.path.join(os.environ.get("WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
                         ".claude/state/browser-budget/slots")


@contextmanager
def _slot(timeout=180):
    """Hold one of BB_MAX_BROWSERS launch slots for the life of a browser.

    WHY (receipt 2026-11-08): a lane looped browser launches and put 237 Chromium
    instances through one boot, three of them multi-GB. No OOM fired; the Wayland
    compositor wedged and the desktop needed a hard reboot mid-filing. The process
    watchdog (scripts/browser-budget.py) is the backstop that catches ANY launcher,
    including a script that imports playwright directly. This is the cooperative half:
    code that comes through lib_browser WAITS for a free slot instead of piling up and
    being reaped, which is both gentler and keeps a lane's work intact.

    An exclusive O_CREAT|O_EXCL file per slot is the lock; a slot whose owner pid is
    gone is reclaimed, so a crashed lane cannot leak capacity forever.
    """
    cap = int(os.environ.get("BB_MAX_BROWSERS", "3"))
    os.makedirs(_SLOT_DIR, exist_ok=True)
    deadline = time.time() + timeout
    held = None
    while held is None:
        for i in range(cap):
            path = os.path.join(_SLOT_DIR, f"slot{i}")
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
                os.write(fd, f"{os.getpid()}\n".encode())
                os.close(fd)
                held = path
                break
            except FileExistsError:
                try:
                    with open(path) as fh:
                        owner = fh.read().strip().split("\n")[0]
                except OSError:
                    continue
                if owner.isdigit() and not os.path.exists(f"/proc/{owner}"):
                    try:
                        os.unlink(path)   # stale: the owner died without releasing
                    except OSError:
                        pass
        if held is None:
            if time.time() > deadline:
                raise RuntimeError(
                    f"browser budget: all {cap} launch slots busy for {timeout}s. "
                    f"Another lane is holding them - check "
                    f"`scripts/browser-budget.py status`. Raise BB_MAX_BROWSERS only "
                    f"if you know the desktop can take it (237 instances froze it once)."
                )
            time.sleep(0.5)
    try:
        yield
    finally:
        try:
            os.unlink(held)
        except OSError:
            pass


@contextmanager
def browser(headless=True, proxy=None, state=None):
    """Stealth Playwright context. `state` = a storage_state.json to reuse a cleared
    session (bot-wall cookies, login). Yields the BrowserContext.

    Holds one of BB_MAX_BROWSERS launch slots (see _slot) so a loop over this helper
    cannot swarm the desktop."""
    with _slot(), sync_playwright() as pw:
        b = pw.chromium.launch(headless=headless, args=STEALTH_ARGS, proxy=_proxy(proxy))
        ctx = b.new_context(user_agent=UA, ignore_https_errors=True, locale="en-US",
                            viewport={"width": 1366, "height": 768},
                            storage_state=state if state and os.path.exists(state) else None)
        ctx.add_init_script(STEALTH_JS)
        try:
            yield ctx
        finally:
            b.close()


def eval_async(page, expr):
    """Return the result of an async expr. Playwright's evaluate awaits promises
    natively - THE fix for nodriver's evaluate() returning None on `(async()=>{})()`.
    Pass an async arrow: eval_async(page, 'async()=>{ await x; return v }')."""
    return page.evaluate(expr)


CLEARANCE_COOKIES = ("cf_clearance", "datadome", "_abck", "_px", "ak_bmsc", "reese84")


def clear_wall(page, url, ready_sel=None, timeout=45000, clearance_cookies=CLEARANCE_COOKIES,
               scope_file=None):
    """Load url and wait past a CF/DataDome/Akamai JS interstitial. Returns the final title.
    'Cleared' = the challenge title is gone OR a clearance cookie (cf_clearance/datadome/_abck)
    appeared (the reliable tell; a title can lag). After this the context holds the clearance
    cookies - dump_state() them so every later request (browser or curl) rides through.
    Pass scope_file to scope-gate the URL."""
    _scope_ok(url, scope_file)
    page.goto(url, wait_until="domcontentloaded", timeout=timeout)
    end = time.time() + timeout / 1000
    walls = ("just a moment", "checking your browser", "attention required", "challenge",
             "verifying you are human", "one more step")
    want = set(clearance_cookies)
    while time.time() < end:
        try:
            if ready_sel and page.query_selector(ready_sel):
                break
            title = (page.title() or "").lower()          # can raise mid-navigation
        except Exception:
            page.wait_for_timeout(800)                    # a redirect is in flight; settle + retry
            continue
        if not any(w in title for w in walls):
            break
        try:
            if want & {c["name"] for c in page.context.cookies()}:
                break
        except Exception:
            pass
        page.wait_for_timeout(1500)
    try:
        return page.title()
    except Exception:
        return ""


def fill_form(page, fields, submit_sel=None, wait="networkidle"):
    """Fill a client-side-rendered form curl can't see. fields = {css_selector: value}."""
    for sel, val in fields.items():
        page.fill(sel, val)
    if submit_sel:
        page.click(submit_sel)
    else:
        page.keyboard.press("Enter")
    if wait:
        page.wait_for_load_state(wait)


def capture_xhr(page):
    """Attach a sink; returns a list that fills with {url,status,body} for XHR/fetch.
    Read it AFTER driving the flow to lift a token the page fetched past a JA3 wall."""
    out = []

    def on_resp(r):
        try:
            if r.request.resource_type in ("xhr", "fetch"):
                out.append({"url": r.url, "status": r.status, "body": r.text()[:4000]})
        except Exception:
            pass

    page.on("response", on_resp)
    return out


def in_page_fetch(page, url, method="GET", body=None, headers=None, scope_file=None):
    """fetch() from inside the page origin - rides the cleared cookies + real browser
    TLS, so it reaches an endpoint that JA3/CORS-blocks curl. Returns {status,len,body,headers}.
    Pass scope_file to scope-gate the URL."""
    _scope_ok(url, scope_file)
    js = """async ({u,m,b,h}) => {
        const r = await fetch(u, {method:m, body:b||undefined, headers:h||{}, credentials:'include'});
        const t = await r.text();
        return {status:r.status, len:t.length, body:t.slice(0,8000),
                headers:Object.fromEntries(r.headers.entries())};
    }"""
    return page.evaluate(js, {"u": url, "m": method, "b": body, "h": headers})


def dump_state(ctx, path):
    """Write storage_state (cookies + localStorage) for curl/curl_cffi replay."""
    ctx.storage_state(path=path)
    return path


# ---------------------------------------------------------------------------
# CDP BRIDGE - drive the operator's live, already-authenticated Chrome
# ---------------------------------------------------------------------------

def _require_playwright():
    """Raise with an install hint if playwright is not importable."""
    if sync_playwright is None:
        raise ImportError(
            "playwright is not installed. Run: pip install playwright && playwright install chromium"
        )


def attach_cdp(cdp_url=_CDP_DEFAULT):
    """Connect to the operator's running Chrome over CDP and return (browser, context).

    Reuses browser.contexts[0] (the operator's authed session) when present, else opens a
    new context.  If the CDP endpoint is not up, raises RuntimeError with a clear
    'CDP_DOWN: ...' message instead of a raw stacktrace.

    the operator starts Chrome once with:
        scripts/cdp-chrome.sh
    and logs into Google / HackerOne / targets once.  Every agent call after that
    reuses those sessions with no re-provisioning.
    """
    _require_playwright()
    from playwright.sync_api import sync_playwright as _sw
    try:
        pw = _sw().start()
    except Exception as e:
        raise RuntimeError(
            f"CDP_DOWN: could not start playwright - {e}. "
            "Run: pip install playwright && playwright install chromium"
        ) from e
    # cdp-chrome.sh Chrome may bind IPv6 [::1] OR IPv4 127.0.0.1 by version; playwright's
    # node client does not try both, so attempt each loopback form (ECONNREFUSED is fast).
    def _swap(u, h):
        for tok in ("[::1]", "127.0.0.1", "localhost"):
            if tok in u:
                return u.replace(tok, h)
        return u
    cands, seen = [], set()
    for h in (None, "[::1]", "127.0.0.1", "localhost"):
        u = cdp_url if h is None else _swap(cdp_url, h)
        if u not in seen:
            seen.add(u)
            cands.append(u)
    browser, last = None, None
    for u in cands:
        try:
            browser = pw.chromium.connect_over_cdp(u)
            break
        except Exception as ex:
            last = ex
    if browser is None:
        pw.stop()
        raise RuntimeError(
            "CDP_DOWN: cannot connect to any of %s (%s). "
            "Run: scripts/cdp-chrome.sh and log into Google/H1/targets once." % (cands, last)
        ) from last
    ctx = browser.contexts[0] if browser.contexts else browser.new_context()
    return browser, ctx


def cdp_fetch(url, method="GET", body=None, headers=None, scope_file=None,
              cdp_url=_CDP_DEFAULT):
    """Run in_page_fetch through the operator's live authed Chrome context.

    SECURITY: scope-gates url against scope_file BEFORE touching the operator's browser.
    Their real Google/personal cookies never reach an off-scope host.
    Opens a NEW ephemeral page; closes ONLY that page when done.
    the operator's existing tabs are never touched.

    Returns {status, len, body, headers} or raises ValueError('OUT_OF_SCOPE ...').
    """
    _scope_ok(url, scope_file)   # hard block; raises ValueError on out-of-scope
    browser, ctx = attach_cdp(cdp_url)
    page = ctx.new_page()
    try:
        # Navigate to origin first so same-origin fetch has the right context
        origin = "/".join(url.split("/")[:3])
        try:
            page.goto(origin, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            pass  # best-effort; in_page_fetch will still work from about:blank
        result = in_page_fetch(page, url, method=method, body=body,
                               headers=headers, scope_file=scope_file)
    finally:
        try:
            page.close()
        except Exception:
            pass
        # NEVER close browser or ctx - the operator's session must survive
    return result


def cdp_tabs(cdp_url=_CDP_DEFAULT):
    """List URLs of all open tabs in the operator's Chrome (so an agent can see what the user
    has already logged into). Returns a list of URL strings."""
    browser, ctx = attach_cdp(cdp_url)
    urls = []
    for page in ctx.pages:
        try:
            urls.append(page.url)
        except Exception:
            pass
    # Do NOT close the browser; just return
    return urls


@contextmanager
def cdp_session(scope_file=None, cdp_url=_CDP_DEFAULT):
    """Yield a PERSISTENT page handle in the operator's live Chrome for a multi-step walk.

    Unlike cdp_fetch (which opens and immediately closes an ephemeral page), this
    context manager keeps the page open so the caller can run N sequential in-page
    fetches while retaining cart state, CSRF tokens, and session cookies across steps.
    The page is closed ONLY when the caller's `with` block exits.  the operator's other tabs
    and their Chrome session are never touched.

    SECURITY: scope_file is checked at open time.  Every in_page_fetch call inside the
    block should also pass scope_file so individual URLs are gated before they fire.

    Usage
    -----
    with cdp_session("targets/myshop/SCOPE.txt") as page:
        result1 = in_page_fetch(page, "https://shop.example.com/cart", method="POST",
                                body='{"product_id":"42"}', scope_file=SCOPE)
        result2 = in_page_fetch(page, "https://shop.example.com/checkout",
                                scope_file=SCOPE)
        result3 = in_page_fetch(page, "https://shop.example.com/pay", method="POST",
                                body=json.dumps(pay_body), scope_file=SCOPE)
    # page is closed here; the operator's other tabs untouched

    The page navigates to about:blank on open (a neutral origin that shares no cookies
    with any target, avoiding cross-origin contamination before the first in_page_fetch
    navigates to the target origin).

    Raises
    ------
    RuntimeError  if CDP is not reachable (with CDP_DOWN prefix + install hint).
    ValueError    if scope_file is set and a pre-flight URL check fails.
    """
    _scope_ok("about:blank", scope_file) if scope_file else None   # pre-flight pass on blank
    b, ctx = attach_cdp(cdp_url)
    page = ctx.new_page()
    try:
        page.goto("about:blank", wait_until="domcontentloaded", timeout=10000)
    except Exception:
        pass  # best-effort; the page is still usable
    try:
        yield page
    finally:
        try:
            page.close()
        except Exception:
            pass
        # NEVER close browser or ctx


def cdp_authed_curl(scope_file=None, cdp_url=_CDP_DEFAULT, host=None):
    """Dump the operator's cookies from their live Chrome into a curl_cffi (or requests) session.

    Calls dump_state on the operator's Chrome context to extract cookies + localStorage, then
    loads them into a session_from_state-compatible requests session for a fast multi-step
    authed walk (no Playwright overhead per request).

    SECURITY: scope_file must be passed for any subsequent session.request() calls that
    use lib_egress (the session itself is not scope-gated here; the scope gate fires inside
    authed_session / make_session when the caller routes through those helpers).

    Returns a curl_cffi requests.Session (or stdlib requests.Session if curl_cffi is not
    installed) pre-loaded with the operator's cookies for the target domain.

    Usage
    -----
    sess = cdp_authed_curl("targets/myshop/SCOPE.txt")
    r = sess.get("https://shop.example.com/api/orders/123")
    # r.text contains the order JSON with the operator's session auth

    Raises
    ------
    RuntimeError  if CDP is not reachable.
    """
    # raw-ws cookie dump: playwright connect_over_cdp HANGS attaching to the operator's busy live
    # Chrome; Storage.getCookies over the browser ws does not. Cookies only - a target that
    # keeps its auth token in localStorage needs the per-tab Runtime.evaluate path instead.
    cookies = _cdp_cookies_ws(cdp_url)
    if host:   # least-privilege: hand the agent ONLY the target host's cookies, not all of the operator's
        h = host.split("://")[-1].split("/")[0]

        def _match(dom):
            d = dom.lstrip(".")
            return bool(d) and (h == d or h.endswith("." + d) or d in h)
        cookies = [c for c in cookies if _match(c.get("domain", ""))]
    try:
        from curl_cffi import requests as _r
        sess = _r.Session(impersonate="chrome124")
    except ImportError:
        import requests as _r
        sess = _r.Session()
    for ck in cookies:
        sess.cookies.set(ck.get("name", ""), ck.get("value", ""),
                         domain=ck.get("domain", ""), path=ck.get("path", "/"))
    return sess


def cdp_ws_call(method, params=None, url_match=None, cdp_url=_CDP_DEFAULT, timeout=20):
    """ONE robust CDP-over-websocket call - USE THIS, never hand-roll a raw socket or CDP framing.

    Connects to LITERAL loopback IPs ([::1] then 127.0.0.1) so websocket-client never hard-fails a
    getaddrinfo on a hostname: cdp-chrome.sh's Chrome binds [::1] ONLY, and websocket-client does
    NOT fall through 127.0.0.1 -> [::1] the way socket.create_connection does (it raises on the
    first). Sends no Origin (Chrome >=111 rejects a foreign one -> 403 handshake). Reads frames via
    websocket-client, skipping CDP event frames until our id returns (the leftover-buffer trap that
    breaks hand-rolled readers). url_match = substring of a page URL to target that page
    (Runtime.evaluate ...); None = the browser target (Storage.getCookies ...). Returns the CDP
    'result' dict. Raises RuntimeError(CDP_DOWN) if no loopback answers."""
    import websocket, urllib.request
    port = cdp_url.rsplit(":", 1)[-1].split("/")[0]
    last = None
    for ip in ("[::1]", "127.0.0.1"):
        base = "http://%s:%s" % (ip, port)
        try:
            if url_match:
                tabs = json.load(urllib.request.urlopen(base + "/json", timeout=5))
                t = next((x for x in tabs
                          if url_match in x.get("url", "") and x.get("type") == "page"), None)
                if not t:
                    raise RuntimeError("no open page matching %r" % url_match)
                raw = t["webSocketDebuggerUrl"]
            else:
                raw = json.load(urllib.request.urlopen(
                    base + "/json/version", timeout=5))["webSocketDebuggerUrl"]
        except Exception as e:
            last = e
            continue
        # force the ws authority to the SAME literal IP (Chrome echoes localhost/[::1] in the URL)
        path = raw.split("://", 1)[1].split("/", 1)[1]
        ws = websocket.create_connection("ws://%s:%s/%s" % (ip, port, path),
                                         timeout=timeout, suppress_origin=True)
        try:
            ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
            m = {}
            while m.get("id") != 1:          # skip CDP event frames until our reply
                m = json.loads(ws.recv())
            if "error" in m:
                raise RuntimeError("CDP %s error: %s" % (method, m["error"]))
            return m.get("result", {})
        finally:
            ws.close()
    raise RuntimeError(
        "CDP_DOWN: no loopback answered on port %s (%s). Run scripts/cdp-chrome.sh." % (port, last))


def _cdp_cookies_ws(cdp_url=_CDP_DEFAULT):
    """All cookies from the operator's live Chrome (browser target) via cdp_ws_call. No playwright."""
    for mth in ("Storage.getCookies", "Network.getAllCookies"):
        ck = cdp_ws_call(mth, cdp_url=cdp_url).get("cookies")
        if ck is not None:
            return ck
    return []


def cswsh_probe(page, ws_url, wait_ms=4000):
    """Open a WebSocket to ws_url from the CURRENT page origin and capture connect +
    first frames. goto() an attacker/blank origin FIRST so Origin != target; a connect
    that returns authed data with a foreign Origin is CSWSH (curl cannot set a real
    browser Origin on a WS handshake)."""
    js = """([u,w]) => new Promise(res => {
        const out = {origin: location.origin, opened:false, msgs:[], error:null};
        let ws;
        try { ws = new WebSocket(u); } catch(e){ out.error = String(e); return res(out); }
        ws.onopen    = () => { out.opened = true; };
        ws.onmessage = (e) => { out.msgs.push(String(e.data).slice(0,500)); };
        ws.onerror   = () => { out.error = out.error || 'ws error'; };
        setTimeout(() => { try{ ws.close(); }catch(_){}; res(out); }, w);
    })"""
    return page.evaluate(js, [ws_url, wait_ms])


def postmessage_capture(page, url, wait_ms=5000):
    """Load url and record every window 'message' event (source origin + data). A sink
    that acts on data from any origin is the postMessage-XSS/ATO seam - curl-blind."""
    page.goto(url, wait_until="domcontentloaded")
    page.evaluate("""() => { window.__pm = []; addEventListener('message', e => {
        window.__pm.push({origin: e.origin,
                          data: (typeof e.data === 'string' ? e.data : JSON.stringify(e.data)).slice(0,500)});
    }); }""")
    page.wait_for_timeout(wait_ms)
    return page.evaluate("() => window.__pm || []")


def screenshot(page, path, full=True):
    """Evidence capture for a report receipt."""
    page.screenshot(path=path, full_page=full)
    return path


# runs post-render so it sees a client-side-rendered form curl reports as empty
_SIGNUP_JS = r"""() => {
    const fields = [...document.querySelectorAll('input,select,textarea')]
        .map(e => ({name: e.name||e.id||null, type: e.type||e.tagName.toLowerCase(),
                    required: !!e.required, placeholder: e.placeholder||null}))
        .filter(f => f.type !== 'hidden');
    const html = document.documentElement.innerHTML;
    const captcha = /hcaptcha|h-captcha/i.test(html) ? 'hcaptcha'
        : /turnstile|challenges\.cloudflare/i.test(html) ? 'turnstile'
        : /recaptcha|gstatic\.com\/recaptcha/i.test(html) ? 'recaptcha'
        : /arkose|funcaptcha/i.test(html) ? 'arkose' : null;
    const has = re => fields.some(f => re.test(f.name||'') || re.test(f.type||''));
    return {fields, captcha, emailField: has(/email/i), phoneField: has(/phone|tel|mobile/i),
            passwordField: has(/password|passwd|^pass$/i),
            submit: !!document.querySelector('button[type=submit],input[type=submit],button')};
}"""


_WALL_COOKIES = {"datadome": "DataDome", "cf_clearance": "Cloudflare", "__cf_bm": "Cloudflare",
                 "_abck": "Akamai", "ak_bmsc": "Akamai", "_px": "PerimeterX", "_px2": "PerimeterX",
                 "px": "PerimeterX", "reese84": "Incapsula", "visid_incap": "Incapsula"}
_WALL_SCRIPTS = [("datadome", "DataDome"), ("kasada", "Kasada"), ("kpsdk", "Kasada"),
                 ("perimeterx", "PerimeterX"), ("px-cdn", "PerimeterX"), ("hcaptcha", "hCaptcha"),
                 ("h-captcha", "hCaptcha"), ("recaptcha", "reCAPTCHA"), ("turnstile", "Cloudflare Turnstile"),
                 ("funcaptcha", "Arkose"), ("arkoselabs", "Arkose"), ("imperva", "Incapsula")]


def detect_wall(page):
    """Identify which bot-wall / captcha a page uses (cookies + script srcs + title), so you
    know whether Playwright-stealth clears it (CF/basic) or you need nodriver or a NEEDS-line
    (Kasada / DataDome / PerimeterX / Arkose rarely fall to a headless browser). Returns a
    sorted vendor list."""
    found = set()
    try:
        for c in page.context.cookies():
            v = _WALL_COOKIES.get(c["name"])
            if v:
                found.add(v)
    except Exception:
        pass
    try:
        html = (page.content() or "").lower()
        for needle, vendor in _WALL_SCRIPTS:
            if needle in html:
                found.add(vendor)
        if any(w in (page.title() or "").lower() for w in ("just a moment", "attention required")):
            found.add("Cloudflare")
    except Exception:
        pass
    return sorted(found)


def signup_recon(page, url, scope_file=None):
    """Load a signup/login page and report what a self-provision must handle: the form
    fields (even client-side-rendered ones curl can't see), the captcha vendor, and the
    likely verify channel. Turns 'no static HTML fields' into a provision plan:
    emailField + no captcha -> lib_provision.TempInbox; phoneField -> SMS wall (NEEDS or
    temp-SMS); captcha set -> drive it in-browser here, do not curl the register call.
    Pass scope_file to scope-gate the URL."""
    _scope_ok(url, scope_file)
    # domcontentloaded + settle, NOT networkidle: a heavy SPA (the CSR signups this targets) keeps
    # background requests open so networkidle never fires and goto times out.
    page.goto(url, wait_until="domcontentloaded", timeout=45000)
    page.wait_for_timeout(1800)                            # let the client-rendered form paint
    try:
        info = page.evaluate(_SIGNUP_JS)
    except Exception:
        page.wait_for_timeout(1000)                        # a late client redirect destroyed the context
        info = page.evaluate(_SIGNUP_JS)
    info["url"] = url
    return info


def _flags(argv):
    a, i = {}, 0
    while i < len(argv):
        if argv[i].startswith("--"):
            k = argv[i][2:]
            if i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                a[k] = argv[i + 1]; i += 2
            else:
                a[k] = True; i += 1
        else:
            i += 1
    return a


def _selfcheck():
    # --- CDP assertions run first (no live Chrome, no playwright binary required) ---
    # 1. _require_playwright raises ImportError with a clear install hint, not AttributeError
    try:
        _require_playwright()
        playwright_ok = True
    except ImportError as e:
        playwright_ok = False
        print(f"  INFO playwright not installed (headless checks skipped): {e}")

    # 2. attach_cdp on a definitely-down port raises RuntimeError with CDP_DOWN prefix
    try:
        attach_cdp("http://127.0.0.1:19222")  # guaranteed-down port in sandbox
        assert False, "attach_cdp should have raised on a down port"
    except RuntimeError as e:
        assert "CDP_DOWN" in str(e), f"expected CDP_DOWN in error, got: {e}"
    except ImportError:
        assert not playwright_ok, "playwright present but got ImportError from attach_cdp"

    # 3. cdp_fetch refuses an off-scope url (scope gate fires BEFORE touching Chrome)
    sfp_cdp = tempfile.NamedTemporaryFile(delete=False).name
    open(sfp_cdp, "w").write("example.com\n")
    try:
        cdp_fetch("https://evil.com/steal", scope_file=sfp_cdp)
        assert False, "cdp_fetch should have raised OUT_OF_SCOPE"
    except ValueError as e:
        assert "OUT_OF_SCOPE" in str(e), f"expected OUT_OF_SCOPE, got: {e}"
    finally:
        os.remove(sfp_cdp)

    # 4. cdp_session on a down port raises RuntimeError with CDP_DOWN prefix (no live Chrome)
    try:
        with cdp_session(cdp_url="http://127.0.0.1:19222"):
            pass
        assert False, "cdp_session should have raised on a down port"
    except RuntimeError as e:
        assert "CDP_DOWN" in str(e), f"expected CDP_DOWN in cdp_session error, got: {e}"
    except ImportError:
        assert not playwright_ok

    # 5. cdp_authed_curl on a down port raises RuntimeError with CDP_DOWN prefix
    try:
        cdp_authed_curl(cdp_url="http://127.0.0.1:19222")
        assert False, "cdp_authed_curl should have raised on a down port"
    except RuntimeError as e:
        assert "CDP_DOWN" in str(e), f"expected CDP_DOWN in cdp_authed_curl error, got: {e}"
    except ImportError:
        assert not playwright_ok

    print("  CDP assertions ok (import-hint, down-graceful, scope-gate, cdp_session-down, cdp_authed_curl-down)")

    if not playwright_ok:
        print("SELFCHECK PARTIAL  CDP ok; headless checks skipped (playwright not installed)")
        return

    # --- Headless playwright checks (require playwright binary) ---
    with browser(headless=True) as ctx:
        pg = ctx.new_page()
        # stealth init script applied on navigation
        pg.goto("about:blank")
        assert not pg.evaluate("() => navigator.webdriver"), "webdriver not hidden"
        assert "en-US" in (pg.evaluate("() => navigator.languages") or []), "languages not spoofed"
        # the load-bearing async-eval fix, verified offline
        assert eval_async(pg, "async()=>{ await new Promise(r=>setTimeout(r,5)); return 6*7; }") == 42
        # CSR form fill on a data page
        pg.set_content("<form><input id='u'><input id='p'></form>")
        pg.fill("#u", "alice")
        assert pg.input_value("#u") == "alice"
        # storage_state dump round-trips
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".json").name
        dump_state(ctx, f)
        assert os.path.exists(f) and "cookies" in json.loads(open(f).read())
        os.remove(f)
        # postMessage capture mechanism (offline: self-post on about:blank)
        pg.goto("about:blank")
        pg.evaluate("()=>{window.__pm=[];addEventListener('message',e=>window.__pm.push({origin:e.origin,data:e.data}))}")
        pg.evaluate("()=>postMessage('hello-pm','*')")
        pg.wait_for_timeout(50)
        assert any(m["data"] == "hello-pm" for m in pg.evaluate("()=>window.__pm")), "postMessage capture"
        # cswsh_probe returns cleanly on a dead ws (no crash, opened False)
        c = cswsh_probe(pg, "ws://127.0.0.1:1/nope", wait_ms=800)
        assert c["opened"] is False and "origin" in c, "cswsh probe"
        # screenshot writes a file
        sp = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
        screenshot(pg, sp, full=False)
        assert os.path.exists(sp) and os.path.getsize(sp) > 0
        os.remove(sp)
        # signup_recon extraction on a CSR-style form
        pg.set_content("<form><input name='email' type='email'><input name='pw' type='password'>"
                       "<div class='h-captcha'></div><button type='submit'>go</button></form>")
        si = pg.evaluate(_SIGNUP_JS)
        assert si["emailField"] and si["passwordField"] and si["captcha"] == "hcaptcha", si
        # detect_wall fingerprints vendors from script srcs
        pg.set_content("<script src='https://js.datadome.co/tags.js'></script>"
                       "<script src='https://js.hcaptcha.com/1/api.js'></script>")
        w = detect_wall(pg)
        assert "DataDome" in w and "hCaptcha" in w, w
    # scope gate raises on an out-of-scope url, passes an in-scope one
    sfp = tempfile.NamedTemporaryFile(delete=False).name
    open(sfp, "w").write("example.com\n")
    try:
        _scope_ok("https://evil.example/", sfp)
        raise SystemExit("scope gate did not fire on out-of-scope url")
    except ValueError:
        pass
    _scope_ok("https://example.com/x", sfp)
    os.remove(sfp)
    print("SELFCHECK OK  async-eval=42, form-fill, state-dump, postMessage, cswsh, screenshot, signup-recon, detect-wall, scope-gate, cdp-import, cdp-down-graceful, cdp-scope-gate, cdp_session-down, cdp_authed_curl-down ok")


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return
    cmd = argv[0]
    if cmd == "selfcheck":
        return _selfcheck()
    if cmd in ("open", "fetch"):
        url = argv[1]
        a = _flags(argv[2:])
        sf = a.get("scope")
        with browser(headless=not a.get("head"), proxy=a.get("proxy"), state=a.get("state")) as ctx:
            pg = ctx.new_page()
            if cmd == "open":
                print("TITLE:", clear_wall(pg, url, scope_file=sf))
                if a.get("state"):
                    dump_state(ctx, a["state"]); print("STATE saved:", a["state"])
            else:  # fetch
                clear_wall(pg, "/".join(url.split("/")[:3]), scope_file=sf)
                print(json.dumps(in_page_fetch(pg, url, a.get("method", "GET"), a.get("body"), scope_file=sf), indent=2))
        return
    if cmd == "cdp-tabs":
        a = _flags(argv[1:])
        tabs = cdp_tabs(a.get("cdp-url", _CDP_DEFAULT))
        for t in tabs:
            print(t)
        return
    if cmd == "cdp-fetch":
        if len(argv) < 2:
            print("usage: lib_browser.py cdp-fetch <url> --scope SCOPE.txt [--method M] [--body B] [--cdp-url URL]")
            return
        url = argv[1]
        a = _flags(argv[2:])
        result = cdp_fetch(url, method=a.get("method", "GET"), body=a.get("body"),
                           scope_file=a.get("scope"), cdp_url=a.get("cdp-url", _CDP_DEFAULT))
        print(json.dumps(result, indent=2))
        return
    if cmd == "cdp":
        # alias: cdp <subcommand> ...
        main(argv[1:])
        return
    print("unknown cmd:", cmd)
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
