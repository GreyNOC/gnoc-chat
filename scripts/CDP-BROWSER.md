# CDP BROWSER BRIDGE

Drive the operator's live, already-authenticated Chrome over the Chrome DevTools Protocol.
Reuse his Google, HackerOne, and target sessions. No re-provisioning; no cold headless context.

## What it is

`scripts/cdp-chrome.sh` launches the operator's Chrome with `--remote-debugging-port=9222` and a
persistent profile (`~/.config/gnoc/chrome-profile`). Logins are saved once; every agent
call after that reuses them via `lib_browser.attach_cdp()`.

`scripts/bbtools/lib_browser.py` adds five CDP-aware calls:
- `attach_cdp(cdp_url)`: connect_over_cdp to the operator's Chrome; return (browser, context)
  reusing `browser.contexts[0]` (his authed session). If CDP is down, raises RuntimeError
  with a `CDP_DOWN: run scripts/cdp-chrome.sh` message, never a raw stacktrace.
- `cdp_fetch(url, method, body, headers, scope_file, cdp_url)`: scope-gate the URL, open a
  new ephemeral page in the operator's context, run `in_page_fetch`, return `{status, len, body,
  headers}`, close only that page. the operator's existing tabs are never touched. Single-shot only.
- `cdp_tabs(cdp_url)`: return a list of open tab URLs (so an agent can see what the operator
  has already logged into).
- `cdp_session(scope_file, cdp_url)` (context manager): open ONE persistent page in the operator's
  Chrome and yield it to the caller's `with` block. The page stays open across N sequential
  `in_page_fetch` calls so cart state, CSRF tokens, and session cookies survive a multi-step
  checkout walk. The page is closed only when the `with` block exits; the operator's other tabs are
  never touched. Use this instead of chaining multiple `cdp_fetch` calls for a flow that has
  state (cart -> checkout -> pay). Raises `RuntimeError(CDP_DOWN: ...)` gracefully.
- `cdp_authed_curl(scope_file, cdp_url)`: dumps the operator's Chrome cookies via `dump_state` into
  a `curl_cffi` Session (falls back to stdlib requests) for a fast multi-step authed walk
  without Playwright overhead per request. Returns the pre-loaded session. Raises
  `RuntimeError(CDP_DOWN: ...)` gracefully.

CLI subcommands:
```
python scripts/bbtools/lib_browser.py cdp-tabs [--cdp-url URL]
python scripts/bbtools/lib_browser.py cdp-fetch <url> --scope targets/<prog>/SCOPE.txt \
    [--method POST] [--body '{"x":1}'] [--cdp-url URL]
```

## Multi-step checkout walk (cdp_session)

`cdp_fetch` is single-shot: it opens a page, fires one fetch, closes the page. For a
multi-step flow (add-to-cart -> checkout -> pay) where the server binds state to the
session (cart ID, CSRF token, order reference), use `cdp_session` instead:

```python
from bbtools.lib_browser import cdp_session, in_page_fetch
import json

SCOPE = "targets/myshop/SCOPE.txt"
pm = stripe_test_pm()["success"]

with cdp_session(SCOPE) as page:
    cart = in_page_fetch(page, "https://shop.example.com/api/cart",
                         method="POST", body='{"product_id":"42","qty":1}',
                         scope_file=SCOPE)
    order = in_page_fetch(page, "https://shop.example.com/api/orders",
                          method="POST",
                          body=json.dumps({"payment_method": pm["number"],
                                           "cvc": pm["cvc"]}),
                          scope_file=SCOPE)
# page closes here; the operator's Chrome keeps running

order_id = json.loads(order["body"])["order_id"]
# order_id is now the BOLA target: point bola_discriminant at /api/orders/{order_id}
```

## Role split: CDP vs headless provision_pair

CDP (`cdp_session` / `cdp_fetch` / `cdp_authed_curl`) reuses the operator's ONE real logged-in
identity. It is the right tool for a single-session multi-step walk on a target the operator is
already authenticated to, not for provisioning independent researcher accounts.

For a buyer-vs-seller BOLA probe, provision BOTH accounts independently using the headless
path so neither account carries the operator's real session:

```python
from bbtools.lib_provision import provision_roles
from bbtools.lib_auth       import session_from_state

accounts = provision_roles("myshop", {
    "buyer":  "https://shop.example.com/signup",
    "seller": "https://shop.example.com/seller/signup",
}, scope_file=SCOPE)
s_buyer  = session_from_state(accounts["buyer"]["state_path"])
s_seller = session_from_state(accounts["seller"]["state_path"])
# s_buyer and s_seller are now independent curl_cffi sessions for the BOLA probe.
```

The headless provisioned accounts are the victim and attacker; `cdp_session` / the operator's
Chrome is only for a one-shot orchestrator confirm or a final PoC re-run (SPINE 7).

## How to start

```bash
scripts/cdp-chrome.sh          # idempotent; prints "CDP already up" if running
```

Log into Google, HackerOne, and any target ONCE in the Chrome window that opens.
The profile is persistent: logins survive reboot. Every subsequent agent call reuses them.

## Cookie-safety scope gate (CRITICAL)

the operator's Chrome holds his real Google and personal session cookies.

`cdp_fetch` ALWAYS runs `_scope_ok(url, scope_file)` BEFORE opening any page in his
context. An off-scope host raises `ValueError("OUT_OF_SCOPE <host>")` and aborts; his
cookies NEVER reach a third-party or attacker-controlled origin.

Agents MUST pass `scope_file=` pointing at `targets/<program>/SCOPE.txt`. Omitting it
bypasses the gate (acceptable only for a url you have already verified in scope by other
means, e.g., inside a tight PoC script that scope-checks externally).

## Tool division rule

| Tool | Owner | When to use |
|------|-------|-------------|
| Burp MCP `127.0.0.1:9876` | ORCHESTRATOR only | One-shot confirm, send_http1/2, generate_collaborator / get_collaborator (blind OOB). Workers cannot use it; ~79% of worker calls fail. |
| `curl_cffi` | WORKERS | Raw HTTP probes, JA3/TLS impersonation, fast loops. Default for all unauth and non-interactive probing. |
| `lib_browser.browser()` (headless) | WORKERS | Fresh/unauth flows, bot-wall clearance, DOM-XSS runtime, postMessage, CSWSH, SPA crawl. No prior session. |
| `lib_browser.cdp_fetch()` (this doc) | WORKERS | Authed / walled flows where the operator's live session is the key: targets he is already logged into, post-login XHR capture, flows behind a corporate SSO, walls his profile already cleared. |
| Plain `curl` | PoC only | Final copy-paste PoC in a report (reproducible by the triager). |

## When CDP vs headless `browser()`

Use CDP (`cdp_fetch` / `attach_cdp`) when:
- The endpoint requires a session the operator already holds (Google OAuth, HackerOne, target SSO).
- The target's bot-wall already trusts the operator's profile (it cleared once in the headed session).
- You need to capture XHR from inside a login-gated SPA without re-provisioning an account.

Use headless `browser()` when:
- The probe is unauthed or uses a self-provisioned researcher account.
- You need a fresh, clean context (no cross-contamination from the operator's sessions).
- Parallel workers need independent contexts (CDP is a single shared Chrome).

## Selfcheck

```bash
python3 scripts/bbtools/lib_browser.py selfcheck
```

The selfcheck verifies (no live Chrome required):
1. `playwright` import available (or a clear install hint).
2. `attach_cdp` on a down port raises `RuntimeError("CDP_DOWN: ...")` gracefully.
3. `cdp_fetch` refuses an off-scope URL with `ValueError("OUT_OF_SCOPE ...")`.
4. `cdp_session` on a down port raises `RuntimeError("CDP_DOWN: ...")` gracefully.
5. `cdp_authed_curl` on a down port raises `RuntimeError("CDP_DOWN: ...")` gracefully.

## Robust CDP primitive + Gmail channel (2026-07-15)

`cdp_ws_call(method, params=None, url_match=None, cdp_url=...)` in `lib_browser` is THE way to talk
CDP - never hand-roll a raw socket or frame-reader. Gotchas it bakes in (each cost real debug time):

- **Bind address flips between Chrome builds - never hardcode one.** History: an older build bound
  **IPv6 `[::1]:9222` ONLY**. Re-verified 2026-09-30 on **Chrome for Testing 154.0.8037.92**: it now
  binds **IPv4 `127.0.0.1` ONLY, with zero IPv6 listeners** - `[::1]` FAILS on every port, `127.0.0.1`
  works (`ss -6tlnp | grep 922[2-5]` returns nothing). Because it has flipped once already, the rule
  below is load-bearing regardless of which family is current:
  connect to LITERAL IPs and TRY BOTH (`[::1]` then `127.0.0.1`), **never a hostname**.
  `websocket-client` given a *hostname* (`localhost`) resolves 127.0.0.1 first and **raises instead of
  falling through to `::1`**, so a hostname breaks on whichever family is not bound. `lib_browser`
  already walks `[::1]` -> `127.0.0.1` -> `localhost`; do NOT "simplify" that chain away.
  Re-check with `ss -tlnp | grep -E '922[2-5]'` after any Chrome upgrade.
  Note: Chrome echoes your Host header back in `webSocketDebuggerUrl`, so the ws URL you get depends on
  what you curled (`localhost` vs `127.0.0.1`) - same browser, cosmetic difference only.

- **Four browsers now, not one.** `main` 9222 (operator's authed identity, the port this whole doc
  assumes), `attacker` 9223, `victim` 9224, `clean` 9225 (unauth negative control, profile wiped each
  launch). Bring them up with `LAUNCH` (see `scripts/LAUNCH.md`); `cdp-chrome.sh` still starts `main`
  alone, unchanged. Isolated profiles are what make the distinct-victim gate real: an access-control
  finding proven from a single cookie jar is not proven. Pass `cdp_url` to target a non-default port.
  `LAUNCH status` reports **FOREIGN** if something other than our profile holds a port - treat that as
  "evidence would come from the wrong identity", not as "up".
- Chrome >=111 rejects a CDP websocket with a non-allowlisted **Origin** -> `suppress_origin=True`.
- The first server frame can arrive with the handshake buffer; hand-rolled readers drop it.
  `websocket-client` + "skip event frames until our id returns" handles it.

`url_match=<page-url-substr>` targets a page (Runtime.evaluate); omit it for the browser target
(Storage.getCookies). `cdp_authed_curl(host=)` builds an authed `curl_cffi` session from the operator's
live cookies (host= = least-privilege filter). Read the provisioning inbox with `gmail_read.py`
(CDP snippet) / `gmail_imap.py` (full body) / `gmail_read.py confirm` (auto-activate).
