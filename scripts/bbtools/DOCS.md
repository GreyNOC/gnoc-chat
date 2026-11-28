# bbtools reference manual

> **Burp proxy port is RESOLVED, not 8080.** `burp_proxy=True` and `bh`'s `via="auto"`
> resolve the listener of the Burp that owns the MCP port (9876) at call time via
> `burp_resolve.py`. A second Burp squatting 8080 captures into a history the
> orchestrator cannot read over MCP - that silent loss is why the hardcode is gone
> (2026-10-01). Check with `python3 scripts/bbtools/bh.py status`.

Shared, tested hunt tooling for the workspace 80%-pain zone: unauth surface, account
self-provisioning, and headless browser. Every lib self-checks; `selfcheck-all.sh` is 17 checks
GREEN on the local box and the VPS. Built and hardened 2026-07-10 (17 real bugs found by two
adversarial reviews plus dogfooding, all fixed and locked with self-check asserts).

> **Android apps:** in-scope APK intake, static mining and headless-AVD flow capture live in
> `scripts/workbench/droid.py` (`gnoc droid`), documented in `scripts/workbench/README.md`.

This file is the full reference. `README.md` is the one-screen index. `SESSION-2026-07-10-BBTOOLS-UPLIFT.md`
(under scripts/learn/) is the build log.

---

## START HERE for target HTTP

`bh` is the single front door for all target HTTP. Import one module; it auto-routes
through Burp (capture + scanner) when the proxy is up, falls back to direct curl_cffi
(JA3 preserved) when it is not, and re-exports race/active_scan/sitemap/macro so you
never need to import burp_ext separately.

```python
import sys; sys.path.insert(0, "scripts")
from bbtools.bh import req, race, active_scan

r = req("https://api.target.com/endpoint", scope_file="targets/x/SCOPE.txt")
# r = {status, len, body, headers, via_used}
# via="direct"  -> force curl_cffi (Akamai/DataDome JA3-walled targets)
# via="burp"    -> force Burp (raises if proxy is down)
```

For JA3-walled targets: `req(..., via="direct")`. For advanced Burp actions: `race()`,
`active_scan()`, `sitemap()`, `macro()` from the same import. For plain session use
without Burp auto-detect: use `lib_egress.make_session` directly (unchanged, no forced routing).

---

## 1. Quick start

```bash
# verify the whole toolkit (browser + real egress + web3), 17 checks
scripts/bbtools/selfcheck-all.sh              # -> ALL GREEN

# see the unauth -> provision -> BOLA chain run end to end on mocks
python3 scripts/bbtools/demo_chain.py
```

Import from Python (the workspace convention, `scripts/` on the path):
```python
import sys; sys.path.insert(0, "scripts")
from bbtools.lib_provision import TempInbox, simple_register, provision_pair, load_account
from bbtools.lib_unauth   import strip_auth_diff, classify, bypass_ladder
from bbtools.lib_auth     import wallet_login_evm, authed_session
from bbtools.bola_discriminant import run as bola_run
from bbtools.lib_browser  import browser, clear_wall, in_page_fetch, signup_recon, detect_wall, dump_state
from bbtools.race_burst   import burst_http, serial_control, count_ok
from bbtools.gql          import introspect, apq_probe, alias_batch
from bbtools.onchain      import connect, call, event_in_receipt
```

Dependencies (all present locally and on the VPS): `curl_cffi`, `playwright`, `nodriver`,
`web3`, `eth_account`, `substrate-interface`. `lib_scope` / `lib_egress` are the pre-existing
scope-gate + egress helpers these build on.

---

## 2. The worked chains (copy-paste recipes)

### Chain A - unauth -> authed 2nd account -> BOLA (the workflow most hunts skip; only ~42% ever provision)
```python
import sys; sys.path.insert(0, "scripts")
from bbtools.lib_provision import provision_pair, simple_register
from bbtools.lib_egress    import make_session
from bbtools.lib_auth      import authed_session
from bbtools.lib_unauth    import strip_auth_diff, bypass_ladder
from bbtools.bola_discriminant import run as bola_run

SCOPE  = "targets/<handle>/SCOPE.txt"
unauth = make_session(SCOPE)                                   # scope-gated, no session
leads  = strip_auth_diff(open("routes.txt").read().split(), unauth)   # SPA-200 discipline applied
# on any 403 lead: bypass_ladder(unauth, "https://host/forbidden")

# mint the two accounts the authed surface needs (email+password targets need no register_fn):
A, B  = provision_pair("<handle>", lambda ib: simple_register("https://host/register", inbox=ib))
sa, sb = authed_session(A, SCOPE), authed_session(B, SCOPE)    # sessions carrying each account's auth
cap = bola_run(sa, sb, whoami=my_whoami, obj_b_url=f".../obj/{B['id']}",
               write_body={"x": 1}, read_b_url=f".../obj/{B['id']}", revert_body={"x": 0})
# cap['distinct'] is gated FIRST; cap['read'] / cap['write'] carry B's own before/after receipts.
```

### Chain A2 - a CSR / CSRF-token / CF-walled signup that `simple_register` (curl) can't complete
```python
from bbtools.lib_provision import provision_pair_browser
from bbtools.lib_auth      import session_from_state
from bbtools.bola_discriminant import run as bola_run

SCOPE = "targets/<handle>/SCOPE.txt"
A, B = provision_pair_browser("<handle>", "https://app.target/signup", scope_file=SCOPE)
# each of A,B: {status, email, password, state_path, ...}. status 'ok'/'submitted' -> proceed;
# 'needs-captcha' -> if Turnstile/reCAPTCHA-v3, SOLVE it (headful + turnstile.render(sitekey,action) + 2captcha + gmail_read OTP; clone targets/kiwicom/.../bola-chain-B/); only hCaptcha-drag / Arkose / 'needs-sms' -> ONE NEEDS line. Do not NEEDS-park a solvable Turnstile.
sa, sb = session_from_state(A["state_path"]), session_from_state(B["state_path"])   # browser clears, curl probes
cap = bola_run(sa, sb, whoami=my_whoami, obj_b_url=f".../obj/{B['email']}", write_body={"x": 1})
# the browser did signup+verify+session-mint; curl carries the storage_state for the fast BOLA walk.
```

### Chain F - buyer -> cart -> test-pay -> order object (commerce BOLA/race entry point)
```python
import sys; sys.path.insert(0, "scripts")
from bbtools.lib_provision  import provision_pair, simple_register
from bbtools.lib_auth       import authed_session
from bbtools.lib_commerce   import stripe_test_pm, reach_checkout
from bbtools.bola_discriminant import run as bola_run

SCOPE = "targets/<handle>/SCOPE.txt"
# Mint buyer A and buyer B (or buyer + seller via roles param)
A, B = provision_pair("<handle>", lambda ib: simple_register("https://host/signup", inbox=ib))
sa, sb = authed_session(A, SCOPE), authed_session(B, SCOPE)

pm = stripe_test_pm()["success"]           # Visa 4242 - always succeeds in Stripe test mode

# A places a test order (captures the order object for the BOLA diff)
order_a = reach_checkout(
    sa,
    add_to_cart_url="https://host/api/cart",
    checkout_url="https://host/api/orders",
    pm=pm,
    scope_file=SCOPE,
    cart_body={"product_id": "1", "qty": 1},
    pay_body={"payment_method": pm["number"], "exp_month": pm["exp_month"],
              "exp_year": pm["exp_year"], "cvc": pm["cvc"]},
)
# order_a["order_id"] is the BOLA target for B
cap = bola_run(sb, sa, whoami=my_whoami,
               obj_b_url=f"https://host/api/orders/{order_a['order_id']}",
               read_b_url=f"https://host/api/orders/{order_a['order_id']}")
# cap['read'] = B (attacker) reading A's order -> the cross-user receipt.
```

### Chain A3 - cross-account ORDER read/write via bola_discriminant (seller-view BOLA)
```python
import sys; sys.path.insert(0, "scripts")
from bbtools.lib_provision  import provision_roles
from bbtools.lib_auth       import session_from_state
from bbtools.lib_commerce   import stripe_test_pm, reach_checkout
from bbtools.bola_discriminant import run as bola_run

SCOPE = "targets/<handle>/SCOPE.txt"
# Mint buyer + seller in their respective roles
accounts = provision_roles("<handle>", {
    "buyer":  "https://host/signup",
    "seller": "https://host/seller/signup",
}, scope_file=SCOPE)
s_buyer  = session_from_state(accounts["buyer"]["state_path"])
s_seller = session_from_state(accounts["seller"]["state_path"])

pm = stripe_test_pm()["success"]
order = reach_checkout(s_buyer, "https://host/api/cart", "https://host/api/orders",
                       pm=pm, scope_file=SCOPE,
                       cart_body={"product_id": "1", "qty": 1},
                       pay_body={"payment_method": pm["number"], "cvc": pm["cvc"]})

# Point bola_discriminant at /api/orders/{id} with seller as attacker, buyer as victim.
# Seller-view before: GET /api/orders/{id}/seller-view with s_seller -> should 403.
cap = bola_run(s_seller, s_buyer, whoami=my_whoami,
               obj_b_url=f"https://host/api/orders/{order['order_id']}/seller-view",
               read_b_url=f"https://host/api/orders/{order['order_id']}/seller-view",
               write_body={"status": "SHIPPED"})
# A seller-as-attacker read that returns buyer's PII (name/address/card-last4) = terminal receipt.
```

### Chain B - clear a bot-wall in the browser, then probe fast with curl
```python
from bbtools.lib_browser import browser, clear_wall, dump_state
from bbtools.lib_auth     import session_from_state
with browser(headless=True, proxy="http://127.0.0.1:8080") as ctx:  # proxy = capture in Burp
    pg = ctx.new_page()
    clear_wall(pg, "https://target/login", scope_file=SCOPE)         # past CF/DataDome
    dump_state(ctx, "state.json")                                    # cookies + localStorage
sess = session_from_state("state.json")                             # curl_cffi with the cleared session
# sess now probes at curl speed carrying the browser's clearance cookies.
```
If `detect_wall(pg)` reports Kasada / DataDome / PerimeterX (they fingerprint Playwright's CDP),
switch to the nodriver backend `lib_browser_nd` before deciding a NEEDS.

### Chain C - wallet sign-in replay (EIP-191 / SIWE; the hibachi #84332 paid class)
```python
from bbtools.lib_auth import wallet_login_evm, recover_evm, siwe_message
w = wallet_login_evm(server_challenge)                 # sign the server's exact challenge, disposable wallet
assert recover_evm(server_challenge, w["signature"]).lower() == w["address"].lower()
# the seam: build BOTH the honest SIWE message and a tampered one (drop nonce/domain/chainId)
# to prove the server binds a field it did not sign; terminal = the cross-user session mint.
```

### Chain D - race a single-use path (SIG-1, the #1 paid signature)
```python
from bbtools.race_burst import burst_http, serial_control, count_ok
req  = {"method": "POST", "url": "https://host/redeem", "json": {"code": "PROMO"}}
conc = count_ok(burst_http(req, n=30), lambda st: st == 200)       # the burst
ser  = count_ok(serial_control(lambda i: one_redeem(), 30), lambda r: r == "ok")  # the control
# race PROVEN only when conc > ser (concurrent lets K>1 through, serial exactly 1).
```

### Chain E - on-chain read + terminal-event gate (Immunefi)
```python
from bbtools.onchain import connect, call, impl_slot, event_in_receipt
w3 = connect("eth")                                    # keyless drpc RPC
px = call(w3, POOL, "slot0()((uint160,int24,uint16,uint16,uint16,uint8,bool))")  # tuple read
# in a fork PoC, gate success on the terminal event, never a print:
assert event_in_receipt(receipt, TRANSFER_TOPIC0), "terminal event absent -> not a finding"
```

---

## 3. Full reference (every public function)

### lib_provision.py  - account self-provisioning
- `class TempInbox(addr=None, prefix="dav")` - disposable mail.tm inbox. `.addr`, `.token`; `.poll(timeout,interval)` yields each message once; `.wait_for(pred,timeout)`; `.messages()`; `TempInbox.attach(token)` re-attaches to a stored inbox. Mint calls retry (mail.tm rate-limits) and force `Accept: application/json` (else mail.tm answers XML).
- `msg_body(msg)` / `links(msg)` / `codes(msg, n=6)` - email body + link/code extractors (null HTML parts safe).
- `unwrap(url)` - follow ONE click-tracking redirect (SendGrid /ls/click) to the real link; the raw oobCode/token is often only in the 302 Location.
- `firebase_emaillink(api_key, target_origin, inbox=None, timeout=180)` - fully-autonomous Firebase passwordless (EMAIL_LINK) provision -> verified idToken, no human inbox. Returns the identitytoolkit signInWithEmailLink JSON (idToken + _claims + _inbox) or {'error':...}.
- `simple_register(register_url, email=None, password="Passw0rd!x", session=None, extra=None, as_form=False, verify="auto", inbox=None, email_field="email", password_field="password", timeout=180)` - the 80%-common signup: POST email+password, poll the inbox, follow a verify LINK or return a verify CODE. Returns {email, inbox_token, register_status, verify_link, verify_code, verify_status}.
- `save_account(handle, tag, data)` / `load_account(handle, tag)` / `accounts_dir(handle)` - the mint-once-reuse store.
- `browser_register(signup_url, handle=None, tag=None, inbox=None, proxy=None, scope_file=None, overrides=None, submit_sel=None, verify="auto", headless=True, max_steps=3)` - THE account-creation workhorse when `simple_register` (curl) can't: a client-side-rendered form, a CSRF token, a CF/DataDome wall. Composes `clear_wall` -> selector-aware recon -> heuristic auto-fill (email/password/confirm/username/first+last-name/required-TOS-checkbox; skips a hidden CSRF token and a display:none honeypot) -> inbox verify-link follow -> `dump_state`. Drives a MULTI-STEP wizard signup (email -> Continue -> details) across up to `max_steps` pages, re-reconning each step and stopping when no new field appears (a validation re-render never loops). Returns `{status, email, password, username, state_path, verify_link, verify_status, captcha, fields}`. `status`: `ok` (verify followed or verify=none) | `submitted` (no verify email seen) | `needs-captcha` | `needs-sms` (a REQUIRED phone field, no free temp-SMS) | `error`. On a `needs-*` it does NOT grind - emit ONE `NEEDS:` line. Feed `state_path` straight to `lib_auth.session_from_state` for the authed curl session. `overrides={name_or_selector: value}` forces a field the heuristic missed.
- `provision_pair_browser(handle, signup_url, tags=("A","B"), roles=None, **kw)` - mint TWO accounts via `browser_register`; returns (A, B) each with a `state_path`. `roles=("https://host/buyer-signup","https://host/seller-signup")` overrides the URL per account so A and B land in DIFFERENT roles (one buyer, one seller). Default (roles=None) uses signup_url for both - the original behavior.
- `provision_pair(handle, register_fn, tags=("A","B"), timeout=180, roles=None)` - mint TWO accounts via a `register_fn(inbox)->dict`. `roles=(buyer_fn, seller_fn)` overrides the callable per account. Default (roles=None) uses register_fn for both.
- `provision_roles(handle, {role: signup_url}, **kw)` - mint one account per named role via `browser_register`; stores each under tag=role_name. Returns `{role_name: account_dict}`. The natural entry point for buyer+seller setups (Chain A3).
- CLI: `inbox` | `wait <token> [secs]` | `firebase <api_key> <origin>` | `register <signup_url> [--handle h --tag A --proxy p --scope f --head --verify none]` | `selfcheck`.

### lib_commerce.py  - test-payment instruments + checkout walk
- `stripe_test_pm()` - dict of canonical PUBLIC Stripe test instruments: `success` (4242...), `threeds` (3DS-required), `insufficient` (declined), `sepa` (IBAN DE89...). Use these verbatim; never a real PAN.
- `paypal_sandbox_buyer()` - placeholder shape for a Umbrella sandbox buyer login (email + password + dashboard URL); replace with the real sandbox account from the Umbrella Developer Dashboard.
- `reach_checkout(session, add_to_cart_url, checkout_url, pm, scope_file=None, ...)` - walk add-to-cart -> pay on an existing authed session. `add_to_cart_url=None` skips the cart step. Returns `{order_id, payment_status, receipt_bytes, cart_status, cart_bytes}`. Scope-gates both URLs before sending any request. `pay_body` / `cart_body` are caller-supplied (target-specific field names stay in the probe script). `extract_order_id(response)->str` can be passed as a custom extractor; default inspects a JSON body for common id keys.
- CLI: `test-pms` | `paypal-buyer` | `selfcheck`.

### lib_browser.py  - hardened headless (Playwright), proxy-aware
- `browser(headless=True, proxy=None, state=None)` - context manager, stealth context (webdriver/languages/plugins/chrome/permissions masked), `state=` a storage_state.json to REUSE a cleared session. proxy from arg or `$BB_PROXY`.
- `eval_async(page, expr)` - return an async expr's result (Playwright awaits promises; the fix for nodriver's None gotcha - use `lib_browser_nd.nd_eval` for the nodriver side).
- `clear_wall(page, url, ready_sel=None, timeout=45000, clearance_cookies=..., scope_file=None)` - load past a CF/DataDome/Akamai interstitial; "cleared" = title clean OR a clearance cookie (cf_clearance/datadome/_abck) appeared. Guards a mid-nav title race. Pass scope_file to scope-gate.
- `fill_form(page, fields, submit_sel=None, wait="networkidle")` - drive a client-side-rendered form curl can't see. fields = {css: value}.
- `in_page_fetch(page, url, method="GET", body=None, headers=None, scope_file=None)` - fetch() from inside the cleared origin, past a JA3/CORS wall. Returns {status, len, body, headers}.
- `capture_xhr(page)` - attach a sink; the returned list fills with {url,status,body} for XHR/fetch (lift a token the page fetched).
- `dump_state(ctx, path)` - write storage_state (cookies + localStorage) for curl_cffi replay.
- `cdp_session(scope_file=None, cdp_url=...)` - context manager yielding a PERSISTENT page in the operator's live Chrome. Keeps cart state / CSRF tokens / session cookies alive across N sequential `in_page_fetch` calls (a multi-step checkout walk). Closes only that page on exit; the operator's other tabs untouched. Raises `RuntimeError(CDP_DOWN: ...)` gracefully if Chrome is not reachable.
- `cdp_authed_curl(scope_file=None, cdp_url=..., host=None)` - raw-ws cookie dump (NOT playwright, which HANGS on the operator's busy live Chrome) into a `curl_cffi` Session for a fast authed walk. Pass `host=` for least-privilege (only that host's cookies, not all of the operator's). Cookies only; a localStorage-token target needs a page eval. Raises `RuntimeError(CDP_DOWN)`.
- `cdp_ws_call(method, params=None, url_match=None, cdp_url=...)` - THE robust CDP-over-websocket primitive; USE THIS, never hand-roll a socket/frame-reader. Literal-IP loopback ([::1] then 127.0.0.1 - websocket-client hard-fails on a hostname and will NOT fall through), no Origin (Chrome >=111 rejects one), skips CDP event frames. `url_match=<page-url-substr>` -> that page (Runtime.evaluate); None -> browser target (Storage.getCookies). Returns the CDP `result`.
- Gmail verify-link/OTP channel (provisioning): `gmail_read.py "<subj>" --wait N` (CDP, snippet), `gmail_imap.py "<subj>" --wait N` (full body, needs GMAIL_APP_PASS), `gmail_read.py confirm "<subj>" <host> --wait N` (auto-activate the account).
- `cswsh_probe(page, ws_url, wait_ms=4000)` - open a WebSocket from the current origin, capture connect + frames (CSWSH; curl-blind).
- `postmessage_capture(page, url, wait_ms=5000)` - record every window 'message' event (origin + data); the weak-origin postMessage seam.
- `screenshot(page, path, full=True)` - evidence.
- `detect_wall(page)` - name the bot-wall/captcha (DataDome, Kasada, Cloudflare, PerimeterX, Arkose, hCaptcha, reCAPTCHA) from cookies + script srcs + title; know clear-vs-NEEDS.
- `signup_recon(page, url, scope_file=None)` - report a signup page's fields (even CSR), captcha vendor, and verify channel = the provision plan. Uses domcontentloaded + settle (networkidle never fires on heavy SPAs).
- CLI: `open <url> [--head] [--state f] [--scope f] [--proxy p]` | `fetch <url> [--state] [--method] [--body] [--scope]` | `cdp-tabs` | `cdp-fetch <url> --scope f` | `selfcheck`.

### lib_browser_nd.py  - nodriver (undetected) backend
Use when `detect_wall` reports Kasada / DataDome / PerimeterX (they fingerprint Playwright's CDP). Async.
- `nd_browser(headless=True, extra_args=None)` - async context manager.
- `nd_eval(page, expr, is_async=False)` - correct nodriver eval; `is_async=True` awaits the promise (await_promise), auto-wrapping an async arrow into a call - the fix for evaluate() returning None on an async IIFE (including a concise body ending in `)`).
- `nd_clear_wall(page, timeout=45)` - wait past the interstitial (nav-race guarded).
- `nd_cookies(browser)` - cookies as dicts (a storage_state 'cookies' list) for curl handoff.
- `nd_fetch(url, headless=True, clear=True)` - sync convenience: launch, clear, return (page_html, cookies).
- CLI: `selfcheck` (launches headless, proves sync + async eval == 42).

### lib_unauth.py  - strip-auth diff + SPA-200 discipline + 403 bypass ladder
- `classify(unauth, sibling, authed=None, shell_len_tol=0.15)` - pure SPA-200 verdict: PROTECTED / REDIRECT / ABSENT / PUBLIC-SHELL (the SPA false-200, NOT a lead) / PRIVATE-BUT-OPEN (the lead) / PUBLIC-DATA. A 200 auth-error or empty body is not a lead; a large data body that merely contains "unauthorized" still is.
- `strip_auth_diff(routes, unauth_session, authed_session=None, method="GET")` - probe each route + a nonsense-sibling control (+ authed if given), classify, return rows leads-first.
- `nonsense_sibling(url)` - the 404-control (last path segment replaced with junk).
- `probe(session, url, method="GET", **kw)` / `resp_of(r)` / `is_html(resp)` - helpers.
- `bypass_variants(url, header_ip="127.0.0.1")` - the 403/401-bypass ladder: path-normalization (trailing-slash, `/.`, `//path`, `%2f`, `..;/`, case), header-spoof (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization), method-tamper (PUT/PATCH/HEAD/OPTIONS/TRACE). Returns [(label, method, url, headers)].
- `bypass_ladder(session, url, baseline_status=None, method="GET")` - fire the ladder; return the variants whose status beats the baseline.
- CLI: `diff <scope_file> <routes_file>` | `selfcheck`.

### lib_auth.py  - login strategies for the authed 2nd-account default
- `wallet_login_evm(challenge, priv=None)` - EIP-191 personal_sign a login challenge; priv=None mints a disposable wallet. Returns {address, signature, priv, challenge}.
- `recover_evm(challenge, signature)` - the verifier's ecrecover (and the self-test).
- `siwe_message(domain, address, uri, nonce, statement=..., chain_id=1, version="1", issued_at=...)` - canonical EIP-4361 string; build honest + tampered to prove a missing-signed-field replay.
- `wallet_login_substrate(challenge, seed=None, crypto="sr25519")` - SR25519/ED25519 sign-in; seed accepts None (mint), a 0x hex seed, a 12/15/18/21/24-word phrase, or a //Alice URI. Never echoes a provided secret.
- `session_from_state(state_json, impersonate="chrome124")` - curl_cffi session preloaded with a lib_browser storage_state (browser clears the wall, curl probes fast).
- `authed_session(account, scope_file=None, bearer=None, cookies=None, header_name="Authorization", impersonate="chrome124")` - the provision->BOLA bridge: build a session carrying an account dict's bearer/cookies. With scope_file it uses the scope-gated lib_egress session and RAISES on failure (never silently ungates).
- `form_login(session, url, fields, csrf_from=None, csrf_field="csrf", csrf_regex=None)` - cookie/CSRF form login (lifts the token from csrf_from first).
- CLI: `evm-sign <challenge> [priv]` | `substrate-sign <challenge>` | `selfcheck`.

### bola_discriminant.py  - the IDOR/BOLA terminal
- `assert_distinct(id_a, id_b)` - gate: raises unless both are resolved, DIFFERENT, and SCALAR (a dict whoami would compare-distinct for the same user and ship a false positive).
- `paired_read(sess_a, url_b, expect_field=None)` - A reads B's object -> the read receipt.
- `paired_write(sess_a, url_b, body, sess_b=None, read_b_url=None, method="PATCH")` - A mutates B's object; captures B's OWN before/after view.
- `run(sess_a, sess_b, whoami, obj_b_url, write_body=None, read_b_url=None, expect_field=None, method="PATCH", revert_body=None)` - full discipline: distinct-gate FIRST, then read, then reversible write. `whoami(session)->scalar id` is target-specific.
- CLI: `selfcheck`.

### race_burst.py  - concurrent burst + serial control
- `burst(fn, n=30, warmup=None)` - fire fn(i) on n Barrier-released threads; returns [(i, val_or_exc)].
- `burst_http(req, n=30, session_factory=None)` - n concurrent identical requests; req = {method,url,json?,data?,headers?}. Returns [(i, status, len, body[:200])].
- `serial_control(fn, n=30)` - the same N calls sequentially; the discriminant a race finding must carry.
- `count_ok(results, ok)` - count rows whose value (element [1]) satisfies ok(); works for burst() and burst_http() shapes.
- CLI: `selfcheck` (proves it creates a real overdraft race).

### gql.py  - GraphQL probe helper
- `gql(session, url, query=None, variables=None, headers=None, extensions=None)` - POST an op; returns {status, json|text}.
- `introspect(session, url, full=True)` - schema dump (or the minimal probe); returns {enabled, type_count, raw}.
- `apq_hash(query)` - Apollo persisted-query sha256.
- `apq_probe(session, url, query, variables=None)` - send the hash only; on PERSISTED_QUERY_NOT_FOUND register the query and replay. `register_on_miss` is True ONLY on a positive data resolve (a WAF/500/non-JSON replay does not fabricate the primitive) - the cache-deception / auth-bypass seam.
- `class Raw(str)` + `alias_batch(field, args_list, selection="id", var_prefix="a")` - N calls in ONE request (rate/oracle bypass); wrap an enum in `Raw('ADMIN')` so it renders unquoted.
- CLI: `selfcheck`.

### onchain.py  - EVM read + proof-integrity (Immunefi)
- `connect(chain="eth")` - web3 on a keyless drpc RPC (eth/base/arbitrum/optimism/polygon/bsc/berachain/avalanche/gnosis/blast, or a url).
- `call(w3, address, sig, *args)` - eth_call a view fn by human signature; handles tuple/struct types (e.g. `slot0()((uint160,int24,uint16))`).
- `impl_slot(w3, address)` - EIP-1967 implementation address (proxy detection; 0x0 if not that shape).
- `storage(w3, address, slot)` - raw storage read (hex).
- `event_in_receipt(receipt, topic0)` - is a terminal event present (gate a PoC on THIS, not a print); normalizes a bare-hex topic.
- `positive_control(fn, *args, **kw)` - run a known true-positive first; raise if it does not fire (prove the harness can observe before trusting a DEAD).
- CLI: `read <chain> <addr> <sig> [args...]` | `selfcheck`.

### demo_chain.py / selfcheck-all.sh
- `demo_chain.py` - runs Chain A end to end on mocks; also an interface-drift test across four libs.
- `selfcheck-all.sh` - runs every lib's self-check; ALL GREEN = tooling sound.

---

## 4. Gotchas baked in (were recurring failures)
- mail.tm content-negotiates on `Accept`; the chrome124 impersonate sends `Accept: text/html` so it answers XML -> lib forces `Accept: application/json`.
- nodriver `evaluate()` returns None on an async IIFE unless `await_promise=True`; `nd_eval` handles it (incl. a concise body ending in `)`).
- Playwright `wait_until="networkidle"` never fires on a heavy SPA (the CSR signups signup_recon targets) -> domcontentloaded + settle.
- Browser egress on the hunt box goes through the proxy (Burp); real sessions have egress, the sandbox does not. Route browser traffic through Burp with `--proxy` / `$BB_PROXY` to capture every request.
- An SPA returns 200 + index.html for every path -> classify's SPA-200 discipline (content-type + length-vs-nonsense-sibling + sibling-404) before flagging any unauth 200.

## 5. Limitations - when to self-provision vs NEEDS-line
`lib_provision` handles email+password signup, email verify (link OR code), and Firebase magic-link.
It does NOT handle (emit ONE `NEEDS:` line, do not grind a wall): SMS/phone-OTP verify (no reliable
free temp-SMS), an interactive Arkose/hCaptcha/Turnstile on the signup (detect with `signup_recon`
/ `detect_wall`; drive in-browser if solvable, else NEEDS), social-only signup (Google/Apple), and
KYC / gov-ID / paid-tier-no-trial. Kasada/DataDome/PerimeterX often beat a headless browser even
stealthy - `detect_wall` names the wall so the hunter chooses browser-vs-nodriver-vs-NEEDS.

## 6. Validation status (live-proven on real egress, not just mocks)
- provision: real mail.tm inbox mint; `browser_register` field-plan heuristic (email/pw/confirm/username/name/TOS map, hidden-CSRF + honeypot + optional-checkbox skip, required-phone -> needs-sms) + a live Playwright fill round-trip (extraction JS -> plan -> fill/check, values read back).
- lib_unauth: `classify` on example.com real bytes.
- gql: `introspect` on a real GraphQL endpoint (23 types).
- race_burst: `burst_http` 10/10 concurrent 200 on a real endpoint.
- lib_browser: real chromium launch + `clear_wall` + stealth verified on bot.sannysoft.com (webdriver hidden, languages/plugins spoofed); `signup_recon`+`detect_wall` on github.com/signup (DataDome+hCaptcha, 8 fields) and reddit.com/register (reCAPTCHA, 4 fields).
- lib_browser_nd: real headless launch, sync + async eval == 42.
- onchain: WETH decimals=18, symbol=WETH; Uniswap-V3 slot0 tuple (7 fields, tick 201384).
- lib_auth: EVM sign->recover round-trip, Substrate sign/verify, state-load.
- selfcheck-all: 17 checks GREEN on local AND VPS.

## 7. Hardening record (17 real bugs found + fixed + locked)
Two fresh-context adversarial reviews plus dogfooding against real signups found what the
happy-path self-checks missed. High-value examples (full list in the session log):
- bola distinct-gate defeated by a dict whoami (same user, diff session fields) -> reject non-scalar ids.
- gql apq `register_on_miss` false-positived on any non-JSON/WAF replay -> gate on positive data.
- onchain sig parser broke on tuple/struct types (Uniswap slot0 unreadable) -> depth-aware parser.
- race_burst count_ok crashed on burst_http 4-tuples -> takes element [1] for both shapes.
- lib_unauth classify flagged a 200 auth-error / empty JSON as PRIVATE-BUT-OPEN -> len + short-body auth-error screen.
- lib_unauth bypass double-slash emitted a trailing-slash dup -> real `//path`.
- lib_provision msg_body crashed on a null HTML part -> str-coerce + drop falsy.
- lib_auth substrate `seed` only took a mnemonic -> branches hex/phrase/uri; never echoes a provided secret.
- lib_auth authed_session silently dropped scope-gating on failure -> now raises.
- lib_browser had no scope-gate -> optional scope_file on clear_wall/in_page_fetch/signup_recon + CLI --scope.
- lib_browser_nd nd_eval concise-body async arrow ending in `)` returned None -> wrap-if-async-arrow.
- clear_wall / signup_recon crashed on a mid-nav title read + networkidle timeout on SPAs -> guarded + domcontentloaded.
- gql alias_batch quoted enums -> Raw('ADMIN') bare. onchain event_in_receipt missed a bare-hex topic -> 0x-normalized.

## 8. Agent wiring (which agent reaches for what)
- browser-hunter + browser-runtime skill -> lib_browser (+ nd), the gotchas.
- unauth-access-hunter + unauth-access-bypass skill -> lib_unauth (strip_auth_diff, classify, bypass_ladder) + provision + SPA-200.
- unauth-surface-mapper -> SPA-200 classify + FLAG-PROVISION handoff + CDN cache-metadata tell.
- idor-hunter -> provision_pair + authed_session + bola_discriminant.
- saml-jwt-hunter -> lib_auth wallet sign-in replay.
- oauth-hunter -> provision_pair + session_from_state.
- race-hunter -> race_burst (burst + serial control); commerce/coupon/wallet races use commerce_receipt.prove for the settled-balance terminal.
- graphql-hunter -> gql (introspect, apq_probe, alias_batch).
- triage-validator -> re-verify a finding with bola_discriminant.assert_distinct + lib_unauth.classify.
- recon-scout -> flag a signup/login/wallet surface as a provisioning entry.
- bizlogic-hunter -> commerce_receipt.prove (money-state terminal), commerce_tamper.tamper_matrix + confirm_diff (price/qty tamper matrix), commerce_webhook.forge_ladder_all (webhook forge), race_burst.burst_http (coupon/wallet race), lib_commerce (test payment instruments).
- CLAUDE.md "Shared tooling" section points the orchestrator at all of it.

### commerce_receipt.py - before/after money-state receipt harness (SPINE TERMINAL gate)
The terminal receipt every commerce finding needs. No submission without a captured delta.

- `set_scope(scope_file)` - set module-level SCOPE.txt; all subsequent calls enforce it.
- `snapshot(session, read_url, fields=None) -> dict` - GET the current account/wallet state; returns `{status, fields, raw_bytes, ts}`.
- `prove(session, read_url, action_fn, fields=None, expect="decrease"|"increase"|"change") -> dict` - snapshot before, run action_fn(session), snapshot after, compute per-field delta, set `confirmed=True` only when a real byte-delta passes the expect gate (mirrors bola_discriminant's `changed=before!=after` discipline); emits a copy-paste `capture.log` block to stdout. Returns `{before, after, action_status, action_bytes, delta, receipt_bytes, confirmed, log_block}`.
- `idem_replay(session, req, key, n=3, mutate=None, read_url=None, fields=None) -> rows` - replay `req` n times with the same idempotency key; optionally a mutated body on attempt n+1 (same key, different payload - tests key-to-resource binding). Scores each attempt against the settled state via snapshot.

### commerce_webhook.py - payment webhook / IPN HMAC forge ladder
- `stripe_sig(secret, body, ts=None) -> str` - Stripe-style `t=<ts>,v1=<HMAC-SHA256>` header.
- `svix_sig(secret, id, ts, body) -> str` - Svix/Clerk/Resend `v1,<base64(HMAC-SHA256)>` header.
- `github_sig(secret, body) -> str` / `hub_sig` - GitHub/Shopify `sha256=<hex>` header.
- `forge_ladder(body, secret=None) -> [(label, header_value)]` - hub-format forge runbook; empty-secret rung FIRST (deterministic public win), then null-byte, sha1-downgrade, known-secret. Try every rung against the webhook endpoint in a loop.
- `forge_ladder_all(body, secret=None) -> [(label, header_name, header_value)]` - same runbook across all three algorithm families (Stripe, Svix, GitHub) for a single-pass sweep.

### commerce_tamper.py - price/currency/quantity confirm-call tamper matrix
- `tamper_matrix(body, price_keys=DEFAULT_PRICE_KEYS) -> [(label, mutated_body)]` - generates the canonical tamper set (negative, zero, one-cent, overflow 99999999999/1e308, currency-swap INR/JPY/KRW, string-vs-int coercion, extra-precision, null, missing) for every matching key. Quantity keys get qty-specific variants; discount keys get zero/full/over/negative discount. Original body is never mutated; baseline is the first entry.
- `confirm_diff(session, confirm_url, matrix, receipt_read_url=None, scope_file=None, method="POST") -> rows` - fire each variant against the confirm/capture endpoint, scope-gate both URLs before sending any bytes, optionally capture settled state via commerce_receipt.snapshot after each call. Returns `[{label, body_sent, status, body_excerpt, settled_state, delta}]`.

## 9. Extending
Build lazily, when a hunt first needs it (do not pre-build): SMS-OTP provisioning (wire a provider),
onchain Substrate `submit_and_assert` (the EVM read/verify core is here). Every new public function
leaves ONE runnable self-check assertion; keep `selfcheck-all.sh` GREEN.

## 10. Network scope proxy + target SimHash (2026-10-23, XBOW items 11 and 7)

### scope_proxy.py + scripts/scope-proxy.sh - scope enforced on the wire
mitmproxy addon. Program, in the scope-gate.sh / lock-lib.sh order: env `HUNT_TARGET`, else this session's
`.claude/state/hunt-loop/LOCK.<sid>` (sid from `CLAUDE_CODE_SESSION_ID` / `CLAUDE_SESSION_ID` / `HUNT_SID`), else every `LOCK.<sid>`
present (if they name DIFFERENT programs the launcher refuses to start and the addon refuses everything: `ProgramConflict`), else the
global `LOCK`; none resolved = refuse everything. `python3 scripts/bbtools/scope_proxy.py resolve` prints what it would enforce.
Rules come from `lib_scope.program_allows` (SCOPE.txt + NOSCOPE.txt, NOSCOPE wins, third-party and internal IPs refused);
the toolchain allowlist is extracted from `TOOLCHAIN_RE` in `.claude/hooks/scope-gate.sh` at startup. Out of scope (checked on
CONNECT, on the URL host, the Host header AND the HTTP/2 `:authority`, and on the TLS SNI) gets a synthetic `403` with body `OUT_OF_SCOPE <host> (<program>)`,
no upstream socket (needs `connection_strategy=lazy`, which the launcher sets), and one line in
`.claude/state/hunt-loop/SCOPE-INCIDENTS.jsonl` `{ts, program, host, url, client_pid, reason}`. In-scope traffic passes untouched;
the addon never re-issues requests, so it chains with the JA3 proxy: `mitmdump -s scope_proxy.py -p 8084 --mode upstream:http://127.0.0.1:8083`.
- FAIL CLOSED (fix3 2026-10-23): any exception inside a decision refuses the flow (body `... (scope decision error)`, incident
  reason `decision-error <Type>`). mitmproxy logs an addon exception and lets the flow CONTINUE, so a raise was fail open: a
  `[evil.test]` Host made `lib_scope.extract_host` raise `ValueError`. `extract_host` now returns "" for any malformed or bracketed
  non-IP host and handles bracketed and bare IPv6 (zone id dropped, `::ffff:127.0.0.1` treated as 127.0.0.1 = internal-ip).
- STRICT (default `SCOPE_PROXY_STRICT=1`): `github.io` and `storage.googleapis.com` are dropped from the proxy's copy of the
  toolchain allowlist, because anyone can publish there (an exfil or C2 sink on the wire). The hook keeps its list unchanged for
  parity; `SCOPE_PROXY_STRICT=0` restores the hook's exact list for a toolchain fetch that needs them.
- `scripts/scope-proxy.sh start|stop|status [program]` - port 8084, pid `.claude/state/hunt-loop/scope-proxy.pid`, log `scope-proxy.log`.
  The system pyOpenSSL is too old for cryptography 50 (mitmdump fails to import); the launcher prepends `.claude/state/hunt-loop/pyossl`
  (`pip install --target .claude/state/hunt-loop/pyossl --no-deps 'pyOpenSSL>=25.3'`) when present.
- `export GNOC_SCOPE_PROXY=http://127.0.0.1:8084` makes `lib_egress.make_session` route through it; the python-side scope check still runs first.
  A Burp proxy setting wins the route, and code cannot chain Burp: on that route lib_egress makes the python gate MANDATORY (even with
  `scope_file=None` it checks the resolved program, fail closed) and prints one warning line. To proxy Burp traffic too, set Burp >
  Settings > Network > Connections > Upstream proxy servers: destination `*`, proxy `127.0.0.1:8084` (`scope-proxy.sh status` says so).
  Clients using curl directly: `curl -x http://127.0.0.1:8084 -k ...`.
- Test: `python3 scripts/bbtools/test_scope_proxy.py` (offline, fake flows; carries the reviewer's attacks: bracketed and forged
  Host / `:authority`, IPv6 forms, numeric IPs, STRICT hosts, an exception in the decision, conflicting session LOCKs).

### target_simhash.py - one model per cluster of cloned hosts
`simhash(resp)` = 64-bit SimHash over status, title, content-type and body 3-word shingles (tags, script/style, digits, hex runs and
random-looking tokens stripped, so CSP nonces and build hashes do not matter). `fingerprint_host(host, session)` fetches `/` once.
`python3 scripts/bbtools/target_simhash.py dedup <program> [hosts...]` clusters within Hamming 3 (single-link; failed fetches stay
singletons), writes `targets/<program>/recon/simhash.json`, prints one representative per cluster. Caveat: very small pages (under ~30 words)
move several bits on a one-line change, so a staging banner on a tiny page can split a cluster; read the printed titles.
Test: `python3 scripts/bbtools/test_target_simhash.py` (offline).

## PHONE_SOCKS (residential egress through the USB phone)
`PHONE_SOCKS=socks5h://127.0.0.1:1081` (kept up by pm2 `phone-link`; full doc `scripts/PHONE-EGRESS.md`; currently exits via home Wi-Fi AS7922 Comcast, NOT cellular, because the SIM is not attached).
- curl_cffi: `requests.get(url, impersonate="chrome124", proxies={"http": PHONE_SOCKS, "https": PHONE_SOCKS})`
- lib_browser: pass `proxy=PHONE_SOCKS` (same URL form)
- check: `/usr/bin/python3 scripts/phone-egress/verify.py`
