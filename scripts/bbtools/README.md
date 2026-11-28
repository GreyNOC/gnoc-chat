# bbtools - shared probe-script helpers

> Full reference manual (every function, worked chains, gotchas, validation, limitations): **DOCS.md**.
> Verify the whole toolkit: `scripts/bbtools/selfcheck-all.sh` (17 checks). Build log: `scripts/learn/SESSION-2026-07-10-BBTOOLS-UPLIFT.md`.

Created 2026-06-20 from the hunt-retrospective script-audit, which found the same logic
rewritten thousands of times across one-off probe scripts (2087 curl_cffi rewrites, 346
Cloudflare re-impls, 160 scope parsers, 1007 hardcoded sys.path.insert lines, 1517 GraphQL
rewrites, 833 BOLA, 395 race, 484 Substrate). Import these instead of re-solving the same
problem every hunt. The SPINE proof-integrity rules are baked into the tools so they cannot
be skipped (scope gate in the session, distinct-victim gate in the BOLA prober, etc).

## START HERE for target HTTP

`bh` is the single front door. Auto-routes through Burp when up, direct curl_cffi fallback
when not. Scope-gate fires first. One import covers plain HTTP + race + scan + sitemap.

```python
import sys; sys.path.insert(0, "scripts")
from bbtools.bh import req, race, active_scan
r = req("https://api.target.com/x", scope_file="targets/x/SCOPE.txt")
# r = {status, len, body, headers, via_used}
# via="direct" for JA3-walled (Akamai/DataDome); via="burp" to force proxy
```

CLI: `python3 scripts/bbtools/bh.py status` (which Burp surfaces are up),
`python3 scripts/bbtools/bh.py get <url> --scope targets/x/SCOPE.txt`,
`python3 scripts/bbtools/bh.py selfcheck` (offline, no Burp needed).

---

## Import
```python
import sys; sys.path.insert(0, "scripts")          # or: pip install -e scripts/  (later)
from bbtools.lib_scope import in_scope, extract_host
from bbtools.lib_egress import make_session, clear_cloudflare, OutOfScope
```

## Available now (tested, `python3 <file>` runs the self-check)
- **lib_scope.py** - `in_scope(host_or_url, scope_file)`, `host_in_scope`, `extract_host`,
  `parse_scope`. Mirrors `.claude/hooks/scope-gate.sh` EXACTLY (OOS-divider awareness,
  `=` exact-only marker, wildcard suffix, public-suffix refusal) so a script and the live
  hook never disagree. Kills the ~160 ad-hoc scope parsers.
- **lib_egress.py** - `make_session(scope_file)` returns a curl_cffi chrome124 session with
  the SCOPE GATE baked in (every request is `in_scope`-checked before it leaves; OOS raises
  `OutOfScope`), optional `pin_ip` for origin-IP pinning via CurlOpt RESOLVE. `clear_cloudflare(host)`
  solves a managed challenge with Playwright and returns the cookies (curl_cffi JA3-spoof alone
  cannot solve a managed challenge - workspace lesson). Kills the ~2087 curl_cffi + 346 CF rewrites.

- **lib_provision.py** - account self-provisioning (the ~80%-pain area: unauth needs an authed
  2nd account and every target reinvented it). `TempInbox` (mail.tm disposable inbox: create/token/
  poll, extract verify link + code, unwrap SendGrid click-wrap; forces `Accept: application/json`
  because the impersonated browser Accept makes mail.tm answer XML), `firebase_emaillink(api_key,
  origin)` (fully-generic Firebase magic-link to a verified idToken, no human inbox - the
  character_ai win, generalized), `provision_pair(handle, register_fn)` mints TWO accounts (the
  IDOR/BOLA default) into `targets/<handle>/accounts/`, `save/load_account` (mint once, reuse). The
  target-specific register/login call stays in the target script; everything else is reused -
  and `simple_register(register_url, extra={...})` covers the 80%-common email+password+verify
  signup (POST -> poll inbox -> follow verify link / return code) with NO custom register_fn.
  Fulfils the mail.tm/OTP + account-store half of the planned lib_auth.py below. Self-check:
  `python3 scripts/bbtools/lib_provision.py selfcheck` (also CLI: `inbox`, `wait <token>`, `firebase`).
- **gmail_read.py / gmail_imap.py** - read the REAL provisioning inbox (researcher@example.com) for a verify link/OTP: `gmail_read.py "<subj>" --wait N` (CDP, no MCP), `gmail_imap.py` (full body, needs GMAIL_APP_PASS), `gmail_read.py confirm "<subj>" <host>` closes signup->verify->login. Authed hunting: `from lib_browser import cdp_authed_curl` (host= filter). Robust CDP: `cdp_ws_call` - never hand-roll a socket.
- **lib_browser.py** - hardened headless (Playwright, proxy-aware). `browser(headless,proxy,state)`
  stealth context with storage_state REUSE (clear a bot-wall once, replay forever), `eval_async`
  (fixes nodriver's evaluate() returning None on an async IIFE), `clear_wall` (CF/DataDome/Akamai
  interstitial), `fill_form` (client-side-rendered forms curl can't see), `in_page_fetch` (fetch
  past a JA3/CORS wall from inside the cleared origin), `dump_state` (hand cookies to curl_cffi for
  the copy-paste PoC), `signup_recon` (report a signup page's fields + captcha vendor + verify
  channel = the provision plan), `cswsh_probe`/`postmessage_capture`/`screenshot` (curl-blind
  classes). Stealth context masks the common bot-wall fingerprints (webdriver/languages/plugins/
  chrome/permissions). Route through Burp with `--proxy` or `$BB_PROXY`. CLI: `open <url> --state s.json`,
  `fetch <url> --state s.json`, `selfcheck`. Self-check: `python3 scripts/bbtools/lib_browser.py selfcheck`.

- **lib_browser_nd.py** - nodriver (undetected) backend for the walls Playwright can't beat.
  When `detect_wall` reports Kasada / DataDome / PerimeterX (they fingerprint Playwright's CDP),
  switch here. `nd_eval(page, expr, is_async=True)` is the correct async eval (fixes nodriver's
  evaluate()-returns-None-on-async-IIFE via await_promise), `nd_clear_wall`, `nd_cookies` (-> curl),
  `nd_fetch(url)` sync convenience. Self-check launches headless and proves sync+async eval == 42.
- **lib_unauth.py** - the strip-auth diff + SPA-200 discipline as a tested tool. `classify()`
  (pure) verdicts a route PROTECTED / PUBLIC-SHELL (the SPA false-200, NOT a lead) /
  PRIVATE-BUT-OPEN (the lead) / PUBLIC-DATA using a nonsense-sibling 404 control;
  `strip_auth_diff(routes, unauth_session, authed_session)` runs it over a route list,
  leads-first. Codifies the #1 unauth move and kills the #1 unauth false positive (H1 RULE-2).
  `bypass_ladder(session, url)` fires the 403/401-bypass ladder (path-normalization, header-spoof
  X-Original-URL/X-Forwarded-For, method-tamper) and returns the variants that beat the baseline.
  CLI: `lib_unauth.py diff <scope_file> <routes_file>`. Self-check offline.
- **lib_auth.py** - pluggable login for the authed 2nd-account default. `wallet_login_evm`
  (EIP-191 personal_sign - the class that paid, hibachi #84332), `siwe_message` (EIP-4361),
  `recover_evm`, `wallet_login_substrate` (SR25519/ED25519), `session_from_state` (load a
  lib_browser storage_state into curl_cffi - browser clears the wall, curl probes fast),
  `form_login` (cookie/CSRF). Crypto self-checks by sign->recover round-trip. CLI: `evm-sign`,
  `substrate-sign`, `selfcheck`.
- **bola_discriminant.py** - the distinct-identity gate + paired cross-user read/write prober.
  `assert_distinct` fails loud on a same-account pair (the false positive that must not ship),
  then `paired_read`/`paired_write` capture A-reads/writes-B with B's own before/after view and
  a reversible revert. Pairs with `provision_pair` (mint A+B) + `lib_auth` (log them in). The
  distinct-victim gate that flipped transferVisitorInfo informative->shippable.

- **race_burst.py** - concurrent burst + serial-replay control for the SIG-1 seam-race class
  (the #1 paid signature) and the floor-gate "concurrent burst before DEAD". `burst(fn,n)`
  (Barrier-synced threads), `burst_http(req,n)` (n concurrent curl_cffi requests),
  `serial_control(fn,n)` (the discriminant: concurrent lets K>1 through, serial exactly 1),
  `count_ok`. Self-check proves it creates a real overdraft race (concurrent overspends,
  serial does not). For a sub-ms H2 single-packet window use Burp Turbo Intruder.
- **gql.py** - GraphQL probe helper. `introspect`, `apq_hash`, `apq_probe` (hash-only ->
  register-on-miss, the cache-deception / auth-bypass seam that is most-skipped), `alias_batch`
  (N calls in one request for a rate-limit / oracle bypass), `gql`. Self-check on a mock.

- **onchain.py** - EVM read + on-chain proof-integrity for Immunefi. `connect(chain)` (keyless
  drpc), `call(w3, addr, 'name(uint)(uint)', *args)` (view read by human signature), `impl_slot`
  (EIP-1967 proxy detection), `storage`, `event_in_receipt` (gate a PoC on the terminal EVENT, not
  a print), `positive_control` (prove the harness can observe a true-positive before trusting a
  DEAD). Live-validated: WETH decimals=18, symbol=WETH. A fork PoC still uses scaffold-fork-poc.sh.

Run every self-check at once: `scripts/bbtools/selfcheck-all.sh` (ALL GREEN = tooling sound).
See the whole chain run end to end on mocks (also an interface-drift test): `python3 scripts/bbtools/demo_chain.py`.

### When to self-provision vs NEEDS-line
`lib_provision` handles: email+password signup, email verify (link OR code), Firebase magic-link.
It does NOT handle (emit ONE `NEEDS:` line, do not grind a wall): SMS/phone-OTP verify (no
reliable free temp-SMS), Arkose/FunCaptcha or an interactive hCaptcha/Turnstile on the signup
(detect with `lib_browser.signup_recon`; drive it in-browser if solvable, else NEEDS), social-only
signup (Google/Apple), and KYC / gov-ID / paid-tier-no-trial. Run `signup_recon(page, url)` FIRST
so you know which wall you face before spending time on it.

### Worked recipe: unauth -> authed 2nd-account -> BOLA (the chain that most hunts skip)
```python
import sys; sys.path.insert(0, "scripts")
from bbtools.lib_provision import provision_pair, simple_register
from bbtools.lib_egress import make_session
from bbtools.lib_auth import authed_session
from bbtools.lib_unauth import strip_auth_diff, bypass_ladder
from bbtools.bola_discriminant import run as bola_run

SCOPE = "targets/<handle>/SCOPE.txt"
unauth = make_session(SCOPE)                                   # scope-gated, no session
leads = strip_auth_diff(open("routes.txt").read().split(), unauth)  # SPA-200 discipline applied
# on any 403 lead: bypass_ladder(unauth, "https://host/forbidden")
# mint the two accounts the authed surface needs (email+password targets need no register_fn):
A, B = provision_pair("<handle>", lambda ib: simple_register("https://host/register", inbox=ib))
sa, sb = authed_session(A, SCOPE), authed_session(B, SCOPE)   # sessions carrying each account's auth
cap = bola_run(sa, sb, whoami=my_whoami, obj_b_url=f".../obj/{B['id']}",
               write_body={"x": 1}, read_b_url=f".../obj/{B['id']}", revert_body={"x": 0})
# cap['distinct'] gated FIRST; cap['read']/cap['write'] are the cross-user receipts.
```

## Recommended next (build lazily, when a hunt first needs the logic - do not pre-build)
All retro P1 libs are now built (above). Remaining lazy extensions, add on first real need:
- **onchain.py Substrate `submit_and_assert`** - the EVM read/verify core is built; the Substrate
  extrinsic submit + terminal-event gate (LAST System.Extrinsic*) is the future add.
- **SMS-OTP provisioning** in lib_provision - no reliable free temp-SMS; wire a provider when a
  target's signup is SMS-gated (else it is a NEEDS-line).

ponytail: build these when the first hunt re-needs them, not before.
