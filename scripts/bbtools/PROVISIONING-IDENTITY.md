# Default signup identity: the HackerOne alias  (set 2026-10-04, GreyNOC)

## USE THIS FIRST for every target signup

    you+<target>-<role>@wearehackerone.com

e.g. `you+ui-a@wearehackerone.com` / `you+ui-b@wearehackerone.com`

The handle comes from `HACKERONE_HANDLE` in `~/.config/gnoc/secrets.env` (authoritative;
it is `greynoc`, NOT the stale `researcher` that appears in older memory and reports).

## WHY it beats mail.tm

1. It is NOT a disposable domain. mail.tm domains (maxxspace.com etc.) sit on commodity
   signup denylists; wearehackerone.com generally does not, and several programmes
   explicitly expect researcher accounts to use it.
2. Plus-addressing gives unlimited DISTINCT identities off one alias, which is exactly
   what a cross-user / cross-tenant BOLA proof needs (A and B must be different users).
3. PROVEN IN A FILED REPORT: a filed cross-account finding used
   `you+user1@wearehackerone.com` and `you+user2@wearehackerone.com` as the two
   distinct workspace members, and the leaked body quoted user2's address verbatim. The
   two-identity discriminant held up. Same mechanism, new handle.
4. It is a truthful researcher identity, not a fabricated persona.

## THE LIMIT - know this before planning a lane around it

The alias FORWARDS to GreyNOC's registered HackerOne email. There is no API and no IMAP
for it: `GMAIL_APP_PASS` and `GMAIL_USER` are NOT in secrets.env (verified 2026-10-04).

  - Signup needing NO email confirmation to reach the crown -> alias works fully, autonomous.
  - Signup needing a CLICKED confirmation link -> GreyNOC must read the mail, OR he signs
    into Gmail once in the CDP Chrome window and agents then read it via CDP.
  - A product needing a real MAILBOX you control (Mailco connecting a Gmail/Outlook
    account, any IMAP/Exchange integration) -> the alias is NOT a mailbox. It cannot help.
  - An interactive CAPTCHA (logitech hCaptcha) -> unrelated to email. The alias does not help.

## ORDER OF PREFERENCE

1. `you+<tag>@wearehackerone.com`                   <- default
2. mail.tm via `lib_provision`                          <- when a readable inbox is required
                                                           and the domain is not blocked
3. `browser_register` / `provision_pair_browser`        <- CSR or bot-walled forms
4. one GreyNOC action (captcha click, Gmail sign-in)    <- genuine hard unlock only

## CDP GOTCHA (fixed 2026-10-04)

Chrome 154 REJECTS a CDP websocket that sends an Origin header:

    Handshake status 403 Forbidden
    "Rejected an incoming WebSocket connection from the http://127.0.0.1:9222 origin"

Fix: pass `suppress_origin=True` to `websocket.create_connection()`, or launch Chrome with
`--remote-allow-origins=*`. Verified working against the live 9222 session. This is why
CLAUDE.md says use `cdp_ws_call` from bbtools `lib_browser` and never hand-roll a CDP
socket - the helper already handles it.
