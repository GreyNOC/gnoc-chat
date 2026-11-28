"""gnoc_doctrine.py - the expert knowledge layer behind gnoc chat: what a senior hunter KNOWS, delivered to the
local model at the moment it is useful instead of never.

The workspace already holds the expertise; the agent was not reading it. This module turns it into retrieval:
    moves(phase, terms)      the reasoning doctrine (patterns/REASONING-DOCTRINE.md, 100+ falsifiable moves) by
                             hunt phase: A hypothesis, B anomaly, C developer psychology, D escalation, E seam /
                             parser differential, F stuck pivot, G discipline, H bespoke input, I paid win-patterns
    cards(terms, k)          pattern cards (patterns/INDEX.md, 2000+) matched on triggers / fingerprint / class,
                             each read back as root cause, detection, exploitation and bypasses
    manual(ids_or_terms)     the Manual's T-NN rules (Rule / Why / Receipt), grepped from the volumes
    next_hops(capability)    the CHAIN TABLE: what a held primitive unlocks (ssrf -> IMDS creds -> cloud IAM; open
                             redirect -> OAuth code -> ATO; self-XSS + login CSRF -> stored XSS ...) so escalation
                             is instantiated, never generic
    kill_match(text)         the 16 shapes our own account was closed Informative on (calibrated, verbatim history)
    premise_gate(...)        T-215: the terminal must lie OUTSIDE what the attacker's own premise already grants
    cwe_for(text, crown)     the CWE of the WEAKNESS (T-105), never the crown's effect
    fingerprint(captures)    stack tags from headers / cookies / bodies / paths, and the first idioms per stack
    canon(capability)        the fixed precondition vocabulary so two lanes' edges actually pair
Everything here is data and parsing; nothing probes.
"""
import glob
import os
import re

# shared helpers (consolidated from the per-module copies)
from gnoc_core.util import _read_strict as _read

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



DOCTRINE = os.path.join(WS, "patterns/REASONING-DOCTRINE.md")
INDEX = os.path.join(WS, "patterns/INDEX.md")
MANUALS = sorted(glob.glob(os.path.join(WS, "Manual/GREYNOC-MANUAL*.md")))

PHASES = {"A": "hypothesis-formation", "B": "anomaly-detection", "C": "developer-psychology",
          "D": "primitive-to-impact escalation", "E": "seam and parser differential", "F": "stuck-pivot",
          "G": "discipline", "H": "bespoke adversarial input", "I": "workspace-paid win patterns"}

# ---------------------------------------------------------------- capability vocabulary (chain-mapper's, extended)

VOCAB = {
    "internal-reach": r"ssrf|internal[- ]fetch|server[- ]side[- ]request|169\.254|metadata|internal[- ]reach|blind[- ]fetch",
    "open-redirect": r"open[- ]redirect|redirect[- ]param|redirect_uri|returnurl|next=",
    "secret": r"secret|credential|api[- ]?key|token[- ]leak|leaked[- ](key|token|password)|private[- ]key|aws[_-]?(access|secret)",
    "victim-session": r"victim[- ]session|session[- ](cookie|token) of|stolen[- ]session|hijack",
    "victim-click": r"victim[- ]click|one[- ]click|user[- ]interaction|phish|lure|ui:r",
    "victim-identifier": r"victim[- ](id|email|identifier|phone)|user[- ]id[- ]of|enumerat",
    "existence-oracle": r"existence[- ]oracle|exists[- ]vs|oracle",
    "header-control": r"header[- ](control|injection)|crlf|set[- ]a[- ]header|response[- ]splitting",
    "browser-origin": r"\bxss\b|script[- ](exec|on)|dom[- ]xss|stored[- ]xss|reflected[- ]xss|js[- ]exec|trusted[- ]origin",
    "self-xss": r"self[- ]xss",
    "csrf": r"\bcsrf\b|cross[- ]site[- ]request|login[- ]csrf|cspt",
    "html-injection": r"html[- ]inject|markup[- ]inject|dangling[- ]markup",
    "internal-hostname": r"internal[- ](host|name|hostname|domain|topology)|leaked[- ]host",
    "file-read": r"\blfi\b|file[- ]read|arbitrary[- ]read|path[- ]traversal[- ]read|directory[- ]traversal",
    "file-write": r"file[- ]write|arbitrary[- ]write|upload|webshell",
    "path-control": r"path[- ]traversal|path[- ]control|dot[- ]segment|\.\./",
    "race-window": r"\brace\b|toctou|concurren|burst|double[- ]spend",
    "cache-control": r"cache[- ](poison|decept|control)|unkeyed",
    "desync": r"desync|smuggl|cl\.te|te\.cl|h2c",
    "oauth-code": r"oauth[- ]code|authorization[- ]code|code[- ]leak|id_token|mix[- ]up",
    "signature-forge": r"forge|alg[- ]none|hs256|rs256|unsigned|signature[- ]bypass|jwt|saml",
    "sql-read": r"\bsqli?\b|sql[- ]inject|nosql|union[- ]select|boolean[- ]based",
    "template-eval": r"\bssti\b|template[- ]inject|expression[- ]language|ognl|spel",
    "deser": r"deserial|pickle|rO0|ObjectInputStream|unserialize",
    "admin-ui-reach": r"admin[- ](panel|ui|console|reach)|actuator|debug[- ]console",
    "email-control": r"email[- ]control|send[- ]as|mail[- ]inject|spf|dmarc",
    "subdomain-control": r"takeover|dangling|cname",
    "cors-read": r"\bcors\b|credentialed[- ]read|cross[- ]origin[- ]read",
    "postmessage-sink": r"postmessage|message[- ]handler",
    "prototype-pollution": r"prototype[- ]pollution|__proto__",
    "attacker-account": r"own[- ]account|attacker[- ]account|self[- ]provision",
    "attacker-tenant": r"own[- ]tenant|attacker[- ]tenant|second[- ]org",
    "approval": r"approval|moderation|review[- ]queue",
    "funds-or-state": r"funds|balance|deposit|paid[- ]plan|credit",
}
_VOCAB = [(k, re.compile(v, re.I)) for k, v in VOCAB.items()]


def canon(name):
    """A capability name -> the canonical vocabulary tag when one matches, else the slug as given."""
    n = (name or "").strip().lower()
    for tag, rx in _VOCAB:
        if n == tag or rx.search(n):
            return tag
    return re.sub(r"[^a-z0-9.:/_-]+", "-", n).strip("-")


# ---------------------------------------------------------------- the chain table (what a primitive unlocks)

# tag -> [(next primitive / move, capability gained, how, doctrine or manual ref)]
NEXT_HOPS = {
    # BUSINESS LOGIC and AUTH are our best-converting classes (83% and 43% accepted against IDOR's 6%,
    # precision ledger n=145, 2026-10-22) and had NO chain edges at all, so a lane that landed one was told
    # nothing about escalating it. These turn the easy win into the SOURCE leg of a crown.
    "entitlement": [
        ("the paid tier you just granted yourself", "admin-ui-reach", "a plan/role flag usually gates FEATURES, not just billing: re-enumerate the route table as the upgraded actor and look for staff, export, bulk or impersonation surfaces that were 403 a moment ago", "D11, T-215"),
        ("the same grant aimed at another account id", "funds-or-state", "if the grant takes a beneficiary id, email or group from the BODY rather than the session, it writes to an account you do not own: that is the cross-user terminal, not a self-grant", "T-247"),
        ("the ledger debit path", "funds-or-state", "find WHEN the quota or balance is debited (on success or on commit) and fire a hostile counterparty that fails AFTER the debit; a cap debited on success is drained by a partner that errors late", "T-247"),
    ],
    "order-state": [
        ("the step you skipped", "funds-or-state", "drive the workflow out of order (pay-then-verify, issue-then-claim, ship-before-capture): the second handler usually trusts that the first one ran", "SIG-1, SIG-5"),
        ("the same seam under concurrency", "race-window", "a check-then-act step that is safe serially is a double-spend when both arms land in one window; the burst needs a SERIAL replay as its control", "T-39"),
    ],
    "identity-bind": [
        ("the unverified claim you control", "ato", "if a binding is keyed on an identifier the server never proved you own (email, phone, sub, external uid), claim the victim's identifier first and let their legitimate login MERGE into your record: zero victim action, so it is zero-click", "T-257, nOAuth"),
        ("the reset or magic-link flow keyed on that identifier", "ato", "a reset is an ATO primitive the moment its key is attacker-settable; capture the token landing in a mailbox you own for an account you do not", "D11"),
    ],
    "reset-state": [
        ("the token you can observe or set", "ato", "bind-test it: does the token stay valid when the email, user id or client is swapped? A token that survives a rebind is a session for the wrong account", "D11"),
        ("the delivery channel", "email-control", "if the flow lets you add, array-wrap or cc a second recipient, the victim's token is delivered to you; refute mail-all with a positive control before believing it", "T-31"),
    ],
    "quota": [
        ("the limit you just bypassed", "funds-or-state", "a missing or client-keyed limit is Low alone: price it. Chain it to the thing the limit PROTECTS (a paid resource, an OTP guess, an invite grant) and capture that terminal, or it stays a LEAD", "T-86b"),
    ],
    "internal-reach": [
        ("IMDS / cloud metadata", "secret", "GET 169.254.169.254/latest/meta-data/iam/security-credentials/ (GCP: metadata.google.internal with Metadata-Flavor); IMDSv2 needs PUT /latest/api/token so a method+header-control SSRF beats it", "D2b, T-197"),
        ("the internal service whose parser lifts the SSRF's limit", "admin-ui-reach", "list the constraint (GET-only, no headers, no body) and hunt the service that does not need it: Redis/memcached via gopher, an actuator, a Consul/etcd/K8s API, a docker socket", "D2"),
        ("redirect-loop body dump", "file-read", "if the fetcher follows redirects, a self-referential 3xx chain past the APP's hop cap can dump intermediate bodies into the visible response", "F10"),
        ("in-band oracle on internal hosts", "internal-hostname", "vary the internal target; status class, length, latency buckets and redirect count leak internal state even when the body does not", "F2, T-222"),
    ],
    "open-redirect": [
        ("OAuth code / token theft", "oauth-code", "point redirect_uri (host-only allowlist) or the trusted Referer through the redirector so the code lands on an attacker path, then redeem it", "D16, D5"),
        ("magic-link / passwordless token leak", "victim-session", "route the login link's landing through the redirect so the token-bearing URL reaches a third-party page or Referer", "D11"),
        ("SSRF allowlist bypass", "internal-reach", "a server-side fetcher that allows only the vendor's host follows the vendor's own redirector to 169.254 or an internal name", "T-197, T-223"),
    ],
    "oauth-code": [
        ("code injection into the attacker's own pre-auth session", "ato", "if PKCE's verifier is client-side or absent, redeem the leaked code at the token endpoint paired with a fresh attacker /auth/params; the victim's tokens land in a session you control", "D12"),
        ("IdP mix-up relay", "ato", "a multi-tenant consumer that picks the token endpoint from a mutable state field relays the victim's code to the attacker's IdP", "T-257"),
    ],
    "secret": [
        ("every service the key reaches", "admin-ui-reach", "re-score a leaked key against EVERY API it authenticates to (new AI/LLM endpoints bill and read files); a sandbox key still proves the issuer's control is broken", "D8"),
        ("in-scope quota meter as the terminal", "money", "when the key's primary terminal is out of scope, consume one metered unit on the in-scope victim's billing (non-destructive) and capture the meter", "D10"),
        ("vendor-operated consumer acceptance", "auth-bypass", "a token is a finding only when a VENDOR-operated consumer accepts it; never build your own gateway to show it works", "T-151"),
    ],
    "existence-oracle": [
        ("victim-identifier feed for a second bug", "victim-identifier", "confirm ids before an expensive secondary call (reset, invite, notification, billing event); scale proves mass impact without touching real data", "acl-drift-existence-oracle-read-endpoint"),
        ("the paired WRITE on the same object", "cross-user-write", "every confirmed read gets a write attempt on an object owned by account B that you provisioned", "D1"),
    ],
    "cross-user-read": [
        ("the paired WRITE / MODIFY / DELETE", "cross-user-write", "same id, same handler family, PUT/PATCH/DELETE on account B's object; read-allowed plus write-unchecked is the IDOR-to-takeover ladder", "D1, SPINE 4 move 3"),
        ("the identity fields that mint a session", "ato", "if the read returns email/phone/reset state, the reset or magic-link flow keyed on it is the ATO partner", "D11"),
        ("same defect on the admin / staff twin", "admin", "apply the identical mechanism to the back-office route family (admin., staff., internal., ops.)", "A1, SPINE 4 move 1"),
    ],
    "self-xss": [
        ("login CSRF partner", "browser-origin", "log the victim into the attacker's account where the payload is stored, then the payload runs in the victim's browser on the real origin", "D3"),
        ("cross-context injection partner", "browser-origin", "find the renderer that shows the stored value to ANOTHER actor (admin view, export, email, PDF, support console)", "T-195"),
    ],
    "browser-origin": [
        ("the credential-trusted origin set of the session API", "ato", "map which origins the session API honours with credentials; script on ANY of them reads/writes the account and mints a PAT", "T-259"),
        ("CSRF token / anti-automation read", "csrf", "read the token from the DOM and fire the state change that SameSite blocked", "D3"),
    ],
    "csrf": [
        ("the highest-value state change behind it", "ato", "email change, password change, payout destination, API key creation, 2FA disable, invite acceptance", "client-trust-hunter"),
        ("CSPT resurrects CSRF under SameSite", "cross-user-write", "a same-origin fetch whose PATH you control fires from the victim's own first-party JS", "F9"),
    ],
    "header-control": [
        ("cache poisoning", "cache-control", "an unkeyed reflected header (X-Forwarded-Host, X-Original-URL) stored by the CDN serves your bytes to every visitor", "cache-hunter"),
        ("response splitting to session fixation", "victim-session", "CRLF into Set-Cookie on the origin that holds the session", "E"),
    ],
    "cache-control": [
        ("stored script on the real origin", "browser-origin", "poison a JS or HTML resource the app loads; the terminal is script on the session origin, not a 200", "cache-hunter"),
        ("web cache deception of a private page", "cross-user-read", "a path-shape twin (/account/x.css) cached with the victim's private body", "cache-hunter"),
    ],
    "desync": [
        ("response queue poisoning / request hijack", "victim-session", "a desync that captures the NEXT user's request (with its cookie) on the shared connection; plain-pipelining control first", "T-166, T-167"),
        ("front-end control bypass", "auth-bypass", "the smuggled request reaches a route the edge denies (admin, internal)", "smuggling-hunter"),
    ],
    "file-read": [
        ("config, env, keys", "secret", "/proc/self/environ, .env, the app config, SSH keys, cloud credential files", "rce-hunter"),
        ("source to find the sink", "rce", "read the handler code and hunt the deserialization / template / exec sink it reveals", "rce-hunter"),
    ],
    "file-write": [
        ("webshell / template / cron", "rce", "write into a served path, a template dir, a cron or an autoload location; MIME and extension twins", "rce-hunter"),
    ],
    "path-control": [
        ("representation-boundary twin", "auth-bypass", "the edge matches path form A, the handler decodes form B: /%2e/, /a/../, double slash, %2561 (T-250, T-256); a denied route runs", "T-191, T-256"),
    ],
    "sql-read": [
        ("auth table / session table", "ato", "the credential or session rows of another user; then log in as them", "sqli-hunter"),
        ("stacked / file / exec to RCE", "rce", "xp_cmdshell, INTO OUTFILE, COPY FROM PROGRAM, UDF - detection first, then one benign proof", "sqli-hunter"),
    ],
    "template-eval": [("object-graph walk to exec", "rce", "class.mro / subprocess / Runtime from the template context; one benign command with OOB proof", "rce-hunter")],
    "deser": [("gadget chain", "rce", "ysoserial / phpggc / pickle reduce; OOB DNS proves execution without side effects", "rce-hunter")],
    "signature-forge": [
        ("forge the privileged identity", "admin", "mint the admin's token / assertion with the broken verifier; prove with a privileged read", "I1, saml-jwt-hunter"),
    ],
    "race-window": [
        ("the money / limit it beats", "money", "coupon, credit, withdrawal, quota, OTP attempts: burst plus the serial-replay control in the same PoC", "I4, G4"),
    ],
    "subdomain-control": [
        ("cookie / CORS / CSP trust of the parent", "victim-session", "a claimed subdomain inside the parent's cookie domain, CORS allowlist or CSP source reads or sets the session", "takeover-hunter"),
    ],
    "cors-read": [("a credentialed PRIVATE page", "cross-user-read", "the read must return bytes that are private to the victim's session; a public page proves nothing", "kill shape 8")],
    "postmessage-sink": [("origin-unchecked handler to DOM sink", "browser-origin", "a handler that writes the message into innerHTML / location / eval with no origin check", "A9")],
    "prototype-pollution": [("the gadget that turns a polluted property into a sink", "rce", "server-side: child_process / template options / fetch options; client-side: a DOM-XSS gadget in the bundle", "protopollution-hunter")],
    "internal-hostname": [("SSRF target / vhost twin", "internal-reach", "feed the name to every server-side fetcher and Host-header twin", "D8")],
    "admin-ui-reach": [("the privileged action behind it", "admin", "a reachable admin UI is Low until a privileged read or write is captured", "T-200")],
}

ESCALATION_MOVES = (
    "(1) SAME DEFECT, HIGHER-VALUE ASSET: the class is the finding; re-aim the identical mechanism at the admin / staff twin, the authed API, the tenant-keyed route, the host that holds the session.",
    "(2) WHAT THE DISCLOSED THING UNLOCKS: a leaked id is an IDOR key, a route is reach, a credential is auth, an internal name is the next hostname. Disclosure is terminal only when nothing it reveals is usable - prove that.",
    "(3) THE PAIRED WRITE: every read gets a write on an object account B owns; every write gets a read.",
    "(4) THE PARTNER BUG: self-XSS + login CSRF; SSRF + the internal service; open redirect + OAuth code; a primitive + the credential wall behind it.",
    "(5) THE MISSING CONTEXT: the same sink on the origin that holds the session; the same handler on the production path.",
)


def next_hops(capability, k=4):
    tag = canon(capability)
    rows = NEXT_HOPS.get(tag, [])
    if not rows:
        return tag, []
    return tag, rows[:k]


def escalation_plan(capability, asset=""):
    """The five moves instantiated for a held capability, plus the chain table's concrete next hops."""
    tag, hops = next_hops(capability, 5)
    out = [f"HELD CAPABILITY: {tag}" + (f" on {asset}" if asset else "")]
    if hops:
        out.append("CONCRETE NEXT HOPS (chain table; each is one hypothesized edge to add and prove):")
        out += [f"  -> {to.upper()} via {via}: {how}  [{ref}]" for via, to, how, ref in hops]
    else:
        out.append("No chain-table entry for this tag: derive the next hop from the five moves below and add it.")
    out.append("THE FIVE MOVES, in historical-yield order (take the first that applies, write the negatives of the rest):")
    out += ["  " + m for m in ESCALATION_MOVES]
    return "\n".join(out)


# ---------------------------------------------------------------- the calibrated kill list (our own closures)

KILL_SHAPES = [
    ("DNS resolves to a private IP", r"resolv\w* to (a )?(private|internal|10\.|192\.168|172\.)"),
    ("dangling CNAME on a domain the vendor validates", r"dangling (cname|dns).{0,80}(validat|verif)"),
    ("reachable pre-auth surface with no private bytes", r"(reachable|accessible) (pre|un)[- ]?auth\w*(?!.{0,120}(private|victim|another user))"),
    ("GraphQL / schema enumeration alone", r"(introspection|schema) (enabled|enumer|exposed)(?!.{0,120}(private|mutation lands|cross))"),
    ("header / stack-trace leak", r"(stack ?trace|x-powered-by|server header|version (header|banner)) (leak|disclos)"),
    ("WAF 200 on a blocked payload", r"waf.{0,40}(bypass|200)(?!.{0,120}(execut|stored|session|exfil))"),
    ("charset / multipart bypass that ends in a 400", r"(charset|multipart).{0,60}bypass.{0,60}\b400\b"),
    ("CORS with no credentialed PRIVATE read", r"\bcors\b(?!.{0,160}(credentialed|private|session|victim))"),
    ("credential spray without a 2FA bypass", r"(spray|brute[- ]?force|credential stuffing)(?!.{0,120}(2fa|mfa|otp).{0,30}bypass)"),
    ("username / email enumeration alone", r"(user(name)?|e-?mail) enumerat(?!.{0,120}(reset|takeover|mass|pii))"),
    ("last-4 / masked PII", r"(last[- ]?4|masked|redacted) (digits|pii|card|phone|email)"),
    ("public-channel action or an 'admin'-named member readable", r"public (channel|group|workspace).{0,60}(read|list|member)"),
    ("own-account step-up or session shared across own apps", r"(own|same) (account|session).{0,60}(step[- ]up|shared across|reuse)"),
    ("unauth CDN upload with no XSS / overwrite", r"(cdn|bucket|blob) upload(?!.{0,120}(xss|overwrite|execut|served from))"),
    ("mechanism on data that is public by design", r"(public by design|intended to be public|publicly (listed|available)) data"),
    ("report against nonexistent code or the wrong vendor", r"(wrong vendor|not (their|our) code|third[- ]party (owned|operated))"),
]
_KILLS = [(n, re.compile(rx, re.I | re.S)) for n, rx in KILL_SHAPES]


def kill_match(text):
    """[(shape, matched snippet)] for every pre-rejected shape the text reads like. Advisory: the capability
    captured in bytes can still clear it, but then the report must SHOW that capability."""
    t = " ".join((text or "").split())
    out = []
    for name, rx in _KILLS:
        m = rx.search(t)
        if m:
            out.append((name, t[max(0, m.start() - 30):m.end() + 30]))
    return out


def premise_gate(start, requires, terminal):
    """T-215: list what the attacker's own premise already grants; the terminal must lie outside it.
    Returns (ok, note)."""
    req = [canon(r) for r in (requires or [])]
    granted = set()
    if start == "own-account" or "attacker-account" in req:
        granted |= {"own data read", "own data write", "own session"}
    if "victim-session" in req:
        granted |= {"everything the victim can do"}
    if "secret" in req:
        granted |= {"whatever the secret authenticates to"}
    if "browser-origin" in req:
        granted |= {"script on that origin (its session, its CSRF tokens)"}
    if "approval" in req:
        granted |= {"an insider's consent"}
    term = canon(terminal)
    bad = {"victim-session": {"ato", "cross-user-read", "cross-user-write"},
           "secret": {"secret"},
           "browser-origin": {"browser-origin", "csrf"}}
    for r in req:
        if term in bad.get(r, set()):
            return False, (f"the terminal {term} is already inside the premise {r}: a precondition priced at zero and the "
                           "mechanism at full is the dominant kill (66% of adjudicated rejections, T-215)")
    note = ("premise grants: " + ", ".join(sorted(granted))) if granted else "premise: anonymous internet attacker"
    return True, note


# ---------------------------------------------------------------- CWE of the weakness (T-105)

CWE_MAP = [
    (r"\bsqli?\b|sql inject", "CWE-89 Improper Neutralization of Special Elements used in an SQL Command"),
    (r"nosql", "CWE-943 Improper Neutralization of Special Elements in Data Query Logic"),
    (r"\bssti\b|template inject", "CWE-1336 Improper Neutralization of Special Elements Used in a Template Engine"),
    (r"command inject|os command|shell", "CWE-78 Improper Neutralization of Special Elements used in an OS Command"),
    (r"deserial|pickle|unserialize", "CWE-502 Deserialization of Untrusted Data"),
    (r"\bxxe\b|external entit", "CWE-611 Improper Restriction of XML External Entity Reference"),
    (r"path traversal|directory traversal|\.\./|dot[- ]segment", "CWE-22 Improper Limitation of a Pathname to a Restricted Directory"),
    (r"\blfi\b|file inclusion", "CWE-98 Improper Control of Filename for Include/Require Statement"),
    (r"file upload|unrestricted upload", "CWE-434 Unrestricted Upload of File with Dangerous Type"),
    (r"\bssrf\b|server[- ]side request", "CWE-918 Server-Side Request Forgery"),
    (r"open redirect", "CWE-601 URL Redirection to Untrusted Site"),
    (r"stored xss|dom xss|reflected xss|\bxss\b|cross[- ]site scripting", "CWE-79 Improper Neutralization of Input During Web Page Generation"),
    (r"\bcsrf\b|cross[- ]site request forgery", "CWE-352 Cross-Site Request Forgery"),
    (r"\bcors\b", "CWE-942 Permissive Cross-domain Policy with Untrusted Domains"),
    (r"clickjack|frame", "CWE-1021 Improper Restriction of Rendered UI Layers or Frames"),
    (r"prototype pollution", "CWE-1321 Improperly Controlled Modification of Object Prototype Attributes"),
    (r"smuggl|desync", "CWE-444 Inconsistent Interpretation of HTTP Requests"),
    (r"cache poison|cache decept", "CWE-349 Acceptance of Extraneous Untrusted Data With Trusted Data"),
    (r"\brace\b|toctou|concurren|double[- ]spend", "CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization"),
    (r"alg[- ]none|hs256|rs256|jwt.{0,30}(forge|confusion)|signature (bypass|not verified|unverified)|unsigned", "CWE-347 Improper Verification of Cryptographic Signature"),
    (r"\bsaml\b.{0,40}(forge|unsigned|wrapping)|xsw", "CWE-347 Improper Verification of Cryptographic Signature"),
    (r"mix[- ]up|redirect_uri|oauth.{0,30}(state|code)", "CWE-287 Improper Authentication"),
    (r"password reset|magic[- ]link|reset token", "CWE-640 Weak Password Recovery Mechanism for Forgotten Password"),
    (r"otp|2fa|mfa.{0,30}bypass|rate limit", "CWE-307 Improper Restriction of Excessive Authentication Attempts"),
    (r"session fixation", "CWE-384 Session Fixation"),
    (r"mass[- ]assign|over[- ]post|bopla", "CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
    (r"\bidor\b|\bbola\b|user[- ]controlled (key|id)|object[- ]level|cross[- ](user|tenant)", "CWE-639 Authorization Bypass Through User-Controlled Key"),
    (r"\bbfla\b|function[- ]level|missing authoriz|no authoriz|privilege", "CWE-862 Missing Authorization"),
    (r"missing auth|unauthenticated|no authentication|pre[- ]auth", "CWE-306 Missing Authentication for Critical Function"),
    (r"hard[- ]?coded (credential|secret|key)", "CWE-798 Use of Hard-coded Credentials"),
    (r"secret|credential|api key|token|private key", "CWE-522 Insufficiently Protected Credentials"),
    (r"business logic|coupon|quota|refund|price", "CWE-840 Business Logic Errors"),
    (r"takeover|dangling|cname", "CWE-1104 Use of Unmaintained Third Party Components"),
    (r"information disclos|leak|expos", "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor"),
]
_CWES = [(re.compile(rx, re.I), cwe) for rx, cwe in CWE_MAP]


def cwe_for(text, crown=None):
    """The first weakness pattern the chain text names wins; the crown only breaks a total miss."""
    t = text or ""
    for rx, cwe in _CWES:
        if rx.search(t):
            return cwe
    return {"rce": "CWE-94 Improper Control of Generation of Code", "money": "CWE-840 Business Logic Errors",
            "ato": "CWE-287 Improper Authentication", "admin": "CWE-269 Improper Privilege Management",
            "auth-bypass": "CWE-287 Improper Authentication"}.get(crown, "CWE-284 Improper Access Control")


# ---------------------------------------------------------------- stack fingerprint + first idioms

STACKS = [
    ("php", r"x-powered-by: php|phpsessid|\.php\b"),
    ("laravel", r"laravel_session|xsrf-token=|ignition|/telescope"),
    ("wordpress", r"wp-json|wp-content|wordpress_logged_in|xmlrpc\.php"),
    ("drupal", r"x-generator: drupal|/jsonapi/|sess[0-9a-f]{32}="),
    ("symfony", r"symfony|/_profiler|_wdt"),
    ("jvm", r"jsessionid|apache-coyote|apache tomcat|x-application-context|whitelabel error|\.do\b|\.action\b|javax\.faces"),
    ("spring", r"spring|/actuator|whitelabel"),
    ("node", r"x-powered-by: express|cannot get /|connect\.sid|server: fastify"),
    ("nextjs", r"/_next/|x-nextjs-cache|__next_data__|x-vercel-id"),
    ("nestjs", r'"statuscode":\d+,"message"|/api-json'),
    ("python", r"server: (werkzeug|gunicorn|uvicorn|tornadoserver)|csrftoken=|sessionid=|wsgi"),
    ("django", r"csrfmiddlewaretoken|django|/admin/login/"),
    ("flask", r"werkzeug|flask"),
    ("fastapi", r'"detail":\[\{"loc"|/openapi\.json|/docs'),
    ("ruby", r"x-runtime:|server: (puma|passenger)|_session=|doesn.t know this ditty|rack"),
    ("rails", r"rails|x-request-id: [0-9a-f-]{36}|/rails/"),
    ("dotnet", r"x-aspnet|x-powered-by: asp\.net|\.aspxauth|__viewstate|server: kestrel|microsoft-iis|__requestverificationtoken|/_blazor"),
    ("go", r"server: go|gin-gonic|chi-router"),
    ("graphql", r"/graphql|persistedquery|__typename|\"errors\":\[\{\"message\""),
    ("firebase", r"firebaseio|firebaseapp|identitytoolkit|googleapis\.com/identitytoolkit"),
    ("aws", r"x-amz-|amazonaws\.com|cloudfront|x-amzn-"),
    ("gcp", r"x-goog-|googleusercontent|appspot|x-cloud-trace"),
    ("azure", r"x-azure-ref|azurewebsites|windows\.net|x-ms-request-id"),
    ("cloudflare", r"cf-ray|__cf_bm|cf-cache-status"),
    ("akamai", r"akamaighost|_abck=|ak_bmsc"),
    ("fastly", r"x-served-by: cache-|fastly"),
    ("vercel", r"x-vercel-|server: vercel"),
    ("nginx", r"server: nginx|openresty"),
    ("kong", r"x-kong-|via: kong"),
    ("envoy", r"server: envoy|x-envoy-"),
    ("okta", r"okta\.com|oktapreview"),
    ("auth0", r"auth0\.com|\.auth0\.|a0-"),
    ("keycloak", r"keycloak|/realms/|/auth/realms"),
    ("saml", r"samlresponse|/saml/|/sso/saml|\bacs\b.{0,20}url|wantassertionssigned"),
    ("oauth", r"/oauth2?/|/authorize\?|redirect_uri=|client_id=|www-authenticate: oauth|access[_ ]token"),
    ("websocket", r"upgrade: websocket|wss://"),
    ("s3", r"amazonaws\.com/|s3\.|x-amz-bucket"),
]
_STACKS = [(t, re.compile(rx, re.I)) for t, rx in STACKS]

IDIOMS = {
    "php": "forced 500 for Whoops / Ignition; type juggling on == compares; $_REQUEST vs $_POST reads (T-46); PHP filter chains on any include; CVE-2024-4577 twin on CGI",
    "laravel": "APP_DEBUG via /_ignition/health-check and execute-solution (CVE-2021-3129); fillable mass-assignment; route-model-binding IDOR on the slug twin; /telescope and /horizon reach",
    "wordpress": "wp-json/wp/v2/users enum then the plugin REST routes (permission_callback __return_true); admin-ajax nopriv_ actions read from $_REQUEST (T-46b); xmlrpc multicall; plugin version vs changelog security tightening (T-12c)",
    "drupal": "/jsonapi node and user reads; Drupalgeddon-class routes on old cores; user/register open; views exposed filters",
    "jvm": "Spring actuator (/actuator/env, /heapdump, /jolokia); DataBinder mass-assign (class.module.classLoader); path-variable owner-key gap; Jackson polymorphic deser; Struts OGNL on .action; JSF ViewState",
    "spring": "/actuator/* unauth, SpEL in any expression param, PreAuthorize drift between controller twins, JPA Sort injection on sort= / order=",
    "node": "Express: middleware-order authz drift, qs prototype pollution (a[__proto__][x]=y), lodash merge; Mongoose operator injection ({\"$gt\":\"\"}) on login; path concat into fetch (CSPT)",
    "nextjs": "CVE-2025-29927 x-middleware-subrequest header on self-hosted; Server Action id replay / argument tamper; _next/image allowlist SSRF twin; edge-vs-origin path decode mismatch (/%2e/, /a/../, %2561) on protected routes (T-256); ISR cache poisoning",
    "nestjs": "DTO whitelist gaps (forbidNonWhitelisted off), Guard missing on a sibling controller, /api-json for the unguarded route list, @nestjs/devtools-integration in prod",
    "python": "Werkzeug debugger PIN on a forced error, Jinja2 SSTI in any rendered param, get_object_or_404 without an owner filter, DRF browsable API and raw() ORM fragments",
    "django": "DEBUG traceback leak, django-filter SQLi on filter params, /admin/ twin, session cookie forge if SECRET_KEY leaks, SerializerMethodField mass-assign",
    "flask": "SSTI {{7*7}} in any template-rendered param, itsdangerous session forge if the key leaks, debugger console",
    "fastapi": "/openapi.json for every route and its auth dependency, 422 detail arrays leak schema, pydantic extra fields accepted, query vs body param confusion",
    "ruby": "render file traversal, YAML.load deser, Ransack column injection on q[...], strong-params drift, find without tenant scope, ruby-saml signature bypass",
    "rails": "mass-assignment on nested attributes, ActiveStorage signed-id confusion, Sidekiq web unauth, secret_key_base forge, Ransack sort twin",
    "dotnet": "__VIEWSTATE MAC-off deser, Telerik WebResource.axd, Json.NET TypeNameHandling, model-binding over-post, antiforgery gap on a sibling action, Blazor circuit messages",
    "go": "net/http path normalization twins (//, /./), gorilla mux vs chi route precedence, JSON unknown-field acceptance",
    "graphql": "introspection off is not schema off (T-155); alias batching past rate limits; node(id) global-ID IDOR; mutation field mass-assign; persisted-query registry is estate-wide (T-231); APQ register-on-miss",
    "firebase": "rules deny-by-default claim: read /.json and the REST path unauth; Firestore listCollectionIds; identitytoolkit signUp open",
    "aws": "IMDS via any SSRF (IMDSv2 needs PUT, D2b); S3 bucket policy on every bucket name in JS; Cognito open sign-up and identity-pool unauth role; presigned URL param tamper",
    "gcp": "metadata.google.internal with Metadata-Flavor: Google; GCS listing on bucket names; Cloud Run service-to-service tokens",
    "azure": "IMDS 169.254.169.254/metadata with Metadata: true; blob container public listing; App Service SCM twin (.scm.azurewebsites.net)",
    "cloudflare": "origin IP via history / certs / alt hosts; cache deception on /path.css; a bot-managed 403 is JA3 not IP (T-153): use curl_cffi chrome124",
    "akamai": "SNI-vs-Host desync carries the Host's WAF policy (T-178); _abck is a bot wall not an authz; path-shape edge vs origin twins",
    "fastly": "cache key vs Vary gaps, fat-GET reflection, Via: 1.1 varnish ESI",
    "vercel": "edge deny rules vs. encoded or dot-segment path variants; x-vercel-cache poisoning; serverless function bundle decodes a path the edge already decoded (T-256)",
    "nginx": "off-by-slash alias traversal (location /static -> /static../), merge_slashes, X-Accel-Redirect, proxy_pass path normalization",
    "kong": "plugin-phase exit on h2c upgrade (CVE-2026-29413), key-auth vs jwt plugin order, admin API on 8001 reach, consumer credential IDOR",
    "envoy": "custom error page embeds the hostname so body length is per-host constant (T-177); ext_authz bypass via path shape; SNI vs Host",
    "okta": "mutable claim pre-ATO (email change before verification), redirect_uri suffix match, nOAuth-shaped email claim trust",
    "auth0": "universal login state replay, custom DB script mass-assign, redirect allowlist wildcards, silent-auth prompt=none token leak into a frame",
    "keycloak": "/realms/<r>/.well-known for every realm then open registration on a dev realm (I2), account-console token exchange, admin REST on a sibling realm",
    "saml": "SP metadata WantAssertionsSigned=false (I1); XSW wrapping; unsigned assertion with correct issuer; the ACS as an unauth XML sink (T-175)",
    "oauth": "redirect_uri host-only allowlist + any open redirect (D16); code injection into own session when PKCE is client-side (D12); state not bound; mix-up across tenants (T-257); DCR open",
    "websocket": "origin not checked on the handshake (CSWSH) with cookies sent; message-level authz drift vs the REST twin",
    "s3": "bucket from JS / error bodies: anonymous list and PUT; presigned URL with a tampered key; bucket policy on the ACL twin",
}


def fingerprint(captures, extra_text=""):
    """captures: iterable of raw capture dicts (request/response) or strings. Returns (tags, evidence lines)."""
    blobs = []
    for c in captures or []:
        if isinstance(c, dict):
            req, resp = c.get("request") or {}, c.get("response") or {}
            req, resp = (req if isinstance(req, dict) else {}), (resp if isinstance(resp, dict) else {})
            h = resp.get("headers")
            hdrs = "\n".join(f"{k}: {v}" for k, v in h.items()) if isinstance(h, dict) else str(h or "")
            body = resp.get("body") or ""
            body = body if isinstance(body, str) else str(body)
            blobs.append(f"{req.get('url', '')}\n{hdrs}\n{body[:4000]}")
        else:
            blobs.append(str(c)[:6000])
    blob = "\n".join(blobs) + "\n" + (extra_text or "")
    tags, why = [], []
    for tag, rx in _STACKS:
        m = rx.search(blob)
        if m:
            tags.append(tag)
            why.append(f"{tag}: {m.group(0)[:50]!r}")
    return tags, why


def idioms_for(tags, cap=8):
    return [f"{t}: {IDIOMS[t]}" for t in (tags or []) if t in IDIOMS][:cap]


# ---------------------------------------------------------------- the reasoning doctrine, by phase

_RULE = re.compile(r"(?m)^([A-I]\d{1,2}[a-z]?)\. (.*)$")
_SECTION = re.compile(r"(?m)^## ([A-I])\. ")
_MOVE = re.compile(r"(?m)^### (M\d+)\. (.*)$")
_doc_cache = {}


def doctrine():
    """{id: {"phase": letter, "text": full rule text}} parsed once from REASONING-DOCTRINE.md."""
    if _doc_cache:
        return _doc_cache
    try:
        text = _read(DOCTRINE)
    except OSError:
        return {}
    # a rule runs from its "X1. " line to the next blank line
    chunks = re.split(r"\n\s*\n", text)
    for ch in chunks:
        m = _RULE.match(ch.strip())
        if m:
            rid = m.group(1)
            _doc_cache[rid] = {"phase": rid[0], "text": " ".join(ch.strip().split())}
            continue
        m = _MOVE.match(ch.strip())
        if m:
            _doc_cache[m.group(1)] = {"phase": "M", "text": " ".join(ch.strip().split())}
    # the EV-ranked opener block, as one entry
    m = re.search(r"(?s)## EV-RANKED OPENER.*?(?=\n## |\n### )", text)
    if m:
        _doc_cache["OPENER"] = {"phase": "0", "text": " ".join(m.group(0).split())}
    return _doc_cache


def _terms(s):
    return set(re.findall(r"[a-z0-9][a-z0-9._/-]{2,}", (s or "").lower()))


def moves(phase=None, terms="", k=6, maxlen=600):
    """The k doctrine rules of a phase (A-I, M, or None for all) best matching the terms. Returns [(id, text)]."""
    d = doctrine()
    want = _terms(terms)
    rows = []
    for rid, r in d.items():
        if phase and r["phase"] not in str(phase):
            continue
        if rid == "OPENER":
            continue
        tt = _terms(r["text"])
        sc = len(want & tt) + (1.5 if r["phase"] == "I" else 0)
        rows.append((sc, rid, r["text"]))
    rows.sort(key=lambda x: (-x[0], x[1]))
    return [(rid, t[:maxlen] + ("..." if len(t) > maxlen else "")) for _, rid, t in rows[:k]]


def opener():
    return doctrine().get("OPENER", {}).get("text", "")[:1800]


# ---------------------------------------------------------------- pattern cards

_idx_cache = []


def index():
    """[(id, class, severity, bounty, triggers, fingerprint)] from patterns/INDEX.md."""
    if _idx_cache:
        return _idx_cache
    try:
        for ln in _read(INDEX).splitlines(True):
            if not ln.startswith("| ") or ln.startswith("| id ") or ln.startswith("|--"):
                continue
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if len(cells) >= 6:
                _idx_cache.append(tuple(cells[:6]))
    except OSError:
        pass
    return _idx_cache


def cards(terms, k=5, classes=None):
    """Best-matching pattern cards for free-text terms (a stack tag, a seam, a crown, a symptom)."""
    want = _terms(terms)
    if not want:
        return []
    rows = []
    for cid, cls, sev, bounty, trig, fp in index():
        if classes and cls not in classes:
            continue
        hay_t = _terms(trig) | _terms(cid)
        hay_f = _terms(fp)
        sc = 2 * len(want & hay_t) + len(want & hay_f)
        if sc:
            rows.append((sc, cid, cls, sev, bounty, trig[:160]))
    rows.sort(key=lambda r: -r[0])
    return [r[1:] for r in rows[:k]]


def card(cid, cap=1600):
    """Root cause / detection / exploitation / bypasses of one card, compact."""
    cid = str(cid or "").strip()
    if not re.fullmatch(r"[\w][\w.-]*", cid):   # an id is a file stem: '../x' or '*' read files that are not cards
        return f"no card {cid}"
    hits = glob.glob(os.path.join(WS, "patterns", "*", f"{cid}.md")) + \
        glob.glob(os.path.join(WS, "patterns", "*", "*", f"{cid}.md"))
    if not hits:
        return f"no card {cid}"
    text = _read(hits[0])
    fm = re.match(r"(?s)^---\n(.*?)\n---", text)
    out = [f"CARD {cid}"]
    if fm:
        for key in ("fingerprint", "bypasses", "real_examples"):
            m = re.search(rf"(?ms)^{key}:\n((?:  - .*\n?)+)", fm.group(1))
            if m:
                items = [x.strip()[2:].strip().strip('"') for x in m.group(1).splitlines() if x.strip().startswith("-")]
                out.append(f"{key}: " + " | ".join(i[:200] for i in items[:4]))
    body = text[fm.end():] if fm else text
    for sec in ("Root cause", "Detection", "Exploitation"):
        m = re.search(rf"(?is)^## {sec}\s*\n(.*?)(?=^## |\Z)", body, re.M)
        if m:
            out.append(f"{sec}: " + " ".join(m.group(1).split())[:420])
    s = "\n".join(out)
    return s[:cap] + ("..." if len(s) > cap else "")


def cards_text(terms, k=4, with_bodies=2):
    rows = cards(terms, k)
    if not rows:
        return ""
    lines = [f"PATTERN CARDS matching '{terms[:60]}' (shapes that paid elsewhere; vary the mechanism, never copy the payload):"]
    for i, (cid, cls, sev, bounty, trig) in enumerate(rows):
        lines.append(f"- {cid} [{cls} {sev} {bounty}] {trig}")
    for cid, *_ in rows[:with_bodies]:
        lines.append(card(cid, 900))
    return "\n".join(lines)


# ---------------------------------------------------------------- the Manual (T-NN)

def manual(query, k=4, cap=900):
    """T-NN entries by id ('T-215') or by terms, from the volumes; Rule + Why only."""
    ids = re.findall(r"T-\d{1,3}[a-z]?", query or "", re.I)
    out = []
    texts = []
    for p in MANUALS:
        try:
            texts.append(_read(p))
        except OSError:
            pass
    entries = []
    for t in texts:
        for m in re.finditer(r"(?ms)^## (T-\d{1,3}[a-z]?) (.*?)(?=^## |\Z)", t):
            entries.append((m.group(1).upper(), m.group(0)))
    if ids:
        want = {i.upper() for i in ids}
        picked = [e for e in entries if e[0] in want]
    else:
        wt = _terms(query)
        scored = sorted(((len(wt & _terms(e[1][:1500])), e) for e in entries), key=lambda x: -x[0])
        picked = [e for s, e in scored[:k] if s]
    seen = set()
    for tid, body in picked:
        if tid in seen:
            continue
        seen.add(tid)
        head = body.splitlines()[0]
        rule = re.search(r"(?s)\*\*Rule\.\*\*(.*?)(?=\*\*Why|\*\*Receipt|\Z)", body)
        why = re.search(r"(?s)\*\*Why\.\*\*(.*?)(?=\*\*Receipt|\*\*Changed|\Z)", body)
        s = head + ("\n  Rule: " + " ".join(rule.group(1).split())[:cap] if rule else "") + \
            ("\n  Why: " + " ".join(why.group(1).split())[:cap // 2] if why else "")
        out.append(s)
    return "\n".join(out) if out else f"no Manual entry for {query!r}"


# ---------------------------------------------------------------- the expert pack per phase

def pack(phase, program_terms="", stack_tags=(), crown="", cap=5200):
    """What an expert would have in mind at this phase, for THIS target: doctrine moves, cards, idioms."""
    parts = []
    terms = f"{program_terms} {' '.join(stack_tags)} {crown}"
    if phase == "hypothesize":
        parts.append("EV-RANKED OPENER: " + opener()[:1200])
        parts.append("PAID WIN-PATTERNS (highest prior):\n" + "\n".join(f"- {i}: {t}" for i, t in moves("I", terms, 5, 380)))
        parts.append("HYPOTHESIS PRIORS:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("AC", terms, 5, 320)))
        parts.append("CRAFTED INPUT:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("H", terms, 2, 320)))
    elif phase == "probe":
        parts.append("TELLS TO WATCH:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("BE", terms, 6, 320)))
        parts.append("DISCIPLINE:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("G", "", 3, 260)))
    elif phase == "escalate":
        parts.append("ESCALATION MOVES:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("D", terms, 6, 380)))
    elif phase == "stuck":
        parts.append("STUCK PIVOTS:\n" + "\n".join(f"- {i}: {t}" for i, t in moves("F", terms, 6, 360)))
    idi = idioms_for(stack_tags)
    if idi:
        parts.append("STACK IDIOMS (fingerprinted):\n- " + "\n- ".join(idi))
    ct = cards_text(terms, 4, 1)
    if ct:
        parts.append(ct)
    out = "\n\n".join(p for p in parts if p.strip())
    return out[:cap] + ("\n[... pack cut]" if len(out) > cap else "")


# ---------------------------------------------------------------- attack tree (the chain table inverted)

START_NODES = {"unauth", "own-account"}


def _prereqs():
    """capability -> [(prerequisite capability, via, how, ref)] by inverting NEXT_HOPS."""
    inv = {}
    for frm, hops in NEXT_HOPS.items():
        for via, to, how, ref in hops:
            inv.setdefault(to, []).append((frm, via, how, ref))
    return inv


def attack_tree(goal, held=(), depth=3):
    """Decompose a crown (or any capability) into the prerequisite capabilities that reach it, from the chain table,
    annotated with what is already held. Leaves are the capabilities to go and prove."""
    inv = _prereqs()
    goal_t = canon(goal)
    held_t = {canon(h) for h in (held or [])}
    lines = [f"ATTACK TREE for {goal_t.upper()} (OR branches; held capabilities marked *; leaves are what to prove next)"]
    leaves = []

    def walk(node, d, seen, indent):
        rows = inv.get(node, [])
        if not rows or d >= depth:
            if node not in held_t and node not in START_NODES:
                leaves.append(node)
            return
        for frm, via, how, ref in rows:
            mark = "*" if frm in held_t else " "
            lines.append(f"{indent}{mark} {frm} --[{via}]--> {node}   ({how[:110]}) [{ref}]")
            if frm not in seen:
                walk(frm, d + 1, seen | {frm}, indent + "    ")
    walk(goal_t, 0, {goal_t}, "  ")
    if len(lines) == 1:
        lines.append("  no chain-table branch reaches it: derive the edges from the five escalation moves and the "
                     "doctrine (playbook kind=moves phase=D).")
    uniq = []
    for l in leaves:
        if l not in uniq:
            uniq.append(l)
    if uniq:
        lines.append("LEAVES TO PROVE (each becomes one hypothesized edge): " + ", ".join(uniq[:12]))
    if held_t:
        lines.append("HELD: " + ", ".join(sorted(held_t)))
    return "\n".join(lines)
